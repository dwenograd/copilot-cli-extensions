// crucible/persistence/artifact-store.mjs
//
// Immutable content-addressed artifact store (CAS) for the Crucible audit
// trail. This is the filesystem durability layer that the event repository
// deliberately does NOT implement: the repository only tracks artifact
// *metadata* and refuses to reference an external artifact until a caller has
// made it durable. This module is what makes it durable.
//
// Design invariants (all fail-closed, all typed errors, no domain policy):
//
//   * Objects are addressed by an algorithm-tagged SHA-256 id ("sha256:<hex>")
//     and stored at objects/sha256/<first-2-hex>/<hex>. The bytes at that path
//     ARE the object; they are never overwritten. A second writer of identical
//     content is a no-op that verifies the existing bytes rather than replacing
//     them.
//
//   * Every write goes through a unique staging file and a durable private
//     installation journal. An object is not reported durable until its bytes,
//     parent/ancestor directories, and installed-state marker have all crossed
//     fsync barriers. A later trusted reconciliation advances installed ->
//     referenced.
//
//   * Ingesting a directory produces an immutable canonical snapshot: a sorted,
//     symlink-free, traversal-checked recursive walk whose per-file hashes are
//     recorded in a canonical manifest object stored in the CAS. Nothing is
//     ever executed. The snapshot id is the manifest object's id, so identical
//     inputs yield identical snapshots.
//
//   * Materialization reads verified CAS objects into a *fresh* destination and
//     refuses a pre-existing destination or any path that would escape it.
//
//   * Verification and reconciliation detect missing/corrupt bytes and only
//     ever delete UNREFERENCED staging/orphan objects older than a
//     caller-supplied age. References are never inferred from untrusted input.
//
// This module has no third-party dependencies; only node: builtins.

import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";

import { CruciblePersistenceError, InvalidArgumentError } from "./errors.mjs";
import { assertLocalDatabasePath } from "./paths.mjs";
import { canonicalize, normalizeCreatedAt } from "./canonical.mjs";
import { DatabaseSync } from "./sqlite.mjs";

// --- constants ------------------------------------------------------------

const ALGO = "sha256";
const HEX_LEN = 64;
const OBJECT_ID_RE = /^([a-z0-9]+):([0-9a-f]+)$/u;
const HEX64_RE = /^[0-9a-f]{64}$/u;
const SNAPSHOT_TYPE = "crucible-snapshot";
const SNAPSHOT_VERSION = 1;
const SNAPSHOT_MANIFEST_KEYS = Object.freeze([
    "algo",
    "entries",
    "fileCount",
    "totalBytes",
    "type",
    "version",
]);
const SNAPSHOT_ENTRY_KEYS = Object.freeze(["object", "path", "size"]);
const WINDOWS_RESERVED_DEVICE_RE =
    /^(?:aux|clock\$|com[1-9¹²³]|con|conin\$|conout\$|lpt[1-9¹²³]|nul|prn)(?:\..*)?$/iu;
const STAGE_CHUNK = 1 << 16;
const STORE_METADATA_DIR = ".crucible";
const JOURNAL_TYPE = "crucible-cas-installation";
const JOURNAL_VERSION = 1;
const JOURNAL_STATES = Object.freeze({
    STAGING: "staging",
    INSTALLED: "installed",
    REFERENCED: "referenced",
});
const STAGING_RECORD_KEYS = Object.freeze([
    "algo",
    "createdAt",
    "object",
    "size",
    "staging",
    "state",
    "transaction",
    "type",
    "version",
]);
const STATE_MARKER_KEYS = Object.freeze([
    "algo",
    "object",
    "size",
    "state",
    "type",
    "version",
]);
const TRANSACTION_RE = /^[0-9a-z]+-[0-9a-z]+-[0-9a-f]{24}$/u;
const JOURNAL_FILE_RE = /^([0-9a-z]+-[0-9a-z]+-[0-9a-f]{24})\.json$/u;
const STATE_MARKER_FILE_RE = /^([0-9a-f]{64})\.(installed|referenced)\.json$/u;
const COORDINATION_DB_FILE = "coordination.sqlite";
const COORDINATION_SCHEMA_VERSION = 1;
const COORDINATION_BUSY_TIMEOUT_MS = 5000;
const LEGACY_DIRECTORY_BARRIER_FILE = ".crucible-dirsync";

const DEFAULT_LIMITS = Object.freeze({
    maxFiles: 100_000,
    maxTotalBytes: 16 * 2 ** 30, // 16 GiB
    maxFileBytes: 8 * 2 ** 30, //  8 GiB
    maxPathLength: 1024, // characters in a relative posix path
    maxDepth: 128,
});

// --- typed errors ---------------------------------------------------------

export const ARTIFACT_STORE_ERROR_CODES = Object.freeze({
    INVALID_ARGUMENT: "CRUCIBLE_CAS_INVALID_ARGUMENT",
    STORE_ROOT_INVALID: "CRUCIBLE_CAS_STORE_ROOT_INVALID",
    UNSAFE_PATH: "CRUCIBLE_CAS_UNSAFE_PATH",
    SYMLINK_REJECTED: "CRUCIBLE_CAS_SYMLINK_REJECTED",
    LIMIT_EXCEEDED: "CRUCIBLE_CAS_LIMIT_EXCEEDED",
    OBJECT_NOT_FOUND: "CRUCIBLE_CAS_OBJECT_NOT_FOUND",
    OBJECT_CORRUPT: "CRUCIBLE_CAS_OBJECT_CORRUPT",
    DESTINATION_EXISTS: "CRUCIBLE_CAS_DESTINATION_EXISTS",
    SNAPSHOT_INVALID: "CRUCIBLE_CAS_SNAPSHOT_INVALID",
    SOURCE_CHANGED: "CRUCIBLE_CAS_SOURCE_CHANGED",
    JOURNAL_CORRUPT: "CRUCIBLE_CAS_JOURNAL_CORRUPT",
    IO_ERROR: "CRUCIBLE_CAS_IO_ERROR",
});

export class ArtifactStoreError extends CruciblePersistenceError {
    constructor(code, message, details) {
        super(code, message, details);
        this.name = "ArtifactStoreError";
    }
}

export class UnsafePathError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.UNSAFE_PATH, message, details);
        this.name = "UnsafePathError";
    }
}

export class SymlinkRejectedError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.SYMLINK_REJECTED, message, details);
        this.name = "SymlinkRejectedError";
    }
}

export class LimitExceededError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.LIMIT_EXCEEDED, message, details);
        this.name = "LimitExceededError";
    }
}

export class ObjectNotFoundError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.OBJECT_NOT_FOUND, message, details);
        this.name = "ObjectNotFoundError";
    }
}

export class ObjectCorruptError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.OBJECT_CORRUPT, message, details);
        this.name = "ObjectCorruptError";
    }
}

export class DestinationExistsError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.DESTINATION_EXISTS, message, details);
        this.name = "DestinationExistsError";
    }
}

export class SnapshotInvalidError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.SNAPSHOT_INVALID, message, details);
        this.name = "SnapshotInvalidError";
    }
}

export class SourceChangedError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.SOURCE_CHANGED, message, details);
        this.name = "SourceChangedError";
    }
}

export class JournalCorruptError extends ArtifactStoreError {
    constructor(message, details) {
        super(ARTIFACT_STORE_ERROR_CODES.JOURNAL_CORRUPT, message, details);
        this.name = "JournalCorruptError";
    }
}

// --- free helpers (also exported for the bundle layer) --------------------

// Algorithm-tagged object id for a hex digest.
export function objectIdFor(hexDigest) {
    if (typeof hexDigest !== "string" || !HEX64_RE.test(hexDigest)) {
        throw new InvalidArgumentError("expected a 64-char lowercase hex sha256 digest", { hexDigest });
    }
    return `${ALGO}:${hexDigest}`;
}

// Parse and validate an algorithm-tagged object id. Only sha256 is supported.
export function parseObjectId(id) {
    if (typeof id !== "string") {
        throw new InvalidArgumentError("object id must be a string", { id: String(id) });
    }
    const m = OBJECT_ID_RE.exec(id);
    if (!m) {
        throw new InvalidArgumentError("malformed object id (expected '<algo>:<hex>')", { id });
    }
    const [, algo, hex] = m;
    if (algo !== ALGO) {
        throw new InvalidArgumentError(`unsupported object hash algorithm '${algo}' (only ${ALGO})`, { id, algo });
    }
    if (hex.length !== HEX_LEN) {
        throw new InvalidArgumentError(`sha256 digest must be ${HEX_LEN} hex chars`, { id, length: hex.length });
    }
    return { algo, hex };
}

// Relative posix path (below the store root) at which an object lives.
export function objectRelPath(hex) {
    return `objects/${ALGO}/${hex.slice(0, 2)}/${hex}`;
}

// Reject a single path *component* that could be used to escape a root or to
// smuggle a stream / drive reference. readdir yields single components; a
// manifest supplies untrusted relative paths that we split on "/".
function assertSafeComponent(name, context) {
    if (typeof name !== "string" || name.length === 0) {
        throw new UnsafePathError("empty path component", { context, name });
    }
    if (name === "." || name === "..") {
        throw new UnsafePathError("relative traversal component is not permitted", { context, name });
    }
    if (name.includes("/") || name.includes("\\") || name.includes("\0")) {
        throw new UnsafePathError("path component contains a separator or NUL", { context, name });
    }
    // Windows alternate-data-stream / drive-letter smuggling.
    if (name.includes(":")) {
        throw new UnsafePathError("path component contains a colon", { context, name });
    }
    if (/[\u0000-\u001f<>"|?*]/u.test(name)) {
        throw new UnsafePathError("path component contains a Windows-reserved character", { context, name });
    }
    if (name.endsWith(".") || name.endsWith(" ")) {
        throw new UnsafePathError("path component has a Windows-ambiguous trailing dot or space", {
            context,
            name,
        });
    }
    if (WINDOWS_RESERVED_DEVICE_RE.test(name)) {
        throw new UnsafePathError("path component is a reserved Windows device name", { context, name });
    }
}

// Validate an untrusted relative posix path (from a manifest). Returns the
// individual, individually-validated segments.
function safeRelSegments(relPath, maxPathLength) {
    if (typeof relPath !== "string" || relPath.length === 0) {
        throw new UnsafePathError("relative path must be a non-empty string", { relPath: String(relPath) });
    }
    if (relPath.length > maxPathLength) {
        throw new LimitExceededError("relative path exceeds maximum length", { relPath, maxPathLength });
    }
    if (path.posix.isAbsolute(relPath) || path.win32.isAbsolute(relPath) || /^[A-Za-z]:/u.test(relPath)) {
        throw new UnsafePathError("absolute paths are not permitted in a snapshot", { relPath });
    }
    if (relPath.includes("\\")) {
        throw new UnsafePathError("snapshot paths must use canonical forward-slash separators", { relPath });
    }
    const segments = relPath.split("/");
    for (const seg of segments) {
        assertSafeComponent(seg, relPath);
    }
    return segments;
}

function hasExactKeys(value, expectedKeys) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const actual = Object.keys(value).sort();
    return actual.length === expectedKeys.length
        && actual.every((key, index) => key === expectedKeys[index]);
}

function windowsPathIdentity(relPath) {
    return relPath.replaceAll("\\", "/").toLowerCase();
}

function validateSnapshotManifest(manifest, options = {}) {
    const { snapshotId = null, rawBytes = null, limits = DEFAULT_LIMITS } = options;
    const at = snapshotId === null ? {} : { snapshotId };

    if (!hasExactKeys(manifest, SNAPSHOT_MANIFEST_KEYS)) {
        throw new SnapshotInvalidError("snapshot manifest must use the canonical schema", {
            ...at,
            expectedKeys: SNAPSHOT_MANIFEST_KEYS,
            actualKeys: manifest && typeof manifest === "object" && !Array.isArray(manifest)
                ? Object.keys(manifest).sort()
                : [],
        });
    }
    if (manifest.type !== SNAPSHOT_TYPE
        || manifest.version !== SNAPSHOT_VERSION
        || manifest.algo !== ALGO
        || !Array.isArray(manifest.entries)) {
        throw new SnapshotInvalidError("snapshot manifest has an unexpected type, version, algorithm, or entries", at);
    }
    if (!Number.isSafeInteger(manifest.fileCount) || manifest.fileCount < 0) {
        throw new SnapshotInvalidError("snapshot manifest fileCount must be a non-negative safe integer", at);
    }
    if (!Number.isSafeInteger(manifest.totalBytes) || manifest.totalBytes < 0) {
        throw new SnapshotInvalidError("snapshot manifest totalBytes must be a non-negative safe integer", at);
    }
    if (manifest.entries.length > limits.maxFiles || manifest.fileCount > limits.maxFiles) {
        throw new SnapshotInvalidError("snapshot manifest exceeds the configured file-count limit", {
            ...at,
            maxFiles: limits.maxFiles,
        });
    }
    if (manifest.totalBytes > limits.maxTotalBytes) {
        throw new SnapshotInvalidError("snapshot manifest exceeds the configured total-byte limit", {
            ...at,
            maxTotalBytes: limits.maxTotalBytes,
        });
    }

    const entries = [];
    const pathsByIdentity = new Map();
    const filePathIdentities = new Set();
    const directoryPathIdentities = new Set();
    const objectSizes = new Map();
    let previousPath = null;
    let computedTotalBytes = 0;

    for (let index = 0; index < manifest.entries.length; index += 1) {
        const entry = manifest.entries[index];
        if (!hasExactKeys(entry, SNAPSHOT_ENTRY_KEYS)) {
            throw new SnapshotInvalidError("snapshot manifest entry must use the canonical schema", {
                ...at,
                index,
                expectedKeys: SNAPSHOT_ENTRY_KEYS,
                actualKeys: entry && typeof entry === "object" && !Array.isArray(entry)
                    ? Object.keys(entry).sort()
                    : [],
            });
        }
        if (typeof entry.path !== "string" || typeof entry.object !== "string") {
            throw new SnapshotInvalidError("snapshot manifest entry path and object must be strings", {
                ...at,
                index,
            });
        }
        if (!Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > limits.maxFileBytes) {
            throw new SnapshotInvalidError("snapshot manifest entry size is invalid", {
                ...at,
                index,
                size: entry.size,
                maxFileBytes: limits.maxFileBytes,
            });
        }

        const segments = safeRelSegments(entry.path, limits.maxPathLength);
        const pathIdentity = windowsPathIdentity(entry.path);
        const priorPath = pathsByIdentity.get(pathIdentity);
        if (priorPath !== undefined) {
            throw new SnapshotInvalidError(
                "snapshot manifest contains duplicate or Windows-colliding paths",
                { ...at, index, path: entry.path, priorPath },
            );
        }
        pathsByIdentity.set(pathIdentity, entry.path);
        if (previousPath !== null && previousPath >= entry.path) {
            throw new SnapshotInvalidError("snapshot manifest entries are not strictly sorted by path", {
                ...at,
                index,
                previousPath,
                path: entry.path,
            });
        }
        previousPath = entry.path;

        const identitySegments = segments.map((segment) => segment.toLowerCase());
        const entryIdentity = identitySegments.join("/");
        if (directoryPathIdentities.has(entryIdentity)) {
            throw new SnapshotInvalidError("snapshot path is both a file and a directory", {
                ...at,
                index,
                path: entry.path,
            });
        }
        for (let depth = 1; depth < identitySegments.length; depth += 1) {
            const parentIdentity = identitySegments.slice(0, depth).join("/");
            if (filePathIdentities.has(parentIdentity)) {
                throw new SnapshotInvalidError("snapshot path descends through another file entry", {
                    ...at,
                    index,
                    path: entry.path,
                });
            }
            directoryPathIdentities.add(parentIdentity);
        }
        filePathIdentities.add(entryIdentity);

        let canonicalObject;
        try {
            const { hex } = parseObjectId(entry.object);
            canonicalObject = objectIdFor(hex);
        } catch (err) {
            throw new SnapshotInvalidError("snapshot manifest entry has an invalid object id", {
                ...at,
                index,
                object: entry.object,
                cause: err.message,
            });
        }
        if (canonicalObject !== entry.object) {
            throw new SnapshotInvalidError("snapshot manifest entry object id is not canonical", {
                ...at,
                index,
                object: entry.object,
            });
        }
        const priorSize = objectSizes.get(canonicalObject);
        if (priorSize !== undefined && priorSize !== entry.size) {
            throw new SnapshotInvalidError("snapshot manifest assigns conflicting sizes to one object", {
                ...at,
                index,
                object: canonicalObject,
                priorSize,
                size: entry.size,
            });
        }
        objectSizes.set(canonicalObject, entry.size);

        if (computedTotalBytes > Number.MAX_SAFE_INTEGER - entry.size) {
            throw new SnapshotInvalidError("snapshot manifest byte total exceeds safe integer range", at);
        }
        computedTotalBytes += entry.size;
        entries.push({ path: entry.path, size: entry.size, object: canonicalObject });
    }

    if (manifest.fileCount !== entries.length) {
        throw new SnapshotInvalidError("snapshot manifest fileCount does not match entries", {
            ...at,
            fileCount: manifest.fileCount,
            actualFileCount: entries.length,
        });
    }
    if (manifest.totalBytes !== computedTotalBytes) {
        throw new SnapshotInvalidError("snapshot manifest totalBytes does not match entry sizes", {
            ...at,
            totalBytes: manifest.totalBytes,
            actualTotalBytes: computedTotalBytes,
        });
    }

    const validated = {
        type: SNAPSHOT_TYPE,
        version: SNAPSHOT_VERSION,
        algo: ALGO,
        fileCount: manifest.fileCount,
        totalBytes: manifest.totalBytes,
        entries,
    };
    if (rawBytes !== null) {
        const sourceBytes = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(rawBytes);
        const canonicalBytes = Buffer.from(canonicalize(validated), "utf8");
        if (!sourceBytes.equals(canonicalBytes)) {
            throw new SnapshotInvalidError("snapshot manifest bytes are not canonical JSON", at);
        }
    }
    return validated;
}

function parseCanonicalJson(bytes, context) {
    let value;
    try {
        value = JSON.parse(bytes.toString("utf8"));
    } catch (err) {
        throw new JournalCorruptError(`${context} is not valid JSON`, {
            cause: err.message,
        });
    }
    const canonicalBytes = Buffer.from(canonicalize(value), "utf8");
    if (!bytes.equals(canonicalBytes)) {
        throw new JournalCorruptError(`${context} is not canonical JSON`);
    }
    return value;
}

function validateStagingRecord(value, options = {}) {
    const { rawBytes = null, fileName = null, limits = DEFAULT_LIMITS } = options;
    if (!hasExactKeys(value, STAGING_RECORD_KEYS)
        || value.type !== JOURNAL_TYPE
        || value.version !== JOURNAL_VERSION
        || value.state !== JOURNAL_STATES.STAGING
        || value.algo !== ALGO
        || typeof value.createdAt !== "string"
        || !TRANSACTION_RE.test(value.transaction)
        || value.staging !== `${value.transaction}.tmp`
        || !Number.isSafeInteger(value.size)
        || value.size < 0
        || value.size > limits.maxFileBytes) {
        throw new JournalCorruptError("installation staging record has an invalid schema", {
            fileName,
        });
    }
    let normalizedCreatedAt;
    try {
        normalizedCreatedAt = normalizeCreatedAt(
            value.createdAt,
            "installation.createdAt",
        );
    } catch (err) {
        throw new JournalCorruptError("installation staging record createdAt is invalid", {
            fileName,
            cause: err.message,
        });
    }
    if (normalizedCreatedAt !== value.createdAt) {
        throw new JournalCorruptError(
            "installation staging record createdAt is not canonical UTC ISO-8601",
            { fileName, createdAt: value.createdAt, normalizedCreatedAt },
        );
    }
    let parsed;
    try {
        parsed = parseObjectId(value.object);
    } catch (err) {
        throw new JournalCorruptError("installation staging record has an invalid object id", {
            fileName,
            object: value.object,
            cause: err.message,
        });
    }
    if (parsed.algo !== ALGO || value.object !== objectIdFor(parsed.hex)) {
        throw new JournalCorruptError("installation staging record object id is not canonical", {
            fileName,
            object: value.object,
        });
    }
    if (fileName !== null) {
        const match = JOURNAL_FILE_RE.exec(fileName);
        if (!match || match[1] !== value.transaction) {
            throw new JournalCorruptError("installation staging record filename disagrees with its transaction", {
                fileName,
                transaction: value.transaction,
            });
        }
    }
    if (rawBytes !== null) {
        const source = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(rawBytes);
        if (!source.equals(Buffer.from(canonicalize(value), "utf8"))) {
            throw new JournalCorruptError("installation staging record bytes are not canonical", {
                fileName,
            });
        }
    }
    const validated = { ...value };
    Object.defineProperty(validated, "hash", {
        value: parsed.hex,
        enumerable: false,
    });
    return Object.freeze(validated);
}

function stateMarkerValue(hash, size, state) {
    return {
        type: JOURNAL_TYPE,
        version: JOURNAL_VERSION,
        state,
        algo: ALGO,
        object: objectIdFor(hash),
        size,
    };
}

function validateStateMarker(value, options = {}) {
    const {
        rawBytes = null,
        fileName = null,
        expectedState = null,
        limits = DEFAULT_LIMITS,
    } = options;
    if (!hasExactKeys(value, STATE_MARKER_KEYS)
        || value.type !== JOURNAL_TYPE
        || value.version !== JOURNAL_VERSION
        || value.algo !== ALGO
        || (value.state !== JOURNAL_STATES.INSTALLED && value.state !== JOURNAL_STATES.REFERENCED)
        || (expectedState !== null && value.state !== expectedState)
        || !Number.isSafeInteger(value.size)
        || value.size < 0
        || value.size > limits.maxFileBytes) {
        throw new JournalCorruptError("installation state marker has an invalid schema", {
            fileName,
            expectedState,
        });
    }
    let parsed;
    try {
        parsed = parseObjectId(value.object);
    } catch (err) {
        throw new JournalCorruptError("installation state marker has an invalid object id", {
            fileName,
            object: value.object,
            cause: err.message,
        });
    }
    if (fileName !== null) {
        const match = STATE_MARKER_FILE_RE.exec(fileName);
        if (!match || match[1] !== parsed.hex || match[2] !== value.state) {
            throw new JournalCorruptError("installation state marker filename disagrees with its contents", {
                fileName,
                object: value.object,
                state: value.state,
            });
        }
    }
    if (rawBytes !== null) {
        const source = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(rawBytes);
        if (!source.equals(Buffer.from(canonicalize(value), "utf8"))) {
            throw new JournalCorruptError("installation state marker bytes are not canonical", {
                fileName,
            });
        }
    }
    const validated = { ...value };
    Object.defineProperty(validated, "hash", {
        value: parsed.hex,
        enumerable: false,
    });
    return Object.freeze(validated);
}

function toPosix(p) {
    return p.split(path.sep).join("/");
}

function asIoError(action, err, details = {}) {
    if (err instanceof CruciblePersistenceError) {
        return err;
    }
    const wrapped = new ArtifactStoreError(
        ARTIFACT_STORE_ERROR_CODES.IO_ERROR,
        `${action}: ${err?.message ?? String(err)}`,
        {
            ...details,
            fsCode: err?.code,
            syscall: err?.syscall,
        },
    );
    wrapped.cause = err;
    return wrapped;
}

function stableIdentity(stat, filePath) {
    const dev = stat?.dev;
    const ino = stat?.ino;
    if ((typeof dev !== "bigint" && typeof dev !== "number")
        || (typeof ino !== "bigint" && typeof ino !== "number")
        || BigInt(dev) <= 0n
        || BigInt(ino) <= 0n) {
        throw new SourceChangedError(
            "filesystem does not expose stable source identity; refusing snapshot ingestion",
            { path: filePath },
        );
    }
    return Object.freeze({
        dev: BigInt(dev).toString(),
        ino: BigInt(ino).toString(),
        size: BigInt(stat.size).toString(),
        mode: BigInt(stat.mode).toString(),
        mtimeNs: BigInt(stat.mtimeNs).toString(),
        ctimeNs: BigInt(stat.ctimeNs).toString(),
    });
}

function assertStableIdentity(before, after, filePath) {
    if (before.dev !== after.dev
        || before.ino !== after.ino
        || before.size !== after.size
        || before.mode !== after.mode
        || before.mtimeNs !== after.mtimeNs
        || before.ctimeNs !== after.ctimeNs) {
        throw new SourceChangedError("snapshot source changed during ingestion", {
            path: filePath,
            before,
            after,
        });
    }
}

function sameCanonicalPath(left, right) {
    return process.platform === "win32"
        ? left.toLowerCase() === right.toLowerCase()
        : left === right;
}

function compareStable(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

function materializationAnchor(stat, filePath) {
    const dev = stat?.dev;
    const ino = stat?.ino;
    if ((typeof dev !== "bigint" && typeof dev !== "number")
        || (typeof ino !== "bigint" && typeof ino !== "number")
        || BigInt(dev) <= 0n
        || BigInt(ino) <= 0n) {
        throw new SourceChangedError(
            "filesystem does not expose stable destination identity; refusing materialization",
            { path: filePath },
        );
    }
    return Object.freeze({
        dev: BigInt(dev).toString(),
        ino: BigInt(ino).toString(),
        mode: BigInt(stat.mode).toString(),
        birthtimeNs: BigInt(stat.birthtimeNs ?? 0n).toString(),
    });
}

function assertMaterializationAnchor(before, after, filePath) {
    if (before.dev !== after.dev
        || before.ino !== after.ino
        || before.mode !== after.mode
        || before.birthtimeNs !== after.birthtimeNs) {
        throw new SourceChangedError("materialization directory was replaced during publication", {
            path: filePath,
            before,
            after,
        });
    }
}

function materializationLstatOrNull(filePath) {
    try {
        return fs.lstatSync(filePath, { bigint: true });
    } catch (err) {
        if (err && err.code === "ENOENT") {
            return null;
        }
        throw err;
    }
}

function assertMaterializationPath(absPath, expectedType) {
    const resolved = path.resolve(absPath);
    const parsed = path.parse(resolved);
    const relative = path.relative(parsed.root, resolved);
    const segments = relative === "" ? [] : relative.split(path.sep);
    let current = parsed.root;
    for (let index = 0; index < segments.length; index += 1) {
        const segment = segments[index];
        assertSafeComponent(segment, resolved);
        current = path.join(current, segment);
        const stat = fs.lstatSync(current, { bigint: true });
        if (stat.isSymbolicLink()) {
            throw new SymlinkRejectedError(
                "materialization path contains a symlink, junction, or reparse point",
                { path: current },
            );
        }
        const leaf = index === segments.length - 1;
        if (!leaf && !stat.isDirectory()) {
            throw new UnsafePathError("materialization path descends through a non-directory", {
                path: current,
            });
        }
        if (leaf && expectedType === "directory" && !stat.isDirectory()) {
            throw new UnsafePathError("materialization path is not a directory", { path: current });
        }
        if (leaf && expectedType === "file" && !stat.isFile()) {
            throw new UnsafePathError("materialization target is not a regular file", { path: current });
        }
        const real = fs.realpathSync.native(current);
        if (!sameCanonicalPath(path.resolve(current), path.resolve(real))) {
            throw new SymlinkRejectedError(
                "materialization path resolves through a symlink, junction, or reparse point",
                { path: current, real },
            );
        }
    }
    const stat = fs.lstatSync(resolved, { bigint: true });
    return {
        path: resolved,
        real: fs.realpathSync.native(resolved),
        stat,
        anchor: materializationAnchor(stat, resolved),
    };
}

function ensureMaterializationDirectory(absPath) {
    const resolved = path.resolve(absPath);
    const parsed = path.parse(resolved);
    const relative = path.relative(parsed.root, resolved);
    const segments = relative === "" ? [] : relative.split(path.sep);
    let current = parsed.root;
    for (const segment of segments) {
        assertSafeComponent(segment, resolved);
        current = path.join(current, segment);
        let stat = materializationLstatOrNull(current);
        if (stat === null) {
            fs.mkdirSync(current, { recursive: false, mode: 0o700 });
            try {
                fs.chmodSync(current, 0o700);
            } catch {
                // Best available Windows permissions; identity checks stay mandatory.
            }
            stat = fs.lstatSync(current, { bigint: true });
        }
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
            throw new SymlinkRejectedError(
                "materialization directory component is a link or non-directory",
                { path: current },
            );
        }
        const real = fs.realpathSync.native(current);
        if (!sameCanonicalPath(path.resolve(current), path.resolve(real))) {
            throw new SymlinkRejectedError(
                "materialization directory resolves through a reparse point",
                { path: current, real },
            );
        }
    }
    return assertMaterializationPath(resolved, "directory");
}

function assertMaterializationRoot(stagePath, stageAnchor, parentPath, parentAnchor) {
    const parent = assertMaterializationPath(parentPath, "directory");
    assertMaterializationAnchor(parentAnchor, parent.anchor, parentPath);
    const stage = assertMaterializationPath(stagePath, "directory");
    assertMaterializationAnchor(stageAnchor, stage.anchor, stagePath);
    if (!isInsideDir(stage.real, parent.real)) {
        throw new UnsafePathError("private materialization staging escaped its verified parent", {
            stagePath,
            real: stage.real,
        });
    }
    return stage;
}

function removeMaterializationTree(rootPath, expectedAnchor = null) {
    const stat = materializationLstatOrNull(rootPath);
    if (stat === null) {
        return;
    }
    if (stat.isSymbolicLink()) {
        fs.unlinkSync(rootPath);
        return;
    }
    if (!stat.isDirectory()) {
        fs.unlinkSync(rootPath);
        return;
    }
    if (expectedAnchor !== null) {
        assertMaterializationAnchor(
            expectedAnchor,
            materializationAnchor(stat, rootPath),
            rootPath,
        );
    }
    const real = fs.realpathSync.native(rootPath);
    if (!sameCanonicalPath(path.resolve(rootPath), path.resolve(real))) {
        throw new SymlinkRejectedError("refusing to clean materialization staging through a reparse point", {
            rootPath,
            real,
        });
    }
    for (const name of fs.readdirSync(rootPath)) {
        assertSafeComponent(name, rootPath);
        const child = path.join(rootPath, name);
        const childStat = fs.lstatSync(child, { bigint: true });
        if (childStat.isSymbolicLink()) {
            fs.unlinkSync(child);
        } else if (childStat.isDirectory()) {
            removeMaterializationTree(child);
        } else {
            fs.unlinkSync(child);
        }
    }
    fs.rmdirSync(rootPath);
}

function verifyMaterializationStage(stagePath, stageAnchor, parentPath, parentAnchor, manifest) {
    assertMaterializationRoot(stagePath, stageAnchor, parentPath, parentAnchor);
    const expected = new Map(manifest.entries.map((entry) => [entry.path, entry]));
    const actualPaths = [];

    const walk = (dirPath, relSegments) => {
        const beforeStat = fs.lstatSync(dirPath, { bigint: true });
        if (beforeStat.isSymbolicLink() || !beforeStat.isDirectory()) {
            throw new SymlinkRejectedError(
                "materialization staging directory changed into a link/non-directory",
                { path: dirPath },
            );
        }
        const before = stableIdentity(beforeStat, dirPath);
        const dirReal = fs.realpathSync.native(dirPath);
        if (!sameCanonicalPath(path.resolve(dirPath), path.resolve(dirReal))
            || !isInsideDir(dirReal, stagePath)) {
            throw new UnsafePathError("materialization staging directory escapes its root", {
                path: dirPath,
                real: dirReal,
            });
        }
        const names = fs.readdirSync(dirPath).sort(compareStable);
        for (const name of names) {
            assertSafeComponent(name, dirPath);
            const childPath = path.join(dirPath, name);
            const childRel = [...relSegments, name];
            const relPath = childRel.join("/");
            const childStat = fs.lstatSync(childPath, { bigint: true });
            if (childStat.isSymbolicLink()) {
                throw new SymlinkRejectedError(
                    "materialization staging contains a symlink, junction, or reparse entry",
                    { relPath },
                );
            }
            const childReal = fs.realpathSync.native(childPath);
            if (!sameCanonicalPath(path.resolve(childPath), path.resolve(childReal))
                || !isInsideDir(childReal, stagePath)) {
                throw new UnsafePathError("materialization staging entry escapes its root", {
                    relPath,
                    real: childReal,
                });
            }
            if (childStat.isDirectory()) {
                walk(childPath, childRel);
                continue;
            }
            if (!childStat.isFile()) {
                throw new UnsafePathError("materialization staging contains a non-regular entry", {
                    relPath,
                });
            }
            const entry = expected.get(relPath);
            if (!entry) {
                throw new UnsafePathError("materialization staging contains an unmanifested file", {
                    relPath,
                });
            }
            const beforeFile = stableIdentity(childStat, childPath);
            const fd = fs.openSync(childPath, "r");
            const hash = createHash(ALGO);
            const buffer = Buffer.allocUnsafe(STAGE_CHUNK);
            let size = 0;
            try {
                const opened = fs.fstatSync(fd, { bigint: true });
                assertStableIdentity(beforeFile, stableIdentity(opened, childPath), childPath);
                for (;;) {
                    const read = fs.readSync(fd, buffer, 0, buffer.length, null);
                    if (read === 0) {
                        break;
                    }
                    hash.update(buffer.subarray(0, read));
                    size += read;
                }
                assertStableIdentity(
                    beforeFile,
                    stableIdentity(fs.fstatSync(fd, { bigint: true }), childPath),
                    childPath,
                );
            } finally {
                fs.closeSync(fd);
            }
            assertStableIdentity(
                beforeFile,
                stableIdentity(fs.lstatSync(childPath, { bigint: true }), childPath),
                childPath,
            );
            const { hex } = parseObjectId(entry.object);
            const actualHash = hash.digest("hex");
            if (actualHash !== hex || size !== entry.size) {
                throw new ObjectCorruptError(
                    "materialized staging bytes disagree with the snapshot manifest",
                    {
                        relPath,
                        object: entry.object,
                        expectedSize: entry.size,
                        actualSize: size,
                        expectedHash: hex,
                        actualHash,
                    },
                );
            }
            actualPaths.push(relPath);
        }
        assertStableIdentity(
            before,
            stableIdentity(fs.lstatSync(dirPath, { bigint: true }), dirPath),
            dirPath,
        );
    };

    walk(stagePath, []);
    const expectedPaths = [...expected.keys()].sort(compareStable);
    actualPaths.sort(compareStable);
    if (canonicalize(actualPaths) !== canonicalize(expectedPaths)) {
        throw new SnapshotInvalidError("materialization staging file set is incomplete", {
            expected: expectedPaths,
            actual: actualPaths,
        });
    }
    assertMaterializationRoot(stagePath, stageAnchor, parentPath, parentAnchor);
}

function normalizeLimits(limits) {
    const merged = { ...DEFAULT_LIMITS, ...(limits ?? {}) };
    for (const key of Object.keys(DEFAULT_LIMITS)) {
        const v = merged[key];
        if (!Number.isInteger(v) || v <= 0) {
            throw new InvalidArgumentError(`limit '${key}' must be a positive integer`, { key, value: v });
        }
    }
    return Object.freeze(merged);
}

// --- ArtifactStore --------------------------------------------------------

export class ArtifactStore {
    #root;
    #objectsRoot;
    #stagingRoot;
    #metadataRoot;
    #journalRoot;
    #installationsRoot;
    #quarantineRoot;
    #coordinationFile;
    #limits;
    #now;
    #readOnly;
    #faultInjector;

    constructor({ root, now, limits, readOnly = false, faultInjector = null }) {
        this.#root = root;
        this.#objectsRoot = path.join(root, "objects", ALGO);
        this.#stagingRoot = path.join(root, "staging");
        this.#metadataRoot = path.join(root, STORE_METADATA_DIR);
        this.#journalRoot = path.join(this.#metadataRoot, "journal");
        this.#installationsRoot = path.join(this.#metadataRoot, "installations", ALGO);
        this.#quarantineRoot = path.join(this.#metadataRoot, "quarantine");
        this.#coordinationFile = path.join(this.#metadataRoot, COORDINATION_DB_FILE);
        this.#limits = limits;
        this.#now = now;
        this.#readOnly = readOnly;
        this.#faultInjector = faultInjector;
    }

    static open(options = {}) {
        const {
            root,
            denyRoots,
            env,
            limits,
            now = () => new Date().toISOString(),
            readOnly = false,
            faultInjector = null,
        } = options;
        if (typeof root !== "string" || root.trim().length === 0) {
            throw new InvalidArgumentError("artifact store root must be a non-empty string", { root });
        }
        if (typeof now !== "function") {
            throw new InvalidArgumentError("artifact store now option must be a function");
        }
        if (faultInjector !== null && typeof faultInjector !== "function") {
            throw new InvalidArgumentError("artifact store faultInjector option must be a function or null");
        }
        let resolved;
        try {
            // Reuse the repository's local-only path gate: a CAS root on a
            // network share or cloud-sync folder has the same corruption /
            // fsync-semantics problems as a WAL database there.
            resolved = assertLocalDatabasePath(root, { denyRoots, env });
        } catch (err) {
            if (err instanceof CruciblePersistenceError && err.code !== ARTIFACT_STORE_ERROR_CODES.INVALID_ARGUMENT) {
                throw err;
            }
            throw new ArtifactStoreError(
                ARTIFACT_STORE_ERROR_CODES.STORE_ROOT_INVALID,
                `invalid artifact store root: ${err.message}`,
                { root },
            );
        }
        const store = new ArtifactStore({
            root: resolved,
            now,
            limits: normalizeLimits(limits),
            readOnly: readOnly === true,
            faultInjector,
        });
        if (readOnly !== true) {
            store.#ensureLayout();
        }
        return store;
    }

    get root() {
        return this.#root;
    }

    get limits() {
        return this.#limits;
    }

    get readOnly() {
        return this.#readOnly;
    }

    #ensureLayout() {
        for (const dir of [
            this.#objectsRoot,
            this.#stagingRoot,
            this.#journalRoot,
            this.#installationsRoot,
            this.#quarantineRoot,
        ]) {
            this.#ensureDirectoryDurable(dir, "artifact store layout");
        }
        this.#initializeCoordination();
    }

    // --- object addressing -------------------------------------------------

    objectPath(id) {
        const { hex } = parseObjectId(id);
        return path.join(this.#objectsRoot, hex.slice(0, 2), hex);
    }

    hasObject(id) {
        try {
            return fs.statSync(this.objectPath(id)).isFile();
        } catch (err) {
            if (err && err.code === "ENOENT") {
                return false;
            }
            throw err;
        }
    }

    // --- staging -----------------------------------------------------------

    #assertWritable() {
        if (this.#readOnly) {
            throw new ArtifactStoreError(
                ARTIFACT_STORE_ERROR_CODES.IO_ERROR,
                "artifact store was opened read-only",
                { root: this.#root },
            );
        }
    }

    #inject(point, details = {}) {
        if (this.#faultInjector !== null) {
            this.#faultInjector({ point, ...details });
        }
    }

    #newStagingTarget() {
        this.#assertWritable();
        const transaction = `${Date.now().toString(36)}-${process.pid.toString(36)}-${randomBytes(12).toString("hex")}`;
        return {
            transaction,
            stagingPath: path.join(this.#stagingRoot, `${transaction}.tmp`),
        };
    }

    #journalPath(transaction) {
        return path.join(this.#journalRoot, `${transaction}.json`);
    }

    #installationDir(hash) {
        return path.join(this.#installationsRoot, hash.slice(0, 2));
    }

    #markerPath(hash, state) {
        return path.join(this.#installationDir(hash), `${hash}.${state}.json`);
    }

    #candidatePath(record) {
        return path.join(
            this.#objectsRoot,
            record.hash.slice(0, 2),
            `.${record.hash}.${record.transaction}.installing`,
        );
    }

    #closeFd(fd, action, details = {}) {
        try {
            fs.closeSync(fd);
        } catch (err) {
            throw asIoError(action, err, details);
        }
    }

    #fsyncFd(fd, purpose, target) {
        try {
            this.#inject("before-file-fsync", { purpose, path: target });
            fs.fsyncSync(fd);
        } catch (err) {
            throw asIoError(`failed to fsync ${purpose}`, err, { path: target, purpose });
        }
    }

    #fsyncFilePath(filePath, purpose) {
        let fd;
        try {
            fd = fs.openSync(filePath, "r+");
            this.#fsyncFd(fd, purpose, filePath);
        } catch (err) {
            if (fd !== undefined) {
                try {
                    fs.closeSync(fd);
                } catch {
                    // Preserve the fsync/open failure.
                }
            }
            throw asIoError(`failed to make ${purpose} durable`, err, { path: filePath, purpose });
        }
        this.#closeFd(fd, `failed to close ${purpose} after fsync`, { path: filePath, purpose });
    }

    #ensureDirectoryDurable(dirPath, purpose) {
        const resolved = path.resolve(dirPath);
        const missing = [];
        let current = resolved;
        for (;;) {
            let stat;
            try {
                stat = fs.lstatSync(current);
            } catch (err) {
                if (!err || err.code !== "ENOENT") {
                    throw asIoError(`failed to inspect ${purpose} directory`, err, {
                        path: current,
                        purpose,
                    });
                }
                missing.push(current);
                const parent = path.dirname(current);
                if (parent === current) {
                    throw new UnsafePathError(`cannot create ${purpose} above a missing filesystem root`, {
                        path: resolved,
                    });
                }
                current = parent;
                continue;
            }
            if (stat.isSymbolicLink() || !stat.isDirectory()) {
                throw new UnsafePathError(`${purpose} path component is not a real directory`, {
                    path: current,
                });
            }
            break;
        }

        for (const candidate of missing.reverse()) {
            const parent = path.dirname(candidate);
            try {
                fs.mkdirSync(candidate, { recursive: false, mode: 0o700 });
                try {
                    fs.chmodSync(candidate, 0o700);
                } catch {
                    // Windows applies the available subset; durability remains mandatory.
                }
            } catch (err) {
                if (!err || err.code !== "EEXIST") {
                    throw asIoError(`failed to create ${purpose} directory`, err, {
                        path: candidate,
                        purpose,
                    });
                }
                const raced = fs.lstatSync(candidate);
                if (raced.isSymbolicLink() || !raced.isDirectory()) {
                    throw new UnsafePathError(`${purpose} directory was replaced during creation`, {
                        path: candidate,
                    });
                }
            }
            this.#fsyncDirectory(parent, `${purpose} parent`);
        }
        return resolved;
    }

    #fsyncDirectoryChain(startDir, stopDir, purpose) {
        const start = path.resolve(startDir);
        const stop = path.resolve(stopDir);
        if (!isInsideDir(start, stop)) {
            throw new UnsafePathError("directory durability fence escaped its trusted root", {
                start,
                stop,
                purpose,
            });
        }
        let current = start;
        let depth = 0;
        for (;;) {
            this.#fsyncDirectory(
                current,
                depth === 0 ? purpose : `${purpose} ancestor`,
            );
            if (sameCanonicalPath(current, stop)) {
                break;
            }
            const parent = path.dirname(current);
            if (parent === current) {
                throw new UnsafePathError("directory durability fence reached a filesystem root early", {
                    start,
                    stop,
                    purpose,
                });
            }
            current = parent;
            depth += 1;
        }
    }

    #fsyncDirectoryAndAncestors(dirPath, purpose) {
        const resolved = path.resolve(dirPath);
        if (!isInsideDir(resolved, this.#root)) {
            throw new UnsafePathError("directory durability fence escaped the artifact store", {
                path: resolved,
                root: this.#root,
                purpose,
            });
        }
        this.#fsyncDirectory(resolved, purpose);
        if (!sameCanonicalPath(resolved, this.#root)) {
            this.#fsyncDirectoryChain(
                path.dirname(resolved),
                this.#root,
                `${purpose} ancestor`,
            );
        }
    }

    #fsyncDirectory(dirPath, purpose) {
        let fd;
        let failure = null;
        try {
            this.#inject("before-directory-fsync", { purpose, path: dirPath });
            fd = fs.openSync(dirPath, process.platform === "win32" ? "r+" : "r");
            fs.fsyncSync(fd);
        } catch (err) {
            failure = err;
        }
        if (fd !== undefined) {
            try {
                fs.closeSync(fd);
            } catch (err) {
                if (failure === null) {
                    failure = err;
                }
            }
        }
        if (failure !== null) {
            throw asIoError(`failed to fsync directory for ${purpose}`, failure, {
                path: dirPath,
                purpose,
            });
        }
        this.#inject("after-directory-fsync", { purpose, path: dirPath });
    }

    #openCoordinationDatabase({ readOnly = false } = {}) {
        let db;
        try {
            db = new DatabaseSync(this.#coordinationFile, { readOnly });
            db.exec(`PRAGMA busy_timeout = ${COORDINATION_BUSY_TIMEOUT_MS};`);
            if (readOnly) {
                db.exec("PRAGMA query_only = ON;");
            } else {
                const journal = db.prepare("PRAGMA journal_mode = DELETE;").get();
                if (String(journal?.journal_mode ?? "").toLowerCase() !== "delete") {
                    throw new Error("failed to enable DELETE journal mode");
                }
                db.exec("PRAGMA synchronous = FULL;");
            }
            return db;
        } catch (err) {
            try {
                db?.close();
            } catch {
                // Preserve the coordination-open failure.
            }
            throw asIoError("failed to open CAS reconciliation coordination database", err, {
                path: this.#coordinationFile,
            });
        }
    }

    #readCoordinationGeneration(db) {
        const row = db.prepare(
            "SELECT generation FROM cas_reconciliation_state WHERE singleton = 1",
        ).get();
        const generation = Number(row?.generation);
        if (!Number.isSafeInteger(generation) || generation < 0) {
            throw new JournalCorruptError("CAS reconciliation generation is invalid", {
                path: this.#coordinationFile,
                generation: row?.generation ?? null,
            });
        }
        return generation;
    }

    #initializeCoordination() {
        const db = this.#openCoordinationDatabase();
        let began = false;
        let committed = false;
        try {
            db.exec("BEGIN IMMEDIATE;");
            began = true;
            const initialVersion = Number(
                db.prepare("PRAGMA user_version;").get()?.user_version,
            );
            if (initialVersion !== 0 && initialVersion !== COORDINATION_SCHEMA_VERSION) {
                throw new JournalCorruptError("CAS coordination schema version is invalid", {
                    expected: COORDINATION_SCHEMA_VERSION,
                    actual: initialVersion,
                });
            }
            db.exec(`
                CREATE TABLE IF NOT EXISTS cas_reconciliation_state (
                    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
                    generation INTEGER NOT NULL CHECK (generation >= 0)
                );
                INSERT OR IGNORE INTO cas_reconciliation_state(singleton, generation)
                VALUES(1, 0);
            `);
            if (initialVersion === 0) {
                db.exec(`PRAGMA user_version = ${COORDINATION_SCHEMA_VERSION};`);
            }
            const version = Number(db.prepare("PRAGMA user_version;").get()?.user_version);
            if (version !== COORDINATION_SCHEMA_VERSION) {
                throw new JournalCorruptError("CAS coordination schema version is invalid", {
                    expected: COORDINATION_SCHEMA_VERSION,
                    actual: version,
                });
            }
            const columns = db.prepare(
                "PRAGMA table_info('cas_reconciliation_state');",
            ).all().map((row) => ({
                name: String(row.name),
                type: String(row.type).toUpperCase(),
                notNull: Number(row.notnull),
                primaryKey: Number(row.pk),
            }));
            if (canonicalize(columns) !== canonicalize([
                { name: "singleton", type: "INTEGER", notNull: 0, primaryKey: 1 },
                { name: "generation", type: "INTEGER", notNull: 1, primaryKey: 0 },
            ])) {
                throw new JournalCorruptError("CAS coordination table schema is invalid", {
                    columns,
                });
            }
            const integrityRows = db.prepare("PRAGMA integrity_check;").all();
            if (integrityRows.length !== 1
                || String(Object.values(integrityRows[0] ?? {})[0] ?? "") !== "ok") {
                throw new JournalCorruptError("CAS coordination database failed integrity_check", {
                    rows: integrityRows,
                });
            }
            this.#readCoordinationGeneration(db);
            db.exec("COMMIT;");
            began = false;
            committed = true;
        } catch (err) {
            if (began) {
                try {
                    db.exec("ROLLBACK;");
                } catch {
                    // Preserve the initialization failure.
                }
            }
            throw err;
        } finally {
            try {
                db.close();
            } catch (err) {
                if (committed) {
                    throw asIoError(
                        "failed to close CAS reconciliation coordination database",
                        err,
                        { path: this.#coordinationFile },
                    );
                }
            }
        }
        this.#fsyncFilePath(this.#coordinationFile, "CAS reconciliation coordination database");
        this.#fsyncDirectoryChain(
            this.#metadataRoot,
            this.#root,
            "CAS reconciliation coordination database parent",
        );
    }

    #coordinationGeneration() {
        const db = this.#openCoordinationDatabase({ readOnly: true });
        try {
            return this.#readCoordinationGeneration(db);
        } finally {
            db.close();
        }
    }

    #withCoordinationTransaction(work) {
        const db = this.#openCoordinationDatabase();
        let began = false;
        let changed = false;
        let generation;
        let result;
        let committed = false;
        try {
            db.exec("BEGIN IMMEDIATE;");
            began = true;
            generation = this.#readCoordinationGeneration(db);
            let nextGeneration = generation;
            result = work({
                generation,
                bumpGeneration() {
                    if (nextGeneration >= Number.MAX_SAFE_INTEGER) {
                        throw new JournalCorruptError(
                            "CAS reconciliation generation exhausted the safe integer range",
                        );
                    }
                    nextGeneration += 1;
                    changed = true;
                    return nextGeneration;
                },
            });
            if (changed) {
                db.prepare(`
                    UPDATE cas_reconciliation_state
                    SET generation = ?
                    WHERE singleton = 1
                `).run(nextGeneration);
            }
            db.exec("COMMIT;");
            began = false;
            committed = true;
        } catch (err) {
            if (began) {
                try {
                    db.exec("ROLLBACK;");
                } catch (rollbackErr) {
                    if (err && typeof err === "object") {
                        err.rollbackError = rollbackErr;
                    }
                }
            }
            if (err instanceof CruciblePersistenceError) {
                throw err;
            }
            throw asIoError("CAS reconciliation transaction failed", err, {
                path: this.#coordinationFile,
            });
        } finally {
            try {
                db.close();
            } catch (err) {
                if (committed) {
                    throw asIoError(
                        "failed to close CAS reconciliation coordination database",
                        err,
                        { path: this.#coordinationFile },
                    );
                }
            }
        }
        if (changed) {
            this.#fsyncFilePath(
                this.#coordinationFile,
                "CAS reconciliation coordination database",
            );
            this.#fsyncDirectoryChain(
                this.#metadataRoot,
                this.#root,
                "CAS reconciliation coordination database parent",
            );
        }
        return { result, generation, changed };
    }

    #unlinkPath(filePath, action) {
        try {
            fs.unlinkSync(filePath);
            return true;
        } catch (err) {
            if (err && err.code === "ENOENT") {
                return false;
            }
            throw asIoError(action, err, { path: filePath });
        }
    }

    #writeImmutableRecord(finalPath, value, purpose, _syncAncestor = null) {
        const bytes = Buffer.from(canonicalize(value), "utf8");
        const parent = path.dirname(finalPath);
        this.#ensureDirectoryDurable(parent, purpose);

        const verifyExisting = () => {
            let existing;
            try {
                existing = fs.readFileSync(finalPath);
            } catch (err) {
                throw asIoError(`failed to read existing ${purpose}`, err, { path: finalPath });
            }
            if (!existing.equals(bytes)) {
                throw new JournalCorruptError(`existing ${purpose} disagrees with canonical state`, {
                    path: finalPath,
                });
            }
        };

        if (fs.existsSync(finalPath)) {
            verifyExisting();
            this.#fsyncFilePath(finalPath, purpose);
            this.#fsyncDirectoryAndAncestors(parent, `${purpose} parent`);
            return true;
        }

        const tempPath = path.join(
            parent,
            `.${path.basename(finalPath)}.${randomBytes(8).toString("hex")}.tmp`,
        );
        let fd;
        try {
            fd = fs.openSync(tempPath, "wx", 0o600);
            let offset = 0;
            while (offset < bytes.length) {
                offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
            }
            this.#fsyncFd(fd, `${purpose} temporary file`, tempPath);
            this.#closeFd(fd, `failed to close ${purpose} temporary file`, { path: tempPath });
            fd = undefined;
        } catch (err) {
            if (fd !== undefined) {
                try {
                    fs.closeSync(fd);
                } catch {
                    // Preserve the write/fsync failure.
                }
            }
            try {
                this.#unlinkPath(tempPath, `failed to remove incomplete ${purpose} temporary file`);
            } catch {
                // Preserve the primary failure.
            }
            throw asIoError(`failed to write ${purpose}`, err, { path: finalPath });
        }

        let existed = false;
        try {
            fs.linkSync(tempPath, finalPath);
        } catch (err) {
            if (err && err.code === "EEXIST") {
                existed = true;
            } else if (err && (err.code === "EPERM"
                || err.code === "ENOSYS"
                || err.code === "EXDEV"
                || err.code === "EMLINK")) {
                try {
                    fs.copyFileSync(tempPath, finalPath, fs.constants.COPYFILE_EXCL);
                } catch (copyErr) {
                    if (copyErr && copyErr.code === "EEXIST") {
                        existed = true;
                    } else {
                        throw asIoError(`failed to install ${purpose}`, copyErr, { path: finalPath });
                    }
                }
            } else {
                throw asIoError(`failed to install ${purpose}`, err, { path: finalPath });
            }
        }

        if (existed) {
            verifyExisting();
        }
        this.#fsyncFilePath(finalPath, purpose);
        this.#fsyncDirectoryAndAncestors(parent, `${purpose} parent`);
        const removedTemp = this.#unlinkPath(tempPath, `failed to remove ${purpose} temporary file`);
        if (removedTemp) {
            this.#fsyncDirectoryAndAncestors(parent, `${purpose} temporary cleanup`);
        }
        return existed;
    }

    #writeStagingRecord(staged) {
        const record = validateStagingRecord({
            type: JOURNAL_TYPE,
            version: JOURNAL_VERSION,
            state: JOURNAL_STATES.STAGING,
            algo: ALGO,
            transaction: staged.transaction,
            staging: path.basename(staged.stagingPath),
            object: objectIdFor(staged.hash),
            size: staged.size,
            createdAt: normalizeCreatedAt(
                this.#now(),
                "installation.createdAt",
            ),
        }, { limits: this.#limits });
        this.#writeImmutableRecord(
            this.#journalPath(record.transaction),
            record,
            "installation staging journal",
            this.#metadataRoot,
        );
        this.#inject("staging-journal-durable", {
            transaction: record.transaction,
            object: record.object,
        });
        return record;
    }

    #writeStateMarker(record, state) {
        const value = stateMarkerValue(record.hash, record.size, state);
        this.#writeImmutableRecord(
            this.#markerPath(record.hash, state),
            value,
            `${state} installation marker`,
            this.#installationsRoot,
        );
        this.#inject(`${state}-marker-durable`, {
            transaction: record.transaction ?? null,
            object: record.object,
        });
        return value;
    }

    #prepareStaged(staged) {
        this.#inject("stage-file-durable", {
            transaction: staged.transaction,
            object: objectIdFor(staged.hash),
        });
        this.#fsyncDirectoryAndAncestors(this.#stagingRoot, "staging entry");
        this.#inject("stage-directory-durable", {
            transaction: staged.transaction,
            object: objectIdFor(staged.hash),
        });
        const record = this.#writeStagingRecord(staged);
        return { ...staged, record };
    }

    // Stream `bytes` into a unique fsync'd staging file, returning its hash+size.
    #stageBytes(bytes) {
        const buf = toBuffer(bytes);
        if (buf.length > this.#limits.maxFileBytes) {
            throw new LimitExceededError("object exceeds maximum object size", {
                size: buf.length,
                maxFileBytes: this.#limits.maxFileBytes,
            });
        }
        const { transaction, stagingPath } = this.#newStagingTarget();
        let fd;
        try {
            fd = fs.openSync(stagingPath, "wx", 0o600);
            let off = 0;
            while (off < buf.length) {
                off += fs.writeSync(fd, buf, off, buf.length - off);
            }
            this.#fsyncFd(fd, "staging object file", stagingPath);
        } catch (err) {
            if (fd !== undefined) {
                try {
                    fs.closeSync(fd);
                } catch {
                    // Preserve the staging failure.
                }
            }
            try {
                this.#unlinkPath(stagingPath, "failed to remove incomplete staging object");
            } catch {
                // Preserve the staging failure.
            }
            throw asIoError("failed to stage object bytes", err, { path: stagingPath });
        }
        this.#closeFd(fd, "failed to close staged object", { path: stagingPath });
        const hash = createHash(ALGO).update(buf).digest("hex");
        return { transaction, stagingPath, hash, size: buf.length };
    }

    // Stream an existing source file into a unique fsync'd staging file while
    // hashing it in a single pass (never loads the whole file into memory).
    #stageFile(srcPath, options = {}) {
        const rootReal = options.rootReal ?? null;
        const hook = options.afterFileOpen ?? null;
        const pathBeforeStat = fs.lstatSync(srcPath, { bigint: true });
        if (pathBeforeStat.isSymbolicLink()) {
            throw new SymlinkRejectedError("refusing a symlink/junction source", { srcPath });
        }
        if (!pathBeforeStat.isFile()) {
            throw new UnsafePathError("source is not a regular file", { srcPath });
        }
        const realBefore = fs.realpathSync.native(srcPath);
        if (rootReal !== null && !isInsideDir(realBefore, rootReal)) {
            throw new UnsafePathError("file escapes snapshot root", {
                srcPath,
                real: realBefore,
            });
        }
        const pathBefore = stableIdentity(pathBeforeStat, srcPath);
        const { transaction, stagingPath } = this.#newStagingTarget();
        const rfd = fs.openSync(srcPath, "r");
        let wfd;
        try {
            const openedStat = fs.fstatSync(rfd, { bigint: true });
            if (!openedStat.isFile()) {
                throw new UnsafePathError("opened snapshot source is not a regular file", { srcPath });
            }
            const opened = stableIdentity(openedStat, srcPath);
            assertStableIdentity(pathBefore, opened, srcPath);
            if (hook !== null) {
                hook({ path: srcPath, fd: rfd });
            }
            wfd = fs.openSync(stagingPath, "wx", 0o600);
        } catch (err) {
            fs.closeSync(rfd);
            safeUnlink(stagingPath);
            throw err;
        }
        const hash = createHash(ALGO);
        const buf = Buffer.allocUnsafe(STAGE_CHUNK);
        let size = 0;
        try {
            for (;;) {
                const n = fs.readSync(rfd, buf, 0, buf.length, null);
                if (n === 0) {
                    break;
                }
                size += n;
                if (size > this.#limits.maxFileBytes) {
                    throw new LimitExceededError("file exceeds maximum object size", {
                        srcPath,
                        maxFileBytes: this.#limits.maxFileBytes,
                    });
                }
                let off = 0;
                while (off < n) {
                    off += fs.writeSync(wfd, buf, off, n - off);
                }
                hash.update(buf.subarray(0, n));
            }
            this.#fsyncFd(wfd, "staging object file", stagingPath);
            const handleAfter = stableIdentity(fs.fstatSync(rfd, { bigint: true }), srcPath);
            assertStableIdentity(pathBefore, handleAfter, srcPath);
            const pathAfterStat = fs.lstatSync(srcPath, { bigint: true });
            if (pathAfterStat.isSymbolicLink() || !pathAfterStat.isFile()) {
                throw new SourceChangedError(
                    "snapshot source changed type during ingestion",
                    { path: srcPath },
                );
            }
            const pathAfter = stableIdentity(pathAfterStat, srcPath);
            assertStableIdentity(pathBefore, pathAfter, srcPath);
            const realAfter = fs.realpathSync.native(srcPath);
            if (!sameCanonicalPath(realBefore, realAfter)
                || (rootReal !== null && !isInsideDir(realAfter, rootReal))) {
                throw new SourceChangedError(
                    "snapshot source realpath or containment changed during ingestion",
                    { path: srcPath, realBefore, realAfter, rootReal },
                );
            }
        } catch (err) {
            fs.closeSync(rfd);
            fs.closeSync(wfd);
            safeUnlink(stagingPath);
            throw err;
        }
        fs.closeSync(rfd);
        fs.closeSync(wfd);
        return { transaction, stagingPath, hash: hash.digest("hex"), size };
    }

    #validateObjectSlot(dest, record) {
        const check = this.#hashExisting(dest);
        if (check === null) {
            return { ok: false, reason: "missing" };
        }
        if (check.hash !== record.hash || check.size !== record.size) {
            return {
                ok: false,
                reason: "corrupt",
                actualHash: check.hash,
                actualSize: check.size,
            };
        }
        return { ok: true, size: check.size };
    }

    #installObjectEntry(record, sourcePath) {
        const dir = path.join(this.#objectsRoot, record.hash.slice(0, 2));
        this.#ensureDirectoryDurable(dir, "object prefix");
        const dest = path.join(dir, record.hash);
        let existed = false;
        let method = "link";

        try {
            this.#inject("before-object-link", {
                transaction: record.transaction,
                object: record.object,
                sourcePath,
                dest,
            });
            fs.linkSync(sourcePath, dest);
        } catch (err) {
            if (err && err.code === "EEXIST") {
                existed = true;
            } else if (err && (err.code === "EPERM" || err.code === "ENOSYS" || err.code === "EXDEV" || err.code === "EMLINK")) {
                method = "rename-copy";
                const candidate = this.#candidatePath(record);
                if (sourcePath !== candidate) {
                    try {
                        this.#inject("before-object-rename", {
                            transaction: record.transaction,
                            object: record.object,
                            sourcePath,
                            candidate,
                            dest,
                        });
                        fs.renameSync(sourcePath, candidate);
                        sourcePath = candidate;
                        this.#inject("object-renamed", {
                            transaction: record.transaction,
                            object: record.object,
                            candidate,
                        });
                    } catch (renameErr) {
                        if (renameErr && renameErr.code === "EEXIST") {
                            const candidateCheck = this.#validateObjectSlot(candidate, record);
                            if (!candidateCheck.ok) {
                                throw new ObjectCorruptError(
                                    "fallback installation candidate does not match its journal",
                                    {
                                        object: record.object,
                                        candidate,
                                        reason: candidateCheck.reason,
                                    },
                                );
                            }
                            sourcePath = candidate;
                        } else {
                            throw asIoError("failed to move staged object into installation directory", renameErr, {
                                object: record.object,
                                sourcePath,
                                candidate,
                            });
                        }
                    }
                }
                try {
                    this.#inject("before-object-copy", {
                        transaction: record.transaction,
                        object: record.object,
                        sourcePath,
                        dest,
                    });
                    fs.copyFileSync(sourcePath, dest, fs.constants.COPYFILE_EXCL);
                    this.#inject("object-copied", {
                        transaction: record.transaction,
                        object: record.object,
                        dest,
                    });
                } catch (copyErr) {
                    if (copyErr && copyErr.code === "EEXIST") {
                        existed = true;
                    } else {
                        throw asIoError("failed to copy staged object into its no-clobber slot", copyErr, {
                            object: record.object,
                            sourcePath,
                            dest,
                        });
                    }
                }
            } else {
                throw asIoError("failed to link staged object into its no-clobber slot", err, {
                    object: record.object,
                    sourcePath,
                    dest,
                });
            }
        }

        this.#inject(existed ? "object-slot-existing" : "object-entry-installed", {
            transaction: record.transaction,
            object: record.object,
            method,
            dest,
        });
        const check = this.#validateObjectSlot(dest, record);
        if (!check.ok) {
            throw new ObjectCorruptError("installed object bytes do not match their content address", {
                object: record.object,
                expectedHash: record.hash,
                expectedSize: record.size,
                actualHash: check.actualHash,
                actualSize: check.actualSize,
                reason: check.reason,
            });
        }
        return { dest, dir, existed, method, sourcePath };
    }

    #makeObjectDurable(record, dest, dir) {
        this.#fsyncFilePath(dest, "installed object file");
        this.#inject("object-file-durable", {
            transaction: record.transaction,
            object: record.object,
            dest,
        });
        this.#fsyncDirectory(dir, "object parent");
        this.#fsyncDirectoryAndAncestors(this.#objectsRoot, "object prefix parent");
        this.#inject("object-directory-durable", {
            transaction: record.transaction,
            object: record.object,
            dest,
        });
    }

    #cleanupTransaction(record) {
        let objectDirChanged = false;
        const stagingRemoved = this.#unlinkPath(
            path.join(this.#stagingRoot, record.staging),
            "failed to remove completed staging object",
        );
        objectDirChanged = this.#unlinkPath(
            this.#candidatePath(record),
            "failed to remove completed installation candidate",
        ) || objectDirChanged;
        if (stagingRemoved) {
            this.#fsyncDirectoryAndAncestors(this.#stagingRoot, "staging cleanup");
        }
        if (objectDirChanged) {
            this.#fsyncDirectoryAndAncestors(
                path.join(this.#objectsRoot, record.hash.slice(0, 2)),
                "installation candidate cleanup",
            );
        }
        const journalRemoved = this.#unlinkPath(
            this.#journalPath(record.transaction),
            "failed to remove completed installation journal",
        );
        if (journalRemoved) {
            this.#fsyncDirectoryAndAncestors(
                this.#journalRoot,
                "installation journal cleanup",
            );
        }
        this.#inject("transaction-cleaned", {
            transaction: record.transaction,
            object: record.object,
        });
    }

    #finishInstall(record, contentType = null, sourcePath = null) {
        const actualSource = sourcePath
            ?? (fs.existsSync(this.#candidatePath(record))
                ? this.#candidatePath(record)
                : path.join(this.#stagingRoot, record.staging));
        const installed = this.#installObjectEntry(record, actualSource);
        this.#makeObjectDurable(record, installed.dest, installed.dir);
        this.#writeStateMarker(record, JOURNAL_STATES.INSTALLED);
        this.#cleanupTransaction(record);
        return {
            id: record.object,
            algo: ALGO,
            hash: record.hash,
            size: record.size,
            path: installed.dest,
            relativePath: objectRelPath(record.hash),
            contentType: contentType ?? null,
            existed: installed.existed,
            durable: true,
        };
    }

    #commitStaged(staged, contentType = null) {
        const prepared = this.#prepareStaged(staged);
        return this.#finishInstall(prepared.record, contentType, prepared.stagingPath);
    }

    // Streaming hash of an already-stored file; null if it does not exist.
    #hashExisting(absPath) {
        let fd;
        try {
            fd = fs.openSync(absPath, "r");
        } catch (err) {
            if (err && err.code === "ENOENT") {
                return null;
            }
            throw err;
        }
        const hash = createHash(ALGO);
        const buf = Buffer.allocUnsafe(STAGE_CHUNK);
        let size = 0;
        try {
            for (;;) {
                const n = fs.readSync(fd, buf, 0, buf.length, null);
                if (n === 0) {
                    break;
                }
                hash.update(buf.subarray(0, n));
                size += n;
            }
        } finally {
            fs.closeSync(fd);
        }
        return { hash: hash.digest("hex"), size };
    }

    // --- public write API --------------------------------------------------

    // Store arbitrary bytes; returns durable object metadata. Idempotent: a
    // second put of identical content returns { existed: true } without
    // overwriting the object.
    putBytes(input, options = {}) {
        return this.#commitStaged(this.#stageBytes(input), options.contentType);
    }

    // Store the contents of an existing file (streamed, never fully buffered).
    putFile(srcPath, options = {}) {
        if (typeof srcPath !== "string" || srcPath.length === 0) {
            throw new InvalidArgumentError("srcPath must be a non-empty string", { srcPath });
        }
        const lst = fs.lstatSync(srcPath);
        if (lst.isSymbolicLink()) {
            throw new SymlinkRejectedError("refusing to ingest a symlink/junction as an object", { srcPath });
        }
        if (!lst.isFile()) {
            throw new UnsafePathError("source is not a regular file", { srcPath });
        }
        return this.#commitStaged(this.#stageFile(srcPath), options.contentType);
    }

    // Store bytes drained from a Node Readable stream.
    async putStream(readable, options = {}) {
        if (!readable || typeof readable[Symbol.asyncIterator] !== "function") {
            throw new InvalidArgumentError("putStream requires an async-iterable readable stream");
        }
        const { transaction, stagingPath } = this.#newStagingTarget();
        let wfd;
        const hash = createHash(ALGO);
        let size = 0;
        try {
            wfd = fs.openSync(stagingPath, "wx", 0o600);
            for await (const chunk of readable) {
                const b = toBuffer(chunk);
                size += b.length;
                if (size > this.#limits.maxFileBytes) {
                    throw new LimitExceededError("stream exceeds maximum object size", {
                        maxFileBytes: this.#limits.maxFileBytes,
                    });
                }
                let off = 0;
                while (off < b.length) {
                    off += fs.writeSync(wfd, b, off, b.length - off);
                }
                hash.update(b);
            }
            this.#fsyncFd(wfd, "staging object file", stagingPath);
        } catch (err) {
            if (wfd !== undefined) {
                try {
                    fs.closeSync(wfd);
                } catch {
                    // Preserve the stream/staging failure.
                }
            }
            try {
                this.#unlinkPath(stagingPath, "failed to remove incomplete streamed staging object");
            } catch {
                // Preserve the stream/staging failure.
            }
            throw asIoError("failed to stage streamed object", err, { path: stagingPath });
        }
        this.#closeFd(wfd, "failed to close streamed staging object", { path: stagingPath });
        return this.#commitStaged({
            transaction,
            stagingPath,
            hash: hash.digest("hex"),
            size,
        }, options.contentType);
    }

    // --- public read/verify API -------------------------------------------

    // Read an object's bytes, verifying the content address by default.
    readObject(id, options = {}) {
        const verify = options.verify !== false;
        const abs = this.objectPath(id);
        let bytes;
        try {
            bytes = fs.readFileSync(abs);
        } catch (err) {
            if (err && err.code === "ENOENT") {
                throw new ObjectNotFoundError("object not found", { id });
            }
            throw err;
        }
        if (verify) {
            const { hex } = parseObjectId(id);
            const actual = createHash(ALGO).update(bytes).digest("hex");
            if (actual !== hex) {
                throw new ObjectCorruptError("object bytes do not match their content address", {
                    id,
                    expected: hex,
                    actual,
                });
            }
        }
        return bytes;
    }

    // Non-throwing integrity probe. Returns { id, ok, size?, reason? }.
    verifyObject(id) {
        const { hex } = parseObjectId(id);
        const abs = this.objectPath(id);
        const res = this.#hashExisting(abs);
        if (res === null) {
            return { id, ok: false, reason: "missing" };
        }
        if (res.hash !== hex) {
            return { id, ok: false, reason: "corrupt", actualHash: res.hash, size: res.size };
        }
        return { id, ok: true, size: res.size };
    }

    // --- snapshots ---------------------------------------------------------

    // Ingest a candidate directory into an immutable canonical snapshot. Walks
    // the tree in sorted order, rejects symlinks/reparse-like entries and any
    // escaping path, enforces file/byte/path-length caps, stores every file and
    // a canonical manifest in the CAS, and returns the snapshot id + manifest.
    // Nothing under sourceDir is ever executed.
    ingestDirectory(options = {}) {
        const { sourceDir, denyRoots, env, hooks = null } = options;
        if (typeof sourceDir !== "string" || sourceDir.trim().length === 0) {
            throw new InvalidArgumentError("sourceDir must be a non-empty string", { sourceDir });
        }
        let resolvedRoot;
        try {
            resolvedRoot = assertLocalDatabasePath(sourceDir, { denyRoots, env });
        } catch (err) {
            if (err instanceof CruciblePersistenceError && err.code !== ARTIFACT_STORE_ERROR_CODES.INVALID_ARGUMENT) {
                throw err;
            }
            throw new InvalidArgumentError(`invalid sourceDir: ${err.message}`, { sourceDir });
        }

        const rootLst = fs.lstatSync(resolvedRoot, { bigint: true });
        if (rootLst.isSymbolicLink()) {
            throw new SymlinkRejectedError("sourceDir is a symlink/junction", { sourceDir });
        }
        if (!rootLst.isDirectory()) {
            throw new InvalidArgumentError("sourceDir is not a directory", { sourceDir });
        }
        const rootReal = fs.realpathSync.native(resolvedRoot);
        if (!sameCanonicalPath(path.resolve(resolvedRoot), rootReal)) {
            throw new SymlinkRejectedError(
                "sourceDir resolves through a symlink, junction, or reparse-point ancestor",
                { sourceDir, resolvedRoot, rootReal },
            );
        }
        const rootIdentity = stableIdentity(rootLst, resolvedRoot);

        const counters = { files: 0, bytes: 0 };
        const entries = [];
        this.#walk(rootReal, rootReal, [], 0, counters, entries, hooks);
        const rootAfter = fs.lstatSync(resolvedRoot, { bigint: true });
        assertStableIdentity(rootIdentity, stableIdentity(rootAfter, resolvedRoot), resolvedRoot);
        const rootRealAfter = fs.realpathSync.native(resolvedRoot);
        if (!sameCanonicalPath(rootReal, rootRealAfter)) {
            throw new SourceChangedError("snapshot source root changed during ingestion", {
                sourceDir,
                rootReal,
                rootRealAfter,
            });
        }

        // Deterministic order: sort by posix relative path.
        entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

        const manifest = validateSnapshotManifest({
            type: SNAPSHOT_TYPE,
            version: SNAPSHOT_VERSION,
            algo: ALGO,
            fileCount: entries.length,
            totalBytes: counters.bytes,
            entries,
        }, { limits: this.#limits });
        const manifestBytes = Buffer.from(canonicalize(manifest), "utf8");
        const manifestMeta = this.putBytes(manifestBytes, { contentType: "application/vnd.crucible.snapshot+json" });

        return {
            snapshot: manifestMeta.id,
            manifestId: manifestMeta.id,
            manifest,
            fileCount: entries.length,
            totalBytes: counters.bytes,
        };
    }

    #walk(rootReal, dirAbs, relSegments, depth, counters, out, hooks) {
        if (depth > this.#limits.maxDepth) {
            throw new LimitExceededError("snapshot exceeds maximum directory depth", {
                maxDepth: this.#limits.maxDepth,
            });
        }
        const dirBeforeStat = fs.lstatSync(dirAbs, { bigint: true });
        if (dirBeforeStat.isSymbolicLink() || !dirBeforeStat.isDirectory()) {
            throw new SymlinkRejectedError("snapshot directory changed into a link/non-directory", {
                path: dirAbs,
            });
        }
        const dirBefore = stableIdentity(dirBeforeStat, dirAbs);
        const dirRealBefore = fs.realpathSync.native(dirAbs);
        if (!isInsideDir(dirRealBefore, rootReal)) {
            throw new UnsafePathError("directory escapes snapshot root", {
                path: dirAbs,
                real: dirRealBefore,
            });
        }
        const dirents = fs.readdirSync(dirAbs, { withFileTypes: true });
        dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

        for (const dirent of dirents) {
            const name = dirent.name;
            assertSafeComponent(name, dirAbs);
            const childAbs = path.join(dirAbs, name);
            const childRel = [...relSegments, name];
            const relPosix = childRel.join("/");
            if (relPosix.length > this.#limits.maxPathLength) {
                throw new LimitExceededError("snapshot path exceeds maximum length", {
                    relPath: relPosix,
                    maxPathLength: this.#limits.maxPathLength,
                });
            }

            // Always lstat: reject symlinks/junctions/reparse points BEFORE we
            // touch the target. Never follow.
            const lst = fs.lstatSync(childAbs, { bigint: true });
            if (lst.isSymbolicLink()) {
                throw new SymlinkRejectedError("refusing symlink/junction inside snapshot source", {
                    relPath: relPosix,
                });
            }

            if (lst.isDirectory()) {
                // Defence in depth beyond the symlink rejection above: the
                // canonical child must still live under the canonical root.
                const real = fs.realpathSync.native(childAbs);
                if (!isInsideDir(real, rootReal)) {
                    throw new UnsafePathError("directory escapes snapshot root", { relPath: relPosix, real });
                }
                this.#walk(rootReal, childAbs, childRel, depth + 1, counters, out, hooks);
                continue;
            }

            if (!lst.isFile()) {
                throw new UnsafePathError("refusing non-regular file (device/fifo/socket/reparse)", {
                    relPath: relPosix,
                });
            }

            counters.files += 1;
            if (counters.files > this.#limits.maxFiles) {
                throw new LimitExceededError("snapshot exceeds maximum file count", {
                    maxFiles: this.#limits.maxFiles,
                });
            }
            const staged = this.#stageFile(childAbs, {
                rootReal,
                afterFileOpen: typeof hooks?.afterFileOpen === "function"
                    ? hooks.afterFileOpen
                    : null,
            });
            const meta = this.#commitStaged(staged, null);
            counters.bytes += meta.size;
            if (counters.bytes > this.#limits.maxTotalBytes) {
                throw new LimitExceededError("snapshot exceeds maximum total bytes", {
                    maxTotalBytes: this.#limits.maxTotalBytes,
                });
            }
            out.push({ path: relPosix, size: meta.size, object: meta.id });
        }
        const dirAfterStat = fs.lstatSync(dirAbs, { bigint: true });
        if (dirAfterStat.isSymbolicLink() || !dirAfterStat.isDirectory()) {
            throw new SourceChangedError("snapshot directory changed type during ingestion", {
                path: dirAbs,
            });
        }
        assertStableIdentity(dirBefore, stableIdentity(dirAfterStat, dirAbs), dirAbs);
        const dirRealAfter = fs.realpathSync.native(dirAbs);
        if (!sameCanonicalPath(dirRealBefore, dirRealAfter)
            || !isInsideDir(dirRealAfter, rootReal)) {
            throw new SourceChangedError(
                "snapshot directory realpath or containment changed during ingestion",
                { path: dirAbs, dirRealBefore, dirRealAfter, rootReal },
            );
        }
    }

    // Load and validate a snapshot manifest from the CAS.
    loadManifest(snapshotId) {
        const bytes = this.readObject(snapshotId, { verify: true });
        let parsed;
        try {
            parsed = JSON.parse(bytes.toString("utf8"));
        } catch (err) {
            throw new SnapshotInvalidError("snapshot manifest is not valid JSON", { snapshotId, cause: err.message });
        }
        return validateSnapshotManifest(parsed, {
            snapshotId,
            rawBytes: bytes,
            limits: this.#limits,
        });
    }

    // Materialize through a private sibling directory, then atomically publish
    // only the fully verified tree. Every path component is reparse-checked and
    // rebound to a stable filesystem identity before writes and publication.
    materializeSnapshot(options = {}) {
        const {
            snapshot,
            destDir,
            readOnly = true,
            hooks = null,
        } = options;
        if (typeof destDir !== "string" || destDir.trim().length === 0) {
            throw new InvalidArgumentError("destDir must be a non-empty string", { destDir });
        }
        if (hooks !== null && (typeof hooks !== "object" || Array.isArray(hooks))) {
            throw new InvalidArgumentError("materialization hooks must be an object or null");
        }
        const destResolved = assertLocalDatabasePath(destDir);
        if (materializationLstatOrNull(destResolved) !== null) {
            throw new DestinationExistsError("destination already exists; refusing to materialize over it", {
                destDir: destResolved,
            });
        }
        const manifest = this.loadManifest(snapshot);
        const resolvedEntries = manifest.entries.map((entry) => ({
            entry,
            segments: entry.path.split("/"),
        }));

        const parentPath = path.dirname(destResolved);
        if (parentPath === destResolved) {
            throw new UnsafePathError("materialization destination cannot be a filesystem root", {
                destDir: destResolved,
            });
        }
        const parent = ensureMaterializationDirectory(parentPath);
        let stagePath;
        let stageAnchor;
        for (let attempt = 0; attempt < 32; attempt += 1) {
            const candidate = path.join(
                parent.path,
                `.crucible-materialize-${randomBytes(12).toString("hex")}.stage`,
            );
            try {
                fs.mkdirSync(candidate, { recursive: false, mode: 0o700 });
                try {
                    fs.chmodSync(candidate, 0o700);
                } catch {
                    // Best available Windows permissions.
                }
                const stage = assertMaterializationPath(candidate, "directory");
                assertMaterializationAnchor(
                    parent.anchor,
                    assertMaterializationPath(parent.path, "directory").anchor,
                    parent.path,
                );
                stagePath = stage.path;
                stageAnchor = stage.anchor;
                break;
            } catch (err) {
                if (err && err.code === "EEXIST") {
                    continue;
                }
                throw err;
            }
        }
        if (stagePath === undefined) {
            throw new ArtifactStoreError(
                ARTIFACT_STORE_ERROR_CODES.IO_ERROR,
                "could not allocate private materialization staging",
                { destDir: destResolved },
            );
        }

        let published = false;
        let fileCount = 0;
        let totalBytes = 0;
        try {
            for (const { entry, segments } of resolvedEntries) {
                assertMaterializationRoot(stagePath, stageAnchor, parent.path, parent.anchor);
                const bytes = this.readObject(entry.object, { verify: true });
                if (bytes.length !== entry.size) {
                    throw new ObjectCorruptError("object size disagrees with manifest", {
                        relPath: entry.path,
                        object: entry.object,
                        expected: entry.size,
                        actual: bytes.length,
                    });
                }

                let targetParent = stagePath;
                for (const segment of segments.slice(0, -1)) {
                    assertSafeComponent(segment, entry.path);
                    targetParent = path.join(targetParent, segment);
                    let stat = materializationLstatOrNull(targetParent);
                    if (stat === null) {
                        fs.mkdirSync(targetParent, { recursive: false, mode: 0o700 });
                        try {
                            fs.chmodSync(targetParent, 0o700);
                        } catch {
                            // Best available Windows permissions.
                        }
                        stat = fs.lstatSync(targetParent, { bigint: true });
                    }
                    if (stat.isSymbolicLink() || !stat.isDirectory()) {
                        throw new SymlinkRejectedError(
                            "materialization staging component changed into a link/non-directory",
                            { relPath: entry.path, path: targetParent },
                        );
                    }
                    const real = fs.realpathSync.native(targetParent);
                    if (!sameCanonicalPath(path.resolve(targetParent), path.resolve(real))
                        || !isInsideDir(real, stagePath)) {
                        throw new UnsafePathError("materialization staging component escapes its root", {
                            relPath: entry.path,
                            path: targetParent,
                            real,
                        });
                    }
                    assertMaterializationRoot(stagePath, stageAnchor, parent.path, parent.anchor);
                }

                const targetAbs = path.join(targetParent, segments.at(-1));
                this.#inject("before-materialization-file-write", {
                    snapshot,
                    relPath: entry.path,
                    path: targetAbs,
                    stagingDir: stagePath,
                    destDir: destResolved,
                });
                if (typeof hooks?.beforeFileWrite === "function") {
                    hooks.beforeFileWrite({
                        snapshot,
                        relPath: entry.path,
                        path: targetAbs,
                        stagingDir: stagePath,
                        destDir: destResolved,
                    });
                }
                assertMaterializationRoot(stagePath, stageAnchor, parent.path, parent.anchor);
                const checkedParent = assertMaterializationPath(targetParent, "directory");
                if (!isInsideDir(checkedParent.real, stagePath)) {
                    throw new UnsafePathError("materialization target parent escaped staging", {
                        relPath: entry.path,
                        real: checkedParent.real,
                    });
                }

                const fd = fs.openSync(targetAbs, "wx", 0o600);
                try {
                    const opened = fs.fstatSync(fd, { bigint: true });
                    const rebound = fs.lstatSync(targetAbs, { bigint: true });
                    if (!opened.isFile() || rebound.isSymbolicLink() || !rebound.isFile()) {
                        throw new UnsafePathError("materialization target is not a regular file", {
                            relPath: entry.path,
                        });
                    }
                    assertStableIdentity(
                        stableIdentity(opened, targetAbs),
                        stableIdentity(rebound, targetAbs),
                        targetAbs,
                    );
                    const targetReal = fs.realpathSync.native(targetAbs);
                    if (!sameCanonicalPath(path.resolve(targetAbs), path.resolve(targetReal))
                        || !isInsideDir(targetReal, stagePath)) {
                        throw new UnsafePathError("opened materialization target escapes staging", {
                            relPath: entry.path,
                            targetReal,
                        });
                    }
                    let offset = 0;
                    while (offset < bytes.length) {
                        offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
                    }
                    fs.fsyncSync(fd);
                } catch (err) {
                    try {
                        fs.closeSync(fd);
                    } catch {
                        // Preserve the binding/write failure.
                    }
                    try {
                        fs.unlinkSync(targetAbs);
                    } catch {
                        // Preserve the binding/write failure.
                    }
                    throw err;
                }
                fs.closeSync(fd);
                assertMaterializationRoot(stagePath, stageAnchor, parent.path, parent.anchor);
                assertMaterializationPath(targetAbs, "file");
                if (readOnly) {
                    try {
                        fs.chmodSync(targetAbs, 0o444);
                    } catch {
                        // Best-effort read-only; Windows honours the read-only bit.
                    }
                }
                fileCount += 1;
                totalBytes += bytes.length;
            }

            this.#inject("before-materialization-publish", {
                snapshot,
                stagingDir: stagePath,
                destDir: destResolved,
            });
            if (typeof hooks?.beforePublish === "function") {
                hooks.beforePublish({
                    snapshot,
                    stagingDir: stagePath,
                    destDir: destResolved,
                });
            }
            assertMaterializationRoot(stagePath, stageAnchor, parent.path, parent.anchor);
            verifyMaterializationStage(
                stagePath,
                stageAnchor,
                parent.path,
                parent.anchor,
                manifest,
            );
            if (materializationLstatOrNull(destResolved) !== null) {
                throw new DestinationExistsError(
                    "destination appeared before materialization publication",
                    { destDir: destResolved },
                );
            }
            fs.renameSync(stagePath, destResolved);
            try {
                const publishedDir = assertMaterializationPath(destResolved, "directory");
                assertMaterializationAnchor(stageAnchor, publishedDir.anchor, destResolved);
                assertMaterializationAnchor(
                    parent.anchor,
                    assertMaterializationPath(parent.path, "directory").anchor,
                    parent.path,
                );
                if (!isInsideDir(publishedDir.real, parent.real)) {
                    throw new UnsafePathError("published materialization escaped its verified parent", {
                        destDir: destResolved,
                        real: publishedDir.real,
                    });
                }
                published = true;
                return {
                    dest: publishedDir.real,
                    snapshot,
                    fileCount,
                    totalBytes,
                };
            } catch (err) {
                try {
                    removeMaterializationTree(destResolved, stageAnchor);
                } catch {
                    // Preserve the publication failure.
                }
                throw err;
            }
        } finally {
            if (!published) {
                try {
                    removeMaterializationTree(stagePath, stageAnchor);
                } catch {
                    // Preserve the materialization failure.
                }
            }
        }
    }

    // Verify a snapshot's object closure. Returns a non-throwing status report
    // distinguishing missing from corrupt bytes.
    verifySnapshot(snapshot) {
        const probe = this.verifyObject(snapshot);
        if (!probe.ok) {
            return {
                snapshot,
                ok: false,
                manifestOk: false,
                reason: probe.reason,
                entries: 0,
                missing: probe.reason === "missing" ? [snapshot] : [],
                corrupt: probe.reason === "corrupt" ? [snapshot] : [],
            };
        }
        let manifest;
        try {
            manifest = this.loadManifest(snapshot);
        } catch (err) {
            return { snapshot, ok: false, manifestOk: false, reason: "invalid-manifest", error: err.code };
        }
        const missing = [];
        const corrupt = [];
        for (const entry of manifest.entries) {
            const r = this.verifyObject(entry.object);
            if (!r.ok) {
                (r.reason === "missing" ? missing : corrupt).push(entry.object);
            } else if (r.size !== entry.size) {
                corrupt.push(entry.object);
            }
        }
        return {
            snapshot,
            ok: missing.length === 0 && corrupt.length === 0,
            manifestOk: true,
            entries: manifest.entries.length,
            missing,
            corrupt,
        };
    }

    // --- enumeration / reconciliation -------------------------------------

    // List every object present on disk as { id, hash, size, mtimeMs }.
    listObjects() {
        const out = [];
        let prefixes;
        try {
            prefixes = fs.readdirSync(this.#objectsRoot, { withFileTypes: true });
        } catch (err) {
            if (err && err.code === "ENOENT") {
                return out;
            }
            throw err;
        }
        for (const p of prefixes) {
            if (!p.isDirectory()) {
                continue;
            }
            const prefixDir = path.join(this.#objectsRoot, p.name);
            for (const f of fs.readdirSync(prefixDir, { withFileTypes: true })) {
                if (!f.isFile() || !HEX64_RE.test(f.name) || f.name.slice(0, 2) !== p.name) {
                    continue;
                }
                const abs = path.join(prefixDir, f.name);
                const st = fs.statSync(abs);
                out.push({ id: objectIdFor(f.name), hash: f.name, size: st.size, mtimeMs: st.mtimeMs, path: abs });
            }
        }
        return out;
    }

    #listStaging() {
        const out = [];
        let files;
        try {
            files = fs.readdirSync(this.#stagingRoot, { withFileTypes: true });
        } catch (err) {
            if (err && err.code === "ENOENT") {
                return out;
            }
            throw err;
        }
        for (const f of files) {
            if (!f.isFile() || f.name === LEGACY_DIRECTORY_BARRIER_FILE) {
                continue;
            }
            const abs = path.join(this.#stagingRoot, f.name);
            try {
                const st = fs.statSync(abs);
                out.push({ name: f.name, path: abs, mtimeMs: st.mtimeMs });
            } catch (err) {
                if (!err || err.code !== "ENOENT") {
                    throw err;
                }
            }
        }
        return out;
    }

    #scanInstallationJournal() {
        const records = [];
        const corrupt = [];
        const temporary = [];
        let files;
        try {
            files = fs.readdirSync(this.#journalRoot, { withFileTypes: true });
        } catch (err) {
            if (err && err.code === "ENOENT") {
                return { records, corrupt, temporary };
            }
            throw asIoError("failed to enumerate installation journal", err, { path: this.#journalRoot });
        }
        for (const file of files) {
            if (!file.isFile() || file.name === LEGACY_DIRECTORY_BARRIER_FILE) {
                continue;
            }
            const filePath = path.join(this.#journalRoot, file.name);
            let stat;
            try {
                stat = fs.statSync(filePath);
            } catch (err) {
                if (err && err.code === "ENOENT") {
                    continue;
                }
                throw asIoError("failed to stat installation journal entry", err, { path: filePath });
            }
            if (file.name.startsWith(".") && file.name.endsWith(".tmp")) {
                temporary.push({ name: file.name, path: filePath, mtimeMs: stat.mtimeMs });
                continue;
            }
            try {
                const bytes = fs.readFileSync(filePath);
                const value = parseCanonicalJson(bytes, "installation staging record");
                const record = validateStagingRecord(value, {
                    rawBytes: bytes,
                    fileName: file.name,
                    limits: this.#limits,
                });
                records.push({ record, path: filePath, mtimeMs: stat.mtimeMs });
            } catch (err) {
                corrupt.push({
                    name: file.name,
                    path: filePath,
                    mtimeMs: stat.mtimeMs,
                    error: err instanceof CruciblePersistenceError
                        ? err
                        : asIoError("failed to read installation journal entry", err, { path: filePath }),
                });
            }
        }
        records.sort((a, b) => a.record.transaction.localeCompare(b.record.transaction));
        corrupt.sort((a, b) => a.name.localeCompare(b.name));
        temporary.sort((a, b) => a.name.localeCompare(b.name));
        return { records, corrupt, temporary };
    }

    #scanStateMarkers() {
        const installed = new Map();
        const referenced = new Map();
        const corrupt = [];
        const temporary = [];
        const protectedIds = new Set();
        const protectedPrefixes = new Set();
        let prefixes;
        try {
            prefixes = fs.readdirSync(this.#installationsRoot, { withFileTypes: true });
        } catch (err) {
            if (err && err.code === "ENOENT") {
                return { installed, referenced, corrupt, temporary, protectedIds, protectedPrefixes };
            }
            throw asIoError("failed to enumerate installation state markers", err, {
                path: this.#installationsRoot,
            });
        }
        prefixes.sort((a, b) => a.name.localeCompare(b.name));
        for (const prefix of prefixes) {
            if (!prefix.isDirectory() || !/^[0-9a-f]{2}$/u.test(prefix.name)) {
                continue;
            }
            const prefixDir = path.join(this.#installationsRoot, prefix.name);
            const files = fs.readdirSync(prefixDir, { withFileTypes: true })
                .sort((a, b) => a.name.localeCompare(b.name));
            for (const file of files) {
                if (!file.isFile() || file.name === LEGACY_DIRECTORY_BARRIER_FILE) {
                    continue;
                }
                const filePath = path.join(prefixDir, file.name);
                if (file.name.startsWith(".") && file.name.endsWith(".tmp")) {
                    const stat = fs.statSync(filePath);
                    temporary.push({
                        name: file.name,
                        path: filePath,
                        mtimeMs: stat.mtimeMs,
                    });
                    continue;
                }
                const match = STATE_MARKER_FILE_RE.exec(file.name);
                if (!match || match[1].slice(0, 2) !== prefix.name) {
                    protectedPrefixes.add(prefix.name);
                    corrupt.push({
                        name: file.name,
                        path: filePath,
                        error: new JournalCorruptError("installation state marker has an invalid filename", {
                            path: filePath,
                        }),
                    });
                    continue;
                }
                const [, hash, state] = match;
                const id = objectIdFor(hash);
                try {
                    const stat = fs.statSync(filePath);
                    const bytes = fs.readFileSync(filePath);
                    const value = parseCanonicalJson(bytes, "installation state marker");
                    const marker = validateStateMarker(value, {
                        rawBytes: bytes,
                        fileName: file.name,
                        expectedState: state,
                        limits: this.#limits,
                    });
                    const entry = { marker, path: filePath, mtimeMs: stat.mtimeMs };
                    (state === JOURNAL_STATES.INSTALLED ? installed : referenced).set(id, entry);
                } catch (err) {
                    protectedIds.add(id);
                    corrupt.push({
                        name: file.name,
                        path: filePath,
                        object: id,
                        error: err instanceof CruciblePersistenceError
                            ? err
                            : asIoError("failed to read installation state marker", err, { path: filePath }),
                    });
                }
            }
        }
        temporary.sort((a, b) => a.path.localeCompare(b.path));
        return { installed, referenced, corrupt, temporary, protectedIds, protectedPrefixes };
    }

    #listInstallationCandidates() {
        const candidates = [];
        let prefixes;
        try {
            prefixes = fs.readdirSync(this.#objectsRoot, { withFileTypes: true });
        } catch (err) {
            if (err && err.code === "ENOENT") {
                return candidates;
            }
            throw asIoError("failed to enumerate object prefixes for installation candidates", err, {
                path: this.#objectsRoot,
            });
        }
        for (const prefix of prefixes) {
            if (!prefix.isDirectory() || !/^[0-9a-f]{2}$/u.test(prefix.name)) {
                continue;
            }
            const prefixDir = path.join(this.#objectsRoot, prefix.name);
            for (const file of fs.readdirSync(prefixDir, { withFileTypes: true })) {
                if (!file.isFile()) {
                    continue;
                }
                const match = /^\.([0-9a-f]{64})\.([0-9a-z]+-[0-9a-z]+-[0-9a-f]{24})\.installing$/u.exec(file.name);
                if (!match || match[1].slice(0, 2) !== prefix.name) {
                    continue;
                }
                const filePath = path.join(prefixDir, file.name);
                const stat = fs.statSync(filePath);
                candidates.push({
                    name: file.name,
                    path: filePath,
                    hash: match[1],
                    transaction: match[2],
                    mtimeMs: stat.mtimeMs,
                });
            }
        }
        candidates.sort((a, b) => a.path.localeCompare(b.path));
        return candidates;
    }

    #recordSourceStatuses(record) {
        const paths = [
            path.join(this.#stagingRoot, record.staging),
            this.#candidatePath(record),
        ];
        return paths.map((sourcePath) => ({
            path: sourcePath,
            status: this.#validateObjectSlot(sourcePath, record),
        }));
    }

    #quarantineCorruptObject(record, dest) {
        const quarantinePath = path.join(
            this.#quarantineRoot,
            `${record.hash}.${record.transaction}.corrupt`,
        );
        const before = this.#hashExisting(dest);
        if (before === null) {
            return null;
        }
        if (!fs.existsSync(quarantinePath)) {
            try {
                fs.copyFileSync(dest, quarantinePath, fs.constants.COPYFILE_EXCL);
            } catch (err) {
                if (!err || err.code !== "EEXIST") {
                    throw asIoError("failed to quarantine corrupt object", err, {
                        object: record.object,
                        source: dest,
                        quarantinePath,
                    });
                }
            }
            this.#fsyncFilePath(quarantinePath, "quarantined corrupt object");
            this.#fsyncDirectoryAndAncestors(
                this.#quarantineRoot,
                "corrupt-object quarantine",
            );
        }
        const after = this.#hashExisting(dest);
        if (after === null) {
            return quarantinePath;
        }
        if (after.hash !== before.hash || after.size !== before.size) {
            throw new ObjectCorruptError("corrupt object changed while reconciliation attempted recovery", {
                object: record.object,
                before,
                after,
            });
        }
        const removed = this.#unlinkPath(dest, "failed to remove quarantined corrupt object slot");
        if (removed) {
            this.#fsyncDirectoryAndAncestors(path.dirname(dest), "corrupt object removal");
        }
        return quarantinePath;
    }

    #recoverJournalRecord(entry, options) {
        const { olderThanMs, now, dryRun } = options;
        const { record, mtimeMs } = entry;
        const age = now - mtimeMs;
        const dest = this.objectPath(record.object);
        const destStatus = this.#validateObjectSlot(dest, record);
        const sources = this.#recordSourceStatuses(record);
        const validSource = sources.find((source) => source.status.ok);

        if (age < olderThanMs) {
            return { action: "pending", transaction: record.transaction, object: record.object };
        }
        if (destStatus.ok) {
            if (!dryRun) {
                this.#makeObjectDurable(record, dest, path.dirname(dest));
                this.#writeStateMarker(record, JOURNAL_STATES.INSTALLED);
                this.#cleanupTransaction(record);
            }
            return { action: "completed", transaction: record.transaction, object: record.object };
        }
        if (validSource !== undefined) {
            if (!dryRun && destStatus.reason === "corrupt") {
                const quarantinePath = this.#quarantineCorruptObject(record, dest);
                this.#finishInstall(record, null, validSource.path);
                if (quarantinePath !== null) {
                    const removed = this.#unlinkPath(
                        quarantinePath,
                        "failed to remove recovered corrupt-object quarantine",
                    );
                    if (removed) {
                        this.#fsyncDirectoryAndAncestors(
                            this.#quarantineRoot,
                            "recovered quarantine cleanup",
                        );
                    }
                }
            } else if (!dryRun) {
                this.#finishInstall(record, null, validSource.path);
            }
            return {
                action: destStatus.reason === "corrupt" ? "repaired" : "completed",
                transaction: record.transaction,
                object: record.object,
            };
        }
        if (!dryRun) {
            this.#cleanupTransaction(record);
        }
        return {
            action: "abandoned",
            transaction: record.transaction,
            object: record.object,
            reason: destStatus.reason,
        };
    }

    #ensureReferencedState(id, size, markerScan, dryRun) {
        const { hex } = parseObjectId(id);
        const record = {
            transaction: null,
            object: id,
            hash: hex,
            size,
        };
        const installedEntry = markerScan.installed.get(id);
        if (installedEntry !== undefined && installedEntry.marker.size !== size) {
            throw new JournalCorruptError("installed marker size disagrees with verified object", {
                object: id,
                markerSize: installedEntry.marker.size,
                objectSize: size,
            });
        }
        const referencedEntry = markerScan.referenced.get(id);
        if (referencedEntry !== undefined && referencedEntry.marker.size !== size) {
            throw new JournalCorruptError("referenced marker size disagrees with verified object", {
                object: id,
                markerSize: referencedEntry.marker.size,
                objectSize: size,
            });
        }
        if (dryRun) {
            return referencedEntry === undefined;
        }
        if (installedEntry === undefined) {
            const dest = this.objectPath(id);
            this.#makeObjectDurable(record, dest, path.dirname(dest));
            this.#writeStateMarker(record, JOURNAL_STATES.INSTALLED);
        }
        if (referencedEntry === undefined) {
            this.#writeStateMarker(record, JOURNAL_STATES.REFERENCED);
            return true;
        }
        return false;
    }

    #removeObjectDurably(objectPath, purpose) {
        const removed = this.#unlinkPath(objectPath, `failed to remove ${purpose}`);
        if (removed) {
            this.#fsyncDirectoryAndAncestors(
                path.dirname(objectPath),
                `${purpose} parent`,
            );
        }
        return removed;
    }

    #removeMarkerDurably(markerEntry, purpose) {
        const removed = this.#unlinkPath(markerEntry.path, `failed to remove ${purpose}`);
        if (removed) {
            this.#fsyncDirectoryAndAncestors(
                path.dirname(markerEntry.path),
                `${purpose} parent`,
            );
        }
        return removed;
    }

    #markObjectReferenced(id, expectedSize, dryRun) {
        if (dryRun) {
            const markerScan = this.#scanStateMarkers();
            return {
                marked: this.#ensureReferencedState(id, expectedSize, markerScan, true),
                probe: this.verifyObject(id),
                markerScan,
            };
        }
        return this.#withCoordinationTransaction(({ bumpGeneration }) => {
            const probe = this.verifyObject(id);
            const markerScan = this.#scanStateMarkers();
            const prefix = parseObjectId(id).hex.slice(0, 2);
            if (!probe.ok
                || markerScan.protectedIds.has(id)
                || markerScan.protectedPrefixes.has(prefix)) {
                return { marked: false, probe, markerScan };
            }
            const marked = this.#ensureReferencedState(id, probe.size, markerScan, false);
            if (marked) {
                bumpGeneration();
            }
            return { marked, probe, markerScan };
        }).result;
    }

    #removeObjectIfStillUnreferenced({
        id,
        objectPath = null,
        installedMarker = false,
        purpose,
        observedGeneration,
    }) {
        this.#inject("before-reconcile-object-delete", {
            object: id,
            path: objectPath,
            installedMarker,
            observedGeneration,
        });
        return this.#withCoordinationTransaction(({ generation, bumpGeneration }) => {
            const markerScan = this.#scanStateMarkers();
            const prefix = parseObjectId(id).hex.slice(0, 2);
            if (markerScan.referenced.has(id)
                || markerScan.protectedIds.has(id)
                || markerScan.protectedPrefixes.has(prefix)) {
                return {
                    removedObject: false,
                    removedMarker: false,
                    protected: true,
                    generationChanged: generation !== observedGeneration,
                    generation,
                };
            }

            let removedObject = false;
            if (objectPath !== null) {
                removedObject = this.#removeObjectDurably(objectPath, purpose);
            }
            let removedMarker = false;
            if (installedMarker) {
                const currentInstalled = markerScan.installed.get(id);
                if (currentInstalled !== undefined) {
                    removedMarker = this.#removeMarkerDurably(
                        currentInstalled,
                        "durable unreferenced installed marker",
                    );
                }
            }
            if (removedObject || removedMarker) {
                bumpGeneration();
            }
            return {
                removedObject,
                removedMarker,
                protected: false,
                generationChanged: generation !== observedGeneration,
                generation,
            };
        }).result;
    }

    // Reconcile the store against trusted caller references plus the private,
    // monotonic referenced markers. Incomplete journalled installs are resumed
    // before reference classification; only aged, durable-unreferenced objects
    // (or aged unjournalled leftovers) are removed.
    reconcile(options = {}) {
        this.#assertWritable();
        const { referenced = [], snapshots = [], olderThanMs, now = Date.now(), dryRun = false } = options;
        if (!Number.isFinite(olderThanMs) || olderThanMs < 0) {
            throw new InvalidArgumentError("olderThanMs must be a non-negative finite number", { olderThanMs });
        }
        if (!Number.isFinite(now)) {
            throw new InvalidArgumentError("now must be a finite epoch-millis number", { now });
        }

        const refSet = new Set();
        const referencedReport = { ok: [], missing: [], corrupt: [] };
        const installationReport = {
            completed: [],
            repaired: [],
            pending: [],
            abandoned: [],
            corruptRecords: [],
            markedReferenced: [],
            persistentReferenced: [],
            durableOrphans: [],
            unjournaledOrphans: [],
            removedMarkers: [],
            removedJournalEntries: [],
            removedMetadataTemps: [],
            removedCandidates: [],
            removedQuarantine: [],
        };

        const addRef = (id) => {
            const { hex } = parseObjectId(id);
            refSet.add(objectIdFor(hex));
        };

        for (const id of referenced) {
            addRef(id);
        }

        // First settle aged incomplete transactions. This makes a journalled
        // snapshot manifest available before we attempt to expand its closure.
        let journalScan = this.#scanInstallationJournal();
        for (const corrupt of journalScan.corrupt) {
            installationReport.corruptRecords.push({
                name: corrupt.name,
                code: corrupt.error.code,
                message: corrupt.error.message,
            });
            if (now - corrupt.mtimeMs >= olderThanMs) {
                if (!dryRun) {
                    const removed = this.#unlinkPath(
                        corrupt.path,
                        "failed to remove corrupt installation journal entry",
                    );
                    if (removed) {
                        this.#fsyncDirectoryAndAncestors(
                            this.#journalRoot,
                            "corrupt journal cleanup",
                        );
                    }
                }
                installationReport.removedJournalEntries.push(corrupt.name);
            }
        }
        for (const entry of journalScan.records) {
            const result = this.#recoverJournalRecord(entry, {
                olderThanMs,
                now,
                dryRun,
            });
            installationReport[result.action].push({
                transaction: result.transaction,
                object: result.object,
                ...(result.reason === undefined ? {} : { reason: result.reason }),
            });
        }

        let markerScan = this.#scanStateMarkers();
        for (const corrupt of markerScan.corrupt) {
            installationReport.corruptRecords.push({
                name: corrupt.name,
                object: corrupt.object,
                code: corrupt.error.code,
                message: corrupt.error.message,
            });
        }
        for (const id of markerScan.referenced.keys()) {
            addRef(id);
            installationReport.persistentReferenced.push(id);
        }

        // Expand caller-supplied snapshot ids by reading their hash-verified
        // manifests. The snapshot ids are trusted (caller-supplied); the
        // manifest bytes are trusted because they are content-addressed and
        // re-hashed on read — this is NOT inferring references from untrusted
        // input.
        for (const snap of snapshots) {
            addRef(snap);
            const probe = this.verifyObject(snap);
            if (!probe.ok) {
                (probe.reason === "missing" ? referencedReport.missing : referencedReport.corrupt).push(snap);
                continue;
            }
            let manifest;
            try {
                manifest = this.loadManifest(snap);
            } catch {
                referencedReport.corrupt.push(snap);
                continue;
            }
            for (const entry of manifest.entries) {
                addRef(entry.object);
            }
        }

        // Classify every referenced object.
        for (const id of refSet) {
            const r = this.verifyObject(id);
            if (r.ok) {
                if (!markerScan.protectedIds.has(id)
                    && !markerScan.protectedPrefixes.has(parseObjectId(id).hex.slice(0, 2))) {
                    try {
                        const marked = this.#markObjectReferenced(id, r.size, dryRun);
                        if (!marked.probe.ok) {
                            if (marked.probe.reason === "missing") {
                                referencedReport.missing.push(id);
                            } else {
                                referencedReport.corrupt.push(id);
                            }
                            continue;
                        }
                        referencedReport.ok.push(id);
                        if (marked.marked) {
                            installationReport.markedReferenced.push(id);
                        }
                    } catch (err) {
                        if (!(err instanceof JournalCorruptError)) {
                            throw err;
                        }
                        markerScan.protectedIds.add(id);
                        installationReport.corruptRecords.push({
                            object: id,
                            code: err.code,
                            message: err.message,
                        });
                    }
                } else {
                    referencedReport.ok.push(id);
                }
            } else if (r.reason === "missing") {
                if (!referencedReport.missing.includes(id)) {
                    referencedReport.missing.push(id);
                }
            } else if (!referencedReport.corrupt.includes(id)) {
                referencedReport.corrupt.push(id);
            }
        }

        // Re-read state after any installed/referenced markers created above.
        markerScan = this.#scanStateMarkers();
        for (const id of markerScan.referenced.keys()) {
            refSet.add(id);
            if (!installationReport.persistentReferenced.includes(id)) {
                installationReport.persistentReferenced.push(id);
            }
        }
        let sweepGeneration = this.#coordinationGeneration();

        // Sweep durable unreferenced objects according to installed markers.
        // A referenced marker is monotonic and permanently protects its object.
        const removedObjects = [];
        const keptOrphans = [];
        const objects = this.listObjects();
        const objectsById = new Map(objects.map((obj) => [obj.id, obj]));
        for (const [id, installedEntry] of markerScan.installed) {
            if (refSet.has(id)
                || markerScan.referenced.has(id)
                || markerScan.protectedIds.has(id)
                || markerScan.protectedPrefixes.has(parseObjectId(id).hex.slice(0, 2))) {
                continue;
            }
            installationReport.durableOrphans.push(id);
            const obj = objectsById.get(id);
            if (obj !== undefined && installedEntry.marker.size !== obj.size) {
                markerScan.protectedIds.add(id);
                installationReport.corruptRecords.push({
                    object: id,
                    code: ARTIFACT_STORE_ERROR_CODES.JOURNAL_CORRUPT,
                    message: "installed marker size disagrees with object slot",
                });
                continue;
            }
            const age = now - (obj?.mtimeMs ?? installedEntry.mtimeMs);
            if (age >= olderThanMs) {
                let removal = {
                    removedObject: obj !== undefined,
                    removedMarker: true,
                    protected: false,
                    generation: sweepGeneration,
                };
                if (!dryRun) {
                    removal = this.#removeObjectIfStillUnreferenced({
                        id,
                        objectPath: obj?.path ?? null,
                        installedMarker: true,
                        purpose: "durable unreferenced object",
                        observedGeneration: sweepGeneration,
                    });
                    sweepGeneration = removal.generation;
                    if (removal.protected) {
                        refSet.add(id);
                        installationReport.persistentReferenced.push(id);
                        installationReport.durableOrphans =
                            installationReport.durableOrphans.filter((value) => value !== id);
                        keptOrphans.push(id);
                        continue;
                    }
                }
                if (obj !== undefined && removal.removedObject) {
                    removedObjects.push(id);
                }
                if (removal.removedMarker) {
                    installationReport.removedMarkers.push(id);
                }
            } else {
                keptOrphans.push(id);
            }
        }

        // Legacy/unjournalled objects are never promoted silently. They retain
        // the old age-based sweep behavior unless protected by a trusted ref or
        // suspicious metadata that makes deletion unsafe.
        for (const obj of objects) {
            const prefix = obj.hash.slice(0, 2);
            if (markerScan.installed.has(obj.id)
                || refSet.has(obj.id)
                || markerScan.protectedIds.has(obj.id)
                || markerScan.protectedPrefixes.has(prefix)) {
                continue;
            }
            installationReport.unjournaledOrphans.push(obj.id);
            const age = now - obj.mtimeMs;
            if (age >= olderThanMs) {
                let removal = {
                    removedObject: true,
                    protected: false,
                    generation: sweepGeneration,
                };
                if (!dryRun) {
                    removal = this.#removeObjectIfStillUnreferenced({
                        id: obj.id,
                        objectPath: obj.path,
                        installedMarker: false,
                        purpose: "unjournalled orphan object",
                        observedGeneration: sweepGeneration,
                    });
                    sweepGeneration = removal.generation;
                    if (removal.protected) {
                        refSet.add(obj.id);
                        installationReport.persistentReferenced.push(obj.id);
                        installationReport.unjournaledOrphans =
                            installationReport.unjournaledOrphans.filter(
                                (value) => value !== obj.id,
                            );
                        keptOrphans.push(obj.id);
                        continue;
                    }
                }
                if (removal.removedObject) {
                    removedObjects.push(obj.id);
                }
            } else {
                keptOrphans.push(obj.id);
            }
        }

        // Sweep stale staging files only when no surviving valid journal record
        // owns their name.
        journalScan = this.#scanInstallationJournal();
        const protectedStaging = new Set(journalScan.records.map((entry) => entry.record.staging));
        const protectedTransactions = new Set(
            journalScan.records.map((entry) => entry.record.transaction),
        );
        const removedStaging = [];
        for (const s of this.#listStaging()) {
            if (protectedStaging.has(s.name)) {
                continue;
            }
            const age = now - s.mtimeMs;
            if (age >= olderThanMs) {
                if (!dryRun) {
                    const removed = this.#unlinkPath(s.path, "failed to remove stale staging file");
                    if (removed) {
                        this.#fsyncDirectoryAndAncestors(
                            this.#stagingRoot,
                            "stale staging cleanup",
                        );
                    }
                }
                removedStaging.push(s.name);
            }
        }

        for (const temp of journalScan.temporary) {
            if (now - temp.mtimeMs >= olderThanMs) {
                if (!dryRun) {
                    const removed = this.#unlinkPath(
                        temp.path,
                        "failed to remove stale journal temporary file",
                    );
                    if (removed) {
                        this.#fsyncDirectoryAndAncestors(
                            this.#journalRoot,
                            "journal temporary cleanup",
                        );
                    }
                }
                installationReport.removedJournalEntries.push(temp.name);
            }
        }

        markerScan = this.#scanStateMarkers();
        for (const temp of markerScan.temporary) {
            if (now - temp.mtimeMs >= olderThanMs) {
                if (!dryRun) {
                    const removed = this.#unlinkPath(
                        temp.path,
                        "failed to remove stale installation-marker temporary file",
                    );
                    if (removed) {
                        this.#fsyncDirectoryAndAncestors(
                            path.dirname(temp.path),
                            "installation-marker temporary cleanup",
                        );
                    }
                }
                installationReport.removedMetadataTemps.push(temp.name);
            }
        }

        for (const candidate of this.#listInstallationCandidates()) {
            if (protectedTransactions.has(candidate.transaction)) {
                continue;
            }
            if (now - candidate.mtimeMs >= olderThanMs) {
                if (!dryRun) {
                    this.#removeObjectDurably(candidate.path, "stale installation candidate");
                }
                installationReport.removedCandidates.push(candidate.name);
            }
        }

        let quarantineFiles = [];
        try {
            quarantineFiles = fs.readdirSync(this.#quarantineRoot, { withFileTypes: true });
        } catch (err) {
            if (!err || err.code !== "ENOENT") {
                throw asIoError("failed to enumerate corrupt-object quarantine", err, {
                    path: this.#quarantineRoot,
                });
            }
        }
        for (const file of quarantineFiles.sort((a, b) => a.name.localeCompare(b.name))) {
            if (!file.isFile() || file.name === LEGACY_DIRECTORY_BARRIER_FILE) {
                continue;
            }
            const filePath = path.join(this.#quarantineRoot, file.name);
            const stat = fs.statSync(filePath);
            if (now - stat.mtimeMs >= olderThanMs) {
                if (!dryRun) {
                    const removed = this.#unlinkPath(filePath, "failed to remove stale corrupt-object quarantine");
                    if (removed) {
                        this.#fsyncDirectoryAndAncestors(
                            this.#quarantineRoot,
                            "stale quarantine cleanup",
                        );
                    }
                }
                installationReport.removedQuarantine.push(file.name);
            }
        }

        const sortUnique = (values) => [...new Set(values)].sort();
        referencedReport.ok = sortUnique(referencedReport.ok);
        referencedReport.missing = sortUnique(referencedReport.missing);
        referencedReport.corrupt = sortUnique(referencedReport.corrupt);
        installationReport.markedReferenced = sortUnique(installationReport.markedReferenced);
        installationReport.persistentReferenced = sortUnique(installationReport.persistentReferenced);
        installationReport.durableOrphans = sortUnique(installationReport.durableOrphans);
        installationReport.unjournaledOrphans = sortUnique(installationReport.unjournaledOrphans);
        installationReport.removedMarkers = sortUnique(installationReport.removedMarkers);
        installationReport.removedJournalEntries = sortUnique(installationReport.removedJournalEntries);
        installationReport.removedMetadataTemps = sortUnique(installationReport.removedMetadataTemps);
        installationReport.removedCandidates = sortUnique(installationReport.removedCandidates);
        installationReport.removedQuarantine = sortUnique(installationReport.removedQuarantine);
        for (const key of ["completed", "repaired", "pending", "abandoned"]) {
            installationReport[key].sort((a, b) => a.transaction.localeCompare(b.transaction));
        }
        installationReport.corruptRecords.sort((a, b) =>
            String(a.object ?? a.name ?? "").localeCompare(String(b.object ?? b.name ?? "")));

        return {
            now,
            olderThanMs,
            dryRun,
            referenced: referencedReport,
            installations: installationReport,
            removedObjects: sortUnique(removedObjects),
            keptOrphans: sortUnique(keptOrphans),
            removedStaging: sortUnique(removedStaging),
        };
    }
}

export function openArtifactStore(options = {}) {
    return ArtifactStore.open(options);
}

export function openArtifactStoreReadOnly(options = {}) {
    return ArtifactStore.open({ ...options, readOnly: true });
}

// --- small internal utilities ---------------------------------------------

function toBuffer(input) {
    if (Buffer.isBuffer(input)) {
        return input;
    }
    if (input instanceof Uint8Array) {
        return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    }
    if (typeof input === "string") {
        return Buffer.from(input, "utf8");
    }
    throw new InvalidArgumentError("expected Buffer, Uint8Array, or string", { type: typeof input });
}

function safeUnlink(p) {
    try {
        fs.unlinkSync(p);
    } catch (err) {
        if (err && err.code !== "ENOENT") {
            // A residual staging file is not fatal; surface nothing but do not
            // pretend a real error (permissions) is success — rethrow those.
            if (err.code !== "EPERM" && err.code !== "EBUSY") {
                throw err;
            }
        }
    }
}

function isInsideDir(childAbs, parentAbs) {
    const child = path.resolve(childAbs);
    const parent = path.resolve(parentAbs);
    if (child === parent) {
        return true;
    }
    const withSep = parent.endsWith(path.sep) ? parent : parent + path.sep;
    return child.startsWith(withSep);
}
