// oracle-v3/persistence/artifact-store.mjs
//
// Immutable content-addressed artifact store (CAS) for the Oracle v3 audit
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
//   * Every write goes through a unique staging file that is fsync'd before it
//     is atomically installed via hard-link (link never overwrites: it fails
//     with EEXIST, which is exactly the "safe against duplicate writers"
//     semantics we want). Parent directories are fsync'd best-effort.
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

import { OraclePersistenceError, InvalidArgumentError } from "./errors.mjs";
import { assertLocalDatabasePath } from "./paths.mjs";
import { canonicalize } from "./canonical.mjs";

// --- constants ------------------------------------------------------------

const ALGO = "sha256";
const HEX_LEN = 64;
const OBJECT_ID_RE = /^([a-z0-9]+):([0-9a-f]+)$/u;
const HEX64_RE = /^[0-9a-f]{64}$/u;
const SNAPSHOT_TYPE = "oracle-v3-snapshot";
const SNAPSHOT_VERSION = 1;
const STAGE_CHUNK = 1 << 16;

const DEFAULT_LIMITS = Object.freeze({
    maxFiles: 100_000,
    maxTotalBytes: 16 * 2 ** 30, // 16 GiB
    maxFileBytes: 8 * 2 ** 30, //  8 GiB
    maxPathLength: 1024, // characters in a relative posix path
    maxDepth: 128,
});

// --- typed errors ---------------------------------------------------------

export const ARTIFACT_STORE_ERROR_CODES = Object.freeze({
    INVALID_ARGUMENT: "ORACLE_CAS_INVALID_ARGUMENT",
    STORE_ROOT_INVALID: "ORACLE_CAS_STORE_ROOT_INVALID",
    UNSAFE_PATH: "ORACLE_CAS_UNSAFE_PATH",
    SYMLINK_REJECTED: "ORACLE_CAS_SYMLINK_REJECTED",
    LIMIT_EXCEEDED: "ORACLE_CAS_LIMIT_EXCEEDED",
    OBJECT_NOT_FOUND: "ORACLE_CAS_OBJECT_NOT_FOUND",
    OBJECT_CORRUPT: "ORACLE_CAS_OBJECT_CORRUPT",
    DESTINATION_EXISTS: "ORACLE_CAS_DESTINATION_EXISTS",
    SNAPSHOT_INVALID: "ORACLE_CAS_SNAPSHOT_INVALID",
    SOURCE_CHANGED: "ORACLE_CAS_SOURCE_CHANGED",
    IO_ERROR: "ORACLE_CAS_IO_ERROR",
});

export class ArtifactStoreError extends OraclePersistenceError {
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
    if (path.isAbsolute(relPath) || /^[A-Za-z]:/u.test(relPath)) {
        throw new UnsafePathError("absolute paths are not permitted in a snapshot", { relPath });
    }
    const segments = relPath.split("/");
    for (const seg of segments) {
        assertSafeComponent(seg, relPath);
    }
    return segments;
}

function toPosix(p) {
    return p.split(path.sep).join("/");
}

function fsyncDirBestEffort(dirPath) {
    // Directory fsync is not portable (Windows returns EPERM). We attempt it
    // and swallow failures rather than pretending it succeeded.
    let fd;
    try {
        fd = fs.openSync(dirPath, "r");
        fs.fsyncSync(fd);
    } catch {
        // best-effort only
    } finally {
        if (fd !== undefined) {
            try {
                fs.closeSync(fd);
            } catch {
                // ignore
            }
        }
    }
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
    #limits;
    #now;
    #verifyExistingOnPut;

    constructor({ root, now, limits, verifyExistingOnPut }) {
        this.#root = root;
        this.#objectsRoot = path.join(root, "objects", ALGO);
        this.#stagingRoot = path.join(root, "staging");
        this.#limits = limits;
        this.#now = now;
        this.#verifyExistingOnPut = verifyExistingOnPut;
    }

    static open(options = {}) {
        const { root, denyRoots, env, limits, now = () => new Date().toISOString(), verifyExistingOnPut = true } =
            options;
        if (typeof root !== "string" || root.trim().length === 0) {
            throw new InvalidArgumentError("artifact store root must be a non-empty string", { root });
        }
        let resolved;
        try {
            // Reuse the repository's local-only path gate: a CAS root on a
            // network share or cloud-sync folder has the same corruption /
            // fsync-semantics problems as a WAL database there.
            resolved = assertLocalDatabasePath(root, { denyRoots, env });
        } catch (err) {
            if (err instanceof OraclePersistenceError && err.code !== ARTIFACT_STORE_ERROR_CODES.INVALID_ARGUMENT) {
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
            verifyExistingOnPut: verifyExistingOnPut !== false,
        });
        store.#ensureLayout();
        return store;
    }

    get root() {
        return this.#root;
    }

    get limits() {
        return this.#limits;
    }

    #ensureLayout() {
        fs.mkdirSync(this.#objectsRoot, { recursive: true });
        fs.mkdirSync(this.#stagingRoot, { recursive: true });
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

    #newStagingPath() {
        const unique = `${Date.now().toString(36)}-${process.pid.toString(36)}-${randomBytes(12).toString("hex")}`;
        return path.join(this.#stagingRoot, `${unique}.tmp`);
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
        const stagingPath = this.#newStagingPath();
        const fd = fs.openSync(stagingPath, "wx");
        try {
            let off = 0;
            while (off < buf.length) {
                off += fs.writeSync(fd, buf, off, buf.length - off);
            }
            fs.fsyncSync(fd);
        } catch (err) {
            fs.closeSync(fd);
            safeUnlink(stagingPath);
            throw err;
        }
        fs.closeSync(fd);
        const hash = createHash(ALGO).update(buf).digest("hex");
        return { stagingPath, hash, size: buf.length };
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
        const stagingPath = this.#newStagingPath();
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
            wfd = fs.openSync(stagingPath, "wx");
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
            fs.fsyncSync(wfd);
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
        return { stagingPath, hash: hash.digest("hex"), size };
    }

    // Install a fsync'd staging file at its content-addressed destination using
    // link/rename semantics that never overwrite an existing object. Returns the
    // durable metadata for the object.
    #install(stagingPath, hash, size, contentType) {
        const dir = path.join(this.#objectsRoot, hash.slice(0, 2));
        fs.mkdirSync(dir, { recursive: true });
        const dest = path.join(dir, hash);

        let existed;
        try {
            // Hard-link never clobbers: it fails EEXIST if the object already
            // exists, which is precisely the duplicate-writer race we must
            // survive without corrupting the winning object.
            fs.linkSync(stagingPath, dest);
            existed = false;
        } catch (err) {
            if (err && err.code === "EEXIST") {
                existed = true;
            } else if (err && (err.code === "EPERM" || err.code === "ENOSYS" || err.code === "EXDEV" || err.code === "EMLINK")) {
                // Filesystem cannot hard-link (rare on same-volume NTFS/ext4).
                // Fall back to rename, but guard against overwrite first.
                if (fs.existsSync(dest)) {
                    existed = true;
                } else {
                    try {
                        fs.renameSync(stagingPath, dest);
                        existed = false;
                    } catch (renameErr) {
                        if (renameErr && (renameErr.code === "EEXIST" || renameErr.code === "EPERM" || renameErr.code === "ENOTEMPTY")) {
                            existed = true;
                        } else {
                            safeUnlink(stagingPath);
                            throw new ArtifactStoreError(
                                ARTIFACT_STORE_ERROR_CODES.IO_ERROR,
                                `failed to install object: ${renameErr.message}`,
                                { hash },
                            );
                        }
                    }
                }
            } else {
                safeUnlink(stagingPath);
                throw new ArtifactStoreError(
                    ARTIFACT_STORE_ERROR_CODES.IO_ERROR,
                    `failed to install object: ${err.message}`,
                    { hash },
                );
            }
        }

        // Staging file is either linked (dest now shares the inode) or the
        // object pre-existed; in both cases we remove the staging name.
        safeUnlink(stagingPath);

        if (existed && this.#verifyExistingOnPut) {
            // We must never trust an existing slot blindly: verify the bytes
            // already there match the id we intended to install.
            const check = this.#hashExisting(dest);
            if (check === null) {
                // A concurrent reconcile could have removed it between link
                // failure and here; re-install by rename of a fresh stage is
                // out of scope — treat as corruption of the CAS invariant.
                throw new ObjectCorruptError("object slot vanished during install verification", { hash });
            }
            if (check.hash !== hash || check.size !== size) {
                throw new ObjectCorruptError("existing object bytes do not match their content address", {
                    expectedHash: hash,
                    actualHash: check.hash,
                    expectedSize: size,
                    actualSize: check.size,
                });
            }
        }

        // Best-effort durability of the directory entries.
        fsyncDirBestEffort(dir);
        fsyncDirBestEffort(this.#objectsRoot);

        return {
            id: objectIdFor(hash),
            algo: ALGO,
            hash,
            size,
            path: dest,
            relativePath: objectRelPath(hash),
            contentType: contentType ?? null,
            existed,
            durable: true,
        };
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
        const { stagingPath, hash, size } = this.#stageBytes(input);
        return this.#install(stagingPath, hash, size, options.contentType);
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
        const { stagingPath, hash, size } = this.#stageFile(srcPath);
        return this.#install(stagingPath, hash, size, options.contentType);
    }

    // Store bytes drained from a Node Readable stream.
    async putStream(readable, options = {}) {
        if (!readable || typeof readable[Symbol.asyncIterator] !== "function") {
            throw new InvalidArgumentError("putStream requires an async-iterable readable stream");
        }
        const stagingPath = this.#newStagingPath();
        const wfd = fs.openSync(stagingPath, "wx");
        const hash = createHash(ALGO);
        let size = 0;
        try {
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
            fs.fsyncSync(wfd);
        } catch (err) {
            fs.closeSync(wfd);
            safeUnlink(stagingPath);
            throw err;
        }
        fs.closeSync(wfd);
        return this.#install(stagingPath, hash.digest("hex"), size, options.contentType);
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
            if (err instanceof OraclePersistenceError && err.code !== ARTIFACT_STORE_ERROR_CODES.INVALID_ARGUMENT) {
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

        const manifest = {
            type: SNAPSHOT_TYPE,
            version: SNAPSHOT_VERSION,
            algo: ALGO,
            fileCount: entries.length,
            totalBytes: counters.bytes,
            entries,
        };
        const manifestBytes = Buffer.from(canonicalize(manifest), "utf8");
        const manifestMeta = this.putBytes(manifestBytes, { contentType: "application/vnd.oracle-v3.snapshot+json" });

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
            const meta = this.#install(
                staged.stagingPath,
                staged.hash,
                staged.size,
                null,
            );
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
        if (
            !parsed ||
            parsed.type !== SNAPSHOT_TYPE ||
            parsed.version !== SNAPSHOT_VERSION ||
            parsed.algo !== ALGO ||
            !Array.isArray(parsed.entries)
        ) {
            throw new SnapshotInvalidError("snapshot manifest has an unexpected shape", { snapshotId });
        }
        for (const e of parsed.entries) {
            if (!e || typeof e.path !== "string" || typeof e.object !== "string" || !Number.isInteger(e.size)) {
                throw new SnapshotInvalidError("snapshot manifest entry is malformed", { snapshotId, entry: e });
            }
        }
        return parsed;
    }

    // Materialize a snapshot read-only into a fresh destination directory by
    // reading verified CAS objects. Refuses a pre-existing destination and any
    // entry path that would escape it.
    materializeSnapshot(options = {}) {
        const { snapshot, destDir, readOnly = true } = options;
        if (typeof destDir !== "string" || destDir.trim().length === 0) {
            throw new InvalidArgumentError("destDir must be a non-empty string", { destDir });
        }
        const destResolved = path.resolve(destDir);
        if (fs.existsSync(destResolved)) {
            throw new DestinationExistsError("destination already exists; refusing to materialize over it", {
                destDir: destResolved,
            });
        }
        const manifest = this.loadManifest(snapshot);

        fs.mkdirSync(destResolved, { recursive: true });
        const destReal = fs.realpathSync.native(destResolved);

        let fileCount = 0;
        let totalBytes = 0;
        for (const entry of manifest.entries) {
            const segments = safeRelSegments(entry.path, this.#limits.maxPathLength);
            const targetAbs = path.join(destReal, ...segments);
            if (!isInsideDir(targetAbs, destReal)) {
                throw new UnsafePathError("snapshot entry escapes destination", {
                    relPath: entry.path,
                    destDir: destReal,
                });
            }
            // Read + verify the object against BOTH its own id and the manifest's
            // recorded size (closure check).
            const bytes = this.readObject(entry.object, { verify: true });
            if (bytes.length !== entry.size) {
                throw new ObjectCorruptError("object size disagrees with manifest", {
                    relPath: entry.path,
                    object: entry.object,
                    expected: entry.size,
                    actual: bytes.length,
                });
            }
            fs.mkdirSync(path.dirname(targetAbs), { recursive: true });
            fs.writeFileSync(targetAbs, bytes);
            if (readOnly) {
                try {
                    fs.chmodSync(targetAbs, 0o444);
                } catch {
                    // best-effort read-only; Windows honours the read-only bit
                }
            }
            fileCount += 1;
            totalBytes += bytes.length;
        }

        return { dest: destReal, snapshot, fileCount, totalBytes };
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
            if (!f.isFile()) {
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

    // Reconcile the store against a TRUSTED reference set. Reports referenced
    // objects that are missing or corrupt, and removes only unreferenced
    // staging files and orphan objects older than `olderThanMs`. References are
    // taken exclusively from the caller (explicit ids and/or verified snapshot
    // closures); nothing is inferred from untrusted on-disk manifests.
    reconcile(options = {}) {
        const { referenced = [], snapshots = [], olderThanMs, now = Date.now(), dryRun = false } = options;
        if (!Number.isFinite(olderThanMs) || olderThanMs < 0) {
            throw new InvalidArgumentError("olderThanMs must be a non-negative finite number", { olderThanMs });
        }
        if (!Number.isFinite(now)) {
            throw new InvalidArgumentError("now must be a finite epoch-millis number", { now });
        }

        const refSet = new Set();
        const referencedReport = { ok: [], missing: [], corrupt: [] };

        const addRef = (id) => {
            const { hex } = parseObjectId(id);
            refSet.add(objectIdFor(hex));
        };

        for (const id of referenced) {
            addRef(id);
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
                referencedReport.ok.push(id);
            } else if (r.reason === "missing") {
                if (!referencedReport.missing.includes(id)) {
                    referencedReport.missing.push(id);
                }
            } else if (!referencedReport.corrupt.includes(id)) {
                referencedReport.corrupt.push(id);
            }
        }

        // Sweep orphan objects. NEVER delete a referenced object, even if it is
        // corrupt (that is a finding to surface, not to silently erase).
        const removedObjects = [];
        const keptOrphans = [];
        for (const obj of this.listObjects()) {
            if (refSet.has(obj.id)) {
                continue;
            }
            const age = now - obj.mtimeMs;
            if (age >= olderThanMs) {
                if (!dryRun) {
                    safeUnlink(obj.path);
                }
                removedObjects.push(obj.id);
            } else {
                keptOrphans.push(obj.id);
            }
        }

        // Sweep stale staging files (never referenced by construction).
        const removedStaging = [];
        for (const s of this.#listStaging()) {
            const age = now - s.mtimeMs;
            if (age >= olderThanMs) {
                if (!dryRun) {
                    safeUnlink(s.path);
                }
                removedStaging.push(s.name);
            }
        }

        return {
            now,
            olderThanMs,
            dryRun,
            referenced: referencedReport,
            removedObjects,
            keptOrphans,
            removedStaging,
        };
    }
}

export function openArtifactStore(options = {}) {
    return ArtifactStore.open(options);
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
