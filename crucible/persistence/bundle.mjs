// crucible/persistence/bundle.mjs
//
// Canonical, self-contained investigation audit bundles. A bundle can prove
// internal consistency by itself, but authenticity is deliberately out-of-band:
// import requires an expected digest/signature unless the caller explicitly
// opts into a "self-consistent" result.

import fs from "node:fs";
import path from "node:path";
import {
    createHash,
    randomBytes,
    timingSafeEqual,
} from "node:crypto";
import { TextDecoder } from "node:util";

import { DOMAIN_VERSION } from "../domain/constants.mjs";
import { CruciblePersistenceError, InvalidArgumentError } from "./errors.mjs";
import { assertLocalDatabasePath } from "./paths.mjs";
import { canonicalize, normalizeCreatedAt } from "./canonical.mjs";
import { DatabaseSync } from "./sqlite.mjs";
import { openRepositoryReadOnly } from "./repository.mjs";
import {
    SCHEMA_FINGERPRINT,
    SCHEMA_VERSION,
    configureConnection,
} from "./schema.mjs";
import {
    ArtifactStore,
    openArtifactStoreReadOnly,
    parseObjectId,
    objectIdFor,
    objectRelPath,
} from "./artifact-store.mjs";

const ALGO = "sha256";
export const BUNDLE_TYPE = "crucible-audit-bundle";
export const BUNDLE_VERSION = 3;

const INVENTORY_NAME = "inventory.sha256";
const MANIFEST_NAME = "manifest.json";
const DB_RELPATH = "db/database.sqlite";
const SNAPSHOT_CONTENT_TYPE = "application/vnd.crucible.snapshot+json";
const COPY_CHUNK = 1 << 16;
const MAX_MANIFEST_BYTES = 8 * 2 ** 20;
const MAX_INVENTORY_BYTES = 16 * 2 ** 20;
const MAX_BUNDLE_FILES = 100_000;
const MAX_DEPTH = 128;
const MAX_REL_PATH = 1024;
const WINDOWS_RESERVED_DEVICE_RE =
    /^(?:aux|clock\$|com[1-9¹²³]|con|conin\$|conout\$|lpt[1-9¹²³]|nul|prn)(?:\..*)?$/iu;
const HEX64_RE = /^[0-9a-f]{64}$/u;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const QUIET_DURABILITY_CONTROL = Object.freeze({
    operation: "durability",
    faultInjector: null,
    hooks: null,
});

const MANIFEST_KEYS = Object.freeze([
    "algo",
    "artifacts",
    "createdAt",
    "database",
    "investigation",
    "metadata",
    "objects",
    "snapshots",
    "type",
    "version",
]);
const DATABASE_KEYS = Object.freeze([
    "path",
    "schemaFingerprint",
    "schemaVersion",
    "sha256",
    "size",
]);
const INVESTIGATION_KEYS = Object.freeze(["domainHead", "domainVersion", "id"]);
const DOMAIN_HEAD_KEYS = Object.freeze(["eventHash", "seq"]);
const ARTIFACT_KEYS = Object.freeze([
    "artifactId",
    "contentType",
    "object",
    "sizeBytes",
]);
const OBJECT_KEYS = Object.freeze(["id", "path", "size"]);

// --- typed errors ---------------------------------------------------------

export const BUNDLE_ERROR_CODES = Object.freeze({
    INVALID_ARGUMENT: "CRUCIBLE_BUNDLE_INVALID_ARGUMENT",
    DESTINATION_EXISTS: "CRUCIBLE_BUNDLE_DESTINATION_EXISTS",
    SOURCE_INVALID: "CRUCIBLE_BUNDLE_SOURCE_INVALID",
    SOURCE_CHANGED: "CRUCIBLE_BUNDLE_SOURCE_CHANGED",
    UNSAFE_PATH: "CRUCIBLE_BUNDLE_UNSAFE_PATH",
    OBJECT_MISSING: "CRUCIBLE_BUNDLE_OBJECT_MISSING",
    INVENTORY_INVALID: "CRUCIBLE_BUNDLE_INVENTORY_INVALID",
    MANIFEST_INVALID: "CRUCIBLE_BUNDLE_MANIFEST_INVALID",
    DOMAIN_VERSION_MISMATCH: "CRUCIBLE_BUNDLE_DOMAIN_VERSION_MISMATCH",
    CLOSURE_INVALID: "CRUCIBLE_BUNDLE_CLOSURE_INVALID",
    AUTHENTICATION_REQUIRED: "CRUCIBLE_BUNDLE_AUTHENTICATION_REQUIRED",
    AUTHENTICATION_FAILED: "CRUCIBLE_BUNDLE_AUTHENTICATION_FAILED",
    TAMPER_DETECTED: "CRUCIBLE_BUNDLE_TAMPER_DETECTED",
    IO_ERROR: "CRUCIBLE_BUNDLE_IO_ERROR",
});

export class BundleError extends CruciblePersistenceError {
    constructor(code, message, details) {
        super(code, message, details);
        this.name = "BundleError";
    }
}

export class BundleDestinationExistsError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.DESTINATION_EXISTS, message, details);
        this.name = "BundleDestinationExistsError";
    }
}

export class BundleTamperError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.TAMPER_DETECTED, message, details);
        this.name = "BundleTamperError";
    }
}

export class BundleInventoryError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.INVENTORY_INVALID, message, details);
        this.name = "BundleInventoryError";
    }
}

export class BundleManifestError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.MANIFEST_INVALID, message, details);
        this.name = "BundleManifestError";
    }
}

export class BundleDomainVersionMismatchError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.DOMAIN_VERSION_MISMATCH, message, {
            compatibility: "legacy_incompatible",
            restartRequired: true,
            requiredAction: "start_new_investigation",
            ...details,
        });
        this.name = "BundleDomainVersionMismatchError";
    }
}

export class BundleAuthenticationError extends BundleError {
    constructor(code, message, details) {
        super(code, message, details);
        this.name = "BundleAuthenticationError";
    }
}

export class BundleSourceChangedError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.SOURCE_CHANGED, message, details);
        this.name = "BundleSourceChangedError";
    }
}

export class BundleUnsafePathError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.UNSAFE_PATH, message, details);
        this.name = "BundleUnsafePathError";
    }
}

// --- generic helpers ------------------------------------------------------

function hasExactKeys(value, expected) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const actual = Object.keys(value).sort();
    return actual.length === expected.length
        && actual.every((key, index) => key === expected[index]);
}

function compareStable(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalEqual(left, right) {
    return canonicalize(left) === canonicalize(right);
}

function sha256Bytes(bytes) {
    return createHash(ALGO).update(bytes).digest("hex");
}

function decodeUtf8(bytes, label, ErrorClass) {
    try {
        return UTF8.decode(bytes);
    } catch (err) {
        throw new ErrorClass(`${label} is not valid UTF-8`, { cause: err.message });
    }
}

function normalizeTaggedDigest(value, field = "expectedDigest") {
    if (typeof value !== "string") {
        throw new InvalidArgumentError(`${field} must be a sha256 digest string`, { field });
    }
    const tagged = HEX64_RE.test(value) ? objectIdFor(value) : value;
    let parsed;
    try {
        parsed = parseObjectId(tagged);
    } catch (err) {
        throw new InvalidArgumentError(`${field} must be sha256:<64 lowercase hex>`, {
            field,
            value,
            cause: err.message,
        });
    }
    return objectIdFor(parsed.hex);
}

function digestMatches(left, right) {
    const leftHex = parseObjectId(left).hex;
    const rightHex = parseObjectId(right).hex;
    return timingSafeEqual(Buffer.from(leftHex, "hex"), Buffer.from(rightHex, "hex"));
}

function sameCanonicalPath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function isInsideDir(childAbs, parentAbs) {
    const relative = path.relative(path.resolve(parentAbs), path.resolve(childAbs));
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function assertSafeComponent(name, context) {
    if (typeof name !== "string" || name.length === 0 || name === "." || name === "..") {
        throw new BundleUnsafePathError("unsafe empty or relative path component", { context, name });
    }
    if (name.includes("/") || name.includes("\\") || name.includes("\0") || name.includes(":")) {
        throw new BundleUnsafePathError("path component contains a separator, colon, or NUL", {
            context,
            name,
        });
    }
    if (/[\u0000-\u001f<>"|?*]/u.test(name)
        || name.endsWith(".")
        || name.endsWith(" ")
        || WINDOWS_RESERVED_DEVICE_RE.test(name)) {
        throw new BundleUnsafePathError("path component is ambiguous or reserved on Windows", {
            context,
            name,
        });
    }
}

function safeRelSegments(relPath) {
    if (typeof relPath !== "string" || relPath.length === 0 || relPath.length > MAX_REL_PATH) {
        throw new BundleInventoryError("inventory path length is invalid", { relPath });
    }
    if (path.posix.isAbsolute(relPath)
        || path.win32.isAbsolute(relPath)
        || /^[A-Za-z]:/u.test(relPath)
        || relPath.includes("\\")) {
        throw new BundleInventoryError("inventory path is not a canonical relative POSIX path", {
            relPath,
        });
    }
    const segments = relPath.split("/");
    try {
        for (const segment of segments) {
            assertSafeComponent(segment, relPath);
        }
    } catch (err) {
        if (err instanceof BundleUnsafePathError) {
            throw new BundleInventoryError(err.message, { relPath, cause: err.details });
        }
        throw err;
    }
    return segments;
}

function identity(stat, { mutable = true } = {}) {
    const dev = stat?.dev;
    const ino = stat?.ino;
    if ((typeof dev !== "bigint" && typeof dev !== "number")
        || (typeof ino !== "bigint" && typeof ino !== "number")
        || BigInt(dev) <= 0n
        || BigInt(ino) <= 0n) {
        throw new BundleSourceChangedError(
            "filesystem does not expose a stable file identity; refusing the operation",
        );
    }
    const result = {
        dev: BigInt(dev).toString(),
        ino: BigInt(ino).toString(),
        mode: BigInt(stat.mode).toString(),
        birthtimeNs: BigInt(stat.birthtimeNs ?? 0n).toString(),
    };
    if (mutable) {
        result.size = BigInt(stat.size).toString();
        result.mtimeNs = BigInt(stat.mtimeNs ?? 0n).toString();
        result.ctimeNs = BigInt(stat.ctimeNs ?? 0n).toString();
    }
    return Object.freeze(result);
}

function assertIdentity(before, after, filePath, message = "filesystem identity changed") {
    if (!canonicalEqual(before, after)) {
        throw new BundleSourceChangedError(message, { path: filePath, before, after });
    }
}

function lstatOrNull(filePath) {
    try {
        return fs.lstatSync(filePath, { bigint: true });
    } catch (err) {
        if (err && err.code === "ENOENT") {
            return null;
        }
        throw err;
    }
}

function assertSafeExistingPath(absPath, expectedType) {
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
            throw new BundleUnsafePathError("symlink, junction, or reparse path component rejected", {
                path: current,
            });
        }
        const leaf = index === segments.length - 1;
        if (!leaf && !stat.isDirectory()) {
            throw new BundleUnsafePathError("non-directory path component rejected", { path: current });
        }
        if (leaf && expectedType === "directory" && !stat.isDirectory()) {
            throw new BundleUnsafePathError("expected a directory", { path: current });
        }
        if (leaf && expectedType === "file" && !stat.isFile()) {
            throw new BundleUnsafePathError("expected a regular file", { path: current });
        }
        const real = fs.realpathSync.native(current);
        if (!sameCanonicalPath(current, real)) {
            throw new BundleUnsafePathError(
                "path component resolves through a symlink, junction, or reparse point",
                { path: current, real },
            );
        }
    }

    const leafStat = fs.lstatSync(resolved, { bigint: true });
    return {
        path: resolved,
        real: fs.realpathSync.native(resolved),
        stat: leafStat,
        identity: identity(leafStat),
        anchor: identity(leafStat, { mutable: false }),
    };
}

function ensureSafeDirectory(absPath, control) {
    const resolved = path.resolve(absPath);
    const parsed = path.parse(resolved);
    const relative = path.relative(parsed.root, resolved);
    const segments = relative === "" ? [] : relative.split(path.sep);
    let current = parsed.root;
    for (const segment of segments) {
        assertSafeComponent(segment, resolved);
        current = path.join(current, segment);
        let stat = lstatOrNull(current);
        if (stat === null) {
            fs.mkdirSync(current, { recursive: false, mode: 0o700 });
            try {
                fs.chmodSync(current, 0o700);
            } catch {
                // Windows applies the available subset; identity checks remain mandatory.
            }
            stat = fs.lstatSync(current, { bigint: true });
            fsyncDirectory(path.dirname(current), control, "bundle directory creation parent");
        }
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
            throw new BundleUnsafePathError("destination path component is not a private directory", {
                path: current,
            });
        }
        const real = fs.realpathSync.native(current);
        if (!sameCanonicalPath(current, real)) {
            throw new BundleUnsafePathError(
                "destination path resolves through a symlink, junction, or reparse point",
                { path: current, real },
            );
        }
    }
    return assertSafeExistingPath(resolved, "directory");
}

function assertDirectoryAnchor(dirPath, anchor) {
    const checked = assertSafeExistingPath(dirPath, "directory");
    assertIdentity(anchor, checked.anchor, dirPath, "directory was replaced during bundle operation");
    return checked;
}

function controlFor(options, operation) {
    const { faultInjector = null, hooks = null } = options;
    if (faultInjector !== null && typeof faultInjector !== "function") {
        throw new InvalidArgumentError("faultInjector must be a function or null");
    }
    if (hooks !== null && (typeof hooks !== "object" || Array.isArray(hooks))) {
        throw new InvalidArgumentError("hooks must be an object or null");
    }
    return Object.freeze({ operation, faultInjector, hooks });
}

const HOOK_NAMES = Object.freeze({
    "after-source-open": "afterSourceOpen",
    "after-source-copy": "afterSourceCopy",
    "after-source-scan": "afterSourceScan",
    "before-stage-file-open": "beforeStageFileOpen",
    "before-database-backup": "beforeDatabaseBackup",
    "before-publish": "beforePublish",
});

function inject(control, point, details = {}) {
    const event = { point, operation: control.operation, ...details };
    if (control.faultInjector !== null) {
        control.faultInjector(event);
    }
    const hookName = HOOK_NAMES[point];
    const hook = hookName === undefined ? null : control.hooks?.[hookName];
    if (typeof hook === "function") {
        hook(event);
    }
}

function fsyncDirectory(dirPath, control, purpose) {
    let fd;
    let failure = null;
    try {
        inject(control, "before-directory-fsync", { path: dirPath, purpose });
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
        throw new BundleError(
            BUNDLE_ERROR_CODES.IO_ERROR,
            `failed to fsync directory for ${purpose}: ${failure.message}`,
            {
                path: dirPath,
                purpose,
                fsCode: failure.code,
                syscall: failure.syscall,
            },
        );
    }
    inject(control, "after-directory-fsync", { path: dirPath, purpose });
}

function fsyncDirectoryChain(startDir, stopDir, control, purpose) {
    const start = path.resolve(startDir);
    const stop = path.resolve(stopDir);
    if (!isInsideDir(start, stop)) {
        throw new BundleUnsafePathError("bundle durability fence escaped its trusted root", {
            start,
            stop,
            purpose,
        });
    }
    let current = start;
    let depth = 0;
    for (;;) {
        fsyncDirectory(
            current,
            control,
            depth === 0 ? purpose : `${purpose} ancestor`,
        );
        if (sameCanonicalPath(current, stop)) {
            break;
        }
        const parent = path.dirname(current);
        if (parent === current) {
            throw new BundleUnsafePathError(
                "bundle durability fence reached a filesystem root early",
                { start, stop, purpose },
            );
        }
        current = parent;
        depth += 1;
    }
}

function removeTreeNoFollow(rootPath, rootAnchor = null) {
    const stat = lstatOrNull(rootPath);
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
    if (rootAnchor !== null) {
        assertIdentity(rootAnchor, identity(stat, { mutable: false }), rootPath,
            "refusing to recursively remove a replaced staging directory");
    }
    const rootReal = fs.realpathSync.native(rootPath);
    if (!sameCanonicalPath(rootPath, rootReal)) {
        throw new BundleUnsafePathError("refusing to clean a staging directory through a reparse point", {
            rootPath,
            rootReal,
        });
    }
    for (const name of fs.readdirSync(rootPath)) {
        assertSafeComponent(name, rootPath);
        const child = path.join(rootPath, name);
        const childStat = fs.lstatSync(child, { bigint: true });
        if (childStat.isSymbolicLink()) {
            fs.unlinkSync(child);
        } else if (childStat.isDirectory()) {
            removeTreeNoFollow(child);
        } else {
            fs.unlinkSync(child);
        }
    }
    fs.rmdirSync(rootPath);
}

function createPrivateStage(destResolved, control) {
    const parent = path.dirname(destResolved);
    if (parent === destResolved) {
        throw new BundleUnsafePathError("bundle destination cannot be a filesystem root", {
            dest: destResolved,
        });
    }
    const parentInfo = ensureSafeDirectory(parent, control);
    const existing = lstatOrNull(destResolved);
    if (existing !== null) {
        const checked = assertSafeExistingPath(destResolved, "directory");
        if (fs.readdirSync(checked.path).length !== 0) {
            throw new BundleDestinationExistsError(
                "destination already exists and is not empty",
                { dest: destResolved },
            );
        }
        fs.rmdirSync(checked.path);
        fsyncDirectory(parent, control, "empty bundle destination removal parent");
    }

    for (let attempt = 0; attempt < 32; attempt += 1) {
        const name = `.crucible-bundle-${control.operation}-${randomBytes(12).toString("hex")}.stage`;
        const stage = path.join(parent, name);
        try {
            fs.mkdirSync(stage, { recursive: false, mode: 0o700 });
            try {
                fs.chmodSync(stage, 0o700);
            } catch {
                // Best available Windows semantics.
            }
            const stageInfo = assertSafeExistingPath(stage, "directory");
            fsyncDirectory(parent, control, "bundle staging parent");
            assertDirectoryAnchor(parent, parentInfo.anchor);
            return {
                dest: destResolved,
                parent,
                parentAnchor: parentInfo.anchor,
                stage,
                stageAnchor: stageInfo.anchor,
            };
        } catch (err) {
            if (err && err.code === "EEXIST") {
                continue;
            }
            throw err;
        }
    }
    throw new BundleError(BUNDLE_ERROR_CODES.IO_ERROR, "could not allocate private bundle staging", {
        dest: destResolved,
    });
}

function assertStageRoot(stageContext) {
    assertDirectoryAnchor(stageContext.parent, stageContext.parentAnchor);
    const checked = assertDirectoryAnchor(stageContext.stage, stageContext.stageAnchor);
    if (!isInsideDir(checked.real, stageContext.parent)) {
        throw new BundleUnsafePathError("staging directory escaped its verified parent", {
            stage: stageContext.stage,
            real: checked.real,
        });
    }
    return checked;
}

function ensureStageParent(stageContext, segments, control) {
    assertStageRoot(stageContext);
    let current = stageContext.stage;
    for (const segment of segments) {
        assertSafeComponent(segment, segments.join("/"));
        current = path.join(current, segment);
        let stat = lstatOrNull(current);
        if (stat === null) {
            fs.mkdirSync(current, { recursive: false, mode: 0o700 });
            try {
                fs.chmodSync(current, 0o700);
            } catch {
                // Best available Windows semantics.
            }
            stat = fs.lstatSync(current, { bigint: true });
            fsyncDirectory(
                path.dirname(current),
                control,
                "bundle staged directory parent",
            );
        }
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
            throw new BundleUnsafePathError("staging path component changed into a link/non-directory", {
                path: current,
            });
        }
        const real = fs.realpathSync.native(current);
        if (!sameCanonicalPath(current, real) || !isInsideDir(real, stageContext.stage)) {
            throw new BundleUnsafePathError("staging path component escapes the private root", {
                path: current,
                real,
            });
        }
        assertStageRoot(stageContext);
    }
    return current;
}

function openStageFile(stageContext, relPath, control) {
    const segments = safeRelSegments(relPath);
    const parent = ensureStageParent(stageContext, segments.slice(0, -1), control);
    const target = path.join(parent, segments.at(-1));
    inject(control, "before-stage-file-open", {
        relativePath: relPath,
        path: target,
        stagingDir: stageContext.stage,
    });
    assertStageRoot(stageContext);
    assertSafeExistingPath(parent, "directory");
    const parentReal = fs.realpathSync.native(parent);
    if (!isInsideDir(parentReal, stageContext.stage)) {
        throw new BundleUnsafePathError("staging file parent escaped the private root", {
            relativePath: relPath,
            parentReal,
        });
    }

    const fd = fs.openSync(target, "wx", 0o600);
    try {
        const handleStat = fs.fstatSync(fd, { bigint: true });
        if (!handleStat.isFile()) {
            throw new BundleUnsafePathError("opened staging target is not a regular file", {
                relativePath: relPath,
            });
        }
        const pathStat = fs.lstatSync(target, { bigint: true });
        if (pathStat.isSymbolicLink() || !pathStat.isFile()) {
            throw new BundleUnsafePathError("staging target changed into a link/non-file", {
                relativePath: relPath,
            });
        }
        assertIdentity(identity(handleStat), identity(pathStat), target,
            "staging path does not identify the opened file");
        const targetReal = fs.realpathSync.native(target);
        if (!sameCanonicalPath(target, targetReal) || !isInsideDir(targetReal, stageContext.stage)) {
            throw new BundleUnsafePathError("opened staging target escapes the private root", {
                relativePath: relPath,
                targetReal,
            });
        }
        assertStageRoot(stageContext);
        return { fd, target };
    } catch (err) {
        fs.closeSync(fd);
        try {
            fs.unlinkSync(target);
        } catch {
            // Preserve the binding failure.
        }
        throw err;
    }
}

function writeAll(fd, bytes) {
    let offset = 0;
    while (offset < bytes.length) {
        offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
    }
}

function writeStageBytes(stageContext, relPath, bytes, control) {
    const source = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    const { fd, target } = openStageFile(stageContext, relPath, control);
    try {
        writeAll(fd, source);
        fs.fsyncSync(fd);
    } finally {
        fs.closeSync(fd);
    }
    const checked = assertSafeExistingPath(target, "file");
    return { path: target, hash: sha256Bytes(source), size: source.length, identity: checked.identity };
}

function readOpenedFile(fd, maxBytes, label) {
    const chunks = [];
    const hash = createHash(ALGO);
    const buffer = Buffer.allocUnsafe(COPY_CHUNK);
    let size = 0;
    for (;;) {
        const read = fs.readSync(fd, buffer, 0, buffer.length, null);
        if (read === 0) {
            break;
        }
        size += read;
        if (size > maxBytes) {
            throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID, `${label} exceeds its size limit`, {
                maxBytes,
            });
        }
        const chunk = Buffer.from(buffer.subarray(0, read));
        chunks.push(chunk);
        hash.update(chunk);
    }
    return { bytes: Buffer.concat(chunks, size), hash: hash.digest("hex"), size };
}

function openStableSource(srcAbs, sourceRoot, relPath, control) {
    const beforePath = assertSafeExistingPath(srcAbs, "file");
    const rootReal = fs.realpathSync.native(sourceRoot);
    if (!isInsideDir(beforePath.real, rootReal)) {
        throw new BundleUnsafePathError("source file escapes its verified root", {
            path: srcAbs,
            sourceRoot,
            real: beforePath.real,
        });
    }
    const fd = fs.openSync(srcAbs, "r");
    try {
        const openedStat = fs.fstatSync(fd, { bigint: true });
        if (!openedStat.isFile()) {
            throw new BundleUnsafePathError("opened source is not a regular file", { path: srcAbs });
        }
        assertIdentity(beforePath.identity, identity(openedStat), srcAbs,
            "source changed between path validation and open");
        const rebound = assertSafeExistingPath(srcAbs, "file");
        assertIdentity(beforePath.identity, rebound.identity, srcAbs,
            "source path changed immediately after open");
        if (!isInsideDir(rebound.real, rootReal)) {
            throw new BundleUnsafePathError("opened source path escapes its root", {
                path: srcAbs,
                real: rebound.real,
            });
        }
        inject(control, "after-source-open", {
            path: srcAbs,
            relativePath: relPath,
            fd,
        });
        const afterHook = assertSafeExistingPath(srcAbs, "file");
        assertIdentity(beforePath.identity, afterHook.identity, srcAbs,
            "source changed after it was opened");
        assertIdentity(beforePath.identity, identity(fs.fstatSync(fd, { bigint: true })), srcAbs,
            "opened source changed after it was validated");
        return { fd, before: beforePath.identity, real: beforePath.real };
    } catch (err) {
        fs.closeSync(fd);
        throw err;
    }
}

function finishStableSource(srcAbs, sourceRoot, opened) {
    const handleAfter = identity(fs.fstatSync(opened.fd, { bigint: true }));
    assertIdentity(opened.before, handleAfter, srcAbs, "opened source changed while being copied");
    const pathAfter = assertSafeExistingPath(srcAbs, "file");
    assertIdentity(opened.before, pathAfter.identity, srcAbs, "source path changed while being copied");
    if (!sameCanonicalPath(opened.real, pathAfter.real)
        || !isInsideDir(pathAfter.real, fs.realpathSync.native(sourceRoot))) {
        throw new BundleSourceChangedError("source realpath or containment changed while being copied", {
            path: srcAbs,
            before: opened.real,
            after: pathAfter.real,
        });
    }
}

function copyStableFile({
    srcAbs,
    sourceRoot,
    relPath,
    stageContext,
    control,
    maxBytes = Number.MAX_SAFE_INTEGER,
}) {
    const opened = openStableSource(srcAbs, sourceRoot, relPath, control);
    let target;
    let wfd;
    const hash = createHash(ALGO);
    const buffer = Buffer.allocUnsafe(COPY_CHUNK);
    let size = 0;
    try {
        const openedTarget = openStageFile(stageContext, relPath, control);
        target = openedTarget.target;
        wfd = openedTarget.fd;
        for (;;) {
            const read = fs.readSync(opened.fd, buffer, 0, buffer.length, null);
            if (read === 0) {
                break;
            }
            size += read;
            if (size > maxBytes) {
                throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID, "bundle file exceeds size limit", {
                    relativePath: relPath,
                    maxBytes,
                });
            }
            let offset = 0;
            while (offset < read) {
                offset += fs.writeSync(wfd, buffer, offset, read - offset);
            }
            hash.update(buffer.subarray(0, read));
        }
        fs.fsyncSync(wfd);
        finishStableSource(srcAbs, sourceRoot, opened);
    } finally {
        try {
            fs.closeSync(opened.fd);
        } finally {
            if (wfd !== undefined) {
                fs.closeSync(wfd);
            }
        }
    }
    assertSafeExistingPath(target, "file");
    const result = { path: target, hash: hash.digest("hex"), size };
    inject(control, "after-source-copy", {
        path: srcAbs,
        relativePath: relPath,
        stagedPath: target,
        hash: result.hash,
        size,
    });
    return result;
}

function readStableFile(absPath, rootPath, maxBytes, label) {
    const control = Object.freeze({ operation: "verify", faultInjector: null, hooks: null });
    const opened = openStableSource(absPath, rootPath, path.relative(rootPath, absPath), control);
    try {
        const result = readOpenedFile(opened.fd, maxBytes, label);
        finishStableSource(absPath, rootPath, opened);
        return result;
    } finally {
        fs.closeSync(opened.fd);
    }
}

function hashStableFile(absPath, rootPath) {
    const control = Object.freeze({ operation: "verify", faultInjector: null, hooks: null });
    const opened = openStableSource(absPath, rootPath, path.relative(rootPath, absPath), control);
    const hash = createHash(ALGO);
    const buffer = Buffer.allocUnsafe(COPY_CHUNK);
    let size = 0;
    try {
        for (;;) {
            const read = fs.readSync(opened.fd, buffer, 0, buffer.length, null);
            if (read === 0) {
                break;
            }
            hash.update(buffer.subarray(0, read));
            size += read;
        }
        finishStableSource(absPath, rootPath, opened);
    } finally {
        fs.closeSync(opened.fd);
    }
    return { hash: hash.digest("hex"), size };
}

function scanTree(rootPath, control) {
    const root = assertSafeExistingPath(rootPath, "directory");
    const files = [];
    const fileIdentities = new Map();
    let count = 0;

    const walk = (dirAbs, relSegments, depth) => {
        if (depth > MAX_DEPTH) {
            throw new BundleUnsafePathError("bundle tree exceeds maximum directory depth", {
                path: dirAbs,
                maxDepth: MAX_DEPTH,
            });
        }
        const before = assertSafeExistingPath(dirAbs, "directory");
        if (!isInsideDir(before.real, root.real)) {
            throw new BundleUnsafePathError("bundle directory escapes its source root", {
                path: dirAbs,
                real: before.real,
            });
        }
        const firstNames = fs.readdirSync(dirAbs).sort(compareStable);
        for (const name of firstNames) {
            assertSafeComponent(name, dirAbs);
            const child = path.join(dirAbs, name);
            const rel = [...relSegments, name];
            const relPath = rel.join("/");
            if (relPath.length > MAX_REL_PATH) {
                throw new BundleUnsafePathError("bundle relative path exceeds maximum length", {
                    relPath,
                });
            }
            const stat = fs.lstatSync(child, { bigint: true });
            if (stat.isSymbolicLink()) {
                throw new BundleUnsafePathError("bundle contains a symlink, junction, or reparse entry", {
                    relPath,
                });
            }
            const real = fs.realpathSync.native(child);
            if (!sameCanonicalPath(child, real) || !isInsideDir(real, root.real)) {
                throw new BundleUnsafePathError("bundle entry escapes its source root", {
                    relPath,
                    real,
                });
            }
            if (stat.isDirectory()) {
                walk(child, rel, depth + 1);
            } else if (stat.isFile()) {
                count += 1;
                if (count > MAX_BUNDLE_FILES) {
                    throw new BundleUnsafePathError("bundle exceeds maximum file count", {
                        maxFiles: MAX_BUNDLE_FILES,
                    });
                }
                files.push(relPath);
                fileIdentities.set(relPath, identity(stat));
            } else {
                throw new BundleUnsafePathError("bundle contains a non-regular filesystem entry", {
                    relPath,
                });
            }
        }
        const secondNames = fs.readdirSync(dirAbs).sort(compareStable);
        if (!canonicalEqual(firstNames, secondNames)) {
            throw new BundleSourceChangedError("bundle directory entries changed during traversal", {
                path: dirAbs,
                before: firstNames,
                after: secondNames,
            });
        }
        const after = assertSafeExistingPath(dirAbs, "directory");
        assertIdentity(before.identity, after.identity, dirAbs,
            "bundle directory changed during traversal");
    };

    walk(root.path, [], 0);
    files.sort(compareStable);
    inject(control, "after-source-scan", { path: root.path, files: [...files] });
    return {
        files,
        fileIdentities,
        rootIdentity: root.identity,
        rootAnchor: root.anchor,
    };
}

function compareScans(before, after, rootPath) {
    if (!canonicalEqual(before.files, after.files)) {
        throw new BundleSourceChangedError("bundle file set changed while it was copied", {
            path: rootPath,
            before: before.files,
            after: after.files,
        });
    }
    assertIdentity(before.rootIdentity, after.rootIdentity, rootPath,
        "bundle source root changed while it was copied");
    for (const relPath of before.files) {
        assertIdentity(
            before.fileIdentities.get(relPath),
            after.fileIdentities.get(relPath),
            path.join(rootPath, ...relPath.split("/")),
            "bundle source file changed while the bundle was copied",
        );
    }
}

function fsyncBundleTree(rootPath, control, purpose) {
    const root = assertSafeExistingPath(rootPath, "directory");
    const walk = (dirPath) => {
        const before = assertSafeExistingPath(dirPath, "directory");
        if (!isInsideDir(before.real, root.real)) {
            throw new BundleUnsafePathError("bundle durability walk escaped its root", {
                root: root.path,
                path: dirPath,
                real: before.real,
            });
        }
        for (const name of fs.readdirSync(dirPath).sort(compareStable)) {
            assertSafeComponent(name, dirPath);
            const child = path.join(dirPath, name);
            const stat = fs.lstatSync(child, { bigint: true });
            if (stat.isSymbolicLink()) {
                throw new BundleUnsafePathError(
                    "bundle durability walk encountered a link or reparse point",
                    { path: child },
                );
            }
            if (stat.isDirectory()) {
                walk(child);
            } else if (!stat.isFile()) {
                throw new BundleUnsafePathError(
                    "bundle durability walk encountered a non-regular entry",
                    { path: child },
                );
            }
        }
        fsyncDirectory(dirPath, control, purpose);
        const after = assertSafeExistingPath(dirPath, "directory");
        assertIdentity(before.identity, after.identity, dirPath,
            "bundle directory changed while durability was fenced");
    };
    walk(root.path);
}

function publishStage(stageContext, control) {
    assertStageRoot(stageContext);
    assertDirectoryAnchor(stageContext.parent, stageContext.parentAnchor);

    const existing = lstatOrNull(stageContext.dest);
    if (existing !== null) {
        const checked = assertSafeExistingPath(stageContext.dest, "directory");
        if (fs.readdirSync(checked.path).length !== 0) {
            throw new BundleDestinationExistsError(
                "destination became non-empty before publication",
                { dest: stageContext.dest },
            );
        }
        throw new BundleDestinationExistsError("empty destination appeared before publication", {
            dest: stageContext.dest,
        });
    }

    fs.renameSync(stageContext.stage, stageContext.dest);
    try {
        fsyncDirectory(stageContext.parent, control, "bundle publication parent");
        const published = assertSafeExistingPath(stageContext.dest, "directory");
        assertIdentity(stageContext.stageAnchor, published.anchor, stageContext.dest,
            "published destination is not the verified staging directory");
        assertDirectoryAnchor(stageContext.parent, stageContext.parentAnchor);
        if (!isInsideDir(published.real, stageContext.parent)) {
            throw new BundleUnsafePathError("published bundle escapes its verified parent", {
                dest: stageContext.dest,
                real: published.real,
            });
        }
        return published.real;
    } catch (err) {
        try {
            removeTreeNoFollow(stageContext.dest, stageContext.stageAnchor);
            fsyncDirectory(
                stageContext.parent,
                control,
                "failed bundle rename cleanup parent",
            );
        } catch (cleanupError) {
            if (err && typeof err === "object") {
                err.cleanupError = cleanupError;
            }
        }
        throw err;
    }
}

function withPrivateStage(destDir, control, work, finalize) {
    const destResolved = assertLocalDatabasePath(destDir);
    const stageContext = createPrivateStage(destResolved, control);
    let published = false;
    try {
        const draft = work(stageContext);
        inject(control, "before-publish", {
            stagingDir: stageContext.stage,
            destDir: stageContext.dest,
            parentDir: stageContext.parent,
        });
        fsyncBundleTree(stageContext.stage, control, "staged bundle directory");
        const prepared = finalize(stageContext.stage, draft, {
            phase: "staged",
            prepared: null,
        });
        fsyncBundleTree(
            stageContext.stage,
            QUIET_DURABILITY_CONTROL,
            "verified staged bundle directory",
        );
        const dest = publishStage(stageContext, control);
        published = true;
        fsyncBundleTree(dest, control, "published bundle directory");
        const result = finalize(dest, draft, {
            phase: "published",
            prepared,
        });
        fsyncBundleTree(
            dest,
            QUIET_DURABILITY_CONTROL,
            "verified published bundle directory",
        );
        return { ...result, dest };
    } catch (err) {
        try {
            if (published) {
                removeTreeNoFollow(stageContext.dest, stageContext.stageAnchor);
                fsyncDirectory(
                    stageContext.parent,
                    control,
                    "failed bundle publication cleanup parent",
                );
            } else {
                removeTreeNoFollow(stageContext.stage, stageContext.stageAnchor);
            }
        } catch (cleanupError) {
            if (err && typeof err === "object") {
                err.cleanupError = cleanupError;
            }
        }
        if (err instanceof CruciblePersistenceError) {
            throw err;
        }
        throw new BundleError(BUNDLE_ERROR_CODES.IO_ERROR, err?.message ?? String(err), {
            fsCode: err?.code,
            syscall: err?.syscall,
        });
    }
}

// --- canonical inventory + manifest --------------------------------------

function serializeInventory(entries) {
    return [...entries]
        .sort((left, right) => compareStable(left.path, right.path))
        .map((entry) => `${entry.hash}  ${entry.path}`)
        .join("\n") + "\n";
}

function parseInventoryBytes(bytes) {
    if (bytes.length === 0 || bytes.length > MAX_INVENTORY_BYTES) {
        throw new BundleInventoryError("inventory size is invalid", {
            size: bytes.length,
            maxBytes: MAX_INVENTORY_BYTES,
        });
    }
    const text = decodeUtf8(bytes, "bundle inventory", BundleInventoryError);
    if (!text.endsWith("\n") || text.includes("\r") || text.endsWith("\n\n")) {
        throw new BundleInventoryError(
            "inventory must use LF lines with exactly one final newline",
        );
    }
    const lines = text.slice(0, -1).split("\n");
    const entries = [];
    let previous = null;
    for (let index = 0; index < lines.length; index += 1) {
        const match = /^([0-9a-f]{64}) {2}(.+)$/u.exec(lines[index]);
        if (!match) {
            throw new BundleInventoryError("malformed inventory line", {
                lineNumber: index + 1,
                line: lines[index],
            });
        }
        const [, hash, relPath] = match;
        safeRelSegments(relPath);
        if (relPath === INVENTORY_NAME) {
            throw new BundleInventoryError("inventory must not list itself");
        }
        if (previous !== null && previous >= relPath) {
            throw new BundleInventoryError(
                "inventory paths must be unique and strictly sorted",
                { previous, relPath },
            );
        }
        previous = relPath;
        entries.push({ hash, path: relPath });
    }
    if (entries.length === 0 || entries.length > MAX_BUNDLE_FILES) {
        throw new BundleInventoryError("inventory entry count is invalid", {
            count: entries.length,
            maxFiles: MAX_BUNDLE_FILES,
        });
    }
    const canonicalBytes = Buffer.from(serializeInventory(entries), "utf8");
    if (!canonicalBytes.equals(bytes)) {
        throw new BundleInventoryError("inventory bytes are not canonical");
    }
    return entries;
}

function assertCanonicalObjectId(value, context, ErrorClass = BundleManifestError) {
    let parsed;
    try {
        parsed = parseObjectId(value);
    } catch (err) {
        throw new ErrorClass("manifest contains an invalid object id", {
            context,
            value,
            cause: err.message,
        });
    }
    const canonical = objectIdFor(parsed.hex);
    if (canonical !== value) {
        throw new ErrorClass("manifest object id is not canonical", { context, value });
    }
    return parsed.hex;
}

function validateManifest(value, rawBytes = null) {
    if (!hasExactKeys(value, MANIFEST_KEYS)
        || value.type !== BUNDLE_TYPE
        || value.version !== BUNDLE_VERSION
        || value.algo !== ALGO
        || typeof value.createdAt !== "string"
        || !Array.isArray(value.artifacts)
        || !Array.isArray(value.objects)
        || !Array.isArray(value.snapshots)
        || !value.metadata
        || typeof value.metadata !== "object"
        || Array.isArray(value.metadata)) {
        throw new BundleManifestError("bundle manifest does not use the canonical schema", {
            actualKeys: value && typeof value === "object" && !Array.isArray(value)
                ? Object.keys(value).sort()
                : [],
            expectedKeys: MANIFEST_KEYS,
        });
    }
    const created = new Date(value.createdAt);
    if (!Number.isFinite(created.valueOf()) || created.toISOString() !== value.createdAt) {
        throw new BundleManifestError("manifest createdAt must be canonical UTC ISO-8601", {
            createdAt: value.createdAt,
        });
    }
    if (!hasExactKeys(value.database, DATABASE_KEYS)
        || value.database.path !== DB_RELPATH
        || value.database.schemaVersion !== SCHEMA_VERSION
        || value.database.schemaFingerprint !== SCHEMA_FINGERPRINT
        || !HEX64_RE.test(value.database.sha256)
        || !Number.isSafeInteger(value.database.size)
        || value.database.size < 0) {
        throw new BundleManifestError("manifest database binding is invalid");
    }
    if (!hasExactKeys(value.investigation, INVESTIGATION_KEYS)
        || typeof value.investigation.id !== "string"
        || value.investigation.id.length === 0
        || !Number.isSafeInteger(value.investigation.domainVersion)
        || value.investigation.domainVersion < 1
        || !hasExactKeys(value.investigation.domainHead, DOMAIN_HEAD_KEYS)) {
        throw new BundleManifestError("manifest investigation binding is invalid");
    }
    const head = value.investigation.domainHead;
    if (!Number.isSafeInteger(head.seq)
        || head.seq < 0
        || (head.seq === 0 ? head.eventHash !== null : !HEX64_RE.test(head.eventHash))) {
        throw new BundleManifestError("manifest domain head is invalid", { head });
    }

    let previousArtifact = null;
    for (const artifact of value.artifacts) {
        if (!hasExactKeys(artifact, ARTIFACT_KEYS)
            || typeof artifact.artifactId !== "string"
            || artifact.artifactId.length === 0
            || (artifact.contentType !== null && typeof artifact.contentType !== "string")
            || (artifact.sizeBytes !== null
                && (!Number.isSafeInteger(artifact.sizeBytes) || artifact.sizeBytes < 0))) {
            throw new BundleManifestError("manifest referenced artifact record is invalid", {
                artifact,
            });
        }
        assertCanonicalObjectId(artifact.object, `artifact:${artifact.artifactId}`);
        if (previousArtifact !== null && previousArtifact >= artifact.artifactId) {
            throw new BundleManifestError("manifest artifacts must be unique and sorted", {
                previousArtifact,
                artifactId: artifact.artifactId,
            });
        }
        previousArtifact = artifact.artifactId;
    }

    let previousObject = null;
    for (const object of value.objects) {
        if (!hasExactKeys(object, OBJECT_KEYS)
            || !Number.isSafeInteger(object.size)
            || object.size < 0) {
            throw new BundleManifestError("manifest object record is invalid", { object });
        }
        const hex = assertCanonicalObjectId(object.id, "objects");
        if (object.path !== objectRelPath(hex)) {
            throw new BundleManifestError("manifest object path does not match its content address", {
                id: object.id,
                path: object.path,
            });
        }
        if (previousObject !== null && previousObject >= object.id) {
            throw new BundleManifestError("manifest objects must be unique and sorted", {
                previousObject,
                id: object.id,
            });
        }
        previousObject = object.id;
    }

    let previousSnapshot = null;
    for (const snapshot of value.snapshots) {
        assertCanonicalObjectId(snapshot, "snapshots");
        if (previousSnapshot !== null && previousSnapshot >= snapshot) {
            throw new BundleManifestError("manifest snapshots must be unique and sorted", {
                previousSnapshot,
                snapshot,
            });
        }
        previousSnapshot = snapshot;
    }

    if (rawBytes !== null) {
        const canonicalBytes = Buffer.from(canonicalize(value) + "\n", "utf8");
        if (!canonicalBytes.equals(rawBytes)) {
            throw new BundleManifestError("manifest bytes are not canonical JSON");
        }
    }
    return value;
}

function parseManifestBytes(bytes) {
    if (bytes.length === 0 || bytes.length > MAX_MANIFEST_BYTES) {
        throw new BundleManifestError("manifest size is invalid", {
            size: bytes.length,
            maxBytes: MAX_MANIFEST_BYTES,
        });
    }
    const text = decodeUtf8(bytes, "bundle manifest", BundleManifestError);
    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch (err) {
        throw new BundleManifestError("bundle manifest is not valid JSON", {
            cause: err.message,
        });
    }
    return validateManifest(parsed, bytes);
}

// --- database and object closure -----------------------------------------

function inferInvestigationId(dbFile) {
    let db;
    try {
        db = new DatabaseSync(dbFile, { readOnly: true });
        const rows = db.prepare(`
            SELECT investigation_id
            FROM investigations
            ORDER BY investigation_id
        `).all();
        if (rows.length !== 1) {
            throw new BundleError(
                BUNDLE_ERROR_CODES.SOURCE_INVALID,
                "investigationId is required when the database does not contain exactly one investigation",
                { investigationCount: rows.length },
            );
        }
        return rows[0].investigation_id;
    } catch (err) {
        if (err instanceof CruciblePersistenceError) {
            throw err;
        }
        throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID,
            `cannot inspect database investigations: ${err.message}`);
    } finally {
        try {
            db?.close();
        } catch {
            // Preserve the primary result.
        }
    }
}

function removeBundleDatabaseSidecars(dbFile) {
    for (const suffix of ["-wal", "-shm"]) {
        const sidecar = `${dbFile}${suffix}`;
        const stat = lstatOrNull(sidecar);
        if (stat === null) {
            continue;
        }
        const checked = assertSafeExistingPath(sidecar, "file");
        if (!sameCanonicalPath(path.dirname(checked.real), path.dirname(dbFile))) {
            throw new BundleUnsafePathError("SQLite sidecar escaped the bundle database directory", {
                sidecar,
                real: checked.real,
            });
        }
        fs.unlinkSync(sidecar);
    }
}

function inspectPersistedDomainVersion(repo, investigation) {
    const metadataDomainVersion = Number.isSafeInteger(
        investigation.metadata?.domainVersion,
    ) && investigation.metadata.domainVersion > 0
        ? investigation.metadata.domainVersion
        : null;
    const first = repo.getEvent(investigation.investigationId, 1);
    const isDomainOpening = first !== null
        && /^domain:(?:v[1-9][0-9]*:)?investigation_opened$/u.test(first.kind)
        && first.payload?.domainEvent?.type === "investigation_opened";
    if (!isDomainOpening) {
        if (metadataDomainVersion === null) {
            throw new BundleError(
                BUNDLE_ERROR_CODES.SOURCE_INVALID,
                "investigation domain version is not discoverable from its opening event or metadata",
                { investigationId: investigation.investigationId },
            );
        }
        return metadataDomainVersion;
    }

    const eventDomainVersion = first.payload?.domainEvent?.payload?.domainVersion;
    const contractDomainVersion =
        first.payload?.domainEvent?.payload?.contract?.domainVersion ?? null;
    if (!Number.isSafeInteger(eventDomainVersion) || eventDomainVersion < 1) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.SOURCE_INVALID,
            "investigation opening event has no valid domain version",
            { investigationId: investigation.investigationId },
        );
    }
    if (contractDomainVersion !== null
        && contractDomainVersion !== eventDomainVersion) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.SOURCE_INVALID,
            "investigation opening event and contract domain versions disagree",
            {
                investigationId: investigation.investigationId,
                eventDomainVersion,
                contractDomainVersion,
            },
        );
    }
    if (eventDomainVersion === DOMAIN_VERSION
        && contractDomainVersion !== DOMAIN_VERSION) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.SOURCE_INVALID,
            "active-domain investigation contract is missing its authoritative domain version",
            {
                investigationId: investigation.investigationId,
                eventDomainVersion,
                contractDomainVersion,
            },
        );
    }
    if (metadataDomainVersion !== null
        && metadataDomainVersion !== eventDomainVersion) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.SOURCE_INVALID,
            "investigation metadata and opening event domain versions disagree",
            {
                investigationId: investigation.investigationId,
                metadataDomainVersion,
                eventDomainVersion,
            },
        );
    }
    return eventDomainVersion;
}

function inspectDatabaseBinding(dbFile, requestedInvestigationId = null) {
    const investigationId = requestedInvestigationId ?? inferInvestigationId(dbFile);
    if (typeof investigationId !== "string" || investigationId.length === 0) {
        throw new InvalidArgumentError("investigationId must be a non-empty string");
    }
    let repo;
    try {
        repo = openRepositoryReadOnly({ file: dbFile });
        const investigation = repo.getInvestigation(investigationId);
        if (investigation === null) {
            throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID,
                "bundle investigation is not present in the database", { investigationId });
        }
        const report = repo.verifyInvestigation(investigationId);
        if (!report.ok) {
            throw new BundleTamperError("database investigation integrity verification failed", {
                investigationId,
                violations: report.violations,
            });
        }
        const domainVersion = inspectPersistedDomainVersion(repo, investigation);
        const head = repo.getHead(investigationId);
        const artifactsById = new Map();
        for (const ref of repo.listArtifactRefs(investigationId)) {
            if (artifactsById.has(ref.artifactId)) {
                continue;
            }
            const artifact = repo.getArtifact(ref.artifactId);
            if (artifact === null || artifact.investigationId !== investigationId) {
                throw new BundleTamperError("database artifact reference is unresolved", {
                    investigationId,
                    artifactId: ref.artifactId,
                });
            }
            if (artifact.storage === "external") {
                if (artifact.hashAlgo !== ALGO || !HEX64_RE.test(artifact.hashValue ?? "")) {
                    throw new BundleError(
                        BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                        "referenced external artifact is not a canonical sha256 CAS object",
                        {
                            investigationId,
                            artifactId: artifact.artifactId,
                            hashAlgo: artifact.hashAlgo,
                            hashValue: artifact.hashValue,
                        },
                    );
                }
                artifactsById.set(artifact.artifactId, {
                    artifactId: artifact.artifactId,
                    contentType: artifact.contentType,
                    object: objectIdFor(artifact.hashValue),
                    sizeBytes: artifact.sizeBytes,
                });
            }
        }
        const artifacts = [...artifactsById.values()]
            .sort((left, right) => compareStable(left.artifactId, right.artifactId));
        const snapshotRoots = artifacts
            .filter((artifact) => artifact.contentType === SNAPSHOT_CONTENT_TYPE)
            .map((artifact) => artifact.object)
            .sort(compareStable);
        return {
            investigationId,
            domainVersion,
            domainHead: { seq: head.seq, eventHash: head.eventHash },
            artifacts,
            snapshotRoots,
        };
    } catch (err) {
        if (err instanceof CruciblePersistenceError) {
            throw err;
        }
        throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID,
            `database binding verification failed: ${err.message}`, { investigationId });
    } finally {
        try {
            repo?.close();
        } catch {
            // Preserve the primary result.
        }
        removeBundleDatabaseSidecars(dbFile);
    }
}

function assertCallerClosureHints(binding, objectIds, snapshots) {
    if (!Array.isArray(objectIds) || !Array.isArray(snapshots)) {
        throw new InvalidArgumentError("objectIds and snapshots must be arrays");
    }
    const direct = new Set(binding.artifacts.map((artifact) => artifact.object));
    for (const [index, id] of objectIds.entries()) {
        const { hex } = parseObjectId(id);
        const canonical = objectIdFor(hex);
        if (!direct.has(canonical)) {
            throw new BundleError(
                BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                "caller-supplied object is not referenced by the investigation database",
                { index, object: canonical },
            );
        }
    }
    if (snapshots.length > 0) {
        const normalized = [...new Set(snapshots.map((id) => {
            const { hex } = parseObjectId(id);
            return objectIdFor(hex);
        }))].sort(compareStable);
        if (!canonicalEqual(normalized, binding.snapshotRoots)) {
            throw new BundleError(
                BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                "caller-supplied snapshot roots disagree with referenced snapshot artifacts",
                { expected: binding.snapshotRoots, actual: normalized },
            );
        }
    }
}

function copyObjectFromStore(store, objectId, stageContext, control) {
    const { hex } = parseObjectId(objectId);
    const relPath = objectRelPath(hex);
    const srcAbs = store.objectPath(objectId);
    let copied;
    try {
        copied = copyStableFile({
            srcAbs,
            sourceRoot: store.root,
            relPath,
            stageContext,
            control,
        });
    } catch (err) {
        if (err && err.code === "ENOENT") {
            throw new BundleError(BUNDLE_ERROR_CODES.OBJECT_MISSING,
                "referenced CAS object is missing", { objectId });
        }
        throw err;
    }
    if (copied.hash !== hex) {
        throw new BundleTamperError("referenced CAS object does not match its content address", {
            objectId,
            expected: hex,
            actual: copied.hash,
        });
    }
    return { id: objectId, path: relPath, size: copied.size };
}

function expandSnapshotClosure(stageRoot, directIds, snapshotRoots) {
    const stagedStore = openArtifactStoreReadOnly({ root: stageRoot });
    const closure = new Set(directIds);
    const expectedSizes = new Map();
    for (const snapshot of snapshotRoots) {
        let manifest;
        try {
            manifest = stagedStore.loadManifest(snapshot);
        } catch (err) {
            throw new BundleError(
                BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                `snapshot manifest is invalid: ${err.message}`,
                { snapshot, cause: err.code },
            );
        }
        for (const entry of manifest.entries) {
            closure.add(entry.object);
            const prior = expectedSizes.get(entry.object);
            if (prior !== undefined && prior !== entry.size) {
                throw new BundleError(
                    BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                    "snapshot closure assigns conflicting sizes to one object",
                    { object: entry.object, prior, size: entry.size },
                );
            }
            expectedSizes.set(entry.object, entry.size);
        }
    }
    return {
        objectIds: [...closure].sort(compareStable),
        expectedSizes,
    };
}

function onlineBackupDatabase(dbFile, stageContext, control) {
    const resolvedDb = assertLocalDatabasePath(dbFile);
    let source;
    try {
        source = assertSafeExistingPath(resolvedDb, "file");
    } catch (err) {
        if (err && err.code === "ENOENT") {
            throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID,
                "database file does not exist", { dbFile: resolvedDb });
        }
        throw err;
    }
    const dbDest = path.join(stageContext.stage, ...DB_RELPATH.split("/"));
    ensureStageParent(stageContext, DB_RELPATH.split("/").slice(0, -1), control);
    inject(control, "before-database-backup", {
        sourcePath: resolvedDb,
        stagedPath: dbDest,
    });
    const afterHook = assertSafeExistingPath(resolvedDb, "file");
    assertIdentity(source.identity, afterHook.identity, resolvedDb,
        "database source changed before backup");
    assertStageRoot(stageContext);

    let backupFd;
    let backupAnchor;
    try {
        const opened = openStageFile(stageContext, DB_RELPATH, control);
        backupFd = opened.fd;
        const openedStat = fs.fstatSync(backupFd, { bigint: true });
        backupAnchor = identity(openedStat, { mutable: false });
        if (BigInt(openedStat.size) !== 0n) {
            throw new BundleUnsafePathError("secure backup destination was not empty", {
                path: opened.target,
            });
        }
    } catch (err) {
        if (backupFd !== undefined) {
            try {
                fs.closeSync(backupFd);
            } catch {
                // Preserve the secure-open failure.
            }
        }
        throw err;
    }

    let backup;
    try {
        let db;
        try {
            db = new DatabaseSync(resolvedDb, { readOnly: true });
            const escaped = dbDest.replaceAll("'", "''");
            db.exec(`VACUUM INTO '${escaped}'`);
        } catch (err) {
            throw new BundleError(BUNDLE_ERROR_CODES.IO_ERROR,
                `online database backup failed: ${err.message}`, { dbFile: resolvedDb });
        } finally {
            try {
                db?.close();
            } catch {
                // Preserve the backup result.
            }
        }
        const afterVacuumPath = assertSafeExistingPath(dbDest, "file");
        assertIdentity(
            backupAnchor,
            afterVacuumPath.anchor,
            dbDest,
            "database backup path was replaced during VACUUM INTO",
        );
        assertIdentity(
            backupAnchor,
            identity(fs.fstatSync(backupFd, { bigint: true }), { mutable: false }),
            dbDest,
            "secure database backup handle changed identity",
        );
        if (!isInsideDir(afterVacuumPath.real, stageContext.stage)) {
            throw new BundleUnsafePathError("database backup escaped the private stage", {
                path: dbDest,
                real: afterVacuumPath.real,
            });
        }
        try {
            db = new DatabaseSync(dbDest);
            configureConnection(db, { busyTimeoutMs: 5000 });
        } catch (err) {
            throw new BundleError(BUNDLE_ERROR_CODES.IO_ERROR,
                `failed to normalize backup database pragmas: ${err.message}`, { dbFile: dbDest });
        } finally {
            try {
                db?.close();
            } catch {
                // Preserve the pragma-normalization result.
            }
        }
        const afterNormalize = assertSafeExistingPath(dbDest, "file");
        assertIdentity(
            backupAnchor,
            afterNormalize.anchor,
            dbDest,
            "database backup path was replaced during pragma normalization",
        );
        removeBundleDatabaseSidecars(dbDest);
        const sourceAfter = assertSafeExistingPath(resolvedDb, "file");
        assertIdentity(source.identity, sourceAfter.identity, resolvedDb,
            "database source changed during backup");
        assertStageRoot(stageContext);
        backup = assertSafeExistingPath(dbDest, "file");
        assertIdentity(
            backupAnchor,
            backup.anchor,
            dbDest,
            "database backup path changed before durability fencing",
        );
        if (!isInsideDir(backup.real, stageContext.stage)) {
            throw new BundleUnsafePathError(
                "database backup escaped the private stage before publication",
                { path: dbDest, real: backup.real, stage: stageContext.stage },
            );
        }
        fs.fsyncSync(backupFd);
    } finally {
        if (backupFd !== undefined) {
            fs.closeSync(backupFd);
            backupFd = undefined;
        }
    }
    fsyncDirectory(
        path.dirname(dbDest),
        control,
        "database backup parent",
    );
    const hashed = hashStableFile(backup.path, stageContext.stage);
    return { path: dbDest, hash: hashed.hash, size: hashed.size };
}

function expectedBundlePaths(manifest) {
    return [
        DB_RELPATH,
        MANIFEST_NAME,
        ...manifest.objects.map((object) => object.path),
    ].sort(compareStable);
}

function verifyBundleStage(
    stageRoot,
    expectedInvestigationId = null,
    requiredDomainVersion = null,
) {
    const scan = scanTree(stageRoot,
        Object.freeze({ operation: "verify", faultInjector: null, hooks: null }));
    const inventoryPath = path.join(stageRoot, INVENTORY_NAME);
    if (!scan.files.includes(INVENTORY_NAME)) {
        throw new BundleInventoryError("bundle is missing its inventory");
    }
    const inventoryRead = readStableFile(
        inventoryPath,
        stageRoot,
        MAX_INVENTORY_BYTES,
        "bundle inventory",
    );
    const inventory = parseInventoryBytes(inventoryRead.bytes);
    const digest = objectIdFor(inventoryRead.hash);
    const inventoryPaths = inventory.map((entry) => entry.path);
    const actualWithoutInventory = scan.files.filter((relPath) => relPath !== INVENTORY_NAME);
    if (!canonicalEqual(inventoryPaths, actualWithoutInventory)) {
        throw new BundleTamperError("inventory does not exactly cover the staged bundle", {
            inventoryPaths,
            actualPaths: actualWithoutInventory,
        });
    }

    const inventoryMap = new Map(inventory.map((entry) => [entry.path, entry.hash]));
    for (const entry of inventory) {
        const abs = path.join(stageRoot, ...entry.path.split("/"));
        const actual = hashStableFile(abs, stageRoot);
        if (actual.hash !== entry.hash) {
            throw new BundleTamperError("staged bundle file hash does not match inventory", {
                path: entry.path,
                expected: entry.hash,
                actual: actual.hash,
            });
        }
    }

    const manifestRead = readStableFile(
        path.join(stageRoot, MANIFEST_NAME),
        stageRoot,
        MAX_MANIFEST_BYTES,
        "bundle manifest",
    );
    const manifest = parseManifestBytes(manifestRead.bytes);
    const allowedPaths = expectedBundlePaths(manifest);
    if (!canonicalEqual(inventoryPaths, allowedPaths)) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.CLOSURE_INVALID,
            "inventory contains files outside the canonical manifest closure",
            { expected: allowedPaths, actual: inventoryPaths },
        );
    }

    const dbAbs = path.join(stageRoot, ...DB_RELPATH.split("/"));
    const dbActual = hashStableFile(dbAbs, stageRoot);
    if (dbActual.hash !== manifest.database.sha256
        || dbActual.size !== manifest.database.size
        || inventoryMap.get(DB_RELPATH) !== manifest.database.sha256) {
        throw new BundleTamperError("database bytes disagree with the canonical manifest", {
            expectedHash: manifest.database.sha256,
            actualHash: dbActual.hash,
            expectedSize: manifest.database.size,
            actualSize: dbActual.size,
        });
    }

    const binding = inspectDatabaseBinding(dbAbs, manifest.investigation.id);
    if (expectedInvestigationId !== null && binding.investigationId !== expectedInvestigationId) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.CLOSURE_INVALID,
            "database investigation differs from the export request",
            { expectedInvestigationId, actualInvestigationId: binding.investigationId },
        );
    }
    if (requiredDomainVersion !== null
        && binding.domainVersion !== requiredDomainVersion) {
        throw new BundleDomainVersionMismatchError(
            "bundle domain version is incompatible with the active Crucible domain",
            {
                expectedDomainVersion: requiredDomainVersion,
                actualDomainVersion: binding.domainVersion,
                manifestDomainVersion: manifest.investigation.domainVersion,
                investigationId: binding.investigationId,
            },
        );
    }
    if (!canonicalEqual(manifest.investigation, {
        id: binding.investigationId,
        domainVersion: binding.domainVersion,
        domainHead: binding.domainHead,
    })) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.CLOSURE_INVALID,
            "manifest investigation/domain head disagrees with the database",
            {
                manifest: manifest.investigation,
                database: {
                    id: binding.investigationId,
                    domainVersion: binding.domainVersion,
                    domainHead: binding.domainHead,
                },
            },
        );
    }
    if (!canonicalEqual(manifest.artifacts, binding.artifacts)) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.CLOSURE_INVALID,
            "manifest referenced artifacts disagree with the database",
            { manifest: manifest.artifacts, database: binding.artifacts },
        );
    }
    if (!canonicalEqual(manifest.snapshots, binding.snapshotRoots)) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.CLOSURE_INVALID,
            "manifest snapshot roots disagree with database artifact types",
            { manifest: manifest.snapshots, database: binding.snapshotRoots },
        );
    }

    const recordsById = new Map();
    for (const record of manifest.objects) {
        const actual = hashStableFile(path.join(stageRoot, ...record.path.split("/")), stageRoot);
        const { hex } = parseObjectId(record.id);
        if (actual.hash !== hex
            || actual.size !== record.size
            || inventoryMap.get(record.path) !== hex) {
            throw new BundleTamperError("bundle object record disagrees with staged bytes", {
                object: record.id,
                expectedHash: hex,
                actualHash: actual.hash,
                expectedSize: record.size,
                actualSize: actual.size,
            });
        }
        recordsById.set(record.id, record);
    }

    const directIds = binding.artifacts.map((artifact) => artifact.object);
    const expanded = expandSnapshotClosure(stageRoot, directIds, binding.snapshotRoots);
    const manifestedIds = manifest.objects.map((record) => record.id);
    if (!canonicalEqual(manifestedIds, expanded.objectIds)) {
        throw new BundleError(
            BUNDLE_ERROR_CODES.CLOSURE_INVALID,
            "manifest object inventory is not the referenced artifact closure",
            { expected: expanded.objectIds, actual: manifestedIds },
        );
    }
    for (const artifact of binding.artifacts) {
        const record = recordsById.get(artifact.object);
        if (!record) {
            throw new BundleError(BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                "referenced artifact object is absent from the manifest", { artifact });
        }
        if (artifact.sizeBytes !== null && artifact.sizeBytes !== record.size) {
            throw new BundleError(
                BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                "database artifact size disagrees with bundled object size",
                { artifactId: artifact.artifactId, expected: artifact.sizeBytes, actual: record.size },
            );
        }
    }
    for (const [objectId, expectedSize] of expanded.expectedSizes) {
        const record = recordsById.get(objectId);
        if (!record || record.size !== expectedSize) {
            throw new BundleError(
                BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                "snapshot manifest size disagrees with bundled closure object",
                { objectId, expectedSize, actualSize: record?.size ?? null },
            );
        }
    }
    const stagedStore = openArtifactStoreReadOnly({ root: stageRoot });
    for (const snapshot of binding.snapshotRoots) {
        const status = stagedStore.verifySnapshot(snapshot);
        if (!status.ok) {
            throw new BundleError(
                BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                "snapshot closure failed staged verification",
                { snapshot, status },
            );
        }
    }

    const finalScan = scanTree(stageRoot,
        Object.freeze({ operation: "verify", faultInjector: null, hooks: null }));
    if (!canonicalEqual(finalScan.files, [...allowedPaths, INVENTORY_NAME].sort(compareStable))) {
        throw new BundleTamperError("staged bundle changed during verification", {
            expected: [...allowedPaths, INVENTORY_NAME].sort(compareStable),
            actual: finalScan.files,
        });
    }

    return {
        binding,
        digest,
        inventory,
        inventoryBytes: inventoryRead.bytes,
        manifest,
        manifestBytes: manifestRead.bytes,
    };
}

function assertSameVerifiedBundle(staged, published) {
    const sameDigest = digestMatches(staged.digest, published.digest);
    const sameInventory = Buffer.from(staged.inventoryBytes)
        .equals(Buffer.from(published.inventoryBytes));
    const sameManifest = Buffer.from(staged.manifestBytes)
        .equals(Buffer.from(published.manifestBytes));
    const sameBinding = canonicalEqual(staged.binding, published.binding);
    if (!sameDigest || !sameInventory || !sameManifest || !sameBinding) {
        throw new BundleTamperError(
            "published bundle bytes differ from the verified private stage",
            {
                stagedDigest: staged.digest,
                publishedDigest: published.digest,
                sameInventory,
                sameManifest,
                sameBinding,
            },
        );
    }
}

function authenticateImport(verification, options) {
    const {
        expectedDigest = null,
        expectedSignature = options.signature ?? null,
        verifySignature = null,
        allowUnauthenticated = false,
    } = options;
    if (typeof allowUnauthenticated !== "boolean") {
        throw new InvalidArgumentError("allowUnauthenticated must be a boolean");
    }
    const hasDigest = expectedDigest !== null && expectedDigest !== undefined;
    const hasSignature = expectedSignature !== null && expectedSignature !== undefined;
    if (!hasDigest && !hasSignature && !allowUnauthenticated) {
        throw new BundleAuthenticationError(
            BUNDLE_ERROR_CODES.AUTHENTICATION_REQUIRED,
            "bundle import requires expectedDigest/signature or explicit allowUnauthenticated",
        );
    }
    if (hasDigest) {
        const normalized = normalizeTaggedDigest(expectedDigest);
        if (!digestMatches(normalized, verification.digest)) {
            throw new BundleAuthenticationError(
                BUNDLE_ERROR_CODES.AUTHENTICATION_FAILED,
                "bundle digest does not match the authenticated expected digest",
                { expected: normalized, actual: verification.digest },
            );
        }
    }
    if (hasSignature) {
        if (typeof verifySignature !== "function") {
            throw new InvalidArgumentError(
                "verifySignature callback is required when an expected signature is supplied",
            );
        }
        let verified = false;
        try {
            verified = verifySignature({
                digest: verification.digest,
                signature: expectedSignature,
                manifest: verification.manifest,
                manifestBytes: Buffer.from(verification.manifestBytes),
                inventoryBytes: Buffer.from(verification.inventoryBytes),
            }) === true;
        } catch (err) {
            throw new BundleAuthenticationError(
                BUNDLE_ERROR_CODES.AUTHENTICATION_FAILED,
                `bundle signature verification failed: ${err.message}`,
            );
        }
        if (!verified) {
            throw new BundleAuthenticationError(
                BUNDLE_ERROR_CODES.AUTHENTICATION_FAILED,
                "bundle signature did not verify",
            );
        }
    }
    return hasDigest || hasSignature ? "authenticated" : "self-consistent";
}

// --- export ---------------------------------------------------------------

export function exportBundle(options = {}) {
    const {
        store,
        dbFile,
        destDir,
        investigationId = null,
        objectIds = [],
        snapshots = [],
        metadata = {},
        now = () => new Date().toISOString(),
    } = options;

    if (!(store instanceof ArtifactStore)) {
        throw new InvalidArgumentError("store must be an ArtifactStore instance");
    }
    if (typeof dbFile !== "string" || dbFile.trim().length === 0) {
        throw new InvalidArgumentError("dbFile must be a non-empty string", { dbFile });
    }
    if (typeof destDir !== "string" || destDir.trim().length === 0) {
        throw new InvalidArgumentError("destDir must be a non-empty string", { destDir });
    }
    if (investigationId !== null
        && (typeof investigationId !== "string" || investigationId.length === 0)) {
        throw new InvalidArgumentError("investigationId must be null or a non-empty string");
    }
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
        throw new InvalidArgumentError("metadata must be an object");
    }
    if (typeof now !== "function") {
        throw new InvalidArgumentError("now must be a function");
    }
    const control = controlFor(options, "export");

    return withPrivateStage(destDir, control, (stageContext) => {
        const dbInfo = onlineBackupDatabase(dbFile, stageContext, control);
        const binding = inspectDatabaseBinding(dbInfo.path, investigationId);
        assertCallerClosureHints(binding, objectIds, snapshots);

        const directIds = [...new Set(binding.artifacts.map((artifact) => artifact.object))]
            .sort(compareStable);
        const records = new Map();
        for (const objectId of directIds) {
            records.set(objectId, copyObjectFromStore(store, objectId, stageContext, control));
        }
        const expanded = expandSnapshotClosure(
            stageContext.stage,
            directIds,
            binding.snapshotRoots,
        );
        for (const objectId of expanded.objectIds) {
            if (!records.has(objectId)) {
                records.set(objectId, copyObjectFromStore(store, objectId, stageContext, control));
            }
        }
        for (const artifact of binding.artifacts) {
            const record = records.get(artifact.object);
            if (artifact.sizeBytes !== null && artifact.sizeBytes !== record.size) {
                throw new BundleError(
                    BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                    "database artifact size disagrees with source CAS object",
                    {
                        artifactId: artifact.artifactId,
                        expected: artifact.sizeBytes,
                        actual: record.size,
                    },
                );
            }
        }
        for (const [objectId, expectedSize] of expanded.expectedSizes) {
            const record = records.get(objectId);
            if (!record || record.size !== expectedSize) {
                throw new BundleError(
                    BUNDLE_ERROR_CODES.CLOSURE_INVALID,
                    "snapshot entry size disagrees with source CAS object",
                    { objectId, expectedSize, actualSize: record?.size ?? null },
                );
            }
        }

        const manifest = validateManifest({
            type: BUNDLE_TYPE,
            version: BUNDLE_VERSION,
            algo: ALGO,
            createdAt: normalizeCreatedAt(now(), "bundle.createdAt"),
            database: {
                path: DB_RELPATH,
                size: dbInfo.size,
                sha256: dbInfo.hash,
                schemaVersion: SCHEMA_VERSION,
                schemaFingerprint: SCHEMA_FINGERPRINT,
            },
            investigation: {
                id: binding.investigationId,
                domainVersion: binding.domainVersion,
                domainHead: binding.domainHead,
            },
            artifacts: binding.artifacts,
            objects: [...records.values()].sort((left, right) => compareStable(left.id, right.id)),
            snapshots: binding.snapshotRoots,
            metadata,
        });
        const manifestBytes = Buffer.from(canonicalize(manifest) + "\n", "utf8");
        writeStageBytes(stageContext, MANIFEST_NAME, manifestBytes, control);

        const inventoryEntries = expectedBundlePaths(manifest).map((relPath) => ({
            path: relPath,
            hash: hashStableFile(
                path.join(stageContext.stage, ...relPath.split("/")),
                stageContext.stage,
            ).hash,
        }));
        const inventoryBytes = Buffer.from(serializeInventory(inventoryEntries), "utf8");
        writeStageBytes(stageContext, INVENTORY_NAME, inventoryBytes, control);

        return {
            binding,
            dbInfo,
            manifest,
            inventoryEntries,
        };
    }, (root, draft, publication) => {
        const verification = verifyBundleStage(root, draft.binding.investigationId);
        if (publication.phase === "staged") {
            return { verification };
        }
        assertSameVerifiedBundle(publication.prepared.verification, verification);
        return {
            objectCount: draft.manifest.objects.length,
            referencedArtifactCount: draft.manifest.artifacts.length,
            databaseSize: draft.dbInfo.size,
            databaseSha256: draft.dbInfo.hash,
            fileCount: draft.inventoryEntries.length,
            digest: verification.digest,
            trustLevel: "self-consistent",
            investigationId: verification.binding.investigationId,
            domainVersion: verification.binding.domainVersion,
            domainHead: verification.binding.domainHead,
        };
    });
}

// --- import ---------------------------------------------------------------

export function importBundle(options = {}) {
    const { bundleDir, destDir } = options;
    if (typeof bundleDir !== "string" || bundleDir.trim().length === 0) {
        throw new InvalidArgumentError("bundleDir must be a non-empty string", { bundleDir });
    }
    if (typeof destDir !== "string" || destDir.trim().length === 0) {
        throw new InvalidArgumentError("destDir must be a non-empty string", { destDir });
    }
    const bundleResolved = assertLocalDatabasePath(bundleDir);
    let sourceRoot;
    try {
        sourceRoot = assertSafeExistingPath(bundleResolved, "directory");
    } catch (err) {
        if (err && err.code === "ENOENT") {
            throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID,
                "bundle directory does not exist", { bundleDir: bundleResolved });
        }
        throw err;
    }
    const destResolved = assertLocalDatabasePath(destDir);
    if (isInsideDir(destResolved, sourceRoot.path) || sameCanonicalPath(destResolved, sourceRoot.path)) {
        throw new BundleUnsafePathError("import destination cannot be inside the source bundle", {
            bundleDir: sourceRoot.path,
            destDir: destResolved,
        });
    }
    const control = controlFor(options, "import");

    return withPrivateStage(destResolved, control, (stageContext) => {
        let inventoryCopy;
        try {
            inventoryCopy = copyStableFile({
                srcAbs: path.join(sourceRoot.path, INVENTORY_NAME),
                sourceRoot: sourceRoot.path,
                relPath: INVENTORY_NAME,
                stageContext,
                control,
                maxBytes: MAX_INVENTORY_BYTES,
            });
        } catch (err) {
            if (err && err.code === "ENOENT") {
                throw new BundleInventoryError("bundle is missing its inventory", {
                    bundleDir: sourceRoot.path,
                });
            }
            throw err;
        }
        const inventoryRead = readStableFile(
            inventoryCopy.path,
            stageContext.stage,
            MAX_INVENTORY_BYTES,
            "bundle inventory",
        );
        const inventory = parseInventoryBytes(inventoryRead.bytes);
        const firstScan = scanTree(sourceRoot.path, control);
        const expectedSourceFiles = [
            ...inventory.map((entry) => entry.path),
            INVENTORY_NAME,
        ].sort(compareStable);
        if (!canonicalEqual(firstScan.files, expectedSourceFiles)) {
            throw new BundleTamperError(
                "source bundle contains added or missing files outside its inventory",
                { expected: expectedSourceFiles, actual: firstScan.files },
            );
        }

        for (const entry of inventory) {
            let copied;
            try {
                copied = copyStableFile({
                    srcAbs: path.join(sourceRoot.path, ...entry.path.split("/")),
                    sourceRoot: sourceRoot.path,
                    relPath: entry.path,
                    stageContext,
                    control,
                });
            } catch (err) {
                if (err && err.code === "ENOENT") {
                    throw new BundleTamperError("inventoried source file is missing", {
                        path: entry.path,
                    });
                }
                throw err;
            }
            if (copied.hash !== entry.hash) {
                throw new BundleTamperError("source bundle file hash does not match inventory", {
                    path: entry.path,
                    expected: entry.hash,
                    actual: copied.hash,
                });
            }
        }
        const secondScan = scanTree(sourceRoot.path, control);
        compareScans(firstScan, secondScan, sourceRoot.path);

        return {};
    }, (root, _draft, publication) => {
        const verification = verifyBundleStage(
            root,
            null,
            DOMAIN_VERSION,
        );
        if (publication.phase === "staged") {
            const trustLevel = authenticateImport(verification, options);
            const postAuthentication = verifyBundleStage(
                root,
                null,
                DOMAIN_VERSION,
            );
            assertSameVerifiedBundle(verification, postAuthentication);
            return {
                verification: postAuthentication,
                trustLevel,
            };
        }
        assertSameVerifiedBundle(publication.prepared.verification, verification);
        const authenticated = publication.prepared.trustLevel === "authenticated";
        return {
            fileCount: verification.inventory.length,
            objectCount: verification.manifest.objects.length,
            selfConsistent: true,
            authenticated,
            verified: authenticated,
            digest: verification.digest,
            trustLevel: publication.prepared.trustLevel,
            investigationId: verification.binding.investigationId,
            domainVersion: verification.binding.domainVersion,
            domainHead: verification.binding.domainHead,
        };
    });
}

// Read and strictly parse a canonical bundle manifest. This intentionally does
// not verify the inventory or authenticate the bundle.
export function readBundleManifest(bundleDir) {
    if (typeof bundleDir !== "string" || bundleDir.trim().length === 0) {
        throw new InvalidArgumentError("bundleDir must be a non-empty string", { bundleDir });
    }
    let root;
    try {
        root = assertSafeExistingPath(assertLocalDatabasePath(bundleDir), "directory");
    } catch (err) {
        if (err && err.code === "ENOENT") {
            throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID,
                "bundle directory does not exist", { bundleDir });
        }
        throw err;
    }
    let read;
    try {
        read = readStableFile(
            path.join(root.path, MANIFEST_NAME),
            root.path,
            MAX_MANIFEST_BYTES,
            "bundle manifest",
        );
    } catch (err) {
        if (err && err.code === "ENOENT") {
            throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID,
                "bundle manifest not found", { bundleDir: root.path });
        }
        throw err;
    }
    return parseManifestBytes(read.bytes);
}
