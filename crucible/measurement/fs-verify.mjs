// crucible/measurement/fs-verify.mjs
//
// File-system verification for the trusted-measurement boundary.
//
// Every file that participates in a measurement (the allowlist file, the
// harness executable, and any declared interpreter/dependency) is checked
// to be:
//   1. An absolute path (no CWD-relative smuggling)
//   2. Not a UNC / network / device path
//   3. A regular file (not a directory, socket, device, FIFO)
//   4. Not a symbolic link — Node reports Windows junctions as symlinks too
//   5. Not a reparse point that would redirect to a different real path or
//      to a UNC target
//
// Files that pass verification are then hashed with SHA-256. All hashes we
// return are algorithm-tagged strings — never bare hex — so a caller cannot
// accidentally compare a raw hex value against a tagged value and get a
// meaningless "not equal".

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

import {
    canonicalJson,
    immutableCanonical,
} from "../domain/canonical.mjs";
import { isNetworkOrUncPath } from "../persistence/paths.mjs";
import {
    FileVerificationError,
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
} from "./errors.mjs";

// Algorithm tags used for measurement-scoped file digests. Different tags for
// different domains prevent cross-domain hash confusion (a stdout hash cannot
// be mistaken for a file hash even if the underlying hex happens to collide).
export const FILE_HASH_ALGORITHM = "sha256:crucible-measurement-file-v1";
export const STREAM_HASH_ALGORITHM = "sha256:crucible-measurement-stream-v1";
export const SNAPSHOT_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-measurement-snapshot-closure-v1";

const HEX64 = /^[a-f0-9]{64}$/u;
const TAGGED_HASH = /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const SNAPSHOT_ID = /^sha256:[a-f0-9]{64}$/u;
const SNAPSHOT_HASH =
    /^sha256:crucible-measurement-snapshot-v1:[a-f0-9]{64}$/u;
const verifiedFileHandles = new WeakMap();
const verifiedSnapshotClosures = new WeakMap();

function fail(code, message, details) {
    throw new FileVerificationError(code, message, details);
}

function bigintStat(filePath, operation) {
    try {
        return operation();
    } catch (err) {
        if (err && (err.code === "ENOENT" || err.code === "ENOTDIR")) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_NOT_FOUND,
                "verified file disappeared during verification",
                { path: filePath, cause: err.code },
            );
        }
        throw err;
    }
}

function fileIdentity(stat, filePath, label) {
    const dev = stat?.dev;
    const ino = stat?.ino;
    if ((typeof dev !== "bigint" && typeof dev !== "number")
        || (typeof ino !== "bigint" && typeof ino !== "number")
        || BigInt(dev) <= 0n
        || BigInt(ino) <= 0n) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_IDENTITY_UNAVAILABLE,
            `${label} filesystem does not expose stable file identity; refusing a racy verification`,
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

function samePath(left, right) {
    return process.platform === "win32"
        ? left.toLowerCase() === right.toLowerCase()
        : left === right;
}

function comparePath(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

function isInsidePath(candidate, root) {
    const relative = path.relative(root, candidate);
    return relative === ""
        || (!path.isAbsolute(relative)
            && relative !== ".."
            && !relative.startsWith(`..${path.sep}`));
}

function assertIdentityStable(before, after, filePath, label) {
    if (before.dev !== after.dev
        || before.ino !== after.ino
        || before.size !== after.size
        || before.mode !== after.mode
        || before.mtimeNs !== after.mtimeNs
        || before.ctimeNs !== after.ctimeNs) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
            `${label} changed while it was being verified`,
            { path: filePath, before, after },
        );
    }
}

function hashOpenFd(fd, algorithm) {
    const hash = createHash("sha256");
    const buf = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (true) {
        const bytes = fs.readSync(fd, buf, 0, buf.length, position);
        if (bytes <= 0) break;
        hash.update(buf.subarray(0, bytes));
        position += bytes;
    }
    return `${algorithm}:${hash.digest("hex")}`;
}

function compareExpectedHash(actualHash, expected, label, resolvedPath) {
    const actualHex = actualHash.split(":").pop();
    const expectedHex = normalizeExpectedHash(expected, label);
    const a = Buffer.from(actualHex, "hex");
    const b = Buffer.from(expectedHex, "hex");
    let diff = 0;
    for (let i = 0; i < 32; i += 1) diff |= a[i] ^ b[i];
    if (diff !== 0) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
            `${label} sha256 mismatch`,
            { path: resolvedPath, expected: expectedHex, actual: actualHex },
        );
    }
}

// Read a raw hex hash from either a bare 64-char hex string or an
// algorithm-tagged form ("sha256:label:<hex>"). Any other shape throws.
export function normalizeExpectedHash(value, label) {
    if (typeof value !== "string" || value.length === 0) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${label} expected hash must be a non-empty string`,
        );
    }
    if (HEX64.test(value)) {
        return value.toLowerCase();
    }
    if (TAGGED_HASH.test(value)) {
        return value.split(":").pop().toLowerCase();
    }
    throw new MeasurementError(
        MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
        `${label} expected hash must be 64-char hex or sha256:tag:<hex>`,
        { value },
    );
}

// Verify a file is a local, regular, non-symlink, non-reparse file at an
// absolute path, and return the resolved absolute path. Does not hash.
export function verifyLocalRegularFile(filePath, options = {}) {
    const label = options.label ?? "file";
    if (typeof filePath !== "string" || filePath.length === 0) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${label} path must be a non-empty string`,
        );
    }
    if (!path.isAbsolute(filePath)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${label} path must be absolute`,
            { path: filePath },
        );
    }
    if (isNetworkOrUncPath(filePath)) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_NOT_LOCAL,
            `${label} path is a UNC / network / device path`,
            { path: filePath, reason: "unc" },
        );
    }

    let lst;
    try {
        lst = fs.lstatSync(filePath);
    } catch (err) {
        if (err && (err.code === "ENOENT" || err.code === "ENOTDIR")) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_NOT_FOUND,
                `${label} not found`,
                { path: filePath, cause: err.code },
            );
        }
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${label} lstat failed: ${err?.message ?? String(err)}`,
            { path: filePath, cause: err?.code ?? null },
        );
    }

    if (lst.isSymbolicLink()) {
        // Node reports Windows junctions AND POSIX symlinks as symbolic
        // links from lstat, so this catches both. We reject rather than
        // resolve because a symlink target is mutable independently of the
        // path we were told to verify.
        fail(
            MEASUREMENT_ERROR_CODES.FILE_SYMLINK,
            `${label} is a symbolic link (or Windows junction); allowlist entries must reference the real file directly`,
            { path: filePath },
        );
    }
    if (!lst.isFile()) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_NOT_REGULAR,
            `${label} is not a regular file`,
            {
                path: filePath,
                isDirectory: lst.isDirectory(),
                isBlockDevice: lst.isBlockDevice(),
                isCharacterDevice: lst.isCharacterDevice(),
                isFIFO: lst.isFIFO(),
                isSocket: lst.isSocket(),
            },
        );
    }

    // Belt-and-suspenders: resolve realpath and reject if it lands on a UNC
    // target (mapped network drive or junction we somehow missed). Also
    // reject any relocation whose case-insensitive resolved path differs
    // from the case-insensitive input — that signals a reparse point/junction
    // in an ancestor directory that would let a caller substitute a file
    // out from under a stable-looking path.
    let real;
    try {
        real = fs.realpathSync.native(filePath);
    } catch (err) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${label} realpath failed: ${err?.message ?? String(err)}`,
            { path: filePath, cause: err?.code ?? null },
        );
    }
    if (isNetworkOrUncPath(real)) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_NOT_LOCAL,
            `${label} realpath resolves to a UNC / network target`,
            { path: filePath, real, reason: "mapped-network-drive" },
        );
    }

    // On Windows the FS is case-insensitive but case-preserving; realpath
    // returns the canonical on-disk casing. So we compare case-insensitively.
    const inputAbs = path.resolve(filePath);
    if (process.platform === "win32") {
        if (inputAbs.toLowerCase() !== real.toLowerCase()) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_REPARSE_POINT,
                `${label} resolves through a reparse point to a different real path`,
                { path: inputAbs, real },
            );
        }
    } else if (inputAbs !== real) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_REPARSE_POINT,
            `${label} resolves through a symlink/junction to a different real path`,
            { path: inputAbs, real },
        );
    }

    return real;
}

// Stream-hash a file with SHA-256 and return an algorithm-tagged digest.
// The path MUST already have been passed through verifyLocalRegularFile
// (we re-open by the resolved path to avoid a race where another symlink
// is substituted between check and open).
export function sha256File(resolvedPath, algorithm = FILE_HASH_ALGORITHM) {
    if (typeof algorithm !== "string" || !TAGGED_HASH.test(`${algorithm}:${"0".repeat(64)}`)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "hash algorithm tag must have the form sha256:<label>",
        );
    }
    const verifiedPath = verifyLocalRegularFile(resolvedPath, { label: "file" });
    const fd = fs.openSync(verifiedPath, "r");
    try {
        return hashOpenFd(fd, algorithm);
    } finally {
        fs.closeSync(fd);
    }
}

// Hash raw bytes (used for captured stdout/stderr) with an algorithm tag.
export function sha256Bytes(bytes, algorithm = STREAM_HASH_ALGORITHM) {
    if (!(bytes instanceof Uint8Array)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "sha256Bytes input must be a Uint8Array / Buffer",
        );
    }
    return `${algorithm}:${createHash("sha256").update(bytes).digest("hex")}`;
}

// Verify a file, then hash it, then compare against an expected digest.
// The comparison uses timing-safe equality of the raw hex bytes so the
// caller need not care whether the expected value is tagged or bare hex.
// Returns { resolvedPath, hash } on success. Throws typed errors on failure.
export function verifyAndHashFile(filePath, expected, options = {}) {
    const handle = openVerifiedFileHandle(filePath, expected, options);
    try {
        return {
            resolvedPath: handle.resolvedPath,
            hash: handle.hash,
            size: handle.size,
            mode: handle.mode,
        };
    } finally {
        closeVerifiedFileHandle(handle);
    }
}

// Open and hash a pinned local file while binding the pathname checks to the
// exact open handle. The opaque token deliberately exposes no fd; only the
// staging helpers below can use it.
export function openVerifiedFileHandle(filePath, expected, options = {}) {
    const label = options.label ?? "file";
    const algorithm = options.algorithm ?? FILE_HASH_ALGORITHM;
    const resolvedPath = verifyLocalRegularFile(filePath, { label });
    const realBefore = fs.realpathSync.native(resolvedPath);
    const pathBeforeStat = bigintStat(
        resolvedPath,
        () => fs.lstatSync(resolvedPath, { bigint: true }),
    );
    const pathBefore = fileIdentity(pathBeforeStat, resolvedPath, label);
    let fd;
    try {
        fd = fs.openSync(resolvedPath, "r");
        const openedStat = fs.fstatSync(fd, { bigint: true });
        if (!openedStat.isFile()) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_NOT_REGULAR,
                `${label} open handle is not a regular file`,
                { path: resolvedPath },
            );
        }
        const opened = fileIdentity(openedStat, resolvedPath, label);
        assertIdentityStable(pathBefore, opened, resolvedPath, label);
        const hash = hashOpenFd(fd, algorithm);
        const afterRead = fileIdentity(
            fs.fstatSync(fd, { bigint: true }),
            resolvedPath,
            label,
        );
        assertIdentityStable(opened, afterRead, resolvedPath, label);
        const pathAfter = fileIdentity(
            bigintStat(resolvedPath, () => fs.lstatSync(resolvedPath, { bigint: true })),
            resolvedPath,
            label,
        );
        assertIdentityStable(opened, pathAfter, resolvedPath, label);
        const realAfter = fs.realpathSync.native(resolvedPath);
        if (!samePath(realBefore, realAfter)) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
                `${label} realpath changed while it was being verified`,
                { path: resolvedPath, realBefore, realAfter },
            );
        }
        compareExpectedHash(hash, expected, label, resolvedPath);

        const token = Object.freeze({
            resolvedPath,
            hash,
            size: Number(openedStat.size),
            mode: Number(openedStat.mode),
        });
        verifiedFileHandles.set(token, {
            fd,
            label,
            resolvedPath,
            realPath: realBefore,
            identity: opened,
            hash,
            size: Number(openedStat.size),
            mode: Number(openedStat.mode),
            closed: false,
        });
        fd = undefined;
        return token;
    } finally {
        if (fd !== undefined) {
            fs.closeSync(fd);
        }
    }
}

function requireVerifiedHandle(token) {
    const state = verifiedFileHandles.get(token);
    if (state === undefined || state.closed) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "verified file handle is not live",
        );
    }
    return state;
}

function recheckOpenSource(state) {
    const afterHandle = fileIdentity(
        fs.fstatSync(state.fd, { bigint: true }),
        state.resolvedPath,
        state.label,
    );
    assertIdentityStable(state.identity, afterHandle, state.resolvedPath, state.label);
    const afterPath = fileIdentity(
        bigintStat(
            state.resolvedPath,
            () => fs.lstatSync(state.resolvedPath, { bigint: true }),
        ),
        state.resolvedPath,
        state.label,
    );
    assertIdentityStable(state.identity, afterPath, state.resolvedPath, state.label);
    const realAfter = fs.realpathSync.native(state.resolvedPath);
    if (!samePath(state.realPath, realAfter)) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
            `${state.label} realpath changed before staging completed`,
            {
                path: state.resolvedPath,
                realBefore: state.realPath,
                realAfter,
            },
        );
    }
}

// Copy bytes from the already-verified open handle, fsync the staged copy,
// reopen and rehash it, and only then return it as spawnable.
export function stageVerifiedFileHandle(token, destination, options = {}) {
    const state = requireVerifiedHandle(token);
    const label = options.label ?? state.label;
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    let fd;
    try {
        fd = fs.openSync(destination, "wx", state.mode & 0o777);
        const buffer = Buffer.allocUnsafe(64 * 1024);
        let position = 0;
        while (true) {
            const bytes = fs.readSync(state.fd, buffer, 0, buffer.length, position);
            if (bytes <= 0) break;
            let offset = 0;
            while (offset < bytes) {
                offset += fs.writeSync(fd, buffer, offset, bytes - offset);
            }
            position += bytes;
        }
        fs.fsyncSync(fd);
    } catch (error) {
        if (fd !== undefined) {
            try { fs.closeSync(fd); } catch { /* already closed */ }
            fd = undefined;
        }
        fs.rmSync(destination, { force: true });
        if (error instanceof MeasurementError) throw error;
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.STAGING_REFUSED,
            `failed to stage ${label}: ${error?.message ?? String(error)}`,
            { source: state.resolvedPath, destination, cause: error?.code ?? null },
        );
    } finally {
        if (fd !== undefined) fs.closeSync(fd);
    }

    recheckOpenSource(state);
    const staged = verifyAndHashFile(destination, state.hash, {
        label: `staged ${label}`,
        algorithm: FILE_HASH_ALGORITHM,
    });
    return Object.freeze({
        path: staged.resolvedPath,
        sourcePath: state.resolvedPath,
        sourceHash: state.hash,
        stagedHash: staged.hash,
        size: staged.size,
    });
}

export function closeVerifiedFileHandle(token) {
    const state = verifiedFileHandles.get(token);
    if (state === undefined || state.closed) return false;
    state.closed = true;
    fs.closeSync(state.fd);
    verifiedFileHandles.delete(token);
    return true;
}

function invalidSnapshot(message, details = null) {
    throw new MeasurementError(
        MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
        message,
        details,
    );
}

function assertFrozenPlainObject(value, label) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)
        || !Object.isFrozen(value)) {
        invalidSnapshot(`${label} must be a frozen plain object`);
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
        invalidSnapshot(`${label} must not contain symbol properties`);
    }
    for (const [key, descriptor] of Object.entries(
        Object.getOwnPropertyDescriptors(value),
    )) {
        if (!Object.hasOwn(descriptor, "value")) {
            invalidSnapshot(`${label}.${key} must be a data property`);
        }
    }
}

function assertFrozenArray(value, label) {
    if (!Array.isArray(value) || !Object.isFrozen(value)) {
        invalidSnapshot(`${label} must be a frozen array`);
    }
}

function safeSnapshotSegments(relPath) {
    if (typeof relPath !== "string" || relPath.length === 0) {
        invalidSnapshot("snapshot manifest paths must be non-empty strings", {
            relPath,
        });
    }
    if (path.isAbsolute(relPath) || /^[A-Za-z]:/u.test(relPath)) {
        invalidSnapshot("snapshot manifest paths must be relative", {
            relPath,
        });
    }
    const segments = relPath.split("/");
    for (const segment of segments) {
        if (segment.length === 0
            || segment === "."
            || segment === ".."
            || segment.includes("/")
            || segment.includes("\\")
            || segment.includes("\0")
            || segment.includes(":")) {
            invalidSnapshot("snapshot manifest contains an unsafe path", {
                relPath,
                segment,
            });
        }
    }
    return segments;
}

function normalizeCandidateSnapshot(snapshot) {
    assertFrozenPlainObject(snapshot, "candidate snapshot");
    if (typeof snapshot.path !== "string"
        || snapshot.path.length === 0
        || !path.isAbsolute(snapshot.path)) {
        invalidSnapshot(
            "candidate snapshot.path must be an absolute string path",
            { path: snapshot.path ?? null },
        );
    }
    if (isNetworkOrUncPath(snapshot.path)) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_NOT_LOCAL,
            "candidate snapshot path is a UNC / network / device path",
            { path: snapshot.path },
        );
    }
    if (typeof snapshot.hash !== "string" || !SNAPSHOT_HASH.test(snapshot.hash)) {
        invalidSnapshot(
            "candidate snapshot.hash must use the measurement snapshot hash algorithm",
            { hash: snapshot.hash ?? null },
        );
    }
    if (typeof snapshot.snapshotId !== "string"
        || !SNAPSHOT_ID.test(snapshot.snapshotId)) {
        invalidSnapshot(
            "candidate snapshot.snapshotId must be sha256:<64hex>",
            { snapshotId: snapshot.snapshotId ?? null },
        );
    }
    if (snapshot.hash.split(":").pop() !== snapshot.snapshotId.slice("sha256:".length)) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
            "candidate snapshot hash does not identify the supplied snapshot manifest",
            {
                hash: snapshot.hash,
                snapshotId: snapshot.snapshotId,
            },
        );
    }

    const manifest = snapshot.manifest;
    assertFrozenPlainObject(manifest, "candidate snapshot.manifest");
    assertFrozenArray(manifest.entries, "candidate snapshot.manifest.entries");
    if (manifest.type !== "crucible-snapshot"
        || manifest.version !== 1
        || manifest.algo !== "sha256"
        || !Number.isSafeInteger(manifest.fileCount)
        || manifest.fileCount < 0
        || !Number.isSafeInteger(manifest.totalBytes)
        || manifest.totalBytes < 0) {
        invalidSnapshot("candidate snapshot manifest has an unexpected shape");
    }

    const expectedFiles = new Map();
    const expectedDirectories = new Set();
    let priorPath = null;
    let totalBytes = 0;
    for (let index = 0; index < manifest.entries.length; index += 1) {
        const entry = manifest.entries[index];
        assertFrozenPlainObject(
            entry,
            `candidate snapshot.manifest.entries[${index}]`,
        );
        if (typeof entry.path !== "string"
            || typeof entry.object !== "string"
            || !SNAPSHOT_ID.test(entry.object)
            || !Number.isSafeInteger(entry.size)
            || entry.size < 0) {
            invalidSnapshot("candidate snapshot manifest entry is malformed", {
                index,
            });
        }
        if (priorPath !== null && comparePath(priorPath, entry.path) >= 0) {
            invalidSnapshot(
                "candidate snapshot manifest entries must be uniquely sorted by path",
                { priorPath, path: entry.path },
            );
        }
        priorPath = entry.path;
        const segments = safeSnapshotSegments(entry.path);
        for (let depth = 1; depth < segments.length; depth += 1) {
            expectedDirectories.add(segments.slice(0, depth).join("/"));
        }
        expectedFiles.set(entry.path, entry);
        totalBytes += entry.size;
        if (!Number.isSafeInteger(totalBytes)) {
            invalidSnapshot("candidate snapshot total byte count is unsafe");
        }
    }
    if (manifest.fileCount !== manifest.entries.length
        || manifest.totalBytes !== totalBytes) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
            "candidate snapshot manifest counters disagree with its entries",
            {
                fileCount: manifest.fileCount,
                actualFileCount: manifest.entries.length,
                totalBytes: manifest.totalBytes,
                actualTotalBytes: totalBytes,
            },
        );
    }

    let manifestBytes;
    try {
        manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
    } catch (error) {
        invalidSnapshot(
            `candidate snapshot manifest is not canonical JSON: ${error?.message ?? String(error)}`,
        );
    }
    const manifestId =
        `sha256:${createHash("sha256").update(manifestBytes).digest("hex")}`;
    if (manifestId !== snapshot.snapshotId) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
            "candidate snapshot manifest bytes do not match snapshotId",
            { expected: snapshot.snapshotId, actual: manifestId },
        );
    }

    assertFrozenArray(
        snapshot.expectedObjectClosure,
        "candidate snapshot.expectedObjectClosure",
    );
    const expectedObjectClosure = [
        ...new Set([
            snapshot.snapshotId,
            ...manifest.entries.map((entry) => entry.object),
        ]),
    ].sort(comparePath);
    if (snapshot.expectedObjectClosure.length !== expectedObjectClosure.length
        || snapshot.expectedObjectClosure.some(
            (objectId, index) =>
                typeof objectId !== "string"
                || !SNAPSHOT_ID.test(objectId)
                || objectId !== expectedObjectClosure[index],
        )) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
            "candidate snapshot expected object closure disagrees with its manifest",
            {
                expected: expectedObjectClosure,
                supplied: snapshot.expectedObjectClosure,
            },
        );
    }

    return {
        path: path.resolve(snapshot.path),
        hash: snapshot.hash,
        snapshotId: snapshot.snapshotId,
        manifest,
        expectedFiles,
        expectedDirectories,
        expectedObjectClosure,
    };
}

function identityRecord(relPath, identity) {
    return {
        path: relPath,
        dev: identity.dev,
        ino: identity.ino,
        size: identity.size,
        mode: identity.mode,
        mtimeNs: identity.mtimeNs,
        ctimeNs: identity.ctimeNs,
    };
}

function assertDirectoryAtPath(dirPath, rootReal, label) {
    const lst = bigintStat(
        dirPath,
        () => fs.lstatSync(dirPath, { bigint: true }),
    );
    if (lst.isSymbolicLink()) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_SYMLINK,
            `${label} is a symbolic link or junction`,
            { path: dirPath },
        );
    }
    if (!lst.isDirectory()) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_NOT_REGULAR,
            `${label} is not a directory`,
            { path: dirPath },
        );
    }
    const identity = fileIdentity(lst, dirPath, label);
    const real = fs.realpathSync.native(dirPath);
    if (!samePath(path.resolve(dirPath), real)
        || (rootReal !== null && !isInsidePath(real, rootReal))) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_REPARSE_POINT,
            `${label} resolves through a reparse point or escapes the snapshot root`,
            { path: dirPath, real, rootReal },
        );
    }
    return { identity, real };
}

function assertSameFileObject(before, after, filePath, label) {
    if (before.dev !== after.dev
        || before.ino !== after.ino
        || before.size !== after.size) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
            `${label} changed while read-only protection was applied`,
            { path: filePath, before, after },
        );
    }
}

function captureCandidateFile(
    filePath,
    relPath,
    expected,
    rootReal,
    { enforceReadOnly, holdOpen },
) {
    const label = `candidate snapshot file ${JSON.stringify(relPath)}`;
    const pathBeforeStat = bigintStat(
        filePath,
        () => fs.lstatSync(filePath, { bigint: true }),
    );
    if (pathBeforeStat.isSymbolicLink()) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_SYMLINK,
            `${label} is a symbolic link`,
            { path: filePath },
        );
    }
    if (!pathBeforeStat.isFile()) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_NOT_REGULAR,
            `${label} is not a regular file`,
            { path: filePath },
        );
    }
    const realBefore = fs.realpathSync.native(filePath);
    if (!samePath(path.resolve(filePath), realBefore)
        || !isInsidePath(realBefore, rootReal)) {
        fail(
            MEASUREMENT_ERROR_CODES.FILE_REPARSE_POINT,
            `${label} resolves through a reparse point or escapes the snapshot root`,
            { path: filePath, real: realBefore, rootReal },
        );
    }
    const pathBefore = fileIdentity(pathBeforeStat, filePath, label);
    let fd;
    try {
        fd = fs.openSync(filePath, "r");
        let openedStat = fs.fstatSync(fd, { bigint: true });
        if (!openedStat.isFile()) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_NOT_REGULAR,
                `${label} open handle is not a regular file`,
                { path: filePath },
            );
        }
        let opened = fileIdentity(openedStat, filePath, label);
        assertIdentityStable(pathBefore, opened, filePath, label);

        if (enforceReadOnly && (Number(openedStat.mode) & 0o222) !== 0) {
            let protectedModeApplied = false;
            try {
                fs.fchmodSync(fd, Number(openedStat.mode) & ~0o222);
                protectedModeApplied = true;
            } catch {
                // Best-effort on filesystems that do not expose a read-only bit.
            }
            if (protectedModeApplied) {
                const protectedStat = fs.fstatSync(fd, { bigint: true });
                const protectedIdentity = fileIdentity(
                    protectedStat,
                    filePath,
                    label,
                );
                assertSameFileObject(opened, protectedIdentity, filePath, label);
                openedStat = protectedStat;
                opened = protectedIdentity;
            }
        }

        const pathProtected = fileIdentity(
            bigintStat(
                filePath,
                () => fs.lstatSync(filePath, { bigint: true }),
            ),
            filePath,
            label,
        );
        assertIdentityStable(opened, pathProtected, filePath, label);
        const hash = hashOpenFd(fd, FILE_HASH_ALGORITHM);
        const afterRead = fileIdentity(
            fs.fstatSync(fd, { bigint: true }),
            filePath,
            label,
        );
        assertIdentityStable(opened, afterRead, filePath, label);
        const pathAfter = fileIdentity(
            bigintStat(
                filePath,
                () => fs.lstatSync(filePath, { bigint: true }),
            ),
            filePath,
            label,
        );
        assertIdentityStable(opened, pathAfter, filePath, label);
        const realAfter = fs.realpathSync.native(filePath);
        if (!samePath(realBefore, realAfter)
            || !samePath(path.resolve(filePath), realAfter)
            || !isInsidePath(realAfter, rootReal)) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
                `${label} realpath changed while it was being verified`,
                { path: filePath, realBefore, realAfter, rootReal },
            );
        }
        if (Number(openedStat.size) !== expected.size) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
                `${label} size disagrees with the snapshot manifest`,
                {
                    path: filePath,
                    expected: expected.size,
                    actual: Number(openedStat.size),
                },
            );
        }
        compareExpectedHash(
            hash,
            expected.object.slice("sha256:".length),
            label,
            filePath,
        );

        const record = {
            path: relPath,
            absPath: filePath,
            realPath: realBefore,
            identity: opened,
            hash,
            object: expected.object,
            size: expected.size,
            readOnlyVerified: (Number(openedStat.mode) & 0o222) === 0,
            fd: holdOpen ? fd : null,
        };
        if (holdOpen) {
            fd = undefined;
        }
        return record;
    } finally {
        if (fd !== undefined) {
            fs.closeSync(fd);
        }
    }
}

function captureCandidateSnapshot(spec, {
    enforceReadOnly,
    holdOpen,
}) {
    const heldFiles = [];
    try {
        const rootBefore = assertDirectoryAtPath(
            spec.path,
            null,
            "candidate snapshot root",
        );
        if (isNetworkOrUncPath(rootBefore.real)) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_NOT_LOCAL,
                "candidate snapshot root resolves to a network path",
                { path: spec.path, real: rootBefore.real },
            );
        }

        const directories = [];
        const files = [];
        const seenDirectories = new Set();
        const seenFiles = new Set();

        function walk(dirPath, relSegments) {
            const relPath = relSegments.length === 0
                ? "."
                : relSegments.join("/");
            const before = assertDirectoryAtPath(
                dirPath,
                rootBefore.real,
                `candidate snapshot directory ${JSON.stringify(relPath)}`,
            );
            if (relPath !== "." && !spec.expectedDirectories.has(relPath)) {
                fail(
                    MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
                    "candidate snapshot contains an unexpected directory",
                    { path: relPath },
                );
            }
            if (relPath !== ".") seenDirectories.add(relPath);

            const dirents = fs.readdirSync(dirPath, { withFileTypes: true })
                .sort((left, right) => comparePath(left.name, right.name));
            for (const dirent of dirents) {
                const name = dirent.name;
                if (name.length === 0
                    || name === "."
                    || name === ".."
                    || name.includes("/")
                    || name.includes("\\")
                    || name.includes("\0")
                    || name.includes(":")) {
                    fail(
                        MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
                        "candidate snapshot contains an unsafe filesystem entry",
                        { directory: relPath, name },
                    );
                }
                const childPath = path.join(dirPath, name);
                const childSegments = [...relSegments, name];
                const childRel = childSegments.join("/");
                const lst = bigintStat(
                    childPath,
                    () => fs.lstatSync(childPath, { bigint: true }),
                );
                if (lst.isSymbolicLink()) {
                    fail(
                        MEASUREMENT_ERROR_CODES.FILE_SYMLINK,
                        "candidate snapshot contains a symbolic link or junction",
                        { path: childRel },
                    );
                }
                if (lst.isDirectory()) {
                    walk(childPath, childSegments);
                    continue;
                }
                if (!lst.isFile()) {
                    fail(
                        MEASUREMENT_ERROR_CODES.FILE_NOT_REGULAR,
                        "candidate snapshot contains a non-regular entry",
                        { path: childRel },
                    );
                }
                const expected = spec.expectedFiles.get(childRel);
                if (expected === undefined) {
                    fail(
                        MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
                        "candidate snapshot contains an unexpected file",
                        { path: childRel },
                    );
                }
                const captured = captureCandidateFile(
                    childPath,
                    childRel,
                    expected,
                    rootBefore.real,
                    { enforceReadOnly, holdOpen },
                );
                files.push(captured);
                seenFiles.add(childRel);
                if (holdOpen) heldFiles.push(captured);
            }

            const after = assertDirectoryAtPath(
                dirPath,
                rootBefore.real,
                `candidate snapshot directory ${JSON.stringify(relPath)}`,
            );
            assertIdentityStable(
                before.identity,
                after.identity,
                dirPath,
                `candidate snapshot directory ${JSON.stringify(relPath)}`,
            );
            if (!samePath(before.real, after.real)) {
                fail(
                    MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
                    "candidate snapshot directory realpath changed during verification",
                    { path: relPath, before: before.real, after: after.real },
                );
            }
            const record = {
                path: relPath,
                absPath: dirPath,
                realPath: before.real,
                identity: before.identity,
            };
            if (relPath === ".") {
                return record;
            }
            directories.push(record);
            return record;
        }

        const root = walk(rootBefore.real, []);
        const missingFiles = [...spec.expectedFiles.keys()]
            .filter((relPath) => !seenFiles.has(relPath));
        const missingDirectories = [...spec.expectedDirectories]
            .filter((relPath) => !seenDirectories.has(relPath));
        if (missingFiles.length > 0 || missingDirectories.length > 0) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
                "candidate snapshot is missing manifest closure entries",
                { missingFiles, missingDirectories },
            );
        }

        directories.sort((left, right) => comparePath(left.path, right.path));
        files.sort((left, right) => comparePath(left.path, right.path));
        const closure = {
            version: 1,
            snapshotId: spec.snapshotId,
            expectedObjectClosure: spec.expectedObjectClosure,
            directories: directories.map((directory) => directory.path),
            files: files.map((file) => ({
                path: file.path,
                size: file.size,
                object: file.object,
            })),
        };
        const closureHash =
            `${SNAPSHOT_CLOSURE_HASH_ALGORITHM}:${createHash("sha256")
                .update(canonicalJson(closure), "utf8")
                .digest("hex")}`;
        const identitySummary = immutableCanonical({
            root: identityRecord(".", root.identity),
            directories: directories.map((directory) =>
                identityRecord(directory.path, directory.identity)),
            files: files.map((file) =>
                identityRecord(file.path, file.identity)),
        });
        const readOnlySummary = immutableCanonical({
            requested: enforceReadOnly,
            fileCount: files.length,
            verifiedReadOnlyFiles: files.filter((file) => file.readOnlyVerified).length,
            unverifiedReadOnlyFiles: files.filter((file) => !file.readOnlyVerified).length,
        });

        return {
            root,
            directories,
            files,
            closureHash,
            identitySummary,
            readOnlySummary,
        };
    } catch (error) {
        for (const file of heldFiles) {
            try {
                if (file.fd !== null) fs.closeSync(file.fd);
            } catch {
                // Best-effort cleanup while preserving the verification error.
            }
        }
        throw error;
    }
}

// Pin and verify the exact materialized candidate closure before spawn.
// Every file is held open until closeVerifiedSnapshotClosure(), so unlink and
// replacement are observable even on platforms that permit deleting open files.
export function openVerifiedSnapshotClosure(snapshot) {
    const spec = normalizeCandidateSnapshot(snapshot);
    let captured;
    try {
        captured = captureCandidateSnapshot(spec, {
            enforceReadOnly: true,
            holdOpen: true,
        });
    } catch (error) {
        if (error instanceof MeasurementError) throw error;
        throw new FileVerificationError(
            MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
            `candidate snapshot could not be verified before execution: ${error?.message ?? String(error)}`,
            {
                snapshotId: spec.snapshotId,
                cause: error?.code ?? null,
            },
        );
    }
    const token = Object.freeze({
        snapshotId: spec.snapshotId,
        snapshotHash: spec.hash,
        preClosureHash: captured.closureHash,
        preIdentitySummary: captured.identitySummary,
        readOnlySummary: captured.readOnlySummary,
    });
    verifiedSnapshotClosures.set(token, {
        spec,
        captured,
        closed: false,
    });
    return token;
}

function requireSnapshotClosure(token) {
    const state = verifiedSnapshotClosures.get(token);
    if (state === undefined || state.closed) {
        invalidSnapshot("verified candidate snapshot closure is not live");
    }
    return state;
}

function rehashHeldSnapshotFiles(captured) {
    for (const file of captured.files) {
        const before = fileIdentity(
            fs.fstatSync(file.fd, { bigint: true }),
            file.absPath,
            `candidate snapshot file ${JSON.stringify(file.path)}`,
        );
        assertIdentityStable(
            file.identity,
            before,
            file.absPath,
            `candidate snapshot file ${JSON.stringify(file.path)}`,
        );
        const hash = hashOpenFd(file.fd, FILE_HASH_ALGORITHM);
        const after = fileIdentity(
            fs.fstatSync(file.fd, { bigint: true }),
            file.absPath,
            `candidate snapshot file ${JSON.stringify(file.path)}`,
        );
        assertIdentityStable(
            file.identity,
            after,
            file.absPath,
            `candidate snapshot file ${JSON.stringify(file.path)}`,
        );
        if (hash !== file.hash) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
                "candidate snapshot file bytes changed during harness execution",
                {
                    path: file.path,
                    before: file.hash,
                    after: hash,
                },
            );
        }
    }
}

// Re-hash the pinned handles and independently re-walk the path closure after
// the child exits. Any mutation, replacement, unlink, added path, or reparse
// change rejects the measurement before parsing or receipt construction.
export function reverifySnapshotClosure(token) {
    const state = requireSnapshotClosure(token);
    try {
        rehashHeldSnapshotFiles(state.captured);
        const post = captureCandidateSnapshot(state.spec, {
            enforceReadOnly: false,
            holdOpen: false,
        });
        if (state.captured.closureHash !== post.closureHash) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
                "candidate snapshot closure changed during harness execution",
                {
                    before: state.captured.closureHash,
                    after: post.closureHash,
                },
            );
        }
        if (canonicalJson(state.captured.identitySummary)
            !== canonicalJson(post.identitySummary)) {
            fail(
                MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
                "candidate snapshot filesystem identities changed during harness execution",
                {
                    before: state.captured.identitySummary,
                    after: post.identitySummary,
                },
            );
        }
        return immutableCanonical({
            preClosureHash: state.captured.closureHash,
            postClosureHash: post.closureHash,
            identitySummary: {
                pre: state.captured.identitySummary,
                post: post.identitySummary,
            },
            mutationCheck: {
                status: "passed",
                closureStable: true,
                identityStable: true,
                openHandleRehashStable: true,
                reparseStable: true,
                readOnly: state.captured.readOnlySummary,
            },
        });
    } catch (error) {
        if (error instanceof FileVerificationError
            && error.code === MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION) {
            throw error;
        }
        throw new FileVerificationError(
            MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
            `candidate snapshot changed during harness execution: ${error?.message ?? String(error)}`,
            {
                snapshotId: state.spec.snapshotId,
                cause: error?.code ?? null,
                causeDetails: error?.details ?? null,
            },
        );
    }
}

export function closeVerifiedSnapshotClosure(token) {
    const state = verifiedSnapshotClosures.get(token);
    if (state === undefined || state.closed) return false;
    state.closed = true;
    let firstError = null;
    for (const file of state.captured.files) {
        if (file.fd === null) continue;
        try {
            fs.closeSync(file.fd);
        } catch (error) {
            firstError ??= error;
        }
        file.fd = null;
    }
    verifiedSnapshotClosures.delete(token);
    if (firstError !== null) throw firstError;
    return true;
}
