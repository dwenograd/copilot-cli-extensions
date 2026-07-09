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

const HEX64 = /^[a-f0-9]{64}$/u;
const TAGGED_HASH = /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const verifiedFileHandles = new WeakMap();

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
