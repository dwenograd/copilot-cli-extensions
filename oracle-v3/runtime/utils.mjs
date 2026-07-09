import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";

import { RuntimeConfigError, RUNTIME_ERROR_CODES, OracleRuntimeError } from "./errors.mjs";

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;
const SAFE_LOWER_IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,127}$/u;

export function isPlainObject(value) {
    return value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        && (Object.getPrototypeOf(value) === Object.prototype
            || Object.getPrototypeOf(value) === null);
}

export function requirePlainObject(value, field) {
    if (!isPlainObject(value)) {
        throw new RuntimeConfigError(`${field} must be a plain object`, { field });
    }
    return value;
}

export function rejectUnknownKeys(value, allowed, field) {
    requirePlainObject(value, field);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            throw new RuntimeConfigError(`${field} has unknown key ${JSON.stringify(key)}`, {
                field,
                key,
            });
        }
    }
}

export function requireString(
    value,
    field,
    {
        min = 1,
        max = 4096,
        trim = false,
        allowLineBreaks = false,
    } = {},
) {
    if (typeof value !== "string") {
        throw new RuntimeConfigError(`${field} must be a string`, { field });
    }
    const normalized = trim ? value.trim() : value;
    const invalidControl = allowLineBreaks
        ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(normalized)
        : CONTROL_CHARACTERS.test(normalized);
    if (normalized.length < min || normalized.length > max || invalidControl) {
        throw new RuntimeConfigError(
            `${field} must contain ${min}..${max} characters without control characters`,
            { field },
        );
    }
    return normalized;
}

export function requireIdentifier(value, field) {
    const normalized = requireString(value, field, { max: 128 });
    if (!SAFE_IDENTIFIER.test(normalized)
        || normalized === "."
        || normalized === ".."
        || normalized.includes("..")) {
        throw new RuntimeConfigError(`${field} must be a safe identifier`, { field, value });
    }
    return normalized;
}

export function requireLowerIdentifier(value, field) {
    const normalized = requireString(value, field, { max: 128 });
    if (!SAFE_LOWER_IDENTIFIER.test(normalized)
        || normalized === "."
        || normalized === ".."
        || normalized.includes("..")) {
        throw new RuntimeConfigError(`${field} must be a lowercase safe identifier`, {
            field,
            value,
        });
    }
    return normalized;
}

export function requireAbsolutePath(value, field) {
    const normalized = requireString(value, field, { max: 32767 });
    if (!path.isAbsolute(normalized)) {
        throw new RuntimeConfigError(`${field} must be an absolute path`, { field, value });
    }
    return path.resolve(normalized);
}

export function requirePositiveInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        throw new RuntimeConfigError(`${field} must be a positive safe integer <= ${maximum}`, {
            field,
            value,
        });
    }
    return value;
}

export function ensureDirectory(directory) {
    assertNoLinkComponents(directory);
    fs.mkdirSync(directory, { recursive: true });
    assertNoLinkComponents(directory);
    return fs.realpathSync.native(directory);
}

export function assertNoLinkComponents(target) {
    const resolved = path.resolve(target);
    const parsed = path.parse(resolved);
    const relative = resolved.slice(parsed.root.length);
    const segments = relative.split(path.sep).filter((segment) => segment.length > 0);
    let current = parsed.root;
    for (const segment of segments) {
        current = path.join(current, segment);
        let stat;
        try {
            stat = fs.lstatSync(current);
        } catch (error) {
            if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
                break;
            }
            throw error;
        }
        if (stat.isSymbolicLink()) {
            throw new OracleRuntimeError(
                RUNTIME_ERROR_CODES.PATH_ESCAPE,
                "Assigned runtime paths cannot traverse a symlink or junction",
                { target: resolved, link: current },
            );
        }
    }
    return resolved;
}

export function isPathInside(candidate, root) {
    const relative = path.relative(path.resolve(root), path.resolve(candidate));
    return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

export function assertPathInside(candidate, root, field = "path") {
    const resolved = path.resolve(candidate);
    const resolvedRoot = path.resolve(root);
    if (!isPathInside(resolved, resolvedRoot)) {
        throw new OracleRuntimeError(
            RUNTIME_ERROR_CODES.PATH_ESCAPE,
            `${field} escapes its assigned root`,
            { field, path: resolved, root: resolvedRoot },
        );
    }
    return resolved;
}

export function atomicWriteJson(file, value, options = {}) {
    const directory = ensureDirectory(path.dirname(file));
    const token = sha256Hex(
        Buffer.from(String(options.token ?? randomBytes(12).toString("hex")), "utf8"),
    ).slice(0, 24);
    const temporary = assertPathInside(
        path.join(directory, `.${path.basename(file)}.${process.pid}.${token}.tmp`),
        directory,
        "atomic temporary file",
    );
    const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    let fd;
    try {
        fd = fs.openSync(temporary, "wx", 0o600);
        let offset = 0;
        while (offset < bytes.length) {
            offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
        }
        fs.fsyncSync(fd);
    } finally {
        if (fd !== undefined) {
            fs.closeSync(fd);
        }
    }
    try {
        fs.renameSync(temporary, file);
    } catch (error) {
        fs.rmSync(temporary, { force: true });
        throw error;
    }
    try {
        const directoryFd = fs.openSync(directory, "r");
        try {
            fs.fsyncSync(directoryFd);
        } finally {
            fs.closeSync(directoryFd);
        }
    } catch {
        // Directory fsync is not uniformly supported on Windows.
    }
    return file;
}

export function readJsonFile(file, field = "JSON file", { maxBytes = 4 * 1024 * 1024 } = {}) {
    let text;
    try {
        const stat = fs.lstatSync(file);
        if (stat.isSymbolicLink() || !stat.isFile()) {
            throw new RuntimeConfigError(`${field} must be a regular non-symlink file`, {
                file,
            });
        }
        if (stat.size > maxBytes) {
            throw new RuntimeConfigError(`${field} exceeds the maximum JSON size`, {
                file,
                bytes: stat.size,
                maxBytes,
            });
        }
        text = fs.readFileSync(file, "utf8");
    } catch (error) {
        if (error instanceof RuntimeConfigError) {
            throw error;
        }
        throw new RuntimeConfigError(`Unable to read ${field}: ${error.message}`, {
            file,
            cause: error.code ?? null,
        });
    }
    try {
        return JSON.parse(text);
    } catch (error) {
        throw new RuntimeConfigError(`${field} is not valid JSON: ${error.message}`, { file });
    }
}

export function sha256Hex(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

export function taggedHash(tag, bytes) {
    if (typeof tag !== "string" || !/^sha256:[a-z0-9][a-z0-9._-]*$/u.test(tag)) {
        throw new RuntimeConfigError("tag must be a sha256 algorithm tag", { tag });
    }
    return `${tag}:${sha256Hex(bytes)}`;
}

export function snapshotObjectHex(snapshotId) {
    if (typeof snapshotId !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(snapshotId)) {
        throw new RuntimeConfigError("snapshot id must be sha256:<64hex>", { snapshotId });
    }
    return snapshotId.slice("sha256:".length);
}

export function measurementSnapshotHash(snapshotId) {
    return `sha256:oracle-measurement-snapshot-v1:${snapshotObjectHex(snapshotId)}`;
}

export function safeFileToken(value) {
    const digest = sha256Hex(Buffer.from(String(value), "utf8")).slice(0, 20);
    return `inv-${digest}`;
}

export function makeUniqueDirectory(root, prefix) {
    const resolvedRoot = ensureDirectory(root);
    const safePrefix = String(prefix).replace(/[^A-Za-z0-9._-]/gu, "-").slice(0, 80);
    const created = fs.mkdtempSync(path.join(resolvedRoot, `${safePrefix}-`));
    return assertPathInside(created, resolvedRoot, "temporary directory");
}

export function removeTreeInside(target, root) {
    const resolved = assertPathInside(target, root, "cleanup target");
    if (path.resolve(resolved) === path.resolve(root)) {
        throw new OracleRuntimeError(
            RUNTIME_ERROR_CODES.PATH_ESCAPE,
            "Refusing to remove the assigned root itself",
            { target: resolved, root: path.resolve(root) },
        );
    }
    fs.rmSync(resolved, { recursive: true, force: true });
}

export function parseDeadline(value, field = "deadline") {
    if (value === null || value === undefined) {
        return null;
    }
    let milliseconds;
    if (typeof value === "number") {
        milliseconds = value;
    } else if (typeof value === "string") {
        milliseconds = Date.parse(value);
    } else {
        throw new RuntimeConfigError(`${field} must be an ISO timestamp, epoch milliseconds, or null`);
    }
    if (!Number.isFinite(milliseconds)) {
        throw new RuntimeConfigError(`${field} is not a valid timestamp`, { value });
    }
    return milliseconds;
}

export function delay(milliseconds, timers = globalThis) {
    return new Promise((resolve) => {
        timers.setTimeout(resolve, Math.max(0, milliseconds));
    });
}

export function parseConfigArgv(argv, programName) {
    if (!Array.isArray(argv)
        || argv.length !== 2
        || argv[0] !== "--config"
        || typeof argv[1] !== "string"
        || !path.isAbsolute(argv[1])) {
        throw new RuntimeConfigError(
            `${programName} requires exactly: --config <absolute-json-path>`,
            { argv },
        );
    }
    return path.resolve(argv[1]);
}
