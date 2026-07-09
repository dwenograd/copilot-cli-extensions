// oracle-v3/tools/configure-harness.mjs
//
// Production operator CLI: create or update an Oracle v3 harness allowlist
// entry BEFORE any investigation starts. This is the only supported way to
// author the operator-owned allowlist that measurement/allowlist.mjs later
// loads fail-closed; the extension process never writes it.
//
// The tool takes a strict JSON *config* file (which lists paths, not hashes)
// and produces a strict *allowlist* entry (which pins content hashes). It:
//
//   * validates a safe id, absolute local non-symlink regular executable /
//     dependency files, and that static-file argv entries are declared
//     dependencies (the same rule the loader enforces);
//   * computes SHA-256 for the executable and every declared dependency;
//   * ingests each validation-case source directory through a *temporary*
//     local ArtifactStore purely to compute the deterministic content-address
//     snapshot id `oracle_start` will later recompute — the temporary store is
//     never retained;
//   * preserves every unrelated existing entry (after a strict parse of the
//     current allowlist), refusing to overwrite an entry whose executable
//     changed unless `--replace` is given;
//   * writes schema version 1 with `validationCases` keyed by id holding
//     `{ snapshotHash, description? }`. Accept/reject expectations are NOT
//     written here — they live in the frozen `oracle_start` contract, and the
//     allowlist schema deliberately does not carry them;
//   * installs the replacement atomically (temp file, fsync, backup of the
//     previous file next to the allowlist, atomic rename) and re-validates the
//     exact bytes it installs by loading them through the real loader.
//
// The CLI prints exactly one JSON object to stdout on success and exits 0; on
// failure it prints one JSON error object to stderr and exits non-zero. It
// never prompts.
//
// No third-party dependencies — only node: builtins and sibling oracle-v3
// modules.

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

import {
    FILE_HASH_ALGORITHM,
    loadHarnessAllowlist,
    sha256File,
    verifyLocalRegularFile,
} from "../measurement/index.mjs";
import { assertLocalDatabasePath, openArtifactStore } from "../persistence/index.mjs";

export const CONFIGURE_SCHEMA_VERSION = 1;

export const CONFIGURE_ERROR_CODES = Object.freeze({
    USAGE: "ORACLE_CONFIGURE_USAGE",
    CONFIG_NOT_FOUND: "ORACLE_CONFIGURE_CONFIG_NOT_FOUND",
    CONFIG_TOO_LARGE: "ORACLE_CONFIGURE_CONFIG_TOO_LARGE",
    CONFIG_INVALID_JSON: "ORACLE_CONFIGURE_CONFIG_INVALID_JSON",
    CONFIG_INVALID: "ORACLE_CONFIGURE_CONFIG_INVALID",
    ALLOWLIST_PATH_INVALID: "ORACLE_CONFIGURE_ALLOWLIST_PATH_INVALID",
    EXECUTABLE_INVALID: "ORACLE_CONFIGURE_EXECUTABLE_INVALID",
    DEPENDENCY_INVALID: "ORACLE_CONFIGURE_DEPENDENCY_INVALID",
    SOURCE_DIR_INVALID: "ORACLE_CONFIGURE_SOURCE_DIR_INVALID",
    VALIDATION_INGEST_FAILED: "ORACLE_CONFIGURE_VALIDATION_INGEST_FAILED",
    EXISTING_ALLOWLIST_INVALID: "ORACLE_CONFIGURE_EXISTING_ALLOWLIST_INVALID",
    ENTRY_CONFLICT: "ORACLE_CONFIGURE_ENTRY_CONFLICT",
    RESULT_INVALID: "ORACLE_CONFIGURE_RESULT_INVALID",
    WRITE_FAILED: "ORACLE_CONFIGURE_WRITE_FAILED",
});

export class ConfigureHarnessError extends Error {
    constructor(code, message, details = null) {
        super(message);
        this.name = "ConfigureHarnessError";
        this.code = code;
        if (details !== null && details !== undefined) {
            this.details = details;
        }
    }
}

// Mirror of the loader's safe-id shape so an id accepted here cannot be
// rejected by the loader later.
const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const ENV_KEY = /^[A-Z_][A-Z0-9_]{0,127}$/u;
const DEFAULT_ROOT_DIRNAME = "OracleV3";
const DEFAULT_ALLOWLIST_FILENAME = "harnesses.json";
const MAX_CONFIG_BYTES = 1 * 1024 * 1024;
const SNAPSHOT_ID_RE = /^sha256:[a-f0-9]{64}$/u;

const CONFIG_ALLOWED_KEYS = new Set([
    "id",
    "executable",
    "argvTemplate",
    "cwd",
    "dependencies",
    "allowedEnv",
    "timeoutMs",
    "maxStdoutBytes",
    "maxStderrBytes",
    "executesCandidateCode",
    "validationCases",
    "description",
]);
const CONFIG_DEPENDENCY_KEYS = new Set(["path", "role"]);
const CONFIG_VALIDATION_CASE_KEYS = new Set(["id", "expectation", "sourceDir", "description"]);
const VALIDATION_EXPECTATIONS = new Set(["accept", "reject"]);

// --- config helpers --------------------------------------------------------

function fail(code, message, details) {
    throw new ConfigureHarnessError(code, message, details);
}

function requireObject(value, field, code = CONFIGURE_ERROR_CODES.CONFIG_INVALID) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        fail(code, `${field} must be an object`);
    }
    return value;
}

function requireString(value, field, { maxLength = 4096, minLength = 1 } = {}) {
    if (typeof value !== "string" || value.length < minLength || value.length > maxLength) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `${field} must be a string of length ${minLength}..${maxLength}`);
    }
    return value;
}

function requirePositiveInteger(value, field, max) {
    if (!Number.isInteger(value) || value <= 0 || value > max) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `${field} must be a positive integer <= ${max}`);
    }
    return value;
}

function requireBool(value, field) {
    if (typeof value !== "boolean") {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `${field} must be a boolean`);
    }
    return value;
}

function rejectUnknownKeys(obj, allowed, field) {
    for (const key of Object.keys(obj)) {
        if (!allowed.has(key)) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `${field} has unknown key ${JSON.stringify(key)}`);
        }
    }
}

// Read + strict-parse a config file. Kept separate so tests can exercise the
// malformed-input paths without a full run.
export function loadConfigFile(configPath) {
    if (typeof configPath !== "string" || configPath.trim().length === 0) {
        fail(CONFIGURE_ERROR_CODES.USAGE, "--config <path> is required");
    }
    let raw;
    try {
        raw = fs.readFileSync(configPath, "utf8");
    } catch (err) {
        if (err && (err.code === "ENOENT" || err.code === "ENOTDIR")) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_NOT_FOUND, `config file not found: ${configPath}`, { path: configPath });
        }
        fail(CONFIGURE_ERROR_CODES.CONFIG_NOT_FOUND, `failed to read config file: ${err?.message ?? String(err)}`, {
            path: configPath,
            cause: err?.code ?? null,
        });
    }
    if (raw.length > MAX_CONFIG_BYTES) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_TOO_LARGE, `config file exceeds ${MAX_CONFIG_BYTES} bytes`, {
            path: configPath,
            bytes: raw.length,
        });
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (err) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID_JSON, `config file is not valid JSON: ${err?.message ?? String(err)}`, {
            path: configPath,
        });
    }
    return parsed;
}

// Validate a raw config object into a normalized shape. Does not touch the
// filesystem beyond nothing (path resolution/verification happens later).
function normalizeConfig(rawConfig) {
    requireObject(rawConfig, "config");
    rejectUnknownKeys(rawConfig, CONFIG_ALLOWED_KEYS, "config");

    const id = requireString(rawConfig.id, "config.id", { maxLength: 128 });
    if (!SAFE_ID.test(id)) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.id ${JSON.stringify(id)} is not a safe id (/^[a-z0-9][a-z0-9._-]{0,127}$/)`);
    }

    const executable = requireString(rawConfig.executable, "config.executable");
    if (!path.isAbsolute(executable)) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.executable must be an absolute path");
    }

    if (!Array.isArray(rawConfig.argvTemplate)) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.argvTemplate must be an array");
    }
    if (rawConfig.argvTemplate.length > 256) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.argvTemplate is too long (max 256)");
    }
    const argvTemplate = rawConfig.argvTemplate.map((item, index) => {
        if (typeof item !== "string") {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.argvTemplate[${index}] must be a string`);
        }
        return item;
    });

    let cwd;
    if (rawConfig.cwd !== undefined && rawConfig.cwd !== null) {
        cwd = requireString(rawConfig.cwd, "config.cwd");
        if (!path.isAbsolute(cwd)) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.cwd must be an absolute path");
        }
    }

    const dependencies = normalizeConfigDependencies(rawConfig.dependencies);
    const allowedEnv = normalizeConfigAllowedEnv(rawConfig.allowedEnv);

    const timeoutMs = requirePositiveInteger(rawConfig.timeoutMs, "config.timeoutMs", 60 * 60 * 1000);
    const maxStdoutBytes = requirePositiveInteger(rawConfig.maxStdoutBytes, "config.maxStdoutBytes", 64 * 1024 * 1024);
    const maxStderrBytes = requirePositiveInteger(rawConfig.maxStderrBytes, "config.maxStderrBytes", 64 * 1024 * 1024);
    const executesCandidateCode = requireBool(rawConfig.executesCandidateCode, "config.executesCandidateCode");

    const validationCases = normalizeConfigValidationCases(rawConfig.validationCases);

    let description;
    if (rawConfig.description !== undefined && rawConfig.description !== null) {
        description = requireString(rawConfig.description, "config.description", { maxLength: 4096 });
    }

    return {
        id,
        executable,
        argvTemplate,
        cwd,
        dependencies,
        allowedEnv,
        timeoutMs,
        maxStdoutBytes,
        maxStderrBytes,
        executesCandidateCode,
        validationCases,
        description,
    };
}

function normalizeConfigDependencies(dependencies) {
    if (dependencies === undefined || dependencies === null) {
        return [];
    }
    if (!Array.isArray(dependencies)) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.dependencies must be an array");
    }
    if (dependencies.length > 64) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.dependencies has too many entries (max 64)");
    }
    return dependencies.map((dep, index) => {
        requireObject(dep, `config.dependencies[${index}]`);
        rejectUnknownKeys(dep, CONFIG_DEPENDENCY_KEYS, `config.dependencies[${index}]`);
        const depPath = requireString(dep.path, `config.dependencies[${index}].path`);
        if (!path.isAbsolute(depPath)) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.dependencies[${index}].path must be an absolute path`);
        }
        let role = "dependency";
        if (dep.role !== undefined && dep.role !== null) {
            role = requireString(dep.role, `config.dependencies[${index}].role`, { maxLength: 64 });
        }
        return { path: depPath, role };
    });
}

function normalizeConfigAllowedEnv(allowedEnv) {
    if (allowedEnv === undefined || allowedEnv === null) {
        return {};
    }
    requireObject(allowedEnv, "config.allowedEnv");
    const out = {};
    for (const key of Object.keys(allowedEnv).sort()) {
        if (!ENV_KEY.test(key)) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.allowedEnv key ${JSON.stringify(key)} must match /^[A-Z_][A-Z0-9_]*$/`);
        }
        const value = allowedEnv[key];
        if (typeof value !== "string" || value.length > 32768) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.allowedEnv[${key}] must be a string <= 32768 chars`);
        }
        out[key] = value;
    }
    return out;
}

function normalizeConfigValidationCases(validationCases) {
    if (!Array.isArray(validationCases)) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.validationCases must be an array");
    }
    if (validationCases.length < 2) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.validationCases must contain at least one accept and one reject case");
    }
    if (validationCases.length > 4096) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.validationCases has too many cases");
    }
    const ids = new Set();
    const expectations = new Set();
    const out = validationCases.map((item, index) => {
        requireObject(item, `config.validationCases[${index}]`);
        rejectUnknownKeys(item, CONFIG_VALIDATION_CASE_KEYS, `config.validationCases[${index}]`);
        const caseId = requireString(item.id, `config.validationCases[${index}].id`, { maxLength: 128 });
        if (!SAFE_ID.test(caseId)) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.validationCases[${index}].id ${JSON.stringify(caseId)} is not a safe id`);
        }
        if (ids.has(caseId)) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.validationCases has duplicate id ${JSON.stringify(caseId)}`);
        }
        ids.add(caseId);
        const expectation = item.expectation;
        if (!VALIDATION_EXPECTATIONS.has(expectation)) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.validationCases[${index}].expectation must be "accept" or "reject"`);
        }
        expectations.add(expectation);
        const sourceDir = requireString(item.sourceDir, `config.validationCases[${index}].sourceDir`);
        if (!path.isAbsolute(sourceDir)) {
            fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, `config.validationCases[${index}].sourceDir must be an absolute path`);
        }
        let description;
        if (item.description !== undefined && item.description !== null) {
            description = requireString(item.description, `config.validationCases[${index}].description`, { maxLength: 4096 });
        }
        return { id: caseId, expectation, sourceDir, description };
    });
    if (!expectations.has("accept") || !expectations.has("reject")) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.validationCases must contain at least one accept and one reject case");
    }
    return out;
}

// --- filesystem verification + hashing -------------------------------------

// Verify a pinned local regular non-symlink file and return its resolved
// realpath plus a bare 64-char SHA-256 hex digest (the on-disk allowlist
// representation used in the README example).
function verifyAndDigestFile(filePath, label, errorCode) {
    let resolvedPath;
    try {
        resolvedPath = verifyLocalRegularFile(filePath, { label });
    } catch (err) {
        fail(errorCode, `${label} could not be verified: ${err?.message ?? String(err)}`, {
            path: filePath,
            cause: err?.code ?? null,
        });
    }
    let tagged;
    try {
        tagged = sha256File(resolvedPath, FILE_HASH_ALGORITHM);
    } catch (err) {
        fail(errorCode, `${label} could not be hashed: ${err?.message ?? String(err)}`, {
            path: resolvedPath,
            cause: err?.code ?? null,
        });
    }
    const sha256 = tagged.split(":").pop();
    return { resolvedPath, sha256 };
}

function verifySourceDir(sourceDir, caseId, env) {
    let local;
    try {
        local = assertLocalDatabasePath(sourceDir, { env });
    } catch (err) {
        fail(CONFIGURE_ERROR_CODES.SOURCE_DIR_INVALID, `validation case '${caseId}' sourceDir must be a trusted local path: ${err?.message ?? String(err)}`, {
            id: caseId,
            path: sourceDir,
            cause: err?.code ?? null,
        });
    }
    let link;
    try {
        link = fs.lstatSync(local);
    } catch (err) {
        fail(CONFIGURE_ERROR_CODES.SOURCE_DIR_INVALID, `validation case '${caseId}' sourceDir does not exist`, {
            id: caseId,
            path: sourceDir,
            cause: err?.code ?? null,
        });
    }
    if (link.isSymbolicLink()) {
        fail(CONFIGURE_ERROR_CODES.SOURCE_DIR_INVALID, `validation case '${caseId}' sourceDir must not be a symlink or junction`, {
            id: caseId,
            path: sourceDir,
        });
    }
    if (!link.isDirectory()) {
        fail(CONFIGURE_ERROR_CODES.SOURCE_DIR_INVALID, `validation case '${caseId}' sourceDir must be a directory`, {
            id: caseId,
            path: sourceDir,
        });
    }
    let real;
    try {
        real = fs.realpathSync.native(local);
    } catch (err) {
        fail(CONFIGURE_ERROR_CODES.SOURCE_DIR_INVALID, `validation case '${caseId}' sourceDir could not be resolved`, {
            id: caseId,
            path: sourceDir,
            cause: err?.code ?? null,
        });
    }
    return real;
}

// --- allowlist path resolution ---------------------------------------------

// Resolve the output allowlist path: an explicit --allowlist wins, otherwise
// the per-user default under %LOCALAPPDATA%. The path must be absolute and on
// a trusted local filesystem.
export function resolveOutputAllowlistPath(explicitPath, env) {
    let raw;
    if (typeof explicitPath === "string" && explicitPath.trim().length > 0) {
        raw = explicitPath;
    } else {
        const localAppData = env?.LOCALAPPDATA;
        if (typeof localAppData !== "string" || localAppData.trim().length === 0) {
            fail(
                CONFIGURE_ERROR_CODES.ALLOWLIST_PATH_INVALID,
                "LOCALAPPDATA is not set; pass --allowlist <path> explicitly",
                { variable: "LOCALAPPDATA" },
            );
        }
        raw = path.join(localAppData, DEFAULT_ROOT_DIRNAME, DEFAULT_ALLOWLIST_FILENAME);
    }
    if (!path.isAbsolute(raw)) {
        fail(CONFIGURE_ERROR_CODES.ALLOWLIST_PATH_INVALID, "allowlist path must be absolute", { path: raw });
    }
    try {
        return assertLocalDatabasePath(raw, { env });
    } catch (err) {
        fail(CONFIGURE_ERROR_CODES.ALLOWLIST_PATH_INVALID, `allowlist path must be on a trusted local filesystem: ${err?.message ?? String(err)}`, {
            path: raw,
            cause: err?.code ?? null,
        });
    }
}

// --- existing-allowlist preservation ---------------------------------------

// Strict-parse the existing allowlist (if any) via the real loader and
// re-serialize every entry into on-disk shape. Fails closed if the existing
// file is malformed rather than silently discarding operator entries.
function loadExistingEntries(allowlistPath) {
    if (!fs.existsSync(allowlistPath)) {
        return { existed: false, entries: {} };
    }
    let loaded;
    try {
        loaded = loadHarnessAllowlist(allowlistPath);
    } catch (err) {
        fail(
            CONFIGURE_ERROR_CODES.EXISTING_ALLOWLIST_INVALID,
            `refusing to overwrite an existing allowlist that does not strict-parse: ${err?.message ?? String(err)}`,
            { path: allowlistPath, cause: err?.code ?? null },
        );
    }
    const entries = {};
    for (const id of loaded.listEntryIds()) {
        entries[id] = serializeEntry(loaded.getEntry(id));
    }
    return { existed: true, entries, loaded };
}

// Convert a loader-normalized entry back into the strict on-disk entry shape,
// dropping the computed-only fields (id key, argvDependencyRefs) and any nulls.
function serializeEntry(entry) {
    const out = {
        executable: entry.executable,
        executableSha256: entry.executableSha256,
        argvTemplate: [...entry.argvTemplate],
        dependencies: entry.dependencies.map((dep) => ({
            path: dep.path,
            sha256: dep.sha256,
            role: dep.role,
        })),
        allowedEnv: { ...entry.allowedEnv },
        timeoutMs: entry.timeoutMs,
        maxStdoutBytes: entry.maxStdoutBytes,
        maxStderrBytes: entry.maxStderrBytes,
        executesCandidateCode: entry.executesCandidateCode,
    };
    if (entry.cwd !== null && entry.cwd !== undefined) {
        out.cwd = entry.cwd;
    }
    if (entry.validationCases !== null && entry.validationCases !== undefined) {
        const cases = {};
        for (const id of Object.keys(entry.validationCases)) {
            const spec = entry.validationCases[id];
            cases[id] = spec.description === null || spec.description === undefined
                ? { snapshotHash: spec.snapshotHash }
                : { snapshotHash: spec.snapshotHash, description: spec.description };
        }
        out.validationCases = cases;
    }
    if (entry.description !== null && entry.description !== undefined) {
        out.description = entry.description;
    }
    return out;
}

function sameExecutable(a, b) {
    const left = path.resolve(a);
    const right = path.resolve(b);
    return process.platform === "win32"
        ? left.toLowerCase() === right.toLowerCase()
        : left === right;
}

// --- atomic install --------------------------------------------------------

function fsyncDirBestEffort(dir) {
    let fd;
    try {
        fd = fs.openSync(dir, "r");
        fs.fsyncSync(fd);
    } catch {
        // Directory fsync is not supported everywhere (notably Windows); the
        // rename itself is atomic, so this is defence-in-depth only.
    } finally {
        if (fd !== undefined) {
            try { fs.closeSync(fd); } catch { /* ignore */ }
        }
    }
}

// Write `contentString` to `targetPath` atomically. If a file already exists
// there, its previous bytes are copied to `<targetPath>.bak` (fsync'd) before
// the atomic rename installs the replacement.
function atomicWriteWithBackup(targetPath, contentString) {
    const dir = path.dirname(targetPath);
    fs.mkdirSync(dir, { recursive: true });
    const existed = fs.existsSync(targetPath);
    const tmpPath = path.join(dir, `.${path.basename(targetPath)}.${randomBytes(8).toString("hex")}.tmp`);

    let fd;
    try {
        fd = fs.openSync(tmpPath, "wx");
        const buffer = Buffer.from(contentString, "utf8");
        let offset = 0;
        while (offset < buffer.length) {
            offset += fs.writeSync(fd, buffer, offset, buffer.length - offset);
        }
        fs.fsyncSync(fd);
    } catch (err) {
        if (fd !== undefined) {
            try { fs.closeSync(fd); } catch { /* ignore */ }
            fd = undefined;
        }
        try { fs.rmSync(tmpPath, { force: true }); } catch { /* ignore */ }
        fail(CONFIGURE_ERROR_CODES.WRITE_FAILED, `failed to stage allowlist: ${err?.message ?? String(err)}`, {
            path: targetPath,
            cause: err?.code ?? null,
        });
    } finally {
        if (fd !== undefined) {
            try { fs.closeSync(fd); } catch { /* ignore */ }
        }
    }

    let backupPath = null;
    if (existed) {
        backupPath = `${targetPath}.bak`;
        try {
            const current = fs.readFileSync(targetPath);
            const bfd = fs.openSync(backupPath, "w");
            try {
                let offset = 0;
                while (offset < current.length) {
                    offset += fs.writeSync(bfd, current, offset, current.length - offset);
                }
                fs.fsyncSync(bfd);
            } finally {
                fs.closeSync(bfd);
            }
        } catch (err) {
            try { fs.rmSync(tmpPath, { force: true }); } catch { /* ignore */ }
            fail(CONFIGURE_ERROR_CODES.WRITE_FAILED, `failed to back up existing allowlist: ${err?.message ?? String(err)}`, {
                path: targetPath,
                backupPath,
                cause: err?.code ?? null,
            });
        }
    }

    try {
        fs.renameSync(tmpPath, targetPath);
    } catch (err) {
        try { fs.rmSync(tmpPath, { force: true }); } catch { /* ignore */ }
        fail(CONFIGURE_ERROR_CODES.WRITE_FAILED, `failed to install allowlist: ${err?.message ?? String(err)}`, {
            path: targetPath,
            cause: err?.code ?? null,
        });
    }
    fsyncDirBestEffort(dir);
    return { backupPath, existed };
}

// --- core -----------------------------------------------------------------

/**
 * Pure(ish) configuration entry point. Performs all validation, hashing,
 * temporary ingestion and the atomic allowlist install, returning a plain
 * result object. Throws ConfigureHarnessError (with a stable `code`) on any
 * failure. The temporary ArtifactStore it creates for snapshot ingestion is
 * always removed before returning, success or failure.
 *
 * options:
 *   config        - a parsed config object (mutually exclusive with configPath)
 *   configPath    - path to a strict JSON config file
 *   allowlistPath - explicit output allowlist path (optional)
 *   replace       - allow overwriting an entry whose executable changed
 *   env           - environment object (defaults to process.env)
 */
export function configureHarness(options = {}) {
    const env = options.env ?? process.env;
    const replace = options.replace === true;

    if (options.config !== undefined && options.configPath !== undefined) {
        fail(CONFIGURE_ERROR_CODES.USAGE, "pass either config or configPath, not both");
    }
    const rawConfig = options.config !== undefined ? options.config : loadConfigFile(options.configPath);
    const config = normalizeConfig(rawConfig);

    const allowlistPath = resolveOutputAllowlistPath(options.allowlistPath, env);
    const allowlistDir = path.dirname(allowlistPath);
    fs.mkdirSync(allowlistDir, { recursive: true });

    // Verify + hash the executable and each declared dependency.
    const executable = verifyAndDigestFile(config.executable, "config.executable", CONFIGURE_ERROR_CODES.EXECUTABLE_INVALID);
    const dependencies = config.dependencies.map((dep, index) => {
        const verified = verifyAndDigestFile(dep.path, `config.dependencies[${index}].path`, CONFIGURE_ERROR_CODES.DEPENDENCY_INVALID);
        return { path: verified.resolvedPath, sha256: verified.sha256, role: dep.role };
    });

    // Ingest each validation source directory through a throwaway local store.
    const storeRoot = path.join(allowlistDir, `.oracle-configure-store-${randomBytes(10).toString("hex")}`);
    const validationCaseSnapshots = {};
    let entryHash = null;
    let contentHash = null;
    let install = null;
    try {
        const store = openArtifactStore({ root: storeRoot, env });
        for (const validationCase of config.validationCases) {
            const sourceDir = verifySourceDir(validationCase.sourceDir, validationCase.id, env);
            let ingested;
            try {
                ingested = store.ingestDirectory({ sourceDir, env });
            } catch (err) {
                fail(
                    CONFIGURE_ERROR_CODES.VALIDATION_INGEST_FAILED,
                    `validation case '${validationCase.id}' could not be ingested: ${err?.message ?? String(err)}`,
                    { id: validationCase.id, path: validationCase.sourceDir, cause: err?.code ?? null },
                );
            }
            if (!SNAPSHOT_ID_RE.test(ingested.snapshot)) {
                fail(CONFIGURE_ERROR_CODES.VALIDATION_INGEST_FAILED, `validation case '${validationCase.id}' produced a malformed snapshot id`, {
                    id: validationCase.id,
                    snapshot: ingested.snapshot,
                });
            }
            validationCaseSnapshots[validationCase.id] = {
                snapshotHash: ingested.snapshot,
                description: validationCase.description,
            };
        }

        // Preserve unrelated existing entries after a strict parse.
        const existing = loadExistingEntries(allowlistPath);
        const replaced = Object.hasOwn(existing.entries, config.id);
        if (replaced) {
            const prior = existing.loaded.getEntry(config.id);
            if (!sameExecutable(prior.executable, executable.resolvedPath) && !replace) {
                fail(
                    CONFIGURE_ERROR_CODES.ENTRY_CONFLICT,
                    `entry '${config.id}' already exists with a different executable; pass --replace to overwrite`,
                    { id: config.id, existingExecutable: prior.executable, newExecutable: executable.resolvedPath },
                );
            }
        }

        // Build the new entry in strict on-disk shape.
        const newEntry = {
            executable: executable.resolvedPath,
            executableSha256: executable.sha256,
            argvTemplate: [...config.argvTemplate],
            dependencies: dependencies.map((dep) => ({ path: dep.path, sha256: dep.sha256, role: dep.role })),
            allowedEnv: { ...config.allowedEnv },
            timeoutMs: config.timeoutMs,
            maxStdoutBytes: config.maxStdoutBytes,
            maxStderrBytes: config.maxStderrBytes,
            executesCandidateCode: config.executesCandidateCode,
            validationCases: buildValidationCaseBlock(validationCaseSnapshots),
        };
        if (config.cwd !== undefined) {
            newEntry.cwd = config.cwd;
        }
        if (config.description !== undefined) {
            newEntry.description = config.description;
        }

        const mergedEntries = { ...existing.entries, [config.id]: newEntry };
        const document = { version: CONFIGURE_SCHEMA_VERSION, entries: sortedEntries(mergedEntries) };
        const contentString = `${JSON.stringify(document, null, 2)}\n`;

        // Pre-validate the exact bytes we are about to install by loading them
        // through the real loader (which enforces the argv → dependency rule
        // and every other allowlist invariant). We validate a throwaway copy
        // first so a rejected document never becomes the live allowlist.
        const validationTmp = path.join(allowlistDir, `.harness-validate-${randomBytes(8).toString("hex")}.json`);
        let loaded;
        try {
            fs.writeFileSync(validationTmp, contentString, { flag: "wx" });
            loaded = loadHarnessAllowlist(validationTmp);
            entryHash = loaded.getEntryHash(config.id);
            contentHash = loaded.contentHash;
        } catch (err) {
            if (err instanceof ConfigureHarnessError) throw err;
            fail(CONFIGURE_ERROR_CODES.RESULT_INVALID, `assembled allowlist failed strict validation: ${err?.message ?? String(err)}`, {
                path: allowlistPath,
                cause: err?.details?.code ?? err?.code ?? null,
            });
        } finally {
            try { fs.rmSync(validationTmp, { force: true }); } catch { /* ignore */ }
        }

        // Install the validated bytes atomically, backing up any prior file.
        install = atomicWriteWithBackup(allowlistPath, contentString);

        return Object.freeze({
            schemaVersion: CONFIGURE_SCHEMA_VERSION,
            allowlistPath,
            entryId: config.id,
            entryHash,
            contentHash,
            executablePath: executable.resolvedPath,
            executableSha256: executable.sha256,
            dependencies: Object.freeze(dependencies.map((dep) => Object.freeze({ path: dep.path, sha256: dep.sha256, role: dep.role }))),
            validationSnapshots: Object.freeze({ ...mapSnapshots(validationCaseSnapshots) }),
            replaced,
            replacedByOverride: replaced && replace,
            backupPath: install.backupPath,
            preservedEntryIds: Object.freeze(Object.keys(existing.entries).filter((id) => id !== config.id).sort()),
        });
    } finally {
        try {
            fs.rmSync(storeRoot, { recursive: true, force: true });
        } catch {
            // Best-effort cleanup: a residual throwaway store is harmless, but
            // we never keep it as authoritative.
        }
    }
}

function buildValidationCaseBlock(snapshots) {
    const out = {};
    for (const id of Object.keys(snapshots).sort()) {
        const spec = snapshots[id];
        out[id] = spec.description === undefined
            ? { snapshotHash: spec.snapshotHash }
            : { snapshotHash: spec.snapshotHash, description: spec.description };
    }
    return out;
}

function mapSnapshots(snapshots) {
    const out = {};
    for (const id of Object.keys(snapshots).sort()) {
        out[id] = snapshots[id].snapshotHash;
    }
    return out;
}

function sortedEntries(entries) {
    const out = {};
    for (const id of Object.keys(entries).sort()) {
        out[id] = entries[id];
    }
    return out;
}

// --- CLI -------------------------------------------------------------------

export function parseArgs(argv) {
    const out = { config: undefined, allowlist: undefined, replace: false, help: false };
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === "--help" || arg === "-h") {
            out.help = true;
        } else if (arg === "--replace") {
            out.replace = true;
        } else if (arg === "--config") {
            out.config = argv[i + 1];
            i += 1;
        } else if (arg.startsWith("--config=")) {
            out.config = arg.slice("--config=".length);
        } else if (arg === "--allowlist") {
            out.allowlist = argv[i + 1];
            i += 1;
        } else if (arg.startsWith("--allowlist=")) {
            out.allowlist = arg.slice("--allowlist=".length);
        } else {
            fail(CONFIGURE_ERROR_CODES.USAGE, `unknown argument ${JSON.stringify(arg)}`);
        }
    }
    return out;
}

const USAGE = `Usage: node tools/configure-harness.mjs --config <path> [--allowlist <path>] [--replace]

Creates or updates an Oracle v3 operator harness allowlist entry from a strict
JSON config file, computing executable/dependency SHA-256 digests and the
deterministic validation-case snapshot ids oracle_start will recompute.

Options:
  --config <path>     Strict JSON harness config (required).
  --allowlist <path>  Output allowlist path (default %LOCALAPPDATA%\\OracleV3\\harnesses.json).
  --replace           Allow overwriting an entry whose executable changed.
  -h, --help          Show this help.`;

export function main(argv = process.argv.slice(2), { env = process.env, stdout = process.stdout, stderr = process.stderr } = {}) {
    let args;
    try {
        args = parseArgs(argv);
    } catch (err) {
        stderr.write(`${JSON.stringify(errorPayload(err))}\n`);
        return 2;
    }
    if (args.help) {
        stdout.write(`${USAGE}\n`);
        return 0;
    }
    if (typeof args.config !== "string" || args.config.trim().length === 0) {
        stderr.write(`${JSON.stringify(errorPayload(new ConfigureHarnessError(CONFIGURE_ERROR_CODES.USAGE, "--config <path> is required")))}\n`);
        return 2;
    }
    try {
        const result = configureHarness({
            configPath: args.config,
            allowlistPath: args.allowlist,
            replace: args.replace,
            env,
        });
        stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
        return 0;
    } catch (err) {
        stderr.write(`${JSON.stringify(errorPayload(err))}\n`);
        return 1;
    }
}

function errorPayload(err) {
    return {
        ok: false,
        error: {
            code: err?.code ?? "ORACLE_CONFIGURE_UNKNOWN",
            message: err?.message ?? String(err),
            ...(err?.details ? { details: err.details } : {}),
        },
    };
}

const invokedDirectly = (() => {
    if (!process.argv[1]) return false;
    try {
        return import.meta.url === pathToFileURL(process.argv[1]).href;
    } catch {
        return false;
    }
})();

if (invokedDirectly) {
    process.exit(main());
}
