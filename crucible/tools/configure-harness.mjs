// crucible/tools/configure-harness.mjs
//
// Production operator CLI: create/update Crucible harness allowlist entries or
// compose them into a HarnessSuiteV4 BEFORE any investigation starts. This is
// the supported authoring path for the operator-owned allowlist that
// measurement/allowlist.mjs later loads fail-closed.
//
// The tool takes a strict JSON *config* file (which lists paths, not hashes)
// and produces a strict *allowlist* entry (which pins content hashes). It:
//
//   * validates a safe id, absolute local non-symlink regular executable /
//     dependency files, and that static-file argv entries are declared
//     dependencies (the same rule the loader enforces);
//   * computes SHA-256 for the executable and every declared dependency;
//   * ingests each validation-case source directory into a durable,
//     operator-owned local ArtifactStore and pins its content address;
//   * preserves every unrelated existing entry (after a strict parse of the
//     current allowlist), refusing to overwrite an entry whose executable
//     changed unless `--replace` is given;
//   * writes schema version 1 with immutable snapshot/expectation pairs;
//   * composes existing entries into strict v4 role suites without exposing
//     protected case manifests through the worker projection;
//   * installs the replacement atomically (temp file, fsync, backup of the
//     previous file next to the allowlist, atomic rename) and re-validates the
//     exact bytes it installs by loading them through the real loader.
//
// The CLI prints exactly one JSON object to stdout on success and exits 0; on
// failure it prints one JSON error object to stderr and exits non-zero. It
// never prompts.
//
// No third-party dependencies — only node: builtins and sibling crucible
// modules.

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
    FILE_HASH_ALGORITHM,
    HARNESS_SUITE_V4_KIND,
    HARNESS_SUITE_V4_REQUIRED_ROLES,
    HARNESS_SUITE_V4_ROLES,
    HARNESS_SUITE_V4_VERIFIER_INDEPENDENCE_ATTESTATION,
    PARSER_SOURCE_HASH_ALGORITHM,
    PARSER_VERSION,
    VERIFIER_PARSER_VERSION,
    PARSER_VERSION_HASH_ALGORITHM,
    applicationEntrypointHashForEntry,
    computeHarnessSuiteV4Identity,
    hashHarnessEnvironmentV4,
    hashHarnessObservableSchemaV4,
    hashHarnessRoleConfigV4,
    loadHarnessAllowlist,
    normalizeHarnessSuiteV4,
    sha256File,
    verifyLocalRegularFile,
} from "../measurement/index.mjs";
import { hashCanonical } from "../domain/canonical.mjs";
import { assertLocalDatabasePath, openArtifactStore } from "../persistence/index.mjs";

const CONFIGURE_SCHEMA_VERSION = 1;

const CONFIGURE_ERROR_CODES = Object.freeze({
    USAGE: "CRUCIBLE_CONFIGURE_USAGE",
    CONFIG_NOT_FOUND: "CRUCIBLE_CONFIGURE_CONFIG_NOT_FOUND",
    CONFIG_TOO_LARGE: "CRUCIBLE_CONFIGURE_CONFIG_TOO_LARGE",
    CONFIG_INVALID_JSON: "CRUCIBLE_CONFIGURE_CONFIG_INVALID_JSON",
    CONFIG_INVALID: "CRUCIBLE_CONFIGURE_CONFIG_INVALID",
    ALLOWLIST_PATH_INVALID: "CRUCIBLE_CONFIGURE_ALLOWLIST_PATH_INVALID",
    CASE_STORE_PATH_INVALID: "CRUCIBLE_CONFIGURE_CASE_STORE_PATH_INVALID",
    EXECUTABLE_INVALID: "CRUCIBLE_CONFIGURE_EXECUTABLE_INVALID",
    DEPENDENCY_INVALID: "CRUCIBLE_CONFIGURE_DEPENDENCY_INVALID",
    SOURCE_DIR_INVALID: "CRUCIBLE_CONFIGURE_SOURCE_DIR_INVALID",
    VALIDATION_INGEST_FAILED: "CRUCIBLE_CONFIGURE_VALIDATION_INGEST_FAILED",
    EXISTING_ALLOWLIST_INVALID: "CRUCIBLE_CONFIGURE_EXISTING_ALLOWLIST_INVALID",
    ENTRY_CONFLICT: "CRUCIBLE_CONFIGURE_ENTRY_CONFLICT",
    SUITE_CONFLICT: "CRUCIBLE_CONFIGURE_SUITE_CONFLICT",
    RESULT_INVALID: "CRUCIBLE_CONFIGURE_RESULT_INVALID",
    WRITE_FAILED: "CRUCIBLE_CONFIGURE_WRITE_FAILED",
});

class ConfigureHarnessError extends Error {
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
const SAFE_ID = /^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$/u;
const ENV_KEY = /^[A-Z_][A-Z0-9_]{0,127}$/u;
const DEFAULT_ROOT_DIRNAME = "Crucible";
const DEFAULT_ALLOWLIST_FILENAME = "harnesses.json";
const DEFAULT_CASE_STORE_DIRNAME = "operator-corpus";
const MAX_CONFIG_BYTES = 1 * 1024 * 1024;
const SNAPSHOT_ID_RE = /^sha256:[a-f0-9]{64}$/u;
const TAGGED_SHA256_RE =
    /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;

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
const SUITE_CONFIG_KEYS = new Set([
    "kind",
    "version",
    "id",
    "environment",
    "sharedPlatformDependencies",
    "roles",
]);
const SUITE_ROLE_KEYS = new Set([
    "harnessId",
    "observableSchema",
    "caseIds",
    "deterministicSeed",
    "sandboxIdentity",
    "independenceAttestation",
    "verificationPolicy",
]);
const SUITE_SHARED_DEPENDENCY_KEYS = new Set([
    "classification",
    "path",
    "role",
]);
const SUITE_SANDBOX_KEYS = new Set(["required", "policyDigest"]);

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

// Read and strict-parse a config file before any output is written.
function loadConfigFile(configPath) {
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

function isSuiteAuthoringConfig(value) {
    return value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        && (value.kind === HARNESS_SUITE_V4_KIND
            || (value.version === 4 && value.roles !== undefined));
}

function normalizeSuiteSandboxIdentity(value, field) {
    requireObject(value, field);
    rejectUnknownKeys(value, SUITE_SANDBOX_KEYS, field);
    const required = requireBool(value.required, `${field}.required`);
    if (!required) {
        if (value.policyDigest !== null) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `${field}.policyDigest must be null when required is false`,
            );
        }
        return { required: false, policyDigest: null };
    }
    if (typeof value.policyDigest !== "string"
        || !TAGGED_SHA256_RE.test(value.policyDigest)) {
        fail(
            CONFIGURE_ERROR_CODES.CONFIG_INVALID,
            `${field}.policyDigest must be an algorithm-tagged SHA-256 identity`,
        );
    }
    return { required: true, policyDigest: value.policyDigest };
}

function normalizeSuiteConfig(rawConfig) {
    requireObject(rawConfig, "config");
    rejectUnknownKeys(rawConfig, SUITE_CONFIG_KEYS, "config");
    if (rawConfig.kind !== HARNESS_SUITE_V4_KIND || rawConfig.version !== 4) {
        fail(
            CONFIGURE_ERROR_CODES.CONFIG_INVALID,
            `suite config must declare kind "${HARNESS_SUITE_V4_KIND}" and version 4`,
        );
    }
    const id = requireString(rawConfig.id, "config.id", { maxLength: 128 });
    if (!SAFE_ID.test(id)) {
        fail(CONFIGURE_ERROR_CODES.CONFIG_INVALID, "config.id is not a safe id");
    }
    requireObject(rawConfig.environment, "config.environment");
    try {
        hashHarnessEnvironmentV4(rawConfig.environment);
    } catch (error) {
        fail(
            CONFIGURE_ERROR_CODES.CONFIG_INVALID,
            `config.environment is not a valid identity payload: ${error?.message ?? String(error)}`,
        );
    }

    const sharedPlatformDependencies = rawConfig.sharedPlatformDependencies
        ?? [];
    if (!Array.isArray(sharedPlatformDependencies)
        || sharedPlatformDependencies.length > 128) {
        fail(
            CONFIGURE_ERROR_CODES.CONFIG_INVALID,
            "config.sharedPlatformDependencies must be an array with at most 128 entries",
        );
    }
    const normalizedShared = sharedPlatformDependencies.map((item, index) => {
        const field = `config.sharedPlatformDependencies[${index}]`;
        requireObject(item, field);
        rejectUnknownKeys(item, SUITE_SHARED_DEPENDENCY_KEYS, field);
        const dependencyPath = requireString(item.path, `${field}.path`);
        if (!path.isAbsolute(dependencyPath)) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `${field}.path must be absolute`,
            );
        }
        if (item.classification !== "platform"
            && item.classification !== "runtime") {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `${field}.classification must be "platform" or "runtime"`,
            );
        }
        return {
            classification: item.classification,
            path: dependencyPath,
            role: requireString(item.role, `${field}.role`, { maxLength: 128 }),
        };
    });

    requireObject(rawConfig.roles, "config.roles");
    for (const role of Object.keys(rawConfig.roles)) {
        if (!HARNESS_SUITE_V4_ROLES.includes(role)) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `config.roles has unknown role ${JSON.stringify(role)}`,
            );
        }
    }
    for (const role of HARNESS_SUITE_V4_REQUIRED_ROLES) {
        if (!Object.hasOwn(rawConfig.roles, role)) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `config.roles.${role} is required`,
            );
        }
    }
    const roles = {};
    for (const role of HARNESS_SUITE_V4_ROLES) {
        if (!Object.hasOwn(rawConfig.roles, role)) continue;
        const field = `config.roles.${role}`;
        const spec = rawConfig.roles[role];
        requireObject(spec, field);
        rejectUnknownKeys(spec, SUITE_ROLE_KEYS, field);
        const harnessId = requireString(
            spec.harnessId,
            `${field}.harnessId`,
            { maxLength: 128 },
        );
        if (!SAFE_ID.test(harnessId)) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `${field}.harnessId is not a safe id`,
            );
        }
        requireObject(spec.observableSchema, `${field}.observableSchema`);
        try {
            hashHarnessObservableSchemaV4(spec.observableSchema);
        } catch (error) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `${field}.observableSchema is invalid: ${error?.message ?? String(error)}`,
            );
        }
        if (!Array.isArray(spec.caseIds) || spec.caseIds.length > 4096) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `${field}.caseIds must be an array with at most 4096 entries`,
            );
        }
        const seen = new Set();
        const caseIds = spec.caseIds.map((caseId, index) => {
            const normalized = requireString(
                caseId,
                `${field}.caseIds[${index}]`,
                { maxLength: 128 },
            );
            if (!SAFE_ID.test(normalized) || seen.has(normalized)) {
                fail(
                    CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                    `${field}.caseIds contains an invalid or duplicate id`,
                    { caseId: normalized },
                );
            }
            seen.add(normalized);
            return normalized;
        }).sort();
        if (role === "calibration" && caseIds.length === 0) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                "config.roles.calibration.caseIds must not be empty",
            );
        }
        roles[role] = {
            harnessId,
            observableSchema: spec.observableSchema,
            caseIds,
            deterministicSeed: requireString(
                spec.deterministicSeed,
                `${field}.deterministicSeed`,
                { maxLength: 256 },
            ),
            sandboxIdentity: normalizeSuiteSandboxIdentity(
                spec.sandboxIdentity,
                `${field}.sandboxIdentity`,
            ),
            ...(role === "impossibility_verifier"
                ? {
                    independenceAttestation:
                        spec.independenceAttestation,
                    verificationPolicy: spec.verificationPolicy,
                }
                : {}),
        };
        if (role === "impossibility_verifier"
            && spec.independenceAttestation?.kind
                !== HARNESS_SUITE_V4_VERIFIER_INDEPENDENCE_ATTESTATION) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `${field}.independenceAttestation must attest a separate operator implementation`,
            );
        }
        if (role !== "impossibility_verifier"
            && (spec.independenceAttestation !== undefined
                || spec.verificationPolicy !== undefined)) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `${field} cannot declare impossibility-verifier fields`,
            );
        }
    }
    return {
        kind: HARNESS_SUITE_V4_KIND,
        version: 4,
        id,
        environment: rawConfig.environment,
        sharedPlatformDependencies: normalizedShared,
        roles,
    };
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
function resolveOutputAllowlistPath(explicitPath, env) {
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

function resolveOperatorCorpusStorePath(
    explicitPath,
    allowlistPath,
    env,
) {
    const raw = typeof explicitPath === "string"
        && explicitPath.trim().length > 0
        ? explicitPath
        : path.join(path.dirname(allowlistPath), DEFAULT_CASE_STORE_DIRNAME);
    if (!path.isAbsolute(raw)) {
        fail(
            CONFIGURE_ERROR_CODES.CASE_STORE_PATH_INVALID,
            "operator corpus store path must be absolute",
            { path: raw },
        );
    }
    try {
        return assertLocalDatabasePath(raw, { env });
    } catch (err) {
        fail(
            CONFIGURE_ERROR_CODES.CASE_STORE_PATH_INVALID,
            `operator corpus store must be on a trusted local filesystem: ${err?.message ?? String(err)}`,
            { path: raw, cause: err?.code ?? null },
        );
    }
}

// --- existing-allowlist preservation ---------------------------------------

// Strict-parse the existing allowlist (if any) via the real loader and
// re-serialize every entry into on-disk shape. Fails closed if the existing
// file is malformed rather than silently discarding operator entries.
function loadExistingEntries(allowlistPath) {
    if (!fs.existsSync(allowlistPath)) {
        return { entries: {}, suites: {} };
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
    const suites = {};
    for (const id of loaded.listSuiteIds()) {
        suites[id] = loaded.getSuite(id);
    }
    return { entries, suites, loaded };
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
            cases[id] = {
                snapshotHash: spec.snapshotHash,
                ...(spec.expectation === null || spec.expectation === undefined
                    ? {}
                    : { expectation: spec.expectation }),
                ...(spec.description === null || spec.description === undefined
                    ? {}
                    : { description: spec.description }),
            };
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
    return { backupPath };
}

// --- core -----------------------------------------------------------------

function roleConfigFromEntry(entry) {
    return {
        argvTemplate: [...entry.argvTemplate],
        cwd: entry.cwd,
        allowedEnv: { ...entry.allowedEnv },
        timeoutMs: entry.timeoutMs,
        maxStdoutBytes: entry.maxStdoutBytes,
        maxStderrBytes: entry.maxStderrBytes,
        executesCandidateCode: entry.executesCandidateCode,
    };
}

function taggedFileHash(hex) {
    return `${FILE_HASH_ALGORITHM}:${hex}`;
}

function trustedParserIdentity(role) {
    const verifier = role === "impossibility_verifier";
    const parserPath = fileURLToPath(
        new URL(
            verifier
                ? "../measurement/verifier-parser.mjs"
                : "../measurement/parser.mjs",
            import.meta.url,
        ),
    );
    const parserVersion = verifier
        ? VERIFIER_PARSER_VERSION
        : PARSER_VERSION;
    return {
        version: parserVersion,
        versionHash: hashCanonical(
            { parserVersion },
            PARSER_VERSION_HASH_ALGORITHM,
        ),
        sourceHash: sha256File(
            parserPath,
            PARSER_SOURCE_HASH_ALGORITHM,
        ),
    };
}

/**
 * Compose already-pinned allowlist entries into one strict HarnessSuiteV4.
 * Validation bytes remain in the durable operator corpus CAS created while
 * authoring the entries; this operation binds their immutable ids and labels.
 */
function configureHarnessSuite(options = {}) {
    const env = options.env ?? process.env;
    const replace = options.replace === true;
    if (options.config !== undefined && options.configPath !== undefined) {
        fail(CONFIGURE_ERROR_CODES.USAGE, "pass either config or configPath, not both");
    }
    if (options.caseStorePath !== undefined) {
        fail(
            CONFIGURE_ERROR_CODES.USAGE,
            "--case-store is not supported for suite configs",
        );
    }
    const rawConfig = options.config !== undefined
        ? options.config
        : loadConfigFile(options.configPath);
    const config = normalizeSuiteConfig(rawConfig);
    const allowlistPath = resolveOutputAllowlistPath(
        options.allowlistPath,
        env,
    );
    const allowlistDir = path.dirname(allowlistPath);
    fs.mkdirSync(allowlistDir, { recursive: true });
    const existing = loadExistingEntries(allowlistPath);

    const sharedPlatformDependencies =
        config.sharedPlatformDependencies.map((dependency, index) => {
            const verified = verifyAndDigestFile(
                dependency.path,
                `config.sharedPlatformDependencies[${index}].path`,
                CONFIGURE_ERROR_CODES.DEPENDENCY_INVALID,
            );
            return {
                classification: dependency.classification,
                role: dependency.role,
                sha256: taggedFileHash(verified.sha256),
            };
        }).sort((left, right) =>
            `${left.classification}\0${left.role}\0${left.sha256}`.localeCompare(
                `${right.classification}\0${right.role}\0${right.sha256}`,
            ));
    const sharedKeys = new Set(
        sharedPlatformDependencies.map((dependency) =>
            `${dependency.role}\0${dependency.sha256}`),
    );
    const operatorCases = {};
    const roles = {};

    for (const role of HARNESS_SUITE_V4_ROLES) {
        const roleConfig = config.roles[role];
        if (roleConfig === undefined) continue;
        if (!existing.loaded
            || !existing.loaded.listEntryIds().includes(roleConfig.harnessId)) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `config.roles.${role}.harnessId does not name an existing allowlist entry`,
                { harnessId: roleConfig.harnessId },
            );
        }
        const entry = existing.loaded.getEntry(roleConfig.harnessId);
        if (entry.executesCandidateCode
            !== roleConfig.sandboxIdentity.required) {
            fail(
                CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                `config.roles.${role}.sandboxIdentity.required must match executesCandidateCode`,
                {
                    harnessId: roleConfig.harnessId,
                    executesCandidateCode: entry.executesCandidateCode,
                },
            );
        }
        const dependencies = entry.dependencies.map((dependency) => {
            const sha256 = taggedFileHash(dependency.sha256);
            return {
                role: dependency.role,
                sha256,
                kind: sharedKeys.has(`${dependency.role}\0${sha256}`)
                    ? "platform"
                    : "application",
            };
        });
        const caseManifest = roleConfig.caseIds.map((caseId) => {
            const pinned = entry.validationCases?.[caseId];
            if (pinned === undefined) {
                fail(
                    CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                    `config.roles.${role}.caseIds references a case not pinned by harness ${roleConfig.harnessId}`,
                    { caseId },
                );
            }
            if (pinned.expectation !== "accept"
                && pinned.expectation !== "reject") {
                fail(
                    CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                    `case ${caseId} has no operator-owned expectation; re-author the harness entry first`,
                    { harnessId: roleConfig.harnessId, caseId },
                );
            }
            const prior = operatorCases[caseId];
            const next = {
                snapshotHash: pinned.snapshotHash,
                expectation: pinned.expectation,
            };
            if (prior !== undefined
                && (prior.snapshotHash !== next.snapshotHash
                    || prior.expectation !== next.expectation)) {
                fail(
                    CONFIGURE_ERROR_CODES.CONFIG_INVALID,
                    `case ${caseId} has conflicting operator-owned definitions across role entries`,
                );
            }
            operatorCases[caseId] = next;
            return { id: caseId, snapshotHash: pinned.snapshotHash };
        });
        roles[role] = {
            harnessId: roleConfig.harnessId,
            harnessEntryHash: existing.loaded.getEntryHash(
                roleConfig.harnessId,
            ),
            executableHash: taggedFileHash(entry.executableSha256),
            applicationEntrypointHash:
                applicationEntrypointHashForEntry(entry),
            parser: trustedParserIdentity(role),
            dependencies,
            configHash: hashHarnessRoleConfigV4(
                roleConfigFromEntry(entry),
            ),
            observableSchemaHash: hashHarnessObservableSchemaV4(
                roleConfig.observableSchema,
            ),
            caseManifest,
            deterministicSeed: roleConfig.deterministicSeed,
            sandboxIdentity: roleConfig.sandboxIdentity,
            ...(role === "impossibility_verifier"
                ? {
                    independenceAttestation:
                        roleConfig.independenceAttestation,
                    verificationPolicy: roleConfig.verificationPolicy,
                }
                : {}),
        };
    }

    let suite;
    try {
        suite = normalizeHarnessSuiteV4({
            version: 4,
            kind: HARNESS_SUITE_V4_KIND,
            id: config.id,
            environmentIdentity: hashHarnessEnvironmentV4(
                config.environment,
            ),
            sharedPlatformDependencies,
            roles,
            operatorCorpus: {
                version: 1,
                cases: operatorCases,
            },
        });
    } catch (error) {
        fail(
            CONFIGURE_ERROR_CODES.CONFIG_INVALID,
            `assembled HarnessSuiteV4 is invalid: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null, details: error?.details ?? null },
        );
    }
    const suiteIdentity = computeHarnessSuiteV4Identity(suite);
    const replaced = Object.hasOwn(existing.suites, config.id);
    if (replaced) {
        const priorIdentity = existing.loaded.getSuiteIdentity(config.id);
        if (priorIdentity !== suiteIdentity && !replace) {
            fail(
                CONFIGURE_ERROR_CODES.SUITE_CONFLICT,
                `suite '${config.id}' has a different identity; pass --replace to overwrite`,
                {
                    id: config.id,
                    existingIdentity: priorIdentity,
                    newIdentity: suiteIdentity,
                },
            );
        }
    }

    const mergedSuites = {
        ...existing.suites,
        [config.id]: suite,
    };
    const document = {
        version: CONFIGURE_SCHEMA_VERSION,
        entries: sortedEntries(existing.entries),
        suites: sortedEntries(mergedSuites),
    };
    const contentString = `${JSON.stringify(document, null, 2)}\n`;
    const validationTmp = path.join(
        allowlistDir,
        `.harness-suite-validate-${randomBytes(8).toString("hex")}.json`,
    );
    let contentHash;
    try {
        fs.writeFileSync(validationTmp, contentString, { flag: "wx" });
        const loaded = loadHarnessAllowlist(validationTmp);
        if (loaded.getSuiteIdentity(config.id) !== suiteIdentity) {
            fail(
                CONFIGURE_ERROR_CODES.RESULT_INVALID,
                "assembled suite identity changed during allowlist validation",
            );
        }
        contentHash = loaded.contentHash;
    } catch (error) {
        if (error instanceof ConfigureHarnessError) throw error;
        fail(
            CONFIGURE_ERROR_CODES.RESULT_INVALID,
            `assembled suite allowlist failed strict validation: ${error?.message ?? String(error)}`,
            { path: allowlistPath, cause: error?.code ?? null },
        );
    } finally {
        try { fs.rmSync(validationTmp, { force: true }); } catch { /* ignore */ }
    }
    const install = atomicWriteWithBackup(allowlistPath, contentString);
    return Object.freeze({
        schemaVersion: CONFIGURE_SCHEMA_VERSION,
        allowlistPath,
        suiteId: config.id,
        suiteIdentity,
        contentHash,
        replaced,
        replacedByOverride: replaced && replace,
        backupPath: install.backupPath,
        roleHarnessIds: Object.freeze(Object.fromEntries(
            Object.entries(suite.roles).map(([role, spec]) => [
                role,
                spec.harnessId,
            ]),
        )),
        operatorCorpusIdentity: suite.operatorCorpus.identity,
        preservedEntryIds: Object.freeze(
            Object.keys(existing.entries).sort(),
        ),
        preservedSuiteIds: Object.freeze(
            Object.keys(existing.suites)
                .filter((id) => id !== config.id)
                .sort(),
        ),
    });
}

/**
 * Pure(ish) configuration entry point. Performs all validation, hashing,
 * durable corpus ingestion and the atomic allowlist install, returning a plain
 * result object. Throws ConfigureHarnessError (with a stable `code`) on any
 * failure.
 *
 * options:
 *   config        - a parsed config object (mutually exclusive with configPath)
 *   configPath    - path to a strict JSON config file
 *   allowlistPath - explicit output allowlist path (optional)
 *   caseStorePath - durable operator corpus CAS root (optional)
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
    if (isSuiteAuthoringConfig(rawConfig)) {
        return configureHarnessSuite({
            ...options,
            config: rawConfig,
            configPath: undefined,
        });
    }
    const config = normalizeConfig(rawConfig);

    const allowlistPath = resolveOutputAllowlistPath(options.allowlistPath, env);
    const allowlistDir = path.dirname(allowlistPath);
    const operatorCorpusStorePath = resolveOperatorCorpusStorePath(
        options.caseStorePath,
        allowlistPath,
        env,
    );
    fs.mkdirSync(allowlistDir, { recursive: true });

    // Verify + hash the executable and each declared dependency.
    const executable = verifyAndDigestFile(config.executable, "config.executable", CONFIGURE_ERROR_CODES.EXECUTABLE_INVALID);
    const dependencies = config.dependencies.map((dep, index) => {
        const verified = verifyAndDigestFile(dep.path, `config.dependencies[${index}].path`, CONFIGURE_ERROR_CODES.DEPENDENCY_INVALID);
        return { path: verified.resolvedPath, sha256: verified.sha256, role: dep.role };
    });

    // Ingest into the durable operator-owned CAS. The allowlist pins immutable
    // snapshot identities; the CAS retains their bytes for later verification.
    const validationCaseSnapshots = {};
    let entryHash = null;
    let contentHash = null;
    let install = null;
    const store = openArtifactStore({
        root: operatorCorpusStorePath,
        env,
    });
    {
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
                expectation: validationCase.expectation,
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
            const priorCases = serializeValidationCaseBlock(
                prior.validationCases,
            );
            const nextCases = buildValidationCaseBlock(
                validationCaseSnapshots,
            );
            if (JSON.stringify(priorCases) !== JSON.stringify(nextCases)
                && !replace) {
                fail(
                    CONFIGURE_ERROR_CODES.ENTRY_CONFLICT,
                    `entry '${config.id}' has a different immutable validation corpus; pass --replace to overwrite`,
                    { id: config.id },
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
        const document = {
            version: CONFIGURE_SCHEMA_VERSION,
            entries: sortedEntries(mergedEntries),
            ...(Object.keys(existing.suites).length === 0
                ? {}
                : { suites: sortedEntries(existing.suites) }),
        };
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
            operatorCorpusStorePath: store.root,
            replaced,
            replacedByOverride: replaced && replace,
            backupPath: install.backupPath,
            preservedEntryIds: Object.freeze(Object.keys(existing.entries).filter((id) => id !== config.id).sort()),
            preservedSuiteIds: Object.freeze(Object.keys(existing.suites).sort()),
        });
    }
}

function buildValidationCaseBlock(snapshots) {
    const out = {};
    for (const id of Object.keys(snapshots).sort()) {
        const spec = snapshots[id];
        out[id] = {
            snapshotHash: spec.snapshotHash,
            expectation: spec.expectation,
            ...(spec.description === undefined
                ? {}
                : { description: spec.description }),
        };
    }
    return out;
}

function serializeValidationCaseBlock(validationCases) {
    if (validationCases === null || validationCases === undefined) return null;
    const out = {};
    for (const id of Object.keys(validationCases).sort()) {
        const spec = validationCases[id];
        out[id] = {
            snapshotHash: spec.snapshotHash,
            ...(spec.expectation === null || spec.expectation === undefined
                ? {}
                : { expectation: spec.expectation }),
            ...(spec.description === null || spec.description === undefined
                ? {}
                : { description: spec.description }),
        };
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

function parseArgs(argv) {
    const out = {
        config: undefined,
        allowlist: undefined,
        caseStore: undefined,
        replace: false,
        help: false,
    };
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
        } else if (arg === "--case-store") {
            out.caseStore = argv[i + 1];
            i += 1;
        } else if (arg.startsWith("--case-store=")) {
            out.caseStore = arg.slice("--case-store=".length);
        } else {
            fail(CONFIGURE_ERROR_CODES.USAGE, `unknown argument ${JSON.stringify(arg)}`);
        }
    }
    return out;
}

const USAGE = `Usage: node tools/configure-harness.mjs --config <path> [--allowlist <path>] [--case-store <path>] [--replace]

Creates or updates a Crucible operator harness entry or composes existing
entries into a HarnessSuiteV4. Validation snapshots are retained in a durable
operator-owned content-addressed store.

Options:
  --config <path>     Strict JSON harness config (required).
  --allowlist <path>  Output allowlist path (default %LOCALAPPDATA%\\Crucible\\harnesses.json).
  --case-store <path> Durable validation-case CAS (default beside the allowlist).
  --replace           Allow replacing changed executable/corpus/suite identity.
  -h, --help          Show this help.`;

function main(argv = process.argv.slice(2), { env = process.env, stdout = process.stdout, stderr = process.stderr } = {}) {
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
            caseStorePath: args.caseStore,
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
            code: err?.code ?? "CRUCIBLE_CONFIGURE_UNKNOWN",
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
