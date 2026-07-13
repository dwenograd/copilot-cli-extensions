import fs from "node:fs";
import path from "node:path";

import {
    DEFAULT_SEARCH_POLICY,
    canonicalEqual,
    canonicalJson,
    contractHash,
    createInvestigationContract,
    experimentAuthorityManifestIdentity,
    hashCanonical,
    immutableCanonical,
    normalizeEnumerandManifest,
    resolveControlEnumerand,
} from "../domain/index.mjs";
import {
    MEASUREMENT_ERROR_CODES,
    loadHarnessAllowlist,
    sha256Bytes,
    verifyAndHashFile,
    verifyLocalRegularFile,
} from "../measurement/index.mjs";
import { assertLocalDatabasePath } from "../persistence/index.mjs";
import {
    CRITICALITY,
    POLICY_VERSION,
    canonicalObjective,
    resolveAllowlistPath,
} from "./environment.mjs";
import { operatorExperimentConfigSpec } from "./schema.mjs";
import {
    EXPERIMENT_AUTHORITY_ERROR_CODES,
    ExperimentAuthorityError,
    buildExperimentAuthorityManifest,
    createExperimentAuthorityEnvelope,
    loadDetachedExperimentSignature,
    readVerifiedExperimentAuthority,
    resolveExperimentTrust,
    verifyExperimentAuthority,
} from "./experiment-authority.mjs";

export const EXPERIMENT_REGISTRY_VERSION = 2;
export const EXPERIMENT_ENTRY_VERSION = 5;
export const EXPERIMENT_ENTRY_IDENTITY_ALGORITHM =
    "sha256:crucible-operator-experiment-v5";
export const EXPERIMENT_REGISTRY_IDENTITY_ALGORITHM =
    "sha256:crucible-operator-experiment-registry-v2";
export const EXPERIMENT_REGISTRY_FILE_HASH_ALGORITHM =
    "sha256:crucible-operator-experiment-registry-file-v1";
export const EXPERIMENT_REGISTRY_ENV = "CRUCIBLE_EXPERIMENT_REGISTRY_PATH";

const DEFAULT_ROOT_DIRNAME = "Crucible";
const DEFAULT_REGISTRY_FILENAME = "experiments.json";
const MAX_REGISTRY_BYTES = 4 * 1024 * 1024;
const MAX_CONFIG_BYTES = 1024 * 1024;
const SAFE_EXPERIMENT_ID = /^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$/u;
const ENTRY_KEYS = new Set([
    "authority",
    "contract",
    "contractHash",
    "experimentId",
    "experimentIdentity",
    "harnessSuiteId",
    "harnessSuiteIdentity",
    "investigationId",
    "projectDir",
    "version",
]);
const REGISTRY_KEYS = new Set(["experiments", "identity", "version"]);

export const EXPERIMENT_REGISTRY_ERROR_CODES = Object.freeze({
    USAGE: "CRUCIBLE_EXPERIMENT_USAGE",
    CONFIG_NOT_FOUND: "CRUCIBLE_EXPERIMENT_CONFIG_NOT_FOUND",
    CONFIG_TOO_LARGE: "CRUCIBLE_EXPERIMENT_CONFIG_TOO_LARGE",
    CONFIG_INVALID_JSON: "CRUCIBLE_EXPERIMENT_CONFIG_INVALID_JSON",
    CONFIG_INVALID: "CRUCIBLE_EXPERIMENT_CONFIG_INVALID",
    REGISTRY_PATH_INVALID: "CRUCIBLE_EXPERIMENT_REGISTRY_PATH_INVALID",
    REGISTRY_NOT_FOUND: "CRUCIBLE_EXPERIMENT_REGISTRY_NOT_FOUND",
    REGISTRY_INVALID: "CRUCIBLE_EXPERIMENT_REGISTRY_INVALID",
    REGISTRY_TAMPERED: "CRUCIBLE_EXPERIMENT_REGISTRY_TAMPERED",
    EXPERIMENT_NOT_FOUND: "CRUCIBLE_EXPERIMENT_NOT_FOUND",
    EXPERIMENT_CONFLICT: "CRUCIBLE_EXPERIMENT_CONFLICT",
    HARNESS_INVALID: "CRUCIBLE_EXPERIMENT_HARNESS_INVALID",
    PROJECT_INVALID: "CRUCIBLE_EXPERIMENT_PROJECT_INVALID",
    WRITE_FAILED: "CRUCIBLE_EXPERIMENT_WRITE_FAILED",
    AUTHORITY_REQUIRED: EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_REQUIRED,
    AUTHORITY_INVALID: EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
    TRUST_NOT_CONFIGURED:
        EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_NOT_CONFIGURED,
    TRUST_CONFIGURATION_INVALID:
        EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
    TRUST_FINGERPRINT_MISMATCH:
        EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_FINGERPRINT_MISMATCH,
    SIGNATURE_INVALID: EXPERIMENT_AUTHORITY_ERROR_CODES.SIGNATURE_INVALID,
});

export class ExperimentRegistryError extends Error {
    constructor(code, message, details = null, options = {}) {
        super(message, options);
        this.name = "ExperimentRegistryError";
        this.code = code;
        if (details !== null && details !== undefined) {
            this.details = details;
        }
    }
}

function fail(code, message, details = null, options = {}) {
    throw new ExperimentRegistryError(code, message, details, options);
}

function rethrowAuthority(error, context) {
    if (!(error instanceof ExperimentAuthorityError)) throw error;
    fail(
        error.code,
        `${context}: ${error.message}`,
        error.details ?? null,
        { cause: error },
    );
}

function isPlainObject(value) {
    return value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        && (Object.getPrototypeOf(value) === Object.prototype
            || Object.getPrototypeOf(value) === null);
}

function requirePlainObject(value, field) {
    if (!isPlainObject(value)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `${field} must be a plain object`,
            { field },
        );
    }
    return value;
}

function rejectUnknownKeys(value, allowed, field) {
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(
                EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
                `${field} has unknown key ${JSON.stringify(key)}`,
                { field, key },
            );
        }
    }
}

function requireSafeExperimentId(value, field = "experimentId") {
    if (typeof value !== "string" || !SAFE_EXPERIMENT_ID.test(value)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `${field} must be a safe lowercase experiment id`,
            { field, value },
        );
    }
    return value;
}

function requireTaggedHash(value, field) {
    if (typeof value !== "string"
        || !/^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u.test(value)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `${field} must be an algorithm-tagged SHA-256 identity`,
            { field, value },
        );
    }
    return value;
}

function requireAbsolutePath(value, field) {
    if (typeof value !== "string" || !path.isAbsolute(value)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `${field} must be an absolute path`,
            { field, value },
        );
    }
    return path.resolve(value);
}

function localAppData(env) {
    const value = env?.LOCALAPPDATA;
    if (typeof value !== "string" || value.trim().length === 0) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_PATH_INVALID,
            `LOCALAPPDATA is not set; set ${EXPERIMENT_REGISTRY_ENV} explicitly`,
            { variable: "LOCALAPPDATA" },
        );
    }
    return value;
}

export function resolveExperimentRegistryPath(explicitPath, env = process.env) {
    const raw = typeof explicitPath === "string" && explicitPath.trim().length > 0
        ? explicitPath
        : typeof env?.[EXPERIMENT_REGISTRY_ENV] === "string"
                && env[EXPERIMENT_REGISTRY_ENV].trim().length > 0
            ? env[EXPERIMENT_REGISTRY_ENV]
            : path.join(localAppData(env), DEFAULT_ROOT_DIRNAME, DEFAULT_REGISTRY_FILENAME);
    if (!path.isAbsolute(raw)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_PATH_INVALID,
            "experiment registry path must be absolute",
            { path: raw },
        );
    }
    try {
        return assertLocalDatabasePath(raw, { env });
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_PATH_INVALID,
            `experiment registry must be on a trusted local filesystem: ${
                error?.message ?? String(error)
            }`,
            { path: raw, cause: error?.code ?? null },
            { cause: error },
        );
    }
}

export function resolveExperimentAllowlistPath(explicitPath, env = process.env) {
    if (typeof explicitPath !== "string" || explicitPath.trim().length === 0) {
        return resolveAllowlistPath(env);
    }
    if (!path.isAbsolute(explicitPath)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.HARNESS_INVALID,
            "harness allowlist path must be absolute",
            { path: explicitPath },
        );
    }
    try {
        return assertLocalDatabasePath(explicitPath, { env });
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.HARNESS_INVALID,
            `harness allowlist must be on a trusted local filesystem: ${
                error?.message ?? String(error)
            }`,
            { path: explicitPath, cause: error?.code ?? null },
            { cause: error },
        );
    }
}

export function resolveExperimentProjectDir(projectDir, env = process.env) {
    if (typeof projectDir !== "string" || !path.isAbsolute(projectDir)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.PROJECT_INVALID,
            "project_dir must be an absolute path",
            { projectDir },
        );
    }
    let local;
    try {
        local = assertLocalDatabasePath(projectDir, { env });
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.PROJECT_INVALID,
            `project_dir must be on a trusted local filesystem: ${
                error?.message ?? String(error)
            }`,
            { projectDir, cause: error?.code ?? null },
            { cause: error },
        );
    }
    let real;
    try {
        real = fs.realpathSync.native(local);
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.PROJECT_INVALID,
            "project_dir does not exist",
            { projectDir, cause: error?.code ?? null },
            { cause: error },
        );
    }
    if (!fs.statSync(real).isDirectory()) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.PROJECT_INVALID,
            "project_dir must be a directory",
            { projectDir },
        );
    }
    return real;
}

function normalizeAuthoringManifest(config) {
    if (config.enumerand_manifest === undefined) return null;
    const raw = config.enumerand_manifest;
    return normalizeEnumerandManifest({
        topology: raw.topology,
        entries: raw.entries,
        control: raw.control.kind === "snapshot"
            ? {
                kind: "reference",
                referenceHash: raw.control.snapshotHash,
            }
            : raw.control,
    }, {
        topology: raw.topology,
        observableRegistry: config.observable_registry,
        hypothesisPolicy: config.hypothesis_policy,
    });
}

function statisticalPolicyInput(config, enumerandManifest) {
    const policy = config.statistical_policy;
    if (policy.control.kind !== "enumerand") {
        return policy;
    }
    const resolved = resolveControlEnumerand(enumerandManifest, {
        topology: config.hypothesis_topology,
        observableRegistry: config.observable_registry,
        hypothesisPolicy: config.hypothesis_policy,
    });
    if (resolved.kind === "reference") {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_INVALID,
            "statistical enumerand control does not match the manifest control",
        );
    }
    return {
        ...policy,
        control: {
            ...policy.control,
            identity: resolved.enumerandHash,
        },
    };
}

function experimentEntryCore(entry) {
    return {
        version: entry.version,
        experimentId: entry.experimentId,
        projectDir: entry.projectDir,
        harnessSuiteId: entry.harnessSuiteId,
        harnessSuiteIdentity: entry.harnessSuiteIdentity,
        contractHash: entry.contractHash,
        investigationId: entry.investigationId,
        contract: entry.contract,
        authority: entry.authority,
    };
}

export function experimentEntryIdentity(entry) {
    return hashCanonical(
        experimentEntryCore(entry),
        EXPERIMENT_ENTRY_IDENTITY_ALGORITHM,
    );
}

function prepareExperimentCore(rawConfig, options = {}) {
    let config;
    try {
        config = operatorExperimentConfigSpec.parse(rawConfig);
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_INVALID,
            `experiment configuration is invalid: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null, details: error?.details ?? null },
            { cause: error },
        );
    }
    const env = options.env ?? process.env;
    const projectDir = resolveExperimentProjectDir(config.project_dir, env);
    const allowlist = options.allowlist
        ?? loadHarnessAllowlist(resolveExperimentAllowlistPath(options.allowlistPath, env));
    if (!allowlist.listSuiteIds().includes(config.harness_suite_id)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.HARNESS_INVALID,
            `harness suite '${config.harness_suite_id}' is not allowlisted`,
            {
                harnessSuiteId: config.harness_suite_id,
                allowlistPath: allowlist.allowlistPath,
            },
        );
    }
    const harnessSuite = allowlist.getSuite(config.harness_suite_id);
    const harnessSuiteIdentity = allowlist.getSuiteIdentity(config.harness_suite_id);
    if (config.harness_suite_identity !== undefined
        && config.harness_suite_identity !== harnessSuiteIdentity) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.HARNESS_INVALID,
            "configured HarnessSuiteV4 identity does not match the operator allowlist",
            {
                harnessSuiteId: config.harness_suite_id,
                expected: config.harness_suite_identity,
                actual: harnessSuiteIdentity,
            },
        );
    }
    const enumerandManifest = normalizeAuthoringManifest(config);
    let contract;
    try {
        contract = createInvestigationContract({
            objective: canonicalObjective(config.objective),
            acceptancePredicate: config.acceptance_predicate,
            harnessSuite,
            harnessSuiteIdentity,
            hypothesisTopology: config.hypothesis_topology,
            criticality: CRITICALITY,
            policyVersion: POLICY_VERSION,
            workerModels: config.worker_models,
            candidatesPerRound: config.candidates_per_round,
            maxRounds: config.max_rounds,
            searchPolicy: config.search_policy ?? DEFAULT_SEARCH_POLICY,
            ...(enumerandManifest === null ? {} : { enumerandManifest }),
            observableRegistry: config.observable_registry,
            hypothesisPolicy: config.hypothesis_policy,
            statisticalPolicy: statisticalPolicyInput(config, enumerandManifest),
        });
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_INVALID,
            `experiment contract validation failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null, details: error?.details ?? null },
            { cause: error },
        );
    }
    const digest = contractHash(contract);
    let trust;
    try {
        trust = resolveExperimentTrust(env);
    } catch (error) {
        rethrowAuthority(error, "experiment trust resolution failed");
    }
    const manifest = buildExperimentAuthorityManifest({
        experimentId: config.experiment_id,
        projectDir,
        harnessSuiteId: config.harness_suite_id,
        contract,
        trustFingerprint: trust.fingerprint,
    });
    return Object.freeze({
        config,
        experimentId: config.experiment_id,
        projectDir,
        harnessSuiteId: config.harness_suite_id,
        harnessSuiteIdentity,
        contractHash: digest,
        contract,
        investigationId: manifest.investigationId,
        manifest,
        manifestIdentity: experimentAuthorityManifestIdentity(manifest),
        canonicalManifest: canonicalJson(manifest),
    });
}

export function prepareExperimentManifest(rawConfig, options = {}) {
    const prepared = prepareExperimentCore(rawConfig, options);
    return Object.freeze({
        experimentId: prepared.experimentId,
        projectDir: prepared.projectDir,
        harnessSuiteId: prepared.harnessSuiteId,
        harnessSuiteIdentity: prepared.harnessSuiteIdentity,
        contractHash: prepared.contractHash,
        enumerandRoot: prepared.manifest.enumerandRoot,
        statisticalPolicyIdentity:
            prepared.manifest.statisticalPolicyIdentity,
        hypothesisPolicyIdentity:
            prepared.manifest.hypothesisPolicyIdentity,
        investigationId: prepared.investigationId,
        trustFingerprint: prepared.manifest.trustFingerprint,
        manifest: prepared.manifest,
        manifestIdentity: prepared.manifestIdentity,
        canonicalManifest: prepared.canonicalManifest,
    });
}

export function createExperimentEntry(rawConfig, options = {}) {
    const prepared = prepareExperimentCore(rawConfig, options);
    let signature = options.signature;
    if (signature === undefined && options.signaturePath !== undefined) {
        try {
            signature = loadDetachedExperimentSignature(options.signaturePath);
        } catch (error) {
            rethrowAuthority(error, "detached experiment signature is invalid");
        }
    }
    if (signature === undefined) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.AUTHORITY_REQUIRED,
            "a detached Ed25519 signature is required before an experiment can be installed",
        );
    }
    let trust;
    let authority;
    try {
        trust = resolveExperimentTrust(options.env ?? process.env);
        const envelope = createExperimentAuthorityEnvelope({
            manifest: prepared.manifest,
            signature: signature?.bytes ?? signature,
            trustFingerprint: trust.fingerprint,
        });
        const capability = verifyExperimentAuthority({
            authority: envelope,
            experimentId: prepared.experimentId,
            projectDir: prepared.projectDir,
            harnessSuiteId: prepared.harnessSuiteId,
            contract: prepared.contract,
            investigationId: prepared.investigationId,
            env: options.env ?? process.env,
        });
        authority = readVerifiedExperimentAuthority(capability).authority;
    } catch (error) {
        rethrowAuthority(error, "experiment authority verification failed");
    }
    const investigationId = prepared.investigationId;
    const core = {
        version: EXPERIMENT_ENTRY_VERSION,
        experimentId: prepared.experimentId,
        projectDir: prepared.projectDir,
        harnessSuiteId: prepared.harnessSuiteId,
        harnessSuiteIdentity: prepared.harnessSuiteIdentity,
        contractHash: prepared.contractHash,
        investigationId,
        contract: prepared.contract,
        authority,
    };
    return immutableCanonical({
        ...core,
        experimentIdentity: experimentEntryIdentity(core),
    });
}

function normalizeRegistryEntry(value, key, options = {}) {
    requirePlainObject(value, `experiments.${key}`);
    rejectUnknownKeys(value, ENTRY_KEYS, `experiments.${key}`);
    if (value.version !== EXPERIMENT_ENTRY_VERSION) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `experiments.${key}.version must be ${EXPERIMENT_ENTRY_VERSION}`,
        );
    }
    const experimentId = requireSafeExperimentId(
        value.experimentId,
        `experiments.${key}.experimentId`,
    );
    if (key !== experimentId) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `experiments.${key} key does not match experimentId`,
        );
    }
    const projectDir = requireAbsolutePath(
        value.projectDir,
        `experiments.${key}.projectDir`,
    );
    const harnessSuiteId = requireSafeExperimentId(
        value.harnessSuiteId,
        `experiments.${key}.harnessSuiteId`,
    );
    const harnessSuiteIdentity = requireTaggedHash(
        value.harnessSuiteIdentity,
        `experiments.${key}.harnessSuiteIdentity`,
    );
    let contract;
    try {
        contract = createInvestigationContract(value.contract);
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `experiments.${key}.contract is invalid: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
    if (!canonicalEqual(contract, value.contract)
        || contract.harnessSuite.id !== harnessSuiteId
        || contract.harnessSuiteIdentity !== harnessSuiteIdentity) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
            `experiments.${key} contract/suite identity is inconsistent`,
        );
    }
    const digest = contractHash(contract);
    if (value.contractHash !== digest) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
            `experiments.${key}.contractHash does not match its canonical contract`,
            { expected: digest, actual: value.contractHash ?? null },
        );
    }
    let authority;
    try {
        const capability = verifyExperimentAuthority({
            authority: value.authority,
            experimentId,
            projectDir,
            harnessSuiteId,
            contract,
            investigationId: value.investigationId,
            env: options.env ?? process.env,
        });
        authority = readVerifiedExperimentAuthority(capability).authority;
    } catch (error) {
        rethrowAuthority(
            error,
            `experiments.${key}.authority failed detached signature verification`,
        );
    }
    const investigationId = authority.manifest.investigationId;
    if (value.investigationId !== investigationId) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
            `experiments.${key}.investigationId does not match its frozen specification`,
            { expected: investigationId, actual: value.investigationId ?? null },
        );
    }
    const core = {
        version: EXPERIMENT_ENTRY_VERSION,
        experimentId,
        projectDir,
        harnessSuiteId,
        harnessSuiteIdentity,
        contractHash: digest,
        investigationId,
        contract,
        authority,
    };
    const identity = experimentEntryIdentity(core);
    if (value.experimentIdentity !== identity) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
            `experiments.${key}.experimentIdentity does not match its canonical entry`,
            { expected: identity, actual: value.experimentIdentity ?? null },
        );
    }
    return immutableCanonical({
        ...core,
        experimentIdentity: identity,
    });
}

function registryCore(experiments) {
    return {
        version: EXPERIMENT_REGISTRY_VERSION,
        experiments,
    };
}

export function experimentRegistryIdentity(experiments) {
    return hashCanonical(
        registryCore(experiments),
        EXPERIMENT_REGISTRY_IDENTITY_ALGORITHM,
    );
}

export function createExperimentRegistryDocument(experiments = {}, options = {}) {
    requirePlainObject(experiments, "experiments");
    const normalized = {};
    for (const key of Object.keys(experiments).sort()) {
        requireSafeExperimentId(key, `experiments key ${JSON.stringify(key)}`);
        normalized[key] = normalizeRegistryEntry(experiments[key], key, options);
    }
    const frozenExperiments = immutableCanonical(normalized);
    return immutableCanonical({
        ...registryCore(frozenExperiments),
        identity: experimentRegistryIdentity(frozenExperiments),
    });
}

export function normalizeExperimentRegistryDocument(value, options = {}) {
    requirePlainObject(value, "experiment registry");
    rejectUnknownKeys(value, REGISTRY_KEYS, "experiment registry");
    if (value.version !== EXPERIMENT_REGISTRY_VERSION) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `experiment registry version must be ${EXPERIMENT_REGISTRY_VERSION}`,
            { actual: value.version ?? null },
        );
    }
    const normalized = createExperimentRegistryDocument(
        value.experiments,
        options,
    );
    if (value.identity !== normalized.identity) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
            "experiment registry identity does not match its canonical entries",
            { expected: normalized.identity, actual: value.identity ?? null },
        );
    }
    return normalized;
}

function readJsonFile(filePath, maximumBytes, codes) {
    let bytes;
    try {
        bytes = fs.readFileSync(filePath);
    } catch (error) {
        fail(
            codes.notFound,
            `failed to read ${codes.label}: ${error?.message ?? String(error)}`,
            { path: filePath, cause: error?.code ?? null },
            { cause: error },
        );
    }
    if (bytes.length > maximumBytes) {
        fail(
            codes.tooLarge,
            `${codes.label} exceeds ${maximumBytes} bytes`,
            { path: filePath, bytes: bytes.length },
        );
    }
    let parsed;
    try {
        parsed = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
        fail(
            codes.invalidJson,
            `${codes.label} is not valid JSON: ${error?.message ?? String(error)}`,
            { path: filePath },
            { cause: error },
        );
    }
    return { bytes, parsed };
}

export function loadExperimentConfig(configPath) {
    if (typeof configPath !== "string" || configPath.trim().length === 0) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
            "--config <path> is required",
        );
    }
    if (!path.isAbsolute(configPath)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_NOT_FOUND,
            "experiment config path must be absolute",
            { path: configPath },
        );
    }
    const { parsed } = readJsonFile(configPath, MAX_CONFIG_BYTES, {
        label: "experiment config",
        notFound: EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_NOT_FOUND,
        tooLarge: EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_TOO_LARGE,
        invalidJson: EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_INVALID_JSON,
    });
    return parsed;
}

export function loadExperimentRegistry(registryPath, options = {}) {
    let resolved;
    try {
        resolved = verifyLocalRegularFile(registryPath, {
            label: "experiment registry",
        });
    } catch (error) {
        fail(
            error?.code === MEASUREMENT_ERROR_CODES.FILE_NOT_FOUND
                ? EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_NOT_FOUND
                : EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            `experiment registry is not a trusted local regular file: ${
                error?.message ?? String(error)
            }`,
            { path: registryPath, cause: error?.code ?? null },
            { cause: error },
        );
    }
    const { bytes, parsed } = readJsonFile(resolved, MAX_REGISTRY_BYTES, {
        label: "experiment registry",
        notFound: EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_NOT_FOUND,
        tooLarge: EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
        invalidJson: EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
    });
    const document = normalizeExperimentRegistryDocument(parsed, {
        env: options.env ?? process.env,
    });
    const fileHash = sha256Bytes(bytes, EXPERIMENT_REGISTRY_FILE_HASH_ALGORITHM);
    try {
        verifyAndHashFile(resolved, fileHash, {
            label: "experiment registry",
            algorithm: EXPERIMENT_REGISTRY_FILE_HASH_ALGORITHM,
        });
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
            `experiment registry changed while it was being verified: ${
                error?.message ?? String(error)
            }`,
            { path: resolved, cause: error?.code ?? null },
            { cause: error },
        );
    }
    const state = Object.freeze({
        path: resolved,
        fileHash,
        identity: document.identity,
        experiments: document.experiments,
        selectedExperimentId: options.experimentId ?? null,
    });
    const registry = Object.freeze({
        version: EXPERIMENT_REGISTRY_VERSION,
        registryPath: state.path,
        registryFileHash: state.fileHash,
        registryIdentity: state.identity,
        listExperimentIds: () => Object.keys(state.experiments),
        getExperiment(experimentId) {
            if (typeof experimentId !== "string"
                || !Object.hasOwn(state.experiments, experimentId)) {
                fail(
                    EXPERIMENT_REGISTRY_ERROR_CODES.EXPERIMENT_NOT_FOUND,
                    `no preapproved experiment ${JSON.stringify(experimentId)}`,
                    {
                        experimentId,
                        registryPath: state.path,
                    },
                );
            }
            return state.experiments[experimentId];
        },
        verification: Object.freeze({
            registryPath: state.path,
            registryFileHash: state.fileHash,
            registryIdentity: state.identity,
            selectedExperimentId: state.selectedExperimentId,
            selectedExperimentIdentity: state.selectedExperimentId === null
                ? null
                : state.experiments[state.selectedExperimentId]
                    ?.experimentIdentity ?? null,
            selectedAuthorityIdentity: state.selectedExperimentId === null
                ? null
                : state.experiments[state.selectedExperimentId]
                    ?.authority?.identity ?? null,
        }),
        reverifyFile(env = options.env ?? process.env) {
            return reverifyExperimentRegistryFile(this.verification, { env });
        },
    });
    if (options.experimentId !== undefined) {
        registry.getExperiment(options.experimentId);
    }
    return registry;
}

export function reverifyExperimentRegistryFile(verification, options = {}) {
    if (!isPlainObject(verification)
        || typeof verification.registryPath !== "string"
        || typeof verification.registryFileHash !== "string"
        || typeof verification.registryIdentity !== "string"
        || (verification.selectedExperimentId !== null
            && typeof verification.selectedExperimentId !== "string")
        || (verification.selectedExperimentIdentity !== null
            && typeof verification.selectedExperimentIdentity !== "string")
        || (verification.selectedAuthorityIdentity !== null
            && typeof verification.selectedAuthorityIdentity !== "string")) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
            "experiment registry re-verification requires a complete frozen identity",
        );
    }
    let result;
    try {
        const loaded = loadExperimentRegistry(verification.registryPath, {
                env: options.env ?? process.env,
                ...(verification.selectedExperimentId === null
                    ? {}
                    : { experimentId: verification.selectedExperimentId }),
        });
        if (loaded.registryFileHash !== verification.registryFileHash
                || loaded.registryIdentity !== verification.registryIdentity) {
                fail(
                    EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
                    "experiment registry no longer matches its preflight identity",
                    {
                        expectedFileHash: verification.registryFileHash,
                        actualFileHash: loaded.registryFileHash,
                        expectedIdentity: verification.registryIdentity,
                        actualIdentity: loaded.registryIdentity,
                    },
                );
        }
        if (verification.selectedExperimentId !== null) {
                const selected = loaded.getExperiment(
                    verification.selectedExperimentId,
                );
                if (selected.experimentIdentity
                        !== verification.selectedExperimentIdentity
                    || selected.authority.identity
                        !== verification.selectedAuthorityIdentity) {
                    fail(
                        EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
                        "selected experiment authority changed after preflight",
                        {
                            experimentId: verification.selectedExperimentId,
                        },
                    );
                }
        }
        result = loaded;
    } catch (error) {
        if (error instanceof ExperimentRegistryError
                && error.code === EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED) {
                throw error;
        }
        fail(
                error instanceof ExperimentRegistryError
                    ? error.code
                    : EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
                `experiment registry no longer matches the preflight identity: ${
                error?.message ?? String(error)
            }`,
            {
                path: verification.registryPath,
                cause: error?.code ?? null,
            },
            { cause: error },
        );
    }
    return Object.freeze({
        registryPath: result.registryPath,
        registryFileHash: result.registryFileHash,
        registryIdentity: verification.registryIdentity,
        selectedExperimentId: verification.selectedExperimentId,
        selectedExperimentIdentity: verification.selectedExperimentIdentity,
        selectedAuthorityIdentity: verification.selectedAuthorityIdentity,
    });
}

export function serializeExperimentRegistryDocument(document, options = {}) {
    const normalized = normalizeExperimentRegistryDocument(document, options);
    return `${JSON.stringify(normalized, null, 2)}\n`;
}
