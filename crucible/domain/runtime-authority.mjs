import {
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import { ContractError } from "./errors.mjs";

export const RUNTIME_CONFIG_AUTHORITY_VERSION = 2;
export const RUNTIME_CONFIG_AUTHORITY_KIND =
    "CrucibleRuntimeConfigAuthority";
export const RUNTIME_CONFIG_AUTHORITY_FINGERPRINT_ALGORITHM =
    "sha256:crucible-runtime-config-authority-v2";

export const RUNTIME_IDENTITY_POLICY_VERSION = 1;
export const RUNTIME_IDENTITY_POLICY_KIND = "CrucibleRuntimeIdentityPolicy";
export const RUNTIME_IDENTITY_POLICY_HASH_ALGORITHM =
    "sha256:crucible-runtime-identity-policy-v1";
export const RUNTIME_IDENTITY_VERSION = 1;
export const RUNTIME_IDENTITY_KIND = "CrucibleRuntimeIdentity";
export const RUNTIME_IDENTITY_ROOT_ALGORITHM =
    "sha256:crucible-runtime-identity-root-v1";
export const RUNTIME_IDENTITY_FILE_HASH_ALGORITHM =
    "sha256:crucible-runtime-file-content-v1";
export const RUNTIME_IDENTITY_FILE_IDENTITY_ALGORITHM =
    "sha256:crucible-runtime-file-identity-v1";
export const RUNTIME_IDENTITY_TREE_MERKLE_ALGORITHM =
    "sha256:crucible-runtime-tree-merkle-v1";
export const RUNTIME_IDENTITY_TREE_IDENTITY_ALGORITHM =
    "sha256:crucible-runtime-tree-identity-v1";
export const RUNTIME_IDENTITY_CLI_IDENTITY_ALGORITHM =
    "sha256:crucible-runtime-cli-identity-v1";
export const RUNTIME_IDENTITY_SANDBOX_IDENTITY_ALGORITHM =
    "sha256:crucible-runtime-sandbox-identity-v1";
export const RUNTIME_IDENTITY_COMMANDS_IDENTITY_ALGORITHM =
    "sha256:crucible-runtime-command-templates-v1";
export const RUNTIME_IDENTITY_ENVIRONMENT_IDENTITY_ALGORITHM =
    "sha256:crucible-runtime-environment-v1";
export const RUNTIME_IDENTITY_ASSUMPTIONS_HASH_ALGORITHM =
    "sha256:crucible-runtime-assumptions-v1";

const TAGGED_SHA256 =
    /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const ENVIRONMENT_KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;
const EXTENSION = /^\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/u;
const POLICY_KEYS = Object.freeze([
    "environmentKeys",
    "kind",
    "limits",
    "treeRules",
    "version",
]);
const POLICY_LIMIT_KEYS = Object.freeze([
    "maxDepth",
    "maxFileBytes",
    "maxFiles",
    "maxTemplateBytes",
    "maxTotalBytes",
]);
const TREE_RULE_KEYS = Object.freeze([
    "excludedBasenames",
    "excludedSegments",
    "excludedSuffixes",
    "includedExtensions",
]);
const TREE_RULE_NAMES = Object.freeze([
    "copilotCliPackage",
    "copilotSdkPackage",
    "crucibleSource",
]);
const AUTHORITY_KEYS = Object.freeze([
    "fingerprint",
    "identities",
    "kind",
    "runtimeIdentity",
    "sandbox",
    "securityConfig",
    "version",
    "workerAdditionalContextHash",
]);

function fail(message, details = null) {
    throw new ContractError(message, details);
}

function requirePlainObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)) {
        fail(`${field} must be a plain object`, { field });
    }
    return value;
}

function requireExactKeys(value, field, expectedKeys) {
    requirePlainObject(value, field);
    const expected = new Set(expectedKeys);
    const missing = expectedKeys.filter((key) => !Object.hasOwn(value, key));
    const unknown = Object.keys(value).filter((key) => !expected.has(key));
    if (missing.length > 0 || unknown.length > 0) {
        fail(`${field} must contain exactly the canonical fields`, {
            field,
            missing,
            unknown,
        });
    }
}

function requireTaggedHash(value, field, algorithm = null) {
    if (typeof value !== "string" || !TAGGED_SHA256.test(value)) {
        fail(`${field} must be an algorithm-tagged SHA-256 identity`, {
            field,
            value,
        });
    }
    if (algorithm !== null && !value.startsWith(`${algorithm}:`)) {
        fail(`${field} must use ${algorithm}`, { field, value });
    }
    return value;
}

function requireNonEmptyString(value, field, maximum = 32767) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > maximum
        || value.includes("\0")) {
        fail(`${field} must be a non-empty bounded string`, { field });
    }
    return value;
}

function requireSafeInteger(value, field, minimum, maximum) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        fail(`${field} must be an integer in [${minimum}, ${maximum}]`, {
            field,
            value,
        });
    }
    return value;
}

function normalizeUniqueStrings(value, field, {
    maximumItems = 256,
    maximumLength = 255,
    pattern = null,
} = {}) {
    if (!Array.isArray(value) || value.length > maximumItems) {
        fail(`${field} must be an array of at most ${maximumItems} strings`, {
            field,
        });
    }
    const normalized = value.map((item, index) => {
        const current = requireNonEmptyString(
            item,
            `${field}[${index}]`,
            maximumLength,
        );
        if (pattern !== null && !pattern.test(current)) {
            fail(`${field}[${index}] has an invalid format`, {
                field,
                value: current,
            });
        }
        return current;
    }).sort((left, right) => left.localeCompare(right));
    if (new Set(normalized).size !== normalized.length) {
        fail(`${field} must not contain duplicates`, { field });
    }
    return normalized;
}

function normalizeTreeRule(value, field) {
    requireExactKeys(value, field, TREE_RULE_KEYS);
    return {
        excludedBasenames: normalizeUniqueStrings(
            value.excludedBasenames,
            `${field}.excludedBasenames`,
        ),
        excludedSegments: normalizeUniqueStrings(
            value.excludedSegments,
            `${field}.excludedSegments`,
        ),
        excludedSuffixes: normalizeUniqueStrings(
            value.excludedSuffixes,
            `${field}.excludedSuffixes`,
            { maximumLength: 64 },
        ),
        includedExtensions: normalizeUniqueStrings(
            value.includedExtensions,
            `${field}.includedExtensions`,
            { maximumLength: 32, pattern: EXTENSION },
        ),
    };
}

export const DEFAULT_RUNTIME_IDENTITY_POLICY = immutableCanonical({
    version: RUNTIME_IDENTITY_POLICY_VERSION,
    kind: RUNTIME_IDENTITY_POLICY_KIND,
    limits: {
        maxFiles: 50_000,
        maxTotalBytes: 1024 * 1024 * 1024,
        maxFileBytes: 256 * 1024 * 1024,
        maxDepth: 64,
        maxTemplateBytes: 64 * 1024,
    },
    environmentKeys: [
        "COMSPEC",
        "COPILOT_CLI_PATH",
        "COPILOT_SDK_PATH",
        "CRUCIBLE_ALLOWLIST_PATH",
        "CRUCIBLE_CASE_STORE_PATH",
        "CRUCIBLE_CLI_PACKAGE_PATH",
        "CRUCIBLE_CLI_PATH",
        "CRUCIBLE_EXPERIMENT_REGISTRY_PATH",
        "CRUCIBLE_NODE_PATH",
        "CRUCIBLE_PERSIST_DENY_ROOTS",
        "CRUCIBLE_RUNTIME_CACHE_ROOT",
        "CRUCIBLE_SANDBOX_CONTROL_ROOT",
        "CRUCIBLE_SANDBOX_HELPER_BINARY_PATH",
        "CRUCIBLE_SANDBOX_HELPER_SOURCE_PATH",
        "CRUCIBLE_SANDBOX_LAUNCHER_PATH",
        "CRUCIBLE_SANDBOX_LAUNCHER_SCRIPT_HASH",
        "CRUCIBLE_STATE_ROOT",
        "LOCALAPPDATA",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    ],
    treeRules: {
        crucibleSource: {
            includedExtensions: [
                ".cjs",
                ".dll",
                ".exe",
                ".js",
                ".json",
                ".mjs",
                ".node",
                ".ps1",
                ".wasm",
            ],
            excludedSegments: ["__tests__"],
            excludedBasenames: ["AGENTS.md", "README.md"],
            excludedSuffixes: [],
        },
        copilotCliPackage: {
            includedExtensions: [],
            excludedSegments: ["copilot-sdk"],
            excludedBasenames: [],
            excludedSuffixes: [".lock"],
        },
        copilotSdkPackage: {
            includedExtensions: [],
            excludedSegments: [],
            excludedBasenames: [],
            excludedSuffixes: [".lock"],
        },
    },
});

export function normalizeRuntimeIdentityPolicy(value) {
    requireExactKeys(value, "runtime identity policy", POLICY_KEYS);
    if (value.version !== RUNTIME_IDENTITY_POLICY_VERSION) {
        fail(
            `runtime identity policy version must be ${
                RUNTIME_IDENTITY_POLICY_VERSION
            }`,
            { actual: value.version ?? null },
        );
    }
    if (value.kind !== RUNTIME_IDENTITY_POLICY_KIND) {
        fail(`runtime identity policy kind must be ${RUNTIME_IDENTITY_POLICY_KIND}`, {
            actual: value.kind ?? null,
        });
    }
    requireExactKeys(
        value.limits,
        "runtime identity policy.limits",
        POLICY_LIMIT_KEYS,
    );
    requireExactKeys(
        value.treeRules,
        "runtime identity policy.treeRules",
        TREE_RULE_NAMES,
    );
    return immutableCanonical({
        version: RUNTIME_IDENTITY_POLICY_VERSION,
        kind: RUNTIME_IDENTITY_POLICY_KIND,
        limits: {
            maxFiles: requireSafeInteger(
                value.limits.maxFiles,
                "runtime identity policy.limits.maxFiles",
                1,
                1_000_000,
            ),
            maxTotalBytes: requireSafeInteger(
                value.limits.maxTotalBytes,
                "runtime identity policy.limits.maxTotalBytes",
                1,
                Number.MAX_SAFE_INTEGER,
            ),
            maxFileBytes: requireSafeInteger(
                value.limits.maxFileBytes,
                "runtime identity policy.limits.maxFileBytes",
                1,
                Number.MAX_SAFE_INTEGER,
            ),
            maxDepth: requireSafeInteger(
                value.limits.maxDepth,
                "runtime identity policy.limits.maxDepth",
                1,
                256,
            ),
            maxTemplateBytes: requireSafeInteger(
                value.limits.maxTemplateBytes,
                "runtime identity policy.limits.maxTemplateBytes",
                1,
                1024 * 1024,
            ),
        },
        environmentKeys: normalizeUniqueStrings(
            value.environmentKeys,
            "runtime identity policy.environmentKeys",
            { maximumItems: 256, maximumLength: 128, pattern: ENVIRONMENT_KEY },
        ),
        treeRules: Object.fromEntries(TREE_RULE_NAMES.map((name) => [
            name,
            normalizeTreeRule(
                value.treeRules[name],
                `runtime identity policy.treeRules.${name}`,
            ),
        ])),
    });
}

export function runtimeIdentityPolicyIdentity(value) {
    return hashCanonical(
        normalizeRuntimeIdentityPolicy(value),
        RUNTIME_IDENTITY_POLICY_HASH_ALGORITHM,
    );
}

function fileIdentityCore(value) {
    return {
        kind: value.kind,
        path: value.path,
        size: value.size,
        contentHash: value.contentHash,
    };
}

function normalizeFileIdentity(value, field) {
    requireExactKeys(value, field, [
        "contentHash",
        "identity",
        "kind",
        "path",
        "size",
    ]);
    if (value.kind !== "file") fail(`${field}.kind must be file`);
    const core = {
        kind: "file",
        path: requireNonEmptyString(value.path, `${field}.path`),
        size: requireSafeInteger(
            value.size,
            `${field}.size`,
            0,
            Number.MAX_SAFE_INTEGER,
        ),
        contentHash: requireTaggedHash(
            value.contentHash,
            `${field}.contentHash`,
            RUNTIME_IDENTITY_FILE_HASH_ALGORITHM,
        ),
    };
    const identity = hashCanonical(
        core,
        RUNTIME_IDENTITY_FILE_IDENTITY_ALGORITHM,
    );
    if (value.identity !== identity) {
        fail(`${field}.identity does not match its canonical file identity`, {
            expected: identity,
            actual: value.identity ?? null,
        });
    }
    return { ...core, identity };
}

function treeIdentityCore(value) {
    return {
        kind: value.kind,
        rootPath: value.rootPath,
        fileCount: value.fileCount,
        totalBytes: value.totalBytes,
        merkleRoot: value.merkleRoot,
    };
}

function normalizeTreeIdentity(value, field) {
    requireExactKeys(value, field, [
        "fileCount",
        "identity",
        "kind",
        "merkleRoot",
        "rootPath",
        "totalBytes",
    ]);
    if (value.kind !== "tree") fail(`${field}.kind must be tree`);
    const core = {
        kind: "tree",
        rootPath: requireNonEmptyString(value.rootPath, `${field}.rootPath`),
        fileCount: requireSafeInteger(
            value.fileCount,
            `${field}.fileCount`,
            1,
            1_000_000,
        ),
        totalBytes: requireSafeInteger(
            value.totalBytes,
            `${field}.totalBytes`,
            0,
            Number.MAX_SAFE_INTEGER,
        ),
        merkleRoot: requireTaggedHash(
            value.merkleRoot,
            `${field}.merkleRoot`,
            RUNTIME_IDENTITY_TREE_MERKLE_ALGORITHM,
        ),
    };
    const identity = hashCanonical(
        core,
        RUNTIME_IDENTITY_TREE_IDENTITY_ALGORITHM,
    );
    if (value.identity !== identity) {
        fail(`${field}.identity does not match its canonical tree identity`, {
            expected: identity,
            actual: value.identity ?? null,
        });
    }
    return { ...core, identity };
}

function normalizeCliIdentity(value) {
    requireExactKeys(value, "runtime identity.components.copilotCli", [
        "identity",
        "kind",
        "launcher",
        "package",
    ]);
    if (value.kind !== "cli") {
        fail("runtime identity.components.copilotCli.kind must be cli");
    }
    const core = {
        kind: "cli",
        launcher: normalizeFileIdentity(
            value.launcher,
            "runtime identity.components.copilotCli.launcher",
        ),
        package: normalizeTreeIdentity(
            value.package,
            "runtime identity.components.copilotCli.package",
        ),
    };
    const identity = hashCanonical(
        core,
        RUNTIME_IDENTITY_CLI_IDENTITY_ALGORITHM,
    );
    if (value.identity !== identity) {
        fail("runtime identity Copilot CLI identity is inconsistent", {
            expected: identity,
            actual: value.identity ?? null,
        });
    }
    return { ...core, identity };
}

function normalizeSandboxIdentity(value) {
    requirePlainObject(value, "runtime identity.components.sandbox");
    if (value.required === false) {
        requireExactKeys(value, "runtime identity.components.sandbox", [
            "identity",
            "kind",
            "required",
        ]);
        if (value.kind !== "sandbox") {
            fail("runtime identity sandbox kind must be sandbox");
        }
        const core = { kind: "sandbox", required: false };
        const identity = hashCanonical(
            core,
            RUNTIME_IDENTITY_SANDBOX_IDENTITY_ALGORITHM,
        );
        if (value.identity !== identity) {
            fail("runtime identity disabled sandbox identity is inconsistent");
        }
        return { ...core, identity };
    }
    requireExactKeys(value, "runtime identity.components.sandbox", [
        "helperBinary",
        "helperSource",
        "identity",
        "kind",
        "launcher",
        "launcherScriptHash",
        "required",
    ]);
    if (value.required !== true || value.kind !== "sandbox") {
        fail("runtime identity sandbox must declare kind sandbox and required boolean");
    }
    const core = {
        kind: "sandbox",
        required: true,
        helperSource: normalizeFileIdentity(
            value.helperSource,
            "runtime identity.components.sandbox.helperSource",
        ),
        helperBinary: normalizeFileIdentity(
            value.helperBinary,
            "runtime identity.components.sandbox.helperBinary",
        ),
        launcher: normalizeFileIdentity(
            value.launcher,
            "runtime identity.components.sandbox.launcher",
        ),
        launcherScriptHash: requireTaggedHash(
            value.launcherScriptHash,
            "runtime identity.components.sandbox.launcherScriptHash",
        ),
    };
    const identity = hashCanonical(
        core,
        RUNTIME_IDENTITY_SANDBOX_IDENTITY_ALGORITHM,
    );
    if (value.identity !== identity) {
        fail("runtime identity sandbox identity is inconsistent", {
            expected: identity,
            actual: value.identity ?? null,
        });
    }
    return { ...core, identity };
}

function normalizeCommandTemplates(value) {
    requireExactKeys(value, "runtime identity.components.commandTemplates", [
        "identity",
        "kind",
        "templates",
    ]);
    if (value.kind !== "command_templates") {
        fail("runtime identity command template kind is invalid");
    }
    requirePlainObject(
        value.templates,
        "runtime identity.components.commandTemplates.templates",
    );
    const core = {
        kind: "command_templates",
        templates: value.templates,
    };
    const identity = hashCanonical(
        core,
        RUNTIME_IDENTITY_COMMANDS_IDENTITY_ALGORITHM,
    );
    if (value.identity !== identity) {
        fail("runtime identity command template identity is inconsistent", {
            expected: identity,
            actual: value.identity ?? null,
        });
    }
    return { ...core, identity };
}

function normalizeEnvironmentIdentity(value) {
    requireExactKeys(value, "runtime identity.components.environment", [
        "identity",
        "kind",
        "variables",
    ]);
    if (value.kind !== "environment") {
        fail("runtime identity environment kind is invalid");
    }
    if (!Array.isArray(value.variables) || value.variables.length > 256) {
        fail("runtime identity environment variables must be a bounded array");
    }
    const variables = value.variables.map((item, index) => {
        const field = `runtime identity.components.environment.variables[${index}]`;
        requireExactKeys(item, field, ["name", "present", "valueHash"]);
        if (typeof item.present !== "boolean") {
            fail(`${field}.present must be boolean`);
        }
        const name = requireNonEmptyString(item.name, `${field}.name`, 128);
        if (!ENVIRONMENT_KEY.test(name)) {
            fail(`${field}.name is invalid`, { name });
        }
        return {
            name,
            present: item.present,
            valueHash: item.present
                ? requireTaggedHash(item.valueHash, `${field}.valueHash`)
                : item.valueHash === null
                    ? null
                    : fail(`${field}.valueHash must be null when absent`),
        };
    }).sort((left, right) => left.name.localeCompare(right.name));
    if (new Set(variables.map((item) => item.name)).size !== variables.length) {
        fail("runtime identity environment variables must have unique names");
    }
    const core = { kind: "environment", variables };
    const identity = hashCanonical(
        core,
        RUNTIME_IDENTITY_ENVIRONMENT_IDENTITY_ALGORITHM,
    );
    if (value.identity !== identity) {
        fail("runtime identity environment identity is inconsistent", {
            expected: identity,
            actual: value.identity ?? null,
        });
    }
    return { ...core, identity };
}

function normalizeRuntimeComponents(value) {
    requireExactKeys(value, "runtime identity.components", [
        "commandTemplates",
        "copilotCli",
        "copilotSdk",
        "crucibleSource",
        "environment",
        "nodeExecutable",
        "sandbox",
    ]);
    return {
        crucibleSource: normalizeTreeIdentity(
            value.crucibleSource,
            "runtime identity.components.crucibleSource",
        ),
        nodeExecutable: normalizeFileIdentity(
            value.nodeExecutable,
            "runtime identity.components.nodeExecutable",
        ),
        copilotCli: normalizeCliIdentity(value.copilotCli),
        copilotSdk: normalizeTreeIdentity(
            value.copilotSdk,
            "runtime identity.components.copilotSdk",
        ),
        sandbox: normalizeSandboxIdentity(value.sandbox),
        commandTemplates: normalizeCommandTemplates(value.commandTemplates),
        environment: normalizeEnvironmentIdentity(value.environment),
    };
}

function runtimeIdentityCore(value) {
    return {
        version: value.version,
        kind: value.kind,
        policy: value.policy,
        policyIdentity: value.policyIdentity,
        components: value.components,
    };
}

export function runtimeIdentityRoot(value) {
    return hashCanonical(
        runtimeIdentityCore(value),
        RUNTIME_IDENTITY_ROOT_ALGORITHM,
    );
}

export function normalizeRuntimeIdentity(value) {
    requireExactKeys(value, "runtime identity", [
        "assumptions",
        "assumptionsHash",
        "components",
        "kind",
        "policy",
        "policyIdentity",
        "root",
        "version",
    ]);
    if (value.version !== RUNTIME_IDENTITY_VERSION) {
        fail(`runtime identity version must be ${RUNTIME_IDENTITY_VERSION}`, {
            actual: value.version ?? null,
        });
    }
    if (value.kind !== RUNTIME_IDENTITY_KIND) {
        fail(`runtime identity kind must be ${RUNTIME_IDENTITY_KIND}`, {
            actual: value.kind ?? null,
        });
    }
    const policy = normalizeRuntimeIdentityPolicy(value.policy);
    const policyIdentity = runtimeIdentityPolicyIdentity(policy);
    if (value.policyIdentity !== policyIdentity) {
        fail("runtime identity policy identity does not match its policy", {
            expected: policyIdentity,
            actual: value.policyIdentity ?? null,
        });
    }
    const components = normalizeRuntimeComponents(value.components);
    requirePlainObject(value.assumptions, "runtime identity.assumptions");
    const assumptions = immutableCanonical(value.assumptions);
    const assumptionsHash = hashCanonical(
        assumptions,
        RUNTIME_IDENTITY_ASSUMPTIONS_HASH_ALGORITHM,
    );
    if (value.assumptionsHash !== assumptionsHash) {
        fail("runtime identity assumptions hash is inconsistent", {
            expected: assumptionsHash,
            actual: value.assumptionsHash ?? null,
        });
    }
    const core = {
        version: RUNTIME_IDENTITY_VERSION,
        kind: RUNTIME_IDENTITY_KIND,
        policy,
        policyIdentity,
        components,
    };
    const root = runtimeIdentityRoot(core);
    if (value.root !== root) {
        fail("runtime identity root does not match its canonical closure", {
            expected: root,
            actual: value.root ?? null,
        });
    }
    return immutableCanonical({
        ...core,
        assumptions,
        assumptionsHash,
        root,
    });
}

function authorityCore(value) {
    return {
        version: value.version,
        kind: value.kind,
        securityConfig: value.securityConfig,
        identities: value.identities,
        runtimeIdentity: value.runtimeIdentity,
        workerAdditionalContextHash: value.workerAdditionalContextHash,
        sandbox: value.sandbox,
    };
}

export function runtimeConfigAuthorityFingerprint(value) {
    return hashCanonical(
        authorityCore(value),
        RUNTIME_CONFIG_AUTHORITY_FINGERPRINT_ALGORITHM,
    );
}

export function normalizeRuntimeConfigAuthority(value) {
    requireExactKeys(value, "runtime config authority", AUTHORITY_KEYS);
    if (value.version !== RUNTIME_CONFIG_AUTHORITY_VERSION) {
        fail(
            `runtime config authority version must be ${
                RUNTIME_CONFIG_AUTHORITY_VERSION
            }`,
            { actual: value.version ?? null },
        );
    }
    if (value.kind !== RUNTIME_CONFIG_AUTHORITY_KIND) {
        fail(`runtime config authority kind must be ${RUNTIME_CONFIG_AUTHORITY_KIND}`, {
            actual: value.kind ?? null,
        });
    }
    const core = {
        version: RUNTIME_CONFIG_AUTHORITY_VERSION,
        kind: RUNTIME_CONFIG_AUTHORITY_KIND,
        securityConfig: requirePlainObject(
            value.securityConfig,
            "runtime config authority.securityConfig",
        ),
        identities: requirePlainObject(
            value.identities,
            "runtime config authority.identities",
        ),
        runtimeIdentity: normalizeRuntimeIdentity(value.runtimeIdentity),
        workerAdditionalContextHash: requireTaggedHash(
            value.workerAdditionalContextHash,
            "runtime config authority.workerAdditionalContextHash",
            "sha256:crucible-worker-additional-context-v1",
        ),
        sandbox: requirePlainObject(
            value.sandbox,
            "runtime config authority.sandbox",
        ),
    };
    const fingerprint = runtimeConfigAuthorityFingerprint(core);
    if (value.fingerprint !== fingerprint) {
        fail("runtime config authority fingerprint does not match its canonical payload", {
            expected: fingerprint,
            actual: value.fingerprint ?? null,
        });
    }
    return immutableCanonical({ ...core, fingerprint });
}
