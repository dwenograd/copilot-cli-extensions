import path from "node:path";

import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
    normalizeRuntimeConfigAuthority,
    normalizeRuntimeIdentity,
    runtimeConfigAuthorityFingerprint,
    RUNTIME_CONFIG_AUTHORITY_KIND,
    RUNTIME_CONFIG_AUTHORITY_VERSION,
} from "../domain/index.mjs";
import {
    sha256File,
    verifyAndHashFile,
    verifyLocalRegularFile,
} from "../measurement/index.mjs";
import {
    coerceSupervisorConfig,
    normalizeSupervisorConfig,
    supervisorConfigDocument,
} from "./config.mjs";
import {
    RuntimeConfigError,
    RuntimeIntegrityError,
} from "./errors.mjs";
import {
    assertRuntimeIdentityVerified,
    reverifyRuntimeIdentity,
    verifyRuntimeIdentity,
} from "./runtime-identity.mjs";

const WORKER_CONTEXT_HASH_ALGORITHM =
    "sha256:crucible-worker-additional-context-v1";
const ALLOWLIST_HASH_ALGORITHM =
    "sha256:crucible-runtime-allowlist-file-v1";
const SDK_ENTRY_HASH_ALGORITHM =
    "sha256:crucible-runtime-sdk-entry-v1";
const COPILOT_CLI_HASH_ALGORITHM =
    "sha256:crucible-runtime-copilot-cli-v1";
const RUNNER_CLI_HASH_ALGORITHM =
    "sha256:crucible-runtime-runner-cli-v1";
const NODE_RUNTIME_HASH_ALGORITHM =
    "sha256:crucible-runtime-node-identity-v1";
const IDENTITY_KEYS = Object.freeze([
    "allowlist",
    "copilotCli",
    "nodeRuntime",
    "runnerCli",
    "sdk",
]);

function samePath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function fileIdentity(file, algorithm, label) {
    const resolved = verifyLocalRegularFile(file, { label });
    return Object.freeze({
        path: resolved,
        hash: sha256File(resolved, algorithm),
    });
}

function securityConfigDocument(config) {
    const document = supervisorConfigDocument(config);
    const { deadline: _deadline, ...runner } = document.runner;
    return immutableCanonical({
        ...document,
        runner,
    });
}

function sandboxIdentity(sandbox) {
    if (sandbox?.required !== true) {
        return immutableCanonical({ required: false });
    }
    const {
        available: _available,
        reason: _reason,
        details: _details,
        probe: _probe,
        helper: _helper,
        controlRoot: _controlRoot,
        required: _required,
        ...identity
    } = sandbox;
    return immutableCanonical({
        required: true,
        identity,
    });
}

function workerContextHash(securityConfig) {
    return hashCanonical(
        {
            content:
                securityConfig.runner.options.workerAdditionalContext ?? null,
        },
        WORKER_CONTEXT_HASH_ALGORITHM,
    );
}

function requireIdentityRecord(value, field) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RuntimeIntegrityError(`${field} must be an object`);
    }
    if (typeof value.path !== "string" || typeof value.hash !== "string") {
        throw new RuntimeIntegrityError(`${field} must contain path and hash`);
    }
    return value;
}

function validateIdentityShape(authority) {
    const keys = Object.keys(authority.identities).sort();
    if (!canonicalEqual(keys, [...IDENTITY_KEYS].sort())) {
        throw new RuntimeIntegrityError(
            "Runtime config authority has an invalid identity set",
            { keys },
        );
    }
    const allowlist = requireIdentityRecord(
        authority.identities.allowlist,
        "identities.allowlist",
    );
    const copilotCli = requireIdentityRecord(
        authority.identities.copilotCli,
        "identities.copilotCli",
    );
    const runnerCli = requireIdentityRecord(
        authority.identities.runnerCli,
        "identities.runnerCli",
    );
    const sdk = authority.identities.sdk;
    if (sdk === null
        || typeof sdk !== "object"
        || Array.isArray(sdk)
        || typeof sdk.path !== "string"
        || typeof sdk.entryPath !== "string"
        || typeof sdk.entryHash !== "string") {
        throw new RuntimeIntegrityError(
            "identities.sdk must contain path, entryPath, and entryHash",
        );
    }
    const nodeRuntime = authority.identities.nodeRuntime;
    if (nodeRuntime === null
        || typeof nodeRuntime !== "object"
        || Array.isArray(nodeRuntime)
        || typeof nodeRuntime.path !== "string"
        || typeof nodeRuntime.hash !== "string"
        || typeof nodeRuntime.version !== "string"
        || typeof nodeRuntime.platform !== "string"
        || typeof nodeRuntime.architecture !== "string") {
        throw new RuntimeIntegrityError(
            "identities.nodeRuntime is incomplete",
        );
    }
    return { allowlist, copilotCli, runnerCli, sdk, nodeRuntime };
}

function verifyIdentityFile(identity, algorithm, label) {
    verifyAndHashFile(identity.path, identity.hash, {
        label,
        algorithm,
    });
}

export function buildRuntimeConfigAuthority({
    supervisorConfig,
    nodeExecutable,
    runtimeIdentity,
    sandbox,
    env = process.env,
}) {
    const config = coerceSupervisorConfig(supervisorConfig, { env });
    if (typeof nodeExecutable !== "string" || !path.isAbsolute(nodeExecutable)) {
        throw new RuntimeConfigError(
            "Runtime config authority requires an absolute Node executable path",
        );
    }
    const securityConfig = securityConfigDocument(config);
    let normalizedRuntimeIdentity;
    try {
        normalizedRuntimeIdentity = normalizeRuntimeIdentity(runtimeIdentity);
    } catch (error) {
        throw new RuntimeConfigError(
            `Runtime config authority requires a canonical runtime identity: ${
                error?.message ?? String(error)
            }`,
            { cause: error?.code ?? null },
        );
    }
    const sdkEntryPath = path.join(config.runner.sdkPath, "index.js");
    const allowlist = fileIdentity(
        config.runner.allowlistPath,
        ALLOWLIST_HASH_ALGORITHM,
        "runtime-authority allowlist",
    );
    const sdkEntry = fileIdentity(
        sdkEntryPath,
        SDK_ENTRY_HASH_ALGORITHM,
        "runtime-authority SDK entry",
    );
    const copilotCli = fileIdentity(
        config.runner.cliPath,
        COPILOT_CLI_HASH_ALGORITHM,
        "runtime-authority Copilot CLI",
    );
    const runnerCli = fileIdentity(
        config.runnerCliPath,
        RUNNER_CLI_HASH_ALGORITHM,
        "runtime-authority runner CLI",
    );
    const nodeRuntimePath = verifyLocalRegularFile(nodeExecutable, {
        label: "runtime-authority Node executable",
    });
    const nodeRuntimeCore = {
        path: nodeRuntimePath,
        version: process.version,
        platform: process.platform,
        architecture: process.arch,
    };
    const core = {
        version: RUNTIME_CONFIG_AUTHORITY_VERSION,
        kind: RUNTIME_CONFIG_AUTHORITY_KIND,
        securityConfig,
        identities: {
            allowlist,
            sdk: {
                path: config.runner.sdkPath,
                entryPath: sdkEntry.path,
                entryHash: sdkEntry.hash,
            },
            copilotCli,
            runnerCli,
            nodeRuntime: {
                ...nodeRuntimeCore,
                hash: hashCanonical(
                    nodeRuntimeCore,
                    NODE_RUNTIME_HASH_ALGORITHM,
                ),
            },
        },
        runtimeIdentity: normalizedRuntimeIdentity,
        workerAdditionalContextHash: workerContextHash(securityConfig),
        sandbox: sandboxIdentity(sandbox),
    };
    return normalizeRuntimeConfigAuthority({
        ...core,
        fingerprint: runtimeConfigAuthorityFingerprint(core),
    });
}

export function supervisorConfigFromRuntimeAuthority(
    value,
    {
        deadlineMs = null,
        env = process.env,
    } = {},
) {
    const authority = normalizeRuntimeConfigAuthority(value);
    const securityConfig = structuredClone(authority.securityConfig);
    if (deadlineMs !== null) {
        if (!Number.isFinite(deadlineMs)) {
            throw new RuntimeConfigError("reattach deadline must be finite");
        }
        securityConfig.runner.deadline = deadlineMs;
    }
    const config = normalizeSupervisorConfig(securityConfig, { env });
    if (!canonicalEqual(
        securityConfigDocument(config),
        authority.securityConfig,
    )) {
        throw new RuntimeIntegrityError(
            "Runtime config authority cannot reconstruct its canonical supervisor config",
        );
    }
    return config;
}

export function assertSupervisorConfigMatchesRuntimeAuthority(
    supervisorConfig,
    value,
    { env = process.env } = {},
) {
    const authority = normalizeRuntimeConfigAuthority(value);
    const config = coerceSupervisorConfig(supervisorConfig, { env });
    if (!canonicalEqual(
        securityConfigDocument(config),
        authority.securityConfig,
    )) {
        throw new RuntimeIntegrityError(
            "Persisted supervisor config differs from the immutable runtime authority",
            {
                expectedFingerprint: authority.fingerprint,
            },
        );
    }
    return config;
}

export function verifyRuntimeConfigAuthority(
    value,
    {
        env = process.env,
        deadlineMs = null,
        expectedInvestigationId = null,
        expectedStateDir = null,
        expectedArtifactRoot = null,
        nodeExecutable = null,
        sandbox = null,
        runtimeIdentityInput = null,
        commandTemplates = null,
        verifyFiles = true,
    } = {},
) {
    const authority = normalizeRuntimeConfigAuthority(value);
    const identities = validateIdentityShape(authority);
    const config = supervisorConfigFromRuntimeAuthority(authority, {
        deadlineMs,
        env,
    });
    if (expectedInvestigationId !== null
        && config.runner.investigationId !== expectedInvestigationId) {
        throw new RuntimeIntegrityError(
            "Runtime config authority belongs to a different investigation",
        );
    }
    if (expectedStateDir !== null
        && !samePath(config.runner.stateDir, expectedStateDir)) {
        throw new RuntimeIntegrityError(
            "Runtime config authority state path is inconsistent",
        );
    }
    if (expectedArtifactRoot !== null
        && !samePath(config.runner.artifactRoot, expectedArtifactRoot)) {
        throw new RuntimeIntegrityError(
            "Runtime config authority artifact path is inconsistent",
        );
    }
    if (!samePath(identities.allowlist.path, config.runner.allowlistPath)
        || !samePath(identities.sdk.path, config.runner.sdkPath)
        || !samePath(
            identities.sdk.entryPath,
            path.join(config.runner.sdkPath, "index.js"),
        )
        || !samePath(identities.copilotCli.path, config.runner.cliPath)
        || !samePath(identities.runnerCli.path, config.runnerCliPath)
        || !samePath(
            authority.runtimeIdentity.components.nodeExecutable.path,
            identities.nodeRuntime.path,
        )
        || !samePath(
            authority.runtimeIdentity.components.copilotCli.launcher.path,
            identities.copilotCli.path,
        )
        || !samePath(
            authority.runtimeIdentity.components.copilotSdk.rootPath,
            identities.sdk.path,
        )) {
        throw new RuntimeIntegrityError(
            "Runtime executable/path identities do not match the immutable supervisor config",
        );
    }
    if (authority.workerAdditionalContextHash
        !== workerContextHash(authority.securityConfig)) {
        throw new RuntimeIntegrityError(
            "Runtime worker additional context hash is inconsistent",
        );
    }
    if (sandbox !== null
        && !canonicalEqual(authority.sandbox, sandboxIdentity(sandbox))) {
        throw new RuntimeIntegrityError(
            "Current sandbox identity differs from the immutable runtime authority",
        );
    }
    if (nodeExecutable !== null) {
        const nodeRuntimeCore = {
            path: identities.nodeRuntime.path,
            version: process.version,
            platform: process.platform,
            architecture: process.arch,
        };
        if (!samePath(nodeExecutable, identities.nodeRuntime.path)
            || identities.nodeRuntime.version !== process.version
            || identities.nodeRuntime.platform !== process.platform
            || identities.nodeRuntime.architecture !== process.arch
            || identities.nodeRuntime.hash !== hashCanonical(
                nodeRuntimeCore,
                NODE_RUNTIME_HASH_ALGORITHM,
            )) {
            throw new RuntimeIntegrityError(
                "Current Node runtime identity differs from the immutable runtime authority",
            );
        }
    }
    if (verifyFiles) {
        const sandboxExpectedHashes = sandbox?.required === true
            ? {
                expectedHelperSourceHash: sandbox.helperSourceHash,
                expectedHelperBinaryHash: sandbox.helperBinaryHash,
                expectedLauncherBinaryHash: sandbox.launcherBinaryHash,
                expectedLauncherScriptHash: sandbox.launcherScriptHash,
            }
            : null;
        const runtimeVerification = runtimeIdentityInput === null
            ? reverifyRuntimeIdentity(authority.runtimeIdentity, {
                env,
                commandTemplates,
                sandboxExpectedHashes,
            })
            : verifyRuntimeIdentity(
                authority.runtimeIdentity,
                runtimeIdentityInput,
            );
        assertRuntimeIdentityVerified(
            runtimeVerification,
            "Current runtime closure differs from the immutable opening identity",
        );
        verifyIdentityFile(
            identities.allowlist,
            ALLOWLIST_HASH_ALGORITHM,
            "runtime-authority allowlist",
        );
        verifyAndHashFile(identities.sdk.entryPath, identities.sdk.entryHash, {
            label: "runtime-authority SDK entry",
            algorithm: SDK_ENTRY_HASH_ALGORITHM,
        });
        verifyIdentityFile(
            identities.copilotCli,
            COPILOT_CLI_HASH_ALGORITHM,
            "runtime-authority Copilot CLI",
        );
        verifyIdentityFile(
            identities.runnerCli,
            RUNNER_CLI_HASH_ALGORITHM,
            "runtime-authority runner CLI",
        );
        verifyLocalRegularFile(identities.nodeRuntime.path, {
            label: "runtime-authority Node executable",
        });
    }
    return Object.freeze({ authority, config });
}
