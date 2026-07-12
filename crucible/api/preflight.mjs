// Single crucible_start preflight/apply boundary. Preflight may read trusted
// inputs and build a disposable isolated snapshot/sandbox workspace, but it
// never creates or mutates investigation state. Apply consumes only the
// branded canonical plan returned here; it never reinterprets raw tool args.

import fs from "node:fs";
import path from "node:path";

import {
    canonicalEqual,
    contractHash,
    createInvestigationContract,
    harnessSuiteRoleCases,
} from "../domain/index.mjs";
import {
    PARSER_VERSION,
    verifyHarnessPreflight,
} from "../measurement/index.mjs";
import {
    RUNTIME_ERROR_CODES,
    assertSupervisorConfigMatchesRuntimeAuthority,
    assertPromptContractCoreFits,
    buildRuntimeConfigAuthority,
    deriveRunnerExecutionLimits,
    normalizeStartDeadline,
    resolveNodeExecutable,
    supervisorConfigFromRuntimeAuthority,
    supervisorPaths,
    verifyRuntimeConfigAuthority,
} from "../runtime/index.mjs";
import {
    buildSupervisorConfigInput,
    createPreflightWorkspace,
    deriveInvestigationId,
    removePreflightWorkspace,
    resolveInvestigationPaths,
    resolveStateRoot,
    resolveStartEnvironment,
} from "./environment.mjs";
import {
    EXPERIMENT_REGISTRY_ERROR_CODES,
    ExperimentRegistryError,
    loadExperimentRegistry,
    resolveExperimentProjectDir,
    resolveExperimentRegistryPath,
    reverifyExperimentRegistryFile,
} from "./experiment-registry.mjs";
import {
    EXPERIMENT_AUTHORITY_ERROR_CODES,
    ExperimentAuthorityError,
    readVerifiedExperimentAuthority,
    verifyExperimentAuthority,
} from "./experiment-authority.mjs";
import {
    ContractConflictError,
    CrucibleApiError,
    HarnessConfigurationError,
    HarnessNotAllowlistedError,
    InvestigationNotFoundError,
    InvestigationNotResumableError,
    LegacyIncompatibleApiError,
    OperationalResetRequiredError,
    ExperimentNotFoundApiError,
    ExperimentAuthorityMismatchApiError,
    ExperimentRegistryApiError,
    SandboxUnavailableApiError,
    StartFailedError,
    StartPreflightError,
} from "./errors.mjs";
import { crucibleStartSpec } from "./schema.mjs";

const PREFLIGHT_PLANS = new WeakSet();
const DISPOSED_PLANS = new WeakSet();
const AUTHORITY_MISMATCH_CODES = new Set([
    EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
    EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_NOT_CONFIGURED,
    EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
    EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_FINGERPRINT_MISMATCH,
    EXPERIMENT_AUTHORITY_ERROR_CODES.SIGNATURE_INVALID,
]);

function authorityMismatch(error, message, details = {}) {
    throw new ExperimentAuthorityMismatchApiError(message, {
        ...details,
        cause: error?.code ?? null,
    }, { cause: error });
}

function throwLegacyIncompatible(error, investigationId) {
    if (error?.code !== RUNTIME_ERROR_CODES.LEGACY_INCOMPATIBLE) {
        throw error;
    }
    throw new LegacyIncompatibleApiError(
        "This investigation belongs to an incompatible legacy domain and cannot be resumed; start a new investigation",
        {
            investigationId,
            expectedDomainVersion: error?.details?.expectedDomainVersion ?? null,
            actualDomainVersion: error?.details?.actualDomainVersion ?? null,
            contractDomainVersion: error?.details?.contractDomainVersion ?? null,
            eventCount: error?.details?.eventCount ?? null,
            archiveable: error?.details?.archiveable === true,
            readOnly: true,
        },
    );
}

function isThenable(value) {
    return value !== null
        && (typeof value === "object" || typeof value === "function")
        && typeof value.then === "function";
}

function sameLocalPath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function loadPreapprovedExperiment(args, deps) {
    const registryPath = resolveExperimentRegistryPath(undefined, deps.env);
    let registry;
    try {
        registry = (deps.loadExperimentRegistry ?? loadExperimentRegistry)(
            registryPath,
            { experimentId: args.experiment_id, env: deps.env },
        );
    } catch (error) {
        if (error instanceof ExperimentRegistryError
            && error.code === EXPERIMENT_REGISTRY_ERROR_CODES.EXPERIMENT_NOT_FOUND) {
            throw new ExperimentNotFoundApiError(error.message, {
                experimentId: args.experiment_id,
                registryPath,
            }, { cause: error });
        }
        if (AUTHORITY_MISMATCH_CODES.has(error?.code)) {
            authorityMismatch(
                error,
                `operator experiment authority verification failed: ${
                    error?.message ?? String(error)
                }`,
                {
                    experimentId: args.experiment_id,
                    registryPath,
                },
            );
        }
        throw new ExperimentRegistryApiError(
            `operator experiment registry verification failed: ${
                error?.message ?? String(error)
            }`,
            {
                experimentId: args.experiment_id,
                registryPath,
                cause: error?.code ?? null,
            },
            { cause: error },
        );
    }
    let experiment;
    try {
        experiment = registry.getExperiment(args.experiment_id);
    } catch (error) {
        throw new ExperimentNotFoundApiError(error.message, {
            experimentId: args.experiment_id,
            registryPath,
        }, { cause: error });
    }
    let projectDir;
    try {
        projectDir = resolveExperimentProjectDir(experiment.projectDir, deps.env);
    } catch (error) {
        if (AUTHORITY_MISMATCH_CODES.has(error?.code)) {
            authorityMismatch(
                error,
                `operator experiment trust changed after preflight: ${
                    error?.message ?? String(error)
                }`,
                {
                    experimentId: plan.experimentId,
                    registryPath:
                        plan.registryVerification.registryPath,
                },
            );
        }
        throw new ExperimentRegistryApiError(
            `preapproved experiment project identity is unavailable: ${
                error?.message ?? String(error)
            }`,
            {
                experimentId: args.experiment_id,
                projectDir: experiment.projectDir,
                cause: error?.code ?? null,
            },
            { cause: error },
        );
    }
    if (!sameLocalPath(projectDir, experiment.projectDir)) {
        throw new ExperimentRegistryApiError(
            "preapproved experiment project path no longer resolves to its operator-owned identity",
            {
                experimentId: args.experiment_id,
                expected: experiment.projectDir,
                actual: projectDir,
            },
        );
    }
    let contract;
    try {
        contract = createInvestigationContract(experiment.contract);
    } catch (error) {
        throw new ExperimentRegistryApiError(
            `preapproved experiment contract failed canonical validation: ${
                error?.message ?? String(error)
            }`,
            {
                experimentId: args.experiment_id,
                cause: error?.code ?? null,
            },
            { cause: error },
        );
    }
    const digest = contractHash(contract);
    if (!canonicalEqual(contract, experiment.contract)
        || digest !== experiment.contractHash
        || contract.harnessSuite.id !== experiment.harnessSuiteId
        || contract.harnessSuiteIdentity !== experiment.harnessSuiteIdentity) {
        throw new ExperimentRegistryApiError(
            "preapproved experiment entry does not match its canonical contract identity",
            { experimentId: args.experiment_id },
        );
    }
    const investigationId = deriveInvestigationId({
        experimentId: experiment.experimentId,
        objective: contract.objective,
        projectDir,
        harnessSuiteId: experiment.harnessSuiteId,
        harnessSuiteIdentity: experiment.harnessSuiteIdentity,
        contractHash: digest,
        trustFingerprint: experiment.authority.trustFingerprint,
    });
    if (investigationId !== experiment.investigationId) {
        throw new ExperimentRegistryApiError(
            "preapproved experiment investigation identity is inconsistent",
            {
                experimentId: args.experiment_id,
                expected: experiment.investigationId,
                actual: investigationId,
            },
        );
    }
    return {
        registry,
        experiment,
        projectDir,
        contract,
        contractDigest: digest,
        investigationId,
        promptCore: assertPromptContractCoreFits(contract),
        authority: experiment.authority,
    };
}

function contractSnapshotReferences(contract) {
    const references = new Map();
    const add = (snapshot, purpose) => {
        if (typeof snapshot === "string" && /^sha256:[a-f0-9]{64}$/u.test(snapshot)) {
            const purposes = references.get(snapshot) ?? new Set();
            purposes.add(purpose);
            references.set(snapshot, purposes);
        }
    };
    for (const [caseId, item] of Object.entries(
        contract.harnessSuite.operatorCorpus.cases,
    )) {
        add(item.snapshotHash, `harness-suite-case:${caseId}`);
    }
    if (contract.enumerandManifest?.topology === "finite_enumerable") {
        for (const entry of contract.enumerandManifest.entries) {
            add(entry.artifactSnapshotHash, `enumerand:${entry.ordinal}`);
        }
    }
    if (contract.enumerandManifest?.control?.kind === "reference") {
        add(contract.enumerandManifest.control.referenceHash, "enumerand-control");
    }
    if (contract.statisticalPolicy.control.kind === "snapshot") {
        add(contract.statisticalPolicy.control.identity, "statistical-control");
    }
    return references;
}

function copyDurableSnapshot(source, destination, snapshot, purposes) {
    const verification = source.verifySnapshot(snapshot);
    if (verification?.ok !== true) {
        throw new StartPreflightError(
            `durable operator snapshot ${snapshot} failed verification`,
            {
                snapshot,
                purposes: [...purposes].sort(),
                verification,
            },
        );
    }
    const manifest = source.loadManifest(snapshot);
    const objectIds = [
        ...new Set([
            ...manifest.entries.map((entry) => entry.object),
            snapshot,
        ]),
    ].sort();
    for (const objectId of objectIds) {
        const bytes = source.readObject(objectId, { verify: true });
        const stored = destination.putBytes(bytes, {
            contentType: objectId === snapshot
                ? "application/vnd.crucible.snapshot+json"
                : "application/octet-stream",
        });
        if (stored.id !== objectId) {
            throw new StartPreflightError(
                "durable snapshot changed content address during preflight staging",
                { expected: objectId, actual: stored.id, snapshot },
            );
        }
    }
    return objectIds;
}

function stageContractSnapshots({
    sourceStore,
    stagingStore,
    contract,
}) {
    const references = contractSnapshotReferences(contract);
    const objectIds = new Set();
    for (const [snapshot, purposes] of references) {
        for (const objectId of copyDurableSnapshot(
            sourceStore,
            stagingStore,
            snapshot,
            purposes,
        )) {
            objectIds.add(objectId);
        }
    }
    return Object.freeze({
        snapshots: Object.freeze([...references.keys()].sort()),
        objectIds: Object.freeze([...objectIds].sort()),
    });
}

function snapshotStagingPlan(workspace, contract, staged) {
    return Object.freeze({
        root: workspace.snapshotStoreRoot,
        validationCases: Object.freeze(contract.validationCases.map((validationCase) =>
            Object.freeze({
                id: validationCase.id,
                expectation: validationCase.expectation,
                artifactHash: validationCase.artifactHash,
            }))),
        snapshots: staged.snapshots,
        objectIds: staged.objectIds,
    });
}

function operationalRecoveryPlan(operationalNonResult, args, deadline) {
    if (operationalNonResult === null) return null;
    const payload = operationalNonResult.payload ?? {};
    const code = payload.code ?? "UNKNOWN_OPERATIONAL_FAILURE";
    if (code === "DEADLINE_EXCEEDED") {
        const previousDeadline = payload.details?.deadlineMs;
        if (!Number.isFinite(previousDeadline)
            || deadline.deadlineMs === null
            || deadline.deadlineMs <= previousDeadline) {
            throw new OperationalResetRequiredError(
                "A deadline non-result requires crucible_start with an explicit later deadline_iso",
                {
                    code,
                    previousDeadline: Number.isFinite(previousDeadline)
                        ? previousDeadline
                        : null,
                    requestedDeadline: deadline.deadlineMs,
                },
            );
        }
        return Object.freeze({
            policy: "later_deadline",
            reason: "Explicit crucible_start supplied a later wall-clock deadline.",
            details: Object.freeze({
                previousDeadline,
                requestedDeadline: deadline.deadlineMs,
            }),
        });
    }
    if (code === "CRUCIBLE_RUNTIME_CIRCUIT_OPEN") {
        if (args.reset_policy !== "circuit_open") {
            throw new OperationalResetRequiredError(
                "A circuit-open non-result requires reset_policy='circuit_open'",
                { code },
            );
        }
        return Object.freeze({
            policy: "circuit_open",
            reason: "Explicit crucible_start reset the persisted circuit breaker.",
            details: null,
        });
    }
    if (payload.details?.recoverable === true) {
        return Object.freeze({
            policy: "recoverable_reattach",
            reason: "Explicit crucible_start reattached after a recoverable operational failure.",
            details: null,
        });
    }
    if (args.reset_policy !== "failed") {
        throw new OperationalResetRequiredError(
            "A non-recoverable failed operational outcome requires reset_policy='failed'",
            { code },
        );
    }
    return Object.freeze({
        policy: "failed",
        reason: "Explicit crucible_start reset a persisted failed operational outcome.",
        details: null,
    });
}

function inspectExistingInvestigation({
    deps,
    paths,
    investigationId,
    requestedContractHash,
    requestedAuthorityIdentity,
    args,
    deadline,
}) {
    const investigationExists = fs.existsSync(paths.investigationDir);
    if (!fs.existsSync(paths.eventsDbPath)) {
        if (investigationExists) {
            throw new StartPreflightError(
                "incomplete investigation state already exists without an event repository",
                { investigationId, investigationDir: paths.investigationDir },
            );
        }
        return Object.freeze({ mode: "new" });
    }
    const repository = deps.openRepositoryReadOnly({
        file: paths.eventsDbPath,
        env: deps.env,
    });
    try {
        const adapter = deps.createDomainRepositoryAdapter({
            repository,
            investigationId,
            ensure: false,
        });
        let current;
        try {
            current = adapter.replay();
        } catch (error) {
            throwLegacyIncompatible(error, investigationId);
        }
        if (current.aggregate.contract === null) {
            throw new StartPreflightError(
                "existing investigation repository has no frozen contract",
                { investigationId },
            );
        }
        if (current.aggregate.contractHash !== requestedContractHash) {
            throw new ContractConflictError(
                "an investigation with this identity already exists with a different contract",
                {
                    investigationId,
                    existingContractHash: current.aggregate.contractHash,
                    requestedContractHash,
                },
            );
        }
        if (current.aggregate.experimentAuthorityIdentity
            !== requestedAuthorityIdentity) {
            throw new ContractConflictError(
                "an investigation with this identity already exists with different operator authority",
                {
                    investigationId,
                    existingAuthorityIdentity:
                        current.aggregate.experimentAuthorityIdentity ?? null,
                    requestedAuthorityIdentity,
                },
            );
        }
        if (current.aggregate.terminal !== null || current.aggregate.nonResults.length > 0) {
            throw new InvestigationNotResumableError(
                "Terminal and domain non-result investigations require a new investigation identity",
                { investigationId, status: current.aggregate.status },
            );
        }
        const operationalNonResult = adapter.latestOperationalNonResult();
        const recovery = operationalRecoveryPlan(
            operationalNonResult,
            args,
            deadline,
        );
        return Object.freeze({
            mode: "reattach",
            expectedLastSeq: current.aggregate.lastSeq,
            expectedPaused: current.aggregate.pause !== null,
            expectedOperationalSeq: operationalNonResult?.seq ?? null,
            recovery,
        });
    } finally {
        repository.close();
    }
}

function normalizeDeadline(args, deps) {
    try {
        return normalizeStartDeadline(args.deadline_iso, {
            now: deps.clock?.now?.() ?? Date.now(),
        });
    } catch (error) {
        throw new StartPreflightError(
            `deadline preflight failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
}

function normalizeSupervisor(input, deps) {
    try {
        return deps.normalizeSupervisorConfig(input, { env: deps.env });
    } catch (error) {
        throw new StartPreflightError(
            `supervisor configuration preflight failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
}

function verifyHarnessSuite(allowlist, suiteId, expectedIdentity) {
    try {
        const suite = allowlist.getSuite(suiteId);
        const suiteIdentity = allowlist.getSuiteIdentity(suiteId);
        if (suiteIdentity !== expectedIdentity) {
            throw new Error("configured suite identity changed during preflight");
        }
        const roles = {};
        for (const [role, spec] of Object.entries(suite.roles)) {
            const cases = harnessSuiteRoleCases(suite, role);
            const verifiedEntry = cases.length === 0
                ? allowlist.verifyEntry(spec.harnessId)
                : verifyHarnessPreflight(allowlist, spec.harnessId, {
                    validationCases: cases,
                    parserVersion: PARSER_VERSION,
                }).verifiedEntry;
            if (verifiedEntry.entryHash !== spec.harnessEntryHash
                || verifiedEntry.executableHash !== spec.executableHash) {
                throw new Error(
                    `verified role ${role} does not match its HarnessSuiteV4 identity`,
                );
            }
            roles[role] = Object.freeze({ spec, verifiedEntry });
        }
        return Object.freeze({
            suite,
            suiteIdentity,
            roles: Object.freeze(roles),
        });
    } catch (error) {
        throw new HarnessConfigurationError(
            `harness-suite preflight failed: ${error?.message ?? String(error)}`,
            {
                suiteId,
                cause: error?.code ?? null,
                details: error?.details ?? null,
            },
            { cause: error },
        );
    }
}

function suiteRequiresSandbox(suite) {
    return Object.values(suite.roles)
        .some((role) => role.sandboxIdentity.required);
}

function validateHarnessSuiteSandbox(suite, sandbox) {
    for (const [role, spec] of Object.entries(suite.roles)) {
        if (!spec.sandboxIdentity.required) continue;
        if (sandbox?.required !== true
            || sandbox.policyDigest !== spec.sandboxIdentity.policyDigest) {
            throw new SandboxUnavailableApiError(
                `sandbox policy does not match HarnessSuiteV4 role '${role}'`,
                {
                    role,
                    expectedPolicyDigest: spec.sandboxIdentity.policyDigest,
                    actualPolicyDigest: sandbox?.policyDigest ?? null,
                },
            );
        }
    }
    return sandbox;
}

function loadAllowlistForPreflight(deps, allowlistPath) {
    try {
        return deps.loadHarnessAllowlist(allowlistPath);
    } catch (error) {
        throw new HarnessConfigurationError(
            `harness allowlist preflight failed: ${error?.message ?? String(error)}`,
            { allowlistPath, cause: error?.code ?? null, details: error?.details ?? null },
            { cause: error },
        );
    }
}

function samePath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function persistedDeadline(config, args, deps) {
    const previous = config.runner.deadlineMs;
    if (args.deadline_iso === undefined) {
        return Object.freeze({
            deadlineIso: previous === null ? null : new Date(previous).toISOString(),
            deadlineMs: previous,
        });
    }
    try {
        return normalizeStartDeadline(args.deadline_iso, {
            now: deps.clock?.now?.() ?? Date.now(),
            afterMs: previous,
        });
    } catch (error) {
        throw new StartPreflightError(
            `reattach deadline preflight failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
}

function validateSupervisorAdmission(config, deps) {
    try {
        const admitted = typeof deps.validateSupervisorAdmission === "function"
            ? deps.validateSupervisorAdmission(config, { env: deps.env })
            : null;
        return Object.freeze({
            config: admitted?.config ?? config,
            nodeExecutable:
                admitted?.nodeExecutable
                ?? (deps.resolveNodeExecutable ?? resolveNodeExecutable)(
                    deps.env,
                ),
        });
    } catch (error) {
        throw new StartPreflightError(
            `supervisor admission preflight failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
}

function verifyPersistedSnapshots(contract, artifactStore) {
    for (const [snapshot, purposes] of contractSnapshotReferences(contract)) {
        const verification = artifactStore.verifySnapshot(snapshot);
        if (verification?.ok !== true) {
            throw new StartPreflightError(
                `persisted frozen snapshot '${snapshot}' failed verification`,
                {
                    snapshot,
                    purposes: [...purposes].sort(),
                    verification,
                },
            );
        }
    }
}

function verifyPersistedExperimentAuthority(aggregate, deps, investigationId) {
    const authority = aggregate.experimentAuthority;
    if (authority === null
        || aggregate.experimentAuthorityIdentity === null
        || authority.identity !== aggregate.experimentAuthorityIdentity) {
        authorityMismatch(
            null,
            "persisted investigation has no valid detached operator authority",
            {
                persistedAuthorityIdentity:
                    aggregate.experimentAuthorityIdentity ?? null,
            },
        );
    }
    const payload = authority.manifest?.experimentPayload;
    try {
        const capability = verifyExperimentAuthority({
            authority,
            experimentId: payload?.experimentId,
            projectDir: payload?.projectDir,
            harnessSuiteId: payload?.harnessSuiteId,
            contract: aggregate.contract,
            investigationId,
            env: deps.env,
        });
        const verified = readVerifiedExperimentAuthority(capability).authority;
        const expectedInvestigationId = deriveInvestigationId({
            experimentId: payload.experimentId,
            objective: aggregate.contract.objective,
            projectDir: payload.projectDir,
            harnessSuiteId: payload.harnessSuiteId,
            harnessSuiteIdentity: aggregate.contract.harnessSuiteIdentity,
            contractHash: aggregate.contractHash,
            trustFingerprint: verified.trustFingerprint,
        });
        if (expectedInvestigationId !== investigationId) {
            authorityMismatch(
                null,
                "persisted experiment authority belongs to a different investigation identity",
                {
                    expectedInvestigationId,
                    actualInvestigationId: investigationId,
                    persistedAuthorityIdentity: verified.identity,
                },
            );
        }
        return capability;
    } catch (error) {
        if (error instanceof ExperimentAuthorityError
            || AUTHORITY_MISMATCH_CODES.has(error?.code)) {
            authorityMismatch(
                error,
                `persisted experiment authority no longer matches the current trust root: ${
                    error?.message ?? String(error)
                }`,
                {
                    persistedAuthorityIdentity:
                        aggregate.experimentAuthorityIdentity,
                    persistedTrustFingerprint:
                        authority.trustFingerprint ?? null,
                },
            );
        }
        throw error;
    }
}

function reattachPlan({
    args,
    deps,
    stateRoot,
    paths,
    current,
    operationalNonResult,
    supervisorConfig,
    supervisorAdmission,
    deadline,
    allowlist,
    sandbox,
    workspace,
    experimentAuthority,
    verifiedExperimentAuthority,
    runtimeConfigAuthority,
    selection = null,
}) {
    const suiteVerification = verifyHarnessSuite(
        allowlist,
        current.aggregate.contract.harnessSuite.id,
        current.aggregate.contract.harnessSuiteIdentity,
    );
    validateHarnessSuiteSandbox(current.aggregate.contract.harnessSuite, sandbox);
    try {
        verifyRuntimeConfigAuthority(runtimeConfigAuthority, {
            env: deps.env,
            deadlineMs: deadline.deadlineMs,
            expectedInvestigationId: args.investigation_id,
            expectedStateDir: paths.stateDir,
            expectedArtifactRoot: paths.artifactRoot,
            nodeExecutable: supervisorAdmission.nodeExecutable,
            sandbox,
        });
    } catch (error) {
        authorityMismatch(
            error,
            `current runtime identity differs from the immutable opening state: ${
                error?.message ?? String(error)
            }`,
            { investigationId: args.investigation_id },
        );
    }
    const recovery = operationalRecoveryPlan(operationalNonResult, args, deadline);
    if (operationalNonResult === null && args.reset_policy !== undefined) {
        throw new OperationalResetRequiredError(
            "reset_policy is only valid when recovering a persisted operational non-result",
        );
    }
    return createPlan({
        version: 1,
        kind: selection === null ? "reattach" : "contract_reattach",
        canonicalArgs: args,
        environment: Object.freeze({ stateRoot }),
        ...(selection === null
            ? {}
            : {
                experimentId: selection.experimentId,
                experimentIdentity: selection.experimentIdentity,
                registryVerification: selection.registryVerification,
            }),
        objective: current.aggregate.contract.objective,
        projectDir: selection?.projectDir ?? null,
        investigationId: args.investigation_id,
        paths,
        deadline,
        supervisorConfig,
        runtimeConfigAuthority,
        contract: current.aggregate.contract,
        experimentAuthority,
        verifiedExperimentAuthority,
        harnessSuite: current.aggregate.contract.harnessSuite,
        hashes: Object.freeze({
            contractHash: current.aggregate.contractHash,
            experimentAuthorityIdentity: experimentAuthority.identity,
            trustFingerprint: experimentAuthority.trustFingerprint,
            runtimeConfigFingerprint: runtimeConfigAuthority.fingerprint,
            harnessSuiteIdentity:
                current.aggregate.contract.harnessSuiteIdentity,
            harnessRoleEntryHashes: Object.freeze(Object.fromEntries(
                Object.entries(current.aggregate.contract.harnessSuite.roles)
                    .map(([role, spec]) => [role, spec.harnessEntryHash]),
            )),
        }),
        harnessVerification: suiteVerification,
        sandbox,
        promptCore: null,
        snapshotStagingPlan: null,
        existing: Object.freeze({
            mode: "reattach",
            expectedLastSeq: current.aggregate.lastSeq,
            expectedPaused: current.aggregate.pause !== null,
            expectedOperationalSeq: operationalNonResult?.seq ?? null,
            recovery,
        }),
        workspace,
    });
}

function preflightReattachInvestigation(args, deps, selection = null) {
    const stateRoot = resolveStateRoot(deps.env);
    const paths = resolveInvestigationPaths(stateRoot, args.investigation_id);
    if (!fs.existsSync(paths.eventsDbPath)) {
        throw new InvestigationNotFoundError("no Crucible investigation with this id", {
            investigationId: args.investigation_id,
        });
    }
    const configPath = supervisorPaths(
        paths.stateDir,
        args.investigation_id,
    ).configPath;
    let persistedConfig;
    try {
        persistedConfig = deps.loadSupervisorConfig(configPath, { env: deps.env });
    } catch (error) {
        authorityMismatch(
            error,
            `persisted supervisor configuration is unavailable or invalid: ${
                error?.message ?? String(error)
            }`,
            {
                investigationId: args.investigation_id,
                configPath,
            },
        );
    }
    const repository = deps.openRepositoryReadOnly({
        file: paths.eventsDbPath,
        env: deps.env,
    });
    let current;
    let operationalNonResult;
    try {
        const adapter = deps.createDomainRepositoryAdapter({
            repository,
            investigationId: args.investigation_id,
            ensure: false,
        });
        try {
            current = adapter.replay();
        } catch (error) {
            throwLegacyIncompatible(error, args.investigation_id);
        }
        if (current.aggregate.contract === null) {
            throw new StartPreflightError(
                "existing investigation repository has no frozen contract",
                { investigationId: args.investigation_id },
            );
        }
        if (current.aggregate.terminal !== null || current.aggregate.nonResults.length > 0) {
            throw new InvestigationNotResumableError(
                "Terminal and domain non-result investigations require a new investigation identity",
                {
                    investigationId: args.investigation_id,
                    status: current.aggregate.status,
                },
            );
        }
        operationalNonResult = adapter.latestOperationalNonResult();
    } finally {
        repository.close();
    }
    const verifiedExperimentAuthority = verifyPersistedExperimentAuthority(
        current.aggregate,
        deps,
        args.investigation_id,
    );
    const experimentAuthority = readVerifiedExperimentAuthority(
        verifiedExperimentAuthority,
    ).authority;
    const runtimeConfigAuthority = current.aggregate.runtimeConfigAuthority;
    if (runtimeConfigAuthority === null
        || current.aggregate.runtimeConfigFingerprint === null
        || runtimeConfigAuthority.fingerprint
            !== current.aggregate.runtimeConfigFingerprint) {
        authorityMismatch(
            null,
            "persisted investigation has no valid immutable runtime config authority",
            { investigationId: args.investigation_id },
        );
    }
    let matchedPersistedConfig;
    try {
        matchedPersistedConfig =
            assertSupervisorConfigMatchesRuntimeAuthority(
                persistedConfig,
                runtimeConfigAuthority,
                { env: deps.env },
            );
    } catch (error) {
        authorityMismatch(
            error,
            `persisted supervisor configuration was tampered: ${
                error?.message ?? String(error)
            }`,
            { investigationId: args.investigation_id },
        );
    }
    const deadline = persistedDeadline(matchedPersistedConfig, args, deps);
    let supervisorAdmission;
    try {
        const reconstructed = supervisorConfigFromRuntimeAuthority(
            runtimeConfigAuthority,
            {
                deadlineMs: deadline.deadlineMs,
                env: deps.env,
            },
        );
        supervisorAdmission = validateSupervisorAdmission(
            reconstructed,
            deps,
        );
        verifyRuntimeConfigAuthority(runtimeConfigAuthority, {
            env: deps.env,
            deadlineMs: deadline.deadlineMs,
            expectedInvestigationId: args.investigation_id,
            expectedStateDir: paths.stateDir,
            expectedArtifactRoot: paths.artifactRoot,
            nodeExecutable: supervisorAdmission.nodeExecutable,
        });
    } catch (error) {
        authorityMismatch(
            error,
            `immutable runtime configuration verification failed: ${
                error?.message ?? String(error)
            }`,
            { investigationId: args.investigation_id },
        );
    }
    const supervisorConfig = supervisorAdmission.config;

    const artifactStore = deps.openArtifactStoreReadOnly({
        root: paths.artifactRoot,
        env: deps.env,
    });
    verifyPersistedSnapshots(current.aggregate.contract, artifactStore);

    const allowlist = loadAllowlistForPreflight(
        deps,
        supervisorConfig.runner.allowlistPath,
    );
    const frozenSuite = current.aggregate.contract.harnessSuite;
    if (!suiteRequiresSandbox(frozenSuite)) {
        return reattachPlan({
            args,
            deps,
            stateRoot,
            paths,
            current,
            operationalNonResult,
            supervisorConfig,
            supervisorAdmission,
            deadline,
            allowlist,
            sandbox: Object.freeze({
                required: false,
                available: true,
                policyDigest: null,
            }),
            workspace: null,
            experimentAuthority,
            verifiedExperimentAuthority,
            runtimeConfigAuthority,
            selection,
        });
    }

    let workspace = null;
    try {
        workspace = createPreflightWorkspace({
            stateRoot,
            investigationId: args.investigation_id,
            env: deps.env,
        });
        const availability = deps.probeSandboxAvailability({
            controlRoot: workspace.sandboxControlRoot,
        });
        const finish = (resolved) => reattachPlan({
            args,
            deps,
            stateRoot,
            paths,
            current,
            operationalNonResult,
            supervisorConfig,
            supervisorAdmission,
            deadline,
            allowlist,
            sandbox: validateSandboxAvailability(resolved, frozenSuite.id),
            workspace,
            experimentAuthority,
            verifiedExperimentAuthority,
            runtimeConfigAuthority,
            selection,
        });
        if (isThenable(availability)) {
            return Promise.resolve(availability).then(finish).catch((error) => {
                cleanupWorkspace(workspace, error);
                throw error;
            });
        }
        return finish(availability);
    } catch (error) {
        cleanupWorkspace(workspace, error);
        throw error;
    }
}

function validateSandboxAvailability(availability, harnessId) {
    if (availability?.available !== true) {
        throw new SandboxUnavailableApiError(
            availability?.reason
                ?? `harness '${harnessId}' executes candidate code but the sandbox is unavailable`,
            {
                harnessId,
                code: availability?.code ?? null,
                details: availability?.details ?? null,
            },
        );
    }
    const identity = availability.policyIdentity;
    if (identity === null
        || typeof identity !== "object"
        || Array.isArray(identity)) {
        throw new SandboxUnavailableApiError(
            "sandbox availability probe did not return its explicit policy identity",
            { harnessId },
        );
    }
    return Object.freeze({
        ...identity,
        required: true,
    });
}

function cleanupWorkspace(workspace, originalError = null) {
    if (workspace === null) return;
    try {
        removePreflightWorkspace(workspace);
    } catch (cleanupError) {
        throw new StartPreflightError(
            `preflight cleanup failed: ${cleanupError?.message ?? String(cleanupError)}`,
            {
                workspace: workspace.root,
                originalError: originalError?.message ?? null,
                cleanupCause: cleanupError?.code ?? null,
            },
            { cause: cleanupError },
        );
    }
}

function createPlan(input) {
    const plan = Object.freeze(input);
    PREFLIGHT_PLANS.add(plan);
    return plan;
}

function finalizePreflight({
    args,
    deps,
    environment,
    experiment,
    registry,
    objective,
    projectDir,
    investigationId,
    paths,
    deadline,
    supervisorConfig,
    supervisorAdmission,
    workspace,
    stagingPlan,
    allowlist,
    sandbox,
    contract,
    contractDigest,
    promptCore,
    executionLimits,
    harnessVerification,
}) {
    try {
        registry.reverifyFile(deps.env);
    } catch (error) {
        throw new ExperimentRegistryApiError(
            `operator experiment registry changed during preflight: ${
                error?.message ?? String(error)
            }`,
            {
                experimentId: experiment.experimentId,
                registryPath: registry.registryPath,
                cause: error?.code ?? null,
            },
            { cause: error },
        );
    }
    let verifiedExperimentAuthority;
    try {
        verifiedExperimentAuthority = verifyExperimentAuthority({
            authority: experiment.authority,
            experimentId: experiment.experimentId,
            projectDir,
            harnessSuiteId: experiment.harnessSuiteId,
            contract,
            investigationId,
            env: deps.env,
        });
    } catch (error) {
        throw new ExperimentRegistryApiError(
            `preapproved experiment authority failed verification during preflight: ${
                error?.message ?? String(error)
            }`,
            {
                experimentId: experiment.experimentId,
                investigationId,
                cause: error?.code ?? null,
            },
            { cause: error },
        );
    }
    validateHarnessSuiteSandbox(contract.harnessSuite, sandbox);
    if (supervisorConfig.runner.options.maxLoopIterations
            < executionLimits.maxLoopIterations
        || supervisorConfig.maxRestarts < executionLimits.maxRestarts) {
        throw new StartPreflightError(
            "normalized supervisor budgets are below the frozen contract requirements",
            {
                required: executionLimits,
                maxLoopIterations:
                    supervisorConfig.runner.options.maxLoopIterations,
                maxRestarts: supervisorConfig.maxRestarts,
            },
        );
    }
    const existing = inspectExistingInvestigation({
        deps,
        paths,
        investigationId,
        requestedContractHash: contractDigest,
        requestedAuthorityIdentity: experiment.authority.identity,
        args,
        deadline,
    });
    if (existing.mode !== "new") {
        throw new StartPreflightError(
            "investigation appeared during preflight; retry crucible_start so immutable reattach admission can replay it",
            { investigationId },
        );
    }
    const runtimeConfigAuthority = buildRuntimeConfigAuthority({
        supervisorConfig,
        nodeExecutable: supervisorAdmission.nodeExecutable,
        sandbox,
        env: deps.env,
    });
    return createPlan({
        version: 1,
        kind: "new",
        canonicalArgs: args,
        environment,
        experimentId: experiment.experimentId,
        experimentIdentity: experiment.experimentIdentity,
        experimentAuthority: experiment.authority,
        registryVerification: registry.verification,
        objective,
        projectDir,
        investigationId,
        paths,
        deadline,
        supervisorConfig,
        runtimeConfigAuthority,
        contract,
        harnessSuite: contract.harnessSuite,
        verifiedExperimentAuthority,
        hashes: Object.freeze({
            contractHash: contractDigest,
            experimentIdentity: experiment.experimentIdentity,
            experimentAuthorityIdentity: experiment.authority.identity,
            authorityManifestIdentity:
                experiment.authority.manifestIdentity,
            trustFingerprint: experiment.authority.trustFingerprint,
            registryFileHash: registry.registryFileHash,
            registryIdentity: registry.registryIdentity,
            allowlistFileHash: allowlist.allowlistFileHash,
            harnessSuiteIdentity: contract.harnessSuiteIdentity,
            harnessRoleEntryHashes: Object.freeze(Object.fromEntries(
                Object.entries(contract.harnessSuite.roles)
                    .map(([role, spec]) => [role, spec.harnessEntryHash]),
            )),
            sandboxHelperSourceHash: sandbox?.helperSourceHash ?? null,
            sandboxHelperBinaryHash: sandbox?.helperBinaryHash ?? null,
            sandboxLauncherBinaryHash: sandbox?.launcherBinaryHash ?? null,
            sandboxLauncherScriptHash: sandbox?.launcherScriptHash ?? null,
            runtimeConfigFingerprint: runtimeConfigAuthority.fingerprint,
        }),
        harnessVerification,
        sandbox,
        promptCore,
        snapshotStagingPlan: stagingPlan,
        existing,
        workspace,
    });
}

export function preflightStartInvestigation(rawArgs, deps) {
    const args = crucibleStartSpec.parse(rawArgs);
    if (args.investigation_id !== undefined) {
        return preflightReattachInvestigation(args, deps);
    }
    const preapproved = loadPreapprovedExperiment(args, deps);
    const reattachStateRoot = resolveStateRoot(deps.env);
    const reattachPaths = resolveInvestigationPaths(
        reattachStateRoot,
        preapproved.investigationId,
    );
    if (fs.existsSync(reattachPaths.eventsDbPath)) {
        const reattachArgs = Object.freeze({
            investigation_id: preapproved.investigationId,
            ...(args.deadline_iso === undefined
                ? {}
                : { deadline_iso: args.deadline_iso }),
            ...(args.reset_policy === undefined
                ? {}
                : { reset_policy: args.reset_policy }),
        });
        const validate = (plan) => {
            if (plan.hashes.contractHash !== preapproved.contractDigest
                || plan.hashes.experimentAuthorityIdentity
                    !== preapproved.experiment.authority.identity) {
                disposeStartPreflight(plan, deps);
                throw new ContractConflictError(
                    "existing investigation does not match the selected authoritative experiment",
                    { investigationId: preapproved.investigationId },
                );
            }
            return plan;
        };
        const reattach = preflightReattachInvestigation(
            reattachArgs,
            deps,
            Object.freeze({
                experimentId: preapproved.experiment.experimentId,
                experimentIdentity:
                    preapproved.experiment.experimentIdentity,
                registryVerification: preapproved.registry.verification,
                projectDir: preapproved.projectDir,
            }),
        );
        return isThenable(reattach)
            ? Promise.resolve(reattach).then(validate)
            : validate(reattach);
    }
    const environment = resolveStartEnvironment(deps.env);
    const allowlist = loadAllowlistForPreflight(deps, environment.allowlistPath);
    if (!allowlist.listSuiteIds().includes(preapproved.experiment.harnessSuiteId)) {
        throw new HarnessNotAllowlistedError(
            `harness suite '${preapproved.experiment.harnessSuiteId}' has no operator allowlist entry`,
            {
                harnessSuiteId: preapproved.experiment.harnessSuiteId,
                allowlistPath: environment.allowlistPath,
            },
        );
    }
    const harnessSuite = allowlist.getSuite(preapproved.experiment.harnessSuiteId);
    const harnessSuiteIdentity = allowlist.getSuiteIdentity(
        preapproved.experiment.harnessSuiteId,
    );
    if (harnessSuiteIdentity !== preapproved.experiment.harnessSuiteIdentity
        || !canonicalEqual(harnessSuite, preapproved.contract.harnessSuite)) {
        throw new HarnessConfigurationError(
            "allowlisted HarnessSuiteV4 no longer matches the preapproved experiment",
            {
                experimentId: preapproved.experiment.experimentId,
                harnessSuiteId: preapproved.experiment.harnessSuiteId,
                expectedIdentity: preapproved.experiment.harnessSuiteIdentity,
                actualIdentity: harnessSuiteIdentity,
            },
        );
    }
    const contractDigest = preapproved.contractDigest;
    const investigationId = preapproved.investigationId;
    const paths = resolveInvestigationPaths(environment.stateRoot, investigationId);
    const deadline = normalizeDeadline(args, deps);
    const executionLimits = deriveRunnerExecutionLimits(preapproved.contract);
    const supervisorInput = buildSupervisorConfigInput({
        investigationId,
        stateDir: paths.stateDir,
        artifactRoot: paths.artifactRoot,
        allowlistPath: environment.allowlistPath,
        sdkPath: environment.sdkPath,
        cliPath: environment.cliPath,
        deadlineIso: deadline.deadlineIso,
        executionLimits,
    });
    const supervisorAdmission = validateSupervisorAdmission(
        normalizeSupervisor(supervisorInput, deps),
        deps,
    );
    const supervisorConfig = supervisorAdmission.config;
    const harnessVerification = verifyHarnessSuite(
        allowlist,
        preapproved.experiment.harnessSuiteId,
        harnessSuiteIdentity,
    );

    let workspace = null;
    try {
        workspace = createPreflightWorkspace({
            stateRoot: environment.stateRoot,
            investigationId,
            env: deps.env,
        });
        const stagingStore = deps.openArtifactStore({
            root: workspace.snapshotStoreRoot,
            env: deps.env,
        });
        const operatorStore = deps.openArtifactStoreReadOnly({
            root: environment.caseStorePath,
            env: deps.env,
        });
        const staged = stageContractSnapshots({
            sourceStore: operatorStore,
            stagingStore,
            contract: preapproved.contract,
        });
        const stagingPlan = snapshotStagingPlan(
            workspace,
            preapproved.contract,
            staged,
        );

        if (!suiteRequiresSandbox(harnessSuite)) {
            return finalizePreflight({
                args,
                deps,
                environment,
                experiment: preapproved.experiment,
                registry: preapproved.registry,
                objective: preapproved.contract.objective,
                projectDir: preapproved.projectDir,
                investigationId,
                paths,
                deadline,
                supervisorConfig,
                supervisorAdmission,
                workspace,
                stagingPlan,
                allowlist,
                sandbox: Object.freeze({
                    required: false,
                    available: true,
                    policyDigest: null,
                }),
                contract: preapproved.contract,
                contractDigest,
                promptCore: preapproved.promptCore,
                executionLimits,
                harnessVerification,
            });
        }

        let availability;
        try {
            availability = deps.probeSandboxAvailability({
                controlRoot: workspace.sandboxControlRoot,
            });
        } catch (error) {
            throw new SandboxUnavailableApiError(
                `sandbox availability probe failed: ${error?.message ?? String(error)}`,
                {
                    harnessSuiteId: preapproved.experiment.harnessSuiteId,
                    cause: error?.code ?? null,
                },
                { cause: error },
            );
        }
        if (isThenable(availability)) {
            return Promise.resolve(availability).then(
                (resolved) => finalizePreflight({
                    args,
                    deps,
                    environment,
                    experiment: preapproved.experiment,
                    registry: preapproved.registry,
                    objective: preapproved.contract.objective,
                    projectDir: preapproved.projectDir,
                    investigationId,
                    paths,
                    deadline,
                    supervisorConfig,
                    supervisorAdmission,
                    workspace,
                    stagingPlan,
                    allowlist,
                    sandbox: validateSandboxAvailability(
                        resolved,
                        preapproved.experiment.harnessSuiteId,
                    ),
                    contract: preapproved.contract,
                    contractDigest,
                    promptCore: preapproved.promptCore,
                    executionLimits,
                    harnessVerification,
                }),
                (error) => {
                    throw new SandboxUnavailableApiError(
                        `sandbox availability probe failed: ${error?.message ?? String(error)}`,
                        {
                            harnessSuiteId:
                                preapproved.experiment.harnessSuiteId,
                            cause: error?.code ?? null,
                        },
                        { cause: error },
                    );
                },
            ).catch((error) => {
                cleanupWorkspace(workspace, error);
                throw error;
            });
        }
        return finalizePreflight({
            args,
            deps,
            environment,
            experiment: preapproved.experiment,
            registry: preapproved.registry,
            objective: preapproved.contract.objective,
            projectDir: preapproved.projectDir,
            investigationId,
            paths,
            deadline,
            supervisorConfig,
            supervisorAdmission,
            workspace,
            stagingPlan,
            allowlist,
            sandbox: validateSandboxAvailability(
                availability,
                preapproved.experiment.harnessSuiteId,
            ),
            contract: preapproved.contract,
            contractDigest,
            promptCore: preapproved.promptCore,
            executionLimits,
            harnessVerification,
        });
    } catch (error) {
        cleanupWorkspace(workspace, error);
        if (error instanceof CrucibleApiError) throw error;
        throw new StartPreflightError(
            `crucible_start preflight failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
}

function requireLivePlan(plan) {
    if (!PREFLIGHT_PLANS.has(plan) || DISPOSED_PLANS.has(plan)) {
        throw new StartPreflightError("start apply requires a live preflight plan");
    }
    return plan;
}

function publishSnapshotStagingPlan(plan, deps) {
    const source = deps.openArtifactStoreReadOnly({
        root: plan.snapshotStagingPlan.root,
        env: deps.env,
    });
    const destination = deps.openArtifactStore({
        root: plan.paths.artifactRoot,
        env: deps.env,
    });
    for (const objectId of plan.snapshotStagingPlan.objectIds) {
        const bytes = source.readObject(objectId, { verify: true });
        const stored = destination.putBytes(bytes, {
            contentType: plan.snapshotStagingPlan.validationCases
                .some((validationCase) => validationCase.artifactHash === objectId)
                ? "application/vnd.crucible.snapshot+json"
                : "application/octet-stream",
        });
        if (stored.id !== objectId) {
            throw new StartPreflightError(
                "published snapshot object changed content address",
                { expected: objectId, actual: stored.id },
            );
        }
    }
}

function assertReattachState(plan, adapter) {
    let current;
    try {
        current = adapter.replay();
    } catch (error) {
        throwLegacyIncompatible(error, plan.investigationId);
    }
    const operationalNonResult = adapter.latestOperationalNonResult();
    if (current.aggregate.contractHash !== plan.hashes.contractHash
        || current.aggregate.experimentAuthorityIdentity
            !== plan.hashes.experimentAuthorityIdentity
        || current.aggregate.runtimeConfigFingerprint
            !== plan.hashes.runtimeConfigFingerprint
        || current.aggregate.lastSeq !== plan.existing.expectedLastSeq
        || (current.aggregate.pause !== null) !== plan.existing.expectedPaused
        || (operationalNonResult?.seq ?? null) !== plan.existing.expectedOperationalSeq
        || current.aggregate.terminal !== null
        || current.aggregate.nonResults.length > 0) {
        throw new StartPreflightError(
            "investigation changed after preflight; retry crucible_start",
            { investigationId: plan.investigationId },
        );
    }
    return { current, operationalNonResult };
}

function applyContractPlan(plan, adapter, verifiedExperimentAuthority) {
    if (plan.existing.mode === "new") {
        const current = adapter.replay();
        if (current.aggregate.contract !== null) {
            throw new StartPreflightError(
                "investigation was opened concurrently after preflight; retry crucible_start",
                { investigationId: plan.investigationId },
            );
        }

        const opened = adapter.openInvestigation(
            plan.contract,
            verifiedExperimentAuthority,
            plan.runtimeConfigAuthority,
        );
        return {
            idempotent: false,
            aggregate: opened.aggregate,
            resumed: false,
            operationalRecovery: null,
        };
    }

    const { current, operationalNonResult } = assertReattachState(plan, adapter);
    if (plan.existing.recovery !== null) {
        adapter.recordOperationalRecovery({
            attemptId:
                `recovery-${operationalNonResult.seq}-${plan.existing.recovery.policy}`,
            previousSeq: operationalNonResult.seq,
            policy: plan.existing.recovery.policy,
            reason: plan.existing.recovery.reason,
            details: plan.existing.recovery.details,
        });
    }
    const resumed = plan.existing.expectedPaused
        ? adapter.resumeInvestigation()
        : { aggregate: current.aggregate, domainEvent: null };
    return {
        idempotent: true,
        aggregate: resumed.aggregate,
        resumed: resumed.domainEvent !== null,
        operationalRecovery: plan.existing.recovery,
    };
}

function compensateFailedReattach(plan, adapter, cause) {
    const current = adapter.replay();
    if (current.aggregate.terminal !== null
        || current.aggregate.nonResults.length > 0
        || current.aggregate.pause !== null) {
        return current.aggregate;
    }
    adapter.requestStop({
        requestId: `resume-compensation-${current.aggregate.lastSeq + 1}`,
        reason:
            `Resume admission failed after persistence (${cause?.code ?? "START_FAILED"}); `
            + "the investigation was returned to a durable pause.",
        pauseRequested: true,
    });
    const paused = adapter.appendKernelDecision();
    if (paused.aggregate.pause === null) {
        throw new StartFailedError(
            "failed resume could not be compensated with a durable pause",
            {
                investigationId: plan.investigationId,
                cause: cause?.code ?? null,
            },
            { cause },
        );
    }
    return paused.aggregate;
}

function supervisorStartAccepted(supervisor) {
    return ["started", "already-running"].includes(supervisor?.action)
        && supervisor?.acknowledged === true
        && Number.isSafeInteger(supervisor?.acknowledgement?.supervisorGeneration)
        && typeof supervisor?.acknowledgement?.runnerIncarnation === "string"
        && supervisor.acknowledgement.runnerIncarnation.length > 0
        && typeof supervisor?.acknowledgement?.configFingerprint === "string"
        && Object.hasOwn(supervisor.acknowledgement, "deadlineMs");
}

function ensureOwnedInvestigationDirectory(plan) {
    if (fs.existsSync(plan.paths.investigationDir)) {
        throw new StartPreflightError(
            "investigation directory appeared after preflight; retry crucible_start",
            { investigationDir: plan.paths.investigationDir },
        );
    }
    const createdStateRoot = !fs.existsSync(plan.environment.stateRoot);
    try {
        fs.mkdirSync(plan.environment.stateRoot, { recursive: true });
        fs.mkdirSync(plan.paths.investigationDir);
        return Object.freeze({ createdStateRoot });
    } catch (error) {
        if (createdStateRoot) {
            try {
                fs.rmdirSync(plan.environment.stateRoot);
            } catch {
                // Preserve the directory-creation failure; cleanup is retried by
                // the outer apply guard if this process owns an investigation.
            }
        }
        throw error;
    }
}

function cleanupFailedNewApply(plan, ownership) {
    fs.rmSync(plan.paths.investigationDir, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 50,
    });
    if (ownership?.createdStateRoot === true) {
        try {
            fs.rmdirSync(plan.environment.stateRoot);
        } catch (error) {
            if (!["ENOENT", "ENOTEMPTY"].includes(error?.code)) throw error;
        }
    }
}

export function applyStartPreflight(plan, deps) {
    requireLivePlan(plan);
    const isNew = plan.existing.mode === "new";
    let ownership = null;
    let repository = null;
    let adapter = null;
    let durableApplied = false;

    const closeRepository = () => {
        if (repository !== null) {
            repository.close();
            repository = null;
            adapter = null;
        }
    };
    const compensate = (cause) => {
        if (!durableApplied) return;
        if (adapter !== null) {
            compensateFailedReattach(plan, adapter, cause);
            return;
        }
        const compensationRepository = deps.openRepository({
            file: plan.paths.eventsDbPath,
            env: deps.env,
        });
        try {
            compensateFailedReattach(
                plan,
                deps.createDomainRepositoryAdapter({
                    repository: compensationRepository,
                    investigationId: plan.investigationId,
                }),
                cause,
            );
        } finally {
            compensationRepository.close();
        }
    };
    const fail = (error) => {
        if (durableApplied) {
            try {
                compensate(error);
            } catch (compensationError) {
                closeRepository();
                throw compensationError;
            }
        } else {
            closeRepository();
            if (isNew && ownership !== null) {
                cleanupFailedNewApply(plan, ownership);
            }
        }
        closeRepository();
        if (error instanceof CrucibleApiError) throw error;
        throw new StartFailedError(
            `crucible_start apply failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    };

    let verifiedExperimentAuthority;
    try {
        try {
            const payload =
                plan.experimentAuthority.manifest.experimentPayload;
            verifiedExperimentAuthority = verifyExperimentAuthority({
                authority: plan.experimentAuthority,
                experimentId: payload.experimentId,
                projectDir: payload.projectDir,
                harnessSuiteId: payload.harnessSuiteId,
                contract: plan.contract,
                investigationId: plan.investigationId,
                env: deps.env,
            });
        } catch (error) {
            authorityMismatch(
                error,
                `experiment authority changed after preflight: ${
                    error?.message ?? String(error)
                }`,
                {
                    investigationId: plan.investigationId,
                    persistedTrustFingerprint:
                        plan.experimentAuthority?.trustFingerprint ?? null,
                },
            );
        }
        try {
            assertSupervisorConfigMatchesRuntimeAuthority(
                plan.supervisorConfig,
                plan.runtimeConfigAuthority,
                { env: deps.env },
            );
            const admission = validateSupervisorAdmission(
                plan.supervisorConfig,
                deps,
            );
            verifyRuntimeConfigAuthority(plan.runtimeConfigAuthority, {
                env: deps.env,
                deadlineMs: plan.deadline.deadlineMs,
                expectedInvestigationId: plan.investigationId,
                expectedStateDir: plan.paths.stateDir,
                expectedArtifactRoot: plan.paths.artifactRoot,
                nodeExecutable: admission.nodeExecutable,
                sandbox: plan.sandbox,
            });
        } catch (error) {
            authorityMismatch(
                error,
                `runtime configuration changed after preflight: ${
                    error?.message ?? String(error)
                }`,
                {
                    investigationId: plan.investigationId,
                    runtimeConfigFingerprint:
                        plan.runtimeConfigAuthority?.fingerprint ?? null,
                },
            );
        }
        if (plan.registryVerification !== undefined
            && plan.registryVerification !== null) {
            try {
                (deps.reverifyExperimentRegistryFile
                    ?? reverifyExperimentRegistryFile)(
                    plan.registryVerification,
                    { env: deps.env },
                );
            } catch (error) {
                throw new ExperimentRegistryApiError(
                    `operator experiment registry changed after preflight: ${
                        error?.message ?? String(error)
                    }`,
                    {
                        experimentId: plan.experimentId,
                        registryPath:
                            plan.registryVerification.registryPath,
                        cause: error?.code ?? null,
                    },
                    { cause: error },
                );
            }
        }
        if (isNew) {
            ownership = ensureOwnedInvestigationDirectory(plan);
        }
        if (plan.snapshotStagingPlan !== null) {
            publishSnapshotStagingPlan(plan, deps);
        }
        fs.mkdirSync(plan.paths.stateDir, { recursive: true });
        repository = deps.openRepository({
            file: plan.paths.eventsDbPath,
            env: deps.env,
        });
        adapter = deps.createDomainRepositoryAdapter({
            repository,
            investigationId: plan.investigationId,
        });
        const opened = applyContractPlan(
            plan,
            adapter,
            verifiedExperimentAuthority,
        );
        durableApplied = true;
        const acceptSupervisor = (supervisor) => {
            if (!supervisorStartAccepted(supervisor)) {
                throw new StartFailedError(
                    `supervisor did not acknowledge the expected runtime authority (${
                        supervisor?.reason ?? supervisor?.action ?? "unknown"
                    })`,
                    {
                        investigationId: plan.investigationId,
                        action: supervisor?.action ?? null,
                        reason: supervisor?.reason ?? null,
                        acknowledged: supervisor?.acknowledged === true,
                    },
                );
            }
            return Object.freeze({ opened, supervisor });
        };
        const ensured = deps.ensureSupervisor(plan.supervisorConfig, {
            env: deps.env,
            resetOperationalState:
                opened.resumed || opened.operationalRecovery !== null,
            requireAcknowledgement: true,
        });
        if (isThenable(ensured)) {
            return Promise.resolve(ensured)
                .then(acceptSupervisor)
                .then(
                    (result) => {
                        closeRepository();
                        return result;
                    },
                    (error) => fail(error),
                );
        }
        const result = acceptSupervisor(ensured);
        closeRepository();
        return result;
    } catch (error) {
        return fail(error);
    }
}

export function disposeStartPreflight(plan, dependencies = {}) {
    if (!PREFLIGHT_PLANS.has(plan) || DISPOSED_PLANS.has(plan)) {
        return false;
    }
    const removeWorkspace =
        dependencies.removePreflightWorkspace
        ?? removePreflightWorkspace;
    if (plan.workspace !== null) {
        try {
            removeWorkspace(plan.workspace);
        } catch (cleanupError) {
            throw new StartPreflightError(
                `preflight cleanup failed: ${
                    cleanupError?.message ?? String(cleanupError)
                }`,
                {
                    originalCause: null,
                    cleanupCause: cleanupError?.code ?? null,
                },
                { cause: cleanupError },
            );
        }
    }
    DISPOSED_PLANS.add(plan);
    return true;
}
