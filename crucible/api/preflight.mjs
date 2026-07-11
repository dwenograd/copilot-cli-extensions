// Single crucible_start preflight/apply boundary. Preflight may read trusted
// inputs and build a disposable isolated snapshot/sandbox workspace, but it
// never creates or mutates investigation state. Apply consumes only the
// branded canonical plan returned here; it never reinterprets raw tool args.

import fs from "node:fs";
import path from "node:path";

import {
    DEFAULT_SEARCH_POLICY,
    contractHash,
    createInvestigationContract,
} from "../domain/index.mjs";
import {
    PARSER_VERSION,
    buildFrozenHarnessIdentity,
    verifyFrozenHarnessIdentity,
    verifyHarnessPreflight,
} from "../measurement/index.mjs";
import { assertLocalDatabasePath } from "../persistence/index.mjs";
import {
    assertPromptContractCoreFits,
    deriveRunnerExecutionLimits,
    normalizeStartDeadline,
    supervisorPaths,
} from "../runtime/index.mjs";
import {
    CRITICALITY,
    POLICY_VERSION,
    buildSupervisorConfigInput,
    canonicalObjective,
    createPreflightWorkspace,
    deriveInvestigationId,
    removePreflightWorkspace,
    resolveInvestigationPaths,
    resolveStateRoot,
    resolveStartEnvironment,
} from "./environment.mjs";
import {
    ContractConflictError,
    CrucibleApiError,
    HarnessConfigurationError,
    HarnessNotAllowlistedError,
    InvestigationNotFoundError,
    InvestigationNotResumableError,
    OperationalResetRequiredError,
    SandboxUnavailableApiError,
    StartFailedError,
    StartPreflightError,
    ValidationCasePathError,
} from "./errors.mjs";
import { crucibleStartSpec } from "./schema.mjs";

const PREFLIGHT_PLANS = new WeakSet();
const DISPOSED_PLANS = new WeakSet();

function isThenable(value) {
    return value !== null
        && (typeof value === "object" || typeof value === "function")
        && typeof value.then === "function";
}

function isInside(childAbs, parentAbs) {
    const relative = path.relative(path.resolve(parentAbs), path.resolve(childAbs));
    return relative === ""
        || (!relative.startsWith(`..${path.sep}`)
            && relative !== ".."
            && !path.isAbsolute(relative));
}

function resolveProjectDir(projectDir, env) {
    if (typeof projectDir !== "string" || !path.isAbsolute(projectDir)) {
        throw new ValidationCasePathError("project_dir must be an absolute path", { projectDir });
    }
    let local;
    try {
        local = assertLocalDatabasePath(projectDir, { env });
    } catch (error) {
        throw new ValidationCasePathError(
            `project_dir must be on a trusted local filesystem: ${error?.message ?? String(error)}`,
            { projectDir },
        );
    }
    let real;
    try {
        real = fs.realpathSync.native(local);
    } catch {
        throw new ValidationCasePathError("project_dir does not exist", { projectDir });
    }
    if (!fs.statSync(real).isDirectory()) {
        throw new ValidationCasePathError("project_dir is not a directory", { projectDir });
    }
    return real;
}

function resolveCasePathInside(projectRoot, candidate) {
    const abs = path.isAbsolute(candidate) ? candidate : path.join(projectRoot, candidate);
    let link;
    try {
        link = fs.lstatSync(abs);
    } catch {
        throw new ValidationCasePathError("validation case path does not exist", { path: candidate });
    }
    if (link.isSymbolicLink()) {
        throw new ValidationCasePathError("validation case path must not be a symlink", {
            path: candidate,
        });
    }
    let real;
    try {
        real = fs.realpathSync.native(abs);
    } catch {
        throw new ValidationCasePathError("validation case path does not exist", { path: candidate });
    }
    if (!isInside(real, projectRoot)) {
        throw new ValidationCasePathError("validation case path escapes project_dir", {
            path: candidate,
            projectDir: projectRoot,
        });
    }
    if (!fs.statSync(real).isDirectory()) {
        throw new ValidationCasePathError("validation case path must be a directory", {
            path: candidate,
        });
    }
    return real;
}

function placeholderSnapshot(index) {
    return `sha256:${index.toString(16).padStart(64, "0")}`;
}

function placeholderHarnessIdentity(harnessId) {
    const hash = (label) => `sha256:${label}:${"0".repeat(64)}`;
    return {
        version: 1,
        harnessId,
        allowlistVersion: 1,
        allowlistFileHash: hash("crucible-measurement-file-v1"),
        harnessEntryHash: hash("crucible-measurement-entry-v1"),
        executableHash: hash("crucible-measurement-file-v1"),
        dependencyHashes: [],
        argvTemplateHash: hash("crucible-measurement-argv-template-v1"),
        allowedEnvHash: hash("crucible-measurement-env-policy-v1"),
        parserVersion: PARSER_VERSION,
        parserVersionHash: hash("crucible-measurement-parser-version-v1"),
        parserSourceHash: hash("crucible-measurement-parser-source-v1"),
        executesCandidateCode: false,
        sandbox: {
            required: false,
            policyIdentity: null,
            policyDigest: null,
        },
    };
}

function contractInput(args, objective, validationCases, harnessIdentity) {
    return {
        objective,
        acceptancePredicate: args.acceptance_predicate,
        validationCases,
        harnessId: args.harness_id,
        harnessIdentity,
        hypothesisTopology: args.hypothesis_topology,
        criticality: CRITICALITY,
        policyVersion: POLICY_VERSION,
        parserVersion: PARSER_VERSION,
        workerModels: args.worker_models,
        candidatesPerRound: args.candidates_per_round,
        maxRounds: args.max_rounds,
        searchPolicy: args.search_policy ?? DEFAULT_SEARCH_POLICY,
        ...(args.bounded_candidate_ids === undefined
            ? {}
            : { boundedCandidateIds: args.bounded_candidate_ids }),
        metrics: args.metrics,
        declaredLimits: {},
    };
}

function validateContractShape(args, objective) {
    const validationCases = args.validation_cases.map((validationCase, index) => ({
        id: validationCase.id,
        expectation: validationCase.expectation,
        artifactHash: placeholderSnapshot(index + 1),
    }));
    try {
        const contract = createInvestigationContract(
            contractInput(
                args,
                objective,
                validationCases,
                placeholderHarnessIdentity(args.harness_id),
            ),
        );
        const promptCore = assertPromptContractCoreFits(contract);
        return { contract, promptCore };
    } catch (error) {
        throw new StartPreflightError(
            `crucible_start contract validation failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
}

function stageValidationCases(store, projectRoot, cases, env) {
    return cases.map((validationCase) => {
        const sourceDir = resolveCasePathInside(projectRoot, validationCase.path);
        let ingested;
        try {
            ingested = store.ingestDirectory({ sourceDir, env });
        } catch (error) {
            throw new ValidationCasePathError(
                `validation case '${validationCase.id}' could not be staged: ${error?.message ?? String(error)}`,
                { id: validationCase.id, path: validationCase.path, code: error?.code ?? null },
            );
        }
        return Object.freeze({
            id: validationCase.id,
            expectation: validationCase.expectation,
            artifactHash: ingested.snapshot,
            objectIds: Object.freeze([
                ...new Set([
                    ...ingested.manifest.entries.map((entry) => entry.object),
                    ingested.snapshot,
                ]),
            ].sort()),
        });
    });
}

function snapshotStagingPlan(workspace, validationCases) {
    return Object.freeze({
        root: workspace.snapshotStoreRoot,
        validationCases: Object.freeze(validationCases.map((validationCase) =>
            Object.freeze({
                id: validationCase.id,
                expectation: validationCase.expectation,
                artifactHash: validationCase.artifactHash,
            }))),
        objectIds: Object.freeze([
            ...new Set(validationCases.flatMap((validationCase) => validationCase.objectIds)),
        ].sort()),
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
        const current = adapter.replay();
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

function verifyHarness(allowlist, harnessId, validationCases) {
    try {
        return verifyHarnessPreflight(allowlist, harnessId, {
            validationCases,
            parserVersion: PARSER_VERSION,
        });
    } catch (error) {
        throw new HarnessConfigurationError(
            `harness preflight failed: ${error?.message ?? String(error)}`,
            { harnessId, cause: error?.code ?? null, details: error?.details ?? null },
            { cause: error },
        );
    }
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

function persistedSupervisorInput(config, deadline) {
    return {
        runner: {
            investigationId: config.runner.investigationId,
            stateDir: config.runner.stateDir,
            artifactRoot: config.runner.artifactRoot,
            allowlistPath: config.runner.allowlistPath,
            copilotSdkPath: config.runner.sdkPath,
            copilotCliPath: config.runner.cliPath,
            runnerEpochId: config.runner.runnerEpochId,
            ...(deadline.deadlineMs === null ? {} : { deadline: deadline.deadlineMs }),
            options: config.runner.options,
        },
        runnerCliPath: config.runnerCliPath,
        supervisorEpochId: config.supervisorEpochId,
        maxRestarts: config.maxRestarts,
        baseBackoffMs: config.baseBackoffMs,
        maxBackoffMs: config.maxBackoffMs,
        heartbeatIntervalMs: config.heartbeatIntervalMs,
        staleLockMs: config.staleLockMs,
        circuitWindowMs: config.circuitWindowMs,
    };
}

function validateSupervisorAdmission(config, deps) {
    if (typeof deps.validateSupervisorAdmission !== "function") return config;
    try {
        const admitted = deps.validateSupervisorAdmission(config, { env: deps.env });
        return admitted?.config ?? config;
    } catch (error) {
        throw new StartPreflightError(
            `supervisor admission preflight failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
}

function verifyPersistedSnapshots(contract, artifactStore) {
    for (const validationCase of contract.validationCases) {
        const verification = artifactStore.verifySnapshot(validationCase.artifactHash);
        if (verification?.ok !== true) {
            throw new StartPreflightError(
                `persisted validation snapshot '${validationCase.id}' failed verification`,
                {
                    id: validationCase.id,
                    artifactHash: validationCase.artifactHash,
                    verification,
                },
            );
        }
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
    deadline,
    allowlist,
    sandbox,
    workspace,
}) {
    let identityVerification;
    try {
        identityVerification = verifyFrozenHarnessIdentity(
            allowlist,
            current.aggregate.contract.harnessIdentity,
            {
                validationCases: current.aggregate.contract.validationCases,
                sandbox,
            },
        );
    } catch (error) {
        throw new HarnessConfigurationError(
            `frozen harness identity verification failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null, details: error?.details ?? null },
            { cause: error },
        );
    }
    const recovery = operationalRecoveryPlan(operationalNonResult, args, deadline);
    if (operationalNonResult === null && args.reset_policy !== undefined) {
        throw new OperationalResetRequiredError(
            "reset_policy is only valid when recovering a persisted operational non-result",
        );
    }
    const identity = current.aggregate.contract.harnessIdentity;
    return createPlan({
        version: 1,
        kind: "reattach",
        canonicalArgs: args,
        environment: Object.freeze({ stateRoot }),
        objective: current.aggregate.contract.objective,
        projectDir: null,
        investigationId: args.investigation_id,
        paths,
        deadline,
        supervisorConfig,
        contract: current.aggregate.contract,
        harnessIdentity: identity,
        hashes: Object.freeze({
            contractHash: current.aggregate.contractHash,
            allowlistFileHash: identity.allowlistFileHash,
            harnessEntryHash: identity.harnessEntryHash,
            executableHash: identity.executableHash,
            dependencyHashes: identity.dependencyHashes,
            argvTemplateHash: identity.argvTemplateHash,
            allowedEnvHash: identity.allowedEnvHash,
            parserVersionHash: identity.parserVersionHash,
            parserSourceHash: identity.parserSourceHash,
            sandboxPolicyDigest: identity.sandbox.policyDigest,
        }),
        harnessVerification: identityVerification.verification,
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

function preflightReattachInvestigation(args, deps) {
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
        throw new StartPreflightError(
            `persisted supervisor configuration is unavailable: ${error?.message ?? String(error)}`,
            { configPath, cause: error?.code ?? null },
            { cause: error },
        );
    }
    if (persistedConfig.runner.investigationId !== args.investigation_id
        || !samePath(persistedConfig.runner.stateDir, paths.stateDir)
        || !samePath(persistedConfig.runner.artifactRoot, paths.artifactRoot)) {
        throw new StartPreflightError(
            "persisted supervisor configuration does not belong to this investigation",
            { investigationId: args.investigation_id },
        );
    }
    const deadline = persistedDeadline(persistedConfig, args, deps);
    const supervisorConfig = validateSupervisorAdmission(
        normalizeSupervisor(
            persistedSupervisorInput(persistedConfig, deadline),
            deps,
        ),
        deps,
    );

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
        current = adapter.replay();
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

    const artifactStore = deps.openArtifactStoreReadOnly({
        root: paths.artifactRoot,
        env: deps.env,
    });
    verifyPersistedSnapshots(current.aggregate.contract, artifactStore);

    const allowlist = loadAllowlistForPreflight(
        deps,
        persistedConfig.runner.allowlistPath,
    );
    const frozenIdentity = current.aggregate.contract.harnessIdentity;
    if (!frozenIdentity.executesCandidateCode) {
        return reattachPlan({
            args,
            deps,
            stateRoot,
            paths,
            current,
            operationalNonResult,
            supervisorConfig,
            deadline,
            allowlist,
            sandbox: Object.freeze({ required: false, available: true }),
            workspace: null,
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
            deadline,
            allowlist,
            sandbox: validateSandboxAvailability(resolved, frozenIdentity.harnessId),
            workspace,
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
    objective,
    projectDir,
    investigationId,
    paths,
    deadline,
    supervisorConfig,
    workspace,
    stagedCases,
    stagingPlan,
    allowlist,
    sandbox,
    harnessVerification: verifiedHarness = null,
}) {
    const harnessVerification = verifiedHarness ?? verifyHarness(
        allowlist,
        args.harness_id,
        stagedCases,
    );
    const harnessIdentity = buildFrozenHarnessIdentity(harnessVerification, {
        sandbox,
    });
    let contract;
    let promptCore;
    try {
        contract = createInvestigationContract(
            contractInput(
                args,
                objective,
                stagingPlan.validationCases,
                harnessIdentity,
            ),
        );
        promptCore = assertPromptContractCoreFits(contract);
    } catch (error) {
        throw new StartPreflightError(
            `canonical contract creation failed: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null },
            { cause: error },
        );
    }
    const contractDigest = contractHash(contract);
    const executionLimits = deriveRunnerExecutionLimits(contract);
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
        args,
        deadline,
    });
    return createPlan({
        version: 1,
        kind: existing.mode === "new" ? "new" : "contract_reattach",
        canonicalArgs: args,
        environment,
        objective,
        projectDir,
        investigationId,
        paths,
        deadline,
        supervisorConfig,
        contract,
        harnessIdentity,
        hashes: Object.freeze({
            contractHash: contractDigest,
            allowlistFileHash: harnessVerification.allowlistFileHash,
            harnessEntryHash: harnessVerification.harnessEntryHash,
            executableHash: harnessVerification.executableHash,
            dependencyHashes: harnessVerification.dependencyHashes,
            argvTemplateHash: harnessVerification.argvTemplateHash,
            allowedEnvHash: harnessVerification.allowedEnvHash,
            parserVersionHash: harnessVerification.parserVersionHash,
            parserSourceHash: harnessVerification.parserSourceHash,
            sandboxHelperSourceHash: sandbox?.helperSourceHash ?? null,
            sandboxHelperBinaryHash: sandbox?.helperBinaryHash ?? null,
            sandboxLauncherBinaryHash: sandbox?.launcherBinaryHash ?? null,
            sandboxLauncherScriptHash: sandbox?.launcherScriptHash ?? null,
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
    const environment = resolveStartEnvironment(deps.env);
    const objective = canonicalObjective(args.objective);
    const projectDir = resolveProjectDir(args.project_dir, deps.env);
    const allowlist = loadAllowlistForPreflight(deps, environment.allowlistPath);
    if (!allowlist.listEntryIds().includes(args.harness_id)) {
        throw new HarnessNotAllowlistedError(
            `harness '${args.harness_id}' has no operator allowlist entry`,
            { harnessId: args.harness_id, allowlistPath: environment.allowlistPath },
        );
    }
    const investigationId = deriveInvestigationId({
        objective,
        projectDir,
        harnessId: args.harness_id,
        harnessEntryHash: allowlist.getEntryHash(args.harness_id),
    });
    const paths = resolveInvestigationPaths(environment.stateRoot, investigationId);
    const deadline = normalizeDeadline(args, deps);
    const contractShape = validateContractShape(args, objective);
    const executionLimits = deriveRunnerExecutionLimits(contractShape.contract);
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
    const supervisorConfig = validateSupervisorAdmission(
        normalizeSupervisor(supervisorInput, deps),
        deps,
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
        const stagedCases = stageValidationCases(
            stagingStore,
            projectDir,
            args.validation_cases,
            deps.env,
        );
        const stagingPlan = snapshotStagingPlan(workspace, stagedCases);
        const initialHarnessVerification = verifyHarness(
            allowlist,
            args.harness_id,
            stagedCases,
        );

        if (!initialHarnessVerification.entry.executesCandidateCode) {
            return finalizePreflight({
                args,
                deps,
                environment,
                objective,
                projectDir,
                investigationId,
                paths,
                deadline,
                supervisorConfig,
                workspace,
                stagedCases,
                stagingPlan,
                allowlist,
                sandbox: Object.freeze({ required: false, available: true }),
                harnessVerification: initialHarnessVerification,
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
                { harnessId: args.harness_id, cause: error?.code ?? null },
                { cause: error },
            );
        }
        if (isThenable(availability)) {
            return Promise.resolve(availability).then(
                (resolved) => finalizePreflight({
                    args,
                    deps,
                    environment,
                    objective,
                    projectDir,
                    investigationId,
                    paths,
                    deadline,
                    supervisorConfig,
                    workspace,
                    stagedCases,
                    stagingPlan,
                    allowlist,
                    sandbox: validateSandboxAvailability(resolved, args.harness_id),
                }),
                (error) => {
                    throw new SandboxUnavailableApiError(
                        `sandbox availability probe failed: ${error?.message ?? String(error)}`,
                        { harnessId: args.harness_id, cause: error?.code ?? null },
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
            objective,
            projectDir,
            investigationId,
            paths,
            deadline,
            supervisorConfig,
            workspace,
            stagedCases,
            stagingPlan,
            allowlist,
            sandbox: validateSandboxAvailability(availability, args.harness_id),
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
    const current = adapter.replay();
    const operationalNonResult = adapter.latestOperationalNonResult();
    if (current.aggregate.contractHash !== plan.hashes.contractHash
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

function applyContractPlan(plan, adapter) {
    if (plan.existing.mode === "new") {
        const current = adapter.replay();
        if (current.aggregate.contract !== null) {
            throw new StartPreflightError(
                "investigation was opened concurrently after preflight; retry crucible_start",
                { investigationId: plan.investigationId },
            );
        }

        const opened = adapter.openInvestigation(plan.contract);
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

    try {
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
        const opened = applyContractPlan(plan, adapter);
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
