// crucible/api/handlers.mjs
//
// The four Crucible tool handlers plus the single SDK error boundary and the
// production runtime wiring. Design rules enforced here:
//
//   * Internal handlers THROW typed errors; only `runToolBoundary` catches, at
//     the SDK edge, converting to a structured `{ textResultForLlm, resultType }`.
//   * All environment/state resolution goes through api/environment.mjs; no tool
//     argument ever selects a filesystem path, harness allowlist, or CLI.
//   * Domain scoring/policy is never recomputed for results: crucible_result reads
//     the persisted terminal decision and reports it (or redacts a non-result).
//   * Diagnostics go only through the injected `log` (session.log), never stdout.
//
// Every runtime collaborator is injectable via `deps` so handler tests can run
// with fakes; `makeDefaultDeps` supplies the real modules in production.

import fs from "node:fs";
import path from "node:path";

import {
    DEFAULT_SEARCH_POLICY,
    SEARCH_OPERATORS,
    buildCandidateArchive,
    contractHash,
    createInvestigationContract,
    decideNext,
    detectPlateau,
    harnessCandidateEvidenceItems,
    qualifyingCandidateEvidence,
    qualifyingCandidateEvidenceItems,
    searchProgress,
} from "../domain/index.mjs";
import {
    assertLocalDatabasePath,
    openArtifactStore,
    openArtifactStoreReadOnly,
    openRepository,
    openRepositoryReadOnly,
} from "../persistence/index.mjs";
import { PARSER_VERSION, loadHarnessAllowlist } from "../measurement/index.mjs";
import {
    createDomainRepositoryAdapter,
    ensureSupervisor,
    isExactPidAlive,
    loadSupervisorConfig,
    readSupervisorLock,
    readStatus,
    requestStop,
    supervisorPaths,
} from "../runtime/index.mjs";

import {
    CRITICALITY,
    POLICY_VERSION,
    buildSupervisorConfigInput,
    canonicalObjective,
    deriveInvestigationId,
    resolveInvestigationPaths,
    resolveStartEnvironment,
    resolveStateRoot,
} from "./environment.mjs";
import { TOOL_SPECS } from "./schema.mjs";
import {
    NON_RESULT_BANNER,
    TERMINAL_BANNER,
    INTEGRITY_NON_RESULT_BANNER,
    failure,
    success,
} from "./result.mjs";
import {
    ContractConflictError,
    HarnessNotAllowlistedError,
    InvestigationNotResumableError,
    InvestigationNotFoundError,
    OperationalResetRequiredError,
    CrucibleApiError,
    ValidationCasePathError,
} from "./errors.mjs";

const TERMINAL_DECISIONS = Object.freeze(["VERIFIED_RESULT", "TARGET_UNREACHABLE"]);

// --- production runtime wiring ---------------------------------------------

export function makeDefaultDeps(env = process.env, log = () => {}) {
    return {
        env,
        log,
        isPidAlive: isExactPidAlive,
        loadHarnessAllowlist,
        openRepository,
        openRepositoryReadOnly,
        openArtifactStore,
        openArtifactStoreReadOnly,
        createDomainRepositoryAdapter,
        ensureSupervisor,
        readStatus,
        requestStop,
        loadSupervisorConfig,
        readSupervisorLock,
    };
}

// --- shared path helpers ----------------------------------------------------

function isInside(childAbs, parentAbs) {
    const relative = path.relative(path.resolve(parentAbs), path.resolve(childAbs));
    return relative === ""
        || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
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

// Resolve a validation-case path, refusing anything that (after symlink
// resolution) escapes projectDir. The ArtifactStore performs the deeper
// symlink/traversal checks during ingestion.
function resolveCasePathInside(projectRoot, candidate) {
    const abs = path.isAbsolute(candidate) ? candidate : path.join(projectRoot, candidate);
    // Refuse a symlink case directory outright (the ArtifactStore also refuses a
    // symlink sourceDir; this is a clear, early refusal at the API edge).
    let link;
    try {
        link = fs.lstatSync(abs);
    } catch {
        throw new ValidationCasePathError("validation case path does not exist", { path: candidate });
    }
    if (link.isSymbolicLink()) {
        throw new ValidationCasePathError("validation case path must not be a symlink", { path: candidate });
    }
    // Resolve symlinked ancestors and confirm containment on the real path, so a
    // parent symlink/junction cannot smuggle content out of project_dir.
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
        throw new ValidationCasePathError("validation case path must be a directory", { path: candidate });
    }
    return real;
}

function ingestValidationCases(store, projectRoot, cases, env) {
    return cases.map((validationCase) => {
        const sourceDir = resolveCasePathInside(projectRoot, validationCase.path);
        let ingested;
        try {
            ingested = store.ingestDirectory({ sourceDir, env });
        } catch (error) {
            throw new ValidationCasePathError(
                `validation case '${validationCase.id}' could not be ingested: ${error?.message ?? String(error)}`,
                { id: validationCase.id, path: validationCase.path, code: error?.code ?? null },
            );
        }
        return {
            id: validationCase.id,
            expectation: validationCase.expectation,
            artifactHash: ingested.snapshot,
        };
    });
}

function openInvestigationForRead(deps, investigationId, paths) {
    const { eventsDbPath, artifactRoot } = paths;
    if (!fs.existsSync(eventsDbPath)) {
        throw new InvestigationNotFoundError("no Crucible investigation with this id", {
            investigationId,
        });
    }
    const repository = deps.openRepositoryReadOnly({
        file: eventsDbPath,
        env: deps.env,
    });
    try {
        const adapter = deps.createDomainRepositoryAdapter({
            repository,
            investigationId,
            ensure: false,
        });
        const artifactStore = deps.openArtifactStoreReadOnly({
            root: artifactRoot,
            env: deps.env,
        });
        // This performs repository/domain replay plus complete terminal artifact
        // closure verification. Both persistence handles are read-only.
        const replay = adapter.verifyTerminalArtifactClosure({ artifactStore });
        const operationalNonResult = adapter.latestOperationalNonResult();
        return {
            aggregate: replay.aggregate,
            operationalNonResult,
            artifactClosureReport: replay.artifactClosureReport,
        };
    } finally {
        repository.close();
    }
}

// --- crucible_start -----------------------------------------------------------

function operationalRecoveryPolicy(operationalNonResult, args) {
    if (operationalNonResult === null) return null;
    const payload = operationalNonResult.payload ?? {};
    const code = payload.code ?? "UNKNOWN_OPERATIONAL_FAILURE";
    if (code === "DEADLINE_EXCEEDED") {
        const previousDeadline = payload.details?.deadlineMs;
        const requestedDeadline = typeof args.deadline_iso === "string"
            ? Date.parse(args.deadline_iso)
            : Number.NaN;
        if (!Number.isFinite(previousDeadline)
            || !Number.isFinite(requestedDeadline)
            || requestedDeadline <= previousDeadline) {
            throw new OperationalResetRequiredError(
                "A deadline non-result requires crucible_start with an explicit later deadline_iso",
                { code, previousDeadline, requestedDeadline: Number.isFinite(requestedDeadline) ? requestedDeadline : null },
            );
        }
        return {
            policy: "later_deadline",
            reason: "Explicit crucible_start supplied a later wall-clock deadline.",
            details: { previousDeadline, requestedDeadline },
        };
    }
    if (code === "CRUCIBLE_RUNTIME_CIRCUIT_OPEN") {
        if (args.reset_policy !== "circuit_open") {
            throw new OperationalResetRequiredError(
                "A circuit-open non-result requires reset_policy='circuit_open'",
                { code },
            );
        }
        return {
            policy: "circuit_open",
            reason: "Explicit crucible_start reset the persisted circuit breaker.",
            details: null,
        };
    }
    if (payload.details?.recoverable === true) {
        return {
            policy: "recoverable_reattach",
            reason: "Explicit crucible_start reattached after a recoverable operational failure.",
            details: null,
        };
    }
    if (args.reset_policy !== "failed") {
        throw new OperationalResetRequiredError(
            "A non-recoverable failed operational outcome requires reset_policy='failed'",
            { code },
        );
    }
    return {
        policy: "failed",
        reason: "Explicit crucible_start reset a persisted failed operational outcome.",
        details: null,
    };
}

function openContractOnce(adapter, contract, newContractHash, args) {
    const current = adapter.replay();
    if (current.aggregate.contract !== null) {
        if (current.aggregate.contractHash === newContractHash) {
            if (current.aggregate.terminal !== null || current.aggregate.nonResults.length > 0) {
                throw new InvestigationNotResumableError(
                    "Terminal and domain non-result investigations require a new investigation identity",
                    {
                        investigationId: adapter.investigationId,
                        status: current.aggregate.status,
                    },
                );
            }
            const operationalNonResult = adapter.latestOperationalNonResult();
            const recovery = operationalRecoveryPolicy(operationalNonResult, args);
            if (recovery !== null) {
                adapter.recordOperationalRecovery({
                    attemptId: `recovery-${operationalNonResult.seq}-${recovery.policy}`,
                    previousSeq: operationalNonResult.seq,
                    policy: recovery.policy,
                    reason: recovery.reason,
                    details: recovery.details,
                });
            }
            const resumed = current.aggregate.pause !== null
                ? adapter.resumeInvestigation()
                : { aggregate: current.aggregate, domainEvent: null };
            return {
                idempotent: true,
                aggregate: resumed.aggregate,
                resumed: resumed.domainEvent !== null,
                operationalRecovery: recovery,
            };
        }
        throw new ContractConflictError(
            "an investigation with this identity already exists with a different contract",
            {
                investigationId: adapter.investigationId,
                existingContractHash: current.aggregate.contractHash,
                requestedContractHash: newContractHash,
            },
        );
    }
    try {
        const result = adapter.openInvestigation(contract);
        return {
            idempotent: false,
            aggregate: result.aggregate,
            resumed: false,
            operationalRecovery: null,
        };
    } catch (error) {
        // Lost a race to open: re-replay and reconcile by contract hash.
        const after = adapter.replay();
        if (after.aggregate.contract !== null) {
            if (after.aggregate.contractHash === newContractHash) {
                return openContractOnce(adapter, contract, newContractHash, args);
            }
            throw new ContractConflictError(
                "an investigation with this identity already exists with a different contract",
                {
                    investigationId: adapter.investigationId,
                    existingContractHash: after.aggregate.contractHash,
                    requestedContractHash: newContractHash,
                },
            );
        }
        throw error;
    }
}

function summarizeSupervisorAction(result) {
    if (result === null || typeof result !== "object") {
        return { action: null };
    }
    return {
        action: result.action ?? "ensured",
        pid: result.pid ?? result.status?.childPid ?? result.status?.pid ?? null,
        status_state: result.status?.state ?? null,
    };
}

export function startInvestigation(args, deps) {
    const env = deps.env;

    // 1. Resolve operator-owned runtime paths (fails clearly if unavailable).
    const { allowlistPath, stateRoot, sdkPath, cliPath } = resolveStartEnvironment(env);

    // 2. Verify the harness allowlist entry exists BEFORE creating any state.
    const allowlist = deps.loadHarnessAllowlist(allowlistPath);
    if (!allowlist.listEntryIds().includes(args.harness_id)) {
        throw new HarnessNotAllowlistedError(
            `harness '${args.harness_id}' has no operator allowlist entry`,
            { harnessId: args.harness_id, allowlistPath },
        );
    }

    // 3. Deterministic identity + local paths.
    const objective = canonicalObjective(args.objective);
    const projectDir = resolveProjectDir(args.project_dir, env);
    const investigationId = deriveInvestigationId({
        objective,
        projectDir,
        harnessId: args.harness_id,
    });
    const paths = resolveInvestigationPaths(stateRoot, investigationId);

    // 4. Ingest validation-case directories; only immutable hashes proceed.
    const store = deps.openArtifactStore({ root: paths.artifactRoot, env });
    const validationCases = ingestValidationCases(store, projectDir, args.validation_cases, env);

    // 5. Build the immutable contract via the domain API.
    const contract = createInvestigationContract({
        objective,
        acceptancePredicate: args.acceptance_predicate,
        validationCases,
        harnessId: args.harness_id,
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
    });
    const newContractHash = contractHash(contract);

    // 6. Open the repository/adapter and open the contract exactly once. The
    //    state directory must exist before SQLite can create the event log.
    fs.mkdirSync(paths.stateDir, { recursive: true });
    const repository = deps.openRepository({ file: paths.eventsDbPath, env });
    let opened;
    try {
        const adapter = deps.createDomainRepositoryAdapter({ repository, investigationId });
        opened = openContractOnce(adapter, contract, newContractHash, args);
    } finally {
        repository.close();
    }

    // 7. Build the strict supervisor config and start/ensure the detached
    //    supervisor via the actual runtime API.
    const supervisorInput = buildSupervisorConfigInput({
        investigationId,
        stateDir: paths.stateDir,
        artifactRoot: paths.artifactRoot,
        allowlistPath,
        sdkPath,
        cliPath,
        deadlineIso: args.deadline_iso,
    });
    const supervisor = deps.ensureSupervisor(supervisorInput, {
        env,
        resetOperationalState: opened.resumed || opened.operationalRecovery !== null,
    });
    const statusPath = supervisorPaths(paths.stateDir, investigationId).statusPath;

    deps.log?.(
        `[crucible] crucible_start ${investigationId} (${opened.idempotent ? "idempotent" : "new"}); `
        + `supervisor=${summarizeSupervisorAction(supervisor).action}`,
    );

    return {
        is_result: false,
        investigation_id: investigationId,
        contract_hash: newContractHash,
        idempotent: opened.idempotent,
        resumed: opened.resumed,
        operational_recovery: opened.operationalRecovery?.policy ?? null,
        state_dir: paths.stateDir,
        status_path: statusPath,
        events_db_path: paths.eventsDbPath,
        artifact_root: paths.artifactRoot,
        supervisor: summarizeSupervisorAction(supervisor),
        message: opened.idempotent
            ? "Investigation already open with an identical contract; re-attached and ensured supervisor. Poll crucible_status."
            : "Investigation started. Poll crucible_status; only crucible_result may report a terminal decision.",
    };
}

// --- crucible_status ----------------------------------------------------------

function summarizeRecommendation(recommendation) {
    if (recommendation === null || typeof recommendation !== "object") {
        return null;
    }
    if (recommendation.kind === "TERMINAL") {
        return null;
    }
    return {
        kind: recommendation.kind ?? null,
        code: recommendation.code ?? null,
        command_kind: recommendation.command?.kind ?? null,
        recorded: recommendation.recorded ?? false,
    };
}

// Adaptive-search progress projection. Exposes only aggregate, non-leaking
// signals: counts, phase labels, and booleans. It deliberately NEVER surfaces a
// decision, candidate identifiers, metric values, or evidence identifiers/hashes
// — those belong only to crucible_result on a persisted terminal decision.
function operatorMix(candidates) {
    const mix = {};
    for (const operator of SEARCH_OPERATORS) {
        mix[operator] = 0;
    }
    for (const evidence of candidates) {
        if (typeof evidence.operator === "string" && Object.hasOwn(mix, evidence.operator)) {
            mix[evidence.operator] += 1;
        }
    }
    return mix;
}

function buildProgress(aggregate) {
    if (aggregate.contract === null) {
        return {
            status: aggregate.status,
            event_seq: aggregate.lastSeq,
            open: false,
        };
    }
    const progress = searchProgress(aggregate);
    const plateau = detectPlateau(aggregate);
    const archive = buildCandidateArchive(aggregate);
    const candidates = harnessCandidateEvidenceItems(aggregate);
    const accepted = qualifyingCandidateEvidenceItems(aggregate);
    const duplicateCount = candidates
        .filter((evidence) => evidence.duplicateOf !== null).length;
    return {
        status: aggregate.status,
        event_seq: aggregate.lastSeq,
        open: true,
        evaluations: progress.attemptedCandidates.length,
        candidates_observed: progress.candidates.length,
        accepted_candidates: accepted.length,
        passing_incumbent_available: qualifyingCandidateEvidence(aggregate) !== null,
        next_round: progress.nextRound,
        next_slot: progress.nextSlot,
        partial_round: progress.partialRound,
        slots_completed_in_round: progress.slotsCompletedInRound,
        completed_rounds: progress.completedRounds,
        rounds_exhausted: progress.roundsExhausted,
        bounded_complete: progress.boundedComplete,
        max_rounds: aggregate.contract.maxRounds,
        candidates_per_round: aggregate.contract.candidatesPerRound,
        plateau_phase: plateau.phase,
        plateau_detected: plateau.plateauDetected,
        escape_rounds_completed: plateau.escapeRoundsCompleted,
        escape_rounds_required: plateau.escapeRoundsRequired,
        operator_mix: operatorMix(candidates),
        archive_counts: {
            accepted: archive.accepted.length,
            near_misses: archive.nearMisses.length,
            rejected: archive.rejected.length,
            invalid_metrics: archive.invalidMetrics.length,
            mechanism_groups: archive.mechanismGroups.length,
            lesson_groups: archive.lessonGroups.length,
        },
        duplicate_count: duplicateCount,
        stop_requests: aggregate.stopRequests.length,
        paused: aggregate.pause !== null,
        non_results: aggregate.nonResults.length,
    };
}

function buildSupervisorHealth(status, lock, isPidAlive, now = Date.now(), staleMs = 30_000) {
    if (status === null || typeof status !== "object") {
        return {
            present: false,
            state: null,
            supervisor_pid: null,
            child_pid: null,
            alive: false,
            heartbeat_at: null,
            restart_count: null,
        };
    }
    const heartbeatAgeMs = now - Date.parse(status.heartbeatAt);
    const ownershipMatches = lock !== null
        && lock.pid === status.pid
        && lock.nonce === status.nonce
        && Number.isFinite(heartbeatAgeMs)
        && heartbeatAgeMs >= -staleMs
        && heartbeatAgeMs < staleMs;
    return {
        present: true,
        state: status.state ?? null,
        supervisor_pid: status.pid ?? null,
        child_pid: status.childPid ?? null,
        alive: ownershipMatches && isPidAlive(status.pid) === true,
        heartbeat_at: status.heartbeatAt ?? null,
        restart_count: status.restartCount ?? null,
    };
}

function tryRestartSupervisor(deps, env, paths, investigationId) {
    const configPath = supervisorPaths(paths.stateDir, investigationId).configPath;
    if (!fs.existsSync(configPath)) {
        return { action: "no-persisted-config" };
    }
    try {
        const config = deps.loadSupervisorConfig(configPath, { env });
        const result = deps.ensureSupervisor(config, { env });
        return summarizeSupervisorAction(result);
    } catch (error) {
        deps.log?.(`[crucible] crucible_status supervisor restart failed: ${error?.message ?? String(error)}`);
        return { action: "restart-failed", code: error?.code ?? null, error: error?.message ?? String(error) };
    }
}

function integrityBlockedPayload(investigationId) {
    return {
        is_result: false,
        banner: INTEGRITY_NON_RESULT_BANNER,
        investigation_id: investigationId,
        integrity_blocked: true,
        non_result: true,
        non_result_code: "INTEGRITY_BLOCKED",
        reason: "Persisted investigation evidence failed integrity verification. No result is available.",
        message: `${INTEGRITY_NON_RESULT_BANNER}\n${NON_RESULT_BANNER}`,
    };
}

function readInvestigationOrIntegrityBlock(deps, investigationId, paths) {
    try {
        return {
            blocked: null,
            read: openInvestigationForRead(deps, investigationId, paths),
        };
    } catch (error) {
        if (error instanceof InvestigationNotFoundError) throw error;
        deps.log?.(
            `[crucible] integrity verification blocked read for ${investigationId}: ${error?.message ?? String(error)}`,
        );
        return {
            blocked: integrityBlockedPayload(investigationId),
            read: null,
        };
    }
}

export function statusInvestigation(args, deps) {
    const env = deps.env;
    const investigationId = args.investigation_id;
    const stateRoot = resolveStateRoot(env);
    const paths = resolveInvestigationPaths(stateRoot, investigationId);

    const verifiedRead = readInvestigationOrIntegrityBlock(
        deps,
        investigationId,
        paths,
    );
    if (verifiedRead.blocked !== null) {
        return {
            ...verifiedRead.blocked,
            terminal_available: false,
            paused: false,
            status: "integrity_blocked",
            note: "Integrity verification failed; status cannot expose or trust a terminal decision.",
        };
    }
    const { aggregate, operationalNonResult } = verifiedRead.read;

    const recommendation = aggregate.contract === null
        || aggregate.terminal !== null
        || aggregate.pause !== null
        || aggregate.nonResults.length > 0
        || operationalNonResult !== null
        ? null
        : summarizeRecommendation(decideNext(aggregate));

    const domainNonterminal = aggregate.terminal === null
        && aggregate.pause === null
        && aggregate.nonResults.length === 0
        && operationalNonResult === null;

    const status = deps.readStatus({ stateDir: paths.stateDir, investigationId });
    let lock = null;
    try {
        lock = deps.readSupervisorLock?.(
            supervisorPaths(paths.stateDir, investigationId).lockPath,
        ) ?? null;
    } catch {
        lock = null;
    }
    const health = buildSupervisorHealth(status, lock, deps.isPidAlive);
    const supervisorMissing = status === null || health.alive === false;

    let ensureAction = null;
    if (domainNonterminal && supervisorMissing) {
        ensureAction = tryRestartSupervisor(deps, env, paths, investigationId);
    }

    return {
        is_result: false,
        investigation_id: investigationId,
        integrity_blocked: false,
        terminal_available: aggregate.terminal !== null,
        non_result: aggregate.nonResults.length > 0 || operationalNonResult !== null,
        non_result_code:
            operationalNonResult?.payload?.code
            ?? aggregate.nonResults.at(-1)?.code
            ?? null,
        non_result_reason:
            operationalNonResult?.payload?.reason
            ?? aggregate.nonResults.at(-1)?.reason
            ?? null,
        paused: aggregate.pause !== null,
        status: aggregate.status,
        contract_hash: aggregate.contractHash,
        event_head: {
            seq: aggregate.lastSeq,
            event_hash: aggregate.terminal === null ? aggregate.lastEventHash : null,
        },
        progress: buildProgress(aggregate),
        supervisor_health: { ...health, ensure_action: ensureAction },
        next_recommendation: recommendation,
        note: aggregate.terminal !== null
            ? "A terminal decision is recorded — call crucible_result to obtain it."
            : operationalNonResult !== null
                ? "An operational non-result is recorded; call crucible_start under the explicit recovery policy to retry."
            : "In progress or paused. This status is not a result.",
    };
}

// --- crucible_stop ------------------------------------------------------------

export function stopInvestigation(args, deps) {
    const env = deps.env;
    const investigationId = args.investigation_id;
    const stateRoot = resolveStateRoot(env);
    const paths = resolveInvestigationPaths(stateRoot, investigationId);

    if (!fs.existsSync(paths.eventsDbPath)) {
        throw new InvestigationNotFoundError("no Crucible investigation with this id", {
            investigationId,
        });
    }

    const result = deps.requestStop({
        stateDir: paths.stateDir,
        investigationId,
        reason: typeof args.reason === "string" && args.reason.length > 0
            ? args.reason
            : "Pause requested via crucible_stop.",
        pauseRequested: true,
    });
    const aggregate = result?.aggregate ?? null;
    const alreadyTerminal = aggregate?.terminal != null;
    const domainNonResult = (aggregate?.nonResults?.length ?? 0) > 0;
    const operationalNonResult = result?.operationalNonResult ?? null;
    const pausePersisted = result?.pausePersisted === true || aggregate?.pause !== null;
    const resumable = pausePersisted
        && !alreadyTerminal
        && !domainNonResult
        && operationalNonResult === null;

    return {
        is_result: false,
        investigation_id: investigationId,
        pause_requested: result?.appended === true,
        pause_persisted: pausePersisted,
        resumable,
        appended: result?.appended === true,
        status: aggregate?.status ?? "pause_requested",
        already_terminal: alreadyTerminal,
        message: alreadyTerminal
            ? "Investigation is already terminal; no pause was requested."
            : resumable
                ? "Pause persisted; the investigation may be resumed by an identical crucible_start reattach."
                : "Pause was not yet persisted, so resumability is not claimed.",
    };
}

// --- crucible_result ----------------------------------------------------------

function describeNonResult(aggregate, operationalNonResult) {
    if (operationalNonResult !== null) {
        return operationalNonResult.payload.reason;
    }
    if (aggregate.pause !== null) {
        return "Investigation is paused and resumable; no terminal decision has been recorded.";
    }
    if (aggregate.nonResults.length > 0) {
        return `Investigation recorded a non-result (${aggregate.nonResults.at(-1)?.code ?? "unknown"}); it is not a verified answer.`;
    }
    if (aggregate.contract === null) {
        return "Investigation has no frozen contract yet.";
    }
    return "Investigation is still in progress; no terminal decision has been recorded.";
}

export function resultInvestigation(args, deps) {
    const env = deps.env;
    const investigationId = args.investigation_id;
    const stateRoot = resolveStateRoot(env);
    const paths = resolveInvestigationPaths(stateRoot, investigationId);

    const verifiedRead = readInvestigationOrIntegrityBlock(
        deps,
        investigationId,
        paths,
    );
    if (verifiedRead.blocked !== null) {
        return verifiedRead.blocked;
    }
    const { aggregate, operationalNonResult } = verifiedRead.read;
    const terminal = aggregate.terminal;
    const isTerminalResult = terminal !== null && TERMINAL_DECISIONS.includes(terminal.decision);

    if (isTerminalResult) {
        return {
            is_result: true,
            banner: TERMINAL_BANNER,
            integrity_verified: true,
            investigation_id: investigationId,
            decision: terminal.decision,
            terminal_seq: terminal.seq,
            terminal_event_hash: terminal.eventHash,
            contract_hash: aggregate.contractHash,
            event_head_hash: aggregate.lastEventHash,
            candidate_id: terminal.candidateId ?? null,
            evidence_id: terminal.evidenceId ?? null,
            evidence_hash: terminal.evidenceHash ?? null,
            evidence_closure: terminal.evidenceClosure ?? terminal.basis?.evidenceClosure ?? null,
            basis: terminal.basis ?? null,
            message: `${TERMINAL_BANNER} decision=${terminal.decision}`,
        };
    }

    // Strict non-result redaction: no winner id, no evidence/contract/event
    // hashes that could be laundered as a successful terminal answer.
    return {
        is_result: false,
        banner: NON_RESULT_BANNER,
        investigation_id: investigationId,
        status: aggregate.status,
        paused: aggregate.pause !== null,
        non_result: aggregate.nonResults.length > 0 || operationalNonResult !== null,
        non_result_code:
            operationalNonResult?.payload?.code
            ?? aggregate.nonResults.at(-1)?.code
            ?? null,
        event_seq: aggregate.lastSeq,
        reason: describeNonResult(aggregate, operationalNonResult),
        message: NON_RESULT_BANNER,
    };
}

// --- SDK boundary + registration -------------------------------------------

const HANDLERS = Object.freeze({
    crucible_start: startInvestigation,
    crucible_status: statusInvestigation,
    crucible_stop: stopInvestigation,
    crucible_result: resultInvestigation,
});

export function runToolBoundary(spec, handler, rawArgs, deps) {
    try {
        const args = spec.parse(rawArgs ?? {});
        const payload = handler(args, deps);
        return success(payload);
    } catch (error) {
        const code = error instanceof CrucibleApiError ? error.code : (error?.code ?? null);
        deps.log?.(
            `[crucible] ${spec.name} failed (${code ?? "ERROR"}): ${error?.message ?? String(error)}`,
        );
        return failure(error?.message ?? String(error), { code, tool: spec.name });
    }
}

// Build the SDK registration payload: exactly the four public tools and NO
// hooks. The returned object contains only a `tools` key, which the extension
// entrypoint passes straight to joinSession.
export function buildRegistration({ env = process.env, log = () => {}, deps } = {}) {
    const resolvedDeps = deps ?? makeDefaultDeps(env, log);
    const tools = TOOL_SPECS.map((spec) => ({
        name: spec.name,
        description: spec.description,
        parameters: spec.parameters,
        handler: (rawArgs) => runToolBoundary(spec, HANDLERS[spec.name], rawArgs, resolvedDeps),
    }));
    return { tools };
}

export { HANDLERS };
