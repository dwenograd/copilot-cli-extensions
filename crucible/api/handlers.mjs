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
    SEARCH_OPERATORS,
    buildCandidateArchive,
    decideNext,
    detectPlateau,
    harnessCandidateEvidenceItems,
    qualifyingCandidateEvidence,
    qualifyingCandidateEvidenceItems,
    searchProgress,
} from "../domain/index.mjs";
import {
    openArtifactStore,
    openArtifactStoreReadOnly,
    openRepository,
    openRepositoryReadOnly,
} from "../persistence/index.mjs";
import {
    loadHarnessAllowlist,
    probeWindowsSandboxAvailability,
} from "../measurement/index.mjs";
import {
    createDomainRepositoryAdapter,
    ensureSupervisor,
    isExactPidAlive,
    loadSupervisorConfig,
    normalizeSupervisorConfig,
    readSupervisorLock,
    readStatus,
    requestStop,
    supervisorPaths,
    validateSupervisorAdmission,
} from "../runtime/index.mjs";

import {
    resolveInvestigationPaths,
    resolveStateRoot,
} from "./environment.mjs";
import {
    applyStartPreflight,
    disposeStartPreflight,
    preflightStartInvestigation,
} from "./preflight.mjs";
import { TOOL_SPECS } from "./schema.mjs";
import {
    NON_RESULT_BANNER,
    TERMINAL_BANNER,
    INTEGRITY_NON_RESULT_BANNER,
    failure,
    success,
} from "./result.mjs";
import {
    InvestigationNotFoundError,
    CrucibleApiError,
} from "./errors.mjs";

const TERMINAL_DECISIONS = Object.freeze(["VERIFIED_RESULT", "TARGET_UNREACHABLE"]);

// --- production runtime wiring ---------------------------------------------

export function makeDefaultDeps(env = process.env, log = () => {}) {
    return {
        env,
        log,
        isPidAlive: isExactPidAlive,
        loadHarnessAllowlist,
        probeSandboxAvailability: probeWindowsSandboxAvailability,
        openRepository,
        openRepositoryReadOnly,
        openArtifactStore,
        openArtifactStoreReadOnly,
        createDomainRepositoryAdapter,
        ensureSupervisor,
        readStatus,
        requestStop,
        normalizeSupervisorConfig,
        loadSupervisorConfig,
        readSupervisorLock,
        validateSupervisorAdmission,
    };
}

function openInvestigationForRead(
    deps,
    investigationId,
    paths,
    { verifyTerminalArtifacts = false } = {},
) {
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
        const replay = verifyTerminalArtifacts
            ? adapter.verifyTerminalArtifactClosure({
                artifactStore: deps.openArtifactStoreReadOnly({
                    root: artifactRoot,
                    env: deps.env,
                }),
            })
            : adapter.replay();
        const operationalNonResult = adapter.latestOperationalNonResult();
        return {
            aggregate: replay.aggregate,
            operationalNonResult,
            artifactClosureReport: replay.artifactClosureReport ?? null,
        };
    } finally {
        repository.close();
    }
}

// --- crucible_start -----------------------------------------------------------

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
    const apply = (plan) => {
        try {
            const { opened, supervisor } = applyStartPreflight(plan, deps);
            deps.log?.(
                `[crucible] crucible_start ${plan.investigationId} (${opened.idempotent ? "idempotent" : "new"}); `
                + `supervisor=${summarizeSupervisorAction(supervisor).action}`,
            );
            return {
                is_result: false,
                investigation_id: plan.investigationId,
                contract_hash: plan.hashes.contractHash,
                idempotent: opened.idempotent,
                reattached_by_id: plan.kind === "reattach",
                resumed: opened.resumed,
                operational_recovery: opened.operationalRecovery?.policy ?? null,
                state_dir: plan.paths.stateDir,
                status_path: plan.supervisorConfig.paths.statusPath,
                events_db_path: plan.paths.eventsDbPath,
                artifact_root: plan.paths.artifactRoot,
                supervisor: summarizeSupervisorAction(supervisor),
                message: plan.kind === "reattach"
                    ? "Persisted investigation reattached by id; frozen contract/config/snapshots were verified and the supervisor was ensured. Poll crucible_status."
                    : opened.idempotent
                        ? "Investigation already open with an identical contract; re-attached and ensured supervisor. Poll crucible_status."
                    : "Investigation started. Poll crucible_status; only crucible_result may report a terminal decision.",
            };
        } finally {
            disposeStartPreflight(plan);
        }
    };
    const preflight = preflightStartInvestigation(args, deps);
    return preflight !== null && typeof preflight?.then === "function"
        ? Promise.resolve(preflight).then(apply)
        : apply(preflight);
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

function readInvestigationOrIntegrityBlock(
    deps,
    investigationId,
    paths,
    { verifyTerminalArtifacts = false } = {},
) {
    try {
        return {
            blocked: null,
            read: openInvestigationForRead(
                deps,
                investigationId,
                paths,
                { verifyTerminalArtifacts },
            ),
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
        paused: aggregate.pause !== null,
        status: aggregate.status,
        progress: buildProgress(aggregate),
        supervisor_health: { ...health, ensure_action: ensureAction },
        next_recommendation: recommendation,
        note: aggregate.terminal !== null
            ? "A terminal decision is recorded — call crucible_result to obtain it."
            : operationalNonResult !== null
                ? "An operational non-result is recorded; reattach by investigation_id with any required recovery inputs."
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
    const stopState = alreadyTerminal
        ? "already_terminal"
        : operationalNonResult !== null
            ? "operational_non_result"
            : domainNonResult
                ? "domain_non_result"
                : pausePersisted
                    ? "pause_persisted"
                    : "pause_requested";
    const pauseRequested = result?.appended === true
        && !alreadyTerminal
        && !domainNonResult
        && operationalNonResult === null;
    const pauseInFlight = stopState === "pause_requested";
    const nonResultCode = operationalNonResult?.payload?.code
        ?? aggregate?.nonResults?.at(-1)?.code
        ?? null;
    const messages = {
        already_terminal:
            "Investigation is already terminal; no pause was requested and it is not resumable.",
        operational_non_result:
            "A persisted operational non-result blocks resumability; reattach by investigation_id with any required later deadline/reset policy.",
        domain_non_result:
            "A persisted domain non-result is final for this investigation identity and is not resumable.",
        pause_persisted:
            "Pause is durably persisted; the investigation is resumable by investigation_id.",
        pause_requested:
            "Pause was requested but is not yet durably persisted; resumability is not claimed.",
    };

    return {
        is_result: false,
        investigation_id: investigationId,
        stop_state: stopState,
        pause_requested: pauseRequested,
        pause_in_flight: pauseInFlight,
        pause_persisted: pausePersisted,
        resumable,
        appended: result?.appended === true,
        status: aggregate?.status ?? "pause_requested",
        already_terminal: alreadyTerminal,
        non_result: domainNonResult || operationalNonResult !== null,
        non_result_code: nonResultCode,
        message: messages[stopState],
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
        { verifyTerminalArtifacts: true },
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
    const handleFailure = (error) => {
        const code = error instanceof CrucibleApiError ? error.code : (error?.code ?? null);
        deps.log?.(
            `[crucible] ${spec.name} failed (${code ?? "ERROR"}): ${error?.message ?? String(error)}`,
        );
        return failure(error?.message ?? String(error), { code, tool: spec.name });
    };
    try {
        const args = spec.parse(rawArgs ?? {});
        const payload = handler(args, deps);
        if (payload !== null
            && (typeof payload === "object" || typeof payload === "function")
            && typeof payload.then === "function") {
            return Promise.resolve(payload).then(success, handleFailure);
        }
        return success(payload);
    } catch (error) {
        return handleFailure(error);
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
