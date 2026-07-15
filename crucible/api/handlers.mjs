// crucible/api/handlers.mjs
//
// The four Crucible tool handlers plus the single SDK error boundary and the
// production runtime wiring. Design rules enforced here:
//
//   * Internal handlers THROW typed errors; only `runToolBoundary` catches, at
//     the SDK edge, converting to a structured `{ textResultForLlm, resultType }`.
//   * Environment/state roots come from api/environment.mjs. The optional archive
//     destination is accepted only inside the state-root retention directory.
//   * crucible_result accepts a persisted terminal only after reducer replay has
//     re-derived and closure-bound statistics from raw blocks and receipts.
//   * Diagnostics go only through the injected `log` (session.log), never stdout.
//
// Every runtime collaborator is injectable via `deps` so handler tests can run
// with fakes; `makeDefaultDeps` supplies the real modules in production.

import fs from "node:fs";
import path from "node:path";

import {
    DOMAIN_VERSION,
    SEARCH_OPERATORS,
    assessPersistedTerminalReadiness,
    buildCandidateArchive,
    decideNext,
    detectPlateau,
    harnessCandidateEvidenceItems,
    qualifyingCandidateEvidenceItems,
    searchProgress,
} from "../domain/index.mjs";
import {
    openArtifactStore,
    openArtifactStoreReadOnly,
    openRepository,
    openRepositoryReadOnly,
    createWorkingSetController,
    publicWorkingSetTelemetry,
    exportBundle,
    importBundle,
    verifyBundleInPlace,
    removeVerifiedBundle,
    writeSignedTombstone,
    verifySignedTombstone,
    measureRetainedTree,
    removeRetainedTree,
} from "../persistence/index.mjs";
import {
    loadHarnessAllowlist,
    probeWindowsSandboxAvailability,
} from "../measurement/index.mjs";
import {
    RUNTIME_ERROR_CODES,
    createDomainRepositoryAdapter,
    ensureSupervisor,
    isExactPidAlive,
    loadSupervisorConfig,
    normalizeSupervisorConfig,
    openResourceBrokerFromStateRoot,
    readSupervisorLock,
    readStatus,
    resourceCatalogPath,
    requestStop,
    waitForStopAcknowledgement,
    supervisorPaths,
    validateSupervisorAdmission,
} from "../runtime/index.mjs";

import {
    resolveInvestigationPaths,
    resolveStateRoot,
} from "./environment.mjs";
import {
    loadExperimentRegistry,
    reverifyExperimentRegistryFile,
} from "./experiment-registry.mjs";
import {
    verifyExperimentAuthority,
} from "./experiment-authority.mjs";
import {
    applyStartPreflight,
    disposeStartPreflight,
    preflightStartInvestigation,
} from "./preflight.mjs";
import { PUBLIC_TOOL_NAMES, TOOL_SPECS } from "./schema.mjs";
import {
    NON_RESULT_BANNER,
    TERMINAL_BANNER,
    INTEGRITY_NON_RESULT_BANNER,
    failure,
    terminalAvailable,
    toolSuccess,
} from "./result.mjs";
import {
    API_ERROR_CODES,
    InvestigationNotFoundError,
    CrucibleApiError,
} from "./errors.mjs";
import {
    activeCatalogSummary,
    archiveInvestigation,
    deleteInvestigation,
    listLifecycleInvestigations,
    resolveLifecycleTarget,
    resultTombstonePayload,
    statusTombstonePayload,
    verifyArchivedTarget,
} from "./lifecycle.mjs";

const TERMINAL_DECISIONS = Object.freeze(["VERIFIED_RESULT", "TARGET_UNREACHABLE"]);

// --- production runtime wiring ---------------------------------------------

export function makeDefaultDeps(env = process.env, log = () => {}) {
    return {
        env,
        log,
        assessPersistedTerminalReadiness,
        isPidAlive: isExactPidAlive,
        loadHarnessAllowlist,
        loadExperimentRegistry,
        pathExists: fs.existsSync,
        reverifyExperimentRegistryFile,
        probeSandboxAvailability: probeWindowsSandboxAvailability,
        openRepository,
        openRepositoryReadOnly,
        openArtifactStore,
        openArtifactStoreReadOnly,
        exportBundle,
        importBundle,
        verifyBundleInPlace,
        removeVerifiedBundle,
        writeSignedTombstone,
        verifySignedTombstone,
        measureRetainedTree,
        removeRetainedTree,
        createDomainRepositoryAdapter,
        ensureSupervisor,
        readStatus,
        requestStop,
        waitForStopAcknowledgement,
        normalizeSupervisorConfig,
        openResourceBrokerFromStateRoot,
        loadSupervisorConfig,
        readSupervisorLock,
        resourceCatalogPath,
        validateSupervisorAdmission,
        verifyExperimentAuthority,
        now: Date.now,
    };
}

function openInvestigationForRead(
    deps,
    investigationId,
    paths,
    {
        verifyTerminalArtifacts = false,
        includeStorageTelemetry = true,
        immutableDatabase = false,
    } = {},
) {
    const { eventsDbPath, artifactRoot } = paths;
    if (!(deps.pathExists ?? fs.existsSync)(eventsDbPath)) {
        throw new InvestigationNotFoundError("no Crucible investigation with this id", {
            investigationId,
        });
    }
    const repository = deps.openRepositoryReadOnly({
        file: eventsDbPath,
        env: deps.env,
        immutable: immutableDatabase,
    });
    const artifactStore = deps.openArtifactStoreReadOnly({
        root: artifactRoot,
        env: deps.env,
    });
    try {
        const adapter = deps.createDomainRepositoryAdapter({
            repository,
            artifactStore,
            investigationId,
            ensure: false,
        });
        let replay = adapter.replay();
        const authority = replay.aggregate.experimentAuthority;
        const payload = authority?.manifest?.experimentPayload;
        if (authority === null
            || replay.aggregate.experimentAuthorityIdentity === null
            || authority.identity
                !== replay.aggregate.experimentAuthorityIdentity) {
            throw new Error(
                "persisted v4 investigation has no valid experiment authority",
            );
        }
        (deps.verifyExperimentAuthority ?? verifyExperimentAuthority)({
            authority,
            experimentId: payload?.experimentId,
            projectDir: payload?.projectDir,
            harnessSuiteId: payload?.harnessSuiteId,
            contract: replay.aggregate.contract,
            investigationId,
            env: deps.env,
        });
        if (verifyTerminalArtifacts && replay.aggregate.terminal !== null) {
            replay = adapter.verifyTerminalArtifactClosure({
                artifactStore,
            });
        }
        const operationalNonResult = adapter.latestOperationalNonResult();
        const quiescentStop =
            typeof repository.getQuiescentStop === "function"
                ? repository.getQuiescentStop(investigationId)
                : null;
        let storageTelemetry = includeStorageTelemetry
            && typeof deps.readWorkingSetTelemetry === "function"
                ? deps.readWorkingSetTelemetry({
                    repository,
                    artifactStore,
                    investigationId,
                    paths,
                    aggregate: replay.aggregate,
                })
                : null;
        if (includeStorageTelemetry
            && storageTelemetry === null
            && replay.aggregate.contract?.workingSetPolicy !== undefined
            && typeof repository.getStorageTelemetry === "function"
            && typeof artifactStore.storageTelemetry === "function") {
            const policy = replay.aggregate.contract.workingSetPolicy;
            const globalLimitBytes =
                replay.aggregate.runtimeConfigAuthority
                    ?.securityConfig?.runner?.resourceBroker
                    ?.config?.capacities?.storageBytes
                ?? policy.perInvestigationBytes;
            storageTelemetry = createWorkingSetController({
                repository,
                artifactStore,
                investigationId,
                investigationDir: paths.investigationDir,
                stateRoot: path.dirname(paths.investigationDir),
                policy,
                globalLimitBytes,
            }).telemetry();
        }
        return {
            aggregate: replay.aggregate,
            repositoryHead:
                typeof repository.getHead === "function"
                    ? repository.getHead(investigationId)
                    : {
                        seq: replay.aggregate.lastSeq,
                        eventHash: replay.aggregate.lastEventHash,
                    },
            updatedAtMs:
                replay.aggregate.lastSeq > 0
                && typeof repository.getEvent === "function"
                    ? Date.parse(
                        repository.getEvent(
                            investigationId,
                            replay.aggregate.lastSeq,
                        )?.createdAt ?? "",
                    )
                    : null,
            operationalNonResult,
            quiescentStop,
            artifactClosureReport: replay.artifactClosureReport ?? null,
            storageTelemetry,
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
        acknowledged: result.acknowledged === true,
        supervisor_generation:
            result.acknowledgement?.supervisorGeneration ?? null,
        runner_incarnation:
            result.acknowledgement?.runnerIncarnation ?? null,
        config_fingerprint:
            result.acknowledgement?.configFingerprint ?? null,
        deadline_ms:
            result.acknowledgement?.deadlineMs ?? null,
    };
}

export function startInvestigation(args, deps) {
    const apply = (plan) => {
        const cleanupBeforeFailure = (error) => {
            try {
                disposeStartPreflight(plan, deps);
            } catch (cleanupError) {
                deps.log?.(
                    `[crucible] crucible_start pre-success cleanup also failed: ${
                    cleanupError?.message ?? String(cleanupError)
                    }`,
                );
            }
            throw error;
        };
        const finish = ({ opened, supervisor }) => {
            const supervisorSummary = summarizeSupervisorAction(supervisor);
            let cleanupWarning = null;
            try {
                disposeStartPreflight(plan, deps);
            } catch (cleanupError) {
                cleanupWarning = {
                    code: cleanupError?.code ?? null,
                    cause_code: cleanupError?.details?.cleanupCause ?? null,
                    message: cleanupError?.message ?? String(cleanupError),
                };
                deps.log?.(
                    `[crucible] crucible_start ${plan.investigationId} durable start succeeded, `
                    + `but preflight cleanup failed: ${cleanupWarning.message}`,
                );
            }
            deps.log?.(
                `[crucible] crucible_start ${plan.investigationId} (${opened.idempotent ? "idempotent" : "new"}); `
                + `supervisor=${supervisorSummary.action}`,
            );
            return {
                is_result: false,
                investigation_id: plan.investigationId,
                ...(plan.experimentId === undefined
                    ? {}
                    : { experiment_id: plan.experimentId }),
                contract_hash: plan.hashes.contractHash,
                harness_suite_identity:
                    plan.contract.harnessSuiteIdentity,
                idempotent: opened.idempotent,
                reattached_by_id: plan.kind === "reattach",
                resumed: opened.resumed,
                operational_recovery: opened.operationalRecovery?.policy ?? null,
                state_dir: plan.paths.stateDir,
                status_path: plan.supervisorConfig.paths.statusPath,
                events_db_path: plan.paths.eventsDbPath,
                artifact_root: plan.paths.artifactRoot,
                supervisor: supervisorSummary,
                ...(cleanupWarning === null
                    ? {}
                    : { cleanup_warning: cleanupWarning }),
                message: plan.kind === "reattach"
                    ? "Persisted investigation reattached by id; frozen contract/config/snapshots and the acknowledged supervisor authority were verified. Poll crucible_status."
                    : opened.idempotent
                    ? "Investigation already open with an identical contract; re-attached to an acknowledged supervisor. Poll crucible_status."
                    : "Investigation started with an acknowledged supervisor. Poll crucible_status; only crucible_result may report a terminal decision.",
            };
        };

        let applied;
        try {
            applied = applyStartPreflight(plan, deps);
        } catch (error) {
            return cleanupBeforeFailure(error);
        }
        return applied !== null && typeof applied?.then === "function"
            ? Promise.resolve(applied).then(finish, cleanupBeforeFailure)
            : finish(applied);
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
        passing_incumbent_available: accepted.length > 0,
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
            inconclusive: archive.inconclusive.length,
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
            runtime_identity: null,
            resource_broker: null,
            control_channel: null,
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
        runtime_identity: status.runtimeIdentity ?? null,
        resource_broker: status.resourceBroker ?? null,
        control_channel: status.controlChannel ?? null,
    };
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

function scientificBlockedPayload(investigationId, assessment) {
    if (assessment.integrityBound !== true) {
        return {
            ...integrityBlockedPayload(investigationId),
            scientific_blocked: true,
            terminal_available: false,
        };
    }
    return {
        is_result: false,
        banner: NON_RESULT_BANNER,
        investigation_id: investigationId,
        integrity_blocked: false,
        scientific_blocked: true,
        terminal_available: false,
        non_result: true,
        non_result_code: assessment.nonResultCode,
        reason:
            "A persisted terminal event does not satisfy the frozen scientific readiness policy. No result is available.",
        message: NON_RESULT_BANNER,
    };
}

function legacyIncompatiblePayload(investigationId, details = {}) {
    return {
        is_result: false,
        banner: NON_RESULT_BANNER,
        investigation_id: investigationId,
        compatibility: "legacy_incompatible",
        legacy_incompatible: true,
        restart_required: true,
        required_action: "start_new_investigation",
        expected_domain_version:
            details.expectedDomainVersion ?? DOMAIN_VERSION,
        actual_domain_version: details.actualDomainVersion ?? null,
        contract_domain_version: details.contractDomainVersion ?? null,
        event_count: details.eventCount ?? null,
        read_only: true,
        archiveable: false,
        integrity_blocked: false,
        terminal_available: false,
        non_result: true,
        non_result_code: "LEGACY_INCOMPATIBLE",
        reason:
            "Persisted state belongs to an incompatible legacy Crucible domain. "
            + "It may be inventoried read-only, but it cannot resume, archive, append, or emit a newly computed result.",
        message: NON_RESULT_BANNER,
    };
}

function isLegacyIncompatibleError(error) {
    return error?.code === RUNTIME_ERROR_CODES.LEGACY_INCOMPATIBLE
        || error?.details?.compatibility === "legacy_incompatible";
}

function readInvestigationOrIntegrityBlock(
    deps,
    investigationId,
    paths,
    {
        verifyTerminalArtifacts = false,
        includeStorageTelemetry = true,
        immutableDatabase = false,
    } = {},
) {
    try {
        return {
            blocked: null,
            legacy: null,
            read: openInvestigationForRead(
                deps,
                investigationId,
                paths,
                {
                    verifyTerminalArtifacts,
                    includeStorageTelemetry,
                    immutableDatabase,
                },
            ),
        };
    } catch (error) {
        if (error instanceof InvestigationNotFoundError) throw error;
        if (isLegacyIncompatibleError(error)) {
            return {
                blocked: null,
                legacy: legacyIncompatiblePayload(
                    investigationId,
                    error?.details ?? {},
                ),
                read: null,
            };
        }
        deps.log?.(
            `[crucible] integrity verification blocked read for ${investigationId}: ${error?.message ?? String(error)}`,
        );
        return {
            blocked: integrityBlockedPayload(investigationId),
            legacy: null,
            read: null,
        };
    }
}

function probeActiveCatalogEntry(entry, stateRoot, deps) {
    const paths = resolveInvestigationPaths(
        stateRoot,
        entry.investigationId,
    );
    const verifiedRead = readInvestigationOrIntegrityBlock(
        deps,
        entry.investigationId,
        paths,
        {
            verifyTerminalArtifacts: true,
            includeStorageTelemetry: false,
        },
    );
    if (verifiedRead.blocked !== null) {
        return activeCatalogSummary({
            entry,
            stateRoot,
            read: null,
            integrityStatus: "blocked",
            deps,
        });
    }
    if (verifiedRead.legacy !== null) {
        return activeCatalogSummary({
            entry,
            stateRoot,
            read: null,
            integrityStatus: "blocked",
            domainVersion:
                verifiedRead.legacy.actual_domain_version ?? null,
            deps,
        });
    }
    return activeCatalogSummary({
        entry,
        stateRoot,
        read: verifiedRead.read,
        integrityStatus: "verified",
        deps,
    });
}

export function statusInvestigation(args, deps) {
    if (args.operation === "list") {
        return listLifecycleInvestigations(args, deps, {
            probeActive: (entry, stateRoot) =>
                probeActiveCatalogEntry(entry, stateRoot, deps),
        });
    }
    const investigationId = args.investigation_id;
    const target = resolveLifecycleTarget({
        deps,
        investigationId,
        verifyArchive: false,
    });
    if (target.state === "tombstoned") {
        return statusTombstonePayload(target);
    }
    const paths = target.paths;
    const lifecycleState = target.state;
    if (lifecycleState === "archived") {
        try {
            verifyArchivedTarget(target, deps);
        } catch (error) {
            deps.log?.(
                `[crucible] archived bundle verification blocked status for ${investigationId}: ${
                    error?.message ?? String(error)
                }`,
            );
            return {
                ...integrityBlockedPayload(investigationId),
                lifecycle_state: "archived",
                terminal_available: false,
                paused: false,
                status: "integrity_blocked",
                note:
                    "Archived bundle verification failed; status cannot expose or trust a terminal decision.",
            };
        }
    }

    const verifiedRead = readInvestigationOrIntegrityBlock(
        deps,
        investigationId,
        paths,
        {
            verifyTerminalArtifacts: true,
            includeStorageTelemetry: lifecycleState === "active",
            immutableDatabase: lifecycleState === "archived",
        },
    );
    if (verifiedRead.blocked !== null) {
        return {
            ...verifiedRead.blocked,
            lifecycle_state: lifecycleState,
            terminal_available: false,
            paused: false,
            status: "integrity_blocked",
            note: "Integrity verification failed; status cannot expose or trust a terminal decision.",
        };
    }
    if (verifiedRead.legacy !== null) {
        return {
            ...verifiedRead.legacy,
            lifecycle_state: lifecycleState,
            paused: false,
            status: "legacy_incompatible",
            note:
                "Legacy state is read-only and restart-required; start a new v4 investigation.",
        };
    }
    const {
        aggregate,
        operationalNonResult,
        quiescentStop,
        storageTelemetry,
    } = verifiedRead.read;
    if (aggregate.terminal !== null) {
        const readiness = (
            deps.assessPersistedTerminalReadiness
            ?? assessPersistedTerminalReadiness
        )(aggregate);
        return readiness.ready
            ? terminalAvailable(investigationId)
            : scientificBlockedPayload(investigationId, readiness);
    }

    const recommendation = aggregate.contract === null
        || aggregate.pause !== null
        || aggregate.nonResults.length > 0
        || operationalNonResult !== null
        ? null
        : summarizeRecommendation(decideNext(aggregate));

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

    return {
        is_result: false,
        investigation_id: investigationId,
        lifecycle_state: lifecycleState,
        integrity_blocked: false,
        terminal_available: false,
        non_result: aggregate.nonResults.length > 0 || operationalNonResult !== null,
        non_result_code:
            operationalNonResult?.payload?.code
            ?? aggregate.nonResults.at(-1)?.code
            ?? null,
        paused: aggregate.pause !== null,
        quiescent: quiescentStop?.state === "PAUSED_QUIESCENT"
            && quiescentStop.quiescent === true,
        resumable: aggregate.pause !== null
            && quiescentStop?.state === "PAUSED_QUIESCENT"
            && quiescentStop.quiescent === true
            && operationalNonResult === null
            && aggregate.nonResults.length === 0,
        stop_state: quiescentStop?.state ?? null,
        intervention_required:
            quiescentStop?.interventionRequired === true,
        status: aggregate.status,
        progress: buildProgress(aggregate),
        storage: publicWorkingSetTelemetry(storageTelemetry),
        supervisor_health: { ...health, ensure_action: null },
        next_recommendation: recommendation,
        note: operationalNonResult !== null
                ? "An operational non-result is recorded; reattach by investigation_id with any required recovery inputs."
                : aggregate.nonResults.length > 0
                    ? `A persisted non-result (${aggregate.nonResults.at(-1)?.code ?? "unknown"}) is recorded; this status is not a result.`
                    : aggregate.pause !== null
                        ? quiescentStop?.state === "PAUSED_QUIESCENT"
                            && quiescentStop.quiescent === true
                            ? "The investigation is paused, quiescent, and resumable; this status is not a result."
                            : "A pause is persisted without a quiescence proof; resumability is not claimed."
                        : "The investigation is in progress; this status is not a result.",
    };
}

// --- crucible_stop ------------------------------------------------------------

function pauseInvestigation(args, deps) {
    const env = deps.env;
    const investigationId = args.investigation_id;
    const stateRoot = resolveStateRoot(env);
    const paths = resolveInvestigationPaths(stateRoot, investigationId);

    if (!(deps.pathExists ?? fs.existsSync)(paths.eventsDbPath)) {
        throw new InvestigationNotFoundError("no Crucible investigation with this id", {
            investigationId,
        });
    }
    if (typeof deps.openRepository === "function") {
        const migrationRepository = deps.openRepository({
            file: paths.eventsDbPath,
            env: deps.env,
        });
        migrationRepository.close();
    }
    const verifiedRead = readInvestigationOrIntegrityBlock(
        deps,
        investigationId,
        paths,
        { verifyTerminalArtifacts: true },
    );
    if (verifiedRead.blocked !== null) {
        return {
            ...verifiedRead.blocked,
            terminal_available: false,
            stop_state: "integrity_blocked",
            pause_requested: false,
            pause_in_flight: false,
            pause_persisted: false,
            quiescent: false,
            resumable: false,
            intervention_required: false,
            appended: false,
            paused: false,
            status: "integrity_blocked",
            already_terminal: false,
        };
    }
    if (verifiedRead.legacy !== null) {
        return {
            ...verifiedRead.legacy,
            stop_state: "legacy_incompatible",
            pause_requested: false,
            pause_in_flight: false,
            pause_persisted: false,
            quiescent: false,
            resumable: false,
            intervention_required: false,
            appended: false,
            paused: false,
            status: "legacy_incompatible",
            already_terminal: false,
        };
    }
    if (verifiedRead.read.aggregate.terminal !== null) {
        const readiness = (
            deps.assessPersistedTerminalReadiness
            ?? assessPersistedTerminalReadiness
        )(verifiedRead.read.aggregate);
        return readiness.ready
            ? terminalAvailable(investigationId)
            : scientificBlockedPayload(investigationId, readiness);
    }

    const result = deps.requestStop({
        stateDir: paths.stateDir,
        artifactRoot: paths.artifactRoot,
        investigationId,
        reason: typeof args.reason === "string" && args.reason.length > 0
            ? args.reason
            : "Pause requested via crucible_stop.",
        pauseRequested: true,
    });
    const finishStop = (acknowledgement) => {
        let aggregate = result?.aggregate ?? null;
        let operationalNonResult =
            result?.operationalNonResult ?? null;
        if (acknowledgement !== null) {
            const afterStop = readInvestigationOrIntegrityBlock(
                deps,
                investigationId,
                paths,
                { verifyTerminalArtifacts: true },
            );
            if (afterStop.blocked !== null) {
                return {
                    ...afterStop.blocked,
                    terminal_available: false,
                    stop_state: "integrity_blocked",
                    pause_requested: false,
                    pause_in_flight: false,
                    pause_persisted: false,
                    quiescent: false,
                    resumable: false,
                    intervention_required: false,
                    appended: result?.appended === true,
                    paused: false,
                    status: "integrity_blocked",
                    already_terminal: false,
                };
            }
            aggregate = afterStop.read.aggregate;
            operationalNonResult =
                afterStop.read.operationalNonResult;
        }
        const alreadyTerminal = aggregate?.terminal != null;
        if (alreadyTerminal) {
            const terminalRead = readInvestigationOrIntegrityBlock(
                deps,
                investigationId,
                paths,
                { verifyTerminalArtifacts: true },
            );
            if (terminalRead.blocked !== null) {
                return {
                    ...terminalRead.blocked,
                    terminal_available: false,
                };
            }
            const readiness = (
                deps.assessPersistedTerminalReadiness
                ?? assessPersistedTerminalReadiness
            )(terminalRead.read.aggregate);
            return readiness.ready
                ? terminalAvailable(investigationId)
                : scientificBlockedPayload(investigationId, readiness);
        }
        const domainNonResult =
            (aggregate?.nonResults?.length ?? 0) > 0;
        const pausePersisted = result?.pausePersisted === true
            || aggregate?.pause !== null;
        const stop = acknowledgement?.stop ?? result?.stop ?? null;
        const quiescent = stop?.state === "PAUSED_QUIESCENT"
            && stop.quiescent === true;
        const interventionRequired =
            stop?.interventionRequired === true;
        const resumable = quiescent
            && pausePersisted
            && !domainNonResult
            && operationalNonResult === null;
        const stopState = operationalNonResult !== null
            ? "operational_non_result"
            : domainNonResult
                ? "domain_non_result"
                : stop?.state === "PAUSED_QUIESCENT"
                    ? "pause_persisted"
                    : stop?.state === "PAUSE_PENDING"
                        ? "pause_pending"
                        : "pause_requested";
        const pauseRequested = result?.appended === true
            && !domainNonResult
            && operationalNonResult === null;
        const pauseInFlight = [
            "pause_requested",
            "pause_pending",
        ].includes(stopState);
        const nonResultCode = operationalNonResult?.payload?.code
            ?? aggregate?.nonResults?.at(-1)?.code
            ?? stop?.nonResultCode
            ?? null;
        const messages = {
            operational_non_result:
                "A persisted operational non-result blocks resumability; reattach by investigation_id with any required later deadline/reset policy.",
            domain_non_result:
                "A persisted domain non-result is final for this investigation identity and is not resumable.",
            pause_persisted:
                "Pause and zero-active-resource proof are durably persisted; the investigation is resumable by investigation_id.",
            pause_pending:
                "The stop barrier is durable, but zero active resources could not be proved within the bound; authority is retained and intervention is required.",
            pause_requested:
                "The stop barrier is durable and reconciliation is in flight; resumability is not claimed.",
        };

        return {
            is_result: false,
            investigation_id: investigationId,
            stop_state: stopState,
            pause_requested: pauseRequested,
            pause_in_flight: pauseInFlight,
            pause_persisted: pausePersisted,
            quiescent,
            resumable,
            intervention_required: interventionRequired,
            acknowledgement_timed_out:
                acknowledgement?.timedOut === true,
            appended: result?.appended === true,
            status: aggregate?.status ?? "pause_requested",
            non_result:
                domainNonResult || operationalNonResult !== null,
            non_result_code: nonResultCode,
            message: messages[stopState],
        };
    };

    const shouldWait = result?.stop !== null
        && result?.stop !== undefined
        && !["PAUSED_QUIESCENT", "PAUSE_PENDING"].includes(
            result.stop.state,
        )
        && typeof deps.waitForStopAcknowledgement === "function";
    if (!shouldWait) {
        return finishStop(null);
    }
    return Promise.resolve(deps.waitForStopAcknowledgement({
        stateDir: paths.stateDir,
        investigationId,
        requestId: result.stop.requestId,
    })).then(finishStop);
}

export function stopInvestigation(args, deps) {
    if (args.operation === "archive") {
        return archiveInvestigation(args, deps, {
            readActive: (investigationId, paths) => {
                const verifiedRead = readInvestigationOrIntegrityBlock(
                    deps,
                    investigationId,
                    paths,
                    {
                        verifyTerminalArtifacts: true,
                        includeStorageTelemetry: false,
                    },
                );
                if (verifiedRead.blocked !== null) {
                    throw new Error(
                        "active investigation integrity verification failed before archive",
                    );
                }
                if (verifiedRead.legacy !== null) {
                    throw new Error(
                        "legacy investigation cannot enter the v4 archive lifecycle",
                    );
                }
                return verifiedRead.read;
            },
        });
    }
    if (args.operation === "delete") {
        return deleteInvestigation(args, deps);
    }
    return pauseInvestigation(args, deps);
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
    const investigationId = args.investigation_id;
    const target = resolveLifecycleTarget({
        deps,
        investigationId,
        verifyArchive: false,
    });
    if (target.state === "tombstoned") {
        return {
            ...resultTombstonePayload(target),
            banner: NON_RESULT_BANNER,
            message: NON_RESULT_BANNER,
        };
    }
    const paths = target.paths;
    const lifecycleState = target.state;
    if (lifecycleState === "archived") {
        try {
            verifyArchivedTarget(target, deps);
        } catch (error) {
            deps.log?.(
                `[crucible] archived bundle verification blocked result for ${investigationId}: ${
                    error?.message ?? String(error)
                }`,
            );
            return integrityBlockedPayload(investigationId);
        }
    }

    const verifiedRead = readInvestigationOrIntegrityBlock(
        deps,
        investigationId,
        paths,
        {
            verifyTerminalArtifacts: true,
            includeStorageTelemetry: lifecycleState === "active",
            immutableDatabase: lifecycleState === "archived",
        },
    );
    if (verifiedRead.blocked !== null) {
        return verifiedRead.blocked;
    }
    if (verifiedRead.legacy !== null) {
        return {
            ...verifiedRead.legacy,
            status: "legacy_incompatible",
            paused: false,
        };
    }
    const { aggregate, operationalNonResult } = verifiedRead.read;
    const terminal = aggregate.terminal;
    const isTerminalResult = terminal !== null && TERMINAL_DECISIONS.includes(terminal.decision);

    if (isTerminalResult) {
        const readiness = (
            deps.assessPersistedTerminalReadiness
            ?? assessPersistedTerminalReadiness
        )(aggregate);
        if (!readiness.ready) {
            return scientificBlockedPayload(investigationId, readiness);
        }
        const closure =
            terminal.evidenceClosure ?? terminal.basis?.evidenceClosure ?? null;
        const candidateConclusions = closure?.scientificConclusions ?? [];
        const primaryConclusion = closure?.scientificConclusion ?? null;
        const conclusions = [
            ...candidateConclusions,
            ...(primaryConclusion === null
                || candidateConclusions.some((item) =>
                    item?.conclusionHash === primaryConclusion.conclusionHash)
                ? []
                : [primaryConclusion]),
        ];
        const performanceClaims = candidateConclusions.flatMap(
            (conclusion) =>
                conclusion?.candidate?.performance?.claims ?? [],
        );
        const predictionOutcomes = candidateConclusions.flatMap(
            (conclusion) =>
                conclusion?.hypotheses?.predictions ?? [],
        );
        const assumptions = conclusions.flatMap((conclusion) => [
            ...(Array.isArray(conclusion?.assumptions)
                ? conclusion.assumptions
                : []),
            ...(conclusion?.candidate?.performance?.assumptions === null
                || conclusion?.candidate?.performance?.assumptions === undefined
                ? []
                : [conclusion.candidate.performance.assumptions]),
        ]);
        const limitations = conclusions.flatMap((conclusion) =>
            Array.isArray(conclusion?.limitations)
                ? conclusion.limitations
                : []);
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
            ...(terminal.decision === "VERIFIED_RESULT"
                ? {
                    ...(terminal.candidateId === null
                        || terminal.candidateId === undefined
                        ? {}
                        : { candidate_id: terminal.candidateId }),
                    candidate_ids:
                        terminal.candidateIds
                        ?? (terminal.candidateId === null
                            || terminal.candidateId === undefined
                            ? []
                            : [terminal.candidateId]),
                    cohort_status:
                        terminal.cohortStatus ?? "UNIQUE_BEST",
                    relation_evidence_hash:
                        terminal.relationEvidenceHash ?? null,
                }
                : {}),
            evidence_id: terminal.evidenceId ?? null,
            evidence_hash: terminal.evidenceHash ?? null,
            ...(terminal.decision === "VERIFIED_RESULT"
                ? {
                    evidence_ids:
                        terminal.evidenceIds
                        ?? (terminal.evidenceId === null
                            || terminal.evidenceId === undefined
                            ? []
                            : [terminal.evidenceId]),
                    evidence_hashes:
                        terminal.evidenceHashes
                        ?? (terminal.evidenceHash === null
                            || terminal.evidenceHash === undefined
                            ? []
                            : [terminal.evidenceHash]),
                }
                : {}),
            evidence_closure: closure,
            scientific_replay:
                closure?.scientificReplay ?? null,
            scientific_conclusion:
                primaryConclusion,
            scientific_conclusions:
                candidateConclusions,
            relation_evidence:
                closure?.relationEvidence ?? null,
            authority_closure: closure?.authority ?? null,
            artifact_closure: closure?.artifacts ?? null,
            discovery_stop: closure?.termination ?? null,
            held_out_state: closure?.scientificConfirmation ?? null,
            unreachable_verifier:
                closure?.unreachableVerifier ?? null,
            performance_claims: performanceClaims,
            prediction_outcomes: predictionOutcomes,
            assumptions,
            limitations,
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
        lifecycle_state: lifecycleState,
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
        const compatibility = error?.details?.compatibility;
        const terminalAvailableForStart =
            spec.name === "crucible_start"
            && code === API_ERROR_CODES.INVESTIGATION_NOT_RESUMABLE
            && error?.details?.status === "terminal";
        let verifiedTerminalAvailable = false;
        if (terminalAvailableForStart) {
            try {
                const investigationId =
                    error?.details?.investigationId ?? null;
                verifiedTerminalAvailable =
                    typeof investigationId === "string"
                    && statusInvestigation({
                        operation: "get",
                        investigation_id: investigationId,
                    }, deps).terminal_available === true;
            } catch {
                verifiedTerminalAvailable = false;
            }
        }
        return failure(error?.message ?? String(error), {
            code,
            tool: spec.name,
            ...(terminalAvailableForStart
                ? { terminal_available: verifiedTerminalAvailable }
                : {}),
            ...(compatibility === "legacy_incompatible"
                ? {
                    compatibility,
                    legacy_incompatible: true,
                    restart_required: true,
                    required_action: "start_new_investigation",
                    expected_domain_version:
                        error?.details?.expectedDomainVersion ?? DOMAIN_VERSION,
                    actual_domain_version:
                        error?.details?.actualDomainVersion ?? null,
                    terminal_available: false,
                }
                : {}),
        });
    };
    const finish = (payload) => toolSuccess(spec.name, payload);
    try {
        const args = spec.parse(rawArgs ?? {});
        const payload = handler(args, deps);
        if (payload !== null
            && (typeof payload === "object" || typeof payload === "function")
            && typeof payload.then === "function") {
            return Promise.resolve(payload).then(finish).catch(handleFailure);
        }
        return finish(payload);
    } catch (error) {
        return handleFailure(error);
    }
}

// Build the SDK registration payload: exactly the four public tools and NO
// hooks. The returned object contains only a `tools` key, which the extension
// entrypoint passes straight to joinSession.
export function buildRegistration({ env = process.env, log = () => {}, deps } = {}) {
    const resolvedDeps = deps ?? makeDefaultDeps(env, log);
    const specs = new Map(TOOL_SPECS.map((spec) => [spec.name, spec]));
    const tools = PUBLIC_TOOL_NAMES.map((name) => {
        const spec = specs.get(name);
        const handler = HANDLERS[name];
        if (spec === undefined || typeof handler !== "function") {
            throw new Error(`Crucible public tool registration is incomplete for ${name}`);
        }
        return Object.freeze({
            name,
            description: spec.description,
            parameters: spec.parameters,
            handler: (rawArgs) => runToolBoundary(spec, handler, rawArgs, resolvedDeps),
        });
    });
    return Object.freeze({ tools: Object.freeze(tools) });
}
