import {
    canonicalEqual,
    canonicalClone,
    deepFreeze,
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import {
    compareCandidateEvidence,
} from "./archive.mjs";
import { DOMAIN_VERSION } from "./constants.mjs";
import {
    createImpossibilityVerificationPackage,
    deriveUnreachableCoverageClosure,
} from "./impossibility.mjs";
import {
    enumerandCoverage,
    normalizeEnumerandManifest,
} from "./enumerands.mjs";
import { replayDerivedCandidateEvidence } from "./scientific-replay.mjs";
import {
    inheritAggregateImpossibilityExecutions,
} from "./private-verifier-execution.mjs";

const BOUNDED_CANDIDATE_SET_HASH_ALGORITHM =
    "sha256:crucible-bounded-candidate-set-v1";
const BOUNDED_EVIDENCE_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-bounded-evidence-closure-v1";

const AGGREGATE_MAP_FIELDS = Object.freeze([
    "capabilityEpochs",
    "commands",
    "observations",
    "evidence",
]);

function ownEntry(record, key) {
    return Object.hasOwn(record, key) ? record[key] : null;
}

function restorePrototypeSafeMaps(aggregate) {
    for (const field of AGGREGATE_MAP_FIELDS) {
        aggregate[field] = Object.assign(Object.create(null), aggregate[field]);
    }
    return aggregate;
}

export function cloneAggregateForMutation(aggregate) {
    return inheritAggregateImpossibilityExecutions(
        aggregate,
        restorePrototypeSafeMaps(canonicalClone(aggregate)),
    );
}

export function immutableAggregate(aggregate) {
    const cloned = cloneAggregateForMutation(aggregate);
    return inheritAggregateImpossibilityExecutions(
        cloned,
        deepFreeze(cloned),
    );
}

export function createInitialAggregate() {
    return immutableAggregate({
        domainVersion: DOMAIN_VERSION,
        status: "empty",
        contract: null,
        contractHash: null,
        experimentAuthority: null,
        experimentAuthorityIdentity: null,
        runtimeConfigAuthority: null,
        runtimeConfigFingerprint: null,
        lastSeq: 0,
        lastEventHash: null,
        capabilityEpochs: {},
        capabilityEpochOrder: [],
        commands: {},
        commandOrder: [],
        observations: {},
        observationOrder: [],
        evidence: {},
        evidenceOrder: [],
        validation: {
            attemptEvidenceIds: [],
            completions: [],
            currentEvidenceId: null,
        },
        confirmation: {
            freeze: null,
        },
        searchStrategy: {
            revision: 0,
            history: [],
        },
        stopRequests: [],
        pause: null,
        pauseHistory: [],
        nonResults: [],
        terminal: null,
        scientificReplay: null,
    });
}

function replayCalibrationState(aggregate, evidenceId) {
    return aggregate.scientificReplay?.calibrationState?.find(
        (item) => item.evidenceId === evidenceId,
    ) ?? null;
}

function replayCandidateSupport(aggregate, evidenceId) {
    return aggregate.scientificReplay?.candidateSupport?.find(
        (item) => item.evidenceId === evidenceId,
    ) ?? null;
}

export function currentValidationEvidence(aggregate) {
    const evidenceId = aggregate.validation.currentEvidenceId;
    if (evidenceId === null) {
        return null;
    }
    const evidence = ownEntry(aggregate.evidence, evidenceId);
    const replayState = replayCalibrationState(aggregate, evidenceId);
    const basisEvidenceIds = replayState?.basisEvidenceIds ?? null;
    if (evidence === null
        || evidence.invalidated
        || replayState?.validationSatisfied !== true
        || !Array.isArray(basisEvidenceIds)
        || basisEvidenceIds.some((basisId) =>
            ownEntry(aggregate.evidence, basisId)?.invalidated !== false)) {
        return null;
    }
    return evidence;
}

export function qualifyingValidationEvidence(aggregate) {
    for (const evidenceId of aggregate.evidenceOrder) {
        const evidence = ownEntry(aggregate.evidence, evidenceId);
        if (evidence === null) {
            continue;
        }
        const replayState = replayCalibrationState(
            aggregate,
            evidence.evidenceId,
        );
        if (!evidence.invalidated
            && evidence.sourceKind === "harness"
            && evidence.purpose === "validation"
            && replayState?.validationSatisfied === true
            && Array.isArray(replayState.basisEvidenceIds)
            && replayState.basisEvidenceIds.every((basisId) =>
                ownEntry(aggregate.evidence, basisId)?.invalidated === false)) {
            return evidence;
        }

    }
    return null;
}

export function validationEvidenceItems(
    aggregate,
    { includeInvalidated = false } = {},
) {
    return aggregate.validation.attemptEvidenceIds
        .map((evidenceId) => ownEntry(aggregate.evidence, evidenceId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
            && evidence.purpose === "validation"
            && (includeInvalidated || !evidence.invalidated));
}

export function validationAttemptIndexes(aggregate) {
    return validationEvidenceItems(aggregate)
        .map((evidence) => evidence.validationAttemptIndex)
        .filter((index) => Number.isSafeInteger(index) && index >= 0)
        .sort((left, right) => left - right);
}

export function activeCommand(aggregate) {
    for (let index = aggregate.commandOrder.length - 1; index >= 0; index -= 1) {
        const command = ownEntry(aggregate.commands, aggregate.commandOrder[index]);
        if (command === null) {
            continue;
        }
        if (command.status !== "observed") {
            return command;
        }
    }
    return null;
}

export function uncommittedObservation(aggregate) {
    for (const observationId of aggregate.observationOrder) {
        const observation = ownEntry(aggregate.observations, observationId);
        if (observation === null) {
            continue;
        }
        if (observation.evidenceId === null) {
            return observation;
        }
    }
    return null;
}

export function qualifyingCandidateEvidence(aggregate) {
    const cohort = candidateCohortState(aggregate);
    if (cohort?.status !== "UNIQUE_BEST"
        || cohort.provisionalWinner === null) {
        return null;
    }
    return ownEntry(
        aggregate.evidence,
        cohort.provisionalWinner.evidenceId,
    );
}

export function candidateCohortState(aggregate) {
    return aggregate?.scientificReplay?.candidateCohort ?? null;
}

export function qualifyingCandidateCohort(aggregate) {
    const cohort = candidateCohortState(aggregate);
    if (cohort?.resolved !== true
        || (cohort.status !== "UNIQUE_BEST"
            && cohort.status !== "TIE_COHORT")) {
        return immutableCanonical([]);
    }
    return immutableCanonical(
        cohort.cohort
            .map((candidate) =>
                ownEntry(aggregate.evidence, candidate.evidenceId))
            .filter((evidence) =>
                evidence !== null && evidence.invalidated !== true),
    );
}

export function qualifyingCandidateEvidenceItems(aggregate) {
    return harnessCandidateEvidenceItems(aggregate)
        .filter((evidence) => {
            const support = replayCandidateSupport(
                aggregate,
                evidence.evidenceId,
            );
            return support?.outcomeClass === "accepted"
                && support.requiredState === "SUPPORTED"
                && support.acceptanceSatisfied === true;
        })
        .sort((left, right) => compareCandidateEvidence(aggregate.contract.metrics, left, right));
}

export function harnessCandidateEvidenceItems(aggregate, { includeInvalidated = false } = {}) {
    return aggregate.evidenceOrder
        .map((evidenceId) => ownEntry(aggregate.evidence, evidenceId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
            && evidence.purpose === "candidate"
            && (includeInvalidated || !evidence.invalidated))
        .map((evidence) =>
            replayDerivedCandidateEvidence(aggregate, evidence));
}

export function replicatedCandidateEvidenceItems(
    aggregate,
    { includeInvalidated = false } = {},
) {
    return harnessCandidateEvidenceItems(aggregate, { includeInvalidated })
        .filter((evidence) =>
            evidence.replication !== null
            && typeof evidence.replication === "object");
}

export function candidateReplicationStatus(aggregate, candidateId) {
    const evidence = replicatedCandidateEvidenceItems(
        aggregate,
        { includeInvalidated: true },
    ).find((item) => item.candidateId === candidateId) ?? null;
    if (evidence === null) return null;
    return immutableCanonical({
        evidenceId: evidence.evidenceId,
        invalidated: evidence.invalidated,
        ...evidence.replication,
    });
}

export function candidatePredictionEvaluation(aggregate, candidateId) {
    const evidence = harnessCandidateEvidenceItems(
        aggregate,
        { includeInvalidated: true },
    ).find((item) => item.candidateId === candidateId) ?? null;
    if (evidence === null) return null;
    return replayCandidateSupport(
        aggregate,
        evidence.evidenceId,
    )?.predictionEvaluation ?? null;
}

export function resolvedPredictionFindings(
    aggregate,
    { statuses = ["SUPPORTED", "REFUTED"] } = {},
) {
    const allowed = new Set(statuses);
    return immutableCanonical(
        harnessCandidateEvidenceItems(aggregate)
            .flatMap((evidence) =>
                (candidatePredictionEvaluation(
                    aggregate,
                    evidence.candidateId,
                )?.predictions ?? [])
                    .filter((prediction) =>
                        allowed.has(prediction.status))
                    .map((prediction) => ({
                        candidateId: evidence.candidateId,
                        evidenceId: evidence.evidenceId,
                        predictionId: prediction.predictionId,
                        predictionIdentity:
                            prediction.predictionIdentity,
                        requiredForResult:
                            prediction.requiredForResult,
                        status: prediction.status,
                        estimate: prediction.estimate,
                        confidenceBounds:
                            prediction.confidenceBounds,
                        evidenceReference:
                            prediction.evidenceReference,
                        blockReference: prediction.blockReference,
                        alphaReference: prediction.alphaReference,
                        limitations: prediction.limitations,
                    }))),
    );
}

export function impossibilityEvidenceItems(aggregate, { includeInvalidated = false } = {}) {
    return aggregate.evidenceOrder
        .map((evidenceId) => ownEntry(aggregate.evidence, evidenceId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
            && evidence.purpose === "impossibility"
            && (includeInvalidated || !evidence.invalidated));
}

export function latestImpossibilityEvidence(aggregate, options = {}) {
    return impossibilityEvidenceItems(aggregate, options).at(-1) ?? null;
}

function impossibilityEvidenceMatchesCurrentTrigger(aggregate, evidence) {
    const observation = ownEntry(aggregate.observations, evidence.observationId);
    const command = observation === null
        ? null
        : ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
    const validation = currentValidationEvidence(aggregate);
    const progress = searchProgress(aggregate);
    if (command?.kind !== "verify_impossibility"
        || validation === null
        || !progress.roundsExhausted) {
        return false;
    }
    try {
        const expected = createImpossibilityVerificationPackage(
            aggregate,
            {
                attemptOrdinal: command.attemptOrdinal,
                progress,
                validation,
            },
        );
        return expected.eligible
            && command.requestHash === expected.requestHash
            && command.proposedCertificateArtifactHash
                === expected.proposalArtifactHash
            && command.proofArtifactHash
                === expected.proofArtifactHash
            && canonicalEqual(
                command.proofArtifact,
                expected.proofArtifact,
            );
    } catch {
        return false;
    }
}

export function latestApplicableImpossibilityEvidence(aggregate) {
    return impossibilityEvidenceItems(aggregate)
        .filter((evidence) => impossibilityEvidenceMatchesCurrentTrigger(aggregate, evidence))
        .at(-1) ?? null;
}

export function searchProgress(aggregate) {
    const candidates = harnessCandidateEvidenceItems(aggregate);
    const attemptedCandidates = harnessCandidateEvidenceItems(
        aggregate,
        { includeInvalidated: true },
    );
    const occupied = new Set(
        candidates.map((evidence) => `${evidence.round}:${evidence.slotIndex}`),
    );
    const capacity = aggregate.contract.candidatesPerRound * aggregate.contract.maxRounds;
    const manifestOptions = {
        topology: aggregate.contract.enumerandManifest?.topology
            ?? aggregate.contract.hypothesisTopology,
        observableRegistry: aggregate.contract.observableRegistry,
        hypothesisPolicy: aggregate.contract.hypothesisPolicy,
    };
    const enumerandManifest = aggregate.contract.enumerandManifest === undefined
        ? null
        : normalizeEnumerandManifest(
            aggregate.contract.enumerandManifest,
            manifestOptions,
        );
    const boundedCandidateIds = aggregate.contract.boundedCandidateIds;
    const maxSlots = enumerandManifest !== null
        ? enumerandManifest.entries.length
        : boundedCandidateIds === undefined
            ? capacity
            : boundedCandidateIds.length;
    let nextRound = null;
    let nextSlot = null;
    for (let globalSlot = 0; globalSlot < maxSlots; globalSlot += 1) {
        const round = Math.floor(globalSlot / aggregate.contract.candidatesPerRound) + 1;
        const slot = globalSlot % aggregate.contract.candidatesPerRound;
        if (!occupied.has(`${round}:${slot}`)) {
            nextRound = round;
            nextSlot = slot;
            break;
        }
    }
    let enumerandCoverageSummary = null;
    let attemptedEnumerandCoverage = null;
    let boundedComplete;
    let boundedAttempted;
    if (enumerandManifest !== null) {
        const attempts = candidates.map((evidence) => ({
            enumerandOrdinal: evidence.enumerandOrdinal,
            enumerandHash: evidence.enumerandHash,
            invalidated: evidence.invalidated,
            outcomeClass: evidence.outcomeClass,
            acceptanceSatisfied: evidence.acceptanceSatisfied,
        }));
        enumerandCoverageSummary = enumerandCoverage(
            enumerandManifest,
            attempts,
            manifestOptions,
        );
        attemptedEnumerandCoverage = enumerandCoverage(
            enumerandManifest,
            attempts,
            { ...manifestOptions, countInvalidMetrics: true },
        );
        boundedComplete = enumerandCoverageSummary.complete;
        boundedAttempted = attemptedEnumerandCoverage.complete;
    } else {
        const evidencedCandidateIds = new Set(
            candidates
                .filter((evidence) => evidence.outcomeClass !== "invalid_metrics")
                .map((evidence) => evidence.candidateId),
        );
        boundedComplete = boundedCandidateIds !== undefined
            && boundedCandidateIds.every((candidateId) =>
                evidencedCandidateIds.has(candidateId));
        const attemptedCandidateIds = new Set(
            candidates.map((evidence) => evidence.candidateId),
        );
        boundedAttempted = boundedCandidateIds !== undefined
            && boundedCandidateIds.every((candidateId) =>
                attemptedCandidateIds.has(candidateId));
    }
    const roundProgress = [];
    const totalRoundCount = Math.ceil(maxSlots / aggregate.contract.candidatesPerRound);
    const roundCount = nextRound === null ? totalRoundCount : nextRound;
    for (let round = 1; round <= roundCount; round += 1) {
        const firstGlobalSlot = (round - 1) * aggregate.contract.candidatesPerRound;
        const expectedSlots = Math.min(
            aggregate.contract.candidatesPerRound,
            maxSlots - firstGlobalSlot,
        );
        const completedSlots = [];
        for (let slot = 0; slot < expectedSlots; slot += 1) {
            if (occupied.has(`${round}:${slot}`)) {
                completedSlots.push(slot);
            }
        }
        roundProgress.push({
            round,
            expectedSlots,
            completedSlots,
            missingSlots: Array.from(
                { length: expectedSlots },
                (_, slot) => slot,
            ).filter((slot) => !completedSlots.includes(slot)),
            complete: completedSlots.length === expectedSlots,
            partial: completedSlots.length > 0 && completedSlots.length < expectedSlots,
        });
    }
    const partialRounds = roundProgress.filter((round) => round.partial);
    const slotsCompletedInRound = nextRound === null
        ? 0
        : candidates.filter((evidence) => evidence.round === nextRound).length;
    const progress = {
        candidates,
        attemptedCandidates,
        nextRound,
        nextSlot,
        partialRound: nextRound !== null && nextSlot > 0,
        partialRounds,
        roundProgress,
        slotsCompletedInRound,
        completedRounds: roundProgress.filter((round) => round.complete).length,
        roundsExhausted: nextRound === null,
        boundedComplete,
        boundedAttempted,
        maxSlots,
        ...(enumerandCoverageSummary === null
            ? {}
            : {
                enumerandCoverage: enumerandCoverageSummary,
                attemptedEnumerandCoverage,
            }),
    };
    return immutableCanonical(progress);
}

export function candidateSelectionReady(aggregate) {
    const cohort = candidateCohortState(aggregate);
    return cohort?.resolved === true
        && cohort.cohort.length > 0
        && searchProgress(aggregate).roundsExhausted;
}

export function boundedSearchExhaustion(aggregate) {
    if (aggregate.contract.enumerandManifest !== undefined) {
        const manifestOptions = {
            topology: aggregate.contract.enumerandManifest?.topology
                ?? aggregate.contract.hypothesisTopology,
            observableRegistry: aggregate.contract.observableRegistry,
            hypothesisPolicy: aggregate.contract.hypothesisPolicy,
        };
        const manifest = normalizeEnumerandManifest(
            aggregate.contract.enumerandManifest,
            manifestOptions,
        );
        const progress = searchProgress(aggregate);
        const coverage = deriveUnreachableCoverageClosure(aggregate);
        if (!coverage.eligible) {
            return null;
        }
        return {
            kind: "search_space_exhausted",
            searchSpaceExhausted: true,
            topology: aggregate.contract.hypothesisTopology,
            enumerandCount: manifest.entries.length,
            enumerandManifestRoot: manifest.merkleRoot,
            enumerandCoverageHash:
                progress.enumerandCoverage?.coverageHash ?? null,
            enumerandExhaustionHash: hashCanonical(
                {
                    manifestRoot: manifest.merkleRoot,
                    coverageClosureRoot: coverage.closure.closureRoot,
                },
                "sha256:crucible-enumerand-exhaustion-v2",
            ),
            evidenceClosureHash: coverage.closure.closureRoot,
        };
    }
    const boundedCandidateIds = aggregate.contract.boundedCandidateIds;
    if (boundedCandidateIds === undefined) {
        return null;
    }
    const progress = searchProgress(aggregate);
    if (!progress.boundedComplete
        || progress.candidates.some((evidence) =>
            evidence.acceptanceSatisfied === true)) {
        return null;
    }
    const byCandidateId = new Map(
        progress.candidates.map((evidence) => [evidence.candidateId, evidence]),
    );
    const evidenceClosure = boundedCandidateIds.map((candidateId) => {
        const evidence = byCandidateId.get(candidateId);
        return {
            candidateId,
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash,
            provenanceRoot: evidence.provenanceRoot,
        };
    });
    return {
        kind: "search_space_exhausted",
        searchSpaceExhausted: true,
        topology: aggregate.contract.hypothesisTopology,
        boundedCandidateCount: boundedCandidateIds.length,
        boundedCandidateIdsHash: hashCanonical(
            boundedCandidateIds,
            BOUNDED_CANDIDATE_SET_HASH_ALGORITHM,
        ),
        evidenceClosureHash: hashCanonical(
            evidenceClosure,
            BOUNDED_EVIDENCE_CLOSURE_HASH_ALGORITHM,
        ),
    };
}

export function qualifyingUnreachableEvidence(aggregate) {
    const evidence = latestApplicableImpossibilityEvidence(aggregate);
    return evidence?.unreachableBasis === null ? null : evidence;
}

export function latestUnhandledStopRequest(aggregate) {
    for (let index = aggregate.stopRequests.length - 1; index >= 0; index -= 1) {
        const request = aggregate.stopRequests[index];
        const handled = aggregate.searchStrategy.history.some(
            (revision) => revision.sourceStopRequestSeq === request.seq,
        ) || aggregate.pauseHistory.some(
            (pause) => pause.sourceStopRequestSeq === request.seq,
        )
            || aggregate.nonResults.some((item) => item.sourceStopRequestSeq === request.seq);
        if (!handled) {
            return request;
        }
    }
    return null;
}
