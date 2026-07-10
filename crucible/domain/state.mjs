import { immutableCanonical } from "./canonical.mjs";
import {
    compareCandidateEvidence,
    selectIncumbent,
} from "./archive.mjs";
import { DOMAIN_VERSION } from "./constants.mjs";

export function createInitialAggregate() {
    return immutableCanonical({
        domainVersion: DOMAIN_VERSION,
        status: "empty",
        contract: null,
        contractHash: null,
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
            completions: [],
            currentEvidenceId: null,
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
    });
}

export function currentValidationEvidence(aggregate) {
    const evidenceId = aggregate.validation.currentEvidenceId;
    if (evidenceId === null) {
        return null;
    }
    const evidence = aggregate.evidence[evidenceId] ?? null;
    if (evidence === null || evidence.invalidated || evidence.validationSatisfied !== true) {
        return null;
    }
    return evidence;
}

export function qualifyingValidationEvidence(aggregate) {
    for (const evidenceId of aggregate.evidenceOrder) {
        const evidence = aggregate.evidence[evidenceId];
        if (!evidence.invalidated
            && evidence.sourceKind === "harness"
            && evidence.purpose === "validation"
            && evidence.validationSatisfied === true) {
            return evidence;
        }
    }
    return null;
}

export function activeCommand(aggregate) {
    for (let index = aggregate.commandOrder.length - 1; index >= 0; index -= 1) {
        const command = aggregate.commands[aggregate.commandOrder[index]];
        if (command.status !== "observed") {
            return command;
        }
    }
    return null;
}

export function uncommittedObservation(aggregate) {
    for (const observationId of aggregate.observationOrder) {
        const observation = aggregate.observations[observationId];
        if (observation.evidenceId === null) {
            return observation;
        }
    }
    return null;
}

export function qualifyingCandidateEvidence(aggregate) {
    return selectIncumbent(aggregate.contract, harnessCandidateEvidenceItems(aggregate));
}

export function qualifyingCandidateEvidenceItems(aggregate) {
    return harnessCandidateEvidenceItems(aggregate)
        .filter((evidence) =>
            evidence.rankable === true
            && evidence.outcomeClass === "accepted")
        .sort((left, right) => compareCandidateEvidence(aggregate.contract.metrics, left, right));
}

export function harnessCandidateEvidenceItems(aggregate, { includeInvalidated = false } = {}) {
    return aggregate.evidenceOrder
        .map((evidenceId) => aggregate.evidence[evidenceId])
        .filter((evidence) =>
            evidence.sourceKind === "harness"
            && evidence.purpose === "candidate"
            && (includeInvalidated || !evidence.invalidated));
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
    const boundedCandidateIds = aggregate.contract.boundedCandidateIds;
    const maxSlots = boundedCandidateIds === undefined
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
    const evidencedCandidateIds = new Set(
        candidates
            .filter((evidence) => evidence.outcomeClass !== "invalid_metrics")
            .map((evidence) => evidence.candidateId),
    );
    const boundedComplete = boundedCandidateIds !== undefined
        && boundedCandidateIds.every((candidateId) => evidencedCandidateIds.has(candidateId));
    const attemptedCandidateIds = new Set(
        candidates.map((evidence) => evidence.candidateId),
    );
    const boundedAttempted = boundedCandidateIds !== undefined
        && boundedCandidateIds.every((candidateId) => attemptedCandidateIds.has(candidateId));
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
    };
    return immutableCanonical(progress);
}

export function candidateSelectionReady(aggregate) {
    const incumbent = qualifyingCandidateEvidence(aggregate);
    return incumbent !== null && (
        aggregate.contract.searchPolicy.stopOnFirstAccept
        || searchProgress(aggregate).roundsExhausted
    );
}

export function boundedSearchExhaustion(aggregate) {
    const boundedCandidateIds = aggregate.contract.boundedCandidateIds;
    if (boundedCandidateIds === undefined) {
        return null;
    }
    const progress = searchProgress(aggregate);
    if (!progress.boundedComplete
        || progress.candidates.some((evidence) =>
            evidence.rankable === true && evidence.outcomeClass === "accepted")) {
        return null;
    }
    const byCandidateId = new Map(
        progress.candidates.map((evidence) => [evidence.candidateId, evidence]),
    );
    return {
        kind: "search_space_exhausted",
        searchSpaceExhausted: true,
        topology: aggregate.contract.hypothesisTopology,
        boundedCandidateIds,
        evidenceClosure: boundedCandidateIds.map((candidateId) => {
            const evidence = byCandidateId.get(candidateId);
            return {
                candidateId,
                evidenceId: evidence.evidenceId,
                evidenceHash: evidence.commitEventHash,
            };
        }),
    };
}

export function qualifyingUnreachableEvidence(aggregate) {
    for (const evidenceId of aggregate.evidenceOrder) {
        const evidence = aggregate.evidence[evidenceId];
        if (!evidence.invalidated
            && evidence.sourceKind === "harness"
            && evidence.purpose === "impossibility"
            && evidence.unreachableBasis !== null) {
            return evidence;
        }
    }
    return null;
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
