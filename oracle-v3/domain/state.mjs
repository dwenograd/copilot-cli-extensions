import { immutableCanonical } from "./canonical.mjs";
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
    return qualifyingCandidateEvidenceItems(aggregate)[0] ?? null;
}

export function qualifyingCandidateEvidenceItems(aggregate) {
    return harnessCandidateEvidenceItems(aggregate)
        .filter((evidence) => evidence.acceptanceSatisfied === true)
        .sort((left, right) => compareCandidateEvidence(aggregate.contract.metrics, left, right));
}

export function harnessCandidateEvidenceItems(aggregate) {
    return aggregate.evidenceOrder
        .map((evidenceId) => aggregate.evidence[evidenceId])
        .filter((evidence) =>
            !evidence.invalidated
            && evidence.sourceKind === "harness"
            && evidence.purpose === "candidate");
}

function compareCandidateEvidence(metrics, left, right) {
    for (const metric of metrics) {
        const epsilon = metric.epsilon > 0 ? metric.epsilon : 0;
        let leftValue = left.metrics[metric.key];
        let rightValue = right.metrics[metric.key];
        if (epsilon > 0) {
            leftValue = Math.round(leftValue / epsilon);
            rightValue = Math.round(rightValue / epsilon);
        }
        if (leftValue === rightValue) {
            continue;
        }
        return metric.direction === "min"
            ? leftValue - rightValue
            : rightValue - leftValue;
    }
    return left.candidateId < right.candidateId
        ? -1
        : left.candidateId > right.candidateId
            ? 1
            : 0;
}

export function searchProgress(aggregate) {
    const candidates = harnessCandidateEvidenceItems(aggregate);
    const countsByRound = new Map();
    for (const evidence of candidates) {
        countsByRound.set(evidence.round, (countsByRound.get(evidence.round) ?? 0) + 1);
    }
    let nextRound = null;
    for (let round = 1; round <= aggregate.contract.maxRounds; round += 1) {
        if ((countsByRound.get(round) ?? 0) < aggregate.contract.candidatesPerRound) {
            nextRound = round;
            break;
        }
    }
    const boundedCandidateIds = aggregate.contract.boundedCandidateIds;
    const evidencedCandidateIds = new Set(candidates.map((evidence) => evidence.candidateId));
    const boundedComplete = boundedCandidateIds !== undefined
        && boundedCandidateIds.every((candidateId) => evidencedCandidateIds.has(candidateId));
    return {
        candidates,
        nextRound,
        roundsExhausted: nextRound === null,
        boundedComplete,
    };
}

export function candidateSelectionReady(aggregate) {
    const accepted = qualifyingCandidateEvidenceItems(aggregate);
    if (accepted.length === 0) {
        return false;
    }
    const progress = searchProgress(aggregate);
    if (aggregate.contract.boundedCandidateIds !== undefined) {
        return progress.boundedComplete;
    }
    const firstAcceptedRound = Math.min(...accepted.map((evidence) => evidence.round));
    const candidateCount = progress.candidates.filter(
        (evidence) => evidence.round === firstAcceptedRound,
    ).length;
    return candidateCount >= aggregate.contract.candidatesPerRound;
}

export function boundedSearchExhaustion(aggregate) {
    const boundedCandidateIds = aggregate.contract.boundedCandidateIds;
    if (boundedCandidateIds === undefined) {
        return null;
    }
    const progress = searchProgress(aggregate);
    if (!progress.boundedComplete
        || progress.candidates.some((evidence) => evidence.acceptanceSatisfied === true)) {
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
