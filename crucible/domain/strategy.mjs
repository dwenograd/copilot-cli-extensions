import { hashCanonical, immutableCanonical } from "./canonical.mjs";
import {
    buildCandidateArchive,
    compareCandidateEvidence,
    metricImprovement,
    selectPromptEvidence,
} from "./archive.mjs";
import {
    ESCAPE_SEARCH_OPERATORS,
    SEARCH_OPERATORS,
} from "./constants.mjs";

function candidateEvidence(aggregate, { includeInvalidated = false } = {}) {
    return aggregate.evidenceOrder
        .map((evidenceId) => aggregate.evidence[evidenceId])
        .filter((evidence) =>
            evidence.sourceKind === "harness"
            && evidence.purpose === "candidate"
            && (includeInvalidated || !evidence.invalidated));
}

function expectedSlotsForRound(contract, round) {
    if (contract.boundedCandidateIds === undefined) {
        return contract.candidatesPerRound;
    }
    const offset = (round - 1) * contract.candidatesPerRound;
    return Math.max(
        0,
        Math.min(
            contract.candidatesPerRound,
            contract.boundedCandidateIds.length - offset,
        ),
    );
}

function completedRoundNumbers(aggregate) {
    const byRound = new Map();
    for (const evidence of candidateEvidence(aggregate)) {
        const slots = byRound.get(evidence.round) ?? new Set();
        slots.add(evidence.slotIndex);
        byRound.set(evidence.round, slots);
    }
    const completed = [];
    for (let round = 1; round <= aggregate.contract.maxRounds; round += 1) {
        const expected = expectedSlotsForRound(aggregate.contract, round);
        if (expected === 0) {
            break;
        }
        const slots = byRound.get(round) ?? new Set();
        if (slots.size !== expected
            || [...slots].some((slot) => slot < 0 || slot >= expected)) {
            break;
        }
        completed.push(round);
    }
    return completed;
}

function passesImprovementThreshold(improvement, threshold) {
    return threshold === 0 ? improvement > 0 : improvement >= threshold;
}

function roundSignalSummaries(aggregate) {
    const contract = aggregate.contract;
    const completed = completedRoundNumbers(aggregate);
    const current = candidateEvidence(aggregate);
    const seenContent = new Set();
    const seenMechanisms = new Set();
    let acceptedSeen = false;
    let best = null;
    const summaries = [];

    for (const round of completed) {
        const items = current
            .filter((evidence) => evidence.round === round)
            .sort((left, right) => left.slotIndex - right.slotIndex);
        let metricImproved = false;
        let acceptanceNovelty = false;
        let mechanismNovelty = false;
        let contentNovelty = false;

        for (const evidence of items) {
            if (evidence.rankable) {
                if (best === null) {
                    metricImproved = contract.metrics.length > 0;
                    best = evidence;
                } else if (compareCandidateEvidence(contract.metrics, evidence, best) < 0) {
                    const improvement = metricImprovement(contract.metrics, evidence, best);
                    if (passesImprovementThreshold(
                        improvement,
                        contract.searchPolicy.plateauMinImprovement,
                    )) {
                        metricImproved = true;
                        best = evidence;
                    }
                }
            }
            if (evidence.outcomeClass === "accepted" && evidence.rankable && !acceptedSeen) {
                acceptanceNovelty = true;
                acceptedSeen = true;
            }
            const mechanism = evidence.annotations?.mechanism;
            if (typeof mechanism === "string"
                && mechanism.length > 0
                && evidence.duplicateOf === null
                && !seenMechanisms.has(mechanism)) {
                seenMechanisms.add(mechanism);
                mechanismNovelty = true;
            }
            if (typeof evidence.contentHash === "string"
                && evidence.duplicateOf === null
                && !seenContent.has(evidence.contentHash)) {
                seenContent.add(evidence.contentHash);
                contentNovelty = true;
            }
        }

        summaries.push({
            round,
            metricImproved,
            acceptanceNovelty,
            mechanismNovelty,
            contentNovelty,
            improvementOrNovelty: metricImproved
                || acceptanceNovelty
                || mechanismNovelty
                || contentNovelty,
        });
    }
    return summaries;
}

export function detectPlateau(aggregate) {
    const policy = aggregate.contract.searchPolicy;
    const summaries = roundSignalSummaries(aggregate);
    let stagnantRounds = 0;
    let triggerRound = null;
    let escapeRoundsCompleted = 0;

    for (const summary of summaries) {
        if (summary.improvementOrNovelty) {
            stagnantRounds = 0;
            triggerRound = null;
            escapeRoundsCompleted = 0;
            continue;
        }
        if (triggerRound !== null) {
            escapeRoundsCompleted += 1;
            continue;
        }
        stagnantRounds += 1;
        if (summary.round >= policy.minRoundsBeforePlateau
            && stagnantRounds >= policy.plateauWindow) {
            triggerRound = summary.round;
            escapeRoundsCompleted = 0;
        }
    }

    const plateauDetected = triggerRound !== null;
    const escapeComplete = plateauDetected
        && escapeRoundsCompleted >= policy.mandatoryEscapeRounds;
    return immutableCanonical({
        completedRounds: summaries.length,
        lastCompletedRound: summaries.at(-1)?.round ?? 0,
        plateauDetected,
        triggerRound,
        stagnantRounds,
        escapeRoundsCompleted,
        escapeRoundsRequired: policy.mandatoryEscapeRounds,
        escapeComplete,
        plateauComplete: escapeComplete,
        phase: !plateauDetected
            ? "normal"
            : escapeComplete
                ? "plateau"
                : "mandatory_escape",
        roundSignals: summaries,
    });
}

export const analyzePlateau = detectPlateau;
export const detectSearchPlateau = detectPlateau;

export function deterministicHashInteger(value, modulus = 0x7fffffff) {
    if (!Number.isSafeInteger(modulus) || modulus < 1) {
        throw new RangeError("modulus must be a positive safe integer");
    }
    const digest = hashCanonical(value).split(":").at(-1);
    return Number(BigInt(`0x${digest.slice(0, 16)}`) % BigInt(modulus));
}

export function deterministicSeed(value) {
    return deterministicHashInteger(value, 0x7ffffffe) + 1;
}

export function adaptiveOperatorWeights(searchPolicy, archive, phase = "normal") {
    const weights = Object.fromEntries(
        SEARCH_OPERATORS.map((operator) => [operator, searchPolicy.operatorWeights[operator]]),
    );
    const parentPool = distinctParentCandidates(archive);

    if (parentPool.length < 1) {
        weights.refinement = 0;
    } else if (weights.refinement > 0) {
        weights.refinement += archive.nearMisses.length + (archive.incumbent === null ? 0 : 1);
    }
    if (parentPool.length < 2 || searchPolicy.promptCaps.parentEvidenceIds < 2) {
        weights.crossover = 0;
    } else if (weights.crossover > 0) {
        weights.crossover += Math.min(archive.mechanismGroups.length, 8);
    }
    if (weights.diversification > 0 && archive.mechanismGroups.length < 2) {
        weights.diversification += 1;
    }
    if (archive.incumbent === null) {
        weights.adversarial = 0;
    }
    if (phase !== "normal") {
        for (const operator of SEARCH_OPERATORS) {
            if (!ESCAPE_SEARCH_OPERATORS.includes(operator)) {
                weights[operator] = 0;
            }
        }
        if (weights.restart > 0) {
            weights.restart += 1;
        }
        if (weights.adversarial > 0 && archive.incumbent !== null) {
            weights.adversarial += 1;
        }
        if (weights.diversification > 0 && archive.mechanismGroups.length === 0) {
            weights.diversification += 1;
        }
    }
    return immutableCanonical(weights);
}

export function selectAdaptiveOperator({
    searchPolicy,
    archive,
    contractHash,
    round,
    slotIndex,
    phase = "normal",
}) {
    if (phase === "normal"
        && archive.incumbent === null
        && archive.nearMisses.length === 0
        && archive.accepted.length === 0
        && archive.rejected.length === 0
        && archive.invalidMetrics.length === 0) {
        return "fresh";
    }
    const weights = adaptiveOperatorWeights(searchPolicy, archive, phase);
    const total = SEARCH_OPERATORS.reduce((sum, operator) => sum + weights[operator], 0);
    if (total < 1) {
        return phase === "normal" ? "fresh" : "restart";
    }
    let selected = deterministicHashInteger({
        contractHash,
        round,
        slotIndex,
        phase,
        weights,
    }, total);
    for (const operator of SEARCH_OPERATORS) {
        if (selected < weights[operator]) {
            return operator;
        }
        selected -= weights[operator];
    }
    return phase === "normal" ? "fresh" : "restart";
}

export const selectOperator = selectAdaptiveOperator;
export const assignSearchOperator = selectAdaptiveOperator;

function distinctParentCandidates(archive) {
    const seen = new Set();
    return [
        archive.incumbent,
        ...archive.nearMisses,
        ...archive.accepted,
    ].filter((candidate) => {
        if (candidate === null
            || candidate === undefined
            || typeof candidate.evidenceId !== "string"
            || seen.has(candidate.evidenceId)) {
            return false;
        }
        seen.add(candidate.evidenceId);
        return true;
    });
}

function fallbackOperator(archive, phase) {
    if (phase !== "normal") {
        return "restart";
    }
    return distinctParentCandidates(archive).length === 0
        ? "fresh"
        : "diversification";
}

function parentEvidenceIds(archive, promptContextRefs, operator, cap) {
    if (operator === "fresh" || operator === "restart") {
        return [];
    }
    if (operator === "adversarial") {
        const incumbentId = archive.incumbent?.evidenceId ?? null;
        return incumbentId !== null && cap >= 1 && promptContextRefs.includes(incumbentId)
            ? [incumbentId]
            : [];
    }
    const visible = distinctParentCandidates(archive)
        .filter((candidate) => promptContextRefs.includes(candidate.evidenceId));
    if (operator !== "crossover") {
        return visible.slice(0, Math.min(1, cap)).map((candidate) => candidate.evidenceId);
    }
    if (visible.length < 2 || cap < 2) {
        return [];
    }
    const first = visible[0];
    const firstMechanism = first.annotations?.mechanism ?? null;
    const second = visible.find((candidate, index) =>
        index > 0
        && firstMechanism !== null
        && candidate.annotations?.mechanism !== null
        && candidate.annotations?.mechanism !== undefined
        && candidate.annotations.mechanism !== firstMechanism)
        ?? visible[1];
    return [first.evidenceId, second.evidenceId];
}

function generatedCandidateId(round, slotIndex, replacementOrdinal = 0) {
    const base = `candidate-r${String(round).padStart(6, "0")}-s${String(slotIndex).padStart(3, "0")}`;
    return replacementOrdinal === 0
        ? base
        : `${base}-retry-${String(replacementOrdinal).padStart(3, "0")}`;
}

function replacementOrdinal(aggregate, round, slotIndex) {
    return candidateEvidence(aggregate, { includeInvalidated: true })
        .filter((evidence) =>
            evidence.invalidated
            && evidence.round === round
            && evidence.slotIndex === slotIndex)
        .length;
}

export function buildSearchCandidateCommand(aggregate, progress) {
    if (progress.nextRound === null || progress.nextSlot === null) {
        return null;
    }
    const contract = aggregate.contract;
    const policy = contract.searchPolicy;
    const archive = buildCandidateArchive(aggregate);
    const plateau = detectPlateau(aggregate);
    const round = progress.nextRound;
    const slotIndex = progress.nextSlot;
    const globalSlot = (round - 1) * contract.candidatesPerRound + slotIndex;
    const boundedCandidateId = contract.boundedCandidateIds?.[globalSlot] ?? null;
    const replacement = replacementOrdinal(aggregate, round, slotIndex);
    const candidateId = boundedCandidateId
        ?? generatedCandidateId(round, slotIndex, replacement);
    const model = contract.workerModels[globalSlot % contract.workerModels.length];
    let operator = selectAdaptiveOperator({
        searchPolicy: policy,
        archive,
        contractHash: aggregate.contractHash,
        round,
        slotIndex,
        phase: plateau.phase,
    });
    const promptContextRefs = selectPromptEvidence(archive, policy);
    const parents = parentEvidenceIds(
        archive,
        promptContextRefs,
        operator,
        policy.promptCaps.parentEvidenceIds,
    );
    const parentEligible = operator === "crossover"
        ? parents.length === 2 && parents[0] !== parents[1]
        : operator === "refinement" || operator === "adversarial"
            ? parents.length === 1
            : true;
    if (!parentEligible) {
        operator = fallbackOperator(archive, plateau.phase);
    }
    const eligibleParents = parentEligible
        ? parents
        : parentEvidenceIds(
            archive,
            promptContextRefs,
            operator,
            policy.promptCaps.parentEvidenceIds,
        );
    const seed = deterministicSeed({
        contractHash: aggregate.contractHash,
        round,
        slotIndex,
        candidateId,
        model,
        operator,
        parentEvidenceIds: eligibleParents,
        promptContextRefs,
        replacementOrdinal: replacement,
    });

    return immutableCanonical({
        kind: "search_candidate",
        round,
        slotIndex,
        candidateId,
        model,
        operator,
        parentEvidenceIds: eligibleParents,
        promptContextRefs,
        seed,
        replacementOrdinal: replacement,
        ...(boundedCandidateId === null ? {} : { boundedCandidateId }),
    });
}

export const deriveSearchCandidateCommand = buildSearchCandidateCommand;
export const createSearchCandidateCommand = buildSearchCandidateCommand;
