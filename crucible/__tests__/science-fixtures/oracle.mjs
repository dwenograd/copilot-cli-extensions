import { SCIENCE_FIXTURES } from "./fixtures.mjs";

function round(value, digits) {
    const scale = 10 ** digits;
    return Math.round((value + Number.EPSILON) * scale) / scale;
}

function compare(actual, operator, expected) {
    switch (operator) {
        case "<": return actual < expected;
        case "<=": return actual <= expected;
        case "==": return actual === expected;
        case ">=": return actual >= expected;
        case ">": return actual > expected;
        default: throw new Error(`Unsupported independent comparison operator: ${operator}`);
    }
}

function evaluatePredicate(predicate, result) {
    switch (predicate.kind) {
        case "constant":
            return predicate.value;
        case "harness_pass":
            return result.pass === true;
        case "metric_compare":
            return compare(
                result.metrics?.[predicate.metric],
                predicate.operator,
                predicate.value,
            );
        default:
            throw new Error(`Unsupported independent predicate kind: ${predicate.kind}`);
    }
}

function evaluatePrediction(candidate) {
    const prediction = candidate.intendedPrediction;
    return compare(
        candidate.result.metrics[prediction.metric],
        prediction.operator,
        prediction.value,
    );
}

export function buildScienceOracle() {
    const nullNoise = SCIENCE_FIXTURES.nullNoise;
    const thresholdCrossings = nullNoise.observations
        .map((score, index) => ({ index, score }))
        .filter(({ score }) => score >= nullNoise.acceptanceThreshold);

    const effect = SCIENCE_FIXTURES.effectAndTie;
    const trueEffectWinner = [...effect.trueEffectCandidates]
        .sort((left, right) => right.score - left.score)[0];
    const tiedScore = effect.equalCandidates[0].score;
    const exactTie = effect.equalCandidates.every((candidate) =>
        candidate.score === tiedScore);

    const drift = SCIENCE_FIXTURES.drift;
    const withinBlockDifferences = drift.blocks.map((block) =>
        block.observations[1].score - block.observations[0].score);
    const rawDriftAcceptedIds = drift.blocks
        .flatMap((block) => block.observations)
        .filter((observation) => observation.score >= drift.acceptanceThreshold)
        .map((observation) => observation.id);

    const predicate = SCIENCE_FIXTURES.predicateDisagreement;
    const predicateCases = predicate.cases.map((item) => ({
        id: item.id,
        harnessPass: item.result.pass,
        predicateSatisfied: evaluatePredicate(item.predicate, item.result),
    }));

    const predictions = SCIENCE_FIXTURES.typedPredictions;
    const predictionTruth = Object.fromEntries(
        predictions.candidates.map((candidate) => [
            candidate.id,
            evaluatePrediction(candidate),
        ]),
    );

    const overfit = SCIENCE_FIXTURES.overfit;
    const confirmedIds = overfit.candidates
        .filter((candidate) =>
            candidate.discovery.pass
            && candidate.heldOut.pass
            && candidate.challenge.pass
            && candidate.heldOut.score >= overfit.acceptanceThreshold
            && candidate.challenge.score >= overfit.acceptanceThreshold)
        .map((candidate) => candidate.id);
    const discoveryWinner = [...overfit.candidates]
        .sort((left, right) => right.discovery.score - left.discovery.score)[0].id;
    const confirmationWinner = [...overfit.candidates]
        .filter((candidate) => confirmedIds.includes(candidate.id))
        .sort((left, right) =>
            Math.min(right.heldOut.score, right.challenge.score)
            - Math.min(left.heldOut.score, left.challenge.score))[0]?.id ?? null;

    const bounded = SCIENCE_FIXTURES.boundedEnumerands;
    const boundedIdsUnique =
        new Set(bounded.duplicateIds).size === bounded.duplicateIds.length;
    const enumerandContentChanged =
        bounded.originalEnumerands["enum-a"].contentHash
        !== bounded.mutatedEnumerands["enum-a"].contentHash;

    const impossibility = SCIENCE_FIXTURES.impossibility;
    const selfGeneratedIsIndependent =
        impossibility.selfCertificationMetadata.generatorId
        !== impossibility.selfCertificationMetadata.verifierId;

    const optimization = SCIENCE_FIXTURES.optimization;
    const bestOptimizationCandidate = [...optimization.candidates]
        .sort((left, right) => right.score - left.score)[0];
    const improvementPercent = (
        (bestOptimizationCandidate.score - optimization.initialScore)
        / optimization.initialScore
    ) * 100;

    return {
        nullNoise: {
            firstThresholdCrossing: thresholdCrossings[0]?.index ?? null,
            thresholdCrossingCount: thresholdCrossings.length,
            familyFalsePositiveProbability: round(
                1 - (nullNoise.acceptanceThreshold ** nullNoise.observations.length),
                12,
            ),
            scientificVerdict: "not_verified",
            reason: "All observations are sampled from a declared null/no-effect stream.",
        },
        effectAndTie: {
            trueEffectWinnerId: trueEffectWinner.id,
            trueEffectWinnerScore: trueEffectWinner.score,
            equalCandidatesAreTied: exactTie,
            tiedCandidateIds: effect.equalCandidates.map((candidate) => candidate.id),
        },
        drift: {
            withinBlockDifferences,
            maxAbsoluteWithinBlockDifference: Math.max(
                ...withinBlockDifferences.map(Math.abs),
            ),
            rawDriftAcceptedIds,
            scientificVerdict: "no_candidate_effect",
        },
        predicateDisagreement: {
            cases: predicateCases,
            disagreementCount: predicateCases.filter((item) =>
                item.harnessPass !== item.predicateSatisfied).length,
        },
        typedPredictions: {
            predictionTruth,
            supportedIds: Object.keys(predictionTruth)
                .filter((id) => predictionTruth[id]),
            refutedIds: Object.keys(predictionTruth)
                .filter((id) => !predictionTruth[id]),
        },
        overfit: {
            discoveryWinner,
            confirmedIds,
            confirmationWinner,
            scientificVerdict: confirmedIds.length > 0
                ? "confirmation_required"
                : "not_verified",
        },
        boundedEnumerands: {
            duplicateIdsUnique: boundedIdsUnique,
            duplicateIdsShouldBeRejected: !boundedIdsUnique,
            enumerandContentChanged,
            contentMutationShouldChangeIdentity: enumerandContentChanged,
        },
        impossibility: {
            selfGeneratedIsIndependent,
            invalidFactsShouldProveUnreachable: false,
            disagreeingAttemptsShouldProveUnreachable: false,
        },
        lifecycleMetadata: {
            rebootRecoveryFieldsRequired:
                SCIENCE_FIXTURES.lifecycleMetadata.rebootRecovery.requiredFields,
            rolloverFieldsRequired:
                SCIENCE_FIXTURES.lifecycleMetadata.rollover.requiredFields,
            resourceContentionFieldsRequired:
                SCIENCE_FIXTURES.lifecycleMetadata.resourceContention.requiredFields,
        },
        optimization: {
            winnerId: bestOptimizationCandidate.id,
            score: bestOptimizationCandidate.score,
            percentOfKnownOptimum: round(
                (bestOptimizationCandidate.score / optimization.knownOptimum) * 100,
                1,
            ),
            improvementPercent: round(improvementPercent, 1),
            exactImprovementPercent: round(improvementPercent, 12),
        },
    };
}

