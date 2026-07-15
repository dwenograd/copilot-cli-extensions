export const METRICS_SCHEMA = "zerotrust-evaluation-metrics/v1";

function rate(numerator, denominator, emptyValue) {
    return denominator === 0 ? emptyValue : numerator / denominator;
}

function isControl(result) {
    return result.expectation.kind === "clean-control"
        || result.expectation.kind === "benign-lookalike";
}

export function calculateMetrics(results = []) {
    const evaluated = results.filter((result) =>
        result.comparison && result.comparison.actual);
    const totals = {
        expectedActivationFacts: 0,
        matchedActivationFacts: 0,
        expectedCandidates: 0,
        matchedCandidates: 0,
        expectedCompleteChains: 0,
        matchedCompleteChains: 0,
        expectedValidationOutcomes: 0,
        matchedValidationOutcomes: 0,
        controlFixtures: 0,
        falsePositiveFixtures: 0,
        candidates: 0,
        unresolved: 0,
    };
    const failureReasons = {
        prepare: {},
        scan: {},
        trace: {},
        validate: {},
        finalize: {},
    };

    for (const result of evaluated) {
        const observation = result.comparison.observations;
        totals.expectedActivationFacts += observation.expectedActivationFacts;
        totals.matchedActivationFacts += observation.matchedActivationFacts;
        totals.expectedCandidates += observation.expectedCandidates;
        totals.matchedCandidates += observation.matchedCandidates;
        totals.expectedCompleteChains += observation.expectedCompleteChains;
        totals.matchedCompleteChains += observation.matchedCompleteChains;
        totals.expectedValidationOutcomes += observation.expectedValidated
            + observation.expectedRefuted;
        totals.matchedValidationOutcomes += observation.matchedValidated
            + observation.matchedRefuted;
        totals.candidates += result.comparison.actual.counts.candidate;
        totals.unresolved += result.comparison.actual.counts.unresolved;

        if (isControl(result)) {
            totals.controlFixtures += 1;
            const actual = result.comparison.actual.counts;
            const expected = result.expectation.expected.counts;
            if (actual.validated > expected.validated.max
                || actual.unresolved > expected.unresolved.max) {
                totals.falsePositiveFixtures += 1;
            }
        }

        const stage = result.comparison.actual.failureStage;
        if (stage && failureReasons[stage]) {
            const reason = result.comparison.actual.failureReason || "unspecified";
            failureReasons[stage][reason] = (failureReasons[stage][reason] || 0) + 1;
        }
    }

    return Object.freeze({
        schema: METRICS_SCHEMA,
        fixtureCount: evaluated.length,
        activationRecall: rate(
            totals.matchedActivationFacts,
            totals.expectedActivationFacts,
            1,
        ),
        candidateRecall: rate(
            totals.matchedCandidates,
            totals.expectedCandidates,
            1,
        ),
        completeChainRecall: rate(
            totals.matchedCompleteChains,
            totals.expectedCompleteChains,
            1,
        ),
        validationRefutationAccuracy: rate(
            totals.matchedValidationOutcomes,
            totals.expectedValidationOutcomes,
            1,
        ),
        falsePositiveRate: rate(
            totals.falsePositiveFixtures,
            totals.controlFixtures,
            0,
        ),
        unresolvedRate: rate(totals.unresolved, totals.candidates, 0),
        failureReasons,
        totals,
    });
}

function thresholdFailure(metric, actual, threshold, direction) {
    const passed = direction === "minimum"
        ? actual >= threshold
        : actual <= threshold;
    return passed ? null : {
        metric,
        actual,
        threshold,
        direction,
    };
}

export function evaluatePromotionGate(metrics, thresholds) {
    if (!thresholds || thresholds.schema !== "zerotrust-promotion-gate/v1") {
        throw new TypeError("promotion thresholds must use zerotrust-promotion-gate/v1");
    }
    const failures = [
        thresholdFailure(
            "activationRecall",
            metrics.activationRecall,
            thresholds.minimum.activation_recall,
            "minimum",
        ),
        thresholdFailure(
            "candidateRecall",
            metrics.candidateRecall,
            thresholds.minimum.candidate_recall,
            "minimum",
        ),
        thresholdFailure(
            "completeChainRecall",
            metrics.completeChainRecall,
            thresholds.minimum.complete_chain_recall,
            "minimum",
        ),
        thresholdFailure(
            "validationRefutationAccuracy",
            metrics.validationRefutationAccuracy,
            thresholds.minimum.validation_refutation_accuracy,
            "minimum",
        ),
        thresholdFailure(
            "falsePositiveRate",
            metrics.falsePositiveRate,
            thresholds.maximum.false_positive_rate,
            "maximum",
        ),
        thresholdFailure(
            "unresolvedRate",
            metrics.unresolvedRate,
            thresholds.maximum.unresolved_rate,
            "maximum",
        ),
    ].filter(Boolean);
    return {
        passed: failures.length === 0,
        failures,
    };
}

export const __internals = Object.freeze({
    rate,
    isControl,
    thresholdFailure,
});
