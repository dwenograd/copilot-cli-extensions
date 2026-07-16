export const METRICS_SCHEMA = "zerotrust-evaluation-metrics";
export const QUALITY_GATE_SCHEMA = "zerotrust-quality-gate";

const FAVORABLE_ASSURANCE_LEVELS = new Set([
    "bounded-static",
    "comprehensive-static",
    "comprehensive-static-with-supply-chain",
]);

function rate(numerator, denominator, emptyValue) {
    return denominator === 0 ? emptyValue: numerator / denominator;
}

function isControl(result) {
    return result.expectation.kind === "clean-control"
        || result.expectation.kind === "benign-lookalike";
}

function calculateAggregate(evaluated) {
    const totals = {
        expectedActivationFacts: 0,
        matchedActivationFacts: 0,
        expectedCandidates: 0,
        matchedCandidates: 0,
        expectedCompleteChains: 0,
        matchedCompleteChains: 0,
        expectedValidationOutcomes: 0,
        matchedValidationOutcomes: 0,
        expectedRefutations: 0,
        matchedRefutations: 0,
        controlFixtures: 0,
        falsePositiveFixtures: 0,
        knownCoverageBlockerFixtures: 0,
        favorableAssuranceWithKnownBlockers: 0,
        candidates: 0,
        unresolved: 0,
        metamorphicVariants: 0,
        matchedMetamorphicVariants: 0,
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
        totals.expectedRefutations += observation.expectedRefuted;
        totals.matchedRefutations += observation.matchedRefuted;
        totals.candidates += result.comparison.actual.counts.candidate;
        totals.unresolved += result.comparison.actual.counts.unresolved;
        totals.metamorphicVariants += result.metamorphic?.variants?.length || 0;
        totals.matchedMetamorphicVariants += (result.metamorphic?.variants || [])
            .filter((variant) => variant.passed).length;

        if (result.expectation.dimensions?.known_coverage_blockers === true) {
            totals.knownCoverageBlockerFixtures += 1;
            if (FAVORABLE_ASSURANCE_LEVELS.has(
                result.comparison.actual.assuranceLevel,
            )) {
                totals.favorableAssuranceWithKnownBlockers += 1;
            }
        }

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

    return {
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
        refutationAccuracy: rate(
            totals.matchedRefutations,
            totals.expectedRefutations,
            1,
        ),
        falsePositiveRate: rate(
            totals.falsePositiveFixtures,
            totals.controlFixtures,
            0,
        ),
        unresolvedRate: rate(totals.unresolved, totals.candidates, 0),
        favorableAssuranceWithKnownBlockers:
            totals.favorableAssuranceWithKnownBlockers,
        metamorphicStability: rate(
            totals.matchedMetamorphicVariants,
            totals.metamorphicVariants,
            1,
        ),
        failureReasons,
        totals,
    };
}

function dimensionMetrics(evaluated, selector) {
    const grouped = new Map();
    for (const result of evaluated) {
        for (const value of selector(result.expectation.dimensions || {})) {
            const entries = grouped.get(value) || [];
            entries.push(result);
            grouped.set(value, entries);
        }
    }
    return Object.freeze(Object.fromEntries(
        [...grouped.entries()]
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([value, entries]) => [
                value,
                Object.freeze(calculateAggregate(entries)),
            ]),
    ));
}

export function calculateMetrics(results = []) {
    const evaluated = results.filter((result) =>
        result.comparison && result.comparison.actual);
    return Object.freeze({
        schema: METRICS_SCHEMA,
        ...calculateAggregate(evaluated),
        dimensions: Object.freeze({
            evasionClass: dimensionMetrics(
                evaluated,
                (value) => value.evasion_classes || [],
            ),
            artifactClass: dimensionMetrics(
                evaluated,
                (value) => value.artifact_classes || [],
            ),
            language: dimensionMetrics(
                evaluated,
                (value) => value.languages || [],
            ),
            size: dimensionMetrics(
                evaluated,
                (value) => value.size ? [value.size]: [],
            ),
        }),
    });
}

function thresholdFailure(metric, actual, threshold, direction) {
    const passed = direction === "minimum"
        ? actual >= threshold: actual <= threshold;
    return passed ? null: {
        metric,
        actual,
        threshold,
        direction,
    };
}

export function evaluateQualityGate(metrics, thresholds) {
    if (!thresholds || thresholds.schema !== QUALITY_GATE_SCHEMA) {
        throw new TypeError(
            "quality thresholds must use zerotrust-quality-gate",
        );
    }
    const failures = [
        thresholdFailure(
            "activationRecall",
            metrics.activationRecall,
            thresholds.minimum.activation_recall,
            "minimum",
        ),
        thresholdFailure(
            "completeChainRecall",
            metrics.completeChainRecall,
            thresholds.minimum.complete_chain_recall,
            "minimum",
        ),
        thresholdFailure(
            "refutationAccuracy",
            metrics.refutationAccuracy,
            thresholds.minimum.refutation_accuracy,
            "minimum",
        ),
        thresholdFailure(
            "falsePositiveRate",
            metrics.falsePositiveRate,
            thresholds.maximum.clean_control_false_positive_rate,
            "maximum",
        ),
        thresholdFailure(
            "favorableAssuranceWithKnownBlockers",
            metrics.favorableAssuranceWithKnownBlockers,
            thresholds.maximum.favorable_assurance_with_known_blockers,
            "maximum",
        ),
    ].filter(Boolean);
    for (const evasionClass of thresholds.mandatory_evasion_classes) {
        const classMetrics = metrics.dimensions?.evasionClass?.[evasionClass];
        if (!classMetrics) {
            failures.push({
                metric: `candidateRecall:${evasionClass}`,
                actual: null,
                threshold:
                    thresholds.minimum.candidate_recall_per_mandatory_evasion_class,
                direction: "minimum",
                reason: "missing mandatory evasion class",
            });
            continue;
        }
        if (classMetrics.totals.expectedCandidates === 0) {
            failures.push({
                metric: `candidateRecall:${evasionClass}`,
                actual: null,
                threshold:
                    thresholds.minimum.candidate_recall_per_mandatory_evasion_class,
                direction: "minimum",
                reason: "mandatory evasion class has no candidate-bearing fixture",
            });
            continue;
        }
        const failure = thresholdFailure(
            `candidateRecall:${evasionClass}`,
            classMetrics.candidateRecall,
            thresholds.minimum.candidate_recall_per_mandatory_evasion_class,
            "minimum",
        );
        if (failure) failures.push(failure);
    }
    return {
        schema: QUALITY_GATE_SCHEMA,
        passed: failures.length === 0,
        failures,
    };
}

export const __internals = Object.freeze({
    rate,
    isControl,
    calculateAggregate,
    dimensionMetrics,
    thresholdFailure,
    FAVORABLE_ASSURANCE_LEVELS,
});
