import { describe, expect, it } from "vitest";

import {
    STATISTICAL_ALLOCATION_SCHEDULE,
    STATISTICAL_DEFAULT_SUCCESS_PROBABILITY_THRESHOLD,
    STATISTICAL_ERROR_CODES,
    claimAlphaAllocation,
    createInvestigationContract,
    evaluateDirectionClaim,
    evaluateIntervalClaim,
    evaluatePracticalEquivalence,
    evaluateStatisticalClaims,
    evaluateThresholdClaim,
    hoeffdingMeanConfidenceSequence,
    hoeffdingPairedDifferenceConfidenceSequence,
    normalizeBinaryObservation,
    normalizeBoundedObservation,
    statisticalMetricClaims,
    statisticalScheduleWeight,
    supportsPracticalEquivalence,
    supportsPracticalMargin,
} from "../domain/index.mjs";
import {
    fakeStatisticalPolicy,
    makeV4ContractInput,
} from "./v4-contract-fixture.mjs";

function makePolicy({
    maxBlocks = 4096,
    minBlocks = 1,
    metrics = null,
    observableRegistry = null,
    familyAllocations = null,
    investigationAlpha = 0.05,
    missingness = null,
} = {}) {
    const resolvedMetrics = metrics ?? [{
        key: "score",
        minimum: 0,
        maximum: 1,
        estimand: "mean score",
        unit: "score",
        direction: "max",
        acceptanceThreshold: 0.8,
        practicalEquivalenceDelta: 0.01,
        family: "primary",
    }];
    const registry = observableRegistry ?? resolvedMetrics.map((metric) => ({
        key: metric.key,
        kind: "numeric",
        minimum: metric.minimum,
        maximum: metric.maximum,
    }));
    const statisticalPolicy = fakeStatisticalPolicy({
        maxBlocks,
        minBlocks,
        metrics: resolvedMetrics,
    });
    statisticalPolicy.investigationAlpha = investigationAlpha;
    statisticalPolicy.familyAllocations = familyAllocations ?? [{
        family: "primary",
        alpha: investigationAlpha,
    }];
    if (missingness !== null) {
        statisticalPolicy.missingness = missingness;
    }
    return createInvestigationContract(makeV4ContractInput({
        observableRegistry: registry,
        statisticalPolicy,
    })).statisticalPolicy;
}

function indexedBlocks(count, candidate, control = undefined) {
    return Array.from({ length: count }, (_unused, blockIndex) => ({
        blockIndex,
        candidate: typeof candidate === "function"
            ? candidate(blockIndex)
            : candidate,
        ...(control === undefined
            ? {}
            : {
                control: typeof control === "function"
                    ? control(blockIndex)
                    : control,
            }),
    }));
}

describe("v4 bounded statistics primitives", () => {
    it("normalizes finite metric and binary observations and rejects bad values", () => {
        expect(normalizeBoundedObservation(15, {
            minimum: 10,
            maximum: 20,
        })).toBe(0.5);
        expect(normalizeBoundedObservation(10, {
            minimum: 10,
            maximum: 20,
        })).toBe(0);
        expect(normalizeBoundedObservation(20, {
            minimum: 10,
            maximum: 20,
        })).toBe(1);
        expect(normalizeBinaryObservation(true)).toBe(1);
        expect(normalizeBinaryObservation(0)).toBe(0);
        expect(() => normalizeBoundedObservation(21, {
            minimum: 10,
            maximum: 20,
        })).toThrow(/outside/u);
        expect(() => normalizeBoundedObservation(Number.NaN, {
            minimum: 0,
            maximum: 1,
        })).toThrow(/finite/u);
        expect(() => normalizeBinaryObservation(0.5)).toThrow(/zero\/one/u);
    });

    it("uses exact telescoping subject/look schedules and an auditable ledger", () => {
        const policy = makePolicy();
        const allocation = claimAlphaAllocation({
            statisticalPolicy: policy,
            family: "primary",
            subject: { kind: "enumerand", index: 0 },
            claimIndex: 0,
            claimCount: 1,
            lookIndex: 3,
        });
        expect(allocation.claim.alpha).toBeCloseTo(0.05 * 0.5, 15);
        expect(allocation.look.alpha).toBeCloseTo(
            0.05 * 0.5 / (3 * 4),
            15,
        );
        expect(allocation.look.cumulativeWeight).toBe(3 / 4);
        expect(allocation.ledger.at(-1)).toMatchObject({
            scope: "look",
            schedule: STATISTICAL_ALLOCATION_SCHEDULE,
            infiniteScheduleWeightSumUpperBound: 1,
        });

        const count = 100_000;
        const sum = Array.from(
            { length: count },
            (_unused, index) => statisticalScheduleWeight(index + 1),
        ).reduce((total, value) => total + value, 0);
        expect(sum).toBeCloseTo(count / (count + 1), 13);
        expect(sum).toBeLessThan(1);
    });

    it("partitions multiple claims and metrics without exceeding familywise alpha", () => {
        const metrics = [
            {
                key: "latency",
                minimum: 0,
                maximum: 100,
                estimand: "mean latency",
                unit: "ms",
                direction: "min",
                acceptanceThreshold: 50,
                practicalEquivalenceDelta: 2,
                family: "secondary",
            },
            {
                key: "score",
                minimum: 0,
                maximum: 1,
                estimand: "mean score",
                unit: "score",
                direction: "max",
                acceptanceThreshold: 0.8,
                practicalEquivalenceDelta: 0.01,
                family: "primary",
            },
        ];
        const policy = makePolicy({
            metrics,
            familyAllocations: [
                { family: "primary", alpha: 0.03 },
                { family: "secondary", alpha: 0.02 },
            ],
        });
        const primary = [0, 1].map((claimIndex) => claimAlphaAllocation({
            statisticalPolicy: policy,
            family: "primary",
            subject: { kind: "candidate", index: 0 },
            claimIndex,
            claimCount: 2,
        }).claim.alpha);
        const secondary = claimAlphaAllocation({
            statisticalPolicy: policy,
            family: "secondary",
            subject: { kind: "candidate", index: 0 },
            claimIndex: 0,
            claimCount: 1,
        }).claim.alpha;
        expect(primary[0] + primary[1] + secondary)
            .toBeCloseTo(policy.investigationAlpha * 0.5, 15);
    });

    it("matches independent Hoeffding golden calculations for means and pairs", () => {
        const observations = Array.from({ length: 100 }, () => 0.5);
        const alphaClaim = 0.04;
        const mean = hoeffdingMeanConfidenceSequence({
            observations,
            alphaClaim,
        });
        const alphaLook = alphaClaim / (100 * 101);
        const expectedRadius = Math.sqrt(
            Math.log(2 / alphaLook) / (2 * observations.length),
        );
        expect(mean.pointEstimate).toBe(0.5);
        expect(mean.radius).toBeCloseTo(expectedRadius, 14);
        expect(mean.confidenceSequence.lower)
            .toBeCloseTo(0.5 - expectedRadius, 14);
        expect(mean.confidenceSequence.upper)
            .toBeCloseTo(0.5 + expectedRadius, 14);

        const pairs = Array.from(
            { length: 200 },
            () => ({ candidate: 0.8, reference: 0.2 }),
        );
        const paired = hoeffdingPairedDifferenceConfidenceSequence({
            pairs,
            alphaClaim: 0.05,
        });
        const pairedAlphaLook = 0.05 / (200 * 201);
        const pairedRadius = 2 * Math.sqrt(
            Math.log(2 / pairedAlphaLook) / (2 * pairs.length),
        );
        expect(paired.pointEstimate).toBeCloseTo(0.6, 14);
        expect(paired.radius).toBeCloseTo(pairedRadius, 14);
        expect(paired.bounds).toEqual({ lower: -1, range: 2, upper: 1 });
    });

    it("implements conservative threshold, interval, direction, and equivalence states", () => {
        expect(evaluateThresholdClaim(
            { lower: 0.81, upper: 0.9 },
            ">=",
            0.8,
        )).toBe("SUPPORTED");
        expect(evaluateThresholdClaim(
            { lower: 0.1, upper: 0.79 },
            ">=",
            0.8,
        )).toBe("REFUTED");
        expect(evaluateIntervalClaim(
            { lower: 0.45, upper: 0.55 },
            0.4,
            0.6,
        )).toBe("SUPPORTED");
        expect(evaluateIntervalClaim(
            { lower: 0.55, upper: 0.65 },
            0.4,
            0.6,
        )).toBe("UNRESOLVED");
        expect(evaluateDirectionClaim(
            { lower: 0.11, upper: 0.3 },
            { direction: "increase", practicalMargin: 0.1 },
        )).toBe("SUPPORTED");
        expect(supportsPracticalMargin(
            { lower: -0.3, upper: -0.11 },
            { direction: "decrease", margin: 0.1 },
        )).toBe(true);
        expect(evaluatePracticalEquivalence(
            { lower: -0.05, upper: 0.05 },
            { margin: 0.1 },
        )).toBe("SUPPORTED");
        expect(evaluatePracticalEquivalence(
            { lower: 0.05, upper: 0.15 },
            { margin: 0.1 },
        )).toBe("UNRESOLVED");
        expect(evaluatePracticalEquivalence(
            { lower: 0.2, upper: 0.3 },
            { margin: 0.1 },
        )).toBe("REFUTED");
        expect(supportsPracticalEquivalence(
            { lower: -0.05, upper: 0.05 },
            { margin: 0.1 },
        )).toBe(true);
    });
});

describe("v4 bounded statistical claim evaluation", () => {
    it("supports and refutes policy-derived metric threshold claims", () => {
        const policy = makePolicy({ maxBlocks: 256 });
        expect(statisticalMetricClaims(policy)).toEqual([{
            family: "primary",
            id: "metric.score.acceptance",
            kind: "threshold",
            observable: "score",
            operator: ">=",
            source: "frozen_statistical_policy",
            value: 0.8,
        }]);
        const supported = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            subject: { kind: "candidate", index: 0 },
            blocks: indexedBlocks(256, { metrics: { score: 1 } }),
        });
        expect(supported.overallState).toBe("SUPPORTED");
        expect(supported.claims[0].state).toBe("SUPPORTED");

        const refuted = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            subject: { kind: "candidate", index: 0 },
            blocks: indexedBlocks(64, { metrics: { score: 0 } }),
        });
        expect(refuted.overallState).toBe("REFUTED");
        expect(refuted.claims[0].state).toBe("REFUTED");
    });

    it("evaluates paired control and assigned-parent directions", () => {
        const policy = makePolicy({ maxBlocks: 128 });
        const control = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            subject: { kind: "candidate", index: 0 },
            claims: [{
                id: "increase-vs-control",
                kind: "direction_vs_control",
                observable: "score",
                direction: "increase",
            }],
            blocks: indexedBlocks(
                128,
                { metrics: { score: 0.8 } },
                { metrics: { score: 0.2 } },
            ),
        });
        expect(control.claims[0]).toMatchObject({
            state: "SUPPORTED",
            reference: { kind: "control" },
        });
        expect(control.claims[0].estimate.pointEstimate).toBeCloseTo(0.6, 14);

        const parent = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            subject: { kind: "candidate", index: 0 },
            claims: [{
                id: "increase-vs-parent",
                kind: "direction",
                observable: "score",
                direction: "increase",
                reference: {
                    kind: "assigned_parent",
                    evidenceId: "ev-parent",
                },
            }],
            blocks: indexedBlocks(
                128,
                (blockIndex) => ({
                    metrics: { score: 0.8 },
                    blockIndex,
                }),
            ).map((block) => ({
                ...block,
                parents: {
                    "ev-parent": { metrics: { score: 0.2 } },
                },
            })),
        });
        expect(parent.claims[0]).toMatchObject({
            state: "SUPPORTED",
            reference: {
                kind: "assigned_parent",
                evidenceId: "ev-parent",
            },
        });
    });

    it("supports categorical and harness-pass claims as bounded Bernoulli means", () => {
        const policy = makePolicy({ maxBlocks: 256 });
        const observableRegistry = [
            { key: "score", kind: "numeric", minimum: 0, maximum: 1 },
            {
                key: "outcome",
                kind: "categorical",
                values: ["accepted", "rejected"],
            },
        ];
        const result = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            observableRegistry,
            subject: { kind: "candidate", index: 0 },
            claims: [
                {
                    id: "accepted-outcome",
                    kind: "categorical_outcome",
                    observable: "outcome",
                    outcome: "accepted",
                },
                {
                    id: "harness-passes",
                    kind: "harness_pass",
                    expected: true,
                },
            ],
            blocks: indexedBlocks(256, {
                pass: true,
                observables: { outcome: "accepted" },
            }),
        });
        expect(result.overallState).toBe("SUPPORTED");
        expect(result.claims.map((claim) => claim.state))
            .toEqual(["SUPPORTED", "SUPPORTED"]);
        expect(result.claims[0].practical.probabilityThreshold)
            .toBe(STATISTICAL_DEFAULT_SUCCESS_PROBABILITY_THRESHOLD);
    });

    it("is permutation invariant after canonical block and claim indexing", () => {
        const policy = makePolicy({ maxBlocks: 32 });
        const blocks = indexedBlocks(
            32,
            (index) => ({ metrics: { score: (index % 5) / 4 } }),
        );
        const claims = [
            {
                id: "threshold-b",
                kind: "threshold",
                observable: "score",
                operator: ">=",
                value: 0.4,
            },
            {
                id: "threshold-a",
                kind: "threshold",
                observable: "score",
                operator: ">=",
                value: 0.2,
            },
        ];
        const first = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            subject: { kind: "enumerand", index: 3 },
            claims,
            blocks,
        });
        const second = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            subject: { kind: "enumerand", index: 3 },
            claims: [...claims].reverse(),
            blocks: [...blocks].reverse(),
        });
        expect(second).toEqual(first);
    });

    it("rejects nonfinite/out-of-bounds observations and malformed block streams", () => {
        const policy = makePolicy({ maxBlocks: 4 });
        for (const value of [1.01, -0.01, Number.POSITIVE_INFINITY]) {
            const result = evaluateStatisticalClaims({
                statisticalPolicy: policy,
                subject: { kind: "candidate", index: 0 },
                blocks: indexedBlocks(1, { metrics: { score: value } }),
            });
            expect(result.overallState).toBe("INVALID");
            expect(result.invalid.code)
                .toBe(STATISTICAL_ERROR_CODES.INVALID_OBSERVATION);
        }
        const gap = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            subject: { kind: "candidate", index: 0 },
            blocks: [{
                blockIndex: 1,
                candidate: { metrics: { score: 0.9 } },
            }],
        });
        expect(gap.overallState).toBe("INVALID");
        expect(gap.invalid.code).toBe(STATISTICAL_ERROR_CODES.INVALID_BLOCK);
    });

    it("fails closed or uses worst-case bounded intervals exactly as frozen", () => {
        const failClosed = makePolicy({ maxBlocks: 4 });
        const missing = indexedBlocks(
            4,
            (index) => ({
                metrics: { score: index === 0 ? null : 1 },
            }),
        );
        const rejected = evaluateStatisticalClaims({
            statisticalPolicy: failClosed,
            subject: { kind: "candidate", index: 0 },
            blocks: missing,
        });
        expect(rejected.overallState).toBe("INVALID");
        expect(rejected.invalid.code)
            .toBe(STATISTICAL_ERROR_CODES.MISSINGNESS_POLICY_VIOLATION);

        const bounded = makePolicy({
            maxBlocks: 4,
            missingness: {
                mode: "bounded",
                maxMissingPerBlock: 1,
                maxMissingFraction: 0.25,
            },
        });
        const conservative = evaluateStatisticalClaims({
            statisticalPolicy: bounded,
            subject: { kind: "candidate", index: 0 },
            blocks: missing,
        });
        expect(conservative.overallState).toBe("UNRESOLVED");
        expect(conservative.missingness).toMatchObject({
            totalMissing: 1,
            totalExpected: 4,
            missingFraction: 0.25,
            treatment: "worst_case_bounded_identification_intervals",
        });
        expect(conservative.claims[0].normalizedConfidenceSequence)
            .toMatchObject({
                empiricalIdentificationInterval: {
                    lower: 0.75,
                    upper: 1,
                },
                missingObservationCount: 1,
            });

        const excessive = evaluateStatisticalClaims({
            statisticalPolicy: bounded,
            subject: { kind: "candidate", index: 0 },
            blocks: indexedBlocks(
                4,
                (index) => ({
                    metrics: { score: index < 2 ? null : 1 },
                }),
            ),
        });
        expect(excessive.overallState).toBe("INVALID");
        expect(excessive.invalid.code)
            .toBe(STATISTICAL_ERROR_CODES.MISSINGNESS_POLICY_VIOLATION);
    });

    it("gates claims on minBlocks and stays finite at subnormal alpha", () => {
        const gatedPolicy = makePolicy({
            maxBlocks: 4,
            minBlocks: 3,
        });
        const gated = evaluateStatisticalClaims({
            statisticalPolicy: gatedPolicy,
            subject: { kind: "candidate", index: 0 },
            blocks: indexedBlocks(2, { metrics: { score: 1 } }),
        });
        expect(gated.claims[0]).toMatchObject({
            state: "UNRESOLVED",
            decision: {
                gatedByMinimumBlocks: true,
                reason: "minimum_blocks_not_met",
            },
        });

        const tinyPolicy = makePolicy({
            maxBlocks: 1,
            investigationAlpha: Number.MIN_VALUE,
        });
        const tiny = evaluateStatisticalClaims({
            statisticalPolicy: tinyPolicy,
            subject: { kind: "candidate", index: 0 },
            blocks: indexedBlocks(1, { metrics: { score: 1 } }),
        });
        const claim = tiny.claims[0];
        expect(claim.allocation.claim.alpha).toBe(0);
        expect(claim.allocation.claim.alphaUnderflowed).toBe(true);
        expect(Number.isFinite(claim.allocation.claim.logAlpha)).toBe(true);
        expect(Number.isFinite(
            claim.normalizedConfidenceSequence.radius,
        )).toBe(true);
        expect(claim.estimate.confidenceSequence)
            .toEqual({ lower: 0, upper: 1 });
    });

    it("records assumptions as conditions rather than proof claims", () => {
        const policy = makePolicy({ maxBlocks: 1 });
        const result = evaluateStatisticalClaims({
            statisticalPolicy: policy,
            subject: { kind: "candidate", index: 0 },
            blocks: indexedBlocks(1, { metrics: { score: 0.5 } }),
        });
        expect(result.assumptions.sampling.independenceAcrossIndexedBlocks)
            .toMatch(/assumed.*not_proven/u);
        expect(result.assumptions.sampling.stabilityAcrossSequentialLooks)
            .toMatch(/assumed.*not_proven/u);
        expect(result.assumptions.interpretation).toMatch(/does not assert/u);
        expect(JSON.stringify(result)).not.toMatch(/pValue|p_value|p-value/u);
    });
});
