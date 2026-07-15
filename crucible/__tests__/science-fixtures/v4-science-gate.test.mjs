import { describe, expect, it } from "vitest";

import {
    V4_SCIENCE_THRESHOLDS,
    buildV4ScienceBenchmark,
} from "./v4-adapter.mjs";

const benchmark = buildV4ScienceBenchmark();

describe("Crucible v4 falsifiable science acceptance benchmark", () => {
    it("bounds false VERIFIED outcomes under continuous peeking and meets power", () => {
        const { null: nullCase, power } =
            benchmark.metrics.nullAndPower;
        expect(nullCase.upperConfidenceBound95).toBeLessThanOrEqual(
            V4_SCIENCE_THRESHOLDS.nullFamilywiseAlpha
            + V4_SCIENCE_THRESHOLDS.nullTolerance,
        );
        expect(power.lowerConfidenceBound95).toBeGreaterThanOrEqual(
            V4_SCIENCE_THRESHOLDS.preregisteredPower,
        );
        expect(nullCase.passed).toBe(true);
        expect(power.passed).toBe(true);
    });

    it("fails closed on drift, invalid controls, correlation, and pass disagreement", () => {
        expect(benchmark.metrics.environment.drift).toMatchObject({
            controlStatus: "drift_detected",
            requiredState: expect.not.stringMatching(/^SUPPORTED$/u),
            passed: true,
        });
        expect(benchmark.metrics.environment.invalidControl).toMatchObject({
            requiredState: expect.not.stringMatching(/^SUPPORTED$/u),
            passed: true,
        });
        expect(benchmark.metrics.environment.correlation).toMatchObject({
            requiredState: expect.not.stringMatching(/^SUPPORTED$/u),
            passed: true,
        });
        expect(benchmark.metrics.predicate).toMatchObject({
            predicateIsAuthoritative: true,
            passed: true,
        });
    });

    it("supports and refutes typed predictions with an exact code-authored conclusion", () => {
        expect(benchmark.metrics.predictions).toEqual({
            statuses: {
                "false-prediction": "REFUTED",
                "true-prediction": "SUPPORTED",
            },
            overallState: "REFUTED",
            requiredState: "SUPPORTED",
            performanceState: "SUPPORTED",
            conclusionHash:
                "sha256:crucible-scientific-conclusion-v1:15d56673451d47873e518578a2579f473f24da6075d5cc1af6b1300ed73c944a",
            excludesModelProse: true,
        });
    });

    it("distinguishes trusted novelty, overfit confirmation, and cohort outcomes", () => {
        expect(benchmark.metrics.novelty).toMatchObject({
            relabeling: {
                contentUnchanged: true,
                structuralUnchanged: true,
                behavioralUnchanged: true,
            },
            structuralDifference: true,
            behavioralDifference: true,
            passed: true,
        });
        expect(benchmark.metrics.overfit).toMatchObject({
            candidates: {
                overfit: {
                    discovery: "SUPPORTED",
                    heldOut: "REFUTED",
                    challenge: "REFUTED",
                },
                generalizer: {
                    discovery: "SUPPORTED",
                    heldOut: "SUPPORTED",
                    challenge: "SUPPORTED",
                },
            },
            passed: true,
        });
        expect(benchmark.metrics.cohorts).toMatchObject({
            uniqueBest: "UNIQUE_BEST",
            practicalTie: "TIE_COHORT",
            unresolved: "UNRESOLVED",
            incomparable: "INCOMPARABLE",
            passed: true,
        });
    });

    it("admits only finite verified impossibility and never open-generative exhaustion", () => {
        expect(benchmark.metrics.impossibility).toEqual({
            verifiedStatus: "VERIFIED",
            verifiedVerdict: "target_unreachable",
            incompleteStatus: "INCONCLUSIVE",
            incompleteVerdict: "inconclusive",
            disagreementRejected: true,
            finiteImmutableExhaustible: true,
            openGenerativeExhaustible: false,
            passed: true,
        });
    });

    it("beats the v3 deceptive-optimization baseline without hiding weak seeds", () => {
        const optimization = benchmark.metrics.optimization;
        expect(optimization.seedCount).toBeGreaterThanOrEqual(32);
        expect(optimization.strategyPolicyVersion)
            .toBe(V4_SCIENCE_THRESHOLDS.strategyPolicyVersion);
        expect(optimization.adaptiveWeightPolicy).toMatchObject({
            version: optimization.strategyPolicyVersion,
            configuredZeroWeightsRemainZero: true,
        });
        expect(optimization.controls.map((control) => control.policy))
            .toEqual([
                "fixed_diversification",
                "fixed_restart",
            ]);
        expect(optimization.controls.every((control) =>
            control.perSeed.length === optimization.seedCount)).toBe(true);
        expect(optimization.observedMedianPercent).toBe(99.994459);
        expect(optimization.bootstrapMedianLower95Percent)
            .toBe(99.990964);
        expect(optimization.strongestControl).toMatchObject({
            policy: "fixed_restart",
            observedMedianPercent: 99.723948,
        });
        expect(
            optimization
                .bootstrapMedianAdvantageOverStrongestControlLower95Percent,
        ).toBe(0.144911);
        expect(optimization.minimumPercent).toBe(98.977158);
        expect(optimization.bootstrapMedianLower95Percent).toBeGreaterThan(
            V4_SCIENCE_THRESHOLDS.v3OptimizationBaselinePercent,
        );
        expect(optimization.observedMedianPercent).toBeGreaterThanOrEqual(
            V4_SCIENCE_THRESHOLDS.v4OptimizationMedianTargetPercent,
        );
        expect(
            optimization
                .bootstrapMedianAdvantageOverStrongestControlLower95Percent,
        ).toBeGreaterThanOrEqual(
            V4_SCIENCE_THRESHOLDS
                .v4OptimizationControlAdvantageMarginPercent,
        );
        expect(optimization.controlAdvantages.every((advantage) =>
            advantage.bootstrapMedianAdvantageLower95Percent
                >= optimization.declaredAdvantageMarginPercent)).toBe(true);
        expect(optimization.knownOptimum).toBe(100);
        expect(optimization.weakestSeeds).toHaveLength(8);
        expect(optimization.weakestSeeds[0].percentOfKnownOptimum)
            .toBe(optimization.minimumPercent);
        expect(optimization.minimumPercent).toBeLessThan(
            optimization.observedMedianPercent,
        );
        expect(optimization.passed).toBe(true);
        expect(benchmark.passed).toBe(true);
    });
});
