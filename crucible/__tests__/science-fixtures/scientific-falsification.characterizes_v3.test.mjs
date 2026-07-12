import { describe, expect, it } from "vitest";

import { buildV3ScienceBaseline } from "./v3-adapter.mjs";

// Phase 0 baseline only: these assertions expose v3 limitations and are
// expected to change when v4 implements the corresponding scientific gates.
// They are not desired-behavior or final v4 acceptance tests.

const baseline = buildV3ScienceBaseline();
const cases = new Map(baseline.cases.map((item) => [item.id, item]));

describe("characterizes_v3 scientific falsification baseline", () => {
    it("characterizes_v3_null_noise_one_lucky_observation_can_verify", () => {
        const item = cases.get("null-noise-lucky-verification");

        expect(item.oracle).toMatchObject({
            firstThresholdCrossing: 4,
            thresholdCrossingCount: 1,
            scientificVerdict: "not_verified",
        });
        expect(item.observedV3).toMatchObject({
            acceptedObservationIndex: 4,
            acceptedScore: 0.981062,
            decision: "VERIFIED_RESULT",
            basisKind: "first_passing_candidate",
            replicationCount: 1,
        });
        expect(item.notDesiredBehavior).toBe(true);
        expect(item.expectedToChangeInV4).toBe(true);
    });

    it("characterizes_v3_known_effect_but_silently_orders_equal_candidates", () => {
        const item = cases.get("known-effect-and-equal-tie");

        expect(item.oracle.trueEffectWinnerId).toBe("effect-high");
        expect(item.observedV3.trueEffectWinnerId).toBe("effect-high");
        expect(item.oracle.equalCandidatesAreTied).toBe(true);
        expect(item.observedV3).toMatchObject({
            tieComparisonSign: -1,
            tieWinnerId: "tie-first",
            tieSurfaced: false,
            tieBreakBasis: "committed_event_order",
        });
    });

    it("characterizes_v3_drift_and_correlated_blocks_as_raw_candidate_scores", () => {
        const item = cases.get("drift-correlated-blocks");

        expect(item.oracle).toMatchObject({
            withinBlockDifferences: [0, 0, 0],
            maxAbsoluteWithinBlockDifference: 0,
            scientificVerdict: "no_candidate_effect",
        });
        expect(item.observedV3).toMatchObject({
            acceptedIds: ["block-3-a", "block-3-b"],
            winnerId: "block-3-a",
            winnerScore: 88,
            blockRelabelingChangesOutcome: false,
            blockAdjustmentApplied: false,
        });
    });

    it("characterizes_v3_acceptance_predicate_as_authority_when_harness_pass_disagrees", () => {
        const item = cases.get("harness-pass-predicate-disagreement");

        expect(item.oracle.disagreementCount).toBe(2);
        expect(item.observedV3).toEqual({
            cases: [
                {
                    id: "harness-pass-predicate-fail",
                    harnessPass: true,
                    acceptanceSatisfied: false,
                    outcomeClass: "rejected",
                },
                {
                    id: "harness-fail-predicate-pass",
                    harnessPass: false,
                    acceptanceSatisfied: true,
                    outcomeClass: "accepted",
                },
            ],
            acceptanceAuthority: "acceptance_predicate",
        });
    });

    it("characterizes_v3_false_and_true_typed_predictions_as_unscored", () => {
        const item = cases.get("true-and-false-typed-predictions");

        expect(item.oracle.predictionTruth).toEqual({
            "prediction-refuted": false,
            "prediction-supported": true,
        });
        expect(item.observedV3).toMatchObject({
            outcomes: {
                "prediction-refuted": "accepted",
                "prediction-supported": "accepted",
            },
            predictionChangesOutcome: false,
            winnerId: "prediction-refuted",
            predictionsScored: false,
        });
    });

    it("characterizes_v3_discovery_overfit_as_verified_despite_heldout_failure", () => {
        const item = cases.get("discovery-overfit-heldout-challenge");

        expect(item.oracle).toMatchObject({
            discoveryWinner: "overfit",
            confirmedIds: ["generalizer"],
            confirmationWinner: "generalizer",
            scientificVerdict: "confirmation_required",
        });
        expect(item.observedV3).toEqual({
            decision: "VERIFIED_RESULT",
            basisKind: "rounds_exhausted_with_incumbent",
            winnerId: "overfit",
            heldOutConsulted: false,
            challengeConsulted: false,
        });
    });

    it("characterizes_v3_prior_optimization_baseline_at_86_7_percent_of_optimum", () => {
        const item = cases.get("prior-optimization-reconstruction");

        expect(item.oracle).toEqual({
            winnerId: "opt-best",
            score: 86.7,
            percentOfKnownOptimum: 86.7,
            improvementPercent: 11.2,
            exactImprovementPercent: 11.153846153846,
        });
        expect(item.observedV3).toMatchObject({
            reconstructionStatus: "aggregate-only",
            sourceNote: expect.stringContaining("+11.2%"),
            winnerId: "opt-best",
            winnerScore: 86.7,
            knownOptimum: 100,
            percentOfKnownOptimum: 86.7,
            rawMetricImprovement: 8.7,
            relativeImprovementPercent: 11.153846153846,
        });
        expect(item.notDesiredBehavior).toBe(false);
    });
});
