import { describe, expect, it } from "vitest";

import {
    canonicalJson,
    compareCandidatePair,
    deriveCandidateCohortComparison,
} from "../domain/index.mjs";

function tagged(algorithm, character) {
    return `${algorithm}:${character.repeat(64)}`;
}

function metric({
    key,
    priority,
    direction = "max",
    practicalEquivalenceDelta = 0.05,
}) {
    return {
        key,
        priority,
        direction,
        practicalEquivalenceDelta,
    };
}

function contract(metrics, { maxBlocks = 2 } = {}) {
    return {
        statisticalPolicy: {
            goalMode: "optimize",
            maxBlocks,
            metrics,
        },
        scientificTerminalPolicy: {
            hypotheses: {
                requiredForResultMustBeSupported: true,
            },
        },
    };
}

function candidate(id, intervals, {
    blockCount = 1,
    requiredPredictionState = "SUPPORTED",
    contentCharacter = null,
} = {}) {
    const claims = Object.entries(intervals).map(
        ([key, confidenceSequence]) => ({
            id: `metric.${key}.acceptance`,
            kind: "threshold",
            observable: key,
            state: "SUPPORTED",
            estimate: {
                scale: "original_metric",
                pointEstimate:
                    (confidenceSequence.lower + confidenceSequence.upper) / 2,
                confidenceSequence,
            },
        }),
    );
    const evidenceId = `evidence-${id}`;
    return {
        candidateId: id,
        evidenceId,
        evidenceHash: tagged("sha256:crucible-event-v4", id[0]),
        active: true,
        invalidated: false,
        requiredState: "SUPPORTED",
        completeValidBlocks: true,
        acceptanceSatisfied: true,
        rankable: true,
        replication: {
            blockCount,
            scheduleHash: tagged(
                "sha256:crucible-replication-schedule-v1",
                id[0],
            ),
        },
        statisticalEvaluation: {
            blockCount,
            statistics: { claims },
        },
        hypothesesIdentity: tagged(
            "sha256:crucible-preregistered-hypotheses-v1",
            id[0],
        ),
        predictionEvaluation: {
            overallState: requiredPredictionState,
            requiredState: requiredPredictionState,
            predictions: [{
                predictionId: "required-prediction",
                predictionIdentity: tagged(
                    "sha256:crucible-preregistered-prediction-v4",
                    id[0],
                ),
                requiredForResult: true,
                status: requiredPredictionState,
            }],
        },
        novelty: contentCharacter === null
            ? null
            : {
                content: {
                    signature: tagged(
                        "sha256:crucible-content-novelty-v1",
                        contentCharacter,
                    ),
                },
                structural: null,
                behavioral: null,
            },
    };
}

describe("v4 candidate cohort relations", () => {
    it("surfaces exact and practical equivalence as tie cohorts without id tie-breaking", () => {
        const policy = contract([
            metric({
                key: "score",
                priority: 0,
                practicalEquivalenceDelta: 0.05,
            }),
        ]);
        const exact = deriveCandidateCohortComparison({
            contract: policy,
            candidates: [
                candidate("zeta", {
                    score: { lower: 0.5, upper: 0.5 },
                }),
                candidate("alpha", {
                    score: { lower: 0.5, upper: 0.5 },
                }),
            ],
        });
        expect(exact).toMatchObject({
            status: "TIE_COHORT",
            resolved: true,
            provisionalWinner: null,
            cohort: [
                { candidateId: "alpha" },
                { candidateId: "zeta" },
            ],
            relations: [{
                relation: "PRACTICALLY_EQUIVALENT",
            }],
        });

        const practical = deriveCandidateCohortComparison({
            contract: policy,
            candidates: [
                candidate("left", {
                    score: { lower: 0.49, upper: 0.51 },
                }),
                candidate("right", {
                    score: { lower: 0.5, upper: 0.52 },
                }),
            ],
        });
        expect(practical.status).toBe("TIE_COHORT");
        expect(practical.relations[0].metricEvidence[0]).toMatchObject({
            relation: "PRACTICALLY_EQUIVALENT",
            orientedDifference: {
                lower: -0.030000000000000027,
                upper: 0.010000000000000009,
            },
        });
    });

    it("keeps overlapping near-ties unresolved until bounds support equivalence", () => {
        const policy = contract([
            metric({
                key: "score",
                priority: 0,
                practicalEquivalenceDelta: 0.02,
            }),
        ]);
        const unresolved = deriveCandidateCohortComparison({
            contract: policy,
            candidates: [
                candidate("left", {
                    score: { lower: 0.49, upper: 0.56 },
                }),
                candidate("right", {
                    score: { lower: 0.5, upper: 0.57 },
                }),
            ],
        });
        expect(unresolved).toMatchObject({
            status: "UNRESOLVED",
            resolved: false,
            provisionalWinner: null,
            tieResolution: {
                required: true,
                schedulable: true,
                exhausted: false,
                nextBlockCandidateEvaluations: 2,
                nextBlockControlEvaluations: 2,
            },
        });
        expect(unresolved.relations[0].metricEvidence[0]).toMatchObject({
            relation: "UNRESOLVED",
            intervalsOverlap: true,
        });
    });

    it("requires a supported margin beyond delta for superiority", () => {
        const policy = contract([
            metric({
                key: "score",
                priority: 0,
                practicalEquivalenceDelta: 0.05,
            }),
        ]);
        expect(compareCandidatePair(
            policy,
            candidate("left", {
                score: { lower: 0.8, upper: 0.85 },
            }),
            candidate("right", {
                score: { lower: 0.6, upper: 0.65 },
            }),
        ).relation).toBe("BETTER");
        expect(compareCandidatePair(
            policy,
            candidate("right", {
                score: { lower: 0.6, upper: 0.65 },
            }),
            candidate("left", {
                score: { lower: 0.8, upper: 0.85 },
            }),
        ).relation).toBe("WORSE");
    });

    it("uses frozen lexicographic metric priority", () => {
        const policy = contract([
            metric({
                key: "z_primary",
                priority: 0,
                practicalEquivalenceDelta: 0.01,
            }),
            metric({
                key: "a_secondary",
                priority: 1,
                practicalEquivalenceDelta: 0.01,
            }),
        ]);
        const primaryWins = compareCandidatePair(
            policy,
            candidate("left", {
                z_primary: { lower: 0.8, upper: 0.81 },
                a_secondary: { lower: 0.1, upper: 0.11 },
            }),
            candidate("right", {
                z_primary: { lower: 0.6, upper: 0.61 },
                a_secondary: { lower: 0.9, upper: 0.91 },
            }),
        );
        expect(primaryWins.relation).toBe("BETTER");
        expect(primaryWins.decisiveMetric).toBe("z_primary");

        const secondaryDecides = compareCandidatePair(
            policy,
            candidate("left", {
                z_primary: { lower: 0.7, upper: 0.7 },
                a_secondary: { lower: 0.2, upper: 0.21 },
            }),
            candidate("right", {
                z_primary: { lower: 0.7, upper: 0.7 },
                a_secondary: { lower: 0.8, upper: 0.81 },
            }),
        );
        expect(secondaryDecides.relation).toBe("WORSE");
        expect(secondaryDecides.metricEvidence.map((item) => item.metric))
            .toEqual(["z_primary", "a_secondary"]);
    });

    it("marks missing metric confidence as incomparable", () => {
        const policy = contract([
            metric({ key: "score", priority: 0 }),
            metric({ key: "latency", priority: 1, direction: "min" }),
        ]);
        const comparison = deriveCandidateCohortComparison({
            contract: policy,
            candidates: [
                candidate("left", {
                    score: { lower: 0.5, upper: 0.5 },
                }),
                candidate("right", {
                    score: { lower: 0.5, upper: 0.5 },
                    latency: { lower: 10, upper: 11 },
                }),
            ],
        });
        expect(comparison.status).toBe("INCOMPARABLE");
        expect(comparison.relations[0]).toMatchObject({
            relation: "INCOMPARABLE",
            decisiveMetric: "latency",
        });
        expect(comparison.tieResolution).toMatchObject({
            required: true,
            schedulable: false,
            exhausted: true,
            hasIrresolvableRelation: true,
        });
    });

    it("is invariant to candidate arrival permutations and carries prediction/novelty evidence", () => {
        const policy = contract([
            metric({ key: "score", priority: 0 }),
        ]);
        const candidates = [
            candidate("bravo", {
                score: { lower: 0.8, upper: 0.81 },
            }, { contentCharacter: "b" }),
            candidate("alpha", {
                score: { lower: 0.6, upper: 0.61 },
            }, { contentCharacter: "a" }),
        ];
        const forward = deriveCandidateCohortComparison({
            contract: policy,
            candidates,
        });
        const reversed = deriveCandidateCohortComparison({
            contract: policy,
            candidates: [...candidates].reverse(),
        });
        expect(canonicalJson(reversed)).toBe(canonicalJson(forward));
        expect(forward).toMatchObject({
            status: "UNIQUE_BEST",
            provisionalWinner: { candidateId: "bravo" },
            relations: [{
                predictions: {
                    left: { requiredState: "SUPPORTED" },
                    right: { requiredState: "SUPPORTED" },
                },
                novelty: {
                    sameContent: false,
                    leftSignatures: [expect.stringMatching(/^sha256:/u)],
                    rightSignatures: [expect.stringMatching(/^sha256:/u)],
                },
            }],
        });
    });

    it("reports scientific non-resolution after preregistered blocks are exhausted", () => {
        const policy = contract([
            metric({
                key: "score",
                priority: 0,
                practicalEquivalenceDelta: 0.02,
            }),
        ], { maxBlocks: 2 });
        const comparison = deriveCandidateCohortComparison({
            contract: policy,
            candidates: [
                candidate("left", {
                    score: { lower: 0.49, upper: 0.56 },
                }, { blockCount: 2 }),
                candidate("right", {
                    score: { lower: 0.5, upper: 0.57 },
                }, { blockCount: 2 }),
            ],
        });
        expect(comparison).toMatchObject({
            status: "UNRESOLVED",
            resolved: false,
            tieResolution: {
                required: true,
                schedulable: false,
                exhausted: true,
                candidates: [],
            },
        });
    });
});
