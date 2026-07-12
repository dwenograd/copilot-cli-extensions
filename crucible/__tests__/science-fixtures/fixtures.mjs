const UINT32_RANGE = 0x1_0000_0000;

function deepFreeze(value) {
    if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
        Object.freeze(value);
        for (const child of Object.values(value)) {
            deepFreeze(child);
        }
    }
    return value;
}

function seededUniform(seed, count) {
    let state = seed >>> 0;
    return Array.from({ length: count }, () => {
        state = (Math.imul(1_664_525, state) + 1_013_904_223) >>> 0;
        return Number((state / UINT32_RANGE).toFixed(6));
    });
}

export const SCIENCE_FIXTURE_VERSION = 1;

export const SCIENCE_FIXTURES = deepFreeze({
    nullNoise: {
        id: "null-noise-lucky-verification",
        seed: 0x1badb002,
        generator: "lcg-1664525-1013904223-uniform",
        distribution: "uniform-null-no-effect",
        acceptanceThreshold: 0.98,
        observations: seededUniform(0x1badb002, 16),
        intendedTruth: "null",
    },
    effectAndTie: {
        id: "known-effect-and-equal-tie",
        acceptanceThreshold: 0.8,
        trueEffectCandidates: [
            { id: "effect-low", score: 0.2, committedSeq: 10 },
            { id: "effect-medium", score: 0.6, committedSeq: 20 },
            { id: "effect-high", score: 0.91, committedSeq: 30 },
        ],
        equalCandidates: [
            { id: "tie-first", score: 0.91, committedSeq: 40 },
            { id: "tie-second", score: 0.91, committedSeq: 50 },
        ],
    },
    drift: {
        id: "drift-correlated-blocks",
        acceptanceThreshold: 87,
        correlationModel: "perfect-shared-block-offset",
        blocks: [
            {
                id: "block-1",
                observations: [
                    { id: "block-1-a", variant: "a", score: 80 },
                    { id: "block-1-b", variant: "b", score: 80 },
                ],
            },
            {
                id: "block-2",
                observations: [
                    { id: "block-2-a", variant: "a", score: 84 },
                    { id: "block-2-b", variant: "b", score: 84 },
                ],
            },
            {
                id: "block-3",
                observations: [
                    { id: "block-3-a", variant: "a", score: 88 },
                    { id: "block-3-b", variant: "b", score: 88 },
                ],
            },
        ],
        intendedTruth: "no-within-block-candidate-effect",
    },
    predicateDisagreement: {
        id: "harness-pass-predicate-disagreement",
        cases: [
            {
                id: "harness-pass-predicate-fail",
                predicate: {
                    kind: "metric_compare",
                    metric: "score",
                    operator: ">=",
                    value: 0.9,
                },
                result: { pass: true, metrics: { score: 0.2 } },
            },
            {
                id: "harness-fail-predicate-pass",
                predicate: { kind: "constant", value: true },
                result: { pass: false, metrics: { score: 0.2 } },
            },
        ],
    },
    typedPredictions: {
        id: "true-and-false-typed-predictions",
        acceptanceThreshold: 0.8,
        candidates: [
            {
                id: "prediction-refuted",
                committedSeq: 60,
                result: { pass: true, metrics: { score: 0.9 } },
                intendedPrediction: {
                    kind: "metric_threshold",
                    metric: "score",
                    operator: "<=",
                    value: 0.2,
                },
            },
            {
                id: "prediction-supported",
                committedSeq: 70,
                result: { pass: true, metrics: { score: 0.9 } },
                intendedPrediction: {
                    kind: "metric_threshold",
                    metric: "score",
                    operator: ">=",
                    value: 0.8,
                },
            },
        ],
    },
    overfit: {
        id: "discovery-overfit-heldout-challenge",
        acceptanceThreshold: 0.8,
        candidates: [
            {
                id: "overfit",
                discovery: { pass: true, score: 0.95 },
                heldOut: { pass: false, score: 0.31 },
                challenge: { pass: false, score: 0.18 },
            },
            {
                id: "generalizer",
                discovery: { pass: true, score: 0.86 },
                heldOut: { pass: true, score: 0.84 },
                challenge: { pass: true, score: 0.82 },
            },
        ],
    },
    boundedEnumerands: {
        id: "bounded-ids-duplicate-and-mutated-enumerand",
        duplicateIds: ["enum-a", "enum-a"],
        boundedIds: ["enum-a"],
        originalEnumerands: {
            "enum-a": {
                contentHash: `sha256:${"1".repeat(64)}`,
                revision: 1,
            },
        },
        mutatedEnumerands: {
            "enum-a": {
                contentHash: `sha256:${"2".repeat(64)}`,
                revision: 2,
            },
        },
        invalidationReason: "fixture replacement after invalidated measurement",
    },
    impossibility: {
        id: "invalid-self-generated-disagreeing-impossibility",
        rawCandidateClaim: {
            pass: false,
            searchSpaceExhausted: true,
            impossibilityCertificateHash: `sha256:${"3".repeat(64)}`,
        },
        invalidFacts: { pass: true, searchSpaceExhausted: false },
        selfCertifiedFacts: { pass: true, searchSpaceExhausted: true },
        selfCertificationMetadata: {
            generatorId: "primary-harness",
            verifierId: "primary-harness",
        },
        disagreeingAttempts: [
            { pass: false, searchSpaceExhausted: true },
            { pass: true, searchSpaceExhausted: true },
        ],
    },
    lifecycleMetadata: {
        id: "reboot-rollover-resource-contention-metadata",
        rebootRecovery: {
            rebootAfterEventSeq: 12,
            requiredFields: [
                "bootId",
                "recoveredFromEventHash",
                "recoveryAttemptOrdinal",
            ],
        },
        rollover: {
            maxEventsPerSegment: 1_000,
            requiredFields: ["segmentId", "previousSegmentRoot", "rolloverReason"],
        },
        resourceContention: {
            resourceId: "gpu-0",
            contenders: ["investigation-a", "investigation-b"],
            requiredFields: ["leaseId", "resourceId", "waitOrdinal"],
        },
    },
    optimization: {
        id: "prior-optimization-reconstruction",
        seed: 8_675_309,
        reconstructionStatus: "aggregate-only",
        sourceNote:
            "The surviving science-audit baseline records +11.2% and 86.7% of a known optimum; the raw prior trace is not present locally.",
        initialScore: 78,
        knownOptimum: 100,
        candidates: [
            { id: "opt-initial", score: 78, committedSeq: 80 },
            { id: "opt-1", score: 80.4, committedSeq: 90 },
            { id: "opt-2", score: 83.2, committedSeq: 100 },
            { id: "opt-3", score: 85.1, committedSeq: 110 },
            { id: "opt-best", score: 86.7, committedSeq: 120 },
            { id: "opt-regression", score: 85.9, committedSeq: 130 },
        ],
    },
});

