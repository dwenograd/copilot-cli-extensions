import { describe, expect, it } from "vitest";

import {
    assessVerifiedResultReadiness,
    canonicalEqual,
    candidatePredictionEvaluation,
    contractHash,
    createCandidateStatisticalClaimPlan,
    createInvestigationContract,
    createRawMeasurementSeries,
    deriveReplicationSchedule,
    deriveScientificConclusion,
    deriveScientificReplayState,
    evaluateReplicatedStatisticalClaims,
    evaluateSealedPredictions,
    hashCanonical,
    materializeScientificReplayState,
    normalizeHypotheses,
    replicationBlockPlan,
    resolvedPredictionFindings,
    statisticalSubjectIndex,
} from "../domain/index.mjs";
import { deriveEvidencePayload } from "../domain/evidence.mjs";
import {
    fakeStatisticalPolicy,
    makeV4ContractInput,
} from "./v4-contract-fixture.mjs";

const OBSERVABLES = [
    { key: "latency", kind: "numeric", minimum: 0, maximum: 1 },
    {
        key: "outcome",
        kind: "categorical",
        values: ["good", "bad"],
    },
    { key: "score", kind: "numeric", minimum: 0, maximum: 1 },
];

const HYPOTHESIS_POLICY = {
    required: false,
    maxPredictions: 8,
    allowedKinds: [
        "threshold",
        "bounded_interval",
        "direction",
        "categorical_outcome",
    ],
    allowRequiredForResult: true,
};

function withConfirmedCohort(aggregate, evidence) {
    const cohort = aggregate.scientificReplay?.candidateCohort ?? null;
    const comparisonHash = cohort?.comparisonHash ?? null;
    const relationEvidenceHash = cohort?.relationEvidenceHash ?? null;
    const freezeHash = hashCanonical(
        { evidenceId: evidence.evidenceId, kind: "confirmation-freeze" },
        "sha256:crucible-scientific-confirmation-freeze-v1",
    );
    const roleEvidenceHash = (role) => hashCanonical(
        { evidenceId: evidence.evidenceId, role },
        `sha256:crucible-${role}-evidence-v1`,
    );
    const confirmationState = {
        version: "crucible-scientific-confirmation-v1",
        status: "READY",
        ready: true,
        failed: false,
        freezeHash,
        members: [{
            candidateId: evidence.candidateId,
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash,
            discoveryBound: true,
            status: "READY",
            roles: ["confirmation", "challenge"].map((role) => ({
                role,
                status: "SUPPORTED",
                evidenceId: `${role}-${evidence.evidenceId}`,
                evidenceHash: roleEvidenceHash(role),
                provenanceRoot: hashCanonical({ role, kind: "provenance" }),
                rawAuthorityDigest: hashCanonical({ role, kind: "raw" }),
                scheduleHash: hashCanonical({ role, kind: "schedule" }),
                evaluationHash: hashCanonical({ role, kind: "evaluation" }),
                alphaUseHash: hashCanonical({ role, kind: "alpha" }),
            })),
        }],
        closureHash: hashCanonical(
            { evidenceId: evidence.evidenceId, kind: "confirmation-closure" },
            "sha256:crucible-scientific-confirmation-closure-v1",
        ),
    };
    return {
        ...aggregate,
        confirmation: {
            freeze: {
                payload: {
                    contractHash: aggregate.contractHash,
                    freezeHash,
                    discoveryClosure: {
                        cohortStatus: cohort?.status ?? "UNIQUE_BEST",
                        candidateIds: [evidence.candidateId],
                        evidenceIds: [evidence.evidenceId],
                        evidenceHashes: [evidence.commitEventHash],
                        cohortComparisonHash: comparisonHash,
                        relationEvidenceHash,
                    },
                },
            },
        },
        scientificReplay: {
            ...aggregate.scientificReplay,
            confirmationState,
        },
    };
}

function fixture() {
    const statisticalPolicy = fakeStatisticalPolicy({
        minBlocks: 512,
        maxBlocks: 512,
        metrics: [{
            key: "score",
            minimum: 0,
            maximum: 1,
            estimand: "mean score",
            unit: "score",
            direction: "max",
            acceptanceThreshold: 0.8,
            practicalEquivalenceDelta: 0.01,
            family: "primary",
        }],
    });
    const contract = createInvestigationContract(makeV4ContractInput({
        observableRegistry: OBSERVABLES,
        hypothesisPolicy: HYPOTHESIS_POLICY,
        statisticalPolicy,
    }));
    const hypotheses = normalizeHypotheses({
        predictions: [
            {
                id: "true-threshold",
                kind: "threshold",
                observable: "score",
                operator: ">=",
                value: 0.8,
                refutation: {
                    kind: "threshold",
                    operator: "<",
                    value: 0.8,
                },
                requiredForResult: true,
            },
            {
                id: "false-threshold",
                kind: "threshold",
                observable: "latency",
                operator: "<=",
                value: 0.2,
                refutation: {
                    kind: "threshold",
                    operator: ">",
                    value: 0.2,
                },
            },
            {
                id: "unresolved-threshold",
                kind: "threshold",
                observable: "score",
                operator: ">",
                value: 0.9,
                refutation: {
                    kind: "threshold",
                    operator: "<=",
                    value: 0.9,
                },
            },
            {
                id: "invalid-category",
                kind: "categorical_outcome",
                observable: "outcome",
                outcome: "good",
                refutation: {
                    kind: "categorical_outcome",
                    operator: "not_equals",
                    outcome: "good",
                },
            },
            {
                id: "control-direction",
                kind: "direction",
                observable: "score",
                direction: "increase",
                reference: { kind: "control" },
                refutation: {
                    kind: "direction",
                    direction: "non_increase",
                },
            },
            {
                id: "parent-direction",
                kind: "direction",
                observable: "latency",
                direction: "increase",
                reference: {
                    kind: "assigned_parent",
                    evidenceId: "parent-evidence",
                },
                refutation: {
                    kind: "direction",
                    direction: "non_increase",
                },
            },
        ],
    }, {
        observableRegistry: contract.observableRegistry,
        hypothesisPolicy: contract.hypothesisPolicy,
        assignedParentEvidenceIds: ["parent-evidence"],
    });
    const schedule = deriveReplicationSchedule({
        contractHash: contractHash(contract),
        statisticalPolicy: contract.statisticalPolicy,
        subject: {
            kind: "candidate",
            index: statisticalSubjectIndex("candidate", 0),
            id: "candidate-0",
            identity: `sha256:${"a".repeat(64)}`,
        },
    });
    const attempts = [];
    for (let blockIndex = 0; blockIndex < 512; blockIndex += 1) {
        for (const arm of replicationBlockPlan(schedule, blockIndex).arms) {
            const candidate = arm.armId === "candidate";
            attempts.push({
                ...arm,
                attemptId: `attempt-${blockIndex}-${arm.armId}`,
                parsed: {
                    pass: true,
                    metrics: { score: candidate ? 1 : 0 },
                    observables: {
                        latency: candidate ? 1 : 0,
                        outcome: candidate ? "outside-registry" : "bad",
                    },
                },
                invalid: null,
                receiptHash: `receipt-${blockIndex}-${arm.armId}`,
                measurementRoot: `measurement-${blockIndex}-${arm.armId}`,
            });
        }
    }
    const parentEvidence = {
        "parent-evidence": {
            evidenceId: "parent-evidence",
            evidenceHash: `sha256:crucible-event-v4:${"b".repeat(64)}`,
            rawAuthorityDigest:
                `sha256:crucible-raw-observation-authority-v1:${"c".repeat(64)}`,
            scheduleHash: `sha256:crucible-replication-schedule-v1:${"d".repeat(64)}`,
            invalidated: false,
            blocks: Array.from({ length: 512 }, (_unused, blockIndex) => ({
                blockIndex,
                candidate: {
                    pass: true,
                    metrics: { score: 0 },
                    observables: { latency: 0, outcome: "bad" },
                },
                control: null,
            })),
        },
    };
    return {
        contract,
        hypotheses,
        schedule,
        attempts,
        parentEvidence,
    };
}

describe("v4 preregistered prediction evaluation", () => {
    it("evaluates every prediction independently from candidate performance", () => {
        const input = fixture();
        const claimPlan = createCandidateStatisticalClaimPlan({
            contract: input.contract,
            hypotheses: input.hypotheses,
            assignedParentEvidenceIds: ["parent-evidence"],
        });
        const performance = evaluateReplicatedStatisticalClaims({
            contract: input.contract,
            schedule: input.schedule,
            attempts: input.attempts,
            claims: claimPlan.acceptanceClaims,
            requiredClaimIds: claimPlan.acceptanceClaimIds,
            allocationClaims: claimPlan.allocationClaims,
        });
        const predictions = evaluateSealedPredictions({
            contract: input.contract,
            schedule: input.schedule,
            attempts: input.attempts,
            claimPlan,
            parentEvidence: input.parentEvidence,
            evidenceId: "candidate-evidence",
            rawAuthorityDigest:
                `sha256:crucible-raw-observation-authority-v1:${"e".repeat(64)}`,
        });
        const byId = new Map(
            predictions.predictions.map((prediction) => [
                prediction.predictionId,
                prediction,
            ]),
        );

        expect(performance.requiredState).toBe("SUPPORTED");
        expect(byId.get("true-threshold").status).toBe("SUPPORTED");
        expect(byId.get("false-threshold").status).toBe("REFUTED");
        expect(byId.get("unresolved-threshold").status).toBe("UNRESOLVED");
        expect(byId.get("invalid-category").status).toBe("INVALID");
        expect(byId.get("control-direction")).toMatchObject({
            status: "SUPPORTED",
            reference: { kind: "control" },
            referenceSampling: "paired_within_block",
        });
        expect(byId.get("parent-direction")).toMatchObject({
            status: "SUPPORTED",
            reference: {
                kind: "assigned_parent",
                evidenceId: "parent-evidence",
            },
            referenceSampling: "independent_replay_blocks",
        });
        expect(predictions.requiredState).toBe("SUPPORTED");
        expect(predictions.overallState).toBe("INVALID");
        for (const prediction of predictions.predictions) {
            expect(prediction.evidenceReference.evidenceId)
                .toBe("candidate-evidence");
            expect(prediction.blockReference.blockLedgerHash)
                .toBe(predictions.blockLedger.hash);
            expect(prediction.alphaReference.ledger.length)
                .toBeGreaterThanOrEqual(4);
        }
        expect(byId.get("false-threshold").estimate.pointEstimate).toBe(1);
        expect(byId.get("invalid-category").limitations[0].code)
            .toMatch(/^CRUCIBLE_STATISTICS_/u);
    });

    it("rejects a post-measurement mutation of the sealed prediction set", () => {
        const input = fixture();
        const claimPlan = createCandidateStatisticalClaimPlan({
            contract: input.contract,
            hypotheses: input.hypotheses,
            assignedParentEvidenceIds: ["parent-evidence"],
        });
        const measured = evaluateSealedPredictions({
            contract: input.contract,
            schedule: input.schedule,
            attempts: input.attempts,
            claimPlan,
            parentEvidence: input.parentEvidence,
            evidenceId: "candidate-evidence",
            rawAuthorityDigest:
                `sha256:crucible-raw-observation-authority-v1:${"e".repeat(64)}`,
        });
        const mutated = structuredClone(input.hypotheses);
        const threshold = mutated.predictions.find(
            (prediction) => prediction.id === "true-threshold",
        );
        threshold.value = 0.99;
        threshold.refutation.value = 0.99;

        expect(() => createCandidateStatisticalClaimPlan({
            contract: input.contract,
            hypotheses: mutated,
            assignedParentEvidenceIds: ["parent-evidence"],
        })).toThrow(/mutated/u);
        expect(measured.predictions.find(
            (prediction) => prediction.predictionId === "true-threshold",
        )?.status).toBe("SUPPORTED");
    });

    it("re-derives prediction caches and replay state from raw replicated blocks", () => {
        const input = fixture();
        const hypotheses = normalizeHypotheses({
            predictions: [
                {
                    id: "raw-replay-support",
                    kind: "threshold",
                    observable: "score",
                    operator: ">=",
                    value: 0.8,
                    refutation: {
                        kind: "threshold",
                        operator: "<",
                        value: 0.8,
                    },
                    requiredForResult: true,
                },
                {
                    id: "raw-replay-refuted-optional",
                    kind: "threshold",
                    observable: "latency",
                    operator: "<=",
                    value: 0.2,
                    refutation: {
                        kind: "threshold",
                        operator: ">",
                        value: 0.2,
                    },
                },
            ],
        }, {
            observableRegistry: input.contract.observableRegistry,
            hypothesisPolicy: input.contract.hypothesisPolicy,
        });
        const commandId = "command-1";
        const observationId = "observation-1";
        const evidenceId = "evidence-1";
        const command = {
            kind: "search_candidate",
            round: 1,
            slotIndex: 0,
            candidateId: "candidate-0",
            model: "worker-a",
            operator: "fresh",
            parentEvidenceIds: [],
            promptContextRefs: [],
            seed: 1,
            hypotheses,
            replicationSchedule: input.schedule,
        };
        const rawAttempts = input.attempts.map((attempt) => ({
            ...attempt,
            parsed: {
                ...attempt.parsed,
                role: "search",
                phase: "search",
                replicateIndex: attempt.replicateIndex,
                blockIndex: attempt.blockIndex,
                armIndex: attempt.armIndex,
                armId: attempt.armId,
                deterministicSeed: attempt.deterministicSeed,
                subjectId: attempt.subjectId,
            },
        }));
        const observation = {
            commandId,
            observationId,
            sourceKind: "harness",
            purpose: "candidate",
            harnessId: input.contract.harnessId,
            parserVersion: input.contract.parserVersion,
            receipt: {
                candidateArtifactHash: `sha256:${"4".repeat(64)}`,
                provenance: {
                    closureRoot:
                        `sha256:crucible-evidence-provenance-v2:${"5".repeat(64)}`,
                    measurements: rawAttempts.map((attempt) => ({
                        subjectId: attempt.subjectId,
                        snapshot: {
                            snapshotHash: attempt.armId === "control"
                                ? `sha256:crucible-measurement-snapshot-v1:${
                                    input.contract.statisticalPolicy.control.identity
                                        .slice("sha256:".length)
                                }`
                                : `sha256:crucible-measurement-snapshot-v1:${
                                    "4".repeat(64)
                                }`,
                        },
                    })),
                },
            },
            data: {
                version: 1,
                series: [createRawMeasurementSeries({
                    schedule: input.schedule,
                    attempts: rawAttempts,
                    role: "search",
                    phase: "search",
                    caseId: null,
                })],
            },
            round: 1,
            slotIndex: 0,
            candidateId: "candidate-0",
            annotations: {
                mechanism: "raw replay prediction",
                hypothesis: "model prose remains non-authoritative",
                expectedEffects: [],
                citedEvidenceIds: [],
                finding: null,
                hypotheses,
            },
        };
        const aggregate = {
            contract: input.contract,
            contractHash: contractHash(input.contract),
            commands: { [commandId]: { command } },
            observations: { [observationId]: observation },
            evidence: {},
            evidenceOrder: [],
            validation: {
                attemptEvidenceIds: [],
                completions: [],
                currentEvidenceId: null,
            },
        };
        const payload = deriveEvidencePayload(
            aggregate,
            observation,
            evidenceId,
        );
        expect(payload).toMatchObject({
            outcomeClass: "accepted",
            acceptanceSatisfied: true,
            hypothesesIdentity: hypotheses.identity,
            predictionEvaluation: {
                requiredState: "SUPPORTED",
            },
        });
        expect(Object.fromEntries(
            payload.predictionEvaluation.predictions.map((prediction) => [
                prediction.predictionId,
                prediction.status,
            ]),
        )).toMatchObject({
            "raw-replay-support": "SUPPORTED",
            "raw-replay-refuted-optional": "REFUTED",
        });

        const committed = {
            ...payload,
            committedSeq: 2,
            commitEventHash:
                `sha256:crucible-event-v4:${"6".repeat(64)}`,
            invalidated: false,
            invalidatedSeq: null,
            invalidationReason: null,
        };
        const replayAggregate = {
            ...aggregate,
            evidence: { [evidenceId]: committed },
            evidenceOrder: [evidenceId],
        };
        const scientificReplay =
            deriveScientificReplayState(replayAggregate);
        const materialized =
            materializeScientificReplayState(replayAggregate);
        const withReplay = {
            ...replayAggregate,
            scientificReplay,
        };
        expect(candidatePredictionEvaluation(withReplay, "candidate-0"))
            .toMatchObject({ requiredState: "SUPPORTED" });
        expect(resolvedPredictionFindings(withReplay).map((finding) => [
            finding.predictionId,
            finding.status,
        ])).toEqual([
            ["raw-replay-refuted-optional", "REFUTED"],
            ["raw-replay-support", "SUPPORTED"],
        ]);
        expect(scientificReplay.candidateSupport[0]).toMatchObject({
            requiredState: "SUPPORTED",
            predictionEvaluation: {
                requiredState: "SUPPORTED",
            },
        });
        const replayPredictions = new Map(
            scientificReplay.candidateSupport[0]
                .predictionEvaluation.predictions.map((prediction) => [
                    prediction.predictionId,
                    prediction,
                ]),
        );
        expect(replayPredictions.get("raw-replay-support")).toMatchObject({
            status: "SUPPORTED",
            evidenceReference: {
                evidenceId,
                evidenceHash: committed.commitEventHash,
            },
        });
        expect(replayPredictions.get("raw-replay-refuted-optional"))
            .toMatchObject({ status: "REFUTED" });
        expect(materialized.claimStates).toEqual(expect.arrayContaining([
            expect.objectContaining({
                source: "prediction",
                caseId: "raw-replay-support",
                state: "SUPPORTED",
            }),
            expect.objectContaining({
                source: "prediction",
                caseId: "raw-replay-refuted-optional",
                state: "REFUTED",
            }),
        ]));
        expect(materialized.alphaLedger.some((entry) =>
            entry.source === "prediction"
            && entry.caseId === "raw-replay-support")).toBe(true);
        expect(deriveScientificConclusion(withReplay, evidenceId))
            .toMatchObject({
                candidate: {
                    performance: { status: "SUPPORTED" },
                },
                hypotheses: {
                    requiredForResultStatus: "SUPPORTED",
                },
            });
        const conclusion = deriveScientificConclusion(
            withReplay,
            evidenceId,
        );
        expect(Object.fromEntries(
            conclusion.hypotheses.predictions.map((prediction) => [
                prediction.predictionId,
                prediction.status,
            ]),
        )).toMatchObject({
            "raw-replay-support": "SUPPORTED",
            "raw-replay-refuted-optional": "REFUTED",
        });
        expect(assessVerifiedResultReadiness({
            ...withReplay,
            scientificTerminalClosure: {
                contractHash: aggregate.contractHash,
                candidateEvidenceHash: committed.commitEventHash,
                confirmation: {
                    trusted: true,
                    status: "supported",
                    evidenceHash: hashCanonical({ kind: "synthetic-confirmation" }),
                },
                challenge: {
                    trusted: true,
                    status: "supported",
                    evidenceHash: hashCanonical({ kind: "synthetic-challenge" }),
                },
            },
        }, committed)).toMatchObject({
            ready: false,
            confirmationSupported: false,
            challengeSupported: false,
        });
        expect(assessVerifiedResultReadiness(
            withConfirmedCohort(withReplay, committed),
            committed,
        )).toMatchObject({
            ready: true,
            requiredPredictionState: "SUPPORTED",
            unsupportedRequiredPredictionIds: [],
            predictionStatuses: expect.arrayContaining([
                {
                    id: "raw-replay-refuted-optional",
                    requiredForResult: false,
                    status: "REFUTED",
                },
            ]),
        });

        const tamperedCache = structuredClone(payload);
        tamperedCache.predictionEvaluation.predictions.find(
            (prediction) =>
                prediction.predictionId === "raw-replay-support",
        ).status = "REFUTED";
        expect(canonicalEqual(
            tamperedCache,
            deriveEvidencePayload(aggregate, observation, evidenceId),
        )).toBe(false);
        const tamperedReplay = deriveScientificReplayState({
            ...replayAggregate,
            evidence: {
                [evidenceId]: {
                    ...committed,
                    predictionEvaluation:
                        tamperedCache.predictionEvaluation,
                },
            },
        });
        expect(tamperedReplay.closureRoot)
            .not.toBe(scientificReplay.closureRoot);
    });

    it("gates only required predictions and emits a code-authored conclusion", () => {
        const input = fixture();
        const claimPlan = createCandidateStatisticalClaimPlan({
            contract: input.contract,
            hypotheses: input.hypotheses,
            assignedParentEvidenceIds: ["parent-evidence"],
        });
        const performance = evaluateReplicatedStatisticalClaims({
            contract: input.contract,
            schedule: input.schedule,
            attempts: input.attempts,
            claims: claimPlan.acceptanceClaims,
            requiredClaimIds: claimPlan.acceptanceClaimIds,
            allocationClaims: claimPlan.allocationClaims,
        });
        const predictionEvaluation = evaluateSealedPredictions({
            contract: input.contract,
            schedule: input.schedule,
            attempts: input.attempts,
            claimPlan,
            parentEvidence: input.parentEvidence,
            evidenceId: "candidate-evidence",
            rawAuthorityDigest:
                `sha256:crucible-raw-observation-authority-v1:${"e".repeat(64)}`,
        });
        const evidenceHash =
            `sha256:crucible-event-v4:${"f".repeat(64)}`;
        const evidence = {
            evidenceId: "candidate-evidence",
            candidateId: "candidate-0",
            commitEventHash: evidenceHash,
            sourceKind: "harness",
            purpose: "candidate",
            annotations: {
                hypothesis:
                    "MODEL PROSE MUST NOT BECOME THE CONCLUSION",
                hypotheses: input.hypotheses,
            },
            statisticalEvaluation: performance,
        };
        const support = {
            evidenceId: evidence.evidenceId,
            evidenceHash,
            candidateId: evidence.candidateId,
            active: true,
            requiredState: "SUPPORTED",
            acceptanceSatisfied: true,
            outcomeClass: "accepted",
            metrics: performance.metrics,
            hypothesesIdentity: input.hypotheses.identity,
            predictionEvaluation: {
                ...predictionEvaluation,
                evidenceReference: {
                    ...predictionEvaluation.evidenceReference,
                    evidenceHash,
                },
                predictions: predictionEvaluation.predictions.map(
                    (prediction) => ({
                        ...prediction,
                        evidenceReference: {
                            ...prediction.evidenceReference,
                            evidenceHash,
                        },
                    }),
                ),
            },
        };
        const aggregate = withConfirmedCohort({
            contract: input.contract,
            contractHash: contractHash(input.contract),
            evidence: { [evidence.evidenceId]: evidence },
            scientificReplay: {
                closureRoot:
                    `sha256:crucible-scientific-replay-closure-v1:${"1".repeat(64)}`,
                candidateSupport: [support],
            },
        }, evidence);

        expect(assessVerifiedResultReadiness(aggregate, evidence)).toMatchObject({
            ready: true,
            statisticalCandidateSupported: true,
            requiredPredictionState: "SUPPORTED",
            unsupportedRequiredPredictionIds: [],
        });
        const conclusion = deriveScientificConclusion(
            aggregate,
            evidence.evidenceId,
        );
        expect(conclusion.authority)
            .toBe("replay_derived_statistical_kernel");
        expect(conclusion.hypotheses.predictions).toHaveLength(6);
        expect(conclusion.hypotheses.predictions.map((item) => item.status))
            .toEqual(expect.arrayContaining([
                "SUPPORTED",
                "REFUTED",
                "UNRESOLVED",
                "INVALID",
            ]));
        expect(JSON.stringify(conclusion)).not.toContain("MODEL PROSE");

        const blocked = structuredClone(aggregate);
        const required = blocked.scientificReplay.candidateSupport[0]
            .predictionEvaluation.predictions.find(
                (prediction) => prediction.predictionId === "true-threshold",
            );
        required.status = "REFUTED";
        blocked.scientificReplay.candidateSupport[0]
            .predictionEvaluation.requiredState = "REFUTED";
        expect(assessVerifiedResultReadiness(blocked, evidence)).toMatchObject({
            ready: false,
            requiredPredictionState: "REFUTED",
            unsupportedRequiredPredictionIds: ["true-threshold"],
            missing: expect.arrayContaining([
                "trusted_required_prediction_evaluations",
            ]),
        });
    });
});
