import { describe, expect, it } from "vitest";

import {
    CANDIDATE_NOVELTY_VERSION,
    behavioralRoleIdentity,
    buildCandidateArchive,
    contentNoveltySignature,
    contractHash,
    createInvestigationContract,
    createRawMeasurementSeries,
    deriveBehavioralNovelty,
    deriveCandidateNovelty,
    deriveReplicationSchedule,
    deriveReplicationSubjectIdentity,
    hashCanonical,
    replayDerivedCandidateNovelty,
    replicationBlockPlan,
    selectPromptEvidence,
    statisticalSubjectIndex,
    structuralRoleIdentity,
    supportedBehavioralDifference,
} from "../domain/index.mjs";
import {
    fakeStatisticalPolicy,
    makeV4ContractInput,
} from "./v4-contract-fixture.mjs";

function noveltyContract({ blocks = 1024 } = {}) {
    const statisticalPolicy = fakeStatisticalPolicy({
        searchSlots: 4,
        minBlocks: blocks,
        maxBlocks: blocks,
        metrics: [{
            key: "score",
            minimum: 0,
            maximum: 1,
            estimand: "mean score",
            unit: "score",
            direction: "max",
            acceptanceThreshold: 0.8,
            practicalEquivalenceDelta: 0.05,
            family: "primary",
        }],
    });
    return createInvestigationContract(makeV4ContractInput({
        candidatesPerRound: 4,
        maxRounds: 1,
        observableRegistry: [{
            key: "score",
            kind: "numeric",
            minimum: 0,
            maximum: 1,
        }],
        statisticalPolicy,
    }));
}

function candidateAggregate({
    contract,
    id,
    subjectIndex,
    score,
    artifactLabel = id,
    annotations = null,
}) {
    const frozenHash = contractHash(contract);
    const seed = subjectIndex + 101;
    const schedule = deriveReplicationSchedule({
        contractHash: frozenHash,
        statisticalPolicy: contract.statisticalPolicy,
        subject: {
            kind: "candidate",
            index: statisticalSubjectIndex("candidate", subjectIndex),
            id,
            identity: deriveReplicationSubjectIdentity({
                contractHash: frozenHash,
                candidateId: id,
                candidateSeed: seed,
                enumerandHash: null,
            }),
        },
    });
    const attempts = [];
    const measurements = [];
    for (let blockIndex = 0; blockIndex < schedule.maxBlocks; blockIndex += 1) {
        for (const arm of replicationBlockPlan(schedule, blockIndex).arms) {
            const value = arm.armId === "candidate" ? score : 0.5;
            const receiptHash = hashCanonical(
                { id, subjectId: arm.subjectId, receipt: true },
                "sha256:crucible-measurement-receipt-v1",
            );
            const measurementRoot = hashCanonical(
                { id, subjectId: arm.subjectId, measurement: true },
                "sha256:crucible-evidence-measurement-provenance-v1",
            );
            attempts.push({
                ...arm,
                attemptId: `${id}-${arm.subjectId}`,
                parsed: {
                    pass: value >= 0.8,
                    metrics: { score: value },
                    role: "search",
                    phase: "search",
                    replicateIndex: arm.replicateIndex,
                    blockIndex: arm.blockIndex,
                    armIndex: arm.armIndex,
                    armId: arm.armId,
                    deterministicSeed: arm.deterministicSeed,
                    subjectId: arm.subjectId,
                },
                invalid: null,
                receiptHash,
                measurementRoot,
            });
            measurements.push({
                role: "search",
                phase: "search",
                subjectId: arm.subjectId,
                receiptHash,
                measurementRoot,
                rawStdoutHash: hashCanonical(
                    { id, subjectId: arm.subjectId, output: "first" },
                    "sha256:crucible-measurement-stream-v1",
                ),
            });
        }
    }
    const series = createRawMeasurementSeries({
        schedule,
        attempts,
        role: "search",
        phase: "search",
        caseId: null,
    });
    const artifact = hashCanonical(
        { artifact: artifactLabel },
        "sha256:crucible-measurement-snapshot-v1",
    );
    const commandId = `command-${id}`;
    const observationId = `observation-${id}`;
    const evidenceId = `evidence-${id}`;
    const observation = {
        observationId,
        commandId,
        sourceKind: "harness",
        purpose: "candidate",
        receipt: {
            candidateArtifactHash: artifact,
            provenance: { measurements },
        },
        data: {
            version: 1,
            series: [series],
        },
        annotations,
    };
    const evidence = {
        evidenceId,
        observationId,
        sourceKind: "harness",
        purpose: "candidate",
        receipt: observation.receipt,
        annotations,
    };
    return {
        contract,
        contractHash: frozenHash,
        evidenceOrder: [evidenceId],
        evidence: { [evidenceId]: evidence },
        observations: { [observationId]: observation },
        commands: {
            [commandId]: {
                command: {
                    kind: "search_candidate",
                    candidateId: id,
                    seed,
                    replicationSchedule: schedule,
                },
            },
        },
        evidenceItem: evidence,
        observation,
    };
}

function cachedEvidence({
    contract,
    id,
    artifact,
    structuralFeatures,
    behavioralInterval,
    mechanism,
    finding,
    score,
}) {
    const structuralRoleFingerprint = structuralRoleIdentity(contract);
    const structural = structuralFeatures === null
        ? null
        : {
            version: "crucible-novelty-role-adapter-v1",
            roleFingerprint: structuralRoleFingerprint,
            structuralFingerprint: hashCanonical({
                version: "crucible-novelty-role-adapter-v1",
                roleFingerprint: structuralRoleFingerprint,
                observableSchemaHash:
                    contract.harnessSuite.roles.novelty.observableSchemaHash,
                features: structuralFeatures,
            }, "sha256:crucible-novelty-structural-v1"),
            features: structuralFeatures,
            receiptHash: hashCanonical(
                { id, receipt: "novelty" },
                "sha256:crucible-measurement-receipt-v1",
            ),
            measurementRoot: hashCanonical(
                { id, measurement: "novelty" },
                "sha256:crucible-evidence-measurement-provenance-v1",
            ),
            subjectId: `novelty-${artifact.split(":").at(-1).slice(0, 48)}`,
        };
    const behavioralRoleFingerprint = behavioralRoleIdentity(contract);
    const behavioralFeatures = behavioralInterval === null
        ? []
        : [{
            id: "acceptance:score",
            kind: "threshold",
            observable: "score",
            referenceKind: "absolute",
            state: "SUPPORTED",
            identifiedBand: 2,
            practical: null,
        }];
    const behavioral = behavioralInterval === null
        ? null
        : {
            signature: hashCanonical({
                version: CANDIDATE_NOVELTY_VERSION,
                roleFingerprint: behavioralRoleFingerprint,
                statisticalPolicyIdentity:
                    contract.statisticalPolicyIdentity,
                features: behavioralFeatures,
            }, "sha256:crucible-behavioral-novelty-v1"),
            roleFingerprint: behavioralRoleFingerprint,
            basisHash: hashCanonical(
                { id, basis: "behavioral" },
                "sha256:crucible-behavioral-novelty-basis-v1",
            ),
            evaluationHash: hashCanonical({ id, evaluation: "behavioral" }),
            features: behavioralFeatures,
            claims: [{
                id: "acceptance:score",
                kind: "threshold",
                observable: "score",
                referenceKind: "absolute",
                state: "SUPPORTED",
                confidenceSequence: behavioralInterval,
                practicalMargin: 0.05,
            }],
        };
    return {
        evidenceId: id,
        committedSeq: 1,
        sourceKind: "harness",
        purpose: "candidate",
        invalidated: false,
        rankable: true,
        outcomeClass: "near_miss",
        metrics: { score },
        receipt: { candidateArtifactHash: artifact },
        duplicateOf: null,
        novelty: {
            version: CANDIDATE_NOVELTY_VERSION,
            content: {
                snapshotHash: artifact,
                signature: contentNoveltySignature(artifact),
            },
            structural,
            behavioral,
        },
        annotations: {
            mechanism,
            finding,
            hypothesis: null,
            expectedEffects: [],
            citedEvidenceIds: [],
        },
    };
}

describe("candidate novelty", () => {
    it("is neutral to candidate/model labels, annotations, and output text hashes", () => {
        const contract = noveltyContract({ blocks: 512 });
        const aggregate = candidateAggregate({
            contract,
            id: "candidate-a",
            subjectIndex: 0,
            score: 1,
            annotations: {
                mechanism: "first wording",
                finding: "first explanation",
            },
        });
        const first = deriveCandidateNovelty({
            aggregate,
            evidence: aggregate.evidenceItem,
        });

        const relabeledEvidence = {
            ...aggregate.evidenceItem,
            evidenceId: "renamed-evidence",
            candidateId: "renamed-candidate",
            model: "different-model",
            annotations: {
                mechanism: "paraphrased mechanism",
                finding: "paraphrased finding",
            },
        };
        const relabeled = deriveCandidateNovelty({
            aggregate,
            evidence: relabeledEvidence,
            observation: {
                ...aggregate.observation,
                annotations: relabeledEvidence.annotations,
                receipt: {
                    ...aggregate.observation.receipt,
                    rawStdoutHash: hashCanonical(
                        { output: "different text" },
                        "sha256:crucible-measurement-stream-v1",
                    ),
                    rawStderrHash: hashCanonical(
                        { output: "different stderr" },
                        "sha256:crucible-measurement-stream-v1",
                    ),
                    provenance: {
                        measurements:
                            aggregate.observation.receipt.provenance.measurements
                                .map((measurement) => ({
                                    ...measurement,
                                    rawStdoutHash: hashCanonical(
                                        {
                                            subjectId: measurement.subjectId,
                                            output: "rewritten text",
                                        },
                                        "sha256:crucible-measurement-stream-v1",
                                    ),
                                })),
                    },
                },
            },
            command: aggregate.commands["command-candidate-a"].command,
        });

        expect(relabeled.content.signature).toBe(first.content.signature);
        expect(relabeled.structural).toBeNull();
        expect(relabeled.behavioral.signature).toBe(first.behavioral.signature);
    });

    it("treats immutable artifact changes as content novelty only", () => {
        const contract = noveltyContract({ blocks: 512 });
        const firstAggregate = candidateAggregate({
            contract,
            id: "candidate-a",
            subjectIndex: 0,
            score: 1,
            artifactLabel: "artifact-a",
        });
        const secondAggregate = candidateAggregate({
            contract,
            id: "candidate-b",
            subjectIndex: 1,
            score: 1,
            artifactLabel: "artifact-b",
        });
        const first = deriveCandidateNovelty({
            aggregate: firstAggregate,
            evidence: firstAggregate.evidenceItem,
        });
        const second = deriveCandidateNovelty({
            aggregate: secondAggregate,
            evidence: secondAggregate.evidenceItem,
        });

        expect(second.content.signature).not.toBe(first.content.signature);
        expect(second.behavioral.signature).toBe(first.behavioral.signature);
    });

    it("recognizes only statistically supported behavioral differences", () => {
        const contract = noveltyContract();
        const highAggregate = candidateAggregate({
            contract,
            id: "candidate-high",
            subjectIndex: 0,
            score: 1,
        });
        const lowAggregate = candidateAggregate({
            contract,
            id: "candidate-low",
            subjectIndex: 1,
            score: 0,
        });
        const closeAggregate = candidateAggregate({
            contract,
            id: "candidate-close",
            subjectIndex: 2,
            score: 0.52,
        });
        const closePeerAggregate = candidateAggregate({
            contract,
            id: "candidate-close-peer",
            subjectIndex: 3,
            score: 0.5,
        });
        const high = deriveBehavioralNovelty({
            aggregate: highAggregate,
            evidence: highAggregate.evidenceItem,
        });
        const low = deriveBehavioralNovelty({
            aggregate: lowAggregate,
            evidence: lowAggregate.evidenceItem,
        });
        const close = deriveBehavioralNovelty({
            aggregate: closeAggregate,
            evidence: closeAggregate.evidenceItem,
        });
        const closePeer = deriveBehavioralNovelty({
            aggregate: closePeerAggregate,
            evidence: closePeerAggregate.evidenceItem,
        });

        expect(high).not.toBeNull();
        expect(low).not.toBeNull();
        expect(supportedBehavioralDifference(high, low)).toBe(true);
        expect(supportedBehavioralDifference(close, closePeer)).toBe(false);

        const evaluated = [
            [highAggregate, high, 1],
            [lowAggregate, low, 0],
            [closeAggregate, close, 0.52],
            [closePeerAggregate, closePeer, 0.5],
        ];
        const archive = buildCandidateArchive({
            contract,
            contractHash: contractHash(contract),
            evidenceOrder: evaluated.map(
                ([aggregate]) => aggregate.evidenceItem.evidenceId,
            ),
            evidence: Object.fromEntries(evaluated.map(
                ([aggregate, behavioral, score], index) => [
                    aggregate.evidenceItem.evidenceId,
                    {
                        ...aggregate.evidenceItem,
                        committedSeq: index + 1,
                        invalidated: false,
                        rankable: true,
                        outcomeClass: "near_miss",
                        metrics: { score },
                        duplicateOf: null,
                        novelty: {
                            version: CANDIDATE_NOVELTY_VERSION,
                            content: {
                                snapshotHash:
                                    aggregate.observation.receipt
                                        .candidateArtifactHash,
                                signature: contentNoveltySignature(
                                    aggregate.observation.receipt
                                        .candidateArtifactHash,
                                ),
                            },
                            structural: null,
                            behavioral,
                        },
                    },
                ],
            )),
        });
        expect(archive.noveltyNiches.behavioral).toHaveLength(3);

        const tampered = {
            ...highAggregate.evidenceItem,
            novelty: {
                version: CANDIDATE_NOVELTY_VERSION,
                content: {
                    snapshotHash:
                        highAggregate.observation.receipt.candidateArtifactHash,
                    signature: contentNoveltySignature(
                        highAggregate.observation.receipt.candidateArtifactHash,
                    ),
                },
                structural: null,
                behavioral: {
                    ...high,
                    signature: hashCanonical(
                        { forged: "behavioral-cache" },
                        "sha256:crucible-behavioral-novelty-v1",
                    ),
                },
            },
        };
        expect(() => replayDerivedCandidateNovelty(
            highAggregate,
            tampered,
        )).toThrow(/invalid novelty replay cache/u);
    });

    it("builds trusted content, structural, and behavioral archive niches", () => {
        const contract = noveltyContract({ blocks: 1 });
        const artifactA = hashCanonical(
            { artifact: "a" },
            "sha256:crucible-measurement-snapshot-v1",
        );
        const artifactB = hashCanonical(
            { artifact: "b" },
            "sha256:crucible-measurement-snapshot-v1",
        );
        const items = [
            cachedEvidence({
                contract,
                id: "evidence-a",
                artifact: artifactA,
                structuralFeatures: { branchCount: 1, nodeCount: 2 },
                behavioralInterval: { lower: 0.6, upper: 0.7 },
                mechanism: "label one",
                finding: "wording one",
                score: 0.7,
            }),
            cachedEvidence({
                contract,
                id: "evidence-b",
                artifact: artifactB,
                structuralFeatures: { branchCount: 2, nodeCount: 2 },
                behavioralInterval: { lower: 0.6, upper: 0.7 },
                mechanism: "label two",
                finding: "wording two",
                score: 0.6,
            }),
        ];
        const aggregate = {
            contract,
            contractHash: contractHash(contract),
            evidenceOrder: items.map((item) => item.evidenceId),
            evidence: Object.fromEntries(
                items.map((item) => [item.evidenceId, item]),
            ),
        };
        const first = buildCandidateArchive(aggregate);
        const paraphrased = buildCandidateArchive({
            ...aggregate,
            evidenceOrder: [...aggregate.evidenceOrder].reverse(),
            evidence: Object.fromEntries(items.map((item) => [
                item.evidenceId,
                {
                    ...item,
                    model: item.evidenceId === "evidence-a"
                        ? "model-z"
                        : "model-a",
                    annotations: {
                        ...item.annotations,
                        mechanism: `paraphrased ${item.evidenceId}`,
                        finding: `rewritten ${item.evidenceId}`,
                    },
                },
            ])),
        });

        expect(first.noveltyNiches.content).toHaveLength(2);
        expect(first.noveltyNiches.structural).toHaveLength(2);
        expect(first.noveltyNiches.behavioral).toHaveLength(1);
        expect(paraphrased.noveltyNiches).toEqual(first.noveltyNiches);
        expect(selectPromptEvidence(first, contract.searchPolicy))
            .toEqual(selectPromptEvidence(paraphrased, contract.searchPolicy));
    });
});
