import { describe, expect, it } from "vitest";

import {
    createInvestigationContract,
    deriveReplicationControlBinding,
    deriveReplicationSchedule,
    deriveScientificConfirmationFreeze,
    deriveScientificConfirmationState,
    hashCanonical,
    statisticalSubjectIndex,
} from "../domain/index.mjs";
import {
    fakeStatisticalPolicy,
    makeV4ContractInput,
} from "./v4-contract-fixture.mjs";

function protocolFixture(maxConfirmations = 2) {
    const statisticalPolicy = fakeStatisticalPolicy({
        maxConfirmations,
        searchSlots: 1,
    });
    const contract = createInvestigationContract(makeV4ContractInput({
        statisticalPolicy,
    }));
    const frozenContractHash = hashCanonical(contract);
    const evidence = ["alpha", "bravo"].map((candidateId, index) => {
        const schedule = deriveReplicationSchedule({
            contractHash: frozenContractHash,
            statisticalPolicy: contract.statisticalPolicy,
            subject: {
                kind: "candidate",
                index: statisticalSubjectIndex("candidate", index),
                id: candidateId,
                identity: hashCanonical({
                    candidateId,
                    kind: "subject",
                }),
            },
        });
        const controlArtifactHash =
            `sha256:crucible-measurement-snapshot-v1:${
                contract.statisticalPolicy.control.identity
                    .slice("sha256:".length)
            }`;
        return {
            candidateId,
            evidenceId: `evidence-${candidateId}`,
            observationId: `observation-${candidateId}`,
            commitEventHash: hashCanonical({
                candidateId,
                kind: "discovery-evidence",
            }),
            provenanceRoot: hashCanonical({
                candidateId,
                kind: "provenance",
            }),
            invalidated: false,
            hypothesesIdentity: null,
            annotations: {
                mechanism: null,
                hypothesis: null,
                expectedEffects: [],
                citedEvidenceIds: [],
                finding: null,
            },
            receipt: {
                candidateArtifactHash: hashCanonical({
                    candidateId,
                    kind: "snapshot",
                }),
            },
            replication: {
                scheduleHash: schedule.scheduleHash,
                control: deriveReplicationControlBinding({
                    contractHash: frozenContractHash,
                    statisticalPolicy: contract.statisticalPolicy,
                    schedule,
                    controlSnapshotHashes: [controlArtifactHash],
                    requireObservedControl: true,
                }),
            },
            command: {
                kind: "search_candidate",
                hypotheses: null,
                replicationSchedule: schedule,
            },
        };
    });
    const cohort = {
        status: "TIE_COHORT",
        resolved: true,
        comparisonHash: hashCanonical({ kind: "tie-comparison" }),
        relationEvidenceHash: hashCanonical({ kind: "tie-relations" }),
        cohort: evidence.map((item) => ({
            candidateId: item.candidateId,
            evidenceId: item.evidenceId,
            evidenceHash: item.commitEventHash,
        })),
        provisionalWinner: null,
    };
    const aggregate = {
        contract,
        contractHash: frozenContractHash,
        confirmation: { freeze: null },
        lastSeq: 9,
        lastEventHash: hashCanonical({ kind: "discovery-head" }),
        scientificReplay: {
            closureRoot: hashCanonical({ kind: "scientific-replay" }),
            rawAuthorityRoot: hashCanonical({ kind: "raw-authority" }),
        },
        searchStrategy: { revision: 0, history: [] },
        evidence: Object.fromEntries(evidence.map((item) => [
            item.evidenceId,
            item,
        ])),
        evidenceOrder: evidence.map((item) => item.evidenceId),
        observations: Object.fromEntries(evidence.map((item) => [
            item.observationId,
            {
                observationId: item.observationId,
                commandId: `command-${item.candidateId}`,
                annotations: item.annotations,
            },
        ])),
        commands: Object.fromEntries(evidence.map((item) => [
            `command-${item.candidateId}`,
            { command: item.command },
        ])),
    };
    return { aggregate, cohort, evidence };
}

function supportedRoleEvidence(freeze, member, role) {
    const protocol = member.roles[role];
    const evidenceId = `${role}-${member.evidenceId}`;
    const observationId = `${role}-observation-${member.memberOrdinal}`;
    const commandId = `${role}-command-${member.memberOrdinal}`;
    return {
        evidence: {
            evidenceId,
            observationId,
            sourceKind: "harness",
            purpose: role,
            candidateId: member.candidateId,
            candidateEvidenceId: member.evidenceId,
            candidateEvidenceHash: member.evidenceHash,
            confirmationFreezeHash: freeze.freezeHash,
            roleManifestHash: protocol.roleManifest.roleManifestHash,
            protocolManifestHash: protocol.protocolManifestHash,
            invalidated: false,
            commitEventHash: hashCanonical({ evidenceId }),
            provenanceRoot: hashCanonical({ evidenceId, kind: "provenance" }),
            rawAuthorityDigest: hashCanonical({ evidenceId, kind: "raw" }),
            receipt: {
                candidateArtifactHash: member.candidateArtifactHash,
            },
            replication: {
                scheduleHash: protocol.replicationSchedule.scheduleHash,
                blockCount: protocol.replicationSchedule.maxBlocks,
                control: protocol.control,
            },
            hypothesesIdentity: member.hypothesesIdentity,
            annotations: {
                mechanism: null,
                hypothesis: null,
                expectedEffects: [],
                citedEvidenceIds: [],
                finding: null,
            },
            statisticalEvaluation: {
                requiredState: "SUPPORTED",
                evaluationHash: hashCanonical({
                    evidenceId,
                    kind: "evaluation",
                }),
                statistics: { claims: [] },
            },
        },
        observation: {
            observationId,
            commandId,
        },
        command: {
            commandId,
            command: {
                kind: role === "confirmation"
                    ? "run_confirmation"
                    : "run_challenge",
                harnessRole: role,
                confirmationFreezeHash: freeze.freezeHash,
                candidateId: member.candidateId,
                candidateEvidenceId: member.evidenceId,
                candidateEvidenceHash: member.evidenceHash,
                candidateArtifactHash: member.candidateArtifactHash,
                roleManifestHash:
                    protocol.roleManifest.roleManifestHash,
                protocolManifest: protocol,
                protocolManifestHash: protocol.protocolManifestHash,
                hypotheses: protocol.hypotheses,
                replicationSchedule: protocol.replicationSchedule,
            },
        },
    };
}

describe("scientific confirmation protocol allocation", () => {
    it("allocates independent held-out lanes to every tie member", () => {
        const { aggregate, cohort, evidence } = protocolFixture();
        const freeze = deriveScientificConfirmationFreeze({
            aggregate,
            cohort,
            cohortEvidence: evidence,
            basis: { kind: "rounds_exhausted_with_supported_cohort" },
        });

        expect(freeze.members).toHaveLength(2);
        const usedSubjectIndexes = freeze.members.flatMap((member) =>
            ["confirmation", "challenge"].map((role) =>
                member.roles[role].replicationSchedule.subject.index));
        expect(new Set(usedSubjectIndexes).size).toBe(4);
        expect(usedSubjectIndexes).not.toContain(1);
        expect(freeze.members.every((member) =>
            member.roles.confirmation.replicationSchedule.scheduleHash
                !== member.roles.challenge.replicationSchedule.scheduleHash))
            .toBe(true);
        expect(freeze.members.every((member) =>
            member.roles.challenge.challengePolicy.candidateDependent))
            .toBe(true);
    });

    it("refuses cohort, capacity, and alpha-lane reuse", () => {
        const { aggregate, cohort, evidence } = protocolFixture();
        const freeze = deriveScientificConfirmationFreeze({
            aggregate,
            cohort,
            cohortEvidence: evidence,
            basis: { kind: "rounds_exhausted_with_supported_cohort" },
        });
        expect(() => deriveScientificConfirmationFreeze({
            aggregate: {
                ...aggregate,
                confirmation: { freeze: { payload: freeze } },
            },
            cohort,
            cohortEvidence: evidence,
            basis: { kind: "reuse" },
        })).toThrow(/only once/u);

        const capacity = protocolFixture(1);
        expect(() => deriveScientificConfirmationFreeze({
            aggregate: capacity.aggregate,
            cohort: capacity.cohort,
            cohortEvidence: capacity.evidence,
            basis: { kind: "capacity" },
        })).toThrow(/capacity/u);
    });

    it("does not ready a tie until every member closes both roles", () => {
        const { aggregate, cohort, evidence } = protocolFixture();
        const freeze = deriveScientificConfirmationFreeze({
            aggregate,
            cohort,
            cohortEvidence: evidence,
            basis: { kind: "rounds_exhausted_with_supported_cohort" },
        });
        const completed = ["confirmation", "challenge"].map((role) =>
            supportedRoleEvidence(freeze, freeze.members[0], role));
        const state = deriveScientificConfirmationState({
            ...aggregate,
            confirmation: {
                freeze: {
                    payload: freeze,
                    seq: 10,
                    eventHash: hashCanonical({ kind: "freeze-event" }),
                },
            },
            evidenceOrder: [
                ...evidence.map((item) => item.evidenceId),
                ...completed.map((item) => item.evidence.evidenceId),
            ],
            evidence: {
                ...Object.fromEntries(evidence.map((item) => [
                    item.evidenceId,
                    item,
                ])),
                ...Object.fromEntries(completed.map((item) => [
                    item.evidence.evidenceId,
                    item.evidence,
                ])),
            },
            observations: Object.fromEntries(completed.map((item) => [
                item.observation.observationId,
                item.observation,
            ])),
            commands: Object.fromEntries(completed.map((item) => [
                item.command.commandId,
                item.command,
            ])),
        });
        expect(state).toMatchObject({
            status: "PENDING",
            ready: false,
            members: [
                { candidateId: "alpha", status: "READY" },
                { candidateId: "bravo", status: "PENDING" },
            ],
        });
    });

    it("treats an unresolved role at its frozen block limit as terminal failure", () => {
        const { aggregate, cohort, evidence } = protocolFixture();
        const freeze = deriveScientificConfirmationFreeze({
            aggregate,
            cohort,
            cohortEvidence: evidence,
            basis: { kind: "rounds_exhausted_with_supported_cohort" },
        });
        const member = freeze.members[0];
        const protocol = member.roles.confirmation;
        const confirmationEvidence = {
            evidenceId: "confirmation-unresolved",
            observationId: "confirmation-observation",
            sourceKind: "harness",
            purpose: "confirmation",
            candidateId: member.candidateId,
            candidateEvidenceId: member.evidenceId,
            candidateEvidenceHash: member.evidenceHash,
            confirmationFreezeHash: freeze.freezeHash,
            roleManifestHash: protocol.roleManifest.roleManifestHash,
            protocolManifestHash: protocol.protocolManifestHash,
            invalidated: false,
            commitEventHash: hashCanonical({
                kind: "confirmation-unresolved",
            }),
            provenanceRoot: hashCanonical({
                kind: "confirmation-unresolved-provenance",
            }),
            rawAuthorityDigest: hashCanonical({
                kind: "confirmation-unresolved-raw",
            }),
            receipt: {
                candidateArtifactHash: member.candidateArtifactHash,
            },
            replication: {
                scheduleHash: protocol.replicationSchedule.scheduleHash,
                blockCount: protocol.replicationSchedule.maxBlocks,
                control: protocol.control,
            },
            hypothesesIdentity: member.hypothesesIdentity,
            annotations: {
                mechanism: null,
                hypothesis: null,
                expectedEffects: [],
                citedEvidenceIds: [],
                finding: null,
            },
            statisticalEvaluation: {
                requiredState: "UNRESOLVED",
                evaluationHash: hashCanonical({
                    kind: "confirmation-unresolved-evaluation",
                }),
                statistics: { claims: [] },
            },
        };
        const state = deriveScientificConfirmationState({
            ...aggregate,
            confirmation: {
                freeze: {
                    payload: freeze,
                    seq: 10,
                    eventHash: hashCanonical({ kind: "freeze-event" }),
                },
            },
            evidenceOrder: [
                ...evidence.map((item) => item.evidenceId),
                confirmationEvidence.evidenceId,
            ],
            evidence: {
                ...Object.fromEntries(evidence.map((item) => [
                    item.evidenceId,
                    item,
                ])),
                [confirmationEvidence.evidenceId]:
                    confirmationEvidence,
            },
            observations: {
                [confirmationEvidence.observationId]: {
                    commandId: "confirmation-command",
                },
            },
            commands: {
                "confirmation-command": {
                    command: {
                        kind: "run_confirmation",
                        harnessRole: "confirmation",
                        confirmationFreezeHash: freeze.freezeHash,
                        candidateId: member.candidateId,
                        candidateEvidenceId: member.evidenceId,
                        candidateEvidenceHash: member.evidenceHash,
                        candidateArtifactHash:
                            member.candidateArtifactHash,
                        roleManifestHash:
                            protocol.roleManifest.roleManifestHash,
                        protocolManifest: protocol,
                        protocolManifestHash:
                            protocol.protocolManifestHash,
                        hypotheses: protocol.hypotheses,
                        replicationSchedule:
                            protocol.replicationSchedule,
                    },
                },
            },
        });
        expect(state).toMatchObject({
            status: "FAILED",
            failed: true,
        });
        const failedMember = state.members.find((item) =>
            item.candidateId === member.candidateId);
        expect(failedMember.status).toBe("FAILED");
        expect(failedMember.roles.find((role) =>
            role.role === "confirmation")).toMatchObject({
            role: "confirmation",
            status: "UNRESOLVED",
        });
    });

    it("rejects consistently forged role hypotheses and alternate controls", () => {
        const { aggregate, cohort, evidence } = protocolFixture();
        const freeze = deriveScientificConfirmationFreeze({
            aggregate,
            cohort,
            cohortEvidence: evidence,
            basis: { kind: "rounds_exhausted_with_supported_cohort" },
        });
        const member = freeze.members[0];
        const completed = supportedRoleEvidence(
            freeze,
            member,
            "confirmation",
        );
        const forgedHypotheses = {
            identity: hashCanonical({ forged: "hypotheses" }),
        };
        completed.evidence.annotations.hypotheses = forgedHypotheses;
        completed.evidence.hypothesesIdentity = forgedHypotheses.identity;
        completed.command.command.hypotheses = forgedHypotheses;

        const forgedControl = structuredClone(
            completed.evidence.replication.control,
        );
        forgedControl.artifactHash =
            `sha256:crucible-measurement-snapshot-v1:${"9".repeat(64)}`;
        const {
            controlBindingHash: _oldControlBindingHash,
            ...controlCore
        } = forgedControl;
        forgedControl.controlBindingHash = hashCanonical(
            controlCore,
            "sha256:crucible-replication-control-binding-v1",
        );
        completed.evidence.replication.control = forgedControl;

        const state = deriveScientificConfirmationState({
            ...aggregate,
            confirmation: {
                freeze: {
                    payload: freeze,
                    seq: 10,
                    eventHash: hashCanonical({ kind: "freeze-event" }),
                },
            },
            evidenceOrder: [
                ...evidence.map((item) => item.evidenceId),
                completed.evidence.evidenceId,
            ],
            evidence: {
                ...aggregate.evidence,
                [completed.evidence.evidenceId]: completed.evidence,
            },
            observations: {
                ...aggregate.observations,
                [completed.observation.observationId]:
                    completed.observation,
            },
            commands: {
                ...aggregate.commands,
                [completed.command.commandId]: completed.command,
            },
        });
        expect(state.status).toBe("FAILED");
        expect(state.members.find((item) =>
            item.candidateId === member.candidateId)
            ?.roles.find((role) => role.role === "confirmation"))
            .toMatchObject({ status: "INVALID" });
    });
});
