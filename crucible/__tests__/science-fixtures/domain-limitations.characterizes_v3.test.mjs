import { describe, expect, it } from "vitest";

import { buildV3ScienceBaseline } from "./v3-adapter.mjs";

// Phase 0 baseline only. These tests make current v3 boundaries explicit so
// later v4 work can replace them with separate desired-behavior acceptance
// tests rather than accidentally treating these limitations as requirements.

const baseline = buildV3ScienceBaseline();
const cases = new Map(baseline.cases.map((item) => [item.id, item]));

describe("characterizes_v3 domain and lifecycle limitations", () => {
    it("characterizes_v3_bounded_ids_reject_duplicates_but_do_not_bind_enumerand_content", () => {
        const item = cases.get("bounded-ids-duplicate-and-mutated-enumerand");

        expect(item.oracle).toEqual({
            duplicateIdsUnique: false,
            duplicateIdsShouldBeRejected: true,
            enumerandContentChanged: true,
            contentMutationShouldChangeIdentity: true,
        });
        expect(item.observedV3).toMatchObject({
            duplicateIdsRejected: true,
            duplicateErrorCode: "INVALID_CONTRACT",
            duplicateErrorMentionsUnique: true,
            mutatedContentsChangeContractHash: false,
            enumerandContentsFrozenInContract: false,
            retryCandidateId: "enum-a",
            retryReplacementOrdinal: 1,
            replacementCandidateId: "enum-a",
            replacementArtifactChanged: true,
        });
        expect(item.expectedToChangeInV4).toBe(true);
    });

    it("characterizes_v3_invalid_self_generated_and_disagreeing_impossibility_proofs", () => {
        const item = cases.get("invalid-self-generated-disagreeing-impossibility");

        expect(item.oracle).toEqual({
            selfGeneratedIsIndependent: false,
            invalidFactsShouldProveUnreachable: false,
            disagreeingAttemptsShouldProveUnreachable: false,
        });
        expect(item.observedV3).toMatchObject({
            rawCandidateClaimRecommendation: {
                kind: "COMMAND",
                commandKind: "verify_impossibility",
            },
            selfCertifiedVerdict: "target_unreachable",
            selfCertifiedDecision: "TARGET_UNREACHABLE",
            generatorEqualsVerifier: true,
            independentVerifierRequired: false,
            invalidVerdict: "invalid",
            invalidRecommendation: {
                kind: "NON_RESULT",
                code: "IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE",
            },
            disagreeingVerdicts: ["not_proven", "target_unreachable"],
            secondAttemptOrdinal: 2,
            disagreeingFinalDecision: "TARGET_UNREACHABLE",
            consensusRequired: false,
        });
    });

    it("characterizes_v3_reboot_rollover_and_resource_contention_as_unbound_metadata", () => {
        const item = cases.get("reboot-rollover-resource-contention-metadata");

        expect(item.oracle.rebootRecoveryFieldsRequired).toEqual([
            "bootId",
            "recoveredFromEventHash",
            "recoveryAttemptOrdinal",
        ]);
        expect(item.oracle.rolloverFieldsRequired).toEqual([
            "segmentId",
            "previousSegmentRoot",
            "rolloverReason",
        ]);
        expect(item.oracle.resourceContentionFieldsRequired).toEqual([
            "leaseId",
            "resourceId",
            "waitOrdinal",
        ]);
        expect(item.observedV3).toEqual({
            lifecycleMetadataChangesContractHash: false,
            normalizedContractFieldsPresent: {
                rebootRecovery: false,
                rollover: false,
                resourceContention: false,
            },
            resumePayloadKeys: ["pausedSeq", "sourceStopRequestSeq"],
            rebootRecoveryBound: false,
            eventLogRolloverBound: false,
            resourceContentionBound: false,
        });
    });
});

