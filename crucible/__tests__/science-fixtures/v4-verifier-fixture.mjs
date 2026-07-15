import {
    hashCanonical,
    impossibilityProofValidationReceiptHash,
    impossibilityVerifierEnumerandResultsRoot,
    impossibilityVerifierFactsRoot,
    impossibilityVerifierRefutationReceiptHash,
    impossibilityVerifierRefutationRoot,
} from "../../domain/index.mjs";

const tagged = (label) => hashCanonical(
    { label },
    "sha256:crucible-v4-science-verifier-fixture-v1",
);

export function createV4VerifierFixture({
    status = "VERIFIED",
    mode = "enumerand_reexecution",
} = {}) {
    const suiteIdentity =
        `sha256:crucible-harness-suite-v4:${"a".repeat(64)}`;
    const environmentIdentity =
        `sha256:crucible-harness-environment-v4:${"b".repeat(64)}`;
    const requestHash = tagged("request");
    const proposedCertificateArtifactHash = tagged("proposal");
    const proofArtifactHash = tagged("proof");
    const evidenceRoots = {
        calibration: tagged("calibration"),
        control: tagged("control"),
        search: tagged("search"),
        scientificReplay: tagged("scientific-replay"),
    };
    const certificateFormat = mode === "certificate_validation"
        ? {
            version: "science-proof-v1",
            schemaHash: tagged("science-proof-schema"),
        }
        : null;
    const proofCheckerIdentity = mode === "certificate_validation"
        ? tagged("proof-checker")
        : null;
    const validatedProofArtifactHash = mode === "certificate_validation"
        ? proofArtifactHash
        : null;
    const verdict = status === "VERIFIED"
        ? "target_unreachable"
        : status === "REJECTED"
            ? "not_proven"
            : status === "INCONCLUSIVE"
                ? "inconclusive"
                : "invalid";
    const checkerEvidenceRoot = tagged("checker-evidence");
    const coverageClosureRoot = tagged("coverage-closure");
    const contractHash = tagged("contract");
    const verifierRoleIdentity = tagged("verifier-role");
    const claimState = status === "VERIFIED"
        ? "REFUTED"
        : status === "REJECTED"
            ? "SUPPORTED"
            : status === "INCONCLUSIVE"
                ? "UNRESOLVED"
                : "INVALID";
    const reevaluationInputs = [0, 1].map((ordinal) => ({
        ordinal,
        enumerandHash: tagged(`enumerand-${ordinal}`),
        inputRoot: tagged(`input-${ordinal}`),
        receiptBindingsRoot: tagged(`receipts-${ordinal}`),
    }));
    const enumerandResults = mode === "enumerand_reexecution"
        ? (status === "VERIFIED" || status === "REJECTED"
            ? [0, 1]
            : [0]).map((ordinal) => {
            const input = reevaluationInputs[ordinal];
            const claimStates = [{
                claimId: "acceptance.score",
                state: claimState,
            }];
            const evidenceRoot = impossibilityVerifierRefutationRoot({
                requestHash,
                verifierRoleIdentity,
                ordinal,
                enumerandHash: input.enumerandHash,
                inputRoot: input.inputRoot,
                claimStates,
            });
            return {
                ordinal,
                enumerandHash: input.enumerandHash,
                claimStates,
                inputRoot: input.inputRoot,
                receiptBindingsRoot: input.receiptBindingsRoot,
                evidenceRoot,
                refutationReceiptHash:
                    impossibilityVerifierRefutationReceiptHash({
                        requestHash,
                        verifierRoleIdentity,
                        ordinal,
                        enumerandHash: input.enumerandHash,
                        inputRoot: input.inputRoot,
                        receiptBindingsRoot:
                            input.receiptBindingsRoot,
                        claimStates,
                        evidenceRoot,
                    }),
            };
        })
        : [];
    const enumerandResultsRoot =
        impossibilityVerifierEnumerandResultsRoot(enumerandResults);
    const coverageEnumerands = [0, 1].map((ordinal) => ({
        ordinal,
        enumerandHash: tagged(`enumerand-${ordinal}`),
        claims: [{ claimId: "acceptance.score" }],
    }));
    const proofValidationReceiptHash = mode === "certificate_validation"
        ? impossibilityProofValidationReceiptHash({
            requestHash,
            proofArtifactHash,
            proofCheckerIdentity,
            certificateFormat,
            status,
            checkerEvidenceRoot,
        })
        : null;
    const independentFactsRoot = impossibilityVerifierFactsRoot({
        mode,
        enumerandResults,
        proofArtifactHash,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
    });
    const output = {
        version: "crucible-impossibility-verifier-output-v1",
        status,
        mode,
        requestHash,
        proposedCertificateArtifactHash,
        proofArtifactHash,
        coverageClosureRoot,
        enumerandManifestRoot: tagged("enumerand-root"),
        enumerandCount: 2,
        checkedEnumerandCount: enumerandResults.length,
        enumerandResults,
        enumerandResultsRoot,
        evidenceRoots,
        statisticalPolicyIdentity: tagged("statistical-policy"),
        alphaLedgerRoot: tagged("alpha-ledger"),
        checkerEvidenceRoot,
        independentFactsRoot,
        disagreementCount: enumerandResults.filter((result) =>
            result.claimStates.some((claim) => claim.state !== "REFUTED")).length,
        complete: status === "VERIFIED" || status === "REJECTED",
        certificateFormat,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
        certificate: {
            version: "crucible-impossibility-certificate-v2",
            status,
            verdict,
            mode,
            requestHash,
            proposedCertificateArtifactHash,
            proofArtifactHash,
            contractHash,
            harnessSuiteIdentity: suiteIdentity,
            verifierRoleIdentity,
            coverageClosureRoot,
            enumerandManifestRoot: tagged("enumerand-root"),
            enumerandResultsRoot,
            evidenceRoots,
            statisticalPolicyIdentity: tagged("statistical-policy"),
            alphaLedgerRoot: tagged("alpha-ledger"),
            checkerEvidenceRoot,
            independentFactsRoot,
            certificateFormat,
            proofCheckerIdentity,
            proofValidationReceiptHash,
            validatedProofArtifactHash,
        },
        role: "impossibility_verifier",
        phase: "impossibility_verification",
        blockIndex: 0,
        deterministicSeed: tagged("seed"),
        subjectId: "impossibility-1",
        environmentIdentity,
        suiteIdentity,
    };
    const request = {
        verifier: {
            roleIdentity: verifierRoleIdentity,
            proofChecker: proofCheckerIdentity === null
                ? null
                : { identity: proofCheckerIdentity },
            verificationPolicy: {
                mode,
                certificateFormat,
            },
        },
        proposedCertificate: {
            artifactHash: proposedCertificateArtifactHash,
        },
        proofArtifact: {
            artifactHash: proofArtifactHash,
        },
        evidence: {
            roots: evidenceRoots,
            coverageClosureRoot,
            coverageClosure: {
                enumerands: coverageEnumerands,
            },
        },
        reevaluation: {
            enumerands: reevaluationInputs,
        },
        enumerands: {
            merkleRoot: output.enumerandManifestRoot,
            count: output.enumerandCount,
        },
        statistics: {
            policyIdentity: output.statisticalPolicyIdentity,
            alphaLedgerRoot: output.alphaLedgerRoot,
        },
        signedExperiment: {
            contractHash,
        },
        harnessSuiteIdentity: suiteIdentity,
    };
    const binding = {
        role: output.role,
        phase: output.phase,
        replicateIndex: null,
        blockIndex: output.blockIndex,
        armIndex: null,
        armId: null,
        deterministicSeed: output.deterministicSeed,
        subjectId: output.subjectId,
        environmentIdentity: output.environmentIdentity,
        suiteIdentity: output.suiteIdentity,
    };
    return {
        output,
        binding,
        request,
        requestHash,
    };
}
