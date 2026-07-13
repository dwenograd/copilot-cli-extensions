import { describe, expect, it } from "vitest";

import {
    hashCanonical,
    impossibilityProofValidationReceiptHash,
    impossibilityVerifierEnumerandResultsRoot,
    impossibilityVerifierFactsRoot,
    impossibilityVerifierRefutationReceiptHash,
    impossibilityVerifierRefutationRoot,
} from "../domain/index.mjs";
import {
    VERIFIER_PARSER_VERSION,
    parseImpossibilityVerifierResult,
} from "../measurement/index.mjs";

const tagged = (label) => hashCanonical(
    { label },
    "sha256:crucible-verifier-parser-test-v1",
);

function validOutput({
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
            version: "suite-proof-v1",
            schemaHash: tagged("suite-proof-schema"),
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
        proofArtifactHash,
    };
}

describe("independent impossibility verifier parser", () => {
    it("parses a complete role-bound re-evaluation without pass/exhausted shortcuts", () => {
        const { output, binding, request, requestHash } = validOutput();
        const parsed = parseImpossibilityVerifierResult(
            JSON.stringify(output),
            {
                expectedBinding: binding,
                request,
                requestHash,
            },
        );

        expect(parsed).toMatchObject({
            status: "VERIFIED",
            mode: "enumerand_reexecution",
            complete: true,
            checkedEnumerandCount: 2,
            disagreementCount: 0,
            parserVersion: VERIFIER_PARSER_VERSION,
            certificate: {
                verdict: "target_unreachable",
            },
        });
        expect(parsed).not.toHaveProperty("pass");
        expect(parsed).not.toHaveProperty("searchSpaceExhausted");
    });

    it("accepts suite-declared formal certificate validation mode", () => {
        const {
            output,
            binding,
            request,
            requestHash,
            proofArtifactHash,
        } = validOutput({
            mode: "certificate_validation",
        });
        const parsed = parseImpossibilityVerifierResult(
            JSON.stringify(output),
            {
                expectedBinding: binding,
                request,
                requestHash,
            },
        );

        expect(parsed.certificateFormat).toEqual(output.certificateFormat);
        expect(parsed.validatedProofArtifactHash)
            .toBe(proofArtifactHash);
        expect(parsed.validatedProofArtifactHash)
            .not.toBe(output.proposedCertificateArtifactHash);
    });

    it("rejects an echo checker that substitutes the request or proposal for independent facts", () => {
        const fixture = validOutput();
        const first = fixture.output.enumerandResults[0];
        first.evidenceRoot =
            fixture.output.proposedCertificateArtifactHash;
        first.refutationReceiptHash = fixture.requestHash;
        fixture.output.enumerandResultsRoot =
            impossibilityVerifierEnumerandResultsRoot(
                fixture.output.enumerandResults,
            );
        fixture.output.independentFactsRoot =
            impossibilityVerifierFactsRoot({
                mode: fixture.output.mode,
                enumerandResults: fixture.output.enumerandResults,
                proofArtifactHash:
                    fixture.output.proofArtifactHash,
                proofCheckerIdentity: null,
                proofValidationReceiptHash: null,
                validatedProofArtifactHash: null,
            });
        Object.assign(fixture.output.certificate, {
            enumerandResultsRoot:
                fixture.output.enumerandResultsRoot,
            independentFactsRoot:
                fixture.output.independentFactsRoot,
        });

        expect(() => parseImpossibilityVerifierResult(
            JSON.stringify(fixture.output),
            {
                expectedBinding: fixture.binding,
                request: fixture.request,
                requestHash: fixture.requestHash,
            },
        )).toThrow(/kernel-derived|receipt-bound/u);
    });

    it("rejects proposal-hash certificate shortcuts", () => {
        const fixture = validOutput({
            mode: "certificate_validation",
        });
        fixture.output.proofArtifactHash =
            fixture.output.proposedCertificateArtifactHash;
        fixture.output.validatedProofArtifactHash =
            fixture.output.proposedCertificateArtifactHash;
        Object.assign(fixture.output.certificate, {
            proofArtifactHash:
                fixture.output.proofArtifactHash,
            validatedProofArtifactHash:
                fixture.output.validatedProofArtifactHash,
        });

        expect(() => parseImpossibilityVerifierResult(
            JSON.stringify(fixture.output),
        )).toThrow(/distinct from the kernel proposal/u);
    });

    it("rejects checker disagreement disguised as VERIFIED", () => {
        const { output } = validOutput();
        output.disagreementCount = 1;
        expect(() => parseImpossibilityVerifierResult(JSON.stringify(output)))
            .toThrow(/disagreementCount/u);
    });

    it("rejects duplicate or re-identified enumerand verifier evidence", () => {
        const duplicate = validOutput();
        duplicate.output.enumerandResults[1].evidenceRoot =
            duplicate.output.enumerandResults[0].evidenceRoot;
        expect(() => parseImpossibilityVerifierResult(
            JSON.stringify(duplicate.output),
        )).toThrow(/duplicate verifier evidence roots/u);

        const reidentified = validOutput();
        reidentified.output.enumerandResults[1].ordinal = 0;
        reidentified.output.enumerandResults[1].enumerandHash =
            reidentified.output.enumerandResults[0].enumerandHash;
        expect(() => parseImpossibilityVerifierResult(
            JSON.stringify(reidentified.output),
        )).toThrow(/duplicate enumerand identities/u);
    });

    it("binds certificate validation to the exact coverage closure", () => {
        const fixture = validOutput({ mode: "certificate_validation" });
        fixture.output.coverageClosureRoot = tagged("tampered-coverage");
        fixture.output.certificate.coverageClosureRoot =
            fixture.output.coverageClosureRoot;
        expect(() => parseImpossibilityVerifierResult(
            JSON.stringify(fixture.output),
            {
                expectedBinding: fixture.binding,
                request: fixture.request,
                requestHash: fixture.requestHash,
            },
        )).toThrow(/reserved verifier request/u);
    });

    it("rejects altered certificate/request bindings", () => {
        const { output } = validOutput();
        output.certificate.requestHash = tagged("altered-request");
        expect(() => parseImpossibilityVerifierResult(JSON.stringify(output)))
            .toThrow(/certificate disagrees/u);
    });

    it("rejects legacy pass plus exhausted output", () => {
        expect(() => parseImpossibilityVerifierResult(JSON.stringify({
            pass: true,
            searchSpaceExhausted: true,
        }))).toThrow(/formal checker fields/u);
    });

    it("rejects duplicate JSON keys", () => {
        const { output } = validOutput();
        const raw = JSON.stringify(output).replace(
            '"status":"VERIFIED"',
            '"status":"VERIFIED","status":"REJECTED"',
        );
        expect(() => parseImpossibilityVerifierResult(raw))
            .toThrow(/duplicate JSON object key/u);
    });
});
