import { hashCanonical, isAlgorithmTaggedSha256 } from "./canonical.mjs";
import {
    acceptanceSatisfied,
    candidateMetricValues,
    validationSatisfied,
} from "./contract.mjs";
import { ERROR_CODES, TransitionError } from "./errors.mjs";

export function deriveEvidencePayload(aggregate, observation, evidenceId) {
    const harnessEvidence = observation.sourceKind === "harness";
    const candidateEvidence = harnessEvidence && observation.purpose === "candidate";
    const validationEvidence = harnessEvidence && observation.purpose === "validation";
    const accepted = candidateEvidence
        && acceptanceSatisfied(aggregate.contract.acceptancePredicate, observation.data);
    const metrics = candidateEvidence
        ? candidateMetricValues(aggregate.contract.metrics, observation.data)
        : null;
    if (candidateEvidence && metrics === null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Harness candidate evidence must provide every frozen ranking metric",
            { candidateId: observation.candidateId },
        );
    }

    return {
        evidenceId,
        observationId: observation.observationId,
        sourceKind: observation.sourceKind,
        purpose: observation.purpose,
        harnessId: observation.harnessId,
        parserVersion: observation.parserVersion,
        receipt: observation.receipt,
        contentHash: hashCanonical(observation.data),
        round: candidateEvidence ? observation.round : null,
        candidateId: candidateEvidence ? observation.candidateId : null,
        metrics,
        acceptanceSatisfied: accepted,
        validationSatisfied: validationEvidence
            && validationSatisfied(aggregate.contract.validationCases, observation.data),
        unreachableBasis: deriveCertificateBasis(aggregate, observation),
    };
}

function deriveCertificateBasis(aggregate, observation) {
    if (observation.sourceKind !== "harness" || observation.purpose !== "impossibility") {
        return null;
    }
    if (aggregate.contract.hypothesisTopology === "certified_impossibility"
        && isAlgorithmTaggedSha256(observation.data?.impossibilityCertificateHash)) {
        return {
            kind: "impossibility_certificate",
            topology: "certified_impossibility",
            impossibilityCertificateHash: observation.data.impossibilityCertificateHash,
        };
    }
    return null;
}
