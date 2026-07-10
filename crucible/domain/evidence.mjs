import { hashCanonical, isAlgorithmTaggedSha256 } from "./canonical.mjs";
import {
    acceptanceSatisfied,
    candidateMetricValues,
    candidateMetricsRankable,
    validationSatisfied,
} from "./contract.mjs";
import {
    classifyCandidateOutcome,
    duplicateEvidenceId,
} from "./archive.mjs";

export function deriveEvidencePayload(aggregate, observation, evidenceId) {
    const harnessEvidence = observation.sourceKind === "harness";
    const candidateEvidence = harnessEvidence && observation.purpose === "candidate";
    const validationEvidence = harnessEvidence && observation.purpose === "validation";
    const accepted = candidateEvidence
        && acceptanceSatisfied(aggregate.contract.acceptancePredicate, observation.data);
    const metrics = candidateEvidence
        ? candidateMetricValues(aggregate.contract.metrics, observation.data)
        : null;
    const rankable = candidateEvidence
        && candidateMetricsRankable(aggregate.contract.metrics, metrics);
    const allPriorCandidates = aggregate.evidenceOrder
        .map((existingId) => aggregate.evidence[existingId])
        .filter((evidence) =>
            evidence.sourceKind === "harness"
            && evidence.purpose === "candidate");
    const priorCandidates = allPriorCandidates.filter((evidence) => !evidence.invalidated);
    const outcomeClass = candidateEvidence
        ? classifyCandidateOutcome(aggregate.contract, observation.data, {
            metrics,
            rankable,
            accepted,
            priorCandidates,
        })
        : null;
    const command = aggregate.commands[observation.commandId]?.command ?? null;
    const candidateArtifactHash = candidateEvidence
        ? observation.receipt.candidateArtifactHash
        : null;

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
        slotIndex: candidateEvidence ? observation.slotIndex : null,
        candidateId: candidateEvidence ? observation.candidateId : null,
        model: candidateEvidence ? command.model : null,
        operator: candidateEvidence ? command.operator : null,
        parentEvidenceIds: candidateEvidence ? command.parentEvidenceIds : [],
        promptContextRefs: candidateEvidence ? command.promptContextRefs : [],
        seed: candidateEvidence ? command.seed : null,
        boundedCandidateId: candidateEvidence ? (command.boundedCandidateId ?? null) : null,
        metrics,
        rankable,
        outcomeClass,
        acceptanceSatisfied: accepted,
        annotations: candidateEvidence ? observation.annotations : null,
        duplicateOf: candidateEvidence
            ? duplicateEvidenceId(allPriorCandidates, candidateArtifactHash)
            : null,
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
