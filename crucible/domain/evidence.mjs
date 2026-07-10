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

function ownEntry(record, key) {
    return Object.hasOwn(record, key) ? record[key] : null;
}

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
        .map((existingId) => ownEntry(aggregate.evidence, existingId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
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
    const command = ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
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
    const command = ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
    const data = observation.data;
    const receipt = observation.receipt;
    if (aggregate.contract.hypothesisTopology === "certified_impossibility"
        && command?.kind === "verify_impossibility"
        && data?.certificateVerdict === "target_unreachable"
        && data.certificateVersion === aggregate.contract.impossibilityPolicy?.certificateVersion
        && data.verificationRequestHash === command.requestHash
        && data.certificateArtifactHash === receipt?.certificateArtifactHash
        && data.measurementReceiptHash === receipt?.measurementReceiptHash
        && data.verificationSnapshotHash === receipt?.verificationSnapshotHash
        && isAlgorithmTaggedSha256(data.certificateArtifactHash)
        && isAlgorithmTaggedSha256(data.measurementReceiptHash)
        && isAlgorithmTaggedSha256(data.verificationRequestHash)
        && isAlgorithmTaggedSha256(data.verificationSnapshotHash)
        && isAlgorithmTaggedSha256(receipt.measurementReceiptArtifactHash)
        && isAlgorithmTaggedSha256(receipt.rawStdoutArtifactHash)
        && isAlgorithmTaggedSha256(receipt.rawStderrArtifactHash)) {
        return {
            kind: "verified_impossibility_certificate",
            topology: "certified_impossibility",
            certificateVersion: data.certificateVersion,
            certificateVerdict: data.certificateVerdict,
            certificateArtifactHash: data.certificateArtifactHash,
            measurementReceiptHash: data.measurementReceiptHash,
            measurementReceiptArtifactHash: receipt.measurementReceiptArtifactHash,
            rawStdoutArtifactHash: receipt.rawStdoutArtifactHash,
            rawStderrArtifactHash: receipt.rawStderrArtifactHash,
            verificationRequestHash: data.verificationRequestHash,
            verificationSnapshotHash: data.verificationSnapshotHash,
        };
    }
    return null;
}
