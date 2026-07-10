import {
    IMPOSSIBILITY_SEARCH_EVIDENCE_HASH_ALGORITHM,
    IMPOSSIBILITY_VERDICTS,
} from "./constants.mjs";
import { hashCanonical } from "./canonical.mjs";

export function deriveImpossibilityVerdict(facts) {
    if (facts?.pass === true && facts?.searchSpaceExhausted === true) {
        return "target_unreachable";
    }
    if (facts?.pass === false) {
        return "not_proven";
    }
    return "invalid";
}

export function isImpossibilityVerdict(value) {
    return IMPOSSIBILITY_VERDICTS.includes(value);
}

export function impossibilitySearchEvidenceHash(candidates) {
    return hashCanonical(
        candidates.map((evidence) => ({
            acceptanceSatisfied: evidence.acceptanceSatisfied,
            candidateArtifactHash: evidence.receipt.candidateArtifactHash,
            candidateId: evidence.candidateId,
            contentHash: evidence.contentHash,
            evidenceHash: evidence.commitEventHash,
            evidenceId: evidence.evidenceId,
            outcomeClass: evidence.outcomeClass,
            rankable: evidence.rankable,
            round: evidence.round,
            slotIndex: evidence.slotIndex,
        })),
        IMPOSSIBILITY_SEARCH_EVIDENCE_HASH_ALGORITHM,
    );
}
