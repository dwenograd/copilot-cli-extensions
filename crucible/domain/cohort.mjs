import {
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import {
    candidateNoveltySignatures,
    supportedBehavioralDifference,
} from "./novelty.mjs";

export const CANDIDATE_RELATIONS = Object.freeze([
    "BETTER",
    "WORSE",
    "PRACTICALLY_EQUIVALENT",
    "UNRESOLVED",
    "INCOMPARABLE",
]);
export const CANDIDATE_COHORT_VERSION =
    "crucible-candidate-cohort-v1";
export const CANDIDATE_RELATION_EVIDENCE_HASH_ALGORITHM =
    "sha256:crucible-candidate-relation-evidence-v1";
export const CANDIDATE_COHORT_HASH_ALGORITHM =
    "sha256:crucible-candidate-cohort-v1";
export const TIE_RESOLUTION_PLAN_HASH_ALGORITHM =
    "sha256:crucible-tie-resolution-plan-v1";

const RESOLVED_COHORT_STATES = new Set([
    "UNIQUE_BEST",
    "TIE_COHORT",
]);

function finite(value) {
    return typeof value === "number" && Number.isFinite(value);
}

function lexical(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

function candidateDisplayKey(candidate) {
    return `${candidate.candidateId ?? ""}\0${candidate.evidenceId ?? ""}`;
}

function displayOrder(left, right) {
    return lexical(candidateDisplayKey(left), candidateDisplayKey(right));
}

function candidateReference(candidate) {
    return {
        candidateId: candidate.candidateId,
        evidenceId: candidate.evidenceId,
        evidenceHash: candidate.evidenceHash ?? null,
    };
}

function metricPriority(contract) {
    return [...(contract?.statisticalPolicy?.metrics ?? [])]
        .map((metric, index) => ({
            ...metric,
            priority: Number.isSafeInteger(metric.priority)
                ? metric.priority
                : index,
        }))
        .sort((left, right) =>
            left.priority - right.priority
            || lexical(left.key, right.key));
}

function requiredPredictionStatuses(candidate) {
    return (candidate.predictionEvaluation?.predictions ?? [])
        .filter((prediction) => prediction.requiredForResult === true)
        .map((prediction) => ({
            predictionId: prediction.predictionId,
            predictionIdentity: prediction.predictionIdentity ?? null,
            status: prediction.status,
        }))
        .sort((left, right) =>
            lexical(left.predictionId, right.predictionId));
}

function predictionEvidence(candidate) {
    const required = requiredPredictionStatuses(candidate);
    return {
        hypothesesIdentity: candidate.hypothesesIdentity ?? null,
        overallState:
            candidate.predictionEvaluation?.overallState
            ?? (required.length === 0 ? "SUPPORTED" : "UNRESOLVED"),
        requiredState:
            candidate.predictionEvaluation?.requiredState
            ?? (required.length === 0 ? "SUPPORTED" : "UNRESOLVED"),
        required,
    };
}

function noveltyEvidence(candidate) {
    const novelty = candidate.novelty ?? null;
    return {
        signatures: candidateNoveltySignatures({ novelty }),
        contentSignature: novelty?.content?.signature ?? null,
        structuralFingerprint:
            novelty?.structural?.structuralFingerprint ?? null,
        behavioralSignature: novelty?.behavioral?.signature ?? null,
        behavioral: novelty?.behavioral ?? null,
    };
}

function candidateEligibility(contract, candidate) {
    const reasons = [];
    if (candidate.active !== true || candidate.invalidated === true) {
        reasons.push("inactive_evidence");
    }
    if (candidate.requiredState !== "SUPPORTED"
        || candidate.acceptanceSatisfied !== true) {
        reasons.push("statistical_acceptance_not_supported");
    }
    if (candidate.completeValidBlocks !== true) {
        reasons.push("incomplete_or_invalid_blocks");
    }
    if (candidate.rankable !== true) {
        reasons.push("missing_rankable_metric");
    }
    const predictions = predictionEvidence(candidate);
    if (contract?.scientificTerminalPolicy?.hypotheses
        ?.requiredForResultMustBeSupported === true
        && predictions.requiredState !== "SUPPORTED") {
        reasons.push("required_predictions_not_supported");
    }
    return {
        eligible: reasons.length === 0,
        reasons,
        predictions,
        novelty: noveltyEvidence(candidate),
    };
}

function metricClaim(candidate, metricKey) {
    const claims =
        candidate.statisticalEvaluation?.statistics?.claims ?? [];
    const preferredId = `metric.${metricKey}.acceptance`;
    return claims.find((claim) =>
        claim.id === preferredId
        && claim.observable === metricKey
        && claim.estimate?.scale === "original_metric")
        ?? claims.find((claim) =>
            claim.observable === metricKey
            && claim.estimate?.scale === "original_metric")
        ?? null;
}

function confidenceSequence(claim) {
    const interval = claim?.estimate?.confidenceSequence;
    return finite(interval?.lower)
        && finite(interval?.upper)
        && interval.lower <= interval.upper
        ? {
            lower: Object.is(interval.lower, -0) ? 0 : interval.lower,
            upper: Object.is(interval.upper, -0) ? 0 : interval.upper,
        }
        : null;
}

function orientedDifference(metric, left, right) {
    if (metric.direction === "max") {
        return {
            lower: left.lower - right.upper,
            upper: left.upper - right.lower,
        };
    }
    return {
        lower: right.lower - left.upper,
        upper: right.upper - left.lower,
    };
}

function metricRelation(metric, leftCandidate, rightCandidate) {
    const leftClaim = metricClaim(leftCandidate, metric.key);
    const rightClaim = metricClaim(rightCandidate, metric.key);
    const leftConfidence = confidenceSequence(leftClaim);
    const rightConfidence = confidenceSequence(rightClaim);
    const common = {
        metric: metric.key,
        priority: metric.priority,
        direction: metric.direction,
        practicalDelta: metric.practicalEquivalenceDelta,
        left: {
            claimId: leftClaim?.id ?? null,
            claimState: leftClaim?.state ?? null,
            confidenceSequence: leftConfidence,
        },
        right: {
            claimId: rightClaim?.id ?? null,
            claimState: rightClaim?.state ?? null,
            confidenceSequence: rightConfidence,
        },
    };
    if (leftConfidence === null || rightConfidence === null) {
        return {
            ...common,
            relation: "INCOMPARABLE",
            orientedDifference: null,
            intervalsOverlap: null,
            additionalBlocksCanResolve: false,
            reason: "missing_supported_metric_confidence_sequence",
        };
    }
    const difference = orientedDifference(
        metric,
        leftConfidence,
        rightConfidence,
    );
    const delta = metric.practicalEquivalenceDelta;
    const intervalsOverlap = Math.max(
        leftConfidence.lower,
        rightConfidence.lower,
    ) <= Math.min(leftConfidence.upper, rightConfidence.upper);
    let relation;
    if (difference.lower > delta) {
        relation = "BETTER";
    } else if (difference.upper < -delta) {
        relation = "WORSE";
    } else if (difference.lower >= -delta
        && difference.upper <= delta) {
        relation = "PRACTICALLY_EQUIVALENT";
    } else {
        relation = "UNRESOLVED";
    }
    return {
        ...common,
        relation,
        orientedDifference: difference,
        intervalsOverlap,
        additionalBlocksCanResolve: relation === "UNRESOLVED",
        reason: relation === "UNRESOLVED"
            ? "confidence_sequence_does_not_support_margin_or_equivalence"
            : "confidence_sequence_support",
    };
}

function pairNoveltyEvidence(left, right) {
    const leftNovelty = noveltyEvidence(left);
    const rightNovelty = noveltyEvidence(right);
    return {
        sameContent:
            leftNovelty.contentSignature !== null
            && leftNovelty.contentSignature === rightNovelty.contentSignature,
        sameStructuralFingerprint:
            leftNovelty.structuralFingerprint !== null
            && leftNovelty.structuralFingerprint
                === rightNovelty.structuralFingerprint,
        supportedBehavioralDifference: supportedBehavioralDifference(
            leftNovelty.behavioral,
            rightNovelty.behavioral,
        ),
        leftSignatures: leftNovelty.signatures,
        rightSignatures: rightNovelty.signatures,
    };
}

function invertRelation(relation) {
    if (relation === "BETTER") return "WORSE";
    if (relation === "WORSE") return "BETTER";
    return relation;
}

export function compareCandidatePair(contract, left, right) {
    const metrics = metricPriority(contract);
    const metricEvidence = [];
    let relation = metrics.length === 0
        ? "INCOMPARABLE"
        : "PRACTICALLY_EQUIVALENT";
    for (const metric of metrics) {
        const evidence = metricRelation(metric, left, right);
        metricEvidence.push(evidence);
        if (evidence.relation === "PRACTICALLY_EQUIVALENT") {
            continue;
        }
        relation = evidence.relation;
        break;
    }
    const core = {
        left: candidateReference(left),
        right: candidateReference(right),
        relation,
        decisiveMetric:
            metricEvidence.find((metric) =>
                metric.relation !== "PRACTICALLY_EQUIVALENT")
                ?.metric
            ?? metricEvidence.at(-1)?.metric
            ?? null,
        metricEvidence,
        predictions: {
            left: predictionEvidence(left),
            right: predictionEvidence(right),
        },
        novelty: pairNoveltyEvidence(left, right),
    };
    return immutableCanonical({
        ...core,
        evidenceHash: hashCanonical(
            core,
            CANDIDATE_RELATION_EVIDENCE_HASH_ALGORITHM,
        ),
    });
}

function relationKey(leftEvidenceId, rightEvidenceId) {
    return `${leftEvidenceId}\0${rightEvidenceId}`;
}

function directedRelation(pair, leftEvidenceId, rightEvidenceId) {
    if (pair.left.evidenceId === leftEvidenceId
        && pair.right.evidenceId === rightEvidenceId) {
        return pair.relation;
    }
    return invertRelation(pair.relation);
}

function relationFor(relations, leftEvidenceId, rightEvidenceId) {
    if (leftEvidenceId === rightEvidenceId) {
        return "PRACTICALLY_EQUIVALENT";
    }
    return relations.get(relationKey(leftEvidenceId, rightEvidenceId))
        ?? invertRelation(
            relations.get(relationKey(rightEvidenceId, leftEvidenceId)),
        );
}

function scientificFrontier(eligible, relationMap) {
    const frontier = eligible.filter((candidate) =>
        !eligible.some((other) =>
            other.evidenceId !== candidate.evidenceId
            && relationFor(
                relationMap,
                other.evidenceId,
                candidate.evidenceId,
            ) === "BETTER"));
    return frontier.length === 0 ? eligible : frontier;
}

function uniqueSupportedBest(eligible, relationMap) {
    if (eligible.length === 1) return eligible[0];
    const supported = eligible.filter((candidate) =>
        eligible.every((other) =>
            other.evidenceId === candidate.evidenceId
            || relationFor(
                relationMap,
                candidate.evidenceId,
                other.evidenceId,
            ) === "BETTER"));
    return supported.length === 1 ? supported[0] : null;
}

function supportedTieCohort(frontier, eligible, relationMap) {
    if (frontier.length < 2) return null;
    const frontierIds = new Set(frontier.map((item) => item.evidenceId));
    const pairwiseEquivalent = frontier.every((candidate, index) =>
        frontier.slice(index + 1).every((other) =>
            relationFor(
                relationMap,
                candidate.evidenceId,
                other.evidenceId,
            ) === "PRACTICALLY_EQUIVALENT"));
    const dominatesOutside = frontier.every((candidate) =>
        eligible.every((other) =>
            frontierIds.has(other.evidenceId)
            || relationFor(
                relationMap,
                candidate.evidenceId,
                other.evidenceId,
            ) === "BETTER"));
    return pairwiseEquivalent && dominatesOutside ? frontier : null;
}

function unresolvedFrontierRelations(frontier, eligible, relationMap) {
    const frontierIds = new Set(
        frontier.map((candidate) => candidate.evidenceId),
    );
    const relations = [];
    for (let leftIndex = 0; leftIndex < eligible.length; leftIndex += 1) {
        for (
            let rightIndex = leftIndex + 1;
            rightIndex < eligible.length;
            rightIndex += 1
        ) {
            const left = eligible[leftIndex];
            const right = eligible[rightIndex];
            const relation = relationFor(
                relationMap,
                left.evidenceId,
                right.evidenceId,
            );
            if ((frontierIds.has(left.evidenceId)
                || frontierIds.has(right.evidenceId))
                && (relation === "UNRESOLVED"
                    || relation === "INCOMPARABLE")) {
                relations.push({
                    leftEvidenceId: left.evidenceId,
                    rightEvidenceId: right.evidenceId,
                    relation,
                });
            }
        }
    }
    return relations;
}

function tieResolutionPlan(
    contract,
    frontier,
    eligible,
    relationMap,
    relationEvidence,
) {
    const unresolved = unresolvedFrontierRelations(
        frontier,
        eligible,
        relationMap,
    );
    const byPair = new Map(relationEvidence.map((pair) => [
        relationKey(pair.left.evidenceId, pair.right.evidenceId),
        pair,
    ]));
    const resolvableEvidenceIds = new Set();
    let hasIrresolvableRelation = false;
    for (const item of unresolved) {
        const pair = byPair.get(relationKey(
            item.leftEvidenceId,
            item.rightEvidenceId,
        )) ?? byPair.get(relationKey(
            item.rightEvidenceId,
            item.leftEvidenceId,
        ));
        const resolvable = item.relation === "UNRESOLVED"
            && (pair?.metricEvidence ?? []).some(
                (metric) => metric.additionalBlocksCanResolve === true,
            );
        if (!resolvable) {
            hasIrresolvableRelation = true;
            continue;
        }
        resolvableEvidenceIds.add(item.leftEvidenceId);
        resolvableEvidenceIds.add(item.rightEvidenceId);
    }
    const maxBlocks = contract?.statisticalPolicy?.maxBlocks ?? 0;
    const candidates = eligible
        .filter((candidate) =>
            resolvableEvidenceIds.has(candidate.evidenceId))
        .map((candidate) => {
            const blockCount = candidate.replication?.blockCount
                ?? candidate.statisticalEvaluation?.blockCount
                ?? 0;
            return {
                ...candidateReference(candidate),
                blockCount,
                nextBlockIndex: blockCount,
                remainingBlocks: Math.max(0, maxBlocks - blockCount),
                scheduleHash:
                    candidate.replication?.scheduleHash
                    ?? candidate.statisticalEvaluation?.scheduleHash
                    ?? null,
            };
        })
        .filter((candidate) => candidate.remainingBlocks > 0)
        .sort(displayOrder);
    const core = {
        required: unresolved.length > 0,
        schedulable: unresolved.length > 0
            && !hasIrresolvableRelation
            && candidates.length > 0,
        exhausted: unresolved.length > 0
            && (hasIrresolvableRelation || candidates.length === 0),
        hasIrresolvableRelation,
        unresolvedRelations: unresolved,
        candidates,
        nextBlockCandidateEvaluations: candidates.length,
        nextBlockControlEvaluations: candidates.length,
        nextBlockTotalEvaluations: candidates.length * 2,
    };
    return {
        ...core,
        planHash: hashCanonical(core, TIE_RESOLUTION_PLAN_HASH_ALGORITHM),
    };
}

function candidateSummary(candidate, eligibility) {
    return {
        ...candidateReference(candidate),
        eligible: eligibility.eligible,
        ineligibilityReasons: eligibility.reasons,
        statisticalState: candidate.requiredState ?? "INVALID",
        completeValidBlocks: candidate.completeValidBlocks === true,
        acceptanceSatisfied: candidate.acceptanceSatisfied === true,
        rankable: candidate.rankable === true,
        blockCount:
            candidate.replication?.blockCount
            ?? candidate.statisticalEvaluation?.blockCount
            ?? 0,
        predictions: eligibility.predictions,
        novelty: {
            signatures: eligibility.novelty.signatures,
            contentSignature: eligibility.novelty.contentSignature,
            structuralFingerprint:
                eligibility.novelty.structuralFingerprint,
            behavioralSignature:
                eligibility.novelty.behavioralSignature,
        },
    };
}

export function deriveCandidateCohortComparison({
    contract,
    candidates,
}) {
    const decorated = candidates.map((candidate) => ({
        candidate,
        eligibility: candidateEligibility(contract, candidate),
    }));
    const eligible = decorated
        .filter((item) => item.eligibility.eligible)
        .map((item) => item.candidate)
        .sort(displayOrder);
    const relationEvidence = [];
    const relationMap = new Map();
    for (let leftIndex = 0; leftIndex < eligible.length; leftIndex += 1) {
        for (
            let rightIndex = leftIndex + 1;
            rightIndex < eligible.length;
            rightIndex += 1
        ) {
            const pair = compareCandidatePair(
                contract,
                eligible[leftIndex],
                eligible[rightIndex],
            );
            relationEvidence.push(pair);
            relationMap.set(
                relationKey(pair.left.evidenceId, pair.right.evidenceId),
                pair.relation,
            );
        }
    }
    const frontier = scientificFrontier(eligible, relationMap);
    const uniqueBest = uniqueSupportedBest(eligible, relationMap);
    const tie = uniqueBest === null
        ? supportedTieCohort(frontier, eligible, relationMap)
        : null;
    const unresolved = unresolvedFrontierRelations(
        frontier,
        eligible,
        relationMap,
    );
    const status = eligible.length === 0
        ? "NO_ELIGIBLE_CANDIDATES"
        : uniqueBest !== null
            ? "UNIQUE_BEST"
            : tie !== null
                ? "TIE_COHORT"
                : unresolved.some((item) => item.relation === "INCOMPARABLE")
                    ? "INCOMPARABLE"
                    : "UNRESOLVED";
    const cohort = uniqueBest !== null
        ? [uniqueBest]
        : tie ?? [];
    const relationCore = {
        metricPriority: metricPriority(contract).map((metric) => ({
            key: metric.key,
            priority: metric.priority,
            direction: metric.direction,
            practicalEquivalenceDelta:
                metric.practicalEquivalenceDelta,
        })),
        relations: relationEvidence,
    };
    const relationEvidenceHash = hashCanonical(
        relationCore,
        CANDIDATE_RELATION_EVIDENCE_HASH_ALGORITHM,
    );
    const resolutionPlan = tieResolutionPlan(
        contract,
        frontier,
        eligible,
        relationMap,
        relationEvidence,
    );
    const core = {
        version: CANDIDATE_COHORT_VERSION,
        status,
        resolved: RESOLVED_COHORT_STATES.has(status),
        metricPriority: relationCore.metricPriority,
        candidates: decorated
            .map((item) => candidateSummary(
                item.candidate,
                item.eligibility,
            ))
            .sort(displayOrder),
        eligible: eligible.map(candidateReference),
        frontier: frontier.map(candidateReference),
        cohort: cohort.map(candidateReference),
        provisionalWinner:
            uniqueBest === null ? null : candidateReference(uniqueBest),
        relations: relationEvidence,
        relationEvidenceHash,
        tieResolution: resolutionPlan,
    };
    return immutableCanonical({
        ...core,
        comparisonHash: hashCanonical(
            core,
            CANDIDATE_COHORT_HASH_ALGORITHM,
        ),
    });
}

export function summarizeCandidateCohortComparison(comparison) {
    const decisiveEvidenceIds = new Set([
        ...comparison.frontier.map((candidate) => candidate.evidenceId),
        ...comparison.cohort.map((candidate) => candidate.evidenceId),
    ]);
    const decisiveRelations = comparison.relations.filter((relation) =>
        decisiveEvidenceIds.has(relation.left.evidenceId)
        || decisiveEvidenceIds.has(relation.right.evidenceId));
    return immutableCanonical({
        version: comparison.version,
        status: comparison.status,
        resolved: comparison.resolved,
        metricPriority: comparison.metricPriority,
        candidates: comparison.candidates,
        eligible: comparison.eligible,
        frontier: comparison.frontier,
        cohort: comparison.cohort,
        provisionalWinner: comparison.provisionalWinner,
        decisiveRelations,
        relationEvidenceHash: comparison.relationEvidenceHash,
        tieResolution: comparison.tieResolution,
        comparisonHash: comparison.comparisonHash,
    });
}
