import { immutableCanonical } from "./canonical.mjs";
import {
    acceptanceSatisfied,
    assessAcceptancePredicate,
    candidateMetricValues,
    candidateMetricsRankable,
} from "./contract.mjs";

function evidenceOrder(left, right) {
    const leftSeq = Number.isSafeInteger(left.committedSeq)
        ? left.committedSeq
        : Number.MAX_SAFE_INTEGER;
    const rightSeq = Number.isSafeInteger(right.committedSeq)
        ? right.committedSeq
        : Number.MAX_SAFE_INTEGER;
    if (leftSeq !== rightSeq) {
        return leftSeq - rightSeq;
    }
    const leftId = left.evidenceId ?? left.candidateId ?? "";
    const rightId = right.evidenceId ?? right.candidateId ?? "";
    return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
}

export function compareCandidateEvidence(metrics, left, right) {
    for (const metric of metrics) {
        const epsilon = metric.epsilon > 0 ? metric.epsilon : 0;
        let leftValue = left.metrics?.[metric.key];
        let rightValue = right.metrics?.[metric.key];
        const leftValid = typeof leftValue === "number" && Number.isFinite(leftValue);
        const rightValid = typeof rightValue === "number" && Number.isFinite(rightValue);
        if (leftValid !== rightValid) {
            return leftValid ? -1 : 1;
        }
        if (!leftValid) {
            continue;
        }
        if (epsilon > 0) {
            leftValue = Math.round(leftValue / epsilon);
            rightValue = Math.round(rightValue / epsilon);
        }
        if (leftValue === rightValue) {
            continue;
        }
        return metric.direction === "min"
            ? leftValue - rightValue
            : rightValue - leftValue;
    }
    return evidenceOrder(left, right);
}

export function metricImprovement(metrics, candidate, incumbent) {
    if (incumbent === null || incumbent === undefined || metrics.length === 0) {
        return 0;
    }
    for (const metric of metrics) {
        const candidateValue = candidate.metrics?.[metric.key];
        const incumbentValue = incumbent.metrics?.[metric.key];
        if (typeof candidateValue !== "number"
            || !Number.isFinite(candidateValue)
            || typeof incumbentValue !== "number"
            || !Number.isFinite(incumbentValue)) {
            return 0;
        }
        const signed = metric.direction === "min"
            ? incumbentValue - candidateValue
            : candidateValue - incumbentValue;
        if (Math.abs(signed) <= metric.epsilon) {
            continue;
        }
        return signed > 0 ? signed : 0;
    }
    return 0;
}

function bestRankable(contract, candidates) {
    return candidates
        .filter((candidate) => candidate.rankable === true)
        .sort((left, right) => compareCandidateEvidence(contract.metrics, left, right))[0] ?? null;
}

export function classifyCandidateOutcome(
    contract,
    harnessResult,
    {
        metrics = candidateMetricValues(contract.metrics, harnessResult),
        rankable = candidateMetricsRankable(contract.metrics, metrics),
        accepted = acceptanceSatisfied(contract.acceptancePredicate, harnessResult),
        priorCandidates = [],
    } = {},
) {
    if (!rankable) {
        return "invalid_metrics";
    }
    if (accepted) {
        return "accepted";
    }

    const predicateAssessment = assessAcceptancePredicate(
        contract.acceptancePredicate,
        harnessResult,
    );
    if (predicateAssessment.near) {
        return "near_miss";
    }

    const candidate = { metrics, rankable: true };
    const previousBest = bestRankable(contract, priorCandidates);
    if (previousBest !== null
        && compareCandidateEvidence(contract.metrics, candidate, previousBest) < 0
        && metricImprovement(contract.metrics, candidate, previousBest)
            >= contract.searchPolicy.plateauMinImprovement) {
        return "near_miss";
    }
    return "rejected";
}

export function boundedSelect(items, cap, comparator = evidenceOrder) {
    return [...items].sort(comparator).slice(0, cap);
}

function artifactHashOf(evidence) {
    return evidence.receipt?.candidateArtifactHash ?? null;
}

export function buildDuplicateIndex(candidateEvidence, cap = Number.MAX_SAFE_INTEGER) {
    const index = {};
    let size = 0;
    const ordered = [...candidateEvidence].sort(evidenceOrder);
    for (const evidence of ordered) {
        const artifactHash = artifactHashOf(evidence);
        if (artifactHash === null || Object.hasOwn(index, artifactHash)) {
            continue;
        }
        if (size >= cap) {
            break;
        }
        index[artifactHash] = evidence.evidenceId;
        size += 1;
    }
    return immutableCanonical(index);
}

export function duplicateEvidenceId(candidateEvidence, candidateArtifactHash) {
    if (candidateArtifactHash === null || candidateArtifactHash === undefined) {
        return null;
    }
    const ordered = [...candidateEvidence].sort(evidenceOrder);
    return ordered.find((evidence) =>
        artifactHashOf(evidence) === candidateArtifactHash)?.evidenceId ?? null;
}

export function selectIncumbent(contract, candidateEvidence) {
    return selectPrimaryEvidence(candidateEvidence
        .filter((evidence) =>
            !evidence.invalidated
            && evidence.rankable === true
            && evidence.outcomeClass === "accepted"))
        .sort((left, right) => compareCandidateEvidence(contract.metrics, left, right))[0] ?? null;
}

function selectPrimaryEvidence(candidates) {
    const activeIds = new Set(candidates.map((candidate) => candidate.evidenceId));
    return candidates.filter((candidate) =>
        candidate.duplicateOf === null
        || candidate.duplicateOf === undefined
        || !activeIds.has(candidate.duplicateOf));
}

function groupAnnotations(candidates, field, outputField, cap, memberCap) {
    const groups = new Map();
    for (const evidence of [...candidates].sort(evidenceOrder)) {
        const value = evidence.annotations?.[field];
        if (typeof value !== "string" || value.length === 0) {
            continue;
        }
        const existing = groups.get(value) ?? [];
        if (existing.length < memberCap) {
            existing.push(evidence.evidenceId);
        }
        groups.set(value, existing);
    }
    return [...groups.entries()]
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .slice(0, cap)
        .map(([value, evidenceIds]) => ({
            [outputField]: value,
            representativeEvidenceId: evidenceIds[0],
            evidenceIds,
        }));
}

export function buildCandidateArchive(aggregate) {
    const contract = aggregate.contract;
    const caps = contract.searchPolicy.archiveCaps;
    const allCandidates = aggregate.evidenceOrder
        .map((evidenceId) => aggregate.evidence[evidenceId])
        .filter((evidence) =>
            evidence.sourceKind === "harness"
            && evidence.purpose === "candidate");
    const candidates = allCandidates.filter((evidence) => !evidence.invalidated);
    const primary = selectPrimaryEvidence(candidates);
    const comparator = (left, right) =>
        compareCandidateEvidence(contract.metrics, left, right);
    const accepted = boundedSelect(
        primary.filter((item) => item.outcomeClass === "accepted" && item.rankable),
        caps.accepted,
        comparator,
    );
    const nearMisses = boundedSelect(
        primary.filter((item) => item.outcomeClass === "near_miss" && item.rankable),
        caps.nearMisses,
        comparator,
    );
    const rejected = boundedSelect(
        primary.filter((item) => item.outcomeClass === "rejected"),
        caps.rejected,
        comparator,
    );
    const invalidMetrics = boundedSelect(
        primary.filter((item) => item.outcomeClass === "invalid_metrics"),
        caps.invalidMetrics,
        evidenceOrder,
    );

    return immutableCanonical({
        accepted,
        nearMisses,
        rejected,
        invalidMetrics,
        mechanismGroups: groupAnnotations(
            primary,
            "mechanism",
            "mechanism",
            caps.mechanismGroups,
            caps.nearMisses,
        ),
        lessonGroups: groupAnnotations(
            primary,
            "finding",
            "finding",
            caps.lessonGroups,
            caps.rejected,
        ),
        duplicateIndex: buildDuplicateIndex(allCandidates, caps.duplicateIndex),
        incumbent: selectIncumbent(contract, candidates),
    });
}

export const createCandidateArchive = buildCandidateArchive;
export const buildArchive = buildCandidateArchive;
export const classifyOutcome = classifyCandidateOutcome;

function addUnique(target, seen, value, cap) {
    if (value === null || value === undefined || seen.has(value) || target.length >= cap) {
        return;
    }
    seen.add(value);
    target.push(value);
}

export function selectPromptEvidence(archive, searchPolicy) {
    const cap = searchPolicy.promptCaps.promptContextRefs;
    const refs = [];
    const seen = new Set();
    addUnique(refs, seen, archive.incumbent?.evidenceId, cap);
    for (const evidence of archive.nearMisses) {
        addUnique(refs, seen, evidence.evidenceId, cap);
    }
    for (const group of archive.mechanismGroups) {
        addUnique(refs, seen, group.representativeEvidenceId, cap);
    }
    for (const group of archive.lessonGroups) {
        addUnique(refs, seen, group.representativeEvidenceId, cap);
    }
    for (const evidence of archive.accepted) {
        addUnique(refs, seen, evidence.evidenceId, cap);
    }
    for (const evidence of archive.rejected) {
        addUnique(refs, seen, evidence.evidenceId, cap);
    }
    return immutableCanonical(refs);
}

export const selectArchive = buildCandidateArchive;
