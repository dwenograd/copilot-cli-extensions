import { immutableCanonical } from "./canonical.mjs";
import {
    acceptanceSatisfied,
    assessAcceptancePredicate,
    candidateMetricValues,
    candidateMetricsRankable,
} from "./contract.mjs";
import { replayDerivedCandidateEvidence } from "./scientific-replay.mjs";
import {
    replayDerivedCandidateNovelty,
    supportedBehavioralDifference,
} from "./novelty.mjs";

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

// Exact IEEE-754 parts keep epsilon bucket ordering finite and stable across runtimes.
function finiteDoubleParts(value) {
    if (value === 0) {
        return { coefficient: 0n, exponent: 0 };
    }
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, value, false);
    const high = view.getUint32(0, false);
    const low = view.getUint32(4, false);
    const exponentBits = (high >>> 20) & 0x7ff;
    const fraction = (BigInt(high & 0x000fffff) << 32n) | BigInt(low);
    const magnitude = exponentBits === 0
        ? fraction
        : (1n << 52n) | fraction;
    return {
        coefficient: (high & 0x80000000) === 0 ? magnitude : -magnitude,
        exponent: exponentBits === 0 ? -1074 : exponentBits - 1023 - 52,
    };
}

function epsilonBucket(value, epsilon) {
    const valueParts = finiteDoubleParts(value);
    if (valueParts.coefficient === 0n) {
        return 0n;
    }
    const epsilonParts = finiteDoubleParts(epsilon);
    let numerator = valueParts.coefficient;
    let denominator = epsilonParts.coefficient;
    const exponentDifference = valueParts.exponent - epsilonParts.exponent;
    if (exponentDifference > 0) {
        numerator <<= BigInt(exponentDifference);
    } else if (exponentDifference < 0) {
        denominator <<= BigInt(-exponentDifference);
    }

    const negative = numerator < 0n;
    const magnitude = negative ? -numerator : numerator;
    let quotient = magnitude / denominator;
    const doubledRemainder = (magnitude % denominator) << 1n;
    if ((!negative && doubledRemainder >= denominator)
        || (negative && doubledRemainder > denominator)) {
        quotient += 1n;
    }
    return negative ? -quotient : quotient;
}

function compareMetricValues(left, right, epsilon) {
    if (left === right) {
        return 0;
    }
    if (epsilon > 0) {
        const leftBucket = epsilonBucket(left, epsilon);
        const rightBucket = epsilonBucket(right, epsilon);
        if (leftBucket === rightBucket) {
            return 0;
        }
        return leftBucket < rightBucket ? -1 : 1;
    }
    return left < right ? -1 : 1;
}

export function compareCandidateEvidence(metrics, left, right) {
    if (left.rankable === true && right.rankable === false) {
        return -1;
    }
    if (left.rankable === false && right.rankable === true) {
        return 1;
    }
    for (const metric of metrics) {
        const epsilon = metric.epsilon > 0 ? metric.epsilon : 0;
        const leftValue = left.metrics?.[metric.key];
        const rightValue = right.metrics?.[metric.key];
        const leftValid = typeof leftValue === "number" && Number.isFinite(leftValue);
        const rightValid = typeof rightValue === "number" && Number.isFinite(rightValue);
        if (leftValid !== rightValid) {
            return leftValid ? -1 : 1;
        }
        if (!leftValid) {
            continue;
        }
        const comparison = compareMetricValues(leftValue, rightValue, epsilon);
        if (comparison === 0) {
            continue;
        }
        return metric.direction === "min"
            ? comparison
            : -comparison;
    }
    const leftArtifact = artifactHashOf(left);
    const rightArtifact = artifactHashOf(right);
    if (typeof leftArtifact === "string"
        && typeof rightArtifact === "string"
        && leftArtifact !== rightArtifact) {
        return leftArtifact < rightArtifact ? -1 : 1;
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
    if (accepted) {
        return "accepted";
    }
    if (!rankable) {
        return "invalid_metrics";
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
    const ordered = selectPrimaryEvidence(candidateEvidence);
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
    return selectPrimaryEvidence(candidateEvidence)
        .filter((evidence) => evidence.outcomeClass === "accepted")
        .sort((left, right) => compareCandidateEvidence(contract.metrics, left, right))[0] ?? null;
}

function duplicateLineageRoot(evidence, evidenceById) {
    let rootId = evidence.evidenceId;
    let duplicateOf = evidence.duplicateOf;
    const visited = new Set([rootId]);
    while (typeof duplicateOf === "string"
        && duplicateOf.length > 0
        && !visited.has(duplicateOf)) {
        rootId = duplicateOf;
        visited.add(duplicateOf);
        duplicateOf = evidenceById.get(duplicateOf)?.duplicateOf;
    }
    return rootId;
}

function selectPrimaryEvidence(candidates) {
    const ordered = [...candidates]
        .filter((candidate) => !candidate.invalidated)
        .sort(evidenceOrder);
    const evidenceById = new Map(
        ordered.map((candidate) => [candidate.evidenceId, candidate]),
    );
    const seenGroups = new Set();
    return ordered.filter((candidate) => {
        const artifactHash = artifactHashOf(candidate);
        const groupKey = artifactHash === null
            ? `lineage:${duplicateLineageRoot(candidate, evidenceById)}`
            : `artifact:${artifactHash}`;
        if (seenGroups.has(groupKey)) {
            return false;
        }
        seenGroups.add(groupKey);
        return true;
    });
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
            && evidence.purpose === "candidate")
        .map((evidence) =>
            replayDerivedCandidateNovelty(
                aggregate,
                replayDerivedCandidateEvidence(aggregate, evidence),
            ));
    const primary = selectPrimaryEvidence(allCandidates);
    const comparator = (left, right) =>
        compareCandidateEvidence(contract.metrics, left, right);
    const accepted = boundedSelect(
        primary.filter((item) => item.outcomeClass === "accepted"),
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
    const inconclusive = boundedSelect(
        primary.filter((item) => item.outcomeClass === "inconclusive"),
        caps.inconclusive,
        comparator,
    );
    const invalidMetrics = boundedSelect(
        primary.filter((item) => item.outcomeClass === "invalid_metrics"),
        caps.invalidMetrics,
        evidenceOrder,
    );
    const noveltyNiches = {
        content: signatureNiches(
            primary,
            (item) => item.novelty?.content?.signature,
            caps.duplicateIndex,
            caps.nearMisses,
        ),
        structural: signatureNiches(
            primary,
            (item) => item.novelty?.structural?.structuralFingerprint,
            caps.mechanismGroups,
            caps.nearMisses,
        ),
        behavioral: behavioralNiches(
            primary,
            caps.lessonGroups,
            caps.nearMisses,
        ),
    };

    return immutableCanonical({
        accepted,
        nearMisses,
        rejected,
        inconclusive,
        invalidMetrics,
        noveltyNiches,
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
        duplicateIndex: buildDuplicateIndex(primary, caps.duplicateIndex),
        incumbent: selectIncumbent(contract, primary),
    });
}

function isAlgorithmTaggedSignature(value) {
    return typeof value === "string"
        && /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u.test(value);
}

function signatureNiches(candidates, selector, cap, memberCap) {
    const groups = new Map();
    for (const evidence of [...candidates].sort((left, right) => {
        const leftArtifact = artifactHashOf(left) ?? "";
        const rightArtifact = artifactHashOf(right) ?? "";
        if (leftArtifact !== rightArtifact) {
            return leftArtifact < rightArtifact ? -1 : 1;
        }
        return evidenceOrder(left, right);
    })) {
        const signature = selector(evidence);
        if (!isAlgorithmTaggedSignature(signature)) continue;
        const existing = groups.get(signature) ?? [];
        if (existing.length < memberCap) existing.push(evidence.evidenceId);
        groups.set(signature, existing);
    }
    return [...groups.entries()]
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .slice(0, cap)
        .map(([signature, evidenceIds]) => ({
            signature,
            representativeEvidenceId: evidenceIds[0],
            evidenceIds,
        }));
}

function behavioralNiches(candidates, cap, memberCap) {
    const groups = [];
    const ordered = [...candidates].sort((left, right) => {
        const leftArtifact = artifactHashOf(left) ?? "";
        const rightArtifact = artifactHashOf(right) ?? "";
        if (leftArtifact !== rightArtifact) {
            return leftArtifact < rightArtifact ? -1 : 1;
        }
        return evidenceOrder(left, right);
    });
    for (const evidence of ordered) {
        const behavioral = evidence.novelty?.behavioral;
        if (!isAlgorithmTaggedSignature(behavioral?.signature)
            || !Array.isArray(behavioral?.claims)
            || behavioral.claims.length === 0) {
            continue;
        }
        const group = groups.find((candidateGroup) =>
            candidateGroup.members.every((member) =>
                !supportedBehavioralDifference(behavioral, member.behavioral)));
        if (group === undefined) {
            groups.push({
                signature: behavioral.signature,
                representativeEvidenceId: evidence.evidenceId,
                evidenceIds: [evidence.evidenceId],
                members: [{ behavioral }],
            });
            continue;
        }
        group.members.push({ behavioral });
        if (group.evidenceIds.length < memberCap) {
            group.evidenceIds.push(evidence.evidenceId);
        }
    }
    return groups.slice(0, cap).map((group) => ({
        signature: group.signature,
        representativeEvidenceId: group.representativeEvidenceId,
        evidenceIds: group.evidenceIds,
    }));
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
    const policyNiches = [
        ...(archive.noveltyNiches?.structural ?? []),
        ...((archive.noveltyNiches?.behavioral?.length ?? 0) > 1
            ? archive.noveltyNiches.behavioral
            : []),
        ...(archive.noveltyNiches?.content ?? []),
    ];
    for (const group of policyNiches) {
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
