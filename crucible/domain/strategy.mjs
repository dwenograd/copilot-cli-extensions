import { hashCanonical, immutableCanonical } from "./canonical.mjs";
import {
    buildCandidateArchive,
    compareCandidateEvidence,
    metricImprovement,
    selectPromptEvidence,
} from "./archive.mjs";
import {
    ESCAPE_SEARCH_OPERATORS,
    SEARCH_OPERATORS,
} from "./constants.mjs";
import {
    enumerandBinding,
    normalizeEnumerandManifest,
} from "./enumerands.mjs";
import {
    deriveReplicationSchedule,
    deriveReplicationSubjectIdentity,
    statisticalSubjectIndex,
} from "./replication.mjs";
import { replayDerivedCandidateEvidence } from "./scientific-replay.mjs";
import {
    behavioralRoleIdentity,
    replayDerivedCandidateNovelty,
    structuralRoleIdentity,
    supportedBehavioralDifference,
} from "./novelty.mjs";

export const SEARCH_OPERATOR_POLICY_IDENTITY_ALGORITHM =
    "sha256:crucible-search-operator-policy-v1";
export const SEARCH_OPERATOR_ARCHIVE_FINGERPRINT_ALGORITHM =
    "sha256:crucible-search-operator-archive-v1";

function candidateEvidence(aggregate, { includeInvalidated = false } = {}) {
    return aggregate.evidenceOrder
        .map((evidenceId) => aggregate.evidence[evidenceId])
        .filter((evidence) =>
            evidence.sourceKind === "harness"
            && evidence.purpose === "candidate"
            && (includeInvalidated || !evidence.invalidated))
        .map((evidence) =>
            replayDerivedCandidateNovelty(
                aggregate,
                replayDerivedCandidateEvidence(aggregate, evidence),
            ));
}

function expectedSlotsForRound(contract, round) {
    if (contract.enumerandManifest !== undefined) {
        const manifest = normalizeEnumerandManifest(
            contract.enumerandManifest,
            {
                topology: contract.enumerandManifest?.topology
                    ?? contract.hypothesisTopology,
                observableRegistry: contract.observableRegistry,
                hypothesisPolicy: contract.hypothesisPolicy,
            },
        );
        const offset = (round - 1) * contract.candidatesPerRound;
        return Math.max(
            0,
            Math.min(
                contract.candidatesPerRound,
                manifest.entries.length - offset,
            ),
        );
    }
    if (contract.boundedCandidateIds === undefined) {
        return contract.candidatesPerRound;
    }
    const offset = (round - 1) * contract.candidatesPerRound;
    return Math.max(
        0,
        Math.min(
            contract.candidatesPerRound,
            contract.boundedCandidateIds.length - offset,
        ),
    );
}

function completedRoundNumbers(aggregate) {
    const byRound = new Map();
    for (const evidence of candidateEvidence(aggregate)) {
        const slots = byRound.get(evidence.round) ?? new Set();
        slots.add(evidence.slotIndex);
        byRound.set(evidence.round, slots);
    }
    const completed = [];
    for (let round = 1; round <= aggregate.contract.maxRounds; round += 1) {
        const expected = expectedSlotsForRound(aggregate.contract, round);
        if (expected === 0) {
            break;
        }
        const slots = byRound.get(round) ?? new Set();
        if (slots.size !== expected
            || [...slots].some((slot) => slot < 0 || slot >= expected)) {
            break;
        }
        completed.push(round);
    }
    return completed;
}

function passesImprovementThreshold(improvement, threshold) {
    return threshold === 0 ? improvement > 0 : improvement >= threshold;
}

function roundSignalSummaries(aggregate) {
    const contract = aggregate.contract;
    const completed = completedRoundNumbers(aggregate);
    const current = candidateEvidence(aggregate);
    const seenContent = new Set();
    const seenStructural = new Set();
    const priorBehavioral = [];
    let acceptedSeen = false;
    let best = null;
    const summaries = [];

    for (const round of completed) {
        const items = current
            .filter((evidence) => evidence.round === round)
            .sort((left, right) => left.slotIndex - right.slotIndex);
        let metricImproved = false;
        let acceptanceNovelty = false;
        let structuralNovelty = false;
        let behavioralNovelty = false;
        let contentNovelty = false;

        for (const evidence of items) {
            if (evidence.rankable) {
                if (best === null) {
                    metricImproved = contract.metrics.length > 0;
                    best = evidence;
                } else if (compareCandidateEvidence(contract.metrics, evidence, best) < 0) {
                    const improvement = metricImprovement(contract.metrics, evidence, best);
                    if (passesImprovementThreshold(
                        improvement,
                        contract.searchPolicy.plateauMinImprovement,
                    )) {
                        metricImproved = true;
                        best = evidence;
                    }
                }
            }
            if (evidence.outcomeClass === "accepted" && !acceptedSeen) {
                acceptanceNovelty = true;
                acceptedSeen = true;
            }
            const content = evidence.novelty?.content?.signature;
            if (typeof content !== "string" || seenContent.has(content)) continue;
            seenContent.add(content);
            contentNovelty = true;

            const structural =
                evidence.novelty?.structural?.structuralFingerprint;
            if (typeof structural === "string"
                && !seenStructural.has(structural)) {
                seenStructural.add(structural);
                structuralNovelty = true;
            }
            const behavioral = evidence.novelty?.behavioral;
            if (behavioral !== null && behavioral !== undefined) {
                if (priorBehavioral.some((prior) =>
                    supportedBehavioralDifference(behavioral, prior))) {
                    behavioralNovelty = true;
                }
                priorBehavioral.push(behavioral);
            }
        }

        summaries.push({
            round,
            metricImproved,
            acceptanceNovelty,
            structuralNovelty,
            behavioralNovelty,
            contentNovelty,
            improvementOrNovelty: metricImproved
                || acceptanceNovelty
                || structuralNovelty
                || behavioralNovelty
                || contentNovelty,
        });
    }
    return summaries;
}

export function detectPlateau(aggregate) {
    const policy = aggregate.contract.searchPolicy;
    const summaries = roundSignalSummaries(aggregate);
    let stagnantRounds = 0;
    let triggerRound = null;
    let escapeRoundsCompleted = 0;

    for (const summary of summaries) {
        if (summary.improvementOrNovelty) {
            stagnantRounds = 0;
            triggerRound = null;
            escapeRoundsCompleted = 0;
            continue;
        }
        if (triggerRound !== null) {
            escapeRoundsCompleted += 1;
            continue;
        }
        stagnantRounds += 1;
        if (summary.round >= policy.minRoundsBeforePlateau
            && stagnantRounds >= policy.plateauWindow) {
            triggerRound = summary.round;
            escapeRoundsCompleted = 0;
        }
    }

    const plateauDetected = triggerRound !== null;
    const escapeComplete = plateauDetected
        && escapeRoundsCompleted >= policy.mandatoryEscapeRounds;
    return immutableCanonical({
        completedRounds: summaries.length,
        lastCompletedRound: summaries.at(-1)?.round ?? 0,
        plateauDetected,
        triggerRound,
        stagnantRounds,
        escapeRoundsCompleted,
        escapeRoundsRequired: policy.mandatoryEscapeRounds,
        escapeComplete,
        plateauComplete: escapeComplete,
        phase: !plateauDetected
            ? "normal"
            : escapeComplete
                ? "plateau"
                : "mandatory_escape",
        roundSignals: summaries,
    });
}

export const analyzePlateau = detectPlateau;
export const detectSearchPlateau = detectPlateau;

export function deterministicHashInteger(value, modulus = 0x7fffffff) {
    if (!Number.isSafeInteger(modulus) || modulus < 1) {
        throw new RangeError("modulus must be a positive safe integer");
    }
    const digest = hashCanonical(value).split(":").at(-1);
    return Number(BigInt(`0x${digest.slice(0, 16)}`) % BigInt(modulus));
}

export function deterministicSeed(value) {
    return deterministicHashInteger(value, 0x7ffffffe) + 1;
}

export function searchOperatorPolicyIdentity(contract) {
    return hashCanonical({
        version: "crucible-search-operator-policy-v1",
        searchPolicy: contract.searchPolicy,
        statisticalPolicyIdentity:
            contract.statisticalPolicyIdentity ?? null,
        structuralRoleIdentity: structuralRoleIdentity(contract),
        behavioralRoleIdentity: behavioralRoleIdentity(contract),
    }, SEARCH_OPERATOR_POLICY_IDENTITY_ALGORITHM);
}

function exactNoveltySignature(value, domain) {
    return typeof value === "string"
        && value.startsWith(`${domain}:`)
        && value.length === domain.length + 65
        && /^[a-f0-9]{64}$/u.test(value.slice(-64));
}

function archivePolicyFingerprint(archive) {
    const candidates = [
        archive.incumbent,
        ...(archive.accepted ?? []),
        ...(archive.nearMisses ?? []),
        ...(archive.rejected ?? []),
        ...(archive.inconclusive ?? []),
        ...(archive.invalidMetrics ?? []),
    ].filter((candidate) =>
        candidate !== null
        && candidate !== undefined
        && candidate.invalidated !== true);
    const byId = new Map(
        candidates
            .filter((candidate) => typeof candidate.evidenceId === "string")
            .map((candidate) => [candidate.evidenceId, candidate]),
    );
    const artifactHashes = [...new Set(candidates
        .map((candidate) => candidate.receipt?.candidateArtifactHash)
        .filter((value) => typeof value === "string"))]
        .sort();
    const structuralSignatures = [...new Set(
        (archive.noveltyNiches?.structural ?? [])
            .map((niche) => niche.signature)
            .filter((value) => exactNoveltySignature(
                value,
                "sha256:crucible-novelty-structural-v1",
            )),
    )].sort();
    const behavioralGroups = archive.noveltyNiches?.behavioral ?? [];
    const behavioralNiches = (behavioralGroups.length > 1
        ? behavioralGroups
        : [])
        .filter((niche) => exactNoveltySignature(
            niche.signature,
            "sha256:crucible-behavioral-novelty-v1",
        ))
        .map((niche) => ({
            artifactHashes: [...new Set(
                (niche.evidenceIds ?? [])
                    .map((evidenceId) =>
                        byId.get(evidenceId)
                            ?.receipt?.candidateArtifactHash ?? null)
                    .filter((value) => typeof value === "string"),
            )].sort(),
        }))
        .filter((niche) => niche.artifactHashes.length > 0)
        .sort((left, right) => {
            const leftKey = left.artifactHashes.join("\0");
            const rightKey = right.artifactHashes.join("\0");
            return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
        });
    return hashCanonical({
        version: "crucible-search-operator-archive-v1",
        artifactHashes,
        structuralSignatures,
        behavioralNiches,
    }, SEARCH_OPERATOR_ARCHIVE_FINGERPRINT_ALGORITHM);
}

function deterministicStrategyError(message) {
    const error = new Error(`Deterministic strategy error: ${message}`);
    error.name = "DeterministicStrategyError";
    return error;
}

function configuredOperatorWeight(searchPolicy, operator) {
    const weight = searchPolicy.operatorWeights[operator];
    return Number.isSafeInteger(weight) && weight > 0 ? weight : 0;
}

function selectWeightedOperator(weights, entropy, emptyReason) {
    const total = SEARCH_OPERATORS.reduce(
        (sum, operator) => sum + (weights[operator] > 0 ? weights[operator] : 0),
        0,
    );
    if (total < 1) {
        throw deterministicStrategyError(emptyReason);
    }
    let selected = deterministicHashInteger(entropy, total);
    for (const operator of SEARCH_OPERATORS) {
        const weight = weights[operator] > 0 ? weights[operator] : 0;
        if (selected < weight) {
            return operator;
        }
        selected -= weight;
    }
    throw deterministicStrategyError("weighted operator selection exhausted unexpectedly");
}

export function adaptiveOperatorWeights(searchPolicy, archive, phase = "normal") {
    const weights = Object.fromEntries(
        SEARCH_OPERATORS.map((operator) => [
            operator,
            configuredOperatorWeight(searchPolicy, operator),
        ]),
    );
    const promptContextRefs = selectPromptEvidence(archive, searchPolicy);
    const parentCap = searchPolicy.promptCaps.parentEvidenceIds;
    const refinementParents = parentEvidenceIds(
        archive,
        promptContextRefs,
        "refinement",
        parentCap,
    );
    const crossoverParents = parentEvidenceIds(
        archive,
        promptContextRefs,
        "crossover",
        parentCap,
    );
    const adversarialParents = parentEvidenceIds(
        archive,
        promptContextRefs,
        "adversarial",
        parentCap,
    );
    const visibleIds = new Set(promptContextRefs);
    const refinementPool = distinctParentCandidates({
        incumbent: archive.incumbent,
        nearMisses: archive.nearMisses,
        accepted: [],
    }).filter((candidate) => visibleIds.has(candidate.evidenceId));

    if (refinementParents.length !== 1) {
        weights.refinement = 0;
    } else if (weights.refinement > 0) {
        weights.refinement += refinementPool.length;
    }
    const structuralNicheCount =
        archive.noveltyNiches?.structural?.length ?? 0;
    const behavioralDifferenceCount = Math.max(
        0,
        (archive.noveltyNiches?.behavioral?.length ?? 0) - 1,
    );
    const trustedNicheCount =
        structuralNicheCount + behavioralDifferenceCount;
    if (crossoverParents.length !== 2) {
        weights.crossover = 0;
    } else if (weights.crossover > 0) {
        weights.crossover += Math.min(trustedNicheCount, 8);
    }
    if (weights.diversification > 0 && trustedNicheCount < 2) {
        weights.diversification += 1;
    }
    if (adversarialParents.length !== 1) {
        weights.adversarial = 0;
    }
    if (phase !== "normal") {
        for (const operator of SEARCH_OPERATORS) {
            if (!ESCAPE_SEARCH_OPERATORS.includes(operator)) {
                weights[operator] = 0;
            }
        }
        if (weights.restart > 0) {
            weights.restart += 1;
        }
        if (weights.adversarial > 0) {
            weights.adversarial += 1;
        }
        if (weights.diversification > 0 && trustedNicheCount === 0) {
            weights.diversification += 1;
        }
    }
    return immutableCanonical(weights);
}

export function selectAdaptiveOperator({
    searchPolicy,
    archive,
    contractHash,
    policyIdentity = contractHash,
    round,
    slotIndex,
    phase = "normal",
}) {
    if (phase === "normal"
        && archive.incumbent === null
        && archive.nearMisses.length === 0
        && archive.accepted.length === 0
        && archive.rejected.length === 0
        && archive.invalidMetrics.length === 0
        && configuredOperatorWeight(searchPolicy, "fresh") > 0) {
        return "fresh";
    }
    const weights = adaptiveOperatorWeights(searchPolicy, archive, phase);
    return selectWeightedOperator(weights, {
        policyIdentity,
        archiveFingerprint: archivePolicyFingerprint(archive),
        round,
        slotIndex,
        phase,
        weights,
    }, `no positive-weight eligible operators for phase "${phase}"`);
}

export const selectOperator = selectAdaptiveOperator;
export const assignSearchOperator = selectAdaptiveOperator;

function eligibleParentCandidate(candidate) {
    return candidate !== null
        && candidate !== undefined
        && candidate.invalidated !== true
        && typeof candidate.evidenceId === "string"
        && candidate.evidenceId.length > 0;
}

function parentLineageRoot(candidate, candidateById) {
    let rootId = candidate.evidenceId;
    let duplicateOf = candidate.duplicateOf;
    const visited = new Set([rootId]);
    while (typeof duplicateOf === "string"
        && duplicateOf.length > 0
        && !visited.has(duplicateOf)) {
        rootId = duplicateOf;
        visited.add(duplicateOf);
        duplicateOf = candidateById.get(duplicateOf)?.duplicateOf;
    }
    return rootId;
}

function distinctParentCandidates(archive) {
    const candidateById = new Map();
    const uniqueIds = [];
    for (const candidate of [
        archive.incumbent,
        ...(archive.nearMisses ?? []),
        ...(archive.accepted ?? []),
    ]) {
        if (!eligibleParentCandidate(candidate)
            || candidateById.has(candidate.evidenceId)) {
            continue;
        }
        candidateById.set(candidate.evidenceId, candidate);
        uniqueIds.push(candidate);
    }

    const seenGroups = new Set();
    return uniqueIds.filter((candidate) => {
        const artifactHash = candidate.receipt?.candidateArtifactHash;
        const groupKey = typeof artifactHash === "string" && artifactHash.length > 0
            ? `artifact:${artifactHash}`
            : `lineage:${parentLineageRoot(candidate, candidateById)}`;
        if (seenGroups.has(groupKey)) {
            return false;
        }
        seenGroups.add(groupKey);
        return true;
    }).sort((left, right) => {
        const leftHash = left.receipt?.candidateArtifactHash ?? "";
        const rightHash = right.receipt?.candidateArtifactHash ?? "";
        if (leftHash !== rightHash) return leftHash < rightHash ? -1 : 1;
        return left.evidenceId < right.evidenceId
            ? -1
            : left.evidenceId > right.evidenceId
                ? 1
                : 0;
    });
}

function eligibleIncumbent(archive) {
    return eligibleParentCandidate(archive.incumbent)
        ? archive.incumbent
        : null;
}

function preferredCrossoverParents(_archive, visible) {
    for (let firstIndex = 0; firstIndex < visible.length - 1; firstIndex += 1) {
        const first = visible[firstIndex];
        const firstStructural =
            first.novelty?.structural?.structuralFingerprint ?? null;
        if (firstStructural === null) continue;
        for (let secondIndex = firstIndex + 1; secondIndex < visible.length; secondIndex += 1) {
            const secondStructural =
                visible[secondIndex].novelty?.structural?.structuralFingerprint
                ?? null;
            if (secondStructural !== null
                && secondStructural !== firstStructural) {
                return [first, visible[secondIndex]];
            }
        }
    }
    for (let firstIndex = 0; firstIndex < visible.length - 1; firstIndex += 1) {
        for (let secondIndex = firstIndex + 1; secondIndex < visible.length; secondIndex += 1) {
            if (supportedBehavioralDifference(
                visible[firstIndex].novelty?.behavioral,
                visible[secondIndex].novelty?.behavioral,
            )) {
                return [visible[firstIndex], visible[secondIndex]];
            }
        }
    }
    return visible.slice(0, 2);
}

function parentEvidenceIds(archive, promptContextRefs, operator, cap) {
    if (operator === "fresh" || operator === "restart") {
        return [];
    }
    if (operator === "adversarial") {
        const incumbentId = eligibleIncumbent(archive)?.evidenceId ?? null;
        return incumbentId !== null && cap >= 1 && promptContextRefs.includes(incumbentId)
            ? [incumbentId]
            : [];
    }
    const visible = distinctParentCandidates(archive)
        .filter((candidate) => promptContextRefs.includes(candidate.evidenceId));
    if (operator !== "crossover") {
        return visible.slice(0, Math.min(1, cap)).map((candidate) => candidate.evidenceId);
    }
    if (visible.length < 2 || cap < 2) {
        return [];
    }
    return preferredCrossoverParents(archive, visible)
        .map((candidate) => candidate.evidenceId);
}

function parentRequirementSatisfied(archive, operator, parents) {
    if (operator === "adversarial") {
        const incumbentId = eligibleIncumbent(archive)?.evidenceId ?? null;
        return parents.length === 1 && parents[0] === incumbentId;
    }
    if (operator === "refinement") {
        return parents.length === 1;
    }
    if (operator === "crossover") {
        return parents.length === 2 && new Set(parents).size === 2;
    }
    return true;
}

function fallbackOperator({
    searchPolicy,
    archive,
    promptContextRefs,
    policyIdentity,
    round,
    slotIndex,
    phase,
    failedOperator,
}) {
    const weights = { ...adaptiveOperatorWeights(searchPolicy, archive, phase) };
    weights[failedOperator] = 0;
    for (const operator of SEARCH_OPERATORS) {
        const parents = parentEvidenceIds(
            archive,
            promptContextRefs,
            operator,
            searchPolicy.promptCaps.parentEvidenceIds,
        );
        if (!parentRequirementSatisfied(archive, operator, parents)) {
            weights[operator] = 0;
        }
    }

    const preferredFallbacks = phase === "normal"
        ? ["fresh", "restart"]
        : ["restart"];
    for (const operator of preferredFallbacks) {
        if (weights[operator] > 0) {
            return operator;
        }
    }
    return selectWeightedOperator(weights, {
        policyIdentity,
        archiveFingerprint: archivePolicyFingerprint(archive),
        round,
        slotIndex,
        phase,
        failedOperator,
        weights,
    }, `no positive-weight eligible fallback after "${failedOperator}" for phase "${phase}"`);
}

function generatedCandidateId(round, slotIndex, replacementOrdinal = 0) {
    const base = `candidate-r${String(round).padStart(6, "0")}-s${String(slotIndex).padStart(3, "0")}`;
    return replacementOrdinal === 0
        ? base
        : `${base}-retry-${String(replacementOrdinal).padStart(3, "0")}`;
}

function replacementOrdinal(aggregate, round, slotIndex) {
    return candidateEvidence(aggregate, { includeInvalidated: true })
        .filter((evidence) =>
            evidence.invalidated
            && evidence.round === round
            && evidence.slotIndex === slotIndex)
        .length;
}

export function buildSearchCandidateCommand(aggregate, progress) {
    if (progress.nextRound === null || progress.nextSlot === null) {
        return null;
    }
    const contract = aggregate.contract;
    const policy = contract.searchPolicy;
    const policyIdentity = searchOperatorPolicyIdentity(contract);
    const archive = buildCandidateArchive(aggregate);
    const plateau = detectPlateau(aggregate);
    const round = progress.nextRound;
    const slotIndex = progress.nextSlot;
    const globalSlot = (round - 1) * contract.candidatesPerRound + slotIndex;
    const manifest = contract.enumerandManifest === undefined
        ? null
        : normalizeEnumerandManifest(
            contract.enumerandManifest,
            {
                topology: contract.enumerandManifest?.topology
                    ?? contract.hypothesisTopology,
                observableRegistry: contract.observableRegistry,
                hypothesisPolicy: contract.hypothesisPolicy,
            },
        );
    const assignedEnumerand = manifest?.entries[globalSlot] ?? null;
    if (manifest !== null && assignedEnumerand === null) {
        throw deterministicStrategyError(
            `search slot ${globalSlot} is outside the frozen enumerand manifest`,
        );
    }
    const boundedCandidateId = assignedEnumerand?.id
        ?? contract.boundedCandidateIds?.[globalSlot]
        ?? null;
    const replacement = replacementOrdinal(aggregate, round, slotIndex);
    const candidateId = boundedCandidateId
        ?? generatedCandidateId(round, slotIndex, replacement);
    const model = contract.workerModels[globalSlot % contract.workerModels.length];
    let operator = selectAdaptiveOperator({
        searchPolicy: policy,
        archive,
        policyIdentity,
        round,
        slotIndex,
        phase: plateau.phase,
    });
    const promptContextRefs = selectPromptEvidence(archive, policy);
    let parents = parentEvidenceIds(
        archive,
        promptContextRefs,
        operator,
        policy.promptCaps.parentEvidenceIds,
    );
    if (!parentRequirementSatisfied(archive, operator, parents)) {
        operator = fallbackOperator({
            searchPolicy: policy,
            archive,
            promptContextRefs,
            policyIdentity,
            round,
            slotIndex,
            phase: plateau.phase,
            failedOperator: operator,
        });
        parents = parentEvidenceIds(
            archive,
            promptContextRefs,
            operator,
            policy.promptCaps.parentEvidenceIds,
        );
    }
    if (configuredOperatorWeight(policy, operator) < 1) {
        throw deterministicStrategyError(
            `selected operator "${operator}" has zero configured weight`,
        );
    }
    if (!parentRequirementSatisfied(archive, operator, parents)) {
        throw deterministicStrategyError(
            `operator "${operator}" lacks eligible parent evidence`,
        );
    }
    const seed = deterministicSeed({
        contractHash: aggregate.contractHash,
        round,
        slotIndex,
        candidateId,
        model,
        operator,
        parentEvidenceIds: parents,
        promptContextRefs,
        replacementOrdinal: replacement,
        enumerandHash: assignedEnumerand?.enumerandHash ?? null,
    });
    const replicationSchedule = deriveReplicationSchedule({
        contractHash: aggregate.contractHash,
        statisticalPolicy: contract.statisticalPolicy,
        subject: {
            kind: assignedEnumerand === null ? "candidate" : "enumerand",
            index: statisticalSubjectIndex(
                assignedEnumerand === null ? "candidate" : "enumerand",
                globalSlot,
            ),
            id: candidateId,
            identity: deriveReplicationSubjectIdentity({
                contractHash: aggregate.contractHash,
                candidateId,
                candidateSeed: seed,
                enumerandHash: assignedEnumerand?.enumerandHash ?? null,
            }),
        },
    });

    const harnessId =
        contract.harnessSuite?.roles?.search?.harnessId
        ?? contract.harnessId;
    const parserVersion =
        contract.harnessSuite?.roles?.search?.parser?.version
        ?? contract.parserVersion;
    return immutableCanonical({
        kind: "search_candidate",
        ...(harnessId === undefined || parserVersion === undefined
            ? {}
            : {
                harnessRole: "search",
                harnessId,
                parserVersion,
            }),
        round,
        slotIndex,
        candidateId,
        model,
        operator,
        parentEvidenceIds: parents,
        promptContextRefs,
        seed,
        hypotheses: assignedEnumerand?.hypotheses ?? null,
        replicationSchedule,
        replacementOrdinal: replacement,
        ...(boundedCandidateId === null ? {} : { boundedCandidateId }),
        ...(assignedEnumerand === null
            ? {}
            : {
                enumerand: enumerandBinding(manifest, assignedEnumerand, {
                    topology: contract.enumerandManifest?.topology
                        ?? contract.hypothesisTopology,
                    observableRegistry: contract.observableRegistry,
                    hypothesisPolicy: contract.hypothesisPolicy,
                }),
            }),
    });
}

export const deriveSearchCandidateCommand = buildSearchCandidateCommand;
export const createSearchCandidateCommand = buildSearchCandidateCommand;
