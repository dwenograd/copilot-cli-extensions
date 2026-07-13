import {
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    deriveCandidateCohortComparison,
    summarizeCandidateCohortComparison,
} from "./cohort.mjs";
import { deriveScientificConfirmationState } from "./confirmation.mjs";

export const SCIENTIFIC_REPLAY_VERSION =
    "crucible-scientific-replay-v1";
export const SCIENTIFIC_RAW_AUTHORITY_HASH_ALGORITHM =
    "sha256:crucible-scientific-raw-authority-v1";
export const SCIENTIFIC_AGGREGATE_HASH_ALGORITHM =
    "sha256:crucible-scientific-aggregate-v1";
export const SCIENTIFIC_CLAIM_STATES_HASH_ALGORITHM =
    "sha256:crucible-scientific-claim-states-v1";
export const SCIENTIFIC_ALPHA_LEDGER_HASH_ALGORITHM =
    "sha256:crucible-scientific-alpha-ledger-v1";
export const SCIENTIFIC_REPLAY_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-scientific-replay-closure-v1";
export const SCIENTIFIC_CONCLUSION_VERSION =
    "crucible-scientific-conclusion-v1";
export const SCIENTIFIC_CONCLUSION_HASH_ALGORITHM =
    "sha256:crucible-scientific-conclusion-v1";

function ownEntry(record, key) {
    return record !== null
        && typeof record === "object"
        && typeof key === "string"
        && Object.hasOwn(record, key)
        ? record[key]
        : null;
}

function compareLexical(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

function evidenceItems(aggregate, purpose) {
    return aggregate.evidenceOrder
        .map((evidenceId) => ownEntry(aggregate.evidence, evidenceId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
            && evidence.purpose === purpose);
}

function candidateProjection(evidence) {
    return {
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        candidateId: evidence.candidateId,
        round: evidence.round,
        slotIndex: evidence.slotIndex,
        invalidated: evidence.invalidated,
        invalidatedSeq: evidence.invalidatedSeq,
        rawAuthorityDigest: evidence.rawAuthorityDigest,
        statisticalCacheDigest: evidence.statisticalCacheDigest,
        outcomeClass: evidence.outcomeClass,
        acceptanceSatisfied: evidence.acceptanceSatisfied,
        rankable: evidence.rankable,
        metrics: evidence.metrics,
        replication: evidence.replication,
        statisticalEvaluation: evidence.statisticalEvaluation,
        novelty: evidence.novelty ?? null,
        hypothesesIdentity: evidence.hypothesesIdentity ?? null,
        predictionEvaluation: evidence.predictionEvaluation ?? null,
    };
}

function calibrationProjection(aggregate, evidence) {
    const basisInvalidated = evidence.validationBasisEvidenceIds.some(
        (evidenceId) => ownEntry(
            aggregate.evidence,
            evidenceId,
        )?.invalidated !== false,
    );
    return {
        evidenceId: evidence.evidenceId,
        attemptIndex: evidence.validationAttemptIndex,
        invalidated: evidence.invalidated,
        invalidatedSeq: evidence.invalidatedSeq,
        basisInvalidated,
        rawAuthorityDigest: evidence.rawAuthorityDigest,
        statisticalCacheDigest: evidence.statisticalCacheDigest,
        validationBasisEvidenceIds: evidence.validationBasisEvidenceIds,
        validationSatisfied: evidence.validationSatisfied,
        validationEvaluation: evidence.validationEvaluation,
        validationControlBindings:
            evidence.validationControlBindings ?? [],
    };
}

function scientificRoleProjection(evidence) {
    return {
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        candidateId: evidence.candidateId,
        candidateEvidenceId: evidence.candidateEvidenceId,
        candidateEvidenceHash: evidence.candidateEvidenceHash,
        confirmationFreezeHash: evidence.confirmationFreezeHash,
        roleManifestHash: evidence.roleManifestHash,
        protocolManifestHash: evidence.protocolManifestHash,
        invalidated: evidence.invalidated,
        invalidatedSeq: evidence.invalidatedSeq,
        rawAuthorityDigest: evidence.rawAuthorityDigest,
        statisticalCacheDigest: evidence.statisticalCacheDigest,
        outcomeClass: evidence.outcomeClass,
        acceptanceSatisfied: evidence.acceptanceSatisfied,
        rankable: evidence.rankable,
        metrics: evidence.metrics,
        replication: evidence.replication,
        statisticalEvaluation: evidence.statisticalEvaluation,
        hypothesesIdentity: evidence.hypothesesIdentity ?? null,
        annotations: evidence.annotations ?? null,
    };
}

function claimContexts(scientificAggregate) {
    const contexts = [];
    for (const candidate of scientificAggregate.candidates) {
        contexts.push({
            source: "candidate",
            evidenceId: candidate.evidenceId,
            subjectId: candidate.candidateId,
            role: "search",
            caseId: null,
            active: !candidate.invalidated,
            statistics: candidate.statisticalEvaluation?.statistics ?? null,
        });
    }
    for (const candidate of scientificAggregate.candidateSupport) {
        for (const prediction of candidate.predictionEvaluation?.predictions ?? []) {
            contexts.push({
                source: "prediction",
                evidenceId: candidate.evidenceId,
                subjectId: candidate.candidateId,
                role: "prediction",
                caseId: prediction.predictionId,
                active: candidate.active,
                statistics: {
                    claims: [{
                        id: prediction.claimId,
                        state: prediction.status,
                        allocation: prediction.alphaReference,
                    }],
                },
            });
        }
    }
    for (const roleEvidence of [
        ...scientificAggregate.confirmations,
        ...scientificAggregate.challenges,
    ]) {
        contexts.push({
            source: roleEvidence.purpose,
            evidenceId: roleEvidence.evidenceId,
            subjectId: roleEvidence.candidateId,
            role: roleEvidence.purpose,
            caseId: null,
            active: !roleEvidence.invalidated,
            statistics:
                roleEvidence.statisticalEvaluation?.statistics ?? null,
        });
    }
    for (const calibration of scientificAggregate.calibration) {
        for (const item of calibration.validationEvaluation?.evaluations ?? []) {
            contexts.push({
                source: "calibration",
                evidenceId: calibration.evidenceId,
                subjectId: `${item.role}:${item.caseId}`,
                role: item.role,
                caseId: item.caseId,
                active: !calibration.invalidated
                    && !calibration.basisInvalidated,
                statistics: item.evaluation?.statistics ?? null,
            });
        }
    }
    return contexts;
}

function flattenClaimStates(scientificAggregate) {
    const states = [];
    for (const context of claimContexts(scientificAggregate)) {
        for (const claim of context.statistics?.claims ?? []) {
            states.push({
                source: context.source,
                evidenceId: context.evidenceId,
                subjectId: context.subjectId,
                role: context.role,
                caseId: context.caseId,
                claimId: claim.id,
                active: context.active,
                rawState: claim.state,
                state: context.active ? claim.state : "UNRESOLVED",
            });
        }
    }
    return states.sort((left, right) => compareLexical(
        `${left.source}\0${left.evidenceId}\0${left.subjectId}\0${left.claimId}`,
        `${right.source}\0${right.evidenceId}\0${right.subjectId}\0${right.claimId}`,
    ));
}

function flattenAlphaLedger(scientificAggregate) {
    const ledger = [];
    for (const context of claimContexts(scientificAggregate)) {
        for (const claim of context.statistics?.claims ?? []) {
            for (
                let ledgerIndex = 0;
                ledgerIndex < (claim.allocation?.ledger?.length ?? 0);
                ledgerIndex += 1
            ) {
                ledger.push({
                    source: context.source,
                    evidenceId: context.evidenceId,
                    subjectId: context.subjectId,
                    role: context.role,
                    caseId: context.caseId,
                    claimId: claim.id,
                    active: context.active,
                    ledgerIndex,
                    entry: claim.allocation.ledger[ledgerIndex],
                });
            }
        }
    }
    return ledger.sort((left, right) => compareLexical(
        `${left.source}\0${left.evidenceId}\0${left.subjectId}\0${left.claimId}\0${
            String(left.ledgerIndex).padStart(12, "0")
        }`,
        `${right.source}\0${right.evidenceId}\0${right.subjectId}\0${right.claimId}\0${
            String(right.ledgerIndex).padStart(12, "0")
        }`,
    ));
}

function statisticalAuthority(aggregate) {
    return aggregate.evidenceOrder
        .map((evidenceId) => ownEntry(aggregate.evidence, evidenceId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
            && (evidence.purpose === "candidate"
                || evidence.purpose === "confirmation"
                || evidence.purpose === "challenge"
                || evidence.purpose === "validation"))
        .map((evidence) => {
            const observation = ownEntry(
                aggregate.observations,
                evidence.observationId,
            );
            const command = observation === null
                ? null
                : ownEntry(
                    aggregate.commands,
                    observation.commandId,
                )?.command ?? null;
            return {
                evidenceId: evidence.evidenceId,
                purpose: evidence.purpose,
                commandId: observation?.commandId ?? null,
                commandAuthority: evidence.purpose === "candidate"
                    || evidence.purpose === "confirmation"
                    || evidence.purpose === "challenge"
                    ? {
                        kind: command?.kind ?? null,
                        candidateId: command?.candidateId ?? null,
                        candidateEvidenceId:
                            command?.candidateEvidenceId ?? null,
                        confirmationFreezeHash:
                            command?.confirmationFreezeHash ?? null,
                        protocolManifest:
                            command?.protocolManifest ?? null,
                        replicationSchedule:
                            command?.replicationSchedule ?? null,
                        hypotheses: command?.hypotheses ?? null,
                    }
                    : {
                        kind: command?.kind ?? null,
                        attemptIndex: command?.attemptIndex ?? null,
                        validationSeries:
                            command?.validationSeries ?? null,
                    },
                observationId: observation?.observationId ?? null,
                receipt: observation?.receipt ?? null,
                rawSeries: observation?.data ?? null,
                rawAuthorityDigest: evidence.rawAuthorityDigest,
            };
        });
}

function aggregateStates(states) {
    if (states.length === 0) return "SUPPORTED";
    if (states.includes("INVALID")) return "INVALID";
    if (states.includes("REFUTED")) return "REFUTED";
    return states.every((state) => state === "SUPPORTED")
        ? "SUPPORTED"
        : "UNRESOLVED";
}

function effectivePredictionEvaluation(candidate, activeEvidenceIds) {
    const raw = candidate.predictionEvaluation;
    if (raw === null || raw === undefined) return null;
    const candidateActive = !candidate.invalidated;
    const predictions = raw.predictions.map((prediction) => {
        const parentEvidenceId = prediction.reference?.kind === "assigned_parent"
            ? prediction.reference.evidenceId
            : null;
        const parentActive = parentEvidenceId === null
            || activeEvidenceIds.has(parentEvidenceId);
        const active = candidateActive && parentActive;
        const status = active ? prediction.status : "UNRESOLVED";
        const limitations = active
            ? prediction.limitations
            : [
                ...prediction.limitations,
                {
                    code: candidateActive
                        ? "REFERENCE_EVIDENCE_INVALIDATED"
                        : "CANDIDATE_EVIDENCE_INVALIDATED",
                    evidenceId: candidateActive
                        ? parentEvidenceId
                        : candidate.evidenceId,
                },
            ];
        return {
            ...prediction,
            rawStatus: prediction.status,
            status,
            active,
            evidenceReference: {
                ...prediction.evidenceReference,
                evidenceHash: candidate.evidenceHash,
            },
            limitations,
        };
    });
    const required = predictions.filter(
        (prediction) => prediction.requiredForResult,
    );
    return {
        ...raw,
        evidenceReference: {
            ...raw.evidenceReference,
            evidenceHash: candidate.evidenceHash,
        },
        rawOverallState: raw.overallState,
        rawRequiredState: raw.requiredState,
        overallState: aggregateStates(
            predictions.map((prediction) => prediction.status),
        ),
        requiredState: aggregateStates(
            required.map((prediction) => prediction.status),
        ),
        predictions,
    };
}

function candidateSupport(candidates) {
    const activeEvidenceIds = new Set(
        candidates
            .filter((candidate) => !candidate.invalidated)
            .map((candidate) => candidate.evidenceId),
    );
    return candidates.map((candidate) => {
        const active = !candidate.invalidated;
        const rawRequiredState =
            candidate.statisticalEvaluation?.requiredState ?? "INVALID";
        return {
            evidenceId: candidate.evidenceId,
            evidenceHash: candidate.evidenceHash,
            candidateId: candidate.candidateId,
            invalidated: candidate.invalidated,
            active,
            rawRequiredState,
            requiredState: active ? rawRequiredState : "UNRESOLVED",
            completeValidBlocks: active
                && candidate.statisticalEvaluation?.completeValidBlocks === true,
            rawOutcomeClass: candidate.outcomeClass,
            outcomeClass: active
                ? candidate.outcomeClass
                : "inconclusive",
            rawAcceptanceSatisfied:
                candidate.acceptanceSatisfied === true,
            acceptanceSatisfied: active
                && candidate.acceptanceSatisfied === true,
            metrics: candidate.metrics,
            rawRankable: candidate.rankable === true,
            rankable: active && candidate.rankable === true,
            replication: candidate.replication,
            evaluationHash:
                candidate.statisticalEvaluation?.evaluationHash ?? null,
            statisticalCacheDigest: candidate.statisticalCacheDigest,
            novelty: candidate.novelty,
            hypothesesIdentity: candidate.hypothesesIdentity,
            predictionEvaluation: effectivePredictionEvaluation(
                candidate,
                activeEvidenceIds,
            ),
        };
    });
}

export function replayDerivedCandidateEvidence(aggregate, evidence) {
    if (evidence?.sourceKind !== "harness"
        || evidence?.purpose !== "candidate") {
        return evidence;
    }
    if (aggregate?.scientificReplay === null
        || aggregate?.scientificReplay === undefined) {
        return evidence;
    }
    const support = aggregate?.scientificReplay?.candidateSupport?.find(
        (item) => item.evidenceId === evidence.evidenceId,
    ) ?? null;
    if (support === null) {
        throw new TypeError(
            `candidate evidence ${evidence.evidenceId} has no replay-derived support`,
        );
    }
    return immutableCanonical({
        ...evidence,
        replication: support.replication,
        metrics: support.metrics,
        rankable: support.rankable,
        outcomeClass: support.outcomeClass,
        acceptanceSatisfied: support.acceptanceSatisfied,
        novelty: support.novelty,
        hypothesesIdentity: support.hypothesesIdentity,
        predictionEvaluation: support.predictionEvaluation,
    });
}

function calibrationState(calibration) {
    return calibration.map((item) => {
        const active = !item.invalidated && !item.basisInvalidated;
        return {
            evidenceId: item.evidenceId,
            attemptIndex: item.attemptIndex,
            invalidated: item.invalidated,
            basisInvalidated: item.basisInvalidated,
            active,
            rawValidationSatisfied: item.validationSatisfied === true,
            validationSatisfied: active
                && item.validationSatisfied === true,
            basisEvidenceIds: item.validationBasisEvidenceIds,
            evaluations: (item.validationEvaluation?.evaluations ?? []).map(
                (evaluation) => ({
                    role: evaluation.role,
                    executionRole: evaluation.executionRole,
                    caseId: evaluation.caseId,
                    expectedState: evaluation.expectedState,
                    rawActualState: evaluation.actualState,
                    actualState: active
                        ? evaluation.actualState
                        : "UNRESOLVED",
                    rawSatisfied: evaluation.satisfied,
                    satisfied: active && evaluation.satisfied,
                    evaluationHash:
                        evaluation.evaluation?.evaluationHash ?? null,
                }),
            ),
            statisticalCacheDigest: item.statisticalCacheDigest,
        };
    });
}

function deriveScientificReplayMaterial(
    aggregate,
    { includeCollections = false } = {},
) {
    if (aggregate?.contract === null || aggregate?.contract === undefined) {
        return null;
    }
    const candidates = evidenceItems(aggregate, "candidate")
        .map(candidateProjection);
    const confirmations = evidenceItems(aggregate, "confirmation")
        .map((evidence) => ({
            purpose: "confirmation",
            ...scientificRoleProjection(evidence),
        }));
    const challenges = evidenceItems(aggregate, "challenge")
        .map((evidence) => ({
            purpose: "challenge",
            ...scientificRoleProjection(evidence),
        }));
    const calibration = evidenceItems(aggregate, "validation")
        .map((evidence) => calibrationProjection(aggregate, evidence));
    const support = candidateSupport(candidates);
    const candidateComparison = deriveCandidateCohortComparison({
        contract: aggregate.contract,
        candidates: support.map((candidate, index) => ({
            ...candidate,
            statisticalEvaluation:
                candidates[index]?.statisticalEvaluation ?? null,
        })),
    });
    const candidateCohort = summarizeCandidateCohortComparison(
        candidateComparison,
    );
    const calibrationSummary = calibrationState(calibration);
    const confirmationState = deriveScientificConfirmationState(aggregate);
    const scientificAggregate = {
        version: SCIENTIFIC_REPLAY_VERSION,
        contractHash: aggregate.contractHash,
        statisticalPolicyIdentity:
            aggregate.contract.statisticalPolicyIdentity,
        currentValidationEvidenceId:
            aggregate.validation.currentEvidenceId,
        candidates,
        confirmations,
        challenges,
        calibration,
        candidateSupport: support,
        candidateComparison,
        calibrationState: calibrationSummary,
        confirmationFreeze:
            aggregate.confirmation?.freeze ?? null,
        confirmationState,
    };
    const claimStates = flattenClaimStates(scientificAggregate);
    const alphaLedger = flattenAlphaLedger(scientificAggregate);
    const rawAuthorityRoot = hashCanonical({
        contractHash: aggregate.contractHash,
        statisticalPolicyIdentity:
            aggregate.contract.statisticalPolicyIdentity,
        statisticalPolicy: aggregate.contract.statisticalPolicy,
        acceptanceClaimSet: aggregate.contract.acceptanceClaimSet,
        validationClaimSet: aggregate.contract.validationClaimSet,
        evidence: statisticalAuthority(aggregate),
    }, SCIENTIFIC_RAW_AUTHORITY_HASH_ALGORITHM);
    const scientificAggregateHash = hashCanonical(
        scientificAggregate,
        SCIENTIFIC_AGGREGATE_HASH_ALGORITHM,
    );
    const claimStatesHash = hashCanonical(
        claimStates,
        SCIENTIFIC_CLAIM_STATES_HASH_ALGORITHM,
    );
    const alphaLedgerHash = hashCanonical(
        alphaLedger,
        SCIENTIFIC_ALPHA_LEDGER_HASH_ALGORITHM,
    );
    const closureCore = {
        version: SCIENTIFIC_REPLAY_VERSION,
        rawAuthorityRoot,
        scientificAggregateHash,
        claimStatesHash,
        alphaLedgerHash,
    };
    const compact = immutableCanonical({
        ...closureCore,
        candidateSupport: support,
        candidateCohort,
        calibrationState: calibrationSummary,
        confirmationState,
        closureRoot: hashCanonical(
            closureCore,
            SCIENTIFIC_REPLAY_CLOSURE_HASH_ALGORITHM,
        ),
    });
    if (!includeCollections) return compact;
    return immutableCanonical({
        ...compact,
        scientificAggregate,
        claimStates,
        alphaLedger,
    });
}

export function deriveScientificReplayState(aggregate) {
    return deriveScientificReplayMaterial(aggregate);
}

export function materializeScientificReplayState(aggregate) {
    return deriveScientificReplayMaterial(
        aggregate,
        { includeCollections: true },
    );
}

function performanceClaimConclusion(evidence, active) {
    return (evidence?.statisticalEvaluation?.statistics?.claims ?? []).map(
        (claim) => ({
            claimId: claim.id,
            status: active ? claim.state : "UNRESOLVED",
            observable: claim.observable,
            estimate: claim.estimate,
            confidenceBounds:
                claim.estimate?.confidenceSequence ?? null,
            alphaReference: claim.allocation ?? null,
            decision: claim.decision ?? null,
        }),
    );
}

function conclusionLimitations(evidence, support) {
    const limitations = [{
        code: "MODEL_PROSE_NON_AUTHORITATIVE",
        note:
            "The conclusion excludes explanatory hypothesis/finding prose; only sealed typed predictions and replay-derived kernel output have scientific status.",
    }, {
        code: "PERFORMANCE_SUPPORT_SEPARATE_FROM_HYPOTHESIS_SUPPORT",
        note:
            "Candidate acceptance and prediction outcomes are independent axes; an accepted candidate may refute an optional prediction.",
    }];
    const interpretation =
        evidence?.statisticalEvaluation?.statistics?.assumptions
            ?.interpretation;
    if (typeof interpretation === "string") {
        limitations.push({
            code: "STATISTICAL_ASSUMPTIONS",
            note: interpretation,
        });
    }
    for (const prediction of support?.predictionEvaluation?.predictions ?? []) {
        for (const limitation of prediction.limitations ?? []) {
            limitations.push({
                predictionId: prediction.predictionId,
                ...limitation,
            });
        }
    }
    return limitations;
}

export function deriveScientificConclusion(aggregate, evidenceId) {
    const evidence = ownEntry(aggregate?.evidence, evidenceId);
    const support = aggregate?.scientificReplay?.candidateSupport?.find(
        (candidate) => candidate.evidenceId === evidenceId,
    ) ?? null;
    if (evidence === null
        || evidence?.sourceKind !== "harness"
        || evidence?.purpose !== "candidate"
        || support === null) {
        throw new TypeError(
            `candidate evidence ${String(evidenceId)} has no replay-derived scientific conclusion`,
        );
    }
    const predictionEvaluation = support.predictionEvaluation;
    const predictions = (predictionEvaluation?.predictions ?? []).map(
        (prediction) => ({
            predictionId: prediction.predictionId,
            predictionIdentity: prediction.predictionIdentity,
            requiredForResult: prediction.requiredForResult,
            prediction: prediction.prediction,
            status: prediction.status,
            estimate: prediction.estimate,
            confidenceBounds: prediction.confidenceBounds,
            confidenceMethod: prediction.confidenceMethod ?? null,
            evidenceReference: prediction.evidenceReference,
            blockReference: prediction.blockReference,
            alphaReference: prediction.alphaReference,
            reference: prediction.reference,
            referenceSampling: prediction.referenceSampling,
            limitations: prediction.limitations,
        }),
    );
    const core = {
        version: SCIENTIFIC_CONCLUSION_VERSION,
        authority: "replay_derived_statistical_kernel",
        contractHash: aggregate.contractHash,
        scientificReplayClosureRoot:
            aggregate.scientificReplay.closureRoot,
        candidate: {
            candidateId: support.candidateId,
            evidenceId: support.evidenceId,
            evidenceHash: support.evidenceHash,
            active: support.active,
            performance: {
                status: support.requiredState,
                acceptanceSatisfied: support.acceptanceSatisfied,
                outcomeClass: support.outcomeClass,
                metrics: support.metrics,
                claims: performanceClaimConclusion(
                    evidence,
                    support.active,
                ),
            },
        },
        hypotheses: {
            identity: support.hypothesesIdentity,
            status: predictionEvaluation?.overallState ?? "SUPPORTED",
            requiredForResultStatus:
                predictionEvaluation?.requiredState ?? "SUPPORTED",
            predictions,
        },
        limitations: conclusionLimitations(evidence, support),
    };
    return immutableCanonical({
        ...core,
        conclusionHash: hashCanonical(
            core,
            SCIENTIFIC_CONCLUSION_HASH_ALGORITHM,
        ),
    });
}

export function scientificReplaySummary(scientificReplay, terminal = null) {
    if (scientificReplay === null
        || scientificReplay === undefined
        || scientificReplay.version !== SCIENTIFIC_REPLAY_VERSION
        || !isAlgorithmTaggedSha256(scientificReplay.rawAuthorityRoot)
        || !isAlgorithmTaggedSha256(scientificReplay.scientificAggregateHash)
        || !isAlgorithmTaggedSha256(scientificReplay.claimStatesHash)
        || !isAlgorithmTaggedSha256(scientificReplay.alphaLedgerHash)
        || !isAlgorithmTaggedSha256(scientificReplay.closureRoot)) {
        throw new TypeError("scientificReplay is not a canonical v4 replay state");
    }
    const terminalClosureRoot =
        terminal?.evidenceClosure?.closureRoot ?? null;
    if (terminalClosureRoot !== null
        && !isAlgorithmTaggedSha256(terminalClosureRoot)) {
        throw new TypeError("terminal evidence closure root is invalid");
    }
    return immutableCanonical({
        version: scientificReplay.version,
        rawAuthorityRoot: scientificReplay.rawAuthorityRoot,
        scientificAggregateHash:
            scientificReplay.scientificAggregateHash,
        claimStatesHash: scientificReplay.claimStatesHash,
        alphaLedgerHash: scientificReplay.alphaLedgerHash,
        closureRoot: scientificReplay.closureRoot,
        terminalClosureRoot,
    });
}
