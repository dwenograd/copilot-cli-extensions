import {
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import {
    aggregateRequiredClaimState,
    claimSetAlphaAllocation,
    evaluateStatisticalClaims,
} from "./statistics.mjs";
import { statisticalClaimsForHypotheses } from "./hypotheses.mjs";
import {
    analyzeReplicationAttempts,
    normalizeReplicationSchedule,
} from "./replication.mjs";

export const STATISTICAL_EVALUATION_VERSION =
    "crucible-replicated-claim-evaluation-v1";
export const CONTROL_TOLERANCE_HASH_ALGORITHM =
    "sha256:crucible-control-tolerance-v2";
export const STATISTICAL_EVALUATION_HASH_ALGORITHM =
    "sha256:crucible-replicated-claim-evaluation-v1";
export const CANDIDATE_CLAIM_PLAN_VERSION =
    "crucible-candidate-statistical-claim-plan-v1";
export const CANDIDATE_CLAIM_PLAN_HASH_ALGORITHM =
    "sha256:crucible-candidate-statistical-claim-plan-v1";
export const PREDICTION_EVALUATION_VERSION =
    "crucible-preregistered-prediction-evaluation-v1";
export const PREDICTION_EVALUATION_HASH_ALGORITHM =
    "sha256:crucible-preregistered-prediction-evaluation-v1";
export const PREDICTION_BLOCK_LEDGER_HASH_ALGORITHM =
    "sha256:crucible-prediction-block-ledger-v1";
export const REPLICATION_STATISTICAL_SUMMARY_HASH_ALGORITHM =
    "sha256:crucible-replication-statistical-summary-v1";
export const REPLICATION_STOPPING_DIGEST_HASH_ALGORITHM =
    "sha256:crucible-replication-stopping-v1";

function plainObject(value) {
    return value !== null
        && typeof value === "object"
        && !Array.isArray(value);
}

function metricValue(record, key) {
    const value = record?.metrics?.[key];
    return typeof value === "number" && Number.isFinite(value)
        ? value
        : null;
}

function aggregateStates(states) {
    if (states.length === 0) return "SUPPORTED";
    if (states.includes("INVALID")) return "INVALID";
    if (states.includes("REFUTED")) return "REFUTED";
    return states.every((state) => state === "SUPPORTED")
        ? "SUPPORTED"
        : "UNRESOLVED";
}

function normalizedParentEvidence(parentEvidence = {}) {
    if (!plainObject(parentEvidence)) return {};
    return Object.fromEntries(
        Object.entries(parentEvidence)
            .filter(([, value]) =>
                plainObject(value) && Array.isArray(value.blocks))
            .sort(([left], [right]) => left.localeCompare(right)),
    );
}

function withParentBlocks(blocks, parentEvidence) {
    const parents = normalizedParentEvidence(parentEvidence);
    if (Object.keys(parents).length === 0) return blocks;
    const indexedParents = Object.entries(parents).map(
        ([evidenceId, source]) => [
            evidenceId,
            new Map(source.blocks.map((block) => [
                block?.blockIndex,
                block,
            ])),
        ],
    );
    return blocks.map((block) => ({
        ...block,
        parents: Object.fromEntries(
            indexedParents.map(([evidenceId, byBlockIndex]) => {
                const parentBlock =
                    byBlockIndex.get(block.blockIndex) ?? null;
                return [
                    evidenceId,
                    parentBlock?.candidate ?? null,
                ];
            }),
        ),
    }));
}

function blockLedger(analysis) {
    const blocks = analysis.completeBlocks.map((block) => ({
        blockIndex: block.blockIndex,
        attempts: block.attempts.map((attempt) => ({
            armId: attempt.armId,
            armIndex: attempt.armIndex,
            subjectId: attempt.subjectId,
            receiptHash: attempt.receiptHash,
            measurementRoot: attempt.measurementRoot,
            invalid: attempt.invalid !== null,
        })),
    }));
    return immutableCanonical({
        blocks,
        hash: hashCanonical(
            blocks,
            PREDICTION_BLOCK_LEDGER_HASH_ALGORITHM,
        ),
    });
}

function parentEvidenceReferences(parentEvidence = {}) {
    return Object.entries(normalizedParentEvidence(parentEvidence))
        .map(([key, source]) => ({
            evidenceId: source.evidenceId ?? key,
            evidenceHash: source.evidenceHash ?? null,
            rawAuthorityDigest: source.rawAuthorityDigest ?? null,
            scheduleHash: source.scheduleHash ?? null,
            blockCount: source.blocks.length,
            invalidated: source.invalidated === true,
        }))
        .sort((left, right) =>
            left.evidenceId < right.evidenceId
                ? -1
                : left.evidenceId > right.evidenceId ? 1 : 0);
}

export function createCandidateStatisticalClaimPlan({
    contract,
    hypotheses = null,
    assignedParentEvidenceIds = [],
}) {
    const predictionSet = statisticalClaimsForHypotheses(hypotheses, {
        observableRegistry: contract.observableRegistry,
        hypothesisPolicy: contract.hypothesisPolicy,
        statisticalPolicy: contract.statisticalPolicy,
        assignedParentEvidenceIds,
        requireSealed: hypotheses !== null && hypotheses !== undefined,
    });
    const acceptanceClaims = contract.acceptanceClaimSet.claims;
    const allocationClaims = [
        ...acceptanceClaims,
        ...predictionSet.claims,
    ];
    const core = {
        version: CANDIDATE_CLAIM_PLAN_VERSION,
        hypothesesIdentity: predictionSet.hypothesesIdentity,
        acceptanceClaimIds:
            contract.acceptanceClaimSet.requiredClaimIds,
        predictionBindings: predictionSet.bindings,
        acceptanceClaims,
        predictionClaims: predictionSet.claims,
        allocationClaims,
    };
    return immutableCanonical({
        ...core,
        claimPlanHash: hashCanonical(
            core,
            CANDIDATE_CLAIM_PLAN_HASH_ALGORITHM,
        ),
    });
}

export function deriveControlToleranceMetadata({
    statisticalPolicy,
    schedule = null,
    blocks,
}) {
    const normalizedSchedule = schedule === null
        ? null
        : normalizeReplicationSchedule(schedule);
    const hasControl = normalizedSchedule === null
        ? blocks.some((block) => Object.hasOwn(block, "control"))
        : normalizedSchedule.arms.some((arm) => arm.armId === "control");
    if (!hasControl) {
        const core = {
            applicable: false,
            control: null,
            blockCount: blocks.length,
            metrics: [],
            invalidObservation: false,
            driftDetected: false,
        };
        return immutableCanonical({
            ...core,
            status: "not_applicable",
            metadataHash: hashCanonical(
                core,
                CONTROL_TOLERANCE_HASH_ALGORITHM,
            ),
        });
    }

    const tolerances = Array.isArray(statisticalPolicy?.control?.tolerances)
        ? statisticalPolicy.control.tolerances
        : [];
    const metrics = tolerances.map((tolerance) => {
        const observations = blocks.map((block) => ({
            blockIndex: block.blockIndex,
            value: metricValue(block.control, tolerance.metric),
        }));
        const baselineObservation = observations.find(
            (observation) => observation.value !== null,
        ) ?? null;
        const baseline = baselineObservation?.value ?? null;
        const checked = observations.map((observation) => {
            if (baseline === null || observation.value === null) {
                return {
                    ...observation,
                    absoluteDeviation: null,
                    relativeDeviation: null,
                    allowedDeviation: null,
                    withinTolerance: false,
                    valid: false,
                };
            }
            const absoluteDeviation = Math.abs(observation.value - baseline);
            const relativeDenominator = Math.max(
                Math.abs(baseline),
                Number.EPSILON,
            );
            const relativeDeviation = absoluteDeviation / relativeDenominator;
            const allowedDeviation = tolerance.absolute
                + tolerance.relative * Math.abs(baseline);
            return {
                ...observation,
                absoluteDeviation,
                relativeDeviation,
                allowedDeviation,
                withinTolerance: absoluteDeviation <= allowedDeviation,
                valid: true,
            };
        });
        return {
            metric: tolerance.metric,
            absoluteTolerance: tolerance.absolute,
            relativeTolerance: tolerance.relative,
            baselineBlockIndex: baselineObservation?.blockIndex ?? null,
            baselineValue: baseline,
            observations: checked,
            invalidObservation: checked.some((item) => !item.valid),
            driftDetected: checked.some((item) =>
                item.valid && !item.withinTolerance),
        };
    });
    const core = {
        applicable: true,
        control: {
            kind: statisticalPolicy?.control?.kind ?? null,
            identity: statisticalPolicy?.control?.identity ?? null,
        },
        blockCount: blocks.length,
        metrics,
        invalidObservation: metrics.some((metric) => metric.invalidObservation),
        driftDetected: metrics.some((metric) => metric.driftDetected),
    };
    return immutableCanonical({
        ...core,
        status: core.invalidObservation
            ? "invalid"
            : core.driftDetected
                ? "drift_detected"
                : "within_tolerance",
        metadataHash: hashCanonical(
            core,
            CONTROL_TOLERANCE_HASH_ALGORITHM,
        ),
    });
}

export function prepareReplicatedStatisticalEvaluation({
    contract,
    schedule,
    attempts,
    parentEvidence = {},
}) {
    const normalizedSchedule = normalizeReplicationSchedule(schedule);
    const analysis = analyzeReplicationAttempts({
        schedule: normalizedSchedule,
        attempts,
    });
    const rawBlocks = analysis.completeBlocks.map(
        (block) => block.statisticalBlock,
    );
    return Object.freeze({
        schedule: normalizedSchedule,
        analysis,
        rawBlocks,
        controlTolerance: deriveControlToleranceMetadata({
            statisticalPolicy: contract.statisticalPolicy,
            schedule: normalizedSchedule,
            blocks: rawBlocks,
        }),
        blockLedger: blockLedger(analysis),
        parentEvidence,
        parentEvidenceReferences:
            parentEvidenceReferences(parentEvidence),
    });
}

function blockExclusion(block, policy, controlTolerance, claims) {
    const requiredMetricKeys = new Set(
        claims
            .filter((claim) => claim.kind !== "harness_pass"
                && claim.kind !== "binary"
                && claim.kind !== "categorical"
                && claim.kind !== "categorical_outcome")
            .map((claim) => claim.observable ?? claim.metric),
    );
    for (const attempt of block.attempts) {
        if (attempt.invalid !== null || !plainObject(attempt.parsed)) {
            return {
                blockIndex: block.blockIndex,
                code: "INVALID_ATTEMPT",
                armId: attempt.armId,
                metric: null,
            };
        }
        for (const metric of policy.metrics) {
            const value = attempt.parsed.metrics?.[metric.key];
            if (value === null || value === undefined) {
                if (requiredMetricKeys.has(metric.key)) {
                    return {
                        blockIndex: block.blockIndex,
                        code: "MISSING_OBSERVATION",
                        armId: attempt.armId,
                        metric: metric.key,
                    };
                }
                continue;
            }
            if (typeof value !== "number"
                || !Number.isFinite(value)
                || value < metric.minimum
                || value > metric.maximum) {
                return {
                    blockIndex: block.blockIndex,
                    code: "OUT_OF_BOUNDS_OBSERVATION",
                    armId: attempt.armId,
                    metric: metric.key,
                };
            }
        }
    }
    if (controlTolerance.applicable) {
        for (const metric of controlTolerance.metrics) {
            const observation = metric.observations.find(
                (item) => item.blockIndex === block.blockIndex,
            );
            if (observation !== undefined
                && (!observation.valid || !observation.withinTolerance)) {
                return {
                    blockIndex: block.blockIndex,
                    code: observation.valid
                        ? "CONTROL_DRIFT"
                        : "INVALID_CONTROL_OBSERVATION",
                    armId: "control",
                    metric: metric.metric,
                };
            }
        }
    }
    return null;
}

function missingBlock(block) {
    const parents = Object.fromEntries(
        Object.keys(block.statisticalBlock.parents ?? {})
            .map((key) => [key, null]),
    );
    const arms = Object.fromEntries(
        Object.keys(block.statisticalBlock.arms ?? {})
            .map((key) => [key, null]),
    );
    return {
        blockIndex: block.blockIndex,
        candidate: null,
        control: null,
        ...(Object.keys(parents).length === 0 ? {} : { parents }),
        ...(Object.keys(arms).length === 0 ? {} : { arms }),
    };
}

function metricEstimates(contract, statistics) {
    const byId = new Map(
        statistics.claims.map((claim) => [claim.id, claim]),
    );
    const values = {};
    for (const metric of contract.statisticalPolicy.metrics) {
        const claim = byId.get(`metric.${metric.key}.acceptance`);
        const value = claim?.estimate?.pointEstimate;
        if (typeof value === "number" && Number.isFinite(value)) {
            values[metric.key] = value;
        }
    }
    return values;
}

export function evaluateReplicatedStatisticalClaims({
    contract,
    schedule,
    attempts,
    claims = contract.acceptanceClaimSet.claims,
    requiredClaimIds = contract.acceptanceClaimSet.requiredClaimIds,
    allocationClaims = claims,
    parentEvidence = {},
    prepared = null,
}) {
    const inputs = prepared ?? prepareReplicatedStatisticalEvaluation({
        contract,
        schedule,
        attempts,
        parentEvidence,
    });
    const normalizedSchedule = inputs.schedule;
    const analysis = inputs.analysis;
    const controlTolerance = inputs.controlTolerance;
    const effectiveParentEvidence = inputs.parentEvidence;
    if (normalizedSchedule.scheduleHash !== schedule?.scheduleHash) {
        throw new TypeError(
            "prepared statistical evaluation does not match the requested schedule",
        );
    }
    const exclusions = analysis.completeBlocks
        .map((block) =>
            blockExclusion(
                block,
                contract.statisticalPolicy,
                controlTolerance,
                claims,
            ))
        .filter((item) => item !== null);
    const excluded = new Set(exclusions.map((item) => item.blockIndex));
    const blocks = analysis.completeBlocks.map((block) =>
        excluded.has(block.blockIndex)
            ? missingBlock(block)
            : block.statisticalBlock);
    const referencedBlocks = withParentBlocks(
        blocks,
        effectiveParentEvidence,
    );
    const statistics = evaluateStatisticalClaims({
        statisticalPolicy: contract.statisticalPolicy,
        claims,
        allocationClaims,
        blocks: referencedBlocks,
        subject: {
            kind: normalizedSchedule.subject.kind,
            index: normalizedSchedule.subject.index,
        },
        observableRegistry: contract.observableRegistry,
    });
    const rawRequiredState = aggregateRequiredClaimState(
        statistics,
        requiredClaimIds,
    );
    const completeValidBlocks = exclusions.length === 0
        && (statistics.missingness?.totalMissing ?? 0) === 0;
    const requiredState = statistics.overallState === "INVALID"
        ? "INVALID"
        : completeValidBlocks
            ? rawRequiredState
            : "UNRESOLVED";
    const core = {
        version: STATISTICAL_EVALUATION_VERSION,
        scheduleHash: normalizedSchedule.scheduleHash,
        subject: statistics.subject,
        blockCount: analysis.contiguousCompleteBlockCount,
        attemptCount: analysis.attempts.length,
        requiredClaimIds,
        requiredState,
        rawRequiredState,
        completeValidBlocks,
        exclusions,
        metrics: metricEstimates(contract, statistics),
        statistics,
        controlTolerance,
        blockLedger: inputs.blockLedger,
        parentEvidenceReferences:
            inputs.parentEvidenceReferences,
    };
    return immutableCanonical({
        ...core,
        evaluationHash: hashCanonical(
            core,
            STATISTICAL_EVALUATION_HASH_ALGORITHM,
        ),
        analysis,
    });
}

export function evaluateReplicationProgress({
    contract,
    schedule,
    attempts,
    claims = contract.acceptanceClaimSet.claims,
    requiredClaimIds = contract.acceptanceClaimSet.requiredClaimIds,
    budgetRemaining = true,
}) {
    const normalizedSchedule = normalizeReplicationSchedule(schedule);
    const evaluation = evaluateReplicatedStatisticalClaims({
        contract,
        schedule: normalizedSchedule,
        attempts,
        claims,
        requiredClaimIds,
    });
    const analysis = evaluation.analysis;
    const blockCount = analysis.contiguousCompleteBlockCount;
    const minimumMet = blockCount >= normalizedSchedule.minBlocks;
    const claimsResolved = minimumMet
        && evaluation.requiredState !== "UNRESOLVED";
    const tieResolutionBlocksPending =
        contract.statisticalPolicy.goalMode === "optimize"
        && evaluation.requiredState === "SUPPORTED"
        && blockCount < normalizedSchedule.maxBlocks;
    let stoppingReason = null;
    const partialBlockCommitted = analysis.invalidIncompleteBlock;
    if (!partialBlockCommitted) {
        if (claimsResolved && !tieResolutionBlocksPending) {
            stoppingReason = "claims_resolved";
        } else if (blockCount >= normalizedSchedule.maxBlocks) {
            stoppingReason = "max_blocks";
        } else if (!budgetRemaining) {
            stoppingReason = "budget_exhausted";
        }
    } else if (!budgetRemaining) {
        stoppingReason = "budget_exhausted";
    }
    const shouldContinue = stoppingReason === null
        && blockCount < normalizedSchedule.maxBlocks;
    const statisticalSummaryHash = hashCanonical(
        evaluation.statistics,
        REPLICATION_STATISTICAL_SUMMARY_HASH_ALGORITHM,
    );
    const stoppingCore = {
        version: 1,
        scheduleHash: normalizedSchedule.scheduleHash,
        minBlocks: normalizedSchedule.minBlocks,
        maxBlocks: normalizedSchedule.maxBlocks,
        goalMode: contract.statisticalPolicy.goalMode,
        blockCount,
        attemptCount: analysis.attempts.length,
        blockLedgerHash: evaluation.blockLedger.hash,
        evaluationHash: evaluation.evaluationHash,
        statisticalSummaryHash,
        statisticalState: evaluation.requiredState,
        minimumMet,
        claimsResolved,
        tieResolutionBlocksPending,
        budgetRemaining,
        shouldContinue,
        stoppingReason,
        nextArm: shouldContinue ? analysis.nextArm : null,
    };
    const stopping = immutableCanonical({
        ...stoppingCore,
        stoppingDigest: hashCanonical(
            stoppingCore,
            REPLICATION_STOPPING_DIGEST_HASH_ALGORITHM,
        ),
    });
    return immutableCanonical({
        ...stopping,
        analysis,
        evaluation,
        statistics: evaluation.statistics,
        controlTolerance: evaluation.controlTolerance,
        stopping,
    });
}

function predictionLimitations({
    status,
    binding,
    evaluation,
    claim,
}) {
    const limitations = [];
    if (evaluation.exclusions.length > 0) {
        limitations.push({
            code: "EXCLUDED_BLOCKS",
            blockIndexes: evaluation.exclusions.map(
                (item) => item.blockIndex,
            ),
        });
    }
    if (evaluation.statistics.invalid !== null) {
        limitations.push({
            code: evaluation.statistics.invalid.code,
            message: evaluation.statistics.invalid.message,
        });
    }
    if (claim?.decision?.gatedByMinimumBlocks === true) {
        limitations.push({
            code: "MINIMUM_BLOCKS_NOT_MET",
            blockCount: evaluation.blockCount,
        });
    }
    if (binding.reference?.kind === "assigned_parent") {
        limitations.push({
            code: "INDEPENDENT_PARENT_REPLAY_COMPARISON",
            evidenceId: binding.reference.evidenceId,
            note:
                "Candidate and parent estimates use separately replayed blocks with a Bonferroni-split independent difference confidence sequence.",
        });
    }
    if (binding.kind === "categorical_outcome") {
        limitations.push({
            code: "CATEGORICAL_PROBABILITY_THRESHOLD",
            note:
                "Categorical support means the anytime-valid lower confidence bound exceeds the frozen default probability threshold.",
        });
    }
    if (status === "UNRESOLVED" && limitations.length === 0) {
        limitations.push({
            code: "CONFIDENCE_SEQUENCE_OVERLAPS_DECISION_BOUNDARY",
        });
    }
    return limitations;
}

export function evaluateSealedPredictions({
    contract,
    schedule,
    attempts,
    claimPlan,
    parentEvidence = {},
    prepared = null,
    evidenceId,
    rawAuthorityDigest,
}) {
    if (claimPlan.predictionBindings.length === 0) return null;
    const claimsById = new Map(
        claimPlan.predictionClaims.map((claim) => [claim.id, claim]),
    );
    let sharedBlockLedger = null;
    let sharedParentEvidenceReferences = null;
    const preparedInputs = prepared
        ?? prepareReplicatedStatisticalEvaluation({
            contract,
            schedule,
            attempts,
            parentEvidence,
        });
    const predictions = claimPlan.predictionBindings.map((binding) => {
        const statisticalClaim = claimsById.get(binding.claimId);
        const evaluation = evaluateReplicatedStatisticalClaims({
            contract,
            schedule,
            attempts,
            claims: [statisticalClaim],
            requiredClaimIds: [binding.claimId],
            allocationClaims: claimPlan.allocationClaims,
            parentEvidence,
            prepared: preparedInputs,
        });
        sharedBlockLedger ??= evaluation.blockLedger;
        sharedParentEvidenceReferences ??=
            evaluation.parentEvidenceReferences;
        const claim = evaluation.statistics.claims.find(
            (item) => item.id === binding.claimId,
        ) ?? null;
        const alphaReference = claimSetAlphaAllocation({
            statisticalPolicy: contract.statisticalPolicy,
            allocationClaims: claimPlan.allocationClaims,
            claimId: binding.claimId,
            subject: evaluation.subject,
            lookIndex: evaluation.blockCount === 0
                ? null
                : evaluation.blockCount,
            observableRegistry: contract.observableRegistry,
        });
        const status = evaluation.requiredState;
        return {
            claimId: binding.claimId,
            predictionId: binding.predictionId,
            predictionIdentity: binding.predictionIdentity,
            hypothesesIdentity: binding.hypothesesIdentity,
            requiredForResult: binding.requiredForResult,
            prediction: binding.prediction,
            status,
            evidenceReference: {
                evidenceId,
                rawAuthorityDigest,
            },
            blockReference: {
                scheduleHash: evaluation.scheduleHash,
                blockLedgerHash: evaluation.blockLedger.hash,
                completeBlockCount: evaluation.blockCount,
                excludedBlockIndexes: evaluation.exclusions.map(
                    (item) => item.blockIndex,
                ),
            },
            alphaReference,
            reference: claim?.reference ?? binding.reference,
            referenceSampling:
                claim?.referenceSampling ?? null,
            estimate: claim?.estimate ?? null,
            confidenceBounds:
                claim?.estimate?.confidenceSequence ?? null,
            confidenceMethod:
                claim?.normalizedConfidenceSequence?.method ?? null,
            decision: claim?.decision ?? null,
            limitations: predictionLimitations({
                status,
                binding,
                evaluation,
                claim,
            }),
            evaluationHash: evaluation.evaluationHash,
        };
    });
    const required = predictions.filter(
        (prediction) => prediction.requiredForResult,
    );
    const core = {
        version: PREDICTION_EVALUATION_VERSION,
        authority: "replay_derived_statistical_kernel",
        hypothesesIdentity: claimPlan.hypothesesIdentity,
        claimPlanHash: claimPlan.claimPlanHash,
        evidenceReference: {
            evidenceId,
            rawAuthorityDigest,
        },
        blockLedger: sharedBlockLedger,
        parentEvidenceReferences:
            sharedParentEvidenceReferences,
        overallState: aggregateStates(
            predictions.map((prediction) => prediction.status),
        ),
        requiredState: aggregateStates(
            required.map((prediction) => prediction.status),
        ),
        predictions,
    };
    return immutableCanonical({
        ...core,
        evaluationHash: hashCanonical(
            core,
            PREDICTION_EVALUATION_HASH_ALGORITHM,
        ),
    });
}
