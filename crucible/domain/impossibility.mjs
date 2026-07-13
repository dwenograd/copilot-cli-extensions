import { createHash } from "node:crypto";

import {
    IMPOSSIBILITY_CALIBRATION_EVIDENCE_HASH_ALGORITHM,
    IMPOSSIBILITY_ALPHA_ALLOCATIONS_HASH_ALGORITHM,
    IMPOSSIBILITY_CERTIFICATE_VERSION,
    IMPOSSIBILITY_CHECKER_OUTPUT_VERSION,
    IMPOSSIBILITY_CHECKER_STATUSES,
    IMPOSSIBILITY_CONTROL_EVIDENCE_HASH_ALGORITHM,
    IMPOSSIBILITY_COVERAGE_CLOSURE_HASH_ALGORITHM,
    IMPOSSIBILITY_COVERAGE_CLOSURE_VERSION,
    IMPOSSIBILITY_ENUMERAND_EVIDENCE_HASH_ALGORITHM,
    IMPOSSIBILITY_EVIDENCE_ROOTS_HASH_ALGORITHM,
    IMPOSSIBILITY_INVALIDATION_ROOT_HASH_ALGORITHM,
    IMPOSSIBILITY_PROPOSAL_HASH_ALGORITHM,
    IMPOSSIBILITY_PROPOSAL_VERSION,
    IMPOSSIBILITY_RAW_BLOCK_ROOTS_HASH_ALGORITHM,
    IMPOSSIBILITY_REQUEST_HASH_ALGORITHM,
    IMPOSSIBILITY_REQUEST_VERSION,
    IMPOSSIBILITY_ROLE_RECEIPTS_HASH_ALGORITHM,
    IMPOSSIBILITY_SEARCH_EVIDENCE_HASH_ALGORITHM,
    IMPOSSIBILITY_VERDICTS,
    IMPOSSIBILITY_PROOF_ARTIFACT_HASH_ALGORITHM,
    IMPOSSIBILITY_PROOF_ARTIFACT_VERSION,
    IMPOSSIBILITY_PROOF_CHECKER_HASH_ALGORITHM,
    IMPOSSIBILITY_PROOF_CHECKER_ROLE,
    IMPOSSIBILITY_PROOF_VALIDATION_RECEIPT_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_ENUMERAND_RESULTS_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_FACTS_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_INPUT_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_INPUT_VERSION,
    IMPOSSIBILITY_VERIFIER_OBJECT_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_OBJECT_MANIFEST_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_OBJECT_MANIFEST_VERSION,
    IMPOSSIBILITY_VERIFIER_RECEIPT_BINDINGS_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_REFUTATION_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_REFUTATION_RECEIPT_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_ROLE_HASH_ALGORITHM,
    STATISTICAL_CLAIM_STATES,
} from "./constants.mjs";
import {
    canonicalEqual,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    enumerandArtifactMeasurementHash,
    enumerandBinding,
    normalizeEnumerandManifest,
} from "./enumerands.mjs";
import {
    deriveReplicationControlBinding,
    normalizeRawMeasurementSeries,
    normalizeReplicationSchedule,
    replicationBlockPlan,
} from "./replication.mjs";
import {
    createCandidateStatisticalClaimPlan,
    evaluateReplicationProgress,
    evaluateReplicatedStatisticalClaims,
    prepareReplicatedStatisticalEvaluation,
} from "./statistical-evaluation.mjs";

const SAFE_ID = /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;
const VERIFIER_MODES = Object.freeze([
    "enumerand_reexecution",
    "certificate_validation",
]);

function fail(message, details = null) {
    const error = new TypeError(message);
    error.code = "CRUCIBLE_IMPOSSIBILITY_PROTOCOL_INVALID";
    if (details !== null) error.details = details;
    throw error;
}

function requireObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)) {
        fail(`${field} must be a plain object`, { field });
    }
    return value;
}

function requireExactKeys(value, field, keys) {
    const input = requireObject(value, field);
    const actual = Object.keys(input).sort();
    const expected = [...keys].sort();
    if (!canonicalEqual(actual, expected)) {
        fail(`${field} must contain exactly the canonical fields`, {
            field,
            actual,
            expected,
        });
    }
    return input;
}

function requireString(value, field, maximum = 4096) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > maximum
        || value.includes("\0")) {
        fail(`${field} must be a non-empty bounded string`, { field });
    }
    return value;
}

function requireId(value, field) {
    const id = requireString(value, field, 128);
    if (!SAFE_ID.test(id) || id === "." || id === "..") {
        fail(`${field} must be a safe identifier`, { field, value });
    }
    return id;
}

function requireHash(value, field) {
    if (!isAlgorithmTaggedSha256(value)) {
        fail(`${field} must be an algorithm-tagged SHA-256 hash`, {
            field,
            value,
        });
    }
    return value;
}

function requireInteger(value, field, minimum = 0) {
    if (!Number.isSafeInteger(value) || value < minimum) {
        fail(`${field} must be a safe integer >= ${minimum}`, { field, value });
    }
    return value;
}

function requireBoolean(value, field) {
    if (typeof value !== "boolean") {
        fail(`${field} must be boolean`, { field, value });
    }
    return value;
}

function normalizeCertificateFormat(value, field) {
    if (value === null) return null;
    const input = requireExactKeys(value, field, ["schemaHash", "version"]);
    return {
        version: requireString(input.version, `${field}.version`, 256),
        schemaHash: requireHash(input.schemaHash, `${field}.schemaHash`),
    };
}

export function deriveImpossibilityVerdict(checkerResult) {
    switch (checkerResult?.status) {
        case "VERIFIED":
            return "target_unreachable";
        case "REJECTED":
            return "not_proven";
        case "INCONCLUSIVE":
            return "inconclusive";
        case "INVALID":
        default:
            return "invalid";
    }
}

export function isImpossibilityVerdict(value) {
    return IMPOSSIBILITY_VERDICTS.includes(value);
}

export function impossibilitySearchEvidenceHash(candidates) {
    return hashCanonical(
        [...candidates]
            .map((evidence) => ({
                acceptanceSatisfied: evidence.acceptanceSatisfied,
                candidateArtifactHash:
                    evidence.receipt?.candidateArtifactHash ?? null,
                candidateId: evidence.candidateId,
                contentHash: evidence.contentHash,
                enumerandHash: evidence.enumerandHash ?? null,
                enumerandManifestRoot:
                    evidence.enumerandManifestRoot ?? null,
                enumerandOrdinal: evidence.enumerandOrdinal ?? null,
                evidenceHash: evidence.commitEventHash,
                evidenceId: evidence.evidenceId,
                outcomeClass: evidence.outcomeClass,
                provenanceRoot: evidence.provenanceRoot,
                rankable: evidence.rankable,
                rawAuthorityDigest: evidence.rawAuthorityDigest,
                replicationControl:
                    evidence.replication?.control ?? null,
                replicationEvaluationHash:
                    evidence.replication?.evaluationHash ?? null,
                round: evidence.round,
                slotIndex: evidence.slotIndex,
            }))
            .sort((left, right) =>
                (left.enumerandOrdinal ?? Number.MAX_SAFE_INTEGER)
                    - (right.enumerandOrdinal ?? Number.MAX_SAFE_INTEGER)
                || left.round - right.round
                || left.slotIndex - right.slotIndex
                || left.evidenceId.localeCompare(right.evidenceId)),
        IMPOSSIBILITY_SEARCH_EVIDENCE_HASH_ALGORITHM,
    );
}

function ownEntry(record, key) {
    return record !== null
        && typeof record === "object"
        && typeof key === "string"
        && Object.hasOwn(record, key)
        ? record[key]
        : null;
}

function candidateEvidenceItems(aggregate, { includeInvalidated = false } = {}) {
    return (aggregate?.evidenceOrder ?? [])
        .map((evidenceId) => ownEntry(aggregate.evidence, evidenceId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
            && evidence.purpose === "candidate"
            && (includeInvalidated || evidence.invalidated !== true));
}

function manifestOptions(contract) {
    return {
        topology: contract.enumerandManifest?.topology
            ?? contract.hypothesisTopology,
        observableRegistry: contract.observableRegistry,
        hypothesisPolicy: contract.hypothesisPolicy,
    };
}

function enumerandKey(ordinal, enumerandHash) {
    return `${ordinal}:${enumerandHash}`;
}

function sortedMissing(items) {
    return [...new Set(items)].sort();
}

function measurementReceiptProjection(measurement) {
    return {
        subjectId: measurement.subjectId,
        role: measurement.role,
        phase: measurement.phase,
        parserVersion: measurement.parserVersion,
        measurementRoot: measurement.measurementRoot,
        receiptHash: measurement.receiptHash,
        rawStdoutHash: measurement.rawStdoutHash,
        rawStderrHash: measurement.rawStderrHash,
        snapshotHash: measurement.snapshot.snapshotHash,
        snapshotClosureRoot: measurement.snapshot.closureRoot,
        sandboxPolicy: measurement.sandboxPolicy,
    };
}

function validateMeasurementReceipts({
    attempts,
    measurements,
    expectedRole,
    expectedPhase,
    expectedParserVersion,
}) {
    const missing = [];
    const bySubject = new Map();
    for (const measurement of measurements) {
        if (bySubject.has(measurement.subjectId)) {
            missing.push(`duplicate_role_receipt:${measurement.subjectId}`);
            continue;
        }
        bySubject.set(measurement.subjectId, measurement);
    }
    const receipts = attempts.map((attempt) => {
        const measurement = bySubject.get(attempt.subjectId) ?? null;
        if (measurement === null) {
            missing.push(`missing_role_receipt:${attempt.subjectId}`);
            return {
                subjectId: attempt.subjectId,
                role: expectedRole,
                phase: expectedPhase,
                parserVersion: expectedParserVersion,
                measurementRoot: attempt.measurementRoot,
                receiptHash: attempt.receiptHash,
                rawStdoutHash: null,
                rawStderrHash: null,
                snapshotHash: null,
                snapshotClosureRoot: null,
                sandboxPolicy: null,
            };
        }
        if (measurement.role !== expectedRole
            || measurement.phase !== expectedPhase
            || measurement.parserVersion !== expectedParserVersion
            || measurement.receiptHash !== attempt.receiptHash
            || measurement.measurementRoot !== attempt.measurementRoot) {
            missing.push(`invalid_role_receipt:${attempt.subjectId}`);
        }
        return measurementReceiptProjection(measurement);
    }).sort((left, right) => left.subjectId.localeCompare(right.subjectId));
    const expectedSubjects = new Set(attempts.map((attempt) => attempt.subjectId));
    for (const measurement of measurements) {
        if (!expectedSubjects.has(measurement.subjectId)) {
            missing.push(`unexpected_role_receipt:${measurement.subjectId}`);
        }
    }
    return { missing, receipts };
}

function expectedCandidateArtifactHash(entry, topology) {
    return topology === "finite_enumerable"
        ? enumerandArtifactMeasurementHash(entry.artifactSnapshotHash)
        : null;
}

function enumerandEntryProjection(entry, topology) {
    return {
        id: entry.id,
        ordinal: entry.ordinal,
        enumerandHash: entry.enumerandHash,
        contentIdentity: topology === "finite_enumerable"
            ? entry.artifactSnapshotHash
            : entry.parameterTupleHash,
    };
}

function projectEnumerandEvidence(
    aggregate,
    manifest,
    entry,
    evidence,
    lineage,
) {
    const missing = [];
    const entryProjection = enumerandEntryProjection(entry, manifest.topology);
    if (evidence === null) {
        return {
            missing: [`enumerand:${entry.ordinal}:missing`],
            projection: {
                ...entryProjection,
                status: "MISSING",
                evidence: null,
                command: null,
                claims: [],
                blockCount: 0,
                blockLedgerHash: null,
                statisticalEvaluationHash: null,
                controlBindingHash: null,
                rawBlocksRoot: null,
                roleReceiptsRoot: null,
                alphaAllocationsRoot: null,
            },
        };
    }
    const observation = ownEntry(aggregate.observations, evidence.observationId);
    const command = observation === null
        ? null
        : ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
    let claims = [];
    let blockCount = evidence.replication?.blockCount ?? 0;
    let blockLedgerHash = evidence.replication?.blockLedgerHash ?? null;
    let statisticalEvaluationHash =
        evidence.statisticalEvaluation?.evaluationHash ?? null;
    let controlBindingHash =
        evidence.replication?.control?.controlBindingHash ?? null;
    let rawBlocksRoot = null;
    let roleReceiptsRoot = null;
    let alphaAllocationsRoot = null;
    try {
        const expectedBinding = enumerandBinding(
            manifest,
            entry,
            manifestOptions(aggregate.contract),
        );
        const globalSlot = command === null
            ? null
            : (command.round - 1) * aggregate.contract.candidatesPerRound
                + command.slotIndex;
        const expectedReplacementOrdinal = lineage.filter((item) =>
            item.invalidated === true
            && item.round === evidence.round
            && item.slotIndex === evidence.slotIndex
            && item.committedSeq < evidence.committedSeq).length;
        if (observation === null
            || command?.kind !== "search_candidate"
            || evidence.invalidated === true
            || !isAlgorithmTaggedSha256(evidence.commitEventHash)
            || !isAlgorithmTaggedSha256(evidence.rawAuthorityDigest)
            || !isAlgorithmTaggedSha256(evidence.provenanceRoot)
            || globalSlot !== entry.ordinal
            || command.candidateId !== entry.id
            || command.replacementOrdinal !== expectedReplacementOrdinal
            || evidence.round !== command.round
            || evidence.slotIndex !== command.slotIndex
            || evidence.candidateId !== command.candidateId
            || evidence.enumerandOrdinal !== entry.ordinal
            || evidence.enumerandHash !== entry.enumerandHash
            || evidence.enumerandManifestRoot !== manifest.merkleRoot
            || !canonicalEqual(command.enumerand, expectedBinding)) {
            missing.push(`enumerand:${entry.ordinal}:binding`);
        }
        const candidateArtifactHash =
            evidence.receipt?.candidateArtifactHash ?? null;
        const expectedArtifactHash = expectedCandidateArtifactHash(
            entry,
            manifest.topology,
        );
        if (!isAlgorithmTaggedSha256(candidateArtifactHash)
            || (expectedArtifactHash !== null
                && candidateArtifactHash !== expectedArtifactHash)) {
            missing.push(`enumerand:${entry.ordinal}:artifact`);
        }
        const rawSeries = normalizeRawMeasurementSeries(
            observation.data.series[0],
            {
                schedule: command.replicationSchedule,
                role: "search",
                phase: "search",
                caseId: null,
            },
        );
        const claimPlan = createCandidateStatisticalClaimPlan({
            contract: aggregate.contract,
            hypotheses: command.hypotheses,
            assignedParentEvidenceIds: command.parentEvidenceIds,
        });
        const prepared = prepareReplicatedStatisticalEvaluation({
            contract: aggregate.contract,
            schedule: command.replicationSchedule,
            attempts: rawSeries.attempts,
            parentEvidence: {},
        });
        const evaluation = evaluateReplicatedStatisticalClaims({
            contract: aggregate.contract,
            schedule: command.replicationSchedule,
            attempts: rawSeries.attempts,
            claims: claimPlan.acceptanceClaims,
            requiredClaimIds: claimPlan.acceptanceClaimIds,
            allocationClaims: claimPlan.allocationClaims,
            parentEvidence: {},
            prepared,
        });
        const stopping = evaluateReplicationProgress({
            contract: aggregate.contract,
            schedule: command.replicationSchedule,
            attempts: rawSeries.attempts,
            claims: claimPlan.acceptanceClaims,
            requiredClaimIds: claimPlan.acceptanceClaimIds,
        });
        if (!canonicalEqual(
            evidence.statisticalEvaluation?.statistics ?? null,
            evaluation.statistics,
        )
            || !canonicalEqual(
                evidence.statisticalEvaluation?.blockLedger ?? null,
                evaluation.blockLedger,
            )
            || !canonicalEqual(
                evidence.statisticalEvaluation?.controlTolerance ?? null,
                evaluation.controlTolerance,
            )
            || !canonicalEqual(
                evidence.replication?.stopping ?? null,
                stopping.stopping,
            )
            || evidence.replication?.stoppingDigest
                !== stopping.stoppingDigest
            || evidence.replication?.scheduleHash
                !== command.replicationSchedule.scheduleHash
            || evidence.replication?.blockCount !== evaluation.blockCount
            || evidence.replication?.attemptCount !== evaluation.attemptCount
            || evidence.replication?.blockLedgerHash
                !== evaluation.blockLedger.hash
            || evidence.replication?.statisticalState
                !== evaluation.requiredState
            || !isAlgorithmTaggedSha256(
                evidence.statisticalEvaluation?.evaluationHash,
            )) {
            missing.push(`enumerand:${entry.ordinal}:statistical_replay`);
        }
        const byClaimId = new Map(
            (evaluation.statistics?.claims ?? [])
                .map((claim) => [claim.id, claim]),
        );
        claims = aggregate.contract.acceptanceClaimSet.requiredClaimIds
            .map((claimId) => {
                const claim = byClaimId.get(claimId) ?? null;
                if (claim === null) {
                    missing.push(
                        `enumerand:${entry.ordinal}:claim:${claimId}:missing`,
                    );
                    return {
                        claimId,
                        state: "INVALID",
                        allocation: null,
                    };
                }
                if (claim.state !== "REFUTED") {
                    missing.push(
                        `enumerand:${entry.ordinal}:claim:${claimId}:${
                            String(claim.state).toLowerCase()
                        }`,
                    );
                }
                if (claim.allocation === null
                    || typeof claim.allocation !== "object") {
                    missing.push(
                        `enumerand:${entry.ordinal}:claim:${claimId}:alpha`,
                    );
                }
                return {
                    claimId,
                    state: claim.state,
                    allocation: claim.allocation ?? null,
                };
            });
        if (evaluation.completeValidBlocks !== true
            || evaluation.exclusions.length !== 0
            || evaluation.requiredState !== "REFUTED"
            || evidence.acceptanceSatisfied !== false
            || evidence.outcomeClass !== "rejected"
            || stopping.shouldContinue
            || evaluation.blockCount < command.replicationSchedule.minBlocks
            || evaluation.blockCount > command.replicationSchedule.maxBlocks) {
            missing.push(`enumerand:${entry.ordinal}:terminal_grade`);
        }
        if (evaluation.controlTolerance?.status !== "within_tolerance") {
            missing.push(`enumerand:${entry.ordinal}:control_drift`);
        }
        const schedule = normalizeReplicationSchedule(
            command.replicationSchedule,
        );
        const measurements =
            evidence.receipt?.provenance?.measurements ?? [];
        const receiptCheck = validateMeasurementReceipts({
            attempts: rawSeries.attempts,
            measurements,
            expectedRole: "search",
            expectedPhase: "search",
            expectedParserVersion:
                aggregate.contract.harnessSuite.roles.search.parser.version,
        });
        missing.push(...receiptCheck.missing.map((item) =>
            `enumerand:${entry.ordinal}:${item}`));
        const bySubject = new Map(
            measurements.map((measurement) => [
                measurement.subjectId,
                measurement,
            ]),
        );
        for (const attempt of rawSeries.attempts) {
            if (attempt.armId === "candidate"
                && bySubject.get(attempt.subjectId)?.snapshot?.snapshotHash
                    !== candidateArtifactHash) {
                missing.push(`enumerand:${entry.ordinal}:candidate_receipt`);
            }
        }
        const controlSnapshotHashes = rawSeries.series.completeBlocks.flatMap(
            (block) => replicationBlockPlan(
                schedule,
                block.blockIndex,
            ).arms.filter((arm) => arm.armId === "control")
                .map((arm) =>
                    bySubject.get(arm.subjectId)?.snapshot?.snapshotHash
                        ?? null),
        );
        if (controlSnapshotHashes.some((hash) => hash === null)) {
            missing.push(`enumerand:${entry.ordinal}:control_receipt`);
        }
        const control = deriveReplicationControlBinding({
            contractHash: aggregate.contractHash,
            statisticalPolicy: aggregate.contract.statisticalPolicy,
            schedule,
            enumerandManifest: manifest,
            manifestOptions: manifestOptions(aggregate.contract),
            controlSnapshotHashes,
            requireObservedControl: true,
        });
        if (!canonicalEqual(evidence.replication?.control ?? null, control)) {
            missing.push(`enumerand:${entry.ordinal}:control_binding`);
        }
        blockCount = evaluation.blockCount;
        blockLedgerHash = evaluation.blockLedger.hash;
        statisticalEvaluationHash =
            evidence.statisticalEvaluation.evaluationHash;
        controlBindingHash = control.controlBindingHash;
        rawBlocksRoot = hashCanonical(
            rawSeries.series.completeBlocks,
            IMPOSSIBILITY_RAW_BLOCK_ROOTS_HASH_ALGORITHM,
        );
        roleReceiptsRoot = hashCanonical(
            receiptCheck.receipts,
            IMPOSSIBILITY_ROLE_RECEIPTS_HASH_ALGORITHM,
        );
        alphaAllocationsRoot = hashCanonical(
            claims.map((claim) => ({
                claimId: claim.claimId,
                allocation: claim.allocation,
            })),
            IMPOSSIBILITY_ALPHA_ALLOCATIONS_HASH_ALGORITHM,
        );
    } catch {
        missing.push(`enumerand:${entry.ordinal}:invalid_evidence`);
    }
    const projection = {
        ...entryProjection,
        status: missing.length === 0 ? "REFUTED" : "INCOMPLETE",
        evidence: {
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash ?? null,
            rawAuthorityDigest: evidence.rawAuthorityDigest ?? null,
            provenanceRoot: evidence.provenanceRoot ?? null,
            candidateArtifactHash:
                evidence.receipt?.candidateArtifactHash ?? null,
        },
        command: command === null
            ? null
            : {
                commandId: observation.commandId,
                round: command.round,
                slotIndex: command.slotIndex,
                candidateId: command.candidateId,
                replacementOrdinal: command.replacementOrdinal,
                scheduleHash:
                    command.replicationSchedule?.scheduleHash ?? null,
            },
        claims,
        blockCount,
        blockLedgerHash,
        statisticalEvaluationHash,
        controlBindingHash,
        rawBlocksRoot,
        roleReceiptsRoot,
        alphaAllocationsRoot,
    };
    return { missing, projection };
}

function projectCalibrationEvidence(aggregate, validation) {
    const missing = [];
    if (validation === null || validation === undefined) {
        return {
            missing: ["calibration:missing"],
            projection: {
                status: "MISSING",
                evidenceId: null,
                evidenceHash: null,
                basisEvidenceIds: [],
                evaluations: [],
                controlsRoot: null,
                rawBlocksRoot: null,
                roleReceiptsRoot: null,
            },
        };
    }
    const basisEvidenceIds =
        validation.validationBasisEvidenceIds ?? [];
    const expectedPairs = aggregate.contract.validationRoles.flatMap((role) =>
        aggregate.contract.validationCases.map((validationCase) =>
            `${role}\0${validationCase.id}`)).sort();
    const evaluations =
        validation.validationEvaluation?.evaluations ?? [];
    const actualPairs = evaluations
        .map((item) => `${item.role}\0${item.caseId}`)
        .sort();
    if (validation.invalidated === true
        || validation.validationSatisfied !== true
        || validation.validationEvaluation?.satisfied !== true
        || !isAlgorithmTaggedSha256(validation.commitEventHash)
        || !isAlgorithmTaggedSha256(validation.rawAuthorityDigest)
        || !isAlgorithmTaggedSha256(validation.provenanceRoot)
        || !canonicalEqual(actualPairs, expectedPairs)
        || basisEvidenceIds.length === 0) {
        missing.push("calibration:incomplete");
    }
    const evaluationProjection = evaluations.map((item) => {
        if (item.satisfied !== true
            || item.actualState !== item.expectedState
            || item.evaluation?.completeValidBlocks !== true
            || (item.evaluation?.exclusions?.length ?? -1) !== 0
            || !isAlgorithmTaggedSha256(item.evaluation?.evaluationHash)
            || !isAlgorithmTaggedSha256(item.evaluation?.blockLedger?.hash)) {
            missing.push(`calibration:${item.role}:${item.caseId}:invalid`);
        }
        return {
            role: item.role,
            executionRole: item.executionRole,
            caseId: item.caseId,
            expectedState: item.expectedState,
            actualState: item.actualState,
            evaluationHash: item.evaluation?.evaluationHash ?? null,
            blockLedgerHash: item.evaluation?.blockLedger?.hash ?? null,
        };
    }).sort((left, right) =>
        `${left.role}\0${left.caseId}`.localeCompare(
            `${right.role}\0${right.caseId}`,
        ));
    const rawSeries = [];
    const roleReceipts = [];
    const controls = [];
    for (const evidenceId of basisEvidenceIds) {
        const evidence = ownEntry(aggregate.evidence, evidenceId);
        const observation = evidence === null
            ? null
            : ownEntry(aggregate.observations, evidence.observationId);
        const command = observation === null
            ? null
            : ownEntry(aggregate.commands, observation.commandId)?.command
                ?? null;
        if (evidence === null
            || evidence.invalidated === true
            || evidence.sourceKind !== "harness"
            || evidence.purpose !== "validation"
            || observation === null
            || command?.kind !== "run_validation"
            || !Array.isArray(command.validationSeries)
            || !Array.isArray(observation.data?.series)) {
            missing.push(`calibration:basis:${evidenceId}:invalid`);
            continue;
        }
        const measurementList =
            evidence.receipt?.provenance?.measurements ?? [];
        const measurementsBySubject = new Map(
            measurementList.map((measurement) => [
                measurement.subjectId,
                measurement,
            ]),
        );
        for (const series of command.validationSeries) {
            const raw = observation.data.series.find((candidate) =>
                candidate.role === series.role
                && candidate.caseId === series.caseId);
            try {
                const normalized = normalizeRawMeasurementSeries(raw, {
                    schedule: series.replicationSchedule,
                    role: series.role,
                    phase: "calibration",
                    caseId: series.caseId,
                });
                const receipts = validateMeasurementReceipts({
                    attempts: normalized.attempts,
                    measurements: normalized.attempts.map((attempt) =>
                        measurementsBySubject.get(attempt.subjectId))
                        .filter((measurement) => measurement !== undefined),
                    expectedRole: series.role,
                    expectedPhase: "calibration",
                    expectedParserVersion:
                        aggregate.contract.harnessSuite.roles[
                            series.role
                        ].parser.version,
                });
                missing.push(...receipts.missing.map((item) =>
                    `calibration:${series.role}:${series.caseId}:${item}`));
                rawSeries.push({
                    evidenceId,
                    role: series.role,
                    coveredRoles: series.coveredRoles,
                    caseId: series.caseId,
                    scheduleHash: series.replicationSchedule.scheduleHash,
                    rawBlocksRoot: hashCanonical(
                        normalized.series.completeBlocks,
                        IMPOSSIBILITY_RAW_BLOCK_ROOTS_HASH_ALGORITHM,
                    ),
                });
                roleReceipts.push(...receipts.receipts.map((receipt) => ({
                    evidenceId,
                    caseId: series.caseId,
                    coveredRoles: series.coveredRoles,
                    ...receipt,
                })));
            } catch {
                missing.push(
                    `calibration:${series.role}:${series.caseId}:invalid_series`,
                );
            }
        }
        const expectedSubjects = new Set(
            roleReceipts
                .filter((receipt) => receipt.evidenceId === evidenceId)
                .map((receipt) => receipt.subjectId),
        );
        for (const measurement of measurementList) {
            if (!expectedSubjects.has(measurement.subjectId)) {
                missing.push(
                    `calibration:basis:${evidenceId}:unexpected_role_receipt:${
                        measurement.subjectId
                    }`,
                );
            }
        }
        for (const control of evidence.validationControlBindings ?? []) {
            if (!isAlgorithmTaggedSha256(control.controlBindingHash)
                || !command.validationSeries.some((series) =>
                    series.replicationSchedule.scheduleHash
                        === control.scheduleHash)) {
                missing.push(`calibration:basis:${evidenceId}:control`);
            }
            controls.push({ evidenceId, ...control });
        }
        if ((evidence.validationControlBindings?.length ?? -1)
            !== command.validationSeries.length) {
            missing.push(`calibration:basis:${evidenceId}:controls_incomplete`);
        }
    }
    rawSeries.sort((left, right) =>
        `${left.evidenceId}\0${left.role}\0${left.caseId}`.localeCompare(
            `${right.evidenceId}\0${right.role}\0${right.caseId}`,
        ));
    roleReceipts.sort((left, right) =>
        `${left.evidenceId}\0${left.subjectId}`.localeCompare(
            `${right.evidenceId}\0${right.subjectId}`,
        ));
    controls.sort((left, right) =>
        `${left.evidenceId}\0${left.scheduleHash}`.localeCompare(
            `${right.evidenceId}\0${right.scheduleHash}`,
        ));
    return {
        missing,
        projection: {
            status: missing.length === 0 ? "COMPLETE" : "INCOMPLETE",
            evidenceId: validation.evidenceId,
            evidenceHash: validation.commitEventHash,
            rawAuthorityDigest: validation.rawAuthorityDigest,
            provenanceRoot: validation.provenanceRoot,
            basisEvidenceIds: [...basisEvidenceIds],
            evaluations: evaluationProjection,
            controlsRoot: hashCanonical(
                controls,
                IMPOSSIBILITY_CONTROL_EVIDENCE_HASH_ALGORITHM,
            ),
            rawBlocksRoot: hashCanonical(
                rawSeries,
                IMPOSSIBILITY_RAW_BLOCK_ROOTS_HASH_ALGORITHM,
            ),
            roleReceiptsRoot: hashCanonical(
                roleReceipts,
                IMPOSSIBILITY_ROLE_RECEIPTS_HASH_ALGORITHM,
            ),
        },
    };
}

function candidateLineageProjection(aggregate) {
    return candidateEvidenceItems(
        aggregate,
        { includeInvalidated: true },
    ).map((evidence) => {
        const observation = ownEntry(
            aggregate.observations,
            evidence.observationId,
        );
        const command = observation === null
            ? null
            : ownEntry(aggregate.commands, observation.commandId)?.command
                ?? null;
        return {
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash ?? null,
            candidateId: evidence.candidateId ?? null,
            candidateArtifactHash:
                evidence.receipt?.candidateArtifactHash ?? null,
            enumerandOrdinal: evidence.enumerandOrdinal ?? null,
            enumerandHash: evidence.enumerandHash ?? null,
            round: evidence.round ?? null,
            slotIndex: evidence.slotIndex ?? null,
            replacementOrdinal: command?.replacementOrdinal ?? null,
            committedSeq: evidence.committedSeq ?? null,
            invalidated: evidence.invalidated === true,
            invalidatedSeq: evidence.invalidatedSeq ?? null,
            invalidationReason: evidence.invalidationReason ?? null,
        };
    }).sort((left, right) =>
        (left.enumerandOrdinal ?? Number.MAX_SAFE_INTEGER)
            - (right.enumerandOrdinal ?? Number.MAX_SAFE_INTEGER)
        || (left.replacementOrdinal ?? Number.MAX_SAFE_INTEGER)
            - (right.replacementOrdinal ?? Number.MAX_SAFE_INTEGER)
        || left.committedSeq - right.committedSeq
        || left.evidenceId.localeCompare(right.evidenceId));
}

export function deriveUnreachableCoverageClosure(aggregate) {
    const missing = [];
    const contract = aggregate?.contract ?? null;
    if (contract === null
        || contract.enumerandManifest === undefined
        || contract.enumerandManifest === null) {
        const closure = immutableCanonical({
            version: IMPOSSIBILITY_COVERAGE_CLOSURE_VERSION,
            complete: false,
            manifest: null,
            enumerands: [],
            calibration: null,
            evidenceLineage: [],
            invalidationsRoot: hashCanonical(
                [],
                IMPOSSIBILITY_INVALIDATION_ROOT_HASH_ALGORITHM,
            ),
            enumerandEvidenceRoot: hashCanonical(
                [],
                IMPOSSIBILITY_ENUMERAND_EVIDENCE_HASH_ALGORITHM,
            ),
            rawBlockRoots: hashCanonical(
                [],
                IMPOSSIBILITY_RAW_BLOCK_ROOTS_HASH_ALGORITHM,
            ),
            roleReceiptsRoot: hashCanonical(
                [],
                IMPOSSIBILITY_ROLE_RECEIPTS_HASH_ALGORITHM,
            ),
            alphaAllocationsRoot: hashCanonical(
                [],
                IMPOSSIBILITY_ALPHA_ALLOCATIONS_HASH_ALGORITHM,
            ),
            scientificReplayRoot: null,
            alphaLedgerRoot: null,
            missing: ["finite_immutable_enumerand_manifest"],
        });
        return immutableCanonical({
            eligible: false,
            missing: closure.missing,
            closure: {
                ...closure,
                closureRoot: hashCanonical(
                    closure,
                    IMPOSSIBILITY_COVERAGE_CLOSURE_HASH_ALGORITHM,
                ),
            },
        });
    }
    let manifest;
    try {
        manifest = normalizeEnumerandManifest(
            contract.enumerandManifest,
            manifestOptions(contract),
        );
    } catch {
        missing.push("finite_immutable_enumerand_manifest");
        manifest = contract.enumerandManifest;
    }
    if (manifest.topology !== "finite_enumerable"
        && manifest.topology !== "bounded_parameterized") {
        missing.push("finite_immutable_enumerand_manifest");
    }
    const lineage = candidateLineageProjection(aggregate);
    const active = candidateEvidenceItems(aggregate);
    const activeByEnumerand = new Map();
    for (const evidence of active) {
        const key = enumerandKey(
            evidence.enumerandOrdinal,
            evidence.enumerandHash,
        );
        const items = activeByEnumerand.get(key) ?? [];
        items.push(evidence);
        activeByEnumerand.set(key, items);
    }
    const manifestKeys = new Set(manifest.entries.map((entry) =>
        enumerandKey(entry.ordinal, entry.enumerandHash)));
    for (const evidence of active) {
        const key = enumerandKey(
            evidence.enumerandOrdinal,
            evidence.enumerandHash,
        );
        if (!manifestKeys.has(key)) {
            missing.push(`off_manifest_evidence:${evidence.evidenceId}`);
        }
    }
    const enumerands = manifest.entries.map((entry) => {
        const items = activeByEnumerand.get(
            enumerandKey(entry.ordinal, entry.enumerandHash),
        ) ?? [];
        if (items.length > 1) {
            missing.push(`enumerand:${entry.ordinal}:duplicate_evidence`);
        }
        const projected = projectEnumerandEvidence(
            aggregate,
            manifest,
            entry,
            items.length === 1 ? items[0] : null,
            lineage,
        );
        missing.push(...projected.missing);
        return projected.projection;
    });
    const activeArtifactOwners = new Map();
    for (const enumerand of enumerands) {
        const artifactHash = enumerand.evidence?.candidateArtifactHash ?? null;
        if (!isAlgorithmTaggedSha256(artifactHash)) continue;
        const owners = activeArtifactOwners.get(artifactHash) ?? [];
        owners.push(enumerand.ordinal);
        activeArtifactOwners.set(artifactHash, owners);
    }
    for (const owners of activeArtifactOwners.values()) {
        if (owners.length < 2) continue;
        for (const ordinal of owners) {
            missing.push(`enumerand:${ordinal}:duplicate_artifact`);
        }
    }
    const validationId = aggregate?.validation?.currentEvidenceId ?? null;
    const validation = ownEntry(aggregate.evidence, validationId);
    const calibration = projectCalibrationEvidence(aggregate, validation);
    missing.push(...calibration.missing);
    const scientificReplayRoot =
        aggregate.scientificReplay?.closureRoot ?? null;
    const alphaLedgerRoot =
        aggregate.scientificReplay?.alphaLedgerHash ?? null;
    if (!isAlgorithmTaggedSha256(scientificReplayRoot)) {
        missing.push("scientific_replay_closure");
    }
    if (!isAlgorithmTaggedSha256(alphaLedgerRoot)) {
        missing.push("statistical_alpha_ledger");
    }
    const normalizedMissing = sortedMissing(missing);
    const core = {
        version: IMPOSSIBILITY_COVERAGE_CLOSURE_VERSION,
        complete: normalizedMissing.length === 0,
        manifest: {
            topology: manifest.topology,
            merkleRoot: manifest.merkleRoot,
            count: manifest.entries.length,
            control: manifest.control,
        },
        enumerands,
        calibration: calibration.projection,
        evidenceLineage: lineage,
        invalidationsRoot: hashCanonical(
            lineage,
            IMPOSSIBILITY_INVALIDATION_ROOT_HASH_ALGORITHM,
        ),
        enumerandEvidenceRoot: hashCanonical(
            enumerands,
            IMPOSSIBILITY_ENUMERAND_EVIDENCE_HASH_ALGORITHM,
        ),
        rawBlockRoots: hashCanonical(
            {
                calibration: calibration.projection.rawBlocksRoot,
                enumerands: enumerands.map((item) => ({
                    ordinal: item.ordinal,
                    rawBlocksRoot: item.rawBlocksRoot,
                })),
            },
            IMPOSSIBILITY_RAW_BLOCK_ROOTS_HASH_ALGORITHM,
        ),
        roleReceiptsRoot: hashCanonical(
            {
                calibration: calibration.projection.roleReceiptsRoot,
                enumerands: enumerands.map((item) => ({
                    ordinal: item.ordinal,
                    roleReceiptsRoot: item.roleReceiptsRoot,
                })),
            },
            IMPOSSIBILITY_ROLE_RECEIPTS_HASH_ALGORITHM,
        ),
        alphaAllocationsRoot: hashCanonical(
            enumerands.map((item) => ({
                ordinal: item.ordinal,
                alphaAllocationsRoot: item.alphaAllocationsRoot,
            })),
            IMPOSSIBILITY_ALPHA_ALLOCATIONS_HASH_ALGORITHM,
        ),
        scientificReplayRoot,
        alphaLedgerRoot,
        missing: normalizedMissing,
    };
    return immutableCanonical({
        eligible: core.complete,
        missing: normalizedMissing,
        closure: {
            ...core,
            closureRoot: hashCanonical(
                core,
                IMPOSSIBILITY_COVERAGE_CLOSURE_HASH_ALGORITHM,
            ),
        },
    });
}

function verifierRoleIdentity(role) {
    return hashCanonical(role, IMPOSSIBILITY_VERIFIER_ROLE_HASH_ALGORITHM);
}

function objectDigest(objectId) {
    if (typeof objectId !== "string"
        || !/^sha256:[a-f0-9]{64}$/u.test(objectId)) {
        fail("verifier request object id must be a raw SHA-256 object id", {
            objectId,
        });
    }
    return objectId.slice("sha256:".length);
}

function objectIdForCanonical(value) {
    return `sha256:${createHash("sha256")
        .update(canonicalJson(value), "utf8")
        .digest("hex")}`;
}

function taggedObjectHash(objectId, algorithm) {
    return `${algorithm}:${objectDigest(objectId)}`;
}

function semanticHashMatchesObject(objectId, semanticHash) {
    return isAlgorithmTaggedSha256(semanticHash)
        && semanticHash.split(":").at(-1) === objectDigest(objectId);
}

function generatedObjectEntry(path, value, semanticHashAlgorithm) {
    const objectId = objectIdForCanonical(value);
    return {
        path,
        kind: "generated",
        objectId,
        byteHash: taggedObjectHash(
            objectId,
            IMPOSSIBILITY_VERIFIER_OBJECT_HASH_ALGORITHM,
        ),
        artifactIds: [],
        semanticHashes: [
            taggedObjectHash(objectId, semanticHashAlgorithm),
        ],
    };
}

function addCasObject(entriesByPath, artifact, semanticHashes = []) {
    if (artifact === null
        || typeof artifact !== "object"
        || typeof artifact.artifactId !== "string") {
        fail("verifier request artifact reference is invalid");
    }
    const digest = objectDigest(artifact.objectId);
    const path = `objects/${digest.slice(0, 2)}/${digest}`;
    const hashes = semanticHashes.filter((hash) => hash !== null);
    if (hashes.some((hash) =>
        !semanticHashMatchesObject(artifact.objectId, hash))) {
        fail("verifier request artifact hash does not match its object id", {
            artifactId: artifact.artifactId,
            objectId: artifact.objectId,
            semanticHashes: hashes,
        });
    }
    const existing = entriesByPath.get(path);
    const entry = existing ?? {
        path,
        kind: "cas_object",
        objectId: artifact.objectId,
        byteHash: taggedObjectHash(
            artifact.objectId,
            IMPOSSIBILITY_VERIFIER_OBJECT_HASH_ALGORITHM,
        ),
        artifactIds: [],
        semanticHashes: [],
    };
    if (entry.objectId !== artifact.objectId) {
        fail("verifier request object path collision", {
            path,
            left: entry.objectId,
            right: artifact.objectId,
        });
    }
    entry.artifactIds = [...new Set([
        ...entry.artifactIds,
        artifact.artifactId,
    ])].sort();
    entry.semanticHashes = [...new Set([
        ...entry.semanticHashes,
        ...hashes,
    ])].sort();
    entriesByPath.set(path, entry);
}

function addGeneratedObject(entriesByPath, path, value, algorithm) {
    const entry = generatedObjectEntry(path, value, algorithm);
    if (entriesByPath.has(path)) {
        fail("verifier request generated-object path is duplicated", { path });
    }
    entriesByPath.set(path, entry);
    return entry;
}

function measurementVerifierBinding(measurement) {
    return {
        subjectId: measurement.subjectId,
        role: measurement.role,
        phase: measurement.phase,
        parserVersion: measurement.parserVersion,
        measurementRoot: measurement.measurementRoot,
        receiptHash: measurement.receiptHash,
        rawStdoutHash: measurement.rawStdoutHash,
        rawStderrHash: measurement.rawStderrHash,
        snapshotHash: measurement.snapshot.snapshotHash,
        snapshotClosureRoot: measurement.snapshot.closureRoot,
        receiptArtifact: measurement.receiptArtifact,
        rawStdoutArtifact: measurement.rawStdoutArtifact,
        rawStderrArtifact: measurement.rawStderrArtifact,
        snapshotManifestArtifact:
            measurement.snapshot.manifestArtifact,
        snapshotObjectArtifacts:
            measurement.snapshot.objectArtifacts,
    };
}

function addMeasurementObjects(entriesByPath, measurement) {
    addCasObject(
        entriesByPath,
        measurement.receiptArtifact,
        [measurement.receiptHash],
    );
    addCasObject(
        entriesByPath,
        measurement.rawStdoutArtifact,
        [measurement.rawStdoutHash],
    );
    addCasObject(
        entriesByPath,
        measurement.rawStderrArtifact,
        [measurement.rawStderrHash],
    );
    addCasObject(
        entriesByPath,
        measurement.snapshot.manifestArtifact,
        [measurement.snapshot.snapshotHash],
    );
    for (const artifact of measurement.snapshot.objectArtifacts) {
        addCasObject(entriesByPath, artifact);
    }
}

function addEvidenceObjects(entriesByPath, evidence) {
    const provenance = evidence?.receipt?.provenance ?? null;
    if (provenance === null) {
        fail("verifier input evidence is missing provenance", {
            evidenceId: evidence?.evidenceId ?? null,
        });
    }
    for (const artifact of [
        provenance.proposalArtifact,
        provenance.validationCompositeArtifact,
        provenance.measurementReuseArtifact,
        provenance.replicationScheduleArtifact,
        provenance.replicationCompositeArtifact,
    ]) {
        if (artifact !== null) addCasObject(entriesByPath, artifact);
    }
    for (const measurement of provenance.measurements) {
        addMeasurementObjects(entriesByPath, measurement);
    }
}

function verifierReceiptBindings(measurements) {
    const bindings = measurements
        .map(measurementVerifierBinding)
        .sort((left, right) =>
            left.subjectId.localeCompare(right.subjectId));
    return {
        bindings,
        root: hashCanonical(
            bindings,
            IMPOSSIBILITY_VERIFIER_RECEIPT_BINDINGS_HASH_ALGORITHM,
        ),
    };
}

function enumerandVerifierInput(
    aggregate,
    manifestEntry,
    coverageEntry,
    entriesByPath,
) {
    const evidence = ownEntry(
        aggregate.evidence,
        coverageEntry.evidence?.evidenceId ?? null,
    );
    const observation = evidence === null
        ? null
        : ownEntry(aggregate.observations, evidence.observationId);
    const command = observation === null
        ? null
        : ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
    if (evidence === null
        || observation === null
        || command?.kind !== "search_candidate"
        || !Array.isArray(observation.data?.series)
        || observation.data.series.length !== 1) {
        fail("complete coverage is missing a verifier-readable enumerand input", {
            ordinal: coverageEntry.ordinal,
        });
    }
    addEvidenceObjects(entriesByPath, evidence);
    const receiptBindings = verifierReceiptBindings(
        evidence.receipt.provenance.measurements,
    );
    const core = {
        version: IMPOSSIBILITY_VERIFIER_INPUT_VERSION,
        ordinal: coverageEntry.ordinal,
        enumerandHash: coverageEntry.enumerandHash,
        manifestEntry,
        command,
        claimIds: coverageEntry.claims
            .map((claim) => claim.claimId)
            .sort(),
        rawCompleteBlocks: observation.data.series[0],
        receiptBindings: receiptBindings.bindings,
        receiptBindingsRoot: receiptBindings.root,
    };
    const input = {
        ...core,
        inputRoot: hashCanonical(
            core,
            IMPOSSIBILITY_VERIFIER_INPUT_HASH_ALGORITHM,
        ),
    };
    addGeneratedObject(
        entriesByPath,
        `reevaluation/enumerands/${String(coverageEntry.ordinal)
            .padStart(6, "0")}.json`,
        input,
        IMPOSSIBILITY_VERIFIER_INPUT_HASH_ALGORITHM,
    );
    return input;
}

function calibrationVerifierInput(aggregate, validation, entriesByPath) {
    const evidenceIds = validation?.validationBasisEvidenceIds ?? [];
    const evidenceInputs = evidenceIds.map((evidenceId) => {
        const evidence = ownEntry(aggregate.evidence, evidenceId);
        const observation = evidence === null
            ? null
            : ownEntry(aggregate.observations, evidence.observationId);
        const command = observation === null
            ? null
            : ownEntry(aggregate.commands, observation.commandId)?.command
                ?? null;
        if (evidence === null
            || observation === null
            || command?.kind !== "run_validation"
            || !Array.isArray(observation.data?.series)) {
            fail("complete coverage is missing verifier-readable calibration input", {
                evidenceId,
            });
        }
        addEvidenceObjects(entriesByPath, evidence);
        const receiptBindings = verifierReceiptBindings(
            evidence.receipt.provenance.measurements,
        );
        return {
            evidenceId,
            evidenceHash: evidence.commitEventHash,
            command,
            rawCompleteBlocks: observation.data.series,
            receiptBindings: receiptBindings.bindings,
            receiptBindingsRoot: receiptBindings.root,
        };
    }).sort((left, right) => left.evidenceId.localeCompare(right.evidenceId));
    const core = {
        version: IMPOSSIBILITY_VERIFIER_INPUT_VERSION,
        evidence: evidenceInputs,
    };
    const input = {
        ...core,
        inputRoot: hashCanonical(
            core,
            IMPOSSIBILITY_VERIFIER_INPUT_HASH_ALGORITHM,
        ),
    };
    addGeneratedObject(
        entriesByPath,
        "reevaluation/calibration.json",
        input,
        IMPOSSIBILITY_VERIFIER_INPUT_HASH_ALGORITHM,
    );
    return input;
}

function proofCheckerIdentity(verifierRole) {
    if (verifierRole.verificationPolicy.mode !== "certificate_validation") {
        return null;
    }
    const matches = verifierRole.dependencies.filter((dependency) =>
        dependency.role === IMPOSSIBILITY_PROOF_CHECKER_ROLE
        && dependency.kind === "application");
    if (matches.length !== 1) {
        fail("certificate validation requires one separately pinned proof checker");
    }
    const core = {
        role: IMPOSSIBILITY_PROOF_CHECKER_ROLE,
        implementationHash: matches[0].sha256,
        certificateFormat:
            verifierRole.verificationPolicy.certificateFormat,
    };
    return {
        ...core,
        identity: hashCanonical(
            core,
            IMPOSSIBILITY_PROOF_CHECKER_HASH_ALGORITHM,
        ),
    };
}

export function createImpossibilityMeasurementBinding(
    contract,
    requestHash,
    attemptOrdinal,
) {
    requireHash(requestHash, "requestHash");
    requireInteger(attemptOrdinal, "attemptOrdinal", 1);
    return immutableCanonical({
        role: "impossibility_verifier",
        phase: "impossibility_verification",
        replicateIndex: null,
        blockIndex: attemptOrdinal - 1,
        armIndex: null,
        armId: null,
        deterministicSeed: hashCanonical({
            contractHash: hashCanonical(
                contract,
                "sha256:crucible-contract-v4",
            ),
            requestHash,
            attemptOrdinal,
        }, "sha256:crucible-impossibility-measurement-seed-v2"),
        subjectId: `impossibility-${attemptOrdinal}`,
        environmentIdentity: contract.harnessSuite.environmentIdentity,
        suiteIdentity: contract.harnessSuiteIdentity,
    });
}

export function createImpossibilityVerificationPackage(
    aggregate,
    {
        attemptOrdinal,
        progress,
        validation,
    },
) {
    if (aggregate?.contract?.hypothesisTopology !== "certified_impossibility") {
        fail("impossibility verification requires certified_impossibility topology");
    }
    const contract = aggregate.contract;
    const manifest = contract.enumerandManifest;
    const verifierRole = contract.harnessSuite?.roles?.impossibility_verifier;
    if (manifest === undefined || verifierRole === undefined) {
        fail("certified impossibility requires an enumerand manifest and verifier role");
    }
    requireInteger(attemptOrdinal, "attemptOrdinal", 1);
    const coverage = deriveUnreachableCoverageClosure(aggregate);
    const entries = [...manifest.entries].sort((left, right) =>
        left.ordinal - right.ordinal);
    const calibration = coverage.closure.calibration;
    const calibrationComplete = calibration?.status === "COMPLETE";
    const controlProjection = {
        calibrationRoot: calibration?.controlsRoot ?? null,
        enumerandControls: coverage.closure.enumerands.map((entry) => ({
            ordinal: entry.ordinal,
            controlBindingHash: entry.controlBindingHash,
        })),
    };
    const controlComplete = calibrationComplete
        && controlProjection.enumerandControls.length === entries.length
        && controlProjection.enumerandControls.every((item) =>
            isAlgorithmTaggedSha256(item.controlBindingHash));
    const searchComplete = progress.roundsExhausted === true
        && coverage.eligible;
    const scientificReplay = aggregate.scientificReplay;
    const statisticalComplete = scientificReplay !== null
        && scientificReplay !== undefined
        && isAlgorithmTaggedSha256(scientificReplay.alphaLedgerHash)
        && isAlgorithmTaggedSha256(scientificReplay.closureRoot)
        && coverage.closure.alphaLedgerRoot
            === scientificReplay.alphaLedgerHash
        && coverage.closure.scientificReplayRoot
            === scientificReplay.closureRoot;
    const evidenceRoots = immutableCanonical({
        calibration: hashCanonical(
            calibration,
            IMPOSSIBILITY_CALIBRATION_EVIDENCE_HASH_ALGORITHM,
        ),
        control: hashCanonical(
            controlProjection,
            IMPOSSIBILITY_CONTROL_EVIDENCE_HASH_ALGORITHM,
        ),
        search: coverage.closure.enumerandEvidenceRoot,
        scientificReplay: statisticalComplete
            ? scientificReplay.closureRoot
            : hashCanonical(
                null,
                "sha256:crucible-impossibility-missing-scientific-replay-v1",
            ),
    });
    const evidenceRootsHash = hashCanonical(
        evidenceRoots,
        IMPOSSIBILITY_EVIDENCE_ROOTS_HASH_ALGORITHM,
    );
    const verificationPolicy = verifierRole.verificationPolicy;
    const signedExperiment = {
        authorityIdentity: requireHash(
            aggregate.experimentAuthorityIdentity,
            "experimentAuthorityIdentity",
        ),
        authorityManifestIdentity: requireHash(
            aggregate.experimentAuthority?.manifestIdentity,
            "experimentAuthority.manifestIdentity",
        ),
        contractHash: requireHash(aggregate.contractHash, "contractHash"),
        trustFingerprint: requireHash(
            aggregate.experimentAuthority?.trustFingerprint,
            "experimentAuthority.trustFingerprint",
        ),
    };
    const verifier = {
        harnessId: verifierRole.harnessId,
        parser: verifierRole.parser,
        executableHash: verifierRole.executableHash,
        applicationEntrypointHash:
            verifierRole.applicationEntrypointHash,
        roleIdentity: verifierRoleIdentity(verifierRole),
        independenceAttestation:
            verifierRole.independenceAttestation,
        sandboxIdentity: verifierRole.sandboxIdentity,
        verificationPolicy,
        proofChecker: proofCheckerIdentity(verifierRole),
    };
    const completeInputs = calibrationComplete
        && controlComplete
        && searchComplete
        && statisticalComplete
        && coverage.missing.length === 0;
    const entriesByPath = new Map();
    addGeneratedObject(
        entriesByPath,
        "coverage-closure.json",
        coverage.closure,
        IMPOSSIBILITY_VERIFIER_OBJECT_HASH_ALGORITHM,
    );
    addGeneratedObject(
        entriesByPath,
        "enumerand-manifest.json",
        manifest,
        IMPOSSIBILITY_VERIFIER_OBJECT_HASH_ALGORITHM,
    );
    addGeneratedObject(
        entriesByPath,
        "scientific-replay.json",
        scientificReplay ?? null,
        IMPOSSIBILITY_VERIFIER_OBJECT_HASH_ALGORITHM,
    );
    const calibrationInput = completeInputs
        ? calibrationVerifierInput(
            aggregate,
            validation,
            entriesByPath,
        )
        : null;
    const enumerandInputs = completeInputs
        ? entries.map((entry, index) =>
            enumerandVerifierInput(
                aggregate,
                entry,
                coverage.closure.enumerands[index],
                entriesByPath,
            ))
        : [];
    const proofArtifact = immutableCanonical({
        version: IMPOSSIBILITY_PROOF_ARTIFACT_VERSION,
        kind: "CrucibleImpossibilityProofArtifact",
        theorem: "TARGET_UNREACHABLE",
        certificateFormat: verificationPolicy.certificateFormat,
        proofCheckerIdentity: verifier.proofChecker?.identity ?? null,
        signedExperiment,
        harnessSuiteIdentity: contract.harnessSuiteIdentity,
        enumerandManifestRoot: manifest.merkleRoot,
        coverageClosureRoot: coverage.closure.closureRoot,
        evidenceRoots,
        statisticalPolicyIdentity: contract.statisticalPolicyIdentity,
        alphaLedgerRoot: statisticalComplete
            ? scientificReplay.alphaLedgerHash
            : hashCanonical(
                null,
                "sha256:crucible-impossibility-missing-alpha-ledger-v1",
            ),
        calibrationInputRoot: calibrationInput?.inputRoot ?? null,
        enumerandWitnesses: coverage.closure.enumerands.map((entry, index) => ({
            ordinal: entry.ordinal,
            enumerandHash: entry.enumerandHash,
            inputRoot: enumerandInputs[index]?.inputRoot ?? null,
            receiptBindingsRoot:
                enumerandInputs[index]?.receiptBindingsRoot ?? null,
            claimRefutations: entry.claims.map((claim) => ({
                claimId: claim.claimId,
                state: claim.state,
                allocation: claim.allocation,
            })),
        })),
    });
    const proofArtifactHash = hashCanonical(
        proofArtifact,
        IMPOSSIBILITY_PROOF_ARTIFACT_HASH_ALGORITHM,
    );
    const proofObject = addGeneratedObject(
        entriesByPath,
        "proof-artifact.json",
        proofArtifact,
        IMPOSSIBILITY_PROOF_ARTIFACT_HASH_ALGORITHM,
    );
    if (!semanticHashMatchesObject(
        proofObject.objectId,
        proofArtifactHash,
    )) {
        fail("proof artifact hash does not bind the proof bytes");
    }
    const objectManifestCore = {
        version: IMPOSSIBILITY_VERIFIER_OBJECT_MANIFEST_VERSION,
        pack: {
            path: "object-pack.json",
            format: "crucible-base64-object-pack-v1",
        },
        entries: [...entriesByPath.values()]
            .map((entry) => ({
                ...entry,
                artifactIds: [...entry.artifactIds].sort(),
                semanticHashes: [...entry.semanticHashes].sort(),
            }))
            .sort((left, right) => left.path.localeCompare(right.path)),
    };
    const objectManifest = immutableCanonical({
        ...objectManifestCore,
        root: hashCanonical(
            objectManifestCore,
            IMPOSSIBILITY_VERIFIER_OBJECT_MANIFEST_HASH_ALGORITHM,
        ),
    });
    const proposal = immutableCanonical({
        version: IMPOSSIBILITY_PROPOSAL_VERSION,
        kind: "CrucibleImpossibilityCertificateProposal",
        claim: "TARGET_UNREACHABLE",
        mode: verificationPolicy.mode,
        certificateFormat: verificationPolicy.certificateFormat,
        signedExperiment,
        harnessSuiteIdentity: contract.harnessSuiteIdentity,
        verifierRoleIdentity: verifier.roleIdentity,
        enumerandManifestRoot: manifest.merkleRoot,
        enumerandCount: entries.length,
        evidenceRoots,
        evidenceRootsHash,
        coverageClosureRoot: coverage.closure.closureRoot,
        objectManifestRoot: objectManifest.root,
        proofArtifactHash,
        statisticalPolicyIdentity: contract.statisticalPolicyIdentity,
        alphaLedgerRoot: proofArtifact.alphaLedgerRoot,
    });
    const proposalArtifactHash = hashCanonical(
        proposal,
        IMPOSSIBILITY_PROPOSAL_HASH_ALGORITHM,
    );
    const request = immutableCanonical({
        version: IMPOSSIBILITY_REQUEST_VERSION,
        kind: "CrucibleImpossibilityVerifierRequest",
        attemptOrdinal,
        signedExperiment,
        contract,
        harnessSuiteIdentity: contract.harnessSuiteIdentity,
        verifier,
        enumerands: {
            topology: manifest.topology,
            manifest,
            merkleRoot: manifest.merkleRoot,
            count: entries.length,
        },
        evidence: {
            roots: evidenceRoots,
            rootsHash: evidenceRootsHash,
            coverageClosure: coverage.closure,
            coverageClosureRoot: coverage.closure.closureRoot,
            calibrationComplete,
            controlComplete,
            searchComplete,
        },
        objectManifest,
        reevaluation: {
            calibration: calibrationInput,
            enumerands: enumerandInputs,
        },
        statistics: {
            policyIdentity: contract.statisticalPolicyIdentity,
            alphaLedgerRoot: proposal.alphaLedgerRoot,
            scientificReplay: scientificReplay ?? null,
        },
        proofArtifact: {
            version: proofArtifact.version,
            path: proofObject.path,
            objectId: proofObject.objectId,
            artifactHash: proofArtifactHash,
            certificateFormat: proofArtifact.certificateFormat,
            checkerIdentity: proofArtifact.proofCheckerIdentity,
        },
        proposedCertificate: {
            version: proposal.version,
            artifactHash: proposalArtifactHash,
        },
    });
    const missing = [
        ...(calibrationComplete ? [] : ["calibration_evidence"]),
        ...(controlComplete ? [] : ["control_evidence"]),
        ...(searchComplete ? [] : ["search_evidence"]),
        ...(statisticalComplete ? [] : ["statistical_alpha_ledger"]),
        ...coverage.missing,
    ];
    return immutableCanonical({
        eligible: sortedMissing(missing).length === 0,
        missing: sortedMissing(missing),
        request,
        requestHash: hashCanonical(
            request,
            IMPOSSIBILITY_REQUEST_HASH_ALGORITHM,
        ),
        proposal,
        proposalArtifactHash,
        proofArtifact,
        proofArtifactHash,
    });
}

export function normalizeImpossibilityEvidenceRoots(value, field = "evidenceRoots") {
    const input = requireExactKeys(
        value,
        field,
        ["calibration", "control", "scientificReplay", "search"],
    );
    return immutableCanonical({
        calibration: requireHash(input.calibration, `${field}.calibration`),
        control: requireHash(input.control, `${field}.control`),
        search: requireHash(input.search, `${field}.search`),
        scientificReplay: requireHash(
            input.scientificReplay,
            `${field}.scientificReplay`,
        ),
    });
}

function normalizeVerifierClaimStates(value, field) {
    if (!Array.isArray(value) || value.length < 1 || value.length > 128) {
        fail(`${field} must be a non-empty bounded claim-state array`);
    }
    const normalized = value.map((item, index) => {
        const input = requireExactKeys(
            item,
            `${field}[${index}]`,
            ["claimId", "state"],
        );
        const state = requireString(
            input.state,
            `${field}[${index}].state`,
            32,
        );
        if (!STATISTICAL_CLAIM_STATES.includes(state)) {
            fail(`${field}[${index}].state is not a statistical claim state`);
        }
        return {
            claimId: requireId(
                input.claimId,
                `${field}[${index}].claimId`,
            ),
            state,
        };
    }).sort((left, right) => left.claimId.localeCompare(right.claimId));
    if (new Set(normalized.map((item) => item.claimId)).size
        !== normalized.length) {
        fail(`${field} contains duplicate claim ids`);
    }
    return normalized;
}

export function impossibilityVerifierRefutationRoot({
    requestHash,
    verifierRoleIdentity: roleIdentity,
    ordinal,
    enumerandHash,
    inputRoot,
    claimStates,
}) {
    return hashCanonical({
        requestHash: requireHash(requestHash, "requestHash"),
        verifierRoleIdentity: requireHash(
            roleIdentity,
            "verifierRoleIdentity",
        ),
        ordinal: requireInteger(ordinal, "ordinal"),
        enumerandHash: requireHash(enumerandHash, "enumerandHash"),
        inputRoot: requireHash(inputRoot, "inputRoot"),
        claimStates: normalizeVerifierClaimStates(
            claimStates,
            "claimStates",
        ),
    }, IMPOSSIBILITY_VERIFIER_REFUTATION_HASH_ALGORITHM);
}

export function impossibilityVerifierRefutationReceiptHash({
    requestHash,
    verifierRoleIdentity: roleIdentity,
    ordinal,
    enumerandHash,
    inputRoot,
    receiptBindingsRoot,
    claimStates,
    evidenceRoot,
}) {
    return hashCanonical({
        requestHash: requireHash(requestHash, "requestHash"),
        verifierRoleIdentity: requireHash(
            roleIdentity,
            "verifierRoleIdentity",
        ),
        ordinal: requireInteger(ordinal, "ordinal"),
        enumerandHash: requireHash(enumerandHash, "enumerandHash"),
        inputRoot: requireHash(inputRoot, "inputRoot"),
        receiptBindingsRoot: requireHash(
            receiptBindingsRoot,
            "receiptBindingsRoot",
        ),
        claimStates: normalizeVerifierClaimStates(
            claimStates,
            "claimStates",
        ),
        evidenceRoot: requireHash(evidenceRoot, "evidenceRoot"),
    }, IMPOSSIBILITY_VERIFIER_REFUTATION_RECEIPT_HASH_ALGORITHM);
}

function normalizeVerifierEnumerandResults(value, field = "enumerandResults") {
    if (!Array.isArray(value) || value.length > 512) {
        fail(`${field} must be a bounded array`);
    }
    const normalized = value.map((item, index) => {
        const input = requireExactKeys(
            item,
            `${field}[${index}]`,
            [
                "claimStates",
                "enumerandHash",
                "evidenceRoot",
                "inputRoot",
                "ordinal",
                "receiptBindingsRoot",
                "refutationReceiptHash",
            ],
        );
        return {
            ordinal: requireInteger(
                input.ordinal,
                `${field}[${index}].ordinal`,
            ),
            enumerandHash: requireHash(
                input.enumerandHash,
                `${field}[${index}].enumerandHash`,
            ),
            claimStates: normalizeVerifierClaimStates(
                input.claimStates,
                `${field}[${index}].claimStates`,
            ),
            evidenceRoot: requireHash(
                input.evidenceRoot,
                `${field}[${index}].evidenceRoot`,
            ),
            inputRoot: requireHash(
                input.inputRoot,
                `${field}[${index}].inputRoot`,
            ),
            receiptBindingsRoot: requireHash(
                input.receiptBindingsRoot,
                `${field}[${index}].receiptBindingsRoot`,
            ),
            refutationReceiptHash: requireHash(
                input.refutationReceiptHash,
                `${field}[${index}].refutationReceiptHash`,
            ),
        };
    }).sort((left, right) =>
        left.ordinal - right.ordinal
        || left.enumerandHash.localeCompare(right.enumerandHash));
    if (new Set(normalized.map((item) =>
        enumerandKey(item.ordinal, item.enumerandHash))).size
        !== normalized.length) {
        fail(`${field} contains duplicate enumerand identities`);
    }
    if (new Set(normalized.map((item) => item.evidenceRoot)).size
        !== normalized.length) {
        fail(`${field} contains duplicate verifier evidence roots`);
    }
    if (new Set(normalized.map((item) => item.refutationReceiptHash)).size
        !== normalized.length) {
        fail(`${field} contains duplicate verifier refutation receipts`);
    }
    return immutableCanonical(normalized);
}

export function impossibilityVerifierEnumerandResultsRoot(results) {
    return hashCanonical(
        normalizeVerifierEnumerandResults(results),
        IMPOSSIBILITY_VERIFIER_ENUMERAND_RESULTS_HASH_ALGORITHM,
    );
}

export function impossibilityProofValidationReceiptHash({
    requestHash,
    proofArtifactHash,
    proofCheckerIdentity: checkerIdentity,
    certificateFormat,
    status,
    checkerEvidenceRoot,
}) {
    return hashCanonical({
        requestHash: requireHash(requestHash, "requestHash"),
        proofArtifactHash: requireHash(
            proofArtifactHash,
            "proofArtifactHash",
        ),
        proofCheckerIdentity: requireHash(
            checkerIdentity,
            "proofCheckerIdentity",
        ),
        certificateFormat: normalizeCertificateFormat(
            certificateFormat,
            "certificateFormat",
        ),
        status: requireString(status, "status", 32),
        checkerEvidenceRoot: requireHash(
            checkerEvidenceRoot,
            "checkerEvidenceRoot",
        ),
    }, IMPOSSIBILITY_PROOF_VALIDATION_RECEIPT_HASH_ALGORITHM);
}

export function impossibilityVerifierFactsRoot({
    mode,
    enumerandResults,
    proofArtifactHash,
    proofCheckerIdentity: checkerIdentity,
    proofValidationReceiptHash,
    validatedProofArtifactHash,
}) {
    if (!VERIFIER_MODES.includes(mode)) {
        fail("verifier facts mode is not supported", { mode });
    }
    return hashCanonical(
        mode === "enumerand_reexecution"
            ? {
                mode,
                refutations: normalizeVerifierEnumerandResults(
                    enumerandResults,
                ).map((result) => ({
                    ordinal: result.ordinal,
                    enumerandHash: result.enumerandHash,
                    inputRoot: result.inputRoot,
                    receiptBindingsRoot: result.receiptBindingsRoot,
                    evidenceRoot: result.evidenceRoot,
                    refutationReceiptHash:
                        result.refutationReceiptHash,
                })),
                proofArtifactHash: requireHash(
                    proofArtifactHash,
                    "proofArtifactHash",
                ),
            }
            : {
                mode,
                proofArtifactHash: requireHash(
                    proofArtifactHash,
                    "proofArtifactHash",
                ),
                proofCheckerIdentity: requireHash(
                    checkerIdentity,
                    "proofCheckerIdentity",
                ),
                proofValidationReceiptHash: requireHash(
                    proofValidationReceiptHash,
                    "proofValidationReceiptHash",
                ),
                validatedProofArtifactHash: requireHash(
                    validatedProofArtifactHash,
                    "validatedProofArtifactHash",
                ),
            },
        IMPOSSIBILITY_VERIFIER_FACTS_HASH_ALGORITHM,
    );
}

function normalizeCheckerCertificate(value) {
    const input = requireExactKeys(value, "certificate", [
        "alphaLedgerRoot",
        "certificateFormat",
        "checkerEvidenceRoot",
        "contractHash",
        "coverageClosureRoot",
        "enumerandManifestRoot",
        "enumerandResultsRoot",
        "evidenceRoots",
        "harnessSuiteIdentity",
        "independentFactsRoot",
        "mode",
        "proofArtifactHash",
        "proofCheckerIdentity",
        "proofValidationReceiptHash",
        "proposedCertificateArtifactHash",
        "requestHash",
        "statisticalPolicyIdentity",
        "status",
        "validatedProofArtifactHash",
        "verdict",
        "verifierRoleIdentity",
        "version",
    ]);
    const status = requireString(input.status, "certificate.status", 32);
    if (!IMPOSSIBILITY_CHECKER_STATUSES.includes(status)) {
        fail("certificate.status is not a verifier status", { status });
    }
    const mode = requireString(input.mode, "certificate.mode", 64);
    if (!VERIFIER_MODES.includes(mode)) {
        fail("certificate.mode is not supported", { mode });
    }
    const verdict = requireString(input.verdict, "certificate.verdict", 64);
    if (verdict !== deriveImpossibilityVerdict({ status })) {
        fail("certificate verdict disagrees with checker status", {
            status,
            verdict,
        });
    }
    return immutableCanonical({
        version: requireString(input.version, "certificate.version", 256),
        status,
        verdict,
        mode,
        requestHash: requireHash(input.requestHash, "certificate.requestHash"),
        proposedCertificateArtifactHash: requireHash(
            input.proposedCertificateArtifactHash,
            "certificate.proposedCertificateArtifactHash",
        ),
        contractHash: requireHash(input.contractHash, "certificate.contractHash"),
        harnessSuiteIdentity: requireHash(
            input.harnessSuiteIdentity,
            "certificate.harnessSuiteIdentity",
        ),
        verifierRoleIdentity: requireHash(
            input.verifierRoleIdentity,
            "certificate.verifierRoleIdentity",
        ),
        coverageClosureRoot: requireHash(
            input.coverageClosureRoot,
            "certificate.coverageClosureRoot",
        ),
        enumerandManifestRoot: requireHash(
            input.enumerandManifestRoot,
            "certificate.enumerandManifestRoot",
        ),
        enumerandResultsRoot: requireHash(
            input.enumerandResultsRoot,
            "certificate.enumerandResultsRoot",
        ),
        evidenceRoots: normalizeImpossibilityEvidenceRoots(
            input.evidenceRoots,
            "certificate.evidenceRoots",
        ),
        statisticalPolicyIdentity: requireHash(
            input.statisticalPolicyIdentity,
            "certificate.statisticalPolicyIdentity",
        ),
        alphaLedgerRoot: requireHash(
            input.alphaLedgerRoot,
            "certificate.alphaLedgerRoot",
        ),
        checkerEvidenceRoot: requireHash(
            input.checkerEvidenceRoot,
            "certificate.checkerEvidenceRoot",
        ),
        independentFactsRoot: requireHash(
            input.independentFactsRoot,
            "certificate.independentFactsRoot",
        ),
        proofArtifactHash: requireHash(
            input.proofArtifactHash,
            "certificate.proofArtifactHash",
        ),
        proofCheckerIdentity: input.proofCheckerIdentity === null
            ? null
            : requireHash(
                input.proofCheckerIdentity,
                "certificate.proofCheckerIdentity",
            ),
        proofValidationReceiptHash:
            input.proofValidationReceiptHash === null
                ? null
                : requireHash(
                    input.proofValidationReceiptHash,
                    "certificate.proofValidationReceiptHash",
                ),
        certificateFormat: normalizeCertificateFormat(
            input.certificateFormat,
            "certificate.certificateFormat",
        ),
        validatedProofArtifactHash:
            input.validatedProofArtifactHash === null
            ? null
            : requireHash(
                input.validatedProofArtifactHash,
                "certificate.validatedProofArtifactHash",
            ),
    });
}

export function normalizeImpossibilityCheckerResult(value, expected = {}) {
    const input = requireExactKeys(value, "checkerResult", [
        "alphaLedgerRoot",
        "armId",
        "armIndex",
        "blockIndex",
        "certificate",
        "certificateFormat",
        "checkedEnumerandCount",
        "checkerEvidenceRoot",
        "complete",
        "coverageClosureRoot",
        "deterministicSeed",
        "disagreementCount",
        "enumerandCount",
        "enumerandManifestRoot",
        "enumerandResults",
        "enumerandResultsRoot",
        "environmentIdentity",
        "evidenceRoots",
        "independentFactsRoot",
        "mode",
        "parserVersion",
        "phase",
        "proofArtifactHash",
        "proofCheckerIdentity",
        "proofValidationReceiptHash",
        "proposedCertificateArtifactHash",
        "replicateIndex",
        "requestHash",
        "role",
        "statisticalPolicyIdentity",
        "status",
        "subjectId",
        "suiteIdentity",
        "validatedProofArtifactHash",
        "version",
    ]);
    if (input.version !== IMPOSSIBILITY_CHECKER_OUTPUT_VERSION) {
        fail(`checkerResult.version must be ${IMPOSSIBILITY_CHECKER_OUTPUT_VERSION}`);
    }
    const status = requireString(input.status, "checkerResult.status", 32);
    if (!IMPOSSIBILITY_CHECKER_STATUSES.includes(status)) {
        fail("checkerResult.status is not supported", { status });
    }
    const mode = requireString(input.mode, "checkerResult.mode", 64);
    if (!VERIFIER_MODES.includes(mode)) {
        fail("checkerResult.mode is not supported", { mode });
    }
    const enumerandCount = requireInteger(
        input.enumerandCount,
        "checkerResult.enumerandCount",
    );
    const checkedEnumerandCount = requireInteger(
        input.checkedEnumerandCount,
        "checkerResult.checkedEnumerandCount",
    );
    if (checkedEnumerandCount > enumerandCount) {
        fail("checkerResult.checkedEnumerandCount cannot exceed enumerandCount");
    }
    const disagreementCount = requireInteger(
        input.disagreementCount,
        "checkerResult.disagreementCount",
    );
    const complete = requireBoolean(input.complete, "checkerResult.complete");
    const enumerandResults = normalizeVerifierEnumerandResults(
        input.enumerandResults,
    );
    if (checkedEnumerandCount !== enumerandResults.length) {
        fail("checkerResult.checkedEnumerandCount must equal enumerandResults length");
    }
    const derivedDisagreementCount = enumerandResults.filter((result) =>
        result.claimStates.some((claim) => claim.state !== "REFUTED")).length;
    if (disagreementCount !== derivedDisagreementCount) {
        fail("checkerResult.disagreementCount does not match enumerand claim states");
    }
    const enumerandResultsRoot =
        impossibilityVerifierEnumerandResultsRoot(enumerandResults);
    if (requireHash(
        input.enumerandResultsRoot,
        "checkerResult.enumerandResultsRoot",
    ) !== enumerandResultsRoot) {
        fail("checkerResult.enumerandResultsRoot is not derived from enumerandResults");
    }
    const certificateFormat = normalizeCertificateFormat(
        input.certificateFormat,
        "checkerResult.certificateFormat",
    );
    const requestHash = requireHash(
        input.requestHash,
        "checkerResult.requestHash",
    );
    const proposedCertificateArtifactHash = requireHash(
        input.proposedCertificateArtifactHash,
        "checkerResult.proposedCertificateArtifactHash",
    );
    const proofArtifactHash = requireHash(
        input.proofArtifactHash,
        "checkerResult.proofArtifactHash",
    );
    const checkerEvidenceRoot = requireHash(
        input.checkerEvidenceRoot,
        "checkerResult.checkerEvidenceRoot",
    );
    const proofCheckerIdentity = input.proofCheckerIdentity === null
        ? null
        : requireHash(
            input.proofCheckerIdentity,
            "checkerResult.proofCheckerIdentity",
        );
    const proofValidationReceiptHash =
        input.proofValidationReceiptHash === null
            ? null
            : requireHash(
                input.proofValidationReceiptHash,
                "checkerResult.proofValidationReceiptHash",
            );
    const validatedProofArtifactHash =
        input.validatedProofArtifactHash === null
            ? null
            : requireHash(
                input.validatedProofArtifactHash,
                "checkerResult.validatedProofArtifactHash",
            );
    if (proofArtifactHash === proposedCertificateArtifactHash) {
        fail(
            "proof artifact must be distinct from the kernel proposal artifact",
        );
    }
    if (mode === "enumerand_reexecution") {
        if (certificateFormat !== null
            || proofCheckerIdentity !== null
            || proofValidationReceiptHash !== null
            || validatedProofArtifactHash !== null) {
            fail("enumerand_reexecution forbids certificate-validation fields");
        }
        if (status === "VERIFIED"
            && (!complete
                || checkedEnumerandCount !== enumerandCount
                || disagreementCount !== 0
                || enumerandResults.some((result) =>
                    result.claimStates.some((claim) =>
                        claim.state !== "REFUTED")))) {
            fail("VERIFIED re-evaluation requires complete zero-disagreement coverage");
        }
    } else {
        if (enumerandResults.length !== 0
            || checkedEnumerandCount !== 0
            || disagreementCount !== 0) {
            fail("certificate_validation forbids enumerand re-evaluation results");
        }
        if (certificateFormat === null
            || proofCheckerIdentity === null
            || proofValidationReceiptHash === null
            || validatedProofArtifactHash === null) {
            fail(
                "certificate_validation requires a separately checked proof artifact",
            );
        }
        if (validatedProofArtifactHash !== proofArtifactHash) {
            fail(
                "certificate_validation validated proof hash does not match the proof artifact",
            );
        }
        const expectedProofReceipt =
            impossibilityProofValidationReceiptHash({
                requestHash,
                proofArtifactHash,
                proofCheckerIdentity,
                certificateFormat,
                status,
                checkerEvidenceRoot,
            });
        if (proofValidationReceiptHash !== expectedProofReceipt) {
            fail(
                "certificate_validation proof receipt is not derived from the pinned checker and proof artifact",
            );
        }
        if (status === "VERIFIED" && (!complete || disagreementCount !== 0)) {
            fail("VERIFIED certificate validation must be complete and disagreement-free");
        }
    }
    const independentFactsRoot = requireHash(
        input.independentFactsRoot,
        "checkerResult.independentFactsRoot",
    );
    const expectedIndependentFactsRoot = impossibilityVerifierFactsRoot({
        mode,
        enumerandResults,
        proofArtifactHash,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
    });
    if (independentFactsRoot !== expectedIndependentFactsRoot) {
        fail(
            "checkerResult.independentFactsRoot is not derived from verifier facts",
        );
    }
    const certificate = normalizeCheckerCertificate(input.certificate);
    const evidenceRoots = normalizeImpossibilityEvidenceRoots(input.evidenceRoots);
    const normalized = immutableCanonical({
        version: IMPOSSIBILITY_CHECKER_OUTPUT_VERSION,
        status,
        mode,
        requestHash,
        proposedCertificateArtifactHash,
        proofArtifactHash,
        coverageClosureRoot: requireHash(
            input.coverageClosureRoot,
            "checkerResult.coverageClosureRoot",
        ),
        enumerandManifestRoot: requireHash(
            input.enumerandManifestRoot,
            "checkerResult.enumerandManifestRoot",
        ),
        enumerandCount,
        checkedEnumerandCount,
        enumerandResults,
        enumerandResultsRoot,
        evidenceRoots,
        statisticalPolicyIdentity: requireHash(
            input.statisticalPolicyIdentity,
            "checkerResult.statisticalPolicyIdentity",
        ),
        alphaLedgerRoot: requireHash(
            input.alphaLedgerRoot,
            "checkerResult.alphaLedgerRoot",
        ),
        checkerEvidenceRoot,
        independentFactsRoot,
        disagreementCount,
        complete,
        certificateFormat,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
        certificate,
        role: requireId(input.role, "checkerResult.role"),
        phase: requireId(input.phase, "checkerResult.phase"),
        replicateIndex: input.replicateIndex,
        blockIndex: requireInteger(input.blockIndex, "checkerResult.blockIndex"),
        armIndex: input.armIndex,
        armId: input.armId,
        deterministicSeed: requireString(
            input.deterministicSeed,
            "checkerResult.deterministicSeed",
            256,
        ),
        subjectId: requireId(input.subjectId, "checkerResult.subjectId"),
        environmentIdentity: requireHash(
            input.environmentIdentity,
            "checkerResult.environmentIdentity",
        ),
        suiteIdentity: requireHash(
            input.suiteIdentity,
            "checkerResult.suiteIdentity",
        ),
        parserVersion: requireId(
            input.parserVersion,
            "checkerResult.parserVersion",
        ),
    });
    if (normalized.replicateIndex !== null
        || normalized.armIndex !== null
        || normalized.armId !== null) {
        fail("impossibility checker result forbids replicate/arm bindings");
    }
    if (normalized.role !== "impossibility_verifier"
        || normalized.phase !== "impossibility_verification"
        || normalized.parserVersion
            !== "crucible-impossibility-verifier-parser-v1"
        || !normalized.environmentIdentity.startsWith(
            "sha256:crucible-harness-environment-v4:",
        )
        || !normalized.suiteIdentity.startsWith(
            "sha256:crucible-harness-suite-v4:",
        )) {
        fail("checker result does not use the pinned impossibility-verifier role identity");
    }
    if (certificate.version !== IMPOSSIBILITY_CERTIFICATE_VERSION
        || certificate.status !== normalized.status
        || certificate.mode !== normalized.mode
        || certificate.requestHash !== normalized.requestHash
        || certificate.proposedCertificateArtifactHash
            !== normalized.proposedCertificateArtifactHash
        || certificate.coverageClosureRoot
            !== normalized.coverageClosureRoot
        || certificate.enumerandManifestRoot
            !== normalized.enumerandManifestRoot
        || certificate.enumerandResultsRoot
            !== normalized.enumerandResultsRoot
        || !canonicalEqual(certificate.evidenceRoots, normalized.evidenceRoots)
        || certificate.statisticalPolicyIdentity
            !== normalized.statisticalPolicyIdentity
        || certificate.alphaLedgerRoot !== normalized.alphaLedgerRoot
        || certificate.checkerEvidenceRoot !== normalized.checkerEvidenceRoot
        || certificate.independentFactsRoot
            !== normalized.independentFactsRoot
        || certificate.proofArtifactHash
            !== normalized.proofArtifactHash
        || certificate.proofCheckerIdentity
            !== normalized.proofCheckerIdentity
        || certificate.proofValidationReceiptHash
            !== normalized.proofValidationReceiptHash
        || !canonicalEqual(
            certificate.certificateFormat,
            normalized.certificateFormat,
        )
        || certificate.validatedProofArtifactHash
            !== normalized.validatedProofArtifactHash) {
        fail("checker certificate disagrees with the parsed verifier output");
    }
    const request = expected.request ?? null;
    if (request !== null) {
        const expectedFormat = request.verifier.verificationPolicy.certificateFormat;
        const expectedEnumerands =
            request.evidence.coverageClosure.enumerands;
        if (normalized.mode !== request.verifier.verificationPolicy.mode
            || normalized.requestHash !== expected.requestHash
            || normalized.proposedCertificateArtifactHash
                !== request.proposedCertificate.artifactHash
            || normalized.coverageClosureRoot
                !== request.evidence.coverageClosureRoot
            || normalized.enumerandManifestRoot !== request.enumerands.merkleRoot
            || normalized.enumerandCount !== request.enumerands.count
            || !canonicalEqual(normalized.evidenceRoots, request.evidence.roots)
            || normalized.statisticalPolicyIdentity
                !== request.statistics.policyIdentity
            || normalized.alphaLedgerRoot !== request.statistics.alphaLedgerRoot
            || !canonicalEqual(normalized.certificateFormat, expectedFormat)
            || normalized.proofArtifactHash
                !== request.proofArtifact.artifactHash
            || normalized.proofCheckerIdentity
                !== (request.verifier.proofChecker?.identity ?? null)
            || normalized.validatedProofArtifactHash
                !== (normalized.mode === "certificate_validation"
                    ? request.proofArtifact.artifactHash
                    : null)
            || certificate.contractHash
                !== request.signedExperiment.contractHash
            || certificate.harnessSuiteIdentity
                !== request.harnessSuiteIdentity
            || certificate.verifierRoleIdentity
                !== request.verifier.roleIdentity) {
            fail("checker result does not match the reserved verifier request");
        }
        if (normalized.mode === "enumerand_reexecution") {
            for (const result of normalized.enumerandResults) {
                const expectedEntry = expectedEnumerands[result.ordinal];
                const expectedInput =
                    request.reevaluation.enumerands[result.ordinal];
                const expectedClaimIds = expectedEntry?.claims
                    ?.map((claim) => claim.claimId)
                    .sort() ?? [];
                const actualClaimIds = result.claimStates
                    .map((claim) => claim.claimId);
                if (expectedEntry === undefined
                    || expectedInput === undefined
                    || expectedEntry.enumerandHash !== result.enumerandHash
                    || expectedInput.ordinal !== result.ordinal
                    || expectedInput.enumerandHash !== result.enumerandHash
                    || expectedInput.inputRoot !== result.inputRoot
                    || expectedInput.receiptBindingsRoot
                        !== result.receiptBindingsRoot
                    || !canonicalEqual(actualClaimIds, expectedClaimIds)) {
                    fail(
                        "checker enumerand result does not match the receipt-bound verifier input",
                        { ordinal: result.ordinal },
                    );
                }
                const expectedEvidenceRoot =
                    impossibilityVerifierRefutationRoot({
                        requestHash: normalized.requestHash,
                        verifierRoleIdentity:
                            request.verifier.roleIdentity,
                        ordinal: result.ordinal,
                        enumerandHash: result.enumerandHash,
                        inputRoot: result.inputRoot,
                        claimStates: result.claimStates,
                    });
                const expectedReceiptHash =
                    impossibilityVerifierRefutationReceiptHash({
                        requestHash: normalized.requestHash,
                        verifierRoleIdentity:
                            request.verifier.roleIdentity,
                        ordinal: result.ordinal,
                        enumerandHash: result.enumerandHash,
                        inputRoot: result.inputRoot,
                        receiptBindingsRoot:
                            result.receiptBindingsRoot,
                        claimStates: result.claimStates,
                        evidenceRoot: expectedEvidenceRoot,
                    });
                if (result.evidenceRoot !== expectedEvidenceRoot
                    || result.refutationReceiptHash
                        !== expectedReceiptHash) {
                    fail(
                        "checker enumerand refutation receipt is not kernel-derived from immutable inputs",
                        { ordinal: result.ordinal },
                    );
                }
            }
            if (normalized.status === "VERIFIED"
                && (normalized.enumerandResults.length
                    !== expectedEnumerands.length
                    || normalized.enumerandResults.some((result, ordinal) =>
                        result.ordinal !== ordinal
                        || result.enumerandHash
                            !== expectedEnumerands[ordinal].enumerandHash
                        || result.claimStates.some((claim) =>
                            claim.state !== "REFUTED")))) {
                fail(
                    "VERIFIED re-evaluation does not cover every exact enumerand claim",
                );
            }
        } else if (normalized.proofValidationReceiptHash
            !== impossibilityProofValidationReceiptHash({
                requestHash: normalized.requestHash,
                proofArtifactHash:
                    request.proofArtifact.artifactHash,
                proofCheckerIdentity:
                    request.verifier.proofChecker.identity,
                certificateFormat: expectedFormat,
                status: normalized.status,
                checkerEvidenceRoot:
                    normalized.checkerEvidenceRoot,
            })) {
            fail(
                "checker proof validation receipt does not match the reserved proof artifact and checker",
            );
        }
    }
    if (expected.binding !== undefined
        && expected.binding !== null) {
        const actualBinding = {
            role: normalized.role,
            phase: normalized.phase,
            replicateIndex: normalized.replicateIndex,
            blockIndex: normalized.blockIndex,
            armIndex: normalized.armIndex,
            armId: normalized.armId,
            deterministicSeed: normalized.deterministicSeed,
            subjectId: normalized.subjectId,
            environmentIdentity: normalized.environmentIdentity,
            suiteIdentity: normalized.suiteIdentity,
        };
        if (!canonicalEqual(actualBinding, expected.binding)) {
            fail("checker result binding does not match the trusted execution binding", {
                actual: actualBinding,
                expected: expected.binding,
            });
        }
    }
    return normalized;
}
