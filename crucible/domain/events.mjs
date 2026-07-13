import {
    EVENT_HASH_ALGORITHM,
    canonicalEqual,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    contractHash,
    createInvestigationContract,
    isSafeDomainIdentifier,
} from "./contract.mjs";
import {
    assertExperimentAuthorityContractBinding,
} from "./authority.mjs";
import {
    normalizeRuntimeConfigAuthority,
} from "./runtime-authority.mjs";
import {
    ANNOTATION_LIMITS,
    DOMAIN_VERSION,
    EVIDENCE_PURPOSES,
    EVENT_TYPES,
    EVENT_VOCABULARY,
    EXTERNAL_EVENT_TYPES,
    IMPOSSIBILITY_CERTIFICATE_VERSION,
    SOURCE_KINDS,
} from "./constants.mjs";
import { decideNext } from "./decision.mjs";
import {
    DecisionError,
    ERROR_CODES,
    EventChainError,
    TransitionError,
} from "./errors.mjs";
import {
    OBSERVATION_STREAM_HASH_ALGORITHM,
    deriveEvidencePayload,
    normalizeEvidenceProvenance,
} from "./evidence.mjs";
import { deriveImpossibilityVerdict } from "./impossibility.mjs";
import { normalizeSealedHypotheses } from "./hypotheses.mjs";
import {
    ReplicationScheduleError,
    assertReplicationSchedulePolicyBinding,
    deriveReplicationControlBinding,
    normalizeRawMeasurementSeries,
    normalizeReplicationSchedule,
    replicationBlockPlan,
} from "./replication.mjs";
import {
    createNoveltyMeasurementBinding,
    normalizeNoveltyRoleAttempt,
} from "../measurement/novelty-role.mjs";
import { createInitialAggregate } from "./state.mjs";

const RECEIPT_FIELDS = Object.freeze([
    "attemptId",
    "candidateArtifactHash",
    "provenance",
    "rawStderrHash",
    "rawStdoutHash",
    "runnerEpochId",
    "version",
]);
const IMPOSSIBILITY_RECEIPT_FIELDS = Object.freeze([
    "certificateArtifactHash",
    "measurementReceiptArtifactHash",
    "measurementReceiptHash",
    "rawStderrArtifactHash",
    "rawStdoutArtifactHash",
    "verificationRequestHash",
    "verificationSnapshotHash",
]);
function requireString(value, field, maximum = 4096) {
    if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be a non-empty string`,
            { field },
        );
    }
    return value;
}

function requirePlainObject(value, field) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be an object`,
            { field },
        );
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be a plain object`,
            { field },
        );
    }
    return value;
}

export function normalizeEventIdentifier(value, field = "identifier") {
    const identifier = requireString(value, field, 128);
    if (!isSafeDomainIdentifier(identifier)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be a safe identifier, not a filesystem path or prototype key`,
            { field, value },
        );
    }

    return identifier;
}

function ownEntry(record, key) {
    if (record === null || typeof record !== "object" || !Object.hasOwn(record, key)) {
        return null;
    }
    return record[key];
}

function requireOwnField(record, field, path) {
    if (!Object.hasOwn(record, field)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${path} is required`,
            { field: path },
        );
    }
    return record[field];
}

function requireNonNegativeInteger(value, field) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be a non-negative safe integer`,
            { field, value },
        );
    }
    return value;
}

function makeEnvelope(aggregate, type, payload) {
    const core = immutableCanonical({
        seq: aggregate.lastSeq + 1,
        prevHash: aggregate.lastEventHash,
        type,
        payload,
    });
    return immutableCanonical({
        ...core,
        eventHash: computeEventHash(core),
    });
}

export function normalizeCapabilityEpochPayload(payload) {
    const input = requirePlainObject(payload, "payload");
    const epochId = normalizeEventIdentifier(
        requireOwnField(input, "epochId", "epochId"),
        "epochId",
    );
    const capabilities = requireOwnField(input, "capabilities", "capabilities");
    if (!Array.isArray(capabilities)
        || capabilities.some((item) => typeof item !== "string" || item.length === 0)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "capabilities must be an array of non-empty strings",
        );
    }
    return immutableCanonical({
        epochId,
        capabilities: [...new Set(capabilities)].sort(),
    });
}

export function normalizeCommandDispatchedPayload(payload) {
    const input = requirePlainObject(payload, "payload");
    const capabilityEpochId = Object.hasOwn(input, "capabilityEpochId")
        ? input.capabilityEpochId
        : undefined;
    return immutableCanonical({
        commandId: normalizeEventIdentifier(
            requireOwnField(input, "commandId", "commandId"),
            "commandId",
        ),
        capabilityEpochId: capabilityEpochId === undefined
            || capabilityEpochId === null
            ? null
            : normalizeEventIdentifier(capabilityEpochId, "capabilityEpochId"),
    });
}

function normalizeAnnotationHypotheses(value, options) {
    try {
        return normalizeSealedHypotheses(value, {
            observableRegistry: options.observableRegistry ?? [],
            hypothesisPolicy: options.hypothesisPolicy ?? {},
            assignedParentEvidenceIds: options.assignedParentEvidenceIds ?? [],
        });
    } catch (error) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            error.message,
            error.details ?? null,
        );
    }
}

function normalizeAnnotations(
    value,
    maximumCitations = ANNOTATION_LIMITS.citedEvidenceCount,
    hypothesisOptions = {},
    expectedHypotheses = undefined,
) {
    if (value === undefined || value === null) {
        const hypotheses = normalizeAnnotationHypotheses(undefined, hypothesisOptions);
        const normalized = {
            mechanism: null,
            hypothesis: null,
            expectedEffects: [],
            citedEvidenceIds: [],
            finding: null,
            ...(hypotheses === null ? {} : { hypotheses }),
        };
        if (expectedHypotheses !== undefined
            && !canonicalEqual(hypotheses, expectedHypotheses)) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                "annotations.hypotheses must match the kernel-frozen command hypotheses",
            );
        }
        return normalized;
    }
    if (typeof value !== "object" || Array.isArray(value)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "annotations must be an object",
        );
    }
    const allowed = new Set([
        "mechanism",
        "hypothesis",
        "expectedEffects",
        "citedEvidenceIds",
        "finding",
        "hypotheses",
    ]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `annotations.${key} is not supported`,
            );
        }
    }
    const boundedString = (input, field, maximum, maximumBytes) => {
        const text = requireString(input, field, maximum);
        if (Buffer.byteLength(text, "utf8") > maximumBytes) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `${field} exceeds ${maximumBytes} UTF-8 bytes`,
            );
        }
        return text;
    };
    const optionalString = (field, maximum, maximumBytes) => {
        if (!Object.hasOwn(value, field)
            || value[field] === undefined
            || value[field] === null) {
            return null;
        }
        return boundedString(
            value[field],
            `annotations.${field}`,
            maximum,
            maximumBytes,
        );
    };
    const expectedEffects = Object.hasOwn(value, "expectedEffects")
        ? value.expectedEffects ?? []
        : [];
    if (!Array.isArray(expectedEffects)
        || expectedEffects.length > ANNOTATION_LIMITS.expectedEffectCount) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `annotations.expectedEffects must contain at most ${ANNOTATION_LIMITS.expectedEffectCount} items`,
        );
    }
    const citedEvidenceIds = Object.hasOwn(value, "citedEvidenceIds")
        ? value.citedEvidenceIds ?? []
        : [];
    if (!Array.isArray(citedEvidenceIds)
        || citedEvidenceIds.length > Math.min(
            ANNOTATION_LIMITS.citedEvidenceCount,
            maximumCitations,
        )) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "annotations.citedEvidenceIds exceeds the prompt citation bound",
        );
    }
    const normalizedCitations = citedEvidenceIds.map((evidenceId, index) =>
        normalizeEventIdentifier(evidenceId, `annotations.citedEvidenceIds[${index}]`));
    if (new Set(normalizedCitations).size !== normalizedCitations.length) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "annotations.citedEvidenceIds must be unique",
        );
    }
    const normalized = {
        mechanism: optionalString(
            "mechanism",
            ANNOTATION_LIMITS.mechanismLength,
            ANNOTATION_LIMITS.mechanismBytes,
        ),
        hypothesis: optionalString(
            "hypothesis",
            ANNOTATION_LIMITS.hypothesisLength,
            ANNOTATION_LIMITS.hypothesisBytes,
        ),
        expectedEffects: expectedEffects.map((effect, index) =>
            boundedString(
                effect,
                `annotations.expectedEffects[${index}]`,
                ANNOTATION_LIMITS.expectedEffectLength,
                ANNOTATION_LIMITS.expectedEffectBytes,
            )),
        citedEvidenceIds: normalizedCitations,
        finding: optionalString(
            "finding",
            ANNOTATION_LIMITS.findingLength,
            ANNOTATION_LIMITS.findingBytes,
        ),
    };
    const hypotheses = normalizeAnnotationHypotheses(value.hypotheses, hypothesisOptions);
    if (expectedHypotheses !== undefined
        && !canonicalEqual(hypotheses, expectedHypotheses)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "annotations.hypotheses must match the kernel-frozen command hypotheses",
        );
    }
    if (hypotheses !== null) {
        normalized.hypotheses = hypotheses;
    }
    const totalBytes = [
        normalized.mechanism,
        normalized.hypothesis,
        normalized.finding,
        ...normalized.expectedEffects,
        ...normalized.citedEvidenceIds,
    ].reduce(
        (sum, item) => sum + (item === null ? 0 : Buffer.byteLength(item, "utf8")),
        0,
    );
    const hypothesesBytes = hypotheses === null
        ? 0
        : Buffer.byteLength(canonicalJson(hypotheses), "utf8");
    if (totalBytes + hypothesesBytes > ANNOTATION_LIMITS.totalBytes) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `annotations exceed ${ANNOTATION_LIMITS.totalBytes} total UTF-8 bytes`,
        );
    }
    return normalized;
}

function replicatedCandidatePurpose(purpose) {
    return purpose === "candidate"
        || purpose === "confirmation"
        || purpose === "challenge";
}

function replicatedRole(purpose, command) {
    return purpose === "candidate"
        ? "search"
        : command?.harnessRole ?? purpose;
}

function replicatedPhase(purpose, command) {
    return purpose === "candidate"
        ? "search"
        : command?.harnessRole ?? purpose;
}

function normalizeHarnessReceipt(value, purpose, { command = null, contract = null } = {}) {
    const receipt = requirePlainObject(value, "receipt");
    const expectedFields = purpose === "impossibility"
        ? [...RECEIPT_FIELDS, ...IMPOSSIBILITY_RECEIPT_FIELDS]
        : RECEIPT_FIELDS;
    const actualFields = Object.keys(receipt).sort();
    if (!canonicalEqual(actualFields, [...expectedFields].sort())) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "receipt must contain exactly the canonical purpose-specific fields",
            { actualFields, expectedFields },
        );
    }
    if (receipt.version !== 1) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "receipt.version must be 1",
        );
    }
    const candidateArtifactHash = receipt.candidateArtifactHash;
    if (replicatedCandidatePurpose(purpose)) {
        requireAlgorithmHash(candidateArtifactHash, "receipt.candidateArtifactHash");
    } else if (candidateArtifactHash !== null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "Non-candidate harness receipts require candidateArtifactHash=null",
        );
    }
    const provenance = normalizeEvidenceProvenance(receipt.provenance, {
        purpose,
        command,
        contract,
    });
    const normalized = {
        version: 1,
        attemptId: normalizeEventIdentifier(receipt.attemptId, "receipt.attemptId"),
        runnerEpochId: normalizeEventIdentifier(receipt.runnerEpochId, "receipt.runnerEpochId"),
        rawStdoutHash: requireAlgorithmHash(receipt.rawStdoutHash, "receipt.rawStdoutHash"),
        rawStderrHash: requireAlgorithmHash(receipt.rawStderrHash, "receipt.rawStderrHash"),
        candidateArtifactHash,
        provenance,
    };
    if (purpose === "validation") {
        const expectedStdoutHash = hashCanonical(
            provenance.measurements.map((item) => ({
                id: item.subjectId,
                hash: item.rawStdoutHash,
            })),
            OBSERVATION_STREAM_HASH_ALGORITHM,
        );
        const expectedStderrHash = hashCanonical(
            provenance.measurements.map((item) => ({
                id: item.subjectId,
                hash: item.rawStderrHash,
            })),
            OBSERVATION_STREAM_HASH_ALGORITHM,
        );
        if (normalized.rawStdoutHash !== expectedStdoutHash
            || normalized.rawStderrHash !== expectedStderrHash) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                "Validation receipt stream roots are not derived from all case outputs",
            );
        }
    } else if (replicatedCandidatePurpose(purpose)) {
        const expectedStdoutHash = hashCanonical(
            provenance.measurements.map((item) => ({
                id: item.subjectId,
                hash: item.rawStdoutHash,
            })),
            OBSERVATION_STREAM_HASH_ALGORITHM,
        );
        const expectedStderrHash = hashCanonical(
            provenance.measurements.map((item) => ({
                id: item.subjectId,
                hash: item.rawStderrHash,
            })),
            OBSERVATION_STREAM_HASH_ALGORITHM,
        );
        if (normalized.rawStdoutHash !== expectedStdoutHash
            || normalized.rawStderrHash !== expectedStderrHash) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `${purpose} receipt stream roots are not derived from every raw replicate attempt`,
            );
        }
    } else {
        const measurement = provenance.measurements[0];
        if (normalized.rawStdoutHash !== measurement.rawStdoutHash
            || normalized.rawStderrHash !== measurement.rawStderrHash) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                "Harness receipt stream hashes do not match the persisted raw-output artifacts",
            );
        }
    }
    if (replicatedCandidatePurpose(purpose)) {
        const schedule = normalizeReplicationSchedule(command?.replicationSchedule);
        assertReplicationSchedulePolicyBinding({
            schedule,
            contractHash: contractHash(contract),
            statisticalPolicy: contract?.statisticalPolicy,
        });
        const role = replicatedRole(purpose, command);
        const phase = replicatedPhase(purpose, command);
        const roleMeasurements = provenance.measurements.filter(
            (measurement) =>
                measurement.role === role && measurement.phase === phase,
        );
        const noveltyMeasurements = purpose === "candidate"
            ? provenance.measurements.filter(
            (measurement) => measurement.role === "novelty",
        )
            : [];
        if (roleMeasurements.length + noveltyMeasurements.length
            !== provenance.measurements.length) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `${purpose} receipt contains an unsupported measurement role`,
            );
        }
        if (roleMeasurements.length % schedule.arms.length !== 0) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `${purpose} receipt must contain complete replicate blocks`,
            );
        }
        const blockCount = roleMeasurements.length / schedule.arms.length;
        const bySubject = new Map(
            roleMeasurements.map((measurement) => [
                measurement.subjectId,
                measurement,
            ]),
        );
        const candidateSnapshots = [];
        const controlSnapshots = [];
        for (let blockIndex = 0; blockIndex < blockCount; blockIndex += 1) {
            const plan = replicationBlockPlan(schedule, blockIndex);
            for (const arm of plan.arms) {
                const measurement = bySubject.get(arm.subjectId);
                if (measurement === undefined) {
                    throw new TransitionError(
                        ERROR_CODES.INVALID_EVENT,
                        "Candidate receipt is missing a scheduled replicate measurement",
                    );
                }
                if (arm.armId === "candidate") {
                    candidateSnapshots.push(measurement.snapshot.snapshotHash);
                } else if (arm.armId === "control") {
                    controlSnapshots.push(measurement.snapshot.snapshotHash);
                }
            }
        }
        if (candidateSnapshots.length !== blockCount
            || candidateSnapshots.some((hash) => hash !== candidateArtifactHash)
            || new Set(controlSnapshots).size > 1
            || noveltyMeasurements.some((measurement) =>
                measurement.snapshot.snapshotHash !== candidateArtifactHash)) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `${purpose} candidate/control snapshot closures are not stable across measurements`,
            );
        }
        try {
            deriveReplicationControlBinding({
                contractHash: contractHash(contract),
                statisticalPolicy: contract.statisticalPolicy,
                schedule,
                enumerandManifest: contract.enumerandManifest ?? null,
                manifestOptions: {
                    topology: contract.hypothesisTopology,
                    observableRegistry: contract.observableRegistry,
                    hypothesisPolicy: contract.hypothesisPolicy,
                },
                controlSnapshotHashes: controlSnapshots,
                requireObservedControl: true,
            });
        } catch (error) {
            if (!(error instanceof ReplicationScheduleError)) throw error;
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `${purpose} control binding is invalid: ${error.message}`,
                error.details ?? null,
            );
        }
    }
    if (purpose === "impossibility") {
        for (const field of IMPOSSIBILITY_RECEIPT_FIELDS) {
            normalized[field] = requireAlgorithmHash(receipt[field], `receipt.${field}`);
        }
    }
    return immutableCanonical(normalized);
}

function requireBooleanOrNull(value, field) {
    if (value !== null && typeof value !== "boolean") {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be boolean or null`,
            { field, value },
        );
    }
    return value;
}

function normalizeImpossibilityData(value, command) {
    const data = requirePlainObject(value, "data");
    const facts = requirePlainObject(
        requireOwnField(data, "verifiedFacts", "data.verifiedFacts"),
        "data.verifiedFacts",
    );
    const normalizedFacts = {
        pass: (() => {
            const pass = requireOwnField(facts, "pass", "data.verifiedFacts.pass");
            if (typeof pass !== "boolean") {
                throw new TransitionError(
                    ERROR_CODES.INVALID_EVENT,
                    "data.verifiedFacts.pass must be boolean",
                );
            }

            return pass;
        })(),
        searchSpaceExhausted: requireBooleanOrNull(
            requireOwnField(
                facts,
                "searchSpaceExhausted",
                "data.verifiedFacts.searchSpaceExhausted",
            ),
            "data.verifiedFacts.searchSpaceExhausted",
        ),
        parserVersion: requireString(
            requireOwnField(facts, "parserVersion", "data.verifiedFacts.parserVersion"),
            "data.verifiedFacts.parserVersion",
            128,
        ),
    };
    const certificateVerdict = requireOwnField(
        data,
        "certificateVerdict",
        "data.certificateVerdict",
    );
    const expectedVerdict = deriveImpossibilityVerdict(normalizedFacts);
    if (certificateVerdict !== expectedVerdict) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "data.certificateVerdict is not derived from the trusted verifier facts",
            { certificateVerdict, expectedVerdict },
        );
    }
    const certificateVersion = requireString(
        requireOwnField(data, "certificateVersion", "data.certificateVersion"),
        "data.certificateVersion",
        128,
    );
    if (certificateVersion !== (command?.certificateVersion ?? IMPOSSIBILITY_CERTIFICATE_VERSION)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "data.certificateVersion does not match the reserved verifier command",
        );
    }
    return immutableCanonical({
        certificateVersion,
        certificateVerdict,
        certificateArtifactHash: requireAlgorithmHash(
            requireOwnField(
                data,
                "certificateArtifactHash",
                "data.certificateArtifactHash",
            ),
            "data.certificateArtifactHash",
        ),
        measurementReceiptHash: requireAlgorithmHash(
            requireOwnField(
                data,
                "measurementReceiptHash",
                "data.measurementReceiptHash",
            ),
            "data.measurementReceiptHash",
        ),
        verificationRequestHash: requireAlgorithmHash(
            requireOwnField(
                data,
                "verificationRequestHash",
                "data.verificationRequestHash",
            ),
            "data.verificationRequestHash",
        ),
        verificationSnapshotHash: requireAlgorithmHash(
            requireOwnField(
                data,
                "verificationSnapshotHash",
                "data.verificationSnapshotHash",
            ),
            "data.verificationSnapshotHash",
        ),
        verifiedFacts: normalizedFacts,
    });
}

function normalizeCandidateRawData(
    value,
    command,
    {
        contract = null,
        candidateArtifactHash = null,
        purpose = "candidate",
    } = {},
) {
    const input = requirePlainObject(value, "data");
    const allowNovelty = purpose === "candidate";
    const expectedKeys = allowNovelty && input.version === 2
        ? ["novelty", "series", "version"]
        : ["series", "version"];
    if (!canonicalEqual(Object.keys(input).sort(), expectedKeys)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${purpose} data must contain only raw complete measurement series`,
        );
    }
    if ((input.version !== 1 && (!allowNovelty || input.version !== 2))
        || !Array.isArray(input.series)
        || input.series.length !== 1) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${purpose} data must contain exactly one versioned raw measurement series`,
        );
    }
    const role = replicatedRole(purpose, command);
    const phase = replicatedPhase(purpose, command);
    let normalized;
    try {
        normalized = normalizeRawMeasurementSeries(input.series[0], {
            schedule: command?.replicationSchedule,
            role,
            phase,
            caseId: null,
        }).series;
    } catch (error) {
        if (!(error instanceof ReplicationScheduleError)) throw error;
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${purpose} raw measurement series is invalid: ${error.message}`,
            error.details ?? null,
        );
    }
    const schedule = normalizeReplicationSchedule(command?.replicationSchedule);
    if (normalized.completeBlocks.length < schedule.minBlocks
        || normalized.completeBlocks.length > schedule.maxBlocks
        || normalized.completeBlocks.some(
            (block, index) => block.blockIndex !== index,
        )) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${purpose} raw complete blocks do not satisfy the frozen schedule`,
        );
    }
    if (input.version === 1) {
        return immutableCanonical({ version: 1, series: [normalized] });
    }
    let novelty = null;
    if (input.novelty !== null) {
        try {
            novelty = normalizeNoveltyRoleAttempt(input.novelty, {
                expectedBinding: createNoveltyMeasurementBinding({
                    contract,
                    candidateArtifactHash,
                }),
                environmentIdentity:
                    contract?.harnessSuite?.environmentIdentity,
                suiteIdentity: contract?.harnessSuiteIdentity,
            });
        } catch (error) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `candidate novelty attempt is invalid: ${error.message}`,
                error.details ?? null,
            );
        }
    }
    return immutableCanonical({
        version: 2,
        series: [normalized],
        novelty,
    });
}

function normalizeValidationRawData(value, command, contract) {
    const input = requirePlainObject(value, "data");
    if (!canonicalEqual(
        Object.keys(input).sort(),
        ["attemptIndex", "series", "version"],
    )) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "validation data must contain only raw role-tagged measurement series",
        );
    }
    if (input.version !== 1
        || input.attemptIndex !== command?.attemptIndex
        || !Array.isArray(input.series)
        || !Array.isArray(command?.validationSeries)
        || input.series.length !== command.validationSeries.length) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "validation raw series do not match the reserved attempt",
        );
    }
    const supplied = new Map(input.series.map((series) => [
        `${series?.role ?? ""}\0${series?.caseId ?? ""}`,
        series,
    ]));
    if (supplied.size !== input.series.length) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "validation raw series contain a duplicate role/case",
        );
    }
    const normalized = command.validationSeries.map((series) => {
        let item;
        try {
            assertReplicationSchedulePolicyBinding({
                schedule: series.replicationSchedule,
                contractHash: contractHash(contract),
                statisticalPolicy: contract.statisticalPolicy,
            });
            item = normalizeRawMeasurementSeries(
                supplied.get(`${series.role}\0${series.caseId}`),
                {
                    schedule: series.replicationSchedule,
                    role: series.role,
                    phase: "calibration",
                    caseId: series.caseId,
                },
            ).series;
        } catch (error) {
            if (!(error instanceof ReplicationScheduleError)) throw error;
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `validation raw measurement series is invalid: ${error.message}`,
                error.details ?? null,
            );
        }
        if (item.completeBlocks.length !== 1
            || item.completeBlocks[0].blockIndex !== command.attemptIndex) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                "validation observation must contain exactly its reserved complete block",
            );
        }
        return item;
    }).sort((left, right) =>
        `${left.role}\0${left.caseId}`.localeCompare(
            `${right.role}\0${right.caseId}`,
        ));
    return immutableCanonical({
        version: 1,
        attemptIndex: command.attemptIndex,
        series: normalized,
    });
}

function assertRawObservationReceiptBindings(receipt, data, purpose) {
    if (!replicatedCandidatePurpose(purpose) && purpose !== "validation") return;
    const measurements = receipt.provenance.measurements;
    const bySubject = new Map(
        measurements.map((measurement) => [
            measurement.subjectId,
            measurement,
        ]),
    );
    const observations = data.series.flatMap((series) =>
        series.completeBlocks.flatMap((block) => block.observations));
    if (purpose === "candidate" && data.novelty !== null
        && data.novelty !== undefined) {
        observations.push(data.novelty);
    }
    if (bySubject.size !== measurements.length
        || observations.length !== measurements.length
        || observations.some((observation) => {
            const measurement = bySubject.get(observation.subjectId);
            return measurement === undefined
                || observation.receiptHash !== measurement.receiptHash
                || observation.measurementRoot !== measurement.measurementRoot;
        })) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${purpose} raw observations are not bound one-to-one to their persisted measurement receipts`,
        );
    }
}

export function normalizeCommandObservedPayload(payload, aggregate = null, options = {}) {
    const input = requirePlainObject(payload, "payload");
    const sourceKind = requireOwnField(input, "sourceKind", "sourceKind");
    const purpose = requireOwnField(input, "purpose", "purpose");
    if (!SOURCE_KINDS.includes(sourceKind)) {
        throw new TransitionError(ERROR_CODES.INVALID_EVENT, "sourceKind is not supported");
    }
    if (!EVIDENCE_PURPOSES.includes(purpose)) {
        throw new TransitionError(ERROR_CODES.INVALID_EVENT, "purpose is not supported");
    }
    const harnessCandidate = sourceKind === "harness" && purpose === "candidate";
    const harnessReplicated = sourceKind === "harness"
        && replicatedCandidatePurpose(purpose);
    const commandId = normalizeEventIdentifier(
        requireOwnField(input, "commandId", "commandId"),
        "commandId",
    );
    const command = ownEntry(aggregate?.commands, commandId)?.command ?? null;
    const commandHypotheses = harnessReplicated
        ? (() => {
            if (command === null || !Object.hasOwn(command, "hypotheses")) {
                throw new TransitionError(
                    ERROR_CODES.INVALID_EVENT,
                    "Replicated commands must carry kernel-frozen hypotheses",
                );
            }
            return normalizeAnnotationHypotheses(command.hypotheses, {
                observableRegistry:
                    options.observableRegistry
                    ?? aggregate?.contract?.observableRegistry
                    ?? [],
                hypothesisPolicy:
                    options.hypothesisPolicy
                    ?? aggregate?.contract?.hypothesisPolicy
                    ?? {},
                assignedParentEvidenceIds:
                    options.assignedParentEvidenceIds
                    ?? command.parentEvidenceIds
                    ?? [],
            });
        })()
        : null;
    const receipt = sourceKind === "harness"
        ? normalizeHarnessReceipt(requireOwnField(input, "receipt", "receipt"), purpose, {
            command,
            contract: aggregate?.contract ?? null,
        })
        : null;
    const round = Object.hasOwn(input, "round") ? input.round : undefined;
    const slotIndex = Object.hasOwn(input, "slotIndex") ? input.slotIndex : undefined;
    const candidateId = Object.hasOwn(input, "candidateId")
        ? input.candidateId
        : undefined;
    const annotations = Object.hasOwn(input, "annotations")
        ? input.annotations
        : undefined;
    const data = purpose === "impossibility"
        ? normalizeImpossibilityData(
            requireOwnField(input, "data", "data"),
            command,
        )
        : harnessReplicated
            ? normalizeCandidateRawData(
                requireOwnField(input, "data", "data"),
                command,
                {
                    contract: aggregate?.contract ?? null,
                    candidateArtifactHash:
                        receipt?.candidateArtifactHash ?? null,
                    purpose,
                },
            )
            : purpose === "validation"
                ? normalizeValidationRawData(
                    requireOwnField(input, "data", "data"),
                    command,
                    aggregate?.contract ?? null,
                )
                : immutableCanonical(requireOwnField(input, "data", "data"));
    if (receipt !== null) {
        assertRawObservationReceiptBindings(receipt, data, purpose);
    }
    return immutableCanonical({
        commandId,
        observationId: normalizeEventIdentifier(
            requireOwnField(input, "observationId", "observationId"),
            "observationId",
        ),
        sourceKind,
        purpose,
        harnessId: sourceKind === "harness"
            ? normalizeEventIdentifier(
                requireOwnField(input, "harnessId", "harnessId"),
                "harnessId",
            )
            : null,
        parserVersion: sourceKind === "harness"
            ? normalizeEventIdentifier(
                requireOwnField(input, "parserVersion", "parserVersion"),
                "parserVersion",
            )
            : null,
        receipt,
        round: harnessCandidate
            ? requirePositiveInteger(round ?? command?.round, "round")
            : null,
        slotIndex: harnessCandidate
            ? requireNonNegativeInteger(slotIndex ?? command?.slotIndex, "slotIndex")
            : null,
        candidateId: harnessReplicated
            ? normalizeEventIdentifier(candidateId ?? command?.candidateId, "candidateId")
            : null,
        annotations: purpose === "candidate" || harnessReplicated
            ? normalizeAnnotations(
                annotations,
                aggregate?.contract?.searchPolicy?.promptCaps?.promptContextRefs
                    ?? ANNOTATION_LIMITS.citedEvidenceCount,
                {
                    observableRegistry:
                        options.observableRegistry
                        ?? aggregate?.contract?.observableRegistry
                        ?? [],
                    hypothesisPolicy:
                        options.hypothesisPolicy
                        ?? aggregate?.contract?.hypothesisPolicy
                        ?? {},
                    assignedParentEvidenceIds:
                        options.assignedParentEvidenceIds
                        ?? command?.parentEvidenceIds
                        ?? [],
                },
                harnessReplicated ? commandHypotheses : undefined,
            )
            : null,
        data,
    });
}

function requirePositiveInteger(value, field) {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be a positive safe integer`,
            { field, value },
        );
    }
    return value;
}

function requireAlgorithmHash(value, field) {
    if (!isAlgorithmTaggedSha256(value)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be an algorithm-tagged SHA-256 hash`,
        );
    }
    return value;
}

export function normalizeEvidenceInvalidatedPayload(payload) {
    const input = requirePlainObject(payload, "payload");
    return immutableCanonical({
        evidenceId: normalizeEventIdentifier(
            requireOwnField(input, "evidenceId", "evidenceId"),
            "evidenceId",
        ),
        reason: requireString(requireOwnField(input, "reason", "reason"), "reason"),
    });
}

export function normalizeStopRequestedPayload(payload) {
    const input = requirePlainObject(payload, "payload");
    return immutableCanonical({
        requestId: normalizeEventIdentifier(
            requireOwnField(input, "requestId", "requestId"),
            "requestId",
        ),
        reason: requireString(requireOwnField(input, "reason", "reason"), "reason"),
        pauseRequested: Object.hasOwn(input, "pauseRequested")
            && input.pauseRequested === true,
    });
}

export function normalizeExternalEventPayload(type, payload, aggregate = null, options = {}) {
    switch (type) {
        case EVENT_TYPES.CAPABILITY_EPOCH_RECORDED:
            return normalizeCapabilityEpochPayload(payload);
        case EVENT_TYPES.COMMAND_DISPATCHED:
            return normalizeCommandDispatchedPayload(payload);
        case EVENT_TYPES.COMMAND_OBSERVED:
            return normalizeCommandObservedPayload(payload, aggregate, options);
        case EVENT_TYPES.EVIDENCE_INVALIDATED:
            return normalizeEvidenceInvalidatedPayload(payload);
        case EVENT_TYPES.STOP_REQUESTED:
            return normalizeStopRequestedPayload(payload);
        default:
            throw new TransitionError(
                ERROR_CODES.UNKNOWN_EVENT_TYPE,
                `External callers cannot create event type ${type}`,
            );
    }
}

export function computeEventHash(event) {
    if (event === null || typeof event !== "object" || Array.isArray(event)) {
        throw new EventChainError(ERROR_CODES.INVALID_EVENT, "Event must be an object");
    }
    const { eventHash: _excluded, ...hashInput } = event;
    return hashCanonical(hashInput, EVENT_HASH_ALGORITHM);
}

export function createInvestigationOpenedEvent(
    contract,
    experimentAuthority,
    runtimeConfigAuthority,
) {
    const initial = createInitialAggregate();
    const normalizedContract = createInvestigationContract(contract);
    if (experimentAuthority === null || experimentAuthority === undefined) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            "V4 investigations require persisted Ed25519 experiment authority",
        );
    }
    let authority;
    try {
        authority = assertExperimentAuthorityContractBinding(
            experimentAuthority,
            normalizedContract,
        );
    } catch (error) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            `V4 experiment authority is invalid: ${
                error?.message ?? String(error)
            }`,
            { cause: error?.code ?? null },
        );
    }
    if (runtimeConfigAuthority === null
        || runtimeConfigAuthority === undefined) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            "V4 investigations require immutable runtime config authority",
        );
    }
    let runtimeAuthority;
    try {
        runtimeAuthority = normalizeRuntimeConfigAuthority(
            runtimeConfigAuthority,
        );
        if (runtimeAuthority.securityConfig?.runner?.investigationId
            !== authority.manifest.investigationId) {
            throw new Error(
                "runtime config authority belongs to a different investigation",
            );
        }
    } catch (error) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            `V4 runtime config authority is invalid: ${
                error?.message ?? String(error)
            }`,
            { cause: error?.code ?? null },
        );
    }
    return makeEnvelope(initial, EVENT_TYPES.INVESTIGATION_OPENED, {
        domainVersion: DOMAIN_VERSION,
        contract: normalizedContract,
        contractHash: contractHash(normalizedContract),
        experimentAuthority: authority,
        experimentAuthorityIdentity: authority.identity,
        runtimeConfigAuthority: runtimeAuthority,
        runtimeConfigFingerprint: runtimeAuthority.fingerprint,
    });
}

export function constructInvestigationResumedEvent(aggregate) {
    if (aggregate?.terminal !== null || aggregate?.nonResults?.length > 0) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal and non-result investigations cannot be resumed",
        );
    }
    if (aggregate?.pause === null || aggregate?.pause === undefined) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Only a paused investigation can be resumed",
        );
    }
    return makeEnvelope(aggregate, EVENT_TYPES.INVESTIGATION_RESUMED, {
        pausedSeq: aggregate.pause.seq,
        sourceStopRequestSeq: aggregate.pause.sourceStopRequestSeq,
    });
}

export function createExternalEvent(aggregate, type, payload, options = {}) {
    if (aggregate.terminal !== null) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal investigations reject subsequent events",
        );
    }
    if (!EXTERNAL_EVENT_TYPES.includes(type)) {
        throw new TransitionError(
            ERROR_CODES.UNAUTHORIZED_DECISION,
            `Event type ${type} is kernel-owned`,
        );
    }
    return makeEnvelope(
        aggregate,
        type,
        normalizeExternalEventPayload(type, payload, aggregate, options),
    );
}

export function constructHarnessObservedEvent(aggregate, payload, options = {}) {
    if (aggregate.terminal !== null) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal investigations reject subsequent events",
        );
    }
    const reserved = aggregate.commands?.[payload?.commandId]?.command ?? null;
    const hypothesisOptions = {
        ...options,
        observableRegistry: aggregate.contract.observableRegistry,
        hypothesisPolicy: aggregate.contract.hypothesisPolicy,
        assignedParentEvidenceIds: reserved?.parentEvidenceIds ?? [],
    };
    return makeEnvelope(
        aggregate,
        EVENT_TYPES.COMMAND_OBSERVED,
        normalizeCommandObservedPayload({
            ...payload,
            sourceKind: "harness",
            harnessId: reserved?.harnessId ?? aggregate.contract.harnessId,
            parserVersion: reserved?.parserVersion ?? aggregate.contract.parserVersion,
        }, aggregate, hypothesisOptions),
    );
}

export function constructModelObservedEvent(aggregate, payload, options = {}) {
    if (aggregate.terminal !== null) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal investigations reject subsequent events",
        );
    }
    const reserved = aggregate.commands?.[payload?.commandId]?.command ?? null;
    return makeEnvelope(
        aggregate,
        EVENT_TYPES.COMMAND_OBSERVED,
        normalizeCommandObservedPayload({
            ...payload,
            sourceKind: "model_review",
            harnessId: null,
            parserVersion: null,
            receipt: null,
        }, aggregate, {
            ...options,
            observableRegistry: aggregate.contract.observableRegistry,
            hypothesisPolicy: aggregate.contract.hypothesisPolicy,
            assignedParentEvidenceIds: reserved?.parentEvidenceIds ?? [],
        }),
    );
}

export function constructEvidenceCommittedEvent(aggregate, input) {
    if (aggregate.terminal !== null) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal investigations reject subsequent events",
        );
    }
    const normalizedInput = requirePlainObject(input, "input");
    const evidenceId = normalizeEventIdentifier(
        requireOwnField(normalizedInput, "evidenceId", "evidenceId"),
        "evidenceId",
    );
    const observationId = normalizeEventIdentifier(
        requireOwnField(normalizedInput, "observationId", "observationId"),
        "observationId",
    );
    const observation = ownEntry(aggregate.observations, observationId);
    if (observation === null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Evidence must reference an existing command observation",
            { observationId },
        );
    }

    if (observation.sourceKind === "harness" && observation.purpose === "candidate") {
        const duplicate = aggregate.evidenceOrder.some((existingId) => {
            const existing = ownEntry(aggregate.evidence, existingId);
            return existing !== null
                && existing.sourceKind === "harness"
                && existing.purpose === "candidate"
                && !existing.invalidated
                && existing.candidateId === observation.candidateId;
        });
        if (duplicate) {
            throw new TransitionError(
                ERROR_CODES.DUPLICATE_ID,
                "Duplicate candidate identifier",
                { id: observation.candidateId },
            );
        }
        const duplicateSlot = aggregate.evidenceOrder.some((existingId) => {
            const existing = ownEntry(aggregate.evidence, existingId);
            return existing !== null
                && existing.sourceKind === "harness"
                && existing.purpose === "candidate"
                && !existing.invalidated
                && existing.round === observation.round
                && existing.slotIndex === observation.slotIndex;
        });
        if (duplicateSlot) {
            throw new TransitionError(
                ERROR_CODES.DUPLICATE_ID,
                "Duplicate candidate slot",
                { id: `${observation.round}:${observation.slotIndex}` },
            );
        }
    }
    const payload = deriveEvidencePayload(aggregate, observation, evidenceId);
    return makeEnvelope(aggregate, EVENT_TYPES.EVIDENCE_COMMITTED, payload);
}

export function constructKernelDecisionEvent(aggregate) {
    if (aggregate.terminal !== null) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal investigations reject subsequent events",
        );
    }
    const recommendation = decideNext(aggregate);
    if (recommendation.event === null) {
        throw new DecisionError(
            ERROR_CODES.NO_DECISION_EVENT,
            "The next action is operational and does not create a decision event",
            { recommendation },
        );
    }
    if (!EVENT_VOCABULARY.includes(recommendation.event.type)) {
        throw new DecisionError(
            ERROR_CODES.UNKNOWN_EVENT_TYPE,
            "Decision function returned an unknown event type",
        );
    }
    return makeEnvelope(
        aggregate,
        recommendation.event.type,
        recommendation.event.payload,
    );
}

export function decisionEventMatches(aggregate, event) {
    const expected = decideNext(aggregate).event;
    return expected !== null
        && expected.type === event.type
        && canonicalEqual(expected.payload, event.payload);
}
