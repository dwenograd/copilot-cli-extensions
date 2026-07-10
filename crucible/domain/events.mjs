import {
    EVENT_HASH_ALGORITHM,
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    contractHash,
    createInvestigationContract,
} from "./contract.mjs";
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
import { deriveEvidencePayload } from "./evidence.mjs";
import { deriveImpossibilityVerdict } from "./impossibility.mjs";
import { createInitialAggregate } from "./state.mjs";

const FORBIDDEN_IDENTIFIERS = new Set([
    "__proto__",
    "constructor",
    "prototype",
]);
const RECEIPT_FIELDS = Object.freeze([
    "attemptId",
    "runnerEpochId",
    "rawStdoutHash",
    "rawStderrHash",
    "candidateArtifactHash",
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
    if (!/^[A-Za-z0-9][A-Za-z0-9._@-]*$/u.test(identifier)
        || identifier === "."
        || identifier === ".."
        || identifier.endsWith(".")
        || identifier.includes("..")
        || FORBIDDEN_IDENTIFIERS.has(identifier.toLowerCase())) {
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

function normalizeAnnotations(value, maximumCitations = ANNOTATION_LIMITS.citedEvidenceCount) {
    if (value === undefined || value === null) {
        return {
            mechanism: null,
            hypothesis: null,
            expectedEffects: [],
            citedEvidenceIds: [],
            finding: null,
        };
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
    ]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVENT,
                `annotations.${key} is not supported`,
            );
        }
    }
    const optionalString = (field, maximum) => {
        if (!Object.hasOwn(value, field)
            || value[field] === undefined
            || value[field] === null) {
            return null;
        }
        return requireString(value[field], `annotations.${field}`, maximum);
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
    return {
        mechanism: optionalString("mechanism", ANNOTATION_LIMITS.mechanismLength),
        hypothesis: optionalString("hypothesis", ANNOTATION_LIMITS.hypothesisLength),
        expectedEffects: expectedEffects.map((effect, index) =>
            requireString(
                effect,
                `annotations.expectedEffects[${index}]`,
                ANNOTATION_LIMITS.expectedEffectLength,
            )),
        citedEvidenceIds: normalizedCitations,
        finding: optionalString("finding", ANNOTATION_LIMITS.findingLength),
    };
}

function normalizeHarnessReceipt(value, purpose) {
    const receipt = requirePlainObject(value, "receipt");
    for (const field of RECEIPT_FIELDS) {
        requireOwnField(receipt, field, `receipt.${field}`);
    }
    if (purpose === "impossibility") {
        for (const field of IMPOSSIBILITY_RECEIPT_FIELDS) {
            requireOwnField(receipt, field, `receipt.${field}`);
        }
    }
    const candidateArtifactHash = receipt.candidateArtifactHash;
    if (purpose === "candidate") {
        requireAlgorithmHash(candidateArtifactHash, "receipt.candidateArtifactHash");
    } else if (candidateArtifactHash !== null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "Non-candidate harness receipts require candidateArtifactHash=null",
        );
    }
    const normalized = {
        attemptId: normalizeEventIdentifier(receipt.attemptId, "receipt.attemptId"),
        runnerEpochId: normalizeEventIdentifier(receipt.runnerEpochId, "receipt.runnerEpochId"),
        rawStdoutHash: requireAlgorithmHash(receipt.rawStdoutHash, "receipt.rawStdoutHash"),
        rawStderrHash: requireAlgorithmHash(receipt.rawStderrHash, "receipt.rawStderrHash"),
        candidateArtifactHash,
    };
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

export function normalizeCommandObservedPayload(payload, aggregate = null) {
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
    const commandId = normalizeEventIdentifier(
        requireOwnField(input, "commandId", "commandId"),
        "commandId",
    );
    const command = ownEntry(aggregate?.commands, commandId)?.command ?? null;
    const receipt = sourceKind === "harness"
        ? normalizeHarnessReceipt(requireOwnField(input, "receipt", "receipt"), purpose)
        : null;
    const round = Object.hasOwn(input, "round") ? input.round : undefined;
    const slotIndex = Object.hasOwn(input, "slotIndex") ? input.slotIndex : undefined;
    const candidateId = Object.hasOwn(input, "candidateId")
        ? input.candidateId
        : undefined;
    const annotations = Object.hasOwn(input, "annotations")
        ? input.annotations
        : undefined;
    return immutableCanonical({
        commandId,
        observationId: normalizeEventIdentifier(
            requireOwnField(input, "observationId", "observationId"),
            "observationId",
        ),
        sourceKind,
        purpose,
        harnessId: sourceKind === "harness"
            ? requireString(
                requireOwnField(input, "harnessId", "harnessId"),
                "harnessId",
                128,
            )
            : null,
        parserVersion: sourceKind === "harness"
            ? requireString(
                requireOwnField(input, "parserVersion", "parserVersion"),
                "parserVersion",
                128,
            )
            : null,
        receipt,
        round: harnessCandidate
            ? requirePositiveInteger(round ?? command?.round, "round")
            : null,
        slotIndex: harnessCandidate
            ? requireNonNegativeInteger(slotIndex ?? command?.slotIndex, "slotIndex")
            : null,
        candidateId: harnessCandidate
            ? normalizeEventIdentifier(candidateId ?? command?.candidateId, "candidateId")
            : null,
        annotations: purpose === "candidate"
            ? normalizeAnnotations(
                annotations,
                aggregate?.contract?.searchPolicy?.promptCaps?.promptContextRefs
                    ?? ANNOTATION_LIMITS.citedEvidenceCount,
            )
            : null,
        data: purpose === "impossibility"
            ? normalizeImpossibilityData(
                requireOwnField(input, "data", "data"),
                command,
            )
            : immutableCanonical(requireOwnField(input, "data", "data")),
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

export function normalizeExternalEventPayload(type, payload, aggregate = null) {
    switch (type) {
        case EVENT_TYPES.CAPABILITY_EPOCH_RECORDED:
            return normalizeCapabilityEpochPayload(payload);
        case EVENT_TYPES.COMMAND_DISPATCHED:
            return normalizeCommandDispatchedPayload(payload);
        case EVENT_TYPES.COMMAND_OBSERVED:
            return normalizeCommandObservedPayload(payload, aggregate);
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

export function createInvestigationOpenedEvent(contract) {
    const initial = createInitialAggregate();
    const normalizedContract = createInvestigationContract(contract);
    return makeEnvelope(initial, EVENT_TYPES.INVESTIGATION_OPENED, {
        domainVersion: DOMAIN_VERSION,
        contract: normalizedContract,
        contractHash: contractHash(normalizedContract),
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

export function createExternalEvent(aggregate, type, payload) {
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
        normalizeExternalEventPayload(type, payload, aggregate),
    );
}

export function constructHarnessObservedEvent(aggregate, payload) {
    if (aggregate.terminal !== null) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal investigations reject subsequent events",
        );
    }
    return makeEnvelope(
        aggregate,
        EVENT_TYPES.COMMAND_OBSERVED,
        normalizeCommandObservedPayload({
            ...payload,
            sourceKind: "harness",
            harnessId: aggregate.contract.harnessId,
            parserVersion: aggregate.contract.parserVersion,
        }, aggregate),
    );
}

export function constructModelObservedEvent(aggregate, payload) {
    if (aggregate.terminal !== null) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal investigations reject subsequent events",
        );
    }
    return makeEnvelope(
        aggregate,
        EVENT_TYPES.COMMAND_OBSERVED,
        normalizeCommandObservedPayload({
            ...payload,
            sourceKind: "model_review",
            harnessId: null,
            parserVersion: null,
            receipt: null,
        }, aggregate),
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
