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
    EVIDENCE_PURPOSES,
    EVENT_TYPES,
    EVENT_VOCABULARY,
    EXTERNAL_EVENT_TYPES,
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
import { createInitialAggregate } from "./state.mjs";

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

function requireIdentifier(value, field) {
    const identifier = requireString(value, field, 128);
    if (!/^[A-Za-z0-9][A-Za-z0-9._@-]*$/u.test(identifier)
        || identifier === "."
        || identifier === ".."
        || identifier.includes("..")) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${field} must be an identifier`,
            { field, value },
        );
    }
    return identifier;
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

function normalizeCapabilityEpoch(payload) {
    requireString(payload?.epochId, "epochId", 128);
    if (!Array.isArray(payload.capabilities)
        || payload.capabilities.some((item) => typeof item !== "string" || item.length === 0)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "capabilities must be an array of non-empty strings",
        );
    }
    return {
        epochId: payload.epochId,
        capabilities: [...new Set(payload.capabilities)].sort(),
    };
}

function normalizeCommandDispatched(payload) {
    return {
        commandId: requireString(payload?.commandId, "commandId", 128),
        capabilityEpochId: payload?.capabilityEpochId === undefined
            ? null
            : payload.capabilityEpochId,
    };
}

function normalizeCommandObserved(payload) {
    const sourceKind = payload?.sourceKind;
    const purpose = payload?.purpose;
    if (!SOURCE_KINDS.includes(sourceKind)) {
        throw new TransitionError(ERROR_CODES.INVALID_EVENT, "sourceKind is not supported");
    }
    if (!EVIDENCE_PURPOSES.includes(purpose)) {
        throw new TransitionError(ERROR_CODES.INVALID_EVENT, "purpose is not supported");
    }
    const harnessCandidate = sourceKind === "harness" && purpose === "candidate";
    const receipt = sourceKind === "harness"
        ? {
            attemptId: requireString(payload.receipt?.attemptId, "receipt.attemptId", 128),
            runnerEpochId: requireString(payload.receipt?.runnerEpochId, "receipt.runnerEpochId", 128),
            rawStdoutHash: requireAlgorithmHash(payload.receipt?.rawStdoutHash, "receipt.rawStdoutHash"),
            rawStderrHash: requireAlgorithmHash(payload.receipt?.rawStderrHash, "receipt.rawStderrHash"),
            candidateArtifactHash: payload.receipt?.candidateArtifactHash === null
                ? null
                : requireAlgorithmHash(payload.receipt?.candidateArtifactHash, "receipt.candidateArtifactHash"),
        }
        : null;
    if (harnessCandidate && receipt.candidateArtifactHash === null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            "Harness candidate observations require a candidate artifact hash",
        );
    }
    return {
        commandId: requireString(payload.commandId, "commandId", 128),
        observationId: requireString(payload.observationId, "observationId", 128),
        sourceKind,
        purpose,
        harnessId: sourceKind === "harness"
            ? requireString(payload.harnessId, "harnessId", 128)
            : null,
        parserVersion: sourceKind === "harness"
            ? requireString(payload.parserVersion, "parserVersion", 128)
            : null,
        receipt,
        round: harnessCandidate
            ? requirePositiveInteger(payload.round, "round")
            : null,
        candidateId: harnessCandidate
            ? requireIdentifier(payload.candidateId, "candidateId")
            : null,
        data: immutableCanonical(payload.data),
    };
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

function normalizeEvidenceInvalidated(payload) {
    return {
        evidenceId: requireString(payload?.evidenceId, "evidenceId", 128),
        reason: requireString(payload?.reason, "reason"),
    };
}

function normalizeStopRequested(payload) {
    return {
        requestId: requireString(payload?.requestId, "requestId", 128),
        reason: requireString(payload?.reason, "reason"),
        pauseRequested: payload?.pauseRequested === true,
    };
}

function normalizeExternalPayload(type, payload) {
    switch (type) {
        case EVENT_TYPES.CAPABILITY_EPOCH_RECORDED:
            return normalizeCapabilityEpoch(payload);
        case EVENT_TYPES.COMMAND_DISPATCHED:
            return normalizeCommandDispatched(payload);
        case EVENT_TYPES.COMMAND_OBSERVED:
            return normalizeCommandObserved(payload);
        case EVENT_TYPES.EVIDENCE_INVALIDATED:
            return normalizeEvidenceInvalidated(payload);
        case EVENT_TYPES.STOP_REQUESTED:
            return normalizeStopRequested(payload);
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
    return makeEnvelope(aggregate, type, normalizeExternalPayload(type, payload));
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
        normalizeCommandObserved({
            ...payload,
            sourceKind: "harness",
            harnessId: aggregate.contract.harnessId,
            parserVersion: aggregate.contract.parserVersion,
        }),
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
        normalizeCommandObserved({
            ...payload,
            sourceKind: "model_review",
            harnessId: null,
            parserVersion: null,
            receipt: null,
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
    const evidenceId = requireString(input?.evidenceId, "evidenceId", 128);
    const observationId = requireString(input?.observationId, "observationId", 128);
    const observation = aggregate.observations[observationId];
    if (observation === undefined) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Evidence must reference an existing command observation",
            { observationId },
        );
    }

    if (observation.sourceKind === "harness" && observation.purpose === "candidate") {
        const duplicate = aggregate.evidenceOrder.some((existingId) =>
            aggregate.evidence[existingId].sourceKind === "harness"
            && aggregate.evidence[existingId].purpose === "candidate"
            && aggregate.evidence[existingId].candidateId === observation.candidateId);
        if (duplicate) {
            throw new TransitionError(
                ERROR_CODES.DUPLICATE_ID,
                "Duplicate candidate identifier",
                { id: observation.candidateId },
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
