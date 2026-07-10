import {
    canonicalEqual,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    contractHash,
    createInvestigationContract,
} from "./contract.mjs";
import {
    DOMAIN_VERSION,
    EVENT_TYPES,
    EVENT_VOCABULARY,
    KERNEL_DECISION_EVENT_TYPES,
} from "./constants.mjs";
import { decisionEventMatches, computeEventHash } from "./events.mjs";
import {
    ERROR_CODES,
    DomainVersionRestartRequiredError,
    EventChainError,
    TransitionError,
} from "./errors.mjs";
import { deriveEvidencePayload } from "./evidence.mjs";
import { createInitialAggregate } from "./state.mjs";

const EVENT_KEYS = Object.freeze(["eventHash", "payload", "prevHash", "seq", "type"]);

function assertEventEnvelope(aggregate, event) {
    if (event === null || typeof event !== "object" || Array.isArray(event)) {
        throw new EventChainError(ERROR_CODES.INVALID_EVENT, "Event must be an object");
    }
    const keys = Object.keys(event).sort();
    if (!canonicalEqual(keys, EVENT_KEYS)) {
        throw new EventChainError(
            ERROR_CODES.INVALID_EVENT,
            "Event envelope contains missing or unexpected fields",
            { keys },
        );
    }
    if (!EVENT_VOCABULARY.includes(event.type)) {
        throw new EventChainError(
            ERROR_CODES.UNKNOWN_EVENT_TYPE,
            `Unknown event type ${event.type}`,
        );
    }
    if (!Number.isSafeInteger(event.seq) || event.seq !== aggregate.lastSeq + 1) {
        throw new EventChainError(
            ERROR_CODES.EVENT_SEQUENCE_MISMATCH,
            "Event sequence is not contiguous",
            { expected: aggregate.lastSeq + 1, actual: event.seq },
        );
    }
    if (event.prevHash !== aggregate.lastEventHash) {
        throw new EventChainError(
            ERROR_CODES.EVENT_PREV_HASH_MISMATCH,
            "Event prevHash does not match the aggregate head",
            { expected: aggregate.lastEventHash, actual: event.prevHash },
        );
    }
    const expectedHash = computeEventHash(event);
    if (event.eventHash !== expectedHash) {
        throw new EventChainError(
            ERROR_CODES.EVENT_HASH_MISMATCH,
            "Event hash does not match canonical event content",
            { expected: expectedHash, actual: event.eventHash },
        );
    }
}

function requireOpen(aggregate, event) {
    if (event.type === EVENT_TYPES.INVESTIGATION_OPENED) {
        if (aggregate.contract !== null) {
            throw new TransitionError(
                ERROR_CODES.ILLEGAL_TRANSITION,
                "An investigation can only be opened once",
            );
        }
        return;
    }
    if (aggregate.contract === null) {
        throw new TransitionError(
            ERROR_CODES.INVESTIGATION_NOT_OPEN,
            "The investigation_opened event must be first",
        );
    }
}

function duplicate(kind, id) {
    throw new TransitionError(
        ERROR_CODES.DUPLICATE_ID,
        `Duplicate ${kind} identifier`,
        { id },
    );
}

function applyInvestigationOpened(next, event) {
    if (event.payload?.domainVersion !== DOMAIN_VERSION) {
        throw new DomainVersionRestartRequiredError(
            "Investigation event history uses an incompatible domain version; start a new investigation",
            {
                expectedDomainVersion: DOMAIN_VERSION,
                actualDomainVersion: event.payload?.domainVersion ?? null,
            },
        );
    }
    if (event.payload?.contract === null || typeof event.payload?.contract !== "object") {
        throw new TransitionError(ERROR_CODES.INVALID_CONTRACT, "Opened event has no contract");
    }
    const normalizedContract = createInvestigationContract(event.payload.contract);
    if (!canonicalEqual(normalizedContract, event.payload.contract)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            "Opened event contract is not in canonical kernel form",
        );
    }
    const expectedHash = contractHash(normalizedContract);
    if (event.payload.contractHash !== expectedHash) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            "Opened event contract hash is invalid",
        );
    }
    next.contract = normalizedContract;
    next.contractHash = expectedHash;
    next.status = "active";
}

function applyCapabilityEpoch(next, event) {
    const { epochId, capabilities } = event.payload;
    if (next.capabilityEpochs[epochId] !== undefined) {
        duplicate("capability epoch", epochId);
    }
    next.capabilityEpochs[epochId] = {
        epochId,
        capabilities,
        seq: event.seq,
    };
    next.capabilityEpochOrder.push(epochId);
}

function applyCommandReserved(next, event) {
    const { commandId, command } = event.payload;
    if (next.commands[commandId] !== undefined) {
        duplicate("command", commandId);
    }
    next.commands[commandId] = {
        commandId,
        command,
        status: "reserved",
        reservedSeq: event.seq,
        dispatchedSeq: null,
        observationId: null,
    };
    next.commandOrder.push(commandId);
}

function applyCommandDispatched(next, event) {
    const { commandId, capabilityEpochId } = event.payload;
    const command = next.commands[commandId];
    if (command === undefined) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Cannot dispatch an unknown command",
            { commandId },
        );
    }
    if (command.status !== "reserved") {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Command may only be dispatched once from reserved state",
            { commandId, status: command.status },
        );
    }
    if (capabilityEpochId !== null && next.capabilityEpochs[capabilityEpochId] === undefined) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Dispatched command references an unknown capability epoch",
            { capabilityEpochId },
        );
    }
    command.status = "dispatched";
    command.dispatchedSeq = event.seq;
    command.capabilityEpochId = capabilityEpochId;
}

function applyCommandObserved(next, event) {
    const payload = event.payload;
    const command = next.commands[payload.commandId];
    if (command === undefined || command.status !== "dispatched") {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Only a dispatched command can be observed",
            { commandId: payload.commandId },
        );
    }
    if (next.observations[payload.observationId] !== undefined) {
        duplicate("observation", payload.observationId);
    }
    if (payload.sourceKind === "harness"
        && (payload.harnessId !== next.contract.harnessId
            || payload.parserVersion !== next.contract.parserVersion)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Harness observation does not match the immutable contract",
        );
    }
    if (command.command.kind === "run_validation"
        && (payload.sourceKind !== "harness" || payload.purpose !== "validation")) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Validation commands require harness validation observations",
        );
    }
    if (command.command.kind === "search_candidate"
        && (payload.sourceKind !== "harness" || payload.purpose !== "candidate")) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Search-candidate commands require authoritative harness candidate observations",
        );
    }
    if (payload.purpose === "candidate") {
        const promptRefs = new Set(command.command.promptContextRefs ?? []);
        if (payload.annotations.citedEvidenceIds.some((evidenceId) => !promptRefs.has(evidenceId))) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Candidate annotations may cite only evidence included in promptContextRefs",
                {
                    citedEvidenceIds: payload.annotations.citedEvidenceIds,
                    promptContextRefs: command.command.promptContextRefs ?? [],
                },
            );
        }
    }
    if (payload.sourceKind === "harness" && payload.purpose === "candidate") {
        if (!Number.isSafeInteger(payload.round)
            || payload.round < 1
            || !Number.isSafeInteger(payload.slotIndex)
            || payload.slotIndex < 0
            || typeof payload.candidateId !== "string"
            || !/^[A-Za-z0-9][A-Za-z0-9._@-]*$/u.test(payload.candidateId)
            || payload.candidateId.includes("..")
            || !isAlgorithmTaggedSha256(payload.receipt?.candidateArtifactHash)) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Harness candidate observation has invalid round, candidateId, or artifact receipt",
            );
        }
        if (command.command.kind !== "search_candidate"
            || payload.round !== command.command.round
            || payload.slotIndex !== command.command.slotIndex
            || payload.candidateId !== command.command.candidateId) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Harness candidate observations must match the reserved search-candidate assignment",
            );
        }
        if (payload.round > next.contract.maxRounds) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Harness candidate observation exceeds the frozen maximum round",
            );
        }
        const boundedIds = next.contract.boundedCandidateIds;
        if (boundedIds !== undefined && !boundedIds.includes(payload.candidateId)) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Harness candidate is outside the frozen bounded search space",
                { candidateId: payload.candidateId },
            );
        }
        if ((command.command.boundedCandidateId ?? null)
            !== (boundedIds === undefined ? null : payload.candidateId)) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Harness candidate observation does not match its bounded candidate assignment",
            );
        }
    }
    next.observations[payload.observationId] = {
        ...payload,
        observedSeq: event.seq,
        evidenceId: null,
    };
    next.observationOrder.push(payload.observationId);
    command.status = "observed";
    command.observationId = payload.observationId;
}

function applyEvidenceCommitted(next, event) {
    const payload = event.payload;
    if (next.evidence[payload.evidenceId] !== undefined) {
        duplicate("evidence", payload.evidenceId);
    }
    const observation = next.observations[payload.observationId];
    if (observation === undefined || observation.evidenceId !== null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Evidence must reference one uncommitted observation",
        );
    }
    if (observation.sourceKind === "harness" && observation.purpose === "candidate") {
        const duplicateCandidate = next.evidenceOrder.some((evidenceId) =>
            next.evidence[evidenceId].sourceKind === "harness"
            && next.evidence[evidenceId].purpose === "candidate"
            && !next.evidence[evidenceId].invalidated
            && next.evidence[evidenceId].candidateId === observation.candidateId);
        if (duplicateCandidate) {
            duplicate("candidate", observation.candidateId);
        }
        const duplicateSlot = next.evidenceOrder.some((evidenceId) =>
            next.evidence[evidenceId].sourceKind === "harness"
            && next.evidence[evidenceId].purpose === "candidate"
            && !next.evidence[evidenceId].invalidated
            && next.evidence[evidenceId].round === observation.round
            && next.evidence[evidenceId].slotIndex === observation.slotIndex);
        if (duplicateSlot) {
            duplicate("candidate slot", `${observation.round}:${observation.slotIndex}`);
        }
    }
    const expected = deriveEvidencePayload(next, observation, payload.evidenceId);
    if (!canonicalEqual(payload, expected)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Committed evidence fields are not kernel-derived from the observation",
        );
    }

    next.evidence[payload.evidenceId] = {
        ...payload,
        committedSeq: event.seq,
        commitEventHash: event.eventHash,
        invalidated: false,
        invalidatedSeq: null,
        invalidationReason: null,
    };
    next.evidenceOrder.push(payload.evidenceId);
    observation.evidenceId = payload.evidenceId;
}

function applyEvidenceInvalidated(next, event) {
    const evidence = next.evidence[event.payload.evidenceId];
    if (evidence === undefined) {
        throw new TransitionError(
            ERROR_CODES.EVIDENCE_NOT_FOUND,
            "Cannot invalidate unknown evidence",
            { evidenceId: event.payload.evidenceId },
        );
    }
    if (evidence.invalidated) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Evidence may only be invalidated once",
            { evidenceId: evidence.evidenceId },
        );
    }
    evidence.invalidated = true;
    evidence.invalidatedSeq = event.seq;
    evidence.invalidationReason = event.payload.reason;
    if (next.validation.currentEvidenceId === evidence.evidenceId) {
        next.validation.currentEvidenceId = null;
    }
}

function applyValidationCompleted(next, event) {
    const evidence = next.evidence[event.payload.evidenceId];
    if (evidence === undefined
        || evidence.invalidated
        || evidence.validationSatisfied !== true
        || event.payload.evidenceHash !== evidence.commitEventHash) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Validation completion requires current committed harness validation evidence",
        );
    }
    if (next.validation.completions.some((item) => item.evidenceId === evidence.evidenceId)) {
        duplicate("validation evidence", evidence.evidenceId);
    }
    next.validation.currentEvidenceId = evidence.evidenceId;
    next.validation.completions.push({
        ...event.payload,
        seq: event.seq,
    });
}

function applySearchStrategyRevised(next, event) {
    if (event.payload.revision !== next.searchStrategy.revision + 1) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Search strategy revisions must be contiguous",
        );
    }
    next.searchStrategy.revision = event.payload.revision;
    next.searchStrategy.history.push({
        ...event.payload,
        seq: event.seq,
    });
}

function applyStopRequested(next, event) {
    if (next.stopRequests.some((request) => request.requestId === event.payload.requestId)) {
        duplicate("stop request", event.payload.requestId);
    }
    next.stopRequests.push({
        ...event.payload,
        seq: event.seq,
    });
}

function applyInvestigationPaused(next, event) {
    if (next.pause !== null) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Investigation is already paused",
        );
    }
    next.pause = {
        ...event.payload,
        seq: event.seq,
    };
    next.pauseHistory.push(next.pause);
    next.status = "paused";
}

function applyInvestigationResumed(next, event) {
    if (next.pause === null
        || event.payload?.pausedSeq !== next.pause.seq
        || event.payload?.sourceStopRequestSeq !== next.pause.sourceStopRequestSeq
        || !canonicalEqual(
            Object.keys(event.payload ?? {}).sort(),
            ["pausedSeq", "sourceStopRequestSeq"],
        )) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "investigation_resumed must exactly reference the current persisted pause",
        );
    }
    next.pause = null;
    next.status = "active";
}

function applyNonResult(next, event) {
    if (next.nonResults.some((item) =>
        item.code === event.payload.code
        && item.sourceStopRequestSeq === event.payload.sourceStopRequestSeq)) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Duplicate non-result decision",
        );
    }
    next.nonResults.push({
        ...event.payload,
        seq: event.seq,
    });
    next.status = "non_result";
}

function applyTerminal(next, event) {
    next.terminal = {
        ...event.payload,
        seq: event.seq,
        eventHash: event.eventHash,
    };
    next.status = "terminal";
}

function applyTransition(next, event) {
    switch (event.type) {
        case EVENT_TYPES.INVESTIGATION_OPENED:
            applyInvestigationOpened(next, event);
            break;
        case EVENT_TYPES.CAPABILITY_EPOCH_RECORDED:
            applyCapabilityEpoch(next, event);
            break;
        case EVENT_TYPES.COMMAND_RESERVED:
            applyCommandReserved(next, event);
            break;
        case EVENT_TYPES.COMMAND_DISPATCHED:
            applyCommandDispatched(next, event);
            break;
        case EVENT_TYPES.COMMAND_OBSERVED:
            applyCommandObserved(next, event);
            break;
        case EVENT_TYPES.EVIDENCE_COMMITTED:
            applyEvidenceCommitted(next, event);
            break;
        case EVENT_TYPES.EVIDENCE_INVALIDATED:
            applyEvidenceInvalidated(next, event);
            break;
        case EVENT_TYPES.VALIDATION_COMPLETED:
            applyValidationCompleted(next, event);
            break;
        case EVENT_TYPES.SEARCH_STRATEGY_REVISED:
            applySearchStrategyRevised(next, event);
            break;
        case EVENT_TYPES.STOP_REQUESTED:
            applyStopRequested(next, event);
            break;
        case EVENT_TYPES.INVESTIGATION_PAUSED:
            applyInvestigationPaused(next, event);
            break;
        case EVENT_TYPES.INVESTIGATION_RESUMED:
            applyInvestigationResumed(next, event);
            break;
        case EVENT_TYPES.NON_RESULT_RECORDED:
            applyNonResult(next, event);
            break;
        case EVENT_TYPES.VERIFIED_RESULT:
        case EVENT_TYPES.TARGET_UNREACHABLE:
            applyTerminal(next, event);
            break;
        default:
            throw new TransitionError(
                ERROR_CODES.UNKNOWN_EVENT_TYPE,
                `Unknown event type ${event.type}`,
            );
    }
}

export function reduceEvent(aggregate, event) {
    if (aggregate?.domainVersion !== DOMAIN_VERSION) {
        throw new DomainVersionRestartRequiredError(
            "Aggregate domain version is incompatible; start a new investigation",
            {
                expectedDomainVersion: DOMAIN_VERSION,
                actualDomainVersion: aggregate?.domainVersion ?? null,
            },
        );
    }
    assertEventEnvelope(aggregate, event);
    if (aggregate.terminal !== null) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Terminal investigations reject subsequent events",
        );
    }
    if (aggregate.nonResults.length > 0) {
        throw new TransitionError(
            ERROR_CODES.TERMINAL_STATE,
            "Non-result investigations reject subsequent events",
        );
    }
    if (aggregate.pause !== null && event.type !== EVENT_TYPES.INVESTIGATION_RESUMED) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Paused investigations accept only the kernel-owned investigation_resumed transition",
        );
    }
    requireOpen(aggregate, event);

    if (KERNEL_DECISION_EVENT_TYPES.includes(event.type)
        && !decisionEventMatches(aggregate, event)) {
        throw new TransitionError(
            ERROR_CODES.UNAUTHORIZED_DECISION,
            "Decision event is not the deterministic decision for the current aggregate",
            { type: event.type },
        );
    }

    const next = JSON.parse(JSON.stringify(aggregate));
    applyTransition(next, event);
    next.lastSeq = event.seq;
    next.lastEventHash = event.eventHash;
    return immutableCanonical(next);
}

export function replayEvents(events) {
    let aggregate = createInitialAggregate();
    for (const event of events) {
        aggregate = reduceEvent(aggregate, event);
    }
    return aggregate;
}

export function verifyEventChain(events) {
    let lastSeq = 0;
    let lastEventHash = null;
    for (const event of events) {
        assertEventEnvelope({ lastSeq, lastEventHash }, event);
        if (event.seq === 1
            && event.type === EVENT_TYPES.INVESTIGATION_OPENED
            && event.payload?.domainVersion !== DOMAIN_VERSION) {
            throw new DomainVersionRestartRequiredError(
                "Investigation event history uses an incompatible domain version; start a new investigation",
                {
                    expectedDomainVersion: DOMAIN_VERSION,
                    actualDomainVersion: event.payload?.domainVersion ?? null,
                },
            );
        }
        lastSeq = event.seq;
        lastEventHash = event.eventHash;
    }
    return immutableCanonical({
        valid: true,
        eventCount: events.length,
        lastSeq,
        lastEventHash,
    });
}
