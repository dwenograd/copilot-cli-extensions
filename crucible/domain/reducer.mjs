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
    assertExperimentAuthorityContractBinding,
} from "./authority.mjs";
import {
    normalizeRuntimeConfigAuthority,
} from "./runtime-authority.mjs";
import {
    DOMAIN_VERSION,
    EVENT_TYPES,
    EVENT_VOCABULARY,
    EXTERNAL_EVENT_TYPES,
    KERNEL_DECISION_EVENT_TYPES,
} from "./constants.mjs";
import {
    computeEventHash,
    decisionEventMatches,
    normalizeEventIdentifier,
    normalizeExternalEventPayload,
} from "./events.mjs";
import {
    ERROR_CODES,
    DomainVersionRestartRequiredError,
    EventChainError,
    TransitionError,
} from "./errors.mjs";
import {
    assertEnumerandBinding,
    enumerandArtifactMeasurementHash,
    normalizeEnumerandManifest,
} from "./enumerands.mjs";
import {
    deriveEvidencePayload,
    deriveRawObservationAuthorityDigest,
} from "./evidence.mjs";
import { deriveScientificReplayState } from "./scientific-replay.mjs";
import {
    cloneAggregateForMutation,
    createInitialAggregate,
    immutableAggregate,
} from "./state.mjs";
import {
    bindAggregateImpossibilityExecution,
    verifierExecutionCapabilityForEvent,
} from "./private-verifier-execution.mjs";

const EVENT_KEYS = Object.freeze(["eventHash", "payload", "prevHash", "seq", "type"]);
const SCIENTIFIC_REPLAY_EVENT_TYPES = new Set([
    EVENT_TYPES.INVESTIGATION_OPENED,
    EVENT_TYPES.EVIDENCE_COMMITTED,
    EVENT_TYPES.VALIDATION_COMPLETED,
    EVENT_TYPES.SCIENTIFIC_CONFIRMATION_FROZEN,
]);

function hasOwnEntry(record, key) {
    return Object.hasOwn(record, key);
}

function ownEntry(record, key) {
    return hasOwnEntry(record, key) ? record[key] : null;
}

function objectIdMatchesTaggedHash(objectId, taggedHash) {
    return typeof objectId === "string"
        && /^sha256:[a-f0-9]{64}$/u.test(objectId)
        && isAlgorithmTaggedSha256(taggedHash)
        && objectId.slice("sha256:".length) === taggedHash.split(":").at(-1);
}

function assertOpeningDomainVersion(event) {
    if (event?.type !== EVENT_TYPES.INVESTIGATION_OPENED) {
        return;
    }
    const eventDomainVersion = event.payload?.domainVersion ?? null;
    const contractDomainVersion = event.payload?.contract?.domainVersion ?? null;
    if (eventDomainVersion !== DOMAIN_VERSION
        || contractDomainVersion !== DOMAIN_VERSION) {
        throw new DomainVersionRestartRequiredError(
            "Investigation event history uses an incompatible domain version; start a new investigation",
            {
                expectedDomainVersion: DOMAIN_VERSION,
                actualDomainVersion: eventDomainVersion,
                contractDomainVersion,
            },
        );
    }
}

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

function assertCanonicalExternalPayload(aggregate, event, options = {}) {
    if (!EXTERNAL_EVENT_TYPES.includes(event.type)
        && event.type !== EVENT_TYPES.COMMAND_OBSERVED) {
        return;
    }
    const normalized = normalizeExternalEventPayload(
        event.type,
        event.payload,
        aggregate,
        options,
    );
    if (!canonicalEqual(normalized, event.payload)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVENT,
            `${event.type} payload is not in canonical kernel form`,
            { type: event.type },
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
    assertOpeningDomainVersion(event);
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
    if (event.payload.experimentAuthority === undefined
        || event.payload.experimentAuthority === null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            "Opened v4 investigations require persisted Ed25519 experiment authority",
        );
    }
    let authority;
    try {
        authority = assertExperimentAuthorityContractBinding(
            event.payload.experimentAuthority,
            normalizedContract,
        );
    } catch (error) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            `Opened event experiment authority is invalid: ${
                error?.message ?? String(error)
            }`,
        );
    }
    const authorityIdentity = event.payload.experimentAuthorityIdentity
        ?? null;
    if (authorityIdentity === null
        || authority.identity !== authorityIdentity) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            "Opened event experiment authority identity is invalid",
        );
    }
    next.experimentAuthority = authority;
    next.experimentAuthorityIdentity = authorityIdentity;
    if (event.payload.runtimeConfigAuthority === undefined
        || event.payload.runtimeConfigAuthority === null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            "Opened v4 investigations require immutable runtime config authority",
        );
    }
    let runtimeAuthority;
    try {
        runtimeAuthority = normalizeRuntimeConfigAuthority(
            event.payload.runtimeConfigAuthority,
        );
        if (runtimeAuthority.securityConfig?.runner?.investigationId
            !== authority.manifest.investigationId) {
            throw new Error(
                "runtime config authority belongs to a different investigation",
            );
        }
        if (runtimeAuthority.runtimeIdentity.root
                !== normalizedContract.runtimeIdentityRoot
            || runtimeAuthority.runtimeIdentity.policyIdentity
                !== normalizedContract.runtimeIdentityPolicyIdentity) {
            throw new Error(
                "runtime config authority is not bound to the signed contract runtime identity",
            );
        }
    } catch (error) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            `Opened event runtime config authority is invalid: ${
                error?.message ?? String(error)
            }`,
        );
    }
    if (event.payload.runtimeConfigFingerprint
        !== runtimeAuthority.fingerprint) {
        throw new TransitionError(
            ERROR_CODES.INVALID_CONTRACT,
            "Opened event runtime config fingerprint is invalid",
        );
    }
    next.runtimeConfigAuthority = runtimeAuthority;
    next.runtimeConfigFingerprint = runtimeAuthority.fingerprint;
    next.status = "active";
}

function applyCapabilityEpoch(next, event) {
    const epochId = normalizeEventIdentifier(event.payload?.epochId, "epochId");
    const { capabilities } = event.payload;
    if (hasOwnEntry(next.capabilityEpochs, epochId)) {
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
    const commandId = normalizeEventIdentifier(event.payload?.commandId, "commandId");
    const { command } = event.payload;
    if (hasOwnEntry(next.commands, commandId)) {
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
    const command = ownEntry(next.commands, commandId);
    if (command === null) {
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
    if (capabilityEpochId !== null && !hasOwnEntry(next.capabilityEpochs, capabilityEpochId)) {
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
    const command = ownEntry(next.commands, payload.commandId);
    if (command === null || command.status !== "dispatched") {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Only a dispatched command can be observed",
            { commandId: payload.commandId },
        );
    }
    if (hasOwnEntry(next.observations, payload.observationId)) {
        duplicate("observation", payload.observationId);
    }
    const expectedHarnessId = command.command.harnessId ?? next.contract.harnessId;
    const expectedParserVersion =
        command.command.parserVersion ?? next.contract.parserVersion;
    if (payload.sourceKind === "harness"
        && (payload.harnessId !== expectedHarnessId
            || payload.parserVersion !== expectedParserVersion)) {
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
    if (command.command.kind === "run_confirmation"
        && (payload.sourceKind !== "harness"
            || payload.purpose !== "confirmation")) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Confirmation commands require authoritative held-out confirmation observations",
        );
    }
    if (command.command.kind === "run_challenge"
        && (payload.sourceKind !== "harness"
            || payload.purpose !== "challenge")) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Challenge commands require authoritative adversarial challenge observations",
        );
    }
    if (command.command.kind === "verify_impossibility"
        && (payload.sourceKind !== "harness" || payload.purpose !== "impossibility")) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Impossibility-verification commands require authoritative harness impossibility observations",
        );
    }
    if (payload.purpose === "impossibility") {
        const measurement = payload.receipt.provenance.measurements[0];
        const certificateArtifact =
            payload.receipt.provenance.impossibilityCertificateArtifact;
        const execution = payload.verifierExecution;
        const facts = execution?.facts;
        if (command.command.kind !== "verify_impossibility"
            || next.contract.hypothesisTopology !== "certified_impossibility") {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Impossibility observations require a reserved certified-impossibility verifier command",
            );
        }
        if (payload.data.certificateVersion !== command.command.certificateVersion
            || payload.data.verificationRequestHash !== command.command.requestHash
            || payload.data.proposedCertificateArtifactHash
                !== command.command.proposedCertificateArtifactHash
            || payload.data.checkerResult.proofArtifactHash
                !== command.command.proofArtifactHash
            || payload.data.checkerResult.proofArtifactHash
                === command.command.proposedCertificateArtifactHash
            || execution?.commandId !== payload.commandId
            || execution?.observationId !== payload.observationId
            || execution?.request?.requestHash !== command.command.requestHash
            || execution?.proof?.artifactHash
                !== command.command.proofArtifactHash
            || execution?.measurement?.receiptHash
                !== measurement.receiptHash
            || execution?.measurement?.rawStdoutArtifact?.artifactId
                !== measurement.rawStdoutArtifact.artifactId
            || execution?.measurement?.rawStderrArtifact?.artifactId
                !== measurement.rawStderrArtifact.artifactId
            || facts?.status !== payload.data.checkerStatus
            || facts?.verdict !== payload.data.certificateVerdict
            || facts?.requestHash !== command.command.requestHash
            || facts?.proofArtifactHash
                !== command.command.proofArtifactHash
            || facts?.complete !== payload.data.checkerResult.complete
            || facts?.disagreementCount
                !== payload.data.checkerResult.disagreementCount
            || payload.receipt.certificateArtifactHash
                !== payload.data.certificateArtifactHash
            || payload.receipt.measurementReceiptHash
                !== payload.data.measurementReceiptHash
            || payload.receipt.verificationRequestHash
                !== payload.data.verificationRequestHash
            || payload.receipt.verificationSnapshotHash
                !== payload.data.verificationSnapshotHash
            || payload.data.checkerResult.parserVersion
                !== command.command.parserVersion
            || payload.data.checkerResult.status
                !== payload.data.checkerStatus
            || measurement.receiptHash !== payload.data.measurementReceiptHash
            || measurement.snapshot.snapshotHash
                !== payload.data.verificationSnapshotHash
            || !objectIdMatchesTaggedHash(
                measurement.receiptArtifact.objectId,
                payload.receipt.measurementReceiptArtifactHash,
            )
            || !objectIdMatchesTaggedHash(
                measurement.rawStdoutArtifact.objectId,
                payload.receipt.rawStdoutArtifactHash,
            )
            || !objectIdMatchesTaggedHash(
                measurement.rawStderrArtifact.objectId,
                payload.receipt.rawStderrArtifactHash,
            )
            || measurement.sandboxPolicy.kind !== "sandbox"
            || certificateArtifact === null
            || !objectIdMatchesTaggedHash(
                certificateArtifact.objectId,
                payload.data.certificateArtifactHash,
            )) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Impossibility observation receipt and verifier facts do not match the reserved command",
            );
        }
    }
    if (payload.sourceKind === "harness"
        && (payload.purpose === "candidate"
            || payload.purpose === "confirmation"
            || payload.purpose === "challenge")
        && (!Object.hasOwn(command.command, "hypotheses")
            || !canonicalEqual(
                payload.annotations?.hypotheses ?? null,
                command.command.hypotheses,
            ))) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Replicated observation hypotheses do not match the kernel-frozen command",
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
    if (payload.purpose === "confirmation"
        || payload.purpose === "challenge") {
        const freeze = next.confirmation.freeze?.payload ?? null;
        const member = freeze?.members?.find((item) =>
            item.evidenceId === command.command.candidateEvidenceId) ?? null;
        const protocol = member?.roles?.[payload.purpose] ?? null;
        const candidateEvidence = member === null
            ? null
            : ownEntry(next.evidence, member.evidenceId);
        if (freeze === null
            || member === null
            || protocol === null
            || candidateEvidence === null
            || candidateEvidence.invalidated
            || command.command.confirmationFreezeHash !== freeze.freezeHash
            || command.command.candidateId !== member.candidateId
            || command.command.candidateEvidenceHash !== member.evidenceHash
            || command.command.candidateArtifactHash
                !== member.candidateArtifactHash
            || command.command.roleManifestHash
                !== protocol.roleManifest.roleManifestHash
            || command.command.protocolManifestHash
                !== protocol.protocolManifestHash
            || !canonicalEqual(command.command.protocolManifest, protocol)
            || !canonicalEqual(
                command.command.replicationSchedule,
                protocol.replicationSchedule,
            )
            || !canonicalEqual(
                command.command.hypotheses,
                protocol.hypotheses,
            )
            || payload.candidateId !== member.candidateId
            || payload.receipt?.candidateArtifactHash
                !== member.candidateArtifactHash) {
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                "Scientific confirmation observation does not match the frozen cohort and role protocol",
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
        const enumerandManifest = next.contract.enumerandManifest === undefined
            ? null
            : normalizeEnumerandManifest(next.contract.enumerandManifest, {
                topology: next.contract.enumerandManifest.topology,
                observableRegistry: next.contract.observableRegistry,
                hypothesisPolicy: next.contract.hypothesisPolicy,
            });
        if (enumerandManifest !== null) {
            let binding;
            try {
                binding = assertEnumerandBinding(
                    enumerandManifest,
                    command.command.enumerand,
                    {
                        topology: next.contract.enumerandManifest.topology,
                        observableRegistry: next.contract.observableRegistry,
                        hypothesisPolicy: next.contract.hypothesisPolicy,
                    },
                );
            } catch (error) {
                throw new TransitionError(
                    ERROR_CODES.INVALID_EVIDENCE,
                    "Harness candidate command is outside the frozen enumerand manifest",
                    { cause: error?.message ?? String(error) },
                );
            }
            const globalSlot = (payload.round - 1) * next.contract.candidatesPerRound
                + payload.slotIndex;
            if (binding.ordinal !== globalSlot
                || binding.id !== payload.candidateId) {
                throw new TransitionError(
                    ERROR_CODES.INVALID_EVIDENCE,
                    "Harness candidate observation does not match its enumerand ordinal",
                    {
                        expectedOrdinal: globalSlot,
                        actualOrdinal: binding.ordinal,
                        expectedId: binding.id,
                        actualId: payload.candidateId,
                    },
                );
            }
            if (!canonicalEqual(
                command.command.hypotheses,
                binding.hypotheses ?? null,
            )) {
                throw new TransitionError(
                    ERROR_CODES.INVALID_EVIDENCE,
                    "Harness candidate command hypotheses do not match the frozen enumerand",
                );
            }
            if (binding.topology === "finite_enumerable"
                && payload.receipt.candidateArtifactHash
                    !== enumerandArtifactMeasurementHash(
                        binding.artifactSnapshotHash,
                    )) {
                throw new TransitionError(
                    ERROR_CODES.INVALID_EVIDENCE,
                    "Finite enumerand observation did not measure its staged artifact snapshot",
                    {
                        ordinal: binding.ordinal,
                        enumerandHash: binding.enumerandHash,
                    },
                );
            }
        } else {
            if (command.command.hypotheses !== null) {
                throw new TransitionError(
                    ERROR_CODES.INVALID_EVIDENCE,
                    "Open-generative candidate commands cannot introduce model-authored hypotheses",
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
    }
    const observation = {
        ...payload,
        observedSeq: event.seq,
        evidenceId: null,
    };
    observation.rawAuthorityDigest = deriveRawObservationAuthorityDigest(
        next,
        observation,
        command.command,
    );
    next.observations[payload.observationId] = observation;
    next.observationOrder.push(payload.observationId);
    command.status = "observed";
    command.observationId = payload.observationId;
}

function applyEvidenceCommitted(next, event) {
    const payload = event.payload;
    const evidenceId = normalizeEventIdentifier(payload?.evidenceId, "evidenceId");
    const observationId = normalizeEventIdentifier(
        payload?.observationId,
        "observationId",
    );
    if (hasOwnEntry(next.evidence, evidenceId)) {
        duplicate("evidence", evidenceId);
    }
    const observation = ownEntry(next.observations, observationId);
    if (observation === null || observation.evidenceId !== null) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Evidence must reference one uncommitted observation",
        );
    }
    if (observation.sourceKind === "harness" && observation.purpose === "candidate") {
        const duplicateCandidate = next.evidenceOrder.some((existingId) => {
            const existing = ownEntry(next.evidence, existingId);
            return existing !== null
                && existing.sourceKind === "harness"
                && existing.purpose === "candidate"
                && !existing.invalidated
                && existing.candidateId === observation.candidateId;
        });
        if (duplicateCandidate) {
            duplicate("candidate", observation.candidateId);
        }
        const duplicateSlot = next.evidenceOrder.some((existingId) => {
            const existing = ownEntry(next.evidence, existingId);
            return existing !== null
                && existing.sourceKind === "harness"
                && existing.purpose === "candidate"
                && !existing.invalidated
                && existing.round === observation.round
                && existing.slotIndex === observation.slotIndex;
        });
        if (duplicateSlot) {
            duplicate("candidate slot", `${observation.round}:${observation.slotIndex}`);
        }
    }
    const expected = deriveEvidencePayload(next, observation, evidenceId);
    if (!canonicalEqual(payload, expected)) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Committed evidence fields are not kernel-derived from the observation",
        );
    }

    next.evidence[evidenceId] = {
        ...expected,
        committedSeq: event.seq,
        commitEventHash: event.eventHash,
        invalidated: false,
        invalidatedSeq: null,
        invalidationReason: null,
    };
    next.evidenceOrder.push(evidenceId);
    observation.evidenceId = evidenceId;
    if (payload.sourceKind === "harness" && payload.purpose === "validation") {
        next.validation.attemptEvidenceIds.push(evidenceId);
    }
}

function applyValidationCompleted(next, event) {
    const evidenceId = normalizeEventIdentifier(event.payload?.evidenceId, "evidenceId");
    const evidence = ownEntry(next.evidence, evidenceId);
    const replayState = next.scientificReplay?.calibrationState?.find(
        (item) => item.evidenceId === evidenceId,
    ) ?? null;
    if (evidence === null
        || evidence.invalidated
        || replayState?.validationSatisfied !== true
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

function applyScientificConfirmationFrozen(next, event) {
    if (next.confirmation.freeze !== null) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Scientific confirmation may be frozen only once",
        );
    }
    next.confirmation.freeze = {
        payload: event.payload,
        seq: event.seq,
        eventHash: event.eventHash,
    };
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

function applyStorageBudgetExhausted(next, event) {
    if (next.storageBudgetExhaustion !== null
        && next.storageBudgetExhaustion !== undefined) {
        throw new TransitionError(
            ERROR_CODES.ILLEGAL_TRANSITION,
            "Storage-budget exhaustion is already recorded",
        );
    }
    next.storageBudgetExhaustion = {
        ...event.payload,
        seq: event.seq,
    };
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
        case EVENT_TYPES.VALIDATION_COMPLETED:
            applyValidationCompleted(next, event);
            break;
        case EVENT_TYPES.SCIENTIFIC_CONFIRMATION_FROZEN:
            applyScientificConfirmationFrozen(next, event);
            break;
        case EVENT_TYPES.STORAGE_BUDGET_EXHAUSTED:
            applyStorageBudgetExhausted(next, event);
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

export function reduceEvent(aggregate, event, options = {}) {
    const verifierExecutionCapability =
        options.verifierExecutionCapability
        ?? verifierExecutionCapabilityForEvent(event);
    const reductionOptions = {
        ...options,
        verifierExecutionCapability,
    };
    if (aggregate?.domainVersion !== DOMAIN_VERSION) {
        throw new DomainVersionRestartRequiredError(
            "Aggregate domain version is incompatible; start a new investigation",
            {
                expectedDomainVersion: DOMAIN_VERSION,
                actualDomainVersion: aggregate?.domainVersion ?? null,
            },
        );
    }
    assertOpeningDomainVersion(event);
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
    assertCanonicalExternalPayload(aggregate, event, reductionOptions);

    if (KERNEL_DECISION_EVENT_TYPES.includes(event.type)
        && !decisionEventMatches(aggregate, event)) {
        throw new TransitionError(
            ERROR_CODES.UNAUTHORIZED_DECISION,
            "Decision event is not the deterministic decision for the current aggregate",
            { type: event.type },
        );
    }

    const next = cloneAggregateForMutation(aggregate);
    applyTransition(next, event);
    if (event.type === EVENT_TYPES.COMMAND_OBSERVED
        && event.payload?.purpose === "impossibility") {
        bindAggregateImpossibilityExecution(
            next,
            event.payload.observationId,
            verifierExecutionCapability,
        );
    }
    next.lastSeq = event.seq;
    next.lastEventHash = event.eventHash;
    if (SCIENTIFIC_REPLAY_EVENT_TYPES.has(event.type)) {
        next.scientificReplay = deriveScientificReplayState(next);
    }
    return immutableAggregate(next);
}

export function replayEvents(events, options = {}) {
    let aggregate = createInitialAggregate();
    for (const event of events) {
        const verifierExecutionCapability =
            typeof options.verifierExecutionResolver === "function"
                ? options.verifierExecutionResolver({ aggregate, event })
                : null;
        aggregate = reduceEvent(aggregate, event, {
            verifierExecutionCapability,
        });
    }
    return aggregate;
}

export function verifyEventChain(events) {
    let lastSeq = 0;
    let lastEventHash = null;
    for (const event of events) {
        assertOpeningDomainVersion(event);
        assertEventEnvelope({ lastSeq, lastEventHash }, event);
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
