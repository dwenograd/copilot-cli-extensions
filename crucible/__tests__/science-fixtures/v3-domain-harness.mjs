import {
    DEFAULT_SEARCH_POLICY,
    EVENT_TYPES,
    IMPOSSIBILITY_CERTIFICATE_VERSION,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructInvestigationResumedEvent,
    constructKernelDecisionEvent,
    createEvidenceProvenance,
    createExternalEvent,
    createInitialAggregate,
    createInvestigationContract,
    createInvestigationOpenedEvent,
    createMeasurementProvenance,
    createSnapshotProvenance,
    hashCanonical,
    reduceEvent,
} from "../../domain/index.mjs";
import { fakeHarnessIdentity } from "../harness-identity-fixture.mjs";
import {
    createRuntimeConfigAuthorityFixture,
    createSignedInvestigationAuthority,
} from "../experiment-authority-fixture.mjs";

export function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

export function searchPolicy(overrides = {}) {
    return {
        ...DEFAULT_SEARCH_POLICY,
        ...overrides,
        operatorWeights: {
            ...DEFAULT_SEARCH_POLICY.operatorWeights,
            ...overrides.operatorWeights,
        },
        archiveCaps: {
            ...DEFAULT_SEARCH_POLICY.archiveCaps,
            ...overrides.archiveCaps,
        },
        promptCaps: {
            ...DEFAULT_SEARCH_POLICY.promptCaps,
            ...overrides.promptCaps,
        },
    };
}

export function contractInput(overrides = {}) {
    return {
        objective: "Characterize deterministic Crucible v3 science behavior",
        acceptancePredicate: { kind: "harness_pass" },
        validationCases: [
            { id: "known-good", expectation: "accept", artifactHash: artifactHash("a") },
            { id: "known-bad", expectation: "reject", artifactHash: artifactHash("b") },
        ],
        harnessId: "primary-harness",
        hypothesisTopology: "open_generative",
        criticality: "high",
        policyVersion: "policy-v2",
        parserVersion: "parser-v2",
        harnessIdentity: fakeHarnessIdentity({
            harnessId: "primary-harness",
            parserVersion: "parser-v2",
        }),
        workerModels: ["model-alpha"],
        candidatesPerRound: 1,
        maxRounds: 4,
        metrics: [],
        searchPolicy: searchPolicy(),
        declaredLimits: { maxCommands: 256 },
        ...overrides,
    };
}

function validationData() {
    return {
        caseResults: [
            { id: "known-good", artifactHash: artifactHash("a"), outcome: "accept" },
            { id: "known-bad", artifactHash: artifactHash("b"), outcome: "reject" },
        ],
    };
}

function digestOf(value) {
    return value.split(":").at(-1);
}

function snapshotHashFor(value) {
    return `sha256:crucible-measurement-snapshot-v1:${digestOf(value)}`;
}

function fakeArtifact(label, hash = hashCanonical({ label, artifact: true })) {
    const safeLabel = label.replace(/[^A-Za-z0-9._-]/gu, "-").slice(0, 48);
    return {
        artifactId: `artifact-${safeLabel}-${digestOf(hash).slice(0, 16)}`,
        objectId: `sha256:${digestOf(hash)}`,
    };
}

function fakeMeasurement({
    subjectId,
    snapshotId,
    observationId,
    parserVersion,
}) {
    const stdoutHash = hashCanonical(
        { observationId, subjectId, stream: "stdout" },
        "sha256:crucible-measurement-stream-v1",
    );
    const stderrHash = hashCanonical(
        { observationId, subjectId, stream: "stderr" },
        "sha256:crucible-measurement-stream-v1",
    );
    const receiptHash = hashCanonical(
        { observationId, subjectId, receipt: true },
        "sha256:crucible-measurement-receipt-v1",
    );
    const executableHash = hashCanonical(
        { harness: "executable" },
        "sha256:crucible-measurement-file-v1",
    );
    const dependencyHash = hashCanonical(
        { harness: "dependency" },
        "sha256:crucible-measurement-file-v1",
    );
    const snapshot = createSnapshotProvenance({
        snapshotHash: snapshotHashFor(snapshotId),
        manifestArtifact: fakeArtifact(`${subjectId}-manifest`, snapshotId),
        objectArtifacts: [
            fakeArtifact(`${subjectId}-object`, hashCanonical({ subjectId, object: true })),
        ],
    });
    const measurement = createMeasurementProvenance({
        subjectId,
        receiptArtifact: fakeArtifact(`${subjectId}-receipt`, receiptHash),
        receiptHash,
        rawStdoutArtifact: fakeArtifact(`${subjectId}-stdout`, stdoutHash),
        rawStdoutHash: stdoutHash,
        rawStderrArtifact: fakeArtifact(`${subjectId}-stderr`, stderrHash),
        rawStderrHash: stderrHash,
        parserVersion,
        allowlistFileHash: hashCanonical(
            { harness: "allowlist" },
            "sha256:crucible-measurement-file-v1",
        ),
        harnessEntryHash: hashCanonical(
            { harness: "entry" },
            "sha256:crucible-measurement-entry-v1",
        ),
        executableHash,
        stagedExecutableHash: executableHash,
        dependencyHashes: [{
            path: "C:\\fixture\\harness.mjs",
            role: "harness-script",
            sha256: dependencyHash,
        }],
        stagedDependencyHashes: [{
            path: "C:\\fixture\\stage\\harness.mjs",
            role: "harness-script",
            sha256: dependencyHash,
        }],
        argvHash: hashCanonical(
            { observationId, subjectId, argv: true },
            "sha256:crucible-measurement-argv-v1",
        ),
        envHash: hashCanonical(
            { observationId, subjectId, env: true },
            "sha256:crucible-measurement-env-v1",
        ),
        sandboxPolicy: {
            kind: "none",
            sandboxId: null,
            environmentHash: null,
        },
        snapshot,
        snapshotExecutionHash: hashCanonical(
            { observationId, subjectId, snapshotExecution: true },
            "sha256:crucible-evidence-snapshot-execution-v1",
        ),
    });
    return { measurement, receiptHash, stdoutHash, stderrHash };
}

function fullHarnessReceipt(context, command, {
    purpose,
    observationId,
    candidateArtifactHash = null,
    certificateArtifactHash = null,
}) {
    const parserVersion = context.contract.parserVersion;
    const measurements = purpose === "validation"
        ? context.contract.validationCases.map((validationCase) =>
            fakeMeasurement({
                subjectId: validationCase.id,
                snapshotId: validationCase.artifactHash,
                observationId,
                parserVersion,
            }))
        : [fakeMeasurement({
            subjectId: purpose === "candidate"
                ? command.candidateId
                : `impossibility-${command.attemptOrdinal ?? ""}`,
            snapshotId: purpose === "candidate"
                ? `sha256:${digestOf(candidateArtifactHash)}`
                : `sha256:${digestOf(command.requestHash)}`,
            observationId,
            parserVersion,
        })];
    const normalizedCandidateHash = purpose === "candidate"
        ? measurements[0].measurement.snapshot.snapshotHash
        : null;
    const certificateArtifact = purpose === "impossibility"
        ? fakeArtifact(`${observationId}-certificate`, certificateArtifactHash)
        : null;
    const provenance = createEvidenceProvenance({
        proposalArtifact: purpose === "candidate"
            ? fakeArtifact(`${observationId}-proposal`)
            : null,
        promptContextHash: purpose === "candidate"
            ? hashCanonical({ observationId, prompt: true })
            : null,
        validationCompositeArtifact: purpose === "validation"
            ? fakeArtifact(`${observationId}-validation-composite`)
            : null,
        impossibilityCertificateArtifact: certificateArtifact,
        measurements: measurements.map((item) => item.measurement),
    }, {
        purpose,
        command,
        contract: context.contract,
    });
    const rawStdoutHash = purpose === "validation"
        ? hashCanonical(
            provenance.measurements.map((item) => ({
                id: item.subjectId,
                hash: item.rawStdoutHash,
            })),
            "sha256:crucible-runtime-observation-streams-v1",
        )
        : measurements[0].stdoutHash;
    const rawStderrHash = purpose === "validation"
        ? hashCanonical(
            provenance.measurements.map((item) => ({
                id: item.subjectId,
                hash: item.rawStderrHash,
            })),
            "sha256:crucible-runtime-observation-streams-v1",
        )
        : measurements[0].stderrHash;
    return {
        version: 1,
        attemptId: `attempt-${observationId}`,
        runnerEpochId: "runner-epoch-science-fixture",
        rawStdoutHash,
        rawStderrHash,
        candidateArtifactHash: normalizedCandidateHash,
        provenance,
    };
}

export function append(context, event) {
    context.history.push(event);
    context.aggregate = reduceEvent(context.aggregate, event);
    return event;
}

export function openInvestigation(overrides = {}) {
    const contract = createInvestigationContract(contractInput(overrides));
    const signed = createSignedInvestigationAuthority({ contract });
    const context = {
        contract,
        investigationId: signed.investigationId,
        history: [],
        aggregate: createInitialAggregate(),
    };
    append(context, createInvestigationOpenedEvent(
        contract,
        signed.authority,
        createRuntimeConfigAuthorityFixture(signed.investigationId),
    ));
    return context;
}

export function reserveAndDispatch(context) {
    const reserve = constructKernelDecisionEvent(context.aggregate);
    if (reserve.type !== EVENT_TYPES.COMMAND_RESERVED) {
        throw new Error(`Expected command_reserved, received ${reserve.type}`);
    }
    append(context, reserve);
    append(context, createExternalEvent(
        context.aggregate,
        EVENT_TYPES.COMMAND_DISPATCHED,
        { commandId: reserve.payload.commandId },
    ));
    return reserve.payload;
}

function observeAndCommit(context, commandId, {
    purpose,
    observationId,
    evidenceId,
    data,
    annotations,
    candidateArtifactHash,
}) {
    const command = context.aggregate.commands[commandId].command;
    const receipt = fullHarnessReceipt(context, command, {
        purpose,
        observationId,
        candidateArtifactHash: purpose === "candidate"
            ? candidateArtifactHash ?? hashCanonical({ observationId, artifact: true })
            : null,
    });
    append(context, constructHarnessObservedEvent(context.aggregate, {
        commandId,
        observationId,
        purpose,
        ...(purpose === "candidate"
            ? {
                round: command.round,
                slotIndex: command.slotIndex,
                candidateId: command.candidateId,
                annotations,
            }
            : {}),
        receipt,
        data,
    }));
    append(context, constructEvidenceCommittedEvent(context.aggregate, {
        evidenceId,
        observationId,
    }));
    return context.aggregate.evidence[evidenceId];
}

export function validateInvestigation(context) {
    const reserved = reserveAndDispatch(context);
    if (reserved.command.kind !== "run_validation") {
        throw new Error(`Expected run_validation, received ${reserved.command.kind}`);
    }
    observeAndCommit(context, reserved.commandId, {
        purpose: "validation",
        observationId: "validation-observation",
        evidenceId: "validation-evidence",
        data: validationData(),
    });
    append(context, constructKernelDecisionEvent(context.aggregate));
    return context;
}

export function commitCandidate(context, {
    data = { pass: false },
    annotations,
    candidateArtifactHash,
    label = String(context.aggregate.evidenceOrder.length),
} = {}) {
    const reserved = reserveAndDispatch(context);
    if (reserved.command.kind !== "search_candidate") {
        throw new Error(`Expected search_candidate, received ${reserved.command.kind}`);
    }
    const evidence = observeAndCommit(context, reserved.commandId, {
        purpose: "candidate",
        observationId: `candidate-observation-${label}`,
        evidenceId: `candidate-evidence-${label}`,
        data,
        annotations,
        candidateArtifactHash,
    });
    return { command: reserved.command, evidence };
}

function impossibilityObservationInput(context, command, label, {
    pass = true,
    searchSpaceExhausted = true,
} = {}) {
    const requestHash = command.requestHash ?? hashCanonical({ label, request: "legacy" });
    const certificateArtifactHash = hashCanonical({ label, artifact: "certificate" });
    const observationId = `impossibility-observation-${label}`;
    const effectiveCommand = { ...command, requestHash };
    const receipt = fullHarnessReceipt(context, effectiveCommand, {
        purpose: "impossibility",
        observationId,
        certificateArtifactHash,
    });
    const measurement = receipt.provenance.measurements[0];
    const measurementReceiptHash = measurement.receiptHash;
    const verificationSnapshotHash = measurement.snapshot.snapshotHash;
    const verifiedFacts = {
        pass,
        searchSpaceExhausted,
        parserVersion: command.parserVersion ?? "parser-v2",
    };
    const certificateVerdict = pass && searchSpaceExhausted
        ? "target_unreachable"
        : pass
            ? "invalid"
            : "not_proven";
    return {
        commandId: command.commandId,
        observationId,
        purpose: "impossibility",
        receipt: {
            ...receipt,
            certificateArtifactHash,
            measurementReceiptArtifactHash:
                `sha256:crucible-impossibility-receipt-artifact-v1:${digestOf(measurement.receiptArtifact.objectId)}`,
            measurementReceiptHash,
            rawStderrArtifactHash:
                `sha256:crucible-impossibility-stderr-artifact-v1:${digestOf(measurement.rawStderrArtifact.objectId)}`,
            rawStdoutArtifactHash:
                `sha256:crucible-impossibility-stdout-artifact-v1:${digestOf(measurement.rawStdoutArtifact.objectId)}`,
            verificationRequestHash: requestHash,
            verificationSnapshotHash,
        },
        data: {
            certificateVersion:
                command.certificateVersion ?? IMPOSSIBILITY_CERTIFICATE_VERSION,
            certificateVerdict,
            certificateArtifactHash,
            measurementReceiptHash,
            verificationRequestHash: requestHash,
            verificationSnapshotHash,
            verifiedFacts,
        },
    };
}

export function commitImpossibility(context, reserved, label, facts = {}) {
    const input = impossibilityObservationInput(context, {
        ...reserved.command,
        commandId: reserved.commandId,
    }, label, facts);
    append(context, constructHarnessObservedEvent(context.aggregate, input));
    const evidenceId = `impossibility-evidence-${label}`;
    append(context, constructEvidenceCommittedEvent(context.aggregate, {
        evidenceId,
        observationId: input.observationId,
    }));
    return context.aggregate.evidence[evidenceId];
}

export function invalidateEvidence(context, evidenceId, reason) {
    return append(context, createExternalEvent(
        context.aggregate,
        EVENT_TYPES.EVIDENCE_INVALIDATED,
        { evidenceId, reason },
    ));
}

export function pauseAndResume(context) {
    append(context, createExternalEvent(
        context.aggregate,
        EVENT_TYPES.STOP_REQUESTED,
        {
            requestId: "science-fixture-pause",
            reason: "deterministic recovery metadata fixture",
            pauseRequested: true,
        },
    ));
    const paused = append(context, constructKernelDecisionEvent(context.aggregate));
    const resumed = append(context, constructInvestigationResumedEvent(context.aggregate));
    return { paused, resumed };
}
