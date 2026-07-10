import { describe, expect, it } from "vitest";
import {
    DEFAULT_SEARCH_POLICY,
    DOMAIN_VERSION,
    DomainVersionRestartRequiredError,
    ERROR_CODES,
    ESCAPE_SEARCH_OPERATORS,
    EVENT_TYPES,
    IMPOSSIBILITY_CERTIFICATE_VERSION,
    NON_RESULT_CODES,
    canonicalJson,
    computeEventHash,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructInvestigationResumedEvent,
    constructKernelDecisionEvent,
    constructModelObservedEvent,
    createExternalEvent,
    createInitialAggregate,
    createEvidenceProvenance,
    createInvestigationContract,
    createInvestigationOpenedEvent,
    createMeasurementProvenance,
    createSnapshotProvenance,
    decideNext,
    detectPlateau,
    hashCanonical,
    normalizeEventIdentifier,
    reduceEvent,
    replayEvents,
    searchProgress,
    verifyEventChain,
} from "../domain/index.mjs";
import { fakeHarnessIdentity } from "./harness-identity-fixture.mjs";

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

function searchPolicy(overrides = {}) {
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

function contractInput(overrides = {}) {
    return {
        objective: "Find a candidate accepted by the terminal harness",
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
        workerModels: ["model-alpha", "model-beta"],
        candidatesPerRound: 1,
        maxRounds: 4,
        metrics: [],
        searchPolicy: searchPolicy(),
        declaredLimits: { maxCommands: 100 },
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
        ? fakeArtifact(
            `${observationId}-certificate`,
            certificateArtifactHash,
        )
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
        runnerEpochId: "runner-epoch-1",
        rawStdoutHash,
        rawStderrHash,
        candidateArtifactHash: normalizedCandidateHash,
        provenance,
    };
}

function append(context, event) {
    context.history.push(event);
    context.aggregate = reduceEvent(context.aggregate, event);
    return event;
}

function forgeEvent(event, payload) {
    const forged = JSON.parse(JSON.stringify(event));
    forged.payload = payload;
    forged.eventHash = computeEventHash(forged);
    return forged;
}

function openInvestigation(overrides = {}) {
    const contract = createInvestigationContract(contractInput(overrides));
    const context = {
        contract,
        history: [],
        aggregate: createInitialAggregate(),
    };
    append(context, createInvestigationOpenedEvent(contract));
    return context;
}

function reserveAndDispatch(context) {
    const reserve = constructKernelDecisionEvent(context.aggregate);
    expect(reserve.type).toBe(EVENT_TYPES.COMMAND_RESERVED);
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
} = {}) {
    const command = context.aggregate.commands[commandId].command;
    const receipt = fullHarnessReceipt(context, command, {
        purpose,
        observationId,
        candidateArtifactHash: purpose === "candidate"
            ? candidateArtifactHash ?? hashCanonical({ observationId, artifact: true })
            : null,
    });
    const observed = constructHarnessObservedEvent(context.aggregate, {
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
    });
    append(context, observed);
    append(context, constructEvidenceCommittedEvent(context.aggregate, {
        evidenceId,
        observationId,
    }));
    return context.aggregate.evidence[evidenceId];
}

function validateInvestigation(context) {
    const reserved = reserveAndDispatch(context);
    expect(reserved.command.kind).toBe("run_validation");
    observeAndCommit(context, reserved.commandId, {
        purpose: "validation",
        observationId: "validation-observation",
        evidenceId: "validation-evidence",
        data: validationData(),
    });
    append(context, constructKernelDecisionEvent(context.aggregate));
    expect(context.aggregate.validation.currentEvidenceId).toBe("validation-evidence");
    return context;
}

function commitCandidate(context, {
    data = { pass: false },
    annotations,
    candidateArtifactHash,
    label = String(context.aggregate.evidenceOrder.length),
} = {}) {
    const reserved = reserveAndDispatch(context);
    expect(reserved.command.kind).toBe("search_candidate");
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
    certificateVerdict,
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
    const derivedVerdict = pass && searchSpaceExhausted
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
            certificateVerdict: certificateVerdict ?? derivedVerdict,
            certificateArtifactHash,
            measurementReceiptHash,
            verificationRequestHash: requestHash,
            verificationSnapshotHash,
            verifiedFacts,
        },
    };
}

function commitImpossibility(context, reserved, label, facts = {}) {
    const input = impossibilityObservationInput(context, {
        ...reserved.command,
        commandId: reserved.commandId,
    }, label, facts);
    const observed = constructHarnessObservedEvent(context.aggregate, input);
    append(context, observed);
    const evidenceId = `impossibility-evidence-${label}`;
    append(context, constructEvidenceCommittedEvent(context.aggregate, {
        evidenceId,
        observationId: input.observationId,
    }));
    return context.aggregate.evidence[evidenceId];
}

describe("Crucible domain version 3 kernel", () => {
    it("stamps investigation_opened with DOMAIN_VERSION=3 and replays deterministically", () => {
        const context = validateInvestigation(openInvestigation());
        const opened = context.history[0];
        expect(DOMAIN_VERSION).toBe(3);
        expect(opened.payload.domainVersion).toBe(3);

        const replayed = replayEvents(context.history);
        expect(canonicalJson(replayed)).toBe(canonicalJson(context.aggregate));
        expect(verifyEventChain(context.history)).toEqual({
            valid: true,
            eventCount: context.history.length,
            lastSeq: context.aggregate.lastSeq,
            lastEventHash: context.aggregate.lastEventHash,
        });
    });

    it("fails old event histories with a typed restart-required error", () => {
        const opened = JSON.parse(JSON.stringify(
            createInvestigationOpenedEvent(createInvestigationContract(contractInput())),
        ));
        opened.payload.domainVersion = 2;
        opened.eventHash = computeEventHash(opened);

        for (const operation of [
            () => replayEvents([opened]),
            () => verifyEventChain([opened]),
        ]) {
            expect(operation).toThrow(DomainVersionRestartRequiredError);
            expect(operation).toThrow(expect.objectContaining({
                code: ERROR_CODES.DOMAIN_VERSION_RESTART_REQUIRED,
                details: expect.objectContaining({ restartRequired: true }),
            }));
        }
    });

    it("uses prototype-safe aggregate maps and rejects unsafe event identifiers", () => {
        const context = openInvestigation();
        const prototypeBefore = Object.getPrototypeOf({});
        const pollutionKey = "__crucible_phase1_polluted__";
        const pollutionBefore = Object.getOwnPropertyDescriptor(Object.prototype, pollutionKey);

        for (const field of ["capabilityEpochs", "commands", "observations", "evidence"]) {
            expect(Object.getPrototypeOf(context.aggregate[field])).toBeNull();
        }
        const replayed = replayEvents(context.history);
        for (const field of ["capabilityEpochs", "commands", "observations", "evidence"]) {
            expect(Object.getPrototypeOf(replayed[field])).toBeNull();
        }

        const unsafeIdentifiers = [
            "__proto__",
            "constructor",
            "prototype",
            "../escape",
            "..\\escape",
            "nested/path",
            "nested\\path",
            "trailing.",
        ];
        for (const identifier of unsafeIdentifiers) {
            expect(() => normalizeEventIdentifier(identifier, "testId")).toThrow(
                expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }),
            );
        }

        const epoch = createExternalEvent(
            context.aggregate,
            EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
            { epochId: "epoch-safe", capabilities: ["execute"] },
        );
        const invalidation = createExternalEvent(
            context.aggregate,
            EVENT_TYPES.EVIDENCE_INVALIDATED,
            { evidenceId: "evidence-safe", reason: "probe" },
        );
        for (const identifier of ["__proto__", "constructor", "prototype", "../escape"]) {
            expect(() => reduceEvent(
                context.aggregate,
                forgeEvent(epoch, { ...epoch.payload, epochId: identifier }),
            )).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
            expect(() => reduceEvent(
                context.aggregate,
                forgeEvent(invalidation, {
                    ...invalidation.payload,
                    evidenceId: identifier,
                }),
            )).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
        }

        expect(Object.getPrototypeOf({})).toBe(prototypeBefore);
        expect(Object.getOwnPropertyDescriptor(Object.prototype, pollutionKey)).toEqual(
            pollutionBefore,
        );
        expect(Object.hasOwn(Object.prototype, pollutionKey)).toBe(
            pollutionBefore !== undefined,
        );
    });

    it("canonical-compares every externally supplied payload before application", () => {
        const open = openInvestigation();
        const capability = createExternalEvent(
            open.aggregate,
            EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
            { epochId: "epoch-a", capabilities: ["a", "z"] },
        );
        const stop = createExternalEvent(open.aggregate, EVENT_TYPES.STOP_REQUESTED, {
            requestId: "stop-a",
            reason: "probe canonical defaults",
        });
        const invalidation = createExternalEvent(
            open.aggregate,
            EVENT_TYPES.EVIDENCE_INVALIDATED,
            { evidenceId: "evidence-a", reason: "probe canonical fields" },
        );

        expect(() => reduceEvent(
            open.aggregate,
            forgeEvent(capability, {
                epochId: "epoch-a",
                capabilities: ["z", "a", "a"],
            }),
        )).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
        expect(() => reduceEvent(
            open.aggregate,
            forgeEvent(stop, {
                requestId: "stop-a",
                reason: "probe canonical defaults",
            }),
        )).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
        expect(() => reduceEvent(
            open.aggregate,
            forgeEvent(invalidation, {
                ...invalidation.payload,
                unexpected: true,
            }),
        )).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));

        const reserved = constructKernelDecisionEvent(open.aggregate);
        append(open, reserved);
        const dispatch = createExternalEvent(open.aggregate, EVENT_TYPES.COMMAND_DISPATCHED, {
            commandId: reserved.payload.commandId,
        });
        expect(() => reduceEvent(
            open.aggregate,
            forgeEvent(dispatch, { commandId: reserved.payload.commandId }),
        )).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
    });

    it("rejects forged validation and candidate receipts during hashed replay", () => {
        const validation = openInvestigation();
        const validationCommand = reserveAndDispatch(validation);
        const validationObserved = constructHarnessObservedEvent(validation.aggregate, {
            commandId: validationCommand.commandId,
            observationId: "forged-validation-observation",
            purpose: "validation",
            receipt: fullHarnessReceipt(validation, validationCommand.command, {
                purpose: "validation",
                observationId: "forged-validation-observation",
            }),
            data: validationData(),
        });
        const validationReceipts = [
            null,
            { attemptId: "minimal-validation-attempt" },
            {
                ...validationObserved.payload.receipt,
                candidateArtifactHash: hashCanonical({ forged: "validation-artifact" }),
            },
        ];
        for (const receipt of validationReceipts) {
            expect(() => replayEvents([
                ...validation.history,
                forgeEvent(validationObserved, {
                    ...validationObserved.payload,
                    receipt,
                }),
            ])).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
        }

        const candidate = validateInvestigation(openInvestigation());
        const candidateCommand = reserveAndDispatch(candidate);
        const candidateObserved = constructHarnessObservedEvent(candidate.aggregate, {
            commandId: candidateCommand.commandId,
            observationId: "forged-candidate-observation",
            purpose: "candidate",
            receipt: fullHarnessReceipt(candidate, candidateCommand.command, {
                purpose: "candidate",
                observationId: "forged-candidate-observation",
                candidateArtifactHash: hashCanonical({ forged: "candidate-artifact" }),
            }),
            data: { pass: false },
        });
        const candidateReceipts = [
            null,
            { attemptId: "minimal-candidate-attempt" },
            {
                ...candidateObserved.payload.receipt,
                candidateArtifactHash: null,
            },
            {
                ...candidateObserved.payload.receipt,
                provenance: {
                    ...candidateObserved.payload.receipt.provenance,
                    closureRoot: hashCanonical({ forged: "provenance-root" }),
                },
            },
        ];
        for (const receipt of candidateReceipts) {
            expect(() => replayEvents([
                ...candidate.history,
                forgeEvent(candidateObserved, {
                    ...candidateObserved.payload,
                    receipt,
                }),
            ])).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
        }
    });

    it("requires an explicit canonical searchPolicy and validates strict bounds", () => {
        const missing = contractInput();
        delete missing.searchPolicy;
        expect(() => createInvestigationContract(missing)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }),
        );

        for (const invalidPolicy of [
            searchPolicy({ plateauWindow: 0 }),
            searchPolicy({ minRoundsBeforePlateau: 2, plateauWindow: 3 }),
            searchPolicy({ mandatoryEscapeRounds: 0 }),
            searchPolicy({ operatorWeights: { fresh: 0 } }),
            searchPolicy({
                operatorWeights: { diversification: 0, adversarial: 0, restart: 0 },
            }),
            searchPolicy({ promptCaps: { parentEvidenceIds: 3, promptContextRefs: 2 } }),
            { ...searchPolicy(), unexpected: true },
        ]) {
            expect(() => createInvestigationContract(contractInput({
                searchPolicy: invalidPolicy,
            }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
        }
    });

    it("commits accepted, near-miss, rejected, and invalid-metrics candidate evidence", () => {
        const context = validateInvestigation(openInvestigation({
            acceptancePredicate: {
                kind: "all",
                predicates: [
                    { kind: "harness_pass" },
                    { kind: "metric_compare", metric: "score", operator: ">=", value: 90 },
                ],
            },
            metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        }));
        const accepted = commitCandidate(context, {
            label: "accepted",
            data: { pass: true, metrics: { score: 95 } },
        }).evidence;
        const nearMiss = commitCandidate(context, {
            label: "near",
            data: { pass: true, metrics: { score: 85 } },
        }).evidence;
        const rejected = commitCandidate(context, {
            label: "rejected",
            data: { pass: false, metrics: { score: 10 } },
        }).evidence;
        const invalid = commitCandidate(context, {
            label: "invalid",
            data: { pass: true, metrics: {} },
        }).evidence;

        expect(accepted).toMatchObject({
            rankable: true,
            outcomeClass: "accepted",
            metrics: { score: 95 },
        });
        expect(nearMiss).toMatchObject({
            rankable: true,
            outcomeClass: "near_miss",
            metrics: { score: 85 },
        });
        expect(rejected).toMatchObject({
            rankable: true,
            outcomeClass: "rejected",
            metrics: { score: 10 },
        });
        expect(invalid).toMatchObject({
            rankable: false,
            outcomeClass: "invalid_metrics",
            metrics: {},
            acceptanceSatisfied: false,
        });
    });

    it("marks duplicate candidate artifacts instead of refusing the evidence", () => {
        const context = validateInvestigation(openInvestigation());
        const artifact = hashCanonical({ same: "candidate-artifact" });
        const first = commitCandidate(context, {
            label: "first",
            data: { pass: false, attempt: 1 },
            candidateArtifactHash: artifact,
        }).evidence;
        const duplicate = commitCandidate(context, {
            label: "duplicate",
            data: { pass: false, attempt: 2 },
            candidateArtifactHash: artifact,
        }).evidence;

        expect(first.duplicateOf).toBeNull();
        expect(duplicate.duplicateOf).toBe(first.evidenceId);
        expect(duplicate.candidateId).not.toBe(first.candidateId);
    });

    it("resumes deterministic per-candidate slots inside a partial round", () => {
        const context = validateInvestigation(openInvestigation({
            candidatesPerRound: 2,
            maxRounds: 2,
        }));
        const firstRecommendation = decideNext(context.aggregate);
        expect(firstRecommendation.command).toMatchObject({
            kind: "search_candidate",
            round: 1,
            slotIndex: 0,
            candidateId: "candidate-r000001-s000",
            model: "model-alpha",
            operator: "fresh",
            parentEvidenceIds: [],
            promptContextRefs: [],
        });
        expect(Number.isSafeInteger(firstRecommendation.command.seed)).toBe(true);

        const first = commitCandidate(context, { label: "slot-0" });
        expect(first.command).toEqual(firstRecommendation.command);
        expect(searchProgress(context.aggregate)).toMatchObject({
            nextRound: 1,
            nextSlot: 1,
            partialRound: true,
            slotsCompletedInRound: 1,
        });

        const replayed = replayEvents(context.history);
        expect(decideNext(replayed)).toEqual(decideNext(context.aggregate));
        const second = commitCandidate(context, { label: "slot-1" });
        expect(second.command).toMatchObject({
            round: 1,
            slotIndex: 1,
            candidateId: "candidate-r000001-s001",
            model: "model-beta",
        });
        expect(searchProgress(context.aggregate)).toMatchObject({
            nextRound: 2,
            nextSlot: 0,
            partialRound: false,
            completedRounds: 1,
        });
    });

    it("binds structured annotations and rejects citations outside promptContextRefs", () => {
        const context = validateInvestigation(openInvestigation());
        const first = commitCandidate(context, {
            label: "context",
            data: { pass: false, marker: "context" },
        });

        const next = decideNext(context.aggregate);
        expect(next.command.promptContextRefs).toContain(first.evidence.evidenceId);

        const valid = commitCandidate(context, {
            label: "annotated",
            data: { pass: false, marker: "annotated" },
            annotations: {
                mechanism: "cache-aware partitioning",
                hypothesis: "Partitioning reduces repeated work.",
                expectedEffects: ["lower repeated work", "stable output"],
                citedEvidenceIds: [first.evidence.evidenceId],
                finding: "The cache boundary is the useful lesson.",
            },
        }).evidence;
        expect(valid.annotations).toEqual({
            mechanism: "cache-aware partitioning",
            hypothesis: "Partitioning reduces repeated work.",
            expectedEffects: ["lower repeated work", "stable output"],
            citedEvidenceIds: [first.evidence.evidenceId],
            finding: "The cache boundary is the useful lesson.",
        });

        const reserved = reserveAndDispatch(context);
        const badObservation = constructHarnessObservedEvent(context.aggregate, {
            commandId: reserved.commandId,
            observationId: "bad-citation-observation",
            purpose: "candidate",
            annotations: {
                citedEvidenceIds: ["evidence-not-in-prompt"],
            },
            receipt: fullHarnessReceipt(context, reserved.command, {
                purpose: "candidate",
                observationId: "bad-citation-observation",
                candidateArtifactHash: hashCanonical({ bad: "artifact" }),
            }),
            data: { pass: false },
        });
        expect(() => reduceEvent(context.aggregate, badObservation)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.INVALID_EVIDENCE }),
        );
    });

    it("rejects model_review as completion authority for a search-candidate command", () => {
        const context = validateInvestigation(openInvestigation());
        const reserved = reserveAndDispatch(context);
        expect(reserved.command.kind).toBe("search_candidate");
        const modelObservation = constructModelObservedEvent(context.aggregate, {
            commandId: reserved.commandId,
            observationId: "model-only-observation",
            purpose: "candidate",
            annotations: {
                mechanism: "model-only proposal",
                citedEvidenceIds: [],
            },
            data: { pass: true, metrics: { score: 1000 } },
        });
        expect(() => reduceEvent(context.aggregate, modelObservation)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.INVALID_EVIDENCE }),
        );
        expect(context.aggregate.commands[reserved.commandId].status).toBe("dispatched");
    });

    it("keeps first passing candidates nonterminal by default", () => {
        const context = validateInvestigation(openInvestigation({ maxRounds: 2 }));
        commitCandidate(context, { label: "accepted", data: { pass: true } });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation.kind).toBe("COMMAND");
        expect(recommendation.command.kind).toBe("search_candidate");
        expect(recommendation.command.round).toBe(2);
    });

    it("supports explicit first-pass termination", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 3,
            searchPolicy: searchPolicy({ stopOnFirstAccept: true }),
        }));
        const accepted = commitCandidate(context, {
            label: "first-pass",
            data: { pass: true },
        }).evidence;

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
            candidateId: accepted.candidateId,
            basis: { kind: "first_passing_candidate" },
            event: {
                payload: {
                    evidenceClosure: {
                        version: 1,
                        validation: {
                            evidenceId: "validation-evidence",
                        },
                        decisive: {
                            kind: "winner",
                            evidence: {
                                evidenceId: accepted.evidenceId,
                                provenanceRoot: accepted.provenanceRoot,
                            },
                        },
                        receipts: { count: 3, evidenceCount: 2 },
                    },
                },
            },
        });
        expect(recommendation.event.payload.evidenceClosure.closureRoot).toMatch(
            /^sha256:crucible-terminal-evidence-closure-v1:[a-f0-9]{64}$/,
        );
        expect(recommendation.event.payload.evidenceClosure.frontier.digest).toMatch(
            /^sha256:crucible-terminal-frontier-v1:[a-f0-9]{64}$/,
        );
        expect(recommendation.event.payload.evidenceClosure.archive.digest).toMatch(
            /^sha256:crucible-terminal-archive-v1:[a-f0-9]{64}$/,
        );
    });

    it("retains the best incumbent until round exhaustion", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 3,
            metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        }));
        const first = commitCandidate(context, {
            label: "score-10",
            data: { pass: true, metrics: { score: 10 } },
        });
        const best = commitCandidate(context, {
            label: "score-20",
            data: { pass: true, metrics: { score: 20 } },
        });
        commitCandidate(context, {
            label: "score-15",
            data: { pass: true, metrics: { score: 15 } },
        });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            decision: "VERIFIED_RESULT",
            candidateId: best.evidence.candidateId,
            evidenceId: best.evidence.evidenceId,
            basis: { kind: "rounds_exhausted_with_incumbent" },
        });
        expect(recommendation.candidateId).not.toBe(first.evidence.candidateId);
    });

    it("requires a mandatory escape round before plateau termination", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 4,
            searchPolicy: searchPolicy({
                plateauWindow: 1,
                minRoundsBeforePlateau: 1,
                mandatoryEscapeRounds: 1,
            }),
        }));
        commitCandidate(context, {
            label: "plateau-1",
            data: { pass: true, marker: "same" },
        });
        commitCandidate(context, {
            label: "plateau-2",
            data: { pass: true, marker: "same" },
        });

        expect(detectPlateau(context.aggregate)).toMatchObject({
            plateauDetected: true,
            escapeComplete: false,
            phase: "mandatory_escape",
        });
        const escape = decideNext(context.aggregate);
        expect(ESCAPE_SEARCH_OPERATORS).toContain(escape.command.operator);
        commitCandidate(context, {
            label: "plateau-escape",
            data: { pass: true, marker: "same" },
        });

        expect(decideNext(context.aggregate)).toMatchObject({
            decision: "VERIFIED_RESULT",
            basis: { kind: "plateau_after_mandatory_escape" },
        });
    });

    it("treats metric-less mechanism/content novelty as plateau-breaking", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 4,
            searchPolicy: searchPolicy({
                plateauWindow: 1,
                minRoundsBeforePlateau: 1,
                mandatoryEscapeRounds: 1,
            }),
        }));
        commitCandidate(context, {
            label: "novelty-1",
            data: { pass: true, marker: "same" },
        });
        commitCandidate(context, {
            label: "novelty-2",
            data: { pass: true, marker: "same" },
        });
        commitCandidate(context, {
            label: "novelty-escape",
            data: { pass: true, marker: "same" },
            annotations: { mechanism: "new-mechanism" },
        });

        expect(detectPlateau(context.aggregate)).toMatchObject({
            plateauDetected: false,
            plateauComplete: false,
            phase: "normal",
        });
        expect(decideNext(context.aggregate).command.kind).toBe("search_candidate");
    });

    it("never declares an open-generative target unreachable", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "open_generative",
            maxRounds: 1,
        }));
        commitCandidate(context, { label: "open-reject", data: { pass: false } });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
        });
        expect(recommendation.event.type).toBe(EVENT_TYPES.NON_RESULT_RECORDED);
    });

    it("rejects the legacy direct-certificate injection path and reserves a kernel verifier", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        expect(context.contract.impossibilityPolicy).toEqual({
            trigger: "search_exhausted",
            requestVersion: "crucible-impossibility-request-v1",
            certificateVersion: IMPOSSIBILITY_CERTIFICATE_VERSION,
        });
        const search = reserveAndDispatch(context);
        expect(search.command.kind).toBe("search_candidate");
        const legacyObserved = constructHarnessObservedEvent(
            context.aggregate,
            impossibilityObservationInput(context, {
                ...search.command,
                commandId: search.commandId,
            }, "legacy"),
        );
        expect(() => reduceEvent(context.aggregate, legacyObserved)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.INVALID_EVIDENCE }),
        );

        observeAndCommit(context, search.commandId, {
            purpose: "candidate",
            observationId: "candidate-observation-certified-reject",
            evidenceId: "candidate-evidence-certified-reject",
            data: {
                pass: false,
                searchSpaceExhausted: true,
                impossibilityCertificateHash: hashCanonical({ modelClaim: true }),
            },
        });
        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "verify_impossibility",
                attemptOrdinal: 1,
                certificateVersion: IMPOSSIBILITY_CERTIFICATE_VERSION,
                request: {
                    trigger: {
                        kind: "search_exhausted",
                        roundsExhausted: true,
                        candidateCount: 1,
                    },
                },
            },
        });
        expect(context.aggregate.evidence["candidate-evidence-certified-reject"].unreachableBasis)
            .toBeNull();
    });

    it("emits TARGET_UNREACHABLE only from a positive verified certificate", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "certified-reject",
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        expect(verifier.command.kind).toBe("verify_impossibility");
        const evidence = commitImpossibility(context, verifier, "positive");
        expect(evidence.unreachableBasis).toMatchObject({
            kind: "verified_impossibility_certificate",
            topology: "certified_impossibility",
            certificateVerdict: "target_unreachable",
        });

        const terminal = constructKernelDecisionEvent(context.aggregate);
        expect(terminal).toMatchObject({
            type: EVENT_TYPES.TARGET_UNREACHABLE,
            payload: {
                decision: "TARGET_UNREACHABLE",
                basis: {
                    kind: "verified_impossibility_certificate",
                    certificateVerdict: "target_unreachable",
                },
                evidenceId: "impossibility-evidence-positive",
                evidenceClosure: {
                    validation: {
                        evidenceId: "validation-evidence",
                    },
                    decisive: {
                        kind: "impossibility_certificate",
                        evidence: {
                            evidenceId: evidence.evidenceId,
                            provenanceRoot: evidence.provenanceRoot,
                        },
                    },
                    receipts: { count: 4, evidenceCount: 3 },
                },
            },
        });
        expect(terminal.payload.evidenceClosure.closureRoot).toMatch(
            /^sha256:crucible-terminal-evidence-closure-v1:[a-f0-9]{64}$/,
        );
        append(context, terminal);
        expect(replayEvents(context.history)).toEqual(context.aggregate);
    });

    it("does not run an impossibility verifier after any candidate satisfies acceptance", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
            metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        }));
        const candidate = commitCandidate(context, {
            label: "accepted-with-invalid-metrics",
            data: { pass: true, metrics: {} },
        });
        expect(candidate.evidence.acceptanceSatisfied).toBe(true);
        expect(candidate.evidence.outcomeClass).toBe("invalid_metrics");
        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
        });
        expect(recommendation.command?.kind).not.toBe("verify_impossibility");
    });

    it.each([
        ["not_proven", { pass: false, searchSpaceExhausted: true }],
        ["invalid", { pass: true, searchSpaceExhausted: false }],
    ])("records a %s impossibility certificate as a non-result", (verdict, facts) => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: `certificate-${verdict}-candidate`,
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        const evidence = commitImpossibility(context, verifier, verdict, facts);
        expect(evidence.unreachableBasis).toBeNull();
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE,
            certificateVerdict: verdict,
            event: {
                type: EVENT_TYPES.NON_RESULT_RECORDED,
                payload: { certificateVerdict: verdict },
            },
        });
    });

    it("rejects forged or minimal impossibility receipts during hashed replay", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "forged-certificate-candidate",
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        const input = impossibilityObservationInput(context, {
            ...verifier.command,
            commandId: verifier.commandId,
        }, "forged");
        const observed = constructHarnessObservedEvent(context.aggregate, input);

        expect(() => replayEvents([
            ...context.history,
            forgeEvent(observed, {
                ...observed.payload,
                receipt: { attemptId: "minimal" },
            }),
        ])).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
        expect(() => replayEvents([
            ...context.history,
            forgeEvent(observed, {
                ...observed.payload,
                receipt: {
                    ...observed.payload.receipt,
                    certificateArtifactHash: hashCanonical({ forged: true }),
                },
            }),
        ])).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVIDENCE }));
    });

    it("retries an invalidated impossibility certificate deterministically", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "invalidate-certificate-candidate",
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        const evidence = commitImpossibility(context, verifier, "invalidate");
        append(context, createExternalEvent(context.aggregate, EVENT_TYPES.EVIDENCE_INVALIDATED, {
            evidenceId: evidence.evidenceId,
            reason: "certificate artifact failed later integrity review",
        }));

        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "verify_impossibility",
                attemptOrdinal: 2,
            },
        });
    });

    it("does not reuse a certificate after its candidate-evidence trigger is invalidated", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        const candidate = commitCandidate(context, {
            label: "invalidate-certificate-trigger",
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        commitImpossibility(context, verifier, "trigger-positive");
        append(context, createExternalEvent(context.aggregate, EVENT_TYPES.EVIDENCE_INVALIDATED, {
            evidenceId: candidate.evidence.evidenceId,
            reason: "candidate measurement was invalidated after certificate creation",
        }));

        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "search_candidate",
                round: 1,
                slotIndex: 0,
                replacementOrdinal: 1,
            },
        });
    });

    it("turns a stop request into a pause instead of an impossibility certificate", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "stop-before-certificate",
            data: { pass: false },
        });
        append(context, createExternalEvent(context.aggregate, EVENT_TYPES.STOP_REQUESTED, {
            requestId: "stop-certified",
            reason: "operator requested pause",
            pauseRequested: true,
        }));
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.INVESTIGATION_PAUSED,
            event: { type: EVENT_TYPES.INVESTIGATION_PAUSED },
        });
    });

    it("can prove a finite declared search space unreachable without a stop request", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "finite_enumerable",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
            boundedCandidateIds: ["bounded-a"],
        }));
        const candidate = commitCandidate(context, {
            label: "bounded",
            data: { pass: false },
        });

        expect(candidate.command).toMatchObject({
            candidateId: "bounded-a",
            boundedCandidateId: "bounded-a",
        });
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
            basis: { kind: "search_space_exhausted" },
        });
    });

    it("retries invalidated slots and excludes them from completion and bounded exhaustion", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "finite_enumerable",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
            boundedCandidateIds: ["bounded-a"],
        }));
        const first = commitCandidate(context, {
            label: "bounded-invalidated",
            data: { pass: true },
        });
        append(context, createExternalEvent(context.aggregate, EVENT_TYPES.EVIDENCE_INVALIDATED, {
            evidenceId: first.evidence.evidenceId,
            reason: "measurement receipt was superseded",
        }));

        expect(searchProgress(context.aggregate)).toMatchObject({
            nextRound: 1,
            nextSlot: 0,
            completedRounds: 0,
            roundsExhausted: false,
            boundedComplete: false,
            boundedAttempted: false,
        });
        const retry = decideNext(context.aggregate);
        expect(retry).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "search_candidate",
                round: 1,
                slotIndex: 0,
                candidateId: "bounded-a",
                boundedCandidateId: "bounded-a",
                replacementOrdinal: 1,
            },
        });
        expect(retry.decision).not.toBe("VERIFIED_RESULT");

        const replacement = commitCandidate(context, {
            label: "bounded-replacement",
            data: { pass: false },
        });
        expect(replacement.command.replacementOrdinal).toBe(1);
        expect(context.aggregate.evidence[first.evidence.evidenceId].invalidated).toBe(true);
        const terminal = decideNext(context.aggregate);
        expect(terminal).toMatchObject({
            decision: "TARGET_UNREACHABLE",
            basis: { kind: "search_space_exhausted" },
            event: {
                payload: {
                    evidenceClosure: {
                        decisive: { kind: "bounded_search", evidence: null },
                        receipts: { count: 4, evidenceCount: 3 },
                    },
                },
            },
        });
        expect(terminal.event.payload.evidenceClosure.receipts.root).toMatch(
            /^sha256:crucible-terminal-receipt-roots-v1:[a-f0-9]{64}$/,
        );
    });

    it("uses a deterministic replacement candidate id and removes invalidated rounds from plateau accounting", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 3,
            searchPolicy: searchPolicy({
                plateauWindow: 1,
                minRoundsBeforePlateau: 1,
                mandatoryEscapeRounds: 1,
            }),
        }));
        commitCandidate(context, {
            label: "plateau-active-1",
            data: { pass: true, marker: "same" },
        });
        const second = commitCandidate(context, {
            label: "plateau-active-2",
            data: { pass: true, marker: "same" },
        });
        expect(detectPlateau(context.aggregate).plateauDetected).toBe(true);

        append(context, createExternalEvent(context.aggregate, EVENT_TYPES.EVIDENCE_INVALIDATED, {
            evidenceId: second.evidence.evidenceId,
            reason: "invalidate the completed second round",
        }));
        expect(detectPlateau(context.aggregate)).toMatchObject({
            completedRounds: 1,
            plateauDetected: false,
            escapeRoundsCompleted: 0,
        });
        expect(searchProgress(context.aggregate)).toMatchObject({
            nextRound: 2,
            nextSlot: 0,
            completedRounds: 1,
            roundsExhausted: false,
        });
        const replacement = decideNext(context.aggregate);
        expect(replacement.command).toMatchObject({
            round: 2,
            slotIndex: 0,
            candidateId: "candidate-r000002-s000-retry-001",
            replacementOrdinal: 1,
        });
    });

    it("treats stop requests only as persisted pauses", () => {
        const context = validateInvestigation(openInvestigation());
        append(context, createExternalEvent(context.aggregate, EVENT_TYPES.STOP_REQUESTED, {
            requestId: "pause-now",
            reason: "operator requested a pause",
            pauseRequested: false,
        }));
        const recommendation = decideNext(context.aggregate);
        expect(recommendation.event.type).toBe(EVENT_TYPES.INVESTIGATION_PAUSED);
        append(context, constructKernelDecisionEvent(context.aggregate));
        expect(context.aggregate.status).toBe("paused");

        append(context, constructInvestigationResumedEvent(context.aggregate));
        expect(context.aggregate.status).toBe("active");
        expect(decideNext(context.aggregate).command.kind).toBe("search_candidate");
    });
});
