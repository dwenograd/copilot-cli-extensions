import { describe, expect, it } from "vitest";
import {
    CONTRACT_LIMITS,
    DEFAULT_SEARCH_POLICY,
    DOMAIN_VERSION,
    DomainVersionRestartRequiredError,
    ERROR_CODES,
    ESCAPE_SEARCH_OPERATORS,
    EVENT_TYPES,
    IMPOSSIBILITY_CERTIFICATE_VERSION,
    IMPOSSIBILITY_PROOF_CHECKER_ROLE,
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
    createImpossibilityVerificationPackage,
    createInvestigationContract,
    createInvestigationOpenedEvent,
    createMeasurementProvenance,
    createSnapshotProvenance,
    createRawMeasurementSeries,
    decideNext,
    deriveUnreachableCoverageClosure,
    deriveTerminalEvidenceClosure,
    detectPlateau,
    enumerandArtifactMeasurementHash,
    hashCanonical,
    impossibilityProofValidationReceiptHash,
    impossibilityVerifierEnumerandResultsRoot,
    impossibilityVerifierFactsRoot,
    impossibilityVerifierRefutationReceiptHash,
    impossibilityVerifierRefutationRoot,
    materializeScientificReplayState,
    normalizeEventIdentifier,
    normalizeHypotheses,
    reduceEvent,
    replicationBlockPlan,
    replayEvents,
    resolveControlEnumerand,
    assessTargetUnreachableReadiness,
    assessPersistedTerminalReadiness,
    scientificReplaySummary,
    searchProgress,
    verifyEventChain,
} from "../domain/index.mjs";
import { fakeHarnessIdentity } from "./harness-identity-fixture.mjs";
import { createLegacyV3OpenedEvent } from "./legacy-v3-fixture.mjs";
import {
    createRuntimeConfigAuthorityFixture,
    createSignedInvestigationAuthority,
} from "./experiment-authority-fixture.mjs";
import {
    fakeEnumerandManifest,
    fakeHarnessSuiteV4,
    fakeStatisticalPolicy,
    upgradeLegacyContractInput,
} from "./v4-contract-fixture.mjs";
import {
    inheritAggregateImpossibilityExecutions,
    issueVerifiedImpossibilityExecutionCapability,
} from "../domain/private-verifier-execution.mjs";

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
    const defaultAcceptancePredicate =
        overrides.hypothesisTopology === "certified_impossibility"
            ? { kind: "harness_pass" }
            : {
                kind: "metric_compare",
                metric: "score",
                operator: ">=",
                value: 0,
            };
    const input = upgradeLegacyContractInput({
        objective: "Find a candidate with a non-negative trusted score",
        acceptancePredicate: defaultAcceptancePredicate,
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
    });
    if (overrides.hypothesisTopology === "certified_impossibility"
        && overrides.statisticalPolicy === undefined) {
        input.statisticalPolicy = fakeStatisticalPolicy({
            topology: "certified_impossibility",
            searchSlots: input.enumerandManifest.entries.length,
            manifest: input.enumerandManifest,
            minBlocks: 1,
            maxBlocks: 32,
            metrics: input.statisticalPolicy.metrics,
        });
    }
    return input;
}

function kernelStatisticalPolicy({
    minBlocks = 1,
    maxBlocks = 1,
    searchSlots = 1,
    acceptanceThreshold = 0,
    maxConfirmations = 1,
    practicalEquivalenceDelta = 1,
    goalMode = "optimize",
} = {}) {
    const policy = fakeStatisticalPolicy({
        minBlocks,
        maxBlocks,
        searchSlots,
        maxConfirmations,
    });
    policy.metrics = [{
        ...policy.metrics[0],
        maximum: 100,
        acceptanceThreshold,
        practicalEquivalenceDelta,
    }];
    policy.control.tolerances = [{
        metric: "score",
        absolute: 0,
        relative: 0,
    }];
    policy.goalMode = goalMode;
    return policy;
}

function digestOf(value) {
    return value.split(":").at(-1);
}

function snapshotHashFor(value) {
    return `sha256:crucible-measurement-snapshot-v1:${digestOf(value)}`;
}

function controlSnapshotId(context) {
    const control = context.contract.statisticalPolicy.control;
    if (control.kind === "snapshot") return control.identity;
    const binding = resolveControlEnumerand(
        context.contract.enumerandManifest,
        {
            topology: context.contract.enumerandManifest.topology,
            observableRegistry: context.contract.observableRegistry,
            hypothesisPolicy: context.contract.hypothesisPolicy,
        },
    );
    return binding.topology === "finite_enumerable"
        ? binding.artifactSnapshotHash
        : artifactHash("c");
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
    role = "search",
    sandboxed = false,
    phase = role === "impossibility_verifier"
        ? "impossibility_verification"
        : role === "search"
            ? "search"
            : "calibration",
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
        role,
        phase,
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
        sandboxPolicy: sandboxed
            ? {
                kind: "sandbox",
                sandboxId: "fixture-appcontainer",
                environmentHash: hashCanonical({
                    sandbox: true,
                    observationId,
                }),
            }
            : {
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
    blockCount = null,
    controlSnapshotOverride = null,
}) {
    const parserVersion = purpose === "impossibility"
        ? context.contract.harnessSuite.roles.impossibility_verifier.parser.version
        : context.contract.parserVersion;
    const measurements = purpose === "validation"
        ? command.validationSeries.flatMap((series) =>
            replicationBlockPlan(
                series.replicationSchedule,
                command.attemptIndex,
            ).arms.map((arm) =>
                fakeMeasurement({
                    subjectId: arm.subjectId,
                    snapshotId: series.artifactHash,
                    observationId,
                    parserVersion,
                    role: series.role,
                    phase: "calibration",
                })))
        : purpose === "candidate"
            ? Array.from(
                {
                    length: blockCount
                        ?? command.replicationSchedule.minBlocks,
                },
                (_unused, blockIndex) => replicationBlockPlan(
                    command.replicationSchedule,
                    blockIndex,
                ).arms,
            ).flat()
                .sort((left, right) =>
                    left.blockIndex - right.blockIndex
                    || left.armIndex - right.armIndex)
                .map((arm) => fakeMeasurement({
                    subjectId: arm.subjectId,
                    snapshotId: arm.armId === "candidate"
                        ? `sha256:${digestOf(candidateArtifactHash)}`
                        : controlSnapshotOverride ?? controlSnapshotId(context),
                    observationId,
                    parserVersion,
                }))
            : [fakeMeasurement({
                subjectId: `impossibility-${command.attemptOrdinal ?? ""}`,
                snapshotId: `sha256:${digestOf(command.requestHash)}`,
                observationId,
                parserVersion,
                role: "impossibility_verifier",
                phase: "impossibility_verification",
                sandboxed: true,
            })];
    const normalizedCandidateHash = purpose === "candidate"
        ? measurements.find((item) =>
            item.measurement.subjectId
                === replicationBlockPlan(command.replicationSchedule, 0)
                    .arms.find((arm) => arm.armId === "candidate").subjectId)
            .measurement.snapshot.snapshotHash
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
        replicationScheduleArtifact: purpose === "candidate"
            ? fakeArtifact(`${observationId}-replication-schedule`)
            : null,
        replicationCompositeArtifact: purpose === "candidate"
            ? fakeArtifact(`${observationId}-replication-composite`)
            : null,
        measurements: measurements.map((item) => item.measurement),
    }, {
        purpose,
        command,
        contract: context.contract,
    });
    const rawStdoutHash = purpose === "validation" || purpose === "candidate"
        ? hashCanonical(
            provenance.measurements.map((item) => ({
                id: item.subjectId,
                hash: item.rawStdoutHash,
            })),
            "sha256:crucible-runtime-observation-streams-v1",
        )
        : measurements[0].stdoutHash;
    const rawStderrHash = purpose === "validation" || purpose === "candidate"
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

function parsedObservation(context, raw, role, phase, arm) {
    const hasMetrics = raw !== null
        && typeof raw === "object"
        && Object.hasOwn(raw, "metrics");
    const metrics = hasMetrics
        ? raw.metrics
        : Object.fromEntries(context.contract.statisticalPolicy.metrics.map(
            (metric) => [
                metric.key,
                raw?.pass === true ? metric.maximum : metric.minimum,
            ],
        ));
    return {
        pass: raw?.pass === true,
        metrics,
        role,
        phase,
        replicateIndex: arm.replicateIndex,
        blockIndex: arm.blockIndex,
        armIndex: arm.armIndex,
        armId: arm.armId,
        deterministicSeed: arm.deterministicSeed,
        subjectId: arm.subjectId,
    };
}

function rawValidationData(
    context,
    command,
    observationId,
    {
        passFor = null,
        metricsFor = null,
    } = {},
) {
    const expectationById = new Map(
        context.contract.validationCases.map((item) => [
            item.id,
            item.expectation,
        ]),
    );
    return {
        version: 1,
        attemptIndex: command.attemptIndex,
        series: command.validationSeries.map((series) => {
            const arm = replicationBlockPlan(
                series.replicationSchedule,
                command.attemptIndex,
            ).arms[0];
            const measurement = fakeMeasurement({
                subjectId: arm.subjectId,
                snapshotId: series.artifactHash,
                observationId,
                parserVersion: context.contract.parserVersion,
                role: series.role,
                phase: "calibration",
            });
            const expectedPass = expectationById.get(series.caseId) === "accept";
            const pass = passFor === null
                ? expectedPass
                : passFor({
                    role: series.role,
                    coveredRoles: series.coveredRoles,
                    caseId: series.caseId,
                    expectedPass,
                });
            const metrics = metricsFor?.({
                role: series.role,
                coveredRoles: series.coveredRoles,
                caseId: series.caseId,
                expectedPass,
            });
            return createRawMeasurementSeries({
                schedule: series.replicationSchedule,
                attempts: [{
                    ...arm,
                    attemptId: `attempt-${observationId}-${arm.subjectId}`,
                    parsed: parsedObservation(
                        context,
                        metrics === undefined ? { pass } : { pass, metrics },
                        series.role,
                        "calibration",
                        arm,
                    ),
                    invalid: null,
                    receiptHash: measurement.receiptHash,
                    measurementRoot: measurement.measurement.measurementRoot,
                }],
                role: series.role,
                phase: "calibration",
                caseId: series.caseId,
            });
        }),
    };
}

function rawCandidateData(
    context,
    command,
    observationId,
    raw,
    blockCount = command.replicationSchedule.minBlocks,
) {
    const attempts = Array.from(
        { length: blockCount },
        (_unused, blockIndex) =>
            replicationBlockPlan(command.replicationSchedule, blockIndex).arms,
    ).flat().map((arm) => {
        const candidate = arm.armId === "candidate";
        const measurement = fakeMeasurement({
            subjectId: arm.subjectId,
            snapshotId: candidate
                ? artifactHash("d")
                : artifactHash("c"),
            observationId,
            parserVersion: context.contract.parserVersion,
        });
        return {
            ...arm,
            attemptId: `attempt-${observationId}-${arm.subjectId}`,
            parsed: parsedObservation(
                context,
                candidate
                    ? raw
                    : {
                        pass: false,
                        metrics: Object.fromEntries(
                            context.contract.statisticalPolicy.metrics.map(
                                (metric) => [metric.key, metric.minimum],
                            ),
                        ),
                    },
                "search",
                "search",
                arm,
            ),
            invalid: null,
            receiptHash: measurement.receiptHash,
            measurementRoot: measurement.measurement.measurementRoot,
        };
    });
    return {
        version: 1,
        series: [createRawMeasurementSeries({
            schedule: command.replicationSchedule,
            attempts,
            role: "search",
            phase: "search",
            caseId: null,
        })],
    };
}

function bindRawDataToReceipt(data, receipt) {
    const measurements = new Map(
        receipt.provenance.measurements.map((measurement) => [
            measurement.subjectId,
            measurement,
        ]),
    );
    return {
        ...data,
        series: data.series.map((series) => ({
            ...series,
            completeBlocks: series.completeBlocks.map((block) => ({
                ...block,
                observations: block.observations.map((observation) => {
                    const measurement = measurements.get(
                        observation.subjectId,
                    );
                    return {
                        ...observation,
                        receiptHash: measurement.receiptHash,
                        measurementRoot: measurement.measurementRoot,
                    };
                }),
            })),
        })),
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

function rehashHistoryFrom(history, startIndex) {
    const copy = structuredClone(history);
    for (let index = startIndex; index < copy.length; index += 1) {
        copy[index].prevHash = index === 0
            ? null
            : copy[index - 1].eventHash;
        copy[index].eventHash = computeEventHash(copy[index]);
    }
    return copy;
}

function openInvestigation(overrides = {}) {
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
    blockCount,
    controlSnapshotOverride,
} = {}) {
    const command = context.aggregate.commands[commandId].command;
    const receipt = fullHarnessReceipt(context, command, {
        purpose,
        observationId,
        candidateArtifactHash: purpose === "candidate"
            ? candidateArtifactHash ?? hashCanonical({ observationId, artifact: true })
            : null,
        blockCount,
        controlSnapshotOverride,
    });
    const rawData = purpose === "validation"
        ? data?.version === 1
            ? data
            : rawValidationData(context, command, observationId)
        : purpose === "candidate"
            ? data?.version === 1
                ? data
                : rawCandidateData(
                    context,
                    command,
                    observationId,
                    data,
                    blockCount,
                )
            : data;
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
        data: purpose === "candidate" || purpose === "validation"
            ? bindRawDataToReceipt(rawData, receipt)
            : rawData,
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
    });
    append(context, constructKernelDecisionEvent(context.aggregate));
    expect(context.aggregate.validation.currentEvidenceId).toBe("validation-evidence");
    return context;
}

function commitValidationAttempt(context, {
    label,
    dataFor,
} = {}) {
    const reserved = reserveAndDispatch(context);
    expect(reserved.command.kind).toBe("run_validation");
    const observationId = `validation-observation-${label}`;
    const evidenceId = `validation-evidence-${label}`;
    const evidence = observeAndCommit(context, reserved.commandId, {
        purpose: "validation",
        observationId,
        evidenceId,
        data: dataFor === undefined
            ? rawValidationData(
                context,
                reserved.command,
                observationId,
            )
            : dataFor(reserved.command, observationId),
    });
    return { command: reserved.command, evidence };
}

function commitCandidate(context, {
    data = { pass: false },
    dataFor,
    annotations,
    candidateArtifactHash,
    blockCount,
    controlSnapshotOverride,
    label = String(context.aggregate.evidenceOrder.length),
} = {}) {
    const reserved = reserveAndDispatch(context);
    expect(reserved.command.kind).toBe("search_candidate");
    const effectiveBlockCount = blockCount
        ?? (context.contract.hypothesisTopology === "certified_impossibility"
            && data?.pass === false
            ? reserved.command.replicationSchedule.maxBlocks
            : undefined);
    const boundArtifactHash =
        reserved.command.enumerand?.topology === "finite_enumerable"
            ? candidateArtifactHash ?? enumerandArtifactMeasurementHash(
                reserved.command.enumerand.artifactSnapshotHash,
            )
            : candidateArtifactHash;
    const evidence = observeAndCommit(context, reserved.commandId, {
        purpose: "candidate",
        observationId: `candidate-observation-${label}`,
        evidenceId: `candidate-evidence-${label}`,
        data: dataFor === undefined
            ? data
            : dataFor(
                reserved.command,
                `candidate-observation-${label}`,
            ),
        annotations,
        candidateArtifactHash: boundArtifactHash,
        blockCount: effectiveBlockCount,
        controlSnapshotOverride,
    });
    return { command: reserved.command, evidence };
}

function impossibilityObservationInput(context, command, label, {
    pass = true,
    searchSpaceExhausted = true,
    certificateVerdict,
    checkerStatus,
} = {}) {
    const requestHash = command.requestHash ?? hashCanonical({ label, request: "legacy" });
    const status = checkerStatus ?? (pass && searchSpaceExhausted
        ? "VERIFIED"
        : pass
            ? "INVALID"
            : "REJECTED");
    const derivedVerdict = status === "VERIFIED"
        ? "target_unreachable"
        : status === "REJECTED"
            ? "not_proven"
            : status === "INCONCLUSIVE"
                ? "inconclusive"
                : "invalid";
    const mode = command.request?.verifier?.verificationPolicy?.mode
        ?? "enumerand_reexecution";
    const certificateFormat =
        command.request?.verifier?.verificationPolicy?.certificateFormat
        ?? null;
    const proofArtifactHash = command.proofArtifactHash
        ?? hashCanonical({ label, proof: true });
    const proofCheckerIdentity = mode === "certificate_validation"
        ? command.request?.verifier?.proofChecker?.identity
            ?? hashCanonical({ label, proofChecker: true })
        : null;
    const validatedProofArtifactHash = mode === "certificate_validation"
        ? proofArtifactHash
        : null;
    const checkerEvidenceRoot = hashCanonical({
        label,
        checker: true,
        status,
    }, "sha256:crucible-test-checker-evidence-v1");
    const evidenceRoots = command.request?.evidence?.roots ?? {
        calibration: hashCanonical({ label, root: "calibration" }),
        control: hashCanonical({ label, root: "control" }),
        search: hashCanonical({ label, root: "search" }),
        scientificReplay: hashCanonical({ label, root: "replay" }),
    };
    const enumerandManifestRoot = command.request?.enumerands?.merkleRoot
        ?? hashCanonical({ label, manifest: true });
    const enumerandCount = command.request?.enumerands?.count ?? 1;
    const proposalHash = command.proposedCertificateArtifactHash
        ?? hashCanonical({ label, proposal: true });
    const verifierRoleIdentity =
        command.request?.verifier?.roleIdentity
        ?? hashCanonical({ label, role: true });
    const statisticalPolicyIdentity =
        command.request?.statistics?.policyIdentity
        ?? context.contract.statisticalPolicyIdentity;
    const alphaLedgerRoot = command.request?.statistics?.alphaLedgerRoot
        ?? hashCanonical({ label, alpha: true });
    const coverageClosureRoot =
        command.request?.evidence?.coverageClosureRoot
        ?? hashCanonical({ label, coverage: true });
    const expectedEnumerands =
        command.request?.evidence?.coverageClosure?.enumerands ?? [{
            ordinal: 0,
            enumerandHash: enumerandManifestRoot,
            claims: [{ claimId: "acceptance.harness_pass" }],
        }];
    const claimState = status === "VERIFIED"
        ? "REFUTED"
        : status === "REJECTED"
            ? "SUPPORTED"
            : status === "INCONCLUSIVE"
                ? "UNRESOLVED"
                : "INVALID";
    const enumerandResults = mode === "enumerand_reexecution"
        ? (status === "INCONCLUSIVE" || status === "INVALID"
            ? expectedEnumerands.slice(0, 1)
            : expectedEnumerands).map((entry) => {
            const input = command.request?.reevaluation?.enumerands?.[
                entry.ordinal
            ] ?? {
                inputRoot: hashCanonical({
                    label,
                    ordinal: entry.ordinal,
                    input: true,
                }),
                receiptBindingsRoot: hashCanonical({
                    label,
                    ordinal: entry.ordinal,
                    receipts: true,
                }),
            };
            const claimStates = entry.claims.map((claim) => ({
                claimId: claim.claimId,
                state: claimState,
            }));
            const evidenceRoot = impossibilityVerifierRefutationRoot({
                requestHash,
                verifierRoleIdentity,
                ordinal: entry.ordinal,
                enumerandHash: entry.enumerandHash,
                inputRoot: input.inputRoot,
                claimStates,
            });
            return {
                ordinal: entry.ordinal,
                enumerandHash: entry.enumerandHash,
                claimStates,
                inputRoot: input.inputRoot,
                receiptBindingsRoot: input.receiptBindingsRoot,
                evidenceRoot,
                refutationReceiptHash:
                    impossibilityVerifierRefutationReceiptHash({
                        requestHash,
                        verifierRoleIdentity,
                        ordinal: entry.ordinal,
                        enumerandHash: entry.enumerandHash,
                        inputRoot: input.inputRoot,
                        receiptBindingsRoot:
                            input.receiptBindingsRoot,
                        claimStates,
                        evidenceRoot,
                    }),
            };
        })
        : [];
    const enumerandResultsRoot =
        impossibilityVerifierEnumerandResultsRoot(enumerandResults);
    const proofValidationReceiptHash = mode === "certificate_validation"
        ? impossibilityProofValidationReceiptHash({
            requestHash,
            proofArtifactHash,
            proofCheckerIdentity,
            certificateFormat,
            status,
            checkerEvidenceRoot,
        })
        : null;
    const independentFactsRoot = impossibilityVerifierFactsRoot({
        mode,
        enumerandResults,
        proofArtifactHash,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
    });
    const certificate = {
        version:
            command.certificateVersion ?? IMPOSSIBILITY_CERTIFICATE_VERSION,
        status,
        verdict: certificateVerdict ?? derivedVerdict,
        mode,
        requestHash,
        proposedCertificateArtifactHash: proposalHash,
        proofArtifactHash,
        contractHash: command.request?.signedExperiment?.contractHash
            ?? context.aggregate.contractHash,
        harnessSuiteIdentity:
            context.contract.harnessSuiteIdentity,
        verifierRoleIdentity,
        coverageClosureRoot,
        enumerandManifestRoot,
        enumerandResultsRoot,
        evidenceRoots,
        statisticalPolicyIdentity,
        alphaLedgerRoot,
        checkerEvidenceRoot,
        independentFactsRoot,
        certificateFormat,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
    };
    const checkerResult = {
        version: "crucible-impossibility-verifier-output-v1",
        status,
        mode,
        requestHash,
        proposedCertificateArtifactHash: proposalHash,
        proofArtifactHash,
        coverageClosureRoot,
        enumerandManifestRoot,
        enumerandCount,
        checkedEnumerandCount: enumerandResults.length,
        enumerandResults,
        enumerandResultsRoot,
        evidenceRoots,
        statisticalPolicyIdentity,
        alphaLedgerRoot,
        checkerEvidenceRoot,
        independentFactsRoot,
        disagreementCount: enumerandResults.filter((result) =>
            result.claimStates.some((claim) => claim.state !== "REFUTED")).length,
        complete: status === "VERIFIED" || status === "REJECTED",
        certificateFormat,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
        certificate,
        ...(command.measurementBinding ?? {
            role: "impossibility_verifier",
            phase: "impossibility_verification",
            replicateIndex: null,
            blockIndex: 0,
            armIndex: null,
            armId: null,
            deterministicSeed: hashCanonical({ label, seed: true }),
            subjectId: "impossibility-1",
            environmentIdentity:
                context.contract.harnessSuite.environmentIdentity,
            suiteIdentity: context.contract.harnessSuiteIdentity,
        }),
        parserVersion: command.parserVersion ?? "parser-v2",
    };
    const certificateArtifactHash = hashCanonical(
        certificate,
        "sha256:crucible-impossibility-certificate-artifact-v2",
    );
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
            checkerStatus: status,
            certificateVerdict: certificateVerdict ?? derivedVerdict,
            certificateArtifactHash,
            measurementReceiptHash,
            verificationRequestHash: requestHash,
            proposedCertificateArtifactHash: proposalHash,
            verificationSnapshotHash,
            checkerResult,
        },
    };
}

function verifiedVerifierCapability(context, input) {
    const command = context.aggregate.commands[input.commandId].command;
    const role = context.contract.harnessSuite.roles.impossibility_verifier;
    const measurement = input.receipt.provenance.measurements[0];
    const checker = input.data.checkerResult;
    const requestArtifact = fakeArtifact(
        `${input.observationId}-request`,
        command.requestHash,
    );
    const proofArtifact = fakeArtifact(
        `${input.observationId}-proof`,
        command.proofArtifactHash,
    );
    const executionIdentity = hashCanonical(
        {
            commandId: input.commandId,
            observationId: input.observationId,
            receiptHash: measurement.receiptHash,
        },
        "sha256:crucible-verified-impossibility-execution-identity-v1",
    );
    const enumerandObservations = checker.enumerandResults.map((result) => {
        const inputArtifact = fakeArtifact(
            `verified-enumerand-${result.ordinal}`,
            result.inputRoot,
        );
        const observationCore = {
            ordinal: result.ordinal,
            enumerandHash: result.enumerandHash,
            inputRoot: result.inputRoot,
            receiptBindingsRoot: result.receiptBindingsRoot,
            claimStates: result.claimStates,
            inputArtifact,
        };
        const observationHash = hashCanonical(
            observationCore,
            "sha256:crucible-verified-impossibility-enumerand-observation-v1",
        );
        const receiptCore = {
            executionIdentity,
            measurementReceiptHash: measurement.receiptHash,
            rawStdoutHash: measurement.rawStdoutHash,
            requestHash: command.requestHash,
            requestArtifact,
            observationHash,
            inputArtifact,
        };
        return {
            ...observationCore,
            observationHash,
            checkerReceipt: {
                ...receiptCore,
                receiptHash: hashCanonical(
                    receiptCore,
                    "sha256:crucible-verified-impossibility-checker-receipt-v1",
                ),
            },
        };
    });
    const proofCheckerReceipt = checker.mode === "certificate_validation"
        ? (() => {
            const core = {
                executionIdentity,
                measurementReceiptHash: measurement.receiptHash,
                rawStdoutHash: measurement.rawStdoutHash,
                requestHash: command.requestHash,
                requestArtifact,
                proofArtifact,
                proofArtifactHash: command.proofArtifactHash,
                proofCheckerIdentity:
                    command.request.verifier.proofChecker.identity,
                certificateFormat:
                    command.request.verifier.verificationPolicy
                        .certificateFormat,
                status: checker.status,
            };
            return {
                ...core,
                receiptHash: hashCanonical(
                    core,
                    "sha256:crucible-verified-impossibility-checker-receipt-v1",
                ),
            };
        })()
        : null;
    const factsCore = {
        status: checker.status,
        verdict: checker.certificate.verdict,
        mode: checker.mode,
        complete: checker.complete,
        disagreementCount: checker.disagreementCount,
        requestHash: command.requestHash,
        proposedCertificateArtifactHash:
            command.proposedCertificateArtifactHash,
        proofArtifactHash: command.proofArtifactHash,
        coverageClosureRoot: checker.coverageClosureRoot,
        enumerandManifestRoot: checker.enumerandManifestRoot,
        enumerandCount: checker.enumerandCount,
        checkedEnumerandCount: checker.checkedEnumerandCount,
        enumerandObservations,
        evidenceRoots: checker.evidenceRoots,
        statisticalPolicyIdentity: checker.statisticalPolicyIdentity,
        alphaLedgerRoot: checker.alphaLedgerRoot,
        checkerEvidenceRoot: checker.checkerEvidenceRoot,
        proofCheckerReceipt,
    };
    const reference = {
        version: "crucible-verified-impossibility-execution-v1",
        commandId: input.commandId,
        observationId: input.observationId,
        request: {
            requestHash: command.requestHash,
            artifact: requestArtifact,
            snapshotManifestArtifact: measurement.snapshot.manifestArtifact,
        },
        proof: {
            artifactHash: command.proofArtifactHash,
            artifact: proofArtifact,
            sizeBytes: 1,
        },
        certificate: {
            artifact:
                input.receipt.provenance.impossibilityCertificateArtifact,
            artifactHash: input.data.certificateArtifactHash,
            sizeBytes: 1,
        },
        measurement: {
            subjectId: measurement.subjectId,
            measurementRoot: measurement.measurementRoot,
            receiptHash: measurement.receiptHash,
            receiptArtifact: measurement.receiptArtifact,
            rawStdoutHash: measurement.rawStdoutHash,
            rawStdoutArtifact: measurement.rawStdoutArtifact,
            rawStderrHash: measurement.rawStderrHash,
            rawStderrArtifact: measurement.rawStderrArtifact,
            snapshotHash: measurement.snapshot.snapshotHash,
            snapshotClosureRoot: measurement.snapshot.closureRoot,
        },
        executionIdentity: {
            identity: executionIdentity,
            harnessId: role.harnessId,
            harnessEntryHash: role.harnessEntryHash,
            executableHash: role.executableHash,
            stagedExecutableHash: role.executableHash,
            applicationEntrypointHash: role.applicationEntrypointHash,
            parserIdentity: role.parser,
            sandbox: {
                policyDigest: role.sandboxIdentity.policyDigest,
                policyIdentity: {
                    securityContext: {
                        appContainer: true,
                        lowIntegrity: true,
                        capabilities: [],
                    },
                },
            },
        },
        effectBinding: {
            effectAttempt: { attemptId: input.receipt.attemptId },
            observationAttempt: { attemptId: "domain-attempt" },
            runnerEpochId: input.receipt.runnerEpochId,
        },
        facts: {
            ...factsCore,
            factsRoot: hashCanonical(
                factsCore,
                "sha256:crucible-verified-impossibility-facts-v1",
            ),
        },
    };
    return issueVerifiedImpossibilityExecutionCapability({
        commandId: input.commandId,
        observationId: input.observationId,
        reference,
    });
}

function constructVerifiedImpossibilityObservedEvent(context, input) {
    return constructHarnessObservedEvent(context.aggregate, input, {
        verifierExecutionCapability:
            verifiedVerifierCapability(context, input),
    });
}

function commitImpossibility(context, reserved, label, facts = {}) {
    const input = impossibilityObservationInput(context, {
        ...reserved.command,
        commandId: reserved.commandId,
    }, label, facts);
    const observed = constructVerifiedImpossibilityObservedEvent(
        context,
        input,
    );
    append(context, observed);
    const evidenceId = `impossibility-evidence-${label}`;
    append(context, constructEvidenceCommittedEvent(context.aggregate, {
        evidenceId,
        observationId: input.observationId,
    }));
    return context.aggregate.evidence[evidenceId];
}

describe("Crucible domain version 4 kernel", () => {
    it("does not export an unsigned v4 opening event constructor path", () => {
        const contract = createInvestigationContract(contractInput());
        expect(() => createInvestigationOpenedEvent(contract))
            .toThrow(expect.objectContaining({
                code: ERROR_CODES.INVALID_CONTRACT,
            }));
    });

    it("stamps the contract and investigation_opened with DOMAIN_VERSION=4", () => {
        const context = validateInvestigation(openInvestigation());
        const opened = context.history[0];
        expect(DOMAIN_VERSION).toBe(4);
        expect(opened.payload.domainVersion).toBe(4);
        expect(opened.payload.contract.domainVersion).toBe(4);
        expect(opened.payload.contractHash).toMatch(
            /^sha256:crucible-contract-v4:[a-f0-9]{64}$/u,
        );
        expect(opened.eventHash).toMatch(
            /^sha256:crucible-event-v4:[a-f0-9]{64}$/u,
        );

        const replayed = replayEvents(context.history);
        expect(canonicalJson(replayed)).toBe(canonicalJson(context.aggregate));
        expect(verifyEventChain(context.history)).toEqual({
            valid: true,
            eventCount: context.history.length,
            lastSeq: context.aggregate.lastSeq,
            lastEventHash: context.aggregate.lastEventHash,
        });
    });

    it("replays appended candidate observations with sealed hypotheses", () => {
            const observableRegistry = [{
                key: "score",
                kind: "numeric",
                minimum: 0,
                maximum: 1,
            }];
            const hypothesisPolicy = {
                required: true,
                maxPredictions: 2,
                allowedKinds: ["threshold"],
                allowRequiredForResult: true,
            };
            const rawHypotheses = {
                predictions: [{
                    id: "score-threshold",
                    kind: "threshold",
                    observable: "score",
                    operator: ">=",
                    value: 0.8,
                    refutation: {
                        kind: "threshold",
                        operator: "<",
                        value: 0.8,
                    },
                    requiredForResult: true,
                }],
            };
            const enumerandManifest = {
                topology: "finite_enumerable",
                entries: [{
                    id: "candidate-r000001-s000",
                    ordinal: 0,
                    artifactSnapshotHash: artifactHash("e"),
                    hypotheses: rawHypotheses,
                }],
                control: {
                    kind: "reference",
                    referenceHash: artifactHash("f"),
                },
            };
            const context = validateInvestigation(openInvestigation({
                hypothesisTopology: "finite_enumerable",
                maxRounds: 1,
                observableRegistry,
                hypothesisPolicy,
                enumerandManifest,
                statisticalPolicy: fakeStatisticalPolicy({
                    topology: "finite_enumerable",
                    searchSlots: 1,
                    control: {
                        kind: "snapshot",
                        identity: artifactHash("f"),
                    },
                    metrics: [{
                        key: "score",
                        minimum: 0,
                        maximum: 1,
                        estimand: "mean score versus control",
                        unit: "score",
                        direction: "max",
                        acceptanceThreshold: 0,
                        practicalEquivalenceDelta: 0.01,
                        family: "primary",
                    }],
                }),
            }));
            const hypotheses = normalizeHypotheses(rawHypotheses, {
                observableRegistry,
                hypothesisPolicy,
            });
            commitCandidate(context, {
                label: "hypothesis-replay",
                data: { pass: true, metrics: { score: 0.9 } },
                annotations: {
                    mechanism: "exercise canonical hypothesis replay",
                    hypotheses,
                },
            });

            const replayed = replayEvents(context.history);
            expect(replayed.observations["candidate-observation-hypothesis-replay"]
                .annotations.hypotheses).toEqual(hypotheses);
            expect(canonicalJson(replayed)).toBe(canonicalJson(context.aggregate));
            expect(decideNext(context.aggregate)).toMatchObject({
                kind: "NON_RESULT",
                code: NON_RESULT_CODES.SCIENTIFIC_PREDICTION_UNRESOLVED,
                evidenceIds: ["candidate-evidence-hypothesis-replay"],
                readiness: {
                    requiredPredictionState: "UNRESOLVED",
                },
            });

        const observationIndex = context.history.findIndex((event) =>
                event.type === EVENT_TYPES.COMMAND_OBSERVED
                && event.payload.purpose === "candidate");
        const omitted = structuredClone(context.history);
        delete omitted[observationIndex].payload.annotations.hypotheses;
        expect(() => replayEvents(rehashHistoryFrom(
                omitted,
                observationIndex,
        ))).toThrow(/hypotheses/u);

        const mutated = structuredClone(context.history);
        mutated[observationIndex].payload.annotations.hypotheses
                .predictions[0].value = 0.9;
        expect(() => replayEvents(rehashHistoryFrom(
                mutated,
                observationIndex,
        ))).toThrow(/hypotheses/u);
    });

    it("records an unresolved required prediction as a typed non-result", () => {
        const observableRegistry = [{
            key: "score",
            kind: "numeric",
            minimum: 0,
            maximum: 1,
        }];
        const hypothesisPolicy = {
            required: true,
            maxPredictions: 1,
            allowedKinds: ["threshold"],
            allowRequiredForResult: true,
        };
        const rawHypotheses = {
            predictions: [{
                id: "required-score-threshold",
                kind: "threshold",
                observable: "score",
                operator: ">=",
                value: 0.8,
                refutation: {
                    kind: "threshold",
                    operator: "<",
                    value: 0.8,
                },
                requiredForResult: true,
            }],
        };
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "finite_enumerable",
            maxRounds: 1,
            observableRegistry,
            hypothesisPolicy,
            enumerandManifest: {
                topology: "finite_enumerable",
                entries: [{
                    id: "candidate-r000001-s000",
                    ordinal: 0,
                    artifactSnapshotHash: artifactHash("e"),
                    hypotheses: rawHypotheses,
                }],
                control: {
                    kind: "reference",
                    referenceHash: artifactHash("f"),
                },
            },
            statisticalPolicy: fakeStatisticalPolicy({
                topology: "finite_enumerable",
                searchSlots: 1,
                minBlocks: 1,
                maxBlocks: 32,
                control: {
                    kind: "snapshot",
                    identity: artifactHash("f"),
                },
                metrics: [{
                    key: "score",
                    minimum: 0,
                    maximum: 1,
                    estimand: "mean score versus control",
                    unit: "score",
                    direction: "max",
                    acceptanceThreshold: 0,
                    practicalEquivalenceDelta: 0.01,
                    family: "primary",
                }],
            }),
        }));
        const hypotheses = normalizeHypotheses(rawHypotheses, {
            observableRegistry,
            hypothesisPolicy,
        });
        const committed = commitCandidate(context, {
            label: "required-unresolved",
            blockCount: 32,
            data: { pass: true, metrics: { score: 0.8 } },
            annotations: {
                mechanism: "prediction must not be laundered into a result",
                hypotheses,
            },
        });
        expect(committed.evidence.predictionEvaluation.requiredState)
            .toBe("UNRESOLVED");
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.SCIENTIFIC_PREDICTION_UNRESOLVED,
            evidenceIds: [committed.evidence.evidenceId],
            readiness: {
                requiredPredictionState: "UNRESOLVED",
            },
        });
        append(context, constructKernelDecisionEvent(context.aggregate));
        expect(context.aggregate).toMatchObject({
            terminal: null,
            status: "non_result",
            nonResults: [{
                code: NON_RESULT_CODES.SCIENTIFIC_PREDICTION_UNRESOLVED,
            }],
        });
    });

    it("never evaluates model-authored observation hypotheses outside a frozen command", () => {
        const context = validateInvestigation(openInvestigation({
                maxRounds: 1,
        }));
        const hypotheses = normalizeHypotheses({
                predictions: [{
                    id: "attacker-authored",
                    kind: "threshold",
                    observable: "score",
                    operator: ">=",
                    value: 0,
                    refutation: {
                        kind: "threshold",
                        operator: "<",
                        value: 0,
                    },
                }],
        }, {
                observableRegistry: context.contract.observableRegistry,
                hypothesisPolicy: context.contract.hypothesisPolicy,
        });
        expect(() => commitCandidate(context, {
                label: "arbitrary-hypotheses",
                data: { pass: true, metrics: { score: 100 } },
                annotations: {
                    mechanism: "attempt to inject post-command hypotheses",
                    hypotheses,
                },
        })).toThrow(/kernel-frozen command hypotheses/u);
    });

    it("rejects truncated discovery evidence until the frozen stopping rule closes", () => {
        const policy = kernelStatisticalPolicy({
                minBlocks: 1,
                maxBlocks: 2,
                searchSlots: 1,
                acceptanceThreshold: 0,
                goalMode: "optimize",
        });
        const truncated = validateInvestigation(openInvestigation({
                maxRounds: 1,
                statisticalPolicy: policy,
        }));
        expect(() => commitCandidate(truncated, {
                label: "truncated-optimize",
                data: { pass: true, metrics: { score: 100 } },
                blockCount: 1,
        })).toThrow(/stopping rule/u);

        const complete = validateInvestigation(openInvestigation({
                maxRounds: 1,
                statisticalPolicy: policy,
        }));
        const evidence = commitCandidate(complete, {
                label: "complete-optimize",
                data: { pass: true, metrics: { score: 100 } },
                blockCount: 2,
        }).evidence;
        expect(evidence.replication).toMatchObject({
                version: 3,
                minBlocks: 1,
                maxBlocks: 2,
                blockCount: 2,
                stopping: {
                    shouldContinue: false,
                },
                stoppingDigest: expect.stringMatching(
                    /^sha256:crucible-replication-stopping-v1:[a-f0-9]{64}$/u,
                ),
        });
    });

    it("applies satisfice stopping policy and rejects unresolved truncation", () => {
        const supported = validateInvestigation(openInvestigation({
                maxRounds: 1,
                statisticalPolicy: kernelStatisticalPolicy({
                    minBlocks: 1,
                    maxBlocks: 2,
                    searchSlots: 1,
                    acceptanceThreshold: 0,
                    goalMode: "satisfice",
                }),
        }));
        expect(commitCandidate(supported, {
                label: "satisfice-supported",
                data: { pass: true, metrics: { score: 100 } },
                blockCount: 1,
        }).evidence.replication.stopping).toMatchObject({
                shouldContinue: false,
                stoppingReason: "claims_resolved",
        });

        const unresolved = validateInvestigation(openInvestigation({
                maxRounds: 1,
                acceptancePredicate: {
                    kind: "metric_compare",
                    metric: "score",
                    operator: ">=",
                    value: 80,
                },
                statisticalPolicy: kernelStatisticalPolicy({
                    minBlocks: 1,
                    maxBlocks: 2,
                    searchSlots: 1,
                    acceptanceThreshold: 80,
                    goalMode: "satisfice",
                }),
        }));
        expect(() => commitCandidate(unresolved, {
                label: "satisfice-unresolved",
                blockCount: 1,
                dataFor: (command, observationId) => {
                    const raw = structuredClone(rawCandidateData(
                        unresolved,
                        command,
                        observationId,
                        { pass: true, metrics: { score: 80 } },
                        1,
                    ));
                    raw.series[0].completeBlocks[0].observations.find(
                        (item) => item.armId === "control",
                    ).parsed.metrics.score = 80;
                    return raw;
                },
        })).toThrow(/stopping rule/u);
    });

    it("rejects a consistently substituted control snapshot", () => {
        const context = validateInvestigation(openInvestigation({
                maxRounds: 1,
        }));
        expect(() => commitCandidate(context, {
                label: "alternate-control",
                data: { pass: true, metrics: { score: 100 } },
                controlSnapshotOverride: artifactHash("9"),
        })).toThrow(/control binding|frozen control/u);
    });

    it("treats persisted statistical summaries as digest-bound replay caches", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "cache-tamper",
            data: { pass: true, metrics: { score: 100 } },
        });
        const replayed = replayEvents(context.history);
        expect(canonicalJson(
            materializeScientificReplayState(replayed).scientificAggregate,
        )).toBe(canonicalJson(
            materializeScientificReplayState(
                context.aggregate,
            ).scientificAggregate,
        ));
        expect(replayed.evidence["candidate-evidence-cache-tamper"])
            .toMatchObject({
                rawAuthorityDigest: expect.stringMatching(
                    /^sha256:crucible-raw-observation-authority-v1:[a-f0-9]{64}$/u,
                ),
                statisticalCacheDigest: expect.stringMatching(
                    /^sha256:crucible-statistical-cache-v1:[a-f0-9]{64}$/u,
                ),
            });

        const eventIndex = context.history.findIndex((event) =>
            event.type === EVENT_TYPES.EVIDENCE_COMMITTED
            && event.payload.evidenceId === "candidate-evidence-cache-tamper");
        const tampered = structuredClone(context.history);
        tampered[eventIndex].payload.statisticalEvaluation
            .statistics.overallState = "REFUTED";
        const rehashed = rehashHistoryFrom(tampered, eventIndex);
        expect(() => replayEvents(rehashed)).toThrow(
            expect.objectContaining({ code: ERROR_CODES.INVALID_EVIDENCE }),
        );
    });

    it("uses replay-derived calibration and candidate support for decisions", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "replay-decision",
            data: { pass: true, metrics: { score: 100 } },
        });
        const expectedDecision = decideNext(context.aggregate);
        const expectedProgress = searchProgress(context.aggregate);
        const forged = structuredClone(context.aggregate);
        const validation = forged.evidence["validation-evidence"];
        validation.validationSatisfied = false;
        validation.validationBasisEvidenceIds = [];
        validation.validationEvaluation.satisfied = false;
        const candidate = forged.evidence["candidate-evidence-replay-decision"];
        candidate.acceptanceSatisfied = false;
        candidate.outcomeClass = "rejected";
        candidate.rankable = false;
        candidate.metrics = { score: 0 };
        candidate.replication.statisticalState = "REFUTED";
        candidate.statisticalEvaluation.requiredState = "REFUTED";

        expect(decideNext(forged)).toEqual(expectedDecision);
        expect(searchProgress(forged).candidates[0]).toMatchObject({
            acceptanceSatisfied:
                expectedProgress.candidates[0].acceptanceSatisfied,
            metrics: expectedProgress.candidates[0].metrics,
            outcomeClass: expectedProgress.candidates[0].outcomeClass,
            rankable: expectedProgress.candidates[0].rankable,
            replication: expectedProgress.candidates[0].replication,
        });
    });

    it("rejects missing, reordered, or mutated raw arm receipt bindings on replay", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "raw-tamper",
            data: { pass: true, metrics: { score: 100 } },
        });
        const eventIndex = context.history.findIndex((event) =>
            event.type === EVENT_TYPES.COMMAND_OBSERVED
            && event.payload.observationId === "candidate-observation-raw-tamper");
        const mutate = (operation) => {
            const history = structuredClone(context.history);
            const event = history[eventIndex];
            const observations =
                event.payload.data.series[0].completeBlocks[0].observations;
            operation(observations, event);
            return rehashHistoryFrom(history, eventIndex);
        };
        const cases = [
            (observations) => observations.pop(),
            (observations) => observations.reverse(),
            (_observations, event) => {
                event.payload.receipt.provenance.measurements.reverse();
            },
            (observations) => {
                observations[0].receiptHash = hashCanonical({
                    tampered: "receipt",
                });
            },
            (observations) => {
                observations[0].deterministicSeed = hashCanonical({
                    tampered: "seed",
                });
            },
            (observations) => {
                observations[0].armIndex = observations[0].armIndex === 0
                    ? 1
                    : 0;
            },
            (observations, event) => {
                event.payload.data.series[0].completeBlocks[0].blockIndex = 1;
                for (const observation of observations) {
                    observation.blockIndex = 1;
                    observation.parsed.blockIndex = 1;
                }
            },
            (observations) => {
                const control = observations.find(
                    (observation) => observation.armId === "control",
                );
                control.parsed.metrics.score = 1;
            },
        ];
        for (const operation of cases) {
            expect(() => replayEvents(mutate(operation))).toThrow(
                expect.objectContaining({
                    code: expect.stringMatching(
                        /^(?:INVALID_EVENT|INVALID_EVIDENCE)$/u,
                    ),
                }),
            );
        }
    });

    it("rejects mutations to frozen bounds, alpha, or control authority", () => {
        const context = openInvestigation();
        const mutations = [
            (contract) => {
                contract.statisticalPolicy.metrics[0].maximum += 1;
            },
            (contract) => {
                contract.statisticalPolicy.investigationAlpha = 0.04;
            },
            (contract) => {
                contract.statisticalPolicy.control.identity = hashCanonical({
                    forged: "control",
                });
            },
        ];
        for (const mutate of mutations) {
            const history = structuredClone(context.history);
            mutate(history[0].payload.contract);
            expect(() => replayEvents(rehashHistoryFrom(history, 0))).toThrow(
                expect.objectContaining({
                    code: expect.stringMatching(
                        /^(?:INVALID_CONTRACT|INVALID_EVENT)$/u,
                    ),
                }),
            );
        }
    });

    it("binds result closure to replay-derived aggregate, claims, alpha, and raw authority", () => {
        const make = (alpha) => {
            const policy = kernelStatisticalPolicy({
                minBlocks: 1,
                maxBlocks: 1,
                acceptanceThreshold: 0,
            });
            policy.investigationAlpha = alpha;
            policy.familyAllocations = [{
                family: "primary",
                alpha,
            }];
            const context = validateInvestigation(openInvestigation({
                maxRounds: 1,
                statisticalPolicy: policy,
            }));
            const evidence = commitCandidate(context, {
                label: `closure-${String(alpha).replace(".", "-")}`,
                data: { pass: true, metrics: { score: 100 } },
            }).evidence;
            const closure = deriveTerminalEvidenceClosure(
                context.aggregate,
                {
                    basis: { kind: "test_result_closure" },
                    decisiveKind: "candidate_cohort",
                    decisiveEvidence: [evidence],
                },
            );
            return { context, evidence, closure };
        };
        const first = make(0.05);
        const second = make(0.04);
        expect(first.closure.scientificReplay).toEqual(
            scientificReplaySummary(first.context.aggregate.scientificReplay),
        );
        expect(first.closure.closureRoot).not.toBe(second.closure.closureRoot);
        expect(first.context.aggregate.scientificReplay.alphaLedgerHash)
            .not.toBe(second.context.aggregate.scientificReplay.alphaLedgerHash);
        expect(first.closure).toMatchObject({
            authority: {
                experiment: {
                    authorityIdentity:
                        first.context.aggregate.experimentAuthorityIdentity,
                },
                contract: {
                    contractHash: first.context.aggregate.contractHash,
                    harnessSuiteIdentity:
                        first.context.aggregate.contract.harnessSuiteIdentity,
                },
                runtime: {
                    fingerprint:
                        first.context.aggregate.runtimeConfigFingerprint,
                },
            },
            artifacts: {
                evidenceCount: first.context.aggregate.evidenceOrder.length,
                artifactReferenceCount: expect.any(Number),
            },
        });

        const cohort =
            first.context.aggregate.scientificReplay.candidateCohort;
        const terminalAggregate = {
            ...first.context.aggregate,
            terminal: {
                decision: "VERIFIED_RESULT",
                cohortStatus: cohort.status,
                candidateId: first.evidence.candidateId,
                candidateIds: [first.evidence.candidateId],
                evidenceId: first.evidence.evidenceId,
                evidenceIds: [first.evidence.evidenceId],
                evidenceHash: first.evidence.commitEventHash,
                evidenceHashes: [first.evidence.commitEventHash],
                cohortComparisonHash: cohort.comparisonHash,
                relationEvidenceHash: cohort.relationEvidenceHash,
                contractHash: first.context.aggregate.contractHash,
                basis: { kind: "test_result_closure" },
                evidenceClosure: first.closure,
            },
        };
        expect(assessPersistedTerminalReadiness(terminalAggregate))
            .toMatchObject({ integrityBound: true, ready: false });
        const forgedClosure = structuredClone(first.closure);
        forgedClosure.scientificReplay.closureRoot = hashCanonical({
            forged: "scientific-closure",
        });
        expect(assessPersistedTerminalReadiness({
            ...terminalAggregate,
            terminal: {
                ...terminalAggregate.terminal,
                evidenceClosure: forgedClosure,
            },
        })).toMatchObject({ integrityBound: false, ready: false });
        for (const mutate of [
            (closure) => {
                closure.authority.runtime.fingerprint = hashCanonical({
                    forged: "runtime",
                });
            },
            (closure) => {
                closure.artifacts.artifactRefsRoot = hashCanonical({
                    forged: "artifact refs",
                });
            },
            (closure) => {
                closure.termination.plateau.phase = "forged";
            },
            (closure) => {
                closure.scientificConclusions[0]
                    .candidate.performance.claims[0].status = "REFUTED";
            },
        ]) {
            const tampered = structuredClone(first.closure);
            mutate(tampered);
            expect(assessPersistedTerminalReadiness({
                ...terminalAggregate,
                terminal: {
                    ...terminalAggregate.terminal,
                    evidenceClosure: tampered,
                },
            })).toMatchObject({ integrityBound: false, ready: false });
        }
    });

    it("rejects an actual v3 opening before v4 hash or contract normalization", () => {
        const opened = createLegacyV3OpenedEvent(
            createInvestigationContract(contractInput()),
        );

        for (const operation of [
            () => replayEvents([opened]),
            () => verifyEventChain([opened]),
        ]) {
            expect(operation).toThrow(DomainVersionRestartRequiredError);
            expect(operation).toThrow(expect.objectContaining({
                code: ERROR_CODES.DOMAIN_VERSION_RESTART_REQUIRED,
                details: expect.objectContaining({
                    compatibility: "legacy_incompatible",
                    actualDomainVersion: 3,
                    contractDomainVersion: null,
                    restartRequired: true,
                }),
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

    it("rejects contract identifiers that cannot be addressed by domain events", () => {
        const invalidIdentifiers = ["constructor", "prototype", "trailing."];
        const contractCases = [
            ["policyVersion", (identifier) => contractInput({ policyVersion: identifier })],
            ["search.workerModels[0]", (identifier) => contractInput({
                workerModels: [identifier],
            })],
            ["statisticalPolicy.metrics[0].key", (identifier) => {
                const input = contractInput();
                input.observableRegistry[0].key = identifier;
                input.statisticalPolicy.metrics[0].key = identifier;
                input.statisticalPolicy.control.tolerances[0].metric = identifier;
                return input;
            }],
        ];

        for (const identifier of invalidIdentifiers) {
            expect(() => normalizeEventIdentifier(identifier, "probeId")).toThrow(
                expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }),
            );
            for (const [field, makeInput] of contractCases) {
                expect(() => createInvestigationContract(makeInput(identifier))).toThrow(
                    expect.objectContaining({
                        code: ERROR_CODES.INVALID_CONTRACT,
                    }),
                );
            }
        }

        const safeIdentifier = "model.v3@provider-a";
        expect(normalizeEventIdentifier(safeIdentifier, "probeId")).toBe(safeIdentifier);
        expect(createInvestigationContract(contractInput({
            workerModels: [safeIdentifier],
        })).workerModels).toEqual([safeIdentifier]);
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
            data: rawValidationData(
                validation,
                validationCommand.command,
                "forged-validation-observation",
            ),
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
        const candidateReceipt = fullHarnessReceipt(
            candidate,
            candidateCommand.command,
            {
                purpose: "candidate",
                observationId: "forged-candidate-observation",
                candidateArtifactHash: hashCanonical({
                    forged: "candidate-artifact",
                }),
            },
        );
        const candidateObserved = constructHarnessObservedEvent(candidate.aggregate, {
            commandId: candidateCommand.commandId,
            observationId: "forged-candidate-observation",
            purpose: "candidate",
            receipt: candidateReceipt,
            data: bindRawDataToReceipt(
                rawCandidateData(
                    candidate,
                    candidateCommand.command,
                    "forged-candidate-observation",
                    { pass: false },
                ),
                candidateReceipt,
            ),
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
            searchPolicy({
                operatorWeights: { diversification: 0, adversarial: 1, restart: 0 },
            }),
            searchPolicy({ archiveCaps: { accepted: 100000 } }),
            searchPolicy({ promptCaps: { promptContextRefs: 100000 } }),
            searchPolicy({ promptCaps: { parentEvidenceIds: 3, promptContextRefs: 2 } }),
            { ...searchPolicy(), unexpected: true },
        ]) {
            expect(() => createInvestigationContract(contractInput({
                searchPolicy: invalidPolicy,
            }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
        }
    });

    it("rejects impractical search, metric, and predicate contracts", () => {
        expect(() => createInvestigationContract(contractInput({
            candidatesPerRound: 8,
            maxRounds: 100000,
        }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
        expect(() => createInvestigationContract(contractInput({
            metrics: Array.from(
                { length: CONTRACT_LIMITS.metrics + 1 },
                (_unused, index) => ({
                    key: `metric-${index}`,
                    direction: "max",
                }),
            ),
        }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
        expect(() => createInvestigationContract(contractInput({
            acceptancePredicate: {
                kind: "all",
                predicates: Array.from(
                    { length: CONTRACT_LIMITS.acceptancePredicateChildren + 1 },
                    () => ({ kind: "harness_pass" }),
                ),
            },
        }))).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_ACCEPTANCE_PREDICATE }));
    });

    it("requires immutable manifests exactly for finite and bounded topologies", () => {
        for (const hypothesisTopology of ["finite_enumerable", "bounded_parameterized"]) {
            const missing = contractInput({
                hypothesisTopology,
            });
            delete missing.enumerandManifest;
            expect(() => createInvestigationContract(missing))
                .toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
            expect(() => createInvestigationContract(contractInput({
                hypothesisTopology,
            }))).not.toThrow();
        }
        for (const hypothesisTopology of ["open_generative", "certified_impossibility"]) {
            const legacy = contractInput({ hypothesisTopology });
            legacy.boundedCandidateIds = ["candidate-a"];
            expect(() => createInvestigationContract(legacy))
                .toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
        }
    });

    it("derives accepted, rejected, inconclusive, and invalid outcomes from claim states", () => {
        const context = validateInvestigation(openInvestigation({
            acceptancePredicate: { kind: "harness_pass" },
            metrics: [{ key: "score", direction: "max", epsilon: 0 }],
            observableRegistry: [{
                key: "score",
                kind: "numeric",
                minimum: 0,
                maximum: 1,
            }],
            statisticalPolicy: fakeStatisticalPolicy({
                searchSlots: 4,
                maxBlocks: 64,
            }),
        }));
        const accepted = commitCandidate(context, {
            label: "accepted",
            data: { pass: true, metrics: { score: 1 } },
            blockCount: 64,
        }).evidence;
        const inconclusive = commitCandidate(context, {
            label: "inconclusive",
            blockCount: 64,
            dataFor: (command, observationId) => {
                const raw = structuredClone(rawCandidateData(
                    context,
                    command,
                    observationId,
                    { pass: true, metrics: { score: 1 } },
                    64,
                ));
                for (const block of raw.series[0].completeBlocks) {
                    block.observations.find((item) =>
                        item.armId === "candidate").parsed.pass =
                            block.blockIndex % 2 === 0;
                }
                return raw;
            },
        }).evidence;
        const rejected = commitCandidate(context, {
            label: "rejected",
            data: { pass: false, metrics: { score: 0 } },
            blockCount: 64,
        }).evidence;
        const invalid = commitCandidate(context, {
            label: "invalid",
            data: { pass: true, metrics: { score: 2 } },
        }).evidence;

        expect(accepted).toMatchObject({
            rankable: false,
            outcomeClass: "accepted",
            metrics: {},
        });
        expect(inconclusive).toMatchObject({
            rankable: false,
            outcomeClass: "inconclusive",
            acceptanceSatisfied: false,
        });
        expect(rejected).toMatchObject({
            rankable: false,
            outcomeClass: "rejected",
            metrics: {},
        });
        expect(invalid).toMatchObject({
            rankable: false,
            outcomeClass: "invalid_metrics",
            metrics: {},
            acceptanceSatisfied: false,
        });
    });

    it("uses the contracted metric claim when parsed pass disagrees", () => {
        const context = validateInvestigation(openInvestigation());
        const candidate = commitCandidate(context, {
            label: "pass-disagrees",
            data: { pass: false, metrics: { score: 50 } },
        }).evidence;
        expect(candidate).toMatchObject({
            acceptanceSatisfied: true,
            outcomeClass: "accepted",
            statisticalEvaluation: {
                requiredState: "SUPPORTED",
            },
        });
    });

    it("keeps positive calibration unresolved until its frozen minimum blocks", () => {
        const context = openInvestigation({
            statisticalPolicy: kernelStatisticalPolicy({
                minBlocks: 2,
                maxBlocks: 2,
                searchSlots: 4,
            }),
        });
        const first = commitValidationAttempt(context, { label: "first" });
        expect(first.evidence.validationSatisfied).toBe(false);
        expect(first.evidence.validationEvaluation.evaluations
            .filter((item) => item.caseId === "known-good")
            .every((item) => item.actualState === "UNRESOLVED")).toBe(true);
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "run_validation",
                attemptIndex: 1,
            },
        });

        const second = commitValidationAttempt(context, { label: "second" });
        expect(second.evidence.validationSatisfied).toBe(true);
        append(context, constructKernelDecisionEvent(context.aggregate));
        expect(context.aggregate.validation.currentEvidenceId)
            .toBe(second.evidence.evidenceId);
    });

    it("requires negative calibration to be REFUTED rather than merely non-supporting", () => {
        const wrong = openInvestigation({
            statisticalPolicy: kernelStatisticalPolicy({
                maxBlocks: 1,
                searchSlots: 4,
            }),
        });
        const wrongAttempt = commitValidationAttempt(wrong, {
            label: "wrong-negative",
            dataFor: (command, observationId) => rawValidationData(
                wrong,
                command,
                observationId,
                {
                    passFor: ({ expectedPass }) => expectedPass ? true : true,
                },
            ),
        });
        const wrongNegative = wrongAttempt.evidence.validationEvaluation.evaluations
            .find((item) => item.caseId === "known-bad");
        expect(wrongNegative).toMatchObject({
            expectedState: "REFUTED",
            actualState: "SUPPORTED",
            satisfied: false,
        });

        const correct = openInvestigation();
        const correctAttempt = commitValidationAttempt(correct, {
            label: "correct-negative",
        });
        expect(correctAttempt.evidence.validationEvaluation.evaluations
            .filter((item) => item.caseId === "known-bad")
            .every((item) =>
                item.actualState === "REFUTED" && item.satisfied)).toBe(true);
    });

    it("rejects validation role mismatches before evidence admission", () => {
        const context = openInvestigation();
        const reserved = reserveAndDispatch(context);
        const observationId = "validation-role-mismatch";
        const data = structuredClone(rawValidationData(
            context,
            reserved.command,
            observationId,
        ));
        data.series[0].role = data.series[0].role === "search"
            ? "calibration"
            : "search";
        expect(() => constructHarnessObservedEvent(context.aggregate, {
            commandId: reserved.commandId,
            observationId,
            purpose: "validation",
            receipt: fullHarnessReceipt(context, reserved.command, {
                purpose: "validation",
                observationId,
            }),
            data,
        })).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
    });

    it("routes out-of-bounds calibration through missingness and never validates it", () => {
        const context = openInvestigation({
            statisticalPolicy: kernelStatisticalPolicy({
                maxBlocks: 1,
                searchSlots: 4,
            }),
        });
        const attempt = commitValidationAttempt(context, {
            label: "out-of-bounds",
            dataFor: (command, observationId) => rawValidationData(
                context,
                command,
                observationId,
                { metricsFor: () => ({ score: 101 }) },
            ),
        });
        expect(attempt.evidence.validationSatisfied).toBe(false);
        expect(attempt.evidence.validationEvaluation.evaluations.every(
            (item) => item.actualState === "INVALID",
        )).toBe(true);
    });

    it("bounds failed calibration retries with a durable VALIDATION_INCONCLUSIVE", () => {
        const context = openInvestigation({
            statisticalPolicy: kernelStatisticalPolicy({
                maxBlocks: 2,
                searchSlots: 4,
            }),
        });
        for (const label of ["one", "two"]) {
            commitValidationAttempt(context, {
                label: `retry-${label}`,
                dataFor: (command, observationId) => rawValidationData(
                    context,
                    command,
                    observationId,
                    {
                        passFor: ({ expectedPass }) => expectedPass ? true : true,
                    },
                ),
            });
        }
        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.VALIDATION_INCONCLUSIVE,
            validationAttemptCount: 2,
            maxValidationAttempts: 2,
        });
        append(context, constructKernelDecisionEvent(context.aggregate));
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.VALIDATION_INCONCLUSIVE,
            recorded: true,
            event: null,
        });
        expect(replayEvents(context.history)).toEqual(context.aggregate);
    });

    it("does not accept a single lucky harness-pass replicate", () => {
        const context = validateInvestigation(openInvestigation({
            acceptancePredicate: { kind: "harness_pass" },
        }));
        const candidate = commitCandidate(context, {
            label: "single-lucky-run",
            data: { pass: true, metrics: { score: 100 } },
        }).evidence;
        expect(candidate).toMatchObject({
            acceptanceSatisfied: false,
            outcomeClass: "inconclusive",
            statisticalEvaluation: {
                requiredState: "UNRESOLVED",
                blockCount: 1,
            },
        });
    });

    it("accepts a statistically supported effect only as provisional evidence", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 1,
            observableRegistry: [{
                key: "score",
                kind: "numeric",
                minimum: 0,
                maximum: 1,
            }],
            acceptancePredicate: {
                kind: "metric_compare",
                metric: "score",
                operator: ">=",
                value: 0.8,
            },
            statisticalPolicy: fakeStatisticalPolicy({
                searchSlots: 1,
                maxBlocks: 256,
            }),
        }));
        const candidate = commitCandidate(context, {
            label: "supported-effect",
            data: { pass: false, metrics: { score: 1 } },
            blockCount: 256,
        }).evidence;
        expect(candidate).toMatchObject({
            acceptanceSatisfied: true,
            outcomeClass: "accepted",
            statisticalEvaluation: {
                requiredState: "SUPPORTED",
            },
        });
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "DECISION",
            decision: "SCIENTIFIC_CONFIRMATION_FROZEN",
            event: {
                type: EVENT_TYPES.SCIENTIFIC_CONFIRMATION_FROZEN,
                payload: {
                    discoveryClosure: {
                        candidateIds: [candidate.candidateId],
                        evidenceIds: [candidate.evidenceId],
                    },
                },
            },
        });
    });

    it("treats control drift as missing evidence that cannot support a candidate", () => {
        const context = openInvestigation({
            maxRounds: 1,
            statisticalPolicy: kernelStatisticalPolicy({
                minBlocks: 2,
                maxBlocks: 2,
                searchSlots: 1,
            }),
        });
        commitValidationAttempt(context, { label: "drift-calibration-one" });
        const validation = commitValidationAttempt(context, {
            label: "drift-calibration-two",
        });
        expect(validation.evidence.validationSatisfied).toBe(true);
        append(context, constructKernelDecisionEvent(context.aggregate));

        const candidate = commitCandidate(context, {
            label: "control-drift",
            blockCount: 2,
            dataFor: (command, observationId) => {
                const data = structuredClone(rawCandidateData(
                    context,
                    command,
                    observationId,
                    { pass: true, metrics: { score: 100 } },
                    2,
                ));
                const driftedControl = data.series[0].completeBlocks[1]
                    .observations.find((item) => item.armId === "control");
                driftedControl.parsed.metrics.score = 1;
                return data;
            },
        }).evidence;
        expect(candidate).toMatchObject({
            acceptanceSatisfied: false,
            outcomeClass: "invalid_metrics",
            statisticalEvaluation: {
                requiredState: "INVALID",
                controlTolerance: {
                    driftDetected: true,
                },
            },
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
            data: { pass: false, marker: "context", metrics: { score: 0.1 } },
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
        const badReceipt = fullHarnessReceipt(context, reserved.command, {
            purpose: "candidate",
            observationId: "bad-citation-observation",
            candidateArtifactHash: hashCanonical({ bad: "artifact" }),
        });
        const badObservation = constructHarnessObservedEvent(context.aggregate, {
            commandId: reserved.commandId,
            observationId: "bad-citation-observation",
            purpose: "candidate",
            annotations: {
                citedEvidenceIds: ["evidence-not-in-prompt"],
            },
            receipt: badReceipt,
            data: bindRawDataToReceipt(
                rawCandidateData(
                    context,
                    reserved.command,
                    "bad-citation-observation",
                    { pass: false },
                ),
                badReceipt,
            ),
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

    it("carries a supported practical tie as a cohort without selecting an id", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 2,
            metrics: [{
                key: "score",
                direction: "max",
                epsilon: 100,
            }],
            statisticalPolicy: kernelStatisticalPolicy({
                searchSlots: 2,
                maxConfirmations: 2,
                practicalEquivalenceDelta: 100,
            }),
        }));
        const first = commitCandidate(context, {
            label: "tie-first",
            data: { pass: true, metrics: { score: 95 } },
        });
        const second = commitCandidate(context, {
            label: "tie-second",
            data: { pass: true, metrics: { score: 95 } },
        });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "DECISION",
            decision: "SCIENTIFIC_CONFIRMATION_FROZEN",
            event: {
                type: EVENT_TYPES.SCIENTIFIC_CONFIRMATION_FROZEN,
                payload: {
                    discoveryClosure: {
                        cohortStatus: "TIE_COHORT",
                        candidateIds: [
                            first.evidence.candidateId,
                            second.evidence.candidateId,
                        ],
                        evidenceIds: [
                            first.evidence.evidenceId,
                            second.evidence.evidenceId,
                        ],
                    },
                    members: [
                        {
                            candidateId: first.evidence.candidateId,
                        },
                        {
                            candidateId: second.evidence.candidateId,
                        },
                    ],
                },
            },
        });
        expect(recommendation).not.toHaveProperty("candidateId");
        expect(context.aggregate.scientificReplay.candidateCohort)
            .toMatchObject({
                status: "TIE_COHORT",
                provisionalWinner: null,
            });
    });

    it("forbids the v3 stopOnFirstAccept policy field", () => {
        expect(() => openInvestigation({
            searchPolicy: searchPolicy({ stopOnFirstAccept: true }),
        })).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_CONTRACT }));
    });

    it("does not turn point-estimate ordering into a winner at round exhaustion", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 3,
            metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        }));
        const first = commitCandidate(context, {
            label: "score-10",
            data: { pass: true, metrics: { score: 10 } },
        });
        commitCandidate(context, {
            label: "score-20",
            data: { pass: true, metrics: { score: 20 } },
        });
        commitCandidate(context, {
            label: "score-15",
            data: { pass: true, metrics: { score: 15 } },
        });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.SCIENTIFIC_COHORT_UNRESOLVED,
            cohortStatus: "UNRESOLVED",
            readiness: {
                cohortStatus: "UNRESOLVED",
            },
        });
        expect(recommendation).not.toHaveProperty("candidateId");
        expect(recommendation.evidenceIds)
            .toContain(first.evidence.evidenceId);
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
        const repeatedArtifact = hashCanonical({ artifact: "plateau-repeat" });
        commitCandidate(context, {
            label: "plateau-1",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: repeatedArtifact,
        });
        commitCandidate(context, {
            label: "plateau-2",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: repeatedArtifact,
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
            candidateArtifactHash: repeatedArtifact,
        });

        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "search_candidate",
                round: 4,
            },
        });
    });

    it("does not treat metric-less model annotation relabeling as novelty", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 4,
            searchPolicy: searchPolicy({
                plateauWindow: 1,
                minRoundsBeforePlateau: 1,
                mandatoryEscapeRounds: 1,
            }),
        }));
        const repeatedArtifact = hashCanonical({ artifact: "annotation-repeat" });
        commitCandidate(context, {
            label: "novelty-1",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: repeatedArtifact,
        });
        commitCandidate(context, {
            label: "novelty-2",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: repeatedArtifact,
        });
        commitCandidate(context, {
            label: "novelty-escape",
            data: { pass: true, marker: "same" },
            annotations: { mechanism: "new-mechanism" },
            candidateArtifactHash: repeatedArtifact,
        });

        expect(detectPlateau(context.aggregate)).toMatchObject({
            plateauDetected: true,
            plateauComplete: true,
            phase: "plateau",
        });
    });

    it("resets a plateau for a new immutable candidate artifact", () => {
        const context = validateInvestigation(openInvestigation({
            maxRounds: 4,
            searchPolicy: searchPolicy({
                plateauWindow: 1,
                minRoundsBeforePlateau: 1,
                mandatoryEscapeRounds: 1,
            }),
        }));
        const repeatedArtifact = hashCanonical({ artifact: "same-content" });
        commitCandidate(context, {
            label: "content-1",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: repeatedArtifact,
        });
        commitCandidate(context, {
            label: "content-2",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: repeatedArtifact,
        });
        expect(detectPlateau(context.aggregate).phase)
            .toBe("mandatory_escape");
        commitCandidate(context, {
            label: "content-3",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: hashCanonical({
                artifact: "changed-content",
            }),
        });
        expect(detectPlateau(context.aggregate)).toMatchObject({
            plateauDetected: false,
            phase: "normal",
        });
    });

    it("never declares an open-generative target unreachable", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "open_generative",
            maxRounds: 1,
            acceptancePredicate: { kind: "harness_pass" },
        }));
        commitCandidate(context, { label: "open-reject", data: { pass: false } });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
        });
        expect(recommendation.event.type).toBe(EVENT_TYPES.NON_RESULT_RECORDED);
    });

    it("treats search-budget exhaustion without proof as inconclusive", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "budget-no-proof",
            data: { pass: false },
        });
        const exhausted = structuredClone(context.aggregate);
        exhausted.contract.declaredLimits.maxCommands =
            exhausted.commandOrder.length;

        expect(decideNext(exhausted)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
        });
        expect(decideNext(exhausted).decision)
            .not.toBe("TARGET_UNREACHABLE");
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
            requestVersion: "crucible-impossibility-request-v2",
            certificateVersion: IMPOSSIBILITY_CERTIFICATE_VERSION,
        });
        const search = reserveAndDispatch(context);
        expect(search.command.kind).toBe("search_candidate");
        expect(() => constructHarnessObservedEvent(
            context.aggregate,
            impossibilityObservationInput(context, {
                ...search.command,
                commandId: search.commandId,
            }, "legacy"),
        )).toThrow(
            expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }),
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
            candidateArtifactHash: enumerandArtifactMeasurementHash(
                search.command.enumerand.artifactSnapshotHash,
            ),
            blockCount: 32,
        });
        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "verify_impossibility",
                attemptOrdinal: 1,
                certificateVersion: IMPOSSIBILITY_CERTIFICATE_VERSION,
                request: {
                    kind: "CrucibleImpossibilityVerifierRequest",
                    signedExperiment: {
                        contractHash: context.aggregate.contractHash,
                    },
                    harnessSuiteIdentity:
                        context.contract.harnessSuiteIdentity,
                    enumerands: {
                        merkleRoot:
                            context.contract.enumerandManifest.merkleRoot,
                        count: 1,
                    },
                    evidence: {
                        calibrationComplete: true,
                        controlComplete: true,
                        searchComplete: true,
                        coverageClosure: {
                            complete: true,
                            manifest: {
                                count: 1,
                            },
                            enumerands: [{
                                ordinal: 0,
                                status: "REFUTED",
                            }],
                        },
                        coverageClosureRoot: expect.stringMatching(
                            /^sha256:crucible-unreachable-coverage-closure-v1:/u,
                        ),
                    },
                    objectManifest: {
                        pack: {
                            path: "object-pack.json",
                            format:
                                "crucible-base64-object-pack-v1",
                        },
                        root: expect.stringMatching(
                            /^sha256:crucible-impossibility-verifier-object-manifest-v1:/u,
                        ),
                        entries: expect.arrayContaining([
                            expect.objectContaining({
                                kind: "cas_object",
                                objectId: expect.stringMatching(
                                    /^sha256:[a-f0-9]{64}$/u,
                                ),
                            }),
                            expect.objectContaining({
                                path: "proof-artifact.json",
                                kind: "generated",
                            }),
                        ]),
                    },
                    reevaluation: {
                        enumerands: [
                            expect.objectContaining({
                                ordinal: 0,
                                inputRoot: expect.stringMatching(
                                    /^sha256:crucible-impossibility-verifier-input-v1:/u,
                                ),
                                receiptBindings: expect.any(Array),
                                receiptBindingsRoot:
                                    expect.stringMatching(/^sha256:/u),
                            }),
                        ],
                    },
                    proofArtifact: {
                        artifactHash: expect.stringMatching(
                            /^sha256:crucible-impossibility-proof-artifact-v1:/u,
                        ),
                    },
                },
                proposedCertificateArtifactHash:
                    expect.stringMatching(
                        /^sha256:crucible-impossibility-certificate-proposal-v1:/u,
                    ),
                proofArtifactHash: expect.stringMatching(
                    /^sha256:crucible-impossibility-proof-artifact-v1:/u,
                ),
                measurementBinding: {
                    role: "impossibility_verifier",
                    blockIndex: 0,
                    subjectId: "impossibility-1",
                },
            },
        });
        expect(context.aggregate.evidence["candidate-evidence-certified-reject"].unreachableBasis)
            .toBeNull();
        expect(recommendation.command.proofArtifactHash)
            .not.toBe(
                recommendation.command
                    .proposedCertificateArtifactHash,
            );
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
            kind: "v4_unreachable",
            topology: "certified_impossibility",
            certificateVerdict: "target_unreachable",
        });
        expect(assessTargetUnreachableReadiness(
            context.aggregate,
            evidence,
        )).toMatchObject({
            ready: true,
            independentlyDerivedVerifierFacts: true,
        });
        const echoedFacts = structuredClone(context.aggregate);
        inheritAggregateImpossibilityExecutions(
            context.aggregate,
            echoedFacts,
        );
        expect(assessTargetUnreachableReadiness(
            echoedFacts,
            echoedFacts.evidence[evidence.evidenceId],
        )).toMatchObject({
            ready: true,
            independentVerifierRoleBound: true,
            independentlyDerivedVerifierFacts: true,
            verifierClosureBound: true,
        });
        const originalFactsRoot = echoedFacts.evidence[evidence.evidenceId]
            .unreachableBasis.verifierFactsRoot;
        echoedFacts.evidence[evidence.evidenceId]
            .unreachableBasis.verifierFactsRoot =
                verifier.command.proposedCertificateArtifactHash;
        expect(echoedFacts.evidence[evidence.evidenceId]
            .unreachableBasis.verifierFactsRoot).not.toBe(originalFactsRoot);
        const tamperedReadiness = assessTargetUnreachableReadiness(
            echoedFacts,
            echoedFacts.evidence[evidence.evidenceId],
        );
        expect(tamperedReadiness).toMatchObject({
            ready: false,
            independentVerifierRoleBound: true,
            independentlyDerivedVerifierFacts: true,
            verifierClosureBound: false,
            independentVerifierSupported: false,
            missing: expect.arrayContaining([
                "independent_impossibility_verifier_evidence",
            ]),
        });
        expect(tamperedReadiness.missing).not.toContain(
            "independently_derived_impossibility_verifier_facts",
        );

        const terminal = constructKernelDecisionEvent(context.aggregate);
        expect(terminal).toMatchObject({
            type: EVENT_TYPES.TARGET_UNREACHABLE,
            payload: {
                decision: "TARGET_UNREACHABLE",
                basis: {
                    kind: "v4_unreachable",
                    certificateVerdict: "target_unreachable",
                    coverageClosureRoot: expect.stringMatching(
                        /^sha256:crucible-unreachable-coverage-closure-v1:/u,
                    ),
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
                    receipts: {
                        count: expect.any(Number),
                        evidenceCount: 3,
                    },
                    unreachableCoverage: {
                        manifest: { count: 1 },
                        closureRoot: expect.stringMatching(
                            /^sha256:crucible-unreachable-coverage-closure-v1:/u,
                        ),
                    },
                },
            },
        });
        expect(terminal.payload.evidenceClosure.closureRoot).toMatch(
            /^sha256:crucible-terminal-evidence-closure-v2:[a-f0-9]{64}$/,
        );
        append(context, terminal);
        expect(replayEvents(context.history)).toEqual(context.aggregate);
    });

    it("requires every acceptance claim to be positively REFUTED", () => {
        const manifest = fakeEnumerandManifest(
            "certified_impossibility",
            ["mixed-claim-state"],
        );
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
            enumerandManifest: manifest,
            observableRegistry: [{
                key: "score",
                kind: "numeric",
                minimum: 0,
                maximum: 1,
            }],
            statisticalPolicy: fakeStatisticalPolicy({
                topology: "certified_impossibility",
                searchSlots: 1,
                manifest,
                minBlocks: 1,
                maxBlocks: 64,
                metrics: [{
                    key: "score",
                    minimum: 0,
                    maximum: 1,
                    estimand: "mean score difference versus control",
                    unit: "score",
                    direction: "max",
                    acceptanceThreshold: 0.01,
                    practicalEquivalenceDelta: 0.001,
                    family: "primary",
                }],
            }),
            acceptancePredicate: {
                kind: "all",
                predicates: [
                    { kind: "harness_pass" },
                    {
                        kind: "metric_compare",
                        metric: "score",
                        operator: ">=",
                        value: 0.01,
                    },
                ],
            },
        }));
        const candidate = commitCandidate(context, {
            label: "mixed-claim-state",
            data: { pass: false, metrics: { score: 1 } },
            blockCount: 64,
        });
        expect(candidate.evidence.outcomeClass).toBe("rejected");
        expect(candidate.evidence.statisticalEvaluation.statistics.claims
            .map((claim) => claim.state)).toEqual(
            expect.arrayContaining(["REFUTED", "SUPPORTED"]),
        );

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE,
            checkerStatus: "INCONCLUSIVE",
        });
        expect(recommendation.missing.some((item) =>
            item.includes(":claim:") && item.endsWith(":supported"))).toBe(true);
        expect(recommendation.command?.kind).not.toBe("verify_impossibility");
    });

    it("does not count duplicate bounded artifacts as two enumerands", () => {
        const manifest = fakeEnumerandManifest(
            "bounded_parameterized",
            ["tuple-a", "tuple-b"],
        );
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 2,
            maxRounds: 1,
            enumerandManifest: manifest,
            observableRegistry: [{
                key: "score",
                kind: "numeric",
                minimum: 0,
                maximum: 1,
            }],
            statisticalPolicy: fakeStatisticalPolicy({
                topology: "certified_impossibility",
                searchSlots: 2,
                manifest,
                minBlocks: 1,
                maxBlocks: 32,
            }),
            acceptancePredicate: { kind: "harness_pass" },
        }));
        const duplicateArtifact = hashCanonical({
            artifact: "same-bounded-output",
        });
        commitCandidate(context, {
            label: "tuple-a",
            data: { pass: false, metrics: { score: 0 } },
            candidateArtifactHash: duplicateArtifact,
            blockCount: 32,
        });
        commitCandidate(context, {
            label: "tuple-b",
            data: { pass: false, metrics: { score: 0 } },
            candidateArtifactHash: duplicateArtifact,
            blockCount: 32,
        });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE,
        });
        expect(recommendation.missing).toEqual(expect.arrayContaining([
            "enumerand:0:duplicate_artifact",
            "enumerand:1:duplicate_artifact",
        ]));
    });

    it("keeps a missing enumerand slot open and verifier-ineligible", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 2,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "only-first-enumerand",
            data: { pass: false },
        });

        const coverage = deriveUnreachableCoverageClosure(context.aggregate);
        expect(coverage).toMatchObject({
            eligible: false,
            closure: {
                complete: false,
                enumerands: [
                    { ordinal: 0, status: "REFUTED" },
                    { ordinal: 1, status: "MISSING" },
                ],
            },
        });
        expect(coverage.missing).toContain("enumerand:1:missing");
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "search_candidate",
                slotIndex: 1,
            },
        });
    });

    it("keeps an unresolved enumerand scientifically inconclusive", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
            acceptancePredicate: {
                kind: "metric_compare",
                metric: "score",
                operator: ">=",
                value: 50,
            },
        }));
        const candidate = commitCandidate(context, {
            label: "threshold-boundary",
            data: { pass: false, metrics: { score: 50 } },
        });
        expect(candidate.evidence.outcomeClass).toBe("inconclusive");
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE,
            missing: expect.arrayContaining([
                expect.stringMatching(/:claim:.*:unresolved$/u),
            ]),
        });
    });

    it("rejects manifest relabeling and evidence re-identification", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        const candidate = commitCandidate(context, {
            label: "identity-bound",
            data: { pass: false },
        });
        expect(deriveUnreachableCoverageClosure(context.aggregate).eligible)
            .toBe(true);

        const relabeled = structuredClone(context.aggregate);
        relabeled.contract.enumerandManifest.entries[0].id = "relabeled";
        expect(deriveUnreachableCoverageClosure(relabeled)).toMatchObject({
            eligible: false,
            missing: expect.arrayContaining([
                "finite_immutable_enumerand_manifest",
            ]),
        });

        const reidentified = structuredClone(context.aggregate);
        reidentified.evidence[candidate.evidence.evidenceId].candidateId =
            "reidentified";
        expect(deriveUnreachableCoverageClosure(reidentified)).toMatchObject({
            eligible: false,
            missing: expect.arrayContaining(["enumerand:0:binding"]),
        });
    });

    it("derives the same closure from replay and candidate arrival projections", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 2,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "arrival-a",
            data: { pass: false },
        });
        commitCandidate(context, {
            label: "arrival-b",
            data: { pass: false },
        });
        const progress = searchProgress(context.aggregate);
        const validation =
            context.aggregate.evidence[
                context.aggregate.validation.currentEvidenceId
            ];
        const forward = createImpossibilityVerificationPackage(
            context.aggregate,
            { attemptOrdinal: 1, progress, validation },
        );
        const reversed = createImpossibilityVerificationPackage(
            context.aggregate,
            {
                attemptOrdinal: 1,
                progress: {
                    ...progress,
                    candidates: [...progress.candidates].reverse(),
                },
                validation,
            },
        );
        const replayed = replayEvents(context.history);
        const replayPackage = createImpossibilityVerificationPackage(
            replayed,
            {
                attemptOrdinal: 1,
                progress: searchProgress(replayed),
                validation:
                    replayed.evidence[replayed.validation.currentEvidenceId],
            },
        );
        expect(forward.eligible).toBe(true);
        expect(reversed.requestHash).toBe(forward.requestHash);
        expect(replayPackage.requestHash).toBe(forward.requestHash);
        expect(replayPackage.request.evidence.coverageClosureRoot)
            .toBe(forward.request.evidence.coverageClosureRoot);
    });

    it("persists an interrupted checker observation and completes from replay", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "checker-crash-candidate",
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        const input = impossibilityObservationInput(context, {
            ...verifier.command,
            commandId: verifier.commandId,
        }, "checker-crash");
        append(
            context,
            constructVerifiedImpossibilityObservedEvent(context, input),
        );

        context.aggregate = replayEvents(context.history);
        const recovery = decideNext(context.aggregate);
        expect(recovery).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "commit_evidence",
                observationId: input.observationId,
            },
        });
        append(
            context,
            constructEvidenceCommittedEvent(context.aggregate, {
                evidenceId: recovery.command.evidenceId,
                observationId: recovery.command.observationId,
            }),
        );
        const terminal = constructKernelDecisionEvent(context.aggregate);
        expect(terminal).toMatchObject({
            type: EVENT_TYPES.TARGET_UNREACHABLE,
            payload: {
                basis: {
                    kind: "v4_unreachable",
                    checkerStatus: "VERIFIED",
                },
            },
        });
    });

    it("does not run the verifier when frozen search evidence is incomplete", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "incomplete-evidence",
            data: { pass: false, metrics: { score: 1000 } },
        });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE,
            checkerStatus: "INCONCLUSIVE",
            certificateVerdict: "inconclusive",
        });
        expect(recommendation.missing).toEqual(expect.arrayContaining([
            "search_evidence",
            expect.stringMatching(/:claim:.*:invalid$/u),
        ]));
        expect(recommendation.command?.kind).not.toBe("verify_impossibility");
    });

    it("supports suite-declared formal certificate validation", () => {
        const suite = fakeHarnessSuiteV4({ includeVerifier: true });
        suite.roles.impossibility_verifier.dependencies.push({
            role: IMPOSSIBILITY_PROOF_CHECKER_ROLE,
            sha256: hashCanonical({
                checker: "fixture-formal-certificate-v1",
            }),
            kind: "application",
        });
        suite.roles.impossibility_verifier.verificationPolicy = {
            mode: "certificate_validation",
            certificateFormat: {
                version: "fixture-formal-certificate-v1",
                schemaHash: hashCanonical({
                    schema: "fixture-formal-certificate-v1",
                }),
            },
        };
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
            harnessSuite: suite,
        }));
        commitCandidate(context, {
            label: "formal-certificate-candidate",
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        expect(verifier.command.request.verifier.verificationPolicy)
            .toEqual(suite.roles.impossibility_verifier.verificationPolicy);
        const evidence = commitImpossibility(
            context,
            verifier,
            "formal-certificate",
        );
        expect(evidence.unreachableBasis).toMatchObject({
            kind: "v4_unreachable",
            verificationMode: "certificate_validation",
            checkerStatus: "VERIFIED",
        });
        expect(assessTargetUnreachableReadiness(
            context.aggregate,
            evidence,
        )).toMatchObject({
            ready: true,
            independentlyDerivedVerifierFacts: true,
        });
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
        });
    });

    it("retains and verifies an accepted candidate without optional ranking metrics", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
            acceptancePredicate: { kind: "harness_pass" },
            observableRegistry: [{
                key: "score",
                kind: "numeric",
                minimum: 0,
                maximum: 1,
            }],
            statisticalPolicy: fakeStatisticalPolicy({
                topology: "certified_impossibility",
                searchSlots: 1,
                maxBlocks: 64,
            }),
            metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        }));
        const candidate = commitCandidate(context, {
            label: "accepted-with-invalid-metrics",
            data: { pass: true, metrics: {} },
            blockCount: 64,
        });
        expect(candidate.evidence.acceptanceSatisfied).toBe(true);
        expect(candidate.evidence.rankable).toBe(false);
        expect(candidate.evidence.outcomeClass).toBe("accepted");
        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
            scientificState: {
                status: "NO_ELIGIBLE_CANDIDATES",
                resolved: false,
            },
        });
        expect(recommendation).not.toHaveProperty("candidateId");
        expect(recommendation.command?.kind).not.toBe("verify_impossibility");
    });

    it.each([
        ["not_proven", { pass: false, searchSpaceExhausted: true }],
        ["inconclusive", { checkerStatus: "INCONCLUSIVE" }],
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
        const observed = constructVerifiedImpossibilityObservedEvent(
            context,
            input,
        );

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
        ])).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
    });

    it("rejects a verifier certificate that tampers with the exact coverage closure", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "coverage-tamper-candidate",
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        const input = impossibilityObservationInput(context, {
            ...verifier.command,
            commandId: verifier.commandId,
        }, "coverage-tamper");
        const tamperedRoot = hashCanonical({
            tampered: true,
        }, "sha256:crucible-unreachable-coverage-closure-v1");
        input.data.checkerResult.coverageClosureRoot = tamperedRoot;
        input.data.checkerResult.certificate.coverageClosureRoot =
            tamperedRoot;

        expect(() => constructVerifiedImpossibilityObservedEvent(context, input))
            .toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_EVENT }));
    });

    it("rejects an impossibility checker that echoes the request or proposal as refutation evidence", () => {
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "certified_impossibility",
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        commitCandidate(context, {
            label: "echo-checker-candidate",
            data: { pass: false },
        });
        const verifier = reserveAndDispatch(context);
        const input = impossibilityObservationInput(context, {
            ...verifier.command,
            commandId: verifier.commandId,
        }, "echo-checker");
        const result = input.data.checkerResult.enumerandResults[0];
        result.evidenceRoot = verifier.command.requestHash;
        result.refutationReceiptHash =
            verifier.command.proposedCertificateArtifactHash;
        input.data.checkerResult.enumerandResultsRoot =
            impossibilityVerifierEnumerandResultsRoot(
                input.data.checkerResult.enumerandResults,
            );
        input.data.checkerResult.independentFactsRoot =
            impossibilityVerifierFactsRoot({
                mode: input.data.checkerResult.mode,
                enumerandResults:
                    input.data.checkerResult.enumerandResults,
                proofArtifactHash:
                    input.data.checkerResult.proofArtifactHash,
                proofCheckerIdentity: null,
                proofValidationReceiptHash: null,
                validatedProofArtifactHash: null,
            });
        Object.assign(input.data.checkerResult.certificate, {
            enumerandResultsRoot:
                input.data.checkerResult.enumerandResultsRoot,
            independentFactsRoot:
                input.data.checkerResult.independentFactsRoot,
        });

        expect(() => constructVerifiedImpossibilityObservedEvent(
            context,
            input,
        )).toThrow(expect.objectContaining({
            code: ERROR_CODES.INVALID_EVENT,
        }));
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
        const originalCoverageRoot =
            verifier.command.request.evidence.coverageClosureRoot;
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
        expect(deriveUnreachableCoverageClosure(context.aggregate).eligible)
            .toBe(false);

        commitCandidate(context, {
            label: "invalidate-certificate-replacement",
            data: { pass: false },
        });
        const replacementCoverage =
            deriveUnreachableCoverageClosure(context.aggregate);
        expect(replacementCoverage.eligible).toBe(true);
        expect(replacementCoverage.closure.invalidationsRoot).toMatch(
            /^sha256:crucible-unreachable-invalidations-v1:/u,
        );
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "verify_impossibility",
                attemptOrdinal: 2,
                request: {
                    evidence: {
                        coverageClosureRoot:
                            replacementCoverage.closure.closureRoot,
                    },
                },
            },
        });
        expect(replacementCoverage.closure.closureRoot)
            .not.toBe(originalCoverageRoot);
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

    it("requires an independent verifier after finite search-space exhaustion", () => {
        const manifest = fakeEnumerandManifest(
            "finite_enumerable",
            ["bounded-a"],
        );
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "finite_enumerable",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
            boundedCandidateIds: ["bounded-a"],
            enumerandManifest: manifest,
            observableRegistry: [{
                key: "score",
                kind: "numeric",
                minimum: 0,
                maximum: 1,
            }],
            statisticalPolicy: fakeStatisticalPolicy({
                topology: "finite_enumerable",
                searchSlots: 1,
                manifest,
                minBlocks: 1,
                maxBlocks: 32,
            }),
            acceptancePredicate: { kind: "harness_pass" },
        }));
        const candidate = commitCandidate(context, {
            label: "bounded",
            data: { pass: false, metrics: { score: 0.1 } },
            blockCount: 32,
        });

        expect(candidate.command).toMatchObject({
            candidateId: "bounded-a",
            boundedCandidateId: "bounded-a",
        });
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.INDEPENDENT_VERIFICATION_REQUIRED,
            basis: { kind: "search_space_exhausted" },
        });
    });

    it("retries invalidated slots and excludes them from completion and bounded exhaustion", () => {
        const manifest = fakeEnumerandManifest(
            "finite_enumerable",
            ["bounded-a"],
        );
        const context = validateInvestigation(openInvestigation({
            hypothesisTopology: "finite_enumerable",
            workerModels: ["model-alpha"],
            candidatesPerRound: 1,
            maxRounds: 1,
            boundedCandidateIds: ["bounded-a"],
            enumerandManifest: manifest,
            observableRegistry: [{
                key: "score",
                kind: "numeric",
                minimum: 0,
                maximum: 1,
            }],
            statisticalPolicy: fakeStatisticalPolicy({
                topology: "finite_enumerable",
                searchSlots: 1,
                manifest,
                minBlocks: 1,
                maxBlocks: 32,
            }),
            acceptancePredicate: { kind: "harness_pass" },
        }));
        const first = commitCandidate(context, {
            label: "bounded-invalidated",
            data: { pass: true, metrics: { score: 0.9 } },
            blockCount: 32,
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
            data: { pass: false, metrics: { score: 0.1 } },
            blockCount: 32,
        });
        expect(replacement.command.replacementOrdinal).toBe(1);
        expect(context.aggregate.evidence[first.evidence.evidenceId].invalidated).toBe(true);
        const terminal = decideNext(context.aggregate);
        expect(terminal).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.INDEPENDENT_VERIFICATION_REQUIRED,
            basis: { kind: "search_space_exhausted" },
            readiness: {
                ready: false,
                independentVerifierSupported: false,
            },
        });
        expect(terminal.event.type).toBe(EVENT_TYPES.NON_RESULT_RECORDED);
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
        const repeatedArtifact = hashCanonical({
            artifact: "replacement-plateau-repeat",
        });
        commitCandidate(context, {
            label: "plateau-active-1",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: repeatedArtifact,
        });
        const second = commitCandidate(context, {
            label: "plateau-active-2",
            data: { pass: true, marker: "same" },
            candidateArtifactHash: repeatedArtifact,
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
