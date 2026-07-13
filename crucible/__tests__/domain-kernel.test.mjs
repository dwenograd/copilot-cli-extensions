import { describe, expect, it } from "vitest";

import {
    DOMAIN_VERSION,
    ERROR_CODES,
    EVENT_TYPES,
    IMPOSSIBILITY_CHECKER_OUTPUT_VERSION,
    NON_RESULT_CODES,
    OBSERVATION_STREAM_HASH_ALGORITHM,
    assessTargetUnreachableReadiness,
    assessVerifiedResultReadiness,
    canonicalJson,
    computeEventHash,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructInvestigationResumedEvent,
    constructKernelDecisionEvent,
    constructModelObservedEvent,
    createEvidenceProvenance,
    createExternalEvent,
    createInitialAggregate,
    createInvestigationContract,
    createInvestigationOpenedEvent,
    createMeasurementProvenance,
    createRawMeasurementSeries,
    createSnapshotProvenance,
    decideNext,
    hashCanonical,
    impossibilityVerifierEnumerandResultsRoot,
    impossibilityVerifierFactsRoot,
    impossibilityVerifierRefutationReceiptHash,
    impossibilityVerifierRefutationRoot,
    normalizeEventIdentifier,
    reduceEvent,
    replayEvents,
    replicationBlockPlan,
    resolveControlEnumerand,
    searchProgress,
    verifyEventChain,
} from "../domain/index.mjs";
import {
    issueVerifiedImpossibilityExecutionCapability,
} from "../domain/private-verifier-execution.mjs";
import {
    createExperimentAuthorityFixture,
    createRuntimeConfigAuthorityFixture,
    createSignedInvestigationAuthority,
} from "./experiment-authority-fixture.mjs";
import {
    fakeEnumerandManifest,
    fakeStatisticalPolicy,
    makeV4ContractInput,
} from "./v4-contract-fixture.mjs";

const AUTHORITY_FIXTURE = createExperimentAuthorityFixture();

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

function digestOf(value) {
    return value.split(":").at(-1);
}

function tagged(label, algorithm = "sha256:crucible-fast-kernel-fixture-v1") {
    return hashCanonical({ label }, algorithm);
}

function objectHash(label) {
    return `sha256:${digestOf(tagged(label))}`;
}

function snapshotHashFor(objectId) {
    return `sha256:crucible-measurement-snapshot-v1:${digestOf(objectId)}`;
}

function artifactRef(label, boundHash = tagged(`${label}-object`)) {
    const safe = label.replace(/[^A-Za-z0-9._-]/gu, "-").slice(0, 48);
    const digest = digestOf(boundHash);
    return {
        artifactId: `artifact-${safe}-${digest.slice(0, 16)}`,
        objectId: `sha256:${digest}`,
    };
}

function fastStatisticalPolicy({
    topology = "open_generative",
    searchSlots = 1,
    manifest = null,
    minBlocks = 1,
    maxBlocks = 1,
    maximum = 100,
    acceptanceThreshold = 0,
    control = null,
} = {}) {
    let resolvedControl = control;
    if (resolvedControl === null && manifest !== null) {
        const binding = resolveControlEnumerand(manifest);
        resolvedControl = binding.kind === "reference"
            ? { kind: "snapshot", identity: binding.referenceHash }
            : { kind: "enumerand", identity: binding.enumerandHash };
    }
    const policy = fakeStatisticalPolicy({
        topology,
        searchSlots,
        manifest,
        minBlocks,
        maxBlocks,
        control: resolvedControl,
        metrics: [{
            key: "score",
            minimum: 0,
            maximum,
            estimand: "mean score difference versus control",
            unit: "score",
            direction: "max",
            acceptanceThreshold,
            practicalEquivalenceDelta: Math.max(maximum / 100, 0.01),
            family: "primary",
        }],
    });
    policy.control.tolerances = [{
        metric: "score",
        absolute: 0,
        relative: 0,
    }];
    return policy;
}

function openInvestigation(overrides = {}) {
    const hypothesisTopology =
        overrides.hypothesisTopology ?? "open_generative";
    const candidatesPerRound = overrides.candidatesPerRound ?? 1;
    const maxRounds = overrides.maxRounds ?? 1;
    const input = {
        objective: "Exercise compact v4 kernel invariants",
        acceptancePredicate:
            hypothesisTopology === "certified_impossibility"
                ? { kind: "harness_pass" }
                : {
                    kind: "metric_compare",
                    metric: "score",
                    operator: ">=",
                    value: 0,
                },
        hypothesisTopology,
        candidatesPerRound,
        maxRounds,
        ...overrides,
    };
    if (overrides.statisticalPolicy === undefined) {
        input.statisticalPolicy = fastStatisticalPolicy({
            topology: hypothesisTopology,
            searchSlots: input.enumerandManifest?.entries?.length
                ?? candidatesPerRound * maxRounds,
            manifest: input.enumerandManifest ?? null,
        });
    }
    if (overrides.observableRegistry === undefined) {
        input.observableRegistry =
            input.statisticalPolicy.metrics.map((metric) => ({
                key: metric.key,
                kind: "numeric",
                minimum: metric.minimum,
                maximum: metric.maximum,
            }));
    }
    const contract = createInvestigationContract(makeV4ContractInput(input));
    const signed = createSignedInvestigationAuthority({
        contract,
        fixture: AUTHORITY_FIXTURE,
    });
    const opened = createInvestigationOpenedEvent(
        contract,
        signed.authority,
        createRuntimeConfigAuthorityFixture(signed.investigationId),
    );
    return {
        contract,
        history: [opened],
        aggregate: reduceEvent(createInitialAggregate(), opened),
    };
}

function append(context, event) {
    const aggregate = reduceEvent(context.aggregate, event);
    context.history.push(event);
    context.aggregate = aggregate;
    return event;
}

function reserveAndDispatch(context, expectedKind = null) {
    const reserved = constructKernelDecisionEvent(context.aggregate);
    append(context, reserved);
    const commandId = reserved.payload.commandId;
    const command = reserved.payload.command;
    if (expectedKind !== null && command.kind !== expectedKind) {
        throw new Error(`expected ${expectedKind}, received ${command.kind}`);
    }
    append(context, createExternalEvent(
        context.aggregate,
        EVENT_TYPES.COMMAND_DISPATCHED,
        { commandId },
    ));
    return { commandId, command };
}

function measurementProvenance(
    context,
    {
        arm,
        observationId,
        role,
        phase,
        snapshotObjectId,
    },
) {
    const roleSpec = context.contract.harnessSuite.roles[role];
    const receiptHash = tagged(
        `${observationId}:${arm.subjectId}:receipt`,
        "sha256:crucible-measurement-receipt-v1",
    );
    const rawStdoutHash = tagged(
        `${observationId}:${arm.subjectId}:stdout`,
        "sha256:crucible-measurement-stream-v1",
    );
    const rawStderrHash = tagged(
        `${observationId}:${arm.subjectId}:stderr`,
        "sha256:crucible-measurement-stream-v1",
    );
    const dependencies = roleSpec.dependencies.map((dependency, index) => ({
        path: `C:\\fixture\\${role}-${index}.bin`,
        role: dependency.role,
        sha256: dependency.sha256,
    }));
    const snapshot = createSnapshotProvenance({
        snapshotHash: snapshotHashFor(snapshotObjectId),
        manifestArtifact: artifactRef(
            `${observationId}-${arm.subjectId}-manifest`,
            snapshotObjectId,
        ),
        objectArtifacts: [],
    });
    return createMeasurementProvenance({
        subjectId: arm.subjectId,
        role,
        phase,
        receiptArtifact: artifactRef(
            `${observationId}-${arm.subjectId}-receipt`,
            receiptHash,
        ),
        receiptHash,
        rawStdoutArtifact: artifactRef(
            `${observationId}-${arm.subjectId}-stdout`,
            rawStdoutHash,
        ),
        rawStdoutHash,
        rawStderrArtifact: artifactRef(
            `${observationId}-${arm.subjectId}-stderr`,
            rawStderrHash,
        ),
        rawStderrHash,
        parserVersion: roleSpec.parser.version,
        allowlistFileHash: tagged(`${role}:allowlist`),
        harnessEntryHash: roleSpec.harnessEntryHash,
        executableHash: roleSpec.executableHash,
        stagedExecutableHash: roleSpec.executableHash,
        dependencyHashes: dependencies,
        stagedDependencyHashes: dependencies,
        argvHash: tagged(`${observationId}:${arm.subjectId}:argv`),
        envHash: tagged(`${observationId}:${arm.subjectId}:env`),
        sandboxPolicy: roleSpec.sandboxIdentity.required
            ? {
                kind: "sandbox",
                sandboxId: "fixture-appcontainer",
                environmentHash:
                    roleSpec.sandboxIdentity.policyDigest
                    ?? tagged(`${role}:sandbox`),
            }
            : {
                kind: "none",
                sandboxId: null,
                environmentHash: null,
            },
        snapshot,
        snapshotExecutionHash: tagged(
            `${observationId}:${arm.subjectId}:snapshot-execution`,
        ),
    });
}

function parsedObservation(raw, role, phase, arm) {
    return {
        pass: raw.pass === true,
        metrics: raw.metrics,
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

function streamRoot(measurements, field) {
    return hashCanonical(
        measurements.map((measurement) => ({
            id: measurement.subjectId,
            hash: measurement[field],
        })),
        OBSERVATION_STREAM_HASH_ALGORITHM,
    );
}

function commitObservation(
    context,
    {
        commandId,
        observationId,
        evidenceId,
        purpose,
        receipt,
        data,
        annotations,
    },
    options = {},
) {
    const observed = constructHarnessObservedEvent(context.aggregate, {
        commandId,
        observationId,
        purpose,
        receipt,
        data,
        ...(annotations === undefined ? {} : { annotations }),
    }, options);
    append(context, observed);
    append(context, constructEvidenceCommittedEvent(context.aggregate, {
        evidenceId,
        observationId,
    }));
    return context.aggregate.evidence[evidenceId];
}

function commitValidation(context, {
    label = String(context.aggregate.validation.attemptEvidenceIds.length),
    passFor = null,
} = {}) {
    const { commandId, command } =
        reserveAndDispatch(context, "run_validation");
    const observationId = `validation-observation-${label}`;
    const expectationById = new Map(
        context.contract.validationCases.map((item) => [
            item.id,
            item.expectation,
        ]),
    );
    const built = command.validationSeries.map((series) => {
        const arm = replicationBlockPlan(
            series.replicationSchedule,
            command.attemptIndex,
        ).arms[0];
        const expectedPass =
            expectationById.get(series.caseId) === "accept";
        const pass = passFor === null
            ? expectedPass
            : passFor({ series, expectedPass });
        const metrics = Object.fromEntries(
            context.contract.statisticalPolicy.metrics.map((metric) => [
                metric.key,
                pass ? metric.maximum : metric.minimum,
            ]),
        );
        const measurement = measurementProvenance(context, {
            arm,
            observationId,
            role: series.role,
            phase: "calibration",
            snapshotObjectId: series.artifactHash,
        });
        return {
            measurement,
            rawSeries: createRawMeasurementSeries({
                schedule: series.replicationSchedule,
                attempts: [{
                    ...arm,
                    attemptId:
                        `attempt-${observationId}-${arm.subjectId}`,
                    parsed: parsedObservation(
                        { pass, metrics },
                        series.role,
                        "calibration",
                        arm,
                    ),
                    invalid: null,
                    receiptHash: measurement.receiptHash,
                    measurementRoot: measurement.measurementRoot,
                }],
                role: series.role,
                phase: "calibration",
                caseId: series.caseId,
            }),
        };
    });
    const measurements = built.map((item) => item.measurement);
    const provenance = createEvidenceProvenance({
        validationCompositeArtifact:
            artifactRef(`${observationId}-validation-composite`),
        measurements,
    }, {
        purpose: "validation",
        command,
        contract: context.contract,
    });
    const evidenceId = `validation-evidence-${label}`;
    const evidence = commitObservation(context, {
        commandId,
        observationId,
        evidenceId,
        purpose: "validation",
        receipt: {
            version: 1,
            attemptId: `attempt-${observationId}`,
            runnerEpochId: "runner-epoch-1",
            rawStdoutHash:
                streamRoot(provenance.measurements, "rawStdoutHash"),
            rawStderrHash:
                streamRoot(provenance.measurements, "rawStderrHash"),
            candidateArtifactHash: null,
            provenance,
        },
        data: {
            version: 1,
            attemptIndex: command.attemptIndex,
            series: built.map((item) => item.rawSeries),
        },
    });
    return { command, evidence, observationId };
}

function validateInvestigation(context) {
    const { evidence } = commitValidation(context);
    if (!evidence.validationSatisfied) {
        throw new Error("compact fixture validation did not close");
    }
    append(context, constructKernelDecisionEvent(context.aggregate));
    return context;
}

function controlObjectId(context) {
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
    return binding.artifactSnapshotHash ?? objectHash("control");
}

function candidateObservation(
    context,
    { commandId, command },
    {
        label,
        pass = true,
        score = 100,
        blockCount = command.replicationSchedule.minBlocks,
        annotations,
    },
) {
    const observationId = `candidate-observation-${label}`;
    const candidateObjectId =
        command.enumerand?.artifactSnapshotHash
        ?? objectHash(`${observationId}-candidate`);
    const controlId = controlObjectId(context);
    const measurements = [];
    const attempts = [];
    for (let blockIndex = 0; blockIndex < blockCount; blockIndex += 1) {
        for (const arm of replicationBlockPlan(
            command.replicationSchedule,
            blockIndex,
        ).arms) {
            const candidate = arm.armId === "candidate";
            const measurement = measurementProvenance(context, {
                arm,
                observationId,
                role: "search",
                phase: "search",
                snapshotObjectId: candidate
                    ? candidateObjectId
                    : controlId,
            });
            measurements.push(measurement);
            attempts.push({
                ...arm,
                attemptId: `attempt-${observationId}-${arm.subjectId}`,
                parsed: parsedObservation(
                    {
                        pass: candidate ? pass : false,
                        metrics: { score: candidate ? score : 0 },
                    },
                    "search",
                    "search",
                    arm,
                ),
                invalid: null,
                receiptHash: measurement.receiptHash,
                measurementRoot: measurement.measurementRoot,
            });
        }
    }
    const provenance = createEvidenceProvenance({
        proposalArtifact: artifactRef(`${observationId}-proposal`),
        promptContextHash: tagged(`${observationId}-prompt`),
        replicationScheduleArtifact:
            artifactRef(`${observationId}-schedule`),
        replicationCompositeArtifact:
            artifactRef(`${observationId}-composite`),
        measurements,
    }, {
        purpose: "candidate",
        command,
        contract: context.contract,
    });
    return {
        observationId,
        input: {
            commandId,
            observationId,
            evidenceId: `candidate-evidence-${label}`,
            purpose: "candidate",
            annotations,
            receipt: {
                version: 1,
                attemptId: `attempt-${observationId}`,
                runnerEpochId: "runner-epoch-1",
                rawStdoutHash:
                    streamRoot(provenance.measurements, "rawStdoutHash"),
                rawStderrHash:
                    streamRoot(provenance.measurements, "rawStderrHash"),
                candidateArtifactHash:
                    snapshotHashFor(candidateObjectId),
                provenance,
            },
            data: {
                version: 1,
                series: [createRawMeasurementSeries({
                    schedule: command.replicationSchedule,
                    attempts,
                    role: "search",
                    phase: "search",
                    caseId: null,
                })],
            },
        },
    };
}

function commitCandidate(context, options) {
    const reserved = reserveAndDispatch(context, "search_candidate");
    const built = candidateObservation(context, reserved, options);
    const evidence = commitObservation(context, built.input);
    return {
        command: reserved.command,
        evidence,
        observationId: built.observationId,
    };
}

function verifierObservation(context, { commandId, command }, label) {
    const request = command.request;
    const mode = "enumerand_reexecution";
    const enumerandResults =
        request.evidence.coverageClosure.enumerands.map((entry) => {
            const input = request.reevaluation.enumerands[entry.ordinal];
            const claimStates = entry.claims.map((claim) => ({
                claimId: claim.claimId,
                state: "REFUTED",
            }));
            const evidenceRoot = impossibilityVerifierRefutationRoot({
                requestHash: command.requestHash,
                verifierRoleIdentity: request.verifier.roleIdentity,
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
                        requestHash: command.requestHash,
                        verifierRoleIdentity:
                            request.verifier.roleIdentity,
                        ordinal: entry.ordinal,
                        enumerandHash: entry.enumerandHash,
                        inputRoot: input.inputRoot,
                        receiptBindingsRoot:
                            input.receiptBindingsRoot,
                        claimStates,
                        evidenceRoot,
                    }),
            };
        });
    const enumerandResultsRoot =
        impossibilityVerifierEnumerandResultsRoot(enumerandResults);
    const checkerEvidenceRoot = tagged(
        `${label}-checker-evidence`,
        "sha256:crucible-test-checker-evidence-v1",
    );
    const independentFactsRoot = impossibilityVerifierFactsRoot({
        mode,
        enumerandResults,
        proofArtifactHash: command.proofArtifactHash,
        proofCheckerIdentity: null,
        proofValidationReceiptHash: null,
        validatedProofArtifactHash: null,
    });
    const certificate = {
        version: command.certificateVersion,
        status: "VERIFIED",
        verdict: "target_unreachable",
        mode,
        requestHash: command.requestHash,
        proposedCertificateArtifactHash:
            command.proposedCertificateArtifactHash,
        proofArtifactHash: command.proofArtifactHash,
        contractHash: request.signedExperiment.contractHash,
        harnessSuiteIdentity: request.harnessSuiteIdentity,
        verifierRoleIdentity: request.verifier.roleIdentity,
        coverageClosureRoot: request.evidence.coverageClosureRoot,
        enumerandManifestRoot: request.enumerands.merkleRoot,
        enumerandResultsRoot,
        evidenceRoots: request.evidence.roots,
        statisticalPolicyIdentity: request.statistics.policyIdentity,
        alphaLedgerRoot: request.statistics.alphaLedgerRoot,
        checkerEvidenceRoot,
        independentFactsRoot,
        certificateFormat: null,
        proofCheckerIdentity: null,
        proofValidationReceiptHash: null,
        validatedProofArtifactHash: null,
    };
    const checkerResult = {
        version: IMPOSSIBILITY_CHECKER_OUTPUT_VERSION,
        status: "VERIFIED",
        mode,
        requestHash: command.requestHash,
        proposedCertificateArtifactHash:
            command.proposedCertificateArtifactHash,
        proofArtifactHash: command.proofArtifactHash,
        coverageClosureRoot: request.evidence.coverageClosureRoot,
        enumerandManifestRoot: request.enumerands.merkleRoot,
        enumerandCount: request.enumerands.count,
        checkedEnumerandCount: enumerandResults.length,
        enumerandResults,
        enumerandResultsRoot,
        evidenceRoots: request.evidence.roots,
        statisticalPolicyIdentity: request.statistics.policyIdentity,
        alphaLedgerRoot: request.statistics.alphaLedgerRoot,
        checkerEvidenceRoot,
        independentFactsRoot,
        disagreementCount: 0,
        complete: true,
        certificateFormat: null,
        proofCheckerIdentity: null,
        proofValidationReceiptHash: null,
        validatedProofArtifactHash: null,
        certificate,
        ...command.measurementBinding,
        parserVersion: command.parserVersion,
    };
    const certificateArtifactHash = hashCanonical(
        certificate,
        "sha256:crucible-impossibility-certificate-artifact-v2",
    );
    const observationId = `impossibility-observation-${label}`;
    const measurement = measurementProvenance(context, {
        arm: command.measurementBinding,
        observationId,
        role: "impossibility_verifier",
        phase: "impossibility_verification",
        snapshotObjectId: `sha256:${digestOf(command.requestHash)}`,
    });
    const provenance = createEvidenceProvenance({
        impossibilityCertificateArtifact:
            artifactRef(`${observationId}-certificate`, certificateArtifactHash),
        measurements: [measurement],
    }, {
        purpose: "impossibility",
        command,
        contract: context.contract,
    });
    return {
        commandId,
        observationId,
        purpose: "impossibility",
        receipt: {
            version: 1,
            attemptId: `attempt-${observationId}`,
            runnerEpochId: "runner-epoch-1",
            rawStdoutHash: measurement.rawStdoutHash,
            rawStderrHash: measurement.rawStderrHash,
            candidateArtifactHash: null,
            provenance,
            certificateArtifactHash,
            measurementReceiptArtifactHash:
                `sha256:crucible-impossibility-receipt-artifact-v1:${
                    digestOf(measurement.receiptArtifact.objectId)
                }`,
            measurementReceiptHash: measurement.receiptHash,
            rawStderrArtifactHash:
                `sha256:crucible-impossibility-stderr-artifact-v1:${
                    digestOf(measurement.rawStderrArtifact.objectId)
                }`,
            rawStdoutArtifactHash:
                `sha256:crucible-impossibility-stdout-artifact-v1:${
                    digestOf(measurement.rawStdoutArtifact.objectId)
                }`,
            verificationRequestHash: command.requestHash,
            verificationSnapshotHash:
                measurement.snapshot.snapshotHash,
        },
        data: {
            certificateVersion: command.certificateVersion,
            checkerStatus: "VERIFIED",
            certificateVerdict: "target_unreachable",
            certificateArtifactHash,
            measurementReceiptHash: measurement.receiptHash,
            verificationRequestHash: command.requestHash,
            proposedCertificateArtifactHash:
                command.proposedCertificateArtifactHash,
            verificationSnapshotHash:
                measurement.snapshot.snapshotHash,
            checkerResult,
        },
    };
}

function verifiedVerifierCapability(context, input) {
    const command = context.aggregate.commands[input.commandId].command;
    const role = context.contract.harnessSuite.roles.impossibility_verifier;
    const measurement = input.receipt.provenance.measurements[0];
    const factsRoot = tagged(
        "verified-adapter-facts",
        "sha256:crucible-verified-impossibility-facts-v1",
    );
    const executionIdentity = tagged(
        "verified-adapter-execution",
        "sha256:crucible-verified-impossibility-execution-identity-v1",
    );
    const enumerandObservations =
        input.data.checkerResult.enumerandResults.map((result) => ({
            ordinal: result.ordinal,
            enumerandHash: result.enumerandHash,
            inputRoot: result.inputRoot,
            receiptBindingsRoot: result.receiptBindingsRoot,
            claimStates: result.claimStates,
            inputArtifact: artifactRef(
                `verified-enumerand-${result.ordinal}`,
                result.inputRoot,
            ),
            observationHash: tagged(
                `verified-observation-${result.ordinal}`,
                "sha256:crucible-verified-impossibility-enumerand-observation-v1",
            ),
            checkerReceipt: {
                receiptHash: tagged(
                    `verified-receipt-${result.ordinal}`,
                    "sha256:crucible-verified-impossibility-checker-receipt-v1",
                ),
            },
        }));
    const reference = {
        version: "crucible-verified-impossibility-execution-v1",
        commandId: input.commandId,
        observationId: input.observationId,
        request: {
            requestHash: command.requestHash,
            artifact: artifactRef("verified-request", command.requestHash),
            snapshotManifestArtifact: measurement.snapshot.manifestArtifact,
        },
        proof: {
            artifactHash: command.proofArtifactHash,
            artifact: artifactRef(
                "verified-proof",
                command.proofArtifactHash,
            ),
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
            status: "VERIFIED",
            verdict: "target_unreachable",
            mode: "enumerand_reexecution",
            complete: true,
            disagreementCount: 0,
            requestHash: command.requestHash,
            proposedCertificateArtifactHash:
                command.proposedCertificateArtifactHash,
            proofArtifactHash: command.proofArtifactHash,
            coverageClosureRoot:
                command.request.evidence.coverageClosureRoot,
            enumerandManifestRoot: command.request.enumerands.merkleRoot,
            enumerandCount: command.request.enumerands.count,
            checkedEnumerandCount: command.request.enumerands.count,
            enumerandObservations,
            evidenceRoots: command.request.evidence.roots,
            statisticalPolicyIdentity:
                command.request.statistics.policyIdentity,
            alphaLedgerRoot: command.request.statistics.alphaLedgerRoot,
            checkerEvidenceRoot:
                input.data.checkerResult.checkerEvidenceRoot,
            proofCheckerReceipt: null,
            factsRoot,
        },
    };
    return issueVerifiedImpossibilityExecutionCapability({
        commandId: input.commandId,
        observationId: input.observationId,
        reference,
    });
}

function certifiedVerifierForgeryContext() {
    const manifest = fakeEnumerandManifest(
        "certified_impossibility",
        ["candidate-a"],
    );
    const context = validateInvestigation(openInvestigation({
        hypothesisTopology: "certified_impossibility",
        enumerandManifest: manifest,
        statisticalPolicy: fastStatisticalPolicy({
            topology: "certified_impossibility",
            searchSlots: 1,
            manifest,
            minBlocks: 1,
            maxBlocks: 32,
            maximum: 1,
        }),
    }));
    commitCandidate(context, {
        label: "certified-rejection",
        pass: false,
        score: 0,
        blockCount: 32,
    });
    const reserved =
        reserveAndDispatch(context, "verify_impossibility");
    const input = verifierObservation(context, reserved, "complete");
    return { context, input };
}

function forgeEvent(event, payload, { rehash = true } = {}) {
    const forged = structuredClone(event);
    forged.payload = payload;
    if (rehash) forged.eventHash = computeEventHash(forged);
    return forged;
}

function requiredPredictionContext(score) {
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
            value: 1,
            refutation: {
                kind: "threshold",
                operator: "<",
                value: 1,
            },
            requiredForResult: true,
        }],
    };
    const control = artifactHash("f");
    const context = validateInvestigation(openInvestigation({
        hypothesisTopology: "finite_enumerable",
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
                referenceHash: control,
            },
        },
        statisticalPolicy: fastStatisticalPolicy({
            topology: "finite_enumerable",
            searchSlots: 1,
            minBlocks: 1,
            maxBlocks: 8,
            maximum: 1,
            control: { kind: "snapshot", identity: control },
        }),
    }));
    const committed = commitCandidate(context, {
        label: `prediction-${String(score).replace(".", "-")}`,
        score,
        blockCount: 8,
        annotations: {
            hypotheses:
                decideNext(context.aggregate).command.hypotheses,
        },
    });
    return { context, committed };
}

const REQUIRED_PREDICTION_CASES = [
    {
        ...requiredPredictionContext(1),
        state: "UNRESOLVED",
        code: NON_RESULT_CODES.SCIENTIFIC_PREDICTION_UNRESOLVED,
    },
    {
        ...requiredPredictionContext(0),
        state: "REFUTED",
        code: NON_RESULT_CODES.SCIENTIFIC_PREDICTION_REFUTED,
    },
];

describe("Crucible v4 fast domain kernel", () => {
    it("opens and replays deterministically with signed authority", () => {
        const context = openInvestigation();
        const opened = context.history[0];

        expect(DOMAIN_VERSION).toBe(4);
        expect(opened.payload).toMatchObject({
            domainVersion: 4,
            contract: { domainVersion: 4 },
            experimentAuthority: {
                algorithm: "Ed25519",
                signature: expect.any(String),
            },
        });
        expect(opened.payload.experimentAuthority.signature.length)
            .toBeGreaterThan(80);
        expect(opened.payload.experimentAuthorityIdentity)
            .toBe(opened.payload.experimentAuthority.identity);
        expect(canonicalJson(replayEvents(context.history)))
            .toBe(canonicalJson(context.aggregate));
        expect(verifyEventChain(context.history)).toMatchObject({
            valid: true,
            eventCount: 1,
            lastEventHash: opened.eventHash,
        });
    });

    it("rejects forged, noncanonical, and prototype-key events", () => {
        const context = openInvestigation();
        for (const field of [
            "capabilityEpochs",
            "commands",
            "observations",
            "evidence",
        ]) {
            expect(Object.getPrototypeOf(context.aggregate[field])).toBeNull();
        }
        const epoch = createExternalEvent(
            context.aggregate,
            EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
            { epochId: "epoch-safe", capabilities: ["a", "z"] },
        );

        expect(() => reduceEvent(
            context.aggregate,
            forgeEvent(epoch, {
                epochId: "epoch-safe",
                capabilities: ["changed"],
            }, { rehash: false }),
        )).toThrow();
        expect(() => reduceEvent(
            context.aggregate,
            forgeEvent(epoch, {
                epochId: "epoch-safe",
                capabilities: ["z", "a", "a"],
            }),
        )).toThrow(expect.objectContaining({
            code: ERROR_CODES.INVALID_EVENT,
        }));
        for (const identifier of [
            "__proto__",
            "constructor",
            "prototype",
        ]) {
            expect(() => normalizeEventIdentifier(identifier, "eventId"))
                .toThrow(expect.objectContaining({
                    code: ERROR_CODES.INVALID_EVENT,
                }));
            expect(() => reduceEvent(
                context.aggregate,
                forgeEvent(epoch, {
                    ...epoch.payload,
                    epochId: identifier,
                }),
            )).toThrow(expect.objectContaining({
                code: ERROR_CODES.INVALID_EVENT,
            }));
        }
    });

    it("keeps validation on statistical claims instead of a pass shortcut", () => {
        const context = openInvestigation({
            statisticalPolicy: fastStatisticalPolicy({
                minBlocks: 2,
                maxBlocks: 2,
            }),
        });
        const first = commitValidation(context, { label: "first" });

        expect(first.evidence.validationSatisfied).toBe(false);
        expect(first.evidence.validationEvaluation.evaluations
            .filter((item) => item.caseId === "known-good")
            .every((item) => item.actualState === "UNRESOLVED"))
            .toBe(true);
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "COMMAND",
            command: {
                kind: "run_validation",
                attemptIndex: 1,
            },
        });
    });

    it("accepts one harness-authoritative evidence item per search slot", () => {
        const context = validateInvestigation(openInvestigation());
        const reserved =
            reserveAndDispatch(context, "search_candidate");
        const modelEvent = constructModelObservedEvent(context.aggregate, {
            commandId: reserved.commandId,
            observationId: "model-candidate",
            purpose: "candidate",
            data: { pass: true },
        });
        expect(() => reduceEvent(context.aggregate, modelEvent))
            .toThrow(expect.objectContaining({
                code: ERROR_CODES.INVALID_EVIDENCE,
            }));

        const built = candidateObservation(context, reserved, {
            label: "authoritative",
            pass: false,
            score: 50,
        });
        const before = context.aggregate.evidenceOrder.length;
        commitObservation(context, built.input);
        expect(context.aggregate.evidenceOrder.length).toBe(before + 1);
        expect(context.aggregate.evidence[built.input.evidenceId])
            .toMatchObject({
                sourceKind: "harness",
                purpose: "candidate",
                round: 1,
                slotIndex: 0,
            });
        expect(() => constructEvidenceCommittedEvent(context.aggregate, {
            evidenceId: "candidate-evidence-duplicate",
            observationId: built.observationId,
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.DUPLICATE_ID,
        }));
    });

    it("reopens an invalidated search slot", () => {
        const context = validateInvestigation(openInvestigation());
        const first = commitCandidate(context, {
            label: "invalidate",
            score: 50,
        });
        append(context, createExternalEvent(
            context.aggregate,
            EVENT_TYPES.EVIDENCE_INVALIDATED,
            {
                evidenceId: first.evidence.evidenceId,
                reason: "receipt integrity failed",
            },
        ));

        expect(searchProgress(context.aggregate)).toMatchObject({
            nextRound: 1,
            nextSlot: 0,
            completedRounds: 0,
            roundsExhausted: false,
        });
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

    it("lets a persisted stop barrier preempt an active command", () => {
        const context = validateInvestigation(openInvestigation());
        const active = reserveAndDispatch(context, "search_candidate");
        append(context, createExternalEvent(
            context.aggregate,
            EVENT_TYPES.STOP_REQUESTED,
            {
                requestId: "preempt-active-command",
                reason: "operator requires a quiescent pause",
                pauseRequested: true,
            },
        ));

        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.INVESTIGATION_PAUSED,
            event: {
                type: EVENT_TYPES.INVESTIGATION_PAUSED,
            },
        });
        expect(context.aggregate.commands[active.commandId].status)
            .toBe("dispatched");
    });

    it("keeps pause, non-result, and terminal states absorbing", () => {
        const paused = openInvestigation();
        append(paused, createExternalEvent(
            paused.aggregate,
            EVENT_TYPES.STOP_REQUESTED,
            {
                requestId: "pause-now",
                reason: "operator pause",
                pauseRequested: true,
            },
        ));
        append(paused, constructKernelDecisionEvent(paused.aggregate));
        expect(paused.aggregate.status).toBe("paused");
        const whilePaused = createExternalEvent(
            paused.aggregate,
            EVENT_TYPES.STOP_REQUESTED,
            {
                requestId: "pause-again",
                reason: "must remain paused",
            },
        );
        expect(() => reduceEvent(paused.aggregate, whilePaused))
            .toThrow(expect.objectContaining({
                code: ERROR_CODES.ILLEGAL_TRANSITION,
            }));
        append(paused, constructInvestigationResumedEvent(paused.aggregate));
        expect(paused.aggregate.status).toBe("active");

        const nonResult = validateInvestigation(openInvestigation({
            acceptancePredicate: {
                kind: "metric_compare",
                metric: "score",
                operator: ">=",
                value: 50,
            },
            statisticalPolicy: fastStatisticalPolicy({
                acceptanceThreshold: 50,
            }),
        }));
        commitCandidate(nonResult, {
            label: "non-result",
            pass: false,
            score: 0,
        });
        append(nonResult, constructKernelDecisionEvent(nonResult.aggregate));
        expect(nonResult.aggregate).toMatchObject({
            status: "non_result",
            terminal: null,
            nonResults: [{ code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE }],
        });
        const afterNonResult = createExternalEvent(
            nonResult.aggregate,
            EVENT_TYPES.STOP_REQUESTED,
            {
                requestId: "after-non-result",
                reason: "must be rejected",
            },
        );
        expect(() => reduceEvent(nonResult.aggregate, afterNonResult))
            .toThrow(expect.objectContaining({
                code: ERROR_CODES.TERMINAL_STATE,
            }));

    });

    it("blocks scientific readiness for unresolved and refuted required predictions", () => {
        for (const {
            context,
            committed,
            state,
            code,
        } of REQUIRED_PREDICTION_CASES) {
            expect(committed.evidence.predictionEvaluation.requiredState)
                .toBe(state);
            expect(assessVerifiedResultReadiness(
                context.aggregate,
                committed.evidence,
            ))
                .toMatchObject({
                    ready: false,
                    requiredPredictionState: state,
                    missing: expect.arrayContaining([
                        "trusted_required_prediction_evaluations",
                    ]),
                });
            expect(decideNext(context.aggregate)).toMatchObject({
                kind: "NON_RESULT",
                code,
                readiness: {
                    requiredPredictionState: state,
                },
            });
        }
    });

    it("cannot terminalize discovery evidence before confirmation", () => {
        const context = validateInvestigation(openInvestigation());
        const candidate = commitCandidate(context, {
            label: "discovery-only",
            pass: false,
            score: 50,
        });

        expect(candidate.evidence).toMatchObject({
            acceptanceSatisfied: true,
            statisticalEvaluation: { requiredState: "SUPPORTED" },
        });
        expect(context.aggregate.terminal).toBeNull();
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "DECISION",
            decision: "SCIENTIFIC_CONFIRMATION_FROZEN",
            event: { type: EVENT_TYPES.SCIENTIFIC_CONFIRMATION_FROZEN },
        });
        append(context, constructKernelDecisionEvent(context.aggregate));
        expect(context.aggregate.terminal).toBeNull();
        expect(decideNext(context.aggregate)).toMatchObject({
            kind: "COMMAND",
            command: { kind: "run_confirmation" },
        });
    });

    it("never declares an open-generative target unreachable", () => {
        const context = validateInvestigation(openInvestigation({
            acceptancePredicate: {
                kind: "metric_compare",
                metric: "score",
                operator: ">=",
                value: 50,
            },
            statisticalPolicy: fastStatisticalPolicy({
                acceptanceThreshold: 50,
            }),
        }));
        commitCandidate(context, {
            label: "open-rejection",
            pass: false,
            score: 0,
        });

        const recommendation = decideNext(context.aggregate);
        expect(recommendation).toMatchObject({
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
        });
        expect(recommendation.decision).not.toBe("TARGET_UNREACHABLE");
        expect(recommendation.event.type)
            .toBe(EVENT_TYPES.NON_RESULT_RECORDED);
    });

    it("rejects a public-helper impossibility result built only from self-issued hashes", () => {
        const { context, input } = certifiedVerifierForgeryContext();

        expect(searchProgress(context.aggregate)).toMatchObject({
            boundedComplete: true,
            roundsExhausted: true,
        });
        expect(assessTargetUnreachableReadiness(context.aggregate, null))
            .toMatchObject({
            ready: false,
            coverageComplete: true,
            independentVerifierSupported: false,
            independentlyDerivedVerifierFacts: false,
        });
        expect(() => constructHarnessObservedEvent(
            context.aggregate,
            input,
        )).toThrow(/verified execution capability/u);
        expect(() => constructHarnessObservedEvent(
            context.aggregate,
            {
                ...input,
                verifierExecution: {
                    version: "crucible-verified-impossibility-execution-v1",
                    facts: input.data.checkerResult,
                },
            },
        )).toThrow(/verified execution capability/u);
    });

    it("accepts a privately code-stamped verifier execution reference", () => {
        const { context, input } = certifiedVerifierForgeryContext();
        const capability = verifiedVerifierCapability(context, input);
        const evidence = commitObservation(context, {
            ...input,
            evidenceId: "impossibility-evidence-verified",
        }, {
            verifierExecutionCapability: capability,
        });

        expect(assessTargetUnreachableReadiness(
            context.aggregate,
            evidence,
        )).toMatchObject({
            ready: true,
            coverageComplete: true,
            independentVerifierSupported: true,
            independentVerifierRoleBound: true,
            independentlyDerivedVerifierFacts: true,
        });
        append(context, constructKernelDecisionEvent(context.aggregate));
        expect(context.aggregate.terminal).toMatchObject({
            decision: "TARGET_UNREACHABLE",
            evidenceId: evidence.evidenceId,
        });
        expect(() => replayEvents(structuredClone(context.history)))
            .toThrow(/verified execution capability/u);
    });
});
