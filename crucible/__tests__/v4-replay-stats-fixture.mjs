import path from "node:path";

import {
    DEFAULT_SEARCH_POLICY,
    EVENT_TYPES,
    OBSERVATION_STREAM_HASH_ALGORITHM,
    canonicalJson,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructKernelDecisionEvent,
    createEvidenceProvenance,
    createExternalEvent,
    createInvestigationContract,
    createMeasurementProvenance,
    createRawMeasurementSeries,
    createSnapshotProvenance,
    evaluateReplicationProgress,
    hashCanonical,
    replicationBlockPlan,
} from "../domain/index.mjs";
import {
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";
import {
    PARSER_VERSION,
    createNoveltyMeasurementBinding,
    hashReceipt,
} from "../measurement/index.mjs";
import { createDomainRepositoryAdapter } from "../runtime/index.mjs";
import {
    createRuntimeConfigAuthorityFixture,
    createSignedInvestigationAuthority,
} from "./experiment-authority-fixture.mjs";
import {
    fakeStatisticalPolicy,
    upgradeLegacyContractInput,
} from "./v4-contract-fixture.mjs";

function digestOf(value) {
    return value.split(":").at(-1);
}

function taggedObjectHash(objectId, algorithm) {
    return `${algorithm}:${digestOf(objectId)}`;
}

function safeLabel(value) {
    return value.replace(/[^A-Za-z0-9._-]/gu, "-").slice(0, 64);
}

function putObject(store, bytes) {
    return store.putBytes(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
}

function artifactRef(repository, investigationId, store, label, bytes) {
    const object = putObject(store, bytes);
    const artifactId =
        `artifact-${safeLabel(label)}-${digestOf(object.id).slice(0, 16)}`;
    if (repository.getArtifact(artifactId) === null) {
        repository.registerExternalArtifact({
            investigationId,
            artifactId,
            algo: "sha256",
            hash: digestOf(object.id),
            sizeBytes: object.size,
            contentType: "application/octet-stream",
        });
        repository.markArtifactDurable(artifactId);
    }
    return {
        artifactId,
        objectId: object.id,
    };
}

function registerExistingObject(
    repository,
    investigationId,
    label,
    object,
) {
    const artifactId =
        `artifact-${safeLabel(label)}-${digestOf(object.id).slice(0, 16)}`;
    if (repository.getArtifact(artifactId) === null) {
        repository.registerExternalArtifact({
            investigationId,
            artifactId,
            algo: "sha256",
            hash: digestOf(object.id),
            sizeBytes: object.size,
            contentType: "application/octet-stream",
        });
        repository.markArtifactDurable(artifactId);
    }
    return {
        artifactId,
        objectId: object.id,
    };
}

function snapshotProvenance(manifestArtifact) {
    return createSnapshotProvenance({
        snapshotHash: taggedObjectHash(
            manifestArtifact.objectId,
            "sha256:crucible-measurement-snapshot-v1",
        ),
        manifestArtifact,
        objectArtifacts: [],
    });
}

function parsedObservation(raw, role, phase, arm) {
    return {
        pass: raw.pass === true,
        metrics: raw.metrics,
        observables: raw.metrics,
        validationCases: null,
        searchSpaceExhausted: null,
        impossibilityCertificateHash: null,
        parserVersion: PARSER_VERSION,
        role,
        phase,
        replicateIndex: arm.replicateIndex,
        blockIndex: arm.blockIndex,
        armIndex: arm.armIndex,
        armId: arm.armId,
        deterministicSeed: arm.deterministicSeed,
        subjectId: arm.subjectId,
        ...(arm.environmentIdentity === undefined
            ? {}
            : { environmentIdentity: arm.environmentIdentity }),
        ...(arm.suiteIdentity === undefined
            ? {}
            : { suiteIdentity: arm.suiteIdentity }),
    };
}

function createMeasurement({
    repository,
    investigationId,
    store,
    contract,
    observationId,
    arm,
    snapshot,
    parsed,
    receiptMutation = null,
}) {
    const attemptId = `${observationId}-${arm.subjectId}`;
    const receiptParsed = receiptMutation === null
        ? parsed
        : receiptMutation({
            observationId,
            arm,
            parsed: structuredClone(parsed),
        });
    const receiptDocument = {
        attemptId,
        observationId,
        subjectId: arm.subjectId,
        role: parsed.role,
        phase: parsed.phase,
        replicateIndex: arm.replicateIndex,
        blockIndex: arm.blockIndex,
        armIndex: arm.armIndex,
        armId: arm.armId,
        deterministicSeed: arm.deterministicSeed,
        parsed: receiptParsed,
    };
    const receiptArtifact = artifactRef(
        repository,
        investigationId,
        store,
        `${observationId}-${arm.subjectId}-receipt`,
        canonicalJson(receiptDocument),
    );
    const rawStdoutArtifact = artifactRef(
        repository,
        investigationId,
        store,
        `${observationId}-${arm.subjectId}-stdout`,
        canonicalJson(parsed),
    );
    const rawStderrArtifact = artifactRef(
        repository,
        investigationId,
        store,
        `${observationId}-${arm.subjectId}-stderr`,
        "",
    );
    const receiptHash = hashReceipt(receiptDocument);
    const rawStdoutHash = taggedObjectHash(
        rawStdoutArtifact.objectId,
        "sha256:crucible-measurement-stream-v1",
    );
    const rawStderrHash = taggedObjectHash(
        rawStderrArtifact.objectId,
        "sha256:crucible-measurement-stream-v1",
    );
    const roleSpec = contract.harnessSuite.roles[parsed.role];
    const executableHash = roleSpec.executableHash;
    const measurement = createMeasurementProvenance({
        subjectId: arm.subjectId,
        role: parsed.role,
        phase: parsed.phase,
        receiptArtifact,
        receiptHash,
        rawStdoutArtifact,
        rawStdoutHash,
        rawStderrArtifact,
        rawStderrHash,
        parserVersion: roleSpec.parser.version,
        allowlistFileHash: hashCanonical(
            { fixture: "allowlist" },
            "sha256:crucible-measurement-file-v1",
        ),
        harnessEntryHash: roleSpec.harnessEntryHash,
        executableHash,
        stagedExecutableHash: executableHash,
        dependencyHashes: [],
        stagedDependencyHashes: [],
        argvHash: hashCanonical(
            { observationId, subjectId: arm.subjectId, argv: true },
            "sha256:crucible-measurement-argv-v1",
        ),
        envHash: hashCanonical(
            { observationId, subjectId: arm.subjectId, env: true },
            "sha256:crucible-measurement-env-v1",
        ),
        sandboxPolicy: {
            kind: "none",
            sandboxId: null,
            environmentHash: null,
        },
        snapshot,
        snapshotExecutionHash: hashCanonical(
            { observationId, subjectId: arm.subjectId, execution: true },
            "sha256:crucible-evidence-snapshot-execution-v1",
        ),
    });
    return {
        measurement,
        attempt: {
            ...arm,
            attemptId,
            parsed,
            invalid: null,
            receiptHash,
            measurementRoot: measurement.measurementRoot,
        },
    };
}

function streamRoot(provenance, field) {
    return hashCanonical(
        provenance.measurements.map((measurement) => ({
            id: measurement.subjectId,
            hash: measurement[field],
        })),
        OBSERVATION_STREAM_HASH_ALGORITHM,
    );
}

function validationObservation({
    repository,
    investigationId,
    store,
    contract,
    command,
    validationSnapshots,
    receiptMutation = null,
}) {
    const observationId = "replay-validation-observation";
    const byCase = new Map(
        contract.validationCases.map((item) => [item.id, item]),
    );
    const measurements = [];
    const attemptsBySeries = new Map();
    for (const series of command.validationSeries) {
        const attempts = [];
        for (const arm of replicationBlockPlan(
            series.replicationSchedule,
            command.attemptIndex,
        ).arms) {
            const pass = byCase.get(series.caseId).expectation === "accept";
            const parsed = parsedObservation({
                pass,
                metrics: { score: pass ? 100 : 0 },
            }, series.role, "calibration", arm);
            const created = createMeasurement({
                repository,
                investigationId,
                store,
                contract,
                observationId,
                arm,
                snapshot: validationSnapshots.get(series.caseId),
                parsed,
                receiptMutation,
            });
            measurements.push(created.measurement);
            attempts.push(created.attempt);
        }
        attemptsBySeries.set(
            `${series.role}\0${series.caseId}`,
            attempts,
        );
    }
    const rawSeries = command.validationSeries.map((series) =>
        createRawMeasurementSeries({
            schedule: series.replicationSchedule,
            attempts: attemptsBySeries.get(
                `${series.role}\0${series.caseId}`,
            ),
            role: series.role,
            phase: "calibration",
            caseId: series.caseId,
        })).sort((left, right) =>
        `${left.role}\0${left.caseId}`.localeCompare(
            `${right.role}\0${right.caseId}`,
        ));
    const validationCompositeArtifact = artifactRef(
        repository,
        investigationId,
        store,
        `${observationId}-composite`,
        canonicalJson({
            version: 2,
            authority: "raw_complete_blocks",
            commandId: command.commandId,
            attemptIndex: command.attemptIndex,
            series: rawSeries,
        }),
    );
    const provenance = createEvidenceProvenance({
        validationCompositeArtifact,
        measurements,
    }, {
        purpose: "validation",
        command,
        contract,
    });
    return {
        commandId: command.commandId,
        observationId,
        purpose: "validation",
        receipt: {
            version: 1,
            attemptId: "replay-validation-attempt",
            runnerEpochId: "replay-runner-epoch",
            rawStdoutHash: streamRoot(provenance, "rawStdoutHash"),
            rawStderrHash: streamRoot(provenance, "rawStderrHash"),
            candidateArtifactHash: null,
            provenance,
        },
        data: {
            version: 1,
            attemptIndex: command.attemptIndex,
            series: rawSeries,
        },
    };
}

function candidateObservation({
    repository,
    investigationId,
    store,
    contract,
    command,
    candidateSnapshot,
    controlSnapshot,
    receiptMutation = null,
}) {
    const observationId = "replay-candidate-observation";
    const measurements = [];
    const attempts = [];
    for (
        let blockIndex = 0;
        blockIndex < command.replicationSchedule.minBlocks;
        blockIndex += 1
    ) {
        for (const arm of replicationBlockPlan(
            command.replicationSchedule,
            blockIndex,
        ).arms) {
            const candidate = arm.armId === "candidate";
            const parsed = parsedObservation({
                pass: candidate,
                metrics: { score: candidate ? 100 : 0 },
            }, "search", "search", arm);
            const created = createMeasurement({
                repository,
                investigationId,
                store,
                contract,
                observationId,
                arm,
                snapshot: candidate
                    ? candidateSnapshot
                    : controlSnapshot,
                parsed,
                receiptMutation,
            });
            measurements.push(created.measurement);
            attempts.push(created.attempt);
        }
    }
    const rawSeries = createRawMeasurementSeries({
        schedule: command.replicationSchedule,
        attempts,
        role: "search",
        phase: "search",
        caseId: null,
    });
    const progress = evaluateReplicationProgress({
        contract,
        schedule: command.replicationSchedule,
        attempts,
    });
    const noveltyBinding = createNoveltyMeasurementBinding({
        contract,
        candidateArtifactHash: candidateSnapshot.snapshotHash,
    });
    const noveltyParsed = parsedObservation(
        {
            pass: true,
            metrics: {
                branchCount: 1,
                nodeCount: 2,
            },
        },
        "novelty",
        "novelty",
        noveltyBinding,
    );
    const noveltyCreated = createMeasurement({
        repository,
        investigationId,
        store,
        contract,
        observationId,
        arm: noveltyBinding,
        snapshot: candidateSnapshot,
        parsed: noveltyParsed,
        receiptMutation,
    });
    measurements.push(noveltyCreated.measurement);
    const noveltyAttempt = {
        version: 1,
        attemptId: noveltyCreated.attempt.attemptId,
        role: "novelty",
        phase: "novelty",
        replicateIndex: noveltyBinding.replicateIndex,
        blockIndex: noveltyBinding.blockIndex,
        armIndex: noveltyBinding.armIndex,
        armId: noveltyBinding.armId,
        deterministicSeed: noveltyBinding.deterministicSeed,
        subjectId: noveltyBinding.subjectId,
        parsed: noveltyCreated.attempt.parsed,
        invalid: noveltyCreated.attempt.invalid,
        receiptHash: noveltyCreated.attempt.receiptHash,
        measurementRoot: noveltyCreated.attempt.measurementRoot,
    };
    const replicationScheduleArtifact = artifactRef(
        repository,
        investigationId,
        store,
        `${observationId}-schedule`,
        canonicalJson(command.replicationSchedule),
    );
    const replicationCompositeArtifact = artifactRef(
        repository,
        investigationId,
        store,
        `${observationId}-composite`,
        canonicalJson({
            version: 2,
            authority: "raw_complete_blocks",
            commandId: command.commandId,
            candidateId: command.candidateId,
            schedule: command.replicationSchedule,
            scheduleArtifact: replicationScheduleArtifact,
            series: rawSeries,
            stopping: progress.stopping,
        }),
    );
    const provenance = createEvidenceProvenance({
        proposalArtifact: artifactRef(
            repository,
            investigationId,
            store,
            `${observationId}-proposal`,
            canonicalJson({ observationId, kind: "proposal" }),
        ),
        promptContextHash: hashCanonical({
            observationId,
            prompt: true,
        }),
        replicationScheduleArtifact,
        replicationCompositeArtifact,
        measurements,
    }, {
        purpose: "candidate",
        command,
        contract,
    });
    return {
        commandId: command.commandId,
        observationId,
        purpose: "candidate",
        receipt: {
            version: 1,
            attemptId: "replay-candidate-attempt",
            runnerEpochId: "replay-runner-epoch",
            rawStdoutHash: streamRoot(provenance, "rawStdoutHash"),
            rawStderrHash: streamRoot(provenance, "rawStderrHash"),
            candidateArtifactHash: candidateSnapshot.snapshotHash,
            provenance,
        },
        data: {
            version: 2,
            series: [rawSeries],
            novelty: noveltyAttempt,
        },
    };
}

function scientificRoleObservation({
    repository,
    investigationId,
    store,
    contract,
    command,
    candidateSnapshot,
    controlSnapshot,
    candidateScore = 100,
    receiptMutation = null,
}) {
    const role = command.harnessRole;
    const observationId =
        `replay-${role}-observation-${command.memberOrdinal}`;
    const measurements = [];
    const attempts = [];
    for (
        let blockIndex = 0;
        blockIndex < command.replicationSchedule.minBlocks;
        blockIndex += 1
    ) {
        for (const arm of replicationBlockPlan(
            command.replicationSchedule,
            blockIndex,
        ).arms) {
            const candidate = arm.armId === "candidate";
            const parsed = parsedObservation({
                pass: candidate && candidateScore >= 0,
                metrics: { score: candidate ? candidateScore : 0 },
            }, role, role, arm);
            const created = createMeasurement({
                repository,
                investigationId,
                store,
                contract,
                observationId,
                arm,
                snapshot: candidate
                    ? candidateSnapshot
                    : controlSnapshot,
                parsed,
                receiptMutation,
            });
            measurements.push(created.measurement);
            attempts.push(created.attempt);
        }
    }
    const rawSeries = createRawMeasurementSeries({
        schedule: command.replicationSchedule,
        attempts,
        role,
        phase: role,
        caseId: null,
    });
    const progress = evaluateReplicationProgress({
        contract,
        schedule: command.replicationSchedule,
        attempts,
    });
    const replicationScheduleArtifact = artifactRef(
        repository,
        investigationId,
        store,
        `${observationId}-schedule`,
        canonicalJson(command.replicationSchedule),
    );
    const replicationCompositeArtifact = artifactRef(
        repository,
        investigationId,
        store,
        `${observationId}-composite`,
        canonicalJson({
            version: 2,
            authority: "raw_complete_blocks",
            commandId: command.commandId,
            candidateId: command.candidateId,
            candidateEvidenceId: command.candidateEvidenceId,
            confirmationFreezeHash:
                command.confirmationFreezeHash,
            role,
            protocolManifest: command.protocolManifest,
            protocolManifestHash: command.protocolManifestHash,
            schedule: command.replicationSchedule,
            scheduleArtifact: replicationScheduleArtifact,
            series: rawSeries,
            stopping: progress.stopping,
        }),
    );
    const provenance = createEvidenceProvenance({
        replicationScheduleArtifact,
        replicationCompositeArtifact,
        measurements,
    }, {
        purpose: role,
        command,
        contract,
    });
    return {
        commandId: command.commandId,
        observationId,
        purpose: role,
        candidateId: command.candidateId,
        annotations: {
            mechanism: null,
            hypothesis: null,
            expectedEffects: [],
            citedEvidenceIds: [],
            finding: null,
            ...(command.hypotheses === null
                ? {}
                : { hypotheses: command.hypotheses }),
        },
        receipt: {
            version: 1,
            attemptId: `replay-${role}-attempt-${command.memberOrdinal}`,
            runnerEpochId: "replay-runner-epoch",
            rawStdoutHash: streamRoot(provenance, "rawStdoutHash"),
            rawStderrHash: streamRoot(provenance, "rawStderrHash"),
            candidateArtifactHash: candidateSnapshot.snapshotHash,
            provenance,
        },
        data: {
            version: 1,
            series: [rawSeries],
        },
    };
}

function appendReservedAndDispatched(adapter) {
    const reserved = adapter.appendKernelDecision().domainEvent.payload;
    adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, {
        commandId: reserved.commandId,
    });
    return {
        ...reserved.command,
        commandId: reserved.commandId,
    };
}

export function createReplayStatsFixture(root, {
    receiptMutation = null,
} = {}) {
    const store = openArtifactStore({ root: path.join(root, "cas") });
    const goodObject = putObject(store, "validation-good");
    const badObject = putObject(store, "validation-bad");
    const controlObject = putObject(store, "statistical-control");
    const candidateObject = putObject(store, "candidate-snapshot");
    const statisticalPolicy = fakeStatisticalPolicy({
        topology: "open_generative",
        searchSlots: 1,
        validationCaseCount: 2,
        validationRoleCount: 4,
        minBlocks: 1,
        maxBlocks: 1,
        control: {
            kind: "snapshot",
            identity: controlObject.id,
        },
        metrics: [{
            key: "score",
            minimum: 0,
            maximum: 100,
            estimand: "mean score",
            unit: "score",
            direction: "max",
            acceptanceThreshold: 0,
            practicalEquivalenceDelta: 1,
            family: "primary",
        }],
    });
    const contract = createInvestigationContract(upgradeLegacyContractInput({
        objective: "Exercise raw-authority statistical replay",
        acceptancePredicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: 0,
        },
        validationCases: [
            {
                id: "known-good",
                expectation: "accept",
                artifactHash: goodObject.id,
            },
            {
                id: "known-bad",
                expectation: "reject",
                artifactHash: badObject.id,
            },
        ],
        harnessId: "replay-fixture-harness",
        hypothesisTopology: "open_generative",
        criticality: "standard",
        policyVersion: "replay-policy-v1",
        parserVersion: "crucible-json-v1",
        workerModels: ["worker-a"],
        candidatesPerRound: 1,
        maxRounds: 1,
        metrics: [{ key: "score", direction: "max", epsilon: 1 }],
        searchPolicy: structuredClone(DEFAULT_SEARCH_POLICY),
        statisticalPolicy,
    }));
    const repository = openRepository({
        file: path.join(root, "events.sqlite"),
    });
    const signed = createSignedInvestigationAuthority({
        contract,
        experimentId: "replay-stats-fixture",
        projectDir: root,
    });
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: signed.investigationId,
    });
    adapter.openInvestigation(
        contract,
        signed.capability,
        createRuntimeConfigAuthorityFixture(signed.investigationId),
    );
    const goodRef = registerExistingObject(
        repository,
        signed.investigationId,
        "validation-known-good",
        goodObject,
    );
    const badRef = registerExistingObject(
        repository,
        signed.investigationId,
        "validation-known-bad",
        badObject,
    );
    const controlRef = registerExistingObject(
        repository,
        signed.investigationId,
        "statistical-control",
        controlObject,
    );
    const candidateRef = registerExistingObject(
        repository,
        signed.investigationId,
        "candidate-snapshot",
        candidateObject,
    );
    for (const series of adapter.replay().aggregate.contract.validationCases) {
        const expected = series.id === "known-good" ? goodRef : badRef;
        if (series.artifactHash !== expected.objectId) {
            throw new Error("validation fixture artifact identity mismatch");
        }
    }

    const validationCommand = appendReservedAndDispatched(adapter);
    const validation = validationObservation({
        repository,
        investigationId: signed.investigationId,
        store,
        contract,
        command: validationCommand,
        receiptMutation,
        validationSnapshots: new Map([
            ["known-good", snapshotProvenance(goodRef)],
            ["known-bad", snapshotProvenance(badRef)],
        ]),
    });
    adapter.appendDomainEvent(
        constructHarnessObservedEvent(
            adapter.replay().aggregate,
            validation,
        ),
    );
    adapter.appendDomainEvent(
        constructEvidenceCommittedEvent(adapter.replay().aggregate, {
            evidenceId: "replay-validation-evidence",
            observationId: validation.observationId,
        }),
    );
    adapter.appendDomainEvent(
        constructKernelDecisionEvent(adapter.replay().aggregate),
    );

    const candidateCommand = appendReservedAndDispatched(adapter);
    const candidate = candidateObservation({
        repository,
        investigationId: signed.investigationId,
        store,
        contract,
        command: candidateCommand,
        candidateSnapshot: snapshotProvenance(candidateRef),
        controlSnapshot: snapshotProvenance(controlRef),
        receiptMutation,
    });
    adapter.appendDomainEvent(
        constructHarnessObservedEvent(
            adapter.replay().aggregate,
            candidate,
        ),
    );
    adapter.appendDomainEvent(
        constructEvidenceCommittedEvent(adapter.replay().aggregate, {
            evidenceId: "replay-candidate-evidence",
            observationId: candidate.observationId,
        }),
    );

    const appendScientificRole = ({
        candidateScore = 100,
        evidenceId = null,
    } = {}) => {
        const command = appendReservedAndDispatched(adapter);
        if (command.kind !== "run_confirmation"
            && command.kind !== "run_challenge") {
            throw new Error(
                `expected a scientific role command, received ${command.kind}`,
            );
        }
        const observation = scientificRoleObservation({
            repository,
            investigationId: signed.investigationId,
            store,
            contract,
            command,
            candidateSnapshot: snapshotProvenance(candidateRef),
            controlSnapshot: snapshotProvenance(controlRef),
            candidateScore,
            receiptMutation,
        });
        adapter.appendDomainEvent(
            constructHarnessObservedEvent(
                adapter.replay().aggregate,
                observation,
            ),
        );
        const committedEvidenceId = evidenceId
            ?? `replay-${command.harnessRole}-evidence-${command.memberOrdinal}`;
        adapter.appendDomainEvent(
            constructEvidenceCommittedEvent(adapter.replay().aggregate, {
                evidenceId: committedEvidenceId,
                observationId: observation.observationId,
            }),
        );
        return {
            command,
            observation,
            evidence:
                adapter.replay().aggregate.evidence[committedEvidenceId],
        };
    };

    return {
        root,
        store,
        repository,
        adapter,
        contract,
        investigationId: signed.investigationId,
        dbFile: repository.databaseFile,
        replay: adapter.replayScientific(),
        freezeConfirmation() {
            const appended = adapter.appendKernelDecision();
            if (appended.domainEvent.type
                !== EVENT_TYPES.SCIENTIFIC_CONFIRMATION_FROZEN) {
                throw new Error(
                    `expected confirmation freeze, received ${appended.domainEvent.type}`,
                );
            }
            return appended.domainEvent;
        },
        appendScientificRole,
        close() {
            repository.close();
        },
    };
}
