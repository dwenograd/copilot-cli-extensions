// Release-only persistence race, corruption, and multiprocess fencing matrix.
import { afterEach, describe, expect, it } from "vitest";
import { fork } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    DEFAULT_SEARCH_POLICY,
    EVENT_TYPES,
    artifactRefsFromProvenance,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructKernelDecisionEvent,
    createExternalEvent,
    createEvidenceProvenance,
    createInvestigationContract,
    createMeasurementProvenance,
    createSnapshotProvenance,
    hashCanonical,
} from "../domain/index.mjs";
import {
    ERROR_CODES as PERSISTENCE_ERROR_CODES,
    canonicalize,
    computeEventHash as computeRepositoryEventHash,
    openRepository,
} from "../persistence/index.mjs";
import { DatabaseSync } from "../persistence/sqlite.mjs";
import { PARSER_VERSION } from "../measurement/index.mjs";
import {
    RUNTIME_ERROR_CODES,
    createDomainRepositoryAdapter,
    formatAttemptCommand,
} from "../runtime/index.mjs";
import { fakeHarnessIdentity } from "./harness-identity-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
// Track every repository we open so a test that throws mid-setup still releases
// the SQLite file handle before afterEach removes its directory. On Windows an
// open handle turns the recursive rmSync into an EPERM that masks the real
// assertion failure, so cleanup closes first and then retries the removal.
const openRepositories = new Set();

function waitForChildMessage(child, type, timeoutMs = 30_000) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(
            () => reject(new Error(`timed out waiting for child message ${type}`)),
            timeoutMs,
        );
        timer.unref?.();
        const onMessage = (message) => {
            if (message?.type !== type) return;
            clearTimeout(timer);
            child.off("message", onMessage);
            resolve(message);
        };
        child.on("message", onMessage);
        child.once("error", reject);
        child.once("exit", (code, signal) => {
            if (code !== 0) {
                reject(new Error(`fence worker exited early: code=${code} signal=${signal}`));
            }
        });
    });
}

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-adapter-${label}-`));
    roots.push(root);
    return root;
}

function trackRepository(repository) {
    openRepositories.add(repository);
    return repository;
}

function releaseRepository(repository) {
    openRepositories.delete(repository);
    repository.close();
}

function removeRootWithRetry(root, attempts = 10) {
    for (let attempt = 0; ; attempt += 1) {
        try {
            fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 25 });
            if (fs.existsSync(root)) {
                throw new Error(`runtime adapter root survived cleanup: ${root}`);
            }
            return;
        } catch (error) {
            if (attempt >= attempts) {
                throw error;
            }
        }
    }
}

afterEach(() => {
    const failures = [];
    for (const repository of openRepositories) {
        try {
            repository.close();
        } catch (error) {
            failures.push(error);
        }
    }
    openRepositories.clear();
    for (const root of roots.splice(0)) {
        try {
            removeRootWithRetry(root);
        } catch (error) {
            failures.push(error);
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "runtime domain-adapter cleanup failed");
    }
});

describe("H7 concurrent runner ownership failure matrix", () => {
    it.each([
        ["reserved", []],
        ["dispatched", ["dispatched"]],
        ["observed", ["dispatched", "observed"]],
    ])("fences a same-generation old incarnation after takeover from %s", (
        expectedState,
        transitions,
    ) => {
        const {
            repositoryA,
            repositoryB,
            adapterA,
        } = openSharedAdapters(`h7-incarnation-${expectedState}`);
        adapterA.openInvestigation(createInvestigationContract(contractInput()));
        repositoryA.claimSupervisorGeneration({
            investigationId: "inv-runtime",
            supervisorGeneration: 9,
            supervisorNonce: "supervisor-nine",
        });
        repositoryA.issueRunnerIncarnation({
            investigationId: "inv-runtime",
            supervisorGeneration: 9,
            supervisorNonce: "supervisor-nine",
            runnerIncarnation: "runner-nine-old",
        });
        const oldLease = repositoryA.acquireLease({
            investigationId: "inv-runtime",
            leaseId: `lease-old-${expectedState}`,
            owner: "runner-old",
            supervisorGeneration: 9,
            runnerIncarnation: "runner-nine-old",
        });
        const attemptId = `attempt-${expectedState}`;
        const command = `command-${expectedState}`;
        repositoryA.reserveCommand({
            investigationId: "inv-runtime",
            attemptId,
            command,
            leaseId: oldLease.leaseId,
            fencingToken: oldLease.fencingToken,
            owner: oldLease.owner,
            supervisorGeneration: 9,
            runnerIncarnation: "runner-nine-old",
        });
        for (const toState of transitions) {
            repositoryA.transitionCommand({
                investigationId: "inv-runtime",
                attemptId,
                toState,
                leaseId: oldLease.leaseId,
                fencingToken: oldLease.fencingToken,
                owner: oldLease.owner,
                supervisorGeneration: 9,
                runnerIncarnation: "runner-nine-old",
            });
        }
        expect(repositoryA.getCommandAttempt(attemptId).state).toBe(expectedState);

        repositoryB.issueRunnerIncarnation({
            investigationId: "inv-runtime",
            supervisorGeneration: 9,
            supervisorNonce: "supervisor-nine",
            runnerIncarnation: "runner-nine-current",
        });
        const currentLease = repositoryB.acquireLease({
            investigationId: "inv-runtime",
            leaseId: `lease-current-${expectedState}`,
            owner: "runner-current",
            supervisorGeneration: 9,
            runnerIncarnation: "runner-nine-current",
        });
        const nextState = {
            reserved: "dispatched",
            dispatched: "observed",
            observed: "committed",
        }[expectedState];
        const before = repositoryB.getCommandAttempt(attemptId);

        expect(() => repositoryA.transitionCommand({
            investigationId: "inv-runtime",
            attemptId,
            toState: nextState,
            leaseId: oldLease.leaseId,
            fencingToken: oldLease.fencingToken,
            owner: oldLease.owner,
            supervisorGeneration: 9,
            runnerIncarnation: "runner-nine-old",
        })).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        }));
        expect(repositoryB.getCommandAttempt(attemptId)).toEqual(before);

        const abandoned = repositoryB.abandonStaleCommand({
            investigationId: "inv-runtime",
            attemptId,
            leaseId: currentLease.leaseId,
            fencingToken: currentLease.fencingToken,
            owner: currentLease.owner,
            supervisorGeneration: 9,
            runnerIncarnation: "runner-nine-current",
        });
        expect(abandoned.state).toBe("abandoned");
    });

    it("rejects a delayed stale generation before it can acquire or resume authority", () => {
        const { repositoryA, repositoryB, adapterA } =
            openSharedAdapters("h7-delayed-generation");
        adapterA.openInvestigation(createInvestigationContract(contractInput()));
        repositoryA.claimSupervisorGeneration({
            investigationId: "inv-runtime",
            supervisorGeneration: 4,
            supervisorNonce: "supervisor-four",
        });
        repositoryA.issueRunnerIncarnation({
            investigationId: "inv-runtime",
            supervisorGeneration: 4,
            supervisorNonce: "supervisor-four",
            runnerIncarnation: "runner-four",
        });
        repositoryA.claimSupervisorGeneration({
            investigationId: "inv-runtime",
            supervisorGeneration: 5,
            supervisorNonce: "supervisor-five",
        });
        repositoryB.issueRunnerIncarnation({
            investigationId: "inv-runtime",
            supervisorGeneration: 5,
            supervisorNonce: "supervisor-five",
            runnerIncarnation: "runner-five",
        });
        const current = repositoryB.acquireLease({
            investigationId: "inv-runtime",
            leaseId: "lease-five",
            owner: "runner-five",
            supervisorGeneration: 5,
            runnerIncarnation: "runner-five",
        });

        expect(() => repositoryA.acquireLease({
            investigationId: "inv-runtime",
            leaseId: "lease-four-delayed",
            owner: "runner-four-delayed",
            supervisorGeneration: 4,
            runnerIncarnation: "runner-four",
        })).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        }));
        expect(repositoryB.getActiveLease("inv-runtime")).toMatchObject(current);
    });
});

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

// Canonical version-2 search policy, optionally overridden. createInvestigationContract
// requires searchPolicy to already be in canonical kernel form, so every override
// is merged onto the frozen DEFAULT_SEARCH_POLICY rather than partially specified.
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
        objective: "Find a score of at least 90",
        acceptancePredicate: {
            kind: "all",
            predicates: [
                { kind: "harness_pass" },
                { kind: "metric_compare", metric: "score", operator: ">=", value: 90 },
            ],
        },
        validationCases: [
            { id: "good", expectation: "accept", artifactHash: artifactHash("a") },
            { id: "bad", expectation: "reject", artifactHash: artifactHash("b") },
        ],
        harnessId: "fixture-harness",
        hypothesisTopology: "finite_enumerable",
        boundedCandidateIds: [
            "fixture-candidate-1",
            "fixture-candidate-2",
        ],
        criticality: "high",
        policyVersion: "policy-v1",
        parserVersion: PARSER_VERSION,
        harnessIdentity: fakeHarnessIdentity({
            harnessId: "fixture-harness",
            parserVersion: PARSER_VERSION,
        }),
        workerModels: ["model-a"],
        candidatesPerRound: 1,
        maxRounds: 2,
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        searchPolicy: searchPolicy(),
        declaredLimits: { maxCommands: 10 },
        ...overrides,
    };
}

function openAdapter(label = "db") {
    const root = makeRoot(label);
    const repository = trackRepository(
        openRepository({ file: path.join(root, "events.sqlite") }),
    );
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: "inv-runtime",
    });
    return { root, repository, adapter };
}

function openSharedAdapters(label) {
    const root = makeRoot(label);
    const file = path.join(root, "events.sqlite");
    const repositoryA = trackRepository(openRepository({ file }));
    const adapterA = createDomainRepositoryAdapter({
        repository: repositoryA,
        investigationId: "inv-runtime",
    });
    const repositoryB = trackRepository(openRepository({ file }));
    const adapterB = createDomainRepositoryAdapter({
        repository: repositoryB,
        investigationId: "inv-runtime",
    });
    return { root, file, repositoryA, repositoryB, adapterA, adapterB };
}

function domainPersistenceSnapshot(repository) {
    return {
        events: repository.listEvents("inv-runtime").map((event) => event.eventHash),
        refs: repository.listArtifactRefs("inv-runtime").map((ref) => ({
            artifactId: ref.artifactId,
            seq: ref.seq,
        })),
        attempts: repository.listCommandAttempts("inv-runtime").map((attempt) => ({
            attemptId: attempt.attemptId,
            command: attempt.command,
            state: attempt.state,
            leaseId: attempt.leaseId,
            fencingToken: attempt.fencingToken,
            owner: attempt.owner,
            supervisorGeneration: attempt.supervisorGeneration,
            runnerIncarnation: attempt.runnerIncarnation,
        })),
    };
}

function digestOf(value) {
    return value.split(":").at(-1);
}

function fakeArtifact(label, hash) {
    return {
        artifactId: `artifact-${label}-${digestOf(hash).slice(0, 16)}`,
        objectId: `sha256:${digestOf(hash)}`,
    };
}

function registerProvenanceArtifacts(repository, provenance) {
    for (const artifact of artifactRefsFromProvenance(provenance)) {
        if (repository.getArtifact(artifact.artifactId) !== null) continue;
        repository.registerExternalArtifact({
            investigationId: "inv-runtime",
            artifactId: artifact.artifactId,
            algo: "sha256",
            hash: artifact.objectId.slice("sha256:".length),
            sizeBytes: 0,
            contentType: "application/octet-stream",
        });
        repository.markArtifactDurable(artifact.artifactId);
    }
}

function harnessReceipt(repository, contract, command, attemptId, purpose) {
    const subjectIds = purpose === "validation"
        ? contract.validationCases.map((item) => item.id)
        : [command.candidateId];
    const measurements = subjectIds.map((subjectId) => {
        const snapshotId = purpose === "validation"
            ? contract.validationCases.find((item) => item.id === subjectId).artifactHash
            : `sha256:${digestOf(hashCanonical({ attemptId, artifact: true }))}`;
        const stdoutHash = hashCanonical(
            { attemptId, subjectId, stream: "stdout" },
            "sha256:crucible-measurement-stream-v1",
        );
        const stderrHash = hashCanonical(
            { attemptId, subjectId, stream: "stderr" },
            "sha256:crucible-measurement-stream-v1",
        );
        const receiptHash = hashCanonical(
            { attemptId, subjectId, receipt: true },
            "sha256:crucible-measurement-receipt-v1",
        );
        const executableHash = hashCanonical(
            { harness: "executable" },
            "sha256:crucible-measurement-file-v1",
        );
        return createMeasurementProvenance({
            subjectId,
            receiptArtifact: fakeArtifact(`${subjectId}-receipt`, receiptHash),
            receiptHash,
            rawStdoutArtifact: fakeArtifact(`${subjectId}-stdout`, stdoutHash),
            rawStdoutHash: stdoutHash,
            rawStderrArtifact: fakeArtifact(`${subjectId}-stderr`, stderrHash),
            rawStderrHash: stderrHash,
            parserVersion: contract.parserVersion,
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
            dependencyHashes: [],
            stagedDependencyHashes: [],
            argvHash: hashCanonical(
                { attemptId, subjectId, argv: true },
                "sha256:crucible-measurement-argv-v1",
            ),
            envHash: hashCanonical(
                { attemptId, subjectId, env: true },
                "sha256:crucible-measurement-env-v1",
            ),
            sandboxPolicy: { kind: "none", sandboxId: null, environmentHash: null },
            snapshot: createSnapshotProvenance({
                snapshotHash:
                    `sha256:crucible-measurement-snapshot-v1:${digestOf(snapshotId)}`,
                manifestArtifact: fakeArtifact(`${subjectId}-manifest`, snapshotId),
                objectArtifacts: [],
            }),
            snapshotExecutionHash: hashCanonical(
                { attemptId, subjectId, execution: true },
                "sha256:crucible-evidence-snapshot-execution-v1",
            ),
        });
    });
    const provenance = createEvidenceProvenance({
        proposalArtifact: purpose === "candidate"
            ? fakeArtifact(
                `${command.candidateId}-proposal`,
                hashCanonical({ attemptId, proposal: true }),
            )
            : null,
        promptContextHash: purpose === "candidate"
            ? hashCanonical({ attemptId, prompt: true })
            : null,
        validationCompositeArtifact: purpose === "validation"
            ? fakeArtifact(
                `${attemptId}-validation`,
                hashCanonical({ attemptId, validation: true }),
            )
            : null,
        measurements,
    }, { purpose, command, contract });
    registerProvenanceArtifacts(repository, provenance);
    return {
        version: 1,
        attemptId,
        runnerEpochId: "runner-epoch",
        rawStdoutHash: purpose === "validation"
            ? hashCanonical(
                provenance.measurements.map((item) => ({
                    id: item.subjectId,
                    hash: item.rawStdoutHash,
                })),
                "sha256:crucible-runtime-observation-streams-v1",
            )
            : provenance.measurements[0].rawStdoutHash,
        rawStderrHash: purpose === "validation"
            ? hashCanonical(
                provenance.measurements.map((item) => ({
                    id: item.subjectId,
                    hash: item.rawStderrHash,
                })),
                "sha256:crucible-runtime-observation-streams-v1",
            )
            : provenance.measurements[0].rawStderrHash,
        candidateArtifactHash: purpose === "candidate"
            ? provenance.measurements[0].snapshot.snapshotHash
            : null,
        provenance,
    };
}

function prepareValidationCommand(adapter, repository, {
    leaseId,
    owner,
    attemptId,
    supervisorGeneration = null,
    runnerIncarnation = null,
} = {}) {
    if (adapter.replay().domainEvents.length === 0) {
        adapter.openInvestigation(createInvestigationContract(contractInput()));
    }
    const reserved = adapter.appendKernelDecision().domainEvent.payload;
    adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, {
        commandId: reserved.commandId,
    });
    const acquired = adapter.acquireRunnerLease({
        leaseId,
        owner,
        supervisorGeneration,
        runnerIncarnation,
    });
    const command = formatAttemptCommand("domain-command", {
        commandId: reserved.commandId,
        command: reserved.command,
    });
    adapter.reserveAttempt({ attemptId, command, lease: acquired.lease });
    adapter.dispatchAttempt(attemptId, acquired.lease);
    const aggregate = adapter.replay().aggregate;
    return {
        reserved,
        lease: acquired.lease,
        command,
        observation: {
            commandId: reserved.commandId,
            observationId: `${attemptId}-validation-observation`,
            purpose: "validation",
            receipt: harnessReceipt(
                repository,
                aggregate.contract,
                reserved.command,
                attemptId,
                "validation",
            ),
            data: {
                caseResults: [
                    { id: "good", artifactHash: artifactHash("a"), outcome: "accept" },
                    { id: "bad", artifactHash: artifactHash("b"), outcome: "reject" },
                ],
            },
        },
    };
}

function appendFullVerifiedHistory(adapter, { includeTerminal = true } = {}) {
    let aggregate = adapter.openInvestigation(
        createInvestigationContract(contractInput({
            searchPolicy: searchPolicy({ stopOnFirstAccept: true }),
        })),
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        constructKernelDecisionEvent(aggregate),
        { aggregate },
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        createExternalEvent(aggregate, EVENT_TYPES.COMMAND_DISPATCHED, {
            commandId: "cmd-000001",
            capabilityEpochId: null,
        }),
        { aggregate },
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        constructHarnessObservedEvent(aggregate, {
            commandId: "cmd-000001",
            observationId: "validation-observation",
            purpose: "validation",
            receipt: harnessReceipt(
                adapter.repository,
                aggregate.contract,
                aggregate.commands["cmd-000001"].command,
                "validation-attempt",
                "validation",
            ),
            data: {
                caseResults: [
                    { id: "good", artifactHash: artifactHash("a"), outcome: "accept" },
                    { id: "bad", artifactHash: artifactHash("b"), outcome: "reject" },
                ],
            },
        }),
        { aggregate },
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        constructEvidenceCommittedEvent(aggregate, {
            evidenceId: "evidence-000001",
            observationId: "validation-observation",
        }),
        { aggregate },
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        constructKernelDecisionEvent(aggregate),
        { aggregate },
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        constructKernelDecisionEvent(aggregate),
        { aggregate },
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        createExternalEvent(aggregate, EVENT_TYPES.COMMAND_DISPATCHED, {
            commandId: "cmd-000002",
            capabilityEpochId: null,
        }),
        { aggregate },
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        constructHarnessObservedEvent(aggregate, {
            commandId: "cmd-000002",
            observationId: "candidate-observation",
            purpose: "candidate",
            // round/slotIndex/candidateId default to the kernel-reserved
            // search-candidate assignment; supplying our own would be rejected.
            receipt: harnessReceipt(
                adapter.repository,
                aggregate.contract,
                aggregate.commands["cmd-000002"].command,
                "candidate-attempt",
                "candidate",
            ),
            data: { pass: true, metrics: { score: 95 } },
        }),
        { aggregate },
    ).aggregate;
    aggregate = adapter.appendDomainEvent(
        constructEvidenceCommittedEvent(aggregate, {
            evidenceId: "evidence-000002",
            observationId: "candidate-observation",
        }),
        { aggregate },
    ).aggregate;
    if (includeTerminal) {
        aggregate = adapter.appendDomainEvent(
            constructKernelDecisionEvent(aggregate),
            { aggregate },
        ).aggregate;
    }
    return aggregate;
}

describe("Crucible domain/persistence adapter", () => {
    it("stores one canonical repository event per domain event with identical sequence", () => {
        const { repository, adapter } = openAdapter("one-to-one");
        const aggregate = appendFullVerifiedHistory(adapter);
        const rows = repository.listEvents("inv-runtime");

        expect(rows).toHaveLength(aggregate.lastSeq);
        for (const row of rows) {
            expect(row.kind).toBe(`domain:${row.payload.domainEvent.type}`);
            expect(row.seq).toBe(row.payload.domainEvent.seq);
            expect(Object.keys(row.payload)).toEqual(["domainEvent"]);
        }
        expect(rows.at(-1)).toMatchObject({
            isTerminal: true,
            terminalKind: "verified_result",
        });
        expect(adapter.replay().aggregate).toEqual(aggregate);
        releaseRepository(repository);
    });

    it("keeps non-domain evidence in the companion log without shifting domain sequence", () => {
        const { repository, adapter } = openAdapter("side-log");
        let aggregate = adapter.openInvestigation(createInvestigationContract(contractInput())).aggregate;
        adapter.ingestOperationalEvidence({
            attemptId: "attempt-side",
            evidenceKind: "candidate:candidate-a",
            payload: { measured: true },
        });
        aggregate = adapter.appendDomainEvent(
            constructKernelDecisionEvent(aggregate),
            { aggregate },
        ).aggregate;

        expect(repository.listEvents("inv-runtime").map((row) => row.seq)).toEqual([1, 2]);
        expect(repository.listEvents(adapter.operationalInvestigationId)).toHaveLength(1);
        expect(aggregate.lastSeq).toBe(2);
        releaseRepository(repository);
    });

    it("detects repository tampering before domain replay", () => {
        const { root, repository, adapter } = openAdapter("repo-tamper");
        adapter.openInvestigation(createInvestigationContract(contractInput()));
        releaseRepository(repository);

        const raw = new DatabaseSync(path.join(root, "events.sqlite"));
        try {
            raw.exec("PRAGMA journal_mode=WAL;");
            raw.prepare("UPDATE events SET payload = ? WHERE investigation_id = ? AND seq = 1")
                .run(JSON.stringify({ domainEvent: { forged: true } }), "inv-runtime");
        } finally {
            raw.close();
        }

        const reopened = trackRepository(openRepository({ file: path.join(root, "events.sqlite") }));
        const replayAdapter = createDomainRepositoryAdapter({
            repository: reopened,
            investigationId: "inv-runtime",
        });
        expect(() => replayAdapter.replay()).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.INTEGRITY_FAILURE,
        }));
        releaseRepository(reopened);
    });

    it("detects a forged domain event even when the repository hash is recomputed", () => {
        const { root, repository, adapter } = openAdapter("domain-tamper");
        adapter.openInvestigation(createInvestigationContract(contractInput()));
        const row = repository.getEvent("inv-runtime", 1);
        releaseRepository(repository);

        const forgedPayload = JSON.parse(JSON.stringify(row.payload));
        forgedPayload.domainEvent.payload.contract.objective = "forged objective";
        const payloadCanonical = canonicalize(forgedPayload);
        const repositoryHash = computeRepositoryEventHash({
            investigationId: row.investigationId,
            seq: row.seq,
            prevHash: row.prevHash,
            kind: row.kind,
            payloadCanonical,
            isTerminal: row.isTerminal,
            terminalKind: row.terminalKind,
            attemptId: row.attemptId,
            evidenceKind: row.evidenceKind,
            createdAt: row.createdAt,
        });
        const raw = new DatabaseSync(path.join(root, "events.sqlite"));
        try {
            raw.exec("PRAGMA journal_mode=WAL;");
            raw.prepare("UPDATE events SET payload = ?, event_hash = ? WHERE investigation_id = ? AND seq = 1")
                .run(payloadCanonical, repositoryHash, "inv-runtime");
        } finally {
            raw.close();
        }

        const reopened = trackRepository(openRepository({ file: path.join(root, "events.sqlite") }));
        const replayAdapter = createDomainRepositoryAdapter({
            repository: reopened,
            investigationId: "inv-runtime",
        });
        expect(reopened.verifyInvestigation("inv-runtime").ok).toBe(true);
        expect(() => replayAdapter.replay()).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.INTEGRITY_FAILURE,
        }));
        releaseRepository(reopened);
    });

    it("prevents evidence commitment when an observation artifact ref is missing", () => {
        const { root, repository, adapter } = openAdapter("missing-artifact-ref");
        let aggregate = adapter.openInvestigation(
            createInvestigationContract(contractInput()),
        ).aggregate;
        const reserved = adapter.appendKernelDecision();
        aggregate = reserved.aggregate;
        aggregate = adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, {
            commandId: reserved.domainEvent.payload.commandId,
        }).aggregate;
        const receipt = harnessReceipt(
            repository,
            aggregate.contract,
            reserved.domainEvent.payload.command,
            "missing-ref-attempt",
            "validation",
        );
        const observed = adapter.appendHarnessObservation({
            commandId: reserved.domainEvent.payload.commandId,
            observationId: "missing-ref-observation",
            purpose: "validation",
            receipt,
            data: {
                caseResults: [
                    { id: "good", artifactHash: artifactHash("a"), outcome: "accept" },
                    { id: "bad", artifactHash: artifactHash("b"), outcome: "reject" },
                ],
            },
        });
        const observationSeq = observed.domainEvent.seq;
        expect(repository.listArtifactRefsForEvent("inv-runtime", observationSeq).length)
            .toBeGreaterThan(0);

        const raw = new DatabaseSync(path.join(root, "events.sqlite"));
        try {
            raw.exec("PRAGMA journal_mode=WAL;");
            raw.prepare(`
                DELETE FROM artifact_refs
                WHERE ref_id = (
                    SELECT ref_id FROM artifact_refs
                    WHERE investigation_id = ? AND seq = ?
                    ORDER BY ref_id ASC LIMIT 1
                )`).run("inv-runtime", observationSeq);
        } finally {
            raw.close();
        }

        expect(() => adapter.appendEvidenceCommit({
            evidenceId: "missing-ref-evidence",
            observationId: "missing-ref-observation",
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.INTEGRITY_FAILURE,
        }));
        expect(repository.listEvents("inv-runtime").some((row) =>
            row.kind === "domain:evidence_committed")).toBe(false);
        releaseRepository(repository);
    });

    it("abandons stale reserved/dispatched attempts before replacement work", () => {
        const { repository, adapter } = openAdapter("recovery");
        adapter.openInvestigation(createInvestigationContract(contractInput()));
        const first = adapter.acquireRunnerLease({ leaseId: "lease-one", owner: "runner-one" });
        adapter.reserveAttempt({
            attemptId: "attempt-reserved",
            command: formatAttemptCommand("test", { id: 1 }),
            lease: first.lease,
        });
        adapter.reserveAttempt({
            attemptId: "attempt-dispatched",
            command: formatAttemptCommand("test", { id: 2 }),
            lease: first.lease,
        });
        adapter.dispatchAttempt("attempt-dispatched", first.lease);

        const second = adapter.acquireRunnerLease({ leaseId: "lease-two", owner: "runner-two" });
        expect(second.recovery).toMatchObject({
            abandonedCount: 2,
            uncertainDispatched: 1,
        });
        expect(repository.getCommandAttempt("attempt-reserved").state).toBe("abandoned");
        expect(repository.getCommandAttempt("attempt-dispatched").state).toBe("abandoned");

        const replacement = adapter.reserveAttempt({
            attemptId: "attempt-replacement",
            command: formatAttemptCommand("test", { id: 1 }),
            lease: second.lease,
        });
        expect(replacement.state).toBe("reserved");
        releaseRepository(repository);
    });

    it("enforces the SQLite lease fence across a real process barrier", async () => {
        const {
            root,
            file,
            repositoryA,
            repositoryB,
            adapterA,
            adapterB,
        } = openSharedAdapters("multiprocess-fence-race");
        const prepared = prepareValidationCommand(adapterA, repositoryA, {
            leaseId: "lease-old-process",
            owner: "runner-old-process",
            attemptId: "attempt-old-process",
        });
        const inputPath = path.join(root, "fence-race-input.json");
        fs.writeFileSync(inputPath, JSON.stringify({
            databasePath: file,
            investigationId: "inv-runtime",
            observation: prepared.observation,
            attemptId: "attempt-old-process",
            command: prepared.command,
            lease: prepared.lease,
        }));
        const child = fork(
            path.join(HERE, "fixtures", "domain-fence-race-worker.mjs"),
            [],
            {
                cwd: root,
                silent: true,
                windowsHide: true,
                env: {
                    ...process.env,
                    CRUCIBLE_FENCE_RACE_INPUT: inputPath,
                },
            },
        );
        let stderr = "";
        child.stderr?.on("data", (chunk) => {
            stderr += chunk.toString("utf8");
        });
        try {
            await waitForChildMessage(child, "ready");
            adapterB.acquireRunnerLease({
                leaseId: "lease-current-process",
                owner: "runner-current-process",
            });
            const beforeStaleWrite = domainPersistenceSnapshot(repositoryB);
            child.send({ type: "go" });
            const result = await waitForChildMessage(child, "result");
            expect(result, stderr).toMatchObject({
                ok: false,
                code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
            });
            expect(domainPersistenceSnapshot(repositoryB)).toEqual(beforeStaleWrite);
            if (child.exitCode === null && child.signalCode === null) {
                await new Promise((resolve) => child.once("exit", resolve));
            }
        } finally {
            if (child.exitCode === null && child.signalCode === null) {
                child.kill("SIGKILL");
                await new Promise((resolve) => child.once("exit", resolve));
            }
        }
    });

    it("leaves no observation, artifact ref, or attempt transition after two-handle takeover", () => {
        const {
            repositoryA,
            repositoryB,
            adapterA,
            adapterB,
        } = openSharedAdapters("two-handle-observation-takeover");
        const prepared = prepareValidationCommand(adapterA, repositoryA, {
            leaseId: "lease-a",
            owner: "runner-a",
            attemptId: "attempt-a",
        });
        const leaseB = repositoryB.acquireLease({
            investigationId: "inv-runtime",
            leaseId: "lease-b",
            owner: "runner-b",
        });
        const beforeStaleWrite = domainPersistenceSnapshot(repositoryB);

        expect(() => adapterA.appendHarnessObservationFenced(
            prepared.observation,
            {
                attemptId: "attempt-a",
                command: prepared.command,
                lease: prepared.lease,
            },
        )).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        }));
        expect(domainPersistenceSnapshot(repositoryB)).toEqual(beforeStaleWrite);
        expect(repositoryB.getCommandAttempt("attempt-a").state).toBe("dispatched");

        adapterB.recoverStaleAttempts(leaseB);
        const currentAttemptId = "attempt-b";
        adapterB.reserveAttempt({
            attemptId: currentAttemptId,
            command: prepared.command,
            lease: leaseB,
        });
        adapterB.dispatchAttempt(currentAttemptId, leaseB);
        const currentAggregate = adapterB.replay().aggregate;
        const currentObservation = {
            ...prepared.observation,
            observationId: "current-validation-observation",
            receipt: harnessReceipt(
                repositoryB,
                currentAggregate.contract,
                prepared.reserved.command,
                currentAttemptId,
                "validation",
            ),
        };
        adapterB.appendHarnessObservationFenced(currentObservation, {
            attemptId: currentAttemptId,
            command: prepared.command,
            lease: leaseB,
        });
        const eventCount = repositoryB.countEvents("inv-runtime");
        expect(() => adapterB.appendHarnessObservationFenced(currentObservation, {
            attemptId: currentAttemptId,
            command: prepared.command,
            lease: leaseB,
        })).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.ILLEGAL_TRANSITION,
        }));
        expect(repositoryB.countEvents("inv-runtime")).toBe(eventCount);
        expect(repositoryB.getCommandAttempt(currentAttemptId).state).toBe("observed");
    });

    it("binds domain append authority to the current same-generation incarnation", () => {
        const {
            repositoryA,
            repositoryB,
            adapterA,
            adapterB,
        } = openSharedAdapters("same-generation-incarnation");
        repositoryA.claimSupervisorGeneration({
            investigationId: "inv-runtime",
            supervisorGeneration: 4,
            supervisorNonce: "supervisor-four",
        });
        repositoryA.issueRunnerIncarnation({
            investigationId: "inv-runtime",
            supervisorGeneration: 4,
            supervisorNonce: "supervisor-four",
            runnerIncarnation: "runner-four-one",
        });
        const prepared = prepareValidationCommand(adapterA, repositoryA, {
            leaseId: "lease-four-one",
            owner: "runner-four-one",
            attemptId: "attempt-four-one",
            supervisorGeneration: 4,
            runnerIncarnation: "runner-four-one",
        });
        repositoryB.issueRunnerIncarnation({
            investigationId: "inv-runtime",
            supervisorGeneration: 4,
            supervisorNonce: "supervisor-four",
            runnerIncarnation: "runner-four-two",
        });
        const activeBeforeRejection = repositoryB.getActiveLease("inv-runtime");
        const beforeStaleWrite = domainPersistenceSnapshot(repositoryB);

        expect(() => adapterA.appendHarnessObservationFenced(
            prepared.observation,
            {
                attemptId: "attempt-four-one",
                command: prepared.command,
                lease: prepared.lease,
            },
        )).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        }));
        expect(domainPersistenceSnapshot(repositoryB)).toEqual(beforeStaleWrite);
        expect(repositoryB.getActiveLease("inv-runtime")).toEqual(activeBeforeRejection);

        expect(() => repositoryA.acquireLease({
            investigationId: "inv-runtime",
            leaseId: "lease-four-old-retry",
            owner: "runner-four-old-retry",
            supervisorGeneration: 4,
            runnerIncarnation: "runner-four-one",
        })).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        }));
        expect(domainPersistenceSnapshot(repositoryB)).toEqual(beforeStaleWrite);
        expect(repositoryB.getActiveLease("inv-runtime")).toEqual(activeBeforeRejection);

        const currentLease = adapterB.acquireRunnerLease({
            leaseId: "lease-four-two",
            owner: "runner-four-two",
            supervisorGeneration: 4,
            runnerIncarnation: "runner-four-two",
        }).lease;
        adapterB.reserveAttempt({
            attemptId: "attempt-four-two",
            command: prepared.command,
            lease: currentLease,
        });
        adapterB.dispatchAttempt("attempt-four-two", currentLease);
        const aggregate = adapterB.replay().aggregate;
        const currentObservation = {
            ...prepared.observation,
            observationId: "runner-four-two-observation",
            receipt: harnessReceipt(
                repositoryB,
                aggregate.contract,
                prepared.reserved.command,
                "attempt-four-two",
                "validation",
            ),
        };
        adapterB.appendHarnessObservationFenced(currentObservation, {
            attemptId: "attempt-four-two",
            command: prepared.command,
            lease: currentLease,
        });
        expect(repositoryB.getCommandAttempt("attempt-four-two").state).toBe("observed");
        expect(adapterB.replay().aggregate.observationOrder)
            .toContain("runner-four-two-observation");
    });

    it("re-reads attempt authority after CAS and never replays a stale observation", () => {
        const {
            repositoryA,
            repositoryB,
            adapterA,
            adapterB,
        } = openSharedAdapters("cas-takeover");
        const prepared = prepareValidationCommand(adapterA, repositoryA, {
            leaseId: "lease-a",
            owner: "runner-a",
            attemptId: "attempt-a",
        });
        let authorityReads = 0;
        let appendCalls = 0;
        let leaseB = null;
        const repositoryProxy = new Proxy(repositoryA, {
            get(target, property, receiver) {
                if (property === "assertAttemptAuthority") {
                    return (input) => {
                        authorityReads += 1;
                        if (authorityReads === 2) {
                            leaseB = repositoryB.acquireLease({
                                investigationId: "inv-runtime",
                                leaseId: "lease-b",
                                owner: "runner-b",
                            });
                        }
                        return target.assertAttemptAuthority(input);
                    };
                }
                if (property === "appendEventsWithAttemptTransition") {
                    return (input) => {
                        appendCalls += 1;
                        if (appendCalls === 1) {
                            adapterB.appendExternal(
                                EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
                                {
                                    epochId: "cas-racer",
                                    capabilities: ["cas-race"],
                                },
                            );
                        }
                        return target.appendEventsWithAttemptTransition(input);
                    };
                }
                const value = Reflect.get(target, property, receiver);
                return typeof value === "function" ? value.bind(target) : value;
            },
        });
        const racingAdapter = createDomainRepositoryAdapter({
            repository: repositoryProxy,
            investigationId: "inv-runtime",
            ensure: false,
        });

        expect(() => racingAdapter.appendHarnessObservationFenced(
            prepared.observation,
            {
                attemptId: "attempt-a",
                command: prepared.command,
                lease: prepared.lease,
            },
        )).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        }));
        expect(authorityReads).toBe(2);
        expect(appendCalls).toBe(1);
        expect(leaseB).not.toBeNull();
        expect(repositoryB.getCommandAttempt("attempt-a").state).toBe("dispatched");
        expect(adapterB.replay().aggregate.observationOrder).toEqual([]);
        expect(repositoryB.listArtifactRefs("inv-runtime")).toEqual([]);

        adapterB.recoverStaleAttempts(leaseB);
        adapterB.reserveAttempt({
            attemptId: "attempt-b",
            command: prepared.command,
            lease: leaseB,
        });
        adapterB.dispatchAttempt("attempt-b", leaseB);
        const aggregate = adapterB.replay().aggregate;
        const currentObservation = {
            ...prepared.observation,
            observationId: "cas-current-observation",
            receipt: harnessReceipt(
                repositoryB,
                aggregate.contract,
                prepared.reserved.command,
                "attempt-b",
                "validation",
            ),
        };
        adapterB.appendHarnessObservationFenced(currentObservation, {
            attemptId: "attempt-b",
            command: prepared.command,
            lease: leaseB,
        });
        expect(adapterB.replay().aggregate.observationOrder)
            .toEqual(["cas-current-observation"]);
    });

    it("fences evidence takeover without changing its event, refs, or observed attempt", () => {
        const {
            repositoryA,
            repositoryB,
            adapterA,
            adapterB,
        } = openSharedAdapters("two-handle-evidence-takeover");
        const prepared = prepareValidationCommand(adapterA, repositoryA, {
            leaseId: "lease-a",
            owner: "runner-a",
            attemptId: "attempt-a",
        });
        adapterA.appendHarnessObservationFenced(prepared.observation, {
            attemptId: "attempt-a",
            command: prepared.command,
            lease: prepared.lease,
        });
        const leaseB = repositoryB.acquireLease({
            investigationId: "inv-runtime",
            leaseId: "lease-b",
            owner: "runner-b",
        });
        const beforeStaleWrite = domainPersistenceSnapshot(repositoryB);

        expect(() => adapterA.appendEvidenceCommitFenced({
            evidenceId: "evidence-000001",
            observationId: prepared.observation.observationId,
        }, {
            attemptId: "attempt-a",
            command: prepared.command,
            lease: prepared.lease,
        })).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        }));
        expect(domainPersistenceSnapshot(repositoryB)).toEqual(beforeStaleWrite);
        expect(repositoryB.getCommandAttempt("attempt-a").state).toBe("observed");

        adapterB.recoverStaleAttempts(leaseB);
        const pendingCommand = formatAttemptCommand("domain-evidence-commit", {
            commandId: prepared.reserved.commandId,
            observationId: prepared.observation.observationId,
            evidenceId: "evidence-000001",
        });
        adapterB.reserveAttempt({
            attemptId: "attempt-b",
            command: pendingCommand,
            lease: leaseB,
        });
        adapterB.dispatchAttempt("attempt-b", leaseB);
        adapterB.observeAttempt("attempt-b", leaseB);
        adapterB.appendEvidenceCommitFenced({
            evidenceId: "evidence-000001",
            observationId: prepared.observation.observationId,
        }, {
            attemptId: "attempt-b",
            command: pendingCommand,
            lease: leaseB,
        });
        const evidenceEvents = repositoryB.listEvents("inv-runtime")
            .filter((event) => event.kind === "domain:evidence_committed");
        expect(evidenceEvents).toHaveLength(1);
        expect(repositoryB.getCommandAttempt("attempt-b").state).toBe("committed");
    });

    it("fences terminal takeover and lets only the current owner persist it once", () => {
        const {
            repositoryA,
            repositoryB,
            adapterA,
            adapterB,
        } = openSharedAdapters("two-handle-terminal-takeover");
        const aggregate = appendFullVerifiedHistory(adapterA, { includeTerminal: false });
        const terminalEvent = constructKernelDecisionEvent(aggregate);
        const factHash = adapterA.domainFactIdentity(terminalEvent);
        const terminalCommand = formatAttemptCommand("domain-event", {
            scope: "kernel-decision",
            eventType: terminalEvent.type,
            factHash,
        });
        const leaseA = adapterA.acquireRunnerLease({
            leaseId: "lease-a",
            owner: "runner-a",
        }).lease;
        adapterA.reserveAttempt({
            attemptId: "terminal-a",
            command: terminalCommand,
            lease: leaseA,
        });
        adapterA.dispatchAttempt("terminal-a", leaseA);
        adapterA.observeAttempt("terminal-a", leaseA);
        const leaseB = repositoryB.acquireLease({
            investigationId: "inv-runtime",
            leaseId: "lease-b",
            owner: "runner-b",
        });
        const beforeStaleWrite = domainPersistenceSnapshot(repositoryB);

        expect(() => adapterA.appendKernelDecisionFenced({
            attemptId: "terminal-a",
            command: terminalCommand,
            lease: leaseA,
            expectedDomainFactHash: factHash,
        })).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        }));
        expect(domainPersistenceSnapshot(repositoryB)).toEqual(beforeStaleWrite);
        expect(repositoryB.getTerminalEvent("inv-runtime")).toBeNull();

        adapterB.recoverStaleAttempts(leaseB);
        adapterB.reserveAttempt({
            attemptId: "terminal-b",
            command: terminalCommand,
            lease: leaseB,
        });
        adapterB.dispatchAttempt("terminal-b", leaseB);
        adapterB.observeAttempt("terminal-b", leaseB);
        adapterB.appendKernelDecisionFenced({
            attemptId: "terminal-b",
            command: terminalCommand,
            lease: leaseB,
            expectedDomainFactHash: factHash,
        });
        expect(repositoryB.listEvents("inv-runtime")
            .filter((event) => event.isTerminal)).toHaveLength(1);
        expect(repositoryB.getCommandAttempt("terminal-b").state).toBe("committed");
        expect(() => adapterB.appendKernelDecisionFenced({
            attemptId: "terminal-b",
            command: terminalCommand,
            lease: leaseB,
            expectedDomainFactHash: factHash,
        })).toThrow(expect.objectContaining({
            code: PERSISTENCE_ERROR_CODES.ILLEGAL_TRANSITION,
        }));
        expect(repositoryB.listEvents("inv-runtime")
            .filter((event) => event.isTerminal)).toHaveLength(1);
    });
});
