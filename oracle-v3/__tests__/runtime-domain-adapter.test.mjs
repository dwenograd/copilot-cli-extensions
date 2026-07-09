import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    EVENT_TYPES,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructKernelDecisionEvent,
    createExternalEvent,
    createInvestigationContract,
    hashCanonical,
} from "../domain/index.mjs";
import {
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

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-adapter-${label}-`));
    roots.push(root);
    return root;
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
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
        criticality: "high",
        policyVersion: "policy-v1",
        parserVersion: PARSER_VERSION,
        workerModels: ["model-a"],
        candidatesPerRound: 1,
        maxRounds: 2,
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        declaredLimits: { maxCommands: 10 },
        ...overrides,
    };
}

function openAdapter(label = "db") {
    const root = makeRoot(label);
    const repository = openRepository({ file: path.join(root, "events.sqlite") });
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: "inv-runtime",
    });
    return { root, repository, adapter };
}

function harnessReceipt(attemptId, candidate = false) {
    return {
        attemptId,
        runnerEpochId: "runner-epoch",
        rawStdoutHash: hashCanonical({ attemptId, stream: "stdout" }),
        rawStderrHash: hashCanonical({ attemptId, stream: "stderr" }),
        candidateArtifactHash: candidate
            ? hashCanonical({ attemptId, artifact: true })
            : null,
    };
}

function appendFullVerifiedHistory(adapter) {
    let aggregate = adapter.openInvestigation(
        createInvestigationContract(contractInput()),
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
            receipt: harnessReceipt("validation-attempt"),
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
            round: 1,
            candidateId: "candidate-a",
            receipt: harnessReceipt("candidate-attempt", true),
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
    aggregate = adapter.appendDomainEvent(
        constructKernelDecisionEvent(aggregate),
        { aggregate },
    ).aggregate;
    return aggregate;
}

describe("Oracle v3 domain/persistence adapter", () => {
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
        repository.close();
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
        repository.close();
    });

    it("detects repository tampering before domain replay", () => {
        const { root, repository, adapter } = openAdapter("repo-tamper");
        adapter.openInvestigation(createInvestigationContract(contractInput()));
        repository.close();

        const raw = new DatabaseSync(path.join(root, "events.sqlite"));
        raw.exec("PRAGMA journal_mode=WAL;");
        raw.prepare("UPDATE events SET payload = ? WHERE investigation_id = ? AND seq = 1")
            .run(JSON.stringify({ domainEvent: { forged: true } }), "inv-runtime");
        raw.close();

        const reopened = openRepository({ file: path.join(root, "events.sqlite") });
        const replayAdapter = createDomainRepositoryAdapter({
            repository: reopened,
            investigationId: "inv-runtime",
        });
        expect(() => replayAdapter.replay()).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.INTEGRITY_FAILURE,
        }));
        reopened.close();
    });

    it("detects a forged domain event even when the repository hash is recomputed", () => {
        const { root, repository, adapter } = openAdapter("domain-tamper");
        adapter.openInvestigation(createInvestigationContract(contractInput()));
        const row = repository.getEvent("inv-runtime", 1);
        repository.close();

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
        raw.exec("PRAGMA journal_mode=WAL;");
        raw.prepare("UPDATE events SET payload = ?, event_hash = ? WHERE investigation_id = ? AND seq = 1")
            .run(payloadCanonical, repositoryHash, "inv-runtime");
        raw.close();

        const reopened = openRepository({ file: path.join(root, "events.sqlite") });
        const replayAdapter = createDomainRepositoryAdapter({
            repository: reopened,
            investigationId: "inv-runtime",
        });
        expect(reopened.verifyInvestigation("inv-runtime").ok).toBe(true);
        expect(() => replayAdapter.replay()).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.INTEGRITY_FAILURE,
        }));
        reopened.close();
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
        repository.close();
    });
});
