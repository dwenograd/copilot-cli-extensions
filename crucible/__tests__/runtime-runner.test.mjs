import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    createInvestigationContract,
    harnessCandidateEvidenceItems,
} from "../domain/index.mjs";
import {
    PARSER_VERSION,
} from "../measurement/index.mjs";
import {
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";
import {
    InjectedCrashError,
    createDomainRepositoryAdapter,
    requestStop,
    runAutonomousInvestigation,
} from "../runtime/index.mjs";
import {
    NODE_EXE,
    nodeExeSha256Hex,
    sha256HexOfFile,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-runner-${label}-`));
    roots.push(root);
    return root;
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function seedSnapshot(store, root, name, score) {
    const source = path.join(root, `snapshot-${name}`);
    fs.mkdirSync(source, { recursive: true });
    fs.writeFileSync(path.join(source, "score.txt"), `${score}\n`);
    return store.ingestDirectory({ sourceDir: source }).snapshot;
}

function writeRuntimeAllowlist(root, harnessId, scriptPath, validationCases) {
    const allowlistPath = path.join(root, "harness.allowlist.json");
    fs.writeFileSync(allowlistPath, JSON.stringify({
        version: 1,
        entries: {
            [harnessId]: {
                executable: NODE_EXE,
                executableSha256: nodeExeSha256Hex(),
                argvTemplate: [scriptPath, "{{candidatePath}}"],
                dependencies: [{
                    path: scriptPath,
                    sha256: sha256HexOfFile(scriptPath),
                    role: "harness-script",
                }],
                timeoutMs: 15_000,
                maxStdoutBytes: 1024 * 1024,
                maxStderrBytes: 256 * 1024,
                executesCandidateCode: false,
                validationCases: Object.fromEntries(
                    Object.entries(validationCases).map(([id, snapshot]) => [
                        id,
                        { snapshotHash: snapshot },
                    ]),
                ),
            },
        },
    }, null, 2));
    return allowlistPath;
}

function makeContract({
    goodSnapshot,
    badSnapshot,
    boundedCandidateIds,
    candidatesPerRound = 1,
    maxRounds = 4,
    maxCommands = 20,
} = {}) {
    return createInvestigationContract({
        objective: "Find a candidate whose trusted score is at least 90",
        acceptancePredicate: {
            kind: "all",
            predicates: [
                { kind: "harness_pass" },
                { kind: "metric_compare", metric: "score", operator: ">=", value: 90 },
            ],
        },
        validationCases: [
            { id: "known-good", expectation: "accept", artifactHash: goodSnapshot },
            { id: "known-bad", expectation: "reject", artifactHash: badSnapshot },
        ],
        harnessId: "score-harness",
        hypothesisTopology: boundedCandidateIds === undefined
            ? "open_generative"
            : "finite_enumerable",
        criticality: "high",
        policyVersion: "policy-v1",
        parserVersion: PARSER_VERSION,
        workerModels: ["model-a", "model-b"],
        candidatesPerRound,
        maxRounds,
        ...(boundedCandidateIds === undefined ? {} : { boundedCandidateIds }),
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        declaredLimits: { maxCommands },
    });
}

function deterministicIds() {
    let next = 0;
    return () => `fixture-id-${++next}`;
}

class FakeWorkerPool {
    constructor(scores) {
        this.scores = [...scores];
        this.calls = [];
        this.released = [];
        this.closed = false;
    }
    async propose(request) {
        this.calls.push(request);
        const score = this.scores.length === 0 ? 0 : this.scores.shift();
        const candidateId = request.allowedCandidateIds[0];
        return {
            candidateId,
            mechanism: `Fixture score ${score}`,
            files: [{ path: "score.txt", content: `${score}\n` }],
            identity: {
                invocationSessionId: request.sessionId,
                configuredModel: request.model,
                challengeNonce: request.challengeNonce,
                promptHash: `sha256:fixture-prompt:${"a".repeat(64)}`,
                payloadHash: `sha256:fixture-payload:${"b".repeat(64)}`,
            },
        };
    }
    releaseCandidateId(candidateId) {
        this.released.push(candidateId);
    }
    async close() {
        this.closed = true;
    }
}

function setupInvestigation(label, contractOptions = {}) {
    const root = makeRoot(label);
    const stateDir = path.join(root, "state");
    const artifactRoot = path.join(root, "artifacts");
    fs.mkdirSync(stateDir, { recursive: true });
    const store = openArtifactStore({ root: artifactRoot });
    const goodSnapshot = seedSnapshot(store, root, "good", 100);
    const badSnapshot = seedSnapshot(store, root, "bad", 10);
    const scriptPath = writeHarnessScript(root, "score-harness", `
        const candidatePath = process.argv[2];
        const score = Number(fs.readFileSync(path.join(candidatePath, "score.txt"), "utf8").trim());
        process.stdout.write(JSON.stringify({
            pass: Number.isFinite(score) && score >= 90,
            metrics: { score }
        }));
    `);
    const allowlistPath = writeRuntimeAllowlist(root, "score-harness", scriptPath, {
        "known-good": goodSnapshot,
        "known-bad": badSnapshot,
    });
    const contract = makeContract({
        goodSnapshot,
        badSnapshot,
        ...contractOptions,
    });
    const repository = openRepository({ file: path.join(stateDir, "events.sqlite") });
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: "runtime-investigation",
    });
    adapter.openInvestigation(contract);
    repository.close();

    const config = {
        investigationId: "runtime-investigation",
        stateDir,
        artifactRoot,
        allowlistPath,
        copilotSdkPath: path.join(root, "unused-sdk"),
        copilotCliPath: path.join(root, "unused-copilot.exe"),
        runnerEpochId: "runner-epoch-1",
        deadline: Date.now() + 120_000,
        options: {
            maxLoopIterations: 1000,
            sessionTimeoutMs: 5000,
        },
    };
    return {
        root,
        stateDir,
        artifactRoot,
        allowlistPath,
        contract,
        config,
    };
}

function replaySetup(setup) {
    const repository = openRepository({ file: path.join(setup.stateDir, "events.sqlite") });
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: "runtime-investigation",
    });
    const replayed = adapter.replay();
    return { repository, adapter, ...replayed };
}

function runnerDependencies(workerPool, extra = {}) {
    return {
        workerPool,
        idFactory: deterministicIds(),
        ...extra,
    };
}

describe("Oracle v3 autonomous runner", () => {
    it("validates both frozen sides, measures concurrent proposals, and verifies unattended", async () => {
        const setup = setupInvestigation("positive", {
            candidatesPerRound: 2,
            maxRounds: 3,
        });
        const pool = new FakeWorkerPool([95, 80, 96, 70]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );

        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
            tempRootCleaned: true,
        });
        expect(pool.calls).toHaveLength(4);
        expect(pool.calls.map((call) => call.model)).toEqual([
            "model-a",
            "model-b",
            "model-a",
            "model-b",
        ]);
        expect(pool.closed).toBe(true);

        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal.decision).toBe("VERIFIED_RESULT");
        expect(replayed.aggregate.capabilityEpochs["runner-epoch-1"].capabilities)
            .toContain("oracle-v3-autonomous-runtime");
        expect(replayed.aggregate.commandOrder.every((commandId) =>
            replayed.aggregate.commands[commandId].capabilityEpochId === "runner-epoch-1"))
            .toBe(true);
        const validationObservation = replayed.aggregate.observations[
            replayed.aggregate.observationOrder.find((id) =>
                replayed.aggregate.observations[id].purpose === "validation")
        ];
        expect(validationObservation.data.caseMap).toMatchObject({
            "known-good": { expectation: "accept", outcome: "accept", matched: true },
            "known-bad": { expectation: "reject", outcome: "reject", matched: true },
        });
        expect(validationObservation.data.compositeReceiptHash).toMatch(
            /^sha256:oracle-runtime-validation-receipts-v1:[a-f0-9]{64}$/,
        );
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(2);

        const operational = replayed.repository.listEvents(replayed.adapter.operationalInvestigationId);
        const candidateMeasurements = operational.filter((row) =>
            row.kind === "runtime:measurement" && row.payload.purpose === "candidate");
        expect(candidateMeasurements).toHaveLength(4);
        expect(replayed.repository.listArtifactRefs("runtime-investigation").length)
            .toBeGreaterThanOrEqual(12);
        replayed.repository.close();

        const tempRoot = path.join(setup.stateDir, "runtime-temp");
        expect(fs.existsSync(tempRoot)).toBe(true);
        expect(fs.readdirSync(tempRoot)).toEqual([]);
    }, 60_000);

    it("persists a command-budget non-result after successful validation", async () => {
        const setup = setupInvestigation("budget", { maxCommands: 1 });
        const pool = new FakeWorkerPool([]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "BUDGET_EXHAUSTED_INCONCLUSIVE",
        });
        expect(pool.calls).toHaveLength(0);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.status).toBe("non_result");
        expect(replayed.aggregate.terminal).toBeNull();
        replayed.repository.close();
    }, 60_000);

    it("records a deadline non-result and never emits TARGET_UNREACHABLE", async () => {
        const setup = setupInvestigation("deadline");
        const pool = new FakeWorkerPool([]);
        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline: Date.now() - 1,
        }, runnerDependencies(pool));
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            terminalEmitted: false,
        });
        expect(pool.calls).toHaveLength(0);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(replayed.repository.getTerminalEvent("runtime-investigation")).toBeNull();
        expect(replayed.repository.listEvents(replayed.adapter.operationalInvestigationId)
            .some((row) => row.kind === "runtime:non_result")).toBe(true);
        replayed.repository.close();

        const replayedResult = await runAutonomousInvestigation({
            ...setup.config,
            deadline: Date.now() + 60_000,
        }, runnerDependencies(new FakeWorkerPool([])));
        expect(replayedResult).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            persisted: true,
        });
    });

    it("emits TARGET_UNREACHABLE only after exhausting every frozen bounded id", async () => {
        const setup = setupInvestigation("bounded", {
            boundedCandidateIds: ["candidate-a", "candidate-b"],
            candidatesPerRound: 1,
            maxRounds: 2,
        });
        const pool = new FakeWorkerPool([20, 30]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
        });
        expect(pool.calls.map((call) => call.allowedCandidateIds)).toEqual([
            ["candidate-a"],
            ["candidate-b"],
        ]);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal.basis.boundedCandidateIds).toEqual([
            "candidate-a",
            "candidate-b",
        ]);
        replayed.repository.close();
    }, 60_000);

    it("honours a persisted stop request by validating and then pausing", async () => {
        const setup = setupInvestigation("pause");
        const stop = requestStop({
            stateDir: setup.stateDir,
            investigationId: "runtime-investigation",
            reason: "Operator requested pause",
            requestId: "stop-before-run",
        });
        expect(stop.appended).toBe(true);

        const pool = new FakeWorkerPool([]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expect(result).toMatchObject({
            kind: "PAUSE",
            code: "INVESTIGATION_PAUSED",
        });
        expect(pool.calls).toHaveLength(0);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.status).toBe("paused");
        replayed.repository.close();
    }, 60_000);

    it.each([
        ["after_reservation", 0],
        ["after_dispatch", 1],
    ])("recovers a crash at %s with a newer fenced attempt", async (point, uncertain) => {
        const setup = setupInvestigation(`crash-${point}`, { maxCommands: 1 });
        const firstPool = new FakeWorkerPool([]);
        let injected = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(firstPool, {
                faultInjector(observedPoint) {
                    if (!injected && observedPoint === point) {
                        injected = true;
                        throw new InjectedCrashError(point);
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: "ORACLE_V3_RUNTIME_INJECTED_CRASH",
        });
        expect(fs.readdirSync(path.join(setup.stateDir, "runtime-temp"))).toEqual([]);

        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new FakeWorkerPool([])),
        );
        expect(result.kind).toBe("NON_RESULT");
        expect(result.recovery).toMatchObject({
            abandonedCount: 1,
            uncertainDispatched: uncertain,
        });
        const replayed = replaySetup(setup);
        const attempts = replayed.repository.listCommandAttempts("runtime-investigation");
        expect(attempts.filter((attempt) => attempt.state === "abandoned")).toHaveLength(1);
        expect(attempts.some((attempt) => attempt.state === "committed")).toBe(true);
        replayed.repository.close();
    }, 60_000);
});
