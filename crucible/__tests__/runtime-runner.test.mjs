import { afterEach, describe, expect, it } from "vitest";
import { spawn as childSpawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    DEFAULT_SEARCH_POLICY,
    ESCAPE_SEARCH_OPERATORS,
    artifactRefsFromProvenance,
    createInvestigationContract,
    harnessCandidateEvidenceItems,
    impossibilityEvidenceItems,
} from "../domain/index.mjs";
import {
    PARSER_VERSION,
    createSandboxProvider,
} from "../measurement/index.mjs";
import {
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";
import {
    InjectedCrashError,
    READ_PARENT_ARTIFACT_TOOL_NAME,
    SUBMIT_CANDIDATE_TOOL_NAME,
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

function writeRuntimeAllowlist(
    root,
    harnessId,
    scriptPath,
    validationCases,
    executesCandidateCode = false,
) {
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
                executesCandidateCode,
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
    hypothesisTopology,
    candidatesPerRound = 1,
    maxRounds = 4,
    maxCommands = 20,
    searchPolicy = {},
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
        hypothesisTopology: hypothesisTopology
            ?? (boundedCandidateIds === undefined
                ? "open_generative"
                : "finite_enumerable"),
        criticality: "high",
        policyVersion: "policy-v1",
        parserVersion: PARSER_VERSION,
        workerModels: ["model-a", "model-b"],
        candidatesPerRound,
        maxRounds,
        ...(boundedCandidateIds === undefined ? {} : { boundedCandidateIds }),
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        searchPolicy: {
            ...DEFAULT_SEARCH_POLICY,
            ...searchPolicy,
            operatorWeights: {
                ...DEFAULT_SEARCH_POLICY.operatorWeights,
                ...searchPolicy.operatorWeights,
            },
            archiveCaps: {
                ...DEFAULT_SEARCH_POLICY.archiveCaps,
                ...searchPolicy.archiveCaps,
            },
            promptCaps: {
                ...DEFAULT_SEARCH_POLICY.promptCaps,
                ...searchPolicy.promptCaps,
            },
        },
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
        const next = this.scores.length === 0 ? 0 : this.scores.shift();
        const value = typeof next === "function"
            ? next(request, this.calls.length - 1)
            : next;
        const spec = value !== null && typeof value === "object"
            ? value
            : { score: value };
        const score = spec.score ?? 0;
        const candidateId = request.candidateId ?? request.allowedCandidateIds[0];
        return {
            candidateId,
            mechanism: spec.mechanism ?? `Fixture score ${score}`,
            annotations: spec.annotations ?? {
                finding: `Fixture outcome requested score ${String(score)}`,
            },
            files: [{
                path: "score.txt",
                content: spec.content ?? `${score}\n`,
            }],
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

function setupInvestigation(label, contractOptions = {}, {
    countHarnessCalls = false,
    impossibilityResult = null,
    executesCandidateCode = false,
} = {}) {
    const root = makeRoot(label);
    const stateDir = path.join(root, "state");
    const artifactRoot = path.join(root, "artifacts");
    fs.mkdirSync(stateDir, { recursive: true });
    const store = openArtifactStore({ root: artifactRoot });
    const goodSnapshot = seedSnapshot(store, root, "good", 100);
    const badSnapshot = seedSnapshot(store, root, "bad", 10);
    const harnessCounterPath = path.join(root, "harness-call-count.txt");
    const countHarnessCall = countHarnessCalls
        ? `fs.appendFileSync(${JSON.stringify(harnessCounterPath)}, "1\\n");`
        : "";
    const certificateResult = impossibilityResult ?? {
        pass: false,
        searchSpaceExhausted: false,
    };
    const scriptPath = writeHarnessScript(root, "score-harness", `
        ${countHarnessCall}
        const candidatePath = process.argv[2];
        const impossibilityRequest = path.join(
            candidatePath,
            "crucible-impossibility-request.json",
        );
        if (fs.existsSync(impossibilityRequest)) {
            process.stdout.write(JSON.stringify(${JSON.stringify(certificateResult)}));
        } else {
            const raw = fs.readFileSync(path.join(candidatePath, "score.txt"), "utf8").trim();
            const score = Number(raw);
            process.stdout.write(JSON.stringify({
                pass: Number.isFinite(score) && score >= 90,
                metrics: raw === "omit" ? {} : { score }
            }));
        }
    `);
    const allowlistPath = writeRuntimeAllowlist(root, "score-harness", scriptPath, {
        "known-good": goodSnapshot,
        "known-bad": badSnapshot,
    }, executesCandidateCode);
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
        harnessCounterPath,
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

function harnessCallCount(setup) {
    if (!fs.existsSync(setup.harnessCounterPath)) {
        return 0;
    }
    return fs.readFileSync(setup.harnessCounterPath, "utf8")
        .split(/\r?\n/u)
        .filter(Boolean)
        .length;
}

function clonePersistedSetup(setup, label) {
    const root = makeRoot(label);
    const stateDir = path.join(root, "state");
    const artifactRoot = path.join(root, "artifacts");
    fs.cpSync(setup.stateDir, stateDir, { recursive: true });
    fs.cpSync(setup.artifactRoot, artifactRoot, { recursive: true });
    return {
        ...setup,
        root,
        stateDir,
        artifactRoot,
        config: {
            ...setup.config,
            stateDir,
            artifactRoot,
            deadline: Date.now() + 120_000,
        },
    };
}

function runnerDependencies(workerPool, extra = {}) {
    return {
        workerPool,
        idFactory: deterministicIds(),
        ...extra,
    };
}

function createRunnerContainmentProvider(calls) {
    let nextCapability = 0;
    return createSandboxProvider({
        providerId: "runner-fixture-containment",
        providerVersion: "v1",
        admitAndPrepare(request, issueLaunchCapability) {
            calls.admissions.push(request);
            let child = null;
            return issueLaunchCapability({
                capabilityId: `runner-capability-${++nextCapability}`,
                policyId: "runner-fixture-policy",
                policyDigest:
                    `sha256:runner-fixture-policy-v1:${"c".repeat(64)}`,
                permittedStagedRoots: request.stagedRoots,
                launch(launchRequest) {
                    calls.launches.push(launchRequest);
                    child = childSpawn(
                        launchRequest.executable,
                        launchRequest.argv,
                        {
                            cwd: launchRequest.options.cwd,
                            env: launchRequest.options.env,
                            stdio: launchRequest.options.stdio,
                            shell: false,
                            windowsHide: true,
                            detached: true,
                        },
                    );
                    return child;
                },
                terminate(terminationRequest) {
                    calls.terminations.push(terminationRequest);
                    if (child?.pid === terminationRequest.pid && !child.killed) {
                        child.kill("SIGKILL");
                    }
                    return true;
                },
                cleanup(cleanupRequest) {
                    calls.cleanups.push(cleanupRequest);
                    return true;
                },
            });
        },
    });
}

describe("Crucible autonomous runner", () => {
    it("commits one candidate evidence for every adaptive slot", async () => {
        const setup = setupInvestigation("positive", {
            candidatesPerRound: 2,
            maxRounds: 2,
        });
        const pool = new FakeWorkerPool([95, 80, 96, 70]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );

        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
            candidateId: "candidate-r000002-s000",
            tempRootCleaned: true,
        });
        expect(pool.calls).toHaveLength(4);
        expect(pool.calls.map((call) => call.model)).toEqual([
            "model-a",
            "model-b",
            "model-a",
            "model-b",
        ]);
        expect(pool.calls.map((call) => call.candidateId)).toEqual([
            "candidate-r000001-s000",
            "candidate-r000001-s001",
            "candidate-r000002-s000",
            "candidate-r000002-s001",
        ]);
        expect(pool.calls.every((call) =>
            Number.isSafeInteger(call.seed)
            && typeof call.operator === "string"
            && call.allowedCandidateIds[0] === call.candidateId)).toBe(true);
        expect(pool.closed).toBe(true);

        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal.decision).toBe("VERIFIED_RESULT");
        expect(replayed.aggregate.capabilityEpochs["runner-epoch-1"].capabilities)
            .toContain("crucible-autonomous-runtime");
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
            /^sha256:crucible-runtime-validation-receipts-v1:[a-f0-9]{64}$/,
        );
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(4);
        const validationEvidence = replayed.aggregate.evidence[
            replayed.aggregate.validation.currentEvidenceId
        ];
        expect(validationEvidence.receipt.provenance).toMatchObject({
            proposalArtifact: null,
            validationCompositeArtifact: {
                artifactId: expect.any(String),
                objectId: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
            },
        });
        expect(validationEvidence.receipt.provenance.measurements).toHaveLength(2);
        const candidateEvidence = harnessCandidateEvidenceItems(replayed.aggregate)[0];
        expect(candidateEvidence.receipt.provenance).toMatchObject({
            proposalArtifact: {
                artifactId: expect.any(String),
                objectId: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
            },
            promptContextHash: expect.stringMatching(
                /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/,
            ),
        });
        expect(candidateEvidence.receipt.provenance.measurements[0]).toMatchObject({
            parserVersion: PARSER_VERSION,
            sandboxPolicy: { kind: "none" },
            receiptArtifact: { artifactId: expect.any(String) },
            rawStdoutArtifact: { artifactId: expect.any(String) },
            rawStderrArtifact: { artifactId: expect.any(String) },
            snapshot: {
                manifestArtifact: { artifactId: expect.any(String) },
                objectArtifacts: expect.any(Array),
            },
        });
        expect(replayed.aggregate.terminal.evidenceClosure).toMatchObject({
            decisive: {
                kind: "winner",
                evidence: {
                    evidenceId: replayed.aggregate.terminal.evidenceId,
                },
            },
            receipts: { count: 6, evidenceCount: 5 },
        });
        expect(replayed.aggregate.terminal.evidenceClosure.closureRoot).toMatch(
            /^sha256:crucible-terminal-evidence-closure-v1:[a-f0-9]{64}$/,
        );
        for (const evidenceId of replayed.aggregate.evidenceOrder) {
            const evidence = replayed.aggregate.evidence[evidenceId];
            const expectedArtifactIds = artifactRefsFromProvenance(
                evidence.receipt.provenance,
            ).map((artifact) => artifact.artifactId).sort();
            expect(
                replayed.repository
                    .listArtifactRefsForEvent(
                        "runtime-investigation",
                        evidence.committedSeq,
                    )
                    .map((ref) => ref.artifactId)
                    .sort(),
            ).toEqual(expectedArtifactIds);
        }

        const operational = replayed.repository.listEvents(replayed.adapter.operationalInvestigationId);
        const candidateMeasurements = operational.filter((row) =>
            row.kind === "runtime:measurement" && row.payload.purpose === "candidate");
        expect(candidateMeasurements).toHaveLength(4);
        const persistedReceipt = candidateMeasurements[0].payload.receipt;
        expect(persistedReceipt.version).toBe(3);
        expect(persistedReceipt.candidateSnapshotPreClosureHash).toMatch(
            /^sha256:crucible-measurement-snapshot-closure-v1:[a-f0-9]{64}$/,
        );
        expect(persistedReceipt.candidateSnapshotPostClosureHash)
            .toBe(persistedReceipt.candidateSnapshotPreClosureHash);
        expect(persistedReceipt.candidateSnapshotIdentitySummary.pre)
            .toEqual(persistedReceipt.candidateSnapshotIdentitySummary.post);
        expect(persistedReceipt.candidateSnapshotMutationCheck.status).toBe("passed");
        expect(persistedReceipt.stagedExecutableHash)
            .toBe(persistedReceipt.executableHash);
        expect(
            persistedReceipt.stagedDependencyHashes.map((item) => item.sha256).sort(),
        ).toEqual(
            persistedReceipt.dependencyHashes.map((item) => item.sha256).sort(),
        );
        expect(replayed.repository.listArtifactRefs("runtime-investigation").length)
            .toBeGreaterThanOrEqual(12);
        replayed.repository.close();

        const tempRoot = path.join(setup.stateDir, "runtime-temp");
        expect(fs.existsSync(tempRoot)).toBe(true);
        expect(fs.readdirSync(tempRoot)).toEqual([]);
    }, 60_000);

    it("configures and persists capability-launched measurements from the Windows provider factory", async () => {
        const setup = setupInvestigation(
            "sandbox-capability",
            { maxRounds: 1 },
            { executesCandidateCode: true },
        );
        const calls = {
            admissions: [],
            launches: [],
            terminations: [],
            cleanups: [],
            hostLaunches: 0,
            hostTerminations: 0,
        };
        const providerControlRoots = [];
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new FakeWorkerPool([95]), {
                windowsSandboxProviderFactory(options) {
                    providerControlRoots.push(options.controlRoot);
                    return createRunnerContainmentProvider(calls);
                },
                processAdapter: {
                    spawn() {
                        calls.hostLaunches += 1;
                        throw new Error("host adapter must not launch candidate code");
                    },
                    terminateTree() {
                        calls.hostTerminations += 1;
                        return false;
                    },
                },
            }),
        );

        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
        });
        expect(calls.hostLaunches).toBe(0);
        expect(calls.hostTerminations).toBe(0);
        expect(providerControlRoots).toHaveLength(1);
        expect(providerControlRoots[0]).toContain(
            path.join("runtime-temp", "run-runner-epoch-1"),
        );
        expect(calls.admissions.length).toBeGreaterThanOrEqual(3);
        expect(calls.launches).toHaveLength(calls.admissions.length);
        expect(calls.cleanups).toHaveLength(calls.admissions.length);
        expect(calls.terminations).toHaveLength(0);

        const replayed = replaySetup(setup);
        const measurements = replayed.adapter.listOperationalEvidence()
            .filter((row) => row.kind === "runtime:measurement");
        expect(measurements).toHaveLength(calls.launches.length);
        for (const measurement of measurements) {
            expect(measurement.payload.receipt.sandbox).toMatchObject({
                providerId: "runner-fixture-containment",
                providerVersion: "v1",
                policyId: "runner-fixture-policy",
                policyDigest:
                    `sha256:runner-fixture-policy-v1:${"c".repeat(64)}`,
                capabilityId: expect.stringMatching(/^runner-capability-\d+$/u),
                launchPath: "sandbox-capability",
                capabilityLaunchUsed: true,
            });
            expect(measurement.payload.measurementProvenance.sandboxPolicy)
                .toMatchObject({
                    kind: "sandbox",
                    environmentHash:
                        `sha256:runner-fixture-policy-v1:${"c".repeat(64)}`,
                });
        }
        expect(replayed.aggregate.terminal.evidenceClosure.closureRoot).toMatch(
            /^sha256:crucible-terminal-evidence-closure-v1:[a-f0-9]{64}$/u,
        );
        replayed.repository.close();
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
        expect(replayed.aggregate.terminal.basis).toMatchObject({
            boundedCandidateCount: 2,
            searchSpaceExhausted: true,
        });
        expect(replayed.aggregate.terminal.basis.boundedCandidateIdsHash).toMatch(
            /^sha256:crucible-bounded-candidate-set-v1:[a-f0-9]{64}$/,
        );
        expect(replayed.aggregate.terminal.evidenceClosure).toMatchObject({
            decisive: { kind: "bounded_search", evidence: null },
            receipts: { count: 4, evidenceCount: 3 },
        });
        replayed.repository.close();
    }, 60_000);

    it("runs the allowlisted verifier and persists a positive impossibility certificate", async () => {
        const setup = setupInvestigation(
            "certified-positive",
            {
                hypothesisTopology: "certified_impossibility",
                candidatesPerRound: 1,
                maxRounds: 1,
            },
            {
                countHarnessCalls: true,
                impossibilityResult: {
                    pass: true,
                    searchSpaceExhausted: true,
                },
            },
        );
        const pool = new FakeWorkerPool([20]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
            tempRootCleaned: true,
        });
        expect(pool.calls).toHaveLength(1);
        expect(harnessCallCount(setup)).toBe(4);

        const replayed = replaySetup(setup);
        expect(replayed.aggregate.commandOrder.map((commandId) =>
            replayed.aggregate.commands[commandId].command.kind)).toEqual([
            "run_validation",
            "search_candidate",
            "verify_impossibility",
        ]);
        const [certificateEvidence] = impossibilityEvidenceItems(replayed.aggregate);
        expect(certificateEvidence.unreachableBasis).toMatchObject({
            kind: "verified_impossibility_certificate",
            certificateVerdict: "target_unreachable",
        });
        expect(replayed.aggregate.terminal.basis).toMatchObject({
            kind: "verified_impossibility_certificate",
            certificateArtifactHash:
                certificateEvidence.unreachableBasis.certificateArtifactHash,
        });
        expect(certificateEvidence.receipt.provenance).toMatchObject({
            proposalArtifact: null,
            validationCompositeArtifact: null,
            measurementReuseArtifact: null,
            impossibilityCertificateArtifact: {
                artifactId: certificateEvidence.unreachableBasis.certificateArtifactId,
            },
        });
        expect(replayed.aggregate.terminal.evidenceClosure).toMatchObject({
            validation: {
                evidenceId: replayed.aggregate.validation.currentEvidenceId,
            },
            decisive: {
                kind: "impossibility_certificate",
                evidence: {
                    evidenceId: certificateEvidence.evidenceId,
                    provenanceRoot: certificateEvidence.provenanceRoot,
                },
            },
            receipts: { count: 4, evidenceCount: 3 },
        });
        const operational = replayed.adapter.listOperationalEvidence();
        const certificateRow = operational.find((row) =>
            row.kind === "runtime:impossibility_certificate");
        expect(certificateRow?.payload).toMatchObject({
            certificateVerdict: "target_unreachable",
        });
        for (const field of [
            "certificateArtifactHash",
            "measurementReceiptArtifactHash",
            "measurementReceiptHash",
            "rawStderrArtifactHash",
            "rawStdoutArtifactHash",
            "verificationSnapshotHash",
        ]) {
            expect(certificateRow.payload[field]).toMatch(
                /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u,
            );
        }
        expect(replayed.repository.getArtifact(certificateRow.payload.certificateArtifactId))
            .toMatchObject({ durable: true, storage: "external" });
        expect(replayed.repository.getArtifact(certificateRow.payload.rawStdoutArtifactId))
            .toMatchObject({ durable: true, storage: "external" });
        expect(replayed.repository.getArtifact(
            certificateRow.payload.measurementReceiptArtifactId,
        )).toMatchObject({ durable: true, storage: "external" });
        replayed.repository.close();
    }, 60_000);

    it.each([
        ["not_proven", { pass: false, searchSpaceExhausted: true }],
        ["invalid", { pass: true, searchSpaceExhausted: false }],
    ])("keeps a %s impossibility certificate as a non-result", async (verdict, output) => {
        const setup = setupInvestigation(
            `certified-${verdict}`,
            {
                hypothesisTopology: "certified_impossibility",
                candidatesPerRound: 1,
                maxRounds: 1,
            },
            { impossibilityResult: output },
        );
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new FakeWorkerPool([20])),
        );
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE",
        });
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(replayed.aggregate.nonResults.at(-1)).toMatchObject({
            code: "IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE",
            certificateVerdict: verdict,
        });
        expect(impossibilityEvidenceItems(replayed.aggregate)[0].unreachableBasis)
            .toBeNull();
        replayed.repository.close();
    }, 60_000);

    it("recovers a committed impossibility verifier effect without re-execution", async () => {
        const setup = setupInvestigation(
            "certified-crash-recovery",
            {
                hypothesisTopology: "certified_impossibility",
                candidatesPerRound: 1,
                maxRounds: 1,
            },
            {
                countHarnessCalls: true,
                impossibilityResult: {
                    pass: true,
                    searchSpaceExhausted: true,
                },
            },
        );
        let injected = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new FakeWorkerPool([20]), {
                faultInjector(point, details) {
                    if (!injected
                        && point === "after_effect_commit"
                        && details.command?.kind === "impossibility-verification") {
                        injected = true;
                        throw new InjectedCrashError(point);
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: "CRUCIBLE_RUNTIME_INJECTED_CRASH",
        });
        expect(harnessCallCount(setup)).toBe(4);

        const branchA = clonePersistedSetup(setup, "certified-crash-branch-a");
        const branchB = clonePersistedSetup(setup, "certified-crash-branch-b");
        const resultA = await runAutonomousInvestigation(
            branchA.config,
            runnerDependencies(new FakeWorkerPool([])),
        );
        const resultB = await runAutonomousInvestigation(
            branchB.config,
            runnerDependencies(new FakeWorkerPool([])),
        );
        expect(resultA).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
        });
        expect(resultB).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
        });
        expect(harnessCallCount(setup)).toBe(4);
        const replayedA = replaySetup(branchA);
        const replayedB = replaySetup(branchB);
        expect(replayedA.aggregate.terminal.eventHash)
            .toBe(replayedB.aggregate.terminal.eventHash);
        expect(replayedA.aggregate.terminal.basis.certificateArtifactHash)
            .toBe(replayedB.aggregate.terminal.basis.certificateArtifactHash);
        replayedA.repository.close();
        replayedB.repository.close();
    }, 120_000);

    it("feeds generation-one outcomes and findings into generation two", async () => {
        const setup = setupInvestigation("prompt-context", {
            candidatesPerRound: 1,
            maxRounds: 2,
        });
        const pool = new FakeWorkerPool([
            {
                score: 40,
                mechanism: "generation-one-mechanism",
                annotations: {
                    hypothesis: "Generation one tests the baseline.",
                    expectedEffects: ["establish a baseline"],
                    finding: "generation-one-finding",
                },
            },
            50,
        ]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );

        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "BUDGET_EXHAUSTED_INCONCLUSIVE",
        });
        expect(pool.calls).toHaveLength(2);
        const second = pool.calls[1];
        expect(second.promptContext.assignment).toMatchObject({
            round: 2,
            slotIndex: 0,
            candidateId: "candidate-r000002-s000",
        });
        expect(second.promptContext.priorWork.failures).toHaveLength(1);
        expect(second.promptContext.priorWork.failures[0]).toMatchObject({
            evidenceId: "evidence-000002",
            mechanism: "generation-one-mechanism",
            finding: "generation-one-finding",
        });
        expect(second.promptContextHash).toMatch(
            /^sha256:crucible-runtime-prompt-context-v1:[a-f0-9]{64}$/,
        );
        expect(second.visibleEvidenceIds).toEqual(second.promptContextRefs);
        expect(second.prompt).toContain(`Trusted prompt context hash: ${second.promptContextHash}`);
        expect(second.prompt).toContain("generation-one-finding");
        const untrustedStart = second.prompt.indexOf("<<<CRUCIBLE_UNTRUSTED_DATA");
        expect(second.prompt.indexOf(`Operator ${second.operator.toUpperCase()}:`))
            .toBeLessThan(untrustedStart);
        expect(second.prompt.indexOf("Acceptance predicate:")).toBeLessThan(untrustedStart);
        expect(second.prompt.indexOf("Omitted history (capped):")).toBeLessThan(untrustedStart);
    }, 60_000);

    it("continues past the first accepted candidate and lets an escape operator win", async () => {
        const setup = setupInvestigation("plateau-escape", {
            candidatesPerRound: 1,
            maxRounds: 3,
            searchPolicy: {
                plateauWindow: 1,
                minRoundsBeforePlateau: 1,
                mandatoryEscapeRounds: 1,
            },
        });
        const pool = new FakeWorkerPool([
            {
                score: 90,
                mechanism: "same-mechanism",
                annotations: { finding: "same-finding" },
            },
            {
                score: 90,
                mechanism: "same-mechanism",
                annotations: { finding: "same-finding" },
            },
            (request) => ({
                score: ESCAPE_SEARCH_OPERATORS.includes(request.operator) ? 100 : 1,
                mechanism: "escape-mechanism",
                annotations: { finding: "escape-found-superior-candidate" },
            }),
        ]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );

        expect(pool.calls).toHaveLength(3);
        expect(ESCAPE_SEARCH_OPERATORS).toContain(pool.calls[2].operator);
        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
            candidateId: "candidate-r000003-s000",
        });
        const replayed = replaySetup(setup);
        const candidates = harnessCandidateEvidenceItems(replayed.aggregate);
        expect(candidates).toHaveLength(3);
        expect(candidates[0].outcomeClass).toBe("accepted");
        expect(candidates[2]).toMatchObject({
            candidateId: "candidate-r000003-s000",
            metrics: { score: 100 },
            outcomeClass: "accepted",
        });
        replayed.repository.close();
    }, 60_000);

    it("marks duplicate artifacts and reuses verified measurement evidence", async () => {
        const setup = setupInvestigation("duplicate", {
            candidatesPerRound: 1,
            maxRounds: 2,
        });
        const pool = new FakeWorkerPool([50, 50]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expect(result.kind).toBe("NON_RESULT");
        expect(pool.calls).toHaveLength(2);

        const replayed = replaySetup(setup);
        const candidates = harnessCandidateEvidenceItems(replayed.aggregate);
        expect(candidates).toHaveLength(2);
        expect(candidates[0].duplicateOf).toBeNull();
        expect(candidates[1].duplicateOf).toBe(candidates[0].evidenceId);
        const operational = replayed.adapter.listOperationalEvidence();
        expect(operational.filter((row) =>
            row.kind === "runtime:measurement" && row.payload.purpose === "candidate"))
            .toHaveLength(1);
        expect(operational.filter((row) => row.kind === "runtime:measurement_reuse"))
            .toHaveLength(1);
        replayed.repository.close();
    }, 60_000);

    it("commits parsed harness failures and non-rankable metrics as evidence", async () => {
        const setup = setupInvestigation("nonrankable", {
            candidatesPerRound: 1,
            maxRounds: 2,
        });
        const pool = new FakeWorkerPool([
            10,
            { score: null, content: "omit\n" },
        ]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expect(result.kind).toBe("NON_RESULT");

        const replayed = replaySetup(setup);
        const candidates = harnessCandidateEvidenceItems(replayed.aggregate);
        expect(candidates).toHaveLength(2);
        expect(candidates[0]).toMatchObject({
            acceptanceSatisfied: false,
            rankable: true,
        });
        expect(candidates[1]).toMatchObject({
            acceptanceSatisfied: false,
            rankable: false,
            outcomeClass: "invalid_metrics",
            metrics: {},
        });
        replayed.repository.close();
    }, 60_000);

    it("exposes only assigned parent snapshots to a worker-pool factory", async () => {
        const setup = setupInvestigation("parent-snapshot", {
            candidatesPerRound: 1,
            maxRounds: 2,
            searchPolicy: {
                operatorWeights: {
                    fresh: 1,
                    refinement: 1_000_000,
                    crossover: 0,
                    diversification: 1,
                    adversarial: 0,
                    restart: 0,
                },
            },
        });
        const calls = [];
        let factoryOptions;
        let assignedParentContent = null;
        let blockedUnassigned = false;
        const workerPoolFactory = (options) => {
            factoryOptions = options;
            return {
                async propose(request) {
                    calls.push(request);
                    if (request.parentEvidenceIds.length > 0) {
                        const evidenceId = request.parentEvidenceIds[0];
                        const parent = options.readParentSnapshot({
                            sessionId: request.sessionId,
                            evidenceId,
                        });
                        assignedParentContent = parent.files[0].content;
                        try {
                            options.readParentSnapshot({
                                sessionId: request.sessionId,
                                evidenceId: "evidence-not-assigned",
                            });
                        } catch (error) {
                            blockedUnassigned = error.code === "CRUCIBLE_RUNTIME_WORKER_PROTOCOL";
                        }
                    }
                    const score = calls.length === 1 ? 90 : 95;
                    return {
                        candidateId: request.candidateId,
                        mechanism: `factory-score-${score}`,
                        files: [{ path: "score.txt", content: `${score}\n` }],
                        identity: {
                            invocationSessionId: request.sessionId,
                            configuredModel: request.model,
                            challengeNonce: request.challengeNonce,
                        },
                    };
                },
                async close() {},
            };
        };
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(undefined, { workerPoolFactory }),
        );

        expect(result.kind).toBe("TERMINAL");
        expect(calls).toHaveLength(2);
        expect(calls[1].operator).toBe("refinement");
        expect(calls[1].parentEvidenceIds).toHaveLength(1);
        expect(calls[1].parents).toEqual([{
            parentId: calls[1].parentEvidenceIds[0],
            snapshotId: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
        }]);
        expect(calls[1].parentReadLimits).toMatchObject({
            maxCalls: expect.any(Number),
            maxChunkBytes: expect.any(Number),
        });
        expect(assignedParentContent).toBe("90\n");
        expect(blockedUnassigned).toBe(true);
        expect(factoryOptions.parentReader).toMatchObject({
            loadManifest: expect.any(Function),
            readObject: expect.any(Function),
        });
        expect(factoryOptions.parentSnapshotAccess).toMatchObject({
            verifySnapshot: expect.any(Function),
            readSnapshot: expect.any(Function),
            readObject: expect.any(Function),
        });
    }, 60_000);

    it("wires trusted bounded context, citations, and parent reads through the real default SDK pool", async () => {
        const setup = setupInvestigation("default-sdk-integration", {
            candidatesPerRound: 1,
            maxRounds: 2,
            searchPolicy: {
                operatorWeights: {
                    fresh: 1,
                    refinement: 1_000_000,
                    crossover: 0,
                    diversification: 1,
                    adversarial: 0,
                    restart: 1,
                },
            },
        });
        const captured = {
            prompts: [],
            configs: [],
            parentResults: [],
            started: false,
            stopped: false,
        };
        const sdkClient = {
            async start() {
                captured.started = true;
            },
            async stop() {
                captured.stopped = true;
            },
            async createSession(config) {
                captured.configs.push(config);
                return {
                    async sendAndWait({ prompt }) {
                        captured.prompts.push(prompt);
                        const candidateId = prompt.match(
                            /Your assigned candidateId is exactly: ([^\r\n]+)/u,
                        )?.[1];
                        const challenge = prompt.match(
                            /Your challenge nonce is exactly: ([^\r\n]+)/u,
                        )?.[1];
                        const parentTool = config.tools.find(
                            (tool) => tool.name === READ_PARENT_ARTIFACT_TOOL_NAME,
                        );
                        const submitTool = config.tools.find(
                            (tool) => tool.name === SUBMIT_CANDIDATE_TOOL_NAME,
                        );
                        const citations = [];
                        if (parentTool !== undefined) {
                            const parentIds = JSON.parse(prompt.match(
                                /Assigned parent evidence: (\[[^\r\n]+\])/u,
                            )[1]);
                            const parentId = parentIds[0];
                            citations.push(parentId);
                            const invocation = {
                                sessionId: config.sessionId,
                                toolName: parentTool.name,
                            };
                            const listed = await parentTool.handler({
                                challenge,
                                parentId,
                                op: "list",
                            }, invocation);
                            const read = await parentTool.handler({
                                challenge,
                                parentId,
                                op: "read",
                                path: "score.txt",
                                offset: 0,
                                length: 64,
                            }, invocation);
                            captured.parentResults.push({
                                listed: JSON.parse(listed.textResultForLlm),
                                read: JSON.parse(read.textResultForLlm),
                            });
                        }
                        const score = captured.prompts.length === 1 ? 90 : 95;
                        await submitTool.handler({
                            challenge,
                            candidateId,
                            annotations: {
                                mechanism: `default-sdk-score-${score}`,
                                finding: captured.prompts.length === 1
                                    ? "prior-model-content-marker"
                                    : "refined the assigned parent",
                                citedEvidenceIds: citations,
                            },
                            files: [{ path: "score.txt", content: `${score}\n` }],
                        }, {
                            sessionId: config.sessionId,
                            toolName: submitTool.name,
                        });
                    },
                    async disconnect() {},
                };
            },
        };

        const result = await runAutonomousInvestigation(
            setup.config,
            {
                idFactory: deterministicIds(),
                sdkClient,
                parentReadLimits: {
                    maxParents: 2,
                    maxCalls: 4,
                    maxListEntries: 8,
                    maxChunkBytes: 128,
                    maxSessionBytes: 512,
                    maxFileBytes: 1024,
                },
            },
        );

        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
            candidateId: "candidate-r000002-s000",
        });
        expect(captured.started).toBe(true);
        expect(captured.stopped).toBe(true);
        expect(captured.prompts).toHaveLength(2);
        const secondPrompt = captured.prompts[1];
        const untrustedStart = secondPrompt.indexOf("<<<CRUCIBLE_UNTRUSTED_DATA");
        expect(secondPrompt).toContain("Operator REFINEMENT:");
        expect(secondPrompt.indexOf("Operator REFINEMENT:")).toBeLessThan(untrustedStart);
        expect(secondPrompt.indexOf("Acceptance predicate:")).toBeLessThan(untrustedStart);
        expect(secondPrompt.indexOf("Ranking metrics:")).toBeLessThan(untrustedStart);
        expect(secondPrompt.indexOf("Omitted history (capped):")).toBeLessThan(untrustedStart);
        expect(secondPrompt).toContain("Trusted prompt context hash:");
        expect(secondPrompt).toContain("Parent read limits:");
        expect(secondPrompt).toContain("prior-model-content-marker");
        expect(secondPrompt).not.toContain("\"data\":");
        expect(Buffer.byteLength(secondPrompt, "utf8")).toBeLessThan(24 * 1024);
        expect(captured.configs[0].tools.map((tool) => tool.name)).toEqual([
            SUBMIT_CANDIDATE_TOOL_NAME,
        ]);
        expect(captured.configs[1].tools.map((tool) => tool.name)).toEqual([
            SUBMIT_CANDIDATE_TOOL_NAME,
            READ_PARENT_ARTIFACT_TOOL_NAME,
        ]);
        expect(captured.parentResults).toHaveLength(1);
        expect(captured.parentResults[0].listed).toMatchObject({
            ok: true,
            entries: [{ path: "score.txt", size: 3 }],
        });
        expect(captured.parentResults[0].read.content).toContain("90\n");

        const replayed = replaySetup(setup);
        const candidates = harnessCandidateEvidenceItems(replayed.aggregate);
        expect(candidates).toHaveLength(2);
        expect(candidates[1].annotations.citedEvidenceIds).toEqual([
            candidates[0].evidenceId,
        ]);
        const secondCommandId = replayed.aggregate.observations[
            candidates[1].observationId
        ].commandId;
        expect(replayed.aggregate.commands[secondCommandId].command.promptContextRefs)
            .toContain(candidates[0].evidenceId);
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
    ])("recovers a candidate crash at %s with a newer fenced attempt", async (point, uncertain) => {
        const setup = setupInvestigation(`crash-${point}`, { maxRounds: 1 });
        const firstPool = new FakeWorkerPool([95]);
        let injected = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(firstPool, {
                faultInjector(observedPoint, details) {
                    if (!injected
                        && observedPoint === point
                        && details.commandId === "cmd-000002") {
                        injected = true;
                        throw new InjectedCrashError(point);
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: "CRUCIBLE_RUNTIME_INJECTED_CRASH",
        });
        expect(firstPool.calls).toHaveLength(0);
        expect(fs.readdirSync(path.join(setup.stateDir, "runtime-temp"))).toEqual([]);

        const recoveredPool = new FakeWorkerPool([95]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(recoveredPool),
        );
        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
        });
        expect(result.recovery).toMatchObject({
            abandonedCount: 1,
            uncertainDispatched: uncertain,
        });
        expect(recoveredPool.calls).toHaveLength(1);
        const replayed = replaySetup(setup);
        const attempts = replayed.repository.listCommandAttempts("runtime-investigation");
        expect(attempts.filter((attempt) => attempt.state === "abandoned")).toHaveLength(1);
        expect(attempts.some((attempt) => attempt.state === "committed")).toBe(true);
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(1);
        replayed.repository.close();
    }, 60_000);

    it("reuses committed proposal and measurement effects after a crash without a second call", async () => {
        const setup = setupInvestigation(
            "committed-effect-recovery",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const firstPool = new FakeWorkerPool([95]);
        let injected = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(firstPool, {
                faultInjector(point, details) {
                    if (!injected
                        && point === "after_effect_commit"
                        && details.command?.kind === "candidate-measurement") {
                        injected = true;
                        throw new InjectedCrashError(point);
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: "CRUCIBLE_RUNTIME_INJECTED_CRASH",
        });
        expect(firstPool.calls).toHaveLength(1);
        expect(harnessCallCount(setup)).toBe(3);

        const branchA = clonePersistedSetup(setup, "committed-effect-branch-a");
        const branchB = clonePersistedSetup(setup, "committed-effect-branch-b");
        const recoveredPoolA = new FakeWorkerPool([]);
        const recoveredPoolB = new FakeWorkerPool([]);
        const resultA = await runAutonomousInvestigation(
            branchA.config,
            runnerDependencies(recoveredPoolA),
        );
        const resultB = await runAutonomousInvestigation(
            branchB.config,
            runnerDependencies(recoveredPoolB),
        );
        expect(resultA).toMatchObject({ kind: "TERMINAL", decision: "VERIFIED_RESULT" });
        expect(resultB).toMatchObject({ kind: "TERMINAL", decision: "VERIFIED_RESULT" });
        expect(recoveredPoolA.calls).toHaveLength(0);
        expect(recoveredPoolB.calls).toHaveLength(0);
        expect(harnessCallCount(setup)).toBe(3);

        const replayedA = replaySetup(branchA);
        const replayedB = replaySetup(branchB);
        expect(replayedA.aggregate.terminal.eventHash).toBe(
            replayedB.aggregate.terminal.eventHash,
        );
        expect(replayedA.aggregate.terminal.evidenceClosure.closureRoot).toBe(
            replayedB.aggregate.terminal.evidenceClosure.closureRoot,
        );
        expect(replayedA.aggregate.terminal.evidenceClosure.receipts.root).toBe(
            replayedB.aggregate.terminal.evidenceClosure.receipts.root,
        );
        const effects = replayedA.adapter.listOperationalEvidence().filter((row) =>
            row.kind === "runtime:model_proposal" || row.kind === "runtime:measurement");
        expect(effects.every((row) =>
            /^sha256:crucible-runtime-logical-effect-v1:[a-f0-9]{64}$/u
                .test(row.payload.logicalEffectKey))).toBe(true);
        const effectAttempts = replayedA.repository
            .listCommandAttempts("runtime-investigation")
            .filter((attempt) => {
                const metadata = JSON.parse(attempt.command);
                return metadata.scope === "external-effect";
            });
        expect(effectAttempts.every((attempt) => {
            const metadata = JSON.parse(attempt.command);
            return /^sha256:crucible-runtime-logical-effect-v1:[a-f0-9]{64}$/u
                .test(metadata.logicalEffectKey);
        })).toBe(true);
        replayedA.repository.close();
        replayedB.repository.close();
    }, 120_000);

    it("refuses committed-effect recovery when a required raw artifact is missing", async () => {
        const setup = setupInvestigation(
            "committed-effect-missing-artifact",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        let injected = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new FakeWorkerPool([95]), {
                faultInjector(point, details) {
                    if (!injected
                        && point === "after_effect_commit"
                        && details.command?.kind === "candidate-measurement") {
                        injected = true;
                        throw new InjectedCrashError(point);
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: "CRUCIBLE_RUNTIME_INJECTED_CRASH",
        });

        const persisted = replaySetup(setup);
        const measurement = persisted.adapter.listOperationalEvidence().find((row) =>
            row.kind === "runtime:measurement" && row.payload.purpose === "candidate");
        const stdoutArtifact = persisted.repository.getArtifact(
            measurement.payload.rawStdoutArtifactId,
        );
        persisted.repository.close();
        const store = openArtifactStore({ root: setup.artifactRoot });
        fs.rmSync(store.objectPath(`sha256:${stdoutArtifact.hashValue}`), { force: true });

        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new FakeWorkerPool([])),
        )).rejects.toMatchObject({
            code: "CRUCIBLE_RUNTIME_INTEGRITY_FAILURE",
        });
        expect(harnessCallCount(setup)).toBe(3);
    }, 120_000);

    it("reruns an uncertain observed effect instead of treating artifact persistence as committed", async () => {
        const setup = setupInvestigation(
            "uncertain-effect-recovery",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const firstPool = new FakeWorkerPool([95]);
        let injected = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(firstPool, {
                faultInjector(point, details) {
                    if (!injected
                        && point === "after_effect_artifact_persistence"
                        && details.command?.kind === "candidate-measurement") {
                        injected = true;
                        throw new InjectedCrashError(point);
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: "CRUCIBLE_RUNTIME_INJECTED_CRASH",
        });
        expect(firstPool.calls).toHaveLength(1);
        expect(harnessCallCount(setup)).toBe(3);

        const recoveredPool = new FakeWorkerPool([]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(recoveredPool),
        );
        expect(result).toMatchObject({ kind: "TERMINAL", decision: "VERIFIED_RESULT" });
        expect(recoveredPool.calls).toHaveLength(0);
        expect(harnessCallCount(setup)).toBe(4);
        expect(result.recovery.uncertainDispatched).toBeGreaterThanOrEqual(1);
    }, 120_000);
});
