// Release-only product, hard-kill, and real-process runtime matrix.
import { afterAll, afterEach, describe, expect, it } from "vitest";
import {
    execFileSync,
    fork,
    spawn as childSpawn,
} from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    DEFAULT_SEARCH_POLICY,
    ESCAPE_SEARCH_OPERATORS,
    EVENT_TYPES,
    artifactRefsFromProvenance,
    createInvestigationContract,
    hashCanonical,
    harnessCandidateEvidenceItems,
    impossibilityEvidenceItems,
    normalizeEnumerandManifest,
} from "../domain/index.mjs";
import {
    PARSER_VERSION,
    buildFrozenHarnessIdentity,
    computeHarnessSuiteV4Identity,
    createDefaultProcessAdapter,
    createSandboxProvider,
    loadHarnessAllowlist,
    verifyHarnessPreflight,
} from "../measurement/index.mjs";
import {
    CasConflictError,
    ERROR_CODES as PERSISTENCE_ERROR_CODES,
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";
import { DatabaseSync } from "../persistence/sqlite.mjs";
import {
    InjectedCrashError,
    READ_PARENT_ARTIFACT_TOOL_NAME,
    RUNTIME_ERROR_CODES,
    SUBMIT_CANDIDATE_TOOL_NAME,
    createDomainRepositoryAdapter,
    deriveRunnerExecutionLimits,
    requestStop,
    runAutonomousInvestigation,
    validateCandidateSubmission,
} from "../runtime/index.mjs";
import {
    NODE_EXE,
    nodeExeSha256Hex,
    sha256HexOfFile,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";
import {
    buildHarnessSuiteForAllowlist,
    upgradeLegacyContractInput,
} from "./v4-contract-fixture.mjs";
import {
    createRuntimeConfigAuthorityFixture,
    createSignedInvestigationAuthority,
} from "./experiment-authority-fixture.mjs";
import { removeTreeRobust } from "./test-cleanup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
const suiteRootPaths = [];
const activeSuitePids = new Set();
const WINDOWS_POWERSHELL = path.join(
    process.env.SystemRoot ?? "C:\\Windows",
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
);

function exactWindowsProcessesForPaths(paths) {
    if (process.platform !== "win32" || paths.length === 0) return [];
    const script = `
        $needles = @((ConvertFrom-Json $env:CRUCIBLE_EXACT_PROCESS_PATHS))
        $rows = @(
            Get-CimInstance Win32_Process | Where-Object {
                $executable = [string]$_.ExecutablePath
                $commandLine = [string]$_.CommandLine
                $matched = $false
                foreach ($needle in $needles) {
                    if ([string]::Equals(
                            $executable,
                            [string]$needle,
                            [StringComparison]::OrdinalIgnoreCase
                        ) -or (
                            -not [string]::IsNullOrEmpty($commandLine) -and
                            $commandLine.IndexOf(
                                [string]$needle,
                                [StringComparison]::OrdinalIgnoreCase
                            ) -ge 0
                        )) {
                        $matched = $true
                        break
                    }
                }
                $matched
            } | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine
        )
        if ($rows.Count -eq 0) {
            [Console]::Out.Write("[]")
        } else {
            [Console]::Out.Write((ConvertTo-Json -InputObject @($rows) -Compress))
        }
    `;
    const output = execFileSync(
        WINDOWS_POWERSHELL,
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        {
            encoding: "utf8",
            env: {
                ...process.env,
                CRUCIBLE_EXACT_PROCESS_PATHS: JSON.stringify(paths),
            },
            windowsHide: true,
            maxBuffer: 4 * 1024 * 1024,
        },
    );
    const parsed = JSON.parse(output || "[]");
    return Array.isArray(parsed) ? parsed : [parsed];
}

async function waitForNoExactWindowsProcess(paths, timeoutMs = 5_000) {
    const deadline = Date.now() + timeoutMs;
    let remaining = exactWindowsProcessesForPaths(paths);
    while (remaining.length > 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 50));
        remaining = exactWindowsProcessesForPaths(paths);
    }
    return remaining;
}

function waitForForkMessage(child, predicate, timeoutMs = 60_000) {
    return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (callback, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            child.off("message", onMessage);
            child.off("error", onError);
            child.off("exit", onExit);
            callback(value);
        };
        const onMessage = (message) => {
            if (predicate(message)) finish(resolve, message);
        };
        const onError = (error) => finish(reject, error);
        const onExit = (code, signal) => finish(
            reject,
            new Error(`hard-kill worker exited early: code=${code} signal=${signal}`),
        );
        const timer = setTimeout(() => {
            finish(reject, new Error("timed out waiting for hard-kill durability boundary"));
        }, timeoutMs);
        timer.unref?.();
        child.on("message", onMessage);
        child.once("error", onError);
        child.once("exit", onExit);
    });
}

function waitForForkExit(child, timeoutMs = 10_000) {
    return new Promise((resolve, reject) => {
        if (child.exitCode !== null || child.signalCode !== null) {
            resolve({ code: child.exitCode, signal: child.signalCode });
            return;
        }
        const timer = setTimeout(
            () => reject(new Error("hard-killed worker did not exit")),
            timeoutMs,
        );
        timer.unref?.();
        child.once("exit", (code, signal) => {
            clearTimeout(timer);
            resolve({ code, signal });
        });
    });
}

function trackSuiteProcess(child) {
    if (Number.isSafeInteger(child?.pid) && child.pid > 0) {
        activeSuitePids.add(child.pid);
        child.once("exit", () => activeSuitePids.delete(child.pid));
    }
    return child;
}

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-runner-${label}-`));
    roots.push(root);
    suiteRootPaths.push(root);
    return root;
}

afterEach(async () => {
    const failures = [];
    for (const root of roots.splice(0)) {
        const ownedDebris = fs.existsSync(root)
            ? fs.readdirSync(root, { recursive: true })
                .map((entry) => String(entry))
                .filter((entry) =>
                    entry.includes(".crucible-job-owner-")
                    || /(?:^|[\\/])runtime-temp[\\/]run-g/u.test(entry))
            : [];
        if (ownedDebris.length > 0) {
            failures.push(new Error(
                `runtime-owned debris remained under ${root}: ${ownedDebris.join(", ")}`,
            ));
        }
        try {
            await removeTreeRobust(root, {
                label: "runtime runner test root",
                timeoutMs: 30_000,
            });
        } catch (error) {
            failures.push(error);
        }
        if (fs.existsSync(root)) {
            failures.push(new Error(`runtime test root survived cleanup: ${root}`));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "runtime runner test cleanup failed");
    }
});

afterAll(async () => {
    const failures = [];
    for (const pid of activeSuitePids) {
        try {
            process.kill(pid, 0);
            failures.push(new Error(`runtime suite leaked tracked child PID ${pid}`));
            process.kill(pid, "SIGKILL");
        } catch {
            activeSuitePids.delete(pid);
        }
    }
    for (const pid of [...activeSuitePids]) {
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline) {
            try {
                process.kill(pid, 0);
                await new Promise((resolve) => setTimeout(resolve, 50));
            } catch {
                activeSuitePids.delete(pid);
                break;
            }
        }
    }
    const leakedExactProcesses = exactWindowsProcessesForPaths(suiteRootPaths);
    if (leakedExactProcesses.length > 0) {
        failures.push(new Error(
            `runtime suite leaked exact-path processes: ${JSON.stringify(leakedExactProcesses)}`,
        ));
        for (const processRecord of leakedExactProcesses) {
            const pid = Number(processRecord.ProcessId);
            if (!Number.isSafeInteger(pid) || pid < 1) continue;
            try {
                process.kill(pid, "SIGKILL");
            } catch {
                // The exact process may exit between enumeration and cleanup.
            }
        }
    }
    const remaining = await waitForNoExactWindowsProcess(suiteRootPaths, 10_000);
    if (remaining.length > 0) {
        failures.push(new Error(
            `runtime suite could not terminate exact-path processes: ${JSON.stringify(remaining)}`,
        ));
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "runtime runner process cleanup failed");
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
                }, {
                    path: NODE_EXE,
                    sha256: nodeExeSha256Hex(),
                    role: "node-runtime",
                }],
                timeoutMs: 15_000,
                maxStdoutBytes: 1024 * 1024,
                maxStderrBytes: 256 * 1024,
                executesCandidateCode,
                validationCases: Object.fromEntries(
                    Object.entries(validationCases).map(([id, snapshot]) => [
                        id,
                        {
                            snapshotHash: snapshot,
                            expectation: id === "known-bad"
                                || id === "challenge-case"
                                ? "reject"
                                : "accept",
                        },
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
    harnessSuite,
    harnessSuiteIdentity,
    enumerandManifest,
} = {}) {
    const input = upgradeLegacyContractInput({
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
        hypothesisTopology: hypothesisTopology
            ?? (boundedCandidateIds === undefined
                ? "open_generative"
                : "finite_enumerable"),
        criticality: "high",
        policyVersion: "policy-v1",
        workerModels: ["model-a", "model-b"],
        candidatesPerRound,
        maxRounds,
        ...(boundedCandidateIds === undefined ? {} : { boundedCandidateIds }),
        ...(enumerandManifest === undefined ? {} : { enumerandManifest }),
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
    input.harnessSuite = harnessSuite;
    input.harnessSuiteIdentity = harnessSuiteIdentity;
    return createInvestigationContract(input);
}

function runnerSandboxIdentity() {
    return {
        required: true,
        primitive: "fixture-containment",
        providerId: "runner-fixture-containment",
        providerVersion: "v1",
        policyId: "runner-fixture-policy",
        helperSourceHash:
            `sha256:runner-fixture-helper-source-v1:${"a".repeat(64)}`,
        helperBinaryHash:
            `sha256:crucible-measurement-file-v1:${"b".repeat(64)}`,
        launcherId: "runner-fixture-launcher-v1",
        launcherBinaryHash:
            `sha256:runner-fixture-launcher-binary-v1:${"c".repeat(64)}`,
        launcherScriptHash:
            `sha256:runner-fixture-launcher-script-v1:${"d".repeat(64)}`,
        securityContext: {
            appContainer: true,
            lowIntegrity: true,
            capabilities: [],
            loopbackExemptionRejected: true,
        },
        network: {
            mode: "deny-by-default",
            enforcement: "fixture zero-capability boundary",
        },
        filesystem: {
            stagedHarness: "exact-manifest-read-execute",
            immutableCandidate: "private-staged-copy-read-only",
            outputTemp: "provider-owned",
            aclJournalRestored: true,
            exactLaunchClosure: true,
            hostWriteDenied: true,
        },
        job: {
            killOnJobClose: true,
            descendantsContained: true,
            uiRestrictions: true,
            activeProcessLimit: 8,
            processMemoryBytes: 512 * 1024 * 1024,
            jobMemoryBytes: 768 * 1024 * 1024,
            cpuRatePercent: 50,
            cpuTimeMs: 30_000,
            wallTimeMs: 120_000,
            terminationGraceMs: 5_000,
        },
    };
}

function deterministicIds() {
    let next = 0;
    return () => `fixture-id-${++next}`;
}

function mutableClock(start = 1_000_000) {
    let now = start;
    return {
        now: () => now,
        isoNow: () => new Date(now).toISOString(),
        advance(milliseconds) {
            now += milliseconds;
        },
    };
}

class ScriptedOrchestrationWorkerPool {
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
        const candidate = validateCandidateSubmission({
            challenge: request.challengeNonce,
            candidateId,
            annotations: {
                mechanism: spec.mechanism ?? `Fixture score ${score}`,
                finding: `Fixture outcome requested score ${String(score)}`,
                ...(spec.annotations ?? {}),
            },
            files: [{
                path: "score.txt",
                content: spec.content ?? `${score}\n`,
            }],
        }, {
            challengeNonce: request.challengeNonce,
            allowedCandidateIds: request.allowedCandidateIds,
            visibleEvidenceIds: request.visibleEvidenceIds,
        });
        return {
            ...candidate,
            identity: {
                invocationSessionId: request.sessionId,
                configuredModel: request.model,
                challengeNonce: request.challengeNonce,
                promptHash: hashCanonical(
                    { prompt: request.prompt },
                    "sha256:crucible-runtime-worker-prompt-v1",
                ),
                contextHash: request.promptContextHash ?? null,
                annotationsHash: hashCanonical(
                    candidate.annotations,
                    "sha256:crucible-runtime-candidate-annotations-v1",
                ),
                payloadHash: hashCanonical(
                    candidate,
                    "sha256:crucible-runtime-candidate-payload-v1",
                ),
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

function createControllableHarnessAdapter() {
    let nextPid = 7600;
    const children = new Map();
    return {
        spawn(_executable, _argv, options) {
            const child = new EventEmitter();
            child.pid = ++nextPid;
            child.stdout = new PassThrough();
            child.stderr = new PassThrough();
            const state = { child, terminated: false, closed: false };
            children.set(child.pid, state);
            setImmediate(() => {
                if (state.terminated || state.closed) return;
                const candidatePath = options.env.CANDIDATE_SNAPSHOT_PATH;
                const score = Number(
                    fs.readFileSync(path.join(candidatePath, "score.txt"), "utf8").trim(),
                );
                child.stdout.end(Buffer.from(JSON.stringify({
                    pass: Number.isFinite(score) && score >= 90,
                    metrics: { score },
                }), "utf8"));
                child.stderr.end();
                state.closed = true;
                children.delete(child.pid);
                child.emit("close", 0, null);
            });
            return child;
        },
        terminateTree(pid) {
            const state = children.get(pid);
            if (state === undefined || state.closed) return false;
            state.terminated = true;
            state.child.stdout.end();
            state.child.stderr.end();
            setImmediate(() => {
                if (state.closed) return;
                state.closed = true;
                children.delete(pid);
                state.child.emit("close", null, "SIGKILL");
            });
            return true;
        },
    };
}

function setupInvestigation(label, contractOptions = {}, {
    countHarnessCalls = false,
    impossibilityResult = null,
    executesCandidateCode = false,
    spawnLingeringCandidateProcess = false,
} = {}) {
    const root = makeRoot(label);
    const stateDir = path.join(root, "state");
    const artifactRoot = path.join(root, "artifacts");
    fs.mkdirSync(stateDir, { recursive: true });
    const store = openArtifactStore({ root: artifactRoot });
    const goodSnapshot = seedSnapshot(store, root, "good", 100);
    const badSnapshot = seedSnapshot(store, root, "bad", 10);
    const roleSnapshots = {
        search: seedSnapshot(store, root, "search-role", 91),
        confirmation: seedSnapshot(store, root, "confirmation-role", 92),
        challenge: seedSnapshot(store, root, "challenge-role", 11),
        novelty: seedSnapshot(store, root, "novelty-role", 94),
    };
    let enumerandManifest;
    if (Array.isArray(contractOptions.boundedCandidateIds)) {
        enumerandManifest = normalizeEnumerandManifest({
            topology: "finite_enumerable",
            entries: contractOptions.boundedCandidateIds.map((id, ordinal) => ({
                id,
                ordinal,
                artifactSnapshotHash: seedSnapshot(
                    store,
                    root,
                    `enumerand-${id}`,
                    20 + ordinal * 10,
                ),
            })),
            control: { kind: "enumerand", ordinal: 0 },
        });
    }
    const harnessCounterPath = path.join(root, "harness-call-count.txt");
    const countHarnessCall = countHarnessCalls
        ? `fs.appendFileSync(${JSON.stringify(harnessCounterPath)}, "1\\n");`
        : "";
    const certificateResult = impossibilityResult ?? {
        pass: false,
        searchSpaceExhausted: false,
    };
    const scriptPath = writeHarnessScript(root, "score-harness", `
        if (process.argv[2] === "--crucible-owned-linger") {
            setInterval(() => {}, 1000);
        } else {
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
                ${spawnLingeringCandidateProcess ? `
                if (score === 95) {
                    const { spawn } = await import("node:child_process");
                    const lingering = spawn(
                        process.execPath,
                        [process.argv[1], "--crucible-owned-linger"],
                        {
                            detached: true,
                            stdio: "ignore",
                            windowsHide: true,
                        },
                    );
                    lingering.unref();
                }
                ` : ""}
                process.stdout.write(JSON.stringify({
                    pass: Number.isFinite(score) && score >= 90,
                    metrics: raw === "omit" ? {} : { score }
                }));
            }
        }
    `);
    const allowlistPath = writeRuntimeAllowlist(root, "score-harness", scriptPath, {
        "known-good": goodSnapshot,
        "known-bad": badSnapshot,
        "search-case": roleSnapshots.search,
        "confirmation-case": roleSnapshots.confirmation,
        "challenge-case": roleSnapshots.challenge,
        "novelty-case": roleSnapshots.novelty,
    }, executesCandidateCode);
    const verifierScript = path.join(root, "impossibility-verifier.ps1");
    const verifierResult = JSON.stringify(certificateResult).replaceAll("'", "''");
    const countVerifierCall = countHarnessCalls
        ? `Add-Content -LiteralPath '${
            harnessCounterPath.replaceAll("'", "''")
        }' -Value '1'`
        : "";
    fs.writeFileSync(
        verifierScript,
        `
param([Parameter(Mandatory = $true)][string]$CandidatePath)
$ErrorActionPreference = "Stop"
${countVerifierCall}
$request = Join-Path -Path $CandidatePath -ChildPath "crucible-impossibility-request.json"
if (-not (Test-Path -LiteralPath $request -PathType Leaf)) {
    throw "missing Crucible impossibility request"
}
[Console]::Out.Write('${verifierResult}')
`,
    );
    const allowlistDocument = JSON.parse(
        fs.readFileSync(allowlistPath, "utf8"),
    );
    allowlistDocument.entries["verifier-harness"] = {
        executable: WINDOWS_POWERSHELL,
        executableSha256: sha256HexOfFile(WINDOWS_POWERSHELL),
        argvTemplate: [verifierScript, "{{candidatePath}}"],
        dependencies: [{
            path: verifierScript,
            sha256: sha256HexOfFile(verifierScript),
            role: "verifier-script",
        }],
        timeoutMs: 15_000,
        maxStdoutBytes: 1024 * 1024,
        maxStderrBytes: 256 * 1024,
        executesCandidateCode: false,
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(allowlistDocument, null, 2));
    let allowlist = loadHarnessAllowlist(allowlistPath);
    const harnessVerification = verifyHarnessPreflight(
        allowlist,
        "score-harness",
        {
            validationCases: [
                {
                    id: "known-good",
                    expectation: "accept",
                    artifactHash: goodSnapshot,
                },
                {
                    id: "known-bad",
                    expectation: "reject",
                    artifactHash: badSnapshot,
                },
            ],
            parserVersion: PARSER_VERSION,
        },
    );
    const harnessIdentity = buildFrozenHarnessIdentity(harnessVerification, {
        sandbox: executesCandidateCode
            ? runnerSandboxIdentity()
            : { required: false },
    });
    allowlistDocument.suites = {
        "score-suite": buildHarnessSuiteForAllowlist(allowlist, {
            suiteId: "score-suite",
            harnessId: "score-harness",
            includeVerifier: true,
            verifierHarnessId: "verifier-harness",
            sandboxPolicyDigest: harnessIdentity.sandbox.policyDigest,
            roleCaseIds: {
                calibration: ["known-good", "known-bad"],
                search: ["search-case"],
                confirmation: ["confirmation-case"],
                challenge: ["challenge-case"],
                novelty: ["novelty-case"],
            },
        }),
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(allowlistDocument, null, 2));
    allowlist = loadHarnessAllowlist(allowlistPath);
    const harnessSuite = allowlist.getSuite("score-suite");
    const contract = makeContract({
        goodSnapshot,
        badSnapshot,
        harnessSuite,
        harnessSuiteIdentity: computeHarnessSuiteV4Identity(harnessSuite),
        enumerandManifest,
        ...contractOptions,
    });
    const repository = openRepository({ file: path.join(stateDir, "events.sqlite") });
    const signed = createSignedInvestigationAuthority({
        contract,
        experimentId: `runner-${label}`,
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
    repository.close();

    const config = {
        investigationId: signed.investigationId,
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
        scriptPath,
        harnessCounterPath,
        contract,
        config,
    };
}

function replaySetup(setup) {
    const repository = openRepository({ file: path.join(setup.stateDir, "events.sqlite") });
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: setup.config.investigationId,
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

function removeRetainedRuntimeRoots(setup) {
    const tempRoot = path.join(setup.stateDir, "runtime-temp");
    const retained = fs.existsSync(tempRoot)
        ? fs.readdirSync(tempRoot)
            .filter((entry) => entry.startsWith("run-g"))
            .map((entry) => path.join(tempRoot, entry))
        : [];
    for (const runtimeRoot of retained) {
        fs.rmSync(runtimeRoot, {
            recursive: true,
            force: true,
            maxRetries: 20,
            retryDelay: 25,
        });
    }
    return retained;
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

function createRunnerContainmentProvider(
    calls,
    { describePolicyIdentity = runnerSandboxIdentity } = {},
) {
    let nextCapability = 0;
    return createSandboxProvider({
        providerId: "runner-fixture-containment",
        providerVersion: "v1",
        describePolicyIdentity,
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

function expectScientificConfirmationRequired(result) {
    expect(result).toMatchObject({
        kind: "NON_RESULT",
        code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
    });
}

describe("Crucible autonomous runner", () => {
    it("commits one candidate evidence for every adaptive slot", async () => {
        const setup = setupInvestigation("positive", {
            candidatesPerRound: 2,
            maxRounds: 2,
        });

        const pool = new ScriptedOrchestrationWorkerPool([95, 80, 96, 70]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );

        expectScientificConfirmationRequired(result);
        expect(result.tempRootCleaned).toBe(true);
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
        expect(replayed.aggregate.terminal).toBeNull();
        const scientificNonResult = replayed.aggregate.nonResults.at(-1);
        expect(scientificNonResult).toMatchObject({
            code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
            candidateId: "candidate-r000002-s000",
            readiness: {
                ready: false,
                confirmationSupported: false,
                challengeSupported: false,
            },
        });
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
        expect(scientificNonResult.evidenceId).toBe(
            replayed.aggregate.evidenceOrder
                .map((id) => replayed.aggregate.evidence[id])
                .find((evidence) =>
                    evidence.candidateId === "candidate-r000002-s000")?.evidenceId,
        );
        for (const evidenceId of replayed.aggregate.evidenceOrder) {
            const evidence = replayed.aggregate.evidence[evidenceId];
            const expectedArtifactIds = artifactRefsFromProvenance(
                evidence.receipt.provenance,
            ).map((artifact) => artifact.artifactId).sort();
            expect(
                replayed.repository
                    .listArtifactRefsForEvent(
                        replayed.adapter.investigationId,
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
        expect(persistedReceipt.version).toBe(5);
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
        expect(replayed.repository.listArtifactRefs(
            replayed.adapter.investigationId,
        ).length)
            .toBeGreaterThanOrEqual(12);
        replayed.repository.close();

        const tempRoot = path.join(setup.stateDir, "runtime-temp");
        expect(fs.existsSync(tempRoot)).toBe(true);
        expect(fs.readdirSync(tempRoot)).toEqual([]);
    }, 60_000);

    it("enforces per-attempt CAS bytes before artifact growth", async () => {
        const setup = setupInvestigation("cas-attempt-budget", {
            candidatesPerRound: 1,
            maxRounds: 1,
            searchPolicy: {},
        });
        const inventory = () => {
            const files = [];
            const walk = (directory) => {
                for (const dirent of fs.readdirSync(directory, {
                    withFileTypes: true,
                })) {
                    const absolute = path.join(directory, dirent.name);
                    if (dirent.isDirectory()) walk(absolute);
                    else if (dirent.isFile()) {
                        files.push({
                            path: path.relative(setup.artifactRoot, absolute),
                            size: fs.statSync(absolute).size,
                        });
                    }
                }
            };
            walk(setup.artifactRoot);
            return files.sort((left, right) =>
                left.path.localeCompare(right.path));
        };
        const before = inventory();
        let outcome;
        try {
            outcome = await runAutonomousInvestigation(
                setup.config,
                runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
                    byteBudgets: {
                        perAttemptCasBytes: 512,
                        perInvestigationCasBytes: 1024,
                    },
                }),
            );
        } catch (error) {
            outcome = error;
        }
        expect(outcome?.message ?? outcome?.reason).toMatch(
            /validation measurements failed/i,
        );
        expect(inventory()).toEqual(before);
    }, 30_000);

    it("seeds the investigation CAS budget from durable prior artifacts", async () => {
        const setup = setupInvestigation("cas-investigation-budget", {
            candidatesPerRound: 1,
            maxRounds: 1,
            searchPolicy: {},
        });
        const store = openArtifactStore({ root: setup.artifactRoot });
        const stored = store.putBytes(Buffer.alloc(2048, 0x61), {
            contentType: "application/octet-stream",
        });
        const repository = openRepository({
            file: path.join(setup.stateDir, "events.sqlite"),
        });
        repository.registerExternalArtifact({
            investigationId: setup.config.investigationId,
            artifactId: "seeded-cas-budget-artifact",
            algo: "sha256",
            hash: stored.id.slice("sha256:".length),
            sizeBytes: stored.size,
            contentType: "application/octet-stream",
        });
        repository.markArtifactDurable("seeded-cas-budget-artifact");
        repository.referenceArtifact({
            investigationId: setup.config.investigationId,
            artifactId: "seeded-cas-budget-artifact",
        });
        repository.close();

        let error;
        try {
            await runAutonomousInvestigation(
                setup.config,
                runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
                    byteBudgets: {
                        perAttemptCasBytes: 1024,
                        perInvestigationCasBytes: 1024,
                    },
                }),
            );
        } catch (caught) {
            error = caught;
        }
        expect([
            error?.message,
            error?.cause?.message,
        ].filter(Boolean).join(" ")).toMatch(
            /Persisted investigation artifacts already exceed/i,
        );
    }, 30_000);

    it("raises a too-small configured loop cap to the frozen-contract budget", async () => {
        const setup = setupInvestigation("derived-loop-budget", {
            candidatesPerRound: 2,
            maxRounds: 2,
        });
        setup.config.options.maxLoopIterations = 1;
        const limits = deriveRunnerExecutionLimits(setup.contract);
        expect(limits.maxLoopIterations).toBeGreaterThan(1);

        const pool = new ScriptedOrchestrationWorkerPool([95, 80, 96, 70]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expectScientificConfirmationRequired(result);
        const replayed = replaySetup(setup);
        expect(replayed.adapter.latestOperationalNonResult()).toBeNull();
        replayed.repository.close();
    }, 60_000);

    it.each([
        [
            "allowlist file",
            (setup) => {
                const allowlist = JSON.parse(fs.readFileSync(setup.allowlistPath, "utf8"));
                allowlist.description = "mutated after the first measurement";
                fs.writeFileSync(setup.allowlistPath, JSON.stringify(allowlist));
            },
        ],
        [
            "harness executable binding",
            (setup) => {
                const allowlist = JSON.parse(fs.readFileSync(setup.allowlistPath, "utf8"));
                allowlist.entries["score-harness"].executableSha256 = "0".repeat(64);
                fs.writeFileSync(setup.allowlistPath, JSON.stringify(allowlist));
            },
        ],
        [
            "dependency bytes",
            (setup) => {
                fs.appendFileSync(setup.scriptPath, "\n// mutated after start\n");
            },
        ],
    ])("fails closed when %s changes between measurements", async (_label, mutate) => {
        const setup = setupInvestigation(`identity-${_label.replaceAll(" ", "-")}`, {
            candidatesPerRound: 1,
            maxRounds: 1,
            searchPolicy: {},
        });
        let mutated = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
                faultInjector(point) {
                    if (!mutated && point === "after_measurement_execution") {
                        mutated = true;
                        mutate(setup);
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
        });
        expect(mutated).toBe(true);
    }, 30_000);

    it("fails closed when the required sandbox policy identity changes", async () => {
        const setup = setupInvestigation(
            "sandbox-policy-identity-mutation",
            {
                candidatesPerRound: 1,
                maxRounds: 1,
                searchPolicy: {},
            },
            { executesCandidateCode: true },
        );
        const calls = {
            admissions: [],
            launches: [],
            terminations: [],
            cleanups: [],
        };
        let mutated = false;
        const sandboxProvider = createRunnerContainmentProvider(calls, {
            describePolicyIdentity() {
                const identity = runnerSandboxIdentity();
                return mutated
                    ? {
                        ...identity,
                        providerVersion: "v2",
                        job: {
                            ...identity.job,
                            activeProcessLimit:
                                identity.job.activeProcessLimit + 1,
                        },
                    }
                    : identity;
            },
        });

        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
                sandboxProvider,
                faultInjector(point) {
                    if (!mutated && point === "after_measurement_execution") {
                        mutated = true;
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
        });
        expect(mutated).toBe(true);
    }, 30_000);

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
            runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
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

        expectScientificConfirmationRequired(result);
        expect(calls.hostLaunches).toBe(0);
        expect(calls.hostTerminations).toBe(0);
        expect(providerControlRoots).toHaveLength(1);
        expect(providerControlRoots[0]).toContain(
            path.join("runtime-temp", "run-g0-"),
        );
        expect(calls.admissions.length).toBeGreaterThanOrEqual(3);
        expect(calls.launches).toHaveLength(calls.admissions.length);
        expect(calls.cleanups).toHaveLength(calls.admissions.length);
        expect(calls.terminations).toHaveLength(0);
        expect(calls.admissions.every((admission) =>
            admission.launch.deadlineMs === setup.config.deadline
            && admission.launch.timeoutMs > 0
            && admission.launch.timeoutMs <= 15_000)).toBe(true);

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
        expect(replayed.aggregate.terminal).toBeNull();
        expect(replayed.aggregate.nonResults.at(-1)).toMatchObject({
            code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
        });
        replayed.repository.close();
    }, 60_000);

    it("persists a search-capacity non-result after successful validation", async () => {
        const setup = setupInvestigation("budget", { maxRounds: 1 });
        const pool = new ScriptedOrchestrationWorkerPool([20]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "BUDGET_EXHAUSTED_INCONCLUSIVE",
        });
        expect(pool.calls).toHaveLength(1);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.status).toBe("non_result");
        expect(replayed.aggregate.terminal).toBeNull();
        replayed.repository.close();
    }, 60_000);

    it("bounds a hung worker-pool close after persisting the scientific non-result", async () => {
        const setup = setupInvestigation("runner-shutdown-bound", { maxRounds: 1 });
        const pool = new ScriptedOrchestrationWorkerPool([95]);
        let closeStartedAt = null;
        pool.close = () => {
            closeStartedAt = Date.now();
            return new Promise(() => {});
        };
        await expect(runAutonomousInvestigation({
            ...setup.config,
            options: {
                ...setup.config.options,
                shutdownTimeoutMs: 10,
            },
        }, runnerDependencies(pool))).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.NON_QUIESCENT,
            details: {
                pausePending: true,
                failures: [
                    expect.objectContaining({
                        component: "workerPool.close",
                        status: "timed_out",
                    }),
                ],
            },
        });
        expect(closeStartedAt).not.toBeNull();
        expect(Date.now() - closeStartedAt).toBeLessThan(500);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(replayed.aggregate.nonResults.at(-1)).toMatchObject({
            code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
        });
        replayed.repository.close();
        expect(removeRetainedRuntimeRoots(setup).length).toBeGreaterThan(0);
    }, 60_000);

    it("records a deadline non-result and never emits TARGET_UNREACHABLE", async () => {
        const setup = setupInvestigation("deadline");
        const pool = new ScriptedOrchestrationWorkerPool([]);
        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline: Date.now() - 1,
        }, runnerDependencies(pool));
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            domainPausePersisted: true,
            terminalEmitted: false,
        });
        expect(pool.calls).toHaveLength(0);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(replayed.aggregate.pause).not.toBeNull();
        expect(replayed.repository.getTerminalEvent(
            replayed.adapter.investigationId,
        )).toBeNull();
        expect(replayed.repository.listEvents(replayed.adapter.operationalInvestigationId)
            .some((row) => row.kind === "runtime:non_result")).toBe(true);
        replayed.repository.close();

        const replayedResult = await runAutonomousInvestigation({
            ...setup.config,
            deadline: Date.now() + 60_000,
        }, runnerDependencies(new ScriptedOrchestrationWorkerPool([])));
        expect(replayedResult).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            persisted: true,
        });
    });

    it("rejects a proposal that completes after the absolute deadline", async () => {
        const setup = setupInvestigation(
            "deadline-proposal",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const clock = mutableClock();
        const deadline = clock.now() + 30_000;
        const pool = new ScriptedOrchestrationWorkerPool([
            () => {
                clock.advance(30_001);
                return 95;
            },
        ]);
        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline,
        }, runnerDependencies(pool, { clock }));
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            terminalEmitted: false,
        });
        expect(pool.calls).toHaveLength(1);
        expect(harnessCallCount(setup)).toBe(2);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(0);
        const operationalNonResult = replayed.adapter.latestOperationalNonResult();
        expect(operationalNonResult).toMatchObject({
            payload: { code: "DEADLINE_EXCEEDED" },
        });
        replayed.adapter.recordOperationalRecovery({
            attemptId: "later-deadline-recovery",
            previousSeq: operationalNonResult.seq,
            policy: "later_deadline",
            reason: "Explicit test recovery supplied a later deadline.",
            details: {
                previousDeadline: deadline,
                requestedDeadline: clock.now() + 60_000,
            },
        });
        if (replayed.aggregate.pause !== null) {
            replayed.adapter.resumeInvestigation();
        }
        expect(replayed.adapter.replay().aggregate.pause).toBeNull();
        expect(replayed.adapter.latestOperationalNonResult()).toBeNull();
        replayed.repository.close();

        const recoveryPool = new ScriptedOrchestrationWorkerPool([95]);
        const recovered = await runAutonomousInvestigation({
            ...setup.config,
            deadline: clock.now() + 60_000,
        }, runnerDependencies(recoveryPool, { clock }));
        expectScientificConfirmationRequired(recovered);
        expect(recoveryPool.calls).toHaveLength(1);
        const recoveredReplay = replaySetup(setup);
        expect(recoveredReplay.adapter.latestOperationalNonResult()).toBeNull();
        expect(recoveredReplay.aggregate.terminal).toBeNull();
        expect(recoveredReplay.aggregate.nonResults.at(-1)).toMatchObject({
            code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
        });
        expect(recoveredReplay.aggregate.pause).toBeNull();
        expect(recoveredReplay.aggregate.pauseHistory).toHaveLength(1);
        expect(harnessCallCount(setup)).toBe(3);
        const deadlineFailures = recoveredReplay.adapter.listOperationalEvidence()
            .filter((row) =>
                row.kind === "runtime:effect_failure"
                && row.payload?.classification === "deadline_expired");
        expect(deadlineFailures).toHaveLength(1);
        recoveredReplay.repository.close();
    }, 60_000);

    it("rejects candidate measurement facts completed after the deadline", async () => {
        const setup = setupInvestigation(
            "deadline-measurement",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const clock = mutableClock();
        const deadline = clock.now() + 30_000;
        let advanced = false;
        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline,
        }, runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
            clock,
            faultInjector(point, details) {
                if (!advanced
                    && point === "after_effect_operation"
                    && details.command?.kind === "candidate-measurement") {
                    advanced = true;
                    clock.advance(30_001);
                }
            },
        }));
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            terminalEmitted: false,
        });
        expect(harnessCallCount(setup)).toBe(3);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(0);
        expect(replayed.adapter.listOperationalEvidence().some((row) =>
            row.kind === "runtime:measurement"
            && row.payload.purpose === "candidate")).toBe(false);
        replayed.repository.close();
    }, 60_000);

    it("keeps artifacts persisted across a deadline crossing out of domain evidence", async () => {
        const setup = setupInvestigation(
            "deadline-artifact",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const clock = mutableClock();
        const deadline = clock.now() + 30_000;
        let advanced = false;
        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline,
        }, runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
            clock,
            faultInjector(point, details) {
                if (!advanced
                    && point === "after_effect_artifact_persistence"
                    && details.command?.kind === "candidate-measurement") {
                    advanced = true;
                    clock.advance(30_001);
                }
            },
        }));
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            terminalEmitted: false,
        });
        expect(harnessCallCount(setup)).toBe(3);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(0);
        expect(replayed.repository.listCommandAttempts(
            replayed.adapter.investigationId,
        )
            .some((attempt) => attempt.state === "observed")).toBe(true);
        replayed.repository.close();
    }, 60_000);

    it("rechecks the deadline before appending a domain observation", async () => {
        const setup = setupInvestigation(
            "deadline-domain-observation",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const clock = mutableClock();
        const deadline = clock.now() + 30_000;
        let advanced = false;
        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline,
        }, runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
            clock,
            faultInjector(point, details) {
                if (!advanced
                    && point === "before_domain_observation"
                    && details.commandId === "cmd-000002") {
                    advanced = true;
                    clock.advance(30_001);
                }
            },
        }));
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            terminalEmitted: false,
        });
        expect(harnessCallCount(setup)).toBe(3);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(0);
        expect(Object.values(replayed.aggregate.observations).some((observation) =>
            observation.purpose === "candidate")).toBe(false);
        expect(replayed.adapter.listOperationalEvidence().some((row) =>
            row.kind === "runtime:measurement"
            && row.payload.purpose === "candidate")).toBe(true);
        replayed.repository.close();
    }, 60_000);

    it("rechecks the deadline before the evidence CAS append", async () => {
        const setup = setupInvestigation(
            "deadline-evidence-cas",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const clock = mutableClock();
        const deadline = clock.now() + 30_000;
        let advanced = false;
        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline,
        }, runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
            clock,
            faultInjector(point, details) {
                if (!advanced
                    && point === "before_domain_evidence_append"
                    && details.commandId === "cmd-000002") {
                    advanced = true;
                    clock.advance(30_001);
                }
            },
        }));
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            terminalEmitted: false,
        });
        expect(harnessCallCount(setup)).toBe(3);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(0);
        expect(Object.values(replayed.aggregate.observations).some((observation) =>
            observation.purpose === "candidate")).toBe(true);
        replayed.repository.close();
    }, 60_000);

    it("suppresses a scientific non-result when the deadline crosses before append", async () => {
        const setup = setupInvestigation(
            "deadline-terminal",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const clock = mutableClock();
        const deadline = clock.now() + 30_000;
        let advanced = false;
        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline,
        }, runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
            clock,
            faultInjector(point) {
                if (!advanced && point === "before_non_result_append") {
                    advanced = true;
                    clock.advance(30_001);
                }
            },
        }));
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            terminalEmitted: false,
        });
        expect(harnessCallCount(setup)).toBe(3);
        const replayed = replaySetup(setup);
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(1);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(replayed.repository.getTerminalEvent(
            replayed.adapter.investigationId,
        )).toBeNull();
        const nonResult = replayed.adapter.latestOperationalNonResult();
        expect(nonResult.payload.details.terminalRecommendationSuppressed).toBe(false);
        replayed.repository.close();
    }, 60_000);

    it("requires independent verification after exhausting every frozen bounded id", async () => {
        const setup = setupInvestigation("bounded", {
            boundedCandidateIds: ["candidate-a", "candidate-b"],
            candidatesPerRound: 1,
            maxRounds: 2,
        });
        const pool = new ScriptedOrchestrationWorkerPool([20, 30]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool),
        );
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "INDEPENDENT_VERIFICATION_REQUIRED",
        });
        expect(pool.calls).toEqual([]);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        const nonResult = replayed.aggregate.nonResults.at(-1);
        expect(nonResult.basis).toMatchObject({
            enumerandCount: 2,
            searchSpaceExhausted: true,
        });
        expect(nonResult.basis.enumerandManifestRoot).toMatch(
            /^sha256:crucible-enumerand-manifest-root-v1:[a-f0-9]{64}$/,
        );
        expect(nonResult.readiness).toMatchObject({
            ready: false,
            independentVerifierSupported: false,
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
        const pool = new ScriptedOrchestrationWorkerPool([20]);
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
            runnerDependencies(new ScriptedOrchestrationWorkerPool([20])),
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
            runnerDependencies(new ScriptedOrchestrationWorkerPool([20]), {
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
            runnerDependencies(new ScriptedOrchestrationWorkerPool([])),
        );
        const resultB = await runAutonomousInvestigation(
            branchB.config,
            runnerDependencies(new ScriptedOrchestrationWorkerPool([])),
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
        const pool = new ScriptedOrchestrationWorkerPool([
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
        const pool = new ScriptedOrchestrationWorkerPool([
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
        expectScientificConfirmationRequired(result);
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
        const pool = new ScriptedOrchestrationWorkerPool([50, 50]);
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
        const pool = new ScriptedOrchestrationWorkerPool([
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

    it("exposes only bounded assigned-parent tool authority to a worker-pool factory", async () => {
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
        let blockedAfterCallBudget = false;
        const workerPoolFactory = (options) => {
            factoryOptions = options;
            const scripted = new ScriptedOrchestrationWorkerPool([90, 95]);
            return {
                async propose(request) {
                    calls.push(request);
                    if (request.parentEvidenceIds.length > 0) {
                        const evidenceId = request.parentEvidenceIds[0];
                        const listed = await options.parentReadAuthority.invoke({
                            sessionId: request.sessionId,
                            invocationSessionId: request.sessionId,
                            args: {
                                challenge: request.challengeNonce,
                                parentId: evidenceId,
                                op: "list",
                            },
                        });
                        const listedPayload = JSON.parse(listed.textResultForLlm);
                        const read = await options.parentReadAuthority.invoke({
                            sessionId: request.sessionId,
                            invocationSessionId: request.sessionId,
                            args: {
                                challenge: request.challengeNonce,
                                parentId: evidenceId,
                                op: "read",
                                path: listedPayload.entries[0].path,
                                offset: 0,
                                length: 16,
                            },
                        });
                        assignedParentContent = JSON.parse(read.textResultForLlm).content;
                        const blocked = await options.parentReadAuthority.invoke({
                            sessionId: request.sessionId,
                            invocationSessionId: request.sessionId,
                            args: {
                                challenge: request.challengeNonce,
                                parentId: "evidence-not-assigned",
                                op: "list",
                            },
                        });
                        blockedUnassigned = JSON.parse(blocked.textResultForLlm).reason
                            === "parent";
                        const exhausted = await options.parentReadAuthority.invoke({
                            sessionId: request.sessionId,
                            invocationSessionId: request.sessionId,
                            args: {
                                challenge: request.challengeNonce,
                                parentId: evidenceId,
                                op: "list",
                            },
                        });
                        blockedAfterCallBudget =
                            JSON.parse(exhausted.textResultForLlm).reason === "limit";
                    }
                    return scripted.propose(request);
                },
                async close() {
                    await scripted.close();
                },
            };
        };
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(undefined, {
                workerPoolFactory,
                parentReadLimits: { maxCalls: 3 },
            }),
        );

        expectScientificConfirmationRequired(result);
        expect(calls).toHaveLength(2);
        expect(calls[1].operator).toBe("refinement");
        expect(calls.every((request) =>
            Object.isFrozen(request)
            && Object.isFrozen(request.allowedCandidateIds)
            && Object.isFrozen(request.parentEvidenceIds)
            && Object.isFrozen(request.promptContext)
            && Object.isFrozen(request.parents)
            && Object.isFrozen(request.parentReadAuthority))).toBe(true);
        expect(calls[1].parentEvidenceIds).toHaveLength(1);
        expect(calls[1].parents).toEqual([{
            parentId: calls[1].parentEvidenceIds[0],
            snapshotId: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
        }]);
        expect(calls[1].parentReadLimits).toMatchObject({
            maxCalls: expect.any(Number),
            maxChunkBytes: expect.any(Number),
        });
        expect(assignedParentContent).toContain("90\n");
        expect(blockedUnassigned).toBe(true);
        expect(blockedAfterCallBudget).toBe(true);
        expect(factoryOptions.parentReadAuthority).toEqual({
            invoke: expect.any(Function),
        });
        expect(factoryOptions).not.toHaveProperty("parentReader");
        expect(factoryOptions).not.toHaveProperty("parentSnapshotAccess");
        expect(factoryOptions).not.toHaveProperty("readParentSnapshot");
        expect(factoryOptions).not.toHaveProperty("readParentSnapshotObject");
    }, 60_000);

    it.each([
        ["missing identity field", (proposal) => {
            delete proposal.identity.annotationsHash;
        }, RUNTIME_ERROR_CODES.WORKER_PROTOCOL],
        ["wrong context hash", (proposal) => {
            proposal.identity.contextHash =
                `sha256:crucible-runtime-prompt-context-v1:${"f".repeat(64)}`;
        }, RUNTIME_ERROR_CODES.WORKER_PROTOCOL],
        ["wrong payload hash", (proposal) => {
            proposal.identity.payloadHash =
                `sha256:crucible-runtime-candidate-payload-v1:${"e".repeat(64)}`;
        }, RUNTIME_ERROR_CODES.WORKER_PROTOCOL],
        ["oversized annotation", (proposal) => {
            proposal.annotations.mechanism = "x".repeat(257);
        }, RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE],
        ["unsafe path", (proposal) => {
            proposal.files[0].path = "../escape.txt";
        }, RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE],
        ["oversized file", (proposal) => {
            proposal.files[0].content = "x".repeat(300 * 1024);
        }, RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE],
    ])("revalidates alternate-worker %s at the runner trust boundary", async (
        _label,
        mutate,
        code,
    ) => {
        const setup = setupInvestigation(`alternate-boundary-${_label.replaceAll(" ", "-")}`, {
            maxRounds: 1,
        });
        const scripted = new ScriptedOrchestrationWorkerPool([95]);
        const workerPool = {
            async propose(request) {
                const proposal = JSON.parse(JSON.stringify(
                    await scripted.propose(request),
                ));
                mutate(proposal);
                return proposal;
            },
            async close() {
                await scripted.close();
            },
        };
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(workerPool),
        )).rejects.toMatchObject({ code });
        const replayed = replaySetup(setup);
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(0);
        expect(replayed.adapter.listOperationalEvidence().filter((event) =>
            event.kind === "runtime:model_proposal")).toHaveLength(0);
        replayed.repository.close();
    }, 60_000);

    it("wires trusted bounded context and parent reads through the SDK pool with a scripted client", async () => {
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

        expectScientificConfirmationRequired(result);
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
            investigationId: setup.config.investigationId,
            reason: "Operator requested pause",
            requestId: "stop-before-run",
        });
        expect(stop.appended).toBe(true);

        const pool = new ScriptedOrchestrationWorkerPool([]);
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

    it("reports a persisted pause as non-quiescent when worker cleanup fails", async () => {
        const setup = setupInvestigation("pause-cleanup-barrier", {
            maxRounds: 1,
        });
        const pool = new ScriptedOrchestrationWorkerPool([50]);
        pool.close = async () => {
            throw new Error("injected worker cleanup failure");
        };
        let requested = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(pool, {
                faultInjector(point) {
                    if (!requested && point === "after_proposal_response") {
                        requested = true;
                        requestStop({
                            stateDir: setup.stateDir,
                            investigationId: setup.config.investigationId,
                            reason: "Pause while the admitted command drains.",
                            requestId: "pause-during-proposal",
                        });
                    }
                },
            }),
        )).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.NON_QUIESCENT,
            details: {
                pausePending: true,
                failures: [
                    expect.objectContaining({
                        component: "workerPool.close",
                    }),
                ],
            },
        });
        expect(requested).toBe(true);
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.pause).not.toBeNull();
        expect(replayed.adapter.latestOperationalNonResult()).toBeNull();
        replayed.repository.close();
        expect(removeRetainedRuntimeRoots(setup).length).toBeGreaterThan(0);
    }, 60_000);

    it.each([
        ["after_reservation", 0],
        ["after_dispatch", 1],
    ])("recovers after an injected candidate fault at %s with a newer fenced attempt", async (point, uncertain) => {
        const setup = setupInvestigation(`crash-${point}`, { maxRounds: 1 });
        const firstPool = new ScriptedOrchestrationWorkerPool([95]);
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

        const recoveredPool = new ScriptedOrchestrationWorkerPool([95]);
        const result = await runAutonomousInvestigation(
            setup.config,
            runnerDependencies(recoveredPool),
        );
        expectScientificConfirmationRequired(result);
        expect(result.recovery).toMatchObject({
            abandonedCount: 1,
            uncertainDispatched: uncertain,
        });
        expect(recoveredPool.calls).toHaveLength(1);
        const replayed = replaySetup(setup);
        const attempts = replayed.repository.listCommandAttempts(
            replayed.adapter.investigationId,
        );
        expect(attempts.filter((attempt) => attempt.state === "abandoned")).toHaveLength(1);
        expect(attempts.some((attempt) => attempt.state === "committed")).toBe(true);
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(1);
        replayed.repository.close();
    }, 60_000);

    it("fences a superseded runner before buffered proposal evidence can persist", async () => {
        const setup = setupInvestigation(
            "proposal-takeover",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const stalePool = new ScriptedOrchestrationWorkerPool([95]);
        const currentPool = new ScriptedOrchestrationWorkerPool([95]);
        let injected = false;
        let staleProposalAttemptId = null;
        let currentResult = null;
        let refsAfterCurrent = null;

        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(stalePool, {
                async faultInjector(point, details) {
                    if (injected
                        || point !== "after_effect_artifact_persistence"
                        || details.command?.kind !== "sdk-proposal") {
                        return;
                    }
                    injected = true;
                    staleProposalAttemptId = details.attemptId;
                    currentResult = await runAutonomousInvestigation(
                        {
                            ...setup.config,
                            runnerEpochId: "runner-epoch-2",
                            deadline: Date.now() + 120_000,
                        },
                        runnerDependencies(currentPool),
                    );
                    const current = replaySetup(setup);
                    refsAfterCurrent = current.repository.listArtifactRefs(
                        current.adapter.investigationId,
                    ).length;
                    current.repository.close();
                },
            }),
        )).rejects.toMatchObject({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        });

        expectScientificConfirmationRequired(currentResult);
        expect(stalePool.calls).toHaveLength(1);
        expect(currentPool.calls).toHaveLength(0);
        const replayed = replaySetup(setup);
        expect(replayed.repository.listEvents(replayed.adapter.investigationId)
            .filter((event) =>
                event.kind === "domain:v4:non_result_recorded")).toHaveLength(1);
        expect(replayed.repository.listArtifactRefs(
            replayed.adapter.investigationId,
        ))
            .toHaveLength(refsAfterCurrent);
        expect(replayed.adapter.listOperationalEvidence().filter((event) =>
            event.attemptId === staleProposalAttemptId
            && event.kind === "runtime:model_proposal")).toEqual([]);
        expect(replayed.repository.getCommandAttempt(staleProposalAttemptId).state)
            .toBe("abandoned");
        replayed.repository.close();
    }, 120_000);

    it("reuses committed proposal and measurement effects after post-commit fault injection", async () => {
        const setup = setupInvestigation(
            "committed-effect-recovery",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const firstPool = new ScriptedOrchestrationWorkerPool([95]);
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
        const recoveredPoolA = new ScriptedOrchestrationWorkerPool([]);
        const recoveredPoolB = new ScriptedOrchestrationWorkerPool([]);
        const resultA = await runAutonomousInvestigation(
            branchA.config,
            runnerDependencies(recoveredPoolA),
        );
        const resultB = await runAutonomousInvestigation(
            branchB.config,
            runnerDependencies(recoveredPoolB),
        );
        expectScientificConfirmationRequired(resultA);
        expectScientificConfirmationRequired(resultB);
        expect(recoveredPoolA.calls).toHaveLength(0);
        expect(recoveredPoolB.calls).toHaveLength(0);
        expect(harnessCallCount(setup)).toBe(3);

        const replayedA = replaySetup(branchA);
        const replayedB = replaySetup(branchB);
        expect(replayedA.aggregate.lastEventHash).toBe(
            replayedB.aggregate.lastEventHash,
        );
        expect(replayedA.aggregate.nonResults.at(-1)).toEqual(
            replayedB.aggregate.nonResults.at(-1),
        );
        const effects = replayedA.adapter.listOperationalEvidence().filter((row) =>
            row.kind === "runtime:model_proposal" || row.kind === "runtime:measurement");
        expect(effects.every((row) =>
            /^sha256:crucible-runtime-logical-effect-v1:[a-f0-9]{64}$/u
                .test(row.payload.logicalEffectKey))).toBe(true);
        const effectAttempts = replayedA.repository
            .listCommandAttempts(replayedA.adapter.investigationId)
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

    it("recovers after the domain observation append without repeating external effects", async () => {
        const setup = setupInvestigation(
            "domain-append-recovery",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const firstPool = new ScriptedOrchestrationWorkerPool([95]);
        let injected = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(firstPool, {
                faultInjector(point, details) {
                    if (!injected
                        && point === "after_domain_observation"
                        && details.commandId === "cmd-000002") {
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

        const branchA = clonePersistedSetup(setup, "domain-append-branch-a");
        const branchB = clonePersistedSetup(setup, "domain-append-branch-b");
        const recoveredPoolA = new ScriptedOrchestrationWorkerPool([]);
        const recoveredPoolB = new ScriptedOrchestrationWorkerPool([]);
        const resultA = await runAutonomousInvestigation(
            branchA.config,
            runnerDependencies(recoveredPoolA),
        );
        const resultB = await runAutonomousInvestigation(
            branchB.config,
            runnerDependencies(recoveredPoolB),
        );
        expectScientificConfirmationRequired(resultA);
        expectScientificConfirmationRequired(resultB);
        expect(recoveredPoolA.calls).toHaveLength(0);
        expect(recoveredPoolB.calls).toHaveLength(0);
        expect(harnessCallCount(setup)).toBe(3);
        const replayedA = replaySetup(branchA);
        const replayedB = replaySetup(branchB);
        expect(replayedA.aggregate.lastEventHash)
            .toBe(replayedB.aggregate.lastEventHash);
        expect(replayedA.aggregate.nonResults.at(-1))
            .toEqual(replayedB.aggregate.nonResults.at(-1));
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
            runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
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
            runnerDependencies(new ScriptedOrchestrationWorkerPool([])),
        )).rejects.toMatchObject({
            code: "CRUCIBLE_RUNTIME_INTEGRITY_FAILURE",
        });
        expect(harnessCallCount(setup)).toBe(3);
    }, 120_000);

    it("recovers an artifact-persisted effect without rerunning the harness", async () => {
        const setup = setupInvestigation(
            "uncertain-effect-recovery",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const firstPool = new ScriptedOrchestrationWorkerPool([95]);
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

        const branchA = clonePersistedSetup(setup, "persisted-effect-branch-a");
        const branchB = clonePersistedSetup(setup, "persisted-effect-branch-b");
        const recoveredPoolA = new ScriptedOrchestrationWorkerPool([]);
        const recoveredPoolB = new ScriptedOrchestrationWorkerPool([]);
        const resultA = await runAutonomousInvestigation(
            branchA.config,
            runnerDependencies(recoveredPoolA),
        );
        const resultB = await runAutonomousInvestigation(
            branchB.config,
            runnerDependencies(recoveredPoolB),
        );
        expectScientificConfirmationRequired(resultA);
        expectScientificConfirmationRequired(resultB);
        expect(recoveredPoolA.calls).toHaveLength(0);
        expect(recoveredPoolB.calls).toHaveLength(0);
        expect(harnessCallCount(setup)).toBe(3);
        expect(resultA.recovery.uncertainDispatched).toBeGreaterThanOrEqual(1);
        const replayedA = replaySetup(branchA);
        const replayedB = replaySetup(branchB);
        expect(replayedA.aggregate.lastEventHash)
            .toBe(replayedB.aggregate.lastEventHash);
        expect(replayedA.aggregate.nonResults.at(-1))
            .toEqual(replayedB.aggregate.nonResults.at(-1));
        replayedA.repository.close();
        replayedB.repository.close();
    }, 120_000);
});

describe("H7 systematic runtime failure matrix", () => {
    const hardKillBoundaries = [
        {
            label: "proposal artifacts installed",
            point: "after_effect_artifact_persistence",
            commandKind: "sdk-proposal",
        },
        {
            label: "measurement effect committed",
            point: "after_effect_commit",
            commandKind: "candidate-measurement",
        },
        {
            label: "science gate append",
            point: "after_non_result_append",
            commandKind: null,
        },
    ];

    it.each(hardKillBoundaries)(
        "recovers deterministically after a hard kill at $label",
        async ({ label, point, commandKind }) => {
            const setup = setupInvestigation(
                `h7-hard-kill-${label.replaceAll(" ", "-")}`,
                { maxRounds: 1 },
                { countHarnessCalls: true },
            );
            const configPath = path.join(setup.root, "hard-kill-config.json");
            const workerCallsPath = path.join(setup.root, "hard-kill-worker-calls.txt");
            fs.writeFileSync(configPath, JSON.stringify(setup.config));
            const child = trackSuiteProcess(fork(
                path.join(HERE, "fixtures", "runtime-runner-kill-worker.mjs"),
                [],
                {
                    cwd: setup.root,
                    silent: true,
                    windowsHide: true,
                    env: {
                        ...process.env,
                        CRUCIBLE_KILL_CONFIG_PATH: configPath,
                        CRUCIBLE_KILL_FAULT_POINT: point,
                        CRUCIBLE_KILL_COMMAND_KIND: commandKind ?? "",
                        CRUCIBLE_KILL_WORKER_CALLS_PATH: workerCallsPath,
                    },
                },
            ));
            let stderr = "";
            child.stderr?.on("data", (chunk) => {
                stderr += chunk.toString("utf8");
            });
            try {
                try {
                    await waitForForkMessage(
                        child,
                        (message) => message?.type === "fault-boundary",
                    );
                } catch (error) {
                    throw new Error(
                        `${error?.message ?? String(error)}${
                            stderr.length === 0 ? "" : `\n${stderr}`
                        }`,
                        { cause: error },
                    );
                }
                expect(child.kill("SIGKILL")).toBe(true);
                const exit = await waitForForkExit(child);
                expect(exit.signal ?? "SIGKILL", stderr).toBe("SIGKILL");
            } finally {
                if (child.exitCode === null && child.signalCode === null) {
                    child.kill("SIGKILL");
                    await waitForForkExit(child).catch(() => {});
                }
            }
            const runtimeTemp = path.join(setup.stateDir, "runtime-temp");
            const abruptRoots = fs.readdirSync(runtimeTemp)
                .filter((entry) => entry.startsWith("run-g"))
                .map((entry) => path.join(runtimeTemp, entry));
            expect(abruptRoots.length).toBeGreaterThan(0);

            const recoveredPool = new ScriptedOrchestrationWorkerPool([95]);
            const result = await runAutonomousInvestigation(
                setup.config,
                runnerDependencies(recoveredPool),
            );
            expectScientificConfirmationRequired(result);
            expect(result.tempRootCleaned).toBe(true);
            expect(recoveredPool.calls).toHaveLength(0);
            expect(fs.readFileSync(workerCallsPath, "utf8").trim().split(/\r?\n/u))
                .toHaveLength(1);
            expect(harnessCallCount(setup)).toBe(3);

            const replayed = replaySetup(setup);
            const operational = replayed.adapter.listOperationalEvidence();
            expect(operational.filter((row) =>
                row.kind === "runtime:model_proposal")).toHaveLength(1);
            expect(operational.filter((row) =>
                row.kind === "runtime:candidate_snapshot")).toHaveLength(1);
            expect(operational.filter((row) =>
                row.kind === "runtime:measurement"
                && row.payload.purpose === "candidate")).toHaveLength(1);
            expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(1);
            expect(replayed.repository.listEvents(
                replayed.adapter.investigationId,
            )
                .filter((event) =>
                    event.kind === "domain:v4:non_result_recorded")).toHaveLength(1);
            const refs = replayed.repository.listArtifactRefs(
                replayed.adapter.investigationId,
            );
            expect(new Set(refs.map((ref) => `${ref.seq}:${ref.artifactId}`)).size)
                .toBe(refs.length);
            replayed.repository.close();
            for (const abruptRoot of abruptRoots) {
                fs.rmSync(abruptRoot, {
                    recursive: true,
                    force: true,
                    maxRetries: 20,
                    retryDelay: 25,
                });
            }
            expect(fs.readdirSync(path.join(setup.stateDir, "runtime-temp"))).toEqual([]);
        },
        120_000,
    );

    it.runIf(process.platform === "win32")(
        "owns the exact harness process tree through committed-effect recovery and parent failure",
        async () => {
            const setup = setupInvestigation(
                "h7-committed-effect-process-ownership",
                { maxRounds: 1 },
                {
                    countHarnessCalls: true,
                    spawnLingeringCandidateProcess: true,
                },
            );
            let capturedLaunch = null;
            let injected = false;
            let exactPaths = [];
            const processOwners = [];
            const makeProcessOwner = () => {
                const owned = createDefaultProcessAdapter();
                const state = { closeCalls: 0 };
                processOwners.push(state);
                return {
                    spawn: (...args) => owned.spawn(...args),
                    terminateTree: (...args) => owned.terminateTree(...args),
                    async close(options) {
                        state.closeCalls += 1;
                        return owned.close(options);
                    },
                };
            };
            try {
                await expect(runAutonomousInvestigation(
                    setup.config,
                    runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
                        processAdapter: makeProcessOwner(),
                        faultInjector(point, details) {
                            if (point === "after_harness_staging") {
                                const scorePath = path.join(
                                    details.candidateRoot,
                                    "score.txt",
                                );
                                if (fs.existsSync(scorePath)
                                    && fs.readFileSync(scorePath, "utf8").trim()
                                        === "95") {
                                    capturedLaunch = {
                                        stageRoot: details.stageRoot,
                                        executable: details.executable,
                                        dependencies: [...details.dependencies],
                                    };
                                }
                            }
                            if (!injected
                                && point === "after_effect_commit"
                                && details.command?.kind
                                    === "candidate-measurement") {
                                injected = true;
                                throw new InjectedCrashError(point);
                            }
                        },
                    }),
                )).rejects.toMatchObject({
                    code: RUNTIME_ERROR_CODES.INJECTED_CRASH,
                });
                expect(injected).toBe(true);
                expect(processOwners[0].closeCalls).toBe(1);
                expect(capturedLaunch).not.toBeNull();
                exactPaths = [
                    capturedLaunch.executable,
                    ...capturedLaunch.dependencies,
                ];
                expect(
                    await waitForNoExactWindowsProcess(exactPaths),
                ).toEqual([]);
                expect(fs.existsSync(capturedLaunch.stageRoot)).toBe(false);
                expect(
                    fs.readdirSync(path.join(setup.stateDir, "runtime-temp")),
                ).toEqual([]);

                const recovered = await runAutonomousInvestigation(
                    setup.config,
                    runnerDependencies(new ScriptedOrchestrationWorkerPool([]), {
                        processAdapter: makeProcessOwner(),
                    }),
                );
                expectScientificConfirmationRequired(recovered);
                expect(recovered.tempRootCleaned).toBe(true);
                expect(harnessCallCount(setup)).toBe(3);
                expect(processOwners[1].closeCalls).toBe(1);
                expect(
                    await waitForNoExactWindowsProcess(exactPaths),
                ).toEqual([]);
                expect(fs.existsSync(capturedLaunch.stageRoot)).toBe(false);
                expect(
                    fs.readdirSync(path.join(setup.stateDir, "runtime-temp")),
                ).toEqual([]);
            } finally {
                for (const processRecord of exactWindowsProcessesForPaths(
                    exactPaths,
                )) {
                    try {
                        process.kill(Number(processRecord.ProcessId), "SIGKILL");
                    } catch {
                        // Exact-path cleanup only; the process may already be gone.
                    }
                }
            }
        },
        120_000,
    );

    it.each([
        {
            label: "proposal dispatch",
            point: "after_effect_dispatch",
            matches: (details) => details.command?.kind === "sdk-proposal",
        },
        {
            label: "proposal response",
            point: "after_proposal_response",
            matches: (details) => details.command?.kind === "sdk-proposal",
        },
        {
            label: "harness launch",
            point: "after_harness_launch",
            matches: (_details, occurrence) => occurrence === 3,
        },
        {
            label: "harness exit",
            point: "after_harness_exit",
            matches: (_details, occurrence) => occurrence === 3,
        },
        {
            label: "receipt persistence",
            point: "after_measurement_receipt_persistence",
            matches: (details) => details.purpose === "candidate",
        },
    ])(
        "blocks automatic replay after an uncertain $label instead of duplicating the effect",
        async ({ label, point, matches }) => {
            const setup = setupInvestigation(
                `h7-uncertain-${label.replaceAll(" ", "-")}`,
                { maxRounds: 1 },
                { countHarnessCalls: true },
            );
            const firstPool = new ScriptedOrchestrationWorkerPool([95]);
            let injected = false;
            let pointOccurrences = 0;
            const processAdapter = point === "after_harness_launch"
                ? createControllableHarnessAdapter()
                : undefined;
            let crashError = null;
            try {
                await runAutonomousInvestigation(
                    setup.config,
                    runnerDependencies(firstPool, {
                        ...(processAdapter === undefined ? {} : { processAdapter }),
                        faultInjector(observedPoint, details) {
                            if (observedPoint === point) {
                                pointOccurrences += 1;
                            }
                            if (!injected
                                && observedPoint === point
                                && matches(details, pointOccurrences)) {
                                injected = true;
                                throw new InjectedCrashError(point);
                            }
                        },
                    }),
                );
            } catch (error) {
                crashError = error;
            }
            expect(
                crashError,
                `${label} returned ${crashError?.code ?? "no error"} at ${
                    crashError?.path ?? "unknown path"
                }`,
            ).toMatchObject({
                code: RUNTIME_ERROR_CODES.INJECTED_CRASH,
            });
            expect(injected).toBe(true);
            const callsBeforeRecovery = firstPool.calls.length;
            const harnessBeforeRecovery = harnessCallCount(setup);

            const recoveryPool = new ScriptedOrchestrationWorkerPool([95]);
            const result = await runAutonomousInvestigation(
                setup.config,
                runnerDependencies(recoveryPool),
            );
            expect(result).toMatchObject({
                kind: "NON_RESULT",
                code: RUNTIME_ERROR_CODES.UNCERTAIN_EXTERNAL_EFFECT,
                persisted: true,
            });
            expect(firstPool.calls).toHaveLength(callsBeforeRecovery);
            expect(recoveryPool.calls).toHaveLength(0);
            expect(harnessCallCount(setup)).toBe(harnessBeforeRecovery);

            const replayed = replaySetup(setup);
            expect(replayed.aggregate.terminal).toBeNull();
            expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(0);
            expect(replayed.adapter.latestOperationalNonResult()).toMatchObject({
                payload: {
                    code: RUNTIME_ERROR_CODES.UNCERTAIN_EXTERNAL_EFFECT,
                    details: {
                        resetRequired: true,
                    },
                },
            });
            replayed.repository.close();
            expect(fs.readdirSync(path.join(setup.stateDir, "runtime-temp"))).toEqual([]);
        },
        120_000,
    );

    it("rechecks the absolute deadline before a CAS retry can append evidence", async () => {
        const setup = setupInvestigation(
            "h7-deadline-cas-retry",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        const clock = mutableClock();
        const deadline = clock.now() + 30_000;
        let evidenceAttempts = 0;
        let injected = false;
        const repositoryFactory = (options) => {
            const repository = openRepository(options);
            return new Proxy(repository, {
                get(target, property) {
                    if (property === "appendEventsWithAttemptTransition") {
                        return (input) => {
                            const type = input.events?.[0]?.payload?.domainEvent?.type;
                            if (type === EVENT_TYPES.EVIDENCE_COMMITTED) {
                                evidenceAttempts += 1;
                                if (!injected && evidenceAttempts === 2) {
                                    injected = true;
                                    clock.advance(30_001);
                                    throw new CasConflictError("injected CAS retry");
                                }
                            }
                            return target.appendEventsWithAttemptTransition(input);
                        };
                    }
                    const value = Reflect.get(target, property, target);
                    return typeof value === "function" ? value.bind(target) : value;
                },
            });
        };

        const result = await runAutonomousInvestigation({
            ...setup.config,
            deadline,
        }, runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
            clock,
            repositoryFactory,
        }));
        expect(injected).toBe(true);
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            terminalEmitted: false,
        });
        const replayed = replaySetup(setup);
        expect(replayed.aggregate.terminal).toBeNull();
        expect(harnessCandidateEvidenceItems(replayed.aggregate)).toHaveLength(0);
        expect(Object.values(replayed.aggregate.observations)
            .some((observation) => observation.purpose === "candidate")).toBe(true);
        replayed.repository.close();
    }, 120_000);

    it("fails closed for representative persisted recovery corruption without rerunning effects", async () => {
        const setup = setupInvestigation(
            "h7-recovery-artifact-base",
            { maxRounds: 1 },
            { countHarnessCalls: true },
        );
        let injected = false;
        await expect(runAutonomousInvestigation(
            setup.config,
            runnerDependencies(new ScriptedOrchestrationWorkerPool([95]), {
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
            code: RUNTIME_ERROR_CODES.INJECTED_CRASH,
        });

        const persisted = replaySetup(setup);
        const db = new DatabaseSync(path.join(setup.stateDir, "events.sqlite"), {
            readOnly: true,
        });
        let capsuleRows;
        try {
            capsuleRows = db.prepare(`
                SELECT artifact_id, hash_value
                FROM artifacts
                WHERE investigation_id = ?
                  AND content_type = ?
                ORDER BY artifact_id ASC`).all(
                setup.config.investigationId,
                "application/vnd.crucible.effect-recovery+json",
            );
        } finally {
            db.close();
        }
        const store = openArtifactStore({ root: setup.artifactRoot });
        const capsules = capsuleRows.map((row) => ({
            artifactId: row.artifact_id,
            objectId: `sha256:${row.hash_value}`,
            value: JSON.parse(store.readObject(`sha256:${row.hash_value}`).toString("utf8")),
        }));
        const measurementCapsule = capsules.find((item) =>
            item.value.command.kind === "candidate-measurement");
        expect(measurementCapsule).toBeTruthy();
        const measurement = measurementCapsule.value.evidence.find((item) =>
            item.kind === "runtime:measurement").payload;
        const artifacts = {
            capsule: {
                artifactId: measurementCapsule.artifactId,
                objectId: measurementCapsule.objectId,
            },
            receipt: measurement.measurementProvenance.receiptArtifact,
            stdout: measurement.measurementProvenance.rawStdoutArtifact,
            stderr: measurement.measurementProvenance.rawStderrArtifact,
            manifest: measurement.measurementProvenance.snapshot.manifestArtifact,
            object: measurement.measurementProvenance.snapshot.objectArtifacts[0],
        };
        persisted.repository.close();
        const baselineHarnessCalls = harnessCallCount(setup);

        const recoveryCases = [
            { label: "capsule-missing", artifact: artifacts.capsule, mode: "missing" },
            { label: "receipt-corrupt", artifact: artifacts.receipt, mode: "corrupt" },
            {
                label: "snapshot-object-substitute",
                artifact: artifacts.object,
                mode: "substitute",
            },
        ];
        for (const { label, artifact, mode } of recoveryCases) {
            const branch = clonePersistedSetup(setup, `h7-recovery-${label}`);
            const branchStore = openArtifactStore({ root: branch.artifactRoot });
            const objectPath = branchStore.objectPath(artifact.objectId);
            if (mode === "missing") {
                fs.rmSync(objectPath, { force: true });
            } else if (mode === "substitute") {
                const replacement = Object.values(artifacts)
                    .find((candidate) => candidate.objectId !== artifact.objectId);
                fs.writeFileSync(
                    objectPath,
                    branchStore.readObject(replacement.objectId),
                );
            } else {
                const original = fs.readFileSync(objectPath);
                const mutated = original.length === 0
                    ? Buffer.from([1])
                    : Buffer.concat([
                        Buffer.from([original[0] ^ 0xff]),
                        original.subarray(1),
                    ]);
                fs.writeFileSync(objectPath, mutated);
            }

            await expect(runAutonomousInvestigation(
                branch.config,
                runnerDependencies(new ScriptedOrchestrationWorkerPool([])),
            ), label).rejects.toMatchObject({
                code: RUNTIME_ERROR_CODES.INTEGRITY_FAILURE,
            });
            expect(harnessCallCount(setup)).toBe(baselineHarnessCalls);
            const branchReplay = replaySetup(branch);
            expect(branchReplay.aggregate.terminal).toBeNull();
            expect(harnessCandidateEvidenceItems(branchReplay.aggregate)).toHaveLength(0);
            branchReplay.repository.close();
        }
    }, 300_000);
});
