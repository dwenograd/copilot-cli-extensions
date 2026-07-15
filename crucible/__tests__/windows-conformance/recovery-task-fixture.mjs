import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startInvestigation, makeDefaultDeps } from "../../api/handlers.mjs";
import { configureExperiment } from "../../tools/configure-experiment.mjs";
import {
    createPowerShellTaskSchedulerAdapter,
    uninstallRecoveryTask,
} from "../../tools/recovery-task.mjs";
import {
    openArtifactStore,
    openRepository,
} from "../../persistence/index.mjs";
import { loadHarnessAllowlist } from "../../measurement/index.mjs";
import {
    openResourceBroker,
    openResourceBrokerFromStateRoot,
    requestStop,
    supervisorConfigDocument,
} from "../../runtime/index.mjs";
import {
    buildHarnessSuiteForAllowlist,
    fakeHypothesisPolicy,
    fakeObservableRegistry,
    fakeStatisticalPolicy,
} from "../v4-contract-fixture.mjs";
import {
    createExperimentAuthorityFixture,
    prepareAndSignExperiment,
} from "../experiment-authority-fixture.mjs";
import { removeTreeRobust } from "../test-cleanup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLEANUP_FILE = "recovery-task-cleanup.json";
const LOCK_FILE = ".recovery-task-conformance.lock";
const OWNER_FILE = "recovery-task-owner.json";
const ROOT_PREFIXES = Object.freeze([
    ".recovery-identity-task-conformance-",
    ".recovery-task-conformance-",
]);

function sha256File(file) {
    return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function processAlive(pid) {
    if (!Number.isSafeInteger(pid) || pid < 1) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

export async function acquireRecoveryTaskConformanceLock(
    parent = HERE,
    timeoutMs = 180_000,
) {
    const file = path.join(parent, LOCK_FILE);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        try {
            const fd = fs.openSync(file, "wx");
            try {
                fs.writeFileSync(fd, JSON.stringify({
                    version: 1,
                    ownerProcessId: process.pid,
                    acquiredAt: new Date().toISOString(),
                }));
            } finally {
                fs.closeSync(fd);
            }
            return Object.freeze({ file, ownerProcessId: process.pid });
        } catch (error) {
            if (error?.code !== "EEXIST") throw error;
            let owner = null;
            let invalidOwner = false;
            try {
                owner = JSON.parse(fs.readFileSync(file, "utf8"));
            } catch {
                invalidOwner = true;
            }
            const invalidIsStale = invalidOwner
                && Date.now() - fs.statSync(file).mtimeMs >= 30_000;
            if (invalidIsStale
                || (!invalidOwner && !processAlive(owner?.ownerProcessId))) {
                try {
                    fs.rmSync(file, { force: true });
                    continue;
                } catch {
                    // Another waiter may have replaced the stale lock.
                }
            }
            if (Date.now() >= deadline) {
                throw new Error(
                    `timed out waiting for Task Scheduler conformance lock ${file}`,
                );
            }
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }
}

export function releaseRecoveryTaskConformanceLock(lock) {
    if (lock?.ownerProcessId !== process.pid
        || typeof lock.file !== "string"
        || !fs.existsSync(lock.file)) {
        return false;
    }
    const observed = JSON.parse(fs.readFileSync(lock.file, "utf8"));
    if (observed?.ownerProcessId !== process.pid) {
        throw new Error("Task Scheduler conformance lock ownership changed");
    }
    fs.rmSync(lock.file, { force: true });
    return true;
}

export function claimRecoveryTaskFixtureRoot(root) {
    fs.writeFileSync(
        path.join(root, OWNER_FILE),
        JSON.stringify({
            version: 1,
            ownerProcessId: process.pid,
            claimedAt: new Date().toISOString(),
        }),
    );
}

function ownedByAnotherLiveProcess(root) {
    const file = path.join(root, OWNER_FILE);
    if (!fs.existsSync(file)) return false;
    try {
        const owner = JSON.parse(fs.readFileSync(file, "utf8"));
        return owner?.ownerProcessId !== process.pid
            && processAlive(owner?.ownerProcessId);
    } catch {
        return false;
    }
}

function recentlyUnclaimed(root) {
    if (fs.existsSync(path.join(root, OWNER_FILE))) return false;
    try {
        return Date.now() - fs.statSync(root).mtimeMs < 10 * 60_000;
    } catch {
        return false;
    }
}

function runPowerShell(script, env = {}) {
    const result = spawnSync(
        "powershell.exe",
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        {
            encoding: "utf8",
            env: { ...process.env, ...env },
            windowsHide: true,
            maxBuffer: 4 * 1024 * 1024,
        },
    );
    if (result.error !== undefined || result.status !== 0) {
        throw new Error(
            `PowerShell fixture operation failed: status=${
                result.status ?? "null"
            }; signal=${result.signal ?? "none"}; stderr=${result.stderr}`,
            result.error === undefined ? undefined : { cause: result.error },
        );
    }
    return result.stdout.trim();
}

function listExactProcesses(root) {
    const output = runPowerShell(String.raw`
$ErrorActionPreference = "Stop"
$root = $env:CRUCIBLE_FIXTURE_ROOT
$items = @(
    Get-CimInstance Win32_Process |
        Where-Object {
            $null -ne $_.CommandLine -and
            $_.CommandLine.Contains($root)
        } |
        ForEach-Object {
            [ordered]@{
                pid = [int]$_.ProcessId
                name = [string]$_.Name
                command = [string]$_.CommandLine
            }
        }
)
ConvertTo-Json -InputObject @($items | Sort-Object pid) -Depth 3 -Compress
`, {
        CRUCIBLE_FIXTURE_ROOT: root,
    });
    const parsed = JSON.parse(output || "[]");
    return Array.isArray(parsed) ? parsed : [parsed];
}

async function terminateExactProcesses(root) {
    const failures = [];
    for (const record of listExactProcesses(root)) {
        if (record.pid === process.pid) continue;
        try {
            process.kill(record.pid, "SIGKILL");
        } catch (error) {
            if (error?.code !== "ESRCH") failures.push(error);
        }
    }
    const deadline = Date.now() + 10_000;
    let remaining = listExactProcesses(root)
        .filter((entry) => entry.pid !== process.pid);
    while (remaining.length > 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 50));
        remaining = listExactProcesses(root)
            .filter((entry) => entry.pid !== process.pid);
    }
    if (remaining.length > 0) {
        failures.push(new Error(
            `test-owned processes survived cleanup: ${
                JSON.stringify(remaining)
            }`,
        ));
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            "scheduler fixture process cleanup failed",
        );
    }
}

function writeFakeSdk(sdkPath) {
    fs.mkdirSync(sdkPath, { recursive: true });
    fs.writeFileSync(
        path.join(sdkPath, "package.json"),
        JSON.stringify({ type: "module" }),
    );
    fs.writeFileSync(path.join(sdkPath, "index.js"), `
export const RuntimeConnection = {
    forStdio(options) {
        return Object.freeze({ ...options });
    },
};

export class CopilotClient {
    constructor(options) {
        this.options = options;
    }

    async start() {}
    async stop() { return []; }
    async forceStop() {}
    async getAuthStatus() { return { isAuthenticated: true }; }
    async listModels() { return [{ id: "model-a" }]; }

    async createSession(config) {
        return {
            async sendAndWait({ prompt }) {
                const candidateId = prompt.match(
                    /Your assigned candidateId is exactly: ([^\\r\\n]+)/u,
                )?.[1];
                const challenge = prompt.match(
                    /Your challenge nonce is exactly: ([^\\r\\n]+)/u,
                )?.[1];
                const submit = config.tools.find(
                    (tool) => tool.name === "crucible_submit_candidate",
                );
                if (candidateId === undefined
                    || challenge === undefined
                    || submit === undefined) {
                    throw new Error("scheduler SDK fixture received no assignment");
                }
                const response = await submit.handler({
                    challenge,
                    candidateId,
                    annotations: {
                        mechanism: "Task Scheduler recovery candidate",
                    },
                    files: [{ path: "score.txt", content: "95\\n" }],
                }, {
                    sessionId: config.sessionId,
                    toolCallId: "scheduler-recovery-submit",
                    toolName: submit.name,
                });
                if (response.resultType !== "success") {
                    throw new Error(response.textResultForLlm);
                }
                return { data: { content: "" } };
            },
            async abort() {},
            async disconnect() {},
        };
    }
}
`);
}

function seedSnapshot(store, root, id, score) {
    const sourceDir = path.join(root, `case-${id}`);
    fs.mkdirSync(sourceDir, { recursive: true });
    fs.writeFileSync(path.join(sourceDir, "score.txt"), `${score}\n`);
    fs.writeFileSync(path.join(sourceDir, "case-id.txt"), `${id}\n`);
    return store.ingestDirectory({ sourceDir }).snapshot;
}

function writeHarness(root, caseStoreRoot) {
    const store = openArtifactStore({ root: caseStoreRoot });
    const snapshots = {
        good: seedSnapshot(store, root, "known-good", 100),
        bad: seedSnapshot(store, root, "known-bad", 0),
        search: seedSnapshot(store, root, "search", 100),
        confirmation: seedSnapshot(store, root, "confirmation", 100),
        challenge: seedSnapshot(store, root, "challenge", -1),
        novelty: seedSnapshot(store, root, "novelty", 100),
    };
    const script = path.join(root, "score-harness.mjs");
    fs.writeFileSync(script, `
import fs from "node:fs";
import path from "node:path";
const candidatePath = process.argv[2];
const score = Number(
    fs.readFileSync(path.join(candidatePath, "score.txt"), "utf8").trim(),
);
process.stdout.write(JSON.stringify({
    pass: Number.isFinite(score) && score >= 90,
    metrics: { score },
}));
`);
    const allowlistPath = path.join(root, "harness.allowlist.json");
    const document = {
        version: 1,
        entries: {
            "score-harness": {
                executable: process.execPath,
                executableSha256: sha256File(process.execPath),
                argvTemplate: [script, "{{candidatePath}}"],
                dependencies: [{
                    path: script,
                    sha256: sha256File(script),
                    role: "harness-script",
                }],
                allowedEnv: {},
                timeoutMs: 15_000,
                maxStdoutBytes: 1024 * 1024,
                maxStderrBytes: 256 * 1024,
                executesCandidateCode: false,
                validationCases: {
                    good: {
                        snapshotHash: snapshots.good,
                        expectation: "accept",
                    },
                    bad: {
                        snapshotHash: snapshots.bad,
                        expectation: "reject",
                    },
                    search: {
                        snapshotHash: snapshots.search,
                        expectation: "accept",
                    },
                    confirmation: {
                        snapshotHash: snapshots.confirmation,
                        expectation: "accept",
                    },
                    challenge: {
                        snapshotHash: snapshots.challenge,
                        expectation: "reject",
                    },
                    novelty: {
                        snapshotHash: snapshots.novelty,
                        expectation: "accept",
                    },
                },
            },
        },
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(document, null, 2));
    const initial = loadHarnessAllowlist(allowlistPath);
    document.suites = {
        "score-suite": buildHarnessSuiteForAllowlist(initial, {
            suiteId: "score-suite",
            harnessId: "score-harness",
            roleCaseIds: {
                calibration: ["good", "bad"],
                search: ["search"],
                confirmation: ["confirmation"],
                challenge: ["challenge"],
                novelty: ["novelty"],
            },
        }),
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(document, null, 2));
    loadHarnessAllowlist(allowlistPath);
    return { allowlistPath, snapshots };
}

export async function seedEligibleRecoveryInvestigation(
    stateRoot,
    fixtureRoot = path.dirname(stateRoot),
) {
    const projectDir = path.join(fixtureRoot, "project");
    const caseStoreRoot = path.join(fixtureRoot, "operator-cases");
    const registryPath = path.join(fixtureRoot, "experiments.json");
    const cliPackagePath = path.join(fixtureRoot, "cli-package");
    const sdkPath = path.join(cliPackagePath, "copilot-sdk");
    fs.mkdirSync(projectDir, { recursive: true });
    fs.mkdirSync(cliPackagePath, { recursive: true });
    fs.writeFileSync(
        path.join(cliPackagePath, "package.json"),
        JSON.stringify({ name: "scheduler-fixture-copilot", type: "module" }),
    );
    fs.writeFileSync(path.join(cliPackagePath, "app.js"), "export {};\n");
    writeFakeSdk(sdkPath);
    const { allowlistPath, snapshots } = writeHarness(
        fixtureRoot,
        caseStoreRoot,
    );
    const authorityFixture = createExperimentAuthorityFixture();
    const statisticalPolicy = fakeStatisticalPolicy({
        topology: "open_generative",
        searchSlots: 1,
        control: { kind: "snapshot", identity: snapshots.good },
    });
    const authority = {
        objective: "Task Scheduler recovery conformance",
        project_dir: projectDir,
        harness_suite_id: "score-suite",
        acceptance_predicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: 0,
        },
        hypothesis_topology: "open_generative",
        observable_registry: fakeObservableRegistry().map((observable) => ({
            ...observable,
            maximum: 100,
        })),
        hypothesis_policy: fakeHypothesisPolicy(),
        statistical_policy: {
            ...statisticalPolicy,
            metrics: statisticalPolicy.metrics.map((metric) => ({
                ...metric,
                maximum: 100,
                acceptanceThreshold: 0,
                practicalEquivalenceDelta: 1,
            })),
        },
        worker_models: ["model-a"],
        candidates_per_round: 1,
        max_rounds: 1,
    };
    const experimentId = `scheduler-${createHash("sha256")
        .update(JSON.stringify(authority))
        .digest("hex")
        .slice(0, 24)}`;
    const config = {
        experiment_id: experimentId,
        ...authority,
    };
    const env = {
        ...process.env,
        CRUCIBLE_ALLOWLIST_PATH: allowlistPath,
        CRUCIBLE_CASE_STORE_PATH: caseStoreRoot,
        CRUCIBLE_EXPERIMENT_REGISTRY_PATH: registryPath,
        CRUCIBLE_STATE_ROOT: stateRoot,
        CRUCIBLE_CLI_PACKAGE_PATH: cliPackagePath,
        CRUCIBLE_NODE_PATH: process.execPath,
        COPILOT_SDK_PATH: sdkPath,
        COPILOT_CLI_PATH: process.execPath,
        ...authorityFixture.env,
    };
    const { signature } = prepareAndSignExperiment({
        config,
        allowlistPath,
        env,
        privateKey: authorityFixture.privateKey,
    });
    configureExperiment({
        config,
        registryPath,
        allowlistPath,
        signature,
        env,
    });
    const deps = {
        ...makeDefaultDeps(env),
        ensureSupervisor(supervisorConfig) {
            const normalized = supervisorConfig;
            fs.mkdirSync(normalized.paths.directory, { recursive: true });
            fs.writeFileSync(
                normalized.paths.configPath,
                `${JSON.stringify(supervisorConfigDocument(normalized))}\n`,
            );
            if (normalized.runner.resourceBroker === null) {
                throw new Error(
                    "scheduler recovery fixture requires a resource broker",
                );
            }
            const supervisorGeneration = 1;
            const supervisorNonce = "scheduler-seed-supervisor";
            const runnerIncarnation = "scheduler-seed-runner";
            const repository = openRepository({
                file: path.join(normalized.runner.stateDir, "events.sqlite"),
            });
            try {
                repository.claimSupervisorGeneration({
                    investigationId: normalized.runner.investigationId,
                    supervisorGeneration,
                    supervisorNonce,
                });
                repository.issueRunnerIncarnation({
                    investigationId: normalized.runner.investigationId,
                    supervisorGeneration,
                    supervisorNonce,
                    runnerIncarnation,
                });
            } finally {
                repository.close();
            }
            const broker = openResourceBroker({
                stateRoot: normalized.runner.resourceBroker.stateRoot,
                config: normalized.runner.resourceBroker.config,
                env,
            });
            try {
                broker.registerInvestigation({
                    investigationId: normalized.runner.investigationId,
                    limits:
                        normalized.runner.resourceBroker.investigationLimits,
                    supervisorGeneration,
                    supervisorNonce,
                    runnerIncarnation,
                });
            } finally {
                broker.close();
            }
            return {
                action: "started",
                pid: process.pid,
                acknowledged: true,
                acknowledgement: {
                    supervisorGeneration,
                    runnerIncarnation,
                    configFingerprint: "sha256:scheduler-seed",
                    deadlineMs: supervisorConfig.runner.deadlineMs,
                },
            };
        },
        probeSandboxAvailability: () => ({ available: true }),
        readStatus: () => null,
        readSupervisorLock: () => null,
        isPidAlive: () => false,
    };
    const started = await startInvestigation({
        experiment_id: experimentId,
    }, deps);
    return Object.freeze({
        investigationId: started.investigation_id,
        stateRoot,
        stateDir: path.dirname(started.events_db_path),
        artifactRoot: path.join(
            path.dirname(path.dirname(started.events_db_path)),
            "artifacts",
        ),
        env,
    });
}

function cleanupPath(root) {
    return path.join(root, CLEANUP_FILE);
}

export function prepareRecoveryTaskCleanup({
    root,
    options,
    investigation,
}) {
    const manifest = {
        version: 2,
        options,
        investigation: {
            investigationId: investigation.investigationId,
            stateDir: investigation.stateDir,
            artifactRoot: investigation.artifactRoot,
        },
    };
    fs.writeFileSync(cleanupPath(root), JSON.stringify(manifest, null, 2));
    return manifest;
}

function readCleanupManifest(root) {
    const file = cleanupPath(root);
    if (!fs.existsSync(file)) return null;
    const manifest = JSON.parse(fs.readFileSync(file, "utf8"));
    if (manifest?.version !== 2
        || typeof manifest.options !== "object"
        || typeof manifest.investigation !== "object") {
        throw new Error(`invalid scheduler cleanup manifest at ${file}`);
    }
    return manifest;
}

function tryStopInvestigation(manifest) {
    const investigation = manifest?.investigation;
    if (typeof investigation?.stateDir !== "string"
        || typeof investigation?.investigationId !== "string"
        || !fs.existsSync(path.join(investigation.stateDir, "events.sqlite"))) {
        return;
    }
    try {
        requestStop({
            stateDir: investigation.stateDir,
            artifactRoot: investigation.artifactRoot,
            investigationId: investigation.investigationId,
            reason: "Task Scheduler conformance cleanup.",
            requestId: "scheduler-conformance-cleanup",
        });
    } catch {
        // Exact-path process cleanup below is the fail-safe.
    }
}

export async function cleanupRecoveryTaskFixtureRoot(root) {
    const failures = [];
    let taskAbsent = false;
    let manifest = null;
    try {
        manifest = readCleanupManifest(root);
    } catch (error) {
        failures.push(error);
    }
    if (manifest !== null) {
        const adapter = createPowerShellTaskSchedulerAdapter();
        try {
            const removal = await uninstallRecoveryTask(
                manifest.options,
                { adapter },
            );
            const after = await adapter.inspect(removal.spec);
            taskAbsent = after?.exists !== true;
            if (!taskAbsent) {
                failures.push(new Error(
                    "exact Task Scheduler action still exists after cleanup",
                ));
            }
        } catch (error) {
            failures.push(new Error(
                "exact Task Scheduler uninstall failed",
                { cause: error },
            ));
        }
        tryStopInvestigation(manifest);
    } else {
        taskAbsent = true;
    }
    try {
        await terminateExactProcesses(root);
    } catch (error) {
        failures.push(error);
    }
    let rootRemoved = false;
    if (taskAbsent && failures.length === 0) {
        await removeTreeRobust(root, {
            label: "Task Scheduler conformance root",
            timeoutMs: 30_000,
        });
        rootRemoved = !fs.existsSync(root);
        if (!rootRemoved) {
            failures.push(new Error(
                `scheduler conformance root survived cleanup: ${root}`,
            ));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            `Task Scheduler conformance cleanup failed; state retained at ${root}`,
        );
    }
    return Object.freeze({ taskAbsent, rootRemoved });
}

export async function cleanupRecoveryTaskFixtureRoots(parent = HERE) {
    if (!fs.existsSync(parent)) return [];
    const roots = fs.readdirSync(parent, { withFileTypes: true })
        .filter((entry) =>
            entry.isDirectory()
            && ROOT_PREFIXES.some((prefix) => entry.name.startsWith(prefix)))
        .map((entry) => path.join(parent, entry.name))
        .filter((root) => !ownedByAnotherLiveProcess(root))
        .filter((root) => !recentlyUnclaimed(root))
        .sort();
    const cleaned = [];
    const failures = [];
    for (const root of roots) {
        try {
            cleaned.push(await cleanupRecoveryTaskFixtureRoot(root));
        } catch (error) {
            failures.push(error);
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            "interrupted Task Scheduler conformance cleanup failed",
        );
    }
    return cleaned;
}

export function readRecoveryOperation(stateRoot, investigationId) {
    const broker = openResourceBrokerFromStateRoot({ stateRoot });
    try {
        return broker.getRecoveryOperation(investigationId);
    } finally {
        broker.close();
    }
}

export function readRecoveryLease(stateRoot) {
    const broker = openResourceBrokerFromStateRoot({ stateRoot });
    try {
        return broker.getRecoveryDaemonLease();
    } finally {
        broker.close();
    }
}
