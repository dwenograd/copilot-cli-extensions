import fs from "node:fs";
import path from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    openRepository,
} from "../persistence/index.mjs";
import {
    DEFAULT_RESOURCE_BROKER_CONFIG,
    RUNTIME_ERROR_CODES,
    CrucibleRuntimeError,
    deriveRunnerExecutionLimits,
    deriveRuntimeResourceAdmission,
    normalizeSupervisorConfig,
    openResourceBroker,
    requestStop,
    runSupervisor,
    startSupervisor,
    supervisorConfigDocument,
} from "../runtime/index.mjs";
import {
    cleanupImpossibilityRunnerFixture,
    replayImpossibilityRunnerFixture,
    runImpossibilityRunnerFixture,
    setupImpossibilityRunnerFixture,
} from "./impossibility-runner-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNNER_CLI = path.join(HERE, "..", "runtime", "runner-cli.mjs");
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.runtime-integration-${label}-`),
    );
    roots.push(root);
    return root;
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 20,
            retryDelay: 25,
        });
    }
});

function runtimeConfig(root) {
    const stateRoot = path.join(root, "state-root");
    const admission = deriveRuntimeResourceAdmission({
        executionLimits: {
            candidateEvaluations: 2,
            byteBudgets: {
                perAttemptOutputBytes: 100,
                perInvestigationOutputBytes: 1_000,
                perAttemptReceiptBytes: 100,
                perInvestigationReceiptBytes: 1_000,
                perAttemptCasBytes: 100,
                perInvestigationCasBytes: 1_000,
            },
        },
        deadlineMs: Date.now() + 60_000,
    });
    return normalizeSupervisorConfig({
        runner: {
            investigationId: "runtime-integration",
            stateDir: path.join(
                stateRoot,
                "runtime-integration",
                "state",
            ),
            artifactRoot: path.join(
                stateRoot,
                "runtime-integration",
                "artifacts",
            ),
            allowlistPath: path.join(root, "allowlist.json"),
            copilotSdkPath: path.join(root, "sdk"),
            copilotCliPath: path.join(root, "copilot.exe"),
            runnerEpochId: "runtime-integration-epoch",
            deadline: Date.now() + 60_000,
            resourceBroker: {
                stateRoot,
                config: admission.config,
                configFingerprint: admission.configFingerprint,
                investigationLimits: admission.investigationLimits,
                limitsFingerprint: admission.limitsFingerprint,
            },
            options: {
                sdkRetryPolicy: admission.sdkRetryPolicy,
            },
        },
        runnerCliPath: RUNNER_CLI,
    });
}

describe("v4 production runtime wiring", () => {
    it("freezes broker and retry policy into the supervisor document", () => {
        const config = runtimeConfig(makeRoot("config"));
        const document = supervisorConfigDocument(config);

        expect(document.runner.resourceBroker).toMatchObject({
            stateRoot: config.runner.resourceBroker.stateRoot,
            configFingerprint:
                config.runner.resourceBroker.configFingerprint,
            limitsFingerprint:
                config.runner.resourceBroker.limitsFingerprint,
        });
        expect(document.runner.options.sdkRetryPolicy).toMatchObject({
            maxAttempts: 3,
            reservedCostUnitsPerAttempt:
                expect.any(Number),
            maxCostUnits: expect.any(Number),
        });
    });

    it("verifies runtime and broker admission immediately before spawn", () => {
        const config = runtimeConfig(makeRoot("launch-order"));
        const order = [];
        const result = startSupervisor(config, {
            nodeExecutable: process.execPath,
            beforeSupervisorLaunch() {
                order.push("before-launch");
            },
            verifySupervisorRuntimeAuthority() {
                order.push("runtime-verified");
                return { runtimeIdentityRoot: "runtime-root" };
            },
            resourceBrokerFactory() {
                order.push("broker-open");
                return {
                    configFingerprint:
                        config.runner.resourceBroker.configFingerprint,
                    databaseFile: path.join(
                        config.runner.resourceBroker.stateRoot,
                        "resource-catalog.sqlite",
                    ),
                    verifyIntegrity() {
                        order.push("broker-verified");
                    },
                    close() {
                        order.push("broker-close");
                    },
                };
            },
            spawnProcess() {
                order.push("spawn");
                return { pid: 1234, unref() {} };
            },
        });

        expect(order).toEqual([
            "before-launch",
            "runtime-verified",
            "broker-open",
            "broker-verified",
            "broker-close",
            "spawn",
        ]);
        expect(result).toMatchObject({
            pid: 1234,
            runtime: {
                runtimeIdentityRoot: "runtime-root",
            },
            broker: {
                configFingerprint:
                    config.runner.resourceBroker.configFingerprint,
            },
        });
    });

    it("blocks a mutated runtime before any supervisor process effect", () => {
        const config = runtimeConfig(makeRoot("drift"));
        let spawned = false;

        expect(() => startSupervisor(config, {
            nodeExecutable: process.execPath,
            verifySupervisorRuntimeAuthority() {
                throw new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.RUNTIME_DRIFT,
                    "mutated runtime",
                );
            },
            resourceBrokerFactory() {
                throw new Error("broker must not open after runtime drift");
            },
            spawnProcess() {
                spawned = true;
                return { pid: 1, unref() {} };
            },
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.RUNTIME_DRIFT,
        }));
        expect(spawned).toBe(false);
    });

    it("claims broker authority before the runner and publishes opaque health", async () => {
        const config = runtimeConfig(makeRoot("supervisor"));
        const order = [];
        let registered = null;
        const broker = {
            configFingerprint:
                config.runner.resourceBroker.configFingerprint,
            getInvestigation() {
                return null;
            },
            registerInvestigation(input) {
                order.push("broker-authority");
                registered = input;
                return { created: true };
            },
            claimAuthority() {
                throw new Error("unexpected broker authority recovery");
            },
            listActiveLeases() {
                return [];
            },
            close() {
                order.push("broker-close");
            },
        };
        const result = await runSupervisor(config, {
            pid: 8801,
            idFactory: () => "runtime-integration-owner",
            isPidAlive: () => false,
            runtimeAuthority: {
                runtimeIdentity: { root: "signed-runtime-root" },
            },
            runtimeIdentityVerifier: async ({ stage }) => {
                order.push(`runtime:${stage}`);
            },
            resourceBrokerFactory: () => broker,
            runnerIncarnationFactory: () => "runner-incarnation-1",
            spawnRunner: async (launchConfig) => {
                order.push("runner-spawn");
                const child = new EventEmitter();
                child.pid = 9911;
                setImmediate(() => {
                    fs.writeFileSync(
                        launchConfig.paths.childResultPath,
                        `${JSON.stringify({
                            version: 1,
                            ok: true,
                            state: "non_result",
                            terminal_available: false,
                            non_result_code: "FAKE_COMPLETE",
                        })}\n`,
                    );
                    child.emit("close", 0, null);
                });
                return {
                    child,
                    resultPath: launchConfig.paths.childResultPath,
                };
            },
        });

        expect(order.indexOf("broker-authority"))
            .toBeLessThan(order.indexOf("runner-spawn"));
        expect(registered).toMatchObject({
            investigationId: "runtime-integration",
            supervisorGeneration: 1,
            runnerIncarnation: "runner-incarnation-1",
        });
        expect(result.status).toMatchObject({
            state: "non_result",
            runtimeIdentity: {
                verified: true,
                root: "signed-runtime-root",
            },
            resourceBroker: {
                healthy: true,
                activeLeaseCount: 0,
            },
            controlChannel: {
                healthy: true,
            },
        });
    });

    it("keeps a stop non-resumable when a live child lacks exact owner status", async () => {
        const setup = setupImpossibilityRunnerFixture(
            "missing-supervisor-status",
        );
        const authority = {
            supervisorGeneration: 1,
            supervisorNonce: "missing-status-owner",
            runnerIncarnation: "missing-status-runner",
        };
        const repository = openRepository({
            file: path.join(setup.stateDir, "events.sqlite"),
        });
        repository.claimSupervisorGeneration({
            investigationId: setup.config.investigationId,
            supervisorGeneration: authority.supervisorGeneration,
            supervisorNonce: authority.supervisorNonce,
        });
        repository.issueRunnerIncarnation({
            investigationId: setup.config.investigationId,
            ...authority,
        });
        repository.acquireLease({
            investigationId: setup.config.investigationId,
            leaseId: "missing-status-lease",
            owner: "missing-status-runner-owner",
            supervisorGeneration: authority.supervisorGeneration,
            runnerIncarnation: authority.runnerIncarnation,
        });
        repository.close();

        try {
            const stopped = requestStop({
                stateDir: setup.stateDir,
                artifactRoot: setup.artifactRoot,
                investigationId: setup.config.investigationId,
                requestId: "missing-status-stop",
                readLock: () => ({
                    pid: 19_001,
                    nonce: authority.supervisorNonce,
                    supervisorGeneration:
                        authority.supervisorGeneration,
                }),
                readSupervisorState: () => ({
                    childPid: 19_002,
                }),
                isPidAlive: () => true,
            });
            expect(stopped).toMatchObject({
                pausePersisted: false,
                quiescent: false,
                interventionRequired: true,
                stop: {
                    state: "PAUSE_PENDING",
                    quiescent: false,
                    interventionRequired: true,
                    targetRunnerPid: 19_002,
                    nonResultCode:
                        RUNTIME_ERROR_CODES.NON_QUIESCENT,
                    details: {
                        proof: {
                            verified: false,
                            quiescent: false,
                            missingVerifications:
                                expect.arrayContaining([
                                    "supervisor_status_ownership",
                                    "runner_child",
                                    "owned_processes",
                                    "sdk_sessions",
                                ]),
                        },
                    },
                },
            });
            expect(stopped.aggregate.pause).toBeNull();
        } finally {
            await cleanupImpossibilityRunnerFixture(setup);
        }
    });

    it("fences and quarantines an effect after TTL expiry lets another holder reclaim its slot", async () => {
        const setup = setupImpossibilityRunnerFixture("lease-reclaim");
        const stateRoot = path.join(setup.root, "resource-state");
        const investigationRoot = path.join(
            stateRoot,
            setup.config.investigationId,
        );
        const stateDir = path.join(investigationRoot, "state");
        const artifactRoot = path.join(investigationRoot, "artifacts");
        fs.mkdirSync(investigationRoot, { recursive: true });
        fs.renameSync(setup.stateDir, stateDir);
        fs.renameSync(setup.artifactRoot, artifactRoot);
        setup.stateDir = stateDir;
        setup.artifactRoot = artifactRoot;
        setup.config = {
            ...setup.config,
            stateDir,
            artifactRoot,
        };
        const brokerConfig = {
            ...DEFAULT_RESOURCE_BROKER_CONFIG,
            lease: {
                defaultTtlMs: 60,
                maxTtlMs: 1_000,
            },
            capacities: {
                ...DEFAULT_RESOURCE_BROKER_CONFIG.capacities,
                sdkSessions: 1,
                sandboxProcesses: 1,
                cpuSlots: { general: 1 },
            },
        };
        const admission = deriveRuntimeResourceAdmission({
            executionLimits: deriveRunnerExecutionLimits(setup.contract),
            deadlineMs: setup.config.deadline,
            brokerConfig,
        });
        const supervisorAuthority = {
            supervisorGeneration: 1,
            supervisorNonce: "lease-supervisor",
            runnerIncarnation: "lease-runner-one",
        };
        const repository = openRepository({
            file: path.join(setup.stateDir, "events.sqlite"),
        });
        repository.claimSupervisorGeneration({
            investigationId: setup.config.investigationId,
            supervisorGeneration:
                supervisorAuthority.supervisorGeneration,
            supervisorNonce: supervisorAuthority.supervisorNonce,
        });
        repository.issueRunnerIncarnation({
            investigationId: setup.config.investigationId,
            ...supervisorAuthority,
        });
        repository.close();
        setup.config = {
            ...setup.config,
            ...supervisorAuthority,
            resourceBroker: {
                stateRoot,
                config: admission.config,
                configFingerprint: admission.configFingerprint,
                investigationLimits: admission.investigationLimits,
                limitsFingerprint: admission.limitsFingerprint,
            },
            options: {
                ...setup.config.options,
                sdkRetryPolicy: admission.sdkRetryPolicy,
            },
        };

        const clock = {
            value: Date.now(),
            now() {
                return this.value;
            },
            isoNow() {
                return new Date(this.value).toISOString();
            },
            advance(milliseconds) {
                this.value += milliseconds;
            },
        };
        const runnerBroker = openResourceBroker({
            stateRoot,
            config: admission.config,
            now: () => clock.now(),
        });
        const holderBroker = openResourceBroker({
            stateRoot,
            config: admission.config,
            now: () => clock.now(),
        });
        holderBroker.registerInvestigation({
            investigationId: "concurrent-holder",
            limits: admission.investigationLimits,
            supervisorGeneration: 1,
            supervisorNonce: "holder-supervisor",
            runnerIncarnation: "holder-runner",
        });
        let replacement = null;
        let renewCalls = 0;
        const broker = {
            get config() {
                return runnerBroker.config;
            },
            get configFingerprint() {
                return runnerBroker.configFingerprint;
            },
            get databaseFile() {
                return runnerBroker.databaseFile;
            },
            verifyIntegrity: () => runnerBroker.verifyIntegrity(),
            registerInvestigation: (input) =>
                runnerBroker.registerInvestigation(input),
            getInvestigation: (id) =>
                runnerBroker.getInvestigation(id),
            claimAuthority: (input) =>
                runnerBroker.claimAuthority(input),
            acquire: (input) => runnerBroker.acquire(input),
            renew(input) {
                renewCalls += 1;
                if (replacement === null) {
                    clock.advance(
                        admission.config.lease.defaultTtlMs + 1,
                    );
                    replacement = holderBroker.acquire({
                        investigationId: "concurrent-holder",
                        ownerId: "holder-owner",
                        supervisorGeneration: 1,
                        runnerIncarnation: "holder-runner",
                        attemptId: "holder-attempt",
                        logicalEffectId: "holder-effect",
                        reservation: {
                            sandboxProcesses: 1,
                            cpuSlots: { general: 1 },
                        },
                    });
                }
                return runnerBroker.renew(input);
            },
            release: (input) => runnerBroker.release(input),
            reconcileUsage: (input) =>
                runnerBroker.reconcileUsage(input),
            listActiveLeases: (input) =>
                runnerBroker.listActiveLeases(input),
            close: () => runnerBroker.close(),
        };

        const children = new Map();
        let terminated = false;
        const processAdapter = {
            spawn(_executable, _argv, options) {
                const child = new EventEmitter();
                child.pid = 18_001 + children.size;
                child.stdout = new PassThrough();
                child.stderr = new PassThrough();
                const timer = setTimeout(() => {
                    if (!children.has(child.pid)) return;
                    const score = Number(fs.readFileSync(
                        path.join(
                            options.env.CANDIDATE_SNAPSHOT_PATH,
                            "score.txt",
                        ),
                        "utf8",
                    ).trim());
                    child.stdout.end(JSON.stringify({
                        pass: score >= 100,
                        metrics: { score },
                    }));
                    child.stderr.end();
                    children.delete(child.pid);
                    child.emit("close", 0, null);
                }, 250);
                children.set(child.pid, { child, timer });
                return child;
            },
            terminateTree(pid) {
                const owned = children.get(pid);
                if (owned === undefined) return false;
                terminated = true;
                clearTimeout(owned.timer);
                owned.child.stdout.end();
                owned.child.stderr.end();
                children.delete(pid);
                setImmediate(() =>
                    owned.child.emit("close", null, "SIGKILL"));
                return true;
            },
            activeOwnedPids() {
                return [...children.keys()];
            },
            async close() {
                for (const pid of [...children.keys()]) {
                    this.terminateTree(pid);
                }
                return true;
            },
        };

        try {
            const { result } = await runImpossibilityRunnerFixture(
                setup,
                {
                    clock,
                    processAdapter,
                    resourceBrokerFactory: () => broker,
                },
            );
            expect(result).toMatchObject({
                kind: "PAUSE",
                drainedOperationalError: {
                    code: RUNTIME_ERROR_CODES.RESOURCE_UNAVAILABLE,
                },
            });
            expect(renewCalls).toBeGreaterThan(0);
            expect(terminated).toBe(true);
            expect(replacement).toMatchObject({
                status: "acquired",
                lease: { status: "active" },
            });
            expect(holderBroker.listActiveLeases({
                investigationId: "concurrent-holder",
            })).toHaveLength(1);

            const replay = replayImpossibilityRunnerFixture(setup);
            try {
                expect(replay.adapter.latestOperationalNonResult())
                    .toMatchObject({
                        payload: {
                            code:
                                RUNTIME_ERROR_CODES.RESOURCE_UNAVAILABLE,
                            details: {
                                outcome: {
                                    status: "lease_authority_lost",
                                    outputQuarantined: true,
                                    renewal: {
                                        renewed: false,
                                        status: "reclaimed",
                                    },
                                },
                            },
                        },
                    });
                const effectAttempt = replay.adapter.listAttempts()
                    .find((attempt) => {
                        try {
                            return JSON.parse(attempt.command).scope
                                === "external-effect";
                        } catch {
                            return false;
                        }
                    });
                expect(effectAttempt).toMatchObject({
                    state: "dispatched",
                });
            } finally {
                replay.repository.close();
            }
        } finally {
            if (replacement?.status === "acquired") {
                holderBroker.release({ lease: replacement.lease });
            }
            try {
                runnerBroker.close();
            } catch {
                // Runner cleanup normally closes this handle.
            }
            holderBroker.close();
            await cleanupImpossibilityRunnerFixture(setup);
        }
    }, 30_000);
});
