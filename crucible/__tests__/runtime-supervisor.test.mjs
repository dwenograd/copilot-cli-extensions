import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    RUNTIME_ERROR_CODES,
    acquireSupervisorLock,
    ensureSupervisor,
    normalizeRunnerConfig,
    normalizeSupervisorConfig,
    releaseSupervisorLock,
    runSupervisor,
    startSupervisor,
    supervisorPaths,
    terminateExactSupervisor,
} from "../runtime/index.mjs";
import { scavengeStaleGenerationOwnedPaths } from "../runtime/supervisor.mjs";
import { RUNTIME_TEMP_OWNER_MARKER } from "../runtime/utils.mjs";
import { ERROR_CODES as PERSISTENCE_ERROR_CODES, openRepository } from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-supervisor-${label}-`));
    roots.push(root);
    return root;
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function rawConfig(root, overrides = {}) {
    return {
        runner: {
            investigationId: "supervised-investigation",
            stateDir: path.join(root, "state"),
            artifactRoot: path.join(root, "artifacts"),
            allowlistPath: path.join(root, "allowlist.json"),
            copilotSdkPath: path.join(root, "sdk"),
            copilotCliPath: path.join(root, "copilot.exe"),
            runnerEpochId: "runner-epoch",
            deadline: Date.now() + 60_000,
        },
        maxRestarts: 2,
        baseBackoffMs: 10,
        maxBackoffMs: 100,
        heartbeatIntervalMs: 100,
        staleLockMs: 2_000,
        circuitWindowMs: 10_000,
        ...overrides,
    };
}

function mutableClock(start = Date.parse("2026-07-09T12:00:00.000Z")) {
    let now = start;
    return {
        now: () => now,
        isoNow: () => new Date(now).toISOString(),
        advance(milliseconds) {
            now += milliseconds;
        },
    };
}

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return { promise, resolve, reject };
}

function controlledTimers() {
    const intervals = new Map();
    let nextId = 1;
    return {
        setInterval(callback) {
            const handle = {
                id: nextId++,
                unref() {},
            };
            intervals.set(handle, callback);
            return handle;
        },
        clearInterval(handle) {
            intervals.delete(handle);
        },
        setTimeout(callback) {
            setImmediate(callback);
            return { unref() {} };
        },
        runIntervals() {
            for (const callback of [...intervals.values()]) {
                callback();
            }
        },
    };
}

function childResultSpawner(sequence) {
    let index = 0;
    return async (config) => {
        const spec = sequence[index++];
        const child = new EventEmitter();
        child.pid = 5000 + index;
        setTimeout(() => {
            if (spec.envelope !== undefined) {
                fs.writeFileSync(
                    config.paths.childResultPath,
                    `${JSON.stringify(spec.envelope)}\n`,
                );
            } else {
                fs.rmSync(config.paths.childResultPath, { force: true });
            }
            child.emit("close", spec.code ?? 0, spec.signal ?? null);
        }, 0);
        return { child, resultPath: config.paths.childResultPath };
    };
}

function writeRuntimeOwnerMarker(root, {
    investigationId = "supervised-investigation",
    supervisorGeneration,
    supervisorNonce,
    runnerEpochId = "runner-epoch",
    pid,
} = {}) {
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, RUNTIME_TEMP_OWNER_MARKER), JSON.stringify({
        version: 1,
        kind: "crucible-runtime-temp-root",
        investigationId,
        supervisorGeneration,
        supervisorNonce,
        runnerEpochId,
        pid,
        root,
        createdAt: new Date(0).toISOString(),
        ownedPaths: [
            root,
            path.join(root, "sdk-home"),
            path.join(root, "sdk-work"),
            path.join(root, "materialized"),
        ],
    }));
}

function writeGenerationRecord(directory, generation, nonce, pid) {
    fs.writeFileSync(path.join(directory, `owner-${generation}.json`), JSON.stringify({
        version: 1,
        investigationId: "supervised-investigation",
        supervisorGeneration: generation,
        pid,
        nonce,
        allocatedAt: new Date(0).toISOString(),
    }));
}

describe("Crucible supervisor", () => {
    it("requires staleLockMs to exceed heartbeat plus jitter and operation margin", () => {
        const root = makeRoot("heartbeat-margin");
        expect(() => normalizeSupervisorConfig(rawConfig(root, {
            heartbeatIntervalMs: 1_000,
            staleLockMs: 2_000,
        }))).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.INVALID_CONFIG,
            details: expect.objectContaining({
                heartbeatIntervalMs: 1_000,
                staleLockMs: 2_000,
                jitterOperationMarginMs: 1_000,
            }),
        }));
        expect(normalizeSupervisorConfig(rawConfig(root, {
            heartbeatIntervalMs: 1_000,
            staleLockMs: 2_001,
        })).staleLockMs).toBe(2_001);
    });

    it("allocates a durable monotonic generation for each acquired supervisor", () => {
        const root = makeRoot("generation");
        const config = normalizeSupervisorConfig(rawConfig(root));
        const first = acquireSupervisorLock(config, {
            pid: 91,
            idFactory: () => "generation-one",
            isPidAlive: () => false,
        });
        expect(first.supervisorGeneration).toBe(1);
        expect(JSON.parse(fs.readFileSync(config.paths.generationPath, "utf8")))
            .toMatchObject({
                supervisorGeneration: 1,
                pid: 91,
                nonce: "generation-one",
            });
        expect(releaseSupervisorLock(first)).toBe(true);

        const second = acquireSupervisorLock(config, {
            pid: 92,
            idFactory: () => "generation-two",
            isPidAlive: () => false,
        });
        expect(second.supervisorGeneration).toBe(2);
        expect(JSON.parse(fs.readFileSync(config.paths.generationPath, "utf8")))
            .toMatchObject({
                supervisorGeneration: 2,
                pid: 92,
                nonce: "generation-two",
            });
        expect(releaseSupervisorLock(second)).toBe(true);
    });

    it("enforces one live supervisor lock per investigation", () => {
        const root = makeRoot("singleton");
        const config = normalizeSupervisorConfig(rawConfig(root));
        const clock = mutableClock();
        const first = acquireSupervisorLock(config, {
            pid: 101,
            idFactory: () => "nonce-one",
            clock,
            isPidAlive: (pid) => pid === 101,
        });
        expect(() => acquireSupervisorLock(config, {
            pid: 202,
            idFactory: () => "nonce-two",
            clock,
            isPidAlive: (pid) => pid === 101,
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.LOCK_HELD,
        }));
        expect(releaseSupervisorLock(first)).toBe(true);
    });

    it("reclaims a stale lock with no fresh heartbeat even when its PID is live", () => {
        const root = makeRoot("stale");
        const config = normalizeSupervisorConfig(rawConfig(root));
        const firstClock = mutableClock();
        acquireSupervisorLock(config, {
            pid: 111,
            idFactory: () => "old-nonce",
            clock: firstClock,
            isPidAlive: () => true,
        });
        const oldTime = new Date(firstClock.now() - 1_000);
        fs.utimesSync(config.paths.lockPath, oldTime, oldTime);

        const secondClock = mutableClock(firstClock.now() + 1000);
        const recovered = acquireSupervisorLock(config, {
            pid: 222,
            idFactory: () => "new-nonce",
            clock: secondClock,
            isPidAlive: () => true,
        });
        expect(recovered).toMatchObject({
            pid: 222,
            nonce: "new-nonce",
            supervisorGeneration: 2,
        });
        expect(releaseSupervisorLock(recovered)).toBe(true);
    });

    it("restarts recoverable crashes with bounded exponential backoff and persists status", async () => {
        const root = makeRoot("restart");
        const config = normalizeSupervisorConfig(rawConfig(root));
        const clock = mutableClock();
        const sleeps = [];
        const result = await runSupervisor(config, {
            pid: 303,
            idFactory: () => "supervisor-nonce",
            clock,
            isPidAlive: () => false,
            sleep: async (milliseconds) => {
                sleeps.push(milliseconds);
                clock.advance(milliseconds);
            },
            spawnRunner: childResultSpawner([
                {
                    code: 75,
                    envelope: {
                        ok: false,
                        error: {
                            code: "TRANSIENT",
                            message: "transient crash",
                            recoverable: true,
                        },
                    },
                },
                {
                    code: 0,
                    envelope: {
                        ok: true,
                        result: {
                            kind: "NON_RESULT",
                            code: "BUDGET_EXHAUSTED_INCONCLUSIVE",
                        },
                    },
                },
            ]),
        });
        expect(result.kind).toBe("NON_RESULT");
        expect(sleeps).toEqual([10]);
        const status = JSON.parse(fs.readFileSync(config.paths.statusPath, "utf8"));
        expect(status).toMatchObject({
            state: "non_result",
            restartCount: 1,
            pid: 303,
            nonce: "supervisor-nonce",
            supervisorGeneration: 1,
        });
        expect(fs.existsSync(config.paths.lockPath)).toBe(false);
    });

    it("persists a unique incarnation before each launch and rotates it before restart", async () => {
        const root = makeRoot("runner-incarnation");
        const config = normalizeSupervisorConfig(rawConfig(root));
        const incarnations = [
            "supervisor-launch-incarnation-one",
            "supervisor-launch-incarnation-two",
        ];
        const launches = [];
        let firstLease = null;
        let staleRejection = null;
        let activeBeforeStaleRejection = null;
        let activeAfterStaleRejection = null;
        const result = await runSupervisor(config, {
            pid: 306,
            idFactory: () => "incarnation-supervisor",
            runnerIncarnationFactory: () => incarnations.shift(),
            isPidAlive: () => false,
            sleep: async () => {},
            spawnRunner: async (launchConfig, context) => {
                const repository = openRepository({
                    file: path.join(config.runner.stateDir, "events.sqlite"),
                });
                const child = new EventEmitter();
                child.pid = 5300 + context.launchNumber;
                try {
                    const authority = repository.getSupervisorAuthority(
                        config.runner.investigationId,
                    );
                    const normalizedChild = normalizeRunnerConfig(
                        context.runnerConfig,
                    );
                    const cliForwardedConfig = normalizeRunnerConfig({
                        investigationId: normalizedChild.investigationId,
                        stateDir: normalizedChild.stateDir,
                        artifactRoot: normalizedChild.artifactRoot,
                        allowlistPath: normalizedChild.allowlistPath,
                        copilotSdkPath: normalizedChild.sdkPath,
                        copilotCliPath: normalizedChild.cliPath,
                        runnerEpochId: normalizedChild.runnerEpochId,
                        deadline: normalizedChild.deadlineMs,
                        resultPath: normalizedChild.resultPath,
                        options: normalizedChild.options,
                    });
                    launches.push({
                        context,
                        authority,
                        config: normalizedChild,
                        cliForwardedConfig,
                        childConfigPath: launchConfig.paths.childConfigPath,
                        childResultPath: launchConfig.paths.childResultPath,
                    });
                    if (context.launchNumber === 1) {
                        firstLease = repository.acquireLease({
                            investigationId: config.runner.investigationId,
                            leaseId: "supervisor-launch-lease-one",
                            owner: "supervisor-launch-runner-one",
                            supervisorGeneration: context.supervisorGeneration,
                            runnerIncarnation: context.runnerIncarnation,
                        });
                        setImmediate(() => child.emit("close", 75, null));
                    } else {
                        activeBeforeStaleRejection = repository.getActiveLease(
                            config.runner.investigationId,
                        );
                        try {
                            repository.acquireLease({
                                investigationId: config.runner.investigationId,
                                leaseId: "supervisor-launch-stale-retry",
                                owner: "supervisor-launch-runner-stale",
                                supervisorGeneration:
                                    launches[0].context.supervisorGeneration,
                                runnerIncarnation:
                                    launches[0].context.runnerIncarnation,
                            });
                        } catch (error) {
                            staleRejection = error;
                        }
                        activeAfterStaleRejection = repository.getActiveLease(
                            config.runner.investigationId,
                        );
                        repository.acquireLease({
                            investigationId: config.runner.investigationId,
                            leaseId: "supervisor-launch-lease-two",
                            owner: "supervisor-launch-runner-two",
                            supervisorGeneration: context.supervisorGeneration,
                            runnerIncarnation: context.runnerIncarnation,
                        });
                        setImmediate(() => {
                            fs.writeFileSync(
                                launchConfig.paths.childResultPath,
                                `${JSON.stringify({
                                    ok: true,
                                    result: {
                                        kind: "NON_RESULT",
                                        code: "INCARNATION_ROTATED",
                                    },
                                })}\n`,
                            );
                            child.emit("close", 0, null);
                        });
                    }
                } finally {
                    repository.close();
                }
                return {
                    child,
                    resultPath: launchConfig.paths.childResultPath,
                };
            },
        });

        expect(result.kind).toBe("NON_RESULT");
        expect(launches).toHaveLength(2);
        expect(launches.map((launch) => launch.context.runnerIncarnation))
            .toEqual([
                "supervisor-launch-incarnation-one",
                "supervisor-launch-incarnation-two",
            ]);
        expect(launches.every((launch) =>
            launch.authority.currentRunnerIncarnation
                === launch.context.runnerIncarnation)).toBe(true);
        expect(launches.every((launch) =>
            launch.config.runnerIncarnation
                === launch.context.runnerIncarnation)).toBe(true);
        expect(launches.every((launch) =>
            launch.cliForwardedConfig.runnerIncarnation
                === launch.context.runnerIncarnation)).toBe(true);
        expect(launches[0].childConfigPath).not.toBe(launches[1].childConfigPath);
        expect(launches[0].childResultPath).not.toBe(launches[1].childResultPath);
        expect(staleRejection).toMatchObject({
            code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
        });
        expect(activeBeforeStaleRejection).toMatchObject({
            ...firstLease,
            releasedAt: null,
        });
        expect(activeAfterStaleRejection).toEqual(activeBeforeStaleRejection);

        const repository = openRepository({
            file: path.join(config.runner.stateDir, "events.sqlite"),
        });
        try {
            expect(repository.getSupervisorAuthority(config.runner.investigationId))
                .toMatchObject({
                    supervisorGeneration: 1,
                    supervisorNonce: "incarnation-supervisor",
                    currentRunnerIncarnation: "supervisor-launch-incarnation-two",
                });
            expect(repository.getActiveLease(config.runner.investigationId))
                .toMatchObject({
                    fencingToken: 2,
                    runnerIncarnation: "supervisor-launch-incarnation-two",
                    releasedAt: null,
                });
            expect(repository.countEvents(config.runner.investigationId)).toBe(0);
        } finally {
            repository.close();
        }
    });

    it("caps retry backoff to the remaining investigation deadline", async () => {
        const root = makeRoot("deadline-backoff");
        const clock = mutableClock();
        const raw = rawConfig(root);
        raw.runner.deadline = clock.now() + 5;
        const config = normalizeSupervisorConfig(raw);
        const sleeps = [];
        const result = await runSupervisor(config, {
            pid: 305,
            idFactory: () => "deadline-backoff-nonce",
            clock,
            isPidAlive: () => false,
            sleep: async (milliseconds) => {
                sleeps.push(milliseconds);
                clock.advance(milliseconds);
            },
            spawnRunner: childResultSpawner([
                { code: 75 },
                {
                    code: 0,
                    envelope: {
                        ok: true,
                        result: {
                            kind: "NON_RESULT",
                            code: "DEADLINE_EXCEEDED",
                        },
                    },
                },
            ]),
        });
        expect(result.kind).toBe("NON_RESULT");
        expect(sleeps).toEqual([5]);
    });

    it("keeps the crash-backoff timer referenced until the restart occurs", async () => {
        const root = makeRoot("referenced-backoff");
        const config = normalizeSupervisorConfig(rawConfig(root));
        let unrefCalls = 0;
        const timers = {
            setTimeout(callback) {
                setImmediate(callback);
                return { unref() { unrefCalls += 1; } };
            },
            setInterval,
            clearInterval,
        };
        const result = await runSupervisor(config, {
            pid: 304,
            idFactory: () => "referenced-backoff-nonce",
            isPidAlive: () => false,
            timers,
            spawnRunner: childResultSpawner([
                { code: 75 },
                {
                    code: 0,
                    envelope: {
                        ok: true,
                        result: { kind: "NON_RESULT", code: "DONE" },
                    },
                },
            ]),
        });
        expect(result.kind).toBe("NON_RESULT");
        expect(unrefCalls).toBe(0);
    });

    it("opens the circuit breaker after the configured restart bound", async () => {
        const root = makeRoot("circuit");
        const config = normalizeSupervisorConfig(rawConfig(root, { maxRestarts: 1 }));
        const clock = mutableClock();
        const operational = [];
        const result = await runSupervisor(config, {
            pid: 404,
            idFactory: () => "circuit-nonce",
            clock,
            isPidAlive: () => false,
            sleep: async (milliseconds) => clock.advance(milliseconds),
            recordOperationalNonResult: (input) => operational.push(input),
            spawnRunner: childResultSpawner([
                { code: 75 },
                { code: 75 },
            ]),
        });
        expect(result.kind).toBe("CIRCUIT_OPEN");
        const status = JSON.parse(fs.readFileSync(config.paths.statusPath, "utf8"));
        expect(status).toMatchObject({
            state: "circuit_open",
            restartCount: 1,
        });
        expect(status.circuit.crashesInWindow).toBe(2);
        expect(operational).toHaveLength(1);
        expect(operational[0]).toMatchObject({
            code: RUNTIME_ERROR_CODES.CIRCUIT_OPEN,
            supervisorGeneration: 1,
            supervisorNonce: "circuit-nonce",
            details: expect.objectContaining({
                supervisorGeneration: 1,
                supervisorNonce: "circuit-nonce",
            }),
        });
    });

    it("persists a failed operational non-result instead of leaving progress ambiguous", async () => {
        const root = makeRoot("failed-outcome");
        const config = normalizeSupervisorConfig(rawConfig(root));
        const operational = [];
        const result = await runSupervisor(config, {
            pid: 405,
            idFactory: () => "failed-nonce",
            isPidAlive: () => false,
            recordOperationalNonResult: (input) => operational.push(input),
            spawnRunner: childResultSpawner([{
                code: 1,
                envelope: {
                    ok: false,
                    error: {
                        code: "FATAL_RUNNER",
                        message: "runner cannot continue",
                        recoverable: false,
                    },
                },
            }]),
        });
        expect(result.kind).toBe("FAILED");
        expect(operational).toEqual([
            expect.objectContaining({
                code: "FATAL_RUNNER",
                reason: "runner cannot continue",
            }),
        ]);
    });

    it("starts detached with argv arrays and shell disabled", () => {
        const root = makeRoot("detached");
        const calls = [];
        const child = { pid: 909, unref: () => calls.push("unref") };
        const result = startSupervisor(rawConfig(root), {
            spawnProcess(executable, argv, options) {
                calls.push({ executable, argv, options });
                return child;
            },
        });
        expect(result.pid).toBe(909);
        expect(calls[0].argv).toEqual([
            expect.stringMatching(/supervisor-cli\.mjs$/),
            "--config",
            expect.stringMatching(/\.config\.json$/),
        ]);
        expect(calls[0].options).toMatchObject({
            detached: true,
            shell: false,
            stdio: "ignore",
        });
        expect(calls[1]).toBe("unref");
    });

    it("detects a missing old supervisor and starts a replacement", () => {
        const root = makeRoot("ensure");
        const config = normalizeSupervisorConfig(rawConfig(root));
        fs.mkdirSync(config.paths.directory, { recursive: true });
        fs.writeFileSync(config.paths.statusPath, JSON.stringify({
            version: 1,
            investigationId: config.runner.investigationId,
            pid: 12345,
            nonce: "dead",
            startedAt: "2026-07-09T10:00:00.000Z",
            heartbeatAt: "2026-07-09T10:00:00.000Z",
            state: "running",
        }));
        const child = { pid: 999, unref() {} };
        const result = ensureSupervisor(config, {
            clock: mutableClock(Date.parse("2026-07-09T12:00:00.000Z")),
            isPidAlive: () => false,
            spawnProcess: () => child,
        });
        expect(result.action).toBe("started");
        expect(result.pid).toBe(999);
    });

    it("reclaims a malformed legacy lock only after stale mtime and no matching heartbeat", () => {
            const root = makeRoot("malformed");
            const config = normalizeSupervisorConfig(rawConfig(root));
            fs.mkdirSync(config.paths.directory, { recursive: true });
            fs.writeFileSync(config.paths.lockPath, "{\"pid\":123");
            expect(() => acquireSupervisorLock(config, {
                pid: 321,
                idFactory: () => "new-owner",
                isPidAlive: () => false,
            })).toThrow(expect.objectContaining({ code: RUNTIME_ERROR_CODES.LOCK_HELD }));

            fs.writeFileSync(config.paths.lockPath, JSON.stringify({
                pid: 123,
                nonce: "legacy-owner",
                startedAt: new Date(Date.now() - 60_000).toISOString(),
                unexpectedLegacyField: true,
            }));
            fs.writeFileSync(config.paths.statusPath, JSON.stringify({
                pid: 123,
                nonce: "legacy-owner",
                heartbeatAt: new Date().toISOString(),
                state: "running",
            }));
            const stale = new Date(Date.now() - config.staleLockMs - 5_000);
            fs.utimesSync(config.paths.lockPath, stale, stale);
            expect(() => acquireSupervisorLock(config, {
                pid: 321,
                idFactory: () => "new-owner",
                isPidAlive: (pid) => pid === 123,
            })).toThrow(expect.objectContaining({ code: RUNTIME_ERROR_CODES.LOCK_HELD }));
            fs.writeFileSync(config.paths.statusPath, JSON.stringify({
                pid: 123,
                nonce: "legacy-owner",
                heartbeatAt: new Date(Date.now() - config.staleLockMs - 5_000).toISOString(),
                state: "running",
            }));
            const lock = acquireSupervisorLock(config, {
                pid: 321,
                idFactory: () => "new-owner",
                isPidAlive: () => false,
            });
            expect(lock).toMatchObject({
                pid: 321,
                nonce: "new-owner",
                supervisorGeneration: 1,
            });
            expect(releaseSupervisorLock(lock)).toBe(true);
    });

    it("does not trust a reused live PID when heartbeat nonce mismatches", () => {
            const root = makeRoot("pid-reuse");
            const config = normalizeSupervisorConfig(rawConfig(root));
            fs.mkdirSync(config.paths.directory, { recursive: true });
            fs.writeFileSync(config.paths.lockPath, JSON.stringify({
                pid: 777,
                nonce: "old-owner",
                startedAt: new Date(Date.now() - 60_000).toISOString(),
                supervisorGeneration: 7,
            }));
            fs.writeFileSync(config.paths.generationPath, JSON.stringify({
                version: 1,
                investigationId: config.runner.investigationId,
                supervisorGeneration: 7,
                pid: 777,
                nonce: "old-owner",
                allocatedAt: new Date(Date.now() - 60_000).toISOString(),
            }));
            fs.writeFileSync(config.paths.statusPath, JSON.stringify({
                pid: 777,
                nonce: "different-owner",
                supervisorGeneration: 7,
                heartbeatAt: new Date().toISOString(),
                state: "running",
            }));
            const stale = new Date(Date.now() - config.staleLockMs - 5_000);
            fs.utimesSync(config.paths.lockPath, stale, stale);
            const lock = acquireSupervisorLock(config, {
                pid: 888,
                idFactory: () => "replacement-owner",
                isPidAlive: (pid) => pid === 777,
            });
            expect(lock).toMatchObject({
                pid: 888,
                nonce: "replacement-owner",
                supervisorGeneration: 8,
            });
            releaseSupervisorLock(lock);
    });

    it("fences a stalled live supervisor after takeover and only the new generation restarts", async () => {
        const root = makeRoot("split-brain");
        const config = normalizeSupervisorConfig(rawConfig(root));
        const clock = mutableClock();
        const oldTimers = controlledTimers();
        const oldStarted = deferred();
        const oldChild = new EventEmitter();
        oldChild.pid = 6101;
        const oldTerminated = [];
        const oldLaunches = [];

        const oldPromise = runSupervisor(config, {
            pid: 601,
            idFactory: () => "stalled-owner",
            clock,
            timers: oldTimers,
            signalSource: new EventEmitter(),
            isPidAlive: () => true,
            spawnRunner: async (ownedConfig, context) => {
               oldLaunches.push({
                   generation: context.supervisorGeneration,
                   nonce: context.supervisorNonce,
                   runnerIncarnation: context.runnerIncarnation,
                   runnerConfig: context.runnerConfig,
               });
               setImmediate(() => oldStarted.resolve({ ownedConfig, context }));
               return {
                   child: oldChild,
                   resultPath: ownedConfig.paths.childResultPath,
               };
            },
            processTreeAdapter: {
               async terminateTree(pid) {
                   oldTerminated.push(pid);
                   setImmediate(() => oldChild.emit("close", null, "SIGTERM"));
                   return true;
               },
            },
        });
        const old = await oldStarted.promise;
        expect(old.context).toMatchObject({
            supervisorGeneration: 1,
            supervisorNonce: "stalled-owner",
            runnerConfig: {
               supervisorGeneration: 1,
               supervisorNonce: "stalled-owner",
            },
        });
        expect(normalizeRunnerConfig(old.context.runnerConfig)).toMatchObject({
            supervisorGeneration: 1,
            supervisorNonce: "stalled-owner",
        });

        clock.advance(config.staleLockMs + 100);
        const staleLockTime = new Date(clock.now() - config.staleLockMs - 1);
        fs.utimesSync(config.paths.lockPath, staleLockTime, staleLockTime);

        const newTimers = controlledTimers();
        const newStarted = deferred();
        const newLaunches = [];
        let activeNewChild = null;
        const newPromise = runSupervisor(config, {
            pid: 602,
            idFactory: () => "takeover-owner",
            clock,
            timers: newTimers,
            signalSource: new EventEmitter(),
            isPidAlive: () => true,
            sleep: async (milliseconds) => clock.advance(milliseconds),
            spawnRunner: async (ownedConfig, context) => {
               const child = new EventEmitter();
               child.pid = 6200 + context.launchNumber;
               activeNewChild = child;
               newLaunches.push({
                   generation: context.supervisorGeneration,
                   nonce: context.supervisorNonce,
                   runnerIncarnation: context.runnerIncarnation,
                   runnerConfig: context.runnerConfig,
                   resultPath: ownedConfig.paths.childResultPath,
                   child,
               });
               if (context.launchNumber === 1) {
                   setImmediate(() => newStarted.resolve({ ownedConfig, context, child }));
               } else {
                   setImmediate(() => {
                       fs.writeFileSync(
                           ownedConfig.paths.childResultPath,
                           `${JSON.stringify({
                               ok: true,
                               result: {
                                   kind: "NON_RESULT",
                                   code: "TAKEOVER_COMPLETE",
                               },
                           })}\n`,
                       );
                       child.emit("close", 0, null);
                   });
               }
               return {
                   child,
                   resultPath: ownedConfig.paths.childResultPath,
               };
            },
        });
        const takeover = await newStarted.promise;
        expect(takeover.context).toMatchObject({
            supervisorGeneration: 2,
            supervisorNonce: "takeover-owner",
            runnerConfig: {
               supervisorGeneration: 2,
               supervisorNonce: "takeover-owner",
            },
        });
        expect(normalizeRunnerConfig(takeover.context.runnerConfig)).toMatchObject({
            supervisorGeneration: 2,
            supervisorNonce: "takeover-owner",
            runnerIncarnation: takeover.context.runnerIncarnation,
        });

        const delayedRepository = openRepository({
            file: path.join(config.runner.stateDir, "events.sqlite"),
        });
        const currentRepository = openRepository({
            file: path.join(config.runner.stateDir, "events.sqlite"),
        });
        try {
            const eventsBeforeDelayedLaunch = currentRepository.countEvents(
                config.runner.investigationId,
            );
            expect(currentRepository.getActiveLease(config.runner.investigationId))
                .toBeNull();
            expect(() => delayedRepository.acquireLease({
                investigationId: config.runner.investigationId,
                leaseId: "delayed-generation-one-lease",
                owner: "delayed-generation-one-runner",
                supervisorGeneration: old.context.supervisorGeneration,
                runnerIncarnation: old.context.runnerIncarnation,
            })).toThrow(expect.objectContaining({
                code: PERSISTENCE_ERROR_CODES.FENCE_REJECTED,
            }));
            expect(currentRepository.getActiveLease(config.runner.investigationId))
                .toBeNull();
            expect(currentRepository.countEvents(config.runner.investigationId))
                .toBe(eventsBeforeDelayedLaunch);
            expect(currentRepository.acquireLease({
                investigationId: config.runner.investigationId,
                leaseId: "takeover-generation-two-lease",
                owner: "takeover-generation-two-runner",
                supervisorGeneration: takeover.context.supervisorGeneration,
                runnerIncarnation: takeover.context.runnerIncarnation,
            })).toMatchObject({
                fencingToken: 1,
                supervisorGeneration: 2,
                runnerIncarnation: takeover.context.runnerIncarnation,
            });
        } finally {
            delayedRepository.close();
            currentRepository.close();
        }

        oldTimers.runIntervals();
        const oldResult = await oldPromise;
        expect(oldResult).toMatchObject({
            kind: "STOPPED",
            ownershipLost: true,
            shutdown: {
               kind: "ownership_lost",
               supervisorGeneration: 1,
               nonce: "stalled-owner",
            },
        });
        expect(oldTerminated).toEqual([6101]);
        expect(oldLaunches).toHaveLength(1);

        const statusAfterTakeover = JSON.parse(
            fs.readFileSync(config.paths.statusPath, "utf8"),
        );
        expect(statusAfterTakeover).toMatchObject({
            state: "running",
            pid: 602,
            nonce: "takeover-owner",
            supervisorGeneration: 2,
        });

        activeNewChild.emit("close", 75, null);
        const newResult = await newPromise;
        expect(newResult.kind).toBe("NON_RESULT");
        expect(newLaunches).toHaveLength(2);
        expect(newLaunches.every((launch) => launch.generation === 2)).toBe(true);
        expect(newLaunches.every((launch) => launch.nonce === "takeover-owner")).toBe(true);
        expect(newLaunches[0].runnerIncarnation)
            .not.toBe(newLaunches[1].runnerIncarnation);
        expect(JSON.parse(fs.readFileSync(config.paths.generationPath, "utf8")))
            .toMatchObject({
               supervisorGeneration: 2,
               pid: 602,
               nonce: "takeover-owner",
            });
        expect(JSON.parse(fs.readFileSync(config.paths.statusPath, "utf8")))
            .toMatchObject({
               state: "non_result",
               restartCount: 1,
               supervisorGeneration: 2,
               nonce: "takeover-owner",
            });
    });

    it("terminates and awaits the exact child tree before releasing ownership on signal", async () => {
            const root = makeRoot("child-cleanup");
            const config = normalizeSupervisorConfig(rawConfig(root));
            const signals = new EventEmitter();
            const child = new EventEmitter();
            child.pid = 6543;
            const terminated = [];
            const resultPromise = runSupervisor(config, {
                pid: 505,
                idFactory: () => "cleanup-nonce",
                isPidAlive: () => false,
                signalSource: signals,
                spawnRunner: async () => {
                    setImmediate(() => signals.emit("SIGTERM"));
                    return { child, resultPath: config.paths.childResultPath };
                },
                processTreeAdapter: {
                    async terminateTree(pid) {
                        terminated.push(pid);
                        setImmediate(() => child.emit("close", null, "SIGTERM"));
                        return true;
                    },
                },
            });
            const result = await resultPromise;
            expect(result.kind).toBe("STOPPED");
            expect(terminated).toEqual([6543]);
            expect(fs.existsSync(config.paths.lockPath)).toBe(false);
    });

    it("releases supervisor ownership within the final shutdown bound", async () => {
        const root = makeRoot("bounded-child-cleanup");
        const config = normalizeSupervisorConfig(rawConfig(root));
        const signals = new EventEmitter();
        const child = new EventEmitter();
        child.pid = 7654;
        const phases = [];
        const started = Date.now();
        const resultPromise = runSupervisor(config, {
            pid: 506,
            idFactory: () => "bounded-cleanup-nonce",
            isPidAlive: () => false,
            signalSource: signals,
            shutdownPolicy: {
                drainMs: 10,
                escalationMs: 10,
                finalMs: 25,
            },
            spawnRunner: async () => {
                setImmediate(() => signals.emit("SIGTERM"));
                return { child, resultPath: config.paths.childResultPath };
            },
            processTreeAdapter: {
                terminateTree(_pid, options) {
                    phases.push(options.phase);
                    return new Promise(() => {});
                },
                closeJobObject() {
                    phases.push("job_object_close");
                    return new Promise(() => {});
                },
            },
        });
        const result = await resultPromise;
        expect(Date.now() - started).toBeLessThan(500);
        expect(result).toMatchObject({
            kind: "STOPPED",
            status: {
                state: "stopped",
            },
        });
        expect(phases).toEqual(["drain", "escalation", "job_object_close"]);
        expect(fs.existsSync(config.paths.lockPath)).toBe(false);
    });

    it("scavenges only dead older-generation runtime debris", () => {
        const root = makeRoot("startup-scavenge");
        const tempRoot = path.join(root, "state", "runtime-temp");
        const supervisorDirectory = path.join(root, "state", "supervisor");
        fs.mkdirSync(tempRoot, { recursive: true });
        fs.mkdirSync(supervisorDirectory, { recursive: true });
        writeGenerationRecord(supervisorDirectory, 1, "stale-owner", 901);
        writeGenerationRecord(supervisorDirectory, 2, "referenced-owner", 902);
        writeGenerationRecord(supervisorDirectory, 3, "alive-owner", 903);
        writeGenerationRecord(supervisorDirectory, 4, "current-owner", 904);

        const stale = path.join(tempRoot, "run-g1-stale");
        writeRuntimeOwnerMarker(stale, {
            supervisorGeneration: 1,
            supervisorNonce: "stale-owner",
            pid: 101,
        });
        fs.mkdirSync(path.join(stale, "sdk-home"), { recursive: true });
        fs.mkdirSync(path.join(stale, ".crucible-stage-abrupt"), { recursive: true });
        fs.writeFileSync(path.join(stale, ".crucible-stage-abrupt", "node.exe"), "debris");

        const current = path.join(tempRoot, "run-g4-current");
        writeRuntimeOwnerMarker(current, {
            supervisorGeneration: 4,
            supervisorNonce: "current-owner",
            pid: 202,
        });

        const referenced = path.join(tempRoot, "run-g1-referenced");
        writeRuntimeOwnerMarker(referenced, {
            supervisorGeneration: 2,
            supervisorNonce: "referenced-owner",
            pid: 103,
        });
        const referencedFile = path.join(referenced, "sdk-work", "active.json");
        fs.mkdirSync(path.dirname(referencedFile), { recursive: true });
        fs.writeFileSync(referencedFile, "{}");

        const alive = path.join(tempRoot, "run-g1-alive");
        writeRuntimeOwnerMarker(alive, {
            supervisorGeneration: 3,
            supervisorNonce: "alive-owner",
            pid: 104,
        });

        const unproven = path.join(tempRoot, "run-g1-unproven");
        fs.mkdirSync(unproven);

        const staleAtomic = path.join(
            supervisorDirectory,
            `.status.json.101.${"a".repeat(24)}.tmp`,
        );
        fs.writeFileSync(staleAtomic, JSON.stringify({
            pid: 101,
            supervisorGeneration: 1,
            nonce: "stale-owner",
        }));
        const currentAtomic = path.join(
            supervisorDirectory,
            `.status.json.202.${"b".repeat(24)}.tmp`,
        );
        fs.writeFileSync(currentAtomic, JSON.stringify({
            pid: 202,
            supervisorGeneration: 4,
            nonce: "current-owner",
        }));

        const result = scavengeStaleGenerationOwnedPaths({
            tempRoot,
            supervisorDirectory,
            investigationId: "supervised-investigation",
            currentGeneration: 4,
            currentNonce: "current-owner",
            currentPid: 202,
            referencedPaths: [referencedFile],
            isPidAlive: (pid) => pid === 104,
            now: Date.now(),
            minimumAgeMs: 0,
        });

        expect(fs.existsSync(stale)).toBe(false);
        expect(fs.existsSync(staleAtomic)).toBe(false);
        expect(fs.existsSync(current)).toBe(true);
        expect(fs.existsSync(referenced)).toBe(true);
        expect(fs.existsSync(alive)).toBe(true);
        expect(fs.existsSync(unproven)).toBe(true);
        expect(fs.existsSync(currentAtomic)).toBe(true);
        expect(result.removed.map((item) => item.kind).sort()).toEqual([
            "atomic_temp",
            "runtime_temp_root",
        ]);
    });

    it("does not write through a junction outside the assigned state root", () => {
        const root = makeRoot("junction");
        const outside = path.join(root, "outside");
        fs.mkdirSync(outside);
        fs.symlinkSync(outside, path.join(root, "state"), "junction");
        const child = { pid: 1, unref() {} };
        expect(() => startSupervisor(rawConfig(root), {
            spawnProcess: () => child,
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.PATH_ESCAPE,
        }));
        expect(fs.existsSync(path.join(outside, "supervisor"))).toBe(false);
    });

    it("requests stop only for a fresh matching heartbeat and never kills by PID", () => {
        const root = makeRoot("terminate");
        const paths = supervisorPaths(path.join(root, "state"), "supervised-investigation");
        fs.mkdirSync(paths.directory, { recursive: true });
        fs.writeFileSync(paths.lockPath, JSON.stringify({
            pid: 777,
            nonce: "expected",
            startedAt: "2026-07-09T12:00:00.000Z",
            supervisorGeneration: 4,
        }));
        fs.writeFileSync(paths.statusPath, JSON.stringify({
            pid: 777,
            nonce: "expected",
            supervisorGeneration: 4,
            heartbeatAt: "2026-07-09T12:00:01.000Z",
            state: "running",
        }));
        const calls = [];
        const result = terminateExactSupervisor({
            lockPath: paths.lockPath,
            statusPath: paths.statusPath,
            stopRequestPath: paths.stopRequestPath,
            expectedNonce: "expected",
            expectedGeneration: 4,
            clock: mutableClock(Date.parse("2026-07-09T12:00:02.000Z")),
            processApi: {
                kill(pid, signal) {
                    calls.push({ pid, signal });
                },
            },
        });
        expect(result.pid).toBe(777);
        expect(result.action).toBe("stop_requested");
        expect(result.supervisorGeneration).toBe(4);
        expect(calls).toEqual([{ pid: 777, signal: 0 }]);
        expect(JSON.parse(fs.readFileSync(result.stopRequestPath, "utf8")))
            .toMatchObject({
                pid: 777,
                nonce: "expected",
                supervisorGeneration: 4,
                signal: "SIGTERM",
            });
        expect(() => terminateExactSupervisor({
            lockPath: paths.lockPath,
            statusPath: paths.statusPath,
            stopRequestPath: paths.stopRequestPath,
            expectedNonce: "wrong",
            processApi: { kill() {} },
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.LOCK_HELD,
        }));
    });
});
