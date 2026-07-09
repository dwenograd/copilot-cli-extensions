import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    RUNTIME_ERROR_CODES,
    acquireSupervisorLock,
    ensureSupervisor,
    normalizeSupervisorConfig,
    releaseSupervisorLock,
    runSupervisor,
    startSupervisor,
    supervisorPaths,
    terminateExactSupervisor,
} from "../runtime/index.mjs";

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
        heartbeatIntervalMs: 1000,
        staleLockMs: 100,
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

describe("Oracle v3 supervisor", () => {
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

    it("recovers a stale lock only when its exact PID is dead and old enough", () => {
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
            isPidAlive: () => false,
        });
        expect(recovered).toMatchObject({ pid: 222, nonce: "new-nonce" });
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
        });
        expect(fs.existsSync(config.paths.lockPath)).toBe(false);
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
            expect(lock).toMatchObject({ pid: 321, nonce: "new-owner" });
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
            }));
            fs.writeFileSync(config.paths.statusPath, JSON.stringify({
                pid: 777,
                nonce: "different-owner",
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
            expect(lock).toMatchObject({ pid: 888, nonce: "replacement-owner" });
            releaseSupervisorLock(lock);
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
        }));
        fs.writeFileSync(paths.statusPath, JSON.stringify({
            pid: 777,
            nonce: "expected",
            heartbeatAt: "2026-07-09T12:00:01.000Z",
            state: "running",
        }));
        const calls = [];
        const result = terminateExactSupervisor({
            lockPath: paths.lockPath,
            statusPath: paths.statusPath,
            stopRequestPath: paths.stopRequestPath,
            expectedNonce: "expected",
            clock: mutableClock(Date.parse("2026-07-09T12:00:02.000Z")),
            processApi: {
                kill(pid, signal) {
                    calls.push({ pid, signal });
                },
            },
        });
        expect(result.pid).toBe(777);
        expect(result.action).toBe("stop_requested");
        expect(calls).toEqual([{ pid: 777, signal: 0 }]);
        expect(JSON.parse(fs.readFileSync(paths.stopRequestPath, "utf8")))
            .toMatchObject({ pid: 777, nonce: "expected", signal: "SIGTERM" });
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
