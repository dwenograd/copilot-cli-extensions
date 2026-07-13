import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    RUNTIME_ERROR_CODES,
    InjectedCrashError,
} from "../runtime/errors.mjs";
import {
    SUBMIT_CANDIDATE_TOOL_NAME,
    createSdkWorkerPool,
} from "../runtime/worker-pool.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.sdk-retry-${label}-`));
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

function payload(candidateId = "candidate-a") {
    return {
        challenge: "challenge-1",
        candidateId,
        annotations: {
            mechanism: "Produce a deterministic retry fixture.",
        },
        files: [{ path: "answer.txt", content: "ok\n" }],
    };
}

function request(deadlineMs, overrides = {}) {
    return {
        model: "gpt-test",
        reasoningEffort: "low",
        sessionId: "session-a",
        proposalSlotId: "slot-a",
        commandId: "command-a",
        logicalEffectId: "effect-a",
        challengeNonce: "challenge-1",
        allowedCandidateIds: ["candidate-a"],
        prompt: "Call the submission tool exactly once.",
        deadlineMs,
        ...overrides,
    };
}

function fakeClock(start = 50_000) {
    let now = start;
    const sleeps = [];
    return {
        sleeps,
        now: () => now,
        async sleep(milliseconds) {
            sleeps.push(milliseconds);
            now += milliseconds;
        },
    };
}

function durableJournal({ afterStore = null } = {}) {
    const records = new Map();
    const quarantines = [];
    const evidence = [];
    let commitCalls = 0;
    return {
        durable: true,
        get commitCalls() {
            return commitCalls;
        },
        records,
        quarantines,
        evidence,
        async recover({ operationIdentity }) {
            return records.get(operationIdentity.operationHash) ?? null;
        },
        async commit(record) {
            commitCalls += 1;
            const existing = records.get(record.operationHash);
            if (existing !== undefined) {
                return { status: "existing", record: existing };
            }
            records.set(record.operationHash, record);
            if (afterStore !== null) await afterStore(record, commitCalls);
            return { status: "committed", record };
        },
        async quarantine(record) {
            quarantines.push(record);
        },
        async recordEvidence(record) {
            evidence.push(record);
        },
    };
}

function retryPolicy(overrides = {}) {
    return {
        maxAttempts: 2,
        baseDelayMs: 0,
        maxDelayMs: 0,
        maxCumulativeDelayMs: 0,
        jitterBps: 0,
        reservedCostUnitsPerAttempt: 10,
        maxCostUnits: 20,
        ...overrides,
    };
}

function poolOptions(root, client, journal, clock, overrides = {}) {
    return {
        client,
        baseDirectory: path.join(root, "sdk"),
        workingDirectory: path.join(root, "work"),
        sdkRetryPolicy: retryPolicy(),
        sdkSubmissionJournal: journal,
        clock,
        sdkRetrySleep: clock.sleep.bind(clock),
        ...overrides,
    };
}

async function submit(config, toolCallId = "call-1", candidateId = "candidate-a") {
    const tool = config.tools.find((entry) => entry.name === SUBMIT_CANDIDATE_TOOL_NAME);
    return tool.handler(payload(candidateId), {
        sessionId: config.sessionId,
        toolCallId,
        toolName: tool.name,
    });
}

describe("SDK worker retry integration", () => {
    it("retries a transient failure before submission with stable logical ids", async () => {
        const root = makeRoot("before-submit");
        const clock = fakeClock();
        const journal = durableJournal();
        const configs = [];
        const guardedStages = [];
        let createCalls = 0;
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                configs.push(config);
                createCalls += 1;
                const attempt = createCalls;
                return {
                    async sendAndWait() {
                        if (attempt === 1) {
                            throw Object.assign(new Error("connection reset"), {
                                code: "ECONNRESET",
                            });
                        }
                        await submit(config);
                    },
                    async abort() {},
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool(poolOptions(
            root,
            client,
            journal,
            clock,
            {
                runtimeGuard: async ({ stage }) => {
                    guardedStages.push(stage);
                },
            },
        ));

        const proposal = await pool.propose(request(clock.now() + 5_000));
        expect(proposal.candidateId).toBe("candidate-a");
        expect(createCalls).toBe(2);
        expect(configs.map((config) => config.sessionId))
            .toEqual(["session-a", "session-a"]);
        expect(journal.commitCalls).toBe(1);
        expect(guardedStages.filter((stage) =>
            stage === "sdk_session_create")).toHaveLength(2);
        expect(guardedStages.filter((stage) =>
            stage === "sdk_request_dispatch")).toHaveLength(2);
        expect(guardedStages).toContain("sdk_submission_recovery");
        const [record] = [...journal.records.values()];
        expect(record).toMatchObject({
            proposalSlotId: "slot-a",
            commandId: "command-a",
            logicalEffectId: "effect-a",
            attempt: 2,
        });
        await pool.close();
    });

    it("honors SDK rate-limit events before recreating the session", async () => {
        const root = makeRoot("rate-limit");
        const clock = fakeClock();
        const journal = durableJournal();
        let createCalls = 0;
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                createCalls += 1;
                const handlers = new Map();
                const attempt = createCalls;
                return {
                    on(type, handler) {
                        handlers.set(type, handler);
                        return () => handlers.delete(type);
                    },
                    async sendAndWait() {
                        if (attempt === 1) {
                            handlers.get("session.error")?.({
                                type: "session.error",
                                data: {
                                    errorType: "rate_limit",
                                    errorCode: "user_model_rate_limited",
                                    message: "wait",
                                    statusCode: 429,
                                    retryAfterSeconds: 0.3,
                                },
                            });
                            return;
                        }
                        await submit(config);
                    },
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool(poolOptions(
            root,
            client,
            journal,
            clock,
            {
                sdkRetryPolicy: retryPolicy({
                    baseDelayMs: 100,
                    maxDelayMs: 500,
                    maxCumulativeDelayMs: 1_000,
                }),
            },
        ));

        await expect(pool.propose(request(clock.now() + 5_000)))
            .resolves.toMatchObject({ candidateId: "candidate-a" });
        expect(createCalls).toBe(2);
        expect(clock.sleeps).toEqual([300]);
        await pool.close();
    });

    it("durably commits the first valid submission before acknowledging the tool", async () => {
        const root = makeRoot("commit-before-ack");
        const clock = fakeClock();
        const order = [];
        const journal = durableJournal({
            afterStore: async () => {
                order.push("durable-commit");
            },
        });
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                return {
                    async sendAndWait() {
                        order.push("tool-call");
                        const result = await submit(config);
                        order.push(`tool-result:${result.resultType}`);
                    },
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool(poolOptions(
            root,
            client,
            journal,
            clock,
            { sdkRetryPolicy: retryPolicy({ maxAttempts: 1, maxCostUnits: 10 }) },
        ));

        await pool.propose(request(clock.now() + 5_000));
        expect(order).toEqual([
            "tool-call",
            "durable-commit",
            "tool-result:success",
        ]);
        await pool.close();
    });

    it("quarantines duplicate callbacks without recommitting or discarding the first", async () => {
        const root = makeRoot("duplicate");
        const clock = fakeClock();
        const journal = durableJournal();
        const results = [];
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                return {
                    async sendAndWait() {
                        results.push(await submit(config, "call-1"));
                        results.push(await submit(config, "call-2"));
                    },
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool(poolOptions(
            root,
            client,
            journal,
            clock,
        ));

        await expect(pool.propose(request(clock.now() + 5_000)))
            .resolves.toMatchObject({ candidateId: "candidate-a" });
        expect(journal.commitCalls).toBe(1);
        expect(results.map((result) => result.resultType))
            .toEqual(["success", "rejected"]);
        expect(journal.quarantines.some((record) =>
            record.reason === "duplicate_tool_callback")).toBe(true);
        await pool.close();
    });

    it("returns the sealed submission when sendAndWait is ambiguous after the callback", async () => {
        const root = makeRoot("ambiguous");
        const clock = fakeClock();
        const journal = durableJournal();
        let createCalls = 0;
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                createCalls += 1;
                return {
                    async sendAndWait() {
                        await submit(config);
                        throw Object.assign(new Error("connection lost after tool result"), {
                            code: "ECONNRESET",
                        });
                    },
                    async abort() {},
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool(poolOptions(
            root,
            client,
            journal,
            clock,
        ));

        await expect(pool.propose(request(clock.now() + 5_000)))
            .resolves.toMatchObject({ candidateId: "candidate-a" });
        expect(createCalls).toBe(1);
        expect(journal.commitCalls).toBe(1);
        expect(journal.quarantines.some((record) =>
            record.reason === "ambiguous_send_and_wait_after_submission"))
            .toBe(true);
        await pool.close();
    });

    it("recovers an in-flight durable callback instead of starting another model attempt", async () => {
        const root = makeRoot("in-flight-callback");
        const clock = fakeClock();
        let releaseCommit;
        let markStored;
        const commitGate = new Promise((resolve) => {
            releaseCommit = resolve;
        });
        const stored = new Promise((resolve) => {
            markStored = resolve;
        });
        const journal = durableJournal({
            afterStore: async () => {
                markStored();
                await commitGate;
            },
        });
        let createCalls = 0;
        let handlerPromise;
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                createCalls += 1;
                return {
                    async sendAndWait() {
                        handlerPromise = submit(config);
                        await stored;
                        throw Object.assign(new Error("ambiguous transport failure"), {
                            code: "ECONNRESET",
                        });
                    },
                    async abort() {},
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool(poolOptions(
            root,
            client,
            journal,
            clock,
        ));

        await expect(pool.propose(request(clock.now() + 5_000)))
            .resolves.toMatchObject({ candidateId: "candidate-a" });
        expect(createCalls).toBe(1);
        expect(journal.commitCalls).toBe(1);
        expect(journal.quarantines.some((record) =>
            record.reason === "ambiguous_callback_recovered_submission"))
            .toBe(true);
        releaseCommit();
        await expect(handlerPromise).resolves.toMatchObject({
            resultType: "success",
        });
        await pool.close();
    });

    it("recovers a crash after durable submission without asking the model again", async () => {
        const root = makeRoot("crash-recover");
        const clock = fakeClock();
        let inject = true;
        const journal = durableJournal({
            afterStore: async () => {
                if (inject) {
                    inject = false;
                    throw new InjectedCrashError("after_durable_sdk_submission");
                }
            },
        });
        let firstCreates = 0;
        const firstClient = {
            async start() {},
            async stop() {},
            async createSession(config) {
                firstCreates += 1;
                return {
                    async sendAndWait() {
                        await submit(config);
                    },
                    async abort() {},
                    async disconnect() {},
                };
            },
        };
        const deadlineMs = clock.now() + 5_000;
        const firstPool = createSdkWorkerPool(poolOptions(
            root,
            firstClient,
            journal,
            clock,
        ));
        await expect(firstPool.propose(request(deadlineMs))).rejects.toMatchObject({
            cause: {
                code: RUNTIME_ERROR_CODES.INJECTED_CRASH,
            },
        });
        expect(firstCreates).toBe(1);
        await firstPool.close();

        let secondStarts = 0;
        let secondCreates = 0;
        let recoveredUsage = null;
        const secondClient = {
            async start() {
                secondStarts += 1;
            },
            async stop() {},
            async createSession() {
                secondCreates += 1;
                throw new Error("model must not be called during recovery");
            },
        };
        const secondPool = createSdkWorkerPool(poolOptions(
            root,
            secondClient,
            journal,
            clock,
            {
                sdkUsageReporter: async (value) => {
                    recoveredUsage = value;
                },
            },
        ));
        await expect(secondPool.propose(request(deadlineMs)))
            .resolves.toMatchObject({ candidateId: "candidate-a" });
        expect(secondStarts).toBe(0);
        expect(secondCreates).toBe(0);
        expect(journal.commitCalls).toBe(1);
        expect(recoveredUsage).toMatchObject({
            recovered: true,
            attempts: 1,
            accounting: {
                reservedCostUnits: 10,
                chargedCostUnits: 10,
            },
        });
        await secondPool.close();
    });

    it("quarantines a callback that arrives after the failed session closed", async () => {
        const root = makeRoot("late");
        const clock = fakeClock();
        const journal = durableJournal();
        let lateSubmit;
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                lateSubmit = () => submit(config, "late-call");
                return {
                    async sendAndWait() {},
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool(poolOptions(
            root,
            client,
            journal,
            clock,
            { sdkRetryPolicy: retryPolicy({ maxAttempts: 1, maxCostUnits: 10 }) },
        ));

        await expect(pool.propose(request(clock.now() + 5_000))).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.WORKER_NO_SUBMISSION,
        });
        await expect(lateSubmit()).resolves.toMatchObject({
            resultType: "rejected",
        });
        expect(journal.commitCalls).toBe(0);
        expect(journal.quarantines.some((record) =>
            record.reason === "late_tool_callback")).toBe(true);
        await pool.close();
    });

    it("does not retry permanent SDK or invalid protocol failures", async () => {
        for (const mode of ["auth", "invalid"]) {
            const root = makeRoot(`no-retry-${mode}`);
            const clock = fakeClock();
            const journal = durableJournal();
            let createCalls = 0;
            const client = {
                async start() {},
                async stop() {},
                async createSession(config) {
                    createCalls += 1;
                    return {
                        async sendAndWait() {
                            if (mode === "auth") {
                                throw Object.assign(new Error("unauthorized"), {
                                    statusCode: 401,
                                });
                            }
                            const tool = config.tools[0];
                            await tool.handler({
                                ...payload(),
                                challenge: "wrong",
                            }, {
                                sessionId: config.sessionId,
                                toolCallId: "invalid",
                                toolName: tool.name,
                            });
                        },
                        async abort() {},
                        async disconnect() {},
                    };
                },
            };
            const pool = createSdkWorkerPool(poolOptions(
                root,
                client,
                journal,
                clock,
            ));
            await expect(pool.propose(request(clock.now() + 5_000))).rejects.toBeTruthy();
            expect(createCalls).toBe(1);
            await pool.close();
        }
    });

    it("reconciles all SDK usage against conservative per-attempt reserves", async () => {
        const root = makeRoot("cost");
        const clock = fakeClock();
        const journal = durableJournal();
        let createCalls = 0;
        let report = null;
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                createCalls += 1;
                const handlers = new Map();
                const attempt = createCalls;
                return {
                    on(type, handler) {
                        handlers.set(type, handler);
                        return () => handlers.delete(type);
                    },
                    async sendAndWait() {
                        handlers.get("assistant.usage")?.({
                            id: `usage-${attempt}`,
                            type: "assistant.usage",
                            data: attempt === 1
                                ? {
                                    model: "gpt-test",
                                    inputTokens: 10,
                                    outputTokens: 10,
                                }
                                : {
                                    model: "gpt-test",
                                    inputTokens: 200,
                                    outputTokens: 100,
                                },
                        });
                        if (attempt === 1) {
                            throw Object.assign(new Error("reset"), {
                                code: "ECONNRESET",
                            });
                        }
                        await submit(config);
                    },
                    async abort() {},
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool(poolOptions(
            root,
            client,
            journal,
            clock,
            {
                sdkRetryPolicy: retryPolicy({
                    reservedCostUnitsPerAttempt: 100,
                    maxCostUnits: 300,
                }),
                sdkUsageToCostUnits: (usage) =>
                    5
                    + usage.inputTokens
                    + usage.cachedInputTokens
                    + usage.outputTokens
                    + usage.reasoningTokens,
                sdkUsageReporter: async (value) => {
                    report = value;
                },
            },
        ));

        await pool.propose(request(clock.now() + 5_000));
        expect(report).toMatchObject({
            attempts: 2,
            accounting: {
                reservedCostUnits: 200,
                reportedCostUnits: 330,
                chargedCostUnits: 330,
                overBudget: true,
            },
        });
        await pool.close();
    });
});
