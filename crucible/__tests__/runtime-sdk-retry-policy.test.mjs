import { describe, expect, it } from "vitest";

import {
    RUNTIME_ERROR_CODES,
    WorkerProtocolError,
} from "../runtime/errors.mjs";
import {
    SDK_FAILURE_CLASSIFICATIONS,
    classifySdkFailure,
    computeSdkRetryDelay,
    createRetryingSdkClient,
    createSdkOperationalEvidence,
    createSdkUsageAccumulator,
    normalizeSdkOperationIdentity,
    reconcileSdkCost,
} from "../runtime/retry-policy.mjs";

const OPERATION = {
    proposalSlotId: "slot-a",
    commandId: "command-a",
    logicalEffectId: "effect-a",
};

function fakeClock(start = 10_000) {
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

describe("SDK failure classification", () => {
    it.each([
        [
            Object.assign(new Error("socket reset"), { code: "ECONNRESET" }),
            {},
            SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_TRANSPORT,
            true,
        ],
        [
            Object.assign(new Error("limited"), {
                statusCode: 429,
                retryAfterSeconds: 2,
            }),
            {},
            SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_RATE_LIMIT,
            true,
        ],
        [
            new Error("CLI was not ready"),
            { stage: "client startup" },
            SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_STARTUP,
            true,
        ],
        [
            Object.assign(new Error("session is disconnected"), {
                code: "SESSION_DISCONNECTED",
                statusCode: 404,
                badRequestKind: "structured_error",
            }),
            {},
            SDK_FAILURE_CLASSIFICATIONS.SESSION_RECREATE,
            true,
        ],
        [
            Object.assign(new Error("login required"), { statusCode: 401 }),
            {},
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_AUTH,
            false,
        ],
        [
            Object.assign(new Error("unknown model"), { code: "MODEL_NOT_FOUND" }),
            {},
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_MODEL,
            false,
        ],
        [
            Object.assign(new Error("schema rejected"), {
                statusCode: 400,
                badRequestKind: "structured_error",
            }),
            {},
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_SCHEMA,
            false,
        ],
        [
            Object.assign(new Error("invalid configuration"), { statusCode: 422 }),
            {},
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_CONFIG,
            false,
        ],
        [
            Object.assign(new Error("content filter"), { errorType: "policy" }),
            {},
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_POLICY,
            false,
        ],
        [
            new WorkerProtocolError(
                RUNTIME_ERROR_CODES.WORKER_WRONG_NONCE,
                "wrong challenge",
            ),
            {},
            SDK_FAILURE_CLASSIFICATIONS.PROTOCOL_INVALID,
            false,
        ],
        [
            new Error("unrecognized SDK failure"),
            {},
            SDK_FAILURE_CLASSIFICATIONS.UNKNOWN,
            false,
        ],
    ])("classifies %# without widening retry authority", (
        error,
        context,
        classification,
        retryable,
    ) => {
        expect(classifySdkFailure(error, context)).toMatchObject({
            classification,
            retryable,
        });
    });

    it("uses SDK error events instead of misclassifying missing output as protocol invalid", () => {
        const result = classifySdkFailure(new Error("turn failed"), {
            sdkEvents: [{
                type: "session.error",
                data: {
                    errorType: "rate_limit",
                    errorCode: "user_model_rate_limited",
                    message: "wait",
                    statusCode: 429,
                    retryAfterSeconds: 3,
                },
            }],
        });
        expect(result).toMatchObject({
            classification: SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_RATE_LIMIT,
            retryable: true,
            retryAfterMs: 3_000,
        });
    });

    it("classifies SDK content-filter usage events as permanent policy failures", () => {
        expect(classifySdkFailure(new Error("turn ended"), {
            sdkEvents: [{
                type: "assistant.usage",
                data: {
                    model: "model-a",
                    contentFilterTriggered: true,
                    finishReason: "content_filter",
                },
            }],
        })).toMatchObject({
            classification: SDK_FAILURE_CLASSIFICATIONS.PERMANENT_POLICY,
            retryable: false,
        });
    });
});

describe("bounded retry execution", () => {
    it("fails closed when retries lack a frozen cost budget", async () => {
        const clock = fakeClock();
        const retrying = createRetryingSdkClient({}, {
            policy: {
                maxAttempts: 2,
                baseDelayMs: 0,
                maxDelayMs: 0,
                maxCumulativeDelayMs: 0,
                jitterBps: 0,
            },
            clock,
            sleep: clock.sleep.bind(clock),
        });
        await expect(retrying.execute({
            operationIdentity: OPERATION,
            deadlineMs: clock.now() + 1_000,
            async operation() {
                return "must-not-run";
            },
        })).rejects.toThrow("positive frozen per-attempt cost reserve");
    });

    it("honors rate-limit delay and keeps all logical ids stable", async () => {
        const clock = fakeClock();
        const seen = [];
        let calls = 0;
        const retrying = createRetryingSdkClient({}, {
            policy: {
                maxAttempts: 2,
                baseDelayMs: 100,
                maxDelayMs: 500,
                maxCumulativeDelayMs: 1_000,
                jitterBps: 0,
                reservedCostUnitsPerAttempt: 10,
                maxCostUnits: 20,
            },
            clock,
            sleep: clock.sleep.bind(clock),
        });
        const result = await retrying.execute({
            operationIdentity: OPERATION,
            deadlineMs: clock.now() + 5_000,
            async operation(_client, context) {
                seen.push(context.operationIdentity);
                calls += 1;
                if (calls === 1) {
                    throw Object.assign(new Error("rate limited"), {
                        statusCode: 429,
                        retryAfterMs: 300,
                    });
                }
                return "ok";
            },
        });
        expect(result.value).toBe("ok");
        expect(result.attempts).toBe(2);
        expect(clock.sleeps).toEqual([300]);
        expect(seen).toEqual([
            normalizeSdkOperationIdentity(OPERATION),
            normalizeSdkOperationIdentity(OPERATION),
        ]);
        expect(result.accounting).toMatchObject({
            reservedCostUnits: 20,
            chargedCostUnits: 20,
        });
    });

    it("exhausts the finite attempt budget", async () => {
        const clock = fakeClock();
        let calls = 0;
        const retrying = createRetryingSdkClient({}, {
            policy: {
                maxAttempts: 3,
                baseDelayMs: 100,
                maxDelayMs: 1_000,
                maxCumulativeDelayMs: 1_000,
                jitterBps: 0,
                reservedCostUnitsPerAttempt: 1,
                maxCostUnits: 3,
            },
            clock,
            sleep: clock.sleep.bind(clock),
        });
        await expect(retrying.execute({
            operationIdentity: OPERATION,
            deadlineMs: clock.now() + 5_000,
            async operation() {
                calls += 1;
                throw Object.assign(new Error("reset"), { code: "ECONNRESET" });
            },
        })).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.SDK_RETRY_EXHAUSTED,
            details: {
                reason: "attempt_budget",
                attempts: 3,
            },
        });
        expect(calls).toBe(3);
        expect(clock.sleeps).toEqual([100, 200]);
    });

    it("does not schedule a retry beyond the absolute deadline", async () => {
        const clock = fakeClock();
        let calls = 0;
        const retrying = createRetryingSdkClient({}, {
            policy: {
                maxAttempts: 3,
                baseDelayMs: 100,
                maxDelayMs: 100,
                maxCumulativeDelayMs: 500,
                jitterBps: 0,
                reservedCostUnitsPerAttempt: 1,
                maxCostUnits: 3,
            },
            clock,
            sleep: clock.sleep.bind(clock),
        });
        await expect(retrying.execute({
            operationIdentity: OPERATION,
            deadlineMs: clock.now() + 50,
            async operation() {
                calls += 1;
                throw Object.assign(new Error("reset"), { code: "ECONNRESET" });
            },
        })).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.SDK_RETRY_EXHAUSTED,
            details: {
                reason: "absolute_deadline",
                attempts: 1,
            },
        });
        expect(calls).toBe(1);
        expect(clock.sleeps).toEqual([]);
    });

    it("stops before an attempt that the frozen cost budget cannot fund", async () => {
        const clock = fakeClock();
        let calls = 0;
        const retrying = createRetryingSdkClient({}, {
            policy: {
                maxAttempts: 3,
                baseDelayMs: 0,
                maxDelayMs: 0,
                maxCumulativeDelayMs: 0,
                jitterBps: 0,
                reservedCostUnitsPerAttempt: 100,
                maxCostUnits: 150,
            },
            clock,
            sleep: clock.sleep.bind(clock),
        });
        await expect(retrying.execute({
            operationIdentity: OPERATION,
            deadlineMs: clock.now() + 1_000,
            async operation() {
                calls += 1;
                throw Object.assign(new Error("reset"), { code: "ECONNRESET" });
            },
        })).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.SDK_RETRY_EXHAUSTED,
            details: {
                reason: "cost_budget",
                attempts: 1,
            },
        });
        expect(calls).toBe(1);
    });

    it("does not retry after observed SDK usage consumes the remaining budget", async () => {
        const clock = fakeClock();
        let calls = 0;
        const observed = [];
        const retrying = createRetryingSdkClient({}, {
            policy: {
                maxAttempts: 3,
                baseDelayMs: 0,
                maxDelayMs: 0,
                maxCumulativeDelayMs: 0,
                jitterBps: 0,
                reservedCostUnitsPerAttempt: 10,
                maxCostUnits: 100,
            },
            clock,
            sleep: clock.sleep.bind(clock),
        });
        await expect(retrying.execute({
            operationIdentity: OPERATION,
            deadlineMs: clock.now() + 1_000,
            getSdkReportedCostUnits: () => observed,
            async operation() {
                calls += 1;
                observed.push(95);
                throw Object.assign(new Error("reset"), { code: "ECONNRESET" });
            },
        })).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.SDK_RETRY_EXHAUSTED,
            details: {
                reason: "cost_budget",
                attempts: 1,
            },
        });
        expect(calls).toBe(1);
    });

    it("charges recovered attempts even when no new SDK call is made", async () => {
        const clock = fakeClock();
        let calls = 0;
        const retrying = createRetryingSdkClient({}, {
            policy: {
                maxAttempts: 3,
                baseDelayMs: 0,
                maxDelayMs: 0,
                maxCumulativeDelayMs: 0,
                jitterBps: 0,
                reservedCostUnitsPerAttempt: 100,
                maxCostUnits: 300,
            },
            clock,
            sleep: clock.sleep.bind(clock),
        });
        const result = await retrying.execute({
            operationIdentity: OPERATION,
            deadlineMs: clock.now() + 1_000,
            recover: async () => ({
                recovered: true,
                value: "sealed",
                attemptedCount: 2,
            }),
            async operation() {
                calls += 1;
                return "must-not-run";
            },
        });
        expect(calls).toBe(0);
        expect(result).toMatchObject({
            value: "sealed",
            recovered: true,
            attempts: 2,
            accounting: {
                reservedCostUnits: 200,
                chargedCostUnits: 200,
            },
        });
    });

    it("never retries permanent, protocol-invalid, or unknown failures", async () => {
        for (const error of [
            Object.assign(new Error("unauthorized"), { statusCode: 401 }),
            new WorkerProtocolError(
                RUNTIME_ERROR_CODES.WORKER_WRONG_NONCE,
                "wrong nonce",
            ),
            new Error("mystery"),
        ]) {
            const clock = fakeClock();
            let calls = 0;
            const retrying = createRetryingSdkClient({}, {
                policy: {
                    maxAttempts: 3,
                    baseDelayMs: 0,
                    maxDelayMs: 0,
                    maxCumulativeDelayMs: 0,
                    jitterBps: 0,
                    reservedCostUnitsPerAttempt: 1,
                    maxCostUnits: 3,
                },
                clock,
                sleep: clock.sleep.bind(clock),
            });
            await expect(retrying.execute({
                operationIdentity: OPERATION,
                deadlineMs: clock.now() + 1_000,
                async operation() {
                    calls += 1;
                    throw error;
                },
            })).rejects.toBeTruthy();
            expect(calls).toBe(1);
        }
    });
});

describe("retry evidence and conservative cost", () => {
    it("produces deterministic jitter and hash-bound operational evidence", () => {
        const policy = {
            maxAttempts: 3,
            baseDelayMs: 1_000,
            maxDelayMs: 10_000,
            maxCumulativeDelayMs: 20_000,
            jitterBps: 2_500,
        };
        expect(computeSdkRetryDelay(policy, {
            operationIdentity: OPERATION,
            failedAttempt: 1,
        })).toEqual(computeSdkRetryDelay(policy, {
            operationIdentity: OPERATION,
            failedAttempt: 1,
        }));

        const evidence = createSdkOperationalEvidence({
            eventType: "attempt_failed",
            operationIdentity: OPERATION,
            attempt: 1,
            observedAtMs: 123,
            classification: SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_TRANSPORT,
            reason: "transport_signal",
            details: { statusCode: 503 },
        });
        expect(evidence.evidenceHash).toMatch(
            /^sha256:crucible-sdk-operational-evidence-v1:[a-f0-9]{64}$/,
        );
    });

    it("deduplicates usage events and never charges below reserved or observed cost", () => {
        const usage = createSdkUsageAccumulator({ model: "model-a" });
        const event = {
            id: "usage-1",
            type: "assistant.usage",
            data: {
                model: "model-a",
                inputTokens: 10,
                cacheReadTokens: 5,
                outputTokens: 20,
                reasoningTokens: 7,
            },
        };
        expect(usage.observe(event)).toBe(true);
        expect(usage.observe(event)).toBe(false);
        expect(usage.snapshot()).toMatchObject({
            eventCount: 1,
            reports: [{
                model: "model-a",
                inputTokens: 10,
                cachedInputTokens: 5,
                outputTokens: 20,
                reasoningTokens: 7,
                totalTokens: 42,
            }],
        });

        expect(reconcileSdkCost({
            reservedCostUnitsPerAttempt: 100,
            attemptedCount: 2,
            sdkReportedCostUnits: [25],
            priorChargedCostUnits: 150,
            maxCostUnits: 500,
        }).chargedCostUnits).toBe(200);
        expect(reconcileSdkCost({
            reservedCostUnitsPerAttempt: 100,
            attemptedCount: 2,
            sdkReportedCostUnits: [125, 175],
            priorChargedCostUnits: 150,
            maxCostUnits: 250,
        })).toMatchObject({
            reservedCostUnits: 200,
            reportedCostUnits: 300,
            chargedCostUnits: 300,
            overBudget: true,
        });
    });
});
