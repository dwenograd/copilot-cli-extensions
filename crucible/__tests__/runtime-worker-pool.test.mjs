import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    DEFAULT_PARENT_READ_LIMITS,
    READ_PARENT_ARTIFACT_TOOL_NAME,
    RUNTIME_ERROR_CODES,
    SUBMIT_CANDIDATE_TOOL_NAME,
    createSdkWorkerPool,
    validateCandidateSubmission,
    validateWorkerProposal,
} from "../runtime/index.mjs";
import { hashCanonical, normalizeHypotheses } from "../domain/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-worker-${label}-`));
    roots.push(root);
    return root;
}

afterEach(() => {
    const failures = [];
    for (const root of roots.splice(0)) {
        try {
            fs.rmSync(root, {
                recursive: true,
                force: true,
                maxRetries: 20,
                retryDelay: 25,
            });
        } catch (error) {
            failures.push(error);
        }
        if (fs.existsSync(root)) {
            failures.push(new Error(`worker-pool test root survived cleanup: ${root}`));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "worker-pool test cleanup failed");
    }
});

function validAnnotations(overrides = {}) {
    return {
        mechanism: "Write a deterministic score fixture.",
        ...overrides,
    };
}

function validPayload(candidateId, challenge = "challenge-1", annotationOverrides = {}) {
    return {
        challenge,
        candidateId,
        annotations: validAnnotations(annotationOverrides),
        files: [{ path: "score.txt", content: "95\n" }],
    };
}

const HYPOTHESIS_OBSERVABLES = [
    { key: "score", kind: "numeric", minimum: 0, maximum: 100 },
    { key: "outcome", kind: "categorical", values: ["accepted", "rejected"] },
];

const REQUIRED_HYPOTHESIS_POLICY = {
    required: true,
    maxPredictions: 4,
};

function thresholdHypotheses(value = 90) {
    return {
        predictions: [{
            id: "score-threshold",
            kind: "threshold",
            observable: "score",
            operator: ">=",
            value,
            refutation: { kind: "threshold", operator: "<", value },
            requiredForResult: true,
        }],
    };
}

function fakeClient(mode, captured) {
    return {
        async start() {
            captured.started = true;
        },
        async stop() {
            captured.stopped = true;
        },
        async createSession(config) {
            captured.configs.push(config);
            return {
                async sendAndWait() {
                    const tool = config.tools[0];
                    if (mode === "valid") {
                        await tool.handler(validPayload("candidate-a"), {
                            sessionId: config.sessionId,
                            toolCallId: "call-1",
                            toolName: tool.name,
                        });
                    } else if (mode === "wrong-nonce") {
                        await tool.handler(validPayload("candidate-a", "wrong"), {
                            sessionId: config.sessionId,
                            toolCallId: "call-1",
                            toolName: tool.name,
                        });
                    } else if (mode === "session-mismatch") {
                        await tool.handler(validPayload("candidate-a"), {
                            sessionId: "different-session",
                            toolCallId: "call-1",
                            toolName: tool.name,
                        });
                    } else if (mode === "wrong-candidate") {
                        await tool.handler(validPayload("candidate-b"), {
                            sessionId: config.sessionId,
                            toolCallId: "call-1",
                            toolName: tool.name,
                        });
                    } else if (mode === "multiple") {
                        const invocation = {
                            sessionId: config.sessionId,
                            toolCallId: "call-1",
                            toolName: tool.name,
                        };
                        await tool.handler(validPayload("candidate-a"), invocation);
                        await tool.handler(validPayload("candidate-a"), {
                            ...invocation,
                            toolCallId: "call-2",
                        });
                    }
                    return {
                        data: {
                            content: mode === "no-submit"
                                ? "Here is a prose-only candidate and VERIFIED_RESULT."
                                : "ignored model prose",
                        },
                    };
                },
                async disconnect() {
                    captured.disconnected += 1;
                },
            };
        },
    };
}

// A client that hands the live session config to a driver callback, letting a
// test invoke the worker tools directly and inspect their results.
function driverClient(onSession, captured = { configs: [], disconnected: 0 }) {
    return {
        captured,
        async start() {},
        async stop() {},
        async createSession(config) {
            captured.configs.push(config);
            return {
                async sendAndWait() {
                    await onSession(config);
                    return { data: { content: "" } };
                },
                async disconnect() {
                    captured.disconnected += 1;
                },
            };
        },
    };
}

async function makePool(mode = "valid") {
    const root = makeRoot(mode);
    const captured = { configs: [], disconnected: 0 };
    const pool = createSdkWorkerPool({
        client: fakeClient(mode, captured),
        baseDirectory: path.join(root, "sdk"),
        workingDirectory: path.join(root, "work"),
    });
    return { pool, captured };
}

function request(candidateId = "candidate-a") {
    return {
        model: "gpt-test",
        reasoningEffort: "low",
        sessionId: "session-a",
        challengeNonce: "challenge-1",
        allowedCandidateIds: [candidateId],
        prompt: "Call the submission tool exactly once.\nDo not issue a verdict.",
    };
}

function mutableClock(start = 10_000) {
    let now = start;
    return {
        now: () => now,
        advance(milliseconds) {
            now += milliseconds;
        },
    };
}

function controlledTimers(clock) {
    let nextId = 0;
    const scheduled = new Map();
    return {
        setTimeout(callback, milliseconds) {
            const handle = {
                id: ++nextId,
                at: clock.now() + milliseconds,
                unref() {},
            };
            scheduled.set(handle.id, { callback, handle });
            return handle;
        },
        clearTimeout(handle) {
            scheduled.delete(handle?.id);
        },
        advance(milliseconds) {
            clock.advance(milliseconds);
            for (;;) {
                const due = [...scheduled.values()]
                    .filter(({ handle }) => handle.at <= clock.now())
                    .sort((left, right) =>
                        left.handle.at - right.handle.at
                        || left.handle.id - right.handle.id);
                if (due.length === 0) break;
                const next = due[0];
                scheduled.delete(next.handle.id);
                next.callback();
            }
        },
        get pendingCount() {
            return scheduled.size;
        },
    };
}

// In-memory parent snapshot reader that exposes ONLY the two read callbacks the
// worker is allowed to use. There is no write/execute surface at all.
const SNAPSHOT_A = `sha256:${"a".repeat(64)}`;
const SNAPSHOT_B = `sha256:${"b".repeat(64)}`;

function makeReader(snapshots) {
    const manifests = new Map();
    const objects = new Map();
    let counter = 0;
    for (const [snapshotId, entries] of Object.entries(snapshots)) {
        const manifestEntries = entries.map((entry) => {
            const object = `object-${counter}`;
            counter += 1;
            objects.set(object, entry.bytes);
            return { path: entry.path, size: entry.bytes.length, object };
        });
        manifests.set(snapshotId, {
            type: "crucible.snapshot",
            version: 1,
            algo: "sha256",
            entries: manifestEntries,
        });
    }
    const reads = [];
    return {
        reads,
        loadManifest(snapshotId) {
            if (!manifests.has(snapshotId)) {
                const error = new Error("no such snapshot");
                error.code = "ENOENT";
                throw error;
            }
            return manifests.get(snapshotId);
        },
        readObject(objectId) {
            reads.push(objectId);
            if (!objects.has(objectId)) {
                const error = new Error("no such object");
                error.code = "ENOENT";
                throw error;
            }
            return objects.get(objectId);
        },
    };
}

// Drive a single proposal that issues a scripted list of parent-read calls and
// then submits a valid candidate so propose() resolves. Returns the parent-read
// tool results plus the resolved proposal.
async function runParentReads({ parents, reader, parentReadLimits = {}, calls }) {
    const root = makeRoot("parent");
    const results = [];
    const client = driverClient(async (config) => {
        const parentTool = config.tools.find((tool) => tool.name === READ_PARENT_ARTIFACT_TOOL_NAME);
        const submitTool = config.tools.find((tool) => tool.name === SUBMIT_CANDIDATE_TOOL_NAME);
        const baseInvocation = { sessionId: config.sessionId, toolName: parentTool?.name };
        for (const call of calls) {
            const args = { challenge: "challenge-1", ...call.args };
            const invocation = call.invocation ?? baseInvocation;
            results.push(await parentTool.handler(args, invocation));
        }
        await submitTool.handler(validPayload("candidate-a"), {
            sessionId: config.sessionId,
            toolName: submitTool.name,
        });
    });
    const pool = createSdkWorkerPool({
        client,
        baseDirectory: path.join(root, "sdk"),
        workingDirectory: path.join(root, "work"),
        parentReader: reader,
        parentReadLimits,
    });
    const proposal = await pool.propose({ ...request("candidate-a"), parents });
    await pool.close();
    return { results: results.map((result) => ({
        resultType: result.resultType,
        parsed: JSON.parse(result.textResultForLlm),
    })), proposal };
}

describe("Crucible SDK worker pool", () => {
    it("uses one non-deferred custom tool and code-stamps worker identity", async () => {
        const { pool, captured } = await makePool("valid");
        const proposal = await pool.propose(request());

        expect(proposal.candidateId).toBe("candidate-a");
        expect(proposal.annotations.mechanism).toBe("Write a deterministic score fixture.");
        expect(proposal.identity).toMatchObject({
            invocationSessionId: "session-a",
            configuredModel: "gpt-test",
            challengeNonce: "challenge-1",
            contextHash: null,
        });
        expect(proposal.identity.promptHash).toMatch(
            /^sha256:crucible-runtime-worker-prompt-v1:[a-f0-9]{64}$/,
        );
        expect(proposal.identity.payloadHash).toMatch(
            /^sha256:crucible-runtime-candidate-payload-v1:[a-f0-9]{64}$/,
        );
        expect(proposal.identity.annotationsHash).toBe(
            hashCanonical(proposal.annotations, "sha256:crucible-runtime-candidate-annotations-v1"),
        );

        const config = captured.configs[0];
        expect(config.tools).toHaveLength(1);
        expect(config.tools[0]).toMatchObject({
            name: SUBMIT_CANDIDATE_TOOL_NAME,
            defer: "never",
            skipPermission: true,
        });
        expect(config.availableTools).toEqual([`custom:${SUBMIT_CANDIDATE_TOOL_NAME}`]);
        expect(config.enableConfigDiscovery).toBe(false);
        expect(config.enableSessionTelemetry).toBe(false);
        expect(config.skipCustomInstructions).toBe(true);
        expect(config.enableSkills).toBe(false);
        expect(config.enableHostGitOperations).toBe(false);
        expect(config.enableSessionStore).toBe(false);
        expect(config.remoteSession).toBe("off");
        expect(captured.disconnected).toBe(1);
        await pool.close();
        expect(captured.stopped).toBe(true);
    });

    it("caps the SDK session timeout to the remaining absolute deadline", async () => {
        const root = makeRoot("deadline");
        const clock = mutableClock();
        const deadlineMs = clock.now() + 600;
        const captured = {
            timeoutMs: null,
            disconnected: 0,
            aborted: 0,
        };
        const client = {
            async start() {},
            async stop() {},
            async createSession(config) {
                return {
                    async sendAndWait(_request, timeoutMs) {
                        captured.timeoutMs = timeoutMs;
                        await config.tools[0].handler(validPayload("candidate-a"), {
                            sessionId: config.sessionId,
                            toolCallId: "deadline-call",
                            toolName: config.tools[0].name,
                        });
                        clock.advance(601);
                    },
                    async abort() {
                        captured.aborted += 1;
                    },
                    async disconnect() {
                        captured.disconnected += 1;
                    },
                };
            },
        };
        const pool = createSdkWorkerPool({
            client,
            baseDirectory: path.join(root, "sdk"),
            workingDirectory: path.join(root, "work"),
            sessionTimeoutMs: 5_000,
            deadlineMs,
            clock,
        });
        await expect(pool.propose(request())).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED,
        });
        expect(captured.timeoutMs).toBe(600);
        expect(captured.aborted).toBe(1);
        expect(captured.disconnected).toBe(1);
        await pool.close();
    });

    it("bounds a hung SDK client shutdown", async () => {
        const root = makeRoot("shutdown-bound");
        const client = {
            async start() {},
            stop() {
                return new Promise(() => {});
            },
            async createSession() {
                throw new Error("must not create a session");
            },
        };
        const pool = createSdkWorkerPool({
            client,
            baseDirectory: path.join(root, "sdk"),
            workingDirectory: path.join(root, "work"),
            shutdownTimeoutMs: 10,
        });
        await pool.start();
        const started = Date.now();
        await expect(pool.close()).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
        });
        expect(Date.now() - started).toBeLessThan(500);
    });

    it("bounds a never-resolving createSession by the absolute deadline and reports it on close", async () => {
        const root = makeRoot("create-session-deadline");
        const clock = mutableClock();
        const timers = controlledTimers(clock);
        let stopCalls = 0;
        let markCreateEntered;
        const createEntered = new Promise((resolve) => {
            markCreateEntered = resolve;
        });
        const client = {
            async start() {},
            async stop() {
                stopCalls += 1;
            },
            createSession() {
                markCreateEntered();
                return new Promise(() => {});
            },
        };
        const deadlineMs = clock.now() + 600;
        const pool = createSdkWorkerPool({
            client,
            baseDirectory: path.join(root, "sdk"),
            workingDirectory: path.join(root, "work"),
            sessionTimeoutMs: 5_000,
            shutdownTimeoutMs: 25,
            deadlineMs,
            clock,
            timers,
        });

        const proposal = pool.propose(request());
        await createEntered;
        timers.advance(600);
        await expect(proposal).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED,
            details: {
                deadlineMs,
                stage: "proposal session creation",
            },
        });

        const closing = pool.close();
        await new Promise((resolve) => setImmediate(resolve));
        expect(timers.pendingCount).toBeGreaterThan(0);
        timers.advance(25);
        await expect(closing).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
            details: {
                failures: [
                    expect.objectContaining({
                        component: "session.create",
                        sessionId: "session-a",
                        model: "gpt-test",
                        status: "timed_out",
                    }),
                ],
            },
        });
        expect(stopCalls).toBe(1);
    });

    it("retains a failed session disconnect so close can retry it", async () => {
        const root = makeRoot("disconnect-retry");
        let disconnectCalls = 0;
        let abortCalls = 0;
        let stopCalls = 0;
        const client = {
            async start() {},
            async stop() {
                stopCalls += 1;
            },
            async createSession(config) {
                return {
                    async sendAndWait() {
                        await config.tools[0].handler(validPayload("candidate-a"), {
                            sessionId: config.sessionId,
                            toolName: config.tools[0].name,
                        });
                    },
                    async abort() {
                        abortCalls += 1;
                    },
                    async disconnect() {
                        disconnectCalls += 1;
                        if (disconnectCalls === 1) {
                            throw new Error("first disconnect failed");
                        }
                    },
                };
            },
        };
        const pool = createSdkWorkerPool({
            client,
            baseDirectory: path.join(root, "sdk"),
            workingDirectory: path.join(root, "work"),
        });
        await expect(pool.propose(request())).rejects.toThrow("first disconnect failed");
        await expect(pool.close()).resolves.toBeUndefined();
        expect(disconnectCalls).toBe(2);
        expect(abortCalls).toBe(1);
        expect(stopCalls).toBe(1);
    });

    it("retains a partially started SDK client when startup cleanup needs a retry", async () => {
        const root = makeRoot("startup-cleanup-retry");
        let stopCalls = 0;
        const client = {
            async start() {
                throw new Error("startup failed");
            },
            stop() {
                stopCalls += 1;
                return stopCalls === 1 ? new Promise(() => {}) : Promise.resolve();
            },
            async createSession() {
                throw new Error("must not create a session");
            },
        };
        const pool = createSdkWorkerPool({
            client,
            baseDirectory: path.join(root, "sdk"),
            workingDirectory: path.join(root, "work"),
            shutdownTimeoutMs: 10,
        });
        await expect(pool.start()).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.WORKER_STARTUP,
            recoverable: true,
            details: {
                cleanupStatus: "timed_out",
            },
        });
        await expect(pool.close()).resolves.toBeUndefined();
        expect(stopCalls).toBe(2);
    });

    it.each([
        ["no-submit", RUNTIME_ERROR_CODES.WORKER_NO_SUBMISSION],
        ["wrong-nonce", RUNTIME_ERROR_CODES.WORKER_WRONG_NONCE],
        ["session-mismatch", RUNTIME_ERROR_CODES.WORKER_SESSION_MISMATCH],
        ["wrong-candidate", RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE],
        ["multiple", RUNTIME_ERROR_CODES.WORKER_MULTIPLE_SUBMISSIONS],
    ])("rejects %s worker protocol violations", async (mode, code) => {
        const { pool } = await makePool(mode);
        await expect(pool.propose(request())).rejects.toMatchObject({ code });
        await pool.close();
    });

    it("rejects duplicate candidate ids across proposal sessions", async () => {
        const { pool } = await makePool("valid");
        await pool.propose(request("candidate-a"));
        await expect(pool.propose({
            ...request("candidate-a"),
            sessionId: "session-b",
        })).rejects.toMatchObject({
            code: RUNTIME_ERROR_CODES.WORKER_DUPLICATE_CANDIDATE,
        });
        await pool.close();
    });

    it("enforces traversal, file, and total-byte bounds before accepting bytes", () => {
        expect(() => validateCandidateSubmission({
            ...validPayload("candidate-a"),
            files: [{ path: "..\\escape.txt", content: "x" }],
        }, {
            challengeNonce: "challenge-1",
            allowedCandidateIds: ["candidate-a"],
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
        }));

        expect(() => validateCandidateSubmission({
            ...validPayload("candidate-a"),
            files: [{ path: "large.txt", content: "x".repeat(10) }],
        }, {
            challengeNonce: "challenge-1",
            allowedCandidateIds: ["candidate-a"],
            limits: { maxFileBytes: 4, maxTotalBytes: 32 },
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
        }));
    });

    describe("structured annotations and citations", () => {
        const options = {
            challengeNonce: "challenge-1",
            allowedCandidateIds: ["candidate-a"],
            visibleEvidenceIds: ["ev-1", "ev-2"],
        };

        it("accepts bounded annotations and returns them normalized", () => {
            const submission = validateCandidateSubmission({
                ...validPayload("candidate-a"),
                annotations: {
                    mechanism: "raise the score",
                    hypothesis: "a higher constant passes",
                    expectedEffects: ["score increases"],
                    citedEvidenceIds: ["ev-1"],
                    finding: "constant fixtures dominate",
                },
            }, options);
            expect(submission.annotations).toEqual({
                mechanism: "raise the score",
                hypothesis: "a higher constant passes",
                expectedEffects: ["score increases"],
                citedEvidenceIds: ["ev-1"],
                finding: "constant fixtures dominate",
            });
        });

        it("seals required typed predictions against an injected observable registry", () => {
            const submission = validateCandidateSubmission({
                ...validPayload("candidate-a"),
                annotations: {
                    mechanism: "raise the score",
                    hypothesis: "explanatory prose only",
                    hypotheses: thresholdHypotheses(),
                },
            }, {
                ...options,
                observableRegistry: HYPOTHESIS_OBSERVABLES,
                hypothesisPolicy: REQUIRED_HYPOTHESIS_POLICY,
            });
            expect(submission.annotations.hypothesis).toBe("explanatory prose only");
            expect(submission.annotations.hypotheses).toMatchObject({
                version: "crucible-preregistered-hypotheses-v4",
                predictions: [{
                    id: "score-threshold",
                    kind: "threshold",
                    requiredForResult: true,
                }],
            });
            expect(submission.annotations.hypotheses.identity).toMatch(
                /^sha256:crucible-preregistered-hypotheses-v4:[a-f0-9]{64}$/,
            );
            expect(Object.isFrozen(submission.annotations.hypotheses)).toBe(true);
        });

        it("rejects missing required predictions and unknown observables", () => {
            const hypothesisOptions = {
                ...options,
                observableRegistry: HYPOTHESIS_OBSERVABLES,
                hypothesisPolicy: REQUIRED_HYPOTHESIS_POLICY,
            };
            expect(() => validateCandidateSubmission(
                validPayload("candidate-a"),
                hypothesisOptions,
            )).toThrow(expect.objectContaining({
                code: RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            }));
            expect(() => validateCandidateSubmission({
                ...validPayload("candidate-a"),
                annotations: {
                    mechanism: "predict an unknown metric",
                    hypotheses: {
                        predictions: [{
                            ...thresholdHypotheses().predictions[0],
                            observable: "unregistered",
                        }],
                    },
                },
            }, hypothesisOptions)).toThrow(expect.objectContaining({
                code: RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            }));
        });

        it("rejects citations outside the visible evidence set", () => {
            expect(() => validateCandidateSubmission({
                ...validPayload("candidate-a"),
                annotations: { mechanism: "cite the invisible", citedEvidenceIds: ["ev-9"] },
            }, options)).toThrow(expect.objectContaining({
                code: RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            }));

            // With no evidence visible, any citation is out of bounds.
            expect(() => validateCandidateSubmission({
                ...validPayload("candidate-a"),
                annotations: { mechanism: "cite anything", citedEvidenceIds: ["ev-1"] },
            }, { ...options, visibleEvidenceIds: [] })).toThrow(expect.objectContaining({
                code: RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
            }));
        });

        it("rejects missing mechanism, unknown fields, and over-count annotations", () => {
            const bad = [
                { annotations: { hypothesis: "no mechanism" } },
                { annotations: { mechanism: "m", surprise: "x" } },
                { annotations: { mechanism: "x".repeat(257) } },
                { annotations: { mechanism: "m", finding: "😀".repeat(300) } },
                { annotations: { mechanism: "m", expectedEffects: Array.from({ length: 17 }, () => "e") } },
                { annotations: { mechanism: "m", citedEvidenceIds: ["not a valid id!"] } },
                { annotations: "not-an-object" },
            ];
            for (const overrides of bad) {
                expect(() => validateCandidateSubmission({
                    ...validPayload("candidate-a"),
                    ...overrides,
                }, options)).toThrow(expect.objectContaining({
                    code: RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                }));
            }
        });

        it("binds prompt-context hash and annotations into worker identity", async () => {
            const root = makeRoot("identity");
            const contextHash = `sha256:crucible-runtime-prompt-context-v1:${"c".repeat(64)}`;
            const client = driverClient(async (config) => {
                const submitTool = config.tools[0];
                await submitTool.handler({
                    ...validPayload("candidate-a"),
                    annotations: { mechanism: "cite ev-1", citedEvidenceIds: ["ev-1"] },
                }, { sessionId: config.sessionId, toolName: submitTool.name });
            });
            const pool = createSdkWorkerPool({
                client,
                baseDirectory: path.join(root, "sdk"),
                workingDirectory: path.join(root, "work"),
            });
            const proposal = await pool.propose({
                ...request("candidate-a"),
                visibleEvidenceIds: ["ev-1", "ev-2"],
                promptContextHash: contextHash,
            });
            expect(proposal.identity.contextHash).toBe(contextHash);
            expect(proposal.annotations.citedEvidenceIds).toEqual(["ev-1"]);
            expect(validateWorkerProposal(proposal, {
                ...request("candidate-a"),
                visibleEvidenceIds: ["ev-1", "ev-2"],
                promptContextHash: contextHash,
            })).toEqual(proposal);
            await pool.close();
        });

        it("binds sealed hypotheses into annotation and proposal payload hashes", async () => {
            const root = makeRoot("hypothesis-identity");
            const client = driverClient(async (config) => {
                const submitTool = config.tools[0];
                expect(submitTool.parameters.properties.annotations.required)
                    .toContain("hypotheses");
                await submitTool.handler({
                    ...validPayload("candidate-a"),
                    annotations: {
                        mechanism: "preregister score",
                        hypotheses: thresholdHypotheses(),
                    },
                }, { sessionId: config.sessionId, toolName: submitTool.name });
            });
            const pool = createSdkWorkerPool({
                client,
                baseDirectory: path.join(root, "sdk"),
                workingDirectory: path.join(root, "work"),
            });
            const hypothesisRequest = {
                ...request("candidate-a"),
                observableRegistry: HYPOTHESIS_OBSERVABLES,
                hypothesisPolicy: REQUIRED_HYPOTHESIS_POLICY,
            };
            const proposal = await pool.propose(hypothesisRequest);
            expect(proposal.identity.annotationsHash).toBe(
                hashCanonical(
                    proposal.annotations,
                    "sha256:crucible-runtime-candidate-annotations-v1",
                ),
            );
            expect(proposal.identity.payloadHash).toBe(
                hashCanonical(
                    {
                        candidateId: proposal.candidateId,
                        annotations: proposal.annotations,
                        files: proposal.files,
                    },
                    "sha256:crucible-runtime-candidate-payload-v1",
                ),
            );
            expect(() => {
                proposal.annotations.hypotheses.predictions[0].value = 95;
            }).toThrow(TypeError);

            const changed = structuredClone(proposal);
            changed.annotations.hypotheses = normalizeHypotheses(
                thresholdHypotheses(95),
                {
                    observableRegistry: HYPOTHESIS_OBSERVABLES,
                    hypothesisPolicy: REQUIRED_HYPOTHESIS_POLICY,
                },
            );
            expect(() => validateWorkerProposal(changed, hypothesisRequest))
                .toThrow(expect.objectContaining({
                    code: RUNTIME_ERROR_CODES.WORKER_PROTOCOL,
                    details: expect.objectContaining({ field: "annotationsHash" }),
                }));
            await pool.close();
        });

        it.each([
            ["invocationSessionId", "different-session"],
            ["configuredModel", "different-model"],
            ["challengeNonce", "different-challenge"],
            ["promptHash", "sha256:wrong-prompt"],
            ["contextHash", "sha256:wrong-context"],
            ["annotationsHash", "sha256:wrong-annotations"],
            ["payloadHash", "sha256:wrong-payload"],
        ])("rejects an independent identity.%s mismatch", async (field, mismatch) => {
            const { pool } = await makePool("valid");
            let proposal;
            try {
                proposal = await pool.propose(request());
                expect(() => validateWorkerProposal({
                    ...proposal,
                    identity: {
                        ...proposal.identity,
                        [field]: mismatch,
                    },
                }, request())).toThrow(expect.objectContaining({
                    code: RUNTIME_ERROR_CODES.WORKER_PROTOCOL,
                    details: expect.objectContaining({ field }),
                }));
            } finally {
                await pool.close();
            }
        });
    });

    describe("conditional parent-read tool set", () => {
        it("adds the parent-read tool only when parent snapshots are assigned", async () => {
            const root = makeRoot("cond");
            const reader = makeReader({ [SNAPSHOT_A]: [{ path: "a.txt", bytes: Buffer.from("hi") }] });
            const captured = { configs: [], disconnected: 0 };
            const client = driverClient(async (config) => {
                const submitTool = config.tools.find((tool) => tool.name === SUBMIT_CANDIDATE_TOOL_NAME);
                const candidateId = config.sessionId === "session-b" ? "candidate-b" : "candidate-a";
                await submitTool.handler(validPayload(candidateId), {
                    sessionId: config.sessionId,
                    toolName: submitTool.name,
                });
            }, captured);
            const pool = createSdkWorkerPool({
                client,
                baseDirectory: path.join(root, "sdk"),
                workingDirectory: path.join(root, "work"),
                parentReader: reader,
            });

            await pool.propose({ ...request("candidate-a") });
            const withoutParents = captured.configs[0];
            expect(withoutParents.tools).toHaveLength(1);
            expect(withoutParents.availableTools).toEqual([`custom:${SUBMIT_CANDIDATE_TOOL_NAME}`]);

            await pool.propose({
                ...request("candidate-b"),
                sessionId: "session-b",
                allowedCandidateIds: ["candidate-b"],
                parents: [{ parentId: "ev-parent", snapshotId: SNAPSHOT_A }],
            });
            const withParents = captured.configs[1];
            expect(withParents.tools.map((tool) => tool.name)).toEqual([
                SUBMIT_CANDIDATE_TOOL_NAME,
                READ_PARENT_ARTIFACT_TOOL_NAME,
            ]);
            expect(withParents.availableTools).toEqual([
                `custom:${SUBMIT_CANDIDATE_TOOL_NAME}`,
                `custom:${READ_PARENT_ARTIFACT_TOOL_NAME}`,
            ]);
            for (const tool of withParents.tools) {
                expect(tool.defer).toBe("never");
                expect(tool.skipPermission).toBe(true);
            }
            await pool.close();
        });

        it("refuses assigned parents when no reader is injected", async () => {
            const { pool } = await makePool("valid");
            await expect(pool.propose({
                ...request("candidate-a"),
                parents: [{ parentId: "ev-parent", snapshotId: SNAPSHOT_A }],
            })).rejects.toMatchObject({ code: RUNTIME_ERROR_CODES.INVALID_CONFIG });
            await pool.close();
        });
    });

    describe("parent-read enforcement", () => {
        const parents = [{ parentId: "ev-parent", snapshotId: SNAPSHOT_A }];

        it("serves a bounded, nonce-framed UTF-8 chunk and lists the manifest", async () => {
            const reader = makeReader({
                [SNAPSHOT_A]: [{ path: "src/main.txt", bytes: Buffer.from("hello world\n") }],
            });
            const { results } = await runParentReads({
                parents,
                reader,
                calls: [
                    { args: { parentId: "ev-parent", op: "list" } },
                    { args: { parentId: "ev-parent", op: "read", path: "src/main.txt", offset: 0, length: 5 } },
                ],
            });
            expect(results[0].resultType).toBe("success");
            expect(results[0].parsed).toMatchObject({
                ok: true,
                is_result: false,
                entries: [{ path: "src/main.txt", size: 12 }],
            });
            expect(results[1].resultType).toBe("success");
            expect(results[1].parsed).toMatchObject({ ok: true, is_result: false, bytes: 5, eof: false });
            expect(results[1].parsed.content).toContain("hello");
            expect(results[1].parsed.content).toMatch(/<<<CRUCIBLE_UNTRUSTED_DATA[^]*hello[^]*END_CRUCIBLE_UNTRUSTED_DATA/);
        });

        it("rejects unauthorized parents, unknown paths, offsets, and challenge/session", async () => {
            const reader = makeReader({
                [SNAPSHOT_A]: [{ path: "a.txt", bytes: Buffer.from("abcdef") }],
            });
            const { results } = await runParentReads({
                parents,
                reader,
                calls: [
                    { args: { parentId: "ev-other", op: "read", path: "a.txt", offset: 0, length: 3 } },
                    { args: { parentId: "ev-parent", op: "read", path: "../a.txt", offset: 0, length: 3 } },
                    { args: { parentId: "ev-parent", op: "read", path: "missing.txt", offset: 0, length: 3 } },
                    { args: { parentId: "ev-parent", op: "read", path: "a.txt", offset: 99, length: 3 } },
                    { args: { challenge: "nope", parentId: "ev-parent", op: "read", path: "a.txt", offset: 0, length: 3 } },
                    {
                        args: { parentId: "ev-parent", op: "read", path: "a.txt", offset: 0, length: 3 },
                        invocation: { sessionId: "somebody-else" },
                    },
                ],
            });
            expect(results.map((result) => result.parsed.reason)).toEqual([
                "parent",
                "path",
                "path",
                "path",
                "challenge",
                "session",
            ]);
            expect(results.every((result) => result.resultType === "failure")).toBe(true);
        });

        it("refuses binary files", async () => {
            const reader = makeReader({
                [SNAPSHOT_A]: [{ path: "blob.bin", bytes: Buffer.from([0x41, 0x00, 0x42]) }],
            });
            const { results } = await runParentReads({
                parents,
                reader,
                calls: [
                    { args: { parentId: "ev-parent", op: "read", path: "blob.bin", offset: 0, length: 3 } },
                ],
            });
            expect(results[0].resultType).toBe("failure");
            expect(results[0].parsed.reason).toBe("binary");
        });

        it("enforces per-call, per-file, per-session, and call-count limits", async () => {
            const bigFile = Buffer.from("0123456789abcdef");
            const perCall = await runParentReads({
                parents,
                reader: makeReader({ [SNAPSHOT_A]: [{ path: "a.txt", bytes: bigFile }] }),
                parentReadLimits: { maxChunkBytes: 4, maxSessionBytes: 64 },
                calls: [
                    { args: { parentId: "ev-parent", op: "read", path: "a.txt", offset: 0, length: 8 } },
                ],
            });
            expect(perCall.results[0].parsed.reason).toBe("limit");

            const perFile = await runParentReads({
                parents,
                reader: makeReader({ [SNAPSHOT_A]: [{ path: "a.txt", bytes: bigFile }] }),
                parentReadLimits: { maxFileBytes: 4 },
                calls: [
                    { args: { parentId: "ev-parent", op: "read", path: "a.txt", offset: 0, length: 4 } },
                ],
            });
            expect(perFile.results[0].parsed.reason).toBe("limit");

            const perSession = await runParentReads({
                parents,
                reader: makeReader({ [SNAPSHOT_A]: [{ path: "a.txt", bytes: bigFile }] }),
                parentReadLimits: { maxChunkBytes: 4, maxSessionBytes: 6 },
                calls: [
                    { args: { parentId: "ev-parent", op: "read", path: "a.txt", offset: 0, length: 4 } },
                    { args: { parentId: "ev-parent", op: "read", path: "a.txt", offset: 4, length: 4 } },
                ],
            });
            expect(perSession.results[0].resultType).toBe("success");
            expect(perSession.results[1].parsed.reason).toBe("limit");

            const callCap = await runParentReads({
                parents,
                reader: makeReader({ [SNAPSHOT_A]: [{ path: "a.txt", bytes: bigFile }] }),
                parentReadLimits: { maxCalls: 1 },
                calls: [
                    { args: { parentId: "ev-parent", op: "read", path: "a.txt", offset: 0, length: 4 } },
                    { args: { parentId: "ev-parent", op: "list" } },
                ],
            });
            expect(callCap.results[0].resultType).toBe("success");
            expect(callCap.results[1].parsed.reason).toBe("limit");
        });

        it("only reads assigned snapshots and never exposes a write surface", async () => {
            const reader = makeReader({
                [SNAPSHOT_A]: [{ path: "a.txt", bytes: Buffer.from("assigned") }],
                [SNAPSHOT_B]: [{ path: "b.txt", bytes: Buffer.from("forbidden") }],
            });
            await runParentReads({
                parents,
                reader,
                calls: [
                    { args: { parentId: "ev-parent", op: "read", path: "a.txt", offset: 0, length: 8 } },
                ],
            });
            // Only the assigned snapshot's object was ever read; the reader has no
            // put/write/materialize methods at all.
            expect(reader.reads).toHaveLength(1);
            expect(Object.keys(reader)).toEqual(["reads", "loadManifest", "readObject"]);
        });
    });

    describe("no terminal authority", () => {
        it("exposes only prefixed custom tools and never emits a verdict", async () => {
            const root = makeRoot("authority");
            const reader = makeReader({ [SNAPSHOT_A]: [{ path: "a.txt", bytes: Buffer.from("ok") }] });
            const captured = { configs: [], disconnected: 0 };
            let submitResult;
            const client = driverClient(async (config) => {
                const submitTool = config.tools.find((tool) => tool.name === SUBMIT_CANDIDATE_TOOL_NAME);
                submitResult = await submitTool.handler(validPayload("candidate-a"), {
                    sessionId: config.sessionId,
                    toolName: submitTool.name,
                });
            }, captured);
            const pool = createSdkWorkerPool({
                client,
                baseDirectory: path.join(root, "sdk"),
                workingDirectory: path.join(root, "work"),
                parentReader: reader,
            });
            await pool.propose({
                ...request("candidate-a"),
                parents: [{ parentId: "ev-parent", snapshotId: SNAPSHOT_A }],
            });
            const config = captured.configs[0];
            expect(config.availableTools).toEqual([
                `custom:${SUBMIT_CANDIDATE_TOOL_NAME}`,
                `custom:${READ_PARENT_ARTIFACT_TOOL_NAME}`,
            ]);
            // No built-in tools of any kind: every advertised tool is a custom:*.
            expect(config.availableTools.every((name) => name.startsWith("custom:"))).toBe(true);
            expect(submitResult.textResultForLlm).toContain("No verdict was produced");
            await pool.close();
        });
    });

    it("dynamically builds an empty-mode stdio SDK client", async () => {
        const root = makeRoot("dynamic");
        const captured = { clientOptions: null, stdio: null, configs: [], disconnected: 0 };
        class FakeClient {
            constructor(options) {
                captured.clientOptions = options;
            }
            async start() {}
            async stop() {}
            async createSession(config) {
                captured.configs.push(config);
                return {
                    async sendAndWait() {
                        await config.tools[0].handler(validPayload("candidate-a"), {
                            sessionId: config.sessionId,
                            toolCallId: "call",
                            toolName: config.tools[0].name,
                        });
                    },
                    async disconnect() {},
                };
            }
        }
        const pool = createSdkWorkerPool({
            sdkPath: path.join(root, "sdk-package"),
            cliPath: path.join(root, "copilot.exe"),
            baseDirectory: path.join(root, "home"),
            workingDirectory: path.join(root, "work"),
            sdkLoader: async () => ({
                CopilotClient: FakeClient,
                RuntimeConnection: {
                    forStdio(options) {
                        captured.stdio = options;
                        return { kind: "stdio", ...options };
                    },
                },
            }),
        });
        await pool.propose(request());
        expect(captured.stdio).toEqual({ path: path.join(root, "copilot.exe") });
        expect(captured.clientOptions).toMatchObject({
            mode: "empty",
            baseDirectory: path.join(root, "home"),
            workingDirectory: path.join(root, "work"),
        });
        await pool.close();
    });

    it("shares startup across concurrent proposals and publishes the client only after start succeeds", async () => {
        const root = makeRoot("concurrent-start");
        let releaseStart;
        let started = false;
        let createSessionCalls = 0;
        const startGate = new Promise((resolve) => { releaseStart = resolve; });
        const client = {
            async start() {
                await startGate;
                started = true;
            },
            async stop() {},
            async createSession(config) {
                createSessionCalls += 1;
                if (!started) throw new Error("client was published before start completed");
                return {
                    async sendAndWait() {
                        const candidateId = config.sessionId === "session-a"
                            ? "candidate-a"
                            : "candidate-b";
                        await config.tools[0].handler(validPayload(candidateId), {
                            sessionId: config.sessionId,
                            toolCallId: `call-${candidateId}`,
                            toolName: config.tools[0].name,
                        });
                    },
                    async disconnect() {},
                };
            },
        };
        const pool = createSdkWorkerPool({
            client,
            baseDirectory: path.join(root, "sdk"),
            workingDirectory: path.join(root, "work"),
        });
        const first = pool.propose(request("candidate-a"));
        const second = pool.propose({
            ...request("candidate-b"),
            sessionId: "session-b",
        });
        await Promise.resolve();
        expect(createSessionCalls).toBe(0);
        releaseStart();
        const proposals = await Promise.all([first, second]);
        expect(proposals.map((proposal) => proposal.candidateId).sort())
            .toEqual(["candidate-a", "candidate-b"]);
        expect(createSessionCalls).toBe(2);
        await pool.close();
    });

    it("shares one typed startup failure across concurrent proposals", async () => {
        const root = makeRoot("concurrent-failure");
        let releaseStart;
        const startGate = new Promise((resolve) => { releaseStart = resolve; });
        const client = {
            async start() {
                await startGate;
                throw new Error("startup exploded");
            },
            async stop() {},
            async createSession() {
                throw new Error("must not create a session");
            },
        };
        const pool = createSdkWorkerPool({
            client,
            baseDirectory: path.join(root, "sdk"),
            workingDirectory: path.join(root, "work"),
        });
        const first = pool.propose(request("candidate-a"));
        const second = pool.propose({
            ...request("candidate-b"),
            sessionId: "session-b",
        });
        releaseStart();
        const settled = await Promise.allSettled([first, second]);
        expect(settled.every((item) => item.status === "rejected")).toBe(true);
        const errors = settled.map((item) => item.reason);
        expect(errors[0]).toBe(errors[1]);
        expect(errors[0]).toMatchObject({
            code: RUNTIME_ERROR_CODES.WORKER_STARTUP,
        });
        await pool.close();
    });
});
