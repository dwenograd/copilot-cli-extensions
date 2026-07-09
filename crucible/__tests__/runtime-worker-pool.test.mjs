import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    RUNTIME_ERROR_CODES,
    SUBMIT_CANDIDATE_TOOL_NAME,
    createSdkWorkerPool,
    validateCandidateSubmission,
} from "../runtime/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-worker-${label}-`));
    roots.push(root);
    return root;
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function validPayload(candidateId, challenge = "challenge-1") {
    return {
        challenge,
        candidateId,
        mechanism: "Write a deterministic score fixture.",
        files: [{ path: "score.txt", content: "95\n" }],
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
                        await tool.handler(validPayload(config.__candidateId ?? "candidate-a"), {
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

describe("Oracle v3 SDK worker pool", () => {
    it("uses one non-deferred custom tool and code-stamps worker identity", async () => {
        const { pool, captured } = await makePool("valid");
        const proposal = await pool.propose(request());

        expect(proposal.candidateId).toBe("candidate-a");
        expect(proposal.identity).toMatchObject({
            invocationSessionId: "session-a",
            configuredModel: "gpt-test",
            challengeNonce: "challenge-1",
        });
        expect(proposal.identity.promptHash).toMatch(
            /^sha256:oracle-runtime-worker-prompt-v1:[a-f0-9]{64}$/,
        );
        expect(proposal.identity.payloadHash).toMatch(
            /^sha256:oracle-runtime-candidate-payload-v1:[a-f0-9]{64}$/,
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
