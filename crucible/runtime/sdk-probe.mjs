import { randomUUID } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";

const sdkPath = process.env.COPILOT_SDK_PATH;
if (!sdkPath) {
    throw new Error("COPILOT_SDK_PATH is required");
}

const cliPath = process.env.COPILOT_CLI_PATH;
if (!cliPath) {
    throw new Error("COPILOT_CLI_PATH is required");
}

const { CopilotClient, RuntimeConnection } = await import(pathToFileURL(path.join(sdkPath, "index.js")).href);

const client = new CopilotClient({
    connection: RuntimeConnection.forStdio({ path: cliPath }),
    mode: "empty",
    baseDirectory: process.env.CRUCIBLE_PROBE_HOME,
    workingDirectory: process.cwd(),
    logLevel: "error",
});

const identities = [];

try {
    await client.start();

    const workers = Array.from({ length: 3 }, async (_, index) => {
        const sessionId = randomUUID();
        const nonce = `sdk-worker-${index + 1}-${sessionId.slice(0, 8)}`;
        let observedIdentity = null;

        const session = await client.createSession({
            sessionId,
            clientName: "crucible-runtime-probe",
            model: "gpt-5.4-mini",
            reasoningEffort: "low",
            availableTools: ["custom:crucible_worker_identity"],
            skipCustomInstructions: true,
            tools: [{
                name: "crucible_worker_identity",
                description: "Return the code-stamped identity for this Crucible worker.",
                defer: "never",
                skipPermission: true,
                parameters: {
                    type: "object",
                    additionalProperties: false,
                    properties: {
                        nonce: { type: "string" },
                    },
                    required: ["nonce"],
                },
                handler: async (args, invocation) => {
                    observedIdentity = {
                        requestedSessionId: sessionId,
                        invocationSessionId: invocation.sessionId,
                        nonce: args.nonce,
                    };
                    return JSON.stringify(observedIdentity);
                },
            }],
        });

        const response = await session.sendAndWait({
            prompt: `Call crucible_worker_identity exactly once with nonce "${nonce}". Return only its JSON result.`,
        }, 60_000);

        await session.disconnect();

        return {
            ...observedIdentity,
            expectedNonce: nonce,
            response: response?.data?.content ?? null,
        };
    });

    identities.push(...await Promise.all(workers));
} finally {
    await client.stop();
}

const uniqueSessions = new Set(identities.map((item) => item.invocationSessionId));
const valid = identities.length === 3
    && identities.every((item) =>
        item.requestedSessionId === item.invocationSessionId
        && item.expectedNonce === item.nonce)
    && uniqueSessions.size === identities.length;

console.log(JSON.stringify({ valid, identities }, null, 2));
process.exitCode = valid ? 0 : 1;
