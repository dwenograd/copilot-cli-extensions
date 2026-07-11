import { randomUUID } from "node:crypto";
import path from "node:path";

import { createSdkWorkerPool } from "./worker-pool.mjs";

const sdkPath = process.env.COPILOT_SDK_PATH;
if (!sdkPath) {
    throw new Error("COPILOT_SDK_PATH is required");
}

const cliPath = process.env.COPILOT_CLI_PATH;
if (!cliPath) {
    throw new Error("COPILOT_CLI_PATH is required");
}

const baseDirectory = process.env.CRUCIBLE_PROBE_HOME;
if (!baseDirectory || !path.isAbsolute(baseDirectory)) {
    throw new Error("CRUCIBLE_PROBE_HOME must be an absolute path");
}

const pool = createSdkWorkerPool({
    sdkPath,
    cliPath,
    baseDirectory,
    workingDirectory: process.cwd(),
    sessionTimeoutMs: 60_000,
    shutdownTimeoutMs: 30_000,
});

let proposals;
let closeDurationMs = null;
try {
    proposals = await Promise.all(Array.from({ length: 3 }, async (_, index) => {
        const candidateId = `sdk-probe-candidate-${index + 1}`;
        const sessionId = randomUUID();
        const challengeNonce = `sdk-probe-${index + 1}-${sessionId.slice(0, 8)}`;
        return pool.propose({
            model: "gpt-5.4-mini",
            reasoningEffort: "low",
            sessionId,
            challengeNonce,
            allowedCandidateIds: [candidateId],
            visibleEvidenceIds: [],
            prompt: [
                "You are an SDK integration smoke worker.",
                `Call crucible_submit_candidate exactly once with challenge ${JSON.stringify(challengeNonce)}.`,
                `Use candidateId ${JSON.stringify(candidateId)}.`,
                `Set annotations.mechanism to ${JSON.stringify(`SDK smoke ${index + 1}`)}.`,
                `Submit one file named probe-${index + 1}.txt with content ${JSON.stringify(`probe-${index + 1}\n`)}.`,
                "Do not return a verdict or a prose-only answer.",
            ].join("\n"),
        });
    }));
} finally {
    const closeStartedAt = Date.now();
    await pool.close();
    closeDurationMs = Date.now() - closeStartedAt;
}

const uniqueSessions = new Set(
    proposals.map((proposal) => proposal.identity.invocationSessionId),
);
const valid = proposals.length === 3
    && proposals.every((proposal, index) =>
        proposal.candidateId === `sdk-probe-candidate-${index + 1}`
        && proposal.identity.configuredModel === "gpt-5.4-mini"
        && proposal.identity.contextHash === null
        && proposal.annotations.mechanism === `SDK smoke ${index + 1}`
        && proposal.files.length === 1
        && proposal.files[0].path === `probe-${index + 1}.txt`
        && proposal.files[0].content === `probe-${index + 1}\n`)
    && uniqueSessions.size === proposals.length;

console.log(JSON.stringify({ valid, closeDurationMs, proposals }, null, 2));
process.exitCode = valid ? 0 : 1;
