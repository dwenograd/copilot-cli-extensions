import fs from "node:fs";

import { hashCanonical } from "../../domain/index.mjs";
import {
    runAutonomousInvestigation,
    validateCandidateSubmission,
} from "../../runtime/index.mjs";

const configPath = process.env.CRUCIBLE_KILL_CONFIG_PATH;
const faultPoint = process.env.CRUCIBLE_KILL_FAULT_POINT;
const commandKind = process.env.CRUCIBLE_KILL_COMMAND_KIND || null;
const workerCallsPath = process.env.CRUCIBLE_KILL_WORKER_CALLS_PATH;

if (!configPath || !faultPoint || !workerCallsPath) {
    throw new Error("hard-kill worker requires config, fault point, and call-counter paths");
}

const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
let nextId = 0;
let reached = false;

const pool = {
    async propose(request) {
        fs.appendFileSync(workerCallsPath, "1\n");
        const candidate = validateCandidateSubmission({
            challenge: request.challengeNonce,
            candidateId: request.candidateId,
            annotations: {
                mechanism: "Hard-kill durability fixture candidate",
            },
            files: [{ path: "score.txt", content: "95\n" }],
        }, {
            challengeNonce: request.challengeNonce,
            allowedCandidateIds: request.allowedCandidateIds,
            visibleEvidenceIds: request.visibleEvidenceIds,
        });
        return {
            ...candidate,
            identity: {
                invocationSessionId: request.sessionId,
                configuredModel: request.model,
                challengeNonce: request.challengeNonce,
                promptHash: hashCanonical(
                    { prompt: request.prompt },
                    "sha256:crucible-runtime-worker-prompt-v1",
                ),
                contextHash: request.promptContextHash ?? null,
                annotationsHash: hashCanonical(
                    candidate.annotations,
                    "sha256:crucible-runtime-candidate-annotations-v1",
                ),
                payloadHash: hashCanonical(
                    candidate,
                    "sha256:crucible-runtime-candidate-payload-v1",
                ),
            },
        };
    },
    async close() {},
};

await runAutonomousInvestigation(config, {
    workerPool: pool,
    idFactory: () => `kill-worker-id-${++nextId}`,
    runtimeIdentityVerifier: async () => ({}),
    async faultInjector(point, details) {
        if (reached
            || point !== faultPoint
            || (commandKind !== null && details.command?.kind !== commandKind)) {
            return;
        }
        reached = true;
        process.send?.({
            type: "fault-boundary",
            point,
            commandKind: details.command?.kind ?? null,
        });
        await new Promise(() => {});
    },
});

process.send?.({ type: "completed-without-kill" });
