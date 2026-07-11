import fs from "node:fs";

import { openRepository } from "../../persistence/index.mjs";
import { createDomainRepositoryAdapter } from "../../runtime/index.mjs";

const inputPath = process.env.CRUCIBLE_FENCE_RACE_INPUT;
if (!inputPath) {
    throw new Error("CRUCIBLE_FENCE_RACE_INPUT is required");
}

const input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
const repository = openRepository({ file: input.databasePath });
const adapter = createDomainRepositoryAdapter({
    repository,
    investigationId: input.investigationId,
});

process.send?.({ type: "ready" });

await new Promise((resolve) => {
    process.once("message", (message) => {
        if (message?.type === "go") resolve();
    });
});

let result;
try {
    adapter.appendHarnessObservationFenced(input.observation, {
        attemptId: input.attemptId,
        command: input.command,
        lease: input.lease,
    });
    result = { type: "result", ok: true };
} catch (error) {
    result = {
        type: "result",
        ok: false,
        code: error?.code ?? null,
        message: error?.message ?? String(error),
    };
} finally {
    repository.close();
}

process.send?.(result);
