import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function fail(message) {
    process.stderr.write(`[crucible integration] ${message}\n`);
    process.stderr.write(
        "[crucible integration] Set COPILOT_SDK_PATH and COPILOT_CLI_PATH to absolute installed paths, and authenticate the Copilot CLI before running this release gate.\n",
    );
    process.exitCode = 1;
}

const sdkPath = process.env.COPILOT_SDK_PATH;
const cliPath = process.env.COPILOT_CLI_PATH;
const problems = [];

if (typeof sdkPath !== "string" || !path.isAbsolute(sdkPath)) {
    problems.push("COPILOT_SDK_PATH is missing or not absolute");
} else if (!fs.existsSync(path.join(sdkPath, "index.js"))) {
    problems.push("COPILOT_SDK_PATH does not contain index.js");
}
if (typeof cliPath !== "string" || !path.isAbsolute(cliPath)) {
    problems.push("COPILOT_CLI_PATH is missing or not absolute");
} else if (!fs.existsSync(cliPath) || !fs.statSync(cliPath).isFile()) {
    problems.push("COPILOT_CLI_PATH does not name an installed CLI executable");
}

if (problems.length > 0) {
    fail(problems.join("; "));
} else {
    const root = fileURLToPath(new URL("..", import.meta.url));
    const vitest = fileURLToPath(
        new URL("../node_modules/vitest/vitest.mjs", import.meta.url),
    );
    const config = fileURLToPath(
        new URL("../vitest.crucible-integration.config.mjs", import.meta.url),
    );
    const result = spawnSync(
        process.execPath,
        [vitest, "run", "--config", config],
        {
            cwd: root,
            env: {
                ...process.env,
                CRUCIBLE_REAL_SDK_SMOKE: "1",
            },
            stdio: "inherit",
            windowsHide: true,
        },
    );

    if (result.error) {
        fail(`failed to start the real SDK/CLI smoke: ${result.error.message}`);
    } else if (result.status !== 0) {
        fail(
            `real SDK/CLI smoke failed with exit ${result.status ?? "unknown"}; verify CLI authentication and SDK/CLI compatibility`,
        );
    } else {
        process.exitCode = 0;
    }
}
