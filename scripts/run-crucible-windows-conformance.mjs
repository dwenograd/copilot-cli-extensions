import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const unavailableCode = "CRUCIBLE_MEASURE_SANDBOX_UNAVAILABLE";

if (process.platform !== "win32") {
    process.stderr.write(`${JSON.stringify({
        ok: false,
        code: unavailableCode,
        reason: `Windows native conformance is unavailable on ${process.platform}`,
    })}\n`);
    process.exitCode = 1;
} else {
    const vitest = fileURLToPath(
        new URL("../node_modules/vitest/vitest.mjs", import.meta.url),
    );
    const config = fileURLToPath(
        new URL("../vitest.windows-conformance.config.mjs", import.meta.url),
    );
    const result = spawnSync(
        process.execPath,
        [vitest, "run", "--config", config],
        {
            cwd: fileURLToPath(new URL("..", import.meta.url)),
            env: {
                ...process.env,
                CRUCIBLE_WINDOWS_CONFORMANCE: "1",
            },
            stdio: "inherit",
            windowsHide: true,
        },
    );

    if (result.error) {
        process.stderr.write(
            `failed to start Windows conformance: ${result.error.message}\n`,
        );
        process.exitCode = 1;
    } else {
        process.exitCode = result.status ?? 1;
    }
}
