import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
);
const VITEST = path.join(ROOT, "node_modules", "vitest", "vitest.mjs");
const CONFIG = path.join(ROOT, "vitest.crucible-unit.config.mjs");
const MAX_RUNTIME_MS = 55_000;

const extraArgs = process.argv.slice(2);
if (extraArgs.some((arg) => arg === "--config" || arg.startsWith("--config="))) {
    throw new TypeError("the fast Crucible suite config cannot be overridden");
}

const result = spawnSync(
    process.execPath,
    [VITEST, "run", "--config", CONFIG, ...extraArgs],
    {
        cwd: ROOT,
        env: process.env,
        stdio: "inherit",
        timeout: MAX_RUNTIME_MS,
        windowsHide: true,
    },
);

if (result.error?.code === "ETIMEDOUT") {
    console.error(
        `Crucible fast tests exceeded ${MAX_RUNTIME_MS / 1000} seconds`,
    );
    process.exitCode = 124;
} else if (result.error) {
    throw result.error;
} else {
    process.exitCode = result.status ?? 1;
}
