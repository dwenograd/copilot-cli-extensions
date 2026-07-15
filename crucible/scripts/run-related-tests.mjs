import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
);
const FAST_RUNNER = path.join(ROOT, "crucible", "scripts", "run-tests.mjs");

const result = spawnSync(process.execPath, [FAST_RUNNER], {
    cwd: ROOT,
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
});

if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
