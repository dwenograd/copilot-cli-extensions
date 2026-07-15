import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
);
const VITEST = path.join(ROOT, "node_modules", "vitest", "vitest.mjs");
const MAX_RUNTIME_MS = 55_000;
const IGNORED_ROOT_ENTRIES = new Set([".git", "node_modules"]);
const TEST_FILES = Object.freeze([
    "crucible/__tests__/api-handlers.test.mjs",
    "crucible/__tests__/api-lifecycle.test.mjs",
    "crucible/__tests__/api-schema.test.mjs",
    "crucible/__tests__/domain-archive-strategy.test.mjs",
    "crucible/__tests__/domain-canonical.test.mjs",
    "crucible/__tests__/domain-cohort.test.mjs",
    "crucible/__tests__/domain-confirmation-protocol.test.mjs",
    "crucible/__tests__/domain-enumerands.test.mjs",
    "crucible/__tests__/domain-hypotheses.test.mjs",
    "crucible/__tests__/domain-kernel.test.mjs",
    "crucible/__tests__/domain-statistics.test.mjs",
    "crucible/__tests__/domain-working-set-policy.test.mjs",
    "crucible/__tests__/measurement-harness-suite.test.mjs",
    "crucible/__tests__/measurement-parser.test.mjs",
    "crucible/__tests__/measurement-verifier-parser.test.mjs",
    "crucible/__tests__/persistence-recovery-catalog.test.mjs",
    "crucible/__tests__/persistence-retention.test.mjs",
    "crucible/__tests__/runtime-discovery.test.mjs",
    "crucible/__tests__/runtime-identity.test.mjs",
    "crucible/__tests__/runtime-prediction-feedback.test.mjs",
    "crucible/__tests__/runtime-process-identity.test.mjs",
    "crucible/__tests__/runtime-recovery-cli.test.mjs",
    "crucible/__tests__/runtime-recovery-daemon.test.mjs",
    "crucible/__tests__/runtime-resource-broker.test.mjs",
    "crucible/__tests__/runtime-sdk-availability.test.mjs",
    "crucible/__tests__/stat-contract.test.mjs",
]);

function repositoryPaths() {
    const paths = new Set();
    const stack = [ROOT];
    while (stack.length > 0) {
        const current = stack.pop();
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            if (current === ROOT && IGNORED_ROOT_ENTRIES.has(entry.name)) {
                continue;
            }
            const absolute = path.join(current, entry.name);
            const relative = path.relative(ROOT, absolute).replaceAll("\\", "/");
            paths.add(relative);
            if (entry.isDirectory() && !entry.isSymbolicLink()) {
                stack.push(absolute);
            }
        }
    }
    return paths;
}

const extraArgs = process.argv.slice(2);

const before = repositoryPaths();
const result = spawnSync(
    process.execPath,
    [
        VITEST,
        "run",
        ...TEST_FILES,
        "--testTimeout=10000",
        "--hookTimeout=10000",
        ...extraArgs,
    ],
    {
        cwd: ROOT,
        env: process.env,
        stdio: "inherit",
        timeout: MAX_RUNTIME_MS,
        windowsHide: true,
    },
);
const leakedPaths = [...repositoryPaths()]
    .filter((entry) => !before.has(entry))
    .sort();

if (leakedPaths.length > 0) {
    console.error("Crucible tests leaked repository paths:");
    for (const entry of leakedPaths) console.error(`- ${entry}`);
    process.exitCode = 1;
} else if (result.error?.code === "ETIMEDOUT") {
    console.error(
        `Crucible fast tests exceeded ${MAX_RUNTIME_MS / 1000} seconds`,
    );
    process.exitCode = 124;
} else if (result.error) {
    throw result.error;
} else {
    process.exitCode = result.status ?? 1;
}
