import { spawn, spawnSync } from "node:child_process";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TEST_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const FILE_TIMEOUT_MS = 60_000;
const TASKKILL_TIMEOUT_MS = 5_000;

let activeChild = null;

function durationMilliseconds(startedAt) {
    return Math.round(Number(process.hrtime.bigint() - startedAt) / 1_000_000);
}

function killProcessTree(child) {
    if (!child?.pid) return;

    if (process.platform === "win32") {
        const result = spawnSync(
            "taskkill",
            ["/PID", String(child.pid), "/T", "/F"],
            {
                stdio: "ignore",
                timeout: TASKKILL_TIMEOUT_MS,
                windowsHide: true,
            },
        );
        if (!result.error && result.status === 0) return;
    }

    try {
        child.kill("SIGKILL");
    } catch {
        // The process may have exited between the timeout and the kill attempt.
    }
}

function runTestFile(fileName) {
    return new Promise((resolve) => {
        const startedAt = process.hrtime.bigint();
        const filePath = path.join(TEST_DIRECTORY, fileName);
        let settled = false;
        let timedOut = false;

        console.log(`[RUN ] ${fileName}`);

        const child = spawn(process.execPath, ["--test", filePath], {
            cwd: path.dirname(TEST_DIRECTORY),
            stdio: ["ignore", "inherit", "inherit"],
            windowsHide: true,
        });
        activeChild = child;

        const finish = (status, detail = "") => {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            if (activeChild === child) activeChild = null;

            const duration = durationMilliseconds(startedAt);
            const suffix = detail ? `: ${detail}` : "";
            console.log(`[${status}] ${fileName} (${duration} ms)${suffix}`);
            resolve(status === "PASS");
        };

        const timeout = setTimeout(() => {
            timedOut = true;
            killProcessTree(child);
            child.unref();
            finish("TIMEOUT", `exceeded ${FILE_TIMEOUT_MS / 1000}s`);
        }, FILE_TIMEOUT_MS);

        child.once("error", (error) => {
            finish("FAIL", error.message);
        });
        child.once("close", (code, signal) => {
            if (timedOut) return;
            if (code === 0) {
                finish("PASS");
                return;
            }
            const detail = signal
                ? `terminated by ${signal}`
                : `exit code ${code ?? "unknown"}`;
            finish("FAIL", detail);
        });
    });
}

function stopActiveChildAndExit(signal) {
    killProcessTree(activeChild);
    process.exitCode = signal === "SIGINT" ? 130 : 143;
}

process.once("SIGINT", () => stopActiveChildAndExit("SIGINT"));
process.once("SIGTERM", () => stopActiveChildAndExit("SIGTERM"));

const testFiles = (await readdir(TEST_DIRECTORY, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && entry.name.endsWith(".test.mjs"))
    .map((entry) => entry.name)
    .sort((left, right) => left.localeCompare(right, "en"));

if (testFiles.length === 0) {
    console.error("No *.test.mjs files found.");
    process.exitCode = 1;
} else {
    for (const fileName of testFiles) {
        if (!await runTestFile(fileName)) {
            process.exitCode = 1;
            break;
        }
    }
}
