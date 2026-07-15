import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    normalizeSupervisorConfig,
    readStatus,
    runSupervisor,
} from "../runtime/index.mjs";
import { removeTrackedRoots } from "./test-cleanup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(
    HERE,
    "fixtures",
    "supervisor-kill-worker.mjs",
);
const roots = [];
const children = [];

function rawConfig(root) {
    return {
        runner: {
            investigationId: "unattended-supervisor-kill",
            stateDir: path.join(root, "state"),
            artifactRoot: path.join(root, "artifacts"),
            allowlistPath: path.join(root, "allowlist.json"),
            copilotSdkPath: path.join(root, "sdk"),
            copilotCliPath: path.join(root, "copilot.exe"),
            runnerEpochId: "unattended-runner-epoch",
            deadline: Date.now() + 5 * 60_000,
        },
        maxRestarts: 2,
        baseBackoffMs: 10,
        maxBackoffMs: 100,
        heartbeatIntervalMs: 100,
        staleLockMs: 2_000,
        circuitWindowMs: 10_000,
    };
}

function waitForLine(child, timeoutMs = 20_000) {
    return new Promise((resolve, reject) => {
        let stdout = "";
        let stderr = "";
        const timer = setTimeout(() => {
            reject(new Error(
                `supervisor fixture timed out; stdout=${stdout}; stderr=${stderr}`,
            ));
        }, timeoutMs);
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (chunk) => {
            stdout += chunk;
            const newline = stdout.indexOf("\n");
            if (newline === -1) return;
            clearTimeout(timer);
            resolve(JSON.parse(stdout.slice(0, newline)));
        });
        child.stderr.on("data", (chunk) => {
            stderr += chunk;
        });
        child.once("error", (error) => {
            clearTimeout(timer);
            reject(error);
        });
        child.once("exit", (code, signal) => {
            clearTimeout(timer);
            reject(new Error(
                `supervisor fixture exited before boundary: code=${code}; signal=${signal}; stderr=${stderr}`,
            ));
        });
    });
}

function waitForExit(child, timeoutMs = 10_000) {
    if (child.exitCode !== null || child.signalCode !== null) {
        return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error("supervisor fixture did not exit"));
        }, timeoutMs);
        child.once("close", () => {
            clearTimeout(timer);
            resolve();
        });
    });
}

function completedRunner(nonResultCode) {
    return async (config) => {
        const child = new EventEmitter();
        child.pid = process.pid + 200_000;
        setImmediate(() => {
            fs.writeFileSync(
                config.paths.childResultPath,
                `${JSON.stringify({
                    version: 1,
                    ok: true,
                    state: "non_result",
                    terminal_available: false,
                    non_result_code: nonResultCode,
                })}\n`,
            );
            child.emit("close", 0, null);
        });
        return {
            child,
            resultPath: config.paths.childResultPath,
        };
    };
}

afterEach(async () => {
    for (const child of children.splice(0)) {
        if (child.exitCode === null && child.signalCode === null) {
            child.kill("SIGKILL");
            await waitForExit(child).catch(() => {});
        }
    }
    await removeTrackedRoots(roots, {
        label: "v4 unattended gate root",
    });
});

describe("v4 unattended release gate", () => {
    it("recovers exactly once after supervisor death at the running boundary", async () => {
        const root = fs.mkdtempSync(
            path.join(HERE, ".v4-unattended-supervisor-"),
        );
        roots.push(root);
        const raw = rawConfig(root);
        const configFile = path.join(root, "supervisor-config.json");
        fs.writeFileSync(configFile, `${JSON.stringify(raw)}\n`);

        const child = spawn(process.execPath, [FIXTURE, configFile], {
            cwd: root,
            windowsHide: true,
            stdio: ["ignore", "pipe", "pipe"],
        });
        children.push(child);
        await expect(waitForLine(child)).resolves.toMatchObject({
            ready: true,
            supervisorGeneration: 1,
        });
        expect(child.kill("SIGKILL")).toBe(true);
        await waitForExit(child);
        await new Promise((resolve) =>
            setTimeout(resolve, raw.staleLockMs + 100));

        let replacementLaunches = 0;
        const recovered = await runSupervisor(
            normalizeSupervisorConfig(raw),
            {
                pid: process.pid,
                idFactory: () => "replacement-supervisor",
                isPidAlive: () => false,
                runnerIncarnationFactory: () => "replacement-runner",
                processTreeAdapter: {
                    async close() {
                        return { verified: true, activePids: [] };
                    },
                },
                spawnRunner(config) {
                    replacementLaunches += 1;
                    return completedRunner("UNATTENDED_RECOVERED")(config);
                },
            },
        );
        expect(replacementLaunches).toBe(1);
        expect(recovered).toMatchObject({
            kind: "NON_RESULT",
            nonResultCode: "UNATTENDED_RECOVERED",
            status: {
                supervisorGeneration: 2,
                state: "non_result",
                childPid: null,
            },
        });
        expect(readStatus({
            stateDir: raw.runner.stateDir,
            investigationId: raw.runner.investigationId,
        })).toMatchObject({
            supervisorGeneration: 2,
            state: "non_result",
        });
        expect(fs.existsSync(
            normalizeSupervisorConfig(raw).paths.lockPath,
        )).toBe(false);
    });
});
