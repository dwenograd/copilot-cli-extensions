import {
    spawn as rawSpawn,
} from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
    afterEach,
    describe,
    expect,
    it,
} from "vitest";

import { createDefaultProcessAdapter } from "../measurement/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.windows-adapter-${label}-`));
    roots.push(root);
    return root;
}

function pidAlive(pid) {
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

async function waitFor(predicate, timeoutMs = 10_000) {
    const deadline = Date.now() + timeoutMs;
    while (!predicate() && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return predicate();
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 100,
            retryDelay: 25,
        });
    }
});

describe("Windows process adapter termination", () => {
    it("bounds a hung taskkill process", async () => {
        const calls = [];
        const killer = new EventEmitter();
        killer.kill = () => {
            calls.push("killer-kill");
            return true;
        };
        const adapter = createDefaultProcessAdapter({
            platform: "win32",
            terminationTimeoutMs: 10,
            spawnProcess(executable, argv, options) {
                calls.push({ executable, argv, options });
                return killer;
            },
        });
        const started = Date.now();
        await expect(adapter.terminateTree(4242, {
            force: false,
            timeoutMs: 10,
        })).resolves.toBe(false);
        expect(Date.now() - started).toBeLessThan(500);
        expect(calls[0].argv).toEqual(["/T", "/PID", "4242"]);
        expect(calls).toContain("killer-kill");
    });

    it("uses forced exact-PID tree termination for escalation", async () => {
        let invocation = null;
        const killer = new EventEmitter();
        killer.kill = () => true;
        const adapter = createDefaultProcessAdapter({
            platform: "win32",
            spawnProcess(executable, argv, options) {
                invocation = { executable, argv, options };
                setImmediate(() => killer.emit("close", 0));
                return killer;
            },
        });
        await expect(adapter.terminateTree(5252, {
            force: true,
            timeoutMs: 100,
        })).resolves.toBe(true);
        expect(invocation.argv).toEqual(["/F", "/T", "/PID", "5252"]);
        expect(invocation.options).toMatchObject({
            shell: false,
            windowsHide: true,
            detached: false,
        });
    });

    it.runIf(process.platform === "win32")(
        "closes the Job Object when the owning parent process crashes",
        async () => {
            const root = makeRoot("parent-death");
            const candidatePidPath = path.join(root, "candidate.pid");
            const ownerPidPath = path.join(root, "owner.pid");
            const harnessPath = path.join(root, "linger.mjs");
            const parentPath = path.join(root, "parent.mjs");
            fs.writeFileSync(harnessPath, `
                import fs from "node:fs";
                fs.writeFileSync(${JSON.stringify(candidatePidPath)}, String(process.pid));
                setInterval(() => {}, 1000);
            `);
            const adapterUrl = pathToFileURL(
                path.join(
                    HERE,
                    "..",
                    "measurement",
                    "windows-adapter.mjs",
                ),
            ).href;
            fs.writeFileSync(parentPath, `
                import fs from "node:fs";
                import { createDefaultProcessAdapter } from ${JSON.stringify(adapterUrl)};
                const adapter = createDefaultProcessAdapter();
                const child = adapter.spawn(
                    process.execPath,
                    [${JSON.stringify(harnessPath)}],
                    {
                        cwd: ${JSON.stringify(root)},
                        env: { SystemRoot: process.env.SystemRoot },
                        stdio: ["ignore", "pipe", "pipe"],
                        executesCandidateCode: false,
                        launchPath: "host-process-adapter",
                        timeoutMs: 60_000,
                        ownerRoot: ${JSON.stringify(root)},
                    },
                );
                fs.writeFileSync(${JSON.stringify(ownerPidPath)}, String(child.pid));
                child.on("error", () => {});
                setInterval(() => {}, 1000);
            `);

            const parent = rawSpawn(process.execPath, [parentPath], {
                cwd: root,
                stdio: "ignore",
                shell: false,
                windowsHide: true,
            });
            let candidatePid = null;
            let ownerPid = null;
            try {
                expect(await waitFor(() =>
                    fs.existsSync(candidatePidPath)
                    && fs.existsSync(ownerPidPath))).toBe(true);
                candidatePid = Number(fs.readFileSync(candidatePidPath, "utf8"));
                ownerPid = Number(fs.readFileSync(ownerPidPath, "utf8"));
                expect(pidAlive(candidatePid)).toBe(true);
                expect(pidAlive(ownerPid)).toBe(true);

                parent.kill("SIGKILL");
                await new Promise((resolve) => parent.once("close", resolve));
                expect(await waitFor(() =>
                    !pidAlive(candidatePid) && !pidAlive(ownerPid))).toBe(true);
            } finally {
                for (const pid of [candidatePid, ownerPid, parent.pid]) {
                    if (!Number.isSafeInteger(pid) || pid < 1) continue;
                    try { process.kill(pid, "SIGKILL"); } catch {}
                }
            }
        },
        30_000,
    );
});
