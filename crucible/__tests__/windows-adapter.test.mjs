import { EventEmitter } from "node:events";

import { describe, expect, it } from "vitest";

import {
    MEASUREMENT_ERROR_CODES,
    createDefaultProcessAdapter,
} from "../measurement/index.mjs";

describe("Windows process adapter termination protocol", () => {
    it("bounds a hung taskkill process and closes the fake child", async () => {
        const calls = [];
        const killer = new EventEmitter();
        killer.kill = () => {
            calls.push("killer-kill");
            setImmediate(() => killer.emit("close", null, "SIGKILL"));
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
        killer.kill = () => {
            setImmediate(() => killer.emit("close", null, "SIGKILL"));
            return true;
        };
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

    it("reports sorted immutable owned Job Object PIDs", async () => {
        const active = new Set([9003, 9001, 9002]);
        let closeOptions = null;
        const adapter = createDefaultProcessAdapter({
            platform: "win32",
            jobProcessAdapter: {
                owns: (pid) => active.has(pid),
                activePids: () => [
                    ...active,
                    ...(active.has(9002) ? [9002] : []),
                ],
                spawn() {
                    throw new Error("spawn is not part of this protocol test");
                },
                terminate() {
                    return false;
                },
                async close(options) {
                    closeOptions = options;
                    active.clear();
                    return true;
                },
            },
        });

        const pids = adapter.activeOwnedPids();
        expect(pids).toEqual([9001, 9002, 9003]);
        expect(Object.isFrozen(pids)).toBe(true);
        await expect(adapter.close({ timeoutMs: 321 })).resolves.toBe(true);
        expect(closeOptions.timeoutMs).toBe(321);
        expect(adapter.activeOwnedPids()).toEqual([]);
    });

    it("fails close when a Job adapter still reports an owned PID", async () => {
        const adapter = createDefaultProcessAdapter({
            platform: "win32",
            jobProcessAdapter: {
                owns: () => false,
                activePids: () => [7777],
                spawn() {
                    throw new Error("spawn is not part of this protocol test");
                },
                terminate() {
                    return false;
                },
                close() {
                    return true;
                },
            },
        });

        await expect(adapter.close({ timeoutMs: 20 })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
            details: { activePids: [7777] },
        });
    });

    it("waits for an exact test-owned direct child to close", async () => {
        const adapter = createDefaultProcessAdapter({
            platform: "linux",
            terminationTimeoutMs: 5_000,
        });
        const child = adapter.spawn(
            process.execPath,
            ["-e", "setTimeout(() => {}, 60000)"],
            {
                cwd: process.cwd(),
                env: {
                    SystemRoot:
                        process.env.SystemRoot
                        ?? process.env.SYSTEMROOT
                        ?? "C:\\Windows",
                },
                stdio: ["ignore", "ignore", "ignore"],
                executesCandidateCode: false,
                launchPath: "host-process-adapter",
            },
        );
        let closeObserved = false;
        child.once("close", () => {
            closeObserved = true;
        });

        try {
            expect(adapter.activeOwnedPids()).toEqual([child.pid]);
            await expect(adapter.close({ timeoutMs: 5_000 }))
                .resolves.toBe(true);
            expect(closeObserved).toBe(true);
            expect(adapter.activeOwnedPids()).toEqual([]);
        } finally {
            try {
                process.kill(child.pid, "SIGKILL");
            } catch {
                // The expected close path already terminated the exact PID.
            }
        }
    }, 10_000);
});
