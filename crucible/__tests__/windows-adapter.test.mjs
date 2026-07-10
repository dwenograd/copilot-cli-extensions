import { EventEmitter } from "node:events";

import { describe, expect, it } from "vitest";

import { createDefaultProcessAdapter } from "../measurement/index.mjs";

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
});
