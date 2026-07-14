import { describe, expect, it } from "vitest";

import {
    createProcessIdentityAdapter,
    readProcessStartId,
} from "../runtime/index.mjs";

describe("exact process identity", () => {
    it("reads Windows process start ticks without a shell", () => {
        let invocation = null;
        const identity = readProcessStartId(42, {
            platform: "win32",
            execFileSync(file, args, options) {
                invocation = { file, args, options };
                return "windows-start-ticks:638880000000000000";
            },
        });
        expect(identity).toBe(
            "windows-start-ticks:638880000000000000",
        );
        expect(invocation).toMatchObject({
            file: "powershell.exe",
            options: {
                windowsHide: true,
                timeout: 5_000,
            },
        });
        expect(invocation.args).toContain("-NonInteractive");
        expect(invocation.args.at(-1)).toContain("Get-Process -Id 42");
    });

    it("distinguishes a missing or PID-reused owner", () => {
        const outputs = [
            "windows-start-ticks:100",
            "windows-start-ticks:100",
            "windows-start-ticks:200",
            "missing",
        ];
        const adapter = createProcessIdentityAdapter({
            platform: "win32",
            execFileSync: () => outputs.shift(),
        });
        expect(adapter.current(7)).toBe("windows-start-ticks:100");
        expect(adapter.isAlive({
            processId: 7,
            processStartId: "windows-start-ticks:100",
        })).toBe(true);
        expect(adapter.isAlive({
            processId: 7,
            processStartId: "windows-start-ticks:100",
        })).toBe(false);
        expect(adapter.isAlive({
            processId: 7,
            processStartId: "windows-start-ticks:100",
        })).toBe(false);
    });
});
