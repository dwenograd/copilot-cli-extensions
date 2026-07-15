import { describe, expect, it } from "vitest";

import {
    captureProcessIdentity,
    createProcessIdentityAdapter,
    parseWindowsCommandLine,
    readProcessIdentity,
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

    it("captures and later matches the exact Windows start, executable, and command identity", () => {
        const executablePath =
            "C:\\Program Files\\nodejs\\node.exe";
        const argv = [
            "C:\\Crucible\\runtime\\runner-cli.mjs",
            "--config",
            "C:\\State\\runner.json",
        ];
        const commandLine = [
            `"${executablePath}"`,
            ...argv.map((value) => `"${value}"`),
        ].join(" ");
        const outputs = [
            JSON.stringify({
                state: "ok",
                processStartId: "windows-start-ticks:100",
                executablePath,
                commandLine,
            }),
            JSON.stringify({
                state: "ok",
                processStartId: "windows-start-ticks:100",
                executablePath,
                commandLine,
            }),
            JSON.stringify({
                state: "ok",
                processStartId: "windows-start-ticks:100",
                executablePath,
                commandLine:
                    `${commandLine} --unexpected-reused-command`,
            }),
            JSON.stringify({
                state: "ok",
                processStartId: "windows-start-ticks:200",
                executablePath,
                commandLine,
            }),
        ];
        const dependencies = {
            platform: "win32",
            execFileSync: () => outputs.shift(),
        };
        const captured = captureProcessIdentity({
            processId: 77,
            executablePath,
            argv,
        }, dependencies);
        expect(captured).toMatchObject({
            version: 1,
            processId: 77,
            processStartId: "windows-start-ticks:100",
            executablePath,
            commandIdentity:
                expect.stringMatching(
                    /^sha256:crucible-process-command-v1:[a-f0-9]{64}$/u,
                ),
        });
        const adapter = createProcessIdentityAdapter(dependencies);
        expect(adapter.matches(captured)).toMatchObject({
            matched: true,
            active: true,
        });
        expect(adapter.matches(captured)).toMatchObject({
            matched: false,
            active: true,
            reason: "identity_mismatch",
        });
        expect(adapter.matches(captured)).toMatchObject({
            matched: false,
            active: true,
            reason: "identity_mismatch",
        });
    });

    it("parses the Windows quoting used by the runner command", () => {
        expect(parseWindowsCommandLine(
            "\"C:\\Program Files\\node.exe\" "
            + "\"C:\\runtime\\runner-cli.mjs\" --config "
            + "\"C:\\state\\runner config.json\"",
        )).toEqual([
            "C:\\Program Files\\node.exe",
            "C:\\runtime\\runner-cli.mjs",
            "--config",
            "C:\\state\\runner config.json",
        ]);
    });

    it("fails closed when full process command identity is unavailable", () => {
        expect(() => readProcessIdentity(88, {
            platform: "win32",
            execFileSync: () => JSON.stringify({
                state: "ok",
                processStartId: "windows-start-ticks:100",
                executablePath: "",
                commandLine: "",
            }),
        })).toThrow(/incomplete/u);
    });
});
