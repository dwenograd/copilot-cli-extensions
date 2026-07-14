import path from "node:path";

import { describe, expect, it } from "vitest";

import {
    mainRecoveryDaemonCli,
    parseRecoveryDaemonArgv,
} from "../runtime/recovery-daemon-cli.mjs";

describe("recovery daemon CLI", () => {
    it("supports an explicit manual one-shot without installed hashes", () => {
        const parsed = parseRecoveryDaemonArgv([
            "--once",
            "--state-root",
            path.resolve("manual-recovery-state"),
        ]);
        expect(parsed).toMatchObject({
            once: true,
            expectedNodeSha256: null,
            expectedDaemonSha256: null,
        });
    });

    it("requires installed executable hashes for continuous mode", () => {
        expect(() => parseRecoveryDaemonArgv([
            "--state-root",
            path.resolve("continuous-recovery-state"),
        ])).toThrow(/requires expected Node and daemon hashes/u);
    });

    it("prints only an aggregate one-shot summary", async () => {
        let output = "";
        const result = await mainRecoveryDaemonCli([
            "--once",
            "--state-root",
            path.resolve("manual-recovery-state"),
        ], {
            stdout: {
                write(value) {
                    output += value;
                },
            },
            runRecoveryDaemon: async () => ({
                state: "one_shot_complete",
                code: null,
                cycles: 1,
                scanned: 1,
                operations: [{
                    investigationId: "private-investigation",
                    state: "started",
                    code: "SUPERVISOR_STARTED",
                    decision: "VERIFIED_RESULT",
                }],
            }),
        });
        expect(result.exitCode).toBe(0);
        expect(JSON.parse(output)).toMatchObject({
            state: "one_shot_complete",
            counts: { started: 1 },
        });
        expect(output).not.toContain("private-investigation");
        expect(output).not.toContain("VERIFIED_RESULT");
    });
});
