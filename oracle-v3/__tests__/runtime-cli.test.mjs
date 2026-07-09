import { describe, expect, it } from "vitest";
import path from "node:path";

import {
    RUNTIME_ERROR_CODES,
    normalizeRunnerConfig,
} from "../runtime/index.mjs";
import { mainRunnerCli } from "../runtime/runner-cli.mjs";
import { mainSupervisorCli } from "../runtime/supervisor-cli.mjs";

describe("Oracle v3 strict runtime CLIs", () => {
    it("rejects anything other than --config with an absolute JSON path", async () => {
        const runner = await mainRunnerCli(["--command", "node evil.js"], {
            stderr: { write() {} },
        });
        expect(runner.exitCode).toBe(64);
        expect(runner.envelope.error.code).toBe(RUNTIME_ERROR_CODES.INVALID_CONFIG);

        const supervisor = await mainSupervisorCli(["relative.json"], {
            stderr: { write() {} },
        });
        expect(supervisor.exitCode).toBe(1);
        expect(supervisor.envelope.error.code).toBe(RUNTIME_ERROR_CODES.INVALID_CONFIG);
    });

    it("rejects unknown config fields and result paths outside stateDir", () => {
        const root = path.resolve("C:\\oracle-runtime-config-test");
        const base = {
            investigationId: "inv",
            stateDir: path.join(root, "state"),
            artifactRoot: path.join(root, "artifacts"),
            allowlistPath: path.join(root, "allowlist.json"),
            copilotSdkPath: path.join(root, "sdk"),
            copilotCliPath: path.join(root, "copilot.exe"),
            runnerEpochId: "runner",
        };
        expect(() => normalizeRunnerConfig({
            ...base,
            shellCommand: "node evil.js",
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.INVALID_CONFIG,
        }));
        expect(() => normalizeRunnerConfig({
            ...base,
            resultPath: path.join(root, "outside.json"),
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.PATH_ESCAPE,
        }));
    });
});
