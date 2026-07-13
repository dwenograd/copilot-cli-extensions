import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    MAX_TRUSTED_OPERATOR_CONTEXT_BYTES,
    RUNTIME_ERROR_CODES,
    normalizeRunnerConfig,
} from "../runtime/index.mjs";
import { mainRunnerCli } from "../runtime/runner-cli.mjs";
import { mainSupervisorCli } from "../runtime/supervisor-cli.mjs";
import {
    normalizeRunnerOutcomeEnvelope,
    projectRunnerOutcome,
} from "../runtime/outcome.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

describe("Crucible strict runtime CLIs", () => {
    it("rejects anything other than --config with an absolute JSON path", async () => {
        const runner = await mainRunnerCli(["--command", "node evil.js"], {
            stderr: { write() {} },
        });
        expect(runner.exitCode).toBe(64);
        expect(runner.envelope.non_result_code).toBe(RUNTIME_ERROR_CODES.INVALID_CONFIG);

        const supervisor = await mainSupervisorCli(["relative.json"], {
            stderr: { write() {} },
        });
        expect(supervisor.exitCode).toBe(64);
        expect(supervisor.envelope.non_result_code).toBe(RUNTIME_ERROR_CODES.INVALID_CONFIG);
    });

    it.each([
        ["runner", path.join(HERE, "..", "runtime", "runner-cli.mjs")],
        ["supervisor", path.join(HERE, "..", "runtime", "supervisor-cli.mjs")],
    ])("uses exit 64 for invalid %s config in a spawned CLI", (_name, cliPath) => {
        const result = spawnSync(
            process.execPath,
            [cliPath, "--config", "relative.json"],
            {
                encoding: "utf8",
                shell: false,
                windowsHide: true,
            },
        );
        expect(result.status).toBe(64);
        expect(result.stdout).toBe("");
        expect(JSON.parse(result.stderr.trim())).toMatchObject({
            ok: false,
            state: "failed",
            non_result_code: RUNTIME_ERROR_CODES.INVALID_CONFIG,
        });
    });

    it("rejects unknown config fields and result paths outside stateDir", () => {
        const root = path.resolve("C:\\crucible-runtime-config-test");
        const base = {
            investigationId: "inv",
            stateDir: path.join(root, "state"),
            artifactRoot: path.join(root, "artifacts"),
            allowlistPath: path.join(root, "allowlist.json"),
            copilotSdkPath: path.join(root, "sdk"),
            copilotCliPath: path.join(root, "copilot.exe"),
            runnerEpochId: "runner",
        };
        expect(normalizeRunnerConfig(base).options.shutdownTimeoutMs).toBe(30_000);
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
        expect(() => normalizeRunnerConfig({
            ...base,
            options: {
                workerAdditionalContext:
                    "😀".repeat(MAX_TRUSTED_OPERATOR_CONTEXT_BYTES / 2),
            },
        })).toThrow(expect.objectContaining({
            code: RUNTIME_ERROR_CODES.INVALID_CONFIG,
        }));
    });

    it("keeps runner quiescence opaque until the supervisor persists pause", () => {
        const envelope = projectRunnerOutcome({
            kind: "QUIESCED",
            code: "INVESTIGATION_PAUSED",
        });
        expect(envelope).toEqual({
            version: 1,
            ok: true,
            state: "quiesced",
            terminal_available: false,
            non_result_code: "INVESTIGATION_PAUSED",
        });
        expect(normalizeRunnerOutcomeEnvelope(envelope)).toEqual(envelope);
    });

    it("preserves supervisor generation and runner incarnation through the CLI", async () => {
        const root = fs.mkdtempSync(
            path.join(HERE, ".runtime-cli-authority-"),
        );
        try {
            const configPath = path.join(root, "runner.json");
            fs.writeFileSync(configPath, JSON.stringify({
                investigationId: "inv",
                stateDir: path.join(root, "state"),
                artifactRoot: path.join(root, "artifacts"),
                allowlistPath: path.join(root, "allowlist.json"),
                copilotSdkPath: path.join(root, "sdk"),
                copilotCliPath: path.join(root, "copilot.exe"),
                runnerEpochId: "runner",
                supervisorGeneration: 7,
                supervisorNonce: "supervisor-nonce",
                runnerIncarnation: "runner-incarnation",
            }));
            let captured = null;
            const outcome = await mainRunnerCli(
                ["--config", configPath],
                {
                    stdout: { write() {} },
                    stderr: { write() {} },
                    runnerFactory(config) {
                        captured = config;
                        return {
                            async run() {
                                return {
                                    kind: "NON_RESULT",
                                    code: "TEST_COMPLETE",
                                };
                            },
                        };
                    },
                },
            );
            expect(outcome.exitCode).toBe(0);
            expect(captured).toMatchObject({
                supervisorGeneration: 7,
                supervisorNonce: "supervisor-nonce",
                runnerIncarnation: "runner-incarnation",
            });
        } finally {
            fs.rmSync(root, { recursive: true, force: true });
        }
    });
});
