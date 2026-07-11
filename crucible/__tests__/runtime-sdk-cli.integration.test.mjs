import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
const enabled = process.env.CRUCIBLE_REAL_SDK_SMOKE === "1";

afterEach(() => {
    const failures = [];
    for (const root of roots.splice(0)) {
        try {
            fs.rmSync(root, {
                recursive: true,
                force: true,
                maxRetries: 20,
                retryDelay: 25,
            });
        } catch (error) {
            failures.push(error);
        }
        if (fs.existsSync(root)) {
            failures.push(new Error(`SDK smoke root survived cleanup: ${root}`));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "SDK smoke cleanup failed");
    }
});

describe.runIf(enabled)("Crucible real SDK/CLI integration", () => {
    it("runs three isolated SDK sessions through the installed CLI", () => {
        const sdkPath = process.env.COPILOT_SDK_PATH;
        const cliPath = process.env.COPILOT_CLI_PATH;
        expect(path.isAbsolute(sdkPath ?? "")).toBe(true);
        expect(path.isAbsolute(cliPath ?? "")).toBe(true);

        const root = fs.mkdtempSync(path.join(HERE, ".runtime-real-sdk-"));
        roots.push(root);
        const probePath = path.join(HERE, "..", "runtime", "sdk-probe.mjs");
        const result = spawnSync(process.execPath, [probePath], {
            cwd: root,
            encoding: "utf8",
            shell: false,
            windowsHide: true,
            timeout: 180_000,
            env: {
                ...process.env,
                COPILOT_SDK_PATH: sdkPath,
                COPILOT_CLI_PATH: cliPath,
                CRUCIBLE_PROBE_HOME: path.join(root, "sdk-home"),
            },
        });
        expect(result.error).toBeUndefined();
        expect(result.status, result.stderr).toBe(0);
        const output = JSON.parse(result.stdout);
        expect(output).toMatchObject({
            valid: true,
            closeDurationMs: expect.any(Number),
            proposals: [
                expect.objectContaining({
                    candidateId: "sdk-probe-candidate-1",
                    identity: expect.objectContaining({
                        invocationSessionId: expect.any(String),
                    }),
                }),
                expect.any(Object),
                expect.any(Object),
            ],
        });
        expect(output.closeDurationMs).toBeLessThan(30_000);
    }, 180_000);
});
