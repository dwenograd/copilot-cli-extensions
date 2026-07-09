import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadRunnerConfig } from "./config.mjs";
import {
    RUNTIME_ERROR_CODES,
    isRecoverableRuntimeError,
    serializeRuntimeError,
} from "./errors.mjs";
import { AutonomousRunner } from "./runner.mjs";
import {
    atomicWriteJson,
    parseConfigArgv,
} from "./utils.mjs";

export async function mainRunnerCli(argv = process.argv.slice(2), dependencies = {}) {
    let config = null;
    try {
        const configPath = parseConfigArgv(argv, "runner-cli.mjs");
        config = loadRunnerConfig(configPath, { env: dependencies.env ?? process.env });
        const runner = new AutonomousRunner({
            investigationId: config.investigationId,
            stateDir: config.stateDir,
            artifactRoot: config.artifactRoot,
            allowlistPath: config.allowlistPath,
            copilotSdkPath: config.sdkPath,
            copilotCliPath: config.cliPath,
            runnerEpochId: config.runnerEpochId,
            deadline: config.deadlineMs,
            resultPath: config.resultPath,
            options: config.options,
        }, dependencies);
        const result = await runner.run();
        const envelope = { ok: true, result };
        if (config.resultPath !== null) {
            atomicWriteJson(config.resultPath, envelope);
        }
        dependencies.stdout?.write?.(`${JSON.stringify(envelope)}\n`);
        return { exitCode: 0, envelope };
    } catch (error) {
        const serialized = serializeRuntimeError(error);
        const envelope = { ok: false, error: serialized };
        if (config?.resultPath !== null && config?.resultPath !== undefined) {
            try {
                atomicWriteJson(config.resultPath, envelope);
            } catch {
                // Preserve the original failure as the process verdict.
            }
        }
        dependencies.stderr?.write?.(`${JSON.stringify(envelope)}\n`);
        const exitCode = error?.code === RUNTIME_ERROR_CODES.INVALID_CONFIG
            ? 64
            : error?.code === RUNTIME_ERROR_CODES.INTEGRITY_FAILURE
                ? 65
                : isRecoverableRuntimeError(error)
                    ? 75
                    : 1;
        return { exitCode, envelope };
    }
}

const isEntrypoint = process.argv[1] !== undefined
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
    const { exitCode } = await mainRunnerCli(process.argv.slice(2), {
        stdout: process.stdout,
        stderr: process.stderr,
    });
    process.exitCode = exitCode;
}
