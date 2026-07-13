import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadRunnerConfig } from "./config.mjs";
import {
    RUNTIME_ERROR_CODES,
} from "./errors.mjs";
import { AutonomousRunner } from "./runner.mjs";
import {
    projectRunnerFailure,
    projectRunnerOutcome,
} from "./outcome.mjs";
import {
    atomicWriteJson,
    parseConfigArgv,
} from "./utils.mjs";

export async function mainRunnerCli(argv = process.argv.slice(2), dependencies = {}) {
    let config = null;
    try {
        const configPath = parseConfigArgv(argv, "runner-cli.mjs");
        config = loadRunnerConfig(configPath, { env: dependencies.env ?? process.env });
        const runnerConfig = {
            investigationId: config.investigationId,
            stateDir: config.stateDir,
            artifactRoot: config.artifactRoot,
            allowlistPath: config.allowlistPath,
            copilotSdkPath: config.sdkPath,
            copilotCliPath: config.cliPath,
            runnerEpochId: config.runnerEpochId,
            supervisorGeneration: config.supervisorGeneration,
            supervisorNonce: config.supervisorNonce,
            runnerIncarnation: config.runnerIncarnation,
            deadline: config.deadlineMs,
            resourceBroker: config.resourceBroker,
            resultPath: config.resultPath,
            options: config.options,
        };
        const runner = dependencies.runnerFactory === undefined
            ? new AutonomousRunner(runnerConfig, dependencies)
            : dependencies.runnerFactory(runnerConfig, dependencies);
        const result = await runner.run();
        const envelope = projectRunnerOutcome(result);
        if (config.resultPath !== null) {
            atomicWriteJson(config.resultPath, envelope);
        }
        dependencies.stdout?.write?.(`${JSON.stringify(envelope)}\n`);
        return { exitCode: 0, envelope };
    } catch (error) {
        const envelope = projectRunnerFailure(error);
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
                : envelope.recoverable
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
