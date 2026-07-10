import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadSupervisorConfig } from "./config.mjs";
import { RUNTIME_ERROR_CODES } from "./errors.mjs";
import { runSupervisor } from "./supervisor.mjs";
import { parseConfigArgv } from "./utils.mjs";

export async function mainSupervisorCli(argv = process.argv.slice(2), dependencies = {}) {
    try {
        const configPath = parseConfigArgv(argv, "supervisor-cli.mjs");
        const config = loadSupervisorConfig(configPath, { env: dependencies.env ?? process.env });
        const result = await runSupervisor(config, dependencies);
        const envelope = {
            version: 1,
            ok: result.kind === "TERMINAL"
                || result.kind === "NON_RESULT"
                || result.kind === "PAUSE",
            state: result.status?.state ?? result.kind.toLowerCase(),
            terminal_available: result.terminalAvailable === true
                || result.status?.terminal_available === true,
            non_result_code:
                result.nonResultCode
                ?? result.status?.non_result_code
                ?? result.error?.code
                ?? null,
        };
        dependencies.stdout?.write?.(`${JSON.stringify(envelope)}\n`);
        return {
            exitCode: envelope.ok ? 0 : result.kind === "CIRCUIT_OPEN" ? 75 : 1,
            envelope,
        };
    } catch (error) {
        const envelope = {
            version: 1,
            ok: false,
            state: "failed",
            terminal_available: false,
            non_result_code: error?.code ?? RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
        };
        dependencies.stderr?.write?.(`${JSON.stringify(envelope)}\n`);
        return { exitCode: 1, envelope };
    }
}

const isEntrypoint = process.argv[1] !== undefined
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
    const { exitCode } = await mainSupervisorCli(process.argv.slice(2), {
        stdout: process.stdout,
        stderr: process.stderr,
    });
    process.exitCode = exitCode;
}
