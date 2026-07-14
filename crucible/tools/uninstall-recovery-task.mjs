import path from "node:path";
import { fileURLToPath } from "node:url";

import { mainRecoveryTaskCli } from "./recovery-task-cli.mjs";

const SELF_PATH = fileURLToPath(import.meta.url);
const isEntrypoint = process.argv[1] !== undefined
    && path.resolve(process.argv[1]) === SELF_PATH;

if (isEntrypoint) {
    const { exitCode } = await mainRecoveryTaskCli(
        ["uninstall", ...process.argv.slice(2)],
        {
            stdout: process.stdout,
            stderr: process.stderr,
        },
    );
    process.exitCode = exitCode;
}
