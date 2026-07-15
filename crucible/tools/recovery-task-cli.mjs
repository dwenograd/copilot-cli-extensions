import path from "node:path";

import {
    configureRecoveryTask,
    createPowerShellTaskSchedulerAdapter,
    installRecoveryTask,
    uninstallRecoveryTask,
} from "./recovery-task.mjs";

function parseInteger(value, flag) {
    if (!/^[0-9]+$/u.test(value ?? "")) {
        throw new TypeError(`${flag} requires a positive integer`);
    }
    return Number(value);
}

export function parseRecoveryTaskArgv(argv) {
    const command = argv[0];
    if (!["configure", "install", "uninstall"].includes(command)) {
        throw new TypeError(
            "expected configure, install, or uninstall",
        );
    }
    const options = {
        stateRoot: null,
        nodePath: process.execPath,
        daemonPath: undefined,
        launcherPath: undefined,
        intervalMs: undefined,
        expectedNodeSha256: undefined,
        expectedDaemonSha256: undefined,
    };
    for (let index = 1; index < argv.length; index += 1) {
        const flag = argv[index];
        const value = argv[index + 1];
        if (value === undefined) {
            throw new TypeError(`${flag} requires a value`);
        }
        index += 1;
        if (flag === "--state-root") {
            options.stateRoot = value;
        } else if (flag === "--node-path") {
            options.nodePath = value;
        } else if (flag === "--daemon-path") {
            options.daemonPath = value;
        } else if (flag === "--launcher-path") {
            options.launcherPath = value;
        } else if (flag === "--interval-ms") {
            options.intervalMs = parseInteger(value, flag);
        } else if (flag === "--expected-node-sha256") {
            options.expectedNodeSha256 = value;
        } else if (flag === "--expected-daemon-sha256") {
            options.expectedDaemonSha256 = value;
        } else {
            throw new TypeError(`unknown recovery task flag ${flag}`);
        }
    }
    if (command !== "uninstall" && options.intervalMs === undefined) {
        options.intervalMs = 30_000;
    }
    if (typeof options.stateRoot !== "string"
        || !path.isAbsolute(options.stateRoot)) {
        throw new TypeError("--state-root must be an absolute path");
    }
    return Object.freeze({ command, options: Object.freeze(options) });
}

function publicTaskResult(command, result) {
    const spec = result.spec;
    return Object.freeze({
        ok: true,
        command,
        task_path: spec.taskPath,
        task_name: spec.taskName,
        task_identity: spec.taskIdentity,
        action_fingerprint: spec.actionFingerprint,
        node_path: spec.runtime.nodePath,
        node_sha256: spec.runtime.nodeSha256,
        daemon_path: spec.runtime.daemonPath,
        daemon_sha256: spec.runtime.daemonSha256,
        launcher_path: spec.runtime.launcherPath ?? null,
        launcher_sha256: spec.runtime.launcherSha256 ?? null,
        launch_manifest_sha256:
            spec.runtime.launchManifestSha256 ?? null,
        state_root: spec.stateRoot,
        trigger: "user_logon",
        interactive_token: true,
        hidden: true,
        restart_on_failure: true,
        installed: result.installed ?? false,
        matching: result.matching ?? null,
        unchanged: result.unchanged ?? false,
        removed: result.removed ?? false,
        absent: result.absent ?? false,
    });
}

export async function mainRecoveryTaskCli(
    argv = process.argv.slice(2),
    dependencies = {},
) {
    try {
        const parsed = parseRecoveryTaskArgv(argv);
        const adapter = dependencies.adapter
            ?? createPowerShellTaskSchedulerAdapter({
                env: dependencies.env ?? process.env,
            });
        const toolDependencies = {
            ...dependencies,
            adapter,
        };
        const operation = parsed.command === "configure"
            ? configureRecoveryTask
            : parsed.command === "install"
                ? installRecoveryTask
                : uninstallRecoveryTask;
        const result = await operation(
            parsed.options,
            toolDependencies,
        );
        const output = publicTaskResult(parsed.command, result);
        dependencies.stdout?.write?.(`${JSON.stringify(output, null, 2)}\n`);
        return { exitCode: 0, output };
    } catch (error) {
        const output = {
            ok: false,
            code: error?.code ?? "RECOVERY_TASK_TOOL_FAILED",
            message: error?.message ?? String(error),
        };
        dependencies.stderr?.write?.(`${JSON.stringify(output)}\n`);
        return {
            exitCode: error instanceof TypeError ? 64 : 1,
            output,
        };
    }
}
