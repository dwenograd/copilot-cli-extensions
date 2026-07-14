import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { canonicalize } from "../persistence/canonical.mjs";
import { assertLocalDatabasePath } from "../persistence/paths.mjs";
import { verifyLocalRegularFile } from "../measurement/fs-verify.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DAEMON_PATH = path.resolve(
    HERE,
    "..",
    "runtime",
    "recovery-daemon-cli.mjs",
);
const TASK_PATH = "\\Crucible\\";
const HASH_RE = /^sha256:[a-f0-9]{64}$/u;

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function fileHash(file) {
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    const fd = fs.openSync(file, "r");
    try {
        for (;;) {
            const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
            if (bytes === 0) break;
            hash.update(buffer.subarray(0, bytes));
        }
    } finally {
        fs.closeSync(fd);
    }
    return `sha256:${hash.digest("hex")}`;
}

function normalizeExpectedHash(value, field) {
    if (typeof value !== "string" || !HASH_RE.test(value)) {
        throw new TypeError(
            `${field} must be sha256:<64 lowercase hex>`,
        );
    }
    return value;
}

function normalizePathForIdentity(value, platform) {
    const resolved = path.resolve(value);
    return platform === "win32" ? resolved.toLowerCase() : resolved;
}

function windowsQuote(value) {
    const text = String(value);
    if (text.length === 0) return "\"\"";
    if (!/[\s"]/u.test(text)) return text;
    let result = "\"";
    let slashes = 0;
    for (const character of text) {
        if (character === "\\") {
            slashes += 1;
        } else if (character === "\"") {
            result += "\\".repeat((slashes * 2) + 1);
            result += "\"";
            slashes = 0;
        } else {
            result += "\\".repeat(slashes);
            result += character;
            slashes = 0;
        }
    }
    result += "\\".repeat(slashes * 2);
    return `${result}"`;
}

function requireUserIdentity(value) {
    if (value === null
        || typeof value !== "object"
        || typeof value.userId !== "string"
        || value.userId.length < 1
        || typeof value.userSid !== "string"
        || !/^S-\d(?:-\d+)+$/u.test(value.userSid)) {
        throw new TypeError(
            "Task Scheduler adapter did not return the current user identity",
        );
    }
    return Object.freeze({
        userId: value.userId,
        userSid: value.userSid,
    });
}

function validateStateRoot(stateRoot, env) {
    if (typeof stateRoot !== "string" || !path.isAbsolute(stateRoot)) {
        throw new TypeError("stateRoot must be an absolute path");
    }
    const root = assertLocalDatabasePath(path.resolve(stateRoot), { env });
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
        throw new TypeError("stateRoot must be an existing local directory");
    }
    verifyLocalRegularFile(path.join(root, "resource-catalog.sqlite"), {
        label: "Crucible resource catalog",
    });
    return root;
}

function validateStateRootIdentity(stateRoot, env) {
    if (typeof stateRoot !== "string" || !path.isAbsolute(stateRoot)) {
        throw new TypeError("stateRoot must be an absolute path");
    }
    return assertLocalDatabasePath(path.resolve(stateRoot), { env });
}

function validateRuntimeFiles({
    nodePath,
    daemonPath,
    expectedNodeSha256 = null,
    expectedDaemonSha256 = null,
    env,
}, dependencies) {
    const node = verifyLocalRegularFile(
        assertLocalDatabasePath(path.resolve(nodePath), { env }),
        { label: "Node executable" },
    );
    const daemon = verifyLocalRegularFile(
        assertLocalDatabasePath(path.resolve(daemonPath), { env }),
        { label: "Crucible recovery daemon" },
    );
    if (path.basename(daemon).toLowerCase() !== "recovery-daemon-cli.mjs") {
        throw new TypeError(
            "daemonPath must name recovery-daemon-cli.mjs",
        );
    }
    const nodeSha256 = fileHash(node);
    const daemonSha256 = fileHash(daemon);
    if (expectedNodeSha256 !== null
        && nodeSha256 !== normalizeExpectedHash(
            expectedNodeSha256,
            "expectedNodeSha256",
        )) {
        throw new Error("Node executable hash does not match the operator value");
    }
    if (expectedDaemonSha256 !== null
        && daemonSha256 !== normalizeExpectedHash(
            expectedDaemonSha256,
            "expectedDaemonSha256",
        )) {
        throw new Error("recovery daemon hash does not match the operator value");
    }
    const probe = dependencies.nodeVersionProbe
        ?? ((file) => execFileSync(file, ["--version"], {
            encoding: "utf8",
            windowsHide: true,
            stdio: ["ignore", "pipe", "ignore"],
            timeout: 5_000,
        }).trim());
    const nodeVersion = probe(node);
    if (typeof nodeVersion !== "string"
        || !/^v\d+\.\d+\.\d+/u.test(nodeVersion)) {
        throw new Error("nodePath did not report a valid Node version");
    }
    return Object.freeze({
        nodePath: node,
        daemonPath: daemon,
        nodeSha256,
        daemonSha256,
        nodeVersion,
    });
}

function expectedRuntimeIdentity({
    nodePath,
    daemonPath,
    expectedNodeSha256,
    expectedDaemonSha256,
    env,
}) {
    if (typeof nodePath !== "string" || !path.isAbsolute(nodePath)
        || typeof daemonPath !== "string" || !path.isAbsolute(daemonPath)) {
        throw new TypeError("Node and daemon paths must be absolute");
    }
    const node = assertLocalDatabasePath(path.resolve(nodePath), { env });
    const daemon = assertLocalDatabasePath(path.resolve(daemonPath), { env });
    if (path.basename(daemon).toLowerCase() !== "recovery-daemon-cli.mjs") {
        throw new TypeError(
            "daemonPath must name recovery-daemon-cli.mjs",
        );
    }
    return Object.freeze({
        nodePath: node,
        daemonPath: daemon,
        nodeSha256: normalizeExpectedHash(
            expectedNodeSha256,
            "expectedNodeSha256",
        ),
        daemonSha256: normalizeExpectedHash(
            expectedDaemonSha256,
            "expectedDaemonSha256",
        ),
        nodeVersion: null,
    });
}

export function buildRecoveryTaskSpec({
    stateRoot,
    runtime,
    user,
    intervalMs = 30_000,
    platform = process.platform,
} = {}) {
    if (!Number.isSafeInteger(intervalMs)
        || intervalMs < 1_000
        || intervalMs > 24 * 60 * 60_000) {
        throw new TypeError("intervalMs is outside the supported range");
    }
    const identityDocument = {
        version: 1,
        userSid: user.userSid,
        stateRoot: normalizePathForIdentity(stateRoot, platform),
    };
    const taskIdentity = `sha256:crucible-recovery-task-v1:${
        sha256(canonicalize(identityDocument))
    }`;
    const identityHex =
        taskIdentity.slice(taskIdentity.lastIndexOf(":") + 1);
    const taskName = `Recovery-${identityHex.slice(0, 24)}`;
    const argumentsList = [
        runtime.daemonPath,
        "--state-root",
        stateRoot,
        "--interval-ms",
        String(intervalMs),
        "--expected-node-sha256",
        runtime.nodeSha256,
        "--expected-daemon-sha256",
        runtime.daemonSha256,
    ];
    const argumentsText = argumentsList.map(windowsQuote).join(" ");
    const actionDocument = {
        version: 1,
        execute: normalizePathForIdentity(runtime.nodePath, platform),
        arguments: argumentsText,
        workingDirectory: normalizePathForIdentity(
            path.dirname(runtime.daemonPath),
            platform,
        ),
        nodeSha256: runtime.nodeSha256,
        daemonSha256: runtime.daemonSha256,
    };
    const actionFingerprint = `sha256:crucible-recovery-action-v1:${
        sha256(canonicalize(actionDocument))
    }`;
    return Object.freeze({
        version: 1,
        taskPath: TASK_PATH,
        taskName,
        taskIdentity,
        actionFingerprint,
        description:
            `Crucible same-user recovery v1; identity=${taskIdentity}; action=${actionFingerprint}`,
        user,
        stateRoot,
        runtime,
        action: Object.freeze({
            execute: runtime.nodePath,
            arguments: argumentsText,
            workingDirectory: path.dirname(runtime.daemonPath),
        }),
        trigger: Object.freeze({
            type: "logon",
            userId: user.userId,
        }),
        principal: Object.freeze({
            userId: user.userId,
            userSid: user.userSid,
            logonType: "InteractiveToken",
            runLevel: "LeastPrivilege",
        }),
        settings: Object.freeze({
            hidden: true,
            startWhenAvailable: true,
            restartCount: 999,
            restartIntervalMinutes: 1,
            multipleInstances: "IgnoreNew",
            executionTimeLimitSeconds: 0,
            allowStartOnBatteries: true,
            stopOnBatteryTransition: false,
        }),
    });
}

function samePath(left, right, platform) {
    if (typeof left !== "string" || typeof right !== "string") return false;
    return normalizePathForIdentity(left, platform)
        === normalizePathForIdentity(right, platform);
}

export function taskActionMatches(observed, expected, {
    platform = process.platform,
} = {}) {
    if (observed?.exists !== true) return false;
    return observed.description === expected.description
        && observed.taskPath === expected.taskPath
        && observed.taskName === expected.taskName
        && samePath(
            observed.action?.execute,
            expected.action.execute,
            platform,
        )
        && observed.action?.arguments === expected.action.arguments
        && samePath(
            observed.action?.workingDirectory,
            expected.action.workingDirectory,
            platform,
        )
        && [
            expected.principal.userId.toLowerCase(),
            expected.principal.userSid.toLowerCase(),
        ].includes(String(observed.principal?.userId ?? "").toLowerCase());
}

export function taskDefinitionMatches(observed, expected, options = {}) {
    return taskActionMatches(observed, expected, options)
        && observed.trigger?.type === expected.trigger.type
        && [
            expected.trigger.userId.toLowerCase(),
            expected.principal.userSid.toLowerCase(),
        ].includes(String(observed.trigger?.userId ?? "").toLowerCase())
        && observed.principal?.logonType
            === expected.principal.logonType
        && observed.principal?.runLevel
            === expected.principal.runLevel
        && observed.settings?.hidden === expected.settings.hidden
        && observed.settings?.startWhenAvailable
            === expected.settings.startWhenAvailable
        && observed.settings?.restartCount
            === expected.settings.restartCount
        && observed.settings?.restartIntervalMinutes
            === expected.settings.restartIntervalMinutes
        && observed.settings?.multipleInstances
            === expected.settings.multipleInstances
        && observed.settings?.executionTimeLimitSeconds
            === expected.settings.executionTimeLimitSeconds;
}

async function preparedTask(
    options,
    dependencies,
    { verifyRuntimeBytes = true } = {},
) {
    const adapter = dependencies.adapter;
    if (adapter === null || typeof adapter !== "object"
        || typeof adapter.currentUser !== "function"
        || typeof adapter.inspect !== "function") {
        throw new TypeError("a Task Scheduler adapter is required");
    }
    const env = dependencies.env ?? process.env;
    const stateRoot = verifyRuntimeBytes
        ? validateStateRoot(options.stateRoot, env)
        : validateStateRootIdentity(options.stateRoot, env);
    const runtime = verifyRuntimeBytes
        ? validateRuntimeFiles({
            nodePath: options.nodePath,
            daemonPath: options.daemonPath ?? DEFAULT_DAEMON_PATH,
            expectedNodeSha256: options.expectedNodeSha256 ?? null,
            expectedDaemonSha256:
                options.expectedDaemonSha256 ?? null,
            env,
        }, dependencies)
        : expectedRuntimeIdentity({
            nodePath: options.nodePath,
            daemonPath: options.daemonPath ?? DEFAULT_DAEMON_PATH,
            expectedNodeSha256: options.expectedNodeSha256,
            expectedDaemonSha256: options.expectedDaemonSha256,
            env,
        });
    const user = requireUserIdentity(await adapter.currentUser());
    const spec = buildRecoveryTaskSpec({
        stateRoot,
        runtime,
        user,
        intervalMs: options.intervalMs,
        platform: dependencies.platform ?? process.platform,
    });
    const observed = await adapter.inspect(spec);
    return { adapter, observed, spec };
}

export async function configureRecoveryTask(options, dependencies = {}) {
    const prepared = await preparedTask(options, dependencies);
    return Object.freeze({
        spec: prepared.spec,
        installed: prepared.observed?.exists === true,
        matching: taskDefinitionMatches(prepared.observed, prepared.spec, {
            platform: dependencies.platform ?? process.platform,
        }),
    });
}

export async function installRecoveryTask(options, dependencies = {}) {
    if (options.expectedNodeSha256 === undefined
        || options.expectedDaemonSha256 === undefined) {
        throw new TypeError(
            "install requires expectedNodeSha256 and expectedDaemonSha256",
        );
    }
    const prepared = await preparedTask(options, dependencies);
    if (prepared.observed?.exists === true) {
        if (!taskDefinitionMatches(prepared.observed, prepared.spec, {
            platform: dependencies.platform ?? process.platform,
        })) {
            throw new Error(
                "a task with the deterministic identity exists under a different definition",
            );
        }
        return Object.freeze({
            installed: false,
            unchanged: true,
            spec: prepared.spec,
        });
    }
    if (typeof prepared.adapter.install !== "function") {
        throw new TypeError("Task Scheduler adapter cannot install tasks");
    }
    await prepared.adapter.install(prepared.spec);
    const verified = await prepared.adapter.inspect(prepared.spec);
    if (!taskDefinitionMatches(verified, prepared.spec, {
        platform: dependencies.platform ?? process.platform,
    })) {
        throw new Error(
            "installed recovery task failed exact action verification",
        );
    }
    return Object.freeze({
        installed: true,
        unchanged: false,
        spec: prepared.spec,
    });
}

export async function uninstallRecoveryTask(options, dependencies = {}) {
    if (options.expectedNodeSha256 === undefined
        || options.expectedDaemonSha256 === undefined) {
        throw new TypeError(
            "uninstall requires expectedNodeSha256 and expectedDaemonSha256",
        );
    }
    const prepared = await preparedTask(
        options,
        dependencies,
        { verifyRuntimeBytes: false },
    );
    if (prepared.observed?.exists !== true) {
        return Object.freeze({
            removed: false,
            absent: true,
            spec: prepared.spec,
        });
    }
    if (!taskActionMatches(prepared.observed, prepared.spec, {
        platform: dependencies.platform ?? process.platform,
    })) {
        throw new Error(
            "refusing to remove a task whose action does not exactly match",
        );
    }
    if (typeof prepared.adapter.uninstall !== "function") {
        throw new TypeError("Task Scheduler adapter cannot uninstall tasks");
    }
    await prepared.adapter.uninstall(prepared.spec);
    const after = await prepared.adapter.inspect(prepared.spec);
    if (after?.exists === true) {
        throw new Error("recovery task still exists after uninstall");
    }
    return Object.freeze({
        removed: true,
        absent: false,
        spec: prepared.spec,
    });
}

function invokePowerShell(script, args, {
    powershellPath = "powershell.exe",
    env = process.env,
} = {}) {
    const output = execFileSync(
        powershellPath,
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script,
            ...args,
        ],
        {
            encoding: "utf8",
            windowsHide: true,
            stdio: ["ignore", "pipe", "pipe"],
            timeout: 30_000,
            env,
        },
    ).trim();
    return output.length === 0 ? null : JSON.parse(output);
}

export function createPowerShellTaskSchedulerAdapter(options = {}) {
    if ((options.platform ?? process.platform) !== "win32") {
        throw new Error("Task Scheduler installation is supported only on Windows");
    }
    const script = (name) => path.join(
        options.scriptsDirectory ?? HERE,
        name,
    );
    return Object.freeze({
        currentUser() {
            return invokePowerShell(
                script("configure-recovery-task.ps1"),
                ["-Mode", "Identity"],
                options,
            );
        },
        inspect(spec) {
            return invokePowerShell(
                script("configure-recovery-task.ps1"),
                [
                    "-Mode",
                    "Inspect",
                    "-TaskPath",
                    spec.taskPath,
                    "-TaskName",
                    spec.taskName,
                ],
                options,
            );
        },
        install(spec) {
            return invokePowerShell(
                script("install-recovery-task.ps1"),
                [
                    "-TaskPath", spec.taskPath,
                    "-TaskName", spec.taskName,
                    "-Description", spec.description,
                    "-Execute", spec.action.execute,
                    "-Arguments", spec.action.arguments,
                    "-WorkingDirectory", spec.action.workingDirectory,
                    "-UserId", spec.user.userId,
                    "-UserSid", spec.user.userSid,
                    "-NodeSha256", spec.runtime.nodeSha256,
                    "-DaemonSha256", spec.runtime.daemonSha256,
                    "-DaemonPath", spec.runtime.daemonPath,
                ],
                options,
            );
        },
        uninstall(spec) {
            return invokePowerShell(
                script("uninstall-recovery-task.ps1"),
                [
                    "-TaskPath", spec.taskPath,
                    "-TaskName", spec.taskName,
                    "-Description", spec.description,
                    "-Execute", spec.action.execute,
                    "-Arguments", spec.action.arguments,
                    "-WorkingDirectory", spec.action.workingDirectory,
                    "-UserId", spec.user.userId,
                    "-UserSid", spec.user.userSid,
                ],
                options,
            );
        },
    });
}
