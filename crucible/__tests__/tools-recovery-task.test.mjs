import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    RESOURCE_BROKER_CONFIG_VERSION,
    openResourceBroker,
} from "../runtime/index.mjs";
import {
    buildRecoveryLaunchManifest,
    buildRecoveryLauncherAction,
    captureRecoveryLaunchEnvironment,
    hashRecoveryLaunchFile,
    parseRecoveryLauncherAction,
    RECOVERY_LAUNCHER_AUTHORITY_BOUNDARY,
    RECOVERY_LAUNCH_TRUST_ENVIRONMENT_KEYS,
} from "../tools/recovery-launcher.mjs";
import {
    configureRecoveryTask,
    installRecoveryTask,
    taskActionMatches,
    uninstallRecoveryTask,
} from "../tools/recovery-task.mjs";
import { parseWindowsCommandLine } from "../runtime/process-identity.mjs";
import {
    mainRecoveryTaskCli,
    parseRecoveryTaskArgv,
} from "../tools/recovery-task-cli.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function brokerConfig() {
    return {
        version: RESOURCE_BROKER_CONFIG_VERSION,
        lease: {
            defaultTtlMs: 1_000,
            maxTtlMs: 10_000,
        },
        capacities: {
            sdkSessions: 1,
            sandboxProcesses: 1,
            cpuSlots: { general: 1 },
            gpuSlots: {},
            outputBytes: 1_000,
            receiptBytes: 1_000,
            casBytes: 1_000,
            storageBytes: 2_000,
            modelCostUnits: 10_000,
        },
    };
}

function makeStateRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.recovery-task-${label}-`),
    );
    roots.push(root);
    const broker = openResourceBroker({
        stateRoot: root,
        config: brokerConfig(),
    });
    broker.close();
    return root;
}

function observed(spec) {
    return {
        exists: true,
        taskPath: spec.taskPath,
        taskName: spec.taskName,
        description: spec.description,
        action: { ...spec.action },
        principal: {
            userId: spec.user.userId,
            userSid: spec.user.userSid,
            logonType: spec.principal.logonType,
            runLevel: spec.principal.runLevel,
        },
        trigger: {
            ...spec.trigger,
            userSid: spec.user.userSid,
        },
        settings: { ...spec.settings },
    };
}

function fakeAdapter() {
    const tasks = new Map();
    const key = (spec) => `${spec.taskPath}${spec.taskName}`;
    return {
        tasks,
        async currentUser() {
            return {
                userId: "CONTOSO\\crucible-user",
                userSid: "S-1-5-21-1000-1001-1002-1003",
            };
        },
        async inspect(spec) {
            return tasks.get(key(spec)) ?? {
                exists: false,
                taskPath: spec.taskPath,
                taskName: spec.taskName,
            };
        },
        async install(spec) {
            tasks.set(key(spec), observed(spec));
        },
        async uninstall(spec) {
            tasks.delete(key(spec));
        },
    };
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 20,
            retryDelay: 20,
        });
    }
});

describe("Task Scheduler recovery tooling", () => {
    it("leaves uninstall interval unspecified for manifest reconstruction", () => {
        const stateRoot = path.join(HERE, "cli-state-root");
        expect(parseRecoveryTaskArgv([
            "uninstall",
            "--state-root",
            stateRoot,
        ]).options.intervalMs).toBeUndefined();
        expect(parseRecoveryTaskArgv([
            "configure",
            "--state-root",
            stateRoot,
        ]).options.intervalMs).toBe(30_000);
    });

    it("builds a deterministic same-user logon task without secrets", async () => {
        const adapter = fakeAdapter();
        const options = {
            stateRoot: makeStateRoot("configure"),
            nodePath: process.execPath,
        };
        const first = await configureRecoveryTask(options, { adapter });
        const second = await configureRecoveryTask(options, { adapter });
        expect(first.spec.taskIdentity).toBe(second.spec.taskIdentity);
        expect(first.spec.taskName).toBe(second.spec.taskName);
        expect(first.spec).toMatchObject({
            version: 2,
            trigger: {
                type: "logon",
                userId: "CONTOSO\\crucible-user",
            },
            principal: {
                logonType: "InteractiveToken",
                runLevel: "LeastPrivilege",
            },
            settings: {
                hidden: true,
                restartCount: 999,
                multipleInstances: "IgnoreNew",
                allowStartOnBatteries: true,
                stopOnBatteryTransition: false,
            },
        });
        expect(first.spec.action.execute.toLowerCase())
            .toContain("powershell.exe");
        expect(first.spec.action.arguments).toContain("-Command");
        expect(first.spec.action.arguments).not.toContain("-File");
        const launch = parseRecoveryLauncherAction(
            first.spec.action.arguments,
        );
        expect(launch.manifest.arguments).toEqual([
            "--state-root",
            first.spec.stateRoot,
            "--interval-ms",
            "30000",
            "--expected-node-sha256",
            first.spec.runtime.nodeSha256,
            "--expected-daemon-sha256",
            first.spec.runtime.daemonSha256,
        ]);
        expect(launch.manifest.authorityBoundary)
            .toEqual(RECOVERY_LAUNCHER_AUTHORITY_BOUNDARY);
        expect(launch.manifest.environment.variables
            .slice(-RECOVERY_LAUNCH_TRUST_ENVIRONMENT_KEYS.length)
            .map((variable) => variable.name))
            .toEqual(RECOVERY_LAUNCH_TRUST_ENVIRONMENT_KEYS);
        expect(launch.manifest.files.map((record) => record.path))
            .toEqual(expect.arrayContaining([
                "runtime/recovery-daemon-cli.mjs",
                "runtime/recovery-daemon.mjs",
                "runtime/supervisor.mjs",
                "runtime/runner.mjs",
                "persistence/repository.mjs",
                "measurement/windows-adapter.mjs",
                "domain/index.mjs",
            ]));
        expect(launch.manifest.files.map((record) => record.path))
            .not.toEqual(expect.arrayContaining([
                "extension.mjs",
                "tools/recovery-task.mjs",
                "__tests__/tools-recovery-task.test.mjs",
            ]));
        expect(first.spec.action.arguments).not.toMatch(
            /token|password|secret|credential/iu,
        );
    });

    it("installs idempotently only after exact path and hash validation", async () => {
        const adapter = fakeAdapter();
        const base = await configureRecoveryTask({
            stateRoot: makeStateRoot("install"),
            nodePath: process.execPath,
        }, { adapter });
        const options = {
            stateRoot: base.spec.stateRoot,
            nodePath: base.spec.runtime.nodePath,
            daemonPath: base.spec.runtime.daemonPath,
            expectedNodeSha256: base.spec.runtime.nodeSha256,
            expectedDaemonSha256: base.spec.runtime.daemonSha256,
        };
        const installed = await installRecoveryTask(options, { adapter });
        expect(installed).toMatchObject({
            installed: true,
            unchanged: false,
        });
        const unchanged = await installRecoveryTask(options, { adapter });
        expect(unchanged).toMatchObject({
            installed: false,
            unchanged: true,
        });
        const taskKey = `${installed.spec.taskPath}${installed.spec.taskName}`;
        adapter.tasks.set(taskKey, {
            ...observed(installed.spec),
            principal: {
                ...observed(installed.spec).principal,
                userId: "crucible-user",
            },
            trigger: {
                ...observed(installed.spec).trigger,
                userId: "crucible-user",
            },
        });
        await expect(installRecoveryTask(options, { adapter }))
            .resolves.toMatchObject({ unchanged: true });
        expect(taskActionMatches(
            await adapter.inspect(installed.spec),
            installed.spec,
        )).toBe(true);

        await expect(installRecoveryTask({
            ...options,
            expectedDaemonSha256:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }, { adapter })).rejects.toThrow(/hash/u);
    });

    it("refuses to uninstall a deterministic task after action drift", async () => {
        const adapter = fakeAdapter();
        const configured = await configureRecoveryTask({
            stateRoot: makeStateRoot("uninstall"),
            nodePath: process.execPath,
        }, { adapter });
        const options = {
            stateRoot: configured.spec.stateRoot,
            nodePath: configured.spec.runtime.nodePath,
            daemonPath: configured.spec.runtime.daemonPath,
            expectedNodeSha256: configured.spec.runtime.nodeSha256,
            expectedDaemonSha256:
                configured.spec.runtime.daemonSha256,
        };
        const installed = await installRecoveryTask(options, { adapter });
        const taskKey = `${installed.spec.taskPath}${installed.spec.taskName}`;
        adapter.tasks.set(taskKey, {
            ...observed(installed.spec),
            action: {
                ...installed.spec.action,
                arguments: `${installed.spec.action.arguments} --unexpected`,
            },
        });
        await expect(uninstallRecoveryTask(options, { adapter }))
            .rejects.toThrow(/refusing to remove/u);
        expect(adapter.tasks.has(taskKey)).toBe(true);

        adapter.tasks.set(taskKey, observed(installed.spec));
        await expect(uninstallRecoveryTask(options, { adapter }))
            .resolves.toMatchObject({ removed: true });
        expect(adapter.tasks.has(taskKey)).toBe(false);
    });

    it.each([
        ["hidden", false],
        ["allowStartOnBatteries", false],
        ["stopOnBatteryTransition", true],
    ])("detects %s drift during install verification", async (field, value) => {
        const adapter = fakeAdapter();
        const configured = await configureRecoveryTask({
            stateRoot: makeStateRoot("definition-drift"),
            nodePath: process.execPath,
        }, { adapter });
        const options = {
            stateRoot: configured.spec.stateRoot,
            nodePath: configured.spec.runtime.nodePath,
            daemonPath: configured.spec.runtime.daemonPath,
            expectedNodeSha256: configured.spec.runtime.nodeSha256,
            expectedDaemonSha256:
                configured.spec.runtime.daemonSha256,
        };
        const installed = await installRecoveryTask(options, { adapter });
        const taskKey = `${installed.spec.taskPath}${installed.spec.taskName}`;
        adapter.tasks.set(taskKey, {
            ...observed(installed.spec),
            settings: {
                ...installed.spec.settings,
                [field]: value,
            },
        });
        await expect(installRecoveryTask(options, { adapter }))
            .rejects.toThrow(/different definition/u);
    });

    it("can remove an exact installed action after daemon bytes change", async () => {
        const adapter = fakeAdapter();
        const stateRoot = makeStateRoot("updated-daemon");
        const runtimeDirectory = path.join(stateRoot, "runtime");
        fs.mkdirSync(runtimeDirectory);
        const daemonPath = path.join(
            runtimeDirectory,
            "recovery-daemon-cli.mjs",
        );
        fs.writeFileSync(daemonPath, "export const version = 1;\n");
        const configured = await configureRecoveryTask({
            stateRoot,
            nodePath: process.execPath,
            daemonPath,
        }, { adapter });
        const options = {
            stateRoot,
            nodePath: configured.spec.runtime.nodePath,
            daemonPath,
            expectedNodeSha256: configured.spec.runtime.nodeSha256,
            expectedDaemonSha256:
                configured.spec.runtime.daemonSha256,
        };
        await installRecoveryTask(options, { adapter });
        fs.writeFileSync(daemonPath, "export const version = 2;\n");
        await expect(uninstallRecoveryTask(options, { adapter }))
            .resolves.toMatchObject({ removed: true });
    });

    it("recovers a non-default interval from the pinned launcher on uninstall", async () => {
        const adapter = fakeAdapter();
        const stateRoot = makeStateRoot("interval-uninstall");
        const configured = await configureRecoveryTask({
            stateRoot,
            intervalMs: 45_000,
            nodePath: process.execPath,
            daemonPath: path.join(
                HERE,
                "..",
                "runtime",
                "recovery-daemon-cli.mjs",
            ),
        }, { adapter });
        const options = {
            stateRoot,
            nodePath: configured.spec.runtime.nodePath,
            daemonPath: configured.spec.runtime.daemonPath,
            expectedNodeSha256: configured.spec.runtime.nodeSha256,
            expectedDaemonSha256:
                configured.spec.runtime.daemonSha256,
            intervalMs: 45_000,
        };
        await installRecoveryTask(options, { adapter });
        await expect(uninstallRecoveryTask({
            ...options,
            intervalMs: undefined,
        }, { adapter })).resolves.toMatchObject({ removed: true });
    });

    it.skipIf(process.platform !== "win32")(
        "rejects a closure mutation before Node executes any recovery module",
        () => {
            const root = fs.mkdtempSync(
                path.join(HERE, ".recovery-launcher-mutation-"),
            );
            roots.push(root);
            const runtimeRoot = path.join(root, "runtime-root");
            const runtimeDirectory = path.join(runtimeRoot, "runtime");
            fs.mkdirSync(runtimeDirectory, { recursive: true });
            const marker = path.join(root, "executed.txt");
            const dependency = path.join(
                runtimeDirectory,
                "dependency.mjs",
            );
            const entry = path.join(
                runtimeDirectory,
                "recovery-daemon-cli.mjs",
            );
            fs.writeFileSync(
                dependency,
                "export const dependency = 1;\n",
            );
            fs.writeFileSync(
                entry,
                [
                    "import fs from \"node:fs\";",
                    "import \"./dependency.mjs\";",
                    "let locked = false;",
                    `try { fs.writeFileSync(${JSON.stringify(dependency)}, "mutated"); } catch { locked = true; }`,
                    "if (!locked) throw new Error(\"verified closure was writable\");",
                    "fs.writeFileSync(process.argv[2], \"executed-locked\");",
                ].join("\n"),
            );
            const launcherPath = path.join(
                process.env.SystemRoot ?? "C:\\Windows",
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe",
            );
            const binding = buildRecoveryLaunchManifest({
                runtimeRoot,
                entryPath: entry,
                node: hashRecoveryLaunchFile(
                    process.execPath,
                    "test Node executable",
                ),
                launcherHost: hashRecoveryLaunchFile(
                    launcherPath,
                    "test launcher host",
                ),
                arguments: [marker],
            });
            const action = buildRecoveryLauncherAction(binding);
            fs.writeFileSync(
                dependency,
                "export const dependency = 2;\n",
            );

            let failure = null;
            try {
                execFileSync(
                    action.execute,
                    parseWindowsCommandLine(action.arguments),
                    {
                        encoding: "utf8",
                        windowsHide: true,
                        stdio: ["ignore", "pipe", "pipe"],
                        timeout: 20_000,
                    },
                );
            } catch (error) {
                failure = error;
            }
            expect(failure).not.toBeNull();
            expect(String(failure.stderr ?? failure.message))
                .toMatch(/hash changed/u);
            expect(fs.existsSync(marker)).toBe(false);
        },
    );

    it("rejects a recovery closure rooted through a reparse point", () => {
        const root = fs.mkdtempSync(
            path.join(HERE, ".recovery-launcher-reparse-"),
        );
        roots.push(root);
        const target = path.join(root, "target");
        const alias = path.join(root, "alias");
        const runtimeDirectory = path.join(target, "runtime");
        fs.mkdirSync(runtimeDirectory, { recursive: true });
        const entry = path.join(
            runtimeDirectory,
            "recovery-daemon-cli.mjs",
        );
        fs.writeFileSync(entry, "export {};\n");
        fs.symlinkSync(
            target,
            alias,
            process.platform === "win32" ? "junction" : "dir",
        );
        const aliasedEntry = path.join(
            alias,
            "runtime",
            "recovery-daemon-cli.mjs",
        );
        const launcherPath = process.platform === "win32"
            ? path.join(
                process.env.SystemRoot ?? "C:\\Windows",
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe",
            )
            : process.execPath;
        expect(() => buildRecoveryLaunchManifest({
            runtimeRoot: alias,
            entryPath: aliasedEntry,
            node: hashRecoveryLaunchFile(process.execPath),
            launcherHost: hashRecoveryLaunchFile(launcherPath),
            arguments: [],
        })).toThrow(/symlink|reparse/u);
    });

    it.skipIf(process.platform !== "win32")(
        "holds the verified closure through execution and clears Node preload injection",
        () => {
            const root = fs.mkdtempSync(
                path.join(HERE, ".recovery-launcher-success-"),
            );
            roots.push(root);
            const runtimeRoot = path.join(root, "runtime-root");
            const runtimeDirectory = path.join(runtimeRoot, "runtime");
            fs.mkdirSync(runtimeDirectory, { recursive: true });
            const marker = path.join(root, "executed.txt");
            const preloadMarker = path.join(root, "preloaded.txt");
            const trustValues = {
                CRUCIBLE_EXPERIMENT_PUBLIC_KEY:
                    "fixture-inline-public-key",
                CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH:
                    "C:\\fixture\\experiment-public-key.pem",
                CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT:
                    `sha256:crucible-experiment-public-key-v1:${
                        "c".repeat(64)
                    }`,
            };
            const dependency = path.join(
                runtimeDirectory,
                "dependency.mjs",
            );
            const entry = path.join(
                runtimeDirectory,
                "recovery-daemon-cli.mjs",
            );
            const preload = path.join(root, "preload.mjs");
            fs.writeFileSync(
                dependency,
                "export const dependency = 1;\n",
            );
            fs.writeFileSync(
                entry,
                [
                    "import fs from \"node:fs\";",
                    "import \"./dependency.mjs\";",
                    "let locked = false;",
                    `try { fs.writeFileSync(${JSON.stringify(dependency)}, "mutated"); } catch { locked = true; }`,
                    "if (!locked) throw new Error(\"verified closure was writable\");",
                    "const trust = [",
                    "  process.env.CRUCIBLE_EXPERIMENT_PUBLIC_KEY,",
                    "  process.env.CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH,",
                    "  process.env.CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT,",
                    "].join(\"|\");",
                    "fs.writeFileSync(process.argv[2], `executed-locked:${trust}`);",
                ].join("\n"),
            );
            fs.writeFileSync(
                preload,
                [
                    "import fs from \"node:fs\";",
                    `fs.writeFileSync(${JSON.stringify(preloadMarker)}, "preloaded");`,
                ].join("\n"),
            );
            const launcherPath = path.join(
                process.env.SystemRoot ?? "C:\\Windows",
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe",
            );
            const binding = buildRecoveryLaunchManifest({
                runtimeRoot,
                entryPath: entry,
                node: hashRecoveryLaunchFile(
                    process.execPath,
                    "test Node executable",
                ),
                launcherHost: hashRecoveryLaunchFile(
                    launcherPath,
                    "test launcher host",
                ),
                arguments: [marker],
                environment: captureRecoveryLaunchEnvironment({
                    ...process.env,
                    ...trustValues,
                }),
            });
            const action = buildRecoveryLauncherAction(binding);
            execFileSync(
                action.execute,
                parseWindowsCommandLine(action.arguments),
                {
                    encoding: "utf8",
                    windowsHide: true,
                    stdio: ["ignore", "pipe", "pipe"],
                    timeout: 20_000,
                    env: {
                        ...process.env,
                        NODE_OPTIONS:
                            `--import=${pathToFileURL(preload).href}`,
                    },
                },
            );
            expect(fs.readFileSync(marker, "utf8"))
                .toBe(`executed-locked:${
                    Object.values(trustValues).join("|")
                }`);
            expect(fs.existsSync(preloadMarker)).toBe(false);
        },
    );

    it("exposes configure as a non-mutating operator CLI", async () => {
        const adapter = fakeAdapter();
        let stdout = "";
        const result = await mainRecoveryTaskCli([
            "configure",
            "--state-root",
            makeStateRoot("cli"),
            "--node-path",
            process.execPath,
        ], {
            adapter,
            stdout: {
                write(value) {
                    stdout += value;
                },
            },
        });
        expect(result.exitCode).toBe(0);
        expect(JSON.parse(stdout)).toMatchObject({
            ok: true,
            command: "configure",
            trigger: "user_logon",
            installed: false,
        });
        expect(adapter.tasks.size).toBe(0);
    });
});
