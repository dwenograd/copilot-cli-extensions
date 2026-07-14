import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    RESOURCE_BROKER_CONFIG_VERSION,
    openResourceBroker,
} from "../runtime/index.mjs";
import {
    configureRecoveryTask,
    installRecoveryTask,
    taskActionMatches,
    uninstallRecoveryTask,
} from "../tools/recovery-task.mjs";
import { mainRecoveryTaskCli } from "../tools/recovery-task-cli.mjs";

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
            logonType: spec.principal.logonType,
            runLevel: spec.principal.runLevel,
        },
        trigger: { ...spec.trigger },
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
            },
        });
        expect(first.spec.action.arguments).toContain(
            "--expected-node-sha256",
        );
        expect(first.spec.action.arguments).toContain(
            "--expected-daemon-sha256",
        );
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

    it("detects trigger or settings drift during install verification", async () => {
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
                hidden: false,
            },
        });
        await expect(installRecoveryTask(options, { adapter }))
            .rejects.toThrow(/different definition/u);
    });

    it("can remove an exact installed action after daemon bytes change", async () => {
        const adapter = fakeAdapter();
        const stateRoot = makeStateRoot("updated-daemon");
        const daemonPath = path.join(
            stateRoot,
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
