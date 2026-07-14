import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
    RESOURCE_BROKER_CONFIG_VERSION,
    openResourceBroker,
} from "../../runtime/index.mjs";
import {
    configureRecoveryTask,
    createPowerShellTaskSchedulerAdapter,
    installRecoveryTask,
    uninstallRecoveryTask,
} from "../../tools/recovery-task.mjs";

const ENABLED = process.platform === "win32"
    && process.env.CRUCIBLE_RUN_TASK_SCHEDULER_CONFORMANCE === "1";
const HERE = path.dirname(fileURLToPath(import.meta.url));

describe.skipIf(!ENABLED)("Windows Task Scheduler recovery conformance", () => {
    it("round-trips one test-owned exact-action task", async () => {
        const stateRoot = fs.mkdtempSync(
            path.join(HERE, ".recovery-task-conformance-"),
        );
        const broker = openResourceBroker({
            stateRoot,
            config: {
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
            },
        });
        broker.close();
        const adapter = createPowerShellTaskSchedulerAdapter();
        let options = null;
        try {
            const configured = await configureRecoveryTask({
                stateRoot,
                nodePath: process.execPath,
            }, { adapter });
            options = {
                stateRoot,
                nodePath: configured.spec.runtime.nodePath,
                daemonPath: configured.spec.runtime.daemonPath,
                expectedNodeSha256: configured.spec.runtime.nodeSha256,
                expectedDaemonSha256:
                    configured.spec.runtime.daemonSha256,
            };
            await expect(installRecoveryTask(options, { adapter }))
                .resolves.toMatchObject({ installed: true });
            await expect(uninstallRecoveryTask(options, { adapter }))
                .resolves.toMatchObject({ removed: true });
            options = null;
        } finally {
            if (options !== null) {
                try {
                    await uninstallRecoveryTask(options, { adapter });
                } catch {
                    // Preserve the primary conformance failure.
                }
            }
            fs.rmSync(stateRoot, {
                recursive: true,
                force: true,
                maxRetries: 20,
                retryDelay: 50,
            });
        }
    });
});
