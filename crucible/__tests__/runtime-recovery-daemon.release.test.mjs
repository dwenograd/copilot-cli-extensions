import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    RESOURCE_BROKER_CONFIG_VERSION,
    openResourceBroker,
    runRecoveryDaemon,
} from "../runtime/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(
    HERE,
    "fixtures",
    "recovery-daemon-kill-worker.mjs",
);
const roots = [];
const children = [];

function waitForLine(child) {
    return new Promise((resolve, reject) => {
        let buffer = "";
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", (chunk) => {
            buffer += chunk;
            const newline = buffer.indexOf("\n");
            if (newline !== -1) {
                resolve(JSON.parse(buffer.slice(0, newline)));
            }
        });
        child.once("error", reject);
        child.once("exit", (code) => {
            reject(new Error(`recovery fixture exited early with ${code}`));
        });
    });
}

afterEach(() => {
    for (const child of children.splice(0)) {
        if (child.exitCode === null) child.kill("SIGKILL");
    }
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 20,
            retryDelay: 50,
        });
    }
});

describe("recovery daemon crash fencing", () => {
    it("takes over after daemon death and fences a supervisor-owned mid-effect lease", async () => {
        const stateRoot = fs.mkdtempSync(
            path.join(HERE, ".recovery-daemon-release-"),
        );
        roots.push(stateRoot);
        const config = {
            version: RESOURCE_BROKER_CONFIG_VERSION,
            lease: {
                defaultTtlMs: 5_000,
                maxTtlMs: 10_000,
            },
            capacities: {
                sdkSessions: 1,
                sandboxProcesses: 1,
                cpuSlots: { general: 1 },
                gpuSlots: {},
                outputBytes: 10_000,
                receiptBytes: 10_000,
                casBytes: 10_000,
                storageBytes: 20_000,
                modelCostUnits: 100_000,
            },
        };
        const broker = openResourceBroker({ stateRoot, config });
        broker.registerInvestigation({
            investigationId: "kill-recovery",
            limits: {
                sdkSessions: 1,
                sandboxProcesses: 1,
                cpuSlots: { general: 1 },
                gpuSlots: {},
                outputBytes: 5_000,
                receiptBytes: 5_000,
                casBytes: 5_000,
                storageBytes: 10_000,
                modelCostUnits: 50_000,
            },
            supervisorGeneration: 1,
            supervisorNonce: "supervisor-g1",
            runnerIncarnation: "runner-g1",
        });
        const inFlight = broker.acquire({
            investigationId: "kill-recovery",
            ownerId: "runner-g1",
            supervisorGeneration: 1,
            runnerIncarnation: "runner-g1",
            attemptId: "attempt-mid-effect",
            logicalEffectId: "logical-effect-mid-effect",
            reservation: { sdkSessions: 1 },
        });
        expect(inFlight.status).toBe("acquired");

        const child = spawn(process.execPath, [FIXTURE, stateRoot], {
            cwd: HERE,
            windowsHide: true,
            stdio: ["ignore", "pipe", "pipe"],
        });
        children.push(child);
        await expect(waitForLine(child)).resolves.toMatchObject({
            ready: true,
            daemonGeneration: 1,
        });
        child.kill("SIGKILL");
        await new Promise((resolve) => child.once("exit", resolve));
        await new Promise((resolve) => setTimeout(resolve, 1_100));

        const recovered = await runRecoveryDaemon({
            stateRoot,
            once: true,
            leaseTtlMs: 2_000,
            heartbeatMs: 500,
        }, {
            broker,
            daemonIncarnation: "replacement-daemon",
            leaseNonce: "replacement-daemon-nonce",
            ownerProcessId: process.pid,
            ownerProcessStartId: "replacement-process",
            inspectRecoveryInvestigation: async () => ({
                eligible: true,
                state: "eligible",
                code: "RECOVERY_ELIGIBLE",
                config: {},
            }),
            ensureSupervisor: async () => {
                broker.claimAuthority({
                    investigationId: "kill-recovery",
                    supervisorGeneration: 2,
                    supervisorNonce: "supervisor-g2",
                    runnerIncarnation: "runner-g2",
                });
                return {
                    action: "started",
                    acknowledgement: {
                        supervisorGeneration: 2,
                        runnerIncarnation: "runner-g2",
                    },
                };
            },
        });
        expect(recovered.operations).toMatchObject([{
            state: "started",
        }]);
        expect(broker.getLease(inFlight.lease.leaseId).status)
            .toBe("reclaimed");
        expect(broker.acquire({
            investigationId: "kill-recovery",
            ownerId: "runner-g2",
            supervisorGeneration: 2,
            runnerIncarnation: "runner-g2",
            attemptId: "attempt-mid-effect-retry",
            logicalEffectId: "logical-effect-mid-effect",
            reservation: { sdkSessions: 1 },
        })).toMatchObject({
            status: "already_finalized",
            deduplicated: true,
        });
        broker.close();
    });
});
