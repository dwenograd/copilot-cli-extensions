import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    ERROR_CODES,
} from "../persistence/index.mjs";
import {
    RESOURCE_BROKER_CONFIG_VERSION,
    openResourceBroker,
} from "../runtime/index.mjs";
import { removeTrackedRoots } from "./test-cleanup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(HERE, "fixtures", "resource-broker-process.mjs");
const roots = [];
const children = [];
const brokers = [];

function wait(delayMs) {
    return new Promise((resolve) => setTimeout(resolve, delayMs));
}

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.resource-broker-release-${label}-`),
    );
    roots.push(root);
    return root;
}

function openBroker(options) {
    const broker = openResourceBroker(options);
    brokers.push(broker);
    return broker;
}

function config(overrides = {}) {
    return {
        version: RESOURCE_BROKER_CONFIG_VERSION,
        lease: {
            defaultTtlMs: 10_000,
            maxTtlMs: 60_000,
        },
        capacities: {
            sdkSessions: 2,
            sandboxProcesses: 2,
            cpuSlots: { general: 2 },
            gpuSlots: {},
            outputBytes: 1_000,
            receiptBytes: 1_000,
            casBytes: 1_000,
            modelCostUnits: 10_000,
            ...overrides,
        },
    };
}

function limits(brokerConfig) {
    return {
        sdkSessions: 1,
        sandboxProcesses: 1,
        cpuSlots: { general: 1 },
        gpuSlots: {},
        outputBytes: Math.min(500, brokerConfig.capacities.outputBytes),
        receiptBytes: Math.min(500, brokerConfig.capacities.receiptBytes),
        casBytes: Math.min(500, brokerConfig.capacities.casBytes),
        modelCostUnits: Math.min(
            5_000,
            brokerConfig.capacities.modelCostUnits,
        ),
    };
}

function register(broker, brokerConfig, investigationId, {
    generation = 1,
    nonce = `nonce-${investigationId}`,
    incarnation = `inc-${investigationId}-1`,
} = {}) {
    broker.registerInvestigation({
        investigationId,
        limits: limits(brokerConfig),
        supervisorGeneration: generation,
        supervisorNonce: nonce,
        runnerIncarnation: incarnation,
    });
}

function launch(specPath) {
    const child = spawn(process.execPath, [FIXTURE, specPath], {
        cwd: path.dirname(HERE),
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
    });
    const record = {
        child,
        stderr: "",
    };
    child.stderr.on("data", (chunk) => {
        record.stderr += chunk.toString("utf8");
    });
    children.push(record);
    return record;
}

async function waitForFiles(files, timeoutMs = 20_000) {
    const deadline = Date.now() + timeoutMs;
    while (files.some((file) => !fs.existsSync(file))) {
        if (Date.now() >= deadline) {
            throw new Error(
                `timed out waiting for subprocess results: ${files.join(", ")}`,
            );
        }
        await wait(20);
    }
}

async function waitForExit(record, timeoutMs = 20_000) {
    if (record.child.exitCode !== null || record.child.signalCode !== null) {
        return;
    }
    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error(
                `resource broker fixture did not exit; stderr=${record.stderr}`,
            ));
        }, timeoutMs);
        record.child.once("close", () => {
            clearTimeout(timer);
            resolve();
        });
    });
}

function writeSpec(root, index, spec) {
    const file = path.join(root, `spec-${index}.json`);
    fs.writeFileSync(file, `${JSON.stringify(spec)}\n`);
    return file;
}

function readResult(file) {
    return JSON.parse(fs.readFileSync(file, "utf8"));
}

afterEach(async () => {
    for (const record of children.splice(0)) {
        if (record.child.exitCode === null && record.child.signalCode === null) {
            record.child.kill();
        }
        try {
            await waitForExit(record, 5_000);
        } catch {
            // Cleanup below reports any surviving open files/directories.
        }
    }
    for (const broker of brokers.splice(0)) {
        try {
            broker.close();
        } catch {
            // A test may already have closed the handle.
        }
    }
    await removeTrackedRoots(roots, {
        label: "resource broker release test root",
    });
});

describe("resource broker multiprocess durability", () => {
    it("serializes concurrent cross-investigation capacity behind a start barrier", async () => {
        const root = makeRoot("capacity");
        const stateRoot = path.join(root, "state-root");
        const brokerConfig = config();
        const setup = openBroker({
            stateRoot,
            config: brokerConfig,
        });
        for (let index = 0; index < 4; index += 1) {
            register(setup, brokerConfig, `inv-${index}`);
        }
        setup.close();

        const startBarrier = path.join(root, "start.barrier");
        const releaseBarrier = path.join(root, "release.barrier");
        const resultPaths = [];
        const records = [];
        for (let index = 0; index < 4; index += 1) {
            const resultPath = path.join(root, `result-${index}.json`);
            resultPaths.push(resultPath);
            records.push(launch(writeSpec(root, index, {
                stateRoot,
                config: brokerConfig,
                startBarrier,
                releaseBarrier,
                resultPath,
                mode: "hold",
                investigationId: `inv-${index}`,
                ownerId: `owner-${index}`,
                ownerProcessStartId: `process-${index}`,
                supervisorGeneration: 1,
                runnerIncarnation: `inc-inv-${index}-1`,
                attemptId: `attempt-${index}`,
                logicalEffectId: `effect-${index}`,
                reservation: { sdkSessions: 1 },
                ttlMs: 30_000,
            })));
        }
        fs.writeFileSync(startBarrier, "go\n");
        await waitForFiles(resultPaths);
        const results = resultPaths.map(readResult);
        expect(results.filter((result) => result.status === "acquired"))
            .toHaveLength(2);
        expect(results.filter((result) => result.status === "throttle"))
            .toHaveLength(2);
        expect(new Set(results
            .filter((result) => result.status === "acquired")
            .map((result) => result.lease.fencingToken)).size).toBe(2);

        fs.writeFileSync(releaseBarrier, "release\n");
        await Promise.all(records.map((record) => waitForExit(record)));
        expect(records.every((record) => record.child.exitCode === 0)).toBe(true);

        const verify = openBroker({
            stateRoot,
            config: brokerConfig,
        });
        expect(verify.listActiveLeases()).toEqual([]);
        expect(verify.getUsageSnapshot()
            .find((row) => row.resourceKey === "sdk_sessions"))
            .toMatchObject({
                committedUnits: 0,
                heldUnits: 0,
                totalUnits: 0,
            });
        verify.close();
    });

    it("recovers a killed owner conservatively, fences a stale process, and leaves no leases", async () => {
        const root = makeRoot("crash");
        const stateRoot = path.join(root, "state-root");
        const brokerConfig = config({
            sdkSessions: 1,
            outputBytes: 500,
            modelCostUnits: 1_000,
        });
        const setup = openBroker({
            stateRoot,
            config: brokerConfig,
        });
        register(setup, brokerConfig, "inv-crash");
        register(setup, brokerConfig, "inv-next");
        register(setup, brokerConfig, "inv-fence", {
            nonce: "fence-supervisor",
            incarnation: "inc-fence-1",
        });
        setup.claimAuthority({
            investigationId: "inv-fence",
            supervisorGeneration: 2,
            supervisorNonce: "fence-supervisor-2",
            runnerIncarnation: "inc-fence-2",
        });
        setup.close();

        const crashStart = path.join(root, "crash-start.barrier");
        const crashResult = path.join(root, "crash-result.json");
        const crash = launch(writeSpec(root, "crash", {
            stateRoot,
            config: brokerConfig,
            startBarrier: crashStart,
            releaseBarrier: path.join(root, "never-release.barrier"),
            resultPath: crashResult,
            mode: "hang",
            investigationId: "inv-crash",
            ownerId: "crash-owner",
            ownerProcessStartId: "crash-process-incarnation",
            supervisorGeneration: 1,
            runnerIncarnation: "inc-inv-crash-1",
            attemptId: "crash-attempt",
            logicalEffectId: "crash-effect",
            reservation: {
                sdkSessions: 1,
                outputBytes: 25,
                modelCostUnits: 100,
            },
            ttlMs: 60_000,
        }));
        fs.writeFileSync(crashStart, "go\n");
        await waitForFiles([crashResult]);
        const crashedLease = readResult(crashResult);
        expect(crashedLease.status).toBe("acquired");
        crash.child.kill("SIGKILL");
        await waitForExit(crash);

        const recovered = openBroker({
            stateRoot,
            config: brokerConfig,
            isOwnerAlive: ({ processId, processStartId }) =>
                !(processId === crashedLease.lease.ownerProcessId
                    && processStartId === "crash-process-incarnation"),
        });
        const replacement = recovered.acquire({
            investigationId: "inv-next",
            ownerId: "next-owner",
            supervisorGeneration: 1,
            runnerIncarnation: "inc-inv-next-1",
            attemptId: "next-attempt",
            logicalEffectId: "next-effect",
            reservation: { sdkSessions: 1 },
        });
        expect(replacement.status).toBe("acquired");
        expect(replacement.reclaimed).toContainEqual({
            fencingToken: crashedLease.lease.fencingToken,
            reason: "owner_dead",
        });
        const reclaimed = recovered.getLease(crashedLease.lease.leaseId);
        expect(reclaimed).toMatchObject({
            status: "reclaimed",
            finalizationReason: "owner_dead",
        });
        expect(reclaimed.allocations.find((entry) =>
            entry.resourceKey === "output_bytes").chargedUnits).toBe(25);
        expect(reclaimed.allocations.find((entry) =>
            entry.resourceKey === "model_cost_units").chargedUnits).toBe(100);
        recovered.release({ lease: replacement.lease });
        recovered.close();

        const staleStart = path.join(root, "stale-start.barrier");
        const staleResult = path.join(root, "stale-result.json");
        const stale = launch(writeSpec(root, "stale", {
            stateRoot,
            config: brokerConfig,
            startBarrier: staleStart,
            releaseBarrier: path.join(root, "stale-release.barrier"),
            resultPath: staleResult,
            mode: "hold",
            investigationId: "inv-fence",
            ownerId: "stale-owner",
            ownerProcessStartId: "stale-process",
            supervisorGeneration: 1,
            runnerIncarnation: "inc-fence-1",
            attemptId: "stale-attempt",
            logicalEffectId: "stale-effect",
            reservation: { sdkSessions: 1 },
            ttlMs: 30_000,
        }));
        fs.writeFileSync(staleStart, "go\n");
        await waitForFiles([staleResult]);
        await waitForExit(stale);
        expect(readResult(staleResult)).toMatchObject({
            status: "error",
            code: ERROR_CODES.FENCE_REJECTED,
        });

        const verify = openBroker({
            stateRoot,
            config: brokerConfig,
        });
        expect(verify.listActiveLeases()).toEqual([]);
        expect(verify.getUsageSnapshot()
            .find((row) => row.resourceKey === "sdk_sessions").totalUnits)
            .toBe(0);
        verify.close();
    });
});
