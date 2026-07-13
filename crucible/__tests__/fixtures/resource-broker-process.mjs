import fs from "node:fs";

import { openResourceBroker } from "../../runtime/resource-broker.mjs";

function wait(delayMs) {
    return new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function waitForFile(file, timeoutMs = 15_000) {
    const deadline = Date.now() + timeoutMs;
    while (!fs.existsSync(file)) {
        if (Date.now() >= deadline) {
            throw new Error(`timed out waiting for barrier ${file}`);
        }
        await wait(10);
    }
}

function publish(file, value) {
    fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { flag: "wx" });
}

const specPath = process.argv[2];
if (!specPath) {
    throw new Error("resource broker process fixture requires a spec path");
}
const spec = JSON.parse(fs.readFileSync(specPath, "utf8"));
let broker = null;

try {
    await waitForFile(spec.startBarrier);
    broker = openResourceBroker({
        stateRoot: spec.stateRoot,
        config: spec.config,
    });
    let acquired;
    try {
        acquired = broker.acquire({
            investigationId: spec.investigationId,
            ownerId: spec.ownerId,
            ownerProcessId: process.pid,
            ownerProcessStartId: spec.ownerProcessStartId,
            supervisorGeneration: spec.supervisorGeneration,
            runnerIncarnation: spec.runnerIncarnation,
            attemptId: spec.attemptId,
            logicalEffectId: spec.logicalEffectId,
            reservation: spec.reservation,
            ttlMs: spec.ttlMs,
        });
    } catch (error) {
        publish(spec.resultPath, {
            status: "error",
            code: error?.code ?? "UNEXPECTED_ERROR",
            message: error?.message ?? String(error),
        });
        broker.close();
        process.exit(0);
    }

    publish(spec.resultPath, {
        status: acquired.status,
        lease: acquired.lease,
        deficit: acquired.deficit ?? null,
    });
    if (acquired.status !== "acquired") {
        broker.close();
        process.exit(0);
    }
    if (spec.mode === "hang") {
        setInterval(() => {}, 60_000);
    } else {
        await waitForFile(spec.releaseBarrier);
        broker.release({
            lease: acquired.lease,
            usage: spec.usage ?? {},
            releaseId: spec.releaseId ?? "release",
        });
        broker.close();
        process.exit(0);
    }
} catch (error) {
    if (!fs.existsSync(spec.resultPath)) {
        publish(spec.resultPath, {
            status: "fixture_error",
            code: error?.code ?? "UNEXPECTED_ERROR",
            message: error?.message ?? String(error),
            stack: error?.stack ?? null,
        });
    }
    try {
        broker?.close();
    } catch {
        // The primary fixture failure is already recorded.
    }
    process.exit(1);
}
