import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    afterAll,
    beforeAll,
    describe,
    expect,
    it,
} from "vitest";

import {
    configureRecoveryTask,
    createPowerShellTaskSchedulerAdapter,
    installRecoveryTask,
} from "../../tools/recovery-task.mjs";
import { readStatus } from "../../runtime/index.mjs";
import {
    acquireRecoveryTaskConformanceLock,
    cleanupRecoveryTaskFixtureRoot,
    cleanupRecoveryTaskFixtureRoots,
    claimRecoveryTaskFixtureRoot,
    prepareRecoveryTaskCleanup,
    readRecoveryLease,
    readRecoveryOperation,
    releaseRecoveryTaskConformanceLock,
    seedEligibleRecoveryInvestigation,
} from "./recovery-task-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
let conformanceLock = null;

function taskSchedulerSupported() {
    if (process.platform !== "win32") return false;
    const result = spawnSync(
        "powershell.exe",
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-Command Get-ScheduledTask,Register-ScheduledTask,Unregister-ScheduledTask,Start-ScheduledTask,Stop-ScheduledTask -ErrorAction Stop | Out-Null",
        ],
        {
            encoding: "utf8",
            windowsHide: true,
        },
    );
    return result.error === undefined && result.status === 0;
}

const ENABLED = process.env.CRUCIBLE_WINDOWS_CONFORMANCE === "1"
    && taskSchedulerSupported();

function pidAlive(pid) {
    if (!Number.isSafeInteger(pid) || pid < 1) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

async function waitFor(read, accept, label, timeoutMs = 45_000) {
    const deadline = Date.now() + timeoutMs;
    let value = null;
    let lastError = null;
    while (Date.now() < deadline) {
        try {
            value = read();
            lastError = null;
            if (accept(value)) return value;
        } catch (error) {
            lastError = error;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(
        `timed out waiting for ${label}: value=${JSON.stringify(value)}; `
        + `lastError=${lastError?.message ?? "none"}`,
        lastError === null ? undefined : { cause: lastError },
    );
}

async function stopScheduledDaemon(adapter, spec, lease, label) {
    adapter.stop(spec);
    await waitFor(
        () => pidAlive(lease.ownerProcessId),
        (alive) => !alive,
        `${label} daemon exit`,
    );
    await waitFor(
        () => adapter.runtime(spec),
        (runtime) => runtime?.state !== "Running",
        `${label} task readiness`,
    );
}

beforeAll(async () => {
    if (!ENABLED) return;
    conformanceLock = await acquireRecoveryTaskConformanceLock();
    await cleanupRecoveryTaskFixtureRoots();
}, 180_000);

afterAll(async () => {
    if (!ENABLED) return;
    try {
        await cleanupRecoveryTaskFixtureRoots();
    } finally {
        releaseRecoveryTaskConformanceLock(conformanceLock);
        conformanceLock = null;
    }
}, 180_000);

describe.skipIf(!ENABLED)("Windows Task Scheduler recovery conformance", () => {
    it("discovers and starts one eligible investigation through the exact installed action", async () => {
        const fixtureRoot = fs.mkdtempSync(
            path.join(HERE, ".recovery-task-conformance-"),
        );
        const stateRoot = path.join(fixtureRoot, "state-root");
        claimRecoveryTaskFixtureRoot(fixtureRoot);
        const adapter = createPowerShellTaskSchedulerAdapter();
        let cleanupComplete = false;
        try {
            const investigation =
                await seedEligibleRecoveryInvestigation(
                    stateRoot,
                    fixtureRoot,
                );
            const configured = await configureRecoveryTask({
                stateRoot,
                nodePath: process.execPath,
            }, {
                adapter,
                env: investigation.env,
            });
            const options = {
                stateRoot,
                nodePath: configured.spec.runtime.nodePath,
                daemonPath: configured.spec.runtime.daemonPath,
                expectedNodeSha256: configured.spec.runtime.nodeSha256,
                expectedDaemonSha256:
                    configured.spec.runtime.daemonSha256,
            };
            prepareRecoveryTaskCleanup({
                root: fixtureRoot,
                options,
                investigation,
            });
            const installed = await installRecoveryTask(options, {
                adapter,
                env: investigation.env,
            });
            expect(installed).toMatchObject({
                installed: true,
                unchanged: false,
            });

            adapter.start(installed.spec);
            const firstLease = await waitFor(
                () => readRecoveryLease(stateRoot),
                (lease) => lease !== null && pidAlive(lease.ownerProcessId),
                "first scheduled recovery daemon",
            );
            const recovered = await waitFor(
                () => ({
                    operation: readRecoveryOperation(
                        stateRoot,
                        investigation.investigationId,
                    ),
                    status: readStatus({
                        stateDir: investigation.stateDir,
                        investigationId: investigation.investigationId,
                    }),
                }),
                ({ operation, status }) =>
                    operation?.state === "eligible"
                    && operation?.code === "RECOVERY_ELIGIBLE"
                    && Number.isSafeInteger(status?.supervisorGeneration)
                    && status.supervisorGeneration >= 2
                    && status.runtimeIdentity?.verified === true
                    && status.resourceBroker?.healthy === true,
                "eligible investigation recovery",
            );
            expect(recovered.operation).toMatchObject({
                investigationId: investigation.investigationId,
                state: "eligible",
                code: "RECOVERY_ELIGIBLE",
            });
            expect(recovered.status).toMatchObject({
                runtimeIdentity: { verified: true },
                resourceBroker: { healthy: true },
            });
            expect(recovered.status.supervisorGeneration)
                .toBeGreaterThanOrEqual(2);
            await stopScheduledDaemon(
                adapter,
                installed.spec,
                firstLease,
                "first scheduled",
            );

            adapter.start(installed.spec);
            const secondLease = await waitFor(
                () => readRecoveryLease(stateRoot),
                (lease) =>
                    lease !== null
                    && lease.daemonGeneration > firstLease.daemonGeneration
                    && pidAlive(lease.ownerProcessId),
                "replacement scheduled recovery daemon",
            );
            await stopScheduledDaemon(
                adapter,
                installed.spec,
                secondLease,
                "replacement scheduled",
            );

            const manual = spawnSync(
                process.execPath,
                [
                    installed.spec.runtime.daemonPath,
                    "--once",
                    "--state-root",
                    stateRoot,
                    "--expected-node-sha256",
                    installed.spec.runtime.nodeSha256,
                    "--expected-daemon-sha256",
                    installed.spec.runtime.daemonSha256,
                ],
                {
                    encoding: "utf8",
                    env: investigation.env,
                    timeout: 60_000,
                    windowsHide: true,
                },
            );
            expect(manual.error).toBeUndefined();
            expect(manual.status, manual.stderr).toBe(0);
            const oneShot = JSON.parse(manual.stdout);
            expect(oneShot).toMatchObject({
                ok: true,
                state: "one_shot_complete",
                scanned: 1,
            });
            expect(Object.values(oneShot.counts)
                .reduce((total, count) => total + count, 0)).toBe(1);

            adapter.start(installed.spec);
            const uninstallLease = await waitFor(
                () => readRecoveryLease(stateRoot),
                (lease) =>
                    lease !== null
                    && lease.daemonGeneration > secondLease.daemonGeneration
                    && pidAlive(lease.ownerProcessId),
                "scheduled recovery daemon before uninstall",
            );
            const cleanup = await cleanupRecoveryTaskFixtureRoot(fixtureRoot);
            cleanupComplete = true;
            expect(cleanup).toEqual({
                taskAbsent: true,
                rootRemoved: true,
            });
            await waitFor(
                () => pidAlive(uninstallLease.ownerProcessId),
                (alive) => !alive,
                "scheduled daemon exit after exact uninstall",
            );
        } finally {
            if (!cleanupComplete && fs.existsSync(fixtureRoot)) {
                await cleanupRecoveryTaskFixtureRoot(fixtureRoot);
            }
        }
    }, 180_000);
});
