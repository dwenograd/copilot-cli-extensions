import path from "node:path";

import { describe, expect, it } from "vitest";

import {
    RECOVERY_DAEMON_CODES,
    RECOVERY_DISCOVERY_CODES,
    recoveryDaemonPublicSummary,
    runRecoveryDaemon,
} from "../runtime/index.mjs";

function fakeBroker({
    investigations = [],
    singletonHeld = false,
} = {}) {
    let released = false;
    const lease = {
        daemonGeneration: 1,
        daemonIncarnation: "daemon-incarnation",
        leaseNonce: "daemon-nonce",
        ownerProcessId: 100,
        ownerProcessStartId: "daemon-process",
        heartbeatAtMs: 1,
        expiresAtMs: 10_000,
    };
    return {
        get released() {
            return released;
        },
        acquireRecoveryDaemonLease: () => singletonHeld
            ? { acquired: false, reason: "held", lease }
            : { acquired: true, reason: "created", lease },
        renewRecoveryDaemonLease: () => lease,
        releaseRecoveryDaemonLease: () => {
            released = true;
            return { released: true };
        },
        listInvestigations: () => investigations,
    };
}

function daemonOptions() {
    return {
        stateRoot: path.resolve("recovery-daemon-state"),
        once: true,
        leaseTtlMs: 2_000,
        heartbeatMs: 500,
    };
}

describe("same-user recovery daemon", () => {
    it("uses the catalog singleton and performs no discovery when held", async () => {
        const broker = fakeBroker({ singletonHeld: true });
        let inspected = false;
        const result = await runRecoveryDaemon(
            daemonOptions(),
            {
                broker,
                inspectRecoveryInvestigation: async () => {
                    inspected = true;
                },
            },
        );
        expect(result).toMatchObject({
            state: "singleton_held",
            code: RECOVERY_DAEMON_CODES.SINGLETON_HELD,
            cycles: 0,
        });
        expect(inspected).toBe(false);
    });

    it("ensures one eligible investigation", async () => {
        const broker = fakeBroker({
            investigations: [{
                investigationId: "eligible-investigation",
                lifecycleState: "active",
            }],
        });
        let launches = 0;
        const result = await runRecoveryDaemon(
            daemonOptions(),
            {
                broker,
                inspectRecoveryInvestigation: async () => ({
                    eligible: true,
                    state: "eligible",
                    code: RECOVERY_DISCOVERY_CODES.ELIGIBLE,
                    config: { opaque: true },
                }),
                ensureSupervisor: async () => {
                    launches += 1;
                    return {
                        action: "started",
                        acknowledgement: {
                            supervisorGeneration: 4,
                            runnerIncarnation: "runner-g4",
                        },
                    };
                },
            },
        );
        expect(launches).toBe(1);
        expect(result.operations).toEqual([{
            investigationId: "eligible-investigation",
            state: "started",
            code: RECOVERY_DAEMON_CODES.SUPERVISOR_STARTED,
        }]);
        expect(broker.released).toBe(true);
    });

    it("launches only eligible runs after unattended restart", async () => {
        const investigations = [
            {
                investigationId: "paused",
                lifecycleState: "active",
            },
            {
                investigationId: "archived",
                lifecycleState: "archived",
            },
            {
                investigationId: "tombstoned",
                lifecycleState: "tombstoned",
            },
            {
                investigationId: "auth-blocked",
                lifecycleState: "active",
            },
            {
                investigationId: "terminal",
                lifecycleState: "active",
            },
            {
                investigationId: "non-result",
                lifecycleState: "active",
            },
            {
                investigationId: "integrity-blocked",
                lifecycleState: "active",
            },
            {
                investigationId: "runtime-drift",
                lifecycleState: "active",
            },
        ];
        const codes = new Map([
            ["paused", RECOVERY_DISCOVERY_CODES.PAUSED],
            ["archived", RECOVERY_DISCOVERY_CODES.LIFECYCLE_ARCHIVED],
            ["tombstoned", RECOVERY_DISCOVERY_CODES.LIFECYCLE_TOMBSTONED],
            ["auth-blocked", RECOVERY_DISCOVERY_CODES.SDK_AUTH_UNAVAILABLE],
            ["terminal", RECOVERY_DISCOVERY_CODES.TERMINAL],
            ["non-result", RECOVERY_DISCOVERY_CODES.NON_RESULT],
            ["integrity-blocked", RECOVERY_DISCOVERY_CODES.INTEGRITY_BLOCKED],
            ["runtime-drift", RECOVERY_DISCOVERY_CODES.RUNTIME_DRIFT],
        ]);
        const blocked = new Set([
            "auth-blocked",
            "integrity-blocked",
            "runtime-drift",
        ]);
        const broker = fakeBroker({ investigations });
        const result = await runRecoveryDaemon(
            daemonOptions(),
            {
                broker,
                inspectRecoveryInvestigation: async ({
                    catalogInvestigation,
                }) => ({
                    eligible: false,
                    state: blocked.has(
                        catalogInvestigation.investigationId,
                    )
                        ? "blocked"
                        : "skipped",
                    code: codes.get(catalogInvestigation.investigationId),
                }),
                ensureSupervisor: () => {
                    throw new Error("ineligible investigation was launched");
                },
            },
        );
        expect(result.operations).toHaveLength(investigations.length);
        expect(result.operations.map((operation) => operation.code).sort())
            .toEqual([...codes.values()].sort());
    });

    it("reports a stale-lock wait without treating it as a launch", async () => {
        const broker = fakeBroker({
            investigations: [{
                investigationId: "stale-lock",
                lifecycleState: "active",
            }],
        });
        const result = await runRecoveryDaemon(
            daemonOptions(),
            {
                broker,
                inspectRecoveryInvestigation: async () => ({
                    eligible: true,
                    state: "eligible",
                    code: RECOVERY_DISCOVERY_CODES.ELIGIBLE,
                    config: {},
                }),
                ensureSupervisor: async () => {
                    throw Object.assign(new Error("lock is not stale yet"), {
                        details: { action: "waiting-for-stale-lock" },
                    });
                },
            },
        );
        expect(result.operations).toEqual([{
            investigationId: "stale-lock",
            state: "waiting",
            code: RECOVERY_DAEMON_CODES.SUPERVISOR_WAITING,
            errorCode: null,
        }]);
    });

    it("publishes only aggregate operational counts", () => {
        const summary = recoveryDaemonPublicSummary({
            state: "one_shot_complete",
            code: null,
            cycles: 1,
            scanned: 2,
            operations: [
                {
                    investigationId: "secret-investigation",
                    state: "started",
                    code: "SUPERVISOR_STARTED",
                    decision: "VERIFIED_RESULT",
                },
                {
                    investigationId: "other",
                    state: "blocked",
                    code: "SDK_AUTH_UNAVAILABLE",
                },
            ],
        });
        expect(summary).toMatchObject({
            scanned: 2,
            counts: {
                started: 1,
                blocked: 1,
            },
        });
        expect(JSON.stringify(summary)).not.toContain("secret-investigation");
        expect(JSON.stringify(summary)).not.toContain("VERIFIED_RESULT");
    });
});
