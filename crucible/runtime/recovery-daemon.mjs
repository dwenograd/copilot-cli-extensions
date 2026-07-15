import { randomBytes, randomUUID } from "node:crypto";

import {
    discoverCatalogInvestigations,
    inspectRecoveryInvestigation,
    RECOVERY_DISCOVERY_CODES,
} from "./discovery.mjs";
import { ensureSupervisor } from "./extension-adapter.mjs";
import { createProcessIdentityAdapter } from "./process-identity.mjs";
import { openResourceBrokerFromStateRoot } from "./resource-broker.mjs";

export const RECOVERY_DAEMON_CODES = Object.freeze({
    SINGLETON_HELD: "RECOVERY_DAEMON_SINGLETON_HELD",
    SUPERVISOR_STARTED: "SUPERVISOR_STARTED",
    SUPERVISOR_ALREADY_RUNNING: "SUPERVISOR_ALREADY_RUNNING",
    SUPERVISOR_WAITING: "SUPERVISOR_WAITING",
    SUPERVISOR_ENSURE_FAILED: "SUPERVISOR_ENSURE_FAILED",
});

const DEFAULT_INTERVAL_MS = 30_000;
const DEFAULT_LEASE_TTL_MS = 60_000;
const DEFAULT_HEARTBEAT_MS = 10_000;

function boundedInteger(value, field, fallback, minimum, maximum) {
    const normalized = value ?? fallback;
    if (!Number.isSafeInteger(normalized)
        || normalized < minimum
        || normalized > maximum) {
        throw new TypeError(
            `${field} must be an integer in ${minimum}..${maximum}`,
        );
    }
    return normalized;
}

function operationAuthority(result) {
    const supervisorGeneration =
        result?.acknowledgement?.supervisorGeneration
        ?? result?.status?.supervisorGeneration
        ?? result?.supervisorGeneration
        ?? null;
    const runnerIncarnation =
        result?.acknowledgement?.runnerIncarnation
        ?? result?.status?.runnerIncarnation
        ?? result?.runnerIncarnation
        ?? null;
    return Number.isSafeInteger(supervisorGeneration)
        && supervisorGeneration > 0
        && typeof runnerIncarnation === "string"
        && runnerIncarnation.length > 0
        ? { supervisorGeneration, runnerIncarnation }
        : {};
}

function operationStateForDiscovery(discovery) {
    if (discovery.state === "running") return "running";
    if (discovery.state === "skipped") return "skipped";
    if (discovery.state === "blocked") return "blocked";
    return "eligible";
}

function safeRecord(broker, leaseController, input) {
    leaseController.assertCurrent();
    return broker.recordRecoveryOperation({
        lease: leaseController.lease,
        ...input,
    });
}

function createLeaseController({
    broker,
    lease,
    ttlMs,
    heartbeatMs,
    timers,
}) {
    let current = lease;
    let failure = null;
    let timer = null;
    const renew = () => {
        if (failure !== null) throw failure;
        try {
            current = broker.renewRecoveryDaemonLease({
                lease: current,
                ttlMs,
            });
            return current;
        } catch (error) {
            failure = error;
            throw error;
        }
    };
    return {
        get lease() {
            return current;
        },
        start() {
            if (timer !== null) return;
            timer = timers.setInterval(() => {
                try {
                    renew();
                } catch {
                    // The active cycle observes failure before another launch.
                }
            }, heartbeatMs);
            timer?.unref?.();
        },
        stop() {
            if (timer !== null) {
                timers.clearInterval(timer);
                timer = null;
            }
        },
        renew,
        assertCurrent() {
            if (failure !== null) throw failure;
            return current;
        },
    };
}

async function waitForNextCycle(
    milliseconds,
    signal,
    { timers, sleep = null },
) {
    if (sleep !== null) {
        await sleep(milliseconds);
        return;
    }
    await new Promise((resolve) => {
        let timer = null;
        const finish = () => {
            if (timer !== null) timers.clearTimeout(timer);
            signal?.removeEventListener?.("abort", finish);
            resolve();
        };
        if (signal?.aborted === true) {
            finish();
            return;
        }
        timer = timers.setTimeout(finish, milliseconds);
        signal?.addEventListener?.("abort", finish, { once: true });
    });
}

export async function runRecoveryCycle({
    stateRoot,
    broker,
    leaseController,
    env = process.env,
} = {}, dependencies = {}) {
    leaseController.renew();
    const discover = dependencies.discoverCatalogInvestigations
        ?? discoverCatalogInvestigations;
    const inspect = dependencies.inspectRecoveryInvestigation
        ?? inspectRecoveryInvestigation;
    const ensure = dependencies.ensureSupervisor ?? ensureSupervisor;
    const investigations = discover(broker);
    const operations = [];

    for (const catalogInvestigation of investigations) {
        leaseController.assertCurrent();
        let discovery;
        try {
            discovery = await inspect({
                stateRoot,
                catalogInvestigation,
                broker,
                daemonLease: leaseController.lease,
                env,
            }, dependencies.discoveryDependencies ?? {});
        } catch (error) {
            discovery = {
                eligible: false,
                state: "blocked",
                code: RECOVERY_DISCOVERY_CODES.INTEGRITY_BLOCKED,
                errorCode: error?.code ?? null,
            };
        }

        if (discovery.eligible !== true) {
            const authority = operationAuthority(discovery);
            safeRecord(broker, leaseController, {
                investigationId: catalogInvestigation.investigationId,
                state: operationStateForDiscovery(discovery),
                code: discovery.code,
                ...authority,
            });
            operations.push(Object.freeze({
                investigationId: catalogInvestigation.investigationId,
                state: operationStateForDiscovery(discovery),
                code: discovery.code,
            }));
            continue;
        }

        safeRecord(broker, leaseController, {
            investigationId: catalogInvestigation.investigationId,
            state: "eligible",
            code: discovery.code,
        });
        leaseController.renew();
        try {
            const ensured = await ensure(discovery.config, {
                env,
                requireAcknowledgement: true,
                ...(dependencies.ensureDependencies ?? {}),
            });
            let state;
            let code;
            if (ensured?.action === "started") {
                state = "started";
                code = RECOVERY_DAEMON_CODES.SUPERVISOR_STARTED;
            } else if (ensured?.action === "already-running") {
                state = "running";
                code = RECOVERY_DAEMON_CODES.SUPERVISOR_ALREADY_RUNNING;
            } else {
                state = "waiting";
                code = RECOVERY_DAEMON_CODES.SUPERVISOR_WAITING;
            }
            safeRecord(broker, leaseController, {
                investigationId: catalogInvestigation.investigationId,
                state,
                code,
                ...operationAuthority(ensured),
            });
            operations.push(Object.freeze({
                investigationId: catalogInvestigation.investigationId,
                state,
                code,
            }));
        } catch (error) {
            if (error?.recoveryDaemonFatal === true) throw error;
            const waiting = error?.details?.action
                === "waiting-for-stale-lock";
            const state = waiting ? "waiting" : "failed";
            const code = waiting
                ? RECOVERY_DAEMON_CODES.SUPERVISOR_WAITING
                : RECOVERY_DAEMON_CODES.SUPERVISOR_ENSURE_FAILED;
            safeRecord(broker, leaseController, {
                investigationId: catalogInvestigation.investigationId,
                state,
                code,
            });
            operations.push(Object.freeze({
                investigationId: catalogInvestigation.investigationId,
                state,
                code,
                errorCode: error?.code ?? null,
            }));
        }
    }
    return Object.freeze({
        scanned: investigations.length,
        operations: Object.freeze(operations),
    });
}

export async function runRecoveryDaemon({
    stateRoot,
    once = false,
    intervalMs = DEFAULT_INTERVAL_MS,
    leaseTtlMs = DEFAULT_LEASE_TTL_MS,
    heartbeatMs = DEFAULT_HEARTBEAT_MS,
    env = process.env,
    signal = null,
} = {}, dependencies = {}) {
    const interval = boundedInteger(
        intervalMs,
        "intervalMs",
        DEFAULT_INTERVAL_MS,
        100,
        24 * 60 * 60_000,
    );
    const ttl = boundedInteger(
        leaseTtlMs,
        "leaseTtlMs",
        DEFAULT_LEASE_TTL_MS,
        1_000,
        10 * 60_000,
    );
    const heartbeat = boundedInteger(
        heartbeatMs,
        "heartbeatMs",
        DEFAULT_HEARTBEAT_MS,
        100,
        ttl - 1,
    );
    if (heartbeat * 2 >= ttl) {
        throw new TypeError(
            "heartbeatMs must be less than half of leaseTtlMs",
        );
    }
    const brokerOwned = dependencies.broker === undefined;
    const processIdentity = dependencies.processIdentityAdapter
        ?? (brokerOwned
            ? createProcessIdentityAdapter(
                dependencies.processIdentityDependencies,
            )
            : null);
    const daemonIncarnation =
        dependencies.daemonIncarnation ?? randomUUID();
    const ownerProcessId = dependencies.ownerProcessId ?? process.pid;
    const ownerProcessStartId = dependencies.ownerProcessStartId
        ?? processIdentity?.current(ownerProcessId)
        ?? daemonIncarnation;
    const broker = dependencies.broker ?? (
        dependencies.openResourceBrokerFromStateRoot
        ?? openResourceBrokerFromStateRoot
    )({
        stateRoot,
        env,
        isRecoveryOwnerAlive:
            dependencies.isRecoveryOwnerAlive
            ?? ((owner) => processIdentity.isAlive(owner)),
    });
    const leaseNonce = dependencies.leaseNonce
        ?? randomBytes(24).toString("hex");
    const timers = dependencies.timers ?? globalThis;
    const acquisition = broker.acquireRecoveryDaemonLease({
        daemonIncarnation,
        leaseNonce,
        ownerProcessId,
        ownerProcessStartId,
        ttlMs: ttl,
    });
    if (acquisition.acquired !== true) {
        if (brokerOwned) broker.close();
        return Object.freeze({
            state: "singleton_held",
            code: RECOVERY_DAEMON_CODES.SINGLETON_HELD,
            cycles: 0,
            scanned: 0,
            operations: Object.freeze([]),
        });
    }

    const leaseController = createLeaseController({
        broker,
        lease: acquisition.lease,
        ttlMs: ttl,
        heartbeatMs: heartbeat,
        timers,
    });
    leaseController.start();
    let cycles = 0;
    let scanned = 0;
    let operations = [];
    let releaseReason = "completed";
    let primaryError = null;
    try {
        for (;;) {
            if (signal?.aborted === true) {
                releaseReason = "aborted";
                break;
            }
            const cycle = await runRecoveryCycle({
                stateRoot,
                broker,
                leaseController,
                env,
            }, dependencies);
            cycles += 1;
            scanned += cycle.scanned;
            operations = [...cycle.operations];
            if (once) break;
            await waitForNextCycle(
                interval,
                signal,
                {
                    timers,
                    sleep: dependencies.sleep ?? null,
                },
            );
        }
        return Object.freeze({
            state: once ? "one_shot_complete" : "stopped",
            code: null,
            cycles,
            scanned,
            operations: Object.freeze(operations),
        });
    } catch (error) {
        releaseReason = "failed";
        primaryError = error;
        throw error;
    } finally {
        const teardownErrors = [];
        try {
            leaseController.stop();
        } catch (error) {
            teardownErrors.push(error);
        }
        try {
            broker.releaseRecoveryDaemonLease({
                lease: leaseController.lease,
                reason: releaseReason,
            });
        } catch (error) {
            teardownErrors.push(error);
        }
        if (brokerOwned) {
            try {
                broker.close();
            } catch (error) {
                teardownErrors.push(error);
            }
        }
        if (primaryError === null && teardownErrors.length > 0) {
            throw teardownErrors.length === 1
                ? teardownErrors[0]
                : new AggregateError(
                    teardownErrors,
                    "Crucible recovery daemon teardown failed",
                );
        }
    }
}

export function recoveryDaemonPublicSummary(result) {
    const counts = {
        started: 0,
        running: 0,
        waiting: 0,
        skipped: 0,
        blocked: 0,
        failed: 0,
    };
    for (const operation of result.operations ?? []) {
        if (Object.hasOwn(counts, operation.state)) {
            counts[operation.state] += 1;
        }
    }
    return Object.freeze({
        ok: true,
        state: result.state,
        code: result.code ?? null,
        cycles: result.cycles,
        scanned: result.scanned,
        counts: Object.freeze(counts),
    });
}
