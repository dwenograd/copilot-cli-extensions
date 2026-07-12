import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { EVENT_TYPES, decideNext } from "../domain/index.mjs";
import {
    coerceSupervisorConfig,
    supervisorConfigDocument,
    supervisorConfigFingerprint,
    supervisorPaths,
} from "./config.mjs";
import { createDomainRepositoryAdapter } from "./domain-adapter.mjs";
import {
    openRepository,
    openRepositoryReadOnly,
} from "../persistence/index.mjs";
import {
    isExactPidAlive,
    readSupervisorLock,
    readSupervisorStatus,
    terminateExactSupervisor,
} from "./supervisor.mjs";
import {
    CrucibleRuntimeError,
    RUNTIME_ERROR_CODES,
} from "./errors.mjs";
import {
    atomicWriteJson,
    delay,
    ensureDirectory,
} from "./utils.mjs";

const ACKNOWLEDGED_ACTIVE_STATES = new Set(["running"]);
const ACKNOWLEDGED_FINAL_STATES = new Set(["terminal", "non_result", "pause"]);
const FAILED_ACKNOWLEDGEMENT_STATES = new Set([
    "failed",
    "failed_non_quiescent",
    "pause_pending",
    "circuit_open",
    "stopped",
]);

export function resolveNodeExecutable(env, explicitPath) {
    if (typeof explicitPath === "string" && path.isAbsolute(explicitPath)) {
        return explicitPath;
    }
    if (typeof env?.CRUCIBLE_NODE_PATH === "string"
        && path.isAbsolute(env.CRUCIBLE_NODE_PATH)) {
        return env.CRUCIBLE_NODE_PATH;
    }
    if (/^node(?:\.exe)?$/iu.test(path.basename(process.execPath))) {
        return process.execPath;
    }
    try {
        const output = execFileSync(
            process.platform === "win32" ? "where.exe" : "which",
            [process.platform === "win32" ? "node.exe" : "node"],
            {
                encoding: "utf8",
                windowsHide: true,
                stdio: ["ignore", "pipe", "ignore"],
                env,
            },
        );
        const resolved = output.split(/\r?\n/u).map((line) => line.trim()).find(Boolean);
        if (resolved && path.isAbsolute(resolved)) {
            return resolved;
        }
    } catch {
        // Fall through to the typed configuration error below.
    }
    throw new Error("Crucible supervisor requires Node on PATH or CRUCIBLE_NODE_PATH");
}

export function validateSupervisorAdmission(input, dependencies = {}) {
    const config = coerceSupervisorConfig(input, {
        env: dependencies.env ?? process.env,
    });
    const nodeExecutable = resolveNodeExecutable(
        dependencies.env ?? process.env,
        dependencies.nodeExecutable,
    );
    if (!fs.existsSync(config.runnerCliPath)
        || !fs.statSync(config.runnerCliPath).isFile()) {
        throw new Error("Crucible supervisor runner CLI is not an existing regular file");
    }
    return Object.freeze({ config, nodeExecutable });
}

export function startSupervisor(input, dependencies = {}) {
    const admission = validateSupervisorAdmission(input, dependencies);
    const { config, nodeExecutable } = admission;
    const configFingerprint = supervisorConfigFingerprint(config);
    ensureDirectory(config.paths.directory);
    atomicWriteJson(config.paths.configPath, supervisorConfigDocument(config));
    const supervisorCliPath = path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        "supervisor-cli.mjs",
    );
    const spawnProcess = dependencies.spawnProcess ?? spawn;
    const child = spawnProcess(
        nodeExecutable,
        [supervisorCliPath, "--config", config.paths.configPath],
        {
            cwd: config.runner.stateDir,
            shell: false,
            windowsHide: true,
            detached: true,
            stdio: "ignore",
        },
    );
    child.unref?.();
    return {
        pid: child.pid ?? null,
        configPath: config.paths.configPath,
        statusPath: config.paths.statusPath,
        lockPath: config.paths.lockPath,
        configFingerprint,
        deadlineMs: config.runner.deadlineMs,
    };
}

export function readStatus({ stateDir, investigationId }) {
    return readSupervisorStatus(stateDir, investigationId);
}

function acknowledgementError(message, details = {}) {
    return new CrucibleRuntimeError(
        RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
        message,
        details,
    );
}

function readAcknowledgementAuthority(config, status, dependencies) {
    const repositoryFactory =
        dependencies.acknowledgementRepositoryFactory
        ?? dependencies.repositoryFactory
        ?? openRepositoryReadOnly;
    const repository = repositoryFactory({
        file: path.join(config.runner.stateDir, "events.sqlite"),
    });
    try {
        const authority = repository.getSupervisorAuthority(
            config.runner.investigationId,
        );
        const lease = repository.getActiveLease(config.runner.investigationId);
        if (authority === null
            || lease === null
            || authority.supervisorGeneration !== status.supervisorGeneration
            || authority.supervisorNonce !== status.nonce
            || authority.currentRunnerIncarnation !== status.runnerIncarnation
            || lease.supervisorGeneration !== status.supervisorGeneration
            || lease.runnerIncarnation !== status.runnerIncarnation
            || lease.releasedAt !== null) {
            return null;
        }
        return { authority, lease };
    } finally {
        repository.close();
    }
}

export async function waitForSupervisorAcknowledgement(
    input,
    ensured,
    dependencies = {},
) {
    const config = coerceSupervisorConfig(input, {
        env: dependencies.env ?? process.env,
    });
    const timeoutMs = dependencies.acknowledgementTimeoutMs ?? 10_000;
    const pollMs = dependencies.acknowledgementPollMs ?? 25;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000
        || !Number.isSafeInteger(pollMs) || pollMs < 1 || pollMs > timeoutMs) {
        throw acknowledgementError(
            "Supervisor acknowledgement timing is invalid",
            { timeoutMs, pollMs },
        );
    }
    const expectedConfigFingerprint = supervisorConfigFingerprint(config);
    const expectedDeadlineMs = config.runner.deadlineMs;
    const expectedPid = Number.isSafeInteger(ensured?.pid) && ensured.pid > 0
        ? ensured.pid
        : Number.isSafeInteger(ensured?.status?.pid) && ensured.status.pid > 0
            ? ensured.status.pid
            : null;
    const previousGeneration = Number.isSafeInteger(
        ensured?.previousStatus?.supervisorGeneration,
    )
        ? ensured.previousStatus.supervisorGeneration
        : 0;
    const readStatusDocument =
        dependencies.readSupervisorStatus
        ?? ((stateDir, investigationId) =>
            readSupervisorStatus(stateDir, investigationId));
    const readLockDocument =
        dependencies.readSupervisorLock
        ?? readSupervisorLock;
    const isPidAlive = dependencies.isPidAlive ?? isExactPidAlive;
    const clock = dependencies.clock ?? { now: () => Date.now() };
    const sleep = dependencies.sleep
        ?? ((milliseconds) => delay(milliseconds, dependencies.timers ?? globalThis));
    const startedAt = Date.now();
    let lastObserved = null;
    let lastReason = "no supervisor status was published";

    while (Date.now() - startedAt <= timeoutMs) {
        const status = readStatusDocument(
            config.runner.stateDir,
            config.runner.investigationId,
        );
        lastObserved = status;
        if (status !== null) {
            const exactSpawn = expectedPid === null || status.pid === expectedPid;
            const exactGeneration = Number.isSafeInteger(status.supervisorGeneration)
                && status.supervisorGeneration > 0
                && (ensured?.action !== "started"
                    || status.supervisorGeneration > previousGeneration);
            const exactConfig = status.version >= 4
                && status.configFingerprint === expectedConfigFingerprint
                && status.deadlineMs === expectedDeadlineMs;
            const exactIncarnation = typeof status.runnerIncarnation === "string"
                && status.runnerIncarnation.length > 0;
            const heartbeatAgeMs = clock.now() - Date.parse(status.heartbeatAt);
            const fresh = Number.isFinite(heartbeatAgeMs)
                && heartbeatAgeMs >= -config.staleLockMs
                && heartbeatAgeMs < config.staleLockMs;

            if (ensured?.action === "already-running" && !exactConfig) {
                throw acknowledgementError(
                    "The existing supervisor does not match the requested configuration or deadline",
                    {
                        expectedConfigFingerprint,
                        actualConfigFingerprint: status.configFingerprint ?? null,
                        expectedDeadlineMs,
                        actualDeadlineMs: status.deadlineMs ?? null,
                    },
                );
            }
            if (ensured?.action === "already-running"
                && !ACKNOWLEDGED_ACTIVE_STATES.has(status.state)) {
                throw acknowledgementError(
                    "An exiting or completed supervisor cannot acknowledge a new start",
                    { state: status.state ?? null },
                );
            }
            if (FAILED_ACKNOWLEDGEMENT_STATES.has(status.state)
                && exactSpawn
                && exactConfig) {
                throw acknowledgementError(
                    "Supervisor exited before acknowledging a runnable incarnation",
                    { state: status.state },
                );
            }

            const activeState = ACKNOWLEDGED_ACTIVE_STATES.has(status.state);
            const finalState = ACKNOWLEDGED_FINAL_STATES.has(status.state)
                && ensured?.action === "started";
            if (exactSpawn && exactGeneration && exactConfig && exactIncarnation && fresh
                && (activeState || finalState)) {
                let lock = null;
                try {
                    lock = readLockDocument(config.paths.lockPath);
                } catch {
                    lock = null;
                }
                const liveOwner = lock !== null
                    && lock.pid === status.pid
                    && lock.nonce === status.nonce
                    && lock.supervisorGeneration === status.supervisorGeneration
                    && isPidAlive(status.pid) === true;
                if (finalState || liveOwner) {
                    let persisted = null;
                    try {
                        persisted = readAcknowledgementAuthority(
                            config,
                            status,
                            dependencies,
                        );
                    } catch (error) {
                        lastReason = `repository acknowledgement unavailable: ${
                            error?.message ?? String(error)
                        }`;
                    }
                    if (persisted !== null) {
                        return Object.freeze({
                            ...ensured,
                            acknowledged: true,
                            status,
                            acknowledgement: Object.freeze({
                                supervisorGeneration: status.supervisorGeneration,
                                runnerIncarnation: status.runnerIncarnation,
                                leaseId: persisted.lease.leaseId,
                                fencingToken: persisted.lease.fencingToken,
                                configFingerprint: expectedConfigFingerprint,
                                deadlineMs: expectedDeadlineMs,
                            }),
                        });
                    }
                    lastReason = "repository generation/incarnation/lease did not match status";
                } else {
                    lastReason = "supervisor owner is not alive under the published lock";
                }
            } else {
                lastReason = "status did not match the expected spawn, configuration, or runnable state";
            }
        }
        await sleep(pollMs);
    }

    throw acknowledgementError(
        "Supervisor did not publish a matching generation/incarnation/config/deadline acknowledgement",
        {
            action: ensured?.action ?? null,
            expectedPid,
            previousGeneration,
            expectedConfigFingerprint,
            expectedDeadlineMs,
            lastReason,
            lastState: lastObserved?.state ?? null,
            lastGeneration: lastObserved?.supervisorGeneration ?? null,
            lastIncarnation: lastObserved?.runnerIncarnation ?? null,
        },
    );
}

export function requestStop({
    stateDir,
    investigationId,
    reason = "Stop requested by the Crucible extension adapter.",
    pauseRequested = true,
    requestId = null,
    repositoryFactory = openRepository,
} = {}) {
    const repository = repositoryFactory({
        file: path.join(stateDir, "events.sqlite"),
    });
    try {
        const adapter = createDomainRepositoryAdapter({
            repository,
            investigationId,
        });
        const result = adapter.requestStop({
            requestId: requestId ?? `stop-${randomUUID()}`,
            reason,
            pauseRequested,
        });
        const operationalNonResult = adapter.latestOperationalNonResult();
        let final = result;
        if (operationalNonResult === null
            && result.aggregate.terminal === null
            && result.aggregate.pause === null
            && result.aggregate.nonResults.length === 0) {
            const recommendation = decideNext(result.aggregate);
            if (recommendation.event?.type === EVENT_TYPES.INVESTIGATION_PAUSED) {
                final = adapter.appendKernelDecision();
            }
        }
        return {
            appended: result.domainEvent !== null,
            aggregate: final.aggregate,
            domainEvent: result.domainEvent,
            pausePersisted: final.aggregate.pause !== null,
            operationalNonResult,
        };
    } finally {
        repository.close();
    }
}

export function ensureSupervisor(input, dependencies = {}) {
    const config = coerceSupervisorConfig(input, {
        env: dependencies.env ?? process.env,
    });
    const finish = (result) => {
        if (dependencies.requireAcknowledgement !== true) return result;
        if (!["started", "already-running"].includes(result?.action)) {
            return Promise.reject(acknowledgementError(
                "Supervisor did not enter an acknowledgement-eligible state",
                {
                    action: result?.action ?? null,
                    reason: result?.reason ?? null,
                },
            ));
        }
        return waitForSupervisorAcknowledgement(config, result, dependencies);
    };
    const status = readSupervisorStatus(
        config.runner.stateDir,
        config.runner.investigationId,
    );
    const isPidAlive = dependencies.isPidAlive ?? isExactPidAlive;
    const now = dependencies.clock?.now?.() ?? Date.now();
    const resetOperationalState = dependencies.resetOperationalState === true;
    if (status !== null) {
        if (status.state === "terminal") {
            return finish({ action: "not-restarted", reason: status.state, status });
        }
        if (["failed_non_quiescent", "pause_pending"].includes(status.state)) {
            return finish({
                action: "not-restarted",
                reason: status.state,
                interventionRequired: true,
                status,
            });
        }
        if (["non_result", "pause", "circuit_open", "failed"].includes(status.state)
            && !resetOperationalState) {
            return finish({ action: "not-restarted", reason: status.state, status });
        }
    }
    let lock = null;
    let malformedLock = false;
    try {
        lock = readSupervisorLock(config.paths.lockPath);
    } catch {
        malformedLock = fs.existsSync(config.paths.lockPath);
    }
    if (lock !== null) {
        const heartbeatAgeMs = status === null
            ? Number.POSITIVE_INFINITY
            : now - Date.parse(status.heartbeatAt);
        const matchingFreshOwner = status !== null
            && status.pid === lock.pid
            && status.nonce === lock.nonce
            && status.supervisorGeneration === lock.supervisorGeneration
            && Number.isFinite(heartbeatAgeMs)
            && heartbeatAgeMs >= -config.staleLockMs
            && heartbeatAgeMs < config.staleLockMs
            && isPidAlive(lock.pid);
        if (matchingFreshOwner) {
            return finish({ action: "already-running", status, lock });
        }
        const lockAgeMs = now - fs.statSync(config.paths.lockPath).mtimeMs;
        if (!Number.isFinite(lockAgeMs) || lockAgeMs < config.staleLockMs) {
            return finish({
                action: "waiting-for-stale-lock",
                status,
                lock,
                ageMs: lockAgeMs,
            });
        }
    } else if (malformedLock) {
        const lockAgeMs = now - fs.statSync(config.paths.lockPath).mtimeMs;
        if (!Number.isFinite(lockAgeMs) || lockAgeMs < config.staleLockMs) {
            return finish({
                action: "waiting-for-stale-lock",
                status,
                lock: null,
                malformedLock: true,
                ageMs: lockAgeMs,
            });
        }
    }
    return finish({
        action: "started",
        ...startSupervisor(config, dependencies),
        previousStatus: status,
    });
}

export function terminateSupervisor({
    stateDir,
    investigationId,
    expectedNonce,
    expectedGeneration,
    signal = "SIGTERM",
    processApi = process,
} = {}) {
    const paths = supervisorPaths(stateDir, investigationId);
    return terminateExactSupervisor({
        lockPath: paths.lockPath,
        statusPath: paths.statusPath,
        stopRequestPath: paths.stopRequestPath,
        expectedNonce,
        expectedGeneration,
        signal,
        processApi,
    });
}
