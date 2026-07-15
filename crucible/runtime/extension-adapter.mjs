import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { EVENT_TYPES } from "../domain/index.mjs";
import {
    coerceSupervisorConfig,
    supervisorConfigDocument,
    supervisorConfigFingerprint,
    supervisorPaths,
} from "./config.mjs";
import { createDomainRepositoryAdapter } from "./domain-adapter.mjs";
import {
    openArtifactStore,
    openArtifactStoreReadOnly,
    openRepository,
    openRepositoryReadOnly,
} from "../persistence/index.mjs";
import {
    openResourceBroker,
} from "./resource-broker.mjs";
import {
    assertSupervisorConfigMatchesRuntimeAuthority,
    supervisorConfigFromRuntimeAuthority,
    verifyRuntimeConfigAuthority,
} from "./config-authority.mjs";
import {
    isExactPidAlive,
    readSupervisorLock,
    readSupervisorStatus,
} from "./supervisor.mjs";
import {
    CrucibleRuntimeError,
    RUNTIME_ERROR_CODES,
} from "./errors.mjs";
import {
    buildQuiescenceSnapshot,
    ensureStopDomainIntent,
    persistPausePending,
    persistQuiescentStopBarrier,
    stopControlPaths,
    waitForQuiescentStopAcknowledgement,
    writeSupervisorStopSignal,
} from "./control-channel.mjs";
import {
    atomicWriteJson,
    delay,
    ensureDirectory,
    sha256Hex,
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

function verifyPersistedSupervisorRuntime(config, nodeExecutable, dependencies) {
    if (typeof dependencies.verifySupervisorRuntimeAuthority === "function") {
        return dependencies.verifySupervisorRuntimeAuthority({
            config,
            nodeExecutable,
        });
    }
    if (config.runner.resourceBroker === null) {
        return null;
    }
    const eventsDbPath = path.join(config.runner.stateDir, "events.sqlite");
    if (!fs.existsSync(eventsDbPath)) {
        if (config.runner.resourceBroker !== null) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.RUNTIME_DRIFT,
                "Supervisor launch requires the persisted runtime authority",
                { eventsDbPath },
            );
        }
        return null;
    }
    const repository = openRepositoryReadOnly({ file: eventsDbPath });
    try {
        const adapter = createDomainRepositoryAdapter({
            repository,
            artifactStore: openArtifactStoreReadOnly({
                root: config.runner.artifactRoot,
            }),
            investigationId: config.runner.investigationId,
            ensure: false,
        });
        const aggregate = adapter.replay().aggregate;
        const authority = aggregate.runtimeConfigAuthority;
        if (authority === null
            || authority.fingerprint !== aggregate.runtimeConfigFingerprint) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.RUNTIME_DRIFT,
                "Supervisor launch has no valid persisted runtime authority",
                { investigationId: config.runner.investigationId },
            );
        }
        assertSupervisorConfigMatchesRuntimeAuthority(config, authority, {
            env: dependencies.env ?? process.env,
        });
        const verified = verifyRuntimeConfigAuthority(authority, {
            env: dependencies.env ?? process.env,
            deadlineMs: config.runner.deadlineMs,
            expectedInvestigationId: config.runner.investigationId,
            expectedStateDir: config.runner.stateDir,
            expectedArtifactRoot: config.runner.artifactRoot,
            nodeExecutable,
        });
        return Object.freeze({
            authority: verified.authority,
            runtimeIdentityRoot: verified.authority.runtimeIdentity.root,
            runtimeConfigFingerprint: verified.authority.fingerprint,
        });
    } finally {
        repository.close();
    }
}

function prepareResourceBroker(config, dependencies) {
    if (config.runner.resourceBroker === null) return null;
    const factory = dependencies.resourceBrokerFactory ?? openResourceBroker;
    const broker = factory({
        stateRoot: config.runner.resourceBroker.stateRoot,
        config: config.runner.resourceBroker.config,
        env: dependencies.env ?? process.env,
    });
    try {
        broker.verifyIntegrity?.();
        return Object.freeze({
            configFingerprint: broker.configFingerprint,
            limitsFingerprint:
                config.runner.resourceBroker.limitsFingerprint,
            databaseFile: broker.databaseFile ?? null,
        });
    } finally {
        broker.close?.();
    }
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
    dependencies.beforeSupervisorLaunch?.({
        config,
        nodeExecutable,
        supervisorCliPath,
    });
    const runtime = verifyPersistedSupervisorRuntime(
        config,
        nodeExecutable,
        dependencies,
    );
    const broker = prepareResourceBroker(config, dependencies);
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
        runtime,
        broker,
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
        const stop = typeof repository.getQuiescentStop === "function"
            ? repository.getQuiescentStop(config.runner.investigationId)
            : null;
        if (status.state === "pause"
            && status.quiescent === true
            && stop?.state === "PAUSED_QUIESCENT"
            && stop.quiescent === true
            && authority !== null
            && authority.supervisorGeneration
                === status.supervisorGeneration
            && authority.supervisorNonce === status.nonce
            && lease === null
            && (
                typeof repository.listCommittableAttempts !== "function"
                || repository.listCommittableAttempts(
                    config.runner.investigationId,
                ).length === 0
            )) {
            return { authority, lease: null, stop };
        }
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
            const exactConfig = status.version === 4
                && status.configFingerprint === expectedConfigFingerprint
                && status.deadlineMs === expectedDeadlineMs;
            const exactIncarnation = (
                typeof status.runnerIncarnation === "string"
                && status.runnerIncarnation.length > 0
            ) || (
                status.state === "pause"
                && status.quiescent === true
            );
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
                                leaseId: persisted.lease?.leaseId ?? null,
                                fencingToken:
                                    persisted.lease?.fencingToken ?? null,
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
    artifactRoot = null,
    investigationId,
    reason = "Stop requested by the Crucible extension adapter.",
    pauseRequested = true,
    forceQuiescence = false,
    requestId = null,
    repositoryFactory = openRepository,
    artifactStoreFactory = openArtifactStore,
    readLock = readSupervisorLock,
    readSupervisorState = readSupervisorStatus,
    isPidAlive = isExactPidAlive,
    env = process.env,
    resourceBrokerFactory = openResourceBroker,
    clock = {
        now: () => Date.now(),
        isoNow: () => new Date().toISOString(),
    },
} = {}) {
    if (typeof forceQuiescence !== "boolean") {
        throw new TypeError("forceQuiescence must be boolean");
    }
    const repository = repositoryFactory({
        file: path.join(stateDir, "events.sqlite"),
    });
    try {
        const resolvedArtifactRoot = artifactRoot
            ?? path.join(path.dirname(stateDir), "artifacts");
        const adapter = createDomainRepositoryAdapter({
            repository,
            artifactStore: artifactStoreFactory({
                root: resolvedArtifactRoot,
            }),
            investigationId,
        });
        const resolvedRequestId = requestId ?? `stop-${randomUUID()}`;
        const operationalNonResult = adapter.latestOperationalNonResult();
        const initial = adapter.replay();
        const existingStop = repository.getQuiescentStop(investigationId);
        if (!forceQuiescence && (
            initial.aggregate.terminal !== null
            || initial.aggregate.nonResults.length > 0
            || operationalNonResult !== null
            || (
                initial.aggregate.pause !== null
                && existingStop?.state === "PAUSED_QUIESCENT"
            ))) {
            return {
                appended: false,
                aggregate: initial.aggregate,
                domainEvent: null,
                pausePersisted: initial.aggregate.pause !== null,
                operationalNonResult,
                stop: existingStop,
                signal: null,
                quiescent: existingStop?.quiescent === true,
                interventionRequired:
                    existingStop?.interventionRequired === true,
            };
        }

        const paths = supervisorPaths(stateDir, investigationId);
        let lock = null;
        let status = null;
        try {
            lock = readLock(paths.lockPath);
        } catch {
            lock = null;
        }
        try {
            status = readSupervisorState(stateDir, investigationId);
        } catch {
            status = null;
        }
        const exactLiveOwner = lock !== null
            && status !== null
            && lock.pid === status.pid
            && lock.nonce === status.nonce
            && lock.supervisorGeneration === status.supervisorGeneration
            && isPidAlive(lock.pid)
            ? {
                pid: lock.pid,
                nonce: lock.nonce,
                supervisorGeneration: lock.supervisorGeneration,
            }
            : null;
        let stop = persistQuiescentStopBarrier({
            repository,
            investigationId,
            requestId: resolvedRequestId,
            reason,
            pauseRequested,
            owner: exactLiveOwner,
            runnerPid:
                Number.isSafeInteger(status?.childPid)
                && status.childPid > 0
                    ? status.childPid
                    : null,
            details: {
                source: "extension-adapter",
                statusState: status?.state ?? null,
            },
        });
        const result = ensureStopDomainIntent(adapter, stop);
        let signal = null;
        if (exactLiveOwner !== null
            && stop.targetSupervisorGeneration
                === exactLiveOwner.supervisorGeneration
            && stop.targetSupervisorNonce === exactLiveOwner.nonce) {
            signal = writeSupervisorStopSignal({
                paths: stopControlPaths(stateDir, investigationId),
                stop,
                owner: exactLiveOwner,
                clock,
            });
        } else {
            let brokerProbe = {
                verified: false,
                reason:
                    "resource broker authority could not be reconstructed",
            };
            const repositoryAuthority =
                repository.getSupervisorAuthority(investigationId);
            try {
                const runtimeAuthority =
                    initial.aggregate.runtimeConfigAuthority;
                if (runtimeAuthority !== null
                    && repositoryAuthority !== null) {
                    const runtimeConfig = supervisorConfigFromRuntimeAuthority(
                        runtimeAuthority,
                        { deadlineMs: null, env },
                    );
                    const resourceBroker =
                        runtimeConfig.runner.resourceBroker;
                    if (resourceBroker === null) {
                        brokerProbe = {
                            verified: true,
                            configured: false,
                            authorityRetired: true,
                            activeLeases: [],
                        };
                    } else {
                        const broker = resourceBrokerFactory({
                            stateRoot: resourceBroker.stateRoot,
                            config: resourceBroker.config,
                            env,
                        });
                        try {
                            const drainIncarnation = `extension-drain-g${
                                repositoryAuthority.supervisorGeneration
                            }-${sha256Hex(Buffer.from(
                                stop.requestId,
                                "utf8",
                            )).slice(0, 32)}`;
                            const brokerInvestigation =
                                broker.getInvestigation(investigationId);
                            if (brokerInvestigation === null) {
                                broker.registerInvestigation({
                                    investigationId,
                                    limits:
                                        resourceBroker.investigationLimits,
                                    supervisorGeneration:
                                        repositoryAuthority
                                            .supervisorGeneration,
                                    supervisorNonce:
                                        repositoryAuthority.supervisorNonce,
                                    runnerIncarnation: drainIncarnation,
                                });
                            } else {
                                broker.claimAuthority({
                                    investigationId,
                                    supervisorGeneration:
                                        repositoryAuthority
                                            .supervisorGeneration,
                                    supervisorNonce:
                                        repositoryAuthority.supervisorNonce,
                                    runnerIncarnation: drainIncarnation,
                                });
                            }
                            const retired =
                                broker.getInvestigation(investigationId);
                            if (retired === null
                                || retired.supervisorGeneration
                                    !== repositoryAuthority
                                        .supervisorGeneration
                                || retired.supervisorNonce
                                    !== repositoryAuthority.supervisorNonce
                                || retired.runnerIncarnation
                                    !== drainIncarnation) {
                                throw new Error(
                                    "resource broker retirement did not persist exact authority",
                                );
                            }
                            const activeLeases = broker.listActiveLeases({
                                investigationId,
                            });
                            if (!Array.isArray(activeLeases)) {
                                throw new Error(
                                    "resource broker active lease probe did not return an array",
                                );
                            }
                            brokerProbe = {
                                verified: true,
                                configured: true,
                                authorityRetired: true,
                                supervisorGeneration:
                                    repositoryAuthority
                                        .supervisorGeneration,
                                supervisorNonce:
                                    repositoryAuthority.supervisorNonce,
                                runnerIncarnation: drainIncarnation,
                                activeLeases,
                            };
                        } finally {
                            broker.close?.();
                        }
                    }
                }
            } catch (error) {
                brokerProbe = {
                    verified: false,
                    reason: error?.message ?? String(error),
                };
            }
            const retiredOwner = status !== null
                && repositoryAuthority !== null
                && status.supervisorGeneration
                    === repositoryAuthority.supervisorGeneration
                && status.nonce
                    === repositoryAuthority.supervisorNonce
                && lock === null
                && !isPidAlive(status.pid)
                ? {
                    pid: status.pid,
                    nonce: status.nonce,
                    supervisorGeneration:
                        status.supervisorGeneration,
                    runnerIncarnation:
                        status.runnerIncarnation ?? null,
                    state: status.state ?? "stopped",
                }
                : null;
            const childPid = Number.isSafeInteger(status?.childPid)
                && status.childPid > 0
                ? status.childPid
                : null;
            const childInactive = childPid === null
                || !isPidAlive(childPid);
            const offlineProofAvailable = retiredOwner !== null
                && childInactive
                && brokerProbe.verified === true
                && brokerProbe.authorityRetired === true
                && Array.isArray(brokerProbe.activeLeases)
                && brokerProbe.activeLeases.length === 0;
            const proof = buildQuiescenceSnapshot({
                repository,
                investigationId,
                supervisorStatus: offlineProofAvailable
                    ? {
                        verified: true,
                        pid: retiredOwner.pid,
                        supervisorGeneration:
                            retiredOwner.supervisorGeneration,
                        supervisorNonce: retiredOwner.nonce,
                        runnerIncarnation:
                            retiredOwner.runnerIncarnation,
                        state: retiredOwner.state,
                    }
                    : {
                        verified: false,
                        reason:
                            status === null
                                ? "supervisor status is missing"
                                : "supervisor status/lock ownership is not exact and retired",
                    },
                processes: offlineProofAvailable
                    ? { verified: true, activePids: [] }
                    : {
                        verified: false,
                        reason:
                            "extension adapter cannot prove exact supervisor-owned process trees",
                    },
                sdkSessions: offlineProofAvailable
                    ? {
                        verified: true,
                        activeCount: 0,
                        source:
                            "retired_supervisor_and_runner_processes",
                    }
                    : {
                        verified: false,
                        reason:
                            "extension adapter cannot prove exact SDK session ownership",
                    },
                runnerChild: offlineProofAvailable
                    ? {
                        verified: true,
                        active: false,
                        pid: childPid,
                        runnerIncarnation:
                            retiredOwner.runnerIncarnation,
                    }
                    : {
                        verified: false,
                        reason:
                            childPid !== null && isPidAlive(childPid)
                                ? "recorded runner child is still live"
                                : "runner child generation/incarnation is unverified",
                    },
                resourceBroker: brokerProbe,
            });
            const terminalOrNonResult =
                initial.aggregate.terminal !== null
                || initial.aggregate.nonResults.length > 0
                || operationalNonResult !== null;
            stop = proof.quiescent === true && terminalOrNonResult
                ? repository.completeQuiescentStop({
                    investigationId,
                    requestId: stop.requestId,
                    state: "STOP_SUPERSEDED",
                    quiescent: false,
                    interventionRequired: false,
                    nonResultCode:
                        operationalNonResult?.payload?.code
                        ?? initial.aggregate.nonResults.at(-1)?.code
                        ?? null,
                    details: {
                        supersededBy:
                            initial.aggregate.terminal !== null
                                ? "terminal"
                                : operationalNonResult !== null
                                    ? "operational_non_result"
                                    : "domain_non_result",
                        proof,
                    },
                })
                : persistPausePending({
                    repository,
                    stop,
                    proof,
                    reason:
                        "No exact live supervisor could prove and atomically commit quiescence.",
                });
        }
        const final = adapter.replay();
        return {
            appended: result.domainEvents.length > initial.domainEvents.length,
            aggregate: final.aggregate,
            domainEvent:
                final.domainEvents.find((event) =>
                    event.type === EVENT_TYPES.STOP_REQUESTED
                    && event.payload?.requestId === stop.requestId)
                ?? null,
            pausePersisted: final.aggregate.pause !== null,
            operationalNonResult,
            stop,
            signal,
            quiescent: stop.quiescent === true,
            interventionRequired: stop.interventionRequired === true,
        };
    } finally {
        repository.close();
    }
}

export async function waitForStopAcknowledgement(input, dependencies = {}) {
    const result = await waitForQuiescentStopAcknowledgement({
        ...input,
        repositoryFactory:
            dependencies.repositoryFactory
            ?? openRepositoryReadOnly,
        sleep: dependencies.sleep,
        ...(dependencies.timeoutMs === undefined
            ? {}
            : { timeoutMs: dependencies.timeoutMs }),
        ...(dependencies.pollMs === undefined
            ? {}
            : { pollMs: dependencies.pollMs }),
    });
    if (!result.timedOut
        || result.stop === null
        || !["STOP_BARRIER_PERSISTED", "STOP_RECONCILING"].includes(
            result.stop.state,
        )) {
        return result;
    }
    const repository = (
        dependencies.writeRepositoryFactory
        ?? openRepository
    )({
        file: path.join(input.stateDir, "events.sqlite"),
    });
    try {
        const stop = repository.completeQuiescentStop({
            investigationId: input.investigationId,
            requestId: input.requestId,
            state: "PAUSE_PENDING",
            quiescent: false,
            interventionRequired: true,
            nonResultCode: RUNTIME_ERROR_CODES.NON_QUIESCENT,
            details: {
                reason:
                    "Supervisor acknowledgement exceeded the bounded stop wait.",
                timeoutMs: dependencies.timeoutMs ?? 25_000,
            },
        });
        return Object.freeze({
            acknowledged: true,
            timedOut: true,
            stop,
        });
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
