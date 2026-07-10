import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { EVENT_TYPES, decideNext } from "../domain/index.mjs";
import { coerceSupervisorConfig, supervisorPaths } from "./config.mjs";
import { createDomainRepositoryAdapter } from "./domain-adapter.mjs";
import { openRepository } from "../persistence/index.mjs";
import {
    isExactPidAlive,
    readSupervisorLock,
    readSupervisorStatus,
    terminateExactSupervisor,
} from "./supervisor.mjs";
import {
    atomicWriteJson,
    ensureDirectory,
} from "./utils.mjs";

function rawRunnerConfig(runner) {
    return {
        investigationId: runner.investigationId,
        stateDir: runner.stateDir,
        artifactRoot: runner.artifactRoot,
        allowlistPath: runner.allowlistPath,
        copilotSdkPath: runner.sdkPath,
        copilotCliPath: runner.cliPath,
        runnerEpochId: runner.runnerEpochId,
        deadline: runner.deadlineMs,
        options: runner.options,
    };
}

function rawSupervisorConfig(config) {
    return {
        runner: rawRunnerConfig(config.runner),
        runnerCliPath: config.runnerCliPath,
        supervisorEpochId: config.supervisorEpochId,
        maxRestarts: config.maxRestarts,
        baseBackoffMs: config.baseBackoffMs,
        maxBackoffMs: config.maxBackoffMs,
        heartbeatIntervalMs: config.heartbeatIntervalMs,
        staleLockMs: config.staleLockMs,
        circuitWindowMs: config.circuitWindowMs,
    };
}

function resolveNodeExecutable(env, explicitPath) {
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

export function startSupervisor(input, dependencies = {}) {
    const config = coerceSupervisorConfig(input, {
        env: dependencies.env ?? process.env,
    });
    ensureDirectory(config.paths.directory);
    atomicWriteJson(config.paths.configPath, rawSupervisorConfig(config));
    const supervisorCliPath = path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        "supervisor-cli.mjs",
    );
    const spawnProcess = dependencies.spawnProcess ?? spawn;
    const nodeExecutable = resolveNodeExecutable(
        dependencies.env ?? process.env,
        dependencies.nodeExecutable,
    );
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
    };
}

export function readStatus({ stateDir, investigationId }) {
    return readSupervisorStatus(stateDir, investigationId);
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
    const status = readSupervisorStatus(
        config.runner.stateDir,
        config.runner.investigationId,
    );
    const isPidAlive = dependencies.isPidAlive ?? isExactPidAlive;
    const now = dependencies.clock?.now?.() ?? Date.now();
    const resetOperationalState = dependencies.resetOperationalState === true;
    if (status !== null) {
        if (status.state === "terminal") {
            return { action: "not-restarted", reason: status.state, status };
        }
        if (["non_result", "pause", "circuit_open", "failed"].includes(status.state)
            && !resetOperationalState) {
            return { action: "not-restarted", reason: status.state, status };
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
            return { action: "already-running", status, lock };
        }
        const lockAgeMs = now - fs.statSync(config.paths.lockPath).mtimeMs;
        if (!Number.isFinite(lockAgeMs) || lockAgeMs < config.staleLockMs) {
            return { action: "waiting-for-stale-lock", status, lock, ageMs: lockAgeMs };
        }
    } else if (malformedLock) {
        const lockAgeMs = now - fs.statSync(config.paths.lockPath).mtimeMs;
        if (!Number.isFinite(lockAgeMs) || lockAgeMs < config.staleLockMs) {
            return {
                action: "waiting-for-stale-lock",
                status,
                lock: null,
                malformedLock: true,
                ageMs: lockAgeMs,
            };
        }
    }
    return { action: "started", ...startSupervisor(config, dependencies), previousStatus: status };
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
