import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";

import { createDefaultProcessAdapter } from "../measurement/windows-adapter.mjs";
import { openRepository } from "../persistence/index.mjs";
import { coerceSupervisorConfig, supervisorPaths } from "./config.mjs";
import { createDomainRepositoryAdapter } from "./domain-adapter.mjs";
import {
    OracleRuntimeError,
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
    SupervisorLockError,
} from "./errors.mjs";
import {
    atomicWriteJson,
    delay,
    ensureDirectory,
    isPlainObject,
    readJsonFile,
    requireString,
    sha256Hex,
} from "./utils.mjs";

function defaultClock() {
    return {
        now: () => Date.now(),
        isoNow: () => new Date().toISOString(),
    };
}

export function isExactPidAlive(pid, processApi = process) {
    if (!Number.isSafeInteger(pid) || pid < 1) {
        return false;
    }
    try {
        processApi.kill(pid, 0);
        return true;
    } catch (error) {
        return error?.code === "EPERM";
    }
}

function validateLockDocument(value, lockPath) {
    const keys = isPlainObject(value) ? Object.keys(value).sort() : [];
    if (!isPlainObject(value)
        || keys.length !== 3
        || keys[0] !== "nonce"
        || keys[1] !== "pid"
        || keys[2] !== "startedAt"
        || !Number.isSafeInteger(value.pid)
        || value.pid < 1
        || typeof value.nonce !== "string"
        || value.nonce.length === 0
        || typeof value.startedAt !== "string"
        || !Number.isFinite(Date.parse(value.startedAt))) {
        throw new SupervisorLockError(
            RUNTIME_ERROR_CODES.LOCK_INVALID,
            "Supervisor lock file is malformed",
            { lockPath },
        );
    }

    return value;
}

export function readSupervisorLock(lockPath) {
    if (!fs.existsSync(lockPath)) {
        return null;
    }
    return validateLockDocument(readJsonFile(lockPath, "supervisor lock"), lockPath);
}

function readStatusForOwnership(statusPath) {
    if (typeof statusPath !== "string" || !path.isAbsolute(statusPath) || !fs.existsSync(statusPath)) {
        return null;
    }
    try {
        const value = readJsonFile(statusPath, "supervisor status");
        if (!isPlainObject(value)
            || !Number.isSafeInteger(value.pid)
            || value.pid < 1
            || typeof value.nonce !== "string"
            || value.nonce.length === 0
            || typeof value.heartbeatAt !== "string"
            || !Number.isFinite(Date.parse(value.heartbeatAt))) {
            return null;
        }
        return value;
    } catch {
        return null;
    }
}

function hasFreshMatchingHeartbeat(lock, status, now, staleLockMs, isPidAlive) {
    if (lock === null || status === null
        || status.pid !== lock.pid
        || status.nonce !== lock.nonce) {
        return false;
    }
    const heartbeatAgeMs = now - Date.parse(status.heartbeatAt);
    return Number.isFinite(heartbeatAgeMs)
        && heartbeatAgeMs >= -staleLockMs
        && heartbeatAgeMs < staleLockMs
        && isPidAlive(lock.pid);
}

function fsyncDirectoryBestEffort(directory) {
    try {
        const fd = fs.openSync(directory, "r");
        try {
            fs.fsyncSync(fd);
        } finally {
            fs.closeSync(fd);
        }
    } catch {
        // Directory fsync is not uniformly available on Windows.
    }
}

function publishLockCrashSafely(lockPath, document, pid, nonce) {
    const directory = path.dirname(lockPath);
    const token = sha256Hex(Buffer.from(`${pid}:${nonce}:${randomUUID()}`, "utf8")).slice(0, 24);
    const temporary = path.join(directory, `.${path.basename(lockPath)}.${pid}.${token}.tmp`);
    const bytes = Buffer.from(`${JSON.stringify(document)}\n`, "utf8");
    try {
        let fd;
        try {
            fd = fs.openSync(temporary, "wx", 0o600);
            let offset = 0;
            while (offset < bytes.length) {
                offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
            }
            fs.fsyncSync(fd);
        } finally {
            if (fd !== undefined) fs.closeSync(fd);
        }
        fs.linkSync(temporary, lockPath);
        fsyncDirectoryBestEffort(directory);
        return true;
    } catch (error) {
        if (error?.code === "EEXIST") return false;
        throw error;
    } finally {
        fs.rmSync(temporary, { force: true });
    }
}

function inspectExistingLock(lockPath) {
    const raw = fs.readFileSync(lockPath);
    const stat = fs.statSync(lockPath);
    let parsed = null;
    let valid = null;
    try {
        parsed = JSON.parse(raw.toString("utf8"));
        valid = validateLockDocument(parsed, lockPath);
    } catch {
        // Malformed/partial legacy lock: recovery is based on mtime + heartbeat.
    }
    return {
        rawHash: sha256Hex(raw),
        mtimeMs: stat.mtimeMs,
        parsed,
        valid,
    };
}

export function acquireSupervisorLock(config, dependencies = {}) {
    const normalized = coerceSupervisorConfig(config, {
        env: dependencies.env ?? process.env,
    });
    const clock = dependencies.clock ?? defaultClock();
    const pid = dependencies.pid ?? process.pid;
    if (!Number.isSafeInteger(pid) || pid < 1) {
        throw new RuntimeConfigError("Supervisor PID must be a positive safe integer", { pid });
    }
    const nonce = requireString(
        dependencies.idFactory?.() ?? randomUUID(),
        "supervisor nonce",
        { max: 256 },
    );
    const isPidAlive = dependencies.isPidAlive ?? isExactPidAlive;
    const lockPath = normalized.paths.lockPath;
    ensureDirectory(path.dirname(lockPath));

    for (let pass = 0; pass < 3; pass += 1) {
        const document = {
            pid,
            nonce,
            startedAt: clock.isoNow(),
        };
        validateLockDocument(document, lockPath);
        try {
            if (!publishLockCrashSafely(lockPath, document, pid, nonce)) {
                throw Object.assign(new Error("lock exists"), { code: "EEXIST" });
            }
            return Object.freeze({ ...document, lockPath });
        } catch (error) {
            if (error?.code !== "EEXIST") {
                throw error;
            }
        }

        let inspected;
        try {
            inspected = inspectExistingLock(lockPath);
        } catch (error) {
            if (error?.code === "ENOENT") continue;
            throw error;
        }
        const now = clock.now();
        const ageMs = now - inspected.mtimeMs;
        const status = readStatusForOwnership(normalized.paths.statusPath);
        const looseOwner = inspected.valid ?? (
            isPlainObject(inspected.parsed)
            && Number.isSafeInteger(inspected.parsed.pid)
            && inspected.parsed.pid > 0
            && typeof inspected.parsed.nonce === "string"
            && inspected.parsed.nonce.length > 0
                ? { pid: inspected.parsed.pid, nonce: inspected.parsed.nonce }
                : null
        );
        const freshOwner = looseOwner !== null
            && hasFreshMatchingHeartbeat(
                looseOwner,
                status,
                now,
                normalized.staleLockMs,
                isPidAlive,
            );
        if (freshOwner || !Number.isFinite(ageMs) || ageMs < normalized.staleLockMs) {
            throw new SupervisorLockError(
                RUNTIME_ERROR_CODES.LOCK_HELD,
                "Another supervisor owns this investigation",
                {
                    investigationId: normalized.runner.investigationId,
                    pid: inspected.valid?.pid ?? null,
                    nonce: inspected.valid?.nonce ?? null,
                    ageMs,
                    freshHeartbeat: freshOwner,
                    malformed: inspected.valid === null,
                },
            );
        }
        const confirm = inspectExistingLock(lockPath);
        if (confirm.rawHash !== inspected.rawHash || confirm.mtimeMs !== inspected.mtimeMs) {
            throw new SupervisorLockError(
                RUNTIME_ERROR_CODES.LOCK_HELD,
                "Supervisor lock changed during stale recovery",
                { lockPath },
            );
        }
        const staleClaimToken = sha256Hex(Buffer.from(nonce, "utf8")).slice(0, 24);
        const staleClaimPath = `${lockPath}.stale-${pid}-${staleClaimToken}`;
        try {
            fs.renameSync(lockPath, staleClaimPath);
        } catch (error) {
            if (error?.code === "ENOENT") {
                continue;
            }
            throw error;
        }
        const claimed = inspectExistingLock(staleClaimPath);
        if (claimed.rawHash !== inspected.rawHash) {
            if (!fs.existsSync(lockPath)) {
                fs.renameSync(staleClaimPath, lockPath);
            }
            throw new SupervisorLockError(
                RUNTIME_ERROR_CODES.LOCK_HELD,
                "A newer supervisor lock appeared during stale recovery",
                { lockPath },
            );
        }
        fs.rmSync(staleClaimPath);
        fsyncDirectoryBestEffort(path.dirname(lockPath));
    }
    throw new SupervisorLockError(
        RUNTIME_ERROR_CODES.LOCK_HELD,
        "Unable to acquire supervisor lock after stale recovery",
        { lockPath },
    );
}

export function releaseSupervisorLock(lock) {
    if (lock === null || typeof lock !== "object") {
        return false;
    }
    let current;
    try {
        current = validateLockDocument(readJsonFile(lock.lockPath, "supervisor lock"), lock.lockPath);
    } catch (error) {
        if (error?.details?.cause === "ENOENT" || !fs.existsSync(lock.lockPath)) {
            return false;
        }
        throw error;
    }
    if (current.pid !== lock.pid || current.nonce !== lock.nonce) {
        return false;
    }
    fs.rmSync(lock.lockPath);
    fsyncDirectoryBestEffort(path.dirname(lock.lockPath));
    return true;
}

function runnerConfigForChild(config) {
    return {
        investigationId: config.runner.investigationId,
        stateDir: config.runner.stateDir,
        artifactRoot: config.runner.artifactRoot,
        allowlistPath: config.runner.allowlistPath,
        copilotSdkPath: config.runner.sdkPath,
        copilotCliPath: config.runner.cliPath,
        runnerEpochId: config.runner.runnerEpochId,
        deadline: config.runner.deadlineMs,
        resultPath: config.paths.childResultPath,
        options: config.runner.options,
    };
}

function waitForChild(child) {
    return new Promise((resolve) => {
        let settled = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            resolve(value);
        };
        child.once("error", (error) => finish({
            code: null,
            signal: null,
            error,
        }));
        child.once("close", (code, signal) => finish({
            code,
            signal,
            error: null,
        }));
    });
}

function defaultSpawnRunner(config) {
    fs.rmSync(config.paths.childResultPath, { force: true });
    atomicWriteJson(config.paths.childConfigPath, runnerConfigForChild(config));
    const child = spawn(
        process.execPath,
        [config.runnerCliPath, "--config", config.paths.childConfigPath],
        {
            cwd: config.runner.stateDir,
            shell: false,
            windowsHide: true,
            stdio: ["ignore", "ignore", "ignore"],
        },
    );
    return { child, resultPath: config.paths.childResultPath };
}

function readChildEnvelope(resultPath) {
    if (!fs.existsSync(resultPath)) {
        return null;
    }
    const value = readJsonFile(resultPath, "runner result");
    if (!isPlainObject(value) || typeof value.ok !== "boolean") {
        throw new RuntimeConfigError("Runner result envelope is malformed", { resultPath });
    }
    return value;
}

function classifySuccessfulResult(result) {
    switch (result?.kind) {
        case "TERMINAL":
            return "terminal";
        case "NON_RESULT":
            return "non_result";
        case "PAUSE":
            return "pause";
        default:
            return null;
    }
}

function persistSupervisorNonResult(config, lock, dependencies, input) {
    if (typeof dependencies.recordOperationalNonResult === "function") {
        return dependencies.recordOperationalNonResult(input);
    }
    const eventsFile = path.join(config.runner.stateDir, "events.sqlite");
    if (!fs.existsSync(eventsFile)) {
        return null;
    }
    const repository = openRepository({ file: eventsFile });
    try {
        const adapter = createDomainRepositoryAdapter({
            repository,
            investigationId: config.runner.investigationId,
        });
        return adapter.recordOperationalNonResult({
            attemptId: `supervisor-${lock.nonce}-${input.code}-${input.restartCount ?? 0}`
                .replace(/[^A-Za-z0-9._@-]/gu, "-")
                .slice(0, 256),
            code: input.code,
            reason: input.reason,
            details: input.details ?? null,
        });
    } finally {
        repository.close();
    }
}

function readMatchingStopRequest(file, lock) {
    if (!fs.existsSync(file)) return null;
    let request;
    try {
        request = readJsonFile(file, "supervisor stop request");
    } catch {
        fs.rmSync(file, { force: true });
        return null;
    }
    if (!isPlainObject(request)
        || request.pid !== lock.pid
        || request.nonce !== lock.nonce
        || typeof request.requestedAt !== "string"
        || !Number.isFinite(Date.parse(request.requestedAt))) {
        fs.rmSync(file, { force: true });
        return null;
    }
    fs.rmSync(file, { force: true });
    return request;
}

export async function runSupervisor(input, dependencies = {}) {
    const config = coerceSupervisorConfig(input, {
        env: dependencies.env ?? process.env,
    });
    const clock = dependencies.clock ?? defaultClock();
    const timers = dependencies.timers ?? globalThis;
    const sleep = dependencies.sleep ?? ((milliseconds) => delay(milliseconds, timers));
    const spawnRunner = dependencies.spawnRunner ?? defaultSpawnRunner;
    const processTreeAdapter = dependencies.processTreeAdapter ?? createDefaultProcessAdapter();
    const signalSource = dependencies.signalSource ?? process;
    const lock = acquireSupervisorLock(config, {
        ...dependencies,
        clock,
    });
    const startedAt = lock.startedAt;
    let status = null;
    let heartbeatTimer = null;
    let controlTimer = null;
    let currentChild = null;
    let currentChildWait = null;
    let currentChildPid = null;
    let restartCount = 0;
    let shutdownRequest = null;
    let resolveShutdown;
    const shutdownPromise = new Promise((resolve) => {
        resolveShutdown = resolve;
    });
    const crashes = [];
    const signalHandlers = new Map();

    const requestShutdown = (request) => {
        if (shutdownRequest !== null) return;
        shutdownRequest = request;
        resolveShutdown(request);
    };

    const writeStatus = (state, extra = {}) => {
        status = {
            version: 1,
            investigationId: config.runner.investigationId,
            supervisorEpochId: config.supervisorEpochId,
            pid: lock.pid,
            nonce: lock.nonce,
            startedAt,
            heartbeatAt: clock.isoNow(),
            state,
            restartCount,
            childPid: currentChildPid,
            ...extra,
        };
        atomicWriteJson(config.paths.statusPath, status);
        return status;
    };

    const startHeartbeat = () => {
        if (heartbeatTimer !== null) return;
        heartbeatTimer = timers.setInterval(() => {
            try {
                writeStatus(status?.state ?? "running", {
                    ...(status ?? {}),
                    heartbeatAt: clock.isoNow(),
                    childPid: currentChildPid,
                    restartCount,
                });
            } catch {
                // The foreground control loop surfaces durable write failures.
            }
        }, config.heartbeatIntervalMs);
        heartbeatTimer?.unref?.();
    };

    const stopHeartbeat = () => {
        if (heartbeatTimer !== null) {
            timers.clearInterval(heartbeatTimer);
            heartbeatTimer = null;
        }
    };

    const terminateCurrentChild = async () => {
        if (currentChild === null || currentChildWait === null) return null;
        const child = currentChild;
        const wait = currentChildWait;
        const pid = currentChildPid;
        if (Number.isSafeInteger(pid) && pid > 0) {
            await processTreeAdapter.terminateTree(pid);
        }
        const exit = await wait;
        if (currentChild === child) {
            currentChild = null;
            currentChildWait = null;
            currentChildPid = null;
        }
        return exit;
    };

    for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
        const handler = () => requestShutdown({ kind: "signal", signal });
        signalHandlers.set(signal, handler);
        signalSource.on?.(signal, handler);
    }
    fs.rmSync(config.paths.stopRequestPath, { force: true });
    controlTimer = timers.setInterval(() => {
        try {
            const request = readMatchingStopRequest(config.paths.stopRequestPath, lock);
            if (request !== null) {
                requestShutdown({ kind: "stop_request", request });
            }
        } catch (error) {
            requestShutdown({
                kind: "control_failure",
                error: { code: error?.code ?? null, message: error?.message ?? String(error) },
            });
        }
    }, Math.min(config.heartbeatIntervalMs, 250));

    try {
        writeStatus("starting");
        for (let launchNumber = 1; ; launchNumber += 1) {
            if (shutdownRequest !== null) {
                writeStatus("stopped", { shutdown: shutdownRequest });
                return { kind: "STOPPED", status, result: null };
            }
            let launched;
            try {
                launched = await spawnRunner(config, {
                    launchNumber,
                    restartCount,
                    runnerConfig: runnerConfigForChild(config),
                });
            } catch (error) {
                launched = { error, child: null, resultPath: config.paths.childResultPath };
            }

            if (launched?.child === null || launched?.child === undefined) {
                const error = launched?.error ?? new Error("spawnRunner returned no child");
                crashes.push(clock.now());
                writeStatus("crashed", {
                    lastError: {
                        code: RUNTIME_ERROR_CODES.CHILD_CRASH,
                        message: error.message,
                    },
                });
            } else {
                currentChild = launched.child;
                currentChildPid = launched.child.pid ?? null;
                currentChildWait = waitForChild(launched.child);
                writeStatus("running", { launchNumber });
                startHeartbeat();
                const completed = await Promise.race([
                    currentChildWait.then((exit) => ({ kind: "child_exit", exit })),
                    shutdownPromise.then((request) => ({ kind: "shutdown", request })),
                ]);
                if (completed.kind === "shutdown") {
                    const exit = await terminateCurrentChild();
                    stopHeartbeat();
                    writeStatus("stopped", { shutdown: completed.request, exit });
                    return { kind: "STOPPED", status, result: null };
                }
                const exit = completed.exit;
                currentChild = null;
                currentChildWait = null;
                currentChildPid = null;
                stopHeartbeat();

                let envelope = null;
                let envelopeError = null;
                try {
                    envelope = readChildEnvelope(launched.resultPath ?? config.paths.childResultPath);
                } catch (error) {
                    envelopeError = error;
                }

                if (envelope?.ok === true) {
                    const finalState = classifySuccessfulResult(envelope.result);
                    if (finalState === null) {
                        const reason = "Runner returned an unsupported result kind";
                        persistSupervisorNonResult(config, lock, dependencies, {
                            code: RUNTIME_ERROR_CODES.RESULT_MISSING,
                            reason,
                            restartCount,
                            details: { exit, result: envelope.result ?? null, recoverable: false },
                        });
                        writeStatus("failed", {
                            lastError: {
                                code: RUNTIME_ERROR_CODES.RESULT_MISSING,
                                message: reason,
                                recoverable: false,
                            },
                            exit,
                        });
                        return { kind: "FAILED", status, result: envelope.result };
                    }
                    writeStatus(finalState, { result: envelope.result, exit });
                    return {
                        kind: finalState === "terminal"
                            ? "TERMINAL"
                            : finalState === "pause"
                                ? "PAUSE"
                                : "NON_RESULT",
                        status,
                        result: envelope.result,
                    };
                }

                const recoverable = envelope?.ok === false
                    ? envelope.error?.recoverable === true
                    : envelopeError === null
                        && exit.code !== 64
                        && exit.code !== 65;
                const lastError = envelope?.error ?? {
                    code: envelopeError?.code ?? RUNTIME_ERROR_CODES.RESULT_MISSING,
                    message: envelopeError?.message
                        ?? exit.error?.message
                        ?? "Runner exited without a result envelope",
                    recoverable,
                };
                if (!recoverable) {
                    persistSupervisorNonResult(config, lock, dependencies, {
                        code: lastError.code ?? RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
                        reason: lastError.message ?? "Runner failed without a recoverable outcome.",
                        restartCount,
                        details: { exit, recoverable: false },
                    });
                    writeStatus("failed", { lastError, exit });
                    return { kind: "FAILED", status, error: lastError };
                }
                crashes.push(clock.now());
                writeStatus("crashed", { lastError, exit });
            }

            const cutoff = clock.now() - config.circuitWindowMs;
            while (crashes.length > 0 && crashes[0] < cutoff) {
                crashes.shift();
            }
            if (restartCount >= config.maxRestarts || crashes.length > config.maxRestarts) {
                const reason = "Supervisor circuit breaker opened after repeated recoverable crashes";
                const circuit = {
                    crashesInWindow: crashes.length,
                    windowMs: config.circuitWindowMs,
                    maxRestarts: config.maxRestarts,
                };
                persistSupervisorNonResult(config, lock, dependencies, {
                    code: RUNTIME_ERROR_CODES.CIRCUIT_OPEN,
                    reason,
                    restartCount,
                    details: { circuit, recoverable: false },
                });
                writeStatus("circuit_open", { circuit });
                return {
                    kind: "CIRCUIT_OPEN",
                    status,
                    error: new OracleRuntimeError(
                        RUNTIME_ERROR_CODES.CIRCUIT_OPEN,
                        reason,
                    ),
                };
            }

            restartCount += 1;
            const backoffMs = Math.min(
                config.maxBackoffMs,
                config.baseBackoffMs * (2 ** (restartCount - 1)),
            );
            writeStatus("backoff", { backoffMs });
            const completed = await Promise.race([
                sleep(backoffMs).then(() => ({ kind: "backoff_complete" })),
                shutdownPromise.then((request) => ({ kind: "shutdown", request })),
            ]);
            if (completed.kind === "shutdown") {
                writeStatus("stopped", { shutdown: completed.request });
                return { kind: "STOPPED", status, result: null };
            }
        }
    } finally {
        stopHeartbeat();
        if (controlTimer !== null) {
            timers.clearInterval(controlTimer);
            controlTimer = null;
        }
        for (const [signal, handler] of signalHandlers) {
            if (typeof signalSource.off === "function") {
                signalSource.off(signal, handler);
            } else {
                signalSource.removeListener?.(signal, handler);
            }
        }
        await terminateCurrentChild();
        releaseSupervisorLock(lock);
    }
}

export function readSupervisorStatus(stateDir, investigationId) {
    const paths = supervisorPaths(stateDir, investigationId);
    if (!fs.existsSync(paths.statusPath)) {
        return null;
    }
    return readJsonFile(paths.statusPath, "supervisor status");
}

export function terminateExactSupervisor({
    lockPath,
    statusPath,
    stopRequestPath,
    expectedNonce,
    signal = "SIGTERM",
    processApi = process,
    clock = defaultClock(),
    staleAfterMs = 30_000,
} = {}) {
    const lock = validateLockDocument(readJsonFile(lockPath, "supervisor lock"), lockPath);
    if (expectedNonce !== undefined && lock.nonce !== expectedNonce) {
        throw new SupervisorLockError(
            RUNTIME_ERROR_CODES.LOCK_HELD,
            "Supervisor nonce changed; refusing to terminate an unverified PID",
            { lockPath },
        );
    }
    const status = readStatusForOwnership(statusPath);
    if (!hasFreshMatchingHeartbeat(
        lock,
        status,
        clock.now(),
        staleAfterMs,
        (pid) => isExactPidAlive(pid, processApi),
    )) {
        throw new SupervisorLockError(
            RUNTIME_ERROR_CODES.LOCK_HELD,
            "Supervisor heartbeat is stale or does not match the lock nonce; refusing PID-based termination",
            {
                lockPath,
                statusPath,
                pid: lock.pid,
                nonce: lock.nonce,
            },
        );
    }
    if (typeof stopRequestPath !== "string" || !path.isAbsolute(stopRequestPath)) {
        throw new RuntimeConfigError("stopRequestPath must be an absolute path");
    }
    atomicWriteJson(stopRequestPath, {
        version: 1,
        pid: lock.pid,
        nonce: lock.nonce,
        signal,
        requestedAt: clock.isoNow(),
    });
    return {
        action: "stop_requested",
        pid: lock.pid,
        nonce: lock.nonce,
        signal,
        stopRequestPath,
    };
}
