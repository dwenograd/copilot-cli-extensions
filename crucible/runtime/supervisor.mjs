import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

import { createDefaultProcessAdapter } from "../measurement/windows-adapter.mjs";
import { openRepository } from "../persistence/index.mjs";
import {
    coerceSupervisorConfig,
    supervisorConfigFingerprint,
    supervisorPaths,
} from "./config.mjs";
import {
    createDomainRepositoryAdapter,
    formatAttemptCommand,
} from "./domain-adapter.mjs";
import { normalizeRunnerOutcomeEnvelope } from "./outcome.mjs";
import {
    CrucibleRuntimeError,
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
    SupervisorLockError,
} from "./errors.mjs";
import {
    RUNTIME_TEMP_OWNER_MARKER,
    atomicWriteJson,
    delay,
    ensureDirectory,
    isPathInside,
    isPlainObject,
    readJsonFile,
    remainingDeadlineMs,
    removeTreeInside,
    requireString,
    settleWithin,
    sha256Hex,
} from "./utils.mjs";

const DEFAULT_SHUTDOWN_POLICY = Object.freeze({
    drainMs: 2_000,
    escalationMs: 3_000,
    finalMs: 10_000,
});

const ATOMIC_TEMP_NAME = /^\..+\.(\d+)\.[a-f0-9]{24}\.tmp$/u;

function defaultClock() {
    return {
        now: () => Date.now(),
        isoNow: () => new Date().toISOString(),
    };
}

function openSupervisorAuthorityRepository(config, dependencies, clock) {
    const owned = dependencies.authorityRepository === undefined;
    const repository = owned
        ? (dependencies.authorityRepositoryFactory ?? openRepository)({
            file: path.join(config.runner.stateDir, "events.sqlite"),
            now: () => clock.isoNow(),
        })
        : dependencies.authorityRepository;
    try {
        repository.ensureInvestigation({
            investigationId: config.runner.investigationId,
            metadata: { role: "crucible-domain" },
        });
        return { repository, owned };
    } catch (error) {
        if (owned) repository.close();
        throw error;
    }
}

function closeSupervisorAuthorityRepository(handle) {
    if (handle?.owned === true) {
        handle.repository.close();
    }
}

function normalizeShutdownPolicy(value = {}) {
    if (!isPlainObject(value)) {
        throw new RuntimeConfigError("shutdownPolicy must be a plain object");
    }
    const unknown = Object.keys(value).filter((key) =>
        !Object.hasOwn(DEFAULT_SHUTDOWN_POLICY, key));
    if (unknown.length > 0) {
        throw new RuntimeConfigError("shutdownPolicy contains unknown keys", { unknown });
    }
    const policy = {};
    for (const [key, fallback] of Object.entries(DEFAULT_SHUTDOWN_POLICY)) {
        const actual = value[key] ?? fallback;
        if (!Number.isSafeInteger(actual) || actual < 1 || actual > 60_000) {
            throw new RuntimeConfigError(
                `shutdownPolicy.${key} must be a positive integer <= 60000`,
                { key, value: actual },
            );
        }
        policy[key] = actual;
    }
    if (policy.finalMs < policy.drainMs + policy.escalationMs) {
        throw new RuntimeConfigError(
            "shutdownPolicy.finalMs must cover drainMs plus escalationMs",
            { policy },
        );
    }
    return Object.freeze(policy);
}

function samePath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function pathIsReferenced(candidate, referencedPaths) {
    return referencedPaths.some((referenced) =>
        samePath(candidate, referenced) || isPathInside(referenced, candidate));
}

function safeAgeMs(target, now) {
    try {
        const ageMs = now - fs.statSync(target).mtimeMs;
        return ageMs < 0 && ageMs >= -1_000 ? 0 : ageMs;
    } catch {
        return Number.NaN;
    }
}

function validRuntimeOwnerMarker(marker, candidate, investigationId) {
    return isPlainObject(marker)
        && marker.version === 1
        && marker.kind === "crucible-runtime-temp-root"
        && marker.investigationId === investigationId
        && Number.isSafeInteger(marker.supervisorGeneration)
        && marker.supervisorGeneration > 0
        && typeof marker.supervisorNonce === "string"
        && marker.supervisorNonce.length > 0
        && typeof marker.runnerEpochId === "string"
        && marker.runnerEpochId.length > 0
        && Number.isSafeInteger(marker.pid)
        && marker.pid > 0
        && typeof marker.root === "string"
        && path.isAbsolute(marker.root)
        && samePath(marker.root, candidate)
        && Array.isArray(marker.ownedPaths)
        && marker.ownedPaths.every((ownedPath) =>
            typeof ownedPath === "string"
            && path.isAbsolute(ownedPath)
            && isPathInside(ownedPath, candidate));
}

function generationOwnerKey(generation, nonce) {
    return `${generation}\0${nonce}`;
}

function readKnownGenerationOwners(supervisorDirectory, investigationId) {
    const owners = new Set();
    if (!fs.existsSync(supervisorDirectory)) return owners;
    for (const entry of fs.readdirSync(supervisorDirectory, { withFileTypes: true })) {
        if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
        const file = path.join(supervisorDirectory, entry.name);
        try {
            const document = validateGenerationDocument(
                readJsonFile(file, "supervisor generation record", {
                    maxBytes: 64 * 1024,
                }),
                file,
                investigationId,
            );
            owners.add(generationOwnerKey(
                document.supervisorGeneration,
                document.nonce,
            ));
        } catch {
            // Non-generation supervisor documents are not ownership proof.
        }
    }
    return owners;
}

export async function scavengeStaleGenerationOwnedPaths({
    tempRoot,
    supervisorDirectory,
    investigationId,
    currentGeneration,
    currentNonce,
    currentPid,
    abandonedRunners = [],
    referencedPaths = [],
    isPidAlive = isExactPidAlive,
    now = Date.now(),
    minimumAgeMs = 0,
} = {}) {
    if (typeof tempRoot !== "string"
        || !path.isAbsolute(tempRoot)
        || typeof supervisorDirectory !== "string"
        || !path.isAbsolute(supervisorDirectory)
        || typeof investigationId !== "string"
        || investigationId.length === 0
        || !isSupervisorGeneration(currentGeneration)
        || typeof currentNonce !== "string"
        || currentNonce.length === 0
        || !Number.isSafeInteger(currentPid)
        || currentPid < 1
        || !Array.isArray(abandonedRunners)
        || !Array.isArray(referencedPaths)
        || !Number.isSafeInteger(minimumAgeMs)
        || minimumAgeMs < 0) {
        throw new RuntimeConfigError("Invalid startup scavenging configuration");
    }
    const abandonedOwners = new Set();
    for (const runner of abandonedRunners) {
        if (!isPlainObject(runner)
            || typeof runner.runnerIncarnation !== "string"
            || runner.runnerIncarnation.length === 0
            || (runner.pid !== undefined
                && (!Number.isSafeInteger(runner.pid) || runner.pid < 1))) {
            throw new RuntimeConfigError(
                "Invalid abandoned runner scavenging authority",
            );
        }
        abandonedOwners.add(runner.runnerIncarnation);
    }
    const references = referencedPaths
        .filter((value) => typeof value === "string" && path.isAbsolute(value))
        .map((value) => path.resolve(value));
    const knownGenerationOwners = readKnownGenerationOwners(
        supervisorDirectory,
        investigationId,
    );
    const removed = [];
    const preserved = [];

    if (fs.existsSync(tempRoot)) {
        for (const entry of fs.readdirSync(tempRoot, { withFileTypes: true })) {
            if (!entry.isDirectory() || !entry.name.startsWith("run-g")) continue;
            const candidate = path.join(tempRoot, entry.name);
            const markerPath = path.join(candidate, RUNTIME_TEMP_OWNER_MARKER);
            let marker = null;
            try {
                marker = readJsonFile(markerPath, "runtime temp owner marker", {
                    maxBytes: 64 * 1024,
                });
            } catch {
                preserved.push({ path: candidate, reason: "owner_unproven" });
                continue;
            }
            const ageMs = safeAgeMs(markerPath, now);
            const abandonedCurrentRunner =
                marker?.supervisorGeneration === currentGeneration
                && marker?.supervisorNonce === currentNonce
                && typeof marker?.runnerIncarnation === "string"
                && abandonedOwners.has(marker.runnerIncarnation);
            if (!validRuntimeOwnerMarker(marker, candidate, investigationId)) {
                preserved.push({ path: candidate, reason: "owner_invalid" });
            } else if (!knownGenerationOwners.has(generationOwnerKey(
                marker.supervisorGeneration,
                marker.supervisorNonce,
            ))) {
                preserved.push({ path: candidate, reason: "generation_unproven" });
            } else if (marker.supervisorGeneration > currentGeneration
                || (marker.supervisorGeneration === currentGeneration
                    && !abandonedCurrentRunner)
                || marker.pid === currentPid) {
                preserved.push({ path: candidate, reason: "current_generation" });
            } else if (!Number.isFinite(ageMs) || ageMs < minimumAgeMs) {
                preserved.push({ path: candidate, reason: "not_stale" });
            } else if (isPidAlive(marker.pid)) {
                preserved.push({ path: candidate, reason: "owner_alive" });
            } else if (pathIsReferenced(candidate, references)) {
                preserved.push({ path: candidate, reason: "referenced" });
            } else {
                removeTreeInside(candidate, tempRoot);
                removed.push({ path: candidate, kind: "runtime_temp_root" });
            }
        }
    }

    for (const directory of [tempRoot, supervisorDirectory]) {
        if (!fs.existsSync(directory)) continue;
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            if (!entry.isFile()) continue;
            const match = ATOMIC_TEMP_NAME.exec(entry.name);
            if (match === null) continue;
            const file = path.join(directory, entry.name);
            let document;
            try {
                document = readJsonFile(file, "atomic temporary file", {
                    maxBytes: 4 * 1024 * 1024,
                });
            } catch {
                preserved.push({ path: file, reason: "atomic_owner_unproven" });
                continue;
            }
            const ownerPid = Number(match[1]);
            const generation = document?.supervisorGeneration;
            const ownerNonce = document?.nonce ?? document?.supervisorNonce;
            const ageMs = safeAgeMs(file, now);
            if (!isSupervisorGeneration(generation)
                || generation >= currentGeneration
                || typeof ownerNonce !== "string"
                || ownerNonce.length === 0
                || !knownGenerationOwners.has(generationOwnerKey(
                    generation,
                    ownerNonce,
                ))
                || (document.pid !== undefined && document.pid !== ownerPid)
                || ownerPid === currentPid
                || (!Number.isFinite(ageMs) || ageMs < minimumAgeMs)
                || isPidAlive(ownerPid)
                || references.some((referenced) => samePath(file, referenced))) {
                preserved.push({ path: file, reason: "atomic_current_or_unproven" });
                continue;
            }
            fs.rmSync(file, { force: true });
            removed.push({ path: file, kind: "atomic_temp" });
        }
    }

    return Object.freeze({
        removed: Object.freeze(removed),
        preserved: Object.freeze(preserved),
    });
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

function isSupervisorGeneration(value) {
    return Number.isSafeInteger(value) && value > 0;
}

function validateLockDocument(value, lockPath) {
    const keys = isPlainObject(value) ? Object.keys(value).sort() : [];
    if (!isPlainObject(value)
        || keys.length !== 4
        || keys[0] !== "nonce"
        || keys[1] !== "pid"
        || keys[2] !== "startedAt"
        || keys[3] !== "supervisorGeneration"
        || !Number.isSafeInteger(value.pid)
        || value.pid < 1
        || !isSupervisorGeneration(value.supervisorGeneration)
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

function validateGenerationDocument(value, generationPath, investigationId) {
    const keys = isPlainObject(value) ? Object.keys(value).sort() : [];
    if (!isPlainObject(value)
        || keys.length !== 6
        || keys[0] !== "allocatedAt"
        || keys[1] !== "investigationId"
        || keys[2] !== "nonce"
        || keys[3] !== "pid"
        || keys[4] !== "supervisorGeneration"
        || keys[5] !== "version"
        || value.version !== 1
        || value.investigationId !== investigationId
        || !Number.isSafeInteger(value.pid)
        || value.pid < 1
        || !isSupervisorGeneration(value.supervisorGeneration)
        || typeof value.nonce !== "string"
        || value.nonce.length === 0
        || typeof value.allocatedAt !== "string"
        || !Number.isFinite(Date.parse(value.allocatedAt))) {
        throw new SupervisorLockError(
            RUNTIME_ERROR_CODES.LOCK_INVALID,
            "Supervisor generation record is malformed",
            { generationPath, investigationId },
        );
    }
    return value;
}

function readGenerationDocument(generationPath, investigationId) {
    if (!fs.existsSync(generationPath)) {
        return null;
    }
    return validateGenerationDocument(
        readJsonFile(generationPath, "supervisor generation record"),
        generationPath,
        investigationId,
    );
}

function readLatestGenerationDocument(paths, investigationId) {
    const records = [];
    const shared = readGenerationDocument(paths.generationPath, investigationId);
    if (shared !== null) {
        records.push(shared);
    }
    if (fs.existsSync(paths.directory)) {
        const extension = path.extname(paths.generationPath);
        const stem = path.basename(
            paths.generationPath,
            extension,
        );
        const prefix = `${stem}.g`;
        for (const entry of fs.readdirSync(paths.directory, { withFileTypes: true })) {
            if (!entry.isFile()
                || !entry.name.startsWith(prefix)
                || !entry.name.endsWith(extension)) {
                continue;
            }
            const record = readGenerationDocument(
                path.join(paths.directory, entry.name),
                investigationId,
            );
            if (record !== null) {
                records.push(record);
            }
        }
    }
    let latest = null;
    for (const record of records) {
        if (latest === null || record.supervisorGeneration > latest.supervisorGeneration) {
            latest = record;
            continue;
        }
        if (record.supervisorGeneration === latest.supervisorGeneration
            && (record.nonce !== latest.nonce || record.pid !== latest.pid)) {
            throw new SupervisorLockError(
                RUNTIME_ERROR_CODES.LOCK_INVALID,
                "Supervisor generation records disagree for the same generation",
                {
                    investigationId,
                    supervisorGeneration: record.supervisorGeneration,
                },
            );
        }
    }
    return latest;
}

export function readSupervisorLock(lockPath) {
    if (!fs.existsSync(lockPath)) {
        return null;
    }
    return validateLockDocument(readJsonFile(lockPath, "supervisor lock"), lockPath);
}

function ownerScopedPath(file, owner) {
    const token = sha256Hex(Buffer.from(owner.nonce, "utf8")).slice(0, 24);
    const extension = path.extname(file);
    const stem = extension.length === 0 ? file : file.slice(0, -extension.length);
    return `${stem}.g${owner.supervisorGeneration}-${token}${extension}`;
}

function ownerRuntimePaths(paths, owner) {
    return Object.freeze({
        statusPath: ownerScopedPath(paths.statusPath, owner),
        childConfigPath: ownerScopedPath(paths.childConfigPath, owner),
        childResultPath: ownerScopedPath(paths.childResultPath, owner),
        stopRequestPath: ownerScopedPath(paths.stopRequestPath, owner),
    });
}

function runnerIncarnationPath(file, runnerIncarnation) {
    const token = sha256Hex(Buffer.from(runnerIncarnation, "utf8")).slice(0, 24);
    const extension = path.extname(file);
    const stem = extension.length === 0 ? file : file.slice(0, -extension.length);
    return `${stem}.r${token}${extension}`;
}

function runnerLaunchPaths(paths, runnerIncarnation) {
    return Object.freeze({
        childConfigPath: runnerIncarnationPath(
            paths.childConfigPath,
            runnerIncarnation,
        ),
        childResultPath: runnerIncarnationPath(
            paths.childResultPath,
            runnerIncarnation,
        ),
    });
}

function readStatusDocument(statusPath) {
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
            || (value.supervisorGeneration !== undefined
                && !isSupervisorGeneration(value.supervisorGeneration))
            || typeof value.heartbeatAt !== "string"
            || !Number.isFinite(Date.parse(value.heartbeatAt))) {
            return null;
        }
        return value;
    } catch {
        return null;
    }
}

function readStatusForOwnership(statusPath, owner = null) {
    if (owner !== null && isSupervisorGeneration(owner.supervisorGeneration)) {
        const owned = readStatusDocument(ownerScopedPath(statusPath, owner));
        if (owned !== null) {
            return owned;
        }
    }
    return readStatusDocument(statusPath);
}

function statusMatchesOwner(status, owner) {
    return status !== null
        && status.pid === owner.pid
        && status.nonce === owner.nonce
        && (!isSupervisorGeneration(owner.supervisorGeneration)
            || status.supervisorGeneration === owner.supervisorGeneration);
}

function hasFreshMatchingHeartbeat(lock, status, now, staleLockMs, isPidAlive) {
    if (lock === null || !statusMatchesOwner(status, lock)) {
        return false;
    }
    const heartbeatAgeMs = now - Date.parse(status.heartbeatAt);
    return Number.isFinite(heartbeatAgeMs)
        && heartbeatAgeMs >= -staleLockMs
        && heartbeatAgeMs < staleLockMs
        && isPidAlive(lock.pid);
}

function retainedNonQuiescentAuthority(lock, status, isPidAlive) {
    if (!statusMatchesOwner(status, lock)
        || !["failed_non_quiescent", "pause_pending"].includes(status.state)) {
        return false;
    }
    if (Number.isSafeInteger(status.childPid) && status.childPid > 0) {
        return isPidAlive(status.childPid);
    }
    return status.state === "failed_non_quiescent";
}

function ownershipLostError(lock, action, current = null) {
    const error = new SupervisorLockError(
        RUNTIME_ERROR_CODES.LOCK_HELD,
        "Supervisor generation ownership was lost",
        {
            action,
            lockPath: lock.lockPath,
            expected: {
                pid: lock.pid,
                nonce: lock.nonce,
                supervisorGeneration: lock.supervisorGeneration,
            },
            current: current === null
                ? null
                : {
                    pid: current.pid,
                    nonce: current.nonce,
                    supervisorGeneration: current.supervisorGeneration,
                },
        },
    );
    error.ownershipLost = true;
    return error;
}

function isOwnershipLostError(error) {
    return error?.ownershipLost === true;
}

function currentLockIfValid(lockPath) {
    try {
        return validateLockDocument(
            readJsonFile(lockPath, "supervisor lock"),
            lockPath,
        );
    } catch {
        return null;
    }
}

function assertSupervisorOwnership(lock, action) {
    const current = currentLockIfValid(lock.lockPath);
    if (current === null
        || current.pid !== lock.pid
        || current.nonce !== lock.nonce
        || current.supervisorGeneration !== lock.supervisorGeneration) {
        throw ownershipLostError(lock, action, current);
    }
    return current;
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

function persistGenerationRecord(config, lock, clock) {
    assertSupervisorOwnership(lock, "supervisor generation allocation");
    const current = readLatestGenerationDocument(
        config.paths,
        config.runner.investigationId,
    );
    if (current !== null) {
        if (current.supervisorGeneration > lock.supervisorGeneration
            || (current.supervisorGeneration === lock.supervisorGeneration
                && (current.nonce !== lock.nonce || current.pid !== lock.pid))) {
            throw new SupervisorLockError(
                RUNTIME_ERROR_CODES.LOCK_INVALID,
                "Supervisor generation record is ahead of the acquired lock",
                {
                    generationPath: config.paths.generationPath,
                    lockGeneration: lock.supervisorGeneration,
                    recordedGeneration: current.supervisorGeneration,
                },
            );
        }
        if (current.supervisorGeneration === lock.supervisorGeneration) {
            return current;
        }
    }
    const document = {
        version: 1,
        investigationId: config.runner.investigationId,
        supervisorGeneration: lock.supervisorGeneration,
        pid: lock.pid,
        nonce: lock.nonce,
        allocatedAt: clock.isoNow(),
    };
    const ownedGenerationPath = ownerScopedPath(config.paths.generationPath, lock);
    assertSupervisorOwnership(lock, "immutable supervisor generation record write");
    if (!publishLockCrashSafely(
        ownedGenerationPath,
        document,
        lock.pid,
        lock.nonce,
    )) {
        const existing = readGenerationDocument(
            ownedGenerationPath,
            config.runner.investigationId,
        );
        if (existing.supervisorGeneration !== lock.supervisorGeneration
            || existing.nonce !== lock.nonce
            || existing.pid !== lock.pid) {
            throw new SupervisorLockError(
                RUNTIME_ERROR_CODES.LOCK_INVALID,
                "Immutable supervisor generation record conflicts with the acquired lock",
                {
                    generationPath: ownedGenerationPath,
                    supervisorGeneration: lock.supervisorGeneration,
                },
            );
        }
    }
    assertSupervisorOwnership(lock, "supervisor generation high-water write");
    const shared = readGenerationDocument(
        config.paths.generationPath,
        config.runner.investigationId,
    );
    if (shared === null || shared.supervisorGeneration < lock.supervisorGeneration) {
        atomicWriteJson(config.paths.generationPath, document, {
            token: `generation:${lock.supervisorGeneration}:${lock.nonce}`,
        });
    } else if (shared.supervisorGeneration === lock.supervisorGeneration
        && (shared.nonce !== lock.nonce || shared.pid !== lock.pid)) {
        throw new SupervisorLockError(
            RUNTIME_ERROR_CODES.LOCK_INVALID,
            "Supervisor generation high-water record conflicts with the acquired lock",
            {
                generationPath: config.paths.generationPath,
                supervisorGeneration: lock.supervisorGeneration,
            },
        );
    }
    const verified = readLatestGenerationDocument(
        config.paths,
        config.runner.investigationId,
    );
    if (verified.supervisorGeneration !== lock.supervisorGeneration
        || verified.nonce !== lock.nonce
        || verified.pid !== lock.pid) {
        throw new SupervisorLockError(
            RUNTIME_ERROR_CODES.LOCK_INVALID,
            "Supervisor generation record verification failed",
            {
                generationPath: config.paths.generationPath,
                supervisorGeneration: lock.supervisorGeneration,
            },
        );
    }
    assertSupervisorOwnership(lock, "supervisor generation allocation verification");
    return verified;
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
    const startedAt = clock.isoNow();
    let observedGeneration = 0;
    const authorityHandle = openSupervisorAuthorityRepository(
        normalized,
        dependencies,
        clock,
    );

    try {
        for (let pass = 0; pass < 8; pass += 1) {
            const generationRecord = readLatestGenerationDocument(
                normalized.paths,
                normalized.runner.investigationId,
            );
            const authority = authorityHandle.repository.getSupervisorAuthority(
                normalized.runner.investigationId,
            );
            const supervisorGeneration = Math.max(
                observedGeneration,
                generationRecord?.supervisorGeneration ?? 0,
                authority?.supervisorGeneration ?? 0,
            ) + 1;
            const document = {
                pid,
                nonce,
                startedAt,
                supervisorGeneration,
            };
            validateLockDocument(document, lockPath);
            try {
                if (!publishLockCrashSafely(lockPath, document, pid, nonce)) {
                    throw Object.assign(new Error("lock exists"), { code: "EEXIST" });
                }
                const lock = Object.freeze({ ...document, lockPath });
                try {
                    persistGenerationRecord(normalized, lock, clock);
                    assertSupervisorOwnership(
                        lock,
                        "supervisor generation authority claim",
                    );
                    authorityHandle.repository.claimSupervisorGeneration({
                        investigationId: normalized.runner.investigationId,
                        supervisorGeneration,
                        supervisorNonce: nonce,
                    });
                    assertSupervisorOwnership(
                        lock,
                        "supervisor generation authority verification",
                    );
                    return lock;
                } catch (error) {
                    releaseSupervisorLock(lock);
                    throw error;
                }
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
            if (isSupervisorGeneration(inspected.parsed?.supervisorGeneration)) {
                observedGeneration = Math.max(
                    observedGeneration,
                    inspected.parsed.supervisorGeneration,
                );
            }
            const now = clock.now();
            const ageMs = now - inspected.mtimeMs;
            const looseOwner = inspected.valid ?? (
                isPlainObject(inspected.parsed)
                && Number.isSafeInteger(inspected.parsed.pid)
                && inspected.parsed.pid > 0
                && typeof inspected.parsed.nonce === "string"
                && inspected.parsed.nonce.length > 0
                    ? {
                        pid: inspected.parsed.pid,
                        nonce: inspected.parsed.nonce,
                        supervisorGeneration: isSupervisorGeneration(
                            inspected.parsed.supervisorGeneration,
                        )
                            ? inspected.parsed.supervisorGeneration
                            : undefined,
                    }
                    : null
            );
            const status = readStatusForOwnership(normalized.paths.statusPath, looseOwner);
            const retainedAuthority = looseOwner !== null
                && retainedNonQuiescentAuthority(looseOwner, status, isPidAlive);
            const freshOwner = looseOwner !== null
                && hasFreshMatchingHeartbeat(
                    looseOwner,
                    status,
                    now,
                    normalized.staleLockMs,
                    isPidAlive,
                );
            if (retainedAuthority
                || freshOwner
                || !Number.isFinite(ageMs)
                || ageMs < normalized.staleLockMs) {
                throw new SupervisorLockError(
                    RUNTIME_ERROR_CODES.LOCK_HELD,
                    "Another supervisor owns this investigation",
                    {
                        investigationId: normalized.runner.investigationId,
                        pid: inspected.valid?.pid ?? null,
                        nonce: inspected.valid?.nonce ?? null,
                        ageMs,
                        freshHeartbeat: freshOwner,
                        retainedNonQuiescentAuthority: retainedAuthority,
                        interventionRequired: retainedAuthority,
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
            const confirmedStatus = readStatusForOwnership(
                normalized.paths.statusPath,
                looseOwner,
            );
            if (looseOwner !== null && retainedNonQuiescentAuthority(
                looseOwner,
                confirmedStatus,
                isPidAlive,
            )) {
                throw new SupervisorLockError(
                    RUNTIME_ERROR_CODES.LOCK_HELD,
                    "Supervisor retained fenced authority for a non-quiescent child",
                    {
                        lockPath,
                        pid: looseOwner.pid,
                        nonce: looseOwner.nonce,
                        supervisorGeneration: looseOwner.supervisorGeneration ?? null,
                        childPid: confirmedStatus?.childPid ?? null,
                        interventionRequired: true,
                    },
                );
            }
            if (looseOwner !== null && hasFreshMatchingHeartbeat(
                looseOwner,
                confirmedStatus,
                clock.now(),
                normalized.staleLockMs,
                isPidAlive,
            )) {
                throw new SupervisorLockError(
                    RUNTIME_ERROR_CODES.LOCK_HELD,
                    "Supervisor heartbeat refreshed during stale recovery",
                    {
                        lockPath,
                        pid: looseOwner.pid,
                        nonce: looseOwner.nonce,
                        supervisorGeneration: looseOwner.supervisorGeneration ?? null,
                    },
                );
            }
            const staleClaimToken = sha256Hex(
                Buffer.from(`${nonce}:${randomUUID()}`, "utf8"),
            ).slice(0, 24);
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
    } finally {
        closeSupervisorAuthorityRepository(authorityHandle);
    }
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
    if (current.pid !== lock.pid
        || current.nonce !== lock.nonce
        || current.supervisorGeneration !== lock.supervisorGeneration) {
        return false;
    }
    fs.rmSync(lock.lockPath);
    fsyncDirectoryBestEffort(path.dirname(lock.lockPath));
    return true;
}

function runnerConfigForChild(config, lock, runnerIncarnation) {
    const supervisorAuthority = Object.freeze({
        supervisorGeneration: lock.supervisorGeneration,
        supervisorNonce: lock.nonce,
        runnerIncarnation,
    });
    return {
        investigationId: config.runner.investigationId,
        stateDir: config.runner.stateDir,
        artifactRoot: config.runner.artifactRoot,
        allowlistPath: config.runner.allowlistPath,
        copilotSdkPath: config.runner.sdkPath,
        copilotCliPath: config.runner.cliPath,
        runnerEpochId: config.runner.runnerEpochId,
        supervisorGeneration: lock.supervisorGeneration,
        supervisorNonce: lock.nonce,
        runnerIncarnation,
        deadline: config.runner.deadlineMs,
        resultPath: config.paths.childResultPath,
        options: {
            ...config.runner.options,
            supervisorAuthority,
        },
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

function defaultSpawnRunner(config, context) {
    context.assertOwnership("runner result cleanup");
    fs.rmSync(config.paths.childResultPath, { force: true });
    context.assertOwnership("runner configuration write");
    atomicWriteJson(config.paths.childConfigPath, context.runnerConfig, {
        token: `runner-config:${context.supervisorGeneration}:${
            context.runnerIncarnation
        }`,
    });
    context.assertOwnership("runner process launch");
    const processAdapter = context.processAdapter
        ?? createDefaultProcessAdapter();
    const remaining = remainingDeadlineMs(config.runner.deadlineMs);
    const child = processAdapter.spawn(
        process.execPath,
        [config.runnerCliPath, "--config", config.paths.childConfigPath],
        {
            cwd: config.runner.stateDir,
            stdio: ["ignore", "ignore", "ignore"],
            env: process.env,
            executesCandidateCode: false,
            launchPath: "host-process-adapter",
            timeoutMs: Number.isFinite(remaining)
                ? Math.max(1, Math.min(remaining, 0x7fffffff))
                : 0x7fffffff,
            ownerRoot: path.join(
                config.runner.options.tempRoot,
                ".supervisor-process-owners",
            ),
        },
    );
    return { child, resultPath: config.paths.childResultPath };
}

function consumeChildEnvelope(resultPath) {
    if (!fs.existsSync(resultPath)) {
        return null;
    }
    try {
        return normalizeRunnerOutcomeEnvelope(
            readJsonFile(resultPath, "runner outcome"),
        );
    } finally {
        fs.rmSync(resultPath, { force: true });
    }
}

function classifySuccessfulResult(envelope) {
    switch (envelope?.state) {
        case "terminal":
        case "non_result":
        case "pause":
            return envelope.state;
        default:
            return null;
    }
}

function persistSupervisorNonResult(
    config,
    lock,
    repository,
    dependencies,
    input,
    assertOwnership,
) {
    const failedRunnerIncarnation = input.runnerIncarnation ?? null;
    const writerToken = requireString(
        (dependencies.operationalWriterIdFactory ?? (() => randomUUID()))({
            investigationId: config.runner.investigationId,
            supervisorGeneration: lock.supervisorGeneration,
            supervisorNonce: lock.nonce,
            failedRunnerIncarnation,
            code: input.code,
            restartCount: input.restartCount ?? 0,
        }),
        "operational writer id",
        { max: 128 },
    );
    const writerIncarnation =
        `supervisor-operational-g${lock.supervisorGeneration}-${writerToken}`
            .replace(/[^A-Za-z0-9._@-]/gu, "-")
            .slice(0, 256);
    const identity = sha256Hex(Buffer.from(JSON.stringify({
        investigationId: config.runner.investigationId,
        supervisorGeneration: lock.supervisorGeneration,
        supervisorNonce: lock.nonce,
        writerIncarnation,
        failedRunnerIncarnation,
        code: input.code,
        restartCount: input.restartCount ?? 0,
    }), "utf8")).slice(0, 40);

    assertOwnership("operational non-result incarnation issue");
    repository.issueRunnerIncarnation({
        investigationId: config.runner.investigationId,
        supervisorGeneration: lock.supervisorGeneration,
        supervisorNonce: lock.nonce,
        runnerIncarnation: writerIncarnation,
    });
    assertOwnership("operational non-result lease acquisition");
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: config.runner.investigationId,
    });
    const { lease } = adapter.acquireRunnerLease({
        leaseId: `supervisor-operational-lease-${identity}`,
        owner: `supervisor-operational-g${lock.supervisorGeneration}`,
        supervisorGeneration: lock.supervisorGeneration,
        runnerIncarnation: writerIncarnation,
    });
    const command = formatAttemptCommand("operational-non-result", {
        source: "supervisor",
        code: input.code,
        restartCount: input.restartCount ?? 0,
        identity,
    });
    const attemptId = `supervisor-operational-${identity}`;
    adapter.reserveAttempt({ attemptId, command, lease });
    adapter.dispatchAttempt(attemptId, lease);
    adapter.observeAttempt(attemptId, lease);
    const details = {
        ...(isPlainObject(input.details) ? input.details : { value: input.details ?? null }),
        supervisorGeneration: lock.supervisorGeneration,
        supervisorNonce: lock.nonce,
        failedRunnerIncarnation,
        operationalWriterIncarnation: writerIncarnation,
        leaseId: lease.leaseId,
        fencingToken: lease.fencingToken,
    };
    assertOwnership("operational non-result fenced append");
    const persisted = adapter.ingestOperationalEvidenceBatchFenced([{
        attemptId,
        evidenceKind: `non-result:${input.code}`,
        kind: "runtime:non_result",
        payload: {
            code: input.code,
            reason: input.reason,
            details,
        },
    }], {
        attemptId,
        command,
        lease,
        fromState: "observed",
        toState: "committed",
    });
    const result = Object.freeze({
        persisted,
        runnerIncarnation: writerIncarnation,
        lease,
        supervisorGeneration: lock.supervisorGeneration,
        supervisorNonce: lock.nonce,
        code: input.code,
        reason: input.reason,
        details,
    });
    dependencies.recordOperationalNonResult?.(result);
    return result;
}

function readMatchingStopRequest(file, lock, assertOwnership) {
    if (!fs.existsSync(file)) return null;
    let request;
    try {
        request = readJsonFile(file, "supervisor stop request");
    } catch {
        return null;
    }
    if (!isPlainObject(request)
        || request.pid !== lock.pid
        || request.nonce !== lock.nonce
        || request.supervisorGeneration !== lock.supervisorGeneration
        || typeof request.requestedAt !== "string"
        || !Number.isFinite(Date.parse(request.requestedAt))) {
        return null;
    }
    assertOwnership("stop request consumption");
    fs.rmSync(file, { force: true });
    return request;
}

export async function runSupervisor(input, dependencies = {}) {
    const config = coerceSupervisorConfig(input, {
        env: dependencies.env ?? process.env,
    });
    const configFingerprint = supervisorConfigFingerprint(config);
    const clock = dependencies.clock ?? defaultClock();
    const timers = dependencies.timers ?? globalThis;
    const sleep = dependencies.sleep ?? ((milliseconds) => delay(milliseconds, timers));
    const processTreeAdapter = dependencies.processTreeAdapter ?? createDefaultProcessAdapter();
    const spawnRunner = dependencies.spawnRunner
        ?? ((runnerConfig, context) => defaultSpawnRunner(runnerConfig, {
            ...context,
            processAdapter: processTreeAdapter,
        }));
    const shutdownPolicy = normalizeShutdownPolicy(dependencies.shutdownPolicy);
    const shutdownTimers = dependencies.shutdownTimers ?? globalThis;
    const signalSource = dependencies.signalSource ?? process;
    const statusFaultInjector = dependencies.statusFaultInjector ?? null;
    if (statusFaultInjector !== null && typeof statusFaultInjector !== "function") {
        throw new RuntimeConfigError("statusFaultInjector must be a function or null");
    }
    const injectStatusFault = (point, details) => {
        if (statusFaultInjector === null) return;
        const result = statusFaultInjector(point, details);
        if (result !== null
            && typeof result === "object"
            && typeof result.then === "function") {
            throw new RuntimeConfigError(
                "statusFaultInjector must be synchronous",
                { point },
            );
        }
    };
    const lock = acquireSupervisorLock(config, {
        ...dependencies,
        clock,
    });
    let authorityHandle;
    try {
        authorityHandle = openSupervisorAuthorityRepository(
            config,
            dependencies,
            clock,
        );
    } catch (error) {
        releaseSupervisorLock(lock);
        throw error;
    }
    const scopedPaths = ownerRuntimePaths(config.paths, lock);
    const ownedConfig = Object.freeze({
        ...config,
        paths: Object.freeze({
            ...config.paths,
            ...scopedPaths,
        }),
    });
    const startedAt = lock.startedAt;
    let status = null;
    let statusRevision = 0;
    let heartbeatTimer = null;
    let controlTimer = null;
    let currentChild = null;
    let currentChildWait = null;
    let currentChildPid = null;
    let currentRunnerIncarnation = null;
    let restartCount = 0;
    let shutdownRequest = null;
    let resolveShutdown;
    const shutdownPromise = new Promise((resolve) => {
        resolveShutdown = resolve;
    });
    const crashes = [];
    const signalHandlers = new Map();
    let scavenging = null;
    let retainAuthority = false;

    const assertOwnership = (action) => assertSupervisorOwnership(lock, action);
    const scavengeRuntime = dependencies.scavengeRuntime
        ?? scavengeStaleGenerationOwnedPaths;
    const scavengingReferences = [
        config.runner.stateDir,
        config.runner.artifactRoot,
        config.runner.allowlistPath,
        config.runner.sdkPath,
        config.runner.cliPath,
        ...Object.values(config.paths),
        ...Object.values(scopedPaths),
    ];
    const scavengeOwnedPaths = (abandonedRunners = []) => scavengeRuntime({
        tempRoot: config.runner.options.tempRoot,
        supervisorDirectory: config.paths.directory,
        investigationId: config.runner.investigationId,
        currentGeneration: lock.supervisorGeneration,
        currentNonce: lock.nonce,
        currentPid: lock.pid,
        abandonedRunners,
        referencedPaths: scavengingReferences,
        isPidAlive: dependencies.isPidAlive ?? isExactPidAlive,
        now: clock.now(),
        minimumAgeMs: dependencies.scavengeMinimumAgeMs ?? 0,
    });
    const reapRunnerOwnedPaths = async (runnerIncarnation, runnerPid) => {
        if (typeof runnerIncarnation !== "string"
            || runnerIncarnation.length === 0) {
            return null;
        }
        return scavengeOwnedPaths([{
            runnerIncarnation,
            ...(Number.isSafeInteger(runnerPid) && runnerPid > 0
                ? { pid: runnerPid }
                : {}),
        }]);
    };
    const recordSupervisorNonResult = (input) => {
        const persisted = persistSupervisorNonResult(
            config,
            lock,
            authorityHandle.repository,
            dependencies,
            {
                ...input,
                runnerIncarnation: currentRunnerIncarnation,
            },
            assertOwnership,
        );
        currentRunnerIncarnation = persisted.runnerIncarnation;
        return persisted;
    };

    const requestShutdown = (request) => {
        if (shutdownRequest !== null) return;
        shutdownRequest = request;
        resolveShutdown(request);
    };

    const requestOwnershipLoss = (action, error = null) => {
        const request = {
            kind: "ownership_lost",
            action,
            error: error === null
                ? null
                : {
                    code: error?.code ?? null,
                    message: error?.message ?? String(error),
                },
            supervisorGeneration: lock.supervisorGeneration,
            nonce: lock.nonce,
        };
        if (shutdownRequest?.kind !== "ownership_lost") {
            shutdownRequest = request;
            resolveShutdown(request);
        }
    };

    const writeStatus = (state, extra = {}) => {
        assertOwnership(`${state} owner status write`);
        const terminalAvailable = state === "terminal"
            || extra.terminal_available === true;
        const nonResultCode = typeof extra.non_result_code === "string"
            && extra.non_result_code.length > 0
            ? extra.non_result_code
            : null;
        const nextStatus = {
            version: 4,
            investigationId: config.runner.investigationId,
            supervisorEpochId: config.supervisorEpochId,
            configFingerprint,
            deadlineMs: config.runner.deadlineMs,
            pid: lock.pid,
            nonce: lock.nonce,
            supervisorGeneration: lock.supervisorGeneration,
            startedAt,
            heartbeatAt: clock.isoNow(),
            state,
            restartCount,
            childPid: currentChildPid,
            runnerIncarnation: currentRunnerIncarnation,
            statusRevision: statusRevision + 1,
            terminal_available: terminalAvailable,
            non_result_code: nonResultCode,
        };
        atomicWriteJson(ownedConfig.paths.statusPath, nextStatus, {
            token: `status:${lock.supervisorGeneration}:${lock.nonce}:${nextStatus.statusRevision}`,
        });
        injectStatusFault("after_owner_status_write", {
            state,
            statusRevision: nextStatus.statusRevision,
            path: ownedConfig.paths.statusPath,
        });
        assertOwnership(`${state} shared status write`);
        atomicWriteJson(config.paths.statusPath, nextStatus, {
            token: `shared-status:${lock.supervisorGeneration}:${lock.nonce}:${nextStatus.statusRevision}`,
        });
        injectStatusFault("after_status_write", {
            state,
            statusRevision: nextStatus.statusRevision,
            path: config.paths.statusPath,
        });
        statusRevision = nextStatus.statusRevision;
        status = nextStatus;
        return status;
    };

    const startHeartbeat = () => {
        if (heartbeatTimer !== null) return;
        heartbeatTimer = timers.setInterval(() => {
            try {
                writeStatus(status?.state ?? "running", {
                    terminal_available: status?.terminal_available === true,
                    non_result_code: status?.non_result_code ?? null,
                });
            } catch (error) {
                if (isOwnershipLostError(error)) {
                    requestOwnershipLoss("heartbeat", error);
                } else {
                    requestShutdown({
                        kind: "control_failure",
                        error: {
                            code: error?.code ?? null,
                            message: error?.message ?? String(error),
                        },
                    });
                }
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
        const started = Date.now();
        const remaining = () => Math.max(
            0,
            shutdownPolicy.finalMs - (Date.now() - started),
        );
        const diagnostics = [];
        let exit = null;
        let jobObjectCloseAttempted = false;

        const runPhase = async (phase, force, timeoutMs) => {
            const budget = Math.max(1, Math.min(timeoutMs, remaining()));
            const termination = Number.isSafeInteger(pid) && pid > 0
                ? settleWithin(
                    () => processTreeAdapter.terminateTree(pid, {
                        force,
                        timeoutMs: budget,
                        phase,
                    }),
                    budget,
                    { timers: shutdownTimers },
                )
                : Promise.resolve({ status: "fulfilled", value: false });
            const childExit = settleWithin(wait, budget, { timers: shutdownTimers });
            const [terminationOutcome, exitOutcome] = await Promise.all([
                termination,
                childExit,
            ]);
            diagnostics.push({
                phase,
                force,
                terminationStatus: terminationOutcome.status,
                terminationResult: terminationOutcome.value ?? null,
                terminationError: terminationOutcome.error?.message ?? null,
                childStatus: exitOutcome.status,
            });
            if (exitOutcome.status === "fulfilled") {
                exit = exitOutcome.value;
                return true;
            }
            return false;
        };

        if (!(await runPhase("drain", false, shutdownPolicy.drainMs))) {
            const escalation = runPhase(
                "escalation",
                true,
                shutdownPolicy.escalationMs,
            );
            let jobClose = null;
            if (typeof processTreeAdapter.closeJobObject === "function") {
                jobObjectCloseAttempted = true;
                jobClose = settleWithin(
                    () => processTreeAdapter.closeJobObject(pid),
                    shutdownPolicy.escalationMs,
                    { timers: shutdownTimers },
                );
            }
            await escalation;
            if (jobClose !== null) {
                const closed = await jobClose;
                diagnostics.push({
                    phase: "job_object_close",
                    status: closed.status,
                    result: closed.value ?? null,
                    error: closed.error?.message ?? null,
                });
            }
        }
        if (exit === null
            && !jobObjectCloseAttempted
            && typeof processTreeAdapter.closeJobObject === "function"
            && remaining() > 0) {
            const budget = Math.max(1, remaining());
            const closed = await settleWithin(
                () => processTreeAdapter.closeJobObject(pid),
                budget,
                { timers: shutdownTimers },
            );
            diagnostics.push({
                phase: "job_object_close",
                status: closed.status,
                result: closed.value ?? null,
                error: closed.error?.message ?? null,
            });
        }
        if (exit === null && remaining() > 0) {
            const finalWait = await settleWithin(wait, remaining(), {
                timers: shutdownTimers,
            });
            diagnostics.push({ phase: "final_wait", status: finalWait.status });
            if (finalWait.status === "fulfilled") {
                exit = finalWait.value;
            }
        }
        if (exit === null) {
            exit = {
                code: null,
                signal: null,
                error: {
                    code: RUNTIME_ERROR_CODES.CHILD_CRASH,
                    message: "Runner child did not exit before the supervisor shutdown bound",
                },
                cleanupTimedOut: true,
            };
        }
        exit = {
            ...exit,
            shutdown: {
                bounded: true,
                elapsedMs: Date.now() - started,
                policy: shutdownPolicy,
                diagnostics,
            },
        };
        if (currentChild === child && exit.cleanupTimedOut !== true) {
            currentChild = null;
            currentChildWait = null;
            currentChildPid = null;
        }
        return exit;
    };

    try {
        scavenging = await scavengeOwnedPaths();
        for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
            const handler = () => requestShutdown({ kind: "signal", signal });
            signalHandlers.set(signal, handler);
            signalSource.on?.(signal, handler);
        }
        assertOwnership("stale stop request cleanup");
        fs.rmSync(ownedConfig.paths.stopRequestPath, { force: true });
        controlTimer = timers.setInterval(() => {
            try {
                assertOwnership("supervisor control poll");
                const request = readMatchingStopRequest(
                    ownedConfig.paths.stopRequestPath,
                    lock,
                    assertOwnership,
                );
                if (request !== null) {
                    requestShutdown({ kind: "stop_request", request });
                }
            } catch (error) {
                if (isOwnershipLostError(error)) {
                    requestOwnershipLoss("control_poll", error);
                } else {
                    requestShutdown({
                        kind: "control_failure",
                        error: {
                            code: error?.code ?? null,
                            message: error?.message ?? String(error),
                        },
                    });
                }
            }
        }, Math.min(config.heartbeatIntervalMs, 250));

        writeStatus("starting", {
            scavenging: {
                removedCount: scavenging?.removed?.length ?? 0,
                preservedCount: scavenging?.preserved?.length ?? 0,
            },
        });
        for (let launchNumber = 1; ; launchNumber += 1) {
            assertOwnership("supervisor control loop");
            if (shutdownRequest !== null) {
                if (shutdownRequest.kind === "ownership_lost") {
                    return {
                        kind: "STOPPED",
                        status,
                        ownershipLost: true,
                        shutdown: shutdownRequest,
                    };
                }
                writeStatus("stopped", { shutdown: shutdownRequest });
                return { kind: "STOPPED", status };
            }
            let launched;
            let launchConfig = ownedConfig;
            try {
                assertOwnership(restartCount === 0 ? "runner launch" : "runner restart");
                const runnerIncarnationFactory =
                    dependencies.runnerIncarnationFactory ?? (() => randomUUID());
                const runnerIncarnation = requireString(
                    runnerIncarnationFactory({
                        investigationId: config.runner.investigationId,
                        supervisorGeneration: lock.supervisorGeneration,
                        supervisorNonce: lock.nonce,
                        launchNumber,
                        restartCount,
                    }),
                    "runner incarnation",
                    { max: 256 },
                );
                assertOwnership("runner incarnation persistence");
                authorityHandle.repository.issueRunnerIncarnation({
                    investigationId: config.runner.investigationId,
                    supervisorGeneration: lock.supervisorGeneration,
                    supervisorNonce: lock.nonce,
                    runnerIncarnation,
                });
                assertOwnership("runner incarnation launch binding");
                currentRunnerIncarnation = runnerIncarnation;
                launchConfig = Object.freeze({
                    ...ownedConfig,
                    paths: Object.freeze({
                        ...ownedConfig.paths,
                        ...runnerLaunchPaths(
                            ownedConfig.paths,
                            runnerIncarnation,
                        ),
                    }),
                });
                const runnerConfig = runnerConfigForChild(
                    launchConfig,
                    lock,
                    runnerIncarnation,
                );
                launched = await spawnRunner(launchConfig, {
                    launchNumber,
                    restartCount,
                    runnerConfig,
                    supervisorGeneration: lock.supervisorGeneration,
                    supervisorNonce: lock.nonce,
                    runnerIncarnation,
                    assertOwnership,
                });
            } catch (error) {
                if (isOwnershipLostError(error)) {
                    throw error;
                }
                launched = {
                    error,
                    child: null,
                    resultPath: launchConfig.paths.childResultPath,
                };
            }

            if (launched?.child !== null && launched?.child !== undefined) {
                currentChild = launched.child;
                currentChildPid = launched.child.pid ?? null;
                currentChildWait = waitForChild(launched.child);
            }
            assertOwnership("runner launch completion");

            if (currentChild === null) {
                const error = launched?.error ?? new Error("spawnRunner returned no child");
                crashes.push(clock.now());
                writeStatus("crashed", {
                    lastError: {
                        code: RUNTIME_ERROR_CODES.CHILD_CRASH,
                        message: error.message,
                    },
                });
            } else {
                writeStatus("running", { launchNumber });
                startHeartbeat();
                const completed = await Promise.race([
                    currentChildWait.then((exit) => ({ kind: "child_exit", exit })),
                    shutdownPromise.then((request) => ({ kind: "shutdown", request })),
                ]);
                if (completed.kind === "shutdown") {
                    const exitedRunnerPid = currentChildPid;
                    const exitedRunnerIncarnation = currentRunnerIncarnation;
                    const exit = await terminateCurrentChild();
                    stopHeartbeat();
                    if (exit?.cleanupTimedOut === true) {
                        retainAuthority = true;
                        writeStatus("pause_pending", {
                            non_result_code: RUNTIME_ERROR_CODES.NON_QUIESCENT,
                        });
                        return {
                            kind: "PAUSE_PENDING",
                            status,
                            terminalAvailable: false,
                            nonResultCode: RUNTIME_ERROR_CODES.NON_QUIESCENT,
                            exit,
                        };
                    }
                    await reapRunnerOwnedPaths(
                        exitedRunnerIncarnation,
                        exitedRunnerPid,
                    );
                    if (completed.request.kind === "ownership_lost") {
                        retainAuthority = true;
                        return {
                            kind: "STOPPED",
                            status,
                            ownershipLost: true,
                            shutdown: completed.request,
                            exit,
                        };
                    }
                    writeStatus("stopped", { shutdown: completed.request, exit });
                    return { kind: "STOPPED", status };
                }
                const exit = completed.exit;
                const exitedRunnerPid = currentChildPid;
                const exitedRunnerIncarnation = currentRunnerIncarnation;
                currentChild = null;
                currentChildWait = null;
                currentChildPid = null;
                stopHeartbeat();
                assertOwnership("runner result processing");
                const reapExitedRunner = () => reapRunnerOwnedPaths(
                    exitedRunnerIncarnation,
                    exitedRunnerPid,
                );

                let envelope = null;
                let envelopeError = null;
                try {
                    assertOwnership("runner result read");
                    envelope = consumeChildEnvelope(
                        launched.resultPath ?? launchConfig.paths.childResultPath,
                    );
                } catch (error) {
                    if (isOwnershipLostError(error)) {
                        throw error;
                    }
                    envelopeError = error;
                }

                if (envelope?.ok === true) {
                    const finalState = classifySuccessfulResult(envelope);
                    if (finalState === null) {
                        await reapExitedRunner();
                        const reason = "Runner returned an unsupported result kind";
                        recordSupervisorNonResult({
                            code: RUNTIME_ERROR_CODES.RESULT_MISSING,
                            reason,
                            restartCount,
                            details: { exit, recoverable: false },
                        });
                        writeStatus("failed", {
                            non_result_code: RUNTIME_ERROR_CODES.RESULT_MISSING,
                        });
                        return {
                            kind: "FAILED",
                            status,
                            terminalAvailable: false,
                            nonResultCode: RUNTIME_ERROR_CODES.RESULT_MISSING,
                        };
                    }
                    await reapExitedRunner();
                    writeStatus(finalState, {
                        terminal_available: envelope.terminal_available,
                        non_result_code: envelope.non_result_code,
                    });
                    return {
                        kind: finalState === "terminal"
                            ? "TERMINAL"
                            : finalState === "pause"
                                ? "PAUSE"
                                : "NON_RESULT",
                        status,
                        terminalAvailable: envelope.terminal_available,
                        nonResultCode: envelope.non_result_code,
                    };
                }

                const recoverable = envelope?.ok === false
                    ? envelope.recoverable === true
                    : envelopeError === null
                        && exit.code !== 64
                        && exit.code !== 65;
                const lastError = {
                    code: envelope?.non_result_code
                        ?? envelopeError?.code
                        ?? RUNTIME_ERROR_CODES.RESULT_MISSING,
                    message: envelope?.ok === false
                        ? "Runner reported an opaque failure outcome"
                        : envelopeError?.message
                            ?? exit.error?.message
                            ?? "Runner exited without an outcome envelope",
                    recoverable,
                };
                if (lastError.code === RUNTIME_ERROR_CODES.NON_QUIESCENT) {
                    retainAuthority = true;
                    writeStatus("failed_non_quiescent", {
                        non_result_code: RUNTIME_ERROR_CODES.NON_QUIESCENT,
                    });
                    return {
                        kind: "FAILED_NON_QUIESCENT",
                        status,
                        terminalAvailable: false,
                        nonResultCode: RUNTIME_ERROR_CODES.NON_QUIESCENT,
                        error: lastError,
                    };
                }
                if (!recoverable) {
                    await reapExitedRunner();
                    recordSupervisorNonResult({
                        code: lastError.code ?? RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
                        reason: lastError.message ?? "Runner failed without a recoverable outcome.",
                        restartCount,
                        details: { exit, recoverable: false },
                    });
                    writeStatus("failed", { non_result_code: lastError.code });
                    return { kind: "FAILED", status, error: lastError };
                }
                await reapExitedRunner();
                crashes.push(clock.now());
                writeStatus("crashed");
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
                recordSupervisorNonResult({
                    code: RUNTIME_ERROR_CODES.CIRCUIT_OPEN,
                    reason,
                    restartCount,
                    details: { circuit, recoverable: false },
                });
                writeStatus("circuit_open", {
                    non_result_code: RUNTIME_ERROR_CODES.CIRCUIT_OPEN,
                });
                return {
                    kind: "CIRCUIT_OPEN",
                    status,
                    error: new CrucibleRuntimeError(
                        RUNTIME_ERROR_CODES.CIRCUIT_OPEN,
                        reason,
                    ),
                };
            }

            restartCount += 1;
            const configuredBackoffMs = Math.min(
                config.maxBackoffMs,
                config.baseBackoffMs * (2 ** (restartCount - 1)),
            );
            const remainingBudget = remainingDeadlineMs(
                config.runner.deadlineMs,
                clock.now(),
            );
            const backoffMs = Number.isFinite(remainingBudget)
                ? Math.min(configuredBackoffMs, remainingBudget)
                : configuredBackoffMs;
            writeStatus("backoff", { backoffMs });
            assertOwnership("runner restart backoff");
            const completed = await Promise.race([
                sleep(backoffMs).then(() => ({ kind: "backoff_complete" })),
                shutdownPromise.then((request) => ({ kind: "shutdown", request })),
            ]);
            if (completed.kind === "shutdown") {
                if (completed.request.kind === "ownership_lost") {
                    return {
                        kind: "STOPPED",
                        status,
                        ownershipLost: true,
                        shutdown: completed.request,
                    };
                }
                writeStatus("stopped", { shutdown: completed.request });
                return { kind: "STOPPED", status };
            }
        }
    } catch (error) {
        if (!isOwnershipLostError(error)) {
            throw error;
        }
        requestOwnershipLoss(error?.details?.action ?? "supervisor action", error);
        retainAuthority = true;
        const exitedRunnerPid = currentChildPid;
        const exitedRunnerIncarnation = currentRunnerIncarnation;
        const exit = await terminateCurrentChild();
        if (exit?.cleanupTimedOut !== true) {
            await reapRunnerOwnedPaths(
                exitedRunnerIncarnation,
                exitedRunnerPid,
            );
        }
        return {
            kind: "STOPPED",
            status,
            ownershipLost: true,
            shutdown: shutdownRequest,
            exit,
        };
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
        const exitedRunnerPid = currentChildPid;
        const exitedRunnerIncarnation = currentRunnerIncarnation;
        let cleanupFailure = null;
        try {
            if (!retainAuthority) {
                const exit = await terminateCurrentChild();
                if (exit?.cleanupTimedOut === true) {
                    retainAuthority = true;
                    cleanupFailure = new CrucibleRuntimeError(
                        RUNTIME_ERROR_CODES.NON_QUIESCENT,
                        "Supervisor could not prove that the runner child process tree exited",
                        {
                            childPid: exitedRunnerPid,
                            runnerIncarnation: exitedRunnerIncarnation,
                            shutdown: exit.shutdown ?? null,
                            interventionRequired: true,
                        },
                    );
                } else {
                    await reapRunnerOwnedPaths(
                        exitedRunnerIncarnation,
                        exitedRunnerPid,
                    );
                }
            }
            if (typeof processTreeAdapter.close === "function") {
                const closed = await settleWithin(
                    () => processTreeAdapter.close({
                        timeoutMs: shutdownPolicy.finalMs,
                    }),
                    shutdownPolicy.finalMs,
                    { timers: shutdownTimers },
                );
                if (closed.status !== "fulfilled") {
                    retainAuthority = true;
                    cleanupFailure ??= new CrucibleRuntimeError(
                        RUNTIME_ERROR_CODES.NON_QUIESCENT,
                        "Supervisor process-owner cleanup did not complete within its bound",
                        {
                            status: closed.status,
                            error: closed.error?.message ?? null,
                            interventionRequired: true,
                        },
                        closed.error === undefined
                            ? undefined
                            : { cause: closed.error },
                    );
                }
            }
            if (cleanupFailure !== null) {
                try {
                    writeStatus("failed_non_quiescent", {
                        non_result_code: RUNTIME_ERROR_CODES.NON_QUIESCENT,
                    });
                } catch (error) {
                    cleanupFailure.details = {
                        ...(cleanupFailure.details ?? {}),
                        statusWriteFailure: {
                            code: error?.code ?? null,
                            message: error?.message ?? String(error),
                        },
                    };
                }
            }
        } finally {
            try {
                closeSupervisorAuthorityRepository(authorityHandle);
            } finally {
                if (!retainAuthority) {
                    releaseSupervisorLock(lock);
                }
            }
        }
        if (cleanupFailure !== null) {
            throw cleanupFailure;
        }
    }
}

export function readSupervisorStatus(stateDir, investigationId) {
    const paths = supervisorPaths(stateDir, investigationId);
    const generation = readLatestGenerationDocument(paths, investigationId);
    const lock = fs.existsSync(paths.lockPath)
        ? currentLockIfValid(paths.lockPath)
        : null;
    let expectedOwner = null;
    if (generation !== null && lock !== null) {
        expectedOwner = generation.supervisorGeneration >= lock.supervisorGeneration
            ? generation
            : lock;
    } else {
        expectedOwner = generation ?? lock;
    }
    const status = readStatusForOwnership(paths.statusPath, expectedOwner);
    if (status === null) {
        return null;
    }
    if (expectedOwner !== null && !statusMatchesOwner(status, expectedOwner)) {
        return null;
    }
    return status;
}

export function terminateExactSupervisor({
    lockPath,
    statusPath,
    stopRequestPath,
    expectedNonce,
    expectedGeneration,
    signal = "SIGTERM",
    processApi = process,
    clock = defaultClock(),
    staleAfterMs = 30_000,
} = {}) {
    const lock = Object.freeze({
        ...validateLockDocument(readJsonFile(lockPath, "supervisor lock"), lockPath),
        lockPath,
    });
    if (expectedNonce !== undefined && lock.nonce !== expectedNonce) {
        throw new SupervisorLockError(
            RUNTIME_ERROR_CODES.LOCK_HELD,
            "Supervisor nonce changed; refusing to terminate an unverified PID",
            { lockPath },
        );
    }
    if (expectedGeneration !== undefined
        && lock.supervisorGeneration !== expectedGeneration) {
        throw new SupervisorLockError(
            RUNTIME_ERROR_CODES.LOCK_HELD,
            "Supervisor generation changed; refusing to terminate an unverified PID",
            { lockPath, expectedGeneration, actualGeneration: lock.supervisorGeneration },
        );
    }
    const status = readStatusForOwnership(statusPath, lock);
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
                supervisorGeneration: lock.supervisorGeneration,
            },
        );
    }
    if (typeof stopRequestPath !== "string" || !path.isAbsolute(stopRequestPath)) {
        throw new RuntimeConfigError("stopRequestPath must be an absolute path");
    }
    const ownedStopRequestPath = ownerScopedPath(stopRequestPath, lock);
    assertSupervisorOwnership(lock, "supervisor stop request write");
    atomicWriteJson(ownedStopRequestPath, {
        version: 2,
        pid: lock.pid,
        nonce: lock.nonce,
        supervisorGeneration: lock.supervisorGeneration,
        signal,
        requestedAt: clock.isoNow(),
    }, {
        token: `stop:${lock.supervisorGeneration}:${lock.nonce}`,
    });
    assertSupervisorOwnership(lock, "supervisor stop request verification");
    return {
        action: "stop_requested",
        pid: lock.pid,
        nonce: lock.nonce,
        supervisorGeneration: lock.supervisorGeneration,
        signal,
        stopRequestPath: ownedStopRequestPath,
    };
}
