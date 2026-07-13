import fs from "node:fs";
import path from "node:path";

import {
    EVENT_TYPES,
    decideNext,
} from "../domain/index.mjs";
import {
    openRepositoryReadOnly,
} from "../persistence/index.mjs";
import {
    CrucibleRuntimeError,
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
} from "./errors.mjs";
import {
    atomicWriteJson,
    delay,
    ensureDirectory,
    isPlainObject,
    readJsonFile,
    safeFileToken,
    sha256Hex,
} from "./utils.mjs";

export const QUIESCENT_STOP_PROTOCOL_VERSION = 1;
export const QUIESCENT_STOP_STATES = Object.freeze({
    BARRIER_PERSISTED: "STOP_BARRIER_PERSISTED",
    RECONCILING: "STOP_RECONCILING",
    SUPERSEDED: "STOP_SUPERSEDED",
    PAUSE_PENDING: "PAUSE_PENDING",
    PAUSED_QUIESCENT: "PAUSED_QUIESCENT",
});
export const ACTIVE_QUIESCENT_STOP_STATES = Object.freeze([
    QUIESCENT_STOP_STATES.BARRIER_PERSISTED,
    QUIESCENT_STOP_STATES.RECONCILING,
    QUIESCENT_STOP_STATES.PAUSE_PENDING,
]);
const ACTIVE_STOP_STATES = new Set(ACTIVE_QUIESCENT_STOP_STATES);

export const QUIESCENT_STOP_INTEGRATION_NOTES = Object.freeze({
    protocolVersion: QUIESCENT_STOP_PROTOCOL_VERSION,
    barrier:
        "persistQuiescentStopBarrier atomically releases the active runner lease and abandons its committable attempts before any control signal is published",
    resourceBroker:
        "Broker authority must be retired and independently verified before buildQuiescenceSnapshot can prove zero active leases",
    sdkRetries:
        "late SDK responses must surface through the runner barrier and remain uncommitted; retry classification is intentionally outside this module",
    completion:
        "only PAUSED_QUIESCENT is resumable; PAUSE_PENDING retains supervisor authority and requires intervention",
});

function requireOwner(owner, label = "control owner") {
    if (!isPlainObject(owner)
        || !Number.isSafeInteger(owner.pid)
        || owner.pid < 1
        || !Number.isSafeInteger(owner.supervisorGeneration)
        || owner.supervisorGeneration < 1
        || typeof owner.nonce !== "string"
        || owner.nonce.length === 0) {
        throw new RuntimeConfigError(`${label} is invalid`, { owner });
    }
    return owner;
}

function requireRunner(runner) {
    if (!isPlainObject(runner)
        || !Number.isSafeInteger(runner.pid)
        || runner.pid < 1
        || typeof runner.runnerIncarnation !== "string"
        || runner.runnerIncarnation.length === 0) {
        throw new RuntimeConfigError("runner control target is invalid", {
            runner,
        });
    }
    return runner;
}

function requireStop(stop) {
    if (!isPlainObject(stop)
        || typeof stop.investigationId !== "string"
        || stop.investigationId.length === 0
        || typeof stop.requestId !== "string"
        || stop.requestId.length === 0
        || typeof stop.state !== "string") {
        throw new RuntimeConfigError("quiescent stop record is invalid");
    }
    return stop;
}

export function isActiveQuiescentStop(stop) {
    return stop !== null
        && isPlainObject(stop)
        && ACTIVE_STOP_STATES.has(stop.state);
}

export function stopControlPaths(stateDir, investigationId) {
    if (typeof stateDir !== "string" || !path.isAbsolute(stateDir)) {
        throw new RuntimeConfigError("stateDir must be absolute");
    }
    if (typeof investigationId !== "string" || investigationId.length === 0) {
        throw new RuntimeConfigError("investigationId is required");
    }
    const directory = path.join(path.resolve(stateDir), "supervisor");
    const token = safeFileToken(investigationId);
    return Object.freeze({
        directory,
        supervisorRequestPath: path.join(
            directory,
            `${token}.stop-request.json`,
        ),
        runnerRequestPath: path.join(
            directory,
            `${token}.runner-stop-request.json`,
        ),
    });
}

export function ownerScopedControlPath(file, owner) {
    requireOwner(owner);
    if (typeof file !== "string" || !path.isAbsolute(file)) {
        throw new RuntimeConfigError("control path must be absolute", { file });
    }
    const token = sha256Hex(Buffer.from(owner.nonce, "utf8")).slice(0, 24);
    const extension = path.extname(file);
    const stem = extension.length === 0 ? file : file.slice(0, -extension.length);
    return `${stem}.g${owner.supervisorGeneration}-${token}${extension}`;
}

export function runnerScopedControlPath(file, owner, runner) {
    const owned = ownerScopedControlPath(file, owner);
    requireRunner(runner);
    const token = sha256Hex(
        Buffer.from(runner.runnerIncarnation, "utf8"),
    ).slice(0, 24);
    const extension = path.extname(owned);
    const stem = extension.length === 0
        ? owned
        : owned.slice(0, -extension.length);
    return `${stem}.r${token}${extension}`;
}

function controlDocument(kind, stop, owner, runner, clock) {
    const record = requireStop(stop);
    const target = requireOwner(owner);
    return {
        version: QUIESCENT_STOP_PROTOCOL_VERSION,
        kind,
        investigationId: record.investigationId,
        requestId: record.requestId,
        barrierAt: record.barrierAt,
        target: {
            pid: target.pid,
            nonce: target.nonce,
            supervisorGeneration: target.supervisorGeneration,
            ...(runner === null
                ? {}
                : {
                    runnerPid: runner.pid,
                    runnerIncarnation: runner.runnerIncarnation,
                }),
        },
        requestedAt: clock.isoNow(),
    };
}

function validateControlDocument(document, kind, stop, owner, runner = null) {
    const record = requireStop(stop);
    const target = requireOwner(owner);
    if (!isPlainObject(document)
        || document.version !== QUIESCENT_STOP_PROTOCOL_VERSION
        || document.kind !== kind
        || document.investigationId !== record.investigationId
        || document.requestId !== record.requestId
        || document.barrierAt !== record.barrierAt
        || !isPlainObject(document.target)
        || document.target.pid !== target.pid
        || document.target.nonce !== target.nonce
        || document.target.supervisorGeneration !== target.supervisorGeneration
        || typeof document.requestedAt !== "string"
        || !Number.isFinite(Date.parse(document.requestedAt))) {
        return null;
    }
    if (runner !== null) {
        const exactRunner = requireRunner(runner);
        if (document.target.runnerPid !== exactRunner.pid
            || document.target.runnerIncarnation
                !== exactRunner.runnerIncarnation) {
            return null;
        }
    }
    return Object.freeze(document);
}

function writeControl(file, document, token) {
    ensureDirectory(path.dirname(file));
    atomicWriteJson(file, document, { token });
    return file;
}

export function writeSupervisorStopSignal({
    paths,
    stop,
    owner,
    clock = {
        isoNow: () => new Date().toISOString(),
    },
} = {}) {
    const record = requireStop(stop);
    const target = requireOwner(owner);
    if (record.targetSupervisorGeneration !== target.supervisorGeneration
        || record.targetSupervisorNonce !== target.nonce
        || (record.targetSupervisorPid !== null
            && record.targetSupervisorPid !== target.pid)) {
        throw new RuntimeConfigError(
            "stop record does not target the exact supervisor owner",
            {
                requestId: record.requestId,
                targetSupervisorGeneration:
                    record.targetSupervisorGeneration,
                actualSupervisorGeneration: target.supervisorGeneration,
            },
        );
    }
    const file = ownerScopedControlPath(paths.supervisorRequestPath, target);
    const document = controlDocument(
        "crucible-supervisor-stop",
        record,
        target,
        null,
        clock,
    );
    writeControl(
        file,
        document,
        `supervisor-stop:${target.supervisorGeneration}:${record.requestId}`,
    );
    return Object.freeze({ file, document });
}

export function consumeSupervisorStopSignal({
    paths,
    stop,
    owner,
} = {}) {
    const file = ownerScopedControlPath(paths.supervisorRequestPath, owner);
    if (!fs.existsSync(file)) return null;
    let document;
    try {
        document = readJsonFile(file, "supervisor stop control", {
            maxBytes: 64 * 1024,
        });
    } catch {
        return null;
    }
    const validated = validateControlDocument(
        document,
        "crucible-supervisor-stop",
        stop,
        owner,
    );
    if (validated === null) return null;
    fs.rmSync(file, { force: true });
    return validated;
}

export function writeRunnerStopSignal({
    paths,
    stop,
    owner,
    runner,
    clock = {
        isoNow: () => new Date().toISOString(),
    },
} = {}) {
    const file = runnerScopedControlPath(
        paths.runnerRequestPath,
        owner,
        runner,
    );
    const document = controlDocument(
        "crucible-runner-stop",
        stop,
        owner,
        runner,
        clock,
    );
    writeControl(
        file,
        document,
        `runner-stop:${owner.supervisorGeneration}:${stop.requestId}`,
    );
    return Object.freeze({ file, document });
}

export function consumeRunnerStopSignal({
    paths,
    stop,
    owner,
    runner,
} = {}) {
    const file = runnerScopedControlPath(
        paths.runnerRequestPath,
        owner,
        runner,
    );
    if (!fs.existsSync(file)) return null;
    let document;
    try {
        document = readJsonFile(file, "runner stop control", {
            maxBytes: 64 * 1024,
        });
    } catch {
        return null;
    }
    const validated = validateControlDocument(
        document,
        "crucible-runner-stop",
        stop,
        owner,
        runner,
    );
    if (validated === null) return null;
    fs.rmSync(file, { force: true });
    return validated;
}

export function persistQuiescentStopBarrier({
    repository,
    investigationId,
    requestId,
    reason,
    pauseRequested = true,
    owner = null,
    runnerPid = null,
    details = {},
} = {}) {
    if (repository === null
        || typeof repository?.persistQuiescentStopBarrier !== "function") {
        throw new RuntimeConfigError(
            "repository does not support the quiescent-stop protocol",
        );
    }
    const target = owner === null ? null : requireOwner(owner);
    return repository.persistQuiescentStopBarrier({
        investigationId,
        requestId,
        reason,
        pauseRequested,
        expectedSupervisorGeneration:
            target?.supervisorGeneration ?? null,
        expectedSupervisorNonce: target?.nonce ?? null,
        targetSupervisorPid: target?.pid ?? null,
        targetRunnerPid: runnerPid,
        details,
    });
}

export function ensureStopDomainIntent(adapter, stop) {
    const record = requireStop(stop);
    let replay = adapter.replay();
    if (replay.aggregate.terminal !== null
        || replay.aggregate.nonResults.length > 0) {
        return replay;
    }
    const present = replay.aggregate.stopRequests.some((request) =>
        request.requestId === record.requestId);
    if (!present) {
        adapter.requestStop({
            requestId: record.requestId,
            reason: record.reason,
            pauseRequested: record.pauseRequested,
        });
        replay = adapter.replay();
    }
    return replay;
}

function sortedPositiveIntegers(values, field) {
    if (!Array.isArray(values)) {
        throw new RuntimeConfigError(`${field} must be an array`);
    }
    return Object.freeze([...new Set(values.map((value) => {
        if (!Number.isSafeInteger(value) || value < 1) {
            throw new RuntimeConfigError(
                `${field} must contain positive integer identifiers`,
                { value },
            );
        }
        return value;
    }))].sort((left, right) => left - right));
}

function unverifiedProbe(value) {
    return Object.freeze({
        verified: false,
        reason: typeof value?.reason === "string"
            ? value.reason
            : "probe unavailable or unverified",
    });
}

function normalizeSupervisorStatus(value) {
    if (value?.verified !== true) return unverifiedProbe(value);
    const owner = requireOwner({
        pid: value.pid,
        nonce: value.supervisorNonce,
        supervisorGeneration: value.supervisorGeneration,
    }, "verified supervisor status");
    if (value.runnerIncarnation !== null
        && (typeof value.runnerIncarnation !== "string"
            || value.runnerIncarnation.length === 0)) {
        throw new RuntimeConfigError(
            "verified supervisor status runnerIncarnation is invalid",
        );
    }
    return Object.freeze({
        verified: true,
        pid: owner.pid,
        supervisorGeneration: owner.supervisorGeneration,
        supervisorNonce: owner.nonce,
        runnerIncarnation: value.runnerIncarnation ?? null,
        state: typeof value.state === "string" ? value.state : null,
    });
}

function normalizeProcessProbe(value) {
    if (value?.verified !== true) return unverifiedProbe(value);
    return Object.freeze({
        verified: true,
        activePids: sortedPositiveIntegers(
            value.activePids,
            "processes.activePids",
        ),
    });
}

function normalizeSdkProbe(value) {
    if (value?.verified !== true) return unverifiedProbe(value);
    if (!Number.isSafeInteger(value.activeCount) || value.activeCount < 0) {
        throw new RuntimeConfigError(
            "sdkSessions.activeCount must be a non-negative integer",
        );
    }
    return Object.freeze({
        verified: true,
        activeCount: value.activeCount,
        source: typeof value.source === "string" ? value.source : null,
    });
}

function normalizeRunnerChild(value) {
    if (value?.verified !== true) return unverifiedProbe(value);
    if (typeof value.active !== "boolean"
        || (value.pid !== null
            && (!Number.isSafeInteger(value.pid) || value.pid < 1))
        || (value.runnerIncarnation !== null
            && (typeof value.runnerIncarnation !== "string"
                || value.runnerIncarnation.length === 0))
        || (value.active && value.pid === null)) {
        throw new RuntimeConfigError("runnerChild verification is invalid");
    }
    return Object.freeze({
        verified: true,
        active: value.active,
        pid: value.pid ?? null,
        runnerIncarnation: value.runnerIncarnation ?? null,
    });
}

function normalizeBrokerProbe(value) {
    if (value?.verified !== true) return unverifiedProbe(value);
    if (typeof value.configured !== "boolean"
        || typeof value.authorityRetired !== "boolean"
        || !Array.isArray(value.activeLeases)) {
        throw new RuntimeConfigError("resourceBroker verification is invalid");
    }
    if (value.configured
        && (!Number.isSafeInteger(value.supervisorGeneration)
            || value.supervisorGeneration < 1
            || typeof value.supervisorNonce !== "string"
            || value.supervisorNonce.length === 0
            || typeof value.runnerIncarnation !== "string"
            || value.runnerIncarnation.length === 0)) {
        throw new RuntimeConfigError(
            "configured resourceBroker authority is incomplete",
        );
    }
    return Object.freeze({
        verified: true,
        configured: value.configured,
        authorityRetired: value.authorityRetired,
        supervisorGeneration: value.supervisorGeneration ?? null,
        supervisorNonce: value.supervisorNonce ?? null,
        runnerIncarnation: value.runnerIncarnation ?? null,
        activeLeases: Object.freeze(value.activeLeases.map((lease) =>
            Object.freeze({ ...lease }))),
    });
}

export function buildQuiescenceSnapshot({
    repository,
    investigationId,
    supervisorStatus = null,
    processes = null,
    sdkSessions = null,
    runnerChild = null,
    resourceBroker = null,
} = {}) {
    const status = normalizeSupervisorStatus(supervisorStatus);
    const processProbe = normalizeProcessProbe(processes);
    const sdkProbe = normalizeSdkProbe(sdkSessions);
    const child = normalizeRunnerChild(runnerChild);
    const broker = normalizeBrokerProbe(resourceBroker);
    const repositoryVerified = repository !== null
        && typeof repository?.getActiveLease === "function"
        && typeof repository?.listCommittableAttempts === "function"
        && typeof repository?.getSupervisorAuthority === "function"
        && typeof repository?.getQuiescentStop === "function";
    const activeLease = repositoryVerified
        ? repository.getActiveLease(investigationId)
        : null;
    const committableAttempts = repositoryVerified
        ? repository.listCommittableAttempts(investigationId)
        : null;
    const authority = repositoryVerified
        ? repository.getSupervisorAuthority(investigationId)
        : null;
    const stop = repositoryVerified
        ? repository.getQuiescentStop(investigationId)
        : null;
    const expectedRunnerIncarnation =
        stop?.targetRunnerIncarnation
        ?? authority?.currentRunnerIncarnation
        ?? null;
    const supervisorOwnershipVerified = status.verified === true
        && authority !== null
        && status.supervisorGeneration === authority.supervisorGeneration
        && status.supervisorNonce === authority.supervisorNonce
        && status.runnerIncarnation === expectedRunnerIncarnation;
    const runnerChildVerified = child.verified === true
        && child.runnerIncarnation === expectedRunnerIncarnation
        && child.pid === (stop?.targetRunnerPid ?? null);
    const brokerAuthorityVerified = broker.verified === true
        && broker.authorityRetired === true
        && (
            broker.configured === false
            || (
                authority !== null
                && broker.supervisorGeneration
                    === authority.supervisorGeneration
                && broker.supervisorNonce === authority.supervisorNonce
            )
        );
    const missingVerifications = [];
    if (!repositoryVerified || authority === null || stop === null) {
        missingVerifications.push("repository_authority");
    }
    if (!supervisorOwnershipVerified) {
        missingVerifications.push("supervisor_status_ownership");
    }
    if (!runnerChildVerified) {
        missingVerifications.push("runner_child");
    }
    if (processProbe.verified !== true) {
        missingVerifications.push("owned_processes");
    }
    if (sdkProbe.verified !== true) {
        missingVerifications.push("sdk_sessions");
    }
    if (!brokerAuthorityVerified) {
        missingVerifications.push("broker_authority");
    }
    const verified = missingVerifications.length === 0;
    const activePids = processProbe.verified
        ? processProbe.activePids
        : null;
    const activeSdkSessions = sdkProbe.verified
        ? sdkProbe.activeCount
        : null;
    const activeResourceLeases = broker.verified
        ? broker.activeLeases
        : null;
    const quiescent = verified
        && activeLease === null
        && committableAttempts.length === 0
        && activePids.length === 0
        && activeSdkSessions === 0
        && activeResourceLeases.length === 0
        && child.active === false;
    return Object.freeze({
        verified,
        quiescent,
        missingVerifications: Object.freeze(missingVerifications),
        supervisorStatus: status,
        supervisorAuthority: authority,
        processes: processProbe,
        sdkSessions: sdkProbe,
        runnerChild: child,
        resourceBroker: broker,
        activeRunnerLease: activeLease,
        committableAttempts: committableAttempts === null
            ? null
            : Object.freeze(committableAttempts),
        activePids,
        activeSdkSessions,
        activeResourceLeases,
    });
}

export function persistPausedQuiescent({
    repository,
    adapter,
    stop,
    proof,
} = {}) {
    const record = requireStop(stop);
    if (proof?.verified !== true || proof?.quiescent !== true) {
        throw new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.NON_QUIESCENT,
            "PAUSED_QUIESCENT requires a fully verified zero-active-resource proof",
            { proof: proof ?? null },
        );
    }
    let replay = ensureStopDomainIntent(adapter, record);
    const operationalNonResult =
        typeof adapter.latestOperationalNonResult === "function"
            ? adapter.latestOperationalNonResult()
            : null;
    if (replay.aggregate.terminal !== null
        || replay.aggregate.nonResults.length > 0
        || operationalNonResult !== null) {
        return repository.completeQuiescentStop({
            investigationId: record.investigationId,
            requestId: record.requestId,
            state: QUIESCENT_STOP_STATES.SUPERSEDED,
            quiescent: false,
            interventionRequired: false,
            nonResultCode:
                operationalNonResult?.payload?.code
                ?? replay.aggregate.nonResults.at(-1)?.code
                ?? null,
            details: {
                supersededBy:
                    replay.aggregate.terminal !== null
                        ? "terminal"
                        : operationalNonResult !== null
                            ? "operational_non_result"
                            : "domain_non_result",
                proof,
            },
        });
    }
    if (replay.aggregate.pause === null) {
        const recommendation = decideNext(replay.aggregate);
        if (recommendation.event?.type !== EVENT_TYPES.INVESTIGATION_PAUSED) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.NON_QUIESCENT,
                "kernel did not authorize the quiescent pause transition",
                {
                    recommendationKind: recommendation.kind ?? null,
                    commandKind: recommendation.command?.kind ?? null,
                },
            );
        }
        adapter.appendKernelDecision();
        replay = adapter.replay();
    }
    if (replay.aggregate.pause === null) {
        throw new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.NON_QUIESCENT,
            "quiescent pause did not persist",
        );
    }
    return repository.completeQuiescentStop({
        investigationId: record.investigationId,
        requestId: record.requestId,
        state: QUIESCENT_STOP_STATES.PAUSED_QUIESCENT,
        quiescent: true,
        interventionRequired: false,
        nonResultCode: null,
        details: { proof },
        quiescenceProof: proof,
    });
}

export function persistPausePending({
    repository,
    stop,
    proof,
    reason,
} = {}) {
    const record = requireStop(stop);
    return repository.completeQuiescentStop({
        investigationId: record.investigationId,
        requestId: record.requestId,
        state: QUIESCENT_STOP_STATES.PAUSE_PENDING,
        quiescent: false,
        interventionRequired: true,
        nonResultCode: RUNTIME_ERROR_CODES.NON_QUIESCENT,
        details: {
            reason,
            proof: proof ?? null,
        },
    });
}

export async function waitForQuiescentStopAcknowledgement({
    stateDir,
    investigationId,
    requestId,
    timeoutMs = 25_000,
    pollMs = 25,
    repositoryFactory = openRepositoryReadOnly,
    sleep = (milliseconds) => delay(milliseconds),
} = {}) {
    if (!Number.isSafeInteger(timeoutMs)
        || timeoutMs < 1
        || timeoutMs > 60_000
        || !Number.isSafeInteger(pollMs)
        || pollMs < 1
        || pollMs > timeoutMs) {
        throw new RuntimeConfigError(
            "quiescent-stop acknowledgement timing is invalid",
            { timeoutMs, pollMs },
        );
    }
    const repository = repositoryFactory({
        file: path.join(stateDir, "events.sqlite"),
    });
    try {
        const started = Date.now();
        let latest = null;
        while (Date.now() - started <= timeoutMs) {
            latest = repository.getQuiescentStop(investigationId);
            if (latest !== null && latest.requestId === requestId
                && [
                    QUIESCENT_STOP_STATES.PAUSED_QUIESCENT,
                    QUIESCENT_STOP_STATES.PAUSE_PENDING,
                    QUIESCENT_STOP_STATES.SUPERSEDED,
                ].includes(latest.state)) {
                return Object.freeze({
                    acknowledged: true,
                    timedOut: false,
                    stop: latest,
                });
            }
            await sleep(pollMs);
        }
        return Object.freeze({
            acknowledged: false,
            timedOut: true,
            stop: latest,
        });
    } finally {
        repository.close();
    }
}
