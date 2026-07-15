import fs from "node:fs";
import path from "node:path";

import { decideNext } from "../domain/index.mjs";
import {
    openArtifactStoreReadOnly,
    openRepositoryReadOnly,
} from "../persistence/index.mjs";
import { verifyExperimentAuthority } from "../api/experiment-authority.mjs";
import { probeWindowsSandboxAvailability } from "../measurement/index.mjs";
import {
    assertSupervisorConfigMatchesRuntimeAuthority,
    verifyRuntimeConfigAuthority,
} from "./config-authority.mjs";
import {
    loadSupervisorConfig,
    supervisorPaths,
} from "./config.mjs";
import {
    deriveRunnerExecutionLimits,
    resourceReservationEntries,
} from "./config-validation.mjs";
import { createDomainRepositoryAdapter } from "./domain-adapter.mjs";
import {
    isExactPidAlive,
    readSupervisorLock,
    readSupervisorStatus,
} from "./supervisor.mjs";
import {
    SDK_AVAILABILITY_CODES,
    probeNoninteractiveSdkAvailability,
} from "./sdk-availability.mjs";

const INVESTIGATION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;

export const RECOVERY_DISCOVERY_CODES = Object.freeze({
    ELIGIBLE: "RECOVERY_ELIGIBLE",
    SUPERVISOR_RUNNING: "SUPERVISOR_RUNNING",
    LIFECYCLE_ARCHIVED: "LIFECYCLE_ARCHIVED",
    LIFECYCLE_TOMBSTONED: "LIFECYCLE_TOMBSTONED",
    TERMINAL: "TERMINAL",
    PAUSED: "PAUSED",
    NON_RESULT: "NON_RESULT",
    DEADLINE_EXPIRED: "DEADLINE_EXPIRED",
    STATE_MISSING: "STATE_MISSING",
    INTEGRITY_BLOCKED: "INTEGRITY_BLOCKED",
    EXPERIMENT_AUTHORITY_BLOCKED: "EXPERIMENT_AUTHORITY_BLOCKED",
    RUNTIME_DRIFT: "RUNTIME_DRIFT",
    SANDBOX_UNAVAILABLE: "SANDBOX_UNAVAILABLE",
    BROKER_INTEGRITY_BLOCKED: "BROKER_INTEGRITY_BLOCKED",
    BROKER_CAPACITY_BLOCKED: "BROKER_CAPACITY_BLOCKED",
    SDK_AUTH_UNAVAILABLE: SDK_AVAILABILITY_CODES.AUTH_UNAVAILABLE,
    SDK_MODEL_UNAVAILABLE: SDK_AVAILABILITY_CODES.MODEL_UNAVAILABLE,
    SDK_PROBE_FAILED: SDK_AVAILABILITY_CODES.PROBE_FAILED,
});

function decision(state, code, extra = {}) {
    return Object.freeze({
        eligible: state === "eligible",
        state,
        code,
        ...extra,
    });
}

function recoveryPaths(stateRoot, investigationId) {
    if (typeof stateRoot !== "string" || !path.isAbsolute(stateRoot)) {
        throw new TypeError("stateRoot must be an absolute path");
    }
    if (typeof investigationId !== "string"
        || !INVESTIGATION_ID_RE.test(investigationId)
        || investigationId.includes("..")) {
        throw new TypeError("investigationId must be filesystem-safe");
    }
    const investigationDir = path.join(stateRoot, investigationId);
    const stateDir = path.join(investigationDir, "state");
    return Object.freeze({
        investigationDir,
        stateDir,
        artifactRoot: path.join(investigationDir, "artifacts"),
        eventsDbPath: path.join(stateDir, "events.sqlite"),
    });
}

export function classifyRecoveryAggregate({
    lifecycleState,
    aggregate,
    operationalNonResult = null,
} = {}) {
    if (lifecycleState === "archived") {
        return decision(
            "skipped",
            RECOVERY_DISCOVERY_CODES.LIFECYCLE_ARCHIVED,
        );
    }
    if (lifecycleState === "tombstoned") {
        return decision(
            "skipped",
            RECOVERY_DISCOVERY_CODES.LIFECYCLE_TOMBSTONED,
        );
    }
    if (lifecycleState !== "active") {
        return decision(
            "blocked",
            RECOVERY_DISCOVERY_CODES.INTEGRITY_BLOCKED,
        );
    }
    if (aggregate === null
        || typeof aggregate !== "object"
        || Array.isArray(aggregate)) {
        return decision(
            "blocked",
            RECOVERY_DISCOVERY_CODES.INTEGRITY_BLOCKED,
        );
    }
    if (aggregate?.terminal !== null) {
        return decision("skipped", RECOVERY_DISCOVERY_CODES.TERMINAL);
    }
    if (aggregate?.pause !== null) {
        return decision("skipped", RECOVERY_DISCOVERY_CODES.PAUSED);
    }
    if ((aggregate?.nonResults?.length ?? 0) > 0
        || operationalNonResult !== null) {
        return decision("skipped", RECOVERY_DISCOVERY_CODES.NON_RESULT);
    }
    return decision("eligible", RECOVERY_DISCOVERY_CODES.ELIGIBLE);
}

export function verifyInvestigationArtifactIntegrity({
    repository,
    artifactStore,
    investigationId,
} = {}) {
    if (typeof repository?.listArtifactRefs !== "function"
        || typeof repository.getArtifact !== "function"
        || typeof artifactStore?.verifyObject !== "function") {
        throw new TypeError(
            "artifact verification requires repository and artifact-store read APIs",
        );
    }
    const artifactIds = [...new Set(
        repository.listArtifactRefs(investigationId)
            .map((reference) => reference.artifactId),
    )].sort();
    for (const artifactId of artifactIds) {
        const metadata = repository.getArtifact(artifactId);
        if (metadata === null
            || metadata.investigationId !== investigationId
            || metadata.durable !== true
            || !Number.isSafeInteger(metadata.sizeBytes)
            || metadata.sizeBytes < 0
            || metadata.hashAlgo !== "sha256"
            || !/^[a-f0-9]{64}$/u.test(metadata.hashValue ?? "")) {
            throw new Error(
                "persisted artifact metadata failed integrity verification",
            );
        }
        if (metadata.storage !== "external") {
            throw new Error("persisted artifact storage kind is invalid");
        }
        const probe = artifactStore.verifyObject(
            `sha256:${metadata.hashValue}`,
        );
        if (probe?.ok !== true || probe.size !== metadata.sizeBytes) {
            throw new Error(
                "persisted external artifact failed integrity verification",
            );
        }
    }
    return Object.freeze({
        verified: true,
        artifactCount: artifactIds.length,
    });
}

export function recoveryReservationForCommand(
    command,
    {
        executionLimits,
        sdkRetryPolicy,
    } = {},
) {
    if (command?.kind === "dispatch_reserved"
        || command?.kind === "await_observation") {
        command = command.reservedCommand ?? null;
    }
    if (command === null) return Object.freeze({});
    if (command.kind === "commit_evidence") return Object.freeze({});
    const reservation = {
        outputBytes: executionLimits.byteBudgets.perAttemptOutputBytes,
        receiptBytes: executionLimits.byteBudgets.perAttemptReceiptBytes,
        casBytes: executionLimits.byteBudgets.perAttemptCasBytes,
        storageBytes: executionLimits.workingSetPolicy.perAttemptBytes,
    };
    if (command.kind === "search_candidate") {
        reservation.sdkSessions = 1;
        reservation.modelCostUnits =
            sdkRetryPolicy.maxCostUnits
            ?? sdkRetryPolicy.reservedCostUnitsPerAttempt;
    } else if ([
        "run_validation",
        "run_confirmation",
        "run_challenge",
        "verify_impossibility",
    ].includes(command.kind)) {
        reservation.sandboxProcesses = 1;
        reservation.cpuSlots = { general: 1 };
    } else {
        throw new Error(
            "recovery capacity encountered an unsupported domain command",
        );
    }
    return Object.freeze(reservation);
}

export function buildRecoveryReservation(aggregate, config) {
    const recommendation = decideNext(aggregate);
    return recoveryReservationForCommand(
        recommendation?.command ?? null,
        {
            executionLimits: deriveRunnerExecutionLimits(
                aggregate.contract,
            ),
            sdkRetryPolicy: config.runner.options.sdkRetryPolicy,
        },
    );
}

function allocationUnits(leases, resourceKey) {
    return leases.reduce((total, lease) => {
        const allocation = lease.allocations?.find(
            (entry) => entry.resourceKey === resourceKey,
        );
        return total + (allocation?.reservedUnits ?? 0);
    }, 0);
}

export function evaluateRecoveryBrokerCapacity({
    broker,
    investigationId,
    reservation,
} = {}) {
    broker.verifyIntegrity();
    broker.reclaimStale();
    const catalogInvestigation = broker.getInvestigation(investigationId);
    if (catalogInvestigation === null
        || catalogInvestigation.lifecycleState !== "active") {
        return Object.freeze({
            ok: false,
            code: RECOVERY_DISCOVERY_CODES.BROKER_INTEGRITY_BLOCKED,
        });
    }
    const entries = resourceReservationEntries(reservation, broker.config);
    const globalRows = new Map(
        broker.getUsageSnapshot().map((row) => [row.resourceKey, row]),
    );
    const investigationRows = new Map(
        broker.getUsageSnapshot({ investigationId })
            .map((row) => [row.resourceKey, row]),
    );
    const targetLeases = broker.listActiveLeases({ investigationId });
    for (const entry of entries) {
        const global = globalRows.get(entry.resourceKey);
        const investigation = investigationRows.get(entry.resourceKey);
        if (global === undefined
            || investigation === undefined
            || global.overdrawnUnits > 0
            || investigation.overdrawnUnits > 0) {
            return Object.freeze({
                ok: false,
                code: RECOVERY_DISCOVERY_CODES.BROKER_INTEGRITY_BLOCKED,
            });
        }
        const reclaimable = global.resourceMode === "concurrency"
            ? allocationUnits(targetLeases, entry.resourceKey)
            : 0;
        if (global.availableUnits + reclaimable < entry.units
            || investigation.availableUnits + reclaimable < entry.units) {
            return Object.freeze({
                ok: false,
                code: RECOVERY_DISCOVERY_CODES.BROKER_CAPACITY_BLOCKED,
                resourceKey: entry.resourceKey,
            });
        }
    }
    return Object.freeze({
        ok: true,
        code: RECOVERY_DISCOVERY_CODES.ELIGIBLE,
        reservationCount: entries.length,
    });
}

function exactSupervisorHealth(config, dependencies, nowMs) {
    let status = null;
    let lock = null;
    try {
        status = (dependencies.readSupervisorStatus ?? readSupervisorStatus)(
            config.runner.stateDir,
            config.runner.investigationId,
        );
    } catch {
        status = null;
    }
    try {
        lock = (dependencies.readSupervisorLock ?? readSupervisorLock)(
            config.paths.lockPath,
        );
    } catch {
        lock = null;
    }
    const heartbeatAgeMs = status === null
        ? Number.POSITIVE_INFINITY
        : nowMs - Date.parse(status.heartbeatAt);
    const alive = status !== null
        && lock !== null
        && status.pid === lock.pid
        && status.nonce === lock.nonce
        && status.supervisorGeneration === lock.supervisorGeneration
        && Number.isFinite(heartbeatAgeMs)
        && heartbeatAgeMs >= -config.staleLockMs
        && heartbeatAgeMs < config.staleLockMs
        && (dependencies.isPidAlive ?? isExactPidAlive)(status.pid) === true;
    return Object.freeze({ alive, status, lock });
}

function experimentAuthorityInput(aggregate, investigationId) {
    const authority = aggregate.experimentAuthority;
    const payload = authority?.manifest?.experimentPayload;
    if (authority === null
        || aggregate.experimentAuthorityIdentity === null
        || authority?.identity !== aggregate.experimentAuthorityIdentity) {
        throw new Error(
            "persisted v4 investigation has no valid experiment authority",
        );
    }
    return {
        authority,
        experimentId: payload?.experimentId,
        projectDir: payload?.projectDir,
        harnessSuiteId: payload?.harnessSuiteId,
        contract: aggregate.contract,
        investigationId,
    };
}

async function currentSandboxIdentity({
    runtimeAuthority,
    paths,
    daemonLease,
    dependencies,
}) {
    if (runtimeAuthority.sandbox?.required !== true) {
        return Object.freeze({ required: false });
    }
    const ownerToken = createHash("sha256")
        .update(
            `${daemonLease.daemonGeneration}:${
                daemonLease.daemonIncarnation
            }`,
        )
        .digest("hex")
        .slice(0, 24);
    const recoveryProbeRoot = path.join(paths.stateDir, "recovery-probe");
    const controlRoot = path.join(
        recoveryProbeRoot,
        `g${daemonLease.daemonGeneration}-${ownerToken}`,
    );
    fs.mkdirSync(controlRoot, { recursive: true, mode: 0o700 });
    try {
        const availability = await (
            dependencies.probeSandboxAvailability
            ?? probeWindowsSandboxAvailability
        )({ controlRoot });
        if (availability?.available !== true
            || availability.policyIdentity === null
            || typeof availability.policyIdentity !== "object"
            || Array.isArray(availability.policyIdentity)) {
            return null;
        }
        return Object.freeze({
            ...availability.policyIdentity,
            required: true,
        });
    } finally {
        fs.rmSync(controlRoot, {
            recursive: true,
            force: true,
            maxRetries: 10,
            retryDelay: 20,
        });
        try {
            fs.rmdirSync(recoveryProbeRoot);
        } catch {
            // Another daemon generation may still own a verified probe root.
        }
    }
}

function samePath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

export function discoverCatalogInvestigations(broker) {
    return Object.freeze(
        broker.listInvestigations({
            lifecycleState: "active",
            excludeFenced: true,
        })
            .slice()
            .sort((left, right) =>
                left.investigationId < right.investigationId
                    ? -1
                    : left.investigationId > right.investigationId
                        ? 1
                        : 0),
    );
}

export async function inspectRecoveryInvestigation({
    stateRoot,
    catalogInvestigation,
    broker,
    daemonLease,
    env = process.env,
    nowMs = Date.now(),
} = {}, dependencies = {}) {
    const investigationId = catalogInvestigation?.investigationId;
    if (catalogInvestigation?.lifecycleState !== "active") {
        return classifyRecoveryAggregate({
            lifecycleState: catalogInvestigation?.lifecycleState,
            aggregate: null,
        });
    }
    const paths = recoveryPaths(stateRoot, investigationId);
    if (!(dependencies.pathExists ?? fs.existsSync)(paths.eventsDbPath)) {
        return decision(
            "blocked",
            RECOVERY_DISCOVERY_CODES.STATE_MISSING,
        );
    }

    const repository = (
        dependencies.openRepositoryReadOnly ?? openRepositoryReadOnly
    )({ file: paths.eventsDbPath, env });
    const artifactStore = (
        dependencies.openArtifactStoreReadOnly ?? openArtifactStoreReadOnly
    )({ root: paths.artifactRoot, env });
    try {
        let aggregate;
        let operationalNonResult;
        try {
            const report = repository.verifyInvestigation(investigationId);
            if (report?.ok !== true) {
                return decision(
                    "blocked",
                    RECOVERY_DISCOVERY_CODES.INTEGRITY_BLOCKED,
                );
            }
            const adapter = (
                dependencies.createDomainRepositoryAdapter
                ?? createDomainRepositoryAdapter
            )({
                repository,
                artifactStore,
                investigationId,
                ensure: false,
            });
            aggregate = adapter.replay().aggregate;
            operationalNonResult = adapter.latestOperationalNonResult();
            (
                dependencies.verifyArtifactIntegrity
                ?? verifyInvestigationArtifactIntegrity
            )({ repository, artifactStore, investigationId });
        } catch (error) {
            return decision(
                "blocked",
                RECOVERY_DISCOVERY_CODES.INTEGRITY_BLOCKED,
                { errorCode: error?.code ?? null },
            );
        }

        const classification = classifyRecoveryAggregate({
            lifecycleState: catalogInvestigation.lifecycleState,
            aggregate,
            operationalNonResult,
        });
        if (!classification.eligible) return classification;

        try {
            (
                dependencies.verifyExperimentAuthority
                ?? verifyExperimentAuthority
            )({
                ...experimentAuthorityInput(aggregate, investigationId),
                env,
            });
        } catch (error) {
            return decision(
                "blocked",
                RECOVERY_DISCOVERY_CODES.EXPERIMENT_AUTHORITY_BLOCKED,
                { errorCode: error?.code ?? null },
            );
        }

        const runtimeAuthority = aggregate.runtimeConfigAuthority;
        if (runtimeAuthority === null
            || runtimeAuthority.fingerprint
                !== aggregate.runtimeConfigFingerprint) {
            return decision(
                "blocked",
                RECOVERY_DISCOVERY_CODES.RUNTIME_DRIFT,
            );
        }
        const configPath =
            supervisorPaths(paths.stateDir, investigationId).configPath;
        let config;
        try {
            const persisted = (
                dependencies.loadSupervisorConfig ?? loadSupervisorConfig
            )(configPath, { env });
            config = (
                dependencies.assertSupervisorConfigMatchesRuntimeAuthority
                ?? assertSupervisorConfigMatchesRuntimeAuthority
            )(persisted, runtimeAuthority, { env });
            if (config.runner.deadlineMs !== null
                && config.runner.deadlineMs <= nowMs) {
                return decision(
                    "skipped",
                    RECOVERY_DISCOVERY_CODES.DEADLINE_EXPIRED,
                );
            }
        } catch (error) {
            return decision(
                "blocked",
                RECOVERY_DISCOVERY_CODES.RUNTIME_DRIFT,
                { errorCode: error?.code ?? null },
            );
        }

        const health = exactSupervisorHealth(config, dependencies, nowMs);
        if (health.alive) {
            return decision(
                "running",
                RECOVERY_DISCOVERY_CODES.SUPERVISOR_RUNNING,
                {
                    supervisorGeneration:
                        health.status.supervisorGeneration ?? null,
                    runnerIncarnation:
                        health.status.runnerIncarnation ?? null,
                },
            );
        }

        try {
            const sandbox = await currentSandboxIdentity({
                runtimeAuthority,
                paths,
                daemonLease,
                dependencies,
            });
            if (sandbox === null) {
                return decision(
                    "blocked",
                    RECOVERY_DISCOVERY_CODES.SANDBOX_UNAVAILABLE,
                );
            }
            (
                dependencies.verifyRuntimeConfigAuthority
                ?? verifyRuntimeConfigAuthority
            )(runtimeAuthority, {
                env,
                deadlineMs: config.runner.deadlineMs,
                expectedInvestigationId: investigationId,
                expectedStateDir: paths.stateDir,
                expectedArtifactRoot: paths.artifactRoot,
                nodeExecutable:
                    dependencies.nodeExecutable ?? process.execPath,
                sandbox,
            });
        } catch (error) {
            return decision(
                "blocked",
                RECOVERY_DISCOVERY_CODES.RUNTIME_DRIFT,
                { errorCode: error?.code ?? null },
            );
        }

        if (config.runner.resourceBroker === null
            || !samePath(config.runner.resourceBroker.stateRoot, stateRoot)
            || config.runner.resourceBroker.configFingerprint
                !== broker.configFingerprint
            || config.runner.resourceBroker.limitsFingerprint
                !== catalogInvestigation.limitsFingerprint) {
            return decision(
                "blocked",
                RECOVERY_DISCOVERY_CODES.BROKER_INTEGRITY_BLOCKED,
            );
        }
        let capacity;
        try {
            const reservation = (
                dependencies.buildRecoveryReservation
                ?? buildRecoveryReservation
            )(aggregate, config);
            capacity = (
                dependencies.evaluateBrokerCapacity
                ?? evaluateRecoveryBrokerCapacity
            )({ broker, investigationId, reservation });
        } catch (error) {
            return decision(
                "blocked",
                RECOVERY_DISCOVERY_CODES.BROKER_INTEGRITY_BLOCKED,
                { errorCode: error?.code ?? null },
            );
        }
        if (capacity.ok !== true) {
            return decision("blocked", capacity.code);
        }

        const requiredModels = Array.isArray(aggregate.contract?.workerModels)
            ? aggregate.contract.workerModels
            : [];
        if (requiredModels.length === 0) {
            return decision(
                "blocked",
                RECOVERY_DISCOVERY_CODES.INTEGRITY_BLOCKED,
            );
        }
        const sdk = await (
            dependencies.probeSdkAvailability
            ?? probeNoninteractiveSdkAvailability
        )({
            sdkPath: config.runner.sdkPath,
            cliPath: config.runner.cliPath,
            workingDirectory: paths.investigationDir,
            requiredModels,
            env,
        });
        if (sdk?.ok !== true) {
            const code = Object.values(SDK_AVAILABILITY_CODES)
                .includes(sdk?.code)
                ? sdk.code
                : RECOVERY_DISCOVERY_CODES.SDK_PROBE_FAILED;
            return decision("blocked", code);
        }
        return decision(
            "eligible",
            RECOVERY_DISCOVERY_CODES.ELIGIBLE,
            { config },
        );
    } finally {
        repository.close();
    }
}
