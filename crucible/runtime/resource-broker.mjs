import fs from "node:fs";
import path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";

import {
    openResourceCatalog,
} from "../persistence/resource-catalog.mjs";
import { assertLocalDatabasePath } from "../persistence/paths.mjs";
import {
    estimateDeterministicModelCostUnits,
    investigationResourceLimitsFingerprint,
    normalizeInvestigationResourceLimits,
    normalizeResourceBrokerConfig,
    normalizeResourceReservation,
    resourceBrokerConfigFingerprint,
    resourceDefinitionsFromConfig,
    resourceLimitEntries,
    resourceReservationEntries,
    resourceUsageEntries,
    sdkUsageToModelCostUnits,
} from "./config-validation.mjs";
import {
    ensureDirectory,
    requireAbsolutePath,
    requireIdentifier,
    requirePositiveInteger,
    requireString,
} from "./utils.mjs";
import { RuntimeConfigError } from "./errors.mjs";

export const RESOURCE_CATALOG_FILENAME = "resource-catalog.sqlite";

export const RESOURCE_BROKER_INTEGRATION_NOTES = Object.freeze({
    catalog:
        "Open one broker against the Crucible state root, not an investigation state directory. The immutable singleton catalog is <state-root>\\resource-catalog.sqlite.",
    admission:
        "Freeze investigation limits before any external effect. Reserve the SDK/sandbox/CPU/GPU slots plus worst-case output, receipt, CAS, and deterministic model-cost units in one acquire call.",
    fencing:
        "The supervisor must claim each generation/incarnation before launching its runner. Persist the returned lease id, nonce, and monotonically increasing fencing token in effect receipts; stale authority must not retry under a new logical-effect id.",
    heartbeat:
        "Renew active leases before expiry. Exact process identity may be supplied for dead-owner reclamation; PID-only liveness is not sufficient because of PID reuse.",
    accounting:
        "Release with observed byte usage. If SDK usage is unavailable, the reserved deterministic model-cost estimate is charged; later SDK reports reconcile monotonically upward and never reduce an existing charge.",
    outcomes:
        "throttle and pause are operational admission outcomes only. They must never be converted into verified_result, target_unreachable, or any other scientific conclusion.",
});

function requireFunction(value, field) {
    if (typeof value !== "function") {
        throw new RuntimeConfigError(`${field} must be a function`, { field });
    }
    return value;
}

function optionalOwnerProcess(ownerProcessId, ownerProcessStartId) {
    if (ownerProcessId === undefined && ownerProcessStartId === undefined) {
        return Object.freeze({
            ownerProcessId: null,
            ownerProcessStartId: null,
        });
    }
    if (ownerProcessId === undefined || ownerProcessStartId === undefined) {
        throw new RuntimeConfigError(
            "ownerProcessId and ownerProcessStartId must be provided together",
        );
    }
    return Object.freeze({
        ownerProcessId: requirePositiveInteger(
            ownerProcessId,
            "ownerProcessId",
        ),
        ownerProcessStartId: requireString(
            ownerProcessStartId,
            "ownerProcessStartId",
            { max: 256 },
        ),
    });
}

function normalizeAuthority({
    investigationId,
    supervisorGeneration,
    supervisorNonce = undefined,
    runnerIncarnation,
}) {
    return Object.freeze({
        investigationId: requireIdentifier(investigationId, "investigationId"),
        supervisorGeneration: requirePositiveInteger(
            supervisorGeneration,
            "supervisorGeneration",
        ),
        ...(supervisorNonce === undefined
            ? {}
            : {
                supervisorNonce: requireString(
                    supervisorNonce,
                    "supervisorNonce",
                    { max: 256 },
                ),
            }),
        runnerIncarnation: requireString(
            runnerIncarnation,
            "runnerIncarnation",
            { max: 256 },
        ),
    });
}

function normalizeLeaseHandle(input, { requireOwner = true } = {}) {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
        throw new RuntimeConfigError("lease handle must be an object");
    }
    const handle = {
        leaseId: requireString(input.leaseId, "leaseId", { max: 256 }),
        fencingToken: requirePositiveInteger(
            input.fencingToken,
            "fencingToken",
        ),
        leaseNonce: requireString(
            input.leaseNonce,
            "leaseNonce",
            { max: 256 },
        ),
    };
    if (requireOwner) {
        handle.ownerId = requireIdentifier(input.ownerId, "ownerId");
        handle.supervisorGeneration = requirePositiveInteger(
            input.supervisorGeneration,
            "supervisorGeneration",
        );
        handle.runnerIncarnation = requireString(
            input.runnerIncarnation,
            "runnerIncarnation",
            { max: 256 },
        );
    }
    return Object.freeze(handle);
}

export function resourceCatalogPath(stateRoot) {
    const root = requireAbsolutePath(stateRoot, "stateRoot");
    return path.join(root, RESOURCE_CATALOG_FILENAME);
}

export function openResourceBroker(options = {}) {
    return ResourceBroker.open(options);
}

export class ResourceBroker {
    #catalog;
    #config;
    #stateRoot;
    #idFactory;
    #nonceFactory;

    constructor(catalog, {
        config,
        stateRoot,
        idFactory,
        nonceFactory,
    }) {
        this.#catalog = catalog;
        this.#config = config;
        this.#stateRoot = stateRoot;
        this.#idFactory = idFactory;
        this.#nonceFactory = nonceFactory;
    }

    static open({
        stateRoot,
        config,
        busyTimeoutMs = 5_000,
        now = Date.now,
        isOwnerAlive = null,
        idFactory = randomUUID,
        nonceFactory = () => randomBytes(24).toString("hex"),
        denyRoots,
        env,
        integrityCheckAdapter = undefined,
    } = {}) {
        const normalizedConfig = normalizeResourceBrokerConfig(config);
        const root = requireAbsolutePath(stateRoot, "stateRoot");
        if (fs.existsSync(root) && !fs.statSync(root).isDirectory()) {
            throw new RuntimeConfigError(
                "stateRoot must be a directory",
                { stateRoot: root },
            );
        }
        assertLocalDatabasePath(
            path.join(root, RESOURCE_CATALOG_FILENAME),
            { denyRoots, env },
        );
        const durableRoot = ensureDirectory(root);
        const normalizedIdFactory = requireFunction(idFactory, "idFactory");
        const normalizedNonceFactory = requireFunction(
            nonceFactory,
            "nonceFactory",
        );
        const catalog = openResourceCatalog({
            file: path.join(durableRoot, RESOURCE_CATALOG_FILENAME),
            config: normalizedConfig,
            definitions: resourceDefinitionsFromConfig(normalizedConfig),
            busyTimeoutMs,
            now,
            isOwnerAlive,
            denyRoots,
            env,
            integrityCheckAdapter,
        });
        return new ResourceBroker(catalog, {
            config: normalizedConfig,
            stateRoot: durableRoot,
            idFactory: normalizedIdFactory,
            nonceFactory: normalizedNonceFactory,
        });
    }

    get stateRoot() {
        return this.#stateRoot;
    }

    get databaseFile() {
        return this.#catalog.databaseFile;
    }

    get config() {
        return this.#config;
    }

    get configFingerprint() {
        return resourceBrokerConfigFingerprint(this.#config);
    }

    close() {
        this.#catalog.close();
    }

    verifyIntegrity() {
        return this.#catalog.verifyIntegrity();
    }

    registerInvestigation({
        investigationId,
        limits,
        supervisorGeneration,
        supervisorNonce,
        runnerIncarnation,
    } = {}) {
        const authority = normalizeAuthority({
            investigationId,
            supervisorGeneration,
            supervisorNonce,
            runnerIncarnation,
        });
        const normalizedLimits = normalizeInvestigationResourceLimits(
            limits,
            this.#config,
        );
        return this.#catalog.registerInvestigation({
            ...authority,
            limits: normalizedLimits,
            limitEntries: resourceLimitEntries(
                normalizedLimits,
                this.#config,
            ),
        });
    }

    getInvestigation(investigationId) {
        return this.#catalog.getInvestigation(
            requireIdentifier(investigationId, "investigationId"),
        );
    }

    claimAuthority({
        investigationId,
        supervisorGeneration,
        supervisorNonce,
        runnerIncarnation,
    } = {}) {
        return this.#catalog.claimAuthority(normalizeAuthority({
            investigationId,
            supervisorGeneration,
            supervisorNonce,
            runnerIncarnation,
        }));
    }

    acquire({
        investigationId,
        ownerId,
        ownerProcessId = undefined,
        ownerProcessStartId = undefined,
        supervisorGeneration,
        runnerIncarnation,
        attemptId,
        logicalEffectId,
        reservation,
        ttlMs = this.#config.lease.defaultTtlMs,
    } = {}) {
        const authority = normalizeAuthority({
            investigationId,
            supervisorGeneration,
            runnerIncarnation,
        });
        const processOwner = optionalOwnerProcess(
            ownerProcessId,
            ownerProcessStartId,
        );
        const normalizedReservation = normalizeResourceReservation(
            reservation,
            this.#config,
        );
        const leaseId = requireString(
            this.#idFactory(),
            "generated leaseId",
            { max: 256 },
        );
        const leaseNonce = requireString(
            this.#nonceFactory(),
            "generated leaseNonce",
            { max: 256 },
        );
        const result = this.#catalog.acquireLease({
            ...authority,
            ...processOwner,
            leaseId,
            leaseNonce,
            ownerId: requireIdentifier(ownerId, "ownerId"),
            attemptId: requireIdentifier(attemptId, "attemptId"),
            logicalEffectId: requireIdentifier(
                logicalEffectId,
                "logicalEffectId",
            ),
            requests: resourceReservationEntries(
                normalizedReservation,
                this.#config,
            ),
            ttlMs: requirePositiveInteger(
                ttlMs,
                "ttlMs",
                this.#config.lease.maxTtlMs,
            ),
        });
        if (result.status === "throttle" || result.status === "pause") {
            return Object.freeze({
                ...result,
                operational: true,
                scientificConclusion: false,
                terminal: false,
            });
        }
        return result;
    }

    renew({
        lease,
        ttlMs = this.#config.lease.defaultTtlMs,
    } = {}) {
        return this.#catalog.renewLease({
            ...normalizeLeaseHandle(lease),
            ttlMs: requirePositiveInteger(
                ttlMs,
                "ttlMs",
                this.#config.lease.maxTtlMs,
            ),
        });
    }

    heartbeat(options) {
        return this.renew(options);
    }

    release({
        lease,
        usage = {},
        releaseId = "release",
    } = {}) {
        return this.#catalog.releaseLease({
            ...normalizeLeaseHandle(lease),
            usage: resourceUsageEntries(usage),
            releaseId: requireIdentifier(releaseId, "releaseId"),
        });
    }

    reconcileUsage({
        lease,
        usage,
        reconciliationId,
        source,
    } = {}) {
        const entries = resourceUsageEntries(usage);
        if (entries.length === 0) {
            throw new RuntimeConfigError(
                "usage reconciliation must report at least one resource",
            );
        }
        return this.#catalog.reconcileUsage({
            ...normalizeLeaseHandle(lease, { requireOwner: false }),
            usage: entries,
            reconciliationId: requireIdentifier(
                reconciliationId,
                "reconciliationId",
            ),
            source: requireIdentifier(source, "source"),
        });
    }

    reconcileModelUsage({
        lease,
        sdkUsage,
        reconciliationId,
    } = {}) {
        const units = sdkUsageToModelCostUnits(
            sdkUsage,
            this.#config.costPolicy,
        );
        return this.reconcileUsage({
            lease,
            usage: { modelCostUnits: units },
            reconciliationId,
            source: "copilot_sdk_usage",
        });
    }

    estimateModelCost(input) {
        return estimateDeterministicModelCostUnits(
            input,
            this.#config.costPolicy,
        );
    }

    reclaimStale() {
        return this.#catalog.reclaimStale();
    }

    getLease(leaseId) {
        return this.#catalog.getLease(
            requireString(leaseId, "leaseId", { max: 256 }),
        );
    }

    listActiveLeases({ investigationId = null } = {}) {
        return this.#catalog.listActiveLeases({
            investigationId: investigationId === null
                ? null
                : requireIdentifier(investigationId, "investigationId"),
        });
    }

    getUsageSnapshot({ investigationId = null } = {}) {
        return this.#catalog.getUsageSnapshot({
            investigationId: investigationId === null
                ? null
                : requireIdentifier(investigationId, "investigationId"),
        });
    }
}

export {
    estimateDeterministicModelCostUnits,
    investigationResourceLimitsFingerprint,
    normalizeInvestigationResourceLimits,
    normalizeResourceBrokerConfig,
    resourceBrokerConfigFingerprint,
    sdkUsageToModelCostUnits,
};
