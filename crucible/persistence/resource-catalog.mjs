import { createHash } from "node:crypto";

import { canonicalize } from "./canonical.mjs";
import {
    ERROR_CODES,
    CruciblePersistenceError,
    InvalidArgumentError,
    NotFoundError,
    CasConflictError,
    AttemptIdentityError,
    FenceRejectedError,
    SchemaIntegrityError,
    StorageError,
} from "./errors.mjs";
import { assertLocalDatabasePath } from "./paths.mjs";
import {
    RESOURCE_CATALOG_CONFIG_HASH_ALGORITHM,
    RESOURCE_CATALOG_SCHEMA_VERSION,
    RESOURCE_LIMITS_HASH_ALGORITHM,
    applyResourceCatalogSchema,
    configureResourceCatalogConnection,
    configureResourceCatalogReadOnlyConnection,
    verifyResourceCatalogSchema,
} from "./resource-catalog-schema.mjs";
import { DatabaseSync } from "./sqlite.mjs";

const DEFAULT_BUSY_TIMEOUT_MS = 5_000;
const LEASE_STATUSES = new Set(["active", "released", "reclaimed"]);
const RESOURCE_MODES = new Set(["concurrency", "consumable"]);

function requireString(value, field, maximum = 512) {
    if (typeof value !== "string"
        || value.length < 1
        || value.length > maximum
        || /[\u0000-\u001f\u007f]/u.test(value)) {
        throw new InvalidArgumentError(
            `${field} must be a non-empty bounded string without control characters`,
            { field },
        );
    }
    return value;
}

function requireSafeInteger(value, field, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new InvalidArgumentError(
            `${field} must be a safe integer in ${minimum}..${maximum}`,
            { field, value },
        );
    }
    return value;
}

function requirePlainObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)) {
        throw new InvalidArgumentError(`${field} must be a plain object`, { field });
    }
    return value;
}

function documentFingerprint(algorithm, value) {
    const digest = createHash("sha256")
        .update(canonicalize(value))
        .digest("hex");
    return `${algorithm}:${digest}`;
}

function isSqliteError(error) {
    return error?.code === "ERR_SQLITE_ERROR";
}

function normalizeDefinitions(definitions) {
    if (!Array.isArray(definitions) || definitions.length < 1) {
        throw new InvalidArgumentError(
            "resource definitions must be a non-empty array",
        );
    }
    const keys = new Set();
    return Object.freeze(definitions.map((input, index) => {
        const value = requirePlainObject(input, `definitions[${index}]`);
        const resourceKey = requireString(
            value.resourceKey,
            `definitions[${index}].resourceKey`,
            256,
        );
        if (keys.has(resourceKey)) {
            throw new InvalidArgumentError(
                "resource definitions contain a duplicate resource key",
                { resourceKey },
            );
        }
        keys.add(resourceKey);
        const resourceMode = requireString(
            value.resourceMode,
            `definitions[${index}].resourceMode`,
            32,
        );
        if (!RESOURCE_MODES.has(resourceMode)) {
            throw new InvalidArgumentError(
                "resource definition mode is invalid",
                { resourceKey, resourceMode },
            );
        }
        return Object.freeze({
            resourceKey,
            resourceFamily: requireString(
                value.resourceFamily,
                `definitions[${index}].resourceFamily`,
                128,
            ),
            resourceName: value.resourceName === null
                ? null
                : requireString(
                    value.resourceName,
                    `definitions[${index}].resourceName`,
                    128,
                ),
            resourceMode,
            capacityUnits: requireSafeInteger(
                value.capacityUnits,
                `definitions[${index}].capacityUnits`,
                { minimum: 1 },
            ),
        });
    }).sort((left, right) => left.resourceKey.localeCompare(right.resourceKey)));
}

function normalizeEntries(entries, field, {
    allowZero = false,
    requireNonEmpty = true,
} = {}) {
    if (!Array.isArray(entries)
        || (requireNonEmpty && entries.length < 1)) {
        throw new InvalidArgumentError(
            `${field} must be ${requireNonEmpty ? "a non-empty" : "an"} array`,
            { field },
        );
    }
    const keys = new Set();
    return entries.map((input, index) => {
        const value = requirePlainObject(input, `${field}[${index}]`);
        const resourceKey = requireString(
            value.resourceKey,
            `${field}[${index}].resourceKey`,
            256,
        );
        if (keys.has(resourceKey)) {
            throw new InvalidArgumentError(
                `${field} contains a duplicate resource`,
                { field, resourceKey },
            );
        }
        keys.add(resourceKey);
        return Object.freeze({
            resourceKey,
            units: requireSafeInteger(
                value.units,
                `${field}[${index}].units`,
                { minimum: allowZero ? 0 : 1 },
            ),
        });
    }).sort((left, right) => left.resourceKey.localeCompare(right.resourceKey));
}

function numberFromSql(value, field) {
    const normalized = Number(value ?? 0);
    if (!Number.isSafeInteger(normalized) || normalized < 0) {
        throw new SchemaIntegrityError(
            `resource catalog ${field} is outside safe integer range`,
            { field, value },
        );
    }
    return normalized;
}

export function openResourceCatalog(options = {}) {
    return ResourceCatalogRepository.open(options);
}

export function openResourceCatalogReadOnly(options = {}) {
    return ResourceCatalogRepository.open({ ...options, readOnly: true });
}

export class ResourceCatalogRepository {
    #db;
    #file;
    #config;
    #configFingerprint;
    #definitions;
    #definitionsByKey;
    #now;
    #isOwnerAlive;
    #readOnly;
    #busyTimeoutMs;
    #integrityCheckAdapter;

    constructor(db, {
        file,
        config,
        configFingerprint,
        definitions,
        now,
        isOwnerAlive,
        readOnly,
        busyTimeoutMs,
        integrityCheckAdapter,
    }) {
        this.#db = db;
        this.#file = file;
        this.#config = config;
        this.#configFingerprint = configFingerprint;
        this.#definitions = definitions;
        this.#definitionsByKey = new Map(
            definitions.map((definition) => [definition.resourceKey, definition]),
        );
        this.#now = now;
        this.#isOwnerAlive = isOwnerAlive;
        this.#readOnly = readOnly;
        this.#busyTimeoutMs = busyTimeoutMs;
        this.#integrityCheckAdapter = integrityCheckAdapter;
    }

    static open(options = {}) {
        const {
            file,
            config,
            definitions,
            busyTimeoutMs = DEFAULT_BUSY_TIMEOUT_MS,
            now = Date.now,
            isOwnerAlive = null,
            denyRoots,
            env,
            readOnly = false,
            integrityCheckAdapter = undefined,
        } = options;
        requirePlainObject(config, "config");
        if (typeof now !== "function") {
            throw new InvalidArgumentError("now must be a function");
        }
        if (isOwnerAlive !== null && typeof isOwnerAlive !== "function") {
            throw new InvalidArgumentError(
                "isOwnerAlive must be a synchronous function or null",
            );
        }
        requireSafeInteger(busyTimeoutMs, "busyTimeoutMs");
        const normalizedDefinitions = normalizeDefinitions(definitions);
        const configFingerprint = documentFingerprint(
            RESOURCE_CATALOG_CONFIG_HASH_ALGORITHM,
            config,
        );
        const resolved = assertLocalDatabasePath(file, { denyRoots, env });

        let db;
        try {
            db = new DatabaseSync(resolved, { readOnly: readOnly === true });
        } catch (error) {
            throw new StorageError(
                `failed to open resource catalog at ${resolved}: ${error.message}`,
                error,
            );
        }

        try {
            if (readOnly === true) {
                configureResourceCatalogReadOnlyConnection(db, { busyTimeoutMs });
                verifyResourceCatalogSchema(db, {
                    busyTimeoutMs,
                    integrityCheckAdapter,
                });
            } else {
                configureResourceCatalogConnection(db, { busyTimeoutMs });
                applyResourceCatalogSchema(db, {
                    busyTimeoutMs,
                    integrityCheckAdapter,
                    nowMs: ResourceCatalogRepository.#readNow(now),
                });
            }
            const repository = new ResourceCatalogRepository(db, {
                file: resolved,
                config,
                configFingerprint,
                definitions: normalizedDefinitions,
                now,
                isOwnerAlive,
                readOnly: readOnly === true,
                busyTimeoutMs,
                integrityCheckAdapter,
            });
            if (readOnly === true) {
                repository.#verifyCatalogConfiguration();
            } else {
                repository.#initializeCatalogConfiguration();
            }
            return repository;
        } catch (error) {
            db.close();
            if (error instanceof CruciblePersistenceError) {
                throw error;
            }
            if (isSqliteError(error)) {
                throw new StorageError(
                    `failed to initialize resource catalog at ${resolved}: ${error.message}`,
                    error,
                );
            }
            throw error;
        }
    }

    static #readNow(now) {
        const value = now();
        return requireSafeInteger(value, "now()", { minimum: 0 });
    }

    get databaseFile() {
        return this.#file;
    }

    get schemaVersion() {
        return RESOURCE_CATALOG_SCHEMA_VERSION;
    }

    get configFingerprint() {
        return this.#configFingerprint;
    }

    get readOnly() {
        return this.#readOnly;
    }

    close() {
        this.#db.close();
    }

    verifyIntegrity() {
        return verifyResourceCatalogSchema(this.#db, {
            busyTimeoutMs: this.#busyTimeoutMs,
            integrityCheckAdapter: this.#integrityCheckAdapter,
        });
    }

    #timestamp() {
        return ResourceCatalogRepository.#readNow(this.#now);
    }

    #tx(operation) {
        if (this.#readOnly) {
            throw new InvalidArgumentError(
                "resource catalog is read-only",
            );
        }
        let began = false;
        try {
            this.#db.exec("BEGIN IMMEDIATE;");
            began = true;
            const result = operation();
            this.#db.exec("COMMIT;");
            began = false;
            return result;
        } catch (error) {
            if (began) {
                try {
                    this.#db.exec("ROLLBACK;");
                } catch (rollbackError) {
                    error.rollbackError = rollbackError;
                }
            }
            if (error instanceof CruciblePersistenceError) {
                throw error;
            }
            if (isSqliteError(error)) {
                throw new StorageError(
                    `resource catalog transaction failed: ${error.message}`,
                    error,
                );
            }
            throw error;
        }
    }

    #initializeCatalogConfiguration() {
        this.#tx(() => {
            const existing = this.#db.prepare(
                "SELECT * FROM catalog_config WHERE singleton_id = 1",
            ).get();
            if (existing === undefined) {
                const definitionCount = Number(this.#db.prepare(
                    "SELECT COUNT(*) AS count FROM resource_definitions",
                ).get()?.count ?? 0);
                if (definitionCount !== 0) {
                    throw new SchemaIntegrityError(
                        "resource definitions exist without singleton catalog configuration",
                        { definitionCount },
                    );
                }
                const nowMs = this.#timestamp();
                this.#db.prepare(`
                    INSERT INTO catalog_config(
                        singleton_id, config_json, config_fingerprint, created_at_ms)
                    VALUES(1, :config, :fingerprint, :createdAt)`).run({
                    config: canonicalize(this.#config),
                    fingerprint: this.#configFingerprint,
                    createdAt: nowMs,
                });
                const insertDefinition = this.#db.prepare(`
                    INSERT INTO resource_definitions(
                        resource_key, resource_family, resource_name,
                        resource_mode, capacity_units, config_fingerprint)
                    VALUES(:key, :family, :name, :mode, :capacity, :fingerprint)`);
                for (const definition of this.#definitions) {
                    insertDefinition.run({
                        key: definition.resourceKey,
                        family: definition.resourceFamily,
                        name: definition.resourceName,
                        mode: definition.resourceMode,
                        capacity: definition.capacityUnits,
                        fingerprint: this.#configFingerprint,
                    });
                }
            }
        });
        this.#verifyCatalogConfiguration();
    }

    #verifyCatalogConfiguration() {
        const row = this.#db.prepare(
            "SELECT * FROM catalog_config WHERE singleton_id = 1",
        ).get();
        if (row === undefined) {
            throw new SchemaIntegrityError(
                "resource catalog singleton configuration is missing",
            );
        }
        const expectedConfig = canonicalize(this.#config);
        if (row.config_json !== expectedConfig
            || row.config_fingerprint !== this.#configFingerprint
            || documentFingerprint(
                RESOURCE_CATALOG_CONFIG_HASH_ALGORITHM,
                JSON.parse(row.config_json),
            ) !== row.config_fingerprint) {
            throw new SchemaIntegrityError(
                "resource catalog configuration differs from the state-root singleton",
                {
                    expectedFingerprint: this.#configFingerprint,
                    storedFingerprint: row.config_fingerprint,
                },
            );
        }
        const rows = this.#db.prepare(`
            SELECT resource_key, resource_family, resource_name,
                   resource_mode, capacity_units, config_fingerprint
            FROM resource_definitions
            ORDER BY resource_key
        `).all().map((definition) => ({
            resourceKey: definition.resource_key,
            resourceFamily: definition.resource_family,
            resourceName: definition.resource_name ?? null,
            resourceMode: definition.resource_mode,
            capacityUnits: numberFromSql(
                definition.capacity_units,
                `capacity:${definition.resource_key}`,
            ),
            configFingerprint: definition.config_fingerprint,
        }));
        const expected = this.#definitions.map((definition) => ({
            ...definition,
            configFingerprint: this.#configFingerprint,
        }));
        if (canonicalize(rows) !== canonicalize(expected)) {
            throw new SchemaIntegrityError(
                "resource definitions differ from the immutable catalog configuration",
                {
                    expectedCount: expected.length,
                    storedCount: rows.length,
                },
            );
        }
        for (const investigation of this.#db.prepare(
            "SELECT * FROM investigations ORDER BY investigation_id",
        ).all()) {
            this.#assertInvestigationLimitsIntegrity(investigation);
            this.#assertInvestigationAuthorityIntegrity(investigation);
        }
    }

    registerInvestigation({
        investigationId,
        limits,
        limitEntries,
        supervisorGeneration,
        supervisorNonce,
        runnerIncarnation,
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        requirePlainObject(limits, "limits");
        const entries = normalizeEntries(limitEntries, "limitEntries", {
            allowZero: true,
        });
        const generation = requireSafeInteger(
            supervisorGeneration,
            "supervisorGeneration",
            { minimum: 1 },
        );
        requireString(supervisorNonce, "supervisorNonce", 256);
        requireString(runnerIncarnation, "runnerIncarnation", 256);
        const limitsJson = canonicalize(limits);
        const limitsFingerprint = documentFingerprint(
            RESOURCE_LIMITS_HASH_ALGORITHM,
            { limits, entries },
        );

        return this.#tx(() => {
            const existing = this.#db.prepare(
                "SELECT * FROM investigations WHERE investigation_id = ?",
            ).get(investigationId);
            if (existing !== undefined) {
                this.#assertInvestigationLimitsIntegrity(existing);
                this.#assertInvestigationAuthorityIntegrity(existing);
                if (existing.limits_json !== limitsJson
                    || existing.limits_fingerprint !== limitsFingerprint) {
                    throw new SchemaIntegrityError(
                        "per-investigation resource limits are already frozen differently",
                        {
                            investigationId,
                            expected: existing.limits_fingerprint,
                            presented: limitsFingerprint,
                        },
                    );
                }
                if (Number(existing.supervisor_generation) !== generation
                    || existing.supervisor_nonce !== supervisorNonce
                    || existing.runner_incarnation !== runnerIncarnation) {
                    throw new FenceRejectedError(
                        "investigation is registered under different runtime authority; claim authority explicitly",
                        {
                            investigationId,
                            currentGeneration: Number(existing.supervisor_generation),
                            presentedGeneration: generation,
                        },
                    );
                }
                return Object.freeze({
                    created: false,
                    investigation: this.#rowToInvestigation(existing),
                });
            }

            if (entries.length !== this.#definitions.length) {
                throw new InvalidArgumentError(
                    "investigation limits must define every catalog resource",
                    {
                        expected: this.#definitions.length,
                        presented: entries.length,
                    },
                );
            }
            for (const entry of entries) {
                const definition = this.#definitionsByKey.get(entry.resourceKey);
                if (definition === undefined) {
                    throw new InvalidArgumentError(
                        "investigation limit names an unknown resource",
                        { resourceKey: entry.resourceKey },
                    );
                }
                if (entry.units > definition.capacityUnits) {
                    throw new InvalidArgumentError(
                        "investigation limit exceeds global capacity",
                        {
                            resourceKey: entry.resourceKey,
                            limitUnits: entry.units,
                            capacityUnits: definition.capacityUnits,
                        },
                    );
                }
            }

            const nowMs = this.#timestamp();
            const incarnationOwner = this.#db.prepare(`
                SELECT investigation_id, supervisor_generation
                FROM authority_incarnations
                WHERE runner_incarnation = ?
            `).get(runnerIncarnation);
            if (incarnationOwner !== undefined) {
                throw new FenceRejectedError(
                    "runner incarnation has already been claimed",
                    {
                        runnerIncarnation,
                        investigationId: incarnationOwner.investigation_id,
                        supervisorGeneration:
                            Number(incarnationOwner.supervisor_generation),
                    },
                );
            }
            this.#db.prepare(`
                INSERT INTO investigations(
                    investigation_id, limits_json, limits_fingerprint,
                    supervisor_generation, supervisor_nonce, runner_incarnation,
                    registered_at_ms, authority_updated_at_ms)
                VALUES(:investigationId, :limits, :fingerprint,
                    :generation, :nonce, :incarnation, :registeredAt, :updatedAt)`)
                .run({
                    investigationId,
                    limits: limitsJson,
                    fingerprint: limitsFingerprint,
                    generation,
                    nonce: supervisorNonce,
                    incarnation: runnerIncarnation,
                    registeredAt: nowMs,
                    updatedAt: nowMs,
                });
            this.#db.prepare(`
                INSERT INTO authority_incarnations(
                    runner_incarnation, investigation_id,
                    supervisor_generation, supervisor_nonce,
                    claimed_at_ms, retired_at_ms)
                VALUES(:incarnation, :investigationId,
                    :generation, :nonce, :claimedAt, NULL)`).run({
                incarnation: runnerIncarnation,
                investigationId,
                generation,
                nonce: supervisorNonce,
                claimedAt: nowMs,
            });
            const insertLimit = this.#db.prepare(`
                INSERT INTO investigation_limits(
                    investigation_id, resource_key, limit_units)
                VALUES(:investigationId, :resourceKey, :limitUnits)`);
            for (const entry of entries) {
                insertLimit.run({
                    investigationId,
                    resourceKey: entry.resourceKey,
                    limitUnits: entry.units,
                });
            }
            return Object.freeze({
                created: true,
                investigation: this.getInvestigation(investigationId),
            });
        });
    }

    getInvestigation(investigationId) {
        requireString(investigationId, "investigationId", 128);
        const row = this.#db.prepare(
            "SELECT * FROM investigations WHERE investigation_id = ?",
        ).get(investigationId);
        if (row === undefined) {
            return null;
        }
        const limits = this.#assertInvestigationLimitsIntegrity(row);
        this.#assertInvestigationAuthorityIntegrity(row);
        return Object.freeze({
            ...this.#rowToInvestigation(row),
            limits: Object.freeze(limits),
        });
    }

    #rowToInvestigation(row) {
        return Object.freeze({
            investigationId: row.investigation_id,
            limitsDocument: JSON.parse(row.limits_json),
            limitsFingerprint: row.limits_fingerprint,
            supervisorGeneration: numberFromSql(
                row.supervisor_generation,
                "supervisorGeneration",
            ),
            supervisorNonce: row.supervisor_nonce,
            runnerIncarnation: row.runner_incarnation,
            registeredAtMs: numberFromSql(row.registered_at_ms, "registeredAtMs"),
            authorityUpdatedAtMs: numberFromSql(
                row.authority_updated_at_ms,
                "authorityUpdatedAtMs",
            ),
        });
    }

    claimAuthority({
        investigationId,
        supervisorGeneration,
        supervisorNonce,
        runnerIncarnation,
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        const generation = requireSafeInteger(
            supervisorGeneration,
            "supervisorGeneration",
            { minimum: 1 },
        );
        requireString(supervisorNonce, "supervisorNonce", 256);
        requireString(runnerIncarnation, "runnerIncarnation", 256);

        return this.#tx(() => {
            const current = this.#requireInvestigationInTransaction(investigationId);
            const currentGeneration = Number(current.supervisor_generation);
            if (generation < currentGeneration) {
                throw new FenceRejectedError(
                    "supervisor generation is below the resource catalog high-water mark",
                    {
                        investigationId,
                        presented: generation,
                        current: currentGeneration,
                    },
                );
            }
            if (generation === currentGeneration
                && current.supervisor_nonce !== supervisorNonce) {
                throw new FenceRejectedError(
                    "supervisor generation is already owned by another nonce",
                    { investigationId, supervisorGeneration: generation },
                );
            }
            if (generation === currentGeneration
                && current.runner_incarnation === runnerIncarnation) {
                return Object.freeze({
                    changed: false,
                    reclaimed: Object.freeze([]),
                    investigation: this.#rowToInvestigation(current),
                });
            }

            const nowMs = this.#timestamp();
            const priorIncarnation = this.#db.prepare(`
                SELECT investigation_id, supervisor_generation, retired_at_ms
                FROM authority_incarnations
                WHERE runner_incarnation = ?
            `).get(runnerIncarnation);
            if (priorIncarnation !== undefined) {
                throw new FenceRejectedError(
                    "runner incarnation cannot be reused",
                    {
                        runnerIncarnation,
                        previousInvestigationId:
                            priorIncarnation.investigation_id,
                        previousSupervisorGeneration:
                            Number(priorIncarnation.supervisor_generation),
                    },
                );
            }
            const active = this.#db.prepare(`
                SELECT fencing_token
                FROM leases
                WHERE investigation_id = ? AND status = 'active'
                ORDER BY fencing_token
            `).all(investigationId);
            const reclaimed = [];
            for (const lease of active) {
                const token = numberFromSql(lease.fencing_token, "fencingToken");
                this.#finalizeUnknownInTransaction(
                    token,
                    "superseded_authority",
                    nowMs,
                );
                reclaimed.push(token);
            }
            const retired = this.#db.prepare(`
                UPDATE authority_incarnations
                SET retired_at_ms = :retiredAt
                WHERE runner_incarnation = :incarnation
                  AND investigation_id = :investigationId
                  AND retired_at_ms IS NULL`).run({
                retiredAt: nowMs,
                incarnation: current.runner_incarnation,
                investigationId,
            });
            if (Number(retired.changes) !== 1) {
                throw new SchemaIntegrityError(
                    "current runner incarnation history is missing or already retired",
                    {
                        investigationId,
                        runnerIncarnation: current.runner_incarnation,
                    },
                );
            }
            this.#db.prepare(`
                INSERT INTO authority_incarnations(
                    runner_incarnation, investigation_id,
                    supervisor_generation, supervisor_nonce,
                    claimed_at_ms, retired_at_ms)
                VALUES(:incarnation, :investigationId,
                    :generation, :nonce, :claimedAt, NULL)`).run({
                incarnation: runnerIncarnation,
                investigationId,
                generation,
                nonce: supervisorNonce,
                claimedAt: nowMs,
            });
            this.#db.prepare(`
                UPDATE investigations
                SET supervisor_generation = :generation,
                    supervisor_nonce = :nonce,
                    runner_incarnation = :incarnation,
                    authority_updated_at_ms = :updatedAt
                WHERE investigation_id = :investigationId`).run({
                generation,
                nonce: supervisorNonce,
                incarnation: runnerIncarnation,
                updatedAt: nowMs,
                investigationId,
            });
            return Object.freeze({
                changed: true,
                reclaimed: Object.freeze(reclaimed),
                investigation: this.#rowToInvestigation(
                    this.#requireInvestigationInTransaction(investigationId),
                ),
            });
        });
    }

    acquireLease({
        investigationId,
        leaseId,
        leaseNonce,
        ownerId,
        ownerProcessId = null,
        ownerProcessStartId = null,
        supervisorGeneration,
        runnerIncarnation,
        attemptId,
        logicalEffectId,
        requests,
        ttlMs,
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        requireString(leaseId, "leaseId", 256);
        requireString(leaseNonce, "leaseNonce", 256);
        requireString(ownerId, "ownerId", 256);
        const generation = requireSafeInteger(
            supervisorGeneration,
            "supervisorGeneration",
            { minimum: 1 },
        );
        requireString(runnerIncarnation, "runnerIncarnation", 256);
        requireString(attemptId, "attemptId", 256);
        requireString(logicalEffectId, "logicalEffectId", 256);
        const normalizedRequests = normalizeEntries(requests, "requests");
        const maximumTtl = requireSafeInteger(
            this.#config.lease?.maxTtlMs,
            "config.lease.maxTtlMs",
            { minimum: 1 },
        );
        const normalizedTtl = requireSafeInteger(ttlMs, "ttlMs", {
            minimum: 1,
            maximum: maximumTtl,
        });
        if ((ownerProcessId === null) !== (ownerProcessStartId === null)) {
            throw new InvalidArgumentError(
                "ownerProcessId and ownerProcessStartId must be provided together",
            );
        }
        const normalizedProcessId = ownerProcessId === null
            ? null
            : requireSafeInteger(ownerProcessId, "ownerProcessId", { minimum: 1 });
        const normalizedProcessStartId = ownerProcessStartId === null
            ? null
            : requireString(ownerProcessStartId, "ownerProcessStartId", 256);
        const requestFingerprint = documentFingerprint(
            "sha256:crucible-resource-reservation-v1",
            normalizedRequests,
        );

        return this.#tx(() => {
            this.#assertCurrentAuthorityInTransaction({
                investigationId,
                supervisorGeneration: generation,
                runnerIncarnation,
            });
            const nowMs = this.#timestamp();
            const reclaimed = this.#reclaimStaleInTransaction(nowMs);

            const existing = this.#db.prepare(`
                SELECT *
                FROM leases
                WHERE investigation_id = ? AND logical_effect_id = ?
            `).get(investigationId, logicalEffectId);
            if (existing !== undefined) {
                if (existing.owner_id !== ownerId
                    || Number(existing.supervisor_generation) !== generation
                    || existing.runner_incarnation !== runnerIncarnation
                    || existing.attempt_id !== attemptId
                    || existing.request_fingerprint !== requestFingerprint) {
                    throw new AttemptIdentityError(
                        "logical effect already has a differently bound resource lease",
                        {
                            investigationId,
                            logicalEffectId,
                            existingLeaseId: existing.lease_id,
                        },
                    );
                }
                const lease = this.#loadLeaseByToken(
                    numberFromSql(existing.fencing_token, "fencingToken"),
                );
                return Object.freeze({
                    status: existing.status === "active"
                        ? "acquired"
                        : "already_finalized",
                    deduplicated: true,
                    lease,
                    reclaimed: Object.freeze(reclaimed),
                });
            }

            const deficits = [];
            for (const request of normalizedRequests) {
                const definition = this.#definitionsByKey.get(request.resourceKey);
                if (definition === undefined) {
                    throw new InvalidArgumentError(
                        "reservation names an unknown resource",
                        { resourceKey: request.resourceKey },
                    );
                }
                const limitRow = this.#db.prepare(`
                    SELECT limit_units
                    FROM investigation_limits
                    WHERE investigation_id = ? AND resource_key = ?
                `).get(investigationId, request.resourceKey);
                if (limitRow === undefined) {
                    throw new SchemaIntegrityError(
                        "investigation is missing a frozen resource limit",
                        { investigationId, resourceKey: request.resourceKey },
                    );
                }
                const investigationLimit = numberFromSql(
                    limitRow.limit_units,
                    `investigationLimit:${request.resourceKey}`,
                );
                const investigationUsage = this.#resourceUsageInTransaction(
                    request.resourceKey,
                    investigationId,
                );
                const globalUsage = this.#resourceUsageInTransaction(
                    request.resourceKey,
                    null,
                );
                this.#appendDeficit(deficits, {
                    scope: "investigation",
                    resourceKey: request.resourceKey,
                    requestedUnits: request.units,
                    limitUnits: investigationLimit,
                    usage: investigationUsage,
                    nowMs,
                    investigationId,
                });
                this.#appendDeficit(deficits, {
                    scope: "global",
                    resourceKey: request.resourceKey,
                    requestedUnits: request.units,
                    limitUnits: definition.capacityUnits,
                    usage: globalUsage,
                    nowMs,
                    investigationId: null,
                });
            }
            if (deficits.length > 0) {
                deficits.sort((left, right) => {
                    if (left.disposition !== right.disposition) {
                        return left.disposition === "pause" ? -1 : 1;
                    }
                    const resourceOrder = left.resourceKey.localeCompare(right.resourceKey);
                    if (resourceOrder !== 0) return resourceOrder;
                    return left.scope.localeCompare(right.scope);
                });
                const primary = deficits[0];
                return Object.freeze({
                    status: primary.disposition,
                    reason: primary.disposition === "pause"
                        ? "resource_budget_exhausted"
                        : "resource_capacity_busy",
                    scientificConclusion: false,
                    terminal: false,
                    deficit: primary,
                    deficits: Object.freeze(deficits),
                    lease: null,
                    reclaimed: Object.freeze(reclaimed),
                });
            }

            const expiresAtMs = nowMs + normalizedTtl;
            if (!Number.isSafeInteger(expiresAtMs)) {
                throw new InvalidArgumentError(
                    "lease expiry exceeds safe integer range",
                    { nowMs, ttlMs: normalizedTtl },
                );
            }
            const inserted = this.#db.prepare(`
                INSERT INTO leases(
                    lease_id, lease_nonce, investigation_id, owner_id,
                    owner_process_id, owner_process_start_id,
                    supervisor_generation, runner_incarnation,
                    attempt_id, logical_effect_id, request_fingerprint,
                    status, acquired_at_ms, heartbeat_at_ms, expires_at_ms,
                    finalized_at_ms, finalization_reason)
                VALUES(:leaseId, :leaseNonce, :investigationId, :ownerId,
                    :ownerProcessId, :ownerProcessStartId,
                    :generation, :incarnation,
                    :attemptId, :logicalEffectId, :requestFingerprint,
                    'active', :nowMs, :nowMs, :expiresAtMs, NULL, NULL)`)
                .run({
                    leaseId,
                    leaseNonce,
                    investigationId,
                    ownerId,
                    ownerProcessId: normalizedProcessId,
                    ownerProcessStartId: normalizedProcessStartId,
                    generation,
                    incarnation: runnerIncarnation,
                    attemptId,
                    logicalEffectId,
                    requestFingerprint,
                    nowMs,
                    expiresAtMs,
                });
            const fencingToken = numberFromSql(
                inserted.lastInsertRowid,
                "fencingToken",
            );
            const insertAllocation = this.#db.prepare(`
                INSERT INTO lease_allocations(
                    fencing_token, resource_key, reserved_units,
                    charged_units, reconciled_at_ms)
                VALUES(:fencingToken, :resourceKey, :reservedUnits, 0, NULL)`);
            for (const request of normalizedRequests) {
                insertAllocation.run({
                    fencingToken,
                    resourceKey: request.resourceKey,
                    reservedUnits: request.units,
                });
            }
            return Object.freeze({
                status: "acquired",
                deduplicated: false,
                lease: this.#loadLeaseByToken(fencingToken),
                reclaimed: Object.freeze(reclaimed),
            });
        });
    }

    #appendDeficit(deficits, {
        scope,
        resourceKey,
        requestedUnits,
        limitUnits,
        usage,
        nowMs,
        investigationId,
    }) {
        const permanentAvailable = Math.max(0, limitUnits - usage.committedUnits);
        const availableNow = Math.max(
            0,
            limitUnits - usage.committedUnits - usage.heldUnits,
        );
        if (requestedUnits <= availableNow) {
            return;
        }
        const disposition = requestedUnits > permanentAvailable
            ? "pause"
            : "throttle";
        const nearestExpiryMs = disposition === "throttle"
            ? this.#nearestExpiryInTransaction(resourceKey, investigationId)
            : null;
        deficits.push(Object.freeze({
            disposition,
            scope,
            resourceKey,
            requestedUnits,
            limitUnits,
            committedUnits: usage.committedUnits,
            heldUnits: usage.heldUnits,
            availableUnits: availableNow,
            retryAfterMs: nearestExpiryMs === null
                ? null
                : Math.max(0, nearestExpiryMs - nowMs),
        }));
    }

    renewLease({
        leaseId,
        fencingToken,
        leaseNonce,
        ownerId,
        supervisorGeneration,
        runnerIncarnation,
        ttlMs,
    } = {}) {
        const credentials = this.#normalizeLeaseCredentials({
            leaseId,
            fencingToken,
            leaseNonce,
            ownerId,
            supervisorGeneration,
            runnerIncarnation,
        });
        const maximumTtl = requireSafeInteger(
            this.#config.lease?.maxTtlMs,
            "config.lease.maxTtlMs",
            { minimum: 1 },
        );
        const normalizedTtl = requireSafeInteger(ttlMs, "ttlMs", {
            minimum: 1,
            maximum: maximumTtl,
        });
        return this.#tx(() => {
            const nowMs = this.#timestamp();
            const reclaimed = this.#reclaimStaleInTransaction(nowMs);
            const row = this.#requireLeaseByIdInTransaction(credentials.leaseId);
            this.#assertLeaseCredentials(row, credentials);
            if (row.status !== "active") {
                return Object.freeze({
                    status: row.status,
                    renewed: false,
                    reclaimed: Object.freeze(reclaimed),
                    lease: this.#loadLeaseByToken(credentials.fencingToken),
                });
            }
            this.#assertCurrentAuthorityInTransaction({
                investigationId: row.investigation_id,
                supervisorGeneration: credentials.supervisorGeneration,
                runnerIncarnation: credentials.runnerIncarnation,
            });
            const expiresAtMs = nowMs + normalizedTtl;
            if (!Number.isSafeInteger(expiresAtMs)) {
                throw new InvalidArgumentError(
                    "lease expiry exceeds safe integer range",
                    { nowMs, ttlMs: normalizedTtl },
                );
            }
            this.#db.prepare(`
                UPDATE leases
                SET heartbeat_at_ms = :heartbeatAt,
                    expires_at_ms = :expiresAt
                WHERE fencing_token = :fencingToken AND status = 'active'`)
                .run({
                    heartbeatAt: nowMs,
                    expiresAt: expiresAtMs,
                    fencingToken: credentials.fencingToken,
                });
            return Object.freeze({
                status: "active",
                renewed: true,
                reclaimed: Object.freeze(reclaimed),
                lease: this.#loadLeaseByToken(credentials.fencingToken),
            });
        });
    }

    releaseLease({
        leaseId,
        fencingToken,
        leaseNonce,
        ownerId,
        supervisorGeneration,
        runnerIncarnation,
        usage = [],
        releaseId = "release",
    } = {}) {
        const credentials = this.#normalizeLeaseCredentials({
            leaseId,
            fencingToken,
            leaseNonce,
            ownerId,
            supervisorGeneration,
            runnerIncarnation,
        });
        const usageEntries = normalizeEntries(usage, "usage", {
            allowZero: true,
            requireNonEmpty: false,
        });
        requireString(releaseId, "releaseId", 256);
        return this.#tx(() => {
            const nowMs = this.#timestamp();
            const reclaimed = this.#reclaimStaleInTransaction(nowMs);
            let row = this.#requireLeaseByIdInTransaction(credentials.leaseId);
            this.#assertLeaseCredentials(row, credentials);
            const allocations = this.#db.prepare(`
                SELECT a.resource_key, a.reserved_units
                FROM lease_allocations AS a
                JOIN resource_definitions AS d
                  ON d.resource_key = a.resource_key
                WHERE a.fencing_token = ?
                  AND d.resource_mode = 'consumable'
                ORDER BY a.resource_key
            `).all(credentials.fencingToken);
            const modelCost = allocations.find(
                (allocation) =>
                    allocation.resource_key === "model_cost_units",
            );
            if (modelCost !== undefined) {
                this.#reconcileAllocationInTransaction({
                    fencingToken: credentials.fencingToken,
                    resourceKey: modelCost.resource_key,
                    reportedUnits: numberFromSql(
                        modelCost.reserved_units,
                        "reserved:model_cost_units",
                    ),
                    reconciliationId:
                        `${releaseId}:model_cost_units:deterministic-estimate`,
                    source: "deterministic_estimate",
                    nowMs,
                });
            }
            const reportedKeys = new Set();
            for (const entry of usageEntries) {
                reportedKeys.add(entry.resourceKey);
                this.#reconcileAllocationInTransaction({
                    fencingToken: credentials.fencingToken,
                    resourceKey: entry.resourceKey,
                    reportedUnits: entry.units,
                    reconciliationId: `${releaseId}:${entry.resourceKey}:reported`,
                    source: "release_reported",
                    nowMs,
                });
            }
            if (row.status === "active") {
                for (const allocation of allocations) {
                    if (reportedKeys.has(allocation.resource_key)
                        || allocation.resource_key === "model_cost_units") {
                        continue;
                    }
                    this.#reconcileAllocationInTransaction({
                        fencingToken: credentials.fencingToken,
                        resourceKey: allocation.resource_key,
                        reportedUnits: numberFromSql(
                            allocation.reserved_units,
                            `reserved:${allocation.resource_key}`,
                        ),
                        reconciliationId:
                            `${releaseId}:${allocation.resource_key}:reservation-fallback`,
                        source: "reservation_fallback",
                        nowMs,
                    });
                }
                this.#db.prepare(`
                    UPDATE leases
                    SET status = 'released',
                        finalized_at_ms = :finalizedAt,
                        finalization_reason = 'released'
                    WHERE fencing_token = :fencingToken AND status = 'active'`)
                    .run({
                        finalizedAt: nowMs,
                        fencingToken: credentials.fencingToken,
                    });
                row = this.#requireLeaseByIdInTransaction(credentials.leaseId);
            }
            return Object.freeze({
                status: row.status,
                released: row.status === "released",
                reclaimed: Object.freeze(reclaimed),
                lease: this.#loadLeaseByToken(credentials.fencingToken),
                overruns: Object.freeze(
                    this.#overrunsInTransaction(row.investigation_id),
                ),
            });
        });
    }

    reconcileUsage({
        leaseId,
        fencingToken,
        leaseNonce,
        usage,
        reconciliationId,
        source,
    } = {}) {
        requireString(leaseId, "leaseId", 256);
        const token = requireSafeInteger(fencingToken, "fencingToken", { minimum: 1 });
        requireString(leaseNonce, "leaseNonce", 256);
        const usageEntries = normalizeEntries(usage, "usage", {
            allowZero: true,
        });
        requireString(reconciliationId, "reconciliationId", 256);
        requireString(source, "source", 128);
        return this.#tx(() => {
            const row = this.#requireLeaseByIdInTransaction(leaseId);
            if (Number(row.fencing_token) !== token || row.lease_nonce !== leaseNonce) {
                throw new FenceRejectedError(
                    "resource lease handle does not match its fencing token/nonce",
                    { leaseId, fencingToken: token },
                );
            }
            const nowMs = this.#timestamp();
            const reconciled = [];
            for (const entry of usageEntries) {
                reconciled.push(this.#reconcileAllocationInTransaction({
                    fencingToken: token,
                    resourceKey: entry.resourceKey,
                    reportedUnits: entry.units,
                    reconciliationId: `${reconciliationId}:${entry.resourceKey}`,
                    source,
                    nowMs,
                }));
            }
            return Object.freeze({
                lease: this.#loadLeaseByToken(token),
                reconciled: Object.freeze(reconciled),
                overruns: Object.freeze(
                    this.#overrunsInTransaction(row.investigation_id),
                ),
            });
        });
    }

    reclaimStale() {
        return this.#tx(() => {
            const nowMs = this.#timestamp();
            const reclaimed = this.#reclaimStaleInTransaction(nowMs);
            return Object.freeze(reclaimed.map(({ fencingToken, reason }) => ({
                fencingToken,
                reason,
                lease: this.#loadLeaseByToken(fencingToken),
            })));
        });
    }

    getLease(leaseId) {
        requireString(leaseId, "leaseId", 256);
        const row = this.#db.prepare(
            "SELECT fencing_token FROM leases WHERE lease_id = ?",
        ).get(leaseId);
        return row === undefined
            ? null
            : this.#loadLeaseByToken(
                numberFromSql(row.fencing_token, "fencingToken"),
            );
    }

    listActiveLeases({ investigationId = null } = {}) {
        if (investigationId !== null) {
            requireString(investigationId, "investigationId", 128);
        }
        const rows = investigationId === null
            ? this.#db.prepare(`
                SELECT fencing_token
                FROM leases
                WHERE status = 'active'
                ORDER BY fencing_token
            `).all()
            : this.#db.prepare(`
                SELECT fencing_token
                FROM leases
                WHERE status = 'active' AND investigation_id = ?
                ORDER BY fencing_token
            `).all(investigationId);
        return Object.freeze(rows.map((row) => this.#loadLeaseByToken(
            numberFromSql(row.fencing_token, "fencingToken"),
        )));
    }

    getUsageSnapshot({ investigationId = null } = {}) {
        if (investigationId !== null) {
            requireString(investigationId, "investigationId", 128);
            this.#requireInvestigationInTransaction(investigationId);
        }
        return Object.freeze(this.#usageSnapshotInTransaction(investigationId));
    }

    #normalizeLeaseCredentials({
        leaseId,
        fencingToken,
        leaseNonce,
        ownerId,
        supervisorGeneration,
        runnerIncarnation,
    }) {
        return Object.freeze({
            leaseId: requireString(leaseId, "leaseId", 256),
            fencingToken: requireSafeInteger(
                fencingToken,
                "fencingToken",
                { minimum: 1 },
            ),
            leaseNonce: requireString(leaseNonce, "leaseNonce", 256),
            ownerId: requireString(ownerId, "ownerId", 256),
            supervisorGeneration: requireSafeInteger(
                supervisorGeneration,
                "supervisorGeneration",
                { minimum: 1 },
            ),
            runnerIncarnation: requireString(
                runnerIncarnation,
                "runnerIncarnation",
                256,
            ),
        });
    }

    #requireInvestigationInTransaction(investigationId) {
        const row = this.#db.prepare(
            "SELECT * FROM investigations WHERE investigation_id = ?",
        ).get(investigationId);
        if (row === undefined) {
            throw new NotFoundError(
                ERROR_CODES.INVESTIGATION_NOT_FOUND,
                "resource catalog investigation not found",
                { investigationId },
            );
        }
        this.#assertInvestigationLimitsIntegrity(row);
        this.#assertInvestigationAuthorityIntegrity(row);
        return row;
    }

    #assertInvestigationLimitsIntegrity(row) {
        let limitsDocument;
        try {
            limitsDocument = JSON.parse(row.limits_json);
        } catch (error) {
            throw new SchemaIntegrityError(
                "investigation resource limits document is not valid JSON",
                {
                    investigationId: row.investigation_id,
                    message: error?.message,
                },
            );
        }
        if (canonicalize(limitsDocument) !== row.limits_json) {
            throw new SchemaIntegrityError(
                "investigation resource limits document is not canonical",
                { investigationId: row.investigation_id },
            );
        }
        const entries = this.#db.prepare(`
            SELECT resource_key, limit_units
            FROM investigation_limits
            WHERE investigation_id = ?
            ORDER BY resource_key
        `).all(row.investigation_id).map((limit) => Object.freeze({
            resourceKey: limit.resource_key,
            units: numberFromSql(
                limit.limit_units,
                `limit:${limit.resource_key}`,
            ),
        }));
        if (entries.length !== this.#definitions.length) {
            throw new SchemaIntegrityError(
                "investigation does not have exactly one limit per catalog resource",
                {
                    investigationId: row.investigation_id,
                    expected: this.#definitions.length,
                    actual: entries.length,
                },
            );
        }
        for (let index = 0; index < entries.length; index += 1) {
            const entry = entries[index];
            const definition = this.#definitions[index];
            if (entry.resourceKey !== definition.resourceKey
                || entry.units > definition.capacityUnits) {
                throw new SchemaIntegrityError(
                    "investigation resource limits do not match catalog definitions",
                    {
                        investigationId: row.investigation_id,
                        resourceKey: entry.resourceKey,
                    },
                );
            }
        }
        const expectedFingerprint = documentFingerprint(
            RESOURCE_LIMITS_HASH_ALGORITHM,
            { limits: limitsDocument, entries },
        );
        if (row.limits_fingerprint !== expectedFingerprint) {
            throw new SchemaIntegrityError(
                "investigation resource limit rows differ from the frozen fingerprint",
                {
                    investigationId: row.investigation_id,
                    expected: expectedFingerprint,
                    stored: row.limits_fingerprint,
                },
            );
        }
        return Object.freeze(entries);
    }

    #assertInvestigationAuthorityIntegrity(row) {
        const active = this.#db.prepare(`
            SELECT *
            FROM authority_incarnations
            WHERE investigation_id = ?
              AND retired_at_ms IS NULL
        `).all(row.investigation_id);
        if (active.length !== 1
            || active[0].runner_incarnation !== row.runner_incarnation
            || Number(active[0].supervisor_generation)
                !== Number(row.supervisor_generation)
            || active[0].supervisor_nonce !== row.supervisor_nonce) {
            throw new SchemaIntegrityError(
                "investigation authority does not match its non-reusable incarnation history",
                {
                    investigationId: row.investigation_id,
                    activeAuthorityCount: active.length,
                },
            );
        }
        return active[0];
    }

    #assertCurrentAuthorityInTransaction({
        investigationId,
        supervisorGeneration,
        runnerIncarnation,
    }) {
        const current = this.#requireInvestigationInTransaction(investigationId);
        if (Number(current.supervisor_generation) !== supervisorGeneration
            || current.runner_incarnation !== runnerIncarnation) {
            throw new FenceRejectedError(
                "resource acquisition authority is stale",
                {
                    investigationId,
                    presentedGeneration: supervisorGeneration,
                    currentGeneration: Number(current.supervisor_generation),
                    presentedIncarnation: runnerIncarnation,
                    currentIncarnation: current.runner_incarnation,
                },
            );
        }
        return current;
    }

    #requireLeaseByIdInTransaction(leaseId) {
        const row = this.#db.prepare(
            "SELECT * FROM leases WHERE lease_id = ?",
        ).get(leaseId);
        if (row === undefined) {
            throw new NotFoundError(
                ERROR_CODES.LEASE_NOT_FOUND,
                "resource lease not found",
                { leaseId },
            );
        }
        return row;
    }

    #assertLeaseCredentials(row, credentials) {
        if (Number(row.fencing_token) !== credentials.fencingToken
            || row.lease_nonce !== credentials.leaseNonce
            || row.owner_id !== credentials.ownerId
            || Number(row.supervisor_generation)
                !== credentials.supervisorGeneration
            || row.runner_incarnation !== credentials.runnerIncarnation) {
            throw new FenceRejectedError(
                "resource lease credentials do not match the fenced owner",
                {
                    leaseId: credentials.leaseId,
                    fencingToken: credentials.fencingToken,
                },
            );
        }
    }

    #reclaimStaleInTransaction(nowMs) {
        const rows = this.#db.prepare(`
            SELECT l.*, i.supervisor_generation AS current_generation,
                   i.runner_incarnation AS current_incarnation
            FROM leases AS l
            JOIN investigations AS i
              ON i.investigation_id = l.investigation_id
            WHERE l.status = 'active'
            ORDER BY l.fencing_token
        `).all();
        const reclaimed = [];
        for (const row of rows) {
            let reason = null;
            if (Number(row.supervisor_generation) !== Number(row.current_generation)
                || row.runner_incarnation !== row.current_incarnation) {
                reason = "stale_authority";
            } else if (Number(row.expires_at_ms) <= nowMs) {
                reason = "expired";
            } else if (row.owner_process_id !== null
                && this.#isOwnerAlive !== null) {
                const alive = this.#isOwnerAlive(Object.freeze({
                    investigationId: row.investigation_id,
                    leaseId: row.lease_id,
                    fencingToken: numberFromSql(
                        row.fencing_token,
                        "fencingToken",
                    ),
                    ownerId: row.owner_id,
                    processId: numberFromSql(
                        row.owner_process_id,
                        "ownerProcessId",
                    ),
                    processStartId: row.owner_process_start_id,
                    supervisorGeneration: numberFromSql(
                        row.supervisor_generation,
                        "supervisorGeneration",
                    ),
                    runnerIncarnation: row.runner_incarnation,
                }));
                if (typeof alive !== "boolean") {
                    throw new InvalidArgumentError(
                        "isOwnerAlive must return a boolean synchronously",
                    );
                }
                if (!alive) {
                    reason = "owner_dead";
                }
            }
            if (reason !== null) {
                const fencingToken = numberFromSql(
                    row.fencing_token,
                    "fencingToken",
                );
                this.#finalizeUnknownInTransaction(
                    fencingToken,
                    reason,
                    nowMs,
                );
                reclaimed.push(Object.freeze({ fencingToken, reason }));
            }
        }
        return reclaimed;
    }

    #finalizeUnknownInTransaction(fencingToken, reason, nowMs) {
        this.#db.prepare(`
            UPDATE lease_allocations
            SET charged_units = MAX(charged_units, reserved_units),
                reconciled_at_ms = :reconciledAt
            WHERE fencing_token = :fencingToken
              AND resource_key IN (
                  SELECT resource_key
                  FROM resource_definitions
                  WHERE resource_mode = 'consumable'
              )`).run({
            reconciledAt: nowMs,
            fencingToken,
        });
        this.#db.prepare(`
            UPDATE leases
            SET status = 'reclaimed',
                finalized_at_ms = :finalizedAt,
                finalization_reason = :reason
            WHERE fencing_token = :fencingToken AND status = 'active'`).run({
            finalizedAt: nowMs,
            reason,
            fencingToken,
        });
    }

    #resourceUsageInTransaction(resourceKey, investigationId) {
        const whereInvestigation = investigationId === null
            ? ""
            : "AND l.investigation_id = :investigationId";
        const row = this.#db.prepare(`
            SELECT
                COALESCE(SUM(
                    CASE
                        WHEN d.resource_mode = 'consumable'
                        THEN a.charged_units
                        ELSE 0
                    END
                ), 0) AS committed_units,
                COALESCE(SUM(
                    CASE
                        WHEN l.status <> 'active' THEN 0
                        WHEN d.resource_mode = 'consumable'
                        THEN MAX(a.reserved_units, a.charged_units)
                             - a.charged_units
                        ELSE a.reserved_units
                    END
                ), 0) AS held_units
            FROM lease_allocations AS a
            JOIN leases AS l ON l.fencing_token = a.fencing_token
            JOIN resource_definitions AS d
              ON d.resource_key = a.resource_key
            WHERE a.resource_key = :resourceKey
              ${whereInvestigation}
        `).get({
            resourceKey,
            ...(investigationId === null ? {} : { investigationId }),
        });
        return Object.freeze({
            committedUnits: numberFromSql(
                row?.committed_units,
                `committed:${resourceKey}`,
            ),
            heldUnits: numberFromSql(row?.held_units, `held:${resourceKey}`),
        });
    }

    #nearestExpiryInTransaction(resourceKey, investigationId) {
        const whereInvestigation = investigationId === null
            ? ""
            : "AND l.investigation_id = :investigationId";
        const row = this.#db.prepare(`
            SELECT MIN(l.expires_at_ms) AS nearest
            FROM lease_allocations AS a
            JOIN leases AS l ON l.fencing_token = a.fencing_token
            WHERE a.resource_key = :resourceKey
              AND l.status = 'active'
              ${whereInvestigation}
        `).get({
            resourceKey,
            ...(investigationId === null ? {} : { investigationId }),
        });
        return row?.nearest === null || row?.nearest === undefined
            ? null
            : numberFromSql(row.nearest, `nearestExpiry:${resourceKey}`);
    }

    #reconcileAllocationInTransaction({
        fencingToken,
        resourceKey,
        reportedUnits,
        reconciliationId,
        source,
        nowMs,
    }) {
        const definition = this.#definitionsByKey.get(resourceKey);
        if (definition === undefined) {
            throw new InvalidArgumentError(
                "usage reconciliation names an unknown resource",
                { resourceKey },
            );
        }
        if (definition.resourceMode !== "consumable") {
            throw new InvalidArgumentError(
                "only consumable resources accept usage reconciliation",
                { resourceKey, resourceMode: definition.resourceMode },
            );
        }
        const existingAllocation = this.#db.prepare(`
            SELECT *
            FROM lease_allocations
            WHERE fencing_token = ? AND resource_key = ?
        `).get(fencingToken, resourceKey);
        if (existingAllocation === undefined) {
            this.#db.prepare(`
                INSERT INTO lease_allocations(
                    fencing_token, resource_key, reserved_units,
                    charged_units, reconciled_at_ms)
                VALUES(?, ?, 0, 0, NULL)
            `).run(fencingToken, resourceKey);
        }
        const existingReconciliation = this.#db.prepare(`
            SELECT *
            FROM usage_reconciliations
            WHERE fencing_token = ?
              AND resource_key = ?
              AND reconciliation_id = ?
        `).get(fencingToken, resourceKey, reconciliationId);
        if (existingReconciliation !== undefined) {
            if (Number(existingReconciliation.reported_units) !== reportedUnits
                || existingReconciliation.source !== source) {
                throw new CasConflictError(
                    "usage reconciliation id was reused with different content",
                    { fencingToken, resourceKey, reconciliationId },
                );
            }
            return Object.freeze({
                resourceKey,
                reportedUnits,
                chargedUnits: numberFromSql(
                    existingReconciliation.resulting_charged_units,
                    `reconciled:${resourceKey}`,
                ),
                deduplicated: true,
            });
        }
        const allocation = this.#db.prepare(`
            SELECT charged_units
            FROM lease_allocations
            WHERE fencing_token = ? AND resource_key = ?
        `).get(fencingToken, resourceKey);
        const chargedUnits = Math.max(
            numberFromSql(allocation.charged_units, `charged:${resourceKey}`),
            reportedUnits,
        );
        this.#db.prepare(`
            UPDATE lease_allocations
            SET charged_units = :chargedUnits,
                reconciled_at_ms = :reconciledAt
            WHERE fencing_token = :fencingToken
              AND resource_key = :resourceKey`).run({
            chargedUnits,
            reconciledAt: nowMs,
            fencingToken,
            resourceKey,
        });
        this.#db.prepare(`
            INSERT INTO usage_reconciliations(
                fencing_token, resource_key, reconciliation_id,
                reported_units, resulting_charged_units, source,
                reconciled_at_ms)
            VALUES(:fencingToken, :resourceKey, :reconciliationId,
                :reportedUnits, :chargedUnits, :source, :reconciledAt)`)
            .run({
                fencingToken,
                resourceKey,
                reconciliationId,
                reportedUnits,
                chargedUnits,
                source,
                reconciledAt: nowMs,
            });
        return Object.freeze({
            resourceKey,
            reportedUnits,
            chargedUnits,
            deduplicated: false,
        });
    }

    #usageSnapshotInTransaction(investigationId) {
        const rows = [];
        for (const definition of this.#definitions) {
            const usage = this.#resourceUsageInTransaction(
                definition.resourceKey,
                investigationId,
            );
            let limitUnits = definition.capacityUnits;
            if (investigationId !== null) {
                const limit = this.#db.prepare(`
                    SELECT limit_units
                    FROM investigation_limits
                    WHERE investigation_id = ? AND resource_key = ?
                `).get(investigationId, definition.resourceKey);
                if (limit === undefined) {
                    throw new SchemaIntegrityError(
                        "investigation is missing a resource limit",
                        {
                            investigationId,
                            resourceKey: definition.resourceKey,
                        },
                    );
                }
                limitUnits = numberFromSql(
                    limit.limit_units,
                    `limit:${definition.resourceKey}`,
                );
            }
            const totalUnits = usage.committedUnits + usage.heldUnits;
            if (!Number.isSafeInteger(totalUnits)) {
                throw new SchemaIntegrityError(
                    "resource usage exceeds safe integer range",
                    { resourceKey: definition.resourceKey },
                );
            }
            rows.push(Object.freeze({
                resourceKey: definition.resourceKey,
                resourceMode: definition.resourceMode,
                limitUnits,
                committedUnits: usage.committedUnits,
                heldUnits: usage.heldUnits,
                totalUnits,
                availableUnits: Math.max(0, limitUnits - totalUnits),
                overdrawnUnits: Math.max(0, totalUnits - limitUnits),
            }));
        }
        return rows;
    }

    #overrunsInTransaction(investigationId) {
        const global = this.#usageSnapshotInTransaction(null)
            .filter((row) => row.overdrawnUnits > 0)
            .map((row) => ({ ...row, scope: "global" }));
        const investigation = this.#usageSnapshotInTransaction(investigationId)
            .filter((row) => row.overdrawnUnits > 0)
            .map((row) => ({ ...row, scope: "investigation" }));
        return [...investigation, ...global].sort((left, right) =>
            left.resourceKey.localeCompare(right.resourceKey)
            || left.scope.localeCompare(right.scope));
    }

    #loadLeaseByToken(fencingToken) {
        const row = this.#db.prepare(
            "SELECT * FROM leases WHERE fencing_token = ?",
        ).get(fencingToken);
        if (row === undefined) {
            throw new NotFoundError(
                ERROR_CODES.LEASE_NOT_FOUND,
                "resource lease not found",
                { fencingToken },
            );
        }
        if (!LEASE_STATUSES.has(row.status)) {
            throw new SchemaIntegrityError(
                "resource lease has an unknown status",
                { fencingToken, status: row.status },
            );
        }
        const allocations = this.#db.prepare(`
            SELECT a.resource_key, d.resource_mode,
                   a.reserved_units, a.charged_units, a.reconciled_at_ms
            FROM lease_allocations AS a
            JOIN resource_definitions AS d
              ON d.resource_key = a.resource_key
            WHERE a.fencing_token = ?
            ORDER BY a.resource_key
        `).all(fencingToken).map((allocation) => Object.freeze({
            resourceKey: allocation.resource_key,
            resourceMode: allocation.resource_mode,
            reservedUnits: numberFromSql(
                allocation.reserved_units,
                `reserved:${allocation.resource_key}`,
            ),
            chargedUnits: numberFromSql(
                allocation.charged_units,
                `charged:${allocation.resource_key}`,
            ),
            reconciledAtMs: allocation.reconciled_at_ms === null
                ? null
                : numberFromSql(
                    allocation.reconciled_at_ms,
                    `reconciledAt:${allocation.resource_key}`,
                ),
        }));
        return Object.freeze({
            leaseId: row.lease_id,
            leaseNonce: row.lease_nonce,
            fencingToken: numberFromSql(row.fencing_token, "fencingToken"),
            investigationId: row.investigation_id,
            ownerId: row.owner_id,
            ownerProcessId: row.owner_process_id === null
                ? null
                : numberFromSql(row.owner_process_id, "ownerProcessId"),
            ownerProcessStartId: row.owner_process_start_id ?? null,
            supervisorGeneration: numberFromSql(
                row.supervisor_generation,
                "supervisorGeneration",
            ),
            runnerIncarnation: row.runner_incarnation,
            attemptId: row.attempt_id,
            logicalEffectId: row.logical_effect_id,
            requestFingerprint: row.request_fingerprint,
            status: row.status,
            acquiredAtMs: numberFromSql(row.acquired_at_ms, "acquiredAtMs"),
            heartbeatAtMs: numberFromSql(row.heartbeat_at_ms, "heartbeatAtMs"),
            expiresAtMs: numberFromSql(row.expires_at_ms, "expiresAtMs"),
            finalizedAtMs: row.finalized_at_ms === null
                ? null
                : numberFromSql(row.finalized_at_ms, "finalizedAtMs"),
            finalizationReason: row.finalization_reason ?? null,
            allocations: Object.freeze(allocations),
        });
    }
}
