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
import { verifyDatabaseIntegrity } from "./schema.mjs";
import { DatabaseSync } from "./sqlite.mjs";

const DEFAULT_BUSY_TIMEOUT_MS = 5_000;
const STORAGE_RESOURCE_KEY = "storage_bytes";
const LEASE_STATUSES = new Set(["active", "released", "reclaimed"]);
const RESOURCE_MODES = new Set(["concurrency", "consumable"]);
const INVESTIGATION_LIFECYCLE_STATES = new Set([
    "active",
    "archived",
    "tombstoned",
]);
const LIFECYCLE_OPERATION_KINDS = new Set(["archive", "delete"]);
const ARCHIVE_TRUST_LEVELS = new Set([
    "authenticated",
    "self-consistent",
]);
const ARCHIVE_INTEGRITY_STATUSES = new Set(["verified", "blocked"]);
const ARCHIVE_DIGEST_RE = /^sha256:[a-f0-9]{64}$/u;
const TAGGED_HASH_RE =
    /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const RAW_SHA256_RE = /^[a-f0-9]{64}$/u;
const RETENTION_RELATIVE_PATH_RE =
    /^(?!.*(?:^|\/)\.\.(?:\/|$))(?!\/)[A-Za-z0-9._@/-]+$/u;
const ARCHIVE_RELATIVE_PATH_RE =
    /^\.retention\/archives\/(?![^/]*\.\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;
const TOMBSTONE_RELATIVE_PATH_RE =
    /^\.retention\/tombstones\/(?![^/]*\.\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}\.json$/u;
const RECOVERY_OPERATION_STATES = new Set([
    "eligible",
    "running",
    "started",
    "waiting",
    "skipped",
    "blocked",
    "failed",
]);
const MAX_RECOVERY_DAEMON_LEASE_MS = 10 * 60_000;

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

function requireArchiveDigest(value, field = "archiveDigest") {
    if (typeof value !== "string" || !ARCHIVE_DIGEST_RE.test(value)) {
        throw new InvalidArgumentError(
            `${field} must be sha256:<64 lowercase hex>`,
            { field, value },
        );
    }
    return value;
}

function isRetentionRelativePath(value) {
    return typeof value === "string"
        && value.length >= 1
        && value.length <= 4096
        && !value.includes("\\")
        && RETENTION_RELATIVE_PATH_RE.test(value)
        && !value.split("/").some((segment) =>
            segment.length === 0 || segment === "." || segment === "..");
}

function requireRetentionRelativePath(value, field) {
    if (!isRetentionRelativePath(value)) {
        throw new InvalidArgumentError(
            `${field} must be a canonical relative POSIX retention path`,
            { field, value },
        );
    }
    return value;
}

function requireArchiveRelativePath(value, field = "archiveRelativePath") {
    requireRetentionRelativePath(value, field);
    if (!ARCHIVE_RELATIVE_PATH_RE.test(value)) {
        throw new InvalidArgumentError(
            `${field} must be a direct state-root archive retention path`,
            { field, value },
        );
    }
    return value;
}

function requireTombstoneRelativePath(
    value,
    field = "tombstoneRelativePath",
) {
    requireRetentionRelativePath(value, field);
    if (!TOMBSTONE_RELATIVE_PATH_RE.test(value)) {
        throw new InvalidArgumentError(
            `${field} must be a direct state-root tombstone retention path`,
            { field, value },
        );
    }
    return value;
}

function normalizeDomainHead(value, field = "domainHead") {
    const head = requirePlainObject(value, field);
    const keys = Object.keys(head).sort();
    if (keys.length !== 2 || keys[0] !== "eventHash" || keys[1] !== "seq") {
        throw new InvalidArgumentError(
            `${field} must contain exactly seq and eventHash`,
        );
    }
    const seq = requireSafeInteger(head.seq, `${field}.seq`);
    if ((seq === 0 && head.eventHash !== null)
        || (seq > 0
            && (typeof head.eventHash !== "string"
                || (!TAGGED_HASH_RE.test(head.eventHash)
                    && !RAW_SHA256_RE.test(head.eventHash))))) {
        throw new InvalidArgumentError(
            `${field}.eventHash is inconsistent with seq`,
            { seq, eventHash: head.eventHash },
        );
    }
    return Object.freeze({ seq, eventHash: head.eventHash });
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

export function readStoredResourceCatalogConfiguration({
    file,
    busyTimeoutMs = DEFAULT_BUSY_TIMEOUT_MS,
    denyRoots,
    env,
    integrityCheckAdapter = undefined,
} = {}) {
    requireSafeInteger(busyTimeoutMs, "busyTimeoutMs");
    const resolved = assertLocalDatabasePath(file, { denyRoots, env });
    let db;
    try {
        db = new DatabaseSync(resolved, { readOnly: true });
        configureResourceCatalogReadOnlyConnection(db, { busyTimeoutMs });
        verifyDatabaseIntegrity(db, { adapter: integrityCheckAdapter });
        const row = db.prepare(`
            SELECT config_json, config_fingerprint
            FROM catalog_config
            WHERE singleton_id = 1
        `).get();
        if (row === undefined) {
            throw new SchemaIntegrityError(
                "resource catalog singleton configuration is missing",
            );
        }
        let config;
        try {
            config = JSON.parse(row.config_json);
        } catch (error) {
            throw new SchemaIntegrityError(
                "resource catalog configuration is not valid JSON",
                { message: error?.message ?? null },
            );
        }
        const canonical = canonicalize(config);
        const fingerprint = documentFingerprint(
            RESOURCE_CATALOG_CONFIG_HASH_ALGORITHM,
            config,
        );
        if (canonical !== row.config_json
            || fingerprint !== row.config_fingerprint) {
            throw new SchemaIntegrityError(
                "resource catalog stored configuration failed integrity verification",
                {
                    expectedFingerprint: fingerprint,
                    storedFingerprint: row.config_fingerprint,
                },
            );
        }
        return Object.freeze({
            file: resolved,
            config: Object.freeze(config),
            configFingerprint: fingerprint,
        });
    } catch (error) {
        if (error instanceof CruciblePersistenceError) throw error;
        if (isSqliteError(error)) {
            throw new StorageError(
                `failed to read resource catalog configuration at ${resolved}: ${error.message}`,
                error,
            );
        }
        throw error;
    } finally {
        db?.close();
    }
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
    #isRecoveryOwnerAlive;
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
        isRecoveryOwnerAlive,
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
        this.#isRecoveryOwnerAlive = isRecoveryOwnerAlive;
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
            isRecoveryOwnerAlive = null,
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
        if (isRecoveryOwnerAlive !== null
            && typeof isRecoveryOwnerAlive !== "function") {
            throw new InvalidArgumentError(
                "isRecoveryOwnerAlive must be a synchronous function or null",
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
                isRecoveryOwnerAlive,
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
        const storageDefinition = this.#definitionsByKey.get(
            STORAGE_RESOURCE_KEY,
        );
        if (storageDefinition === undefined
            || storageDefinition.resourceMode !== "consumable") {
            throw new SchemaIntegrityError(
                "resource catalog requires a consumable storage_bytes definition",
            );
        }
        for (const investigation of this.#db.prepare(
            "SELECT * FROM investigations ORDER BY investigation_id",
        ).all()) {
            this.#assertInvestigationLimitsIntegrity(investigation);
            this.#assertInvestigationAuthorityIntegrity(investigation);
            const lifecycle =
                this.#assertInvestigationLifecycleIntegrity(investigation);
            const operation = this.#db.prepare(`
                SELECT *
                FROM lifecycle_operations
                WHERE investigation_id = ?
            `).get(investigation.investigation_id);
            const archive = this.#db.prepare(`
                SELECT *
                FROM investigation_archives
                WHERE investigation_id = ?
            `).get(investigation.investigation_id);
            if (operation !== undefined) {
                const parsed = this.#rowToLifecycleOperation(operation);
                const expectedState = parsed.operationKind === "archive"
                    ? "active"
                    : "archived";
                if (lifecycle.lifecycle_state !== expectedState) {
                    throw new SchemaIntegrityError(
                        "catalog lifecycle operation is inconsistent with lifecycle state",
                        {
                            investigationId:
                                investigation.investigation_id,
                            operationKind: parsed.operationKind,
                            lifecycleState: lifecycle.lifecycle_state,
                        },
                    );
                }
            }
            if (archive !== undefined) {
                this.#rowToArchive(archive);
                if (lifecycle.lifecycle_state !== "archived") {
                    throw new SchemaIntegrityError(
                        "catalog archive exists outside archived lifecycle state",
                        {
                            investigationId:
                                investigation.investigation_id,
                            lifecycleState: lifecycle.lifecycle_state,
                        },
                    );
                }
            }
        }
        for (const tombstone of this.#db.prepare(`
            SELECT *
            FROM investigation_tombstones
            ORDER BY investigation_id
        `).all()) {
            this.#rowToTombstone(tombstone);
            if (this.#db.prepare(`
                SELECT 1 AS present
                FROM investigations
                WHERE investigation_id = ?
            `).get(tombstone.investigation_id) !== undefined) {
                throw new SchemaIntegrityError(
                    "catalog contains both a live investigation and tombstone for one identity",
                    { investigationId: tombstone.investigation_id },
                );
            }
        }
        this.#verifyRecoveryCatalogIntegrity();
    }

    #verifyRecoveryCatalogIntegrity() {
        const authorityRows = this.#db.prepare(`
            SELECT *
            FROM recovery_daemon_authority
            ORDER BY singleton_id
        `).all();
        if (authorityRows.length > 1) {
            throw new SchemaIntegrityError(
                "resource catalog has multiple recovery daemon authorities",
            );
        }
        const activeHistory = this.#db.prepare(`
            SELECT *
            FROM recovery_daemon_incarnations
            WHERE retired_at_ms IS NULL
            ORDER BY daemon_generation
        `).all();
        if (authorityRows.length !== activeHistory.length
            || (authorityRows.length === 1
                && (authorityRows[0].daemon_incarnation
                    !== activeHistory[0].daemon_incarnation
                    || Number(authorityRows[0].daemon_generation)
                        !== Number(activeHistory[0].daemon_generation)
                    || authorityRows[0].lease_nonce
                        !== activeHistory[0].lease_nonce
                    || Number(authorityRows[0].owner_process_id)
                        !== Number(activeHistory[0].owner_process_id)
                    || authorityRows[0].owner_process_start_id
                        !== activeHistory[0].owner_process_start_id))) {
            throw new SchemaIntegrityError(
                "recovery daemon authority does not match incarnation history",
                {
                    authorityCount: authorityRows.length,
                    activeHistoryCount: activeHistory.length,
                },
            );
        }
        for (const row of this.#db.prepare(`
            SELECT o.*, d.daemon_generation AS incarnation_generation
            FROM recovery_operations AS o
            JOIN recovery_daemon_incarnations AS d
              ON d.daemon_incarnation = o.daemon_incarnation
            ORDER BY investigation_id
        `).all()) {
            if (!RECOVERY_OPERATION_STATES.has(row.operation_state)
                || typeof row.operation_code !== "string"
                || row.operation_code.length < 1
                || row.operation_code.length > 128
                || Number(row.daemon_generation)
                    !== Number(row.incarnation_generation)) {
                throw new SchemaIntegrityError(
                    "recovery operation state is invalid",
                    { investigationId: row.investigation_id },
                );
            }
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
            const tombstone = this.#db.prepare(`
                SELECT investigation_id, tombstone_digest
                FROM investigation_tombstones
                WHERE investigation_id = ?
            `).get(investigationId);
            if (tombstone !== undefined) {
                throw new FenceRejectedError(
                    "a durably tombstoned investigation identity cannot be registered again",
                    {
                        investigationId,
                        tombstoneDigest: tombstone.tombstone_digest,
                    },
                );
            }
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
                    investigation: this.getInvestigation(investigationId),
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
                INSERT INTO storage_usage(
                    investigation_id, actual_units, reconciled_at_ms)
                VALUES(?, 0, ?)
            `).run(investigationId, nowMs);
            this.#db.prepare(`
                INSERT INTO investigation_lifecycle(
                    investigation_id, lifecycle_state, updated_at_ms, reason_code)
                VALUES(?, 'active', ?, NULL)
            `).run(investigationId, nowMs);
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
            const tombstone = this.#db.prepare(`
                SELECT *
                FROM investigation_tombstones
                WHERE investigation_id = ?
            `).get(investigationId);
            return tombstone === undefined
                ? null
                : this.#rowToTombstone(tombstone);
        }
        const limits = this.#assertInvestigationLimitsIntegrity(row);
        this.#assertInvestigationAuthorityIntegrity(row);
        const lifecycle = this.#assertInvestigationLifecycleIntegrity(row);
        const operation = this.#db.prepare(`
            SELECT *
            FROM lifecycle_operations
            WHERE investigation_id = ?
        `).get(investigationId);
        const archive = this.#db.prepare(`
            SELECT *
            FROM investigation_archives
            WHERE investigation_id = ?
        `).get(investigationId);
        return Object.freeze({
            ...this.#rowToInvestigation(row),
            limits: Object.freeze(limits),
            lifecycleState: lifecycle.lifecycle_state,
            lifecycleUpdatedAtMs: numberFromSql(
                lifecycle.updated_at_ms,
                "lifecycleUpdatedAtMs",
            ),
            lifecycleReasonCode: lifecycle.reason_code ?? null,
            lifecycleOperation: operation === undefined
                ? null
                : this.#rowToLifecycleOperation(operation),
            archive: archive === undefined
                ? null
                : this.#rowToArchive(archive),
            tombstone: null,
        });
    }

    listInvestigations({
        lifecycleState = null,
        excludeFenced = false,
        afterInvestigationId = null,
        limit = null,
    } = {}) {
        if (lifecycleState !== null
            && !INVESTIGATION_LIFECYCLE_STATES.has(lifecycleState)) {
            throw new InvalidArgumentError(
                "lifecycleState is invalid",
                { lifecycleState },
            );
        }
        if (typeof excludeFenced !== "boolean") {
            throw new InvalidArgumentError("excludeFenced must be boolean");
        }
        if (afterInvestigationId !== null) {
            requireString(
                afterInvestigationId,
                "afterInvestigationId",
                128,
            );
        }
        if (limit !== null) {
            requireSafeInteger(limit, "limit", {
                minimum: 1,
                maximum: 1000,
            });
        }
        const ids = this.#db.prepare(`
            SELECT investigation_id
            FROM (
                SELECT i.investigation_id AS investigation_id,
                       l.lifecycle_state AS lifecycle_state,
                       CASE WHEN o.investigation_id IS NULL
                            THEN 0 ELSE 1 END AS lifecycle_fenced
                FROM investigations AS i
                JOIN investigation_lifecycle AS l
                  ON l.investigation_id = i.investigation_id
                LEFT JOIN lifecycle_operations AS o
                  ON o.investigation_id = i.investigation_id

                UNION ALL

                SELECT investigation_id,
                       'tombstoned' AS lifecycle_state,
                       0 AS lifecycle_fenced
                FROM investigation_tombstones
            )
            WHERE (:lifecycleState IS NULL
                   OR lifecycle_state = :lifecycleState)
              AND (:excludeFenced = 0 OR lifecycle_fenced = 0)
              AND (:afterId IS NULL OR investigation_id > :afterId)
            ORDER BY investigation_id
            LIMIT :limit
        `).all({
            lifecycleState,
            excludeFenced: excludeFenced ? 1 : 0,
            afterId: afterInvestigationId,
            limit: limit ?? -1,
        });
        return Object.freeze(ids.map((entry) =>
            this.getInvestigation(entry.investigation_id)));
    }

    setInvestigationLifecycle({
        investigationId,
        lifecycleState,
        reasonCode = null,
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        if (!INVESTIGATION_LIFECYCLE_STATES.has(lifecycleState)) {
            throw new InvalidArgumentError(
                "lifecycleState is invalid",
                { lifecycleState },
            );
        }
        const normalizedReason = reasonCode === null
            ? null
            : requireString(reasonCode, "reasonCode", 128);
        return this.#tx(() => {
            const investigation =
                this.#requireInvestigationInTransaction(investigationId);
            const current =
                this.#assertInvestigationLifecycleIntegrity(investigation);
            if (current.lifecycle_state === "tombstoned"
                && lifecycleState !== "tombstoned") {
                throw new FenceRejectedError(
                    "a tombstoned investigation cannot be reactivated",
                    { investigationId, lifecycleState },
                );
            }
            if (current.lifecycle_state === "archived"
                && lifecycleState === "active"
                && this.#db.prepare(`
                    SELECT 1 AS present
                    FROM investigation_archives
                    WHERE investigation_id = ?
                `).get(investigationId) !== undefined) {
                throw new FenceRejectedError(
                    "a verified archived investigation cannot be reactivated",
                    { investigationId },
                );
            }
            if (lifecycleState !== "active") {
                const activeLeaseCount = Number(this.#db.prepare(`
                    SELECT COUNT(*) AS count
                    FROM leases
                    WHERE investigation_id = ? AND status = 'active'
                `).get(investigationId)?.count ?? 0);
                if (activeLeaseCount !== 0) {
                    throw new FenceRejectedError(
                        "an investigation with active resource leases cannot be archived or tombstoned",
                        { investigationId, activeLeaseCount },
                    );
                }
            }
            if (current.lifecycle_state === lifecycleState
                && current.reason_code === normalizedReason) {
                return Object.freeze({
                    changed: false,
                    investigation: this.getInvestigation(investigationId),
                });
            }
            const nowMs = this.#timestamp();
            this.#db.prepare(`
                UPDATE investigation_lifecycle
                SET lifecycle_state = ?, updated_at_ms = ?, reason_code = ?
                WHERE investigation_id = ?
            `).run(
                lifecycleState,
                nowMs,
                normalizedReason,
                investigationId,
            );
            return Object.freeze({
                changed: true,
                investigation: this.getInvestigation(investigationId),
            });
        });
    }

    beginLifecycleOperation({
        investigationId,
        operationKind,
        operationToken,
        ownerProcessId,
        ownerProcessStartId,
        archiveRelativePath = null,
        expectedArchiveDigest = null,
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        if (!LIFECYCLE_OPERATION_KINDS.has(operationKind)) {
            throw new InvalidArgumentError(
                "operationKind must be archive or delete",
                { operationKind },
            );
        }
        requireString(operationToken, "operationToken", 256);
        const processId = requireSafeInteger(
            ownerProcessId,
            "ownerProcessId",
            { minimum: 1 },
        );
        const processStartId = requireString(
            ownerProcessStartId,
            "ownerProcessStartId",
            256,
        );
        const expectedDigest = expectedArchiveDigest === null
            ? null
            : requireArchiveDigest(
                expectedArchiveDigest,
                "expectedArchiveDigest",
            );
        if ((operationKind === "delete") !== (expectedDigest !== null)) {
            throw new InvalidArgumentError(
                "delete lifecycle operations require expectedArchiveDigest and archive operations forbid it",
                { operationKind },
            );
        }
        const reservedArchivePath = archiveRelativePath === null
            ? null
            : requireArchiveRelativePath(
                archiveRelativePath,
                "archiveRelativePath",
            );
        if ((operationKind === "archive")
            !== (reservedArchivePath !== null)) {
            throw new InvalidArgumentError(
                "archive lifecycle operations require archiveRelativePath and delete operations forbid it",
                { operationKind },
            );
        }
        return this.#tx(() => {
            if (this.#db.prepare(`
                SELECT 1 AS present
                FROM investigation_tombstones
                WHERE investigation_id = ?
            `).get(investigationId) !== undefined) {
                throw new FenceRejectedError(
                    "a tombstoned investigation has no live lifecycle operation",
                    { investigationId, operationKind },
                );
            }
            const investigation =
                this.#requireInvestigationInTransaction(investigationId);
            const lifecycle =
                this.#assertInvestigationLifecycleIntegrity(investigation);
            const requiredState = operationKind === "archive"
                ? "active"
                : "archived";
            if (lifecycle.lifecycle_state !== requiredState) {
                throw new FenceRejectedError(
                    `${operationKind} requires lifecycle state ${requiredState}`,
                    {
                        investigationId,
                        lifecycleState: lifecycle.lifecycle_state,
                    },
                );
            }
            const existing = this.#db.prepare(`
                SELECT *
                FROM lifecycle_operations
                WHERE investigation_id = ?
            `).get(investigationId);
            if (existing !== undefined) {
                if (existing.operation_kind === operationKind
                    && existing.operation_token === operationToken
                    && Number(existing.owner_process_id) === processId
                    && existing.owner_process_start_id === processStartId
                    && (existing.archive_relpath ?? null)
                        === reservedArchivePath
                    && (existing.expected_archive_digest ?? null)
                        === expectedDigest) {
                    return Object.freeze({
                        created: false,
                        operation:
                            this.#rowToLifecycleOperation(existing),
                    });
                }
                throw new FenceRejectedError(
                    "another lifecycle operation already fences this investigation",
                    {
                        investigationId,
                        operationKind: existing.operation_kind,
                    },
                );
            }
            const activeLeaseCount = Number(this.#db.prepare(`
                SELECT COUNT(*) AS count
                FROM leases
                WHERE investigation_id = ? AND status = 'active'
            `).get(investigationId)?.count ?? 0);
            if (activeLeaseCount !== 0) {
                throw new FenceRejectedError(
                    "lifecycle operation requires zero active resource leases",
                    { investigationId, activeLeaseCount },
                );
            }
            if (operationKind === "delete") {
                const archive = this.#db.prepare(`
                    SELECT archive_digest
                    FROM investigation_archives
                    WHERE investigation_id = ?
                `).get(investigationId);
                if (archive === undefined) {
                    throw new SchemaIntegrityError(
                        "archived lifecycle state has no verified archive record",
                        { investigationId },
                    );
                }
                if (archive.archive_digest !== expectedDigest) {
                    throw new FenceRejectedError(
                        "expected archive digest does not match the catalog",
                        {
                            investigationId,
                            expectedArchiveDigest: expectedDigest,
                            actualArchiveDigest: archive.archive_digest,
                        },
                    );
                }
            } else {
                const operationOwner = this.#db.prepare(`
                    SELECT investigation_id
                    FROM lifecycle_operations
                    WHERE archive_relpath = ?
                `).get(reservedArchivePath);
                if (operationOwner !== undefined
                    && operationOwner.investigation_id
                        !== investigationId) {
                    throw new FenceRejectedError(
                        "archive retention path is reserved by another lifecycle operation",
                        {
                            investigationId,
                            archiveRelativePath:
                                reservedArchivePath,
                            ownerInvestigationId:
                                operationOwner.investigation_id,
                        },
                    );
                }
                const archiveOwner = this.#db.prepare(`
                    SELECT investigation_id
                    FROM investigation_archives
                    WHERE archive_relpath = ?
                `).get(reservedArchivePath);
                if (archiveOwner !== undefined
                    && archiveOwner.investigation_id
                        !== investigationId) {
                    throw new FenceRejectedError(
                        "archive retention path is already owned by another investigation",
                        {
                            investigationId,
                            archiveRelativePath:
                                reservedArchivePath,
                            ownerInvestigationId:
                                archiveOwner.investigation_id,
                        },
                    );
                }
            }
            const startedAtMs = this.#timestamp();
            this.#db.prepare(`
                INSERT INTO lifecycle_operations(
                    investigation_id, operation_kind, operation_token,
                    owner_process_id, owner_process_start_id,
                    archive_relpath, expected_archive_digest, started_at_ms)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                investigationId,
                operationKind,
                operationToken,
                processId,
                processStartId,
                reservedArchivePath,
                expectedDigest,
                startedAtMs,
            );
            return Object.freeze({
                created: true,
                operation: this.#rowToLifecycleOperation(
                    this.#db.prepare(`
                        SELECT *
                        FROM lifecycle_operations
                        WHERE investigation_id = ?
                    `).get(investigationId),
                ),
            });
        });
    }

    abortLifecycleOperation({
        investigationId,
        operationToken,
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        requireString(operationToken, "operationToken", 256);
        return this.#tx(() => {
            const existing = this.#db.prepare(`
                SELECT *
                FROM lifecycle_operations
                WHERE investigation_id = ?
            `).get(investigationId);
            if (existing === undefined) {
                return Object.freeze({ changed: false });
            }
            if (existing.operation_token !== operationToken) {
                throw new FenceRejectedError(
                    "lifecycle operation token is stale",
                    { investigationId },
                );
            }
            this.#db.prepare(`
                DELETE FROM lifecycle_operations
                WHERE investigation_id = ? AND operation_token = ?
            `).run(investigationId, operationToken);
            return Object.freeze({ changed: true });
        });
    }

    commitArchive({
        investigationId,
        operationToken,
        archiveRelativePath,
        archiveDigest,
        trustLevel,
        domainVersion,
        terminalAvailable,
        integrityStatus = "verified",
        sizeBytes,
        domainHead,
        reasonCode = "operator_archive",
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        requireString(operationToken, "operationToken", 256);
        const relativePath = requireArchiveRelativePath(
            archiveRelativePath,
            "archiveRelativePath",
        );
        const digest = requireArchiveDigest(archiveDigest);
        if (!ARCHIVE_TRUST_LEVELS.has(trustLevel)) {
            throw new InvalidArgumentError(
                "trustLevel is invalid",
                { trustLevel },
            );
        }
        const version = requireSafeInteger(
            domainVersion,
            "domainVersion",
            { minimum: 1 },
        );
        if (typeof terminalAvailable !== "boolean") {
            throw new InvalidArgumentError(
                "terminalAvailable must be boolean",
            );
        }
        if (!ARCHIVE_INTEGRITY_STATUSES.has(integrityStatus)) {
            throw new InvalidArgumentError(
                "integrityStatus is invalid",
                { integrityStatus },
            );
        }
        const size = requireSafeInteger(sizeBytes, "sizeBytes");
        const head = normalizeDomainHead(domainHead);
        const reason = requireString(reasonCode, "reasonCode", 128);
        return this.#tx(() => {
            const investigation =
                this.#requireInvestigationInTransaction(investigationId);
            const lifecycle =
                this.#assertInvestigationLifecycleIntegrity(investigation);
            const operation = this.#db.prepare(`
                SELECT *
                FROM lifecycle_operations
                WHERE investigation_id = ?
            `).get(investigationId);
            if (lifecycle.lifecycle_state !== "active"
                || operation === undefined
                || operation.operation_kind !== "archive"
                || operation.operation_token !== operationToken
                || operation.archive_relpath !== relativePath) {
                throw new FenceRejectedError(
                    "archive publication lost its catalog fence",
                    { investigationId },
                );
            }
            const activeLeaseCount = Number(this.#db.prepare(`
                SELECT COUNT(*) AS count
                FROM leases
                WHERE investigation_id = ? AND status = 'active'
            `).get(investigationId)?.count ?? 0);
            if (activeLeaseCount !== 0) {
                throw new FenceRejectedError(
                    "archive publication requires zero active resource leases",
                    { investigationId, activeLeaseCount },
                );
            }
            const archivedAtMs = this.#timestamp();
            this.#db.prepare(`
                INSERT INTO investigation_archives(
                    investigation_id, archive_relpath, archive_digest,
                    trust_level, domain_version, terminal_available,
                    integrity_status, size_bytes, domain_head_seq,
                    domain_head_hash, archived_at_ms)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                investigationId,
                relativePath,
                digest,
                trustLevel,
                version,
                terminalAvailable ? 1 : 0,
                integrityStatus,
                size,
                head.seq,
                head.eventHash,
                archivedAtMs,
            );
            this.#db.prepare(`
                UPDATE investigation_lifecycle
                SET lifecycle_state = 'archived',
                    updated_at_ms = ?,
                    reason_code = ?
                WHERE investigation_id = ?
            `).run(archivedAtMs, reason, investigationId);
            const storageUpdated = this.#db.prepare(`
                UPDATE storage_usage
                SET actual_units = ?, reconciled_at_ms = ?
                WHERE investigation_id = ?
            `).run(size, archivedAtMs, investigationId);
            if (Number(storageUpdated.changes) !== 1) {
                throw new SchemaIntegrityError(
                    "archive publication could not reconcile retained storage",
                    { investigationId },
                );
            }
            this.#db.prepare(`
                DELETE FROM lifecycle_operations
                WHERE investigation_id = ? AND operation_token = ?
            `).run(investigationId, operationToken);
            return Object.freeze({
                changed: true,
                investigation: this.getInvestigation(investigationId),
            });
        });
    }

    commitDelete({
        investigationId,
        operationToken,
        expectedArchiveDigest,
        tombstoneRelativePath,
        tombstoneDigest,
        signingKeyFingerprint,
        signature,
        tombstoneSizeBytes,
        deletedAtMs,
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        requireString(operationToken, "operationToken", 256);
        const expectedDigest = requireArchiveDigest(
            expectedArchiveDigest,
            "expectedArchiveDigest",
        );
        const relativePath = requireTombstoneRelativePath(
            tombstoneRelativePath,
            "tombstoneRelativePath",
        );
        const durableDigest = requireArchiveDigest(
            tombstoneDigest,
            "tombstoneDigest",
        );
        requireString(
            signingKeyFingerprint,
            "signingKeyFingerprint",
            256,
        );
        requireString(signature, "signature", 4096);
        const sizeBytes = requireSafeInteger(
            tombstoneSizeBytes,
            "tombstoneSizeBytes",
            { minimum: 1 },
        );
        const deleted = requireSafeInteger(
            deletedAtMs,
            "deletedAtMs",
        );
        return this.#tx(() => {
            const investigation =
                this.#requireInvestigationInTransaction(investigationId);
            const lifecycle =
                this.#assertInvestigationLifecycleIntegrity(investigation);
            const operation = this.#db.prepare(`
                SELECT *
                FROM lifecycle_operations
                WHERE investigation_id = ?
            `).get(investigationId);
            const archive = this.#db.prepare(`
                SELECT *
                FROM investigation_archives
                WHERE investigation_id = ?
            `).get(investigationId);
            if (lifecycle.lifecycle_state !== "archived"
                || operation === undefined
                || operation.operation_kind !== "delete"
                || operation.operation_token !== operationToken
                || operation.expected_archive_digest !== expectedDigest
                || archive === undefined
                || archive.archive_digest !== expectedDigest) {
                throw new FenceRejectedError(
                    "delete publication lost its exact archived catalog fence",
                    { investigationId },
                );
            }
            const activeLeaseCount = Number(this.#db.prepare(`
                SELECT COUNT(*) AS count
                FROM leases
                WHERE investigation_id = ? AND status = 'active'
            `).get(investigationId)?.count ?? 0);
            if (activeLeaseCount !== 0) {
                throw new FenceRejectedError(
                    "delete requires zero active resource leases",
                    { investigationId, activeLeaseCount },
                );
            }
            const createdAtMs = numberFromSql(
                investigation.registered_at_ms,
                "registeredAtMs",
            );
            if (deleted < createdAtMs) {
                throw new InvalidArgumentError(
                    "deletedAtMs predates investigation creation",
                    { deletedAtMs: deleted, createdAtMs },
                );
            }
            this.#db.prepare(`
                INSERT INTO investigation_tombstones(
                    investigation_id, created_at_ms, deleted_at_ms,
                    domain_version, archive_digest, tombstone_relpath,
                    tombstone_digest, signing_key_fingerprint, signature,
                    size_bytes, integrity_status, domain_head_seq,
                    domain_head_hash)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?)
            `).run(
                investigationId,
                createdAtMs,
                deleted,
                archive.domain_version,
                archive.archive_digest,
                relativePath,
                durableDigest,
                signingKeyFingerprint,
                signature,
                sizeBytes,
                archive.domain_head_seq,
                archive.domain_head_hash,
            );
            this.#db.prepare(`
                DELETE FROM usage_reconciliations
                WHERE fencing_token IN (
                    SELECT fencing_token FROM leases
                    WHERE investigation_id = ?
                )
            `).run(investigationId);
            this.#db.prepare(`
                DELETE FROM lease_allocations
                WHERE fencing_token IN (
                    SELECT fencing_token FROM leases
                    WHERE investigation_id = ?
                )
            `).run(investigationId);
            this.#db.prepare(
                "DELETE FROM leases WHERE investigation_id = ?",
            ).run(investigationId);
            for (const table of [
                "recovery_operations",
                "storage_reconciliations",
                "storage_usage",
                "investigation_limits",
                "authority_incarnations",
                "investigation_archives",
                "lifecycle_operations",
                "investigation_lifecycle",
            ]) {
                this.#db.prepare(
                    `DELETE FROM ${table} WHERE investigation_id = ?`,
                ).run(investigationId);
            }
            this.#db.prepare(
                "DELETE FROM investigations WHERE investigation_id = ?",
            ).run(investigationId);
            return Object.freeze({
                changed: true,
                investigation: this.getInvestigation(investigationId),
            });
        });
    }

    acquireRecoveryDaemonLease({
        daemonIncarnation,
        leaseNonce,
        ownerProcessId,
        ownerProcessStartId,
        ttlMs,
    } = {}) {
        requireString(daemonIncarnation, "daemonIncarnation", 256);
        requireString(leaseNonce, "leaseNonce", 256);
        const processId = requireSafeInteger(
            ownerProcessId,
            "ownerProcessId",
            { minimum: 1 },
        );
        const processStartId = requireString(
            ownerProcessStartId,
            "ownerProcessStartId",
            256,
        );
        const leaseTtlMs = requireSafeInteger(ttlMs, "ttlMs", {
            minimum: 1,
            maximum: MAX_RECOVERY_DAEMON_LEASE_MS,
        });
        return this.#tx(() => {
            const nowMs = this.#timestamp();
            const current = this.#db.prepare(`
                SELECT *
                FROM recovery_daemon_authority
                WHERE singleton_id = 1
            `).get();
            if (current !== undefined) {
                let retirementReason = null;
                if (Number(current.expires_at_ms) <= nowMs) {
                    retirementReason = "expired";
                } else if (this.#isRecoveryOwnerAlive !== null) {
                    const alive = this.#isRecoveryOwnerAlive(Object.freeze({
                        kind: "recovery-daemon",
                        processId: numberFromSql(
                            current.owner_process_id,
                            "recoveryDaemon.ownerProcessId",
                        ),
                        processStartId: current.owner_process_start_id,
                        daemonGeneration: numberFromSql(
                            current.daemon_generation,
                            "recoveryDaemon.daemonGeneration",
                        ),
                        daemonIncarnation: current.daemon_incarnation,
                    }));
                    if (typeof alive !== "boolean") {
                        throw new InvalidArgumentError(
                            "isRecoveryOwnerAlive must return a boolean synchronously",
                        );
                    }
                    if (!alive) retirementReason = "owner_dead";
                }
                if (retirementReason === null) {
                    return Object.freeze({
                        acquired: false,
                        reason: "held",
                        lease: this.#rowToRecoveryDaemonLease(current),
                    });
                }
                this.#retireRecoveryDaemonInTransaction(
                    current,
                    nowMs,
                    retirementReason,
                );
            }

            const previousGeneration = numberFromSql(
                this.#db.prepare(`
                    SELECT COALESCE(MAX(daemon_generation), 0) AS generation
                    FROM recovery_daemon_incarnations
                `).get()?.generation ?? 0,
                "recoveryDaemon.previousGeneration",
            );
            if (previousGeneration >= Number.MAX_SAFE_INTEGER) {
                throw new SchemaIntegrityError(
                    "recovery daemon generation exhausted the safe integer range",
                );
            }
            const daemonGeneration = previousGeneration + 1;
            const existingIncarnation = this.#db.prepare(`
                SELECT daemon_generation
                FROM recovery_daemon_incarnations
                WHERE daemon_incarnation = ?
            `).get(daemonIncarnation);
            if (existingIncarnation !== undefined) {
                throw new FenceRejectedError(
                    "recovery daemon incarnation has already been used",
                    {
                        daemonIncarnation,
                        daemonGeneration:
                            Number(existingIncarnation.daemon_generation),
                    },
                );
            }
            const expiresAtMs = nowMs + leaseTtlMs;
            if (!Number.isSafeInteger(expiresAtMs)) {
                throw new InvalidArgumentError(
                    "recovery daemon lease expiry exceeds safe integer range",
                );
            }
            this.#db.prepare(`
                INSERT INTO recovery_daemon_incarnations(
                    daemon_incarnation, daemon_generation, lease_nonce,
                    owner_process_id, owner_process_start_id,
                    claimed_at_ms, retired_at_ms, retirement_reason)
                VALUES(?, ?, ?, ?, ?, ?, NULL, NULL)
            `).run(
                daemonIncarnation,
                daemonGeneration,
                leaseNonce,
                processId,
                processStartId,
                nowMs,
            );
            this.#db.prepare(`
                INSERT INTO recovery_daemon_authority(
                    singleton_id, daemon_generation, daemon_incarnation,
                    lease_nonce, owner_process_id, owner_process_start_id,
                    heartbeat_at_ms, expires_at_ms)
                VALUES(1, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                daemonGeneration,
                daemonIncarnation,
                leaseNonce,
                processId,
                processStartId,
                nowMs,
                expiresAtMs,
            );
            return Object.freeze({
                acquired: true,
                reason: current === undefined ? "created" : "reclaimed",
                lease: this.getRecoveryDaemonLease(),
            });
        });
    }

    getRecoveryDaemonLease() {
        const row = this.#db.prepare(`
            SELECT *
            FROM recovery_daemon_authority
            WHERE singleton_id = 1
        `).get();
        return row === undefined
            ? null
            : this.#rowToRecoveryDaemonLease(row);
    }

    renewRecoveryDaemonLease({
        lease,
        ttlMs,
    } = {}) {
        const credentials = this.#normalizeRecoveryDaemonCredentials(lease);
        const leaseTtlMs = requireSafeInteger(ttlMs, "ttlMs", {
            minimum: 1,
            maximum: MAX_RECOVERY_DAEMON_LEASE_MS,
        });
        return this.#tx(() => {
            const nowMs = this.#timestamp();
            const current = this.#assertCurrentRecoveryDaemonInTransaction(
                credentials,
                nowMs,
            );
            const expiresAtMs = nowMs + leaseTtlMs;
            if (!Number.isSafeInteger(expiresAtMs)) {
                throw new InvalidArgumentError(
                    "recovery daemon lease expiry exceeds safe integer range",
                );
            }
            this.#db.prepare(`
                UPDATE recovery_daemon_authority
                SET heartbeat_at_ms = ?, expires_at_ms = ?
                WHERE singleton_id = 1
            `).run(nowMs, expiresAtMs);
            return Object.freeze({
                ...this.#rowToRecoveryDaemonLease(current),
                heartbeatAtMs: nowMs,
                expiresAtMs,
            });
        });
    }

    releaseRecoveryDaemonLease({
        lease,
        reason = "released",
    } = {}) {
        const credentials = this.#normalizeRecoveryDaemonCredentials(lease);
        const retirementReason = requireString(reason, "reason", 128);
        return this.#tx(() => {
            const nowMs = this.#timestamp();
            const current = this.#assertCurrentRecoveryDaemonInTransaction(
                credentials,
                nowMs,
                { allowExpired: true },
            );
            this.#retireRecoveryDaemonInTransaction(
                current,
                nowMs,
                retirementReason,
            );
            return Object.freeze({
                released: true,
                lease: this.#rowToRecoveryDaemonLease(current),
                reason: retirementReason,
                retiredAtMs: nowMs,
            });
        });
    }

    recordRecoveryOperation({
        lease,
        investigationId,
        state,
        code,
        supervisorGeneration = null,
        runnerIncarnation = null,
    } = {}) {
        const credentials = this.#normalizeRecoveryDaemonCredentials(lease);
        requireString(investigationId, "investigationId", 128);
        if (!RECOVERY_OPERATION_STATES.has(state)) {
            throw new InvalidArgumentError(
                "recovery operation state is invalid",
                { state },
            );
        }
        const operationCode = requireString(code, "code", 128);
        const hasSupervisorGeneration = supervisorGeneration !== null;
        const hasRunnerIncarnation = runnerIncarnation !== null;
        if (hasSupervisorGeneration !== hasRunnerIncarnation) {
            throw new InvalidArgumentError(
                "supervisorGeneration and runnerIncarnation must be provided together",
            );
        }
        const normalizedGeneration = hasSupervisorGeneration
            ? requireSafeInteger(
                supervisorGeneration,
                "supervisorGeneration",
                { minimum: 1 },
            )
            : null;
        const normalizedIncarnation = hasRunnerIncarnation
            ? requireString(
                runnerIncarnation,
                "runnerIncarnation",
                256,
            )
            : null;
        return this.#tx(() => {
            const nowMs = this.#timestamp();
            this.#assertCurrentRecoveryDaemonInTransaction(
                credentials,
                nowMs,
            );
            this.#requireInvestigationInTransaction(investigationId);
            this.#db.prepare(`
                INSERT INTO recovery_operations(
                    investigation_id, daemon_generation, daemon_incarnation,
                    operation_state, operation_code, supervisor_generation,
                    runner_incarnation, attempt_count, updated_at_ms)
                VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(investigation_id) DO UPDATE SET
                    daemon_generation = excluded.daemon_generation,
                    daemon_incarnation = excluded.daemon_incarnation,
                    operation_state = excluded.operation_state,
                    operation_code = excluded.operation_code,
                    supervisor_generation = excluded.supervisor_generation,
                    runner_incarnation = excluded.runner_incarnation,
                    attempt_count = recovery_operations.attempt_count + 1,
                    updated_at_ms = excluded.updated_at_ms
            `).run(
                investigationId,
                credentials.daemonGeneration,
                credentials.daemonIncarnation,
                state,
                operationCode,
                normalizedGeneration,
                normalizedIncarnation,
                nowMs,
            );
            return this.getRecoveryOperation(investigationId);
        });
    }

    getRecoveryOperation(investigationId) {
        requireString(investigationId, "investigationId", 128);
        const row = this.#db.prepare(`
            SELECT *
            FROM recovery_operations
            WHERE investigation_id = ?
        `).get(investigationId);
        return row === undefined
            ? null
            : this.#rowToRecoveryOperation(row);
    }

    listRecoveryOperations() {
        return Object.freeze(this.#db.prepare(`
            SELECT *
            FROM recovery_operations
            ORDER BY investigation_id
        `).all().map((row) => this.#rowToRecoveryOperation(row)));
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

    #rowToLifecycleOperation(row) {
        if (row === undefined
            || !LIFECYCLE_OPERATION_KINDS.has(row.operation_kind)
            || typeof row.operation_token !== "string"
            || row.operation_token.length < 1
            || row.operation_token.length > 256
            || !Number.isSafeInteger(Number(row.owner_process_id))
            || Number(row.owner_process_id) < 1
            || typeof row.owner_process_start_id !== "string"
            || row.owner_process_start_id.length < 1
            || row.owner_process_start_id.length > 256
            || (row.operation_kind === "archive"
                ? !ARCHIVE_RELATIVE_PATH_RE.test(
                    row.archive_relpath ?? "",
                )
                : row.archive_relpath !== null)
            || (row.operation_kind === "delete"
                ? !ARCHIVE_DIGEST_RE.test(
                    row.expected_archive_digest ?? "",
                )
                : row.expected_archive_digest !== null)) {
            throw new SchemaIntegrityError(
                "catalog lifecycle operation is invalid",
                { investigationId: row?.investigation_id ?? null },
            );
        }
        return Object.freeze({
            investigationId: row.investigation_id,
            operationKind: row.operation_kind,
            operationToken: row.operation_token,
            ownerProcessId: Number(row.owner_process_id),
            ownerProcessStartId: row.owner_process_start_id,
            archiveRelativePath: row.archive_relpath ?? null,
            expectedArchiveDigest:
                row.expected_archive_digest ?? null,
            startedAtMs: numberFromSql(
                row.started_at_ms,
                "lifecycleOperation.startedAtMs",
            ),
        });
    }

    #rowToArchive(row) {
        if (row === undefined
            || !ARCHIVE_TRUST_LEVELS.has(row.trust_level)
            || !ARCHIVE_INTEGRITY_STATUSES.has(row.integrity_status)
            || !ARCHIVE_DIGEST_RE.test(row.archive_digest ?? "")
            || !ARCHIVE_RELATIVE_PATH_RE.test(
                row.archive_relpath ?? "",
            )
            || ![0, 1].includes(Number(row.terminal_available))) {
            throw new SchemaIntegrityError(
                "catalog archive record is invalid",
                { investigationId: row?.investigation_id ?? null },
            );
        }
        const head = normalizeDomainHead({
            seq: numberFromSql(
                row.domain_head_seq,
                "archive.domainHead.seq",
            ),
            eventHash: row.domain_head_hash ?? null,
        }, "archive.domainHead");
        return Object.freeze({
            investigationId: row.investigation_id,
            relativePath: row.archive_relpath,
            digest: row.archive_digest,
            trustLevel: row.trust_level,
            domainVersion: requireSafeInteger(
                Number(row.domain_version),
                "archive.domainVersion",
                { minimum: 1 },
            ),
            terminalAvailable: Number(row.terminal_available) === 1,
            integrityStatus: row.integrity_status,
            sizeBytes: numberFromSql(
                row.size_bytes,
                "archive.sizeBytes",
            ),
            domainHead: head,
            archivedAtMs: numberFromSql(
                row.archived_at_ms,
                "archive.archivedAtMs",
            ),
        });
    }

    #rowToTombstone(row) {
        if (row === undefined
            || !ARCHIVE_DIGEST_RE.test(row.archive_digest ?? "")
            || !ARCHIVE_DIGEST_RE.test(row.tombstone_digest ?? "")
            || row.integrity_status !== "verified"
            || !TOMBSTONE_RELATIVE_PATH_RE.test(
                row.tombstone_relpath ?? "",
            )
            || typeof row.signing_key_fingerprint !== "string"
            || row.signing_key_fingerprint.length < 1
            || typeof row.signature !== "string"
            || row.signature.length < 1) {
            throw new SchemaIntegrityError(
                "catalog tombstone record is invalid",
                { investigationId: row?.investigation_id ?? null },
            );
        }
        const createdAtMs = numberFromSql(
            row.created_at_ms,
            "tombstone.createdAtMs",
        );
        const deletedAtMs = numberFromSql(
            row.deleted_at_ms,
            "tombstone.deletedAtMs",
        );
        if (deletedAtMs < createdAtMs) {
            throw new SchemaIntegrityError(
                "catalog tombstone predates investigation creation",
                { investigationId: row.investigation_id },
            );
        }
        const tombstone = Object.freeze({
            relativePath: row.tombstone_relpath,
            digest: row.tombstone_digest,
            signingKeyFingerprint: row.signing_key_fingerprint,
            signature: row.signature,
            archiveDigest: row.archive_digest,
            domainVersion: requireSafeInteger(
                Number(row.domain_version),
                "tombstone.domainVersion",
                { minimum: 1 },
            ),
            domainHead: normalizeDomainHead({
                seq: numberFromSql(
                    row.domain_head_seq,
                    "tombstone.domainHead.seq",
                ),
                eventHash: row.domain_head_hash ?? null,
            }, "tombstone.domainHead"),
            sizeBytes: numberFromSql(
                row.size_bytes,
                "tombstone.sizeBytes",
            ),
            deletedAtMs,
            integrityStatus: "verified",
        });
        return Object.freeze({
            investigationId: row.investigation_id,
            limitsDocument: null,
            limitsFingerprint: null,
            supervisorGeneration: null,
            supervisorNonce: null,
            runnerIncarnation: null,
            registeredAtMs: createdAtMs,
            authorityUpdatedAtMs: deletedAtMs,
            limits: null,
            lifecycleState: "tombstoned",
            lifecycleUpdatedAtMs: deletedAtMs,
            lifecycleReasonCode: "operator_delete",
            lifecycleOperation: null,
            archive: null,
            tombstone,
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
            const lifecycle =
                this.#assertInvestigationLifecycleIntegrity(current);
            const lifecycleOperation = this.#db.prepare(`
                SELECT operation_kind
                FROM lifecycle_operations
                WHERE investigation_id = ?
            `).get(investigationId);
            if (lifecycle.lifecycle_state !== "active"
                || lifecycleOperation !== undefined) {
                throw new FenceRejectedError(
                    "runtime authority cannot be claimed outside an unfenced active lifecycle",
                    {
                        investigationId,
                        lifecycleState: lifecycle.lifecycle_state,
                        lifecycleOperation:
                            lifecycleOperation?.operation_kind ?? null,
                    },
                );
            }
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
                    const reservedUnits = numberFromSql(
                        allocation.reserved_units,
                        `reserved:${allocation.resource_key}`,
                    );
                    const reportedUnits =
                        allocation.resource_key === STORAGE_RESOURCE_KEY
                            ? numberFromSql(
                                this.#db.prepare(`
                                    SELECT actual_units
                                    FROM storage_usage
                                    WHERE investigation_id = ?
                                `).get(row.investigation_id)?.actual_units ?? 0,
                                "storage_usage.actual_units",
                            ) + reservedUnits
                            : reservedUnits;
                    this.#reconcileAllocationInTransaction({
                        fencingToken: credentials.fencingToken,
                        resourceKey: allocation.resource_key,
                        reportedUnits,
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

    reconcileStorageUsage({
        investigationId,
        supervisorGeneration,
        runnerIncarnation,
        actualUnits,
        reconciliationId,
        source,
    } = {}) {
        requireString(investigationId, "investigationId", 128);
        const generation = requireSafeInteger(
            supervisorGeneration,
            "supervisorGeneration",
            { minimum: 1 },
        );
        requireString(runnerIncarnation, "runnerIncarnation", 256);
        const reported = requireSafeInteger(
            actualUnits,
            "actualUnits",
            { minimum: 0 },
        );
        requireString(reconciliationId, "reconciliationId", 256);
        requireString(source, "source", 128);
        return this.#tx(() => {
            const investigation = this.#requireInvestigationInTransaction(
                investigationId,
            );
            if (Number(investigation.supervisor_generation) !== generation
                || investigation.runner_incarnation !== runnerIncarnation) {
                throw new FenceRejectedError(
                    "storage reconciliation authority is stale",
                    {
                        investigationId,
                        supervisorGeneration: generation,
                        runnerIncarnation,
                    },
                );
            }
            const existing = this.#db.prepare(`
                SELECT reported_units, source
                FROM storage_reconciliations
                WHERE investigation_id = ? AND reconciliation_id = ?
            `).get(investigationId, reconciliationId);
            if (existing !== undefined) {
                if (Number(existing.reported_units) !== reported
                    || existing.source !== source) {
                    throw new CasConflictError(
                        "storage reconciliation id was reused with different content",
                        { investigationId, reconciliationId },
                    );
                }
                return Object.freeze({
                    deduplicated: true,
                    actualUnits: reported,
                    snapshot: Object.freeze(
                        this.#usageSnapshotInTransaction(investigationId),
                    ),
                });
            }
            const nowMs = this.#timestamp();
            this.#db.prepare(`
                UPDATE storage_usage
                SET actual_units = ?, reconciled_at_ms = ?
                WHERE investigation_id = ?
            `).run(reported, nowMs, investigationId);
            this.#db.prepare(`
                INSERT INTO storage_reconciliations(
                    investigation_id, reconciliation_id, reported_units,
                    source, reconciled_at_ms)
                VALUES(?, ?, ?, ?, ?)
            `).run(
                investigationId,
                reconciliationId,
                reported,
                source,
                nowMs,
            );
            return Object.freeze({
                deduplicated: false,
                actualUnits: reported,
                snapshot: Object.freeze(
                    this.#usageSnapshotInTransaction(investigationId),
                ),
                overruns: Object.freeze(
                    this.#overrunsInTransaction(investigationId),
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

    #normalizeRecoveryDaemonCredentials(value) {
        const lease = requirePlainObject(value, "lease");
        return Object.freeze({
            daemonGeneration: requireSafeInteger(
                lease.daemonGeneration,
                "lease.daemonGeneration",
                { minimum: 1 },
            ),
            daemonIncarnation: requireString(
                lease.daemonIncarnation,
                "lease.daemonIncarnation",
                256,
            ),
            leaseNonce: requireString(
                lease.leaseNonce,
                "lease.leaseNonce",
                256,
            ),
            ownerProcessId: requireSafeInteger(
                lease.ownerProcessId,
                "lease.ownerProcessId",
                { minimum: 1 },
            ),
            ownerProcessStartId: requireString(
                lease.ownerProcessStartId,
                "lease.ownerProcessStartId",
                256,
            ),
        });
    }

    #assertCurrentRecoveryDaemonInTransaction(
        credentials,
        nowMs,
        { allowExpired = false } = {},
    ) {
        const current = this.#db.prepare(`
            SELECT *
            FROM recovery_daemon_authority
            WHERE singleton_id = 1
        `).get();
        if (current === undefined
            || Number(current.daemon_generation)
                !== credentials.daemonGeneration
            || current.daemon_incarnation
                !== credentials.daemonIncarnation
            || current.lease_nonce !== credentials.leaseNonce
            || Number(current.owner_process_id)
                !== credentials.ownerProcessId
            || current.owner_process_start_id
                !== credentials.ownerProcessStartId) {
            throw new FenceRejectedError(
                "recovery daemon lease authority is stale",
                {
                    presentedGeneration: credentials.daemonGeneration,
                    currentGeneration:
                        current === undefined
                            ? null
                            : Number(current.daemon_generation),
                },
            );
        }
        if (!allowExpired && Number(current.expires_at_ms) <= nowMs) {
            throw new FenceRejectedError(
                "recovery daemon lease has expired",
                {
                    daemonGeneration: credentials.daemonGeneration,
                    expiresAtMs: Number(current.expires_at_ms),
                    nowMs,
                },
            );
        }
        return current;
    }

    #retireRecoveryDaemonInTransaction(row, nowMs, reason) {
        this.#db.prepare(`
            UPDATE recovery_daemon_incarnations
            SET retired_at_ms = ?, retirement_reason = ?
            WHERE daemon_incarnation = ? AND retired_at_ms IS NULL
        `).run(nowMs, reason, row.daemon_incarnation);
        this.#db.prepare(`
            DELETE FROM recovery_daemon_authority
            WHERE singleton_id = 1
              AND daemon_generation = ?
              AND daemon_incarnation = ?
              AND lease_nonce = ?
        `).run(
            row.daemon_generation,
            row.daemon_incarnation,
            row.lease_nonce,
        );
    }

    #rowToRecoveryDaemonLease(row) {
        return Object.freeze({
            daemonGeneration: numberFromSql(
                row.daemon_generation,
                "recoveryDaemon.daemonGeneration",
            ),
            daemonIncarnation: row.daemon_incarnation,
            leaseNonce: row.lease_nonce,
            ownerProcessId: numberFromSql(
                row.owner_process_id,
                "recoveryDaemon.ownerProcessId",
            ),
            ownerProcessStartId: row.owner_process_start_id,
            heartbeatAtMs: numberFromSql(
                row.heartbeat_at_ms,
                "recoveryDaemon.heartbeatAtMs",
            ),
            expiresAtMs: numberFromSql(
                row.expires_at_ms,
                "recoveryDaemon.expiresAtMs",
            ),
        });
    }

    #rowToRecoveryOperation(row) {
        return Object.freeze({
            investigationId: row.investigation_id,
            daemonGeneration: numberFromSql(
                row.daemon_generation,
                "recoveryOperation.daemonGeneration",
            ),
            daemonIncarnation: row.daemon_incarnation,
            state: row.operation_state,
            code: row.operation_code,
            supervisorGeneration: row.supervisor_generation === null
                ? null
                : numberFromSql(
                    row.supervisor_generation,
                    "recoveryOperation.supervisorGeneration",
                ),
            runnerIncarnation: row.runner_incarnation ?? null,
            attemptCount: numberFromSql(
                row.attempt_count,
                "recoveryOperation.attemptCount",
            ),
            updatedAtMs: numberFromSql(
                row.updated_at_ms,
                "recoveryOperation.updatedAtMs",
            ),
        });
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
        const storage = this.#db.prepare(`
            SELECT actual_units, reconciled_at_ms
            FROM storage_usage
            WHERE investigation_id = ?
        `).get(row.investigation_id);
        if (storage === undefined
            || !Number.isSafeInteger(Number(storage.actual_units))
            || Number(storage.actual_units) < 0
            || !Number.isSafeInteger(Number(storage.reconciled_at_ms))
            || Number(storage.reconciled_at_ms) < 0) {
            throw new SchemaIntegrityError(
                "investigation storage usage row is missing or invalid",
                { investigationId: row.investigation_id },
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

    #assertInvestigationLifecycleIntegrity(row) {
        const lifecycle = this.#db.prepare(`
            SELECT lifecycle_state, updated_at_ms, reason_code
            FROM investigation_lifecycle
            WHERE investigation_id = ?
        `).get(row.investigation_id);
        if (lifecycle === undefined
            || !INVESTIGATION_LIFECYCLE_STATES.has(
                lifecycle.lifecycle_state,
            )
            || !Number.isSafeInteger(Number(lifecycle.updated_at_ms))
            || Number(lifecycle.updated_at_ms) < 0
            || (lifecycle.reason_code !== null
                && (typeof lifecycle.reason_code !== "string"
                    || lifecycle.reason_code.length < 1
                    || lifecycle.reason_code.length > 128))) {
            throw new SchemaIntegrityError(
                "investigation lifecycle state is missing or invalid",
                { investigationId: row.investigation_id },
            );
        }
        return lifecycle;
    }

    #assertCurrentAuthorityInTransaction({
        investigationId,
        supervisorGeneration,
        runnerIncarnation,
    }) {
        const current = this.#requireInvestigationInTransaction(investigationId);
        const lifecycle = this.#assertInvestigationLifecycleIntegrity(current);
        const lifecycleOperation = this.#db.prepare(`
            SELECT operation_kind
            FROM lifecycle_operations
            WHERE investigation_id = ?
        `).get(investigationId);
        if (lifecycle.lifecycle_state !== "active"
            || lifecycleOperation !== undefined) {
            throw new FenceRejectedError(
                "resource acquisition is fenced by investigation lifecycle",
                {
                    investigationId,
                    lifecycleState: lifecycle.lifecycle_state,
                    lifecycleOperation:
                        lifecycleOperation?.operation_kind ?? null,
                },
            );
        }
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
        const storage = this.#db.prepare(`
            SELECT l.investigation_id, a.reserved_units
            FROM lease_allocations AS a
            JOIN leases AS l ON l.fencing_token = a.fencing_token
            WHERE a.fencing_token = ? AND a.resource_key = ?
        `).get(fencingToken, STORAGE_RESOURCE_KEY);
        if (storage !== undefined) {
            this.#db.prepare(`
                UPDATE storage_usage
                SET actual_units = actual_units + ?,
                    reconciled_at_ms = ?
                WHERE investigation_id = ?
            `).run(
                numberFromSql(
                    storage.reserved_units,
                    "reserved:storage_bytes",
                ),
                nowMs,
                storage.investigation_id,
            );
        }
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
        if (resourceKey === STORAGE_RESOURCE_KEY) {
            const committedRow = investigationId === null
                ? this.#db.prepare(`
                    SELECT COALESCE(SUM(actual_units), 0) AS total
                    FROM storage_usage
                `).get()
                : this.#db.prepare(`
                    SELECT actual_units AS total
                    FROM storage_usage
                    WHERE investigation_id = ?
                `).get(investigationId);
            const heldRow = investigationId === null
                ? this.#db.prepare(`
                    SELECT COALESCE(SUM(a.reserved_units), 0) AS total
                    FROM lease_allocations AS a
                    JOIN leases AS l ON l.fencing_token = a.fencing_token
                    WHERE a.resource_key = ?
                      AND l.status = 'active'
                `).get(STORAGE_RESOURCE_KEY)
                : this.#db.prepare(`
                    SELECT COALESCE(SUM(a.reserved_units), 0) AS total
                    FROM lease_allocations AS a
                    JOIN leases AS l ON l.fencing_token = a.fencing_token
                    WHERE a.resource_key = ?
                      AND l.status = 'active'
                      AND l.investigation_id = ?
                `).get(STORAGE_RESOURCE_KEY, investigationId);
            return Object.freeze({
                committedUnits: numberFromSql(
                    committedRow?.total ?? 0,
                    `committed:${resourceKey}`,
                ),
                heldUnits: numberFromSql(
                    heldRow?.total ?? 0,
                    `held:${resourceKey}`,
                ),
            });
        }
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
        let chargedUnits = Math.max(
            numberFromSql(allocation.charged_units, `charged:${resourceKey}`),
            reportedUnits,
        );
        if (resourceKey === STORAGE_RESOURCE_KEY) {
            chargedUnits = reportedUnits;
            const lease = this.#db.prepare(`
                SELECT investigation_id
                FROM leases
                WHERE fencing_token = ?
            `).get(fencingToken);
            if (lease === undefined) {
                throw new SchemaIntegrityError(
                    "storage reconciliation lease is missing",
                    { fencingToken },
                );
            }
            this.#db.prepare(`
                UPDATE storage_usage
                SET actual_units = ?, reconciled_at_ms = ?
                WHERE investigation_id = ?
            `).run(reportedUnits, nowMs, lease.investigation_id);
        }
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
