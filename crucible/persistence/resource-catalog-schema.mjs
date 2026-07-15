import { createHash } from "node:crypto";

import { canonicalize } from "./canonical.mjs";
import {
    CruciblePersistenceError,
    DatabaseIntegrityError,
    SchemaIntegrityError,
    SchemaVersionError,
    StorageError,
} from "./errors.mjs";
import {
    configureConnection,
    configureReadOnlyConnection,
    verifyDatabaseIntegrity,
} from "./schema.mjs";
import { DatabaseSync } from "./sqlite.mjs";

export const RESOURCE_CATALOG_SCHEMA_VERSION = 6;
export const RESOURCE_CATALOG_SCHEMA_HASH_ALGORITHM =
    "sha256:crucible-resource-catalog-schema-v6";
export const RESOURCE_CATALOG_CONFIG_HASH_ALGORITHM =
    "sha256:crucible-resource-broker-config-v2";
export const RESOURCE_LIMITS_HASH_ALGORITHM =
    "sha256:crucible-investigation-resource-limits-v2";

const BASE_DDL = `
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE catalog_config (
    singleton_id       INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    config_json        TEXT    NOT NULL CHECK (json_valid(config_json)),
    config_fingerprint TEXT    NOT NULL UNIQUE,
    created_at_ms      INTEGER NOT NULL CHECK (created_at_ms >= 0)
);

CREATE TABLE resource_definitions (
    resource_key       TEXT    PRIMARY KEY,
    resource_family    TEXT    NOT NULL,
    resource_name      TEXT,
    resource_mode      TEXT    NOT NULL CHECK (resource_mode IN ('concurrency', 'consumable')),
    capacity_units     INTEGER NOT NULL CHECK (capacity_units > 0),
    config_fingerprint TEXT    NOT NULL REFERENCES catalog_config(config_fingerprint),
    UNIQUE (resource_family, resource_name)
);

CREATE TABLE investigations (
    investigation_id      TEXT    PRIMARY KEY,
    limits_json           TEXT    NOT NULL CHECK (json_valid(limits_json)),
    limits_fingerprint    TEXT    NOT NULL,
    supervisor_generation INTEGER NOT NULL CHECK (supervisor_generation > 0),
    supervisor_nonce      TEXT    NOT NULL,
    runner_incarnation    TEXT    NOT NULL,
    registered_at_ms      INTEGER NOT NULL CHECK (registered_at_ms >= 0),
    authority_updated_at_ms INTEGER NOT NULL CHECK (authority_updated_at_ms >= 0)
);

CREATE TABLE authority_incarnations (
    runner_incarnation    TEXT    PRIMARY KEY,
    investigation_id     TEXT    NOT NULL REFERENCES investigations(investigation_id),
    supervisor_generation INTEGER NOT NULL CHECK (supervisor_generation > 0),
    supervisor_nonce      TEXT    NOT NULL,
    claimed_at_ms         INTEGER NOT NULL CHECK (claimed_at_ms >= 0),
    retired_at_ms         INTEGER,
    CHECK (retired_at_ms IS NULL OR retired_at_ms >= claimed_at_ms)
);

CREATE UNIQUE INDEX ux_resource_current_authority
    ON authority_incarnations(investigation_id)
    WHERE retired_at_ms IS NULL;
CREATE INDEX ix_resource_authority_generation
    ON authority_incarnations(
        investigation_id, supervisor_generation, claimed_at_ms
    );

CREATE TABLE investigation_limits (
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    resource_key     TEXT    NOT NULL REFERENCES resource_definitions(resource_key),
    limit_units      INTEGER NOT NULL CHECK (limit_units >= 0),
    PRIMARY KEY (investigation_id, resource_key)
);

CREATE TABLE storage_usage (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(investigation_id),
    actual_units     INTEGER NOT NULL CHECK (actual_units >= 0),
    reconciled_at_ms INTEGER NOT NULL CHECK (reconciled_at_ms >= 0)
);

CREATE TABLE storage_reconciliations (
    investigation_id  TEXT    NOT NULL REFERENCES investigations(investigation_id),
    reconciliation_id TEXT    NOT NULL,
    reported_units    INTEGER NOT NULL CHECK (reported_units >= 0),
    source            TEXT    NOT NULL,
    reconciled_at_ms  INTEGER NOT NULL CHECK (reconciled_at_ms >= 0),
    PRIMARY KEY (investigation_id, reconciliation_id)
);

CREATE TABLE leases (
    fencing_token         INTEGER PRIMARY KEY AUTOINCREMENT,
    lease_id              TEXT    NOT NULL UNIQUE,
    lease_nonce           TEXT    NOT NULL,
    investigation_id      TEXT    NOT NULL REFERENCES investigations(investigation_id),
    owner_id              TEXT    NOT NULL,
    owner_process_id      INTEGER,
    owner_process_start_id TEXT,
    supervisor_generation INTEGER NOT NULL CHECK (supervisor_generation > 0),
    runner_incarnation    TEXT    NOT NULL,
    attempt_id            TEXT    NOT NULL,
    logical_effect_id     TEXT    NOT NULL,
    request_fingerprint   TEXT    NOT NULL,
    status                TEXT    NOT NULL CHECK (status IN ('active', 'released', 'reclaimed')),
    acquired_at_ms        INTEGER NOT NULL CHECK (acquired_at_ms >= 0),
    heartbeat_at_ms       INTEGER NOT NULL CHECK (heartbeat_at_ms >= 0),
    expires_at_ms         INTEGER NOT NULL CHECK (expires_at_ms > acquired_at_ms),
    finalized_at_ms       INTEGER,
    finalization_reason   TEXT,
    UNIQUE (investigation_id, logical_effect_id),
    CHECK (
        (owner_process_id IS NULL AND owner_process_start_id IS NULL)
        OR
        (owner_process_id > 0 AND owner_process_start_id IS NOT NULL)
    ),
    CHECK (
        (status = 'active' AND finalized_at_ms IS NULL AND finalization_reason IS NULL)
        OR
        (status <> 'active' AND finalized_at_ms IS NOT NULL AND finalization_reason IS NOT NULL)
    )
);

CREATE INDEX ix_resource_leases_active
    ON leases(status, expires_at_ms, fencing_token);
CREATE INDEX ix_resource_leases_authority
    ON leases(investigation_id, supervisor_generation, runner_incarnation, status);

CREATE TABLE lease_allocations (
    fencing_token  INTEGER NOT NULL REFERENCES leases(fencing_token),
    resource_key   TEXT    NOT NULL REFERENCES resource_definitions(resource_key),
    reserved_units INTEGER NOT NULL CHECK (reserved_units >= 0),
    charged_units  INTEGER NOT NULL DEFAULT 0 CHECK (charged_units >= 0),
    reconciled_at_ms INTEGER,
    PRIMARY KEY (fencing_token, resource_key)
);

CREATE INDEX ix_lease_allocations_resource
    ON lease_allocations(resource_key, fencing_token);

CREATE TABLE usage_reconciliations (
    fencing_token    INTEGER NOT NULL,
    resource_key     TEXT    NOT NULL,
    reconciliation_id TEXT  NOT NULL,
    reported_units   INTEGER NOT NULL CHECK (reported_units >= 0),
    resulting_charged_units INTEGER NOT NULL CHECK (resulting_charged_units >= 0),
    source            TEXT    NOT NULL,
    reconciled_at_ms  INTEGER NOT NULL CHECK (reconciled_at_ms >= 0),
    PRIMARY KEY (fencing_token, resource_key, reconciliation_id),
    FOREIGN KEY (fencing_token, resource_key)
        REFERENCES lease_allocations(fencing_token, resource_key)
);
`;

const RECOVERY_DDL = `
CREATE TABLE investigation_lifecycle (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(investigation_id),
    lifecycle_state  TEXT    NOT NULL
        CHECK (lifecycle_state IN ('active', 'archived', 'tombstoned')),
    updated_at_ms    INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    reason_code      TEXT
);

CREATE INDEX ix_investigation_lifecycle_state
    ON investigation_lifecycle(lifecycle_state, investigation_id);

CREATE TABLE recovery_daemon_incarnations (
    daemon_incarnation    TEXT    PRIMARY KEY,
    daemon_generation     INTEGER NOT NULL UNIQUE CHECK (daemon_generation > 0),
    lease_nonce           TEXT    NOT NULL,
    owner_process_id      INTEGER NOT NULL CHECK (owner_process_id > 0),
    owner_process_start_id TEXT   NOT NULL,
    claimed_at_ms         INTEGER NOT NULL CHECK (claimed_at_ms >= 0),
    retired_at_ms         INTEGER,
    retirement_reason     TEXT,
    CHECK (
        (retired_at_ms IS NULL AND retirement_reason IS NULL)
        OR
        (retired_at_ms IS NOT NULL
            AND retired_at_ms >= claimed_at_ms
            AND retirement_reason IS NOT NULL)
    )
);

CREATE TABLE recovery_daemon_authority (
    singleton_id          INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    daemon_generation     INTEGER NOT NULL UNIQUE CHECK (daemon_generation > 0),
    daemon_incarnation    TEXT    NOT NULL UNIQUE
        REFERENCES recovery_daemon_incarnations(daemon_incarnation),
    lease_nonce           TEXT    NOT NULL,
    owner_process_id      INTEGER NOT NULL CHECK (owner_process_id > 0),
    owner_process_start_id TEXT   NOT NULL,
    heartbeat_at_ms       INTEGER NOT NULL CHECK (heartbeat_at_ms >= 0),
    expires_at_ms         INTEGER NOT NULL CHECK (expires_at_ms > heartbeat_at_ms)
);

`;

const LIFECYCLE_DDL = `
CREATE TABLE lifecycle_operations (
    investigation_id       TEXT PRIMARY KEY REFERENCES investigations(investigation_id),
    operation_kind         TEXT    NOT NULL
        CHECK (operation_kind IN ('archive', 'delete')),
    operation_token        TEXT    NOT NULL UNIQUE,
    owner_process_id       INTEGER NOT NULL CHECK (owner_process_id > 0),
    owner_process_start_id TEXT    NOT NULL,
    archive_relpath        TEXT    UNIQUE,
    expected_archive_digest TEXT,
    started_at_ms          INTEGER NOT NULL CHECK (started_at_ms >= 0),
    CHECK (
        (operation_kind = 'archive'
            AND archive_relpath IS NOT NULL
            AND expected_archive_digest IS NULL)
        OR
        (operation_kind = 'delete'
            AND archive_relpath IS NULL
            AND expected_archive_digest IS NOT NULL)
    )
);

CREATE INDEX ix_lifecycle_operations_kind
    ON lifecycle_operations(operation_kind, started_at_ms, investigation_id);

CREATE TABLE investigation_archives (
    investigation_id       TEXT PRIMARY KEY REFERENCES investigations(investigation_id),
    archive_relpath        TEXT    NOT NULL UNIQUE,
    archive_digest         TEXT    NOT NULL UNIQUE,
    trust_level            TEXT    NOT NULL
        CHECK (trust_level IN ('authenticated', 'self-consistent')),
    domain_version         INTEGER NOT NULL CHECK (domain_version > 0),
    terminal_available     INTEGER NOT NULL CHECK (terminal_available IN (0, 1)),
    integrity_status       TEXT    NOT NULL
        CHECK (integrity_status IN ('verified', 'blocked')),
    size_bytes             INTEGER NOT NULL CHECK (size_bytes >= 0),
    domain_head_seq        INTEGER NOT NULL CHECK (domain_head_seq >= 0),
    domain_head_hash       TEXT,
    archived_at_ms         INTEGER NOT NULL CHECK (archived_at_ms >= 0),
    CHECK (
        (domain_head_seq = 0 AND domain_head_hash IS NULL)
        OR
        (domain_head_seq > 0 AND domain_head_hash IS NOT NULL)
    )
);

CREATE INDEX ix_investigation_archives_time
    ON investigation_archives(archived_at_ms, investigation_id);

CREATE TABLE investigation_tombstones (
    investigation_id       TEXT PRIMARY KEY,
    created_at_ms          INTEGER NOT NULL CHECK (created_at_ms >= 0),
    deleted_at_ms          INTEGER NOT NULL CHECK (deleted_at_ms >= created_at_ms),
    domain_version         INTEGER NOT NULL CHECK (domain_version > 0),
    archive_digest         TEXT    NOT NULL,
    tombstone_relpath      TEXT    NOT NULL UNIQUE,
    tombstone_digest       TEXT    NOT NULL UNIQUE,
    signing_key_fingerprint TEXT   NOT NULL,
    signature              TEXT    NOT NULL,
    size_bytes             INTEGER NOT NULL CHECK (size_bytes > 0),
    integrity_status       TEXT    NOT NULL CHECK (integrity_status = 'verified'),
    domain_head_seq        INTEGER NOT NULL CHECK (domain_head_seq >= 0),
    domain_head_hash       TEXT,
    CHECK (
        (domain_head_seq = 0 AND domain_head_hash IS NULL)
        OR
        (domain_head_seq > 0 AND domain_head_hash IS NOT NULL)
    )
);

CREATE INDEX ix_investigation_tombstones_deleted
    ON investigation_tombstones(deleted_at_ms, investigation_id);
`;

const DELETE_CLEANUP_DDL = `
CREATE TABLE investigation_delete_cleanup (
    investigation_id       TEXT PRIMARY KEY REFERENCES investigations(investigation_id),
    authority_kind         TEXT    NOT NULL
        CHECK (authority_kind = 'pending_delete'),
    source_authority       TEXT    NOT NULL
        CHECK (source_authority = 'verified_bundle'),
    cleanup_state          TEXT    NOT NULL
        CHECK (cleanup_state IN (
            'reserved', 'marked', 'moved',
            'durability_pending', 'durable'
        )),
    archive_relpath        TEXT    NOT NULL UNIQUE,
    cleanup_relpath        TEXT    NOT NULL UNIQUE,
    archive_absent         INTEGER NOT NULL CHECK (archive_absent = 0),
    archive_digest         TEXT    NOT NULL UNIQUE,
    cleanup_marker_nonce   TEXT    NOT NULL UNIQUE,
    cleanup_marker_digest  TEXT    NOT NULL UNIQUE,
    tombstone_relpath      TEXT    NOT NULL UNIQUE,
    tombstone_digest       TEXT    NOT NULL UNIQUE,
    signing_key_fingerprint TEXT   NOT NULL,
    signature              TEXT    NOT NULL,
    tombstone_size_bytes   INTEGER NOT NULL CHECK (tombstone_size_bytes > 0),
    deleted_at_ms          INTEGER NOT NULL CHECK (deleted_at_ms >= 0),
    prepared_at_ms         INTEGER NOT NULL CHECK (prepared_at_ms >= 0),
    CHECK (archive_relpath <> cleanup_relpath)
);

CREATE INDEX ix_investigation_delete_cleanup_state
    ON investigation_delete_cleanup(
        authority_kind, source_authority, cleanup_state,
        prepared_at_ms, investigation_id
    );
`;

const DDL = `${BASE_DDL}\n${RECOVERY_DDL}\n${LIFECYCLE_DDL}\n${DELETE_CLEANUP_DDL}`;

function normalizeSql(sql) {
    return String(sql ?? "")
        .replace(/\s+/gu, " ")
        .trim();
}

function schemaManifest(db) {
    return db.prepare(`
        SELECT type, name, tbl_name, sql
        FROM sqlite_schema
        WHERE name NOT LIKE 'sqlite_%'
          AND sql IS NOT NULL
        ORDER BY type, name
    `).all().map((row) => ({
        type: row.type,
        name: row.name,
        table: row.tbl_name,
        sql: normalizeSql(row.sql),
    }));
}

function fingerprintManifest(
    manifest,
    {
        version = RESOURCE_CATALOG_SCHEMA_VERSION,
        algorithm = RESOURCE_CATALOG_SCHEMA_HASH_ALGORITHM,
    } = {},
) {
    const digest = createHash("sha256")
        .update(canonicalize({
            version,
            manifest,
        }))
        .digest("hex");
    return `${algorithm}:${digest}`;
}

function expectedManifest(ddl = DDL) {
    const db = new DatabaseSync(":memory:");
    try {
        db.exec("PRAGMA foreign_keys = ON;");
        db.exec(ddl);
        return schemaManifest(db);
    } finally {
        db.close();
    }
}

const EXPECTED_MANIFEST = Object.freeze(expectedManifest());
export const RESOURCE_CATALOG_SCHEMA_FINGERPRINT =
    fingerprintManifest(EXPECTED_MANIFEST);

function pragmaScalar(db, name) {
    const row = db.prepare(`PRAGMA ${name};`).get();
    return row ? Object.values(row)[0] : undefined;
}

function tableExists(db, name) {
    return Boolean(db.prepare(`
        SELECT 1 AS present
        FROM sqlite_schema
        WHERE type = 'table' AND name = ?
    `).get(name));
}

function initializeLifecycleGeneration(db) {
    db.prepare(`
        INSERT OR REPLACE INTO schema_meta(key, value)
        VALUES('lifecycle_generation', '0')
    `).run();
}

function rollbackQuietly(db) {
    try {
        db.exec("ROLLBACK;");
    } catch {
        // Preserve the original failure.
    }
}

function verifyConnection(
    db,
    { busyTimeoutMs } = {},
) {
    const observed = {
        foreignKeys: Number(pragmaScalar(db, "foreign_keys")),
        journalMode: String(pragmaScalar(db, "journal_mode") ?? "").toLowerCase(),
        synchronous: Number(pragmaScalar(db, "synchronous")),
        userVersion: Number(pragmaScalar(db, "user_version")),
    };
    const expected = {
        foreignKeys: 1,
        journalMode: "wal",
        synchronous: 2,
        userVersion: RESOURCE_CATALOG_SCHEMA_VERSION,
    };
    if (canonicalize(observed) !== canonicalize(expected)) {
        throw new SchemaIntegrityError(
            "resource catalog connection pragmas do not match the durable contract",
            { expected, observed },
        );
    }

    if (busyTimeoutMs !== undefined
        && Number(pragmaScalar(db, "busy_timeout")) !== busyTimeoutMs) {
        throw new SchemaIntegrityError(
            "resource catalog busy_timeout does not match the requested contract",
            {
                expected: busyTimeoutMs,
                observed: Number(pragmaScalar(db, "busy_timeout")),
            },
        );
    }
}

function verifySchemaObjects(db) {
    const actual = schemaManifest(db);
    const actualFingerprint = fingerprintManifest(actual);
    if (canonicalize(actual) !== canonicalize(EXPECTED_MANIFEST)
        || actualFingerprint !== RESOURCE_CATALOG_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog schema does not match the canonical definition",
            {
                expected: RESOURCE_CATALOG_SCHEMA_FINGERPRINT,
                actual: actualFingerprint,
            },
        );
    }
}

function createFreshSchema(db, nowMs) {
    db.exec("BEGIN IMMEDIATE;");
    try {
        if (tableExists(db, "schema_meta")) {
            db.exec("COMMIT;");
            return false;
        }
        db.exec(DDL);
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)")
            .run(String(RESOURCE_CATALOG_SCHEMA_VERSION));
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('schema_fingerprint', ?)")
            .run(RESOURCE_CATALOG_SCHEMA_FINGERPRINT);
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('created_at_ms', ?)")
            .run(String(nowMs));
        initializeLifecycleGeneration(db);
        db.exec(`PRAGMA user_version = ${RESOURCE_CATALOG_SCHEMA_VERSION};`);
        db.exec("COMMIT;");
        return true;
    } catch (error) {
        rollbackQuietly(db);
        throw error;
    }
}

function assertFreshOrInitialized(db) {
    if (tableExists(db, "schema_meta")) {
        return true;
    }
    const objectCount = Number(db.prepare(`
        SELECT COUNT(*) AS count
        FROM sqlite_schema
        WHERE name NOT LIKE 'sqlite_%'
    `).get()?.count ?? 0);
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    if (objectCount !== 0 || userVersion !== 0) {
        throw new SchemaIntegrityError(
            "resource catalog contains partial schema state",
            { objectCount, userVersion },
        );
    }
    return false;
}

export function configureResourceCatalogConnection(db, { busyTimeoutMs }) {
    configureConnection(db, { busyTimeoutMs });
}

export function configureResourceCatalogReadOnlyConnection(db, { busyTimeoutMs }) {
    configureReadOnlyConnection(db, { busyTimeoutMs });
}

export function verifyResourceCatalogSchema(db, {
    busyTimeoutMs = undefined,
    integrityCheckAdapter = undefined,
} = {}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== RESOURCE_CATALOG_SCHEMA_VERSION
        || storedVersion !== RESOURCE_CATALOG_SCHEMA_VERSION) {
        throw new SchemaVersionError(
            "resource catalog schema version mismatch",
            {
                fileUserVersion: userVersion,
                fileMetaVersion: storedVersion,
                expected: RESOURCE_CATALOG_SCHEMA_VERSION,
            },
        );
    }
    verifyConnection(db, { busyTimeoutMs });
    verifyDatabaseIntegrity(db, { adapter: integrityCheckAdapter });
    verifySchemaObjects(db);
    const storedFingerprint = db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_fingerprint'",
    ).get()?.value ?? null;
    if (storedFingerprint !== RESOURCE_CATALOG_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "stored resource catalog schema fingerprint does not match",
            {
                expected: RESOURCE_CATALOG_SCHEMA_FINGERPRINT,
                stored: storedFingerprint,
            },
        );
    }
    return Object.freeze({
        version: RESOURCE_CATALOG_SCHEMA_VERSION,
        fingerprint: RESOURCE_CATALOG_SCHEMA_FINGERPRINT,
    });
}

export function applyResourceCatalogSchema(db, {
    busyTimeoutMs = undefined,
    integrityCheckAdapter = undefined,
    nowMs,
} = {}) {
    try {
        const initialized = assertFreshOrInitialized(db);
        let created = false;
        if (!initialized) {
            created = createFreshSchema(db, nowMs);
        }
        verifyResourceCatalogSchema(db, {
            busyTimeoutMs,
            integrityCheckAdapter,
        });
        return Object.freeze({
            created,
            version: RESOURCE_CATALOG_SCHEMA_VERSION,
            fingerprint: RESOURCE_CATALOG_SCHEMA_FINGERPRINT,
        });
    } catch (error) {
        if (error instanceof CruciblePersistenceError) {
            throw error;
        }
        if (error?.code === "ERR_SQLITE_ERROR") {
            throw new StorageError(
                `failed to initialize resource catalog schema: ${error.message}`,
                error,
            );
        }
        throw new DatabaseIntegrityError(
            "failed to initialize resource catalog schema",
            { message: error?.message ?? String(error) },
        );
    }
}
