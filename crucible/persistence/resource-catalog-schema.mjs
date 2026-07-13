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

export const RESOURCE_CATALOG_SCHEMA_VERSION = 1;
export const RESOURCE_CATALOG_SCHEMA_HASH_ALGORITHM =
    "sha256:crucible-resource-catalog-schema-v1";
export const RESOURCE_CATALOG_CONFIG_HASH_ALGORITHM =
    "sha256:crucible-resource-broker-config-v1";
export const RESOURCE_LIMITS_HASH_ALGORITHM =
    "sha256:crucible-investigation-resource-limits-v1";

const DDL = `
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

function fingerprintManifest(manifest) {
    const digest = createHash("sha256")
        .update(canonicalize({
            version: RESOURCE_CATALOG_SCHEMA_VERSION,
            manifest,
        }))
        .digest("hex");
    return `${RESOURCE_CATALOG_SCHEMA_HASH_ALGORITHM}:${digest}`;
}

function expectedManifest() {
    const db = new DatabaseSync(":memory:");
    try {
        db.exec("PRAGMA foreign_keys = ON;");
        db.exec(DDL);
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

function rollbackQuietly(db) {
    try {
        db.exec("ROLLBACK;");
    } catch {
        // Preserve the original failure.
    }
}

function verifyConnection(db, { busyTimeoutMs } = {}) {
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
