import { createHash, randomBytes } from "node:crypto";

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

const V2_SCHEMA_VERSION = 2;
const V2_SCHEMA_HASH_ALGORITHM =
    "sha256:crucible-resource-catalog-schema-v2";
const V3_SCHEMA_VERSION = 3;
const V3_SCHEMA_HASH_ALGORITHM =
    "sha256:crucible-resource-catalog-schema-v3";
const V4_SCHEMA_VERSION = 4;
const V4_SCHEMA_HASH_ALGORITHM =
    "sha256:crucible-resource-catalog-schema-v4";
const V5_SCHEMA_VERSION = 5;
const V5_SCHEMA_HASH_ALGORITHM =
    "sha256:crucible-resource-catalog-schema-v5";
const INVESTIGATION_ID_RE =
    /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;
const ARCHIVE_DIGEST_RE = /^sha256:[a-f0-9]{64}$/u;
const ARCHIVE_RELATIVE_PATH_RE =
    /^\.retention\/archives\/(?![^/]*\.\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;

const V2_DDL = `
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

CREATE TABLE recovery_operations (
    investigation_id      TEXT PRIMARY KEY REFERENCES investigations(investigation_id),
    daemon_generation     INTEGER NOT NULL CHECK (daemon_generation > 0),
    daemon_incarnation    TEXT    NOT NULL
        REFERENCES recovery_daemon_incarnations(daemon_incarnation),
    operation_state       TEXT    NOT NULL
        CHECK (operation_state IN (
            'eligible', 'running', 'started', 'waiting',
            'skipped', 'blocked', 'failed'
        )),
    operation_code        TEXT    NOT NULL,
    supervisor_generation INTEGER,
    runner_incarnation    TEXT,
    attempt_count         INTEGER NOT NULL CHECK (attempt_count > 0),
    updated_at_ms         INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK (
        (supervisor_generation IS NULL AND runner_incarnation IS NULL)
        OR
        (supervisor_generation > 0 AND runner_incarnation IS NOT NULL)
    )
);

CREATE INDEX ix_recovery_operations_state
    ON recovery_operations(operation_state, updated_at_ms, investigation_id);
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

const V5_DELETE_CLEANUP_DDL = `
CREATE TABLE investigation_delete_cleanup (
    investigation_id       TEXT PRIMARY KEY REFERENCES investigations(investigation_id),
    archive_relpath        TEXT    NOT NULL UNIQUE,
    archive_digest         TEXT    NOT NULL UNIQUE,
    tombstone_relpath      TEXT    NOT NULL UNIQUE,
    tombstone_digest       TEXT    NOT NULL UNIQUE,
    signing_key_fingerprint TEXT   NOT NULL,
    signature              TEXT    NOT NULL,
    tombstone_size_bytes   INTEGER NOT NULL CHECK (tombstone_size_bytes > 0),
    deleted_at_ms          INTEGER NOT NULL CHECK (deleted_at_ms >= 0),
    prepared_at_ms         INTEGER NOT NULL CHECK (prepared_at_ms >= 0)
);

CREATE INDEX ix_investigation_delete_cleanup_prepared
    ON investigation_delete_cleanup(prepared_at_ms, investigation_id);
`;

const DELETE_CLEANUP_DDL = `
CREATE TABLE investigation_delete_cleanup (
    investigation_id       TEXT PRIMARY KEY,
    authority_kind         TEXT    NOT NULL
        CHECK (authority_kind IN ('pending_delete', 'legacy_tombstone')),
    source_authority       TEXT    NOT NULL
        CHECK (source_authority IN (
            'verified_bundle', 'legacy_preverified', 'legacy_discovery'
        )),
    cleanup_state          TEXT    NOT NULL
        CHECK (cleanup_state IN (
            'reserved', 'marked', 'moved',
            'durability_pending', 'durable'
        )),
    archive_relpath        TEXT    UNIQUE,
    cleanup_relpath        TEXT    NOT NULL UNIQUE,
    archive_absent         INTEGER NOT NULL
        CHECK (archive_absent IN (0, 1)),
    archive_digest         TEXT    NOT NULL UNIQUE,
    cleanup_marker_nonce   TEXT    NOT NULL UNIQUE,
    cleanup_marker_digest  TEXT    UNIQUE,
    tombstone_relpath      TEXT    NOT NULL UNIQUE,
    tombstone_digest       TEXT    NOT NULL UNIQUE,
    signing_key_fingerprint TEXT   NOT NULL,
    signature              TEXT    NOT NULL,
    tombstone_size_bytes   INTEGER NOT NULL CHECK (tombstone_size_bytes > 0),
    deleted_at_ms          INTEGER NOT NULL CHECK (deleted_at_ms >= 0),
    prepared_at_ms         INTEGER NOT NULL CHECK (prepared_at_ms >= 0),
    CHECK (archive_relpath IS NULL OR archive_relpath <> cleanup_relpath),
    CHECK (
        (source_authority = 'legacy_discovery'
            AND archive_relpath IS NULL
            AND cleanup_marker_digest IS NULL)
        OR
        (source_authority <> 'legacy_discovery'
            AND archive_relpath IS NOT NULL
            AND archive_absent = 0
            AND cleanup_marker_digest IS NOT NULL)
    )
);

CREATE INDEX ix_investigation_delete_cleanup_state
    ON investigation_delete_cleanup(
        authority_kind, source_authority, cleanup_state,
        prepared_at_ms, investigation_id
    );
`;

const V3_DDL = `${V2_DDL}\n${RECOVERY_DDL}`;
const V4_DDL = `${V3_DDL}\n${LIFECYCLE_DDL}`;
const V5_DDL = `${V4_DDL}\n${V5_DELETE_CLEANUP_DDL}`;
const DDL = `${V4_DDL}\n${DELETE_CLEANUP_DDL}`;

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

const V2_EXPECTED_MANIFEST = Object.freeze(expectedManifest(V2_DDL));
const V2_SCHEMA_FINGERPRINT = fingerprintManifest(
    V2_EXPECTED_MANIFEST,
    {
        version: V2_SCHEMA_VERSION,
        algorithm: V2_SCHEMA_HASH_ALGORITHM,
    },
);
const V3_EXPECTED_MANIFEST = Object.freeze(expectedManifest(V3_DDL));
const V3_SCHEMA_FINGERPRINT = fingerprintManifest(
    V3_EXPECTED_MANIFEST,
    {
        version: V3_SCHEMA_VERSION,
        algorithm: V3_SCHEMA_HASH_ALGORITHM,
    },
);
const V4_EXPECTED_MANIFEST = Object.freeze(expectedManifest(V4_DDL));
const V4_SCHEMA_FINGERPRINT = fingerprintManifest(
    V4_EXPECTED_MANIFEST,
    {
        version: V4_SCHEMA_VERSION,
        algorithm: V4_SCHEMA_HASH_ALGORITHM,
    },
);
const V5_EXPECTED_MANIFEST = Object.freeze(expectedManifest(V5_DDL));
const V5_SCHEMA_FINGERPRINT = fingerprintManifest(
    V5_EXPECTED_MANIFEST,
    {
        version: V5_SCHEMA_VERSION,
        algorithm: V5_SCHEMA_HASH_ALGORITHM,
    },
);
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

function canonicalTombstoneRelativePath(investigationId) {
    const relative =
        `.retention/tombstones/${investigationId}.json`;
    return process.platform === "win32"
        ? relative.toLowerCase()
        : relative;
}

function cleanupRelativePath(investigationId, archiveDigest) {
    const digest = createHash("sha256")
        .update("crucible-delete-cleanup-v2\0")
        .update(investigationId)
        .update("\0")
        .update(archiveDigest)
        .digest("hex");
    return `.retention/archives/cleanup-${digest}`;
}

function cleanupMarkerDigest({
    investigationId,
    archiveRelativePath,
    cleanupRelativePath: cleanupPath,
    archiveDigest,
    nonce,
}) {
    const document = {
        type: "crucible-delete-cleanup-marker",
        version: 1,
        investigationId,
        archiveRelativePath,
        cleanupRelativePath: cleanupPath,
        archiveDigest,
        nonce,
    };
    const bytes = Buffer.from(`${canonicalize(document)}\n`, "utf8");
    return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function assertMigrationCleanupAuthority(row) {
    if (row === undefined
        || !INVESTIGATION_ID_RE.test(row.investigation_id ?? "")
        || !ARCHIVE_RELATIVE_PATH_RE.test(row.archive_relpath ?? "")
        || !ARCHIVE_DIGEST_RE.test(row.archive_digest ?? "")
        || !ARCHIVE_DIGEST_RE.test(row.tombstone_digest ?? "")
        || row.tombstone_relpath
            !== canonicalTombstoneRelativePath(
                row.investigation_id ?? "",
            )
        || typeof row.signing_key_fingerprint !== "string"
        || row.signing_key_fingerprint.length < 1
        || row.signing_key_fingerprint.length > 256
        || typeof row.signature !== "string"
        || row.signature.length < 1
        || row.signature.length > 4096
        || !Number.isSafeInteger(Number(row.tombstone_size_bytes))
        || Number(row.tombstone_size_bytes) < 1
        || !Number.isSafeInteger(Number(row.deleted_at_ms))
        || Number(row.deleted_at_ms) < 0
        || !Number.isSafeInteger(Number(row.prepared_at_ms))
        || Number(row.prepared_at_ms) < 0) {
        throw new SchemaIntegrityError(
            "resource catalog v5 cleanup authority is invalid",
            { investigationId: row?.investigation_id ?? null },
        );
    }
}

function initializeLifecycleGeneration(db) {
    db.prepare(`
        INSERT OR REPLACE INTO schema_meta(key, value)
        VALUES('lifecycle_generation', '0')
    `).run();
}

function insertLegacyTombstoneDiscovery(db, nowMs) {
    const insert = db.prepare(`
        INSERT INTO investigation_delete_cleanup(
            investigation_id, authority_kind, source_authority,
            cleanup_state, archive_relpath, cleanup_relpath,
            archive_absent, archive_digest, cleanup_marker_nonce,
            cleanup_marker_digest, tombstone_relpath,
            tombstone_digest, signing_key_fingerprint, signature,
            tombstone_size_bytes, deleted_at_ms, prepared_at_ms)
        VALUES(
            ?, 'legacy_tombstone', 'legacy_discovery',
            'reserved', NULL, ?, 0, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?
        )
    `);
    for (const row of db.prepare(`
        SELECT *
        FROM investigation_tombstones
        WHERE investigation_id NOT IN (
            SELECT investigation_id
            FROM investigation_delete_cleanup
        )
        ORDER BY investigation_id
    `).all()) {
        if (!INVESTIGATION_ID_RE.test(row.investigation_id ?? "")
            || !ARCHIVE_DIGEST_RE.test(row.archive_digest ?? "")
            || !ARCHIVE_DIGEST_RE.test(row.tombstone_digest ?? "")
            || row.tombstone_relpath
                !== canonicalTombstoneRelativePath(
                    row.investigation_id ?? "",
                )
            || typeof row.signing_key_fingerprint !== "string"
            || row.signing_key_fingerprint.length < 1
            || row.signing_key_fingerprint.length > 256
            || typeof row.signature !== "string"
            || row.signature.length < 1
            || row.signature.length > 4096
            || !Number.isSafeInteger(Number(row.size_bytes))
            || Number(row.size_bytes) < 1
            || !Number.isSafeInteger(Number(row.deleted_at_ms))
            || Number(row.deleted_at_ms) < 0) {
            throw new SchemaIntegrityError(
                "resource catalog legacy tombstone discovery authority is invalid",
                { investigationId: row?.investigation_id ?? null },
            );
        }
        insert.run(
            row.investigation_id,
            cleanupRelativePath(
                row.investigation_id,
                row.archive_digest,
            ),
            row.archive_digest,
            randomBytes(32).toString("hex"),
            row.tombstone_relpath,
            row.tombstone_digest,
            row.signing_key_fingerprint,
            row.signature,
            row.size_bytes,
            row.deleted_at_ms,
            nowMs,
        );
    }
}

function assertMigrationRetentionOwnership(db) {
    const rows = db.prepare(`
        SELECT investigation_id, source, relative_path
        FROM (
            SELECT investigation_id,
                   'archive_operation' AS source,
                   archive_relpath AS relative_path
            FROM lifecycle_operations
            WHERE archive_relpath IS NOT NULL

            UNION ALL

            SELECT investigation_id,
                   'archive' AS source,
                   archive_relpath AS relative_path
            FROM investigation_archives

            UNION ALL

            SELECT investigation_id,
                   'cleanup_archive' AS source,
                   archive_relpath AS relative_path
            FROM investigation_delete_cleanup
            WHERE archive_relpath IS NOT NULL

            UNION ALL

            SELECT investigation_id,
                   'cleanup_target' AS source,
                   cleanup_relpath AS relative_path
            FROM investigation_delete_cleanup
        )
        ORDER BY relative_path, source, investigation_id
    `).all();
    const grouped = new Map();
    for (const row of rows) {
        const owners = grouped.get(row.relative_path) ?? [];
        owners.push(row);
        grouped.set(row.relative_path, owners);
    }
    for (const [relativePath, owners] of grouped) {
        if (owners.length <= 1) continue;
        const ids = new Set(owners.map((owner) => owner.investigation_id));
        const sources = new Set(owners.map((owner) => owner.source));
        const allowed = ids.size === 1
            && owners.length === 2
            && sources.has("archive")
            && sources.has("cleanup_archive");
        if (!allowed) {
            throw new SchemaIntegrityError(
                "resource catalog migration found conflicting retention ownership",
                { relativePath, owners },
            );
        }
    }
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
    {
        busyTimeoutMs,
        schemaVersion = RESOURCE_CATALOG_SCHEMA_VERSION,
    } = {},
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
        userVersion: schemaVersion,
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

function verifyV2SchemaForMigration(db, {
    busyTimeoutMs,
    integrityCheckAdapter = undefined,
} = {}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== V2_SCHEMA_VERSION
        || storedVersion !== V2_SCHEMA_VERSION) {
        throw new SchemaVersionError(
            "resource catalog v2 migration source version mismatch",
            {
                fileUserVersion: userVersion,
                fileMetaVersion: storedVersion,
                expected: V2_SCHEMA_VERSION,
            },
        );
    }
    verifyConnection(db, {
        busyTimeoutMs,
        schemaVersion: V2_SCHEMA_VERSION,
    });
    verifyDatabaseIntegrity(db, { adapter: integrityCheckAdapter });
    const actual = schemaManifest(db);
    const actualFingerprint = fingerprintManifest(actual, {
        version: V2_SCHEMA_VERSION,
        algorithm: V2_SCHEMA_HASH_ALGORITHM,
    });
    if (canonicalize(actual) !== canonicalize(V2_EXPECTED_MANIFEST)
        || actualFingerprint !== V2_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog v2 migration source schema is not canonical",
            {
                expected: V2_SCHEMA_FINGERPRINT,
                actual: actualFingerprint,
            },
        );
    }
    const storedFingerprint = db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_fingerprint'",
    ).get()?.value ?? null;
    if (storedFingerprint !== V2_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog v2 migration source fingerprint does not match",
            {
                expected: V2_SCHEMA_FINGERPRINT,
                stored: storedFingerprint,
            },
        );
    }
}

function verifyV3SchemaForMigration(db, {
    busyTimeoutMs,
    integrityCheckAdapter = undefined,
} = {}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== V3_SCHEMA_VERSION
        || storedVersion !== V3_SCHEMA_VERSION) {
        throw new SchemaVersionError(
            "resource catalog v3 migration source version mismatch",
            {
                fileUserVersion: userVersion,
                fileMetaVersion: storedVersion,
                expected: V3_SCHEMA_VERSION,
            },
        );
    }
    verifyConnection(db, {
        busyTimeoutMs,
        schemaVersion: V3_SCHEMA_VERSION,
    });
    verifyDatabaseIntegrity(db, { adapter: integrityCheckAdapter });
    const actual = schemaManifest(db);
    const actualFingerprint = fingerprintManifest(actual, {
        version: V3_SCHEMA_VERSION,
        algorithm: V3_SCHEMA_HASH_ALGORITHM,
    });
    if (canonicalize(actual) !== canonicalize(V3_EXPECTED_MANIFEST)
        || actualFingerprint !== V3_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog v3 migration source schema is not canonical",
            {
                expected: V3_SCHEMA_FINGERPRINT,
                actual: actualFingerprint,
            },
        );
    }
    const storedFingerprint = db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_fingerprint'",
    ).get()?.value ?? null;
    if (storedFingerprint !== V3_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog v3 migration source fingerprint does not match",
            {
                expected: V3_SCHEMA_FINGERPRINT,
                stored: storedFingerprint,
            },
        );
    }
}

function verifyV4SchemaForMigration(db, {
    busyTimeoutMs,
    integrityCheckAdapter = undefined,
} = {}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== V4_SCHEMA_VERSION
        || storedVersion !== V4_SCHEMA_VERSION) {
        throw new SchemaVersionError(
            "resource catalog v4 migration source version mismatch",
            {
                fileUserVersion: userVersion,
                fileMetaVersion: storedVersion,
                expected: V4_SCHEMA_VERSION,
            },
        );
    }
    verifyConnection(db, {
        busyTimeoutMs,
        schemaVersion: V4_SCHEMA_VERSION,
    });
    verifyDatabaseIntegrity(db, { adapter: integrityCheckAdapter });
    const actual = schemaManifest(db);
    const actualFingerprint = fingerprintManifest(actual, {
        version: V4_SCHEMA_VERSION,
        algorithm: V4_SCHEMA_HASH_ALGORITHM,
    });
    if (canonicalize(actual) !== canonicalize(V4_EXPECTED_MANIFEST)
        || actualFingerprint !== V4_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog v4 migration source schema is not canonical",
            {
                expected: V4_SCHEMA_FINGERPRINT,
                actual: actualFingerprint,
            },
        );
    }
    const storedFingerprint = db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_fingerprint'",
    ).get()?.value ?? null;
    if (storedFingerprint !== V4_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog v4 migration source fingerprint does not match",
            {
                expected: V4_SCHEMA_FINGERPRINT,
                stored: storedFingerprint,
            },
        );
    }
}

function verifyV5SchemaForMigration(db, {
    busyTimeoutMs,
    integrityCheckAdapter = undefined,
} = {}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== V5_SCHEMA_VERSION
        || storedVersion !== V5_SCHEMA_VERSION) {
        throw new SchemaVersionError(
            "resource catalog v5 migration source version mismatch",
            {
                fileUserVersion: userVersion,
                fileMetaVersion: storedVersion,
                expected: V5_SCHEMA_VERSION,
            },
        );
    }
    verifyConnection(db, {
        busyTimeoutMs,
        schemaVersion: V5_SCHEMA_VERSION,
    });
    verifyDatabaseIntegrity(db, { adapter: integrityCheckAdapter });
    const actual = schemaManifest(db);
    const actualFingerprint = fingerprintManifest(actual, {
        version: V5_SCHEMA_VERSION,
        algorithm: V5_SCHEMA_HASH_ALGORITHM,
    });
    if (canonicalize(actual) !== canonicalize(V5_EXPECTED_MANIFEST)
        || actualFingerprint !== V5_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog v5 migration source schema is not canonical",
            {
                expected: V5_SCHEMA_FINGERPRINT,
                actual: actualFingerprint,
            },
        );
    }
    const storedFingerprint = db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_fingerprint'",
    ).get()?.value ?? null;
    if (storedFingerprint !== V5_SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "resource catalog v5 migration source fingerprint does not match",
            {
                expected: V5_SCHEMA_FINGERPRINT,
                stored: storedFingerprint,
            },
        );
    }
}

function migrateV2Schema(db, {
    busyTimeoutMs,
    integrityCheckAdapter,
    nowMs,
}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== V2_SCHEMA_VERSION
        || storedVersion !== V2_SCHEMA_VERSION) {
        return false;
    }
    verifyV2SchemaForMigration(db, {
        busyTimeoutMs,
        integrityCheckAdapter,
    });
    db.exec("BEGIN IMMEDIATE;");
    try {
        db.exec(RECOVERY_DDL);
        db.exec(LIFECYCLE_DDL);
        db.exec(DELETE_CLEANUP_DDL);
        db.prepare(`
            INSERT INTO investigation_lifecycle(
                investigation_id, lifecycle_state, updated_at_ms, reason_code)
            SELECT investigation_id, 'active', ?, NULL
            FROM investigations
        `).run(nowMs);
        initializeLifecycleGeneration(db);
        db.prepare(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
        ).run(String(RESOURCE_CATALOG_SCHEMA_VERSION));
        db.prepare(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_fingerprint'",
        ).run(RESOURCE_CATALOG_SCHEMA_FINGERPRINT);
        db.prepare(`
            INSERT OR REPLACE INTO schema_meta(key, value)
            VALUES('recovery_schema_migrated_at_ms', ?)
        `).run(String(nowMs));
        db.prepare(`
            INSERT OR REPLACE INTO schema_meta(key, value)
            VALUES('lifecycle_schema_migrated_at_ms', ?)
        `).run(String(nowMs));
        db.exec(`PRAGMA user_version = ${RESOURCE_CATALOG_SCHEMA_VERSION};`);
        db.exec("COMMIT;");
        return true;
    } catch (error) {
        rollbackQuietly(db);
        throw error;
    }
}

function migrateV3Schema(db, {
    busyTimeoutMs,
    integrityCheckAdapter,
    nowMs,
}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== V3_SCHEMA_VERSION
        || storedVersion !== V3_SCHEMA_VERSION) {
        return false;
    }
    verifyV3SchemaForMigration(db, {
        busyTimeoutMs,
        integrityCheckAdapter,
    });
    db.exec("BEGIN IMMEDIATE;");
    try {
        db.exec(LIFECYCLE_DDL);
        db.exec(DELETE_CLEANUP_DDL);
        initializeLifecycleGeneration(db);
        db.prepare(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
        ).run(String(RESOURCE_CATALOG_SCHEMA_VERSION));
        db.prepare(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_fingerprint'",
        ).run(RESOURCE_CATALOG_SCHEMA_FINGERPRINT);
        db.prepare(`
            INSERT OR REPLACE INTO schema_meta(key, value)
            VALUES('lifecycle_schema_migrated_at_ms', ?)
        `).run(String(nowMs));
        db.exec(`PRAGMA user_version = ${RESOURCE_CATALOG_SCHEMA_VERSION};`);
        db.exec("COMMIT;");
        return true;
    } catch (error) {
        rollbackQuietly(db);
        throw error;
    }
}

function migrateV4Schema(db, {
    busyTimeoutMs,
    integrityCheckAdapter,
    nowMs,
}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== V4_SCHEMA_VERSION
        || storedVersion !== V4_SCHEMA_VERSION) {
        return false;
    }
    verifyV4SchemaForMigration(db, {
        busyTimeoutMs,
        integrityCheckAdapter,
    });
    db.exec("BEGIN IMMEDIATE;");
    try {
        db.exec(DELETE_CLEANUP_DDL);
        insertLegacyTombstoneDiscovery(db, nowMs);
        assertMigrationRetentionOwnership(db);
        initializeLifecycleGeneration(db);
        db.prepare(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
        ).run(String(RESOURCE_CATALOG_SCHEMA_VERSION));
        db.prepare(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_fingerprint'",
        ).run(RESOURCE_CATALOG_SCHEMA_FINGERPRINT);
        db.prepare(`
            INSERT OR REPLACE INTO schema_meta(key, value)
            VALUES('delete_cleanup_schema_migrated_at_ms', ?)
        `).run(String(nowMs));
        db.exec(`PRAGMA user_version = ${RESOURCE_CATALOG_SCHEMA_VERSION};`);
        db.exec("COMMIT;");
        return true;
    } catch (error) {
        rollbackQuietly(db);
        throw error;
    }
}

function migrateV5Schema(db, {
    busyTimeoutMs,
    integrityCheckAdapter,
    nowMs,
}) {
    const userVersion = Number(pragmaScalar(db, "user_version") ?? 0);
    const storedVersion = Number(db.prepare(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
    ).get()?.value ?? Number.NaN);
    if (userVersion !== V5_SCHEMA_VERSION
        || storedVersion !== V5_SCHEMA_VERSION) {
        return false;
    }
    verifyV5SchemaForMigration(db, {
        busyTimeoutMs,
        integrityCheckAdapter,
    });
    db.exec("BEGIN IMMEDIATE;");
    try {
        db.exec(`
            ALTER TABLE investigation_delete_cleanup
                RENAME TO investigation_delete_cleanup_v5;
            DROP INDEX ix_investigation_delete_cleanup_prepared;
        `);
        db.exec(DELETE_CLEANUP_DDL);
        const insert = db.prepare(`
            INSERT INTO investigation_delete_cleanup(
                investigation_id, authority_kind, source_authority,
                cleanup_state, archive_relpath, cleanup_relpath,
                archive_absent, archive_digest, cleanup_marker_nonce,
                cleanup_marker_digest, tombstone_relpath,
                tombstone_digest, signing_key_fingerprint, signature,
                tombstone_size_bytes, deleted_at_ms, prepared_at_ms)
            VALUES(
                ?, 'pending_delete', 'legacy_preverified',
                'reserved', ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        `);
        for (const row of db.prepare(`
            SELECT *
            FROM investigation_delete_cleanup_v5
            ORDER BY investigation_id
        `).all()) {
            assertMigrationCleanupAuthority(row);
            const archive = db.prepare(`
                SELECT a.archive_relpath, a.archive_digest,
                       l.lifecycle_state
                FROM investigation_archives AS a
                JOIN investigation_lifecycle AS l
                  ON l.investigation_id = a.investigation_id
                WHERE a.investigation_id = ?
            `).get(row.investigation_id);
            if (archive === undefined
                || archive.lifecycle_state !== "archived"
                || archive.archive_relpath !== row.archive_relpath
                || archive.archive_digest !== row.archive_digest) {
                throw new SchemaIntegrityError(
                    "resource catalog v5 cleanup lacks exact archived authority",
                    { investigationId: row.investigation_id },
                );
            }
            const cleanupPath = cleanupRelativePath(
                row.investigation_id,
                row.archive_digest,
            );
            const nonce = randomBytes(32).toString("hex");
            insert.run(
                row.investigation_id,
                row.archive_relpath,
                cleanupPath,
                row.archive_digest,
                nonce,
                cleanupMarkerDigest({
                    investigationId: row.investigation_id,
                    archiveRelativePath: row.archive_relpath,
                    cleanupRelativePath: cleanupPath,
                    archiveDigest: row.archive_digest,
                    nonce,
                }),
                row.tombstone_relpath,
                row.tombstone_digest,
                row.signing_key_fingerprint,
                row.signature,
                row.tombstone_size_bytes,
                row.deleted_at_ms,
                row.prepared_at_ms,
            );
        }
        db.exec("DROP TABLE investigation_delete_cleanup_v5;");
        insertLegacyTombstoneDiscovery(db, nowMs);
        assertMigrationRetentionOwnership(db);
        initializeLifecycleGeneration(db);
        db.prepare(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
        ).run(String(RESOURCE_CATALOG_SCHEMA_VERSION));
        db.prepare(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_fingerprint'",
        ).run(RESOURCE_CATALOG_SCHEMA_FINGERPRINT);
        db.prepare(`
            INSERT OR REPLACE INTO schema_meta(key, value)
            VALUES('delete_cleanup_schema_migrated_at_ms', ?)
        `).run(String(nowMs));
        db.exec(`PRAGMA user_version = ${RESOURCE_CATALOG_SCHEMA_VERSION};`);
        db.exec("COMMIT;");
        return true;
    } catch (error) {
        rollbackQuietly(db);
        throw error;
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
        let migrated = false;
        if (!initialized) {
            created = createFreshSchema(db, nowMs);
        } else {
            migrated = migrateV2Schema(db, {
                busyTimeoutMs,
                integrityCheckAdapter,
                nowMs,
            });
            if (!migrated) {
                migrated = migrateV3Schema(db, {
                    busyTimeoutMs,
                    integrityCheckAdapter,
                    nowMs,
                });
            }
            if (!migrated) {
                migrated = migrateV4Schema(db, {
                    busyTimeoutMs,
                    integrityCheckAdapter,
                    nowMs,
                });
            }
            if (!migrated) {
                migrated = migrateV5Schema(db, {
                    busyTimeoutMs,
                    integrityCheckAdapter,
                    nowMs,
                });
            }
        }
        verifyResourceCatalogSchema(db, {
            busyTimeoutMs,
            integrityCheckAdapter,
        });
        return Object.freeze({
            created,
            migrated,
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
