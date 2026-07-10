// crucible/persistence/schema.mjs
//
// Schema definition, explicit version stamping, and connection configuration
// for the Crucible event repository.
//
// Versioning is explicit and fail-closed: the schema version is stamped both in
// `PRAGMA user_version` and in the `schema_meta` table. Opening a database
// created by a newer/older incompatible schema throws SchemaVersionError rather
// than silently migrating or corrupting data.

import { SchemaVersionError, StorageError } from "./errors.mjs";

export const SCHEMA_VERSION = 4;

// Terminal event kinds. At most one of these may exist per investigation.
export const TERMINAL_KINDS = Object.freeze(["verified_result", "target_unreachable"]);

// Command lifecycle states, in legal forward order.
export const COMMAND_STATES = Object.freeze(["reserved", "dispatched", "observed", "committed", "abandoned"]);

const DDL = `
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One row per investigation. The event log below is partitioned by this id.
CREATE TABLE investigations (
    investigation_id TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    metadata         TEXT NOT NULL DEFAULT '{}'
);

-- Append-only event log. seq is 1-based and contiguous per investigation.
-- prev_hash links each event to its predecessor (GENESIS for the first).
-- event_hash is the repository-computed structural hash of the row.
CREATE TABLE events (
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    seq              INTEGER NOT NULL,
    prev_hash        TEXT    NOT NULL,
    event_hash       TEXT    NOT NULL,
    kind             TEXT    NOT NULL,
    payload          TEXT    NOT NULL,          -- canonical JSON string
    is_terminal      INTEGER NOT NULL DEFAULT 0,
    terminal_kind    TEXT,                      -- non-null iff is_terminal=1
    attempt_id       TEXT,                      -- set for evidence events
    evidence_kind    TEXT,                      -- set for evidence events
    created_at       TEXT    NOT NULL,
    PRIMARY KEY (investigation_id, seq),
    CHECK (is_terminal IN (0, 1)),
    CHECK ((is_terminal = 1) = (terminal_kind IS NOT NULL)),
    CHECK (terminal_kind IS NULL OR terminal_kind IN ('verified_result', 'target_unreachable')),
    CHECK ((attempt_id IS NULL) = (evidence_kind IS NULL))
);

-- Unique event hash per investigation (no two identical-content events).
CREATE UNIQUE INDEX ux_events_hash ON events(investigation_id, event_hash);

-- At most one terminal event per investigation.
CREATE UNIQUE INDEX ux_events_terminal ON events(investigation_id) WHERE is_terminal = 1;

-- Idempotent, commutative evidence: at most one event per
-- (investigation, attempt, evidence_kind).
CREATE UNIQUE INDEX ux_events_evidence
    ON events(investigation_id, attempt_id, evidence_kind)
    WHERE evidence_kind IS NOT NULL;

CREATE INDEX ix_events_kind ON events(investigation_id, kind);

-- Runner leases + monotonic fencing tokens. fencing_token increases per
-- investigation on each acquisition; the newest token is the valid one.
CREATE TABLE runner_leases (
    lease_id         TEXT    PRIMARY KEY,
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    owner            TEXT    NOT NULL,
    fencing_token    INTEGER NOT NULL,
    supervisor_generation INTEGER,
    runner_incarnation TEXT,
    acquired_at      TEXT    NOT NULL,
    released_at      TEXT,
    CHECK (supervisor_generation IS NULL OR supervisor_generation > 0),
    UNIQUE (investigation_id, fencing_token)
);

CREATE INDEX ix_leases_inv ON runner_leases(investigation_id, fencing_token);

-- Durable command lifecycle. A reservation is a row in state 'reserved'.
CREATE TABLE command_attempts (
    attempt_id       TEXT    PRIMARY KEY,
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    command          TEXT    NOT NULL,
    state            TEXT    NOT NULL,
    lease_id         TEXT    NOT NULL REFERENCES runner_leases(lease_id),
    fencing_token    INTEGER NOT NULL,
    owner            TEXT    NOT NULL,
    supervisor_generation INTEGER,
    runner_incarnation TEXT,
    reserved_at      TEXT    NOT NULL,
    dispatched_at    TEXT,
    observed_at      TEXT,
    committed_at     TEXT,
    abandoned_at     TEXT,
    updated_at       TEXT    NOT NULL,
    CHECK (state IN ('reserved', 'dispatched', 'observed', 'committed', 'abandoned')),
    CHECK (supervisor_generation IS NULL OR supervisor_generation > 0)
);

-- At most one active (uncommitted) reservation per (investigation, command).
CREATE UNIQUE INDEX ux_active_reservation
    ON command_attempts(investigation_id, command)
    WHERE state NOT IN ('committed', 'abandoned');

-- Durable supervisor generation authority and single-use runner launches.
-- The current generation is the authoritative high-water mark. Each launch
-- receives a globally unique incarnation which is consumed by exactly one
-- lease acquisition and retained for audit/recovery fencing.
CREATE TABLE runner_incarnations (
    runner_incarnation    TEXT    PRIMARY KEY,
    investigation_id     TEXT    NOT NULL REFERENCES investigations(investigation_id),
    supervisor_generation INTEGER NOT NULL,
    supervisor_nonce      TEXT    NOT NULL,
    issued_at             TEXT    NOT NULL,
    consumed_at           TEXT,
    revoked_at            TEXT,
    lease_id              TEXT    UNIQUE REFERENCES runner_leases(lease_id),
    CHECK (supervisor_generation > 0),
    CHECK ((consumed_at IS NULL) = (lease_id IS NULL))
);

CREATE INDEX ix_runner_incarnations_authority
    ON runner_incarnations(investigation_id, supervisor_generation, issued_at);

CREATE TABLE supervisor_authority (
    investigation_id          TEXT    PRIMARY KEY REFERENCES investigations(investigation_id),
    supervisor_generation     INTEGER NOT NULL,
    supervisor_nonce          TEXT    NOT NULL,
    current_runner_incarnation TEXT REFERENCES runner_incarnations(runner_incarnation),
    claimed_at                TEXT    NOT NULL,
    updated_at                TEXT    NOT NULL,
    CHECK (supervisor_generation > 0)
);

-- Artifacts: either inline BLOB or an external algorithm-tagged hash.
-- External artifacts start non-durable (durable=0) and may only be referenced
-- once the caller marks them durable. Inline artifacts are durable by nature.
CREATE TABLE artifacts (
    artifact_id      TEXT    PRIMARY KEY,
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    storage          TEXT    NOT NULL,          -- 'inline' | 'external'
    content_type     TEXT,
    size_bytes       INTEGER,
    inline_blob      BLOB,
    hash_algo        TEXT,                       -- e.g. 'sha256' (external)
    hash_value       TEXT,                       -- hex digest (external)
    durable          INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL,
    CHECK (storage IN ('inline', 'external')),
    CHECK (durable IN (0, 1)),
    CHECK (
        (storage = 'inline'
            AND inline_blob IS NOT NULL
            AND hash_algo IS NULL
            AND hash_value IS NULL
            AND durable = 1)
        OR
        (storage = 'external'
            AND inline_blob IS NULL
            AND hash_algo IS NOT NULL
            AND hash_value IS NOT NULL)
    )
);

-- References binding an artifact to (optionally) an event seq. Referencing an
-- external artifact requires durable=1 (enforced in the repository).
CREATE TABLE artifact_refs (
    ref_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    artifact_id      TEXT    NOT NULL REFERENCES artifacts(artifact_id),
    seq              INTEGER,
    created_at       TEXT    NOT NULL,
    UNIQUE (artifact_id, seq)
);

-- Projection / read-model checkpoints. '*' investigation_id = global.
CREATE TABLE projection_metadata (
    projection_name  TEXT    NOT NULL,
    investigation_id TEXT    NOT NULL DEFAULT '*',
    last_applied_seq INTEGER NOT NULL DEFAULT 0,
    checkpoint       TEXT,
    updated_at       TEXT    NOT NULL,
    PRIMARY KEY (projection_name, investigation_id)
);
`;

// Apply the pragmas that make this connection safe and durable. Called on every
// open (pragmas are per-connection, not stored in the file).
export function configureConnection(db, { busyTimeoutMs }) {
    // Order matters: foreign_keys is per-connection and must be set explicitly.
    db.exec("PRAGMA foreign_keys = ON;");
    // WAL is a persistent, file-level mode but we (re)assert it on open.
    const jm = db.prepare("PRAGMA journal_mode = WAL;").get();
    if (!jm || String(jm.journal_mode).toLowerCase() !== "wal") {
        throw new StorageError(
            `failed to enable WAL journal mode (got ${JSON.stringify(jm)})`,
            null,
        );
    }
    db.exec("PRAGMA synchronous = FULL;");
    db.exec(`PRAGMA busy_timeout = ${Number(busyTimeoutMs)};`);
}

function readUserVersion(db) {
    const row = db.prepare("PRAGMA user_version;").get();
    return row ? Number(row.user_version) : 0;
}

function tableExists(db, name) {
    const row = db
        .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?")
        .get(name);
    return Boolean(row);
}

function migrateVersion2To3(db) {
    db.exec("BEGIN IMMEDIATE;");
    try {
        const userVersion = readUserVersion(db);
        const metaRow = db
            .prepare("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            .get();
        const metaVersion = metaRow ? Number(metaRow.value) : NaN;
        if ((userVersion === 3 && metaVersion === 3)
            || (userVersion === SCHEMA_VERSION && metaVersion === SCHEMA_VERSION)) {
            db.exec("COMMIT;");
            return false;
        }
        if (userVersion !== 2 || metaVersion !== 2) {
            throw new SchemaVersionError(
                "schema version changed while waiting to migrate",
                {
                    fileUserVersion: userVersion,
                    fileMetaVersion: metaRow ? metaRow.value : null,
                    expected: 2,
                },
            );
        }
        db.exec("ALTER TABLE runner_leases ADD COLUMN supervisor_generation INTEGER;");
        db.exec("ALTER TABLE command_attempts ADD COLUMN supervisor_generation INTEGER;");
        db.prepare("UPDATE schema_meta SET value = ? WHERE key = 'schema_version'")
            .run("3");
        db.exec("PRAGMA user_version = 3;");
        db.exec("COMMIT;");
        return true;
    } catch (err) {
        db.exec("ROLLBACK;");
        throw err;
    }
}

function migrateVersion3To4(db) {
    db.exec("BEGIN IMMEDIATE;");
    try {
        const userVersion = readUserVersion(db);
        const metaRow = db
            .prepare("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            .get();
        const metaVersion = metaRow ? Number(metaRow.value) : NaN;
        if (userVersion === SCHEMA_VERSION && metaVersion === SCHEMA_VERSION) {
            db.exec("COMMIT;");
            return false;
        }
        if (userVersion !== 3 || metaVersion !== 3) {
            throw new SchemaVersionError(
                "schema version changed while waiting to migrate",
                {
                    fileUserVersion: userVersion,
                    fileMetaVersion: metaRow ? metaRow.value : null,
                    expected: 3,
                },
            );
        }
        db.exec("ALTER TABLE runner_leases ADD COLUMN runner_incarnation TEXT;");
        db.exec("ALTER TABLE command_attempts ADD COLUMN runner_incarnation TEXT;");
        db.exec(`
            CREATE TABLE runner_incarnations (
                runner_incarnation    TEXT    PRIMARY KEY,
                investigation_id     TEXT    NOT NULL REFERENCES investigations(investigation_id),
                supervisor_generation INTEGER NOT NULL,
                supervisor_nonce      TEXT    NOT NULL,
                issued_at             TEXT    NOT NULL,
                consumed_at           TEXT,
                revoked_at            TEXT,
                lease_id              TEXT    UNIQUE REFERENCES runner_leases(lease_id),
                CHECK (supervisor_generation > 0),
                CHECK ((consumed_at IS NULL) = (lease_id IS NULL))
            );
            CREATE INDEX ix_runner_incarnations_authority
                ON runner_incarnations(investigation_id, supervisor_generation, issued_at);
            CREATE TABLE supervisor_authority (
                investigation_id          TEXT    PRIMARY KEY REFERENCES investigations(investigation_id),
                supervisor_generation     INTEGER NOT NULL,
                supervisor_nonce          TEXT    NOT NULL,
                current_runner_incarnation TEXT REFERENCES runner_incarnations(runner_incarnation),
                claimed_at                TEXT    NOT NULL,
                updated_at                TEXT    NOT NULL,
                CHECK (supervisor_generation > 0)
            );
        `);
        db.prepare("UPDATE schema_meta SET value = ? WHERE key = 'schema_version'")
            .run(String(SCHEMA_VERSION));
        db.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`);
        db.exec("COMMIT;");
        return true;
    } catch (err) {
        db.exec("ROLLBACK;");
        throw err;
    }
}

// Create the schema on a fresh database, or verify the version of an existing
// one. Runs inside a single transaction. Throws SchemaVersionError on mismatch.
export function applySchema(db) {
    const alreadyInitialized = tableExists(db, "schema_meta");

    if (alreadyInitialized) {
        const userVersion = readUserVersion(db);
        const metaRow = db
            .prepare("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            .get();
        const metaVersion = metaRow ? Number(metaRow.value) : NaN;
        if (userVersion === 2 && metaVersion === 2) {
            migrateVersion2To3(db);
            migrateVersion3To4(db);
            return { created: false, migrated: true, version: SCHEMA_VERSION };
        }
        if (userVersion === 3 && metaVersion === 3) {
            const migrated = migrateVersion3To4(db);
            return { created: false, migrated, version: SCHEMA_VERSION };
        }
        if (userVersion !== SCHEMA_VERSION || metaVersion !== SCHEMA_VERSION) {
            throw new SchemaVersionError(
                `schema version mismatch: file has user_version=${userVersion}, schema_meta=${metaRow ? metaRow.value : "<none>"}, expected ${SCHEMA_VERSION}`,
                { fileUserVersion: userVersion, fileMetaVersion: metaRow ? metaRow.value : null, expected: SCHEMA_VERSION },
            );
        }
        return { created: false, version: SCHEMA_VERSION };
    }

    db.exec("BEGIN IMMEDIATE;");
    try {
        db.exec(DDL);
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)")
            .run(String(SCHEMA_VERSION));
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('created_at', ?)")
            .run(new Date().toISOString());
        db.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`);
        db.exec("COMMIT;");
    } catch (err) {
        db.exec("ROLLBACK;");
        throw err;
    }
    return { created: true, version: SCHEMA_VERSION };
}
