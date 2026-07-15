// crucible/persistence/schema.mjs
//
// Canonical schema definition, connection configuration, and fail-closed
// verification for the Crucible event repository.

import { createHash } from "node:crypto";

import { DatabaseSync } from "./sqlite.mjs";
import { canonicalize } from "./canonical.mjs";
import {
    CruciblePersistenceError,
    DatabaseIntegrityError,
    InvalidArgumentError,
    SchemaIntegrityError,
    SchemaVersionError,
    StorageError,
} from "./errors.mjs";

export const SCHEMA_VERSION = 6;
export const EVENT_HASH_VERSION = 2;

export const TERMINAL_KINDS = Object.freeze(["verified_result", "target_unreachable"]);
export const COMMAND_STATES = Object.freeze(["reserved", "dispatched", "observed", "committed", "abandoned"]);

const FINGERPRINT_FORMAT_VERSION = 1;
const EXPECTED_CONNECTION_PRAGMAS = Object.freeze({
    foreignKeys: 1,
    journalMode: "wal",
    synchronous: 2,
});

const RUNNER_LEASE_INDEX_DDL =
    "CREATE INDEX ix_leases_inv ON runner_leases(investigation_id, fencing_token);";
const COMMAND_ATTEMPT_INDEX_DDL = `
CREATE UNIQUE INDEX ux_active_reservation
    ON command_attempts(investigation_id, command)
    WHERE state NOT IN ('committed', 'abandoned');`;
const QUIESCENT_STOPS_TABLE_DDL = `
CREATE TABLE quiescent_stops (
    investigation_id           TEXT    PRIMARY KEY REFERENCES investigations(investigation_id),
    request_id                 TEXT    NOT NULL,
    reason                     TEXT    NOT NULL,
    pause_requested            INTEGER NOT NULL,
    state                      TEXT    NOT NULL,
    target_supervisor_generation INTEGER,
    target_supervisor_nonce    TEXT,
    target_supervisor_pid      INTEGER,
    target_runner_incarnation  TEXT,
    target_runner_pid          INTEGER,
    target_lease_id            TEXT,
    target_fencing_token       INTEGER,
    fenced_attempts            TEXT    NOT NULL,
    requested_at               TEXT    NOT NULL,
    barrier_at                 TEXT    NOT NULL,
    acknowledged_at            TEXT,
    completed_at               TEXT,
    quiescent                  INTEGER NOT NULL DEFAULT 0,
    intervention_required      INTEGER NOT NULL DEFAULT 0,
    non_result_code            TEXT,
    details                    TEXT    NOT NULL,
    updated_at                 TEXT    NOT NULL,
    CHECK (pause_requested IN (0, 1)),
    CHECK (state IN (
        'STOP_BARRIER_PERSISTED',
        'STOP_RECONCILING',
        'STOP_SUPERSEDED',
        'PAUSE_PENDING',
        'PAUSED_QUIESCENT'
    )),
    CHECK (quiescent IN (0, 1)),
    CHECK (intervention_required IN (0, 1)),
    CHECK (
        target_supervisor_generation IS NULL
        OR target_supervisor_generation > 0
    ),
    CHECK (target_supervisor_pid IS NULL OR target_supervisor_pid > 0),
    CHECK (target_runner_pid IS NULL OR target_runner_pid > 0),
    CHECK (target_fencing_token IS NULL OR target_fencing_token > 0),
    CHECK (
        (target_supervisor_generation IS NULL)
        = (target_supervisor_nonce IS NULL)
    ),
    CHECK (
        (target_lease_id IS NULL)
        = (target_fencing_token IS NULL)
    )
);`;

function runnerLeasesTableDdl(name) {
    return `CREATE TABLE ${name} (
    ${[
        "lease_id TEXT PRIMARY KEY",
        "investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id)",
        "owner TEXT NOT NULL",
        "fencing_token INTEGER NOT NULL",
        "supervisor_generation INTEGER",
        "runner_incarnation TEXT",
        "acquired_at TEXT NOT NULL",
        "released_at TEXT",
        "CHECK (supervisor_generation IS NULL OR supervisor_generation > 0)",
        "UNIQUE (investigation_id, fencing_token)",
    ].join(",\n    ")}
);`;
}

function commandAttemptsTableDdl(name) {
    return `CREATE TABLE ${name} (
    ${[
        "attempt_id TEXT PRIMARY KEY",
        "investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id)",
        "command TEXT NOT NULL",
        "state TEXT NOT NULL",
        "lease_id TEXT NOT NULL REFERENCES runner_leases(lease_id)",
        "fencing_token INTEGER NOT NULL",
        "owner TEXT NOT NULL",
        "supervisor_generation INTEGER",
        "runner_incarnation TEXT",
        "reserved_at TEXT NOT NULL",
        "dispatched_at TEXT",
        "observed_at TEXT",
        "committed_at TEXT",
        "abandoned_at TEXT",
        "updated_at TEXT NOT NULL",
        "CHECK (state IN ('reserved', 'dispatched', 'observed', 'committed', 'abandoned'))",
        "CHECK (supervisor_generation IS NULL OR supervisor_generation > 0)",
    ].join(",\n    ")}
);`;
}

const DDL = `
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE investigations (
    investigation_id TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    metadata         TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE events (
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    seq              INTEGER NOT NULL,
    prev_hash        TEXT    NOT NULL,
    event_hash       TEXT    NOT NULL,
    kind             TEXT    NOT NULL,
    payload          TEXT    NOT NULL,
    is_terminal      INTEGER NOT NULL DEFAULT 0,
    terminal_kind    TEXT,
    attempt_id       TEXT,
    evidence_kind    TEXT,
    created_at       TEXT    NOT NULL,
    PRIMARY KEY (investigation_id, seq),
    CHECK (is_terminal IN (0, 1)),
    CHECK ((is_terminal = 1) = (terminal_kind IS NOT NULL)),
    CHECK (terminal_kind IS NULL OR terminal_kind IN ('verified_result', 'target_unreachable')),
    CHECK ((attempt_id IS NULL) = (evidence_kind IS NULL))
);

CREATE UNIQUE INDEX ux_events_hash ON events(investigation_id, event_hash);
CREATE UNIQUE INDEX ux_events_terminal ON events(investigation_id) WHERE is_terminal = 1;
CREATE UNIQUE INDEX ux_events_evidence
    ON events(investigation_id, attempt_id, evidence_kind)
    WHERE evidence_kind IS NOT NULL;
CREATE INDEX ix_events_kind ON events(investigation_id, kind);

${runnerLeasesTableDdl("runner_leases")}
${RUNNER_LEASE_INDEX_DDL}

${commandAttemptsTableDdl("command_attempts")}
${COMMAND_ATTEMPT_INDEX_DDL}

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

${QUIESCENT_STOPS_TABLE_DDL}

CREATE TABLE artifacts (
    artifact_id      TEXT    PRIMARY KEY,
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    storage          TEXT    NOT NULL,
    content_type     TEXT,
    size_bytes       INTEGER,
    hash_algo        TEXT    NOT NULL,
    hash_value       TEXT    NOT NULL,
    durable          INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL,
    CHECK (storage = 'external'),
    CHECK (durable IN (0, 1))
);

CREATE TABLE artifact_refs (
    ref_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT    NOT NULL REFERENCES investigations(investigation_id),
    artifact_id      TEXT    NOT NULL REFERENCES artifacts(artifact_id),
    seq              INTEGER,
    created_at       TEXT    NOT NULL,
    UNIQUE (artifact_id, seq)
);

`;

function normalizeBusyTimeout(value) {
    const normalized = Number(value);
    if (!Number.isSafeInteger(normalized) || normalized < 0) {
        throw new InvalidArgumentError(
            "busyTimeoutMs must be a non-negative safe integer",
            { busyTimeoutMs: value },
        );
    }
    return normalized;
}

function pragmaScalar(db, name) {
    const row = db.prepare(`PRAGMA ${name};`).get();
    return row ? Object.values(row)[0] : undefined;
}

function readObservedPragmas(db) {
    return {
        foreignKeys: Number(pragmaScalar(db, "foreign_keys")),
        journalMode: String(pragmaScalar(db, "journal_mode") ?? "").toLowerCase(),
        synchronous: Number(pragmaScalar(db, "synchronous")),
        userVersion: Number(pragmaScalar(db, "user_version")),
    };
}

function assertConnectionPragmas(db, {
    busyTimeoutMs,
    expectedVersion,
    expectedJournalMode = EXPECTED_CONNECTION_PRAGMAS.journalMode,
} = {}) {
    const observed = readObservedPragmas(db);
    const expected = {
        ...EXPECTED_CONNECTION_PRAGMAS,
        journalMode: expectedJournalMode,
        userVersion: expectedVersion,
    };
    if (canonicalize(observed) !== canonicalize(expected)) {
        throw new SchemaIntegrityError(
            "SQLite connection pragmas do not match the canonical persistence contract",
            { expected, observed },
        );
    }
    if (busyTimeoutMs !== undefined) {
        const expectedTimeout = normalizeBusyTimeout(busyTimeoutMs);
        const observedTimeout = Number(pragmaScalar(db, "busy_timeout"));
        if (observedTimeout !== expectedTimeout) {
            throw new SchemaIntegrityError(
                "SQLite busy_timeout does not match the requested connection contract",
                { expected: expectedTimeout, observed: observedTimeout },
            );
        }
    }
    return observed;
}

export function configureConnection(db, { busyTimeoutMs }) {
    const timeout = normalizeBusyTimeout(busyTimeoutMs);
    db.exec("PRAGMA foreign_keys = ON;");
    const journalMode = db.prepare("PRAGMA journal_mode = WAL;").get();
    if (!journalMode || String(journalMode.journal_mode).toLowerCase() !== "wal") {
        throw new StorageError(
            `failed to enable WAL journal mode (got ${JSON.stringify(journalMode)})`,
            null,
        );
    }
    db.exec("PRAGMA synchronous = FULL;");
    db.exec(`PRAGMA busy_timeout = ${timeout};`);
}

export function configureReadOnlyConnection(db, { busyTimeoutMs }) {
    const timeout = normalizeBusyTimeout(busyTimeoutMs);
    db.exec(`
        PRAGMA foreign_keys = ON;
        PRAGMA synchronous = FULL;
        PRAGMA busy_timeout = ${timeout};
        PRAGMA query_only = ON;
    `);
    if (Number(pragmaScalar(db, "query_only")) !== 1) {
        throw new StorageError("failed to enable SQLite query_only mode", null);
    }
}

function sqlQuote(value) {
    return `'${String(value).replaceAll("'", "''")}'`;
}

function pragmaRows(db, pragma, argument) {
    return db.prepare(`PRAGMA ${pragma}(${sqlQuote(argument)});`).all();
}

function cleanSql(sql) {
    const source = String(sql ?? "");
    let output = "";
    let quote = null;
    let lineComment = false;
    let blockComment = false;
    let pendingSpace = false;

    for (let index = 0; index < source.length; index += 1) {
        const ch = source[index];
        const next = source[index + 1];

        if (lineComment) {
            if (ch === "\n" || ch === "\r") {
                lineComment = false;
                pendingSpace = true;
            }
            continue;
        }
        if (blockComment) {
            if (ch === "*" && next === "/") {
                blockComment = false;
                pendingSpace = true;
                index += 1;
            }
            continue;
        }
        if (quote !== null) {
            output += ch;
            if (quote === "[") {
                if (ch === "]") {
                    quote = null;
                }
            } else if (ch === quote) {
                if (next === quote) {
                    output += next;
                    index += 1;
                } else {
                    quote = null;
                }
            }
            continue;
        }
        if (ch === "-" && next === "-") {
            lineComment = true;
            pendingSpace = true;
            index += 1;
            continue;
        }
        if (ch === "/" && next === "*") {
            blockComment = true;
            pendingSpace = true;
            index += 1;
            continue;
        }
        if (ch === "'" || ch === "\"" || ch === "`" || ch === "[") {
            if (pendingSpace && output.length > 0 && !output.endsWith(" ")) {
                output += " ";
            }
            pendingSpace = false;
            quote = ch;
            output += ch;
            continue;
        }
        if (/\s/u.test(ch)) {
            pendingSpace = true;
            continue;
        }
        if (pendingSpace && output.length > 0 && !output.endsWith(" ")) {
            output += " ";
        }
        pendingSpace = false;
        output += ch;
    }
    return output.trim();
}

function tableBodyBounds(sql) {
    let quote = null;
    let depth = 0;
    let open = -1;
    for (let index = 0; index < sql.length; index += 1) {
        const ch = sql[index];
        const next = sql[index + 1];
        if (quote !== null) {
            if (quote === "[") {
                if (ch === "]") {
                    quote = null;
                }
            } else if (ch === quote) {
                if (next === quote) {
                    index += 1;
                } else {
                    quote = null;
                }
            }
            continue;
        }
        if (ch === "'" || ch === "\"" || ch === "`" || ch === "[") {
            quote = ch;
            continue;
        }
        if (ch === "(") {
            if (open === -1) {
                open = index;
            }
            depth += 1;
        } else if (ch === ")") {
            depth -= 1;
            if (open !== -1 && depth === 0) {
                return { open, close: index };
            }
        }
    }
    return null;
}

function splitTopLevelClauses(body) {
    const clauses = [];
    let start = 0;
    let quote = null;
    let depth = 0;
    for (let index = 0; index < body.length; index += 1) {
        const ch = body[index];
        const next = body[index + 1];
        if (quote !== null) {
            if (quote === "[") {
                if (ch === "]") {
                    quote = null;
                }
            } else if (ch === quote) {
                if (next === quote) {
                    index += 1;
                } else {
                    quote = null;
                }
            }
            continue;
        }
        if (ch === "'" || ch === "\"" || ch === "`" || ch === "[") {
            quote = ch;
        } else if (ch === "(") {
            depth += 1;
        } else if (ch === ")") {
            depth -= 1;
        } else if (ch === "," && depth === 0) {
            clauses.push(cleanSql(body.slice(start, index)));
            start = index + 1;
        }
    }
    clauses.push(cleanSql(body.slice(start)));
    return clauses.filter((clause) => clause.length > 0).sort();
}

function canonicalTableDdl(sql) {
    const cleaned = cleanSql(sql);
    const bounds = tableBodyBounds(cleaned);
    if (!bounds) {
        return { clauses: [], suffix: cleaned };
    }
    return {
        clauses: splitTopLevelClauses(cleaned.slice(bounds.open + 1, bounds.close)),
        suffix: cleanSql(cleaned.slice(bounds.close + 1)),
    };
}

function sortCanonical(values) {
    return values.sort((left, right) =>
        canonicalize(left).localeCompare(canonicalize(right)));
}

function buildSchemaManifest(db) {
    const objects = db.prepare(`
        SELECT type, name, tbl_name, sql
        FROM sqlite_schema
        WHERE type IN ('table', 'index', 'trigger', 'view')
          AND name NOT LIKE 'sqlite_%'
        ORDER BY type, name
    `).all();

    const tables = objects
        .filter((object) => object.type === "table")
        .map((object) => {
            const columns = pragmaRows(db, "table_xinfo", object.name).map((row) => ({
                name: String(row.name),
                type: String(row.type ?? ""),
                notNull: Number(row.notnull),
                defaultValue: row.dflt_value ?? null,
                primaryKeyPosition: Number(row.pk),
                hidden: Number(row.hidden),
            })).sort((left, right) => left.name.localeCompare(right.name));

            const foreignKeys = sortCanonical(
                pragmaRows(db, "foreign_key_list", object.name).map((row) => ({
                    sequence: Number(row.seq),
                    table: String(row.table),
                    from: row.from ?? null,
                    to: row.to ?? null,
                    onUpdate: String(row.on_update),
                    onDelete: String(row.on_delete),
                    match: String(row.match),
                })),
            );

            const indexes = sortCanonical(
                pragmaRows(db, "index_list", object.name).map((row) => ({
                    name: row.origin === "c" ? String(row.name) : null,
                    unique: Number(row.unique),
                    origin: String(row.origin),
                    partial: Number(row.partial),
                    columns: pragmaRows(db, "index_xinfo", row.name)
                        .map((column) => ({
                            sequence: Number(column.seqno),
                            columnId: Number(column.cid),
                            name: column.name ?? null,
                            descending: Number(column.desc),
                            collation: column.coll ?? null,
                            key: Number(column.key),
                        }))
                        .sort((left, right) => left.sequence - right.sequence),
                })),
            );

            return {
                name: String(object.name),
                ddl: canonicalTableDdl(object.sql),
                columns,
                foreignKeys,
                indexes,
            };
        })
        .sort((left, right) => left.name.localeCompare(right.name));

    const ddlObjects = objects.map((object) => ({
        type: String(object.type),
        name: String(object.name),
        table: String(object.tbl_name),
        ddl: object.type === "table"
            ? canonicalTableDdl(object.sql)
            : cleanSql(object.sql),
    }));

    return { ddlObjects, tables };
}

function structuralFingerprint(manifest) {
    return createHash("sha256")
        .update(canonicalize({
            formatVersion: FINGERPRINT_FORMAT_VERSION,
            manifest,
        }))
        .digest("hex");
}

function schemaFingerprint(manifest, pragmas, schemaVersion, eventHashVersion) {
    return createHash("sha256")
        .update(canonicalize({
            formatVersion: FINGERPRINT_FORMAT_VERSION,
            schemaVersion,
            eventHashVersion,
            pragmas,
            manifest,
        }))
        .digest("hex");
}

function expectedManifest() {
    const db = new DatabaseSync(":memory:");
    try {
        db.exec(DDL);
        return buildSchemaManifest(db);
    } finally {
        db.close();
    }
}

const EXPECTED_MANIFEST = expectedManifest();

export const SCHEMA_FINGERPRINT = schemaFingerprint(
    EXPECTED_MANIFEST,
    {
        ...EXPECTED_CONNECTION_PRAGMAS,
        userVersion: SCHEMA_VERSION,
    },
    SCHEMA_VERSION,
    EVENT_HASH_VERSION,
);

function assertCurrentSchemaStructure(db) {
    const actualManifest = buildSchemaManifest(db);
    const actualFingerprint = structuralFingerprint(actualManifest);
    const expectedFingerprint = structuralFingerprint(EXPECTED_MANIFEST);
    if (actualFingerprint === expectedFingerprint) {
        return { manifest: actualManifest, fingerprint: actualFingerprint };
    }
    throw new SchemaIntegrityError(
        "database schema does not match the current canonical definition",
        {
            schemaVersion: SCHEMA_VERSION,
            actualFingerprint,
            expectedFingerprint,
        },
    );
}

function tableExists(db, name) {
    return Boolean(db
        .prepare("SELECT 1 AS present FROM sqlite_schema WHERE type = 'table' AND name = ?")
        .get(name));
}

function readUserVersion(db) {
    return Number(pragmaScalar(db, "user_version") ?? 0);
}

function readMetaValue(db, key) {
    return db.prepare("SELECT value FROM schema_meta WHERE key = ?").get(key)?.value ?? null;
}

function readVersionPair(db) {
    try {
        const userVersion = readUserVersion(db);
        const metaValue = readMetaValue(db, "schema_version");
        const metaVersion = metaValue === null ? Number.NaN : Number(metaValue);
        return { userVersion, metaValue, metaVersion };
    } catch (err) {
        if (err instanceof CruciblePersistenceError) {
            throw err;
        }
        throw new SchemaIntegrityError(
            "failed to read required schema metadata",
            { sqliteCode: err?.code, message: err?.message },
        );
    }
}

function assertVersionPair(db, expected) {
    const pair = readVersionPair(db);
    if (pair.userVersion !== expected || pair.metaVersion !== expected) {
        throw new SchemaVersionError(
            `schema version mismatch: file has user_version=${pair.userVersion}, schema_meta=${pair.metaValue ?? "<none>"}, expected ${expected}`,
            {
                fileUserVersion: pair.userVersion,
                fileMetaVersion: pair.metaValue,
                expected,
            },
        );
    }
    return pair;
}

function adapterRows(adapter, method, fallback, db, check) {
    try {
        const fn = adapter?.[method];
        return fn === undefined ? fallback(db) : fn(db);
    } catch (err) {
        if (err instanceof CruciblePersistenceError) {
            throw err;
        }
        throw new DatabaseIntegrityError(
            `failed to execute PRAGMA ${check}`,
            { check, sqliteCode: err?.code, message: err?.message },
        );
    }
}

export function verifyDatabaseIntegrity(db, { adapter = undefined } = {}) {
    const integrityRows = adapterRows(
        adapter,
        "integrityCheck",
        (database) => database.prepare("PRAGMA integrity_check;").all(),
        db,
        "integrity_check",
    );
    const integrityOk = Array.isArray(integrityRows)
        && integrityRows.length === 1
        && String(Object.values(integrityRows[0] ?? {})[0] ?? "") === "ok";
    if (!integrityOk) {
        throw new DatabaseIntegrityError(
            "SQLite integrity_check did not return exactly one 'ok' row",
            { check: "integrity_check", rows: integrityRows },
        );
    }

    const foreignKeyRows = adapterRows(
        adapter,
        "foreignKeyCheck",
        (database) => database.prepare("PRAGMA foreign_key_check;").all(),
        db,
        "foreign_key_check",
    );
    if (!Array.isArray(foreignKeyRows) || foreignKeyRows.length !== 0) {
        throw new DatabaseIntegrityError(
            "SQLite foreign_key_check reported violations",
            { check: "foreign_key_check", rows: foreignKeyRows },
        );
    }
    return { integrityCheck: "ok", foreignKeyViolations: 0 };
}

function rollbackQuietly(db) {
    try {
        db.exec("ROLLBACK;");
    } catch {
        // The original typed failure is more useful.
    }
}

function createFreshSchema(db) {
    db.exec("BEGIN IMMEDIATE;");
    try {
        db.exec(DDL);
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)")
            .run(String(SCHEMA_VERSION));
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('created_at', ?)")
            .run(new Date().toISOString());
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('schema_fingerprint', ?)")
            .run(SCHEMA_FINGERPRINT);
        db.prepare("INSERT INTO schema_meta(key, value) VALUES('event_hash_version', ?)")
            .run(String(EVENT_HASH_VERSION));
        db.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`);
        db.exec("COMMIT;");
    } catch (err) {
        rollbackQuietly(db);
        throw err;
    }
}

export function verifySchema(db, {
    busyTimeoutMs = undefined,
    integrityCheckAdapter = undefined,
    expectedJournalMode = EXPECTED_CONNECTION_PRAGMAS.journalMode,
} = {}) {
    assertVersionPair(db, SCHEMA_VERSION);
    const pragmas = assertConnectionPragmas(db, {
        busyTimeoutMs,
        expectedVersion: SCHEMA_VERSION,
        expectedJournalMode,
    });
    verifyDatabaseIntegrity(db, { adapter: integrityCheckAdapter });
    const matched = assertCurrentSchemaStructure(db);
    const fingerprintPragmas = expectedJournalMode
        === EXPECTED_CONNECTION_PRAGMAS.journalMode
        ? pragmas
        : {
            ...pragmas,
            journalMode: EXPECTED_CONNECTION_PRAGMAS.journalMode,
        };
    const actualFingerprint = schemaFingerprint(
        matched.manifest,
        fingerprintPragmas,
        SCHEMA_VERSION,
        EVENT_HASH_VERSION,
    );
    if (actualFingerprint !== SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "computed schema fingerprint does not match the canonical fingerprint",
            { expected: SCHEMA_FINGERPRINT, actual: actualFingerprint },
        );
    }
    const storedFingerprint = readMetaValue(db, "schema_fingerprint");
    if (storedFingerprint !== SCHEMA_FINGERPRINT) {
        throw new SchemaIntegrityError(
            "stored schema fingerprint does not match the canonical fingerprint",
            { expected: SCHEMA_FINGERPRINT, stored: storedFingerprint },
        );
    }
    const storedHashVersion = readMetaValue(db, "event_hash_version");
    if (storedHashVersion !== String(EVENT_HASH_VERSION)) {
        throw new SchemaIntegrityError(
            "stored event hash version does not match the canonical format",
            { expected: String(EVENT_HASH_VERSION), stored: storedHashVersion },
        );
    }
    return {
        version: SCHEMA_VERSION,
        fingerprint: SCHEMA_FINGERPRINT,
        eventHashVersion: EVENT_HASH_VERSION,
    };
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
    const userVersion = readUserVersion(db);
    if (objectCount !== 0 || userVersion !== 0) {
        throw new SchemaIntegrityError(
            "database contains schema objects but no schema_meta table",
            { objectCount, userVersion },
        );
    }
    return false;
}

export function applySchema(db, {
    busyTimeoutMs = undefined,
    integrityCheckAdapter = undefined,
} = {}) {
    const initialized = assertFreshOrInitialized(db);
    if (!initialized) {
        createFreshSchema(db);
        verifySchema(db, { busyTimeoutMs, integrityCheckAdapter });
        return {
            created: true,
            version: SCHEMA_VERSION,
            fingerprint: SCHEMA_FINGERPRINT,
        };
    }

    verifySchema(db, { busyTimeoutMs, integrityCheckAdapter });
    return {
        created: false,
        version: SCHEMA_VERSION,
        fingerprint: SCHEMA_FINGERPRINT,
    };
}
