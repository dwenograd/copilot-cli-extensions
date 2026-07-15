import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { TextDecoder } from "node:util";

import { DatabaseSync } from "./sqlite.mjs";
import {
    canonicalize,
    computeEventHash,
    GENESIS_PREV_HASH,
    inspectCanonicalJson,
    normalizeCreatedAt,
} from "./canonical.mjs";
import {
    CruciblePersistenceError,
    InvalidArgumentError,
    SegmentIntegrityError,
    SegmentRotationError,
    StorageError,
} from "./errors.mjs";
import {
    EVENT_HASH_VERSION,
    SCHEMA_FINGERPRINT,
    SCHEMA_VERSION,
} from "./schema.mjs";

const SEGMENT_CATALOG_TYPE = "crucible-event-segment-catalog";
const SEGMENT_CATALOG_VERSION = 1;
const SEGMENT_SCHEMA_VERSION = 1;
const DEFAULT_SEGMENT_EVENT_THRESHOLD = 50_000;
const DEFAULT_SEGMENT_BYTE_THRESHOLD = 256 * 1024 * 1024;

const UTF8 = new TextDecoder("utf-8", { fatal: true });
const HEX64_RE = /^[0-9a-f]{64}$/u;
const SAFE_BASENAME_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]+$/u;
const CATALOG_MAX_BYTES = 16 * 1024 * 1024;
const JOURNAL_TYPE = "crucible-event-segment-rotation";
const JOURNAL_VERSION = 1;
const HASH_BUFFER_SIZE = 1024 * 1024;

const CATALOG_KEYS = Object.freeze([
    "active",
    "generation",
    "hashAlgorithm",
    "segmentPrefix",
    "segments",
    "type",
    "version",
]);
const ACTIVE_KEYS = Object.freeze([
    "eventHashVersion",
    "index",
    "schemaFingerprint",
    "schemaVersion",
]);
const ENTRY_KEYS = Object.freeze([
    "domainVersion",
    "eventCount",
    "file",
    "fileSha256",
    "fileSize",
    "firstEventHash",
    "firstSeq",
    "index",
    "investigationId",
    "lastEventHash",
    "lastSeq",
    "previousSegmentAnchor",
    "schemaVersion",
    "sealedAt",
    "segmentSchemaVersion",
]);
const DESCRIPTOR_KEYS = Object.freeze(
    ENTRY_KEYS.filter((key) => key !== "fileSha256" && key !== "fileSize"),
);
const ANCHOR_KEYS = Object.freeze([
    "fileSha256",
    "index",
    "lastEventHash",
    "lastSeq",
]);
const JOURNAL_KEYS = Object.freeze([
    "baseGeneration",
    "descriptor",
    "entry",
    "operationId",
    "stage",
    "tempFile",
    "type",
    "version",
]);
const SEGMENT_SCHEMA_OBJECTS = Object.freeze([
    "events",
    "ix_segment_events_kind",
    "segment_meta",
    "ux_segment_events_evidence",
    "ux_segment_events_hash",
    "ux_segment_events_terminal",
]);
const EVENT_COLUMNS = Object.freeze([
    "investigation_id",
    "seq",
    "prev_hash",
    "event_hash",
    "kind",
    "payload",
    "is_terminal",
    "terminal_kind",
    "attempt_id",
    "evidence_kind",
    "created_at",
]);

const SEGMENT_DDL = `
CREATE TABLE segment_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE events (
    investigation_id TEXT    NOT NULL,
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

CREATE UNIQUE INDEX ux_segment_events_hash
    ON events(investigation_id, event_hash);
CREATE UNIQUE INDEX ux_segment_events_terminal
    ON events(investigation_id) WHERE is_terminal = 1;
CREATE UNIQUE INDEX ux_segment_events_evidence
    ON events(investigation_id, attempt_id, evidence_kind)
    WHERE evidence_kind IS NOT NULL;
CREATE INDEX ix_segment_events_kind
    ON events(investigation_id, kind);
`;

function exactKeys(value, keys) {
    return value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        && canonicalize(Object.keys(value).sort()) === canonicalize([...keys].sort());
}

function requireSafeBasename(value, field) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > 240
        || !SAFE_BASENAME_RE.test(value)
        || path.basename(value) !== value) {
        throw new SegmentIntegrityError(`${field} is not a safe local basename`, {
            field,
            value,
        });
    }
    return value;
}

function requirePositiveSafeInteger(value, field) {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new SegmentIntegrityError(`${field} must be a positive safe integer`, {
            field,
            value,
        });
    }
    return value;
}

function normalizeThreshold(value, fallback, field) {
    const chosen = value === undefined ? fallback : value;
    if (chosen === Number.POSITIVE_INFINITY) return chosen;
    if (!Number.isSafeInteger(chosen) || chosen < 1) {
        throw new InvalidArgumentError(
            `${field} must be a positive safe integer or Infinity`,
            { [field]: chosen },
        );
    }
    return chosen;
}

function stableStatIdentity(stat) {
    return {
        dev: stat.dev,
        ino: stat.ino,
        size: stat.size,
        mtimeNs: stat.mtimeNs,
    };
}

function sameStatIdentity(left, right) {
    return left.dev === right.dev
        && left.ino === right.ino
        && left.size === right.size
        && left.mtimeNs === right.mtimeNs;
}

function lstatRegularFile(file, label) {
    let stat;
    try {
        stat = fs.lstatSync(file, { bigint: true });
    } catch (error) {
        throw new SegmentIntegrityError(`${label} is missing or unreadable`, {
            file,
            fsCode: error?.code,
        });
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new SegmentIntegrityError(`${label} must be a regular non-link file`, {
            file,
        });
    }
    return stat;
}

function hashStableFile(file) {
    const before = lstatRegularFile(file, "segment file");
    const beforeIdentity = stableStatIdentity(before);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(HASH_BUFFER_SIZE);
    let fd;
    try {
        fd = fs.openSync(file, "r");
        let position = 0;
        for (;;) {
            const count = fs.readSync(fd, buffer, 0, buffer.length, position);
            if (count === 0) break;
            hash.update(buffer.subarray(0, count));
            position += count;
        }
        const afterFd = stableStatIdentity(fs.fstatSync(fd, { bigint: true }));
        if (!sameStatIdentity(beforeIdentity, afterFd)) {
            throw new SegmentIntegrityError("segment file changed while it was hashed", {
                file,
            });
        }
    } finally {
        if (fd !== undefined) fs.closeSync(fd);
    }
    const after = stableStatIdentity(lstatRegularFile(file, "segment file"));
    if (!sameStatIdentity(beforeIdentity, after)) {
        throw new SegmentIntegrityError("segment file identity changed while it was hashed", {
            file,
        });
    }
    return {
        hash: hash.digest("hex"),
        size: Number(before.size),
        identity: beforeIdentity,
    };
}

function fsyncFile(file) {
    const fd = fs.openSync(file, process.platform === "win32" ? "r+" : "r");
    try {
        fs.fsyncSync(fd);
    } finally {
        fs.closeSync(fd);
    }
}

function fsyncDirectory(directory) {
    let fd;
    try {
        fd = fs.openSync(directory, process.platform === "win32" ? "r+" : "r");
        fs.fsyncSync(fd);
    } catch (error) {
        throw new SegmentRotationError("failed to fsync segment directory", {
            directory,
            fsCode: error?.code,
            message: error?.message,
        });
    } finally {
        if (fd !== undefined) fs.closeSync(fd);
    }
}

function readBoundedFile(file, maximum, label) {
    const stat = lstatRegularFile(file, label);
    if (stat.size < 1n || stat.size > BigInt(maximum)) {
        throw new SegmentIntegrityError(`${label} size is invalid`, {
            file,
            size: Number(stat.size),
            maximum,
        });
    }
    return fs.readFileSync(file);
}

function parseCanonicalDocument(bytes, label) {
    let text;
    try {
        text = UTF8.decode(bytes);
    } catch (error) {
        throw new SegmentIntegrityError(`${label} is not valid UTF-8`, {
            cause: error?.message,
        });
    }
    if (!text.endsWith("\n") || text.endsWith("\n\n")) {
        throw new SegmentIntegrityError(`${label} must have exactly one final LF`);
    }
    let value;
    try {
        value = JSON.parse(text.slice(0, -1));
    } catch (error) {
        throw new SegmentIntegrityError(`${label} is not valid JSON`, {
            cause: error?.message,
        });
    }
    const canonical = Buffer.from(`${canonicalize(value)}\n`, "utf8");
    if (!canonical.equals(bytes)) {
        throw new SegmentIntegrityError(`${label} is not canonical JSON`);
    }
    return value;
}

function readFileOrNull(file) {
    try {
        return fs.readFileSync(file);
    } catch (error) {
        if (error?.code === "ENOENT") return null;
        throw error;
    }
}

function atomicReplace(file, bytes, expectedBytes) {
    const directory = path.dirname(file);
    const temporary = path.join(
        directory,
        `.${path.basename(file)}.${randomBytes(12).toString("hex")}.tmp`,
    );
    let fd;
    try {
        fd = fs.openSync(temporary, "wx", 0o600);
        fs.writeFileSync(fd, bytes);
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        fd = undefined;

        const actual = readFileOrNull(file);
        const expectedMatches = expectedBytes === null
            ? actual === null
            : actual !== null && Buffer.from(expectedBytes).equals(actual);
        if (!expectedMatches) {
            throw new SegmentRotationError("segment catalog compare-and-swap failed", {
                file,
            });
        }
        if (actual !== null) lstatRegularFile(file, "segment state file");
        fs.renameSync(temporary, file);
        fsyncDirectory(directory);
        const published = readBoundedFile(file, CATALOG_MAX_BYTES, "segment state file");
        if (!published.equals(bytes)) {
            throw new SegmentRotationError(
                "published segment state differs from the durable candidate",
                { file },
            );
        }
    } finally {
        if (fd !== undefined) {
            try {
                fs.closeSync(fd);
            } catch {
                // Preserve the primary failure.
            }
        }
        try {
            fs.unlinkSync(temporary);
        } catch (error) {
            if (error?.code !== "ENOENT") {
                // The state file outcome is already authoritative.
            }
        }
    }
}

function unlinkDurable(file) {
    try {
        const stat = fs.lstatSync(file);
        if (!stat.isFile() || stat.isSymbolicLink()) {
            throw new SegmentIntegrityError("refusing to remove non-regular segment scratch", {
                file,
            });
        }
        fs.unlinkSync(file);
        fsyncDirectory(path.dirname(file));
    } catch (error) {
        if (error?.code !== "ENOENT") throw error;
    }
}

function descriptorForEntry(entry) {
    const descriptor = {};
    for (const key of DESCRIPTOR_KEYS) descriptor[key] = entry[key];
    return descriptor;
}

function normalizeRawRow(row) {
    return {
        investigation_id: row.investigation_id,
        seq: Number(row.seq),
        prev_hash: row.prev_hash,
        event_hash: row.event_hash,
        kind: row.kind,
        payload: row.payload,
        is_terminal: Number(row.is_terminal),
        terminal_kind: row.terminal_kind ?? null,
        attempt_id: row.attempt_id ?? null,
        evidence_kind: row.evidence_kind ?? null,
        created_at: row.created_at,
    };
}

function sameRawRow(left, right) {
    return canonicalize(normalizeRawRow(left)) === canonicalize(normalizeRawRow(right));
}

function validateDescriptor(descriptor, segmentPrefix, expectedIndex = null) {
    if (!exactKeys(descriptor, DESCRIPTOR_KEYS)) {
        throw new SegmentIntegrityError("segment descriptor has an invalid shape");
    }
    const index = descriptor.index;
    if (!Number.isSafeInteger(index) || index < 0
        || (expectedIndex !== null && index !== expectedIndex)) {
        throw new SegmentIntegrityError("segment index is invalid", {
            index,
            expectedIndex,
        });
    }
    if (typeof descriptor.investigationId !== "string"
        || descriptor.investigationId.length === 0
        || descriptor.investigationId.length > 1024) {
        throw new SegmentIntegrityError("segment investigationId is invalid", {
            index,
        });
    }
    requirePositiveSafeInteger(descriptor.firstSeq, "segment.firstSeq");
    requirePositiveSafeInteger(descriptor.lastSeq, "segment.lastSeq");
    requirePositiveSafeInteger(descriptor.eventCount, "segment.eventCount");
    if (descriptor.lastSeq < descriptor.firstSeq
        || descriptor.lastSeq - descriptor.firstSeq + 1 !== descriptor.eventCount) {
        throw new SegmentIntegrityError("segment sequence range is not contiguous", {
            index,
            firstSeq: descriptor.firstSeq,
            lastSeq: descriptor.lastSeq,
            eventCount: descriptor.eventCount,
        });
    }
    if (!HEX64_RE.test(descriptor.firstEventHash)
        || !HEX64_RE.test(descriptor.lastEventHash)) {
        throw new SegmentIntegrityError("segment event hash binding is invalid", { index });
    }
    if (descriptor.schemaVersion !== SCHEMA_VERSION
        || descriptor.segmentSchemaVersion !== SEGMENT_SCHEMA_VERSION) {
        throw new SegmentIntegrityError("segment schema version is incompatible", {
            index,
            schemaVersion: descriptor.schemaVersion,
            segmentSchemaVersion: descriptor.segmentSchemaVersion,
        });
    }
    if (descriptor.domainVersion !== null
        && (!Number.isSafeInteger(descriptor.domainVersion)
            || descriptor.domainVersion < 1)) {
        throw new SegmentIntegrityError("segment domainVersion is invalid", {
            index,
            domainVersion: descriptor.domainVersion,
        });
    }
    const normalizedSealedAt = normalizeCreatedAt(
        descriptor.sealedAt,
        "segment.sealedAt",
    );
    if (normalizedSealedAt !== descriptor.sealedAt) {
        throw new SegmentIntegrityError("segment sealedAt is not canonical", { index });
    }
    const file = requireSafeBasename(descriptor.file, "segment.file");
    if (file !== `${segmentPrefix}.${index}.sqlite`) {
        throw new SegmentIntegrityError("segment filename does not match its catalog index", {
            index,
            file,
            expected: `${segmentPrefix}.${index}.sqlite`,
        });
    }
    if (!exactKeys(descriptor.previousSegmentAnchor, ANCHOR_KEYS)) {
        throw new SegmentIntegrityError("previous segment anchor has an invalid shape", {
            index,
        });
    }
    const anchor = descriptor.previousSegmentAnchor;
    if (anchor.index === null) {
        if (anchor.fileSha256 !== null
            || anchor.lastSeq !== 0
            || anchor.lastEventHash !== GENESIS_PREV_HASH) {
            throw new SegmentIntegrityError("genesis segment anchor is invalid", { index });
        }
    } else if (!Number.isSafeInteger(anchor.index)
        || anchor.index < 0
        || anchor.index >= index
        || !HEX64_RE.test(anchor.fileSha256)
        || !Number.isSafeInteger(anchor.lastSeq)
        || anchor.lastSeq < 1
        || !HEX64_RE.test(anchor.lastEventHash)) {
        throw new SegmentIntegrityError("previous segment anchor is invalid", {
            index,
            anchor,
        });
    }
    return descriptor;
}

function validateEntry(entry, segmentPrefix, expectedIndex) {
    if (!exactKeys(entry, ENTRY_KEYS)) {
        throw new SegmentIntegrityError("segment catalog entry has an invalid shape", {
            expectedIndex,
        });
    }
    validateDescriptor(descriptorForEntry(entry), segmentPrefix, expectedIndex);
    if (!HEX64_RE.test(entry.fileSha256)
        || !Number.isSafeInteger(entry.fileSize)
        || entry.fileSize < 1) {
        throw new SegmentIntegrityError("segment file binding is invalid", {
            index: entry.index,
        });
    }
    return entry;
}

function validateCatalog(catalog) {
    if (!exactKeys(catalog, CATALOG_KEYS)
        || catalog.type !== SEGMENT_CATALOG_TYPE
        || catalog.version !== SEGMENT_CATALOG_VERSION
        || catalog.hashAlgorithm !== "sha256"
        || !Array.isArray(catalog.segments)
        || !Number.isSafeInteger(catalog.generation)
        || catalog.generation < 0
        || catalog.generation !== catalog.segments.length
        || !exactKeys(catalog.active, ACTIVE_KEYS)
        || catalog.active.index !== catalog.generation
        || catalog.active.schemaVersion !== SCHEMA_VERSION
        || catalog.active.schemaFingerprint !== SCHEMA_FINGERPRINT
        || catalog.active.eventHashVersion !== EVENT_HASH_VERSION) {
        throw new SegmentIntegrityError("segment catalog does not match the active schema");
    }
    const prefix = requireSafeBasename(catalog.segmentPrefix, "segmentPrefix");
    const perInvestigation = new Map();
    for (const [index, entry] of catalog.segments.entries()) {
        validateEntry(entry, prefix, index);
        const previous = perInvestigation.get(entry.investigationId) ?? null;
        const expectedAnchor = previous === null
            ? {
                index: null,
                lastSeq: 0,
                lastEventHash: GENESIS_PREV_HASH,
                fileSha256: null,
            }
            : {
                index: previous.index,
                lastSeq: previous.lastSeq,
                lastEventHash: previous.lastEventHash,
                fileSha256: previous.fileSha256,
            };
        if (canonicalize(entry.previousSegmentAnchor) !== canonicalize(expectedAnchor)
            || entry.firstSeq !== expectedAnchor.lastSeq + 1) {
            throw new SegmentIntegrityError(
                "segment catalog chain is reordered, overlapping, or discontinuous",
                {
                    index,
                    investigationId: entry.investigationId,
                    expectedAnchor,
                    actualAnchor: entry.previousSegmentAnchor,
                    firstSeq: entry.firstSeq,
                },
            );
        }
        perInvestigation.set(entry.investigationId, entry);
    }
    return catalog;
}

function validateJournal(journal, segmentPrefix) {
    if (!exactKeys(journal, JOURNAL_KEYS)
        || journal.type !== JOURNAL_TYPE
        || journal.version !== JOURNAL_VERSION
        || typeof journal.operationId !== "string"
        || !HEX64_RE.test(journal.operationId)
        || !Number.isSafeInteger(journal.baseGeneration)
        || journal.baseGeneration < 0
        || !["prepared", "sealed", "segment_published", "manifest_published", "active_pruned"]
            .includes(journal.stage)) {
        throw new SegmentIntegrityError("segment rotation journal is invalid");
    }
    validateDescriptor(journal.descriptor, segmentPrefix);
    requireSafeBasename(journal.tempFile, "rotation.tempFile");
    if (!journal.tempFile.startsWith(`.${journal.descriptor.file}.`)
        || !journal.tempFile.endsWith(".seal")) {
        throw new SegmentIntegrityError("segment rotation temp filename is invalid");
    }
    if (journal.entry !== null) {
        validateEntry(journal.entry, segmentPrefix, journal.descriptor.index);
        if (canonicalize(descriptorForEntry(journal.entry))
            !== canonicalize(journal.descriptor)) {
            throw new SegmentIntegrityError(
                "segment rotation journal entry disagrees with its descriptor",
            );
        }
    }
    return journal;
}

function eventColumnsAreCanonical(db) {
    const rows = db.prepare("PRAGMA table_info('events');").all();
    return rows.length === EVENT_COLUMNS.length
        && rows.every((row, index) => row.name === EVENT_COLUMNS[index]);
}

function validateRowsAgainstDescriptor(rows, descriptor) {
    if (rows.length !== descriptor.eventCount) {
        throw new SegmentIntegrityError("segment event count disagrees with its catalog", {
            index: descriptor.index,
            expected: descriptor.eventCount,
            actual: rows.length,
        });
    }
    let expectedSeq = descriptor.firstSeq;
    let expectedPrev = descriptor.previousSegmentAnchor.lastEventHash;
    for (const raw of rows) {
        const row = normalizeRawRow(raw);
        if (row.investigation_id !== descriptor.investigationId
            || row.seq !== expectedSeq
            || row.prev_hash !== expectedPrev) {
            throw new SegmentIntegrityError("sealed segment event chain is discontinuous", {
                index: descriptor.index,
                expectedSeq,
                actualSeq: row.seq,
                expectedPrev,
                actualPrev: row.prev_hash,
            });
        }
        const inspected = inspectCanonicalJson(row.payload);
        if (!inspected.ok) {
            throw new SegmentIntegrityError("sealed segment payload is not canonical", {
                index: descriptor.index,
                seq: row.seq,
                reason: inspected.reason,
            });
        }
        const normalizedCreatedAt = normalizeCreatedAt(
            row.created_at,
            "sealed event.createdAt",
        );
        if (normalizedCreatedAt !== row.created_at) {
            throw new SegmentIntegrityError(
                "sealed segment event timestamp is not canonical",
                { index: descriptor.index, seq: row.seq },
            );
        }
        const computed = computeEventHash({
            investigationId: row.investigation_id,
            seq: row.seq,
            prevHash: row.prev_hash,
            kind: row.kind,
            payloadCanonical: row.payload,
            isTerminal: row.is_terminal,
            terminalKind: row.terminal_kind,
            attemptId: row.attempt_id,
            evidenceKind: row.evidence_kind,
            createdAt: row.created_at,
        });
        if (computed !== row.event_hash) {
            throw new SegmentIntegrityError("sealed segment event hash is invalid", {
                index: descriptor.index,
                seq: row.seq,
                expected: computed,
                actual: row.event_hash,
            });
        }
        expectedSeq += 1;
        expectedPrev = row.event_hash;
    }
    if (rows[0]?.event_hash !== descriptor.firstEventHash
        || rows.at(-1)?.event_hash !== descriptor.lastEventHash
        || rows.at(-1)?.seq !== descriptor.lastSeq) {
        throw new SegmentIntegrityError("sealed segment boundary hashes are invalid", {
            index: descriptor.index,
        });
    }
}

function readAndVerifySegment(directory, entry) {
    const file = path.join(directory, entry.file);
    const hashed = hashStableFile(file);
    if (hashed.hash !== entry.fileSha256 || hashed.size !== entry.fileSize) {
        throw new SegmentIntegrityError("sealed segment file hash or size mismatch", {
            index: entry.index,
            file,
            expectedHash: entry.fileSha256,
            actualHash: hashed.hash,
            expectedSize: entry.fileSize,
            actualSize: hashed.size,
        });
    }

    let db;
    try {
        db = new DatabaseSync(file, { readOnly: true });
        db.exec("PRAGMA query_only = ON; PRAGMA busy_timeout = 5000;");
        const journalMode = String(
            Object.values(db.prepare("PRAGMA journal_mode;").get() ?? {})[0] ?? "",
        ).toLowerCase();
        if (journalMode !== "delete") {
            throw new SegmentIntegrityError(
                "sealed segment must not retain an active WAL journal",
                { index: entry.index, journalMode },
            );
        }
        const integrity = db.prepare("PRAGMA integrity_check;").all();
        if (integrity.length !== 1
            || String(Object.values(integrity[0] ?? {})[0] ?? "") !== "ok") {
            throw new SegmentIntegrityError("sealed segment SQLite integrity check failed", {
                index: entry.index,
                rows: integrity,
            });
        }
        const userVersion = Number(
            Object.values(db.prepare("PRAGMA user_version;").get() ?? {})[0] ?? 0,
        );
        if (userVersion !== SEGMENT_SCHEMA_VERSION) {
            throw new SegmentIntegrityError("sealed segment schema version is invalid", {
                index: entry.index,
                userVersion,
            });
        }
        const objects = db.prepare(`
            SELECT name
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY name
        `).all().map((row) => row.name);
        if (canonicalize(objects) !== canonicalize(SEGMENT_SCHEMA_OBJECTS)
            || !eventColumnsAreCanonical(db)) {
            throw new SegmentIntegrityError("sealed segment schema shape is invalid", {
                index: entry.index,
                objects,
            });
        }
        const metaRows = db.prepare(
            "SELECT key, value FROM segment_meta ORDER BY key",
        ).all();
        if (metaRows.length !== 2
            || metaRows[0].key !== "descriptor"
            || metaRows[1].key !== "segment_schema_version"
            || metaRows[1].value !== String(SEGMENT_SCHEMA_VERSION)) {
            throw new SegmentIntegrityError("sealed segment metadata is invalid", {
                index: entry.index,
            });
        }
        const descriptor = JSON.parse(metaRows[0].value);
        if (canonicalize(descriptor) !== metaRows[0].value
            || canonicalize(descriptor) !== canonicalize(descriptorForEntry(entry))) {
            throw new SegmentIntegrityError(
                "sealed segment metadata disagrees with the catalog",
                { index: entry.index },
            );
        }
        const rows = db.prepare("SELECT * FROM events ORDER BY seq").all();
        validateRowsAgainstDescriptor(rows, descriptor);
        const afterIdentity = stableStatIdentity(
            lstatRegularFile(file, "segment file"),
        );
        if (!sameStatIdentity(hashed.identity, afterIdentity)) {
            throw new SegmentIntegrityError(
                "sealed segment changed while its SQLite contents were verified",
                { index: entry.index, file },
            );
        }
        return {
            rows: rows.map(normalizeRawRow),
            identity: afterIdentity,
        };
    } catch (error) {
        if (error instanceof CruciblePersistenceError) throw error;
        throw new SegmentIntegrityError("failed to authenticate sealed segment", {
            index: entry.index,
            file,
            sqliteCode: error?.code,
            message: error?.message,
        });
    } finally {
        try {
            db?.close();
        } catch {
            // Preserve the primary result.
        }
    }
}

function createFreshCatalog(segmentPrefix) {
    return {
        type: SEGMENT_CATALOG_TYPE,
        version: SEGMENT_CATALOG_VERSION,
        hashAlgorithm: "sha256",
        generation: 0,
        segmentPrefix,
        active: {
            index: 0,
            schemaVersion: SCHEMA_VERSION,
            schemaFingerprint: SCHEMA_FINGERPRINT,
            eventHashVersion: EVENT_HASH_VERSION,
        },
        segments: [],
    };
}

function stemForDatabase(file) {
    const parsed = path.parse(file);
    return requireSafeBasename(parsed.name || "events", "database stem");
}

function segmentCatalogPathFor(databaseFile, explicit = undefined) {
    if (typeof explicit === "string" && explicit.length > 0) {
        return path.resolve(explicit);
    }
    const resolved = path.resolve(databaseFile);
    const parsed = path.parse(resolved);
    return path.join(parsed.dir, `${parsed.name}.segments.json`);
}

function segmentJournalPathFor(databaseFile, explicitCatalog = undefined) {
    const catalog = segmentCatalogPathFor(databaseFile, explicitCatalog);
    const parsed = path.parse(catalog);
    return path.join(parsed.dir, `${parsed.name}.prepare.json`);
}

function readCatalogFile(catalogFile, { allowMissing = false } = {}) {
    let bytes;
    try {
        bytes = readBoundedFile(catalogFile, CATALOG_MAX_BYTES, "segment catalog");
    } catch (error) {
        if (allowMissing
            && error instanceof SegmentIntegrityError
            && error.details?.fsCode === "ENOENT") {
            return null;
        }
        throw error;
    }
    return {
        bytes,
        catalog: validateCatalog(parseCanonicalDocument(bytes, "segment catalog")),
    };
}

function readJournalFile(journalFile, segmentPrefix, { allowMissing = true } = {}) {
    let bytes;
    try {
        bytes = readBoundedFile(
            journalFile,
            CATALOG_MAX_BYTES,
            "segment rotation journal",
        );
    } catch (error) {
        if (allowMissing
            && error instanceof SegmentIntegrityError
            && error.details?.fsCode === "ENOENT") {
            return null;
        }
        throw error;
    }
    return {
        bytes,
        journal: validateJournal(
            parseCanonicalDocument(bytes, "segment rotation journal"),
            segmentPrefix,
        ),
    };
}

function eventStorageBytes(db, investigationId, floor) {
    const row = db.prepare(`
        SELECT
            COUNT(*) AS event_count,
            COALESCE(SUM(
                length(CAST(investigation_id AS BLOB))
                + length(CAST(prev_hash AS BLOB))
                + length(CAST(event_hash AS BLOB))
                + length(CAST(kind AS BLOB))
                + length(CAST(payload AS BLOB))
                + length(CAST(COALESCE(terminal_kind, '') AS BLOB))
                + length(CAST(COALESCE(attempt_id, '') AS BLOB))
                + length(CAST(COALESCE(evidence_kind, '') AS BLOB))
                + length(CAST(created_at AS BLOB))
                + 24
            ), 0) AS stored_bytes
        FROM events
        WHERE investigation_id = ? AND seq > ?
    `).get(investigationId, floor);
    return {
        eventCount: Number(row.event_count),
        storedBytes: Number(row.stored_bytes),
    };
}

function domainVersionFor(db, investigationId) {
    const row = db.prepare(
        "SELECT metadata FROM investigations WHERE investigation_id = ?",
    ).get(investigationId);
    if (!row) {
        throw new InvalidArgumentError("cannot rotate an unknown investigation", {
            investigationId,
        });
    }
    let metadata;
    try {
        metadata = JSON.parse(row.metadata);
    } catch (error) {
        throw new SegmentIntegrityError("investigation metadata is not valid JSON", {
            investigationId,
            cause: error?.message,
        });
    }
    return Number.isSafeInteger(metadata?.domainVersion)
        && metadata.domainVersion > 0
        ? metadata.domainVersion
        : null;
}

function previousEntryFor(catalog, investigationId) {
    for (let index = catalog.segments.length - 1; index >= 0; index -= 1) {
        const entry = catalog.segments[index];
        if (entry.investigationId === investigationId) return entry;
    }
    return null;
}

function anchorFor(previous) {
    return previous === null
        ? {
            index: null,
            lastSeq: 0,
            lastEventHash: GENESIS_PREV_HASH,
            fileSha256: null,
        }
        : {
            index: previous.index,
            lastSeq: previous.lastSeq,
            lastEventHash: previous.lastEventHash,
            fileSha256: previous.fileSha256,
        };
}

function writeSegmentDatabase(file, descriptor, rows) {
    let db;
    try {
        db = new DatabaseSync(file);
        db.exec("PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL;");
        db.exec(SEGMENT_DDL);
        db.exec(`PRAGMA user_version = ${SEGMENT_SCHEMA_VERSION};`);
        db.prepare("INSERT INTO segment_meta(key, value) VALUES(?, ?)")
            .run("descriptor", canonicalize(descriptor));
        db.prepare("INSERT INTO segment_meta(key, value) VALUES(?, ?)")
            .run("segment_schema_version", String(SEGMENT_SCHEMA_VERSION));
        const insert = db.prepare(`
            INSERT INTO events(
                investigation_id, seq, prev_hash, event_hash, kind, payload,
                is_terminal, terminal_kind, attempt_id, evidence_kind, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        db.exec("BEGIN IMMEDIATE;");
        try {
            for (const row of rows) {
                insert.run(
                    row.investigation_id,
                    Number(row.seq),
                    row.prev_hash,
                    row.event_hash,
                    row.kind,
                    row.payload,
                    Number(row.is_terminal),
                    row.terminal_kind,
                    row.attempt_id,
                    row.evidence_kind,
                    row.created_at,
                );
            }
            db.exec("COMMIT;");
        } catch (error) {
            try {
                db.exec("ROLLBACK;");
            } catch {
                // Preserve the insert failure.
            }
            throw error;
        }
        const integrity = db.prepare("PRAGMA integrity_check;").all();
        if (integrity.length !== 1
            || String(Object.values(integrity[0] ?? {})[0] ?? "") !== "ok") {
            throw new SegmentRotationError("new sealed segment failed integrity_check", {
                rows: integrity,
            });
        }
    } catch (error) {
        if (error instanceof CruciblePersistenceError) throw error;
        throw new SegmentRotationError("failed to build sealed event segment", {
            file,
            sqliteCode: error?.code,
            message: error?.message,
        });
    } finally {
        try {
            db?.close();
        } catch {
            // Preserve the primary result.
        }
    }
    fsyncFile(file);
    fsyncDirectory(path.dirname(file));
    return hashStableFile(file);
}

function inject(faultInjector, stage, context) {
    if (faultInjector !== null) faultInjector(stage, context);
}

function isSqliteError(error) {
    return error?.code === "ERR_SQLITE_ERROR";
}

function fileBytesOrZero(file) {
    try {
        const stat = fs.lstatSync(file);
        return stat.isFile() && !stat.isSymbolicLink() ? stat.size : 0;
    } catch (error) {
        if (error?.code === "ENOENT") return 0;
        throw error;
    }
}

export class EventSegmentManager {
    #db;
    #databaseFile;
    #directory;
    #catalogFile;
    #journalFile;
    #readOnly;
    #eventThreshold;
    #byteThreshold;
    #now;
    #faultInjector;
    #catalogBytes = null;
    #catalog = null;
    #verifiedFiles = new Map();
    #terminalRows = new Map();
    #evidenceRows = new Map();

    constructor(db, {
        databaseFile,
        catalogFile,
        readOnly,
        eventThreshold,
        byteThreshold,
        now,
        faultInjector,
    }) {
        this.#db = db;
        this.#databaseFile = databaseFile;
        this.#directory = path.dirname(databaseFile);
        this.#catalogFile = catalogFile;
        this.#journalFile = segmentJournalPathFor(databaseFile, catalogFile);
        this.#readOnly = readOnly;
        this.#eventThreshold = eventThreshold;
        this.#byteThreshold = byteThreshold;
        this.#now = now;
        this.#faultInjector = faultInjector;
    }

    static open({
        db,
        databaseFile,
        catalogFile = undefined,
        readOnly = false,
        eventThreshold = DEFAULT_SEGMENT_EVENT_THRESHOLD,
        byteThreshold = DEFAULT_SEGMENT_BYTE_THRESHOLD,
        now = () => new Date().toISOString(),
        faultInjector = null,
    } = {}) {
        if (!db || typeof db.prepare !== "function") {
            throw new InvalidArgumentError("segment manager requires an open SQLite database");
        }
        if (typeof databaseFile !== "string" || databaseFile.length === 0) {
            throw new InvalidArgumentError("segment manager databaseFile is required");
        }
        if (typeof now !== "function") {
            throw new InvalidArgumentError("segment manager now must be a function");
        }
        if (faultInjector !== null && typeof faultInjector !== "function") {
            throw new InvalidArgumentError("segment faultInjector must be a function or null");
        }
        const resolvedDatabase = path.resolve(databaseFile);
        const resolvedCatalog = segmentCatalogPathFor(resolvedDatabase, catalogFile);
        if (path.dirname(resolvedCatalog) !== path.dirname(resolvedDatabase)) {
            throw new InvalidArgumentError(
                "segment catalog must be in the active database directory",
                { databaseFile: resolvedDatabase, catalogFile: resolvedCatalog },
            );
        }
        const manager = new EventSegmentManager(db, {
            databaseFile: resolvedDatabase,
            catalogFile: resolvedCatalog,
            readOnly: readOnly === true,
            eventThreshold: normalizeThreshold(
                eventThreshold,
                DEFAULT_SEGMENT_EVENT_THRESHOLD,
                "segmentEventThreshold",
            ),
            byteThreshold: normalizeThreshold(
                byteThreshold,
                DEFAULT_SEGMENT_BYTE_THRESHOLD,
                "segmentByteThreshold",
            ),
            now,
            faultInjector,
        });
        if (readOnly === true) {
            manager.#loadCatalog({ allowMissing: true, forceVerify: true });
            manager.#validateReadOnlyTransition();
        } else {
            manager.#initialize();
            manager.recoverPending();
            manager.#loadCatalog({ allowMissing: false, forceVerify: true });
        }
        return manager;
    }

    configureThresholds({
        eventThreshold = this.#eventThreshold,
        byteThreshold = this.#byteThreshold,
    } = {}) {
        this.#eventThreshold = normalizeThreshold(
            eventThreshold,
            this.#eventThreshold,
            "segmentEventThreshold",
        );
        this.#byteThreshold = normalizeThreshold(
            byteThreshold,
            this.#byteThreshold,
            "segmentByteThreshold",
        );
        return Object.freeze({
            eventThreshold: this.#eventThreshold,
            byteThreshold: this.#byteThreshold,
        });
    }

    #initialize() {
        let began = false;
        try {
            this.#db.exec("BEGIN IMMEDIATE;");
            began = true;
            const existing = readFileOrNull(this.#catalogFile);
            if (existing === null) {
                const prefix = stemForDatabase(this.#databaseFile);
                const catalog = createFreshCatalog(prefix);
                atomicReplace(
                    this.#catalogFile,
                    Buffer.from(`${canonicalize(catalog)}\n`, "utf8"),
                    null,
                );
            } else {
                validateCatalog(parseCanonicalDocument(existing, "segment catalog"));
            }
            this.#db.exec("COMMIT;");
            began = false;
        } catch (error) {
            if (began) {
                try {
                    this.#db.exec("ROLLBACK;");
                } catch {
                    // Preserve the initialization failure.
                }
            }
            if (error instanceof CruciblePersistenceError) throw error;
            if (isSqliteError(error)) {
                throw new StorageError("failed to initialize event segment catalog", error);
            }
            throw new SegmentRotationError("failed to initialize event segment catalog", {
                message: error?.message,
                fsCode: error?.code,
            });
        }
    }

    #loadCatalog({ allowMissing, forceVerify = false } = {}) {
        const loaded = readCatalogFile(this.#catalogFile, { allowMissing });
        if (loaded === null) {
            const ambiguous = fs.readdirSync(this.#directory).filter((name) =>
                /^.+\.\d+\.sqlite$/u.test(name)
                && path.join(this.#directory, name) !== this.#databaseFile);
            if (ambiguous.length > 0 || readFileOrNull(this.#journalFile) !== null) {
                throw new SegmentIntegrityError(
                    "segment catalog is missing while sealed or pending segment state exists",
                    { files: ambiguous.sort() },
                );
            }
            const catalog = createFreshCatalog(stemForDatabase(this.#databaseFile));
            this.#catalog = catalog;
            this.#catalogBytes = null;
            this.#terminalRows.clear();
            this.#evidenceRows.clear();
            return { catalog, bytes: null, present: false };
        }
        const unchanged = this.#catalogBytes !== null
            && this.#catalogBytes.equals(loaded.bytes);
        this.#catalog = loaded.catalog;
        this.#catalogBytes = Buffer.from(loaded.bytes);
        if (!unchanged || forceVerify) {
            this.#verifyCatalogFiles(loaded.catalog);
        }
        return {
            catalog: loaded.catalog,
            bytes: Buffer.from(loaded.bytes),
            present: true,
        };
    }

    #journal(catalog) {
        return readJournalFile(this.#journalFile, catalog.segmentPrefix);
    }

    #verifyCatalogFiles(catalog) {
        const expectedFiles = new Set(catalog.segments.map((entry) => entry.file));
        const journal = readJournalFile(
            this.#journalFile,
            catalog.segmentPrefix,
        )?.journal ?? null;
        if (journal !== null) {
            expectedFiles.add(journal.descriptor.file);
            expectedFiles.add(journal.tempFile);
        }
        const candidate = new RegExp(
            `^${catalog.segmentPrefix.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.\\d+\\.sqlite$`,
            "u",
        );
        for (const name of fs.readdirSync(this.#directory)) {
            if (candidate.test(name) && !expectedFiles.has(name)) {
                throw new SegmentIntegrityError(
                    "unmanifested sealed segment file creates ambiguous authority",
                    { file: name },
                );
            }
        }

        const evidenceKeys = new Set();
        const terminals = new Set();
        const terminalRows = new Map();
        const evidenceRows = new Map();
        for (const entry of catalog.segments) {
            const verified = readAndVerifySegment(this.#directory, entry);
            const rows = verified.rows;
            this.#rememberVerifiedFile(entry, verified.identity);
            for (const row of rows) {
                if (row.evidence_kind !== null) {
                    const key = `${row.investigation_id}\0${row.attempt_id}\0${row.evidence_kind}`;
                    if (evidenceKeys.has(key)) {
                        throw new SegmentIntegrityError(
                            "evidence idempotency key appears in multiple sealed segments",
                            { index: entry.index, seq: row.seq },
                        );
                    }
                    evidenceKeys.add(key);
                    evidenceRows.set(key, row);
                }
                if (row.is_terminal === 1) {
                    if (terminals.has(row.investigation_id)) {
                        throw new SegmentIntegrityError(
                            "terminal event appears in multiple sealed segments",
                            { index: entry.index, investigationId: row.investigation_id },
                        );
                    }
                    terminals.add(row.investigation_id);
                    terminalRows.set(row.investigation_id, row);
                }
            }
        }
        this.#terminalRows = terminalRows;
        this.#evidenceRows = evidenceRows;
    }

    #rememberVerifiedFile(entry, identity = null) {
        const file = path.join(this.#directory, entry.file);
        this.#verifiedFiles.set(entry.index, {
            fileSha256: entry.fileSha256,
            fileSize: entry.fileSize,
            identity: identity
                ?? stableStatIdentity(lstatRegularFile(file, "segment file")),
        });
    }

    #ensureVerifiedFile(entry) {
        const file = path.join(this.#directory, entry.file);
        const identity = stableStatIdentity(lstatRegularFile(file, "segment file"));
        const cached = this.#verifiedFiles.get(entry.index);
        if (cached
            && cached.fileSha256 === entry.fileSha256
            && cached.fileSize === entry.fileSize
            && sameStatIdentity(cached.identity, identity)) {
            return;
        }
        const verified = readAndVerifySegment(this.#directory, entry);
        this.#rememberVerifiedFile(entry, verified.identity);
    }

    #validateReadOnlyTransition() {
        const { catalog, present } = this.#loadCatalog({
            allowMissing: true,
            forceVerify: false,
        });
        const journal = readJournalFile(
            this.#journalFile,
            catalog.segmentPrefix,
        );
        if (!present && journal !== null) {
            throw new SegmentIntegrityError(
                "rotation journal exists without a segment catalog",
            );
        }
        if (journal === null) {
            this.#assertCatalogOverlap(catalog, null);
            return;
        }
        const published = catalog.segments[journal.journal.descriptor.index] ?? null;
        if (published !== null) {
            if (journal.journal.entry === null
                || canonicalize(published) !== canonicalize(journal.journal.entry)) {
                throw new SegmentIntegrityError(
                    "published catalog disagrees with the pending rotation journal",
                );
            }
            this.#assertActiveOverlapMatches(published, { allowEmpty: true });
            this.#assertCatalogOverlap(catalog, published);
            return;
        }
        if (catalog.generation !== journal.journal.baseGeneration) {
            throw new SegmentIntegrityError(
                "rotation journal base generation is no longer recoverable",
            );
        }
        this.#assertOldStateIntact(journal.journal);
        this.#assertCatalogOverlap(catalog, null);
    }

    #assertCatalogOverlap(catalog, allowedEntry) {
        const lastByInvestigation = new Map();
        for (const entry of catalog.segments) {
            lastByInvestigation.set(entry.investigationId, entry);
        }
        for (const [investigationId, last] of lastByInvestigation) {
            const rows = this.#db.prepare(`
                SELECT seq
                FROM events
                WHERE investigation_id = ? AND seq <= ?
                ORDER BY seq
            `).all(investigationId, last.lastSeq).map((row) => Number(row.seq));
            if (allowedEntry !== null
                && allowedEntry.investigationId === investigationId) {
                if (rows.length === 0) continue;
                const expected = Array.from(
                    { length: allowedEntry.eventCount },
                    (_unused, index) => allowedEntry.firstSeq + index,
                );
                if (canonicalize(rows) === canonicalize(expected)) continue;
            } else if (rows.length === 0) {
                continue;
            }
            throw new SegmentIntegrityError(
                "active database unexpectedly overlaps sealed segment authority",
                {
                    investigationId,
                    sealedThrough: last.lastSeq,
                    activeSequences: rows,
                    allowedIndex: allowedEntry?.index ?? null,
                },
            );
        }
    }

    #assertOldStateIntact(journal) {
        const descriptor = journal.descriptor;
        const rows = this.#db.prepare(`
            SELECT *
            FROM events
            WHERE investigation_id = ?
              AND seq BETWEEN ? AND ?
            ORDER BY seq
        `).all(
            descriptor.investigationId,
            descriptor.firstSeq,
            descriptor.lastSeq,
        ).map(normalizeRawRow);
        if (rows.length !== descriptor.eventCount
            || rows[0]?.event_hash !== descriptor.firstEventHash
            || rows.at(-1)?.event_hash !== descriptor.lastEventHash) {
            throw new SegmentIntegrityError(
                "unpublished rotation cannot recover the intact old active state",
                {
                    investigationId: descriptor.investigationId,
                    expectedCount: descriptor.eventCount,
                    actualCount: rows.length,
                },
            );
        }
        validateRowsAgainstDescriptor(rows, descriptor);
    }

    #assertActiveOverlapMatches(entry, { allowEmpty }) {
        const active = this.#db.prepare(`
            SELECT *
            FROM events
            WHERE investigation_id = ?
              AND seq BETWEEN ? AND ?
            ORDER BY seq
        `).all(
            entry.investigationId,
            entry.firstSeq,
            entry.lastSeq,
        ).map(normalizeRawRow);
        if (allowEmpty && active.length === 0) return { active, sealed: null };
        if (active.length !== entry.eventCount) {
            throw new SegmentIntegrityError(
                "active database partially overlaps a published sealed segment",
                {
                    index: entry.index,
                    expectedCount: entry.eventCount,
                    actualCount: active.length,
                },
            );
        }
        const verified = readAndVerifySegment(this.#directory, entry);
        const sealed = verified.rows;
        this.#rememberVerifiedFile(entry, verified.identity);
        if (!active.every((row, index) => sameRawRow(row, sealed[index]))) {
            throw new SegmentIntegrityError(
                "active duplicate rows disagree with the published sealed segment",
                { index: entry.index },
            );
        }
        return { active, sealed };
    }

    recoverPending() {
        if (this.#readOnly) return { recovered: false, readOnly: true };
        const loaded = this.#loadCatalog({
            allowMissing: false,
            forceVerify: false,
        });
        const journalLoaded = this.#journal(loaded.catalog);
        if (journalLoaded === null) return { recovered: false };

        const { journal } = journalLoaded;
        let began = false;
        let published = false;
        try {
            this.#db.exec("BEGIN IMMEDIATE;");
            began = true;
            const current = this.#loadCatalog({
                allowMissing: false,
                forceVerify: true,
            });
            const entry = current.catalog.segments[journal.descriptor.index] ?? null;
            if (entry !== null) {
                if (journal.entry === null
                    || canonicalize(entry) !== canonicalize(journal.entry)) {
                    throw new SegmentIntegrityError(
                        "published rotation cannot be reconciled with its journal",
                    );
                }
                const overlap = this.#assertActiveOverlapMatches(entry, {
                    allowEmpty: true,
                });
                if (overlap.active.length > 0) {
                    const removed = this.#db.prepare(`
                        DELETE FROM events
                        WHERE investigation_id = ?
                          AND seq BETWEEN ? AND ?
                    `).run(entry.investigationId, entry.firstSeq, entry.lastSeq);
                    if (Number(removed.changes) !== entry.eventCount) {
                        throw new SegmentIntegrityError(
                            "published rotation active cleanup was not exact",
                            { index: entry.index, changes: Number(removed.changes) },
                        );
                    }
                }
                published = true;
            } else {
                if (current.catalog.generation !== journal.baseGeneration) {
                    throw new SegmentIntegrityError(
                        "rotation journal generation conflicts with the catalog",
                        {
                            baseGeneration: journal.baseGeneration,
                            catalogGeneration: current.catalog.generation,
                        },
                    );
                }
                this.#assertOldStateIntact(journal);
            }
            this.#db.exec("COMMIT;");
            began = false;
        } catch (error) {
            if (began) {
                try {
                    this.#db.exec("ROLLBACK;");
                } catch {
                    // Preserve the recovery failure.
                }
            }
            if (error instanceof CruciblePersistenceError) throw error;
            if (isSqliteError(error)) {
                throw new StorageError("segment recovery transaction failed", error);
            }
            throw new SegmentRotationError("segment recovery failed", {
                message: error?.message,
                fsCode: error?.code,
            });
        }

        unlinkDurable(path.join(this.#directory, journal.tempFile));
        if (!published) {
            unlinkDurable(path.join(this.#directory, journal.descriptor.file));
        }
        unlinkDurable(this.#journalFile);
        this.#catalog = null;
        this.#catalogBytes = null;
        this.#loadCatalog({ allowMissing: false, forceVerify: true });
        return {
            recovered: true,
            outcome: published ? "published" : "rolled_back",
            index: journal.descriptor.index,
        };
    }

    snapshot({ verify = true } = {}) {
        const loaded = this.#loadCatalog({
            allowMissing: this.#readOnly,
            forceVerify: verify,
        });
        if (!loaded.present) {
            return {
                present: false,
                catalogFile: this.#catalogFile,
                catalogBytes: null,
                catalog: loaded.catalog,
                files: [],
            };
        }
        return {
            present: true,
            catalogFile: this.#catalogFile,
            catalogBytes: Buffer.from(loaded.bytes),
            catalog: JSON.parse(canonicalize(loaded.catalog)),
            files: loaded.catalog.segments.map((entry) => ({
                index: entry.index,
                file: path.join(this.#directory, entry.file),
                name: entry.file,
                sha256: entry.fileSha256,
                size: entry.fileSize,
            })),
        };
    }

    verify() {
        const snapshot = this.snapshot({ verify: true });
        this.#validateReadOnlyTransition();
        return {
            ok: true,
            generation: snapshot.catalog.generation,
            segmentCount: snapshot.catalog.segments.length,
            catalogFile: snapshot.catalogFile,
        };
    }

    storageTelemetry(investigationId) {
        if (typeof investigationId !== "string" || investigationId.length === 0) {
            throw new InvalidArgumentError(
                "investigationId must be a non-empty string",
            );
        }
        const loaded = this.#loadCatalog({
            allowMissing: this.#readOnly,
            forceVerify: false,
        });
        const entries = loaded.catalog.segments.filter(
            (entry) => entry.investigationId === investigationId,
        );
        const floor = entries.at(-1)?.lastSeq ?? 0;
        const active = eventStorageBytes(this.#db, investigationId, floor);
        return Object.freeze({
            activeEventCount: active.eventCount,
            activeStoredBytes: active.storedBytes,
            sealedEventCount: entries.reduce(
                (total, entry) => total + entry.eventCount,
                0,
            ),
            sealedSegmentCount: entries.length,
            sealedSegmentBytes: entries.reduce(
                (total, entry) => total + entry.fileSize,
                0,
            ),
            catalogBytes: fileBytesOrZero(this.#catalogFile),
            rotationJournalBytes: fileBytesOrZero(this.#journalFile),
            catalogGeneration: loaded.catalog.generation,
            activeIndex: loaded.catalog.active.index,
            thresholds: Object.freeze({
                eventCount: this.#eventThreshold,
                storedBytes: this.#byteThreshold,
            }),
        });
    }

    entriesFor(investigationId) {
        return this.#loadCatalog({
            allowMissing: this.#readOnly,
            forceVerify: false,
        }).catalog.segments.filter(
            (entry) => entry.investigationId === investigationId,
        );
    }

    lastEntryFor(investigationId) {
        const entries = this.entriesFor(investigationId);
        return entries.at(-1) ?? null;
    }

    sealedFloor(investigationId) {
        return this.lastEntryFor(investigationId)?.lastSeq ?? 0;
    }

    sealedHead(investigationId) {
        const entry = this.lastEntryFor(investigationId);
        return entry === null
            ? { seq: 0, eventHash: null }
            : { seq: entry.lastSeq, eventHash: entry.lastEventHash };
    }

    listRows(investigationId, { fromSeq = 1, toSeq = undefined } = {}) {
        const rows = [];
        for (const entry of this.entriesFor(investigationId)) {
            if (entry.lastSeq < fromSeq
                || (toSeq !== undefined && entry.firstSeq > toSeq)) {
                continue;
            }
            const file = path.join(this.#directory, entry.file);
            this.#ensureVerifiedFile(entry);
            let db;
            try {
                db = new DatabaseSync(file, { readOnly: true });
                db.exec("PRAGMA query_only = ON; PRAGMA busy_timeout = 5000;");
                const params = { inv: investigationId, from: fromSeq };
                let sql = "SELECT * FROM events WHERE investigation_id = :inv AND seq >= :from";
                if (toSeq !== undefined) {
                    sql += " AND seq <= :to";
                    params.to = toSeq;
                }
                sql += " ORDER BY seq";
                rows.push(...db.prepare(sql).all(params).map(normalizeRawRow));
            } finally {
                try {
                    db?.close();
                } catch {
                    // Preserve the query result.
                }
            }
        }
        return rows;
    }

    getRow(investigationId, seq) {
        const entry = this.entriesFor(investigationId)
            .find((candidate) => seq >= candidate.firstSeq && seq <= candidate.lastSeq);
        if (!entry) return null;
        return this.listRows(investigationId, { fromSeq: seq, toSeq: seq })[0] ?? null;
    }

    terminalRow(investigationId) {
        for (const entry of this.entriesFor(investigationId)) {
            this.#ensureVerifiedFile(entry);
        }
        return this.#terminalRows.get(investigationId) ?? null;
    }

    evidenceRow(investigationId, attemptId, evidenceKind) {
        for (const entry of this.entriesFor(investigationId)) {
            this.#ensureVerifiedFile(entry);
        }
        return this.#evidenceRows.get(
            `${investigationId}\0${attemptId}\0${evidenceKind}`,
        ) ?? null;
    }

    rotateIfNeeded({
        investigationId,
        quiescent = false,
        eventThreshold = undefined,
        byteThreshold = undefined,
        faultInjector = undefined,
    } = {}) {
        if (this.#readOnly) {
            throw new InvalidArgumentError("read-only repositories cannot rotate segments");
        }
        if (typeof investigationId !== "string" || investigationId.length === 0) {
            throw new InvalidArgumentError("investigationId must be a non-empty string");
        }
        const eventLimit = normalizeThreshold(
            eventThreshold,
            this.#eventThreshold,
            "eventThreshold",
        );
        const byteLimit = normalizeThreshold(
            byteThreshold,
            this.#byteThreshold,
            "byteThreshold",
        );
        const injector = faultInjector === undefined
            ? this.#faultInjector
            : faultInjector;
        if (injector !== null && typeof injector !== "function") {
            throw new InvalidArgumentError("faultInjector must be a function or null");
        }

        this.recoverPending();
        let began = false;
        let journalBytes = null;
        let journal = null;
        try {
            this.#db.exec("BEGIN IMMEDIATE;");
            began = true;
            const loaded = this.#loadCatalog({
                allowMissing: false,
                forceVerify: true,
            });
            const previous = previousEntryFor(loaded.catalog, investigationId);
            const floor = previous?.lastSeq ?? 0;
            const domainVersion = domainVersionFor(this.#db, investigationId);
            const stats = eventStorageBytes(this.#db, investigationId, floor);
            const thresholdReached = stats.eventCount >= eventLimit
                || stats.storedBytes >= byteLimit;
            if (!thresholdReached) {
                this.#db.exec("ROLLBACK;");
                began = false;
                return {
                    rotated: false,
                    reason: "below_threshold",
                    ...stats,
                    eventThreshold: eventLimit,
                    byteThreshold: byteLimit,
                };
            }
            if (quiescent !== true) {
                this.#db.exec("ROLLBACK;");
                began = false;
                return {
                    rotated: false,
                    reason: "not_quiescent",
                    ...stats,
                    eventThreshold: eventLimit,
                    byteThreshold: byteLimit,
                };
            }

            const rows = this.#db.prepare(`
                SELECT *
                FROM events
                WHERE investigation_id = ? AND seq > ?
                ORDER BY seq
            `).all(investigationId, floor).map(normalizeRawRow);
            const index = loaded.catalog.active.index;
            const sealedAt = normalizeCreatedAt(this.#now(), "segment.sealedAt");
            const descriptor = {
                index,
                investigationId,
                firstSeq: rows[0].seq,
                lastSeq: rows.at(-1).seq,
                firstEventHash: rows[0].event_hash,
                lastEventHash: rows.at(-1).event_hash,
                previousSegmentAnchor: anchorFor(previous),
                file: `${loaded.catalog.segmentPrefix}.${index}.sqlite`,
                schemaVersion: SCHEMA_VERSION,
                segmentSchemaVersion: SEGMENT_SCHEMA_VERSION,
                domainVersion,
                eventCount: rows.length,
                sealedAt,
            };
            validateDescriptor(descriptor, loaded.catalog.segmentPrefix, index);
            validateRowsAgainstDescriptor(rows, descriptor);

            const tempFile =
                `.${descriptor.file}.${randomBytes(12).toString("hex")}.seal`;
            journal = {
                type: JOURNAL_TYPE,
                version: JOURNAL_VERSION,
                operationId: randomBytes(32).toString("hex"),
                baseGeneration: loaded.catalog.generation,
                descriptor,
                entry: null,
                tempFile,
                stage: "prepared",
            };
            journalBytes = Buffer.from(`${canonicalize(journal)}\n`, "utf8");
            atomicReplace(this.#journalFile, journalBytes, null);
            inject(injector, "after-prepare", { journal, stats });

            const temporaryPath = path.join(this.#directory, tempFile);
            const finalPath = path.join(this.#directory, descriptor.file);
            if (readFileOrNull(finalPath) !== null || readFileOrNull(temporaryPath) !== null) {
                throw new SegmentRotationError(
                    "segment destination already exists before sealing",
                    { index, finalPath, temporaryPath },
                );
            }
            const hashed = writeSegmentDatabase(temporaryPath, descriptor, rows);
            const entry = {
                ...descriptor,
                fileSha256: hashed.hash,
                fileSize: hashed.size,
            };
            validateEntry(entry, loaded.catalog.segmentPrefix, index);
            journal = { ...journal, entry, stage: "sealed" };
            let nextJournalBytes = Buffer.from(`${canonicalize(journal)}\n`, "utf8");
            atomicReplace(this.#journalFile, nextJournalBytes, journalBytes);
            journalBytes = nextJournalBytes;
            inject(injector, "after-segment-seal", { journal, entry });

            fs.renameSync(temporaryPath, finalPath);
            fsyncDirectory(this.#directory);
            const publishedFile = hashStableFile(finalPath);
            if (publishedFile.hash !== entry.fileSha256
                || publishedFile.size !== entry.fileSize) {
                throw new SegmentRotationError(
                    "published segment differs from the durable sealed candidate",
                    { index },
                );
            }
            journal = { ...journal, stage: "segment_published" };
            nextJournalBytes = Buffer.from(`${canonicalize(journal)}\n`, "utf8");
            atomicReplace(this.#journalFile, nextJournalBytes, journalBytes);
            journalBytes = nextJournalBytes;
            inject(injector, "after-segment-publish", { journal, entry });

            const nextCatalog = {
                ...loaded.catalog,
                generation: loaded.catalog.generation + 1,
                active: {
                    ...loaded.catalog.active,
                    index: loaded.catalog.active.index + 1,
                },
                segments: [...loaded.catalog.segments, entry],
            };
            validateCatalog(nextCatalog);
            const nextCatalogBytes =
                Buffer.from(`${canonicalize(nextCatalog)}\n`, "utf8");
            atomicReplace(this.#catalogFile, nextCatalogBytes, loaded.bytes);
            this.#catalog = nextCatalog;
            this.#catalogBytes = null;
            journal = { ...journal, stage: "manifest_published" };
            nextJournalBytes = Buffer.from(`${canonicalize(journal)}\n`, "utf8");
            atomicReplace(this.#journalFile, nextJournalBytes, journalBytes);
            journalBytes = nextJournalBytes;
            inject(injector, "after-manifest-publish", { journal, entry });

            const removed = this.#db.prepare(`
                DELETE FROM events
                WHERE investigation_id = ?
                  AND seq BETWEEN ? AND ?
            `).run(investigationId, descriptor.firstSeq, descriptor.lastSeq);
            if (Number(removed.changes) !== descriptor.eventCount) {
                throw new SegmentRotationError(
                    "active segment prune did not remove the exact sealed range",
                    {
                        index,
                        expected: descriptor.eventCount,
                        actual: Number(removed.changes),
                    },
                );
            }
            journal = { ...journal, stage: "active_pruned" };
            nextJournalBytes = Buffer.from(`${canonicalize(journal)}\n`, "utf8");
            atomicReplace(this.#journalFile, nextJournalBytes, journalBytes);
            journalBytes = nextJournalBytes;
            inject(injector, "after-active-prune", { journal, entry });

            this.#db.exec("COMMIT;");
            began = false;
            inject(injector, "after-active-commit", { journal, entry });
            unlinkDurable(this.#journalFile);
            this.#catalog = null;
            this.#catalogBytes = null;
            this.#loadCatalog({ allowMissing: false, forceVerify: true });
            return {
                rotated: true,
                entry: JSON.parse(canonicalize(entry)),
                ...stats,
                eventThreshold: eventLimit,
                byteThreshold: byteLimit,
            };
        } catch (error) {
            if (began) {
                try {
                    this.#db.exec("ROLLBACK;");
                } catch (rollbackError) {
                    error.rollbackError = rollbackError;
                }
            }
            if (error instanceof CruciblePersistenceError) throw error;
            if (isSqliteError(error)) {
                throw new StorageError("segment rotation transaction failed", error);
            }
            throw error;
        }
    }
}

export function inspectSegmentStorage({
    databaseFile,
    catalogFile = undefined,
} = {}) {
    if (typeof databaseFile !== "string" || databaseFile.length === 0) {
        throw new InvalidArgumentError("databaseFile must be a non-empty string");
    }
    const resolved = path.resolve(databaseFile);
    let db;
    try {
        db = new DatabaseSync(resolved, { readOnly: true });
        db.exec("PRAGMA query_only = ON; PRAGMA busy_timeout = 5000;");
        const manager = EventSegmentManager.open({
            db,
            databaseFile: resolved,
            catalogFile,
            readOnly: true,
        });
        return manager.snapshot({ verify: true });
    } finally {
        try {
            db?.close();
        } catch {
            // Preserve the inspection result.
        }
    }
}
