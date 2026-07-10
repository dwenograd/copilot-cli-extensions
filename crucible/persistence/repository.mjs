// crucible/persistence/repository.mjs
//
// Transactional SQLite event repository for Crucible, built on the Node 24
// built-in `node:sqlite` (DatabaseSync). ESM, synchronous engine.
//
// Design guarantees:
//   * Local-file-only durability (see paths.mjs).
//   * WAL + synchronous=FULL + foreign_keys + busy_timeout, explicit schema
//     version (see schema.mjs).
//   * Append-only, hash-chained event log with per-investigation unique seq and
//     event hash, at-most-one terminal event, compare-and-swap batch append.
//   * Idempotent commutative evidence ingestion.
//   * Durable command lifecycle with fencing tokens / lease ownership.
//   * Inline + external artifact metadata with a durability gate on external
//     references (the filesystem CAS itself lives elsewhere).
//   * Read-only query methods that never repair or mutate.
//   * Structural integrity verification (no domain-policy recomputation).
//
// Every failure throws a typed CruciblePersistenceError subclass; there is no
// broad catch-that-returns-success anywhere.

import { DatabaseSync } from "./sqlite.mjs";

import {
    ERROR_CODES,
    SQLITE_ERRCODE,
    CruciblePersistenceError,
    InvalidArgumentError,
    NotFoundError,
    CasConflictError,
    TerminalExistsError,
    IllegalTransitionError,
    FenceRejectedError,
    AttemptIdentityError,
    ArtifactNotDurableError,
    StorageError,
} from "./errors.mjs";
import { assertLocalDatabasePath } from "./paths.mjs";
import {
    canonicalize,
    computeEventHash,
    inspectCanonicalJson,
    parseCanonicalJson,
    sha256Hex,
    GENESIS_PREV_HASH,
} from "./canonical.mjs";
import {
    SCHEMA_VERSION,
    COMMAND_STATES,
    TERMINAL_KINDS,
    configureConnection,
    configureReadOnlyConnection,
    applySchema,
    verifySchema,
} from "./schema.mjs";

const DEFAULT_BUSY_TIMEOUT_MS = 5000;

const NEXT_STATE = Object.freeze({
    reserved: "dispatched",
    dispatched: "observed",
    observed: "committed",
    committed: null,
});

const STATE_TIMESTAMP_COLUMN = Object.freeze({
    dispatched: "dispatched_at",
    observed: "observed_at",
    committed: "committed_at",
});

function requireNonEmptyString(value, name) {
    if (typeof value !== "string" || value.length === 0) {
        throw new InvalidArgumentError(`${name} must be a non-empty string`, { [name]: value });
    }
    return value;
}

function normalizeSupervisorGeneration(value) {
    if (value === undefined || value === null) {
        return null;
    }
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new InvalidArgumentError(
            "supervisorGeneration must be a positive safe integer or null",
            { supervisorGeneration: value },
        );
    }
    return value;
}

function normalizeRunnerIncarnation(value) {
    if (value === undefined || value === null) {
        return null;
    }
    if (typeof value !== "string" || value.length === 0 || value.length > 256) {
        throw new InvalidArgumentError(
            "runnerIncarnation must be a non-empty string of at most 256 characters or null",
            { runnerIncarnation: value },
        );
    }
    return value;
}

function normalizeRunnerAuthority(supervisorGeneration, runnerIncarnation) {
    const generation = normalizeSupervisorGeneration(supervisorGeneration);
    const incarnation = normalizeRunnerIncarnation(runnerIncarnation);
    if ((generation === null) !== (incarnation === null)) {
        throw new InvalidArgumentError(
            "supervisorGeneration and runnerIncarnation must be provided together",
            { supervisorGeneration: generation, runnerIncarnation: incarnation },
        );
    }
    return { supervisorGeneration: generation, runnerIncarnation: incarnation };
}

function isSqliteError(err) {
    return Boolean(err) && err.code === "ERR_SQLITE_ERROR";
}

function isUniqueViolation(err) {
    return isSqliteError(err)
        && (err.errcode === SQLITE_ERRCODE.CONSTRAINT_UNIQUE
            || err.errcode === SQLITE_ERRCODE.CONSTRAINT_PRIMARYKEY);
}

export function openRepository(options = {}) {
    return EventRepository.open(options);
}

export function openRepositoryReadOnly(options = {}) {
    return EventRepository.open({ ...options, readOnly: true });
}

export class EventRepository {
    #db;
    #now;
    #file;
    #readOnly;

    constructor(db, { now, file, readOnly = false }) {
        this.#db = db;
        this.#now = now;
        this.#file = file;
        this.#readOnly = readOnly;
    }

    static open(options = {}) {
        const {
            file,
            busyTimeoutMs = DEFAULT_BUSY_TIMEOUT_MS,
            now = () => new Date().toISOString(),
            denyRoots,
            env,
            readOnly = false,
        } = options;

        const resolved = assertLocalDatabasePath(file, { denyRoots, env });

        let db;
        try {
            db = new DatabaseSync(resolved, { readOnly: readOnly === true });
        } catch (err) {
            throw new StorageError(`failed to open database at ${resolved}: ${err.message}`, err);
        }

        try {
            if (readOnly === true) {
                configureReadOnlyConnection(db, { busyTimeoutMs });
                verifySchema(db, { busyTimeoutMs });
            } else {
                configureConnection(db, { busyTimeoutMs });
                applySchema(db, { busyTimeoutMs });
            }
        } catch (err) {
            db.close();
            if (!(err instanceof CruciblePersistenceError) && isSqliteError(err)) {
                throw new StorageError(
                    `failed to initialize database at ${resolved}: ${err.message}`,
                    err,
                );
            }
            throw err;
        }

        return new EventRepository(db, { now, file: resolved, readOnly: readOnly === true });
    }

    get databaseFile() {
        return this.#file;
    }

    get schemaVersion() {
        return SCHEMA_VERSION;
    }

    get readOnly() {
        return this.#readOnly;
    }

    close() {
        this.#db.close();
    }

    // --- transaction helper ------------------------------------------------

    #tx(fn) {
        let began = false;
        try {
            this.#db.exec("BEGIN IMMEDIATE;");
            began = true;
            const result = fn();
            this.#db.exec("COMMIT;");
            began = false;
            return result;
        } catch (err) {
            if (began) {
                try {
                    this.#db.exec("ROLLBACK;");
                } catch (rollbackErr) {
                    err.rollbackError = rollbackErr;
                }
            }
            if (isSqliteError(err)) {
                throw new StorageError(`transaction failed: ${err.message}`, err);
            }
            throw err;
        }
    }

    // --- investigations ----------------------------------------------------

    ensureInvestigation({ investigationId, metadata = {} } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        const meta = canonicalize(metadata);
        return this.#tx(() => {
            const existing = this.#db
                .prepare("SELECT investigation_id, created_at, metadata FROM investigations WHERE investigation_id = ?")
                .get(investigationId);
            if (existing) {
                return this.#rowToInvestigation(existing);
            }
            const createdAt = this.#now();
            this.#db
                .prepare("INSERT INTO investigations(investigation_id, created_at, metadata) VALUES(:id, :createdAt, :metadata)")
                .run({ id: investigationId, createdAt, metadata: meta });
            return { investigationId, createdAt, metadata: JSON.parse(meta) };
        });
    }

    getInvestigation(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        const row = this.#db
            .prepare("SELECT investigation_id, created_at, metadata FROM investigations WHERE investigation_id = ?")
            .get(investigationId);
        return row ? this.#rowToInvestigation(row) : null;
    }

    #requireInvestigation(investigationId) {
        const row = this.#db
            .prepare("SELECT 1 AS present FROM investigations WHERE investigation_id = ?")
            .get(investigationId);
        if (!row) {
            throw new NotFoundError(
                ERROR_CODES.INVESTIGATION_NOT_FOUND,
                `unknown investigation '${investigationId}'`,
                { investigationId },
            );
        }
    }

    #rowToInvestigation(row) {
        return {
            investigationId: row.investigation_id,
            createdAt: row.created_at,
            metadata: JSON.parse(row.metadata),
        };
    }

    // --- event log (read) --------------------------------------------------

    getHead(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        const row = this.#db
            .prepare("SELECT seq, event_hash FROM events WHERE investigation_id = ? ORDER BY seq DESC LIMIT 1")
            .get(investigationId);
        if (!row) {
            return { seq: 0, eventHash: null };
        }
        return { seq: Number(row.seq), eventHash: row.event_hash };
    }

    listEvents(investigationId, { fromSeq = 1, toSeq } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        const params = { inv: investigationId, from: fromSeq };
        let sql = "SELECT * FROM events WHERE investigation_id = :inv AND seq >= :from";
        if (toSeq !== undefined) {
            sql += " AND seq <= :to";
            params.to = toSeq;
        }
        sql += " ORDER BY seq ASC";
        return this.#db.prepare(sql).all(params).map((r) => this.#rowToEvent(r));
    }

    getEvent(investigationId, seq) {
        requireNonEmptyString(investigationId, "investigationId");
        const row = this.#db
            .prepare("SELECT * FROM events WHERE investigation_id = ? AND seq = ?")
            .get(investigationId, seq);
        return row ? this.#rowToEvent(row) : null;
    }

    getTerminalEvent(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        const row = this.#db
            .prepare("SELECT * FROM events WHERE investigation_id = ? AND is_terminal = 1 LIMIT 1")
            .get(investigationId);
        return row ? this.#rowToEvent(row) : null;
    }

    countEvents(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        const row = this.#db
            .prepare("SELECT COUNT(*) AS c FROM events WHERE investigation_id = ?")
            .get(investigationId);
        return Number(row.c);
    }

    #rowToEvent(row) {
        return {
            investigationId: row.investigation_id,
            seq: Number(row.seq),
            prevHash: row.prev_hash,
            eventHash: row.event_hash,
            kind: row.kind,
            payload: parseCanonicalJson(row.payload, {
                investigationId: row.investigation_id,
                seq: Number(row.seq),
            }),
            isTerminal: row.is_terminal === 1,
            terminalKind: row.terminal_kind ?? null,
            attemptId: row.attempt_id ?? null,
            evidenceKind: row.evidence_kind ?? null,
            createdAt: row.created_at,
        };
    }

    // --- event log (write) -------------------------------------------------

    // Compare-and-swap append of a decision event batch. `expectedHead` MUST be
    // provided: `null` asserts the log is empty; a hash asserts it is the
    // current head. The whole batch is appended atomically or not at all.
    appendEvents({ investigationId, expectedHead, events } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        if (expectedHead !== null && typeof expectedHead !== "string") {
            throw new InvalidArgumentError(
                "expectedHead is required for CAS append: pass null (empty log) or the current head hash",
                { expectedHead },
            );
        }
        if (!Array.isArray(events) || events.length === 0) {
            throw new InvalidArgumentError("events must be a non-empty array", { events });
        }

        return this.#tx(() =>
            this.#appendEventsInTransaction({ investigationId, expectedHead, events }));
    }

    #appendEventsInTransaction({ investigationId, expectedHead, events }) {
        this.#requireInvestigation(investigationId);

        const head = this.getHead(investigationId);
        const currentHeadHash = head.eventHash;
        if ((expectedHead ?? null) !== (currentHeadHash ?? null)) {
            throw new CasConflictError(
                "append rejected: expected head does not match current head",
                { expectedHead: expectedHead ?? null, actualHead: currentHeadHash ?? null },
            );
        }

        let hasTerminal = Boolean(
            this.#db
                .prepare("SELECT 1 AS present FROM events WHERE investigation_id = ? AND is_terminal = 1 LIMIT 1")
                .get(investigationId),
        );
        if (hasTerminal) {
            throw new TerminalExistsError(
                "terminal investigations reject subsequent events",
                { investigationId },
            );
        }

        let prevSeq = head.seq;
        let prevHash = currentHeadHash ?? GENESIS_PREV_HASH;
        const appended = [];

        const insert = this.#db.prepare(`
            INSERT INTO events(
                investigation_id, seq, prev_hash, event_hash, kind, payload,
                is_terminal, terminal_kind, attempt_id, evidence_kind, created_at)
            VALUES(:inv, :seq, :prev, :hash, :kind, :payload,
                :isTerminal, :tkind, NULL, NULL, :createdAt)`);

        for (const [eventIndex, ev] of events.entries()) {
            const kind = requireNonEmptyString(ev.kind, "event.kind");
            const artifactIds = ev.artifactIds === undefined || ev.artifactIds === null
                ? []
                : this.#normalizeArtifactIds(ev.artifactIds, "event.artifactIds");
            const terminalKind = this.#normalizeTerminalKind(ev.terminal ?? ev.terminalKind ?? null);
            const isTerminal = terminalKind ? 1 : 0;
            if (isTerminal && hasTerminal) {
                throw new TerminalExistsError(
                    "investigation already has a terminal event",
                    { investigationId },
                );
            }
            if (isTerminal && eventIndex !== events.length - 1) {
                throw new InvalidArgumentError(
                    "a terminal event must be the final event in its batch",
                    { investigationId, eventIndex },
                );
            }
            const payloadCanonical = canonicalize(ev.payload === undefined ? {} : ev.payload);
            const createdAt = ev.createdAt ?? this.#now();
            const seq = prevSeq + 1;
            const eventHash = computeEventHash({
                investigationId,
                seq,
                prevHash,
                kind,
                payloadCanonical,
                isTerminal,
                terminalKind,
                attemptId: null,
                evidenceKind: null,
                createdAt,
            });
            if (ev.expectedEventHash != null && ev.expectedEventHash !== eventHash) {
                throw new CruciblePersistenceError(
                    ERROR_CODES.EVENT_HASH_MISMATCH,
                    "supplied event hash does not match canonical computation",
                    { seq, expected: ev.expectedEventHash, computed: eventHash },
                );
            }

            try {
                insert.run({
                    inv: investigationId,
                    seq,
                    prev: prevHash,
                    hash: eventHash,
                    kind,
                    payload: payloadCanonical,
                    isTerminal,
                    tkind: terminalKind,
                    createdAt,
                });
            } catch (err) {
                throw this.#translateEventInsert(err, { investigationId, seq });
            }

            const artifactRefs = this.#referenceArtifactsInTransaction({
                investigationId,
                artifactIds,
                seq,
                createdAt,
            });
            appended.push({
                investigationId, seq, prevHash, eventHash, kind,
                payload: JSON.parse(payloadCanonical),
                isTerminal: isTerminal === 1,
                terminalKind, createdAt, artifactRefs,
            });
            hasTerminal = hasTerminal || isTerminal === 1;
            prevSeq = seq;
            prevHash = eventHash;
        }

        return { head: { seq: prevSeq, eventHash: prevHash }, events: appended };
    }

    appendEventsWithAttemptTransition({
        investigationId,
        authorityInvestigationId = investigationId,
        expectedHead,
        events,
        attemptId,
        attemptCommand,
        leaseId,
        fencingToken,
        owner,
        supervisorGeneration = null,
        runnerIncarnation = null,
        fromState,
        toState,
    } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(authorityInvestigationId, "authorityInvestigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(attemptCommand, "attemptCommand");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");
        requireNonEmptyString(fromState, "fromState");
        requireNonEmptyString(toState, "toState");
        const authority = normalizeRunnerAuthority(
            supervisorGeneration,
            runnerIncarnation,
        );
        if (expectedHead !== null && typeof expectedHead !== "string") {
            throw new InvalidArgumentError(
                "expectedHead is required for CAS append: pass null (empty log) or the current head hash",
                { expectedHead },
            );
        }
        if (!Array.isArray(events) || events.length === 0) {
            throw new InvalidArgumentError("events must be a non-empty array", { events });
        }
        if (!COMMAND_STATES.includes(fromState)
            || !COMMAND_STATES.includes(toState)
            || NEXT_STATE[fromState] !== toState) {
            throw new InvalidArgumentError(
                "attempt transition must be one legal forward lifecycle step",
                { fromState, toState },
            );
        }

        return this.#tx(() => {
            const attempt = this.#assertAttemptAuthorityInTransaction({
                authorityInvestigationId,
                attemptId,
                attemptCommand,
                leaseId,
                fencingToken,
                owner,
                ...authority,
                expectedStates: [fromState],
            });

            const appended = this.#appendEventsInTransaction({
                investigationId,
                expectedHead,
                events,
            });
            return {
                ...appended,
                attempt: this.#transitionAttemptInTransaction({
                    attempt,
                    attemptCommand,
                    leaseId,
                    fencingToken,
                    owner,
                    ...authority,
                    fromState,
                    toState,
                }),
            };
        });
    }

    #normalizeTerminalKind(terminal) {
        if (terminal === null || terminal === undefined || terminal === false) {
            return null;
        }
        const kind = typeof terminal === "object" ? terminal.kind : terminal;
        requireNonEmptyString(kind, "terminal.kind");
        if (!TERMINAL_KINDS.includes(kind)) {
            throw new InvalidArgumentError(
                `terminal kind must be one of ${TERMINAL_KINDS.join(", ")}`,
                { terminalKind: kind },
            );
        }
        return kind;
    }

    #translateEventInsert(err, { investigationId, seq }) {
        if (isUniqueViolation(err)) {
            const msg = String(err.message ?? "");
            if (msg.includes("is_terminal") || /ux_events_terminal/.test(msg)) {
                return new TerminalExistsError("investigation already has a terminal event", { investigationId });
            }
            if (msg.includes("event_hash")) {
                return new CruciblePersistenceError(
                    ERROR_CODES.EVENT_HASH_MISMATCH,
                    "duplicate event hash for investigation",
                    { investigationId, seq },
                );
            }
            if (msg.includes("evidence") || msg.includes("attempt")) {
                return new CruciblePersistenceError(
                    ERROR_CODES.EVIDENCE_CONFLICT,
                    "duplicate evidence key",
                    { investigationId, seq },
                );
            }
            // seq / primary-key collision => sequence conflict.
            return new CruciblePersistenceError(
                ERROR_CODES.SEQUENCE_CONFLICT,
                "sequence conflict while appending event",
                { investigationId, seq },
            );
        }
        if (isSqliteError(err)) {
            return new StorageError(`event insert failed: ${err.message}`, err);
        }
        return err;
    }

    // Idempotent, commutative evidence ingestion keyed by
    // (investigation, attempt_id, evidence_kind). A duplicate returns the
    // already-stored event instead of appending a second one.
    ingestEvidence({ investigationId, attemptId, evidenceKind, kind, payload, createdAt } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(evidenceKind, "evidenceKind");
        const eventKind = requireNonEmptyString(kind, "kind");
        const payloadCanonical = canonicalize(payload === undefined ? {} : payload);

        return this.#tx(() => {
            this.#requireInvestigation(investigationId);
            if (this.getTerminalEvent(investigationId) !== null) {
                throw new TerminalExistsError(
                    "terminal investigations reject subsequent evidence",
                    { investigationId },
                );
            }

            const existing = this.#db
                .prepare("SELECT * FROM events WHERE investigation_id = ? AND attempt_id = ? AND evidence_kind = ?")
                .get(investigationId, attemptId, evidenceKind);
            if (existing) {
                return { deduplicated: true, event: this.#rowToEvent(existing) };
            }

            const head = this.getHead(investigationId);
            const prevHash = head.eventHash ?? GENESIS_PREV_HASH;
            const seq = head.seq + 1;
            const ts = createdAt ?? this.#now();
            const eventHash = computeEventHash({
                investigationId,
                seq,
                prevHash,
                kind: eventKind,
                payloadCanonical,
                isTerminal: false,
                terminalKind: null,
                attemptId,
                evidenceKind,
                createdAt: ts,
            });

            try {
                this.#db.prepare(`
                    INSERT INTO events(
                        investigation_id, seq, prev_hash, event_hash, kind, payload,
                        is_terminal, terminal_kind, attempt_id, evidence_kind, created_at)
                    VALUES(:inv, :seq, :prev, :hash, :kind, :payload,
                        0, NULL, :attempt, :ekind, :createdAt)`).run({
                    inv: investigationId,
                    seq,
                    prev: prevHash,
                    hash: eventHash,
                    kind: eventKind,
                    payload: payloadCanonical,
                    attempt: attemptId,
                    ekind: evidenceKind,
                    createdAt: ts,
                });
            } catch (err) {
                throw this.#translateEventInsert(err, { investigationId, seq });
            }

            const event = {
                investigationId, seq, prevHash, eventHash, kind: eventKind,
                payload: JSON.parse(payloadCanonical), isTerminal: false, terminalKind: null,
                attemptId, evidenceKind, createdAt: ts,
            };
            return { deduplicated: false, event };
        });
    }

    ingestEvidenceBatchFenced({
        investigationId,
        authorityInvestigationId,
        attemptId,
        attemptCommand,
        leaseId,
        fencingToken,
        owner,
        supervisorGeneration = null,
        runnerIncarnation = null,
        expectedState,
        evidence,
    } = {}) {
        this.#validateFencedEvidenceInput({
            investigationId,
            authorityInvestigationId,
            attemptId,
            attemptCommand,
            leaseId,
            owner,
            expectedState,
            evidence,
        });
        const authority = normalizeRunnerAuthority(
            supervisorGeneration,
            runnerIncarnation,
        );
        return this.#tx(() => {
            const attempt = this.#assertAttemptAuthorityInTransaction({
                authorityInvestigationId,
                attemptId,
                attemptCommand,
                leaseId,
                fencingToken,
                owner,
                ...authority,
                expectedStates: [expectedState],
            });
            const appended = this.#ingestEvidenceBatchInTransaction({
                investigationId,
                attemptId,
                evidence,
                duplicateMode: "deduplicate-exact",
            });
            return {
                ...appended,
                attempt: this.#rowToAttempt(attempt),
            };
        });
    }

    ingestEvidenceBatchWithAttemptTransition({
        investigationId,
        authorityInvestigationId,
        attemptId,
        attemptCommand,
        leaseId,
        fencingToken,
        owner,
        supervisorGeneration = null,
        runnerIncarnation = null,
        fromState,
        toState,
        evidence,
    } = {}) {
        this.#validateFencedEvidenceInput({
            investigationId,
            authorityInvestigationId,
            attemptId,
            attemptCommand,
            leaseId,
            owner,
            expectedState: fromState,
            evidence,
        });
        requireNonEmptyString(toState, "toState");
        if (!COMMAND_STATES.includes(toState) || NEXT_STATE[fromState] !== toState) {
            throw new InvalidArgumentError(
                "attempt transition must be one legal forward lifecycle step",
                { fromState, toState },
            );
        }
        const authority = normalizeRunnerAuthority(
            supervisorGeneration,
            runnerIncarnation,
        );
        return this.#tx(() => {
            const attempt = this.#assertAttemptAuthorityInTransaction({
                authorityInvestigationId,
                attemptId,
                attemptCommand,
                leaseId,
                fencingToken,
                owner,
                ...authority,
                expectedStates: [fromState, toState],
            });
            if (attempt.state === toState) {
                const deduplicated = this.#ingestEvidenceBatchInTransaction({
                    investigationId,
                    attemptId,
                    evidence,
                    duplicateMode: "require-exact",
                });
                return {
                    ...deduplicated,
                    attempt: this.#rowToAttempt(attempt),
                };
            }
            const appended = this.#ingestEvidenceBatchInTransaction({
                investigationId,
                attemptId,
                evidence,
                duplicateMode: "reject",
            });
            return {
                ...appended,
                attempt: this.#transitionAttemptInTransaction({
                    attempt,
                    attemptCommand,
                    leaseId,
                    fencingToken,
                    owner,
                    ...authority,
                    fromState,
                    toState,
                }),
            };
        });
    }

    #validateFencedEvidenceInput({
        investigationId,
        authorityInvestigationId,
        attemptId,
        attemptCommand,
        leaseId,
        owner,
        expectedState,
        evidence,
    }) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(authorityInvestigationId, "authorityInvestigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(attemptCommand, "attemptCommand");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");
        requireNonEmptyString(expectedState, "expectedState");
        if (!COMMAND_STATES.includes(expectedState)) {
            throw new InvalidArgumentError(
                `expectedState must be one of ${COMMAND_STATES.join(", ")}`,
                { expectedState },
            );
        }
        if (!Array.isArray(evidence) || evidence.length === 0) {
            throw new InvalidArgumentError("evidence must be a non-empty array", { evidence });
        }
    }

    #ingestEvidenceBatchInTransaction({
        investigationId,
        attemptId,
        evidence,
        duplicateMode,
    }) {
        this.#requireInvestigation(investigationId);
        if (this.getTerminalEvent(investigationId) !== null) {
            throw new TerminalExistsError(
                "terminal investigations reject subsequent evidence",
                { investigationId },
            );
        }
        const normalized = evidence.map((item, index) => {
            if (item === null || typeof item !== "object" || Array.isArray(item)) {
                throw new InvalidArgumentError(
                    `evidence[${index}] must be an object`,
                    { index },
                );
            }
            return {
                evidenceKind: requireNonEmptyString(
                    item.evidenceKind,
                    `evidence[${index}].evidenceKind`,
                ),
                kind: requireNonEmptyString(item.kind, `evidence[${index}].kind`),
                payloadCanonical: canonicalize(
                    item.payload === undefined ? {} : item.payload,
                ),
                createdAt: item.createdAt ?? this.#now(),
            };
        });
        if (new Set(normalized.map((item) => item.evidenceKind)).size !== normalized.length) {
            throw new InvalidArgumentError(
                "evidence batch contains duplicate evidenceKind values",
            );
        }

        const existing = normalized.map((item) => this.#db
            .prepare("SELECT * FROM events WHERE investigation_id = ? AND attempt_id = ? AND evidence_kind = ?")
            .get(investigationId, attemptId, item.evidenceKind) ?? null);
        const existingCount = existing.filter((row) => row !== null).length;
        if (existingCount > 0) {
            const exact = existingCount === normalized.length
                && existing.every((row, index) =>
                    row.kind === normalized[index].kind
                    && row.payload === normalized[index].payloadCanonical);
            if (exact
                && (duplicateMode === "deduplicate-exact"
                    || duplicateMode === "require-exact")) {
                return {
                    deduplicated: true,
                    events: existing.map((row) => this.#rowToEvent(row)),
                };
            }
            throw new CruciblePersistenceError(
                ERROR_CODES.EVIDENCE_CONFLICT,
                "fenced evidence batch conflicts with already-persisted facts",
                {
                    investigationId,
                    attemptId,
                    existingCount,
                    evidenceCount: normalized.length,
                },
            );
        }
        if (duplicateMode === "require-exact") {
            throw new CruciblePersistenceError(
                ERROR_CODES.EVIDENCE_CONFLICT,
                "committed attempt is missing its atomic evidence batch",
                { investigationId, attemptId },
            );
        }

        const head = this.getHead(investigationId);
        let prevSeq = head.seq;
        let prevHash = head.eventHash ?? GENESIS_PREV_HASH;
        const appended = [];
        const insert = this.#db.prepare(`
            INSERT INTO events(
                investigation_id, seq, prev_hash, event_hash, kind, payload,
                is_terminal, terminal_kind, attempt_id, evidence_kind, created_at)
            VALUES(:inv, :seq, :prev, :hash, :kind, :payload,
                0, NULL, :attempt, :evidenceKind, :createdAt)`);
        for (const item of normalized) {
            const seq = prevSeq + 1;
            const eventHash = computeEventHash({
                investigationId,
                seq,
                prevHash,
                kind: item.kind,
                payloadCanonical: item.payloadCanonical,
                isTerminal: false,
                terminalKind: null,
                attemptId,
                evidenceKind: item.evidenceKind,
                createdAt: item.createdAt,
            });
            try {
                insert.run({
                    inv: investigationId,
                    seq,
                    prev: prevHash,
                    hash: eventHash,
                    kind: item.kind,
                    payload: item.payloadCanonical,
                    attempt: attemptId,
                    evidenceKind: item.evidenceKind,
                    createdAt: item.createdAt,
                });
            } catch (err) {
                throw this.#translateEventInsert(err, { investigationId, seq });
            }
            appended.push({
                investigationId,
                seq,
                prevHash,
                eventHash,
                kind: item.kind,
                payload: JSON.parse(item.payloadCanonical),
                isTerminal: false,
                terminalKind: null,
                attemptId,
                evidenceKind: item.evidenceKind,
                createdAt: item.createdAt,
            });
            prevSeq = seq;
            prevHash = eventHash;
        }
        return { deduplicated: false, events: appended };
    }

    // --- supervisor generations / runner incarnations ----------------------

    getSupervisorAuthority(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        const row = this.#db
            .prepare("SELECT * FROM supervisor_authority WHERE investigation_id = ?")
            .get(investigationId);
        return row ? this.#rowToSupervisorAuthority(row) : null;
    }

    claimSupervisorGeneration({
        investigationId,
        supervisorGeneration,
        supervisorNonce,
    } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        const generation = normalizeSupervisorGeneration(supervisorGeneration);
        if (generation === null) {
            throw new InvalidArgumentError(
                "supervisorGeneration is required",
                { supervisorGeneration },
            );
        }
        requireNonEmptyString(supervisorNonce, "supervisorNonce");

        return this.#tx(() => {
            this.#requireInvestigation(investigationId);
            const current = this.#db
                .prepare("SELECT * FROM supervisor_authority WHERE investigation_id = ?")
                .get(investigationId);
            if (current !== undefined) {
                const currentGeneration = Number(current.supervisor_generation);
                if (generation < currentGeneration) {
                    throw new FenceRejectedError(
                        "supervisor generation is below the authoritative high-water mark",
                        {
                            investigationId,
                            presented: generation,
                            current: currentGeneration,
                        },
                    );
                }
                if (generation === currentGeneration) {
                    if (current.supervisor_nonce !== supervisorNonce) {
                        throw new FenceRejectedError(
                            "supervisor generation is already owned by another supervisor",
                            {
                                investigationId,
                                supervisorGeneration: generation,
                            },
                        );
                    }
                    return this.#rowToSupervisorAuthority(current);
                }
            }

            const claimedAt = this.#now();
            this.#db.prepare(`
                UPDATE runner_incarnations
                SET revoked_at = COALESCE(revoked_at, :at)
                WHERE investigation_id = :inv
                  AND revoked_at IS NULL`).run({
                inv: investigationId,
                at: claimedAt,
            });
            if (current === undefined) {
                this.#db.prepare(`
                    INSERT INTO supervisor_authority(
                        investigation_id, supervisor_generation, supervisor_nonce,
                        current_runner_incarnation, claimed_at, updated_at)
                    VALUES(:inv, :generation, :nonce, NULL, :at, :at)`).run({
                    inv: investigationId,
                    generation,
                    nonce: supervisorNonce,
                    at: claimedAt,
                });
            } else {
                this.#db.prepare(`
                    UPDATE supervisor_authority
                    SET supervisor_generation = :generation,
                        supervisor_nonce = :nonce,
                        current_runner_incarnation = NULL,
                        claimed_at = :at,
                        updated_at = :at
                    WHERE investigation_id = :inv`).run({
                    inv: investigationId,
                    generation,
                    nonce: supervisorNonce,
                    at: claimedAt,
                });
            }
            return this.#rowToSupervisorAuthority(
                this.#db
                    .prepare("SELECT * FROM supervisor_authority WHERE investigation_id = ?")
                    .get(investigationId),
            );
        });
    }

    issueRunnerIncarnation({
        investigationId,
        supervisorGeneration,
        supervisorNonce,
        runnerIncarnation,
    } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        const generation = normalizeSupervisorGeneration(supervisorGeneration);
        if (generation === null) {
            throw new InvalidArgumentError(
                "supervisorGeneration is required",
                { supervisorGeneration },
            );
        }
        requireNonEmptyString(supervisorNonce, "supervisorNonce");
        const incarnation = normalizeRunnerIncarnation(runnerIncarnation);
        if (incarnation === null) {
            throw new InvalidArgumentError(
                "runnerIncarnation is required",
                { runnerIncarnation },
            );
        }

        return this.#tx(() => {
            this.#requireInvestigation(investigationId);
            const authority = this.#db
                .prepare("SELECT * FROM supervisor_authority WHERE investigation_id = ?")
                .get(investigationId);
            if (authority === undefined
                || Number(authority.supervisor_generation) !== generation
                || authority.supervisor_nonce !== supervisorNonce) {
                throw new FenceRejectedError(
                    "runner incarnation issuer does not own the current supervisor generation",
                    {
                        investigationId,
                        supervisorGeneration: generation,
                    },
                );
            }
            const existing = this.#db
                .prepare("SELECT 1 AS present FROM runner_incarnations WHERE runner_incarnation = ?")
                .get(incarnation);
            if (existing !== undefined) {
                throw new FenceRejectedError(
                    "runner incarnation has already been issued",
                    { investigationId, runnerIncarnation: incarnation },
                );
            }

            const issuedAt = this.#now();
            if (authority.current_runner_incarnation !== null) {
                this.#db.prepare(`
                    UPDATE runner_incarnations
                    SET revoked_at = COALESCE(revoked_at, :at)
                    WHERE runner_incarnation = :incarnation
                      AND investigation_id = :inv`).run({
                    at: issuedAt,
                    incarnation: authority.current_runner_incarnation,
                    inv: investigationId,
                });
            }
            this.#db.prepare(`
                INSERT INTO runner_incarnations(
                    runner_incarnation, investigation_id, supervisor_generation,
                    supervisor_nonce, issued_at, consumed_at, revoked_at, lease_id)
                VALUES(:incarnation, :inv, :generation, :nonce, :at, NULL, NULL, NULL)`)
                .run({
                    incarnation,
                    inv: investigationId,
                    generation,
                    nonce: supervisorNonce,
                    at: issuedAt,
                });
            const updated = this.#db.prepare(`
                UPDATE supervisor_authority
                SET current_runner_incarnation = :incarnation,
                    updated_at = :at
                WHERE investigation_id = :inv
                  AND supervisor_generation = :generation
                  AND supervisor_nonce = :nonce`).run({
                incarnation,
                at: issuedAt,
                inv: investigationId,
                generation,
                nonce: supervisorNonce,
            });
            if (Number(updated.changes) !== 1) {
                throw new FenceRejectedError(
                    "supervisor generation changed before runner incarnation issuance",
                    {
                        investigationId,
                        supervisorGeneration: generation,
                        runnerIncarnation: incarnation,
                    },
                );
            }
            return Object.freeze({
                investigationId,
                supervisorGeneration: generation,
                supervisorNonce,
                runnerIncarnation: incarnation,
                issuedAt,
                consumedAt: null,
                revokedAt: null,
                leaseId: null,
            });
        });
    }

    #rowToSupervisorAuthority(row) {
        return Object.freeze({
            investigationId: row.investigation_id,
            supervisorGeneration: Number(row.supervisor_generation),
            supervisorNonce: row.supervisor_nonce,
            currentRunnerIncarnation: row.current_runner_incarnation ?? null,
            claimedAt: row.claimed_at,
            updatedAt: row.updated_at,
        });
    }

    #assertLeaseAcquisitionAuthorityInTransaction({
        investigationId,
        supervisorGeneration,
        runnerIncarnation,
    }) {
        const authority = this.#db
            .prepare("SELECT * FROM supervisor_authority WHERE investigation_id = ?")
            .get(investigationId);
        if (supervisorGeneration === null) {
            if (authority !== undefined) {
                throw new FenceRejectedError(
                    "supervisor generation and runner incarnation are required by current authority",
                    { investigationId },
                );
            }
            return null;
        }
        if (authority === undefined) {
            throw new FenceRejectedError(
                "supervisor generation has not been claimed in the authoritative repository",
                {
                    investigationId,
                    supervisorGeneration,
                    runnerIncarnation,
                },
            );
        }
        const currentGeneration = Number(authority.supervisor_generation);
        if (supervisorGeneration !== currentGeneration) {
            throw new FenceRejectedError(
                "supervisor generation is not current",
                {
                    investigationId,
                    presented: supervisorGeneration,
                    current: currentGeneration,
                    runnerIncarnation,
                },
            );
        }
        if (authority.current_runner_incarnation !== runnerIncarnation) {
            throw new FenceRejectedError(
                "runner incarnation is not current for the supervisor generation",
                {
                    investigationId,
                    supervisorGeneration,
                    runnerIncarnation,
                },
            );
        }
        const issued = this.#db
            .prepare("SELECT * FROM runner_incarnations WHERE runner_incarnation = ?")
            .get(runnerIncarnation);
        if (issued === undefined
            || issued.investigation_id !== investigationId
            || Number(issued.supervisor_generation) !== supervisorGeneration
            || issued.supervisor_nonce !== authority.supervisor_nonce
            || issued.revoked_at !== null
            || issued.consumed_at !== null
            || issued.lease_id !== null) {
            throw new FenceRejectedError(
                "runner incarnation is invalid, revoked, or already consumed",
                {
                    investigationId,
                    supervisorGeneration,
                    runnerIncarnation,
                },
            );
        }
        return issued;
    }

    // --- runner leases / fencing tokens ------------------------------------

    acquireLease({
        investigationId,
        leaseId,
        owner,
        supervisorGeneration = null,
        runnerIncarnation = null,
    } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");
        const authority = normalizeRunnerAuthority(
            supervisorGeneration,
            runnerIncarnation,
        );

        return this.#tx(() => {
            this.#requireInvestigation(investigationId);
            const issued = this.#assertLeaseAcquisitionAuthorityInTransaction({
                investigationId,
                ...authority,
            });
            const maxRow = this.#db
                .prepare("SELECT COALESCE(MAX(fencing_token), 0) AS maxToken FROM runner_leases WHERE investigation_id = ?")
                .get(investigationId);
            const fencingToken = Number(maxRow.maxToken) + 1;
            const acquiredAt = this.#now();

            // Supersede any currently-active leases: the newest token wins.
            this.#db
                .prepare("UPDATE runner_leases SET released_at = ? WHERE investigation_id = ? AND released_at IS NULL")
                .run(acquiredAt, investigationId);

            try {
                this.#db
                    .prepare(`
                        INSERT INTO runner_leases(
                            lease_id, investigation_id, owner, fencing_token,
                            supervisor_generation, runner_incarnation, acquired_at)
                        VALUES(:id, :inv, :owner, :token, :generation, :incarnation, :at)`)
                    .run({
                        id: leaseId,
                        inv: investigationId,
                        owner,
                        token: fencingToken,
                        generation: authority.supervisorGeneration,
                        incarnation: authority.runnerIncarnation,
                        at: acquiredAt,
                    });
            } catch (err) {
                if (isUniqueViolation(err)) {
                    throw new InvalidArgumentError("lease_id already exists", { leaseId });
                }
                if (isSqliteError(err)) {
                    throw new StorageError(`lease insert failed: ${err.message}`, err);
                }
                throw err;
            }
            if (issued !== null) {
                const consumed = this.#db.prepare(`
                    UPDATE runner_incarnations
                    SET consumed_at = :at, lease_id = :leaseId
                    WHERE runner_incarnation = :incarnation
                      AND investigation_id = :inv
                      AND supervisor_generation = :generation
                      AND consumed_at IS NULL
                      AND revoked_at IS NULL
                      AND lease_id IS NULL`).run({
                    at: acquiredAt,
                    leaseId,
                    incarnation: authority.runnerIncarnation,
                    inv: investigationId,
                    generation: authority.supervisorGeneration,
                });
                if (Number(consumed.changes) !== 1) {
                    throw new FenceRejectedError(
                        "runner incarnation was consumed before lease acquisition committed",
                        {
                            investigationId,
                            supervisorGeneration: authority.supervisorGeneration,
                            runnerIncarnation: authority.runnerIncarnation,
                            leaseId,
                        },
                    );
                }
            }

            return {
                leaseId,
                investigationId,
                owner,
                fencingToken,
                supervisorGeneration: authority.supervisorGeneration,
                runnerIncarnation: authority.runnerIncarnation,
                acquiredAt,
            };
        });
    }

    getActiveLease(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        const row = this.#db
            .prepare("SELECT * FROM runner_leases WHERE investigation_id = ? AND released_at IS NULL ORDER BY fencing_token DESC LIMIT 1")
            .get(investigationId);
        return row ? this.#rowToLease(row) : null;
    }

    #currentMaxToken(investigationId) {
        const row = this.#db
            .prepare("SELECT COALESCE(MAX(fencing_token), 0) AS maxToken FROM runner_leases WHERE investigation_id = ?")
            .get(investigationId);
        return Number(row.maxToken);
    }

    #rowToLease(row) {
        return {
            leaseId: row.lease_id,
            investigationId: row.investigation_id,
            owner: row.owner,
            fencingToken: Number(row.fencing_token),
            supervisorGeneration: row.supervisor_generation == null
                ? null
                : Number(row.supervisor_generation),
            runnerIncarnation: row.runner_incarnation ?? null,
            acquiredAt: row.acquired_at,
            releasedAt: row.released_at ?? null,
        };
    }

    // Assert the supplied fencing token is the newest issued for this
    // investigation (i.e. the caller still holds the current lease). Any older
    // token is fenced out.
    #assertFencingCurrent(investigationId, fencingToken, extra = {}) {
        if (!Number.isInteger(fencingToken)) {
            throw new InvalidArgumentError("fencingToken must be an integer", { fencingToken });
        }
        const maxToken = this.#currentMaxToken(investigationId);
        if (maxToken === 0) {
            throw new FenceRejectedError("no lease has been acquired for this investigation", { investigationId, ...extra });
        }
        if (fencingToken !== maxToken) {
            throw new FenceRejectedError(
                "fencing token is not the current lease token",
                { investigationId, presented: fencingToken, current: maxToken, ...extra },
            );
        }
    }

    assertAttemptAuthority({
        authorityInvestigationId,
        attemptId,
        attemptCommand,
        leaseId,
        fencingToken,
        owner,
        supervisorGeneration = null,
        runnerIncarnation = null,
        expectedState,
    } = {}) {
        requireNonEmptyString(authorityInvestigationId, "authorityInvestigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(attemptCommand, "attemptCommand");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");
        requireNonEmptyString(expectedState, "expectedState");
        if (!COMMAND_STATES.includes(expectedState)) {
            throw new InvalidArgumentError(
                `expectedState must be one of ${COMMAND_STATES.join(", ")}`,
                { expectedState },
            );
        }
        const authority = normalizeRunnerAuthority(
            supervisorGeneration,
            runnerIncarnation,
        );
        return this.#tx(() => this.#rowToAttempt(
            this.#assertAttemptAuthorityInTransaction({
                authorityInvestigationId,
                attemptId,
                attemptCommand,
                leaseId,
                fencingToken,
                owner,
                ...authority,
                expectedStates: [expectedState],
            }),
        ));
    }

    #assertAttemptAuthorityInTransaction({
        authorityInvestigationId,
        attemptId,
        attemptCommand,
        leaseId,
        fencingToken,
        owner,
        supervisorGeneration,
        runnerIncarnation,
        expectedStates,
    }) {
        this.#requireInvestigation(authorityInvestigationId);
        const attempt = this.#db
            .prepare("SELECT * FROM command_attempts WHERE attempt_id = ?")
            .get(attemptId);
        if (!attempt || attempt.investigation_id !== authorityInvestigationId) {
            throw new NotFoundError(
                ERROR_CODES.NOT_FOUND,
                `unknown command attempt '${attemptId}'`,
                { attemptId, authorityInvestigationId },
            );
        }
        if (attempt.command !== attemptCommand) {
            throw new AttemptIdentityError(
                "attempt command does not match the expected logical identity",
                { attemptId, authorityInvestigationId },
            );
        }
        if (attempt.lease_id !== leaseId
            || Number(attempt.fencing_token) !== fencingToken
            || attempt.owner !== owner) {
            throw new FenceRejectedError(
                "attempt identity does not match the presented runner lease",
                {
                    attemptId,
                    leaseId,
                    fencingToken,
                    owner,
                },
            );
        }
        const lease = this.#db
            .prepare("SELECT * FROM runner_leases WHERE lease_id = ?")
            .get(leaseId);
        if (!lease
            || lease.investigation_id !== authorityInvestigationId
            || lease.owner !== owner
            || Number(lease.fencing_token) !== fencingToken
            || lease.released_at !== null) {
            throw new FenceRejectedError(
                "presented runner lease is not active for this investigation",
                {
                    authorityInvestigationId,
                    attemptId,
                    leaseId,
                    fencingToken,
                    owner,
                },
            );
        }
        this.#assertFencingCurrent(
            authorityInvestigationId,
            fencingToken,
            { attemptId, leaseId },
        );
        this.#assertRunnerAuthorityInTransaction({
            investigationId: authorityInvestigationId,
            supervisorGeneration,
            runnerIncarnation,
            attempt,
            lease,
            details: { authorityInvestigationId, attemptId, leaseId },
        });
        if (!expectedStates.includes(attempt.state)) {
            throw new IllegalTransitionError(
                `attempt must be ${expectedStates.join(" or ")} before fenced persistence`,
                {
                    attemptId,
                    state: attempt.state,
                    expected: expectedStates,
                },
            );
        }
        return attempt;
    }

    #assertRunnerAuthorityInTransaction({
        investigationId,
        supervisorGeneration,
        runnerIncarnation,
        attempt,
        lease,
        details,
    }) {
        const authority = this.#db
            .prepare("SELECT * FROM supervisor_authority WHERE investigation_id = ?")
            .get(investigationId);
        const persistedGenerations = [];
        const persistedIncarnations = [];
        for (const row of [lease, attempt]) {
            if (Object.hasOwn(row, "supervisor_generation")) {
                persistedGenerations.push(row.supervisor_generation);
            }
            if (Object.hasOwn(row, "runner_incarnation")) {
                persistedIncarnations.push(row.runner_incarnation);
            }
        }

        if (supervisorGeneration === null) {
            if (authority !== undefined
                || persistedGenerations.some((value) => value !== null)
                || persistedIncarnations.some((value) => value !== null)) {
                throw new FenceRejectedError(
                    "supervisor generation and runner incarnation are required by persisted authority",
                    details,
                );
            }
            return;
        }
        if (authority === undefined) {
            throw new FenceRejectedError(
                "supervisor generation is not persisted by the authority table",
                { ...details, supervisorGeneration, runnerIncarnation },
            );
        }
        const currentGeneration = Number(authority.supervisor_generation);
        if (currentGeneration !== supervisorGeneration
            || authority.current_runner_incarnation !== runnerIncarnation) {
            throw new FenceRejectedError(
                "runner generation or incarnation is not current",
                {
                    ...details,
                    supervisorGeneration,
                    runnerIncarnation,
                    currentGeneration,
                    currentRunnerIncarnation:
                        authority.current_runner_incarnation ?? null,
                },
            );
        }
        if (persistedGenerations.length === 0 || persistedIncarnations.length === 0
            || persistedGenerations.some((value) =>
                value === null || Number(value) !== supervisorGeneration)
            || persistedIncarnations.some((value) =>
                value === null || value !== runnerIncarnation)) {
            throw new FenceRejectedError(
                "runner generation or incarnation does not match persisted lease authority",
                { ...details, supervisorGeneration, runnerIncarnation },
            );
        }
        const issued = this.#db
            .prepare("SELECT * FROM runner_incarnations WHERE runner_incarnation = ?")
            .get(runnerIncarnation);
        if (issued === undefined
            || issued.investigation_id !== investigationId
            || Number(issued.supervisor_generation) !== supervisorGeneration
            || issued.supervisor_nonce !== authority.supervisor_nonce
            || issued.revoked_at !== null
            || issued.consumed_at === null
            || issued.lease_id !== lease.lease_id) {
            throw new FenceRejectedError(
                "runner incarnation is not the active consumed authority for this lease",
                { ...details, supervisorGeneration, runnerIncarnation },
            );
        }
    }

    #transitionAttemptInTransaction({
        attempt,
        attemptCommand,
        leaseId,
        fencingToken,
        owner,
        supervisorGeneration,
        runnerIncarnation,
        fromState,
        toState,
    }) {
        if (NEXT_STATE[fromState] !== toState) {
            throw new InvalidArgumentError(
                "attempt transition must be one legal forward lifecycle step",
                { fromState, toState },
            );
        }
        const ts = this.#now();
        const tsColumn = STATE_TIMESTAMP_COLUMN[toState];
        const result = this.#db.prepare(`
            UPDATE command_attempts
            SET state = :toState, ${tsColumn} = :ts, updated_at = :ts
            WHERE attempt_id = :attemptId
              AND investigation_id = :investigationId
              AND command = :attemptCommand
              AND state = :fromState
              AND lease_id = :leaseId
              AND fencing_token = :fencingToken
              AND owner = :owner
              AND supervisor_generation IS :supervisorGeneration
              AND runner_incarnation IS :runnerIncarnation`).run({
            toState,
            ts,
            attemptId: attempt.attempt_id,
            investigationId: attempt.investigation_id,
            attemptCommand,
            fromState,
            leaseId,
            fencingToken,
            owner,
            supervisorGeneration,
            runnerIncarnation,
        });
        if (Number(result.changes) !== 1) {
            throw new FenceRejectedError(
                "attempt authority changed before the atomic transition",
                {
                    attemptId: attempt.attempt_id,
                    fromState,
                    toState,
                    leaseId,
                    fencingToken,
                    owner,
                },
            );
        }
        return this.#rowToAttempt(
            this.#db
                .prepare("SELECT * FROM command_attempts WHERE attempt_id = ?")
                .get(attempt.attempt_id),
        );
    }

    // --- command lifecycle -------------------------------------------------

    reserveCommand({
        investigationId,
        attemptId,
        command,
        leaseId,
        fencingToken,
        owner,
        supervisorGeneration = null,
        runnerIncarnation = null,
    } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(command, "command");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");
        const authority = normalizeRunnerAuthority(
            supervisorGeneration,
            runnerIncarnation,
        );

        return this.#tx(() => {
            this.#requireInvestigation(investigationId);

            const lease = this.#db
                .prepare("SELECT * FROM runner_leases WHERE lease_id = ?")
                .get(leaseId);
            if (!lease || lease.investigation_id !== investigationId) {
                throw new NotFoundError(ERROR_CODES.LEASE_NOT_FOUND, `unknown lease '${leaseId}'`, { leaseId });
            }
            if (Number(lease.fencing_token) !== fencingToken) {
                throw new FenceRejectedError("fencing token does not match lease", {
                    leaseId, presented: fencingToken, leaseToken: Number(lease.fencing_token),
                });
            }
            if (lease.owner !== owner) {
                throw new FenceRejectedError("owner does not match lease owner", {
                    leaseId, presented: owner, leaseOwner: lease.owner,
                });
            }
            this.#assertRunnerAuthorityInTransaction({
                investigationId,
                ...authority,
                attempt: {},
                lease,
                details: { investigationId, leaseId, attemptId },
            });
            this.#assertFencingCurrent(investigationId, fencingToken, { leaseId });

            const ts = this.#now();
            try {
                this.#db.prepare(`
                    INSERT INTO command_attempts(
                        attempt_id, investigation_id, command, state, lease_id,
                        fencing_token, owner, supervisor_generation,
                        runner_incarnation, reserved_at, updated_at)
                    VALUES(
                        :id, :inv, :cmd, 'reserved', :lease, :token, :owner,
                        :generation, :incarnation, :at, :at)`).run({
                    id: attemptId, inv: investigationId, cmd: command,
                    lease: leaseId,
                    token: fencingToken,
                    owner,
                    generation: authority.supervisorGeneration,
                    incarnation: authority.runnerIncarnation,
                    at: ts,
                });
            } catch (err) {
                if (isUniqueViolation(err)) {
                    if (err.errcode === SQLITE_ERRCODE.CONSTRAINT_UNIQUE) {
                        throw new CruciblePersistenceError(
                            ERROR_CODES.RESERVATION_CONFLICT,
                            "an active reservation already exists for this command",
                            { investigationId, command },
                        );
                    }
                    throw new InvalidArgumentError("attempt_id already exists", { attemptId });
                }
                if (isSqliteError(err)) {
                    throw new StorageError(`reservation insert failed: ${err.message}`, err);
                }
                throw err;
            }

            return this.getCommandAttempt(attemptId);
        });
    }

    transitionCommand({
        investigationId,
        attemptId,
        toState,
        leaseId = null,
        fencingToken,
        owner = null,
        supervisorGeneration = null,
        runnerIncarnation = null,
    } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(toState, "toState");
        if (!COMMAND_STATES.includes(toState)) {
            throw new InvalidArgumentError(`toState must be one of ${COMMAND_STATES.join(", ")}`, { toState });
        }

        const authority = normalizeRunnerAuthority(
            supervisorGeneration,
            runnerIncarnation,
        );
        return this.#tx(() => {
            const persisted = this.#db
                .prepare("SELECT * FROM command_attempts WHERE attempt_id = ?")
                .get(attemptId);
            if (!persisted || persisted.investigation_id !== investigationId) {
                throw new NotFoundError(ERROR_CODES.NOT_FOUND, `unknown command attempt '${attemptId}'`, { attemptId });
            }
            const supervised = persisted.supervisor_generation !== null
                || persisted.runner_incarnation !== null;
            if (supervised && (leaseId === null || owner === null)) {
                throw new FenceRejectedError(
                    "supervised attempt transitions require full lease authority",
                    { investigationId, attemptId },
                );
            }
            const presentedLeaseId = leaseId ?? persisted.lease_id;
            const presentedOwner = owner ?? persisted.owner;
            const attempt = this.#assertAttemptAuthorityInTransaction({
                authorityInvestigationId: investigationId,
                attemptId,
                attemptCommand: persisted.command,
                leaseId: presentedLeaseId,
                fencingToken,
                owner: presentedOwner,
                ...authority,
                expectedStates: [persisted.state],
            });

            const expected = NEXT_STATE[attempt.state];
            if (toState !== expected) {
                throw new IllegalTransitionError(
                    `illegal command transition ${attempt.state} -> ${toState}`,
                    { attemptId, from: attempt.state, to: toState, expected },
                );
            }
            return this.#transitionAttemptInTransaction({
                attempt,
                attemptCommand: attempt.command,
                leaseId: presentedLeaseId,
                fencingToken,
                owner: presentedOwner,
                ...authority,
                fromState: attempt.state,
                toState,
            });
        });
    }

    dispatchCommand(args) {
        return this.transitionCommand({ ...args, toState: "dispatched" });
    }

    observeCommand(args) {
        return this.transitionCommand({ ...args, toState: "observed" });
    }

    commitCommand(args) {
        return this.transitionCommand({ ...args, toState: "committed" });
    }

    abandonStaleCommand({
        investigationId,
        attemptId,
        leaseId,
        fencingToken,
        owner,
        supervisorGeneration = null,
        runnerIncarnation = null,
    } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");
        const authority = normalizeRunnerAuthority(
            supervisorGeneration,
            runnerIncarnation,
        );

        return this.#tx(() => {
            const lease = this.#db
                .prepare("SELECT * FROM runner_leases WHERE lease_id = ?")
                .get(leaseId);
            if (!lease || lease.investigation_id !== investigationId) {
                throw new NotFoundError(ERROR_CODES.LEASE_NOT_FOUND, `unknown lease '${leaseId}'`, { leaseId });
            }
            if (Number(lease.fencing_token) !== fencingToken || lease.owner !== owner) {
                throw new FenceRejectedError("current lease identity does not match", {
                    leaseId,
                    fencingToken,
                    owner,
                });
            }
            this.#assertRunnerAuthorityInTransaction({
                investigationId,
                ...authority,
                attempt: {},
                lease,
                details: { investigationId, leaseId, attemptId },
            });
            this.#assertFencingCurrent(investigationId, fencingToken, { leaseId, attemptId });

            const attempt = this.#db
                .prepare("SELECT * FROM command_attempts WHERE attempt_id = ?")
                .get(attemptId);
            if (!attempt || attempt.investigation_id !== investigationId) {
                throw new NotFoundError(ERROR_CODES.NOT_FOUND, `unknown command attempt '${attemptId}'`, { attemptId });
            }
            if (attempt.state === "committed" || attempt.state === "abandoned") {
                throw new IllegalTransitionError(
                    `cannot abandon command attempt in state ${attempt.state}`,
                    { attemptId, state: attempt.state },
                );
            }
            if (Number(attempt.fencing_token) >= fencingToken) {
                throw new FenceRejectedError(
                    "only a newer lease may abandon a stale command attempt",
                    { attemptId, attemptToken: Number(attempt.fencing_token), fencingToken },
                );
            }

            const ts = this.#now();
            this.#db.prepare(`
                UPDATE command_attempts
                SET state = 'abandoned', lease_id = :lease, fencing_token = :token,
                    owner = :owner, supervisor_generation = :generation,
                    runner_incarnation = :incarnation,
                    abandoned_at = :ts, updated_at = :ts
                WHERE attempt_id = :id`).run({
                lease: leaseId,
                token: fencingToken,
                owner,
                generation: authority.supervisorGeneration,
                incarnation: authority.runnerIncarnation,
                ts,
                id: attemptId,
            });
            return this.getCommandAttempt(attemptId);
        });
    }

    getCommandAttempt(attemptId) {
        requireNonEmptyString(attemptId, "attemptId");
        const row = this.#db
            .prepare("SELECT * FROM command_attempts WHERE attempt_id = ?")
            .get(attemptId);
        return row ? this.#rowToAttempt(row) : null;
    }

    listCommandAttempts(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        return this.#db
            .prepare("SELECT * FROM command_attempts WHERE investigation_id = ? ORDER BY reserved_at ASC, attempt_id ASC")
            .all(investigationId)
            .map((r) => this.#rowToAttempt(r));
    }

    #rowToAttempt(row) {
        return {
            attemptId: row.attempt_id,
            investigationId: row.investigation_id,
            command: row.command,
            state: row.state,
            leaseId: row.lease_id,
            fencingToken: Number(row.fencing_token),
            owner: row.owner,
            supervisorGeneration: row.supervisor_generation == null
                ? null
                : Number(row.supervisor_generation),
            runnerIncarnation: row.runner_incarnation ?? null,
            reservedAt: row.reserved_at,
            dispatchedAt: row.dispatched_at ?? null,
            observedAt: row.observed_at ?? null,
            committedAt: row.committed_at ?? null,
            abandonedAt: row.abandoned_at ?? null,
            updatedAt: row.updated_at,
        };
    }

    // --- artifacts ---------------------------------------------------------

    putInlineArtifact({ investigationId, artifactId, bytes, contentType = null } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(artifactId, "artifactId");
        const buf = this.#coerceBytes(bytes);

        return this.#tx(() => {
            this.#requireInvestigation(investigationId);
            const createdAt = this.#now();
            try {
                this.#db.prepare(`
                    INSERT INTO artifacts(
                        artifact_id, investigation_id, storage, content_type, size_bytes,
                        inline_blob, hash_algo, hash_value, durable, created_at)
                    VALUES(:id, :inv, 'inline', :ct, :size, :blob, NULL, NULL, 1, :at)`).run({
                    id: artifactId, inv: investigationId, ct: contentType,
                    size: buf.length, blob: buf, at: createdAt,
                });
            } catch (err) {
                throw this.#translateArtifactInsert(err, artifactId);
            }
            return {
                artifactId, investigationId, storage: "inline", contentType,
                sizeBytes: buf.length, sha256: sha256Hex(buf), durable: true, createdAt,
            };
        });
    }

    registerExternalArtifact({ investigationId, artifactId, algo, hash, sizeBytes = null, contentType = null } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(artifactId, "artifactId");
        requireNonEmptyString(algo, "algo");
        requireNonEmptyString(hash, "hash");

        return this.#tx(() => {
            this.#requireInvestigation(investigationId);
            const createdAt = this.#now();
            try {
                this.#db.prepare(`
                    INSERT INTO artifacts(
                        artifact_id, investigation_id, storage, content_type, size_bytes,
                        inline_blob, hash_algo, hash_value, durable, created_at)
                    VALUES(:id, :inv, 'external', :ct, :size, NULL, :algo, :hash, 0, :at)`).run({
                    id: artifactId, inv: investigationId, ct: contentType,
                    size: sizeBytes, algo, hash, at: createdAt,
                });
            } catch (err) {
                throw this.#translateArtifactInsert(err, artifactId);
            }
            return {
                artifactId, investigationId, storage: "external", contentType,
                sizeBytes, hashAlgo: algo, hashValue: hash, durable: false, createdAt,
            };
        });
    }

    markArtifactDurable(artifactId) {
        requireNonEmptyString(artifactId, "artifactId");
        return this.#tx(() => {
            const result = this.#db
                .prepare("UPDATE artifacts SET durable = 1 WHERE artifact_id = ?")
                .run(artifactId);
            if (result.changes === 0) {
                throw new NotFoundError(ERROR_CODES.ARTIFACT_NOT_FOUND, `unknown artifact '${artifactId}'`, { artifactId });
            }
            return this.getArtifact(artifactId);
        });
    }

    // Bind an artifact to the investigation (optionally to an event seq).
    // External artifacts must be marked durable first; the repository refuses to
    // reference a non-durable external artifact (the filesystem CAS that makes
    // it durable is intentionally out of scope here).
    referenceArtifact({ investigationId, artifactId, seq = null } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(artifactId, "artifactId");

        return this.#tx(() => this.#referenceArtifactInTransaction({
            investigationId,
            artifactId,
            seq,
            createdAt: this.#now(),
        }));
    }

    #normalizeArtifactIds(value, field) {
        if (!Array.isArray(value)) {
            throw new InvalidArgumentError(`${field} must be an array`, { field });
        }
        const normalized = value.map((artifactId, index) =>
            requireNonEmptyString(artifactId, `${field}[${index}]`));
        return [...new Set(normalized)].sort();
    }

    #referenceArtifactsInTransaction({
        investigationId,
        artifactIds,
        seq,
        createdAt,
    }) {
        return artifactIds.map((artifactId) =>
            this.#referenceArtifactInTransaction({
                investigationId,
                artifactId,
                seq,
                createdAt,
            }));
    }

    #referenceArtifactInTransaction({
        investigationId,
        artifactId,
        seq,
        createdAt,
    }) {
        const art = this.#db
            .prepare("SELECT * FROM artifacts WHERE artifact_id = ?")
            .get(artifactId);
        if (!art || art.investigation_id !== investigationId) {
            throw new NotFoundError(
                ERROR_CODES.ARTIFACT_NOT_FOUND,
                `unknown artifact '${artifactId}'`,
                { artifactId },
            );
        }
        if (art.storage === "external" && art.durable !== 1) {
            throw new ArtifactNotDurableError(
                "external artifact must be marked durable before it can be referenced",
                { artifactId },
            );
        }
        if (seq !== null) {
            const ev = this.#db
                .prepare("SELECT 1 AS present FROM events WHERE investigation_id = ? AND seq = ?")
                .get(investigationId, seq);
            if (!ev) {
                throw new NotFoundError(
                    ERROR_CODES.NOT_FOUND,
                    `no event at seq ${seq}`,
                    { investigationId, seq },
                );
            }
        }
        const existing = seq === null
            ? null
            : this.#db
                .prepare(`
                    SELECT ref_id, created_at
                    FROM artifact_refs
                    WHERE investigation_id = ? AND artifact_id = ? AND seq = ?`)
                .get(investigationId, artifactId, seq);
        if (existing) {
            return {
                refId: Number(existing.ref_id),
                artifactId,
                investigationId,
                seq,
                createdAt: existing.created_at,
                deduplicated: true,
            };
        }
        try {
            const result = this.#db
                .prepare("INSERT INTO artifact_refs(investigation_id, artifact_id, seq, created_at) VALUES(:inv, :art, :seq, :at)")
                .run({ inv: investigationId, art: artifactId, seq, at: createdAt });
            return {
                refId: Number(result.lastInsertRowid),
                artifactId,
                investigationId,
                seq,
                createdAt,
                deduplicated: false,
            };
        } catch (err) {
            if (isUniqueViolation(err) && seq !== null) {
                const raced = this.#db
                    .prepare(`
                        SELECT ref_id, created_at
                        FROM artifact_refs
                        WHERE investigation_id = ? AND artifact_id = ? AND seq = ?`)
                    .get(investigationId, artifactId, seq);
                if (raced) {
                    return {
                        refId: Number(raced.ref_id),
                        artifactId,
                        investigationId,
                        seq,
                        createdAt: raced.created_at,
                        deduplicated: true,
                    };
                }
            }
            if (isUniqueViolation(err)) {
                throw new CruciblePersistenceError(
                    ERROR_CODES.ARTIFACT_CONFLICT,
                    "artifact already referenced at this seq",
                    { artifactId, seq },
                );
            }
            if (isSqliteError(err)) {
                throw new StorageError(`artifact reference failed: ${err.message}`, err);
            }
            throw err;
        }
    }

    getArtifact(artifactId) {
        requireNonEmptyString(artifactId, "artifactId");
        const row = this.#db
            .prepare("SELECT artifact_id, investigation_id, storage, content_type, size_bytes, hash_algo, hash_value, durable, created_at FROM artifacts WHERE artifact_id = ?")
            .get(artifactId);
        return row ? this.#rowToArtifactMeta(row) : null;
    }

    getInlineArtifact(artifactId) {
        requireNonEmptyString(artifactId, "artifactId");
        const row = this.#db
            .prepare("SELECT * FROM artifacts WHERE artifact_id = ?")
            .get(artifactId);
        if (!row) {
            throw new NotFoundError(ERROR_CODES.ARTIFACT_NOT_FOUND, `unknown artifact '${artifactId}'`, { artifactId });
        }
        if (row.storage !== "inline") {
            throw new InvalidArgumentError("artifact is not inline", { artifactId, storage: row.storage });
        }
        const bytes = Buffer.from(row.inline_blob);
        return { ...this.#rowToArtifactMeta(row), bytes };
    }

    listArtifactRefs(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        return this.#db
            .prepare("SELECT ref_id, investigation_id, artifact_id, seq, created_at FROM artifact_refs WHERE investigation_id = ? ORDER BY ref_id ASC")
            .all(investigationId)
            .map((r) => ({
                refId: Number(r.ref_id),
                investigationId: r.investigation_id,
                artifactId: r.artifact_id,
                seq: r.seq === null ? null : Number(r.seq),
                createdAt: r.created_at,
            }));
    }

    listArtifactRefsForEvent(investigationId, seq) {
        requireNonEmptyString(investigationId, "investigationId");
        if (!Number.isSafeInteger(seq) || seq < 1) {
            throw new InvalidArgumentError("seq must be a positive safe integer", { seq });
        }
        return this.#db
            .prepare(`
                SELECT ref_id, investigation_id, artifact_id, seq, created_at
                FROM artifact_refs
                WHERE investigation_id = ? AND seq = ?
                ORDER BY artifact_id ASC`)
            .all(investigationId, seq)
            .map((r) => ({
                refId: Number(r.ref_id),
                investigationId: r.investigation_id,
                artifactId: r.artifact_id,
                seq: Number(r.seq),
                createdAt: r.created_at,
            }));
    }

    #rowToArtifactMeta(row) {
        return {
            artifactId: row.artifact_id,
            investigationId: row.investigation_id,
            storage: row.storage,
            contentType: row.content_type ?? null,
            sizeBytes: row.size_bytes === null ? null : Number(row.size_bytes),
            hashAlgo: row.hash_algo ?? null,
            hashValue: row.hash_value ?? null,
            durable: row.durable === 1,
            createdAt: row.created_at,
        };
    }

    #coerceBytes(bytes) {
        if (Buffer.isBuffer(bytes)) {
            return bytes;
        }
        if (bytes instanceof Uint8Array) {
            return Buffer.from(bytes);
        }
        throw new InvalidArgumentError("bytes must be a Buffer or Uint8Array", { type: typeof bytes });
    }

    #translateArtifactInsert(err, artifactId) {
        if (isUniqueViolation(err)) {
            return new CruciblePersistenceError(
                ERROR_CODES.ARTIFACT_CONFLICT,
                `artifact '${artifactId}' already exists`,
                { artifactId },
            );
        }
        if (isSqliteError(err)) {
            return new StorageError(`artifact insert failed: ${err.message}`, err);
        }
        return err;
    }

    // --- projection metadata ----------------------------------------------

    getProjectionCheckpoint({ name, investigationId = "*" } = {}) {
        requireNonEmptyString(name, "name");
        const row = this.#db
            .prepare("SELECT * FROM projection_metadata WHERE projection_name = ? AND investigation_id = ?")
            .get(name, investigationId);
        if (!row) {
            return { projectionName: name, investigationId, lastAppliedSeq: 0, checkpoint: null, updatedAt: null };
        }
        return {
            projectionName: row.projection_name,
            investigationId: row.investigation_id,
            lastAppliedSeq: Number(row.last_applied_seq),
            checkpoint: row.checkpoint === null ? null : JSON.parse(row.checkpoint),
            updatedAt: row.updated_at,
        };
    }

    setProjectionCheckpoint({ name, investigationId = "*", lastAppliedSeq, checkpoint = null } = {}) {
        requireNonEmptyString(name, "name");
        if (!Number.isInteger(lastAppliedSeq) || lastAppliedSeq < 0) {
            throw new InvalidArgumentError("lastAppliedSeq must be a non-negative integer", { lastAppliedSeq });
        }
        const checkpointJson = checkpoint === null ? null : canonicalize(checkpoint);
        return this.#tx(() => {
            const updatedAt = this.#now();
            this.#db.prepare(`
                INSERT INTO projection_metadata(projection_name, investigation_id, last_applied_seq, checkpoint, updated_at)
                VALUES(:name, :inv, :seq, :cp, :at)
                ON CONFLICT(projection_name, investigation_id)
                DO UPDATE SET last_applied_seq = :seq, checkpoint = :cp, updated_at = :at`).run({
                name, inv: investigationId, seq: lastAppliedSeq, cp: checkpointJson, at: updatedAt,
            });
            return this.getProjectionCheckpoint({ name, investigationId });
        });
    }

    // --- integrity verification (read-only) --------------------------------

    // Verify the *structural* integrity of an investigation's log and artifact
    // references: sequence continuity, prev_hash linkage, event-hash
    // recomputation, terminal uniqueness, and artifact reference validity. This
    // does NOT recompute any domain policy; it only checks that the stored bytes
    // are internally consistent and untampered. Returns a report; never mutates.
    verifyInvestigation(investigationId) {
        requireNonEmptyString(investigationId, "investigationId");
        this.#requireInvestigation(investigationId);

        const violations = [];
        const events = this.#db
            .prepare("SELECT * FROM events WHERE investigation_id = ? ORDER BY seq ASC")
            .all(investigationId);

        let expectedSeq = 1;
        let expectedPrev = GENESIS_PREV_HASH;
        let terminalCount = 0;

        for (const row of events) {
            const seq = Number(row.seq);
            if (seq !== expectedSeq) {
                violations.push({
                    code: ERROR_CODES.SEQUENCE_CONFLICT,
                    seq,
                    detail: `expected seq ${expectedSeq}, found ${seq}`,
                });
            }
            if (row.prev_hash !== expectedPrev) {
                violations.push({
                    code: ERROR_CODES.PREV_HASH_MISMATCH,
                    seq,
                    detail: `prev_hash does not chain to predecessor`,
                });
            }
            const inspectedPayload = inspectCanonicalJson(row.payload);
            if (!inspectedPayload.ok) {
                violations.push({
                    code: ERROR_CODES.EVENT_PAYLOAD_NOT_CANONICAL,
                    seq,
                    detail: inspectedPayload.reason,
                });
            }
            try {
                const recomputed = computeEventHash({
                    investigationId,
                    seq,
                    prevHash: row.prev_hash,
                    kind: row.kind,
                    payloadCanonical: row.payload,
                    isTerminal: row.is_terminal,
                    terminalKind: row.terminal_kind,
                    attemptId: row.attempt_id,
                    evidenceKind: row.evidence_kind,
                    createdAt: row.created_at,
                });
                if (recomputed !== row.event_hash) {
                    violations.push({
                        code: ERROR_CODES.EVENT_HASH_MISMATCH,
                        seq,
                        detail: `stored event_hash does not match recomputation (tamper?)`,
                    });
                }
            } catch (err) {
                violations.push({
                    code: ERROR_CODES.EVENT_HASH_MISMATCH,
                    seq,
                    detail: `event hash could not be recomputed: ${err.message}`,
                });
            }
            if (row.is_terminal === 1) {
                terminalCount += 1;
            }
            expectedSeq = seq + 1;
            expectedPrev = row.event_hash;
        }

        if (terminalCount > 1) {
            violations.push({
                code: ERROR_CODES.TERMINAL_EXISTS,
                detail: `found ${terminalCount} terminal events; at most one is allowed`,
            });
        }

        const refs = this.#db
            .prepare("SELECT * FROM artifact_refs WHERE investigation_id = ?")
            .all(investigationId);
        for (const ref of refs) {
            const art = this.#db
                .prepare("SELECT * FROM artifacts WHERE artifact_id = ?")
                .get(ref.artifact_id);
            if (!art) {
                violations.push({
                    code: ERROR_CODES.ARTIFACT_NOT_FOUND,
                    detail: `artifact_ref ${ref.ref_id} points at missing artifact '${ref.artifact_id}'`,
                });
                continue;
            }
            if (art.investigation_id !== investigationId) {
                violations.push({
                    code: ERROR_CODES.ARTIFACT_CONFLICT,
                    detail: `artifact '${ref.artifact_id}' belongs to a different investigation`,
                });
            }
            if (art.storage === "external" && art.durable !== 1) {
                violations.push({
                    code: ERROR_CODES.ARTIFACT_NOT_DURABLE,
                    detail: `referenced external artifact '${ref.artifact_id}' is not durable`,
                });
            }
            if (art.storage === "inline" && art.inline_blob === null) {
                violations.push({
                    code: ERROR_CODES.INTEGRITY_VIOLATION,
                    detail: `inline artifact '${ref.artifact_id}' has no blob`,
                });
            } else if (art.storage === "inline") {
                const bytes = Buffer.from(art.inline_blob);
                if (!Number.isSafeInteger(Number(art.size_bytes))
                    || Number(art.size_bytes) !== bytes.length) {
                    violations.push({
                        code: ERROR_CODES.INTEGRITY_VIOLATION,
                        detail: `inline artifact '${ref.artifact_id}' size metadata does not match its blob`,
                    });
                }
            }
            if (ref.seq !== null) {
                const ev = this.#db
                    .prepare("SELECT 1 AS present FROM events WHERE investigation_id = ? AND seq = ?")
                    .get(investigationId, ref.seq);
                if (!ev) {
                    violations.push({
                        code: ERROR_CODES.INTEGRITY_VIOLATION,
                        detail: `artifact_ref ${ref.ref_id} points at missing event seq ${ref.seq}`,
                    });
                }
            }
        }

        return {
            ok: violations.length === 0,
            investigationId,
            checkedEvents: events.length,
            checkedArtifactRefs: refs.length,
            violations,
        };
    }
}
