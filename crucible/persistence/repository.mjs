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
    ArtifactNotDurableError,
    StorageError,
} from "./errors.mjs";
import { assertLocalDatabasePath } from "./paths.mjs";
import { canonicalize, computeEventHash, sha256Hex, GENESIS_PREV_HASH } from "./canonical.mjs";
import {
    SCHEMA_VERSION,
    COMMAND_STATES,
    TERMINAL_KINDS,
    configureConnection,
    applySchema,
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

export class EventRepository {
    #db;
    #now;
    #file;

    constructor(db, { now, file }) {
        this.#db = db;
        this.#now = now;
        this.#file = file;
    }

    static open(options = {}) {
        const {
            file,
            busyTimeoutMs = DEFAULT_BUSY_TIMEOUT_MS,
            now = () => new Date().toISOString(),
            denyRoots,
            env,
        } = options;

        const resolved = assertLocalDatabasePath(file, { denyRoots, env });

        let db;
        try {
            db = new DatabaseSync(resolved);
        } catch (err) {
            throw new StorageError(`failed to open database at ${resolved}: ${err.message}`, err);
        }

        try {
            configureConnection(db, { busyTimeoutMs });
            applySchema(db);
        } catch (err) {
            db.close();
            throw err;
        }

        return new EventRepository(db, { now, file: resolved });
    }

    get databaseFile() {
        return this.#file;
    }

    get schemaVersion() {
        return SCHEMA_VERSION;
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
            payload: JSON.parse(row.payload),
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

        return this.#tx(() => {
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

                appended.push({
                    investigationId, seq, prevHash, eventHash, kind,
                    payload: JSON.parse(payloadCanonical),
                    isTerminal: isTerminal === 1,
                    terminalKind, createdAt,
                });
                hasTerminal = hasTerminal || isTerminal === 1;
                prevSeq = seq;
                prevHash = eventHash;
            }

            return { head: { seq: prevSeq, eventHash: prevHash }, events: appended };
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

    // --- runner leases / fencing tokens ------------------------------------

    acquireLease({ investigationId, leaseId, owner } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");

        return this.#tx(() => {
            this.#requireInvestigation(investigationId);
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
                    .prepare("INSERT INTO runner_leases(lease_id, investigation_id, owner, fencing_token, acquired_at) VALUES(:id, :inv, :owner, :token, :at)")
                    .run({ id: leaseId, inv: investigationId, owner, token: fencingToken, at: acquiredAt });
            } catch (err) {
                if (isUniqueViolation(err)) {
                    throw new InvalidArgumentError("lease_id already exists", { leaseId });
                }
                if (isSqliteError(err)) {
                    throw new StorageError(`lease insert failed: ${err.message}`, err);
                }
                throw err;
            }

            return { leaseId, investigationId, owner, fencingToken, acquiredAt };
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

    // --- command lifecycle -------------------------------------------------

    reserveCommand({ investigationId, attemptId, command, leaseId, fencingToken, owner } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(command, "command");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");

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
            this.#assertFencingCurrent(investigationId, fencingToken, { leaseId });

            const ts = this.#now();
            try {
                this.#db.prepare(`
                    INSERT INTO command_attempts(
                        attempt_id, investigation_id, command, state, lease_id,
                        fencing_token, owner, reserved_at, updated_at)
                    VALUES(:id, :inv, :cmd, 'reserved', :lease, :token, :owner, :at, :at)`).run({
                    id: attemptId, inv: investigationId, cmd: command,
                    lease: leaseId, token: fencingToken, owner, at: ts,
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

    transitionCommand({ investigationId, attemptId, toState, fencingToken } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(toState, "toState");
        if (!COMMAND_STATES.includes(toState)) {
            throw new InvalidArgumentError(`toState must be one of ${COMMAND_STATES.join(", ")}`, { toState });
        }

        return this.#tx(() => {
            const attempt = this.#db
                .prepare("SELECT * FROM command_attempts WHERE attempt_id = ?")
                .get(attemptId);
            if (!attempt || attempt.investigation_id !== investigationId) {
                throw new NotFoundError(ERROR_CODES.NOT_FOUND, `unknown command attempt '${attemptId}'`, { attemptId });
            }

            // Fencing: the presented token must equal the token this attempt was
            // reserved under AND still be the current lease token (nobody newer
            // has taken over).
            if (Number(attempt.fencing_token) !== fencingToken) {
                throw new FenceRejectedError("fencing token does not match the reserving lease", {
                    attemptId, presented: fencingToken, attemptToken: Number(attempt.fencing_token),
                });
            }
            this.#assertFencingCurrent(investigationId, fencingToken, { attemptId });

            const expected = NEXT_STATE[attempt.state];
            if (toState !== expected) {
                throw new IllegalTransitionError(
                    `illegal command transition ${attempt.state} -> ${toState}`,
                    { attemptId, from: attempt.state, to: toState, expected },
                );
            }

            const ts = this.#now();
            const tsColumn = STATE_TIMESTAMP_COLUMN[toState];
            this.#db
                .prepare(`UPDATE command_attempts SET state = :state, ${tsColumn} = :ts, updated_at = :ts WHERE attempt_id = :id`)
                .run({ state: toState, ts, id: attemptId });

            return this.getCommandAttempt(attemptId);
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

    abandonStaleCommand({ investigationId, attemptId, leaseId, fencingToken, owner } = {}) {
        requireNonEmptyString(investigationId, "investigationId");
        requireNonEmptyString(attemptId, "attemptId");
        requireNonEmptyString(leaseId, "leaseId");
        requireNonEmptyString(owner, "owner");

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
                    owner = :owner, abandoned_at = :ts, updated_at = :ts
                WHERE attempt_id = :id`).run({
                lease: leaseId,
                token: fencingToken,
                owner,
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

        return this.#tx(() => {
            const art = this.#db
                .prepare("SELECT * FROM artifacts WHERE artifact_id = ?")
                .get(artifactId);
            if (!art || art.investigation_id !== investigationId) {
                throw new NotFoundError(ERROR_CODES.ARTIFACT_NOT_FOUND, `unknown artifact '${artifactId}'`, { artifactId });
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
                    throw new NotFoundError(ERROR_CODES.NOT_FOUND, `no event at seq ${seq}`, { investigationId, seq });
                }
            }
            const createdAt = this.#now();
            try {
                this.#db
                    .prepare("INSERT INTO artifact_refs(investigation_id, artifact_id, seq, created_at) VALUES(:inv, :art, :seq, :at)")
                    .run({ inv: investigationId, art: artifactId, seq, at: createdAt });
            } catch (err) {
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
            return { artifactId, investigationId, seq, createdAt };
        });
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
