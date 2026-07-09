// oracle-v3/__tests__/persistence-event-log.test.mjs
//
// Event-log behaviour: CAS conflict under concurrency, idempotent commutative
// evidence, single-terminal enforcement, transactional rollback, and structural
// integrity / tamper detection.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "../persistence/sqlite.mjs";

import { openRepository, ERROR_CODES } from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

let dir;
let repo;

beforeEach(() => {
    dir = fs.mkdtempSync(path.join(HERE, ".persist-tmp-"));
    repo = openRepository({ file: path.join(dir, "events.sqlite") });
    repo.ensureInvestigation({ investigationId: "inv-1", metadata: { note: "test" } });
});

afterEach(() => {
    try {
        repo?.close();
    } catch {
        // connection may already be closed by a test
    }
    fs.rmSync(dir, { recursive: true, force: true });
});

function catchCode(fn) {
    try {
        fn();
    } catch (err) {
        return err;
    }
    throw new Error("expected the operation to throw");
}

describe("append-only hash-chained event log", () => {
    it("appends a decision batch atomically and chains hashes", () => {
        const result = repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [
                { kind: "opened", payload: { question: "why" } },
                { kind: "decided", payload: { choice: 3 } },
            ],
        });

        expect(result.events.map((e) => e.seq)).toEqual([1, 2]);
        expect(result.events[0].prevHash).toBe("0".repeat(64));
        expect(result.events[1].prevHash).toBe(result.events[0].eventHash);
        expect(repo.getHead("inv-1")).toEqual({ seq: 2, eventHash: result.events[1].eventHash });
        expect(repo.verifyInvestigation("inv-1").ok).toBe(true);
    });

    it("rejects a compare-and-swap append when the head moved (concurrent writers)", () => {
        // Two independent repository handles on the same database file model two
        // concurrent runners racing to extend the same log.
        const repoB = openRepository({ file: repo.databaseFile });
        try {
            const headA = repo.getHead("inv-1");
            const headB = repoB.getHead("inv-1");
            expect(headA).toEqual(headB); // both observe the same empty head

            // Runner A wins the race.
            repo.appendEvents({
                investigationId: "inv-1",
                expectedHead: headA.eventHash,
                events: [{ kind: "a-move", payload: {} }],
            });

            // Runner B still believes the head is where it read it -> CAS conflict.
            const err = catchCode(() => repoB.appendEvents({
                investigationId: "inv-1",
                expectedHead: headB.eventHash,
                events: [{ kind: "b-move", payload: {} }],
            }));
            expect(err.code).toBe(ERROR_CODES.CAS_CONFLICT);
            expect(err.details.expectedHead).toBe(headB.eventHash);

            // Only runner A's event landed.
            expect(repo.countEvents("inv-1")).toBe(1);
        } finally {
            repoB.close();
        }
    });

    it("requires an explicit expectedHead for CAS discipline", () => {
        const err = catchCode(() => repo.appendEvents({
            investigationId: "inv-1",
            events: [{ kind: "x", payload: {} }],
        }));
        expect(err.code).toBe(ERROR_CODES.INVALID_ARGUMENT);
    });
});

describe("idempotent commutative evidence ingestion", () => {
    it("returns the existing event on a duplicate (investigation, attempt, evidence_kind) key", () => {
        const first = repo.ingestEvidence({
            investigationId: "inv-1",
            attemptId: "attempt-9",
            evidenceKind: "stdout",
            kind: "evidence-observed",
            payload: { bytes: 10 },
        });
        expect(first.deduplicated).toBe(false);

        // A second ingestion with a *different* payload must NOT append again and
        // must return the originally stored event unchanged (commutative + idempotent).
        const second = repo.ingestEvidence({
            investigationId: "inv-1",
            attemptId: "attempt-9",
            evidenceKind: "stdout",
            kind: "evidence-observed",
            payload: { bytes: 999999 },
        });
        expect(second.deduplicated).toBe(true);
        expect(second.event.seq).toBe(first.event.seq);
        expect(second.event.eventHash).toBe(first.event.eventHash);
        expect(second.event.payload).toEqual({ bytes: 10 });

        expect(repo.countEvents("inv-1")).toBe(1);

        // A different evidence_kind for the same attempt is a distinct event.
        const other = repo.ingestEvidence({
            investigationId: "inv-1",
            attemptId: "attempt-9",
            evidenceKind: "stderr",
            kind: "evidence-observed",
            payload: {},
        });
        expect(other.deduplicated).toBe(false);
        expect(repo.countEvents("inv-1")).toBe(2);
        expect(repo.verifyInvestigation("inv-1").ok).toBe(true);
    });
});

describe("terminal-event uniqueness", () => {
    it("rejects a second terminal event", () => {
        const head0 = repo.getHead("inv-1");
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: head0.eventHash,
            events: [{ kind: "verified", terminal: { kind: "verified_result" }, payload: { ok: true } }],
        });

        const head1 = repo.getHead("inv-1");
        const err = catchCode(() => repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: head1.eventHash,
            events: [{ kind: "unreachable", terminal: { kind: "target_unreachable" }, payload: {} }],
        }));
        expect(err.code).toBe(ERROR_CODES.TERMINAL_EXISTS);
        expect(repo.getTerminalEvent("inv-1").terminalKind).toBe("verified_result");
    });

    it("rejects every write after terminal and requires terminal-last batches", () => {
        const invalidBatch = catchCode(() => repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [
                { kind: "verified", terminal: { kind: "verified_result" }, payload: { ok: true } },
                { kind: "late-note", payload: {} },
            ],
        }));
        expect(invalidBatch.code).toBe(ERROR_CODES.INVALID_ARGUMENT);
        expect(repo.countEvents("inv-1")).toBe(0);

        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{ kind: "verified", terminal: { kind: "verified_result" }, payload: { ok: true } }],
        });
        expect(catchCode(() => repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: repo.getHead("inv-1").eventHash,
            events: [{ kind: "late-note", payload: {} }],
        })).code).toBe(ERROR_CODES.TERMINAL_EXISTS);
        expect(catchCode(() => repo.ingestEvidence({
            investigationId: "inv-1",
            attemptId: "late-attempt",
            evidenceKind: "stdout",
            kind: "late-evidence",
            payload: {},
        })).code).toBe(ERROR_CODES.TERMINAL_EXISTS);
    });
});

describe("transactional rollback", () => {
    it("discards every event in a batch when one fails mid-batch", () => {
        const head0 = repo.getHead("inv-1");
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: head0.eventHash,
            events: [{ kind: "verified", terminal: { kind: "verified_result" }, payload: {} }],
        });
        expect(repo.countEvents("inv-1")).toBe(1);

        const head1 = repo.getHead("inv-1");
        // First event of the batch is a legal non-terminal note (it *will* be
        // inserted), the second is a forbidden second terminal (fails). The whole
        // batch must roll back, leaving only the original terminal.
        const err = catchCode(() => repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: head1.eventHash,
            events: [
                { kind: "note", payload: { n: 1 } },
                { kind: "second-terminal", terminal: { kind: "target_unreachable" }, payload: {} },
            ],
        }));
        expect(err.code).toBe(ERROR_CODES.TERMINAL_EXISTS);

        // The "note" write was rolled back with the failing terminal.
        expect(repo.countEvents("inv-1")).toBe(1);
        expect(repo.getHead("inv-1")).toEqual(head1);
        expect(repo.verifyInvestigation("inv-1").ok).toBe(true);
    });
});

describe("integrity verification & tamper detection", () => {
    it("detects an out-of-band payload mutation via event-hash recomputation", () => {
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [
                { kind: "a", payload: { v: 1 } },
                { kind: "b", payload: { v: 2 } },
            ],
        });
        expect(repo.verifyInvestigation("inv-1").ok).toBe(true);
        repo.close();

        // Tamper with a stored payload directly, leaving event_hash stale.
        const raw = new DatabaseSync(repo.databaseFile);
        raw.exec("PRAGMA journal_mode=WAL;");
        raw.prepare("UPDATE events SET payload = ? WHERE investigation_id = 'inv-1' AND seq = 1")
            .run(JSON.stringify({ v: 666 }));
        raw.close();

        repo = openRepository({ file: repo.databaseFile });
        const report = repo.verifyInvestigation("inv-1");
        expect(report.ok).toBe(false);
        expect(report.violations.some((v) => v.code === ERROR_CODES.EVENT_HASH_MISMATCH)).toBe(true);
    });

    it("detects a broken prev_hash chain link", () => {
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{ kind: "a", payload: {} }, { kind: "b", payload: {} }],
        });
        repo.close();

        const raw = new DatabaseSync(repo.databaseFile);
        raw.exec("PRAGMA journal_mode=WAL;");
        raw.prepare("UPDATE events SET prev_hash = ? WHERE investigation_id = 'inv-1' AND seq = 2")
            .run("f".repeat(64));
        raw.close();

        repo = openRepository({ file: repo.databaseFile });
        const report = repo.verifyInvestigation("inv-1");
        expect(report.ok).toBe(false);
        expect(report.violations.some((v) => v.code === ERROR_CODES.PREV_HASH_MISMATCH)).toBe(true);
    });

    it("detects terminal-metadata tampering", () => {
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{ kind: "verified", terminal: { kind: "verified_result" }, payload: { ok: true } }],
        });
        repo.close();

        const raw = new DatabaseSync(repo.databaseFile);
        raw.exec("PRAGMA journal_mode=WAL;");
        raw.prepare("UPDATE events SET terminal_kind = 'target_unreachable' WHERE investigation_id = 'inv-1' AND seq = 1").run();
        raw.close();

        repo = openRepository({ file: repo.databaseFile });
        const report = repo.verifyInvestigation("inv-1");
        expect(report.ok).toBe(false);
        expect(report.violations.some((v) => v.code === ERROR_CODES.EVENT_HASH_MISMATCH)).toBe(true);
    });
});
