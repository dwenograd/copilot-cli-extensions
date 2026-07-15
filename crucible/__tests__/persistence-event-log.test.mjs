// crucible/__tests__/persistence-event-log.test.mjs
//
// Event-log behaviour: CAS conflict under concurrency, idempotent/conflict-safe
// evidence, single-terminal enforcement, transactional rollback, and structural
// integrity / tamper detection.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "../persistence/sqlite.mjs";

import {
    openRepository,
    openRepositoryReadOnly,
    computeEventHash,
    ERROR_CODES,
} from "../persistence/index.mjs";

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

    it("opens immutable read views without creating SQLite sidecars", () => {
        const file = repo.databaseFile;
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{ kind: "immutable-read", payload: {} }],
        });
        repo.checkpointWal({ force: true, mode: "TRUNCATE" });
        repo.close();
        repo = null;
        fs.rmSync(`${file}-wal`, { force: true });
        fs.rmSync(`${file}-shm`, { force: true });

        const readOnly = openRepositoryReadOnly({
            file,
            immutable: true,
        });
        try {
            expect(readOnly.countEvents("inv-1")).toBe(1);
            expect(readOnly.verifyInvestigation("inv-1").ok).toBe(true);
        } finally {
            readOnly.close();
        }
        expect(fs.existsSync(`${file}-wal`)).toBe(false);
        expect(fs.existsSync(`${file}-shm`)).toBe(false);
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

    it("rejects non-string createdAt values before hashing or SQLite binding", () => {
        for (const createdAt of [123, new Date("2026-01-01T00:00:00.000Z"), null]) {
            const err = catchCode(() => repo.appendEvents({
                investigationId: "inv-1",
                expectedHead: null,
                events: [{ kind: "bad-time", payload: {}, createdAt }],
            }));
            expect(err.code).toBe(ERROR_CODES.INVALID_ARGUMENT);
            expect(repo.countEvents("inv-1")).toBe(0);
        }
        expect(() => computeEventHash({
            investigationId: "inv-1",
            seq: 1,
            prevHash: "0".repeat(64),
            kind: "bad-time",
            payloadCanonical: "{}",
            createdAt: 123,
        })).toThrow(expect.objectContaining({ code: ERROR_CODES.INVALID_ARGUMENT }));
    });

    it("normalizes a valid zoned createdAt string before hashing and insertion", () => {
        const appended = repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{
                kind: "normalized-time",
                payload: {},
                createdAt: "2026-01-01T01:00:00+01:00",
            }],
        }).events[0];
        expect(appended.createdAt).toBe("2026-01-01T00:00:00.000Z");
        expect(repo.getEvent("inv-1", 1).createdAt).toBe(appended.createdAt);
        expect(repo.verifyInvestigation("inv-1").ok).toBe(true);
    });

    it("rejects a non-string repository clock before any row is inserted", () => {
        const file = path.join(dir, "bad-clock.sqlite");
        const badClock = openRepository({ file, now: () => 123 });
        try {
            const err = catchCode(() =>
                badClock.ensureInvestigation({ investigationId: "clock-inv" }));
            expect(err.code).toBe(ERROR_CODES.INVALID_ARGUMENT);
            expect(badClock.getInvestigation("clock-inv")).toBeNull();
        } finally {
            badClock.close();
        }
    });
});

describe("idempotent evidence ingestion", () => {
    it("deduplicates exact facts and rejects conflicting facts under the same key", () => {
        const first = repo.ingestEvidence({
            investigationId: "inv-1",
            attemptId: "attempt-9",
            evidenceKind: "stdout",
            kind: "evidence-observed",
            payload: { bytes: 10 },
        });
        expect(first.deduplicated).toBe(false);

        const duplicate = repo.ingestEvidence({
            investigationId: "inv-1",
            attemptId: "attempt-9",
            evidenceKind: "stdout",
            kind: "evidence-observed",
            payload: { bytes: 10 },
        });
        expect(duplicate.deduplicated).toBe(true);
        expect(duplicate.event.seq).toBe(first.event.seq);
        expect(duplicate.event.eventHash).toBe(first.event.eventHash);

        for (const conflict of [
            { kind: "evidence-observed", payload: { bytes: 999999 } },
            { kind: "different-kind", payload: { bytes: 10 } },
        ]) {
            const err = catchCode(() => repo.ingestEvidence({
                investigationId: "inv-1",
                attemptId: "attempt-9",
                evidenceKind: "stdout",
                ...conflict,
            }));
            expect(err.code).toBe(ERROR_CODES.EVIDENCE_CONFLICT);
        }

        expect(repo.countEvents("inv-1")).toBe(1);
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
    it("rolls back a first insert when the second event fails", () => {
        const head = repo.getHead("inv-1");
        const err = catchCode(() => repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: head.eventHash,
            events: [
                { kind: "first-write", payload: { n: 1 } },
                {
                    kind: "second-write",
                    payload: { n: 2 },
                    expectedEventHash: "0".repeat(64),
                },
            ],
        }));
        expect(err.code).toBe(ERROR_CODES.EVENT_HASH_MISMATCH);

        expect(repo.countEvents("inv-1")).toBe(0);
        expect(repo.getHead("inv-1")).toEqual(head);
        expect(repo.verifyInvestigation("inv-1").ok).toBe(true);
    });
});

describe("integrity verification & tamper detection", () => {
    it("binds event hashes to the exact payload text bytes", () => {
        const fields = {
            investigationId: "inv-1",
            seq: 1,
            prevHash: "0".repeat(64),
            kind: "opened",
            isTerminal: false,
            terminalKind: null,
            attemptId: null,
            evidenceKind: null,
            createdAt: "2026-01-01T00:00:00.000Z",
        };
        expect(computeEventHash({
            ...fields,
            payloadCanonical: '{"a":1,"b":2}',
        })).not.toBe(computeEventHash({
            ...fields,
            payloadCanonical: '{ "a": 1, "b": 2 }',
        }));
    });

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

    it.each([
        ["whitespace", '{ "a":1,"b":2,"text":"a"}'],
        ["key order", '{"b":2,"a":1,"text":"a"}'],
        ["alternate escape encoding", '{"a":1,"b":2,"text":"\\u0061"}'],
    ])("rejects a payload %s mutation even when JSON semantics are unchanged", (_label, mutated) => {
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{ kind: "opened", payload: { a: 1, b: 2, text: "a" } }],
        });
        const file = repo.databaseFile;
        repo.close();

        const raw = new DatabaseSync(file);
        raw.prepare("UPDATE events SET payload = ? WHERE investigation_id = 'inv-1' AND seq = 1")
            .run(mutated);
        raw.close();

        repo = openRepository({ file });
        const report = repo.verifyInvestigation("inv-1");
        expect(report.ok).toBe(false);
        expect(report.violations.some(
            (violation) => violation.code === ERROR_CODES.EVENT_PAYLOAD_NOT_CANONICAL,
        )).toBe(true);
        expect(report.violations.some(
            (violation) => violation.code === ERROR_CODES.EVENT_HASH_MISMATCH,
        )).toBe(true);
        expect(catchCode(() => repo.getEvent("inv-1", 1)).code)
            .toBe(ERROR_CODES.EVENT_PAYLOAD_NOT_CANONICAL);
    });

    it("rejects non-canonical payload text even when its exact-byte hash is rewritten", () => {
        const appended = repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{ kind: "opened", payload: { a: 1, b: 2 } }],
        }).events[0];
        const mutated = '{"b":2,"a":1}';
        const rewrittenHash = computeEventHash({
            investigationId: appended.investigationId,
            seq: appended.seq,
            prevHash: appended.prevHash,
            kind: appended.kind,
            payloadCanonical: mutated,
            isTerminal: appended.isTerminal,
            terminalKind: appended.terminalKind,
            attemptId: appended.attemptId,
            evidenceKind: appended.evidenceKind,
            createdAt: appended.createdAt,
        });
        const file = repo.databaseFile;
        repo.close();

        const raw = new DatabaseSync(file);
        raw.prepare(`
            UPDATE events
            SET payload = ?, event_hash = ?
            WHERE investigation_id = 'inv-1' AND seq = 1
        `).run(mutated, rewrittenHash);
        raw.close();

        repo = openRepository({ file });
        const report = repo.verifyInvestigation("inv-1");
        expect(report.ok).toBe(false);
        expect(report.violations.some(
            (violation) => violation.code === ERROR_CODES.EVENT_PAYLOAD_NOT_CANONICAL,
        )).toBe(true);
        expect(report.violations.some(
            (violation) => violation.code === ERROR_CODES.EVENT_HASH_MISMATCH,
        )).toBe(false);
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
