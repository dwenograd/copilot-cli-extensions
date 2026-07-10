// crucible/__tests__/persistence-safety.test.mjs
//
// Cross-cutting safety guarantees: read-only queries never mutate state,
// local-file-only path rejection, and explicit schema-version fail-closed.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "../persistence/sqlite.mjs";

import {
    openRepository,
    assertLocalDatabasePath,
    ERROR_CODES,
    SCHEMA_VERSION,
} from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

const TABLES = [
    "schema_meta",
    "investigations",
    "events",
    "runner_leases",
    "command_attempts",
    "runner_incarnations",
    "supervisor_authority",
    "artifacts",
    "artifact_refs",
    "projection_metadata",
];

let dir;
let repo;

beforeEach(() => {
    dir = fs.mkdtempSync(path.join(HERE, ".persist-tmp-"));
    repo = openRepository({ file: path.join(dir, "events.sqlite") });
});

afterEach(() => {
    try {
        repo?.close();
    } catch {
        // already closed
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

// Logical snapshot of the whole database, read via an independent read-only
// connection so the assertion is decoupled from the repository under test.
function snapshot(file) {
    const ro = new DatabaseSync(file, { readOnly: true });
    try {
        const parts = [];
        const uv = ro.prepare("PRAGMA user_version").get();
        parts.push(`user_version=${uv.user_version}`);
        for (const table of TABLES) {
            const rows = ro.prepare(`SELECT * FROM ${table}`).all();
            const normalized = rows.map((row) => {
                const out = {};
                for (const key of Object.keys(row).sort()) {
                    const value = row[key];
                    out[key] = value instanceof Uint8Array ? `blob:${Buffer.from(value).toString("hex")}` : value;
                }
                return out;
            });
            normalized.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
            parts.push(`${table}=${JSON.stringify(normalized)}`);
        }
        return parts.join("\n");
    } finally {
        ro.close();
    }
}

describe("read-only queries do not mutate state", () => {
    it("leaves the database byte-for-byte (logically) unchanged", () => {
        // Populate a representative amount of state.
        repo.ensureInvestigation({ investigationId: "inv-1", metadata: { a: 1 } });
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{ kind: "opened", payload: { q: 1 } }],
        });
        repo.ingestEvidence({ investigationId: "inv-1", attemptId: "a1", evidenceKind: "obs", kind: "ev", payload: {} });
        repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: repo.getHead("inv-1").eventHash,
            events: [{ kind: "verified", terminal: { kind: "verified_result" }, payload: { ok: true } }],
        });
        repo.acquireLease({ investigationId: "inv-1", leaseId: "L1", owner: "runner" });
        repo.reserveCommand({ investigationId: "inv-1", attemptId: "c1", command: "cmd", leaseId: "L1", fencingToken: 1, owner: "runner" });
        repo.putInlineArtifact({ investigationId: "inv-1", artifactId: "art1", bytes: Buffer.from("data") });
        repo.registerExternalArtifact({ investigationId: "inv-1", artifactId: "art2", algo: "sha256", hash: "aa".repeat(32) });
        repo.markArtifactDurable("art2");
        repo.referenceArtifact({ investigationId: "inv-1", artifactId: "art2" });
        repo.setProjectionCheckpoint({ name: "proj", investigationId: "inv-1", lastAppliedSeq: 3, checkpoint: { c: 1 } });

        const before = snapshot(repo.databaseFile);

        // Exercise every read-only accessor, including integrity verification.
        repo.getInvestigation("inv-1");
        repo.getHead("inv-1");
        repo.listEvents("inv-1");
        repo.getEvent("inv-1", 1);
        repo.getTerminalEvent("inv-1");
        repo.countEvents("inv-1");
        repo.getCommandAttempt("c1");
        repo.listCommandAttempts("inv-1");
        repo.getActiveLease("inv-1");
        repo.getSupervisorAuthority("inv-1");
        repo.getArtifact("art1");
        repo.getInlineArtifact("art1");
        repo.getArtifact("art2");
        repo.listArtifactRefs("inv-1");
        repo.getProjectionCheckpoint({ name: "proj", investigationId: "inv-1" });
        const report = repo.verifyInvestigation("inv-1");
        expect(report.ok).toBe(true);

        const after = snapshot(repo.databaseFile);
        expect(after).toBe(before);
    });

    it("verifyInvestigation does not repair a tampered log", () => {
        repo.ensureInvestigation({ investigationId: "inv-1" });
        repo.appendEvents({ investigationId: "inv-1", expectedHead: null, events: [{ kind: "a", payload: { v: 1 } }] });
        repo.close();

        const raw = new DatabaseSync(repo.databaseFile);
        raw.exec("PRAGMA journal_mode=WAL;");
        raw.prepare("UPDATE events SET payload = ? WHERE seq = 1").run(JSON.stringify({ v: 2 }));
        raw.close();

        repo = openRepository({ file: repo.databaseFile });
        const before = snapshot(repo.databaseFile);
        expect(repo.verifyInvestigation("inv-1").ok).toBe(false);
        // Running verification again must still report the same tamper (no repair).
        const after = snapshot(repo.databaseFile);
        expect(after).toBe(before);
        expect(repo.verifyInvestigation("inv-1").ok).toBe(false);
    });
});

describe("local-file-only path rejection", () => {
    it("rejects UNC / network paths", () => {
        for (const p of [
            "\\\\192.168.1.117\\Spire\\AI\\db.sqlite",
            "//fileserver/share/db.sqlite",
            "\\\\?\\GLOBALROOT\\Device\\Mup\\server\\share\\db.sqlite",
        ]) {
            const err = catchCode(() => assertLocalDatabasePath(p));
            expect(err.code).toBe(ERROR_CODES.LOCAL_PATH_REQUIRED);
            expect(err.details.reason).toBe("unc");
        }
    });

    it("rejects known cloud-sync roots", () => {
        const err = catchCode(() => assertLocalDatabasePath("C:/Users/Someone/OneDrive/crucible/db.sqlite"));
        expect(err.code).toBe(ERROR_CODES.LOCAL_PATH_REQUIRED);
        expect(err.details.reason).toBe("cloud-sync");
    });

    it("rejects a configured deny root", () => {
        const err = catchCode(() => assertLocalDatabasePath("X:/AI/spotter/db.sqlite", { denyRoots: ["X:/AI"] }));
        expect(err.code).toBe(ERROR_CODES.LOCAL_PATH_REQUIRED);
        expect(err.details.reason).toBe("deny-root");
    });

    it("rejects in-memory databases (no durability)", () => {
        const err = catchCode(() => assertLocalDatabasePath(":memory:"));
        expect(err.code).toBe(ERROR_CODES.INVALID_ARGUMENT);
    });

    it("openRepository refuses a UNC path outright", () => {
        const err = catchCode(() => openRepository({ file: "\\\\server\\share\\db.sqlite" }));
        expect(err.code).toBe(ERROR_CODES.LOCAL_PATH_REQUIRED);
    });

    it("accepts a normal local path", () => {
        const resolved = assertLocalDatabasePath(path.join(dir, "ok.sqlite"));
        expect(resolved.endsWith("ok.sqlite")).toBe(true);
        expect(assertLocalDatabasePath(path.join(dir, "box", "ok.sqlite"))).toContain("box");
    });
});

describe("explicit schema versioning", () => {
    it("migrates generation-only schema 3 databases to incarnation authority", () => {
        const legacyFile = path.join(dir, "schema-3.sqlite");
        const legacy = openRepository({ file: legacyFile });
        legacy.ensureInvestigation({ investigationId: "legacy-inv" });
        legacy.close();

        const raw = new DatabaseSync(legacyFile);
        raw.exec(`
            PRAGMA foreign_keys = OFF;
            DROP TABLE supervisor_authority;
            DROP TABLE runner_incarnations;
            ALTER TABLE command_attempts DROP COLUMN runner_incarnation;
            ALTER TABLE runner_leases DROP COLUMN runner_incarnation;
            UPDATE schema_meta SET value = '3' WHERE key = 'schema_version';
            PRAGMA user_version = 3;
        `);
        raw.close();

        const migrated = openRepository({ file: legacyFile });
        try {
            expect(migrated.schemaVersion).toBe(SCHEMA_VERSION);
            migrated.claimSupervisorGeneration({
                investigationId: "legacy-inv",
                supervisorGeneration: 1,
                supervisorNonce: "legacy-supervisor",
            });
            migrated.issueRunnerIncarnation({
                investigationId: "legacy-inv",
                supervisorGeneration: 1,
                supervisorNonce: "legacy-supervisor",
                runnerIncarnation: "legacy-runner-incarnation",
            });
            expect(migrated.acquireLease({
                investigationId: "legacy-inv",
                leaseId: "legacy-lease",
                owner: "legacy-runner",
                supervisorGeneration: 1,
                runnerIncarnation: "legacy-runner-incarnation",
            })).toMatchObject({
                fencingToken: 1,
                runnerIncarnation: "legacy-runner-incarnation",
            });
        } finally {
            migrated.close();
        }
    });

    it("fails closed when the on-disk schema version does not match", () => {
        repo.ensureInvestigation({ investigationId: "inv-1" });
        repo.close();

        // Simulate a database written by an incompatible schema version.
        const raw = new DatabaseSync(repo.databaseFile);
        raw.exec("PRAGMA journal_mode=WAL;");
        raw.exec("PRAGMA user_version = 999;");
        raw.prepare("UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'").run();
        raw.close();

        const err = catchCode(() => openRepository({ file: repo.databaseFile }));
        expect(err.code).toBe(ERROR_CODES.SCHEMA_VERSION_MISMATCH);

        // Reopen at the correct version for afterEach cleanup symmetry.
        const rawFix = new DatabaseSync(repo.databaseFile);
        rawFix.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`);
        rawFix.prepare("UPDATE schema_meta SET value = ? WHERE key = 'schema_version'").run(String(SCHEMA_VERSION));
        rawFix.close();
        repo = openRepository({ file: repo.databaseFile });
    });
});
