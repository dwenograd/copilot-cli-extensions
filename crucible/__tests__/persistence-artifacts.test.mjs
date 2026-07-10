// crucible/__tests__/persistence-artifacts.test.mjs
//
// Artifact metadata: inline BLOB round-trip and the external durable gate.
// The repository intentionally does NOT implement the filesystem CAS; it only
// tracks metadata and refuses to reference a non-durable external artifact.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    openRepository,
    openRepositoryReadOnly,
    ERROR_CODES,
    sha256Hex,
} from "../persistence/index.mjs";
import { DatabaseSync } from "../persistence/sqlite.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

let dir;
let repo;

beforeEach(() => {
    dir = fs.mkdtempSync(path.join(HERE, ".persist-tmp-"));
    repo = openRepository({ file: path.join(dir, "events.sqlite") });
    repo.ensureInvestigation({ investigationId: "inv-1" });
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

describe("inline artifacts", () => {
    it("round-trips arbitrary bytes (including NULs and high bytes)", () => {
        const bytes = Buffer.from([0, 1, 2, 255, 0, 42, 128, 7]);
        const meta = repo.putInlineArtifact({
            investigationId: "inv-1",
            artifactId: "art-inline",
            bytes,
            contentType: "application/octet-stream",
        });
        expect(meta.storage).toBe("inline");
        expect(meta.durable).toBe(true);
        expect(meta.sizeBytes).toBe(bytes.length);
        expect(meta.sha256).toBe(sha256Hex(bytes));

        const fetched = repo.getInlineArtifact("art-inline");
        expect(Buffer.from(fetched.bytes).equals(bytes)).toBe(true);
        expect(fetched.contentType).toBe("application/octet-stream");
    });

    it("inline artifacts are immediately referenceable (durable by nature)", () => {
        repo.putInlineArtifact({ investigationId: "inv-1", artifactId: "art-inline", bytes: Buffer.from("hi") });
        const ref = repo.referenceArtifact({ investigationId: "inv-1", artifactId: "art-inline" });
        expect(ref.artifactId).toBe("art-inline");
        expect(repo.listArtifactRefs("inv-1")).toHaveLength(1);
    });

    it("rejects fetching an external artifact through the inline accessor", () => {
        repo.registerExternalArtifact({
            investigationId: "inv-1", artifactId: "art-ext", algo: "sha256", hash: "ab".repeat(32),
        });
        const err = catchCode(() => repo.getInlineArtifact("art-ext"));
        expect(err.code).toBe(ERROR_CODES.INVALID_ARGUMENT);
    });

    it("reports referenced inline blob size corruption during read-only verification", () => {
        repo.putInlineArtifact({
            investigationId: "inv-1",
            artifactId: "art-inline",
            bytes: Buffer.from("inline-integrity"),
        });
        repo.referenceArtifact({ investigationId: "inv-1", artifactId: "art-inline" });
        repo.close();
        repo = null;

        const db = new DatabaseSync(path.join(dir, "events.sqlite"));
        try {
            db.prepare(
                "UPDATE artifacts SET size_bytes = size_bytes + 1 WHERE artifact_id = 'art-inline'",
            ).run();
        } finally {
            db.close();
        }
        repo = openRepository({ file: path.join(dir, "events.sqlite") });
        const report = repo.verifyInvestigation("inv-1");
        expect(report.ok).toBe(false);
        expect(report.violations.some((item) =>
            item.detail.includes("size metadata does not match"))).toBe(true);
    });
});

describe("read-only repository", () => {
    it("verifies existing state without permitting mutation", () => {
        repo.putInlineArtifact({
            investigationId: "inv-1",
            artifactId: "art-inline",
            bytes: Buffer.from("read-only"),
        });
        repo.referenceArtifact({ investigationId: "inv-1", artifactId: "art-inline" });
        const readOnly = openRepositoryReadOnly({
            file: path.join(dir, "events.sqlite"),
        });
        try {
            expect(readOnly.readOnly).toBe(true);
            expect(readOnly.verifyInvestigation("inv-1").ok).toBe(true);
            expect(() => readOnly.ensureInvestigation({
                investigationId: "must-not-write",
            })).toThrow();
        } finally {
            readOnly.close();
        }
        expect(repo.getInvestigation("must-not-write")).toBeNull();
    });
});

describe("external artifacts durable gate", () => {
    it("refuses to reference an external artifact before it is marked durable", () => {
        repo.registerExternalArtifact({
            investigationId: "inv-1",
            artifactId: "art-ext",
            algo: "sha256",
            hash: "cd".repeat(32),
            sizeBytes: 4096,
        });
        expect(repo.getArtifact("art-ext").durable).toBe(false);

        const err = catchCode(() => repo.referenceArtifact({ investigationId: "inv-1", artifactId: "art-ext" }));
        expect(err.code).toBe(ERROR_CODES.ARTIFACT_NOT_DURABLE);
        expect(repo.listArtifactRefs("inv-1")).toHaveLength(0);
    });

    it("allows referencing an external artifact after the caller marks it durable", () => {
        repo.registerExternalArtifact({
            investigationId: "inv-1", artifactId: "art-ext", algo: "blake3", hash: "ef".repeat(32),
        });
        const marked = repo.markArtifactDurable("art-ext");
        expect(marked.durable).toBe(true);
        expect(marked.hashAlgo).toBe("blake3");

        const ref = repo.referenceArtifact({ investigationId: "inv-1", artifactId: "art-ext" });
        expect(ref.artifactId).toBe("art-ext");
        expect(repo.verifyInvestigation("inv-1").ok).toBe(true);
    });

    it("reports ARTIFACT_NOT_FOUND when marking a missing artifact durable", () => {
        const err = catchCode(() => repo.markArtifactDurable("nope"));
        expect(err.code).toBe(ERROR_CODES.ARTIFACT_NOT_FOUND);
    });

    it("atomically binds durable artifact refs to the appended event sequence", () => {
        for (const [artifactId, hash] of [
            ["receipt-artifact", "12".repeat(32)],
            ["stdout-artifact", "34".repeat(32)],
        ]) {
            repo.registerExternalArtifact({
                investigationId: "inv-1",
                artifactId,
                algo: "sha256",
                hash,
                sizeBytes: 1,
            });
            repo.markArtifactDurable(artifactId);
        }

        const appended = repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{
                kind: "evidence",
                payload: { closure: "root" },
                artifactIds: ["stdout-artifact", "receipt-artifact", "receipt-artifact"],
            }],
        });

        expect(appended.events[0].artifactRefs.map((ref) => ref.artifactId)).toEqual([
            "receipt-artifact",
            "stdout-artifact",
        ]);
        expect(repo.listArtifactRefsForEvent("inv-1", 1).map((ref) => ref.artifactId))
            .toEqual(["receipt-artifact", "stdout-artifact"]);

        const duplicate = repo.referenceArtifact({
            investigationId: "inv-1",
            artifactId: "receipt-artifact",
            seq: 1,
        });
        expect(duplicate.deduplicated).toBe(true);
        expect(repo.listArtifactRefsForEvent("inv-1", 1)).toHaveLength(2);
    });

    it("rolls back an event append when any required artifact is missing or non-durable", () => {
        repo.registerExternalArtifact({
            investigationId: "inv-1",
            artifactId: "not-durable",
            algo: "sha256",
            hash: "56".repeat(32),
        });

        expect(() => repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{
                kind: "evidence",
                payload: {},
                artifactIds: ["not-durable"],
            }],
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.ARTIFACT_NOT_DURABLE,
        }));
        expect(repo.countEvents("inv-1")).toBe(0);
        expect(repo.listArtifactRefs("inv-1")).toEqual([]);

        expect(() => repo.appendEvents({
            investigationId: "inv-1",
            expectedHead: null,
            events: [{
                kind: "evidence",
                payload: {},
                artifactIds: ["missing-artifact"],
            }],
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.ARTIFACT_NOT_FOUND,
        }));
        expect(repo.countEvents("inv-1")).toBe(0);
        expect(repo.listArtifactRefs("inv-1")).toEqual([]);
    });
});
