// oracle-v3/__tests__/persistence-artifacts.test.mjs
//
// Artifact metadata: inline BLOB round-trip and the external durable gate.
// The repository intentionally does NOT implement the filesystem CAS; it only
// tracks metadata and refuses to reference a non-durable external artifact.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { openRepository, ERROR_CODES, sha256Hex } from "../persistence/index.mjs";

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
});
