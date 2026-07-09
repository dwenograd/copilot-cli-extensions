// oracle-v3/__tests__/persistence-artifact-store.test.mjs
//
// Immutable content-addressed artifact store: durable writes safe against
// duplicate writers, corruption detection, traversal + symlink rejection,
// deterministic snapshots, read-only materialization, and reconciliation that
// only ever sweeps unreferenced, aged objects.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
    ArtifactStore,
    openArtifactStore,
    ARTIFACT_STORE_ERROR_CODES,
    objectIdFor,
    parseObjectId,
    canonicalize,
} from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

let base;
let store;

beforeEach(() => {
    base = fs.mkdtempSync(path.join(HERE, ".persist-tmp-"));
    store = openArtifactStore({ root: path.join(base, "cas") });
});

afterEach(() => {
    fs.rmSync(base, { recursive: true, force: true });
});

function catchErr(fn) {
    try {
        fn();
    } catch (err) {
        return err;
    }
    throw new Error("expected the operation to throw");
}

function sha256Hex(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

describe("object writes", () => {
    it("stores bytes at an algorithm-tagged content address and round-trips", () => {
        const bytes = Buffer.from([0, 1, 2, 255, 0, 42, 128, 7]);
        const meta = store.putBytes(bytes, { contentType: "application/octet-stream" });

        expect(meta.algo).toBe("sha256");
        expect(meta.hash).toBe(sha256Hex(bytes));
        expect(meta.id).toBe(`sha256:${sha256Hex(bytes)}`);
        expect(meta.size).toBe(bytes.length);
        expect(meta.durable).toBe(true);
        expect(meta.existed).toBe(false);
        expect(meta.relativePath).toBe(
            `objects/sha256/${meta.hash.slice(0, 2)}/${meta.hash}`,
        );
        expect(fs.existsSync(meta.path)).toBe(true);

        const read = store.readObject(meta.id);
        expect(Buffer.from(read).equals(bytes)).toBe(true);
    });

    it("is idempotent: a duplicate write does not overwrite and reports existed=true", () => {
        const bytes = Buffer.from("hello world");
        const first = store.putBytes(bytes);
        const before = fs.statSync(first.path);

        const second = store.putBytes(bytes);
        expect(second.id).toBe(first.id);
        expect(second.existed).toBe(true);

        const after = fs.statSync(first.path);
        // Object bytes are immutable; the inode/content is untouched.
        expect(after.size).toBe(before.size);
        expect(store.readObject(first.id).toString()).toBe("hello world");
    });

    it("survives concurrent duplicate writers with exactly one installer", async () => {
        const bytes = Buffer.from("racing-writers-payload");
        const results = await Promise.all(
            Array.from({ length: 12 }, () => store.putStream(Readable.from([bytes]))),
        );
        const ids = new Set(results.map((r) => r.id));
        expect(ids.size).toBe(1);
        const installers = results.filter((r) => r.existed === false);
        expect(installers).toHaveLength(1);
        expect(store.verifyObject([...ids][0]).ok).toBe(true);
    });

    it("streams a file into the store without buffering the whole file", () => {
        const src = path.join(base, "big.bin");
        const payload = Buffer.alloc(200_000, 7);
        fs.writeFileSync(src, payload);
        const meta = store.putFile(src);
        expect(meta.size).toBe(payload.length);
        expect(meta.hash).toBe(sha256Hex(payload));
        expect(Buffer.from(store.readObject(meta.id)).equals(payload)).toBe(true);
    });

    it("verifies pre-existing bytes on put and rejects a corrupt occupying slot", () => {
        const bytes = Buffer.from("content-under-address");
        const meta = store.putBytes(bytes);
        // Corrupt the object file in place, then attempt to (re)write the same
        // content: install hits EEXIST and must catch the mismatch.
        fs.writeFileSync(meta.path, Buffer.from("tampered-different-bytes"));
        const err = catchErr(() => store.putBytes(bytes));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.OBJECT_CORRUPT);
    });
});

describe("read/verify integrity", () => {
    it("detects a corrupt object on read and via verifyObject", () => {
        const meta = store.putBytes(Buffer.from("integrity-check"));
        fs.writeFileSync(meta.path, Buffer.from("integrity-CHECK"));

        const err = catchErr(() => store.readObject(meta.id));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.OBJECT_CORRUPT);

        const status = store.verifyObject(meta.id);
        expect(status.ok).toBe(false);
        expect(status.reason).toBe("corrupt");
    });

    it("detects a missing object", () => {
        const meta = store.putBytes(Buffer.from("gone-soon"));
        fs.rmSync(meta.path);

        const err = catchErr(() => store.readObject(meta.id));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.OBJECT_NOT_FOUND);
        expect(store.verifyObject(meta.id)).toMatchObject({ ok: false, reason: "missing" });
    });

    it("rejects malformed and non-sha256 object ids", () => {
        expect(catchErr(() => parseObjectId("not-an-id"))).toBeInstanceOf(Error);
        expect(catchErr(() => parseObjectId("md5:abcd"))).toBeInstanceOf(Error);
        expect(catchErr(() => store.objectPath("sha256:xyz"))).toBeInstanceOf(Error);
    });
});

describe("directory snapshots", () => {
    function seedTree(root) {
        fs.mkdirSync(path.join(root, "sub", "deep"), { recursive: true });
        fs.writeFileSync(path.join(root, "a.txt"), "alpha");
        fs.writeFileSync(path.join(root, "b.txt"), "bravo");
        fs.writeFileSync(path.join(root, "sub", "c.txt"), "charlie");
        fs.writeFileSync(path.join(root, "sub", "deep", "d.bin"), Buffer.from([1, 2, 3, 4]));
    }

    it("produces a deterministic, sorted, canonical snapshot", () => {
        const s1 = path.join(base, "src1");
        const s2 = path.join(base, "src2");
        seedTree(s1);
        seedTree(s2);

        const snapA = store.ingestDirectory({ sourceDir: s1 });
        const snapB = store.ingestDirectory({ sourceDir: s2 });

        expect(snapA.snapshot).toBe(snapB.snapshot);
        expect(snapA.fileCount).toBe(4);

        const paths = snapA.manifest.entries.map((e) => e.path);
        expect(paths).toEqual(["a.txt", "b.txt", "sub/c.txt", "sub/deep/d.bin"]);
        expect([...paths]).toEqual([...paths].sort());
        // Every entry references a real, verifiable CAS object.
        for (const e of snapA.manifest.entries) {
            expect(store.verifyObject(e.object).ok).toBe(true);
        }
    });

    it("rejects a symlink/junction inside the source tree", () => {
        const src = path.join(base, "with-link");
        fs.mkdirSync(src, { recursive: true });
        fs.writeFileSync(path.join(src, "real.txt"), "ok");
        const outside = path.join(base, "outside");
        fs.mkdirSync(outside, { recursive: true });
        fs.writeFileSync(path.join(outside, "secret.txt"), "leak");

        // A directory junction needs no elevation on Windows and behaves like a
        // symlink for lstat purposes.
        fs.symlinkSync(outside, path.join(src, "escape"), "junction");

        const err = catchErr(() => store.ingestDirectory({ sourceDir: src }));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.SYMLINK_REJECTED);
    });

    it("rejects a symlinked source root", () => {
        const realRoot = path.join(base, "real-root");
        fs.mkdirSync(realRoot, { recursive: true });
        fs.writeFileSync(path.join(realRoot, "x.txt"), "x");
        const linkRoot = path.join(base, "link-root");
        fs.symlinkSync(realRoot, linkRoot, "junction");

        const err = catchErr(() => store.ingestDirectory({ sourceDir: linkRoot }));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.SYMLINK_REJECTED);
    });

    it("enforces the file-count cap", () => {
        const capped = openArtifactStore({ root: path.join(base, "cas-capped"), limits: { maxFiles: 1 } });
        const src = path.join(base, "many");
        fs.mkdirSync(src, { recursive: true });
        fs.writeFileSync(path.join(src, "one.txt"), "1");
        fs.writeFileSync(path.join(src, "two.txt"), "2");
        const err = catchErr(() => capped.ingestDirectory({ sourceDir: src }));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.LIMIT_EXCEEDED);
    });

    it("fails closed when a file is swapped after open during ingestion", () => {
        const src = path.join(base, "swap-race");
        fs.mkdirSync(src, { recursive: true });
        const target = path.join(src, "entry.txt");
        fs.writeFileSync(target, "before");
        let injected = false;
        const err = catchErr(() => store.ingestDirectory({
            sourceDir: src,
            hooks: {
                afterFileOpen({ path: openedPath }) {
                    if (!injected && openedPath === target) {
                        injected = true;
                        fs.writeFileSync(target, "after-with-different-bytes");
                    }
                },
            },
        }));
        expect(injected).toBe(true);
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.SOURCE_CHANGED);
    });
});

describe("materialization", () => {
    function seedAndSnapshot() {
        const src = path.join(base, "src");
        fs.mkdirSync(path.join(src, "sub"), { recursive: true });
        fs.writeFileSync(path.join(src, "a.txt"), "alpha");
        fs.writeFileSync(path.join(src, "sub", "b.txt"), "bravo");
        return store.ingestDirectory({ sourceDir: src });
    }

    it("materializes a snapshot read-only into a fresh destination", () => {
        const snap = seedAndSnapshot();
        const dest = path.join(base, "out");
        const res = store.materializeSnapshot({ snapshot: snap.snapshot, destDir: dest });

        expect(res.fileCount).toBe(2);
        expect(fs.readFileSync(path.join(dest, "a.txt"), "utf8")).toBe("alpha");
        expect(fs.readFileSync(path.join(dest, "sub", "b.txt"), "utf8")).toBe("bravo");

        // Best-effort read-only bit on the materialized files.
        const mode = fs.statSync(path.join(dest, "a.txt")).mode;
        expect(mode & 0o200).toBe(0);
    });

    it("refuses a pre-existing destination", () => {
        const snap = seedAndSnapshot();
        const dest = path.join(base, "out");
        fs.mkdirSync(dest, { recursive: true });
        const err = catchErr(() => store.materializeSnapshot({ snapshot: snap.snapshot, destDir: dest }));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.DESTINATION_EXISTS);
    });

    it("refuses a manifest whose entry path escapes the destination (traversal)", () => {
        const inner = store.putBytes(Buffer.from("x"));
        const manifest = {
            type: "oracle-v3-snapshot",
            version: 1,
            algo: "sha256",
            fileCount: 1,
            totalBytes: 1,
            entries: [{ path: "../escape.txt", size: 1, object: inner.id }],
        };
        const evil = store.putBytes(Buffer.from(canonicalize(manifest), "utf8"));
        const err = catchErr(() => store.materializeSnapshot({ snapshot: evil.id, destDir: path.join(base, "out") }));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.UNSAFE_PATH);
        expect(fs.existsSync(path.join(base, "out", "..", "escape.txt"))).toBe(false);
    });

    it("refuses a manifest with an absolute entry path", () => {
        const inner = store.putBytes(Buffer.from("y"));
        const manifest = {
            type: "oracle-v3-snapshot",
            version: 1,
            algo: "sha256",
            fileCount: 1,
            totalBytes: 1,
            entries: [{ path: "C:/Windows/evil.txt", size: 1, object: inner.id }],
        };
        const evil = store.putBytes(Buffer.from(canonicalize(manifest), "utf8"));
        const err = catchErr(() => store.materializeSnapshot({ snapshot: evil.id, destDir: path.join(base, "out2") }));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.UNSAFE_PATH);
    });

    it("verifySnapshot reports missing and corrupt closure members", () => {
        const snap = seedAndSnapshot();
        expect(store.verifySnapshot(snap.snapshot).ok).toBe(true);

        const entry = snap.manifest.entries[0];
        fs.writeFileSync(store.objectPath(entry.object), Buffer.from("corrupted"));
        const report = store.verifySnapshot(snap.snapshot);
        expect(report.ok).toBe(false);
        expect(report.corrupt).toContain(entry.object);
    });
});

describe("reconciliation", () => {
    it("reports referenced missing/corrupt and never deletes referenced objects", () => {
        const kept = store.putBytes(Buffer.from("kept-referenced"));
        const corrupt = store.putBytes(Buffer.from("will-corrupt"));
        const gone = store.putBytes(Buffer.from("will-delete"));

        fs.writeFileSync(store.objectPath(corrupt.id), Buffer.from("xxxxxxxx"));
        fs.rmSync(store.objectPath(gone.id));

        const report = store.reconcile({
            referenced: [kept.id, corrupt.id, gone.id],
            olderThanMs: 0,
            now: Date.now(),
        });

        expect(report.referenced.ok).toContain(kept.id);
        expect(report.referenced.corrupt).toContain(corrupt.id);
        expect(report.referenced.missing).toContain(gone.id);
        // A corrupt-but-referenced object is a finding, never silently removed.
        expect(report.removedObjects).not.toContain(corrupt.id);
        expect(fs.existsSync(store.objectPath(corrupt.id))).toBe(true);
    });

    it("removes only unreferenced orphan objects older than the caller age", () => {
        const referenced = store.putBytes(Buffer.from("stay"));
        const oldOrphan = store.putBytes(Buffer.from("old-orphan"));
        const freshOrphan = store.putBytes(Buffer.from("fresh-orphan"));

        // Age the old orphan two hours into the past.
        const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
        fs.utimesSync(store.objectPath(oldOrphan.id), twoHoursAgo, twoHoursAgo);

        const report = store.reconcile({
            referenced: [referenced.id],
            olderThanMs: 60 * 60 * 1000, // 1 hour
            now: Date.now(),
        });

        expect(report.removedObjects).toContain(oldOrphan.id);
        expect(report.keptOrphans).toContain(freshOrphan.id);
        expect(fs.existsSync(store.objectPath(oldOrphan.id))).toBe(false);
        expect(fs.existsSync(store.objectPath(freshOrphan.id))).toBe(true);
        expect(fs.existsSync(store.objectPath(referenced.id))).toBe(true);
    });

    it("expands snapshot closures from trusted caller-supplied snapshot ids", () => {
        const src = path.join(base, "snap-src");
        fs.mkdirSync(src, { recursive: true });
        fs.writeFileSync(path.join(src, "keep.txt"), "keep-me");
        const snap = store.ingestDirectory({ sourceDir: src });

        const orphan = store.putBytes(Buffer.from("orphan"));
        const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
        fs.utimesSync(store.objectPath(orphan.id), twoHoursAgo, twoHoursAgo);
        // Age the snapshot's file object too, to prove reference protection —
        // not age — is what keeps it.
        for (const e of snap.manifest.entries) {
            fs.utimesSync(store.objectPath(e.object), twoHoursAgo, twoHoursAgo);
        }
        fs.utimesSync(store.objectPath(snap.snapshot), twoHoursAgo, twoHoursAgo);

        const report = store.reconcile({
            snapshots: [snap.snapshot],
            olderThanMs: 60 * 60 * 1000,
            now: Date.now(),
        });

        expect(report.removedObjects).toContain(orphan.id);
        for (const e of snap.manifest.entries) {
            expect(report.removedObjects).not.toContain(e.object);
            expect(fs.existsSync(store.objectPath(e.object))).toBe(true);
        }
        expect(fs.existsSync(store.objectPath(snap.snapshot))).toBe(true);
    });

    it("sweeps stale staging files", () => {
        const stagingDir = path.join(store.root, "staging");
        const stale = path.join(stagingDir, "stale-abandoned.tmp");
        fs.writeFileSync(stale, "half-written");
        const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
        fs.utimesSync(stale, twoHoursAgo, twoHoursAgo);

        const report = store.reconcile({ referenced: [], olderThanMs: 60 * 60 * 1000, now: Date.now() });
        expect(report.removedStaging).toContain("stale-abandoned.tmp");
        expect(fs.existsSync(stale)).toBe(false);
    });

    it("requires a non-negative caller-provided age", () => {
        const err = catchErr(() => store.reconcile({ referenced: [], olderThanMs: -1, now: Date.now() }));
        expect(err.code).toBe("ORACLE_PERSIST_INVALID_ARGUMENT");
    });
});

describe("store construction", () => {
    it("is created via openArtifactStore and exposes its resolved root", () => {
        expect(store).toBeInstanceOf(ArtifactStore);
        expect(fs.existsSync(path.join(store.root, "objects", "sha256"))).toBe(true);
        expect(fs.existsSync(path.join(store.root, "staging"))).toBe(true);
    });

    it("objectIdFor validates the digest shape", () => {
        expect(objectIdFor("ab".repeat(32))).toBe(`sha256:${"ab".repeat(32)}`);
        expect(catchErr(() => objectIdFor("short"))).toBeInstanceOf(Error);
    });
});
