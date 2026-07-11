import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
    ARTIFACT_STORE_ERROR_CODES,
    openArtifactStore,
} from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

let base;
let root;

beforeEach(() => {
    base = fs.mkdtempSync(path.join(HERE, ".cas-durable-tmp-"));
    root = path.join(base, "cas");
});

afterEach(() => {
    fs.rmSync(base, { recursive: true, force: true });
});

function objectIdentity(bytes) {
    const hash = createHash("sha256").update(bytes).digest("hex");
    return { hash, id: `sha256:${hash}` };
}

function markerPath(hash, state) {
    return path.join(
        root,
        ".crucible",
        "installations",
        "sha256",
        hash.slice(0, 2),
        `${hash}.${state}.json`,
    );
}

function journalFiles() {
    const journalRoot = path.join(root, ".crucible", "journal");
    return fs.readdirSync(journalRoot)
        .filter((name) => name.endsWith(".json"))
        .sort();
}

function fault(code, message) {
    return Object.assign(new Error(message), { code, syscall: "injected" });
}

function throwOnceAt(point, predicate = () => true, error = new Error(`simulated crash at ${point}`)) {
    let thrown = false;
    return (event) => {
        if (!thrown && event.point === point && predicate(event)) {
            thrown = true;
            throw error;
        }
    };
}

function catchErr(fn) {
    try {
        fn();
    } catch (err) {
        return err;
    }
    throw new Error("expected operation to throw");
}

describe("CAS durable installation lifecycle", () => {
    it("persists monotonic installed and referenced state under private metadata", () => {
        const store = openArtifactStore({ root });
        const bytes = Buffer.from("journal-lifecycle");
        const meta = store.putBytes(bytes);

        expect(meta.durable).toBe(true);
        expect(fs.existsSync(markerPath(meta.hash, "installed"))).toBe(true);
        expect(fs.existsSync(markerPath(meta.hash, "referenced"))).toBe(false);
        expect(journalFiles()).toEqual([]);

        const report = store.reconcile({
            referenced: [meta.id],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.referenced.ok).toContain(meta.id);
        expect(report.installations.markedReferenced).toContain(meta.id);
        expect(fs.existsSync(markerPath(meta.hash, "referenced"))).toBe(true);

        const later = store.reconcile({
            referenced: [],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(later.installations.persistentReferenced).toContain(meta.id);
        expect(later.removedObjects).not.toContain(meta.id);
        expect(store.verifyObject(meta.id).ok).toBe(true);
    });

    it("recovers a durable staging journal and completes it before marking referenced", () => {
        const bytes = Buffer.from("recover-journalled-stage");
        const { id, hash } = objectIdentity(bytes);
        const crashing = openArtifactStore({
            root,
            faultInjector: throwOnceAt("staging-journal-durable"),
        });

        expect(() => crashing.putBytes(bytes)).toThrow();
        expect(journalFiles()).toHaveLength(1);
        expect(fs.existsSync(markerPath(hash, "installed"))).toBe(false);

        const recovered = openArtifactStore({ root });
        const report = recovered.reconcile({
            referenced: [id],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.installations.completed.map((entry) => entry.object)).toContain(id);
        expect(report.referenced).toMatchObject({ missing: [], corrupt: [] });
        expect(report.referenced.ok).toContain(id);
        expect(recovered.verifyObject(id).ok).toBe(true);
        expect(fs.existsSync(markerPath(hash, "installed"))).toBe(true);
        expect(fs.existsSync(markerPath(hash, "referenced"))).toBe(true);
        expect(journalFiles()).toEqual([]);
    });

    it("reports and removes an aged durable unreferenced orphan with its marker", () => {
        const store = openArtifactStore({ root });
        const meta = store.putBytes(Buffer.from("durable-orphan"));
        const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
        fs.utimesSync(meta.path, old, old);

        const report = store.reconcile({
            referenced: [],
            olderThanMs: 60 * 60 * 1000,
            now: Date.now(),
        });
        expect(report.installations.durableOrphans).toContain(meta.id);
        expect(report.removedObjects).toContain(meta.id);
        expect(report.installations.removedMarkers).toContain(meta.id);
        expect(fs.existsSync(meta.path)).toBe(false);
        expect(fs.existsSync(markerPath(meta.hash, "installed"))).toBe(false);
    });

    it("rechecks the reference generation before deleting a raced object", () => {
        const writer = openArtifactStore({ root });
        const meta = writer.putBytes(Buffer.from("newly-referenced-race"));
        const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
        fs.utimesSync(meta.path, old, old);

        let raced = false;
        const sweeper = openArtifactStore({
            root,
            faultInjector(event) {
                if (!raced
                    && event.point === "before-reconcile-object-delete"
                    && event.object === meta.id) {
                    raced = true;
                    openArtifactStore({ root }).reconcile({
                        referenced: [meta.id],
                        olderThanMs: 0,
                        now: Date.now(),
                    });
                }
            },
        });
        const report = sweeper.reconcile({
            referenced: [],
            olderThanMs: 60 * 60 * 1000,
            now: Date.now(),
        });

        expect(raced).toBe(true);
        expect(report.removedObjects).not.toContain(meta.id);
        expect(report.installations.persistentReferenced).toContain(meta.id);
        expect(fs.existsSync(meta.path)).toBe(true);
        expect(fs.existsSync(markerPath(meta.hash, "referenced"))).toBe(true);
    });

    it("rejects a non-string installation clock before journaling it", () => {
        const badClock = openArtifactStore({ root, now: () => 123 });
        const { hash } = objectIdentity(Buffer.from("bad-installation-clock"));
        const err = catchErr(() => badClock.putBytes(Buffer.from("bad-installation-clock")));
        expect(err.code).toBe("CRUCIBLE_PERSIST_INVALID_ARGUMENT");
        expect(fs.existsSync(markerPath(hash, "installed"))).toBe(false);
    });

    it("removes an aged corrupt journal without trusting its staged path", () => {
        const bytes = Buffer.from("corrupt-journal");
        const crashing = openArtifactStore({
            root,
            faultInjector: throwOnceAt("staging-journal-durable"),
        });
        expect(() => crashing.putBytes(bytes)).toThrow();

        const [journalName] = journalFiles();
        const journalPath = path.join(root, ".crucible", "journal", journalName);
        fs.writeFileSync(journalPath, "{\"tampered\":true}");
        const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
        fs.utimesSync(journalPath, old, old);
        for (const name of fs.readdirSync(path.join(root, "staging"))) {
            if (name.endsWith(".tmp")) {
                fs.utimesSync(path.join(root, "staging", name), old, old);
            }
        }

        const report = openArtifactStore({ root }).reconcile({
            referenced: [],
            olderThanMs: 60 * 60 * 1000,
            now: Date.now(),
        });
        expect(report.installations.corruptRecords).toHaveLength(1);
        expect(report.installations.removedJournalEntries).toContain(journalName);
        expect(report.removedStaging.some((name) => name.endsWith(".tmp"))).toBe(true);
        expect(journalFiles()).toEqual([]);
    });
});

describe("fsync failure propagation", () => {
    it.each([
        ["staging file", "before-file-fsync", (event) => event.purpose === "staging object file", false],
        ["installed object file", "before-file-fsync", (event) => event.purpose === "installed object file", true],
        ["object parent directory", "before-directory-fsync", (event) => event.purpose === "object parent", true],
        [
            "object prefix parent directory",
            "before-directory-fsync",
            (event) => event.purpose === "object prefix parent",
            true,
        ],
        [
            "installed marker file",
            "before-file-fsync",
            (event) => event.purpose === "installed installation marker temporary file",
            true,
        ],
        [
            "installed marker directory",
            "before-directory-fsync",
            (event) => event.purpose === "installed installation marker parent",
            true,
        ],
        [
            "installed marker ancestor directory",
            "before-directory-fsync",
            (event) => event.purpose === "installed installation marker parent ancestor",
            true,
        ],
    ])("propagates an unexpected %s fsync failure and never returns durable", (
        _label,
        point,
        predicate,
        recoverable,
    ) => {
        const bytes = Buffer.from(`fsync-failure-${_label}`);
        const { id, hash } = objectIdentity(bytes);
        const store = openArtifactStore({
            root,
            faultInjector: throwOnceAt(
                point,
                predicate,
                fault("EIO", `injected ${_label} fsync failure`),
            ),
        });

        const err = catchErr(() => store.putBytes(bytes));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.IO_ERROR);
        expect(fs.existsSync(markerPath(hash, "referenced"))).toBe(false);

        const recovered = openArtifactStore({ root });
        const report = recovered.reconcile({
            referenced: recoverable ? [id] : [],
            olderThanMs: 0,
            now: Date.now(),
        });
        if (recoverable) {
            expect(report.referenced.ok).toContain(id);
            expect(report.referenced.missing).not.toContain(id);
            expect(recovered.verifyObject(id).ok).toBe(true);
        } else {
            expect(recovered.hasObject(id)).toBe(false);
        }
    });

    it("does not treat an unsupported Windows directory fsync as durable", () => {
        if (process.platform !== "win32") {
            return;
        }
        const bytes = Buffer.from("unsupported-windows-directory-fsync");
        const { hash } = objectIdentity(bytes);
        const store = openArtifactStore({
            root,
            faultInjector: throwOnceAt(
                "before-directory-fsync",
                (event) => event.purpose === "installed installation marker parent",
                fault("EPERM", "directory fsync unsupported"),
            ),
        });

        const err = catchErr(() => store.putBytes(bytes));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.IO_ERROR);
        expect(fs.existsSync(markerPath(hash, "referenced"))).toBe(false);
    });
});

describe("no-clobber duplicate and fallback installation", () => {
    const linkUnsupported = (event) => {
        if (event.point === "before-object-link") {
            throw fault("EPERM", "hard links unavailable");
        }
    };

    it("uses the rename/copy fallback without clobbering duplicate writers", () => {
        const bytes = Buffer.from("fallback-duplicate");
        const store = openArtifactStore({ root, faultInjector: linkUnsupported });

        const first = store.putBytes(bytes);
        const second = store.putBytes(bytes);
        expect(first.existed).toBe(false);
        expect(second.existed).toBe(true);
        expect(second.id).toBe(first.id);
        expect(store.readObject(first.id).equals(bytes)).toBe(true);
    });

    it("propagates link and rename failures while leaving journalled recovery deterministic", () => {
        const bytes = Buffer.from("rename-failure-recovery");
        const { id } = objectIdentity(bytes);
        const injector = (event) => {
            if (event.point === "before-object-link") {
                throw fault("EPERM", "force fallback");
            }
            if (event.point === "before-object-rename") {
                throw fault("EIO", "rename failed");
            }
        };
        const store = openArtifactStore({ root, faultInjector: injector });

        const err = catchErr(() => store.putBytes(bytes));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.IO_ERROR);
        expect(journalFiles()).toHaveLength(1);

        const recovered = openArtifactStore({ root });
        const reconcileNow = Date.now();
        const first = recovered.reconcile({
            referenced: [id],
            olderThanMs: 0,
            now: reconcileNow,
            dryRun: true,
        });
        const second = recovered.reconcile({
            referenced: [id],
            olderThanMs: 0,
            now: reconcileNow,
            dryRun: true,
        });
        expect(second).toEqual(first);

        const actual = recovered.reconcile({
            referenced: [id],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(actual.referenced.ok).toContain(id);
        expect(recovered.verifyObject(id).ok).toBe(true);
    });

    it("propagates an unexpected link failure and recovers from the retained journal", () => {
        const bytes = Buffer.from("link-failure-recovery");
        const { id } = objectIdentity(bytes);
        const store = openArtifactStore({
            root,
            faultInjector: throwOnceAt(
                "before-object-link",
                () => true,
                fault("EIO", "link failed"),
            ),
        });

        const err = catchErr(() => store.putBytes(bytes));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.IO_ERROR);
        expect(journalFiles()).toHaveLength(1);

        const recovered = openArtifactStore({ root });
        const report = recovered.reconcile({
            referenced: [id],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.referenced.ok).toContain(id);
        expect(recovered.verifyObject(id).ok).toBe(true);
    });

    it("validates a racing existing slot and never overwrites different bytes", () => {
        const bytes = Buffer.from("intended-fallback-bytes");
        const { id, hash } = objectIdentity(bytes);
        const occupying = Buffer.from("racing-writer-different-bytes");
        let occupied = false;
        const injector = (event) => {
            if (event.point === "before-object-link") {
                throw fault("EPERM", "force fallback");
            }
            if (!occupied && event.point === "before-object-copy") {
                occupied = true;
                fs.writeFileSync(event.dest, occupying, { flag: "wx" });
            }
        };
        const store = openArtifactStore({ root, faultInjector: injector });

        const err = catchErr(() => store.putBytes(bytes));
        expect(err.code).toBe(ARTIFACT_STORE_ERROR_CODES.OBJECT_CORRUPT);
        expect(fs.readFileSync(store.objectPath(id)).equals(occupying)).toBe(true);
        expect(fs.existsSync(markerPath(hash, "installed"))).toBe(false);

        const recovered = openArtifactStore({ root });
        const report = recovered.reconcile({
            referenced: [id],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.installations.repaired.map((entry) => entry.object)).toContain(id);
        expect(report.referenced.ok).toContain(id);
        expect(recovered.readObject(id).equals(bytes)).toBe(true);
    });
});

describe("crash-window reconciliation", () => {
    it.each([
        "stage-file-durable",
        "stage-directory-durable",
    ])("does not create a durable reference for a pre-journal crash at %s", (point) => {
        const bytes = Buffer.from(`pre-journal-${point}`);
        const { id, hash } = objectIdentity(bytes);
        const store = openArtifactStore({ root, faultInjector: throwOnceAt(point) });

        expect(() => store.putBytes(bytes)).toThrow();
        const report = openArtifactStore({ root }).reconcile({
            referenced: [],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.installations.persistentReferenced).not.toContain(id);
        expect(fs.existsSync(markerPath(hash, "referenced"))).toBe(false);
        expect(fs.existsSync(path.join(root, "objects", "sha256", hash.slice(0, 2), hash))).toBe(false);
    });

    it.each([
        "staging-journal-durable",
        "object-entry-installed",
        "object-file-durable",
        "object-directory-durable",
        "installed-marker-durable",
        "transaction-cleaned",
    ])("recovers deterministically after a crash at %s", (point) => {
        const bytes = Buffer.from(`recover-${point}`);
        const { id, hash } = objectIdentity(bytes);
        const store = openArtifactStore({ root, faultInjector: throwOnceAt(point) });

        expect(() => store.putBytes(bytes)).toThrow();
        const recovered = openArtifactStore({ root });
        const report = recovered.reconcile({
            referenced: [id],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.referenced.ok).toContain(id);
        expect(report.referenced.missing).not.toContain(id);
        expect(report.referenced.corrupt).not.toContain(id);
        expect(recovered.verifyObject(id).ok).toBe(true);
        expect(fs.existsSync(markerPath(hash, "referenced"))).toBe(true);
    });

    it.each([
        "object-renamed",
        "object-copied",
    ])("recovers the no-clobber fallback after a crash at %s", (point) => {
        const bytes = Buffer.from(`fallback-crash-${point}`);
        const { id } = objectIdentity(bytes);
        let crashed = false;
        const injector = (event) => {
            if (event.point === "before-object-link") {
                throw fault("EPERM", "force fallback");
            }
            if (!crashed && event.point === point) {
                crashed = true;
                throw new Error(`simulated crash at ${point}`);
            }
        };
        const store = openArtifactStore({ root, faultInjector: injector });

        expect(() => store.putBytes(bytes)).toThrow();
        expect(crashed).toBe(true);
        const recovered = openArtifactStore({ root });
        const report = recovered.reconcile({
            referenced: [id],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.referenced.ok).toContain(id);
        expect(recovered.readObject(id).equals(bytes)).toBe(true);
    });

    it("preserves an object when the process crashes after its referenced marker is durable", () => {
        const writer = openArtifactStore({ root });
        const meta = writer.putBytes(Buffer.from("referenced-crash"));
        const crashingReconciler = openArtifactStore({
            root,
            faultInjector: throwOnceAt("referenced-marker-durable"),
        });

        expect(() => crashingReconciler.reconcile({
            referenced: [meta.id],
            olderThanMs: 0,
            now: Date.now(),
        })).toThrow();
        expect(fs.existsSync(markerPath(meta.hash, "referenced"))).toBe(true);

        const recovered = openArtifactStore({ root });
        const report = recovered.reconcile({
            referenced: [],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.installations.persistentReferenced).toContain(meta.id);
        expect(report.removedObjects).not.toContain(meta.id);
        expect(recovered.verifyObject(meta.id).ok).toBe(true);
    });

    it("reports persisted referenced objects that later become missing or corrupt", () => {
        const store = openArtifactStore({ root });
        const missing = store.putBytes(Buffer.from("later-missing"));
        const corrupt = store.putBytes(Buffer.from("later-corrupt"));
        store.reconcile({
            referenced: [missing.id, corrupt.id],
            olderThanMs: 0,
            now: Date.now(),
        });

        fs.rmSync(missing.path);
        fs.writeFileSync(corrupt.path, Buffer.from("tampered"));
        const report = store.reconcile({
            referenced: [],
            olderThanMs: 0,
            now: Date.now(),
        });
        expect(report.referenced.missing).toContain(missing.id);
        expect(report.referenced.corrupt).toContain(corrupt.id);
        expect(report.removedObjects).not.toContain(corrupt.id);
        expect(fs.existsSync(corrupt.path)).toBe(true);
    });
});
