// oracle-v3/__tests__/persistence-bundle.test.mjs
//
// Self-contained audit bundle: deterministic directory export (DB online
// backup + referenced CAS objects + manifest + SHA-256 inventory) and a verified
// import that refuses to copy a tampered bundle or import into a non-empty
// destination.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    openRepository,
    openArtifactStore,
    exportBundle,
    importBundle,
    readBundleManifest,
    BUNDLE_ERROR_CODES,
} from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

let base;
let store;
let repo;
let snap;
let extraObject;

beforeEach(() => {
    base = fs.mkdtempSync(path.join(HERE, ".persist-tmp-"));
    store = openArtifactStore({ root: path.join(base, "cas") });

    // A snapshot (manifest + files) plus a standalone object to include.
    const src = path.join(base, "evidence");
    fs.mkdirSync(path.join(src, "logs"), { recursive: true });
    fs.writeFileSync(path.join(src, "report.txt"), "the target was reachable");
    fs.writeFileSync(path.join(src, "logs", "trace.log"), "step-1\nstep-2\n");
    snap = store.ingestDirectory({ sourceDir: src });
    extraObject = store.putBytes(Buffer.from("standalone-attachment"));

    repo = openRepository({ file: path.join(base, "events.sqlite") });
    repo.ensureInvestigation({ investigationId: "inv-1", metadata: { case: "audit" } });
});

afterEach(() => {
    try {
        repo?.close();
    } catch {
        // already closed
    }
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

function doExport(destName = "bundle") {
    const destDir = path.join(base, destName);
    const res = exportBundle({
        store,
        dbFile: repo.databaseFile,
        destDir,
        objectIds: [extraObject.id],
        snapshots: [snap.snapshot],
        now: () => "2026-07-09T00:00:00.000Z",
    });
    return { destDir, res };
}

describe("export", () => {
    it("produces a deterministic self-contained bundle directory", () => {
        const { destDir, res } = doExport();

        expect(fs.existsSync(path.join(destDir, "db", "database.sqlite"))).toBe(true);
        expect(fs.existsSync(path.join(destDir, "manifest.json"))).toBe(true);
        expect(fs.existsSync(path.join(destDir, "inventory.sha256"))).toBe(true);
        expect(fs.existsSync(path.join(destDir, "objects", "sha256"))).toBe(true);

        // Closure = snapshot manifest + its 2 files + the standalone object.
        expect(res.objectCount).toBe(4);

        const manifest = readBundleManifest(destDir);
        expect(manifest.type).toBe("oracle-v3-audit-bundle");
        expect(manifest.database.path).toBe("db/database.sqlite");
        expect(manifest.snapshots).toContain(snap.snapshot);
        expect(manifest.objects.map((o) => o.id)).toContain(extraObject.id);

        // Inventory covers every file except itself, and lists the DB.
        const inv = fs.readFileSync(path.join(destDir, "inventory.sha256"), "utf8");
        expect(inv).toMatch(/ {2}db\/database\.sqlite$/m);
        expect(inv).not.toMatch(/inventory\.sha256/);
    });

    it("refuses a non-empty destination", () => {
        const destDir = path.join(base, "occupied");
        fs.mkdirSync(destDir, { recursive: true });
        fs.writeFileSync(path.join(destDir, "squatter"), "x");
        const err = catchErr(() =>
            exportBundle({ store, dbFile: repo.databaseFile, destDir, objectIds: [extraObject.id] }),
        );
        expect(err.code).toBe(BUNDLE_ERROR_CODES.DESTINATION_EXISTS);
    });

    it("fails when a referenced object is missing from the store", () => {
        const destDir = path.join(base, "bundle-missing");
        const err = catchErr(() =>
            exportBundle({ store, dbFile: repo.databaseFile, destDir, objectIds: ["sha256:" + "ab".repeat(32)] }),
        );
        expect(err.code).toBe(BUNDLE_ERROR_CODES.OBJECT_MISSING);
    });
});

describe("import round-trip", () => {
    it("verifies the inventory and materializes an intact bundle", () => {
        const { destDir } = doExport();
        repo.close(); // release the live DB before re-opening the backup copy

        const dest = path.join(base, "imported");
        const imp = importBundle({ bundleDir: destDir, destDir: dest });
        expect(imp.verified).toBe(true);

        // The restored DB is a real, openable repository with the same data.
        const restored = openRepository({ file: path.join(dest, "db", "database.sqlite") });
        try {
            expect(restored.getInvestigation("inv-1")).not.toBeNull();
        } finally {
            restored.close();
        }

        // The restored objects verify under a fresh store rooted at the import.
        const restoredStore = openArtifactStore({ root: dest });
        expect(restoredStore.verifyObject(extraObject.id).ok).toBe(true);
        expect(restoredStore.verifySnapshot(snap.snapshot).ok).toBe(true);
    });

    it("refuses to import into a non-empty destination", () => {
        const { destDir } = doExport();
        const dest = path.join(base, "occupied-import");
        fs.mkdirSync(dest, { recursive: true });
        fs.writeFileSync(path.join(dest, "pre-existing"), "x");
        const err = catchErr(() => importBundle({ bundleDir: destDir, destDir: dest }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.DESTINATION_EXISTS);
    });
});

describe("tamper detection", () => {
    function firstObjectFile(destDir) {
        const objectsRoot = path.join(destDir, "objects", "sha256");
        const prefix = fs.readdirSync(objectsRoot)[0];
        const prefixDir = path.join(objectsRoot, prefix);
        return path.join(prefixDir, fs.readdirSync(prefixDir)[0]);
    }

    it("rejects a bundle whose CAS object bytes were altered", () => {
        const { destDir } = doExport();
        const victim = firstObjectFile(destDir);
        fs.writeFileSync(victim, Buffer.from("tampered-object-bytes"));

        const dest = path.join(base, "imported");
        const err = catchErr(() => importBundle({ bundleDir: destDir, destDir: dest }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.TAMPER_DETECTED);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects a bundle whose database backup was altered", () => {
        const { destDir } = doExport();
        const dbPath = path.join(destDir, "db", "database.sqlite");
        const bytes = fs.readFileSync(dbPath);
        bytes[bytes.length - 1] ^= 0xff;
        fs.writeFileSync(dbPath, bytes);

        const dest = path.join(base, "imported");
        const err = catchErr(() => importBundle({ bundleDir: destDir, destDir: dest }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.TAMPER_DETECTED);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects a bundle whose manifest was altered", () => {
        const { destDir } = doExport();
        const manifestPath = path.join(destDir, "manifest.json");
        fs.appendFileSync(manifestPath, "\n");

        const dest = path.join(base, "imported");
        const err = catchErr(() => importBundle({ bundleDir: destDir, destDir: dest }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.TAMPER_DETECTED);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects a bundle with an injected file not present in the inventory", () => {
        const { destDir } = doExport();
        fs.writeFileSync(path.join(destDir, "db", "planted.txt"), "surprise");

        const dest = path.join(base, "imported");
        const err = catchErr(() => importBundle({ bundleDir: destDir, destDir: dest }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.TAMPER_DETECTED);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects a bundle with a file removed after inventory was written", () => {
        const { destDir } = doExport();
        fs.rmSync(firstObjectFile(destDir));

        const dest = path.join(base, "imported");
        const err = catchErr(() => importBundle({ bundleDir: destDir, destDir: dest }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.TAMPER_DETECTED);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects a malformed inventory", () => {
        const { destDir } = doExport();
        fs.writeFileSync(path.join(destDir, "inventory.sha256"), "not a valid inventory line\n");

        const dest = path.join(base, "imported");
        const err = catchErr(() => importBundle({ bundleDir: destDir, destDir: dest }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.INVENTORY_INVALID);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects a bundle missing its inventory entirely", () => {
        const { destDir } = doExport();
        fs.rmSync(path.join(destDir, "inventory.sha256"));

        const dest = path.join(base, "imported");
        const err = catchErr(() => importBundle({ bundleDir: destDir, destDir: dest }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.INVENTORY_INVALID);
    });
});
