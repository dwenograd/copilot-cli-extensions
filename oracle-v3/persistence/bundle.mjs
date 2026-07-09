// oracle-v3/persistence/bundle.mjs
//
// Self-contained investigation audit bundle: export + verified import.
//
// An audit bundle is a *deterministic directory* (deliberately NOT a zip — a
// directory is inspectable, diffable, and needs no archive library) that
// packages everything an investigator needs to independently re-verify an
// investigation offline:
//
//   bundle/
//     db/database.sqlite        online (VACUUM INTO) backup of the event DB
//     objects/sha256/<2>/<hex>  the referenced content-addressed CAS objects
//     manifest.json             canonical description of the bundle contents
//     inventory.sha256          SHA-256 of every other file in the bundle
//
// The inventory is the tamper-evidence anchor: `importBundle` re-hashes every
// file and compares it to the inventory BEFORE copying a single byte into the
// destination, and refuses to import into anything but a new empty directory.
//
// This layer is intentionally free of domain policy: it knows about a database
// file, a CAS, and a set of object ids to include. It does not know what an
// investigation, event, or decision is. The caller decides which objects and
// snapshots belong in the bundle.
//
// No third-party dependencies; only node: builtins + the sibling CAS/canonical
// helpers.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

import { OraclePersistenceError, InvalidArgumentError } from "./errors.mjs";
import { assertLocalDatabasePath } from "./paths.mjs";
import { canonicalize } from "./canonical.mjs";
import { DatabaseSync } from "./sqlite.mjs";
import { ArtifactStore, parseObjectId, objectIdFor, objectRelPath } from "./artifact-store.mjs";

const ALGO = "sha256";
const BUNDLE_TYPE = "oracle-v3-audit-bundle";
const BUNDLE_VERSION = 1;
const INVENTORY_NAME = "inventory.sha256";
const MANIFEST_NAME = "manifest.json";
const DB_RELPATH = "db/database.sqlite";
const COPY_CHUNK = 1 << 16;

// --- typed errors ---------------------------------------------------------

export const BUNDLE_ERROR_CODES = Object.freeze({
    INVALID_ARGUMENT: "ORACLE_BUNDLE_INVALID_ARGUMENT",
    DESTINATION_EXISTS: "ORACLE_BUNDLE_DESTINATION_EXISTS",
    SOURCE_INVALID: "ORACLE_BUNDLE_SOURCE_INVALID",
    OBJECT_MISSING: "ORACLE_BUNDLE_OBJECT_MISSING",
    INVENTORY_INVALID: "ORACLE_BUNDLE_INVENTORY_INVALID",
    TAMPER_DETECTED: "ORACLE_BUNDLE_TAMPER_DETECTED",
    IO_ERROR: "ORACLE_BUNDLE_IO_ERROR",
});

export class BundleError extends OraclePersistenceError {
    constructor(code, message, details) {
        super(code, message, details);
        this.name = "BundleError";
    }
}

export class BundleDestinationExistsError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.DESTINATION_EXISTS, message, details);
        this.name = "BundleDestinationExistsError";
    }
}

export class BundleTamperError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.TAMPER_DETECTED, message, details);
        this.name = "BundleTamperError";
    }
}

export class BundleInventoryError extends BundleError {
    constructor(message, details) {
        super(BUNDLE_ERROR_CODES.INVENTORY_INVALID, message, details);
        this.name = "BundleInventoryError";
    }
}

// --- helpers --------------------------------------------------------------

function sha256File(absPath) {
    const fd = fs.openSync(absPath, "r");
    const hash = createHash(ALGO);
    const buf = Buffer.allocUnsafe(COPY_CHUNK);
    let size = 0;
    try {
        for (;;) {
            const n = fs.readSync(fd, buf, 0, buf.length, null);
            if (n === 0) {
                break;
            }
            hash.update(buf.subarray(0, n));
            size += n;
        }
    } finally {
        fs.closeSync(fd);
    }
    return { hash: hash.digest("hex"), size };
}

function copyFileStreamed(srcAbs, destAbs) {
    fs.mkdirSync(path.dirname(destAbs), { recursive: true });
    const rfd = fs.openSync(srcAbs, "r");
    let wfd;
    try {
        wfd = fs.openSync(destAbs, "wx");
    } catch (err) {
        fs.closeSync(rfd);
        throw err;
    }
    const buf = Buffer.allocUnsafe(COPY_CHUNK);
    try {
        for (;;) {
            const n = fs.readSync(rfd, buf, 0, buf.length, null);
            if (n === 0) {
                break;
            }
            let off = 0;
            while (off < n) {
                off += fs.writeSync(wfd, buf, off, n - off);
            }
        }
        fs.fsyncSync(wfd);
    } finally {
        fs.closeSync(rfd);
        fs.closeSync(wfd);
    }
}

function isEmptyDir(absPath) {
    try {
        return fs.readdirSync(absPath).length === 0;
    } catch (err) {
        if (err && err.code === "ENOENT") {
            return true;
        }
        throw err;
    }
}

function assertFreshDestination(destResolved, ErrorClass) {
    if (fs.existsSync(destResolved) && !isEmptyDir(destResolved)) {
        throw new ErrorClass("destination already exists and is not empty", { dest: destResolved });
    }
}

// Recursively list every file under `rootAbs` as posix-relative paths (sorted).
function listAllFiles(rootAbs) {
    const out = [];
    const walk = (dirAbs, relSegs) => {
        const dirents = fs.readdirSync(dirAbs, { withFileTypes: true });
        dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        for (const d of dirents) {
            const childAbs = path.join(dirAbs, d.name);
            const childRel = [...relSegs, d.name];
            if (d.isDirectory()) {
                walk(childAbs, childRel);
            } else if (d.isFile()) {
                out.push(childRel.join("/"));
            }
        }
    };
    walk(rootAbs, []);
    out.sort();
    return out;
}

// Serialize an inventory map (relpath -> hex) into a deterministic
// `<hex>  <relpath>` document sorted by relpath.
function serializeInventory(entries) {
    const lines = [...entries]
        .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
        .map((e) => `${e.hash}  ${e.path}`);
    return lines.join("\n") + "\n";
}

// Parse an inventory document into [{ hash, path }]. Format matches the
// coreutils `sha256sum` convention: "<64hex><space><space><relpath>".
function parseInventory(text) {
    const entries = [];
    const seen = new Set();
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        if (line.length === 0) {
            continue;
        }
        const m = /^([0-9a-f]{64})\s{2}(.+)$/u.exec(line);
        if (!m) {
            throw new BundleInventoryError("malformed inventory line", { lineNumber: i + 1, line });
        }
        const [, hash, relPath] = m;
        if (relPath === INVENTORY_NAME) {
            throw new BundleInventoryError("inventory must not list itself", { line });
        }
        if (path.isAbsolute(relPath) || relPath.includes("\\") || relPath.split("/").some((s) => s === "." || s === "..")) {
            throw new BundleInventoryError("unsafe inventory path", { relPath });
        }
        if (seen.has(relPath)) {
            throw new BundleInventoryError("duplicate inventory path", { relPath });
        }
        seen.add(relPath);
        entries.push({ hash, path: relPath });
    }
    if (entries.length === 0) {
        throw new BundleInventoryError("inventory is empty", {});
    }
    return entries;
}

// --- online DB backup -----------------------------------------------------

// Produce a consistent online backup of a live SQLite database into destAbs
// using `VACUUM INTO`. This reads a committed snapshot under a shared lock and
// materializes a standalone, self-contained database file (no WAL sidecar).
function onlineBackupDatabase(dbFile, destAbs) {
    const resolvedDb = assertLocalDatabasePath(dbFile);
    if (!fs.existsSync(resolvedDb)) {
        throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID, "database file does not exist", { dbFile });
    }
    fs.mkdirSync(path.dirname(destAbs), { recursive: true });
    if (fs.existsSync(destAbs)) {
        throw new BundleError(BUNDLE_ERROR_CODES.IO_ERROR, "backup target already exists", { destAbs });
    }
    let db;
    try {
        db = new DatabaseSync(resolvedDb);
    } catch (err) {
        throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID, `cannot open database: ${err.message}`, { dbFile });
    }
    try {
        const escaped = destAbs.replace(/'/g, "''");
        db.exec(`VACUUM INTO '${escaped}'`);
    } catch (err) {
        throw new BundleError(BUNDLE_ERROR_CODES.IO_ERROR, `online backup failed: ${err.message}`, { dbFile });
    } finally {
        try {
            db.close();
        } catch {
            // already closed / nothing to do
        }
    }
    return sha256File(destAbs);
}

// --- reference-set resolution ---------------------------------------------

// Resolve the closure of object ids to include: explicit ids plus the verified
// closure of any snapshot ids (manifest + its entries). Every object must exist
// and verify — a bundle must be self-contained and internally consistent.
function resolveObjectClosure(store, objectIds, snapshots) {
    const ids = new Set();
    for (const id of objectIds) {
        const { hex } = parseObjectId(id);
        ids.add(objectIdFor(hex));
    }
    for (const snap of snapshots) {
        const { hex } = parseObjectId(snap);
        ids.add(objectIdFor(hex));
        let manifest;
        try {
            manifest = store.loadManifest(snap);
        } catch (err) {
            throw new BundleError(BUNDLE_ERROR_CODES.OBJECT_MISSING, `snapshot manifest unreadable: ${err.message}`, {
                snapshot: snap,
            });
        }
        for (const entry of manifest.entries) {
            const { hex: eh } = parseObjectId(entry.object);
            ids.add(objectIdFor(eh));
        }
    }
    return [...ids].sort();
}

// --- export ---------------------------------------------------------------

// Export a deterministic audit bundle directory. Contents:
//   * db/database.sqlite  — online backup of `dbFile`
//   * objects/...         — every referenced CAS object (verified on copy)
//   * manifest.json       — canonical bundle description
//   * inventory.sha256    — SHA-256 of every other file in the bundle
export function exportBundle(options = {}) {
    const {
        store,
        dbFile,
        destDir,
        objectIds = [],
        snapshots = [],
        metadata = {},
        now = () => new Date().toISOString(),
    } = options;

    if (!(store instanceof ArtifactStore)) {
        throw new InvalidArgumentError("store must be an ArtifactStore instance");
    }
    if (typeof dbFile !== "string" || dbFile.trim().length === 0) {
        throw new InvalidArgumentError("dbFile must be a non-empty string", { dbFile });
    }
    if (typeof destDir !== "string" || destDir.trim().length === 0) {
        throw new InvalidArgumentError("destDir must be a non-empty string", { destDir });
    }
    if (!Array.isArray(objectIds) || !Array.isArray(snapshots)) {
        throw new InvalidArgumentError("objectIds and snapshots must be arrays");
    }

    const destResolved = path.resolve(destDir);
    assertFreshDestination(destResolved, BundleDestinationExistsError);
    fs.mkdirSync(destResolved, { recursive: true });

    const includedIds = resolveObjectClosure(store, objectIds, snapshots);

    // 1) Online DB backup.
    const dbDest = path.join(destResolved, ...DB_RELPATH.split("/"));
    const dbInfo = onlineBackupDatabase(dbFile, dbDest);

    // 2) Copy every referenced object, verifying each against its content
    //    address as we go.
    const objectRecords = [];
    for (const id of includedIds) {
        const { hex } = parseObjectId(id);
        const srcAbs = store.objectPath(id);
        if (!fs.existsSync(srcAbs)) {
            throw new BundleError(BUNDLE_ERROR_CODES.OBJECT_MISSING, "referenced object is missing from the store", {
                id,
            });
        }
        const rel = objectRelPath(hex);
        const destAbs = path.join(destResolved, ...rel.split("/"));
        copyFileStreamed(srcAbs, destAbs);
        const info = sha256File(destAbs);
        if (info.hash !== hex) {
            throw new BundleError(BUNDLE_ERROR_CODES.TAMPER_DETECTED, "object corrupt during export copy", {
                id,
                expected: hex,
                actual: info.hash,
            });
        }
        objectRecords.push({ id, path: rel, size: info.size });
    }

    // 3) Canonical bundle manifest.
    const manifest = {
        type: BUNDLE_TYPE,
        version: BUNDLE_VERSION,
        algo: ALGO,
        createdAt: now(),
        database: { path: DB_RELPATH, size: dbInfo.size, sha256: dbInfo.hash },
        objects: objectRecords.map((r) => ({ id: r.id, path: r.path, size: r.size })),
        snapshots: [...snapshots].sort(),
        metadata,
    };
    const manifestAbs = path.join(destResolved, MANIFEST_NAME);
    fs.writeFileSync(manifestAbs, canonicalize(manifest) + "\n");

    // 4) Inventory of every file except the inventory itself.
    const files = listAllFiles(destResolved).filter((rel) => rel !== INVENTORY_NAME);
    const inventoryEntries = files.map((rel) => ({
        path: rel,
        hash: sha256File(path.join(destResolved, ...rel.split("/"))).hash,
    }));
    const inventoryAbs = path.join(destResolved, INVENTORY_NAME);
    fs.writeFileSync(inventoryAbs, serializeInventory(inventoryEntries));

    return {
        dest: destResolved,
        objectCount: objectRecords.length,
        databaseSize: dbInfo.size,
        databaseSha256: dbInfo.hash,
        fileCount: inventoryEntries.length,
        manifestPath: manifestAbs,
        inventoryPath: inventoryAbs,
    };
}

// --- import ---------------------------------------------------------------

// Verify a bundle against its inventory, then copy it into a NEW EMPTY
// destination. Verification happens in full before any bytes are copied: any
// missing file, extra unlisted file, or hash mismatch aborts with a
// BundleTamperError and nothing is written to the destination.
export function importBundle(options = {}) {
    const { bundleDir, destDir } = options;
    if (typeof bundleDir !== "string" || bundleDir.trim().length === 0) {
        throw new InvalidArgumentError("bundleDir must be a non-empty string", { bundleDir });
    }
    if (typeof destDir !== "string" || destDir.trim().length === 0) {
        throw new InvalidArgumentError("destDir must be a non-empty string", { destDir });
    }
    const bundleResolved = path.resolve(bundleDir);
    if (!fs.existsSync(bundleResolved) || !fs.statSync(bundleResolved).isDirectory()) {
        throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID, "bundle directory does not exist", { bundleDir });
    }

    const inventoryAbs = path.join(bundleResolved, INVENTORY_NAME);
    let inventoryText;
    try {
        inventoryText = fs.readFileSync(inventoryAbs, "utf8");
    } catch (err) {
        if (err && err.code === "ENOENT") {
            throw new BundleInventoryError("bundle is missing its inventory", { bundleDir });
        }
        throw err;
    }
    const inventory = parseInventory(inventoryText);
    const inventoryMap = new Map(inventory.map((e) => [e.path, e.hash]));

    // Detect extra files not covered by the inventory (an injected payload).
    const actualFiles = listAllFiles(bundleResolved).filter((rel) => rel !== INVENTORY_NAME);
    const actualSet = new Set(actualFiles);
    for (const rel of actualFiles) {
        if (!inventoryMap.has(rel)) {
            throw new BundleTamperError("bundle contains a file not listed in the inventory", { path: rel });
        }
    }
    // Verify every inventoried file exists and matches — BEFORE copying.
    for (const { path: rel, hash } of inventory) {
        if (!actualSet.has(rel)) {
            throw new BundleTamperError("inventoried file is missing from the bundle", { path: rel });
        }
        const abs = path.join(bundleResolved, ...rel.split("/"));
        const info = sha256File(abs);
        if (info.hash !== hash) {
            throw new BundleTamperError("bundle file hash does not match inventory", {
                path: rel,
                expected: hash,
                actual: info.hash,
            });
        }
    }

    // Only now, with the whole bundle proven intact, materialize it.
    const destResolved = path.resolve(destDir);
    assertFreshDestination(destResolved, BundleDestinationExistsError);
    fs.mkdirSync(destResolved, { recursive: true });

    for (const rel of [...inventory.map((e) => e.path), INVENTORY_NAME]) {
        const srcAbs = path.join(bundleResolved, ...rel.split("/"));
        const destAbs = path.join(destResolved, ...rel.split("/"));
        copyFileStreamed(srcAbs, destAbs);
    }

    return {
        dest: destResolved,
        fileCount: inventory.length,
        verified: true,
    };
}

// Read and parse a bundle manifest (does not verify the inventory).
export function readBundleManifest(bundleDir) {
    const abs = path.join(path.resolve(bundleDir), MANIFEST_NAME);
    let text;
    try {
        text = fs.readFileSync(abs, "utf8");
    } catch (err) {
        if (err && err.code === "ENOENT") {
            throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID, "bundle manifest not found", { bundleDir });
        }
        throw err;
    }
    try {
        return JSON.parse(text);
    } catch (err) {
        throw new BundleError(BUNDLE_ERROR_CODES.SOURCE_INVALID, "bundle manifest is not valid JSON", {
            bundleDir,
            cause: err.message,
        });
    }
}
