// oracle-v3/persistence/paths.mjs
//
// Local-file-only safety gate for the event repository.
//
// The repository is a durability boundary: WAL + synchronous=FULL only give
// their guarantees on a real local disk. Network filesystems (SMB/UNC, mapped
// network drives) and cloud-sync folders (OneDrive/Dropbox/etc.) can corrupt
// SQLite WAL databases because their locking and fsync semantics are not the
// POSIX/Win32 semantics SQLite assumes. We therefore refuse to open a database
// on any location we can *determine* to be non-local, and we express that
// refusal as a typed `LocalPathError` (code ORACLE_PERSIST_LOCAL_PATH_REQUIRED)
// rather than a silent comment or best-effort warning.
//
// "When determinable" is deliberate: we cannot always prove a drive letter is
// local, so we reject the cases we CAN identify (UNC prefixes, device
// namespaces, realpath resolving to a UNC target, known cloud-sync roots, and
// caller-supplied deny roots) and otherwise allow the path.

import path from "node:path";
import fs from "node:fs";

import { LocalPathError, InvalidArgumentError } from "./errors.mjs";

// Folder names that indicate a cloud-sync provider root. Matched
// case-insensitively against individual path segments.
const CLOUD_SYNC_SEGMENTS = Object.freeze([
    "onedrive",
    "onedrive - personal",
    "dropbox",
    "google drive",
    "googledrive",
    "my drive",
    "icloud drive",
    "icloud~",
    "iclouddrive",
    "com~apple~clouddocs",
    "box sync",
    "pcloud",
    "nextcloud",
    "owncloud",
    "syncthing",
    "creative cloud files",
    "sync.com",
]);

function normalizeToBackslashes(p) {
    return p.replace(/\//g, "\\");
}

// Detect a Windows UNC / network / device path from a raw string, before it is
// resolved. Handles: \\server\share, //server/share, \\?\UNC\server\share,
// and device namespace \\.\ . A local long path \\?\C:\... is NOT UNC.
export function isNetworkOrUncPath(raw) {
    if (typeof raw !== "string" || raw.length === 0) {
        return false;
    }
    const s = normalizeToBackslashes(raw);
    if (!s.startsWith("\\\\")) {
        return false;
    }
    const rest = s.slice(2);
    // Only a canonical local-drive long path is accepted from the extended
    // namespace. GLOBALROOT, Volume GUID, UNC, and other device targets are
    // rejected because they can address network redirectors or devices.
    if (rest.startsWith("?\\")) {
        return !/^\?\\[A-Za-z]:\\/u.test(rest);
    }
    // \\.\device namespace -> not a normal file path.
    if (rest.startsWith(".\\")) {
        return true;
    }
    // Plain \\server\share.
    return true;
}

function splitSegments(absPath) {
    return normalizeToBackslashes(absPath)
        .split("\\")
        .filter((seg) => seg.length > 0);
}

function matchesCloudSyncRoot(absPath) {
    const segments = splitSegments(absPath).map((s) => s.toLowerCase());
    for (const seg of segments) {
        if (CLOUD_SYNC_SEGMENTS.includes(seg)) {
            return seg;
        }
    }
    return null;
}

function isInside(childAbs, parentAbs) {
    const child = normalizeToBackslashes(path.resolve(childAbs)).toLowerCase();
    const parent = normalizeToBackslashes(path.resolve(parentAbs)).toLowerCase().replace(/\\+$/, "");
    if (parent.length === 0) {
        return false;
    }
    return child === parent || child.startsWith(parent + "\\");
}

// Resolve the realpath of the nearest existing ancestor. If a mapped network
// drive (or a junction/symlink) points at a UNC target, realpath surfaces it,
// which lets us reject an otherwise innocent-looking drive letter.
function nearestExistingRealpath(absPath) {
    let current = absPath;
    for (let i = 0; i < 64; i += 1) {
        try {
            return fs.realpathSync.native(current);
        } catch (err) {
            if (err && (err.code === "ENOENT" || err.code === "ENOTDIR")) {
                const parent = path.dirname(current);
                if (parent === current) {
                    return null;
                }
                current = parent;
                continue;
            }
            // Any other error (permissions, etc.) is not evidence of a network
            // path; we simply cannot determine locality this way. We do not
            // treat an inability to resolve as either success or failure of the
            // whole check — the other rules still apply.
            return null;
        }
    }
    return null;
}

function envDenyRoots(env) {
    const raw = env?.ORACLE_PERSIST_DENY_ROOTS;
    if (typeof raw !== "string" || raw.trim().length === 0) {
        return [];
    }
    return raw.split(/[;]/).map((s) => s.trim()).filter(Boolean);
}

function envCloudRoots(env) {
    const roots = [];
    for (const key of ["OneDrive", "OneDriveConsumer", "OneDriveCommercial", "Dropbox"]) {
        const v = env?.[key];
        if (typeof v === "string" && v.trim().length > 0) {
            roots.push(v.trim());
        }
    }
    return roots;
}

// Validate and normalize a database path. Returns the resolved absolute path on
// success; throws LocalPathError with a `reason` detail otherwise.
export function assertLocalDatabasePath(dbPath, options = {}) {
    if (typeof dbPath !== "string" || dbPath.trim().length === 0) {
        throw new InvalidArgumentError("database path must be a non-empty string", { dbPath });
    }
    if (dbPath === ":memory:" || dbPath.startsWith("file::memory:")) {
        // An in-memory database cannot honour WAL/synchronous durability, which
        // is the whole point of this repository. Reject explicitly.
        throw new InvalidArgumentError(
            "in-memory databases are not permitted; a durable local file path is required",
            { dbPath },
        );
    }

    const env = options.env ?? process.env;

    // 1. Raw UNC / network / device prefixes (checked before resolution so a
    //    relative path cannot smuggle a UNC root past us).
    if (isNetworkOrUncPath(dbPath)) {
        throw new LocalPathError(
            "refusing UNC / network / device path; a local disk file is required",
            { reason: "unc", dbPath },
        );
    }

    const resolved = path.resolve(dbPath);

    if (isNetworkOrUncPath(resolved)) {
        throw new LocalPathError(
            "resolved path is a UNC / network path; a local disk file is required",
            { reason: "unc", dbPath, resolved },
        );
    }

    // 2. Known cloud-sync provider roots, by folder-name segment...
    const cloudSegment = matchesCloudSyncRoot(resolved);
    if (cloudSegment) {
        throw new LocalPathError(
            `refusing path inside a cloud-sync folder ('${cloudSegment}'); WAL databases can corrupt on synchronized storage`,
            { reason: "cloud-sync", dbPath, resolved, segment: cloudSegment },
        );
    }

    // ...and by environment-advertised cloud roots (e.g. %OneDrive%).
    for (const root of envCloudRoots(env)) {
        if (isInside(resolved, root)) {
            throw new LocalPathError(
                "refusing path inside an environment-advertised cloud-sync root",
                { reason: "cloud-sync-env", dbPath, resolved, root },
            );
        }
    }

    // 3. Caller / env supplied deny roots (e.g. a known NAS mount letter).
    const denyRoots = [...(options.denyRoots ?? []), ...envDenyRoots(env)];
    for (const root of denyRoots) {
        if (isInside(resolved, root)) {
            throw new LocalPathError(
                "refusing path inside a configured deny root",
                { reason: "deny-root", dbPath, resolved, root },
            );
        }
    }

    // 4. Mapped network drive detection via realpath of nearest existing
    //    ancestor. If the OS resolves the location to a UNC target, it is a
    //    network mount masquerading as a drive letter.
    const real = nearestExistingRealpath(resolved);
    if (real && isNetworkOrUncPath(real)) {
        throw new LocalPathError(
            "path resolves to a UNC / network target (mapped network drive or junction)",
            { reason: "mapped-network-drive", dbPath, resolved, real },
        );
    }

    return resolved;
}
