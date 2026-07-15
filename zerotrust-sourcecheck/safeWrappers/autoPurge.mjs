// safeWrappers/autoPurge.mjs — stale-clone auto-purge logic for safe_clone.
//
// Purpose: every audit's clone is left on disk forever unless the agent
// remembers to call zerotrust_cleanup_audit at the end. In practice, agents
// crash, sessions end early, and old clones accumulate. Auto-purge runs at
// the START of every safe_clone call and deletes any clone in build_root
// whose mtime is older than the configured threshold.
//
// Why mtime instead of ctime/atime: mtime is the most reliably-set on
// Windows + the most predictable across ecosystems (atime depends on
// filesystem mount options, ctime can be modified by metadata changes).
//
// Configurable via ZEROTRUST_AUTO_PURGE_HOURS env var:
//   - unset / not a number → DEFAULT_HOURS (24)
//   - 0 → disabled (operator-managed cleanup)
//   - positive number → that many hours
//
// What gets purged: stale top-level clone directories under build_root only.
// Reports and quarantine are never side effects of auto-purge; their explicit
// active-audit-bound cleanup tools own those artifacts.

import { existsSync, readdirSync, rmSync, statSync } from "node:fs";
import nodePath from "node:path";
import { ARTIFACT_NAME_RE } from "../urlParser.mjs";

export const DEFAULT_PURGE_HOURS = 24;

// Newly-created clone names are canonical hashed repository identities.
const CLONE_NAME_RE = ARTIFACT_NAME_RE;
const LEGACY_FULL_SHA_CLONE_NAME_RE = /^[A-Za-z0-9._-]+-[A-Za-z0-9._-]+-[0-9a-f]{40}$/;
const LEGACY_CLONE_NAME_RE = /^[A-Za-z0-9._-]+-[A-Za-z0-9._-]+-[0-9a-f]{7}$/;

export function getPurgeHours(env) {
    const e = env || (typeof process !== "undefined" ? process.env : {}) || {};
    const raw = e.ZEROTRUST_AUTO_PURGE_HOURS;
    if (raw === undefined || raw === null || raw === "") return DEFAULT_PURGE_HOURS;
    const n = Number(raw);
    if (!Number.isFinite(n) || n < 0) return DEFAULT_PURGE_HOURS;
    return n; // 0 = disabled
}

function safeRemove(p) {
    if (!existsSync(p)) return false;
    try {
        rmSync(p, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        return !existsSync(p);
    } catch {
        return false;
    }
}

function listDirEntries(dir) {
    if (!existsSync(dir)) return [];
    try {
        return readdirSync(dir, { withFileTypes: true });
    } catch {
        return [];
    }
}

/**
 * Compute the list of directory names under build_root that look like
 * stale clones (older than `hoursThreshold`). Pure-ish — does no
 * deletion. Caller passes a `now` for testability.
 *
 * Returns: string[] of basenames (relative to build_root).
 */
export function findStaleClones({ buildRoot, hoursThreshold, now, exclude = [] }) {
    if (!buildRoot || hoursThreshold <= 0) return [];
    const cutoffMs = (now || Date.now()) - hoursThreshold * 60 * 60 * 1000;
    const stale = [];
    for (const ent of listDirEntries(buildRoot)) {
        if (!ent.isDirectory()) continue;
        if (!CLONE_NAME_RE.test(ent.name)
            && !LEGACY_FULL_SHA_CLONE_NAME_RE.test(ent.name)
            && !LEGACY_CLONE_NAME_RE.test(ent.name)) continue;
        if (exclude.includes(ent.name)) continue;
        const full = nodePath.join(buildRoot, ent.name);
        let st;
        try {
            st = statSync(full);
        } catch {
            continue;
        }
        if (st.mtimeMs < cutoffMs) {
            stale.push(ent.name);
        }
    }
    return stale;
}

/**
 * Purge stale clone directories from build_root. Returns a structured summary.
 *
 * Containment: every path constructed and deleted is rooted at
 * `nodePath.join(buildRoot, ...)`, so we never escape build_root.
 *
 * `exclude` is a list of basenames the caller wants to keep (e.g., the
 * about-to-be-created clone for the current invocation, in the unlikely
 * case the operator has set ZEROTRUST_AUTO_PURGE_HOURS to a tiny number
 * AND a previous run with the same SHA happened seconds ago).
 */
export function purgeStaleClones({ buildRoot, hoursThreshold, now, exclude = [] }) {
    const stale = findStaleClones({ buildRoot, hoursThreshold, now, exclude });
    const purged = [];
    const failed = [];
    for (const basename of stale) {
        const clonePath = nodePath.join(buildRoot, basename);
        const cloneOk = safeRemove(clonePath);
        const entry = {
            basename,
            clone: cloneOk,
        };
        if (cloneOk) {
            purged.push(entry);
        } else {
            failed.push(entry);
        }
    }
    return { purged, failed };
}

export const __internals = {
    CLONE_NAME_RE,
    LEGACY_FULL_SHA_CLONE_NAME_RE,
    LEGACY_CLONE_NAME_RE,
    safeRemove,
    listDirEntries,
};
