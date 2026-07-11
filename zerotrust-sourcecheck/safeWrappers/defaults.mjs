// safeWrappers/defaults.mjs — single source of truth for DEFAULT_BUILD_ROOT.
//
// Before this module existed, a developer-specific Windows path was duplicated
// across several files, making other hosts require `build_root` on every call.
// This module centralizes the env override and portable home-directory fallback.
//
// Override order (first non-empty wins):
//   1. `ZEROTRUST_BUILD_ROOT` env var
//   2. `<homedir>/.copilot/zerotrust-sandbox`
//
// Callers receive an absolute, normalised path string. Wrappers that
// perform destructive ops should still validate that an agent-supplied
// `args.build_root` matches DEFAULT_BUILD_ROOT (or an active audit
// anchor) before touching it — see the round-17 defence-in-depth
// checks in sweepWrapper.mjs / reportWrapper.mjs.

import os from "node:os";
import nodePath from "node:path";
import { mkdirSync } from "node:fs";

// Obviously dangerous defaults that an operator should never have the
// extension treat as its sandbox root. If `ZEROTRUST_BUILD_ROOT` is set
// to one of these (or evaluates to one after `nodePath.resolve`), we
// fall back to the homedir default and surface a warning to stderr.
//
// This is a defence-in-depth check, not a full validation — the
// operator owns their env vars. But it catches obvious typos like
// `ZEROTRUST_BUILD_ROOT=/` (which would put _quarantine/, _reports/,
// and clones at the filesystem root) and `=C:\\Windows` (system dir).
const DANGEROUS_ROOTS = new Set([
    // POSIX filesystem root + common system dirs.
    "/",
    "/etc",
    "/usr",
    "/usr/local",
    "/bin",
    "/sbin",
    "/var",
    "/tmp",
    "/opt",
    "/srv",
    "/home",
    "/root",
    // macOS-specific:
    "/Users",
    "/Library",
    "/System",
    "/Applications",
    // Windows drive roots + system / program dirs:
    "C:\\",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\Users",
    "D:\\",
    "E:\\",
    "F:\\",
    "G:\\",
]);

function isDangerousRoot(p) {
    if (!p) return true;
    const normalized = nodePath.resolve(p);
    // Direct match against the denylist.
    for (const bad of DANGEROUS_ROOTS) {
        if (normalized.toLowerCase() === bad.toLowerCase()) return true;
    }
    // Reject anything obviously shallow (<2 path segments below root)
    // — `/foo` or `C:\foo` are still risky as audit sandboxes because
    // a typo or untrusted env value could land at a single common
    // directory name that exists on most systems (`/opt`, `/var`, etc.
    // — many of which are already in the denylist above but the
    // segment-count gate catches the rest).
    const parsed = nodePath.parse(normalized);
    const relFromRoot = normalized.slice(parsed.root.length);
    const segments = relFromRoot.split(/[\\/]+/).filter((s) => s.length > 0);
    if (segments.length < 2) return true;
    return false;
}

function resolveDefault() {
    const fromEnv = process.env.ZEROTRUST_BUILD_ROOT;
    if (fromEnv && typeof fromEnv === "string" && fromEnv.trim().length > 0) {
        const resolved = nodePath.resolve(fromEnv.trim());
        if (isDangerousRoot(resolved)) {
            // eslint-disable-next-line no-console
            console.warn(
                `[zerotrust-sourcecheck] WARNING: ZEROTRUST_BUILD_ROOT=${fromEnv.trim()} ` +
                `resolves to a dangerous path (${resolved}) — refusing to use it as the audit sandbox. ` +
                `Falling back to <homedir>/.copilot/zerotrust-sandbox. ` +
                `Set ZEROTRUST_BUILD_ROOT to a dedicated sandbox directory at least 2 levels deep.`,
            );
        } else {
            return resolved;
        }
    }
    return nodePath.resolve(nodePath.join(os.homedir(), ".copilot", "zerotrust-sandbox"));
}

export const DEFAULT_BUILD_ROOT = resolveDefault();

// First-use mkdir. Idempotent — `recursive: true` + try/catch swallow
// any "already exists" / permission errors. Wrappers can call this
// before write operations to make sure the directory tree is present.
let ensured = false;
export function ensureDefaultBuildRoot() {
    if (ensured) return DEFAULT_BUILD_ROOT;
    try {
        mkdirSync(DEFAULT_BUILD_ROOT, { recursive: true });
    } catch {
        // Best-effort — if mkdir fails (e.g. permission denied), the
        // wrapper that actually writes will surface a clearer error.
    }
    ensured = true;
    return DEFAULT_BUILD_ROOT;
}

// Test seam — exposes the resolution function so tests can verify
// env-var precedence without polluting other tests' DEFAULT_BUILD_ROOT.
export const __internals = {
    resolveDefault,
    isDangerousRoot,
    DANGEROUS_ROOTS,
};
