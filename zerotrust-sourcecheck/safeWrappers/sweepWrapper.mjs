// safeWrappers/sweepWrapper.mjs — zerotrust_sweep_audit_scratch tool.
//
// Cleans up scratch files left by sub-agents in build_root and optionally
// its immediate parent directory. Sub-agents have been observed violating
// the API-direct contract by saving source bytes or path enumerations to
// disk via PowerShell (`Out-File`, `Set-Content`, `iwr -OutFile`, etc.).
//
// The `preToolUseHook` policy in enforcement.mjs would deny most of those
// calls if it were wired in — but as of v4-r3 we do NOT register
// `onPreToolUse` (the elevated "register hooks" permission isn't worth
// paying for a hook the runtime ignores anyway; see README's "Honest
// disclosure" section and extension.mjs top-of-file comment for the full
// rationale). Even when the hook was registered, Copilot CLI 1.0.x did
// not invoke `onPreToolUse` for built-in tools (powershell/view/glob/grep).
// This wrapper runs INSIDE the extension process where we control
// execution unconditionally — so cleanup works regardless of hook status.
//
// Lifecycle role: sweep is destructive cleanup only. It deliberately does
// NOT deactivate audit state. The packet calls zerotrust_close_audit only
// after every retryable cleanup step succeeds, preserving the trusted audit
// anchor when a deletion fails.
//
// Substitutional safety:
// - Only deletes top-level FILES (never directories — protects _reports/,
//   _quarantine/, and canonical clone dirs).
// - Only operates on build_root and (optionally) its immediate parent.
// - Whitelists known-good filenames (README, .gitignore, .gitkeep, etc.).
// - Refuses to traverse outside build_root + immediate parent.
// - dry_run mode: returns the candidate list without deleting.

import { existsSync, readdirSync, rmSync } from "node:fs";
import nodePath from "node:path";

import { getTrustedAuditContext } from "../enforcement.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";

// Top-level filenames that are LEGITIMATE in build_root or its parent.
// Lowercased for case-insensitive matching. Anything not in this set
// (and not a directory) is treated as scratch.
const ALLOWED_TOP_LEVEL_FILES = new Set([
    // Documentation / standard repo files
    "readme.md", "readme.txt", "readme",
    "changelog.md", "changelog",
    "contributing.md", "contributing",
    "code_of_conduct.md", "security.md",
    "license", "license.txt", "license.md", "licence", "licence.txt", "licence.md",
    "authors", "authors.md", "notice",
    // Git / VCS / editor
    ".gitignore", ".gitattributes", ".gitkeep", ".keep",
    ".gitmodules", ".mailmap",
    ".editorconfig", ".prettierrc", ".prettierrc.json", ".prettierrc.js",
    ".eslintrc", ".eslintrc.js", ".eslintrc.json",
    // Node
    "package.json", "package-lock.json", ".npmrc", ".nvmrc", ".npmignore",
    "yarn.lock", ".yarnrc", ".yarnrc.yml",
    "pnpm-lock.yaml", ".pnpmfile.cjs",
    "tsconfig.json", "jsconfig.json",
    // Python
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "pipfile", "pipfile.lock", "poetry.lock",
    // Rust / Go / .NET / Java
    "cargo.toml", "cargo.lock",
    "go.mod", "go.sum",
    "global.json", "directory.build.props", "directory.packages.props",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    // Build / container / CI
    "makefile", "gnumakefile",
    "dockerfile", ".dockerignore", "compose.yaml", "compose.yml",
    "docker-compose.yaml", "docker-compose.yml",
    ".env.example",
]);

function isAllowedFilename(name) {
    if (ALLOWED_TOP_LEVEL_FILES.has(name.toLowerCase())) return true;
    // Round-15: Section 9b creates `<original>.zerotrust-backup-<utc-ts>`
    // files as part of the defang flow. If <original> happens to live at
    // the top level of build_root or its parent (rare but possible — e.g.
    // local-source audit pointed at a flat directory of source files),
    // the backup would also be at the top level. Protect those from sweep
    // so the audit's safety net isn't undone by its own cleanup step.
    // The convention is documented in packet.mjs:74.
    //
    // Round-16 fix: the original `[A-Za-z0-9_:.-]+$` included `.` inside
    // the character class, allowing files like
    // `evil.zerotrust-backup-DROP.exe` to bypass the sweep — the inner
    // class would consume `DROP.exe` all the way to end-of-string.
    // The legitimate timestamp format is ISO 8601 basic (YYYYMMDDTHHMMSSZ),
    // which contains no dots. Tighten the class to exclude `.`.
    if (/\.zerotrust-backup-[A-Za-z0-9_:-]+$/i.test(name)) return true;
    return false;
}

function safeRemoveFile(p) {
    if (!existsSync(p)) return { existed: false, removed: false };
    try {
        rmSync(p, { force: true, maxRetries: 3, retryDelay: 100 });
        if (existsSync(p)) {
            return { existed: true, removed: false, error: "path still exists after removal" };
        }
        return { existed: true, removed: true };
    } catch (err) {
        return { existed: true, removed: false, error: err.message };
    }
}

function listScratchFiles(dir) {
    if (!existsSync(dir)) return [];
    let entries;
    try {
        entries = readdirSync(dir, { withFileTypes: true });
    } catch {
        return [];
    }
    const out = [];
    for (const entry of entries) {
        if (!entry.isFile()) continue;
        if (isAllowedFilename(entry.name)) continue;
        out.push(nodePath.join(dir, entry.name));
    }
    return out;
}

/**
 * Tool signature:
 *   zerotrust_sweep_audit_scratch({
 *     build_root?: string,           // default DEFAULT_BUILD_ROOT (or active audit's build_root)
 *     also_sweep_parent?: boolean,   // default false — opt in to dirname(build_root)
 *     dry_run?: boolean,             // default false — when true, list only, don't delete
 *   })
 */
export async function sweepAuditScratchHandler(args, invocation, dependencies = {}) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;

    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) return failure(ctx.error);

    // Round-17 defense-in-depth: sweep is destructive (rmSync per file).
    // getTrustedAuditContext's strict mismatch check is gated on a truthy
    // sessionId for backward compat with non-destructive callers; but a
    // destructive caller MUST refuse an agent-supplied build_root that
    // doesn't match either the active-audit anchor or the default,
    // regardless of whether sessionId is present. Without this, a tool
    // invocation with a falsy sessionId could supply an arbitrary path
    // (e.g. "C:\\Users\\testuser") and have sweep operate on it.
    if (args.build_root && !ctx.hasActiveAudit) {
        const argResolved = nodePath.resolve(String(args.build_root)).toLowerCase();
        const defaultResolved = nodePath.resolve(DEFAULT_BUILD_ROOT).toLowerCase();
        if (argResolved !== defaultResolved) {
            return failure(
                `sweep refused: args.build_root (${args.build_root}) does not match ` +
                    `default build_root (${DEFAULT_BUILD_ROOT}) and no active audit is anchoring this path. ` +
                    `Refusing to perform destructive sweep on agent-supplied path. ` +
                    `Re-invoke zerotrust_sourcecheck to activate an audit first.`,
            );
        }
    }

    const buildRoot = nodePath.resolve(ctx.buildRoot);
    if (!nodePath.isAbsolute(buildRoot)) {
        return failure(`build_root must be absolute, got ${JSON.stringify(buildRoot)}`);
    }

    const alsoSweepParent = args.also_sweep_parent === true; // default false
    const dryRun = args.dry_run === true;

    const sweepDirs = [buildRoot];
    if (alsoSweepParent) {
        const parent = nodePath.dirname(buildRoot);
        // Defensive: refuse to sweep the filesystem root or to repeat
        // ourselves if buildRoot is already at the root.
        const parentRoot = nodePath.parse(parent).root;
        if (parent && parent !== buildRoot && parent !== parentRoot) {
            sweepDirs.push(parent);
        }
    }

    const found = [];
    const removed = [];
    const errors = [];
    const removeFile = dependencies.removeFile || safeRemoveFile;

    for (const dir of sweepDirs) {
        const files = listScratchFiles(dir);
        for (const f of files) {
            found.push(f);
            if (!dryRun) {
                const r = removeFile(f);
                if (r.removed) {
                    removed.push(f);
                } else if (r.error || r.existed) {
                    errors.push({ path: f, error: r.error || "path was not removed" });
                }
            }
        }
    }

    if (errors.length > 0) {
        return failure(
            "sweep did not remove every candidate; the active audit remains open so cleanup can be retried",
            {
                buildRoot,
                sweptDirs: sweepDirs,
                dryRun,
                foundCount: found.length,
                found,
                removedCount: removed.length,
                removed,
                errors,
                auditStillActive: ctx.hasActiveAudit,
            },
        );
    }

    return success({
        buildRoot,
        sweptDirs: sweepDirs,
        dryRun,
        foundCount: found.length,
        found,
        removedCount: dryRun ? 0 : removed.length,
        removed: dryRun ? null : removed,
        errors,
        auditStillActive: ctx.hasActiveAudit,
    });
}

// Test seam: exposes the file-allowlist + helper for unit tests.
export const __internals = {
    ALLOWED_TOP_LEVEL_FILES,
    isAllowedFilename,
    listScratchFiles,
    DEFAULT_BUILD_ROOT,
};
