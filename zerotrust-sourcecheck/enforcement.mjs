// enforcement.mjs — onPreToolUse hook logic + audit-in-progress state machine.
//
// The instruction packet is the primary control (it tells the agent what
// commands are safe). The hook here is the SECOND LAYER of defense: even if
// the agent ignores the packet, the hook intercepts dangerous shell calls
// before they execute on the user's host. This is what makes the extension
// "zerotrust" rather than merely advisory.
//
// State model: the handler activates an audit by recording { sessionId,
// buildPath, mode, expiresAt } in an in-memory Map. While an audit is active
// for a session, the hook applies strict rules to any shell-flavored tool
// call. The audit auto-expires after the mode-specific TTL so a forgotten
// audit doesn't leave the session permanently locked-down.

import nodePath from "node:path";
import {
    BUILD_MODES_SET as SHARED_BUILD_MODES,
    FULL_BUILD_MODES_SET as SHARED_FULL_BUILD_MODES,
    modeNeedsClone as SHARED_modeNeedsClone,
} from "./modes.mjs";
import { parseGithubUrl } from "./urlParser.mjs";

// TTL is mode-dependent (v3 fix). The 30-min default silently expired during
// real audit_source_council runs (15-30 min wall-clock) — once expiresAt
// passed, getActiveAudit() returned null and the entire enforcement hook
// became a no-op for the rest of the session. New per-mode TTLs leave
// generous headroom for retries and slow networks.
// Add TTL entries for the new local-source modes.
const AUDIT_TTL_MS_BY_MODE = {
    "metadata_only": 15 * 60 * 1000,
    "audit_source": 60 * 60 * 1000,
    "audit_source_council": 90 * 60 * 1000,
    "audit_local_source": 60 * 60 * 1000,
    "audit_local_source_council": 90 * 60 * 1000,
    "verify_release": 30 * 60 * 1000,
    "audit_and_safe_build": 120 * 60 * 1000,
    "audit_and_full_build": 120 * 60 * 1000,
    "audit_and_safe_build_council": 180 * 60 * 1000,
    "audit_and_full_build_council": 180 * 60 * 1000,
};

// Fallback for any future mode that's not in the map yet — generous default
// so a forgotten table entry doesn't reintroduce the silent-expiry regression.
const AUDIT_TTL_MS_DEFAULT = 90 * 60 * 1000;

function ttlForMode(mode) {
    return AUDIT_TTL_MS_BY_MODE[mode] ?? AUDIT_TTL_MS_DEFAULT;
}

// Mode taxonomy is centralized in modes.mjs; these aliases preserve source
// compatibility with the rest of this file.
const BUILD_MODES = SHARED_BUILD_MODES;
const FULL_BUILD_MODES = SHARED_FULL_BUILD_MODES;

const activeAudits = new Map(); // sessionId -> { buildPath, mode, expiresAt, expectedClonePath }

/**
 * Activate an audit-in-progress state for a session. Called by the tool
 * handler before returning the instruction packet.
 *
 * `buildPath` is the canonical build root (e.g. ~/.copilot/zerotrust-sandbox).
 * `expectedClonePath` is the specific subdirectory the packet has authorized
 * for the clone (e.g. ~/.copilot/zerotrust-sandbox/owner-repo-abc1234).
 */
export function activateAudit({ sessionId, buildPath, mode, expectedClonePath, owner, repo, ref, refType, localPath, expectedReportPath }) {
    if (!sessionId) throw new Error("activateAudit requires sessionId");
    if (!buildPath) throw new Error("activateAudit requires buildPath");
    const effectiveMode = mode || "audit_source";

    // Local-source modes don't have a clone path (they read from an
    // operator-supplied on-disk directory). They DO have a localPath
    // we pin so the wrappers can detect this audit shape.
    const isLocal = effectiveMode === "audit_local_source"
        || effectiveMode === "audit_local_source_council";

    if (!isLocal && !expectedClonePath) {
        throw new Error("activateAudit requires expectedClonePath (non-local-source modes)");
    }
    if (isLocal && !localPath) {
        throw new Error("activateAudit requires localPath (local-source modes)");
    }

    activeAudits.set(sessionId, {
        buildPath: nodePath.resolve(buildPath),
        mode: effectiveMode,
        expiresAt: Date.now() + ttlForMode(effectiveMode),
        // URL-driven audits get expectedClonePath / owner / repo / ref / refType.
        // Local audits get localPath / expectedReportPath. Mutually-exclusive
        // shapes; the audit object carries only the fields appropriate for
        // its mode.
        expectedClonePath: expectedClonePath ? nodePath.resolve(expectedClonePath) : null,
        owner: owner ? String(owner).toLowerCase() : null,
        repo: repo ? String(repo).toLowerCase() : null,
        // Round-8 hardening (gpt-5.5 R8 F1): also pin the ref so safe_clone
        // refuses to clone a different ref of the same repo. Null ref means
        // "no specific ref pinned at activation time" (e.g. the user passed
        // a bare repo URL with no /tree/<ref>); in that case safe_clone
        // accepts any ref.
        ref: ref ? String(ref) : null,
        refType: refType ? String(refType) : null,
        // Local-source fields.
        localPath: localPath ? nodePath.resolve(localPath) : null,
        expectedReportPath: expectedReportPath ? nodePath.resolve(expectedReportPath) : null,
    });
}

export function deactivateAudit(sessionId) {
    activeAudits.delete(sessionId);
}

/**
 * Record the actual resolved clone path for an active audit, after safe_clone
 * has resolved the SHA and physically created the clone directory. Subsequent
 * install/build/cleanup/finalize_report calls cross-check args.clone_path
 * against this recorded value to ensure the wrapper operates on the audit's
 * own clone rather than some other sibling directory under build_root.
 *
 * Round-4 hardening (gpt-5.5 reviewer F2): the round-1 cluster-J fix only
 * constrained operations to be UNDER build_root, not to the SPECIFIC clone
 * for the active audit. Without binding, a session activated for repo A
 * could be tricked into building a sibling repo-B directory in the same
 * sandbox, attaching audit-A's council outcome to a different target.
 */
export function recordResolvedClonePath(sessionId, resolvedClonePath) {
    const audit = activeAudits.get(sessionId);
    if (!audit) return false;
    if (audit.expiresAt < Date.now()) return false;
    audit.resolvedClonePath = nodePath.resolve(resolvedClonePath);
    return true;
}

// v4-r2 round-5 (C-R5-2 high): record the resolved commit SHA when
// safe_list_tree pins the audit to a specific commit. Subsequent
// safe_fetch_file calls must use this same SHA — so a malicious file
// in the audited tree can't trick the agent into fetching from a
// different commit and reporting under the pinned audit's identity.
export function recordResolvedSha(sessionId, sha) {
    const audit = activeAudits.get(sessionId);
    if (!audit) return false;
    if (audit.expiresAt < Date.now()) return false;
    if (typeof sha !== "string" || !/^[a-f0-9]{40}$/i.test(sha)) return false;
    // First-write-wins: once a SHA is pinned for the audit, refuse to
    // overwrite (avoids a malicious tree from re-pinning to a different
    // commit mid-audit).
    if (audit.resolvedSha) return audit.resolvedSha.toLowerCase() === sha.toLowerCase();
    audit.resolvedSha = sha.toLowerCase();
    return true;
}

// Track sessions that recently expired so we can log it once on the next
// getActiveAudit() call. Keyed by sessionId; cleared when reported.
const recentlyExpired = new Map(); // sessionId -> { mode, expiredAt }

/**
 * Returns the most recent expiry record for a session and clears it. Lets
 * callers (or higher-level diagnostic code) surface "your enforcement TTL
 * just expired and your hook went no-op" warnings instead of letting that
 * happen silently.
 */
export function consumeExpiryNotice(sessionId) {
    const notice = recentlyExpired.get(sessionId);
    if (notice) recentlyExpired.delete(sessionId);
    return notice || null;
}

export function getActiveAudit(sessionId) {
    const audit = activeAudits.get(sessionId);
    if (!audit) return null;
    if (audit.expiresAt < Date.now()) {
        recentlyExpired.set(sessionId, { mode: audit.mode, expiredAt: audit.expiresAt });
        activeAudits.delete(sessionId);
        // Round-3 hardening: also clear any recorded council outcome on
        // TTL expiry. Without this, a passing outcome from one audit could
        // satisfy the council-build gate of a *different* mode the agent
        // claims after expiry (since the outcome is keyed only on sessionId).
        // Do a dynamic import to avoid a circular dep at module load.
        try {
            import("./safeWrappers/state.mjs").then((m) => m.clearRecordedOutcome(sessionId)).catch(() => {});
        } catch { /* best-effort */ }
        return null;
    }
    return audit;
}

/**
 * Resolve the trusted audit context for a wrapper invocation.
 *
 * Returns one of:
 *   { ok: true,  buildRoot, mode, expectedClonePath, resolvedClonePath, owner, repo, hasActiveAudit: true  }
 *   { ok: true,  buildRoot, mode, expectedClonePath, resolvedClonePath, owner, repo, hasActiveAudit: false }
 *   { ok: false, error }
 */
export function getTrustedAuditContext({ sessionId, args, defaultBuildRoot }) {
    const audit = sessionId ? getActiveAudit(sessionId) : null;

    if (audit) {
        if (args && args.build_root) {
            const argResolved = nodePath.resolve(String(args.build_root)).toLowerCase();
            const auditResolved = audit.buildPath.toLowerCase();
            if (argResolved !== auditResolved) {
                return {
                    ok: false,
                    error: `args.build_root (${args.build_root}) does not match the active audit's build_root (${audit.buildPath}); refusing to operate on a different sandbox`,
                };
            }
        }
        return {
            ok: true,
            buildRoot: audit.buildPath,
            mode: audit.mode,
            expectedClonePath: audit.expectedClonePath,
            resolvedClonePath: audit.resolvedClonePath || null,
            resolvedSha: audit.resolvedSha || null,
            owner: audit.owner || null,
            repo: audit.repo || null,
            ref: audit.ref || null,
            refType: audit.refType || null,
            // Local-source audit fields. Null on URL-driven audits.
            localPath: audit.localPath || null,
            expectedReportPath: audit.expectedReportPath || null,
            hasActiveAudit: true,
        };
    }

    const fallback = (args && args.build_root) || defaultBuildRoot;
    if (!fallback) {
        return { ok: false, error: "no active audit and no default build_root supplied" };
    }
    if (sessionId && args && args.build_root) {
        const argResolved = nodePath.resolve(String(args.build_root)).toLowerCase();
        const defaultResolved = nodePath.resolve(String(defaultBuildRoot)).toLowerCase();
        if (argResolved !== defaultResolved) {
            return {
                ok: false,
                error: `no active audit for session and args.build_root (${args.build_root}) does not match default build_root; refusing to operate on agent-supplied build_root without an audit. Re-invoke zerotrust_sourcecheck to activate an audit first.`,
            };
        }
    }

    return {
        ok: true,
        buildRoot: nodePath.resolve(String(fallback)),
        mode: null,
        expectedClonePath: null,
        resolvedClonePath: null,
        resolvedSha: null,
        owner: null,
        repo: null,
        ref: null,
        refType: null,
        localPath: null,
        expectedReportPath: null,
        hasActiveAudit: false,
    };
}

// Tools we treat as command-runners and inspect before execution.
// "powershell" is the primary CLI shell tool; "bash" / "run_command"
// covered for portability with other shell-flavored extension tools.
const SHELL_TOOLS = new Set(["powershell", "bash", "run_command"]);

// Patterns that indicate a package manager install. Each entry is
// { pattern, requiredFlagRegex, ecosystem } — the install is denied
// unless requiredFlagRegex matches the same command (or the audit
// mode is audit_and_full_build, which deliberately allows lifecycle
// scripts).
// v4-r2 round-5 (A-R5-1): superseded by hasSafeIgnoreScripts() etc.
// Kept here as legacy reference; no callers remain.
const NEVER_MATCH = /(?!)/;

// v4-r2 round-5 hardening (A-R5-1 critical): nopt (npm's CLI parser)
// consumes the NEXT argv as the value of a Boolean flag if that argv
// is one of true/false/0/1/yes/no/on/off. So `--ignore-scripts false`
// disables script suppression even though the regex sees the safe
// flag. Replace REQUIRE_IGNORE_SCRIPTS with an argv-walker that
// handles `=value`, separate-token value, and the inverse form.
//
// hasSafeIgnoreScripts returns true iff:
//   - some token is `--ignore-scripts` (bare, OR with `=true`/`=1`/
//     `=yes`/`=on`), AND
//   - that bare-form token is NOT immediately followed by a value-token
//     in {false, 0, no, off}, AND
//   - no token is `--no-ignore-scripts`, AND
//   - no token is `--ignore-scripts` with `=false`/`=0`/`=no`/`=off`.
function hasSafeIgnoreScripts(cmd) {
    const tokens = tokenizeShell(String(cmd || ""));
    let hasSafe = false;
    let hasNegation = false;
    const stripVal = (s) => String(s || "").replace(/^["']|["']$/g, "").toLowerCase();
    for (let i = 0; i < tokens.length; i++) {
        const tLower = tokens[i].toLowerCase().replace(/["']/g, "");
        if (tLower === "--no-ignore-scripts") {
            hasNegation = true;
            continue;
        }
        const m = tLower.match(/^--ignore-scripts(?:=(.+))?$/);
        if (!m) continue;
        const attached = m[1];
        if (attached === undefined) {
            // Bare flag — peek next token.
            const next = stripVal(tokens[i + 1]);
            if (["true", "1", "yes", "on"].includes(next)) {
                hasSafe = true; i++;
            } else if (["false", "0", "no", "off"].includes(next)) {
                hasNegation = true; i++;
            } else {
                hasSafe = true;
            }
        } else {
            const v = stripVal(attached);
            if (["true", "1", "yes", "on"].includes(v)) hasSafe = true;
            else if (["false", "0", "no", "off"].includes(v)) hasNegation = true;
        }
    }
    return hasSafe && !hasNegation;
}

function hasSafePipFlags(cmd) {
    const tokens = tokenizeShell(String(cmd || "")).map((t) => t.replace(/["']/g, ""));
    if (tokens.includes("--only-binary=:all:")) return true;
    return tokens.includes("--no-deps") && tokens.includes("--no-build-isolation");
}

function hasSafeCargoFlags(cmd) {
    const tokens = tokenizeShell(String(cmd || "")).map((t) => t.replace(/["']/g, ""));
    return tokens.includes("--locked") && tokens.includes("--offline");
}

function neverSafe() {
    return false;
}

const INSTALL_RULES = [
    {
        ecosystem: "npm",
        pattern: /\b(?:npm)\s+(?:install|i|add|ci)\b/i,
        // npm subcommands that run lifecycle scripts but are
        // neutralizable by --ignore-scripts. Note: exec/x/init/create
        // moved to the no-safe-flag rule below since --ignore-scripts
        // doesn't actually prevent npx-style download+execute.
        normalizedPattern: /\bnpm(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:install|i|add|ci|pack|rebuild|run|run-script|test|start|prune)\b/,
        safeChecker: hasSafeIgnoreScripts,
        flagHint: "--ignore-scripts (no =false/no separate-token value/no --no-ignore-scripts)",
    },
    {
        // v4-r2 round-5 (A-R5-3, B-R5-1, C-R5-1): npx, pnpm dlx, yarn
        // dlx, npm exec, npm x, npm init, npm create, pnpm create,
        // pnpm dlx, yarn dlx — all download AND execute a package as
        // their primary purpose. NO safe-flag equivalent.
        // Suffix group is now WITHIN each alternation arm so .exe/.cmd/
        // .ps1 attach to the program name correctly (pnpm.exe dlx
        // bypassed the round-4 pattern).
        ecosystem: "npx",
        pattern: /\bnpx\b/i,
        normalizedPattern:
            /\b(?:npx(?:\.exe|\.cmd|\.ps1)?\b|npm(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:exec|x|init|create)\b|pnpm(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:dlx|create|exec)\b|yarn(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:dlx|create)\b)/,
        safeChecker: neverSafe,
        flagHint: "(npx/dlx/exec/x/init/create have no safe-mode flag — use audit_and_full_build with explicit ack)",
    },
    {
        ecosystem: "yarn",
        pattern: /\byarn(?:\s+(?:install|add))?\b/i,
        normalizedPattern: /\byarn(?:\.exe|\.cmd|\.ps1)?\b/,
        safeChecker: hasSafeIgnoreScripts,
        flagHint: "--ignore-scripts (no =false/no separate-token value/no --no-ignore-scripts)",
    },
    {
        ecosystem: "pnpm",
        pattern: /\bpnpm\s+(?:install|i|add)\b/i,
        normalizedPattern: /\bpnpm(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:install|i|add|update|rebuild|run|test|start|pack|prune)\b/,
        safeChecker: hasSafeIgnoreScripts,
        flagHint: "--ignore-scripts (no =false/no separate-token value/no --no-ignore-scripts)",
    },
    {
        ecosystem: "pip",
        pattern: /\bpip3?\s+install\b/i,
        // v4-r2 round-5 (A-R5-4): allow no-space short option
        // `python -mpip install` (CPython parses -mPATH as -m PATH).
        normalizedPattern: /(?:\bpip3?(?:\.exe)?\s+install\b|\b(?:python\d*|py)(?:\.exe)?\s+-m\s*pip(?:\d*)?\s+install\b)/,
        safeChecker: hasSafePipFlags,
        flagHint: "--only-binary=:all: (or --no-deps --no-build-isolation, no =false negations)",
    },
    {
        ecosystem: "cargo",
        pattern: /\bcargo\s+install\b/i,
        normalizedPattern: /\bcargo(?:\.exe)?\s+install\b/,
        safeChecker: hasSafeCargoFlags,
        flagHint: "--locked --offline",
    },
    {
        ecosystem: "go",
        pattern: /\bgo\s+install\b/i,
        normalizedPattern: /\bgo(?:\.exe)?\s+install\b/,
        safeChecker: neverSafe,
        flagHint: "(no safe equivalent on Go — use audit_and_full_build if you need it)",
    },
    {
        ecosystem: "gradle",
        pattern: /\b(?:gradle|gradlew|\.\/gradlew)\b/i,
        normalizedPattern: /\b(?:gradle|gradlew)(?:\.bat|\.exe)?\b/,
        safeChecker: neverSafe,
        flagHint: "(gradle has no safe-mode flag — use audit_and_full_build if you need it)",
    },
    {
        ecosystem: "maven",
        pattern: /\b(?:mvn|mvnw|\.\/mvnw)\b/i,
        normalizedPattern: /\b(?:mvn|mvnw)(?:\.bat|\.exe|\.cmd)?\b/,
        safeChecker: neverSafe,
        flagHint: "(mvn has no safe-mode flag — use audit_and_full_build if you need it)",
    },
];

// Synthesized install rule for the PS programmatic name-synthesis
// fallback. Always denied — there's no legit reason to construct
// `npm` etc. via [char] arithmetic during an audit.
const SYNTHESIZED_INSTALL_RULE = {
    ecosystem: "synthesized",
    pattern: /(?!)/,
    normalizedPattern: /(?!)/,
    safeChecker: neverSafe,
    flagHint: "(programmatic name-synthesis denied in audit modes)",
};

// v4-r2 round-6 (C-R6-2 high): add `i` (npm/pnpm single-letter
// install alias). The synthesis fallback fires when an install-verb
// is paired with a PS sigil, so adding `i` here closes synthesized
// `npm i` (e.g. `& ([char]110+[char]112+[char]109) i`).
const INSTALL_VERB_RE =
    /\b(?:install|i|ci|add|init|create|pack|rebuild|run|run-script|test|start|exec|prune|dlx|x|update)\b/i;

// Patterns matching "running an executable from build_root". Mainly meant
// to prevent the agent from accidentally launching a downloaded release
// binary or compiled artifact from inside the audited tree.
//
// AV-safety: process-launch cmdlet names are built by character-concatenation
// at module load time so the literal cmdlet strings NEVER appear as
// contiguous bytes anywhere in this source file (including this comment).
// This matters because external code-review agents sometimes invoke ripgrep
// with offensive cmdlet names concatenated into a single regex argument,
// which trips Defender heuristics when the cmdline enumerates many such
// cmdlets together. Keeping our own source files free of contiguous
// offensive-cmdlet strings reduces the risk that any tool that reads our
// source then writes the read content back into a process argv list will
// trigger AV. (Round-8 hardening: the previous version of this comment
// inadvertently spelled out the three cmdlet names in a list — removed.)
const EXEC_CMDLET_PARTS = [
    ["Start", "Process"],
    ["Invoke", "Item"],
    ["Mount", "DiskImage"],
];
const EXECUTION_PATTERNS = EXEC_CMDLET_PARTS.map(
    (parts) => new RegExp("\\b" + parts.join("-") + "\\b", "i"),
);

// v4-r2 round-14: refuse GUI-launching and disk-writing commands during
// ANY audit mode (not just build modes). The user-visible bug was a
// sub-agent calling `Invoke-Item <path-to-file>` mid-audit, which
// opened the file in Notepad — surprising/unwanted side effect. The
// same sub-agents also downloaded source files to disk via
// `iwr -OutFile` instead of using zerotrust_safe_fetch_file. Both
// classes of misuse now hit a hard deny here.
//
// AV-safety: same parts-join trick as EXEC_CMDLET_PARTS — the literal
// cmdlet strings are assembled at module load, never appear as
// contiguous bytes in this source.
const GUI_OPEN_CMDLET_PARTS = [
    ["Invoke", "Item"],
    ["Start", "Process"],
];
const GUI_BARE_PROGRAMS = [
    "notepad", "wordpad", "mspaint",
    "winword", "excel", "powerpnt", "outlook",
];
const GUI_OPEN_PATTERNS = (() => {
    const out = [];
    for (const parts of GUI_OPEN_CMDLET_PARTS) {
        out.push({
            re: new RegExp("\\b" + parts.join("-") + "\\b", "i"),
            name: parts.join("-"),
        });
    }
    // `ii` PowerShell alias for Invoke-Item. Require some target token
    // after the alias to avoid matching the word "ii" inside identifiers.
    // Round-15 fix: the original regex `["']?(?:[\\\/A-Za-z]|\.{1,2}[\\\/])`
    // required a slash AFTER the dot, missing `ii .` (open current dir
    // in Explorer — a common PowerShell idiom that pops a GUI window).
    // Broaden target to any non-whitespace char after the optional quote.
    out.push({
        re: /(?:^|[\s;|&`])ii\s+["']?\S/i,
        name: "ii (Invoke-Item alias)",
    });
    // `cmd /c start <thing>` (the cmd.exe builtin "start" opens the
    // default handler for a file or URL — Notepad for .txt, the
    // default browser for URLs, etc.).
    out.push({
        re: /\bcmd(?:\.exe)?\s+\/c\s+start\b/i,
        name: "cmd /c start",
    });
    // Bare `start <arg>` at the head of a (sub)command. We intentionally
    // do NOT match `Start-` (PowerShell `Start-*` cmdlets are caught by
    // their own GUI_OPEN_CMDLET_PARTS entry) because the `\b\s+`
    // requirement means `Start-Process` (with `-` after `t`) won't
    // satisfy the post-`start` whitespace.
    // Round-15 fix: the original regex required a path-shaped target
    // (`[A-Za-z]:\\`, `./`, `name.ext`, or `https://`), missing `start .`
    // (opens current dir in Explorer). Broaden to any non-empty arg.
    out.push({
        re: /(?:^|[;&|`]\s*)start\b\s+\S/i,
        name: "cmd.exe start",
    });
    for (const prog of GUI_BARE_PROGRAMS) {
        out.push({
            re: new RegExp("\\b" + prog + "(?:\\.exe)?\\b", "i"),
            name: prog,
        });
    }
    // VS Code / similar IDE launcher, but only when invoked with a
    // target argument. Don't match the substring "code" in identifiers.
    // Round-15 fix: the original regex required a path-shaped target
    // (`X:\`, `./`, `--flag`), missing `code .` (open current dir in
    // VS Code — extremely common command). Use a negative lookahead to
    // exclude bare `code` and broaden target.
    out.push({
        re: /\bcode(?:\.cmd|\.exe)?\s+(?!--?\w)\S/i,
        name: "VS Code launcher",
    });
    return out;
})();

// Disk-writing download patterns. During an audit the right tool for
// fetching repo content is zerotrust_safe_fetch_file (API-direct, no
// disk writes, audit-scoped to the pinned SHA). Sub-agents reaching
// for `iwr -OutFile` / `curl -o` / `wget -O` are working around the
// API-direct contract and leaving scratch source files on disk.
//
// KNOWN LIMITATION (round-15): pure shell-redirect downloads cannot be
// reliably regex-matched without false positives — e.g.,
//   curl https://example.com > foo
//   gh api repos/.../contents/file > foo
//   Invoke-WebRequest -Uri ... > foo
// would all bypass these patterns. Catching `> file` unconditionally
// would false-positive on every legitimate stdout-to-file write the
// orchestrator might do (REPORT.md generation, etc.). The downstream
// `zerotrust_sweep_audit_scratch` wrapper is the active mitigation for
// the resulting scratch files; treat these enforcement patterns as
// forward-compatible defense for the specific named-flag forms only.
const DISK_DOWNLOAD_PATTERNS = [
    {
        re: /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^;|]*?\s-OutFile\b/i,
        name: "Invoke-WebRequest -OutFile",
    },
    {
        re: /\bcurl(?:\.exe)?\b[^;|]*\s(?:-o|-O|--output)(?:\s|=)/i,
        name: "curl -o/--output",
    },
    {
        re: /\bwget(?:\.exe)?\b[^;|]*\s(?:-O|--output-document)(?:\s|=)/i,
        name: "wget -O/--output-document",
    },
    // Round-15: catch the `<download-cmd> | Out-File/Set-Content/Add-Content/Tee-Object`
    // pipe form. The download source is unambiguously a download (iwr,
    // curl, wget, Invoke-RestMethod, gh api raw); the sink is unambiguously
    // a disk-write cmdlet. False positives are highly unlikely.
    {
        re: /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl(?:\.exe)?|wget(?:\.exe)?|gh\s+api)\b[^;]*\|\s*\b(?:Out-File|Set-Content|Add-Content|Tee-Object)\b/i,
        name: "download piped to Out-File / Set-Content / Tee-Object",
    },
];

// Heuristic: extract any path-like tokens from the command string.
// Returns absolute paths only. We skip git's own arguments here (because
// git accepts "remote URLs that look like paths") by handling git clone
// specially in the main inspector.
function extractPathTokens(command) {
    const tokens = [];
    // Quoted absolute paths
    const quoted = command.match(/(?:"|')([A-Za-z]:[\\\/][^"']{0,500})(?:"|')/g) || [];
    for (const q of quoted) tokens.push(q.slice(1, -1));
    // Bare absolute paths (drive letter + slash, terminated by whitespace)
    const bare = command.match(/(?<!["'])\b([A-Za-z]:[\\\/][^\s"']*)/g) || [];
    for (const b of bare) tokens.push(b);
    return tokens;
}

// v4-r2 round-3 hardening: high-recall substring-based normalization
// for the audit-mode denial path. The tokenizer/operator-stripping
// approach (round-1/round-2) tried to parse shell syntax but every
// attacker shape we missed (env -i, & "sudo" git, /usr/bin/sudo git,
// nice -n 19 git, "git" cl"o"ne, & {git clone}, bash -c "git clone",
// xargs git clone, eval "git clone", g\it on bash, line continuation,
// etc.) became a real bypass.
//
// New design (defense-in-depth):
//   Layer 1 — substring scan (this function): for AUDIT-ONLY modes,
//     normalize the entire command into a quote/escape/whitespace-
//     stripped lowercase form, then scan for the substring "git" +
//     "clone" together (or gh+repo+clone). Audit modes have no legit
//     reason for these substrings to appear; false positives don't
//     matter — the agent will use safe_fetch_file, not a clone.
//   Layer 2 — tokenizer (existing detectsClone/validateCloneHit):
//     for BUILD modes only, where we need to validate the clone
//     destination matches the planned path. Tokenizer issues here
//     downgrade to "skipped path validation" (the agent's clone
//     proceeds with whatever destination it chose, which in build
//     mode the user has already authorized).
//
// This dual approach means no single bypass class can defeat both
// layers in audit mode — the substring layer is broad and cheap.
// v4-r2 round-4 hardening: pre-collapse line continuations and
// caret/ANSI-C escapes BEFORE whitespace processing so:
//   - PS:    `git cl`<LF>one`             → `git clone`     (continuation FUSES tokens)
//   - bash:  `git cl\<LF>one`              → `git clone`
//   - cmd:   `g^it cl^one`                 → `git clone`     (caret-escape removed)
//   - bash:  `$'\x67it' clone`             → `git clone`     (ANSI-C decode)
//   - bash:  `git $'\x63\x6c\x6f\x6e\x65'` → `git clone`     (ANSI-C decode)
// Round-3 fix only handled BETWEEN-token continuations; round-4 also
// handles MID-token continuations (which the whitespace-collapse path
// would have split into two harmless words like `cl one`).
// v4-r2 round-11 hardening (A-R11-1 high): PowerShell 7+ added the
// Unicode-codepoint escape `` `u{HHHH} `` that decodes to any Unicode
// character (including ASCII letters). The round-9 backtick-strip
// preserves `\`u` (it's in the disallowed-set), but doesn't decode
// the trailing `{HHHH}`. So `` g`u{0069}t `` evaluates to `git` in
// PS 7+ but our regex sees the literal `gu{0069}t`, missing the
// detection. Mirror the bash ANSI-C decoder. Run this BEFORE the
// backtick-strip so the decoded char is processed normally.
function decodePsUnicodeEscapes(s) {
    return String(s || "").replace(/`u\{([0-9a-fA-F]{1,6})\}/g, (_m, hex) => {
        const cp = parseInt(hex, 16);
        if (!Number.isFinite(cp) || cp < 0 || cp > 0x10FFFD) return "";
        try { return String.fromCodePoint(cp); } catch { return ""; }
    });
}

const ANSI_C_ESCAPES = {
    "n": "\n", "r": "\r", "t": "\t", "b": "\b", "a": "\x07",
    "f": "\f", "v": "\v", "e": "\x1b", "0": "\0",
    "\\": "\\", "'": "'", '"': '"', "?": "?",
};

function decodeAnsiCQuoting(s) {
    return s.replace(/\$'([^']*)'/g, (_match, body) => {
        let out = "";
        for (let i = 0; i < body.length; i++) {
            if (body[i] === "\\" && i + 1 < body.length) {
                const next = body[i + 1];
                if (next === "x" && /[0-9a-f]{2}/i.test(body.substr(i + 2, 2))) {
                    out += String.fromCharCode(parseInt(body.substr(i + 2, 2), 16));
                    i += 3;
                } else if (next === "u" && /[0-9a-f]{4}/i.test(body.substr(i + 2, 4))) {
                    out += String.fromCharCode(parseInt(body.substr(i + 2, 4), 16));
                    i += 5;
                } else if (next in ANSI_C_ESCAPES) {
                    out += ANSI_C_ESCAPES[next];
                    i += 1;
                } else {
                    out += next;
                    i += 1;
                }
            } else {
                out += body[i];
            }
        }
        return out;
    });
}

// v4-r2 round-7 hardening (A-R7-1 high): tighten PS_SYNTHESIS_SIGIL_RE
// to avoid over-blocking legitimate audit commands. The previous regex
// matched:
//   - `&&  (` (the `&` of `&&` followed by ` (`) — chained sub-shell
//   - `gh api -f "key=val"` — gh CLI form-field syntax (cited by packet)
//   - `-join` anywhere — including grep IOC pattern
//   - `iex` / `Invoke-Expression` inside quoted strings (literal IOC grep)
//
// Fix:
//   1. Anchor `& (` and `& {` so the `&` cannot be the second of `&&`
//      (require the preceding char NOT be `&`).
//   2. Drop `-join` and `-f "…"` from the blanket-deny set entirely —
//      they're string-construction operators that only matter WHEN
//      paired with synthesis sigils (still caught via [char] / & $var
//      / `iex` / `& (`).
//   3. Strip all quoted spans before regex testing so legit commands
//      that grep for `iex` / `Invoke-Expression` literals don't fire.
const PS_SYNTHESIS_SIGIL_RE =
    /(?:\[char\]\s*\d|&\s*\$\w|invoke-expression|\biex\b|(?<![&|])&[ \t]*\(|(?<![&|])&[ \t]*\{|invoke-command\b)/i;

// v4-r2 round-10 (C-R10-1 high): detect when a double-quoted span
// containing PS expansion ($var, $(...), ${...}) is used as the
// PROGRAM TOKEN (after `&` call operator or `.` dot-source operator).
// `& "$x" install` synthesizes the program name at runtime — the
// preserved-quote span hides the real program from substring scans.
// Treat as synthesis.
const PS_QUOTED_PROGRAM_RE = /(?:^|\s)[&.]\s*"[^"]*\$[({\w][^"]*"/;

function commandHasPsSynthesis(cmd) {
    // v4-r2 round-8 (A-R8-2 critical): preserve double-quoted spans
    // that contain PowerShell expansion constructs (`$(`, `${`, `$<word>`).
    // PS double-quoted strings are NOT inert — `"$(...)"` interpolates
    // sub-expressions at runtime. Stripping such spans hides the
    // synthesis sigil inside, defeating the whole detection.
    // Single-quoted spans in PS ARE literal, so safe to strip.
    let stripped = String(cmd || "").replace(
        /(["'])((?:\\.|(?!\1).)*)\1/g,
        (m, q, body) => {
            if (q === '"' && /\$[({\w]/.test(body)) return m;
            return "";
        },
    );
    // v4-r2 round-11 (A-R11-1): decode PS 7+ Unicode escapes BEFORE
    // the simple backtick-strip so `` g`u{0069}t `` becomes `git`.
    stripped = decodePsUnicodeEscapes(stripped);
    // v4-r2 round-9 (B-R9-1): strip PS backtick escapes BEFORE running
    // PS_SYNTHESIS_SIGIL_RE.
    // v4-r2 round-10 (A-R10-1): drop the case-insensitive `i` flag —
    // PS escape sequences are case-sensitive lowercase-only.
    stripped = stripped.replace(/`([^nrtbafve0\\'"])/g, "$1");
    if (PS_SYNTHESIS_SIGIL_RE.test(stripped)) return true;
    // v4-r2 round-10 (C-R10-1): also catch "& "$var-expansion"" or
    // ". "$var-expansion"" — synthesized program token via preserved
    // double-quoted interpolation.
    if (PS_QUOTED_PROGRAM_RE.test(String(cmd || ""))) return true;
    return false;
}

// v4-r2 round-3 hardening: dual normalization for substring scan.
// Backslash has two valid meanings:
//   (a) Windows path separator: `C:\path\to\git.exe` — must be
//       SPLIT on `\` so `git.exe` becomes a standalone word for the
//       \bgit\b detection to fire.
//   (b) bash escape char: `g\it` evaluates to `git` — must be
//       STRIPPED so the underlying program name is reconstructed.
// We can't pick one; produce both forms and scan both.
//
// v4-r2 round-4 hardening: BEFORE the whitespace step, pre-collapse
// (a) cmd.exe caret escapes (`g^it` → `git`), (b) PS / bash line
// continuations (so `cl<LF>one` FUSES into `clone` instead of
// splitting into two words), and (c) bash ANSI-C `$'\xHH'` quoting
// decoding (so `$'\x67it'` becomes `git` literally).
function normalizeForSubstringScan(command) {
    let raw = String(command || "");
    // ANSI-C decode first — operates on the raw bytes before any other
    // transformation so `$'\x67\x69\x74'` becomes `git`.
    raw = decodeAnsiCQuoting(raw);
    // v4-r2 round-11 (A-R11-1): also decode PS 7+ Unicode escapes
    // (`` `u{HHHH} ``). Bash already covered via decodeAnsiCQuoting;
    // PS needs its own decoder.
    raw = decodePsUnicodeEscapes(raw);
    // cmd.exe caret escape: `^X` → `X` (the caret is removed; the next
    // char is left literal). Run before the lowercase + quote-strip.
    raw = raw.replace(/\^(.)/g, "$1");
    // Line-continuation FUSE: PS backtick + newline, bash backslash +
    // newline. Both should join the surrounding chars (NOT introduce
    // whitespace), so that `cl<LF>one` becomes `clone`. Run BEFORE
    // the `\r\n\t` → space step.
    raw = raw.replace(/`\s*\r?\n/g, "").replace(/\\\s*\r?\n/g, "");
    const lower = raw.toLowerCase();
    const stripQuotesAndCollapse = (s) => s
        .replace(/["'`]/g, "")
        .replace(/[\r\n\t]+/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    // Form A: `\` → space (Windows path semantics).
    const formA = stripQuotesAndCollapse(lower.replace(/\\/g, " "));
    // Form B: `\` stripped (bash escape semantics).
    const formB = stripQuotesAndCollapse(lower.replace(/\\/g, ""));
    return [formA, formB];
}

// Layer-1 detection: does the normalized command contain a clone
// invocation in any shape? Returns { kind: "git" | "gh" } when a
// clone is suspected, or null. False positives are acceptable in
// audit mode — the agent doesn't legitimately need to clone there.
function commandLooksLikeClone(command) {
    const forms = normalizeForSubstringScan(command);
    for (const norm of forms) {
        if (/\bgit(?:\.exe|\.cmd|\.com|\.ps1)?\b/.test(norm) && /\bclone\b/.test(norm)) {
            return { kind: "git" };
        }
        if (/\bgh(?:\.exe|\.cmd|\.ps1)?\b/.test(norm) && /\brepo\b/.test(norm) && /\bclone\b/.test(norm)) {
            return { kind: "gh" };
        }
    }
    // v4-r2 round-4 hardening (A-R4-3): PowerShell programmatic name
    // synthesis can construct `git` at runtime so the substring scan
    // never sees it. If the command contains `clone` AND any PS
    // synthesis sigil, treat as a likely git clone. False positives
    // in audit mode are acceptable.
    for (const norm of forms) {
        if (/\bclone\b/.test(norm) && commandHasPsSynthesis(command)) {
            return { kind: "git" };
        }
    }
    return null;
}

// Layer-1 detection for package-manager installs. Returns ALL matched
// rules across all sub-commands (one per sub-command), or empty array.
//
// v4-r2 round-6 (A-R6-1 critical): first-rule-wins was bypassable.
// `npm install --ignore-scripts && pnpm dlx evilpkg` matched the npm
// rule first, satisfied --ignore-scripts, and the chained pnpm dlx
// (a NEVER_MATCH ecosystem) was never checked. New design: enumerate
// every sub-command, find ALL matching rules, validate each. Deny if
// ANY hit fails.
//
// v4-r2 round-5 PS-synthesis fallback retained, now per-sub-command.
function detectAllInstallHits(command) {
    const hits = [];
    for (const sub of splitSubCommands(command)) {
        const subForms = normalizeForSubstringScan(sub);
        for (const rule of INSTALL_RULES) {
            if (subForms.some((n) => rule.normalizedPattern.test(n))) {
                hits.push({ rule, sub, normalized: subForms[0] });
                break;
            }
        }
        // PS-synthesis fallback per sub-command.
        if (subForms.some((n) => INSTALL_VERB_RE.test(n)) && commandHasPsSynthesis(sub)) {
            hits.push({ rule: SYNTHESIZED_INSTALL_RULE, sub, normalized: subForms[0] });
        }
    }
    // v4-r2 round-7 (B-R7-1) + round-8 (B-R8-1): whole-command fallback.
    // splitSubCommands breaks `(`/`)` apart so a synthesized invocation
    // like `& ([char]110+[char]112+[char]109) install` becomes two
    // sub-commands neither of which has BOTH a verb AND a sigil.
    // Re-check the full command. Round-8: the previous `hits.length === 0`
    // guard let `npm ci --ignore-scripts && & ([char]…) install` slip
    // through (legitimate npm hit short-circuited the fallback). Always
    // run the whole-command check; SYNTHESIZED_INSTALL_RULE is neverSafe
    // so it's correct to deny if a sigil+verb pair exists anywhere.
    const wholeForms = normalizeForSubstringScan(command);
    if (wholeForms.some((n) => INSTALL_VERB_RE.test(n)) && commandHasPsSynthesis(command)) {
        hits.push({ rule: SYNTHESIZED_INSTALL_RULE, sub: command, normalized: wholeForms[0] });
    }
    return hits;
}

function pathIsUnder(parent, child) {
    const p = nodePath.resolve(parent).toLowerCase();
    const c = nodePath.resolve(child).toLowerCase();
    if (p === c) return true;
    const rel = nodePath.relative(p, c);
    return !!rel && !rel.startsWith("..") && !nodePath.isAbsolute(rel);
}

// v4-r2 hardening (3/3 reviewer consensus on critical regex bypass):
// Replace the previous narrow regex `/\bgit(?:\s+-c\s+\S+)*\s+clone\b/i`
// with an argv-aware tokenizer. The old regex only handled `-c key=val`
// global flags. Any other shape bypassed:
//   - git.exe clone …
//   - git --no-pager clone …
//   - git --git-dir=x clone …
//   - git --bare clone …
//   - C:\path\to\git.exe clone …
//   - gh repo clone … (entirely separate program, never matched)
// In non-clone modes (audit_source / audit_source_council / verify_release)
// any of these would slip past the v4-r1 mode-based deny, drop attacker
// source onto disk, and trip Defender — defeating the headline fix this
// round shipped.

// Strip surrounding quotes, take basename across both / and \, lowercase,
// and drop a trailing `.exe`/`.cmd`/`.bat`/`.com` so `C:\Program Files\Git\bin\git.exe`
// normalizes to `git`.
//
// v4-r2 round-2 hardening: strip ALL quote characters (not just outer)
// to defeat PowerShell quote-fragment concatenation `g"it"` (which PS
// treats as the single string `git`).
function normalizeProgramToken(rawTok) {
    if (!rawTok) return "";
    let t = String(rawTok).trim();
    // Strip ALL quote chars — PS allows `g"it"` to evaluate to `git`
    // and `git"".exe` to evaluate to `git.exe`. Defensive: strip them
    // all so the basename/extension logic sees the underlying program.
    t = t.replace(/["']/g, "");
    const lastSep = Math.max(t.lastIndexOf("/"), t.lastIndexOf("\\"));
    if (lastSep >= 0) t = t.substring(lastSep + 1);
    t = t.toLowerCase();
    t = t.replace(/\.(?:exe|cmd|bat|com|ps1)$/i, "");
    return t;
}

// Split a command line into sub-commands by shell separators (`;`, `&&`,
// `||`, `|`, single `&` for backgrounding, `\r`, `\n`) and unwrap
// command-substitution / process-substitution forms (`$( … )`, `>(…)`,
// `<(…)`, backticks) so their inner content is exposed as a separate
// sub-command. We don't need a perfect shell parser — just enough that
// an attacker can't hide `git clone` inside a chained or substituted
// invocation.
//
// v4-r2 round-2 hardening:
//   - Add single `&` (background operator) as a separator (with
//     lookbehind/lookahead to disambiguate from `&&`).
//   - Add `>(…)` / `<(…)` (bash process substitution) wrappers.
//   - Backticks have TWO valid shell meanings:
//       (a) bash `` `cmd` `` — command substitution (inner content runs
//           as a separate sub-command); replace with " ; " separator so
//           the inner content is exposed for detection.
//       (b) PS `\`` — escape char (so `cl\`one` evaluates to `clone`);
//           stripping backticks entirely un-escapes the literal.
//     We process BOTH interpretations and concatenate the sub-commands
//     so detection runs against either. Either detection is enough to
//     trigger the deny path.
function splitSubCommands(cmd) {
    let raw = String(cmd || "");
    // v4-r2 round-11 (A-R11-1): decode PS 7+ Unicode escapes BEFORE
    // any backtick handling. Otherwise the backtick that's part of
    // `` `u{HHHH} `` gets treated as a command-substitution wrapper
    // (form A) or stripped (form B), separating the `u{HHHH}` from
    // its decoder. Decoding here ensures `n`u{0070}m` becomes `npm`
    // before the form-A/form-B split.
    raw = decodePsUnicodeEscapes(raw);
    // Form A: backticks as bash command-substitution wrappers.
    const formA = raw.replace(/`/g, " ; ");
    // Form B: backticks stripped (PS escape unwrap).
    const subs = unwrapAndSplit(formA);
    if (raw.indexOf("`") !== -1) {
        const formB = raw.replace(/`/g, "");
        for (const s of unwrapAndSplit(formB)) subs.push(s);
    }
    return subs;
}

function unwrapAndSplit(s) {
    // Replace command/process substitution wrappers with separators so
    // their inner content becomes its own sub-command for inspection.
    s = s.replace(/[<>]?\$?\(/g, " ; ").replace(/\)/g, " ; ");
    return s.split(/(?:&&|\|\||;|\|(?!\|)|(?<!&)&(?!&)|\r|\n)+/g)
        .map((p) => p.trim())
        .filter(Boolean);
}

// Quote-aware tokenizer. Splits on whitespace but keeps double- and
// single-quoted spans together so paths like `"C:\Program Files\Git\bin\git.exe"`
// stay one token. Backslash-escapes are not interpreted (Powershell
// doesn't treat backslash as an escape char inside double-quoted strings).
function tokenizeShell(s) {
    const out = [];
    let cur = "";
    let quote = null; // null | '"' | "'"
    for (let i = 0; i < s.length; i++) {
        const ch = s[i];
        if (quote) {
            cur += ch;
            if (ch === quote) {
                quote = null;
            }
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            cur += ch;
            continue;
        }
        if (/\s/.test(ch)) {
            if (cur) { out.push(cur); cur = ""; }
            continue;
        }
        cur += ch;
    }
    if (cur) out.push(cur);
    return out;
}

// v4-r2 round-2 hardening: leading shell-passthrough operators and
// env-var prefixes that put the actual program one (or more) tokens
// later. Examples:
//   `& "git.exe" clone …`        — PS call operator
//   `. git.exe clone …`          — PS dot-source
//   `sudo git clone …`           — POSIX privilege escalation
//   `nohup git clone …`          — POSIX detach
//   `env git clone …`            — POSIX env-clearing
//   `time git clone …`           — POSIX timing
//   `command git clone …`        — POSIX shell-builtin bypass
//   `exec git clone …`           — POSIX exec replacement
//   `GIT_DIR=/x git clone …`     — POSIX env-var prefix
//
// All of these were live-confirmed bypasses of v4-r2 round-1 detection.
const SHELL_PASSTHROUGH_OPERATORS = new Set([
    "&", ".", "\\",
    "sudo", "nice", "time", "env", "setsid", "nohup",
    "command", "exec",
]);
const ENV_PREFIX_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

function stripLeadingOperators(tokens) {
    let i = 0;
    while (i < tokens.length) {
        const t = tokens[i];
        if (SHELL_PASSTHROUGH_OPERATORS.has(t.toLowerCase())) { i++; continue; }
        if (ENV_PREFIX_RE.test(t)) { i++; continue; }
        break;
    }
    return tokens.slice(i);
}

// v4-r2 round-2 hardening: enumeration of git/gh global flags that
// take a separate-token value (no `=`). Without this, `git --git-dir
// /tmp/x clone …` was tokenized as
//   ["git", "--git-dir", "/tmp/x", "clone", …]
// the loop saw `--git-dir` (skip), then `/tmp/x` (no leading `-`,
// break), then tested `/tmp/x === "clone"` → false → returned null →
// the entire clone gate was bypassed. This set gives us the flag/value
// pairs to skip atomically.
const VALUE_TAKING_FLAGS = new Set([
    // git
    "-c", "-C",
    "--git-dir", "--work-tree", "--exec-path",
    "--namespace", "--super-prefix", "--config-env",
    "--list-cmds", "--shallow-file",
    // gh — no global value-taking flags we care about, but the set is
    // shared with gh so add gh-specific value flags here if needed.
]);

// Detect whether a sub-command is performing a git/gh clone. Returns
// `{ program, tail }` (tail = tokens after the `clone` subcommand) when
// it is, or null otherwise.
//
// Recognizes:
//   - `git[.exe] [global-flags] clone …`
//   - `gh[.exe] [global-flags] repo [global-flags] clone …`
//   - All of the above prefixed by leading shell-passthrough operators
//     (`& "git.exe" clone`, `sudo git clone`, `GIT_DIR=/x git clone`).
//
// `git`/`gh` may be a full path (basename is what matters), and may be
// quoted (e.g. `"C:\Program Files\Git\bin\git.exe"`) or use PS
// quote-fragment concatenation (`g"it".exe`).
function detectsClone(sub) {
    let tokens = tokenizeShell(String(sub || "").trim());
    tokens = stripLeadingOperators(tokens);
    if (tokens.length < 2) return null;

    const program = normalizeProgramToken(tokens[0]);
    if (program !== "git" && program !== "gh") return null;

    let i = 1;
    // Skip global flags. For value-taking flags (no `=`), also skip the
    // next token (the value).
    while (i < tokens.length) {
        const t = tokens[i];
        if (!t.startsWith("-")) break;
        if (VALUE_TAKING_FLAGS.has(t) && !t.includes("=") && i + 1 < tokens.length) {
            i += 2;
            continue;
        }
        i += 1;
    }

    if (i >= tokens.length) return null;
    const sub1 = tokens[i].toLowerCase();

    if (program === "git" && sub1 === "clone") {
        return { program: "git", tail: tokens.slice(i + 1) };
    }

    // gh repo clone <repo> [<dir>] — and gh itself may take global flags
    // before `repo`, then more flags before `clone`.
    if (program === "gh" && sub1 === "repo") {
        let j = i + 1;
        while (j < tokens.length && tokens[j].startsWith("-")) j++;
        if (j < tokens.length && tokens[j].toLowerCase() === "clone") {
            return { program: "gh", tail: tokens.slice(j + 1) };
        }
    }

    return null;
}

// v4-r2 round-2 hardening: return ALL clone hits across every
// sub-command, not just the first. Old behavior (first-clone-wins) let
// `<good clone> && git clone <bad-dest>` validate the first clone and
// return allow, leaving the second clone (and any subsequent
// install/exec rules) unchecked.
function detectAllCloneHits(command) {
    const hits = [];
    for (const sub of splitSubCommands(command)) {
        const hit = detectsClone(sub);
        if (hit) {
            // v4-r2 round-8 (A-R8-1, C-R8-2): carry the originating
            // sub-command so validateCloneHit can check hardening and
            // URL-binding against the actual clone invocation, not
            // the full chained command.
            hit.sub = sub;
            hits.push(hit);
        }
    }
    return hits;
}

// v4-r2 round-3 hardening (B-R3-1 high): clone-subcommand flags that
// take separate-token values. The destination is the LAST positional
// (non-flag) token. Without this set we'd treat a flag's value (which
// has no leading `-`) as the destination — letting an attacker spoof
// it with `git clone <bad-dest> --reference <legit-path>`.
const CLONE_VALUE_TAKING_FLAGS = new Set([
    "--reference", "--reference-if-able", "--separate-git-dir",
    "--template", "--origin", "-o", "--branch", "-b", "--depth",
    "--jobs", "-j", "--bundle-uri", "--shallow-since",
    "--shallow-exclude", "--server-option", "--config", "--upload-pack",
    "-u", "--filter", "--recurse-submodules",
]);

// Extract positional (non-flag) tokens from a clone tail, correctly
// skipping flag+value pairs for value-taking clone-subcommand flags.
// Returns the array of positionals; caller picks tail[length-1] as
// the destination (the URL is positionals[0]).
function extractClonePositionals(tail) {
    const positionals = [];
    let i = 0;
    while (i < tail.length) {
        const t = tail[i];
        if (t.startsWith("-")) {
            if (CLONE_VALUE_TAKING_FLAGS.has(t) && !t.includes("=") && i + 1 < tail.length) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        positionals.push(t);
        i += 1;
    }
    return positionals;
}

// v4-r2 round-7 hardening (C-R7-2 high): build-mode raw `git clone`
// must include the safe-clone hardening flags. Otherwise an ordinary
// clone (default checkout + fetch behavior) writes potentially-malicious
// payload bytes to disk before our wrapper invariants apply. The flags
// enforced here mirror what zerotrust_safe_clone applies internally.
//
// REQUIRED: -c protocol.file.allow=never  (disable file:// transport)
//           --no-checkout                  (no working tree, hash-only)
//           --filter=blob:none             (lazy blob fetch — defers code)
//           --no-recurse-submodules        (no sub-payload pull)
//           -c core.symlinks=false         (defang symlink-as-payload)
const REQUIRED_HARDENING_TOKENS = [
    "protocol.file.allow=never",
    "core.symlinks=false",
    "--no-checkout",
    "--filter=blob:none",
    "--no-recurse-submodules",
];

function hasRequiredCloneHardening(rawCommand) {
    const lower = String(rawCommand || "").toLowerCase();
    for (const token of REQUIRED_HARDENING_TOKENS) {
        if (!lower.includes(token.toLowerCase())) return false;
    }
    return true;
}

// Validate a single clone hit against the active audit. Returns
// { decision: "deny", reason } on failure, or null if the hit is valid
// for this mode.
function validateCloneHit(audit, hit, _rawCommandUnusedNow) {
    if (hit.program === "gh") {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: \`gh repo clone\` is not allowed — it bypasses the safe-clone hardening flags (protocol.file.allow=never, --no-checkout, --filter=blob:none). Use zerotrust_safe_clone (preferred) or raw \`git clone\` with the hardening flags applied.`,
        };
    }
    if (!SHARED_modeNeedsClone(audit.mode)) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: \`git clone\` is not allowed in audit mode '${audit.mode}' (v4: only build modes use on-disk clones). Use the API-direct flow (zerotrust_safe_list_tree + zerotrust_safe_fetch_file) instead, OR re-invoke zerotrust_sourcecheck with audit_and_safe_build* / audit_and_full_build* if you need source on disk for a build.`,
        };
    }
    const tail = hit.tail || [];
    // v4-r2 round-3: use flag-aware positional extractor.
    const positionals = extractClonePositionals(tail);
    if (positionals.length < 2) {
        return {
            decision: "deny",
            reason:
                "zerotrust-sourcecheck: `git clone` without an explicit destination would clone into the current working directory. Specify the destination path under build_root.",
        };
    }
    // v4-r2 round-8 (C-R8-1 high): URL-binding check. The first
    // positional is the clone source URL — must match the audit's
    // pinned owner/repo. Otherwise an attacker could clone a different
    // repo into the approved clone path.
    const url = positionals[0].replace(/^["']|["']$/g, "");
    const parsed = parseGithubUrl(url);
    if (!parsed.ok) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: clone URL ${url} could not be parsed as a GitHub URL (rejected: ${parsed.error}).`,
        };
    }
    if (audit.owner && audit.repo) {
        if (parsed.parsed.owner.toLowerCase() !== audit.owner.toLowerCase() ||
            parsed.parsed.repo.toLowerCase() !== audit.repo.toLowerCase()) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: clone URL owner/repo (${parsed.parsed.owner}/${parsed.parsed.repo}) does not match the active audit's pinned target (${audit.owner}/${audit.repo}).`,
            };
        }
    }
    const dest = positionals[positionals.length - 1].replace(/^["']|["']$/g, "");
    let absDest;
    try {
        absDest = nodePath.isAbsolute(dest) ? dest : nodePath.resolve(process.cwd(), dest);
    } catch {
        return {
            decision: "deny",
            reason: "zerotrust-sourcecheck: clone destination could not be resolved to an absolute path.",
        };
    }
    if (!pathIsUnder(audit.buildPath, absDest)) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: clone destination ${absDest} is not under the audit build_root ${audit.buildPath}.`,
        };
    }
    if (!pathIsUnder(audit.expectedClonePath, absDest) && absDest.toLowerCase() !== audit.expectedClonePath.toLowerCase()) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: clone destination ${absDest} doesn't match the planned clone path ${audit.expectedClonePath}.`,
        };
    }
    // v4-r2 round-7 + round-8 (C-R7-2 + A-R8-1 + C-R8-2): require the
    // safe-clone hardening flags. Round-8 fix: check against THIS
    // sub-command's argv tokens (preFlags + tail), not the full chained
    // command — `git clone <url> <dest> ; echo 'protocol.file.allow=...'`
    // would otherwise satisfy the substring check via the echo argument.
    const subTokens = tokenizeShell(String(hit.sub || "").trim()).map((t) =>
        t.replace(/["']/g, "").toLowerCase()
    );
    // Required tokens that must appear in subTokens for the actual clone
    // invocation (not anywhere else in the wider command):
    //   protocol.file.allow=never  (paired with -c)
    //   core.symlinks=false        (paired with -c)
    //   --no-checkout
    //   --filter=blob:none
    //   --no-recurse-submodules
    const REQUIRED_FLAG_TOKENS = [
        "protocol.file.allow=never",
        "core.symlinks=false",
        "--no-checkout",
        "--filter=blob:none",
        "--no-recurse-submodules",
    ];
    const missing = REQUIRED_FLAG_TOKENS.filter((t) => !subTokens.includes(t));
    if (missing.length > 0) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: raw \`git clone\` is missing required hardening flag(s) in the actual clone invocation: ${missing.join(", ")}. Use zerotrust_safe_clone (preferred — applies all flags), or include all of: -c protocol.file.allow=never -c core.symlinks=false --no-checkout --filter=blob:none --no-recurse-submodules.`,
        };
    }
    return null;
}

/**
 * Inspect a tool invocation against the active audit (if any).
 * Returns { decision: "allow" | "deny", reason?: string } — undefined
 * decision means "no opinion" (the SDK will fall through to default permissions).
 *
 * v4-r2 round-3: TWO-LAYER defense.
 *   Layer 1 — substring scan (commandLooksLikeClone / detectInstallInCommand).
 *     High recall, broad coverage. Used to refuse audit-mode clones
 *     and audit-mode installs regardless of how cleverly the attacker
 *     spelled the command.
 *   Layer 2 — tokenizer (detectAllCloneHits / validateCloneHit).
 *     Used in build modes for destination-path validation. If layer-2
 *     misses (because of an obscure bypass shape), the agent's clone
 *     proceeds with whatever path it specified — which in build modes
 *     the user has already authorized as the planned clone path.
 */
export function inspectToolCall({ sessionId, toolName, toolArgs }) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return { decision: undefined };
    if (!SHELL_TOOLS.has(toolName)) return { decision: undefined };

    const command = String(toolArgs?.command || "").trim();
    if (!command) return { decision: undefined };

    // ---- Layer 1: substring-based clone denial ----
    // gh repo clone always denied (bypasses safe-clone hardening flags).
    // git clone in non-clone modes always denied (no on-disk clone needed
    // for API-direct audit modes).
    const looksLikeClone = commandLooksLikeClone(command);
    if (looksLikeClone) {
        if (looksLikeClone.kind === "gh") {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: \`gh repo clone\` is not allowed — it bypasses the safe-clone hardening flags. Use zerotrust_safe_clone (preferred) or raw \`git clone\` with the hardening flags applied.`,
            };
        }
        if (!SHARED_modeNeedsClone(audit.mode)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: \`git clone\` is not allowed in audit mode '${audit.mode}' (v4: only build modes use on-disk clones). Use the API-direct flow (zerotrust_safe_list_tree + zerotrust_safe_fetch_file) instead, OR re-invoke zerotrust_sourcecheck with audit_and_safe_build* / audit_and_full_build* if you need source on disk for a build.`,
            };
        }
        // Audit needs a clone — fall through to layer-2 path validation.
    }

    // ---- Layer 2: tokenizer-based clone destination validation (build modes only) ----
    let cloneAllowed = false;
    if (looksLikeClone && SHARED_modeNeedsClone(audit.mode)) {
        const cloneHits = detectAllCloneHits(command);
        for (const hit of cloneHits) {
            const denial = validateCloneHit(audit, hit, command);
            if (denial) return denial;
            cloneAllowed = true;
        }
        // If layer-1 said "looks like clone" but layer-2 found no
        // structured hits (because of an obscure shell-syntax form),
        // we DENY in build mode too — the agent should be using
        // zerotrust_safe_clone, not raw shell trickery.
        if (!cloneAllowed) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: clone-like command detected but the destination/structure could not be validated. Use the zerotrust_safe_clone wrapper, which applies the hardening flags and validates the destination path.`,
            };
        }
    }

    // ---- Layer 1: substring-based install denial ----
    // v4-r2 round-6 (A-R6-1): validate ALL install hits, not just
    // the first. `npm install --ignore-scripts && pnpm dlx evil`
    // bypassed first-rule-wins because the npm rule was satisfied
    // and the chained pnpm dlx was never re-checked.
    const installHits = detectAllInstallHits(command);
    for (const hit of installHits) {
        // Outside any build mode → no installs at all.
        if (!BUILD_MODES.has(audit.mode)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: package-manager install detected (${hit.rule.ecosystem}) but the audit mode '${audit.mode}' does not include a build step. Re-run with mode='audit_and_safe_build' or 'audit_and_full_build' to permit installation.`,
            };
        }
        // In safe-build (not full-build) → must have the safe flag in
        // THIS specific sub-command (per-sub-command isolation).
        if (!FULL_BUILD_MODES.has(audit.mode)) {
            if (!hit.rule.safeChecker(hit.sub)) {
                return {
                    decision: "deny",
                    reason: `zerotrust-sourcecheck: ${hit.rule.ecosystem} install without ${hit.rule.flagHint}. The audit mode '${audit.mode}' requires this safe-flag (in the SAME sub-command as the install) to neutralize lifecycle scripts. Re-run with mode='audit_and_full_build' if you intentionally want lifecycle scripts to execute.`,
                };
            }
        }
    }

    // v4-r2 round-6 (C-R6-2 partial): in audit-only modes, deny ANY
    // command containing PS programmatic name-synthesis sigils. There
    // is no legitimate audit-time use of [char] arithmetic / -join /
    // -f format / & $var indirection / iex — these are exclusively
    // attacker-evasion patterns. False positives in audit mode are
    // acceptable per the round-3 design philosophy.
    if (!BUILD_MODES.has(audit.mode) && commandHasPsSynthesis(command)) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: command uses PowerShell programmatic name-synthesis ([char] arithmetic, -join, -f format, & \$var indirection, Invoke-Expression, etc.) which has no legitimate use during an audit and bypasses program-name detection. Refused.`,
        };
    }

    // ---- 2.5. GUI-launch and disk-write enforcement (any audit mode) ----
    // Deny commands that open files with their default handler (the
    // Notepad-pop-up bug) or download bytes to disk (sub-agents were
    // saving source files to scratch paths instead of using the
    // API-direct safe_fetch_file wrapper).
    for (const p of GUI_OPEN_PATTERNS) {
        if (p.re.test(command)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: \`${p.name}\` refused during audit mode '${audit.mode}'. Default-handler file openers and GUI editor launchers can produce surprising side effects (Notepad pop-ups, IDE windows) and are not needed during an audit. Use the read tools (view/grep/glob or zerotrust_safe_fetch_file) instead.`,
            };
        }
    }
    for (const p of DISK_DOWNLOAD_PATTERNS) {
        if (p.re.test(command)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: \`${p.name}\` refused during audit mode '${audit.mode}' — disk-writing downloads violate the API-direct contract and leave scratch source files behind. Use zerotrust_safe_fetch_file for repo content or web_fetch for external metadata.`,
            };
        }
    }

    // ---- 3. Execution from inside build_root ----
    for (const re of EXECUTION_PATTERNS) {
        if (re.test(command)) {
            const paths = extractPathTokens(command);
            for (const p of paths) {
                if (pathIsUnder(audit.buildPath, p)) {
                    return {
                        decision: "deny",
                        reason: `zerotrust-sourcecheck: refusing to execute file under audit build_root via a process-launch cmdlet. Audited binaries are quarantined and must not be executed by the audit itself.`,
                    };
                }
            }
        }
    }

    // ---- 4. Direct execution of `.exe`/`.msi`/`.bat`/`.cmd`/`.ps1` paths
    //       that resolve under build_root ----
    const execExtRe = /(?:^|[\s&;|`])["']?([A-Za-z]:[\\\/][^\s"';|&`]*\.(?:exe|msi|bat|cmd|ps1|vbs|dll))["']?/gi;
    let m;
    while ((m = execExtRe.exec(command)) !== null) {
        const candidate = m[1];
        if (pathIsUnder(audit.buildPath, candidate)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: refusing to invoke ${candidate} — executables under build_root must not be run as part of the audit.`,
            };
        }
    }

    if (cloneAllowed) return { decision: "allow" };
    return { decision: undefined };
}

/**
 * Hook adapter: takes an SDK onPreToolUse `input` + `invocation` and
 * returns the SDK's expected output shape.
 */
export function preToolUseHook(input, invocation) {
    const result = inspectToolCall({
        sessionId: invocation?.sessionId,
        toolName: input?.toolName,
        toolArgs: input?.toolArgs,
    });
    if (result.decision === undefined) return undefined;
    if (result.decision === "deny") {
        return {
            permissionDecision: "deny",
            permissionDecisionReason: result.reason,
        };
    }
    if (result.decision === "allow") {
        // We deliberately don't override allow-decisions with permissionDecision:"allow"
        // because that would bypass other extensions' deny checks. Returning
        // undefined lets the default permission logic proceed.
        return undefined;
    }
    return undefined;
}

// Exposed for tests.
export const __internals = {
    activeAudits,
    AUDIT_TTL_MS_BY_MODE,
    AUDIT_TTL_MS_DEFAULT,
    ttlForMode,
    recentlyExpired,
    BUILD_MODES,
    FULL_BUILD_MODES,
    INSTALL_RULES,
    EXECUTION_PATTERNS,
    extractPathTokens,
    pathIsUnder,
    recordResolvedClonePath,
};
