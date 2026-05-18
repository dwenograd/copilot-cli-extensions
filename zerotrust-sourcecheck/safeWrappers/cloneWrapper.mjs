// safeWrappers/cloneWrapper.mjs — zerotrust_safe_clone tool implementation.
//
// Substitutional safety: agent calls this tool instead of running raw
// `git clone` via powershell. The wrapper itself runs git with the
// hardened security flags hardcoded — agent has no way to omit them.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import nodePath from "node:path";

import { parseGithubUrl, buildClonePath, validateRef } from "../urlParser.mjs";
import { purgeStaleClones, getPurgeHours } from "./autoPurge.mjs";
import { getTrustedAuditContext, recordResolvedClonePath, recordResolvedSha } from "../enforcement.mjs";
import { modeNeedsClone } from "../modes.mjs";
import { resolveTrustedProgram } from "./programResolver.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";

// Cross-platform "discard hooks" path. On Windows, `NUL` is the magic
// null device. On POSIX, `/dev/null` is. Using the wrong one means git
// would search a directory literally named "NUL" (or "/dev/null") for
// hook scripts — on Linux/macOS that could be subverted if a sub-agent
// or repo file created a `NUL/` dir with executable scripts at the
// right cwd. Switch on platform.
const NULL_HOOKS_PATH = process.platform === "win32" ? "NUL" : "/dev/null";

const HARDENED_GIT_FLAGS = [
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "core.symlinks=false",
    "-c", "core.fsmonitor=false",
    "-c", `core.hooksPath=${NULL_HOOKS_PATH}`,
    "-c", "core.longpaths=true",
];

const HARDENED_CLONE_FLAGS = [
    "--no-recurse-submodules",
    "--no-tags",
    "--filter=blob:none",
    "--no-checkout",
];

const SHA_RE = /^[0-9a-fA-F]{40}$/;

function looksLikeSha(s) {
    return typeof s === "string" && SHA_RE.test(s);
}

/**
 * Resolve a ref to a SHA via `git ls-remote`.
 *
 * Round-10 hardening (gpt-5.5 R10 F2): for known ref types, use the exact
 * refspec form so we don't get the wrong commit due to:
 *   - branch/tag name collisions (a branch and tag with the same name)
 *   - annotated tags returning the tag-object SHA before the peeled commit
 *
 * Refspec rules:
 *   - "release_tag" → `refs/tags/<ref>` AND prefer `<ref>^{}` (peeled commit
 *     for annotated tags) when present.
 *   - "branch_or_tag" → `refs/heads/<ref>` first, fall back to
 *     `refs/tags/<ref>` (with peel preference). This matches `git clone`'s
 *     priority where branches win on collision.
 *   - "pr_head" → already in the form `refs/pull/<n>/head` from urlParser,
 *     pass through as-is.
 *   - "commit" / SHA → return directly without ls-remote.
 *   - null / unknown → fall back to bare ref (legacy behavior); HEAD if no ref.
 */
function resolveRefViaLsRemote(canonicalUrl, ref, refType, gitPath) {
    if (looksLikeSha(ref)) return ref;
    const refToResolve = ref || "HEAD";

    // Build the candidate refspec list based on refType.
    let candidates;
    switch (refType) {
        case "release_tag":
            candidates = [`refs/tags/${refToResolve}`];
            break;
        case "branch_or_tag":
            candidates = [`refs/heads/${refToResolve}`, `refs/tags/${refToResolve}`];
            break;
        case "pr_head":
            candidates = [refToResolve]; // already `refs/pull/<n>/head`
            break;
        default:
            candidates = [refToResolve];
            break;
    }

    let lastError;
    for (const candidate of candidates) {
        let stdout;
        try {
            stdout = execFileSync(
                gitPath,
                ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "ls-remote", "--exit-code", canonicalUrl, candidate, `${candidate}^{}`],
                { encoding: "utf-8", windowsHide: true, timeout: 60_000, env: { ...process.env, GIT_TERMINAL_PROMPT: "0" } },
            );
        } catch (err) {
            lastError = err;
            continue; // try next candidate
        }
        // Prefer the peeled-commit line (`<candidate>^{}`) if it exists —
        // for annotated tags, `^{}` resolves to the actual commit.
        const lines = String(stdout).split(/\r?\n/).filter((l) => l.trim().length > 0);
        const peeledLine = lines.find((l) => l.endsWith(`${candidate}^{}`));
        const directLine = lines.find((l) => l.endsWith(candidate));
        const winner = peeledLine || directLine;
        if (!winner) {
            lastError = new Error(`git ls-remote returned no matching ref for ${candidate}`);
            continue;
        }
        const sha = winner.split(/\s+/)[0];
        if (!looksLikeSha(sha)) {
            lastError = new Error(`git ls-remote returned non-SHA: ${JSON.stringify(sha)}`);
            continue;
        }
        return sha;
    }
    throw new Error(`git ls-remote failed for ${canonicalUrl} ref=${refToResolve}: ${lastError?.stderr || lastError?.message || "no candidates resolved"}`);
}

function ensureDirExists(p) {
    if (!existsSync(p)) mkdirSync(p, { recursive: true });
}

function doHardenedClone({ canonicalUrl, sha, clonePath, gitPath }) {
    if (existsSync(clonePath)) {
        throw new Error(`clone path already exists: ${clonePath}. Refusing to overwrite. Delete it manually if you intended to re-clone.`);
    }
    ensureDirExists(nodePath.dirname(clonePath));
    const cloneArgs = [
        ...HARDENED_GIT_FLAGS,
        "clone",
        ...HARDENED_CLONE_FLAGS,
        canonicalUrl,
        clonePath,
    ];
    execFileSync(gitPath, cloneArgs, {
        encoding: "utf-8",
        windowsHide: true,
        timeout: 600_000,
        env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_LFS_SKIP_SMUDGE: "1" },
    });
    execFileSync(
        gitPath,
        ["-C", clonePath, ...HARDENED_GIT_FLAGS, "checkout", sha],
        {
            encoding: "utf-8",
            windowsHide: true,
            timeout: 300_000,
            env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_LFS_SKIP_SMUDGE: "1" },
        },
    );
}

export async function safeCloneHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;

    if (typeof args.url !== "string") {
        return failure("url is required (string)");
    }
    const parsed = parseGithubUrl(args.url);
    if (!parsed.ok) {
        return failure(`URL rejected: ${parsed.error}`);
    }
    const { owner, repo, canonicalUrl } = parsed.parsed;

    // Resolve trusted context up front so we can cross-check the URL
    // against the active audit's owner/repo BEFORE doing any network I/O.
    const ctx = getTrustedAuditContext({ sessionId, args, defaultBuildRoot: DEFAULT_BUILD_ROOT });
    if (!ctx.ok) return failure(ctx.error);

    // Local-source mode refusal (clearer error than the generic
    // modeNeedsClone branch below). An audit in audit_local_source*
    // mode has no GitHub URL pinned — cloning anything would attach
    // a clone to the wrong audit identity.
    if (ctx.hasActiveAudit && ctx.localPath) {
        return failure(`safe_clone refused: active audit is local-source mode (target: ${ctx.localPath}). Clone operations apply to URL-driven audits only. Use view/grep/glob on the local path; the role agents already have those.`);
    }

    // Round-7 hardening (gpt-5.5 R7 F2) + v4: only build modes need a
    // clone. Refuse if the active audit's mode doesn't need a clone.
    if (ctx.hasActiveAudit && ctx.mode && !modeNeedsClone(ctx.mode)) {
        return failure(`safe_clone refused: active audit mode '${ctx.mode}' does not need a clone (only build modes use on-disk clones in v4; pure audit modes operate via API-direct using zerotrust_safe_list_tree + zerotrust_safe_fetch_file). To run a build, re-invoke zerotrust_sourcecheck with audit_and_safe_build* / audit_and_full_build* + the required ack flags.`);
    }

    // v4-r1 hardening (gpt-5.5 R1 F1): when sessionId is supplied (production
    // agents always have one) but no active audit exists (TTL expired or
    // zerotrust_sourcecheck not invoked), REFUSE the clone. Without this
    // guard, an audit-mode session whose TTL elapsed mid-audit would let
    // safe_clone proceed silently — circumventing the "audit modes never
    // clone" promise. Mirrors the install/build wrapper's same guard.
    if (sessionId && !ctx.hasActiveAudit) {
        return failure(`safe_clone refused: no active audit for this session (TTL expired or zerotrust_sourcecheck not invoked). Re-invoke zerotrust_sourcecheck before any wrapper call.`);
    }

    // Round-5 hardening (gpt-5.5 R5 F1): an active audit pins owner/repo;
    // safe_clone must refuse a different repo so an agent can't activate an
    // audit for repo A and then clone repo B under audit-A's mode + ack
    // flags + (later) audit-A's council outcome.
    if (ctx.hasActiveAudit && ctx.owner && ctx.repo) {
        if (owner.toLowerCase() !== ctx.owner || repo.toLowerCase() !== ctx.repo) {
            return failure(`safe_clone refused: URL owner/repo (${owner}/${repo}) does not match the active audit's pinned target (${ctx.owner}/${ctx.repo}). Activate a new audit for the new repo.`);
        }
    }

    // Round-8 hardening (gpt-5.5 R8 F1): if the active audit pinned a
    // specific ref (the user invoked sourcecheck with a /tree/<ref> URL,
    // /commit/<sha> URL, /pull/<n> URL, or /releases/tag/<tag> URL),
    // safe_clone must refuse a different ref. Without this, an audit
    // pinned to v1.0 could be tricked into cloning v2.0.
    // Round-8 hardening (gpt-5.5 R8 F1) + round-9 (gpt-5.5 R9 F1): if the
    // active audit pinned a specific ref, safe_clone must use THAT ref.
    // - If args.ref is supplied, it must equal the pinned ref.
    // - If args.ref is OMITTED (bare repo URL), default to the pinned ref
    //   so we don't silently fall through to HEAD (the previous version
    //   only checked when refToUse was non-null, which let bare URLs
    //   bypass the pin and clone HEAD).
    let refToUse = args.ref || parsed.parsed.ref || null;
    if (ctx.hasActiveAudit && ctx.ref) {
        if (refToUse && refToUse !== ctx.ref) {
            return failure(`safe_clone refused: ref (${refToUse}) does not match the active audit's pinned ref (${ctx.ref}). Activate a new audit for the new ref.`);
        }
        if (!refToUse) {
            // Use the audit's pinned ref so we don't silently clone HEAD
            // when the audit was activated for a specific ref.
            refToUse = ctx.ref;
        }
    }

    if (refToUse !== null) {
        if (typeof refToUse !== "string") return failure("ref must be a string when provided");
        const refError = validateRef(refToUse);
        if (refError) return failure(`ref rejected: ${refError}`);
    }

    // v4-r2 round-10 (B-R10-1 high): resolve `git` through
    // resolveTrustedProgram (mirrors apiClient/install/build wrappers).
    // Forbids any candidate under build_root so an attacker can't plant
    // git.exe / git.cmd in the audit sandbox to win OS search order.
    const buildRootForCheck = ctx.buildRoot;
    const gitPath = resolveTrustedProgram("git", { forbiddenRoots: [buildRootForCheck] });
    if (!gitPath) {
        return failure(`safe_clone refused: could not resolve a trusted \`git\` executable on PATH outside build_root. Install git or check PATH.`);
    }

    let resolvedSha;
    try {
        // Pass the refType (from URL parsing OR from active audit) so
        // resolveRefViaLsRemote uses the precise refspec form.
        const refTypeToUse = ctx.refType || parsed.parsed.refType || null;
        resolvedSha = resolveRefViaLsRemote(canonicalUrl, refToUse, refTypeToUse, gitPath);
    } catch (err) {
        return failure(`SHA resolution failed: ${err.message}`);
    }

    // v4-r2 round-12 (C-R12-1 high): if the audit already has a pinned
    // resolvedSha (from a prior safe_list_tree or safe_clone call),
    // refuse to clone any other SHA. Without this, a bare-repo-URL
    // build audit (no pinned ref) could be re-cloned to a different
    // commit; safe_build then runs on the second commit while the
    // audit identity stays pinned to the first. Mirrors the same gate
    // in safeListTreeHandler.
    if (ctx.hasActiveAudit && ctx.resolvedSha) {
        if (resolvedSha.toLowerCase() !== ctx.resolvedSha.toLowerCase()) {
            return failure(`safe_clone refused: resolved SHA (${resolvedSha}) does not match the audit's previously-pinned commit (${ctx.resolvedSha}). Re-invoke zerotrust_sourcecheck with the new ref to clone a different commit.`);
        }
    }

    // Resolve the trusted build_root from ctx (already computed above).
    const buildRoot = ctx.buildRoot;
    if (!nodePath.isAbsolute(buildRoot)) {
        return failure(`build_root must be absolute, got ${JSON.stringify(buildRoot)}`);
    }

    let clonePath;
    try {
        clonePath = buildClonePath(buildRoot, owner, repo, resolvedSha.slice(0, 7));
    } catch (err) {
        return failure(`path construction failed: ${err.message}`);
    }

    // Auto-purge stale clones from build_root before adding a new one.
    // Defends against forgotten audits / crashed sessions / Defender-quarantine
    // residue. Disabled when ZEROTRUST_AUTO_PURGE_HOURS=0.
    let purgeSummary = null;
    try {
        const hours = getPurgeHours();
        if (hours > 0) {
            const result = purgeStaleClones({
                buildRoot,
                hoursThreshold: hours,
                exclude: [nodePath.basename(clonePath)],
            });
            if (result.purged.length > 0 || result.failed.length > 0) {
                purgeSummary = {
                    hoursThreshold: hours,
                    purgedCount: result.purged.length,
                    failedCount: result.failed.length,
                    purgedBasenames: result.purged.map((e) => e.basename),
                };
            }
        }
    } catch {
        // Auto-purge MUST NOT block the actual clone — best-effort only.
        purgeSummary = { error: "auto-purge encountered an error; clone proceeded" };
    }

    try {
        doHardenedClone({ canonicalUrl, sha: resolvedSha, clonePath, gitPath });
    } catch (err) {
        const stderr = err.stderr ? String(err.stderr) : "";
        return failure(`hardened clone failed: ${err.message}${stderr ? `\nstderr: ${stderr}` : ""}`);
    }

    // Round-4 hardening (gpt-5.5 F2): bind the resolved clone path to the
    // active audit so subsequent install/build/cleanup/finalize_report calls
    // can cross-check that they're operating on THIS audit's clone, not a
    // sibling repo dropped in the same sandbox by a different session.
    if (sessionId) {
        try {
            recordResolvedClonePath(sessionId, clonePath);
        } catch {
            // best-effort — wrapper still succeeds even if recording fails
        }
        // v4-r2 round-6 (A-R6-2 high): also pin the audit's SHA so any
        // subsequent safe_fetch_file in build mode is constrained to
        // the same commit we just cloned. Mirrors what safe_list_tree
        // does for API-direct modes.
        // v4-r2 round-12 (C-R12-1): check the boolean return of
        // recordResolvedSha — first-write-wins should only return false
        // on a SHA conflict, which we already gated above; this is a
        // belt-and-suspenders re-check.
        try {
            const pinOk = recordResolvedSha(sessionId, resolvedSha);
            if (pinOk === false && ctx.hasActiveAudit) {
                return failure(`safe_clone refused: resolved SHA conflicts with the audit's previously-pinned commit (race or repeated clone with different ref).`);
            }
        } catch {
            // best-effort
        }
    }

    return success({
        clonePath,
        sha: resolvedSha,
        canonicalUrl,
        ...(purgeSummary ? { autoPurge: purgeSummary } : {}),
    });
}

function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, ...data }, null, 2),
        resultType: "success",
    };
}

function failure(message) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, error: message }, null, 2),
        resultType: "failure",
    };
}

export const __internals = {
    HARDENED_GIT_FLAGS,
    HARDENED_CLONE_FLAGS,
    looksLikeSha,
    resolveRefViaLsRemote,
};
