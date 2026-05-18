// safeWrappers/safeListTreeHandler.mjs — zerotrust_safe_list_tree tool.
//
// API-direct alternative to safe_clone for the tree-enumeration step of an
// audit. Calls `gh api repos/X/Y/git/trees/SHA?recursive=1` and returns the
// tree in memory. NO files are written to disk.
//
// Trust model:
// - Validates owner/repo against the same regexes urlParser uses.
// - Resolves ref → SHA before listing (so the agent can pin to a commit).
// - Refuses if active audit pins owner/repo and the args don't match.

import { listTree, resolveRefToSha } from "./apiClient.mjs";
import { parseGithubUrl } from "../urlParser.mjs";
import { getTrustedAuditContext, recordResolvedSha } from "../enforcement.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";

export async function safeListTreeHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;

    // Accept either { url } or { owner, repo, ref? }
    let owner, repo, ref, refType;
    if (typeof args.url === "string") {
        const parsed = parseGithubUrl(args.url);
        if (!parsed.ok) return failure(`URL rejected: ${parsed.error}`);
        owner = parsed.parsed.owner;
        repo = parsed.parsed.repo;
        ref = args.ref || parsed.parsed.ref || null;
        refType = parsed.parsed.refType || null;
    } else {
        if (typeof args.owner !== "string" || typeof args.repo !== "string") {
            return failure("must provide either { url } or { owner, repo }");
        }
        owner = args.owner;
        repo = args.repo;
        ref = args.ref || null;
        refType = args.refType || null;
    }

    // v4-r2 round-10 (C-R10-2): always inherit refType from the audit
    // context if not explicitly provided. Without this, a PR-pinned
    // audit (refType: "pr_head") would lose its refType when the agent
    // calls safe_list_tree without specifying refType, causing
    // resolveRefToSha to use the wrong refspec form.
    // Cross-check against active audit's pinned owner/repo/ref.
    const ctx = getTrustedAuditContext({ sessionId, args, defaultBuildRoot: DEFAULT_BUILD_ROOT });
    if (!ctx.ok) return failure(ctx.error);

    // Local-source mode refusal (clearer than the generic
    // "owner/repo doesn't match" gate below, which assumes the audit
    // has owner/repo pinned). A local-source audit reads on-disk
    // bytes — there's no GitHub API call to authorize.
    if (ctx.hasActiveAudit && ctx.localPath) {
        return failure(`safe_list_tree refused: active audit is local-source mode (target: ${ctx.localPath}). API-direct tree listing applies to URL-driven audits only. Use \`glob\` against ${ctx.localPath} to enumerate files.`);
    }

    // v4-r2 round-13 (C-R13-1 high): if sessionId is supplied but no
    // active audit (TTL expired or sourcecheck never invoked), REFUSE.
    // Otherwise an expired audit silently falls through to the no-binding
    // path and the agent could list a different owner/repo/ref under the
    // operator's `gh` auth. Mirrors the same guard in cloneWrapper.
    if (sessionId && !ctx.hasActiveAudit) {
        return failure(`safe_list_tree refused: no active audit for this session (TTL expired or zerotrust_sourcecheck not invoked). Re-invoke zerotrust_sourcecheck before any wrapper call.`);
    }
    if (ctx.hasActiveAudit && ctx.owner && ctx.repo) {
        if (owner.toLowerCase() !== ctx.owner || repo.toLowerCase() !== ctx.repo) {
            return failure(`safe_list_tree refused: owner/repo (${owner}/${repo}) does not match the active audit's pinned target (${ctx.owner}/${ctx.repo}).`);
        }
    }
    if (ctx.hasActiveAudit && ctx.ref) {
        if (ref && ref !== ctx.ref) {
            return failure(`safe_list_tree refused: ref (${ref}) does not match the active audit's pinned ref (${ctx.ref}).`);
        }
        if (!ref) {
            ref = ctx.ref;
        }
    }
    // v4-r2 round-10 (C-R10-2): always inherit refType from the audit
    // context if not explicitly provided. Without this, a PR-pinned
    // audit (refType: "pr_head") would lose its refType when the agent
    // calls safe_list_tree without specifying refType, causing
    // resolveRefToSha to use the wrong refspec form.
    //
    // v4-r2 round-11 (C-R11-1 high): also enforce refType MATCH — if
    // the audit pinned a refType (e.g. release_tag) and the caller
    // supplies a different one (e.g. branch_or_tag), refuse. Without
    // this, an audit on /releases/tag/v1 could be re-resolved by the
    // agent against /tree/v1 (heads namespace) and return a different
    // commit while the audit identity stays pinned to the tag.
    if (ctx.hasActiveAudit && ctx.refType) {
        if (refType && refType !== ctx.refType) {
            return failure(`safe_list_tree refused: refType (${refType}) does not match the active audit's pinned refType (${ctx.refType}). Activate a new audit if you want a different ref namespace.`);
        }
        if (!refType) {
            refType = ctx.refType;
        }
    }

    let sha;
    try {
        sha = resolveRefToSha(owner, repo, ref, refType);
    } catch (err) {
        return failure(`SHA resolution failed: ${err.message}`);
    }

    // v4-r2 round-9 (C-R9-2 high): if the audit already has a pinned
    // resolvedSha (from a prior safe_list_tree or safe_clone call),
    // refuse to list a tree for any other SHA. Without this, a bare
    // repo-URL audit (no /tree/branch suffix → no ctx.ref) would let
    // a subsequent call request a different ref, returning a tree from
    // a different commit while the audit's identity stays pinned to
    // the first.
    if (ctx.hasActiveAudit && ctx.resolvedSha) {
        if (sha.toLowerCase() !== ctx.resolvedSha.toLowerCase()) {
            return failure(`safe_list_tree refused: resolved SHA (${sha}) does not match the audit's previously-pinned commit (${ctx.resolvedSha}). Re-invoke zerotrust_sourcecheck with the new ref to audit a different commit.`);
        }
    }

    let result;
    try {
        result = listTree(owner, repo, sha);
    } catch (err) {
        return failure(`tree listing failed: ${err.message}`);
    }

    // v4-r2 round-5 (C-R5-2): pin the audit to this resolved SHA so
    // subsequent safe_fetch_file calls must use the same commit.
    // recordResolvedSha is first-write-wins; round-9 also explicitly
    // checks the return value so a silent pin-conflict can't slip
    // through (the gate above also catches it before we get here, but
    // belt + suspenders).
    if (sessionId) {
        try {
            const pinOk = recordResolvedSha(sessionId, result.sha);
            if (pinOk === false && ctx.hasActiveAudit) {
                return failure(`safe_list_tree refused: resolved SHA conflicts with the audit's previously-pinned commit. This indicates a race or repeated call with a different ref.`);
            }
        } catch { /* best-effort — non-fatal */ }
    }

    return success({
        owner,
        repo,
        sha: result.sha,
        truncated: result.truncated,
        entriesTruncated: !!result.entriesTruncated,
        totalEntryCount: typeof result.totalEntryCount === "number"
            ? result.totalEntryCount
            : result.entries.length,
        entries: result.entries,
        entryCount: result.entries.length,
        coverageComplete: !result.truncated && !result.entriesTruncated,
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
