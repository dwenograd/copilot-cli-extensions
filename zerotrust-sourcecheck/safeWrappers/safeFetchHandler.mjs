// safeWrappers/safeFetchHandler.mjs — zerotrust_safe_fetch_file tool.
//
// API-direct fetch of a single file's contents. Returns the bytes (text or
// base64) IN MEMORY — never writes to disk. Refuses oversized files
// (returns sha256 + size + preview instead).
//
// Trust model:
// - Owner/repo/sha/path validated against pure regexes (no traversal).
// - Cross-checks active audit's pinned owner/repo/ref/sha.
// - Per-fetch byte cap defends against accidental gigabyte-file pulls
//   (an oversized binary returns metadata only).

import { fetchFile } from "./apiClient.mjs";
import { getTrustedAuditContext } from "../enforcement.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";

export async function safeFetchFileHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;

    if (typeof args.owner !== "string" || typeof args.repo !== "string") {
        return failure("owner and repo are required strings");
    }
    if (typeof args.sha !== "string") {
        return failure("sha is required (40-char hex)");
    }
    if (typeof args.path !== "string") {
        return failure("path is required (forward-slash repo-relative path)");
    }
    const owner = args.owner;
    const repo = args.repo;
    const sha = args.sha;
    const path = args.path;

    // Cross-check against active audit's pinned owner/repo.
    const ctx = getTrustedAuditContext({ sessionId, args, defaultBuildRoot: DEFAULT_BUILD_ROOT });
    if (!ctx.ok) return failure(ctx.error);

    // Local-source mode refusal (clearer than the existing
    // owner/repo-mismatch gate below). A local-source audit reads
    // bytes already on disk — there's no API fetch to authorize.
    if (ctx.hasActiveAudit && ctx.localPath) {
        return failure(`safe_fetch_file refused: active audit is local-source mode (target: ${ctx.localPath}). API-direct file fetch applies to URL-driven audits only. Use \`view\` on a path under ${ctx.localPath} to read a local file.`);
    }

    // v4-r2 round-13 (C-R13-1 high): if sessionId is supplied but no
    // active audit (TTL expired or sourcecheck never invoked), REFUSE.
    // Mirrors the same guard in cloneWrapper.
    if (sessionId && !ctx.hasActiveAudit) {
        return failure(`safe_fetch_file refused: no active audit for this session (TTL expired or zerotrust_sourcecheck not invoked). Re-invoke zerotrust_sourcecheck before any wrapper call.`);
    }
    if (ctx.hasActiveAudit && ctx.owner && ctx.repo) {
        if (owner.toLowerCase() !== ctx.owner || repo.toLowerCase() !== ctx.repo) {
            return failure(`safe_fetch_file refused: owner/repo (${owner}/${repo}) does not match the active audit's pinned target (${ctx.owner}/${ctx.repo}).`);
        }
    }
    // v4-r2 round-5/round-6 (C-R5-2 + A-R6-2 high): SHA-binding gate.
    // The audit must have pinned a specific commit SHA before any
    // fetch is allowed — pin happens via safe_list_tree (or safe_clone
    // in build modes). Without this gate, a malicious file in the
    // audited tree could prompt the agent to fetch from an arbitrary
    // (e.g. older, clean) commit and the report would cite content
    // that was never part of the pinned target.
    if (ctx.hasActiveAudit) {
        if (!ctx.resolvedSha) {
            return failure(`safe_fetch_file refused: no resolved commit SHA pinned for the audit. Call zerotrust_safe_list_tree first (it pins the SHA from the audit's ref) before any fetches.`);
        }
        if (sha.toLowerCase() !== ctx.resolvedSha.toLowerCase()) {
            return failure(`safe_fetch_file refused: sha (${sha}) does not match the audit's pinned commit (${ctx.resolvedSha}). To audit a different commit, re-invoke zerotrust_sourcecheck with the new ref.`);
        }
    }

    // Optional per-call cap overrides (capped at hardcoded ceilings).
    const HARD_CEILING_BYTES = 50 * 1024 * 1024;     // 50 MB absolute
    const HARD_CEILING_TEXT_INLINE = 1024 * 1024;    // 1 MB max inline text
    const opts = {};
    if (typeof args.max_bytes === "number" && Number.isFinite(args.max_bytes) && args.max_bytes > 0) {
        opts.maxBytes = Math.min(args.max_bytes, HARD_CEILING_BYTES);
    }
    if (typeof args.max_text_bytes === "number" && Number.isFinite(args.max_text_bytes) && args.max_text_bytes > 0) {
        opts.maxTextBytes = Math.min(args.max_text_bytes, HARD_CEILING_TEXT_INLINE);
    }

    let result;
    try {
        result = fetchFile(owner, repo, sha, path, opts);
    } catch (err) {
        return failure(`fetch_file failed: ${err.message}`);
    }

    return success(result);
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
