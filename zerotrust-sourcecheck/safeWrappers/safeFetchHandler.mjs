// safeWrappers/safeFetchHandler.mjs — zerotrust_safe_fetch_file tool.
//
// API-direct fetch of one file. Returns bounded text or binary metadata through
// the tool result and performs no source-file write. Runtime logging/spill is
// outside this module. Oversized files return metadata and sometimes a preview.
//
// Trust model:
// - Owner/repo/sha/path validated against pure regexes (no traversal).
// - Cross-checks active audit's pinned owner/repo/ref/sha.
// - Per-fetch byte cap defends against accidental gigabyte-file pulls
//   (over-ceiling results remain explicit mandatory-coverage gaps).

import { fetchFile } from "./apiClient.mjs";
import {
    getAcquisitionCoverageState,
    getAnalysisIndexState,
    getAnalysisIndexSnapshot,
    getTreeEnumerationState,
    getTrustedAuditContext,
    maybeAdvanceAnalysisPrepared,
    mutateAcquisitionCoverageState,
    mutateAnalysisIndexState,
} from "../enforcement.mjs";
import { modeUsesCouncil } from "../modes.mjs";
import { extractFactsFromText } from "../analysis/extractFacts.mjs";
import { listIndexedFacts, recordIndexedFile } from "../analysis/indexState.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";
import {
    buildCoverageSnapshot,
    COVERAGE_SCOPES,
    createCoverageState,
    recordEnumeratedEntries,
    recordFetchFailure,
    recordFetchResult,
} from "./coverageAccounting.mjs";

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
    if (args.coverage_scope !== undefined
        && !COVERAGE_SCOPES.includes(args.coverage_scope)) {
        return failure(`coverage_scope must be one of: ${COVERAGE_SCOPES.join(" | ")}`);
    }

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

    const coverageScope = args.coverage_scope
        || (modeUsesCouncil(ctx.mode) ? "council_sample" : "mandatory");
    const treeState = sessionId ? getTreeEnumerationState(sessionId) : null;
    if (ctx.hasActiveAudit) {
        if (!treeState?.rootTreeSha) {
            return failure("safe_fetch_file refused: tree-enumeration state is missing. Call zerotrust_safe_list_tree before fetching files.");
        }
        const acquisitionState = getAcquisitionCoverageState(sessionId);
        const enumeratedIndex = acquisitionState?.enumeratedFileIndex?.get(path);
        const enumerated = Number.isInteger(enumeratedIndex)
            ? acquisitionState.enumeratedFiles[enumeratedIndex]
            : null;
        if (!enumerated) {
            return failure(`safe_fetch_file refused: path was not enumerated as a blob in the pinned commit tree: ${path}`);
        }
    }
    const coverageMutation = ctx.hasActiveAudit
        ? {
            commitSha: sha.toLowerCase(),
            rootTreeSha: treeState.rootTreeSha,
            createState: () => {
                const state = createCoverageState(sha, treeState.rootTreeSha);
                recordEnumeratedEntries(state, treeState.entries || []);
                return state;
            },
        }
        : null;

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
    const doFetch = invocation?.apiClient?.fetchFile
        || invocation?.fetchFile
        || fetchFile;
    try {
        result = doFetch(owner, repo, sha, path, opts);
    } catch (err) {
        let acquisitionCoverage = null;
        if (coverageMutation) {
            const updated = mutateAcquisitionCoverageState(
                sessionId,
                coverageMutation,
                (state) => {
                    recordFetchFailure(state, {
                        path,
                        scope: coverageScope,
                        error: err,
                    });
                    return buildCoverageSnapshot(state, treeState);
                },
            );
            if (!updated.ok) {
                return failure(
                    `fetch_file failed: ${err.message}; acquisition-coverage failure could not be persisted`,
                );
            }
            acquisitionCoverage = updated.value;
        }
        return failure(
            `fetch_file failed: ${err.message}`,
            acquisitionCoverage
                ? { acquisitionCoverage }
                : {},
        );
    }

    if (!coverageMutation) return success(result);

    let updated;
    try {
        updated = mutateAcquisitionCoverageState(
            sessionId,
            coverageMutation,
            (state) => {
                const acquisition = recordFetchResult(state, {
                    path,
                    scope: coverageScope,
                    result,
                });
                return {
                    acquisition,
                    acquisitionCoverage: buildCoverageSnapshot(state, treeState),
                };
            },
        );
    } catch (err) {
        return failure(`fetch_file coverage accounting failed: ${err.message}`);
    }
    if (!updated.ok) {
        return failure("safe_fetch_file refused: could not persist acquisition-coverage state for the pinned audit");
    }

    let analysisFacts = [];
    let analysisIndex = null;
    let analysisStageState = ctx.analysisStageState;
    let analysisPlugins = ctx.analysisPlugins;
    let behaviorGraph = ctx.behaviorGraph;
    if (coverageScope === "mandatory") {
        let extraction = { facts: [], overflow: false, lineCount: null };
        const fullyReturnedText = result.classification === "text"
            && result.classificationComplete === true
            && result.contentReturned === true
            && result.textTruncated !== true
            && result.contentTooLarge !== true
            && typeof result.text === "string";
        try {
            if (fullyReturnedText) {
                extraction = extractFactsFromText({ path, text: result.text });
            }
            const indexed = mutateAnalysisIndexState(sessionId, (indexState) => {
                const snapshot = recordIndexedFile(indexState, {
                    path,
                    size: result.sizeBytes,
                    classification: result.classification,
                    classificationComplete: result.classificationComplete,
                    contentTooLarge: result.contentTooLarge === true,
                    textTruncated: result.textTruncated === true,
                    contentSha256: result.sha256 || null,
                    blobSha: result.blobSha || null,
                    facts: extraction.facts,
                    factsOverflow: extraction.overflow,
                    lineCount: fullyReturnedText ? extraction.lineCount : null,
                    invisibleUnicodeScanComplete:
                        updated.value.acquisition.invisibleUnicodeScan?.complete === true,
                    invisibleUnicodeMatchCount:
                        updated.value.acquisition.invisibleUnicodeScan?.matchCount || 0,
                });
                analysisFacts = listIndexedFacts(indexState, {
                    path,
                    limit: 256,
                }).facts;
                return snapshot;
            });
            if (!indexed.ok) {
                return failure(
                    "safe_fetch_file refused: could not persist the mandatory analysis index",
                    { acquisitionCoverage: updated.value.acquisitionCoverage },
                );
            }
            const preparation = maybeAdvanceAnalysisPrepared(sessionId);
            analysisIndex = preparation?.analysisIndex || getAnalysisIndexSnapshot(sessionId);
            analysisStageState = preparation?.analysisStageState || analysisStageState;
            analysisPlugins = preparation?.analysisPlugins || analysisPlugins;
            behaviorGraph = preparation?.behaviorGraph || behaviorGraph;
        } catch (err) {
            return failure(
                `safe_fetch_file analysis indexing failed: ${err.message}`,
                { acquisitionCoverage: updated.value.acquisitionCoverage },
            );
        }
    } else if (ctx.hasActiveAudit) {
        const indexState = getAnalysisIndexState(sessionId);
        analysisFacts = indexState
            ? listIndexedFacts(indexState, { path, limit: 256 }).facts
            : [];
        analysisIndex = getAnalysisIndexSnapshot(sessionId);
    }

    return success({
        ...result,
        coverageScope,
        invisibleUnicodeScan: updated.value.acquisition.invisibleUnicodeScan,
        acquisitionCoverage: updated.value.acquisitionCoverage,
        analysisFacts,
        analysisIndex,
        analysisStageState,
        analysisPlugins,
        behaviorGraph,
    });
}
