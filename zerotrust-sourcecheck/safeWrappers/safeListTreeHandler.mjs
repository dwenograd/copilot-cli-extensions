// safeWrappers/safeListTreeHandler.mjs — bounded, state-bound API tree enumeration.

import {
    getCommitIdentity,
    listTreeBySha,
    resolveRefToSha,
    resolveReleaseIdentity,
} from "./apiClient.mjs";
import {
    buildQuarantinePath,
    buildReportPath,
    parseGithubUrl,
} from "../urlParser.mjs";
import {
    getAcquisitionCoverageState,
    getAnalysisIndexSnapshot,
    getTreeEnumerationState,
    getTrustedAuditContext,
    getAssuranceState,
    advanceAssuranceStage,
    maybeAdvanceAnalysisPrepared,
    mutateAnalysisIndexState,
    recordAcquisitionCoverageState,
    recordReleaseIdentity,
    recordResolvedArtifactPaths,
    recordResolvedSha,
    recordTreeEnumerationState,
    recordAssuranceSnapshot,
} from "../enforcement.mjs";
import { recordIndexEnumeration } from "../analysis/indexState.mjs";
import {
    EVASIVE_BLOCKERS,
    buildGitObjectInventory,
    classifyGitTreeEntry,
} from "../analysis/index.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";
import {
    annotateTreeEntry,
    buildCoverageSnapshot,
    createCoverageState,
    recordEnumeratedEntries,
    recordEnumerationFailure,
    validateCoverageStateIdentity,
} from "./coverageAccounting.mjs";

const MAX_TRACKED_ENTRIES = 50_000;
const MAX_TRACKED_SUBTREES = 10_000;
const MAX_AGGREGATE_OUTPUT_ENTRIES = 1_000;
const MAX_UNRESOLVED_OUTPUT = 500;
const MAX_BLOCKERS_OUTPUT = 50;

const defaultApiClient = {
    getCommitIdentity,
    listTreeBySha,
    resolveRefToSha,
    resolveReleaseIdentity,
};

export async function safeListTreeHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    const apiClient = invocation?.apiClient || defaultApiClient;

    let owner, repo, ref, refType;
    if (typeof args.url === "string") {
        const parsed = parseGithubUrl(args.url);
        if (!parsed.ok) return failure(`URL rejected: ${parsed.error}`);
        owner = parsed.parsed.owner;
        repo = parsed.parsed.repo;
        ref = args.ref || parsed.parsed.ref || null;
        refType = args.refType || parsed.parsed.refType || null;
    } else {
        if (typeof args.owner !== "string" || typeof args.repo !== "string") {
            return failure("must provide either { url } or { owner, repo }");
        }
        owner = args.owner;
        repo = args.repo;
        ref = args.ref || null;
        refType = args.refType || null;
    }

    const ctx = getTrustedAuditContext({ sessionId, args, defaultBuildRoot: DEFAULT_BUILD_ROOT });
    if (!ctx.ok) return failure(ctx.error);
    if (ctx.hasActiveAudit && ctx.localPath) {
        return failure(`safe_list_tree refused: active audit is local-source mode (target: ${ctx.localPath}). API-direct tree listing applies to URL-driven audits only. Use \`glob\` against ${ctx.localPath} to enumerate files.`);
    }
    if (sessionId && !ctx.hasActiveAudit) {
        return failure(`safe_list_tree refused: no active audit for this session (TTL expired or zerotrust_sourcecheck not invoked). Re-invoke zerotrust_sourcecheck before any wrapper call.`);
    }
    if (ctx.hasActiveAudit && ctx.owner && ctx.repo
        && (owner.toLowerCase() !== ctx.owner || repo.toLowerCase() !== ctx.repo)) {
        return failure(`safe_list_tree refused: owner/repo (${owner}/${repo}) does not match the active audit's pinned target (${ctx.owner}/${ctx.repo}).`);
    }
    if (ctx.hasActiveAudit && ctx.ref) {
        if (ref && ref !== ctx.ref) {
            return failure(`safe_list_tree refused: ref (${ref}) does not match the active audit's pinned ref (${ctx.ref}).`);
        }
        if (!ref) ref = ctx.ref;
    }
    if (ctx.hasActiveAudit && ctx.refType) {
        if (refType && refType !== ctx.refType) {
            return failure(`safe_list_tree refused: refType (${refType}) does not match the active audit's pinned refType (${ctx.refType}). Activate a new audit if you want a different ref namespace.`);
        }
        if (!refType) refType = ctx.refType;
    }

    const subtreePathArg = args.subtree_path;
    const treeShaArg = args.tree_sha;
    if (subtreePathArg !== undefined && typeof subtreePathArg !== "string") {
        return failure("subtree_path must be a string when provided");
    }
    if (treeShaArg !== undefined
        && (typeof treeShaArg !== "string" || !/^[a-f0-9]{40}$/i.test(treeShaArg))) {
        return failure("tree_sha must be a 40-char hex Git tree SHA when provided");
    }
    if (subtreePathArg !== undefined && treeShaArg !== undefined) {
        return failure("provide only one of subtree_path or tree_sha");
    }
    if (subtreePathArg !== undefined) {
        try {
            validateSubtreePath(subtreePathArg);
        } catch (err) {
            return failure(err.message);
        }
    }
    if ((subtreePathArg !== undefined || treeShaArg !== undefined) && !sessionId) {
        return failure("subtree enumeration requires an active audit session");
    }

    let releaseIdentity = ctx.releaseIdentity || null;
    let commitIdentity;
    try {
        if (ctx.hasActiveAudit && ctx.urlKind === "release") {
            if (!releaseIdentity) {
                releaseIdentity = apiClient.resolveReleaseIdentity(owner, repo, {
                    requestedTag: ctx.releaseSelector === "tag" ? ctx.ref: null,
                });
                if (!releaseIdentity
                    || !recordReleaseIdentity(sessionId, releaseIdentity)) {
                    return failure("release identity could not be bound to the active audit");
                }
            }
            commitIdentity = {
                commitSha: releaseIdentity.sourceCommitSha,
                rootTreeSha: releaseIdentity.rootTreeSha,
            };
        } else if (ctx.hasActiveAudit && ctx.resolvedSha) {
            commitIdentity = ctx.rootTreeSha
                ? { commitSha: ctx.resolvedSha, rootTreeSha: ctx.rootTreeSha }: apiClient.getCommitIdentity(owner, repo, ctx.resolvedSha);
        } else {
            const sha = apiClient.resolveRefToSha(owner, repo, ref, refType);
            commitIdentity = apiClient.getCommitIdentity(owner, repo, sha);
        }
        validateCommitIdentity(commitIdentity);
    } catch (err) {
        return failure(`SHA resolution failed: ${err.message}`);
    }

    const commitSha = commitIdentity.commitSha.toLowerCase();
    const rootTreeSha = commitIdentity.rootTreeSha.toLowerCase();
    if (ctx.hasActiveAudit && ctx.resolvedSha
        && commitSha !== ctx.resolvedSha.toLowerCase()) {
        return failure(`safe_list_tree refused: resolved SHA (${commitSha}) does not match the audit's previously-pinned commit (${ctx.resolvedSha}). Re-invoke zerotrust_sourcecheck with the new ref to audit a different commit.`);
    }
    if (sessionId) {
        const pinOk = recordResolvedSha(sessionId, commitSha);
        if (pinOk === false && ctx.hasActiveAudit) {
            return failure(`safe_list_tree refused: resolved SHA conflicts with the audit's previously-pinned commit. This indicates a race or repeated call with a different ref.`);
        }
    }

    let reportPath = null;
    let quarantinePath = null;
    try {
        reportPath = buildReportPath(ctx.buildRoot, owner, repo, commitSha);
        quarantinePath = buildQuarantinePath(ctx.buildRoot, owner, repo, commitSha);
        if (sessionId) recordResolvedArtifactPaths(sessionId, { reportPath, quarantinePath });
    } catch (err) {
        return failure(`bound artifact path construction failed: ${err.message}`);
    }

    let state = sessionId ? getTreeEnumerationState(sessionId): null;
    if (state && (state.commitSha !== commitSha || state.rootTreeSha !== rootTreeSha)) {
        return failure("safe_list_tree refused: tree-enumeration state does not match the pinned commit/root tree");
    }
    if (!state) state = createEnumerationState(commitSha, rootTreeSha);

    let acquisitionState = sessionId ? getAcquisitionCoverageState(sessionId): null;
    if (acquisitionState
        && !validateCoverageStateIdentity(acquisitionState, commitSha, rootTreeSha)) {
        return failure("safe_list_tree refused: acquisition-coverage state does not match the pinned commit/root tree");
    }
    if (!acquisitionState) acquisitionState = createCoverageState(commitSha, rootTreeSha);

    let target;
    try {
        target = resolveEnumerationTarget(state, subtreePathArg, treeShaArg);
    } catch (err) {
        return failure(`safe_list_tree refused: ${err.message}`);
    }

    let currentEntries = [];
    if (!target.alreadyComplete) {
        try {
            const recursiveResult = apiClient.listTreeBySha(owner, repo, target.sha, {
                recursive: true,
            });
            validateTreeResult(recursiveResult, target.sha, true);
            state.githubTruncationSeen ||= recursiveResult.truncated;
            state.localEntryCapSeen ||= recursiveResult.entriesTruncated;
            state.discoveryTruncated ||= recursiveResult.discoveryTruncated === true;

            if (!recursiveResult.truncated
                && !recursiveResult.entriesTruncated
                && !recursiveResult.discoveryTruncated) {
                currentEntries = prefixEntries(target.path, recursiveResult.entries);
                addDiscoveredSubtrees(state, target.path, recursiveResult.discoveredSubtrees);
                markSubtreeComplete(state, target.path);
            } else {
                const directResult = apiClient.listTreeBySha(owner, repo, target.sha, {
                    recursive: false,
                });
                validateTreeResult(directResult, target.sha, false);
                state.githubTruncationSeen ||= directResult.truncated;
                state.localEntryCapSeen ||= directResult.entriesTruncated;
                state.discoveryTruncated ||= directResult.discoveryTruncated === true;
                currentEntries = prefixEntries(target.path, directResult.entries);

                const childTrees = addDiscoveredSubtrees(
                    state,
                    target.path,
                    directResult.discoveredSubtrees,
                    { requireDirectChildren: true },
                );
                splitUnresolvedSubtree(state, target.path, childTrees);
                if (directResult.truncated || directResult.entriesTruncated
                    || directResult.discoveryTruncated) {
                    addCoverageBlocker(
                        state,
                        target.path,
                        "non-recursive listing was truncated; direct entries in this subtree remain undisclosed",
                    );
                } else if (childTrees.length === 0) {
                    addCoverageBlocker(
                        state,
                        target.path,
                        "recursive listing exceeded a cap but the subtree has no child trees to split further",
                    );
                }
            }
            mergeEntries(state, currentEntries);
            recordEnumeratedEntries(acquisitionState, currentEntries);
        } catch (err) {
            recordEnumerationFailure(acquisitionState, {
                path: target.path || "<root>",
                error: err,
            });
            if (sessionId) recordAcquisitionCoverageState(sessionId, acquisitionState);
            return failure(
                `tree listing failed: ${err.message}`,
                { acquisitionCoverage: buildCoverageSnapshot(acquisitionState, state) },
            );
        }
    }

    if (sessionId && !recordTreeEnumerationState(sessionId, state)) {
        return failure("safe_list_tree refused: could not persist tree-enumeration state for the pinned audit");
    }
    if (sessionId && !recordAcquisitionCoverageState(sessionId, acquisitionState)) {
        return failure("safe_list_tree refused: could not persist acquisition-coverage state for the pinned audit");
    }

    const acquisitionCoverage = buildCoverageSnapshot(acquisitionState, state);
    let analysisIndex = null;
    let analysisStageState = ctx.analysisStageState;
    let analysisPlugins = ctx.analysisPlugins;
    let behaviorGraph = ctx.behaviorGraph;
    let assuranceObjectInventory = null;
    if (sessionId) {
        try {
            const indexed = mutateAnalysisIndexState(sessionId, (indexState) =>
                recordIndexEnumeration(indexState, {
                    entries: state.entries
                        .filter((entry) => entry.type === "blob")
                        .map((entry) => ({
                            path: entry.path,
                            size: Number.isSafeInteger(entry.size) ? entry.size: 0,
                            blobSha: entry.sha,
                        })),
                    complete: acquisitionCoverage.enumeration.complete,
                    trackingTruncated: acquisitionCoverage.enumeration.stateTrackingTruncated
                        || acquisitionCoverage.enumeration.discoveryTruncated,
                    blocker: acquisitionCoverage.enumeration.coverageBlockers > 0
                        ? "Git tree enumeration reported coverage blockers": null,
                }));
            if (!indexed.ok) {
                return failure("safe_list_tree refused: could not persist analysis-index enumeration state");
            }
            const preparation = maybeAdvanceAnalysisPrepared(sessionId);
            analysisIndex = preparation?.analysisIndex || getAnalysisIndexSnapshot(sessionId);
            analysisStageState = preparation?.analysisStageState || analysisStageState;
            analysisPlugins = preparation?.analysisPlugins || analysisPlugins;
            behaviorGraph = preparation?.behaviorGraph || behaviorGraph;
        } catch (err) {
            return failure(`safe_list_tree analysis-index accounting failed: ${err.message}`);
        }
    }

    if (sessionId && ctx.hasActiveAudit) {
        try {
            assuranceObjectInventory = persistGitObjectInventory({
                sessionId,
                ctx,
                commitSha,
                rootTreeSha,
                treeState: state,
                acquisitionState,
            });
        } catch {
            assuranceObjectInventory = {
                schemaVersion: 6,
                complete: false,
                blockerCodes: [EVASIVE_BLOCKERS.INVENTORY_INCOMPLETE],
            };
        }
    }

    return success(renderEnumerationResult({
        owner,
        repo,
        state,
        currentEntries,
        target,
        releaseIdentity,
        reportPath,
        quarantinePath,
        acquisitionState,
        acquisitionCoverage,
        analysisIndex,
        analysisStageState,
        analysisPlugins,
        behaviorGraph,
        assuranceObjectInventory,
    }));
}

function validateCommitIdentity(identity) {
    if (!identity || !/^[a-f0-9]{40}$/i.test(identity.commitSha || "")
        || !/^[a-f0-9]{40}$/i.test(identity.rootTreeSha || "")) {
        throw new Error("API returned an invalid commit/root-tree identity");
    }
}

function validateSubtreePath(path) {
    if (path.length < 1 || path.length > 1024 || /[\u0000-\u001f\u007f\\]/u.test(path)
        || path.startsWith("/") || path.endsWith("/") || path.includes("//")
        || path.split("/").some((segment) => segment === "." || segment === "..")) {
        throw new Error(`invalid subtree_path: ${JSON.stringify(path)}`);
    }
}

function createEnumerationState(commitSha, rootTreeSha) {
    return {
        commitSha,
        rootTreeSha,
        discoveredSubtrees: [{ path: "", sha: rootTreeSha }],
        unresolvedSubtrees: [{ path: "", sha: rootTreeSha }],
        completedSubtrees: [],
        entries: [],
        aggregateEntryCount: 0,
        duplicateEntryCount: 0,
        stateTrackingTruncated: false,
        discoveryTruncated: false,
        githubTruncationSeen: false,
        localEntryCapSeen: false,
        coverageBlockers: [],
    };
}

function resolveEnumerationTarget(state, subtreePath, treeSha) {
    if (subtreePath === undefined && treeSha === undefined) {
        if (state.completedSubtrees.includes("") || !state.unresolvedSubtrees.some((item) => item.path === "")) {
            return { path: "", sha: state.rootTreeSha, alreadyComplete: true };
        }
        return { path: "", sha: state.rootTreeSha, alreadyComplete: false };
    }
    if (subtreePath !== undefined) {
        const found = state.discoveredSubtrees.find((item) => item.path === subtreePath);
        if (!found) throw new Error(`subtree_path ${JSON.stringify(subtreePath)} was not discovered from the pinned commit tree`);
        return {
            ...found,
            alreadyComplete: state.completedSubtrees.includes(found.path),
        };
    }
    const normalizedSha = treeSha.toLowerCase();
    const matches = state.discoveredSubtrees.filter((item) => item.sha === normalizedSha);
    if (matches.length === 0) {
        throw new Error(`tree_sha ${treeSha} was not discovered from the pinned commit tree`);
    }
    if (matches.length > 1) {
        throw new Error(`tree_sha ${treeSha} is shared by multiple discovered paths; use subtree_path to disambiguate`);
    }
    return {
        ...matches[0],
        alreadyComplete: state.completedSubtrees.includes(matches[0].path),
    };
}

function validateTreeResult(result, expectedSha, recursive) {
    if (!result || result.treeSha?.toLowerCase() !== expectedSha.toLowerCase()
        || result.recursive !== recursive || !Array.isArray(result.entries)
        || !Array.isArray(result.discoveredSubtrees)) {
        throw new Error(`tree identity mismatch for ${expectedSha}`);
    }
}

function prefixEntries(basePath, entries) {
    return entries.map((entry) => {
        const classification = classifyGitTreeEntry(entry);
        return {
            ...entry,
            mode: classification.mode,
            modeInferred: classification.modeInferred,
            objectKind: classification.objectKind,
            executable: classification.executable,
            path: basePath ? `${basePath}/${entry.path}`: entry.path,
        };
    });
}

function addDiscoveredSubtrees(state, basePath, discovered, { requireDirectChildren = false } = {}) {
    const added = [];
    for (const item of discovered) {
        if (!item || item.type !== "tree" || !/^[a-f0-9]{40}$/i.test(item.sha || "")) {
            throw new Error("tree response contained an invalid discovered subtree");
        }
        if (requireDirectChildren && item.path.includes("/")) {
            throw new Error(`non-recursive tree response contained a non-direct path: ${item.path}`);
        }
        const path = basePath ? `${basePath}/${item.path}`: item.path;
        validateSubtreePath(path);
        const sha = item.sha.toLowerCase();
        const existing = state.discoveredSubtrees.find((entry) => entry.path === path);
        if (existing) {
            if (existing.sha !== sha) throw new Error(`subtree identity conflict at ${path}`);
            added.push(existing);
            continue;
        }
        if (state.discoveredSubtrees.length >= MAX_TRACKED_SUBTREES) {
            state.discoveryTruncated = true;
            continue;
        }
        const normalized = { path, sha };
        state.discoveredSubtrees.push(normalized);
        added.push(normalized);
    }
    return added;
}

function markSubtreeComplete(state, path) {
    if (!state.completedSubtrees.includes(path)) state.completedSubtrees.push(path);
    state.unresolvedSubtrees = state.unresolvedSubtrees.filter(
        (item) => item.path !== path && !(path === "" || item.path.startsWith(`${path}/`)),
    );
    state.coverageBlockers = state.coverageBlockers.filter(
        (item) => item.path !== (path || "<root>")
            && !(path === "" || item.path.startsWith(`${path}/`)),
    );
}

function splitUnresolvedSubtree(state, path, childTrees) {
    state.unresolvedSubtrees = state.unresolvedSubtrees.filter((item) => item.path !== path);
    for (const child of childTrees) {
        if (!state.completedSubtrees.includes(child.path)
            && !state.unresolvedSubtrees.some((item) => item.path === child.path)) {
            state.unresolvedSubtrees.push(child);
        }
    }
}

function addCoverageBlocker(state, path, reason) {
    if (!state.coverageBlockers.some((item) => item.path === path && item.reason === reason)) {
        state.coverageBlockers.push({ path: path || "<root>", reason });
    }
}

function mergeEntries(state, entries) {
    const byPath = new Map(state.entries.map((entry) => [entry.path, entry]));
    for (const entry of entries) {
        const existing = byPath.get(entry.path);
        if (existing) {
            if (existing.sha !== entry.sha || existing.type !== entry.type
                || existing.mode !== entry.mode) {
                throw new Error(`entry identity conflict at ${entry.path}`);
            }
            state.duplicateEntryCount += 1;
            continue;
        }
        state.aggregateEntryCount += 1;
        if (state.entries.length >= MAX_TRACKED_ENTRIES) {
            state.stateTrackingTruncated = true;
            continue;
        }
        state.entries.push(entry);
        byPath.set(entry.path, entry);
    }
}

function renderEnumerationResult({
    owner,
    repo,
    state,
    currentEntries,
    target,
    releaseIdentity,
    reportPath,
    quarantinePath,
    acquisitionState,
    acquisitionCoverage,
    analysisIndex,
    analysisStageState,
    analysisPlugins,
    behaviorGraph,
    assuranceObjectInventory,
}) {
    const unresolved = [...state.unresolvedSubtrees].sort((a, b) => a.path.localeCompare(b.path));
    const coverageComplete = unresolved.length === 0
        && state.coverageBlockers.length === 0
        && !state.stateTrackingTruncated
        && !state.discoveryTruncated;
    return {
        owner,
        repo,
        sha: state.commitSha,
        rootTreeSha: state.rootTreeSha,
        releaseIdentity,
        boundContext: {
            sourceCommitSha: state.commitSha,
            rootTreeSha: state.rootTreeSha,
            releaseId: releaseIdentity?.releaseId || null,
            releaseTag: releaseIdentity?.tagName || null,
            reportPath,
            quarantinePath,
        },
        subtree: {
            path: target.path || null,
            treeSha: target.sha,
            alreadyComplete: target.alreadyComplete,
        },
        truncated: state.githubTruncationSeen,
        entriesTruncated: state.localEntryCapSeen,
        entries: currentEntries.map(annotateTreeEntry),
        entryCount: currentEntries.length,
        totalEntryCount: state.aggregateEntryCount,
        aggregateEntries: state.entries
            .slice(0, MAX_AGGREGATE_OUTPUT_ENTRIES)
            .map(annotateTreeEntry),
        aggregateEntryCount: state.aggregateEntryCount,
        aggregateEntriesTruncated: state.stateTrackingTruncated
            || state.entries.length > MAX_AGGREGATE_OUTPUT_ENTRIES,
        duplicateEntryCount: state.duplicateEntryCount,
        unresolvedSubtrees: unresolved.slice(0, MAX_UNRESOLVED_OUTPUT),
        unresolvedSubtreeCount: unresolved.length,
        unresolvedSubtreesTruncated: unresolved.length > MAX_UNRESOLVED_OUTPUT,
        coverageBlockers: state.coverageBlockers.slice(0, MAX_BLOCKERS_OUTPUT),
        coverageBlockersTruncated: state.coverageBlockers.length > MAX_BLOCKERS_OUTPUT,
        coverageComplete,
        acquisitionCoverage: acquisitionCoverage
            || buildCoverageSnapshot(acquisitionState, state),
        analysisIndex,
        analysisStageState,
        analysisPlugins,
        behaviorGraph,
        assuranceObjectInventory,
    };
}

function persistGitObjectInventory({
    sessionId,
    ctx,
    commitSha,
    rootTreeSha,
    treeState,
    acquisitionState,
}) {
    let current = getAssuranceState(sessionId, { auditId: ctx.auditId });
    if (!current || !["acquired", "inventoried"].includes(current.stageState.current)) {
        return current?.analysisSnapshot
            ? {
                schemaVersion: 6,
                snapshotId: current.analysisSnapshot.snapshotId,
                stage: current.stageState.current,
                complete: current.stageState.history.includes("inventoried"),
                blockerCodes: current.analysisSnapshot.blockerCodes,
                inventorySha256: current.analysisSnapshot.hashes.inventorySha256,
                sourceIdentitySha256:
                    current.analysisSnapshot.hashes.sourceIdentitySha256,
            }: null;
    }
    let built = buildGitObjectInventory({
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        stageState: current.stageState,
        commitSha,
        rootTreeSha,
        treeState,
        acquisitionState,
        previousSnapshot: current.analysisSnapshot,
    });
    if (built.summary.complete && current.stageState.current === "acquired") {
        current = advanceAssuranceStage(sessionId, {
            auditId: current.auditId,
            from: "acquired",
            to: "inventoried",
        });
        built = buildGitObjectInventory({
            auditId: current.auditId,
            sourceNamespace: current.sourceNamespace,
            stageState: current.stageState,
            commitSha,
            rootTreeSha,
            treeState,
            acquisitionState,
        });
    }
    recordAssuranceSnapshot(sessionId, {
        auditId: current.auditId,
        snapshot: built.snapshot,
    });
    return built.summary;
}

export const __internals = {
    createEnumerationState,
    resolveEnumerationTarget,
    mergeEntries,
    renderEnumerationResult,
    MAX_TRACKED_ENTRIES,
    MAX_TRACKED_SUBTREES,
};
