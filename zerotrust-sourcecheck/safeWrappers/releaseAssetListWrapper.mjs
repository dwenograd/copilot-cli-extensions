import { execFileSync } from "node:child_process";

import {
    getReleaseAssetCoverageState,
    getTrustedAuditContext,
    mutateReleaseAssetCoverageState,
} from "../enforcement.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { resolveTrustedProgram } from "./programResolver.mjs";
import { failure, success } from "./result.mjs";
import {
    buildReleaseAssetCoverageSnapshot,
    createReleaseAssetCoverageState,
    MAX_RELEASE_ASSETS,
    recordReleaseAssetEnumeration,
    recordReleaseAssetListFailure,
} from "./releaseAssetCoverage.mjs";

const GH_TIMEOUT_MS = 60_000;
const GH_MAX_JSON_BYTES = 32 * 1024 * 1024;

export async function safeListReleaseAssetsHandler(args, invocation, dependencies = {}) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    const identity = validateBoundArgs(args);
    if (!identity.ok) return failure(identity.error);
    if (!sessionId) return failure("safe_list_release_assets requires an active audit session");

    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) return failure(ctx.error);
    const mismatch = validateActiveReleaseIdentity(ctx, identity.value);
    if (mismatch) return failure(mismatch);

    const mutate = (mutator) => mutateReleaseAssetCoverageState(
        sessionId,
        {
            ...identity.value,
            createState: () => createReleaseAssetCoverageState(identity.value),
        },
        mutator,
    );
    const recordFailure = (error) => {
        const updated = mutate((state) => recordReleaseAssetListFailure(state, error));
        return updated.ok
            ? buildReleaseAssetCoverageSnapshot(getReleaseAssetCoverageState(sessionId))
            : null;
    };

    let release;
    try {
        const requestRelease = dependencies.requestRelease || requestBoundRelease;
        release = await requestRelease({
            owner: ctx.canonicalOwner,
            repo: ctx.canonicalRepo,
            releaseId: identity.value.releaseId,
        });
    } catch (err) {
        return failure(`release asset listing failed: ${err.message}`, {
            releaseAssetCoverage: recordFailure(err),
        });
    }

    const responseId = normalizePositiveId(release?.id);
    if (!responseId || responseId !== identity.value.releaseId) {
        const error = new Error(
            `release identity mismatch: requested id ${identity.value.releaseId}, API returned ${JSON.stringify(release?.id)}`,
        );
        return failure(error.message, {
            releaseAssetCoverage: recordFailure(error),
        });
    }
    if (release?.tag_name !== identity.value.tagName) {
        const error = new Error(
            `release identity mismatch: expected tag ${JSON.stringify(identity.value.tagName)}, API returned ${JSON.stringify(release?.tag_name)}`,
        );
        return failure(error.message, {
            releaseAssetCoverage: recordFailure(error),
        });
    }
    if (!Array.isArray(release?.assets)) {
        const error = new Error("release response did not include an assets array");
        return failure(error.message, {
            releaseAssetCoverage: recordFailure(error),
        });
    }

    let enumeration;
    try {
        enumeration = normalizeReleaseAssets(release.assets);
        const recorded = mutate((state) => recordReleaseAssetEnumeration(state, enumeration));
        if (!recorded.ok) {
            return failure("release asset enumeration could not be bound to the active audit");
        }
    } catch (err) {
        return failure(`release asset enumeration refused: ${err.message}`, {
            releaseAssetCoverage: recordFailure(err),
        });
    }

    const releaseAssetCoverage = buildReleaseAssetCoverageSnapshot(
        getReleaseAssetCoverageState(sessionId),
    );
    return success({
        owner: ctx.canonicalOwner,
        repo: ctx.canonicalRepo,
        releaseIdentity: {
            releaseId: identity.value.releaseId,
            tagName: identity.value.tagName,
            sourceCommitSha: identity.value.sourceCommitSha,
        },
        assets: enumeration.assets,
        assetsTruncated: enumeration.enumerationTruncated,
        releaseAssetCoverage,
    });
}

function validateBoundArgs(args) {
    const releaseId = normalizePositiveId(args.release_id);
    if (!releaseId) {
        return { ok: false, error: "release_id must be a positive numeric ID returned by safe_list_tree" };
    }
    if (typeof args.tag_name !== "string" || args.tag_name.length < 1 || args.tag_name.length > 255) {
        return { ok: false, error: "tag_name must be the bound release tag returned by safe_list_tree" };
    }
    const sourceCommitSha = String(args.source_sha || "").toLowerCase();
    if (!/^[a-f0-9]{40}$/.test(sourceCommitSha)) {
        return { ok: false, error: "source_sha must be the full bound 40-character release source SHA" };
    }
    if (typeof args.owner !== "string" || typeof args.repo !== "string") {
        return { ok: false, error: "owner and repo are required" };
    }
    return {
        ok: true,
        value: {
            owner: args.owner.toLowerCase(),
            repo: args.repo.toLowerCase(),
            releaseId,
            tagName: args.tag_name,
            sourceCommitSha,
        },
    };
}

function validateActiveReleaseIdentity(ctx, identity) {
    if (!ctx.hasActiveAudit || ctx.mode !== "verify_release") {
        return `safe_list_release_assets is only valid for an active verify_release audit (active mode: ${ctx.mode || "none"})`;
    }
    if (!ctx.releaseIdentity || !ctx.resolvedSha) {
        return "safe_list_release_assets requires safe_list_tree to bind the release ID, tag, and source SHA first";
    }
    if (identity.owner !== ctx.owner
        || identity.repo !== ctx.repo
        || identity.releaseId !== ctx.releaseIdentity.releaseId
        || identity.tagName !== ctx.releaseIdentity.tagName
        || identity.sourceCommitSha !== ctx.releaseIdentity.sourceCommitSha
        || identity.sourceCommitSha !== ctx.resolvedSha) {
        return "safe_list_release_assets refused: caller release identity does not match the active audit's already-bound release ID/tag/source SHA";
    }
    return null;
}

function normalizeReleaseAssets(rawAssets) {
    const unique = new Map();
    let duplicateAssetCount = 0;
    for (const raw of rawAssets) {
        const id = normalizePositiveId(raw?.id);
        if (!id) throw new Error("release response contained an asset without a valid positive numeric id");
        const sizeBytes = raw?.size;
        if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 0) {
            throw new Error(`release asset ${id} has an invalid size`);
        }
        const asset = {
            id,
            name: typeof raw?.name === "string" ? raw.name : "",
            contentType: typeof raw?.content_type === "string" ? raw.content_type : "",
            sizeBytes,
            digest: typeof raw?.digest === "string" ? raw.digest : null,
        };
        const existing = unique.get(id);
        if (existing) {
            duplicateAssetCount += 1;
            if (JSON.stringify(existing) !== JSON.stringify(asset)) {
                throw new Error(`release response reused asset id ${id} with conflicting metadata`);
            }
            continue;
        }
        unique.set(id, asset);
    }
    const all = [...unique.values()];
    return {
        assets: all.slice(0, MAX_RELEASE_ASSETS),
        totalAssetsReported: rawAssets.length,
        duplicateAssetCount,
        enumerationComplete: all.length <= MAX_RELEASE_ASSETS,
        enumerationTruncated: all.length > MAX_RELEASE_ASSETS,
    };
}

function requestBoundRelease({ owner, repo, releaseId }) {
    const program = resolveTrustedProgram("gh", { forbiddenRoots: [] });
    if (!program) {
        throw new Error("could not resolve a trusted absolute path for 'gh' on PATH");
    }
    const stdout = execFileSync(
        program,
        ["api", `repos/${owner}/${repo}/releases/${releaseId}`],
        {
            encoding: "utf-8",
            timeout: GH_TIMEOUT_MS,
            windowsHide: true,
            env: { ...process.env, GH_PROMPT_DISABLED: "1" },
            stdio: ["ignore", "pipe", "pipe"],
            maxBuffer: GH_MAX_JSON_BYTES,
        },
    );
    return JSON.parse(stdout);
}

function normalizePositiveId(value) {
    if (Number.isSafeInteger(value) && value > 0) return String(value);
    if (typeof value === "string" && /^[1-9][0-9]{0,19}$/.test(value)) return value;
    return null;
}

export const __internals = {
    normalizePositiveId,
    normalizeReleaseAssets,
    requestBoundRelease,
    validateActiveReleaseIdentity,
};
