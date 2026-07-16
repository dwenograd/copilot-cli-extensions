export const MAX_RELEASE_ASSETS = 512;
export const MAX_RELEASE_ASSET_BYTES = 100 * 1024 * 1024;
export const MAX_RELEASE_ASSET_SNAPSHOT_ITEMS = 50;
export const RELEASE_ASSET_PREVIEW_BYTES = 256;

const MAX_ERROR_LENGTH = 300;

export function createReleaseAssetCoverageState({
    releaseId,
    tagName,
    sourceCommitSha,
} = {}) {
    return {
        schemaVersion: 1,
        releaseId: normalizeReleaseId(releaseId),
        tagName: normalizeTagName(tagName),
        sourceCommitSha: normalizeSha(sourceCommitSha),
        listAttempts: 0,
        listFailureAttempts: 0,
        listFailures: [],
        enumerationRecorded: false,
        enumerationComplete: false,
        enumerationTruncated: false,
        totalAssetsReported: 0,
        duplicateAssetCount: 0,
        assets: [],
        fetchAttempts: 0,
        duplicateFetchCalls: 0,
        successfulDownloads: {},
        failedAssets: {},
        oversizedAssets: {},
        byteMismatchAssets: {},
    };
}

export function recordReleaseAssetListFailure(state, error) {
    assertState(state);
    state.listAttempts += 1;
    state.listFailureAttempts += 1;
    if (state.listFailures.length < MAX_RELEASE_ASSET_SNAPSHOT_ITEMS) {
        state.listFailures.push(normalizeError(error));
    }
    return state;
}

export function recordReleaseAssetEnumeration(state, {
    assets,
    totalAssetsReported,
    duplicateAssetCount = 0,
    enumerationComplete = true,
    enumerationTruncated = false,
} = {}) {
    assertState(state);
    if (!Array.isArray(assets)) throw new Error("release assets must be an array");
    const normalized = assets.map(normalizeAsset);
    const fingerprint = JSON.stringify(normalized);

    if (state.enumerationRecorded) {
        if (state.enumerationFingerprint !== fingerprint
            || state.totalAssetsReported !== totalAssetsReported
            || state.duplicateAssetCount !== duplicateAssetCount
            || state.enumerationComplete !== (enumerationComplete === true)
            || state.enumerationTruncated !== (enumerationTruncated === true)) {
            throw new Error("release asset enumeration changed after it was bound to this audit");
        }
        state.listAttempts += 1;
        return state;
    }

    state.listAttempts += 1;
    state.enumerationRecorded = true;
    state.enumerationComplete = enumerationComplete === true;
    state.enumerationTruncated = enumerationTruncated === true;
    state.totalAssetsReported = normalizeCount(totalAssetsReported);
    state.duplicateAssetCount = normalizeCount(duplicateAssetCount);
    state.assets = normalized;
    state.enumerationFingerprint = fingerprint;
    return state;
}

export function findEnumeratedReleaseAsset(state, assetId) {
    assertState(state);
    const id = normalizeReleaseId(assetId);
    return state.assets.find((asset) => asset.id === id) || null;
}

export function getSuccessfulReleaseAsset(state, assetId) {
    assertState(state);
    return state.successfulDownloads[normalizeReleaseId(assetId)] || null;
}

export function recordReleaseAssetFetchFailure(state, {
    assetId,
    kind = "download_failed",
    error,
} = {}) {
    assertState(state);
    const id = normalizeReleaseId(assetId);
    state.fetchAttempts += 1;
    delete state.successfulDownloads[id];
    const detail = {
        kind: normalizeKind(kind),
        error: normalizeError(error),
    };
    state.failedAssets[id] = detail;
    if (detail.kind === "oversized") state.oversizedAssets[id] = detail;
    if (detail.kind === "byte_mismatch") state.byteMismatchAssets[id] = detail;
    return detail;
}

export function recordReleaseAssetFetchSuccess(state, {
    assetId,
    sizeBytes,
    sha256,
    path,
    classification,
    previewByteCount,
} = {}) {
    assertState(state);
    const id = normalizeReleaseId(assetId);
    if (!findEnumeratedReleaseAsset(state, id)) {
        throw new Error(`release asset ${id} was not enumerated`);
    }
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 0) {
        throw new Error("release asset sizeBytes must be a non-negative safe integer");
    }
    if (typeof sha256 !== "string" || !/^[a-f0-9]{64}$/i.test(sha256)) {
        throw new Error("release asset sha256 must be 64 hexadecimal characters");
    }
    if (typeof path !== "string" || path.length === 0) {
        throw new Error("release asset path is required");
    }
    state.fetchAttempts += 1;
    state.successfulDownloads[id] = Object.freeze({
        assetId: id,
        sizeBytes,
        sha256: sha256.toLowerCase(),
        path,
        classification: ["binary", "text", "unknown"].includes(classification)
            ? classification: "unknown",
        previewByteCount: Number.isSafeInteger(previewByteCount) && previewByteCount >= 0
            ? previewByteCount: 0,
    });
    delete state.failedAssets[id];
    delete state.oversizedAssets[id];
    delete state.byteMismatchAssets[id];
    return state.successfulDownloads[id];
}

export function recordDuplicateReleaseAssetFetch(state, assetId) {
    assertState(state);
    normalizeReleaseId(assetId);
    state.fetchAttempts += 1;
    state.duplicateFetchCalls += 1;
}

export function buildReleaseAssetCoverageSnapshot(state, {
    maxItems = MAX_RELEASE_ASSET_SNAPSHOT_ITEMS,
} = {}) {
    const itemLimit = Number.isSafeInteger(maxItems) && maxItems >= 0
        ? Math.min(maxItems, MAX_RELEASE_ASSET_SNAPSHOT_ITEMS): MAX_RELEASE_ASSET_SNAPSHOT_ITEMS;
    if (!state) {
        return {
            schemaVersion: 1,
            requiredReleaseAssetAcquisitionComplete: false,
            enumeration: {
                recorded: false,
                complete: false,
                uniqueAssets: 0,
                zeroAssets: false,
            },
            blockers: [{ kind: "release_asset_enumeration_missing" }],
        };
    }
    assertState(state);

    const successfulIds = new Set(Object.keys(state.successfulDownloads));
    const failedIds = new Set(Object.keys(state.failedAssets));
    const oversizedIds = new Set(Object.keys(state.oversizedAssets));
    const byteMismatchIds = new Set(Object.keys(state.byteMismatchAssets));
    const skippedIds = state.assets
        .map((asset) => asset.id)
        .filter((id) => !successfulIds.has(id)
            && !failedIds.has(id)
            && !oversizedIds.has(id)
            && !byteMismatchIds.has(id));
    const unresolvedIds = state.assets
        .map((asset) => asset.id)
        .filter((id) => !successfulIds.has(id));
    const blockers = [];
    if (!state.enumerationRecorded) blockers.push({ kind: "release_asset_enumeration_missing" });
    if (!state.enumerationComplete) blockers.push({ kind: "release_asset_enumeration_incomplete" });
    if (state.enumerationTruncated) blockers.push({ kind: "release_asset_enumeration_truncated" });
    if (state.listFailureAttempts > 0 && !state.enumerationRecorded) {
        blockers.push({ kind: "release_asset_list_failed", attempts: state.listFailureAttempts });
    }
    if (unresolvedIds.length > 0) {
        blockers.push({ kind: "release_assets_not_downloaded_and_hashed", count: unresolvedIds.length });
    }

    const complete = state.enumerationRecorded
        && state.enumerationComplete
        && !state.enumerationTruncated
        && unresolvedIds.length === 0;
    const downloaded = Object.values(state.successfulDownloads)
        .sort((a, b) => compareIds(a.assetId, b.assetId));

    return {
        schemaVersion: 1,
        releaseId: state.releaseId,
        tagName: state.tagName,
        sourceCommitSha: state.sourceCommitSha,
        requiredReleaseAssetAcquisitionComplete: complete,
        enumeration: {
            recorded: state.enumerationRecorded,
            complete: state.enumerationComplete,
            truncated: state.enumerationTruncated,
            listAttempts: state.listAttempts,
            listFailureAttempts: state.listFailureAttempts,
            totalAssetsReported: state.totalAssetsReported,
            uniqueAssets: state.assets.length,
            duplicateAssets: state.duplicateAssetCount,
            zeroAssets: state.enumerationRecorded
                && state.enumerationComplete
                && state.assets.length === 0,
            maxTrackedAssets: MAX_RELEASE_ASSETS,
        },
        acquisition: {
            fetchAttempts: state.fetchAttempts,
            uniqueDownloadedAndHashedAssets: downloaded.length,
            duplicateFetchCalls: state.duplicateFetchCalls,
            skippedAssets: skippedIds.length,
            failedAssets: failedIds.size,
            oversizedAssets: oversizedIds.size,
            byteMismatchAssets: byteMismatchIds.size,
        },
        blockers,
        details: {
            downloadedAndHashed: downloaded.slice(0, itemLimit),
            downloadedAndHashedTruncated: downloaded.length > itemLimit,
            skippedAssetIds: skippedIds.slice(0, itemLimit),
            skippedAssetIdsTruncated: skippedIds.length > itemLimit,
            failedAssetIds: [...failedIds].sort(compareIds).slice(0, itemLimit),
            failedAssetIdsTruncated: failedIds.size > itemLimit,
            oversizedAssetIds: [...oversizedIds].sort(compareIds).slice(0, itemLimit),
            oversizedAssetIdsTruncated: oversizedIds.size > itemLimit,
            byteMismatchAssetIds: [...byteMismatchIds].sort(compareIds).slice(0, itemLimit),
            byteMismatchAssetIdsTruncated: byteMismatchIds.size > itemLimit,
            listFailures: state.listFailures.slice(0, itemLimit),
            listFailuresTruncated: state.listFailureAttempts > itemLimit,
        },
    };
}

function normalizeAsset(asset) {
    if (!asset || typeof asset !== "object") throw new Error("invalid release asset");
    const name = typeof asset.name === "string" ? asset.name: "";
    const contentType = typeof asset.contentType === "string" ? asset.contentType: "";
    const digest = typeof asset.digest === "string" ? asset.digest: null;
    if (!Number.isSafeInteger(asset.sizeBytes) || asset.sizeBytes < 0) {
        throw new Error(`invalid size for release asset ${asset.id}`);
    }
    return {
        id: normalizeReleaseId(asset.id),
        name: name.slice(0, 256),
        nameTruncated: name.length > 256,
        contentType: contentType.slice(0, 128),
        sizeBytes: asset.sizeBytes,
        digest: digest ? digest.slice(0, 128): null,
    };
}

function assertState(state) {
    if (!state || state.schemaVersion !== 1) {
        throw new Error("invalid release asset coverage state");
    }
}

function normalizeReleaseId(value) {
    const normalized = String(value || "");
    if (!/^[1-9][0-9]{0,19}$/.test(normalized)) {
        throw new Error(`invalid release asset/release id: ${JSON.stringify(value)}`);
    }
    return normalized;
}

function normalizeTagName(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 255) {
        throw new Error("invalid release tag name");
    }
    return value;
}

function normalizeSha(value) {
    const normalized = String(value || "").toLowerCase();
    if (!/^[a-f0-9]{40}$/.test(normalized)) {
        throw new Error("invalid release source commit SHA");
    }
    return normalized;
}

function normalizeCount(value) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error("release asset count must be a non-negative safe integer");
    }
    return value;
}

function normalizeError(error) {
    return String(error?.message || error || "unknown error").slice(0, MAX_ERROR_LENGTH);
}

function normalizeKind(kind) {
    const normalized = String(kind || "download_failed");
    return /^[a-z][a-z0-9_]{0,63}$/.test(normalized)
        ? normalized: "download_failed";
}

function compareIds(left, right) {
    const a = BigInt(left);
    const b = BigInt(right);
    return a < b ? -1: a > b ? 1: 0;
}

export const __internals = {
    normalizeAsset,
    normalizeReleaseId,
};
