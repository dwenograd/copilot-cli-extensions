import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
    existsSync,
    mkdirSync,
    rmSync,
    statSync,
    writeFileSync,
} from "node:fs";
import nodePath from "node:path";

import {
    getReleaseAssetCoverageState,
    getTrustedAuditContext,
    mutateReleaseAssetCoverageState,
} from "../enforcement.mjs";
import { buildQuarantinePath } from "../urlParser.mjs";
import { __internals as apiClientInternals } from "./apiClient.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { resolveTrustedProgram } from "./programResolver.mjs";
import {
    buildReleaseAssetCoverageSnapshot,
    createReleaseAssetCoverageState,
    findEnumeratedReleaseAsset,
    getSuccessfulReleaseAsset,
    MAX_RELEASE_ASSET_BYTES,
    recordDuplicateReleaseAssetFetch,
    recordReleaseAssetFetchFailure,
    recordReleaseAssetFetchSuccess,
    RELEASE_ASSET_PREVIEW_BYTES,
} from "./releaseAssetCoverage.mjs";

const GH_DOWNLOAD_TIMEOUT_MS = 5 * 60_000;

export async function safeFetchReleaseAssetHandler(args, invocation, dependencies = {}) {
    args = args || {};
    const unexpected = Object.keys(args).filter((key) => !["asset_id", "max_bytes", "build_root"].includes(key));
    if (unexpected.length > 0) {
        return failure(
            `safe_fetch_release_asset accepts only asset_id, max_bytes, and build_root; refused: ${unexpected.join(", ")}`,
        );
    }
    const assetId = normalizePositiveId(args.asset_id);
    if (!assetId) return failure("asset_id must be a positive numeric ID returned by safe_list_release_assets");
    const maxBytes = resolveMaxBytes(args.max_bytes);
    if (!maxBytes.ok) return failure(maxBytes.error);

    const sessionId = invocation?.sessionId || null;
    if (!sessionId) return failure("safe_fetch_release_asset requires an active audit session");
    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) return failure(ctx.error);
    if (!ctx.hasActiveAudit || ctx.mode !== "verify_release") {
        return failure(
            `safe_fetch_release_asset is only valid for an active verify_release audit (active mode: ${ctx.mode || "none"})`,
        );
    }
    if (!ctx.releaseIdentity
        || !ctx.resolvedSha
        || ctx.releaseIdentity.sourceCommitSha !== ctx.resolvedSha) {
        return failure("safe_fetch_release_asset requires a bound release ID/tag/source SHA");
    }

    const identity = {
        releaseId: ctx.releaseIdentity.releaseId,
        tagName: ctx.releaseIdentity.tagName,
        sourceCommitSha: ctx.releaseIdentity.sourceCommitSha,
    };
    const state = getReleaseAssetCoverageState(sessionId);
    const asset = state ? findEnumeratedReleaseAsset(state, assetId) : null;
    if (!asset) {
        return failure(
            `safe_fetch_release_asset refused: asset id ${assetId} was not discovered by safe_list_release_assets for this active audit`,
            { releaseAssetCoverage: buildReleaseAssetCoverageSnapshot(state) },
        );
    }

    const quarantinePath = deriveCanonicalQuarantinePath(ctx);
    if (!quarantinePath) {
        return failure("safe_fetch_release_asset could not derive the canonical quarantine path");
    }
    const assetPath = nodePath.join(quarantinePath, `${assetId}.bin`);
    if (!pathsEqual(nodePath.dirname(assetPath), quarantinePath)
        || nodePath.basename(assetPath) !== `${assetId}.bin`) {
        return failure("safe_fetch_release_asset canonical numeric filename containment check failed");
    }

    const mutate = (mutator) => mutateReleaseAssetCoverageState(
        sessionId,
        {
            ...identity,
            createState: () => createReleaseAssetCoverageState(identity),
        },
        mutator,
    );
    const coverage = () => buildReleaseAssetCoverageSnapshot(
        getReleaseAssetCoverageState(sessionId),
    );
    const recordedSuccess = getSuccessfulReleaseAsset(state, assetId);
    if (recordedSuccess) {
        if (!existsSync(assetPath) || statSync(assetPath).size !== recordedSuccess.sizeBytes) {
            mutate((live) => recordReleaseAssetFetchFailure(live, {
                assetId,
                kind: "recorded_file_missing_or_changed",
                error: "previously downloaded numeric asset file is missing or its byte count changed",
            }));
            return failure(
                `safe_fetch_release_asset refused: recorded asset ${assetId} is missing or changed in quarantine`,
                { releaseAssetCoverage: coverage() },
            );
        }
        mutate((live) => recordDuplicateReleaseAssetFetch(live, assetId));
        return success({
            asset: renderAsset(asset),
            assetPath,
            sizeBytes: recordedSuccess.sizeBytes,
            sha256: recordedSuccess.sha256,
            classification: recordedSuccess.classification,
            previewByteCount: recordedSuccess.previewByteCount,
            alreadyFetched: true,
            releaseAssetCoverage: coverage(),
        });
    }

    if (asset.sizeBytes > maxBytes.value) {
        mutate((live) => recordReleaseAssetFetchFailure(live, {
            assetId,
            kind: "oversized",
            error: `declared asset size ${asset.sizeBytes} exceeds hard cap ${maxBytes.value}`,
        }));
        return failure(
            `release asset ${assetId} declares ${asset.sizeBytes} bytes, exceeding the ${maxBytes.value}-byte cap`,
            { asset: renderAsset(asset), releaseAssetCoverage: coverage() },
        );
    }

    let bytes;
    try {
        const downloadAsset = dependencies.downloadAsset || downloadBoundAsset;
        bytes = await downloadAsset({
            owner: ctx.canonicalOwner,
            repo: ctx.canonicalRepo,
            releaseId: identity.releaseId,
            assetId,
            maxBytes: maxBytes.value,
        });
        if (!Buffer.isBuffer(bytes)) {
            throw new Error("release asset downloader did not return a Buffer");
        }
        if (bytes.length > maxBytes.value) {
            throw new Error(`download exceeded hard cap ${maxBytes.value}`);
        }
    } catch (err) {
        mutate((live) => recordReleaseAssetFetchFailure(live, {
            assetId,
            kind: /maxBuffer|hard cap|ENOBUFS/i.test(String(err?.message || err))
                ? "oversized"
                : "download_failed",
            error: err,
        }));
        return failure(`release asset ${assetId} download failed: ${err.message}`, {
            asset: renderAsset(asset),
            releaseAssetCoverage: coverage(),
        });
    }

    if (bytes.length !== asset.sizeBytes) {
        mutate((live) => recordReleaseAssetFetchFailure(live, {
            assetId,
            kind: "byte_mismatch",
            error: `listed size ${asset.sizeBytes}, downloaded ${bytes.length}`,
        }));
        return failure(
            `release asset ${assetId} byte-count mismatch: listed ${asset.sizeBytes}, downloaded ${bytes.length}`,
            { asset: renderAsset(asset), releaseAssetCoverage: coverage() },
        );
    }

    if (existsSync(assetPath)) {
        mutate((live) => recordReleaseAssetFetchFailure(live, {
            assetId,
            kind: "unrecorded_file_exists",
            error: "canonical numeric asset file already exists without a successful ledger record",
        }));
        return failure(
            `safe_fetch_release_asset refused to overwrite unrecorded file ${assetPath}`,
            { releaseAssetCoverage: coverage() },
        );
    }

    try {
        mkdirSync(quarantinePath, { recursive: true });
        writeFileSync(assetPath, bytes, { flag: "wx" });
        const writtenBytes = statSync(assetPath).size;
        if (writtenBytes !== bytes.length) {
            rmSync(assetPath, { force: true });
            throw new Error(`written byte count ${writtenBytes} did not match downloaded byte count ${bytes.length}`);
        }
    } catch (err) {
        mutate((live) => recordReleaseAssetFetchFailure(live, {
            assetId,
            kind: "write_failed",
            error: err,
        }));
        return failure(`release asset ${assetId} quarantine write failed: ${err.message}`, {
            releaseAssetCoverage: coverage(),
        });
    }

    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const classification = apiClientInternals.classifyActualBytes(bytes, `${assetId}.bin`).kind;
    const preview = bytes.subarray(0, RELEASE_ASSET_PREVIEW_BYTES);
    const recorded = mutate((live) => recordReleaseAssetFetchSuccess(live, {
        assetId,
        sizeBytes: bytes.length,
        sha256,
        path: assetPath,
        classification,
        previewByteCount: preview.length,
    }));
    if (!recorded.ok) {
        rmSync(assetPath, { force: true });
        return failure("release asset was written but could not be recorded in active-audit coverage state");
    }

    return success({
        asset: renderAsset(asset),
        assetPath,
        sizeBytes: bytes.length,
        sha256,
        classification,
        magicHex: bytes.subarray(0, 32).toString("hex"),
        previewBase64: preview.toString("base64"),
        previewByteCount: preview.length,
        alreadyFetched: false,
        releaseAssetCoverage: coverage(),
    });
}

function deriveCanonicalQuarantinePath(ctx) {
    if (!ctx.canonicalOwner || !ctx.canonicalRepo || !ctx.resolvedSha) return null;
    const canonical = buildQuarantinePath(
        ctx.buildRoot,
        ctx.canonicalOwner,
        ctx.canonicalRepo,
        ctx.resolvedSha,
    );
    if (ctx.expectedQuarantinePath && !pathsEqual(ctx.expectedQuarantinePath, canonical)) {
        return null;
    }
    return canonical;
}

function downloadBoundAsset({ owner, repo, assetId, maxBytes }) {
    const program = resolveTrustedProgram("gh", { forbiddenRoots: [] });
    if (!program) {
        throw new Error("could not resolve a trusted absolute path for 'gh' on PATH");
    }
    return execFileSync(
        program,
        [
            "api",
            "-H",
            "Accept: application/octet-stream",
            `repos/${owner}/${repo}/releases/assets/${assetId}`,
        ],
        {
            encoding: null,
            timeout: GH_DOWNLOAD_TIMEOUT_MS,
            windowsHide: true,
            env: { ...process.env, GH_PROMPT_DISABLED: "1" },
            stdio: ["ignore", "pipe", "pipe"],
            maxBuffer: maxBytes,
        },
    );
}

function resolveMaxBytes(value) {
    if (value === undefined || value === null) {
        return { ok: true, value: MAX_RELEASE_ASSET_BYTES };
    }
    if (!Number.isSafeInteger(value) || value < 1 || value > MAX_RELEASE_ASSET_BYTES) {
        return {
            ok: false,
            error: `max_bytes must be an integer from 1 through ${MAX_RELEASE_ASSET_BYTES} (100 MB hard maximum)`,
        };
    }
    return { ok: true, value };
}

function renderAsset(asset) {
    return {
        id: asset.id,
        name: asset.name,
        nameTruncated: asset.nameTruncated,
        contentType: asset.contentType,
        sizeBytes: asset.sizeBytes,
        digest: asset.digest,
    };
}

function normalizePositiveId(value) {
    if (Number.isSafeInteger(value) && value > 0) return String(value);
    if (typeof value === "string" && /^[1-9][0-9]{0,19}$/.test(value)) return value;
    return null;
}

function pathsEqual(left, right) {
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, ...data }, null, 2),
        resultType: "success",
    };
}

function failure(message, data = {}) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, error: message, ...data }, null, 2),
        resultType: "failure",
    };
}

export const __internals = {
    deriveCanonicalQuarantinePath,
    downloadBoundAsset,
    normalizePositiveId,
    resolveMaxBytes,
};
