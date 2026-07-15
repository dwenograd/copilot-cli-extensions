import { after, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import {
    existsSync,
    mkdirSync,
    readFileSync,
    rmSync,
} from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";

import {
    activateAudit,
    deactivateAudit,
    getReleaseAssetCoverageState,
    recordAcquisitionCoverageState,
    recordReleaseIdentity,
    recordResolvedArtifactPaths,
    recordResolvedSha,
    recordTreeEnumerationState,
} from "../enforcement.mjs";
import { cleanupQuarantineHandler } from "../safeWrappers/quarantineWrapper.mjs";
import { createCoverageState } from "../safeWrappers/coverageAccounting.mjs";
import { safeFetchReleaseAssetHandler } from "../safeWrappers/releaseAssetFetchWrapper.mjs";
import { safeListReleaseAssetsHandler } from "../safeWrappers/releaseAssetListWrapper.mjs";
import { MAX_RELEASE_ASSET_BYTES } from "../safeWrappers/releaseAssetCoverage.mjs";
import {
    buildClonePath,
    buildQuarantinePath,
    buildReportPath,
} from "../urlParser.mjs";

const HERE = nodePath.dirname(fileURLToPath(import.meta.url));
const SCRATCH = nodePath.join(HERE, ".release-assets-scratch");
const OWNER = "OctoCat";
const REPO = "Demo";
const SHA = "a".repeat(40);
const ROOT = "b".repeat(40);
const TAG_REF = "c".repeat(40);
const RELEASE_ID = "12345";
const TAG = "v1.2.3";
let sequence = 0;

beforeEach(() => {
    rmSync(SCRATCH, { recursive: true, force: true });
    mkdirSync(SCRATCH, { recursive: true });
});

after(() => {
    rmSync(SCRATCH, { recursive: true, force: true });
});

function session(label) {
    sequence += 1;
    return `release-assets-${label}-${sequence}`;
}

function activateReleaseAudit(label) {
    const sessionId = session(label);
    activateAudit({
        sessionId,
        buildPath: SCRATCH,
        mode: "verify_release",
        expectedClonePath: buildClonePath(SCRATCH, OWNER, REPO, "0".repeat(40)),
        owner: OWNER,
        repo: REPO,
        ref: TAG,
        refType: "release_tag",
        urlKind: "release",
        releaseSelector: "tag",
    });
    assert.equal(recordResolvedSha(sessionId, SHA), true);
    assert.equal(recordReleaseIdentity(sessionId, {
        releaseId: RELEASE_ID,
        tagName: TAG,
        sourceCommitSha: SHA,
        rootTreeSha: ROOT,
        tagRefSha: TAG_REF,
        tagObjectSha: null,
        annotatedTag: false,
        tagPeelDepth: 0,
        targetCommitish: "main",
    }), true);
    assert.equal(recordResolvedArtifactPaths(sessionId, {
        reportPath: buildReportPath(SCRATCH, OWNER, REPO, SHA),
        quarantinePath: buildQuarantinePath(SCRATCH, OWNER, REPO, SHA),
    }), true);
    return sessionId;
}

function listArgs(overrides = {}) {
    return {
        owner: OWNER,
        repo: REPO,
        release_id: RELEASE_ID,
        tag_name: TAG,
        source_sha: SHA,
        ...overrides,
    };
}

function releaseResponse(assets = [], overrides = {}) {
    return {
        id: Number(RELEASE_ID),
        tag_name: TAG,
        assets,
        ...overrides,
    };
}

function asset(id, name, size, overrides = {}) {
    return {
        id,
        name,
        size,
        content_type: "application/octet-stream",
        ...overrides,
    };
}

function parse(result) {
    return JSON.parse(result.textResultForLlm);
}

async function list(sessionId, assets, overrides = {}) {
    return safeListReleaseAssetsHandler(
        listArgs(overrides.args),
        { sessionId },
        {
            requestRelease: async () => releaseResponse(assets, overrides.response),
        },
    );
}

test("release asset listing rejects caller and API identity mismatches", async () => {
    const callerSession = activateReleaseAudit("caller-mismatch");
    try {
        const callerMismatch = await safeListReleaseAssetsHandler(
            listArgs({ release_id: "999" }),
            { sessionId: callerSession },
            { requestRelease: async () => releaseResponse([]) },
        );
        assert.equal(callerMismatch.resultType, "failure");
        assert.match(callerMismatch.textResultForLlm, /does not match.*already-bound/i);
    } finally {
        deactivateAudit(callerSession);
    }

    const apiSession = activateReleaseAudit("api-mismatch");
    try {
        const apiMismatch = await safeListReleaseAssetsHandler(
            listArgs(),
            { sessionId: apiSession },
            {
                requestRelease: async () => releaseResponse([], {
                    id: 999,
                    tag_name: "v9",
                }),
            },
        );
        assert.equal(apiMismatch.resultType, "failure");
        const body = parse(apiMismatch);
        assert.match(body.error, /release identity mismatch/i);
        assert.equal(body.releaseAssetCoverage.enumeration.recorded, false);
        assert.equal(body.releaseAssetCoverage.enumeration.listFailureAttempts, 1);
    } finally {
        deactivateAudit(apiSession);
    }
});

test("undiscovered release asset IDs are refused without downloading", async () => {
    const sessionId = activateReleaseAudit("undiscovered");
    let downloads = 0;
    try {
        assert.equal((await list(sessionId, [asset(1, "one.bin", 3)])).resultType, "success");
        const result = await safeFetchReleaseAssetHandler(
            { asset_id: "2" },
            { sessionId },
            {
                downloadAsset: async () => {
                    downloads += 1;
                    return Buffer.from("bad");
                },
            },
        );
        assert.equal(result.resultType, "failure");
        assert.match(result.textResultForLlm, /was not discovered/i);
        assert.equal(downloads, 0);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("attacker-controlled traversal names never affect the numeric quarantine path", async () => {
    const sessionId = activateReleaseAudit("traversal-name");
    const bytes = Buffer.from("MZ release bytes");
    try {
        const listed = await list(sessionId, [
            asset(77, "..\\..\\evil.exe", bytes.length),
        ]);
        assert.equal(listed.resultType, "success");
        const fetched = await safeFetchReleaseAssetHandler(
            { asset_id: "77" },
            { sessionId },
            { downloadAsset: async () => bytes },
        );
        assert.equal(fetched.resultType, "success");
        const body = parse(fetched);
        const quarantine = buildQuarantinePath(SCRATCH, OWNER, REPO, SHA);
        assert.equal(body.assetPath, nodePath.join(quarantine, "77.bin"));
        assert.equal(readFileSync(body.assetPath).equals(bytes), true);
        assert.equal(existsSync(nodePath.join(SCRATCH, "evil.exe")), false);
        assert.equal(body.asset.name, "..\\..\\evil.exe");
    } finally {
        deactivateAudit(sessionId);
    }
});

test("release asset size cap is absolute and oversized assets remain incomplete", async () => {
    const sessionId = activateReleaseAudit("size-cap");
    let downloads = 0;
    try {
        assert.equal((await list(sessionId, [
            asset(8, "huge.bin", MAX_RELEASE_ASSET_BYTES + 1),
        ])).resultType, "success");
        const oversized = await safeFetchReleaseAssetHandler(
            { asset_id: "8" },
            { sessionId },
            {
                downloadAsset: async () => {
                    downloads += 1;
                    return Buffer.alloc(0);
                },
            },
        );
        assert.equal(oversized.resultType, "failure");
        const body = parse(oversized);
        assert.match(body.error, /exceeding.*cap/i);
        assert.equal(body.releaseAssetCoverage.acquisition.oversizedAssets, 1);
        assert.equal(body.releaseAssetCoverage.requiredReleaseAssetAcquisitionComplete, false);
        assert.equal(downloads, 0);

        const raised = await safeFetchReleaseAssetHandler(
            { asset_id: "8", max_bytes: MAX_RELEASE_ASSET_BYTES + 1 },
            { sessionId },
        );
        assert.equal(raised.resultType, "failure");
        assert.match(raised.textResultForLlm, /100 MB hard maximum/i);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("downloaded byte-count mismatch is recorded and no file is written", async () => {
    const sessionId = activateReleaseAudit("byte-mismatch");
    try {
        assert.equal((await list(sessionId, [asset(9, "wrong.bin", 10)])).resultType, "success");
        const mismatch = await safeFetchReleaseAssetHandler(
            { asset_id: "9" },
            { sessionId },
            { downloadAsset: async () => Buffer.from("short") },
        );
        assert.equal(mismatch.resultType, "failure");
        const body = parse(mismatch);
        assert.match(body.error, /byte-count mismatch/i);
        assert.equal(body.releaseAssetCoverage.acquisition.byteMismatchAssets, 1);
        assert.equal(
            existsSync(nodePath.join(buildQuarantinePath(SCRATCH, OWNER, REPO, SHA), "9.bin")),
            false,
        );
    } finally {
        deactivateAudit(sessionId);
    }
});

test("partial and zero-asset ledgers are distinguished", async () => {
    const partialSession = activateReleaseAudit("partial");
    try {
        assert.equal((await list(partialSession, [
            asset(1, "one.bin", 3),
            asset(2, "two.bin", 3),
        ])).resultType, "success");
        assert.equal((await safeFetchReleaseAssetHandler(
            { asset_id: "1" },
            { sessionId: partialSession },
            { downloadAsset: async () => Buffer.from("one") },
        )).resultType, "success");
        const snapshot = parse(await safeFetchReleaseAssetHandler(
            { asset_id: "1" },
            { sessionId: partialSession },
        )).releaseAssetCoverage;
        assert.equal(snapshot.requiredReleaseAssetAcquisitionComplete, false);
        assert.equal(snapshot.acquisition.uniqueDownloadedAndHashedAssets, 1);
        assert.equal(snapshot.acquisition.skippedAssets, 1);
    } finally {
        deactivateAudit(partialSession);
    }

    const zeroSession = activateReleaseAudit("zero");
    try {
        const zero = parse(await list(zeroSession, []));
        assert.equal(zero.releaseAssetCoverage.enumeration.zeroAssets, true);
        assert.equal(zero.releaseAssetCoverage.requiredReleaseAssetAcquisitionComplete, true);
    } finally {
        deactivateAudit(zeroSession);
    }
});

test("duplicate fetch is idempotent and does not inflate unique coverage", async () => {
    const sessionId = activateReleaseAudit("duplicate");
    let downloads = 0;
    try {
        assert.equal((await list(sessionId, [asset(4, "four.bin", 4)])).resultType, "success");
        const dependencies = {
            downloadAsset: async () => {
                downloads += 1;
                return Buffer.from("four");
            },
        };
        assert.equal((await safeFetchReleaseAssetHandler(
            { asset_id: "4" },
            { sessionId },
            dependencies,
        )).resultType, "success");
        const duplicate = parse(await safeFetchReleaseAssetHandler(
            { asset_id: "4" },
            { sessionId },
            dependencies,
        ));
        assert.equal(duplicate.alreadyFetched, true);
        assert.equal(duplicate.releaseAssetCoverage.acquisition.uniqueDownloadedAndHashedAssets, 1);
        assert.equal(duplicate.releaseAssetCoverage.acquisition.duplicateFetchCalls, 1);
        assert.equal(downloads, 1);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("cleanup removes only the canonical quarantine path returned by the path builder", async () => {
    const sessionId = activateReleaseAudit("cleanup");
    try {
        assert.equal((await list(sessionId, [asset(5, "five.bin", 4)])).resultType, "success");
        assert.equal((await safeFetchReleaseAssetHandler(
            { asset_id: "5" },
            { sessionId },
            { downloadAsset: async () => Buffer.from("five") },
        )).resultType, "success");
        const canonical = buildQuarantinePath(SCRATCH, OWNER, REPO, SHA);
        assert.equal(existsSync(canonical), true);

        const cleaned = await cleanupQuarantineHandler({}, { sessionId });
        assert.equal(cleaned.resultType, "success");
        assert.equal(parse(cleaned).quarantinePath, canonical);
        assert.equal(existsSync(canonical), false);
        assert.equal(getReleaseAssetCoverageState(sessionId) !== null, true);
    } finally {
        deactivateAudit(sessionId);
    }
});

export function markSourceCoverageComplete(sessionId) {
    assert.equal(recordTreeEnumerationState(sessionId, {
        commitSha: SHA,
        rootTreeSha: ROOT,
        entries: [],
        duplicateEntryCount: 0,
        unresolvedSubtrees: [],
        coverageBlockers: [],
        stateTrackingTruncated: false,
        discoveryTruncated: false,
    }), true);
    assert.equal(
        recordAcquisitionCoverageState(sessionId, createCoverageState(SHA, ROOT)),
        true,
    );
}
