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
    getActiveAudit,
    recordAcquisitionCoverageState,
    recordReleaseIdentity,
    recordResolvedArtifactPaths,
    recordResolvedSha,
    recordTreeEnumerationState,
} from "../enforcement.mjs";
import { runHandler } from "../handler.mjs";
import { createCoverageState } from "../safeWrappers/coverageAccounting.mjs";
import { recordOutcomeHandler } from "../safeWrappers/outcomeWrapper.mjs";
import { safeFetchReleaseAssetHandler } from "../safeWrappers/releaseAssetFetchWrapper.mjs";
import { safeListReleaseAssetsHandler } from "../safeWrappers/releaseAssetListWrapper.mjs";
import { finalizeReportHandler } from "../safeWrappers/reportWrapper.mjs";
import { clearRecordedOutcome } from "../safeWrappers/state.mjs";
import {
    buildClonePath,
    buildQuarantinePath,
    buildReportPath,
} from "../urlParser.mjs";

const HERE = nodePath.dirname(fileURLToPath(import.meta.url));
const SCRATCH = nodePath.join(HERE, ".release-verdict-scratch");
const OWNER = "OctoCat";
const REPO = "Demo";
const SHA = "d".repeat(40);
const ROOT = "e".repeat(40);
const TAG_REF = "f".repeat(40);
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
    return `release-verdict-${label}-${sequence}`;
}

function parse(result) {
    return JSON.parse(result.textResultForLlm);
}

function activateUrlAudit(label, mode) {
    const sessionId = session(label);
    activateAudit({
        sessionId,
        buildPath: SCRATCH,
        mode,
        expectedClonePath: buildClonePath(SCRATCH, OWNER, REPO, "0".repeat(40)),
        owner: OWNER,
        repo: REPO,
    });
    assert.equal(recordResolvedSha(sessionId, SHA), true);
    assert.equal(recordResolvedArtifactPaths(sessionId, {
        reportPath: buildReportPath(SCRATCH, OWNER, REPO, SHA),
    }), true);
    return sessionId;
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
        ref: "baseline",
        refType: "release_tag",
        urlKind: "release",
        releaseSelector: "tag",
    });
    assert.equal(recordResolvedSha(sessionId, SHA), true);
    assert.equal(recordReleaseIdentity(sessionId, {
        releaseId: "123",
        tagName: "baseline",
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
    markSourceCoverageComplete(sessionId);
    return sessionId;
}

function markSourceCoverageComplete(sessionId) {
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

async function recordOutcome(sessionId, {
    verdict,
    complete,
    criticalCount = 0,
    highCount = 0,
}) {
    return recordOutcomeHandler(
        {
            audit_id: getActiveAudit(sessionId).auditId,
            verdict,
            critical_count: criticalCount,
            high_count: highCount,
            complete,
        },
        { sessionId },
    );
}

async function listReleaseAssets(sessionId, assets) {
    return safeListReleaseAssetsHandler(
        {
            owner: OWNER,
            repo: REPO,
            release_id: "123",
            tag_name: "baseline",
            source_sha: SHA,
        },
        { sessionId },
        {
            requestRelease: async () => ({
                id: 123,
                tag_name: "baseline",
                assets,
            }),
        },
    );
}

function reportArgs(body) {
    return {
        owner: OWNER,
        repo: REPO,
        resolved_sha: SHA,
        markdown_body: body,
    };
}

test("verify_release trusted verdict is blocked for partial assets and incomplete is allowed", async () => {
    const sessionId = activateReleaseAudit("partial-assets");
    try {
        assert.equal((await listReleaseAssets(sessionId, [
            { id: 1, name: "one.bin", size: 3, content_type: "application/octet-stream" },
            { id: 2, name: "two.bin", size: 3, content_type: "application/octet-stream" },
        ])).resultType, "success");
        assert.equal((await safeFetchReleaseAssetHandler(
            { asset_id: "1" },
            { sessionId },
            { downloadAsset: async () => Buffer.from("one") },
        )).resultType, "success");

        const trusted = await finalizeReportHandler(
            reportArgs("# report\n\nVerdict: no red flags found"),
            { sessionId },
        );
        assert.equal(trusted.resultType, "failure");
        const blocked = parse(trusted);
        assert.match(blocked.error, /incomplete release-asset coverage/i);
        assert.equal(blocked.releaseAssetCoverage.acquisition.skippedAssets, 1);

        const incomplete = await finalizeReportHandler(
            reportArgs("# INCOMPLETE — DO NOT TRUST\n\nVerdict: incomplete"),
            { sessionId },
        );
        assert.equal(incomplete.resultType, "success");
        const finalized = parse(incomplete);
        const markdown = readFileSync(finalized.reportPath, "utf-8");
        assert.match(markdown, /Trusted release-asset coverage snapshot/);
        assert.match(markdown, /requiredReleaseAssetAcquisitionComplete/);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("successfully enumerated zero-assets release may finalize a trusted verdict", async () => {
    const sessionId = activateReleaseAudit("zero-assets");
    try {
        const listed = parse(await listReleaseAssets(sessionId, []));
        assert.equal(listed.releaseAssetCoverage.enumeration.zeroAssets, true);
        const finalized = await finalizeReportHandler(
            reportArgs("# report\n\nVerdict: no red flags found"),
            { sessionId },
        );
        assert.equal(finalized.resultType, "success");
        const body = parse(finalized);
        assert.equal(body.releaseAssetCoverage.requiredReleaseAssetAcquisitionComplete, true);
        assert.equal(existsSync(body.reportPath), true);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("baseline council finalization rejects legacy Markdown verdict ownership", async () => {
    const sessionId = activateUrlAudit("legacy-markdown", "audit_and_safe_build_council");
    try {
        assert.equal((await recordOutcome(sessionId, {
            verdict: "incomplete",
            complete: false,
        })).resultType, "success");
        const refused = await finalizeReportHandler(
            reportArgs("# report\n\nVerdict: no red flags found\n\nCouncil coverage complete: true"),
            { sessionId },
        );
        assert.equal(refused.resultType, "failure");
        assert.match(refused.textResultForLlm, /refused fields: markdown_body/i);
    } finally {
        clearRecordedOutcome(sessionId);
        deactivateAudit(sessionId);
    }
});

test("baseline council finalization requires the trusted ledger even for incomplete output", async () => {
    const invalidSession = activateUrlAudit("missing-ledger", "audit_and_safe_build_council");
    try {
        assert.equal((await recordOutcome(invalidSession, {
            verdict: "incomplete",
            complete: false,
        })).resultType, "success");
        const invalid = await finalizeReportHandler(
            {
                owner: OWNER,
                repo: REPO,
                resolved_sha: SHA,
                operator_decisions: [],
            },
            { sessionId: invalidSession },
        );
        assert.equal(invalid.resultType, "failure");
        assert.match(
            invalid.textResultForLlm,
            /baseline council finalization[\s\S]*trusted finding ledger/i,
        );
    } finally {
        clearRecordedOutcome(invalidSession);
        deactivateAudit(invalidSession);
    }
});

test("deterministic report finalization remains unaffected by council outcome gates", async () => {
    const sessionId = activateUrlAudit("deterministic", "audit_and_safe_build");
    try {
        const result = await finalizeReportHandler(
            reportArgs("# report\n\nVerdict: low"),
            { sessionId },
        );
        assert.equal(result.resultType, "success");
    } finally {
        deactivateAudit(sessionId);
    }
});

test("packet orchestration derives outcomes at finalization and uses release wrappers", () => {
    const source = runHandler(
        {
            url: "https://github.com/octocat/demo/tree/main",
            mode: "audit_source_council",
            build_root: SCRATCH,
        },
        { sessionId: session("packet-source") },
    );
    assert.equal(source.resultType, "success");
    assert.match(source.textResultForLlm, /zerotrust_finalize_assurance_validation/);
    assert.match(source.textResultForLlm, /const finalizeResult = zerotrust_finalize_report\(\{/);
    assert.doesNotMatch(source.textResultForLlm, /zerotrust_record_council_outcome\(\{/);

    const build = runHandler(
        {
            url: "https://github.com/octocat/demo/tree/main",
            mode: "audit_and_safe_build_council",
            build_root: SCRATCH,
            i_understand_build_executes_code: true,
        },
        { sessionId: session("packet-build") },
    );
    assert.equal(build.resultType, "success");
    const finalizerCall = build.textResultForLlm.indexOf(
        "const finalizeResult = zerotrust_finalize_report({",
    );
    const hostExecutionInstructions = build.textResultForLlm.indexOf(
        "Use `zerotrust_safe_install` for installs",
        finalizerCall,
    );
    assert.ok(finalizerCall >= 0);
    assert.ok(hostExecutionInstructions > finalizerCall);

    const localPath = nodePath.join(SCRATCH, "local-source");
    mkdirSync(localPath, { recursive: true });
    const local = runHandler(
        {
            local_path: localPath,
            mode: "audit_local_source_council",
            build_root: SCRATCH,
            i_understand_local_path_reads_my_disk: true,
        },
        { sessionId: session("packet-local") },
    );
    assert.equal(local.resultType, "success");
    assert.match(local.textResultForLlm, /zerotrust_finalize_assurance_validation/);
    assert.match(local.textResultForLlm, /const finalizeResult = zerotrust_finalize_report\(\{/);
    assert.doesNotMatch(local.textResultForLlm, /zerotrust_record_council_outcome\(\{/);

    const release = runHandler(
        {
            url: "https://github.com/octocat/demo/releases/tag/baseline",
            mode: "verify_release",
            build_root: SCRATCH,
        },
        { sessionId: session("packet-release") },
    );
    assert.equal(release.resultType, "success");
    assert.match(release.textResultForLlm, /zerotrust_safe_list_release_assets/);
    assert.match(release.textResultForLlm, /zerotrust_safe_fetch_release_asset/);
    assert.doesNotMatch(release.textResultForLlm, /Invoke-WebRequest[\s\S]*-OutFile/i);
});

test("extension registers bounded release wrapper schemas", () => {
    const extensionSource = readFileSync(nodePath.join(HERE, "..", "extension.mjs"), "utf-8");
    const listBlock = extensionSource.slice(
        extensionSource.indexOf('name: "zerotrust_safe_list_release_assets"'),
        extensionSource.indexOf('name: "zerotrust_safe_fetch_release_asset"'),
    );
    assert.match(listBlock, /required:\s*\["owner", "repo", "release_id", "tag_name", "source_sha"\]/);
    assert.match(listBlock, /maximum 512 tracked unique assets/i);

    const fetchBlock = extensionSource.slice(
        extensionSource.indexOf('name: "zerotrust_safe_fetch_release_asset"'),
        extensionSource.indexOf("// ----- Substitutional-safety wrapper tools"),
    );
    assert.match(fetchBlock, /maximum:\s*104857600/);
    assert.match(fetchBlock, /numeric asset ID/i);
    assert.doesNotMatch(fetchBlock, /asset_name|download_url|browser_download_url/);
});
