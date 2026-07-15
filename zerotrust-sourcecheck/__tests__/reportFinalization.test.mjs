import { after, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import {
    existsSync,
    mkdirSync,
    readFileSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";

import {
    activateAudit,
    deactivateAudit,
    getActiveAudit,
    recordResolvedArtifactPaths,
    recordResolvedSha,
} from "../enforcement.mjs";
import { buildInstructionPacket } from "../packet.mjs";
import {
    finalizeReportHandler,
    __internals as reportInternals,
} from "../safeWrappers/reportWrapper.mjs";
import { buildClonePath, buildReportPath } from "../urlParser.mjs";

const HERE = nodePath.dirname(fileURLToPath(import.meta.url));
const SCRATCH = nodePath.join(HERE, ".report-finalization-scratch");
const SHA = "abcdef0123456789abcdef0123456789abcdef01";
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
    return `report-finalization-${label}-${sequence}`;
}

function activateUrlAudit({
    sessionId,
    mode = "audit_source",
    owner = "OctoCat",
    repo = "Demo",
    sha = SHA,
} = {}) {
    activateAudit({
        sessionId,
        buildPath: SCRATCH,
        mode,
        expectedClonePath: buildClonePath(SCRATCH, owner, repo, "0".repeat(40)),
        owner,
        repo,
    });
    assert.equal(recordResolvedSha(sessionId, sha), true);
    const reportDir = buildReportPath(SCRATCH, owner, repo, sha);
    assert.equal(
        recordResolvedArtifactPaths(sessionId, { reportPath: reportDir }),
        true,
    );
    return reportDir;
}

function parseResult(result) {
    return JSON.parse(result.textResultForLlm);
}

test("URL reports reject owner/repo/SHA identity mismatches", async () => {
    for (const [label, overrides] of [
        ["owner", { owner: "someone-else" }],
        ["repo", { repo: "other-repo" }],
        ["sha", { resolved_sha: "1".repeat(40) }],
    ]) {
        const sessionId = session(`mismatch-${label}`);
        activateUrlAudit({ sessionId });
        try {
            const result = await finalizeReportHandler(
                {
                    owner: "octocat",
                    repo: "demo",
                    resolved_sha: SHA,
                    markdown_body: "# report\n\nVerdict: incomplete",
                    ...overrides,
                },
                { sessionId },
            );
            assert.equal(result.resultType, "failure");
            assert.match(result.textResultForLlm, /does not match the active audit/i);
        } finally {
            deactivateAudit(sessionId);
        }
    }
});

test("URL reports use the full SHA and return canonical reportPath", async () => {
    const sessionId = session("full-sha");
    const reportDir = activateUrlAudit({ sessionId });
    try {
        const result = await finalizeReportHandler(
            {
                owner: "octocat",
                repo: "demo",
                resolved_sha: SHA,
                markdown_body: "# report\n\nVerdict: incomplete",
            },
            { sessionId },
        );
        assert.equal(result.resultType, "success");
        const body = parseResult(result);
        assert.equal(body.reportIdentity.resolvedSha, SHA);
        assert.equal(body.reportPath, nodePath.join(reportDir, "REPORT.md"));
        assert.match(body.reportPath, /zt-v1-[0-9a-f]{64}[\\/]REPORT\.md$/);
        assert.equal(existsSync(body.reportPath), true);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("report finalization is exactly once and changed retries cannot rewrite", async () => {
    const sessionId = session("exactly-once");
    activateUrlAudit({ sessionId, mode: "audit_and_safe_build" });
    try {
        const first = await finalizeReportHandler(
            {
                owner: "octocat",
                repo: "demo",
                resolved_sha: SHA,
                markdown_body: "# original\n\nVerdict: low",
            },
            { sessionId },
        );
        assert.equal(first.resultType, "success");
        const firstBody = parseResult(first);
        assert.equal(getActiveAudit(sessionId).reportFinalization.reportPath, firstBody.reportPath);
        const original = readFileSync(firstBody.reportPath, "utf-8");

        const retry = await finalizeReportHandler(
            {
                owner: "octocat",
                repo: "demo",
                resolved_sha: SHA,
                markdown_body: "# replacement\n\nVerdict: critical",
            },
            { sessionId },
        );
        assert.equal(retry.resultType, "success");
        const retryBody = parseResult(retry);
        assert.equal(retryBody.alreadyFinalized, true);
        assert.equal(retryBody.reportPath, firstBody.reportPath);
        assert.equal(readFileSync(firstBody.reportPath, "utf-8"), original);
        assert.doesNotMatch(original, /replacement/);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("pre-existing unrecorded REPORT.md is conservatively refused", async () => {
    const sessionId = session("pre-existing");
    const reportDir = activateUrlAudit({
        sessionId,
        mode: "audit_and_safe_build",
    });
    mkdirSync(reportDir, { recursive: true });
    const reportPath = nodePath.join(reportDir, "REPORT.md");
    writeFileSync(reportPath, "untrusted pre-existing body");
    try {
        const result = await finalizeReportHandler(
            {
                owner: "octocat",
                repo: "demo",
                resolved_sha: SHA,
                markdown_body: "# replacement\n\nVerdict: low",
            },
            { sessionId },
        );
        assert.equal(result.resultType, "failure");
        assert.match(result.textResultForLlm, /already exists without a finalization record/i);
        assert.equal(readFileSync(reportPath, "utf-8"), "untrusted pre-existing body");
    } finally {
        deactivateAudit(sessionId);
    }
});

test("local reports use only the active canonical slug/timestamp identity", async () => {
    const sessionId = session("local");
    const localPath = nodePath.join(SCRATCH, "Sample Project");
    const timestamp = "20260713092953";
    const expectedReportPath = nodePath.join(
        SCRATCH,
        "_reports",
        `local-sample-project-${timestamp}`,
    );
    activateAudit({
        sessionId,
        buildPath: SCRATCH,
        mode: "audit_local_source",
        localPath,
        expectedReportPath,
    });
    try {
        const redirected = await finalizeReportHandler(
            {
                markdown_body: "# local report",
                report_path: nodePath.join(SCRATCH, "_reports", "attacker"),
            },
            { sessionId },
        );
        assert.equal(redirected.resultType, "failure");
        assert.match(redirected.textResultForLlm, /do not accept caller-supplied identity\/path/i);

        const result = await finalizeReportHandler(
            { markdown_body: "# local report" },
            { sessionId },
        );
        assert.equal(result.resultType, "success");
        const body = parseResult(result);
        assert.equal(body.reportIdentity.sourceKind, "local");
        assert.equal(body.reportIdentity.localSlug, "sample-project");
        assert.equal(body.reportIdentity.localTimestamp, timestamp);
        assert.equal(
            body.reportPath,
            nodePath.join(expectedReportPath, "REPORT.md"),
        );
    } finally {
        deactivateAudit(sessionId);
    }
});

test("report finalization refuses inactive sessions", async () => {
    const result = await finalizeReportHandler(
        {
            owner: "octocat",
            repo: "demo",
            resolved_sha: SHA,
            markdown_body: "# report",
        },
        { sessionId: session("inactive") },
    );
    assert.equal(result.resultType, "failure");
    assert.match(result.textResultForLlm, /no active audit/i);
});

test("API-direct no-red-flags report is blocked when mandatory acquisition is incomplete", async () => {
    const sessionId = session("coverage-gate");
    activateUrlAudit({ sessionId });
    try {
        const result = await finalizeReportHandler(
            {
                owner: "octocat",
                repo: "demo",
                resolved_sha: SHA,
                markdown_body: "# report\n\nVerdict: no red flags found",
            },
            { sessionId },
        );
        assert.equal(result.resultType, "failure");
        const body = parseResult(result);
        assert.equal(body.acquisitionCoverage.requiredAcquisitionComplete, false);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("API-direct trusted severity report is blocked when mandatory acquisition is incomplete", async () => {
    const sessionId = session("coverage-gate-high");
    activateUrlAudit({ sessionId });
    try {
        for (const markdown_body of [
            "# report\n\nVerdict: high",
            "# report\n\nVerdict: incomplete\n\nVerdict: high",
        ]) {
            const result = await finalizeReportHandler(
                {
                    owner: "octocat",
                    repo: "demo",
                    resolved_sha: SHA,
                    markdown_body,
                },
                { sessionId },
            );
            assert.equal(result.resultType, "failure");
            const body = parseResult(result);
            assert.match(body.error, /only verdict 'incomplete'/i);
            assert.equal(body.acquisitionCoverage.requiredAcquisitionComplete, false);
        }
    } finally {
        deactivateAudit(sessionId);
    }
});

test("final report includes the bounded trusted acquisition snapshot and enforces final 1MB cap", async () => {
    const snapshotSession = session("snapshot");
    activateUrlAudit({ sessionId: snapshotSession });
    try {
        const result = await finalizeReportHandler(
            {
                owner: "octocat",
                repo: "demo",
                resolved_sha: SHA,
                markdown_body: "# report\n\nVerdict: incomplete",
            },
            { sessionId: snapshotSession },
        );
        assert.equal(result.resultType, "success");
        const body = parseResult(result);
        const markdown = readFileSync(body.reportPath, "utf-8");
        assert.match(markdown, /## Trusted acquisition coverage snapshot/);
        assert.match(markdown, /requiredAcquisitionComplete/);
    } finally {
        deactivateAudit(snapshotSession);
    }

    const capSession = session("cap");
    activateUrlAudit({ sessionId: capSession });
    try {
        const result = await finalizeReportHandler(
            {
                owner: "octocat",
                repo: "demo",
                resolved_sha: SHA,
                markdown_body: "X".repeat(reportInternals.MAX_REPORT_BYTES),
            },
            { sessionId: capSession },
        );
        assert.equal(result.resultType, "failure");
        assert.match(result.textResultForLlm, /exceeds 1048576 bytes/i);
    } finally {
        deactivateAudit(capSession);
    }
});

function urlPacket(mode, { council = false } = {}) {
    return buildInstructionPacket({
        mode,
        parsed: {
            owner: "octocat",
            repo: "demo",
            ref: "main",
            refType: "branch_or_tag",
            kind: mode === "verify_release" ? "release" : "tree",
            releaseSelector: mode === "verify_release" ? "tag" : null,
            canonicalUrl: mode === "verify_release"
                ? "https://github.com/octocat/demo/releases/tag/v1"
                : "https://github.com/octocat/demo/tree/main",
        },
        refOverride: null,
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "report-finalization-packet",
        scrubNote: null,
        privateRepoAck: true,
        buildExecAck: mode.includes("build"),
        unsafeAck: mode.includes("full"),
        buildRoot: SCRATCH,
        expectedClonePath: nodePath.join(SCRATCH, `octocat-demo-${"0".repeat(40)}`),
        expectedReportPath: nodePath.join(
            SCRATCH,
            "_reports",
            `octocat-demo-${"0".repeat(40)}`,
        ),
        expectedQuarantinePath: nodePath.join(
            SCRATCH,
            "_quarantine",
            `octocat-demo-${"0".repeat(40)}`,
        ),
        placeholderSha: true,
        councilManifest: council ? [{
            id: "mandatory-test",
            category: "execution",
            model: "gpt-5.6-sol",
            tier: "source-inspection",
            mandatory: true,
            angle: "test",
            ignore_clauses: [],
        }] : null,
        councilJudgeModel: council ? "gpt-5.6-sol" : null,
        councilSubJudgeModel: council ? "gpt-5.6-sol" : null,
        maxPremiumCalls: council ? 10 : null,
    });
}

function localPacket(mode) {
    return buildInstructionPacket({
        mode,
        target: {
            kind: "local",
            localPath: nodePath.join(SCRATCH, "sample"),
            slug: "sample",
        },
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "report-finalization-local",
        scrubNote: null,
        buildRoot: SCRATCH,
        expectedReportPath: nodePath.join(
            SCRATCH,
            "_reports",
            "local-sample-20260713092953",
        ),
        councilManifest: null,
        councilJudgeModel: null,
        councilSubJudgeModel: null,
        maxPremiumCalls: null,
    });
}

test("every mode routes its only report write through the finalizer wrapper", () => {
    const packets = new Map([
        ["metadata_only", urlPacket("metadata_only")],
        ["audit_source", urlPacket("audit_source")],
        ["audit_source_council", urlPacket("audit_source_council", { council: true })],
        ["verify_release", urlPacket("verify_release")],
        ["audit_and_safe_build", urlPacket("audit_and_safe_build")],
        ["audit_and_full_build", urlPacket("audit_and_full_build")],
        ["audit_and_safe_build_council", urlPacket("audit_and_safe_build_council", { council: true })],
        ["audit_and_full_build_council", urlPacket("audit_and_full_build_council", { council: true })],
        ["audit_local_source", localPacket("audit_local_source")],
        ["audit_local_source_council", localPacket("audit_local_source_council")],
    ]);

    for (const [mode, packet] of packets) {
        assert.equal(
            (packet.match(/zerotrust_finalize_report\(\{/g) || []).length,
            1,
            `${mode} must contain exactly one finalizer call`,
        );
        assert.doesNotMatch(
            packet,
            /New-Item\s+-ItemType\s+Directory[^\n]*(?:_reports|REPORT\.md)/i,
            `${mode} must not create report directories with raw shell instructions`,
        );
        assert.doesNotMatch(
            packet,
            /(?:Out-File|Set-Content)\s+(?:-Path\s+)?["'][^"']*REPORT\.md/i,
            `${mode} must not write reports through raw filesystem commands`,
        );
        assert.match(packet, /finalizeResult\.reportPath/);
    }
});

test("council incomplete fallback assembles in memory and uses the single shared finalizer", () => {
    const packet = urlPacket("audit_source_council", { council: true });
    assert.match(packet, /INCOMPLETE-report draft fallback/);
    assert.match(packet, /Do not write it here/);
    assert.equal((packet.match(/zerotrust_finalize_report\(\{/g) || []).length, 1);
});

test("report tool schema requires full resolved SHA for URL identity and exposes no short_sha", () => {
    const extensionSource = readFileSync(
        nodePath.join(HERE, "..", "extension.mjs"),
        "utf-8",
    );
    const reportBlock = extensionSource.slice(
        extensionSource.indexOf('name: "zerotrust_finalize_report"'),
        extensionSource.indexOf('name: "zerotrust_cleanup_audit"'),
    );
    assert.match(reportBlock, /resolved_sha/);
    assert.match(reportBlock, /\^\[a-fA-F0-9\]\{40\}\$/);
    assert.doesNotMatch(reportBlock, /short_sha\s*:/);
    assert.match(reportBlock, /canonical reportPath/);
    assert.match(reportBlock, /operator_decisions/);
    assert.match(reportBlock, /operator_rationale/);
    assert.doesNotMatch(reportBlock, /executive_summary\s*:/);
    assert.doesNotMatch(reportBlock, /operator_context\s*:/);
});

test("outcome and cleanup schemas expose the hardened identity contract", () => {
    const extensionSource = readFileSync(
        nodePath.join(HERE, "..", "extension.mjs"),
        "utf-8",
    );
    const outcomeBlock = extensionSource.slice(
        extensionSource.indexOf('name: "zerotrust_record_council_outcome"'),
        extensionSource.indexOf('name: "zerotrust_finalize_report"'),
    );
    assert.match(outcomeBlock, /audit_id/);
    assert.match(outcomeBlock, /required:\s*\["audit_id"/);
    assert.match(outcomeBlock, /immutable/i);
    assert.match(outcomeBlock, /owner\/repo\/full resolved SHA/i);

    const cleanupBlock = extensionSource.slice(
        extensionSource.indexOf('name: "zerotrust_cleanup_audit"'),
        extensionSource.indexOf('name: "zerotrust_cleanup_quarantine"'),
    );
    assert.match(cleanupBlock, /real sessionId/i);
    assert.match(cleanupBlock, /active build mode/i);
    assert.match(cleanupBlock, /recorded resolved clone path/i);
    assert.match(cleanupBlock, /hashed-identity/i);
});
