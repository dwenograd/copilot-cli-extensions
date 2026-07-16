import { test } from "node:test";
import assert from "node:assert/strict";
import nodePath from "node:path";

import { buildInstructionPacket } from "../packet.mjs";
import { buildClonePath, buildQuarantinePath, buildReportPath } from "../urlParser.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/var/zerotrust-sourcecheck";
const PLACEHOLDER = "0".repeat(40);
const CLONE = buildClonePath(BUILD_ROOT, "octocat", "Hello", PLACEHOLDER);
const REPORT = buildReportPath(BUILD_ROOT, "octocat", "Hello", PLACEHOLDER);
const QUARANTINE = buildQuarantinePath(BUILD_ROOT, "octocat", "Hello", PLACEHOLDER);

function urlPacket(mode, overrides = {}) {
    return buildInstructionPacket({
        mode,
        parsed: {
            owner: "octocat",
            repo: "Hello",
            ref: "main",
            refType: "branch",
            kind: "tree",
            canonicalUrl: "https://github.com/octocat/Hello/tree/main",
        },
        refOverride: null,
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "lifecycle-test",
        scrubNote: null,
        privateRepoAck: true,
        buildExecAck: mode.includes("build"),
        unsafeAck: mode.includes("full"),
        buildRoot: BUILD_ROOT,
        expectedClonePath: CLONE,
        expectedReportPath: REPORT,
        expectedQuarantinePath: QUARANTINE,
        placeholderSha: true,
        councilManifest: null,
        councilJudgeModel: null,
        councilSubJudgeModel: null,
        maxPremiumCalls: null,
        ...overrides,
    });
}

test("metadata terminal path sweeps build_root with parent off before close", () => {
    const packet = urlPacket("metadata_only");
    const sweep = packet.indexOf("zerotrust_sweep_audit_scratch({ also_sweep_parent: false })");
    const close = packet.indexOf("zerotrust_close_audit({})", sweep);
    assert.ok(sweep >= 0);
    assert.ok(close > sweep);
    assert.match(packet, /If the sweep fails, do not close the audit/);
});

test("private-repo stop explicitly closes active state", () => {
    const packet = urlPacket("audit_source", { privateRepoAck: false });
    assert.match(packet, /\*\*STOP\*\*\. Before returning, call `zerotrust_close_audit\(\{\}\)`/);
});

test("verify_release cleanup runs quarantine then sweep then close", () => {
    const packet = urlPacket("verify_release");
    const quarantine = packet.indexOf("zerotrust_cleanup_quarantine({})");
    const sweep = packet.indexOf("zerotrust_sweep_audit_scratch({", quarantine);
    const close = packet.indexOf("zerotrust_close_audit({})", sweep);
    assert.ok(quarantine >= 0);
    assert.ok(sweep > quarantine);
    assert.ok(close > sweep);
    assert.match(packet, /also_sweep_parent: false/);
});

test("build cleanup runs clone cleanup then sweep then close", () => {
    const packet = urlPacket("audit_and_safe_build");
    const cleanup = packet.indexOf("zerotrust_cleanup_audit({");
    const sweep = packet.indexOf("zerotrust_sweep_audit_scratch({", cleanup);
    const close = packet.indexOf("zerotrust_close_audit({})", sweep);
    assert.ok(cleanup >= 0);
    assert.ok(sweep > cleanup);
    assert.ok(close > sweep);
});

test("parent sweep is opt-in and packet dry-runs before the explicit parent sweep", () => {
    const packet = urlPacket("audit_source");
    assert.match(packet, /also_sweep_parent: true,\s+dry_run: true/);
    assert.match(packet, /After reviewing that candidate list/);
    assert.match(packet, /also_sweep_parent: true` and `dry_run: false/);
});

test("local completion sweeps before idempotent close", () => {
    const packet = buildInstructionPacket({
        mode: "audit_local_source",
        target: {
            kind: "local",
            localPath: process.platform === "win32" ? "C:\\projects\\sample": "/srv/sample",
            slug: "sample",
        },
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "local-lifecycle",
        scrubNote: null,
        buildRoot: BUILD_ROOT,
        expectedReportPath: nodePath.join(BUILD_ROOT, "_reports", "local-sample"),
        councilManifest: null,
        councilJudgeModel: null,
        councilSubJudgeModel: null,
        maxPremiumCalls: null,
    });
    const sweep = packet.indexOf("zerotrust_sweep_audit_scratch({");
    const close = packet.indexOf("zerotrust_close_audit({})", sweep);
    assert.ok(sweep >= 0);
    assert.ok(close > sweep);
    assert.match(packet, /also_sweep_parent: false/);
});

test("incomplete council outcomes continue to cleanup and close", () => {
    const packet = urlPacket("audit_source_council", {
        councilManifest: [{
            id: "mandatory-test",
            category: "execution",
            model: "gpt-5.6-sol",
            tier: "source-inspection",
            mandatory: true,
            renderedPrompt: "investigation-only; report findings in your reply, do NOT write any files",
        }],
        councilJudgeModel: "gpt-5.6-sol",
        councilSubJudgeModel: "gpt-5.6-sol",
        maxPremiumCalls: 10,
    });
    const failedRole = packet.indexOf("Retry one malformed role output once");
    const semanticCoverage = packet.indexOf("Candidate submission is advisory", failedRole);
    const finalizer = packet.lastIndexOf("zerotrust_finalize_report");
    const close = packet.lastIndexOf("zerotrust_close_audit");
    assert.ok(failedRole >= 0);
    assert.ok(semanticCoverage > failedRole);
    assert.ok(finalizer > semanticCoverage);
    assert.ok(close > finalizer);
});

test("local incomplete council outcomes still reach lifecycle close", () => {
    const packet = buildInstructionPacket({
        mode: "audit_local_source_council",
        target: {
            kind: "local",
            localPath: process.platform === "win32" ? "C:\\projects\\sample": "/srv/sample",
            slug: "sample",
        },
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "local-incomplete",
        scrubNote: null,
        buildRoot: BUILD_ROOT,
        expectedReportPath: nodePath.join(BUILD_ROOT, "_reports", "local-sample"),
        councilManifest: [{
            id: "mandatory-test",
            category: "execution",
            model: "gpt-5.6-sol",
            tier: "source-inspection",
            mandatory: true,
            renderedPrompt: "investigation-only; report findings in your reply, do NOT write any files",
        }],
        councilJudgeModel: "gpt-5.6-sol",
        councilSubJudgeModel: "gpt-5.6-sol",
        maxPremiumCalls: 10,
    });
    const failedRole = packet.indexOf("mark that role FAILED and preserve the coverage limitation");
    const semanticCoverage = packet.indexOf("Continue into semantic coverage", failedRole);
    const finalizer = packet.lastIndexOf("zerotrust_finalize_report");
    const close = packet.lastIndexOf("zerotrust_close_audit");
    assert.ok(failedRole >= 0);
    assert.ok(semanticCoverage > failedRole);
    assert.ok(finalizer > semanticCoverage);
    assert.ok(close > finalizer);
});
