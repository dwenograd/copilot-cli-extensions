// safeWrappers.test.mjs — unit tests for the substitutional-safety wrappers.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import nodePath from "node:path";

import {
    recordCouncilOutcome,
    getRecordedOutcome,
    clearRecordedOutcome,
    evaluateCouncilGate,
    __internals as stateInternals,
} from "../safeWrappers/state.mjs";

import { safeBuildHandler } from "../safeWrappers/buildWrapper.mjs";
import { recordOutcomeHandler } from "../safeWrappers/outcomeWrapper.mjs";
import { finalizeReportHandler } from "../safeWrappers/reportWrapper.mjs";
import { safeInstallHandler } from "../safeWrappers/installWrapper.mjs";
import { safeCloneHandler, __internals as cloneInternals } from "../safeWrappers/cloneWrapper.mjs";

const SESSION = "test-session-wrapper";
const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck"
    : "/tmp/zerotrust-sourcecheck";

beforeEach(() => {
    stateInternals.recordedOutcomes.clear();
});

// PLACEHOLDER — tests added below via edit

// ---------- state.mjs: record / get / clear ----------

test("recordCouncilOutcome stores + getRecordedOutcome retrieves", () => {
    recordCouncilOutcome(SESSION, { verdict: "low", criticalCount: 0, highCount: 0, complete: true });
    const got = getRecordedOutcome(SESSION);
    assert.equal(got.verdict, "low");
    assert.equal(got.criticalCount, 0);
    assert.equal(got.complete, true);
});

test("clearRecordedOutcome removes the entry", () => {
    recordCouncilOutcome(SESSION, { verdict: "low", criticalCount: 0, highCount: 0, complete: true });
    clearRecordedOutcome(SESSION);
    assert.equal(getRecordedOutcome(SESSION), null);
});

test("recordCouncilOutcome requires sessionId", () => {
    assert.throws(() => recordCouncilOutcome(null, { verdict: "low", criticalCount: 0, highCount: 0, complete: true }));
});

// ---------- evaluateCouncilGate semantics ----------

test("evaluateCouncilGate: no outcome → blocked", () => {
    const r = evaluateCouncilGate(null);
    assert.equal(r.passes, false);
    assert.match(r.reason, /not recorded/);
});

test("evaluateCouncilGate: complete + 'no red flags found' → passes", () => {
    const r = evaluateCouncilGate({ verdict: "no red flags found", criticalCount: 0, highCount: 0, complete: true });
    assert.equal(r.passes, true);
});

test("evaluateCouncilGate: complete + 'low' → passes", () => {
    const r = evaluateCouncilGate({ verdict: "low", criticalCount: 0, highCount: 0, complete: true });
    assert.equal(r.passes, true);
});

test("evaluateCouncilGate: complete + 'medium' → blocked unless override", () => {
    assert.equal(evaluateCouncilGate({ verdict: "medium", criticalCount: 0, highCount: 0, complete: true }).passes, false);
    assert.equal(
        evaluateCouncilGate({ verdict: "medium", criticalCount: 0, highCount: 0, complete: true }, { override: true }).passes,
        true,
    );
});

test("evaluateCouncilGate: complete + 'high' → blocked unless override", () => {
    assert.equal(evaluateCouncilGate({ verdict: "high", criticalCount: 0, highCount: 5, complete: true }).passes, false);
    assert.equal(
        evaluateCouncilGate({ verdict: "high", criticalCount: 0, highCount: 5, complete: true }, { override: true }).passes,
        true,
    );
});

test("evaluateCouncilGate: complete + 'critical' → blocked unless override", () => {
    assert.equal(evaluateCouncilGate({ verdict: "critical", criticalCount: 1, highCount: 0, complete: true }).passes, false);
    assert.equal(
        evaluateCouncilGate({ verdict: "critical", criticalCount: 1, highCount: 0, complete: true }, { override: true }).passes,
        true,
    );
});

test("evaluateCouncilGate: incomplete → blocked unless overrideOnFailure (NOT override)", () => {
    const incomplete = { verdict: "low", criticalCount: 0, highCount: 0, complete: false };
    assert.equal(evaluateCouncilGate(incomplete).passes, false);
    assert.equal(evaluateCouncilGate(incomplete, { override: true }).passes, false);
    assert.equal(evaluateCouncilGate(incomplete, { overrideOnFailure: true }).passes, true);
});

// ---------- recordOutcomeHandler input validation ----------

test("recordOutcomeHandler accepts valid input", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "low", critical_count: 0, high_count: 0, complete: true },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "success");
    assert.ok(getRecordedOutcome(SESSION));
});

test("recordOutcomeHandler rejects unknown verdict", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "weird-verdict", critical_count: 0, high_count: 0, complete: true },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
});

test("recordOutcomeHandler rejects negative count", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "low", critical_count: -1, high_count: 0, complete: true },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
});

test("recordOutcomeHandler rejects non-boolean complete", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "low", critical_count: 0, high_count: 0, complete: "yes" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
});

// ---------- safeBuildHandler input + council-gate integration ----------

test("safeBuildHandler rejects unknown ecosystem", async () => {
    const r = await safeBuildHandler(
        { ecosystem: "rocket-fuel", clone_path: nodePath.join(BUILD_ROOT, "x") },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
});

test("safeBuildHandler rejects clone_path outside build_root", async () => {
    const outside = process.platform === "win32" ? "C:\\Windows\\Temp\\evil" : "/etc/evil";
    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: outside },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    // Round-3 hardening reordered checks: when no active audit, the no-active-audit
    // failure fires before the path-containment failure. Either failure mode confirms
    // the call was refused; accept either message.
    assert.match(r.textResultForLlm, /not under build_root|no active audit/);
});

test("safeBuildHandler rejects extra_args with disallowed characters", async () => {
    const cp = nodePath.join(BUILD_ROOT, "octocat-Hello-aaaaaaa");
    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: cp, extra_args: ["--build", "; do bad"] },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
});

// NOTE: The "council-build mode REFUSES when no outcome recorded" integration
// test will land in Feature 3, once modes.mjs gains audit_and_safe_build_council
// + audit_and_full_build_council. The gate function (evaluateCouncilGate) is
// already unit-tested above; the integration test needs a real council-build
// mode string to exercise buildWrapper's mode-aware codepath.
//
// What we CAN verify today: audit_source_council is council-only (not build),
// so buildWrapper must NOT consult the gate when invoked with that mode.

test("safeBuildHandler audit_source_council mode does NOT consult council gate (council-only, not build)", async () => {
    const cp = nodePath.join(BUILD_ROOT, "octocat-Hello-aaaaaaa");
    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: cp, mode: "audit_source_council" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.doesNotMatch(r.textResultForLlm, /council-build gate/);
});

// ---------- safeInstallHandler input validation ----------

test("safeInstallHandler rejects unknown ecosystem", async () => {
    const r = await safeInstallHandler({
        ecosystem: "snake-oil",
        clone_path: nodePath.join(BUILD_ROOT, "x"),
    });
    assert.equal(r.resultType, "failure");
});

test("safeInstallHandler rejects clone_path outside build_root", async () => {
    const outside = process.platform === "win32" ? "C:\\Windows\\Temp\\evil" : "/etc/evil";
    const r = await safeInstallHandler({ ecosystem: "npm", clone_path: outside });
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /not under build_root/);
});

test("safeInstallHandler rejects extra_args with too many entries", async () => {
    const cp = nodePath.join(BUILD_ROOT, "octocat-Hello-aaaaaaa");
    const tooMany = Array.from({ length: 33 }, (_, i) => `--arg${i}`);
    const r = await safeInstallHandler({ ecosystem: "npm", clone_path: cp, extra_args: tooMany });
    assert.equal(r.resultType, "failure");
});

// ---------- finalizeReportHandler input + path containment ----------

test("finalizeReportHandler rejects missing required fields", async () => {
    const r = await finalizeReportHandler({});
    assert.equal(r.resultType, "failure");
});

test("finalizeReportHandler rejects oversized markdown_body", async () => {
    const r = await finalizeReportHandler({
        owner: "octocat",
        repo: "Hello-World",
        short_sha: "abcdef0",
        markdown_body: "X".repeat(2 * 1024 * 1024),
    });
    assert.equal(r.resultType, "failure");
});

test("finalizeReportHandler rejects bad owner (would escape path)", async () => {
    const r = await finalizeReportHandler({
        owner: "..",
        repo: "Hello-World",
        short_sha: "abcdef0",
        markdown_body: "test",
    });
    assert.equal(r.resultType, "failure");
});

test("finalizeReportHandler rejects bad short_sha", async () => {
    const r = await finalizeReportHandler({
        owner: "octocat",
        repo: "Hello-World",
        short_sha: "not-a-sha",
        markdown_body: "test",
    });
    assert.equal(r.resultType, "failure");
});

// Round-17: same defense-in-depth class as sweepWrapper. finalize_report
// writes 1MB markdown to <build_root>/_reports/<owner>-<repo>-<sha>/REPORT.md.
// If sessionId is missing and the agent supplies a non-default build_root,
// refuse — without this check, a falsy-sessionId tool invocation could
// redirect writes anywhere on disk (creating spurious _reports/... dirs).
test("round-17: finalizeReportHandler refuses non-default build_root when sessionId is null", async () => {
    const r = await finalizeReportHandler(
        {
            build_root: "C:\\Users\\testuser",
            owner: "octocat",
            repo: "Hello-World",
            short_sha: "abc1234",
            markdown_body: "attacker content",
        },
        {},
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match default build_root/i);
});

test("round-17: finalizeReportHandler refuses non-default build_root when sessionId is undefined", async () => {
    const r = await finalizeReportHandler(
        {
            build_root: "C:\\evil",
            owner: "foo",
            repo: "bar",
            short_sha: "0000000",
            markdown_body: "x",
        },
        { sessionId: undefined },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match default build_root/i);
});

test("round-17: finalizeReportHandler refuses non-default build_root when sessionId is empty string", async () => {
    const r = await finalizeReportHandler(
        {
            build_root: "C:\\Windows\\Temp",
            owner: "foo",
            repo: "bar",
            short_sha: "0000000",
            markdown_body: "x",
        },
        { sessionId: "" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match default build_root/i);
});

// ---------- safeCloneHandler input validation (no network) ----------

test("safeCloneHandler rejects missing url", async () => {
    const r = await safeCloneHandler({});
    assert.equal(r.resultType, "failure");
});

test("safeCloneHandler rejects bad URL", async () => {
    const r = await safeCloneHandler({ url: "not-a-github-url" });
    assert.equal(r.resultType, "failure");
});

test("safeCloneHandler rejects SSH URL", async () => {
    const r = await safeCloneHandler({ url: "git@github.com:octocat/Hello-World.git" });
    assert.equal(r.resultType, "failure");
});

test("cloneInternals.looksLikeSha works", () => {
    assert.equal(cloneInternals.looksLikeSha("abcdef0123456789abcdef0123456789abcdef01"), true);
    assert.equal(cloneInternals.looksLikeSha("abc1234"), false);
    assert.equal(cloneInternals.looksLikeSha("XYZNOTHEX0123456789abcdef0123456789abcdef"), false);
    assert.equal(cloneInternals.looksLikeSha(null), false);
});
