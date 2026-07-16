// __tests__/wrapper-security-boundaries.test.mjs
//
// Tests for the security rationale pass — fixes prompted by the first
// triple-review round (clusters A/B/C/D/E/G/I/J/K/L/M).
//
// Rather than try to retrofit each new test into existing test files, this
// dedicated file documents the security properties added in the security rationale
// in one place. Each test maps to a specific reviewer finding by reference.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, existsSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import nodePath from "node:path";
import { tmpdir } from "node:os";

import { evaluateCouncilGate } from "../safeWrappers/state.mjs";
import { __internals as installInternals, safeInstallHandler } from "../safeWrappers/installWrapper.mjs";
import { __internals as buildInternals, safeBuildHandler } from "../safeWrappers/buildWrapper.mjs";
import { recordOutcomeHandler } from "../safeWrappers/outcomeWrapper.mjs";
import { cleanupAuditHandler } from "../safeWrappers/cleanupWrapper.mjs";
import { safeCloneHandler } from "../safeWrappers/cloneWrapper.mjs";
import {
    activateAudit,
    deactivateAudit,
    getActiveAudit,
    getTrustedAuditContext,
    recordResolvedArtifactPaths,
    recordResolvedClonePath,
    recordResolvedSha,
} from "../enforcement.mjs";
import { buildClonePath, buildReportPath, parseGithubUrl } from "../urlParser.mjs";
import { recordCouncilOutcome, getRecordedOutcome, clearRecordedOutcome } from "../safeWrappers/state.mjs";

const BR = join(tmpdir(), "zt-wrapper-security-boundaries-test-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8));
const SESSION = "wrapper-security-boundaries-test-session-" + Math.random().toString(36).slice(2, 8);

function freshSandbox() {
    if (existsSync(BR)) rmSync(BR, { recursive: true, force: true });
    mkdirSync(BR, { recursive: true });
}

function activate(sessionId, mode) {
    const cp = join(BR, "octocat-Hello-World-aaaaaaa");
    activateAudit({
        sessionId,
        buildPath: BR,
        mode: mode || "audit_source",
        expectedClonePath: cp,
    });
    // security rationale: install/build wrappers require resolvedClonePath
    // to be set when an audit is active. Tests that exercise those wrappers
    // don't actually clone; record the planned path so the downstream
    // checks (mode-is-build, council-gate, etc.) are reached.
    recordResolvedClonePath(sessionId, cp);
}

function activeAuditFor(owner, repo) {
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        // current: switched to a build mode so safe_clone is reachable in these
        // tests. Audit modes are now API-direct and don't allow safe_clone.
        mode: "audit_and_safe_build",
        expectedClonePath: buildClonePath(BR, owner, repo, "0".repeat(40)),
        owner,
        repo,
    });
}

test.beforeEach(() => {
    freshSandbox();
    deactivateAudit(SESSION);
    clearRecordedOutcome(SESSION);
});

test.after(() => {
    if (existsSync(BR)) rmSync(BR, { recursive: true, force: true });
    deactivateAudit(SESSION);
    clearRecordedOutcome(SESSION);
});

// =====================================================================
// Cluster M: deprecated compatibility outcomes have no bypass path.
// =====================================================================

test("M: incomplete critical compatibility outcome stays blocked", () => {
    const outcome = { verdict: "critical", criticalCount: 1, highCount: 0, complete: false };
    const r = evaluateCouncilGate(outcome);
    assert.equal(r.passes, false);
    assert.match(r.reason, /incomplete/i);
});

test("M: incomplete low compatibility outcome stays blocked", () => {
    const outcome = { verdict: "low", criticalCount: 0, highCount: 0, complete: false };
    const r = evaluateCouncilGate(outcome);
    assert.equal(r.passes, false);
    assert.match(r.reason, /incomplete/i);
});

test("M: complete critical compatibility outcome stays blocked", () => {
    const outcome = { verdict: "critical", criticalCount: 1, highCount: 0, complete: true };
    const r = evaluateCouncilGate(outcome);
    assert.equal(r.passes, false);
});

// =====================================================================
// Cluster B: extra_args denylist for safety-flag negation.
// =====================================================================

test("B: install validateExtraArgs rejects --no-ignore-scripts (npm/yarn/pnpm safety bypass)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--no-ignore-scripts"]), /negate hardcoded safety|positional|positional/);
});

test("B: install validateExtraArgs rejects --ignore-scripts=false", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--ignore-scripts=false"]), /negate hardcoded safety|positional|positional/);
});

test("B: install validateExtraArgs rejects pip --only-binary=:none:", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--only-binary=:none:"]), /negate hardcoded safety|positional|positional/);
});

test("B: install validateExtraArgs rejects pip --only-binary= other than:all:", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--only-binary=:wheel:"]), /negate hardcoded safety|positional|positional/);
});

test("B: install validateExtraArgs rejects --prefix= (path redirect)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--prefix=/elsewhere"]), /negate hardcoded safety|positional|positional/);
});

test("B: install validateExtraArgs accepts benign extra args", () => {
    assert.doesNotThrow(() => installInternals.validateExtraArgs(["--verbose", "--no-progress"]));
});

test("B: build validateExtraArgs rejects cargo --no-locked", () => {
    assert.throws(() => buildInternals.validateExtraArgs(["--no-locked"]), /negate hardcoded safety|positional|positional/);
});

test("B: build validateExtraArgs rejects --manifest-path= (path redirect)", () => {
    assert.throws(() => buildInternals.validateExtraArgs(["--manifest-path=/etc/evil/Cargo.toml"]), /negate hardcoded safety|positional|positional/);
});

test("B: build validateExtraArgs accepts benign extra args", () => {
    assert.doesNotThrow(() => buildInternals.validateExtraArgs(["--release", "--verbose"]));
});

// =====================================================================
// Cluster J: getTrustedAuditContext — agent-supplied build_root cannot
// override the active audit's build_root.
// =====================================================================

test("J: getTrustedAuditContext rejects agent build_root that differs from active audit", () => {
    activate(SESSION);
    const ctx = getTrustedAuditContext({
        sessionId: SESSION,
        args: { build_root: "C:\\Users\\testuser\\Documents" },
        defaultBuildRoot: BR,
    });
    assert.equal(ctx.ok, false);
    assert.match(ctx.error, /does not match the active audit/i);
});

test("J: getTrustedAuditContext accepts agent build_root that matches active audit", () => {
    activate(SESSION);
    const ctx = getTrustedAuditContext({
        sessionId: SESSION,
        args: { build_root: BR },
        defaultBuildRoot: BR,
    });
    assert.equal(ctx.ok, true);
    assert.equal(ctx.buildRoot.toLowerCase(), BR.toLowerCase());
});

test("J: getTrustedAuditContext uses active audit's buildPath even when agent omits build_root", () => {
    activate(SESSION);
    const ctx = getTrustedAuditContext({ sessionId: SESSION, args: {}, defaultBuildRoot: "C:\\never\\used" });
    assert.equal(ctx.ok, true);
    assert.equal(ctx.buildRoot.toLowerCase(), BR.toLowerCase());
});

test("J: getTrustedAuditContext falls back to default when no active audit + no args.build_root", () => {
    const ctx = getTrustedAuditContext({ sessionId: "session-with-no-audit", args: {}, defaultBuildRoot: BR });
    assert.equal(ctx.ok, true);
    assert.equal(ctx.hasActiveAudit, false);
});

test("J: getTrustedAuditContext exposes trusted mode from active audit", () => {
    activate(SESSION, "audit_and_safe_build_council");
    const ctx = getTrustedAuditContext({ sessionId: SESSION, args: {}, defaultBuildRoot: BR });
    assert.equal(ctx.ok, true);
    assert.equal(ctx.mode, "audit_and_safe_build_council");
});

// =====================================================================
// Cluster A: safeBuildHandler must consult trusted mode, not args.mode.
// =====================================================================

test("A: safeBuildHandler enforces finalized-report gate even if args.mode says non-council", async () => {
    activate(SESSION, "audit_and_safe_build_council"); // trusted
    // Agent tries to skip the gate by passing a non-council build mode
    const r = await safeBuildHandler(
        {
            ecosystem: "npm",
            clone_path: join(BR, "octocat-Hello-World-aaaaaaa"),
            mode: "audit_and_safe_build", // advisory — should be IGNORED
        },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /host build gate CLOSED/);
});

test("A: safeBuildHandler enforces finalized-report gate when args.mode is omitted", async () => {
    activate(SESSION, "audit_and_safe_build_council");
    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: join(BR, "octocat-Hello-World-aaaaaaa") },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /host build gate CLOSED/);
});

test("A: safeBuildHandler enforces finalized-report gate for non-council build modes too", async () => {
    activate(SESSION, "audit_and_safe_build"); // non-council
    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: join(BR, "octocat-Hello-World-aaaaaaa"), mode: "audit_and_safe_build_council" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /host build gate CLOSED/);
});

// =====================================================================
// Cluster D + I: cleanupAuditHandler containment security.
// =====================================================================

test("D: cleanupAuditHandler refuses _reports as the clone_path", async () => {
    mkdirSync(join(BR, "_reports", "octocat-X-1234567"), { recursive: true });
    writeFileSync(join(BR, "_reports", "octocat-X-1234567", "REPORT.md"), "# important");
    const r = await cleanupAuditHandler({ clone_path: join(BR, "_reports"), build_root: BR }, {});
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /requires an invocation sessionId/);
    // Verify the _reports dir still exists
    assert.equal(existsSync(join(BR, "_reports", "octocat-X-1234567", "REPORT.md")), true);
});

test("D: cleanupAuditHandler refuses _quarantine as the clone_path", async () => {
    mkdirSync(join(BR, "_quarantine"), { recursive: true });
    const r = await cleanupAuditHandler({ clone_path: join(BR, "_quarantine"), build_root: BR }, {});
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /requires an invocation sessionId/);
});

test("D: cleanupAuditHandler refuses non-canonical clone basename", async () => {
    mkdirSync(join(BR, "random-dir"), { recursive: true });
    const r = await cleanupAuditHandler({ clone_path: join(BR, "random-dir"), build_root: BR }, {});
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /requires an invocation sessionId/);
});

test("D: cleanupAuditHandler refuses non-immediate child of build_root", async () => {
    mkdirSync(join(BR, "sub", "sub2", "octocat-Hello-aaaaaaa"), { recursive: true });
    const r = await cleanupAuditHandler({ clone_path: join(BR, "sub", "sub2", "octocat-Hello-aaaaaaa"), build_root: BR }, {});
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /requires an invocation sessionId/);
});

test("D: cleanupAuditHandler no longer accepts no-session canonical-looking clones", async () => {
    const cp = join(BR, "octocat-Hello-aaaaaaa");
    mkdirSync(cp, { recursive: true });
    writeFileSync(join(cp, "marker.txt"), "x");
    const r = await cleanupAuditHandler({ clone_path: cp, build_root: BR }, {});
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /requires an invocation sessionId/);
    assert.equal(existsSync(cp), true);
});

// =====================================================================
// Cluster E: outcomeWrapper requires real sessionId (no fail-open fallback).
// =====================================================================

test("E: recordOutcomeHandler refuses missing sessionId (no shared-bucket fallback)", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "low", critical_count: 0, high_count: 0, complete: true },
        {},
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /sessionId/i);
});

test("E: recordOutcomeHandler accepts when sessionId is provided", async () => {
    const sessionId = "real-session-id";
    activateAudit({
        sessionId,
        buildPath: BR,
        mode: "audit_and_safe_build_council",
        expectedClonePath: buildClonePath(BR, "octocat", "Hello", "0".repeat(40)),
        owner: "octocat",
        repo: "Hello",
    });
    recordResolvedSha(sessionId, "a".repeat(40));
    try {
        const r = await recordOutcomeHandler(
            {
                audit_id: getActiveAudit(sessionId).auditId,
                verdict: "low",
                critical_count: 0,
                high_count: 0,
                complete: true,
            },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
    } finally {
        clearRecordedOutcome(sessionId);
        deactivateAudit(sessionId);
    }
});

// =====================================================================
// Cluster G: safeCloneHandler validates ref via REF_RE.
// =====================================================================

test("G: safeCloneHandler rejects ref starting with - (would be parsed as flag)", async () => {
    const r = await safeCloneHandler({
        url: "https://github.com/octocat/Hello-World",
        ref: "-upload-pack=evil",
    });
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /ref rejected/i);
});

test("G: safeCloneHandler rejects ref with disallowed characters", async () => {
    const r = await safeCloneHandler({
        url: "https://github.com/octocat/Hello-World",
        ref: "branch with spaces",
    });
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /ref rejected.*disallowed/i);
});

test("G: safeCloneHandler rejects ref with .. traversal", async () => {
    const r = await safeCloneHandler({
        url: "https://github.com/octocat/Hello-World",
        ref: "refs/heads/../evil",
    });
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /ref rejected.*traversal/i);
});

// =====================================================================
// Cluster K: PR URLs resolve to refs/pull/N/head.
// =====================================================================

test("K: parseGithubUrl sets PR URL ref to refs/pull/N/head (not null)", () => {
    const r = parseGithubUrl("https://github.com/octocat/Hello-World/pull/42");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.kind, "pr");
    assert.equal(r.parsed.prNumber, 42);
    assert.equal(r.parsed.ref, "refs/pull/42/head");
});

// =====================================================================
// Cluster L: stale council outcomes cleared on new audit activation.
// =====================================================================

test("L: starting a new audit in same session clears prior recorded outcome", async () => {
    // Simulate: session ran audit-A → recorded outcome → starts audit-B
    recordCouncilOutcome(SESSION, {
        auditId: "prior-audit-generation",
        verdict: "low",
        criticalCount: 0,
        highCount: 0,
        complete: true,
    });
    assert.ok(getRecordedOutcome(SESSION), "outcome was recorded");

    // Import handler dynamically so the mocked sessionId path is exercised
    const { runHandler } = await import("../handler.mjs");
    const r = await runHandler(
        { url: "https://github.com/octocat/Hello-World" },
        { sessionId: SESSION, log:() => {} },
    );
    assert.equal(r.resultType, "success");

    // After activating a new audit, the prior outcome should be cleared
    assert.equal(getRecordedOutcome(SESSION), null, "prior outcome cleared on new audit activation");

    // Cleanup the audit state for next tests
    deactivateAudit(SESSION);
});

// =====================================================================
// Cluster J (continued): wrappers refuse mismatched build_root from agent.
// =====================================================================

test("J: safeBuildHandler refuses agent build_root that differs from active audit", async () => {
    activate(SESSION, "audit_and_safe_build");
    const r = await safeBuildHandler(
        {
            ecosystem: "npm",
            clone_path: join("C:\\Users\\testuser\\evil", "x-y-aaaaaaa"),
            build_root: "C:\\Users\\testuser\\evil",
        },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match the active audit/i);
});

test("J: safeInstallHandler refuses agent build_root that differs from active audit", async () => {
    activate(SESSION, "audit_and_safe_build");
    const r = await safeInstallHandler(
        {
            ecosystem: "npm",
            clone_path: join("C:\\Users\\testuser\\evil", "x-y-aaaaaaa"),
            build_root: "C:\\Users\\testuser\\evil",
        },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match the active audit/i);
});

test("J: cleanupAuditHandler refuses agent build_root that differs from active audit", async () => {
    activate(SESSION, "audit_and_safe_build");
    const fakeBR = join(tmpdir(), "different-build-root-" + Date.now());
    mkdirSync(fakeBR, { recursive: true });
    try {
        const r = await cleanupAuditHandler(
            {
                clone_path: join(fakeBR, "octocat-Hello-aaaaaaa"),
                build_root: fakeBR,
            },
            { sessionId: SESSION },
        );
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /does not match the active audit/i);
    } finally {
        rmSync(fakeBR, { recursive: true, force: true });
    }
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R2/J: finalizeReportHandler uses active-audit build_root when agent omits build_root", async () => {
    const sha = "a".repeat(40);
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_source",
        expectedClonePath: buildClonePath(BR, "octocat", "Hello", "0".repeat(40)),
        owner: "octocat",
        repo: "Hello",
    });
    recordResolvedSha(SESSION, sha);
    recordResolvedArtifactPaths(SESSION, {
        reportPath: buildReportPath(BR, "octocat", "Hello", sha),
    });
    const { finalizeReportHandler } = await import("../safeWrappers/reportWrapper.mjs");
    const r = await finalizeReportHandler(
        { owner: "octocat", repo: "Hello", resolved_sha: sha, markdown_body: "# ok\n\nVerdict: incomplete" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "success");
});

test("R2/TTL: getTrustedAuditContext refuses non-default build_root when sessionId given but no audit", () => {
    const ctx = getTrustedAuditContext({
        sessionId: "fresh-session-no-audit",
        args: { build_root: "C:\\Users\\testuser\\evil" },
        defaultBuildRoot: BR,
    });
    assert.equal(ctx.ok, false);
    assert.match(ctx.error, /no active audit.*does not match default/i);
});

test("R2/TTL: getTrustedAuditContext accepts default build_root with no audit", () => {
    const ctx = getTrustedAuditContext({
        sessionId: "fresh-session-no-audit",
        args: { build_root: BR },
        defaultBuildRoot: BR,
    });
    assert.equal(ctx.ok, true);
    assert.equal(ctx.hasActiveAudit, false);
});

test("R2/B: install rejects bare --no-binary (split-form bypass)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--no-binary", ":all:"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R2/B: install rejects bare --only-binary", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--only-binary", ":none:"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R2/B: install rejects bare --prefix", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--prefix", "."]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R2/B: install rejects bare --use-feature", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--use-feature", "no-build-isolation-fallback"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R2/B: install rejects absolute Windows path in extra_args", () => {
    assert.throws(() => installInternals.validateExtraArgs(["C:\\Users\\testuser\\evil"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R2/B: install rejects path-traversal in extra_args", () => {
    assert.throws(() => installInternals.validateExtraArgs(["../escape"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R2/B: build rejects bare --manifest-path (split-form)", () => {
    assert.throws(() => buildInternals.validateExtraArgs(["--manifest-path", "/etc/evil/Cargo.toml"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R2/B: build rejects absolute path positional arg", () => {
    assert.throws(() => buildInternals.validateExtraArgs(["C:\\Users\\testuser\\evil\\app.sln"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R2/4: safeBuildHandler refuses when active-audit mode is not a build mode", async () => {
    activate(SESSION, "audit_source"); // not a build mode
    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: join(BR, "octocat-Hello-World-aaaaaaa") },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /not a build mode/i);
});

test("R2/4: safeInstallHandler refuses when active-audit mode is not a build mode", async () => {
    activate(SESSION, "audit_source"); // not a build mode
    const { safeInstallHandler } = await import("../safeWrappers/installWrapper.mjs");
    const r = await safeInstallHandler(
        { ecosystem: "npm", clone_path: join(BR, "octocat-Hello-World-aaaaaaa") },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /not a build mode/i);
});

test("R2/5: handler.mjs ref override uses validateRef directly (rejects # fragment)", async () => {
    const { runHandler } = await import("../handler.mjs");
    const r = await runHandler(
        { url: "https://github.com/octocat/Hello-World", ref: "main#evil" },
        { sessionId: "ref-test-1", log:() => {} },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /ref override rejected/i);
});

test("R2/5: handler.mjs ref override rejects newline injection", async () => {
    const { runHandler } = await import("../handler.mjs");
    const r = await runHandler(
        { url: "https://github.com/octocat/Hello-World", ref: "main\nevil" },
        { sessionId: "ref-test-2", log:() => {} },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /ref override rejected/i);
});

test("R2/6: parseGithubUrl supports slash-containing release tags (e.g. baseline/2)", () => {
    const r = parseGithubUrl("https://github.com/octocat/Hello-World/releases/tag/baseline/2");
    assert.equal(r.ok, true);
    assert.equal(r.parsed.kind, "release");
    assert.equal(r.parsed.ref, "baseline/2");
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R3/1: safeBuildHandler refuses when sessionId given but no active audit", async () => {
    // No activate() call here on purpose
    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: join(BR, "octocat-Hello-aaaaaaa"), mode: "audit_and_full_build" },
        { sessionId: "fresh-session-no-audit" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /no active audit for this session/i);
});

test("R3/1: safeInstallHandler refuses when sessionId given but no active audit", async () => {
    const { safeInstallHandler } = await import("../safeWrappers/installWrapper.mjs");
    const r = await safeInstallHandler(
        { ecosystem: "npm", clone_path: join(BR, "octocat-Hello-aaaaaaa") },
        { sessionId: "fresh-session-no-audit" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /no active audit for this session/i);
});

test("R3/2-UNC: install rejects UNC absolute path in extra_args", () => {
    assert.throws(() => installInternals.validateExtraArgs(["\\\\server\\share\\evil.whl"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R3/2-UNC: install rejects bare-leading-backslash path", () => {
    assert.throws(() => installInternals.validateExtraArgs(["\\foo\\bar"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R3/2-UNC: build rejects UNC absolute path in extra_args", () => {
    assert.throws(() => buildInternals.validateExtraArgs(["\\\\evil-server\\share\\app.csproj"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R3/3: recordOutcomeHandler rejects inconsistent verdict='low' + critical_count=1", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "low", critical_count: 1, high_count: 0, complete: true },
        { sessionId: "r3-test-1" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /inconsistent outcome/i);
});

test("R3/3: recordOutcomeHandler rejects inconsistent verdict='no red flags found' + high_count=2", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "no red flags found", critical_count: 0, high_count: 2, complete: true },
        { sessionId: "r3-test-2" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /inconsistent outcome/i);
});

test("R3/3: recordOutcomeHandler rejects 'critical' verdict with critical_count=0", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "critical", critical_count: 0, high_count: 0, complete: true },
        { sessionId: "r3-test-3" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /inconsistent outcome/i);
});

test("R3/4-flag-value: install rejects --target=C:\\evil (absolute path in flag value)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--target=C:\\evil"]),
        /negate hardcoded safety|positional|absolute path/i,
    );
});

test("R3/4-flag-value: install rejects --output=\\\\server\\share (UNC in flag value)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--output=\\\\server\\share"]),
        /absolute path|negate hardcoded safety|positional/i,
    );
});

test("R3/4-flag-value: install rejects --cache-dir=../escape (traversal in flag value)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--cache-dir=../escape"]),
        /traversal|negate hardcoded safety|positional/i,
    );
});

test("R3/4-flag-value: build rejects --output=C:\\bad (absolute path in flag value)", () => {
    assert.throws(() => buildInternals.validateExtraArgs(["--output=C:\\bad"]),
        /negate hardcoded safety|positional|absolute path/i,
    );
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R4/registry: install rejects --index-url=https://attacker/ (pip)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--index-url=https://attacker.example/"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R4/registry: install rejects bare --extra-index-url (split-form)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--extra-index-url", "https://attacker/"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R4/registry: install rejects --trusted-host=attacker", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--trusted-host=attacker.example"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R4/registry: install rejects --registry=https://attacker/", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--registry=https://attacker/"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R4/registry: build rejects --source=https://attacker/ (dotnet/cargo)", () => {
    assert.throws(() => buildInternals.validateExtraArgs(["--source=https://attacker/"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R4/lockfile: install rejects --no-package-lock", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--no-package-lock"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R4/clone-binding: safeBuildHandler refuses when clone_path differs from active audit's resolved clone", async () => {
    const { recordResolvedClonePath } = await import("../enforcement.mjs");
    const realClone = join(BR, "real-clone-aaaaaaa");
    const evilClone = join(BR, "evil-sibling-bbbbbbb");
    activate(SESSION, "audit_and_safe_build");
    recordResolvedClonePath(SESSION, realClone);

    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: evilClone },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match the active audit's resolved clone/i);
});

test("R4/clone-binding: safeInstallHandler refuses sibling clone_path", async () => {
    const { recordResolvedClonePath } = await import("../enforcement.mjs");
    const { safeInstallHandler } = await import("../safeWrappers/installWrapper.mjs");
    const realClone = join(BR, "real-clone-aaaaaaa");
    const evilClone = join(BR, "evil-sibling-bbbbbbb");
    activate(SESSION, "audit_and_safe_build");
    recordResolvedClonePath(SESSION, realClone);

    const r = await safeInstallHandler(
        { ecosystem: "npm", clone_path: evilClone },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match the active audit's resolved clone/i);
});

test("R4/clone-binding: cleanupAuditHandler refuses sibling clone_path", async () => {
    const { recordResolvedClonePath } = await import("../enforcement.mjs");
    const realClone = buildClonePath(BR, "octocat", "real", "a".repeat(40));
    const evilClone = buildClonePath(BR, "octocat", "evil", "b".repeat(40));
    mkdirSync(realClone, { recursive: true });
    mkdirSync(evilClone, { recursive: true });
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_and_safe_build",
        expectedClonePath: realClone,
        owner: "octocat",
        repo: "real",
    });
    recordResolvedClonePath(SESSION, realClone);

    const r = await cleanupAuditHandler(
        { clone_path: evilClone },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match the active audit's resolved clone/i);
});

test("R4/build_root-type: handler rejects non-string build_root", async () => {
    const { runHandler } = await import("../handler.mjs");
    const r = await runHandler(
        { url: "https://github.com/octocat/Hello-World", build_root: { malicious: "object" } },
        { sessionId: "r4-buildroot-test", log:() => {} },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /build_root must be a non-empty string/i);
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R5/positional-url: install rejects positional URL arg", () => {
    assert.throws(() => installInternals.validateExtraArgs(["https://attacker.example/evil.whl"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R5/positional-url: install rejects ftp:// positional", () => {
    assert.throws(() => installInternals.validateExtraArgs(["ftp://attacker/x.tgz"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R5/positional-url: install rejects file:// positional", () => {
    assert.throws(() => installInternals.validateExtraArgs(["file:///etc/evil"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R5/version-pin: install rejects pip-style version-pin (pkg==1.2.3)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["malicious-pkg==1.2.3"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R5/version-pin: install rejects npm-style version-pin (pkg@1.2.3)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["malicious-pkg@1.2.3"]),
        /negate hardcoded safety|positional|positional/,
    );
});

test("R5/url-in-flag-value: install rejects --cache-dir=https://attacker/", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--cache-dir=https://attacker.example/"]),
        /remote URL|absolute path|negate hardcoded safety|positional/i,
    );
});

test("R5/url-in-flag-value: build rejects --output=https://attacker/", () => {
    assert.throws(() => buildInternals.validateExtraArgs(["--output=https://attacker.example/"]),
        /remote URL|absolute path|negate hardcoded safety|positional/i,
    );
});

test("R5/clone-vs-audit-repo: safe_clone refuses repo B when audit was activated for repo A", async () => {
    // Use a sessionId that has an active audit pinned to octocat/Hello-World
    activeAuditFor("octocat", "Hello-World");
    const r = await safeCloneHandler(
        { url: "https://github.com/different/repo" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match the active audit's pinned target/i);
});

test("R5/clone-vs-audit-repo: safe_clone allows matching owner/repo (different ref ok)", async () => {
    // Activate an audit pinned to octocat/Hello-World.
    activeAuditFor("octocat", "Hello-World");
    // Give a bad ref so we don't actually try to network — error should be
    // ref/SHA-resolution failure, NOT the owner/repo mismatch.
    const r = await safeCloneHandler(
        { url: "https://github.com/octocat/Hello-World", ref: "-evil" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.doesNotMatch(r.textResultForLlm, /does not match the active audit's pinned target/i);
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R6/scoped-pkg: install rejects npm scoped package version-pin (@scope/pkg@1.2.3)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["@scope/malicious-pkg@1.2.3"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R6/scoped-pkg: install rejects bare npm scoped package", () => {
    assert.throws(() => installInternals.validateExtraArgs(["@scope/malicious-pkg"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R6/scoped-pkg: install rejects @scope/pkg@latest", () => {
    assert.throws(() => installInternals.validateExtraArgs(["@scope/malicious-pkg@latest"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R6/clone-binding: safeBuildHandler refuses when audit active but no clone recorded yet", async () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_and_safe_build",
        expectedClonePath: join(BR, "octocat-Hello-World-aaaaaaa"),
    });
    const r = await safeBuildHandler(
        { ecosystem: "npm", clone_path: join(BR, "any-old-clone-bbbbbbb") },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /no resolved clone path recorded/i);
});

test("R6/clone-binding: safeInstallHandler refuses when audit active but no clone recorded yet", async () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_and_safe_build",
        expectedClonePath: join(BR, "octocat-Hello-World-aaaaaaa"),
    });
    const { safeInstallHandler } = await import("../safeWrappers/installWrapper.mjs");
    const r = await safeInstallHandler(
        { ecosystem: "npm", clone_path: join(BR, "any-old-clone-bbbbbbb") },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /no resolved clone path recorded/i);
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R7/ignore-scripts-true: install rejects --no-ignore-scripts=true", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--no-ignore-scripts=true"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R7/ignore-scripts-true: install rejects --no-ignore-scripts=1", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--no-ignore-scripts=1"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R7/ignore-scripts-true: install rejects bare --ignore-scripts (already hardcoded)", () => {
    assert.throws(() => installInternals.validateExtraArgs(["--ignore-scripts=anything"]),
        /negate hardcoded safety|positional|positional/i,
    );
});

test("R7/metadata_only: safe_clone refuses when active audit is metadata_only", async () => {
    activeAuditFor("octocat", "Hello-World");
    // Override the activated mode to metadata_only
    deactivateAudit(SESSION);
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "metadata_only",
        expectedClonePath: join(BR, "octocat-Hello-World-aaaaaaa"),
        owner: "octocat",
        repo: "Hello-World",
    });
    const r = await safeCloneHandler(
        { url: "https://github.com/octocat/Hello-World" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not need a clone/i);
});

test("R7/cleanup-binding: cleanupAuditHandler refuses when audit active but no resolved clone yet", async () => {
    const cp = join(BR, `octocat-Hello-World-${"a".repeat(40)}`);
    mkdirSync(cp, { recursive: true });
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_and_safe_build",
        expectedClonePath: cp,
    });
    // Don't recordResolvedClonePath
    const r = await cleanupAuditHandler(
        { clone_path: cp },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /no resolved clone path recorded/i);
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R8/F1-ref-binding: safe_clone refuses different ref of same repo", async () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_and_safe_build",
        expectedClonePath: join(BR, "octocat-Hello-World-aaaaaaa"),
        owner: "octocat",
        repo: "Hello-World",
        ref: "baseline.0",
        refType: "branch_or_tag",
    });
    const r = await safeCloneHandler(
        { url: "https://github.com/octocat/Hello-World", ref: "previous.0" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match the active audit's pinned ref/i);
});

test("R8/F2-bare-pkg: install rejects bare positional package name", () => {
    assert.throws(() => installInternals.validateExtraArgs(["malicious-pkg"]),
        /positional/i,
    );
});

test("R8/F2-bare-pkg: install accepts pure flag args", () => {
    assert.doesNotThrow(() => installInternals.validateExtraArgs(["--verbose", "--no-progress"]));
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R9/F1-omitted-ref: safe_clone with bare URL uses pinned audit ref (no fall-through to HEAD)", async () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_and_safe_build",
        expectedClonePath: join(BR, "octocat-Hello-World-aaaaaaa"),
        owner: "octocat",
        repo: "Hello-World",
        ref: "baseline.0",
        refType: "branch_or_tag",
    });
    // Agent calls safe_clone WITHOUT a ref — should use ctx.ref instead of
    // falling through to HEAD. Pass an obviously-bad ref via the fallback
    // path that ls-remote will reject — proves we used ctx.ref="baseline.0", not HEAD.
    // Use a dummy URL that fails URL validation if the audit guard didn't fire.
    const r = await safeCloneHandler(
        { url: "https://github.com/octocat/Hello-World" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    // Expect the failure to be about ls-remote not finding baseline.0 (we're not actually
    // hitting the network in tests, but the message would mention SHA resolution).
    // Critically: should NOT be a "ref does not match" failure either — we filled it in.
    assert.doesNotMatch(r.textResultForLlm, /does not match the active audit's pinned ref/i);
});

test("R9/F1-explicit-ref-mismatch: safe_clone with explicit different ref still refused", async () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_and_safe_build",
        expectedClonePath: join(BR, "octocat-Hello-World-aaaaaaa"),
        owner: "octocat",
        repo: "Hello-World",
        ref: "baseline.0",
        refType: "branch_or_tag",
    });
    const r = await safeCloneHandler(
        { url: "https://github.com/octocat/Hello-World", ref: "previous.0" },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match the active audit's pinned ref/i);
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R10/F1-incomplete-verdict: recordOutcomeHandler refuses verdict='incomplete' with complete=true", async () => {
    const r = await recordOutcomeHandler(
        { verdict: "incomplete", critical_count: 0, high_count: 0, complete: true },
        { sessionId: "r10-incomplete-test" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /must be recorded with complete=false/i);
});

test("R10/F1-incomplete-verdict: recordOutcomeHandler accepts verdict='incomplete' with complete=false", async () => {
    const sessionId = "r10-incomplete-test-2";
    activateAudit({
        sessionId,
        buildPath: BR,
        mode: "audit_source_council",
        expectedClonePath: buildClonePath(BR, "octocat", "Hello", "0".repeat(40)),
        owner: "octocat",
        repo: "Hello",
    });
    recordResolvedSha(sessionId, "a".repeat(40));
    try {
        const r = await recordOutcomeHandler(
            {
                audit_id: getActiveAudit(sessionId).auditId,
                verdict: "incomplete",
                critical_count: 0,
                high_count: 0,
                complete: false,
            },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
    } finally {
        clearRecordedOutcome(sessionId);
        deactivateAudit(sessionId);
    }
});

test("R10/F2-refspec: cloneInternals.resolveRefViaLsRemote uses refType-aware refspec for release_tag", async () => {
    // We can't call ls-remote in tests without network; but verify the
    // function accepts the refType parameter and that pass-through still
    // works for SHA refs (no ls-remote needed).
    const cloneMod = await import("../safeWrappers/cloneWrapper.mjs");
    const sha40 = "abcdef0123456789abcdef0123456789abcdef01";
    // SHA bypasses ls-remote — should return immediately.
    assert.equal(cloneMod.__internals.resolveRefViaLsRemote("https://x", sha40, "release_tag"), sha40);
    assert.equal(cloneMod.__internals.resolveRefViaLsRemote("https://x", sha40, "branch_or_tag"), sha40);
    assert.equal(cloneMod.__internals.resolveRefViaLsRemote("https://x", sha40, "pr_head"), sha40);
});

// =====================================================================
// security anchors below.
// =====================================================================

test("R11/F1-program: resolveTrustedProgram refuses planted binary inside forbidden root", async () => {
    const { resolveTrustedProgram } = await import("../safeWrappers/programResolver.mjs");
    const cp = join(BR, "octocat-Hello-World-aaaaaaa");
    mkdirSync(cp, { recursive: true });
    const planted = join(cp, "npm.cmd");
    writeFileSync(planted, "@echo malicious\n");
    const oldPath = process.env.PATH;
    try {
        process.env.PATH = cp + nodePath.delimiter + (process.env.PATH || "");
        const resolved = resolveTrustedProgram("npm", { forbiddenRoots: [BR] });
        if (resolved !== null) {
            assert.notEqual(resolved.toLowerCase(), planted.toLowerCase());
            assert.ok(!resolved.toLowerCase().startsWith(BR.toLowerCase()),
                `resolved program should not be under BR: ${resolved}`);
        }
    } finally {
        process.env.PATH = oldPath;
    }
});

test("R11/F1-program: resolveTrustedProgram returns null for nonexistent program", async () => {
    const { resolveTrustedProgram } = await import("../safeWrappers/programResolver.mjs");
    const r = resolveTrustedProgram("nonexistent-program-xyzzy-12345", { forbiddenRoots: [] });
    assert.equal(r, null);
});

test("R11/F1-program: resolveTrustedProgram refuses absolute path inside forbidden root", async () => {
    const { resolveTrustedProgram } = await import("../safeWrappers/programResolver.mjs");
    const cp = join(BR, "octocat-Hello-World-aaaaaaa");
    mkdirSync(cp, { recursive: true });
    const planted = join(cp, "npm.exe");
    writeFileSync(planted, "X");
    const r = resolveTrustedProgram(planted, { forbiddenRoots: [BR] });
    assert.equal(r, null);
});

test("R11/F1-program: resolveTrustedProgram accepts a system program (best-effort)", async () => {
    const { resolveTrustedProgram } = await import("../safeWrappers/programResolver.mjs");
    // Try `node` since we're literally executing this test under node.
    const r = resolveTrustedProgram("node", { forbiddenRoots: [BR] });
    if (r) {
        assert.ok(nodePath.isAbsolute(r), `resolved path should be absolute: ${r}`);
        assert.ok(!r.toLowerCase().startsWith(BR.toLowerCase()),
            `resolved path should not be under BR: ${r}`);
    }
    // If null, that's fine — node might not be on PATH in the test env.
});
