// __tests__/api-direct-binary-boundaries.test.mjs
//
// Anchor tests for api-direct-binary-boundaries security (the security rationale triple-review fixes
// shipped after current + current security):
//   1. Classification inspects the full byte buffer without treating
//      valid UTF-8 control bytes as structural binary evidence.
//   2. Binary classification inspects the full byte buffer.
//   3. renderRolePrompt branches on apiDirect (sub-agents must call
//      zerotrust_safe_fetch_file in API-direct, not look for a clone).
//   4. safeCloneHandler refuses when sessionId given but no active
//      audit (TTL-expiry guard, mirrors install/build wrappers).
//   5. inspectToolCall denies `git clone` in audit-only modes regardless
//      of path. NOTE: this is the executable spec for the unregistered
//      `preToolUseHook` (see enforcement.mjs top comment + README "Honest
//      disclosure"). The Copilot CLI runtime doesn't fire onPreToolUse
//      for built-in tools, AND as of current implementation we no longer register the
//      hook at all — so this test pins the deny POLICY (what would
//      happen if the hook were re-wired), not a live runtime defense.
//      The actual runtime defense is the safeWrappers/* tools (the
//      packet instructs the agent to use those rather than raw shell).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
    classifyAsBinary,
    isKnownBinaryPath,
} from "../safeWrappers/apiClient.mjs";
import { renderRolePrompt, __internals as ptInternals } from "../council/promptTemplate.mjs";
import { safeCloneHandler } from "../safeWrappers/cloneWrapper.mjs";
import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60": "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

// ---------- 1. polyglot binary detection ----------

test("api-direct-binary-boundaries: valid UTF-8 remains text even with a null byte past the old preview window", () => {
    const ascii = Buffer.alloc(8192, 0x41); // 8KB of 'A'
    const polyglotPayload = Buffer.from([0x42, 0x43, 0x00, 0x44, 0x45]); // null inside
    const buf = Buffer.concat([ascii, polyglotPayload]);
    assert.equal(classifyAsBinary(buf, "innocent.txt"), false,
        "valid UTF-8 must remain text; null alone is not structural binary proof");
});

// ---------- 2. suffixes are prioritization hints, not classification ----------

test("coverage security: valid text bytes override known binary suffixes", () => {
    const cleanText = Buffer.from(
        "just some all-ASCII text with no null bytes anywhere here",
        "utf-8",
    );
    assert.equal(cleanText.includes(0), false, "test setup: control buffer has no nulls");
    assert.equal(classifyAsBinary(cleanText, "setup.exe"), false);
    assert.equal(classifyAsBinary(cleanText, "evil.jse"), false);
    assert.equal(classifyAsBinary(cleanText, "cert.pfx"), false);
    assert.equal(classifyAsBinary(cleanText, "image.png"), false);
    assert.equal(classifyAsBinary(cleanText, "src/index.js"), false, "regular .js stays text");
    assert.equal(classifyAsBinary(cleanText, "README.md"), false, "regular .md stays text");
    assert.equal(isKnownBinaryPath("setup.exe"), true, "suffix remains a fetch-order hint");
    assert.equal(isKnownBinaryPath("image.png"), true, "suffix remains a fetch-order hint");
});

test("api-direct-binary-boundaries: classifyAsBinary requires a Buffer", () => {
    assert.throws(() => classifyAsBinary("a string", "x.txt"), /requires a Buffer/);
    assert.throws(() => classifyAsBinary(null, "x.txt"), /requires a Buffer/);
});

// ---------- 3. council prompt template apiDirect branch ----------

const FAKE_ROLE = {
    id: "test-role",
    tier: "source-inspection",
    category: "A",
    description: "test description",
    angle: "test angle",
    ignore_clauses: ["adjacent role's territory"],
    priors: ["prior 1", "prior 2"],
};
const RUNTIME_SHA = "a".repeat(40);

test("api-direct-binary-boundaries: renderRolePrompt apiDirect=true uses safe_fetch_file ground rule", () => {
    const prompt = renderRolePrompt(FAKE_ROLE, {
        auditId: "11111111-1111-4111-8111-111111111111",
        nonce: "abcd1234",
        apiDirect: true,
        owner: "octocat",
        repo: "Hello-World",
        sourceCommitSha: RUNTIME_SHA,
        buildRoot: BUILD_ROOT,
        coverageSnapshot: { coverageComplete: true, aggregateEntryCount: 1 },
        candidatePaths: ["package.json"],
    });
    assert.match(prompt, /zerotrust_safe_fetch_file/, "API-direct prompt mentions safe_fetch_file");
    assert.match(prompt, /octocat/, "owner is interpolated");
    assert.match(prompt, /Hello-World/, "repo is interpolated");
    assert.doesNotMatch(prompt, /ALREADY CLONED/i, "API-direct must not say ALREADY CLONED");
});

test("api-direct-binary-boundaries: renderRolePrompt apiDirect=false uses on-disk clone ground rule", () => {
    const prompt = renderRolePrompt(FAKE_ROLE, {
        auditId: "11111111-1111-4111-8111-111111111111",
        clonePath: CLONE_PATH,
        owner: "octocat",
        repo: "Hello-World",
        nonce: "abcd1234",
        apiDirect: false,
        sourceCommitSha: RUNTIME_SHA,
        buildRoot: BUILD_ROOT,
        coverageSnapshot: { coverageComplete: true, aggregateEntryCount: 1 },
        candidatePaths: ["package.json"],
    });
    assert.match(prompt, /ALREADY CLONED/i, "on-disk prompt mentions clone");
    assert.doesNotMatch(prompt, /zerotrust_safe_fetch_file/, "on-disk prompt does not direct to safe_fetch_file");
});

test("api-direct-binary-boundaries: both whitelists exported from promptTemplate __internals", () => {
    assert.ok(ptInternals.TIER_TOOL_WHITELIST_API_DIRECT, "API-direct whitelist exported");
    assert.ok(ptInternals.TIER_TOOL_WHITELIST_ON_DISK, "on-disk whitelist exported");
    assert.ok(
        ptInternals.TIER_TOOL_WHITELIST_API_DIRECT["source-inspection"],
        "API-direct whitelist has source-inspection tier",
    );
    assert.ok(
        ptInternals.TIER_TOOL_WHITELIST_ON_DISK["source-inspection"],
        "on-disk whitelist has source-inspection tier",
    );
});

// ---------- 4. safeCloneHandler TTL-expiry guard ----------

test("api-direct-binary-boundaries: safeCloneHandler refuses when sessionId given but no active audit (TTL expiry)", async () => {
    const sid = "api-direct-binary-boundaries-no-active-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid); // make sure no audit
    const r = await safeCloneHandler(
        { url: "https://github.com/octocat/Hello-World" },
        { sessionId: sid },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /no active audit|TTL expired|sourcecheck not invoked/i);
});

// ---------- 5. inspectToolCall clone-mode refusal (executable spec for the unregistered preToolUseHook — see file header) ----------

test("api-direct-binary-boundaries: enforcement denies git clone in audit_source mode regardless of path", () => {
    const sid = "api-direct-binary-boundaries-clone-deny-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "git clone https://github.com/octocat/Hello-World " + CLONE_PATH },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /audit_source|API-direct|not allowed/i);
    deactivateAudit(sid);
});

test("api-direct-binary-boundaries: enforcement denies git clone in audit_source_council mode", () => {
    const sid = "api-direct-binary-boundaries-clone-deny-council-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_source_council",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "git clone https://github.com/octocat/Hello-World " + CLONE_PATH },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("api-direct-binary-boundaries: enforcement denies git clone in verify_release mode", () => {
    const sid = "api-direct-binary-boundaries-clone-deny-release-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "verify_release",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "git clone https://github.com/octocat/Hello-World " + CLONE_PATH },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("api-direct-binary-boundaries: enforcement allows git clone in build modes (sanity check — clone is needed for builds)", () => {
    const sid = "api-direct-binary-boundaries-clone-allow-build-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const cmd = "git -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --filter=blob:none --no-checkout https://github.com/octocat/Hello-World " + CLONE_PATH;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "allow", "build modes must still allow hardened clone (not affected by api-direct-binary-boundaries)");
    deactivateAudit(sid);
});
