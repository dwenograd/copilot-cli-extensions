// __tests__/v4r1Hardening.test.mjs
//
// Anchor tests for v4-r1 hardening (the round-1 triple-review fixes
// shipped after v4 + v4.1):
//   1. classifyAsBinary catches polyglot files (clean ASCII first 8KB
//      then null byte deeper). The original 8KB-only sniff bypassed.
//   2. classifyAsBinary uses extension allowlist for null-byte-free
//      binary formats (JSE, PFX, etc.).
//   3. renderRolePrompt branches on apiDirect (sub-agents must call
//      zerotrust_safe_fetch_file in API-direct, not look for a clone).
//   4. safeCloneHandler refuses when sessionId given but no active
//      audit (TTL-expiry guard, mirrors install/build wrappers).
//   5. inspectToolCall denies `git clone` in audit-only modes regardless
//      of path. NOTE: this is the executable spec for the unregistered
//      `preToolUseHook` (see enforcement.mjs top comment + README "Honest
//      disclosure"). The Copilot CLI runtime doesn't fire onPreToolUse
//      for built-in tools, AND as of v4-r3 we no longer register the
//      hook at all — so this test pins the deny POLICY (what would
//      happen if the hook were re-wired), not a live runtime defense.
//      The actual runtime defense is the safeWrappers/* tools (the
//      packet instructs the agent to use those rather than raw shell).

import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyAsBinary } from "../safeWrappers/apiClient.mjs";
import { renderRolePrompt, __internals as ptInternals } from "../council/promptTemplate.mjs";
import { safeCloneHandler } from "../safeWrappers/cloneWrapper.mjs";
import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck"
    : "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60"
    : "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

// ---------- 1. polyglot binary detection ----------

test("v4-r1: classifyAsBinary catches polyglot (clean ASCII first 8KB + null deep in buffer)", () => {
    const ascii = Buffer.alloc(8192, 0x41); // 8KB of 'A'
    const polyglotPayload = Buffer.from([0x42, 0x43, 0x00, 0x44, 0x45]); // null inside
    const buf = Buffer.concat([ascii, polyglotPayload]);
    assert.equal(classifyAsBinary(buf, "innocent.txt"), true,
        "polyglot file with null past 8KB must classify as binary");
});

// ---------- 2. extension-based binary detection ----------

test("v4-r1: classifyAsBinary uses extension allowlist for null-byte-free binaries", () => {
    const cleanText = Buffer.from(
        "just some all-ASCII text with no null bytes anywhere here",
        "utf-8",
    );
    assert.equal(cleanText.includes(0), false, "test setup: control buffer has no nulls");
    assert.equal(classifyAsBinary(cleanText, "setup.exe"), true, "setup.exe path forces binary");
    assert.equal(classifyAsBinary(cleanText, "evil.jse"), true, "JSE encoded scripts → binary");
    assert.equal(classifyAsBinary(cleanText, "cert.pfx"), true, "PFX certs → binary");
    assert.equal(classifyAsBinary(cleanText, "image.png"), true, "PNG → binary");
    assert.equal(classifyAsBinary(cleanText, "src/index.js"), false, "regular .js stays text");
    assert.equal(classifyAsBinary(cleanText, "README.md"), false, "regular .md stays text");
});

test("v4-r1: classifyAsBinary requires a Buffer", () => {
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

test("v4-r1: renderRolePrompt apiDirect=true uses safe_fetch_file ground rule", () => {
    const prompt = renderRolePrompt(FAKE_ROLE, {
        nonce: "abcd1234",
        apiDirect: true,
        owner: "octocat",
        repo: "Hello-World",
    });
    assert.match(prompt, /zerotrust_safe_fetch_file/, "API-direct prompt mentions safe_fetch_file");
    assert.match(prompt, /octocat/, "owner is interpolated");
    assert.match(prompt, /Hello-World/, "repo is interpolated");
    assert.doesNotMatch(prompt, /ALREADY CLONED/i, "API-direct must not say ALREADY CLONED");
});

test("v4-r1: renderRolePrompt apiDirect=false uses on-disk clone ground rule", () => {
    const prompt = renderRolePrompt(FAKE_ROLE, {
        clonePath: CLONE_PATH,
        nonce: "abcd1234",
        apiDirect: false,
    });
    assert.match(prompt, /ALREADY CLONED/i, "on-disk prompt mentions clone");
    assert.doesNotMatch(prompt, /zerotrust_safe_fetch_file/, "on-disk prompt does not direct to safe_fetch_file");
});

test("v4-r1: both whitelists exported from promptTemplate __internals", () => {
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

test("v4-r1: safeCloneHandler refuses when sessionId given but no active audit (TTL expiry)", async () => {
    const sid = "v4r1-no-active-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid); // make sure no audit
    const r = await safeCloneHandler(
        { url: "https://github.com/octocat/Hello-World" },
        { sessionId: sid },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /no active audit|TTL expired|sourcecheck not invoked/i);
});

// ---------- 5. inspectToolCall clone-mode refusal (executable spec for the unregistered preToolUseHook — see file header) ----------

test("v4-r1: enforcement denies git clone in audit_source mode regardless of path", () => {
    const sid = "v4r1-clone-deny-" + Math.random().toString(36).slice(2, 8);
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

test("v4-r1: enforcement denies git clone in audit_source_council mode", () => {
    const sid = "v4r1-clone-deny-council-" + Math.random().toString(36).slice(2, 8);
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

test("v4-r1: enforcement denies git clone in verify_release mode", () => {
    const sid = "v4r1-clone-deny-release-" + Math.random().toString(36).slice(2, 8);
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

test("v4-r1: enforcement allows git clone in build modes (sanity check — clone is needed for builds)", () => {
    const sid = "v4r1-clone-allow-build-" + Math.random().toString(36).slice(2, 8);
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
    assert.equal(r.decision, "allow", "build modes must still allow hardened clone (not affected by v4-r1)");
    deactivateAudit(sid);
});
