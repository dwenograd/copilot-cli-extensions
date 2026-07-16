// __tests__/chained-install-fetch-fallback.test.mjs
//
// Anchor tests for security rationale:
//   Security case — first-rule-wins on install detection
//                  (`npm install --ignore-scripts && pnpm dlx evil` allowed)
//   Security case — SHA-binding only fires after safe_list_tree
//                  (direct safe_fetch_file with arbitrary SHA accepted)
//   Security case — synthesis fallback misses `npm i` (single-letter alias)
//                  + synthesized npx (no install verb at all)
//   Security case — Contents API returns encoding="none" for >1MB files,
//                  fetchFile threw instead of falling through

import { test } from "node:test";
import assert from "node:assert/strict";

import { inspectToolCall, activateAudit, deactivateAudit, recordResolvedSha } from "../enforcement.mjs";
import { safeFetchFileHandler } from "../safeWrappers/safeFetchHandler.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60": "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

const SAFE_BUILD = "audit_and_safe_build";

// ----: validate ALL install hits across sub-commands ----

test("chained-install-fetch-fallback: `npm install --ignore-scripts && pnpm dlx evilpkg` is DENIED in safe-build", () => {
    const sid = "chained-install-fetch-fallback-chained-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --ignore-scripts && pnpm dlx evilpkg" },
    });
    assert.equal(r.decision, "deny",
        `chained dlx after safe install must be denied, got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("chained-install-fetch-fallback: `npm install --ignore-scripts; npx evilpkg` is DENIED", () => {
    const sid = "chained-install-fetch-fallback-chained-npx-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --ignore-scripts; npx evilpkg" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("chained-install-fetch-fallback: `npm install --ignore-scripts && go install ./...` is DENIED", () => {
    const sid = "chained-install-fetch-fallback-chained-go-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --ignore-scripts && go install ./..." },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("chained-install-fetch-fallback: `pip install --no-deps --no-build-isolation foo && cargo install bar` is DENIED", () => {
    const sid = "chained-install-fetch-fallback-chained-cargo-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "pip install --no-deps --no-build-isolation foo && cargo install bar" },
    });
    assert.equal(r.decision, "deny",
        "second install (cargo without --locked --offline) must be denied");
    deactivateAudit(sid);
});

test("chained-install-fetch-fallback: `npm install --ignore-scripts && yarn install --ignore-scripts` is ALLOWED (both safe)", () => {
    const sid = "chained-install-fetch-fallback-chained-good-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --ignore-scripts && yarn install --ignore-scripts" },
    });
    assert.notEqual(r.decision, "deny",
        `both safe-flagged installs must be allowed, got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

// ----: SHA-binding gate (also blocks direct fetch without prior safe_list_tree) ----

test("chained-install-fetch-fallback: safe_fetch_file refuses when no SHA pinned (no prior safe_list_tree)", async () => {
    const sid = "chained-install-fetch-fallback-nopin-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: CLONE_PATH,
        owner: "octocat",
        repo: "hello-world",
    });
    // No recordResolvedSha call — simulating direct fetch without
    // calling safe_list_tree first.
    const r = await safeFetchFileHandler(
        {
            owner: "octocat",
            repo: "hello-world",
            sha: "1111111111111111111111111111111111111111",
            path: "README.md",
        },
        { sessionId: sid },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /no resolved commit SHA pinned|safe_list_tree/i);
    deactivateAudit(sid);
});

test("chained-install-fetch-fallback: safe_fetch_file accepts after recordResolvedSha pin (sanity)", async () => {
    const sid = "chained-install-fetch-fallback-pinned-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: CLONE_PATH,
        owner: "octocat",
        repo: "hello-world",
    });
    const pinned = "1111111111111111111111111111111111111111";
    recordResolvedSha(sid, pinned);
    const r = await safeFetchFileHandler(
        {
            owner: "octocat",
            repo: "hello-world",
            sha: pinned,
            path: "README.md",
        },
        { sessionId: sid },
    );
    if (r.resultType === "failure") {
        assert.doesNotMatch(r.textResultForLlm, /no resolved commit SHA pinned/i);
    }
    deactivateAudit(sid);
});

// ----: synthesized npm i + synthesized npx ----

function denyTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "chained-install-fetch-fallback-syn-" + Math.random().toString(36).slice(2, 8);
        deactivateAudit(sid);
        activateAudit({
            sessionId: sid,
            buildPath: BUILD_ROOT,
            mode,
            expectedClonePath: CLONE_PATH,
        });
        const r = inspectToolCall({
            sessionId: sid,
            toolName: "powershell",
            toolArgs: { command },
        });
        assert.equal(r.decision, "deny",
            `expected deny, got: ${r.decision} | reason: ${r.reason || ""}`);
        deactivateAudit(sid);
    });
}

denyTest("chained-install-fetch-fallback: `& ([char]110+[char]112+[char]109) i` (synthesized npm i) is DENIED",
    "& ([char]110+[char]112+[char]109) i somepkg");
denyTest("chained-install-fetch-fallback: `& ([char]110+[char]112+[char]120) somepkg` (synthesized npx, no verb) is DENIED",
    "& ([char]110+[char]112+[char]120) somepkg");
denyTest("chained-install-fetch-fallback: any command with PS synthesis sigil in audit-only mode is DENIED",
    "& ([char]65+[char]66+[char]67) somerandomcommand");

test("chained-install-fetch-fallback: PS synthesis is ALLOWED in build mode (sanity — agent uses safe wrappers)", () => {
    // In build mode the wrappers do their own validation; PS synthesis
    // is only blanket-blocked in audit-only modes.
    const sid = "chained-install-fetch-fallback-syn-build-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: SAFE_BUILD,
        expectedClonePath: CLONE_PATH,
    });
    // Bare synthesis with no clone/install pattern — should pass through.
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "& ('a','b','c' -join '')" },
    });
    assert.notEqual(r.decision, "deny");
    deactivateAudit(sid);
});

// ---- Sanity ----

test("chained-install-fetch-fallback sanity: legitimate audit command without synthesis is ALLOWED", () => {
    const sid = "chained-install-fetch-fallback-sanity-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "echo hello world" },
    });
    assert.notEqual(r.decision, "deny");
    deactivateAudit(sid);
});

test("chained-install-fetch-fallback sanity: hardened raw git clone in build mode still ALLOWED", () => {
    const sid = "chained-install-fetch-fallback-allow-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: SAFE_BUILD,
        expectedClonePath: CLONE_PATH,
    });
    const cmd = "git -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --filter=blob:none --no-checkout https://github.com/octocat/Hello-World " + CLONE_PATH;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "allow");
    deactivateAudit(sid);
});
