// __tests__/v4r2r7Hardening.test.mjs
//
// Anchor tests for v4-r2 ROUND-7 hardening:
//   1/3 HIGH (B) — synthesis sigils split apart by `(`/`)`
//                  (`& ([char]110+[char]112+[char]109) install` bypassed
//                  in BUILD mode because per-sub detection lost the pair)
//   1/3 HIGH (A) — PS_SYNTHESIS_SIGIL_RE over-blocked legit audit cmds
//                  (`gh api -f`, `&& (subshell)`, `grep "iex"`)
//   1/3 HIGH (C) — verify_release tool description claim mismatch
//   1/3 HIGH (C) — build-mode raw `git clone` allowed without hardening
//                  flags (only path was validated)

import { test } from "node:test";
import assert from "node:assert/strict";

import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck"
    : "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60"
    : "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

const SAFE_BUILD = "audit_and_safe_build";

// ---- B-R7-1: whole-command synthesis fallback in BUILD mode ----

test("v4-r2-r7: `& ([char]110+[char]112+[char]109) install` is DENIED in BUILD mode (whole-command synthesis fallback)", () => {
    const sid = "v4r2r7-syninstall-build-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "& ([char]110+[char]112+[char]109) install" },
    });
    assert.equal(r.decision, "deny",
        `synthesis-as-install must be denied in build mode too. got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("v4-r2-r7: `& ([char]110+[char]112+[char]109) install --ignore-scripts` is DENIED in BUILD mode", () => {
    const sid = "v4r2r7-syninstall-build2-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "& ([char]110+[char]112+[char]109) install --ignore-scripts" },
    });
    assert.equal(r.decision, "deny",
        "synthesized install denied regardless of safe-flag presence");
    deactivateAudit(sid);
});

// ---- A-R7-1: PS_SYNTHESIS_SIGIL_RE false-positive cleanup ----

function allowTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "v4r2r7-allow-" + Math.random().toString(36).slice(2, 8);
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
        assert.notEqual(r.decision, "deny",
            `expected NOT deny, got: ${r.decision} | reason: ${r.reason || ""}`);
        deactivateAudit(sid);
    });
}

allowTest("v4-r2-r7: `cd repo && (ls -la)` (chained subshell, not synthesis) is ALLOWED",
    "cd repo && (ls -la)");
allowTest("v4-r2-r7: `Test-Path foo && { echo yes }` (chained scriptblock) is ALLOWED",
    "Test-Path foo && { echo yes }");
allowTest('v4-r2-r7: `gh api -f "title=bug" repos/x/y/issues` (gh form-field syntax) is ALLOWED',
    'gh api -f "title=bug" repos/x/y/issues');
allowTest('v4-r2-r7: `Select-String -Pattern "iex" -Path *.ps1` (literal IOC grep) is ALLOWED',
    'Select-String -Pattern "iex" -Path *.ps1');
allowTest('v4-r2-r7: `echo "avoid Invoke-Expression please"` (literal in quoted string) is ALLOWED',
    'echo "avoid Invoke-Expression please"');
allowTest('v4-r2-r7: `rg -join "hello"` (literal -join in arg) is ALLOWED',
    'rg -join "hello"');

// Sanity: synthesis sigils OUTSIDE quoted strings still trip
function denyTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "v4r2r7-deny-" + Math.random().toString(36).slice(2, 8);
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

denyTest("v4-r2-r7 sanity: real `& ([char]…)` synthesis still DENIED in audit mode",
    "& ([char]110+[char]112+[char]109) install");
denyTest("v4-r2-r7 sanity: real `iex \"...\"` (Invoke-Expression usage) still DENIED",
    "iex \"git clone https://x/y\"");
denyTest("v4-r2-r7 sanity: real `& $g clone` still DENIED",
    "$g='git'; & $g clone https://x/y " + CLONE_PATH);

// ---- C-R7-2: build-mode raw clone requires hardening flags ----

test("v4-r2-r7: build-mode `git clone <url> <correct-dest>` (no hardening flags) is DENIED", () => {
    const sid = "v4r2r7-clone-bare-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "git clone https://github.com/octocat/Hello-World " + CLONE_PATH },
    });
    assert.equal(r.decision, "deny",
        `bare git clone (no hardening flags) must be denied. got: ${r.decision} | reason: ${r.reason || ""}`);
    assert.match(r.reason, /hardening flag/i);
    deactivateAudit(sid);
});

test("v4-r2-r7: build-mode `git clone --depth 1 <url> <correct-dest>` (partial hardening) is DENIED", () => {
    const sid = "v4r2r7-clone-partial-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "git clone --depth 1 https://github.com/octocat/Hello-World " + CLONE_PATH },
    });
    assert.equal(r.decision, "deny",
        "missing flags like --no-checkout / --filter=blob:none should be denied");
    deactivateAudit(sid);
});

test("v4-r2-r7: build-mode `git clone` with ALL hardening flags is ALLOWED (sanity)", () => {
    const sid = "v4r2r7-clone-full-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const cmd = "git -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --filter=blob:none --no-checkout https://github.com/octocat/Hello-World " + CLONE_PATH;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "allow");
    deactivateAudit(sid);
});

test("v4-r2-r7: build-mode `git clone` missing only `--filter=blob:none` is DENIED with explicit list", () => {
    const sid = "v4r2r7-clone-missing-filter-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const cmd = "git -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --no-checkout https://github.com/octocat/Hello-World " + CLONE_PATH;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /--filter=blob:none/);
    deactivateAudit(sid);
});
