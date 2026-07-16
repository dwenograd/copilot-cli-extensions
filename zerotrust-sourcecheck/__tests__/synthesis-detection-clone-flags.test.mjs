// __tests__/synthesis-detection-clone-flags.test.mjs
//
// Anchor tests for security rationale:
//   Security case — synthesis sigils split apart by `(`/`)`
//                  (`& ([char]110+[char]112+[char]109) install` bypassed
//                  in BUILD mode because per-sub detection lost the pair)
//   Security case — PS_SYNTHESIS_SIGIL_RE over-blocked legit audit cmds
//                  (`gh api -f`, `&& (subshell)`, `grep "iex"`)
//   Security case — verify_release tool description claim mismatch
//   Security case — build-mode raw `git clone` allowed without security
//                  flags (only path was validated)

import { test } from "node:test";
import assert from "node:assert/strict";

import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60": "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

const SAFE_BUILD = "audit_and_safe_build";

// ----: whole-command synthesis fallback in BUILD mode ----

test("synthesis-detection-clone-flags: `& ([char]110+[char]112+[char]109) install` is DENIED in BUILD mode (whole-command synthesis fallback)", () => {
    const sid = "synthesis-detection-clone-flags-syninstall-build-" + Math.random().toString(36).slice(2, 8);
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

test("synthesis-detection-clone-flags: `& ([char]110+[char]112+[char]109) install --ignore-scripts` is DENIED in BUILD mode", () => {
    const sid = "synthesis-detection-clone-flags-syninstall-build2-" + Math.random().toString(36).slice(2, 8);
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

// ----: PS_SYNTHESIS_SIGIL_RE false-positive cleanup ----

function allowTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "synthesis-detection-clone-flags-allow-" + Math.random().toString(36).slice(2, 8);
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

allowTest("synthesis-detection-clone-flags: `cd repo && (ls -la)` (chained subshell, not synthesis) is ALLOWED",
    "cd repo && (ls -la)");
allowTest("synthesis-detection-clone-flags: `Test-Path foo && { echo yes }` (chained scriptblock) is ALLOWED",
    "Test-Path foo && { echo yes }");
allowTest('synthesis-detection-clone-flags: `gh api -f "title=bug" repos/x/y/issues` (gh form-field syntax) is ALLOWED',
    'gh api -f "title=bug" repos/x/y/issues');
allowTest('synthesis-detection-clone-flags: `Select-String -Pattern "iex" -Path *.ps1` (literal IOC grep) is ALLOWED',
    'Select-String -Pattern "iex" -Path *.ps1');
allowTest('synthesis-detection-clone-flags: `echo "avoid Invoke-Expression please"` (literal in quoted string) is ALLOWED',
    'echo "avoid Invoke-Expression please"');
allowTest('synthesis-detection-clone-flags: `rg -join "hello"` (literal -join in arg) is ALLOWED',
    'rg -join "hello"');

// Sanity: synthesis sigils OUTSIDE quoted strings still trip
function denyTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "synthesis-detection-clone-flags-deny-" + Math.random().toString(36).slice(2, 8);
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

denyTest("synthesis-detection-clone-flags sanity: real `& ([char]…)` synthesis still DENIED in audit mode",
    "& ([char]110+[char]112+[char]109) install");
denyTest("synthesis-detection-clone-flags sanity: real `iex \"...\"` (Invoke-Expression usage) still DENIED",
    "iex \"git clone https://x/y\"");
denyTest("synthesis-detection-clone-flags sanity: real `& $g clone` still DENIED",
    "$g='git'; & $g clone https://x/y " + CLONE_PATH);

// ----: build-mode raw clone requires security flags ----

test("synthesis-detection-clone-flags: build-mode `git clone <url> <correct-dest>` (no security flags) is DENIED", () => {
    const sid = "synthesis-detection-clone-flags-clone-bare-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({ sessionId: sid, buildPath: BUILD_ROOT, mode: SAFE_BUILD, expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "git clone https://github.com/octocat/Hello-World " + CLONE_PATH },
    });
    assert.equal(r.decision, "deny",
        `bare git clone (no security flags) must be denied. got: ${r.decision} | reason: ${r.reason || ""}`);
    assert.match(r.reason, /security flag/i);
    deactivateAudit(sid);
});

test("synthesis-detection-clone-flags: build-mode `git clone --depth 1 <url> <correct-dest>` (partial security) is DENIED", () => {
    const sid = "synthesis-detection-clone-flags-clone-partial-" + Math.random().toString(36).slice(2, 8);
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

test("synthesis-detection-clone-flags: build-mode `git clone` with ALL security flags is ALLOWED (sanity)", () => {
    const sid = "synthesis-detection-clone-flags-clone-full-" + Math.random().toString(36).slice(2, 8);
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

test("synthesis-detection-clone-flags: build-mode `git clone` missing only `--filter=blob:none` is DENIED with explicit list", () => {
    const sid = "synthesis-detection-clone-flags-clone-missing-filter-" + Math.random().toString(36).slice(2, 8);
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
