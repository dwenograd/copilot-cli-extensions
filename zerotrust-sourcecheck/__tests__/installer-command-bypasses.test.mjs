// __tests__/installer-command-bypasses.test.mjs
//
// Anchor tests for security rationale. security rationale found 8
// critical/high issues across 3 reviewers:
//
//   Security case — `--ignore-scripts=false` and full-command flag check
//     (npm install --ignore-scripts=false satisfied the regex but
//     npm interprets it as scripts-ENABLED; flag in a different
//     sub-command also satisfied)
//   Security case — cmd.exe caret escapes (cmd /c g^it cl^one)
//   Security case — install detection misses npm global flags + python -m pip
//   Security case — missing npm subcommands (pack/rebuild/run/test/start/exec)
//   Security case — npx + pnpm dlx + yarn dlx (download + execute)
//   Security case — PowerShell programmatic name synthesis
//   Security case — Bash ANSI-C $'\x67it' decoding
//   Security case — mid-token line continuation (git cl\<LF>one)
//
// All fixed in security rationale by:
//   - REQUIRE_IGNORE_SCRIPTS regex with negative lookahead
//   - Per-sub-command flag validation in inspectToolCall
//   - decodeAnsiCQuoting + caret-strip + line-continuation FUSE
//     in normalizeForSubstringScan
//   - Expanded INSTALL_RULES (npm subcommand list + npx/dlx separate
//     ecosystem + python -m pip + npm global-flag tolerance)
//   - PS_SYNTHESIS_SIGIL_RE detection in commandLooksLikeClone

import { test } from "node:test";
import assert from "node:assert/strict";

import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60": "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

function denyTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "installer-command-bypasses-" + Math.random().toString(36).slice(2, 8);
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

// ---- --ignore-scripts=false bypass ----

test("installer-command-bypasses: `npm install --ignore-scripts=false` is DENIED in safe-build (negation form)", () => {
    const sid = "installer-command-bypasses-isfalse-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --ignore-scripts=false" },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /ignore-scripts/i);
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npm install --ignore-scripts=0` is DENIED (negation form)", () => {
    const sid = "installer-command-bypasses-is0-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --ignore-scripts=0" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npm install --no-ignore-scripts` is DENIED (inverse form)", () => {
    const sid = "installer-command-bypasses-noinv-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --no-ignore-scripts" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npm install --ignore-scripts` (canonical form) is ALLOWED", () => {
    const sid = "installer-command-bypasses-iscan-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --ignore-scripts" },
    });
    assert.notEqual(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npm install --ignore-scripts=true` is ALLOWED", () => {
    const sid = "installer-command-bypasses-istrue-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install --ignore-scripts=true" },
    });
    assert.notEqual(r.decision, "deny");
    deactivateAudit(sid);
});

// ---- Per-sub-command flag validation ----

test("installer-command-bypasses: `npm install && echo --ignore-scripts` is DENIED (flag in wrong sub-command)", () => {
    const sid = "installer-command-bypasses-flagsub-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npm install && echo --ignore-scripts" },
    });
    assert.equal(r.decision, "deny",
        `expected deny: flag must be in same sub-command as install. got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("installer-command-bypasses: `echo --ignore-scripts; npm install` is DENIED (flag in different sub-command)", () => {
    const sid = "installer-command-bypasses-flagsub2-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "echo --ignore-scripts; npm install" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

// ---- cmd.exe caret escapes ----

denyTest("installer-command-bypasses: cmd /c `g^it cl^one` is DENIED",
    "cmd /c g^it cl^one https://github.com/x/y " + CLONE_PATH);
denyTest("installer-command-bypasses: `g^it clone` is DENIED",
    "g^it clone https://github.com/x/y " + CLONE_PATH);

// ---- npm global flags before install ----

test("installer-command-bypasses: `npm --prefix . install` in audit_source is DENIED", () => {
    const sid = "installer-command-bypasses-npmprefix-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm --prefix . install" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npm.ps1 install` in audit_source is DENIED", () => {
    const sid = "installer-command-bypasses-npmps1-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm.ps1 install" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

// ---- python -m pip and py -m pip ----

test("installer-command-bypasses: `python -m pip install foo` in audit_source is DENIED", () => {
    const sid = "installer-command-bypasses-pythonpip-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "python -m pip install foo" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `py -m pip install foo` in audit_source is DENIED (Windows launcher)", () => {
    const sid = "installer-command-bypasses-pypip-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "py -m pip install foo" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

// ---- npm subcommand expansion (pack/rebuild/run/test/start/exec) ----

test("installer-command-bypasses: `npm pack` in audit_source is DENIED (runs prepack/postpack)", () => {
    const sid = "installer-command-bypasses-npmpack-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm pack" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npm rebuild` in audit_source is DENIED", () => {
    const sid = "installer-command-bypasses-npmrebuild-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm rebuild" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npm run build` in audit_source is DENIED", () => {
    const sid = "installer-command-bypasses-npmrun-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm run build" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npm test` in audit_source is DENIED", () => {
    const sid = "installer-command-bypasses-npmtest-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm test" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

// ---- npx + pnpm dlx + yarn dlx ----

test("installer-command-bypasses: `npx evilpkg` in audit_source is DENIED", () => {
    const sid = "installer-command-bypasses-npx-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npx evilpkg" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `npx evilpkg` in safe-build is DENIED (no safe-flag)", () => {
    const sid = "installer-command-bypasses-npxbuild-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "npx evilpkg" },
    });
    assert.equal(r.decision, "deny",
        `npx has no safe-flag equivalent. got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("installer-command-bypasses: `pnpm dlx evilpkg` in safe-build is DENIED", () => {
    const sid = "installer-command-bypasses-pnpmdlx-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "pnpm dlx evilpkg" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses: `yarn dlx evilpkg` in safe-build is DENIED", () => {
    const sid = "installer-command-bypasses-yarndlx-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: "yarn dlx evilpkg" },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

// ---- PowerShell programmatic name synthesis ----

denyTest("installer-command-bypasses: `& ([char]103+[char]105+[char]116) clone` is DENIED",
    "& ([char]103+[char]105+[char]116) clone https://github.com/x/y " + CLONE_PATH);
denyTest("installer-command-bypasses: `& ('g','i','t' -join '') clone` is DENIED",
    "& ('g','i','t' -join '') clone https://github.com/x/y " + CLONE_PATH);
denyTest("installer-command-bypasses: `& ('{0}{1}{2}' -f 'g','i','t') clone` is DENIED",
    "& ('{0}{1}{2}' -f 'g','i','t') clone https://github.com/x/y " + CLONE_PATH);
denyTest("installer-command-bypasses: `iex 'git clone ...'` (Invoke-Expression) is DENIED",
    "iex 'git clone https://github.com/x/y " + CLONE_PATH + "'");

// ---- Bash ANSI-C $'\xHH' decoding ----

denyTest("installer-command-bypasses: bash `$'\\x67it' clone` (ANSI-C hex escape) is DENIED",
    "$'\\x67it' clone https://github.com/x/y " + CLONE_PATH);
denyTest("installer-command-bypasses: bash `git $'\\x63\\x6c\\x6f\\x6e\\x65'` (subcommand ANSI-C) is DENIED",
    "git $'\\x63\\x6c\\x6f\\x6e\\x65' https://github.com/x/y " + CLONE_PATH);
denyTest("installer-command-bypasses: bash `$'\\u0067it' clone` (ANSI-C unicode escape) is DENIED",
    "$'\\u0067it' clone https://github.com/x/y " + CLONE_PATH);

// ---- Mid-token line continuation ----

denyTest("installer-command-bypasses: bash mid-token line-continuation `git cl\\\\nonely` is DENIED",
    "git cl\\\none https://github.com/x/y " + CLONE_PATH);
denyTest("installer-command-bypasses: PS mid-token backtick line-continuation `git cl`\\nonely` is DENIED",
    "git cl`\none https://github.com/x/y " + CLONE_PATH);

// ---- Sanity: legit commands not over-blocked ----

test("installer-command-bypasses sanity: `npm view foo` is ALLOWED (no install/script-running subcommand)", () => {
    const sid = "installer-command-bypasses-npmview-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm view foo" },
    });
    assert.notEqual(r.decision, "deny",
        `npm view doesn't run scripts. got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("installer-command-bypasses sanity: `git status` is ALLOWED (no clone)", () => {
    const sid = "installer-command-bypasses-gitstatus-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "git status" },
    });
    assert.notEqual(r.decision, "deny");
    deactivateAudit(sid);
});

test("installer-command-bypasses sanity: hardened raw git clone in build mode is ALLOWED (regression)", () => {
    const sid = "installer-command-bypasses-allow-" + Math.random().toString(36).slice(2, 8);
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
    assert.equal(r.decision, "allow");
    deactivateAudit(sid);
});
