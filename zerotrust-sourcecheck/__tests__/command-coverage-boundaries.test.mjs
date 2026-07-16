// __tests__/command-coverage-boundaries.test.mjs
//
// Anchor tests for command-coverage-boundaries security — the security rationale triple-review fixes
// shipped after api-direct-binary-boundaries. security rationale found 3 critical/high issues with 3/3
// reviewer consensus:
//
//   1. CRITICAL: Git-clone regex `/\bgit(?:\s+-c\s+\S+)*\s+clone\b/i`
//      was bypassed by ALL non-`-c` global flag forms:
//        git.exe clone, git --no-pager clone, git --git-dir=x clone,
//        git --bare clone, git --work-tree=x clone,
//        full-path "C:\Program Files\Git\bin\git.exe" clone,
//        and entirely-different program `gh repo clone`.
//      In audit-only modes any of these would put attacker source on
//      disk and trip Defender — defeating current's headline guarantee.
//
//   2. HIGH: safeListTreeHandler dropped the local 5000-entry cap
//      signals (entriesTruncated / totalEntryCount). A malicious
//      >5000-entry repo could hide payload past the cap; agent saw
//      `truncated: false` and assumed complete coverage.
//
//   3. HIGH: text scripts must be classified from bytes and returned as text.

import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyAsBinary } from "../safeWrappers/apiClient.mjs";
import { safeListTreeHandler } from "../safeWrappers/safeListTreeHandler.mjs";
import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60": "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

// ---------- 1. Binary classification: text scripts must be TEXT ----------

test("command-coverage-boundaries: classifyAsBinary keeps PowerShell scripts (.ps1/.psm1/.psd1) as TEXT", () => {
    const cleanText = Buffer.from("Write-Host 'hello world'", "utf-8");
    assert.equal(classifyAsBinary(cleanText, "install.ps1"), false, ".ps1 must be text");
    assert.equal(classifyAsBinary(cleanText, "module.psm1"), false, ".psm1 must be text");
    assert.equal(classifyAsBinary(cleanText, "manifest.psd1"), false, ".psd1 must be text");
});

test("command-coverage-boundaries: classifyAsBinary keeps Windows batch (.bat/.cmd) as TEXT", () => {
    const cleanText = Buffer.from("@echo off\r\necho hello\r\n", "utf-8");
    assert.equal(classifyAsBinary(cleanText, "setup.bat"), false, ".bat must be text");
    assert.equal(classifyAsBinary(cleanText, "build.cmd"), false, ".cmd must be text");
});

test("command-coverage-boundaries: classifyAsBinary keeps Windows scripts (.wsf/.hta) and SVG as TEXT", () => {
    const cleanText = Buffer.from("<job><script>WScript.Echo('x')</script></job>", "utf-8");
    assert.equal(classifyAsBinary(cleanText, "wrap.wsf"), false, ".wsf must be text");
    assert.equal(classifyAsBinary(cleanText, "app.hta"), false, ".hta must be text");
    assert.equal(classifyAsBinary(cleanText, "icon.svg"), false, ".svg must be text");
});

test("coverage security: plain text under .jse/.vbe remains TEXT", () => {
    const cleanText = Buffer.from("plain text but extension says encoded", "utf-8");
    assert.equal(classifyAsBinary(cleanText, "evil.jse"), false);
    assert.equal(classifyAsBinary(cleanText, "evil.vbe"), false);
});

test("command-coverage-boundaries: classifyAsBinary still treats true binaries as BINARY", () => {
    const pe = Buffer.alloc(132);
    pe[0] = 0x4D;
    pe[1] = 0x5A;
    pe.writeUInt32LE(128, 0x3C);
    pe.set([0x50, 0x45, 0x00, 0x00], 128);
    assert.equal(classifyAsBinary(pe, "setup.exe"), true);
    assert.equal(classifyAsBinary(Buffer.from([0x7F, 0x45, 0x4C, 0x46]), "lib.dll"), true);
    assert.equal(classifyAsBinary(Buffer.from([0x50, 0x4B, 0x03, 0x04]), "archive.zip"), true);
    assert.equal(classifyAsBinary(
        Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        "image.png",
    ), true);
});

// ---------- 2. safeListTreeHandler forwards truncation signals ----------
//
// We can't make a live API call without network, so verify the SHAPE of
// the response on a validation-failure path (the input-validation path
// returns a structured failure that doesn't include these fields anyway).
// The contract is enforced by the source change in safeListTreeHandler.mjs;
// here we just sanity-check that the response shape is JSON.

test("command-coverage-boundaries: safeListTreeHandler input-validation failure still returns valid shape", async () => {
    const r = await safeListTreeHandler({ url: "not-a-github-url" }, {});
    assert.equal(r.resultType, "failure");
    const parsed = JSON.parse(r.textResultForLlm);
    assert.equal(parsed.ok, false);
});

// We test the truncation-signal forwarding by reading the source file
// directly and asserting the keys are emitted.
test("command-coverage-boundaries: safeListTreeHandler surfaces truncation and aggregate coverage fields", async () => {
    const fs = await import("node:fs");
    const url = await import("node:url");
    const path = await import("node:path");
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    const src = fs.readFileSync(path.join(here, "..", "safeWrappers", "safeListTreeHandler.mjs"), "utf-8");
    assert.match(src, /entriesTruncated:\s*state\.localEntryCapSeen/,
        "must surface local entry-cap truncation");
    assert.match(src, /aggregateEntryCount:/, "must surface aggregate entry count");
    assert.match(src, /unresolvedSubtrees:/, "must surface unresolved subtrees");
    assert.match(src, /coverageComplete[,:]/, "must surface combined coverageComplete flag");
});

// ---------- 3. Git-clone bypass: ALL forms denied in audit modes ----------

function testCloneDenied(testName, command, mode = "audit_source") {
    test(testName, () => {
        const sid = "command-coverage-boundaries-clone-deny-" + Math.random().toString(36).slice(2, 8);
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
        assert.equal(r.decision, "deny", `expected deny, got: ${r.decision} | reason: ${r.reason || ""}`);
        deactivateAudit(sid);
    });
}

testCloneDenied(
    "command-coverage-boundaries: git.exe clone in audit_source is DENIED",
    "git.exe clone https://github.com/octocat/Hello-World " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: git --no-pager clone in audit_source is DENIED",
    "git --no-pager clone https://github.com/octocat/Hello-World " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: git --git-dir=x clone in audit_source is DENIED",
    "git --git-dir=x clone https://github.com/octocat/Hello-World " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: git --bare clone in audit_source is DENIED",
    "git --bare clone https://github.com/octocat/Hello-World " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: git --work-tree=x clone in audit_source is DENIED",
    "git --work-tree=x clone https://github.com/octocat/Hello-World " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: git --paginate clone in audit_source is DENIED",
    "git --paginate clone https://github.com/octocat/Hello-World " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: gh repo clone in audit_source is DENIED",
    "gh repo clone octocat/Hello-World " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: gh.exe repo clone in audit_source is DENIED",
    "gh.exe repo clone octocat/Hello-World " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: full-path quoted git.exe clone in audit_source is DENIED",
    '"C:\\Program Files\\Git\\bin\\git.exe" clone https://github.com/x/y ' + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: chained `echo; git.exe clone` in audit_source is DENIED",
    "echo hi; git.exe clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: chained `echo && git --git-dir=x clone` in audit_source is DENIED",
    "echo hi && git --git-dir=x clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDenied(
    "command-coverage-boundaries: command-substitution `$(git clone ...)` in audit_source is DENIED",
    "$(git clone https://github.com/x/y " + CLONE_PATH + ")",
);
testCloneDenied(
    "command-coverage-boundaries: backtick `git clone ...` in audit_source is DENIED",
    "x=`git clone https://github.com/x/y " + CLONE_PATH + "`",
);

// All bypasses also denied in council audit mode + verify_release.
testCloneDenied(
    "command-coverage-boundaries: git.exe clone in audit_source_council is DENIED",
    "git.exe clone https://github.com/x/y " + CLONE_PATH,
    "audit_source_council",
);
testCloneDenied(
    "command-coverage-boundaries: gh repo clone in verify_release is DENIED",
    "gh repo clone x/y " + CLONE_PATH,
    "verify_release",
);

// gh repo clone is denied even in BUILD modes (it bypasses our
// security flags). The agent must use zerotrust_safe_clone or raw
// `git clone` with security flags applied.
test("command-coverage-boundaries: gh repo clone is DENIED even in build modes", () => {
    const sid = "command-coverage-boundaries-gh-build-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: "gh repo clone octocat/Hello-World " + CLONE_PATH },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /gh repo clone|security/i);
    deactivateAudit(sid);
});

// Sanity: hardened raw `git clone` STILL allowed in build mode.
test("command-coverage-boundaries sanity: hardened raw git clone still allowed in build mode", () => {
    const sid = "command-coverage-boundaries-clone-allow-" + Math.random().toString(36).slice(2, 8);
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
    assert.equal(r.decision, "allow", "build modes must still allow hardened clone");
    deactivateAudit(sid);
});

// Sanity: git.exe clone with valid path also allowed in build mode (not
// just literal "git" — the program-token-normalization fix from command-coverage-boundaries
// must accept the .exe basename too).
test("command-coverage-boundaries sanity: hardened git.exe clone allowed in build mode", () => {
    const sid = "command-coverage-boundaries-clone-allow-exe-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const cmd = "git.exe -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --filter=blob:none --no-checkout https://github.com/octocat/Hello-World " + CLONE_PATH;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "allow", "git.exe should normalize to git for the path-validation branch");
    deactivateAudit(sid);
});
