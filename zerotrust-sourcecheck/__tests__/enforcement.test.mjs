// enforcement.test.mjs
// Tests for the onPreToolUse audit-state machine + deny rules. Run with:
//   node --test __tests__/enforcement.test.mjs

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

import {
    activateAudit,
    deactivateAudit,
    getActiveAudit,
    inspectToolCall,
    preToolUseHook,
    consumeExpiryNotice,
    __internals,
} from "../enforcement.mjs";

const BUILD_ROOT = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck": "/tmp/zerotrust-sourcecheck";
const CLONE_PATH = process.platform === "win32"
    ? "C:\\test\\zerotrust-sourcecheck\\octocat-hello-abc1234": "/tmp/zerotrust-sourcecheck/octocat-hello-abc1234";

const SESSION = "test-session-1";

beforeEach(() => {
    __internals.activeAudits.clear();
});

test("no decision when no audit is active", () => {
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "git clone https://example.com/foo /tmp/foo" },
    });
    assert.equal(r.decision, undefined);
});

test("activate + getActiveAudit roundtrip", () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: CLONE_PATH,
    });
    const a = getActiveAudit(SESSION);
    assert.ok(a);
    assert.equal(a.mode, "audit_source");
    deactivateAudit(SESSION);
    assert.equal(getActiveAudit(SESSION), null);
});

test("expired audit is auto-cleared on read", () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: CLONE_PATH,
    });
    // Force-expire it.
    __internals.activeAudits.get(SESSION).expiresAt = Date.now() - 1000;
    assert.equal(getActiveAudit(SESSION), null);
});

// ---------- current Step 0.3: mode-dependent TTL ----------

test("current: ttlForMode returns generous values per mode (audit_source 60min, council 90min, build_council 180min)", () => {
    assert.equal(__internals.ttlForMode("audit_source"), 60 * 60 * 1000);
    assert.equal(__internals.ttlForMode("audit_source_council"), 90 * 60 * 1000);
    assert.equal(__internals.ttlForMode("audit_and_safe_build"), 120 * 60 * 1000);
    assert.equal(__internals.ttlForMode("audit_and_full_build"), 120 * 60 * 1000);
    assert.equal(__internals.ttlForMode("audit_and_safe_build_council"), 180 * 60 * 1000);
    assert.equal(__internals.ttlForMode("audit_and_full_build_council"), 180 * 60 * 1000);
    assert.equal(__internals.ttlForMode("metadata_only"), 15 * 60 * 1000);
    assert.equal(__internals.ttlForMode("verify_release"), 30 * 60 * 1000);
});

test("current: ttlForMode falls back to a generous default for unknown modes (no silent 30-min regression)", () => {
    assert.equal(__internals.ttlForMode("future-mode-not-in-table"), __internals.AUDIT_TTL_MS_DEFAULT);
    assert.ok(__internals.AUDIT_TTL_MS_DEFAULT >= 60 * 60 * 1000,
        "default TTL must be at least 60 minutes to avoid the previous silent-expiry regression");
});

test("current: activateAudit picks per-mode TTL (council mode gets >= 90 min)", () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BUILD_ROOT,
        mode: "audit_source_council",
        expectedClonePath: CLONE_PATH,
    });
    const a = __internals.activeAudits.get(SESSION);
    const remainingMs = a.expiresAt - Date.now();
    // Allow some slack for clock drift in the test
    assert.ok(remainingMs >= 89 * 60 * 1000, `council TTL too short: ${remainingMs}ms`);
    assert.ok(remainingMs <= 91 * 60 * 1000, `council TTL too long: ${remainingMs}ms`);
});

test("current: consumeExpiryNotice surfaces the silent-expiry event so it isn't invisible", () => {
    activateAudit({
        sessionId: SESSION,
        buildPath: BUILD_ROOT,
        mode: "audit_source_council",
        expectedClonePath: CLONE_PATH,
    });
    // Force expiration
    __internals.activeAudits.get(SESSION).expiresAt = Date.now() - 1000;
    // Reading triggers the expiry notice
    assert.equal(getActiveAudit(SESSION), null);
    const notice = consumeExpiryNotice(SESSION);
    assert.ok(notice, "expiry notice should be set");
    assert.equal(notice.mode, "audit_source_council");
    assert.ok(typeof notice.expiredAt === "number");
    // Notice is one-shot: consume clears it
    assert.equal(consumeExpiryNotice(SESSION), null);
});

test("current: consumeExpiryNotice returns null when nothing expired", () => {
    assert.equal(consumeExpiryNotice("never-existed-session"), null);
});

// ---------- git clone enforcement ----------

test("denies bare `git clone <url>` without destination", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "git clone https://github.com/octocat/hello.git" },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /destination/i);
});

test("denies clone to a path outside build_root", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const outside = process.platform === "win32" ? "C:\\temp\\evil": "/tmp/evil";
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `git clone https://github.com/octocat/hello.git ${outside}` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /build_root/i);
});

test("denies clone to a sibling under build_root that isn't the planned path", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const sibling = process.platform === "win32"
        ? "C:\\test\\zerotrust-sourcecheck\\unrelated-other": "/tmp/zerotrust-sourcecheck/unrelated-other";
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `git clone https://github.com/octocat/hello.git ${sibling}` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /planned/i);
});

test("allows clone to the planned path with security flags", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: {
            command: `git -c protocol.file.allow=never -c core.symlinks=false clone --no-recurse-submodules --filter=blob:none --no-checkout https://github.com/octocat/hello.git ${CLONE_PATH}`,
        },
    });
    assert.equal(r.decision, "allow");
});

// ---------- Package-manager install enforcement ----------

test("denies `npm install` without --ignore-scripts in audit_and_safe_build", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "npm install" },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /--ignore-scripts/);
});

test("denies `npm ci` without --ignore-scripts in audit_and_safe_build", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "npm ci" },
    });
    assert.equal(r.decision, "deny");
});

test("allows `npm ci --ignore-scripts` in audit_and_safe_build", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "npm ci --ignore-scripts" },
    });
    assert.equal(r.decision, undefined);
});

test("denies any npm install in audit_only / verify_release / metadata_only / audit_source modes", () => {
    for (const mode of ["audit_source", "verify_release", "metadata_only"]) {
        __internals.activeAudits.clear();
        activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode, expectedClonePath: CLONE_PATH });
        const r = inspectToolCall({
            sessionId: SESSION,
            toolName: "powershell",
            toolArgs: { command: "npm ci --ignore-scripts" },
        });
        assert.equal(r.decision, "deny", `mode=${mode} should deny installs entirely`);
        assert.match(r.reason, /does not include a build step/i);
    }
});

test("permits `npm install` (no flag) only in audit_and_full_build", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_full_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "npm install" },
    });
    assert.equal(r.decision, undefined); // no opinion -> default permission flow
});

test("denies `pip install` without safe flag in audit_and_safe_build", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "pip install -r requirements.txt" },
    });
    assert.equal(r.decision, "deny");
});

test("allows `pip install --only-binary=:all:` in audit_and_safe_build", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "pip install --only-binary=:all: -r requirements.txt" },
    });
    assert.equal(r.decision, undefined);
});

test("denies `gradle build` even in safe-build mode (no safe-mode flag)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "./gradlew build" },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /gradle/i);
});

// ---------- Execution enforcement ----------

test("denies Start-Process of a binary under build_root", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const targetExe = process.platform === "win32"
        ? `${CLONE_PATH}\\dist\\app.exe`: `${CLONE_PATH}/dist/app.exe`;
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `Start-Process "${targetExe}"` },
    });
    assert.equal(r.decision, "deny");
});

test("denies direct .exe invocation under build_root", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const targetExe = process.platform === "win32"
        ? `${CLONE_PATH}\\dist\\app.exe`: `${CLONE_PATH}/dist/app.exe`;
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `& "${targetExe}" --help` },
    });
    assert.equal(r.decision, "deny");
});

test("denies Mount-DiskImage of an .iso under build_root", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "verify_release", expectedClonePath: CLONE_PATH });
    const targetIso = process.platform === "win32"
        ? `C:\\test\\zerotrust-sourcecheck\\_quarantine\\octocat-hello-abc1234\\foo.bin`: `/tmp/zerotrust-sourcecheck/_quarantine/octocat-hello-abc1234/foo.bin`;
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `Mount-DiskImage -ImagePath "${targetIso}"` },
    });
    assert.equal(r.decision, "deny");
});

test("ignores benign command outside enforcement scope", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: "Get-Date" },
    });
    assert.equal(r.decision, undefined);
});

// ---------- Hook adapter shape ----------

test("preToolUseHook returns SDK-shaped output for deny", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_and_safe_build", expectedClonePath: CLONE_PATH });
    const out = preToolUseHook(
        { toolName: "powershell", toolArgs: { command: "npm install" } },
        { sessionId: SESSION },
    );
    assert.equal(out.permissionDecision, "deny");
    assert.match(out.permissionDecisionReason, /--ignore-scripts/);
});

test("preToolUseHook returns undefined when no opinion", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const out = preToolUseHook(
        { toolName: "powershell", toolArgs: { command: "Get-Date" } },
        { sessionId: SESSION },
    );
    assert.equal(out, undefined);
});

// ---------- security rationale: GUI-launch + disk-download enforcement ----------
// Regression for the user-visible "Notepad opened itself on agent_scratch.txt"
// and "command-line windows briefly flashed" bugs. Sub-agents called
// `Invoke-Item <file>` (Notepad pop-up) and `iwr -OutFile <file>` (downloaded
// source bytes to disk leaving scratch files) during an API-direct audit.

const TARGET_TXT = process.platform === "win32"
    ? "C:\\test\\agent_scratch.txt": "/tmp/agent_scratch.txt";

test("denies Invoke-Item against a file outside build_root (Notepad pop-up bug)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source_council", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `Invoke-Item "${TARGET_TXT}"` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /Invoke-Item|default-handler/i);
});

test("denies `ii` PowerShell alias for Invoke-Item", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source_council", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `ii "${TARGET_TXT}"` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /ii|Invoke-Item/i);
});

test("denies Start-Process against a file outside build_root", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source_council", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `Start-Process "${TARGET_TXT}"` },
    });
    assert.equal(r.decision, "deny");
});

test("denies `cmd /c start <file>` (default handler launch)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_local_source", localPath: BUILD_ROOT, expectedReportPath: `${BUILD_ROOT}/_reports/x` });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `cmd /c start "${TARGET_TXT}"` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /cmd \/c start|default-handler/i);
});

test("denies bare `start <file>` (cmd.exe builtin)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `start "${TARGET_TXT}"` },
    });
    assert.equal(r.decision, "deny");
});

test("denies notepad against any file", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `notepad "${TARGET_TXT}"` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /notepad/i);
});

test("denies VS Code launcher (`code <path>`)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `code "${TARGET_TXT}"` },
    });
    assert.equal(r.decision, "deny");
});

test("denies Invoke-WebRequest -OutFile (disk-write download)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source_council", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `Invoke-WebRequest -Uri https://example.com/file.cpp -OutFile "${TARGET_TXT}"` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /OutFile|disk-writing|safe_fetch_file/i);
});

test("denies `iwr` alias with -OutFile", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source_council", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `iwr https://example.com/x.c -OutFile x.c` },
    });
    assert.equal(r.decision, "deny");
});

test("denies `curl -o <file>` download", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `curl -o BootEncryption.cpp https://example.com/BootEncryption.cpp` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /curl/i);
});

test("denies `wget -O <file>` download", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `wget -O out.bin https://example.com/file` },
    });
    assert.equal(r.decision, "deny");
});

// ---- regression: legitimate commands must NOT be denied ----

test("ALLOWS Invoke-WebRequest without -OutFile (in-memory fetch)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `Invoke-WebRequest -Uri https://api.example.com/x.json` },
    });
    assert.notEqual(r.decision, "deny");
});

test("ALLOWS curl without -o (stdout)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `curl -fsSL https://api.example.com/foo` },
    });
    assert.notEqual(r.decision, "deny");
});

test("ALLOWS gh api (legitimate maintainer-history use)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source_council", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `gh api repos/octocat/Hello-World/commits?per_page=10` },
    });
    assert.notEqual(r.decision, "deny");
});

test("ALLOWS Get-ChildItem / Get-FileHash / standard read ops", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    for (const cmd of [
        `Get-ChildItem C:\\test\\zerotrust-sourcecheck\\_reports`,
        `Get-FileHash -Algorithm SHA256 some/path.bin`,
        `git log --oneline -n 10`,
    ]) {
        const r = inspectToolCall({
            sessionId: SESSION,
            toolName: "powershell",
            toolArgs: { command: cmd },
        });
        assert.notEqual(r.decision, "deny", `should not deny: ${cmd}`);
    }
});

test("does NOT deny `start` substring inside other tokens (false-positive guard)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    // "Start" / "start" should only deny when it's a standalone cmd.exe
    // invocation against a path/URL — not when it appears inside a word
    // or as part of a normal cmdlet name (Start-Sleep, etc. are still
    // denied as Start-Process variants are dangerous, but Get-Service /
    // Start-Sleep alone shouldn't be a false positive here).
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `Get-Content somefile.txt | Select-String "start"` },
    });
    assert.notEqual(r.decision, "deny");
});

// ---------- security rationale: regex-bypass fixes from triple-review ----------

test("denies `ii .` (open current dir in Explorer)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `ii .` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /ii|Invoke-Item/i);
});

test("denies `ii ..` and `ii $path` (variable target)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    for (const cmd of [`ii ..`, `ii $somepath`, `ii foo`]) {
        const r = inspectToolCall({
            sessionId: SESSION,
            toolName: "powershell",
            toolArgs: { command: cmd },
        });
        assert.equal(r.decision, "deny", `should deny: ${cmd}`);
    }
});

test("denies `code .` (open current dir in VS Code)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `code .` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /VS Code/i);
});

test("denies `code ..` and `code somefile.txt`", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    for (const cmd of [`code ..`, `code somefile.txt`]) {
        const r = inspectToolCall({
            sessionId: SESSION,
            toolName: "powershell",
            toolArgs: { command: cmd },
        });
        assert.equal(r.decision, "deny", `should deny: ${cmd}`);
    }
});

test("ALLOWS `code -v` / `code --version` (flag-only, no target)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    for (const cmd of [`code -v`, `code --version`, `code --help`]) {
        const r = inspectToolCall({
            sessionId: SESSION,
            toolName: "powershell",
            toolArgs: { command: cmd },
        });
        assert.notEqual(r.decision, "deny", `should NOT deny: ${cmd}`);
    }
});

test("denies `start .` and `start /B foo`", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    for (const cmd of [`start .`, `start ..`, `start /B foo.exe`, `start "title" foo.txt`]) {
        const r = inspectToolCall({
            sessionId: SESSION,
            toolName: "powershell",
            toolArgs: { command: cmd },
        });
        assert.equal(r.decision, "deny", `should deny: ${cmd}`);
    }
});

test("`Start-Process` still caught by its own pattern (not the new bare-start pattern)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `Start-Process notepad` },
    });
    assert.equal(r.decision, "deny");
});

test("denies `iwr URL | Out-File file` (pipe to disk-write sink)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `iwr https://example.com/x.c | Out-File x.c` },
    });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /Out-File|Set-Content|Tee-Object|disk-writing/i);
});

test("denies `curl URL | Set-Content file` (pipe form)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `curl https://example.com/x.c | Set-Content x.c` },
    });
    assert.equal(r.decision, "deny");
});

test("denies `gh api ... | Out-File file` (pipe form)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `gh api repos/foo/bar/contents/file.c | Out-File file.c` },
    });
    assert.equal(r.decision, "deny");
});

test("ALLOWS legitimate `Out-File` for report writing (no download upstream)", () => {
    activateAudit({ sessionId: SESSION, buildPath: BUILD_ROOT, mode: "audit_source", expectedClonePath: CLONE_PATH });
    // The orchestrator writing REPORT.md via Out-File is legitimate.
    // Only the <download> | Out-File COMBINATION is denied.
    const r = inspectToolCall({
        sessionId: SESSION,
        toolName: "powershell",
        toolArgs: { command: `"# audit report" | Out-File REPORT.md` },
    });
    assert.notEqual(r.decision, "deny");
});


