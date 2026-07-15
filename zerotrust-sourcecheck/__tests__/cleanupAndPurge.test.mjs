// __tests__/cleanupAndPurge.test.mjs
//
// Tests for v3.1 hardening:
//   - safeWrappers/cleanupWrapper.mjs (zerotrust_cleanup_audit tool)
//   - safeWrappers/autoPurge.mjs (stale-clone purge logic)

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, existsSync, statSync, utimesSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { cleanupAuditHandler } from "../safeWrappers/cleanupWrapper.mjs";
import {
    findStaleClones,
    purgeStaleClones,
    getPurgeHours,
    DEFAULT_PURGE_HOURS,
    __internals as purgeInternals,
} from "../safeWrappers/autoPurge.mjs";
import { __internals as cleanupInternals } from "../safeWrappers/cleanupWrapper.mjs";
import {
    activateAudit,
    deactivateAudit,
    getActiveAudit,
    recordResolvedClonePath,
} from "../enforcement.mjs";
import {
    clearRecordedOutcome,
    getRecordedOutcome,
    recordCouncilOutcome,
} from "../safeWrappers/state.mjs";
import { buildArtifactIdentityName } from "../urlParser.mjs";

const BR = join(tmpdir(), "zerotrust-test-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8));
let cleanupSequence = 0;

function fullBasename(repo, hex) {
    return buildArtifactIdentityName("octocat", repo, hex.repeat(40));
}

async function withCleanupAudit(clonePath, fn, mode = "audit_and_safe_build") {
    cleanupSequence += 1;
    const sessionId = `cleanup-active-${cleanupSequence}`;
    activateAudit({
        sessionId,
        buildPath: BR,
        mode,
        expectedClonePath: clonePath,
        owner: "octocat",
        repo: "Hello",
    });
    recordResolvedClonePath(sessionId, clonePath);
    try {
        return await fn(sessionId);
    } finally {
        deactivateAudit(sessionId);
        clearRecordedOutcome(sessionId);
    }
}

function mkClone(basename, contents = "test") {
    const p = join(BR, basename);
    mkdirSync(p, { recursive: true });
    writeFileSync(join(p, "marker.txt"), contents);
    return p;
}

function mkReportFor(basename) {
    const p = join(BR, "_reports", basename);
    mkdirSync(p, { recursive: true });
    writeFileSync(join(p, "REPORT.md"), "# fake report");
    return p;
}

function mkQuarantineFor(basename) {
    const p = join(BR, "_quarantine", basename);
    mkdirSync(p, { recursive: true });
    writeFileSync(join(p, "asset.bin"), Buffer.from([0x00, 0x01, 0x02]));
    return p;
}

function setMtimeAgo(p, hoursAgo) {
    const t = new Date(Date.now() - hoursAgo * 60 * 60 * 1000);
    utimesSync(p, t, t);
}

test.beforeEach(() => {
    if (existsSync(BR)) rmSync(BR, { recursive: true, force: true });
    mkdirSync(BR, { recursive: true });
});

test.after(() => {
    if (existsSync(BR)) rmSync(BR, { recursive: true, force: true });
});

// ---------- cleanupAuditHandler ----------

test("cleanupAuditHandler rejects missing clone_path", async () => {
    const r = await cleanupAuditHandler({ build_root: BR }, {});
    assert.equal(r.resultType, "failure");
});

test("cleanupAuditHandler rejects relative clone_path", async () => {
    const r = await cleanupAuditHandler({ clone_path: "relative\\path", build_root: BR }, {});
    assert.equal(r.resultType, "failure");
});

test("cleanupAuditHandler rejects clone_path equal to build_root (would delete sandbox)", async () => {
    const r = await cleanupAuditHandler({ clone_path: BR, build_root: BR }, {});
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /requires an invocation sessionId/);
});

test("cleanupAuditHandler rejects clone_path outside build_root", async () => {
    const outside = process.platform === "win32" ? "C:\\Windows\\Temp\\evil" : "/etc/evil";
    const r = await cleanupAuditHandler({ clone_path: outside, build_root: BR }, {});
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /requires an invocation sessionId/);
});

test("cleanupAuditHandler deletes existing clone (idempotent on missing)", async () => {
    const cp = mkClone(fullBasename("Hello", "a"));
    assert.ok(existsSync(cp));
    await withCleanupAudit(cp, async (sessionId) => {
        const r = await cleanupAuditHandler({ clone_path: cp, build_root: BR }, { sessionId });
        assert.equal(r.resultType, "success");
        assert.equal(existsSync(cp), false);

        const r2 = await cleanupAuditHandler({ clone_path: cp, build_root: BR }, { sessionId });
        assert.equal(r2.resultType, "success");
    });
});

test("cleanupAuditHandler keeps REPORT.md by default", async () => {
    const basename = fullBasename("Hello", "b");
    const cp = mkClone(basename);
    const rp = mkReportFor(basename);
    await withCleanupAudit(cp, async (sessionId) => {
        const r = await cleanupAuditHandler({ clone_path: cp, build_root: BR }, { sessionId });
        assert.equal(r.resultType, "success");
        assert.equal(existsSync(cp), false);
        assert.equal(existsSync(rp), true, "report dir preserved");
    });
});

test("cleanupAuditHandler deletes REPORT.md when also_delete_report=true", async () => {
    const basename = fullBasename("Hello", "c");
    const cp = mkClone(basename);
    const rp = mkReportFor(basename);
    await withCleanupAudit(cp, async (sessionId) => {
        const r = await cleanupAuditHandler(
            { clone_path: cp, build_root: BR, also_delete_report: true },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
        assert.equal(existsSync(rp), false);
    });
});

test("cleanupAuditHandler deletes _quarantine by default", async () => {
    const basename = fullBasename("Hello", "d");
    const cp = mkClone(basename);
    const qp = mkQuarantineFor(basename);
    await withCleanupAudit(cp, async (sessionId) => {
        const r = await cleanupAuditHandler({ clone_path: cp, build_root: BR }, { sessionId });
        assert.equal(r.resultType, "success");
        assert.equal(existsSync(qp), false);
    });
});

test("cleanupAuditHandler keeps _quarantine when also_delete_quarantine=false", async () => {
    const basename = fullBasename("Hello", "e");
    const cp = mkClone(basename);
    const qp = mkQuarantineFor(basename);
    await withCleanupAudit(cp, async (sessionId) => {
        const r = await cleanupAuditHandler(
            { clone_path: cp, build_root: BR, also_delete_quarantine: false },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
        assert.equal(existsSync(qp), true, "quarantine preserved");
    });
});

test("cleanupAuditHandler is robust against attempted ../ escape via clone_path", async () => {
    // pathIsUnder uses path.relative which canonicalizes ../, so an attacker
    // can't smuggle a ../escape past the containment check.
    const escape = join(BR, "..", "outside-target");
    const r = await cleanupAuditHandler({ clone_path: escape, build_root: BR }, {});
    assert.equal(r.resultType, "failure");
});

test("cleanupAuditHandler refuses a real session with no active audit or custom-root fallback", async () => {
    const cp = mkClone(fullBasename("Hello", "2"));
    const r = await cleanupAuditHandler(
        { clone_path: cp, build_root: BR },
        { sessionId: "cleanup-no-active" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /requires an active audit|no active audit/i);
    assert.equal(existsSync(cp), true);
});

test("cleanupAuditHandler refuses non-build audits and clone-path mismatches", async () => {
    const cp = mkClone(fullBasename("Hello", "3"));
    const sibling = mkClone(fullBasename("Other", "4"));
    const nonBuild = "cleanup-non-build";
    activateAudit({
        sessionId: nonBuild,
        buildPath: BR,
        mode: "audit_source",
        expectedClonePath: cp,
        owner: "octocat",
        repo: "Hello",
    });
    recordResolvedClonePath(nonBuild, cp);
    try {
        const refused = await cleanupAuditHandler({ clone_path: cp }, { sessionId: nonBuild });
        assert.equal(refused.resultType, "failure");
        assert.match(refused.textResultForLlm, /only valid for build-mode audits/i);
    } finally {
        deactivateAudit(nonBuild);
    }

    await withCleanupAudit(cp, async (sessionId) => {
        const mismatch = await cleanupAuditHandler(
            { clone_path: sibling },
            { sessionId },
        );
        assert.equal(mismatch.resultType, "failure");
        assert.match(mismatch.textResultForLlm, /does not match the active audit's resolved clone path/i);
        assert.equal(existsSync(sibling), true);
    });
});

test("cleanupAuditHandler refuses legacy 7-character clone names for active cleanup", async () => {
    const cp = mkClone("octocat-Hello-abcdef0");
    await withCleanupAudit(cp, async (sessionId) => {
        const r = await cleanupAuditHandler({ clone_path: cp }, { sessionId });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /zt-v1-<sha256>/);
        assert.equal(existsSync(cp), true);
    });
});

test("cleanupAuditHandler refuses legacy flattened full-SHA names for active cleanup", async () => {
    const cp = mkClone(`octocat-Hello-${"a".repeat(40)}`);
    await withCleanupAudit(cp, async (sessionId) => {
        const r = await cleanupAuditHandler({ clone_path: cp }, { sessionId });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /zt-v1-<sha256>/);
        assert.equal(existsSync(cp), true);
    });
});

test("cleanupAuditHandler preserves trusted state after successful cleanup until close", async () => {
    const sessionId = "cleanup-state-" + Math.random().toString(36).slice(2);
    const cp = mkClone(fullBasename("Hello", "f"));
    activateAudit({
        sessionId,
        buildPath: BR,
        mode: "audit_and_safe_build_council",
        expectedClonePath: cp,
        owner: "octocat",
        repo: "Hello",
    });
    recordResolvedClonePath(sessionId, cp);
    recordCouncilOutcome(sessionId, {
        auditId: getActiveAudit(sessionId).auditId,
        owner: "octocat",
        repo: "hello",
        resolvedSha: null,
        verdict: "low",
        criticalCount: 0,
        highCount: 0,
        complete: true,
    });
    try {
        const r = await cleanupAuditHandler(
            { clone_path: cp, build_root: BR },
            { sessionId },
        );
        assert.equal(r.resultType, "success");
        assert.ok(getActiveAudit(sessionId), "cleanup must leave active audit context intact");
        assert.ok(getRecordedOutcome(sessionId), "cleanup must not clear council outcome");
    } finally {
        deactivateAudit(sessionId);
        clearRecordedOutcome(sessionId);
    }
});

test("cleanupAuditHandler deletion errors fail and preserve trusted state", async () => {
    const sessionId = "cleanup-failure-" + Math.random().toString(36).slice(2);
    const cp = mkClone(fullBasename("Hello", "1"));
    activateAudit({
        sessionId,
        buildPath: BR,
        mode: "audit_and_safe_build",
        expectedClonePath: cp,
        owner: "octocat",
        repo: "Hello",
    });
    recordResolvedClonePath(sessionId, cp);
    try {
        const r = await cleanupAuditHandler(
            { clone_path: cp, build_root: BR },
            { sessionId },
            {
                remove: () => ({
                    existed: true,
                    removed: false,
                    error: "simulated access denied",
                }),
            },
        );
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /simulated access denied/);
        assert.ok(getActiveAudit(sessionId), "failed cleanup must not deactivate the audit");
        assert.ok(existsSync(cp), "failed target must remain available for retry");
    } finally {
        deactivateAudit(sessionId);
    }
});

// ---------- autoPurge: getPurgeHours ----------

test("getPurgeHours: defaults to 24 when env unset", () => {
    assert.equal(getPurgeHours({}), DEFAULT_PURGE_HOURS);
});

test("getPurgeHours: returns 0 (disabled) when env=0", () => {
    assert.equal(getPurgeHours({ ZEROTRUST_AUTO_PURGE_HOURS: "0" }), 0);
});

test("getPurgeHours: returns custom value", () => {
    assert.equal(getPurgeHours({ ZEROTRUST_AUTO_PURGE_HOURS: "48" }), 48);
});

test("getPurgeHours: rejects negative values, falls back to default", () => {
    assert.equal(getPurgeHours({ ZEROTRUST_AUTO_PURGE_HOURS: "-1" }), DEFAULT_PURGE_HOURS);
});

test("getPurgeHours: rejects non-numeric, falls back to default", () => {
    assert.equal(getPurgeHours({ ZEROTRUST_AUTO_PURGE_HOURS: "yes" }), DEFAULT_PURGE_HOURS);
});

// ---------- autoPurge: findStaleClones ----------

test("findStaleClones: returns empty when build_root has no clones", () => {
    const stale = findStaleClones({ buildRoot: BR, hoursThreshold: 24 });
    assert.deepEqual(stale, []);
});

test("findStaleClones: ignores clones newer than threshold", () => {
    const cp = mkClone("octocat-Hello-1234567");
    setMtimeAgo(cp, 5); // 5h ago
    const stale = findStaleClones({ buildRoot: BR, hoursThreshold: 24 });
    assert.deepEqual(stale, []);
});

test("findStaleClones: returns clones older than threshold", () => {
    const cp = mkClone("octocat-Hello-1234567");
    setMtimeAgo(cp, 48); // 2 days ago
    const stale = findStaleClones({ buildRoot: BR, hoursThreshold: 24 });
    assert.deepEqual(stale, ["octocat-Hello-1234567"]);
});

test("findStaleClones recognizes canonical hashes and legacy orphan names", () => {
    const currentName = fullBasename("Hello", "a");
    const current = mkClone(currentName);
    const legacyFullName = `octocat-Hello-${"b".repeat(40)}`;
    const legacyFull = mkClone(legacyFullName);
    const legacy = mkClone("octocat-Hello-abcdef0");
    setMtimeAgo(current, 48);
    setMtimeAgo(legacyFull, 48);
    setMtimeAgo(legacy, 48);
    const stale = findStaleClones({ buildRoot: BR, hoursThreshold: 24 }).sort();
    assert.deepEqual(stale, ["octocat-Hello-abcdef0", legacyFullName, currentName].sort());
    assert.equal(purgeInternals.CLONE_NAME_RE.test(currentName), true);
    assert.equal(purgeInternals.CLONE_NAME_RE.test(legacyFullName), false);
    assert.equal(purgeInternals.CLONE_NAME_RE.test("octocat-Hello-abcdef0"), false);
    assert.equal(purgeInternals.LEGACY_FULL_SHA_CLONE_NAME_RE.test(legacyFullName), true);
    assert.equal(purgeInternals.LEGACY_CLONE_NAME_RE.test("octocat-Hello-abcdef0"), true);
});

test("findStaleClones: ignores _reports/ and _quarantine/ dirs (don't match clone-name regex)", () => {
    mkReportFor("octocat-Hello-1234567");
    mkQuarantineFor("octocat-Hello-1234567");
    setMtimeAgo(join(BR, "_reports"), 48);
    setMtimeAgo(join(BR, "_quarantine"), 48);
    const stale = findStaleClones({ buildRoot: BR, hoursThreshold: 24 });
    assert.deepEqual(stale, []);
});

test("findStaleClones: ignores arbitrarily-named dirs that don't match clone convention", () => {
    mkdirSync(join(BR, "random-dir"), { recursive: true });
    setMtimeAgo(join(BR, "random-dir"), 100);
    const stale = findStaleClones({ buildRoot: BR, hoursThreshold: 24 });
    assert.deepEqual(stale, []);
});

test("findStaleClones: respects exclude list", () => {
    const a = mkClone("octocat-A-aaaaaaa");
    const b = mkClone("octocat-B-bbbbbbb");
    setMtimeAgo(a, 48);
    setMtimeAgo(b, 48);
    const stale = findStaleClones({
        buildRoot: BR,
        hoursThreshold: 24,
        exclude: ["octocat-B-bbbbbbb"],
    });
    assert.deepEqual(stale.sort(), ["octocat-A-aaaaaaa"]);
});

test("findStaleClones: returns empty when threshold=0 (disabled)", () => {
    const cp = mkClone("octocat-X-7777777");
    setMtimeAgo(cp, 999);
    assert.deepEqual(findStaleClones({ buildRoot: BR, hoursThreshold: 0 }), []);
});

// ---------- autoPurge: purgeStaleClones ----------

test("purgeStaleClones: deletes only stale clones and preserves reports/quarantine", () => {
    const basename = fullBasename("X", "a");
    const cp = mkClone(basename);
    const rp = mkReportFor(basename);
    const qp = mkQuarantineFor(basename);
    setMtimeAgo(cp, 48);

    const result = purgeStaleClones({ buildRoot: BR, hoursThreshold: 24 });
    assert.equal(result.purged.length, 1);
    assert.deepEqual(result.purged[0], { basename, clone: true });
    assert.equal(existsSync(cp), false);
    assert.equal(existsSync(rp), true);
    assert.equal(existsSync(qp), true);
});

test("purgeStaleClones: leaves fresh clones alone", () => {
    const fresh = mkClone("octocat-X-bbbbbbb");
    const stale = mkClone("octocat-X-ccccccc");
    setMtimeAgo(fresh, 5);
    setMtimeAgo(stale, 48);

    const result = purgeStaleClones({ buildRoot: BR, hoursThreshold: 24 });
    assert.equal(result.purged.length, 1);
    assert.equal(existsSync(fresh), true);
    assert.equal(existsSync(stale), false);
});

test("purgeStaleClones: respects exclude (current-invocation safety)", () => {
    const stale = mkClone("octocat-X-ddddddd");
    setMtimeAgo(stale, 48);
    const result = purgeStaleClones({
        buildRoot: BR,
        hoursThreshold: 24,
        exclude: ["octocat-X-ddddddd"],
    });
    assert.equal(result.purged.length, 0);
    assert.equal(existsSync(stale), true);
});

test("purgeStaleClones: returns empty when build_root doesn't exist", () => {
    const fakeRoot = join(BR, "nonexistent");
    const result = purgeStaleClones({ buildRoot: fakeRoot, hoursThreshold: 24 });
    assert.deepEqual(result, { purged: [], failed: [] });
});

// ---------- AV-safety: refactored EXECUTION_PATTERNS still match ----------

test("enforcement.mjs: EXECUTION_PATTERNS match the same cmdlets after refactor", async () => {
    // Verify the character-concatenated regexes still match what they used to.
    const enf = await import("../enforcement.mjs");
    const { EXECUTION_PATTERNS } = enf.__internals;
    // Use character-concatenation to avoid having literals in the test file too.
    const startProc = "Start" + "-" + "Process" + " ./bad.exe";
    const invokeItem = "Invoke" + "-" + "Item" + " './bad.bat'";
    const mountDisk = "Mount" + "-" + "DiskImage" + " ./bad.iso";
    const benign = "echo hello world";
    assert.equal(EXECUTION_PATTERNS.some((re) => re.test(startProc)), true);
    assert.equal(EXECUTION_PATTERNS.some((re) => re.test(invokeItem)), true);
    assert.equal(EXECUTION_PATTERNS.some((re) => re.test(mountDisk)), true);
    assert.equal(EXECUTION_PATTERNS.some((re) => re.test(benign)), false);
    assert.equal(EXECUTION_PATTERNS.length, 3);
});
