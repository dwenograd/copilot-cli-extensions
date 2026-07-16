import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import nodePath from "node:path";
import { tmpdir } from "node:os";

import {
    activateAudit,
    deactivateAudit,
    getActiveAudit,
    recordResolvedArtifactPaths,
    recordResolvedClonePath,
    recordResolvedSha,
} from "../enforcement.mjs";
import { closeAuditHandler } from "../safeWrappers/lifecycleWrapper.mjs";
import { cleanupQuarantineHandler } from "../safeWrappers/quarantineWrapper.mjs";
import {
    clearRecordedOutcome,
    getRecordedOutcome,
    recordCouncilOutcome,
} from "../safeWrappers/state.mjs";
import { buildClonePath, buildQuarantinePath } from "../urlParser.mjs";

const ROOT = nodePath.join(
    tmpdir(),
    "zerotrust-lifecycle-" + Date.now() + "-" + Math.random().toString(36).slice(2),
);
const SHA = "abcdef0123456789abcdef0123456789abcdef01";

function activateVerify(sessionId, { resolved = true } = {}) {
    activateAudit({
        sessionId,
        buildPath: ROOT,
        mode: "verify_release",
        expectedClonePath: buildClonePath(ROOT, "OctoCat", "Hello", "0".repeat(40)),
        owner: "OctoCat",
        repo: "Hello",
        ref: "baseline.0.0",
        refType: "tag",
    });
    if (resolved) {
        recordResolvedSha(sessionId, SHA);
        recordResolvedArtifactPaths(sessionId, {
            quarantinePath: quarantinePath(),
        });
    }
}

function quarantinePath() {
    return buildQuarantinePath(ROOT, "OctoCat", "Hello", SHA);
}

function recordOutcomeFor(sessionId) {
    const audit = getActiveAudit(sessionId);
    recordCouncilOutcome(sessionId, {
        auditId: audit.auditId,
        owner: audit.owner,
        repo: audit.repo,
        resolvedSha: audit.resolvedSha,
        verdict: "low",
        criticalCount: 0,
        highCount: 0,
        complete: true,
    });
}

test.beforeEach(() => {
    if (existsSync(ROOT)) rmSync(ROOT, { recursive: true, force: true });
    mkdirSync(ROOT, { recursive: true });
});

test.after(() => {
    if (existsSync(ROOT)) rmSync(ROOT, { recursive: true, force: true });
});

test("closeAuditHandler is non-destructive and idempotently clears session state", async () => {
    const sessionId = "close-" + Math.random().toString(36).slice(2);
    activateVerify(sessionId);
    recordOutcomeFor(sessionId);
    const marker = nodePath.join(ROOT, "keep.txt");
    writeFileSync(marker, "keep");

    const first = await closeAuditHandler({}, { sessionId });
    assert.equal(first.resultType, "success");
    assert.equal(getActiveAudit(sessionId), null);
    assert.equal(getRecordedOutcome(sessionId), null);
    assert.ok(existsSync(marker), "close must not delete files");

    const second = await closeAuditHandler({}, { sessionId });
    assert.equal(second.resultType, "success");
    assert.equal(JSON.parse(second.textResultForLlm).alreadyClosed, true);
});

test("closeAuditHandler refuses an invocation without session identity", async () => {
    const r = await closeAuditHandler({}, {});
    assert.equal(r.resultType, "failure");
});

test("closeAuditHandler preserves cleanup authority while a recorded build clone exists", async () => {
    const sessionId = "close-build-artifact-" + Math.random().toString(36).slice(2);
    const clonePath = buildClonePath(ROOT, "OctoCat", "Hello", SHA);
    mkdirSync(clonePath, { recursive: true });
    activateAudit({
        sessionId,
        buildPath: ROOT,
        mode: "audit_and_safe_build",
        expectedClonePath: clonePath,
        owner: "OctoCat",
        repo: "Hello",
    });
    recordResolvedClonePath(sessionId, clonePath);
    const refused = await closeAuditHandler({}, { sessionId });
    assert.equal(refused.resultType, "failure");
    assert.match(refused.textResultForLlm, /cleanup_audit/);
    assert.ok(getActiveAudit(sessionId));

    rmSync(clonePath, { recursive: true, force: true });
    const closed = await closeAuditHandler({}, { sessionId });
    assert.equal(closed.resultType, "success");
    assert.equal(getActiveAudit(sessionId), null);
});

test("closeAuditHandler refuses verify_release quarantine unless explicitly abandoned", async () => {
    const sessionId = "close-quarantine-artifact-" + Math.random().toString(36).slice(2);
    activateVerify(sessionId);
    const target = quarantinePath();
    mkdirSync(target, { recursive: true });
    const refused = await closeAuditHandler({}, { sessionId });
    assert.equal(refused.resultType, "failure");
    assert.match(refused.textResultForLlm, /cleanup_quarantine/);
    assert.ok(getActiveAudit(sessionId));

    const abandoned = await closeAuditHandler(
        { abandon_artifacts: true },
        { sessionId },
    );
    assert.equal(abandoned.resultType, "success");
    const body = JSON.parse(abandoned.textResultForLlm);
    assert.equal(body.artifactsAbandoned, true);
    assert.equal(getActiveAudit(sessionId), null);
    assert.equal(existsSync(target), true, "abandonment intentionally leaves the artifact");
});

test("close_audit schema documents the explicit abandon_artifacts acknowledgement", () => {
    const source = readFileSync(new URL("../extension.mjs", import.meta.url), "utf-8");
    const closeBlock = source.slice(
        source.indexOf('name: "zerotrust_close_audit"'),
        source.indexOf("],\n    // Intentionally no", source.indexOf('name: "zerotrust_close_audit"')),
    );
    assert.match(closeBlock, /abandon_artifacts/);
    assert.match(closeBlock, /type:\s*"boolean"/);
    assert.match(closeBlock, /intentionally leave/i);
    assert.match(closeBlock, /relinquish/i);
});

test("artifact-free metadata, API, and local audits are closable", async () => {
    const cases = [
        { mode: "metadata_only", local: false },
        { mode: "audit_source", local: false },
        { mode: "audit_local_source", local: true },
    ];
    for (const [index, item] of cases.entries()) {
        const sessionId = `close-artifact-free-${index}`;
        activateAudit({
            sessionId,
            buildPath: ROOT,
            mode: item.mode,
            expectedClonePath: item.local
                ? undefined: nodePath.join(ROOT, `OctoCat-Hello-${"0".repeat(40)}`),
            owner: item.local ? undefined: "OctoCat",
            repo: item.local ? undefined: "Hello",
            localPath: item.local ? nodePath.join(ROOT, "local-source"): undefined,
            expectedReportPath: item.local
                ? nodePath.join(ROOT, "_reports", "local-local-source-20260713100727"): undefined,
        });
        const result = await closeAuditHandler({}, { sessionId });
        assert.equal(result.resultType, "success", item.mode);
        assert.equal(getActiveAudit(sessionId), null);
    }
});

test("cleanupQuarantineHandler deletes only the active verify_release quarantine", async () => {
    const sessionId = "quarantine-" + Math.random().toString(36).slice(2);
    activateVerify(sessionId);
    const target = quarantinePath();
    mkdirSync(target, { recursive: true });
    writeFileSync(nodePath.join(target, "1.bin"), "asset");
    const sibling = nodePath.join(ROOT, "_quarantine", "other-repo-1234567");
    mkdirSync(sibling, { recursive: true });
    writeFileSync(nodePath.join(sibling, "keep.bin"), "keep");
    try {
        const r = await cleanupQuarantineHandler({}, { sessionId });
        assert.equal(r.resultType, "success");
        assert.equal(existsSync(target), false);
        assert.equal(existsSync(sibling), true);
        assert.ok(getActiveAudit(sessionId), "cleanup must preserve state until close");

        const again = await cleanupQuarantineHandler({}, { sessionId });
        assert.equal(again.resultType, "success", "missing quarantine is idempotent");
    } finally {
        deactivateAudit(sessionId);
    }
});

test("cleanupQuarantineHandler deletion failure leaves trusted context active", async () => {
    const sessionId = "quarantine-failure-" + Math.random().toString(36).slice(2);
    activateVerify(sessionId);
    recordOutcomeFor(sessionId);
    try {
        const r = await cleanupQuarantineHandler(
            {},
            { sessionId },
            {
                remove:() => ({
                    existed: true,
                    removed: false,
                    error: "simulated quarantine lock",
                }),
            },
        );
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /simulated quarantine lock/);
        assert.ok(getActiveAudit(sessionId));
        assert.ok(getRecordedOutcome(sessionId));
    } finally {
        deactivateAudit(sessionId);
        clearRecordedOutcome(sessionId);
    }
});

test("cleanupQuarantineHandler requires verify_release mode and a resolved SHA", async () => {
    const unresolved = "quarantine-unresolved-" + Math.random().toString(36).slice(2);
    activateVerify(unresolved, { resolved: false });
    try {
        const missingSha = await cleanupQuarantineHandler({}, { sessionId: unresolved });
        assert.equal(missingSha.resultType, "failure");
        assert.match(missingSha.textResultForLlm, /no resolved SHA/i);
    } finally {
        deactivateAudit(unresolved);
    }

    const wrongMode = "quarantine-mode-" + Math.random().toString(36).slice(2);
    activateAudit({
        sessionId: wrongMode,
        buildPath: ROOT,
        mode: "audit_source",
        expectedClonePath: nodePath.join(ROOT, `OctoCat-Hello-${"0".repeat(40)}`),
        owner: "OctoCat",
        repo: "Hello",
    });

    test("cleanupQuarantineHandler rejects caller-supplied deletion paths", async () => {
        const sessionId = "quarantine-raw-path-" + Math.random().toString(36).slice(2);
        activateVerify(sessionId);
        try {
            const r = await cleanupQuarantineHandler(
                { quarantine_path: nodePath.join(ROOT, "_quarantine", "other") },
                { sessionId },
            );
            assert.equal(r.resultType, "failure");
            assert.match(r.textResultForLlm, /does not accept raw paths/i);
        } finally {
            deactivateAudit(sessionId);
        }
    });
    try {
        const r = await cleanupQuarantineHandler({}, { sessionId: wrongMode });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /only valid for verify_release/i);
    } finally {
        deactivateAudit(wrongMode);
    }
});
