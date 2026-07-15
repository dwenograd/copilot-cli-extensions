// buildCouncil.test.mjs — Wave 1 Feature 3 council-build integration tests.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import nodePath from "node:path";

import {
    isValidMode,
    modeUsesCouncil,
    modeIsBuild,
    modeIsFullBuild,
    modeIsCouncilBuild,
} from "../modes.mjs";
import { safeBuildHandler } from "../safeWrappers/buildWrapper.mjs";
import { __internals as cloneInternals } from "../safeWrappers/cloneWrapper.mjs";
import { recordOutcomeHandler } from "../safeWrappers/outcomeWrapper.mjs";
import {
    recordCouncilOutcome,
    __internals as stateInternals,
} from "../safeWrappers/state.mjs";
import { runHandler } from "../handler.mjs";
import {
    activateAudit,
    deactivateAudit,
    getActiveAudit,
    recordResolvedClonePath,
    recordResolvedSha,
} from "../enforcement.mjs";
import { ROLES, materializeCouncilManifest } from "../council/index.mjs";
import { buildClonePath, buildQuarantinePath, buildReportPath } from "../urlParser.mjs";

const SESSION = "test-session-build-council";
const BUILD_ROOT = "C:\\test\\zerotrust-sourcecheck";
const CLONE_PATH = nodePath.join(BUILD_ROOT, `__missing_build_council_${process.pid}__`);
const URL = "https://github.com/octocat/Hello-World";
const PINNED_SHA = "b".repeat(40);

let cachedSafeCouncilPacket = null;
let currentAuditId;

beforeEach(() => {
    stateInternals.recordedOutcomes.clear();
    activateAudit({
        sessionId: SESSION,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build_council",
        expectedClonePath: CLONE_PATH,
        owner: "octocat",
        repo: "Hello-World",
    });
    // Round-6 hardening: build wrapper requires a recorded resolved clone
    // path. These tests don't actually clone; record the planned path so
    // the council-gate and mode-is-build checks (which run AFTER the
    // resolved-path check) are reached.
    recordResolvedClonePath(SESSION, CLONE_PATH);
    recordResolvedSha(SESSION, PINNED_SHA);
    currentAuditId = getActiveAudit(SESSION).auditId;
});

function safeBuildArgs(extra = {}) {
    return {
        ecosystem: "npm",
        clone_path: CLONE_PATH,
        build_root: BUILD_ROOT,
        mode: "audit_and_safe_build_council",
        ...extra,
    };
}

async function recordOutcome(verdict, complete, counts = {}) {
    const r = await recordOutcomeHandler(
        {
            audit_id: currentAuditId,
            verdict,
            critical_count: counts.critical_count ?? 0,
            high_count: counts.high_count ?? 0,
            complete,
        },
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "success");
}

function runSourcecheck(args) {
    return runHandler(
        {
            url: URL,
            build_root: BUILD_ROOT,
            ...args,
        },
        { sessionId: `handler-${args.mode}` },
    );
}

function getSafeCouncilPacket() {
    if (!cachedSafeCouncilPacket) {
        const r = runSourcecheck({
            mode: "audit_and_safe_build_council",
            i_understand_build_executes_code: true,
        });
        assert.equal(r.resultType, "success");
        cachedSafeCouncilPacket = r.textResultForLlm;
    }
    return cachedSafeCouncilPacket;
}

test("audit_and_safe_build_council is a valid mode", () => {
    assert.equal(isValidMode("audit_and_safe_build_council"), true);
});

test("audit_and_safe_build_council uses the council", () => {
    assert.equal(modeUsesCouncil("audit_and_safe_build_council"), true);
});

test("audit_and_safe_build_council is a build mode", () => {
    assert.equal(modeIsBuild("audit_and_safe_build_council"), true);
});

test("audit_and_safe_build_council is not a full-build mode", () => {
    assert.equal(modeIsFullBuild("audit_and_safe_build_council"), false);
});

test("audit_and_full_build_council is a full-build mode", () => {
    assert.equal(modeIsFullBuild("audit_and_full_build_council"), true);
});

test("modeIsCouncilBuild identifies safe council build mode", () => {
    assert.equal(modeIsCouncilBuild("audit_and_safe_build_council"), true);
});

test("safeBuildHandler refuses council build when no outcome is recorded", async () => {
    const r = await safeBuildHandler(safeBuildArgs(), { sessionId: SESSION });
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /council-build gate CLOSED/);
});

test("delayed audit-A outcome is refused after audit B activates in the same session", async () => {
    const auditA = currentAuditId;
    activateAudit({
        sessionId: SESSION,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build_council",
        expectedClonePath: CLONE_PATH,
        owner: "octocat",
        repo: "Hello-World",
    });
    recordResolvedClonePath(SESSION, CLONE_PATH);
    recordResolvedSha(SESSION, PINNED_SHA);
    const auditB = getActiveAudit(SESSION).auditId;
    assert.notEqual(auditA, auditB);

    const delayed = await recordOutcomeHandler(
        {
            audit_id: auditA,
            verdict: "low",
            critical_count: 0,
            high_count: 0,
            complete: true,
        },
        { sessionId: SESSION },
    );
    assert.equal(delayed.resultType, "failure");
    assert.match(delayed.textResultForLlm, /does not match the current active audit/i);

    recordCouncilOutcome(SESSION, {
        auditId: auditA,
        owner: "octocat",
        repo: "hello-world",
        resolvedSha: PINNED_SHA,
        verdict: "low",
        criticalCount: 0,
        highCount: 0,
        complete: true,
    });
    const build = await safeBuildHandler(safeBuildArgs(), { sessionId: SESSION });
    assert.equal(build.resultType, "failure");
    assert.match(build.textResultForLlm, /different audit identity/i);
});

test("safeBuildHandler blocks a complete critical council outcome", async () => {
    await recordOutcome("critical", true, { critical_count: 1 });
    const r = await safeBuildHandler(safeBuildArgs(), { sessionId: SESSION });
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /council-build gate CLOSED/);
});

test("safeBuildHandler allows override for a complete critical council outcome", async () => {
    await recordOutcome("critical", true, { critical_count: 1 });
    const r = await safeBuildHandler(
        safeBuildArgs({ council_build_override: true }),
        { sessionId: SESSION },
    );
    assert.equal(r.resultType, "failure");
    assert.doesNotMatch(r.textResultForLlm, /council-build gate CLOSED/);
});

test("safeBuildHandler blocks incomplete low outcome unless proceed flag is set", async () => {
    await recordOutcome("low", false);

    const blocked = await safeBuildHandler(safeBuildArgs(), { sessionId: SESSION });
    assert.equal(blocked.resultType, "failure");
    assert.match(blocked.textResultForLlm, /council-build gate CLOSED/);

    const proceeded = await safeBuildHandler(
        safeBuildArgs({ proceed_on_council_failure: true }),
        { sessionId: SESSION },
    );
    assert.equal(proceeded.resultType, "failure");
    assert.doesNotMatch(proceeded.textResultForLlm, /council-build gate CLOSED/);
});

test("handler accepts the new council-build modes with required acknowledgements", () => {
    const safe = runSourcecheck({
        mode: "audit_and_safe_build_council",
        i_understand_build_executes_code: true,
    });
    assert.equal(safe.resultType, "success");

    const full = runSourcecheck({
        mode: "audit_and_full_build_council",
        i_understand_build_executes_code: true,
        unsafe: true,
    });
    assert.equal(full.resultType, "success");
});

test("handler rejects new build modes without build-exec acknowledgement", () => {
    for (const mode of ["audit_and_safe_build_council", "audit_and_full_build_council"]) {
        const r = runSourcecheck({ mode });
        assert.equal(r.resultType, "failure");
        assert.match(r.textResultForLlm, /i_understand_build_executes_code/);
    }
});

test("handler rejects audit_and_full_build_council without unsafe acknowledgement", () => {
    const r = runSourcecheck({
        mode: "audit_and_full_build_council",
        i_understand_build_executes_code: true,
    });
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /unsafe/);
});

test("packet emits council role table for audit_and_safe_build_council", () => {
    assert.match(getSafeCouncilPacket(), /32-role|meta-judge/);
});

test("packet emits build instructions for audit_and_safe_build_council", () => {
    assert.match(getSafeCouncilPacket(), /zerotrust_safe_build/);
});

test("packet tells agent to record council outcome before safe build", () => {
    assert.match(getSafeCouncilPacket(), /zerotrust_record_council_outcome/);
    assert.match(getSafeCouncilPacket(), /audit_id:\s*runtimeContext\.auditId/);
    assert.match(
        getSafeCouncilPacket(),
        /immutable active-audit ID[\s\S]*[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i,
    );
    assert.match(getSafeCouncilPacket(), /runtimeContext[\s\S]*auditId = "[0-9a-f-]{36}"/i);
});

test("build wrapper identity handoff materializes concrete council prompts", () => {
    const actualClonePath = buildClonePath(BUILD_ROOT, "octocat", "Hello-World", PINNED_SHA);
    const boundContext = cloneInternals.buildCloneBoundContext({
        buildRoot: BUILD_ROOT,
        owner: "octocat",
        repo: "Hello-World",
        resolvedSha: PINNED_SHA,
        clonePath: actualClonePath,
    });
    const role = ROLES.find((r) => r.id === "compiler-toolchain-codegen");
    const materialized = materializeCouncilManifest([role], {
        auditId: "11111111-1111-4111-8111-111111111111",
        sourceKind: "build",
        owner: "octocat",
        repo: "Hello-World",
        sourceCommitSha: boundContext.sourceCommitSha,
        clonePath: boundContext.clonePath,
        buildRoot: BUILD_ROOT,
        nonce: "runtime-build",
        aggregateEntries: [
            "src/main.cpp",
            "CMakeLists.txt",
            "tools/codegen/generate.py",
            "README.md",
        ],
        coverageSnapshot: {
            coverageComplete: true,
            aggregateEntryCount: 4,
            aggregateEntriesTruncated: false,
            coverageBlockers: [],
        },
    })[0];

    assert.equal(boundContext.clonePath, actualClonePath);
    assert.equal(boundContext.reportPath, buildReportPath(BUILD_ROOT, "octocat", "Hello-World", PINNED_SHA));
    assert.equal(boundContext.quarantinePath, buildQuarantinePath(BUILD_ROOT, "octocat", "Hello-World", PINNED_SHA));
    assert.match(materialized.renderedPrompt, new RegExp(PINNED_SHA));
    assert.ok(materialized.renderedPrompt.includes(actualClonePath));
    assert.match(materialized.renderedPrompt, /tools\/codegen\/generate\.py/);
    assert.doesNotMatch(materialized.renderedPrompt, /<RESOLVED_SHA>|not yet substituted/i);
});

test("build-council orchestration consumes wrapper-returned runtime identities", () => {
    const section = getSafeCouncilPacket().slice(
        getSafeCouncilPacket().indexOf("## Section 5b"),
        getSafeCouncilPacket().indexOf("## Section 6"),
    );
    assert.match(section, /cloneResult\.boundContext\.clonePath/);
    assert.match(section, /runtimeContext\.reportPath/);
    assert.match(section, /single Section 8 finalizer/);
    assert.doesNotMatch(section, /zerotrust_finalize_report\(\{/);
    assert.match(section, /only identities subsequent remediation, report, and cleanup instructions may consume/);
    assert.doesNotMatch(section, /0000000|RESOLVED_SHA|not yet substituted/i);
});
