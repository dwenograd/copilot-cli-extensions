import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import { runHandler } from "../handler.mjs";
import {
    __internals,
    activateAudit,
    advanceAnalysisStage,
    deactivateAudit,
    getAnalysisStageState,
    getTrustedAuditContext,
} from "../enforcement.mjs";
import { ANALYSIS_STAGES } from "../analysis/index.mjs";

const AUDIT_ID_PATTERN = /^[0-9a-f-]{36}$/;
const SESSION = "v5-stage-session";
const BUILD_ROOT = process.cwd();
const CLONE_PATH = process.platform === "win32"
    ? `${BUILD_ROOT}\\zt-v5-stage-test`
    : `${BUILD_ROOT}/zt-v5-stage-test`;

function activate(sessionId = SESSION, mode = "audit_source") {
    return activateAudit({
        sessionId,
        buildPath: BUILD_ROOT,
        mode,
        expectedClonePath: CLONE_PATH,
        owner: "example",
        repo: "repo",
    });
}

beforeEach(() => {
    __internals.activeAudits.clear();
});

test("v5 active audits initialize at acquired and bind stage state to immutable audit ID", () => {
    const auditId = activate();
    assert.match(auditId, AUDIT_ID_PATTERN);
    const state = getAnalysisStageState(SESSION, { auditId });
    assert.deepEqual(state, {
        schemaVersion: 5,
        auditId,
        current: "acquired",
        history: ["acquired"],
    });
    assert.equal(__internals.activeAudits.get(SESSION).auditId, auditId);
    assert.throws(() => {
        __internals.activeAudits.get(SESSION).auditId =
            "22222222-2222-4222-8222-222222222222";
    }, TypeError);
});

test("v5 analysis stages advance only through the legal ordered sequence", () => {
    const auditId = activate(SESSION, "metadata_only");
    let current = "acquired";
    for (const next of ANALYSIS_STAGES.slice(1)) {
        const state = advanceAnalysisStage(SESSION, {
            auditId,
            from: current,
            to: next,
        });
        assert.equal(state.current, next);
        assert.deepEqual(
            state.history,
            ANALYSIS_STAGES.slice(0, ANALYSIS_STAGES.indexOf(next) + 1),
        );
        current = next;
    }
    assert.equal(getAnalysisStageState(SESSION).current, "finalized");
});

test("v5 analysis stages fail closed on skipped, reversed, stale, or cross-audit transitions", () => {
    const auditId = activate(SESSION, "metadata_only");
    assert.throws(
        () => advanceAnalysisStage(SESSION, {
            auditId,
            from: "acquired",
            to: "scanned",
        }),
        /illegal analysis stage transition/,
    );
    advanceAnalysisStage(SESSION, {
        auditId,
        from: "acquired",
        to: "prepared",
    });

    assert.throws(
        () => advanceAnalysisStage(SESSION, {
            auditId,
            from: "acquired",
            to: "prepared",
        }),
        /stale analysis stage transition/,
    );
    assert.throws(
        () => advanceAnalysisStage(SESSION, {
            auditId,
            from: "prepared",
            to: "acquired",
        }),
        /illegal analysis stage transition/,
    );
    assert.throws(
        () => advanceAnalysisStage(SESSION, {
            auditId: "22222222-2222-4222-8222-222222222222",
            from: "prepared",
            to: "scanned",
        }),
        /does not match active audit/,
    );
});

test("v5 source audits cannot advance acquired to prepared before index coverage completes", () => {
    const auditId = activate();
    assert.throws(
        () => advanceAnalysisStage(SESSION, {
            auditId,
            from: "acquired",
            to: "prepared",
        }),
        /analysis preparation incomplete/,
    );
    assert.equal(getAnalysisStageState(SESSION).current, "acquired");
});

test("v5 same-stage retries are idempotent when the caller's expected stage is current", () => {
    const auditId = activate();
    const state = advanceAnalysisStage(SESSION, {
        auditId,
        from: "acquired",
        to: "acquired",
    });
    assert.equal(state.current, "acquired");
    assert.deepEqual(state.history, ["acquired"]);
});

test("legacy active audit records lazily acquire compatible v5 stage state", () => {
    const auditId = activate();
    delete __internals.activeAudits.get(SESSION).analysisStageState;
    const state = getAnalysisStageState(SESSION, { auditId });
    assert.equal(state.current, "acquired");
    assert.equal(state.auditId, auditId);
});

test("v4 trusted context remains usable without any stage advancement", () => {
    const auditId = activate();
    const context = getTrustedAuditContext({
        sessionId: SESSION,
        args: {},
        defaultBuildRoot: BUILD_ROOT,
    });
    assert.equal(context.ok, true);
    assert.equal(context.auditId, auditId);
    assert.equal(context.analysisStageState.current, "acquired");
    assert.equal(context.hasActiveAudit, true);
});

test("handler activation initializes stage state without changing packet execution requirements", () => {
    const sessionId = "v5-handler-stage";
    const result = runHandler({
        url: "https://github.com/example/repo",
        mode: "audit_source",
        build_root: BUILD_ROOT,
    }, { sessionId });
    try {
        assert.equal(result.resultType, "success");
        const state = getAnalysisStageState(sessionId);
        assert.equal(state.current, "acquired");
        assert.match(state.auditId, AUDIT_ID_PATTERN);
    } finally {
        deactivateAudit(sessionId);
    }
});
