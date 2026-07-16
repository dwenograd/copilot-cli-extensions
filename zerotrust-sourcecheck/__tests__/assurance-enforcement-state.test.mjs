import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import {
    __internals,
    activateAudit,
    advanceAssuranceStage,
    getAnalysisStageState,
    getAssuranceSnapshot,
    getAssuranceState,
    recordAssuranceSnapshot,
} from "../enforcement.mjs";
import { createAssuranceAnalysisSnapshot } from "../analysis/index.mjs";
import { ASSURANCE_ANALYSIS_SCHEMA_REVISION } from "../analysis/assuranceState.mjs";

const SESSION = "assurance-state-session";
const BUILD_ROOT = process.cwd();
const CLONE_PATH = process.platform === "win32"
    ? `${BUILD_ROOT}\\zt-assurance-state-test`: `${BUILD_ROOT}/zt-assurance-state-test`;

function activate(sessionId = SESSION) {
    return activateAudit({
        sessionId,
        buildPath: BUILD_ROOT,
        mode: "metadata_only",
        expectedClonePath: CLONE_PATH,
        owner: "example",
        repo: "repo",
    });
}

beforeEach(() => {
    __internals.activeAudits.clear();
});

test("assurance state initializes automatically without changing baseline state", () => {
    const auditId = activate();
    const audit = __internals.activeAudits.get(SESSION);
    assert.equal(Object.hasOwn(audit, "assurance"), true);
    assert.equal(getAnalysisStageState(SESSION, { auditId }).current, "acquired");

    const assurance = getAssuranceState(SESSION, { auditId });
    assert.equal(assurance.schemaVersion, ASSURANCE_ANALYSIS_SCHEMA_REVISION);
    assert.equal(assurance.auditId, auditId);
    assert.equal(assurance.stageState.current, "acquired");
    assert.equal(assurance.analysisSnapshot, null);
    assert.equal(Object.hasOwn(audit, "assurance"), true);
    assert.equal(getAnalysisStageState(SESSION, { auditId }).current, "acquired");

    const advanced = advanceAssuranceStage(SESSION, {
        auditId,
        from: "acquired",
        to: "inventoried",
    });
    assert.equal(advanced.stageState.current, "inventoried");
    assert.equal(getAnalysisStageState(SESSION, { auditId }).current, "acquired");
});

test("assurance accessors fail closed on cross-audit or corrupted state", () => {
    const auditId = activate();
    getAssuranceState(SESSION, { auditId });
    assert.throws(() => getAssuranceState(SESSION, {
            auditId: "22222222-2222-4222-8222-222222222222",
        }),
        /does not match active audit/,
    );
    const audit = __internals.activeAudits.get(SESSION);
    audit.assurance = {
        ...audit.assurance,
        auditId: "22222222-2222-4222-8222-222222222222",
    };
    assert.throws(() => getAssuranceState(SESSION, { auditId }),
        /auditId does not match active audit/,
    );
});

test("assurance snapshots stay inside the active audit generation", () => {
    const auditId = activate();
    const initial = getAssuranceState(SESSION, { auditId });
    const snapshot = createAssuranceAnalysisSnapshot({
        auditId,
        sourceNamespace: initial.sourceNamespace,
        stageState: initial.stageState,
        status: "incomplete",
        objectInventory: [],
        derivedArtifacts: [],
        semanticReviewCoverage: [],
        redTeamCoverage: [],
        blockerCodes: [],
        sourceIdentitySha256: "a".repeat(64),
    });
    recordAssuranceSnapshot(SESSION, { auditId, snapshot });
    assert.equal(
        getAssuranceSnapshot(SESSION, { auditId }).snapshotId,
        snapshot.snapshotId,
    );

    const replacementAuditId = activate();
    assert.notEqual(replacementAuditId, auditId);
    const replacement = getAssuranceState(SESSION, {
        auditId: replacementAuditId,
    });
    assert.equal(Object.hasOwn(__internals.activeAudits.get(SESSION), "assurance"), true);
    assert.equal(replacement.auditId, replacementAuditId);
    assert.notEqual(replacement.sourceNamespace, initial.sourceNamespace);
    assert.equal(replacement.analysisSnapshot, null);
});
