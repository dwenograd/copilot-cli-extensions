import { readFileSync } from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
    ASSURANCE_CACHE_POLICY,
    CACHE_CONTENT_SCOPE,
    CACHE_FORMAT_ID,
    CACHE_SCHEMA_REVISION,
    FINDINGS_ARTIFACT_SCHEMA_REVISION,
    createAssuranceAnalysisSnapshot,
} from "../analysis/index.mjs";
import {
    __internals,
    activateAudit,
    advanceAssuranceStage,
    deactivateAudit,
    getAnalysisStageState,
    getAssuranceState,
    recordAssuranceSnapshot,
    recordResolvedArtifactPaths,
    recordResolvedSha,
} from "../enforcement.mjs";
import { cacheListHandler } from "../safeWrappers/cacheWrapper.mjs";
import { evaluateFinalizedReportExecutionGate } from "../safeWrappers/finalizedReportGate.mjs";
import { finalizeReportHandler } from "../safeWrappers/reportWrapper.mjs";
import {
    evaluateCouncilGate,
    recordCouncilOutcome,
} from "../safeWrappers/state.mjs";
import {
    buildClonePath,
    buildReportPath,
} from "../urlParser.mjs";

const __dirname = nodePath.dirname(fileURLToPath(import.meta.url));
const ROOT = nodePath.resolve(__dirname, "..");
const BUILD_ROOT = nodePath.join(ROOT, "__tests__", "workflow-state-scratch");
const SHA = "a".repeat(40);
const CURRENT_TOOL_NAMES = Object.freeze([
    "zerotrust_prepare_semantic_coverage",
    "zerotrust_record_semantic_scanner",
    "zerotrust_assign_semantic_review",
    "zerotrust_record_semantic_review",
    "zerotrust_get_semantic_coverage",
    "zerotrust_prepare_red_team",
    "zerotrust_assign_red_team_review",
    "zerotrust_record_red_team_review",
    "zerotrust_get_red_team",
    "zerotrust_finalize_red_team",
    "zerotrust_prepare_evasive_graph",
    "zerotrust_trace_evasive_graph",
    "zerotrust_get_evasive_graph",
    "zerotrust_prepare_assurance_validation",
    "zerotrust_record_assurance_validation",
    "zerotrust_finalize_assurance_validation",
]);

function activate(sessionId) {
    return activateAudit({
        sessionId,
        buildPath: BUILD_ROOT,
        mode: "audit_source",
        expectedClonePath: buildClonePath(
            BUILD_ROOT,
            "owner",
            "repo",
            "0".repeat(40),
        ),
        owner: "owner",
        repo: "repo",
        ref: "main",
        refType: "branch_or_tag",
        urlKind: "repo",
    });
}

test("current assurance state is automatic and remains separate from baseline state", () => {
    const sessionId = "workflow-state-automatic";
    const auditId = activate(sessionId);
    try {
        const assurance = getAssuranceState(sessionId, { auditId });
        assert.equal(assurance.schemaVersion, 6);
        assert.equal(assurance.stageState.current, "acquired");
        assert.equal(getAnalysisStageState(sessionId, { auditId }).current, "acquired");

        advanceAssuranceStage(sessionId, {
            auditId,
            from: "acquired",
            to: "inventoried",
        });
        assert.equal(
            getAssuranceState(sessionId, { auditId }).stageState.current,
            "inventoried",
        );
        assert.equal(getAnalysisStageState(sessionId, { auditId }).current, "acquired");
    } finally {
        deactivateAudit(sessionId);
    }
});

test("pre-acquisition assurance state rebinds once to the exact pinned source", () => {
    const sessionId = "workflow-source-pin";
    const auditId = activate(sessionId);
    try {
        assert.equal(
            getAssuranceState(sessionId, { auditId }).sourceNamespace,
            `audit:${auditId}`,
        );
        assert.equal(recordResolvedSha(sessionId, SHA), true);
        const pinned = getAssuranceState(sessionId, { auditId });
        assert.equal(pinned.sourceNamespace, `github.com/owner/repo@${SHA}`);
        assert.equal(pinned.stageState.sourceNamespace, pinned.sourceNamespace);
        assert.equal(pinned.analysisSnapshot, null);
        assert.equal(recordResolvedSha(sessionId, SHA), true);
        assert.deepEqual(getAssuranceState(sessionId, { auditId }), pinned);
        assert.equal(recordResolvedSha(sessionId, "b".repeat(40)), false);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("source rebinding refuses progressed state and recorded snapshots", () => {
    const progressedSession = "workflow-progressed-state";
    const recordedSession = "workflow-recorded-state";
    const progressedAuditId = activate(progressedSession);
    const recordedAuditId = activate(recordedSession);
    try {
        advanceAssuranceStage(progressedSession, {
            auditId: progressedAuditId,
            from: "acquired",
            to: "inventoried",
        });
        assert.equal(recordResolvedSha(progressedSession, SHA), false);
        assert.equal(
            __internals.activeAudits.get(progressedSession).resolvedSha,
            undefined,
        );

        const state = getAssuranceState(recordedSession, {
            auditId: recordedAuditId,
        });
        recordAssuranceSnapshot(recordedSession, {
            auditId: recordedAuditId,
            snapshot: createAssuranceAnalysisSnapshot({
                auditId: recordedAuditId,
                sourceNamespace: state.sourceNamespace,
                stageState: state.stageState,
                status: "incomplete",
                objectInventory: [],
                derivedArtifacts: [],
                semanticReviewCoverage: [],
                redTeamCoverage: [],
                blockerCodes: [],
                sourceIdentitySha256: "c".repeat(64),
            }),
        });
        assert.equal(recordResolvedSha(recordedSession, SHA), false);
        assert.equal(
            __internals.activeAudits.get(recordedSession).resolvedSha,
            undefined,
        );
    } finally {
        deactivateAudit(progressedSession);
        deactivateAudit(recordedSession);
    }
});

test("metadata cache is explicitly separate from assurance state", async () => {
    const sessionId = "workflow-cache-separation";
    const auditId = activate(sessionId);
    try {
        assert.equal(CACHE_SCHEMA_REVISION, 2);
        assert.equal(CACHE_FORMAT_ID, "analysis-metadata-only");
        assert.equal(CACHE_CONTENT_SCOPE, "analysis-metadata-only");
        assert.equal(
            ASSURANCE_CACHE_POLICY,
            "excluded-from-current-cache-schema",
        );
        assert.equal(FINDINGS_ARTIFACT_SCHEMA_REVISION, 1);
        assert.equal(recordResolvedSha(sessionId, SHA), true);
        const before = getAssuranceState(sessionId, { auditId });
        const result = await cacheListHandler(
            { audit_id: auditId },
            { sessionId },
        );
        assert.equal(result.resultType, "success");
        assert.deepEqual(getAssuranceState(sessionId, { auditId }), before);
    } finally {
        deactivateAudit(sessionId);
    }
});

test("deprecated council outcome cannot replace current report validation", async () => {
    const sessionId = "workflow-report-separation";
    const auditId = activate(sessionId);
    try {
        assert.equal(recordResolvedSha(sessionId, SHA), true);
        const reportPath = buildReportPath(BUILD_ROOT, "owner", "repo", SHA);
        assert.equal(recordResolvedArtifactPaths(sessionId, { reportPath }), true);
        const deprecated = recordCouncilOutcome(sessionId, {
            auditId,
            owner: "owner",
            repo: "repo",
            resolvedSha: SHA,
            verdict: "no red flags found",
            criticalCount: 0,
            highCount: 0,
            complete: true,
        });
        assert.equal(evaluateCouncilGate(deprecated).passes, true);
        assert.equal(
            evaluateFinalizedReportExecutionGate(deprecated, {
                auditId,
                owner: "owner",
                repo: "repo",
                resolvedSha: SHA,
            }).passes,
            false,
        );

        advanceAssuranceStage(sessionId, {
            auditId,
            from: "acquired",
            to: "inventoried",
        });
        const result = await finalizeReportHandler(
            {
                owner: "owner",
                repo: "repo",
                resolved_sha: SHA,
            },
            { sessionId },
        );
        assert.equal(result.resultType, "failure");
        assert.match(
            result.textResultForLlm,
            /current assurance analysis is not validated/i,
        );
    } finally {
        deactivateAudit(sessionId);
    }
});

test("all current assurance tools are registered with strict schemas", () => {
    const source = readFileSync(nodePath.join(ROOT, "extension.mjs"), "utf8");
    for (const name of CURRENT_TOOL_NAMES) {
        const start = source.indexOf(`name: "${name}"`);
        assert.notEqual(start, -1, `${name} must be registered`);
        const finish = source.indexOf("handler:", start);
        assert.notEqual(finish, -1, `${name} must have a handler`);
        const block = source.slice(start, finish);
        assert.match(block, /additionalProperties:\s*false/u);
    }
});

test("corpus documentation names the current quality contract", () => {
    const corpus = readFileSync(
        nodePath.join(ROOT, "__corpus__", "README.md"),
        "utf8",
    );
    assert.match(corpus, /--quality-gate/u);
    assert.match(corpus, /quality-gate\.json/u);
    assert.match(corpus, /zerotrust-evaluation-expectation/u);
});
