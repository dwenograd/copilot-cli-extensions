import { createHash } from "node:crypto";
import {
    existsSync,
    mkdirSync,
    readFileSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import nodePath from "node:path";
import { after, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import {
    ASSURANCE_CONFIRM_CHECKS,
    ASSURANCE_NO_FINDING_CHECKS,
    ASSURANCE_NO_SUPPORTED_BEHAVIOR_VERDICT,
    ASSURANCE_REFUTE_CHECKS,
    computeAssuranceFindingsDecision,
    createInitialAssuranceStageState,
    createAssuranceAnalysisSnapshot,
    createAssuranceValidationPlan,
    createAssuranceValidationRecord,
    createEvasiveGraphEdge,
    createEvasiveGraphEvidenceRecord,
    createEvasiveGraphNode,
    evaluateAssuranceValidation,
    mergeEvasiveGraphRecords,
    traceEvasiveGraph,
    transitionAssuranceStageState,
} from "../analysis/index.mjs";
import {
    activateAudit,
    deactivateAudit,
    getActiveAudit,
    recordResolvedArtifactPaths,
    recordResolvedClonePath,
    recordResolvedSha,
} from "../enforcement.mjs";
import { safeBuildHandler } from "../safeWrappers/buildWrapper.mjs";
import { safeInstallHandler } from "../safeWrappers/installWrapper.mjs";
import { finalizeReportHandler } from "../safeWrappers/reportWrapper.mjs";
import { buildClonePath, buildReportPath } from "../urlParser.mjs";

const SCRATCH = nodePath.join(
    nodePath.dirname(fileURLToPath(import.meta.url)),
    ".assurance-verdict-build-scratch",
);
const OWNER = "octocat";
const REPO = "assurance-report";
const SHA = "a".repeat(40);
let sequence = 0;

function sha256(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}

function stageAt(auditId, sourceNamespace, target) {
    const stages = [
        "acquired",
        "inventoried",
        "decoded",
        "semantically-covered",
        "scanned",
        "red-teamed",
        "traced",
        "validated",
    ];
    let state = createInitialAssuranceStageState({ auditId, sourceNamespace });
    for (let index = 1; index <= stages.indexOf(target); index += 1) {
        state = transitionAssuranceStageState(state, {
            auditId,
            sourceNamespace,
            from: stages[index - 1],
            to: stages[index],
        });
    }
    return state;
}

function snapshotAt(auditId, sourceNamespace, target) {
    return createAssuranceAnalysisSnapshot({
        auditId,
        sourceNamespace,
        stageState: stageAt(auditId, sourceNamespace, target),
        status: "incomplete",
        objectInventory: [],
        derivedArtifacts: [],
        semanticReviewCoverage: [],
        semanticCandidateLedger: [],
        redTeamCoverage: [],
        blockerCodes: [],
        sourceIdentitySha256: "f".repeat(64),
    });
}

function node(kind, identity, candidateId, evidenceId) {
    return createEvasiveGraphNode({
        kind,
        identityKind: "target",
        identity,
        status: "supported",
        bindings: {
            objectIds: [],
            artifactIds: [],
            factIds: [],
            evidenceIds: [evidenceId],
            supplyChainNodeIds: [],
            semanticReviewIds: [],
            candidateIds: candidateId ? [candidateId]: [],
            redTeamGraphNodeIds: [],
        },
    });
}

function edge(from, to, candidateId, evidenceId) {
    return createEvasiveGraphEdge({
        kind: "executes",
        fromNodeId: from.nodeId,
        toNodeId: to.nodeId,
        bindings: {
            artifactIds: [],
            factIds: [],
            evidenceIds: [evidenceId],
            supplyChainEdgeIds: [],
            candidateIds: candidateId ? [candidateId]: [],
            redTeamGraphEdgeIds: [],
        },
    });
}

function assuranceStateFixture(auditId, {
    severity = null,
} = {}) {
    const sourceNamespace = `github.com/${OWNER}/${REPO}@${SHA}`;
    const graphBaseSnapshot = snapshotAt(auditId, sourceNamespace, "red-teamed");
    const tracedSnapshot = snapshotAt(auditId, sourceNamespace, "traced");
    const validatedSnapshot = snapshotAt(auditId, sourceNamespace, "validated");
    const evidenceDescriptor = {
        evidenceKind: "fact",
        objectId: "object-proof",
        artifactId: null,
        factId: "fact-proof",
        supplyChainNodeId: null,
        path: "src/proof.mjs",
        startLine: 1,
        endLine: 1,
        excerptHash: sha256("excerpt"),
        contentSha256: sha256("content"),
    };
    const evidence = createEvasiveGraphEvidenceRecord({
        evidenceId: `ztve-${sha256(JSON.stringify(evidenceDescriptor))}`,
        ...evidenceDescriptor,
    });
    const candidateId = severity
        ? `ztrf-${sha256(`candidate-${severity}`)}`: null;
    const root = node("trigger", candidateId ? `${candidateId}:trigger`: "root",
        candidateId, evidence.evidenceId);
    const effect = node("effect", candidateId ? `${candidateId}:effect`: "effect",
        candidateId, evidence.evidenceId);
    const flow = edge(root, effect, candidateId, evidence.evidenceId);
    const graphPlan = mergeEvasiveGraphRecords({
        auditId,
        sourceNamespace,
        snapshotId: graphBaseSnapshot.snapshotId,
        snapshotSha256: graphBaseSnapshot.hashes.snapshotSha256,
        nodes: [root, effect],
        proposedEdges: [flow],
        evidence: [evidence],
        findingDescriptors: severity ? [{
            findingId: candidateId,
            origin: "red-team",
            severity,
            objectIds: [],
            artifactIds: [],
            factIds: [],
            evidenceIds: [evidence.evidenceId],
            nodeIds: [root.nodeId, effect.nodeId],
            edgeIds: [flow.edgeId],
            sourceRecordIds: ["red-team-review-1"],
        }]: [],
        blockerCodes: [],
    });
    const graphTrace = traceEvasiveGraph(graphPlan);
    const semanticEvaluation = {
        schemaVersion: 6,
        auditId,
        sourceNamespace,
        evaluationId: `ztse-${"b".repeat(64)}`,
        complete: true,
        status: "comprehensive",
        truncated: false,
        coverageRecords: [],
        candidateLedger: [],
        blockerCodes: [],
        counts: {
            classifiedObjects: 0,
            scannerAssignments: 0,
            scannerRecords: 0,
            modelSubjects: 0,
            reviewAssignments: 0,
            completedReviews: 0,
            candidates: 0,
            coveredObjects: 0,
        },
    };
    const redTeamEvaluation = {
        schemaVersion: 6,
        auditId,
        sourceNamespace,
        evaluationId: `ztreval-${"c".repeat(64)}`,
        complete: true,
        status: "comprehensive",
        truncated: false,
        coverageRecords: [],
        candidateLedger: [],
        blockerCodes: [],
        blockerDetails: [],
        gates: {
            assignmentCount: 9,
            successfulAssignments: 9,
            assignmentCoveragePercent: 100,
            ninetyPercentSatisfied: true,
            mandatoryCategoriesSatisfied: true,
            missingMandatoryCategoryIds: [],
            stageEligible: true,
        },
    };
    const planInputs = {
        snapshot: tracedSnapshot,
        graphBaseSnapshot,
        graph: graphPlan,
        trace: graphTrace,
        semanticEvaluation,
        redTeamEvaluation,
        supplyChainGraph: null,
    };
    const assignmentKeys = candidateId
        ? [`${candidateId}:confirm`, `${candidateId}:refute`]: ["no-finding-assurance"];
    const assuranceValidationPlan = createAssuranceValidationPlan({
        ...planInputs,
        validatorIds: {
            noFinding: "validator-no-finding",
            confirm: "validator-confirm",
            refute: "validator-refute",
        },
        validatorVersion: "1.0.0",
        assignmentNonceSha256ByKey: Object.fromEntries(
            assignmentKeys.map((key, index) => [
                key,
                String(index + 1).repeat(64),
            ]),
        ),
    });
    let assuranceValidationRecords;
    if (!candidateId) {
        const assignment = assuranceValidationPlan.assignments[0];
        assuranceValidationRecords = [createAssuranceValidationRecord({
            assignment,
            assignmentToken: assignment.assignmentToken,
            validatorId: assignment.validatorId,
            conclusion: "supported",
            reviewedNodeIds: assignment.context.nodeIds,
            reviewedEdgeIds: assignment.context.edgeIds,
            reviewedPathIds: assignment.context.pathIds,
            reviewedEvidenceIds: assignment.context.evidenceIds,
            reviewedBasisIds: assignment.context.basisIds,
            checks: Object.fromEntries(
                ASSURANCE_NO_FINDING_CHECKS.map((name) => [name, "passed"]),
            ),
            negativeEvidenceCodes: assignment.context.negativeEvidenceCodes,
            blockerCodes: [],
        })];
    } else {
        const confirm = assuranceValidationPlan.assignments.find((assignment) =>
            assignment.decisionType === "confirm");
        const refute = assuranceValidationPlan.assignments.find((assignment) =>
            assignment.decisionType === "refute");
        assuranceValidationRecords = [
            createAssuranceValidationRecord({
                assignment: confirm,
                assignmentToken: confirm.assignmentToken,
                validatorId: confirm.validatorId,
                conclusion: "confirmed",
                reviewedNodeIds: confirm.context.nodeIds,
                reviewedEdgeIds: confirm.context.edgeIds,
                reviewedPathIds: confirm.context.pathIds,
                reviewedEvidenceIds: confirm.context.evidenceIds,
                reviewedBasisIds: confirm.context.basisIds,
                checks: Object.fromEntries(
                    ASSURANCE_CONFIRM_CHECKS.map((name) => [name, true]),
                ),
                negativeEvidenceCodes: [],
                blockerCodes: [],
            }),
            createAssuranceValidationRecord({
                assignment: refute,
                assignmentToken: refute.assignmentToken,
                validatorId: refute.validatorId,
                conclusion: "not-refuted",
                reviewedNodeIds: refute.context.nodeIds,
                reviewedEdgeIds: refute.context.edgeIds,
                reviewedPathIds: refute.context.pathIds,
                reviewedEvidenceIds: refute.context.evidenceIds,
                reviewedBasisIds: refute.context.basisIds,
                checks: Object.fromEntries(
                    ASSURANCE_REFUTE_CHECKS.map((name) => [name, "does-not-refute"]),
                ),
                negativeEvidenceCodes: [],
                blockerCodes: [],
            }),
        ];
    }
    const assuranceValidationEvaluation = evaluateAssuranceValidation({
        plan: assuranceValidationPlan,
        planInputs,
        records: assuranceValidationRecords,
    });
    return {
        schemaVersion: 6,
        auditId,
        sourceNamespace,
        stageState: validatedSnapshot.stageState,
        analysisSnapshot: validatedSnapshot,
        supplyChainGraph: null,
        semanticCoveragePlan: null,
        semanticCoverageEvaluation: semanticEvaluation,
        redTeamPlan: null,
        redTeamEvaluation,
        graphPlan,
        graphTrace,
        assuranceValidationPlan,
        assuranceValidationRecords,
        assuranceValidationEvaluation,
    };
}

function session(label) {
    sequence += 1;
    return `assurance-verdict-build-${label}-${sequence}`;
}

function activateBuildAudit(label) {
    const sessionId = session(label);
    const clonePath = buildClonePath(SCRATCH, OWNER, REPO, SHA);
    const auditId = activateAudit({
        sessionId,
        buildPath: SCRATCH,
        mode: "audit_and_safe_build_council",
        expectedClonePath: clonePath,
        owner: OWNER,
        repo: REPO,
        councilRoleManifest: [{
            id: "assurance-test-role",
            category: "A",
            mandatory: true,
        }],
    });
    recordResolvedClonePath(sessionId, clonePath);
    recordResolvedSha(sessionId, SHA);
    const reportPath = buildReportPath(SCRATCH, OWNER, REPO, SHA);
    recordResolvedArtifactPaths(sessionId, { reportPath });
    return {
        sessionId,
        clonePath,
        reportPath,
        auditId,
    };
}

function installFinalization(fixture, {
    verdict,
    severityCounts = {},
    complete = true,
    assuranceLevel = "comprehensive-static-with-supply-chain",
    assuranceComplete = true,
    identity = {},
} = {}) {
    mkdirSync(fixture.reportPath, { recursive: true });
    const reportBody = "report\n";
    const findingsBody = "{}\n";
    const reportFile = nodePath.join(fixture.reportPath, "REPORT.md");
    const findingsFile = nodePath.join(fixture.reportPath, "FINDINGS.json");
    writeFileSync(reportFile, reportBody);
    writeFileSync(findingsFile, findingsBody);
    getActiveAudit(fixture.sessionId).reportFinalization = Object.freeze({
        auditId: fixture.auditId,
        reportPath: reportFile,
        findingsPath: findingsFile,
        bytesWritten: Buffer.byteLength(reportBody),
        findingsBytesWritten: Buffer.byteLength(findingsBody),
        contentSha256: sha256(reportBody),
        findingsSha256: sha256(findingsBody),
        reportIdentity: {
            sourceKind: "url",
            owner: identity.owner || OWNER,
            repo: identity.repo || REPO,
            resolvedSha: identity.resolvedSha || SHA,
        },
        flow: "evasive-assurance",
        ledgerDecisionId: `ztvo-${"3".repeat(64)}`,
        trustedOutcome: {
            schemaVersion: 6,
            outcomeId: `ztvo-${"3".repeat(64)}`,
            verdict,
            severityCounts: Object.fromEntries(
                ["info", "low", "medium", "high", "critical"].map((severity) => [
                    severity,
                    severityCounts[severity] || 0,
                ]),
            ),
            complete,
            assurance: {
                level: assuranceLevel,
                complete: assuranceComplete,
            },
            trusted: true,
        },
        stageFinalized: true,
    });
}

async function build(fixture, extra = {}) {
    return safeBuildHandler({
        ecosystem: "npm",
        clone_path: fixture.clonePath,
        mode: "audit_and_safe_build_council",
        ...extra,
    }, { sessionId: fixture.sessionId });
}

async function install(fixture, extra = {}) {
    return safeInstallHandler({
        ecosystem: "npm",
        clone_path: fixture.clonePath,
        ...extra,
    }, { sessionId: fixture.sessionId });
}

beforeEach(() => {
    rmSync(SCRATCH, { recursive: true, force: true });
    mkdirSync(SCRATCH, { recursive: true });
});

after(() => {
    rmSync(SCRATCH, { recursive: true, force: true });
});

test("assurance findings verdict is highest validated severity or no-supported behavior", () => {
    const noFinding = assuranceStateFixture(
        "11111111-1111-4111-8111-111111111111",
    );
    assert.equal(
        computeAssuranceFindingsDecision(noFinding).verdict,
        ASSURANCE_NO_SUPPORTED_BEHAVIOR_VERDICT,
    );
    const high = assuranceStateFixture(
        "22222222-2222-4222-8222-222222222222",
        { severity: "high" },
    );
    assert.equal(computeAssuranceFindingsDecision(high).verdict, "high");
});

test("assurance finalization refuses caller verdict fields and renders assurance wording", async () => {
    const fixture = activateBuildAudit("report");
    const assuranceState = assuranceStateFixture(fixture.auditId, { severity: "low" });
    const dependencies = {
        getAssuranceState:() => assuranceState,
        finalizeAssuranceState:() => ({
            stageState: { current: "finalized" },
        }),
    };
    const callerVerdict = await finalizeReportHandler({
        owner: OWNER,
        repo: REPO,
        resolved_sha: SHA,
        verdict: "low",
    }, { sessionId: fixture.sessionId }, dependencies);
    assert.equal(callerVerdict.resultType, "failure");
    assert.match(callerVerdict.textResultForLlm, /derives verdict, counts, completeness/i);

    const first = await finalizeReportHandler({
        owner: OWNER,
        repo: REPO,
        resolved_sha: SHA,
        operator_decisions: [],
    }, { sessionId: fixture.sessionId }, dependencies);
    assert.equal(first.resultType, "success", first.textResultForLlm);
    const body = JSON.parse(first.textResultForLlm);
    const markdown = readFileSync(body.reportPath, "utf8");
    const findings = JSON.parse(readFileSync(body.findingsPath, "utf8"));
    assert.equal(findings.flow, "evasive-assurance");
    assert.equal(findings.verdict.value, "low");
    assert.equal(
        findings.assurance.assuranceLevel,
        "comprehensive-static-with-supply-chain",
    );
    assert.match(markdown, /Findings verdict and assurance/);
    assert.match(markdown, /Host build execution is neither isolation nor assurance evidence/);
    assert.doesNotMatch(markdown, /\b(?:safe|clean)\b/i);

    const retry = await finalizeReportHandler({
        owner: OWNER,
        repo: REPO,
        resolved_sha: SHA,
        operator_decisions: [{
            finding_id: findings.verdict.activeFindingIds[0],
            action: "kept-as-is",
            rationale_category: "accepted-risk",
        }],
    }, { sessionId: fixture.sessionId }, dependencies);
    assert.equal(retry.resultType, "success");
    assert.equal(JSON.parse(retry.textResultForLlm).alreadyFinalized, true);
    assert.equal(existsSync(body.reportPath), true);
    deactivateAudit(fixture.sessionId);
});

test("host build gate requires finalized identity and refuses incomplete/high outcomes", async () => {
    const missing = activateBuildAudit("missing");
    assert.match((await build(missing)).textResultForLlm, /host build gate CLOSED/);
    deactivateAudit(missing.sessionId);

    const incomplete = activateBuildAudit("incomplete");
    installFinalization(incomplete, {
        verdict: "low",
        complete: false,
    });
    assert.match((await build(incomplete)).textResultForLlm, /findings outcome is incomplete/i);
    deactivateAudit(incomplete.sessionId);

    const incompleteAssurance = activateBuildAudit("incomplete-assurance");
    installFinalization(incompleteAssurance, {
        verdict: "low",
        assuranceLevel: "partial",
        assuranceComplete: false,
    });
    assert.match((await build(incompleteAssurance)).textResultForLlm, /assurance is incomplete/i);
    deactivateAudit(incompleteAssurance.sessionId);

    const boundedAssurance = activateBuildAudit("bounded-assurance");
    installFinalization(boundedAssurance, {
        verdict: "low",
        assuranceLevel: "bounded-static",
        assuranceComplete: false,
    });
    assert.match((await build(boundedAssurance)).textResultForLlm, /assurance is incomplete/i);
    deactivateAudit(boundedAssurance.sessionId);

    const high = activateBuildAudit("high");
    installFinalization(high, {
        verdict: "high",
        severityCounts: { high: 1 },
    });
    assert.match((await build(high)).textResultForLlm, /critical\/high malicious behavior/i);
    deactivateAudit(high.sessionId);

    const mismatch = activateBuildAudit("mismatch");
    installFinalization(mismatch, {
        verdict: "low",
        identity: { repo: "other" },
    });
    assert.match((await build(mismatch)).textResultForLlm, /does not match the active audit identity/i);
    deactivateAudit(mismatch.sessionId);
});

test("host install gate also requires the finalized trusted report", async () => {
    const missing = activateBuildAudit("install-missing");
    assert.match((await install(missing)).textResultForLlm, /host install gate CLOSED/);
    deactivateAudit(missing.sessionId);

    const high = activateBuildAudit("install-high");
    installFinalization(high, {
        verdict: "high",
        severityCounts: { high: 1 },
    });
    assert.match((await install(high)).textResultForLlm, /critical\/high malicious behavior/i);
    deactivateAudit(high.sessionId);

    const low = activateBuildAudit("install-low");
    installFinalization(low, {
        verdict: "low",
        severityCounts: { low: 1 },
    });
    const result = await install(low);
    assert.equal(result.resultType, "failure");
    assert.doesNotMatch(result.textResultForLlm, /host install gate CLOSED/);
    deactivateAudit(low.sessionId);
});

test("host build gate allows low and no-supported outcomes past policy checks", async () => {
    for (const [label, verdict, counts] of [
        ["low", "low", { low: 1 }],
        ["none", ASSURANCE_NO_SUPPORTED_BEHAVIOR_VERDICT, {}],
    ]) {
        const fixture = activateBuildAudit(label);
        installFinalization(fixture, {
            verdict,
            severityCounts: counts,
        });
        const result = await build(fixture);
        assert.equal(result.resultType, "failure");
        assert.doesNotMatch(result.textResultForLlm, /host build gate CLOSED/);
        deactivateAudit(fixture.sessionId);
    }
});
