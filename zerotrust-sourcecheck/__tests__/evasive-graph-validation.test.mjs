import { createHash } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
    EVASIVE_BLOCKERS,
    ASSURANCE_CONFIRM_CHECKS,
    ASSURANCE_NO_FINDING_CHECKS,
    ASSURANCE_REFUTE_CHECKS,
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
    validateEvasiveGraphPlan,
} from "../analysis/index.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_NAMESPACE =
    "github.com/example/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function sha256(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}

function bindings(overrides = {}) {
    return {
        objectIds: [],
        artifactIds: [],
        factIds: [],
        evidenceIds: [],
        supplyChainNodeIds: [],
        semanticReviewIds: [],
        candidateIds: [],
        redTeamGraphNodeIds: [],
        ...overrides,
    };
}

function edgeBindings(overrides = {}) {
    return {
        artifactIds: [],
        factIds: [],
        evidenceIds: [],
        supplyChainEdgeIds: [],
        candidateIds: [],
        redTeamGraphEdgeIds: [],
        ...overrides,
    };
}

function node(kind, identity, overrides = {}) {
    return createEvasiveGraphNode({
        kind,
        identityKind: overrides.identityKind || "target",
        identity,
        status: overrides.status || "supported",
        bindings: bindings(overrides.bindings),
    });
}

function edge(kind, from, to, overrides = {}) {
    return createEvasiveGraphEdge({
        kind,
        fromNodeId: from.nodeId,
        toNodeId: to.nodeId,
        bindings: edgeBindings(overrides),
    });
}

function evidence(name) {
    const descriptor = {
        evidenceKind: "fact",
        objectId: `object-${name}`,
        artifactId: null,
        factId: `fact-${name}`,
        supplyChainNodeId: null,
        path: `src/${name}.mjs`,
        startLine: 1,
        endLine: 1,
        excerptHash: sha256(`excerpt-${name}`),
        contentSha256: sha256(`content-${name}`),
    };
    return createEvasiveGraphEvidenceRecord({
        evidenceId: `ztve-${sha256(JSON.stringify(descriptor))}`,
        ...descriptor,
    });
}

function graph({
    nodes,
    edges,
    evidenceRecords = [],
    findingDescriptors = [],
    blockerCodes = [],
    snapshot = null,
    limits = {},
}) {
    return mergeEvasiveGraphRecords({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        snapshotId: snapshot?.snapshotId || `zts-${"a".repeat(64)}`,
        snapshotSha256: snapshot?.hashes.snapshotSha256 || "a".repeat(64),
        nodes,
        proposedEdges: edges,
        evidence: evidenceRecords,
        findingDescriptors,
        blockerCodes,
        limits,
    });
}

function stageAt(target) {
    const stages = [
        "acquired",
        "inventoried",
        "decoded",
        "semantically-covered",
        "scanned",
        "red-teamed",
        "traced",
    ];
    let state = createInitialAssuranceStageState({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
    });
    for (let index = 1; index <= stages.indexOf(target); index += 1) {
        state = transitionAssuranceStageState(state, {
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            from: stages[index - 1],
            to: stages[index],
        });
    }
    return state;
}

function snapshotAt(target) {
    return createAssuranceAnalysisSnapshot({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        stageState: stageAt(target),
        status: "incomplete",
        objectInventory: [],
        derivedArtifacts: [],
        semanticReviewCoverage: [],
        redTeamCoverage: [],
        blockerCodes: [],
        sourceIdentitySha256: "f".repeat(64),
    });
}

function evaluations() {
    return {
        semanticEvaluation: {
            schemaVersion: 6,
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            evaluationId: `ztse-${"b".repeat(64)}`,
            complete: true,
            truncated: false,
            blockerCodes: [],
        },
        redTeamEvaluation: {
            schemaVersion: 6,
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            evaluationId: `ztreval-${"c".repeat(64)}`,
            complete: true,
            truncated: false,
            blockerCodes: [],
            gates: {
                ninetyPercentSatisfied: true,
                mandatoryCategoriesSatisfied: true,
            },
        },
    };
}

function validationBundle({ withFinding = false } = {}) {
    const graphBaseSnapshot = snapshotAt("red-teamed");
    const tracedSnapshot = snapshotAt("traced");
    const proofEvidence = evidence("proof");
    const candidateId = `ztrf-${sha256("candidate")}`;
    const root = node("trigger", withFinding ? `${candidateId}:trigger`: "root", {
        bindings: withFinding
            ? { candidateIds: [candidateId], evidenceIds: [proofEvidence.evidenceId] }: { evidenceIds: [proofEvidence.evidenceId] },
    });
    const effect = node("effect", withFinding ? `${candidateId}:effect`: "effect", {
        bindings: withFinding
            ? { candidateIds: [candidateId], evidenceIds: [proofEvidence.evidenceId] }: { evidenceIds: [proofEvidence.evidenceId] },
    });
    const flow = edge("executes", root, effect, {
        candidateIds: withFinding ? [candidateId]: [],
        evidenceIds: [proofEvidence.evidenceId],
    });
    const findingDescriptors = withFinding
        ? [{
            findingId: candidateId,
            origin: "red-team",
            severity: "low",
            objectIds: [],
            artifactIds: [],
            factIds: [],
            evidenceIds: [proofEvidence.evidenceId],
            nodeIds: [root.nodeId, effect.nodeId],
            edgeIds: [flow.edgeId],
            sourceRecordIds: ["red-team-review-1"],
        }]: [];
    const graphPlan = graph({
        nodes: [root, effect],
        edges: [flow],
        evidenceRecords: [proofEvidence],
        findingDescriptors,
        snapshot: graphBaseSnapshot,
    });
    const trace = traceEvasiveGraph(graphPlan);
    assert.equal(trace.complete, true);
    const foundation = evaluations();
    const keys = withFinding
        ? [`${candidateId}:confirm`, `${candidateId}:refute`]: ["no-finding-assurance"];
    const assignmentNonceSha256ByKey = Object.fromEntries(
        keys.map((key, index) => [key, String(index + 1).repeat(64)]),
    );
    const planInputs = {
        snapshot: tracedSnapshot,
        graphBaseSnapshot,
        graph: graphPlan,
        trace,
        ...foundation,
        supplyChainGraph: null,
    };
    const plan = createAssuranceValidationPlan({
        ...planInputs,
        validatorIds: {
            noFinding: "validator-no-finding",
            confirm: "validator-confirm",
            refute: "validator-refute",
        },
        validatorVersion: "1.0.0",
        assignmentNonceSha256ByKey,
    });
    return {
        candidateId,
        graphPlan,
        trace,
        planInputs,
        plan,
    };
}

test("assurance trace preserves benign and malicious alternate paths from every root", () => {
    const root = node("activation", "root");
    const benign = node("capability", "benign");
    const transform = node("transform", "alternate-transform");
    const effect = node("effect", "alternate-effect");
    const plan = graph({
        nodes: [root, benign, transform, effect],
        edges: [
            edge("calls", root, benign),
            edge("calls", root, transform),
            edge("executes", transform, effect),
        ],
    });
    const trace = traceEvasiveGraph(plan);
    assert.equal(trace.complete, true);
    assert.equal(trace.counts.roots, 1);
    assert.equal(trace.counts.benignPaths, 1);
    assert.equal(trace.counts.effectPaths, 1);
    assert.equal(trace.rootCoverage[0].pathIds.length, 2);
});

test("unordered endpoint/kind buckets quarantine every forward and reverse record", () => {
    const evidenceA = evidence("a");
    const evidenceB = evidence("b");
    const left = node("transform", "left");
    const right = node("capability", "right");
    const plan = graph({
        nodes: [left, right],
        evidenceRecords: [evidenceA, evidenceB],
        edges: [
            edge("calls", left, right, { evidenceIds: [evidenceA.evidenceId] }),
            edge("calls", left, right, { evidenceIds: [evidenceB.evidenceId] }),
            edge("calls", right, left, { evidenceIds: [evidenceA.evidenceId] }),
            edge("calls", right, left, { evidenceIds: [evidenceB.evidenceId] }),
        ],
    });
    assert.equal(plan.edges.length, 0);
    assert.equal(plan.conflicts.length, 1);
    assert.equal(plan.conflicts[0].records.length, 4);
    assert.deepEqual(
        plan.conflicts[0].records.flatMap((record) =>
            record.bindings.evidenceIds).sort(),
        [
            evidenceA.evidenceId,
            evidenceA.evidenceId,
            evidenceB.evidenceId,
            evidenceB.evidenceId,
        ].sort(),
    );
    assert.ok(plan.blockerCodes.includes(EVASIVE_BLOCKERS.TRACE_CONFLICT));
});

test("dynamic targets and unsupported binary nodes block comprehensive trace", () => {
    const root = node("trigger", "root");
    const dynamic = node("dynamic-target", "dynamic", { status: "unresolved" });
    const unsupportedBinary = node("unsupported-target", "binary", {
        status: "unsupported",
    });
    const dynamicPlan = graph({
        nodes: [root, dynamic],
        edges: [edge("loads", root, dynamic)],
    });
    const dynamicTrace = traceEvasiveGraph(dynamicPlan);
    assert.equal(dynamicTrace.complete, false);
    assert.ok(dynamicTrace.blockerCodes.includes(
        EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED,
    ));

    const binaryPlan = graph({
        nodes: [root, unsupportedBinary],
        edges: [edge("loads", root, unsupportedBinary)],
        blockerCodes: [EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT],
    });
    const binaryTrace = traceEvasiveGraph(binaryPlan);
    assert.equal(binaryTrace.complete, false);
    assert.ok(binaryTrace.blockerCodes.includes(
        EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT,
    ));
});

test("no-finding assurance proof covers every assigned graph and foundation identity", () => {
    const bundle = validationBundle();
    assert.equal(bundle.plan.mode, "no-finding");
    const assignment = bundle.plan.assignments[0];
    const record = createAssuranceValidationRecord({
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
    });
    const evaluation = evaluateAssuranceValidation({
        plan: bundle.plan,
        planInputs: bundle.planInputs,
        records: [record],
    });
    assert.equal(evaluation.complete, true);
    assert.equal(evaluation.noFindingOutcome, "supported");
    assert.equal(
        evaluation.assurance.assuranceLevel,
        "comprehensive-static-with-supply-chain",
    );
});

test("candidate validation includes low severity and requires independent confirm/refute", () => {
    const bundle = validationBundle({ withFinding: true });
    assert.equal(bundle.plan.mode, "findings");
    assert.equal(bundle.plan.findingIds.length, 1);
    assert.equal(bundle.plan.assignments.length, 2);
    assert.equal(bundle.plan.assignments[0].context.severity, "low");
    const confirm = bundle.plan.assignments.find((assignment) =>
        assignment.decisionType === "confirm");
    const refute = bundle.plan.assignments.find((assignment) =>
        assignment.decisionType === "refute");
    assert.notEqual(confirm.validatorId, refute.validatorId);
    const confirmRecord = createAssuranceValidationRecord({
        assignment: confirm,
        assignmentToken: confirm.assignmentToken,
        validatorId: confirm.validatorId,
        conclusion: "confirmed",
        reviewedNodeIds: confirm.context.nodeIds,
        reviewedEdgeIds: confirm.context.edgeIds,
        reviewedPathIds: confirm.context.pathIds,
        reviewedEvidenceIds: confirm.context.evidenceIds,
        reviewedBasisIds: confirm.context.basisIds,
        checks: Object.fromEntries(ASSURANCE_CONFIRM_CHECKS.map((name) => [name, true])),
        negativeEvidenceCodes: [],
        blockerCodes: [],
    });
    const refuteRecord = createAssuranceValidationRecord({
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
    });
    const evaluation = evaluateAssuranceValidation({
        plan: bundle.plan,
        planInputs: bundle.planInputs,
        records: [confirmRecord, refuteRecord],
    });
    assert.equal(evaluation.complete, true);
    assert.equal(evaluation.findingOutcomes[0].outcome, "validated");
});

test("identity tampering is refused and exact duplicate records are idempotent", () => {
    const bundle = validationBundle();
    const assignment = bundle.plan.assignments[0];
    assert.throws(() => createAssuranceValidationRecord({
            assignment,
            assignmentToken: `ztavt-${"0".repeat(64)}`,
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
        }),
        /wrapper-issued token/,
    );
    assert.throws(() => validateEvasiveGraphPlan({
            ...bundle.graphPlan,
            snapshotId: `zts-${"0".repeat(64)}`,
        }),
        /deterministic assurance graph hashes/,
    );
    const record = createAssuranceValidationRecord({
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
    });
    const evaluation = evaluateAssuranceValidation({
        plan: bundle.plan,
        planInputs: bundle.planInputs,
        records: [record, record],
    });
    assert.equal(evaluation.counts.records, 1);
    assert.equal(evaluation.complete, true);
});

test("graph caps fail closed without silently dropping completeness blockers", () => {
    const root = node("activation", "root");
    const first = node("effect", "first");
    const second = node("effect", "second");
    const plan = graph({
        nodes: [root, first, second],
        edges: [
            edge("executes", root, first),
            edge("writes", root, second),
        ],
        limits: { edges: 1 },
    });
    assert.equal(plan.truncation.edges, true);
    assert.ok(plan.blockerCodes.includes(EVASIVE_BLOCKERS.TRACE_TRUNCATED));
    assert.equal(traceEvasiveGraph(plan).complete, false);
});
