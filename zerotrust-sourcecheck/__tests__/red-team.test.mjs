import { createHash } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
    PROMPT_REVIEW_CANARY_MARKER,
    PROMPT_REVIEW_MODE,
    PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER,
    RED_TEAM_CANARY_MARKER,
    RED_TEAM_CATEGORY_IDS,
    RED_TEAM_OUTPUT_CONTRACT_MARKER,
    SEMANTIC_CHECK_NAMES,
    SEMANTIC_NEGATIVE_EVIDENCE_CODES,
    EVASIVE_BLOCKERS,
    applyRedTeamCoverageToSnapshot,
    applySemanticCoverageToSnapshot,
    buildEvasiveGraph,
    createInitialAssuranceStageState,
    createPromptMetadataFact,
    createPromptReviewRecord,
    createRedTeamAssignment,
    createRedTeamPlan,
    createRedTeamReviewRecord,
    createRedTeamScannedSnapshot,
    createSemanticCoveragePlan,
    createSemanticReviewAssignment,
    createSemanticReviewRecord,
    createSemanticScannerCoverageRecord,
    createAssuranceAnalysisSnapshot,
    createEvasiveObjectInventoryRecord,
    detectPromptLikeSource,
    evaluateRedTeamCoverage,
    evaluateSemanticCoverage,
    redTeamSnapshotCanAdvance,
    scanSourceText,
    transitionAssuranceStageState,
    validateRedTeamAssignment,
} from "../analysis/index.mjs";
import { __internals as wrapperInternals } from "../safeWrappers/redTeamWrapper.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_NAMESPACE =
    "github.com/example/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function sha256(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}

function decodedStage() {
    let state = createInitialAssuranceStageState({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
    });
    state = transitionAssuranceStageState(state, {
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        from: "acquired",
        to: "inventoried",
    });
    return transitionAssuranceStageState(state, {
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        from: "inventoried",
        to: "decoded",
    });
}

function objectFor(path, text) {
    return createEvasiveObjectInventoryRecord({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path,
        parentObjectId: null,
        objectKind: "source-text",
        byteLength: Buffer.byteLength(text),
        status: "inventoried",
        blockerCodes: [],
        contentSha256: sha256(text),
        upstreamSha: null,
        executable: false,
    });
}

function checks() {
    return Object.fromEntries(
        SEMANTIC_CHECK_NAMES.map((name) => [name, "checked"]),
    );
}

function semanticBundle({
    files = {
        "src/main.mjs":
            "import fs from \"node:fs\"; export function start() { return fs.readFileSync(\"config.json\", \"utf8\"); }\n",
    },
    promptPaths = [],
    semanticCandidateSeverity = null,
} = {}) {
    const objects = Object.entries(files).map(([path, text]) =>
        objectFor(path, text));
    const decodedSnapshot = createAssuranceAnalysisSnapshot({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        stageState: decodedStage(),
        status: "incomplete",
        objectInventory: objects,
        derivedArtifacts: [],
        semanticReviewCoverage: [],
        redTeamCoverage: [],
        blockerCodes: [],
        sourceIdentitySha256: "f".repeat(64),
    });
    const normalizedViews = objects.map((object) => {
        const promptAffected = promptPaths.includes(object.path);
        const metadataFacts = promptAffected
            ? [createPromptMetadataFact({
                kind: "prompt-fragment",
                tokens: ["ignore", "previous", "instructions"],
                evidence: {
                    path: object.path,
                    startLine: 1,
                    endLine: 1,
                    excerptHash: "e".repeat(64),
                },
            })]: [];
        return detectPromptLikeSource({
            object,
            detectorId: "prompt-detector",
            detectorVersion: "1.0.0",
            facts: [],
            metadataFacts,
        });
    });
    const semanticPlan = createSemanticCoveragePlan({
        snapshot: decodedSnapshot,
        normalizedViews,
    });
    const textByPath = new Map(Object.entries(files));
    const scannerRecords = semanticPlan.scannerAssignments.map((assignment) =>
        createSemanticScannerCoverageRecord({
            plan: semanticPlan,
            snapshot: decodedSnapshot,
            assignmentId: assignment.assignmentId,
            assignmentToken: assignment.assignmentToken,
            scannerResult: scanSourceText({
                path: assignment.path,
                text: textByPath.get(assignment.path),
            }),
        }));
    const reviewAssignments = [];
    const reviewRecords = [];
    for (const shard of semanticPlan.modelReviewShards) {
        for (let slot = 1; slot <= shard.requiredReviewerCount; slot += 1) {
            const assignment = createSemanticReviewAssignment({
                plan: semanticPlan,
                snapshot: decodedSnapshot,
                scannerRecords,
                objectId: shard.objectId,
                reviewerSlot: slot,
                reviewerId: `semantic-reviewer-${shard.objectId.slice(-6)}-${slot}`,
                reviewerVersion: "1.0.0",
                assignmentNonceSha256: String(slot).repeat(64),
            });
            const promptReviewRecord = assignment.promptAssignment
                ? createPromptReviewRecord({
                    assignment: assignment.promptAssignment,
                    reviewerId: assignment.reviewerId,
                    assignmentToken:
                        assignment.promptAssignment.assignmentToken,
                    reviewMode: PROMPT_REVIEW_MODE,
                    decision: "manipulation-candidate",
                    reviewedSignalIds:
                        assignment.promptAssignment.normalizedView.signals
                            .map((signal) => signal.signalId),
                    factIds: assignment.promptAssignment.normalizedView.facts
                        .map((fact) => fact.factId),
                    evidenceIds:
                        assignment.promptAssignment.normalizedView.evidence
                            .map((evidence) => evidence.evidenceId),
                    blockerCodes: [],
                    canaryMarker: PROMPT_REVIEW_CANARY_MARKER,
                    outputContractMarker:
                        PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER,
                }): null;
            const candidateFact = assignment.semanticView.facts[0] || null;
            const candidateEvidence = assignment.semanticView.evidence.find((entry) =>
                entry.factId === candidateFact?.id);
            const semanticCandidates = semanticCandidateSeverity && slot === 1
                ? [{
                    behavior: {
                        trigger: "runtime-start",
                        capability: "file-read-capability",
                        action: "read-sensitive-input",
                        target: "local-configuration",
                    },
                    severity: semanticCandidateSeverity,
                    confidence: "high",
                    maliciousProjectFit: "likely",
                    benignHypothesisCode: "no-benign-hypothesis",
                    objectIds: [assignment.objectId],
                    artifactIds: [],
                    factIds: [candidateFact.id],
                    evidenceIds: [candidateEvidence.evidenceId],
                }]: [];
            const review = createSemanticReviewRecord({
                assignment,
                plan: semanticPlan,
                snapshot: decodedSnapshot,
                scannerRecords,
                assignmentToken: assignment.assignmentToken,
                reviewerId: assignment.reviewerId,
                objectId: assignment.objectId,
                artifactIds: assignment.artifactIds,
                semanticViewId: assignment.semanticView.semanticViewId,
                semanticViewSha256:
                    assignment.semanticView.hashes.semanticViewSha256,
                reviewedFactIds: assignment.semanticView.facts
                    .map((fact) => fact.id),
                reviewedArtifactIds: assignment.semanticView.derivedArtifacts
                    .map((artifact) => artifact.artifactId),
                decision: semanticCandidates.length > 0
                    ? "findings-recorded": "no-findings",
                checks: checks(),
                negativeEvidenceCodes: semanticCandidates.length > 0
                    ? []: SEMANTIC_NEGATIVE_EVIDENCE_CODES,
                candidates: semanticCandidates,
                blockerCodes: [],
                promptReviewRecord,
            });
            reviewAssignments.push(assignment);
            reviewRecords.push(review);
        }
    }
    const semanticEvaluation = evaluateSemanticCoverage({
        snapshot: decodedSnapshot,
        plan: semanticPlan,
        scannerRecords,
        reviewAssignments,
        reviewRecords,
    });
    assert.equal(semanticEvaluation.complete, true);
    const semanticStage = transitionAssuranceStageState(decodedSnapshot.stageState, {
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        from: "decoded",
        to: "semantically-covered",
    });
    const semanticSnapshot = applySemanticCoverageToSnapshot({
        snapshot: decodedSnapshot,
        evaluation: semanticEvaluation,
        stageState: semanticStage,
    });
    const scannedSnapshot = createRedTeamScannedSnapshot({
        snapshot: semanticSnapshot,
    });
    const planInputs = {
        snapshot: scannedSnapshot,
        semanticBaseSnapshot: decodedSnapshot,
        semanticPlan,
        semanticEvaluation,
        semanticScannerRecords: scannerRecords,
        semanticReviewAssignments: reviewAssignments,
        semanticReviewRecords: reviewRecords,
    };
    const redTeamPlan = createRedTeamPlan(planInputs);
    return {
        objects,
        decodedSnapshot,
        semanticPlan,
        semanticEvaluation,
        scannerRecords,
        reviewAssignments,
        reviewRecords,
        semanticSnapshot,
        scannedSnapshot,
        planInputs,
        redTeamPlan,
    };
}

function assignmentFor(bundle, categoryId) {
    return createRedTeamAssignment({
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        categoryId,
        reviewerId: `red-reviewer-${categoryId}`,
        reviewerVersion: "1.0.0",
        modelId: `red-model-${categoryId}`,
        assignmentNonceSha256: sha256(categoryId),
    });
}

function emptyReview(bundle, assignment, overrides = {}) {
    return createRedTeamReviewRecord({
        assignment,
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        assignmentToken: assignment.assignmentToken,
        reviewerId: assignment.reviewerId,
        decision: "no-candidate",
        reviewedObjectIds: assignment.subjects.objectIds,
        reviewedArtifactIds: assignment.subjects.artifactIds,
        reviewedFactIds: assignment.subjects.factIds,
        reviewedEvidenceIds: assignment.subjects.evidenceIds,
        reviewedGraphNodeIds: assignment.subjects.graphNodeIds,
        reviewedGraphEdgeIds: assignment.subjects.graphEdgeIds,
        falsificationChecks: assignment.falsificationChecks,
        negativeEvidenceCodes: assignment.negativeEvidenceCodes,
        candidates: [],
        blockerCodes: [],
        canaryMarker: RED_TEAM_CANARY_MARKER,
        outputContractMarker: RED_TEAM_OUTPUT_CONTRACT_MARKER,
        ...overrides,
    });
}

function completeRedTeam(bundle, omittedCategoryId = null) {
    const assignments = [];
    const reviews = [];
    for (const categoryId of RED_TEAM_CATEGORY_IDS) {
        if (categoryId === omittedCategoryId) continue;
        const assignment = assignmentFor(bundle, categoryId);
        assignments.push(assignment);
        reviews.push(emptyReview(bundle, assignment));
    }
    return { assignments, reviews };
}

test("red-team assignments derive reviewer limits and do not invent model independence", () => {
    const bundle = semanticBundle();
    const assignment = assignmentFor(bundle, "split-cross-file-chains");
    assert.equal(assignment.independence.reviewerDistinctFromInitial, true);
    assert.deepEqual(assignment.independence.initialModelIds, []);
    assert.equal(assignment.independence.modelDistinctFromInitial, null);
    assert.equal(assignment.independence.modelIndependenceVerified, false);
    assert.equal(
        assignment.independence.proceduralLimitCode,
        "model-independence-unverifiable",
    );
});

test("new red-team candidates enter the assurance candidate ledger with exact evidence identities", () => {
    const bundle = semanticBundle();
    const assignment = assignmentFor(
        bundle,
        "dynamic-external-payload-loading",
    );
    const evidence = assignment.normalizedView.evidence.find((entry) =>
        entry.evidenceKind === "object");
    const objectNode = assignment.normalizedView.graph.nodes.find((node) =>
        node.identity === evidence.objectId);
    const review = createRedTeamReviewRecord({
        assignment,
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        assignmentToken: assignment.assignmentToken,
        reviewerId: assignment.reviewerId,
        decision: "candidate-submitted",
        reviewedObjectIds: assignment.subjects.objectIds,
        reviewedArtifactIds: assignment.subjects.artifactIds,
        reviewedFactIds: assignment.subjects.factIds,
        reviewedEvidenceIds: assignment.subjects.evidenceIds,
        reviewedGraphNodeIds: assignment.subjects.graphNodeIds,
        reviewedGraphEdgeIds: assignment.subjects.graphEdgeIds,
        falsificationChecks: assignment.falsificationChecks,
        negativeEvidenceCodes: [],
        candidates: [{
            behavior: {
                trigger: "runtime-start",
                capability: "external-payload-loader",
                action: "load-and-execute",
                target: "user-host",
            },
            severity: "high",
            confidence: "high",
            maliciousProjectFit: "likely",
            benignHypothesisCode: "unknown",
            objectIds: [evidence.objectId],
            artifactIds: [],
            factIds: [],
            evidenceIds: [evidence.evidenceId],
            graphNodeIds: [objectNode.nodeId],
            graphEdgeIds: [],
        }],
        blockerCodes: [],
        canaryMarker: RED_TEAM_CANARY_MARKER,
        outputContractMarker: RED_TEAM_OUTPUT_CONTRACT_MARKER,
    });
    const evaluation = evaluateRedTeamCoverage({
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        assignments: [assignment],
        reviewRecords: [review],
    });
    assert.equal(evaluation.candidateLedger.length, 1);
    assert.match(evaluation.candidateLedger[0].candidateId, /^ztrf-/);
    assert.deepEqual(
        evaluation.candidateLedger[0].evidenceIds,
        [evidence.evidenceId],
    );
});

test("assurance graph merges semantic and red-team ledgers with semantic severity fidelity", () => {
    const bundle = semanticBundle({ semanticCandidateSeverity: "high" });
    assert.equal(bundle.semanticEvaluation.candidateLedger.length, 1);
    const semanticCandidate = bundle.semanticEvaluation.candidateLedger[0];
    const { assignments, reviews } = completeRedTeam(bundle);
    const redTeamEvaluation = evaluateRedTeamCoverage({
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        assignments,
        reviewRecords: reviews,
    });
    const redTeamedStage = transitionAssuranceStageState(
        bundle.scannedSnapshot.stageState,
        {
            auditId: AUDIT_ID,
            sourceNamespace: SOURCE_NAMESPACE,
            from: "scanned",
            to: "red-teamed",
        },
    );
    const redTeamedSnapshot = applyRedTeamCoverageToSnapshot({
        snapshot: bundle.scannedSnapshot,
        evaluation: redTeamEvaluation,
        stageState: redTeamedStage,
    });
    const graph = buildEvasiveGraph({
        snapshot: redTeamedSnapshot,
        redTeamBaseSnapshot: bundle.scannedSnapshot,
        semanticBaseSnapshot: bundle.decodedSnapshot,
        semanticPlan: bundle.semanticPlan,
        semanticEvaluation: bundle.semanticEvaluation,
        semanticScannerRecords: bundle.scannerRecords,
        semanticReviewAssignments: bundle.reviewAssignments,
        semanticReviewRecords: bundle.reviewRecords,
        redTeamPlan: bundle.redTeamPlan,
        redTeamAssignments: assignments,
        redTeamReviewRecords: reviews,
        redTeamEvaluation,
        supplyChainGraph: null,
    });
    const finding = graph.findings.find((entry) =>
        entry.findingId === semanticCandidate.candidateId);
    assert.equal(finding.origin, "semantic-review");
    assert.equal(finding.severity, "high");
    assert.deepEqual(finding.factIds, semanticCandidate.factIds);
    assert.deepEqual(finding.evidenceIds, semanticCandidate.evidenceIds);
});

test("empty category results require complete subjects, falsification checks, and exact negative proof", () => {
    const bundle = semanticBundle();
    const assignment = assignmentFor(bundle, "generated-decoded-code");
    assert.throws(() => emptyReview(bundle, assignment, {
            negativeEvidenceCodes:
                assignment.negativeEvidenceCodes.slice(1),
        }),
        /negativeEvidenceCodes/,
    );
    assert.equal(emptyReview(bundle, assignment).decision, "no-candidate");
});

test("missing mandatory category prevents red-teamed eligibility despite the deterministic 90 percent gate", () => {
    const bundle = semanticBundle();
    const { assignments, reviews } = completeRedTeam(
        bundle,
        "prompt-reviewer-manipulation",
    );
    const evaluation = evaluateRedTeamCoverage({
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        assignments,
        reviewRecords: reviews,
    });
    assert.equal(evaluation.complete, false);
    assert.equal(evaluation.gates.mandatoryCategoriesSatisfied, false);
    assert.ok(evaluation.gates.missingMandatoryCategoryIds.includes(
        "prompt-reviewer-manipulation",
    ));
    assert.ok(evaluation.blockerCodes.includes(
        EVASIVE_BLOCKERS.RED_TEAM_MISSING_CATEGORY,
    ));
});

test("prompt-manipulation assignments carry normalized signals and reject marker tampering", () => {
    const bundle = semanticBundle({
        promptPaths: ["src/main.mjs"],
    });
    const assignment = assignmentFor(
        bundle,
        "prompt-reviewer-manipulation",
    );
    assert.ok(assignment.normalizedView.promptViews[0].signals.length > 0);
    assert.equal(
        assignment.normalizedView.initialNoFindings[0].promptReviewDecision,
        "manipulation-candidate",
    );
    assert.throws(() => emptyReview(bundle, assignment, {
            canaryMarker: "changed",
        }),
        /canary|output-contract/,
    );
});

test("benign-decoy category receives alternate same-basename paths", () => {
    const text =
        "import fs from \"node:fs\"; export function start() { return fs.readFileSync(\"config.json\", \"utf8\"); }\n";
    const bundle = semanticBundle({
        files: {
            "src/main.mjs": text,
            "fallback/main.mjs": text,
        },
    });
    const assignment = assignmentFor(
        bundle,
        "benign-decoy-alternate-path",
    );
    const group = assignment.normalizedView.alternatePathGroups
        .find((entry) => entry.basename === "main.mjs");
    assert.deepEqual(group.paths, ["fallback/main.mjs", "src/main.mjs"]);
});

test("red-team assignments reject normalized-view identity tampering", () => {
    const bundle = semanticBundle();
    const assignment = assignmentFor(bundle, "split-cross-file-chains");
    const tampered = {
        ...assignment,
        normalizedView: {
            ...assignment.normalizedView,
            facts: [],
        },
    };
    assert.throws(() => validateRedTeamAssignment(tampered, {
            plan: bundle.redTeamPlan,
            planInputs: bundle.planInputs,
        }),
        /wrapper-issued red-team assignment/,
    );
});

test("identical red-team assignment and review retries do not inflate coverage or candidates", () => {
    const bundle = semanticBundle();
    const assignment = assignmentFor(bundle, "binary-archive-concealment");
    const review = emptyReview(bundle, assignment);
    const evaluation = evaluateRedTeamCoverage({
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        assignments: [assignment, assignment],
        reviewRecords: [review, review],
    });
    assert.equal(evaluation.gates.successfulAssignments, 1);
    assert.equal(evaluation.candidateLedger.length, 0);
});

test("stage ordering requires scanned preparation and complete red-team gates before advancement", () => {
    const bundle = semanticBundle();
    assert.throws(() => createRedTeamPlan({
            ...bundle.planInputs,
            snapshot: bundle.semanticSnapshot,
        }),
        /must be scanned/,
    );
    const incomplete = evaluateRedTeamCoverage({
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        assignments: [],
        reviewRecords: [],
    });
    assert.equal(
        redTeamSnapshotCanAdvance(bundle.scannedSnapshot, incomplete),
        false,
    );
    const { assignments, reviews } = completeRedTeam(bundle);
    const complete = evaluateRedTeamCoverage({
        plan: bundle.redTeamPlan,
        planInputs: bundle.planInputs,
        assignments,
        reviewRecords: reviews,
    });
    assert.equal(complete.complete, true);
    assert.equal(
        redTeamSnapshotCanAdvance(bundle.scannedSnapshot, complete),
        true,
    );
});

test("red-team wrapper review JSON is strict and refuses unknown fields", () => {
    assert.throws(() => wrapperInternals.parseReviewJson(JSON.stringify({
            ...Object.fromEntries(
                [...wrapperInternals.REVIEW_FIELDS].map((field) => [field, null]),
            ),
            sourceText: "forbidden",
        })),
        /unsupported fields/,
    );
});
