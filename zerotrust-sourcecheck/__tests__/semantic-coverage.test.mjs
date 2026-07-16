import { createHash } from "node:crypto";
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";

import {
    SEMANTIC_CHECK_NAMES,
    SEMANTIC_NEGATIVE_EVIDENCE_CODES,
    PROMPT_REVIEW_CANARY_MARKER,
    PROMPT_REVIEW_MODE,
    PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER,
    EVASIVE_BLOCKERS,
    applySemanticCoverageToSnapshot,
    classifyObjectForSemanticCoverage,
    createInitialAssuranceStageState,
    createPromptMetadataFact,
    createPromptReviewRecord,
    createSemanticCoveragePlan,
    createSemanticReviewAssignment,
    createSemanticReviewRecord,
    createSemanticScannerCoverageRecord,
    createAssuranceAnalysisSnapshot,
    createEvasiveObjectInventoryRecord,
    detectPromptLikeSource,
    evaluateSemanticCoverage,
    scanSourceText,
    transitionAssuranceStageState,
    validateSemanticReviewAssignment,
    validateSemanticReviewRecord,
} from "../analysis/index.mjs";
import {
    __internals,
    activateAudit,
    advanceAssuranceStage,
    getAssuranceState,
    issueSemanticReviewAssignment,
    prepareSemanticCoverage,
    recordAssuranceSnapshot,
    recordSemanticReview,
    recordSemanticScannerCoverage,
} from "../enforcement.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_NAMESPACE =
    "github.com/example/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NONCE_A = "a".repeat(64);
const NONCE_B = "b".repeat(64);

beforeEach(() => {
    __internals.activeAudits.clear();
});

function sha256(text) {
    return createHash("sha256").update(text, "utf8").digest("hex");
}

function decodedStage(auditId = AUDIT_ID, sourceNamespace = SOURCE_NAMESPACE) {
    let state = createInitialAssuranceStageState({ auditId, sourceNamespace });
    state = transitionAssuranceStageState(state, {
        auditId,
        sourceNamespace,
        from: "acquired",
        to: "inventoried",
    });
    return transitionAssuranceStageState(state, {
        auditId,
        sourceNamespace,
        from: "inventoried",
        to: "decoded",
    });
}

function objectFor({
    auditId = AUDIT_ID,
    sourceNamespace = SOURCE_NAMESPACE,
    path = "src/index.mjs",
    text = "export function start() { return 1; }\n",
    objectKind = "source-text",
    executable = false,
    gitMode = null,
} = {}) {
    return createEvasiveObjectInventoryRecord({
        auditId,
        sourceNamespace,
        path,
        parentObjectId: null,
        objectKind,
        byteLength: Buffer.byteLength(text),
        status: "inventoried",
        blockerCodes: [],
        contentSha256: sha256(text),
        upstreamSha: gitMode ? "c".repeat(40): null,
        gitObjectType: gitMode ? "blob": null,
        gitMode,
        parentUpstreamSha: gitMode ? "d".repeat(40): null,
        executable,
    });
}

function snapshotFor(object, {
    auditId = object.auditId,
    sourceNamespace = object.sourceNamespace,
} = {}) {
    const stageState = decodedStage(auditId, sourceNamespace);
    return createAssuranceAnalysisSnapshot({
        auditId,
        sourceNamespace,
        stageState,
        status: "incomplete",
        objectInventory: [object],
        derivedArtifacts: [],
        semanticReviewCoverage: [],
        redTeamCoverage: [],
        blockerCodes: [],
        sourceIdentitySha256: "e".repeat(64),
    });
}

function normalizedView(object, { promptAffected = false } = {}) {
    const metadataFacts = promptAffected
        ? [createPromptMetadataFact({
            kind: "prompt-fragment",
            tokens: ["ignore", "previous", "instructions"],
            evidence: {
                path: object.path,
                startLine: 1,
                endLine: 1,
                excerptHash: "2".repeat(64),
            },
        })]: [];
    return detectPromptLikeSource({
        object,
        detectorId: "semantic-prompt-detector",
        detectorVersion: "1.0.0",
        facts: [],
        metadataFacts,
    });
}

function checks(result = "checked") {
    return Object.fromEntries(
        SEMANTIC_CHECK_NAMES.map((name) => [name, result]),
    );
}

function noFindingsReview({
    assignment,
    plan,
    snapshot,
    scannerRecords,
    promptReviewRecord = null,
}) {
    return createSemanticReviewRecord({
        assignment,
        plan,
        snapshot,
        scannerRecords,
        assignmentToken: assignment.assignmentToken,
        reviewerId: assignment.reviewerId,
        objectId: assignment.objectId,
        artifactIds: assignment.artifactIds,
        semanticViewId: assignment.semanticView.semanticViewId,
        semanticViewSha256: assignment.semanticView.hashes.semanticViewSha256,
        reviewedFactIds: assignment.semanticView.facts.map((fact) => fact.id),
        reviewedArtifactIds: assignment.semanticView.derivedArtifacts
            .map((artifact) => artifact.artifactId),
        decision: "no-findings",
        checks: checks(),
        negativeEvidenceCodes: SEMANTIC_NEGATIVE_EVIDENCE_CODES,
        candidates: [],
        blockerCodes: [],
        promptReviewRecord,
    });
}

function semanticCandidateInput(assignment, overrides = {}) {
    const fact = assignment.semanticView.facts[0];
    const evidence = assignment.semanticView.evidence.find((entry) =>
        entry.factId === fact.id);
    return {
        behavior: {
            trigger: "runtime-start",
            capability: "module-access",
            action: "load-sensitive-capability",
            target: "local-host",
        },
        severity: "high",
        confidence: "high",
        maliciousProjectFit: "likely",
        benignHypothesisCode: "no-benign-hypothesis",
        objectIds: [assignment.objectId],
        artifactIds: [],
        factIds: [fact.id],
        evidenceIds: [evidence.evidenceId],
        ...overrides,
    };
}

function findingsReview({
    assignment,
    plan,
    snapshot,
    scannerRecords,
    candidates,
}) {
    return createSemanticReviewRecord({
        assignment,
        plan,
        snapshot,
        scannerRecords,
        assignmentToken: assignment.assignmentToken,
        reviewerId: assignment.reviewerId,
        objectId: assignment.objectId,
        artifactIds: assignment.artifactIds,
        semanticViewId: assignment.semanticView.semanticViewId,
        semanticViewSha256: assignment.semanticView.hashes.semanticViewSha256,
        reviewedFactIds: assignment.semanticView.facts.map((fact) => fact.id),
        reviewedArtifactIds: assignment.semanticView.derivedArtifacts
            .map((artifact) => artifact.artifactId),
        decision: "findings-recorded",
        checks: checks(),
        negativeEvidenceCodes: [],
        candidates,
        blockerCodes: [],
        promptReviewRecord: null,
    });
}

test("assurance objects receive one of the exhaustive semantic classes", () => {
    const cases = [
        ["src/index.mjs", "source-text", "executable-source"],
        ["package.json", "manifest", "build-config"],
        [".github/workflows/release.yml", "source-text", "workflow"],
        ["templates/client.mustache", "source-text", "generated-input"],
        ["package-lock.json", "dependency-metadata", "dependency-metadata"],
        ["payload.zip", "archive", "binary-archive"],
        ["README.md", "source-text", "document-data"],
        ["vendor-link", "symlink", "unsupported"],
    ];
    for (const [path, objectKind, expected] of cases) {
        const text = objectKind === "symlink" ? "target": "content";
        const object = objectKind === "symlink"
            ? createEvasiveObjectInventoryRecord({
                auditId: AUDIT_ID,
                sourceNamespace: SOURCE_NAMESPACE,
                path,
                parentObjectId: null,
                objectKind,
                byteLength: text.length,
                status: "inventoried",
                blockerCodes: [],
                contentSha256: sha256(text),
                upstreamSha: "3".repeat(40),
                gitObjectType: "blob",
                gitMode: "120000",
                parentUpstreamSha: "4".repeat(40),
                executable: false,
                symlinkTarget: {
                    targetSha256: sha256(text),
                    kind: "relative",
                    byteLength: text.length,
                },
            }): objectFor({ path, text, objectKind });
        assert.equal(
            classifyObjectForSemanticCoverage(object).semanticClass,
            expected,
        );
    }
});

test("scanner and one wrapper-issued review cover ordinary executable source", () => {
    const text = "import fs from \"node:fs\"; export function start() { return fs.constants.F_OK; }\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
        scannerShardCount: 4,
        modelShardCount: 4,
    });
    assert.equal(plan.classifications[0].requiredReviewerCount, 1);
    assert.equal(plan.scannerAssignments.length, 1);

    const scannerResult = scanSourceText({ path: object.path, text });
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult,
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    assert.ok(assignment.semanticView.substantive);
    assert.ok(assignment.semanticView.facts.length > 0);
    assert.deepEqual(
        Object.keys(assignment.semanticView.checks),
        SEMANTIC_CHECK_NAMES,
    );
    const review = noFindingsReview({
        assignment,
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
    });
    const evaluation = evaluateSemanticCoverage({
        snapshot,
        plan,
        scannerRecords: [scannerRecord],
        reviewAssignments: [assignment],
        reviewRecords: [review, review],
    });
    assert.equal(evaluation.complete, true);
    assert.equal(evaluation.counts.completedReviews, 1);
    assert.deepEqual(evaluation.blockerCodes, []);
});

test("semantic assignment validation rejects semanticView tampering", () => {
    const text = "import fs from \"node:fs\"; export const mode = fs.constants.F_OK;\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
    });
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult: scanSourceText({ path: object.path, text }),
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    const tampered = {
        ...assignment,
        semanticView: {
            ...assignment.semanticView,
            facts: [],
        },
    };
    assert.throws(() => validateSemanticReviewAssignment(tampered, {
            plan,
            snapshot,
            scannerRecords: [scannerRecord],
        }),
        /deterministic scanner-derived semantic view|wrapper-issued semantic assignment/,
    );
});

test("structured semantic candidates enter an immutable severity-faithful ledger", () => {
    const text = "import fs from \"node:fs\"; export const mode = fs.constants.F_OK;\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
    });
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult: scanSourceText({ path: object.path, text }),
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    const review = findingsReview({
        assignment,
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        candidates: [semanticCandidateInput(assignment, {
            severity: "critical",
        })],
    });
    assert.match(review.candidates[0].candidateId, /^ztsf-/);
    assert.equal(review.candidates[0].severity, "critical");
    const evaluation = evaluateSemanticCoverage({
        snapshot,
        plan,
        scannerRecords: [scannerRecord],
        reviewAssignments: [assignment, assignment],
        reviewRecords: [review, review],
    });
    assert.equal(evaluation.candidateLedger.length, 1);
    assert.equal(evaluation.candidateLedger[0].severity, "critical");
    const coveredStage = transitionAssuranceStageState(snapshot.stageState, {
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        from: "decoded",
        to: "semantically-covered",
    });
    const coveredSnapshot = applySemanticCoverageToSnapshot({
        snapshot,
        evaluation,
        stageState: coveredStage,
    });
    assert.deepEqual(
        coveredSnapshot.semanticCandidateLedger,
        evaluation.candidateLedger,
    );
});

test("semantic candidate tampering and duplicate candidate identities are rejected", () => {
    const text = "import fs from \"node:fs\"; export const mode = fs.constants.F_OK;\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
    });
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult: scanSourceText({ path: object.path, text }),
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    const candidate = semanticCandidateInput(assignment);
    const review = findingsReview({
        assignment,
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        candidates: [candidate],
    });
    const tampered = {
        ...review,
        candidates: [{
            ...review.candidates[0],
            severity: "info",
        }],
    };
    assert.throws(() => validateSemanticReviewRecord(tampered, {
            assignment,
            plan,
            snapshot,
            scannerRecords: [scannerRecord],
        }),
        /candidate identity|deterministic assurance identity|immutable semantic review record/,
    );
    assert.throws(() => findingsReview({
            assignment,
            plan,
            snapshot,
            scannerRecords: [scannerRecord],
            candidates: [candidate, candidate],
        }),
        /duplicate candidates/,
    );
});

test("semantic candidates cannot cite identities outside the assignment", () => {
    const text = "import fs from \"node:fs\"; export const mode = fs.constants.F_OK;\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
    });
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult: scanSourceText({ path: object.path, text }),
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    assert.throws(() => findingsReview({
            assignment,
            plan,
            snapshot,
            scannerRecords: [scannerRecord],
            candidates: [semanticCandidateInput(assignment, {
                factIds: ["f".repeat(64)],
            })],
        }),
        /fact outside the assignment|does not evidence fact/,
    );
});

test("unresolved scanner semantics prevent no-findings and comprehensive coverage", () => {
    const text =
        "const moduleName = process.env.MODULE_NAME; export async function start() { return import(moduleName); }\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
    });
    const scannerResult = scanSourceText({ path: object.path, text });
    assert.ok(scannerResult.facts.some((fact) =>
        fact.kind === "unresolved-dynamic-target"));
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult,
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    assert.equal(assignment.semanticView.complete, false);
    assert.ok(assignment.semanticView.unresolvedDynamicFactIds.length > 0);
    assert.throws(() => noFindingsReview({
            assignment,
            plan,
            snapshot,
            scannerRecords: [scannerRecord],
        }),
        /incomplete semantic view/,
    );
    const evaluation = evaluateSemanticCoverage({
        snapshot,
        plan,
        scannerRecords: [scannerRecord],
        reviewAssignments: [assignment],
        reviewRecords: [],
    });
    assert.equal(evaluation.complete, false);
    assert.ok(evaluation.blockerCodes.includes(EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE));
});

test("empty semantic views cannot satisfy executable or config review", () => {
    const text = "export const ready = true;\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
    });
    const scannerResult = scanSourceText({ path: object.path, text });
    assert.equal(scannerResult.factCount, 0);
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult,
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    assert.equal(assignment.semanticView.substantive, false);
    assert.throws(() => noFindingsReview({
            assignment,
            plan,
            snapshot,
            scannerRecords: [scannerRecord],
        }),
        /incomplete semantic view/,
    );
});

test("high-risk workflow coverage requires two independent reviewers", () => {
    const text = "name: release\non: push\njobs: {}\n";
    const object = objectFor({
        path: ".github/workflows/release.yml",
        text,
    });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
    });
    assert.equal(plan.classifications[0].highRisk, true);
    assert.equal(plan.classifications[0].requiredReviewerCount, 2);

    const scannerResult = scanSourceText({ path: object.path, text });
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult,
    });
    const first = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    const firstReview = noFindingsReview({
        assignment: first,
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
    });
    const partial = evaluateSemanticCoverage({
        snapshot,
        plan,
        scannerRecords: [scannerRecord],
        reviewAssignments: [first],
        reviewRecords: [firstReview, firstReview],
    });
    assert.equal(partial.complete, false);
    assert.ok(partial.blockerCodes.includes(EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE));

    const second = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 2,
        reviewerId: "semantic-reviewer-b",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_B,
    });
    const secondReview = noFindingsReview({
        assignment: second,
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
    });
    const complete = evaluateSemanticCoverage({
        snapshot,
        plan,
        scannerRecords: [scannerRecord],
        reviewAssignments: [first, second],
        reviewRecords: [firstReview, secondReview],
    });
    assert.equal(complete.complete, true);
});

test("empty findings require exact checks and negative-evidence codes", () => {
    const text = "import fs from \"node:fs\"; export function start() { return fs.constants.F_OK; }\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object)],
    });
    const scannerResult = scanSourceText({ path: object.path, text });
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult,
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    assert.throws(() => createSemanticReviewRecord({
            assignment,
            plan,
            snapshot,
            scannerRecords: [scannerRecord],
            assignmentToken: assignment.assignmentToken,
            reviewerId: assignment.reviewerId,
            objectId: assignment.objectId,
            artifactIds: assignment.artifactIds,
            semanticViewId: assignment.semanticView.semanticViewId,
            semanticViewSha256:
                assignment.semanticView.hashes.semanticViewSha256,
            reviewedFactIds: assignment.semanticView.facts.map((fact) => fact.id),
            reviewedArtifactIds: assignment.semanticView.derivedArtifacts
                .map((artifact) => artifact.artifactId),
            decision: "no-findings",
            checks: checks(),
            negativeEvidenceCodes: SEMANTIC_NEGATIVE_EVIDENCE_CODES.slice(1),
            candidates: [],
            blockerCodes: [],
        }),
        /exact bounded negative-evidence set/,
    );
});

test("prompt-affected semantic reviews require the normalized-view contract", () => {
    const text = "import fs from \"node:fs\"; export function start() { return fs.constants.F_OK; }\n";
    const object = objectFor({ text });
    const snapshot = snapshotFor(object);
    const plan = createSemanticCoveragePlan({
        snapshot,
        normalizedViews: [normalizedView(object, { promptAffected: true })],
    });
    const scannerRecord = createSemanticScannerCoverageRecord({
        plan,
        snapshot,
        assignmentId: plan.scannerAssignments[0].assignmentId,
        assignmentToken: plan.scannerAssignments[0].assignmentToken,
        scannerResult: scanSourceText({ path: object.path, text }),
    });
    const assignment = createSemanticReviewAssignment({
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
        assignmentNonceSha256: NONCE_A,
    });
    assert.ok(assignment.promptAssignment);
    assert.throws(() => noFindingsReview({
            assignment,
            plan,
            snapshot,
            scannerRecords: [scannerRecord],
        }),
        /promptReviewRecord.*required/,
    );
    const promptAssignment = assignment.promptAssignment;
    const promptReviewRecord = createPromptReviewRecord({
        assignment: promptAssignment,
        reviewerId: promptAssignment.reviewerId,
        assignmentToken: promptAssignment.assignmentToken,
        reviewMode: PROMPT_REVIEW_MODE,
        decision: "no-manipulation-supported",
        reviewedSignalIds: promptAssignment.normalizedView.signals
            .map((signal) => signal.signalId),
        factIds: promptAssignment.normalizedView.facts.map((fact) => fact.factId),
        evidenceIds: promptAssignment.normalizedView.evidence
            .map((evidence) => evidence.evidenceId),
        blockerCodes: [],
        canaryMarker: PROMPT_REVIEW_CANARY_MARKER,
        outputContractMarker: PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER,
    });
    const review = createSemanticReviewRecord({
        assignment,
        plan,
        snapshot,
        scannerRecords: [scannerRecord],
        assignmentToken: assignment.assignmentToken,
        reviewerId: assignment.reviewerId,
        objectId: assignment.objectId,
        artifactIds: assignment.artifactIds,
        semanticViewId: assignment.semanticView.semanticViewId,
        semanticViewSha256: assignment.semanticView.hashes.semanticViewSha256,
        reviewedFactIds: assignment.semanticView.facts.map((fact) => fact.id),
        reviewedArtifactIds: assignment.semanticView.derivedArtifacts
            .map((artifact) => artifact.artifactId),
        decision: "no-findings",
        checks: checks(),
        negativeEvidenceCodes: SEMANTIC_NEGATIVE_EVIDENCE_CODES,
        candidates: [],
        blockerCodes: [],
        promptReviewRecord,
    });
    assert.equal(review.promptReviewRecord.reviewId, promptReviewRecord.reviewId);
});

test("enforcement advances decoded only through complete semantic coverage", () => {
    const sessionId = "assurance-semantic-enforcement";
    const buildRoot = process.cwd();
    const expectedClonePath = process.platform === "win32"
        ? `${buildRoot}\\zt-semantic`: `${buildRoot}/zt-semantic`;
    const auditId = activateAudit({
        sessionId,
        buildPath: buildRoot,
        expectedClonePath,
        mode: "metadata_only",
        owner: "example",
        repo: "repo",
    });
    advanceAssuranceStage(sessionId, {
        auditId,
        from: "acquired",
        to: "inventoried",
    });
    advanceAssuranceStage(sessionId, {
        auditId,
        from: "inventoried",
        to: "decoded",
    });
    const state = getAssuranceState(sessionId, { auditId });
    const text = "import fs from \"node:fs\"; export const ready = fs.constants.F_OK;\n";
    const object = objectFor({
        auditId,
        sourceNamespace: state.sourceNamespace,
        text,
    });
    const snapshot = snapshotFor(object, {
        auditId,
        sourceNamespace: state.sourceNamespace,
    });
    recordAssuranceSnapshot(sessionId, { auditId, snapshot });
    assert.throws(() => advanceAssuranceStage(sessionId, {
            auditId,
            from: "decoded",
            to: "semantically-covered",
        }),
        /owned by complete assurance semantic coverage/,
    );

    const prepared = prepareSemanticCoverage(sessionId, {
        auditId,
        normalizedViews: [normalizedView(object)],
    });
    const scannerAssignment = prepared.semanticCoveragePlan.scannerAssignments[0];
    recordSemanticScannerCoverage(sessionId, {
        auditId,
        assignmentId: scannerAssignment.assignmentId,
        assignmentToken: scannerAssignment.assignmentToken,
        scannerResult: scanSourceText({ path: object.path, text }),
    });
    const assignment = issueSemanticReviewAssignment(sessionId, {
        auditId,
        objectId: object.objectId,
        reviewerSlot: 1,
        reviewerId: "semantic-reviewer-a",
        reviewerVersion: "1.0.0",
    });
    recordSemanticReview(sessionId, {
        auditId,
        assignmentId: assignment.assignmentId,
        assignmentToken: assignment.assignmentToken,
        reviewerId: assignment.reviewerId,
        objectId: assignment.objectId,
        artifactIds: assignment.artifactIds,
        semanticViewId: assignment.semanticView.semanticViewId,
        semanticViewSha256: assignment.semanticView.hashes.semanticViewSha256,
        reviewedFactIds: assignment.semanticView.facts.map((fact) => fact.id),
        reviewedArtifactIds: assignment.semanticView.derivedArtifacts
            .map((artifact) => artifact.artifactId),
        decision: "no-findings",
        checks: checks(),
        negativeEvidenceCodes: SEMANTIC_NEGATIVE_EVIDENCE_CODES,
        candidates: [],
        blockerCodes: [],
    });
    assert.equal(
        getAssuranceState(sessionId, { auditId }).stageState.current,
        "semantically-covered",
    );
});
