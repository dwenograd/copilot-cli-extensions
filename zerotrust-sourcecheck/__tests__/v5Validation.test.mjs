import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
    __internals as enforcementInternals,
    activateAudit,
    getAnalysisStageState,
    maybeAdvanceAnalysisPrepared,
    mutateAnalysisIndexState,
} from "../enforcement.mjs";
import {
    recordIndexEnumeration,
    recordIndexedFile,
} from "../analysis/indexState.mjs";
import { recordCouncilCandidatesHandler } from "../safeWrappers/findingLedgerWrapper.mjs";
import { recordOutcomeHandler } from "../safeWrappers/outcomeWrapper.mjs";
import { traceBehaviorGraphHandler } from "../safeWrappers/traceWrapper.mjs";
import {
    recordValidationHandler,
} from "../safeWrappers/validationWrapper.mjs";
import { __internals as stateInternals } from "../safeWrappers/state.mjs";
import {
    renderConfirmValidatorPrompt,
    renderRefuteValidatorPrompt,
    renderValidationAdjudicationPrompt,
} from "../council/validationPromptTemplate.mjs";

const SESSION = "v5-validation-session";
const BUILD_ROOT = process.cwd();
const LOCAL_PATH = process.platform === "win32"
    ? "C:\\projects\\v5-validation"
    : "/srv/v5-validation";
const FILE_PATH = "src/loader.mjs";
const CONTENT_SHA = "c".repeat(64);
const EXCERPT_HASH = "e".repeat(64);
const ROLE = Object.freeze({
    id: "validation-role",
    category: "A",
    mandatory: true,
});
const FACT_ID = createHash("sha256")
    .update(`sink-hint\0${FILE_PATH}\0${10}\0process-execution\0`)
    .digest("hex");

function parse(result) {
    return JSON.parse(result.textResultForLlm);
}

function activate({
    sessionId = SESSION,
    validationMinSeverity = "high",
} = {}) {
    return activateAudit({
        sessionId,
        buildPath: BUILD_ROOT,
        mode: "audit_local_source_council",
        localPath: LOCAL_PATH,
        expectedReportPath: process.platform === "win32"
            ? `${BUILD_ROOT}\\_reports\\local-v5-validation-20260714010000`
            : `${BUILD_ROOT}/_reports/local-v5-validation-20260714010000`,
        councilRoleManifest: [ROLE],
        validationMinSeverity,
    });
}

function indexOneFile(sessionId = SESSION) {
    mutateAnalysisIndexState(sessionId, (state) => {
        recordIndexEnumeration(state, {
            entries: [{ path: FILE_PATH, size: 64, blobSha: null }],
            complete: true,
        });
        recordIndexedFile(state, {
            path: FILE_PATH,
            size: 64,
            classification: "text",
            classificationComplete: true,
            contentSha256: CONTENT_SHA,
            blobSha: null,
            lineCount: 100,
            invisibleUnicodeScanComplete: true,
            facts: [{
                id: FACT_ID,
                kind: "sink-hint",
                path: FILE_PATH,
                line: 10,
                endLine: 10,
                excerptHash: EXCERPT_HASH,
                name: "process-execution",
            }],
        });
    });
    assert.equal(maybeAdvanceAnalysisPrepared(sessionId).analysisStageState.current, "prepared");
}

function evidence() {
    return {
        path: FILE_PATH,
        startLine: 10,
        endLine: 10,
        blobSha: CONTENT_SHA,
        excerptHash: EXCERPT_HASH,
        producer: ROLE.id,
        coverageScope: "local_source",
    };
}

function candidate(auditId, severity = "high") {
    const activation = "validation-role.candidate-1.activation";
    const capability = "validation-role.candidate-1.capability";
    const effect = "validation-role.candidate-1.effect";
    const activates = "validation-role.candidate-1.activates";
    const flows = "validation-role.candidate-1.flows";
    return {
        finding: {
            schemaVersion: 5,
            auditId,
            sourceIdentity: {
                type: "local-file",
                namespace: `local-audit:${auditId}`,
                path: FILE_PATH,
                contentSha256: CONTENT_SHA,
                blobSha: CONTENT_SHA,
            },
            behaviorSignature: {
                trigger: "package-install",
                capability: "process-spawn",
                action: "execute",
                target: "shell",
            },
            title: "Install activation reaches a shell",
            summary: "The candidate graph links activation to an execution sink.",
            severity,
            confidence: "medium",
            maliciousProjectFit: "likely",
            state: "candidate",
            evidence: [evidence()],
            nodeIds: [activation, capability, effect],
            edgeIds: [activates, flows],
            producer: ROLE.id,
        },
        strongestBenignHypothesis: "This may be a documented development helper.",
        coveragePerformed: ["Reviewed indexed activation and sink facts."],
        graph: {
            nodes: [
                {
                    schemaVersion: 5,
                    auditId,
                    id: activation,
                    kind: "activation",
                    label: "package install",
                    producer: ROLE.id,
                    evidence: [],
                },
                {
                    schemaVersion: 5,
                    auditId,
                    id: capability,
                    kind: "capability",
                    label: "process spawn",
                    producer: ROLE.id,
                    evidence: [],
                },
                {
                    schemaVersion: 5,
                    auditId,
                    id: effect,
                    kind: "sink",
                    label: "shell",
                    producer: ROLE.id,
                    evidence: [],
                },
            ],
            edges: [
                {
                    schemaVersion: 5,
                    auditId,
                    id: activates,
                    kind: "activates",
                    from: activation,
                    to: capability,
                    producer: ROLE.id,
                    evidence: [],
                },
                {
                    schemaVersion: 5,
                    auditId,
                    id: flows,
                    kind: "flows-to",
                    from: capability,
                    to: effect,
                    producer: ROLE.id,
                    evidence: [],
                },
            ],
        },
    };
}

async function prepareTraced({
    sessionId = SESSION,
    severity = "high",
    validationMinSeverity = "high",
    withCandidate = true,
} = {}) {
    const auditId = activate({ sessionId, validationMinSeverity });
    indexOneFile(sessionId);
    const submitted = parse(await recordCouncilCandidatesHandler({
        action: "submit",
        schemaVersion: 5,
        audit_id: auditId,
        producer_role_id: ROLE.id,
        producer_category: ROLE.category,
        source_identity: { kind: "local", local_path: LOCAL_PATH },
        coverage_performed: ["Completed validation-role review."],
        coverage_skipped: [],
        candidates: withCandidate ? [candidate(auditId, severity)] : [],
    }, { sessionId }));
    assert.equal(submitted.ok, true, submitted.error);
    const finalized = parse(await recordCouncilCandidatesHandler({
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
        successful_role_ids: [ROLE.id],
        failed_role_ids: [],
        deterministic_baseline_complete: true,
    }, { sessionId }));
    assert.equal(finalized.ok, true, finalized.error);
    const traced = parse(await traceBehaviorGraphHandler({
        audit_id: auditId,
    }, { sessionId }));
    assert.equal(traced.ok, true, traced.error);
    assert.equal(traced.analysisStageAfter, "traced");
    return { auditId, traced };
}

async function prepareValidation(auditId, sessionId = SESSION) {
    const prepared = parse(await recordValidationHandler({
        action: "prepare",
        schemaVersion: 5,
        audit_id: auditId,
        cursor: 0,
        limit: 8,
    }, { sessionId }));
    assert.equal(prepared.ok, true, prepared.error);
    return prepared;
}

function chainReferences(context) {
    const chain = context.chains.find((entry) => entry.status === "complete");
    assert.ok(chain);
    return {
        chain,
        chainIds: [chain.id],
        nodeIds: [...new Set(chain.steps.flatMap((step) => step.nodeIds))],
        edgeIds: [...new Set(chain.links.flatMap((link) => link.edgeIds))],
    };
}

function confirmArgs(auditId, context, conclusion = "confirmed") {
    const refs = chainReferences(context);
    return {
        action: "submit",
        schemaVersion: 5,
        audit_id: auditId,
        finding_id: context.finding.id,
        validator_id: "confirm-validator",
        decision_type: "confirm",
        conclusion,
        chain_ids: conclusion === "confirmed" ? refs.chainIds : [],
        node_ids: conclusion === "confirmed" ? refs.nodeIds : [],
        edge_ids: conclusion === "confirmed" ? refs.edgeIds : [],
        evidence: [context.allowedEvidence[0]],
        rationale_code: conclusion === "confirmed"
            ? "complete-reachable-chain"
            : "activation-not-established",
        rationale: conclusion === "confirmed"
            ? "The existing complete chain establishes activation and effect reachability."
            : "The supplied context does not establish concrete activation reachability.",
        checks: {
            activationReachable: conclusion === "confirmed",
            effectReachable: conclusion === "confirmed",
            sourceToEffectPath: conclusion === "confirmed",
            gatingConsidered: true,
            brokenEdgesConsidered: true,
        },
    };
}

function refuteArgs(auditId, context, conclusion = "not-refuted") {
    const supports = conclusion === "refuted";
    return {
        action: "submit",
        schemaVersion: 5,
        audit_id: auditId,
        finding_id: context.finding.id,
        validator_id: "refute-validator",
        decision_type: "refute",
        conclusion,
        chain_ids: [],
        node_ids: [],
        edge_ids: [],
        evidence: [context.allowedEvidence[0]],
        rationale_code: supports ? "dead-code-refutation" : "no-refutation-established",
        rationale: supports
            ? "The activation is unreachable in the legitimate project configuration."
            : "None of the six required alternatives refutes the existing chain.",
        checks: {
            deadOrUnreachableCode: supports
                ? "supports-refutation"
                : "does-not-refute",
            docsOrTestsOnlyContext: "does-not-refute",
            activationGating: "does-not-refute",
            sanitizationOrNeutralization: "does-not-refute",
            brokenGraphEdges: "does-not-refute",
            legitimateProjectFit: "does-not-refute",
        },
    };
}

function adjudicateArgs(auditId, context, {
    decision,
    confidence = "high",
    chainIds = [],
    nodeIds = [],
    edgeIds = [],
} = {}) {
    return {
        action: "adjudicate",
        schemaVersion: 5,
        audit_id: auditId,
        finding_id: context.finding.id,
        adjudicator_id: "validation-adjudicator",
        decision,
        severity: decision === "refuted" ? "low" : context.finding.severity,
        confidence,
        malicious_project_fit: decision === "refuted" ? "unlikely" : "likely",
        rationale_code: `${decision}-after-two-sided-review`,
        rationale: "The terminal state follows the two independent static decisions.",
        chain_ids: chainIds,
        node_ids: nodeIds,
        edge_ids: edgeIds,
        evidence: [context.allowedEvidence[0]],
    };
}

beforeEach(() => {
    enforcementInternals.activeAudits.clear();
    stateInternals.councilLedgers.clear();
    stateInternals.recordedOutcomes.clear();
});

test("confirmed chain receives two decisions, adjudicates validated, and advances stage", async () => {
    const { auditId } = await prepareTraced();
    const prepared = await prepareValidation(auditId);
    assert.equal(prepared.page.total, 1);
    const context = prepared.page.contexts[0];
    assert.equal(context.finding.state, "validating");
    assert.equal(context.truncated, false);
    const refs = chainReferences(context);

    assert.equal(parse(await recordValidationHandler(
        confirmArgs(auditId, context),
        { sessionId: SESSION },
    )).ok, true);
    assert.equal(parse(await recordValidationHandler(
        refuteArgs(auditId, context),
        { sessionId: SESSION },
    )).ok, true);
    const adjudicated = parse(await recordValidationHandler(adjudicateArgs(
        auditId,
        context,
        {
            decision: "validated",
            chainIds: refs.chainIds,
            nodeIds: refs.nodeIds,
            edgeIds: refs.edgeIds,
        },
    ), { sessionId: SESSION }));
    assert.equal(adjudicated.ok, true, adjudicated.error);
    const finalized = parse(await recordValidationHandler({
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
    }, { sessionId: SESSION }));
    assert.equal(finalized.ok, true, finalized.error);
    assert.equal(finalized.analysisStageAfter, "validated");
    assert.equal(finalized.validation.completion.complete, true);
    assert.equal(finalized.decisionSnapshot.auditId, auditId);
    assert.equal(
        finalized.decisionSnapshot.overallVerdictEligibility.recommendedVerdict,
        "high",
    );
    assert.equal(
        finalized.decisionSnapshot.overallVerdictEligibility.trustedDecisionEligible,
        true,
    );
    assert.equal(finalized.decisionSnapshot.severityCounts.active.high, 1);
    assert.equal(finalized.remediation.auditId, auditId);
    assert.equal(finalized.remediation.candidates.length, 1);
    assert.equal(
        finalized.remediation.candidates[0].staticVerification.fixClaimAllowed,
        true,
    );
    assert.equal(getAnalysisStageState(SESSION).current, "validated");
    const retriedFinalization = parse(await recordValidationHandler({
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
    }, { sessionId: SESSION }));
    assert.equal(retriedFinalization.ok, true, retriedFinalization.error);
    assert.equal(retriedFinalization.idempotent, true);
    assert.equal(
        retriedFinalization.decisionSnapshot.decisionId,
        finalized.decisionSnapshot.decisionId,
    );
    assert.equal(retriedFinalization.remediation.id, finalized.remediation.id);

    const outcome = parse(await recordOutcomeHandler({
        audit_id: auditId,
        verdict: "high",
        critical_count: 0,
        high_count: 1,
        complete: true,
    }, { sessionId: SESSION }));
    assert.equal(outcome.ok, true, outcome.error);
});

test("strong static refutation produces a refuted terminal finding", async () => {
    const { auditId } = await prepareTraced();
    const context = (await prepareValidation(auditId)).page.contexts[0];
    assert.equal(parse(await recordValidationHandler(
        confirmArgs(auditId, context, "not-confirmed"),
        { sessionId: SESSION },
    )).ok, true);
    assert.equal(parse(await recordValidationHandler(
        refuteArgs(auditId, context, "refuted"),
        { sessionId: SESSION },
    )).ok, true);
    const adjudicated = parse(await recordValidationHandler(adjudicateArgs(
        auditId,
        context,
        { decision: "refuted" },
    ), { sessionId: SESSION }));
    assert.equal(adjudicated.ok, true, adjudicated.error);
    assert.equal(adjudicated.adjudication.decision, "refuted");
});

test("confirm/refute disagreement is unresolved and confidence-lowered", async () => {
    const { auditId } = await prepareTraced();
    const context = (await prepareValidation(auditId)).page.contexts[0];
    const refs = chainReferences(context);
    await recordValidationHandler(confirmArgs(auditId, context), { sessionId: SESSION });
    await recordValidationHandler(
        refuteArgs(auditId, context, "refuted"),
        { sessionId: SESSION },
    );
    const invalid = parse(await recordValidationHandler(adjudicateArgs(
        auditId,
        context,
        {
            decision: "validated",
            chainIds: refs.chainIds,
            nodeIds: refs.nodeIds,
            edgeIds: refs.edgeIds,
        },
    ), { sessionId: SESSION }));
    assert.equal(invalid.ok, false);
    assert.match(invalid.error, /expected unresolved/);

    const unresolved = parse(await recordValidationHandler(adjudicateArgs(
        auditId,
        context,
        {
            decision: "unresolved",
            confidence: "low",
            chainIds: refs.chainIds,
            nodeIds: refs.nodeIds,
            edgeIds: refs.edgeIds,
        },
    ), { sessionId: SESSION }));
    assert.equal(unresolved.ok, true, unresolved.error);
});

test("missing validation side blocks adjudication and finalization without deleting candidate", async () => {
    const { auditId } = await prepareTraced();
    const context = (await prepareValidation(auditId)).page.contexts[0];
    await recordValidationHandler(confirmArgs(auditId, context), { sessionId: SESSION });
    const adjudicated = parse(await recordValidationHandler(adjudicateArgs(
        auditId,
        context,
        { decision: "unresolved", confidence: "low" },
    ), { sessionId: SESSION }));
    assert.equal(adjudicated.ok, false);
    assert.match(adjudicated.error, /requires both confirm and refute/);
    const finalized = parse(await recordValidationHandler({
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
    }, { sessionId: SESSION }));
    assert.equal(finalized.ok, false);
    assert.match(finalized.error, /refute=0\/1/);
    assert.equal(getAnalysisStageState(SESSION).current, "traced");
});

test("identical validation retries are idempotent and changed retries are rejected", async () => {
    const { auditId } = await prepareTraced();
    const context = (await prepareValidation(auditId)).page.contexts[0];
    const decision = confirmArgs(auditId, context);
    const first = parse(await recordValidationHandler(decision, { sessionId: SESSION }));
    const retry = parse(await recordValidationHandler(
        structuredClone(decision),
        { sessionId: SESSION },
    ));
    assert.equal(first.idempotent, false);
    assert.equal(retry.idempotent, true);
    const changed = structuredClone(decision);
    changed.rationale = "Changed immutable rationale.";
    const conflict = parse(await recordValidationHandler(changed, { sessionId: SESSION }));
    assert.equal(conflict.ok, false);
    assert.match(conflict.error, /immutable after first submission/);
});

test("validation and adjudication reject evidence injection", async () => {
    const { auditId } = await prepareTraced();
    const context = (await prepareValidation(auditId)).page.contexts[0];
    const injected = confirmArgs(auditId, context);
    injected.evidence[0] = {
        ...injected.evidence[0],
        sourceText: "not allowed",
    };
    assert.match(
        parse(await recordValidationHandler(injected, { sessionId: SESSION })).error,
        /unknown field/,
    );

    await recordValidationHandler(confirmArgs(auditId, context), { sessionId: SESSION });
    await recordValidationHandler(refuteArgs(auditId, context), { sessionId: SESSION });
    const adjudication = adjudicateArgs(auditId, context, { decision: "validated" });
    adjudication.evidence[0] = {
        ...adjudication.evidence[0],
        excerptHash: "f".repeat(64),
    };
    const rejected = parse(await recordValidationHandler(
        adjudication,
        { sessionId: SESSION },
    ));
    assert.equal(rejected.ok, false);
    assert.match(rejected.error, /introduces evidence/);
});

test("incomplete graph/stage and validation caps fail closed", async () => {
    const auditId = activate();
    indexOneFile();
    await recordCouncilCandidatesHandler({
        action: "submit",
        schemaVersion: 5,
        audit_id: auditId,
        producer_role_id: ROLE.id,
        producer_category: ROLE.category,
        source_identity: { kind: "local", local_path: LOCAL_PATH },
        coverage_performed: ["Completed validation-role review."],
        coverage_skipped: [],
        candidates: [candidate(auditId)],
    }, { sessionId: SESSION });
    await recordCouncilCandidatesHandler({
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
        successful_role_ids: [ROLE.id],
        failed_role_ids: [],
        deterministic_baseline_complete: true,
    }, { sessionId: SESSION });
    const early = parse(await recordValidationHandler({
        action: "prepare",
        schemaVersion: 5,
        audit_id: auditId,
        cursor: 0,
        limit: 8,
    }, { sessionId: SESSION }));
    assert.equal(early.ok, false);
    assert.match(early.error, /stage traced/);

    await traceBehaviorGraphHandler({ audit_id: auditId }, { sessionId: SESSION });
    const cap = parse(await recordValidationHandler({
        action: "prepare",
        schemaVersion: 5,
        audit_id: auditId,
        cursor: 0,
        limit: 9,
    }, { sessionId: SESSION }));
    assert.equal(cap.ok, false);
    assert.match(cap.error, /between 1 and 8/);

    const oversized = parse(await recordValidationHandler({
        action: "submit",
        schemaVersion: 5,
        audit_id: auditId,
        finding_id: `ztf-v5-${"a".repeat(64)}`,
        validator_id: "confirm-validator",
        decision_type: "confirm",
        conclusion: "unresolved",
        chain_ids: [],
        node_ids: [],
        edge_ids: [],
        evidence: [],
        rationale_code: "oversized",
        rationale: "x".repeat(70_000),
        checks: {
            activationReachable: false,
            effectReachable: false,
            sourceToEffectPath: false,
            gatingConsidered: true,
            brokenEdgesConsidered: true,
        },
    }, { sessionId: SESSION }));
    assert.equal(oversized.ok, false);
    assert.match(oversized.error, /serialized bytes/);
});

test("configured lower-severity candidates enter validation", async () => {
    const { auditId } = await prepareTraced({
        severity: "medium",
        validationMinSeverity: "medium",
    });
    const prepared = await prepareValidation(auditId);
    assert.equal(prepared.validation.minSeverity, "medium");
    assert.equal(prepared.page.total, 1);
    assert.equal(prepared.page.contexts[0].finding.severity, "medium");
});

test("zero-candidate validation completes and advances traced to validated", async () => {
    const sessionId = `${SESSION}-zero`;
    const { auditId } = await prepareTraced({
        sessionId,
        withCandidate: false,
    });
    const prepared = await prepareValidation(auditId, sessionId);
    assert.equal(prepared.page.total, 0);
    assert.equal(prepared.validation.completion.complete, true);
    const finalized = parse(await recordValidationHandler({
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
    }, { sessionId }));
    assert.equal(finalized.ok, true, finalized.error);
    assert.equal(finalized.analysisStageAfter, "validated");
    assert.equal(
        finalized.decisionSnapshot.overallVerdictEligibility.noRedFlagsEligible,
        true,
    );
});

test("validator and adjudicator prompts are static, source-text-free, and no-write", async () => {
    const { auditId } = await prepareTraced();
    const context = (await prepareValidation(auditId)).page.contexts[0];
    const confirm = renderConfirmValidatorPrompt({
        auditId,
        context,
        nonce: "confirm-nonce",
    });
    const refute = renderRefuteValidatorPrompt({
        auditId,
        context,
        nonce: "refute-nonce",
    });
    const adjudicate = renderValidationAdjudicationPrompt({
        auditId,
        context,
        confirmDecision: { decision_type: "confirm" },
        refuteDecision: { decision_type: "refute" },
        nonce: "adjudicate-nonce",
    });
    for (const prompt of [confirm, refute, adjudicate]) {
        assert.match(prompt, /call no tools/iu);
        assert.match(prompt, /write no files|write any file/iu);
        assert.match(prompt, /Do not quote|source snippets/iu);
        assert.doesNotMatch(prompt, /powershell|bash|proof-of-concept file/iu);
    }
    assert.match(confirm, /source-to-effect/iu);
    assert.match(refute, /dead\/unreachable code/iu);
    assert.match(refute, /sanitization\/neutralization/iu);
    assert.match(adjudicate, /cannot introduce.*source evidence/isu);
});

test("extension registers the audit-bound validation tool and configurable floor", () => {
    const source = readFileSync(
        new URL("../extension.mjs", import.meta.url),
        "utf8",
    );
    assert.match(source, /name:\s*"zerotrust_record_validation"/u);
    assert.match(source, /\brecordValidationHandler\b/u);
    assert.match(source, /validation_min_severity/u);
    assert.match(source, /independent static confirm\/refute\/adjudication/u);
});
