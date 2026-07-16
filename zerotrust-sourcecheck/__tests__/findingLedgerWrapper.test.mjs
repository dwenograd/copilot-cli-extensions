import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
    activateAudit,
    __internals as enforcementInternals,
    getAcquisitionCoverageState,
    getAnalysisStageState,
    maybeAdvanceAnalysisPrepared,
    mutateAnalysisIndexState,
    recordAcquisitionCoverageState,
    recordResolvedClonePath,
    recordResolvedSha,
    recordTreeEnumerationState,
} from "../enforcement.mjs";
import {
    recordIndexEnumeration,
    recordIndexedFile,
} from "../analysis/indexState.mjs";
import { ROLES } from "../council/roster.mjs";
import {
    recordCouncilCandidatesHandler,
} from "../safeWrappers/findingLedgerWrapper.mjs";
import { recordOutcomeHandler } from "../safeWrappers/outcomeWrapper.mjs";
import { traceBehaviorGraphHandler } from "../safeWrappers/traceWrapper.mjs";
import { safeFetchFileHandler } from "../safeWrappers/safeFetchHandler.mjs";
import { __internals as apiClientInternals } from "../safeWrappers/apiClient.mjs";
import {
    createCoverageState,
    recordEnumeratedEntries,
} from "../safeWrappers/coverageAccounting.mjs";
import { __internals as stateInternals } from "../safeWrappers/state.mjs";

const SESSION = "finding-ledger-wrapper-session";
const LOCAL_PATH = process.platform === "win32"
    ? "C:\\projects\\council-ingestion": "/srv/council-ingestion";
const BUILD_ROOT = process.cwd();
const FILE_PATH = "src/loader.mjs";
const CONTENT_SHA = "c".repeat(64);
const GIT_BLOB_SHA = "b".repeat(40);
const EXCERPT_HASH = "e".repeat(64);
const FACT_ID = createHash("sha256")
    .update(`sink-hint\0${FILE_PATH}\0${10}\0process-execution\0`)
    .digest("hex");
const RESOLVED_SHA = "a".repeat(40);
const ROOT_TREE_SHA = "d".repeat(40);

function parse(result) {
    return JSON.parse(result.textResultForLlm);
}

function activateLocal(sessionId = SESSION) {
    return activateAudit({
        sessionId,
        buildPath: BUILD_ROOT,
        mode: "audit_local_source_council",
        localPath: LOCAL_PATH,
        expectedReportPath: process.platform === "win32"
            ? `${BUILD_ROOT}\\_reports\\local-council-ingestion-20260713230000`: `${BUILD_ROOT}/_reports/local-council-ingestion-20260713230000`,
        councilRoleManifest: ROLES.map((role) => ({
            id: role.id,
            category: role.category,
            mandatory: role.mandatory,
        })),
    });
}

function indexOneFile(sessionId, {
    blobSha = null,
    sourceKind = "local-source",
} = {}) {
    const result = mutateAnalysisIndexState(sessionId, (state) => {
        assert.equal(state.sourceKind, sourceKind);
        recordIndexEnumeration(state, {
            entries: [{ path: FILE_PATH, size: 64, blobSha }],
            complete: true,
        });
        recordIndexedFile(state, {
            path: FILE_PATH,
            size: 64,
            classification: "text",
            classificationComplete: true,
            contentSha256: CONTENT_SHA,
            blobSha,
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
    assert.equal(result.ok, true);
    const prepared = maybeAdvanceAnalysisPrepared(sessionId);
    assert.equal(prepared.analysisStageState.current, "prepared");
}

function evidence(roleId, blobSha = CONTENT_SHA, coverageScope = null) {
    return {
        path: FILE_PATH,
        startLine: 10,
        endLine: 10,
        blobSha,
        excerptHash: EXCERPT_HASH,
        producer: roleId,
        coverageScope: coverageScope
            || (blobSha.length === 40 ? "council_sample": "local_source"),
    };
}

function candidate(roleId, auditId, {
    nodePrefix = roleId,
    sourceType = "local-file",
    namespace = `local-audit:${auditId}`,
    blobSha = CONTENT_SHA,
    contentSha256 = CONTENT_SHA,
    path = FILE_PATH,
    excerptHash = EXCERPT_HASH,
    omitSourceBlobSha = false,
} = {}) {
    const activation = `${nodePrefix}.candidate-1.activation`;
    const capability = `${nodePrefix}.candidate-1.capability`;
    const effect = `${nodePrefix}.candidate-1.effect`;
    const firstEdge = `${nodePrefix}.candidate-1.activates`;
    const secondEdge = `${nodePrefix}.candidate-1.effects`;
    const ref = {
        ...evidence(
            roleId,
            blobSha,
            sourceType === "local-file" ? "local_source": "council_sample",
        ),
        path,
        excerptHash,
    };
    const sourceIdentity = {
        type: sourceType,
        namespace,
        path,
        contentSha256,
    };
    if (!omitSourceBlobSha) sourceIdentity.blobSha = blobSha;
    return {
        finding: {
            schemaVersion: 5,
            auditId,
            sourceIdentity,
            behaviorSignature: {
                trigger: "package-install",
                capability: "process-spawn",
                action: "execute",
                target: "shell",
            },
            title: "Install activation reaches a shell capability",
            summary: "The indexed activation and execution facts form a candidate chain.",
            severity: "high",
            confidence: "medium",
            maliciousProjectFit: "likely",
            state: "candidate",
            evidence: [ref],
            nodeIds: [activation, capability, effect],
            edgeIds: [firstEdge, secondEdge],
            producer: roleId,
            tags: ["process-spawn"],
        },
        strongestBenignHypothesis:
            "The process launch may be a documented developer convenience rather than a payload.",
        coveragePerformed: ["Inspected indexed install activation and process-execution facts."],
        graph: {
            nodes: [
                {
                    schemaVersion: 5,
                    auditId,
                    id: activation,
                    kind: "activation",
                    label: "package install activation",
                    producer: roleId,
                    evidence: [],
                },
                {
                    schemaVersion: 5,
                    auditId,
                    id: capability,
                    kind: "capability",
                    label: "process spawn capability",
                    producer: roleId,
                    evidence: [],
                },
                {
                    schemaVersion: 5,
                    auditId,
                    id: effect,
                    kind: "sink",
                    label: "shell execution target",
                    producer: roleId,
                    evidence: [],
                },
            ],
            edges: [
                {
                    schemaVersion: 5,
                    auditId,
                    id: firstEdge,
                    kind: "activates",
                    from: activation,
                    to: capability,
                    producer: roleId,
                    evidence: [],
                },
                {
                    schemaVersion: 5,
                    auditId,
                    id: secondEdge,
                    kind: "flows-to",
                    from: capability,
                    to: effect,
                    producer: roleId,
                    evidence: [],
                },
            ],
        },
    };
}

function localSubmit(auditId, role = ROLES[0], candidates = [candidate(role.id, auditId)]) {
    return {
        action: "submit",
        schemaVersion: 5,
        audit_id: auditId,
        producer_role_id: role.id,
        producer_category: role.category,
        source_identity: {
            kind: "local",
            local_path: LOCAL_PATH,
        },
        coverage_performed: [`Completed ${role.id} indexed review.`],
        coverage_skipped: [],
        candidates,
    };
}

async function call(args, sessionId = SESSION) {
    return recordCouncilCandidatesHandler(args, { sessionId });
}

beforeEach(() => {
    enforcementInternals.activeAudits.clear();
    stateInternals.recordedOutcomes.clear();
    stateInternals.councilLedgers.clear();
});

test("records a bounded structured candidate and connected behavior graph", async () => {
    const auditId = activateLocal();
    indexOneFile(SESSION);
    const body = parse(await call(localSubmit(auditId)));
    assert.equal(body.ok, true);
    assert.equal(body.recorded, true);
    assert.equal(body.candidate_count, 1);
    assert.equal(body.total_findings, 1);
    assert.equal(body.total_graph_nodes, 3);
    assert.equal(body.total_graph_edges, 2);
    assert.equal(body.mandatory_acquisition_satisfied_by_ingestion, false);
    assert.equal(getAnalysisStageState(SESSION).current, "prepared");
});

test("identical role retries are idempotent and changed batches are immutable", async () => {
    const auditId = activateLocal();
    indexOneFile(SESSION);
    const args = localSubmit(auditId);
    assert.equal(parse(await call(args)).idempotent, false);
    assert.equal(parse(await call(structuredClone(args))).idempotent, true);
    const changed = structuredClone(args);
    changed.coverage_performed = ["Changed coverage claim."];
    const rejected = parse(await call(changed));
    assert.equal(rejected.ok, false);
    assert.match(rejected.error, /different immutable candidate batch/);
});

test("enforces strict batch, candidate, graph, and prose bounds", async () => {
    const auditId = activateLocal();
    indexOneFile(SESSION);
    const tooMany = localSubmit(
        auditId,
        ROLES[0],
        Array.from({ length: 33 }, () => candidate(ROLES[0].id, auditId)),
    );
    assert.match(parse(await call(tooMany)).error, /at most 32/);

    const longHypothesis = localSubmit(auditId);
    longHypothesis.candidates[0].strongestBenignHypothesis = "x".repeat(2049);
    assert.match(parse(await call(longHypothesis)).error, /1-2048/);

    const tooFewNodes = localSubmit(auditId);
    tooFewNodes.candidates[0].graph.nodes.pop();
    assert.match(parse(await call(tooFewNodes)).error, /must contain 3-16/);
});

test("rejects unknown roles, category/identity mismatches, and pre-preparation submissions", async () => {
    const auditId = activateLocal();
    const early = parse(await call(localSubmit(auditId)));
    assert.equal(early.ok, false);
    assert.match(early.error, /expected prepared/);

    indexOneFile(SESSION);
    const unknown = localSubmit(auditId);
    unknown.producer_role_id = "unknown-role";
    assert.match(parse(await call(unknown)).error, /unknown council producer role/);

    const category = localSubmit(auditId);
    category.producer_category = "G";
    assert.match(parse(await call(category)).error, /producer category mismatch/);

    const identity = localSubmit(auditId);
    identity.source_identity.local_path = `${LOCAL_PATH}-other`;
    assert.match(parse(await call(identity)).error, /does not match the active audit/);
});

test("accepts an extra role only when it is bound into the active council manifest", async () => {
    const extraRole = { id: "custom-review", category: "G", mandatory: false };
    const auditId = activateAudit({
        sessionId: SESSION,
        buildPath: BUILD_ROOT,
        mode: "audit_local_source_council",
        localPath: LOCAL_PATH,
        expectedReportPath: nodePathForTest("_reports/local-custom-20260713230000"),
        councilRoleManifest: [
            ...ROLES.map((role) => ({
                id: role.id,
                category: role.category,
                mandatory: role.mandatory,
            })),
            extraRole,
        ],
    });
    indexOneFile(SESSION);
    const accepted = parse(await call(localSubmit(auditId, extraRole, [])));
    assert.equal(accepted.ok, true);
    assert.equal(accepted.producer_role_id, extraRole.id);
});

test("build-clone findings omit sourceIdentity.blobSha when the index has no Git blob identity", async () => {
    const clonePath = nodePathForTest("build-candidate-clone");
    const auditId = activateAudit({
        sessionId: SESSION,
        buildPath: BUILD_ROOT,
        mode: "audit_and_safe_build_council",
        expectedClonePath: clonePath,
        owner: "Example",
        repo: "Repo",
        councilRoleManifest: ROLES.map((role) => ({
            id: role.id,
            category: role.category,
            mandatory: role.mandatory,
        })),
    });
    recordResolvedClonePath(SESSION, clonePath);
    recordResolvedSha(SESSION, RESOLVED_SHA);
    indexOneFile(SESSION, { sourceKind: "build-clone" });

    const role = ROLES[0];
    const buildCandidate = candidate(role.id, auditId, {
        sourceType: "git-blob",
        namespace: `github.com/example/repo@${RESOLVED_SHA}`,
        omitSourceBlobSha: true,
    });
    const args = {
        ...localSubmit(auditId, role, [buildCandidate]),
        source_identity: {
            kind: "git",
            owner: "example",
            repo: "repo",
            resolved_sha: RESOLVED_SHA,
        },
    };
    const accepted = parse(await call(args));
    assert.equal(accepted.ok, true, accepted.error);
});

test("rejects unenumerated paths, invalid excerpt hashes, source snippets, and conflicting IDs", async () => {
    const auditId = activateLocal();
    indexOneFile(SESSION);

    const unenumerated = localSubmit(auditId, ROLES[0], [
        candidate(ROLES[0].id, auditId, { path: "src/missing.mjs" }),
    ]);
    assert.match(parse(await call(unenumerated)).error, /was not enumerated/);

    const badHash = localSubmit(auditId, ROLES[0], [
        candidate(ROLES[0].id, auditId, { excerptHash: "0".repeat(64) }),
    ]);
    assert.match(parse(await call(badHash)).error, /not a trusted indexed fact/);

    const sourceText = localSubmit(auditId);
    sourceText.candidates[0].finding.evidence[0].sourceText = "do not ingest source";
    assert.match(parse(await call(sourceText)).error, /unknown field|not allowed/);

    const duplicateFindingA = candidate(ROLES[0].id, auditId);
    const duplicateFindingB = candidate(ROLES[0].id, auditId, {
        nodePrefix: `${ROLES[0].id}.second`,
    });
    duplicateFindingB.finding.title = "Conflicting prose for the same derived finding ID";
    const duplicateFinding = localSubmit(
        auditId,
        ROLES[0],
        [duplicateFindingA, duplicateFindingB],
    );
    assert.match(parse(await call(duplicateFinding)).error, /conflicting finding id/);

    assert.equal(parse(await call(localSubmit(auditId))).ok, true);
    const secondRole = ROLES[1];
    const conflict = localSubmit(auditId, secondRole, [
        candidate(secondRole.id, auditId, { nodePrefix: ROLES[0].id }),
    ]);
    assert.match(parse(await call(conflict)).error, /conflicting graph node id/);
});

test("finalizes scanned only after mandatory/category/90% gates and all submissions", async () => {
    const auditId = activateLocal();
    indexOneFile(SESSION);
    for (const [index, role] of ROLES.entries()) {
        const candidates = index === 0 ? [candidate(role.id, auditId)]: [];
        const submitted = parse(await call(localSubmit(auditId, role, candidates)));
        assert.equal(submitted.ok, true, role.id);
    }
    assert.equal(getAnalysisStageState(SESSION).current, "prepared");
    const prematureOutcome = parse(await recordOutcomeHandler({
        audit_id: auditId,
        verdict: "low",
        critical_count: 0,
        high_count: 0,
        complete: true,
    }, { sessionId: SESSION }));
    assert.equal(prematureOutcome.ok, false);
    assert.match(
        prematureOutcome.error,
        /candidate submission.*graph tracing.*confirm\/refute\/adjudication/,
    );

    const finalizeArgs = {
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
        successful_role_ids: ROLES.map((role) => role.id),
        failed_role_ids: [],
        deterministic_baseline_complete: true,
    };
    const finalized = parse(await call(finalizeArgs));
    assert.equal(finalized.ok, true);
    assert.equal(finalized.analysis_stage, "scanned");
    assert.equal(finalized.successful_roles, 32);
    assert.equal(getAnalysisStageState(SESSION).current, "scanned");
    assert.equal(parse(await call(structuredClone(finalizeArgs))).idempotent, true);
    const traced = parse(await traceBehaviorGraphHandler({
        audit_id: auditId,
    }, { sessionId: SESSION }));
    assert.equal(traced.ok, true);
    assert.equal(traced.coverageComplete, true);
    assert.equal(traced.analysisStageAfter, "traced");
    assert.equal(getAnalysisStageState(SESSION).current, "traced");
    const recordedOutcome = parse(await recordOutcomeHandler({
        audit_id: auditId,
        verdict: "low",
        critical_count: 0,
        high_count: 0,
        complete: true,
    }, { sessionId: SESSION }));
    assert.equal(recordedOutcome.ok, false);
    assert.match(recordedOutcome.error, /analysis stage validated or later/);
});

test("failed gates or incomplete submissions never advance the scan stage", async () => {
    const auditId = activateLocal();
    indexOneFile(SESSION);
    const nonMandatory = ROLES.filter((role) => !role.mandatory);
    for (const role of nonMandatory) {
        assert.equal(parse(await call(localSubmit(auditId, role, []))).ok, true);
    }
    const failedMandatory = ROLES.filter((role) => role.mandatory).map((role) => role.id);
    const result = parse(await call({
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
        successful_role_ids: nonMandatory.map((role) => role.id),
        failed_role_ids: failedMandatory,
        deterministic_baseline_complete: true,
    }));
    assert.equal(result.ok, false);
    assert.match(result.error, /council gates failed/);
    assert.equal(getAnalysisStageState(SESSION).current, "prepared");
});

test("candidate ingestion cannot satisfy API-direct mandatory acquisition", async () => {
    const sessionId = `${SESSION}-api`;
    const auditId = activateAudit({
        sessionId,
        buildPath: BUILD_ROOT,
        mode: "audit_source_council",
        expectedClonePath: nodePathForTest("clone"),
        owner: "Example",
        repo: "Repo",
        councilRoleManifest: ROLES.map((role) => ({
            id: role.id,
            category: role.category,
            mandatory: role.mandatory,
        })),
    });
    recordResolvedSha(sessionId, RESOLVED_SHA);
    recordTreeEnumerationState(sessionId, {
        commitSha: RESOLVED_SHA,
        rootTreeSha: ROOT_TREE_SHA,
        discoveredSubtrees: [{ path: "", sha: ROOT_TREE_SHA }],
        unresolvedSubtrees: [],
        completedSubtrees: [""],
        entries: [{ path: FILE_PATH, type: "blob", sha: GIT_BLOB_SHA, size: 64 }],
        aggregateEntryCount: 1,
        duplicateEntryCount: 0,
        stateTrackingTruncated: false,
        discoveryTruncated: false,
        githubTruncationSeen: false,
        localEntryCapSeen: false,
        coverageBlockers: [],
    });
    const coverage = createCoverageState(RESOLVED_SHA, ROOT_TREE_SHA);
    recordEnumeratedEntries(coverage, [{
        path: FILE_PATH,
        type: "blob",
        sha: GIT_BLOB_SHA,
        size: 64,
    }]);
    recordAcquisitionCoverageState(sessionId, coverage);
    indexOneFile(sessionId, { blobSha: GIT_BLOB_SHA, sourceKind: "api-direct" });

    const sample = parse(await safeFetchFileHandler({
        owner: "example",
        repo: "repo",
        sha: RESOLVED_SHA,
        path: FILE_PATH,
        coverage_scope: "council_sample",
    }, {
        sessionId,
        apiClient: {
            fetchFile:() => apiClientInternals.buildFetchResultFromBuffer(
                FILE_PATH,
                Buffer.from("processExecution();", "utf8"),
                { blobSha: GIT_BLOB_SHA },
            ),
        },
    }));
    assert.equal(sample.ok, true);
    assert.equal(sample.coverageScope, "council_sample");
    assert.equal(sample.analysisFacts.length, 1);

    const role = ROLES[0];
    const args = {
        ...localSubmit(auditId, role, [candidate(role.id, auditId, {
            sourceType: "git-blob",
            namespace: `github.com/example/repo@${RESOLVED_SHA}`,
            blobSha: GIT_BLOB_SHA,
        })]),
        source_identity: {
            kind: "git",
            owner: "example",
            repo: "repo",
            resolved_sha: RESOLVED_SHA,
        },
    };
    const before = structuredClone(getAcquisitionCoverageState(sessionId));
    assert.equal(parse(await call(args, sessionId)).ok, true);
    assert.deepEqual(getAcquisitionCoverageState(sessionId), before);

    for (const roleEntry of ROLES.slice(1)) {
        const empty = {
            ...localSubmit(auditId, roleEntry, []),
            source_identity: args.source_identity,
        };
        assert.equal(parse(await call(empty, sessionId)).ok, true);
    }
    const finalized = parse(await call({
        action: "finalize",
        schemaVersion: 5,
        audit_id: auditId,
        successful_role_ids: ROLES.map((entry) => entry.id),
        failed_role_ids: [],
        deterministic_baseline_complete: true,
    }, sessionId));
    assert.equal(finalized.ok, false);
    assert.match(finalized.error, /mandatory acquisition is incomplete/);
    assert.equal(getAnalysisStageState(sessionId).current, "prepared");
});

test("extension registers the audit-bound candidate recorder and bounded schema", () => {
    const extensionSource = readFileSync(
        new URL("../extension.mjs", import.meta.url),
        "utf8",
    );
    assert.match(extensionSource, /\brecordCouncilCandidatesHandler\b/);
    assert.match(extensionSource, /name:\s*"zerotrust_record_council_candidates"/);
    assert.match(extensionSource, /maxItems:\s*32/);
    assert.match(extensionSource, /submissions never satisfy mandatory acquisition/i);
    assert.match(extensionSource, /name:\s*"zerotrust_trace_evasive_graph"/);
});

function nodePathForTest(name) {
    return process.platform === "win32"
        ? `${BUILD_ROOT}\\${name}`: `${BUILD_ROOT}/${name}`;
}
