import { after, afterEach, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import {
    existsSync,
    linkSync,
    mkdirSync,
    readFileSync,
    rmSync,
    unlinkSync,
    writeFileSync,
} from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";

import {
    ANALYSIS_SCHEMA_VERSION,
    BehaviorGraph,
    FindingLedger,
    REPORT_LEDGER_LIMITS,
    assertMarkdownFindingsConsistency,
    buildTrustedDecisionSnapshot,
    computeFindingId,
    serializeFindingsArtifact,
} from "../analysis/index.mjs";
import {
    recordIndexEnumeration,
    recordIndexedFile,
} from "../analysis/indexState.mjs";
import { buildValidationSnapshot } from "../analysis/validation.mjs";
import {
    __internals as enforcementInternals,
    activateAudit,
    deactivateAudit,
    getActiveAudit,
    maybeAdvanceAnalysisPrepared,
    mutateAnalysisIndexState,
    recordResolvedArtifactPaths,
    recordResolvedClonePath,
    recordResolvedSha,
} from "../enforcement.mjs";
import { cleanupAuditHandler } from "../safeWrappers/cleanupWrapper.mjs";
import {
    __internals as reportInternals,
    finalizeReportHandler,
} from "../safeWrappers/reportWrapper.mjs";
import {
    __internals as stateInternals,
    recordCouncilOutcome,
} from "../safeWrappers/state.mjs";
import { buildClonePath, buildReportPath } from "../urlParser.mjs";

const HERE = nodePath.dirname(fileURLToPath(import.meta.url));
const SCRATCH = nodePath.join(HERE, ".v5-dual-finalization-scratch");
const OWNER = "octocat";
const REPO = "dual-finalization";
const SHA = "a".repeat(40);
const BLOB = "b".repeat(40);
const CONTENT = "c".repeat(64);
const EXCERPT = "d".repeat(64);
const ROLE = Object.freeze({ id: "dual-role", category: "A", mandatory: true });
let sequence = 0;

beforeEach(() => {
    rmSync(SCRATCH, { recursive: true, force: true });
    mkdirSync(SCRATCH, { recursive: true });
});

afterEach(() => {
    enforcementInternals.activeAudits.clear();
    stateInternals.councilLedgers.clear();
    stateInternals.recordedOutcomes.clear();
    stateInternals.cacheBindings.clear();
});

after(() => {
    rmSync(SCRATCH, { recursive: true, force: true });
});

function session(label) {
    sequence += 1;
    return `v5-dual-${label}-${sequence}`;
}

function parse(result) {
    return JSON.parse(result.textResultForLlm);
}

function indexAudit(sessionId) {
    mutateAnalysisIndexState(sessionId, (state) => {
        recordIndexEnumeration(state, {
            entries: [{ path: "src/loader.mjs", size: 16, blobSha: BLOB }],
            complete: true,
        });
        recordIndexedFile(state, {
            path: "src/loader.mjs",
            size: 16,
            classification: "text",
            classificationComplete: true,
            contentSha256: CONTENT,
            blobSha: BLOB,
            lineCount: 1,
            facts: [],
            invisibleUnicodeScanComplete: true,
        });
    });
    assert.equal(maybeAdvanceAnalysisPrepared(sessionId).analysisIndex.complete, true);
}

function traceSnapshot(auditId) {
    return {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        sourceNamespace: `github.com/${OWNER}/${REPO}@${SHA}`,
        inputFingerprint: "trace-" + "e".repeat(58),
        coverageComplete: true,
        gates: {
            stageScanned: true,
            candidateIngestionComplete: true,
            indexComplete: true,
            pluginCoverageComplete: true,
            graphMergeComplete: true,
            traceAccountingComplete: true,
        },
        counts: {
            inputGraphs: 1,
            uniqueGraphs: 1,
            mergedGraphs: 1,
            nodes: 3,
            edges: 2,
            conflicts: 0,
            unresolvedReferences: 0,
            identityMismatches: 0,
            semanticNodes: 3,
            semanticEdges: 2,
            chains: 1,
            completeChains: 1,
            unresolvedChains: 0,
            contestedChains: 0,
            cycles: 0,
            exploredBranches: 1,
        },
        truncation: {},
        blockers: [],
        validationQueue: [],
        cycles: [],
        chains: [{
            id: "chain.dual",
            pattern: "install-fetch-decode-execute",
            priority: 1,
            status: "complete",
            crossFile: false,
            steps: [
                { kind: "activation", nodeIds: ["dual.activation"] },
                { kind: "capability", nodeIds: ["dual.capability"] },
                { kind: "sink", nodeIds: ["dual.effect"] },
            ],
            links: [
                { kind: "activates", edgeIds: ["dual.activates"] },
                { kind: "flows-to", edgeIds: ["dual.flows"] },
            ],
            evidence: [],
            paths: ["src/loader.mjs"],
            effectKinds: ["sink"],
            unresolvedReasons: [],
            validationIds: [],
        }],
    };
}

function evidence(coverageScope) {
    return {
        path: "src/loader.mjs",
        startLine: 1,
        endLine: 1,
        blobSha: BLOB,
        excerptHash: EXCERPT,
        producer: ROLE.id,
        coverageScope,
    };
}

function installCouncilLedger(sessionId, {
    auditId,
    local = false,
    severity = "high",
} = {}) {
    const sourceIdentity = {
        type: local ? "local-file" : "git-blob",
        namespace: local
            ? `local-audit:${auditId}`
            : `github.com/${OWNER}/${REPO}@${SHA}`,
        path: "src/loader.mjs",
        contentSha256: CONTENT,
        blobSha: BLOB,
    };
    const behaviorSignature = {
        trigger: "package-install",
        capability: "process-spawn",
        action: "execute",
        target: "shell",
    };
    const findingId = computeFindingId(sourceIdentity, behaviorSignature);
    const ledger = new FindingLedger({ auditId });
    ledger.addCandidate({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        id: findingId,
        sourceIdentity,
        behaviorSignature,
        title: "Source text must not be serialized",
        summary: "This narrative must stay out of FINDINGS.json.",
        severity,
        confidence: "medium",
        maliciousProjectFit: "likely",
        state: "candidate",
        evidence: [evidence(local ? "local_source" : "mandatory")],
        nodeIds: ["dual.activation", "dual.capability", "dual.effect"],
        edgeIds: ["dual.activates", "dual.flows"],
        producer: ROLE.id,
    });
    ledger.beginValidation(findingId, { auditId });
    ledger.applyValidationDecision({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        findingId,
        validator: "dual-adjudicator",
        decision: "validated",
        severity,
        confidence: "high",
        maliciousProjectFit: "likely",
        rationaleCode: "complete-reachable-chain",
        rationale: "Narrative rationale must not be serialized.",
        evidence: [evidence(local ? "local_source" : "mandatory")],
    });
    const confirm = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        findingId,
        validatorId: "dual-confirm",
        decisionType: "confirm",
        conclusion: "confirmed",
        chainIds: ["chain.dual"],
        nodeIds: ["dual.activation", "dual.capability", "dual.effect"],
        edgeIds: ["dual.activates", "dual.flows"],
        evidence: [evidence(local ? "local_source" : "mandatory")],
        rationaleCode: "complete-reachable-chain",
        rationale: "Do not serialize this rationale.",
        checks: {
            activationReachable: true,
            effectReachable: true,
            sourceToEffectPath: true,
            gatingConsidered: true,
            brokenEdgesConsidered: true,
        },
    };
    const refute = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        findingId,
        validatorId: "dual-refute",
        decisionType: "refute",
        conclusion: "not-refuted",
        chainIds: ["chain.dual"],
        nodeIds: ["dual.activation", "dual.capability", "dual.effect"],
        edgeIds: ["dual.activates", "dual.flows"],
        evidence: [evidence(local ? "local_source" : "mandatory")],
        rationaleCode: "no-static-refutation",
        rationale: "Do not serialize this rationale either.",
        checks: {
            deadOrUnreachableCode: "does-not-refute",
            docsOrTestsOnlyContext: "does-not-refute",
            activationGating: "does-not-refute",
            sanitizationOrNeutralization: "does-not-refute",
            brokenGraphEdges: "does-not-refute",
            legitimateProjectFit: "does-not-refute",
        },
    };
    const adjudication = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        findingId,
        adjudicatorId: "dual-adjudicator",
        decision: "validated",
        severity,
        confidence: "high",
        maliciousProjectFit: "likely",
        rationaleCode: "validators-agree",
        rationale: "Adjudication prose must not be serialized.",
        chainIds: ["chain.dual"],
        nodeIds: ["dual.activation", "dual.capability", "dual.effect"],
        edgeIds: ["dual.activates", "dual.flows"],
        evidence: [evidence(local ? "local_source" : "mandatory")],
    };
    const validationState = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        minSeverity: "high",
        inputFingerprint: "validation-" + "f".repeat(53),
        requiredFindingIds: [findingId],
        contexts: new Map(),
        decisions: new Map([
            [`${findingId}:confirm`, { digest: "1".repeat(64), decision: confirm }],
            [`${findingId}:refute`, { digest: "2".repeat(64), decision: refute }],
        ]),
        adjudications: new Map([
            [findingId, { digest: "3".repeat(64), decision: adjudication }],
        ]),
        truncation: { contexts: false },
        finalization: { digest: "4".repeat(64), requiredCandidates: 1 },
    };
    const trace = traceSnapshot(auditId);
    const validation = buildValidationSnapshot(validationState);
    const decisionSnapshot = buildTrustedDecisionSnapshot({
        auditId,
        findings: ledger.listFindings(),
        traceSnapshot: trace,
        validationSnapshot: validation,
        coverage: {
            acquisitionComplete: true,
            indexComplete: true,
            pluginCoverageComplete: true,
            councilComplete: true,
            traceComplete: true,
            validationComplete: true,
            cacheTrackingComplete: true,
        },
    });
    stateInternals.councilLedgers.set(sessionId, {
        auditId,
        roles: [ROLE],
        findingLedger: ledger,
        behaviorGraph: new BehaviorGraph({ auditId }),
        submissions: new Map([[
            ROLE.id,
            {
                digest: "5".repeat(64),
                candidateCount: 1,
                coveragePerformedCount: 1,
            },
        ]]),
        candidateContexts: new Map(),
        finalization: {
            successfulRoleIds: [ROLE.id],
            failedRoleIds: [],
            digest: "6".repeat(64),
        },
        validationState,
        decisionSnapshot,
    });
    const audit = getActiveAudit(sessionId);
    audit.analysisTraceState = {
        inputFingerprint: trace.inputFingerprint,
        snapshot: trace,
    };
    audit.analysisStageState = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        current: "validated",
        history: ["acquired", "prepared", "scanned", "traced", "validated"],
    };
    return { decisionSnapshot, findingId };
}

function activateCouncil({
    label,
    mode = "audit_and_safe_build_council",
    local = false,
} = {}) {
    const sessionId = session(label);
    let auditId;
    let reportDir;
    let args;
    let clonePath = null;
    if (local) {
        const localPath = nodePath.join(SCRATCH, "sample-project");
        mkdirSync(localPath, { recursive: true });
        reportDir = nodePath.join(
            SCRATCH,
            "_reports",
            "local-sample-project-20260714010101",
        );
        auditId = activateAudit({
            sessionId,
            buildPath: SCRATCH,
            mode: "audit_local_source_council",
            localPath,
            expectedReportPath: reportDir,
            councilRoleManifest: [ROLE],
        });
        args = {};
    } else {
        clonePath = buildClonePath(SCRATCH, OWNER, REPO, SHA);
        auditId = activateAudit({
            sessionId,
            buildPath: SCRATCH,
            mode,
            expectedClonePath: clonePath,
            owner: OWNER,
            repo: REPO,
            councilRoleManifest: [ROLE],
        });
        assert.equal(recordResolvedSha(sessionId, SHA), true);
        reportDir = buildReportPath(SCRATCH, OWNER, REPO, SHA);
        assert.equal(recordResolvedArtifactPaths(sessionId, { reportPath: reportDir }), true);
        args = { owner: OWNER, repo: REPO, resolved_sha: SHA };
    }
    indexAudit(sessionId);
    const installed = installCouncilLedger(sessionId, { auditId, local });
    return { sessionId, auditId, reportDir, args, clonePath, ...installed };
}

function recordExpectedOutcome(sessionId, {
    verdict = "high",
    highCount = 1,
    criticalCount = 0,
    complete = true,
} = {}) {
    const audit = getActiveAudit(sessionId);
    recordCouncilOutcome(sessionId, {
        auditId: audit.auditId,
        owner: audit.owner || null,
        repo: audit.repo || null,
        resolvedSha: audit.resolvedSha || null,
        verdict,
        criticalCount,
        highCount,
        complete,
    });
}

async function finalizeCouncil(fixture, extra = {}, dependencies = {}) {
    return finalizeReportHandler(
        {
            ...fixture.args,
            operator_decisions: [],
            ...extra,
        },
        { sessionId: fixture.sessionId },
        dependencies,
    );
}

test("v5 council finalization writes and records the canonical pair from one ledger snapshot", async () => {
    const fixture = activateCouncil({ label: "pair-success" });
    const plugin = getActiveAudit(fixture.sessionId).analysisPluginState.plugins[0];
    plugin.detected = true;
    plugin.completed = true;
    plugin.factCount = 1;
    plugin.facts = [{
        id: "7".repeat(64),
        kind: "manifest-key",
        name: "source-controlled-plugin-name",
        value: "SOURCE_PLUGIN_VALUE_MUST_NOT_PERSIST",
        path: "src/loader.mjs",
        line: 1,
        endLine: 1,
        excerptHash: EXCERPT,
    }];
    recordExpectedOutcome(fixture.sessionId);
    const result = await finalizeCouncil(fixture);
    assert.equal(result.resultType, "success", result.textResultForLlm);
    const body = parse(result);
    assert.equal(body.verdict, "high");
    assert.equal(body.trustedVerdict, true);
    assert.equal(body.analysisStageAfter, "finalized");
    assert.equal(existsSync(body.reportPath), true);
    assert.equal(existsSync(body.findingsPath), true);
    const markdown = readFileSync(body.reportPath, "utf8");
    const findings = JSON.parse(readFileSync(body.findingsPath, "utf8"));
    assert.equal(findings.flow, "v5-ledger");
    assert.equal(findings.verdict.value, "high");
    assert.equal(findings.canonicalFindings[0].stateClass, "validated");
    assert.equal(findings.canonicalFindings[0].scores.impactSeverity.level, "high");
    assert.equal(findings.validationDecisions.length, 2);
    assert.equal(findings.adjudications.length, 1);
    assert.equal(findings.graph.chains[0].id, "chain.dual");
    assert.equal(findings.remediation.operatorDecisions.length, 0);
    assert.deepEqual(
        Object.keys(findings.coverage.analysisPlugins.facts[0]).sort(),
        [
            "endLine",
            "excerptHash",
            "id",
            "kind",
            "line",
            "path",
            "pluginId",
            "pluginVersion",
            "producer",
        ].sort(),
    );
    assert.match(markdown, /\| validated \| high \|/u);
    assert.match(
        markdown,
        /The validated trusted ledger produced the deterministic verdict high\./u,
    );
    assert.match(
        markdown,
        /Do not use the audited project until every active critical\/high finding/u,
    );
    assert.equal(assertMarkdownFindingsConsistency(markdown, findings), true);
    assert.doesNotMatch(
        readFileSync(body.findingsPath, "utf8"),
        /Source text must not be serialized|narrative|rationale must not|SOURCE_PLUGIN_VALUE_MUST_NOT_PERSIST|source-controlled-plugin-name/u,
    );
    const record = getActiveAudit(fixture.sessionId).reportFinalization;
    assert.equal(record.reportPath, body.reportPath);
    assert.equal(record.findingsPath, body.findingsPath);
    assert.equal(record.contentSha256, body.reportSha256);
    assert.equal(record.findingsSha256, body.findingsSha256);
});

test("idempotent retry verifies both hashes and a second-write attack fails closed", async () => {
    const fixture = activateCouncil({ label: "idempotency" });
    recordExpectedOutcome(fixture.sessionId);
    const first = parse(await finalizeCouncil(fixture));
    const reportBefore = readFileSync(first.reportPath, "utf8");
    const findingsBefore = readFileSync(first.findingsPath, "utf8");
    const retry = await finalizeCouncil(fixture, {
        operator_decisions: [{
            finding_id: fixture.decisionSnapshot.canonicalFindings[0].canonicalId,
            action: "kept-as-is",
            rationale_category: "accepted-risk",
        }],
    });
    assert.equal(retry.resultType, "success");
    assert.equal(parse(retry).alreadyFinalized, true);
    assert.equal(readFileSync(first.reportPath, "utf8"), reportBefore);
    assert.equal(readFileSync(first.findingsPath, "utf8"), findingsBefore);

    writeFileSync(first.findingsPath, `${findingsBefore.trim()}\n `);
    const attacked = await finalizeCouncil(fixture);
    assert.equal(attacked.resultType, "failure");
    assert.match(attacked.textResultForLlm, /changed after exactly-once finalization/i);
});

test("partial pair publication rolls back the first canonical artifact", async () => {
    const fixture = activateCouncil({ label: "partial-failure" });
    recordExpectedOutcome(fixture.sessionId);
    const result = await finalizeCouncil(fixture, {}, {
        publish(tempPath, destinationPath, { index }) {
            if (index === 1) throw new Error("simulated second publish failure");
            linkSync(tempPath, destinationPath);
            unlinkSync(tempPath);
        },
    });
    assert.equal(result.resultType, "failure");
    assert.match(result.textResultForLlm, /simulated second publish failure/);
    assert.equal(existsSync(nodePath.join(fixture.reportDir, "REPORT.md")), false);
    assert.equal(existsSync(nodePath.join(fixture.reportDir, "FINDINGS.json")), false);
    assert.equal(getActiveAudit(fixture.sessionId).reportFinalization, undefined);
});

test("council finalization fails closed for a missing ledger or unrecorded artifact", async () => {
    const missingLedger = activateCouncil({ label: "missing-ledger" });
    stateInternals.councilLedgers.delete(missingLedger.sessionId);
    recordExpectedOutcome(missingLedger.sessionId, {
        verdict: "incomplete",
        complete: false,
    });
    const refused = await finalizeCouncil(missingLedger);
    assert.equal(refused.resultType, "failure");
    assert.match(refused.textResultForLlm, /requires the active audit's trusted finding ledger/i);

    const preExisting = activateCouncil({ label: "pre-existing" });
    recordExpectedOutcome(preExisting.sessionId);
    mkdirSync(preExisting.reportDir, { recursive: true });
    writeFileSync(nodePath.join(preExisting.reportDir, "FINDINGS.json"), "{}\n");
    const blocked = await finalizeCouncil(preExisting);
    assert.equal(blocked.resultType, "failure");
    assert.match(blocked.textResultForLlm, /already exists without a finalization record/i);
});

test("v5 rejects model prose and unsafe operator rationale while preserving report/ledger parity", async () => {
    const fixture = activateCouncil({ label: "mismatch" });
    getActiveAudit(fixture.sessionId).analysisIndexState.facts.push({
        id: "8".repeat(64),
        kind: "manifest-key",
        path: "src/loader.mjs",
        line: 1,
        endLine: 1,
        excerptHash: EXCERPT,
        name: "indexed-source-token",
        value: "INDEXED_SOURCE_VALUE_MUST_BE_REFUSED",
    });
    recordExpectedOutcome(fixture.sessionId);
    const modelProse = await finalizeCouncil(fixture, {
        executive_summary: "Overall verdict is low.",
    });
    assert.equal(modelProse.resultType, "failure");
    assert.match(modelProse.textResultForLlm, /model-authored report prose is refused/i);
    const canonicalId = fixture.decisionSnapshot.canonicalFindings[0].canonicalId;
    for (const rationale of [
        "Source text must not be serialized",
        "INDEXED_SOURCE_VALUE_MUST_BE_REFUSED",
        "Use `inline code` here",
        "See https://example.invalid/decision",
        "A".repeat(64),
        "This finding is safe.",
    ]) {
        const refused = await finalizeCouncil(fixture, {
            operator_decisions: [{
                finding_id: canonicalId,
                action: "kept-as-is",
                rationale_category: "other",
                operator_rationale: rationale,
            }],
        });
        assert.equal(refused.resultType, "failure", rationale);
    }

    const good = parse(await finalizeCouncil(fixture, {
        operator_decisions: [{
            finding_id: canonicalId,
            action: "kept-as-is",
            rationale_category: "required-functionality",
            operator_rationale: "Needed for the approved deployment workflow.",
        }],
    }));
    const originalMarkdown = readFileSync(good.reportPath, "utf8");
    const markdown = originalMarkdown
        .replace("| validated | high |", "| refuted | low |");
    const findings = JSON.parse(readFileSync(good.findingsPath, "utf8"));
    assert.equal(findings.remediation.operatorDecisions[0].operatorRationale.origin,
        "operator-supplied");
    assert.match(readFileSync(good.reportPath, "utf8"), /user-supplied rationale=/u);
    assert.throws(
        () => assertMarkdownFindingsConsistency(markdown, findings),
        /finding rows do not match/i,
    );
    assert.throws(
        () => assertMarkdownFindingsConsistency(
            originalMarkdown.replace("action=kept-as-is", "action=defanged"),
            findings,
        ),
        /operator decisions do not match/i,
    );
    assert.throws(
        () => assertMarkdownFindingsConsistency(
            originalMarkdown.replace("deterministic verdict high", "deterministic verdict low"),
            findings,
        ),
        /executive summary does not match/i,
    );
});

test("recorded council outcome must exactly match the deterministic ledger verdict and counts", async () => {
    const fixture = activateCouncil({ label: "outcome-mismatch" });
    recordExpectedOutcome(fixture.sessionId, {
        verdict: "low",
        highCount: 0,
        complete: true,
    });
    const result = await finalizeCouncil(fixture);
    assert.equal(result.resultType, "failure");
    const body = parse(result);
    assert.match(body.error, /recorded council outcome conflicts with the trusted ledger/i);
    assert.equal(body.expectedOutcome.verdict, "high");
    assert.equal(body.expectedOutcome.highCount, 1);
});

test("incomplete API gates finalize exact blockers, while local/build trusted and release legacy modes write pairs", async () => {
    const api = activateCouncil({
        label: "api-incomplete",
        mode: "audit_source_council",
    });
    recordExpectedOutcome(api.sessionId, {
        verdict: "incomplete",
        highCount: 1,
        complete: false,
    });
    const apiResult = await finalizeCouncil(api);
    assert.equal(apiResult.resultType, "success", apiResult.textResultForLlm);
    const apiBody = parse(apiResult);
    const apiFindings = JSON.parse(readFileSync(apiBody.findingsPath, "utf8"));
    assert.equal(apiFindings.verdict.value, "incomplete");
    assert.equal(apiFindings.verdict.trusted, false);
    assert.ok(apiFindings.blockers.some((entry) =>
        entry.code === "required-acquisition-incomplete"));
    assert.match(readFileSync(apiBody.reportPath, "utf8"), /INCOMPLETE — DO NOT TRUST/u);
    deactivateAudit(api.sessionId);

    const local = activateCouncil({ label: "local", local: true });
    recordExpectedOutcome(local.sessionId);
    const localResult = await finalizeCouncil(local);
    assert.equal(localResult.resultType, "success", localResult.textResultForLlm);
    assert.match(
        parse(localResult).findingsPath,
        /local-sample-project-[0-9]{14}[\\/]FINDINGS\.json$/u,
    );
    deactivateAudit(local.sessionId);

    const releaseSession = session("release");
    const releaseRepo = "dual-release";
    const releaseAuditId = activateAudit({
        sessionId: releaseSession,
        buildPath: SCRATCH,
        mode: "verify_release",
        expectedClonePath: buildClonePath(SCRATCH, OWNER, releaseRepo, SHA),
        owner: OWNER,
        repo: releaseRepo,
    });
    assert.ok(releaseAuditId);
    assert.equal(recordResolvedSha(releaseSession, SHA), true);
    const releaseReportDir = buildReportPath(SCRATCH, OWNER, releaseRepo, SHA);
    assert.equal(
        recordResolvedArtifactPaths(releaseSession, { reportPath: releaseReportDir }),
        true,
    );
    const release = await finalizeReportHandler({
        owner: OWNER,
        repo: releaseRepo,
        resolved_sha: SHA,
        markdown_body: "# INCOMPLETE — DO NOT TRUST\n\nVerdict: incomplete",
    }, { sessionId: releaseSession });
    assert.equal(release.resultType, "success", release.textResultForLlm);
    const releaseBody = parse(release);
    assert.equal(existsSync(releaseBody.reportPath), true);
    assert.equal(existsSync(releaseBody.findingsPath), true);
    assert.equal(
        JSON.parse(readFileSync(releaseBody.findingsPath, "utf8")).flow,
        "legacy-v4",
    );
    assert.equal(
        JSON.parse(readFileSync(releaseBody.findingsPath, "utf8")).verdict.trusted,
        false,
    );
});

test("artifact size caps reject oversized operator rationale and oversized findings serialization", async () => {
    const fixture = activateCouncil({ label: "caps" });
    recordExpectedOutcome(fixture.sessionId);
    const canonicalId = fixture.decisionSnapshot.canonicalFindings[0].canonicalId;
    const oversized = await finalizeCouncil(fixture, {
        operator_decisions: [{
            finding_id: canonicalId,
            action: "kept-as-is",
            rationale_category: "other",
            operator_rationale: "word ".repeat(
                REPORT_LEDGER_LIMITS.operatorRationaleBytes,
            ),
        }],
    });
    assert.equal(oversized.resultType, "failure");
    assert.match(oversized.textResultForLlm, /operator_rationale must contain/i);

    const document = {
        schemaVersion: 5,
        artifactVersion: 1,
        artifactType: "zerotrust-sourcecheck-findings",
        flow: "legacy-v4",
        blockers: [{
            code: "oversized",
            details: "x".repeat(REPORT_LEDGER_LIMITS.findingsBytes),
        }],
    };
    assert.throws(
        () => serializeFindingsArtifact(document),
        /FINDINGS\.json exceeds/i,
    );
    assert.throws(
        () => serializeFindingsArtifact({
            flow: "v5-ledger",
            payload: { arbitrary: "source controlled free string" },
        }),
        /not permitted to contain an arbitrary string/i,
    );
    assert.equal(reportInternals.MAX_REPORT_BYTES, 1024 * 1024);
});

test("build cleanup preserves both finalized artifacts by default", async () => {
    const fixture = activateCouncil({ label: "cleanup" });
    mkdirSync(fixture.clonePath, { recursive: true });
    assert.equal(recordResolvedClonePath(fixture.sessionId, fixture.clonePath), true);
    recordExpectedOutcome(fixture.sessionId);
    const finalized = parse(await finalizeCouncil(fixture));
    const cleanup = await cleanupAuditHandler(
        { clone_path: fixture.clonePath },
        { sessionId: fixture.sessionId },
    );
    assert.equal(cleanup.resultType, "success", cleanup.textResultForLlm);
    const cleanupBody = parse(cleanup);
    assert.equal(existsSync(fixture.clonePath), false);
    assert.equal(existsSync(finalized.reportPath), true);
    assert.equal(existsSync(finalized.findingsPath), true);
    assert.deepEqual(
        cleanupBody.keptReportArtifacts.sort(),
        [finalized.findingsPath, finalized.reportPath].sort(),
    );
});
