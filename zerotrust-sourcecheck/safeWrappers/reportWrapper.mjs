import {
    closeSync,
    constants,
    existsSync,
    fsyncSync,
    linkSync,
    mkdirSync,
    openSync,
    readFileSync,
    unlinkSync,
    writeFileSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import nodePath from "node:path";

import {
    advanceAnalysisStage,
    getAcquisitionCoverageState,
    getAnalysisTraceSnapshot,
    getReleaseAssetCoverageState,
    getTreeEnumerationState,
    getTrustedAuditContext,
    listAnalysisFacts,
    recordReportFinalization,
} from "../enforcement.mjs";
import {
    buildFindingsArtifact,
    buildLegacyFindingsArtifact,
    buildTrustedDecisionSnapshot,
    assertMarkdownFindingsConsistency,
    renderFindingsMarkdown,
    serializeFindingsArtifact,
} from "../analysis/index.mjs";
import { buildReportPath } from "../urlParser.mjs";
import { modeUsesApiDirect, modeUsesCouncil } from "../modes.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { buildCoverageSnapshot } from "./coverageAccounting.mjs";
import { buildReleaseAssetCoverageSnapshot } from "./releaseAssetCoverage.mjs";
import { failure, success } from "./result.mjs";
import {
    councilOutcomeMatchesAudit,
    getCacheBinding,
    getCouncilLedgerSnapshot,
    getRecordedOutcome,
} from "./state.mjs";

const MAX_REPORT_BYTES = 1024 * 1024;
const HASH_RE = /^[a-f0-9]{64}$/u;

export async function finalizeReportHandler(args, invocation, dependencies = {}) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) return failure(ctx.error);
    if (!sessionId || !ctx.hasActiveAudit) {
        return failure(
            "finalize_report refused: no active audit for this session (TTL expired, audit already closed, or zerotrust_sourcecheck was not invoked). Re-invoke zerotrust_sourcecheck before finalizing a report.",
        );
    }
    if (!nodePath.isAbsolute(ctx.buildRoot)) {
        return failure(`build_root must be absolute, got ${JSON.stringify(ctx.buildRoot)}`);
    }

    let resolved;
    try {
        resolved = resolveReportIdentity(ctx, args);
    } catch (error) {
        return failure(`report path construction failed: ${error.message}`);
    }
    const { reportDir, reportIdentity } = resolved;
    const reportPath = nodePath.join(reportDir, "REPORT.md");
    const findingsPath = nodePath.join(reportDir, "FINDINGS.json");
    for (const artifactPath of [reportPath, findingsPath]) {
        const rel = nodePath.relative(nodePath.resolve(ctx.buildRoot), artifactPath);
        if (rel.startsWith("..") || nodePath.isAbsolute(rel)) {
            return failure(
                `computed artifact path ${artifactPath} would escape build_root ${ctx.buildRoot}`,
            );
        }
    }

    const contractError = validateFinalizerArgumentKeys(args, ctx.mode);
    if (contractError) return failure(contractError);

    if (ctx.reportFinalization) {
        return returnRecordedPair({
            ctx,
            sessionId,
            reportPath,
            findingsPath,
            dependencies,
        });
    }

    const coverageState = getAcquisitionCoverageState(sessionId);
    const treeState = getTreeEnumerationState(sessionId);
    const acquisitionCoverage = (modeUsesApiDirect(ctx.mode) || coverageState || treeState)
        ? buildCoverageSnapshot(coverageState, treeState)
        : null;
    const releaseAssetCoverage = ctx.mode === "verify_release"
        ? buildReleaseAssetCoverageSnapshot(getReleaseAssetCoverageState(sessionId))
        : null;
    let cacheBinding = null;
    try {
        cacheBinding = getCacheBinding(sessionId, { auditId: ctx.auditId });
    } catch (error) {
        return failure(`finalize_report refused: cache metadata binding failed: ${error.message}`);
    }

    let artifacts;
    let recordedOutcome = null;
    if (modeUsesCouncil(ctx.mode)) {
        const built = buildCouncilArtifacts({
            args,
            ctx,
            sessionId,
            reportIdentity,
            acquisitionCoverage,
            releaseAssetCoverage,
            cacheBinding,
        });
        if (!built.ok) return failure(built.error, built.data);
        artifacts = built.artifacts;
        recordedOutcome = built.recordedOutcome;
    } else {
        const built = buildLegacyArtifacts({
            args,
            ctx,
            reportIdentity,
            acquisitionCoverage,
            releaseAssetCoverage,
            cacheBinding,
        });
        if (!built.ok) return failure(built.error, built.data);
        artifacts = built.artifacts;
    }

    if (Buffer.byteLength(artifacts.markdown, "utf8") > MAX_REPORT_BYTES) {
        return failure(
            `final report exceeds ${MAX_REPORT_BYTES} bytes after trusted assembly`,
            coverageResult(acquisitionCoverage, releaseAssetCoverage),
        );
    }

    const io = buildIo(dependencies);
    if (!io.exists(reportDir)) {
        try {
            io.mkdir(reportDir, { recursive: true });
        } catch (error) {
            return failure(`failed to create report dir ${reportDir}: ${error.message}`);
        }
    }
    const preExisting = [reportPath, findingsPath].filter((path) => io.exists(path));
    if (preExisting.length > 0) {
        return failure(
            "finalize_report refused: a canonical report artifact already exists without a finalization record; refusing to overwrite or adopt unrecorded files",
            { preExisting },
        );
    }

    const creation = createArtifactPair({
        reportPath,
        findingsPath,
        reportBody: artifacts.markdown,
        findingsBody: artifacts.findingsJson,
        io,
    });
    if (!creation.ok) {
        return failure(`dual-artifact write failed: ${creation.error}`, {
            rollback: creation.rollback,
        });
    }

    const recorded = recordReportFinalization(sessionId, {
        auditId: ctx.auditId,
        reportPath,
        findingsPath,
        bytesWritten: creation.report.bytes,
        contentSha256: creation.report.sha256,
        findingsBytesWritten: creation.findings.bytes,
        findingsSha256: creation.findings.sha256,
        reportIdentity,
        flow: artifacts.flow,
        ledgerDecisionId: artifacts.ledgerDecisionId,
    });
    if (!recorded) {
        const rollback = rollbackCanonicalPair([reportPath, findingsPath], io);
        return failure(
            "finalize_report created both artifacts but could not record exactly-once finalization state",
            { rollback },
        );
    }

    let analysisStageAfter = ctx.analysisStageState?.current || null;
    if (artifacts.flow === "v5-ledger" && analysisStageAfter === "validated") {
        try {
            analysisStageAfter = advanceAnalysisStage(sessionId, {
                auditId: ctx.auditId,
                from: "validated",
                to: "finalized",
            }).current;
        } catch (error) {
            return failure(
                `finalize_report durably recorded the pair but could not advance validated to finalized: ${error.message}. Retry the same finalizer call; it will not rewrite either artifact.`,
                pairResult({
                    reportPath,
                    findingsPath,
                    reportIdentity,
                    creation,
                    artifacts,
                    alreadyFinalized: true,
                    analysisStageAfter,
                }),
            );
        }
    }

    return success({
        ...pairResult({
            reportPath,
            findingsPath,
            reportIdentity,
            creation,
            artifacts,
            alreadyFinalized: false,
            analysisStageAfter,
        }),
        ...coverageResult(acquisitionCoverage, releaseAssetCoverage),
        ...(recordedOutcome ? { recordedOutcome: renderRecordedOutcome(recordedOutcome) } : {}),
    });
}

function validateFinalizerArgumentKeys(args, mode) {
    const allowed = modeUsesCouncil(mode)
        ? new Set([
            "owner",
            "repo",
            "resolved_sha",
            "build_root",
            "operator_decisions",
        ])
        : new Set([
            "owner",
            "repo",
            "resolved_sha",
            "build_root",
            "markdown_body",
        ]);
    const unexpected = Object.keys(args).filter((key) => !allowed.has(key));
    if (unexpected.length === 0) return null;
    return modeUsesCouncil(mode)
        ? `v5 council finalization accepts only structured operator_decisions; model-authored report prose is refused. Refused fields: ${unexpected.join(", ")}`
        : `legacy finalization does not accept arguments: ${unexpected.join(", ")}`;
}

function resolveReportIdentity(ctx, args) {
    let reportDir;
    let reportIdentity;
    if (ctx.localPath) {
        const forbiddenIdentityArgs = [
            "owner",
            "repo",
            "resolved_sha",
            "short_sha",
            "report_path",
            "path",
        ].filter((key) => Object.hasOwn(args, key));
        if (forbiddenIdentityArgs.length > 0) {
            throw new Error(
                `local-source reports do not accept caller-supplied identity/path fields (${forbiddenIdentityArgs.join(", ")}). The active audit's canonical local slug/timestamp identity is authoritative.`,
            );
        }
        if (!ctx.localReportSlug || !ctx.localReportTimestamp || !ctx.expectedReportPath) {
            throw new Error(
                "active local audit is missing its canonical slug/timestamp report identity. Re-invoke zerotrust_sourcecheck to start a fresh local audit.",
            );
        }
        reportDir = buildLocalReportPath(
            ctx.buildRoot,
            ctx.localReportSlug,
            ctx.localReportTimestamp,
        );
        if (!pathsEqual(reportDir, ctx.expectedReportPath)) {
            throw new Error(
                "active local report identity does not match the canonical build_root/_reports path.",
            );
        }
        reportIdentity = {
            sourceKind: "local",
            localSlug: ctx.localReportSlug,
            localTimestamp: ctx.localReportTimestamp,
        };
    } else {
        if (typeof args.owner !== "string"
            || typeof args.repo !== "string"
            || typeof args.resolved_sha !== "string") {
            throw new Error("owner, repo, and resolved_sha are required strings for URL reports");
        }
        if (Object.hasOwn(args, "short_sha")) {
            throw new Error(
                "short_sha is not accepted; pass the full 40-character resolved_sha used by the canonical artifact path",
            );
        }
        const callerSha = args.resolved_sha.toLowerCase();
        if (!/^[a-f0-9]{40}$/.test(callerSha)) {
            throw new Error("resolved_sha must be a full 40-character hexadecimal commit SHA");
        }
        if (!ctx.owner || !ctx.repo || !ctx.canonicalOwner || !ctx.canonicalRepo
            || !ctx.resolvedSha) {
            throw new Error(
                "active URL audit is not fully bound to owner/repo/full resolved SHA. Complete safe_list_tree or safe_clone before finalizing.",
            );
        }
        if (args.owner.toLowerCase() !== ctx.owner
            || args.repo.toLowerCase() !== ctx.repo
            || callerSha !== ctx.resolvedSha) {
            throw new Error(
                `caller identity (${args.owner}/${args.repo}@${callerSha}) does not match the active audit's bound identity (${ctx.canonicalOwner}/${ctx.canonicalRepo}@${ctx.resolvedSha}).`,
            );
        }
        reportDir = buildReportPath(
            ctx.buildRoot,
            ctx.canonicalOwner,
            ctx.canonicalRepo,
            ctx.resolvedSha,
        );
        if (ctx.expectedReportPath && !pathsEqual(reportDir, ctx.expectedReportPath)) {
            throw new Error(
                "active URL report path does not match the canonical owner/repo/resolved-SHA identity.",
            );
        }
        reportIdentity = {
            sourceKind: "url",
            owner: ctx.canonicalOwner,
            repo: ctx.canonicalRepo,
            resolvedSha: ctx.resolvedSha,
        };
    }
    return { reportDir, reportIdentity };
}

function buildCouncilArtifacts({
    args,
    ctx,
    sessionId,
    reportIdentity,
    acquisitionCoverage,
    releaseAssetCoverage,
    cacheBinding,
}) {
    const allowed = new Set([
        "owner",
        "repo",
        "resolved_sha",
        "build_root",
        "operator_decisions",
    ]);
    const unexpected = Object.keys(args).filter((key) => !allowed.has(key));
    if (unexpected.length > 0) {
        return {
            ok: false,
            error:
                `v5 council finalization accepts only structured operator_decisions; model-authored report prose is refused. Refused fields: ${unexpected.join(", ")}`,
        };
    }
    const ledgerSnapshot = getCouncilLedgerSnapshot(sessionId, { auditId: ctx.auditId });
    if (!ledgerSnapshot) {
        return {
            ok: false,
            error:
                "finalize_report refused: v5 council finalization requires the active audit's trusted finding ledger",
        };
    }
    const stageState = ctx.analysisStageState;
    if (!stageState) {
        return { ok: false, error: "finalize_report refused: analysis stage state is missing" };
    }
    if (stageState.current === "finalized") {
        return {
            ok: false,
            error:
                "finalize_report refused: analysis stage is finalized but no dual-artifact finalization record exists",
        };
    }
    const traceSnapshot = getAnalysisTraceSnapshot(sessionId, { auditId: ctx.auditId });
    const liveCoverage = decisionCoverage(ctx, ledgerSnapshot, traceSnapshot);
    const decisionSnapshot = ledgerSnapshot.decisionSnapshot || buildTrustedDecisionSnapshot({
        auditId: ctx.auditId,
        findings: ledgerSnapshot.findingLedger.findings,
        traceSnapshot,
        validationSnapshot: ledgerSnapshot.validation,
        coverage: liveCoverage,
    });
    const blockers = [...decisionSnapshot.blockers];
    if (!ledgerSnapshot.decisionSnapshot) {
        blockers.push({ code: "validated-decision-snapshot-missing" });
    }
    if (stageState.current !== "validated") {
        blockers.push({
            code: "analysis-stage-not-validated",
            currentStage: stageState.current,
        });
    }
    for (const [gate, complete] of Object.entries(liveCoverage)) {
        if (!complete) {
            blockers.push({
                code: `${gate.replace(/[A-Z]/gu, (match) =>
                    `-${match.toLowerCase()}`)}-live-incomplete`,
            });
        }
    }
    if (acquisitionCoverage?.requiredAcquisitionComplete === false) {
        blockers.push({
            code: "required-acquisition-incomplete",
            blockers: acquisitionCoverage.blockers,
            ...(acquisitionCoverage.details
                ? { details: acquisitionCoverage.details }
                : {}),
        });
    }
    if (releaseAssetCoverage?.requiredReleaseAssetAcquisitionComplete === false) {
        blockers.push({
            code: "required-release-asset-acquisition-incomplete",
            blockers: releaseAssetCoverage.blockers,
            ...(releaseAssetCoverage.details
                ? { details: releaseAssetCoverage.details }
                : {}),
        });
    }
    const trustedVerdict = !!ledgerSnapshot.decisionSnapshot
        && stageState.current === "validated"
        && decisionSnapshot.overallVerdictEligibility.trustedDecisionEligible === true
        && Object.values(liveCoverage).every(Boolean)
        && acquisitionCoverage?.requiredAcquisitionComplete !== false
        && releaseAssetCoverage?.requiredReleaseAssetAcquisitionComplete !== false;
    const verdict = trustedVerdict
        ? decisionSnapshot.overallVerdictEligibility.recommendedVerdict
        : "incomplete";

    const recordedOutcome = getRecordedOutcome(sessionId);
    const activeIdentity = {
        auditId: ctx.auditId,
        owner: ctx.owner || null,
        repo: ctx.repo || null,
        resolvedSha: ctx.resolvedSha || null,
    };
    if (!councilOutcomeMatchesAudit(recordedOutcome, activeIdentity)) {
        return {
            ok: false,
            error:
                "finalize_report refused: council mode requires an identity-matching zerotrust_record_council_outcome result for the current immutable audit before finalization",
        };
    }
    const expectedOutcome = {
        verdict,
        criticalCount: decisionSnapshot.severityCounts.active.critical,
        highCount: decisionSnapshot.severityCounts.active.high,
        complete: trustedVerdict,
    };
    if (recordedOutcome.verdict !== expectedOutcome.verdict
        || recordedOutcome.criticalCount !== expectedOutcome.criticalCount
        || recordedOutcome.highCount !== expectedOutcome.highCount
        || recordedOutcome.complete !== expectedOutcome.complete) {
        return {
            ok: false,
            error:
                "finalize_report refused: recorded council outcome conflicts with the trusted ledger decision",
            data: {
                recordedOutcome: renderRecordedOutcome(recordedOutcome),
                expectedOutcome,
            },
        };
    }

    let document;
    let findingsJson;
    let markdown;
    try {
        const knownSourceStrings = collectIndexedFactStrings(
            sessionId,
            ctx.auditId,
            args.operator_decisions || [],
        );
        document = buildFindingsArtifact({
            context: ctx,
            reportIdentity,
            decisionSnapshot,
            ledgerSnapshot,
            traceSnapshot,
            analysisIndex: ctx.analysisIndex,
            analysisPlugins: ctx.analysisPlugins,
            stageState,
            cacheBinding,
            acquisitionCoverage,
            releaseAssetCoverage,
            blockers,
            verdict,
            trustedVerdict,
            operatorDecisions: args.operator_decisions || [],
            knownSourceStrings,
        });
        findingsJson = serializeFindingsArtifact(document);
        const findingsSha256 = sha256(findingsJson);
        markdown = renderFindingsMarkdown({
            document,
            findingsSha256,
        });
        markdown = appendTrustedCoverageSnapshots(
            markdown,
            document.coverage.acquisition,
            document.coverage.releaseAssets,
        );
        assertMarkdownFindingsConsistency(markdown, document);
    } catch (error) {
        return {
            ok: false,
            error: `finalize_report refused: trusted ledger rendering failed: ${error.message}`,
        };
    }
    return {
        ok: true,
        recordedOutcome,
        artifacts: {
            flow: "v5-ledger",
            ledgerDecisionId: decisionSnapshot.decisionId,
            document,
            findingsJson,
            markdown,
        },
    };
}

function collectIndexedFactStrings(sessionId, auditId, operatorDecisions) {
    if (!(operatorDecisions || []).some((decision) =>
        Object.hasOwn(decision || {}, "operator_rationale"))) {
        return [];
    }
    const values = [];
    let cursor = 0;
    do {
        const page = listAnalysisFacts(sessionId, {
            auditId,
            cursor,
            limit: 256,
        });
        for (const fact of page.facts || []) {
            if (typeof fact.name === "string") values.push(fact.name);
            if (typeof fact.value === "string") values.push(fact.value);
        }
        cursor = page.nextCursor;
    } while (cursor !== null);
    return values;
}

function decisionCoverage(ctx, ledgerSnapshot, traceSnapshot) {
    const submitted = new Set(
        (ledgerSnapshot.submissions || []).map((entry) => entry.roleId),
    );
    const successful = ledgerSnapshot.finalization?.successfulRoleIds || [];
    const councilComplete = !!ledgerSnapshot.finalization
        && successful.length === submitted.size
        && successful.every((roleId) => submitted.has(roleId));
    const validation = ledgerSnapshot.validation;
    return {
        acquisitionComplete: ctx.analysisIndex?.complete === true,
        indexComplete: ctx.analysisIndex?.complete === true,
        pluginCoverageComplete: ctx.analysisPlugins?.coverageComplete === true,
        councilComplete,
        traceComplete: traceSnapshot?.coverageComplete === true
            && Object.values(traceSnapshot?.gates || {}).every(Boolean)
            && !Object.values(traceSnapshot?.truncation || {}).some(Boolean),
        validationComplete: validation?.completion?.complete === true
            && !Object.values(validation?.truncation || {}).some(Boolean)
            && !!validation?.finalization,
        cacheTrackingComplete: true,
    };
}

function buildLegacyArtifacts({
    args,
    ctx,
    reportIdentity,
    acquisitionCoverage,
    releaseAssetCoverage,
    cacheBinding,
}) {
    const allowed = new Set([
        "owner",
        "repo",
        "resolved_sha",
        "build_root",
        "markdown_body",
    ]);
    const unexpected = Object.keys(args).filter((key) => !allowed.has(key));
    if (unexpected.length > 0) {
        return {
            ok: false,
            error: `legacy finalization does not accept arguments: ${unexpected.join(", ")}`,
        };
    }
    if (typeof args.markdown_body !== "string") {
        return { ok: false, error: "markdown_body is required for legacy finalization" };
    }
    const inputBytes = Buffer.byteLength(args.markdown_body, "utf8");
    if (inputBytes > MAX_REPORT_BYTES) {
        return {
            ok: false,
            error: `final report exceeds ${MAX_REPORT_BYTES} bytes`,
        };
    }
    if (inputBytes === MAX_REPORT_BYTES) {
        return {
            ok: false,
            error:
                `final report exceeds ${MAX_REPORT_BYTES} bytes after trusted dual-artifact binding`,
        };
    }
    const declarations = extractDeclaredVerdictDeclarations(args.markdown_body);
    if (modeUsesApiDirect(ctx.mode)
        && acquisitionCoverage?.requiredAcquisitionComplete !== true
        && (declarations.length !== 1 || declarations[0] !== "incomplete")) {
        return {
            ok: false,
            error:
                "finalize_report refused: incomplete mandatory acquisition coverage permits only verdict 'incomplete'; no trusted critical/high/medium/low/no-red-flags verdict may be finalized. Fetch every enumerated blob with coverage_scope='mandatory'; each must be byte-classified, and every text result must be fully returned and invisible-Unicode scanned. Otherwise report the audit as incomplete.",
            data: { acquisitionCoverage },
        };
    }
    if (ctx.mode === "verify_release"
        && releaseAssetCoverage?.requiredReleaseAssetAcquisitionComplete !== true
        && (declarations.length !== 1 || declarations[0] !== "incomplete")) {
        return {
            ok: false,
            error:
                "finalize_report refused: incomplete release-asset coverage permits only verdict 'incomplete'. List the already-bound release through zerotrust_safe_list_release_assets and successfully fetch/hash every enumerated asset through zerotrust_safe_fetch_release_asset; otherwise report the audit as incomplete.",
            data: { acquisitionCoverage, releaseAssetCoverage },
        };
    }
    if (declarations.length > 1) {
        return {
            ok: false,
            error: "legacy report must not contain multiple verdict declarations",
            data: { declaredVerdicts: declarations },
        };
    }
    const verdict = declarations[0]
        || (ctx.mode === "metadata_only" ? "reconnaissance only" : "incomplete");
    const blockers = [];
    if (acquisitionCoverage?.requiredAcquisitionComplete === false) {
        blockers.push({
            code: "required-acquisition-incomplete",
            blockers: acquisitionCoverage.blockers,
            ...(acquisitionCoverage.details
                ? { details: acquisitionCoverage.details }
                : {}),
        });
    }
    if (releaseAssetCoverage?.requiredReleaseAssetAcquisitionComplete === false) {
        blockers.push({
            code: "required-release-asset-acquisition-incomplete",
            blockers: releaseAssetCoverage.blockers,
            ...(releaseAssetCoverage.details
                ? { details: releaseAssetCoverage.details }
                : {}),
        });
    }
    let document;
    let findingsJson;
    try {
        document = buildLegacyFindingsArtifact({
            context: ctx,
            reportIdentity,
            stageState: ctx.analysisStageState,
            cacheBinding,
            acquisitionCoverage,
            releaseAssetCoverage,
            blockers,
            verdict,
        });
        findingsJson = serializeFindingsArtifact(document);
    } catch (error) {
        return {
            ok: false,
            error: `legacy FINDINGS.json assembly failed: ${error.message}`,
        };
    }
    const findingsSha256 = sha256(findingsJson);
    const markdown = appendLegacyArtifactBinding(
        appendTrustedCoverageSnapshots(
            args.markdown_body,
            acquisitionCoverage,
            releaseAssetCoverage,
        ),
        document,
        findingsSha256,
    );
    return {
        ok: true,
        artifacts: {
            flow: "legacy-v4",
            ledgerDecisionId: null,
            document,
            findingsJson,
            markdown,
        },
    };
}

function returnRecordedPair({
    ctx,
    sessionId,
    reportPath,
    findingsPath,
    dependencies,
}) {
    const record = ctx.reportFinalization;
    if (record.auditId !== ctx.auditId
        || !pathsEqual(record.reportPath, reportPath)
        || !pathsEqual(record.findingsPath, findingsPath)) {
        return failure(
            "finalize_report refused: recorded finalization identity conflicts with the active audit's canonical artifact pair",
        );
    }
    const io = buildIo(dependencies);
    const missing = [reportPath, findingsPath].filter((path) => !io.exists(path));
    if (missing.length > 0) {
        return failure(
            "finalize_report refused: this audit was already finalized, but a recorded artifact is missing; exactly-once finalization will not recreate it",
            { missing },
        );
    }
    let report;
    let findings;
    try {
        report = readArtifactIdentity(reportPath, io);
        findings = readArtifactIdentity(findingsPath, io);
    } catch (error) {
        return failure(`finalize_report refused: recorded artifact verification failed: ${error.message}`);
    }
    if (report.sha256 !== record.contentSha256
        || report.bytes !== record.bytesWritten
        || findings.sha256 !== record.findingsSha256
        || findings.bytes !== record.findingsBytesWritten) {
        return failure(
            "finalize_report refused: a recorded report artifact changed after exactly-once finalization",
            {
                expected: {
                    reportSha256: record.contentSha256,
                    reportBytes: record.bytesWritten,
                    findingsSha256: record.findingsSha256,
                    findingsBytes: record.findingsBytesWritten,
                },
                observed: {
                    reportSha256: report.sha256,
                    reportBytes: report.bytes,
                    findingsSha256: findings.sha256,
                    findingsBytes: findings.bytes,
                },
            },
        );
    }
    let analysisStageAfter = ctx.analysisStageState?.current || null;
    if (record.flow === "v5-ledger" && analysisStageAfter === "validated") {
        try {
            analysisStageAfter = advanceAnalysisStage(sessionId, {
                auditId: ctx.auditId,
                from: "validated",
                to: "finalized",
            }).current;
        } catch (error) {
            return failure(
                `finalize_report verified the recorded pair but could not advance validated to finalized: ${error.message}`,
            );
        }
    }
    return success({
        reportPath: record.reportPath,
        findingsPath: record.findingsPath,
        bytesWritten: record.bytesWritten,
        findingsBytesWritten: record.findingsBytesWritten,
        reportSha256: record.contentSha256,
        findingsSha256: record.findingsSha256,
        reportIdentity: record.reportIdentity,
        flow: record.flow,
        ledgerDecisionId: record.ledgerDecisionId,
        analysisStageAfter,
        alreadyFinalized: true,
    });
}

function buildIo(dependencies) {
    return {
        exists: dependencies.exists || existsSync,
        mkdir: dependencies.mkdir || mkdirSync,
        open: dependencies.open || openSync,
        write: dependencies.write || writeFileSync,
        fsync: dependencies.fsync || fsyncSync,
        close: dependencies.close || closeSync,
        publish: dependencies.publish || defaultPublishExclusive,
        unlink: dependencies.unlink || unlinkSync,
        read: dependencies.read || readFileSync,
    };
}

function writeDurableTemp(path, body, io) {
    let fd = null;
    try {
        fd = io.open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
        io.write(fd, body, { encoding: "utf8" });
        io.fsync(fd);
    } finally {
        if (fd !== null) io.close(fd);
    }
}

function defaultPublishExclusive(tempPath, destinationPath) {
    linkSync(tempPath, destinationPath);
    try {
        unlinkSync(tempPath);
    } catch (error) {
        try {
            unlinkSync(destinationPath);
        } catch {
            // The caller will report both paths and fail closed.
        }
        throw error;
    }
}

function safeUnlink(path, io) {
    if (!io.exists(path)) return { existed: false, removed: false };
    try {
        io.unlink(path);
        return { existed: true, removed: !io.exists(path) };
    } catch (error) {
        return { existed: true, removed: false, error: error.message };
    }
}

function rollbackCanonicalPair(paths, io) {
    return Object.fromEntries(paths.map((path) => [path, safeUnlink(path, io)]));
}

function createArtifactPair({
    reportPath,
    findingsPath,
    reportBody,
    findingsBody,
    io,
}) {
    const token = randomUUID();
    const reportTemp = nodePath.join(nodePath.dirname(reportPath), `.REPORT.${token}.tmp`);
    const findingsTemp = nodePath.join(nodePath.dirname(findingsPath), `.FINDINGS.${token}.tmp`);
    const published = [];
    try {
        writeDurableTemp(reportTemp, reportBody, io);
        writeDurableTemp(findingsTemp, findingsBody, io);
        if (io.exists(reportPath) || io.exists(findingsPath)) {
            throw new Error("a canonical artifact appeared before exclusive pair publication");
        }
        io.publish(findingsTemp, findingsPath, { index: 0 });
        published.push(findingsPath);
        io.publish(reportTemp, reportPath, { index: 1 });
        published.push(reportPath);
        const report = readArtifactIdentity(reportPath, io);
        const findings = readArtifactIdentity(findingsPath, io);
        if (report.sha256 !== sha256(reportBody) || findings.sha256 !== sha256(findingsBody)) {
            throw new Error("artifact read-back hash mismatch");
        }
        return { ok: true, report, findings };
    } catch (error) {
        const rollback = rollbackCanonicalPair(published.reverse(), io);
        safeUnlink(reportTemp, io);
        safeUnlink(findingsTemp, io);
        return { ok: false, error: error.message, rollback };
    } finally {
        safeUnlink(reportTemp, io);
        safeUnlink(findingsTemp, io);
    }
}

function readArtifactIdentity(path, io) {
    const bytes = io.read(path);
    const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), "utf8");
    return {
        bytes: buffer.byteLength,
        sha256: createHash("sha256").update(buffer).digest("hex"),
    };
}

function pairResult({
    reportPath,
    findingsPath,
    reportIdentity,
    creation,
    artifacts,
    alreadyFinalized,
    analysisStageAfter,
}) {
    return {
        reportPath,
        findingsPath,
        bytesWritten: creation.report.bytes,
        findingsBytesWritten: creation.findings.bytes,
        reportSha256: creation.report.sha256,
        findingsSha256: creation.findings.sha256,
        reportIdentity,
        flow: artifacts.flow,
        ledgerDecisionId: artifacts.ledgerDecisionId,
        verdict: artifacts.document.verdict.value,
        trustedVerdict: artifacts.document.verdict.trusted,
        analysisStageAfter,
        alreadyFinalized,
    };
}

function buildLocalReportPath(buildRoot, slug, timestamp) {
    if (typeof slug !== "string" || !/^[a-z0-9][a-z0-9._-]{0,59}$/.test(slug)) {
        throw new Error(`invalid local report slug: ${slug}`);
    }
    if (typeof timestamp !== "string" || !/^[0-9]{14}$/.test(timestamp)) {
        throw new Error(`invalid local report timestamp: ${timestamp}`);
    }
    const resolvedRoot = nodePath.resolve(buildRoot);
    const candidate = nodePath.resolve(
        resolvedRoot,
        "_reports",
        `local-${slug}-${timestamp}`,
    );
    const rel = nodePath.relative(resolvedRoot, candidate);
    if (rel.startsWith("..") || nodePath.isAbsolute(rel)) {
        throw new Error(`local report path ${candidate} would escape build_root`);
    }
    return candidate;
}

function pathsEqual(left, right) {
    if (typeof left !== "string" || typeof right !== "string") return false;
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function appendTrustedCoverageSnapshot(markdown, acquisitionCoverage) {
    const body = String(markdown).replace(/\s+$/u, "");
    if (!acquisitionCoverage) return `${body}\n`;
    const json = escapeHtml(JSON.stringify(acquisitionCoverage, null, 2));
    return `${body}\n\n## Trusted acquisition coverage snapshot\n\n`
        + "<!-- Generated by zerotrust_finalize_report from active-audit state. -->\n"
        + `<pre>${json}</pre>\n`;
}

function appendTrustedCoverageSnapshots(markdown, acquisitionCoverage, releaseAssetCoverage) {
    let body = appendTrustedCoverageSnapshot(markdown, acquisitionCoverage).replace(/\s+$/u, "");
    if (!releaseAssetCoverage) return `${body}\n`;
    const json = escapeHtml(JSON.stringify(releaseAssetCoverage, null, 2));
    body += "\n\n## Trusted release-asset coverage snapshot\n\n"
        + "<!-- Generated by zerotrust_finalize_report from active-audit state. -->\n"
        + `<pre>${json}</pre>`;
    return `${body}\n`;
}

function appendLegacyArtifactBinding(markdown, document, findingsSha256) {
    const body = String(markdown).replace(/\s+$/u, "");
    return `${body}\n\n## Trusted dual-artifact binding\n\n`
        + "- **Flow:** legacy-v4 compatibility\n"
        + `- **FINDINGS.json SHA-256:** ${findingsSha256}\n`
        + `- **Findings document ID:** ${document.documentId}\n`
        + `- **Legacy declared verdict:** ${document.verdict.value}\n`;
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

function extractDeclaredVerdicts(markdown) {
    return [...new Set(extractDeclaredVerdictDeclarations(markdown))];
}

function extractDeclaredVerdictDeclarations(markdown) {
    const verdicts =
        "critical|high|medium|low|no red flags found|incomplete|reconnaissance only";
    const re = new RegExp(`^Verdict\\s*:\\s*(${verdicts})(?:\\s*[.!])?$`, "i");
    const found = [];
    for (const line of String(markdown || "").split(/\r?\n/u)) {
        const normalized = line
            .replace(/^\s*(?:(?:#{1,6}\s*)|(?:[-+*]\s+)|(?:\d+[.)]\s+))*/u, "")
            .replace(/[*_`]+/gu, "")
            .replace(/\s+/gu, " ")
            .trim();
        const match = normalized.match(re);
        if (match) found.push(match[1].toLowerCase());
    }
    return found;
}

function extractDeclaredVerdict(markdown) {
    const verdicts = extractDeclaredVerdicts(markdown);
    if (verdicts.includes("no red flags found")) return "no red flags found";
    return verdicts[0] || null;
}

function extractDeclaredCouncilCompletionStates(markdown) {
    const re = /^Council coverage complete\s*:\s*(true|false)(?:\s*[.!])?$/i;
    const found = [];
    for (const line of String(markdown || "").split(/\r?\n/u)) {
        const normalized = line
            .replace(/^\s*(?:(?:#{1,6}\s*)|(?:[-+*]\s+)|(?:\d+[.)]\s+))*/u, "")
            .replace(/[*_`]+/gu, "")
            .replace(/\s+/gu, " ")
            .trim();
        const match = normalized.match(re);
        if (match) found.push(match[1].toLowerCase() === "true");
    }
    return found;
}

function renderRecordedOutcome(outcome) {
    return {
        auditId: outcome.auditId,
        verdict: outcome.verdict,
        criticalCount: outcome.criticalCount,
        highCount: outcome.highCount,
        complete: outcome.complete,
    };
}

function sha256(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}

function coverageResult(acquisitionCoverage, releaseAssetCoverage) {
    return {
        ...(acquisitionCoverage ? { acquisitionCoverage } : {}),
        ...(releaseAssetCoverage ? { releaseAssetCoverage } : {}),
    };
}

export const __internals = {
    HASH_RE,
    MAX_REPORT_BYTES,
    appendTrustedCoverageSnapshot,
    appendTrustedCoverageSnapshots,
    buildCouncilArtifacts,
    buildLegacyArtifacts,
    buildLocalReportPath,
    createArtifactPair,
    decisionCoverage,
    extractDeclaredCouncilCompletionStates,
    extractDeclaredVerdict,
    extractDeclaredVerdictDeclarations,
    extractDeclaredVerdicts,
    readArtifactIdentity,
    rollbackCanonicalPair,
};
