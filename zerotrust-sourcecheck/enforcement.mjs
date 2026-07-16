// enforcement.mjs — audit-in-progress state machine + (unregistered)
// onPreToolUse hook logic.
//
// Two distinct concerns live in this file:
//
//   1. The active-audit state machine (activateAudit, getActiveAudit,
//      deactivateAudit, recordResolvedClonePath, recordResolvedSha,
//      getTrustedAuditContext). This is REAL, LOAD-BEARING code: the
//      safeWrappers/* tools call into it to decide whether a clone /
//      install / build / fetch is bound to a trusted, in-flight audit
//      with a matching build_root, owner/repo, and resolved SHA. Without
//      this state the wrappers can't tell a legitimate audit apart from
//      an opportunistic invocation.
//
//   2. The preToolUseHook function at the bottom of the file. This was
//      designed as a second-layer defence — even if the agent ignored
//      the packet, the hook would intercept dangerous shell calls before
//      they ran on the operator's host. Empirically, the tested Copilot CLI
//      runtime does not invoke onPreToolUse for built-in tools (powershell,
//      view, glob, grep), despite the SDK contract. This repository does not
//      record a public issue URL.
//
//      The extension no longer registers this hook in extension.mjs.
//      Registering hooks at all triggers an "extension wants elevated
//      permissions: register hooks" prompt at every CLI launch (the
//      class includes see-every-tool-input, modify-tool-input, and run
//      arbitrary code on every invocation), and we don't want to ask
//      operators for a capability the extension doesn't actually need.
//      The function is still EXPORTED so the unit tests in
//      __tests__/enforcement.test.mjs continue to pin the deny policy as
//      executable documentation, and so that if a future CLI release
//      offers a narrower opt-in deny-only hook surface the policy is
//      already written.
//
// State model: the handler activates an audit by recording { sessionId,
// buildPath, mode, expiresAt } in an in-memory Map. While an audit is
// active for a session, the wrappers apply strict rules to any audit-
// dangerous tool call. The audit auto-expires after the mode-specific
// TTL so a forgotten audit doesn't leave the session permanently locked
// down; TTL expiry also clears the recorded council outcome to prevent
// a passing outcome from one audit satisfying a different mode's gate.

import nodePath from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import {
    BUILD_MODES_SET as SHARED_BUILD_MODES,
    FULL_BUILD_MODES_SET as SHARED_FULL_BUILD_MODES,
    modeNeedsClone as SHARED_modeNeedsClone,
    modeUsesApiDirect,
    modeUsesCouncil,
    modeUsesLocalSource,
} from "./modes.mjs";
import { slugForPath } from "./localPathValidator.mjs";
import {
    buildQuarantinePath,
    buildReportPath,
    parseGithubUrl,
} from "./urlParser.mjs";
import {
    clearCacheBinding,
    clearCouncilLedgerState,
    clearRecordedOutcome,
    getCouncilLedgerSnapshot,
    mutateCouncilLedgerState,
} from "./safeWrappers/state.mjs";
import {
    ANALYSIS_SCHEMA_REVISION,
    ANALYSIS_STAGES,
    ASSURANCE_ANALYSIS_SCHEMA_REVISION,
    createInitialAnalysisStageState,
    createInitialAssuranceStageState,
    createAssuranceAnalysisSnapshot,
    transitionAssuranceStageState,
    validateAnalysisStageState,
    validateAuditId,
    validateAssuranceAnalysisSnapshot,
    validateAssuranceStageState,
} from "./analysis/schemas.mjs";
import { buildTrustedDecisionSnapshot } from "./analysis/scoring.mjs";
import { generateRemediationPlan } from "./analysis/remediation.mjs";
import { BehaviorGraph } from "./analysis/behaviorGraph.mjs";
import { mergeBehaviorGraphs } from "./analysis/graphMerge.mjs";
import { traceBehaviorGraph } from "./analysis/traceGraph.mjs";
import {
    buildAnalysisIndexSnapshot,
    createAnalysisIndexState,
    listIndexedFacts,
} from "./analysis/indexState.mjs";
import {
    buildPluginCacheRecords,
    buildPluginRunnerSnapshot,
    createPluginRunnerState,
    runAnalysisPlugins,
} from "./analysis/plugins/runner.mjs";
import {
    buildValidationPlan,
    buildValidationSnapshot,
    createValidationState,
    finalizeValidationState,
    normalizeValidationMinSeverity,
    pageValidationContexts,
    storeAdjudication,
    storeStaticDecision,
    validateAdjudicationSubmission,
    validateStaticDecisionSubmission,
} from "./analysis/validation.mjs";
import {
    applySemanticCoverageToSnapshot,
    createSemanticCoveragePlan,
    createSemanticReviewAssignment,
    createSemanticReviewRecord,
    createSemanticScannerCoverageRecord,
    evaluateSemanticCoverage,
    semanticSnapshotCanAdvance,
    validateSemanticCoveragePlan,
    validateSemanticReviewAssignment,
    validateSemanticReviewRecord,
} from "./analysis/semanticCoverage.mjs";
import {
    applyRedTeamCoverageToSnapshot,
    createRedTeamAssignment,
    createRedTeamPlan,
    createRedTeamReviewRecord,
    createRedTeamScannedSnapshot,
    evaluateRedTeamCoverage,
    redTeamSnapshotCanAdvance,
    validateRedTeamAssignment,
    validateRedTeamPlan,
    validateRedTeamReviewRecord,
} from "./analysis/redTeam.mjs";
import { validateSupplyChainGraph } from "./analysis/supplyChainGraph.mjs";
import {
    buildEvasiveGraph,
} from "./analysis/evasiveGraph.mjs";
import {
    traceEvasiveGraph,
    evasiveTraceCanAdvance,
    validateEvasiveTrace,
} from "./analysis/evasiveTrace.mjs";
import {
    createAssuranceValidationPlan,
    createAssuranceValidationRecord,
    evaluateAssuranceValidation,
    listAssuranceValidationAssignmentKeys,
    assuranceValidationCanAdvance,
    validateAssuranceValidationPlan,
    validateAssuranceValidationRecord,
} from "./analysis/assuranceValidation.mjs";
import { validateEvasiveGraphPlan } from "./analysis/evasiveGraphSchemas.mjs";

// TTL is mode-dependent. The 30-minute default silently expired during
// real audit_source_council runs (15-30 min wall-clock) — once expiresAt
// passed, getActiveAudit() returned null, the safeWrappers/* tools refused
// (or fell back to default-build-root behaviour) for the rest of the
// session, and any session-end cleanup that would have hit the audit
// became a no-op. New per-mode TTLs leave generous headroom for retries
// and slow networks.
// Add TTL entries for the new local-source modes.
const AUDIT_TTL_MS_BY_MODE = {
    "metadata_only": 15 * 60 * 1000,
    "audit_source": 60 * 60 * 1000,
    "audit_source_council": 90 * 60 * 1000,
    "audit_local_source": 60 * 60 * 1000,
    "audit_local_source_council": 90 * 60 * 1000,
    "verify_release": 30 * 60 * 1000,
    "audit_and_safe_build": 120 * 60 * 1000,
    "audit_and_full_build": 120 * 60 * 1000,
    "audit_and_safe_build_council": 180 * 60 * 1000,
    "audit_and_full_build_council": 180 * 60 * 1000,
};

// Fallback for any future mode that's not in the map yet — generous default
// so a forgotten table entry doesn't reintroduce the silent-expiry regression.
const AUDIT_TTL_MS_DEFAULT = 90 * 60 * 1000;

function ttlForMode(mode) {
    return AUDIT_TTL_MS_BY_MODE[mode] ?? AUDIT_TTL_MS_DEFAULT;
}

// Mode taxonomy is centralized in modes.mjs; these aliases preserve source
// compatibility with the rest of this file.
const BUILD_MODES = SHARED_BUILD_MODES;
const FULL_BUILD_MODES = SHARED_FULL_BUILD_MODES;

const activeAudits = new Map(); // sessionId -> active audit identity + lifecycle state

function analysisSourceKindForMode(mode) {
    if (mode === "metadata_only") return "metadata-only";
    if (modeUsesLocalSource(mode)) return "local-source";
    if (SHARED_modeNeedsClone(mode)) return "build-clone";
    if (modeUsesApiDirect(mode)) return "api-direct";
    return "metadata-only";
}

function sourceNamespaceForAudit(audit) {
    if (modeUsesLocalSource(audit.mode)) return `local-audit:${audit.auditId}`;
    if (audit.owner && audit.repo && audit.resolvedSha) {
        return `github.com/${audit.owner}/${audit.repo}@${audit.resolvedSha}`;
    }
    return `audit:${audit.auditId}`;
}

function pathsEqual(left, right) {
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase(): a === b;
}

function deriveLocalReportIdentity(buildPath, localPath, expectedReportPath) {
    if (!expectedReportPath) return null;
    const slug = slugForPath(localPath);
    const basename = nodePath.basename(nodePath.resolve(expectedReportPath));
    const prefix = `local-${slug}-`;
    if (!basename.startsWith(prefix)) return null;
    const timestamp = basename.slice(prefix.length);
    if (!/^[0-9]{14}$/.test(timestamp)) return null;
    const canonicalPath = nodePath.resolve(
        buildPath,
        "_reports",
        `local-${slug}-${timestamp}`,
    );
    if (!pathsEqual(canonicalPath, expectedReportPath)) return null;
    return { slug, timestamp };
}

function normalizeCouncilRoleManifest(value) {
    if (value === null || value === undefined) return null;
    if (!Array.isArray(value) || value.length === 0) {
        throw new Error("councilRoleManifest must be a non-empty array when provided");
    }
    const seen = new Set();
    return Object.freeze(value.map((role, index) => {
        const id = String(role?.id || "");
        const category = String(role?.category || "");
        if (!/^[a-z][a-z0-9-]{2,63}$/.test(id)) {
            throw new Error(`invalid council role id at index ${index}`);
        }
        if (!/^[A-G]$/.test(category)) {
            throw new Error(`invalid council role category for ${id}`);
        }
        if (seen.has(id)) throw new Error(`duplicate council role id: ${id}`);
        seen.add(id);
        return Object.freeze({
            id,
            category,
            mandatory: role?.mandatory === true,
        });
    }));
}

/**
 * Activate an audit-in-progress state for a session. Called by the tool
 * handler before returning the instruction packet.
 *
 * `buildPath` is the canonical build root (e.g. ~/.copilot/zerotrust-sandbox).
 * `expectedClonePath` is the specific subdirectory the packet has authorized
 * for the clone.
 */
export function activateAudit({
    sessionId,
    buildPath,
    mode,
    expectedClonePath,
    owner,
    repo,
    ref,
    refType,
    urlKind,
    releaseSelector,
    localPath,
    expectedReportPath,
    expectedQuarantinePath,
    councilRoleManifest,
    validationMinSeverity = "high",
}) {
    if (!sessionId) throw new Error("activateAudit requires sessionId");
    if (!buildPath) throw new Error("activateAudit requires buildPath");
    const effectiveMode = mode || "audit_source";

    // Local-source modes don't have a clone path (they read from an
    // operator-supplied on-disk directory). They DO have a localPath
    // we pin so the wrappers can detect this audit shape.
    const isLocal = effectiveMode === "audit_local_source"
        || effectiveMode === "audit_local_source_council";

    if (!isLocal && !expectedClonePath) {
        throw new Error("activateAudit requires expectedClonePath (non-local-source modes)");
    }
    if (isLocal && !localPath) {
        throw new Error("activateAudit requires localPath (local-source modes)");
    }

    const resolvedBuildPath = nodePath.resolve(buildPath);
    const resolvedLocalPath = localPath ? nodePath.resolve(localPath): null;
    const resolvedReportPath = expectedReportPath
        ? nodePath.resolve(expectedReportPath): null;
    const localReportIdentity = isLocal
        ? deriveLocalReportIdentity(
            resolvedBuildPath,
            resolvedLocalPath,
            resolvedReportPath,
        ): null;

    const auditId = randomUUID();
    const audit = {
        buildPath: resolvedBuildPath,
        mode: effectiveMode,
        expiresAt: Date.now() + ttlForMode(effectiveMode),
        // URL-driven audits get expectedClonePath / owner / repo / ref / refType.
        // Local audits get localPath / expectedReportPath. Mutually-exclusive
        // shapes; the audit object carries only the fields appropriate for
        // its mode.
        expectedClonePath: expectedClonePath ? nodePath.resolve(expectedClonePath): null,
        owner: owner ? String(owner).toLowerCase(): null,
        repo: repo ? String(repo).toLowerCase(): null,
        canonicalOwner: owner ? String(owner): null,
        canonicalRepo: repo ? String(repo): null,
        // security rationale: also pin the ref so safe_clone
        // refuses to clone a different ref of the same repo. Null ref means
        // "no specific ref pinned at activation time" (e.g. the user passed
        // a bare repo URL with no /tree/<ref>); in that case safe_clone
        // accepts any ref.
        ref: ref ? String(ref): null,
        refType: refType ? String(refType): null,
        urlKind: urlKind ? String(urlKind): null,
        releaseSelector: releaseSelector ? String(releaseSelector): null,
        // Local-source fields.
        localPath: resolvedLocalPath,
        localReportSlug: localReportIdentity?.slug || null,
        localReportTimestamp: localReportIdentity?.timestamp || null,
        expectedReportPath: resolvedReportPath,
        expectedQuarantinePath: expectedQuarantinePath ? nodePath.resolve(expectedQuarantinePath): null,
        councilRoleManifest: modeUsesCouncil(effectiveMode)
            ? normalizeCouncilRoleManifest(councilRoleManifest): null,
        validationMinSeverity: modeUsesCouncil(effectiveMode)
            ? normalizeValidationMinSeverity(validationMinSeverity): "high",
    };
    Object.defineProperty(audit, "auditId", {
        value: auditId,
        enumerable: true,
        writable: false,
        configurable: false,
    });
    audit.analysisStageState = createInitialAnalysisStageState(auditId);
    audit.analysisIndexState = createAnalysisIndexState({
        auditId,
        sourceKind: analysisSourceKindForMode(effectiveMode),
    });
    audit.behaviorGraph = new BehaviorGraph({ auditId });
    audit.analysisPluginState = createPluginRunnerState({ auditId });
    audit.analysisTraceState = null;
    audit.assurance = createEmptyAssuranceState(audit);
    clearRecordedOutcome(sessionId);
    clearCouncilLedgerState(sessionId);
    clearCacheBinding(sessionId);
    activeAudits.set(sessionId, audit);
    return auditId;
}

export function deactivateAudit(sessionId) {
    clearCouncilLedgerState(sessionId);
    clearCacheBinding(sessionId);
    return activeAudits.delete(sessionId);
}

/**
 * Record the actual resolved clone path for an active audit, after safe_clone
 * has resolved the SHA and physically created the clone directory. Subsequent
 * install/build/cleanup/finalize_report calls cross-check args.clone_path
 * against this recorded value to ensure the wrapper operates on the audit's
 * own clone rather than some other sibling directory under build_root.
 *
 * Constraining operations only to paths under build_root is insufficient;
 * they must also be bound to the specific clone
 * for the active audit. Without binding, a session activated for repo A
 * could be tricked into building a sibling repo-B directory in the same
 * sandbox, attaching audit-A's council outcome to a different target.
 */
export function recordResolvedClonePath(sessionId, resolvedClonePath) {
    const audit = activeAudits.get(sessionId);
    if (!audit) return false;
    if (audit.expiresAt < Date.now()) return false;
    if (typeof resolvedClonePath !== "string" || !nodePath.isAbsolute(resolvedClonePath)) {
        return false;
    }
    const normalizedPath = nodePath.resolve(resolvedClonePath);
    if (pathsEqual(normalizedPath, audit.buildPath)
        || !pathIsUnder(audit.buildPath, normalizedPath)) {
        return false;
    }
    if (audit.resolvedClonePath) {
        return pathsEqual(audit.resolvedClonePath, normalizedPath);
    }
    audit.resolvedClonePath = normalizedPath;
    return true;
}

// security rationale: record the resolved commit SHA when
// safe_list_tree pins the audit to a specific commit. Subsequent
// safe_fetch_file calls must use this same SHA — so a malicious file
// in the audited tree can't trick the agent into fetching from a
// different commit and reporting under the pinned audit's identity.
export function recordResolvedSha(sessionId, sha) {
    const audit = activeAudits.get(sessionId);
    if (!audit) return false;
    if (audit.expiresAt < Date.now()) return false;
    if (typeof sha !== "string" || !/^[a-f0-9]{40}$/i.test(sha)) return false;
    // First-write-wins: once a SHA is pinned for the audit, refuse to
    // overwrite (avoids a malicious tree from re-pinning to a different
    // commit mid-audit).
    if (audit.resolvedSha) return audit.resolvedSha.toLowerCase() === sha.toLowerCase();
    const normalizedSha = sha.toLowerCase();
    if (!rebindEmptyAssuranceStateForResolvedSha(audit, normalizedSha)) return false;
    audit.resolvedSha = normalizedSha;
    return true;
}

export function recordReleaseIdentity(sessionId, identity) {
    const audit = activeAudits.get(sessionId);
    if (!audit || audit.expiresAt < Date.now()) return false;
    if (!identity || typeof identity !== "object") return false;
    const normalized = {
        releaseId: String(identity.releaseId || ""),
        tagName: String(identity.tagName || ""),
        sourceCommitSha: String(identity.sourceCommitSha || "").toLowerCase(),
        rootTreeSha: String(identity.rootTreeSha || "").toLowerCase(),
        tagRefSha: String(identity.tagRefSha || "").toLowerCase(),
        tagObjectSha: identity.tagObjectSha ? String(identity.tagObjectSha).toLowerCase(): null,
        annotatedTag: identity.annotatedTag === true,
        tagPeelDepth: Number(identity.tagPeelDepth || 0),
        targetCommitish: typeof identity.targetCommitish === "string"
            && /^[A-Za-z0-9._/-]{1,255}$/.test(identity.targetCommitish)
            ? identity.targetCommitish.slice(0, 255): null,
    };
    const tagSegments = normalized.tagName.split("/");
    if (!/^[1-9][0-9]{0,19}$/.test(normalized.releaseId)
        || !/^[A-Za-z0-9._/-]{1,255}$/.test(normalized.tagName)
        || normalized.tagName.startsWith("/")
        || normalized.tagName.endsWith("/")
        || normalized.tagName.includes("//")
        || tagSegments.some((segment) => segment === "." || segment === "..")
        || !/^[a-f0-9]{40}$/.test(normalized.sourceCommitSha)
        || !/^[a-f0-9]{40}$/.test(normalized.rootTreeSha)
        || !/^[a-f0-9]{40}$/.test(normalized.tagRefSha)
        || (normalized.tagObjectSha && !/^[a-f0-9]{40}$/.test(normalized.tagObjectSha))
        || !Number.isSafeInteger(normalized.tagPeelDepth)
        || normalized.tagPeelDepth < 0
        || normalized.tagPeelDepth > 8) {
        return false;
    }
    if (audit.ref && audit.ref !== normalized.tagName) return false;
    if (audit.releaseIdentity) {
        return JSON.stringify(audit.releaseIdentity) === JSON.stringify(normalized);
    }
    audit.releaseIdentity = normalized;
    return true;
}

export function recordResolvedArtifactPaths(sessionId, { reportPath, quarantinePath } = {}) {
    const audit = activeAudits.get(sessionId);
    if (!audit || audit.expiresAt < Date.now()) return false;
    if (reportPath) {
        const resolvedReportPath = nodePath.resolve(reportPath);
        if (audit.localPath) {
            if (!audit.expectedReportPath
                || !pathsEqual(resolvedReportPath, audit.expectedReportPath)) {
                return false;
            }
        } else {
            if (!audit.canonicalOwner || !audit.canonicalRepo || !audit.resolvedSha) {
                return false;
            }
            const canonicalReportPath = buildReportPath(
                audit.buildPath,
                audit.canonicalOwner,
                audit.canonicalRepo,
                audit.resolvedSha,
            );
            if (!pathsEqual(resolvedReportPath, canonicalReportPath)) return false;
            audit.expectedReportPath = resolvedReportPath;
        }
    }
    if (quarantinePath) {
        if (audit.localPath
            || !audit.canonicalOwner
            || !audit.canonicalRepo
            || !audit.resolvedSha) {
            return false;
        }
        const resolvedQuarantinePath = nodePath.resolve(quarantinePath);
        const canonicalQuarantinePath = buildQuarantinePath(
            audit.buildPath,
            audit.canonicalOwner,
            audit.canonicalRepo,
            audit.resolvedSha,
        );
        if (!pathsEqual(resolvedQuarantinePath, canonicalQuarantinePath)) return false;
        audit.expectedQuarantinePath = resolvedQuarantinePath;
    }
    return true;
}

export function recordReportFinalization(sessionId, finalization) {
    const audit = activeAudits.get(sessionId);
    if (!audit || audit.expiresAt < Date.now()) return false;
    if (!finalization || typeof finalization !== "object") return false;
    if (finalization.auditId !== audit.auditId) return false;
    if (typeof finalization.reportPath !== "string"
        || !nodePath.isAbsolute(finalization.reportPath)) {
        return false;
    }
    if (typeof finalization.findingsPath !== "string"
        || !nodePath.isAbsolute(finalization.findingsPath)) {
        return false;
    }
    const reportPath = nodePath.resolve(finalization.reportPath);
    const findingsPath = nodePath.resolve(finalization.findingsPath);
    if (!audit.expectedReportPath
        || !pathsEqual(nodePath.dirname(reportPath), audit.expectedReportPath)
        || !pathsEqual(nodePath.dirname(findingsPath), audit.expectedReportPath)
        || nodePath.basename(reportPath).toLowerCase() !== "report.md"
        || nodePath.basename(findingsPath).toLowerCase() !== "findings.json") {
        return false;
    }
    const flow = String(finalization.flow || "");
    const ledgerDecisionId = finalization.ledgerDecisionId
        ? String(finalization.ledgerDecisionId): null;
    let trustedOutcome = null;
    if (flow === "trusted-ledger" || flow === "evasive-assurance") {
        const value = finalization.trustedOutcome;
        const expectedSchemaRevision = flow === "trusted-ledger"
            ? ANALYSIS_SCHEMA_REVISION: ASSURANCE_ANALYSIS_SCHEMA_REVISION;
        const allowedVerdicts = flow === "trusted-ledger"
            ? new Set([
                "critical",
                "high",
                "medium",
                "low",
                "no red flags found",
                "incomplete",
            ]): new Set([
                "critical",
                "high",
                "medium",
                "low",
                "info",
                "no supported malicious behavior found",
            ]);
        const severityCounts = value?.severityCounts;
        const assurance = value?.assurance;
        if (!value
            || value.schemaVersion !== expectedSchemaRevision
            || value.outcomeId !== ledgerDecisionId
            || !allowedVerdicts.has(value.verdict)
            || typeof value.complete !== "boolean"
            || !severityCounts
            || ["info", "low", "medium", "high", "critical"].some((severity) =>
                !Number.isSafeInteger(severityCounts[severity])
                || severityCounts[severity] < 0)
            || (flow === "trusted-ledger" && assurance !== null)
            || (flow === "evasive-assurance"
                && (!assurance
                    || ![
                        "unsupported",
                        "partial",
                        "bounded-static",
                        "comprehensive-static",
                        "comprehensive-static-with-supply-chain",
                    ].includes(assurance.level)
                    || typeof assurance.complete !== "boolean"))) {
            return false;
        }
        trustedOutcome = Object.freeze({
            schemaVersion: value.schemaVersion,
            outcomeId: value.outcomeId,
            verdict: value.verdict,
            severityCounts: Object.freeze(Object.fromEntries(
                ["info", "low", "medium", "high", "critical"].map((severity) => [
                    severity,
                    severityCounts[severity],
                ]),
            )),
            complete: value.complete,
            assurance: assurance === null
                ? null: Object.freeze({
                    level: assurance.level,
                    complete: assurance.complete,
                }),
            trusted: true,
        });
    } else if (flow !== "compatibility-report"
        || (finalization.trustedOutcome !== null
            && finalization.trustedOutcome !== undefined)) {
        return false;
    }
    const normalized = Object.freeze({
        auditId: audit.auditId,
        reportPath,
        findingsPath,
        bytesWritten: Number(finalization.bytesWritten) || 0,
        contentSha256: String(finalization.contentSha256 || "").toLowerCase(),
        findingsBytesWritten: Number(finalization.findingsBytesWritten) || 0,
        findingsSha256: String(finalization.findingsSha256 || "").toLowerCase(),
        reportIdentity: structuredClone(finalization.reportIdentity || null),
        flow,
        ledgerDecisionId,
        trustedOutcome,
        stageFinalized: false,
        finalizedAt: Date.now(),
    });
    if (!/^[a-f0-9]{64}$/.test(normalized.contentSha256)
        || !/^[a-f0-9]{64}$/.test(normalized.findingsSha256)
        || !Number.isSafeInteger(normalized.bytesWritten)
        || normalized.bytesWritten < 0
        || !Number.isSafeInteger(normalized.findingsBytesWritten)
        || normalized.findingsBytesWritten < 0
        || !["trusted-ledger", "evasive-assurance", "compatibility-report"].includes(normalized.flow)
        || (normalized.flow === "trusted-ledger"
            && !/^ztd-[a-f0-9]{64}$/u.test(normalized.ledgerDecisionId || ""))
        || (normalized.flow === "evasive-assurance"
            && !/^zto-[a-f0-9]{64}$/u.test(normalized.ledgerDecisionId || ""))
        || (normalized.flow === "compatibility-report" && normalized.ledgerDecisionId !== null)) {
        return false;
    }
    if (audit.reportFinalization) {
        const identical = audit.reportFinalization.auditId === normalized.auditId
            && pathsEqual(audit.reportFinalization.reportPath, normalized.reportPath)
            && pathsEqual(audit.reportFinalization.findingsPath, normalized.findingsPath)
            && audit.reportFinalization.contentSha256 === normalized.contentSha256
            && audit.reportFinalization.findingsSha256 === normalized.findingsSha256
            && audit.reportFinalization.flow === normalized.flow
            && audit.reportFinalization.ledgerDecisionId === normalized.ledgerDecisionId
            && JSON.stringify(audit.reportFinalization.trustedOutcome)
                === JSON.stringify(normalized.trustedOutcome);
        return identical ? audit.reportFinalization: false;
    }
    audit.reportFinalization = normalized;
    return audit.reportFinalization;
}

export function markReportFinalizationStageComplete(sessionId, { auditId } = {}) {
    const audit = activeAudits.get(sessionId);
    if (!audit || audit.expiresAt < Date.now() || audit.auditId !== auditId) {
        return false;
    }
    const record = audit.reportFinalization;
    if (!record || record.auditId !== audit.auditId) return false;
    if (record.stageFinalized === true) return record;
    audit.reportFinalization = Object.freeze({
        ...record,
        stageFinalized: true,
    });
    return audit.reportFinalization;
}

export function getTreeEnumerationState(sessionId) {
    const audit = sessionId ? getActiveAudit(sessionId): null;
    return audit?.treeEnumerationState
        ? structuredClone(audit.treeEnumerationState): null;
}

export function recordTreeEnumerationState(sessionId, state) {
    const audit = activeAudits.get(sessionId);
    if (!audit || audit.expiresAt < Date.now() || !state || typeof state !== "object") {
        return false;
    }
    const commitSha = String(state.commitSha || "").toLowerCase();
    const rootTreeSha = String(state.rootTreeSha || "").toLowerCase();
    if (!/^[a-f0-9]{40}$/.test(commitSha) || !/^[a-f0-9]{40}$/.test(rootTreeSha)) {
        return false;
    }
    if (audit.resolvedSha && audit.resolvedSha !== commitSha) return false;
    if (audit.treeEnumerationState
        && (audit.treeEnumerationState.commitSha !== commitSha
            || audit.treeEnumerationState.rootTreeSha !== rootTreeSha)) {
        return false;
    }
    audit.treeEnumerationState = structuredClone(state);
    return true;
}

export function getAcquisitionCoverageState(sessionId) {
    const audit = sessionId ? getActiveAudit(sessionId): null;
    return audit?.acquisitionCoverageState
        ? structuredClone(audit.acquisitionCoverageState): null;
}

export function recordAcquisitionCoverageState(sessionId, state) {
    const audit = activeAudits.get(sessionId);
    if (!audit || audit.expiresAt < Date.now() || !state || typeof state !== "object") {
        return false;
    }
    const commitSha = String(state.commitSha || "").toLowerCase();
    const rootTreeSha = String(state.rootTreeSha || "").toLowerCase();
    if (!/^[a-f0-9]{40}$/.test(commitSha) || !/^[a-f0-9]{40}$/.test(rootTreeSha)) {
        return false;
    }
    if (audit.resolvedSha && audit.resolvedSha !== commitSha) return false;
    if (audit.treeEnumerationState
        && (audit.treeEnumerationState.commitSha !== commitSha
            || audit.treeEnumerationState.rootTreeSha !== rootTreeSha)) {
        return false;
    }
    if (audit.acquisitionCoverageState
        && (audit.acquisitionCoverageState.commitSha !== commitSha
            || audit.acquisitionCoverageState.rootTreeSha !== rootTreeSha)) {
        return false;
    }
    audit.acquisitionCoverageState = structuredClone(state);
    return true;
}

export function mutateAcquisitionCoverageState(sessionId, {
    commitSha,
    rootTreeSha,
    createState,
} = {}, mutator) {
    const audit = getActiveAudit(sessionId);
    if (!audit || typeof mutator !== "function") return { ok: false };
    const commit = String(commitSha || "").toLowerCase();
    const root = String(rootTreeSha || "").toLowerCase();
    if (!/^[a-f0-9]{40}$/.test(commit) || !/^[a-f0-9]{40}$/.test(root)) {
        return { ok: false };
    }
    if (audit.resolvedSha && audit.resolvedSha !== commit) return { ok: false };
    if (audit.treeEnumerationState
        && (audit.treeEnumerationState.commitSha !== commit
            || audit.treeEnumerationState.rootTreeSha !== root)) {
        return { ok: false };
    }
    if (audit.acquisitionCoverageState
        && (audit.acquisitionCoverageState.commitSha !== commit
            || audit.acquisitionCoverageState.rootTreeSha !== root)) {
        return { ok: false };
    }
    if (!audit.acquisitionCoverageState) {
        if (typeof createState !== "function") return { ok: false };
        const initialState = createState();
        if (!initialState
            || initialState.commitSha !== commit
            || initialState.rootTreeSha !== root) {
            return { ok: false };
        }
        audit.acquisitionCoverageState = initialState;
    }
    return {
        ok: true,
        value: mutator(audit.acquisitionCoverageState),
    };
}

export function getReleaseAssetCoverageState(sessionId) {
    const audit = sessionId ? getActiveAudit(sessionId): null;
    return audit?.releaseAssetCoverageState
        ? structuredClone(audit.releaseAssetCoverageState): null;
}

export function mutateReleaseAssetCoverageState(sessionId, {
    releaseId,
    tagName,
    sourceCommitSha,
    createState,
} = {}, mutator) {
    const audit = getActiveAudit(sessionId);
    if (!audit || audit.mode !== "verify_release" || typeof mutator !== "function") {
        return { ok: false };
    }
    const normalized = {
        releaseId: String(releaseId || ""),
        tagName: String(tagName || ""),
        sourceCommitSha: String(sourceCommitSha || "").toLowerCase(),
    };
    if (!audit.releaseIdentity
        || audit.releaseIdentity.releaseId !== normalized.releaseId
        || audit.releaseIdentity.tagName !== normalized.tagName
        || audit.releaseIdentity.sourceCommitSha !== normalized.sourceCommitSha
        || audit.resolvedSha !== normalized.sourceCommitSha) {
        return { ok: false };
    }
    if (audit.releaseAssetCoverageState
        && (audit.releaseAssetCoverageState.releaseId !== normalized.releaseId
            || audit.releaseAssetCoverageState.tagName !== normalized.tagName
            || audit.releaseAssetCoverageState.sourceCommitSha !== normalized.sourceCommitSha)) {
        return { ok: false };
    }
    if (!audit.releaseAssetCoverageState) {
        if (typeof createState !== "function") return { ok: false };
        const initialState = createState();
        if (!initialState
            || initialState.releaseId !== normalized.releaseId
            || initialState.tagName !== normalized.tagName
            || initialState.sourceCommitSha !== normalized.sourceCommitSha) {
            return { ok: false };
        }
        audit.releaseAssetCoverageState = initialState;
    }
    return {
        ok: true,
        value: mutator(audit.releaseAssetCoverageState),
    };
}

// Track sessions that recently expired so we can log it once on the next
// getActiveAudit() call. Keyed by sessionId; cleared when reported.
const recentlyExpired = new Map(); // sessionId -> { mode, expiredAt }

/**
 * Returns the most recent expiry record for a session and clears it. Lets
 * callers (or higher-level diagnostic code) surface "your audit TTL just
 * expired and your wrappers/policy are operating without an active-audit
 * anchor" warnings instead of letting that happen silently. (Historically
 * this also covered the onPreToolUse hook becoming a no-op on expiry;
 * the hook is no longer registered in the current runtime, but the diagnostic value
 * for wrapper callers remains.)
 */
export function consumeExpiryNotice(sessionId) {
    const notice = recentlyExpired.get(sessionId);
    if (notice) recentlyExpired.delete(sessionId);
    return notice || null;
}

export function getActiveAudit(sessionId) {
    const audit = activeAudits.get(sessionId);
    if (!audit) return null;
    if (audit.expiresAt < Date.now()) {
        recentlyExpired.set(sessionId, { mode: audit.mode, expiredAt: audit.expiresAt });
        activeAudits.delete(sessionId);
        // security rationale: also clear any recorded council outcome on
        // TTL expiry. Without this, a passing outcome from one audit could
        // satisfy the council-build gate of a *different* mode the agent
        // claims after expiry (since the outcome is keyed only on sessionId).
        clearRecordedOutcome(sessionId);
        clearCouncilLedgerState(sessionId);
        clearCacheBinding(sessionId);
        return null;
    }
    ensureAnalysisStageState(audit);
    ensureAnalysisIndexState(audit);
    ensureBehaviorGraph(audit);
    ensureAnalysisPluginState(audit);
    ensureAssuranceState(audit);
    return audit;
}

function ensureAnalysisStageState(audit) {
    if (!audit.analysisStageState) {
        audit.analysisStageState = createInitialAnalysisStageState(audit.auditId);
    }
    const state = validateAnalysisStageState(audit.analysisStageState);
    if (state.auditId !== audit.auditId) {
        throw new Error("analysis stage state auditId does not match active audit");
    }
    return state;
}

function ensureAnalysisIndexState(audit) {
    if (!audit.analysisIndexState) {
        audit.analysisIndexState = createAnalysisIndexState({
            auditId: audit.auditId,
            sourceKind: analysisSourceKindForMode(audit.mode),
        });
    }
    if (audit.analysisIndexState.auditId !== audit.auditId) {
        throw new Error("analysis index state auditId does not match active audit");
    }
    return audit.analysisIndexState;
}

function ensureBehaviorGraph(audit) {
    if (!audit.behaviorGraph) {
        audit.behaviorGraph = new BehaviorGraph({ auditId: audit.auditId });
    }
    if (audit.behaviorGraph.auditId !== audit.auditId) {
        throw new Error("behavior graph auditId does not match active audit");
    }
    return audit.behaviorGraph;
}

function ensureAnalysisPluginState(audit) {
    if (!audit.analysisPluginState) {
        audit.analysisPluginState = createPluginRunnerState({ auditId: audit.auditId });
    }
    if (audit.analysisPluginState.auditId !== audit.auditId) {
        throw new Error("analysis plugin state auditId does not match active audit");
    }
    return audit.analysisPluginState;
}

function validateAssuranceStateContainer(value, audit) {
    const prototype = value && typeof value === "object"
        ? Object.getPrototypeOf(value): null;
    if (!value
        || typeof value !== "object"
        || Array.isArray(value)
        || (prototype !== Object.prototype && prototype !== null)) {
        throw new Error("assurance audit state must be a plain object");
    }
    const keys = Object.keys(value);
    const expectedKeys = [
        "schemaVersion",
        "auditId",
        "sourceNamespace",
        "stageState",
        "analysisSnapshot",
        "supplyChainGraph",
        "semanticCoverageBaseSnapshot",
        "semanticCoveragePlan",
        "semanticScannerRecords",
        "semanticReviewAssignments",
        "semanticReviewRecords",
        "semanticCoverageEvaluation",
        "redTeamBaseSnapshot",
        "redTeamPlan",
        "redTeamAssignments",
        "redTeamReviewRecords",
        "redTeamEvaluation",
        "graphBaseSnapshot",
        "graphPlan",
        "graphTrace",
        "validationBaseSnapshot",
        "assuranceValidationPlan",
        "assuranceValidationRecords",
        "assuranceValidationEvaluation",
    ];
    if (keys.length !== expectedKeys.length
        || keys.some((key) => !expectedKeys.includes(key))) {
        throw new Error("assurance audit state has an invalid shape");
    }
    if (value.schemaVersion !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
        throw new Error("assurance state has an invalid schema revision");
    }
    const auditId = validateAuditId(value.auditId);
    if (auditId !== audit.auditId) {
        throw new Error("assurance audit state auditId does not match active audit");
    }
    const sourceNamespace = sourceNamespaceForAudit(audit);
    const stageState = validateAssuranceStageState(value.stageState);
    if (stageState.auditId !== auditId
        || stageState.sourceNamespace !== value.sourceNamespace
        || value.sourceNamespace !== sourceNamespace) {
        throw new Error(
            "assurance audit state source identity does not match active audit",
        );
    }
    const analysisSnapshot = value.analysisSnapshot === null
        ? null: validateAssuranceAnalysisSnapshot(value.analysisSnapshot);
    if (analysisSnapshot
        && (analysisSnapshot.auditId !== auditId
            || analysisSnapshot.sourceNamespace !== sourceNamespace
            || analysisSnapshot.stageState.current !== stageState.current
            || analysisSnapshot.stageState.history.length !== stageState.history.length
            || analysisSnapshot.stageState.history.some(
                (stage, index) => stage !== stageState.history[index],
            ))) {
        throw new Error("assurance analysis snapshot does not match assurance audit state");
    }
    const supplyChainGraph = value.supplyChainGraph === null
        ? null: validateSupplyChainGraph(value.supplyChainGraph);
    if (supplyChainGraph
        && (supplyChainGraph.auditId !== auditId
            || supplyChainGraph.sourceNamespace !== sourceNamespace)) {
        throw new Error("assurance supply-chain graph does not match active audit");
    }
    const semanticCoverageBaseSnapshot =
        value.semanticCoverageBaseSnapshot === null
            ? null: validateAssuranceAnalysisSnapshot(value.semanticCoverageBaseSnapshot);
    if (semanticCoverageBaseSnapshot
        && (semanticCoverageBaseSnapshot.auditId !== auditId
            || semanticCoverageBaseSnapshot.sourceNamespace !== sourceNamespace
            || semanticCoverageBaseSnapshot.stageState.current !== "decoded")) {
        throw new Error("assurance semantic coverage base snapshot is invalid");
    }
    const semanticCoveragePlan = value.semanticCoveragePlan === null
        ? null: validateSemanticCoveragePlan(
            value.semanticCoveragePlan,
            semanticCoverageBaseSnapshot,
        );
    if ((semanticCoverageBaseSnapshot === null) !== (semanticCoveragePlan === null)) {
        throw new Error("assurance semantic coverage plan and base snapshot must coexist");
    }
    if (!Array.isArray(value.semanticScannerRecords)
        || !Array.isArray(value.semanticReviewAssignments)
        || !Array.isArray(value.semanticReviewRecords)) {
        throw new Error("assurance semantic coverage records must be arrays");
    }
    if (!semanticCoveragePlan
        && (value.semanticScannerRecords.length > 0
            || value.semanticReviewAssignments.length > 0
            || value.semanticReviewRecords.length > 0
            || value.semanticCoverageEvaluation !== null)) {
        throw new Error("assurance semantic coverage records require a plan");
    }
    const semanticReviewAssignments = semanticCoveragePlan
        ? value.semanticReviewAssignments.map((assignment, index) =>
            validateSemanticReviewAssignment(
                assignment,
                {
                    plan: semanticCoveragePlan,
                    snapshot: semanticCoverageBaseSnapshot,
                    scannerRecords: value.semanticScannerRecords,
                },
                `assuranceState.semanticReviewAssignments[${index}]`,
            )): [];
    const assignmentById = new Map(
        semanticReviewAssignments.map((assignment) =>
            [assignment.assignmentId, assignment]),
    );
    const semanticReviewRecords = semanticCoveragePlan
        ? value.semanticReviewRecords.map((record, index) => {
            const assignment = assignmentById.get(record?.assignmentId);
            if (!assignment) {
                throw new Error(
                    "assurance semantic review record references an unknown assignment",
                );
            }
            return validateSemanticReviewRecord(
                record,
                {
                    assignment,
                    plan: semanticCoveragePlan,
                    snapshot: semanticCoverageBaseSnapshot,
                    scannerRecords: value.semanticScannerRecords,
                },
                `assuranceState.semanticReviewRecords[${index}]`,
            );
        }): [];
    const semanticCoverageEvaluation = semanticCoveragePlan
        ? evaluateSemanticCoverage({
            snapshot: semanticCoverageBaseSnapshot,
            plan: semanticCoveragePlan,
            scannerRecords: value.semanticScannerRecords,
            reviewAssignments: semanticReviewAssignments,
            reviewRecords: semanticReviewRecords,
        }): null;
    if (JSON.stringify(value.semanticCoverageEvaluation)
        !== JSON.stringify(semanticCoverageEvaluation)) {
        throw new Error("assurance semantic coverage evaluation is not canonical");
    }
    if (semanticCoverageEvaluation
        && analysisSnapshot
        && analysisSnapshot.stageState.current === "semantically-covered"
        && !semanticCoverageEvaluation.complete) {
        throw new Error("assurance semantic stage cannot be covered by an incomplete evaluation");
    }
    if (semanticCoverageEvaluation
        && analysisSnapshot
        && JSON.stringify(analysisSnapshot.semanticCandidateLedger)
            !== JSON.stringify(semanticCoverageEvaluation.candidateLedger)) {
        throw new Error("assurance semantic candidate snapshot ledger is not canonical");
    }
    const redTeamBaseSnapshot = value.redTeamBaseSnapshot === null
        ? null: validateAssuranceAnalysisSnapshot(value.redTeamBaseSnapshot);
    if (redTeamBaseSnapshot
        && (redTeamBaseSnapshot.auditId !== auditId
            || redTeamBaseSnapshot.sourceNamespace !== sourceNamespace
            || redTeamBaseSnapshot.stageState.current !== "scanned")) {
        throw new Error("assurance red-team base snapshot is invalid");
    }
    const redTeamPlanInputs = redTeamBaseSnapshot && semanticCoveragePlan
        ? {
            snapshot: redTeamBaseSnapshot,
            semanticBaseSnapshot: semanticCoverageBaseSnapshot,
            semanticPlan: semanticCoveragePlan,
            semanticEvaluation: semanticCoverageEvaluation,
            semanticScannerRecords: value.semanticScannerRecords,
            semanticReviewAssignments,
            semanticReviewRecords,
            supplyChainGraph,
        }: null;
    const redTeamPlan = value.redTeamPlan === null
        ? null: validateRedTeamPlan(
            value.redTeamPlan,
            redTeamPlanInputs,
            "assuranceState.redTeamPlan",
        );
    if ((redTeamBaseSnapshot === null) !== (redTeamPlan === null)) {
        throw new Error("assurance red-team plan and base snapshot must coexist");
    }
    if (!Array.isArray(value.redTeamAssignments)
        || !Array.isArray(value.redTeamReviewRecords)) {
        throw new Error("assurance red-team records must be arrays");
    }
    if (!redTeamPlan
        && (value.redTeamAssignments.length > 0
            || value.redTeamReviewRecords.length > 0
            || value.redTeamEvaluation !== null)) {
        throw new Error("assurance red-team records require a plan");
    }
    const redTeamAssignments = redTeamPlan
        ? value.redTeamAssignments.map((assignment, index) =>
            validateRedTeamAssignment(
                assignment,
                { plan: redTeamPlan, planInputs: redTeamPlanInputs },
                `assuranceState.redTeamAssignments[${index}]`,
            )): [];
    const redTeamAssignmentById = new Map(
        redTeamAssignments.map((assignment) =>
            [assignment.assignmentId, assignment]),
    );
    const redTeamReviewRecords = redTeamPlan
        ? value.redTeamReviewRecords.map((record, index) => {
            const assignment = redTeamAssignmentById.get(record?.assignmentId);
            if (!assignment) {
                throw new Error(
                    "assurance red-team review record references an unknown assignment",
                );
            }
            return validateRedTeamReviewRecord(
                record,
                {
                    assignment,
                    plan: redTeamPlan,
                    planInputs: redTeamPlanInputs,
                },
                `assuranceState.redTeamReviewRecords[${index}]`,
            );
        }): [];
    const redTeamEvaluation = redTeamPlan
        ? evaluateRedTeamCoverage({
            plan: redTeamPlan,
            planInputs: redTeamPlanInputs,
            assignments: redTeamAssignments,
            reviewRecords: redTeamReviewRecords,
        }): null;
    if (JSON.stringify(value.redTeamEvaluation) !== JSON.stringify(redTeamEvaluation)) {
        throw new Error("assurance red-team evaluation is not canonical");
    }
    if (analysisSnapshot?.stageState.current === "red-teamed"
        && !redTeamEvaluation?.complete) {
        throw new Error("assurance red-teamed stage requires complete red-team coverage");
    }
    const graphBaseSnapshot = value.graphBaseSnapshot === null
        ? null: validateAssuranceAnalysisSnapshot(value.graphBaseSnapshot);
    if (graphBaseSnapshot
        && (graphBaseSnapshot.auditId !== auditId
            || graphBaseSnapshot.sourceNamespace !== sourceNamespace
            || graphBaseSnapshot.stageState.current !== "red-teamed")) {
        throw new Error("assurance graph base snapshot is invalid");
    }
    const graphInputs = graphBaseSnapshot && redTeamPlan
        ? {
            snapshot: graphBaseSnapshot,
            redTeamBaseSnapshot,
            semanticBaseSnapshot: semanticCoverageBaseSnapshot,
            semanticPlan: semanticCoveragePlan,
            semanticEvaluation: semanticCoverageEvaluation,
            semanticScannerRecords: value.semanticScannerRecords,
            semanticReviewAssignments,
            semanticReviewRecords,
            redTeamPlan,
            redTeamAssignments,
            redTeamReviewRecords,
            redTeamEvaluation,
            supplyChainGraph,
            limits: value.graphPlan?.limits,
        }: null;
    const graphPlan = value.graphPlan === null
        ? null: buildEvasiveGraph(graphInputs);
    if ((graphBaseSnapshot === null) !== (graphPlan === null)
        || JSON.stringify(value.graphPlan) !== JSON.stringify(graphPlan)) {
        throw new Error("assurance graph plan is not canonical");
    }
    const graphTrace = value.graphTrace === null
        ? null: validateEvasiveTrace(
            value.graphTrace,
            graphPlan,
            "assuranceState.graphTrace",
        );
    if (graphTrace && !graphPlan) {
        throw new Error("assurance graph trace requires a graph plan");
    }
    if (analysisSnapshot
        && ["traced", "validated", "finalized"].includes(
            analysisSnapshot.stageState.current,
        )
        && (!graphTrace?.complete || graphTrace.blockerCodes.length > 0)) {
        throw new Error("assurance traced stage requires a complete exhaustive graph trace");
    }
    const validationBaseSnapshot = value.validationBaseSnapshot === null
        ? null: validateAssuranceAnalysisSnapshot(value.validationBaseSnapshot);
    if (validationBaseSnapshot
        && (validationBaseSnapshot.auditId !== auditId
            || validationBaseSnapshot.sourceNamespace !== sourceNamespace
            || validationBaseSnapshot.stageState.current !== "traced")) {
        throw new Error("assurance validation base snapshot is invalid");
    }
    const assurancePlanInputs = validationBaseSnapshot && graphPlan && graphTrace
        ? {
            snapshot: validationBaseSnapshot,
            graphBaseSnapshot,
            graph: graphPlan,
            trace: graphTrace,
            semanticEvaluation: semanticCoverageEvaluation,
            redTeamEvaluation,
            supplyChainGraph,
        }: null;
    const assuranceValidationPlan = value.assuranceValidationPlan === null
        ? null: validateAssuranceValidationPlan(
            value.assuranceValidationPlan,
            assurancePlanInputs,
            "assuranceState.assuranceValidationPlan",
        );
    if ((validationBaseSnapshot === null) !== (assuranceValidationPlan === null)) {
        throw new Error("assurance validation plan and base snapshot must coexist");
    }
    if (!Array.isArray(value.assuranceValidationRecords)) {
        throw new Error("assurance validation records must be an array");
    }
    if (!assuranceValidationPlan
        && (value.assuranceValidationRecords.length > 0
            || value.assuranceValidationEvaluation !== null)) {
        throw new Error("assurance validation records require a plan");
    }
    const assuranceAssignmentById = new Map(
        (assuranceValidationPlan?.assignments || []).map((assignment) =>
            [assignment.assignmentId, assignment]),
    );
    const assuranceValidationRecords = assuranceValidationPlan
        ? value.assuranceValidationRecords.map((record, index) => {
            const assignment = assuranceAssignmentById.get(record?.assignmentId);
            if (!assignment) {
                throw new Error(
                    "assurance validation record references an unknown assignment",
                );
            }
            return validateAssuranceValidationRecord(
                record,
                assignment,
                `assuranceState.assuranceValidationRecords[${index}]`,
            );
        }): [];
    const assuranceValidationEvaluation = assuranceValidationPlan
        ? evaluateAssuranceValidation({
            plan: assuranceValidationPlan,
            planInputs: assurancePlanInputs,
            records: assuranceValidationRecords,
        }): null;
    if (JSON.stringify(value.assuranceValidationEvaluation)
        !== JSON.stringify(assuranceValidationEvaluation)) {
        throw new Error("assurance validation evaluation is not canonical");
    }
    if (analysisSnapshot
        && ["validated", "finalized"].includes(analysisSnapshot.stageState.current)
        && !assuranceValidationEvaluation?.complete) {
        throw new Error("assurance validated stage requires complete assurance validation");
    }
    return Object.freeze({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId,
        sourceNamespace,
        stageState,
        analysisSnapshot,
        supplyChainGraph,
        semanticCoverageBaseSnapshot,
        semanticCoveragePlan,
        semanticScannerRecords: Object.freeze(
            value.semanticScannerRecords.map((record) => Object.freeze(record)),
        ),
        semanticReviewAssignments: Object.freeze(semanticReviewAssignments),
        semanticReviewRecords: Object.freeze(semanticReviewRecords),
        semanticCoverageEvaluation,
        redTeamBaseSnapshot,
        redTeamPlan,
        redTeamAssignments: Object.freeze(redTeamAssignments),
        redTeamReviewRecords: Object.freeze(redTeamReviewRecords),
        redTeamEvaluation,
        graphBaseSnapshot,
        graphPlan,
        graphTrace,
        validationBaseSnapshot,
        assuranceValidationPlan,
        assuranceValidationRecords: Object.freeze(assuranceValidationRecords),
        assuranceValidationEvaluation,
    });
}

function createEmptyAssuranceState(audit, sourceNamespace = sourceNamespaceForAudit(audit)) {
    return Object.freeze({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId: audit.auditId,
        sourceNamespace,
        stageState: createInitialAssuranceStageState({
            auditId: audit.auditId,
            sourceNamespace,
        }),
        analysisSnapshot: null,
        supplyChainGraph: null,
        semanticCoverageBaseSnapshot: null,
        semanticCoveragePlan: null,
        semanticScannerRecords: Object.freeze([]),
        semanticReviewAssignments: Object.freeze([]),
        semanticReviewRecords: Object.freeze([]),
        semanticCoverageEvaluation: null,
        redTeamBaseSnapshot: null,
        redTeamPlan: null,
        redTeamAssignments: Object.freeze([]),
        redTeamReviewRecords: Object.freeze([]),
        redTeamEvaluation: null,
        graphBaseSnapshot: null,
        graphPlan: null,
        graphTrace: null,
        validationBaseSnapshot: null,
        assuranceValidationPlan: null,
        assuranceValidationRecords: Object.freeze([]),
        assuranceValidationEvaluation: null,
    });
}

function assuranceStateIsEmptyAtAcquired(value) {
    return value.stageState.current === "acquired"
        && value.stageState.history.length === 1
        && value.stageState.history[0] === "acquired"
        && value.analysisSnapshot === null
        && value.supplyChainGraph === null
        && value.semanticCoverageBaseSnapshot === null
        && value.semanticCoveragePlan === null
        && value.semanticScannerRecords.length === 0
        && value.semanticReviewAssignments.length === 0
        && value.semanticReviewRecords.length === 0
        && value.semanticCoverageEvaluation === null
        && value.redTeamBaseSnapshot === null
        && value.redTeamPlan === null
        && value.redTeamAssignments.length === 0
        && value.redTeamReviewRecords.length === 0
        && value.redTeamEvaluation === null
        && value.graphBaseSnapshot === null
        && value.graphPlan === null
        && value.graphTrace === null
        && value.validationBaseSnapshot === null
        && value.assuranceValidationPlan === null
        && value.assuranceValidationRecords.length === 0
        && value.assuranceValidationEvaluation === null;
}

function rebindEmptyAssuranceStateForResolvedSha(audit, normalizedSha) {
    if (!Object.hasOwn(audit, "assurance")) return false;
    if (!audit.owner || !audit.repo || audit.resolvedSha) return false;

    let current;
    try {
        current = validateAssuranceStateContainer(audit.assurance, audit);
    } catch {
        return false;
    }
    const prePinNamespace = `audit:${audit.auditId}`;
    if (current.sourceNamespace !== prePinNamespace || !assuranceStateIsEmptyAtAcquired(current)) {
        return false;
    }

    const previousAssurance = audit.assurance;
    audit.resolvedSha = normalizedSha;
    try {
        audit.assurance = validateAssuranceStateContainer(
            createEmptyAssuranceState(audit),
            audit,
        );
        return true;
    } catch {
        audit.assurance = previousAssurance;
        delete audit.resolvedSha;
        return false;
    }
}

function ensureAssuranceState(audit) {
    if (!Object.hasOwn(audit, "assurance")) {
        audit.assurance = createEmptyAssuranceState(audit);
    }
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return audit.assurance;
}

export function getAssuranceState(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("assurance audit state auditId does not match active audit");
    }
    return structuredClone(ensureAssuranceState(audit));
}

export function advanceAssuranceStage(sessionId, {
    auditId,
    from,
    to,
} = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("cannot advance assurance stage without an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("assurance stage transition auditId does not match active audit");
    }
    const current = ensureAssuranceState(audit);
    if (from === "decoded" && to === "semantically-covered") {
        throw new Error(
            "decoded -> semantically-covered is owned by complete assurance semantic coverage",
        );
    }
    if (from === "semantically-covered" && to === "scanned") {
        throw new Error(
            "semantically-covered -> scanned is owned by assurance red-team preparation",
        );
    }
    if (from === "scanned" && to === "red-teamed") {
        throw new Error(
            "scanned -> red-teamed is owned by complete assurance red-team coverage",
        );
    }
    if (from === "red-teamed" && to === "traced") {
        throw new Error(
            "red-teamed -> traced is owned by complete assurance graph tracing",
        );
    }
    if (from === "traced" && to === "validated") {
        throw new Error(
            "traced -> validated is owned by complete assurance validation",
        );
    }
    if (from === "validated" && to === "finalized") {
        throw new Error(
            "validated -> finalized is owned by assurance report finalization",
        );
    }
    const stageState = transitionAssuranceStageState(current.stageState, {
        auditId: normalizedAuditId,
        sourceNamespace: current.sourceNamespace,
        from,
        to,
    });
    const preserveCoverage = [
        "red-teamed",
        "traced",
        "validated",
        "finalized",
    ].includes(from);
    audit.assurance = Object.freeze({
        ...current,
        stageState,
        analysisSnapshot: to === from ? current.analysisSnapshot: null,
        ...(to === from || preserveCoverage ? {}: {
            semanticCoverageBaseSnapshot: null,
            semanticCoveragePlan: null,
            semanticScannerRecords: Object.freeze([]),
            semanticReviewAssignments: Object.freeze([]),
            semanticReviewRecords: Object.freeze([]),
            semanticCoverageEvaluation: null,
            redTeamBaseSnapshot: null,
            redTeamPlan: null,
            redTeamAssignments: Object.freeze([]),
            redTeamReviewRecords: Object.freeze([]),
            redTeamEvaluation: null,
            graphBaseSnapshot: null,
            graphPlan: null,
            graphTrace: null,
            validationBaseSnapshot: null,
            assuranceValidationPlan: null,
            assuranceValidationRecords: Object.freeze([]),
            assuranceValidationEvaluation: null,
        }),
    });
    return structuredClone(audit.assurance);
}

export function finalizeAssuranceReportState(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("assurance report finalization requires an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("assurance report finalization auditId does not match active audit");
    }
    const current = ensureAssuranceState(audit);
    const record = audit.reportFinalization;
    if (!record
        || record.auditId !== current.auditId
        || record.flow !== "evasive-assurance"
        || record.trustedOutcome?.schemaVersion !== ASSURANCE_ANALYSIS_SCHEMA_REVISION
        || record.trustedOutcome.complete !== true) {
        throw new Error(
            "assurance report finalization requires the durable identity-bound report pair record",
        );
    }
    if (current.stageState.current === "finalized") {
        return structuredClone(current);
    }
    if (current.stageState.current !== "validated"
        || !current.analysisSnapshot
        || !current.assuranceValidationEvaluation?.complete
        || current.assuranceValidationEvaluation.blockerCodes.length > 0) {
        throw new Error(
            `assurance report finalization requires validated assurance state (current: ${current.stageState.current})`,
        );
    }
    const stageState = transitionAssuranceStageState(current.stageState, {
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        from: "validated",
        to: "finalized",
    });
    const analysisSnapshot = createAssuranceAnalysisSnapshot({
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        stageState,
        status: "complete",
        objectInventory: current.analysisSnapshot.objectInventory,
        derivedArtifacts: current.analysisSnapshot.derivedArtifacts,
        semanticReviewCoverage: current.analysisSnapshot.semanticReviewCoverage,
        semanticCandidateLedger: current.analysisSnapshot.semanticCandidateLedger,
        redTeamCoverage: current.analysisSnapshot.redTeamCoverage,
        blockerCodes: [],
        sourceIdentitySha256:
            current.analysisSnapshot.hashes.sourceIdentitySha256,
    });
    audit.assurance = Object.freeze({
        ...current,
        stageState,
        analysisSnapshot,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return structuredClone(audit.assurance);
}

export function recordAssuranceSnapshot(sessionId, {
    auditId,
    snapshot,
} = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("cannot record assurance snapshot without an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("assurance snapshot auditId does not match active audit");
    }
    const current = ensureAssuranceState(audit);
    const normalizedSnapshot = validateAssuranceAnalysisSnapshot(snapshot);
    if (normalizedSnapshot.auditId !== current.auditId
        || normalizedSnapshot.sourceNamespace !== current.sourceNamespace
        || normalizedSnapshot.stageState.current !== current.stageState.current
        || normalizedSnapshot.stageState.history.length
            !== current.stageState.history.length
        || normalizedSnapshot.stageState.history.some(
            (stage, index) => stage !== current.stageState.history[index],
        )) {
        throw new Error("assurance snapshot does not match active assurance audit state");
    }
    if (current.semanticCoveragePlan
        && current.stageState.current === "decoded"
        && normalizedSnapshot.snapshotId !== current.analysisSnapshot?.snapshotId) {
        throw new Error(
            "assurance snapshot replacement refused after semantic coverage preparation",
        );
    }
    if (current.graphPlan
        && normalizedSnapshot.snapshotId !== current.analysisSnapshot?.snapshotId) {
        throw new Error(
            "assurance snapshot replacement refused after graph preparation",
        );
    }
    audit.assurance = Object.freeze({
        ...current,
        analysisSnapshot: normalizedSnapshot,
    });
    return structuredClone(normalizedSnapshot);
}

export function getAssuranceSnapshot(sessionId, { auditId } = {}) {
    const state = getAssuranceState(sessionId, { auditId });
    return state?.analysisSnapshot || null;
}

export function recordAssuranceSupplyChainGraph(sessionId, {
    auditId,
    graph,
} = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("cannot record assurance supply-chain graph without an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("assurance supply-chain graph auditId does not match active audit");
    }
    const current = ensureAssuranceState(audit);
    if (current.semanticCoveragePlan) {
        throw new Error("assurance supply-chain graph is immutable after semantic preparation");
    }
    const normalizedGraph = validateSupplyChainGraph(graph);
    if (normalizedGraph.auditId !== current.auditId
        || normalizedGraph.sourceNamespace !== current.sourceNamespace) {
        throw new Error("assurance supply-chain graph does not match active source identity");
    }
    if (current.supplyChainGraph) {
        if (current.supplyChainGraph.graphId === normalizedGraph.graphId) {
            return structuredClone(current.supplyChainGraph);
        }
    }
    audit.assurance = Object.freeze({
        ...current,
        supplyChainGraph: normalizedGraph,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return structuredClone(normalizedGraph);
}

function requireSemanticState(sessionId, auditId) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("assurance semantic coverage requires an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("assurance semantic coverage auditId does not match active audit");
    }
    return { audit, current: ensureAssuranceState(audit) };
}

function storeSemanticEvaluation(audit, current, {
    scannerRecords = current.semanticScannerRecords,
    reviewAssignments = current.semanticReviewAssignments,
    reviewRecords = current.semanticReviewRecords,
} = {}) {
    const evaluation = evaluateSemanticCoverage({
        snapshot: current.semanticCoverageBaseSnapshot,
        plan: current.semanticCoveragePlan,
        scannerRecords,
        reviewAssignments,
        reviewRecords,
    });
    let stageState = current.stageState;
    if (semanticSnapshotCanAdvance(
        current.semanticCoverageBaseSnapshot,
        evaluation,
    )) {
        stageState = transitionAssuranceStageState(current.stageState, {
            auditId: current.auditId,
            sourceNamespace: current.sourceNamespace,
            from: "decoded",
            to: "semantically-covered",
        });
    }
    const analysisSnapshot = applySemanticCoverageToSnapshot({
        snapshot: current.semanticCoverageBaseSnapshot,
        evaluation,
        stageState,
    });
    audit.assurance = Object.freeze({
        ...current,
        stageState,
        analysisSnapshot,
        semanticScannerRecords: Object.freeze([...scannerRecords]),
        semanticReviewAssignments: Object.freeze([...reviewAssignments]),
        semanticReviewRecords: Object.freeze([...reviewRecords]),
        semanticCoverageEvaluation: evaluation,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return audit.assurance;
}

export function prepareSemanticCoverage(sessionId, {
    auditId,
    normalizedViews = [],
    scannerShardCount = 16,
    modelShardCount = 16,
} = {}) {
    const { audit, current } = requireSemanticState(sessionId, auditId);
    if (!current.analysisSnapshot) {
        throw new Error("assurance semantic coverage requires a recorded decoded snapshot");
    }
    if (!["decoded", "semantically-covered"].includes(current.stageState.current)) {
        throw new Error(
            `assurance semantic coverage requires decoded stage (current: ${current.stageState.current})`,
        );
    }
    const baseSnapshot = current.semanticCoverageBaseSnapshot
        || current.analysisSnapshot;
    const plan = createSemanticCoveragePlan({
        snapshot: baseSnapshot,
        normalizedViews,
        scannerShardCount,
        modelShardCount,
    });
    if (current.semanticCoveragePlan) {
        if (current.semanticCoveragePlan.planId !== plan.planId) {
            throw new Error("assurance semantic coverage plan is immutable");
        }
        return structuredClone(current);
    }
    const next = Object.freeze({
        ...current,
        semanticCoverageBaseSnapshot: baseSnapshot,
        semanticCoveragePlan: plan,
    });
    return structuredClone(storeSemanticEvaluation(audit, next));
}

export function getSemanticCoverageState(sessionId, { auditId } = {}) {
    const state = getAssuranceState(sessionId, { auditId });
    if (!state) return null;
    return {
        plan: state.semanticCoveragePlan,
        scannerRecords: state.semanticScannerRecords,
        reviewAssignments: state.semanticReviewAssignments,
        reviewRecords: state.semanticReviewRecords,
        evaluation: state.semanticCoverageEvaluation,
        stageState: state.stageState,
        analysisSnapshot: state.analysisSnapshot,
    };
}

export function recordSemanticScannerCoverage(sessionId, {
    auditId,
    assignmentId,
    assignmentToken,
    scannerResult,
} = {}) {
    const { audit, current } = requireSemanticState(sessionId, auditId);
    if (!current.semanticCoveragePlan) {
        throw new Error("assurance semantic scanner coverage requires a prepared plan");
    }
    const record = createSemanticScannerCoverageRecord({
        plan: current.semanticCoveragePlan,
        snapshot: current.semanticCoverageBaseSnapshot,
        assignmentId,
        assignmentToken,
        scannerResult,
    });
    const existing = current.semanticScannerRecords.find((entry) =>
        entry.assignmentId === record.assignmentId);
    if (existing) {
        if (existing.scannerRecordId !== record.scannerRecordId) {
            throw new Error("assurance semantic scanner record is immutable");
        }
        return structuredClone({
            record: existing,
            state: current,
        });
    }
    if (current.stageState.current !== "decoded") {
        throw new Error("assurance semantic scanner coverage is already finalized");
    }
    const next = storeSemanticEvaluation(audit, current, {
        scannerRecords: [...current.semanticScannerRecords, record],
    });
    return structuredClone({ record, state: next });
}

export function issueSemanticReviewAssignment(sessionId, {
    auditId,
    objectId,
    reviewerSlot,
    reviewerId,
    reviewerVersion,
} = {}) {
    const { audit, current } = requireSemanticState(sessionId, auditId);
    if (!current.semanticCoveragePlan) {
        throw new Error("assurance semantic review assignment requires a prepared plan");
    }
    const sameSlot = current.semanticReviewAssignments.find((assignment) =>
        assignment.objectId === objectId
        && assignment.reviewerSlot === reviewerSlot);
    if (sameSlot) {
        if (sameSlot.reviewerId !== reviewerId
            || sameSlot.reviewerVersion !== reviewerVersion) {
            throw new Error("assurance semantic reviewer slot is immutable");
        }
        return structuredClone(sameSlot);
    }
    if (current.stageState.current !== "decoded") {
        throw new Error("assurance semantic review assignments are already finalized");
    }
    if (current.semanticReviewAssignments.some((assignment) =>
        assignment.objectId === objectId
        && assignment.reviewerId === reviewerId)) {
        throw new Error("assurance high-risk review slots require independent reviewers");
    }
    const assignment = createSemanticReviewAssignment({
        plan: current.semanticCoveragePlan,
        snapshot: current.semanticCoverageBaseSnapshot,
        scannerRecords: current.semanticScannerRecords,
        objectId,
        reviewerSlot,
        reviewerId,
        reviewerVersion,
        assignmentNonceSha256: randomBytes(32).toString("hex"),
    });
    storeSemanticEvaluation(audit, current, {
        reviewAssignments: [
            ...current.semanticReviewAssignments,
            assignment,
        ],
    });
    return structuredClone(assignment);
}

export function recordSemanticReview(sessionId, {
    auditId,
    assignmentId,
    assignmentToken,
    reviewerId,
    objectId,
    artifactIds,
    semanticViewId,
    semanticViewSha256,
    reviewedFactIds,
    reviewedArtifactIds,
    decision,
    checks,
    negativeEvidenceCodes,
    candidates,
    blockerCodes,
    promptReviewRecord = null,
} = {}) {
    const { audit, current } = requireSemanticState(sessionId, auditId);
    if (!current.semanticCoveragePlan) {
        throw new Error("assurance semantic review requires a prepared plan");
    }
    const assignment = current.semanticReviewAssignments.find((entry) =>
        entry.assignmentId === assignmentId);
    if (!assignment) {
        throw new Error("assurance semantic review references an unknown assignment");
    }
    const record = createSemanticReviewRecord({
        assignment,
        plan: current.semanticCoveragePlan,
        snapshot: current.semanticCoverageBaseSnapshot,
        scannerRecords: current.semanticScannerRecords,
        assignmentToken,
        reviewerId,
        objectId,
        artifactIds,
        semanticViewId,
        semanticViewSha256,
        reviewedFactIds,
        reviewedArtifactIds,
        decision,
        checks,
        negativeEvidenceCodes,
        candidates,
        blockerCodes,
        promptReviewRecord,
    });
    const existing = current.semanticReviewRecords.find((entry) =>
        entry.assignmentId === assignment.assignmentId);
    if (existing) {
        if (existing.reviewId !== record.reviewId) {
            throw new Error("assurance semantic review record is immutable");
        }
        return structuredClone({
            record: existing,
            state: current,
        });
    }
    if (current.stageState.current !== "decoded") {
        throw new Error("assurance semantic review coverage is already finalized");
    }
    const next = storeSemanticEvaluation(audit, current, {
        reviewRecords: [...current.semanticReviewRecords, record],
    });
    return structuredClone({ record, state: next });
}

function requireRedTeamState(sessionId, auditId) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("assurance red-team coverage requires an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("assurance red-team coverage auditId does not match active audit");
    }
    return { audit, current: ensureAssuranceState(audit) };
}

function buildRedTeamPlanInputs(current) {
    if (!current.redTeamBaseSnapshot
        || !current.semanticCoverageBaseSnapshot
        || !current.semanticCoveragePlan
        || !current.semanticCoverageEvaluation) {
        throw new Error("assurance red-team coverage requires completed semantic state");
    }
    return {
        snapshot: current.redTeamBaseSnapshot,
        semanticBaseSnapshot: current.semanticCoverageBaseSnapshot,
        semanticPlan: current.semanticCoveragePlan,
        semanticEvaluation: current.semanticCoverageEvaluation,
        semanticScannerRecords: current.semanticScannerRecords,
        semanticReviewAssignments: current.semanticReviewAssignments,
        semanticReviewRecords: current.semanticReviewRecords,
        supplyChainGraph: current.supplyChainGraph,
    };
}

function storeRedTeamEvaluation(audit, current, {
    assignments = current.redTeamAssignments,
    reviewRecords = current.redTeamReviewRecords,
} = {}) {
    const planInputs = buildRedTeamPlanInputs(current);
    const evaluation = evaluateRedTeamCoverage({
        plan: current.redTeamPlan,
        planInputs,
        assignments,
        reviewRecords,
    });
    audit.assurance = Object.freeze({
        ...current,
        redTeamAssignments: Object.freeze([...assignments]),
        redTeamReviewRecords: Object.freeze([...reviewRecords]),
        redTeamEvaluation: evaluation,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return audit.assurance;
}

export function prepareRedTeam(sessionId, { auditId } = {}) {
    const { audit, current } = requireRedTeamState(sessionId, auditId);
    if (current.redTeamPlan) return structuredClone(current);
    if (!current.analysisSnapshot
        || current.stageState.current !== "semantically-covered"
        || current.semanticCoverageEvaluation?.complete !== true) {
        throw new Error(
            `assurance red-team preparation requires semantically-covered stage (current: ${current.stageState.current})`,
        );
    }
    const stageState = transitionAssuranceStageState(current.stageState, {
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        from: "semantically-covered",
        to: "scanned",
    });
    const scannedSnapshot = createRedTeamScannedSnapshot({
        snapshot: current.analysisSnapshot,
        stageState,
    });
    const planInputs = {
        snapshot: scannedSnapshot,
        semanticBaseSnapshot: current.semanticCoverageBaseSnapshot,
        semanticPlan: current.semanticCoveragePlan,
        semanticEvaluation: current.semanticCoverageEvaluation,
        semanticScannerRecords: current.semanticScannerRecords,
        semanticReviewAssignments: current.semanticReviewAssignments,
        semanticReviewRecords: current.semanticReviewRecords,
        supplyChainGraph: current.supplyChainGraph,
    };
    const plan = createRedTeamPlan(planInputs);
    const evaluation = evaluateRedTeamCoverage({
        plan,
        planInputs,
        assignments: [],
        reviewRecords: [],
    });
    audit.assurance = Object.freeze({
        ...current,
        stageState,
        analysisSnapshot: scannedSnapshot,
        redTeamBaseSnapshot: scannedSnapshot,
        redTeamPlan: plan,
        redTeamAssignments: Object.freeze([]),
        redTeamReviewRecords: Object.freeze([]),
        redTeamEvaluation: evaluation,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return structuredClone(audit.assurance);
}

export function getRedTeamState(sessionId, { auditId } = {}) {
    const state = getAssuranceState(sessionId, { auditId });
    if (!state) return null;
    return {
        plan: state.redTeamPlan,
        assignments: state.redTeamAssignments,
        reviewRecords: state.redTeamReviewRecords,
        evaluation: state.redTeamEvaluation,
        candidateLedger: state.redTeamEvaluation?.candidateLedger || [],
        stageState: state.stageState,
        analysisSnapshot: state.analysisSnapshot,
    };
}

export function issueRedTeamAssignment(sessionId, {
    auditId,
    categoryId,
    reviewerId,
    reviewerVersion,
    modelId,
} = {}) {
    const { audit, current } = requireRedTeamState(sessionId, auditId);
    if (!current.redTeamPlan) {
        throw new Error("assurance red-team assignment requires a prepared plan");
    }
    const existing = current.redTeamAssignments.find((assignment) =>
        assignment.categoryId === categoryId);
    if (existing) {
        if (existing.reviewerId !== reviewerId
            || existing.reviewerVersion !== reviewerVersion
            || existing.modelId !== modelId) {
            throw new Error("assurance red-team category assignment is immutable");
        }
        return structuredClone(existing);
    }
    if (current.stageState.current !== "scanned") {
        throw new Error("assurance red-team assignments are already finalized");
    }
    const planInputs = buildRedTeamPlanInputs(current);
    const assignment = createRedTeamAssignment({
        plan: current.redTeamPlan,
        planInputs,
        categoryId,
        reviewerId,
        reviewerVersion,
        modelId,
        assignmentNonceSha256: randomBytes(32).toString("hex"),
    });
    storeRedTeamEvaluation(audit, current, {
        assignments: [...current.redTeamAssignments, assignment],
    });
    return structuredClone(assignment);
}

export function recordRedTeamReview(sessionId, {
    auditId,
    assignmentId,
    review,
} = {}) {
    const { audit, current } = requireRedTeamState(sessionId, auditId);
    if (!current.redTeamPlan) {
        throw new Error("assurance red-team review requires a prepared plan");
    }
    const assignment = current.redTeamAssignments.find((entry) =>
        entry.assignmentId === assignmentId);
    if (!assignment) {
        throw new Error("assurance red-team review references an unknown assignment");
    }
    if (!review || typeof review !== "object" || Array.isArray(review)
        || review.contractKind !== "evasive-red-team-review-record"
        || review.assignmentId !== assignment.assignmentId) {
        throw new Error("assurance red-team review has an invalid assignment contract");
    }
    const planInputs = buildRedTeamPlanInputs(current);
    const record = createRedTeamReviewRecord({
        assignment,
        plan: current.redTeamPlan,
        planInputs,
        assignmentToken: review.assignmentToken,
        reviewerId: review.reviewerId,
        decision: review.decision,
        reviewedObjectIds: review.reviewedObjectIds,
        reviewedArtifactIds: review.reviewedArtifactIds,
        reviewedFactIds: review.reviewedFactIds,
        reviewedEvidenceIds: review.reviewedEvidenceIds,
        reviewedGraphNodeIds: review.reviewedGraphNodeIds,
        reviewedGraphEdgeIds: review.reviewedGraphEdgeIds,
        falsificationChecks: review.falsificationChecks,
        negativeEvidenceCodes: review.negativeEvidenceCodes,
        candidates: review.candidates,
        blockerCodes: review.blockerCodes,
        canaryMarker: review.canaryMarker,
        outputContractMarker: review.outputContractMarker,
    });
    const existing = current.redTeamReviewRecords.find((entry) =>
        entry.assignmentId === assignment.assignmentId);
    if (existing) {
        if (existing.reviewId !== record.reviewId) {
            throw new Error("assurance red-team review record is immutable");
        }
        return structuredClone({ record: existing, state: current });
    }
    if (current.stageState.current !== "scanned") {
        throw new Error("assurance red-team review coverage is already finalized");
    }
    const next = storeRedTeamEvaluation(audit, current, {
        reviewRecords: [...current.redTeamReviewRecords, record],
    });
    return structuredClone({ record, state: next });
}

export function finalizeRedTeam(sessionId, { auditId } = {}) {
    const { audit, current } = requireRedTeamState(sessionId, auditId);
    if (!current.redTeamPlan || !current.redTeamEvaluation) {
        throw new Error("assurance red-team finalization requires a prepared plan");
    }
    if (current.stageState.current === "red-teamed") {
        return structuredClone({ advanced: true, state: current });
    }
    if (current.stageState.current !== "scanned") {
        throw new Error(
            `assurance red-team finalization requires scanned stage (current: ${current.stageState.current})`,
        );
    }
    if (!redTeamSnapshotCanAdvance(
        current.redTeamBaseSnapshot,
        current.redTeamEvaluation,
    )) {
        return structuredClone({ advanced: false, state: current });
    }
    const stageState = transitionAssuranceStageState(current.stageState, {
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        from: "scanned",
        to: "red-teamed",
    });
    const analysisSnapshot = applyRedTeamCoverageToSnapshot({
        snapshot: current.redTeamBaseSnapshot,
        evaluation: current.redTeamEvaluation,
        stageState,
    });
    audit.assurance = Object.freeze({
        ...current,
        stageState,
        analysisSnapshot,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return structuredClone({ advanced: true, state: audit.assurance });
}

function requireEvasiveGraphState(sessionId, auditId) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("assurance graph tracing requires an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("assurance graph auditId does not match active audit");
    }
    return { audit, current: ensureAssuranceState(audit) };
}

function buildEvasiveGraphInputs(current, snapshot = current.graphBaseSnapshot) {
    if (!snapshot
        || !current.redTeamBaseSnapshot
        || !current.semanticCoverageBaseSnapshot
        || !current.semanticCoveragePlan
        || !current.semanticCoverageEvaluation
        || !current.redTeamPlan
        || !current.redTeamEvaluation) {
        throw new Error("assurance graph tracing requires completed semantic and red-team state");
    }
    return {
        snapshot,
        redTeamBaseSnapshot: current.redTeamBaseSnapshot,
        semanticBaseSnapshot: current.semanticCoverageBaseSnapshot,
        semanticPlan: current.semanticCoveragePlan,
        semanticEvaluation: current.semanticCoverageEvaluation,
        semanticScannerRecords: current.semanticScannerRecords,
        semanticReviewAssignments: current.semanticReviewAssignments,
        semanticReviewRecords: current.semanticReviewRecords,
        redTeamPlan: current.redTeamPlan,
        redTeamAssignments: current.redTeamAssignments,
        redTeamReviewRecords: current.redTeamReviewRecords,
        redTeamEvaluation: current.redTeamEvaluation,
        supplyChainGraph: current.supplyChainGraph,
    };
}

export function prepareEvasiveGraph(sessionId, { auditId } = {}) {
    const { audit, current } = requireEvasiveGraphState(sessionId, auditId);
    if (current.graphPlan) return structuredClone(current);
    if (!current.analysisSnapshot
        || current.stageState.current !== "red-teamed"
        || current.redTeamEvaluation?.complete !== true) {
        throw new Error(
            `assurance graph preparation requires red-teamed stage (current: ${current.stageState.current})`,
        );
    }
    const graphBaseSnapshot = current.analysisSnapshot;
    const graphPlan = buildEvasiveGraph(
        buildEvasiveGraphInputs(current, graphBaseSnapshot),
    );
    audit.assurance = Object.freeze({
        ...current,
        graphBaseSnapshot,
        graphPlan,
        graphTrace: null,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return structuredClone(audit.assurance);
}

export function traceEvasiveGraphState(sessionId, { auditId } = {}) {
    const { audit, current } = requireEvasiveGraphState(sessionId, auditId);
    if (!current.graphPlan || !current.graphBaseSnapshot) {
        throw new Error("assurance graph trace requires a prepared graph");
    }
    if (current.stageState.current === "traced"
        || current.stageState.current === "validated") {
        return structuredClone({
            advanced: true,
            state: current,
            trace: current.graphTrace,
        });
    }
    if (current.stageState.current !== "red-teamed") {
        throw new Error(
            `assurance graph trace requires red-teamed stage (current: ${current.stageState.current})`,
        );
    }
    const recomputedGraph = buildEvasiveGraph({
        ...buildEvasiveGraphInputs(current),
        limits: current.graphPlan.limits,
    });
    if (recomputedGraph.graphId !== current.graphPlan.graphId) {
        throw new Error("assurance graph identity changed before trace");
    }
    const trace = traceEvasiveGraph(recomputedGraph);
    let stageState = current.stageState;
    let analysisSnapshot = current.analysisSnapshot;
    let advanced = false;
    if (evasiveTraceCanAdvance(recomputedGraph, trace)) {
        stageState = transitionAssuranceStageState(current.stageState, {
            auditId: current.auditId,
            sourceNamespace: current.sourceNamespace,
            from: "red-teamed",
            to: "traced",
        });
        analysisSnapshot = createAssuranceAnalysisSnapshot({
            auditId: current.auditId,
            sourceNamespace: current.sourceNamespace,
            stageState,
            status: "incomplete",
            objectInventory: current.analysisSnapshot.objectInventory,
            derivedArtifacts: current.analysisSnapshot.derivedArtifacts,
            semanticReviewCoverage:
                current.analysisSnapshot.semanticReviewCoverage,
            semanticCandidateLedger:
                current.analysisSnapshot.semanticCandidateLedger,
            redTeamCoverage: current.analysisSnapshot.redTeamCoverage,
            blockerCodes: [],
            sourceIdentitySha256:
                current.analysisSnapshot.hashes.sourceIdentitySha256,
        });
        advanced = true;
    }
    audit.assurance = Object.freeze({
        ...current,
        stageState,
        analysisSnapshot,
        graphPlan: recomputedGraph,
        graphTrace: trace,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return structuredClone({ advanced, state: audit.assurance, trace });
}

export function getEvasiveGraphState(sessionId, { auditId } = {}) {
    const state = getAssuranceState(sessionId, { auditId });
    if (!state) return null;
    return {
        graphBaseSnapshot: state.graphBaseSnapshot,
        graphPlan: state.graphPlan,
        graphTrace: state.graphTrace,
        stageState: state.stageState,
        analysisSnapshot: state.analysisSnapshot,
    };
}

function requireAssuranceValidationState(sessionId, auditId) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("assurance validation requires an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("assurance validation auditId does not match active audit");
    }
    return { audit, current: ensureAssuranceState(audit) };
}

function buildAssurancePlanInputs(
    current,
    snapshot = current.validationBaseSnapshot,
) {
    if (!snapshot
        || !current.graphBaseSnapshot
        || !current.graphPlan
        || !current.graphTrace
        || !current.semanticCoverageEvaluation
        || !current.redTeamEvaluation) {
        throw new Error("assurance validation requires a complete graph trace");
    }
    return {
        snapshot,
        graphBaseSnapshot: current.graphBaseSnapshot,
        graph: current.graphPlan,
        trace: current.graphTrace,
        semanticEvaluation: current.semanticCoverageEvaluation,
        redTeamEvaluation: current.redTeamEvaluation,
        supplyChainGraph: current.supplyChainGraph,
    };
}

function storeAssuranceEvaluation(audit, current, {
    records = current.assuranceValidationRecords,
} = {}) {
    const evaluation = evaluateAssuranceValidation({
        plan: current.assuranceValidationPlan,
        planInputs: buildAssurancePlanInputs(current),
        records,
    });
    audit.assurance = Object.freeze({
        ...current,
        assuranceValidationRecords: Object.freeze([...records]),
        assuranceValidationEvaluation: evaluation,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return audit.assurance;
}

export function prepareAssuranceValidation(sessionId, {
    auditId,
    validatorIds,
    validatorVersion,
} = {}) {
    const { audit, current } = requireAssuranceValidationState(
        sessionId,
        auditId,
    );
    if (current.assuranceValidationPlan) {
        if (JSON.stringify(current.assuranceValidationPlan.validatorIds)
                !== JSON.stringify(validatorIds)
            || current.assuranceValidationPlan.validatorVersion
                !== validatorVersion) {
            throw new Error("assurance validation plan is immutable");
        }
        return structuredClone(current);
    }
    if (!current.analysisSnapshot
        || current.stageState.current !== "traced"
        || !current.graphTrace?.complete) {
        throw new Error(
            `assurance validation requires traced stage (current: ${current.stageState.current})`,
        );
    }
    const validationBaseSnapshot = current.analysisSnapshot;
    const planInputs = buildAssurancePlanInputs(
        current,
        validationBaseSnapshot,
    );
    const keys = listAssuranceValidationAssignmentKeys({
        graph: current.graphPlan,
    });
    const assignmentNonceSha256ByKey = Object.fromEntries(
        keys.map((key) => [key, randomBytes(32).toString("hex")]),
    );
    const assuranceValidationPlan = createAssuranceValidationPlan({
        ...planInputs,
        validatorIds,
        validatorVersion,
        assignmentNonceSha256ByKey,
    });
    const next = Object.freeze({
        ...current,
        validationBaseSnapshot,
        assuranceValidationPlan,
        assuranceValidationRecords: Object.freeze([]),
        assuranceValidationEvaluation: null,
    });
    return structuredClone(storeAssuranceEvaluation(audit, next));
}

export function recordAssuranceValidation(sessionId, {
    auditId,
    assignmentId,
    record,
} = {}) {
    const { audit, current } = requireAssuranceValidationState(
        sessionId,
        auditId,
    );
    if (!current.assuranceValidationPlan) {
        throw new Error("assurance validation requires a prepared plan");
    }
    const assignment = current.assuranceValidationPlan.assignments.find((entry) =>
        entry.assignmentId === assignmentId);
    if (!assignment) {
        throw new Error("assurance validation record references an unknown assignment");
    }
    const normalized = createAssuranceValidationRecord({
        assignment,
        assignmentToken: record?.assignmentToken,
        validatorId: record?.validatorId,
        conclusion: record?.conclusion,
        reviewedNodeIds: record?.reviewedNodeIds,
        reviewedEdgeIds: record?.reviewedEdgeIds,
        reviewedPathIds: record?.reviewedPathIds,
        reviewedEvidenceIds: record?.reviewedEvidenceIds,
        reviewedBasisIds: record?.reviewedBasisIds,
        checks: record?.checks,
        negativeEvidenceCodes: record?.negativeEvidenceCodes,
        blockerCodes: record?.blockerCodes,
    });
    const existing = current.assuranceValidationRecords.find((entry) =>
        entry.assignmentId === normalized.assignmentId);
    if (existing) {
        if (existing.recordId !== normalized.recordId) {
            throw new Error("assurance validation record is immutable");
        }
        return structuredClone({ record: existing, state: current });
    }
    if (current.stageState.current !== "traced") {
        throw new Error("assurance validation is already finalized");
    }
    const next = storeAssuranceEvaluation(audit, current, {
        records: [...current.assuranceValidationRecords, normalized],
    });
    return structuredClone({ record: normalized, state: next });
}

export function finalizeAssuranceValidation(sessionId, { auditId } = {}) {
    const { audit, current } = requireAssuranceValidationState(
        sessionId,
        auditId,
    );
    if (!current.assuranceValidationPlan
        || !current.assuranceValidationEvaluation) {
        throw new Error("assurance validation finalization requires a plan");
    }
    if (current.stageState.current === "validated") {
        return structuredClone({ advanced: true, state: current });
    }
    if (current.stageState.current !== "traced") {
        throw new Error(
            `assurance validation finalization requires traced stage (current: ${current.stageState.current})`,
        );
    }
    const evaluation = evaluateAssuranceValidation({
        plan: current.assuranceValidationPlan,
        planInputs: buildAssurancePlanInputs(current),
        records: current.assuranceValidationRecords,
    });
    if (!assuranceValidationCanAdvance(
        current.assuranceValidationPlan,
        evaluation,
    )) {
        audit.assurance = Object.freeze({
            ...current,
            assuranceValidationEvaluation: evaluation,
        });
        audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
        return structuredClone({ advanced: false, state: audit.assurance });
    }
    const stageState = transitionAssuranceStageState(current.stageState, {
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        from: "traced",
        to: "validated",
    });
    const analysisSnapshot = createAssuranceAnalysisSnapshot({
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        stageState,
        status: "incomplete",
        objectInventory: current.analysisSnapshot.objectInventory,
        derivedArtifacts: current.analysisSnapshot.derivedArtifacts,
        semanticReviewCoverage: current.analysisSnapshot.semanticReviewCoverage,
        semanticCandidateLedger: current.analysisSnapshot.semanticCandidateLedger,
        redTeamCoverage: current.analysisSnapshot.redTeamCoverage,
        blockerCodes: [],
        sourceIdentitySha256:
            current.analysisSnapshot.hashes.sourceIdentitySha256,
    });
    audit.assurance = Object.freeze({
        ...current,
        stageState,
        analysisSnapshot,
        assuranceValidationEvaluation: evaluation,
    });
    audit.assurance = validateAssuranceStateContainer(audit.assurance, audit);
    return structuredClone({ advanced: true, state: audit.assurance });
}

export function getAnalysisIndexState(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("analysis index state auditId does not match active audit");
    }
    return structuredClone(ensureAnalysisIndexState(audit));
}

export function getAnalysisIndexSnapshot(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("analysis index snapshot auditId does not match active audit");
    }
    return buildAnalysisIndexSnapshot(ensureAnalysisIndexState(audit));
}

export function getAnalysisPluginSnapshot(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("analysis plugin snapshot auditId does not match active audit");
    }

    return buildPluginRunnerSnapshot(
        ensureAnalysisPluginState(audit),
        ensureBehaviorGraph(audit),
    );
}

export function getAnalysisPluginCacheRecords(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("analysis plugin cache records auditId does not match active audit");
    }
    return buildPluginCacheRecords(ensureAnalysisPluginState(audit));
}

export function getBehaviorGraphDocument(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("behavior graph auditId does not match active audit");
    }
    return ensureBehaviorGraph(audit).toDocument();
}

function traceBlockerSnapshot(audit, stage, blockers, gates = {}) {
    return Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: audit.auditId,
        sourceNamespace: sourceNamespaceForAudit(audit),
        inputFingerprint: null,
        coverageComplete: false,
        advanced: false,
        idempotent: false,
        analysisStageBefore: stage.current,
        analysisStageAfter: stage.current,
        gates: Object.freeze({
            stageScanned: gates.stageScanned === true,
            candidateIngestionComplete: gates.candidateIngestionComplete === true,
            indexComplete: gates.indexComplete === true,
            pluginCoverageComplete: gates.pluginCoverageComplete === true,
            graphMergeComplete: gates.graphMergeComplete === true,
            traceAccountingComplete: gates.traceAccountingComplete === true,
        }),
        counts: Object.freeze({
            inputGraphs: 0,
            uniqueGraphs: 0,
            mergedGraphs: 0,
            nodes: 0,
            edges: 0,
            conflicts: 0,
            unresolvedReferences: 0,
            identityMismatches: 0,
            semanticNodes: 0,
            semanticEdges: 0,
            chains: 0,
            completeChains: 0,
            unresolvedChains: 0,
            contestedChains: 0,
            cycles: 0,
            exploredBranches: 0,
        }),
        truncation: Object.freeze({}),
        blockers: Object.freeze(blockers),
        validationQueue: Object.freeze([]),
        cycles: Object.freeze([]),
        chains: Object.freeze([]),
    });
}

export function getAnalysisTraceSnapshot(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("analysis trace snapshot auditId does not match active audit");
    }
    return audit.analysisTraceState?.snapshot
        ? structuredClone(audit.analysisTraceState.snapshot): null;
}

export function traceAnalysisGraph(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("behavior trace requires an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("behavior trace auditId does not match active audit");
    }
    const stage = ensureAnalysisStageState(audit);
    const indexState = ensureAnalysisIndexState(audit);
    const index = buildAnalysisIndexSnapshot(indexState);
    const plugins = buildPluginRunnerSnapshot(
        ensureAnalysisPluginState(audit),
        ensureBehaviorGraph(audit),
    );
    const councilSnapshot = modeUsesCouncil(audit.mode)
        ? getCouncilLedgerSnapshot(sessionId, { auditId: audit.auditId }): null;
    const blockers = [];
    const stageScanned = ["scanned", "traced", "validated", "finalized"].includes(stage.current);
    let candidateIngestionComplete = !modeUsesCouncil(audit.mode);
    if (modeUsesCouncil(audit.mode)) {
        const successful = councilSnapshot?.finalization?.successfulRoleIds || [];
        const submitted = new Set(
            councilSnapshot?.submissions?.map((entry) => entry.roleId) || [],
        );
        candidateIngestionComplete = !!councilSnapshot?.finalization
            && successful.length === submitted.size
            && successful.every((roleId) => submitted.has(roleId));
    }
    if (!stageScanned) {
        blockers.push({
            code: "scan-stage-incomplete",
            currentStage: stage.current,
        });
    }
    if (!candidateIngestionComplete) {
        blockers.push({ code: "candidate-ingestion-gates-incomplete" });
    }
    if (!index.complete) blockers.push({ code: "analysis-index-incomplete" });
    if (!plugins.coverageComplete) blockers.push({ code: "analysis-plugin-coverage-incomplete" });
    if (blockers.length > 0) {
        return traceBlockerSnapshot(audit, stage, blockers, {
            stageScanned,
            candidateIngestionComplete,
            indexComplete: index.complete,
            pluginCoverageComplete: plugins.coverageComplete,
        });
    }

    const graphs = [{
        kind: "deterministic-plugin-seeds",
        document: ensureBehaviorGraph(audit).toDocument(),
    }];
    const findings = [];
    if (councilSnapshot) {
        graphs.push({
            kind: "council-fragments",
            document: councilSnapshot.behaviorGraph,
        });
        findings.push(...councilSnapshot.findingLedger.findings);
    }
    const merged = mergeBehaviorGraphs({
        auditId: audit.auditId,
        sourceNamespace: sourceNamespaceForAudit(audit),
        indexState,
        graphs,
        findings,
    });
    const traced = traceBehaviorGraph(merged);
    const gates = Object.freeze({
        stageScanned: true,
        candidateIngestionComplete,
        indexComplete: index.complete,
        pluginCoverageComplete: plugins.coverageComplete,
        graphMergeComplete: merged.coverageComplete,
        traceAccountingComplete: traced.coverageComplete,
    });
    if (audit.analysisTraceState) {
        if (audit.analysisTraceState.inputFingerprint !== traced.inputFingerprint) {
            return traceBlockerSnapshot(audit, stage, [{
                code: "trace-input-identity-changed",
            }], {
                stageScanned: true,
                candidateIngestionComplete,
                indexComplete: index.complete,
                pluginCoverageComplete: plugins.coverageComplete,
            });
        }
        return structuredClone({
            ...audit.analysisTraceState.snapshot,
            idempotent: true,
        });
    }

    let snapshot = Object.freeze({
        ...traced,
        advanced: false,
        idempotent: false,
        analysisStageBefore: stage.current,
        analysisStageAfter: stage.current,
        gates,
    });
    audit.analysisTraceState = {
        inputFingerprint: traced.inputFingerprint,
        snapshot,
    };
    if (traced.coverageComplete && stage.current === "scanned") {
        const advanced = advanceAnalysisStage(sessionId, {
            auditId: audit.auditId,
            from: "scanned",
            to: "traced",
        });
        snapshot = Object.freeze({
            ...snapshot,
            advanced: true,
            analysisStageAfter: advanced.current,
        });
        audit.analysisTraceState = {
            inputFingerprint: traced.inputFingerprint,
            snapshot,
        };
    }
    return structuredClone(snapshot);
}

function validationRolesForAudit(audit) {
    if (!Array.isArray(audit.councilRoleManifest)
        || audit.councilRoleManifest.length === 0) {
        throw new Error("validation requires the active council role manifest");
    }
    return audit.councilRoleManifest;
}

function requireValidationAudit(sessionId, auditId) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("validation requires an active audit");
    if (!modeUsesCouncil(audit.mode)) {
        throw new Error("validation is available only for council audits");
    }
    if (validateAuditId(auditId) !== audit.auditId) {
        throw new Error("validation auditId does not match active audit");
    }
    return audit;
}

export function getAnalysisValidationSnapshot(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("validation snapshot auditId does not match active audit");
    }
    return getCouncilLedgerSnapshot(sessionId, { auditId: audit.auditId })?.validation || null;
}

export function getAnalysisDecisionSnapshot(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("decision snapshot auditId does not match active audit");
    }
    return getCouncilLedgerSnapshot(sessionId, {
        auditId: audit.auditId,
    })?.decisionSnapshot || null;
}

export function prepareAnalysisValidation(sessionId, {
    auditId,
    cursor = 0,
    limit = 8,
} = {}) {
    const audit = requireValidationAudit(sessionId, auditId);
    const stage = ensureAnalysisStageState(audit);
    if (!["traced", "validated", "finalized"].includes(stage.current)) {
        throw new Error(
            `validation preparation requires analysis stage traced or later; current is ${stage.current}`,
        );
    }
    const traceSnapshot = audit.analysisTraceState?.snapshot;
    if (!traceSnapshot || traceSnapshot.coverageComplete !== true
        || Object.values(traceSnapshot.truncation || {}).some(Boolean)
        || Object.values(traceSnapshot.gates || {}).some((value) => value !== true)) {
        throw new Error("validation preparation requires complete, untruncated graph tracing");
    }
    const roles = validationRolesForAudit(audit);
    const councilSnapshot = getCouncilLedgerSnapshot(sessionId, {
        auditId: audit.auditId,
    });
    if (!councilSnapshot?.finalization) {
        throw new Error("validation preparation requires finalized council candidate ingestion");
    }

    let validationState;
    mutateCouncilLedgerState(sessionId, {
        auditId: audit.auditId,
        roles,
    }, (state) => {
        if (!state.validationState) {
            const findings = state.findingLedger.listFindings();
            const invalidState = findings.find((finding) =>
                finding.state !== "candidate" && finding.state !== "validating");
            if (invalidState) {
                throw new Error(
                    `validation cannot start from finding state ${invalidState.state}: ${invalidState.id}`,
                );
            }
            const plan = buildValidationPlan({
                auditId: audit.auditId,
                minSeverity: audit.validationMinSeverity,
                findings,
                candidateContexts: [...state.candidateContexts.entries()]
                    .map(([findingId, context]) => ({ findingId, ...context })),
                traceSnapshot,
                graphDocuments: [
                    ensureBehaviorGraph(audit).toDocument(),
                    state.behaviorGraph.toDocument(),
                ],
                indexState: ensureAnalysisIndexState(audit),
            });
            for (const context of plan.contexts) {
                state.findingLedger.beginValidation(context.finding.id, {
                    auditId: audit.auditId,
                });
            }
            state.validationState = createValidationState(plan);
        }
        validationState = state.validationState;
    });

    return {
        analysisStageBefore: stage.current,
        analysisStageAfter: ensureAnalysisStageState(audit).current,
        validation: buildValidationSnapshot(validationState),
        page: pageValidationContexts(validationState, { cursor, limit }),
    };
}

export function submitAnalysisValidationDecision(sessionId, input) {
    const audit = requireValidationAudit(sessionId, input?.audit_id);
    const stage = ensureAnalysisStageState(audit);
    if (!["traced", "validated", "finalized"].includes(stage.current)) {
        throw new Error(`validation submission requires traced stage; current is ${stage.current}`);
    }
    const roles = validationRolesForAudit(audit);
    let result;
    mutateCouncilLedgerState(sessionId, {
        auditId: audit.auditId,
        roles,
    }, (state) => {
        const validationState = state.validationState;
        if (!validationState) {
            throw new Error("validation has not been prepared");
        }
        const context = validationState.contexts.get(input.finding_id);
        if (!context) throw new Error(`finding is not in the validation queue: ${input.finding_id}`);
        const otherType = input.decision_type === "confirm" ? "refute": "confirm";
        const otherDecision = validationState.decisions
            .get(`${input.finding_id}:${otherType}`)?.decision || null;
        const decision = validateStaticDecisionSubmission(input, {
            context,
            otherDecision,
        });
        result = storeStaticDecision(validationState, decision);
    });
    return {
        analysisStageBefore: stage.current,
        analysisStageAfter: ensureAnalysisStageState(audit).current,
        idempotent: result.idempotent,
        decision: result.decision,
        validation: getAnalysisValidationSnapshot(sessionId, {
            auditId: audit.auditId,
        }),
    };
}

export function adjudicateAnalysisValidation(sessionId, input) {
    const audit = requireValidationAudit(sessionId, input?.audit_id);
    const stage = ensureAnalysisStageState(audit);
    if (!["traced", "validated", "finalized"].includes(stage.current)) {
        throw new Error(`validation adjudication requires traced stage; current is ${stage.current}`);
    }
    const roles = validationRolesForAudit(audit);
    let result;
    mutateCouncilLedgerState(sessionId, {
        auditId: audit.auditId,
        roles,
    }, (state) => {
        const validationState = state.validationState;
        if (!validationState) {
            throw new Error("validation has not been prepared");
        }
        const context = validationState.contexts.get(input.finding_id);
        if (!context) throw new Error(`finding is not in the validation queue: ${input.finding_id}`);
        const confirmDecision = validationState.decisions
            .get(`${input.finding_id}:confirm`)?.decision || null;
        const refuteDecision = validationState.decisions
            .get(`${input.finding_id}:refute`)?.decision || null;
        const adjudication = validateAdjudicationSubmission(input, {
            context,
            confirmDecision,
            refuteDecision,
        });
        const existing = validationState.adjudications.get(adjudication.findingId);
        if (existing) {
            result = storeAdjudication(validationState, adjudication);
            return;
        }
        const finding = state.findingLedger.getFinding(adjudication.findingId);
        if (!finding || finding.state !== "validating") {
            throw new Error(
                `finding ${adjudication.findingId} is not in validating state`,
            );
        }
        state.findingLedger.applyValidationDecision({
            schemaVersion: ANALYSIS_SCHEMA_REVISION,
            auditId: audit.auditId,
            findingId: adjudication.findingId,
            validator: adjudication.adjudicatorId,
            decision: adjudication.decision,
            severity: adjudication.severity,
            confidence: adjudication.confidence,
            maliciousProjectFit: adjudication.maliciousProjectFit,
            rationaleCode: adjudication.rationaleCode,
            rationale: adjudication.rationale,
            evidence: adjudication.evidence,
        });
        result = storeAdjudication(validationState, adjudication);
    });
    return {
        analysisStageBefore: stage.current,
        analysisStageAfter: ensureAnalysisStageState(audit).current,
        idempotent: result.idempotent,
        adjudication: result.decision,
        validation: getAnalysisValidationSnapshot(sessionId, {
            auditId: audit.auditId,
        }),
    };
}

export function finalizeAnalysisValidation(sessionId, { auditId } = {}) {
    const audit = requireValidationAudit(sessionId, auditId);
    const roles = validationRolesForAudit(audit);
    const stage = ensureAnalysisStageState(audit);
    let finalized;
    mutateCouncilLedgerState(sessionId, {
        auditId: audit.auditId,
        roles,
    }, (state) => {
        if (!state.validationState) {
            throw new Error("validation has not been prepared");
        }
        finalized = finalizeValidationState(state.validationState);
        const validationSnapshot = buildValidationSnapshot(state.validationState);
        const indexSnapshot = buildAnalysisIndexSnapshot(ensureAnalysisIndexState(audit));
        const pluginSnapshot = buildPluginRunnerSnapshot(
            ensureAnalysisPluginState(audit),
            ensureBehaviorGraph(audit),
        );
        const traceSnapshot = audit.analysisTraceState?.snapshot || null;
        const successfulRoleIds = state.finalization?.successfulRoleIds || [];
        const submittedRoleIds = new Set(state.submissions.keys());
        const councilComplete = !!state.finalization
            && successfulRoleIds.length === submittedRoleIds.size
            && successfulRoleIds.every((roleId) => submittedRoleIds.has(roleId));
        const decisionSnapshot = buildTrustedDecisionSnapshot({
            auditId: audit.auditId,
            findings: state.findingLedger.listFindings(),
            traceSnapshot,
            validationSnapshot,
            coverage: {
                acquisitionComplete: indexSnapshot.complete,
                indexComplete: indexSnapshot.complete,
                pluginCoverageComplete: pluginSnapshot.coverageComplete,
                councilComplete,
                traceComplete: traceSnapshot?.coverageComplete === true
                    && Object.values(traceSnapshot?.gates || {}).every(Boolean)
                    && !Object.values(traceSnapshot?.truncation || {}).some(Boolean),
                validationComplete: validationSnapshot.completion.complete === true
                    && !Object.values(validationSnapshot.truncation || {}).some(Boolean)
                    && !!validationSnapshot.finalization,
                cacheTrackingComplete: true,
            },
        });
        if (state.decisionSnapshot
            && state.decisionSnapshot.decisionId !== decisionSnapshot.decisionId) {
            throw new Error("validated decision snapshot identity changed");
        }
        state.decisionSnapshot ||= decisionSnapshot;
        state.findingLedger.setRemediationPlan(generateRemediationPlan({
            auditId: audit.auditId,
            decisionSnapshot: state.decisionSnapshot,
            traceSnapshot,
        }));
    });
    let advanced = false;
    let nextStage = ensureAnalysisStageState(audit);
    if (nextStage.current === "traced") {
        nextStage = advanceAnalysisStage(sessionId, {
            auditId: audit.auditId,
            from: "traced",
            to: "validated",
        });
        advanced = true;
    } else if (!["validated", "finalized"].includes(nextStage.current)) {
        throw new Error(
            `validation finalization requires traced stage; current is ${nextStage.current}`,
        );
    }
    return {
        analysisStageBefore: stage.current,
        analysisStageAfter: nextStage.current,
        advanced,
        idempotent: finalized.idempotent || !advanced,
        validation: getAnalysisValidationSnapshot(sessionId, {
            auditId: audit.auditId,
        }),
        decisionSnapshot: getAnalysisDecisionSnapshot(sessionId, {
            auditId: audit.auditId,
        }),
        remediation: getCouncilLedgerSnapshot(sessionId, {
            auditId: audit.auditId,
        })?.findingLedger.remediation || null,
    };
}

function requireAnalysisAudit(sessionId, auditId) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("analysis index requires an active audit");
    if (validateAuditId(auditId) !== audit.auditId) {
        throw new Error("analysis index auditId does not match active audit");
    }
    return audit;
}

function normalizeIndexedSourcePath(path) {
    const normalized = String(path || "").replace(/\\/g, "/").replace(/^\.\/+/, "");
    if (!normalized || normalized.length > 1024 || normalized.startsWith("/")
        || normalized.endsWith("/") || normalized.includes("//")
        || normalized.split("/").some((segment) => segment === "." || segment === "..")
        || /[\u0000-\u001f\u007f]/u.test(normalized)) {
        throw new Error(`invalid indexed source path: ${JSON.stringify(path)}`);
    }
    return normalized;
}

function indexedSourceFileRecord(audit, path) {
    const state = ensureAnalysisIndexState(audit);
    const normalizedPath = normalizeIndexedSourcePath(path);
    const index = state.fileIndex.get(normalizedPath);
    const file = Number.isInteger(index) ? state.files[index]: null;
    if (!file) throw new Error(`indexed source path was not enumerated: ${normalizedPath}`);
    const evidenceReferences = Object.freeze(file.factIds.map((factId) => {
        const factIndex = state.factIndex.get(factId);
        return Number.isInteger(factIndex) ? state.facts[factIndex]: null;
    }).filter(Boolean).map((fact) => Object.freeze({
        startLine: fact.line,
        endLine: fact.endLine,
        excerptHash: fact.excerptHash,
        factId: fact.id,
        kind: fact.kind,
    })));
    return {
        auditId: audit.auditId,
        sourceKind: state.sourceKind,
        path: normalizedPath,
        size: file.size,
        status: file.status,
        classification: file.classification,
        contentSha256: file.contentSha256,
        blobSha: file.blobSha,
        blobOrContentSha: file.blobSha || file.contentSha256,
        lineCount: file.lineCount,
        evidenceReferences,
    };
}

export function listIndexedSourceFiles(sessionId, {
    auditId,
    cursor = 0,
    limit = 1_000,
} = {}) {
    const audit = requireAnalysisAudit(sessionId, auditId);
    if (!Number.isSafeInteger(cursor) || cursor < 0) {
        throw new Error("indexed source cursor must be a non-negative integer");
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
        throw new Error("indexed source limit must be between 1 and 1000");
    }
    const state = ensureAnalysisIndexState(audit);
    const paths = state.files.map((file) => file.path).sort((a, b) => a.localeCompare(b));
    return Object.freeze({
        auditId: audit.auditId,
        sourceKind: state.sourceKind,
        total: paths.length,
        cursor,
        nextCursor: cursor + limit < paths.length ? cursor + limit: null,
        files: Object.freeze(paths.slice(cursor, cursor + limit).map((path) =>
            Object.freeze(indexedSourceFileRecord(audit, path)))),
    });
}

export function getIndexedSourceFile(sessionId, { auditId, path } = {}) {
    const audit = requireAnalysisAudit(sessionId, auditId);
    return Object.freeze(indexedSourceFileRecord(audit, path));
}

export function listAnalysisFacts(sessionId, {
    auditId,
    path = null,
    kind = null,
    cursor = 0,
    limit = 256,
} = {}) {
    const audit = requireAnalysisAudit(sessionId, auditId);
    const state = ensureAnalysisIndexState(audit);
    const page = listIndexedFacts(state, { path, kind, cursor, limit });
    return Object.freeze({
        auditId: audit.auditId,
        sourceKind: state.sourceKind,
        path: path === null ? null: normalizeIndexedSourcePath(path),
        kind,
        ...page,
        facts: Object.freeze(page.facts.map((fact) => Object.freeze(fact))),
    });
}

export function validateIndexedEvidenceReference(sessionId, {
    auditId,
    path,
    startLine,
    endLine,
    excerptHash,
    blobSha,
    contentSha256,
} = {}) {
    const file = getIndexedSourceFile(sessionId, { auditId, path });
    if (file.status !== "indexed-text" || file.classification !== "text") {
        throw new Error(`evidence source is not fully indexed text: ${file.path}`);
    }
    if (!Number.isSafeInteger(startLine) || startLine < 1
        || !Number.isSafeInteger(endLine) || endLine < startLine
        || !Number.isSafeInteger(file.lineCount) || endLine > file.lineCount) {
        throw new Error(`evidence line range is outside indexed bounds for ${file.path}`);
    }
    const normalizedExcerptHash = String(excerptHash || "").toLowerCase();
    if (!/^[a-f0-9]{64}$/u.test(normalizedExcerptHash)) {
        throw new Error("evidence excerptHash must be a SHA-256 hex digest");
    }
    if (blobSha !== undefined && blobSha !== null
        && String(blobSha).toLowerCase() !== file.blobOrContentSha) {
        throw new Error(`evidence blob/content identity mismatch at ${file.path}`);
    }
    if (contentSha256 !== undefined && contentSha256 !== null
        && String(contentSha256).toLowerCase() !== file.contentSha256) {
        throw new Error(`evidence content SHA-256 mismatch at ${file.path}`);
    }
    const match = file.evidenceReferences.find((reference) =>
        reference.startLine === startLine
        && reference.endLine === endLine
        && reference.excerptHash === normalizedExcerptHash);
    if (!match) {
        throw new Error(
            `evidence excerpt hash/line range is not a trusted indexed fact: ${file.path}:${startLine}-${endLine}`,
        );
    }
    return Object.freeze({
        ok: true,
        auditId: file.auditId,
        sourceKind: file.sourceKind,
        path: file.path,
        startLine,
        endLine,
        excerptHash: normalizedExcerptHash,
        blobSha: file.blobOrContentSha,
        contentSha256: file.contentSha256,
        factId: match.factId,
        factKind: match.kind,
    });
}

export function mutateAnalysisIndexState(sessionId, mutator) {
    const audit = getActiveAudit(sessionId);
    if (!audit || typeof mutator !== "function") return { ok: false };
    const state = ensureAnalysisIndexState(audit);
    return {
        ok: true,
        value: mutator(state),
    };
}

export function maybeAdvanceAnalysisPrepared(sessionId) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    const stage = ensureAnalysisStageState(audit);
    const index = buildAnalysisIndexSnapshot(ensureAnalysisIndexState(audit));
    let analysisPlugins = buildPluginRunnerSnapshot(
        ensureAnalysisPluginState(audit),
        ensureBehaviorGraph(audit),
    );
    if (index.complete) {
        analysisPlugins = runAnalysisPlugins({
            auditId: audit.auditId,
            indexState: ensureAnalysisIndexState(audit),
            behaviorGraph: ensureBehaviorGraph(audit),
            state: ensureAnalysisPluginState(audit),
            sourceNamespace: sourceNamespaceForAudit(audit),
        });
    }
    if (stage.current === "acquired" && index.complete && analysisPlugins.coverageComplete) {
        audit.analysisStageState = validateAnalysisStageState({
            schemaVersion: ANALYSIS_SCHEMA_REVISION,
            auditId: audit.auditId,
            current: "prepared",
            history: ["acquired", "prepared"],
        });
    }
    return {
        analysisStageState: structuredClone(ensureAnalysisStageState(audit)),
        analysisIndex: index,
        analysisPlugins,
        behaviorGraph: analysisPlugins.behaviorGraph,
    };
}

export function getAnalysisStageState(sessionId, { auditId } = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== audit.auditId) {
        throw new Error("analysis stage state auditId does not match active audit");
    }
    return structuredClone(ensureAnalysisStageState(audit));
}

export function advanceAnalysisStage(sessionId, {
    auditId,
    from,
    to,
} = {}) {
    const audit = getActiveAudit(sessionId);
    if (!audit) throw new Error("cannot advance analysis stage without an active audit");
    const normalizedAuditId = validateAuditId(auditId);
    if (normalizedAuditId !== audit.auditId) {
        throw new Error("analysis stage transition auditId does not match active audit");
    }
    if (!ANALYSIS_STAGES.includes(from)) {
        throw new Error(`unknown analysis source stage: ${String(from)}`);
    }
    if (!ANALYSIS_STAGES.includes(to)) {
        throw new Error(`unknown analysis target stage: ${String(to)}`);
    }
    const current = ensureAnalysisStageState(audit);
    if (current.current !== from) {
        throw new Error(
            `stale analysis stage transition: expected ${from}, current is ${current.current}`,
        );
    }
    if (to === from) return structuredClone(current);
    const currentIndex = ANALYSIS_STAGES.indexOf(current.current);
    if (ANALYSIS_STAGES[currentIndex + 1] !== to) {
        throw new Error(`illegal analysis stage transition: ${current.current} -> ${to}`);
    }
    if (current.current === "acquired" && to === "prepared") {
        const index = buildAnalysisIndexSnapshot(ensureAnalysisIndexState(audit));
        if (!index.complete) {
            throw new Error(
                "analysis preparation incomplete: acquisition/enumeration/read/index requirements are not complete",
            );
        }
        const analysisPlugins = runAnalysisPlugins({
            auditId: audit.auditId,
            indexState: ensureAnalysisIndexState(audit),
            behaviorGraph: ensureBehaviorGraph(audit),
            state: ensureAnalysisPluginState(audit),
            sourceNamespace: sourceNamespaceForAudit(audit),
        });
        if (!analysisPlugins.coverageComplete) {
            throw new Error(
                "analysis preparation incomplete: one or more detected ecosystem plugins failed or truncated",
            );
        }
    }
    if (current.current === "scanned" && to === "traced"
        && audit.mode !== "metadata_only") {
        const trace = audit.analysisTraceState?.snapshot;
        if (!trace || trace.coverageComplete !== true
            || trace.gates?.candidateIngestionComplete !== true
            || trace.gates?.indexComplete !== true
            || trace.gates?.pluginCoverageComplete !== true
            || trace.gates?.graphMergeComplete !== true
            || trace.gates?.traceAccountingComplete !== true) {
            throw new Error(
                "analysis trace incomplete: scanned can advance to traced only after candidate, index, plugin, graph-merge, and bounded trace-accounting gates pass",
            );
        }
    }
    if (current.current === "traced" && to === "validated"
        && modeUsesCouncil(audit.mode)) {
        const validation = getCouncilLedgerSnapshot(sessionId, {
            auditId: audit.auditId,
        })?.validation;
        if (!validation
            || validation.completion?.complete !== true
            || Object.values(validation.truncation || {}).some(Boolean)
            || !validation.finalization) {
            throw new Error(
                "analysis validation incomplete: traced can advance to validated only after every required candidate has independent confirm/refute decisions and an adjudication, with no validation truncation",
            );
        }
    }
    const next = validateAnalysisStageState({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: audit.auditId,
        current: to,
        history: [...current.history, to],
    });
    audit.analysisStageState = next;
    return structuredClone(next);
}

/**
 * Resolve the trusted audit context for a wrapper invocation.
 *
 * Returns one of:
 *   { ok: true,  buildRoot, mode, expectedClonePath, resolvedClonePath, owner, repo, hasActiveAudit: true  }
 *   { ok: true,  buildRoot, mode, expectedClonePath, resolvedClonePath, owner, repo, hasActiveAudit: false }
 *   { ok: false, error }
 */
export function getTrustedAuditContext({ sessionId, args, defaultBuildRoot }) {
    const audit = sessionId ? getActiveAudit(sessionId): null;

    if (audit) {
        if (args && args.build_root) {
            const argResolved = nodePath.resolve(String(args.build_root)).toLowerCase();
            const auditResolved = audit.buildPath.toLowerCase();
            if (argResolved !== auditResolved) {
                return {
                    ok: false,
                    error: `args.build_root (${args.build_root}) does not match the active audit's build_root (${audit.buildPath}); refusing to operate on a different sandbox`,
                };
            }
        }
        return {
            ok: true,
            buildRoot: audit.buildPath,
            auditId: audit.auditId,
            mode: audit.mode,
            expectedClonePath: audit.expectedClonePath,
            resolvedClonePath: audit.resolvedClonePath || null,
            resolvedSha: audit.resolvedSha || null,
            owner: audit.owner || null,
            repo: audit.repo || null,
            canonicalOwner: audit.canonicalOwner || null,
            canonicalRepo: audit.canonicalRepo || null,
            ref: audit.ref || null,
            refType: audit.refType || null,
            urlKind: audit.urlKind || null,
            releaseSelector: audit.releaseSelector || null,
            releaseIdentity: audit.releaseIdentity
                ? structuredClone(audit.releaseIdentity): null,
            rootTreeSha: audit.treeEnumerationState?.rootTreeSha || null,
            // Local-source audit fields. Null on URL-driven audits.
            localPath: audit.localPath || null,
            localReportSlug: audit.localReportSlug || null,
            localReportTimestamp: audit.localReportTimestamp || null,
            expectedReportPath: audit.expectedReportPath || null,
            expectedQuarantinePath: audit.expectedQuarantinePath || null,
            reportFinalization: audit.reportFinalization
                ? structuredClone(audit.reportFinalization): null,
            analysisStageState: structuredClone(ensureAnalysisStageState(audit)),
            analysisIndex: buildAnalysisIndexSnapshot(ensureAnalysisIndexState(audit)),
            analysisPlugins: buildPluginRunnerSnapshot(
                ensureAnalysisPluginState(audit),
                ensureBehaviorGraph(audit),
            ),
            behaviorGraph: {
                auditId: audit.auditId,
                nodeCount: ensureBehaviorGraph(audit).nodeCount,
                edgeCount: ensureBehaviorGraph(audit).edgeCount,
            },
            analysisTrace: audit.analysisTraceState?.snapshot
                ? {
                    coverageComplete: audit.analysisTraceState.snapshot.coverageComplete,
                    chainCount: audit.analysisTraceState.snapshot.counts.chains,
                    conflictCount: audit.analysisTraceState.snapshot.counts.conflicts,
                }: null,
            analysisValidation: modeUsesCouncil(audit.mode)
                ? getCouncilLedgerSnapshot(sessionId, {
                    auditId: audit.auditId,
                })?.validation || null: null,
            analysisDecision: modeUsesCouncil(audit.mode)
                ? getCouncilLedgerSnapshot(sessionId, {
                    auditId: audit.auditId,
                })?.decisionSnapshot || null: null,
            assurance: (() => {
                const state = ensureAssuranceState(audit);
                return {
                    schemaVersion: state.schemaVersion,
                    sourceNamespace: state.sourceNamespace,
                    stageState: structuredClone(state.stageState),
                    hasAnalysisSnapshot: state.analysisSnapshot !== null,
                    hasSupplyChainGraph: state.supplyChainGraph !== null,
                };
            }),
            hasActiveAudit: true,
        };
    }

    const fallback = (args && args.build_root) || defaultBuildRoot;
    if (!fallback) {
        return { ok: false, error: "no active audit and no default build_root supplied" };
    }
    if (sessionId && args && args.build_root) {
        const argResolved = nodePath.resolve(String(args.build_root)).toLowerCase();
        const defaultResolved = nodePath.resolve(String(defaultBuildRoot)).toLowerCase();
        if (argResolved !== defaultResolved) {
            return {
                ok: false,
                error: `no active audit for session and args.build_root (${args.build_root}) does not match default build_root; refusing to operate on agent-supplied build_root without an audit. Re-invoke zerotrust_sourcecheck to activate an audit first.`,
            };
        }
    }

    return {
        ok: true,
        buildRoot: nodePath.resolve(String(fallback)),
        auditId: null,
        mode: null,
        expectedClonePath: null,
        resolvedClonePath: null,
        resolvedSha: null,
        owner: null,
        repo: null,
        canonicalOwner: null,
        canonicalRepo: null,
        ref: null,
        refType: null,
        urlKind: null,
        releaseSelector: null,
        releaseIdentity: null,
        rootTreeSha: null,
        localPath: null,
        localReportSlug: null,
        localReportTimestamp: null,
        expectedReportPath: null,
        expectedQuarantinePath: null,
        reportFinalization: null,
        analysisStageState: null,
        analysisIndex: null,
        analysisPlugins: null,
        behaviorGraph: null,
        assurance: null,
        hasActiveAudit: false,
    };
}

// Tools we treat as command-runners and inspect before execution.
// "powershell" is the primary CLI shell tool; "bash" / "run_command"
// covered for portability with other shell-flavored extension tools.
const SHELL_TOOLS = new Set(["powershell", "bash", "run_command"]);

// Patterns that indicate a package manager install. Each entry is
// { pattern, requiredFlagRegex, ecosystem } — the install is denied
// unless requiredFlagRegex matches the same command. The unregistered compatibility
// hook still preserves its historical full-mode exemption below, but that is
// not the current wrapper behavior: safe/full modes use the same installer and
// install lifecycle scripts remain suppressed.
// security rationale: superseded by hasSafeIgnoreScripts etc.
// Kept here as compatibility reference; no callers remain.
const NEVER_MATCH = /(?!)/;

// security rationale: nopt (npm's CLI parser)
// consumes the NEXT argv as the value of a Boolean flag if that argv
// is one of true/false/0/1/yes/no/on/off. So `--ignore-scripts false`
// disables script suppression even though the regex sees the safe
// flag. Replace REQUIRE_IGNORE_SCRIPTS with an argv-walker that
// handles `=value`, separate-token value, and the inverse form.
//
// hasSafeIgnoreScripts returns true iff:
//   - some token is `--ignore-scripts` (bare, OR with `=true`/`=1`/
//     `=yes`/`=on`), AND
//   - that bare-form token is NOT immediately followed by a value-token
//     in {false, 0, no, off}, AND
//   - no token is `--no-ignore-scripts`, AND
//   - no token is `--ignore-scripts` with `=false`/`=0`/`=no`/`=off`.
function hasSafeIgnoreScripts(cmd) {
    const tokens = tokenizeShell(String(cmd || ""));
    let hasSafe = false;
    let hasNegation = false;
    const stripVal = (s) => String(s || "").replace(/^["']|["']$/g, "").toLowerCase();
    for (let i = 0; i < tokens.length; i++) {
        const tLower = tokens[i].toLowerCase().replace(/["']/g, "");
        if (tLower === "--no-ignore-scripts") {
            hasNegation = true;
            continue;
        }
        const m = tLower.match(/^--ignore-scripts(?:=(.+))?$/);
        if (!m) continue;
        const attached = m[1];
        if (attached === undefined) {
            // Bare flag — peek next token.
            const next = stripVal(tokens[i + 1]);
            if (["true", "1", "yes", "on"].includes(next)) {
                hasSafe = true; i++;
            } else if (["false", "0", "no", "off"].includes(next)) {
                hasNegation = true; i++;
            } else {
                hasSafe = true;
            }
        } else {
            const v = stripVal(attached);
            if (["true", "1", "yes", "on"].includes(v)) hasSafe = true;
            else if (["false", "0", "no", "off"].includes(v)) hasNegation = true;
        }
    }
    return hasSafe && !hasNegation;
}

function hasSafePipFlags(cmd) {
    const tokens = tokenizeShell(String(cmd || "")).map((t) => t.replace(/["']/g, ""));
    if (tokens.includes("--only-binary=:all:")) return true;
    return tokens.includes("--no-deps") && tokens.includes("--no-build-isolation");
}

function hasSafeCargoFlags(cmd) {
    const tokens = tokenizeShell(String(cmd || "")).map((t) => t.replace(/["']/g, ""));
    return tokens.includes("--locked") && tokens.includes("--offline");
}

function neverSafe() {
    return false;
}

const INSTALL_RULES = [
    {
        ecosystem: "npm",
        pattern: /\b(?:npm)\s+(?:install|i|add|ci)\b/i,
        // npm subcommands that run lifecycle scripts but are
        // neutralizable by --ignore-scripts. Note: exec/x/init/create
        // moved to the no-safe-flag rule below since --ignore-scripts
        // doesn't actually prevent npx-style download+execute.
        normalizedPattern: /\bnpm(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:install|i|add|ci|pack|rebuild|run|run-script|test|start|prune)\b/,
        safeChecker: hasSafeIgnoreScripts,
        flagHint: "--ignore-scripts (no =false/no separate-token value/no --no-ignore-scripts)",
    },
    {
        // security rationale: npx, pnpm dlx, yarn
        // dlx, npm exec, npm x, npm init, npm create, pnpm create,
        // pnpm dlx, yarn dlx — all download AND execute a package as
        // their primary purpose. NO safe-flag equivalent.
        // Suffix group is now WITHIN each alternation arm so .exe/.cmd/
        // .ps1 attach to the program name correctly (pnpm.exe dlx
        // bypassed the security pattern).
        ecosystem: "npx",
        pattern: /\bnpx\b/i,
        normalizedPattern:
            /\b(?:npx(?:\.exe|\.cmd|\.ps1)?\b|npm(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:exec|x|init|create)\b|pnpm(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:dlx|create|exec)\b|yarn(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:dlx|create)\b)/,
        safeChecker: neverSafe,
        flagHint: "(npx/dlx/exec/x/init/create have no safe-mode flag — use audit_and_full_build with explicit ack)",
    },
    {
        ecosystem: "yarn",
        pattern: /\byarn(?:\s+(?:install|add))?\b/i,
        normalizedPattern: /\byarn(?:\.exe|\.cmd|\.ps1)?\b/,
        safeChecker: hasSafeIgnoreScripts,
        flagHint: "--ignore-scripts (no =false/no separate-token value/no --no-ignore-scripts)",
    },
    {
        ecosystem: "pnpm",
        pattern: /\bpnpm\s+(?:install|i|add)\b/i,
        normalizedPattern: /\bpnpm(?:\.exe|\.cmd|\.ps1)?\s+(?:\S+\s+)*?(?:install|i|add|update|rebuild|run|test|start|pack|prune)\b/,
        safeChecker: hasSafeIgnoreScripts,
        flagHint: "--ignore-scripts (no =false/no separate-token value/no --no-ignore-scripts)",
    },
    {
        ecosystem: "pip",
        pattern: /\bpip3?\s+install\b/i,
        // security rationale: allow no-space short option
        // `python -mpip install` (CPython parses -mPATH as -m PATH).
        normalizedPattern: /(?:\bpip3?(?:\.exe)?\s+install\b|\b(?:python\d*|py)(?:\.exe)?\s+-m\s*pip(?:\d*)?\s+install\b)/,
        safeChecker: hasSafePipFlags,
        flagHint: "--only-binary=:all: (or --no-deps --no-build-isolation, no =false negations)",
    },
    {
        ecosystem: "cargo",
        pattern: /\bcargo\s+install\b/i,
        normalizedPattern: /\bcargo(?:\.exe)?\s+install\b/,
        safeChecker: hasSafeCargoFlags,
        flagHint: "--locked --offline",
    },
    {
        ecosystem: "go",
        pattern: /\bgo\s+install\b/i,
        normalizedPattern: /\bgo(?:\.exe)?\s+install\b/,
        safeChecker: neverSafe,
        flagHint: "(no safe equivalent on Go — use audit_and_full_build if you need it)",
    },
    {
        ecosystem: "gradle",
        pattern: /\b(?:gradle|gradlew|\.\/gradlew)\b/i,
        normalizedPattern: /\b(?:gradle|gradlew)(?:\.bat|\.exe)?\b/,
        safeChecker: neverSafe,
        flagHint: "(gradle has no safe-mode flag — use audit_and_full_build if you need it)",
    },
    {
        ecosystem: "maven",
        pattern: /\b(?:mvn|mvnw|\.\/mvnw)\b/i,
        normalizedPattern: /\b(?:mvn|mvnw)(?:\.bat|\.exe|\.cmd)?\b/,
        safeChecker: neverSafe,
        flagHint: "(mvn has no safe-mode flag — use audit_and_full_build if you need it)",
    },
];

// Synthesized install rule for the PS programmatic name-synthesis
// fallback. Always denied — there's no legit reason to construct
// `npm` etc. via [char] arithmetic during an audit.
const SYNTHESIZED_INSTALL_RULE = {
    ecosystem: "synthesized",
    pattern: /(?!)/,
    normalizedPattern: /(?!)/,
    safeChecker: neverSafe,
    flagHint: "(programmatic name-synthesis denied in audit modes)",
};

// security rationale: add `i` (npm/pnpm single-letter
// install alias). The synthesis fallback fires when an install-verb
// is paired with a PS sigil, so adding `i` here closes synthesized
// `npm i` (e.g. `& ([char]110+[char]112+[char]109) i`).
const INSTALL_VERB_RE =
    /\b(?:install|i|ci|add|init|create|pack|rebuild|run|run-script|test|start|exec|prune|dlx|x|update)\b/i;

// Patterns matching "running an executable from build_root". Mainly meant
// to prevent the agent from accidentally launching a downloaded release
// binary or compiled artifact from inside the audited tree.
//
// AV-safety: process-launch cmdlet names are built by character-concatenation
// at module load time so the literal cmdlet strings NEVER appear as
// contiguous bytes anywhere in this source file (including this comment).
// This matters because external code-review agents sometimes invoke ripgrep
// with offensive cmdlet names concatenated into a single regex argument,
// which trips Defender heuristics when the cmdline enumerates many such
// cmdlets together. Keeping our own source files free of contiguous
// offensive-cmdlet strings reduces the risk that any tool that reads our
// source then writes the read content back into a process argv list will
// trigger AV. (security rationale: the previous version of this comment
// inadvertently spelled out the three cmdlet names in a list — removed.)
const EXEC_CMDLET_PARTS = [
    ["Start", "Process"],
    ["Invoke", "Item"],
    ["Mount", "DiskImage"],
];
const EXECUTION_PATTERNS = EXEC_CMDLET_PARTS.map(
    (parts) => new RegExp("\\b" + parts.join("-") + "\\b", "i"),
);

// security rationale: refuse GUI-launching and disk-writing commands during
// ANY audit mode (not just build modes). The user-visible bug was a
// sub-agent calling `Invoke-Item <path-to-file>` mid-audit, which
// opened the file in Notepad — surprising/unwanted side effect. The
// same sub-agents also downloaded source files to disk via
// `iwr -OutFile` instead of using zerotrust_safe_fetch_file. Both
// classes of misuse now hit a hard deny here.
//
// AV-safety: same parts-join trick as EXEC_CMDLET_PARTS — the literal
// cmdlet strings are assembled at module load, never appear as
// contiguous bytes in this source.
const GUI_OPEN_CMDLET_PARTS = [
    ["Invoke", "Item"],
    ["Start", "Process"],
];
const GUI_BARE_PROGRAMS = [
    "notepad", "wordpad", "mspaint",
    "winword", "excel", "powerpnt", "outlook",
];
const GUI_OPEN_PATTERNS = (() => {
    const out = [];
    for (const parts of GUI_OPEN_CMDLET_PARTS) {
        out.push({
            re: new RegExp("\\b" + parts.join("-") + "\\b", "i"),
            name: parts.join("-"),
        });
    }
    // `ii` PowerShell alias for Invoke-Item. Require some target token
    // after the alias to avoid matching the word "ii" inside identifiers.
    // security fix: the original regex `["']?(?:[\\\/A-Za-z]|\.{1,2}[\\\/])`
    // required a slash AFTER the dot, missing `ii .` (open current dir
    // in Explorer — a common PowerShell idiom that pops a GUI window).
    // Broaden target to any non-whitespace char after the optional quote.
    out.push({
        re: /(?:^|[\s;|&`])ii\s+["']?\S/i,
        name: "ii (Invoke-Item alias)",
    });
    // `cmd /c start <thing>` (the cmd.exe builtin "start" opens the
    // default handler for a file or URL — Notepad for .txt, the
    // default browser for URLs, etc.).
    out.push({
        re: /\bcmd(?:\.exe)?\s+\/c\s+start\b/i,
        name: "cmd /c start",
    });
    // Bare `start <arg>` at the head of a (sub)command. We intentionally
    // do NOT match `Start-` (PowerShell `Start-*` cmdlets are caught by
    // their own GUI_OPEN_CMDLET_PARTS entry) because the `\b\s+`
    // requirement means `Start-Process` (with `-` after `t`) won't
    // satisfy the post-`start` whitespace.
    // security fix: the original regex required a path-shaped target
    // (`[A-Za-z]:\\`, `./`, `name.ext`, or `https://`), missing `start .`
    // (opens current dir in Explorer). Broaden to any non-empty arg.
    out.push({
        re: /(?:^|[;&|`]\s*)start\b\s+\S/i,
        name: "cmd.exe start",
    });
    for (const prog of GUI_BARE_PROGRAMS) {
        out.push({
            re: new RegExp("\\b" + prog + "(?:\\.exe)?\\b", "i"),
            name: prog,
        });
    }
    // VS Code / similar IDE launcher, but only when invoked with a
    // target argument. Don't match the substring "code" in identifiers.
    // security fix: the original regex required a path-shaped target
    // (`X:\`, `./`, `--flag`), missing `code .` (open current dir in
    // VS Code — extremely common command). Use a negative lookahead to
    // exclude bare `code` and broaden target.
    out.push({
        re: /\bcode(?:\.cmd|\.exe)?\s+(?!--?\w)\S/i,
        name: "VS Code launcher",
    });
    return out;
})();

// Disk-writing download patterns. During an audit the right tool for
// fetching repo content is zerotrust_safe_fetch_file (API-direct, no
// disk writes, audit-scoped to the pinned SHA). Sub-agents reaching
// for `iwr -OutFile` / `curl -o` / `wget -O` are working around the
// API-direct contract and leaving scratch source files on disk.
//
// KNOWN LIMITATION (security rationale): pure shell-redirect downloads cannot be
// reliably regex-matched without false positives — e.g.,
//   curl https://example.com > foo
//   gh api repos/.../contents/file > foo
//   Invoke-WebRequest -Uri ... > foo
// would all bypass these patterns. Catching `> file` unconditionally
// would false-positive on every legitimate stdout-to-file write the
// orchestrator might do (REPORT.md generation, etc.). The downstream
// `zerotrust_sweep_audit_scratch` wrapper is the active mitigation for
// the resulting scratch files; treat these enforcement patterns as
// forward-compatible defense for the specific named-flag forms only.
const DISK_DOWNLOAD_PATTERNS = [
    {
        re: /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^;|]*?\s-OutFile\b/i,
        name: "Invoke-WebRequest -OutFile",
    },
    {
        re: /\bcurl(?:\.exe)?\b[^;|]*\s(?:-o|-O|--output)(?:\s|=)/i,
        name: "curl -o/--output",
    },
    {
        re: /\bwget(?:\.exe)?\b[^;|]*\s(?:-O|--output-document)(?:\s|=)/i,
        name: "wget -O/--output-document",
    },
    // security rationale: catch the `<download-cmd> | Out-File/Set-Content/Add-Content/Tee-Object`
    // pipe form. The download source is unambiguously a download (iwr,
    // curl, wget, Invoke-RestMethod, gh api raw); the sink is unambiguously
    // a disk-write cmdlet. False positives are highly unlikely.
    {
        re: /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl(?:\.exe)?|wget(?:\.exe)?|gh\s+api)\b[^;]*\|\s*\b(?:Out-File|Set-Content|Add-Content|Tee-Object)\b/i,
        name: "download piped to Out-File / Set-Content / Tee-Object",
    },
];

// Heuristic: extract any path-like tokens from the command string.
// Returns absolute paths only. We skip git's own arguments here (because
// git accepts "remote URLs that look like paths") by handling git clone
// specially in the main inspector.
function extractPathTokens(command) {
    const tokens = [];
    // Quoted absolute paths
    const quoted = command.match(/(?:"|')([A-Za-z]:[\\\/][^"']{0,500})(?:"|')/g) || [];
    for (const q of quoted) tokens.push(q.slice(1, -1));
    // Bare absolute paths (drive letter + slash, terminated by whitespace)
    const bare = command.match(/(?<!["'])\b([A-Za-z]:[\\\/][^\s"']*)/g) || [];
    for (const b of bare) tokens.push(b);
    return tokens;
}

// security rationale: high-recall substring-based normalization
// for the audit-mode denial path. The tokenizer/operator-stripping
// approach (security rationale/security rationale) tried to parse shell syntax but every
// attacker shape we missed (env -i, & "sudo" git, /usr/bin/sudo git,
// nice -n 19 git, "git" cl"o"ne, & {git clone}, bash -c "git clone",
// xargs git clone, eval "git clone", g\it on bash, line continuation,
// etc.) became a real bypass.
//
// New design (defense-in-depth):
//   Layer 1 — substring scan (this function): for AUDIT-ONLY modes,
//     normalize the entire command into a quote/escape/whitespace-
//     stripped lowercase form, then scan for the substring "git" +
//     "clone" together (or gh+repo+clone). Audit modes have no legit
//     reason for these substrings to appear; false positives don't
//     matter — the agent will use safe_fetch_file, not a clone.
//   Layer 2 — tokenizer (existing detectsClone/validateCloneHit):
//     for BUILD modes only, where we need to validate the clone
//     destination matches the planned path. Tokenizer issues here
//     downgrade to "skipped path validation" (the agent's clone
//     proceeds with whatever destination it chose, which in build
//     mode the user has already authorized).
//
// This dual approach means no single bypass class can defeat both
// layers in audit mode — the substring layer is broad and cheap.
// security rationale: pre-collapse line continuations and
// caret/ANSI-C escapes BEFORE whitespace processing so:
//   - PS:    `git cl`<LF>one`             → `git clone`     (continuation FUSES tokens)
//   - bash:  `git cl\<LF>one`              → `git clone`
//   - cmd:   `g^it cl^one`                 → `git clone`     (caret-escape removed)
//   - bash:  `$'\x67it' clone`             → `git clone`     (ANSI-C decode)
//   - bash:  `git $'\x63\x6c\x6f\x6e\x65'` → `git clone`     (ANSI-C decode)
// security fix only handled BETWEEN-token continuations; security rationale also
// handles MID-token continuations (which the whitespace-collapse path
// would have split into two harmless words like `cl one`).
// security rationale: PowerShell 7+ added the
// Unicode-codepoint escape `` `u{HHHH} `` that decodes to any Unicode
// character (including ASCII letters). The security rationale backtick-strip
// preserves `\`u` (it's in the disallowed-set), but doesn't decode
// the trailing `{HHHH}`. So `` g`u{0069}t `` evaluates to `git` in
// PS 7+ but our regex sees the literal `gu{0069}t`, missing the
// detection. Mirror the bash ANSI-C decoder. Run this BEFORE the
// backtick-strip so the decoded char is processed normally.
function decodePsUnicodeEscapes(s) {
    return String(s || "").replace(/`u\{([0-9a-fA-F]{1,6})\}/g, (_m, hex) => {
        const cp = parseInt(hex, 16);
        if (!Number.isFinite(cp) || cp < 0 || cp > 0x10FFFD) return "";
        try { return String.fromCodePoint(cp); } catch { return ""; }
    });
}

const ANSI_C_ESCAPES = {
    "n": "\n", "r": "\r", "t": "\t", "b": "\b", "a": "\x07",
    "f": "\f", "v": "\v", "e": "\x1b", "0": "\0",
    "\\": "\\", "'": "'", '"': '"', "?": "?",
};

function decodeAnsiCQuoting(s) {
    return s.replace(/\$'([^']*)'/g, (_match, body) => {
        let out = "";
        for (let i = 0; i < body.length; i++) {
            if (body[i] === "\\" && i + 1 < body.length) {
                const next = body[i + 1];
                if (next === "x" && /[0-9a-f]{2}/i.test(body.substr(i + 2, 2))) {
                    out += String.fromCharCode(parseInt(body.substr(i + 2, 2), 16));
                    i += 3;
                } else if (next === "u" && /[0-9a-f]{4}/i.test(body.substr(i + 2, 4))) {
                    out += String.fromCharCode(parseInt(body.substr(i + 2, 4), 16));
                    i += 5;
                } else if (next in ANSI_C_ESCAPES) {
                    out += ANSI_C_ESCAPES[next];
                    i += 1;
                } else {
                    out += next;
                    i += 1;
                }
            } else {
                out += body[i];
            }
        }
        return out;
    });
}

// security rationale: tighten PS_SYNTHESIS_SIGIL_RE
// to avoid over-blocking legitimate audit commands. The previous regex
// matched:
//   - `&&  (` (the `&` of `&&` followed by ` (`) — chained sub-shell
//   - `gh api -f "key=val"` — gh CLI form-field syntax (cited by packet)
//   - `-join` anywhere — including grep IOC pattern
//   - `iex` / `Invoke-Expression` inside quoted strings (literal IOC grep)
//
// Fix:
//   1. Anchor `& (` and `& {` so the `&` cannot be the second of `&&`
//      (require the preceding char NOT be `&`).
//   2. Drop `-join` and `-f "…"` from the blanket-deny set entirely —
//      they're string-construction operators that only matter WHEN
//      paired with synthesis sigils (still caught via [char] / & $var
//      / `iex` / `& (`).
//   3. Strip all quoted spans before regex testing so legit commands
//      that grep for `iex` / `Invoke-Expression` literals don't fire.
const PS_SYNTHESIS_SIGIL_RE =
    /(?:\[char\]\s*\d|&\s*\$\w|invoke-expression|\biex\b|(?<![&|])&[ \t]*\(|(?<![&|])&[ \t]*\{|invoke-command\b)/i;

// security rationale: detect when a double-quoted span
// containing PS expansion ($var, $(...), ${...}) is used as the
// PROGRAM TOKEN (after `&` call operator or `.` dot-source operator).
// `& "$x" install` synthesizes the program name at runtime — the
// preserved-quote span hides the real program from substring scans.
// Treat as synthesis.
const PS_QUOTED_PROGRAM_RE = /(?:^|\s)[&.]\s*"[^"]*\$[({\w][^"]*"/;

function commandHasPsSynthesis(cmd) {
    // security rationale: preserve double-quoted spans
    // that contain PowerShell expansion constructs (`$(`, `${`, `$<word>`).
    // PS double-quoted strings are NOT inert — `"$(...)"` interpolates
    // sub-expressions at runtime. Stripping such spans hides the
    // synthesis sigil inside, defeating the whole detection.
    // Single-quoted spans in PS ARE literal, so safe to strip.
    let stripped = String(cmd || "").replace(
        /(["'])((?:\\.|(?!\1).)*)\1/g,
        (m, q, body) => {
            if (q === '"' && /\$[({\w]/.test(body)) return m;
            return "";
        },
    );
    // security rationale: decode PS 7+ Unicode escapes BEFORE
    // the simple backtick-strip so `` g`u{0069}t `` becomes `git`.
    stripped = decodePsUnicodeEscapes(stripped);
    // security rationale: strip PS backtick escapes BEFORE running
    // PS_SYNTHESIS_SIGIL_RE.
    // security rationale: drop the case-insensitive `i` flag —
    // PS escape sequences are case-sensitive lowercase-only.
    stripped = stripped.replace(/`([^nrtbafve0\\'"])/g, "$1");
    if (PS_SYNTHESIS_SIGIL_RE.test(stripped)) return true;
    // security rationale: also catch "& "$var-expansion"" or
    // ". "$var-expansion"" — synthesized program token via preserved
    // double-quoted interpolation.
    if (PS_QUOTED_PROGRAM_RE.test(String(cmd || ""))) return true;
    return false;
}

// security rationale: dual normalization for substring scan.
// Backslash has two valid meanings:
//   (a) Windows path separator: `C:\path\to\git.exe` — must be
//       SPLIT on `\` so `git.exe` becomes a standalone word for the
//       \bgit\b detection to fire.
//   (b) bash escape char: `g\it` evaluates to `git` — must be
//       STRIPPED so the underlying program name is reconstructed.
// We can't pick one; produce both forms and scan both.
//
// security rationale: BEFORE the whitespace step, pre-collapse
// (a) cmd.exe caret escapes (`g^it` → `git`), (b) PS / bash line
// continuations (so `cl<LF>one` FUSES into `clone` instead of
// splitting into two words), and (c) bash ANSI-C `$'\xHH'` quoting
// decoding (so `$'\x67it'` becomes `git` literally).
function normalizeForSubstringScan(command) {
    let raw = String(command || "");
    // ANSI-C decode first — operates on the raw bytes before any other
    // transformation so `$'\x67\x69\x74'` becomes `git`.
    raw = decodeAnsiCQuoting(raw);
    // security rationale: also decode PS 7+ Unicode escapes
    // (`` `u{HHHH} ``). Bash already covered via decodeAnsiCQuoting;
    // PS needs its own decoder.
    raw = decodePsUnicodeEscapes(raw);
    // cmd.exe caret escape: `^X` → `X` (the caret is removed; the next
    // char is left literal). Run before the lowercase + quote-strip.
    raw = raw.replace(/\^(.)/g, "$1");
    // Line-continuation FUSE: PS backtick + newline, bash backslash +
    // newline. Both should join the surrounding chars (NOT introduce
    // whitespace), so that `cl<LF>one` becomes `clone`. Run BEFORE
    // the `\r\n\t` → space step.
    raw = raw.replace(/`\s*\r?\n/g, "").replace(/\\\s*\r?\n/g, "");
    const lower = raw.toLowerCase();
    const stripQuotesAndCollapse = (s) => s
        .replace(/["'`]/g, "")
        .replace(/[\r\n\t]+/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    // Form A: `\` → space (Windows path semantics).
    const formA = stripQuotesAndCollapse(lower.replace(/\\/g, " "));
    // Form B: `\` stripped (bash escape semantics).
    const formB = stripQuotesAndCollapse(lower.replace(/\\/g, ""));
    return [formA, formB];
}

// Layer-1 detection: does the normalized command contain a clone
// invocation in any shape? Returns { kind: "git" | "gh" } when a
// clone is suspected, or null. False positives are acceptable in
// audit mode — the agent doesn't legitimately need to clone there.
function commandLooksLikeClone(command) {
    const forms = normalizeForSubstringScan(command);
    for (const norm of forms) {
        if (/\bgit(?:\.exe|\.cmd|\.com|\.ps1)?\b/.test(norm) && /\bclone\b/.test(norm)) {
            return { kind: "git" };
        }
        if (/\bgh(?:\.exe|\.cmd|\.ps1)?\b/.test(norm) && /\brepo\b/.test(norm) && /\bclone\b/.test(norm)) {
            return { kind: "gh" };
        }
    }
    // security rationale: PowerShell programmatic name
    // synthesis can construct `git` at runtime so the substring scan
    // never sees it. If the command contains `clone` AND any PS
    // synthesis sigil, treat as a likely git clone. False positives
    // in audit mode are acceptable.
    for (const norm of forms) {
        if (/\bclone\b/.test(norm) && commandHasPsSynthesis(command)) {
            return { kind: "git" };
        }
    }
    return null;
}

// Layer-1 detection for package-manager installs. Returns ALL matched
// rules across all sub-commands (one per sub-command), or empty array.
//
// security rationale: first-rule-wins was bypassable.
// `npm install --ignore-scripts && pnpm dlx evilpkg` matched the npm
// rule first, satisfied --ignore-scripts, and the chained pnpm dlx
// (a NEVER_MATCH ecosystem) was never checked. New design: enumerate
// every sub-command, find ALL matching rules, validate each. Deny if
// ANY hit fails.
//
// security rationale PS-synthesis fallback retained, now per-sub-command.
function detectAllInstallHits(command) {
    const hits = [];
    for (const sub of splitSubCommands(command)) {
        const subForms = normalizeForSubstringScan(sub);
        for (const rule of INSTALL_RULES) {
            if (subForms.some((n) => rule.normalizedPattern.test(n))) {
                hits.push({ rule, sub, normalized: subForms[0] });
                break;
            }
        }
        // PS-synthesis fallback per sub-command.
        if (subForms.some((n) => INSTALL_VERB_RE.test(n)) && commandHasPsSynthesis(sub)) {
            hits.push({ rule: SYNTHESIZED_INSTALL_RULE, sub, normalized: subForms[0] });
        }
    }
    // security rationale: whole-command fallback.
    // splitSubCommands breaks `(`/`)` apart so a synthesized invocation
    // like `& ([char]110+[char]112+[char]109) install` becomes two
    // sub-commands neither of which has BOTH a verb AND a sigil.
    // Re-check the full command. security rationale: the previous `hits.length === 0`
    // guard let `npm ci --ignore-scripts && & ([char]…) install` slip
    // through (legitimate npm hit short-circuited the fallback). Always
    // run the whole-command check; SYNTHESIZED_INSTALL_RULE is neverSafe
    // so it's correct to deny if a sigil+verb pair exists anywhere.
    const wholeForms = normalizeForSubstringScan(command);
    if (wholeForms.some((n) => INSTALL_VERB_RE.test(n)) && commandHasPsSynthesis(command)) {
        hits.push({ rule: SYNTHESIZED_INSTALL_RULE, sub: command, normalized: wholeForms[0] });
    }
    return hits;
}

function pathIsUnder(parent, child) {
    const p = nodePath.resolve(parent).toLowerCase();
    const c = nodePath.resolve(child).toLowerCase();
    if (p === c) return true;
    const rel = nodePath.relative(p, c);
    return !!rel && !rel.startsWith("..") && !nodePath.isAbsolute(rel);
}

// security review security (3/3 reviewer consensus on critical regex bypass):
// Replace the previous narrow regex `/\bgit(?:\s+-c\s+\S+)*\s+clone\b/i`
// with an argv-aware tokenizer. The old regex only handled `-c key=val`
// global flags. Any other shape bypassed:
//   - git.exe clone …
//   - git --no-pager clone …
//   - git --git-dir=x clone …
//   - git --bare clone …
//   - C:\path\to\git.exe clone …
//   - gh repo clone … (entirely separate program, never matched)
// In non-clone modes (audit_source / audit_source_council / verify_release)
// any of these would slip past the earlier policy mode-based deny, drop attacker
// source onto disk, and trip Defender — defeating the headline fix this
// round shipped.

// Strip surrounding quotes, take basename across both / and \, lowercase,
// and drop a trailing `.exe`/`.cmd`/`.bat`/`.com` so `C:\Program Files\Git\bin\git.exe`
// normalizes to `git`.
//
// security rationale: strip ALL quote characters (not just outer)
// to defeat PowerShell quote-fragment concatenation `g"it"` (which PS
// treats as the single string `git`).
function normalizeProgramToken(rawTok) {
    if (!rawTok) return "";
    let t = String(rawTok).trim();
    // Strip ALL quote chars — PS allows `g"it"` to evaluate to `git`
    // and `git"".exe` to evaluate to `git.exe`. Defensive: strip them
    // all so the basename/extension logic sees the underlying program.
    t = t.replace(/["']/g, "");
    const lastSep = Math.max(t.lastIndexOf("/"), t.lastIndexOf("\\"));
    if (lastSep >= 0) t = t.substring(lastSep + 1);
    t = t.toLowerCase();
    t = t.replace(/\.(?:exe|cmd|bat|com|ps1)$/i, "");
    return t;
}

// Split a command line into sub-commands by shell separators (`;`, `&&`,
// `||`, `|`, single `&` for backgrounding, `\r`, `\n`) and unwrap
// command-substitution / process-substitution forms (`$( … )`, `>(…)`,
// `<(…)`, backticks) so their inner content is exposed as a separate
// sub-command. We don't need a perfect shell parser — just enough that
// an attacker can't hide `git clone` inside a chained or substituted
// invocation.
//
// security rationale:
//   - Add single `&` (background operator) as a separator (with
//     lookbehind/lookahead to disambiguate from `&&`).
//   - Add `>(…)` / `<(…)` (bash process substitution) wrappers.
//   - Backticks have TWO valid shell meanings:
//       (a) bash `` `cmd` `` — command substitution (inner content runs
//           as a separate sub-command); replace with "; " separator so
//           the inner content is exposed for detection.
//       (b) PS `\`` — escape char (so `cl\`one` evaluates to `clone`);
//           stripping backticks entirely un-escapes the literal.
//     We process BOTH interpretations and concatenate the sub-commands
//     so detection runs against either. Either detection is enough to
//     trigger the deny path.
function splitSubCommands(cmd) {
    let raw = String(cmd || "");
    // security rationale: decode PS 7+ Unicode escapes BEFORE
    // any backtick handling. Otherwise the backtick that's part of
    // `` `u{HHHH} `` gets treated as a command-substitution wrapper
    // (form A) or stripped (form B), separating the `u{HHHH}` from
    // its decoder. Decoding here ensures `n`u{0070}m` becomes `npm`
    // before the form-A/form-B split.
    raw = decodePsUnicodeEscapes(raw);
    // Form A: backticks as bash command-substitution wrappers.
    const formA = raw.replace(/`/g, "; ");
    // Form B: backticks stripped (PS escape unwrap).
    const subs = unwrapAndSplit(formA);
    if (raw.indexOf("`") !== -1) {
        const formB = raw.replace(/`/g, "");
        for (const s of unwrapAndSplit(formB)) subs.push(s);
    }
    return subs;
}

function unwrapAndSplit(s) {
    // Replace command/process substitution wrappers with separators so
    // their inner content becomes its own sub-command for inspection.
    s = s.replace(/[<>]?\$?\(/g, "; ").replace(/\)/g, "; ");
    return s.split(/(?:&&|\|\||;|\|(?!\|)|(?<!&)&(?!&)|\r|\n)+/g)
        .map((p) => p.trim())
        .filter(Boolean);
}

// Quote-aware tokenizer. Splits on whitespace but keeps double- and
// single-quoted spans together so paths like `"C:\Program Files\Git\bin\git.exe"`
// stay one token. Backslash-escapes are not interpreted (Powershell
// doesn't treat backslash as an escape char inside double-quoted strings).
function tokenizeShell(s) {
    const out = [];
    let cur = "";
    let quote = null; // null | '"' | "'"
    for (let i = 0; i < s.length; i++) {
        const ch = s[i];
        if (quote) {
            cur += ch;
            if (ch === quote) {
                quote = null;
            }
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            cur += ch;
            continue;
        }
        if (/\s/.test(ch)) {
            if (cur) { out.push(cur); cur = ""; }
            continue;
        }
        cur += ch;
    }
    if (cur) out.push(cur);
    return out;
}

// security rationale: leading shell-passthrough operators and
// env-var prefixes that put the actual program one (or more) tokens
// later. Examples:
//   `& "git.exe" clone …`        — PS call operator
//   `. git.exe clone …`          — PS dot-source
//   `sudo git clone …`           — POSIX privilege escalation
//   `nohup git clone …`          — POSIX detach
//   `env git clone …`            — POSIX env-clearing
//   `time git clone …`           — POSIX timing
//   `command git clone …`        — POSIX shell-builtin bypass
//   `exec git clone …`           — POSIX exec replacement
//   `GIT_DIR=/x git clone …`     — POSIX env-var prefix
//
// All of these were live-confirmed bypasses of security review security detection.
const SHELL_PASSTHROUGH_OPERATORS = new Set([
    "&", ".", "\\",
    "sudo", "nice", "time", "env", "setsid", "nohup",
    "command", "exec",
]);
const ENV_PREFIX_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

function stripLeadingOperators(tokens) {
    let i = 0;
    while (i < tokens.length) {
        const t = tokens[i];
        if (SHELL_PASSTHROUGH_OPERATORS.has(t.toLowerCase())) { i++; continue; }
        if (ENV_PREFIX_RE.test(t)) { i++; continue; }
        break;
    }
    return tokens.slice(i);
}

// security rationale: enumeration of git/gh global flags that
// take a separate-token value (no `=`). Without this, `git --git-dir
// /tmp/x clone …` was tokenized as
//   ["git", "--git-dir", "/tmp/x", "clone", …]
// the loop saw `--git-dir` (skip), then `/tmp/x` (no leading `-`,
// break), then tested `/tmp/x === "clone"` → false → returned null →
// the entire clone gate was bypassed. This set gives us the flag/value
// pairs to skip atomically.
const VALUE_TAKING_FLAGS = new Set([
    // git
    "-c", "-C",
    "--git-dir", "--work-tree", "--exec-path",
    "--namespace", "--super-prefix", "--config-env",
    "--list-cmds", "--shallow-file",
    // gh — no global value-taking flags we care about, but the set is
    // shared with gh so add gh-specific value flags here if needed.
]);

// Detect whether a sub-command is performing a git/gh clone. Returns
// `{ program, tail }` (tail = tokens after the `clone` subcommand) when
// it is, or null otherwise.
//
// Recognizes:
//   - `git[.exe] [global-flags] clone …`
//   - `gh[.exe] [global-flags] repo [global-flags] clone …`
//   - All of the above prefixed by leading shell-passthrough operators
//     (`& "git.exe" clone`, `sudo git clone`, `GIT_DIR=/x git clone`).
//
// `git`/`gh` may be a full path (basename is what matters), and may be
// quoted (e.g. `"C:\Program Files\Git\bin\git.exe"`) or use PS
// quote-fragment concatenation (`g"it".exe`).
function detectsClone(sub) {
    let tokens = tokenizeShell(String(sub || "").trim());
    tokens = stripLeadingOperators(tokens);
    if (tokens.length < 2) return null;

    const program = normalizeProgramToken(tokens[0]);
    if (program !== "git" && program !== "gh") return null;

    let i = 1;
    // Skip global flags. For value-taking flags (no `=`), also skip the
    // next token (the value).
    while (i < tokens.length) {
        const t = tokens[i];
        if (!t.startsWith("-")) break;
        if (VALUE_TAKING_FLAGS.has(t) && !t.includes("=") && i + 1 < tokens.length) {
            i += 2;
            continue;
        }
        i += 1;
    }

    if (i >= tokens.length) return null;
    const sub1 = tokens[i].toLowerCase();

    if (program === "git" && sub1 === "clone") {
        return { program: "git", tail: tokens.slice(i + 1) };
    }

    // gh repo clone <repo> [<dir>] — and gh itself may take global flags
    // before `repo`, then more flags before `clone`.
    if (program === "gh" && sub1 === "repo") {
        let j = i + 1;
        while (j < tokens.length && tokens[j].startsWith("-")) j++;
        if (j < tokens.length && tokens[j].toLowerCase() === "clone") {
            return { program: "gh", tail: tokens.slice(j + 1) };
        }
    }

    return null;
}

// security rationale: return ALL clone hits across every
// sub-command, not just the first. Old behavior (first-clone-wins) let
// `<good clone> && git clone <bad-dest>` validate the first clone and
// return allow, leaving the second clone (and any subsequent
// install/exec rules) unchecked.
function detectAllCloneHits(command) {
    const hits = [];
    for (const sub of splitSubCommands(command)) {
        const hit = detectsClone(sub);
        if (hit) {
            // security rationale: carry the originating
            // sub-command so validateCloneHit can check security and
            // URL-binding against the actual clone invocation, not
            // the full chained command.
            hit.sub = sub;
            hits.push(hit);
        }
    }
    return hits;
}

// security rationale: clone-subcommand flags that
// take separate-token values. The destination is the LAST positional
// (non-flag) token. Without this set we'd treat a flag's value (which
// has no leading `-`) as the destination — letting an attacker spoof
// it with `git clone <bad-dest> --reference <legit-path>`.
const CLONE_VALUE_TAKING_FLAGS = new Set([
    "--reference", "--reference-if-able", "--separate-git-dir",
    "--template", "--origin", "-o", "--branch", "-b", "--depth",
    "--jobs", "-j", "--bundle-uri", "--shallow-since",
    "--shallow-exclude", "--server-option", "--config", "--upload-pack",
    "-u", "--filter", "--recurse-submodules",
]);

// Extract positional (non-flag) tokens from a clone tail, correctly
// skipping flag+value pairs for value-taking clone-subcommand flags.
// Returns the array of positionals; caller picks tail[length-1] as
// the destination (the URL is positionals[0]).
function extractClonePositionals(tail) {
    const positionals = [];
    let i = 0;
    while (i < tail.length) {
        const t = tail[i];
        if (t.startsWith("-")) {
            if (CLONE_VALUE_TAKING_FLAGS.has(t) && !t.includes("=") && i + 1 < tail.length) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        positionals.push(t);
        i += 1;
    }
    return positionals;
}

// security rationale: build-mode raw `git clone`
// must include the safe-clone security flags. Otherwise an ordinary
// clone (default checkout + fetch behavior) writes potentially-malicious
// payload bytes to disk before our wrapper invariants apply. The flags
// enforced here mirror what zerotrust_safe_clone applies internally.
//
// REQUIRED: -c protocol.file.allow=never  (disable file:// transport)
//           --no-checkout                  (no working tree, hash-only)
//           --filter=blob:none             (lazy blob fetch — defers code)
//           --no-recurse-submodules        (no sub-payload pull)
//           -c core.symlinks=false         (defang symlink-as-payload)
const REQUIRED_SECURITY_TOKENS = [
    "protocol.file.allow=never",
    "core.symlinks=false",
    "--no-checkout",
    "--filter=blob:none",
    "--no-recurse-submodules",
];

function hasRequiredCloneSecurity(rawCommand) {
    const lower = String(rawCommand || "").toLowerCase();
    for (const token of REQUIRED_SECURITY_TOKENS) {
        if (!lower.includes(token.toLowerCase())) return false;
    }
    return true;
}

// Validate a single clone hit against the active audit. Returns
// { decision: "deny", reason } on failure, or null if the hit is valid
// for this mode.
function validateCloneHit(audit, hit, _rawCommandUnusedNow) {
    if (hit.program === "gh") {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: \`gh repo clone\` is not allowed — it bypasses the safe-clone security flags (protocol.file.allow=never, --no-checkout, --filter=blob:none). Use zerotrust_safe_clone (preferred) or raw \`git clone\` with the security flags applied.`,
        };
    }
    if (!SHARED_modeNeedsClone(audit.mode)) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: \`git clone\` is not allowed in audit mode '${audit.mode}' (only build modes use on-disk clones). Use the API-direct flow (zerotrust_safe_list_tree + zerotrust_safe_fetch_file) instead, OR re-invoke zerotrust_sourcecheck with audit_and_safe_build* / audit_and_full_build* if you need source on disk for a build.`,
        };
    }
    const tail = hit.tail || [];
    // security rationale: use flag-aware positional extractor.
    const positionals = extractClonePositionals(tail);
    if (positionals.length < 2) {
        return {
            decision: "deny",
            reason:
                "zerotrust-sourcecheck: `git clone` without an explicit destination would clone into the current working directory. Specify the destination path under build_root.",
        };
    }
    // security rationale: URL-binding check. The first
    // positional is the clone source URL — must match the audit's
    // pinned owner/repo. Otherwise an attacker could clone a different
    // repo into the approved clone path.
    const url = positionals[0].replace(/^["']|["']$/g, "");
    const parsed = parseGithubUrl(url);
    if (!parsed.ok) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: clone URL ${url} could not be parsed as a GitHub URL (rejected: ${parsed.error}).`,
        };
    }
    if (audit.owner && audit.repo) {
        if (parsed.parsed.owner.toLowerCase() !== audit.owner.toLowerCase() ||
            parsed.parsed.repo.toLowerCase() !== audit.repo.toLowerCase()) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: clone URL owner/repo (${parsed.parsed.owner}/${parsed.parsed.repo}) does not match the active audit's pinned target (${audit.owner}/${audit.repo}).`,
            };
        }
    }
    const dest = positionals[positionals.length - 1].replace(/^["']|["']$/g, "");
    let absDest;
    try {
        absDest = nodePath.isAbsolute(dest) ? dest: nodePath.resolve(process.cwd(), dest);
    } catch {
        return {
            decision: "deny",
            reason: "zerotrust-sourcecheck: clone destination could not be resolved to an absolute path.",
        };
    }
    if (!pathIsUnder(audit.buildPath, absDest)) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: clone destination ${absDest} is not under the audit build_root ${audit.buildPath}.`,
        };
    }
    if (!pathIsUnder(audit.expectedClonePath, absDest) && absDest.toLowerCase() !== audit.expectedClonePath.toLowerCase()) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: clone destination ${absDest} doesn't match the planned clone path ${audit.expectedClonePath}.`,
        };
    }
    // security rationale: require the
    // safe-clone security flags. security fix: check against THIS
    // sub-command's argv tokens (preFlags + tail), not the full chained
    // command — `git clone <url> <dest>; echo 'protocol.file.allow=...'`
    // would otherwise satisfy the substring check via the echo argument.
    const subTokens = tokenizeShell(String(hit.sub || "").trim()).map((t) =>
        t.replace(/["']/g, "").toLowerCase()
    );
    // Required tokens that must appear in subTokens for the actual clone
    // invocation (not anywhere else in the wider command):
    //   protocol.file.allow=never  (paired with -c)
    //   core.symlinks=false        (paired with -c)
    //   --no-checkout
    //   --filter=blob:none
    //   --no-recurse-submodules
    const REQUIRED_FLAG_TOKENS = [
        "protocol.file.allow=never",
        "core.symlinks=false",
        "--no-checkout",
        "--filter=blob:none",
        "--no-recurse-submodules",
    ];
    const missing = REQUIRED_FLAG_TOKENS.filter((t) => !subTokens.includes(t));
    if (missing.length > 0) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: raw \`git clone\` is missing required security flag(s) in the actual clone invocation: ${missing.join(", ")}. Use zerotrust_safe_clone (preferred — applies all flags), or include all of: -c protocol.file.allow=never -c core.symlinks=false --no-checkout --filter=blob:none --no-recurse-submodules.`,
        };
    }
    return null;
}

/**
 * Inspect a tool invocation against the active audit (if any).
 * Returns { decision: "allow" | "deny", reason?: string } — undefined
 * decision means "no opinion" (the SDK will fall through to default permissions).
 *
 * security rationale: TWO-LAYER defense.
 *   Layer 1 — substring scan (commandLooksLikeClone / detectInstallInCommand).
 *     High recall, broad coverage. Used to refuse audit-mode clones
 *     and audit-mode installs regardless of how cleverly the attacker
 *     spelled the command.
 *   Layer 2 — tokenizer (detectAllCloneHits / validateCloneHit).
 *     Used in build modes for destination-path validation. If layer-2
 *     misses (because of an obscure bypass shape), the agent's clone
 *     proceeds with whatever path it specified — which in build modes
 *     the user has already authorized as the planned clone path.
 */
export function inspectToolCall({ sessionId, toolName, toolArgs }) {
    const audit = getActiveAudit(sessionId);
    if (!audit) return { decision: undefined };
    if (!SHELL_TOOLS.has(toolName)) return { decision: undefined };

    const command = String(toolArgs?.command || "").trim();
    if (!command) return { decision: undefined };

    // ---- Layer 1: substring-based clone denial ----
    // gh repo clone always denied (bypasses safe-clone security flags).
    // git clone in non-clone modes always denied (no on-disk clone needed
    // for API-direct audit modes).
    const looksLikeClone = commandLooksLikeClone(command);
    if (looksLikeClone) {
        if (looksLikeClone.kind === "gh") {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: \`gh repo clone\` is not allowed — it bypasses the safe-clone security flags. Use zerotrust_safe_clone (preferred) or raw \`git clone\` with the security flags applied.`,
            };
        }
        if (!SHARED_modeNeedsClone(audit.mode)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: \`git clone\` is not allowed in audit mode '${audit.mode}' (only build modes use on-disk clones). Use the API-direct flow (zerotrust_safe_list_tree + zerotrust_safe_fetch_file) instead, OR re-invoke zerotrust_sourcecheck with audit_and_safe_build* / audit_and_full_build* if you need source on disk for a build.`,
            };
        }
        // Audit needs a clone — fall through to layer-2 path validation.
    }

    // ---- Layer 2: tokenizer-based clone destination validation (build modes only) ----
    let cloneAllowed = false;
    if (looksLikeClone && SHARED_modeNeedsClone(audit.mode)) {
        const cloneHits = detectAllCloneHits(command);
        for (const hit of cloneHits) {
            const denial = validateCloneHit(audit, hit, command);
            if (denial) return denial;
            cloneAllowed = true;
        }
        // If layer-1 said "looks like clone" but layer-2 found no
        // structured hits (because of an obscure shell-syntax form),
        // we DENY in build mode too — the agent should be using
        // zerotrust_safe_clone, not raw shell trickery.
        if (!cloneAllowed) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: clone-like command detected but the destination/structure could not be validated. Use the zerotrust_safe_clone wrapper, which applies the security flags and validates the destination path.`,
            };
        }
    }

    // ---- Layer 1: substring-based install denial ----
    // security rationale: validate ALL install hits, not just
    // the first. `npm install --ignore-scripts && pnpm dlx evil`
    // bypassed first-rule-wins because the npm rule was satisfied
    // and the chained pnpm dlx was never re-checked.
    const installHits = detectAllInstallHits(command);
    for (const hit of installHits) {
        // Outside any build mode → no installs at all.
        if (!BUILD_MODES.has(audit.mode)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: package-manager install detected (${hit.rule.ecosystem}) but the audit mode '${audit.mode}' does not include a build step. Re-run with mode='audit_and_safe_build' or 'audit_and_full_build' to permit installation.`,
            };
        }
        // Historical unregistered-hook behavior: safe-build (not full-build)
        // must have the safe flag in THIS specific sub-command. This branch is
        // retained as an executable specification only; the current safe/full
        // wrapper path always supplies the same install safety flags.
        if (!FULL_BUILD_MODES.has(audit.mode)) {
            if (!hit.rule.safeChecker(hit.sub)) {
                return {
                    decision: "deny",
                    reason: `zerotrust-sourcecheck: ${hit.rule.ecosystem} install without ${hit.rule.flagHint}. The audit mode '${audit.mode}' requires this safe-flag in the same sub-command. Use zerotrust_safe_install; current safe/full modes use the same installer and keep install lifecycle scripts suppressed.`,
                };
            }
        }
    }

    // security rationale: in audit-only modes, deny ANY
    // command containing PS programmatic name-synthesis sigils. There
    // is no legitimate audit-time use of [char] arithmetic / -join /
    // -f format / & $var indirection / iex — these are exclusively
    // attacker-evasion patterns. False positives in audit mode are
    // acceptable per the security design philosophy.
    if (!BUILD_MODES.has(audit.mode) && commandHasPsSynthesis(command)) {
        return {
            decision: "deny",
            reason: `zerotrust-sourcecheck: command uses PowerShell programmatic name-synthesis ([char] arithmetic, -join, -f format, & \$var indirection, Invoke-Expression, etc.) which has no legitimate use during an audit and bypasses program-name detection. Refused.`,
        };
    }

    // ---- 2.5. GUI-launch and disk-write enforcement (any audit mode) ----
    // Deny commands that open files with their default handler (the
    // Notepad-pop-up bug) or download bytes to disk (sub-agents were
    // saving source files to scratch paths instead of using the
    // API-direct safe_fetch_file wrapper).
    for (const p of GUI_OPEN_PATTERNS) {
        if (p.re.test(command)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: \`${p.name}\` refused during audit mode '${audit.mode}'. Default-handler file openers and GUI editor launchers can produce surprising side effects (Notepad pop-ups, IDE windows) and are not needed during an audit. Use the read tools (view/grep/glob or zerotrust_safe_fetch_file) instead.`,
            };
        }
    }
    for (const p of DISK_DOWNLOAD_PATTERNS) {
        if (p.re.test(command)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: \`${p.name}\` refused during audit mode '${audit.mode}' — disk-writing downloads violate the API-direct contract and leave scratch source files behind. Use zerotrust_safe_fetch_file for repo content or web_fetch for external metadata.`,
            };
        }
    }

    // ---- 3. Execution from inside build_root ----
    for (const re of EXECUTION_PATTERNS) {
        if (re.test(command)) {
            const paths = extractPathTokens(command);
            for (const p of paths) {
                if (pathIsUnder(audit.buildPath, p)) {
                    return {
                        decision: "deny",
                        reason: `zerotrust-sourcecheck: refusing to execute file under audit build_root via a process-launch cmdlet. Audited binaries are quarantined and must not be executed by the audit itself.`,
                    };
                }
            }
        }
    }

    // ---- 4. Direct execution of `.exe`/`.msi`/`.bat`/`.cmd`/`.ps1` paths
    //       that resolve under build_root ----
    const execExtRe = /(?:^|[\s&;|`])["']?([A-Za-z]:[\\\/][^\s"';|&`]*\.(?:exe|msi|bat|cmd|ps1|vbs|dll))["']?/gi;
    let m;
    while ((m = execExtRe.exec(command)) !== null) {
        const candidate = m[1];
        if (pathIsUnder(audit.buildPath, candidate)) {
            return {
                decision: "deny",
                reason: `zerotrust-sourcecheck: refusing to invoke ${candidate} — executables under build_root must not be run as part of the audit.`,
            };
        }
    }

    if (cloneAllowed) return { decision: "allow" };
    return { decision: undefined };
}

/**
 * Hook adapter: takes an SDK onPreToolUse `input` + `invocation` and
 * returns the SDK's expected output shape.
 */
export function preToolUseHook(input, invocation) {
    const result = inspectToolCall({
        sessionId: invocation?.sessionId,
        toolName: input?.toolName,
        toolArgs: input?.toolArgs,
    });
    if (result.decision === undefined) return undefined;
    if (result.decision === "deny") {
        return {
            permissionDecision: "deny",
            permissionDecisionReason: result.reason,
        };
    }
    if (result.decision === "allow") {
        // We deliberately don't override allow-decisions with permissionDecision:"allow"
        // because that would bypass other extensions' deny checks. Returning
        // undefined lets the default permission logic proceed.
        return undefined;
    }
    return undefined;
}

// Exposed for tests.
export const __internals = {
    activeAudits,
    AUDIT_TTL_MS_BY_MODE,
    AUDIT_TTL_MS_DEFAULT,
    ttlForMode,
    recentlyExpired,
    BUILD_MODES,
    FULL_BUILD_MODES,
    INSTALL_RULES,
    EXECUTION_PATTERNS,
    extractPathTokens,
    pathIsUnder,
    recordResolvedClonePath,
    getAcquisitionCoverageState,
    recordAcquisitionCoverageState,
    mutateAcquisitionCoverageState,
    getReleaseAssetCoverageState,
    mutateReleaseAssetCoverageState,
    ensureAnalysisStageState,
    ensureAnalysisIndexState,
    ensureAssuranceState,
    analysisSourceKindForMode,
};
