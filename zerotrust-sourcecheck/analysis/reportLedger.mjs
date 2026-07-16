import { createHash } from "node:crypto";
import nodePath from "node:path";

import {
    ANALYSIS_SCHEMA_REVISION,
    CONFIDENCE_LEVELS,
    COVERAGE_SCOPES,
    FINDING_STATES,
    GRAPH_EDGE_KINDS,
    GRAPH_NODE_KINDS,
    MALICIOUS_PROJECT_FIT_LEVELS,
    SEVERITIES,
    validateAuditId,
} from "./schemas.mjs";
import { FACT_KINDS } from "./extractFacts.mjs";

// Baseline council artifacts are deterministic projections of trusted structured
// state. Compatibility non-council callers remain supported through a separate
// compatibility-report/trusted:false path.
export const FINDINGS_ARTIFACT_SCHEMA_REVISION = 1;

export const REPORT_LEDGER_LIMITS = Object.freeze({
    executiveSummaryBytes: 8 * 1024,
    recommendationBytes: 4 * 1024,
    operatorContextBytes: 16 * 1024,
    operatorDecisions: 512,
    operatorRationaleBytes: 240,
    findingsBytes: 4 * 1024 * 1024,
});

const HASH_RE = /^[a-f0-9]{64}$/u;
const VERDICTS = Object.freeze([
    "critical",
    "high",
    "medium",
    "low",
    "no red flags found",
    "incomplete",
    "reconnaissance only",
]);
const FORBIDDEN_ARTIFACT_KEYS = new Set([
    "sourceText",
    "source_text",
    "snippet",
    "excerptText",
    "excerpt_text",
    "quotedEvidence",
    "quoted_evidence",
    "markdown",
    "markdownBody",
    "markdown_body",
    "reportBody",
    "report_body",
    "prompt",
    "modelOutput",
    "model_output",
    "title",
    "summary",
    "rationale",
    "label",
    "name",
    "message",
    "error",
    "warnings",
    "behaviorSignature",
    "signature",
    "strongestBenignHypothesis",
    "coveragePerformed",
    "coverageSkipped",
]);
const OPERATOR_ACTIONS = Object.freeze([
    "defanged",
    "kept-as-is",
    "delete-project",
    "investigate",
    "no-action",
]);
const OPERATOR_RATIONALE_CATEGORIES = Object.freeze([
    "remediation-applied",
    "accepted-risk",
    "required-functionality",
    "false-positive-suspected",
    "deferred-review",
    "project-deleted",
    "alternate-path-remains",
    "graph-incomplete",
    "other",
]);
const CHAIN_PATTERNS = Object.freeze([
    "install-fetch-decode-execute",
    "credential-read-transform-send",
    "startup-persistence",
    "ai-instruction-tool-effect",
    "ci-trigger-secret-external-sink",
    "behavior-chain",
]);
const CHAIN_STATUSES = Object.freeze(["complete", "unresolved", "contested"]);
const BASELINE_ALLOWED_STRING_KEYS = new Set([
    "action",
    "adjudicatorId",
    "artifactType",
    "assetId",
    "auditId",
    "behaviorIntentHash",
    "blobSha",
    "cacheFile",
    "canonicalFindingId",
    "canonicalId",
    "category",
    "classification",
    "code",
    "confidence",
    "conclusion",
    "coverageScope",
    "currentStage",
    "decisionId",
    "decision",
    "decisionType",
    "digest",
    "documentId",
    "excerptHash",
    "final",
    "finalizationDigest",
    "findingId",
    "flow",
    "fromKind",
    "graphCoverage",
    "id",
    "input",
    "inputFingerprint",
    "indexFingerprint",
    "intentHash",
    "kind",
    "level",
    "linkKind",
    "localSlug",
    "localTimestamp",
    "locationHash",
    "maliciousProjectFit",
    "mode",
    "minSeverity",
    "namespace",
    "namespaceKey",
    "origin",
    "outcome",
    "owner",
    "path",
    "pattern",
    "planId",
    "pluginId",
    "pluginVersion",
    "producer",
    "rationaleCategory",
    "rationaleCode",
    "releaseId",
    "repo",
    "resolvedSha",
    "renderManifestSha256",
    "rootTreeSha",
    "roleId",
    "scope",
    "severity",
    "sha",
    "sha256",
    "sourceCommitSha",
    "sourceKind",
    "sourceKey",
    "sourcePath",
    "state",
    "stateClass",
    "status",
    "strongestObservedSeverity",
    "strategy",
    "tagName",
    "tagObjectSha",
    "tagRefSha",
    "text",
    "toKind",
    "type",
    "validatorId",
    "value",
    "version",
    "contentSha256",
    "deadOrUnreachableCode",
    "docsOrTestsOnlyContext",
    "activationGating",
    "sanitizationOrNeutralization",
    "brokenGraphEdges",
    "legitimateProjectFit",
]);
const BASELINE_ALLOWED_STRING_ARRAY_KEYS = new Set([
    "alternateChainIds",
    "chainIds",
    "completeChainIds",
    "criteriaCodes",
    "edgeIds",
    "effectKinds",
    "eligibleVerdicts",
    "failedAssetIds",
    "failedRoleIds",
    "findingIds",
    "guidanceCodes",
    "history",
    "independentPaths",
    "nodeIds",
    "notFetched",
    "observedConfidences",
    "observedProjectFits",
    "observedSeverities",
    "observedStates",
    "oversizedAssetIds",
    "paths",
    "producers",
    "rationaleCodes",
    "requiredFindingIds",
    "riskCodes",
    "sharedChainIds",
    "skippedAssetIds",
    "sourceFindingIds",
    "successfulRoleIds",
    "unresolvedReasons",
    "validatedChainIds",
    "validationChainIds",
    "validationIds",
    "byteMismatchAssetIds",
]);

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

export function canonicalJson(value) {
    if (value === undefined) throw new TypeError("canonical JSON cannot contain undefined");
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

export function sha256Canonical(value) {
    return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function uniqueCanonical(values) {
    const entries = new Map();
    for (const value of values) entries.set(canonicalJson(value), value);
    return [...entries.values()].sort((left, right) =>
        canonicalJson(left).localeCompare(canonicalJson(right)));
}

function sanitizeEvidence(value) {
    return {
        path: value.path,
        startLine: value.startLine,
        endLine: value.endLine,
        blobSha: value.blobSha,
        excerptHash: value.excerptHash,
        producer: value.producer,
        coverageScope: value.coverageScope,
    };
}

function sanitizeSourceIdentity(value) {
    if (!value) return null;
    return {
        type: value.type,
        namespace: value.namespace,
        path: value.path,
        contentSha256: value.contentSha256,
        ...(value.blobSha ? { blobSha: value.blobSha }: {}),
    };
}

function sanitizeValidationDecision(value) {
    return {
        findingId: value.findingId,
        validatorId: value.validatorId,
        decisionType: value.decisionType,
        conclusion: value.conclusion,
        chainIds: [...(value.chainIds || [])],
        nodeIds: [...(value.nodeIds || [])],
        edgeIds: [...(value.edgeIds || [])],
        evidence: (value.evidence || []).map(sanitizeEvidence),
        checks: Object.fromEntries(Object.entries(value.checks || {}).map(([key, entry]) => [
            key,
            entry,
        ])),
    };
}

function sanitizeAdjudication(value) {
    return {
        findingId: value.findingId,
        adjudicatorId: value.adjudicatorId,
        decision: value.decision,
        severity: value.severity,
        confidence: value.confidence,
        maliciousProjectFit: value.maliciousProjectFit,
        chainIds: [...(value.chainIds || [])],
        nodeIds: [...(value.nodeIds || [])],
        edgeIds: [...(value.edgeIds || [])],
        evidence: (value.evidence || []).map(sanitizeEvidence),
    };
}

function sanitizeChain(value) {
    if (!CHAIN_PATTERNS.includes(value.pattern)) {
        throw new Error(`unexpected behavior-chain pattern in report ledger: ${value.pattern}`);
    }
    if (!CHAIN_STATUSES.includes(value.status)) {
        throw new Error(`unexpected behavior-chain status in report ledger: ${value.status}`);
    }
    return {
        id: value.id,
        pattern: value.pattern,
        priority: value.priority,
        status: value.status,
        crossFile: value.crossFile === true,
        steps: (value.steps || []).map((step) => ({
            kind: step.kind,
            nodeIds: [...(step.nodeIds || [])],
        })),
        links: (value.links || []).map((link) => ({
            kind: link.kind,
            edgeIds: [...(link.edgeIds || [])],
        })),
        evidence: (value.evidence || []).map(sanitizeEvidence),
        paths: [...(value.paths || [])],
        effectKinds: [...(value.effectKinds || [])],
        unresolvedReasons: [...(value.unresolvedReasons || [])],
        validationIds: [...(value.validationIds || [])],
    };
}

function sanitizeIndexBlocker(value) {
    return {
        kind: value.kind,
        ...(value.path ? { path: value.path }: {}),
    };
}

function compactAnalysisIndex(value) {
    if (!value) return null;
    return {
        schemaVersion: value.schemaVersion,
        sourceKind: value.sourceKind,
        complete: value.complete === true,
        enumeration: {
            attempts: value.enumeration?.attempts || 0,
            complete: value.enumeration?.complete === true,
            trackedFiles: value.enumeration?.trackedFiles || 0,
            totalBytes: value.enumeration?.totalBytes || 0,
            byteCountSaturated: value.enumeration?.byteCountSaturated === true,
            trackingTruncated: value.enumeration?.trackingTruncated === true,
            directories: value.enumeration?.directories || 0,
            reparsePointsSkipped: value.enumeration?.reparsePointsSkipped || 0,
            otherEntriesSkipped: value.enumeration?.otherEntriesSkipped || 0,
        },
        reads: {
            attempts: value.reads?.attempts || 0,
            failures: value.reads?.failures || 0,
            pendingFiles: value.reads?.pendingFiles || 0,
            indexedTextFiles: value.reads?.indexedTextFiles || 0,
            classifiedBinaryFiles: value.reads?.classifiedBinaryFiles || 0,
            indexedTextBytes: value.reads?.indexedTextBytes || 0,
            classifiedBinaryBytes: value.reads?.classifiedBinaryBytes || 0,
            incompleteBytes: value.reads?.incompleteBytes || 0,
            incompleteFiles: value.reads?.incompleteFiles || 0,
            statusCounts: Object.fromEntries([
                "pending",
                "indexed-text",
                "classified-binary",
                "read-failed",
                "index-overflow",
                "incomplete",
            ].map((status) => [status, value.reads?.statusCounts?.[status] || 0])),
        },
        facts: {
            total: value.facts?.total || 0,
            perFileCap: value.facts?.perFileCap || 0,
            perAuditCap: value.facts?.perAuditCap || 0,
            perFileOverflowCount: value.facts?.perFileOverflowCount || 0,
            auditOverflow: value.facts?.auditOverflow === true,
            byKind: Object.fromEntries(FACT_KINDS.map((kind) => [
                kind,
                value.facts?.byKind?.[kind] || 0,
            ])),
        },
        invisibleUnicode: {
            matchedFiles: value.invisibleUnicode?.matchedFiles || 0,
            matchCount: value.invisibleUnicode?.matchCount || 0,
        },
        blockers: (value.blockers || []).map(sanitizeIndexBlocker),
        blockersTruncated: value.blockersTruncated === true,
        incompletePaths: (value.incompletePaths || []).map((entry) => ({
            path: entry.path,
            status: entry.status,
        })),
    };
}

function compactPlugins(value) {
    if (!value) return null;
    return {
        schemaVersion: value.schemaVersion,
        runCount: value.runCount,
        indexFingerprint: value.indexFingerprint,
        coverageComplete: value.coverageComplete === true,
        counts: {
            registered: value.counts?.registered || 0,
            supported: value.counts?.supported || 0,
            detected: value.counts?.detected || 0,
            completed: value.counts?.completed || 0,
            failed: value.counts?.failed || 0,
            truncated: value.counts?.truncated || 0,
        },
        facts: (value.facts || []).map((fact) => ({
            id: fact.id,
            kind: fact.kind,
            producer: fact.pluginId,
            pluginId: fact.pluginId,
            pluginVersion: fact.pluginVersion,
            path: fact.path,
            line: fact.line,
            endLine: fact.endLine,
            excerptHash: fact.excerptHash,
            ...(fact.sourceIdentity
                ? { sourceIdentity: sanitizeSourceIdentity(fact.sourceIdentity) }: {}),
        })),
        factCount: Number.isSafeInteger(value.factCount)
            ? value.factCount: (value.facts || []).length,
        factsTruncated: value.factsTruncated === true,
        plugins: (value.plugins || []).map((plugin) => ({
            id: plugin.pluginId,
            version: plugin.pluginVersion,
            supported: plugin.supported === true,
            detected: plugin.detected === true,
            completed: plugin.completed === true,
            failed: plugin.failed === true,
            truncated: plugin.truncated === true,
        })),
        blockers: (value.blockers || []).map((blocker) => ({
            pluginId: blocker.pluginId,
            kind: blocker.kind,
        })),
        blockersTruncated: value.blockersTruncated === true,
        behaviorGraph: value.behaviorGraph ? {
            auditId: value.behaviorGraph.auditId,
            nodeCount: value.behaviorGraph.nodeCount,
            edgeCount: value.behaviorGraph.edgeCount,
        }: null,
    };
}

function buildSourceIdentity(context) {
    if (context.localPath) {
        return {
            kind: "local",
            path: context.localPath,
            localSlug: context.localReportSlug,
            localTimestamp: context.localReportTimestamp,
        };
    }
    return {
        kind: "github",
        owner: context.canonicalOwner,
        repo: context.canonicalRepo,
        resolvedSha: context.resolvedSha,
        rootTreeSha: context.rootTreeSha || null,
        releaseIdentity: context.releaseIdentity ? {
            releaseId: context.releaseIdentity.releaseId,
            tagName: context.releaseIdentity.tagName,
            sourceCommitSha: context.releaseIdentity.sourceCommitSha,
            rootTreeSha: context.releaseIdentity.rootTreeSha || null,
            tagObjectSha: context.releaseIdentity.tagObjectSha || null,
            tagRefSha: context.releaseIdentity.tagRefSha || null,
        }: null,
    };
}

function normalizeCacheMetadata(binding) {
    if (!binding) return { bound: false };
    return {
        bound: true,
        sourceKey: binding.sourceKey,
        namespaceKey: binding.namespaceKey,
        cacheFile: nodePath.basename(binding.cachePath),
    };
}

function sanitizeCanonicalFinding(finding) {
    return {
        canonicalId: finding.canonicalId,
        stateClass: finding.stateClass,
        aliases: (finding.aliases || []).map((alias) => ({
            findingId: alias.findingId,
            state: alias.state,
            severity: alias.severity,
            confidence: alias.confidence,
            maliciousProjectFit: alias.maliciousProjectFit,
            sourcePath: alias.sourcePath,
            producer: alias.producer,
            chainIds: [...(alias.chainIds || [])],
            completeChainIds: [...(alias.completeChainIds || [])],
            validationChainIds: [...(alias.validationChainIds || [])],
            validatedChainIds: [...(alias.validatedChainIds || [])],
        })),
        observedStates: [...(finding.observedStates || [])],
        observedSeverities: [...(finding.observedSeverities || [])],
        observedConfidences: [...(finding.observedConfidences || [])],
        observedProjectFits: [...(finding.observedProjectFits || [])],
        strongestObservedSeverity: finding.strongestObservedSeverity,
        evidence: (finding.evidence || []).map(sanitizeEvidence),
        independentPaths: [...(finding.independentPaths || [])],
        provenance: {
            findingIds: [...(finding.provenance?.findingIds || [])],
            producers: [...(finding.provenance?.producers || [])],
            crossValidationCount: finding.provenance?.crossValidationCount || 0,
            independentPathCount: finding.provenance?.independentPathCount || 0,
        },
        chainIds: [...(finding.chainIds || [])],
        validationChainIds: [...(finding.validationChainIds || [])],
        validatedChainIds: [...(finding.validatedChainIds || [])],
        nodeIds: [...(finding.nodeIds || [])],
        edgeIds: [...(finding.edgeIds || [])],
        truncation: {
            aliases: finding.truncation?.aliases === true,
            evidence: finding.truncation?.evidence === true,
            paths: finding.truncation?.paths === true,
            producers: finding.truncation?.producers === true,
            chains: finding.truncation?.chains === true,
            nodeIds: finding.truncation?.nodeIds === true,
            edgeIds: finding.truncation?.edgeIds === true,
        },
        scores: {
            impactSeverity: {
                level: finding.scores?.impactSeverity?.level,
                rank: finding.scores?.impactSeverity?.rank,
            },
            evidenceConfidence: {
                level: finding.scores?.evidenceConfidence?.level,
                rank: finding.scores?.evidenceConfidence?.rank,
            },
            maliciousProjectFitLikelihood: {
                level: finding.scores?.maliciousProjectFitLikelihood?.level,
                rank: finding.scores?.maliciousProjectFitLikelihood?.rank,
            },
            trustedValidatedChain: finding.scores?.trustedValidatedChain === true,
            rationaleCodes: [...(finding.scores?.rationaleCodes || [])],
        },
    };
}

function sanitizeBlocker(value) {
    if (!isPlainObject(value)) return { code: "invalid-blocker-shape" };
    return {
        ...(value.code ? { code: value.code }: {}),
        ...(value.kind ? { kind: value.kind }: {}),
        ...(value.canonicalId ? { canonicalId: value.canonicalId }: {}),
        ...(value.canonicalFindingId
            ? { canonicalFindingId: value.canonicalFindingId }: {}),
        ...(value.currentStage ? { currentStage: value.currentStage }: {}),
        ...(value.path ? { path: value.path }: {}),
        ...(value.status ? { status: value.status }: {}),
        ...(Number.isSafeInteger(value.count) ? { count: value.count }: {}),
        ...(Number.isSafeInteger(value.cap) ? { cap: value.cap }: {}),
        ...(Number.isSafeInteger(value.observed) ? { observed: value.observed }: {}),
        ...(Number.isSafeInteger(value.attempts) ? { attempts: value.attempts }: {}),
        ...(Array.isArray(value.blockers)
            ? { blockers: value.blockers.map(sanitizeBlocker) }: {}),
    };
}

function sanitizeAcquisitionCoverage(value) {
    if (!value) return null;
    return {
        schemaVersion: value.schemaVersion,
        commitSha: value.commitSha || null,
        rootTreeSha: value.rootTreeSha || null,
        requiredAcquisitionComplete: value.requiredAcquisitionComplete === true,
        enumeration: {
            complete: value.enumeration?.complete === true,
            uniqueFiles: value.enumeration?.uniqueFiles || 0,
            uniqueBlobShas: value.enumeration?.uniqueBlobShas || 0,
            duplicateEntries: value.enumeration?.duplicateEntries || 0,
            unresolvedSubtrees: value.enumeration?.unresolvedSubtrees || 0,
            coverageBlockers: value.enumeration?.coverageBlockers || 0,
            stateTrackingTruncated: value.enumeration?.stateTrackingTruncated === true,
            discoveryTruncated: value.enumeration?.discoveryTruncated === true,
            failureAttempts: value.enumeration?.failureAttempts || 0,
            likelyBinaryByExtension: value.enumeration?.likelyBinaryByExtension || 0,
        },
        acquisition: {
            uniqueFetchedFiles: value.acquisition?.uniqueFetchedFiles || 0,
            fetchAttempts: value.acquisition?.fetchAttempts || 0,
            duplicateFetchCalls: value.acquisition?.duplicateFetchCalls || 0,
            fetchFailureAttempts: value.acquisition?.fetchFailureAttempts || 0,
            observedOutcomes: Object.fromEntries([
                "fullTextFiles",
                "truncatedTextFiles",
                "binaryMetadataOnlyFiles",
                "oversizedMetadataOnlyFiles",
                "metadataOnlyFiles",
                "failureFiles",
            ].map((key) => [key, value.acquisition?.observedOutcomes?.[key] || 0])),
            bestOutcomes: Object.fromEntries([
                "fullTextFiles",
                "truncatedTextFiles",
                "binaryMetadataOnlyFiles",
                "oversizedMetadataOnlyFiles",
                "metadataOnlyFiles",
                "failureOnlyFiles",
            ].map((key) => [key, value.acquisition?.bestOutcomes?.[key] || 0])),
        },
        deterministicMandatory: {
            requiredBlobClassifications:
                value.deterministicMandatory?.requiredBlobClassifications || 0,
            mandatoryAttemptedBlobs:
                value.deterministicMandatory?.mandatoryAttemptedBlobs || 0,
            classifiedAndInspectedBlobs:
                value.deterministicMandatory?.classifiedAndInspectedBlobs || 0,
            fullyFetchedAndScannedTextBlobs:
                value.deterministicMandatory?.fullyFetchedAndScannedTextBlobs || 0,
            classifiedBinaryBlobs:
                value.deterministicMandatory?.classifiedBinaryBlobs || 0,
            missingOrIncomplete:
                value.deterministicMandatory?.missingOrIncomplete || 0,
            notFetched: value.deterministicMandatory?.notFetched || 0,
            councilSampleOnlyBlobs:
                value.deterministicMandatory?.councilSampleOnlyBlobs || 0,
            invisibleUnicodeMatchedFiles:
                value.deterministicMandatory?.invisibleUnicodeMatchedFiles || 0,
            invisibleUnicodeMatchCount:
                value.deterministicMandatory?.invisibleUnicodeMatchCount || 0,
        },
        councilSampling: {
            uniqueSampledFiles: value.councilSampling?.uniqueSampledFiles || 0,
            satisfiesMandatoryCoverage:
                value.councilSampling?.satisfiesMandatoryCoverage === true,
        },
        blockers: (value.blockers || []).map(sanitizeBlocker),
        details: {
            missingOrIncomplete: (value.details?.missingOrIncomplete || []).map((entry) => ({
                path: entry.path,
                size: entry.size,
                likelyBinaryByExtension: entry.likelyBinaryByExtension === true,
                status: entry.status,
            })),
            notFetched: [...(value.details?.notFetched || [])],
            unresolvedSubtrees: (value.details?.unresolvedSubtrees || []).map((entry) => ({
                path: entry.path,
                sha: entry.sha,
            })),
            fetchFailures: (value.details?.fetchFailures || []).map((entry) => ({
                path: entry.path,
                scope: entry.scope,
            })),
            enumerationFailures: (value.details?.enumerationFailures || []).map((entry) => ({
                path: entry.path,
            })),
            invisibleUnicodeMatches:
                (value.details?.invisibleUnicodeMatches || []).map((entry) => ({
                    path: entry.path,
                    matchCount: entry.matchCount,
                    complete: entry.complete === true,
                })),
        },
        bounded: Object.fromEntries([
            "maxItems",
            "blockersTruncated",
            "missingOrIncompleteTruncated",
            "notFetchedTruncated",
            "unresolvedSubtreesTruncated",
            "fetchFailuresTruncated",
            "enumerationFailuresTruncated",
            "invisibleUnicodeMatchesTruncated",
        ].map((key) => [key, value.bounded?.[key] ?? false])),
    };
}

function sanitizeReleaseAssetCoverage(value) {
    if (!value) return null;
    return {
        schemaVersion: value.schemaVersion,
        releaseId: value.releaseId || null,
        tagName: value.tagName || null,
        sourceCommitSha: value.sourceCommitSha || null,
        requiredReleaseAssetAcquisitionComplete:
            value.requiredReleaseAssetAcquisitionComplete === true,
        enumeration: {
            recorded: value.enumeration?.recorded === true,
            complete: value.enumeration?.complete === true,
            truncated: value.enumeration?.truncated === true,
            listAttempts: value.enumeration?.listAttempts || 0,
            listFailureAttempts: value.enumeration?.listFailureAttempts || 0,
            totalAssetsReported: value.enumeration?.totalAssetsReported || 0,
            uniqueAssets: value.enumeration?.uniqueAssets || 0,
            duplicateAssets: value.enumeration?.duplicateAssets || 0,
            zeroAssets: value.enumeration?.zeroAssets === true,
            maxTrackedAssets: value.enumeration?.maxTrackedAssets || 0,
        },
        acquisition: {
            fetchAttempts: value.acquisition?.fetchAttempts || 0,
            uniqueDownloadedAndHashedAssets:
                value.acquisition?.uniqueDownloadedAndHashedAssets || 0,
            duplicateFetchCalls: value.acquisition?.duplicateFetchCalls || 0,
            skippedAssets: value.acquisition?.skippedAssets || 0,
            failedAssets: value.acquisition?.failedAssets || 0,
            oversizedAssets: value.acquisition?.oversizedAssets || 0,
            byteMismatchAssets: value.acquisition?.byteMismatchAssets || 0,
        },
        blockers: (value.blockers || []).map(sanitizeBlocker),
        details: {
            downloadedAndHashed: (value.details?.downloadedAndHashed || []).map((entry) => ({
                assetId: entry.assetId,
                sizeBytes: entry.sizeBytes,
                sha256: entry.sha256,
                path: entry.path,
                classification: entry.classification,
                previewByteCount: entry.previewByteCount,
            })),
            downloadedAndHashedTruncated:
                value.details?.downloadedAndHashedTruncated === true,
            skippedAssetIds: [...(value.details?.skippedAssetIds || [])],
            skippedAssetIdsTruncated: value.details?.skippedAssetIdsTruncated === true,
            failedAssetIds: [...(value.details?.failedAssetIds || [])],
            failedAssetIdsTruncated: value.details?.failedAssetIdsTruncated === true,
            oversizedAssetIds: [...(value.details?.oversizedAssetIds || [])],
            oversizedAssetIdsTruncated:
                value.details?.oversizedAssetIdsTruncated === true,
            byteMismatchAssetIds: [...(value.details?.byteMismatchAssetIds || [])],
            byteMismatchAssetIdsTruncated:
                value.details?.byteMismatchAssetIdsTruncated === true,
            listFailureCount: (value.details?.listFailures || []).length,
            listFailuresTruncated: value.details?.listFailuresTruncated === true,
        },
    };
}

function sanitizeCouncilCoverage(ledgerSnapshot) {
    return {
        roles: (ledgerSnapshot.roles || []).map((role) => ({
            id: role.id,
            category: role.category,
            mandatory: role.mandatory === true,
        })),
        submissions: (ledgerSnapshot.submissions || []).map((submission) => ({
            roleId: submission.roleId,
            digest: submission.digest,
            candidateCount: submission.candidateCount,
            coveragePerformedCount: submission.coveragePerformedCount,
        })),
        finalization: ledgerSnapshot.finalization ? {
            successfulRoleIds: [...(ledgerSnapshot.finalization.successfulRoleIds || [])],
            failedRoleIds: [...(ledgerSnapshot.finalization.failedRoleIds || [])],
            deterministicBaselineComplete:
                ledgerSnapshot.finalization.deterministicBaselineComplete === true,
            digest: ledgerSnapshot.finalization.digest,
        }: null,
    };
}

function sanitizeRemediationPlan(value, operatorDecisions) {
    if (!value) {
        return {
            planId: null,
            inputFingerprint: null,
            coverageComplete: false,
            counts: { candidates: 0, investigationGuidance: 0, blockers: 0 },
            candidates: [],
            investigationGuidance: [],
            truncation: {},
            blockers: [],
            operatorDecisions,
        };
    }
    return {
        planId: value.id,
        inputFingerprint: value.inputFingerprint,
        coverageComplete: value.coverageComplete === true,
        counts: {
            candidates: (value.candidates || []).length,
            investigationGuidance: (value.investigationGuidance || []).length,
            blockers: (value.blockers || []).length,
        },
        candidates: (value.candidates || []).map((candidate) => ({
            id: candidate.id,
            canonicalFindingId: candidate.canonicalFindingId,
            sourceFindingIds: [...candidate.sourceFindingIds],
            target: {
                strategy: candidate.target.strategy,
                chainId: candidate.target.chainId,
                edgeIds: [...candidate.target.edgeIds],
                linkKind: candidate.target.linkKind,
                evidence: candidate.target.evidence.map(sanitizeEvidence),
                locationHash: candidate.target.locationHash,
            },
            expectedBehaviorRemoved: {
                chainIds: [...candidate.expectedBehaviorRemoved.chainIds],
                linkKind: candidate.expectedBehaviorRemoved.linkKind,
                fromKind: candidate.expectedBehaviorRemoved.fromKind,
                toKind: candidate.expectedBehaviorRemoved.toKind,
                effectKinds: [...candidate.expectedBehaviorRemoved.effectKinds],
                behaviorIntentHash: candidate.expectedBehaviorRemoved.behaviorIntentHash,
            },
            legitimateFunctionalityRisk: {
                level: candidate.legitimateFunctionalityRisk.level,
                riskCodes: [...candidate.legitimateFunctionalityRisk.riskCodes],
                sharedChainIds: [...candidate.legitimateFunctionalityRisk.sharedChainIds],
            },
            staticVerification: {
                graphCoverage: candidate.staticVerification.graphCoverage,
                outcome: candidate.staticVerification.outcome,
                maliciousChainRemains:
                    candidate.staticVerification.maliciousChainRemains,
                fixClaimAllowed: candidate.staticVerification.fixClaimAllowed === true,
                alternateChainIds: [...candidate.staticVerification.alternateChainIds],
                criteriaCodes: [...candidate.staticVerification.criteriaCodes],
            },
            intentHash: candidate.intentHash,
        })),
        investigationGuidance: (value.investigationGuidance || []).map((guidance) => ({
            id: guidance.id,
            canonicalFindingId: guidance.canonicalFindingId,
            sourceFindingIds: [...guidance.sourceFindingIds],
            evidence: guidance.evidence.map(sanitizeEvidence),
            guidanceCodes: [...guidance.guidanceCodes],
            confidentPatchAllowed: guidance.confidentPatchAllowed === true,
            locationHash: guidance.locationHash,
        })),
        truncation: {
            canonicalFindings: value.truncation?.canonicalFindings === true,
            candidates: value.truncation?.candidates === true,
            guidance: value.truncation?.guidance === true,
            blockers: value.truncation?.blockers === true,
        },
        blockers: (value.blockers || []).map(sanitizeBlocker),
        operatorDecisions,
    };
}

function collectKnownSourceStrings(ledgerSnapshot, analysisPlugins) {
    const values = [];
    const add = (value) => {
        if (typeof value === "string" && value.trim()) values.push(value.normalize("NFKC").trim());
    };
    for (const fact of analysisPlugins?.facts || []) {
        add(fact.name);
        add(fact.value);
    }
    for (const finding of ledgerSnapshot?.findingLedger?.findings || []) {
        add(finding.title);
        add(finding.summary);
    }
    for (const decision of ledgerSnapshot?.findingLedger?.validationDecisions || []) {
        add(decision.rationale);
    }
    for (const decision of ledgerSnapshot?.validation?.decisions || []) add(decision.rationale);
    for (const adjudication of ledgerSnapshot?.validation?.adjudications || []) {
        add(adjudication.rationale);
    }
    for (const node of ledgerSnapshot?.behaviorGraph?.nodes || []) add(node.label);
    return values;
}

function normalizeOperatorRationale(value, knownSourceStrings) {
    if (typeof value !== "string") throw new TypeError("operator_rationale must be a string");
    const normalized = value.normalize("NFKC").trim();
    if (!normalized || Buffer.byteLength(normalized, "utf8")
        > REPORT_LEDGER_LIMITS.operatorRationaleBytes) {
        throw new TypeError(
            `operator_rationale must contain 1-${REPORT_LEDGER_LIMITS.operatorRationaleBytes} UTF-8 bytes`,
        );
    }
    if (/[\u0000-\u001f\u007f]/u.test(normalized)) {
        throw new TypeError("operator_rationale must be one line without control characters");
    }
    if (normalized.includes("`")) {
        throw new TypeError("operator_rationale must not contain backticks or code fences");
    }
    if (/\b(?:https?:\/\/|www\.|[a-z][a-z0-9+.-]*:\/\/)/iu.test(normalized)) {
        throw new TypeError("operator_rationale must not contain URLs");
    }
    if (/[A-Za-z0-9+/_=-]{48,}/u.test(normalized)) {
        throw new TypeError("operator_rationale contains a long encoded or opaque token");
    }
    if (/\b(?:finding|verdict|severity|confidence|validated|refuted|unresolved|critical|high|medium|low|no red flags)\b/iu.test(normalized)) {
        throw new TypeError("operator_rationale must not make finding or verdict claims");
    }
    const lower = normalized.toLowerCase();
    for (const sourceValue of knownSourceStrings) {
        const sourceLower = sourceValue.toLowerCase();
        if (sourceLower.length >= 12 && lower.includes(sourceLower)) {
            throw new TypeError("operator_rationale matches known source-derived text");
        }
        for (const token of sourceLower.match(/[a-z0-9_$@./:+?&=%#,-]{16,}/gu) || []) {
            if (lower.includes(token)) {
                throw new TypeError("operator_rationale contains a known source-derived token");
            }
        }
    }
    return normalized;
}

export function normalizeOperatorDecisions(value = [], {
    decisionSnapshot,
    remediationPlan = null,
    knownSourceStrings = [],
} = {}) {
    if (!Array.isArray(value) || value.length > REPORT_LEDGER_LIMITS.operatorDecisions) {
        throw new TypeError(
            `operator_decisions must contain at most ${REPORT_LEDGER_LIMITS.operatorDecisions} records`,
        );
    }
    const canonicalIds = new Set((decisionSnapshot?.canonicalFindings || []).map((finding) =>
        finding.canonicalId));
    const candidates = new Map((remediationPlan?.candidates || []).map((candidate) => [
        candidate.canonicalFindingId,
        candidate,
    ]));
    const seen = new Set();
    return Object.freeze(value.map((entry, index) => {
        if (!isPlainObject(entry)) {
            throw new TypeError(`operator_decisions[${index}] must be an object`);
        }
        const allowed = new Set([
            "finding_id",
            "action",
            "rationale_category",
            "operator_rationale",
        ]);
        for (const key of Object.keys(entry)) {
            if (!allowed.has(key)) {
                throw new TypeError(`operator_decisions[${index}].${key} is not allowed`);
            }
        }
        const findingId = String(entry.finding_id || "");
        if (!canonicalIds.has(findingId)) {
            throw new TypeError(
                `operator_decisions[${index}].finding_id must reference a canonical finding`,
            );
        }
        if (seen.has(findingId)) {
            throw new TypeError(`operator_decisions contains duplicate finding_id ${findingId}`);
        }
        seen.add(findingId);
        if (!OPERATOR_ACTIONS.includes(entry.action)) {
            throw new TypeError(`operator_decisions[${index}].action is invalid`);
        }
        if (!OPERATOR_RATIONALE_CATEGORIES.includes(entry.rationale_category)) {
            throw new TypeError(
                `operator_decisions[${index}].rationale_category is invalid`,
            );
        }
        const rationale = Object.hasOwn(entry, "operator_rationale")
            ? normalizeOperatorRationale(entry.operator_rationale, knownSourceStrings): null;
        if (entry.rationale_category === "other" && !rationale) {
            throw new TypeError("rationale_category 'other' requires operator_rationale");
        }
        if (entry.action === "defanged") {
            const candidate = candidates.get(findingId);
            if (entry.rationale_category !== "remediation-applied"
                || candidate?.staticVerification?.fixClaimAllowed !== true) {
                throw new TypeError(
                    "defanged decisions require a trusted fix-claim candidate and remediation-applied category",
                );
            }
        }
        if (entry.action === "delete-project"
            && entry.rationale_category !== "project-deleted") {
            throw new TypeError("delete-project decisions require project-deleted category");
        }
        if (entry.action === "kept-as-is"
            && ["remediation-applied", "project-deleted"].includes(entry.rationale_category)) {
            throw new TypeError("kept-as-is decisions require a keep rationale category");
        }
        return Object.freeze({
            findingId,
            action: entry.action,
            rationaleCategory: entry.rationale_category,
            ...(rationale ? {
                operatorRationale: Object.freeze({
                    origin: "operator-supplied",
                    text: rationale,
                }),
            }: {}),
        });
    }));
}

function renderManifestFor(document) {
    return {
        verdict: document.verdict.value,
        findings: document.canonicalFindings.map((finding) => ({
            canonicalId: finding.canonicalId,
            state: finding.stateClass,
            severity: finding.scores.impactSeverity.level,
            confidence: finding.scores.evidenceConfidence.level,
            maliciousProjectFit: finding.scores.maliciousProjectFitLikelihood.level,
            evidenceCount: finding.evidence.length,
            chainCount: finding.chainIds.length,
        })),
        ...(document.flow === "trusted-ledger" ? { remediation: {
            planId: document.remediation.planId,
            counts: document.remediation.counts,
            operatorDecisions: document.remediation.operatorDecisions,
        } }: {}),
    };
}

function assertSourceTextFree(value, path = "findingsArtifact") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => assertSourceTextFree(entry, `${path}[${index}]`));
        return;
    }
    if (!isPlainObject(value)) return;
    for (const [key, entry] of Object.entries(value)) {
        if (FORBIDDEN_ARTIFACT_KEYS.has(key)) {
            throw new Error(`${path}.${key} is not permitted in the source-text-free findings artifact`);
        }
        assertSourceTextFree(entry, `${path}.${key}`);
    }
}

function assertBaselineArtifactPrivacy(value, path = "findingsArtifact", parentKey = null) {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => {
            if (typeof entry === "string"
                && !BASELINE_ALLOWED_STRING_ARRAY_KEYS.has(parentKey)) {
                throw new Error(
                    `${path}[${index}] is not permitted to contain an arbitrary string`,
                );
            }
            assertBaselineArtifactPrivacy(entry, `${path}[${index}]`, parentKey);
        });
        return;
    }
    if (typeof value === "string") {
        if (!BASELINE_ALLOWED_STRING_KEYS.has(parentKey)
            && !BASELINE_ALLOWED_STRING_ARRAY_KEYS.has(parentKey)) {
            throw new Error(`${path} is not permitted to contain an arbitrary string`);
        }
        if (/[\u0000-\u001f\u007f]/u.test(value)) {
            throw new Error(`${path} contains a control character`);
        }
        if (parentKey === "value" && path !== "findingsArtifact.verdict.value") {
            throw new Error(`${path} is not permitted to persist a source-controlled value`);
        }
        if (parentKey === "text" && !path.endsWith(".operatorRationale.text")) {
            throw new Error(`${path} is not a permitted operator-supplied rationale`);
        }
        return;
    }
    if (!isPlainObject(value)) return;
    for (const [key, entry] of Object.entries(value)) {
        if (FORBIDDEN_ARTIFACT_KEYS.has(key)) {
            throw new Error(
                `${path}.${key} is not permitted in the baseline analysis privacy artifact`,
            );
        }
        assertBaselineArtifactPrivacy(entry, `${path}.${key}`, key);
    }
}

function finalizeDocument(base) {
    const withManifest = {
        ...base,
        renderManifestSha256: sha256Canonical(renderManifestFor(base)),
    };
    const document = {
        ...withManifest,
        documentId: `ztfindings-${sha256Canonical(withManifest)}`,
    };
    if (document.flow === "trusted-ledger") assertBaselineArtifactPrivacy(document);
    else assertSourceTextFree(document);
    return Object.freeze(structuredClone(document));
}

export function buildFindingsArtifact({
    context,
    reportIdentity,
    decisionSnapshot,
    ledgerSnapshot,
    traceSnapshot,
    analysisIndex,
    analysisPlugins,
    stageState,
    cacheBinding,
    acquisitionCoverage,
    releaseAssetCoverage,
    blockers = [],
    verdict,
    trustedVerdict,
    operatorDecisions = [],
    knownSourceStrings = [],
} = {}) {
    const auditId = validateAuditId(context?.auditId);
    if (!decisionSnapshot || decisionSnapshot.auditId !== auditId) {
        throw new Error("findings artifact requires an audit-bound decision snapshot");
    }
    if (!ledgerSnapshot || ledgerSnapshot.auditId !== auditId) {
        throw new Error("findings artifact requires the active audit's council ledger");
    }
    if (!VERDICTS.includes(verdict)) throw new Error(`invalid findings verdict: ${verdict}`);

    const validation = ledgerSnapshot.validation;
    const normalizedOperatorDecisions = normalizeOperatorDecisions(operatorDecisions, {
        decisionSnapshot,
        remediationPlan: ledgerSnapshot.findingLedger?.remediation || null,
        knownSourceStrings: [
            ...knownSourceStrings,
            ...collectKnownSourceStrings(ledgerSnapshot, analysisPlugins),
        ],
    });
    const canonicalFindings = decisionSnapshot.canonicalFindings.map(sanitizeCanonicalFinding);
    const base = {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        artifactSchemaRevision: FINDINGS_ARTIFACT_SCHEMA_REVISION,
        artifactType: "zerotrust-sourcecheck-findings",
        flow: "trusted-ledger",
        auditId,
        mode: context.mode,
        sourceIdentity: buildSourceIdentity(context),
        reportIdentity: structuredClone(reportIdentity),
        decision: {
            decisionId: decisionSnapshot.decisionId,
            inputFingerprint: decisionSnapshot.inputFingerprint,
            policy: structuredClone(decisionSnapshot.policy),
            rationaleCodes: [...decisionSnapshot.rationaleCodes],
            truncation: structuredClone(decisionSnapshot.truncation),
        },
        verdict: {
            value: verdict,
            trusted: trustedVerdict === true,
            deterministic: true,
            eligibleVerdicts: [...decisionSnapshot.overallVerdictEligibility.eligibleVerdicts],
            trustedDecisionEligible:
                decisionSnapshot.overallVerdictEligibility.trustedDecisionEligible === true,
        },
        stage: {
            input: stageState.current,
            history: [...stageState.history],
            final: stageState.current === "validated" ? "finalized": stageState.current,
        },
        coverage: {
            decision: Object.fromEntries(Object.entries(decisionSnapshot.coverage).map(
                ([key, complete]) => [key, complete === true],
            )),
            acquisition: sanitizeAcquisitionCoverage(acquisitionCoverage),
            releaseAssets: sanitizeReleaseAssetCoverage(releaseAssetCoverage),
            analysisIndex: compactAnalysisIndex(analysisIndex),
            analysisPlugins: compactPlugins(analysisPlugins),
            council: sanitizeCouncilCoverage(ledgerSnapshot),
            validation: validation ? {
                minSeverity: validation.minSeverity,
                inputFingerprint: validation.inputFingerprint,
                requiredFindingIds: [...validation.requiredFindingIds],
                counts: Object.fromEntries(Object.entries(validation.counts || {}).map(
                    ([key, count]) => [key, count],
                )),
                completion: Object.fromEntries(Object.entries(validation.completion || {}).map(
                    ([key, complete]) => [key, complete],
                )),
                truncation: Object.fromEntries(Object.entries(validation.truncation || {}).map(
                    ([key, truncated]) => [key, truncated === true],
                )),
                finalizationDigest: validation.finalization?.digest || null,
            }: null,
        },
        cache: normalizeCacheMetadata(cacheBinding),
        stateCounts: Object.fromEntries(FINDING_STATES.map((state) => [
            state,
            decisionSnapshot.stateCounts?.[state] || 0,
        ])),
        severityCounts: Object.fromEntries(Object.entries(
            decisionSnapshot.severityCounts,
        ).map(([bucket, counts]) => [
            bucket,
            Object.fromEntries(SEVERITIES.map((severity) => [
                severity,
                counts?.[severity] || 0,
            ])),
        ])),
        canonicalFindings,
        aliases: canonicalFindings.map((finding) => ({
            canonicalId: finding.canonicalId,
            findingIds: finding.aliases.map((alias) => alias.findingId),
        })),
        validationDecisions: (validation?.decisions || []).map(sanitizeValidationDecision),
        adjudications: (validation?.adjudications || []).map(sanitizeAdjudication),
        graph: traceSnapshot ? {
            inputFingerprint: traceSnapshot.inputFingerprint,
            coverageComplete: traceSnapshot.coverageComplete === true,
            gates: Object.fromEntries(Object.entries(traceSnapshot.gates || {}).map(
                ([key, complete]) => [key, complete === true],
            )),
            counts: Object.fromEntries(Object.entries(traceSnapshot.counts || {}).map(
                ([key, count]) => [key, count],
            )),
            truncation: Object.fromEntries(Object.entries(traceSnapshot.truncation || {}).map(
                ([key, truncated]) => [key, truncated === true],
            )),
            blockers: (traceSnapshot.blockers || []).map(sanitizeBlocker),
            chains: (traceSnapshot.chains || []).map(sanitizeChain),
        }: null,
        remediation: sanitizeRemediationPlan(
            ledgerSnapshot.findingLedger?.remediation || null,
            normalizedOperatorDecisions,
        ),
        blockers: uniqueCanonical(blockers.map(sanitizeBlocker)),
    };
    return finalizeDocument(base);
}

export function buildCompatibilityFindingsArtifact({
    context,
    reportIdentity,
    stageState,
    cacheBinding,
    acquisitionCoverage,
    releaseAssetCoverage,
    blockers = [],
    verdict,
} = {}) {
    const auditId = validateAuditId(context?.auditId);
    if (!VERDICTS.includes(verdict)) throw new Error(`invalid compatibility findings verdict: ${verdict}`);
    return finalizeDocument({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        artifactSchemaRevision: FINDINGS_ARTIFACT_SCHEMA_REVISION,
        artifactType: "zerotrust-sourcecheck-findings",
        flow: "compatibility-report",
        auditId,
        mode: context.mode,
        sourceIdentity: buildSourceIdentity(context),
        reportIdentity: structuredClone(reportIdentity),
        decision: null,
        verdict: {
            value: verdict,
            trusted: false,
            deterministic: false,
            eligibleVerdicts: [verdict],
            trustedDecisionEligible: false,
        },
        stage: {
            input: stageState.current,
            history: [...stageState.history],
            final: stageState.current,
        },
        coverage: {
            acquisition: structuredClone(acquisitionCoverage || null),
            releaseAssets: structuredClone(releaseAssetCoverage || null),
        },
        cache: normalizeCacheMetadata(cacheBinding),
        stateCounts: null,
        severityCounts: null,
        canonicalFindings: [],
        aliases: [],
        validationDecisions: [],
        adjudications: [],
        graph: null,
        blockers: uniqueCanonical([
            { code: "compatibility-report-no-validated-ledger" },
            ...blockers,
        ]),
    });
}

export function serializeFindingsArtifact(document) {
    if (document?.flow === "trusted-ledger") assertBaselineArtifactPrivacy(document);
    else assertSourceTextFree(document);
    const serialized = `${canonicalJson(document)}\n`;
    const bytes = Buffer.byteLength(serialized, "utf8");
    if (bytes > REPORT_LEDGER_LIMITS.findingsBytes) {
        throw new RangeError(
            `FINDINGS.json exceeds ${REPORT_LEDGER_LIMITS.findingsBytes} bytes`,
        );
    }
    return serialized;
}

function totalCounts(value) {
    return Object.values(value || {}).reduce((sum, count) => sum + Number(count || 0), 0);
}

function deterministicExecutiveSummary(document) {
    const active = document.severityCounts.active;
    const activeCount = totalCounts(active);
    const states = document.stateCounts;
    const blockerCount = document.blockers.length;
    const remediation = document.remediation;
    if (document.verdict.value === "incomplete") {
        return `The audit is incomplete because ${blockerCount} trusted blocker`
            + `${blockerCount === 1 ? "": "s"} remain. Partial active finding counts are `
            + `${activeCount} total (${active.critical} critical, ${active.high} high, `
            + `${active.medium} medium, ${active.low} low, ${active.info} info); these counts `
            + "are not a trusted overall severity conclusion.";
    }
    return `The validated trusted ledger produced the deterministic verdict `
        + `${document.verdict.value}. Active findings: ${activeCount} total `
        + `(${active.critical} critical, ${active.high} high, ${active.medium} medium, `
        + `${active.low} low, ${active.info} info); states: ${states.validated} validated, `
        + `${states.unresolved} unresolved, ${states.refuted} refuted. Remediation metadata `
        + `contains ${remediation.counts.candidates} candidate`
        + `${remediation.counts.candidates === 1 ? "": "s"}, `
        + `${remediation.counts.investigationGuidance} investigation-guidance record`
        + `${remediation.counts.investigationGuidance === 1 ? "": "s"}, and `
        + `${remediation.operatorDecisions.length} operator decision`
        + `${remediation.operatorDecisions.length === 1 ? "": "s"}.`;
}

function deterministicRecommendation(document) {
    const verdict = document.verdict.value;
    if (verdict === "incomplete") {
        return "Resolve every trusted blocker and re-run the same audit before relying on a severity conclusion.";
    }
    if (verdict === "critical" || verdict === "high") {
        return "Do not use the audited project until every active critical/high finding is remediated or explicitly accepted by the operator and a fresh audit completes.";
    }
    if (verdict === "medium") {
        return "Review and remediate the active medium findings before deployment, then run a fresh audit.";
    }
    if (verdict === "low") {
        return "Review the low/info findings and their evidence hashes before use; re-audit after any change.";
    }
    if (verdict === "no red flags found") {
        return "No red flags were found within the completed static coverage; this is not a guarantee against environment-gated or novel behavior.";
    }
    return "Treat reconnaissance-only output as non-conclusive and run a full audit before use.";
}

function escapeMarkdown(value) {
    return String(value)
        .replace(/\\/gu, "\\\\")
        .replace(/([`*_[\]<>|])/gu, "\\$1");
}

function evidenceLine(evidence) {
    return `${escapeMarkdown(evidence.path)}:${evidence.startLine}-${evidence.endLine}`
        + `; blob=${evidence.blobSha}; excerpt=${evidence.excerptHash}`
        + `; producer=${escapeMarkdown(evidence.producer)}`
        + `; scope=${evidence.coverageScope}`;
}

function renderOperatorDecisionLines(document) {
    return document.remediation.operatorDecisions.map((decision) => {
        const rationale = decision.operatorRationale
            ? `; user-supplied rationale=${escapeMarkdown(decision.operatorRationale.text)}`: "";
        return `- ${decision.findingId}: action=${decision.action}; `
            + `rationale-category=${decision.rationaleCategory}${rationale}`;
    }).join("\n");
}

export function renderFindingsMarkdown({
    document,
    findingsSha256,
} = {}) {
    if (!HASH_RE.test(String(findingsSha256 || ""))) {
        throw new Error("renderFindingsMarkdown requires the FINDINGS.json SHA-256");
    }
    const incomplete = document.verdict.value === "incomplete";
    const rows = document.canonicalFindings.map((finding) => {
        const score = finding.scores;
        return `| ${finding.canonicalId} | ${finding.stateClass} | `
            + `${score.impactSeverity.level} | ${score.evidenceConfidence.level} | `
            + `${score.maliciousProjectFitLikelihood.level} | ${finding.evidence.length} | `
            + `${finding.chainIds.length} |`;
    }).join("\n");
    const details = document.canonicalFindings.map((finding) => {
        const score = finding.scores;
        const aliases = finding.aliases.map((alias) =>
            `${alias.findingId} (${alias.state}, ${alias.producer}, ${escapeMarkdown(alias.sourcePath)})`);
        const evidence = finding.evidence.map((entry) => `  - ${evidenceLine(entry)}`);
        return `### ${finding.canonicalId}

- **State:** ${finding.stateClass}
- **Impact severity:** ${score.impactSeverity.level}
- **Evidence confidence:** ${score.evidenceConfidence.level}
- **Malicious-project fit:** ${score.maliciousProjectFitLikelihood.level}
- **Trusted validated chain:** ${score.trustedValidatedChain}
- **Aliases:** ${aliases.length > 0 ? aliases.join("; "): "none"}
- **Chain IDs:** ${finding.chainIds.length > 0 ? finding.chainIds.join(", "): "none"}
- **Validation chain IDs:** ${finding.validationChainIds.length > 0
        ? finding.validationChainIds.join(", "): "none"}
- **Validated complete chain IDs:** ${finding.validatedChainIds.length > 0
        ? finding.validatedChainIds.join(", "): "none"}
- **Evidence references:**
${evidence.length > 0 ? evidence.join("\n"): "  - none"}
`;
    }).join("\n");
    const blockers = document.blockers.length > 0
        ? document.blockers.map((blocker) => `- \`${escapeMarkdown(canonicalJson(blocker))}\``).join("\n"): "- none";
    const title = incomplete
        ? "# INCOMPLETE — DO NOT TRUST — zerotrust-sourcecheck report": "# zerotrust-sourcecheck report";

    return `${title}

- **Audit ID:** ${document.auditId}
- **Mode:** ${document.mode}
- **Verdict:** ${document.verdict.value}
- **Trusted verdict:** ${document.verdict.trusted}
- **Decision ID:** ${document.decision.decisionId}
- **FINDINGS.json SHA-256:** ${findingsSha256}
- **Ledger render SHA-256:** ${document.renderManifestSha256}
- **Analysis stage at finalization:** ${document.stage.input}

## Executive summary

${deterministicExecutiveSummary(document)}

## Findings

<!-- BEGIN TRUSTED FINDING ROWS -->
| Canonical ID | State | Severity | Confidence | Project fit | Evidence refs | Chain IDs |
|---|---|---|---|---|---:|---:|
${rows}
<!-- END TRUSTED FINDING ROWS -->

${details || "No canonical findings were recorded."}

## Exact blockers

${blockers}

## Recommendation

${deterministicRecommendation(document)}

## Operator decisions

<!-- BEGIN STRUCTURED OPERATOR DECISIONS -->
${renderOperatorDecisionLines(document) || "- none"}
<!-- END STRUCTURED OPERATOR DECISIONS -->

Any rationale above is explicitly user-supplied operator context. It is not trusted evidence and did not affect the verdict, finding states, or scoring.
`;
}

function expectedRows(document) {
    return document.canonicalFindings.map((finding) => ({
        canonicalId: finding.canonicalId,
        state: finding.stateClass,
        severity: finding.scores.impactSeverity.level,
        confidence: finding.scores.evidenceConfidence.level,
        maliciousProjectFit: finding.scores.maliciousProjectFitLikelihood.level,
        evidenceCount: String(finding.evidence.length),
        chainCount: String(finding.chainIds.length),
    }));
}

function parseTrustedRows(markdown) {
    const begin = "<!-- BEGIN TRUSTED FINDING ROWS -->";
    const end = "<!-- END TRUSTED FINDING ROWS -->";
    const start = markdown.indexOf(begin);
    const finish = markdown.indexOf(end);
    if (start < 0 || finish < start) throw new Error("trusted finding-row markers are missing");
    const lines = markdown.slice(start + begin.length, finish)
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.startsWith("|"));
    return lines.slice(2).map((line) => {
        const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
        if (cells.length !== 7) throw new Error("trusted finding row has the wrong column count");
        return {
            canonicalId: cells[0],
            state: cells[1],
            severity: cells[2],
            confidence: cells[3],
            maliciousProjectFit: cells[4],
            evidenceCount: cells[5],
            chainCount: cells[6],
        };
    });
}

export function assertMarkdownFindingsConsistency(markdown, document) {
    const verdicts = [...String(markdown).matchAll(/^- \*\*Verdict:\*\* (.+)$/gmu)]
        .map((match) => match[1].trim());
    if (verdicts.length !== 1 || verdicts[0] !== document.verdict.value) {
        throw new Error("REPORT.md verdict does not match FINDINGS.json");
    }
    const hashes = [...String(markdown).matchAll(
        /^- \*\*Ledger render SHA-256:\*\* ([a-f0-9]{64})$/gmu,
    )].map((match) => match[1]);
    if (hashes.length !== 1 || hashes[0] !== document.renderManifestSha256) {
        throw new Error("REPORT.md ledger render identity does not match FINDINGS.json");
    }
    if (document.renderManifestSha256 !== sha256Canonical(renderManifestFor(document))) {
        throw new Error("FINDINGS.json render manifest identity is invalid");
    }
    if (canonicalJson(parseTrustedRows(markdown)) !== canonicalJson(expectedRows(document))) {
        throw new Error("REPORT.md finding rows do not match FINDINGS.json");
    }
    const expectedSummary = `## Executive summary\n\n${deterministicExecutiveSummary(document)}`;
    if (!String(markdown).includes(expectedSummary)) {
        throw new Error("REPORT.md deterministic executive summary does not match FINDINGS.json");
    }
    const expectedRecommendation =
        `## Recommendation\n\n${deterministicRecommendation(document)}`;
    if (!String(markdown).includes(expectedRecommendation)) {
        throw new Error("REPORT.md deterministic recommendation does not match FINDINGS.json");
    }
    const expectedDecisions = "<!-- BEGIN STRUCTURED OPERATOR DECISIONS -->\n"
        + `${renderOperatorDecisionLines(document) || "- none"}\n`
        + "<!-- END STRUCTURED OPERATOR DECISIONS -->";
    if (!String(markdown).includes(expectedDecisions)) {
        throw new Error("REPORT.md operator decisions do not match FINDINGS.json");
    }
    return true;
}

export const __internals = Object.freeze({
    FORBIDDEN_ARTIFACT_KEYS,
    VERDICTS,
    assertBaselineArtifactPrivacy,
    assertSourceTextFree,
    compactPlugins,
    deterministicExecutiveSummary,
    deterministicRecommendation,
    expectedRows,
    parseTrustedRows,
    renderManifestFor,
    sanitizeAcquisitionCoverage,
    sanitizeReleaseAssetCoverage,
});
