import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import nodePath from "node:path";

import {
    deriveTags,
    normalizeCategory,
    normalizeTag,
} from "./tagDictionary.mjs";

export const SEVERITIES = Object.freeze([
    "none",
    "info",
    "low",
    "medium",
    "high",
    "critical",
]);

const SEVERITY_RE = /\b(critical|high|medium|low|info|informational)\b/iu;
const CATEGORY_RE = /\bcategory\s*[:#-]?\s*([A-G])\b/iu;
const FILE_FIELD_RE = /\b(?:file|path)\s*[:=]\s*`?([^`\s,;]+)`?/iu;
const LINE_RE = /\bline\s*[:#= ]\s*(\d{1,7})\b/iu;
const FILE_LINE_RE = /`?([A-Za-z0-9_.@()\\/-]+\.[A-Za-z0-9_+-]{1,12})`?:(\d{1,7})\b/u;
const TAGS_RE = /\btags?\s*[:=]\s*([^\r\n]+)/iu;
const PATH_TOKEN_RE = /`?([A-Za-z0-9_.@()\\/-]+\.[A-Za-z0-9_+-]{1,12})`?/u;

function hashEvidence(text) {
    return createHash("sha256")
        .update(String(text).trim().replace(/\s+/gu, " "))
        .digest("hex");
}

function normalizeSeverity(severity) {
    if (!severity) return "info";
    const value = String(severity).toLowerCase();
    return value === "informational" ? "info": value;
}

function parseTags(block) {
    const match = TAGS_RE.exec(block);
    if (!match) return [];
    return match[1]
        .split(/[;,]/u)
        .map((value) => normalizeTag(value))
        .filter(Boolean);
}

function parseFileAndLine(block) {
    const fileLine = FILE_LINE_RE.exec(block);
    if (fileLine) return { file: fileLine[1], line: Number(fileLine[2]) };
    const field = FILE_FIELD_RE.exec(block);
    const pathToken = field || PATH_TOKEN_RE.exec(block);
    const lineMatch = LINE_RE.exec(block);
    return {
        file: pathToken ? pathToken[1]: null,
        line: lineMatch ? Number(lineMatch[1]): null,
    };
}

function splitFindingBlocks(markdown) {
    const text = String(markdown || "").replace(/\r\n/gu, "\n");
    const blocks = [];
    let current = [];
    for (const line of text.split("\n")) {
        const startsFinding = /^(#{2,6}\s+|[-*]\s+)/u.test(line)
            && CATEGORY_RE.test(line);
        if (startsFinding && current.length > 0) {
            blocks.push(current.join("\n"));
            current = [line];
        } else if (startsFinding) current = [line];
        else if (current.length > 0) current.push(line);
    }
    if (current.length > 0) blocks.push(current.join("\n"));
    if (blocks.length > 0) return blocks;
    return text.split(/\n\s*\n+/u).filter((block) => CATEGORY_RE.test(block));
}

export function parseFindings(markdown, { source = "REPORT.md" } = {}) {
    const text = String(markdown || "");
    if (/\bno\s+red\s+flags\s+found\b/iu.test(text) && !CATEGORY_RE.test(text)) {
        return [];
    }
    const findings = [];
    for (const block of splitFindingBlocks(text)) {
        const category = normalizeCategory(CATEGORY_RE.exec(block)?.[1]);
        if (!category) continue;
        const severity = normalizeSeverity(SEVERITY_RE.exec(block)?.[1]);
        const { file, line } = parseFileAndLine(block);
        const explicitTags = parseTags(block);
        findings.push({
            severity,
            category,
            file,
            line,
            tags: deriveTags({ category, text: block, extraTags: explicitTags }),
            evidenceHash: hashEvidence(block),
            source,
        });
    }
    return findings;
}

function unique(values) {
    return [...new Set(values.filter(Boolean).map((value) =>
        String(value).trim().toLowerCase()).filter(Boolean))].sort();
}

function factTokens(fact) {
    return unique([
        fact.pluginId,
        fact.kind,
        fact.name,
        fact.value,
        ...String(fact.value || "").split(/[|,]/u),
    ]);
}

function findingTags(finding, chainById) {
    const chains = (finding.chainIds || []).map((id) => chainById.get(id)).filter(Boolean);
    return unique([
        ...(finding.tags || []),
        finding.signature?.activationVector,
        finding.signature?.capability,
        finding.signature?.effect?.action,
        finding.signature?.effect?.target,
        ...chains.map((chain) => chain.pattern),
        ...chains.flatMap((chain) =>
            (chain.steps || []).flatMap((step) => step.tags || [])),
    ]);
}

function normalizeArtifactFinding(finding, chainById, source) {
    const score = finding.scores || {};
    const evidence = finding.evidence?.[0] || {};
    return {
        severity: score.impactSeverity?.level
            || finding.severity
            || finding.strongestObservedSeverity
            || "info",
        confidence: score.evidenceConfidence?.level
            || finding.confidence
            || finding.observedConfidences?.[0]
            || "low",
        projectFit: score.maliciousProjectFitLikelihood?.level
            || finding.maliciousProjectFit
            || finding.observedProjectFits?.[0]
            || "unknown",
        state: finding.stateClass || finding.state || "unresolved",
        category: finding.category || null,
        file: evidence.path || finding.independentPaths?.[0] || null,
        line: evidence.startLine || null,
        tags: findingTags(finding, chainById),
        evidenceHash: evidence.excerptHash || finding.canonicalId || finding.id || null,
        source,
    };
}

function candidateCount(document, stateCounts) {
    if (Number.isSafeInteger(document.evaluation?.counts?.candidate)) {
        return document.evaluation.counts.candidate;
    }
    const submissions = document.coverage?.council?.submissions || [];
    const submitted = submissions.reduce((total, entry) =>
        total + (Number.isSafeInteger(entry.candidateCount) ? entry.candidateCount: 0), 0);
    if (submitted > 0) return submitted;
    const required = document.coverage?.validation?.requiredFindingIds;
    if (Array.isArray(required)) return required.length;
    return Object.values(stateCounts).reduce((total, value) =>
        total + (Number.isSafeInteger(value) ? value: 0), 0);
}

function blockerToken(blocker) {
    if (typeof blocker === "string") return normalizeTag(blocker);
    return normalizeTag(blocker?.code || blocker?.kind || "unspecified-blocker");
}

function inferFailureStage(finalStage) {
    if (finalStage === "acquired") return "prepare";
    if (finalStage === "prepared") return "scan";
    if (finalStage === "scanned") return "trace";
    if (finalStage === "traced") return "validate";
    if (finalStage === "validated") return "finalize";
    return null;
}

function maximum(values, order, fallback) {
    return values.reduce((best, value) =>
        order.indexOf(value) > order.indexOf(best) ? value: best, fallback);
}

export function parseFindingsJson(document, { source = "FINDINGS.json" } = {}) {
    if (!document || typeof document !== "object" || Array.isArray(document)) {
        throw new TypeError("FINDINGS.json must contain an object");
    }
    const isArtifact = document.artifactType === "zerotrust-sourcecheck-findings";
    const isDecision = typeof document.decisionId === "string"
        && document.overallVerdictEligibility;
    if (!isArtifact && !isDecision) {
        throw new TypeError("unsupported FINDINGS.json or decision snapshot shape");
    }
    const graph = document.graph || document.traceSnapshot || null;
    const chains = graph?.chains || [];
    const chainById = new Map(chains.map((chain) => [chain.id, chain]));
    const canonical = document.canonicalFindings || [];
    const findings = canonical.map((finding) =>
        normalizeArtifactFinding(finding, chainById, source));
    const stateCounts = {
        candidate: Number(document.stateCounts?.candidate || 0),
        validating: Number(document.stateCounts?.validating || 0),
        validated: Number(document.stateCounts?.validated || 0),
        refuted: Number(document.stateCounts?.refuted || 0),
        unresolved: Number(document.stateCounts?.unresolved || 0),
    };
    const pluginFacts = document.coverage?.analysisPlugins?.facts || [];
    const pluginFactTokens = unique(pluginFacts.flatMap(factTokens));
    const activationFacts = unique([
        ...pluginFacts
            .filter((fact) =>
                fact.kind === "execution-registration"
                || /activat|trigger|startup|workflow|lifecycle/iu.test(
                    `${fact.name || ""} ${fact.value || ""}`,
                ))
            .flatMap(factTokens),
        ...chains.flatMap((chain) =>
            (chain.steps || [])
                .filter((step) => step.kind === "activation" || step.kind === "trigger")
                .flatMap((step) => step.tags || [])),
    ]);
    const blockers = unique((document.blockers || []).map(blockerToken));
    const stages = document.stage?.history || [];
    const finalStage = document.stage?.final || null;
    const counts = {
        candidate: candidateCount(document, stateCounts),
        validated: Number(document.evaluation?.counts?.validated ?? stateCounts.validated),
        refuted: Number(document.evaluation?.counts?.refuted ?? stateCounts.refuted),
        unresolved: Number(document.evaluation?.counts?.unresolved ?? stateCounts.unresolved),
    };
    return Object.freeze({
        sourceFormat: isArtifact ? "findings-json": "decision-snapshot",
        source,
        findings,
        verdict: document.verdict?.value
            || document.overallVerdictEligibility?.recommendedVerdict
            || null,
        assuranceLevel: document.assurance?.level
            || document.evaluation?.assuranceLevel
            || null,
        stage: {
            completed: unique(stages),
            final: finalStage,
        },
        activationFacts,
        pluginFacts: pluginFactTokens,
        counts,
        chains: {
            all: chains,
            types: unique(chains.map((chain) => chain.pattern)),
            completeTypes: unique(chains
                .filter((chain) => chain.status === "complete")
                .map((chain) => chain.pattern)),
        },
        scores: {
            severity: maximum(
                findings.map((finding) => finding.severity),
                SEVERITIES,
                "none",
            ),
            confidence: maximum(
                findings.map((finding) => finding.confidence),
                ["none", "low", "medium", "high"],
                "none",
            ),
            projectFit: maximum(
                findings.map((finding) => finding.projectFit),
                ["none", "unknown", "unlikely", "ambiguous", "likely", "strong"],
                "none",
            ),
        },
        tags: unique([
            ...findings.flatMap((finding) => finding.tags),
            ...pluginFactTokens,
        ]),
        blockers,
        failureStage: document.evaluation?.failureStage || inferFailureStage(finalStage),
        failureReason: document.evaluation?.failureReason || null,
    });
}

function legacySnapshot(markdown, { source }) {
    const findings = parseFindings(markdown, { source });
    return Object.freeze({
        sourceFormat: "report-markdown",
        source,
        findings,
        verdict: /\bno\s+red\s+flags\s+found\b/iu.test(markdown)
            ? "no red flags found": null,
        assuranceLevel: null,
        stage: { completed: [], final: null },
        activationFacts: [],
        pluginFacts: [],
        counts: {
            candidate: findings.length,
            validated: 0,
            refuted: 0,
            unresolved: findings.length,
        },
        chains: { all: [], types: [], completeTypes: [] },
        scores: {
            severity: maximum(
                findings.map((finding) => finding.severity),
                SEVERITIES,
                "none",
            ),
            confidence: "none",
            projectFit: "none",
        },
        tags: unique(findings.flatMap((finding) => finding.tags)),
        blockers: [],
        failureStage: null,
        failureReason: null,
    });
}

export function parseAuditArtifacts({
    findingsPath = null,
    reportPath = null,
    findingsJson = null,
    reportMarkdown = null,
    decisionSnapshot = null,
} = {}) {
    if (decisionSnapshot) {
        return parseFindingsJson(decisionSnapshot, { source: "decision-snapshot" });
    }
    if (findingsJson) {
        const document = typeof findingsJson === "string"
            ? JSON.parse(findingsJson): findingsJson;
        return parseFindingsJson(document, {
            source: findingsPath || "FINDINGS.json",
        });
    }
    const inferredFindingsPath = findingsPath
        || (reportPath ? nodePath.join(nodePath.dirname(reportPath), "FINDINGS.json"): null);
    if (inferredFindingsPath && existsSync(inferredFindingsPath)) {
        return parseFindingsJson(
            JSON.parse(readFileSync(inferredFindingsPath, "utf8")),
            { source: inferredFindingsPath },
        );
    }
    const markdown = reportMarkdown
        ?? (reportPath && existsSync(reportPath) ? readFileSync(reportPath, "utf8"): null);
    if (markdown === null) {
        throw new Error("no FINDINGS.json or REPORT.md artifact was available");
    }
    return legacySnapshot(markdown, { source: reportPath || "REPORT.md" });
}

export const __internals = {
    CATEGORY_RE,
    SEVERITY_RE,
    hashEvidence,
    normalizeSeverity,
    parseFileAndLine,
    splitFindingBlocks,
    unique,
    factTokens,
    findingTags,
    normalizeArtifactFinding,
    candidateCount,
    blockerToken,
    inferFailureStage,
    maximum,
    legacySnapshot,
};
