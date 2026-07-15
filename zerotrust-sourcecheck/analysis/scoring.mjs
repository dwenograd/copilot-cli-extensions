import { createHash } from "node:crypto";

import {
    ANALYSIS_SCHEMA_VERSION,
    CONFIDENCE_LEVELS,
    MALICIOUS_PROJECT_FIT_LEVELS,
    SEVERITIES,
    validateAuditId,
} from "./schemas.mjs";
import { dedupeFindings } from "./dedupe.mjs";

export const DECISION_SNAPSHOT_LIMITS = Object.freeze({
    blockers: 256,
    rationaleCodes: 256,
});

export const DECISION_COVERAGE_GATES = Object.freeze([
    "acquisitionComplete",
    "indexComplete",
    "pluginCoverageComplete",
    "councilComplete",
    "traceComplete",
    "validationComplete",
    "cacheTrackingComplete",
]);

const SEVERITY_RANK = Object.freeze(Object.fromEntries(
    SEVERITIES.map((severity, index) => [severity, index]),
));
const PROJECT_FIT_RANK = Object.freeze(Object.fromEntries(
    MALICIOUS_PROJECT_FIT_LEVELS.map((level, index) => [level, index]),
));

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function digest(prefix, value) {
    return createHash("sha256")
        .update(prefix, "utf8")
        .update("\0", "utf8")
        .update(canonicalJson(value), "utf8")
        .digest("hex");
}

function unique(values) {
    return [...new Set(values)].sort();
}

function strongest(values, ranks, fallback) {
    return values.reduce((current, value) =>
        ranks[value] > ranks[current] ? value : current, fallback);
}

function bumpConfidence(level, amount = 1) {
    return CONFIDENCE_LEVELS[
        Math.min(CONFIDENCE_LEVELS.length - 1, CONFIDENCE_LEVELS.indexOf(level) + amount)
    ];
}

function countTemplate() {
    return Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
}

function stateCountTemplate() {
    return {
        candidate: 0,
        validating: 0,
        validated: 0,
        refuted: 0,
        unresolved: 0,
    };
}

function scoreFinding(canonicalFinding) {
    const severity = strongest(
        canonicalFinding.observedSeverities,
        SEVERITY_RANK,
        "info",
    );
    const baseConfidence = strongest(
        canonicalFinding.observedConfidences,
        Object.fromEntries(CONFIDENCE_LEVELS.map((level, index) => [level, index])),
        "low",
    );
    const projectFit = strongest(
        canonicalFinding.observedProjectFits,
        PROJECT_FIT_RANK,
        "unknown",
    );
    const rationaleCodes = [
        `impact-max-${severity}`,
        `confidence-base-${baseConfidence}`,
        `project-fit-max-${projectFit}`,
    ];
    let confidence = baseConfidence;
    if (canonicalFinding.provenance.crossValidationCount > 1) {
        confidence = bumpConfidence(confidence);
        rationaleCodes.push("confidence-independent-producers");
    }
    if (canonicalFinding.provenance.independentPathCount > 1) {
        confidence = bumpConfidence(confidence);
        rationaleCodes.push("confidence-independent-paths");
    }
    const trustedValidatedChain = canonicalFinding.stateClass === "validated"
        && canonicalFinding.validatedChainIds.length > 0;
    if (trustedValidatedChain) rationaleCodes.push("validated-complete-chain");
    if (canonicalFinding.stateClass === "validated" && !trustedValidatedChain) {
        confidence = "low";
        rationaleCodes.push("validated-without-complete-chain");
    }
    if (canonicalFinding.stateClass === "unresolved"
        && CONFIDENCE_LEVELS.indexOf(confidence) > CONFIDENCE_LEVELS.indexOf("medium")) {
        confidence = "medium";
        rationaleCodes.push("unresolved-confidence-ceiling");
    }
    if (canonicalFinding.stateClass === "refuted") {
        rationaleCodes.push("refuted-excluded-from-active-verdict");
    }
    return Object.freeze({
        impactSeverity: Object.freeze({
            level: severity,
            rank: SEVERITY_RANK[severity],
        }),
        evidenceConfidence: Object.freeze({
            level: confidence,
            rank: CONFIDENCE_LEVELS.indexOf(confidence),
        }),
        maliciousProjectFitLikelihood: Object.freeze({
            level: projectFit,
            rank: PROJECT_FIT_RANK[projectFit],
        }),
        trustedValidatedChain,
        rationaleCodes: Object.freeze(unique(rationaleCodes)),
    });
}

function normalizeCoverage(value = {}) {
    const normalized = {};
    for (const gate of DECISION_COVERAGE_GATES) normalized[gate] = value[gate] === true;
    return Object.freeze(normalized);
}

function normalizePolicy(value = {}) {
    if (!isPlainObject(value)) throw new TypeError("decision policy must be a plain object");
    const allowed = new Set(["allowNoRedFlagsWithUnresolvedSevere"]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) throw new TypeError(`decision policy.${key} is not allowed`);
    }
    return Object.freeze({
        allowNoRedFlagsWithUnresolvedSevere:
            value.allowNoRedFlagsWithUnresolvedSevere === true,
    });
}

function verdictForSeverity(severity) {
    if (severity === "critical") return "critical";
    if (severity === "high") return "high";
    if (severity === "medium") return "medium";
    return "low";
}

export function scoreCanonicalFinding(canonicalFinding) {
    return scoreFinding(canonicalFinding);
}

export function buildTrustedDecisionSnapshot({
    auditId,
    findings = [],
    traceSnapshot = null,
    validationSnapshot = null,
    dedupeResult = null,
    coverage = {},
    policy = {},
    limits = {},
} = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    const normalizedCoverage = normalizeCoverage(coverage);
    const normalizedPolicy = normalizePolicy(policy);
    const deduped = dedupeResult || dedupeFindings({
        auditId: normalizedAuditId,
        findings,
        traceSnapshot,
        validationSnapshot,
        limits,
    });
    if (deduped.auditId !== normalizedAuditId) {
        throw new Error("dedupe result auditId does not match decision snapshot auditId");
    }

    const canonicalFindings = deduped.canonicalFindings.map((finding) => Object.freeze({
        ...finding,
        scores: scoreFinding(finding),
    }));
    const stateCounts = deduped.stateCounts
        ? { ...stateCountTemplate(), ...deduped.stateCounts }
        : stateCountTemplate();
    const severityCounts = {
        active: countTemplate(),
        trustedValidated: countTemplate(),
        unresolved: countTemplate(),
        refuted: countTemplate(),
    };
    for (const finding of canonicalFindings) {
        const severity = finding.scores.impactSeverity.level;
        if (finding.stateClass === "refuted") {
            severityCounts.refuted[severity] += 1;
            continue;
        }
        severityCounts.active[severity] += 1;
        if (finding.stateClass === "validated" && finding.scores.trustedValidatedChain) {
            severityCounts.trustedValidated[severity] += 1;
        } else {
            severityCounts.unresolved[severity] += 1;
        }
    }

    const blockers = [...deduped.blockers];
    const rationaleCodes = [];
    for (const gate of DECISION_COVERAGE_GATES) {
        if (!normalizedCoverage[gate]) {
            blockers.push({ code: `${gate.replace(/[A-Z]/gu, (match) =>
                `-${match.toLowerCase()}`)}-incomplete` });
            rationaleCodes.push(`gate-incomplete-${gate}`);
        }
    }
    const unresolvedFindings = canonicalFindings.filter((finding) =>
        finding.stateClass !== "refuted"
        && !(finding.stateClass === "validated" && finding.scores.trustedValidatedChain));
    const unresolvedSevere = unresolvedFindings.filter((finding) =>
        SEVERITY_RANK[finding.scores.impactSeverity.level] >= SEVERITY_RANK.high);
    for (const finding of unresolvedSevere) {
        blockers.push({
            code: "unresolved-severe-finding",
            canonicalId: finding.canonicalId,
            severity: finding.scores.impactSeverity.level,
        });
    }
    for (const finding of canonicalFindings.filter((entry) =>
        entry.stateClass === "validated" && !entry.scores.trustedValidatedChain)) {
        blockers.push({
            code: "validated-finding-without-complete-chain",
            canonicalId: finding.canonicalId,
        });
    }
    if (unresolvedFindings.length > 0) {
        rationaleCodes.push("active-untrusted-findings-present");
    }
    if (unresolvedSevere.length > 0) rationaleCodes.push("unresolved-severe-present");
    if (stateCounts.refuted > 0) rationaleCodes.push("refuted-findings-excluded");
    if (deduped.coverageComplete) rationaleCodes.push("dedupe-complete");
    else rationaleCodes.push("dedupe-incomplete");

    const blockerLimit = Number.isSafeInteger(limits.blockers)
        ? Math.max(1, Math.min(limits.blockers, DECISION_SNAPSHOT_LIMITS.blockers))
        : DECISION_SNAPSHOT_LIMITS.blockers;
    const rationaleLimit = Number.isSafeInteger(limits.rationaleCodes)
        ? Math.max(1, Math.min(
            limits.rationaleCodes,
            DECISION_SNAPSHOT_LIMITS.rationaleCodes,
        ))
        : DECISION_SNAPSHOT_LIMITS.rationaleCodes;
    const orderedBlockers = [...new Map(blockers.map((blocker) => [
        canonicalJson(blocker),
        blocker,
    ])).values()].sort((left, right) =>
        canonicalJson(left).localeCompare(canonicalJson(right)));
    const baseRationaleCodes = unique([
        ...rationaleCodes,
        ...canonicalFindings.flatMap((finding) => finding.scores.rationaleCodes),
    ]);
    const outputBoundsComplete = orderedBlockers.length <= blockerLimit
        && baseRationaleCodes.length + 1 <= rationaleLimit;
    const coverageComplete = DECISION_COVERAGE_GATES.every((gate) =>
        normalizedCoverage[gate]) && deduped.coverageComplete && outputBoundsComplete;
    const activeCount = Object.values(severityCounts.active)
        .reduce((sum, count) => sum + count, 0);
    const trustedCount = Object.values(severityCounts.trustedValidated)
        .reduce((sum, count) => sum + count, 0);
    const unresolvedSevereBlocksNoRedFlags = unresolvedSevere.length > 0
        && !normalizedPolicy.allowNoRedFlagsWithUnresolvedSevere;
    const policyAllowsUnresolvedSevereNoRedFlags =
        normalizedPolicy.allowNoRedFlagsWithUnresolvedSevere
        && unresolvedFindings.length > 0
        && unresolvedFindings.length === unresolvedSevere.length
        && unresolvedFindings.length === activeCount;
    const allActiveTrusted = activeCount === trustedCount;
    const noRedFlagsEligible = coverageComplete
        && (activeCount === 0 || policyAllowsUnresolvedSevereNoRedFlags)
        && !unresolvedSevereBlocksNoRedFlags;
    const severityVerdictEligible = coverageComplete
        && activeCount > 0
        && allActiveTrusted;
    const trustedDecisionEligible = noRedFlagsEligible || severityVerdictEligible;
    let recommendedVerdict = "incomplete";
    const eligibleVerdicts = [];
    if (noRedFlagsEligible) {
        recommendedVerdict = "no red flags found";
        eligibleVerdicts.push("no red flags found");
        rationaleCodes.push(activeCount === 0
            ? "no-active-findings"
            : "policy-allows-unresolved-severe-no-red-flags");
    } else if (severityVerdictEligible) {
        const highest = strongest(
            canonicalFindings
                .filter((finding) =>
                    finding.stateClass === "validated"
                    && finding.scores.trustedValidatedChain)
                .map((finding) => finding.scores.impactSeverity.level),
            SEVERITY_RANK,
            "info",
        );
        recommendedVerdict = verdictForSeverity(highest);
        eligibleVerdicts.push(recommendedVerdict);
        rationaleCodes.push(`verdict-highest-impact-${highest}`);
    } else {
        eligibleVerdicts.push("incomplete");
        rationaleCodes.push("trusted-overall-verdict-ineligible");
    }

    const orderedRationaleCodes = unique([
        ...rationaleCodes,
        ...canonicalFindings.flatMap((finding) => finding.scores.rationaleCodes),
    ]);
    const truncation = Object.freeze({
        ...deduped.truncation,
        blockers: deduped.truncation.blockers || orderedBlockers.length > blockerLimit,
        rationaleCodes: orderedRationaleCodes.length > rationaleLimit,
    });
    const boundedBlockers = orderedBlockers.slice(0, blockerLimit);
    const boundedRationaleCodes = orderedRationaleCodes.slice(0, rationaleLimit);
    const inputFingerprint = digest("zerotrust-decision-input-v5", {
        auditId: normalizedAuditId,
        dedupeInputFingerprint: deduped.inputFingerprint,
        coverage: normalizedCoverage,
        policy: normalizedPolicy,
    });
    const decisionId = `ztd-v5-${digest("zerotrust-decision-snapshot-v5", {
        auditId: normalizedAuditId,
        inputFingerprint,
        canonicalFindings,
        stateCounts,
        severityCounts,
        blockers: boundedBlockers,
        overallVerdictEligibility: {
            trustedDecisionEligible,
            noRedFlagsEligible,
            severityVerdictEligible,
            recommendedVerdict,
            eligibleVerdicts,
        },
    })}`;

    return Object.freeze(structuredClone({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: normalizedAuditId,
        decisionId,
        inputFingerprint,
        coverage: normalizedCoverage,
        policy: normalizedPolicy,
        canonicalFindings,
        aliases: canonicalFindings.map((finding) => ({
            canonicalId: finding.canonicalId,
            findingIds: finding.aliases.map((alias) => alias.findingId),
        })),
        stateCounts,
        severityCounts,
        blockers: boundedBlockers,
        overallVerdictEligibility: {
            trustedDecisionEligible,
            noRedFlagsEligible,
            severityVerdictEligible,
            recommendedVerdict,
            eligibleVerdicts,
        },
        rationaleCodes: boundedRationaleCodes,
        truncation,
    }));
}

export const __internals = Object.freeze({
    canonicalJson,
    digest,
    normalizeCoverage,
    normalizePolicy,
    verdictForSeverity,
    scoreFinding,
});
