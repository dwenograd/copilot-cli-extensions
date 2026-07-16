import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import nodePath from "node:path";

export function pathsEqual(left, right) {
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase(): a === b;
}

export function fileIdentity(path) {
    const bytes = readFileSync(path);
    return {
        bytes: bytes.byteLength,
        sha256: createHash("sha256").update(bytes).digest("hex"),
    };
}

export function finalizedReportMatchesAudit(record, audit) {
    if (!record || !audit || record.auditId !== audit.auditId) return false;
    const identity = record.reportIdentity;
    if (!identity || identity.sourceKind !== "url") return false;
    const expectedDirectoryMatches = !audit.expectedReportPath
        || (pathsEqual(nodePath.dirname(record.reportPath), audit.expectedReportPath)
            && pathsEqual(nodePath.dirname(record.findingsPath), audit.expectedReportPath));
    return expectedDirectoryMatches
        && String(identity.owner || "").toLowerCase() === audit.owner
        && String(identity.repo || "").toLowerCase() === audit.repo
        && identity.resolvedSha === audit.resolvedSha;
}

export function evaluateFinalizedReportExecutionGate(record, audit) {
    if (!record) {
        return {
            passes: false,
            reason:
                "a durable canonical REPORT.md + FINDINGS.json finalization record is required before hazardous post-audit host execution",
        };
    }
    if (!finalizedReportMatchesAudit(record, audit)) {
        return {
            passes: false,
            reason: "the finalized report record does not match the active audit identity",
        };
    }
    const artifactPaths = [record.reportPath, record.findingsPath];
    if (artifactPaths.some((path) =>
        typeof path !== "string" || !nodePath.isAbsolute(path) || !existsSync(path))) {
        return { passes: false, reason: "a finalized report artifact is missing" };
    }
    let reportIdentity;
    let findingsIdentity;
    try {
        reportIdentity = fileIdentity(record.reportPath);
        findingsIdentity = fileIdentity(record.findingsPath);
    } catch (error) {
        return {
            passes: false,
            reason: `finalized report artifact verification failed: ${error.message}`,
        };
    }
    if (reportIdentity.sha256 !== record.contentSha256
        || reportIdentity.bytes !== record.bytesWritten
        || findingsIdentity.sha256 !== record.findingsSha256
        || findingsIdentity.bytes !== record.findingsBytesWritten) {
        return {
            passes: false,
            reason: "the finalized report pair no longer matches its durable hashes",
        };
    }
    if (record.stageFinalized !== true) {
        return {
            passes: false,
            reason: "the report pair exists but validated -> finalized has not completed",
        };
    }
    const outcome = record.trustedOutcome;
    if (!outcome || outcome.trusted !== true) {
        return {
            passes: false,
            reason: "the finalized report does not contain a finalizer-derived trusted outcome",
        };
    }
    if (record.flow === "trusted-ledger"
        && (outcome.schemaVersion !== 5 || outcome.assurance != null)) {
        return {
            passes: false,
            reason: "the baseline report outcome does not match the baseline analysis report contract",
        };
    }
    if (record.flow === "evasive-assurance"
        && outcome.schemaVersion !== 6) {
        return {
            passes: false,
            reason: "the assurance report outcome does not match the assurance report contract",
        };
    }
    if (record.flow !== "evasive-assurance") {
        return {
            passes: false,
            reason:
                "host execution requires the finalized evasive-assurance flow; baseline and compatibility reports are not eligible",
        };
    }
    if (outcome.complete !== true) {
        return { passes: false, reason: "the finalized findings outcome is incomplete" };
    }
    if (outcome.assurance?.complete !== true
        || ["unsupported", "partial"].includes(outcome.assurance?.level)) {
        return {
            passes: false,
            reason:
                `assurance is incomplete (${outcome.assurance?.level || "missing"})`,
        };
    }
    const critical = outcome.severityCounts?.critical || 0;
    const high = outcome.severityCounts?.high || 0;
    if (critical > 0
        || high > 0
        || outcome.verdict === "critical"
        || outcome.verdict === "high") {
        return {
            passes: false,
            reason:
                `supported critical/high malicious behavior blocks host execution (verdict=${outcome.verdict}, critical=${critical}, high=${high})`,
        };
    }
    return {
        passes: true,
        reason:
            `identity-matching finalized assurance report accepted (verdict=${outcome.verdict}; assurance=${outcome.assurance.level})`,
    };
}
