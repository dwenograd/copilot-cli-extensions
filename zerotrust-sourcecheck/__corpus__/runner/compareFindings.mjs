// __corpus__/runner/compareFindings.mjs
// Acceptance-gate comparison between deterministic and council reports.

export const SEVERITY_RANK = Object.freeze({
    none: 0,
    "no red flags found": 0,
    info: 1,
    informational: 1,
    low: 2,
    medium: 3,
    high: 4,
    critical: 5,
});

function normalizeSeverity(s) {
    const key = String(s || "info").trim().toLowerCase();
    if (key === "informational") return "info";
    return Object.hasOwn(SEVERITY_RANK, key) ? key : "info";
}

function severityRank(s) {
    return SEVERITY_RANK[normalizeSeverity(s)] ?? 1;
}

export function maxSeverity(findings = []) {
    let best = "none";
    for (const f of findings) {
        if (severityRank(f.severity) > severityRank(best)) best = normalizeSeverity(f.severity);
    }
    return best;
}

function tagsOf(finding) {
    return new Set((finding.tags || []).map((t) => String(t).toLowerCase()));
}

function shareTag(a, b) {
    const aTags = tagsOf(a);
    for (const tag of tagsOf(b)) {
        if (aTags.has(tag)) return true;
    }
    return false;
}

function sameFile(a, b) {
    if (!a.file || !b.file) return true;
    return String(a.file).toLowerCase() === String(b.file).toLowerCase();
}

function lineClose(a, b, tolerance) {
    if (a.line == null || b.line == null) return true;
    return Math.abs(Number(a.line) - Number(b.line)) <= tolerance;
}

export function findingMatches(a, b, { lineTolerance = 5, requireEvidenceHash = false } = {}) {
    if (!a || !b) return false;
    if (a.category && b.category && String(a.category).toUpperCase() !== String(b.category).toUpperCase()) return false;
    if (!sameFile(a, b)) return false;
    if (!lineClose(a, b, lineTolerance)) return false;

    const sameHash = a.evidenceHash && b.evidenceHash && a.evidenceHash === b.evidenceHash;
    if (requireEvidenceHash) return Boolean(sameHash);
    return Boolean(sameHash || shareTag(a, b) || !a.evidenceHash || !b.evidenceHash);
}

function isControl(expectation) {
    const kind = String(expectation.kind || "").toLowerCase();
    if (kind.includes("control")) return true;
    return severityRank(expectation.expected_min_verdict || expectation.expectedMinVerdict) <= SEVERITY_RANK.info;
}

function tagPresent(findings, tag) {
    const wanted = String(tag).toLowerCase();
    return findings.some((f) => tagsOf(f).has(wanted));
}

function highOrWorseForbidden(findings, forbiddenTags) {
    const forbidden = new Set((forbiddenTags || []).map((t) => String(t).toLowerCase()).filter(Boolean));
    if (forbidden.size === 0) return [];
    return findings.filter((f) => severityRank(f.severity) >= SEVERITY_RANK.high && [...tagsOf(f)].some((t) => forbidden.has(t)));
}

export function compareFindings({
    v1Findings = [],
    v2Findings = [],
    expectation = {},
    v1Verdict = null,
    v2Verdict = null,
    councilComplete = true,
    lineTolerance = 5,
    requireEvidenceHash = false,
} = {}) {
    const failures = [];
    const warnings = [];
    const matches = [];
    const missingV1 = [];

    if (!councilComplete) {
        warnings.push("council incomplete");
    }

    for (const v1 of v1Findings) {
        const match = v2Findings.find((v2) => findingMatches(v1, v2, { lineTolerance, requireEvidenceHash }));
        if (match) {
            matches.push({ v1, v2: match });
        } else {
            missingV1.push(v1);
            failures.push(`missing v1 finding in council report: category ${v1.category || "?"} ${v1.file || "unknown"}`);
        }
    }

    const v1Max = normalizeSeverity(v1Verdict || maxSeverity(v1Findings));
    const v2Max = normalizeSeverity(v2Verdict || maxSeverity(v2Findings));
    if (severityRank(v2Max) < severityRank(v1Max)) {
        failures.push(`council severity downgrade: v1=${v1Max} v2=${v2Max}`);
    }

    const expectedMin = normalizeSeverity(expectation.expected_min_verdict || expectation.expectedMinVerdict || "none");
    if (severityRank(v2Max) < severityRank(expectedMin)) {
        failures.push(`council verdict below expected minimum: expected ${expectedMin}, got ${v2Max}`);
    }

    const requiredTags = expectation.required_tags || expectation.requiredTags || [];
    for (const tag of requiredTags) {
        if (!tagPresent(v2Findings, tag)) failures.push(`missing required tag: ${tag}`);
    }

    const forbiddenTags = expectation.forbidden_tags || expectation.forbiddenTags || [];
    const forbiddenHits = highOrWorseForbidden(v2Findings, forbiddenTags);
    for (const hit of forbiddenHits) {
        failures.push(`forbidden high-severity tag present: ${hit.category || "?"} ${hit.file || "unknown"}`);
    }

    if (isControl(expectation)) {
        for (const [label, findings] of [["v1", v1Findings], ["v2", v2Findings]]) {
            for (const f of findings) {
                if (severityRank(f.severity) > SEVERITY_RANK.info) {
                    failures.push(`clean control ${label} has finding above info: ${f.category || "?"} ${f.file || "unknown"}`);
                }
            }
        }
    }

    const status = warnings.includes("council incomplete") && failures.length === 0
        ? "INCONCLUSIVE"
        : failures.length === 0 ? "PASS" : "FAIL";

    return {
        passed: status === "PASS",
        status,
        failures,
        warnings,
        matches,
        missingV1,
        summary: {
            v1Count: v1Findings.length,
            v2Count: v2Findings.length,
            v1Max,
            v2Max,
        },
    };
}

export const __internals = {
    normalizeSeverity,
    severityRank,
    isControl,
    tagPresent,
    highOrWorseForbidden,
};

