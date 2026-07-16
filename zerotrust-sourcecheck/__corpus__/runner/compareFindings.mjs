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
export const CONFIDENCE_RANK = Object.freeze({
    none: 0,
    low: 1,
    medium: 2,
    high: 3,
});
export const PROJECT_FIT_RANK = Object.freeze({
    none: 0,
    unknown: 1,
    unlikely: 2,
    ambiguous: 3,
    likely: 4,
    strong: 5,
});

function normalizeSeverity(value) {
    const key = String(value || "info").trim().toLowerCase();
    if (key === "informational") return "info";
    return Object.hasOwn(SEVERITY_RANK, key) ? key: "info";
}

function severityRank(value) {
    return SEVERITY_RANK[normalizeSeverity(value)] ?? 1;
}

export function maxSeverity(findings = []) {
    let best = "none";
    for (const finding of findings) {
        if (severityRank(finding.severity) > severityRank(best)) {
            best = normalizeSeverity(finding.severity);
        }
    }
    return best;
}

function tagsOf(finding) {
    return new Set((finding.tags || []).map((tag) => String(tag).toLowerCase()));
}

function shareTag(left, right) {
    const leftTags = tagsOf(left);
    for (const tag of tagsOf(right)) {
        if (leftTags.has(tag)) return true;
    }
    return false;
}

function sameFile(left, right) {
    if (!left.file || !right.file) return true;
    return String(left.file).toLowerCase() === String(right.file).toLowerCase();
}

function lineClose(left, right, tolerance) {
    if (left.line == null || right.line == null) return true;
    return Math.abs(Number(left.line) - Number(right.line)) <= tolerance;
}

export function findingMatches(left, right, {
    lineTolerance = 5,
    requireEvidenceHash = false,
} = {}) {
    if (!left || !right) return false;
    if (left.category && right.category
        && String(left.category).toUpperCase() !== String(right.category).toUpperCase()) {
        return false;
    }
    if (!sameFile(left, right) || !lineClose(left, right, lineTolerance)) return false;
    const sameHash = left.evidenceHash
        && right.evidenceHash
        && left.evidenceHash === right.evidenceHash;
    if (requireEvidenceHash) return Boolean(sameHash);
    return Boolean(
        sameHash
        || shareTag(left, right)
        || !left.evidenceHash
        || !right.evidenceHash,
    );
}

function isControl(expectation) {
    const kind = String(expectation.kind || "").toLowerCase();
    if (kind.includes("control")) return true;
    return severityRank(
        expectation.expected_min_verdict || expectation.expectedMinVerdict,
    ) <= SEVERITY_RANK.info;
}

function tagPresent(findings, tag) {
    const wanted = String(tag).toLowerCase();
    return findings.some((finding) => tagsOf(finding).has(wanted));
}

function highOrWorseForbidden(findings, forbiddenTags) {
    const forbidden = new Set(
        (forbiddenTags || []).map((tag) => String(tag).toLowerCase()).filter(Boolean),
    );
    if (forbidden.size === 0) return [];
    return findings.filter((finding) =>
        severityRank(finding.severity) >= SEVERITY_RANK.high
        && [...tagsOf(finding)].some((tag) => forbidden.has(tag)));
}

export function compareFindings({
    baselineFindings = [],
    councilFindings = [],
    expectation = {},
    baselineVerdict = null,
    councilVerdict = null,
    councilComplete = true,
    lineTolerance = 5,
    requireEvidenceHash = false,
} = {}) {
    const failures = [];
    const warnings = [];
    const matches = [];
    const missingBaseline = [];

    if (!councilComplete) warnings.push("council incomplete");
    for (const baseline of baselineFindings) {
        const match = councilFindings.find((council) =>
            findingMatches(baseline, council, { lineTolerance, requireEvidenceHash }));
        if (match) matches.push({ baseline, council: match });
        else {
            missingBaseline.push(baseline);
            failures.push(
                `missing baseline finding in council report: category ${baseline.category || "?"} ${baseline.file || "unknown"}`,
            );
        }
    }

    const baselineMax = normalizeSeverity(
        baselineVerdict || maxSeverity(baselineFindings),
    );
    const councilMax = normalizeSeverity(councilVerdict || maxSeverity(councilFindings));
    if (severityRank(councilMax) < severityRank(baselineMax)) {
        failures.push(
            `council severity downgrade: baseline=${baselineMax} council=${councilMax}`,
        );
    }
    const expectedMin = normalizeSeverity(
        expectation.expected_min_verdict || expectation.expectedMinVerdict || "none",
    );
    if (severityRank(councilMax) < severityRank(expectedMin)) {
        failures.push(
            `council verdict below expected minimum: expected ${expectedMin}, got ${councilMax}`,
        );
    }
    for (const tag of expectation.required_tags || expectation.requiredTags || []) {
        if (!tagPresent(councilFindings, tag)) failures.push(`missing required tag: ${tag}`);
    }
    const forbiddenHits = highOrWorseForbidden(
        councilFindings,
        expectation.forbidden_tags || expectation.forbiddenTags || [],
    );
    for (const hit of forbiddenHits) {
        failures.push(`forbidden high-severity tag present: ${hit.category || "?"} ${hit.file || "unknown"}`);
    }
    if (isControl(expectation)) {
        for (const [label, findings] of [
            ["baseline", baselineFindings],
            ["council", councilFindings],
        ]) {
            for (const finding of findings) {
                if (severityRank(finding.severity) > SEVERITY_RANK.info) {
                    failures.push(
                        `clean control ${label} has finding above info: ${finding.category || "?"} ${finding.file || "unknown"}`,
                    );
                }
            }
        }
    }
    const status = warnings.includes("council incomplete") && failures.length === 0
        ? "INCONCLUSIVE": failures.length === 0 ? "PASS": "FAIL";
    return {
        passed: status === "PASS",
        status,
        failures,
        warnings,
        matches,
        missingBaseline,
        summary: {
            baselineCount: baselineFindings.length,
            councilCount: councilFindings.length,
            baselineMax,
            councilMax,
        },
    };
}

function inRange(value, range, ranks) {
    const rank = ranks[value];
    return Number.isInteger(rank)
        && rank >= ranks[range.min]
        && rank <= ranks[range.max];
}

function countInRange(value, range) {
    return Number.isSafeInteger(value) && value >= range.min && value <= range.max;
}

function missingTokens(actual, required) {
    const present = new Set(actual || []);
    return (required || []).filter((token) => !present.has(token));
}

function unexpectedBlockers(actual, acceptable) {
    const allowed = new Set(acceptable || []);
    return (actual || []).filter((blocker) => !allowed.has(blocker));
}

export function compareEvaluation(actual, expectation) {
    const expected = expectation.expected || expectation;
    const failures = [];
    const warnings = [];
    for (const stage of expected.stage.required) {
        if (!actual.stage.completed.includes(stage)) {
            failures.push(`required stage not completed: ${stage}`);
        }
    }
    if (actual.stage.final !== expected.stage.final) {
        failures.push(
            `final stage mismatch: expected ${expected.stage.final}, got ${actual.stage.final || "none"}`,
        );
    }

    for (const [label, actualFacts, factExpectation] of [
        ["activation", actual.activationFacts, expected.activation_facts],
        ["plugin", actual.pluginFacts, expected.plugin_facts],
    ]) {
        if (actualFacts.length < factExpectation.minimum) {
            failures.push(
                `${label} fact count below minimum: expected ${factExpectation.minimum}, got ${actualFacts.length}`,
            );
        }
        for (const token of missingTokens(actualFacts, factExpectation.required)) {
            failures.push(`missing required ${label} fact: ${token}`);
        }
    }

    for (const key of ["candidate", "validated", "refuted", "unresolved"]) {
        if (!countInRange(actual.counts[key], expected.counts[key])) {
            failures.push(
                `${key} count outside expected range ${expected.counts[key].min}-${expected.counts[key].max}: ${actual.counts[key]}`,
            );
        }
    }
    for (const chain of expected.chains.required) {
        if (!actual.chains.types.includes(chain)) failures.push(`missing required chain type: ${chain}`);
    }
    for (const chain of expected.chains.complete_required) {
        if (!actual.chains.completeTypes.includes(chain)) {
            failures.push(`missing required complete chain type: ${chain}`);
        }
    }
    for (const chain of expected.chains.forbidden) {
        if (actual.chains.types.includes(chain)) failures.push(`forbidden chain type present: ${chain}`);
    }

    for (const [key, ranks] of [
        ["severity", SEVERITY_RANK],
        ["confidence", CONFIDENCE_RANK],
        ["project_fit", PROJECT_FIT_RANK],
    ]) {
        const actualKey = key === "project_fit" ? "projectFit": key;
        if (!inRange(actual.scores[actualKey], expected.scores[key], ranks)) {
            failures.push(
                `${key} outside expected range ${expected.scores[key].min}-${expected.scores[key].max}: ${actual.scores[actualKey]}`,
            );
        }
    }
    for (const token of missingTokens(actual.tags, expected.tags.required)) {
        failures.push(`missing required tag: ${token}`);
    }
    for (const token of expected.tags.forbidden) {
        if (actual.tags.includes(token)) failures.push(`forbidden tag present: ${token}`);
    }
    for (const blocker of unexpectedBlockers(
        actual.blockers,
        expected.acceptable_blockers,
    )) {
        failures.push(`unexpected blocker: ${blocker}`);
    }
    if (actual.failureStage !== expected.failure_stage) {
        failures.push(
            `failure stage mismatch: expected ${expected.failure_stage || "none"}, got ${actual.failureStage || "none"}`,
        );
    }

    const status = failures.length === 0 ? "PASS": "FAIL";
    return {
        passed: status === "PASS",
        status,
        failures,
        warnings,
        actual,
        observations: {
            expectedActivationFacts: expected.activation_facts.required.length,
            matchedActivationFacts: expected.activation_facts.required.length
                - missingTokens(actual.activationFacts, expected.activation_facts.required).length,
            expectedCandidates: expected.counts.candidate.min,
            matchedCandidates: Math.min(actual.counts.candidate, expected.counts.candidate.min),
            expectedCompleteChains: expected.chains.complete_required.length,
            matchedCompleteChains: expected.chains.complete_required.filter((chain) =>
                actual.chains.completeTypes.includes(chain)).length,
            expectedValidated: expected.counts.validated.min,
            matchedValidated: Math.min(actual.counts.validated, expected.counts.validated.min),
            expectedRefuted: expected.counts.refuted.min,
            matchedRefuted: Math.min(actual.counts.refuted, expected.counts.refuted.min),
        },
    };
}

export const __internals = {
    normalizeSeverity,
    severityRank,
    isControl,
    tagPresent,
    highOrWorseForbidden,
    inRange,
    countInRange,
    missingTokens,
    unexpectedBlockers,
};
