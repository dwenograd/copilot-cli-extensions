// __tests__/corpusRunner.test.mjs
// Pure-logic tests for the local regression corpus harness. Synthetic report
// content uses category-letter prose and generic paths only.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveTags, tagsForCategory } from "../__corpus__/runner/tagDictionary.mjs";
import { parseFindings } from "../__corpus__/runner/parseFindings.mjs";
import { compareFindings, findingMatches, maxSeverity } from "../__corpus__/runner/compareFindings.mjs";
import { classifyFailure, FAILURE_CLASSES } from "../__corpus__/runner/failureClassifier.mjs";
import { dispatchAudit, __internals as dispatchInternals } from "../__corpus__/runner/dispatchAudit.mjs";
import { __internals as runnerInternals } from "../__corpus__/runner/runCorpus.mjs";

function finding(overrides = {}) {
    return {
        severity: "medium",
        category: "B",
        file: "src/foo.js",
        line: 10,
        tags: ["code-execution"],
        evidenceHash: "h1",
        ...overrides,
    };
}

const genericReport = `## Findings

### Category B (code execution): medium finding in src/foo.js
Severity: medium
File: src/foo.js
Line: 10
Tags: code-execution

Generic prose for the finding.
`;

test("tagDictionary derives tags from category letters", () => {
    assert.deepEqual(tagsForCategory("C"), ["credential-store-read", "credential"]);
    assert.ok(tagsForCategory("A").includes("remote-fetch"));
});

test("tagDictionary derives tags from generic words", () => {
    const tags = deriveTags({ category: "E", text: "The report mentions unicode obfuscation in a hidden section." });
    assert.ok(tags.includes("obfuscation"));
});

test("tagDictionary normalizes explicit tags", () => {
    const tags = deriveTags({ category: "G", text: "workflow runner", extraTags: [" CI Workflow ", "hook"] });
    assert.ok(tags.includes("ci-workflow"));
    assert.ok(tags.includes("hook"));
});

test("parseFindings returns no findings for a no-red-flags report", () => {
    assert.deepEqual(parseFindings("# Report\n\nVerdict: no red flags found\n"), []);
});

test("parseFindings parses category, severity, file, line, and tags", () => {
    const findings = parseFindings(genericReport);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].category, "B");
    assert.equal(findings[0].severity, "medium");
    assert.equal(findings[0].file, "src/foo.js");
    assert.equal(findings[0].line, 10);
    assert.ok(findings[0].tags.includes("code-execution"));
});

test("parseFindings parses file:line syntax", () => {
    const findings = parseFindings("### Category A: high finding\nSeverity: high\nLocation: src/net.js:42\nGeneric remote fetch prose.");
    assert.equal(findings[0].file, "src/net.js");
    assert.equal(findings[0].line, 42);
    assert.ok(findings[0].tags.includes("remote-fetch"));
});

test("parseFindings parses multiple category blocks", () => {
    const report = `### Category D: low finding in src/start.js
Severity: low
File: src/start.js
Line: 3

### Category F: medium finding in package.json
Severity: medium
File: package.json
Line: 7
`;
    const findings = parseFindings(report);
    assert.equal(findings.length, 2);
    assert.deepEqual(findings.map((f) => f.category), ["D", "F"]);
});

test("parseFindings hashes evidence and does not expose plain evidence", () => {
    const [parsed] = parseFindings(genericReport);
    assert.match(parsed.evidenceHash, /^[0-9a-f]{64}$/);
    assert.equal(Object.hasOwn(parsed, "evidence"), false);
});

test("findingMatches accepts exact hash match", () => {
    assert.equal(findingMatches(finding(), finding()), true);
});

test("findingMatches accepts small line drift with shared tags", () => {
    const a = finding({ evidenceHash: "left", line: 10 });
    const b = finding({ evidenceHash: "right", line: 14 });
    assert.equal(findingMatches(a, b, { lineTolerance: 5 }), true);
});

test("findingMatches rejects category mismatch", () => {
    assert.equal(findingMatches(finding({ category: "B" }), finding({ category: "E" })), false);
});

test("compareFindings passes when council preserves deterministic finding", () => {
    const result = compareFindings({
        v1Findings: [finding()],
        v2Findings: [finding()],
        expectation: { kind: "risky", expected_min_verdict: "medium" },
    });
    assert.equal(result.status, "PASS");
});

test("compareFindings fails when v1 finding is missing", () => {
    const result = compareFindings({
        v1Findings: [finding()],
        v2Findings: [],
        expectation: { kind: "risky", expected_min_verdict: "none" },
    });
    assert.equal(result.status, "FAIL");
    assert.match(result.failures.join("\n"), /missing v1 finding/);
});

test("compareFindings fails on severity downgrade", () => {
    const result = compareFindings({
        v1Findings: [finding({ severity: "high" })],
        v2Findings: [finding({ severity: "low" })],
        expectation: { kind: "risky", expected_min_verdict: "low" },
        v1Verdict: "high",
        v2Verdict: "low",
    });
    assert.equal(result.status, "FAIL");
    assert.match(result.failures.join("\n"), /downgrade/);
});

test("compareFindings enforces required tags", () => {
    const result = compareFindings({
        v1Findings: [],
        v2Findings: [finding({ category: "E", tags: ["obfuscation"], severity: "medium" })],
        expectation: { kind: "risky", expected_min_verdict: "medium", required_tags: ["obfuscation"] },
    });
    assert.equal(result.status, "PASS");
});

test("compareFindings fails when required tags are absent", () => {
    const result = compareFindings({
        v1Findings: [],
        v2Findings: [finding({ category: "B", tags: ["code-execution"], severity: "medium" })],
        expectation: { kind: "risky", expected_min_verdict: "medium", required_tags: ["obfuscation"] },
    });
    assert.equal(result.status, "FAIL");
});

test("compareFindings fails clean controls with findings above info", () => {
    const result = compareFindings({
        v1Findings: [],
        v2Findings: [finding({ severity: "low" })],
        expectation: { kind: "clean-control", expected_min_verdict: "no red flags found" },
    });
    assert.equal(result.status, "FAIL");
    assert.match(result.failures.join("\n"), /clean control/);
});

test("compareFindings fails forbidden high-severity tags", () => {
    const result = compareFindings({
        v1Findings: [],
        v2Findings: [finding({ severity: "high", tags: ["network"] })],
        expectation: { kind: "risky", expected_min_verdict: "high", forbidden_tags: ["network"] },
    });
    assert.equal(result.status, "FAIL");
    assert.match(result.failures.join("\n"), /forbidden/);
});

test("compareFindings marks incomplete council as inconclusive", () => {
    const result = compareFindings({
        v1Findings: [],
        v2Findings: [],
        expectation: { kind: "risky", expected_min_verdict: "none" },
        councilComplete: false,
    });
    assert.equal(result.status, "INCONCLUSIVE");
    assert.equal(result.passed, false);
});

test("maxSeverity returns the highest finding severity", () => {
    assert.equal(maxSeverity([finding({ severity: "low" }), finding({ severity: "critical" })]), "critical");
});

test("failureClassifier detects rate limits", () => {
    const r = classifyFailure({ stderr: "GitHub API rate limit reached" });
    assert.equal(r.classification, FAILURE_CLASSES.RATELIMIT);
    assert.equal(r.skipped, true);
});

test("failureClassifier detects vanished repositories", () => {
    const r = classifyFailure({ stderr: "HTTP 404 repository not found" });
    assert.equal(r.classification, FAILURE_CLASSES.VANISHED);
    assert.equal(r.skipped, true);
});

test("failureClassifier detects local protection alerts", () => {
    const r = classifyFailure({ stderr: "Defender alert: threat detected and quarantined" });
    assert.equal(r.classification, FAILURE_CLASSES.AV_TRIPPED);
    assert.equal(r.abort, true);
});

test("failureClassifier marks council failure ratio as inconclusive", () => {
    const r = classifyFailure({ councilFailures: 4, councilTotal: 32 });
    assert.equal(r.classification, FAILURE_CLASSES.INCONCLUSIVE);
});

test("failureClassifier marks parse errors as failed execution", () => {
    const r = classifyFailure({ parseError: new Error("report parse failed") });
    assert.equal(r.classification, FAILURE_CLASSES.FAILED_EXECUTION);
});

test("dispatchAudit dry-run plans without subprocess", async () => {
    const r = await dispatchAudit({ url: "https://github.com/octocat/Hello-World", mode: "audit_source", dryRun: true });
    assert.equal(r.ok, true);
    assert.equal(r.planned, true);
});

test("dispatchAudit finds Windows report paths in text", () => {
    const p = dispatchInternals.findReportPath("report written: C:\\work\\_reports\\owner-repo\\REPORT.md");
    assert.equal(p, "C:\\work\\_reports\\owner-repo\\REPORT.md");
});

test("runCorpus registry reads committed clean controls", () => {
    const fixtures = runnerInternals.readUrlRegistry();
    assert.equal(fixtures.length >= 2, true);
    assert.ok(fixtures.every((f) => f.kind === "clean-control"));
});

test("runCorpus parses list columns", () => {
    assert.deepEqual(runnerInternals.parseList("remote-fetch, obfuscation"), ["remote-fetch", "obfuscation"]);
    assert.deepEqual(runnerInternals.parseList(""), []);
});
