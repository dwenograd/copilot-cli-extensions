// __tests__/corpusRunner.test.mjs
// Pure-logic tests for the local regression corpus harness. Synthetic report
// content uses category-letter prose and generic paths only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import nodePath from "node:path";

import { deriveTags, tagsForCategory } from "../__corpus__/runner/tagDictionary.mjs";
import {
    parseAuditArtifacts,
    parseFindings,
    parseFindingsJson,
} from "../__corpus__/runner/parseFindings.mjs";
import {
    compareEvaluation,
    compareFindings,
    findingMatches,
    maxSeverity,
} from "../__corpus__/runner/compareFindings.mjs";
import {
    classifyFailure,
    classifyStageFailure,
    FAILURE_CLASSES,
} from "../__corpus__/runner/failureClassifier.mjs";
import { dispatchAudit, __internals as dispatchInternals } from "../__corpus__/runner/dispatchAudit.mjs";
import {
    EXPECTATION_SCHEMA,
    validateExpectation,
} from "../__corpus__/runner/expectationSchema.mjs";
import {
    executeLocalFixture,
    __internals as localExecutorInternals,
} from "../__corpus__/runner/localFixtureExecutor.mjs";
import {
    calculateMetrics,
    evaluateQualityGate,
} from "../__corpus__/runner/metrics.mjs";
import {
    main as runCorpus,
    __internals as runnerInternals,
} from "../__corpus__/runner/runCorpus.mjs";

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
        baselineFindings: [finding()],
        councilFindings: [finding()],
        expectation: { kind: "risky", expected_min_verdict: "medium" },
    });
    assert.equal(result.status, "PASS");
});

test("compareFindings fails when baseline finding is missing", () => {
    const result = compareFindings({
        baselineFindings: [finding()],
        councilFindings: [],
        expectation: { kind: "risky", expected_min_verdict: "none" },
    });
    assert.equal(result.status, "FAIL");
    assert.match(result.failures.join("\n"), /missing baseline finding/);
});

test("compareFindings fails on severity downgrade", () => {
    const result = compareFindings({
        baselineFindings: [finding({ severity: "high" })],
        councilFindings: [finding({ severity: "low" })],
        expectation: { kind: "risky", expected_min_verdict: "low" },
        baselineVerdict: "high",
        councilVerdict: "low",
    });
    assert.equal(result.status, "FAIL");
    assert.match(result.failures.join("\n"), /downgrade/);
});

test("compareFindings enforces required tags", () => {
    const result = compareFindings({
        baselineFindings: [],
        councilFindings: [finding({ category: "E", tags: ["obfuscation"], severity: "medium" })],
        expectation: { kind: "risky", expected_min_verdict: "medium", required_tags: ["obfuscation"] },
    });
    assert.equal(result.status, "PASS");
});

test("compareFindings fails when required tags are absent", () => {
    const result = compareFindings({
        baselineFindings: [],
        councilFindings: [finding({ category: "B", tags: ["code-execution"], severity: "medium" })],
        expectation: { kind: "risky", expected_min_verdict: "medium", required_tags: ["obfuscation"] },
    });
    assert.equal(result.status, "FAIL");
});

test("compareFindings fails clean controls with findings above info", () => {
    const result = compareFindings({
        baselineFindings: [],
        councilFindings: [finding({ severity: "low" })],
        expectation: { kind: "clean-control", expected_min_verdict: "no red flags found" },
    });
    assert.equal(result.status, "FAIL");
    assert.match(result.failures.join("\n"), /clean control/);
});

test("compareFindings fails forbidden high-severity tags", () => {
    const result = compareFindings({
        baselineFindings: [],
        councilFindings: [finding({ severity: "high", tags: ["network"] })],
        expectation: { kind: "risky", expected_min_verdict: "high", forbidden_tags: ["network"] },
    });
    assert.equal(result.status, "FAIL");
    assert.match(result.failures.join("\n"), /forbidden/);
});

test("compareFindings marks incomplete council as inconclusive", () => {
    const result = compareFindings({
        baselineFindings: [],
        councilFindings: [],
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
    const canonical = `zt-${"a".repeat(64)}`;
    const p = dispatchInternals.findReportPath(`report written: C:\\work\\_reports\\${canonical}\\REPORT.md`);
    assert.equal(p, `C:\\work\\_reports\\${canonical}\\REPORT.md`);
});

test("dispatchAudit finds POSIX and JSON artifact paths", () => {
    assert.equal(
        dispatchInternals.findReportPath("report written: /work/_reports/sample/REPORT.md"),
        "/work/_reports/sample/REPORT.md",
    );
    assert.equal(
        dispatchInternals.findFindingsPath('{"findingsPath":"/work/_reports/sample/FINDINGS.json"}'),
        "/work/_reports/sample/FINDINGS.json",
    );
    assert.equal(
        dispatchInternals.siblingArtifactPath("C:\\work\\sample\\REPORT.md", "FINDINGS.json"),
        "C:\\work\\sample\\FINDINGS.json",
    );
    assert.equal(
        dispatchInternals.siblingArtifactPath("/work/sample/REPORT.md", "FINDINGS.json"),
        "/work/sample/FINDINGS.json",
    );
});

test("dispatchAudit refuses live work without the explicit environment gate", async () => {
    const result = await dispatchAudit({
        url: "https://github.com/octocat/Hello-World",
        mode: "audit_source",
        env: {},
    });
    assert.equal(result.ok, false);
    assert.match(result.stderr, /ZEROTRUST_CORPUS_LIVE=1/u);
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

test("expectation schema is unversioned and rejects traversal or unknown fields", () => {
    const expectation = runnerInternals.loadExpectation("local-clean-control");
    assert.equal(expectation.schema, EXPECTATION_SCHEMA);
    assert.throws(() => validateExpectation({
            ...expectation,
            source: { type: "local", path: "../outside" },
        }),
        /inside the corpus root/u,
    );
    assert.throws(() => validateExpectation({ ...expectation, extra: true }),
        /not allowed/u,
    );
});

test("registry includes local clean, benign, risky, incomplete, and broken fixtures", () => {
    const expectations = runnerInternals.loadExpectations();
    assert.equal(expectations.length >= 33, true);
    assert.ok(expectations.some((entry) => entry.kind === "clean-control"));
    assert.ok(expectations.some((entry) => entry.kind === "benign-lookalike"));
    assert.ok(expectations.some((entry) => entry.kind === "synthetic-risk"));
    assert.ok(expectations.some((entry) => entry.kind === "synthetic-incomplete"));
    assert.ok(expectations.some((entry) => entry.kind === "synthetic-broken"));
    assert.ok(expectations.some((entry) =>
        entry.dimensions.evasion_classes.length > 0));
});

test("all local fixtures are printable inert marker declarations", () => {
    for (const expectation of runnerInternals.loadExpectations()
        .filter((entry) => entry.source.type === "local")) {
        const root = nodePath.resolve(
            runnerInternals.CORPUS_ROOT,
            expectation.source.path,
        );
        for (const file of localExecutorInternals.walkFiles(root)) {
            const text = readFileSync(file, "utf8");
            const relative = nodePath.relative(root, file).replace(/\\/gu, "/");
            const markers = localExecutorInternals.validateFixtureText(text, relative);
            assert.ok(markers.length >= 1);
            assert.doesNotMatch(text, /https?:|data:|file:/iu);
        }
    }
});

test("local deterministic executor covers index, plugin, graph, scoring, and expectations", () => {
    const results = [];
    const chainTypes = new Set();
    for (const expectation of runnerInternals.loadExpectations()
        .filter((entry) => entry.source.type === "local")) {
        const document = executeLocalFixture({
            fixtureRoot: nodePath.resolve(
                runnerInternals.CORPUS_ROOT,
                expectation.source.path,
            ),
            slug: expectation.slug,
        });
        const actual = parseFindingsJson(document);
        const comparison = compareEvaluation(actual, expectation);
        assert.equal(
            comparison.status,
            "PASS",
            `${expectation.slug}: ${comparison.failures.join("; ")}`,
        );
        for (const chain of actual.chains.types) chainTypes.add(chain);
        results.push({ expectation, comparison });
    }
    assert.deepEqual(
        [...chainTypes].sort(),
        [
            "ai-instruction-tool-effect",
            "behavior-chain",
            "ci-trigger-secret-external-sink",
            "credential-read-transform-send",
            "install-fetch-decode-execute",
            "startup-persistence",
        ],
    );
    const metrics = calculateMetrics(results);
    assert.equal(metrics.activationRecall, 1);
    assert.equal(metrics.candidateRecall, 1);
    assert.equal(metrics.completeChainRecall, 1);
    assert.equal(metrics.validationRefutationAccuracy, 1);
    assert.equal(metrics.falsePositiveRate, 0);
    assert.ok(metrics.unresolvedRate > 0 && metrics.unresolvedRate < 0.2);
    assert.equal(
        evaluateQualityGate(
            metrics,
            runnerInternals.loadQualityThresholds(),
        ).passed,
        true,
    );
});

test("synthetic complete chain shapes are cross-file", () => {
    for (const slug of [
        "activation-fetch-transform-effect",
        "credential-transform-sink",
        "startup-persistence",
        "ci-secret-external",
        "ai-instruction-tool-effect",
    ]) {
        const expectation = runnerInternals.loadExpectation(slug);
        const document = executeLocalFixture({
            fixtureRoot: nodePath.resolve(
                runnerInternals.CORPUS_ROOT,
                expectation.source.path,
            ),
            slug,
        });
        assert.ok(document.graph.chains.some((chain) =>
            chain.status === "complete" && chain.crossFile));
    }
});

test("broken fixture reports a prepare failure and acceptable blocker", () => {
    const expectation = runnerInternals.loadExpectation("broken-reference");
    const document = executeLocalFixture({
        fixtureRoot: nodePath.resolve(
            runnerInternals.CORPUS_ROOT,
            expectation.source.path,
        ),
        slug: expectation.slug,
    });
    const actual = parseFindingsJson(document);
    assert.equal(actual.failureStage, "prepare");
    assert.deepEqual(actual.blockers, ["plugin-failed"]);
    assert.equal(compareEvaluation(actual, expectation).status, "PASS");
});

test("FINDINGS.json is primary and REPORT.md remains a legacy fallback", () => {
    const expectation = runnerInternals.loadExpectation("local-clean-control");
    const document = executeLocalFixture({
        fixtureRoot: nodePath.resolve(
            runnerInternals.CORPUS_ROOT,
            expectation.source.path,
        ),
        slug: expectation.slug,
    });
    const primary = parseAuditArtifacts({
        findingsJson: document,
        reportMarkdown: genericReport,
    });
    assert.equal(primary.sourceFormat, "findings-json");
    assert.equal(primary.findings.length, 0);
    const fallback = parseAuditArtifacts({ reportMarkdown: genericReport });
    assert.equal(fallback.sourceFormat, "report-markdown");
    assert.equal(fallback.findings.length, 1);
});

test("decision snapshots are accepted as evaluation inputs", () => {
    const expectation = runnerInternals.loadExpectation("startup-persistence");
    const document = executeLocalFixture({
        fixtureRoot: nodePath.resolve(
            runnerInternals.CORPUS_ROOT,
            expectation.source.path,
        ),
        slug: expectation.slug,
    });
    const parsed = parseAuditArtifacts({ decisionSnapshot: document.decision });
    assert.equal(parsed.sourceFormat, "decision-snapshot");
    assert.equal(parsed.counts.validated, 1);
    assert.equal(parsed.scores.severity, "high");
});

test("stage failure classification covers prepare through finalize", () => {
    const cases = [
        ["acquired", "prepare", FAILURE_CLASSES.PREPARE_FAILED],
        ["prepared", "scan", FAILURE_CLASSES.SCAN_FAILED],
        ["scanned", "trace", FAILURE_CLASSES.TRACE_FAILED],
        ["traced", "validate", FAILURE_CLASSES.VALIDATE_FAILED],
        ["validated", "finalize", FAILURE_CLASSES.FINALIZE_FAILED],
    ];
    for (const [finalStage, stage, classification] of cases) {
        const result = classifyStageFailure({
            finalStage,
            blockers: [{ code: `${stage}-blocker` }],
        });
        assert.equal(result.stage, stage);
        assert.equal(result.classification, classification);
        assert.match(result.reason, new RegExp(stage, "u"));
    }
});

test("dry-run validates local fixtures without writing corpus results", async () => {
    const resultsDir = runnerInternals.RESULTS_DIR;
    const before = existsSync(resultsDir) ? readdirSync(resultsDir).sort(): [];
    assert.equal(await runCorpus(["--dry-run", "--quality-gate"]), 0);
    const after = existsSync(resultsDir) ? readdirSync(resultsDir).sort(): [];
    assert.deepEqual(after, before);
});
