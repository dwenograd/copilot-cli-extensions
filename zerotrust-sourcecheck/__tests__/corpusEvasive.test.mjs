import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import nodePath from "node:path";

import { EVASION_CLASS_VALUES } from "../analysis/assurance.mjs";
import {
    executeLocalFixture,
    __internals as executorInternals,
} from "../__corpus__/runner/localFixtureExecutor.mjs";
import {
    applyMetamorphicTransforms,
    METAMORPHIC_TRANSFORMS,
} from "../__corpus__/runner/metamorphicTransforms.mjs";
import {
    calculateMetrics,
    evaluateQualityGate,
} from "../__corpus__/runner/metrics.mjs";
import { parseFindingsJson } from "../__corpus__/runner/parseFindings.mjs";
import { compareEvaluation } from "../__corpus__/runner/compareFindings.mjs";
import {
    ARTIFACT_CLASSES,
    LANGUAGE_CLASSES,
    validateExpectation,
} from "../__corpus__/runner/expectationSchema.mjs";
import {
    __internals as runnerInternals,
} from "../__corpus__/runner/runCorpus.mjs";

function executeExpectation(expectation, transforms = []) {
    const document = executeLocalFixture({
        fixtureRoot: nodePath.resolve(
            runnerInternals.CORPUS_ROOT,
            expectation.source.path,
        ),
        slug: expectation.slug,
        transforms,
    });
    const actual = parseFindingsJson(document);
    return {
        expectation,
        document,
        comparison: compareEvaluation(actual, expectation),
    };
}

test("evasive corpus covers every mandatory assurance evasion class", () => {
    const expectations = runnerInternals.loadExpectations();
    const covered = new Set(expectations.flatMap((entry) =>
        entry.dimensions.evasion_classes));
    assert.deepEqual([...covered].sort(), [...EVASION_CLASS_VALUES].sort());
    assert.deepEqual(
        [...runnerInternals.loadQualityThresholds()
            .mandatory_evasion_classes].sort(),
        [...EVASION_CLASS_VALUES].sort(),
    );
});

test("evasive corpus dimensions cover multiple artifacts, languages, and sizes", () => {
    const expectations = runnerInternals.loadExpectations();
    const artifacts = new Set(expectations.flatMap((entry) =>
        entry.dimensions.artifact_classes));
    const languages = new Set(expectations.flatMap((entry) =>
        entry.dimensions.languages));
    const sizes = new Set(expectations.map((entry) => entry.dimensions.size)
        .filter(Boolean));
    for (const artifact of [
        "source-text",
        "generated-source",
        "submodule",
        "lfs-pointer",
        "archive",
        "binary",
        "release-asset",
    ]) {
        assert.ok(ARTIFACT_CLASSES.includes(artifact));
        assert.ok(artifacts.has(artifact));
    }
    for (const language of [
        "javascript",
        "python",
        "rust",
        "csharp",
        "msbuild",
        "git",
        "go",
        "generic",
    ]) {
        assert.ok(LANGUAGE_CLASSES.includes(language));
        assert.ok(languages.has(language));
    }
    assert.deepEqual([...sizes].sort(), ["medium", "small"]);
});

test("dimension metadata rejects unknown grouping or transform values", () => {
    const expectation = runnerInternals.loadExpectation(
        "evasive-string-splitting-encoding",
    );
    assert.throws(() => validateExpectation({
            ...expectation,
            dimensions: {
                ...expectation.dimensions,
                artifact_classes: ["unknown-artifact"],
            },
        }),
        /unsupported value/u,
    );
    assert.throws(() => validateExpectation({
            ...expectation,
            dimensions: {
                ...expectation.dimensions,
                metamorphic_transforms: ["unknown-transform"],
            },
        }),
        /unsupported value/u,
    );
});

test("joined inert strings parse to the same generic marker arguments", () => {
    const marker = executorInternals.parseMarkerLine(
        'marker.fact("literal"+"-fragments", "display"+"-label", "string"+"-split");',
        { path: "fixture.ztfixture", lineNumber: 1 },
    );
    assert.deepEqual(marker.args, [
        "literal-fragments",
        "display-label",
        "string-split",
    ]);
});

test("metamorphic transforms are deterministic and remain inert", () => {
    const expectation = runnerInternals.loadExpectation(
        "evasive-string-splitting-encoding",
    );
    const root = nodePath.resolve(
        runnerInternals.CORPUS_ROOT,
        expectation.source.path,
    );
    const documents = executorInternals.fixtureDocuments(root);
    const first = applyMetamorphicTransforms(documents, METAMORPHIC_TRANSFORMS);
    const second = applyMetamorphicTransforms(documents, METAMORPHIC_TRANSFORMS);
    assert.deepEqual(first, second);
    assert.ok(first.every((document) => document.path.startsWith("relocated/")));
    assert.ok(first.some((document) => document.text.includes("marker.comment(")));
    assert.ok(first.some((document) => document.text.includes('" + "')));
    for (const document of first) {
        assert.ok(executorInternals.validateFixtureText(
            document.text,
            document.path,
        ).length > 0);
    }
});

test("metamorphic variants preserve expected corpus behavior", () => {
    for (const slug of [
        "evasive-string-splitting-encoding",
        "evasive-cross-file-source-transform-sink",
        "evasive-dormant-gates",
        "evasive-generated-code-hook",
        "evasive-prompt-comments",
        "evasive-alternate-path",
    ]) {
        const expectation = runnerInternals.loadExpectation(slug);
        for (const transform of expectation.dimensions.metamorphic_transforms) {
            const result = executeExpectation(expectation, [transform]);
            assert.equal(
                result.comparison.status,
                "PASS",
                `${slug}/${transform}: ${result.comparison.failures.join("; ")}`,
            );
        }
    }
    const combinedExpectation = runnerInternals.loadExpectation(
        "evasive-string-splitting-encoding",
    );
    const combined = executeExpectation(
        combinedExpectation,
        combinedExpectation.dimensions.metamorphic_transforms,
    );
    assert.equal(
        combined.comparison.status,
        "PASS",
        combined.comparison.failures.join("; "),
    );
});

test("cross-file and alternate-path fixtures retain complete risky chains", () => {
    const crossFile = executeExpectation(runnerInternals.loadExpectation(
        "evasive-cross-file-source-transform-sink",
    ));
    assert.ok(crossFile.document.graph.chains.some((chain) =>
        chain.status === "complete"
        && chain.crossFile
        && chain.pattern === "credential-read-transform-send"));

    const alternate = executeExpectation(runnerInternals.loadExpectation(
        "evasive-alternate-path",
    ));
    const completePatterns = new Set(alternate.document.graph.chains
        .filter((chain) => chain.status === "complete")
        .map((chain) => chain.pattern));
    assert.ok(completePatterns.has("behavior-chain"));
    assert.ok(completePatterns.has("credential-read-transform-send"));
});

test("inventory and release blockers cannot report favorable assurance", () => {
    for (const slug of [
        "inventory-submodule-blocker",
        "inventory-lfs-blocker",
        "inventory-archive-blocker",
        "inventory-binary-blocker",
        "source-release-divergence",
    ]) {
        const expectation = runnerInternals.loadExpectation(slug);
        const result = executeExpectation(expectation);
        assert.equal(result.comparison.status, "PASS");
        assert.equal(result.document.assurance.level, "partial");
        assert.equal(result.document.verdict.value, "incomplete");
    }
});

test("dimension metrics group results and enforce approved thresholds", () => {
    const results = runnerInternals.loadExpectations()
        .filter((expectation) => expectation.source.type === "local")
        .map((expectation) => executeExpectation(expectation));
    const metrics = calculateMetrics(results);
    assert.equal(metrics.refutationAccuracy, 1);
    assert.equal(metrics.favorableAssuranceWithKnownBlockers, 0);
    assert.ok(metrics.dimensions.evasionClass[
        "encoding-and-parser-differentials"
    ]);
    assert.ok(metrics.dimensions.artifactClass.archive);
    assert.ok(metrics.dimensions.language.javascript);
    assert.ok(metrics.dimensions.size.medium);
    const gate = evaluateQualityGate(
        metrics,
        runnerInternals.loadQualityThresholds(),
    );
    assert.equal(gate.passed, true, JSON.stringify(gate.failures));

    const blockedFailure = evaluateQualityGate(
        {
            ...metrics,
            favorableAssuranceWithKnownBlockers: 1,
        },
        runnerInternals.loadQualityThresholds(),
    );
    assert.ok(blockedFailure.failures.some((failure) =>
        failure.metric === "favorableAssuranceWithKnownBlockers"));
});

test("committed evasive fixtures remain printable ASCII marker data", () => {
    for (const expectation of runnerInternals.loadExpectations()
        .filter((entry) => entry.source.type === "local"
            && entry.dimensions.evasion_classes.length > 0)) {
        const root = nodePath.resolve(
            runnerInternals.CORPUS_ROOT,
            expectation.source.path,
        );
        for (const path of executorInternals.walkFiles(root)) {
            const text = readFileSync(path, "utf8");
            assert.match(text, /^[\x09\x0a\x0d\x20-\x7e]*$/u);
            assert.doesNotMatch(text, /https?:|file:|data:/iu);
            assert.ok(executorInternals.validateFixtureText(
                text,
                nodePath.basename(path),
            ).length > 0);
        }
    }
});
