import {
    existsSync,
    mkdirSync,
    readFileSync,
    readdirSync,
    writeFileSync,
} from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";

import { parseGithubUrl } from "../../urlParser.mjs";
import {
    compareEvaluation,
    compareFindings,
} from "./compareFindings.mjs";
import { dispatchAudit } from "./dispatchAudit.mjs";
import {
    EXPECTATION_SCHEMA,
    validateExpectation,
} from "./expectationSchema.mjs";
import { classifyFailure } from "./failureClassifier.mjs";
import { executeLocalFixture } from "./localFixtureExecutor.mjs";
import {
    calculateMetrics,
    evaluatePromotionGate,
} from "./metrics.mjs";
import {
    parseAuditArtifacts,
    parseFindingsJson,
} from "./parseFindings.mjs";

const __dirname = nodePath.dirname(fileURLToPath(import.meta.url));
const CORPUS_ROOT = nodePath.resolve(__dirname, "..");
const URLS_PATH = nodePath.join(CORPUS_ROOT, "urls.txt");
const EXPECTATIONS_DIR = nodePath.join(CORPUS_ROOT, "expectations");
const FIXTURES_DIR = nodePath.join(CORPUS_ROOT, "fixtures");
const RESULTS_DIR = nodePath.join(CORPUS_ROOT, "results");
const PROMOTION_GATE_PATH = nodePath.join(CORPUS_ROOT, "promotion-gate.v1.json");
const SPACING_MS = 30_000;

function parseArgs(argv) {
    const args = {
        execution: "dry-run",
        fixture: null,
        promoteGate: false,
    };
    let explicitExecution = false;
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (["--dry-run", "--local", "--live"].includes(arg)) {
            if (explicitExecution) throw new Error("choose only one of --dry-run, --local, or --live");
            args.execution = arg.slice(2);
            explicitExecution = true;
        } else if (arg === "--promote-gate") args.promoteGate = true;
        else if (arg === "--fixture") args.fixture = argv[++i];
        else if (arg === "--help" || arg === "-h") args.help = true;
        else throw new Error(`unknown argument: ${arg}`);
    }
    return args;
}

function usage() {
    return [
        "Usage: node __corpus__/runner/runCorpus.mjs [--dry-run|--local|--live] [--fixture <slug>] [--promote-gate]",
        "",
        "--dry-run       validate every expectation and execute local inert fixtures in memory",
        "--local         execute local inert fixtures and write ignored result artifacts",
        "--live          run GitHub URL fixtures; requires ZEROTRUST_CORPUS_LIVE=1",
        "--fixture       select one expectation slug",
        "--promote-gate  apply versioned metric thresholds",
        "",
        "No execution flag defaults to --dry-run. Live network/model use is never implicit.",
    ].join("\n");
}

function parseList(value) {
    if (!value || value === "-") return [];
    return String(value).split(",").map((entry) => entry.trim()).filter(Boolean);
}

function slugFromParsed(parsed) {
    return `${parsed.owner}-${parsed.repo}`.toLowerCase().replace(/[^a-z0-9._-]+/gu, "-");
}

function readUrlRegistry() {
    const text = readFileSync(URLS_PATH, "utf8");
    const fixtures = [];
    for (const [index, rawLine] of text.split(/\r?\n/u).entries()) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        const cols = rawLine.split("\t");
        if (cols.length < 5) throw new Error(`urls.txt line ${index + 1}: expected 5 TSV columns`);
        const [url, kind, expectedMinVerdict, requiredTagsRaw, forbiddenTagsRaw] = cols;
        const parsed = parseGithubUrl(url);
        if (!parsed.ok) throw new Error(`urls.txt line ${index + 1}: URL rejected: ${parsed.error}`);
        fixtures.push({
            slug: slugFromParsed(parsed.parsed),
            url,
            kind,
            expected_min_verdict: expectedMinVerdict,
            required_tags: parseList(requiredTagsRaw),
            forbidden_tags: parseList(forbiddenTagsRaw),
            parsed: parsed.parsed,
        });
    }
    return fixtures;
}

function expectationFiles() {
    return readdirSync(EXPECTATIONS_DIR, { withFileTypes: true })
        .filter((entry) =>
            entry.isFile()
            && entry.name.endsWith(".json")
            && entry.name !== "schema-v1.json")
        .map((entry) => nodePath.join(EXPECTATIONS_DIR, entry.name))
        .sort();
}

function loadExpectations() {
    const urls = new Map(readUrlRegistry().map((entry) => [entry.url, entry]));
    const seen = new Set();
    return expectationFiles().map((path) => {
        const expectation = validateExpectation(
            JSON.parse(readFileSync(path, "utf8")),
            nodePath.basename(path),
        );
        if (seen.has(expectation.slug)) throw new Error(`duplicate expectation slug: ${expectation.slug}`);
        seen.add(expectation.slug);
        if (expectation.source.type === "github") {
            const registered = urls.get(expectation.source.url);
            if (!registered) {
                throw new Error(`${expectation.slug}: GitHub expectation is absent from urls.txt`);
            }
            if (registered.slug !== expectation.slug) {
                throw new Error(`${expectation.slug}: GitHub expectation slug mismatch`);
            }
        } else {
            const fixtureRoot = nodePath.resolve(CORPUS_ROOT, expectation.source.path);
            const relative = nodePath.relative(FIXTURES_DIR, fixtureRoot);
            if (relative.startsWith("..") || nodePath.isAbsolute(relative)
                || !existsSync(fixtureRoot)) {
                throw new Error(`${expectation.slug}: local fixture path is missing or outside fixtures/`);
            }
        }
        return expectation;
    });
}

function loadExpectation(fixture) {
    const expectations = loadExpectations();
    const slug = typeof fixture === "string" ? fixture : fixture.slug;
    const expectation = expectations.find((entry) => entry.slug === slug);
    if (!expectation) throw new Error(`missing expectation file for ${slug}`);
    return expectation;
}

function runId() {
    return new Date().toISOString().replace(/[:.]/gu, "-");
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function localResult(expectation, { dryRun, runDir }) {
    const fixtureRoot = nodePath.resolve(CORPUS_ROOT, expectation.source.path);
    const document = executeLocalFixture({
        fixtureRoot,
        slug: expectation.slug,
    });
    const actual = parseFindingsJson(document, {
        source: `${expectation.slug}/FINDINGS.json`,
    });
    const comparison = compareEvaluation(actual, expectation);
    let outPath = null;
    if (!dryRun) {
        const fixtureDir = nodePath.join(runDir, expectation.slug);
        mkdirSync(fixtureDir, { recursive: true });
        writeFileSync(
            nodePath.join(fixtureDir, "FINDINGS.json"),
            `${JSON.stringify(document, null, 2)}\n`,
        );
        outPath = nodePath.join(fixtureDir, "comparison.json");
        writeFileSync(
            outPath,
            `${JSON.stringify({ expectation, comparison }, null, 2)}\n`,
        );
    }
    return {
        slug: expectation.slug,
        status: comparison.status,
        passed: comparison.passed,
        expectation,
        comparison,
        outPath,
    };
}

async function liveResult(expectation, { runDir }) {
    const fixtureDir = nodePath.join(runDir, expectation.slug);
    mkdirSync(fixtureDir, { recursive: true });
    const outputs = {};
    for (const mode of ["audit_source", "audit_source_council"]) {
        const sessionId = `corpus-${expectation.slug}-${mode}-${Date.now()}`;
        const result = await dispatchAudit({
            url: expectation.source.url,
            mode,
            outDir: fixtureDir,
            sessionId,
        });
        outputs[mode] = result;
        if (!result.ok) {
            const classified = classifyFailure(result);
            if (classified.abort) {
                throw new Error(
                    `${expectation.slug}: ${classified.classification}: ${classified.reason}`,
                );
            }
            return {
                slug: expectation.slug,
                status: classified.classification,
                passed: false,
                expectation,
                classified,
            };
        }
    }

    const baseline = parseAuditArtifacts({
        findingsPath: outputs.audit_source.findingsPath,
        reportPath: outputs.audit_source.reportPath,
    });
    const council = parseAuditArtifacts({
        findingsPath: outputs.audit_source_council.findingsPath,
        reportPath: outputs.audit_source_council.reportPath,
    });
    const baselineComparison = compareEvaluation(baseline, expectation);
    const comparison = compareEvaluation(council, expectation);
    const continuity = compareFindings({
        v1Findings: baseline.findings,
        v2Findings: council.findings,
        expectation: {
            kind: expectation.kind,
            expected_min_verdict: expectation.expected.scores.severity.min,
            required_tags: expectation.expected.tags.required,
            forbidden_tags: expectation.expected.tags.forbidden,
        },
        v1Verdict: baseline.verdict,
        v2Verdict: council.verdict,
        councilComplete: council.stage.completed.includes("validated"),
    });
    const passed = baselineComparison.passed && comparison.passed && continuity.passed;
    const outPath = nodePath.join(fixtureDir, "comparison.json");
    writeFileSync(
        outPath,
        `${JSON.stringify({
            expectation,
            baselineComparison,
            comparison,
            continuity,
        }, null, 2)}\n`,
    );
    return {
        slug: expectation.slug,
        status: passed ? "PASS" : "FAIL",
        passed,
        expectation,
        comparison,
        baselineComparison,
        continuity,
        outPath,
    };
}

async function runFixture(expectation, options) {
    if (expectation.source.type === "local") {
        if (options.execution === "live") {
            return {
                slug: expectation.slug,
                status: "SKIPPED-LOCAL",
                passed: true,
                expectation,
            };
        }
        return localResult(expectation, {
            dryRun: options.execution === "dry-run",
            runDir: options.runDir,
        });
    }
    if (options.execution !== "live") {
        console.log(`[planned] ${expectation.slug}: live GitHub audit skipped`);
        return {
            slug: expectation.slug,
            status: "PLANNED",
            passed: true,
            expectation,
        };
    }
    return liveResult(expectation, options);
}

function loadPromotionThresholds() {
    return JSON.parse(readFileSync(PROMOTION_GATE_PATH, "utf8"));
}

export async function main(argv = process.argv.slice(2)) {
    const args = parseArgs(argv);
    if (args.help) {
        console.log(usage());
        return 0;
    }
    if (args.execution === "live" && process.env.ZEROTRUST_CORPUS_LIVE !== "1") {
        throw new Error("--live requires ZEROTRUST_CORPUS_LIVE=1");
    }

    let expectations = loadExpectations();
    if (args.fixture) {
        expectations = expectations.filter((entry) => entry.slug === args.fixture);
    }
    if (expectations.length === 0) {
        throw new Error(args.fixture ? `no such fixture: ${args.fixture}` : "no fixtures configured");
    }

    const thisRunId = runId();
    const runDir = nodePath.join(RESULTS_DIR, thisRunId);
    if (args.execution !== "dry-run") mkdirSync(runDir, { recursive: true });

    console.log(`Corpus fixtures: ${expectations.length}`);
    console.log(`Expectation schema: ${EXPECTATION_SCHEMA}`);
    console.log(`Mode: ${args.execution}${args.promoteGate ? " promote-gate" : ""}`);

    const results = [];
    const runnable = expectations.filter((expectation) =>
        args.execution === "live"
            ? expectation.source.type === "github"
            : expectation.source.type === "local");
    let runnableIndex = 0;
    for (const expectation of expectations) {
        const result = await runFixture(expectation, {
            execution: args.execution,
            runDir,
        });
        results.push(result);
        console.log(`${result.status.padEnd(16)} ${result.slug}`);
        if (args.execution === "live" && expectation.source.type === "github") {
            runnableIndex += 1;
            if (runnableIndex < runnable.length) await sleep(SPACING_MS);
        }
    }

    const metrics = calculateMetrics(results);
    const failed = results.filter((result) => !result.passed);
    const inconclusive = results.filter((result) => result.status === "INCONCLUSIVE");
    console.log(
        `Metrics: activation=${metrics.activationRecall.toFixed(3)}`
        + ` candidate=${metrics.candidateRecall.toFixed(3)}`
        + ` complete-chain=${metrics.completeChainRecall.toFixed(3)}`
        + ` validation/refutation=${metrics.validationRefutationAccuracy.toFixed(3)}`
        + ` false-positive=${metrics.falsePositiveRate.toFixed(3)}`
        + ` unresolved=${metrics.unresolvedRate.toFixed(3)}`,
    );
    console.log(
        `Summary: pass=${results.filter((result) => result.status === "PASS").length}`
        + ` planned=${results.filter((result) => result.status === "PLANNED").length}`
        + ` failed=${failed.length} inconclusive=${inconclusive.length}`,
    );

    let gate = { passed: true, failures: [] };
    if (args.promoteGate) {
        gate = evaluatePromotionGate(metrics, loadPromotionThresholds());
        if (!gate.passed) {
            for (const failure of gate.failures) {
                console.error(
                    `promotion gate: ${failure.metric} ${failure.direction}`
                    + ` ${failure.threshold}, got ${failure.actual}`,
                );
            }
        }
    }

    if (args.execution !== "dry-run") {
        writeFileSync(
            nodePath.join(runDir, "summary.json"),
            `${JSON.stringify({ results, metrics, gate }, null, 2)}\n`,
        );
    }
    return failed.length > 0 || inconclusive.length > 0 || !gate.passed ? 1 : 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === nodePath.resolve(process.argv[1])) {
    main().then((code) => {
        process.exitCode = code;
    }).catch((error) => {
        console.error(error.message || error);
        process.exitCode = 1;
    });
}

export const __internals = {
    CORPUS_ROOT,
    URLS_PATH,
    EXPECTATIONS_DIR,
    FIXTURES_DIR,
    RESULTS_DIR,
    PROMOTION_GATE_PATH,
    parseArgs,
    parseList,
    slugFromParsed,
    readUrlRegistry,
    expectationFiles,
    loadExpectations,
    loadExpectation,
    runId,
    localResult,
    loadPromotionThresholds,
};
