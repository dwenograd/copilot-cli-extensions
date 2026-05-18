// __corpus__/runner/runCorpus.mjs
// Local-only corpus runner. Dry-run mode validates fixtures without dispatching
// audits or touching the network.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import nodePath from "node:path";
import { fileURLToPath } from "node:url";

import { parseGithubUrl } from "../../urlParser.mjs";
import { parseFindings } from "./parseFindings.mjs";
import { compareFindings } from "./compareFindings.mjs";
import { classifyFailure } from "./failureClassifier.mjs";
import { dispatchAudit } from "./dispatchAudit.mjs";

const __dirname = nodePath.dirname(fileURLToPath(import.meta.url));
const CORPUS_ROOT = nodePath.resolve(__dirname, "..");
const URLS_PATH = nodePath.join(CORPUS_ROOT, "urls.txt");
const EXPECTATIONS_DIR = nodePath.join(CORPUS_ROOT, "expectations");
const RESULTS_DIR = nodePath.join(CORPUS_ROOT, "results");
const SPACING_MS = 30_000;

function parseArgs(argv) {
    const args = { dryRun: false, fixture: null, promoteGate: false };
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === "--dry-run") args.dryRun = true;
        else if (arg === "--promote-gate") args.promoteGate = true;
        else if (arg === "--fixture") args.fixture = argv[++i];
        else if (arg === "--help" || arg === "-h") args.help = true;
        else throw new Error(`unknown argument: ${arg}`);
    }
    return args;
}

function usage() {
    return [
        "Usage: node __corpus__\\runner\\runCorpus.mjs [--dry-run] [--fixture <slug>] [--promote-gate]",
        "",
        "--dry-run       validate corpus and print planned actions only",
        "--fixture       run only one expectation slug",
        "--promote-gate  require zero failures and zero inconclusive fixtures",
    ].join("\n");
}

function parseList(value) {
    if (!value || value === "-") return [];
    return String(value).split(",").map((s) => s.trim()).filter(Boolean);
}

function slugFromParsed(parsed) {
    return `${parsed.owner}-${parsed.repo}`.toLowerCase().replace(/[^a-z0-9._-]+/g, "-");
}

function readUrlRegistry() {
    const text = readFileSync(URLS_PATH, "utf-8");
    const fixtures = [];
    for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        const cols = rawLine.split("\t");
        if (cols.length < 5) throw new Error(`urls.txt line ${index + 1}: expected 5 TSV columns`);
        const [url, kind, expectedMinVerdict, requiredTagsRaw, forbiddenTagsRaw] = cols;
        const parsed = parseGithubUrl(url);
        if (!parsed.ok) throw new Error(`urls.txt line ${index + 1}: URL rejected: ${parsed.error}`);
        const slug = slugFromParsed(parsed.parsed);
        fixtures.push({
            slug,
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

function loadExpectation(fixture) {
    const p = nodePath.join(EXPECTATIONS_DIR, `${fixture.slug}.json`);
    if (!existsSync(p)) throw new Error(`missing expectation file for ${fixture.slug}: ${p}`);
    const expectation = JSON.parse(readFileSync(p, "utf-8"));
    if (expectation.url && expectation.url !== fixture.url) {
        throw new Error(`expectation URL mismatch for ${fixture.slug}`);
    }
    return {
        ...fixture,
        ...expectation,
        required_tags: expectation.required_tags || fixture.required_tags,
        forbidden_tags: expectation.forbidden_tags || fixture.forbidden_tags,
        expected_min_verdict: expectation.expected_min_verdict || fixture.expected_min_verdict,
    };
}

function runId() {
    return new Date().toISOString().replace(/[:.]/g, "-");
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runFixture(fixture, { dryRun, promoteGate, runDir }) {
    const expectation = loadExpectation(fixture);
    const modes = ["audit_source", "audit_source_council"];
    if (dryRun) {
        console.log(`[dry-run] ${fixture.slug}`);
        console.log(`  url: ${fixture.url}`);
        console.log(`  kind: ${fixture.kind}`);
        console.log(`  expected_min_verdict: ${expectation.expected_min_verdict}`);
        console.log(`  modes: ${modes.join(" -> ")}`);
        console.log("  dispatch: skipped");
        return { slug: fixture.slug, status: "PLANNED", passed: true };
    }

    const fixtureDir = nodePath.join(runDir, fixture.slug);
    mkdirSync(fixtureDir, { recursive: true });
    const outputs = {};

    for (const mode of modes) {
        const sessionId = `corpus-${fixture.slug}-${mode}-${Date.now()}`;
        const result = await dispatchAudit({ url: fixture.url, mode, outDir: fixtureDir, sessionId });
        outputs[mode] = result;
        if (!result.ok) {
            const classified = classifyFailure(result);
            if (classified.abort) throw new Error(`${fixture.slug}: ${classified.classification}: ${classified.reason}`);
            return { slug: fixture.slug, status: classified.classification, passed: false, classified };
        }
    }

    const v1Report = readFileSync(outputs.audit_source.reportPath, "utf-8");
    const v2Report = readFileSync(outputs.audit_source_council.reportPath, "utf-8");
    const comparison = compareFindings({
        v1Findings: parseFindings(v1Report, { source: outputs.audit_source.reportPath }),
        v2Findings: parseFindings(v2Report, { source: outputs.audit_source_council.reportPath }),
        expectation,
        councilComplete: true,
    });

    const outPath = nodePath.join(fixtureDir, "comparison.json");
    writeFileSync(outPath, JSON.stringify({ fixture: fixture.slug, comparison }, null, 2));
    if (promoteGate && comparison.status !== "PASS") process.exitCode = 1;
    return { slug: fixture.slug, ...comparison, outPath };
}

export async function main(argv = process.argv.slice(2)) {
    const args = parseArgs(argv);
    if (args.help) {
        console.log(usage());
        return 0;
    }

    let fixtures = readUrlRegistry();
    fixtures = fixtures.map(loadExpectation);
    if (args.fixture) fixtures = fixtures.filter((f) => f.slug === args.fixture);
    if (fixtures.length === 0) throw new Error(args.fixture ? `no such fixture: ${args.fixture}` : "no fixtures configured");

    const thisRunId = runId();
    const runDir = nodePath.join(RESULTS_DIR, thisRunId);
    if (!args.dryRun) mkdirSync(runDir, { recursive: true });

    console.log(`Corpus fixtures: ${fixtures.length}`);
    console.log(`Mode: ${args.dryRun ? "dry-run" : "live"}${args.promoteGate ? " promote-gate" : ""}`);

    const results = [];
    for (let i = 0; i < fixtures.length; i += 1) {
        const fixture = fixtures[i];
        const result = await runFixture(fixture, { dryRun: args.dryRun, promoteGate: args.promoteGate, runDir });
        results.push(result);
        if (!args.dryRun && i < fixtures.length - 1) await sleep(SPACING_MS);
    }

    const failed = results.filter((r) => !r.passed);
    const inconclusive = results.filter((r) => r.status === "INCONCLUSIVE");
    console.log(`Summary: planned=${results.filter((r) => r.status === "PLANNED").length} pass=${results.filter((r) => r.status === "PASS").length} failed=${failed.length} inconclusive=${inconclusive.length}`);

    if (args.promoteGate && (failed.length > 0 || inconclusive.length > 0)) return 1;
    return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === nodePath.resolve(process.argv[1])) {
    main().then((code) => {
        process.exitCode = code;
    }).catch((err) => {
        console.error(err.message || err);
        process.exitCode = 1;
    });
}

export const __internals = {
    CORPUS_ROOT,
    URLS_PATH,
    EXPECTATIONS_DIR,
    parseArgs,
    parseList,
    slugFromParsed,
    readUrlRegistry,
    loadExpectation,
};

