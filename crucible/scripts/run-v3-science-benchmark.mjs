import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { canonicalJson } from "../domain/index.mjs";
import { buildV3ScienceBaseline } from "../__tests__/science-fixtures/v3-adapter.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASELINE_PATH = path.resolve(
    HERE,
    "..",
    "__tests__",
    "science-fixtures",
    "baseline.v3.json",
);

function prettyJson(value) {
    return `${JSON.stringify(value, null, 2)}\n`;
}

function readBaseline() {
    return JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8"));
}

export function buildMachineSummary() {
    const current = buildV3ScienceBaseline();
    const baseline = readBaseline();
    return {
        runnerVersion: 1,
        suite: current.suite,
        baselineMatch: canonicalJson(current) === canonicalJson(baseline),
        caseCount: current.caseCount,
        expectedToChangeInV4Count: current.cases.filter(
            (item) => item.expectedToChangeInV4,
        ).length,
        notDesiredBehaviorCount: current.cases.filter(
            (item) => item.notDesiredBehavior,
        ).length,
        summary: current,
    };
}

function usage() {
    return [
        "Usage: node crucible/scripts/run-v3-science-benchmark.mjs [--check|--current|--list]",
        "  --check    emit a machine summary for the committed v3 fixture baseline",
        "  --current  emit the committed raw v3 fixture payload without writing files",
        "  --list     emit fixture case IDs",
    ].join("\n");
}

export function runCli(
    args,
    {
        stdout = process.stdout,
        stderr = process.stderr,
    } = {},
) {
    const mode = args.length === 0 ? "--check" : args[0];
    if (args.length > 1 || !["--check", "--current", "--list"].includes(mode)) {
        stderr.write(`${usage()}\n`);
        return 2;
    }
    const current = buildV3ScienceBaseline();
    if (mode === "--current") {
        stdout.write(prettyJson(current));
        return 0;
    }
    if (mode === "--list") {
        stdout.write(prettyJson({
            suite: current.suite,
            cases: current.cases.map((item) => item.id),
        }));
        return 0;
    }
    const summary = buildMachineSummary();
    stdout.write(prettyJson(summary));
    return summary.baselineMatch ? 0 : 1;
}

const invokedPath = process.argv[1] === undefined
    ? null
    : pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedPath === import.meta.url) {
    process.exitCode = runCli(process.argv.slice(2));
}
