import path from "node:path";
import { pathToFileURL } from "node:url";

import {
    buildV4ScienceBenchmark,
} from "../__tests__/science-fixtures/v4-adapter.mjs";

function prettyJson(value) {
    return `${JSON.stringify(value, null, 2)}\n`;
}

function usage() {
    return [
        "Usage: node crucible/scripts/run-v4-science-benchmark.mjs [--check|--list]",
        "  --check  run all deterministic v4 science experiments and emit metrics",
        "  --list   emit the named release-gate checks without running them",
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
    if (args.length > 1 || !["--check", "--list"].includes(mode)) {
        stderr.write(`${usage()}\n`);
        return 2;
    }
    if (mode === "--list") {
        stdout.write(prettyJson({
            suite: "crucible-v4-science-gate",
            checks: [
                "nullFalseVerified",
                "knownEffectPower",
                "environmentFailClosed",
                "predicateDisagreement",
                "predictionsAndConclusion",
                "novelty",
                "cohorts",
                "overfit",
                "impossibility",
                "optimization",
            ],
        }));
        return 0;
    }
    const benchmark = buildV4ScienceBenchmark();
    stdout.write(prettyJson(benchmark));
    return benchmark.passed ? 0 : 1;
}

const invokedPath = process.argv[1] === undefined
    ? null
    : pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedPath === import.meta.url) {
    process.exitCode = runCli(process.argv.slice(2));
}
