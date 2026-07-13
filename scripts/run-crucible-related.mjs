import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function gitLines(args) {
    const output = execFileSync("git", args, {
        cwd: ROOT,
        encoding: "utf8",
        windowsHide: true,
        stdio: ["ignore", "pipe", "inherit"],
    });
    return output.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
}

const explicit = process.argv.slice(2).filter((arg) => !arg.startsWith("--"));
const changed = explicit.length > 0
    ? explicit
    : [
        ...gitLines(["diff", "--name-only", "--diff-filter=ACMRTUXB", "HEAD", "--", "crucible"]),
        ...gitLines(["ls-files", "--others", "--exclude-standard", "--", "crucible"]),
    ];

const inputs = [...new Set(changed)]
    .filter((file) => /\.(?:mjs|js|json)$/u.test(file))
    .map((file) => file.replaceAll("\\", "/"));

if (inputs.length === 0) {
    process.stderr.write("No changed Crucible source/test files were found.\n");
    process.exit(2);
}

const TEST_ROOT = "crucible/__tests__/";
const tests = new Set();

const ownership = [
    [/domain\/canonical\.mjs$/u, ["domain-canonical.test.mjs"]],
    [/domain\/enumerands\.mjs$/u, ["domain-enumerands.test.mjs"]],
    [/domain\/hypotheses\.mjs$/u, ["domain-hypotheses.test.mjs"]],
    [/domain\/statistics\.mjs$/u, ["domain-statistics.test.mjs"]],
    [/domain\/cohort\.mjs$/u, ["domain-cohort.test.mjs", "domain-kernel.test.mjs"]],
    [/domain\/confirmation\.mjs$/u, [
        "domain-confirmation-protocol.test.mjs",
        "domain-confirmation.test.mjs",
        "domain-confirmation-failure.test.mjs",
    ]],
    [/domain\/novelty\.mjs$/u, ["domain-novelty.test.mjs"]],
    [/domain\/(?:archive|strategy)\.mjs$/u, ["domain-archive-strategy.test.mjs"]],
    [/domain\/(?:events|evidence|reducer|state|decision|scientific-readiness|scientific-replay)\.mjs$/u, [
        "domain-kernel.test.mjs",
        "domain-confirmation.test.mjs",
        "domain-confirmation-failure.test.mjs",
    ]],
    [/domain\/(?:contract|constants)\.mjs$/u, ["v4-stat-contract.test.mjs", "api-schema.test.mjs"]],
    [/api\/schema\.mjs$/u, ["api-schema.test.mjs"]],
    [/api\/(?:environment|experiment-authority|experiment-registry)\.mjs$/u, ["tools-configure-experiment.test.mjs", "api-preflight.test.mjs"]],
    [/api\/preflight\.mjs$/u, ["api-preflight.test.mjs"]],
    [/api\/(?:handlers|result)\.mjs$/u, ["api-handlers.test.mjs"]],
    [/runtime\/runner\.mjs$/u, ["runtime-runner.test.mjs"]],
    [/runtime\/worker-pool\.mjs$/u, ["runtime-worker-pool.test.mjs"]],
    [/runtime\/prompt-context\.mjs$/u, ["runtime-prompt-context.test.mjs"]],
    [/runtime\/measurement-scheduler\.mjs$/u, ["runtime-measurement-scheduler.test.mjs"]],
    [/runtime\/domain-adapter\.mjs$/u, ["runtime-domain-adapter.test.mjs"]],
    [/runtime\/supervisor\.mjs$/u, ["runtime-supervisor.test.mjs"]],
    [/runtime\/.*cli\.mjs$/u, ["runtime-cli.test.mjs"]],
    [/measurement\/parser\.mjs$/u, ["measurement-parser.test.mjs"]],
    [/measurement\/(?:allowlist|harness-suite)\.mjs$/u, ["measurement-allowlist.test.mjs", "measurement-harness-suite.test.mjs"]],
    [/measurement\/(?:executor|receipt|fs-verify)\.mjs$/u, ["measurement-executor.test.mjs", "measurement-fs-verify.test.mjs"]],
    [/measurement\/(?:sandbox|windows-.*)\.mjs$/u, ["measurement-sandbox-capability.test.mjs", "windows-sandbox-provider.test.mjs", "windows-adapter.test.mjs"]],
    [/persistence\/artifact-store\.mjs$/u, ["persistence-artifact-store.test.mjs"]],
    [/persistence\/bundle\.mjs$/u, ["persistence-bundle.test.mjs"]],
    [/persistence\/(?:repository|schema|canonical)\.mjs$/u, ["persistence-event-log.test.mjs", "persistence-commands.test.mjs", "persistence-safety.test.mjs"]],
    [/tools\/configure-harness\.mjs$/u, ["tools-configure-harness.test.mjs"]],
    [/tools\/configure-experiment\.mjs$/u, ["tools-configure-experiment.test.mjs"]],
];

for (const input of inputs) {
    if (input.startsWith(TEST_ROOT) && input.endsWith(".test.mjs")
        && !input.endsWith(".release.test.mjs")
        && !input.endsWith(".integration.test.mjs")) {
        tests.add(input);
        continue;
    }
    for (const [pattern, ownedTests] of ownership) {
        if (pattern.test(input)) {
            for (const test of ownedTests) {
                tests.add(`${TEST_ROOT}${test}`);
            }
        }
    }
}

if (tests.size === 0) {
    process.stderr.write(
        "No ownership mapping matched the changed files; running the fast unit tier.\n",
    );
}

const vitest = path.join(ROOT, "node_modules", "vitest", "vitest.mjs");
const result = spawnSync(
    process.execPath,
    tests.size === 0
        ? [vitest, "run", "--config", path.join(ROOT, "vitest.crucible-unit.config.mjs")]
        : [vitest, "run", ...tests],
    {
        cwd: ROOT,
        env: process.env,
        stdio: "inherit",
        windowsHide: true,
        timeout: 120_000,
    },
);

if (result.error?.code === "ETIMEDOUT") {
    process.stderr.write(
        "Changed-file tests exceeded 120 seconds. Run narrower test files instead of raising the timeout.\n",
    );
    process.exit(124);
}

process.exit(result.status ?? 1);
