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

const argv = process.argv.slice(2);
const explicit = argv.filter((arg) => !arg.startsWith("--"));
const releaseGate = argv.includes("--release")
    || explicit.some((file) => file.endsWith(".release.test.mjs"));
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
    [/domain\/(?:contract|constants|runtime-authority)\.mjs$/u, [
        "v4-stat-contract.test.mjs",
        "runtime-identity.test.mjs",
        "api-schema.test.mjs",
    ]],
    [/domain\/working-set-policy\.mjs$/u, [
        "domain-working-set-policy.test.mjs",
        "v4-stat-contract.test.mjs",
        "api-schema.test.mjs",
    ]],
    [/api\/schema\.mjs$/u, ["api-schema.test.mjs"]],
    [/api\/(?:environment|experiment-authority|experiment-registry)\.mjs$/u, [
        "tools-configure-experiment.test.mjs",
        "api-preflight.test.mjs",
        "api-lifecycle.test.mjs",
        "persistence-retention.test.mjs",
    ]],
    [/api\/preflight\.mjs$/u, ["api-preflight.test.mjs"]],
    [/api\/(?:handlers|result)\.mjs$/u, [
        "api-handlers.test.mjs",
        "api-lifecycle.test.mjs",
    ]],
    [/api\/lifecycle\.mjs$/u, [
        "api-lifecycle.test.mjs",
        "api-handlers.test.mjs",
    ]],
    [/runtime\/runner\.mjs$/u, ["runtime-runner.test.mjs"]],
    [/runtime\/config\.mjs$/u, [
        "runtime-cli.test.mjs",
        "runtime-supervisor.test.mjs",
    ]],
    [/runtime\/(?:config-validation|resource-broker)\.mjs$/u, [
        "runtime-resource-broker.test.mjs",
        "runtime-runner.test.mjs",
    ]],
    [/runtime\/worker-pool\.mjs$/u, ["runtime-worker-pool.test.mjs"]],
    [/runtime\/prompt-context\.mjs$/u, ["runtime-prompt-context.test.mjs"]],
    [/runtime\/measurement-scheduler\.mjs$/u, ["runtime-measurement-scheduler.test.mjs"]],
    [/runtime\/domain-adapter\.mjs$/u, ["runtime-domain-adapter.test.mjs"]],
    [/runtime\/supervisor\.mjs$/u, ["runtime-supervisor.test.mjs"]],
    [/runtime\/(?:runtime-identity|config-authority)\.mjs$/u, [
        "runtime-identity.test.mjs",
        "api-preflight.test.mjs",
    ]],
    [/runtime\/.*cli\.mjs$/u, ["runtime-cli.test.mjs"]],
    [/measurement\/parser\.mjs$/u, ["measurement-parser.test.mjs"]],
    [/measurement\/(?:allowlist|harness-suite)\.mjs$/u, ["measurement-allowlist.test.mjs", "measurement-harness-suite.test.mjs"]],
    [/measurement\/(?:executor|receipt|fs-verify)\.mjs$/u, ["measurement-executor.test.mjs", "measurement-fs-verify.test.mjs"]],
    [/measurement\/(?:sandbox|windows-.*)\.mjs$/u, ["measurement-sandbox-capability.test.mjs", "windows-sandbox-provider.test.mjs", "windows-adapter.test.mjs"]],
    [/persistence\/artifact-store\.mjs$/u, [
        "persistence-artifact-store.test.mjs",
        "persistence-working-set.test.mjs",
    ]],
    [/persistence\/working-set\.mjs$/u, [
        "persistence-working-set.test.mjs",
        "api-handlers.test.mjs",
    ]],
    [/persistence\/bundle\.mjs$/u, ["persistence-bundle.test.mjs"]],
    [/persistence\/segment-manager\.mjs$/u, [
        "persistence-segments.test.mjs",
        "persistence-event-log.test.mjs",
        "persistence-bundle.test.mjs",
        "runtime-domain-adapter.test.mjs",
    ]],
    [/persistence\/(?:repository|schema|canonical)\.mjs$/u, [
        "persistence-event-log.test.mjs",
        "persistence-segments.test.mjs",
        "persistence-commands.test.mjs",
        "persistence-safety.test.mjs",
        "persistence-working-set.test.mjs",
    ]],
    [/persistence\/(?:resource-catalog|resource-catalog-schema)\.mjs$/u, [
        "runtime-resource-broker.test.mjs",
        "persistence-recovery-catalog.test.mjs",
        "persistence-retention.test.mjs",
    ]],
    [/persistence\/retention\.mjs$/u, [
        "persistence-retention.test.mjs",
    ]],
    [/tools\/configure-harness\.mjs$/u, ["tools-configure-harness.test.mjs"]],
    [/tools\/configure-experiment\.mjs$/u, ["tools-configure-experiment.test.mjs"]],
];

const releaseOwnership = [
    [/api\/(?:handlers|result|lifecycle)\.mjs$/u, [
        "api-handlers.release.test.mjs",
    ]],
    [/persistence\/bundle\.mjs$/u, [
        "persistence-bundle.release.test.mjs",
        "v4-replay-stats.release.test.mjs",
    ]],
    [/persistence\/segment-manager\.mjs$/u, [
        "persistence-segments.release.test.mjs",
    ]],
    [/persistence\/working-set\.mjs$/u, [
        "persistence-working-set.release.test.mjs",
    ]],
    [/__tests__\/v4-replay-stats-fixture\.mjs$/u, [
        "v4-replay-stats.release.test.mjs",
    ]],
];

for (const input of inputs) {
    if (releaseGate
        && input.startsWith(TEST_ROOT)
        && input.endsWith(".release.test.mjs")) {
        tests.add(input);
        continue;
    }
    if (!releaseGate
        && input.startsWith(TEST_ROOT)
        && input.endsWith(".test.mjs")
        && !input.endsWith(".release.test.mjs")
        && !input.endsWith(".integration.test.mjs")) {
        tests.add(input);
        continue;
    }
    for (const [pattern, ownedTests] of releaseGate
        ? releaseOwnership
        : ownership) {
        if (pattern.test(input)) {
            for (const test of ownedTests) {
                tests.add(`${TEST_ROOT}${test}`);
            }
        }
    }
}

if (tests.size === 0) {
    if (releaseGate) {
        process.stderr.write(
            "No release ownership mapping matched the explicit phase-gate inputs.\n",
        );
        process.exit(2);
    }
    process.stderr.write(
        "No ownership mapping matched the changed files; running the fast unit tier.\n",
    );
}

const vitest = path.join(ROOT, "node_modules", "vitest", "vitest.mjs");
const vitestArgs = releaseGate
    ? [
        vitest,
        "run",
        "--config",
        path.join(ROOT, "vitest.crucible-release.config.mjs"),
        ...tests,
    ]
    : tests.size === 0
        ? [
            vitest,
            "run",
            "--config",
            path.join(ROOT, "vitest.crucible-unit.config.mjs"),
        ]
        : [vitest, "run", ...tests];
const result = spawnSync(
    process.execPath,
    vitestArgs,
    {
        cwd: ROOT,
        env: process.env,
        stdio: "inherit",
        windowsHide: true,
        ...(releaseGate ? {} : { timeout: 120_000 }),
    },
);

if (!releaseGate && result.error?.code === "ETIMEDOUT") {
    process.stderr.write(
        "Changed-file tests exceeded 120 seconds. Run narrower test files instead of raising the timeout.\n",
    );
    process.exit(124);
}

process.exit(result.status ?? 1);
