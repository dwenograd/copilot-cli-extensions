import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
);

const TEST_ROOT = "crucible/__tests__/";
const SOURCE_EXTENSIONS = new Set([".js", ".json", ".mjs", ".ps1"]);
const TOP_LEVEL_INPUTS = new Set([
    "package.json",
    "vitest.config.mjs",
    "vitest.crucible-integration.config.mjs",
    "vitest.crucible-release.config.mjs",
    "vitest.crucible-science.config.mjs",
    "vitest.crucible-unattended.config.mjs",
    "vitest.crucible-unit.config.mjs",
    "vitest.windows-conformance.config.mjs",
    "vitest.workspace-fast.config.mjs",
]);

function target(file, tier = "unit", pattern = null) {
    return Object.freeze({ file: `${TEST_ROOT}${file}`, tier, pattern });
}

const RULES = [
    {
        pattern: /^crucible\/extension\.mjs$/u,
        targets: [target("api-extension.test.mjs")],
    },
    {
        pattern: /^crucible\/api\/schema\.mjs$/u,
        targets: [target("api-schema.test.mjs")],
    },
    {
        pattern:
            /^crucible\/api\/(?:environment|experiment-authority|experiment-registry|preflight)\.mjs$/u,
        targets: [
            target("api-preflight.test.mjs"),
            target("tools-configure-experiment.test.mjs"),
        ],
    },
    {
        pattern:
            /^crucible\/api\/(?:handlers|lifecycle|result)\.mjs$/u,
        targets: [
            target("api-handlers.test.mjs"),
            target("api-lifecycle.test.mjs"),
        ],
        releaseTargets: [target("api-handlers.release.test.mjs", "release")],
    },
    {
        pattern: /^crucible\/api\/errors\.mjs$/u,
        targets: [target("api-handlers.test.mjs")],
    },
    {
        pattern: /^crucible\/domain\/canonical\.mjs$/u,
        targets: [target("domain-canonical.test.mjs")],
    },
    {
        pattern: /^crucible\/domain\/enumerands\.mjs$/u,
        targets: [target("domain-enumerands.test.mjs")],
    },
    {
        pattern: /^crucible\/domain\/hypotheses\.mjs$/u,
        targets: [target("domain-hypotheses.test.mjs")],
    },
    {
        pattern:
            /^crucible\/domain\/(?:statistics|statistical-evaluation|replication)\.mjs$/u,
        targets: [
            target("domain-statistics.test.mjs"),
            target("domain-kernel.test.mjs"),
            target("domain-statistical-alpha-lanes.test.mjs"),
        ],
        releaseTargets: [
            target("domain-statistics.release.test.mjs", "release"),
        ],
    },
    {
        pattern: /^crucible\/domain\/cohort\.mjs$/u,
        targets: [
            target("domain-cohort.test.mjs"),
            target("domain-kernel.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/domain\/confirmation\.mjs$/u,
        targets: [
            target("domain-confirmation-protocol.test.mjs"),
            target("domain-confirmation.test.mjs"),
            target("domain-confirmation-failure.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/domain\/novelty\.mjs$/u,
        targets: [target("domain-novelty.test.mjs")],
    },
    {
        pattern:
            /^crucible\/domain\/(?:archive|strategy)\.mjs$/u,
        targets: [
            target("domain-archive-strategy.test.mjs"),
            target("domain-statistical-alpha-lanes.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/domain\/working-set-policy\.mjs$/u,
        targets: [
            target("domain-working-set-policy.test.mjs"),
            target("v4-stat-contract.test.mjs"),
        ],
    },
    {
        pattern:
            /^crucible\/domain\/(?:authority|constants|contract|runtime-authority)\.mjs$/u,
        targets: [
            target("v4-stat-contract.test.mjs"),
            target("api-schema.test.mjs"),
            target("runtime-identity.test.mjs"),
        ],
    },
    {
        pattern:
            /^crucible\/domain\/(?:prediction-evaluation)\.mjs$/u,
        targets: [target("domain-prediction-evaluation.test.mjs")],
    },
    {
        pattern:
            /^crucible\/domain\/(?:impossibility|private-verifier-execution|terminal-closure)\.mjs$/u,
        targets: [target("domain-kernel.test.mjs")],
        releaseTargets: [
            target(
                "domain-kernel.release.test.mjs",
                "release",
                "independent verifier|impossibility|TARGET_UNREACHABLE",
            ),
        ],
    },
    {
        pattern:
            /^crucible\/domain\/(?:decision|events|evidence|reducer|scientific-readiness|scientific-replay|state)\.mjs$/u,
        targets: [
            target("domain-kernel.test.mjs"),
            target("domain-confirmation.test.mjs"),
            target("domain-confirmation-failure.test.mjs"),
            target("domain-statistical-alpha-lanes.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/domain\/(?:errors|index)\.mjs$/u,
        targets: [target("domain-kernel.test.mjs")],
    },
    {
        pattern: /^crucible\/measurement\/allowlist\.mjs$/u,
        targets: [
            target("measurement-allowlist.test.mjs"),
            target("measurement-harness-suite.test.mjs"),
        ],
    },
    {
        pattern:
            /^crucible\/measurement\/(?:executor|receipt|fs-verify)\.mjs$/u,
        targets: [
            target("measurement-executor.test.mjs"),
            target("measurement-fs-verify.test.mjs"),
        ],
        releaseTargets: [
            target("measurement-executor.release.test.mjs", "release"),
        ],
    },
    {
        pattern: /^crucible\/measurement\/harness-suite\.mjs$/u,
        targets: [target("measurement-harness-suite.test.mjs")],
    },
    {
        pattern: /^crucible\/measurement\/novelty-role\.mjs$/u,
        targets: [target("measurement-novelty-role.test.mjs")],
    },
    {
        pattern: /^crucible\/measurement\/parser\.mjs$/u,
        targets: [target("measurement-parser.test.mjs")],
    },
    {
        pattern: /^crucible\/measurement\/verifier-parser\.mjs$/u,
        targets: [target("measurement-verifier-parser.test.mjs")],
    },
    {
        pattern:
            /^crucible\/measurement\/(?:sandbox|private-adapters)\.mjs$/u,
        targets: [target("measurement-sandbox-capability.test.mjs")],
    },
    {
        pattern:
            /^crucible\/measurement\/windows-job-process-adapter\.mjs$/u,
        targets: [target("windows-adapter.test.mjs")],
        releaseTargets: [
            target(
                "windows-conformance/windows-sandbox.conformance.test.mjs",
                "windows",
            ),
        ],
    },
    {
        pattern:
            /^crucible\/measurement\/windows-sandbox-provider\.mjs$/u,
        targets: [target("windows-sandbox-provider.test.mjs")],
        releaseTargets: [
            target(
                "windows-conformance/windows-sandbox.conformance.test.mjs",
                "windows",
            ),
        ],
    },
    {
        pattern: /^crucible\/measurement\/windows-adapter\.mjs$/u,
        targets: [target("windows-adapter.test.mjs")],
    },
    {
        pattern: /^crucible\/measurement\/(?:errors|index)\.mjs$/u,
        targets: [
            target("measurement-executor.test.mjs"),
            target("measurement-parser.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/persistence\/artifact-store\.mjs$/u,
        targets: [
            target("persistence-artifact-store.test.mjs"),
            target("persistence-cas-durability.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/persistence\/bundle\.mjs$/u,
        targets: [target("persistence-bundle.test.mjs")],
        releaseTargets: [
            target("persistence-bundle.release.test.mjs", "release"),
            target("v4-replay-stats.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/persistence\/(?:enumerand-staging|working-set)\.mjs$/u,
        targets: [target("persistence-working-set.test.mjs")],
        releaseTargets: [
            target("persistence-working-set.release.test.mjs", "release"),
        ],
    },
    {
        pattern: /^crucible\/persistence\/segment-manager\.mjs$/u,
        targets: [
            target("persistence-segments.test.mjs"),
            target("persistence-event-log.test.mjs"),
        ],
        releaseTargets: [
            target("persistence-segments.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/persistence\/(?:repository|schema|canonical|sqlite)\.mjs$/u,
        targets: [
            target("persistence-event-log.test.mjs"),
            target("persistence-segments.test.mjs"),
            target("persistence-commands.test.mjs"),
            target("persistence-safety.test.mjs"),
        ],
    },
    {
        pattern:
            /^crucible\/persistence\/(?:resource-catalog|resource-catalog-schema)\.mjs$/u,
        targets: [
            target("runtime-resource-broker.test.mjs"),
            target("persistence-recovery-catalog.test.mjs"),
            target("persistence-retention.test.mjs"),
        ],
        releaseTargets: [
            target("runtime-resource-broker.release.test.mjs", "release"),
        ],
    },
    {
        pattern: /^crucible\/persistence\/retention\.mjs$/u,
        targets: [target("persistence-retention.test.mjs")],
    },
    {
        pattern: /^crucible\/persistence\/paths\.mjs$/u,
        targets: [
            target("persistence-safety.test.mjs"),
            target("runtime-identity.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/persistence\/(?:errors|index)\.mjs$/u,
        targets: [
            target("persistence-safety.test.mjs"),
            target("persistence-event-log.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/runtime\/runner\.mjs$/u,
        targets: [target("runtime-runner.test.mjs")],
        releaseTargets: [
            target(
                "runtime-runner.release.test.mjs",
                "release",
                "recovers deterministically after a hard kill|owns the exact harness process tree|blocks automatic replay",
            ),
        ],
    },
    {
        pattern:
            /^crucible\/runtime\/(?:config|supervisor)\.mjs$/u,
        targets: [
            target("runtime-supervisor.test.mjs"),
            target("runtime-cli.test.mjs"),
        ],
        releaseTargets: [
            target("v4-unattended-gate.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/runtime\/(?:config-validation|resource-broker)\.mjs$/u,
        targets: [
            target("runtime-resource-broker.test.mjs"),
            target("runtime-runner.test.mjs"),
        ],
        releaseTargets: [
            target("runtime-resource-broker.release.test.mjs", "release"),
        ],
    },
    {
        pattern: /^crucible\/runtime\/worker-pool\.mjs$/u,
        targets: [
            target("runtime-worker-pool.test.mjs"),
            target("runtime-worker-pool-retry.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/runtime\/retry-policy\.mjs$/u,
        targets: [
            target("runtime-sdk-retry-policy.test.mjs"),
            target("runtime-worker-pool-retry.test.mjs"),
        ],
    },
    {
        pattern:
            /^crucible\/runtime\/(?:sdk-availability|sdk-probe)\.mjs$/u,
        targets: [target("runtime-sdk-availability.test.mjs")],
        releaseTargets: [
            target("runtime-sdk-cli.integration.test.mjs", "integration"),
        ],
    },
    {
        pattern: /^crucible\/runtime\/prompt-context\.mjs$/u,
        targets: [
            target("runtime-prompt-context.test.mjs"),
            target("runtime-prediction-feedback.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/runtime\/measurement-scheduler\.mjs$/u,
        targets: [target("runtime-measurement-scheduler.test.mjs")],
    },
    {
        pattern: /^crucible\/runtime\/domain-adapter\.mjs$/u,
        targets: [
            target("runtime-domain-adapter.test.mjs"),
            target("runtime-prediction-feedback.test.mjs"),
        ],
        releaseTargets: [
            target("runtime-domain-adapter.release.test.mjs", "release"),
            target(
                "runtime-runner.release.test.mjs",
                "release",
                "recovers a committed impossibility verifier effect|recovers a capsule-persisted impossibility verifier effect",
            ),
        ],
    },
    {
        pattern:
            /^crucible\/runtime\/(?:runtime-identity|config-authority)\.mjs$/u,
        targets: [
            target("runtime-identity.test.mjs"),
            target("api-preflight.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/runtime\/control-channel\.mjs$/u,
        targets: [target("runtime-control-channel.test.mjs")],
    },
    {
        pattern: /^crucible\/runtime\/discovery\.mjs$/u,
        targets: [target("runtime-discovery.test.mjs")],
    },
    {
        pattern:
            /^crucible\/runtime\/(?:recovery-daemon|recovery-daemon-cli)\.mjs$/u,
        targets: [
            target("runtime-recovery-daemon.test.mjs"),
            target("runtime-recovery-cli.test.mjs"),
        ],
        releaseTargets: [
            target("runtime-recovery-daemon.release.test.mjs", "release"),
            target(
                "windows-conformance/recovery-task.conformance.test.mjs",
                "windows",
            ),
        ],
    },
    {
        pattern: /^crucible\/runtime\/process-identity\.mjs$/u,
        targets: [target("runtime-process-identity.test.mjs")],
    },
    {
        pattern: /^crucible\/runtime\/enumerand-execution\.mjs$/u,
        targets: [target("runtime-integration-wiring.test.mjs")],
    },
    {
        pattern: /^crucible\/runtime\/extension-adapter\.mjs$/u,
        targets: [
            target("runtime-integration-wiring.test.mjs"),
            target("api-handlers.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/runtime\/.*cli\.mjs$/u,
        targets: [target("runtime-cli.test.mjs")],
    },
    {
        pattern: /^crucible\/runtime\/utils\.mjs$/u,
        targets: [target("runtime-utils-failure-matrix.test.mjs")],
    },
    {
        pattern: /^crucible\/runtime\/(?:errors|index|outcome)\.mjs$/u,
        targets: [target("runtime-runner.test.mjs")],
    },
    {
        pattern:
            /^crucible\/tools\/(?:configure-harness)(?:\.mjs)?$/u,
        targets: [target("tools-configure-harness.test.mjs")],
    },
    {
        pattern:
            /^crucible\/tools\/(?:configure-experiment)(?:\.mjs)?$/u,
        targets: [target("tools-configure-experiment.test.mjs")],
    },
    {
        pattern:
            /^crucible\/tools\/(?:configure-recovery-task|control-recovery-task|install-recovery-task|uninstall-recovery-task|recovery-launcher|recovery-task|recovery-task-cli)\.(?:mjs|ps1)$/u,
        targets: [target("tools-recovery-task.test.mjs")],
        releaseTargets: [
            target(
                "windows-conformance/recovery-task.conformance.test.mjs",
                "windows",
            ),
        ],
    },
    {
        pattern: /^crucible\/scripts\/run-v4-science-benchmark\.mjs$/u,
        targets: [
            target("science-fixtures/v4-science-gate.test.mjs", "science"),
        ],
    },
    {
        pattern:
            /^scripts\/run-crucible-related\.mjs$/u,
        targets: [target("release-plumbing.test.mjs")],
    },
    {
        pattern:
            /^scripts\/run-crucible-fast\.mjs$/u,
        targets: [target("release-plumbing.test.mjs")],
    },
    {
        pattern:
            /^scripts\/run-crucible-unattended-release\.mjs$/u,
        targets: [target("release-plumbing.test.mjs")],
    },
    {
        pattern: /^scripts\/run-crucible-integration\.mjs$/u,
        targets: [
            target("runtime-sdk-availability.test.mjs"),
            target("release-plumbing.test.mjs"),
        ],
        releaseTargets: [
            target("runtime-sdk-cli.integration.test.mjs", "integration"),
        ],
    },
    {
        pattern: /^scripts\/run-crucible-windows-conformance\.mjs$/u,
        targets: [target("release-plumbing.test.mjs")],
        releaseTargets: [
            target(
                "windows-conformance/windows-sandbox.conformance.test.mjs",
                "windows",
            ),
            target(
                "windows-conformance/recovery-task.conformance.test.mjs",
                "windows",
            ),
        ],
    },
    {
        pattern: /^(?:package\.json|vitest(?:\.[^.]+)*\.config\.mjs)$/u,
        targets: [target("release-plumbing.test.mjs")],
    },
];

const FIXTURE_RULES = [
    {
        pattern:
            /^crucible\/__tests__\/experiment-authority-fixture\.mjs$/u,
        targets: [
            target("api-preflight.test.mjs"),
            target("tools-configure-experiment.test.mjs"),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/harness-identity-fixture\.mjs$/u,
        targets: [
            target("measurement-harness-suite.test.mjs"),
            target("tools-configure-harness.test.mjs"),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/impossibility-runner-fixture\.mjs$/u,
        targets: [target("runtime-integration-wiring.test.mjs")],
        releaseTargets: [
            target(
                "runtime-impossibility-verification.release.test.mjs",
                "release",
            ),
            target(
                "runtime-runner.release.test.mjs",
                "release",
                "runs the allowlisted verifier|keeps a .* impossibility certificate|recovers a committed impossibility verifier effect|recovers a capsule-persisted impossibility verifier effect",
            ),
        ],
    },
    {
        pattern: /^crucible\/__tests__\/legacy-v3-fixture\.mjs$/u,
        targets: [target("api-lifecycle.test.mjs")],
        releaseTargets: [
            target("persistence-bundle.release.test.mjs", "release"),
            target("api-handlers.release.test.mjs", "release"),
        ],
    },
    {
        pattern: /^crucible\/__tests__\/measurement-fixtures\.mjs$/u,
        targets: [
            target("measurement-executor.test.mjs"),
            target("measurement-fs-verify.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/__tests__\/test-cleanup\.mjs$/u,
        targets: [
            target("api-preflight.test.mjs"),
            target("runtime-worker-pool.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/__tests__\/v4-contract-fixture\.mjs$/u,
        targets: [
            target("v4-stat-contract.test.mjs"),
            target("domain-kernel.test.mjs"),
        ],
    },
    {
        pattern: /^crucible\/__tests__\/v4-replay-stats-fixture\.mjs$/u,
        targets: [target("v4-replay-stats.test.mjs")],
        releaseTargets: [
            target("v4-replay-stats.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/fixtures\/domain-fence-race-worker\.mjs$/u,
        releaseTargets: [
            target("runtime-domain-adapter.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/fixtures\/recovery-daemon-kill-worker\.mjs$/u,
        releaseTargets: [
            target("runtime-recovery-daemon.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/fixtures\/resource-broker-process\.mjs$/u,
        releaseTargets: [
            target("runtime-resource-broker.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/fixtures\/runtime-runner-kill-worker\.mjs$/u,
        releaseTargets: [
            target(
                "runtime-runner.release.test.mjs",
                "release",
                "recovers deterministically after a hard kill",
            ),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/fixtures\/segment-rotation-kill-worker\.mjs$/u,
        releaseTargets: [
            target("persistence-segments.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/fixtures\/supervisor-kill-worker\.mjs$/u,
        releaseTargets: [
            target("v4-unattended-gate.release.test.mjs", "release"),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/windows-conformance\/(?:conformance-fixtures|recovery-task-fixture)\.mjs$/u,
        releaseTargets: [
            target(
                "windows-conformance/recovery-task.conformance.test.mjs",
                "windows",
            ),
            target(
                "windows-conformance/windows-sandbox.conformance.test.mjs",
                "windows",
            ),
        ],
    },
    {
        pattern:
            /^crucible\/__tests__\/science-fixtures\/(?:(?:fixtures|oracle|v4-adapter|v4-verifier-fixture)\.mjs)$/u,
        releaseTargets: [
            target("science-fixtures/v4-science-gate.test.mjs", "science"),
            target(
                "science-fixtures/v4-runner-science.release.test.mjs",
                "science",
            ),
        ],
    },
];

function normalizeInput(file, root = ROOT) {
    if (typeof file !== "string" || file.trim().length === 0) return null;
    const absolute = path.isAbsolute(file)
        ? path.resolve(file)
        : path.resolve(root, file);
    const relative = path.relative(root, absolute);
    if (relative === ""
        || relative.startsWith(`..${path.sep}`)
        || path.isAbsolute(relative)) {
        return null;
    }
    return relative.replaceAll("\\", "/");
}

export function isCrucibleOwnershipInput(file) {
    const normalized = normalizeInput(file);
    if (normalized === null) return false;
    if (TOP_LEVEL_INPUTS.has(normalized)) return true;
    if (/^scripts\/run-crucible-.*\.mjs$/u.test(normalized)) return true;
    if (normalized.split("/").some((segment) => segment.startsWith("."))) {
        return false;
    }
    return normalized.startsWith("crucible/")
        && SOURCE_EXTENSIONS.has(path.extname(normalized).toLowerCase());
}

function directTestTarget(input) {
    if (!input.startsWith(TEST_ROOT) || !input.endsWith(".test.mjs")) {
        return null;
    }
    if (input.includes("/windows-conformance/")
        && input.endsWith(".conformance.test.mjs")) {
        return target(input.slice(TEST_ROOT.length), "windows");
    }
    if (input.endsWith(".integration.test.mjs")) {
        return target(input.slice(TEST_ROOT.length), "integration");
    }
    if (input.includes("/science-fixtures/")
        && input.endsWith(".release.test.mjs")) {
        return target(input.slice(TEST_ROOT.length), "science");
    }
    if (input.endsWith(".release.test.mjs")) {
        return target(input.slice(TEST_ROOT.length), "release");
    }
    return target(input.slice(TEST_ROOT.length));
}

function targetsForRule(rule, includeRelease) {
    return [
        ...(rule.targets ?? []),
        ...(includeRelease ? rule.releaseTargets ?? [] : []),
    ];
}

export function resolveOwnership(inputs, { includeRelease = false } = {}) {
    const targets = [];
    const unmatched = [];
    const releaseRequired = [];
    const normalizedInputs = [];

    for (const rawInput of inputs) {
        const input = normalizeInput(rawInput);
        if (input === null || !isCrucibleOwnershipInput(input)) {
            unmatched.push(String(rawInput));
            continue;
        }
        normalizedInputs.push(input);
        const direct = directTestTarget(input);
        if (direct !== null) {
            if (direct.tier === "unit" || includeRelease) {
                targets.push(direct);
            } else {
                releaseRequired.push(input);
            }
            continue;
        }

        const rules = input.startsWith(TEST_ROOT) ? FIXTURE_RULES : RULES;
        const rule = rules.find((candidate) => candidate.pattern.test(input));
        if (rule === undefined) {
            unmatched.push(input);
            continue;
        }
        const owned = targetsForRule(rule, includeRelease);
        if (owned.length === 0 && (rule.releaseTargets?.length ?? 0) > 0) {
            releaseRequired.push(input);
            continue;
        }
        targets.push(...owned);
    }

    const unique = new Map();
    for (const item of targets) {
        unique.set(
            `${item.tier}\0${item.pattern ?? ""}\0${item.file}`,
            item,
        );
    }
    return Object.freeze({
        inputs: Object.freeze([...new Set(normalizedInputs)].sort()),
        targets: Object.freeze([...unique.values()].sort((left, right) =>
            `${left.tier}\0${left.pattern ?? ""}\0${left.file}`
                .localeCompare(`${right.tier}\0${right.pattern ?? ""}\0${right.file}`))),
        unmatched: Object.freeze([...new Set(unmatched)].sort()),
        releaseRequired: Object.freeze(
            [...new Set(releaseRequired)].sort(),
        ),
    });
}

function walkFiles(root, relativeRoot) {
    const absoluteRoot = path.join(root, ...relativeRoot.split("/"));
    if (!fs.existsSync(absoluteRoot)) return [];
    const files = [];
    const stack = [absoluteRoot];
    while (stack.length > 0) {
        const current = stack.pop();
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const child = path.join(current, entry.name);
            if (entry.isDirectory()) {
                if (entry.name.startsWith(".")
                    || entry.name === "node_modules") {
                    continue;
                }
                stack.push(child);
            } else if (entry.isFile()) {
                const relative = path.relative(root, child).replaceAll("\\", "/");
                if (isCrucibleOwnershipInput(relative)) files.push(relative);
            }
        }
    }
    return files;
}

export function listCurrentOwnershipInputs(root = ROOT) {
    const inputs = [
        ...walkFiles(root, "crucible"),
        ...walkFiles(root, "scripts")
            .filter((file) => /^scripts\/run-crucible-.*\.mjs$/u.test(file)),
    ];
    for (const file of TOP_LEVEL_INPUTS) {
        if (fs.existsSync(path.join(root, file))) inputs.push(file);
    }
    return Object.freeze([...new Set(inputs)].sort());
}

function gitLines(args) {
    const output = execFileSync("git", args, {
        cwd: ROOT,
        encoding: "utf8",
        windowsHide: true,
        stdio: ["ignore", "pipe", "inherit"],
    });
    return output.split(/\r?\n/u)
        .map((line) => line.trim())
        .filter(Boolean);
}

function changedInputs() {
    return [
        ...gitLines([
            "diff",
            "--name-only",
            "--diff-filter=ACDMRTUXB",
            "HEAD",
        ]),
        ...gitLines(["ls-files", "--others", "--exclude-standard"]),
    ].filter(isCrucibleOwnershipInput);
}

function configForTier(tier) {
    if (tier === "unit") return null;
    const name = {
        release: "vitest.crucible-release.config.mjs",
        integration: "vitest.crucible-integration.config.mjs",
        science: "vitest.crucible-science.config.mjs",
        windows: "vitest.windows-conformance.config.mjs",
    }[tier];
    if (name === undefined) {
        throw new Error(`unsupported Crucible ownership tier ${tier}`);
    }
    return path.join(ROOT, name);
}

function runTargets(targets) {
    const vitest = path.join(ROOT, "node_modules", "vitest", "vitest.mjs");
    const groups = new Map();
    for (const item of targets) {
        const key = `${item.tier}\0${item.pattern ?? ""}`;
        const group = groups.get(key) ?? {
            tier: item.tier,
            pattern: item.pattern,
            files: [],
        };
        group.files.push(item.file);
        groups.set(key, group);
    }

    for (const group of groups.values()) {
        const config = configForTier(group.tier);
        const args = [
            vitest,
            "run",
            ...(config === null ? [] : ["--config", config]),
            ...[...new Set(group.files)].sort(),
            ...(group.pattern === null
                ? []
                : ["--testNamePattern", group.pattern]),
        ];
        const result = spawnSync(process.execPath, args, {
            cwd: ROOT,
            env: group.tier === "windows"
                ? {
                    ...process.env,
                    CRUCIBLE_WINDOWS_CONFORMANCE: "1",
                }
                : process.env,
            stdio: "inherit",
            windowsHide: true,
            timeout: group.tier === "unit" ? 120_000 : 360_000,
        });
        if (result.error?.code === "ETIMEDOUT") {
            process.stderr.write(
                `Mapped ${group.tier} tests exceeded ${
                    group.tier === "unit" ? 120 : 360
                } seconds; select a narrower explicit test target.\n`,
            );
            return 124;
        }
        if (result.error !== undefined) {
            process.stderr.write(
                `Mapped ${group.tier} tests failed to start: ${result.error.message}\n`,
            );
            return 1;
        }
        if (result.status !== 0) return result.status ?? 1;
    }
    return 0;
}

export function main(argv = process.argv.slice(2)) {
    const includeRelease = argv.includes("--release");
    const explicit = argv.filter((arg) => arg !== "--release");
    const inputs = explicit.length > 0 ? explicit : changedInputs();
    if (inputs.length === 0) {
        process.stderr.write(
            "No changed Crucible source, test, PowerShell, or test configuration files were found.\n",
        );
        return 2;
    }

    const selection = resolveOwnership(inputs, { includeRelease });
    if (selection.unmatched.length > 0) {
        process.stderr.write(
            `No Crucible test ownership mapping exists for:\n${
                selection.unmatched.map((file) => `  - ${file}`).join("\n")
            }\nRefusing to run an unrelated fallback suite.\n`,
        );
        return 2;
    }
    if (selection.releaseRequired.length > 0) {
        process.stderr.write(
            `Release-gated Crucible inputs require --release:\n${
                selection.releaseRequired.map((file) => `  - ${file}`).join("\n")
            }\n`,
        );
        return 2;
    }
    if (selection.targets.length === 0) {
        process.stderr.write(
            "Crucible ownership resolution produced no test targets; refusing to continue.\n",
        );
        return 2;
    }
    return runTargets(selection.targets);
}

const isEntrypoint = process.argv[1] !== undefined
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
    process.exitCode = main();
}
