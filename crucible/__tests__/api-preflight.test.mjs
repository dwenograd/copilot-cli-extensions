import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    CONTRACT_LIMITS,
    normalizeEnumerandManifest,
} from "../domain/index.mjs";
import {
    DEFAULT_PROMPT_CONTEXT_BYTE_CAP,
    RuntimeConfigError,
    createDomainRepositoryAdapter,
    normalizeSupervisorConfig,
} from "../runtime/index.mjs";
import {
    loadHarnessAllowlist,
} from "../measurement/index.mjs";
import {
    openArtifactStore,
    openArtifactStoreReadOnly,
    openRepository,
    openRepositoryReadOnly,
} from "../persistence/index.mjs";
import {
    applyStartPreflight,
    disposeStartPreflight,
    preflightStartInvestigation,
} from "../api/preflight.mjs";
import { startInvestigation } from "../api/handlers.mjs";
import {
    ExperimentAuthorityMismatchApiError,
    ExperimentRegistryApiError,
    HarnessConfigurationError,
    SandboxUnavailableApiError,
    StartPreflightError,
} from "../api/errors.mjs";
import {
    EXPERIMENT_REGISTRY_ERROR_CODES,
} from "../api/experiment-registry.mjs";
import { configureExperiment } from "../tools/configure-experiment.mjs";
import {
    buildHarnessSuiteForAllowlist,
    fakeHypothesisPolicy,
    fakeObservableRegistry,
    fakeStatisticalPolicy,
} from "./v4-contract-fixture.mjs";
import {
    createExperimentAuthorityFixture,
    prepareAndSignExperiment,
} from "./experiment-authority-fixture.mjs";
import { removeTrackedRoots } from "./test-cleanup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(async () => {
    await removeTrackedRoots(roots, {
        label: "api-preflight test root",
    });
});

function makeWorkspace(label, entryOverrides = {}) {
    const root = fs.mkdtempSync(path.join(HERE, `.api-preflight-${label}-`));
    roots.push(root);
    const authority = createExperimentAuthorityFixture();
    const projectDir = path.join(root, "project");
    const goodDir = path.join(projectDir, "cases", "good");
    const badDir = path.join(projectDir, "cases", "bad");
    fs.mkdirSync(goodDir, { recursive: true });
    fs.mkdirSync(badDir, { recursive: true });
    fs.writeFileSync(path.join(goodDir, "input.txt"), "good-case");
    fs.writeFileSync(path.join(badDir, "input.txt"), "bad-case");

    const fixtureStoreRoot = path.join(root, "operator-corpus");
    const fixtureStore = openArtifactStore({ root: fixtureStoreRoot });
    const goodSnapshot = fixtureStore.ingestDirectory({ sourceDir: goodDir }).snapshot;
    const badSnapshot = fixtureStore.ingestDirectory({ sourceDir: badDir }).snapshot;
    const extraCases = {};
    for (const [id, text] of [
        ["search", "search-case"],
        ["confirmation", "confirmation-case"],
        ["challenge", "challenge-case"],
        ["novelty", "novelty-case"],
    ]) {
        const sourceDir = path.join(root, `${id}-case`);
        fs.mkdirSync(sourceDir, { recursive: true });
        fs.writeFileSync(path.join(sourceDir, "input.txt"), text);
        extraCases[id] = fixtureStore.ingestDirectory({ sourceDir }).snapshot;
    }

    const allowlistPath = path.join(root, "harnesses.json");
    const harnessExecutable = path.join(root, "trusted-harness.exe");
    fs.writeFileSync(harnessExecutable, "trusted harness executable fixture");
    const harnessExecutableSha256 = createHash("sha256")
        .update(fs.readFileSync(harnessExecutable))
        .digest("hex");
    const harnessScript = path.join(root, "trusted-harness.mjs");
    fs.writeFileSync(harnessScript, "process.stdout.write('{\"pass\":true}');\n");
    const harnessScriptSha256 = createHash("sha256")
        .update(fs.readFileSync(harnessScript))
        .digest("hex");
    const baseEntry = {
        executable: harnessExecutable,
        executableSha256: harnessExecutableSha256,
        argvTemplate: [harnessScript],
        dependencies: [{
            path: harnessScript,
            sha256: harnessScriptSha256,
            role: "script",
        }],
        allowedEnv: { CRUCIBLE_MODE: "strict" },
        timeoutMs: 15_000,
        maxStdoutBytes: 1024 * 1024,
        maxStderrBytes: 256 * 1024,
        executesCandidateCode: entryOverrides.executesCandidateCode ?? false,
        validationCases: {
            good: { snapshotHash: goodSnapshot, expectation: "accept" },
            bad: { snapshotHash: badSnapshot, expectation: "reject" },
            search: { snapshotHash: extraCases.search, expectation: "accept" },
            confirmation: {
                snapshotHash: extraCases.confirmation,
                expectation: "accept",
            },
            challenge: {
                snapshotHash: extraCases.challenge,
                expectation: "reject",
            },
            novelty: { snapshotHash: extraCases.novelty, expectation: "accept" },
        },
    };
    const initial = {
        version: 1,
        entries: { "primary-harness": baseEntry },
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(initial));
    const initialAllowlist = loadHarnessAllowlist(allowlistPath);
    initial.suites = {
        "primary-suite": buildHarnessSuiteForAllowlist(initialAllowlist, {
            sandboxPolicyDigest: baseEntry.executesCandidateCode
                ? `sha256:crucible-test-sandbox-v1:${"a".repeat(64)}`
                : null,
            roleCaseIds: {
                calibration: ["good", "bad"],
                search: ["search"],
                confirmation: ["confirmation"],
                challenge: ["challenge"],
                novelty: ["novelty"],
            },
        }),
    };
    initial.entries["primary-harness"] = {
        ...baseEntry,
        ...entryOverrides,
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(initial));

    const stateRoot = path.join(root, "state-root");
    const experimentRegistryPath = path.join(root, "experiments.json");
    const env = {
        CRUCIBLE_ALLOWLIST_PATH: allowlistPath,
        CRUCIBLE_CASE_STORE_PATH: fixtureStoreRoot,
        CRUCIBLE_EXPERIMENT_REGISTRY_PATH: experimentRegistryPath,
        CRUCIBLE_STATE_ROOT: stateRoot,
        COPILOT_SDK_PATH: path.join(root, "sdk"),
        COPILOT_CLI_PATH: path.join(root, "copilot.exe"),
        ...authority.env,
    };
    fs.mkdirSync(env.COPILOT_SDK_PATH, { recursive: true });
    fs.writeFileSync(
        path.join(env.COPILOT_SDK_PATH, "index.js"),
        "export {};\n",
    );
    fs.writeFileSync(env.COPILOT_CLI_PATH, "fixture copilot cli");
    return {
        root,
        projectDir,
        goodDir,
        badDir,
        goodSnapshot,
        badSnapshot,
        caseStorePath: fixtureStoreRoot,
        allowlistPath,
        experimentRegistryPath,
        stateRoot,
        env,
        authority,
    };
}

function startArgs(workspace, overrides = {}) {
    const { projectDir } = workspace;
    const configured = JSON.parse(fs.readFileSync(
        path.join(path.dirname(projectDir), "harnesses.json"),
        "utf8",
    ));
    const controlSnapshot =
        configured.entries["primary-harness"].validationCases?.good?.snapshotHash
        ?? `sha256:${"f".repeat(64)}`;
    const statisticalPolicy = fakeStatisticalPolicy({
        topology: overrides.hypothesis_topology ?? "open_generative",
        searchSlots:
            (overrides.candidates_per_round ?? 1)
            * (overrides.max_rounds ?? 2),
        control: { kind: "snapshot", identity: controlSnapshot },
    });
    const {
        deadline_iso,
        ...authorityOverrides
    } = overrides;
    const authority = {
        objective: "find a candidate scoring at least 90",
        project_dir: projectDir,
        harness_suite_id: "primary-suite",
        acceptance_predicate: {
            kind: "all",
            predicates: [
                { kind: "harness_pass" },
                { kind: "metric_compare", metric: "score", operator: ">=", value: 90 },
            ],
        },
        hypothesis_topology: "open_generative",
        observable_registry: fakeObservableRegistry().map((observable) => ({
            ...observable,
            maximum: 100,
        })),
        hypothesis_policy: fakeHypothesisPolicy(),
        statistical_policy: {
            ...statisticalPolicy,
            metrics: statisticalPolicy.metrics.map((metric) => ({
                ...metric,
                maximum: 100,
                acceptanceThreshold: 90,
                practicalEquivalenceDelta: 1,
            })),
        },
        worker_models: ["model-a"],
        candidates_per_round: 1,
        max_rounds: 2,
        ...authorityOverrides,
    };
    const experiment_id = `test-${createHash("sha256")
        .update(JSON.stringify(authority))
        .digest("hex")
        .slice(0, 24)}`;
    const root = path.dirname(projectDir);
    const registryPath = path.join(root, "experiments.json");
    const config = {
        experiment_id,
        ...authority,
    };
    const { signature } = prepareAndSignExperiment({
        config,
        allowlistPath: path.join(root, "harnesses.json"),
        env: workspace.env,
        privateKey: workspace.authority.privateKey,
    });
    configureExperiment({
        config,
        registryPath,
        allowlistPath: path.join(root, "harnesses.json"),
        signature,
        env: {
            ...workspace.env,
        },
    });
    return {
        experiment_id,
        ...(deadline_iso === undefined ? {} : { deadline_iso }),
    };
}

function makeDeps(workspace, overrides = {}) {
    const calls = { ensure: [] };
    return {
        calls,
        deps: {
            env: workspace.env,
            log: () => {},
            clock: { now: () => Date.parse("2030-01-01T00:00:00.000Z") },
            loadHarnessAllowlist,
            probeSandboxAvailability: () => ({ available: true }),
            normalizeSupervisorConfig,
            openArtifactStore,
            openArtifactStoreReadOnly,
            openRepository,
            openRepositoryReadOnly,
            createDomainRepositoryAdapter,
            ensureSupervisor: (config, options) => {
                calls.ensure.push({ config, options });
                return {
                    action: "started",
                    pid: 4242,
                    acknowledged: true,
                    acknowledgement: {
                        supervisorGeneration: 1,
                        runnerIncarnation: "fixture-runner-incarnation",
                        configFingerprint: "sha256:fixture-supervisor-config",
                        deadlineMs: config.runner.deadlineMs,
                    },
                };
            },
            ...overrides,
        },
    };
}

function expectNoPersistentSideEffects(workspace) {
    expect(fs.existsSync(workspace.stateRoot)).toBe(false);
    expect(
        fs.readdirSync(workspace.root)
            .filter((name) => name.startsWith(".crucible-preflight-")),
    ).toEqual([]);
}

async function expectRejectedWithoutState(workspace, args, deps, expectedError) {
    await expect(Promise.resolve().then(() => startInvestigation(args, deps)))
        .rejects.toBeInstanceOf(expectedError);
    expectNoPersistentSideEffects(workspace);
}

describe("crucible_start lifecycle preflight", () => {
    it.each([
        [
            "oversized objective",
            (workspace) => startArgs(workspace, {
                objective: "x".repeat(CONTRACT_LIMITS.objectiveCharacters + 1),
            }),
        ],
        [
            "oversized predicate",
            (workspace) => startArgs(workspace, {
                acceptance_predicate: {
                    kind: "field_equals",
                    path: "value",
                    value: "x".repeat(17 * 1024),
                },
            }),
        ],
        [
            "unsafe dot-dot id",
            (workspace) => startArgs(workspace, {
                worker_models: ["model..escape"],
            }),
        ],
        [
            "duplicate metric keys",
            (workspace) => startArgs(workspace, {
                metrics: [
                    { key: "score", direction: "max" },
                    { key: "score", direction: "min" },
                ],
            }),
        ],
        [
            "validation set without a reject",
            (workspace) => startArgs(workspace, {
                validation_cases: [
                    { id: "good", expectation: "accept", path: "cases/good" },
                    { id: "bad", expectation: "accept", path: "cases/bad" },
                ],
            }),
        ],
    ])("rejects %s before creating persistent state", async (_label, buildArgs) => {
        const workspace = makeWorkspace(`schema-${_label.replaceAll(" ", "-")}`);
        const { deps } = makeDeps(workspace);
        await expect(Promise.resolve().then(() =>
            startInvestigation(buildArgs(workspace), deps))).rejects.toThrow();
        expectNoPersistentSideEffects(workspace);
    });

    it("rejects invalid, past, and non-calendar ISO deadlines before state", async () => {
        const incomplete = makeWorkspace("deadline-incomplete");
        const { deps: incompleteDeps } = makeDeps(incomplete);
        await expect(Promise.resolve().then(() => startInvestigation(
            startArgs(incomplete, { deadline_iso: "2031-01-01" }),
            incompleteDeps,
        ))).rejects.toThrow();
        expectNoPersistentSideEffects(incomplete);

        for (const deadline_iso of [
            "2031-02-30T00:00:00.000Z",
            "2029-12-31T23:59:59.999Z",
        ]) {
            const workspace = makeWorkspace(`deadline-${deadline_iso.replaceAll(":", "-")}`);
            const { deps } = makeDeps(workspace);
            await expectRejectedWithoutState(
                workspace,
                startArgs(workspace, { deadline_iso }),
                deps,
                StartPreflightError,
            );
        }
    });

    it("rejects a tampered operator experiment registry without state", async () => {
        const workspace = makeWorkspace("registry-tamper");
        const { deps } = makeDeps(workspace);
        const args = startArgs(workspace);
        const tampered = JSON.parse(fs.readFileSync(
            workspace.experimentRegistryPath,
            "utf8",
        ));
        tampered.experiments[args.experiment_id].contract.objective =
            "prompt-injected objective";
        fs.writeFileSync(
            workspace.experimentRegistryPath,
            JSON.stringify(tampered),
        );
        await expectRejectedWithoutState(
            workspace,
            args,
            deps,
            ExperimentRegistryApiError,
        );
    });

    it("rejects bounded search sets that exceed frozen round capacity before state", async () => {
        const workspace = makeWorkspace("round-capacity");
        const { deps } = makeDeps(workspace);
        const manifest = normalizeEnumerandManifest({
            topology: "finite_enumerable",
            entries: [
                {
                    id: "candidate-a",
                    ordinal: 0,
                    artifactSnapshotHash: workspace.goodSnapshot,
                },
                {
                    id: "candidate-b",
                    ordinal: 1,
                    artifactSnapshotHash: workspace.badSnapshot,
                },
                {
                    id: "candidate-c",
                    ordinal: 2,
                    artifactSnapshotHash:
                        JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"))
                            .entries["primary-harness"].validationCases.search.snapshotHash,
                },
            ],
            control: { kind: "enumerand", ordinal: 0 },
        });
        const statisticalPolicy = fakeStatisticalPolicy({
            topology: "finite_enumerable",
            searchSlots: manifest.entries.length,
            manifest,
        });
        await expect(Promise.resolve().then(() =>
            startArgs(workspace, {
                hypothesis_topology: "finite_enumerable",
                candidates_per_round: 1,
                max_rounds: 2,
                enumerand_manifest: {
                    topology: manifest.topology,
                    entries: manifest.entries.map((entry) => ({
                        id: entry.id,
                        ordinal: entry.ordinal,
                        artifactSnapshotHash: entry.artifactSnapshotHash,
                    })),
                    control: { kind: "enumerand", ordinal: 0 },
                },
                statistical_policy: {
                    ...statisticalPolicy,
                    metrics: statisticalPolicy.metrics.map((metric) => ({
                        ...metric,
                        maximum: 100,
                        acceptanceThreshold: 90,
                        practicalEquivalenceDelta: 1,
                    })),
                    control: {
                        kind: "enumerand",
                        tolerances: statisticalPolicy.control.tolerances,
                    },
                },
            }))).rejects.toMatchObject({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_INVALID,
        });
        expectNoPersistentSideEffects(workspace);
    });

    it("rejects finite and bounded topologies without bounded ids before state", async () => {
        for (const hypothesis_topology of ["finite_enumerable", "bounded_parameterized"]) {
            const workspace = makeWorkspace(`missing-bounded-${hypothesis_topology}`);
            const { deps } = makeDeps(workspace);
            await expect(Promise.resolve().then(() =>
                startArgs(workspace, { hypothesis_topology })))
                .rejects.toMatchObject({
                    code: EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_INVALID,
                });
            expectNoPersistentSideEffects(workspace);
        }
    });

    it("rejects oversized prompt inputs before state", async () => {
        const workspace = makeWorkspace("prompt-core");
        const { deps } = makeDeps(workspace);
        await expect(Promise.resolve().then(() => startInvestigation(
            startArgs(workspace, {
                objective: "o".repeat(4000),
                acceptance_predicate: {
                    kind: "field_equals",
                    path: "payload",
                    value: "p".repeat(12_500),
                },
            }),
            deps,
        ))).rejects.toThrow();
        expectNoPersistentSideEffects(workspace);
    });

    it("rejects predicate complexity and metric-count audit reproductions before state", async () => {
        const cases = [
            (() => {
                let predicate = { kind: "harness_pass" };
                for (let index = 0;
                    index <= CONTRACT_LIMITS.acceptancePredicateDepth;
                    index += 1) {
                    predicate = { kind: "not", predicate };
                }
                return { acceptance_predicate: predicate };
            })(),
            {
                acceptance_predicate: {
                    kind: "all",
                    predicates: Array.from(
                        { length: CONTRACT_LIMITS.acceptancePredicateChildren + 1 },
                        () => ({ kind: "harness_pass" }),
                    ),
                },
            },
            {
                acceptance_predicate: {
                    kind: "field_equals",
                    path: "payload",
                    value: Array.from(
                        { length: CONTRACT_LIMITS.acceptanceValueArrayItems + 1 },
                        (_unused, index) => index,
                    ),
                },
            },
            {
                metrics: Array.from(
                    { length: CONTRACT_LIMITS.metrics + 1 },
                    (_unused, index) => ({
                        key: `metric-${index}`,
                        direction: "max",
                    }),
                ),
            },
        ];
        for (const [index, overrides] of cases.entries()) {
            const workspace = makeWorkspace(`contract-limit-${index}`);
            const { deps } = makeDeps(workspace);
            await expect(Promise.resolve().then(() =>
                startInvestigation(startArgs(workspace, overrides), deps)))
                .rejects.toThrow();
            expectNoPersistentSideEffects(workspace);
        }
    });

    it("serializes the worst-case legal trusted core before creating state", () => {
        const workspace = makeWorkspace("worst-legal-core");
        const { deps } = makeDeps(workspace);
        const plan = preflightStartInvestigation(startArgs(workspace, {
            objective: "o".repeat(CONTRACT_LIMITS.objectiveBytes),
            acceptance_predicate: {
                kind: "metric_compare",
                metric: "score",
                operator: ">=",
                value: 90,
            },
            candidates_per_round: CONTRACT_LIMITS.candidatesPerRound,
            max_rounds: CONTRACT_LIMITS.maxRounds,
        }), deps);
        try {
            expect(plan.promptCore.coreBytes)
                .toBeLessThanOrEqual(DEFAULT_PROMPT_CONTEXT_BYTE_CAP);
            expect(plan.supervisorConfig.runner.options.maxLoopIterations)
                .toBeGreaterThan(1000);
            expect(plan.supervisorConfig.maxRestarts).toBeGreaterThanOrEqual(3);
            expect(fs.existsSync(workspace.stateRoot)).toBe(false);
        } finally {
            disposeStartPreflight(plan);
        }
    });

    it("validates normalized supervisor/runner configuration before staging or state", async () => {
        const workspace = makeWorkspace("invalid-supervisor-config");
        const { deps } = makeDeps(workspace, {
            normalizeSupervisorConfig: () => {
                throw new RuntimeConfigError("injected invalid supervisor timing");
            },
        });
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace),
            deps,
            StartPreflightError,
        );
    });

    it("rejects an allowlist validation snapshot mismatch without publishing snapshots", async () => {
        const workspace = makeWorkspace("allowlist-mismatch");
        const args = startArgs(workspace);
        const raw = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        raw.entries["primary-harness"].validationCases.good.snapshotHash =
            `sha256:${"0".repeat(64)}`;
        fs.writeFileSync(workspace.allowlistPath, JSON.stringify(raw));
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            args,
            deps,
            HarnessConfigurationError,
        );
    });

    it("requires the allowlist entry to pin requested validation cases", async () => {
        const workspace = makeWorkspace("allowlist-cases-missing");
        const args = startArgs(workspace);
        const raw = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        delete raw.entries["primary-harness"].validationCases;
        fs.writeFileSync(workspace.allowlistPath, JSON.stringify(raw));
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            args,
            deps,
            HarnessConfigurationError,
        );
    });

    it("rejects an invalid allowlist schema before persistent state", async () => {
        const workspace = makeWorkspace("allowlist-schema-invalid");
        const args = startArgs(workspace);
        const raw = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        raw.entries["primary-harness"].unexpected = true;
        fs.writeFileSync(workspace.allowlistPath, JSON.stringify(raw));
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            args,
            deps,
            HarnessConfigurationError,
        );
    });

    it("rejects an executable hash mismatch without persistent state", async () => {
        const workspace = makeWorkspace("executable-mismatch");
        const args = startArgs(workspace);
        const raw = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        raw.entries["primary-harness"].executableSha256 = "0".repeat(64);
        fs.writeFileSync(workspace.allowlistPath, JSON.stringify(raw));
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            args,
            deps,
            HarnessConfigurationError,
        );
    });

    it("rejects a dependency hash mismatch without persistent state", async () => {
        const workspace = makeWorkspace("dependency-mismatch");
        const args = startArgs(workspace);
        const allowlist = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        fs.writeFileSync(
            allowlist.entries["primary-harness"].dependencies[0].path,
            "tampered dependency bytes\n",
        );
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            args,
            deps,
            HarnessConfigurationError,
        );
    });

    it("fails closed when a candidate-code sandbox is unavailable", async () => {
        const workspace = makeWorkspace("sandbox-unavailable", {
            executesCandidateCode: true,
        });
        const { deps } = makeDeps(workspace, {
            probeSandboxAvailability: async () => ({
                available: false,
                code: "CRUCIBLE_MEASUREMENT_SANDBOX_UNAVAILABLE",
                reason: "sandbox deliberately unavailable in test",
            }),
        });
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace),
            deps,
            SandboxUnavailableApiError,
        );
    });

    it("compensates a post-persistence supervisor failure to a durable pause", async () => {
        const workspace = makeWorkspace("apply-failure-cleanup");
        const { deps } = makeDeps(workspace, {
            ensureSupervisor: (config) => {
                fs.mkdirSync(config.paths.directory, { recursive: true });
                fs.writeFileSync(config.paths.configPath, "{}");
                throw new Error("injected supervisor launch failure");
            },
        });
        await expect(Promise.resolve().then(() =>
            startInvestigation(startArgs(workspace), deps)))
            .rejects.toThrow("injected supervisor launch failure");
        expect(fs.existsSync(workspace.stateRoot)).toBe(true);
        const investigationDir = fs.readdirSync(workspace.stateRoot)
            .map((name) => path.join(workspace.stateRoot, name))
            .find((candidate) => fs.existsSync(path.join(candidate, "state", "events.sqlite")));
        expect(investigationDir).toBeTruthy();
        const repository = openRepositoryReadOnly({
            file: path.join(investigationDir, "state", "events.sqlite"),
        });
        try {
            const adapter = createDomainRepositoryAdapter({
                repository,
                investigationId: path.basename(investigationDir),
                ensure: false,
            });
            expect(adapter.replay().aggregate.pause).not.toBeNull();
        } finally {
            repository.close();
        }
    });

    it("reports post-success preflight cleanup as a warning without failing start", async () => {
        const workspace = makeWorkspace("post-success-cleanup-warning");
        const messages = [];
        const { deps } = makeDeps(workspace, {
            log: (message) => messages.push(message),
            removePreflightWorkspace: () => {
                throw Object.assign(new Error("injected cleanup failure"), {
                    code: "EBUSY",
                });
            },
        });
        const result = await Promise.resolve(
            startInvestigation(startArgs(workspace), deps),
        );
        expect(result.supervisor.acknowledged).toBe(true);
        expect(result.cleanup_warning).toMatchObject({
            code: "CRUCIBLE_API_PREFLIGHT_FAILED",
            cause_code: "EBUSY",
            message: expect.stringContaining("injected cleanup failure"),
        });
        expect(messages.some((message) =>
            message.includes("durable start succeeded")
            && message.includes("injected cleanup failure"))).toBe(true);
        expect(fs.existsSync(result.events_db_path)).toBe(true);
    });

    it("returns one canonical plan and applies only its staged snapshots/config", () => {
        const workspace = makeWorkspace("canonical-plan");
        const { deps, calls } = makeDeps(workspace);
        const args = startArgs(workspace);
        const plan = preflightStartInvestigation(args, deps);
        expect(plan).not.toHaveProperty("then");
        expect(fs.existsSync(workspace.stateRoot)).toBe(false);
        expect(plan.contract.objective).toBe(
            "find a candidate scoring at least 90",
        );
        expect(plan.experimentId).toBe(args.experiment_id);
        expect(plan.hashes).toMatchObject({
            contractHash: expect.stringMatching(/^sha256:crucible-contract-v4:[a-f0-9]{64}$/u),
            experimentIdentity: expect.stringMatching(/^sha256:crucible-operator-experiment-v5:[a-f0-9]{64}$/u),
            experimentAuthorityIdentity: expect.stringMatching(/^sha256:crucible-experiment-authority-v1:[a-f0-9]{64}$/u),
            authorityManifestIdentity: expect.stringMatching(/^sha256:crucible-experiment-authority-manifest-v1:[a-f0-9]{64}$/u),
            trustFingerprint: expect.stringMatching(/^sha256:crucible-experiment-public-key-v1:[a-f0-9]{64}$/u),
            registryFileHash: expect.stringMatching(/^sha256:crucible-operator-experiment-registry-file-v1:[a-f0-9]{64}$/u),
            registryIdentity: expect.stringMatching(/^sha256:crucible-operator-experiment-registry-v2:[a-f0-9]{64}$/u),
            allowlistFileHash: expect.stringMatching(/^sha256:crucible-measurement-file-v1:[a-f0-9]{64}$/u),
            harnessSuiteIdentity: expect.stringMatching(/^sha256:crucible-harness-suite-v4:[a-f0-9]{64}$/u),
        });
        expect(Object.keys(plan.hashes.harnessRoleEntryHashes).sort()).toEqual([
            "calibration",
            "challenge",
            "confirmation",
            "novelty",
            "search",
        ]);
        expect(plan.supervisorConfig.paths.configPath)
            .toContain(path.join("state", "supervisor"));

        args.experiment_id = "mutated-raw-selection";
        fs.writeFileSync(path.join(workspace.goodDir, "input.txt"), "mutated-after-preflight");
        try {
            const applied = applyStartPreflight(plan, deps);
            expect(applied.opened.idempotent).toBe(false);
            expect(calls.ensure).toHaveLength(1);
            expect(calls.ensure[0].config).toBe(plan.supervisorConfig);
        } finally {
            disposeStartPreflight(plan);
        }

        const repository = openRepositoryReadOnly({ file: plan.paths.eventsDbPath });
        try {
            const adapter = createDomainRepositoryAdapter({
                repository,
                investigationId: plan.investigationId,
                ensure: false,
            });
            const aggregate = adapter.replay().aggregate;
            expect(aggregate.contract.objective).toBe("find a candidate scoring at least 90");
            const good = aggregate.contract.validationCases.find((item) => item.id === "good");
            const store = openArtifactStoreReadOnly({ root: plan.paths.artifactRoot });
            const manifest = store.loadManifest(good.artifactHash);
            expect(store.readObject(manifest.entries[0].object).toString("utf8"))
                .toBe("good-case");
        } finally {
            repository.close();
        }
        expect(
            fs.readdirSync(workspace.root)
                .filter((name) => name.startsWith(".crucible-preflight-")),
        ).toEqual([]);
    });

    it("rejects a trust-key change between preflight capability issuance and apply", () => {
        const workspace = makeWorkspace("authority-key-replay");
        const { deps, calls } = makeDeps(workspace);
        const plan = preflightStartInvestigation(startArgs(workspace), deps);
        const replacementTrust = createExperimentAuthorityFixture();
        deps.env = {
            ...workspace.env,
            ...replacementTrust.env,
        };
        try {
            expect(() => applyStartPreflight(plan, deps))
                .toThrow(ExperimentAuthorityMismatchApiError);
            expect(calls.ensure).toHaveLength(0);
            expect(fs.existsSync(plan.paths.eventsDbPath)).toBe(false);
        } finally {
            disposeStartPreflight(plan);
        }
    });
});
