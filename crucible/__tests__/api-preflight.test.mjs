import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
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
    HarnessConfigurationError,
    SandboxUnavailableApiError,
    StartPreflightError,
} from "../api/errors.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function makeWorkspace(label, entryOverrides = {}) {
    const root = fs.mkdtempSync(path.join(HERE, `.api-preflight-${label}-`));
    roots.push(root);
    const projectDir = path.join(root, "project");
    const goodDir = path.join(projectDir, "cases", "good");
    const badDir = path.join(projectDir, "cases", "bad");
    fs.mkdirSync(goodDir, { recursive: true });
    fs.mkdirSync(badDir, { recursive: true });
    fs.writeFileSync(path.join(goodDir, "input.txt"), "good-case");
    fs.writeFileSync(path.join(badDir, "input.txt"), "bad-case");

    const fixtureStoreRoot = path.join(root, "fixture-snapshots");
    const fixtureStore = openArtifactStore({ root: fixtureStoreRoot });
    const goodSnapshot = fixtureStore.ingestDirectory({ sourceDir: goodDir }).snapshot;
    const badSnapshot = fixtureStore.ingestDirectory({ sourceDir: badDir }).snapshot;
    fs.rmSync(fixtureStoreRoot, { recursive: true, force: true });

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
    const entry = {
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
        executesCandidateCode: false,
        validationCases: {
            good: { snapshotHash: goodSnapshot },
            bad: { snapshotHash: badSnapshot },
        },
        ...entryOverrides,
    };
    fs.writeFileSync(allowlistPath, JSON.stringify({
        version: 1,
        entries: { "primary-harness": entry },
    }));

    const stateRoot = path.join(root, "state-root");
    const env = {
        CRUCIBLE_ALLOWLIST_PATH: allowlistPath,
        CRUCIBLE_STATE_ROOT: stateRoot,
        COPILOT_SDK_PATH: path.join(root, "sdk"),
        COPILOT_CLI_PATH: path.join(root, "copilot.exe"),
    };
    return {
        root,
        projectDir,
        goodDir,
        badDir,
        goodSnapshot,
        badSnapshot,
        allowlistPath,
        stateRoot,
        env,
    };
}

function startArgs(projectDir, overrides = {}) {
    return {
        objective: "find a candidate scoring at least 90",
        project_dir: projectDir,
        harness_id: "primary-harness",
        acceptance_predicate: {
            kind: "all",
            predicates: [
                { kind: "harness_pass" },
                { kind: "metric_compare", metric: "score", operator: ">=", value: 90 },
            ],
        },
        hypothesis_topology: "finite_enumerable",
        validation_cases: [
            { id: "good", expectation: "accept", path: "cases/good" },
            { id: "bad", expectation: "reject", path: "cases/bad" },
        ],
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        worker_models: ["model-a"],
        candidates_per_round: 1,
        max_rounds: 2,
        ...overrides,
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
                return { action: "started", pid: 4242 };
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
            (workspace) => startArgs(workspace.projectDir, {
                objective: "x".repeat(4097),
            }),
        ],
        [
            "oversized predicate",
            (workspace) => startArgs(workspace.projectDir, {
                acceptance_predicate: {
                    kind: "field_equals",
                    path: "value",
                    value: "x".repeat(17 * 1024),
                },
            }),
        ],
        [
            "unsafe dot-dot id",
            (workspace) => startArgs(workspace.projectDir, {
                worker_models: ["model..escape"],
            }),
        ],
        [
            "duplicate metric keys",
            (workspace) => startArgs(workspace.projectDir, {
                metrics: [
                    { key: "score", direction: "max" },
                    { key: "score", direction: "min" },
                ],
            }),
        ],
        [
            "validation set without a reject",
            (workspace) => startArgs(workspace.projectDir, {
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
            startArgs(incomplete.projectDir, { deadline_iso: "2031-01-01" }),
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
                startArgs(workspace.projectDir, { deadline_iso }),
                deps,
                StartPreflightError,
            );
        }
    });

    it("rejects bounded search sets that exceed frozen round capacity before state", async () => {
        const workspace = makeWorkspace("round-capacity");
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace.projectDir, {
                bounded_candidate_ids: ["candidate-a", "candidate-b", "candidate-c"],
            }),
            deps,
            StartPreflightError,
        );
    });

    it("rejects an irreducible prompt core above the runtime byte cap", async () => {
        const workspace = makeWorkspace("prompt-core");
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace.projectDir, {
                objective: "o".repeat(4000),
                acceptance_predicate: {
                    kind: "field_equals",
                    path: "payload",
                    value: "p".repeat(12_500),
                },
            }),
            deps,
            StartPreflightError,
        );
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
            startArgs(workspace.projectDir),
            deps,
            StartPreflightError,
        );
    });

    it("rejects an allowlist validation snapshot mismatch without publishing snapshots", async () => {
        const workspace = makeWorkspace("allowlist-mismatch", {
            validationCases: {
                good: { snapshotHash: `sha256:${"0".repeat(64)}` },
                bad: { snapshotHash: workspacePlaceholder() },
            },
        });
        const raw = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        raw.entries["primary-harness"].validationCases.bad.snapshotHash = workspace.badSnapshot;
        fs.writeFileSync(workspace.allowlistPath, JSON.stringify(raw));
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace.projectDir),
            deps,
            HarnessConfigurationError,
        );
    });

    it("requires the allowlist entry to pin requested validation cases", async () => {
        const workspace = makeWorkspace("allowlist-cases-missing", {
            validationCases: undefined,
        });
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace.projectDir),
            deps,
            HarnessConfigurationError,
        );
    });

    it("rejects an invalid allowlist schema before persistent state", async () => {
        const workspace = makeWorkspace("allowlist-schema-invalid");
        const raw = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        raw.entries["primary-harness"].unexpected = true;
        fs.writeFileSync(workspace.allowlistPath, JSON.stringify(raw));
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace.projectDir),
            deps,
            HarnessConfigurationError,
        );
    });

    it("rejects an executable hash mismatch without persistent state", async () => {
        const workspace = makeWorkspace("executable-mismatch", {
            executableSha256: "0".repeat(64),
        });
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace.projectDir),
            deps,
            HarnessConfigurationError,
        );
    });

    it("rejects a dependency hash mismatch without persistent state", async () => {
        const workspace = makeWorkspace("dependency-mismatch");
        const allowlist = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        fs.writeFileSync(
            allowlist.entries["primary-harness"].dependencies[0].path,
            "tampered dependency bytes\n",
        );
        const { deps } = makeDeps(workspace);
        await expectRejectedWithoutState(
            workspace,
            startArgs(workspace.projectDir),
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
            startArgs(workspace.projectDir),
            deps,
            SandboxUnavailableApiError,
        );
    });

    it("removes new investigation, artifact, state, and config paths when apply fails", async () => {
        const workspace = makeWorkspace("apply-failure-cleanup");
        const { deps } = makeDeps(workspace, {
            ensureSupervisor: (config) => {
                fs.mkdirSync(config.paths.directory, { recursive: true });
                fs.writeFileSync(config.paths.configPath, "{}");
                throw new Error("injected supervisor launch failure");
            },
        });
        await expect(Promise.resolve().then(() =>
            startInvestigation(startArgs(workspace.projectDir), deps)))
            .rejects.toThrow("injected supervisor launch failure");
        expectNoPersistentSideEffects(workspace);
    });

    it("returns one canonical plan and applies only its staged snapshots/config", () => {
        const workspace = makeWorkspace("canonical-plan");
        const { deps, calls } = makeDeps(workspace);
        const args = startArgs(workspace.projectDir);
        const plan = preflightStartInvestigation(args, deps);
        expect(plan).not.toHaveProperty("then");
        expect(fs.existsSync(workspace.stateRoot)).toBe(false);
        expect(plan.contract.objective).toBe(args.objective);
        expect(plan.hashes).toMatchObject({
            contractHash: expect.stringMatching(/^sha256:crucible-contract-v1:[a-f0-9]{64}$/u),
            allowlistFileHash: expect.stringMatching(/^sha256:crucible-measurement-file-v1:[a-f0-9]{64}$/u),
            harnessEntryHash: expect.stringMatching(/^sha256:crucible-measurement-entry-v1:[a-f0-9]{64}$/u),
            executableHash: expect.stringMatching(/^sha256:crucible-measurement-file-v1:[a-f0-9]{64}$/u),
            argvTemplateHash: expect.stringMatching(/^sha256:crucible-measurement-argv-template-v1:[a-f0-9]{64}$/u),
            allowedEnvHash: expect.stringMatching(/^sha256:crucible-measurement-env-policy-v1:[a-f0-9]{64}$/u),
            parserVersionHash: expect.stringMatching(/^sha256:crucible-measurement-parser-version-v1:[a-f0-9]{64}$/u),
            parserSourceHash: expect.stringMatching(/^sha256:crucible-measurement-parser-source-v1:[a-f0-9]{64}$/u),
        });
        expect(plan.hashes.dependencyHashes).toHaveLength(1);
        expect(plan.supervisorConfig.paths.configPath)
            .toContain(path.join("state", "supervisor"));

        args.objective = "mutated raw args";
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
});

function workspacePlaceholder() {
    return `sha256:${"1".repeat(64)}`;
}
