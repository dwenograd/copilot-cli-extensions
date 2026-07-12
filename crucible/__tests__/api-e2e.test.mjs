import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    openArtifactStore,
    openArtifactStoreReadOnly,
    openRepository,
    openRepositoryReadOnly,
} from "../persistence/index.mjs";
import { loadHarnessAllowlist } from "../measurement/index.mjs";
import {
    SUBMIT_CANDIDATE_TOOL_NAME,
    createDomainRepositoryAdapter,
    normalizeSupervisorConfig,
    runAutonomousInvestigation,
    supervisorConfigDocument,
} from "../runtime/index.mjs";
import {
    resultInvestigation,
    startInvestigation,
    statusInvestigation,
} from "../api/handlers.mjs";
import { configureExperiment } from "../tools/configure-experiment.mjs";
import {
    buildHarnessSuiteForAllowlist,
    fakeHypothesisPolicy,
    fakeObservableRegistry,
    fakeStatisticalPolicy,
} from "./v4-contract-fixture.mjs";
import { normalizeEnumerandManifest } from "../domain/index.mjs";
import {
    createExperimentAuthorityFixture,
    prepareAndSignExperiment,
} from "./experiment-authority-fixture.mjs";
import { removeTrackedRoots } from "./test-cleanup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(async () => {
    await removeTrackedRoots(roots, {
        label: "api-e2e test root",
    });
});

function sha256File(file) {
    return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function makeWorkspace() {
    const root = fs.mkdtempSync(path.join(path.dirname(HERE), ".e-"));
    roots.push(root);
    const experimentAuthority = createExperimentAuthorityFixture();
    const projectDir = path.join(root, "p");
    const goodDir = path.join(projectDir, "c", "g");
    const badDir = path.join(projectDir, "c", "b");
    fs.mkdirSync(goodDir, { recursive: true });
    fs.mkdirSync(badDir, { recursive: true });
    fs.writeFileSync(path.join(goodDir, "score.txt"), "100\n");
    fs.writeFileSync(path.join(badDir, "score.txt"), "10\n");

    const fixtureStoreRoot = path.join(root, "f");
    const fixtureStore = openArtifactStore({ root: fixtureStoreRoot });
    const goodSnapshot = fixtureStore.ingestDirectory({ sourceDir: goodDir }).snapshot;
    const badSnapshot = fixtureStore.ingestDirectory({ sourceDir: badDir }).snapshot;
    const roleSnapshots = {};
    for (const [id, score] of [
        ["search", "100\n"],
        ["confirmation", "100\n"],
        ["challenge", "10\n"],
        ["novelty", "100\n"],
        ["candidate-a", "10\n"],
        ["candidate-b", "20\n"],
    ]) {
        const sourceDir = path.join(root, `case-${id}`);
        fs.mkdirSync(sourceDir, { recursive: true });
        fs.writeFileSync(path.join(sourceDir, "score.txt"), score);
        fs.writeFileSync(path.join(sourceDir, "case-id.txt"), id);
        roleSnapshots[id] = fixtureStore.ingestDirectory({ sourceDir }).snapshot;
    }

    const harnessScript = path.join(root, "h.mjs");
    fs.writeFileSync(harnessScript, `
        import fs from "node:fs";
        import path from "node:path";
        const candidatePath = process.argv[2];
        const raw = fs.readFileSync(path.join(candidatePath, "score.txt"), "utf8").trim();
        if (raw === "accept-without-metric") {
            process.stdout.write(JSON.stringify({ pass: true }));
        } else {
            const score = Number(raw);
            process.stdout.write(JSON.stringify({
                pass: Number.isFinite(score) && score >= 90,
                metrics: { score }
            }));
        }
    `);

    const allowlistPath = path.join(root, "a.json");
    const allowlistJson = {
        version: 1,
        entries: {
            "score-harness": {
                executable: process.execPath,
                executableSha256: sha256File(process.execPath),
                argvTemplate: [harnessScript, "{{candidatePath}}"],
                dependencies: [{
                    path: harnessScript,
                    sha256: sha256File(harnessScript),
                    role: "harness-script",
                }],
                allowedEnv: {},
                timeoutMs: 15_000,
                maxStdoutBytes: 1024 * 1024,
                maxStderrBytes: 256 * 1024,
                executesCandidateCode: false,
                validationCases: {
                    good: { snapshotHash: goodSnapshot, expectation: "accept" },
                    bad: { snapshotHash: badSnapshot, expectation: "reject" },
                    search: {
                        snapshotHash: roleSnapshots.search,
                        expectation: "accept",
                    },
                    confirmation: {
                        snapshotHash: roleSnapshots.confirmation,
                        expectation: "accept",
                    },
                    challenge: {
                        snapshotHash: roleSnapshots.challenge,
                        expectation: "reject",
                    },
                    novelty: {
                        snapshotHash: roleSnapshots.novelty,
                        expectation: "accept",
                    },
                },
            },
        },
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(allowlistJson, null, 2));
    const initialAllowlist = loadHarnessAllowlist(allowlistPath);
    allowlistJson.suites = {
        "score-suite": buildHarnessSuiteForAllowlist(initialAllowlist, {
            suiteId: "score-suite",
            harnessId: "score-harness",
            roleCaseIds: {
                calibration: ["good", "bad"],
                search: ["search"],
                confirmation: ["confirmation"],
                challenge: ["challenge"],
                novelty: ["novelty"],
            },
        }),
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(allowlistJson, null, 2));
    loadHarnessAllowlist(allowlistPath);

    const sdkPath = path.join(root, "d");
    const cliPath = path.join(root, "c.exe");
    fs.mkdirSync(sdkPath);
    fs.writeFileSync(path.join(sdkPath, "index.js"), "export {};\n");
    fs.writeFileSync(cliPath, "");
    const stateRoot = path.join(root, "s");
    const experimentRegistryPath = path.join(root, "experiments.json");
    return {
        root,
        projectDir,
        stateRoot,
        env: {
            CRUCIBLE_ALLOWLIST_PATH: allowlistPath,
            CRUCIBLE_CASE_STORE_PATH: fixtureStoreRoot,
            CRUCIBLE_EXPERIMENT_REGISTRY_PATH: experimentRegistryPath,
            CRUCIBLE_STATE_ROOT: stateRoot,
            COPILOT_SDK_PATH: sdkPath,
            COPILOT_CLI_PATH: cliPath,
            ...experimentAuthority.env,
        },
        experimentAuthority,
        goodSnapshot,
        roleSnapshots,
    };
}

function startArgs(workspace, overrides = {}) {
    const { projectDir } = workspace;
    const workspaceRoot = path.dirname(projectDir);
    const configured = JSON.parse(
        fs.readFileSync(path.join(workspaceRoot, "a.json"), "utf8"),
    );
    const controlSnapshot =
        configured.entries["score-harness"].validationCases.good.snapshotHash;
    const statisticalPolicy = fakeStatisticalPolicy({
        topology: overrides.hypothesis_topology ?? "open_generative",
        searchSlots:
            (overrides.candidates_per_round ?? 1)
            * (overrides.max_rounds ?? 1),
        control: { kind: "snapshot", identity: controlSnapshot },
    });
    const authority = {
        objective: "e2e",
        project_dir: projectDir,
        harness_suite_id: "score-suite",
        acceptance_predicate: { kind: "harness_pass" },
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
        max_rounds: 1,
        ...overrides,
    };
    const root = path.dirname(projectDir);
    const experiment_id = `e2e-${createHash("sha256")
        .update(JSON.stringify(authority))
        .digest("hex")
        .slice(0, 24)}`;
    const registryPath = path.join(root, "experiments.json");
    const config = {
        experiment_id,
        ...authority,
    };
    const { signature } = prepareAndSignExperiment({
        config,
        allowlistPath: path.join(root, "a.json"),
        env: workspace.env,
        privateKey: workspace.experimentAuthority.privateKey,
    });
    configureExperiment({
        config,
        registryPath,
        allowlistPath: path.join(root, "a.json"),
        signature,
        env: workspace.env,
    });
    return { experiment_id };
}

function sdkClientFor(candidateContent) {
    let proposalIndex = 0;
    return {
        async start() {},
        async stop() {},
        async createSession(config) {
            return {
                async sendAndWait({ prompt }) {
                    const candidateId = prompt.match(
                        /Your assigned candidateId is exactly: ([^\r\n]+)/u,
                    )?.[1];
                    const challenge = prompt.match(
                        /Your challenge nonce is exactly: ([^\r\n]+)/u,
                    )?.[1];
                    const submit = config.tools.find(
                        (tool) => tool.name === SUBMIT_CANDIDATE_TOOL_NAME,
                    );
                    if (candidateId === undefined || challenge === undefined || submit === undefined) {
                        throw new Error("SDK fixture did not receive a candidate assignment");
                    }
                    const response = await submit.handler({
                        challenge,
                        candidateId,
                        annotations: {
                            mechanism: `write deterministic candidate ${candidateId}`,
                        },
                        files: [{
                            path: "score.txt",
                            content: candidateContent(candidateId, proposalIndex),
                        }],
                    }, {
                        sessionId: config.sessionId,
                        toolName: submit.name,
                    });
                    proposalIndex += 1;
                    if (response.resultType !== "success") {
                        throw new Error(response.textResultForLlm);
                    }
                    return { data: { content: "" } };
                },
                async disconnect() {},
            };
        },
    };
}

function makeDeps(workspace, candidateContent) {
    let runnerPromise = null;
    const deps = {
        env: workspace.env,
        log: () => {},
        loadHarnessAllowlist,
        probeSandboxAvailability: () => ({ available: true }),
        normalizeSupervisorConfig,
        openArtifactStore,
        openArtifactStoreReadOnly,
        openRepository,
        openRepositoryReadOnly,
        createDomainRepositoryAdapter,
        readStatus: () => null,
        readSupervisorLock: () => null,
        isPidAlive: () => false,
        ensureSupervisor(config) {
            runnerPromise = runAutonomousInvestigation(
                supervisorConfigDocument(config).runner,
                {
                    env: workspace.env,
                    sdkClient: sdkClientFor(candidateContent),
                },
            );
            return {
                action: "started",
                pid: process.pid,
                acknowledged: true,
                acknowledgement: {
                    supervisorGeneration: 1,
                    runnerIncarnation: "inline-api-e2e-runner",
                    configFingerprint: "sha256:inline-api-e2e",
                    deadlineMs: config.runner.deadlineMs,
                },
            };
        },
    };
    return {
        deps,
        async waitForRunner() {
            if (runnerPromise === null) {
                throw new Error("inline supervisor did not launch the runner");
            }
            return runnerPromise;
        },
    };
}

describe("joined Crucible API execution", () => {
    it("keeps a search-only accepted candidate behind the scientific closure gate", async () => {
        const workspace = makeWorkspace();
        const joined = makeDeps(workspace, () => "accept-without-metric\n");
        const started = await startInvestigation(
            startArgs(workspace),
            joined.deps,
        );

        expect(await joined.waitForRunner()).toMatchObject({
            kind: "NON_RESULT",
            code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
        });
        expect(statusInvestigation({
            investigation_id: started.investigation_id,
        }, joined.deps)).toMatchObject({
            is_result: false,
            investigation_id: started.investigation_id,
            terminal_available: false,
            non_result: true,
            non_result_code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
        });

        const repository = openRepositoryReadOnly({ file: started.events_db_path });
        try {
            const aggregate = createDomainRepositoryAdapter({
                repository,
                investigationId: started.investigation_id,
                ensure: false,
            }).replay().aggregate;
            const candidate = aggregate.evidenceOrder
                .map((evidenceId) => aggregate.evidence[evidenceId])
                .find((evidence) => evidence.purpose === "candidate");
            expect(candidate).toMatchObject({
                acceptanceSatisfied: true,
                outcomeClass: "accepted",
                rankable: false,
            });
        } finally {
            repository.close();
        }

        const result = resultInvestigation({
            investigation_id: started.investigation_id,
        }, joined.deps);
        expect(result).toMatchObject({
            is_result: false,
            non_result: true,
            non_result_code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
        });
        expect(result).not.toHaveProperty("decision");
        expect(result).not.toHaveProperty("candidate_id");
        expect(result).not.toHaveProperty("evidence_id");
    }, 60_000);

    it("requires independent verification after the real runner exhausts bounded ids", async () => {
        const workspace = makeWorkspace();
        const scores = new Map([
            ["candidate-a", "10\n"],
            ["candidate-b", "20\n"],
        ]);
        const joined = makeDeps(workspace, (candidateId) => scores.get(candidateId));
        const manifest = normalizeEnumerandManifest({
            topology: "finite_enumerable",
            entries: [...scores.keys()].map((id, ordinal) => ({
                id,
                ordinal,
                artifactSnapshotHash: workspace.roleSnapshots[id],
            })),
            control: { kind: "enumerand", ordinal: 0 },
        });
        const statisticalPolicy = fakeStatisticalPolicy({
            topology: "finite_enumerable",
            searchSlots: manifest.entries.length,
            manifest,
        });
        const started = await startInvestigation(startArgs(workspace, {
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
        }), joined.deps);

        expect(await joined.waitForRunner()).toMatchObject({
            kind: "NON_RESULT",
            code: "INDEPENDENT_VERIFICATION_REQUIRED",
        });
        const result = resultInvestigation({
            investigation_id: started.investigation_id,
        }, joined.deps);
        expect(result).toMatchObject({
            is_result: false,
            non_result: true,
            non_result_code: "INDEPENDENT_VERIFICATION_REQUIRED",
        });
        expect(result).not.toHaveProperty("decision");
        expect(result).not.toHaveProperty("evidence_id");
        expect(result).not.toHaveProperty("evidence_hash");
    }, 60_000);
});
