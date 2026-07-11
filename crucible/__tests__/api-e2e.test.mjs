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

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function sha256File(file) {
    return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function makeWorkspace() {
    const root = fs.mkdtempSync(path.join(path.dirname(HERE), ".e-"));
    roots.push(root);
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
    fs.rmSync(fixtureStoreRoot, { recursive: true, force: true });

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
    fs.writeFileSync(allowlistPath, JSON.stringify({
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
                    good: { snapshotHash: goodSnapshot },
                    bad: { snapshotHash: badSnapshot },
                },
            },
        },
    }, null, 2));

    const sdkPath = path.join(root, "d");
    const cliPath = path.join(root, "c.exe");
    fs.mkdirSync(sdkPath);
    fs.writeFileSync(cliPath, "");
    const stateRoot = path.join(root, "s");
    return {
        root,
        projectDir,
        stateRoot,
        env: {
            CRUCIBLE_ALLOWLIST_PATH: allowlistPath,
            CRUCIBLE_STATE_ROOT: stateRoot,
            COPILOT_SDK_PATH: sdkPath,
            COPILOT_CLI_PATH: cliPath,
        },
    };
}

function startArgs(projectDir, overrides = {}) {
    return {
        objective: "e2e",
        project_dir: projectDir,
        harness_id: "score-harness",
        acceptance_predicate: { kind: "harness_pass" },
        hypothesis_topology: "open_generative",
        validation_cases: [
            { id: "good", expectation: "accept", path: "c/g" },
            { id: "bad", expectation: "reject", path: "c/b" },
        ],
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        worker_models: ["model-a"],
        candidates_per_round: 1,
        max_rounds: 1,
        ...overrides,
    };
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
    it("returns a verified accepted result when optional ranking metrics are absent", async () => {
        const workspace = makeWorkspace();
        const joined = makeDeps(workspace, () => "accept-without-metric\n");
        const started = await startInvestigation(startArgs(workspace.projectDir, {
            search_policy: { stopOnFirstAccept: true },
        }), joined.deps);

        expect(await joined.waitForRunner()).toMatchObject({
            kind: "TERMINAL",
            decision: "VERIFIED_RESULT",
        });
        expect(statusInvestigation({
            investigation_id: started.investigation_id,
        }, joined.deps)).toEqual({
            is_result: false,
            investigation_id: started.investigation_id,
            terminal_available: true,
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

        expect(resultInvestigation({
            investigation_id: started.investigation_id,
        }, joined.deps)).toMatchObject({
            is_result: true,
            banner: "===== CRUCIBLE TERMINAL RESULT =====",
            decision: "VERIFIED_RESULT",
        });
    }, 60_000);

    it("returns TARGET_UNREACHABLE only after the real runner exhausts bounded ids", async () => {
        const workspace = makeWorkspace();
        const scores = new Map([
            ["candidate-a", "10\n"],
            ["candidate-b", "20\n"],
        ]);
        const joined = makeDeps(workspace, (candidateId) => scores.get(candidateId));
        const started = await startInvestigation(startArgs(workspace.projectDir, {
            hypothesis_topology: "finite_enumerable",
            bounded_candidate_ids: [...scores.keys()],
            max_rounds: 2,
        }), joined.deps);

        expect(await joined.waitForRunner()).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
        });
        expect(resultInvestigation({
            investigation_id: started.investigation_id,
        }, joined.deps)).toMatchObject({
            is_result: true,
            banner: "===== CRUCIBLE TERMINAL RESULT =====",
            decision: "TARGET_UNREACHABLE",
            basis: {
                kind: "search_space_exhausted",
                boundedCandidateCount: 2,
            },
        });
    }, 60_000);
});
