// crucible/__tests__/api-handlers.test.mjs
//
// Handler tests for the Crucible four-tool API, driven with injected
// environment + runtime functions (fake supervisor, controllable pid liveness)
// so nothing spawns a real process. Real domain / persistence / artifact-store /
// measurement modules are used end-to-end. Covers: path/state resolution,
// validation-case ingestion + containment, idempotent and conflicting start,
// missing allowlist, supervisor start, status restart, stop/pause, positive
// terminal results (verified + target-unreachable), and strict non-result
// redaction.

import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
    DEFAULT_SEARCH_POLICY,
    DOMAIN_VERSION,
    EVENT_TYPES,
    createInvestigationContract,
    decideNext,
    deriveImpossibilityVerdict,
    hashCanonical,
} from "../domain/index.mjs";
import { openArtifactStore, openRepository } from "../persistence/index.mjs";
import {
    createDomainRepositoryAdapter,
    loadSupervisorConfig,
    readSupervisorLock,
    readStatus,
    requestStop,
    supervisorPaths,
} from "../runtime/index.mjs";
import { loadHarnessAllowlist } from "../measurement/index.mjs";

import {
    deriveInvestigationId,
    resolveInvestigationPaths,
    resolveStateRoot,
} from "../api/environment.mjs";
import {
    resultInvestigation,
    startInvestigation,
    statusInvestigation,
    stopInvestigation,
} from "../api/handlers.mjs";
import { NON_RESULT_BANNER, TERMINAL_BANNER } from "../api/result.mjs";
import {
    ContractConflictError,
    EnvironmentError,
    HarnessNotAllowlistedError,
    InvestigationNotResumableError,
    InvestigationNotFoundError,
    OperationalResetRequiredError,
    ValidationCasePathError,
} from "../api/errors.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function makeWorkspace(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.api-handlers-${label}-`));
    roots.push(root);
    const stateRoot = path.join(root, "state-root");
    const projectDir = path.join(root, "project");
    const goodDir = path.join(projectDir, "cases", "good");
    const badDir = path.join(projectDir, "cases", "bad");
    fs.mkdirSync(goodDir, { recursive: true });
    fs.mkdirSync(badDir, { recursive: true });
    fs.writeFileSync(path.join(goodDir, "input.txt"), "good-case");
    fs.writeFileSync(path.join(badDir, "input.txt"), "bad-case");

    const allowlistPath = path.join(root, "harnesses.json");
    fs.writeFileSync(allowlistPath, JSON.stringify({
        version: 1,
        entries: {
            "primary-harness": {
                executable: "C:\\fake\\harness.exe",
                executableSha256: "a".repeat(64),
                argvTemplate: [],
                timeoutMs: 15000,
                maxStdoutBytes: 1048576,
                maxStderrBytes: 262144,
                executesCandidateCode: false,
            },
        },
    }, null, 2));

    const env = {
        CRUCIBLE_ALLOWLIST_PATH: allowlistPath,
        CRUCIBLE_STATE_ROOT: stateRoot,
        COPILOT_SDK_PATH: path.join(root, "sdk"),
        COPILOT_CLI_PATH: path.join(root, "cli.exe"),
    };
    return { root, stateRoot, projectDir, allowlistPath, env };
}

function makeDeps(env, overrides = {}) {
    const calls = { ensure: [] };
    const deps = {
        env,
        log: () => {},
        isPidAlive: () => false,
        loadHarnessAllowlist,
        openRepository,
        openArtifactStore,
        createDomainRepositoryAdapter,
        ensureSupervisor: (input, opts) => {
            calls.ensure.push({ input, opts });
            return { action: "started", pid: 4242, statusPath: "status" };
        },
        readStatus,
        requestStop,
        loadSupervisorConfig,
        readSupervisorLock,
        ...overrides,
    };
    return { deps, calls };
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

// --- domain seeding for terminal-state result tests ------------------------

const seedArtifactHash = (character) => `sha256:${character.repeat(64)}`;

// Canonical version-2 search policy, optionally overridden. The domain requires
// searchPolicy to already be in canonical kernel form, so overrides are merged
// onto the frozen DEFAULT_SEARCH_POLICY rather than partially specified.
function searchPolicy(overrides = {}) {
    return {
        ...DEFAULT_SEARCH_POLICY,
        ...overrides,
        operatorWeights: {
            ...DEFAULT_SEARCH_POLICY.operatorWeights,
            ...overrides.operatorWeights,
        },
        archiveCaps: {
            ...DEFAULT_SEARCH_POLICY.archiveCaps,
            ...overrides.archiveCaps,
        },
        promptCaps: {
            ...DEFAULT_SEARCH_POLICY.promptCaps,
            ...overrides.promptCaps,
        },
    };
}

function seedReceipt(observationId, isCandidate) {
    return {
        attemptId: `attempt-${observationId}`,
        runnerEpochId: "runner-epoch-seed",
        rawStdoutHash: hashCanonical({ observationId, stream: "stdout" }),
        rawStderrHash: hashCanonical({ observationId, stream: "stderr" }),
        candidateArtifactHash: isCandidate ? hashCanonical({ observationId, artifact: true }) : null,
    };
}

function seedImpossibilityObservation(reserved, observationId, facts) {
    const verifiedFacts = {
        pass: facts.pass,
        searchSpaceExhausted: facts.searchSpaceExhausted,
        parserVersion: reserved.parserVersion,
    };
    const certificateArtifactHash = hashCanonical({
        observationId,
        artifact: "certificate",
    });
    const measurementReceiptHash = hashCanonical({
        observationId,
        receipt: "measurement",
    });
    const verificationSnapshotHash = hashCanonical({
        observationId,
        snapshot: "verification",
    });
    return {
        purpose: "impossibility",
        receipt: {
            attemptId: `attempt-${observationId}`,
            runnerEpochId: "runner-epoch-seed",
            rawStdoutHash: hashCanonical({ observationId, stream: "stdout" }),
            rawStderrHash: hashCanonical({ observationId, stream: "stderr" }),
            candidateArtifactHash: null,
            certificateArtifactHash,
            measurementReceiptArtifactHash: hashCanonical({
                observationId,
                artifact: "measurement-receipt",
            }),
            measurementReceiptHash,
            rawStderrArtifactHash: hashCanonical({
                observationId,
                artifact: "stderr",
            }),
            rawStdoutArtifactHash: hashCanonical({
                observationId,
                artifact: "stdout",
            }),
            verificationRequestHash: reserved.requestHash,
            verificationSnapshotHash,
        },
        data: {
            certificateVersion: reserved.certificateVersion,
            certificateVerdict: deriveImpossibilityVerdict(verifiedFacts),
            certificateArtifactHash,
            measurementReceiptHash,
            verificationRequestHash: reserved.requestHash,
            verificationSnapshotHash,
            verifiedFacts,
        },
    };
}

function baseSeedContract(overrides = {}) {
    return {
        objective: "seed objective",
        acceptancePredicate: {
            kind: "all",
            predicates: [
                { kind: "harness_pass" },
                { kind: "metric_compare", metric: "score", operator: ">=", value: 90 },
            ],
        },
        validationCases: [
            { id: "good", expectation: "accept", artifactHash: seedArtifactHash("a") },
            { id: "bad", expectation: "reject", artifactHash: seedArtifactHash("b") },
        ],
        harnessId: "primary-harness",
        criticality: "standard",
        policyVersion: "policy-v1",
        parserVersion: "parser-v1",
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        searchPolicy: searchPolicy(),
        declaredLimits: {},
        ...overrides,
    };
}

// Generic domain driver: consumes decideNext recommendations, supplying
// external inputs (dispatch/observe/commit/stop) and recording kernel decisions,
// until a terminal / pause / non-result aggregate is reached. Under domain-v2 the
// kernel reserves one deterministic per-candidate `search_candidate` command per
// slot; each queue entry supplies only the harness `data` (and optional
// annotations) for the next candidate slot, while round/slot/candidateId are
// inherited from the reserved assignment.
function driveToTerminal(adapter, candidateQueue) {
    let observations = 0;
    let stops = 0;
    for (let iteration = 0; iteration < 500; iteration += 1) {
        const { aggregate } = adapter.replay();
        if (aggregate.terminal !== null || aggregate.pause !== null || aggregate.nonResults.length > 0) {
            return aggregate;
        }
        const recommendation = decideNext(aggregate);
        if (recommendation.event !== null) {
            adapter.appendKernelDecision();
            continue;
        }
        if (recommendation.kind !== "COMMAND") {
            throw new Error(`unexpected recommendation kind ${recommendation.kind}`);
        }
        const command = recommendation.command;
        switch (command.kind) {
            case "dispatch_reserved":
                adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, {
                    commandId: recommendation.commandId,
                });
                break;
            case "commit_evidence":
                adapter.appendEvidenceCommit({
                    evidenceId: command.evidenceId,
                    observationId: command.observationId,
                });
                break;
            case "await_stop_request":
                adapter.appendExternal(EVENT_TYPES.STOP_REQUESTED, {
                    requestId: `stop-${stops += 1}`,
                    reason: "seed stop",
                    pauseRequested: false,
                });
                break;
            case "await_observation": {
                const reserved = command.reservedCommand;
                const observationId = `obs-${observations += 1}`;
                if (reserved.kind === "run_validation") {
                    const caseResults = aggregate.contract.validationCases.map((validationCase) => ({
                        id: validationCase.id,
                        artifactHash: validationCase.artifactHash,
                        outcome: validationCase.expectation,
                    }));
                    adapter.appendHarnessObservation({
                        commandId: recommendation.commandId,
                        observationId,
                        purpose: "validation",
                        receipt: seedReceipt(observationId, false),
                        data: { caseResults },
                    });
                } else if (reserved.kind === "search_candidate") {
                    const spec = candidateQueue.shift();
                    if (spec === undefined) {
                        throw new Error("candidate queue exhausted");
                    }
                    adapter.appendHarnessObservation({
                        commandId: recommendation.commandId,
                        observationId,
                        purpose: "candidate",
                        // round/slotIndex/candidateId are inherited from the
                        // reserved search-candidate assignment.
                        receipt: seedReceipt(observationId, true),
                        data: spec.data,
                        ...(spec.annotations === undefined ? {} : { annotations: spec.annotations }),
                    });
                } else if (reserved.kind === "verify_impossibility") {
                    const spec = candidateQueue.shift();
                    if (spec?.certificateFacts === undefined) {
                        throw new Error("impossibility certificate queue entry is missing");
                    }
                    adapter.appendHarnessObservation({
                        commandId: recommendation.commandId,
                        observationId,
                        ...seedImpossibilityObservation(
                            reserved,
                            observationId,
                            spec.certificateFacts,
                        ),
                    });
                } else {
                    throw new Error(`unexpected reserved command ${reserved.kind}`);
                }
                break;
            }
            default:
                throw new Error(`unexpected command kind ${command.kind}`);
        }
    }
    throw new Error("driver did not reach a terminal state");
}

function seedInvestigation(stateRoot, investigationId, contractInput, seedFn) {
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    fs.mkdirSync(paths.stateDir, { recursive: true });
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const adapter = createDomainRepositoryAdapter({ repository, investigationId });
        adapter.openInvestigation(createInvestigationContract(contractInput));
        return seedFn(adapter);
    } finally {
        repository.close();
    }
}

function seedVerifiedResult(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        baseSeedContract({
            hypothesisTopology: "open_generative",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 3,
            // Immediate terminal: the first accepted candidate verifies.
            searchPolicy: searchPolicy({ stopOnFirstAccept: true }),
        }),
        (adapter) => driveToTerminal(adapter, [
            { data: { pass: true, metrics: { score: 95 } } },
        ]),
    );
}

// The deterministic candidateId the kernel assigns to round 1, slot 0 for an
// unbounded (generated) search space. Result assertions compare against this.
const FIRST_GENERATED_CANDIDATE_ID = "candidate-r000001-s000";

function seedTargetUnreachable(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        baseSeedContract({
            hypothesisTopology: "finite_enumerable",
            workerModels: ["model-a"],
            candidatesPerRound: 2,
            maxRounds: 1,
            boundedCandidateIds: ["cand-a", "cand-b"],
        }),
        (adapter) => driveToTerminal(adapter, [
            { data: { pass: false, metrics: { score: 10 } } },
            { data: { pass: false, metrics: { score: 20 } } },
        ]),
    );
}

function seedCertifiedTargetUnreachable(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        baseSeedContract({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }),
        (adapter) => driveToTerminal(adapter, [
            { data: { pass: false, metrics: { score: 20 } } },
            {
                certificateFacts: {
                    pass: true,
                    searchSpaceExhausted: true,
                },
            },
        ]),
    );
}

function seedCertifiedNonResult(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        baseSeedContract({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }),
        (adapter) => driveToTerminal(adapter, [
            { data: { pass: false, metrics: { score: 20 } } },
            {
                certificateFacts: {
                    pass: false,
                    searchSpaceExhausted: true,
                },
            },
        ]),
    );
}

function seedPaused(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        baseSeedContract({
            hypothesisTopology: "open_generative",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 3,
        }),
        (adapter) => {
            const reserve = adapter.appendKernelDecision();
            const validationCommandId = reserve.domainEvent.payload.commandId;
            adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, { commandId: validationCommandId });
            adapter.appendHarnessObservation({
                commandId: validationCommandId,
                observationId: "validation-obs",
                purpose: "validation",
                receipt: seedReceipt("validation-obs", false),
                data: {
                    caseResults: [
                        { id: "good", artifactHash: seedArtifactHash("a"), outcome: "accept" },
                        { id: "bad", artifactHash: seedArtifactHash("b"), outcome: "reject" },
                    ],
                },
            });
            adapter.appendEvidenceCommit({ evidenceId: "validation-evidence", observationId: "validation-obs" });
            adapter.appendKernelDecision(); // VALIDATION_COMPLETED
            adapter.appendExternal(EVENT_TYPES.STOP_REQUESTED, {
                requestId: "stop-pause",
                reason: "pause please",
                pauseRequested: true,
            });
            return adapter.appendKernelDecision().aggregate; // INVESTIGATION_PAUSED
        },
    );
}

function replayAggregate(stateRoot, investigationId) {
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const adapter = createDomainRepositoryAdapter({ repository, investigationId, ensure: false });
        return adapter.replay().aggregate;
    } finally {
        repository.close();
    }
}

function persistPauseForStarted(workspace, started) {
    const paths = resolveInvestigationPaths(workspace.stateRoot, started.investigation_id);
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const adapter = createDomainRepositoryAdapter({
            repository,
            investigationId: started.investigation_id,
        });
        let { aggregate } = adapter.replay();
        aggregate = adapter.appendKernelDecision().aggregate;
        const commandId = aggregate.commandOrder.at(-1);
        aggregate = adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, {
            commandId,
        }).aggregate;
        aggregate = adapter.appendHarnessObservation({
            commandId,
            observationId: "pause-validation-observation",
            purpose: "validation",
            receipt: seedReceipt("pause-validation-observation", false),
            data: {
                caseResults: aggregate.contract.validationCases.map((validationCase) => ({
                    id: validationCase.id,
                    artifactHash: validationCase.artifactHash,
                    outcome: validationCase.expectation,
                })),
            },
        }).aggregate;
        aggregate = adapter.appendEvidenceCommit({
            evidenceId: "pause-validation-evidence",
            observationId: "pause-validation-observation",
        }).aggregate;
        adapter.appendKernelDecision();
    } finally {
        repository.close();
    }
}

function recordOperationalNonResult(stateRoot, investigationId, input) {
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const adapter = createDomainRepositoryAdapter({ repository, investigationId });
        return adapter.recordOperationalNonResult(input);
    } finally {
        repository.close();
    }
}

// Reserve and dispatch the first kernel command (validation) without observing
// it, leaving an in-flight command. A crucible_stop against this state records
// the stop request but the kernel cannot persist the pause until the active
// command resolves, so resumability must not yet be claimed.
function seedDispatchedCommand(stateRoot, investigationId) {
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const adapter = createDomainRepositoryAdapter({ repository, investigationId });
        const reserve = adapter.appendKernelDecision();
        const commandId = reserve.domainEvent.payload.commandId;
        adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, { commandId });
    } finally {
        repository.close();
    }
}

// --- environment / path + state resolution ---------------------------------

describe("environment: path + state resolution", () => {
    it("derives a deterministic, filesystem-safe investigationId", () => {
        const id1 = deriveInvestigationId({
            objective: "  find   a  candidate ",
            projectDir: "C:\\proj",
            harnessId: "h1",
        });
        const id2 = deriveInvestigationId({
            objective: "find a candidate",
            projectDir: "C:\\proj\\",
            harnessId: "h1",
        });
        expect(id1).toBe(id2); // whitespace + trailing-slash canonicalized
        expect(id1).toMatch(/^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u);
        expect(id1.includes("..")).toBe(false);

        const differentObjective = deriveInvestigationId({
            objective: "find another candidate",
            projectDir: "C:\\proj",
            harnessId: "h1",
        });
        const differentHarness = deriveInvestigationId({
            objective: "find a candidate",
            projectDir: "C:\\proj",
            harnessId: "h2",
        });
        expect(differentObjective).not.toBe(id1);
        expect(differentHarness).not.toBe(id1);
    });

    it("namespaces investigation identity by DOMAIN_VERSION instead of reopening v1", () => {
        const objective = "find a candidate";
        const projectDir = "C:\\proj";
        const harnessId = "h1";
        const legacyMaterial = [
            "crucible-investigation-v1",
            harnessId,
            objective,
            path.resolve(projectDir).replace(/\//gu, "\\").toLowerCase(),
        ].join("\u0000");
        const legacySuffix = createHash("sha256")
            .update(legacyMaterial, "utf8")
            .digest("hex")
            .slice(0, 16);
        const legacyId = `find-a-candidate-${legacySuffix}`;
        const currentId = deriveInvestigationId({ objective, projectDir, harnessId });

        expect(DOMAIN_VERSION).toBe(2);
        expect(currentId).not.toBe(legacyId);
        expect(currentId).toBe(deriveInvestigationId({ objective, projectDir, harnessId }));
    });

    it("resolves investigation paths under the state root", () => {
        const paths = resolveInvestigationPaths("C:\\root", "inv-x");
        expect(paths.stateDir).toBe(path.join("C:\\root", "inv-x", "state"));
        expect(paths.artifactRoot).toBe(path.join("C:\\root", "inv-x", "artifacts"));
        expect(paths.eventsDbPath).toBe(path.join("C:\\root", "inv-x", "state", "events.sqlite"));
    });

    it("fails clearly when required environment configuration is unavailable", () => {
        expect(() => resolveStateRoot({})).toThrow(EnvironmentError);
        const { env } = makeWorkspace("env-missing-sdk");
        const withoutSdk = { ...env };
        delete withoutSdk.COPILOT_SDK_PATH;
        const { deps } = makeDeps(withoutSdk);
        expect(() => startInvestigation(startArgs(makeWorkspace("proj").projectDir), deps))
            .toThrow(EnvironmentError);
    });
});

// --- crucible_start ----------------------------------------------------------

describe("crucible_start", () => {
    it("freezes a contract, ingests validation cases, and starts the supervisor", () => {
        const workspace = makeWorkspace("start");
        const { deps, calls } = makeDeps(workspace.env);
        const result = startInvestigation(startArgs(workspace.projectDir), deps);

        expect(result.is_result).toBe(false);
        expect(result.idempotent).toBe(false);
        expect(result.contract_hash).toMatch(/^sha256:crucible-contract-v1:[a-f0-9]{64}$/u);

        const expectedId = deriveInvestigationId({
            objective: "find a candidate scoring at least 90",
            projectDir: fs.realpathSync.native(workspace.projectDir),
            harnessId: "primary-harness",
        });
        expect(result.investigation_id).toBe(expectedId);

        const paths = resolveInvestigationPaths(resolveStateRoot(workspace.env), expectedId);
        expect(fs.existsSync(paths.eventsDbPath)).toBe(true);
        expect(fs.existsSync(paths.artifactRoot)).toBe(true);
        expect(result.state_dir).toBe(paths.stateDir);

        // Supervisor started exactly once with a strict runner config.
        expect(calls.ensure).toHaveLength(1);
        const runner = calls.ensure[0].input.runner;
        expect(runner.investigationId).toBe(expectedId);
        expect(runner.stateDir).toBe(paths.stateDir);
        expect(runner.artifactRoot).toBe(paths.artifactRoot);
        expect(runner.allowlistPath).toBe(path.resolve(workspace.allowlistPath));
        expect(path.isAbsolute(runner.copilotSdkPath)).toBe(true);
        expect(path.isAbsolute(runner.copilotCliPath)).toBe(true);
        expect(runner.runnerEpochId).toMatch(/^epoch-[a-f0-9]{16}$/u);
        expect(result.supervisor.action).toBe("started");

        // Only immutable content hashes entered the contract.
        const aggregate = replayAggregate(resolveStateRoot(workspace.env), expectedId);
        for (const validationCase of aggregate.contract.validationCases) {
            expect(validationCase.artifactHash).toMatch(/^sha256:[a-f0-9]{64}$/u);
            expect(validationCase).not.toHaveProperty("path");
        }
    });

    it("freezes the certified-impossibility trigger and certificate prerequisites", () => {
        const workspace = makeWorkspace("start-certified");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir, {
            hypothesis_topology: "certified_impossibility",
            max_rounds: 1,
        }), deps);
        const aggregate = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(aggregate.contract).toMatchObject({
            hypothesisTopology: "certified_impossibility",
            impossibilityPolicy: {
                trigger: "search_exhausted",
                requestVersion: "crucible-impossibility-request-v1",
                certificateVersion: "crucible-impossibility-certificate-v1",
            },
        });
    });

    it("starts domain v2 beside a legacy v1 identity instead of reopening it", () => {
        const workspace = makeWorkspace("versioned-start");
        const objective = "find a candidate scoring at least 90";
        const canonicalProjectDir = fs.realpathSync.native(workspace.projectDir);
        const legacyMaterial = [
            "crucible-investigation-v1",
            "primary-harness",
            objective,
            path.resolve(canonicalProjectDir).replace(/\//gu, "\\").toLowerCase(),
        ].join("\u0000");
        const legacyId = `find-a-candidate-scoring-at-least-90-${createHash("sha256")
            .update(legacyMaterial, "utf8")
            .digest("hex")
            .slice(0, 16)}`;
        const stateRoot = resolveStateRoot(workspace.env);
        const legacyPaths = resolveInvestigationPaths(stateRoot, legacyId);
        fs.mkdirSync(legacyPaths.stateDir, { recursive: true });
        const legacyMarker = path.join(legacyPaths.stateDir, "legacy-v1.marker");
        fs.writeFileSync(legacyMarker, "do-not-reopen");

        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);

        expect(started.investigation_id).not.toBe(legacyId);
        expect(fs.readFileSync(legacyMarker, "utf8")).toBe("do-not-reopen");
        expect(fs.existsSync(resolveInvestigationPaths(
            stateRoot,
            started.investigation_id,
        ).eventsDbPath)).toBe(true);
    });

    it("is idempotent for an identical contract and returns the existing investigation", () => {
        const workspace = makeWorkspace("idem");
        const { deps, calls } = makeDeps(workspace.env);
        const first = startInvestigation(startArgs(workspace.projectDir), deps);
        const second = startInvestigation(startArgs(workspace.projectDir), deps);

        expect(second.idempotent).toBe(true);
        expect(second.investigation_id).toBe(first.investigation_id);
        expect(second.contract_hash).toBe(first.contract_hash);
        // Both calls ensured the supervisor; no second investigation_opened event.
        expect(calls.ensure).toHaveLength(2);
        const aggregate = replayAggregate(resolveStateRoot(workspace.env), first.investigation_id);
        expect(aggregate.lastSeq).toBe(1);
    });

    it("resumes a persisted pause on identical crucible_start reattach and ensures the supervisor", () => {
        const workspace = makeWorkspace("resume");
        const { deps, calls } = makeDeps(workspace.env);
        const args = startArgs(workspace.projectDir);
        const started = startInvestigation(args, deps);
        persistPauseForStarted(workspace, started);
        const stopped = stopInvestigation({
            investigation_id: started.investigation_id,
            reason: "persist pause",
        }, deps);
        expect(stopped.pause_persisted).toBe(true);
        expect(stopped.resumable).toBe(true);

        const resumed = startInvestigation(args, deps);
        expect(resumed.idempotent).toBe(true);
        expect(resumed.resumed).toBe(true);
        expect(calls.ensure.at(-1).opts.resetOperationalState).toBe(true);
        const aggregate = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(aggregate.pause).toBeNull();
        expect(aggregate.status).toBe("active");
        expect(aggregate.pauseHistory).toHaveLength(1);
    });

    it("does not resume terminal investigations without a new identity", () => {
        const workspace = makeWorkspace("terminal-reattach");
        const { deps } = makeDeps(workspace.env);
        const args = startArgs(workspace.projectDir, {
            search_policy: searchPolicy({ stopOnFirstAccept: true }),
        });
        const started = startInvestigation(args, deps);
        const paths = resolveInvestigationPaths(workspace.stateRoot, started.investigation_id);
        const repository = openRepository({ file: paths.eventsDbPath });
        try {
            const adapter = createDomainRepositoryAdapter({
                repository,
                investigationId: started.investigation_id,
            });
            driveToTerminal(adapter, [
                { data: { pass: true, metrics: { score: 95 } } },
            ]);
        } finally {
            repository.close();
        }
        expect(() => startInvestigation(args, deps))
            .toThrow(InvestigationNotResumableError);
    });

    it("requires explicit operational recovery policy and accepts a later deadline", () => {
        const workspace = makeWorkspace("operational-recovery");
        const { deps } = makeDeps(workspace.env);
        const args = startArgs(workspace.projectDir, {
            deadline_iso: "2026-07-10T00:00:00.000Z",
        });
        const started = startInvestigation(args, deps);
        recordOperationalNonResult(workspace.stateRoot, started.investigation_id, {
            attemptId: "deadline-attempt",
            code: "DEADLINE_EXCEEDED",
            reason: "deadline elapsed",
            details: { deadlineMs: Date.parse(args.deadline_iso), recoverable: false },
        });
        expect(() => startInvestigation(args, deps))
            .toThrow(OperationalResetRequiredError);
        const recovered = startInvestigation({
            ...args,
            deadline_iso: "2026-07-11T00:00:00.000Z",
        }, deps);
        expect(recovered.operational_recovery).toBe("later_deadline");

        recordOperationalNonResult(workspace.stateRoot, started.investigation_id, {
            attemptId: "circuit-attempt",
            code: "CRUCIBLE_RUNTIME_CIRCUIT_OPEN",
            reason: "circuit open",
            details: { recoverable: false },
        });
        expect(() => startInvestigation({
            ...args,
            deadline_iso: "2026-07-12T00:00:00.000Z",
        }, deps)).toThrow(OperationalResetRequiredError);
        const reset = startInvestigation({
            ...args,
            deadline_iso: "2026-07-12T00:00:00.000Z",
            reset_policy: "circuit_open",
        }, deps);
        expect(reset.operational_recovery).toBe("circuit_open");
    });

    it("rejects a conflicting contract for the same identity", () => {
        const workspace = makeWorkspace("conflict");
        const { deps } = makeDeps(workspace.env);
        startInvestigation(startArgs(workspace.projectDir), deps);
        // Same objective/project/harness (=> same id) but a different contract.
        expect(() => startInvestigation(startArgs(workspace.projectDir, { max_rounds: 5 }), deps))
            .toThrow(ContractConflictError);
    });

    it("refuses a harness with no operator allowlist entry", () => {
        const workspace = makeWorkspace("allow-miss");
        const { deps } = makeDeps(workspace.env);
        expect(() => startInvestigation(startArgs(workspace.projectDir, { harness_id: "unknown-harness" }), deps))
            .toThrow(HarnessNotAllowlistedError);
    });

    it("fails when the allowlist file itself is absent", () => {
        const workspace = makeWorkspace("allow-file-missing");
        fs.rmSync(workspace.allowlistPath, { force: true });
        const { deps } = makeDeps(workspace.env);
        expect(() => startInvestigation(startArgs(workspace.projectDir), deps)).toThrow();
    });

    it("refuses a validation-case path that escapes project_dir", () => {
        const workspace = makeWorkspace("escape");
        const outside = path.join(workspace.root, "outside");
        fs.mkdirSync(outside, { recursive: true });
        fs.writeFileSync(path.join(outside, "x.txt"), "x");
        const { deps } = makeDeps(workspace.env);
        const args = startArgs(workspace.projectDir, {
            validation_cases: [
                { id: "good", expectation: "accept", path: "cases/good" },
                { id: "bad", expectation: "reject", path: "..\\outside" },
            ],
        });
        expect(() => startInvestigation(args, deps)).toThrow(ValidationCasePathError);
    });

    it("refuses a validation-case path that is a file, not a directory", () => {
        const workspace = makeWorkspace("case-file");
        fs.writeFileSync(path.join(workspace.projectDir, "loose.txt"), "not a dir");
        const { deps } = makeDeps(workspace.env);
        const args = startArgs(workspace.projectDir, {
            validation_cases: [
                { id: "good", expectation: "accept", path: "cases/good" },
                { id: "bad", expectation: "reject", path: "loose.txt" },
            ],
        });
        expect(() => startInvestigation(args, deps)).toThrow(ValidationCasePathError);
    });
});

describe("crucible_status", () => {
    it("reports nonterminal progress, contract hash, event head, and a recommendation", () => {
        const workspace = makeWorkspace("status");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);

        const status = statusInvestigation({ investigation_id: started.investigation_id }, deps);
        expect(status.is_result).toBe(false);
        expect(status.terminal_available).toBe(false);
        expect(status.contract_hash).toBe(started.contract_hash);
        expect(status.event_head.seq).toBe(1);
        expect(typeof status.event_head.event_hash).toBe("string");
        expect(status.progress.open).toBe(true);
        expect(status.next_recommendation.kind).toBeTruthy();
    });

    it("restarts a missing supervisor from persisted config when nonterminal", () => {
        const workspace = makeWorkspace("status-restart");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);

        // Simulate a persisted supervisor config existing on disk.
        const paths = resolveInvestigationPaths(resolveStateRoot(workspace.env), started.investigation_id);
        const configPath = supervisorPaths(paths.stateDir, started.investigation_id).configPath;
        fs.mkdirSync(path.dirname(configPath), { recursive: true });
        fs.writeFileSync(configPath, JSON.stringify({ persisted: true }));

        const restartCalls = [];
        const { deps: statusDeps } = makeDeps(workspace.env, {
            readStatus: () => null, // supervisor missing
            isPidAlive: () => false,
            loadSupervisorConfig: () => ({ loaded: "config" }),
            ensureSupervisor: (input) => {
                restartCalls.push(input);
                return { action: "started", pid: 999 };
            },
        });

        const status = statusInvestigation({ investigation_id: started.investigation_id }, statusDeps);
        expect(restartCalls).toHaveLength(1);
        expect(restartCalls[0]).toEqual({ loaded: "config" });
        expect(status.supervisor_health.ensure_action.action).toBe("started");
    });

    it("does not restart when the supervisor is alive", () => {
        const workspace = makeWorkspace("status-alive");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);

        const ensureCalls = [];
        const { deps: statusDeps } = makeDeps(workspace.env, {
            readStatus: () => ({
                state: "running",
                pid: 4321,
                nonce: "alive-nonce",
                childPid: 8765,
                heartbeatAt: new Date().toISOString(),
                restartCount: 0,
            }),
            readSupervisorLock: () => ({
                pid: 4321,
                nonce: "alive-nonce",
                startedAt: new Date().toISOString(),
            }),
            isPidAlive: (pid) => pid === 4321,
            ensureSupervisor: (input) => {
                ensureCalls.push(input);
                return { action: "already-running" };
            },
        });

        const status = statusInvestigation({ investigation_id: started.investigation_id }, statusDeps);
        expect(ensureCalls).toHaveLength(0);
        expect(status.supervisor_health.ensure_action).toBeNull();
        expect(status.supervisor_health.alive).toBe(true);
    });

    it("does not restart a terminal investigation", () => {
        const workspace = makeWorkspace("status-terminal");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const ensureCalls = [];
        const { deps } = makeDeps(workspace.env, {
            readStatus: () => null,
            isPidAlive: () => false,
            ensureSupervisor: (input) => {
                ensureCalls.push(input);
                return { action: "started" };
            },
        });
        const status = statusInvestigation({ investigation_id: "verified-inv" }, deps);
        expect(status.terminal_available).toBe(true);
        expect(ensureCalls).toHaveLength(0);
        expect(status.supervisor_health.ensure_action).toBeNull();
    });

    it("redacts terminal decision, winner, and evidence data from status", () => {
        const workspace = makeWorkspace("status-redaction");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const { deps } = makeDeps(workspace.env, { readStatus: () => null });
        const status = statusInvestigation({ investigation_id: "verified-inv" }, deps);
        expect(status.terminal_available).toBe(true);
        expect(status).not.toHaveProperty("terminal");
        expect(status).not.toHaveProperty("terminal_decision");
        expect(status.next_recommendation).toBeNull();
        expect(status.event_head.event_hash).toBeNull();
        const serialized = JSON.stringify(status);
        expect(serialized).not.toContain("VERIFIED_RESULT");
        expect(serialized).not.toContain("TARGET_UNREACHABLE");
        expect(serialized).not.toContain("cand-a");
        expect(serialized).not.toContain("evidence_hash");
    });

    it("reports an integrity-checked operational deadline as a non-result", () => {
        const workspace = makeWorkspace("status-deadline");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
        recordOperationalNonResult(workspace.stateRoot, started.investigation_id, {
            attemptId: "deadline-status",
            code: "DEADLINE_EXCEEDED",
            reason: "The deadline expired before a result.",
            details: { deadlineMs: Date.now() - 1, recoverable: false },
        });
        const status = statusInvestigation({
            investigation_id: started.investigation_id,
        }, deps);
        expect(status).toMatchObject({
            is_result: false,
            terminal_available: false,
            non_result: true,
            non_result_code: "DEADLINE_EXCEEDED",
            non_result_reason: "The deadline expired before a result.",
        });
        expect(status.note).not.toContain("In progress");
    });

    it("fails clearly for an unknown investigation", () => {
        const workspace = makeWorkspace("status-missing");
        const { deps } = makeDeps(workspace.env);
        expect(() => statusInvestigation({ investigation_id: "does-not-exist" }, deps))
            .toThrow(InvestigationNotFoundError);
    });
});

// --- crucible_stop -----------------------------------------------------------

describe("crucible_stop", () => {
    it("does not claim resumability until the pause transition is persisted", () => {
        const workspace = makeWorkspace("stop");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
        // Leave a dispatched (in-flight) command so the kernel cannot persist the
        // pause yet; the stop request is recorded but not resumable.
        seedDispatchedCommand(workspace.stateRoot, started.investigation_id);

        const stop = stopInvestigation({ investigation_id: started.investigation_id, reason: "operator pause" }, deps);
        expect(stop.is_result).toBe(false);
        expect(stop.pause_requested).toBe(true);
        expect(stop.resumable).toBe(false);
        expect(stop.appended).toBe(true);
        expect(stop.already_terminal).toBe(false);
        expect(stop.pause_persisted).toBe(false);

        const aggregate = replayAggregate(resolveStateRoot(workspace.env), started.investigation_id);
        expect(aggregate.stopRequests).toHaveLength(1);
        expect(aggregate.stopRequests[0].pauseRequested).toBe(true);
        expect(aggregate.pause).toBeNull();
        expect(aggregate.terminal).toBeNull();
    });

    it("returns resumable only after the pause event is durably persisted", () => {
        const workspace = makeWorkspace("stop-persisted");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
        persistPauseForStarted(workspace, started);
        const stop = stopInvestigation({
            investigation_id: started.investigation_id,
            reason: "pause now",
        }, deps);
        expect(stop).toMatchObject({
            pause_requested: true,
            pause_persisted: true,
            resumable: true,
            already_terminal: false,
        });
        expect(replayAggregate(workspace.stateRoot, started.investigation_id).pause)
            .not.toBeNull();
    });

    it("is honest when stop is called after a terminal result", () => {
        const workspace = makeWorkspace("stop-terminal");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const { deps } = makeDeps(workspace.env);
        const stop = stopInvestigation({ investigation_id: "verified-inv" }, deps);
        expect(stop).toMatchObject({
            appended: false,
            pause_persisted: false,
            resumable: false,
            already_terminal: true,
        });
    });

    it("fails clearly for an unknown investigation", () => {
        const workspace = makeWorkspace("stop-missing");
        const { deps } = makeDeps(workspace.env);
        expect(() => stopInvestigation({ investigation_id: "nope" }, deps))
            .toThrow(InvestigationNotFoundError);
    });
});

// --- crucible_result ---------------------------------------------------------

describe("crucible_result", () => {
    it("returns is_result:true with the verified terminal decision + hashes", () => {
        const workspace = makeWorkspace("result-verified");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const { deps } = makeDeps(workspace.env);

        const result = resultInvestigation({ investigation_id: "verified-inv" }, deps);
        expect(result.is_result).toBe(true);
        expect(result.banner).toBe(TERMINAL_BANNER);
        expect(result.decision).toBe("VERIFIED_RESULT");
        expect(result.candidate_id).toBe(FIRST_GENERATED_CANDIDATE_ID);
        expect(result.evidence_hash).toMatch(/^sha256:/u);
        expect(result.contract_hash).toMatch(/^sha256:crucible-contract-v1:/u);
        expect(typeof result.terminal_event_hash).toBe("string");
        expect(result.message).toContain("VERIFIED_RESULT");
    });

    it("returns is_result:true for a target-unreachable terminal decision", () => {
        const workspace = makeWorkspace("result-unreach");
        seedTargetUnreachable(workspace.stateRoot, "unreach-inv");
        const { deps } = makeDeps(workspace.env);

        const result = resultInvestigation({ investigation_id: "unreach-inv" }, deps);
        expect(result.is_result).toBe(true);
        expect(result.banner).toBe(TERMINAL_BANNER);
        expect(result.decision).toBe("TARGET_UNREACHABLE");
        expect(result.basis.kind).toBe("search_space_exhausted");
    });

    it("returns a persisted certificate-backed TARGET_UNREACHABLE only at result", () => {
        const workspace = makeWorkspace("result-certified-unreach");
        seedCertifiedTargetUnreachable(workspace.stateRoot, "certified-unreach-inv");
        const { deps } = makeDeps(workspace.env);

        const result = resultInvestigation({
            investigation_id: "certified-unreach-inv",
        }, deps);
        expect(result).toMatchObject({
            is_result: true,
            banner: TERMINAL_BANNER,
            decision: "TARGET_UNREACHABLE",
            basis: {
                kind: "verified_impossibility_certificate",
                certificateVerdict: "target_unreachable",
            },
        });
        expect(result.basis.certificateArtifactHash).toMatch(
            /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u,
        );
    });

    it("keeps an inconclusive certificate behind the strict non-result boundary", () => {
        const workspace = makeWorkspace("result-certified-non-result");
        seedCertifiedNonResult(workspace.stateRoot, "certified-non-result-inv");
        const { deps } = makeDeps(workspace.env);

        const result = resultInvestigation({
            investigation_id: "certified-non-result-inv",
        }, deps);
        expect(result).toMatchObject({
            is_result: false,
            banner: NON_RESULT_BANNER,
            non_result: true,
            non_result_code: "IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE",
        });
        for (const forbidden of [
            "decision",
            "evidence_id",
            "evidence_hash",
            "basis",
            "contract_hash",
            "terminal_event_hash",
        ]) {
            expect(result).not.toHaveProperty(forbidden);
        }
    });

    it("strictly redacts an in-progress non-result", () => {
        const workspace = makeWorkspace("result-inprogress");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);

        const result = resultInvestigation({ investigation_id: started.investigation_id }, deps);
        expect(result.is_result).toBe(false);
        expect(result.banner).toBe(NON_RESULT_BANNER);
        expect(result.message).toBe(NON_RESULT_BANNER);
        expect(typeof result.reason).toBe("string");
        // No winner or hash payload that could be laundered as success.
        for (const forbidden of [
            "decision",
            "candidate_id",
            "evidence_id",
            "evidence_hash",
            "evidence_closure",
            "contract_hash",
            "terminal_event_hash",
            "event_head_hash",
            "basis",
        ]) {
            expect(result).not.toHaveProperty(forbidden);
        }
    });

    it("strictly redacts a paused non-result", () => {
        const workspace = makeWorkspace("result-paused");
        seedPaused(workspace.stateRoot, "paused-inv");
        const { deps } = makeDeps(workspace.env);

        const result = resultInvestigation({ investigation_id: "paused-inv" }, deps);
        expect(result.is_result).toBe(false);
        expect(result.banner).toBe(NON_RESULT_BANNER);
        expect(result.paused).toBe(true);
        expect(result).not.toHaveProperty("candidate_id");
        expect(result).not.toHaveProperty("evidence_hash");
        expect(result).not.toHaveProperty("contract_hash");
    });

    it("returns persisted operational deadline outcome instead of 'still in progress'", () => {
        const workspace = makeWorkspace("result-deadline");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
        recordOperationalNonResult(workspace.stateRoot, started.investigation_id, {
            attemptId: "deadline-result",
            code: "DEADLINE_EXCEEDED",
            reason: "Deadline exhausted the current run.",
            details: { deadlineMs: Date.now() - 1, recoverable: false },
        });
        const result = resultInvestigation({
            investigation_id: started.investigation_id,
        }, deps);
        expect(result).toMatchObject({
            is_result: false,
            non_result: true,
            non_result_code: "DEADLINE_EXCEEDED",
            reason: "Deadline exhausted the current run.",
        });
        expect(result.reason).not.toContain("still in progress");
        for (const forbidden of [
            "decision",
            "candidate_id",
            "evidence_id",
            "evidence_hash",
            "contract_hash",
            "terminal_event_hash",
        ]) {
            expect(result).not.toHaveProperty(forbidden);
        }
    });

    it("fails clearly for an unknown investigation", () => {
        const workspace = makeWorkspace("result-missing");
        const { deps } = makeDeps(workspace.env);
        expect(() => resultInvestigation({ investigation_id: "nope" }, deps))
            .toThrow(InvestigationNotFoundError);
    });
});
