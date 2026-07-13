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

import { afterEach, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
    DEFAULT_SEARCH_POLICY,
    DOMAIN_VERSION,
    EVENT_TYPES,
    assessPersistedTerminalReadiness,
    createEvidenceProvenance,
    createRawMeasurementSeries,
    createInvestigationContract,
    createMeasurementProvenance,
    createSnapshotProvenance,
    canonicalJson,
    contractHash,
    computeEventHash as computeDomainEventHash,
    decideNext,
    deriveImpossibilityVerdict,
    deriveTerminalEvidenceClosure,
    enumerandBindingHash,
    evaluateReplicationProgress,
    hashCanonical,
    impossibilityProofValidationReceiptHash,
    impossibilityVerifierEnumerandResultsRoot,
    impossibilityVerifierFactsRoot,
    impossibilityVerifierRefutationReceiptHash,
    impossibilityVerifierRefutationRoot,
    replicationBlockPlan,
    resolveControlEnumerand,
} from "../domain/index.mjs";
import {
    canonicalize,
    computeEventHash as computeRepositoryEventHash,
    exportBundle,
    importBundle,
    openArtifactStore,
    openArtifactStoreReadOnly,
    openRepository,
    openRepositoryReadOnly,
    sha256Hex,
} from "../persistence/index.mjs";
import { DatabaseSync } from "../persistence/sqlite.mjs";
import {
    PROMPT_CONTEXT_HASH_ALGORITHM,
    createDomainRepositoryAdapter,
    loadSupervisorConfig,
    normalizeSupervisorConfig,
    readSupervisorLock,
    readStatus,
    requestStop,
    supervisorPaths,
} from "../runtime/index.mjs";
import {
    STREAM_HASH_ALGORITHM,
    buildMeasurementReceipt,
    hashReceipt,
    loadHarnessAllowlist,
    sha256Bytes,
} from "../measurement/index.mjs";

import {
    deriveInvestigationId,
    resolveInvestigationPaths,
    resolveStateRoot,
} from "../api/environment.mjs";
import {
    buildRegistration,
    resultInvestigation,
    runToolBoundary,
    startInvestigation,
    statusInvestigation,
    stopInvestigation,
} from "../api/handlers.mjs";
import { crucibleStartSpec } from "../api/schema.mjs";
import {
    NON_RESULT_BANNER,
    assertPublicToolPayload,
} from "../api/result.mjs";
import {
    ContractConflictError,
    EnvironmentError,
    ExperimentAuthorityMismatchApiError,
    HarnessConfigurationError,
    HarnessNotAllowlistedError,
    InvestigationNotResumableError,
    InvestigationNotFoundError,
    LegacyIncompatibleApiError,
    OperationalResetRequiredError,
    SchemaValidationError,
    StartFailedError,
    StartPreflightError,
    ValidationCasePathError,
} from "../api/errors.mjs";
import { configureExperiment } from "../tools/configure-experiment.mjs";
import { loadExperimentRegistry } from "../api/experiment-registry.mjs";
import { fakeHarnessIdentity } from "./harness-identity-fixture.mjs";
import { appendLegacyV3Investigation } from "./legacy-v3-fixture.mjs";
import {
    buildHarnessSuiteForAllowlist,
    fakeHypothesisPolicy,
    fakeObservableRegistry,
    fakeStatisticalPolicy,
    upgradeLegacyContractInput,
} from "./v4-contract-fixture.mjs";
import {
    createExperimentAuthorityFixture,
    createRuntimeConfigAuthorityFixture,
    createSignedInvestigationAuthority,
    prepareAndSignExperiment,
} from "./experiment-authority-fixture.mjs";
import {
    removeStaleTestRoots,
    removeTrackedRoots,
} from "./test-cleanup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
const authorityFixturesByStateRoot = new Map();
const VERIFIER_SANDBOX = fakeHarnessIdentity({
    harnessId: "verifier-harness",
    executesCandidateCode: true,
}).sandbox;

beforeAll(async () => {
    await removeStaleTestRoots(HERE, ".api-handlers-", {
        label: "stale api-handlers test root",
    });
});

afterEach(async () => {
    await removeTrackedRoots(roots, {
        label: "api-handlers test root",
    });
    authorityFixturesByStateRoot.clear();
});

function makeWorkspace(label) {
    const safeLabel = label.replace(/[^A-Za-z0-9._-]/gu, "-");
    const root = fs.mkdtempSync(path.join(HERE, `.api-handlers-${safeLabel}-`));
    roots.push(root);
    const experimentAuthority = createExperimentAuthorityFixture();
    const stateRoot = path.join(root, "state-root");
    const projectDir = path.join(root, "project");
    const goodDir = path.join(projectDir, "cases", "good");
    const badDir = path.join(projectDir, "cases", "bad");
    fs.mkdirSync(goodDir, { recursive: true });
    fs.mkdirSync(badDir, { recursive: true });
    fs.writeFileSync(path.join(goodDir, "input.txt"), "good-case");
    fs.writeFileSync(path.join(badDir, "input.txt"), "bad-case");

    const snapshotStoreRoot = path.join(root, "operator-corpus");
    const snapshotStore = openArtifactStore({ root: snapshotStoreRoot });
    const goodSnapshot = snapshotStore.ingestDirectory({ sourceDir: goodDir }).snapshot;
    const badSnapshot = snapshotStore.ingestDirectory({ sourceDir: badDir }).snapshot;
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
        extraCases[id] = snapshotStore.ingestDirectory({ sourceDir }).snapshot;
    }
    const harnessExecutable = path.join(root, "trusted-harness.exe");
    fs.writeFileSync(harnessExecutable, "trusted harness fixture");
    const harnessExecutableSha256 = createHash("sha256")
        .update(fs.readFileSync(harnessExecutable))
        .digest("hex");
    const verifierExecutable = path.join(root, "trusted-verifier.exe");
    fs.writeFileSync(verifierExecutable, "independent verifier fixture");
    const verifierExecutableSha256 = createHash("sha256")
        .update(fs.readFileSync(verifierExecutable))
        .digest("hex");

    const allowlistPath = path.join(root, "harnesses.json");
    const allowlistJson = {
        version: 1,
        entries: {
            "primary-harness": {
                executable: harnessExecutable,
                executableSha256: harnessExecutableSha256,
                argvTemplate: [],
                allowedEnv: {},
                timeoutMs: 15000,
                maxStdoutBytes: 1048576,
                maxStderrBytes: 262144,
                executesCandidateCode: false,
                validationCases: {
                    good: { snapshotHash: goodSnapshot, expectation: "accept" },
                    bad: { snapshotHash: badSnapshot, expectation: "reject" },
                    search: {
                        snapshotHash: extraCases.search,
                        expectation: "accept",
                    },
                    confirmation: {
                        snapshotHash: extraCases.confirmation,
                        expectation: "accept",
                    },
                    challenge: {
                        snapshotHash: extraCases.challenge,
                        expectation: "reject",
                    },
                    novelty: {
                        snapshotHash: extraCases.novelty,
                        expectation: "accept",
                    },
                },
            },
            "verifier-harness": {
                executable: verifierExecutable,
                executableSha256: verifierExecutableSha256,
                argvTemplate: [],
                allowedEnv: {},
                timeoutMs: 15000,
                maxStdoutBytes: 1048576,
                maxStderrBytes: 262144,
                executesCandidateCode: true,
            },
        },
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(allowlistJson, null, 2));
    const initialAllowlist = loadHarnessAllowlist(allowlistPath);
    allowlistJson.suites = {
        "primary-suite": buildHarnessSuiteForAllowlist(initialAllowlist, {
            includeVerifier: true,
            verifierHarnessId: "verifier-harness",
            sandboxPolicyDigest: VERIFIER_SANDBOX.policyDigest,
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

    const env = {
        CRUCIBLE_ALLOWLIST_PATH: allowlistPath,
        CRUCIBLE_CASE_STORE_PATH: snapshotStoreRoot,
        CRUCIBLE_EXPERIMENT_REGISTRY_PATH: path.join(root, "experiments.json"),
        CRUCIBLE_STATE_ROOT: stateRoot,
        COPILOT_SDK_PATH: path.join(root, "sdk"),
        COPILOT_CLI_PATH: path.join(root, "cli.exe"),
        ...experimentAuthority.env,
    };
    const sdkPath = env.COPILOT_SDK_PATH;
    fs.mkdirSync(sdkPath, { recursive: true });
    fs.writeFileSync(path.join(sdkPath, "index.js"), "export {};\n");
    fs.writeFileSync(env.COPILOT_CLI_PATH, "fixture copilot cli");
    authorityFixturesByStateRoot.set(stateRoot, {
        fixture: experimentAuthority,
        projectDir,
    });
    return {
        root,
        stateRoot,
        projectDir,
        allowlistPath,
        caseStorePath: snapshotStoreRoot,
        env,
        experimentAuthority,
    };
}

function persistSupervisorConfig(config) {
    fs.mkdirSync(config.paths.directory, { recursive: true });
    fs.writeFileSync(config.paths.configPath, JSON.stringify({
        runner: {
            investigationId: config.runner.investigationId,
            stateDir: config.runner.stateDir,
            artifactRoot: config.runner.artifactRoot,
            allowlistPath: config.runner.allowlistPath,
            copilotSdkPath: config.runner.sdkPath,
            copilotCliPath: config.runner.cliPath,
            runnerEpochId: config.runner.runnerEpochId,
            deadline: config.runner.deadlineMs,
            options: config.runner.options,
        },
        runnerCliPath: config.runnerCliPath,
        supervisorEpochId: config.supervisorEpochId,
        maxRestarts: config.maxRestarts,
        baseBackoffMs: config.baseBackoffMs,
        maxBackoffMs: config.maxBackoffMs,
        heartbeatIntervalMs: config.heartbeatIntervalMs,
        staleLockMs: config.staleLockMs,
        circuitWindowMs: config.circuitWindowMs,
    }));
}

function makeDeps(env, overrides = {}) {
    const calls = { ensure: [] };
    const deps = {
        env,
        log: () => {},
        clock: { now: () => Date.parse("2026-07-09T00:00:00.000Z") },
        isPidAlive: () => false,
        loadHarnessAllowlist,
        probeSandboxAvailability: () => ({
            available: true,
            policyIdentity: {
                ...VERIFIER_SANDBOX.policyIdentity,
                policyDigest: VERIFIER_SANDBOX.policyDigest,
            },
        }),
        openRepository,
        openRepositoryReadOnly,
        openArtifactStore,
        openArtifactStoreReadOnly,
        createDomainRepositoryAdapter,
        ensureSupervisor: (input, opts) => {
            calls.ensure.push({ input, opts });
            persistSupervisorConfig(input);
            return {
                action: "started",
                pid: 4242,
                statusPath: "status",
                acknowledged: true,
                acknowledgement: {
                    supervisorGeneration: 1,
                    runnerIncarnation: "fixture-runner-incarnation",
                    configFingerprint: "sha256:fixture-supervisor-config",
                    deadlineMs: input.runner.deadlineMs,
                },
            };
        },
        readStatus,
        requestStop,
        normalizeSupervisorConfig,
        loadSupervisorConfig,
        readSupervisorLock,
        ...overrides,
    };
    return { deps, calls };
}

function startArgs(workspace, overrides = {}) {
    const { projectDir } = workspace;
    const configured = JSON.parse(fs.readFileSync(
        path.join(path.dirname(projectDir), "harnesses.json"),
        "utf8",
    ));
    const controlSnapshot =
        configured.entries["primary-harness"].validationCases.good.snapshotHash;
    const statisticalPolicy = fakeStatisticalPolicy({
        topology: overrides.hypothesis_topology ?? "open_generative",
        searchSlots:
            (overrides.candidates_per_round ?? 1)
            * (overrides.max_rounds ?? 2),
    });
    const requestedTopology =
        overrides.hypothesis_topology ?? "open_generative";
    const searchSlots = (overrides.candidates_per_round ?? 1)
        * (overrides.max_rounds ?? 2);
    const defaultEnumerandManifest =
        requestedTopology === "certified_impossibility"
            ? {
                topology: "finite_enumerable",
                entries: Array.from({ length: searchSlots }, (_unused, index) => ({
                    id: `candidate-${index}`,
                    ordinal: index,
                    artifactSnapshotHash: [
                        configured.entries["primary-harness"]
                            .validationCases.search.snapshotHash,
                        configured.entries["primary-harness"]
                            .validationCases.confirmation.snapshotHash,
                        configured.entries["primary-harness"]
                            .validationCases.challenge.snapshotHash,
                        configured.entries["primary-harness"]
                            .validationCases.novelty.snapshotHash,
                    ][index % 4],
                })),
                control: {
                    kind: "snapshot",
                    snapshotHash: controlSnapshot,
                },
            }
            : undefined;
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
        ...(defaultEnumerandManifest === undefined
            ? {}
            : { enumerand_manifest: defaultEnumerandManifest }),
        observable_registry: fakeObservableRegistry().map((observable) => ({
            ...observable,
            maximum: observable.key === "score" ? 100 : observable.maximum,
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
            control: {
                ...statisticalPolicy.control,
                identity: controlSnapshot,
            },
        },
        worker_models: ["model-a"],
        candidates_per_round: 1,
        max_rounds: 2,
        ...authorityOverrides,
    };
    const root = path.dirname(projectDir);
    const experiment_id = `test-${createHash("sha256")
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
        allowlistPath: path.join(root, "harnesses.json"),
        env: workspace.env,
        privateKey: workspace.experimentAuthority.privateKey,
    });
    configureExperiment({
        config,
        registryPath,
        allowlistPath: path.join(root, "harnesses.json"),
        signature,
        env: workspace.env,
    });
    return {
        experiment_id,
        ...(deadline_iso === undefined ? {} : { deadline_iso }),
    };
}

// --- domain seeding for terminal-state result tests ------------------------

const seedArtifactHash = (character) => `sha256:${character.repeat(64)}`;
const fixtureHarnessEntryHash = (character = "a") =>
    `sha256:crucible-measurement-entry-v1:${character.repeat(64)}`;

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

function seedDigest(value) {
    return value.split(":").at(-1);
}

function seedArtifact(label, hash) {
    const safeLabel = label.replace(/[^A-Za-z0-9._-]/gu, "-").slice(0, 48);
    return {
        artifactId: `seed-${safeLabel}-${seedDigest(hash).slice(0, 16)}`,
        objectId: `sha256:${seedDigest(hash)}`,
    };
}

function registerStoredArtifact(adapter, label, stored, contentType) {
    const artifact = seedArtifact(label, stored.id);
    const existing = adapter.repository.getArtifact(artifact.artifactId);
    if (existing === null) {
        adapter.repository.registerExternalArtifact({
            investigationId: adapter.investigationId,
            artifactId: artifact.artifactId,
            algo: "sha256",
            hash: stored.hash,
            sizeBytes: stored.size,
            contentType,
        });
        adapter.repository.markArtifactDurable(artifact.artifactId);
    }
    return artifact;
}

function persistSeedBytes(adapter, store, label, bytes, contentType) {
    return registerStoredArtifact(
        adapter,
        label,
        store.putBytes(bytes, { contentType }),
        contentType,
    );
}

function createSeedSnapshot(store, files) {
    const entries = files.map((file) => {
        const bytes = Buffer.isBuffer(file.content)
            ? file.content
            : Buffer.from(file.content, "utf8");
        const stored = store.putBytes(bytes, { contentType: "application/octet-stream" });
        return { path: file.path, size: stored.size, object: stored.id };
    }).sort((left, right) => left.path.localeCompare(right.path));
    const manifest = {
        type: "crucible-snapshot",
        version: 1,
        algo: "sha256",
        fileCount: entries.length,
        totalBytes: entries.reduce((sum, entry) => sum + entry.size, 0),
        entries,
    };
    const stored = store.putBytes(
        Buffer.from(canonicalize(manifest), "utf8"),
        { contentType: "application/vnd.crucible.snapshot+json" },
    );
    return { snapshotId: stored.id, manifest };
}

function impossibilitySnapshotFiles(store, reserved) {
    const generated = new Map([
        [
            "coverage-closure.json",
            reserved.request.evidence.coverageClosure,
        ],
        [
            "enumerand-manifest.json",
            reserved.request.enumerands.manifest,
        ],
        [
            "scientific-replay.json",
            reserved.request.statistics.scientificReplay,
        ],
        ["proof-artifact.json", reserved.proofArtifact],
    ]);
    if (reserved.request.reevaluation.calibration !== null) {
        generated.set(
            "reevaluation/calibration.json",
            reserved.request.reevaluation.calibration,
        );
    }
    for (const input of reserved.request.reevaluation.enumerands) {
        generated.set(
            `reevaluation/enumerands/${String(input.ordinal)
                .padStart(6, "0")}.json`,
            input,
        );
    }
    const generatedFiles = reserved.request.objectManifest.entries
        .filter((entry) => entry.kind === "generated")
        .map((entry) => ({
            path: entry.path,
            content: canonicalJson(generated.get(entry.path)),
        }));
    const packedEntries = reserved.request.objectManifest.entries
        .filter((entry) => entry.kind === "cas_object")
        .map((entry) => ({
            path: entry.path,
            objectId: entry.objectId,
            byteHash: entry.byteHash,
            artifactIds: entry.artifactIds,
            semanticHashes: entry.semanticHashes,
            contentBase64:
                store.readObject(entry.objectId).toString("base64"),
        }));
    return [
        {
            path: "request.json",
            content: canonicalJson(reserved.request),
        },
        {
            path: "proposed-certificate.json",
            content: canonicalJson(reserved.proposedCertificate),
        },
        ...generatedFiles,
        {
            path: reserved.request.objectManifest.pack.path,
            content: canonicalJson({
                version:
                    reserved.request.objectManifest.pack.format,
                entries: packedEntries,
            }),
        },
    ];
}

function seedSnapshotClosureHash(snapshotId, manifest) {
    const directories = new Set();
    for (const entry of manifest.entries) {
        const segments = entry.path.split("/");
        for (let depth = 1; depth < segments.length; depth += 1) {
            directories.add(segments.slice(0, depth).join("/"));
        }
    }
    return hashCanonical({
        version: 1,
        snapshotId,
        expectedObjectClosure: [...new Set([
            snapshotId,
            ...manifest.entries.map((entry) => entry.object),
        ])].sort(),
        directories: [...directories].sort(),
        files: manifest.entries.map((entry) => ({
            path: entry.path,
            size: entry.size,
            object: entry.object,
        })),
    }, "sha256:crucible-measurement-snapshot-closure-v1");
}

function persistSeedSnapshot(adapter, store, label, snapshotId) {
    const manifest = store.loadManifest(snapshotId);
    const manifestBytes = store.readObject(snapshotId);
    const manifestArtifact = registerStoredArtifact(
        adapter,
        `${label}-manifest`,
        {
            id: snapshotId,
            hash: seedDigest(snapshotId),
            size: manifestBytes.length,
        },
        "application/vnd.crucible.snapshot+json",
    );
    const objectArtifacts = [...new Map(
        manifest.entries.map((entry) => [entry.object, entry.size]),
    ).entries()].sort(([left], [right]) => left.localeCompare(right))
        .map(([objectId, size], index) =>
            registerStoredArtifact(
                adapter,
                `${label}-object-${index}`,
                { id: objectId, hash: seedDigest(objectId), size },
                "application/octet-stream",
            ));
    return createSnapshotProvenance({
        snapshotHash: `sha256:crucible-measurement-snapshot-v1:${seedDigest(snapshotId)}`,
        manifestArtifact,
        objectArtifacts,
    });
}

function seedValidationCases(store) {
    return [
        {
            id: "good",
            expectation: "accept",
            artifactHash: createSeedSnapshot(store, [
                { path: "input.txt", content: "good-case" },
            ]).snapshotId,
        },
        {
            id: "bad",
            expectation: "reject",
            artifactHash: createSeedSnapshot(store, [
                { path: "input.txt", content: "bad-case" },
            ]).snapshotId,
        },
    ];
}

function seedMeasurementReceipt({
    aggregate,
    observationId,
    subjectId,
    snapshotHash,
    snapshotId,
    snapshotManifest,
    parsed,
    stdoutHash,
    stderrHash,
    stdoutBytes,
    stderrBytes,
    measurementBinding = null,
}) {
    const executableHash = hashCanonical(
        { harness: "executable" },
        "sha256:crucible-measurement-file-v1",
    );
    const dependencyHash = hashCanonical(
        { harness: "dependency" },
        "sha256:crucible-measurement-file-v1",
    );
    const closureHash = seedSnapshotClosureHash(snapshotId, snapshotManifest);
    const identity = {
        root: snapshotHash,
        files: [{ subjectId, snapshotHash }],
    };
    const verifier = measurementBinding?.role === "impossibility_verifier";
    const parserVersion = verifier
        ? aggregate.contract.harnessSuite.roles.impossibility_verifier
            .parser.version
        : aggregate.contract.parserVersion;
    const parserIdentity = verifier
        ? aggregate.contract.harnessSuite.roles.impossibility_verifier.parser
        : aggregate.contract.harnessSuite.roles.search.parser;
    const harnessId = verifier
        ? aggregate.contract.harnessSuite.roles.impossibility_verifier.harnessId
        : aggregate.contract.harnessSuite.roles.search.harnessId;
    const sandbox = verifier
        ? {
            sandboxId: "fixture-appcontainer",
            environmentHash: hashCanonical({
                observationId,
                subjectId,
                sandbox: true,
            }),
            providerId: VERIFIER_SANDBOX.policyIdentity.providerId,
            providerVersion: VERIFIER_SANDBOX.policyIdentity.providerVersion,
            policyId: VERIFIER_SANDBOX.policyIdentity.policyId,
            policyDigest: VERIFIER_SANDBOX.policyDigest,
            policyIdentity: VERIFIER_SANDBOX.policyIdentity,
            policy: VERIFIER_SANDBOX.policyIdentity,
            capabilityId: `capability-${subjectId}`,
            launchPath: "fixture-appcontainer-launch",
            capabilityLaunchUsed: true,
            permittedStagedRoots: ["C:\\fixture\\stage"],
        }
        : null;
    return buildMeasurementReceipt({
        harnessId,
        allowlistFileHash: hashCanonical(
            { harness: "allowlist" },
            "sha256:crucible-measurement-file-v1",
        ),
        harnessEntryHash: hashCanonical(
            { harness: "entry" },
            "sha256:crucible-measurement-entry-v1",
        ),
        executableHash,
        stagedExecutableHash: executableHash,
        dependencyHashes: [{
            path: "C:\\fake\\dependency.bin",
            role: "support",
            sha256: dependencyHash,
        }],
        stagedDependencyHashes: [{
            path: "C:\\stage\\dependency.bin",
            role: "support",
            sha256: dependencyHash,
        }],
        launchFileBindings: [{
            path: "C:\\stage\\candidate.bin",
            role: "candidate",
            sha256: snapshotHash,
            identity: {
                dev: "1",
                ino: "1",
                size: "1",
                mode: "33188",
                mtimeNs: "1",
                ctimeNs: "1",
            },
        }],
        argvHash: hashCanonical(
            { observationId, subjectId, argv: true },
            "sha256:crucible-measurement-argv-v1",
        ),
        envHash: hashCanonical(
            { observationId, subjectId, env: true },
            "sha256:crucible-measurement-env-v1",
        ),
        candidateSnapshotHash: snapshotHash,
        stagedCandidateSnapshotHash: snapshotHash,
        stagedCandidateSnapshotClosureHash: closureHash,
        stagedCandidateSnapshotIdentitySummary: identity,
        candidateSnapshotPreClosureHash: closureHash,
        candidateSnapshotPostClosureHash: closureHash,
        candidateSnapshotIdentitySummary: { pre: identity, post: identity },
        candidateSnapshotMutationCheck: {
            status: "passed",
            closureStable: true,
            identityStable: true,
            openHandleRehashStable: true,
            reparseStable: true,
        },
        stdoutHash,
        stderrHash,
        outputCapture: {
            stdout: {
                capBytes: 1024 * 1024,
                totalObservedBytes: stdoutBytes,
                retainedBytes: stdoutBytes,
                overflowed: false,
                truncated: false,
            },
            stderr: {
                capBytes: 256 * 1024,
                totalObservedBytes: stderrBytes,
                retainedBytes: stderrBytes,
                overflowed: false,
                truncated: false,
            },
            overflowed: false,
            truncated: false,
        },
        parserVersion,
        parserIdentity,
        sandbox,
        ...(measurementBinding === null ? {} : { measurementBinding }),
        attemptId: `attempt-${observationId}-${subjectId}`,
        runnerEpochId: "runner-epoch-seed",
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:00:00.001Z",
        durationMs: 1,
        exit: { code: 0, signal: null, timedOut: false },
        parsed,
    });
}

function seedImpossibilityCheckerResult(aggregate, reserved, facts) {
    const status = facts?.status
        ?? (facts?.pass === false
            ? "REJECTED"
            : facts?.searchSpaceExhausted === false
                ? "INVALID"
                : "VERIFIED");
    const verdict = deriveImpossibilityVerdict({ status });
    const mode = reserved.request.verifier.verificationPolicy.mode;
    const certificateFormat =
        reserved.request.verifier.verificationPolicy.certificateFormat;
    const proofArtifactHash = reserved.proofArtifactHash;
    const proofCheckerIdentity = mode === "certificate_validation"
        ? reserved.request.verifier.proofChecker.identity
        : null;
    const validatedProofArtifactHash = mode === "certificate_validation"
        ? proofArtifactHash
        : null;
    const checkerEvidenceRoot = hashCanonical({
        requestHash: reserved.requestHash,
        status,
        checker: "fixture",
    }, "sha256:crucible-test-checker-evidence-v1");
    const coverageClosureRoot =
        reserved.request.evidence.coverageClosureRoot;
    const expectedEnumerands =
        reserved.request.evidence.coverageClosure.enumerands;
    const claimState = status === "VERIFIED"
        ? "REFUTED"
        : status === "REJECTED"
            ? "SUPPORTED"
            : status === "INCONCLUSIVE"
                ? "UNRESOLVED"
                : "INVALID";
    const enumerandResults = mode === "enumerand_reexecution"
        ? (status === "INCONCLUSIVE" || status === "INVALID"
            ? expectedEnumerands.slice(0, 1)
            : expectedEnumerands).map((entry) => {
            const input =
                reserved.request.reevaluation.enumerands[entry.ordinal];
            const claimStates = entry.claims.map((claim) => ({
                claimId: claim.claimId,
                state: claimState,
            }));
            const evidenceRoot = impossibilityVerifierRefutationRoot({
                requestHash: reserved.requestHash,
                verifierRoleIdentity:
                    reserved.request.verifier.roleIdentity,
                ordinal: entry.ordinal,
                enumerandHash: entry.enumerandHash,
                inputRoot: input.inputRoot,
                claimStates,
            });
            return {
                ordinal: entry.ordinal,
                enumerandHash: entry.enumerandHash,
                claimStates,
                inputRoot: input.inputRoot,
                receiptBindingsRoot: input.receiptBindingsRoot,
                evidenceRoot,
                refutationReceiptHash:
                    impossibilityVerifierRefutationReceiptHash({
                        requestHash: reserved.requestHash,
                        verifierRoleIdentity:
                            reserved.request.verifier.roleIdentity,
                        ordinal: entry.ordinal,
                        enumerandHash: entry.enumerandHash,
                        inputRoot: input.inputRoot,
                        receiptBindingsRoot:
                            input.receiptBindingsRoot,
                        claimStates,
                        evidenceRoot,
                    }),
            };
        })
        : [];
    const enumerandResultsRoot =
        impossibilityVerifierEnumerandResultsRoot(enumerandResults);
    const proofValidationReceiptHash = mode === "certificate_validation"
        ? impossibilityProofValidationReceiptHash({
            requestHash: reserved.requestHash,
            proofArtifactHash,
            proofCheckerIdentity,
            certificateFormat,
            status,
            checkerEvidenceRoot,
        })
        : null;
    const independentFactsRoot = impossibilityVerifierFactsRoot({
        mode,
        enumerandResults,
        proofArtifactHash,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
    });
    const certificate = {
        version: reserved.certificateVersion,
        status,
        verdict,
        mode,
        requestHash: reserved.requestHash,
        proposedCertificateArtifactHash:
            reserved.proposedCertificateArtifactHash,
        proofArtifactHash,
        contractHash: aggregate.contractHash,
        harnessSuiteIdentity: aggregate.contract.harnessSuiteIdentity,
        verifierRoleIdentity: reserved.request.verifier.roleIdentity,
        coverageClosureRoot,
        enumerandManifestRoot: reserved.request.enumerands.merkleRoot,
        enumerandResultsRoot,
        evidenceRoots: reserved.request.evidence.roots,
        statisticalPolicyIdentity:
            reserved.request.statistics.policyIdentity,
        alphaLedgerRoot: reserved.request.statistics.alphaLedgerRoot,
        checkerEvidenceRoot,
        independentFactsRoot,
        certificateFormat,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
    };
    const raw = {
        version: "crucible-impossibility-verifier-output-v1",
        status,
        mode,
        requestHash: reserved.requestHash,
        proposedCertificateArtifactHash:
            reserved.proposedCertificateArtifactHash,
        proofArtifactHash,
        coverageClosureRoot,
        enumerandManifestRoot: reserved.request.enumerands.merkleRoot,
        enumerandCount: reserved.request.enumerands.count,
        checkedEnumerandCount: enumerandResults.length,
        enumerandResults,
        enumerandResultsRoot,
        evidenceRoots: reserved.request.evidence.roots,
        statisticalPolicyIdentity:
            reserved.request.statistics.policyIdentity,
        alphaLedgerRoot: reserved.request.statistics.alphaLedgerRoot,
        checkerEvidenceRoot,
        independentFactsRoot,
        disagreementCount: enumerandResults.filter((result) =>
            result.claimStates.some((claim) => claim.state !== "REFUTED")).length,
        complete: status === "VERIFIED" || status === "REJECTED",
        certificateFormat,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
        certificate,
        role: reserved.measurementBinding.role,
        phase: reserved.measurementBinding.phase,
        blockIndex: reserved.measurementBinding.blockIndex,
        deterministicSeed: reserved.measurementBinding.deterministicSeed,
        subjectId: reserved.measurementBinding.subjectId,
        environmentIdentity:
            reserved.measurementBinding.environmentIdentity,
        suiteIdentity: reserved.measurementBinding.suiteIdentity,
    };
    return {
        raw,
        parsed: {
            ...raw,
            replicateIndex: null,
            armIndex: null,
            armId: null,
            parserVersion: reserved.parserVersion,
        },
        certificate,
        status,
        verdict,
    };
}

function seedControlSnapshotId(aggregate) {
    const control = aggregate.contract.statisticalPolicy.control;
    if (control.kind === "snapshot") return control.identity;
    const binding = resolveControlEnumerand(
        aggregate.contract.enumerandManifest,
        {
            topology: aggregate.contract.enumerandManifest.topology,
            observableRegistry: aggregate.contract.observableRegistry,
            hypothesisPolicy: aggregate.contract.hypothesisPolicy,
        },
    );
    if (binding.kind === "reference") return binding.referenceHash;
    if (binding.topology === "finite_enumerable") {
        return binding.artifactSnapshotHash;
    }
    throw new Error("seeded bounded control requires a snapshot reference");
}

function seedReceipt(adapter, store, aggregate, reserved, observationId, purpose, options = {}) {
    const replicatedPurpose = purpose === "candidate"
        || purpose === "confirmation"
        || purpose === "challenge";
    const impossibilityChecker = purpose === "impossibility"
        ? seedImpossibilityCheckerResult(
            aggregate,
            reserved,
            options.impossibilityFacts,
        )
        : null;
    const subjectDescriptors = purpose === "validation"
        ? reserved.validationSeries.flatMap((series) =>
            replicationBlockPlan(
                series.replicationSchedule,
                reserved.attemptIndex,
            ).arms.map((arm) => ({
                subjectId: arm.subjectId,
                arm,
                series,
            })))
        : replicatedPurpose
            ? Array.from(
                {
                    length: options.blockCount
                        ?? reserved.replicationSchedule.minBlocks,
                },
                (_unused, blockIndex) =>
                    replicationBlockPlan(
                        reserved.replicationSchedule,
                        blockIndex,
                    ).arms,
            ).flat()
                .sort((left, right) =>
                    left.blockIndex - right.blockIndex
                    || left.armIndex - right.armIndex)
                .map((arm) => ({ subjectId: arm.subjectId, arm, series: null }))
            : [{
                subjectId: `impossibility-${reserved.attemptOrdinal}`,
                arm: null,
                series: null,
            }];
    let candidateProposalArtifact = null;
    let promptContextHash = null;
    let candidateSnapshot = null;
    let replicationScheduleArtifact = null;
    if (purpose === "candidate") {
        const assignment = {
            operator: reserved.operator,
            round: reserved.round,
            slotIndex: reserved.slotIndex,
            candidateId: reserved.candidateId,
            model: reserved.model,
            seed: reserved.seed,
            parentEvidenceIds: reserved.parentEvidenceIds,
            promptContextRefs: reserved.promptContextRefs,
            ...(reserved.boundedCandidateId === null
                || reserved.boundedCandidateId === undefined
                ? {}
                : { boundedCandidateId: reserved.boundedCandidateId }),
        };
        const promptContext = {
            version: "crucible-runtime-prompt-context-v1",
            assignment,
            objective: aggregate.contract.objective,
            priorWork: {},
        };
        promptContextHash = hashCanonical(
            promptContext,
            PROMPT_CONTEXT_HASH_ALGORITHM,
        );
        const finiteEnumerand =
            reserved.enumerand?.topology === "finite_enumerable";
        const proposal = {
            candidateId: reserved.candidateId,
            annotations: {
                mechanism: null,
                hypothesis: null,
                expectedEffects: [],
                citedEvidenceIds: [],
                finding: null,
            },
            files: finiteEnumerand
                ? []
                : [{
                    path: "candidate.txt",
                    content: `candidate-${reserved.candidateId}-${observationId}`,
                }],
            identity: finiteEnumerand
                ? {
                    source: "frozen_enumerand_manifest",
                    enumerandBindingHash:
                        enumerandBindingHash(reserved.enumerand),
                }
                : null,
        };
        candidateSnapshot = reserved.enumerand?.topology === "finite_enumerable"
            ? {
                snapshotId: reserved.enumerand.artifactSnapshotHash,
                manifest: store.loadManifest(
                    reserved.enumerand.artifactSnapshotHash,
                ),
            }
            : createSeedSnapshot(store, proposal.files);
        candidateProposalArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-proposal`,
            Buffer.from(canonicalJson({
                assignment,
                promptContext,
                promptContextHash,
                ...(finiteEnumerand
                    ? { enumerand: reserved.enumerand }
                    : {}),
                proposal,
            }), "utf8"),
            "application/vnd.crucible.candidate-proposal+json",
        );
    } else if (replicatedPurpose) {
        const snapshotId =
            `sha256:${reserved.candidateArtifactHash.split(":").at(-1)}`;
        candidateSnapshot = {
            snapshotId,
            manifest: store.loadManifest(snapshotId),
        };
    }
    if (replicatedPurpose) {
        replicationScheduleArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-replication-schedule`,
            Buffer.from(canonicalJson(reserved.replicationSchedule), "utf8"),
            "application/vnd.crucible.measurement-schedule+json",
        );
    }
    const measurementDetails = subjectDescriptors.map(({
        subjectId,
        arm,
        series,
    }) => {
        const snapshotId = purpose === "validation"
            ? series.artifactHash
            : replicatedPurpose
                ? arm.armId === "control"
                    ? seedControlSnapshotId(aggregate)
                    : candidateSnapshot.snapshotId
                : createSeedSnapshot(
                    store,
                    impossibilitySnapshotFiles(store, reserved),
                ).snapshotId;
        const rawParsed = purpose === "validation"
            ? {
                pass: aggregate.contract.validationCases.find(
                    (item) => item.id === series.caseId,
                ).expectation === "accept",
                metrics: {
                    score: aggregate.contract.validationCases.find(
                        (item) => item.id === series.caseId,
                    ).expectation === "accept"
                        ? aggregate.contract.statisticalPolicy.metrics[0].maximum
                        : aggregate.contract.statisticalPolicy.metrics[0].minimum,
                },
            }
            : replicatedPurpose
                ? options.candidateData
                : impossibilityChecker.raw;
        const measurementBinding = arm === null
            ? reserved.measurementBinding
            : {
                role: purpose === "validation"
                    ? series.role
                    : purpose === "candidate"
                        ? "search"
                        : purpose,
                phase: purpose === "validation"
                    ? "calibration"
                    : purpose === "candidate"
                        ? "search"
                        : purpose,
                replicateIndex: arm.replicateIndex,
                blockIndex: arm.blockIndex,
                armIndex: arm.armIndex,
                armId: arm.armId,
                deterministicSeed: arm.deterministicSeed,
                subjectId: arm.subjectId,
                environmentIdentity:
                    aggregate.contract.harnessSuite.environmentIdentity,
                suiteIdentity: aggregate.contract.harnessSuiteIdentity,
            };
        const parsed = purpose === "impossibility"
            ? impossibilityChecker.parsed
            : measurementBinding === null
            ? rawParsed
            : { ...rawParsed, ...measurementBinding };
        const stdoutBytes = Buffer.from(canonicalJson(rawParsed), "utf8");
        const stderrBytes = Buffer.from(`stderr-${observationId}-${subjectId}`, "utf8");
        const stdoutHash = sha256Bytes(stdoutBytes, STREAM_HASH_ALGORITHM);
        const stderrHash = sha256Bytes(stderrBytes, STREAM_HASH_ALGORITHM);
        const snapshot = persistSeedSnapshot(
            adapter,
            store,
            `${observationId}-${subjectId}`,
            snapshotId,
        );
        const fullReceipt = seedMeasurementReceipt({
            aggregate,
            observationId,
            subjectId,
            snapshotHash: snapshot.snapshotHash,
            snapshotId,
            snapshotManifest: store.loadManifest(snapshotId),
            parsed,
            stdoutHash,
            stderrHash,
            stdoutBytes: stdoutBytes.length,
            stderrBytes: stderrBytes.length,
            measurementBinding,
        });
        const receiptArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-${subjectId}-receipt`,
            Buffer.from(canonicalJson(fullReceipt), "utf8"),
            "application/vnd.crucible.measurement-receipt+json",
        );
        const rawStdoutArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-${subjectId}-stdout`,
            stdoutBytes,
            "application/vnd.crucible.measurement-stdout",
        );
        const rawStderrArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-${subjectId}-stderr`,
            stderrBytes,
            "application/vnd.crucible.measurement-stderr",
        );
        const measurement = createMeasurementProvenance({
            subjectId,
            role: fullReceipt.role
                ?? (purpose === "impossibility"
                    ? "impossibility_verifier"
                    : purpose === "validation"
                        ? series.role
                        : purpose === "candidate"
                            ? "search"
                            : purpose),
            phase: fullReceipt.phase
                ?? (purpose === "impossibility"
                    ? "impossibility_verification"
                    : purpose === "validation"
                        ? "calibration"
                        : purpose === "candidate"
                            ? "search"
                            : purpose),
            receiptArtifact,
            receiptHash: hashReceipt(fullReceipt),
            rawStdoutArtifact,
            rawStdoutHash: stdoutHash,
            rawStderrArtifact,
            rawStderrHash: stderrHash,
            parserVersion: fullReceipt.parserVersion,
            allowlistFileHash: fullReceipt.allowlistFileHash,
            harnessEntryHash: fullReceipt.harnessEntryHash,
            executableHash: fullReceipt.executableHash,
            stagedExecutableHash: fullReceipt.stagedExecutableHash,
            dependencyHashes: fullReceipt.dependencyHashes,
            stagedDependencyHashes: fullReceipt.stagedDependencyHashes,
            argvHash: fullReceipt.argvHash,
            envHash: fullReceipt.envHash,
            sandboxPolicy: purpose === "impossibility"
                ? {
                    kind: "sandbox",
                    sandboxId: fullReceipt.sandbox.sandboxId,
                    environmentHash:
                        fullReceipt.sandbox.environmentHash,
                }
                : {
                    kind: "none",
                    sandboxId: null,
                    environmentHash: null,
                },
            snapshot,
            snapshotExecutionHash: hashCanonical(
                {
                    stagedCandidateSnapshotHash:
                        fullReceipt.stagedCandidateSnapshotHash,
                    stagedCandidateSnapshotClosureHash:
                        fullReceipt.stagedCandidateSnapshotClosureHash,
                    stagedCandidateSnapshotIdentitySummary:
                        fullReceipt.stagedCandidateSnapshotIdentitySummary,
                    candidateSnapshotPreClosureHash:
                        fullReceipt.candidateSnapshotPreClosureHash,
                    candidateSnapshotPostClosureHash:
                        fullReceipt.candidateSnapshotPostClosureHash,
                    candidateSnapshotIdentitySummary:
                        fullReceipt.candidateSnapshotIdentitySummary,
                    candidateSnapshotMutationCheck:
                        fullReceipt.candidateSnapshotMutationCheck,
                },
                "sha256:crucible-evidence-snapshot-execution-v1",
            ),
        });
        adapter.ingestOperationalEvidence({
            attemptId: fullReceipt.attemptId,
            evidenceKind:
                `measurement:${aggregate.commandOrder.at(-1)}:${subjectId}`,
            kind: "runtime:measurement",
            payload: {
                commandId: aggregate.commandOrder.at(-1),
                purpose,
                measurementSubjectId: subjectId,
                measurementProvenance: measurement,
            },
        });
        return {
            measurement,
            fullReceipt,
            stdoutBytes,
            stderrBytes,
            arm,
            series,
        };
    });
    const measurements = measurementDetails.map((item) => item.measurement);
    let validationCompositeArtifact = null;
    let impossibilityCertificateArtifact = null;
    let replicationCompositeArtifact = null;
    let data;
    let impossibilityReceiptFields = {};
    if (purpose === "validation") {
        const series = reserved.validationSeries.map((reservedSeries) => {
            const details = measurementDetails.filter((detail) =>
                detail.series.role === reservedSeries.role
                && detail.series.caseId === reservedSeries.caseId);
            return createRawMeasurementSeries({
                schedule: reservedSeries.replicationSchedule,
                attempts: details.map((detail) => ({
                    ...detail.arm,
                    attemptId: detail.fullReceipt.attemptId,
                    parsed: detail.fullReceipt.parsed,
                    invalid: null,
                    receiptHash: detail.measurement.receiptHash,
                    measurementRoot: detail.measurement.measurementRoot,
                })),
                role: reservedSeries.role,
                phase: "calibration",
                caseId: reservedSeries.caseId,
            });
        }).sort((left, right) =>
            `${left.role}\0${left.caseId}`.localeCompare(
                `${right.role}\0${right.caseId}`,
            ));
        data = {
            version: 1,
            attemptIndex: reserved.attemptIndex,
            series,
        };
        validationCompositeArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-validation`,
            Buffer.from(canonicalJson({
                version: 2,
                authority: "raw_complete_blocks",
                commandId: aggregate.commandOrder.at(-1),
                attemptIndex: reserved.attemptIndex,
                series,
            }), "utf8"),
            "application/vnd.crucible.validation-receipt+json",
        );
    } else if (replicatedPurpose) {
        const role = purpose === "candidate" ? "search" : purpose;
        const series = createRawMeasurementSeries({
            schedule: reserved.replicationSchedule,
            attempts: measurementDetails.map((detail) => ({
                ...detail.arm,
                attemptId: detail.fullReceipt.attemptId,
                parsed: detail.fullReceipt.parsed,
                invalid: null,
                receiptHash: detail.measurement.receiptHash,
                measurementRoot: detail.measurement.measurementRoot,
            })),
            role,
            phase: role,
            caseId: null,
        });
        const replicationProgress = evaluateReplicationProgress({
            contract: aggregate.contract,
            schedule: reserved.replicationSchedule,
            attempts: series.completeBlocks.flatMap(
                (block) => block.observations,
            ),
        });
        data = { version: 1, series: [series] };
        const composite = purpose === "candidate"
            ? {
                version: 2,
                authority: "raw_complete_blocks",
                commandId: aggregate.commandOrder.at(-1),
                candidateId: reserved.candidateId,
                schedule: reserved.replicationSchedule,
                scheduleArtifact: replicationScheduleArtifact,
                series,
                stopping: replicationProgress.stopping,
            }
            : {
                version: 2,
                authority: "raw_complete_blocks",
                commandId: aggregate.commandOrder.at(-1),
                candidateId: reserved.candidateId,
                candidateEvidenceId: reserved.candidateEvidenceId,
                confirmationFreezeHash:
                    reserved.confirmationFreezeHash,
                role,
                protocolManifest: reserved.protocolManifest,
                protocolManifestHash:
                    reserved.protocolManifestHash,
                schedule: reserved.replicationSchedule,
                scheduleArtifact: replicationScheduleArtifact,
                series,
                stopping: replicationProgress.stopping,
            };
        replicationCompositeArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-replication-composite`,
            Buffer.from(canonicalJson(composite), "utf8"),
            "application/vnd.crucible.replication-composite+json",
        );
    } else {
        const detail = measurementDetails[0];
        const certificate = impossibilityChecker.certificate;
        const certificateVerdict = impossibilityChecker.verdict;
        const certificateBytes = Buffer.from(canonicalJson(certificate), "utf8");
        impossibilityCertificateArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-certificate`,
            certificateBytes,
            "application/vnd.crucible.impossibility-certificate+json",
        );
        data = {
            certificateVersion: reserved.certificateVersion,
            checkerStatus: impossibilityChecker.status,
            certificateVerdict,
            certificateArtifactHash: `sha256:crucible-impossibility-certificate-artifact-v2:${sha256Hex(certificateBytes)}`,
            measurementReceiptHash: detail.measurement.receiptHash,
            verificationRequestHash: reserved.requestHash,
            proposedCertificateArtifactHash:
                reserved.proposedCertificateArtifactHash,
            verificationSnapshotHash: detail.measurement.snapshot.snapshotHash,
            checkerResult: impossibilityChecker.parsed,
        };
        impossibilityReceiptFields = {
            certificateArtifactHash: data.certificateArtifactHash,
            measurementReceiptArtifactHash:
                `sha256:crucible-impossibility-receipt-artifact-v1:${sha256Hex(Buffer.from(canonicalJson(detail.fullReceipt), "utf8"))}`,
            measurementReceiptHash: detail.measurement.receiptHash,
            rawStderrArtifactHash:
                `sha256:crucible-impossibility-stderr-artifact-v1:${sha256Hex(detail.stderrBytes)}`,
            rawStdoutArtifactHash:
                `sha256:crucible-impossibility-stdout-artifact-v1:${sha256Hex(detail.stdoutBytes)}`,
            verificationRequestHash: reserved.requestHash,
            verificationSnapshotHash: detail.measurement.snapshot.snapshotHash,
        };
    }
    const provenance = createEvidenceProvenance({
        proposalArtifact: candidateProposalArtifact,
        promptContextHash,
        validationCompositeArtifact,
        impossibilityCertificateArtifact,
        replicationScheduleArtifact,
        replicationCompositeArtifact,
        measurements,
    }, {
        purpose,
        command: reserved,
        contract: aggregate.contract,
    });
    return {
        receipt: {
        version: 1,
        attemptId: purpose === "validation" || replicatedPurpose
            ? `attempt-${observationId}`
            : measurementDetails[0].fullReceipt.attemptId,
        runnerEpochId: "runner-epoch-seed",
        rawStdoutHash: purpose === "validation" || replicatedPurpose
            ? hashCanonical(
                provenance.measurements.map((item) => ({
                    id: item.subjectId,
                    hash: item.rawStdoutHash,
                })),
                "sha256:crucible-runtime-observation-streams-v1",
            )
            : provenance.measurements[0].rawStdoutHash,
        rawStderrHash: purpose === "validation" || replicatedPurpose
            ? hashCanonical(
                provenance.measurements.map((item) => ({
                    id: item.subjectId,
                    hash: item.rawStderrHash,
                })),
                "sha256:crucible-runtime-observation-streams-v1",
            )
            : provenance.measurements[0].rawStderrHash,
        candidateArtifactHash: replicatedPurpose
            ? measurementDetails.find((detail) =>
                detail.arm.armId === "candidate")
                .measurement.snapshot.snapshotHash
            : null,
        provenance,
        ...impossibilityReceiptFields,
        },
        data,
    };
}

function seedImpossibilityObservation(adapter, store, aggregate, reserved, observationId, facts) {
    const seeded = seedReceipt(
        adapter,
        store,
        aggregate,
        reserved,
        observationId,
        "impossibility",
        { impossibilityFacts: facts },
    );
    return {
        purpose: "impossibility",
        receipt: seeded.receipt,
        data: seeded.data,
    };
}

function baseSeedContract(overrides = {}) {
    const input = upgradeLegacyContractInput({
        objective: "seed objective",
        acceptancePredicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: 0,
        },
        validationCases: [
            { id: "good", expectation: "accept", artifactHash: seedArtifactHash("a") },
            { id: "bad", expectation: "reject", artifactHash: seedArtifactHash("b") },
        ],
        harnessId: "primary-harness",
        criticality: "standard",
        policyVersion: "policy-v1",
        parserVersion: "parser-v1",
        harnessIdentity: fakeHarnessIdentity({
            harnessId: "primary-harness",
            parserVersion: "parser-v1",
        }),
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        searchPolicy: searchPolicy(),
        declaredLimits: {},
        verifierSandboxPolicyDigest: VERIFIER_SANDBOX.policyDigest,
        ...overrides,
    });
    if ((input.hypothesisTopology === "finite_enumerable"
            || input.hypothesisTopology === "bounded_parameterized"
            || input.hypothesisTopology === "certified_impossibility")
        && overrides.statisticalPolicy === undefined) {
        input.statisticalPolicy = fakeStatisticalPolicy({
            topology: input.hypothesisTopology,
            searchSlots: input.enumerandManifest.entries.length,
            manifest: input.enumerandManifest,
            minBlocks: 1,
            maxBlocks: 32,
            metrics: input.statisticalPolicy.metrics,
        });
    }
    return input;
}

// Generic domain driver: consumes decideNext recommendations, supplying
// external inputs (dispatch/observe/commit/stop) and recording kernel decisions,
// until a terminal / pause / non-result aggregate is reached. Under domain-v2 the
// kernel reserves one deterministic per-candidate `search_candidate` command per
// slot; each queue entry supplies only the harness `data` (and optional
// annotations) for the next candidate slot, while round/slot/candidateId are
// inherited from the reserved assignment.
function driveToTerminal(adapter, store, candidateQueue) {
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
                    const seeded = seedReceipt(
                        adapter,
                        store,
                        aggregate,
                        reserved,
                        observationId,
                        "validation",
                    );
                    adapter.appendHarnessObservation({
                        commandId: recommendation.commandId,
                        observationId,
                        purpose: "validation",
                        receipt: seeded.receipt,
                        data: seeded.data,
                    });
                } else if (reserved.kind === "search_candidate") {
                    const spec = candidateQueue.shift();
                    if (spec === undefined) {
                        throw new Error("candidate queue exhausted");
                    }
                    const seeded = seedReceipt(
                        adapter,
                        store,
                        aggregate,
                        reserved,
                        observationId,
                        "candidate",
                        {
                            candidateData: spec.data,
                            blockCount: spec.blockCount
                                ?? (aggregate.contract.hypothesisTopology
                                    !== "open_generative"
                                    && spec.data?.pass === false
                                    ? reserved.replicationSchedule.maxBlocks
                                    : undefined),
                        },
                    );
                    adapter.appendHarnessObservation({
                        commandId: recommendation.commandId,
                        observationId,
                        purpose: "candidate",
                        // round/slotIndex/candidateId are inherited from the
                        // reserved search-candidate assignment.
                        receipt: seeded.receipt,
                        data: seeded.data,
                        ...(spec.annotations === undefined ? {} : { annotations: spec.annotations }),
                    });
                } else if (reserved.kind === "run_confirmation"
                    || reserved.kind === "run_challenge") {
                    const purpose = reserved.harnessRole;
                    const seeded = seedReceipt(
                        adapter,
                        store,
                        aggregate,
                        reserved,
                        observationId,
                        purpose,
                        {
                            candidateData: {
                                pass: true,
                                metrics: {
                                    score: aggregate.contract
                                        .statisticalPolicy.metrics[0]
                                        .maximum,
                                },
                            },
                        },
                    );
                    adapter.appendHarnessObservation({
                        commandId: recommendation.commandId,
                        observationId,
                        purpose,
                        candidateId: reserved.candidateId,
                        receipt: seeded.receipt,
                        data: seeded.data,
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
                            adapter,
                            store,
                            aggregate,
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
    const fixture = authorityFixturesByStateRoot.get(stateRoot);
    if (fixture === undefined) {
        throw new Error("seed investigation requires the workspace authority fixture");
    }
    const stagingId = `seed-staging-${createHash("sha256")
        .update(investigationId)
        .digest("hex")
        .slice(0, 16)}`;
    const stagingPaths = resolveInvestigationPaths(stateRoot, stagingId);
    const stagingStore = openArtifactStore({ root: stagingPaths.artifactRoot });
    const resolvedContract = typeof contractInput === "function"
        ? contractInput(stagingStore)
        : contractInput;
    const signed = createSignedInvestigationAuthority({
        contract: createInvestigationContract(resolvedContract),
        experimentId: `seed-${investigationId}`.replace(/[^a-z0-9._-]/gu, "-"),
        projectDir: fixture.projectDir,
        fixture: fixture.fixture,
    });
    const paths = resolveInvestigationPaths(stateRoot, signed.investigationId);
    fs.mkdirSync(stateRoot, { recursive: true });
    if (fs.existsSync(paths.investigationDir)) {
        fs.rmSync(stagingPaths.investigationDir, {
            recursive: true,
            force: true,
        });
        throw new Error("seeded investigation identity already exists");
    }
    fs.renameSync(stagingPaths.investigationDir, paths.investigationDir);
    fs.mkdirSync(paths.stateDir, { recursive: true });
    const store = openArtifactStore({ root: paths.artifactRoot });
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const adapter = createDomainRepositoryAdapter({
            repository,
            investigationId: signed.investigationId,
        });
        adapter.openInvestigation(
            createInvestigationContract(
                resolvedContract,
            ),
            signed.capability,
            createRuntimeConfigAuthorityFixture(signed.investigationId),
        );
        return {
            aggregate: seedFn(adapter, store),
            investigationId: signed.investigationId,
            paths,
        };
    } finally {
        repository.close();
    }
}

function seedLegacyV3State(stateRoot, investigationId) {
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    fs.mkdirSync(paths.stateDir, { recursive: true });
    fs.mkdirSync(paths.artifactRoot, { recursive: true });
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const contract = createInvestigationContract(baseSeedContract({
            hypothesisTopology: "open_generative",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        appendLegacyV3Investigation(repository, investigationId, contract);
    } finally {
        repository.close();
    }
    return paths;
}

function seedUnsignedForgedTerminal(stateRoot, investigationId) {
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    fs.mkdirSync(paths.stateDir, { recursive: true });
    fs.mkdirSync(paths.artifactRoot, { recursive: true });
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const contract = createInvestigationContract(baseSeedContract({
            hypothesisTopology: "open_generative",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        const openedCore = {
            seq: 1,
            type: EVENT_TYPES.INVESTIGATION_OPENED,
            prevHash: null,
            payload: {
                domainVersion: DOMAIN_VERSION,
                contract,
                contractHash: contractHash(contract),
            },
        };
        const opened = {
            ...openedCore,
            eventHash: computeDomainEventHash(openedCore),
        };
        const terminalCore = {
            seq: 2,
            type: EVENT_TYPES.VERIFIED_RESULT,
            prevHash: opened.eventHash,
            payload: {
                decision: "VERIFIED_RESULT",
                candidateId: "forged-winner",
                evidenceId: "forged-evidence",
                evidenceHash: `sha256:${"f".repeat(64)}`,
            },
        };
        const terminal = {
            ...terminalCore,
            eventHash: computeDomainEventHash(terminalCore),
        };
        repository.ensureInvestigation({
            investigationId,
            metadata: {
                role: "crucible-domain",
                domainVersion: DOMAIN_VERSION,
            },
        });
        repository.appendEvents({
            investigationId,
            expectedHead: null,
            events: [
                {
                    kind: "domain:v4:investigation_opened",
                    payload: { domainEvent: opened },
                },
                {
                    kind: "domain:v4:verified_result",
                    payload: { domainEvent: terminal },
                },
            ],
        });
    } finally {
        repository.close();
    }
    return paths;
}

function persistLegacyV3SupervisorConfig(workspace, investigationId, paths) {
    const config = normalizeSupervisorConfig({
        runner: {
            investigationId,
            stateDir: paths.stateDir,
            artifactRoot: paths.artifactRoot,
            allowlistPath: workspace.allowlistPath,
            copilotSdkPath: workspace.env.COPILOT_SDK_PATH,
            copilotCliPath: workspace.env.COPILOT_CLI_PATH,
            runnerEpochId: "epoch-legacy-v3",
            options: {},
        },
    }, { env: workspace.env });
    persistSupervisorConfig(config);
}

function seedVerifiedResult(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        (store) => {
            const controlSnapshot = createSeedSnapshot(store, [{
                path: "control.txt",
                content: "frozen-control",
            }]).snapshotId;
            return baseSeedContract({
                hypothesisTopology: "open_generative",
                workerModels: ["model-a"],
                candidatesPerRound: 1,
                maxRounds: 1,
                validationCases: seedValidationCases(store),
                searchPolicy: searchPolicy(),
                statisticalPolicy: fakeStatisticalPolicy({
                    topology: "open_generative",
                    searchSlots: 1,
                    minBlocks: 1,
                    maxBlocks: 1,
                    acceptanceThreshold: 0,
                    control: {
                        kind: "snapshot",
                        identity: controlSnapshot,
                    },
                    metrics: [{
                        key: "score",
                        minimum: 0,
                        maximum: 100,
                        estimand: "mean score",
                        unit: "score",
                        direction: "max",
                        acceptanceThreshold: 0,
                        practicalEquivalenceDelta: 1,
                        family: "primary",
                    }],
                }),
            });
        },
        (adapter, store) => driveToTerminal(adapter, store, [
            { data: { pass: true, metrics: { score: 95 } } },
        ]),
    );
}

function seedVerifiedTieResult(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        (store) => {
            const controlSnapshot = createSeedSnapshot(store, [{
                path: "control.txt",
                content: "frozen-control",
            }]).snapshotId;
            return baseSeedContract({
                hypothesisTopology: "open_generative",
                workerModels: ["model-a"],
                candidatesPerRound: 1,
                maxRounds: 2,
                metrics: [{
                    key: "score",
                    direction: "max",
                    epsilon: 100,
                }],
                validationCases: seedValidationCases(store),
                searchPolicy: searchPolicy(),
                statisticalPolicy: fakeStatisticalPolicy({
                    topology: "open_generative",
                    searchSlots: 2,
                    minBlocks: 1,
                    maxBlocks: 1,
                    maxConfirmations: 2,
                    acceptanceThreshold: 0,
                    practicalEquivalenceDelta: 100,
                    control: {
                        kind: "snapshot",
                        identity: controlSnapshot,
                    },
                    metrics: [{
                        key: "score",
                        minimum: 0,
                        maximum: 100,
                        estimand: "mean score",
                        unit: "score",
                        direction: "max",
                        acceptanceThreshold: 0,
                        practicalEquivalenceDelta: 100,
                        family: "primary",
                    }],
                }),
            });
        },
        (adapter, store) => driveToTerminal(adapter, store, [
            { data: { pass: true, metrics: { score: 95 } } },
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
        (store) => {
            const enumerands = ["cand-a"].map((id, ordinal) => ({
                id,
                ordinal,
                artifactSnapshotHash: createSeedSnapshot(store, [{
                    path: "candidate.txt",
                    content: `frozen-${id}`,
                }]).snapshotId,
            }));
            return baseSeedContract({
                hypothesisTopology: "finite_enumerable",
                workerModels: ["model-a"],
                candidatesPerRound: 1,
                maxRounds: 1,
                boundedCandidateIds: ["cand-a"],
                acceptancePredicate: { kind: "harness_pass" },
                enumerandManifest: {
                    topology: "finite_enumerable",
                    entries: enumerands,
                    control: { kind: "enumerand", ordinal: 0 },
                },
                validationCases: seedValidationCases(store),
            });
        },
        (adapter, store) => driveToTerminal(adapter, store, [
            { data: { pass: false, metrics: { score: 10 } } },
        ]),
    );
}

function seedCertifiedTargetUnreachable(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        (store) => {
            const validationCases = seedValidationCases(store);
            const candidate = createSeedSnapshot(store, [{
                path: "candidate.txt",
                content: "certified-candidate",
            }]).snapshotId;
            return baseSeedContract({
                hypothesisTopology: "certified_impossibility",
                workerModels: ["model-a"],
                candidatesPerRound: 1,
                maxRounds: 1,
                acceptancePredicate: { kind: "harness_pass" },
                validationCases,
                enumerandManifest: {
                    topology: "finite_enumerable",
                    entries: [{
                        id: "certified-candidate",
                        ordinal: 0,
                        artifactSnapshotHash: candidate,
                    }],
                    control: {
                        kind: "reference",
                        referenceHash: validationCases[0].artifactHash,
                    },
                },
            });
        },
        (adapter, store) => driveToTerminal(adapter, store, [
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
        (store) => {
            const validationCases = seedValidationCases(store);
            const candidate = createSeedSnapshot(store, [{
                path: "candidate.txt",
                content: "certified-non-result-candidate",
            }]).snapshotId;
            return baseSeedContract({
                hypothesisTopology: "certified_impossibility",
                workerModels: ["model-a"],
                candidatesPerRound: 1,
                maxRounds: 1,
                acceptancePredicate: { kind: "harness_pass" },
                validationCases,
                enumerandManifest: {
                    topology: "finite_enumerable",
                    entries: [{
                        id: "certified-candidate",
                        ordinal: 0,
                        artifactSnapshotHash: candidate,
                    }],
                    control: {
                        kind: "reference",
                        referenceHash: validationCases[0].artifactHash,
                    },
                },
            });
        },
        (adapter, store) => driveToTerminal(adapter, store, [
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
        (store) => baseSeedContract({
            hypothesisTopology: "open_generative",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 3,
            validationCases: seedValidationCases(store),
        }),
        (adapter, store) => {
            const reserve = adapter.appendKernelDecision();
            const validationCommandId = reserve.domainEvent.payload.commandId;
            adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, { commandId: validationCommandId });
            adapter.appendHarnessObservation({
                commandId: validationCommandId,
                observationId: "validation-obs",
                purpose: "validation",
                ...(() => {
                    const seeded = seedReceipt(
                        adapter,
                        store,
                        adapter.replay().aggregate,
                        reserve.domainEvent.payload.command,
                        "validation-obs",
                        "validation",
                    );
                    return { receipt: seeded.receipt, data: seeded.data };
                })(),
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

function withSyntheticTerminal(aggregate, decision) {
    const evidence = aggregate.evidenceOrder
        .map((id) => aggregate.evidence[id])
        .find((item) => item.purpose === "candidate");
    const decisiveKind = decision === "VERIFIED_RESULT"
        ? "winner"
        : "impossibility_certificate";
    return {
        ...aggregate,
        status: "terminal",
        nonResults: [],
        terminal: {
            decision,
            candidateId: decision === "VERIFIED_RESULT"
                ? evidence.candidateId
                : null,
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash,
            contractHash: aggregate.contractHash,
            basis: { kind: "synthetic_search_only_terminal" },
            evidenceClosure: {
                decisive: { kind: decisiveKind },
                closureRoot: hashCanonical(
                    { decision, evidenceHash: evidence.commitEventHash },
                    "sha256:crucible-terminal-evidence-closure-v1",
                ),
            },
            seq: aggregate.lastSeq + 1,
            eventHash: hashCanonical(
                { decision, evidenceHash: evidence.commitEventHash },
                "sha256:crucible-synthetic-terminal-v1",
            ),
        },
    };
}

function depsForSyntheticTerminal(workspace, aggregate) {
    const paths = resolveInvestigationPaths(
        workspace.stateRoot,
        aggregate.experimentAuthority.manifest.investigationId,
    );
    fs.mkdirSync(paths.stateDir, { recursive: true });
    fs.writeFileSync(paths.eventsDbPath, "synthetic persisted terminal fixture");
    const repository = { close() {} };
    const adapter = {
        replay: () => ({ aggregate }),
        verifyTerminalArtifactClosure: () => ({
            aggregate,
            artifactClosureReport: { verified: true },
        }),
        latestOperationalNonResult: () => null,
    };
    return makeDeps(workspace.env, {
        openRepositoryReadOnly: () => repository,
        openArtifactStoreReadOnly: () => ({}),
        createDomainRepositoryAdapter: () => adapter,
    }).deps;
}

function terminalArtifactClasses(stateRoot, investigationId) {
    const aggregate = replayAggregate(stateRoot, investigationId);
    const evidence = aggregate.evidenceOrder.map((id) => aggregate.evidence[id]);
    const validation = evidence.find((item) => item.purpose === "validation");
    const candidate = evidence.find((item) => item.purpose === "candidate");
    const impossibility = evidence.find((item) => item.purpose === "impossibility");
    const candidateMeasurement = candidate?.receipt.provenance.measurements[0] ?? null;
    return {
        aggregate,
        artifacts: {
            "validation composite": validation?.receipt.provenance.validationCompositeArtifact,
            "proposal/context": candidate?.receipt.provenance.proposalArtifact,
            "measurement receipt": candidateMeasurement?.receiptArtifact,
            "raw stdout": candidateMeasurement?.rawStdoutArtifact,
            "raw stderr": candidateMeasurement?.rawStderrArtifact,
            "snapshot manifest": candidateMeasurement?.snapshot.manifestArtifact,
            "snapshot object": candidateMeasurement?.snapshot.objectArtifacts[0],
            "impossibility certificate":
                impossibility?.receipt.provenance.impossibilityCertificateArtifact,
        },
    };
}

function corruptCasArtifact(
    stateRoot,
    investigationId,
    artifact,
    mode,
    replacementArtifact = null,
) {
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    const store = openArtifactStoreReadOnly({ root: paths.artifactRoot });
    const objectPath = store.objectPath(artifact.objectId);
    if (mode === "missing") {
        fs.rmSync(objectPath);
        return;
    }
    if (mode === "substitute") {
        if (replacementArtifact === null
            || replacementArtifact.objectId === artifact.objectId) {
            throw new Error("substitution requires a different artifact object");
        }
        fs.writeFileSync(objectPath, store.readObject(replacementArtifact.objectId));
        return;
    }
    const original = fs.readFileSync(objectPath);
    const corrupted = original.length === 0
        ? Buffer.from([1])
        : Buffer.concat([
            Buffer.from([original[0] ^ 0xff]),
            original.subarray(1),
        ]);
    fs.writeFileSync(objectPath, corrupted);
}

function expectIntegrityBlocked(result) {
    expect(result).toMatchObject({
        is_result: false,
        banner: "===== CRUCIBLE INTEGRITY BLOCKED — NOT A RESULT =====",
        integrity_blocked: true,
        non_result: true,
        non_result_code: "INTEGRITY_BLOCKED",
    });
    expect(result.message).toContain(NON_RESULT_BANNER);
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
    expect(JSON.stringify(result)).not.toContain("sha256:");
    expect(JSON.stringify(result)).not.toContain("VERIFIED_RESULT");
    expect(JSON.stringify(result)).not.toContain("TARGET_UNREACHABLE");
}

function rewriteTerminalEvent(stateRoot, investigationId, mutatePayload) {
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    const db = new DatabaseSync(paths.eventsDbPath);
    try {
        const row = db.prepare(
            "SELECT * FROM events WHERE investigation_id = ? ORDER BY seq DESC LIMIT 1",
        ).get(investigationId);
        const payload = JSON.parse(row.payload);
        mutatePayload(payload.domainEvent.payload);
        payload.domainEvent.eventHash = computeDomainEventHash(payload.domainEvent);
        const payloadCanonical = canonicalize(payload);
        const repositoryHash = computeRepositoryEventHash({
            investigationId,
            seq: Number(row.seq),
            prevHash: row.prev_hash,
            kind: row.kind,
            payloadCanonical,
            isTerminal: row.is_terminal,
            terminalKind: row.terminal_kind,
            attemptId: row.attempt_id,
            evidenceKind: row.evidence_kind,
            createdAt: row.created_at,
        });
        db.prepare(
            "UPDATE events SET payload = ?, event_hash = ? WHERE investigation_id = ? AND seq = ?",
        ).run(payloadCanonical, repositoryHash, investigationId, Number(row.seq));
    } finally {
        db.close();
    }
}

function rewriteTerminalWithoutClosure(stateRoot, investigationId) {
    rewriteTerminalEvent(stateRoot, investigationId, (payload) => {
        delete payload.evidenceClosure;
    });
}

function persistPauseForStarted(workspace, started) {
    const paths = resolveInvestigationPaths(workspace.stateRoot, started.investigation_id);
    const store = openArtifactStore({ root: paths.artifactRoot });
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
        const seeded = seedReceipt(
            adapter,
            store,
            aggregate,
            aggregate.commands[commandId].command,
            "pause-validation-observation",
            "validation",
        );
        aggregate = adapter.appendHarnessObservation({
            commandId,
            observationId: "pause-validation-observation",
            purpose: "validation",
            receipt: seeded.receipt,
            data: seeded.data,
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
        const contractHash = `sha256:crucible-contract-v4:${"c".repeat(64)}`;
        const id1 = deriveInvestigationId({
            objective: "  find   a  candidate ",
            projectDir: "C:\\proj",
            harnessSuiteId: "suite-1",
            harnessSuiteIdentity: fixtureHarnessEntryHash(),
            contractHash,
        });
        const id2 = deriveInvestigationId({
            objective: "find a candidate",
            projectDir: "C:\\proj\\",
            harnessSuiteId: "suite-1",
            harnessSuiteIdentity: fixtureHarnessEntryHash(),
            contractHash,
        });
        expect(id1).toBe(id2); // whitespace + trailing-slash canonicalized
        expect(id1).toMatch(/^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u);
        expect(id1.includes("..")).toBe(false);

        const differentObjective = deriveInvestigationId({
            objective: "find another candidate",
            projectDir: "C:\\proj",
            harnessSuiteId: "suite-1",
            harnessSuiteIdentity: fixtureHarnessEntryHash(),
            contractHash,
        });
        const differentHarness = deriveInvestigationId({
            objective: "find a candidate",
            projectDir: "C:\\proj",
            harnessSuiteId: "suite-2",
            harnessSuiteIdentity: fixtureHarnessEntryHash(),
            contractHash,
        });
        const differentEntry = deriveInvestigationId({
            objective: "find a candidate",
            projectDir: "C:\\proj",
            harnessSuiteId: "suite-1",
            harnessSuiteIdentity: fixtureHarnessEntryHash("b"),
            contractHash,
        });
        expect(differentObjective).not.toBe(id1);
        expect(differentHarness).not.toBe(id1);
        expect(differentEntry).not.toBe(id1);
    });

    it("includes DOMAIN_VERSION in the deterministic investigation identity", () => {
        const objective = "find a candidate";
        const projectDir = "C:\\proj";
        const harnessSuiteId = "suite-1";
        const harnessSuiteIdentity = fixtureHarnessEntryHash();
        const contractHash = `sha256:crucible-contract-v4:${"c".repeat(64)}`;
        const legacyMaterial = [
            "crucible-investigation-v1",
            harnessSuiteId,
            objective,
            path.resolve(projectDir).replace(/\//gu, "\\").toLowerCase(),
        ].join("\u0000");
        const legacySuffix = createHash("sha256")
            .update(legacyMaterial, "utf8")
            .digest("hex")
            .slice(0, 16);
        const legacyId = `find-a-candidate-${legacySuffix}`;
        const v3Material = [
            "crucible-investigation-domain-v3",
            harnessSuiteId,
            harnessSuiteIdentity,
            objective,
            path.resolve(projectDir).replace(/\//gu, "\\").toLowerCase(),
        ].join("\u0000");
        const v3Id = `find-a-candidate-${
            createHash("sha256")
                .update(v3Material, "utf8")
                .digest("hex")
                .slice(0, 16)
        }`;
        const currentId = deriveInvestigationId({
            objective,
            projectDir,
            harnessSuiteId,
            harnessSuiteIdentity,
            contractHash,
        });

        expect(DOMAIN_VERSION).toBe(4);
        expect(currentId).not.toBe(legacyId);
        expect(currentId).not.toBe(v3Id);
        expect(currentId).toBe(deriveInvestigationId({
            objective,
            projectDir,
            harnessSuiteId,
            harnessSuiteIdentity,
            contractHash,
        }));
    });

    it("resolves investigation paths under the state root", () => {
        const paths = resolveInvestigationPaths("C:\\root", "inv-x");
        expect(paths.stateDir).toBe(path.join("C:\\root", "inv-x", "state"));
        expect(paths.artifactRoot).toBe(path.join("C:\\root", "inv-x", "artifacts"));
        expect(paths.eventsDbPath).toBe(path.join("C:\\root", "inv-x", "state", "events.sqlite"));
    });

    it("fails clearly when required environment configuration is unavailable", () => {
        expect(() => resolveStateRoot({})).toThrow(EnvironmentError);
        const workspace = makeWorkspace("env-missing-sdk");
        const args = startArgs(workspace);
        const { env } = workspace;
        const withoutSdk = { ...env };
        delete withoutSdk.COPILOT_SDK_PATH;
        const { deps } = makeDeps(withoutSdk);
        expect(() => startInvestigation(args, deps))
            .toThrow(EnvironmentError);
    });
});

// --- crucible_start ----------------------------------------------------------

describe("crucible_start", () => {
    it("rejects v3 reattach through a typed restart-required path", () => {
        const workspace = makeWorkspace("legacy-v3-reattach");
        const investigationId = "legacy-v3-investigation";
        const paths = seedLegacyV3State(
            workspace.stateRoot,
            investigationId,
        );
        persistLegacyV3SupervisorConfig(
            workspace,
            investigationId,
            paths,
        );
        const { deps, calls } = makeDeps(workspace.env);

        expect(() => startInvestigation({
            investigation_id: investigationId,
        }, deps)).toThrow(LegacyIncompatibleApiError);
        expect(() => startInvestigation({
            investigation_id: investigationId,
        }, deps)).toThrow(expect.objectContaining({
            code: "CRUCIBLE_API_LEGACY_INCOMPATIBLE",
            details: expect.objectContaining({
                compatibility: "legacy_incompatible",
                actualDomainVersion: 3,
                restartRequired: true,
            }),
        }));
        expect(calls.ensure).toHaveLength(0);
    });

    it("freezes a contract, ingests validation cases, and starts the supervisor", () => {
        const workspace = makeWorkspace("start");
        const { deps, calls } = makeDeps(workspace.env);
        const args = startArgs(workspace);
        const result = startInvestigation(args, deps);

        expect(result.is_result).toBe(false);
        expect(result.experiment_id).toBe(args.experiment_id);
        expect(result.idempotent).toBe(false);
        expect(result.contract_hash).toMatch(/^sha256:crucible-contract-v4:[a-f0-9]{64}$/u);

        const experiment = loadExperimentRegistry(
            workspace.env.CRUCIBLE_EXPERIMENT_REGISTRY_PATH,
            { env: workspace.env },
        ).getExperiment(result.experiment_id);
        const expectedId = deriveInvestigationId({
            experimentId: result.experiment_id,
            objective: "find a candidate scoring at least 90",
            projectDir: fs.realpathSync.native(workspace.projectDir),
            harnessSuiteId: "primary-suite",
            harnessSuiteIdentity:
                loadHarnessAllowlist(workspace.allowlistPath)
                    .getSuiteIdentity("primary-suite"),
            contractHash: result.contract_hash,
            trustFingerprint: experiment.authority.trustFingerprint,
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
        expect(path.isAbsolute(runner.sdkPath)).toBe(true);
        expect(path.isAbsolute(runner.cliPath)).toBe(true);
        expect(runner.runnerEpochId).toMatch(/^epoch-[a-f0-9]{16}$/u);
        expect(result.supervisor.action).toBe("started");

        // Only immutable content hashes entered the contract.
        const aggregate = replayAggregate(resolveStateRoot(workspace.env), expectedId);
        expect(aggregate.contract).toMatchObject({
            harnessSuite: {
                version: 4,
                kind: "HarnessSuiteV4",
                id: "primary-suite",
            },
            harnessSuiteIdentity: result.harness_suite_identity,
            statisticalPolicy: {
                goalMode: "optimize",
            },
        });
        expect(aggregate.contract.harnessSuiteIdentity)
            .toMatch(/^sha256:crucible-harness-suite-v4:[a-f0-9]{64}$/u);
        expect(aggregate.experimentAuthority).toMatchObject({
            algorithm: "Ed25519",
            trustFingerprint:
                expect.stringMatching(/^sha256:crucible-experiment-public-key-v1:[a-f0-9]{64}$/u),
            manifest: {
                investigationId: expectedId,
                trustFingerprint: experiment.authority.trustFingerprint,
            },
        });
        expect(aggregate.experimentAuthorityIdentity)
            .toBe(aggregate.experimentAuthority.identity);
        expect(aggregate.runtimeConfigAuthority).toMatchObject({
            fingerprint: expect.stringMatching(
                /^sha256:crucible-runtime-config-authority-v2:[a-f0-9]{64}$/u,
            ),
            securityConfig: {
                runner: {
                    investigationId: expectedId,
                    stateDir: paths.stateDir,
                    artifactRoot: paths.artifactRoot,
                    allowlistPath: path.resolve(workspace.allowlistPath),
                },
            },
        });
        expect(aggregate.runtimeConfigFingerprint)
            .toBe(aggregate.runtimeConfigAuthority.fingerprint);
        for (const validationCase of aggregate.contract.validationCases) {
            expect(validationCase.artifactHash).toMatch(/^sha256:[a-f0-9]{64}$/u);
            expect(validationCase).not.toHaveProperty("path");
        }
    });

    it("freezes the certified-impossibility trigger and certificate prerequisites", () => {
        const workspace = makeWorkspace("start-certified");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace, {
            hypothesis_topology: "certified_impossibility",
            max_rounds: 1,
        }), deps);
        const aggregate = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(aggregate.contract).toMatchObject({
            hypothesisTopology: "certified_impossibility",
            impossibilityPolicy: {
                trigger: "search_exhausted",
                requestVersion: "crucible-impossibility-request-v2",
                certificateVersion: "crucible-impossibility-certificate-v2",
            },
        });
    });

    it("is idempotent for an identical contract and returns the existing investigation", () => {
        const workspace = makeWorkspace("idem");
        const { deps, calls } = makeDeps(workspace.env);
        const first = startInvestigation(startArgs(workspace), deps);
        const second = startInvestigation(startArgs(workspace), deps);

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
        const args = startArgs(workspace);
        const started = startInvestigation(args, deps);
        persistPauseForStarted(workspace, started);
        const stopped = stopInvestigation({
            investigation_id: started.investigation_id,
            reason: "persist pause",
        }, deps);
        expect(stopped.pause_persisted).toBe(true);
        expect(stopped.resumable).toBe(true);

        const resumed = startInvestigation({
            investigation_id: started.investigation_id,
        }, deps);
        expect(resumed.idempotent).toBe(true);
        expect(resumed.resumed).toBe(true);
        expect(calls.ensure.at(-1).opts.resetOperationalState).toBe(true);
        const aggregate = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(aggregate.pause).toBeNull();
        expect(aggregate.status).toBe("active");
        expect(aggregate.pauseHistory).toHaveLength(1);
    });

    it("requires a new investigation when the trusted experiment key changes", () => {
        const workspace = makeWorkspace("reattach-trust-change");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);
        const replacementTrust = createExperimentAuthorityFixture();
        const { deps: changedDeps, calls } = makeDeps({
            ...workspace.env,
            ...replacementTrust.env,
        });

        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, changedDeps)).toThrow(ExperimentAuthorityMismatchApiError);
        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, changedDeps)).toThrow(expect.objectContaining({
            code: "CRUCIBLE_API_EXPERIMENT_AUTHORITY_MISMATCH",
            details: expect.objectContaining({
                restartRequired: true,
                requiredAction: "start_new_investigation",
            }),
        }));
        expect(calls.ensure).toHaveLength(0);
    });

    it("resumes by investigation id after the original project and case directories are deleted", () => {
        const workspace = makeWorkspace("resume-without-project");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);
        persistPauseForStarted(workspace, started);
        const stopped = stopInvestigation({
            investigation_id: started.investigation_id,
            reason: "pause before removing source inputs",
        }, deps);
        expect(stopped.resumable).toBe(true);

        fs.rmSync(workspace.projectDir, { recursive: true, force: true });
        delete deps.env.CRUCIBLE_ALLOWLIST_PATH;
        delete deps.env.COPILOT_SDK_PATH;
        delete deps.env.COPILOT_CLI_PATH;
        const resumed = startInvestigation({
            investigation_id: started.investigation_id,
        }, deps);

        expect(resumed).toMatchObject({
            investigation_id: started.investigation_id,
            reattached_by_id: true,
            resumed: true,
        });
        expect(replayAggregate(workspace.stateRoot, started.investigation_id).pause)
            .toBeNull();
    });

    it("rejects invalid persisted resume configuration without mutating paused state", () => {
        const workspace = makeWorkspace("resume-invalid-config");
        const { deps, calls } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);
        persistPauseForStarted(workspace, started);
        stopInvestigation({ investigation_id: started.investigation_id }, deps);
        const before = replayAggregate(workspace.stateRoot, started.investigation_id);
        const configPath = supervisorPaths(
            resolveInvestigationPaths(
                workspace.stateRoot,
                started.investigation_id,
            ).stateDir,
            started.investigation_id,
        ).configPath;
        const persisted = JSON.parse(fs.readFileSync(configPath, "utf8"));
        persisted.maxBackoffMs = 1;
        persisted.baseBackoffMs = 2;
        fs.writeFileSync(configPath, JSON.stringify(persisted));

        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, deps)).toThrow(ExperimentAuthorityMismatchApiError);

        const after = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(after.lastSeq).toBe(before.lastSeq);
        expect(after.pause).toEqual(before.pause);
        expect(calls.ensure).toHaveLength(1);
    });

    it("compensates a failed asynchronous supervisor acknowledgement to a durable pause", async () => {
        const workspace = makeWorkspace("resume-supervisor-failure");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);
        persistPauseForStarted(workspace, started);
        stopInvestigation({ investigation_id: started.investigation_id }, deps);
        const workingEnsure = deps.ensureSupervisor;
        deps.ensureSupervisor = () =>
            Promise.reject(new Error("injected resume acknowledgement failure"));

        await expect(Promise.resolve(startInvestigation({
            investigation_id: started.investigation_id,
        }, deps))).rejects.toBeInstanceOf(StartFailedError);

        const compensated = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(compensated.pause).not.toBeNull();
        expect(compensated.terminal).toBeNull();
        expect(compensated.nonResults).toHaveLength(0);

        deps.ensureSupervisor = workingEnsure;
        const retried = startInvestigation({
            investigation_id: started.investigation_id,
        }, deps);
        expect(retried.resumed).toBe(true);
        expect(replayAggregate(workspace.stateRoot, started.investigation_id).pause)
            .toBeNull();
    });

    it("preflights a reattach before recording recovery/resume or ensuring the supervisor", () => {
        const workspace = makeWorkspace("resume-preflight");
        const { deps, calls } = makeDeps(workspace.env);
        const args = startArgs(workspace);
        const started = startInvestigation(args, deps);
        persistPauseForStarted(workspace, started);
        const stopped = stopInvestigation({
            investigation_id: started.investigation_id,
            reason: "persist pause",
        }, deps);
        expect(stopped.pause_persisted).toBe(true);
        const before = replayAggregate(workspace.stateRoot, started.investigation_id);
        const allowlist = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        allowlist.entries["primary-harness"].validationCases.good.snapshotHash =
            `sha256:${"0".repeat(64)}`;
        fs.writeFileSync(workspace.allowlistPath, JSON.stringify(allowlist));

        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, deps)).toThrow(ExperimentAuthorityMismatchApiError);

        const after = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(after.lastSeq).toBe(before.lastSeq);
        expect(after.pause).toEqual(before.pause);
        expect(calls.ensure).toHaveLength(1);
        expect(
            fs.readdirSync(workspace.root)
                .filter((name) => name.startsWith(".crucible-preflight-")),
        ).toEqual([]);
    });

    it.each([
        ["runnerCliPath", (document, workspace) => {
            document.runnerCliPath = workspace.env.COPILOT_CLI_PATH;
        }],
        ["workerAdditionalContext", (document) => {
            document.runner.options.workerAdditionalContext =
                "tampered operator context";
        }],
        ["runner options", (document) => {
            document.runner.options.sessionTimeoutMs += 1;
        }],
        ["derived paths", (document, workspace) => {
            document.runner.stateDir = path.join(
                workspace.root,
                "tampered-state",
            );
        }],
    ])("keeps a paused investigation paused when persisted %s is tampered", (
        _label,
        mutate,
    ) => {
        const workspace = makeWorkspace(`reattach-tamper-${_label}`);
        const { deps, calls } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);
        persistPauseForStarted(workspace, started);
        const paths = resolveInvestigationPaths(
            workspace.stateRoot,
            started.investigation_id,
        );
        const configPath = supervisorPaths(
            paths.stateDir,
            started.investigation_id,
        ).configPath;
        const document = JSON.parse(fs.readFileSync(configPath, "utf8"));
        mutate(document, workspace);
        fs.writeFileSync(configPath, JSON.stringify(document));
        const before = replayAggregate(
            workspace.stateRoot,
            started.investigation_id,
        );
        const ensureCount = calls.ensure.length;

        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, deps)).toThrow(ExperimentAuthorityMismatchApiError);

        const after = replayAggregate(
            workspace.stateRoot,
            started.investigation_id,
        );
        expect(after.lastSeq).toBe(before.lastSeq);
        expect(after.pause).toEqual(before.pause);
        expect(calls.ensure).toHaveLength(ensureCount);
    });

    it("does not resume terminal investigations without a new identity", () => {
        const workspace = makeWorkspace("terminal-reattach");
        const { deps } = makeDeps(workspace.env);
        const args = startArgs(workspace, {
            hypothesis_topology: "certified_impossibility",
            max_rounds: 1,
        });
        const started = startInvestigation(args, deps);
        const paths = resolveInvestigationPaths(workspace.stateRoot, started.investigation_id);
        const store = openArtifactStore({ root: paths.artifactRoot });
        const repository = openRepository({ file: paths.eventsDbPath });
        try {
            const adapter = createDomainRepositoryAdapter({
                repository,
                investigationId: started.investigation_id,
            });
            driveToTerminal(adapter, store, [
                { data: { pass: false, metrics: { score: 20 } } },
                {
                    certificateFacts: {
                        pass: true,
                        searchSpaceExhausted: true,
                    },
                },
            ]);
        } finally {
            repository.close();
        }
        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, deps))
            .toThrow(InvestigationNotResumableError);

        const startTool = buildRegistration({ deps }).tools
            .find((tool) => tool.name === "crucible_start");
        const boundary = startTool.handler({
            investigation_id: started.investigation_id,
        });
        expect(boundary.resultType).toBe("failure");
        const payload = JSON.parse(boundary.textResultForLlm);
        expect(payload).toMatchObject({
            ok: false,
            is_result: false,
            tool: "crucible_start",
            code: "CRUCIBLE_API_INVESTIGATION_NOT_RESUMABLE",
            terminal_available: true,
        });
        expect(JSON.stringify(payload)).not.toContain("VERIFIED_RESULT");
        expect(JSON.stringify(payload)).not.toContain(FIRST_GENERATED_CANDIDATE_ID);
    });

    it("does not resume persisted domain non-results", () => {
        const workspace = makeWorkspace("domain-non-result-reattach");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace, {
            hypothesis_topology: "certified_impossibility",
            max_rounds: 1,
        }), deps);
        const paths = resolveInvestigationPaths(workspace.stateRoot, started.investigation_id);
        const store = openArtifactStore({ root: paths.artifactRoot });
        const repository = openRepository({ file: paths.eventsDbPath });
        try {
            const adapter = createDomainRepositoryAdapter({
                repository,
                investigationId: started.investigation_id,
            });
            const aggregate = driveToTerminal(adapter, store, [
                { data: { pass: false, metrics: { score: 20 } } },
                {
                    certificateFacts: {
                        pass: false,
                        searchSpaceExhausted: true,
                    },
                },
            ]);
            expect(aggregate.nonResults).toHaveLength(1);
        } finally {
            repository.close();
        }

        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, deps)).toThrow(InvestigationNotResumableError);
    });

    it("requires explicit operational recovery policy and accepts a later deadline", () => {
        const workspace = makeWorkspace("operational-recovery");
        const { deps, calls } = makeDeps(workspace.env);
        const args = startArgs(workspace, {
            deadline_iso: "2026-07-10T00:00:00.000Z",
        });
        const started = startInvestigation(args, deps);
        recordOperationalNonResult(workspace.stateRoot, started.investigation_id, {
            attemptId: "deadline-attempt",
            code: "DEADLINE_EXCEEDED",
            reason: "deadline elapsed",
            details: { deadlineMs: Date.parse(args.deadline_iso), recoverable: false },
        });
        const beforeRejectedReattach = replayAggregate(
            workspace.stateRoot,
            started.investigation_id,
        );
        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, deps))
            .toThrow(OperationalResetRequiredError);
        expect(replayAggregate(workspace.stateRoot, started.investigation_id).lastSeq)
            .toBe(beforeRejectedReattach.lastSeq);
        expect(calls.ensure).toHaveLength(1);
        expect(
            fs.readdirSync(workspace.root)
                .filter((name) => name.startsWith(".crucible-preflight-")),
        ).toEqual([]);
        const recovered = startInvestigation({
            investigation_id: started.investigation_id,
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
            investigation_id: started.investigation_id,
            deadline_iso: "2026-07-12T00:00:00.000Z",
        }, deps)).toThrow(OperationalResetRequiredError);
        const reset = startInvestigation({
            investigation_id: started.investigation_id,
            deadline_iso: "2026-07-12T00:00:00.000Z",
            reset_policy: "circuit_open",
        }, deps);
        expect(reset.operational_recovery).toBe("circuit_open");
    });

    it("derives a distinct identity when the complete contract changes", () => {
        const workspace = makeWorkspace("conflict");
        const { deps } = makeDeps(workspace.env);
        const first = startInvestigation(startArgs(workspace), deps);
        const second = startInvestigation(
            startArgs(workspace, { max_rounds: 5 }),
            deps,
        );
        expect(second.investigation_id).not.toBe(first.investigation_id);
    });

    it("refuses a harness with no operator allowlist entry", () => {
        const workspace = makeWorkspace("allow-miss");
        const { deps } = makeDeps(workspace.env);
        const args = startArgs(workspace);
        const allowlist = JSON.parse(fs.readFileSync(workspace.allowlistPath, "utf8"));
        delete allowlist.suites["primary-suite"];
        fs.writeFileSync(workspace.allowlistPath, JSON.stringify(allowlist));
        expect(() => startInvestigation(args, deps))
            .toThrow(HarnessNotAllowlistedError);
    });

    it("fails when the allowlist file itself is absent", () => {
        const workspace = makeWorkspace("allow-file-missing");
        fs.rmSync(workspace.allowlistPath, { force: true });
        const { deps } = makeDeps(workspace.env);
        expect(() => startInvestigation(startArgs(workspace), deps)).toThrow();
    });

    it("rejects legacy caller-supplied validation cases without state", () => {
        const workspace = makeWorkspace("escape");
        const outside = path.join(workspace.root, "outside");
        fs.mkdirSync(outside, { recursive: true });
        fs.writeFileSync(path.join(outside, "x.txt"), "x");
        const { deps } = makeDeps(workspace.env);
        const args = {
            ...startArgs(workspace),
            validation_cases: [
                { id: "good", expectation: "accept", path: "cases/good" },
                { id: "bad", expectation: "reject", path: "..\\outside" },
            ],
        };
        expect(() => startInvestigation(args, deps)).toThrow(SchemaValidationError);
        expect(fs.existsSync(workspace.stateRoot)).toBe(false);
    });

    it("rejects legacy caller-supplied validation-case files without state", () => {
        const workspace = makeWorkspace("case-file");
        fs.writeFileSync(path.join(workspace.projectDir, "loose.txt"), "not a dir");
        const { deps } = makeDeps(workspace.env);
        const args = {
            ...startArgs(workspace),
            validation_cases: [
                { id: "good", expectation: "accept", path: "cases/good" },
                { id: "bad", expectation: "reject", path: "loose.txt" },
            ],
        };
        expect(() => startInvestigation(args, deps)).toThrow(SchemaValidationError);
        expect(fs.existsSync(workspace.stateRoot)).toBe(false);
    });
});

describe("crucible_status", () => {
    it("discovers v3 state read-only without restart, append, or result disclosure", () => {
        const workspace = makeWorkspace("legacy-v3-read-only");
        const investigationId = "legacy-v3-read-only";
        const paths = seedLegacyV3State(
            workspace.stateRoot,
            investigationId,
        );
        const { deps, calls } = makeDeps(workspace.env);

        const registration = buildRegistration({ deps });
        const invoke = (name) => {
            const response = registration.tools
                .find((tool) => tool.name === name)
                .handler({ investigation_id: investigationId });
            expect(response.resultType).toBe("success");
            return JSON.parse(response.textResultForLlm);
        };
        const status = invoke("crucible_status");
        const result = invoke("crucible_result");
        const stopped = invoke("crucible_stop");

        for (const payload of [status, result, stopped]) {
            expect(payload).toMatchObject({
                ok: true,
                is_result: false,
                compatibility: "legacy_incompatible",
                legacy_incompatible: true,
                restart_required: true,
                required_action: "start_new_investigation",
                expected_domain_version: 4,
                actual_domain_version: 3,
                event_count: 1,
                read_only: true,
                archiveable: true,
                non_result_code: "LEGACY_INCOMPATIBLE",
            });
            expect(payload).not.toHaveProperty("decision");
            expect(payload).not.toHaveProperty("candidate_id");
            expect(payload).not.toHaveProperty("contract_hash");
        }
        expect(stopped).toMatchObject({
            stop_state: "legacy_incompatible",
            appended: false,
            resumable: false,
        });
        expect(calls.ensure).toHaveLength(0);

        const repository = openRepositoryReadOnly({
            file: paths.eventsDbPath,
        });
        try {
            expect(repository.countEvents(investigationId)).toBe(1);
            expect(repository.getInvestigation(
                `${investigationId}.runtime-evidence`,
            )).toBeNull();
        } finally {
            repository.close();
        }
    });

    it("reports nonterminal progress, contract hash, event head, and a recommendation", () => {
        const workspace = makeWorkspace("status");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);

        const status = statusInvestigation({ investigation_id: started.investigation_id }, deps);
        expect(status.is_result).toBe(false);
        expect(status.terminal_available).toBe(false);
        expect(status).not.toHaveProperty("contract_hash");
        expect(status).not.toHaveProperty("event_head");
        expect(status.progress.open).toBe(true);
        expect(status.next_recommendation.kind).toBeTruthy();
    });

    it("restarts a missing supervisor from persisted config when nonterminal", () => {
        const workspace = makeWorkspace("status-restart");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);

        const restartCalls = [];
        const { deps: statusDeps } = makeDeps(workspace.env, {
            readStatus: () => null, // supervisor missing
            isPidAlive: () => false,
            ensureSupervisor: (input) => {
                restartCalls.push(input);
                return { action: "started", pid: 999 };
            },
        });

        const status = statusInvestigation({ investigation_id: started.investigation_id }, statusDeps);
        expect(restartCalls).toHaveLength(1);
        expect(restartCalls[0].runner.investigationId)
            .toBe(started.investigation_id);
        expect(status.supervisor_health.ensure_action.action).toBe("started");
    });

    it("does not restart when the supervisor is alive", () => {
        const workspace = makeWorkspace("status-alive");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);

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
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const ensureCalls = [];
        const { deps } = makeDeps(workspace.env, {
            readStatus: () => null,
            isPidAlive: () => false,
            ensureSupervisor: (input) => {
                ensureCalls.push(input);
                return { action: "started" };
            },
        });
        const status = statusInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(status).toEqual({
            is_result: false,
            investigation_id: seeded.investigationId,
            terminal_available: true,
        });
        expect(ensureCalls).toHaveLength(0);
    });

    it("uses the exact terminal status key allowlist before result verification", () => {
        const workspace = makeWorkspace("status-redaction");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const { deps } = makeDeps(workspace.env, { readStatus: () => null });
        const status = statusInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(Object.keys(status).sort()).toEqual([
            "investigation_id",
            "is_result",
            "terminal_available",
        ]);
        expect(status).toEqual({
            is_result: false,
            investigation_id: seeded.investigationId,
            terminal_available: true,
        });
        const serialized = JSON.stringify(status);
        expect(serialized).not.toContain("VERIFIED_RESULT");
        expect(serialized).not.toContain("TARGET_UNREACHABLE");
        expect(serialized).not.toContain("cand-a");
        expect(serialized).not.toContain("evidence_hash");
    });

    it("reports an integrity-checked operational deadline as a non-result", () => {
        const workspace = makeWorkspace("status-deadline");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);
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
        });
        expect(status.note).not.toContain("In progress");
    });

    it("describes a persisted domain non-result without calling it in progress", () => {
        const workspace = makeWorkspace("status-domain-non-result");
        const seeded = seedCertifiedNonResult(
            workspace.stateRoot,
            "certified-non-result-inv",
        );
        const { deps } = makeDeps(workspace.env, { readStatus: () => null });
        const status = statusInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(status).toMatchObject({
            is_result: false,
            terminal_available: false,
            non_result: true,
            non_result_code: "IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE",
        });
        expect(status.note).toContain("persisted non-result");
        expect(status.note).not.toContain("in progress");
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
        const started = startInvestigation(startArgs(workspace), deps);
        // Leave a dispatched (in-flight) command so the kernel cannot persist the
        // pause yet; the stop request is recorded but not resumable.
        seedDispatchedCommand(workspace.stateRoot, started.investigation_id);

        const stop = stopInvestigation({ investigation_id: started.investigation_id, reason: "operator pause" }, deps);
        expect(stop.is_result).toBe(false);
        expect(stop.pause_requested).toBe(true);
        expect(stop.stop_state).toBe("pause_requested");
        expect(stop.pause_in_flight).toBe(true);
        expect(stop.resumable).toBe(false);
        expect(stop.appended).toBe(true);
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
        const started = startInvestigation(startArgs(workspace), deps);
        persistPauseForStarted(workspace, started);
        const stop = stopInvestigation({
            investigation_id: started.investigation_id,
            reason: "pause now",
        }, deps);
        expect(stop).toMatchObject({
            stop_state: "pause_persisted",
            pause_requested: true,
            pause_in_flight: false,
            pause_persisted: true,
            resumable: true,
        });
        expect(replayAggregate(workspace.stateRoot, started.investigation_id).pause)
            .not.toBeNull();
    });

    it("is honest when stop is called after a terminal result", () => {
        const workspace = makeWorkspace("stop-terminal");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const { deps } = makeDeps(workspace.env);
        const stop = stopInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(stop).toEqual({
            is_result: false,
            investigation_id: seeded.investigationId,
            terminal_available: true,
        });
    });

    it.each([
        [
            "operational_non_result",
            (aggregate) => ({
                appended: false,
                aggregate,
                pausePersisted: false,
                operationalNonResult: {
                    payload: {
                        code: "DEADLINE_EXCEEDED",
                        reason: "deadline expired",
                    },
                },
            }),
            "DEADLINE_EXCEEDED",
        ],
        [
            "domain_non_result",
            (aggregate) => ({
                appended: false,
                aggregate: {
                    ...aggregate,
                    nonResults: [{
                        code: "VALIDATION_INCONCLUSIVE",
                        reason: "validation inconclusive",
                    }],
                },
                pausePersisted: false,
                operationalNonResult: null,
            }),
            "VALIDATION_INCONCLUSIVE",
        ],
    ])("reports %s as a distinct non-resumable stop state", (
        expectedState,
        buildResult,
        expectedCode,
    ) => {
        const workspace = makeWorkspace(`stop-${expectedState}`);
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace), deps);
        const aggregate = replayAggregate(workspace.stateRoot, started.investigation_id);
        deps.requestStop = () => buildResult(aggregate);

        const stopped = stopInvestigation({
            investigation_id: started.investigation_id,
        }, deps);
        expect(stopped).toMatchObject({
            stop_state: expectedState,
            pause_persisted: false,
            pause_in_flight: false,
            resumable: false,
            non_result: true,
            non_result_code: expectedCode,
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
    it("keeps cohort and relation evidence result-only", () => {
        expect(() => assertPublicToolPayload("crucible_status", {
            is_result: false,
            investigation_id: "redacted-cohort",
            cohort_status: "TIE_COHORT",
        })).toThrow(expect.objectContaining({
            code: "CRUCIBLE_API_PUBLIC_PAYLOAD_INVARIANT",
        }));
        expect(() => assertPublicToolPayload("crucible_result", {
            is_result: false,
            investigation_id: "redacted-relations",
            relation_evidence_hash: hashCanonical({ relations: true }),
        })).toThrow(expect.objectContaining({
            code: "CRUCIBLE_API_PUBLIC_PAYLOAD_INVARIANT",
        }));
    });

    it("returns a confirmation-closed unique cohort with relation structure only at result", () => {
        const workspace = makeWorkspace("result-confirmed-cohort");
        const seeded = seedVerifiedResult(
            workspace.stateRoot,
            "confirmed-cohort-source",
        );
        const aggregate = seeded.aggregate;
        const evidence = aggregate.evidenceOrder
            .map((id) => aggregate.evidence[id])
            .find((item) => item.purpose === "candidate");
        const cohort = aggregate.scientificReplay.candidateCohort;
        expect(aggregate.terminal).toMatchObject({
            decision: "VERIFIED_RESULT",
            candidateId: evidence.candidateId,
        });
        const deps = depsForSyntheticTerminal(workspace, aggregate);

        expect(statusInvestigation({
            investigation_id: seeded.investigationId,
        }, deps)).toEqual({
            is_result: false,
            investigation_id: seeded.investigationId,
            terminal_available: true,
        });
        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(result).toMatchObject({
            is_result: true,
            decision: "VERIFIED_RESULT",
            candidate_id: evidence.candidateId,
            candidate_ids: [evidence.candidateId],
            cohort_status: "UNIQUE_BEST",
            evidence_ids: [evidence.evidenceId],
            evidence_hashes: [evidence.commitEventHash],
            relation_evidence_hash: cohort.relationEvidenceHash,
            relation_evidence: {
                comparisonHash: cohort.comparisonHash,
                relationEvidenceHash: cohort.relationEvidenceHash,
                status: "UNIQUE_BEST",
            },
            scientific_conclusions: [
                expect.objectContaining({
                    candidate: expect.objectContaining({
                        candidateId: evidence.candidateId,
                    }),
                    heldOut: expect.objectContaining({
                        status: "READY",
                        confirmation: expect.objectContaining({
                            status: "SUPPORTED",
                        }),
                        challenge: expect.objectContaining({
                            status: "SUPPORTED",
                        }),
                    }),
                }),
            ],
            authority_closure: {
                experiment: {
                    authorityIdentity:
                        aggregate.experimentAuthorityIdentity,
                },
                runtime: {
                    fingerprint: aggregate.runtimeConfigFingerprint,
                },
            },
            artifact_closure: {
                evidenceCount: aggregate.evidenceOrder.length,
            },
            held_out_state: {
                status: "READY",
            },
        });
        expect(result.performance_claims.length).toBeGreaterThan(0);
        expect(result.assumptions.length).toBeGreaterThan(0);
        expect(result.limitations.length).toBeGreaterThan(0);
    });

    it("returns a supported tie as a cohort without inventing a winner", () => {
        const workspace = makeWorkspace("result-confirmed-tie");
        const seeded = seedVerifiedTieResult(
            workspace.stateRoot,
            "confirmed-tie-source",
        );
        const aggregate = seeded.aggregate;
        expect(aggregate.terminal).toMatchObject({
            decision: "VERIFIED_RESULT",
            cohortStatus: "TIE_COHORT",
            candidateId: null,
            evidenceId: null,
        });
        const deps = depsForSyntheticTerminal(workspace, aggregate);

        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(result).toMatchObject({
            is_result: true,
            decision: "VERIFIED_RESULT",
            cohort_status: "TIE_COHORT",
            candidate_ids: aggregate.terminal.candidateIds,
            evidence_ids: aggregate.terminal.evidenceIds,
            scientific_conclusions: [
                expect.objectContaining({
                    heldOut: expect.objectContaining({
                        status: "READY",
                        confirmation: expect.objectContaining({
                            status: "SUPPORTED",
                        }),
                        challenge: expect.objectContaining({
                            status: "SUPPORTED",
                        }),
                    }),
                }),
                expect.objectContaining({
                    heldOut: expect.objectContaining({
                        status: "READY",
                        confirmation: expect.objectContaining({
                            status: "SUPPORTED",
                        }),
                        challenge: expect.objectContaining({
                            status: "SUPPORTED",
                        }),
                    }),
                }),
            ],
        });
        expect(result).not.toHaveProperty("candidate_id");
        expect(result.evidence_id).toBeNull();
        expect(result.relation_evidence).toMatchObject({
            status: "TIE_COHORT",
        });
    });

    it("round-trips a verified terminal bundle with its scientific closure", () => {
        const workspace = makeWorkspace("result-bundle-roundtrip");
        const seeded = seedVerifiedResult(
            workspace.stateRoot,
            "bundle-terminal-source",
        );
        const bundleDir = path.join(workspace.root, "terminal-bundle");
        const exported = exportBundle({
            store: openArtifactStoreReadOnly({
                root: seeded.paths.artifactRoot,
            }),
            dbFile: seeded.paths.eventsDbPath,
            destDir: bundleDir,
            investigationId: seeded.investigationId,
            now: () => "2026-07-13T00:00:00.000Z",
        });
        const importedDir = path.join(workspace.root, "terminal-import");
        const imported = importBundle({
            bundleDir,
            destDir: importedDir,
            expectedDigest: exported.digest,
        });
        expect(imported).toMatchObject({
            authenticated: true,
            investigationId: seeded.investigationId,
            domainVersion: DOMAIN_VERSION,
        });

        const repository = openRepositoryReadOnly({
            file: path.join(importedDir, "db", "database.sqlite"),
        });
        try {
            const verified = createDomainRepositoryAdapter({
                repository,
                investigationId: seeded.investigationId,
                ensure: false,
            }).verifyTerminalArtifactClosure({
                artifactStore: openArtifactStoreReadOnly({
                    root: importedDir,
                }),
            });
            expect(verified.aggregate.terminal.evidenceClosure.closureRoot)
                .toBe(seeded.aggregate.terminal.evidenceClosure.closureRoot);
            expect(assessPersistedTerminalReadiness(verified.aggregate))
                .toMatchObject({
                    ready: true,
                    integrityBound: true,
                    decision: "VERIFIED_RESULT",
                });
        } finally {
            repository.close();
        }
    });

    it("blocks a directly forged unsigned v4 terminal without disclosing hashes", () => {
        const workspace = makeWorkspace("result-unsigned-forged");
        const investigationId = "unsigned-forged-terminal";
        seedUnsignedForgedTerminal(workspace.stateRoot, investigationId);
        const { deps } = makeDeps(workspace.env);

        const status = statusInvestigation({
            investigation_id: investigationId,
        }, deps);
        expect(status).toMatchObject({
            is_result: false,
            integrity_blocked: true,
            terminal_available: false,
        });
        const result = resultInvestigation({
            investigation_id: investigationId,
        }, deps);
        expectIntegrityBlocked(result);
        expect(JSON.stringify(result)).not.toContain("forged-winner");
        expect(result).not.toHaveProperty("terminal_event_hash");
        expect(result).not.toHaveProperty("contract_hash");
    });

    it("recomputes the signed investigation identity before terminal disclosure", () => {
        const workspace = makeWorkspace("result-authority-id-mismatch");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "authority-source",
        );
        const deps = depsForSyntheticTerminal(workspace, seeded.aggregate);
        const mismatchedId = "mismatched-signed-investigation";
        const paths = resolveInvestigationPaths(
            workspace.stateRoot,
            mismatchedId,
        );
        fs.mkdirSync(paths.stateDir, { recursive: true });
        fs.writeFileSync(paths.eventsDbPath, "forged id alias");

        const result = resultInvestigation({
            investigation_id: mismatchedId,
        }, deps);
        expectIntegrityBlocked(result);
        expect(result).not.toHaveProperty("decision");
        expect(result).not.toHaveProperty("evidence_hash");
        expect(result).not.toHaveProperty("terminal_event_hash");
    });

    it("blocks status and result after the configured trust root changes", () => {
        const workspace = makeWorkspace("result-trust-change");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "trust-change-source",
        );
        const changedTrust = createExperimentAuthorityFixture();
        const { deps } = makeDeps({
            ...workspace.env,
            ...changedTrust.env,
        });

        const status = statusInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(status).toMatchObject({
            is_result: false,
            integrity_blocked: true,
            terminal_available: false,
        });
        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expectIntegrityBlocked(result);
        expect(result).not.toHaveProperty("decision");
        expect(result).not.toHaveProperty("contract_hash");
    });

    it("does not disclose a persisted search-only VERIFIED_RESULT", () => {
        const workspace = makeWorkspace("result-verified");
        const seeded = seedVerifiedResult(
            workspace.stateRoot,
            "search-only-source",
        );
        const aggregate = withSyntheticTerminal(
            seeded.aggregate,
            "VERIFIED_RESULT",
        );
        const deps = depsForSyntheticTerminal(workspace, aggregate);

        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(result).toMatchObject({
            is_result: false,
            scientific_blocked: true,
            terminal_available: false,
            non_result: true,
            non_result_code: "INTEGRITY_BLOCKED",
        });
        expect(result).not.toHaveProperty("decision");
        expect(result).not.toHaveProperty("candidate_id");
        expect(result).not.toHaveProperty("evidence_id");
        expect(result).not.toHaveProperty("evidence_hash");
        expect(result).not.toHaveProperty("contract_hash");

        const status = statusInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(status).toMatchObject({
            is_result: false,
            scientific_blocked: true,
            terminal_available: false,
            non_result_code: "INTEGRITY_BLOCKED",
        });
        expect(status).not.toHaveProperty("decision");
        expect(status).not.toHaveProperty("candidate_id");
        expect(status).not.toHaveProperty("evidence_id");
    });

    it("does not disclose a synthetic search-only TARGET_UNREACHABLE", () => {
        const workspace = makeWorkspace("result-synthetic-unreachable");
        const seeded = seedTargetUnreachable(
            workspace.stateRoot,
            "search-only-unreachable-source",
        );
        const aggregate = withSyntheticTerminal(
            seeded.aggregate,
            "TARGET_UNREACHABLE",
        );
        const deps = depsForSyntheticTerminal(workspace, aggregate);

        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(result).toMatchObject({
            is_result: false,
            integrity_blocked: true,
            scientific_blocked: true,
            terminal_available: false,
            non_result_code: "INTEGRITY_BLOCKED",
        });
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

    it("does not treat finite search exhaustion as TARGET_UNREACHABLE", () => {
        const workspace = makeWorkspace("result-unreach");
        const seeded = seedTargetUnreachable(
            workspace.stateRoot,
            "unreach-inv",
        );
        const { deps } = makeDeps(workspace.env);
        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(result).toMatchObject({
            is_result: false,
            non_result: true,
            non_result_code: "INDEPENDENT_VERIFICATION_REQUIRED",
        });
        expect(replayAggregate(
            workspace.stateRoot,
            seeded.investigationId,
        ).terminal)
            .toBeNull();
    });

    it("reserves terminal disclosure to the actual registered result handler", async () => {
        const workspace = makeWorkspace("registered-terminal-boundary");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const { deps } = makeDeps(workspace.env);
        const registration = buildRegistration({ deps });
        const invoke = async (name) => {
            const tool = registration.tools.find((candidate) => candidate.name === name);
            const response = await tool.handler({
                investigation_id: seeded.investigationId,
            });
            return {
                response,
                payload: JSON.parse(response.textResultForLlm),
            };
        };

        for (const name of ["crucible_status", "crucible_stop"]) {
            const { response, payload } = await invoke(name);
            expect(response.resultType).toBe("success");
            expect(payload).toEqual({
                is_result: false,
                investigation_id: seeded.investigationId,
                terminal_available: true,
                ok: true,
            });
        }

        const { response, payload } = await invoke("crucible_result");
        expect(response.resultType).toBe("success");
        expect(payload).toMatchObject({
            ok: true,
            is_result: true,
            decision: "TARGET_UNREACHABLE",
        });
        expect(payload).not.toHaveProperty("candidate_id");
        expect(payload.evidence_id).toBeTruthy();
        expect(payload.evidence_hash).toMatch(/^sha256:/u);
        expect(payload.evidence_closure).toBeTruthy();
    });

    it("returns a persisted certificate-backed TARGET_UNREACHABLE only at result", () => {
        const workspace = makeWorkspace("result-certified-unreach");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "certified-unreach-inv",
        );
        const { deps } = makeDeps(workspace.env);
        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(result).toMatchObject({
            is_result: true,
            banner: "===== CRUCIBLE TERMINAL RESULT =====",
            decision: "TARGET_UNREACHABLE",
            basis: {
                kind: "v4_unreachable",
                certificateVerdict: "target_unreachable",
                independenceClassification:
                    "operator_attested_separate_implementation",
                mathematicalIndependenceProven: false,
                coverageClosureRoot: expect.stringMatching(
                    /^sha256:crucible-unreachable-coverage-closure-v1:/u,
                ),
            },
            scientific_conclusion: {
                authority: "replay_derived_statistical_kernel",
                decision: "TARGET_UNREACHABLE",
                coverage: {
                    coverageClosureRoot: expect.stringMatching(
                        /^sha256:crucible-unreachable-coverage-closure-v1:/u,
                    ),
                },
            },
            unreachable_verifier: {
                output: {
                    checkerStatus: "VERIFIED",
                    certificateVerdict: "target_unreachable",
                },
            },
        });
        expect(result.basis.certificateArtifactHash).toMatch(
            /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u,
        );
        expect(result.evidence_closure).toMatchObject({
            unreachableCoverage: {
                manifest: { count: 1 },
                closureRoot: result.basis.coverageClosureRoot,
            },
        });
    });

    it("round-trips the TARGET_UNREACHABLE verifier closure", () => {
        const workspace = makeWorkspace("unreachable-bundle-roundtrip");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "unreachable-bundle-source",
        );
        const bundleDir = path.join(
            workspace.root,
            "unreachable-terminal-bundle",
        );
        const exported = exportBundle({
            store: openArtifactStoreReadOnly({
                root: seeded.paths.artifactRoot,
            }),
            dbFile: seeded.paths.eventsDbPath,
            destDir: bundleDir,
            investigationId: seeded.investigationId,
            now: () => "2026-07-13T00:00:00.000Z",
        });
        const importedDir = path.join(
            workspace.root,
            "unreachable-terminal-import",
        );
        importBundle({
            bundleDir,
            destDir: importedDir,
            expectedDigest: exported.digest,
        });
        const repository = openRepositoryReadOnly({
            file: path.join(importedDir, "db", "database.sqlite"),
        });
        try {
            const verified = createDomainRepositoryAdapter({
                repository,
                investigationId: seeded.investigationId,
                ensure: false,
            }).verifyTerminalArtifactClosure({
                artifactStore: openArtifactStoreReadOnly({
                    root: importedDir,
                }),
            });
            expect(assessPersistedTerminalReadiness(verified.aggregate))
                .toMatchObject({
                    ready: true,
                    integrityBound: true,
                    decision: "TARGET_UNREACHABLE",
                });
            expect(verified.aggregate.terminal.evidenceClosure)
                .toMatchObject({
                    unreachableVerifier: {
                        output: {
                            checkerStatus: "VERIFIED",
                            certificateVerdict: "target_unreachable",
                        },
                    },
                });
        } finally {
            repository.close();
        }
    });

    it.each([
        "validation composite",
        "proposal/context",
        "measurement receipt",
        "raw stdout",
        "raw stderr",
        "snapshot manifest",
        "snapshot object",
    ])("refuses a terminal result when the %s artifact is corrupt", (artifactClass) => {
        const workspace = makeWorkspace(`result-${artifactClass}-corrupt`);
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            seeded.investigationId,
        );
        expect(artifacts[artifactClass]).toBeTruthy();
        corruptCasArtifact(
            workspace.stateRoot,
            seeded.investigationId,
            artifacts[artifactClass],
            "corrupt",
        );
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
    });

    it.each(["missing", "substitute"])(
        "refuses a terminal result when decisive measurement evidence is %s",
        (mode) => {
            const workspace = makeWorkspace(`result-measurement-${mode}`);
            const seeded = seedCertifiedTargetUnreachable(
                workspace.stateRoot,
                "verified-inv",
            );
            const { artifacts } = terminalArtifactClasses(
                workspace.stateRoot,
                seeded.investigationId,
            );
            const artifact = artifacts["measurement receipt"];
            const replacement = Object.values(artifacts).find((candidate) =>
                candidate?.objectId !== undefined
                && candidate.objectId !== artifact.objectId);
            corruptCasArtifact(
                workspace.stateRoot,
                seeded.investigationId,
                artifact,
                mode,
                replacement,
            );
            const { deps } = makeDeps(workspace.env);
            expectIntegrityBlocked(resultInvestigation({
                investigation_id: seeded.investigationId,
            }, deps));
        },
    );

    it("refuses a certified terminal result with a corrupt impossibility certificate", () => {
        const workspace = makeWorkspace("result-certificate-corrupt");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "certified-unreach-inv",
        );
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            seeded.investigationId,
        );
        corruptCasArtifact(
            workspace.stateRoot,
            seeded.investigationId,
            artifacts["impossibility certificate"],
            "corrupt",
        );
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
    });

    it("refuses external artifact size metadata that does not match CAS bytes", () => {
        const workspace = makeWorkspace("result-size-mismatch");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            seeded.investigationId,
        );
        const paths = resolveInvestigationPaths(
            workspace.stateRoot,
            seeded.investigationId,
        );
        const db = new DatabaseSync(paths.eventsDbPath);
        try {
            db.prepare(
                "UPDATE artifacts SET size_bytes = size_bytes + 1 WHERE artifact_id = ?",
            ).run(artifacts["measurement receipt"].artifactId);
        } finally {
            db.close();
        }
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
    });

    it("refuses an external artifact with incomplete size metadata", () => {
        const workspace = makeWorkspace("result-size-missing");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            seeded.investigationId,
        );
        const paths = resolveInvestigationPaths(
            workspace.stateRoot,
            seeded.investigationId,
        );
        const db = new DatabaseSync(paths.eventsDbPath);
        try {
            db.prepare(
                "UPDATE artifacts SET size_bytes = NULL WHERE artifact_id = ?",
            ).run(artifacts["measurement receipt"].artifactId);
        } finally {
            db.close();
        }
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
    });

    it("does not recreate or repair a missing artifact store during result", () => {
        const workspace = makeWorkspace("result-no-artifact-repair");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const paths = resolveInvestigationPaths(
            workspace.stateRoot,
            seeded.investigationId,
        );
        fs.rmSync(paths.artifactRoot, { recursive: true, force: true });
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
        expect(fs.existsSync(paths.artifactRoot)).toBe(false);
    });

    it("verifies inline artifact checksums before returning a result", () => {
        const workspace = makeWorkspace("result-inline-corrupt");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            seeded.investigationId,
        );
        const proposal = artifacts["proposal/context"];
        const paths = resolveInvestigationPaths(
            workspace.stateRoot,
            seeded.investigationId,
        );
        const store = openArtifactStoreReadOnly({ root: paths.artifactRoot });
        const bytes = store.readObject(proposal.objectId);
        const db = new DatabaseSync(paths.eventsDbPath);
        try {
            db.prepare(`
                UPDATE artifacts
                SET storage = 'inline',
                    inline_blob = ?,
                    hash_algo = NULL,
                    hash_value = NULL,
                    durable = 1,
                    size_bytes = ?
                WHERE artifact_id = ?`).run(bytes, bytes.length, proposal.artifactId);
        } finally {
            db.close();
        }
        const { deps } = makeDeps(workspace.env);
        expect(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps).is_result).toBe(true);

        const mutated = Buffer.from(bytes);
        mutated[0] ^= 0xff;
        const corruptDb = new DatabaseSync(paths.eventsDbPath);
        try {
            corruptDb.prepare(`
                UPDATE artifacts
                SET inline_blob = ?,
                    size_bytes = ?
                WHERE artifact_id = ?`).run(
                mutated,
                mutated.length,
                proposal.artifactId,
            );
        } finally {
            corruptDb.close();
        }
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
    });

    it("refuses a synthetic terminal event that omits its evidence closure", () => {
        const workspace = makeWorkspace("result-synthetic-terminal");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        rewriteTerminalWithoutClosure(
            workspace.stateRoot,
            seeded.investigationId,
        );
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
    });

    it("refuses a terminal event whose persisted closure root is inconsistent", () => {
        const workspace = makeWorkspace("result-terminal-closure-root");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        rewriteTerminalEvent(workspace.stateRoot, seeded.investigationId, (payload) => {
            payload.evidenceClosure.closureRoot =
                `sha256:crucible-terminal-evidence-closure-v1:${"0".repeat(64)}`;
        });
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
    });

    it("status withholds terminal availability when artifact verification fails", () => {
        const workspace = makeWorkspace("status-integrity-blocked");
        const seeded = seedCertifiedTargetUnreachable(
            workspace.stateRoot,
            "verified-inv",
        );
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            seeded.investigationId,
        );
        corruptCasArtifact(
            workspace.stateRoot,
            seeded.investigationId,
            artifacts["proposal/context"],
            "corrupt",
        );
        const { deps } = makeDeps(workspace.env);
        const status = statusInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
        expect(status).toMatchObject({
            is_result: false,
            investigation_id: seeded.investigationId,
            integrity_blocked: true,
            terminal_available: false,
            non_result_code: "INTEGRITY_BLOCKED",
        });
        expect(JSON.stringify(status)).not.toContain("VERIFIED_RESULT");
        expect(status).not.toHaveProperty("decision");
        expect(status).not.toHaveProperty("candidate_id");
        expect(status).not.toHaveProperty("evidence_id");
        expect(JSON.stringify(status)).not.toContain("coverageClosure");
        expect(JSON.stringify(status)).not.toContain("coverage_closure");
        expect(stopInvestigation({
            investigation_id: seeded.investigationId,
        }, deps)).toMatchObject({
            is_result: false,
            integrity_blocked: true,
            terminal_available: false,
        });
        const startBoundary = runToolBoundary(
            crucibleStartSpec,
            () => {
                throw new InvestigationNotResumableError(
                    "terminal investigation",
                    {
                        investigationId: seeded.investigationId,
                        status: "terminal",
                    },
                );
            },
            { experiment_id: "terminal-integrity-probe" },
            deps,
        );
        expect(JSON.parse(startBoundary.textResultForLlm)).toMatchObject({
            is_result: false,
            terminal_available: false,
        });
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps));
    });

    it("keeps an inconclusive certificate behind the strict non-result boundary", () => {
        const workspace = makeWorkspace("result-certified-non-result");
        const seeded = seedCertifiedNonResult(
            workspace.stateRoot,
            "certified-non-result-inv",
        );
        const { deps } = makeDeps(workspace.env);

        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
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
        const started = startInvestigation(startArgs(workspace), deps);

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
        const seeded = seedPaused(workspace.stateRoot, "paused-inv");
        const { deps } = makeDeps(workspace.env);

        const result = resultInvestigation({
            investigation_id: seeded.investigationId,
        }, deps);
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
        const started = startInvestigation(startArgs(workspace), deps);
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
