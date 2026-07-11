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
    createEvidenceProvenance,
    createInvestigationContract,
    createMeasurementProvenance,
    createSnapshotProvenance,
    canonicalJson,
    computeEventHash as computeDomainEventHash,
    decideNext,
    deriveImpossibilityVerdict,
    hashCanonical,
} from "../domain/index.mjs";
import {
    canonicalize,
    computeEventHash as computeRepositoryEventHash,
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
    resultInvestigation,
    startInvestigation,
    statusInvestigation,
    stopInvestigation,
} from "../api/handlers.mjs";
import {
    INTEGRITY_NON_RESULT_BANNER,
    NON_RESULT_BANNER,
    TERMINAL_BANNER,
} from "../api/result.mjs";
import {
    ContractConflictError,
    EnvironmentError,
    HarnessConfigurationError,
    HarnessNotAllowlistedError,
    InvestigationNotResumableError,
    InvestigationNotFoundError,
    OperationalResetRequiredError,
    StartFailedError,
    StartPreflightError,
    ValidationCasePathError,
} from "../api/errors.mjs";
import { fakeHarnessIdentity } from "./harness-identity-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

function makeWorkspace(label) {
    const safeLabel = label.replace(/[^A-Za-z0-9._-]/gu, "-");
    const root = fs.mkdtempSync(path.join(HERE, `.api-handlers-${safeLabel}-`));
    roots.push(root);
    const stateRoot = path.join(root, "state-root");
    const projectDir = path.join(root, "project");
    const goodDir = path.join(projectDir, "cases", "good");
    const badDir = path.join(projectDir, "cases", "bad");
    fs.mkdirSync(goodDir, { recursive: true });
    fs.mkdirSync(badDir, { recursive: true });
    fs.writeFileSync(path.join(goodDir, "input.txt"), "good-case");
    fs.writeFileSync(path.join(badDir, "input.txt"), "bad-case");

    const snapshotStoreRoot = path.join(root, "allowlist-snapshot-staging");
    const snapshotStore = openArtifactStore({ root: snapshotStoreRoot });
    const goodSnapshot = snapshotStore.ingestDirectory({ sourceDir: goodDir }).snapshot;
    const badSnapshot = snapshotStore.ingestDirectory({ sourceDir: badDir }).snapshot;
    fs.rmSync(snapshotStoreRoot, { recursive: true, force: true });
    const harnessExecutable = path.join(root, "trusted-harness.exe");
    fs.writeFileSync(harnessExecutable, "trusted harness fixture");
    const harnessExecutableSha256 = createHash("sha256")
        .update(fs.readFileSync(harnessExecutable))
        .digest("hex");

    const allowlistPath = path.join(root, "harnesses.json");
    fs.writeFileSync(allowlistPath, JSON.stringify({
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
                    good: { snapshotHash: goodSnapshot },
                    bad: { snapshotHash: badSnapshot },
                },
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
        probeSandboxAvailability: () => ({ available: true }),
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
        const bytes = Buffer.from(file.content, "utf8");
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
    return buildMeasurementReceipt({
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
        parserVersion: aggregate.contract.parserVersion,
        sandbox: null,
        attemptId: `attempt-${observationId}-${subjectId}`,
        runnerEpochId: "runner-epoch-seed",
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:00:00.001Z",
        durationMs: 1,
        exit: { code: 0, signal: null, timedOut: false },
        parsed,
    });
}

function seedReceipt(adapter, store, aggregate, reserved, observationId, purpose, options = {}) {
    const subjectIds = purpose === "validation"
        ? aggregate.contract.validationCases.map((item) => item.id)
        : [purpose === "candidate"
            ? reserved.candidateId
            : `impossibility-${reserved.attemptOrdinal}`];
    let candidateProposalArtifact = null;
    let promptContextHash = null;
    let candidateSnapshot = null;
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
        const proposal = {
            candidateId: reserved.candidateId,
            files: [{
                path: "candidate.txt",
                content: `candidate-${reserved.candidateId}-${observationId}`,
            }],
            identity: null,
        };
        candidateSnapshot = createSeedSnapshot(store, proposal.files);
        candidateProposalArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-proposal`,
            Buffer.from(canonicalJson({
                assignment,
                promptContext,
                promptContextHash,
                proposal,
            }), "utf8"),
            "application/vnd.crucible.candidate-proposal+json",
        );
    }
    const measurementDetails = subjectIds.map((subjectId) => {
        const snapshotId = purpose === "validation"
            ? aggregate.contract.validationCases.find((item) => item.id === subjectId)
                .artifactHash
            : purpose === "candidate"
                ? candidateSnapshot.snapshotId
                : createSeedSnapshot(store, [{
                    path: "request.json",
                    content: canonicalJson(reserved.request),
                }]).snapshotId;
        const parsed = purpose === "validation"
            ? {
                pass: aggregate.contract.validationCases.find(
                    (item) => item.id === subjectId,
                ).expectation === "accept",
                metrics: {},
            }
            : purpose === "candidate"
                ? options.candidateData
                : {
                    pass: options.impossibilityFacts.pass,
                    searchSpaceExhausted: options.impossibilityFacts.searchSpaceExhausted,
                    metrics: {},
                };
        const stdoutBytes = Buffer.from(canonicalJson(parsed), "utf8");
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
            receiptArtifact,
            receiptHash: hashReceipt(fullReceipt),
            rawStdoutArtifact,
            rawStdoutHash: stdoutHash,
            rawStderrArtifact,
            rawStderrHash: stderrHash,
            parserVersion: aggregate.contract.parserVersion,
            allowlistFileHash: fullReceipt.allowlistFileHash,
            harnessEntryHash: fullReceipt.harnessEntryHash,
            executableHash: fullReceipt.executableHash,
            stagedExecutableHash: fullReceipt.stagedExecutableHash,
            dependencyHashes: fullReceipt.dependencyHashes,
            stagedDependencyHashes: fullReceipt.stagedDependencyHashes,
            argvHash: fullReceipt.argvHash,
            envHash: fullReceipt.envHash,
            sandboxPolicy: { kind: "none", sandboxId: null, environmentHash: null },
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
        return {
            measurement,
            fullReceipt,
            stdoutBytes,
            stderrBytes,
        };
    });
    const measurements = measurementDetails.map((item) => item.measurement);
    let validationCompositeArtifact = null;
    let impossibilityCertificateArtifact = null;
    let data;
    let impossibilityReceiptFields = {};
    if (purpose === "validation") {
        const caseMap = {};
        const cases = [];
        const sortedDetails = [...measurementDetails].sort((left, right) =>
            left.measurement.subjectId.localeCompare(right.measurement.subjectId));
        for (const detail of sortedDetails) {
            const validationCase = aggregate.contract.validationCases.find(
                (item) => item.id === detail.measurement.subjectId,
            );
            const outcome = detail.fullReceipt.parsed.pass ? "accept" : "reject";
            caseMap[validationCase.id] = {
                artifactHash: validationCase.artifactHash,
                expectation: validationCase.expectation,
                outcome,
                matched: outcome === validationCase.expectation,
                attemptId: detail.fullReceipt.attemptId,
                parsed: detail.fullReceipt.parsed,
                receiptHash: detail.measurement.receiptHash,
            };
            cases.push({
                id: validationCase.id,
                receiptHash: detail.measurement.receiptHash,
                attemptId: detail.fullReceipt.attemptId,
            });
        }
        const compositeReceiptHash = hashCanonical(
            { cases },
            "sha256:crucible-runtime-validation-receipts-v1",
        );
        validationCompositeArtifact = persistSeedBytes(
            adapter,
            store,
            `${observationId}-validation`,
            Buffer.from(canonicalJson({ caseMap, compositeReceiptHash }), "utf8"),
            "application/vnd.crucible.validation-receipt+json",
        );
        data = {
            caseResults: [...aggregate.contract.validationCases]
                .sort((left, right) => left.id.localeCompare(right.id))
                .map((validationCase) => ({
                id: validationCase.id,
                artifactHash: validationCase.artifactHash,
                outcome: caseMap[validationCase.id].outcome,
                })),
            caseMap,
            compositeReceiptHash,
        };
    } else if (purpose === "candidate") {
        data = options.candidateData;
    } else {
        const detail = measurementDetails[0];
        const verifiedFacts = {
            pass: options.impossibilityFacts.pass,
            searchSpaceExhausted: options.impossibilityFacts.searchSpaceExhausted,
            parserVersion: reserved.parserVersion,
        };
        const certificateVerdict = deriveImpossibilityVerdict(verifiedFacts);
        const certificate = {
            version: reserved.certificateVersion,
            verdict: certificateVerdict,
            contractHash: aggregate.contractHash,
            harnessId: reserved.harnessId,
            parserVersion: reserved.parserVersion,
            verificationRequestHash: reserved.requestHash,
            verificationSnapshotHash: detail.measurement.snapshot.snapshotHash,
            measurementReceiptHash: detail.measurement.receiptHash,
            verifiedFacts,
            parsedResult: detail.fullReceipt.parsed,
        };
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
            certificateVerdict,
            certificateArtifactHash: `sha256:crucible-impossibility-certificate-artifact-v1:${sha256Hex(certificateBytes)}`,
            measurementReceiptHash: detail.measurement.receiptHash,
            verificationRequestHash: reserved.requestHash,
            verificationSnapshotHash: detail.measurement.snapshot.snapshotHash,
            verifiedFacts,
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
        measurements,
    }, {
        purpose,
        command: reserved,
        contract: aggregate.contract,
    });
    return {
        receipt: {
        version: 1,
        attemptId: purpose === "validation"
            ? `attempt-${observationId}`
            : measurementDetails[0].fullReceipt.attemptId,
        runnerEpochId: "runner-epoch-seed",
        rawStdoutHash: purpose === "validation"
            ? hashCanonical(
                provenance.measurements.map((item) => ({
                    id: item.subjectId,
                    hash: item.rawStdoutHash,
                })),
                "sha256:crucible-runtime-observation-streams-v1",
            )
            : provenance.measurements[0].rawStdoutHash,
        rawStderrHash: purpose === "validation"
            ? hashCanonical(
                provenance.measurements.map((item) => ({
                    id: item.subjectId,
                    hash: item.rawStderrHash,
                })),
                "sha256:crucible-runtime-observation-streams-v1",
            )
            : provenance.measurements[0].rawStderrHash,
        candidateArtifactHash: purpose === "candidate"
            ? provenance.measurements[0].snapshot.snapshotHash
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
        harnessIdentity: fakeHarnessIdentity({
            harnessId: "primary-harness",
            parserVersion: "parser-v1",
        }),
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
                        { candidateData: spec.data },
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
    const paths = resolveInvestigationPaths(stateRoot, investigationId);
    fs.mkdirSync(paths.stateDir, { recursive: true });
    const store = openArtifactStore({ root: paths.artifactRoot });
    const repository = openRepository({ file: paths.eventsDbPath });
    try {
        const adapter = createDomainRepositoryAdapter({ repository, investigationId });
        const resolvedContract = typeof contractInput === "function"
            ? contractInput(store)
            : contractInput;
        adapter.openInvestigation(createInvestigationContract(resolvedContract));
        return seedFn(adapter, store);
    } finally {
        repository.close();
    }
}

function seedVerifiedResult(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        (store) => baseSeedContract({
            hypothesisTopology: "open_generative",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 3,
            validationCases: seedValidationCases(store),
            // Immediate terminal: the first accepted candidate verifies.
            searchPolicy: searchPolicy({ stopOnFirstAccept: true }),
        }),
        (adapter, store) => driveToTerminal(adapter, store, [
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
        (store) => baseSeedContract({
            hypothesisTopology: "finite_enumerable",
            workerModels: ["model-a"],
            candidatesPerRound: 2,
            maxRounds: 1,
            boundedCandidateIds: ["cand-a", "cand-b"],
            validationCases: seedValidationCases(store),
        }),
        (adapter, store) => driveToTerminal(adapter, store, [
            { data: { pass: false, metrics: { score: 10 } } },
            { data: { pass: false, metrics: { score: 20 } } },
        ]),
    );
}

function seedCertifiedTargetUnreachable(stateRoot, investigationId) {
    return seedInvestigation(
        stateRoot,
        investigationId,
        (store) => baseSeedContract({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 1,
            validationCases: seedValidationCases(store),
        }),
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
        (store) => baseSeedContract({
            hypothesisTopology: "certified_impossibility",
            workerModels: ["model-a"],
            candidatesPerRound: 1,
            maxRounds: 1,
            validationCases: seedValidationCases(store),
        }),
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
        banner: INTEGRITY_NON_RESULT_BANNER,
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
        const id1 = deriveInvestigationId({
            objective: "  find   a  candidate ",
            projectDir: "C:\\proj",
            harnessId: "h1",
            harnessEntryHash: fixtureHarnessEntryHash(),
        });
        const id2 = deriveInvestigationId({
            objective: "find a candidate",
            projectDir: "C:\\proj\\",
            harnessId: "h1",
            harnessEntryHash: fixtureHarnessEntryHash(),
        });
        expect(id1).toBe(id2); // whitespace + trailing-slash canonicalized
        expect(id1).toMatch(/^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u);
        expect(id1.includes("..")).toBe(false);

        const differentObjective = deriveInvestigationId({
            objective: "find another candidate",
            projectDir: "C:\\proj",
            harnessId: "h1",
            harnessEntryHash: fixtureHarnessEntryHash(),
        });
        const differentHarness = deriveInvestigationId({
            objective: "find a candidate",
            projectDir: "C:\\proj",
            harnessId: "h2",
            harnessEntryHash: fixtureHarnessEntryHash(),
        });
        const differentEntry = deriveInvestigationId({
            objective: "find a candidate",
            projectDir: "C:\\proj",
            harnessId: "h1",
            harnessEntryHash: fixtureHarnessEntryHash("b"),
        });
        expect(differentObjective).not.toBe(id1);
        expect(differentHarness).not.toBe(id1);
        expect(differentEntry).not.toBe(id1);
    });

    it("namespaces investigation identity by DOMAIN_VERSION instead of reopening v1", () => {
        const objective = "find a candidate";
        const projectDir = "C:\\proj";
        const harnessId = "h1";
        const harnessEntryHash = fixtureHarnessEntryHash();
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
        const currentId = deriveInvestigationId({
            objective,
            projectDir,
            harnessId,
            harnessEntryHash,
        });

        expect(DOMAIN_VERSION).toBe(3);
        expect(currentId).not.toBe(legacyId);
        expect(currentId).toBe(deriveInvestigationId({
            objective,
            projectDir,
            harnessId,
            harnessEntryHash,
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
            harnessEntryHash:
                loadHarnessAllowlist(workspace.allowlistPath)
                    .getEntryHash("primary-harness"),
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
        expect(aggregate.contract.harnessIdentity).toMatchObject({
            version: 1,
            harnessId: "primary-harness",
            allowlistVersion: 1,
            executesCandidateCode: false,
            sandbox: {
                required: false,
                policyIdentity: null,
                policyDigest: null,
            },
        });
        for (const field of [
            "allowlistFileHash",
            "harnessEntryHash",
            "executableHash",
            "argvTemplateHash",
            "allowedEnvHash",
            "parserVersionHash",
            "parserSourceHash",
        ]) {
            expect(aggregate.contract.harnessIdentity[field])
                .toMatch(/^sha256:[a-z0-9._-]+:[a-f0-9]{64}$/u);
        }
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

    it("resumes by investigation id after the original project and case directories are deleted", () => {
        const workspace = makeWorkspace("resume-without-project");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
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
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
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
        }, deps)).toThrow(StartPreflightError);

        const after = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(after.lastSeq).toBe(before.lastSeq);
        expect(after.pause).toEqual(before.pause);
        expect(calls.ensure).toHaveLength(1);
    });

    it("compensates a failed asynchronous supervisor acknowledgement to a durable pause", async () => {
        const workspace = makeWorkspace("resume-supervisor-failure");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
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
        const args = startArgs(workspace.projectDir);
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
        }, deps)).toThrow(HarnessConfigurationError);

        const after = replayAggregate(workspace.stateRoot, started.investigation_id);
        expect(after.lastSeq).toBe(before.lastSeq);
        expect(after.pause).toEqual(before.pause);
        expect(calls.ensure).toHaveLength(1);
        expect(
            fs.readdirSync(workspace.root)
                .filter((name) => name.startsWith(".crucible-preflight-")),
        ).toEqual([]);
    });

    it("does not resume terminal investigations without a new identity", () => {
        const workspace = makeWorkspace("terminal-reattach");
        const { deps } = makeDeps(workspace.env);
        const args = startArgs(workspace.projectDir, {
            search_policy: searchPolicy({ stopOnFirstAccept: true }),
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
                { data: { pass: true, metrics: { score: 95 } } },
            ]);
        } finally {
            repository.close();
        }
        expect(() => startInvestigation({
            investigation_id: started.investigation_id,
        }, deps))
            .toThrow(InvestigationNotResumableError);
    });

    it("does not resume persisted domain non-results", () => {
        const workspace = makeWorkspace("domain-non-result-reattach");
        const { deps } = makeDeps(workspace.env);
        const started = startInvestigation(startArgs(workspace.projectDir, {
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
        expect(status).not.toHaveProperty("contract_hash");
        expect(status).not.toHaveProperty("event_head");
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
        expect(status).toEqual({
            is_result: false,
            investigation_id: "verified-inv",
            terminal_available: true,
        });
        expect(ensureCalls).toHaveLength(0);
    });

    it("uses the exact terminal status key allowlist before result verification", () => {
        const workspace = makeWorkspace("status-redaction");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const { deps } = makeDeps(workspace.env, { readStatus: () => null });
        const status = statusInvestigation({ investigation_id: "verified-inv" }, deps);
        expect(Object.keys(status).sort()).toEqual([
            "investigation_id",
            "is_result",
            "terminal_available",
        ]);
        expect(status).toEqual({
            is_result: false,
            investigation_id: "verified-inv",
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
        });
        expect(status.note).not.toContain("In progress");
    });

    it("describes a persisted domain non-result without calling it in progress", () => {
        const workspace = makeWorkspace("status-domain-non-result");
        seedCertifiedNonResult(workspace.stateRoot, "certified-non-result-inv");
        const { deps } = makeDeps(workspace.env, { readStatus: () => null });
        const status = statusInvestigation({
            investigation_id: "certified-non-result-inv",
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
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
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
            stop_state: "pause_persisted",
            pause_requested: true,
            pause_in_flight: false,
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
            stop_state: "already_terminal",
            appended: false,
            pause_persisted: false,
            resumable: false,
            already_terminal: true,
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
        const started = startInvestigation(startArgs(workspace.projectDir), deps);
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
        const persisted = replayAggregate(workspace.stateRoot, "verified-inv").terminal;
        expect(result).toMatchObject({
            decision: persisted.decision,
            terminal_seq: persisted.seq,
            terminal_event_hash: persisted.eventHash,
            candidate_id: persisted.candidateId,
            evidence_id: persisted.evidenceId,
            evidence_hash: persisted.evidenceHash,
            evidence_closure: persisted.evidenceClosure,
            basis: persisted.basis,
        });
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
        const persisted = replayAggregate(workspace.stateRoot, "unreach-inv").terminal;
        expect(result).toMatchObject({
            decision: persisted.decision,
            terminal_seq: persisted.seq,
            terminal_event_hash: persisted.eventHash,
            evidence_closure: persisted.evidenceClosure,
            basis: persisted.basis,
        });
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

    for (const artifactClass of [
        "validation composite",
        "proposal/context",
        "measurement receipt",
        "raw stdout",
        "raw stderr",
        "snapshot manifest",
        "snapshot object",
    ]) {
        for (const mode of ["missing", "corrupt", "substitute"]) {
            it(`refuses a terminal result when the ${artifactClass} artifact is ${mode}`, () => {
                const workspace = makeWorkspace(`result-${artifactClass}-${mode}`);
                seedVerifiedResult(workspace.stateRoot, "verified-inv");
                const { artifacts } = terminalArtifactClasses(
                    workspace.stateRoot,
                    "verified-inv",
                );
                expect(artifacts[artifactClass]).toBeTruthy();
                const replacement = Object.values(artifacts).find((artifact) =>
                    artifact?.objectId !== undefined
                    && artifact.objectId !== artifacts[artifactClass].objectId);
                corruptCasArtifact(
                    workspace.stateRoot,
                    "verified-inv",
                    artifacts[artifactClass],
                    mode,
                    replacement,
                );
                const { deps } = makeDeps(workspace.env);
                expectIntegrityBlocked(resultInvestigation({
                    investigation_id: "verified-inv",
                }, deps));
            });
        }
    }

    for (const mode of ["missing", "corrupt", "substitute"]) {
        it(`refuses a certified terminal result when the impossibility certificate is ${mode}`, () => {
            const workspace = makeWorkspace(`result-certificate-${mode}`);
            seedCertifiedTargetUnreachable(
                workspace.stateRoot,
                "certified-unreach-inv",
            );
            const { artifacts } = terminalArtifactClasses(
                workspace.stateRoot,
                "certified-unreach-inv",
            );
            const replacement = Object.values(artifacts).find((artifact) =>
                artifact?.objectId !== undefined
                && artifact.objectId !== artifacts["impossibility certificate"].objectId);
            corruptCasArtifact(
                workspace.stateRoot,
                "certified-unreach-inv",
                artifacts["impossibility certificate"],
                mode,
                replacement,
            );
            const { deps } = makeDeps(workspace.env);
            expectIntegrityBlocked(resultInvestigation({
                investigation_id: "certified-unreach-inv",
            }, deps));
        });
    }

    it("refuses external artifact size metadata that does not match CAS bytes", () => {
        const workspace = makeWorkspace("result-size-mismatch");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            "verified-inv",
        );
        const paths = resolveInvestigationPaths(workspace.stateRoot, "verified-inv");
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
            investigation_id: "verified-inv",
        }, deps));
    });

    it("refuses an external artifact with incomplete size metadata", () => {
        const workspace = makeWorkspace("result-size-missing");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            "verified-inv",
        );
        const paths = resolveInvestigationPaths(workspace.stateRoot, "verified-inv");
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
            investigation_id: "verified-inv",
        }, deps));
    });

    it("does not recreate or repair a missing artifact store during result", () => {
        const workspace = makeWorkspace("result-no-artifact-repair");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const paths = resolveInvestigationPaths(workspace.stateRoot, "verified-inv");
        fs.rmSync(paths.artifactRoot, { recursive: true, force: true });
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: "verified-inv",
        }, deps));
        expect(fs.existsSync(paths.artifactRoot)).toBe(false);
    });

    it.each([
        ["delete", (bytes) => Buffer.alloc(0), 0],
        ["corrupt", (bytes) => {
            const corrupted = Buffer.from(bytes);
            corrupted[0] ^= 0xff;
            return corrupted;
        }, null],
        ["substitute", (bytes) => Buffer.alloc(bytes.length, 0x5a), null],
    ])("verifies inline artifact checksums and refuses %s", (
        mode,
        mutate,
        explicitSize,
    ) => {
        const workspace = makeWorkspace(`result-inline-${mode}`);
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            "verified-inv",
        );
        const proposal = artifacts["proposal/context"];
        const paths = resolveInvestigationPaths(workspace.stateRoot, "verified-inv");
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
            investigation_id: "verified-inv",
        }, deps).is_result).toBe(true);

        const mutated = mutate(bytes);
        const corruptDb = new DatabaseSync(paths.eventsDbPath);
        try {
            corruptDb.prepare(`
                UPDATE artifacts
                SET inline_blob = ?,
                    size_bytes = ?
                WHERE artifact_id = ?`).run(
                mutated,
                explicitSize ?? mutated.length,
                proposal.artifactId,
            );
        } finally {
            corruptDb.close();
        }
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: "verified-inv",
        }, deps));
    });

    it("refuses a synthetic terminal event that omits its evidence closure", () => {
        const workspace = makeWorkspace("result-synthetic-terminal");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        rewriteTerminalWithoutClosure(workspace.stateRoot, "verified-inv");
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: "verified-inv",
        }, deps));
    });

    it("refuses a terminal event whose persisted closure root is inconsistent", () => {
        const workspace = makeWorkspace("result-terminal-closure-root");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        rewriteTerminalEvent(workspace.stateRoot, "verified-inv", (payload) => {
            payload.evidenceClosure.closureRoot =
                `sha256:crucible-terminal-evidence-closure-v1:${"0".repeat(64)}`;
        });
        const { deps } = makeDeps(workspace.env);
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: "verified-inv",
        }, deps));
    });

    it("status exposes only terminal availability while result alone verifies artifacts", () => {
        const workspace = makeWorkspace("status-integrity-blocked");
        seedVerifiedResult(workspace.stateRoot, "verified-inv");
        const { artifacts } = terminalArtifactClasses(
            workspace.stateRoot,
            "verified-inv",
        );
        corruptCasArtifact(
            workspace.stateRoot,
            "verified-inv",
            artifacts["proposal/context"],
            "corrupt",
        );
        const { deps } = makeDeps(workspace.env);
        const status = statusInvestigation({
            investigation_id: "verified-inv",
        }, deps);
        expect(status).toEqual({
            is_result: false,
            investigation_id: "verified-inv",
            terminal_available: true,
        });
        expect(JSON.stringify(status)).not.toContain("VERIFIED_RESULT");
        expect(status).not.toHaveProperty("decision");
        expect(status).not.toHaveProperty("candidate_id");
        expect(status).not.toHaveProperty("evidence_id");
        expectIntegrityBlocked(resultInvestigation({
            investigation_id: "verified-inv",
        }, deps));
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
