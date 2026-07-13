import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";

import {
    DEFAULT_SEARCH_POLICY,
    createInvestigationContract,
    hashCanonical,
    normalizeEnumerandManifest,
} from "../domain/index.mjs";
import {
    VERIFIER_PARSER_VERSION,
    buildFrozenHarnessIdentity,
    computeHarnessSuiteV4Identity,
    createSandboxProvider,
    loadHarnessAllowlist,
    verifyHarnessPreflight,
} from "../measurement/index.mjs";
import {
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";
import {
    createDomainRepositoryAdapter,
    runAutonomousInvestigation,
    validateCandidateSubmission,
} from "../runtime/index.mjs";
import {
    NODE_EXE,
    makeTempRoot,
    nodeExeSha256Hex,
    sha256HexOfFile,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";
import { removeTreeRobust } from "./test-cleanup.mjs";
import {
    buildHarnessSuiteForAllowlist,
    fakeStatisticalPolicy,
    upgradeLegacyContractInput,
} from "./v4-contract-fixture.mjs";
import {
    createRuntimeConfigAuthorityFixture,
    createSignedInvestigationAuthority,
} from "./experiment-authority-fixture.mjs";

const WINDOWS_CMD = path.join(
    process.env.SystemRoot ?? "C:\\Windows",
    "System32",
    "cmd.exe",
);

function seedSnapshot(store, root, name, score) {
    const source = path.join(root, `snapshot-${name}`);
    fs.mkdirSync(source, { recursive: true });
    fs.writeFileSync(path.join(source, "score.txt"), `${score}\n`);
    fs.writeFileSync(path.join(source, "fixture-id.txt"), `${name}\n`);
    return store.ingestDirectory({ sourceDir: source }).snapshot;
}

function sandboxIdentity() {
    return {
        required: true,
        primitive: "fixture-containment",
        providerId: "runner-fixture-containment",
        providerVersion: "v1",
        policyId: "runner-fixture-policy",
        helperSourceHash:
            `sha256:runner-fixture-helper-source-v1:${"a".repeat(64)}`,
        helperBinaryHash:
            `sha256:crucible-measurement-file-v1:${"b".repeat(64)}`,
        launcherId: "runner-fixture-launcher-v1",
        launcherBinaryHash:
            `sha256:runner-fixture-launcher-binary-v1:${"c".repeat(64)}`,
        launcherScriptHash:
            `sha256:runner-fixture-launcher-script-v1:${"d".repeat(64)}`,
        securityContext: {
            appContainer: true,
            lowIntegrity: true,
            capabilities: [],
            loopbackExemptionRejected: true,
        },
        network: {
            mode: "deny-by-default",
            enforcement: "fixture zero-capability boundary",
        },
        filesystem: {
            stagedHarness: "exact-manifest-read-execute",
            immutableCandidate: "private-staged-copy-read-only",
            outputTemp: "provider-owned",
            aclJournalRestored: true,
            exactLaunchClosure: true,
            hostWriteDenied: true,
        },
        job: {
            killOnJobClose: true,
            descendantsContained: true,
            uiRestrictions: true,
            activeProcessLimit: 8,
            processMemoryBytes: 512 * 1024 * 1024,
            jobMemoryBytes: 768 * 1024 * 1024,
            cpuRatePercent: 50,
            cpuTimeMs: 30_000,
            wallTimeMs: 120_000,
            terminationGraceMs: 5_000,
        },
    };
}

function makeContract({
    goodSnapshot,
    badSnapshot,
    harnessSuite,
    harnessSuiteIdentity,
    enumerandManifest,
    maxBlocks = 8,
    alpha = 0.5,
}) {
    const input = upgradeLegacyContractInput({
        objective: "Prove the finite target is unreachable",
        acceptancePredicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: 100,
        },
        validationCases: [
            { id: "known-good", expectation: "accept", artifactHash: goodSnapshot },
            { id: "known-bad", expectation: "reject", artifactHash: badSnapshot },
        ],
        hypothesisTopology: "certified_impossibility",
        criticality: "high",
        policyVersion: "policy-v1",
        workerModels: ["model-a"],
        candidatesPerRound: 1,
        maxRounds: 1,
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        searchPolicy: DEFAULT_SEARCH_POLICY,
        declaredLimits: { maxCommands: 20 },
        enumerandManifest,
    });
    input.statisticalPolicy = fakeStatisticalPolicy({
        topology: "certified_impossibility",
        searchSlots: 1,
        manifest: enumerandManifest,
        minBlocks: 1,
        maxBlocks,
    });
    input.statisticalPolicy.investigationAlpha = alpha;
    input.statisticalPolicy.familyAllocations = [{
        family: "primary",
        alpha,
    }];
    input.observableRegistry = [{
        key: "score",
        kind: "numeric",
        minimum: 0,
        maximum: 100,
    }];
    input.statisticalPolicy.metrics = [{
        key: "score",
        minimum: 0,
        maximum: 100,
        estimand: "mean score versus frozen control",
        unit: "score",
        direction: "max",
        acceptanceThreshold: 100,
        practicalEquivalenceDelta: 1,
        family: "primary",
    }];
    input.statisticalPolicy.control = {
        kind: input.statisticalPolicy.control.kind,
        identity: input.statisticalPolicy.control.identity,
        tolerances: [{
            metric: "score",
            absolute: 0,
            relative: 0,
        }],
    };
    input.harnessSuite = harnessSuite;
    input.harnessSuiteIdentity = harnessSuiteIdentity;
    return createInvestigationContract(input);
}

function scoreProcessAdapter() {
    let nextPid = 8_000;
    const children = new Map();
    return {
        spawn(_executable, _argv, options) {
            const child = new EventEmitter();
            child.pid = ++nextPid;
            child.stdout = new PassThrough();
            child.stderr = new PassThrough();
            const state = { child, closed: false };
            children.set(child.pid, state);
            setImmediate(() => {
                const raw = fs.readFileSync(
                    path.join(
                        options.env.CANDIDATE_SNAPSHOT_PATH,
                        "score.txt",
                    ),
                    "utf8",
                ).trim();
                const score = Number(raw);
                child.stdout.end(Buffer.from(JSON.stringify({
                    pass: Number.isFinite(score) && score >= 100,
                    metrics: { score },
                }), "utf8"));
                child.stderr.end();
                state.closed = true;
                children.delete(child.pid);
                child.emit("close", 0, null);
            });
            return child;
        },
        terminateTree(pid) {
            const state = children.get(pid);
            if (state === undefined || state.closed) return false;
            state.child.stdout.end();
            state.child.stderr.end();
            state.closed = true;
            children.delete(pid);
            setImmediate(() => state.child.emit("close", null, "SIGKILL"));
            return true;
        },
    };
}

function writeVerifierScript(root, checkerEvidenceRoot) {
    return writeHarnessScript(root, "impossibility-verifier", `
const { createHash } = await import("node:crypto");
const candidatePath = process.argv[2];
const requestPath = path.join(candidatePath, "request.json");
const requestBytes = fs.readFileSync(requestPath);
const request = JSON.parse(requestBytes.toString("utf8"));
const canonical = (value) => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value !== null && typeof value === "object") {
        return Object.fromEntries(
            Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
        );
    }
    return value;
};
const digest = (bytes) =>
    createHash("sha256").update(bytes).digest("hex");
const hash = (value, tag) =>
    \`\${tag}:\${digest(Buffer.from(JSON.stringify(canonical(value)), "utf8"))}\`;
const requestHash =
    \`sha256:crucible-impossibility-request-v2:\${digest(requestBytes)}\`;
const mode = request.verifier.verificationPolicy.mode;
const proofArtifactHash = request.proofArtifact.artifactHash;
const certificateFormat =
    request.verifier.verificationPolicy.certificateFormat;
const proofCheckerIdentity = mode === "certificate_validation"
    ? request.verifier.proofChecker.identity
    : null;
const enumerandResults = mode === "enumerand_reexecution"
    ? request.evidence.coverageClosure.enumerands.map((entry) => {
        const input = request.reevaluation.enumerands[entry.ordinal];
        const claimStates = entry.claims
            .map((claim) => ({ claimId: claim.claimId, state: "REFUTED" }))
            .sort((left, right) => left.claimId.localeCompare(right.claimId));
        const evidenceRoot = hash({
            requestHash,
            verifierRoleIdentity: request.verifier.roleIdentity,
            ordinal: entry.ordinal,
            enumerandHash: entry.enumerandHash,
            inputRoot: input.inputRoot,
            claimStates,
        }, "sha256:crucible-impossibility-verifier-refutation-v1");
        return {
            ordinal: entry.ordinal,
            enumerandHash: entry.enumerandHash,
            claimStates,
            evidenceRoot,
            inputRoot: input.inputRoot,
            receiptBindingsRoot: input.receiptBindingsRoot,
            refutationReceiptHash: hash({
                requestHash,
                verifierRoleIdentity: request.verifier.roleIdentity,
                ordinal: entry.ordinal,
                enumerandHash: entry.enumerandHash,
                inputRoot: input.inputRoot,
                receiptBindingsRoot: input.receiptBindingsRoot,
                claimStates,
                evidenceRoot,
            }, "sha256:crucible-impossibility-verifier-refutation-receipt-v1"),
        };
    })
    : [];
const enumerandResultsRoot = hash(
    enumerandResults,
    "sha256:crucible-impossibility-verifier-enumerand-results-v1",
);
const proofValidationReceiptHash = mode === "certificate_validation"
    ? hash({
        requestHash,
        proofArtifactHash,
        proofCheckerIdentity,
        certificateFormat,
        status: "VERIFIED",
        checkerEvidenceRoot: ${JSON.stringify(checkerEvidenceRoot)},
    }, "sha256:crucible-impossibility-proof-validation-receipt-v1")
    : null;
const validatedProofArtifactHash = mode === "certificate_validation"
    ? proofArtifactHash
    : null;
const independentFactsRoot = mode === "enumerand_reexecution"
    ? hash({
        mode,
        refutations: enumerandResults.map((result) => ({
            ordinal: result.ordinal,
            enumerandHash: result.enumerandHash,
            inputRoot: result.inputRoot,
            receiptBindingsRoot: result.receiptBindingsRoot,
            evidenceRoot: result.evidenceRoot,
            refutationReceiptHash: result.refutationReceiptHash,
        })),
        proofArtifactHash,
    }, "sha256:crucible-impossibility-verifier-facts-v1")
    : hash({
        mode,
        proofArtifactHash,
        proofCheckerIdentity,
        proofValidationReceiptHash,
        validatedProofArtifactHash,
    }, "sha256:crucible-impossibility-verifier-facts-v1");
const certificate = {
    version: "crucible-impossibility-certificate-v2",
    status: "VERIFIED",
    verdict: "target_unreachable",
    mode,
    requestHash,
    proposedCertificateArtifactHash:
        request.proposedCertificate.artifactHash,
    proofArtifactHash,
    contractHash: request.signedExperiment.contractHash,
    harnessSuiteIdentity: request.harnessSuiteIdentity,
    verifierRoleIdentity: request.verifier.roleIdentity,
    coverageClosureRoot: request.evidence.coverageClosureRoot,
    enumerandManifestRoot: request.enumerands.merkleRoot,
    enumerandResultsRoot,
    evidenceRoots: request.evidence.roots,
    statisticalPolicyIdentity: request.statistics.policyIdentity,
    alphaLedgerRoot: request.statistics.alphaLedgerRoot,
    checkerEvidenceRoot: ${JSON.stringify(checkerEvidenceRoot)},
    independentFactsRoot,
    certificateFormat,
    proofCheckerIdentity,
    proofValidationReceiptHash,
    validatedProofArtifactHash,
};
process.stdout.write(JSON.stringify({
    version: "crucible-impossibility-verifier-output-v1",
    status: "VERIFIED",
    mode,
    requestHash,
    proposedCertificateArtifactHash:
        request.proposedCertificate.artifactHash,
    proofArtifactHash,
    coverageClosureRoot: request.evidence.coverageClosureRoot,
    enumerandManifestRoot: request.enumerands.merkleRoot,
    enumerandCount: request.enumerands.count,
    checkedEnumerandCount: enumerandResults.length,
    enumerandResults,
    enumerandResultsRoot,
    evidenceRoots: request.evidence.roots,
    statisticalPolicyIdentity: request.statistics.policyIdentity,
    alphaLedgerRoot: request.statistics.alphaLedgerRoot,
    checkerEvidenceRoot: ${JSON.stringify(checkerEvidenceRoot)},
    independentFactsRoot,
    disagreementCount: 0,
    complete: true,
    certificateFormat,
    proofCheckerIdentity,
    proofValidationReceiptHash,
    validatedProofArtifactHash,
    certificate,
    role: process.env.CRUCIBLE_ROLE,
    phase: process.env.CRUCIBLE_PHASE,
    blockIndex: Number(process.env.CRUCIBLE_BLOCK_INDEX),
    deterministicSeed: process.env.CRUCIBLE_DETERMINISTIC_SEED,
    subjectId: process.env.CRUCIBLE_SUBJECT_ID,
    environmentIdentity: process.env.CRUCIBLE_ENVIRONMENT_IDENTITY,
    suiteIdentity: process.env.CRUCIBLE_SUITE_IDENTITY,
}));
`);
}

class WorkerPool {
    constructor() {
        this.calls = [];
    }

    async propose(request) {
        this.calls.push(request);
        const candidate = validateCandidateSubmission({
            challenge: request.challengeNonce,
            candidateId:
                request.candidateId ?? request.allowedCandidateIds[0],
            annotations: {
                mechanism: "Fixture rejects the only enumerand",
                finding: "Fixture score remains below threshold",
            },
            files: [{ path: "score.txt", content: "0\n" }],
        }, {
            challengeNonce: request.challengeNonce,
            allowedCandidateIds: request.allowedCandidateIds,
            visibleEvidenceIds: request.visibleEvidenceIds,
        });
        return {
            ...candidate,
            identity: {
                invocationSessionId: request.sessionId,
                configuredModel: request.model,
                challengeNonce: request.challengeNonce,
                promptHash: hashCanonical(
                    { prompt: request.prompt },
                    "sha256:crucible-runtime-worker-prompt-v1",
                ),
                contextHash: request.promptContextHash ?? null,
                annotationsHash: hashCanonical(
                    candidate.annotations,
                    "sha256:crucible-runtime-candidate-annotations-v1",
                ),
                payloadHash: hashCanonical(
                    candidate,
                    "sha256:crucible-runtime-candidate-payload-v1",
                ),
            },
        };
    }

    releaseCandidateId() {}
    async close() {}
}

function containmentProvider(
    identity = sandboxIdentity(),
    policyDigest =
        `sha256:runner-fixture-policy-v1:${"c".repeat(64)}`,
) {
    let nextCapability = 0;
    return createSandboxProvider({
        providerId: identity.providerId,
        providerVersion: identity.providerVersion,
        describePolicyIdentity: () => identity,
        admitAndPrepare(request, issueLaunchCapability) {
            let child = null;
            return issueLaunchCapability({
                capabilityId: `runner-capability-${++nextCapability}`,
                policyId: identity.policyId,
                policyDigest,
                policyIdentity: identity,
                policy: {
                    version: 1,
                    identity,
                },
                permittedStagedRoots: request.stagedRoots,
                launch(launchRequest) {
                    child = spawn(
                        launchRequest.executable,
                        launchRequest.argv,
                        {
                            cwd: launchRequest.options.cwd,
                            env: launchRequest.options.env,
                            stdio: launchRequest.options.stdio,
                            shell: false,
                            windowsHide: true,
                            detached: true,
                        },
                    );
                    return child;
                },
                terminate({ pid }) {
                    if (child?.pid === pid && !child.killed) {
                        child.kill("SIGKILL");
                    }
                    return true;
                },
                cleanup() {
                    return true;
                },
            });
        },
    });
}

export function setupImpossibilityRunnerFixture(
    label,
    {
        mode = "enumerand_reexecution",
        maxBlocks = 3,
        alpha = 0.5,
    } = {},
) {
    const root = makeTempRoot(`impossibility-${label}`);
    const stateDir = path.join(root, "state");
    const artifactRoot = path.join(root, "artifacts");
    fs.mkdirSync(stateDir, { recursive: true });
    const store = openArtifactStore({ root: artifactRoot });
    const goodSnapshot = seedSnapshot(store, root, "good", 100);
    const badSnapshot = seedSnapshot(store, root, "bad", 0);
    const roleSnapshots = {
        search: seedSnapshot(store, root, "search-role", 0),
        confirmation: seedSnapshot(store, root, "confirmation-role", 0),
        challenge: seedSnapshot(store, root, "challenge-role", 0),
        novelty: seedSnapshot(store, root, "novelty-role", 0),
    };
    const enumerandManifest = normalizeEnumerandManifest({
        topology: "finite_enumerable",
        entries: [{
            id: "certified-candidate",
            ordinal: 0,
            artifactSnapshotHash:
                seedSnapshot(store, root, "certified-enumerand", 0),
        }],
        control: { kind: "reference", referenceHash: badSnapshot },
    });
    const allowlistPath = path.join(root, "harness.allowlist.json");
    const validationCases = {
        "known-good": goodSnapshot,
        "known-bad": badSnapshot,
        "search-case": roleSnapshots.search,
        "confirmation-case": roleSnapshots.confirmation,
        "challenge-case": roleSnapshots.challenge,
        "novelty-case": roleSnapshots.novelty,
    };
    const checkerEvidenceRoot = hashCanonical(
        { label, checker: "actual-process" },
        "sha256:crucible-runtime-checker-evidence-v1",
    );
    const verifierScript =
        writeVerifierScript(root, checkerEvidenceRoot);
    const proofChecker = path.join(root, "proof-checker.bin");
    fs.writeFileSync(proofChecker, "operator-attested proof checker bytes\n");
    const verifierDependencies = [{
        path: verifierScript,
        sha256: sha256HexOfFile(verifierScript),
        role: "verifier-script",
    }];
    if (mode === "certificate_validation") {
        verifierDependencies.push({
            path: proofChecker,
            sha256: sha256HexOfFile(proofChecker),
            role: "impossibility-proof-checker",
        });
    }
    const allowlistDocument = {
        version: 1,
        entries: {
            "score-harness": {
                executable: WINDOWS_CMD,
                executableSha256: sha256HexOfFile(WINDOWS_CMD),
                argvTemplate: [],
                dependencies: [],
                timeoutMs: 15_000,
                maxStdoutBytes: 1024 * 1024,
                maxStderrBytes: 256 * 1024,
                executesCandidateCode: false,
                validationCases: Object.fromEntries(
                    Object.entries(validationCases).map(([id, snapshotHash]) => [
                        id,
                        {
                            snapshotHash,
                            expectation: id === "known-bad"
                                || id === "challenge-case"
                                ? "reject"
                                : "accept",
                        },
                    ]),
                ),
            },
            "verifier-harness": {
                executable: NODE_EXE,
                executableSha256: nodeExeSha256Hex(),
                argvTemplate: [verifierScript, "{{candidatePath}}"],
                dependencies: verifierDependencies,
                timeoutMs: 15_000,
                maxStdoutBytes: 1024 * 1024,
                maxStderrBytes: 256 * 1024,
                executesCandidateCode: true,
                validationCases: {
                    "known-good": {
                        snapshotHash: goodSnapshot,
                        expectation: "accept",
                    },
                    "known-bad": {
                        snapshotHash: badSnapshot,
                        expectation: "reject",
                    },
                },
            },
        },
    };
    fs.writeFileSync(
        allowlistPath,
        JSON.stringify(allowlistDocument, null, 2),
    );
    let allowlist = loadHarnessAllowlist(allowlistPath);
    const verifierVerification = verifyHarnessPreflight(
        allowlist,
        "verifier-harness",
        {
            parserVersion: VERIFIER_PARSER_VERSION,
            validationCases: [
                {
                    id: "known-good",
                    expectation: "accept",
                    artifactHash: goodSnapshot,
                },
                {
                    id: "known-bad",
                    expectation: "reject",
                    artifactHash: badSnapshot,
                },
            ],
        },
    );
    const verifierIdentity = buildFrozenHarnessIdentity(
        verifierVerification,
        { sandbox: sandboxIdentity() },
    );
    allowlistDocument.suites = {
        "score-suite": buildHarnessSuiteForAllowlist(allowlist, {
            suiteId: "score-suite",
            harnessId: "score-harness",
            includeVerifier: true,
            verifierHarnessId: "verifier-harness",
            sandboxPolicyDigest: verifierIdentity.sandbox.policyDigest,
            roleCaseIds: {
                calibration: ["known-good", "known-bad"],
                search: ["search-case"],
                confirmation: ["confirmation-case"],
                challenge: ["challenge-case"],
                novelty: ["novelty-case"],
            },
        }),
    };
    if (mode === "certificate_validation") {
        allowlistDocument.suites["score-suite"].roles
            .impossibility_verifier.verificationPolicy = {
                mode,
                certificateFormat: {
                    version: "fixture-proof-v1",
                    schemaHash: hashCanonical(
                        { mode, schema: "fixture" },
                        "sha256:crucible-fixture-proof-schema-v1",
                    ),
                },
            };
    }
    fs.writeFileSync(
        allowlistPath,
        JSON.stringify(allowlistDocument, null, 2),
    );
    allowlist = loadHarnessAllowlist(allowlistPath);
    const harnessSuite = allowlist.getSuite("score-suite");
    const contract = makeContract({
        goodSnapshot,
        badSnapshot,
        harnessSuite,
        harnessSuiteIdentity:
            computeHarnessSuiteV4Identity(harnessSuite),
        enumerandManifest,
        maxBlocks,
        alpha,
    });
    const repository = openRepository({
        file: path.join(stateDir, "events.sqlite"),
    });
    const signed = createSignedInvestigationAuthority({
        contract,
        experimentId: `runner-${label}`,
        projectDir: root,
    });
    const adapter = createDomainRepositoryAdapter({
        repository,
        artifactStore: store,
        investigationId: signed.investigationId,
    });
    adapter.openInvestigation(
        contract,
        signed.capability,
        createRuntimeConfigAuthorityFixture(signed.investigationId, {
            sandbox: {
                ...sandboxIdentity(),
                policyDigest: verifierIdentity.sandbox.policyDigest,
            },
        }),
    );
    repository.close();
    return {
        root,
        stateDir,
        artifactRoot,
        allowlistPath,
        verifierScript,
        proofChecker,
        sandboxPolicyDigest: verifierIdentity.sandbox.policyDigest,
        contract,
        config: {
            investigationId: signed.investigationId,
            stateDir,
            artifactRoot,
            allowlistPath,
            copilotSdkPath: path.join(root, "unused-sdk"),
            copilotCliPath: path.join(root, "unused-copilot.exe"),
            runnerEpochId: "runner-epoch-1",
            deadline: Date.now() + 120_000,
            options: {
                maxLoopIterations: 1000,
                sessionTimeoutMs: 5000,
            },
        },
    };
}

export async function runImpossibilityRunnerFixture(
    setup,
    { sandbox = sandboxIdentity() } = {},
) {
    const workerPool = new WorkerPool();
    const result = await runAutonomousInvestigation(setup.config, {
        workerPool,
        idFactory: (() => {
            let next = 0;
            return () => `fixture-id-${++next}`;
        })(),
        processAdapter: scoreProcessAdapter(),
        sandboxProvider: containmentProvider(
            sandbox,
            setup.sandboxPolicyDigest,
        ),
    });
    return { result, workerPool };
}

export function replayImpossibilityRunnerFixture(setup) {
    const repository = openRepository({
        file: path.join(setup.stateDir, "events.sqlite"),
    });
    const artifactStore = openArtifactStore({ root: setup.artifactRoot });
    const adapter = createDomainRepositoryAdapter({
        repository,
        artifactStore,
        investigationId: setup.config.investigationId,
    });
    return {
        repository,
        artifactStore,
        adapter,
        ...adapter.replay(),
    };
}

export function cloneImpossibilityRunnerFixture(setup, label) {
    const root = makeTempRoot(`impossibility-clone-${label}`);
    const stateDir = path.join(root, "state");
    const artifactRoot = path.join(root, "artifacts");
    fs.cpSync(setup.stateDir, stateDir, { recursive: true });
    fs.cpSync(setup.artifactRoot, artifactRoot, { recursive: true });
    return {
        ...setup,
        root,
        stateDir,
        artifactRoot,
        config: {
            ...setup.config,
            stateDir,
            artifactRoot,
            deadline: Date.now() + 120_000,
        },
    };
}

export async function cleanupImpossibilityRunnerFixture(setup) {
    if (setup?.root === undefined) return;
    await removeTreeRobust(setup.root, {
        label: "impossibility runner fixture",
        timeoutMs: 30_000,
    });
}

export function wrongSandboxIdentity() {
    const identity = structuredClone(sandboxIdentity());
    identity.securityContext.capabilities = ["internetClient"];
    return identity;
}
