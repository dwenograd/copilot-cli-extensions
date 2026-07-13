import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

import {
    ANNOTATION_LIMITS,
    EVENT_TYPES,
    IMPOSSIBILITY_REQUEST_HASH_ALGORITHM,
    IMPOSSIBILITY_PROPOSAL_HASH_ALGORITHM,
    IMPOSSIBILITY_PROOF_ARTIFACT_HASH_ALGORITHM,
    IMPOSSIBILITY_VERIFIER_OBJECT_MANIFEST_HASH_ALGORITHM,
    NON_RESULT_CODES,
    OBSERVATION_STREAM_HASH_ALGORITHM,
    SNAPSHOT_EXECUTION_HASH_ALGORITHM,
    buildCandidateArchive,
    canonicalEqual,
    canonicalJson,
    constructInvestigationResumedEvent,
    createImpossibilityVerificationPackage,
    createEvidenceProvenance,
    createMeasurementProvenance,
    createSnapshotProvenance,
    createExternalEvent,
    decideNext,
    deriveReplicationControlBinding,
    detectPlateau,
    duplicateEvidenceId,
    enumerandBindingHash,
    hashCanonical,
    harnessCandidateEvidenceItems,
    immutableCanonical,
    currentValidationEvidence,
    latestUnhandledStopRequest,
    resolveControlEnumerand,
    createRawMeasurementSeries,
    statisticalSubjectIndex,
    normalizeImpossibilityCheckerResult,
    searchProgress,
} from "../domain/index.mjs";
import {
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";
import {
    PARSER_VERSION,
    VERIFIER_PARSER_VERSION,
    trustedParserIdentity,
    RECEIPT_VERSION,
    HARNESS_SUITE_RECEIPT_VERSION,
    SANDBOX_POLICY_IDENTITY_HASH_ALGORITHM,
    STREAM_HASH_ALGORITHM,
    DEFAULT_MEASUREMENT_BYTE_BUDGETS,
    createMeasurementExecutor,
    createDefaultProcessAdapter,
    createWindowsSandboxProvider,
    describeSandboxProviderPolicy,
    hashReceipt,
    applicationEntrypointHashForEntry,
    loadHarnessAllowlist,
    sha256Bytes,
} from "../measurement/index.mjs";
import { MEASUREMENT_LIFECYCLE_ADAPTER } from "../measurement/private-adapters.mjs";
import { normalizeRunnerConfig } from "./config.mjs";
import { deriveRunnerExecutionLimits } from "./config-validation.mjs";
import { createDomainRepositoryAdapter, formatAttemptCommand } from "./domain-adapter.mjs";
import { projectRunnerOutcome } from "./outcome.mjs";
import {
    CrucibleRuntimeError,
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
    RuntimeIntegrityError,
} from "./errors.mjs";
import {
    DEFAULT_PARENT_READ_LIMITS,
    buildProposalPrompt,
    createBoundedParentReadAuthority,
    createSdkWorkerPool,
    normalizeParentReadLimits,
    validateCandidateSubmission,
    validateWorkerProposal,
} from "./worker-pool.mjs";
import {
    assertBoundedEnumerandRequest,
    assertFiniteEnumerandSnapshot,
    resolveCommandEnumerand,
} from "./enumerand-execution.mjs";
import {
    evaluateReplicationProgress,
    normalizeReplicationSchedule,
    replicationBlockPlan,
} from "./measurement-scheduler.mjs";
import { buildPromptContext } from "./prompt-context.mjs";
import {
    RUNTIME_TEMP_OWNER_MARKER,
    assertPathInside,
    atomicWriteJson,
    deadlineReached,
    ensureDirectory,
    makeUniqueDirectory,
    measurementSnapshotHash,
    remainingDeadlineMs,
    removeTreeInside,
    safeFileToken,
    sha256Hex,
    snapshotObjectHex,
    settleWithin,
    taggedHash,
} from "./utils.mjs";

const LOGICAL_EFFECT_KEY_ALGORITHM = "sha256:crucible-runtime-logical-effect-v1";
const EFFECT_RECOVERY_CAPSULE_HASH_ALGORITHM =
    "sha256:crucible-runtime-effect-recovery-capsule-v1";
const EFFECT_RECOVERY_CAPSULE_VERSION = 1;
const RUNTIME_TEMP_OWNER_VERSION = 1;
const IMPOSSIBILITY_CERTIFICATE_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-certificate-artifact-v2";
const IMPOSSIBILITY_RECEIPT_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-receipt-artifact-v1";
const IMPOSSIBILITY_STDOUT_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-stdout-artifact-v1";
const IMPOSSIBILITY_STDERR_ARTIFACT_HASH_ALGORITHM =
    "sha256:crucible-impossibility-stderr-artifact-v1";
const IMPOSSIBILITY_REQUEST_FILENAME = "request.json";
const IMPOSSIBILITY_PROPOSAL_FILENAME = "proposed-certificate.json";
const IMPOSSIBILITY_PROOF_FILENAME = "proof-artifact.json";
const SNAPSHOT_CLOSURE_HASH =
    /^sha256:crucible-measurement-snapshot-closure-v1:[a-f0-9]{64}$/u;
export const DEFAULT_RUNTIME_BYTE_BUDGETS = Object.freeze({
    ...DEFAULT_MEASUREMENT_BYTE_BUDGETS,
    perAttemptCasBytes: 32 * 1024 * 1024,
    perInvestigationCasBytes: 2 * 1024 * 1024 * 1024,
});

function objectIdForBytes(bytes) {
    return `sha256:${sha256Hex(bytes)}`;
}

function taggedHashMatchesObjectId(tagged, objectId) {
    return typeof tagged === "string"
        && typeof objectId === "string"
        && tagged.split(":").at(-1)
            === objectId.slice("sha256:".length);
}

function impossibilityManifestCore(manifest) {
    return {
        version: manifest.version,
        pack: manifest.pack,
        entries: manifest.entries,
    };
}

function generatedImpossibilityDocuments(command) {
    const documents = new Map([
        [
            "coverage-closure.json",
            command.request.evidence.coverageClosure,
        ],
        [
            "enumerand-manifest.json",
            command.request.enumerands.manifest,
        ],
        [
            "scientific-replay.json",
            command.request.statistics.scientificReplay,
        ],
        [
            IMPOSSIBILITY_PROOF_FILENAME,
            command.proofArtifact,
        ],
    ]);
    if (command.request.reevaluation.calibration !== null) {
        documents.set(
            "reevaluation/calibration.json",
            command.request.reevaluation.calibration,
        );
    }
    for (const input of command.request.reevaluation.enumerands) {
        documents.set(
            `reevaluation/enumerands/${String(input.ordinal)
                .padStart(6, "0")}.json`,
            input,
        );
    }
    return documents;
}

function normalizeRuntimeByteBudgets(
    value = {},
    fallbacks = DEFAULT_RUNTIME_BYTE_BUDGETS,
) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RuntimeConfigError("byteBudgets must be an object");
    }
    const unknown = Object.keys(value).filter((key) =>
        !Object.hasOwn(DEFAULT_RUNTIME_BYTE_BUDGETS, key));
    if (unknown.length > 0) {
        throw new RuntimeConfigError("byteBudgets contain unknown keys", { unknown });
    }
    const normalized = {};
    for (const [key, fallback] of Object.entries(fallbacks)) {
        const actual = value[key] ?? fallback;
        if (!Number.isSafeInteger(actual)
            || actual < 1
            || actual > 4 * 1024 * 1024 * 1024) {
            throw new RuntimeConfigError(
                `byteBudgets.${key} must be a positive safe integer <= 4 GiB`,
                { value: actual },
            );
        }
        normalized[key] = actual;
    }
    if (normalized.perInvestigationOutputBytes < normalized.perAttemptOutputBytes
        || normalized.perInvestigationReceiptBytes < normalized.perAttemptReceiptBytes
        || normalized.perInvestigationCasBytes < normalized.perAttemptCasBytes) {
        throw new RuntimeConfigError(
            "per-investigation byte budgets must be at least their per-attempt budgets",
        );
    }
    return Object.freeze(normalized);
}

function runtimeSandboxIdentity(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return value;
    }
    if (typeof value.policyDigest === "string") {
        return Object.freeze({ ...value });
    }
    const source = value.policyIdentity !== null
        && typeof value.policyIdentity === "object"
        && !Array.isArray(value.policyIdentity)
        ? value.policyIdentity
        : value;
    const policyIdentity = Object.fromEntries(
        Object.entries(source).filter(([key]) =>
            !["available", "policyDigest", "policyIdentity", "required"].includes(key)),
    );
    return Object.freeze({
        ...value,
        policyIdentity: Object.freeze(policyIdentity),
        policyDigest: hashCanonical(
            policyIdentity,
            SANDBOX_POLICY_IDENTITY_HASH_ALGORITHM,
        ),
    });
}

function compareStable(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

function stagedHarnessHashesMatch(receipt) {
    if (receipt?.stagedExecutableHash !== receipt?.executableHash
        || !Array.isArray(receipt?.dependencyHashes)
        || !Array.isArray(receipt?.stagedDependencyHashes)
        || receipt.dependencyHashes.length !== receipt.stagedDependencyHashes.length) {
        return false;
    }
    const project = (items) => items
        .map((item) => ({
            role: item?.role ?? null,
            sha256: item?.sha256 ?? null,
        }))
        .sort((left, right) =>
            compareStable(
                `${left.role ?? ""}\0${left.sha256 ?? ""}`,
                `${right.role ?? ""}\0${right.sha256 ?? ""}`,
            ));
    return canonicalEqual(
        project(receipt.dependencyHashes),
        project(receipt.stagedDependencyHashes),
    );
}

function receiptHasCompleteOutput(receipt) {
    const capture = receipt?.outputCapture;
    if (capture === null
        || typeof capture !== "object"
        || capture.overflowed !== false
        || capture.truncated !== false) {
        return false;
    }
    return ["stdout", "stderr"].every((stream) => {
        const value = capture[stream];
        return value !== null
            && typeof value === "object"
            && Number.isSafeInteger(value.capBytes)
            && value.capBytes > 0
            && Number.isSafeInteger(value.totalObservedBytes)
            && value.totalObservedBytes >= 0
            && value.retainedBytes === value.totalObservedBytes
            && value.retainedBytes <= value.capBytes
            && value.overflowed === false
            && value.truncated === false;
    });
}

function receiptHasVerifiedSnapshotBytes(
    receipt,
    candidateSnapshotHash,
    { requireCompleteOutput = true } = {},
) {
    const identity = receipt?.candidateSnapshotIdentitySummary;
    const stagedIdentity = receipt?.stagedCandidateSnapshotIdentitySummary;
    const mutation = receipt?.candidateSnapshotMutationCheck;
    return (receipt?.version === RECEIPT_VERSION
            || receipt?.version === HARNESS_SUITE_RECEIPT_VERSION)
        && receipt.candidateSnapshotHash === candidateSnapshotHash
        && receipt.stagedCandidateSnapshotHash === candidateSnapshotHash
        && SNAPSHOT_CLOSURE_HASH.test(
            receipt.stagedCandidateSnapshotClosureHash ?? "",
        )
        && stagedIdentity !== null
        && typeof stagedIdentity === "object"
        && Array.isArray(receipt.launchFileBindings)
        && receipt.launchFileBindings.some((file) =>
            file?.role === "candidate"
            && typeof file?.sha256 === "string")
        && SNAPSHOT_CLOSURE_HASH.test(
            receipt.candidateSnapshotPreClosureHash ?? "",
        )
        && receipt.candidateSnapshotPreClosureHash
            === receipt.candidateSnapshotPostClosureHash
        && identity !== null
        && typeof identity === "object"
        && identity.pre !== undefined
        && identity.post !== undefined
        && canonicalEqual(identity.pre, identity.post)
        && mutation?.status === "passed"
        && mutation.closureStable === true
        && mutation.identityStable === true
        && mutation.openHandleRehashStable === true
        && mutation.reparseStable === true
        && (!requireCompleteOutput || receiptHasCompleteOutput(receipt))
        && stagedHarnessHashesMatch(receipt);
}

export function inspectFrozenImpossibilityVerifierExecution({
    receipt,
    verifierRole,
    parserVersion,
} = {}) {
    const securityContext =
        receipt?.sandbox?.policyIdentity?.securityContext;
    const checks = {
        receiptVersion:
            receipt?.version === HARNESS_SUITE_RECEIPT_VERSION,
        harnessId: receipt?.harnessId === verifierRole?.harnessId,
        parserVersion: receipt?.parserVersion === parserVersion,
        parserIdentity: canonicalEqual(
            receipt?.parserIdentity,
            verifierRole?.parser,
        ),
        harnessEntry: receipt?.harnessEntryHash
            === verifierRole?.harnessEntryHash,
        executable: receipt?.executableHash
            === verifierRole?.executableHash,
        stagedExecutable: receipt?.stagedExecutableHash
            === verifierRole?.executableHash,
        sandboxPolicy: receipt?.sandbox?.policyDigest
            === verifierRole?.sandboxIdentity?.policyDigest,
        sandboxCapability:
            receipt?.sandbox?.capabilityLaunchUsed === true
            && typeof receipt?.sandbox?.capabilityId === "string"
            && receipt.sandbox.capabilityId.length > 0,
        appContainer: securityContext?.appContainer === true,
        lowIntegrity: securityContext?.lowIntegrity === true,
        zeroCapabilities: Array.isArray(securityContext?.capabilities)
            && securityContext.capabilities.length === 0,
    };
    const failedBindings = Object.entries(checks)
        .filter(([, valid]) => !valid)
        .map(([name]) => name);
    return immutableCanonical({
        valid: failedBindings.length === 0,
        failedBindings,
    });
}

function snapshotExecutionHash(receipt) {
    return hashCanonical({
        stagedCandidateSnapshotHash: receipt.stagedCandidateSnapshotHash,
        stagedCandidateSnapshotClosureHash:
            receipt.stagedCandidateSnapshotClosureHash,
        stagedCandidateSnapshotIdentitySummary:
            receipt.stagedCandidateSnapshotIdentitySummary,
        candidateSnapshotPreClosureHash: receipt.candidateSnapshotPreClosureHash,
        candidateSnapshotPostClosureHash: receipt.candidateSnapshotPostClosureHash,
        candidateSnapshotIdentitySummary: receipt.candidateSnapshotIdentitySummary,
        candidateSnapshotMutationCheck: receipt.candidateSnapshotMutationCheck,
    }, SNAPSHOT_EXECUTION_HASH_ALGORITHM);
}

function defaultClock() {
    return {
        now: () => Date.now(),
        isoNow: () => new Date().toISOString(),
    };
}

function stableHex(value) {
    return sha256Hex(Buffer.from(canonicalJson(value), "utf8"));
}

function uuidFromHex(hex) {
    const normalized = hex.padEnd(32, "0").slice(0, 32);
    const variant = (Number.parseInt(normalized[16], 16) & 0x3) | 0x8;
    return [
        normalized.slice(0, 8),
        normalized.slice(8, 12),
        `4${normalized.slice(13, 16)}`,
        `${variant.toString(16)}${normalized.slice(17, 20)}`,
        normalized.slice(20, 32),
    ].join("-");
}

function uniqueNonexistentPath(root, prefix, idFactory) {
    ensureDirectory(root);
    for (let attempt = 0; attempt < 100; attempt += 1) {
        const token = stableHex({ prefix, nonce: idFactory(), attempt }).slice(0, 24);
        const candidate = assertPathInside(path.join(root, `${prefix}-${token}`), root, "temporary path");
        if (!fs.existsSync(candidate)) {
            return candidate;
        }
    }
    throw new CrucibleRuntimeError(
        RUNTIME_ERROR_CODES.CHILD_CRASH,
        "Unable to allocate a unique temporary path",
        { root, prefix },
    );
}

function terminalResult(aggregate) {
    return {
        kind: "TERMINAL",
        decision: aggregate.terminal.decision,
        candidateId: aggregate.terminal.candidateId ?? null,
        evidenceId: aggregate.terminal.evidenceId ?? null,
        eventHash: aggregate.terminal.eventHash,
        seq: aggregate.terminal.seq,
    };
}

function nonResult(aggregate) {
    const item = aggregate.nonResults.at(-1);
    return {
        kind: "NON_RESULT",
        code: item.code,
        reason: item.reason,
        seq: item.seq,
    };
}

function pauseResult(aggregate) {
    return {
        kind: "PAUSE",
        code: NON_RESULT_CODES.INVESTIGATION_PAUSED,
        reason: aggregate.pause.reason,
        seq: aggregate.pause.seq,
    };
}

function ensureReceiptObservationHash(receiptHash) {
    if (typeof receiptHash !== "string"
        || !/^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u.test(receiptHash)) {
        throw new RuntimeIntegrityError("Measurement receipt hash is not algorithm-tagged", {
            receiptHash,
        });
    }
    return receiptHash;
}

function truncateUtf8(value, maximumCharacters, maximumBytes) {
    let output = value.slice(0, maximumCharacters);
    while (Buffer.byteLength(output, "utf8") > maximumBytes) {
        output = output.slice(0, -1);
    }
    return output;
}

function measurementFailureMetadata(error) {
    return immutableCanonical({
        name: error?.name ?? "Error",
        code: error?.code ?? null,
        message: truncateUtf8(
            error?.message ?? String(error),
            2048,
            4096,
        ),
    });
}

export class AutonomousRunner {
    #config;
    #dependencies;
    #repository = null;
    #adapter = null;
    #artifactStore = null;
    #allowlist = null;
    #contract = null;
    #sandboxProvider = null;
    #sandboxIdentity = Object.freeze({ required: false });
    #executor = null;
    #workerPool = null;
    #parentReadController = null;
    #parentReadLimits;
    #lease = null;
    #recovery = null;
    #runTempRoot = null;
    #attemptCounter = 0;
    #effectAttemptCount = 0;
    #executionLimits = null;
    #attemptCommands = new Map();
    #effectEvidenceBuffers = new Map();
    #capturedOutputs = new Map();
    #recoveredDeadlineStopRequestSeqs = new Set();
    #byteBudgets;
    #byteBudgetOverride;
    #investigationByteUsage = {
        casBytes: 0,
        outputBytes: 0,
        receiptBytes: 0,
    };
    #attemptCasBytes = new Map();
    #countedCasObjects = new Set();
    #domainDeadlineGuardDepth = 0;
    #domainDeadlineStage = null;
    #clock;

    constructor(config, dependencies = {}) {
        this.#config = normalizeRunnerConfig(config, { env: dependencies.env ?? process.env });
        this.#dependencies = dependencies;
        this.#byteBudgets = null;
        this.#byteBudgetOverride = dependencies.byteBudgets ?? null;
        this.#parentReadLimits = normalizeParentReadLimits(
            dependencies.parentReadLimits ?? {},
        );
        this.#clock = dependencies.clock ?? defaultClock();
        if (typeof this.#clock.now !== "function" || typeof this.#clock.isoNow !== "function") {
            throw new RuntimeConfigError("clock must expose now() and isoNow()");
        }
    }

    get config() {
        return this.#config;
    }

    get recovery() {
        return this.#recovery;
    }

    async run() {
        let result;
        let thrown = null;
        try {
            await this.#initialize();
            result = await this.#runLoop();
        } catch (error) {
            if (this.#isDeadlineError(error) && this.#adapter !== null) {
                try {
                    result = this.#recordDeadlineNonResult(
                        this.#adapter.replay().aggregate,
                        error,
                    );
                } catch (deadlinePersistenceError) {
                    thrown = deadlinePersistenceError;
                }
            } else {
                const pauseOutcome = this.#pauseResultAfterOperationalError(error);
                if (pauseOutcome === null) {
                    thrown = error;
                } else {
                    result = pauseOutcome;
                }
            }
        } finally {
            const cleanupError = await this.#cleanup();
            if (cleanupError !== null) {
                if (thrown !== null) {
                    cleanupError.details = {
                        ...(cleanupError.details ?? {}),
                        originalFailure: {
                            name: thrown?.name ?? "Error",
                            code: thrown?.code ?? null,
                            message: thrown?.message ?? String(thrown),
                        },
                    };
                }
                thrown = cleanupError;
            }
        }
        if (thrown !== null) {
            if (typeof thrown?.code !== "string") {
                const wrapped = new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
                    `Autonomous runner failed: ${thrown?.message ?? String(thrown)}`,
                    {
                        name: thrown?.name ?? "Error",
                    },
                    { cause: thrown },
                );
                throw wrapped;
            }
            throw thrown;
        }
        return {
            ...result,
            runnerEpochId: this.#config.runnerEpochId,
            runnerIncarnation: this.#config.runnerIncarnation,
            recovery: this.#recovery,
            tempRootCleaned: this.#runTempRoot === null || !fs.existsSync(this.#runTempRoot),
        };
    }

    #loadRecoveredDeadlineStopRequestSeqs() {
        const events = this.#adapter.listOperationalEvidence();
        const bySeq = new Map(events.map((event) => [event.seq, event]));
        const recovered = new Set();
        for (const event of events) {
            if (event.kind !== "runtime:non_result_recovery"
                || event.payload?.policy !== "later_deadline") {
                continue;
            }
            const previous = bySeq.get(event.payload.previousSeq) ?? null;
            const stopRequestSeq =
                previous?.kind === "runtime:non_result"
                && previous.payload?.code === "DEADLINE_EXCEEDED"
                    ? previous.payload?.details?.deadlineStopRequestSeq
                    : null;
            if (Number.isSafeInteger(stopRequestSeq) && stopRequestSeq > 0) {
                recovered.add(stopRequestSeq);
            }
        }
        return recovered;
    }

    #pauseResultAfterOperationalError(error) {
        if (this.#adapter === null
            || error?.code === RUNTIME_ERROR_CODES.INTEGRITY_FAILURE
            || error?.code === RUNTIME_ERROR_CODES.INVALID_CONFIG) {
            return null;
        }
        try {
            let { aggregate } = this.#adapter.replay();
            if (aggregate.pause === null && error?.pauseBarrier === true) {
                const recommendation = decideNext(aggregate);
                if (recommendation.event?.type === EVENT_TYPES.INVESTIGATION_PAUSED) {
                    this.#appendKernelDecisionFenced({ deadlineExempt: true });
                    ({ aggregate } = this.#adapter.replay());
                }
            }
            if (aggregate.pause === null) return null;
            return {
                ...pauseResult(aggregate),
                drainedOperationalError: {
                    code: error?.code ?? null,
                    message: error?.message ?? String(error),
                },
            };
        } catch {
            return null;
        }
    }

    async #initialize() {
        const stateDir = ensureDirectory(this.#config.stateDir);
        const artifactRoot = ensureDirectory(this.#config.artifactRoot);

        const repositoryFactory = this.#dependencies.repositoryFactory ?? openRepository;
        this.#repository = repositoryFactory({
            file: path.join(stateDir, "events.sqlite"),
            now: () => {
                if (this.#domainDeadlineGuardDepth > 0) {
                    this.#assertDeadlineOpen(
                        this.#domainDeadlineStage ?? "domain persistence",
                    );
                }
                return this.#clock.isoNow();
            },
        });
        const artifactStoreFactory =
            this.#dependencies.artifactStoreFactory ?? openArtifactStore;
        this.#artifactStore = artifactStoreFactory({ root: artifactRoot });
        this.#adapter = createDomainRepositoryAdapter({
            repository: this.#repository,
            artifactStore: this.#artifactStore,
            investigationId: this.#config.investigationId,
            beforeCasAttempt: () => {
                if (this.#domainDeadlineGuardDepth > 0) {
                    this.#assertDeadlineOpen(
                        this.#domainDeadlineStage ?? "domain CAS retry",
                    );
                }
            },
        });
        const opened = this.#adapter.replay();
        if (opened.domainEvents.length === 0 || opened.aggregate.contract === null) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.INVESTIGATION_NOT_OPEN,
                "The runner requires an existing investigation_opened domain event",
                { investigationId: this.#config.investigationId },
            );
        }
        this.#contract = opened.aggregate.contract;
        this.#executionLimits = deriveRunnerExecutionLimits(this.#contract);
        const frozenByteBudgets = normalizeRuntimeByteBudgets(
            this.#executionLimits.byteBudgets,
        );
        if (this.#byteBudgetOverride === null) {
            this.#byteBudgets = frozenByteBudgets;
        } else {
            const override = normalizeRuntimeByteBudgets(
                this.#byteBudgetOverride,
                frozenByteBudgets,
            );
            for (const [key, value] of Object.entries(override)) {
                if (value > frozenByteBudgets[key]) {
                    throw new RuntimeConfigError(
                        `byteBudgets.${key} cannot exceed the frozen statistical resource budget`,
                        {
                            key,
                            configured: value,
                            frozen: frozenByteBudgets[key],
                        },
                    );
                }
            }
            for (const kind of ["Output", "Receipt", "Cas"]) {
                const required = override[`perAttempt${kind}Bytes`]
                    * this.#executionLimits.requiredMeasurementEvaluations;
                if (!Number.isSafeInteger(required)
                    || override[`perInvestigation${kind}Bytes`] < required) {
                    throw new RuntimeConfigError(
                        `byteBudgets.perInvestigation${kind}Bytes cannot cover worst-case role × block × arm attempts`,
                        {
                            kind,
                            required,
                            requiredMeasurementEvaluations:
                                this.#executionLimits.requiredMeasurementEvaluations,
                            perAttempt:
                                override[`perAttempt${kind}Bytes`],
                            perInvestigation:
                                override[`perInvestigation${kind}Bytes`],
                        },
                    );
                }
            }
            this.#byteBudgets = override;
        }
        const operationalNonResult = this.#adapter.latestOperationalNonResult();
        this.#recoveredDeadlineStopRequestSeqs =
            this.#loadRecoveredDeadlineStopRequestSeqs();

        this.#seedByteUsage();
        if (opened.aggregate.terminal !== null
            || opened.aggregate.pause !== null
            || opened.aggregate.nonResults.length > 0
            || operationalNonResult !== null) {
            return;
        }

        const previousLease = this.#repository.getActiveLease(this.#config.investigationId);
        const leaseGeneration = (previousLease?.fencingToken ?? 0) + 1;
        const leaseId = this.#nextStableId("lease", {
            epoch: this.#config.runnerEpochId,
            runnerIncarnation: this.#config.runnerIncarnation,
            leaseGeneration,
            previousLeaseId: previousLease?.leaseId ?? null,
            nonce: this.#idFactory()(),
        });
        const owner = `runner-${this.#config.runnerEpochId}-${
            safeFileToken(
                this.#config.runnerIncarnation ?? this.#config.runnerEpochId,
            ).slice(-12)
        }-${process.pid}`;
        const acquired = this.#adapter.acquireRunnerLease({
            leaseId,
            owner,
            supervisorGeneration: this.#config.supervisorGeneration,
            runnerIncarnation: this.#config.runnerIncarnation,
        });
        this.#lease = acquired.lease;
        this.#recovery = acquired.recovery;
        const unresolvedEffects = this.#unresolvedExternalEffects();
        if (unresolvedEffects.length > 0) {
            this.#recordOperationalNonResultFenced({
                scope: "uncertain-external-effect",
                code: RUNTIME_ERROR_CODES.UNCERTAIN_EXTERNAL_EFFECT,
                reason:
                    "A prior runner stopped after dispatching an external effect but before durably recording its outcome. Automatic replay is blocked to prevent duplicating that effect.",
                details: {
                    count: unresolvedEffects.length,
                    effects: unresolvedEffects.slice(0, 64),
                    omittedCount: Math.max(0, unresolvedEffects.length - 64),
                    resetRequired: true,
                },
            });
            return;
        }
        if (this.#deadlineReached()) {
            return;
        }

        const tempRoot = ensureDirectory(this.#config.options.tempRoot);
        this.#runTempRoot = makeUniqueDirectory(
            tempRoot,
            `run-g${this.#config.supervisorGeneration ?? 0}-${safeFileToken(
                this.#config.runnerIncarnation
                    ?? this.#config.supervisorNonce
                    ?? this.#config.runnerEpochId,
            ).slice(-8)}`,
        );
        this.#writeRuntimeTempOwnerMarker();
        const allowlistLoader = this.#dependencies.allowlistLoader ?? loadHarnessAllowlist;
        this.#allowlist = allowlistLoader(this.#config.allowlistPath);
        const baseProcessAdapter = this.#dependencies.processAdapter
            ?? createDefaultProcessAdapter();
        const processAdapter = baseProcessAdapter;
        const sandboxProvider = Object.hasOwn(
            this.#dependencies,
            "sandboxProvider",
        )
            ? this.#dependencies.sandboxProvider
            : (this.#dependencies.windowsSandboxProviderFactory
                ?? createWindowsSandboxProvider)({
                controlRoot: path.join(
                    this.#runTempRoot,
                    "windows-sandbox-control",
                ),
            });
        this.#sandboxProvider = sandboxProvider;
        const suiteRequiresSandbox = Object.values(
            this.#contract.harnessSuite.roles,
        ).some((role) => role.sandboxIdentity.required);
        if (suiteRequiresSandbox) {
            if (sandboxProvider === null) {
                throw new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                    "Frozen harness identity requires a sandbox provider",
                );
            }
            const describePolicy = this.#dependencies.describeSandboxProviderPolicy
                ?? describeSandboxProviderPolicy;
            const sandboxIdentity = await describePolicy(sandboxProvider);
            if (sandboxIdentity === null) {
                throw new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                    "Sandbox provider did not attest its frozen policy identity",
                );
            }
            this.#sandboxIdentity = runtimeSandboxIdentity(sandboxIdentity);
        }
        for (const role of Object.keys(this.#contract.harnessSuite.roles)) {
            this.#validateHarnessContract(this.#contract, role);
        }
        this.#recordCapabilityEpoch(opened.aggregate);
        this.#executor = this.#dependencies.executor
            ?? (this.#dependencies.executorFactory ?? createMeasurementExecutor)({
                allowlist: this.#allowlist,
                sandboxProvider,
                processAdapter,
                clock: this.#clock,
                scratchRoot: this.#runTempRoot,
                terminationDrainMs: Math.min(
                    5_000,
                    this.#config.options.shutdownTimeoutMs,
                ),
                capabilityCleanupTimeoutMs:
                    this.#config.options.shutdownTimeoutMs,
                byteBudgets: {
                    perAttemptOutputBytes:
                        this.#byteBudgets.perAttemptOutputBytes,
                    perInvestigationOutputBytes:
                        this.#byteBudgets.perInvestigationOutputBytes,
                    perAttemptReceiptBytes:
                        this.#byteBudgets.perAttemptReceiptBytes,
                    perInvestigationReceiptBytes:
                        this.#byteBudgets.perInvestigationReceiptBytes,
                    perAttemptCasBytes:
                        this.#byteBudgets.perAttemptCasBytes,
                    perInvestigationCasBytes:
                        this.#byteBudgets.perInvestigationCasBytes,
                },
                initialByteUsage: {
                    outputBytes:
                        this.#investigationByteUsage.outputBytes,
                    receiptBytes:
                        this.#investigationByteUsage.receiptBytes,
                    casBytes:
                        this.#investigationByteUsage.casBytes,
                },
                onCapturedOutput: ({
                    attemptId,
                    stdout,
                    stderr,
                    launchPath,
                }) => {
                    this.#capturedOutputs.set(attemptId, {
                        stdout: [stdout],
                        stderr: [stderr],
                    });
                },
                [MEASUREMENT_LIFECYCLE_ADAPTER]:
                    this.#measurementLifecycleAdapter(),
            });

    }

    #measurementLifecycleAdapter() {
        const invoke = async (point, details = {}) => {
            let command = null;
            const attemptCommand = this.#attemptCommands.get(details.attemptId);
            if (attemptCommand !== undefined) {
                try {
                    command = JSON.parse(attemptCommand)?.effect ?? null;
                } catch {
                    command = null;
                }
            }
            await this.#fault(point, { ...details, command });
        };
        return Object.freeze({
            afterHarnessStaging: (details) =>
                invoke("after_harness_staging", details),
            beforeHarnessLaunch: (details) =>
                invoke("before_harness_launch", details),
            afterHarnessLaunch: (details) =>
                invoke("after_harness_launch", details),
            afterHarnessExit: (details) =>
                invoke("after_harness_exit", details),
        });
    }

    #recordCapabilityEpoch(aggregate) {
        if (aggregate.terminal !== null
            || aggregate.pause !== null
            || aggregate.nonResults.length > 0) {
            return;
        }
        const capabilities = [
            "crucible-autonomous-runtime",
            `harness-suite:${aggregate.contract.harnessSuiteIdentity}`,
            `parser:${aggregate.contract.parserVersion}`,
            `allowlist:${this.#allowlist.contentHash}`,
            ...(aggregate.contract.hypothesisTopology === "certified_impossibility"
                ? [
                    `impossibility-verifier:${
                        aggregate.contract.harnessSuite.roles.impossibility_verifier.harnessId
                    }`,
                ]
                : []),
            ...Object.entries(aggregate.contract.harnessSuite.roles)
                .map(([role, spec]) => `harness-role:${role}:${spec.harnessId}`),
            ...aggregate.contract.workerModels.map((model) => `model:${model}`),
        ].sort();
        const existing = aggregate.capabilityEpochs[this.#config.runnerEpochId];
        if (existing !== undefined) {
            if (canonicalJson(existing.capabilities) !== canonicalJson(capabilities)) {
                throw new RuntimeIntegrityError(
                    "runnerEpochId was already recorded with different capabilities",
                    {
                        runnerEpochId: this.#config.runnerEpochId,
                        existing: existing.capabilities,
                        current: capabilities,
                    },
                );
            }
            return;
        }
        this.#appendExternalFencedWithAttempt(
            EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
            {
                epochId: this.#config.runnerEpochId,
                capabilities,
            },
            "capability-epoch",
        );
    }

    #validateHarnessContract(contract, role = "search") {
        const frozenRole = contract.harnessSuite?.roles?.[role];
        if (frozenRole === undefined) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                `Frozen HarnessSuiteV4 role ${JSON.stringify(role)} is unavailable`,
                { role },
            );
        }
        const expectedParserVersion = role === "impossibility_verifier"
            ? VERIFIER_PARSER_VERSION
            : PARSER_VERSION;
        const currentParserIdentity =
            trustedParserIdentity(expectedParserVersion);
        if (frozenRole.parser.version !== expectedParserVersion) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                "Frozen contract parserVersion does not match the trusted measurement parser",
                {
                    role,
                    contract: frozenRole.parser.version,
                    runtime: expectedParserVersion,
                },
            );
        }
        if (!canonicalEqual(frozenRole.parser, currentParserIdentity)) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                "Frozen parser identity does not match the trusted parser bytes",
                {
                    role,
                    contract: frozenRole.parser,
                    runtime: currentParserIdentity,
                },
            );
        }
        try {
            const currentSuite = this.#allowlist.getSuite(contract.harnessSuite.id);
            const currentIdentity = this.#allowlist.getSuiteIdentity(
                contract.harnessSuite.id,
            );
            if (currentIdentity !== contract.harnessSuiteIdentity
                || !canonicalEqual(currentSuite, contract.harnessSuite)) {
                throw new RuntimeIntegrityError(
                    "Configured HarnessSuiteV4 no longer matches the frozen contract",
                    {
                        expectedIdentity: contract.harnessSuiteIdentity,
                        actualIdentity: currentIdentity,
                    },
                );
            }
            if (frozenRole.sandboxIdentity.required) {
                if (this.#sandboxIdentity?.policyDigest
                    !== frozenRole.sandboxIdentity.policyDigest) {
                    throw new RuntimeIntegrityError(
                        "Current sandbox policy does not match the frozen harness role",
                        {
                            role,
                            expected: frozenRole.sandboxIdentity.policyDigest,
                            actual: this.#sandboxIdentity?.policyDigest ?? null,
                        },
                    );
                }
                if (role === "impossibility_verifier") {
                    const securityContext =
                        this.#sandboxIdentity?.policyIdentity?.securityContext;
                    if (securityContext?.appContainer !== true
                        || securityContext?.lowIntegrity !== true
                        || !Array.isArray(securityContext.capabilities)
                        || securityContext.capabilities.length !== 0) {
                        throw new RuntimeIntegrityError(
                            "Impossibility verifier requires the frozen zero-capability AppContainer policy",
                            { role, securityContext: securityContext ?? null },
                        );
                    }
                }
            }
            const verifiedEntry = this.#allowlist.verifyEntry(frozenRole.harnessId);
            if (verifiedEntry.entryHash !== frozenRole.harnessEntryHash
                || verifiedEntry.executableHash !== frozenRole.executableHash
                || applicationEntrypointHashForEntry(verifiedEntry.entry)
                    !== frozenRole.applicationEntrypointHash) {
                throw new RuntimeIntegrityError(
                    "Verified harness role bytes do not match HarnessSuiteV4",
                    { role, harnessId: frozenRole.harnessId },
                );
            }
            return { verifiedEntry, role: frozenRole };
        } catch (error) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                `Frozen harness suite no longer matches runtime inputs: ${error?.message ?? String(error)}`,
                {
                    role,
                    harnessId: frozenRole.harnessId,
                    cause: error?.code ?? null,
                },
                { cause: error },
            );
        }
    }

    async #verifiedHarnessForMeasurement(role = "search") {
        const roleSpec = this.#contract.harnessSuite.roles[role];
        if (roleSpec?.sandboxIdentity.required) {
            const describePolicy = this.#dependencies.describeSandboxProviderPolicy
                ?? describeSandboxProviderPolicy;
            const current = await describePolicy(this.#sandboxProvider);
            if (current === null) {
                throw new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                    "Sandbox provider stopped attesting its frozen policy identity",
                );
            }
            this.#sandboxIdentity = runtimeSandboxIdentity(current);
        }
        return this.#validateHarnessContract(this.#contract, role).verifiedEntry;
    }

    #idFactory() {
        return this.#dependencies.idFactory ?? (() => randomUUID());
    }

    #nextStableId(prefix, basis = {}) {
        this.#attemptCounter += 1;
        const hex = stableHex({
            investigationId: this.#config.investigationId,
            runnerEpochId: this.#config.runnerEpochId,
            fencingToken: this.#lease?.fencingToken ?? 0,
            counter: this.#attemptCounter,
            basis,
        }).slice(0, 24);
        return `${prefix}-${this.#lease?.fencingToken ?? 0}-${this.#attemptCounter}-${hex}`.toLowerCase();
    }

    #stableAttemptId(scope, basis = {}) {
        const safeScope = String(scope).replace(/[^A-Za-z0-9._-]/gu, "-").slice(0, 32);
        const hex = stableHex({
            investigationId: this.#config.investigationId,
            runnerEpochId: this.#config.runnerEpochId,
            fencingToken: this.#lease?.fencingToken ?? 0,
            scope,
            basis,
        }).slice(0, 40);
        return `attempt-${this.#lease?.fencingToken ?? 0}-${safeScope}-${hex}`.toLowerCase();
    }

    #stableObservationId(commandId, basis = {}) {
        return `observation-${stableHex({
            investigationId: this.#config.investigationId,
            commandId,
            basis,
        }).slice(0, 48)}`;
    }

    #reserveAttempt(attemptId, command) {
        const reserved = this.#adapter.reserveAttempt({
            attemptId,
            command,
            lease: this.#lease,
        });
        this.#attemptCommands.set(attemptId, command);
        return reserved;
    }

    #attemptCommand(attemptId) {
        const command = this.#attemptCommands.get(attemptId);
        if (command === undefined) {
            throw new RuntimeIntegrityError(
                "Active attempt is missing its runner-held logical identity",
                { attemptId },
            );
        }
        return command;
    }

    #ingestOperationalEvidence(input) {
        const buffer = this.#effectEvidenceBuffers.get(input.attemptId);
        if (buffer !== undefined) {
            buffer.push(input);
            return { buffered: true };
        }
        return this.#adapter.ingestOperationalEvidenceFenced(input, {
            attemptId: input.attemptId,
            command: this.#attemptCommand(input.attemptId),
            lease: this.#lease,
            fromState: "dispatched",
        });
    }

    #recordOperationalNonResultFenced({ scope, code, reason, details }) {
        const identity = stableHex({ scope, code, reason, details });
        const attemptId = this.#stableAttemptId("operational-non-result", {
            scope,
            code,
            identity,
        });
        const command = formatAttemptCommand("operational-non-result", {
            scope,
            code,
            identity,
        });
        this.#reserveAttempt(attemptId, command);
        this.#adapter.dispatchAttempt(attemptId, this.#lease);
        this.#adapter.observeAttempt(attemptId, this.#lease);
        const result = this.#adapter.ingestOperationalEvidenceBatchFenced([{
            attemptId,
            evidenceKind: `non-result:${code}`,
            kind: "runtime:non_result",
            payload: { code, reason, details },
        }], {
            attemptId,
            command,
            lease: this.#lease,
            fromState: "observed",
            toState: "committed",
        });
        this.#attemptCommands.delete(attemptId);
        return result;
    }

    #appendDedicatedDomainEvent({
        scope,
        domainEvent,
        append,
        deadlineExempt = false,
    }) {
        const factHash = this.#adapter.domainFactIdentity(domainEvent);
        const command = formatAttemptCommand("domain-event", {
            scope,
            eventType: domainEvent.type,
            factHash,
        });
        const attemptId = this.#stableAttemptId("domain-event", {
            scope,
            eventType: domainEvent.type,
            factHash,
        });
        this.#reserveAttempt(attemptId, command);
        this.#adapter.dispatchAttempt(attemptId, this.#lease);
        this.#adapter.observeAttempt(attemptId, this.#lease);
        const result = this.#withDomainDeadlineGuard(
            `${scope} domain append`,
            () => append({
                attemptId,
                command,
                lease: this.#lease,
                expectedDomainFactHash: factHash,
            }),
            { deadlineExempt },
        );
        if (result.domainEvent === null) {
            throw new RuntimeIntegrityError(
                "Fenced domain append became a no-op after its attempt was reserved",
                { attemptId, scope, factHash },
            );
        }
        this.#attemptCommands.delete(attemptId);
        return result;
    }

    #appendKernelDecisionFenced({ deadlineExempt = false } = {}) {
        const { aggregate } = this.#adapter.replay();
        const recommendation = decideNext(aggregate);
        if (recommendation.event === null) {
            throw new RuntimeIntegrityError(
                "Kernel decision append was requested without a domain event",
                { recommendation },
            );
        }
        if (deadlineExempt
            && recommendation.event.type !== EVENT_TYPES.INVESTIGATION_PAUSED) {
            throw new RuntimeIntegrityError(
                "Only a deadline pause decision may bypass the domain deadline guard",
                { type: recommendation.event.type },
            );
        }
        return this.#appendDedicatedDomainEvent({
            scope: "kernel-decision",
            domainEvent: recommendation.event,
            append: (authority) =>
                this.#adapter.appendKernelDecisionFenced(authority),
            deadlineExempt,
        });
    }

    #resumeRecoveredDeadlinePause() {
        const { aggregate } = this.#adapter.replay();
        if (aggregate.pause === null) {
            throw new RuntimeIntegrityError(
                "Recovered deadline pause resume requires a persisted pause",
            );
        }
        const domainEvent = constructInvestigationResumedEvent(aggregate);
        return this.#appendDedicatedDomainEvent({
            scope: "deadline-recovery-resume",
            domainEvent,
            append: (authority) =>
                this.#adapter.resumeInvestigationFenced(authority),
        });
    }

    #appendExternalFencedWithAttempt(type, payload, scope) {
        const { aggregate } = this.#adapter.replay();
        const domainEvent = createExternalEvent(aggregate, type, payload);
        return this.#appendDedicatedDomainEvent({
            scope,
            domainEvent,
            append: (authority) => this.#adapter.appendExternalFenced(
                type,
                payload,
                {
                    ...authority,
                    fromState: "observed",
                    toState: "committed",
                },
            ),
        });
    }

    #requestStopFenced({ requestId, reason, pauseRequested }) {
        const { aggregate } = this.#adapter.replay();
        const domainEvent = createExternalEvent(
            aggregate,
            EVENT_TYPES.STOP_REQUESTED,
            { requestId, reason, pauseRequested },
        );
        return this.#appendDedicatedDomainEvent({
            scope: "stop-request",
            domainEvent,
            append: (authority) => this.#adapter.requestStopFenced({
                requestId,
                reason,
                pauseRequested,
                ...authority,
            }),
            deadlineExempt: true,
        });
    }

    async #fault(point, details = {}) {
        if (typeof this.#dependencies.faultInjector === "function") {
            await this.#dependencies.faultInjector(point, details);
        }
    }

    #writeRuntimeTempOwnerMarker() {
        const ownedPaths = [
            this.#runTempRoot,
            path.join(this.#runTempRoot, "sdk-home"),
            path.join(this.#runTempRoot, "sdk-work"),
            path.join(this.#runTempRoot, "windows-sandbox-control"),
            path.join(this.#runTempRoot, "submitted"),
            path.join(this.#runTempRoot, "materialized"),
        ];
        atomicWriteJson(path.join(this.#runTempRoot, RUNTIME_TEMP_OWNER_MARKER), {
            version: RUNTIME_TEMP_OWNER_VERSION,
            kind: "crucible-runtime-temp-root",
            investigationId: this.#config.investigationId,
            supervisorGeneration: this.#config.supervisorGeneration,
            supervisorNonce: this.#config.supervisorNonce,
            runnerIncarnation: this.#config.runnerIncarnation,
            runnerEpochId: this.#config.runnerEpochId,
            pid: process.pid,
            root: this.#runTempRoot,
            createdAt: this.#clock.isoNow(),
            ownedPaths,
        }, {
            token: `runtime-owner:${this.#config.supervisorGeneration ?? "none"}:${
                safeFileToken(
                    this.#config.runnerIncarnation ?? this.#config.runnerEpochId,
                ).slice(-12)
            }:${process.pid}`,
        });
    }

    #logicalEffectKey(command) {
        return hashCanonical({
            investigationId: this.#config.investigationId,
            domainCommandId: command.commandId ?? null,
            phase: command.kind ?? null,
            round: command.round ?? null,
            slotIndex: command.slotIndex ?? null,
            candidateId: command.candidateId ?? command.caseId ?? null,
            snapshotId: command.snapshot ?? null,
            scheduleHash: command.scheduleHash ?? null,
            blockIndex: command.blockIndex ?? null,
            replicateIndex: command.replicateIndex ?? null,
            armIndex: command.armIndex ?? null,
            armId: command.armId ?? null,
            deterministicSeed: command.deterministicSeed ?? null,
            subjectId: command.subjectId ?? null,
        }, LOGICAL_EFFECT_KEY_ALGORITHM);
    }

    #unresolvedExternalEffects() {
        const uncertain = Array.isArray(this.#recovery?.uncertain)
            ? this.#recovery.uncertain
            : [];
        const unresolved = [];
        const seen = new Set();
        for (const attempt of uncertain) {
            let metadata;
            try {
                metadata = JSON.parse(attempt.command);
            } catch (error) {
                throw new RuntimeIntegrityError(
                    "Recovered command-attempt metadata is not valid JSON",
                    { attemptId: attempt.attemptId },
                    { cause: error },
                );
            }
            if (metadata?.scope !== "external-effect") {
                continue;
            }
            const command = metadata.effect;
            const logicalEffectKey = metadata.logicalEffectKey;
            if (command === null
                || typeof command !== "object"
                || Array.isArray(command)
                || typeof logicalEffectKey !== "string"
                || logicalEffectKey !== this.#logicalEffectKey(command)) {
                throw new RuntimeIntegrityError(
                    "Recovered external-effect attempt has invalid logical identity",
                    {
                        attemptId: attempt.attemptId,
                        logicalEffectKey: logicalEffectKey ?? null,
                    },
                );
            }
            if (seen.has(logicalEffectKey)) {
                continue;
            }
            seen.add(logicalEffectKey);
            if (this.#readEffectRecoveryCapsule(logicalEffectKey, command) !== null) {
                continue;
            }
            unresolved.push(Object.freeze({
                attemptId: attempt.attemptId,
                previousState: attempt.previousState ?? attempt.state,
                logicalEffectKey,
                kind: command.kind ?? null,
                commandId: command.commandId ?? null,
                candidateId: command.candidateId ?? command.caseId ?? null,
            }));
        }
        return Object.freeze(unresolved);
    }

    #deadlineReached() {
        return deadlineReached(this.#config.deadlineMs, this.#clock.now());
    }

    #remainingDeadlineMs() {
        return remainingDeadlineMs(this.#config.deadlineMs, this.#clock.now());
    }

    #deadlineError(stage) {
        const error = new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED,
            `The autonomous investigation deadline expired during ${stage}`,
            {
                deadlineMs: this.#config.deadlineMs,
                observedAt: this.#clock.isoNow(),
                observedAtMs: this.#clock.now(),
                stage,
            },
        );
        error.deadlineExceeded = true;
        return error;
    }

    #isDeadlineError(error) {
        return error?.deadlineExceeded === true
            || error?.code === RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED
            || (error?.details?.deadlineExceeded === true && this.#deadlineReached());
    }

    #assertDeadlineOpen(stage) {
        if (this.#deadlineReached()) {
            throw this.#deadlineError(stage);
        }
    }

    #withDomainDeadlineGuard(stage, operation, { deadlineExempt = false } = {}) {
        if (deadlineExempt) {
            return operation();
        }
        this.#assertDeadlineOpen(stage);
        const previousStage = this.#domainDeadlineStage;
        this.#domainDeadlineGuardDepth += 1;
        this.#domainDeadlineStage = stage;
        try {
            return operation();
        } finally {
            this.#domainDeadlineGuardDepth -= 1;
            this.#domainDeadlineStage = previousStage;
        }
    }

    #takeCapturedOutput(attemptId, measurement) {
        const captured = this.#capturedOutputs.get(attemptId) ?? null;
        this.#capturedOutputs.delete(attemptId);
        const stdout = captured === null
            ? measurement?.rawStdoutBytes ?? null
            : Buffer.concat(captured.stdout);
        const stderr = captured === null
            ? measurement?.rawStderrBytes ?? null
            : Buffer.concat(captured.stderr);
        if (!Buffer.isBuffer(stdout) || !Buffer.isBuffer(stderr)) {
            return null;
        }
        if (sha256Bytes(stdout, STREAM_HASH_ALGORITHM) !== measurement.stdoutHash
            || sha256Bytes(stderr, STREAM_HASH_ALGORITHM) !== measurement.stderrHash) {
            throw new RuntimeIntegrityError(
                "Captured harness output does not match the trusted measurement receipt",
                { attemptId },
            );
        }
        if (measurement.receipt.outputCapture.stdout.retainedBytes !== stdout.length
            || measurement.receipt.outputCapture.stderr.retainedBytes !== stderr.length) {
            throw new RuntimeIntegrityError(
                "Captured harness output lengths do not match the trusted measurement receipt",
                { attemptId },
            );
        }
        return { stdout, stderr };
    }

    async #runHarnessMeasurement(input) {
        let measurement;
        let invalid = null;
        const captureInvalid = input.captureInvalid === true;
        try {
            const {
                harnessRole = "search",
                captureInvalid: _captureInvalid,
                ...measurementInput
            } = input;
            const verifiedEntry = await this.#verifiedHarnessForMeasurement(
                harnessRole,
            );
            measurement = await this.#executor.run({
                ...measurementInput,
                verifiedEntry,
                deadlineMs: this.#config.deadlineMs,
            });
        } catch (error) {
            if (error?.details?.deadlineExceeded === true || this.#deadlineReached()) {
                this.#capturedOutputs.delete(input.attemptId);
                throw this.#deadlineError("trusted harness execution");
            }
            const receipt = captureInvalid ? error?.details?.receipt ?? null : null;
            if (receipt === null) {
                this.#capturedOutputs.delete(input.attemptId);
                throw error;
            }
            measurement = {
                receipt,
                parsed: null,
                stdoutHash: receipt.stdoutHash,
                stderrHash: receipt.stderrHash,
            };
            invalid = measurementFailureMetadata(error);
        }
        await this.#fault("after_measurement_execution", {
            attemptId: input.attemptId,
        });
        this.#assertDeadlineOpen("measurement fact acceptance");
        const rawOutput = this.#takeCapturedOutput(input.attemptId, measurement);
        if (rawOutput === null) {
            throw new RuntimeIntegrityError(
                "The trusted harness completed without capturable raw output",
                { attemptId: input.attemptId },
            );
        }
        return { measurement, rawOutput, invalid };
    }

    async #runLoop() {
        const maxLoopIterations = Math.max(
            this.#config.options.maxLoopIterations,
            this.#executionLimits?.maxLoopIterations ?? 0,
        );
        for (let iteration = 0; iteration < maxLoopIterations; iteration += 1) {
            const { aggregate } = this.#adapter.replay();
            if (aggregate.terminal !== null) {
                return terminalResult(aggregate);
            }
            const operationalNonResult = this.#adapter.latestOperationalNonResult();
            if (operationalNonResult !== null) {
                return {
                    kind: "NON_RESULT",
                    code: operationalNonResult.payload.code,
                    reason: operationalNonResult.payload.reason,
                    persisted: true,
                    operationalSeq: operationalNonResult.seq,
                };
            }
            if (aggregate.pause !== null) {
                return pauseResult(aggregate);
            }
            if (aggregate.nonResults.length > 0) {
                return nonResult(aggregate);
            }
            if (this.#deadlineReached()) {
                return this.#recordDeadlineNonResult(aggregate);
            }

            const recommendation = decideNext(aggregate);
            if (recommendation.recorded === true) {
                if (recommendation.kind === "TERMINAL") {
                    return terminalResult(aggregate);
                }
                return aggregate.pause === null ? nonResult(aggregate) : pauseResult(aggregate);
            }
            if (recommendation.event !== null) {
                try {
                    const finalNonResult =
                        recommendation.kind === "NON_RESULT"
                        && recommendation.event.type === EVENT_TYPES.NON_RESULT_RECORDED;
                    if (recommendation.kind === "TERMINAL") {
                        await this.#fault("before_terminal_append", {
                            recommendation,
                        });
                    } else if (finalNonResult) {
                        await this.#fault("before_non_result_append", {
                            recommendation,
                        });
                    }
                    const appended = this.#appendKernelDecisionFenced();
                    const recoveredDeadlineStopRequestSeq =
                        appended.domainEvent?.type === EVENT_TYPES.INVESTIGATION_PAUSED
                            ? appended.domainEvent.payload?.sourceStopRequestSeq
                            : null;
                    if (this.#recoveredDeadlineStopRequestSeqs.has(
                        recoveredDeadlineStopRequestSeq,
                    )) {
                        this.#resumeRecoveredDeadlinePause();
                        this.#recoveredDeadlineStopRequestSeqs.delete(
                            recoveredDeadlineStopRequestSeq,
                        );
                    }
                    if (recommendation.kind === "TERMINAL") {
                        await this.#fault("after_terminal_append", {
                            type: appended.domainEvent?.type ?? null,
                            seq: appended.repositoryEvent?.seq ?? null,
                            eventHash: appended.repositoryEvent?.eventHash ?? null,
                        });
                    } else if (finalNonResult) {
                        await this.#fault("after_non_result_append", {
                            type: appended.domainEvent?.type ?? null,
                            seq: appended.repositoryEvent?.seq ?? null,
                            eventHash: appended.repositoryEvent?.eventHash ?? null,
                        });
                    }
                } catch (error) {
                    if (this.#isDeadlineError(error)) {
                        return this.#recordDeadlineNonResult(
                            this.#adapter.replay().aggregate,
                            error,
                        );
                    }
                    throw error;
                }
                continue;
            }
            if (recommendation.kind !== "COMMAND") {
                throw new RuntimeIntegrityError("Kernel returned an unsupported recommendation", {
                    recommendation,
                });
            }

            try {
                switch (recommendation.command.kind) {
                    case "dispatch_reserved":
                    case "await_observation":
                        await this.#executeDomainCommand(aggregate, recommendation);
                        break;
                    case "commit_evidence":
                        await this.#commitPendingEvidence(recommendation);
                        break;
                    default:
                        throw new RuntimeIntegrityError(
                            "Kernel returned an operational command the runner does not implement",
                            { command: recommendation.command },
                        );
                }
            } catch (error) {
                if (this.#isDeadlineError(error)) {
                    return this.#recordDeadlineNonResult(
                        this.#adapter.replay().aggregate,
                        error,
                    );
                }
                throw error;
            }
        }
        throw new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.CHILD_CRASH,
            "Runner exceeded maxLoopIterations without a persisted outcome",
            {
                maxLoopIterations,
                configuredMaxLoopIterations:
                    this.#config.options.maxLoopIterations,
                derivedExecutionLimits: this.#executionLimits,
            },
        );
    }

    async #executeDomainCommand(aggregate, recommendation) {
        const commandId = recommendation.commandId;
        const commandRecord = aggregate.commands[commandId];
        if (commandRecord === undefined) {
            throw new RuntimeIntegrityError("Active domain command is missing from aggregate", {
                commandId,
            });
        }
        const mainAttemptId = this.#stableAttemptId("domain-command", {
            commandId,
            command: commandRecord.command,
        });
        const mainAttemptCommand = formatAttemptCommand("domain-command", {
            commandId,
            command: commandRecord.command,
        });
        this.#reserveAttempt(mainAttemptId, mainAttemptCommand);
        await this.#fault("after_reservation", { attemptId: mainAttemptId, commandId });

        if (commandRecord.status === "reserved") {
            this.#withDomainDeadlineGuard(
                "command dispatch append",
                () => this.#adapter.appendExternalFenced(
                    EVENT_TYPES.COMMAND_DISPATCHED,
                    {
                        commandId,
                        capabilityEpochId: this.#config.runnerEpochId,
                    },
                    {
                        attemptId: mainAttemptId,
                        command: mainAttemptCommand,
                        lease: this.#lease,
                        fromState: "reserved",
                        toState: "dispatched",
                    },
                ),
            );
        } else {
            this.#adapter.dispatchAttempt(mainAttemptId, this.#lease);
        }
        await this.#fault("after_dispatch", { attemptId: mainAttemptId, commandId });

        const currentAggregate = this.#adapter.replay().aggregate;
        let observation;
        if (commandRecord.command.kind === "run_validation") {
            observation = await this.#runValidationCommand(
                currentAggregate,
                commandId,
                mainAttemptId,
            );
        } else if (commandRecord.command.kind === "search_candidate") {
            observation = await this.#runSearchCandidateCommand(
                currentAggregate,
                commandId,
                mainAttemptId,
                commandRecord.command,
            );
        } else if (commandRecord.command.kind === "run_confirmation"
            || commandRecord.command.kind === "run_challenge") {
            observation = await this.#runScientificRoleCommand(
                currentAggregate,
                commandId,
                mainAttemptId,
                commandRecord.command,
            );
        } else if (commandRecord.command.kind === "verify_impossibility") {
            observation = await this.#runImpossibilityVerificationCommand(
                currentAggregate,
                commandId,
                mainAttemptId,
                commandRecord.command,
            );
        } else {
            throw new RuntimeIntegrityError("Unsupported reserved command kind", {
                command: commandRecord.command,
            });
        }

        await this.#fault("before_domain_observation", {
            attemptId: mainAttemptId,
            commandId,
            observationId: observation.observationId,
        });
        this.#withDomainDeadlineGuard(
            "harness observation append",
            () => this.#adapter.appendHarnessObservationFenced(observation, {
                attemptId: mainAttemptId,
                command: mainAttemptCommand,
                lease: this.#lease,
            }),
        );
        await this.#fault("after_domain_observation", {
            attemptId: mainAttemptId,
            commandId,
            observationId: observation.observationId,
        });
        const afterObservation = this.#adapter.replay().aggregate;
        const commitRecommendation = decideNext(afterObservation);
        if (commitRecommendation.command?.kind !== "commit_evidence") {
            throw new RuntimeIntegrityError(
                "A harness observation was not followed by deterministic evidence commitment",
                { recommendation: commitRecommendation },
            );
        }
        await this.#fault("before_domain_evidence_append", {
            attemptId: mainAttemptId,
            commandId,
            evidenceId: commitRecommendation.command.evidenceId,
            observationId: commitRecommendation.command.observationId,
        });
        this.#withDomainDeadlineGuard(
            "evidence commitment append",
            () => this.#adapter.appendEvidenceCommitFenced({
                evidenceId: commitRecommendation.command.evidenceId,
                observationId: commitRecommendation.command.observationId,
            }, {
                attemptId: mainAttemptId,
                command: mainAttemptCommand,
                lease: this.#lease,
            }),
        );
        this.#attemptCommands.delete(mainAttemptId);
        await this.#fault("after_evidence_commit", {
            attemptId: mainAttemptId,
            commandId,
            evidenceId: commitRecommendation.command.evidenceId,
        });
    }

    async #commitPendingEvidence(recommendation) {
        const attemptId = this.#stableAttemptId("domain-evidence-commit", {
            commandId: recommendation.commandId,
            observationId: recommendation.command.observationId,
            evidenceId: recommendation.command.evidenceId,
        });
        const attemptCommand = formatAttemptCommand("domain-evidence-commit", {
            commandId: recommendation.commandId,
            observationId: recommendation.command.observationId,
            evidenceId: recommendation.command.evidenceId,
        });
        this.#reserveAttempt(attemptId, attemptCommand);
        this.#adapter.dispatchAttempt(attemptId, this.#lease);
        this.#adapter.observeAttempt(attemptId, this.#lease);
        await this.#fault("before_domain_evidence_append", {
            attemptId,
            commandId: recommendation.commandId,
            evidenceId: recommendation.command.evidenceId,
            observationId: recommendation.command.observationId,
        });
        this.#withDomainDeadlineGuard(
            "pending evidence commitment append",
            () => this.#adapter.appendEvidenceCommitFenced({
                evidenceId: recommendation.command.evidenceId,
                observationId: recommendation.command.observationId,
            }, {
                attemptId,
                command: attemptCommand,
                lease: this.#lease,
            }),
        );
        this.#attemptCommands.delete(attemptId);
        await this.#fault("after_evidence_commit", {
            commandId: recommendation.commandId,
            observationId: recommendation.command.observationId,
            evidenceId: recommendation.command.evidenceId,
        });
    }

    #effectRecoveryCapsuleArtifactId(logicalEffectKey, command) {
        const identity = hashCanonical({
            investigationId: this.#config.investigationId,
            logicalEffectKey,
            command,
        }, EFFECT_RECOVERY_CAPSULE_HASH_ALGORITHM);
        return `runtime-effect-capsule-${identity
            .slice(identity.lastIndexOf(":") + 1)
            .slice(0, 40)}`;
    }

    #persistEffectRecoveryCapsule({
        attemptId,
        command,
        logicalEffectKey,
        evidence,
    }) {
        this.#assertDeadlineOpen("effect recovery capsule persistence");
        if (!Array.isArray(evidence) || evidence.length === 0) {
            throw new RuntimeIntegrityError(
                "A recoverable external effect must persist at least one evidence record",
                { attemptId, logicalEffectKey },
            );
        }
        const normalizedEvidence = evidence.map((item, index) => {
            if (item === null
                || typeof item !== "object"
                || typeof item.evidenceKind !== "string"
                || typeof item.kind !== "string"
                || item.payload === null
                || typeof item.payload !== "object"
                || item.payload.logicalEffectKey !== logicalEffectKey) {
                throw new RuntimeIntegrityError(
                    "Effect recovery evidence is not bound to its logical effect",
                    { attemptId, logicalEffectKey, index },
                );
            }
            return {
                evidenceKind: item.evidenceKind,
                kind: item.kind,
                payload: item.payload,
            };
        });
        if (new Set(normalizedEvidence.map((item) => item.evidenceKind)).size
            !== normalizedEvidence.length) {
            throw new RuntimeIntegrityError(
                "Effect recovery evidence kinds must be unique",
                { attemptId, logicalEffectKey },
            );
        }
        const identityHash = hashCanonical({
            investigationId: this.#config.investigationId,
            logicalEffectKey,
            command,
            effectAttemptId: attemptId,
            evidence: normalizedEvidence,
        }, EFFECT_RECOVERY_CAPSULE_HASH_ALGORITHM);
        const capsule = {
            version: EFFECT_RECOVERY_CAPSULE_VERSION,
            kind: "crucible-runtime-effect-recovery",
            investigationId: this.#config.investigationId,
            logicalEffectKey,
            command,
            effectAttemptId: attemptId,
            identityHash,
            evidence: normalizedEvidence,
        };
        const bytes = Buffer.from(canonicalJson(capsule), "utf8");
        const expectedObjectId = `sha256:${sha256Hex(bytes)}`;
        this.#reserveCasBytes(
            attemptId,
            bytes.length,
            expectedObjectId,
            "effect-recovery-capsule",
        );
        const stored = this.#artifactStore.putBytes(bytes, {
            contentType: "application/vnd.crucible.effect-recovery+json",
        });
        if (stored.id !== expectedObjectId || stored.size !== bytes.length) {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule CAS identity changed during persistence",
                {
                    expectedObjectId,
                    actualObjectId: stored.id,
                    expectedSize: bytes.length,
                    actualSize: stored.size,
                },
            );
        }
        const artifactId = this.#effectRecoveryCapsuleArtifactId(
            logicalEffectKey,
            command,
        );
        const existing = this.#repository.getArtifact(artifactId);
        if (existing === null) {
            this.#repository.registerExternalArtifact({
                investigationId: this.#config.investigationId,
                artifactId,
                algo: "sha256",
                hash: snapshotObjectHex(stored.id),
                sizeBytes: stored.size,
                contentType: "application/vnd.crucible.effect-recovery+json",
            });
            this.#repository.markArtifactDurable(artifactId);
        } else if (existing.investigationId !== this.#config.investigationId
            || existing.storage !== "external"
            || existing.hashAlgo !== "sha256"
            || existing.hashValue !== snapshotObjectHex(stored.id)
            || existing.sizeBytes !== stored.size
            || existing.contentType !== "application/vnd.crucible.effect-recovery+json") {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule artifact id collision",
                { artifactId, logicalEffectKey },
            );
        } else if (existing.durable !== true) {
            this.#artifactStore.readObject(stored.id, { verify: true });
            this.#repository.markArtifactDurable(artifactId);
        }
        const verified = this.#artifactStore.readObject(stored.id, { verify: true });
        if (!verified.equals(bytes)) {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule changed during persistence",
                { artifactId, logicalEffectKey },
            );
        }
        this.#assertDeadlineOpen("effect recovery capsule persistence");
        return { artifactId, objectId: stored.id, capsule };
    }

    #readEffectRecoveryCapsule(logicalEffectKey, command) {
        const artifactId = this.#effectRecoveryCapsuleArtifactId(
            logicalEffectKey,
            command,
        );
        const metadata = this.#repository.getArtifact(artifactId);
        if (metadata === null) return null;
        if (metadata.investigationId !== this.#config.investigationId
            || metadata.storage !== "external"
            || metadata.durable !== true
            || metadata.hashAlgo !== "sha256"
            || typeof metadata.hashValue !== "string"
            || metadata.contentType !== "application/vnd.crucible.effect-recovery+json") {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule metadata is not durable and canonical",
                { artifactId, logicalEffectKey },
            );
        }
        const objectId = `sha256:${metadata.hashValue}`;
        let bytes;
        try {
            bytes = this.#artifactStore.readObject(objectId, { verify: true });
        } catch (error) {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule failed ArtifactStore verification",
                { artifactId, logicalEffectKey, objectId },
                { cause: error },
            );
        }
        if (bytes.length !== metadata.sizeBytes) {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule size disagrees with repository metadata",
                { artifactId, logicalEffectKey },
            );
        }
        let capsule;
        try {
            capsule = JSON.parse(bytes.toString("utf8"));
        } catch (error) {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule is not valid JSON",
                { artifactId, logicalEffectKey },
                { cause: error },
            );
        }
        if (!Buffer.from(canonicalJson(capsule), "utf8").equals(bytes)
            || capsule?.version !== EFFECT_RECOVERY_CAPSULE_VERSION
            || capsule.kind !== "crucible-runtime-effect-recovery"
            || capsule.investigationId !== this.#config.investigationId
            || capsule.logicalEffectKey !== logicalEffectKey
            || !canonicalEqual(capsule.command, command)
            || typeof capsule.effectAttemptId !== "string"
            || !Array.isArray(capsule.evidence)
            || capsule.evidence.length === 0) {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule is malformed or bound to another effect",
                { artifactId, logicalEffectKey },
            );
        }
        const expectedIdentityHash = hashCanonical({
            investigationId: this.#config.investigationId,
            logicalEffectKey,
            command,
            effectAttemptId: capsule.effectAttemptId,
            evidence: capsule.evidence,
        }, EFFECT_RECOVERY_CAPSULE_HASH_ALGORITHM);
        if (capsule.identityHash !== expectedIdentityHash
            || new Set(capsule.evidence.map((item) => item?.evidenceKind)).size
                !== capsule.evidence.length
            || capsule.evidence.some((item) =>
                item === null
                || typeof item !== "object"
                || typeof item.evidenceKind !== "string"
                || typeof item.kind !== "string"
                || item.payload?.logicalEffectKey !== logicalEffectKey)) {
            throw new RuntimeIntegrityError(
                "Effect recovery capsule identity or evidence binding is invalid",
                { artifactId, logicalEffectKey },
            );
        }
        return { artifactId, objectId, capsule };
    }

    async #recoverPersistedEffectCapsule({
        capsuleRecord,
        command,
        logicalEffectKey,
        recover,
    }) {
        const synthetic = {
            attempt: {
                attemptId: capsuleRecord.capsule.effectAttemptId,
                state: "committed",
            },
            events: capsuleRecord.capsule.evidence.map((item, index) => ({
                ...item,
                seq: index + 1,
                attemptId: capsuleRecord.capsule.effectAttemptId,
            })),
            effectAttemptId: capsuleRecord.capsule.effectAttemptId,
        };
        const recovered = await recover(synthetic, logicalEffectKey);
        if (recovered === null
            || typeof recovered !== "object"
            || !Object.hasOwn(recovered, "result")
            || !Object.hasOwn(recovered, "persisted")) {
            throw new RuntimeIntegrityError(
                "Persisted effect recovery did not reproduce a canonical outcome",
                { logicalEffectKey, command },
            );
        }
        this.#assertDeadlineOpen("persisted effect recovery");
        const recoveryAttemptId = this.#stableAttemptId("effect-recovery", {
            logicalEffectKey,
            effectAttemptId: capsuleRecord.capsule.effectAttemptId,
        });
        const attemptCommand = formatAttemptCommand("external-effect", {
            logicalEffectKey,
            effect: command,
            recoveredFromAttemptId: capsuleRecord.capsule.effectAttemptId,
            recoveryCapsuleArtifactId: capsuleRecord.artifactId,
        });
        this.#reserveAttempt(recoveryAttemptId, attemptCommand);
        this.#adapter.dispatchAttempt(recoveryAttemptId, this.#lease);
        this.#adapter.observeAttempt(recoveryAttemptId, this.#lease);
        this.#adapter.ingestOperationalEvidenceBatchFenced(
            capsuleRecord.capsule.evidence,
            {
                attemptId: recoveryAttemptId,
                command: attemptCommand,
                lease: this.#lease,
                fromState: "observed",
                toState: "committed",
            },
        );
        this.#attemptCommands.delete(recoveryAttemptId);
        await this.#fault("after_effect_commit", {
            attemptId: recoveryAttemptId,
            effectAttemptId: capsuleRecord.capsule.effectAttemptId,
            command,
            logicalEffectKey,
            recoveredFromCapsule: true,
        });
        return {
            attemptId: capsuleRecord.capsule.effectAttemptId,
            result: recovered.result,
            persisted: recovered.persisted,
            logicalEffectKey,
            recovered: true,
            recoveredFromCapsule: true,
        };
    }

    #assertEffectLaunchAllowed(command) {
        const { aggregate } = this.#adapter.replay();
        if (aggregate.pause === null) {
            const stopRequest = latestUnhandledStopRequest(aggregate);
            const admittedCommand = command?.commandId === undefined
                ? null
                : aggregate.commands[command.commandId] ?? null;
            if (stopRequest === null
                || (admittedCommand !== null
                    && admittedCommand.reservedSeq < stopRequest.seq)) {
                return;
            }
        }
        const error = new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.PAUSED,
            "Persisted stop/pause authority forbids launching a new external effect",
            {
                commandKind: command?.kind ?? null,
                commandId: command?.commandId ?? null,
                paused: aggregate.pause !== null,
                stopRequestSeq:
                    latestUnhandledStopRequest(aggregate)?.seq ?? null,
            },
        );
        error.pauseBarrier = true;
        throw error;
    }

    async #executeEffect(command, operation, persist = null, recover = null) {
        this.#effectAttemptCount += 1;
        if (this.#executionLimits !== null
            && this.#effectAttemptCount > this.#executionLimits.maxExternalEffects) {
            throw new RuntimeIntegrityError(
                "Runner exceeded the frozen-contract external-effect budget",
                {
                    effectAttemptCount: this.#effectAttemptCount,
                    executionLimits: this.#executionLimits,
                    command,
                },
            );
        }
        const logicalEffectKey = this.#logicalEffectKey(command);
        const committed = this.#findCommittedEffect(logicalEffectKey, command);
        if (committed !== null) {
            if (recover === null) {
                throw new RuntimeIntegrityError(
                    "A committed logical effect exists but no recovery decoder was provided",
                    { logicalEffectKey, command },
                );
            }
            const recovered = await recover(committed, logicalEffectKey);
            if (recovered === null
                || typeof recovered !== "object"
                || !Object.hasOwn(recovered, "result")
                || !Object.hasOwn(recovered, "persisted")) {
                throw new RuntimeIntegrityError(
                    "Recovery decoder did not return canonical result and persistence state",
                    { logicalEffectKey, command },
                );
            }
            return {
                attemptId: committed.effectAttemptId,
                result: recovered.result,
                persisted: recovered.persisted,
                logicalEffectKey,
                recovered: true,
            };
        }
        const capsuleRecord = this.#readEffectRecoveryCapsule(
            logicalEffectKey,
            command,
        );
        if (capsuleRecord !== null) {
            if (recover === null) {
                throw new RuntimeIntegrityError(
                    "A persisted logical effect exists but no recovery decoder was provided",
                    { logicalEffectKey, command },
                );
            }
            return this.#recoverPersistedEffectCapsule({
                capsuleRecord,
                command,
                logicalEffectKey,
                recover,
            });
        }
        this.#assertEffectLaunchAllowed(command);
        const attemptId = this.#stableAttemptId("external-effect", command);
        const attemptCommand = formatAttemptCommand("external-effect", {
            logicalEffectKey,
            effect: command,
        });
        this.#reserveAttempt(attemptId, attemptCommand);
        await this.#fault("after_effect_reservation", {
            attemptId,
            command,
            logicalEffectKey,
        });
        this.#adapter.dispatchAttempt(attemptId, this.#lease);
        await this.#fault("after_effect_dispatch", {
            attemptId,
            command,
            logicalEffectKey,
        });

        let result;
        try {
            this.#assertEffectLaunchAllowed(command);
            result = await operation(attemptId);
            await this.#fault("after_effect_operation", {
                attemptId,
                command,
                logicalEffectKey,
            });
            this.#assertDeadlineOpen("external effect output acceptance");
        } catch (error) {
            if (error?.leaveAttemptActive === true) {
                throw error;
            }
            const deadlineFailure = this.#isDeadlineError(error);
            this.#adapter.observeAttempt(attemptId, this.#lease);
            this.#adapter.ingestOperationalEvidenceBatchFenced([{
                attemptId,
                evidenceKind: "effect-failure",
                kind: "runtime:effect_failure",
                payload: {
                    command,
                    logicalEffectKey,
                    classification: deadlineFailure
                        ? "deadline_expired"
                        : error?.pauseBarrier === true
                            ? "pause_barrier"
                            : "effect_error",
                    deadlineMs: deadlineFailure
                        ? this.#config.deadlineMs
                        : null,
                    error: {
                        name: error?.name ?? "Error",
                        code: error?.code ?? null,
                        message: error?.message ?? String(error),
                        details: error?.details ?? null,
                    },
                },
            }], {
                attemptId,
                command: attemptCommand,
                lease: this.#lease,
                fromState: "observed",
                toState: "committed",
            });
            this.#attemptCommands.delete(attemptId);
            throw error;
        }

        this.#adapter.observeAttempt(attemptId, this.#lease);
        this.#effectEvidenceBuffers.set(attemptId, []);
        let persisted;
        try {
            persisted = persist === null
                ? null
                : await persist(result, attemptId, logicalEffectKey);
            const evidence = this.#effectEvidenceBuffers.get(attemptId);
            this.#assertDeadlineOpen("effect artifact persistence");
            this.#persistEffectRecoveryCapsule({
                attemptId,
                command,
                logicalEffectKey,
                evidence,
            });
            await this.#fault("after_effect_artifact_persistence", {
                attemptId,
                command,
                logicalEffectKey,
            });
            this.#assertDeadlineOpen("effect commitment");
            if (evidence.length === 0) {
                this.#adapter.commitAttempt(attemptId, this.#lease);
            } else {
                this.#adapter.ingestOperationalEvidenceBatchFenced(evidence, {
                    attemptId,
                    command: attemptCommand,
                    lease: this.#lease,
                    fromState: "observed",
                    toState: "committed",
                });
            }
        } finally {
            this.#effectEvidenceBuffers.delete(attemptId);
        }
        this.#attemptCommands.delete(attemptId);
        await this.#fault("after_effect_commit", {
            attemptId,
            command,
            logicalEffectKey,
        });
        return {
            attemptId,
            result,
            persisted,
            logicalEffectKey,
            recovered: false,
        };
    }

    #findCommittedEffect(logicalEffectKey, command) {
        const committed = [];
        for (const attempt of this.#adapter.listAttempts()) {
            let metadata;
            try {
                metadata = JSON.parse(attempt.command);
            } catch (error) {
                throw new RuntimeIntegrityError(
                    "Command-attempt metadata is not valid canonical JSON",
                    { attemptId: attempt.attemptId },
                    { cause: error },
                );
            }
            if (metadata?.scope !== "external-effect"
                || metadata.logicalEffectKey !== logicalEffectKey) {
                continue;
            }
            if (!canonicalEqual(metadata.effect, command)) {
                throw new RuntimeIntegrityError(
                    "Logical effect key is bound to different attempt metadata",
                    {
                        logicalEffectKey,
                        attemptId: attempt.attemptId,
                        expected: command,
                        actual: metadata.effect ?? null,
                    },
                );
            }
            if (attempt.state === "committed") {
                committed.push(attempt);
            }
        }
        if (committed.length === 0) {
            return null;
        }
        const operationalEvents = this.#adapter.listOperationalEvidence();
        const successful = [];
        for (const attempt of committed) {
            const events = operationalEvents.filter((event) =>
                event.attemptId === attempt.attemptId
                && event.payload?.logicalEffectKey === logicalEffectKey);
            const failure = events.find((event) =>
                event.kind === "runtime:effect_failure");
            if (failure === undefined) {
                successful.push({ attempt, events });
                continue;
            }
            const classification = failure.payload?.classification ?? null;
            const previousDeadlineMs = failure.payload?.deadlineMs ?? null;
            const laterDeadline = Number.isFinite(previousDeadlineMs)
                && (this.#config.deadlineMs === null
                    || this.#config.deadlineMs > previousDeadlineMs);
            if ((classification === "deadline_expired" && laterDeadline)
                || classification === "pause_barrier") {
                continue;
            }
            throw new CrucibleRuntimeError(
                classification === "deadline_expired"
                    ? RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED
                    : RUNTIME_ERROR_CODES.CHILD_CRASH,
                classification === "deadline_expired"
                    ? "A previously committed logical effect expired under the current deadline"
                    : "A previously committed logical effect recorded a failure",
                {
                    logicalEffectKey,
                    attemptId: attempt.attemptId,
                    classification,
                    previousDeadlineMs,
                    currentDeadlineMs: this.#config.deadlineMs,
                    persistedError: failure.payload?.error ?? null,
                },
            );
        }
        if (successful.length > 1) {
            throw new RuntimeIntegrityError(
                "More than one successful committed attempt exists for one logical effect",
                {
                    logicalEffectKey,
                    attemptIds: successful.map(({ attempt }) => attempt.attemptId),
                },
            );
        }
        if (successful.length === 0) {
            return null;
        }
        const { attempt, events } = successful[0];
        let effectAttemptId = attempt.attemptId;
        let metadata;
        try {
            metadata = JSON.parse(attempt.command);
        } catch (error) {
            throw new RuntimeIntegrityError(
                "Committed effect command metadata is not valid JSON",
                { attemptId: attempt.attemptId },
                { cause: error },
            );
        }
        if (metadata.recoveredFromAttemptId !== undefined) {
            if (typeof metadata.recoveredFromAttemptId !== "string"
                || metadata.recoveredFromAttemptId.length === 0) {
                throw new RuntimeIntegrityError(
                    "Recovered effect metadata has an invalid source attempt id",
                    { attemptId: attempt.attemptId, logicalEffectKey },
                );
            }
            effectAttemptId = metadata.recoveredFromAttemptId;
        }
        return { attempt, events, effectAttemptId };
    }

    #requireRecoveredEffectEvent(committed, kind, logicalEffectKey) {
        const matches = committed.events.filter((event) => event.kind === kind);
        if (matches.length !== 1) {
            throw new RuntimeIntegrityError(
                "Committed logical effect does not have exactly one recoverable evidence record",
                {
                    logicalEffectKey,
                    attemptId: committed.attempt.attemptId,
                    kind,
                    count: matches.length,
                },
            );
        }
        return matches[0];
    }

    #readRegisteredJsonArtifact(artifactId, label) {
        const bytes = this.#readRegisteredBytesArtifact(artifactId, label);
        let value;
        try {
            value = JSON.parse(bytes.toString("utf8"));
        } catch (error) {
            throw new RuntimeIntegrityError(
                `${label} artifact is not valid JSON`,
                { artifactId },
                { cause: error },
            );
        }
        if (!Buffer.from(canonicalJson(value), "utf8").equals(bytes)) {
            throw new RuntimeIntegrityError(
                `${label} artifact is not in canonical persisted form`,
                { artifactId },
            );
        }
        return value;
    }

    #registeredArtifactRef(artifactId, label) {
        const artifact = this.#repository.getArtifact(artifactId);
        if (artifact === null
            || artifact.investigationId !== this.#config.investigationId
            || artifact.storage !== "external"
            || artifact.durable !== true
            || artifact.hashAlgo !== "sha256"
            || typeof artifact.hashValue !== "string") {
            throw new RuntimeIntegrityError(
                `${label} artifact metadata is missing or not durable`,
                { artifactId },
            );
        }
        const objectId = `sha256:${artifact.hashValue}`;
        return {
            artifact: {
                artifactId,
                objectId,
            },
            metadata: artifact,
        };
    }

    #readRegisteredBytesArtifact(artifactId, label) {
        const registered = this.#registeredArtifactRef(artifactId, label);
        const { artifact, metadata } = registered;
        const objectId = artifact.objectId;
        let bytes;
        try {
            bytes = this.#artifactStore.readObject(objectId, { verify: true });
        } catch (error) {
            throw new RuntimeIntegrityError(
                `${label} artifact failed ArtifactStore verification`,
                { artifactId, objectId },
                { cause: error },
            );
        }
        if (metadata.sizeBytes !== bytes.length) {
            throw new RuntimeIntegrityError(
                `${label} artifact size disagrees with repository metadata`,
                {
                    artifactId,
                    expectedSize: metadata.sizeBytes,
                    actualSize: bytes.length,
                },
            );
        }
        return bytes;
    }

    #recoverProposalEffect({
        committed,
        logicalEffectKey,
        request,
        commandId,
        assignment,
    }) {
        const event = this.#requireRecoveredEffectEvent(
            committed,
            "runtime:model_proposal",
            logicalEffectKey,
        );
        const payload = event.payload;
        if (payload.commandId !== commandId
            || payload.round !== assignment.round
            || payload.slotIndex !== assignment.slotIndex
            || payload.candidateId !== assignment.candidateId
            || payload.model !== assignment.model
            || payload.operator !== assignment.operator
            || payload.seed !== assignment.seed
            || payload.promptContextHash !== request.promptContextHash
            || (request.enumerandBindingHash !== undefined
                && payload.enumerandBindingHash
                    !== request.enumerandBindingHash)
            || !canonicalEqual(payload.parentEvidenceIds, assignment.parentEvidenceIds)
            || !canonicalEqual(payload.promptContextRefs, assignment.promptContextRefs)) {
            throw new RuntimeIntegrityError(
                "Committed proposal evidence does not match the reserved search assignment",
                { logicalEffectKey, attemptId: committed.attempt.attemptId },
            );
        }
        const value = this.#readRegisteredJsonArtifact(
            payload.artifactId,
            "Committed proposal",
        );
        if (!canonicalEqual(value.assignment, request.promptContext.assignment)
            || !canonicalEqual(value.promptContext, request.promptContext)
            || value.promptContextHash !== request.promptContextHash) {
            throw new RuntimeIntegrityError(
                "Committed proposal artifact does not match the trusted prompt context",
                { logicalEffectKey, artifactId: payload.artifactId },
            );
        }
        const proposal = value.proposal;
        if (!canonicalEqual(payload.identity, proposal?.identity ?? null)) {
            throw new RuntimeIntegrityError(
                "Committed proposal artifact contains an invalid candidate",
                { logicalEffectKey, artifactId: payload.artifactId },
            );
        }
        let validatedProposal;
        try {
            validatedProposal = validateWorkerProposal(proposal, request, {
                limits: this.#config.options.candidateLimits,
            });
        } catch (error) {
            throw new RuntimeIntegrityError(
                "Committed proposal failed the runner trust-boundary protocol",
                {
                    logicalEffectKey,
                    artifactId: payload.artifactId,
                    cause: error?.code ?? null,
                },
                { cause: error },
            );
        }
        const proposalArtifact = this.#registeredArtifactRef(
            payload.artifactId,
            "Committed proposal",
        ).artifact;
        return {
            result: validatedProposal,
            persisted: {
                proposalArtifact,
                promptContextHash: request.promptContextHash,
            },
        };
    }

    #recoverMeasurementEffect({
        committed,
        logicalEffectKey,
        aggregate,
        purpose,
        commandId,
        round = null,
        slotIndex = null,
        candidateId,
        measurementSubjectId = candidateId,
        snapshotId,
        replication = null,
        harnessRole: requestedHarnessRole = null,
        measurementPhase = null,
    }) {
        const harnessRole = requestedHarnessRole ?? (purpose === "validation"
            ? "calibration"
            : purpose === "impossibility"
                ? "impossibility_verifier"
                : "search");
        const expectedParserVersion =
            aggregate.contract.harnessSuite.roles[harnessRole].parser.version;
        const event = this.#requireRecoveredEffectEvent(
            committed,
            "runtime:measurement",
            logicalEffectKey,
        );
        const payload = event.payload;
        const candidateArtifactHash = measurementSnapshotHash(snapshotId);
        if (payload.purpose !== purpose
            || payload.commandId !== commandId
            || payload.round !== round
            || payload.slotIndex !== slotIndex
            || payload.candidateId !== candidateId
            || payload.measurementSubjectId !== measurementSubjectId
            || payload.snapshotId !== snapshotId
            || payload.candidateArtifactHash !== candidateArtifactHash
            || (payload.harnessRole ?? harnessRole) !== harnessRole
            || (payload.measurementPhase ?? (
                purpose === "validation" ? "calibration" : "search"
            )) !== (measurementPhase ?? (
                purpose === "validation" ? "calibration" : "search"
            ))
            || payload.receipt?.attemptId !== committed.effectAttemptId
            || !receiptHasVerifiedSnapshotBytes(
                payload.receipt,
                candidateArtifactHash,
                { requireCompleteOutput: payload.invalid === null },
            )
            || payload.receipt?.parserVersion !== expectedParserVersion
            || payload.stdoutHash !== payload.receipt?.stdoutHash
            || payload.stderrHash !== payload.receipt?.stderrHash
            || hashReceipt(payload.receipt) !== payload.receiptHash) {
            throw new RuntimeIntegrityError(
                "Committed measurement evidence does not match its logical effect",
                { logicalEffectKey, attemptId: committed.attempt.attemptId },
            );
        }
        if (!canonicalEqual(payload.replication, replication)) {
            throw new RuntimeIntegrityError(
                "Committed measurement replication binding changed",
                { logicalEffectKey, attemptId: committed.attempt.attemptId },
            );
        }
        if (replication !== null) {
            const expectedBinding = {
                role: harnessRole,
                phase: measurementPhase ?? (purpose === "validation"
                    ? "calibration"
                    : "search"),
                replicateIndex: replication.replicateIndex,
                blockIndex: replication.blockIndex,
                armIndex: replication.armIndex,
                armId: replication.armId,
                deterministicSeed: replication.deterministicSeed,
                subjectId: replication.subjectId,
                environmentIdentity:
                    aggregate.contract.harnessSuite.environmentIdentity,
                suiteIdentity: aggregate.contract.harnessSuiteIdentity,
            };
            const actualBinding = Object.fromEntries(
                Object.keys(expectedBinding).map((key) => [
                    key,
                    payload.receipt?.[key] ?? null,
                ]),
            );
            if (!canonicalEqual(actualBinding, expectedBinding)) {
                throw new RuntimeIntegrityError(
                    "Committed measurement receipt changed its replicate binding",
                    { logicalEffectKey, attemptId: committed.attempt.attemptId },
                );
            }
        }
        const snapshotStatus = this.#artifactStore.verifySnapshot(snapshotId);
        if (!snapshotStatus.ok) {
            throw new RuntimeIntegrityError(
                "Committed measurement snapshot failed ArtifactStore verification",
                { logicalEffectKey, snapshotId, snapshotStatus },
            );
        }
        const verifiedEntry = this.#validateHarnessContract(
            aggregate.contract,
            harnessRole,
        ).verifiedEntry;
        const expectedDependencies = verifiedEntry.dependencies
            .map((dependency) => ({
                path: dependency.path,
                role: dependency.role,
                sha256: dependency.sha256,
            }))
            .sort((left, right) => left.path.localeCompare(right.path));
        if (payload.receipt.allowlistFileHash !== verifiedEntry.allowlistFileHash
            || payload.receipt.harnessEntryHash !== verifiedEntry.entryHash
            || payload.receipt.executableHash !== verifiedEntry.executableHash
            || !canonicalEqual(payload.receipt.dependencyHashes, expectedDependencies)) {
            throw new RuntimeIntegrityError(
                "Committed measurement receipt no longer matches the verified harness",
                { logicalEffectKey, attemptId: committed.attempt.attemptId },
            );
        }
        const persistedReceipt = this.#readRegisteredJsonArtifact(
            payload.receiptArtifactId,
            "Committed measurement receipt",
        );
        if (!canonicalEqual(persistedReceipt, payload.receipt)
            || !canonicalEqual(payload.parsed, payload.receipt.parsed)) {
            throw new RuntimeIntegrityError(
                "Committed measurement receipt artifact disagrees with operational evidence",
                {
                    logicalEffectKey,
                    attemptId: committed.attempt.attemptId,
                    artifactId: payload.receiptArtifactId,
                },
            );
        }
        const rawStdoutBytes = this.#readRegisteredBytesArtifact(
            payload.rawStdoutArtifactId,
            "Committed measurement stdout",
        );
        const rawStderrBytes = this.#readRegisteredBytesArtifact(
            payload.rawStderrArtifactId,
            "Committed measurement stderr",
        );
        if (sha256Bytes(rawStdoutBytes, STREAM_HASH_ALGORITHM) !== payload.stdoutHash
            || sha256Bytes(rawStderrBytes, STREAM_HASH_ALGORITHM) !== payload.stderrHash) {
            throw new RuntimeIntegrityError(
                "Committed raw-output artifacts disagree with the measurement receipt",
                { logicalEffectKey, attemptId: committed.attempt.attemptId },
            );
        }
        const receiptArtifact = this.#registeredArtifactRef(
            payload.receiptArtifactId,
            "Committed measurement receipt",
        ).artifact;
        const rawStdoutArtifact = this.#registeredArtifactRef(
            payload.rawStdoutArtifactId,
            "Committed measurement stdout",
        ).artifact;
        const rawStderrArtifact = this.#registeredArtifactRef(
            payload.rawStderrArtifactId,
            "Committed measurement stderr",
        ).artifact;
        const snapshot = this.#verifySnapshotProvenance(
            payload.measurementProvenance?.snapshot,
            snapshotId,
            "Committed measurement snapshot",
        );
        const measurementProvenance = createMeasurementProvenance({
            subjectId: measurementSubjectId,
            role: payload.receipt.role ?? harnessRole,
            phase: payload.receipt.phase ?? measurementPhase,
            receiptArtifact,
            receiptHash: payload.receiptHash,
            rawStdoutArtifact,
            rawStdoutHash: payload.stdoutHash,
            rawStderrArtifact,
            rawStderrHash: payload.stderrHash,
            parserVersion: payload.receipt.parserVersion,
            allowlistFileHash: payload.receipt.allowlistFileHash,
            harnessEntryHash: payload.receipt.harnessEntryHash,
            executableHash: payload.receipt.executableHash,
            stagedExecutableHash: payload.receipt.stagedExecutableHash,
            dependencyHashes: payload.receipt.dependencyHashes,
            stagedDependencyHashes: payload.receipt.stagedDependencyHashes,
            argvHash: payload.receipt.argvHash,
            envHash: payload.receipt.envHash,
            sandboxPolicy: payload.receipt.sandbox === null
                ? {
                    kind: "none",
                    sandboxId: null,
                    environmentHash: null,
                }
                : {
                    kind: "sandbox",
                    sandboxId: payload.receipt.sandbox.sandboxId,
                    environmentHash: payload.receipt.sandbox.environmentHash,
                },
            snapshot,
            snapshotExecutionHash: snapshotExecutionHash(payload.receipt),
        });
        if (!canonicalEqual(payload.measurementProvenance, measurementProvenance)) {
            throw new RuntimeIntegrityError(
                "Committed measurement provenance does not reproduce its artifact closure",
                { logicalEffectKey, attemptId: committed.attempt.attemptId },
            );
        }
        const measurement = {
            parsed: payload.parsed,
            receipt: payload.receipt,
            stdoutHash: payload.stdoutHash,
            stderrHash: payload.stderrHash,
        };
        return {
            measurement,
            invalid: payload.invalid,
            rawOutput: {
                stdout: rawStdoutBytes,
                stderr: rawStderrBytes,
            },
            persisted: {
                measurementProvenance,
            },
        };
    }

    #verifySnapshotProvenance(snapshotProvenance, snapshotId, label) {
        const snapshotStatus = this.#artifactStore.verifySnapshot(snapshotId);
        if (!snapshotStatus.ok) {
            throw new RuntimeIntegrityError(
                `${label} failed ArtifactStore verification`,
                { snapshotId, snapshotStatus },
            );
        }
        const manifest = this.#artifactStore.loadManifest(snapshotId);
        if (snapshotProvenance?.manifestArtifact?.objectId !== snapshotId) {
            throw new RuntimeIntegrityError(
                `${label} manifest artifact does not match its snapshot id`,
                { snapshotId },
            );
        }
        const registeredManifest = this.#registeredArtifactRef(
            snapshotProvenance.manifestArtifact.artifactId,
            `${label} manifest`,
        );
        const manifestArtifact = registeredManifest.artifact;
        const manifestBytes = this.#artifactStore.readObject(snapshotId, { verify: true });
        if (registeredManifest.metadata.sizeBytes !== manifestBytes.length) {
            throw new RuntimeIntegrityError(
                `${label} manifest size disagrees with repository metadata`,
                {
                    artifactId: manifestArtifact.artifactId,
                    expectedSize: registeredManifest.metadata.sizeBytes,
                    actualSize: manifestBytes.length,
                },
            );
        }
        const expectedObjects = [...new Set(manifest.entries.map((entry) => entry.object))]
            .sort(compareStable);
        const expectedSizes = new Map(
            manifest.entries.map((entry) => [entry.object, entry.size]),
        );
        const suppliedObjects = (snapshotProvenance.objectArtifacts ?? [])
            .map((artifact) => artifact.objectId)
            .sort(compareStable);
        if (!canonicalEqual(suppliedObjects, expectedObjects)) {
            throw new RuntimeIntegrityError(
                `${label} object artifact set does not match the canonical manifest closure`,
                { snapshotId, suppliedObjects, expectedObjects },
            );
        }
        const objectArtifacts = snapshotProvenance.objectArtifacts.map((artifact, index) => {
            const registeredRecord = this.#registeredArtifactRef(
                artifact.artifactId,
                `${label} object ${index}`,
            );
            const registered = registeredRecord.artifact;
            if (registered.objectId !== artifact.objectId) {
                throw new RuntimeIntegrityError(
                    `${label} object artifact metadata changed`,
                    { artifactId: artifact.artifactId },
                );
            }
            const bytes = this.#artifactStore.readObject(registered.objectId, { verify: true });
            if (registeredRecord.metadata.sizeBytes !== bytes.length
                || expectedSizes.get(registered.objectId) !== bytes.length) {
                throw new RuntimeIntegrityError(
                    `${label} object size disagrees with repository or manifest metadata`,
                    {
                        artifactId: artifact.artifactId,
                        objectId: registered.objectId,
                        repositorySize: registeredRecord.metadata.sizeBytes,
                        manifestSize: expectedSizes.get(registered.objectId) ?? null,
                        actualSize: bytes.length,
                    },
                );
            }
            return registered;
        });
        const rebuilt = createSnapshotProvenance({
            snapshotHash: measurementSnapshotHash(snapshotId),
            manifestArtifact,
            objectArtifacts,
        });
        if (!canonicalEqual(snapshotProvenance, rebuilt)) {
            throw new RuntimeIntegrityError(
                `${label} provenance root is not canonical`,
                { snapshotId },
            );
        }
        return rebuilt;
    }

    #recoverImpossibilityVerification({
        committed,
        logicalEffectKey,
        aggregate,
        commandId,
        command,
        snapshotId,
    }) {
        const recoveredMeasurement = this.#recoverMeasurementEffect({
            committed,
            logicalEffectKey,
            aggregate,
            purpose: "impossibility",
            commandId,
            candidateId: `impossibility-${command.attemptOrdinal}`,
            snapshotId,
            harnessRole: "impossibility_verifier",
            measurementPhase: "impossibility_verification",
        });
        const measurement = recoveredMeasurement.measurement;
        const measurementEvent = this.#requireRecoveredEffectEvent(
            committed,
            "runtime:measurement",
            logicalEffectKey,
        );
        const certificateEvent = this.#requireRecoveredEffectEvent(
            committed,
            "runtime:impossibility_certificate",
            logicalEffectKey,
        );
        const payload = certificateEvent.payload;
        if (payload.commandId !== commandId
            || payload.attemptOrdinal !== command.attemptOrdinal
            || payload.requestHash !== command.requestHash
            || payload.proposedCertificateArtifactHash
                !== command.proposedCertificateArtifactHash
            || payload.proofArtifactHash !== command.proofArtifactHash
            || payload.objectManifestRoot
                !== command.request.objectManifest.root
            || payload.snapshotId !== snapshotId
            || payload.verificationSnapshotHash !== measurementSnapshotHash(snapshotId)
            || payload.measurementReceiptArtifactId
                !== measurementEvent.payload.receiptArtifactId
            || payload.rawStdoutArtifactId
                !== measurementEvent.payload.rawStdoutArtifactId
            || payload.rawStderrArtifactId
                !== measurementEvent.payload.rawStderrArtifactId) {
            throw new RuntimeIntegrityError(
                "Committed impossibility certificate does not match the reserved verifier command",
                { logicalEffectKey, attemptId: committed.attempt.attemptId },
            );
        }
        const rawStdoutBytes = recoveredMeasurement.rawOutput.stdout;
        const rawStderrBytes = recoveredMeasurement.rawOutput.stderr;
        const rebuilt = this.#buildImpossibilityVerificationResult({
            aggregate,
            command,
            snapshotId,
            measurement,
            rawOutput: {
                stdout: rawStdoutBytes,
                stderr: rawStderrBytes,
            },
        });
        const persistedCertificate = this.#readRegisteredJsonArtifact(
            payload.certificateArtifactId,
            "Committed impossibility certificate",
        );
        if (!canonicalEqual(persistedCertificate, rebuilt.certificate)
            || payload.certificateArtifactHash !== rebuilt.certificateArtifactHash
            || payload.checkerStatus !== rebuilt.checkerStatus
            || payload.certificateVerdict !== rebuilt.certificateVerdict
            || payload.measurementReceiptHash !== rebuilt.measurementReceiptHash
            || payload.measurementReceiptArtifactHash
                !== rebuilt.measurementReceiptArtifactHash
            || payload.rawStdoutArtifactHash !== rebuilt.rawStdoutArtifactHash
            || payload.rawStderrArtifactHash !== rebuilt.rawStderrArtifactHash
            || !canonicalEqual(
                payload.measurementProvenance,
                recoveredMeasurement.persisted.measurementProvenance,
            )) {
            throw new RuntimeIntegrityError(
                "Committed impossibility artifacts do not reproduce the trusted certificate",
                { logicalEffectKey, attemptId: committed.attempt.attemptId },
            );
        }
        const certificateArtifact = this.#registeredArtifactRef(
            payload.certificateArtifactId,
            "Committed impossibility certificate",
        ).artifact;
        return {
            result: rebuilt,
            persisted: {
                measurementProvenance:
                    recoveredMeasurement.persisted.measurementProvenance,
                certificateArtifact,
            },
        };
    }

    async #runValidationCommand(aggregate, commandId, mainAttemptId) {
        const contract = aggregate.contract;
        const reserved = aggregate.commands[commandId].command;
        const runSeries = async (series) => {
            const blockPlan = replicationBlockPlan(
                series.replicationSchedule,
                reserved.attemptIndex,
            );
            if (blockPlan.arms.length !== 1
                || blockPlan.arms[0].armId !== "candidate") {
                throw new RuntimeIntegrityError(
                    "Validation series must reserve exactly one candidate arm",
                    { commandId, role: series.role, caseId: series.caseId },
                );
            }
            const arm = blockPlan.arms[0];
            const replication = immutableCanonical({
                scheduleHash: series.replicationSchedule.scheduleHash,
                blockIndex: arm.blockIndex,
                replicateIndex: arm.replicateIndex,
                armIndex: arm.armIndex,
                armId: arm.armId,
                deterministicSeed: arm.deterministicSeed,
                subjectId: arm.subjectId,
            });
            const effectCommand = {
                kind: "validation-measurement",
                commandId,
                role: series.role,
                caseId: series.caseId,
                attemptIndex: reserved.attemptIndex,
                scheduleHash: series.replicationSchedule.scheduleHash,
                blockIndex: arm.blockIndex,
                deterministicSeed: arm.deterministicSeed,
                subjectId: arm.subjectId,
                snapshot: series.artifactHash,
            };
            const materialized = this.#materializeSnapshot(
                series.artifactHash,
                `validation-${series.role}-${series.caseId}`,
            );
            try {
                const effect = await this.#executeEffect(
                    effectCommand,
                    async (attemptId) => {
                        return this.#runHarnessMeasurement({
                            harnessRole: series.role,
                            candidateSnapshot: materialized.candidateSnapshot,
                            attemptId,
                            runnerEpochId: this.#config.runnerEpochId,
                            measurementBinding: {
                                role: series.role,
                                phase: "calibration",
                                replicateIndex: arm.replicateIndex,
                                blockIndex: arm.blockIndex,
                                armIndex: arm.armIndex,
                                armId: arm.armId,
                                deterministicSeed: arm.deterministicSeed,
                                subjectId: arm.subjectId,
                                environmentIdentity:
                                    contract.harnessSuite.environmentIdentity,
                                suiteIdentity: contract.harnessSuiteIdentity,
                            },
                            captureInvalid: true,
                        });
                    },
                    async (executed, attemptId, logicalEffectKey) =>
                        this.#persistMeasurement({
                            measurement: executed.measurement,
                            rawOutput: executed.rawOutput,
                            invalid: executed.invalid,
                            attemptId,
                            logicalEffectKey,
                            purpose: "validation",
                            commandId,
                            candidateId: `${series.role}.${series.caseId}`,
                            measurementSubjectId: arm.subjectId,
                            snapshotId: series.artifactHash,
                            replication,
                            harnessRole: series.role,
                            measurementPhase: "calibration",
                        }),
                    async (committed, logicalEffectKey) => {
                        const recovered = this.#recoverMeasurementEffect({
                            committed,
                            logicalEffectKey,
                            aggregate,
                            purpose: "validation",
                            commandId,
                            candidateId: `${series.role}.${series.caseId}`,
                            measurementSubjectId: arm.subjectId,
                            snapshotId: series.artifactHash,
                            replication,
                            harnessRole: series.role,
                            measurementPhase: "calibration",
                        });
                        return {
                            result: {
                                measurement: recovered.measurement,
                                rawOutput: null,
                                invalid: recovered.invalid,
                            },
                            persisted: recovered.persisted,
                        };
                    },
                );
                const measurement = effect.result.measurement;
                return {
                    role: series.role,
                    caseId: series.caseId,
                    schedule: series.replicationSchedule,
                    replication,
                    attemptId: effect.attemptId,
                    parsed: measurement.parsed,
                    invalid: effect.result.invalid ?? null,
                    receiptHash: ensureReceiptObservationHash(hashReceipt(measurement.receipt)),
                    measurementRoot:
                        effect.persisted.measurementProvenance.measurementRoot,
                    measurementProvenance: effect.persisted.measurementProvenance,
                };
            } finally {
                removeTreeInside(materialized.dest, this.#runTempRoot);
            }
        };
        const settledSeries = [];
        for (const series of reserved.validationSeries) {
            try {
                settledSeries.push({
                    status: "fulfilled",
                    value: await runSeries(series),
                });
            } catch (reason) {
                settledSeries.push({ status: "rejected", reason });
            }
        }
        const validationFailures = settledSeries.filter(
            (item) => item.status === "rejected",
        );
        if (validationFailures.length > 0) {
            const injectedCrash = validationFailures.find(
                (item) => item.reason?.leaveAttemptActive === true,
            );
            if (injectedCrash !== undefined) {
                throw injectedCrash.reason;
            }
            const configurationFailure = validationFailures.find(
                (item) =>
                    item.reason?.code
                        === RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
            );
            if (configurationFailure !== undefined) {
                throw configurationFailure.reason;
            }
            const error = new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.CHILD_CRASH,
                "One or more trusted validation measurements failed before producing evidence",
                {
                    commandId,
                    failures: validationFailures.map((item) => ({
                        code: item.reason?.code ?? null,
                        message: item.reason?.message ?? String(item.reason),
                    })),
                },
            );
            error.recoverable = true;
            throw error;
        }
        const seriesRuns = settledSeries.map((item) => item.value)
            .sort((left, right) =>
                `${left.role}\0${left.caseId}`.localeCompare(
                    `${right.role}\0${right.caseId}`,
                ));
        const data = immutableCanonical({
            version: 1,
            attemptIndex: reserved.attemptIndex,
            series: seriesRuns.map((item) =>
                createRawMeasurementSeries({
                    schedule: item.schedule,
                    attempts: [{
                        ...item.replication,
                        attemptId: item.attemptId,
                        parsed: item.parsed,
                        invalid: item.invalid,
                        receiptHash: item.receiptHash,
                        measurementRoot: item.measurementRoot,
                    }],
                    role: item.role,
                    phase: "calibration",
                    caseId: item.caseId,
                })),
        });
        const compositeArtifact = this.#persistJsonArtifact({
            attemptId: mainAttemptId,
            kind: "validation-composite-receipt",
            value: {
                version: 2,
                authority: "raw_complete_blocks",
                commandId,
                attemptIndex: reserved.attemptIndex,
                series: data.series,
            },
            contentType: "application/vnd.crucible.validation-receipt+json",
        });
        this.#ingestOperationalEvidence({
            attemptId: mainAttemptId,
            evidenceKind: "validation-composite",
            kind: "runtime:validation_composite",
            payload: {
                commandId,
                attemptIndex: reserved.attemptIndex,
                artifactId: compositeArtifact.artifactId,
            },
        });
        const provenance = createEvidenceProvenance({
            validationCompositeArtifact: compositeArtifact,
            measurements: seriesRuns.map((item) => item.measurementProvenance),
        }, {
            purpose: "validation",
            command: aggregate.commands[commandId].command,
            contract,
        });

        return {
            commandId,
            observationId: this.#stableObservationId(commandId, {
                purpose: "validation",
            }),
            purpose: "validation",
            receipt: {
                version: 1,
                attemptId: mainAttemptId,
                runnerEpochId: this.#config.runnerEpochId,
                rawStdoutHash: hashCanonical(
                    provenance.measurements.map((item) => ({
                        id: item.subjectId,
                        hash: item.rawStdoutHash,
                    })),
                    OBSERVATION_STREAM_HASH_ALGORITHM,
                ),
                rawStderrHash: hashCanonical(
                    provenance.measurements.map((item) => ({
                        id: item.subjectId,
                        hash: item.rawStderrHash,
                    })),
                    OBSERVATION_STREAM_HASH_ALGORITHM,
                ),
                candidateArtifactHash: null,
                provenance,
            },
            data,
        };
    }

    #ingestImpossibilityRequest(command, attemptId) {
        this.#assertDeadlineOpen("impossibility request artifact ingestion");
        const expectedRequestHash = hashCanonical(
            command.request,
            IMPOSSIBILITY_REQUEST_HASH_ALGORITHM,
        );
        const expectedProposalHash = hashCanonical(
            command.proposedCertificate,
            IMPOSSIBILITY_PROPOSAL_HASH_ALGORITHM,
        );
        const expectedProofHash = hashCanonical(
            command.proofArtifact,
            IMPOSSIBILITY_PROOF_ARTIFACT_HASH_ALGORITHM,
        );
        const manifest = command.request?.objectManifest ?? null;
        const expectedManifestRoot = manifest === null
            ? null
            : hashCanonical(
                impossibilityManifestCore(manifest),
                IMPOSSIBILITY_VERIFIER_OBJECT_MANIFEST_HASH_ALGORITHM,
            );
        if (command.requestHash !== expectedRequestHash
            || command.proposedCertificateArtifactHash
                !== expectedProposalHash
            || command.proofArtifactHash !== expectedProofHash
            || command.request?.contract?.hypothesisTopology
                !== "certified_impossibility"
            || command.request?.proposedCertificate?.artifactHash
                !== command.proposedCertificateArtifactHash
            || command.request?.proofArtifact?.artifactHash
                !== command.proofArtifactHash
            || command.request?.proofArtifact?.path
                !== IMPOSSIBILITY_PROOF_FILENAME
            || command.request?.proofArtifact?.objectId
                !== objectIdForBytes(
                    Buffer.from(canonicalJson(command.proofArtifact), "utf8"),
                )
            || command.proposedCertificate?.proofArtifactHash
                !== command.proofArtifactHash
            || manifest === null
            || !Array.isArray(manifest.entries)
            || manifest.pack?.path !== "object-pack.json"
            || manifest.pack?.format
                !== "crucible-base64-object-pack-v1"
            || manifest.root !== expectedManifestRoot
            || command.proposedCertificate?.objectManifestRoot
                !== manifest.root
            || command.proofArtifactHash
                === command.proposedCertificateArtifactHash) {
            throw new RuntimeIntegrityError(
                "Reserved impossibility request is not canonical or certified-impossibility scoped",
                {
                    expectedRequestHash,
                    actualRequestHash: command.requestHash ?? null,
                },
            );
        }
        const sourceRoot = ensureDirectory(path.join(this.#runTempRoot, "impossibility-requests"));
        const sourceDir = makeUniqueDirectory(
            sourceRoot,
            `request-${command.attemptOrdinal}`,
        );
        try {
            const writeBytes = (relativePath, bytes) => {
                const target = assertPathInside(
                    path.join(sourceDir, ...relativePath.split("/")),
                    sourceDir,
                    "impossibility verifier input",
                );
                fs.mkdirSync(path.dirname(target), {
                    recursive: true,
                    mode: 0o700,
                });
                fs.writeFileSync(target, bytes, {
                    flag: "wx",
                    mode: 0o600,
                });
            };
            writeBytes(
                IMPOSSIBILITY_REQUEST_FILENAME,
                Buffer.from(canonicalJson(command.request), "utf8"),
            );
            writeBytes(
                IMPOSSIBILITY_PROPOSAL_FILENAME,
                Buffer.from(
                    canonicalJson(command.proposedCertificate),
                    "utf8",
                ),
            );
            const generated = generatedImpossibilityDocuments(command);
            const seenPaths = new Set();
            const packedObjects = [];
            for (const entry of manifest.entries) {
                if (entry === null
                    || typeof entry !== "object"
                    || !canonicalEqual(
                        Object.keys(entry).sort(),
                        [
                            "artifactIds",
                            "byteHash",
                            "kind",
                            "objectId",
                            "path",
                            "semanticHashes",
                        ],
                    )
                    || typeof entry.path !== "string"
                    || typeof entry.objectId !== "string"
                    || typeof entry.byteHash !== "string"
                    || (entry.kind !== "generated"
                        && entry.kind !== "cas_object")
                    || !Array.isArray(entry.artifactIds)
                    || (entry.kind === "generated"
                        && entry.artifactIds.length !== 0)
                    || (entry.kind === "cas_object"
                        && entry.artifactIds.length === 0)
                    || [
                        IMPOSSIBILITY_REQUEST_FILENAME,
                        IMPOSSIBILITY_PROPOSAL_FILENAME,
                        manifest.pack.path,
                    ].includes(entry.path)
                    || seenPaths.has(entry.path)) {
                    throw new RuntimeIntegrityError(
                        "Impossibility verifier object manifest is malformed",
                        { entry },
                    );
                }
                seenPaths.add(entry.path);
                const document = generated.get(entry.path);
                if ((entry.kind === "generated") !== (document !== undefined)) {
                    throw new RuntimeIntegrityError(
                        "Impossibility verifier object source kind is inconsistent",
                        { path: entry.path, kind: entry.kind },
                    );
                }
                const bytes = document === undefined
                    ? this.#artifactStore.readObject(
                        entry.objectId,
                        { verify: true },
                    )
                    : Buffer.from(canonicalJson(document), "utf8");
                if (objectIdForBytes(bytes) !== entry.objectId
                    || !taggedHashMatchesObjectId(
                        entry.byteHash,
                        entry.objectId,
                    )
                    || !Array.isArray(entry.semanticHashes)
                    || entry.semanticHashes.some((hash) =>
                        !taggedHashMatchesObjectId(
                            hash,
                            entry.objectId,
                        ))) {
                    throw new RuntimeIntegrityError(
                        "Impossibility verifier object bytes disagree with the request manifest",
                        { path: entry.path, objectId: entry.objectId },
                    );
                }
                if (document === undefined) {
                    packedObjects.push({
                        path: entry.path,
                        objectId: entry.objectId,
                        byteHash: entry.byteHash,
                        artifactIds: entry.artifactIds,
                        semanticHashes: entry.semanticHashes,
                        contentBase64: bytes.toString("base64"),
                    });
                } else {
                    writeBytes(entry.path, bytes);
                }
            }
            if ([...generated.keys()].some((path) => !seenPaths.has(path))) {
                throw new RuntimeIntegrityError(
                    "Impossibility verifier object manifest omitted a generated proof input",
                    {
                        missing: [...generated.keys()]
                            .filter((path) => !seenPaths.has(path)),
                    },
                );
            }
            const objectPack = {
                version: manifest.pack.format,
                entries: packedObjects.sort((left, right) =>
                    left.path.localeCompare(right.path)),
            };
            const objectPackBytes = Buffer.from(
                canonicalJson(objectPack),
                "utf8",
            );
            writeBytes(manifest.pack.path, objectPackBytes);
            this.#reserveDirectoryCas(
                attemptId,
                sourceDir,
                `impossibility-request-${command.attemptOrdinal}`,
            );
            const snapshot = this.#artifactStore.ingestDirectory({ sourceDir });
            const expectedEntries = new Map([
                [
                    IMPOSSIBILITY_REQUEST_FILENAME,
                    objectIdForBytes(
                        Buffer.from(canonicalJson(command.request), "utf8"),
                    ),
                ],
                [
                    IMPOSSIBILITY_PROPOSAL_FILENAME,
                    objectIdForBytes(
                        Buffer.from(
                            canonicalJson(command.proposedCertificate),
                            "utf8",
                        ),
                    ),
                ],
                ...manifest.entries
                    .filter((entry) => entry.kind === "generated")
                    .map((entry) => [
                        entry.path,
                        entry.objectId,
                    ]),
                [
                    manifest.pack.path,
                    objectIdForBytes(objectPackBytes),
                ],
            ]);
            if (snapshot.manifest.entries.length !== expectedEntries.size
                || snapshot.manifest.entries.some((entry) =>
                    expectedEntries.get(entry.path) !== entry.object)) {
                throw new RuntimeIntegrityError(
                    "Persisted impossibility verifier snapshot does not match the request object manifest",
                );
            }
            this.#assertDeadlineOpen("impossibility request artifact persistence");
            return snapshot;
        } finally {
            removeTreeInside(sourceDir, sourceRoot);
        }
    }

    #persistImpossibilityRequestSnapshot({
        attemptId,
        commandId,
        command,
        snapshotId,
    }) {
        const snapshotProvenance = this.#persistSnapshotProvenance({
            attemptId,
            kind: `impossibility-request-${command.attemptOrdinal}`,
            snapshotId,
        });
        this.#ingestOperationalEvidence({
            attemptId,
            evidenceKind: `impossibility-request:${command.attemptOrdinal}`,
            kind: "runtime:impossibility_request",
            payload: {
                commandId,
                attemptOrdinal: command.attemptOrdinal,
                requestHash: command.requestHash,
                proposedCertificateArtifactHash:
                    command.proposedCertificateArtifactHash,
                proofArtifactHash: command.proofArtifactHash,
                objectManifestRoot:
                    command.request.objectManifest.root,
                snapshotId,
                verificationSnapshotHash: measurementSnapshotHash(snapshotId),
                artifactId: snapshotProvenance.manifestArtifact.artifactId,
                snapshotProvenance,
            },
        });
    }

    #buildImpossibilityVerificationResult({
        aggregate,
        command,
        snapshotId,
        measurement,
        rawOutput,
    }) {
        const verificationSnapshotHash = measurementSnapshotHash(snapshotId);
        let checkerResult;
        try {
            checkerResult = normalizeImpossibilityCheckerResult(
                measurement.parsed,
                {
                    request: command.request,
                    requestHash: command.requestHash,
                    binding: command.measurementBinding,
                },
            );
        } catch (error) {
            throw new RuntimeIntegrityError(
                `Impossibility checker output is invalid: ${
                    error?.message ?? String(error)
                }`,
                { cause: error?.code ?? null },
            );
        }
        const verifierRole = aggregate.contract.harnessSuite.roles
            .impossibility_verifier;
        const frozenExecution =
            inspectFrozenImpossibilityVerifierExecution({
                receipt: measurement.receipt,
                verifierRole,
                parserVersion: command.parserVersion,
            });
        const bindingChecks = {
            snapshotBytes: receiptHasVerifiedSnapshotBytes(
                measurement.receipt,
                verificationSnapshotHash,
            ),
            parsed: measurement.receipt?.parsed !== undefined
                && canonicalEqual(
                    measurement.receipt.parsed,
                    measurement.parsed,
                ),
            stdout: sha256Bytes(rawOutput.stdout, STREAM_HASH_ALGORITHM)
                === measurement.stdoutHash,
            stderr: sha256Bytes(rawOutput.stderr, STREAM_HASH_ALGORITHM)
                === measurement.stderrHash,
        };
        const failedBindings = Object.entries(bindingChecks)
            .filter(([, valid]) => !valid)
            .map(([name]) => name)
            .concat(frozenExecution.failedBindings);
        if (failedBindings.length > 0) {
            throw new RuntimeIntegrityError(
                "Impossibility measurement receipt is not bound to the reserved verifier request",
                {
                    requestHash: command.requestHash,
                    verificationSnapshotHash,
                    failedBindings,
                },
            );
        }
        const certificate = checkerResult.certificate;
        const certificateVerdict = certificate.verdict;
        const checkerStatus = checkerResult.status;
        const measurementReceiptHash = hashReceipt(measurement.receipt);
        const measurementReceiptBytes = Buffer.from(
            canonicalJson(measurement.receipt),
            "utf8",
        );
        const certificateBytes = Buffer.from(canonicalJson(certificate), "utf8");
        return {
            measurement,
            rawStdoutBytes: rawOutput.stdout,
            rawStderrBytes: rawOutput.stderr,
            certificate,
            certificateBytes,
            checkerResult,
            checkerStatus,
            certificateVerdict,
            verificationSnapshotHash,
            measurementReceiptHash,
            measurementReceiptArtifactHash: taggedHash(
                IMPOSSIBILITY_RECEIPT_ARTIFACT_HASH_ALGORITHM,
                measurementReceiptBytes,
            ),
            rawStdoutArtifactHash: taggedHash(
                IMPOSSIBILITY_STDOUT_ARTIFACT_HASH_ALGORITHM,
                rawOutput.stdout,
            ),
            rawStderrArtifactHash: taggedHash(
                IMPOSSIBILITY_STDERR_ARTIFACT_HASH_ALGORITHM,
                rawOutput.stderr,
            ),
            certificateArtifactHash: taggedHash(
                IMPOSSIBILITY_CERTIFICATE_ARTIFACT_HASH_ALGORITHM,
                certificateBytes,
            ),
        };
    }

    async #runImpossibilityVerificationCommand(
        aggregate,
        commandId,
        mainAttemptId,
        command,
    ) {
        if (command.request.signedExperiment.contractHash
                !== aggregate.contractHash
            || !canonicalEqual(command.request.contract, aggregate.contract)) {
            throw new RuntimeIntegrityError(
                "Reserved impossibility request does not match the replayed contract",
                { commandId, requestHash: command.requestHash },
            );
        }
        const verification = createImpossibilityVerificationPackage(
            aggregate,
            {
                attemptOrdinal: command.attemptOrdinal,
                progress: searchProgress(aggregate),
                validation: currentValidationEvidence(aggregate),
            },
        );
        if (!verification.eligible
            || verification.requestHash !== command.requestHash
            || verification.proposalArtifactHash
                !== command.proposedCertificateArtifactHash
            || verification.proofArtifactHash
                !== command.proofArtifactHash
            || !canonicalEqual(
                verification.proofArtifact,
                command.proofArtifact,
            )) {
            throw new RuntimeIntegrityError(
                "Reserved impossibility request no longer matches complete current coverage",
                {
                    commandId,
                    requestHash: command.requestHash,
                    missing: verification.missing,
                },
            );
        }
        const requestSnapshot = this.#ingestImpossibilityRequest(
            command,
            mainAttemptId,
        );
        this.#persistImpossibilityRequestSnapshot({
            attemptId: mainAttemptId,
            commandId,
            command,
            snapshotId: requestSnapshot.snapshot,
        });
        const materialized = this.#materializeSnapshot(
            requestSnapshot.snapshot,
            `impossibility-${command.attemptOrdinal}`,
        );
        const measurementBinding = command.measurementBinding;
        try {
            const effect = await this.#executeEffect(
                {
                    kind: "impossibility-verification",
                    commandId,
                    attemptOrdinal: command.attemptOrdinal,
                    requestHash: command.requestHash,
                    snapshot: requestSnapshot.snapshot,
                },
                async (attemptId) => {
                    const executed = await this.#runHarnessMeasurement({
                        harnessRole: "impossibility_verifier",
                        candidateSnapshot: materialized.candidateSnapshot,
                        attemptId,
                        runnerEpochId: this.#config.runnerEpochId,
                        measurementBinding,
                        resultParserContext: {
                            request: command.request,
                            requestHash: command.requestHash,
                        },
                    });
                    return this.#buildImpossibilityVerificationResult({
                        aggregate,
                        command,
                        snapshotId: requestSnapshot.snapshot,
                        measurement: executed.measurement,
                        rawOutput: executed.rawOutput,
                    });
                },
                async (result, attemptId, logicalEffectKey) =>
                    this.#persistImpossibilityVerification({
                        result,
                        attemptId,
                        logicalEffectKey,
                        commandId,
                        command,
                        snapshotId: requestSnapshot.snapshot,
                    }),
                async (committed, logicalEffectKey) =>
                    this.#recoverImpossibilityVerification({
                        committed,
                        logicalEffectKey,
                        aggregate,
                        commandId,
                        command,
                        snapshotId: requestSnapshot.snapshot,
                    }),
            );
            const result = effect.result;
            const provenance = createEvidenceProvenance({
                impossibilityCertificateArtifact:
                    effect.persisted.certificateArtifact,
                measurements: [effect.persisted.measurementProvenance],
            }, {
                purpose: "impossibility",
                command,
                contract: aggregate.contract,
            });
            return {
                commandId,
                observationId: this.#stableObservationId(commandId, {
                    purpose: "impossibility",
                    attemptOrdinal: command.attemptOrdinal,
                    requestHash: command.requestHash,
                }),
                purpose: "impossibility",
                receipt: {
                    version: 1,
                    attemptId: effect.attemptId,
                    runnerEpochId: result.measurement.receipt.runnerEpochId,
                    rawStdoutHash: result.measurement.stdoutHash,
                    rawStderrHash: result.measurement.stderrHash,
                    candidateArtifactHash: null,
                    certificateArtifactHash: result.certificateArtifactHash,
                    measurementReceiptArtifactHash:
                        result.measurementReceiptArtifactHash,
                    measurementReceiptHash: result.measurementReceiptHash,
                    rawStderrArtifactHash: result.rawStderrArtifactHash,
                    rawStdoutArtifactHash: result.rawStdoutArtifactHash,
                    verificationRequestHash: command.requestHash,
                    verificationSnapshotHash: result.verificationSnapshotHash,
                    provenance,
                },
                data: {
                    certificateVersion: command.certificateVersion,
                    checkerStatus: result.checkerStatus,
                    certificateVerdict: result.certificateVerdict,
                    certificateArtifactHash: result.certificateArtifactHash,
                    measurementReceiptHash: result.measurementReceiptHash,
                    verificationRequestHash: command.requestHash,
                    proposedCertificateArtifactHash:
                        command.proposedCertificateArtifactHash,
                    proofArtifactHash: command.proofArtifactHash,
                    verificationSnapshotHash: result.verificationSnapshotHash,
                    checkerResult: result.checkerResult,
                },
            };
        } finally {
            removeTreeInside(materialized.dest, this.#runTempRoot);
        }
    }

    #ensureReplicationScheduleArtifact({
        aggregate,
        commandId,
        mainAttemptId,
        command,
    }) {
        const schedule = normalizeReplicationSchedule(command.replicationSchedule);
        const searchCommand = command.kind === "search_candidate";
        const scientificRoleCommand = command.kind === "run_confirmation"
            || command.kind === "run_challenge";
        const searchBindingValid = searchCommand
            && schedule.subject.id === command.candidateId
            && schedule.subject.index
                === statisticalSubjectIndex(
                    schedule.subject.kind,
                    (command.round - 1)
                        * aggregate.contract.candidatesPerRound
                        + command.slotIndex,
                );
        const scientificBindingValid = scientificRoleCommand
            && command.protocolManifest?.replicationSchedule?.scheduleHash
                === schedule.scheduleHash
            && command.protocolManifestHash
                === command.protocolManifest?.protocolManifestHash
            && command.protocolManifest?.candidateId === command.candidateId
            && command.protocolManifest?.candidateEvidenceId
                === command.candidateEvidenceId
            && command.protocolManifest?.candidateArtifactHash
                === command.candidateArtifactHash;
        if (schedule.contractHash !== aggregate.contractHash
            || (!searchBindingValid && !scientificBindingValid)) {
            throw new RuntimeIntegrityError(
                "Reserved replication schedule does not match the candidate assignment",
                { commandId, scheduleHash: schedule.scheduleHash },
            );
        }
        const existing = this.#adapter.listOperationalEvidence().filter((event) =>
            event.kind === "runtime:measurement_schedule"
            && event.payload?.commandId === commandId);
        if (existing.length > 1) {
            throw new RuntimeIntegrityError(
                "More than one measurement schedule exists for one candidate command",
                { commandId },
            );
        }
        if (existing.length === 1) {
            const payload = existing[0].payload;
            if (payload.scheduleHash !== schedule.scheduleHash
                || payload.candidateId !== command.candidateId
                || (payload.harnessRole ?? command.harnessRole ?? "search")
                    !== (command.harnessRole ?? "search")
                || (payload.protocolManifestHash
                    ?? command.protocolManifestHash
                    ?? null)
                    !== (command.protocolManifestHash ?? null)) {
                throw new RuntimeIntegrityError(
                    "Persisted measurement schedule does not match the reserved command",
                    { commandId, scheduleHash: schedule.scheduleHash },
                );
            }
            const persisted = this.#readRegisteredJsonArtifact(
                payload.artifactId,
                "Persisted measurement schedule",
            );
            if (!canonicalEqual(persisted, schedule)) {
                throw new RuntimeIntegrityError(
                    "Persisted measurement schedule artifact changed",
                    { commandId, artifactId: payload.artifactId },
                );
            }
            return {
                schedule,
                artifact: this.#registeredArtifactRef(
                    payload.artifactId,
                    "Persisted measurement schedule",
                ).artifact,
            };
        }
        const artifact = this.#persistJsonArtifact({
            attemptId: mainAttemptId,
            kind: `measurement-schedule-${command.harnessRole ?? "search"}-${command.candidateId}`,
            value: schedule,
            contentType: "application/vnd.crucible.measurement-schedule+json",
        });
        this.#ingestOperationalEvidence({
            attemptId: mainAttemptId,
            evidenceKind: `measurement-schedule:${command.candidateId}`,
            kind: "runtime:measurement_schedule",
            payload: {
                commandId,
                candidateId: command.candidateId,
                harnessRole: command.harnessRole ?? "search",
                protocolManifestHash:
                    command.protocolManifestHash ?? null,
                scheduleHash: schedule.scheduleHash,
                artifactId: artifact.artifactId,
            },
        });
        return { schedule, artifact };
    }

    async #resolveReplicationControlSnapshot({
        aggregate,
        commandId,
        mainAttemptId,
        command,
        schedule,
        candidateSnapshotId,
        enumerandPlan,
    }) {
        const control = aggregate.contract.statisticalPolicy.control;
        if (control.kind === "snapshot") {
            return control.identity;
        }
        if (aggregate.contract.enumerandManifest === undefined) {
            throw new RuntimeIntegrityError(
                "Enumerand control requires a frozen enumerand manifest",
                { commandId, control },
            );
        }
        const manifestOptions = {
            topology: aggregate.contract.enumerandManifest?.topology
                ?? aggregate.contract.hypothesisTopology,
            observableRegistry: aggregate.contract.observableRegistry,
            hypothesisPolicy: aggregate.contract.hypothesisPolicy,
        };
        const binding = resolveControlEnumerand(
            aggregate.contract.enumerandManifest,
            manifestOptions,
        );
        if (binding.kind === "reference"
            || binding.enumerandHash !== control.identity) {
            throw new RuntimeIntegrityError(
                "Frozen control enumerand does not match the statistical policy",
                { commandId, control, binding },
            );
        }
        if (binding.topology === "finite_enumerable") {
            return binding.artifactSnapshotHash;
        }
        if (enumerandPlan?.binding?.enumerandHash === binding.enumerandHash) {
            return candidateSnapshotId;
        }

        const existing = this.#adapter.listOperationalEvidence().filter((event) =>
            event.kind === "runtime:replication_control_snapshot"
            && event.payload?.commandId === commandId);
        if (existing.length > 1) {
            throw new RuntimeIntegrityError(
                "More than one parameterized control snapshot exists for one command",
                { commandId },
            );
        }
        if (existing.length === 1) {
            const payload = existing[0].payload;
            if (payload.scheduleHash !== schedule.scheduleHash
                || payload.enumerandHash !== binding.enumerandHash
                || payload.enumerandBindingHash
                    !== enumerandBindingHash(binding, manifestOptions)
                || payload.candidateArtifactHash
                    !== measurementSnapshotHash(payload.snapshotId)) {
                throw new RuntimeIntegrityError(
                    "Persisted parameterized control does not match its frozen binding",
                    { commandId },
                );
            }
            this.#verifySnapshotProvenance(
                payload.snapshotProvenance,
                payload.snapshotId,
                "Persisted replication control snapshot",
            );
            return payload.snapshotId;
        }

        const generator = this.#dependencies.parameterizedCandidateGenerator;
        if (typeof generator !== "function") {
            throw new RuntimeConfigError(
                "Parameterized control enumerands require a trusted parameterizedCandidateGenerator",
                {
                    ordinal: binding.ordinal,
                    enumerandHash: binding.enumerandHash,
                },
            );
        }
        const bindingHash = enumerandBindingHash(binding, manifestOptions);
        const generationRequest = immutableCanonical({
            kind: "replication_control",
            commandId,
            candidateId: binding.id,
            scheduleHash: schedule.scheduleHash,
            enumerandBinding: binding,
            enumerandBindingHash: bindingHash,
            parameterTuple: binding.parameterTuple,
            parameterTupleHash: binding.parameterTupleHash,
        });
        const generated = await generator(generationRequest);
        const expectedKeys = [
            "annotations",
            "candidateId",
            "enumerandBindingHash",
            "files",
        ];
        if (generated === null
            || typeof generated !== "object"
            || Array.isArray(generated)
            || !canonicalEqual(Object.keys(generated).sort(), expectedKeys)
            || generated.enumerandBindingHash !== bindingHash) {
            throw new RuntimeIntegrityError(
                "Trusted parameterized control generator returned an invalid binding",
                { commandId, bindingHash },
            );
        }
        const challengeNonce = stableHex({
            investigationId: this.#config.investigationId,
            commandId,
            scheduleHash: schedule.scheduleHash,
            enumerandBindingHash: bindingHash,
        });
        const candidate = validateCandidateSubmission({
            challenge: challengeNonce,
            candidateId: generated.candidateId,
            annotations: generated.annotations,
            files: generated.files,
        }, {
            challengeNonce,
            allowedCandidateIds: [binding.id],
            visibleEvidenceIds: command.promptContextRefs,
            observableRegistry: aggregate.contract.observableRegistry,
            hypothesisPolicy: aggregate.contract.hypothesisPolicy,
            assignedParentEvidenceIds: command.parentEvidenceIds,
            enumerandBinding: binding,
            trustedParameterizedGenerator: true,
            limits: this.#config.options.candidateLimits,
        });
        const proposal = immutableCanonical({
            ...candidate,
            identity: {
                source: "trusted_parameterized_control_generator",
                enumerandBindingHash: bindingHash,
                generatedPayloadHash: hashCanonical(
                    candidate,
                    "sha256:crucible-parameterized-control-v1",
                ),
            },
        });
        const proposalArtifact = this.#persistJsonArtifact({
            attemptId: mainAttemptId,
            kind: `replication-control-${binding.id}`,
            value: { generationRequest, proposal },
            contentType:
                "application/vnd.crucible.replication-control-generation+json",
        });
        const snapshot = this.#ingestCandidate(proposal, mainAttemptId);
        const candidateArtifactHash = measurementSnapshotHash(snapshot.snapshot);
        const snapshotProvenance = this.#persistSnapshotProvenance({
            attemptId: mainAttemptId,
            kind: `replication-control-snapshot-${binding.id}`,
            snapshotId: snapshot.snapshot,
        });
        this.#ingestOperationalEvidence({
            attemptId: mainAttemptId,
            evidenceKind: `replication-control-snapshot:${command.candidateId}`,
            kind: "runtime:replication_control_snapshot",
            payload: {
                commandId,
                scheduleHash: schedule.scheduleHash,
                enumerandHash: binding.enumerandHash,
                enumerandBindingHash: bindingHash,
                snapshotId: snapshot.snapshot,
                candidateArtifactHash,
                proposalArtifactId: proposalArtifact.artifactId,
                snapshotProvenance,
            },
        });
        return snapshot.snapshot;
    }

    #replicationBudgetAllows(
        schedule,
        blockPlan,
        {
            purpose = "candidate",
            harnessRole = "search",
        } = {},
    ) {
        const policy = this.#contract.statisticalPolicy.evaluationBudget;
        const measurements = this.#adapter.listOperationalEvidence().filter(
            (event) => event.kind === "runtime:measurement",
        );
        const existingKeys = new Set(measurements
            .filter((event) =>
                event.payload?.purpose === purpose
                && (event.payload?.harnessRole ?? "search") === harnessRole
                &&
                event.payload?.replication?.scheduleHash === schedule.scheduleHash)
            .map((event) =>
                `${event.payload.replication.blockIndex}:${
                    event.payload.replication.armIndex
                }`));
        const pending = blockPlan.arms.filter((arm) =>
            !existingKeys.has(`${arm.blockIndex}:${arm.armIndex}`));
        const candidateCount = measurements.filter((event) =>
            (event.payload?.purpose === "candidate"
                || event.payload?.purpose === "confirmation"
                || event.payload?.purpose === "challenge")
            && event.payload?.replication?.armId === "candidate").length;
        const controlCount = measurements.filter((event) =>
            (event.payload?.purpose === "candidate"
                || event.payload?.purpose === "confirmation"
                || event.payload?.purpose === "challenge")
            && event.payload?.replication?.armId === "control").length;
        return candidateCount + pending.filter((arm) =>
            arm.armId === "candidate").length
                <= policy.maxCandidateEvaluations
            && controlCount + pending.filter((arm) =>
                arm.armId === "control").length
                <= policy.maxControlEvaluations
            && measurements.length + pending.length
                <= policy.maxTotalEvaluations;
    }

    async #runReplicationMeasurements({
        aggregate,
        commandId,
        command,
        schedule,
        candidateSnapshotId,
        controlSnapshotId,
        purpose = "candidate",
        harnessRole = "search",
        measurementPhase = "search",
    }) {
        const candidateMaterialized = this.#materializeSnapshot(
            candidateSnapshotId,
            `candidate-${command.candidateId}`,
        );
        const controlMaterialized = this.#materializeSnapshot(
            controlSnapshotId,
            `control-${command.candidateId}`,
        );
        const attempts = [];
        let progress = null;
        try {
            for (
                let blockIndex = 0;
                blockIndex < schedule.maxBlocks;
                blockIndex += 1
            ) {
                const blockPlan = replicationBlockPlan(schedule, blockIndex);
                if (!this.#replicationBudgetAllows(schedule, blockPlan, {
                    purpose,
                    harnessRole,
                })) {
                    progress = evaluateReplicationProgress({
                        contract: aggregate.contract,
                        schedule,
                        attempts,
                        budgetRemaining: false,
                    });
                    break;
                }
                for (const arm of blockPlan.arms) {
                    const snapshotId = arm.armId === "control"
                        ? controlSnapshotId
                        : candidateSnapshotId;
                    const materialized = arm.armId === "control"
                        ? controlMaterialized
                        : candidateMaterialized;
                    const replication = immutableCanonical({
                        scheduleHash: schedule.scheduleHash,
                        blockIndex: arm.blockIndex,
                        replicateIndex: arm.replicateIndex,
                        armIndex: arm.armIndex,
                        armId: arm.armId,
                        deterministicSeed: arm.deterministicSeed,
                        subjectId: arm.subjectId,
                    });
                    const measurementBinding = {
                        role: harnessRole,
                        phase: measurementPhase,
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
                    const effectCommand = {
                        kind: "replicate-measurement",
                        purpose,
                        harnessRole,
                        measurementPhase,
                        commandId,
                        round: command.round ?? null,
                        slotIndex: command.slotIndex ?? null,
                        candidateId: command.candidateId,
                        scheduleHash: schedule.scheduleHash,
                        blockIndex: arm.blockIndex,
                        replicateIndex: arm.replicateIndex,
                        armIndex: arm.armIndex,
                        armId: arm.armId,
                        deterministicSeed: arm.deterministicSeed,
                        subjectId: arm.subjectId,
                        snapshot: snapshotId,
                    };
                    const effect = await this.#executeEffect(
                        effectCommand,
                        async (attemptId) => this.#runHarnessMeasurement({
                            harnessRole,
                            candidateSnapshot: materialized.candidateSnapshot,
                            attemptId,
                            runnerEpochId: this.#config.runnerEpochId,
                            measurementBinding,
                            captureInvalid: true,
                        }),
                        async (executed, attemptId, logicalEffectKey) =>
                            this.#persistMeasurement({
                                measurement: executed.measurement,
                                rawOutput: executed.rawOutput,
                                invalid: executed.invalid,
                                attemptId,
                                logicalEffectKey,
                                purpose,
                                commandId,
                                round: command.round ?? null,
                                slotIndex: command.slotIndex ?? null,
                                candidateId: command.candidateId,
                                measurementSubjectId: arm.subjectId,
                                snapshotId,
                                replication,
                                harnessRole,
                                measurementPhase,
                            }),
                        async (committed, logicalEffectKey) => {
                            const recovered = this.#recoverMeasurementEffect({
                                committed,
                                logicalEffectKey,
                                aggregate,
                                purpose,
                                commandId,
                                round: command.round ?? null,
                                slotIndex: command.slotIndex ?? null,
                                candidateId: command.candidateId,
                                measurementSubjectId: arm.subjectId,
                                snapshotId,
                                replication,
                                harnessRole,
                                measurementPhase,
                            });
                            return {
                                result: {
                                    measurement: recovered.measurement,
                                    rawOutput: null,
                                    invalid: recovered.invalid,
                                },
                                persisted: recovered.persisted,
                            };
                        },
                    );
                    attempts.push({
                        ...replication,
                        attemptId: effect.attemptId,
                        parsed: effect.result.measurement.parsed,
                        invalid: effect.result.invalid ?? null,
                        receiptHash: hashReceipt(effect.result.measurement.receipt),
                        measurementRoot:
                            effect.persisted.measurementProvenance.measurementRoot,
                        measurementProvenance:
                            effect.persisted.measurementProvenance,
                    });
                    await this.#fault("after_replication_arm", {
                        command: effectCommand,
                        commandId,
                        attemptId: effect.attemptId,
                        blockIndex: arm.blockIndex,
                        armIndex: arm.armIndex,
                        armId: arm.armId,
                    });
                }
                progress = evaluateReplicationProgress({
                    contract: aggregate.contract,
                    schedule,
                    attempts,
                });
                await this.#fault("after_replication_block", {
                    commandId,
                    blockIndex,
                    blockCount: progress.blockCount,
                });
                if (!progress.shouldContinue) break;
            }
        } finally {
            removeTreeInside(candidateMaterialized.dest, this.#runTempRoot);
            removeTreeInside(controlMaterialized.dest, this.#runTempRoot);
        }
        progress ??= evaluateReplicationProgress({
            contract: aggregate.contract,
            schedule,
            attempts,
            budgetRemaining: false,
        });
        if (progress.blockCount < schedule.minBlocks
            || progress.stoppingReason === null) {
            throw new RuntimeIntegrityError(
                "Replication stopped without the frozen minimum complete blocks",
                {
                    commandId,
                    blockCount: progress.blockCount,
                    minBlocks: schedule.minBlocks,
                    stoppingReason: progress.stoppingReason,
                },
            );
        }
        return { attempts, progress };
    }

    #ensureReplicationCompositeArtifact({
        commandId,
        mainAttemptId,
        command,
        schedule,
        scheduleArtifact,
        attempts,
        progress,
        rawSeries,
        purpose = "candidate",
        harnessRole = "search",
        protocolManifest = null,
    }) {
        const value = immutableCanonical(purpose === "candidate"
            ? {
                version: 2,
                authority: "raw_complete_blocks",
                commandId,
                candidateId: command.candidateId,
                schedule,
                scheduleArtifact,
                series: rawSeries,
                stopping: progress.stopping,
            }
            : {
                version: 2,
                authority: "raw_complete_blocks",
                commandId,
                candidateId: command.candidateId,
                candidateEvidenceId: command.candidateEvidenceId,
                confirmationFreezeHash:
                    command.confirmationFreezeHash,
                role: harnessRole,
                protocolManifest,
                protocolManifestHash:
                    command.protocolManifestHash,
                schedule,
                scheduleArtifact,
                series: rawSeries,
                stopping: progress.stopping,
            });
        const existing = this.#adapter.listOperationalEvidence().filter((event) =>
            event.kind === "runtime:replication_composite"
            && event.payload?.commandId === commandId);
        if (existing.length > 1) {
            throw new RuntimeIntegrityError(
                "More than one replication composite exists for one candidate command",
                { commandId },
            );
        }
        if (existing.length === 1) {
            const payload = existing[0].payload;
            const persisted = this.#readRegisteredJsonArtifact(
                payload.artifactId,
                "Persisted replication composite",
            );
            if (payload.scheduleHash !== schedule.scheduleHash
                || (payload.purpose ?? "candidate") !== purpose
                || (payload.harnessRole ?? "search") !== harnessRole
                || (payload.protocolManifestHash ?? null)
                    !== (command.protocolManifestHash ?? null)
                || payload.stoppingDigest !== progress.stoppingDigest
                || !canonicalEqual(persisted, value)) {
                throw new RuntimeIntegrityError(
                    "Persisted replication composite changed during recovery",
                    { commandId, artifactId: payload.artifactId },
                );
            }
            return this.#registeredArtifactRef(
                payload.artifactId,
                "Persisted replication composite",
            ).artifact;
        }
        const artifact = this.#persistJsonArtifact({
            attemptId: mainAttemptId,
            kind: `replication-composite-${harnessRole}-${command.candidateId}`,
            value,
            contentType: "application/vnd.crucible.replication-composite+json",
        });
        this.#ingestOperationalEvidence({
            attemptId: mainAttemptId,
            evidenceKind: `replication-composite:${command.candidateId}`,
            kind: "runtime:replication_composite",
            payload: {
                commandId,
                candidateId: command.candidateId,
                purpose,
                harnessRole,
                protocolManifestHash:
                    command.protocolManifestHash ?? null,
                scheduleHash: schedule.scheduleHash,
                blockCount: progress.blockCount,
                attemptCount: attempts.length,
                stoppingDigest: progress.stoppingDigest,
                artifactId: artifact.artifactId,
            },
        });
        return artifact;
    }

    #resolveScientificRoleSnapshots(aggregate, command) {
        const source = this.#resolveParentSnapshot(
            aggregate,
            command.candidateEvidenceId,
        );
        if (source.evidence.candidateId !== command.candidateId
            || source.evidence.commitEventHash
                !== command.candidateEvidenceHash
            || source.evidence.receipt?.candidateArtifactHash
                !== command.candidateArtifactHash
            || measurementSnapshotHash(source.snapshotId)
                !== command.candidateArtifactHash) {
            throw new RuntimeIntegrityError(
                "Frozen scientific role command no longer matches its candidate snapshot",
                {
                    candidateId: command.candidateId,
                    candidateEvidenceId: command.candidateEvidenceId,
                },
            );
        }
        const sourceObservation =
            aggregate.observations[source.evidence.observationId] ?? null;
        const sourceCommandId = sourceObservation?.commandId ?? null;
        const controlMeasurements = this.#adapter.listOperationalEvidence()
            .filter((event) =>
                event.kind === "runtime:measurement"
                && event.payload?.purpose === "candidate"
                && event.payload?.commandId === sourceCommandId
                && event.payload?.replication?.armId === "control");
        const controlMeasurement = controlMeasurements.at(-1) ?? null;
        let controlSnapshotId = controlMeasurement?.payload?.snapshotId ?? null;
        if (controlSnapshotId === null) {
            const control = aggregate.contract.statisticalPolicy.control;
            if (control.kind === "snapshot") {
                controlSnapshotId = control.identity;
            } else if (aggregate.contract.enumerandManifest !== undefined) {
                const binding = resolveControlEnumerand(
                    aggregate.contract.enumerandManifest,
                    {
                        topology: aggregate.contract.enumerandManifest?.topology
                            ?? aggregate.contract.hypothesisTopology,
                        observableRegistry:
                            aggregate.contract.observableRegistry,
                        hypothesisPolicy:
                            aggregate.contract.hypothesisPolicy,
                    },
                );
                if (binding.kind !== "reference"
                    && binding.topology === "finite_enumerable") {
                    controlSnapshotId = binding.artifactSnapshotHash;
                }
            }
        }
        if (typeof controlSnapshotId !== "string"
            || !this.#artifactStore.verifySnapshot(controlSnapshotId).ok) {
            throw new RuntimeIntegrityError(
                "Frozen scientific role control snapshot is missing or invalid",
                {
                    candidateId: command.candidateId,
                    candidateEvidenceId: command.candidateEvidenceId,
                },
            );
        }
        const sourceSchedule = aggregate.commands[sourceCommandId]
            ?.command?.replicationSchedule ?? null;
        const controlBinding = deriveReplicationControlBinding({
            contractHash: aggregate.contractHash,
            statisticalPolicy: aggregate.contract.statisticalPolicy,
            schedule: sourceSchedule,
            enumerandManifest: aggregate.contract.enumerandManifest ?? null,
            manifestOptions: {
                topology: aggregate.contract.enumerandManifest?.topology
                    ?? aggregate.contract.hypothesisTopology,
                observableRegistry: aggregate.contract.observableRegistry,
                hypothesisPolicy: aggregate.contract.hypothesisPolicy,
            },
            controlSnapshotHashes: controlMeasurements.map((measurement) =>
                measurementSnapshotHash(measurement.payload.snapshotId)),
            requireObservedControl: true,
        });
        if (controlMeasurements.length !== source.evidence.replication?.blockCount
            || measurementSnapshotHash(controlSnapshotId)
                !== controlBinding.artifactHash
            || !canonicalEqual(
                controlBinding,
                source.evidence.replication?.control ?? null,
            )) {
            throw new RuntimeIntegrityError(
                "Frozen scientific role control does not match the discovery control authority",
                {
                    candidateId: command.candidateId,
                    candidateEvidenceId: command.candidateEvidenceId,
                },
            );
        }
        return {
            candidateSnapshotId: source.snapshotId,
            controlSnapshotId,
        };
    }

    async #runScientificRoleCommand(
        aggregate,
        commandId,
        mainAttemptId,
        command,
    ) {
        const purpose = command.kind === "run_confirmation"
            ? "confirmation"
            : "challenge";
        if (command.harnessRole !== purpose
            || command.protocolManifest?.role !== purpose
            || command.protocolManifestHash
                !== command.protocolManifest?.protocolManifestHash) {
            throw new RuntimeIntegrityError(
                "Scientific role command is not bound to its frozen protocol manifest",
                { commandId, purpose },
            );
        }
        const scheduled = this.#ensureReplicationScheduleArtifact({
            aggregate,
            commandId,
            mainAttemptId,
            command,
        });
        const snapshots = this.#resolveScientificRoleSnapshots(
            aggregate,
            command,
        );
        const replicated = await this.#runReplicationMeasurements({
            aggregate,
            commandId,
            command,
            schedule: scheduled.schedule,
            candidateSnapshotId: snapshots.candidateSnapshotId,
            controlSnapshotId: snapshots.controlSnapshotId,
            purpose,
            harnessRole: purpose,
            measurementPhase: purpose,
        });
        const rawSeries = createRawMeasurementSeries({
            schedule: scheduled.schedule,
            attempts: replicated.attempts,
            role: purpose,
            phase: purpose,
            caseId: null,
        });
        const replicationCompositeArtifact =
            this.#ensureReplicationCompositeArtifact({
                commandId,
                mainAttemptId,
                command,
                schedule: scheduled.schedule,
                scheduleArtifact: scheduled.artifact,
                attempts: replicated.attempts,
                progress: replicated.progress,
                rawSeries,
                purpose,
                harnessRole: purpose,
                protocolManifest: command.protocolManifest,
            });
        const provenance = createEvidenceProvenance({
            replicationScheduleArtifact: scheduled.artifact,
            replicationCompositeArtifact,
            measurements: replicated.attempts.map((attempt) =>
                attempt.measurementProvenance),
        }, {
            purpose,
            command,
            contract: aggregate.contract,
        });
        return {
            commandId,
            observationId: this.#stableObservationId(commandId, {
                purpose,
                candidateId: command.candidateId,
                candidateEvidenceId: command.candidateEvidenceId,
                confirmationFreezeHash:
                    command.confirmationFreezeHash,
            }),
            purpose,
            candidateId: command.candidateId,
            annotations: {
                mechanism: null,
                hypothesis: null,
                expectedEffects: [],
                citedEvidenceIds: [],
                finding: null,
                ...(command.hypotheses === null
                    ? {}
                    : { hypotheses: command.hypotheses }),
            },
            receipt: {
                version: 1,
                attemptId: mainAttemptId,
                runnerEpochId: this.#config.runnerEpochId,
                rawStdoutHash: hashCanonical(
                    provenance.measurements.map((item) => ({
                        id: item.subjectId,
                        hash: item.rawStdoutHash,
                    })),
                    OBSERVATION_STREAM_HASH_ALGORITHM,
                ),
                rawStderrHash: hashCanonical(
                    provenance.measurements.map((item) => ({
                        id: item.subjectId,
                        hash: item.rawStderrHash,
                    })),
                    OBSERVATION_STREAM_HASH_ALGORITHM,
                ),
                candidateArtifactHash:
                    command.candidateArtifactHash,
                provenance,
            },
            data: {
                version: 1,
                series: [rawSeries],
            },
        };
    }

    async #runSearchCandidateCommand(aggregate, commandId, mainAttemptId, command) {
        const enumerandPlan = resolveCommandEnumerand(
            aggregate.contract,
            command,
        );
        const scheduled = this.#ensureReplicationScheduleArtifact({
            aggregate,
            commandId,
            mainAttemptId,
            command,
        });
        const schedule = scheduled.schedule;
        await this.#fault("after_replication_schedule", {
            commandId,
            candidateId: command.candidateId,
            scheduleHash: schedule.scheduleHash,
            artifactId: scheduled.artifact.artifactId,
        });
        const finiteEnumerand = enumerandPlan?.execution?.kind
            === "staged_snapshot";
        const boundedEnumerand = enumerandPlan?.execution?.kind
            === "bounded_parameter_generation";
        let request;
        let proposalEffect;
        if (finiteEnumerand) {
            proposalEffect = this.#prepareFiniteEnumerandProposal({
                aggregate,
                commandId,
                attemptId: mainAttemptId,
                command,
                enumerandPlan,
            });
            request = proposalEffect.request;
        } else if (boundedEnumerand) {
            proposalEffect = await this.#prepareBoundedEnumerandProposal({
                aggregate,
                commandId,
                attemptId: mainAttemptId,
                command,
                enumerandPlan,
            });
            request = proposalEffect.request;
        } else {
            const workerPool = this.#getWorkerPool(aggregate);
            request = this.#buildSearchRequest(
                aggregate,
                commandId,
                command,
                enumerandPlan,
            );
            this.#parentReadController.register(request);
            try {
                proposalEffect = await this.#executeEffect(
                    {
                        kind: "sdk-proposal",
                        commandId,
                        round: command.round,
                        slotIndex: command.slotIndex,
                        model: command.model,
                        operator: command.operator,
                        sessionId: request.sessionId,
                        candidateId: command.candidateId,
                        seed: command.seed,
                    },
                    async (attemptId) => {
                        const proposal = validateWorkerProposal(
                            await workerPool.propose(request),
                            request,
                            { limits: this.#config.options.candidateLimits },
                        );
                        if (proposal.candidateId !== command.candidateId) {
                            throw new CrucibleRuntimeError(
                                RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
                                "Worker proposal did not preserve the kernel-assigned candidate id",
                                {
                                    assignedCandidateId: command.candidateId,
                                    proposedCandidateId: proposal.candidateId,
                                },
                            );
                        }
                        await this.#fault("after_proposal_response", {
                            attemptId,
                            command: {
                                kind: "sdk-proposal",
                                commandId,
                                round: command.round,
                                slotIndex: command.slotIndex,
                                candidateId: command.candidateId,
                                model: command.model,
                            },
                        });
                        return proposal;
                    },
                    async (proposal, attemptId, logicalEffectKey) => {
                        const artifact = this.#persistJsonArtifact({
                            attemptId,
                            kind: `proposal-${proposal.candidateId}`,
                            value: {
                                assignment: request.promptContext.assignment,
                                promptContext: request.promptContext,
                                promptContextHash: request.promptContextHash,
                                proposal,
                            },
                            contentType: "application/vnd.crucible.candidate-proposal+json",
                        });
                        this.#ingestOperationalEvidence({
                            attemptId,
                            evidenceKind: `proposal:${proposal.candidateId}`,
                            kind: "runtime:model_proposal",
                            payload: {
                                commandId,
                                logicalEffectKey,
                                round: command.round,
                                slotIndex: command.slotIndex,
                                candidateId: proposal.candidateId,
                                model: command.model,
                                operator: command.operator,
                                parentEvidenceIds: command.parentEvidenceIds,
                                promptContextRefs: command.promptContextRefs,
                                seed: command.seed,
                                identity: proposal.identity ?? null,
                                promptContextHash: request.promptContextHash,
                                artifactId: artifact.artifactId,
                                ...(enumerandPlan === null
                                    ? {}
                                    : {
                                        enumerandBindingHash:
                                            enumerandPlan.bindingHash,
                                    }),
                            },
                        });
                        return {
                            proposalArtifact: artifact,
                            promptContextHash: request.promptContextHash,
                        };
                    },
                    async (committed, logicalEffectKey) =>
                        this.#recoverProposalEffect({
                            committed,
                            logicalEffectKey,
                            request,
                            commandId,
                            assignment: command,
                        }),
                );
            } finally {
                this.#parentReadController.unregister(request.sessionId);
            }
        }

        const proposal = proposalEffect.result;
        const proposalProvenance = proposalEffect.persisted;
        if (proposalProvenance === null
            || proposalProvenance.proposalArtifact === undefined
            || proposalProvenance.promptContextHash !== request.promptContextHash) {
            throw new RuntimeIntegrityError(
                "Proposal effect completed without durable prompt/proposal provenance",
                { commandId, candidateId: command.candidateId },
            );
        }
        const annotations = proposal.annotations;
        const persistedSnapshot = finiteEnumerand
            ? null
            : this.#loadPersistedCandidateSnapshot({
                commandId,
                command,
                proposal,
            });
        const snapshot = finiteEnumerand
            ? { snapshot: enumerandPlan.execution.artifactSnapshotHash }
            : persistedSnapshot === null
                ? this.#ingestCandidate(proposal, mainAttemptId)
                : { snapshot: persistedSnapshot.snapshotId };
        const candidateArtifactHash = measurementSnapshotHash(snapshot.snapshot);
        if (finiteEnumerand) {
            assertFiniteEnumerandSnapshot(
                enumerandPlan,
                snapshot.snapshot,
                candidateArtifactHash,
            );
        }
        this.#persistCandidateSnapshot({
            attemptId: mainAttemptId,
            commandId,
            command,
            snapshotId: snapshot.snapshot,
            candidateArtifactHash,
        });
        await this.#fault("after_candidate_snapshot", {
            attemptId: mainAttemptId,
            commandId,
            candidateId: command.candidateId,
            candidateArtifactHash,
        });

        const controlSnapshotId = await this.#resolveReplicationControlSnapshot({
            aggregate,
            commandId,
            mainAttemptId,
            command,
            schedule,
            candidateSnapshotId: snapshot.snapshot,
            enumerandPlan,
        });
        const replicated = await this.#runReplicationMeasurements({
            aggregate,
            commandId,
            command,
            schedule,
            candidateSnapshotId: snapshot.snapshot,
            controlSnapshotId,
        });
        const rawSeries = createRawMeasurementSeries({
            schedule,
            attempts: replicated.attempts,
            role: "search",
            phase: "search",
            caseId: null,
        });
        const replicationCompositeArtifact =
            this.#ensureReplicationCompositeArtifact({
                commandId,
                mainAttemptId,
                command,
                schedule,
                scheduleArtifact: scheduled.artifact,
                attempts: replicated.attempts,
                progress: replicated.progress,
                rawSeries,
            });
        await this.#fault("after_replication_composite", {
            commandId,
            candidateId: command.candidateId,
            scheduleHash: schedule.scheduleHash,
            blockCount: replicated.progress.blockCount,
            artifactId: replicationCompositeArtifact.artifactId,
        });

        const provenance = createEvidenceProvenance({
            proposalArtifact: proposalProvenance.proposalArtifact,
            promptContextHash: proposalProvenance.promptContextHash,
            replicationScheduleArtifact: scheduled.artifact,
            replicationCompositeArtifact,
            measurements: replicated.attempts.map((attempt) =>
                attempt.measurementProvenance),
        }, {
            purpose: "candidate",
            command,
            contract: aggregate.contract,
        });
        const streamItems = provenance.measurements.map((measurement) => ({
            id: measurement.subjectId,
            hash: measurement.rawStdoutHash,
        }));
        const stderrItems = provenance.measurements.map((measurement) => ({
            id: measurement.subjectId,
            hash: measurement.rawStderrHash,
        }));
        return {
            commandId,
            observationId: this.#stableObservationId(commandId, {
                purpose: "candidate",
                round: command.round,
                slotIndex: command.slotIndex,
                candidateId: command.candidateId,
            }),
            purpose: "candidate",
            round: command.round,
            slotIndex: command.slotIndex,
            candidateId: command.candidateId,
            annotations: {
                ...annotations,
                finding: annotations.finding ?? null,
            },
            receipt: {
                version: 1,
                attemptId: mainAttemptId,
                runnerEpochId: this.#config.runnerEpochId,
                rawStdoutHash: hashCanonical(
                    streamItems,
                    OBSERVATION_STREAM_HASH_ALGORITHM,
                ),
                rawStderrHash: hashCanonical(
                    stderrItems,
                    OBSERVATION_STREAM_HASH_ALGORITHM,
                ),
                candidateArtifactHash,
                provenance,
            },
            data: {
                version: 1,
                series: [rawSeries],
            },
        };
    }

    #prepareFiniteEnumerandProposal({
        aggregate,
        commandId,
        attemptId,
        command,
        enumerandPlan,
    }) {
        const archive = buildCandidateArchive(aggregate);
        const { context: promptContext, hash: promptContextHash } = buildPromptContext({
            contract: aggregate.contract,
            archive,
            plateau: detectPlateau(aggregate),
            slot: command,
        });
        const proposal = immutableCanonical({
            candidateId: command.candidateId,
            annotations: {
                mechanism:
                    `Frozen finite enumerand ordinal ${enumerandPlan.binding.ordinal} `
                    + "evaluated directly from its staged snapshot.",
                hypothesis: null,
                expectedEffects: [],
                citedEvidenceIds: [],
                finding: null,
                ...(command.hypotheses === null
                    ? {}
                    : { hypotheses: command.hypotheses }),
            },
            files: [],
            identity: {
                source: "frozen_enumerand_manifest",
                enumerandBindingHash: enumerandPlan.bindingHash,
            },
        });
        const existing = this.#adapter.listOperationalEvidence().filter((event) =>
            event.kind === "runtime:enumerand_selection"
            && event.payload?.commandId === commandId
            && event.payload?.candidateId === command.candidateId);
        if (existing.length > 1) {
            throw new RuntimeIntegrityError(
                "More than one finite-enumerand selection exists for one command",
                { commandId, candidateId: command.candidateId },
            );
        }
        if (existing.length === 1) {
            const payload = existing[0].payload;
            if (payload.enumerandBindingHash !== enumerandPlan.bindingHash
                || payload.snapshotId
                    !== enumerandPlan.execution.artifactSnapshotHash
                || payload.promptContextHash !== promptContextHash) {
                throw new RuntimeIntegrityError(
                    "Persisted finite-enumerand selection does not match the frozen command",
                    { commandId, candidateId: command.candidateId },
                );
            }
            const value = this.#readRegisteredJsonArtifact(
                payload.artifactId,
                "Persisted finite-enumerand selection",
            );
            if (!canonicalEqual(value.assignment, promptContext.assignment)
                || !canonicalEqual(value.promptContext, promptContext)
                || value.promptContextHash !== promptContextHash
                || !canonicalEqual(value.enumerand, enumerandPlan.binding)
                || !canonicalEqual(value.proposal, proposal)) {
                throw new RuntimeIntegrityError(
                    "Persisted finite-enumerand selection artifact is inconsistent",
                    { commandId, artifactId: payload.artifactId },
                );
            }
            return {
                request: {
                    promptContext,
                    promptContextHash,
                },
                result: proposal,
                persisted: {
                    proposalArtifact: this.#registeredArtifactRef(
                        payload.artifactId,
                        "Persisted finite-enumerand selection",
                    ).artifact,
                    promptContextHash,
                },
            };
        }
        const artifact = this.#persistJsonArtifact({
            attemptId,
            kind: `enumerand-selection-${command.candidateId}`,
            value: {
                assignment: promptContext.assignment,
                promptContext,
                promptContextHash,
                enumerand: enumerandPlan.binding,
                proposal,
            },
            contentType: "application/vnd.crucible.enumerand-selection+json",
        });
        this.#ingestOperationalEvidence({
            attemptId,
            evidenceKind: `enumerand-selection:${command.candidateId}`,
            kind: "runtime:enumerand_selection",
            payload: {
                commandId,
                round: command.round,
                slotIndex: command.slotIndex,
                candidateId: command.candidateId,
                enumerandOrdinal: enumerandPlan.binding.ordinal,
                enumerandHash: enumerandPlan.binding.enumerandHash,
                enumerandManifestRoot: enumerandPlan.binding.manifestRoot,
                enumerandBindingHash: enumerandPlan.bindingHash,
                snapshotId: enumerandPlan.execution.artifactSnapshotHash,
                promptContextHash,
                artifactId: artifact.artifactId,
            },
        });
        return {
            request: {
                promptContext,
                promptContextHash,
            },
            result: proposal,
            persisted: {
                proposalArtifact: artifact,
                promptContextHash,
            },
        };
    }

    async #prepareBoundedEnumerandProposal({
        aggregate,
        commandId,
        attemptId,
        command,
        enumerandPlan,
    }) {
        const archive = buildCandidateArchive(aggregate);
        const { context: promptContext, hash: promptContextHash } = buildPromptContext({
            contract: aggregate.contract,
            archive,
            plateau: detectPlateau(aggregate),
            slot: command,
        });
        const generationRequest = immutableCanonical({
            candidateId: command.candidateId,
            commandId,
            round: command.round,
            slotIndex: command.slotIndex,
            enumerandBinding: enumerandPlan.binding,
            enumerandBindingHash: enumerandPlan.bindingHash,
            parameterTuple: enumerandPlan.execution.parameterTuple,
            parameterTupleHash: enumerandPlan.execution.parameterTupleHash,
            promptContext,
            promptContextHash,
        });
        const challengeNonce = stableHex({
            investigationId: this.#config.investigationId,
            contractHash: aggregate.contractHash,
            commandId,
            enumerandBindingHash: enumerandPlan.bindingHash,
        });
        const candidateOptions = {
            challengeNonce,
            allowedCandidateIds: [command.candidateId],
            visibleEvidenceIds: command.promptContextRefs,
            observableRegistry: aggregate.contract.observableRegistry ?? [],
            hypothesisPolicy: aggregate.contract.hypothesisPolicy ?? {},
            assignedParentEvidenceIds: command.parentEvidenceIds,
            enumerandBinding: enumerandPlan.binding,
            expectedHypotheses: command.hypotheses,
            trustedParameterizedGenerator: true,
            limits: this.#config.options.candidateLimits,
        };
        const existing = this.#adapter.listOperationalEvidence().filter((event) =>
            event.kind === "runtime:enumerand_generation"
            && event.payload?.commandId === commandId
            && event.payload?.candidateId === command.candidateId);
        if (existing.length > 1) {
            throw new RuntimeIntegrityError(
                "More than one parameterized-enumerand generation exists for one command",
                { commandId, candidateId: command.candidateId },
            );
        }
        if (existing.length === 1) {
            const payload = existing[0].payload;
            if (payload.enumerandBindingHash !== enumerandPlan.bindingHash
                || payload.parameterTupleHash
                    !== enumerandPlan.execution.parameterTupleHash
                || payload.promptContextHash !== promptContextHash) {
                throw new RuntimeIntegrityError(
                    "Persisted parameterized generation does not match the frozen tuple",
                    { commandId, candidateId: command.candidateId },
                );
            }
            const value = this.#readRegisteredJsonArtifact(
                payload.artifactId,
                "Persisted parameterized-enumerand generation",
            );
            if (!canonicalEqual(value.assignment, promptContext.assignment)
                || !canonicalEqual(value.promptContext, promptContext)
                || value.promptContextHash !== promptContextHash
                || !canonicalEqual(value.generationRequest, generationRequest)) {
                throw new RuntimeIntegrityError(
                    "Persisted parameterized generation artifact is inconsistent",
                    { commandId, artifactId: payload.artifactId },
                );
            }
            const persistedProposal = value.proposal;
            if (persistedProposal?.identity?.source
                    !== "trusted_parameterized_generator"
                || persistedProposal.identity.enumerandBindingHash
                    !== enumerandPlan.bindingHash) {
                throw new RuntimeIntegrityError(
                    "Persisted parameterized proposal identity is invalid",
                    { commandId, artifactId: payload.artifactId },
                );
            }
            const candidate = validateCandidateSubmission({
                challenge: challengeNonce,
                candidateId: persistedProposal.candidateId,
                annotations: persistedProposal.annotations,
                files: persistedProposal.files,
            }, candidateOptions);
            const expectedProposal = immutableCanonical({
                ...candidate,
                identity: {
                    source: "trusted_parameterized_generator",
                    enumerandBindingHash: enumerandPlan.bindingHash,
                    generatedPayloadHash: hashCanonical(
                        candidate,
                        "sha256:crucible-parameterized-candidate-v1",
                    ),
                },
            });
            if (!canonicalEqual(persistedProposal, expectedProposal)) {
                throw new RuntimeIntegrityError(
                    "Persisted parameterized proposal payload is invalid",
                    { commandId, artifactId: payload.artifactId },
                );
            }
            return {
                request: {
                    promptContext,
                    promptContextHash,
                },
                result: expectedProposal,
                persisted: {
                    proposalArtifact: this.#registeredArtifactRef(
                        payload.artifactId,
                        "Persisted parameterized-enumerand generation",
                    ).artifact,
                    promptContextHash,
                },
            };
        }
        const generator = this.#dependencies.parameterizedCandidateGenerator;
        if (typeof generator !== "function") {
            throw new RuntimeConfigError(
                "bounded_parameterized enumerands require a trusted parameterizedCandidateGenerator",
                {
                    ordinal: enumerandPlan.binding.ordinal,
                    enumerandHash: enumerandPlan.binding.enumerandHash,
                },
            );
        }
        const generated = await generator(generationRequest);
        if (generated === null
            || typeof generated !== "object"
            || Array.isArray(generated)) {
            throw new RuntimeIntegrityError(
                "Trusted parameterized candidate generator returned a non-object",
            );
        }
        const keys = Object.keys(generated).sort();
        const expectedKeys = [
            "annotations",
            "candidateId",
            "enumerandBindingHash",
            "files",
        ];
        if (keys.length !== expectedKeys.length
            || keys.some((key, index) => key !== expectedKeys[index])) {
            throw new RuntimeIntegrityError(
                "Parameterized generator output must contain exactly candidateId, annotations, files, and enumerandBindingHash",
                { keys },
            );
        }
        if (generated.enumerandBindingHash !== enumerandPlan.bindingHash) {
            throw new RuntimeIntegrityError(
                "Parameterized generator output is bound to a different enumerand",
                {
                    expected: enumerandPlan.bindingHash,
                    actual: generated.enumerandBindingHash ?? null,
                },
            );
        }
        const candidate = validateCandidateSubmission({
            challenge: challengeNonce,
            candidateId: generated.candidateId,
            annotations: generated.annotations,
            files: generated.files,
        }, candidateOptions);
        const proposal = immutableCanonical({
            ...candidate,
            identity: {
                source: "trusted_parameterized_generator",
                enumerandBindingHash: enumerandPlan.bindingHash,
                generatedPayloadHash: hashCanonical(
                    candidate,
                    "sha256:crucible-parameterized-candidate-v1",
                ),
            },
        });
        const artifact = this.#persistJsonArtifact({
            attemptId,
            kind: `enumerand-generation-${command.candidateId}`,
            value: {
                assignment: promptContext.assignment,
                promptContext,
                promptContextHash,
                generationRequest,
                proposal,
            },
            contentType: "application/vnd.crucible.enumerand-generation+json",
        });
        this.#ingestOperationalEvidence({
            attemptId,
            evidenceKind: `enumerand-generation:${command.candidateId}`,
            kind: "runtime:enumerand_generation",
            payload: {
                commandId,
                round: command.round,
                slotIndex: command.slotIndex,
                candidateId: command.candidateId,
                enumerandOrdinal: enumerandPlan.binding.ordinal,
                enumerandHash: enumerandPlan.binding.enumerandHash,
                enumerandManifestRoot: enumerandPlan.binding.manifestRoot,
                enumerandBindingHash: enumerandPlan.bindingHash,
                parameterTupleHash: enumerandPlan.execution.parameterTupleHash,
                promptContextHash,
                artifactId: artifact.artifactId,
            },
        });
        return {
            request: {
                promptContext,
                promptContextHash,
            },
            result: proposal,
            persisted: {
                proposalArtifact: artifact,
                promptContextHash,
            },
        };
    }

    #buildSearchRequest(aggregate, commandId, command, enumerandPlan = null) {
        const contract = aggregate.contract;
        const archive = buildCandidateArchive(aggregate);
        const promptRefSet = new Set(command.promptContextRefs);
        if (command.parentEvidenceIds.some((evidenceId) => !promptRefSet.has(evidenceId))) {
            throw new RuntimeIntegrityError(
                "Kernel-authored parent evidence must be included in promptContextRefs",
                {
                    commandId,
                    parentEvidenceIds: command.parentEvidenceIds,
                    promptContextRefs: command.promptContextRefs,
                },
            );
        }

        for (const evidenceId of command.promptContextRefs) {
            const evidence = aggregate.evidence[evidenceId];
            if (evidence?.sourceKind !== "harness"
                || evidence?.purpose !== "candidate"
                || evidence.invalidated) {
                throw new RuntimeIntegrityError(
                    "Prompt context references must identify active committed candidate evidence",
                    { commandId, evidenceId },
                );
            }
        }
        const { context: promptContext, hash: promptContextHash } = buildPromptContext({
            contract,
            archive,
            plateau: detectPlateau(aggregate),
            slot: command,
        });
        const parents = command.parentEvidenceIds.map((evidenceId) => {
            const assigned = this.#resolveParentSnapshot(aggregate, evidenceId);
            return {
                parentId: evidenceId,
                snapshotId: assigned.snapshotId,
            };
        });
        const parentReadLimits = this.#parentReadLimits ?? DEFAULT_PARENT_READ_LIMITS;
        const sessionId = uuidFromHex(stableHex({
            investigationId: this.#config.investigationId,
            contractHash: aggregate.contractHash,
            commandId,
            assignment: promptContext.assignment,
            promptContextHash,
        }));
        const challengeNonce = stableHex({
            investigationId: this.#config.investigationId,
            contractHash: aggregate.contractHash,
            commandId,
            candidateId: command.candidateId,
            seed: command.seed,
            sessionId,
        });
        const prompt = buildProposalPrompt({
            objective: contract.objective,
            candidateId: command.candidateId,
            challengeNonce,
            round: command.round,
            model: command.model,
            operator: command.operator,
            promptContext,
            contextHash: promptContextHash,
            parentReadToolAvailable: parents.length > 0,
            parentReadLimits,
            trustedOperatorContext: this.#config.options.workerAdditionalContext,
            observableRegistry: contract.observableRegistry,
            hypothesisPolicy: contract.hypothesisPolicy,
            assignedParentEvidenceIds: command.parentEvidenceIds,
            expectedHypotheses: command.hypotheses,
            enumerandBinding: enumerandPlan?.binding ?? null,
        });
        const request = Object.freeze({
            candidateId: command.candidateId,
            round: command.round,
            slotIndex: command.slotIndex,
            model: command.model,
            operator: command.operator,
            parentEvidenceIds: Object.freeze([...command.parentEvidenceIds]),
            promptContextRefs: Object.freeze([...command.promptContextRefs]),
            visibleEvidenceIds: Object.freeze([...command.promptContextRefs]),
            observableRegistry: contract.observableRegistry,
            hypothesisPolicy: contract.hypothesisPolicy,
            assignedParentEvidenceIds: Object.freeze([
                ...command.parentEvidenceIds,
            ]),
            expectedHypotheses: command.hypotheses,
            seed: command.seed,
            boundedCandidateId: command.boundedCandidateId ?? null,
            promptContext,
            promptContextHash,
            parents: Object.freeze(
                parents.map((parent) => Object.freeze({ ...parent })),
            ),
            parentReadLimits,
            reasoningEffort: this.#config.options.reasoningEffort,
            deadlineMs: this.#config.deadlineMs,
            remainingBudgetMs: this.#remainingDeadlineMs(),
            sessionId,
            challengeNonce,
            allowedCandidateIds: Object.freeze([command.candidateId]),
            ...(enumerandPlan === null
                ? {}
                : {
                    enumerandBinding: enumerandPlan.binding,
                    enumerandBindingHash: enumerandPlan.bindingHash,
                }),
            prompt,
            parentReadAuthority: this.#parentReadController.authority,
        });
        if (enumerandPlan?.execution?.kind === "bounded_parameter_generation") {
            assertBoundedEnumerandRequest(enumerandPlan, request);
        }
        return request;
    }

    #persistCandidateSnapshot({
        attemptId,
        commandId,
        command,
        snapshotId,
        candidateArtifactHash,
    }) {
        const existing = this.#adapter.listOperationalEvidence().filter((event) =>
            event.kind === "runtime:candidate_snapshot"
            && event.payload?.commandId === commandId
            && event.payload?.candidateId === command.candidateId);
        if (existing.length > 1) {
            throw new RuntimeIntegrityError(
                "More than one candidate-snapshot record exists for one reserved candidate",
                { commandId, candidateId: command.candidateId },
            );
        }
        if (existing.length === 1) {
            const payload = existing[0].payload;
            if (payload.round !== command.round
                || payload.slotIndex !== command.slotIndex
                || payload.snapshotId !== snapshotId
                || payload.candidateArtifactHash !== candidateArtifactHash
                || (command.enumerand !== undefined
                    && (payload.enumerandOrdinal !== command.enumerand.ordinal
                        || payload.enumerandHash !== command.enumerand.enumerandHash
                        || payload.enumerandManifestRoot
                            !== command.enumerand.manifestRoot))
                || payload.artifactId
                    !== payload.snapshotProvenance?.manifestArtifact?.artifactId) {
                throw new RuntimeIntegrityError(
                    "Persisted candidate snapshot does not match the reserved search assignment",
                    { commandId, candidateId: command.candidateId },
                );
            }
            return this.#verifySnapshotProvenance(
                payload.snapshotProvenance,
                snapshotId,
                "Persisted candidate snapshot",
            );
        }
        const snapshotProvenance = this.#persistSnapshotProvenance({
            attemptId,
            kind: `candidate-snapshot-${command.candidateId}`,
            snapshotId,
        });
        this.#ingestOperationalEvidence({
            attemptId,
            evidenceKind: `candidate-snapshot:${command.candidateId}`,
            kind: "runtime:candidate_snapshot",
            payload: {
                commandId,
                round: command.round,
                slotIndex: command.slotIndex,
                candidateId: command.candidateId,
                snapshotId,
                candidateArtifactHash,
                ...(command.enumerand === undefined
                    ? {}
                    : {
                        enumerandOrdinal: command.enumerand.ordinal,
                        enumerandHash: command.enumerand.enumerandHash,
                        enumerandManifestRoot: command.enumerand.manifestRoot,
                    }),
                artifactId: snapshotProvenance.manifestArtifact.artifactId,
                snapshotProvenance,
            },
        });
        return snapshotProvenance;
    }

    #loadPersistedCandidateSnapshot({ commandId, command, proposal }) {
        const existing = this.#adapter.listOperationalEvidence().filter((event) =>
            event.kind === "runtime:candidate_snapshot"
            && event.payload?.commandId === commandId
            && event.payload?.candidateId === command.candidateId);
        if (existing.length === 0) {
            return null;
        }
        if (existing.length > 1) {
            throw new RuntimeIntegrityError(
                "More than one candidate-snapshot record exists for one reserved candidate",
                { commandId, candidateId: command.candidateId },
            );
        }
        const payload = existing[0].payload;
        if (payload.round !== command.round
            || payload.slotIndex !== command.slotIndex
            || typeof payload.snapshotId !== "string"
            || payload.candidateArtifactHash
                !== measurementSnapshotHash(payload.snapshotId)
            || (command.enumerand !== undefined
                && (payload.enumerandOrdinal !== command.enumerand.ordinal
                    || payload.enumerandHash !== command.enumerand.enumerandHash
                    || payload.enumerandManifestRoot
                        !== command.enumerand.manifestRoot))
            || payload.artifactId
                !== payload.snapshotProvenance?.manifestArtifact?.artifactId) {
            throw new RuntimeIntegrityError(
                "Persisted candidate snapshot does not match the reserved search assignment",
                { commandId, candidateId: command.candidateId },
            );
        }
        this.#verifySnapshotProvenance(
            payload.snapshotProvenance,
            payload.snapshotId,
            "Persisted candidate snapshot",
        );
        const manifest = this.#artifactStore.loadManifest(payload.snapshotId);
        const expectedFiles = [...proposal.files]
            .map((file) => ({ path: file.path, bytes: Buffer.from(file.content, "utf8") }))
            .sort((left, right) => compareStable(left.path, right.path));
        if (manifest.entries.length !== expectedFiles.length) {
            throw new RuntimeIntegrityError(
                "Persisted candidate snapshot file set does not match its proposal",
                { commandId, candidateId: command.candidateId },
            );
        }
        for (const [index, entry] of manifest.entries.entries()) {
            const expected = expectedFiles[index];
            const bytes = this.#artifactStore.readObject(entry.object, { verify: true });
            if (entry.path !== expected.path
                || entry.size !== expected.bytes.length
                || !bytes.equals(expected.bytes)) {
                throw new RuntimeIntegrityError(
                    "Persisted candidate snapshot bytes do not match its proposal",
                    {
                        commandId,
                        candidateId: command.candidateId,
                        path: entry.path,
                    },
                );
            }
        }
        return Object.freeze({ snapshotId: payload.snapshotId });
    }

    #findReusableMeasurement(aggregate, duplicateOf, candidateArtifactHash) {
        const seen = new Set();
        let evidence = aggregate.evidence[duplicateOf] ?? null;
        while (evidence !== null && evidence.duplicateOf !== null) {
            if (seen.has(evidence.evidenceId)) {
                return null;
            }
            seen.add(evidence.evidenceId);
            evidence = aggregate.evidence[evidence.duplicateOf] ?? null;
        }
        if (evidence === null
            || evidence.receipt?.candidateArtifactHash !== candidateArtifactHash) {
            return null;
        }
        const observation = aggregate.observations[evidence.observationId] ?? null;
        if (observation === null
            || observation.receipt?.candidateArtifactHash !== candidateArtifactHash) {
            return null;
        }

        const verifiedEntry = this.#validateHarnessContract(
            aggregate.contract,
            "search",
        ).verifiedEntry;
        const expectedDependencies = verifiedEntry.dependencies
            .map((dependency) => ({
                path: dependency.path,
                role: dependency.role,
                sha256: dependency.sha256,
            }))
            .sort((left, right) => left.path.localeCompare(right.path));
        const operational = this.#adapter.listOperationalEvidence();
        for (let index = operational.length - 1; index >= 0; index -= 1) {
            const row = operational[index];
            const payload = row.payload;
            if (row.kind !== "runtime:measurement"
                || payload?.purpose !== "candidate"
                || payload.candidateId !== evidence.candidateId
                || payload.snapshotId === undefined
                || measurementSnapshotHash(payload.snapshotId) !== candidateArtifactHash
                || !canonicalEqual(payload.parsed, observation.data)
                || payload.stdoutHash !== observation.receipt.rawStdoutHash
                || payload.stderrHash !== observation.receipt.rawStderrHash
                || hashReceipt(payload.receipt) !== payload.receiptHash
                || payload.receipt.allowlistFileHash !== verifiedEntry.allowlistFileHash
                || payload.receipt.harnessEntryHash !== verifiedEntry.entryHash
                || payload.receipt.executableHash !== verifiedEntry.executableHash
                || payload.receipt.parserVersion
                    !== aggregate.contract.harnessSuite.roles.search.parser.version
                || !receiptHasVerifiedSnapshotBytes(
                    payload.receipt,
                    candidateArtifactHash,
                )
                || !canonicalEqual(payload.receipt.dependencyHashes, expectedDependencies)
                || !canonicalEqual(
                    payload.measurementProvenance,
                    observation.receipt.provenance.measurements[0],
                )) {
                continue;
            }
            const snapshotStatus = this.#artifactStore.verifySnapshot(payload.snapshotId);
            if (!snapshotStatus.ok) {
                continue;
            }
            const receiptArtifact = this.#repository.getArtifact(payload.receiptArtifactId);
            if (receiptArtifact === null
                || receiptArtifact.durable !== true
                || receiptArtifact.hashAlgo !== "sha256"
                || typeof receiptArtifact.hashValue !== "string") {
                continue;
            }
            const receiptObjectId = `sha256:${receiptArtifact.hashValue}`;
            let receiptBytes;
            try {
                receiptBytes = this.#artifactStore.readObject(receiptObjectId, { verify: true });
            } catch {
                continue;
            }
            if (receiptArtifact.sizeBytes !== receiptBytes.length) {
                continue;
            }
            let persistedReceipt;
            try {
                persistedReceipt = JSON.parse(receiptBytes.toString("utf8"));
            } catch {
                continue;
            }
            if (!canonicalEqual(persistedReceipt, payload.receipt)) {
                continue;
            }
            try {
                const rawStdoutBytes = this.#readRegisteredBytesArtifact(
                    payload.rawStdoutArtifactId,
                    "Reusable measurement stdout",
                );
                const rawStderrBytes = this.#readRegisteredBytesArtifact(
                    payload.rawStderrArtifactId,
                    "Reusable measurement stderr",
                );
                if (sha256Bytes(rawStdoutBytes, STREAM_HASH_ALGORITHM) !== payload.stdoutHash
                    || sha256Bytes(rawStderrBytes, STREAM_HASH_ALGORITHM)
                        !== payload.stderrHash) {
                    continue;
                }
                this.#verifySnapshotProvenance(
                    payload.measurementProvenance.snapshot,
                    payload.snapshotId,
                    "Reusable measurement snapshot",
                );
            } catch {
                continue;
            }
            return {
                evidence,
                observation,
                measurementRecord: row,
                measurementProvenance: payload.measurementProvenance,
                snapshotId: payload.snapshotId,
            };
        }
        return null;
    }

    #persistDuplicateMeasurementReuse({
        attemptId,
        commandId,
        command,
        snapshotId,
        candidateArtifactHash,
        duplicateOf,
        reusable,
    }) {
        const value = {
            version: 1,
            policy: "mark",
            commandId,
            candidateId: command.candidateId,
            candidateArtifactHash,
            snapshotId,
            duplicateOf,
            sourceEvidenceId: reusable.evidence.evidenceId,
            sourceObservationId: reusable.observation.observationId,
            sourceMeasurementAttemptId: reusable.observation.receipt.attemptId,
            sourceReceiptHash: reusable.measurementRecord.payload.receiptHash,
        };
        const artifact = this.#persistJsonArtifact({
            attemptId,
            kind: `measurement-reuse-${command.candidateId}`,
            value,
            contentType: "application/vnd.crucible.measurement-reuse+json",
        });
        this.#ingestOperationalEvidence({
            attemptId,
            evidenceKind: `measurement-reuse:candidate:${command.candidateId}`,
            kind: "runtime:measurement_reuse",
            payload: {
                ...value,
                round: command.round,
                slotIndex: command.slotIndex,
                purpose: "candidate",
                parsed: reusable.observation.data,
                receipt: reusable.measurementRecord.payload.receipt,
                receiptArtifactId: reusable.measurementRecord.payload.receiptArtifactId,
                artifactId: artifact.artifactId,
            },
        });
        return { artifact };
    }

    #resolveParentSnapshot(aggregate, evidenceId) {
        const evidence = aggregate.evidence[evidenceId];
        if (evidence?.sourceKind !== "harness"
            || evidence?.purpose !== "candidate"
            || evidence.invalidated) {
            throw new RuntimeIntegrityError(
                "Assigned parent evidence is not committed candidate evidence",
                { evidenceId },
            );
        }
        const operational = this.#adapter.listOperationalEvidence();
        for (let index = operational.length - 1; index >= 0; index -= 1) {
            const row = operational[index];
            const payload = row.payload;
            if (row.kind !== "runtime:candidate_snapshot"
                || payload?.candidateId !== evidence.candidateId
                || payload.candidateArtifactHash !== evidence.receipt.candidateArtifactHash) {
                continue;
            }
            const status = this.#artifactStore.verifySnapshot(payload.snapshotId);
            if (status.ok) {
                return {
                    evidence,
                    snapshotId: payload.snapshotId,
                    status,
                };
            }
        }
        throw new RuntimeIntegrityError(
            "Assigned parent snapshot is missing or failed integrity verification",
            { evidenceId, candidateId: evidence.candidateId },
        );
    }

    #getWorkerPool(aggregate) {
        if (this.#workerPool !== null) {
            return this.#workerPool;
        }
        if (this.#parentReadController === null) {
            const parentReader = Object.freeze({
                loadManifest: (snapshotId) => {
                    const status = this.#artifactStore.verifySnapshot(snapshotId);
                    if (!status.ok) {
                        throw new RuntimeIntegrityError(
                            "Parent snapshot closure failed ArtifactStore verification",
                            { snapshotId, status },
                        );
                    }
                    return this.#artifactStore.loadManifest(snapshotId);
                },
                readObject: (objectId) =>
                    this.#artifactStore.readObject(objectId, { verify: true }),
            });
            this.#parentReadController = createBoundedParentReadAuthority({
                parentReader,
                parentReadLimits: this.#parentReadLimits,
                clock: this.#clock,
            });
        }
        if (this.#dependencies.workerPool !== undefined) {
            this.#workerPool = this.#dependencies.workerPool;
            return this.#workerPool;
        }
        const existingCandidateIds = harnessCandidateEvidenceItems(aggregate)
            .map((item) => item.candidateId);
        const factory = this.#dependencies.workerPoolFactory ?? createSdkWorkerPool;
        this.#workerPool = factory({
            sdkPath: this.#config.sdkPath,
            cliPath: this.#config.cliPath,
            baseDirectory: path.join(this.#runTempRoot, "sdk-home"),
            workingDirectory: path.join(this.#runTempRoot, "sdk-work"),
            candidateLimits: this.#config.options.candidateLimits,
            sessionTimeoutMs: this.#config.options.sessionTimeoutMs,
            shutdownTimeoutMs: this.#config.options.shutdownTimeoutMs,
            deadlineMs: this.#config.deadlineMs,
            clock: this.#clock,
            timers: this.#dependencies.timers ?? globalThis,
            existingCandidateIds,
            parentReadAuthority: this.#parentReadController.authority,
            parentReadLimits: this.#parentReadLimits,
            client: this.#dependencies.sdkClient,
            sdkLoader: this.#dependencies.sdkLoader,
            clientFactory: this.#dependencies.sdkClientFactory,
        });
        return this.#workerPool;
    }

    #ingestCandidate(proposal, attemptId) {
        this.#assertDeadlineOpen("candidate artifact ingestion");
        const sourceRoot = ensureDirectory(path.join(this.#runTempRoot, "submitted"));
        const sourceDir = makeUniqueDirectory(sourceRoot, proposal.candidateId);
        try {
            for (const file of proposal.files) {
                const target = assertPathInside(
                    path.join(sourceDir, ...file.path.split("/")),
                    sourceDir,
                    "candidate file",
                );
                fs.mkdirSync(path.dirname(target), { recursive: true });
                fs.writeFileSync(target, file.content, { encoding: "utf8", flag: "wx", mode: 0o600 });
            }
            this.#reserveDirectoryCas(
                attemptId,
                sourceDir,
                `candidate-${proposal.candidateId}`,
            );
            const snapshot = this.#artifactStore.ingestDirectory({ sourceDir });
            this.#assertDeadlineOpen("candidate artifact persistence");
            return snapshot;
        } finally {
            removeTreeInside(sourceDir, sourceRoot);
        }
    }

    #materializeSnapshot(snapshotId, label) {
        this.#assertDeadlineOpen("snapshot materialization");
        const status = this.#artifactStore.verifySnapshot(snapshotId);
        if (!status.ok) {
            throw new RuntimeIntegrityError("Snapshot closure failed verification", {
                snapshotId,
                status,
            });
        }
        const root = ensureDirectory(path.join(this.#runTempRoot, "materialized"));
        const destDir = uniqueNonexistentPath(root, label, this.#idFactory());
        const manifest = this.#artifactStore.loadManifest(snapshotId);
        let minimumBytes = manifest.totalBytes + 128;
        for (const entry of manifest.entries) {
            minimumBytes += 128 + Buffer.byteLength(entry.path, "utf8");
            if (!Number.isSafeInteger(minimumBytes)
                || minimumBytes > this.#byteBudgets.perAttemptCasBytes) {
                throw new RuntimeIntegrityError(
                    "Snapshot exceeds the per-attempt CAS/materialization byte budget",
                    {
                        snapshotId,
                        minimumBytes,
                        limit: this.#byteBudgets.perAttemptCasBytes,
                    },
                );
            }
        }
        const logicalBytes = manifest.totalBytes
            + Buffer.byteLength(canonicalJson(manifest), "utf8");
        if (!Number.isSafeInteger(logicalBytes)
            || logicalBytes > this.#byteBudgets.perAttemptCasBytes) {
            throw new RuntimeIntegrityError(
                "Snapshot exceeds the per-attempt CAS/materialization byte budget",
                {
                    snapshotId,
                    logicalBytes,
                    limit: this.#byteBudgets.perAttemptCasBytes,
                },
            );
        }
        const materialized = this.#artifactStore.materializeSnapshot({
            snapshot: snapshotId,
            destDir,
            readOnly: true,
        });
        const expectedObjectClosure = [
            ...new Set([
                snapshotId,
                ...manifest.entries.map((entry) => entry.object),
            ]),
        ].sort(compareStable);
        const result = {
            ...materialized,
            candidateSnapshot: immutableCanonical({
                path: materialized.dest,
                hash: measurementSnapshotHash(snapshotId),
                snapshotId,
                manifest,
                expectedObjectClosure,
            }),
        };
        this.#assertDeadlineOpen("snapshot materialization");
        return result;
    }

    async #persistMeasurement({
        measurement,
        rawOutput,
        attemptId,
        logicalEffectKey,
        purpose,
        commandId = null,
        round = null,
        slotIndex = null,
        candidateId,
        measurementSubjectId = candidateId,
        snapshotId,
        replication = null,
        invalid = null,
        harnessRole = "search",
        measurementPhase = purpose === "validation"
            ? "calibration"
            : "search",
    }) {
        const candidateArtifactHash = measurementSnapshotHash(snapshotId);
        if (!receiptHasVerifiedSnapshotBytes(
            measurement.receipt,
            candidateArtifactHash,
            { requireCompleteOutput: invalid === null },
        )) {
            throw new RuntimeIntegrityError(
                "Measurement receipt does not bind the exact executed candidate bytes",
                {
                    candidateId,
                    snapshotId,
                    candidateArtifactHash,
                    receiptCandidateSnapshotHash:
                        measurement.receipt?.candidateSnapshotHash ?? null,
                },
            );
        }
        if (replication !== null) {
            const expectedBinding = {
                role: harnessRole,
                phase: measurementPhase,
                replicateIndex: replication.replicateIndex,
                blockIndex: replication.blockIndex,
                armIndex: replication.armIndex,
                armId: replication.armId,
                deterministicSeed: replication.deterministicSeed,
                subjectId: replication.subjectId,
                environmentIdentity:
                    this.#contract.harnessSuite.environmentIdentity,
                suiteIdentity: this.#contract.harnessSuiteIdentity,
            };
            const actualBinding = Object.fromEntries(
                Object.keys(expectedBinding).map((key) => [
                    key,
                    measurement.receipt?.[key] ?? null,
                ]),
            );
            if (measurement.receipt?.version !== HARNESS_SUITE_RECEIPT_VERSION
                || !canonicalEqual(actualBinding, expectedBinding)) {
                throw new RuntimeIntegrityError(
                    "Measurement receipt does not match the scheduled replicate binding",
                    {
                        expectedBinding,
                        actualBinding,
                    },
                );
            }
        }
        if (rawOutput === null
            || !Buffer.isBuffer(rawOutput.stdout)
            || !Buffer.isBuffer(rawOutput.stderr)
            || sha256Bytes(rawOutput.stdout, STREAM_HASH_ALGORITHM)
                !== measurement.stdoutHash
            || sha256Bytes(rawOutput.stderr, STREAM_HASH_ALGORITHM)
                !== measurement.stderrHash) {
            throw new RuntimeIntegrityError(
                "Measurement raw output bytes do not match the trusted receipt",
                { attemptId, candidateId },
            );
        }
        const receiptArtifact = this.#persistJsonArtifact({
            attemptId,
            kind: `measurement-receipt-${measurementSubjectId}`,
            value: measurement.receipt,
            contentType: "application/vnd.crucible.measurement-receipt+json",
        });
        await this.#fault("after_measurement_receipt_persistence", {
            attemptId,
            logicalEffectKey,
            purpose,
            harnessRole,
            measurementPhase,
            commandId,
            candidateId,
            artifactId: receiptArtifact.artifactId,
            objectId: receiptArtifact.objectId,
        });
        const rawStdoutArtifact = this.#persistBytesArtifact({
            attemptId,
            kind: `measurement-stdout-${measurementSubjectId}`,
            bytes: rawOutput.stdout,
            contentType: "application/vnd.crucible.measurement-stdout",
        });
        const rawStderrArtifact = this.#persistBytesArtifact({
            attemptId,
            kind: `measurement-stderr-${measurementSubjectId}`,
            bytes: rawOutput.stderr,
            contentType: "application/vnd.crucible.measurement-stderr",
        });
        const snapshot = this.#persistSnapshotProvenance({
            attemptId,
            kind: `measurement-snapshot-${measurementSubjectId}`,
            snapshotId,
        });
        const measurementProvenance = createMeasurementProvenance({
            subjectId: measurementSubjectId,
            role: measurement.receipt.role ?? harnessRole,
            phase: measurement.receipt.phase ?? measurementPhase,
            receiptArtifact,
            receiptHash: hashReceipt(measurement.receipt),
            rawStdoutArtifact,
            rawStdoutHash: measurement.stdoutHash,
            rawStderrArtifact,
            rawStderrHash: measurement.stderrHash,
            parserVersion: measurement.receipt.parserVersion,
            allowlistFileHash: measurement.receipt.allowlistFileHash,
            harnessEntryHash: measurement.receipt.harnessEntryHash,
            executableHash: measurement.receipt.executableHash,
            stagedExecutableHash: measurement.receipt.stagedExecutableHash,
            dependencyHashes: measurement.receipt.dependencyHashes,
            stagedDependencyHashes: measurement.receipt.stagedDependencyHashes,
            argvHash: measurement.receipt.argvHash,
            envHash: measurement.receipt.envHash,
            sandboxPolicy: measurement.receipt.sandbox === null
                ? {
                    kind: "none",
                    sandboxId: null,
                    environmentHash: null,
                }
                : {
                    kind: "sandbox",
                    sandboxId: measurement.receipt.sandbox.sandboxId,
                    environmentHash: measurement.receipt.sandbox.environmentHash,
                },
            snapshot,
            snapshotExecutionHash: snapshotExecutionHash(measurement.receipt),
        });
        this.#ingestOperationalEvidence({
            attemptId,
            evidenceKind: replication === null
                ? `measurement:${purpose}:${measurementSubjectId}`
                : `measurement:${purpose}:${replication.blockIndex}:${
                    replication.armIndex
                }`,
            kind: "runtime:measurement",
            payload: {
                logicalEffectKey,
                purpose,
                harnessRole,
                measurementPhase,
                commandId,
                round,
                slotIndex,
                candidateId,
                measurementSubjectId,
                candidateArtifactHash,
                parsed: measurement.parsed,
                invalid,
                replication,
                receipt: measurement.receipt,
                receiptHash: hashReceipt(measurement.receipt),
                receiptArtifactId: receiptArtifact.artifactId,
                rawStdoutArtifactId: rawStdoutArtifact.artifactId,
                rawStderrArtifactId: rawStderrArtifact.artifactId,
                snapshotId,
                stdoutHash: measurement.stdoutHash,
                stderrHash: measurement.stderrHash,
                measurementProvenance,
            },
        });
        return {
            measurementProvenance,
            receiptArtifact,
            rawStdoutArtifact,
            rawStderrArtifact,
            snapshot,
        };
    }

    async #persistImpossibilityVerification({
        result,
        attemptId,
        logicalEffectKey,
        commandId,
        command,
        snapshotId,
    }) {
        const persistedMeasurement = await this.#persistMeasurement({
            measurement: result.measurement,
            rawOutput: {
                stdout: result.rawStdoutBytes,
                stderr: result.rawStderrBytes,
            },
            attemptId,
            logicalEffectKey,
            purpose: "impossibility",
            commandId,
            candidateId: `impossibility-${command.attemptOrdinal}`,
            snapshotId,
            harnessRole: "impossibility_verifier",
            measurementPhase: "impossibility_verification",
        });
        const measurementReceiptBytes = Buffer.from(
            canonicalJson(result.measurement.receipt),
            "utf8",
        );
        const receiptArtifactHash = taggedHash(
            IMPOSSIBILITY_RECEIPT_ARTIFACT_HASH_ALGORITHM,
            measurementReceiptBytes,
        );
        if (receiptArtifactHash !== result.measurementReceiptArtifactHash) {
            throw new RuntimeIntegrityError(
                "Impossibility measurement receipt artifact hash changed before persistence",
                { attemptId },
            );
        }
        const certificateArtifact = this.#persistJsonArtifact({
            attemptId,
            kind: `impossibility-certificate-${command.attemptOrdinal}`,
            value: result.certificate,
            contentType: "application/vnd.crucible.impossibility-certificate+json",
        });
        if (taggedHash(
            IMPOSSIBILITY_STDOUT_ARTIFACT_HASH_ALGORITHM,
            result.rawStdoutBytes,
        ) !== result.rawStdoutArtifactHash
            || taggedHash(
                IMPOSSIBILITY_STDERR_ARTIFACT_HASH_ALGORITHM,
                result.rawStderrBytes,
            ) !== result.rawStderrArtifactHash
            || taggedHash(
                IMPOSSIBILITY_CERTIFICATE_ARTIFACT_HASH_ALGORITHM,
                result.certificateBytes,
            ) !== result.certificateArtifactHash) {
            throw new RuntimeIntegrityError(
                "Impossibility artifact hashes changed before persistence",
                { attemptId },
            );
        }
        this.#ingestOperationalEvidence({
            attemptId,
            evidenceKind: `impossibility-certificate:${command.attemptOrdinal}`,
            kind: "runtime:impossibility_certificate",
            payload: {
                logicalEffectKey,
                commandId,
                attemptOrdinal: command.attemptOrdinal,
                requestHash: command.requestHash,
                proposedCertificateArtifactHash:
                    command.proposedCertificateArtifactHash,
                proofArtifactHash: command.proofArtifactHash,
                objectManifestRoot:
                    command.request.objectManifest.root,
                snapshotId,
                verificationSnapshotHash: result.verificationSnapshotHash,
                checkerStatus: result.checkerStatus,
                certificateVerdict: result.certificateVerdict,
                certificateArtifactHash: result.certificateArtifactHash,
                certificateArtifactId: certificateArtifact.artifactId,
                measurementReceiptHash: result.measurementReceiptHash,
                measurementReceiptArtifactHash: result.measurementReceiptArtifactHash,
                measurementReceiptArtifactId:
                    persistedMeasurement.receiptArtifact.artifactId,
                rawStdoutArtifactHash: result.rawStdoutArtifactHash,
                rawStdoutArtifactId: persistedMeasurement.rawStdoutArtifact.artifactId,
                rawStderrArtifactHash: result.rawStderrArtifactHash,
                rawStderrArtifactId: persistedMeasurement.rawStderrArtifact.artifactId,
                measurementProvenance: persistedMeasurement.measurementProvenance,
            },
        });
        return {
            measurementProvenance: persistedMeasurement.measurementProvenance,
            certificateArtifact,
        };
    }

    #persistSnapshotProvenance({ attemptId, kind, snapshotId }) {
        this.#assertDeadlineOpen("snapshot provenance persistence");
        const status = this.#artifactStore.verifySnapshot(snapshotId);
        if (!status.ok) {
            throw new RuntimeIntegrityError(
                "Snapshot closure failed verification before provenance persistence",
                { snapshotId, status },
            );
        }
        const manifest = this.#artifactStore.loadManifest(snapshotId);
        const manifestBytes = this.#artifactStore.readObject(snapshotId, { verify: true });
        const manifestArtifact = this.#registerCasObject({
            attemptId,
            kind: `${kind}-manifest`,
            objectId: snapshotId,
            size: manifestBytes.length,
            contentType: "application/vnd.crucible.snapshot+json",
        });
        const byObjectId = new Map();
        for (const entry of manifest.entries) {
            byObjectId.set(entry.object, entry.size);
        }
        const objectArtifacts = [...byObjectId.entries()]
            .sort(([left], [right]) => compareStable(left, right))
            .map(([objectId, size], index) => {
                const verified = this.#artifactStore.readObject(objectId, { verify: true });
                if (verified.length !== size) {
                    throw new RuntimeIntegrityError(
                        "Snapshot object size changed before provenance persistence",
                        { snapshotId, objectId, expectedSize: size, actualSize: verified.length },
                    );
                }
                return this.#registerCasObject({
                    attemptId,
                    kind: `${kind}-object-${String(index).padStart(6, "0")}`,
                    objectId,
                    size,
                    contentType: "application/octet-stream",
                });
            });
        const provenance = createSnapshotProvenance({
            snapshotHash: measurementSnapshotHash(snapshotId),
            manifestArtifact,
            objectArtifacts,
        });
        this.#assertDeadlineOpen("snapshot provenance persistence");
        return provenance;
    }

    #seedByteUsage() {
        const seenArtifacts = new Set();
        for (const ref of this.#repository.listArtifactRefs(
            this.#config.investigationId,
        )) {
            if (seenArtifacts.has(ref.artifactId)) continue;
            seenArtifacts.add(ref.artifactId);
            const artifact = this.#repository.getArtifact(ref.artifactId);
            if (artifact === null
                || artifact.investigationId !== this.#config.investigationId
                || !Number.isSafeInteger(artifact.sizeBytes)
                || artifact.sizeBytes < 0) {
                continue;
            }
            if (artifact.contentType
                === "application/vnd.crucible.measurement-stdout"
                || artifact.contentType
                    === "application/vnd.crucible.measurement-stderr") {
                this.#investigationByteUsage.outputBytes += artifact.sizeBytes;
            } else if (artifact.contentType
                === "application/vnd.crucible.measurement-receipt+json") {
                this.#investigationByteUsage.receiptBytes += artifact.sizeBytes;
            }
            if (artifact.storage === "external"
                && artifact.hashAlgo === "sha256"
                && typeof artifact.hashValue === "string") {
                const objectId = `sha256:${artifact.hashValue}`;
                if (!this.#countedCasObjects.has(objectId)) {
                    this.#countedCasObjects.add(objectId);
                    this.#investigationByteUsage.casBytes += artifact.sizeBytes;
                }
            }
        }
        if (this.#investigationByteUsage.outputBytes
                > this.#byteBudgets.perInvestigationOutputBytes
            || this.#investigationByteUsage.receiptBytes
                > this.#byteBudgets.perInvestigationReceiptBytes
            || this.#investigationByteUsage.casBytes
                > this.#byteBudgets.perInvestigationCasBytes) {
            throw new RuntimeIntegrityError(
                "Persisted investigation artifacts already exceed the runtime byte budgets",
                {
                    usage: this.#investigationByteUsage,
                    limits: this.#byteBudgets,
                },
            );
        }
    }

    #reserveCasBytes(attemptId, bytes, objectId, kind) {
        if (!Number.isSafeInteger(bytes) || bytes < 0) {
            throw new RuntimeIntegrityError(
                "CAS byte reservation is invalid",
                { attemptId, bytes, objectId, kind },
            );
        }
        if (this.#countedCasObjects.has(objectId)) return;
        const attemptBytes = (this.#attemptCasBytes.get(attemptId) ?? 0) + bytes;
        const investigationBytes =
            this.#investigationByteUsage.casBytes + bytes;
        if (!Number.isSafeInteger(attemptBytes)
            || !Number.isSafeInteger(investigationBytes)
            || attemptBytes > this.#byteBudgets.perAttemptCasBytes
            || investigationBytes
                > this.#byteBudgets.perInvestigationCasBytes) {
            throw new RuntimeIntegrityError(
                "Runtime CAS byte budget exceeded before artifact persistence",
                {
                    attemptId,
                    kind,
                    objectId,
                    bytes,
                    attemptBytes,
                    attemptLimit:
                        this.#byteBudgets.perAttemptCasBytes,
                    investigationBytes,
                    investigationLimit:
                        this.#byteBudgets.perInvestigationCasBytes,
                },
            );
        }
        this.#attemptCasBytes.set(attemptId, attemptBytes);
        this.#investigationByteUsage.casBytes = investigationBytes;
        this.#countedCasObjects.add(objectId);
    }

    #reserveDirectoryCas(attemptId, sourceDir, kind) {
        const entries = [];
        const walk = (directory, segments = []) => {
            const dirents = fs.readdirSync(directory, { withFileTypes: true })
                .sort((left, right) => compareStable(left.name, right.name));
            for (const dirent of dirents) {
                const absolute = path.join(directory, dirent.name);
                const childSegments = [...segments, dirent.name];
                if (dirent.isDirectory()) {
                    walk(absolute, childSegments);
                    continue;
                }
                if (!dirent.isFile()) {
                    throw new RuntimeIntegrityError(
                        "CAS reservation encountered a non-regular candidate entry",
                        { path: absolute },
                    );
                }
                const bytes = fs.readFileSync(absolute);
                entries.push({
                    path: childSegments.join("/"),
                    size: bytes.length,
                    object: `sha256:${sha256Hex(bytes)}`,
                });
            }
        };
        walk(sourceDir);
        entries.sort((left, right) => compareStable(left.path, right.path));
        const manifest = {
            type: "crucible-snapshot",
            version: 1,
            algo: "sha256",
            fileCount: entries.length,
            totalBytes: entries.reduce((total, entry) => total + entry.size, 0),
            entries,
        };
        const manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
        const objects = [
            ...entries.map((entry) => ({
                id: entry.object,
                size: entry.size,
            })),
            {
                id: `sha256:${sha256Hex(manifestBytes)}`,
                size: manifestBytes.length,
            },
        ];
        const unique = new Map();
        for (const object of objects) {
            unique.set(object.id, object);
        }
        for (const object of unique.values()) {
            this.#reserveCasBytes(
                attemptId,
                object.size,
                object.id,
                kind,
            );
        }
    }

    #persistJsonArtifact({ attemptId, kind, value, contentType }) {
        const bytes = Buffer.from(canonicalJson(value), "utf8");
        return this.#persistBytesArtifact({
            attemptId,
            kind,
            bytes,
            contentType,
        });
    }

    #persistBytesArtifact({ attemptId, kind, bytes, contentType }) {
        this.#assertDeadlineOpen("artifact persistence");
        const expectedObjectId = `sha256:${sha256Hex(bytes)}`;
        this.#reserveCasBytes(
            attemptId,
            bytes.length,
            expectedObjectId,
            kind,
        );
        const stored = this.#artifactStore.putBytes(bytes, { contentType });
        if (stored.id !== expectedObjectId || stored.size !== bytes.length) {
            throw new RuntimeIntegrityError(
                "ArtifactStore returned an unexpected CAS identity",
                {
                    kind,
                    expectedObjectId,
                    actualObjectId: stored.id,
                    expectedSize: bytes.length,
                    actualSize: stored.size,
                },
            );
        }
        const registered = this.#registerCasObject({
            attemptId,
            kind,
            objectId: stored.id,
            size: stored.size,
            contentType,
        });
        this.#assertDeadlineOpen("artifact persistence");
        return registered;
    }

    #registerCasObject({ attemptId, kind, objectId, size, contentType }) {
        this.#assertDeadlineOpen("artifact registration");
        const artifactId = `runtime-${stableHex({
            investigationId: this.#config.investigationId,
            attemptId,
            kind,
            objectId,
        }).slice(0, 40)}`;
        const existing = this.#repository.getArtifact(artifactId);
        if (existing === null) {
            this.#repository.registerExternalArtifact({
                investigationId: this.#config.investigationId,
                artifactId,
                algo: "sha256",
                hash: snapshotObjectHex(objectId),
                sizeBytes: size,
                contentType,
            });
            this.#repository.markArtifactDurable(artifactId);
        } else {
            if (existing.hashValue !== snapshotObjectHex(objectId)
                || existing.investigationId !== this.#config.investigationId
                || existing.storage !== "external"
                || existing.hashAlgo !== "sha256"
                || existing.sizeBytes !== size
                || existing.contentType !== contentType) {
                throw new RuntimeIntegrityError("Artifact id collision", {
                    artifactId,
                    objectId,
                });
            }
            if (existing.durable !== true) {
                this.#artifactStore.readObject(objectId, { verify: true });
                this.#repository.markArtifactDurable(artifactId);
            }
        }
        this.#assertDeadlineOpen("artifact registration");
        return { artifactId, objectId };
    }

    #recordDeadlineNonResult(aggregate, cause = null) {
        const currentRecommendation = decideNext(aggregate);
        let domainPausePersisted = false;
        let deadlineStopRequestSeq = null;
        try {
            const requested = this.#requestStopFenced({
                requestId: this.#nextStableId("stop", { reason: "deadline" }),
                reason: "Autonomous runner deadline reached.",
                pauseRequested: true,
            });
            if (requested.domainEvent !== null) {
                deadlineStopRequestSeq = requested.domainEvent.seq;
                const afterStop = requested.aggregate;
                const recommendation = decideNext(afterStop);
                if (recommendation.event?.type === EVENT_TYPES.INVESTIGATION_PAUSED) {
                    this.#appendKernelDecisionFenced({ deadlineExempt: true });
                    domainPausePersisted = true;
                }
            }
        } catch (error) {
            if (error?.code !== RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID) {
                throw error;
            }
        }
        this.#recordOperationalNonResultFenced({
            scope: "deadline",
            code: "DEADLINE_EXCEEDED",
            reason: "The wall-clock deadline expired before a terminal result.",
            details: {
                deadlineMs: this.#config.deadlineMs,
                observedAt: this.#clock.isoNow(),
                domainPausePersisted,
                deadlineStopRequestSeq,
                terminalEmitted: false,
                terminalRecommendationSuppressed:
                    currentRecommendation.kind === "TERMINAL",
                stage: cause?.details?.stage ?? null,
                causeCode: cause?.code ?? null,
            },
        });
        return {
            kind: "NON_RESULT",
            code: "DEADLINE_EXCEEDED",
            reason: "The wall-clock deadline expired before a terminal result.",
            persisted: true,
            domainPausePersisted,
            terminalEmitted: false,
        };
    }

    async #cleanup() {
        let firstError = null;
        const nonQuiescentFailures = [];
        this.#capturedOutputs.clear();
        this.#effectEvidenceBuffers.clear();
        this.#attemptCommands.clear();
        if (this.#executor !== null && typeof this.#executor.close === "function") {
            const outcome = await settleWithin(
                () => this.#executor.close({
                    timeoutMs: this.#config.options.shutdownTimeoutMs,
                }),
                this.#config.options.shutdownTimeoutMs,
                { timers: this.#dependencies.timers ?? globalThis },
            );
            if (outcome.status === "rejected") {
                firstError ??= outcome.error;
                nonQuiescentFailures.push({
                    component: "executor.close",
                    status: outcome.status,
                    error: outcome.error?.message ?? null,
                });
            } else if (outcome.status === "timed_out") {
                const error = new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
                    "Runner external-effect process cleanup exceeded its final shutdown bound",
                    { timeoutMs: this.#config.options.shutdownTimeoutMs },
                );
                firstError ??= error;
                nonQuiescentFailures.push({
                    component: "executor.close",
                    status: outcome.status,
                    error: error.message,
                });
            }
        }
        if (this.#workerPool !== null && typeof this.#workerPool.close === "function") {
            const outcome = await settleWithin(
                () => this.#workerPool.close(),
                this.#config.options.shutdownTimeoutMs,
                { timers: this.#dependencies.timers ?? globalThis },
            );
            if (outcome.status === "rejected") {
                firstError ??= outcome.error;
                nonQuiescentFailures.push({
                    component: "workerPool.close",
                    status: outcome.status,
                    error: outcome.error?.message ?? null,
                });
            } else if (outcome.status === "timed_out") {
                const error = new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
                    "Runner worker-pool cleanup exceeded its final shutdown bound",
                    { timeoutMs: this.#config.options.shutdownTimeoutMs },
                );
                firstError ??= error;
                nonQuiescentFailures.push({
                    component: "workerPool.close",
                    status: outcome.status,
                    error: error.message,
                });
            }
        }
        this.#parentReadController?.close();
        if (this.#repository !== null) {
            try {
                this.#repository.close();
            } catch (error) {
                firstError ??= error;
            }
        }
        if (this.#runTempRoot !== null && nonQuiescentFailures.length === 0) {
            try {
                removeTreeInside(this.#runTempRoot, this.#config.options.tempRoot);
            } catch (error) {
                firstError ??= error;
            }
        }
        if (nonQuiescentFailures.length > 0) {
            return new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.NON_QUIESCENT,
                "Runner cleanup could not prove that every worker and child process stopped",
                {
                    failures: nonQuiescentFailures,
                    retainedTempRoot: this.#runTempRoot,
                    firstError: firstError === null
                        ? null
                        : {
                            name: firstError?.name ?? "Error",
                            code: firstError?.code ?? null,
                            message: firstError?.message ?? String(firstError),
                        },
                    pausePending: true,
                },
                firstError === null ? undefined : { cause: firstError },
            );
        }
        if (firstError === null || typeof firstError?.code === "string") {
            return firstError;
        }
        return new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
            `Runner cleanup failed: ${firstError?.message ?? String(firstError)}`,
            {
                name: firstError?.name ?? "Error",
            },
            { cause: firstError },
        );
    }
}

export async function runAutonomousInvestigation(config, dependencies = {}) {
    const runner = new AutonomousRunner(config, dependencies);
    const result = await runner.run();
    if (runner.config.resultPath !== null) {
        atomicWriteJson(runner.config.resultPath, projectRunnerOutcome(result));
    }
    return result;
}
