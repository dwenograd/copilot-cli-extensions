import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

import {
    EVENT_TYPES,
    NON_RESULT_CODES,
    acceptanceSatisfied,
    candidateMetricValues,
    canonicalJson,
    createExternalEvent,
    decideNext,
    hashCanonical,
    harnessCandidateEvidenceItems,
} from "../domain/index.mjs";
import {
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";
import {
    PARSER_VERSION,
    createMeasurementExecutor,
    hashReceipt,
    loadHarnessAllowlist,
} from "../measurement/index.mjs";
import { normalizeRunnerConfig } from "./config.mjs";
import { createDomainRepositoryAdapter, formatAttemptCommand } from "./domain-adapter.mjs";
import {
    CrucibleRuntimeError,
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
    RuntimeIntegrityError,
} from "./errors.mjs";
import {
    buildProposalPrompt,
    createSdkWorkerPool,
} from "./worker-pool.mjs";
import {
    assertPathInside,
    atomicWriteJson,
    ensureDirectory,
    makeUniqueDirectory,
    measurementSnapshotHash,
    removeTreeInside,
    sha256Hex,
    snapshotObjectHex,
} from "./utils.mjs";

const VALIDATION_RECEIPT_HASH_ALGORITHM = "sha256:crucible-runtime-validation-receipts-v1";
const OBSERVATION_STREAM_HASH_ALGORITHM = "sha256:crucible-runtime-observation-streams-v1";

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

function compareMetricCandidates(metrics, left, right) {
    for (const metric of metrics) {
        const epsilon = metric.epsilon > 0 ? metric.epsilon : 0;
        let leftValue = left.metricValues[metric.key];
        let rightValue = right.metricValues[metric.key];
        if (epsilon > 0) {
            leftValue = Math.round(leftValue / epsilon);
            rightValue = Math.round(rightValue / epsilon);
        }
        if (leftValue === rightValue) {
            continue;
        }
        return metric.direction === "min"
            ? leftValue - rightValue
            : rightValue - leftValue;
    }
    return left.proposal.candidateId.localeCompare(right.proposal.candidateId);
}

function selectCandidate(contract, candidates) {
    const accepted = candidates
        .filter((candidate) => candidate.accepted)
        .sort((left, right) => compareMetricCandidates(contract.metrics, left, right));
    if (accepted.length > 0) {
        return accepted[0];
    }
    return [...candidates].sort((left, right) =>
        left.proposal.candidateId.localeCompare(right.proposal.candidateId))[0] ?? null;
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

export class AutonomousRunner {
    #config;
    #dependencies;
    #repository = null;
    #adapter = null;
    #artifactStore = null;
    #allowlist = null;
    #executor = null;
    #workerPool = null;
    #lease = null;
    #recovery = null;
    #runTempRoot = null;
    #attemptCounter = 0;
    #clock;

    constructor(config, dependencies = {}) {
        this.#config = normalizeRunnerConfig(config, { env: dependencies.env ?? process.env });
        this.#dependencies = dependencies;
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
            this.#initialize();
            result = await this.#runLoop();
        } catch (error) {
            thrown = error;
        } finally {
            const cleanupError = await this.#cleanup();
            if (thrown === null && cleanupError !== null) {
                thrown = cleanupError;
            }
        }
        if (thrown !== null) {
            if (result !== undefined) {
                const cleanupFailure = new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
                    `Autonomous runner cleanup failed: ${thrown?.message ?? String(thrown)}`,
                    {
                        name: thrown?.name ?? "Error",
                        code: thrown?.code ?? null,
                    },
                    { cause: thrown },
                );
                cleanupFailure.recoverable = true;
                throw cleanupFailure;
            }
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
            recovery: this.#recovery,
            tempRootCleaned: this.#runTempRoot === null || !fs.existsSync(this.#runTempRoot),
        };
    }

    #initialize() {
        const stateDir = ensureDirectory(this.#config.stateDir);
        const artifactRoot = ensureDirectory(this.#config.artifactRoot);

        const repositoryFactory = this.#dependencies.repositoryFactory ?? openRepository;
        this.#repository = repositoryFactory({
            file: path.join(stateDir, "events.sqlite"),
            now: () => this.#clock.isoNow(),
        });
        this.#adapter = createDomainRepositoryAdapter({
            repository: this.#repository,
            investigationId: this.#config.investigationId,
        });
        const opened = this.#adapter.replay();
        if (opened.domainEvents.length === 0 || opened.aggregate.contract === null) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.INVESTIGATION_NOT_OPEN,
                "The runner requires an existing investigation_opened domain event",
                { investigationId: this.#config.investigationId },
            );
        }
        const operationalNonResult = this.#adapter.latestOperationalNonResult();

        const artifactStoreFactory = this.#dependencies.artifactStoreFactory ?? openArtifactStore;
        this.#artifactStore = artifactStoreFactory({ root: artifactRoot });
        if (opened.aggregate.terminal !== null
            || opened.aggregate.pause !== null
            || opened.aggregate.nonResults.length > 0
            || operationalNonResult !== null
            || this.#deadlineReached()) {
            return;
        }

        const tempRoot = ensureDirectory(this.#config.options.tempRoot);
        this.#runTempRoot = makeUniqueDirectory(
            tempRoot,
            `run-${this.#config.runnerEpochId}`,
        );
        const allowlistLoader = this.#dependencies.allowlistLoader ?? loadHarnessAllowlist;
        this.#allowlist = allowlistLoader(this.#config.allowlistPath);
        this.#validateHarnessContract(opened.aggregate.contract);
        this.#recordCapabilityEpoch(opened.aggregate);

        this.#executor = this.#dependencies.executor
            ?? (this.#dependencies.executorFactory ?? createMeasurementExecutor)({
                allowlist: this.#allowlist,
                sandboxProvider: this.#dependencies.sandboxProvider ?? null,
                processAdapter: this.#dependencies.processAdapter,
                clock: this.#clock,
                scratchRoot: this.#runTempRoot,
            });

        const previousLease = this.#repository.getActiveLease(this.#config.investigationId);
        const leaseGeneration = (previousLease?.fencingToken ?? 0) + 1;
        const leaseId = this.#nextStableId("lease", {
            epoch: this.#config.runnerEpochId,
            leaseGeneration,
            previousLeaseId: previousLease?.leaseId ?? null,
            nonce: this.#idFactory()(),
        });
        const owner = `runner-${this.#config.runnerEpochId}-${process.pid}`;
        const acquired = this.#adapter.acquireRunnerLease({ leaseId, owner });
        this.#lease = acquired.lease;
        this.#recovery = acquired.recovery;
    }

    #recordCapabilityEpoch(aggregate) {
        if (aggregate.terminal !== null
            || aggregate.pause !== null
            || aggregate.nonResults.length > 0) {
            return;
        }
        const capabilities = [
            "crucible-autonomous-runtime",
            `harness:${aggregate.contract.harnessId}`,
            `parser:${aggregate.contract.parserVersion}`,
            `allowlist:${this.#allowlist.contentHash}`,
            ...aggregate.contract.workerModels.map((model) => `model:${model}`),
        ].sort();
        this.#adapter.appendFromFactory((current) => {
            const existing = current.capabilityEpochs[this.#config.runnerEpochId];
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
                return null;
            }
            return createExternalEvent(current, EVENT_TYPES.CAPABILITY_EPOCH_RECORDED, {
                epochId: this.#config.runnerEpochId,
                capabilities,
            });
        });
    }

    #validateHarnessContract(contract) {
        if (contract.parserVersion !== PARSER_VERSION) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                "Frozen contract parserVersion does not match the trusted measurement parser",
                { contract: contract.parserVersion, runtime: PARSER_VERSION },
            );
        }
        const entry = this.#allowlist.getEntry(contract.harnessId);
        if (entry.validationCases === null) {
            throw new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                "Allowlist entry must pin every frozen validation case",
                { harnessId: contract.harnessId },
            );
        }
        for (const validationCase of contract.validationCases) {
            const allowlisted = entry.validationCases[validationCase.id];
            if (allowlisted === undefined
                || allowlisted.snapshotHash !== validationCase.artifactHash) {
                throw new CrucibleRuntimeError(
                    RUNTIME_ERROR_CODES.HARNESS_CONFIGURATION_INVALID,
                    "Allowlist validation snapshot does not match the immutable contract",
                    {
                        caseId: validationCase.id,
                        contractArtifactHash: validationCase.artifactHash,
                        allowlistSnapshotHash: allowlisted?.snapshotHash ?? null,
                    },
                );
            }
        }
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

    async #fault(point, details = {}) {
        if (typeof this.#dependencies.faultInjector === "function") {
            await this.#dependencies.faultInjector(point, details);
        }
    }

    #deadlineReached() {
        return this.#config.deadlineMs !== null && this.#clock.now() >= this.#config.deadlineMs;
    }

    async #runLoop() {
        for (let iteration = 0; iteration < this.#config.options.maxLoopIterations; iteration += 1) {
            const { aggregate } = this.#adapter.replay();
            if (aggregate.terminal !== null) {
                return terminalResult(aggregate);
            }
            if (aggregate.pause !== null) {
                return pauseResult(aggregate);
            }
            if (aggregate.nonResults.length > 0) {
                return nonResult(aggregate);
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
                this.#adapter.appendKernelDecision();
                continue;
            }
            if (recommendation.kind !== "COMMAND") {
                throw new RuntimeIntegrityError("Kernel returned an unsupported recommendation", {
                    recommendation,
                });
            }

            switch (recommendation.command.kind) {
                case "dispatch_reserved":
                case "await_observation":
                    await this.#executeDomainCommand(aggregate, recommendation);
                    break;
                case "commit_evidence":
                    this.#adapter.appendEvidenceCommit({
                        evidenceId: recommendation.command.evidenceId,
                        observationId: recommendation.command.observationId,
                    });
                    await this.#fault("after_evidence_commit", {
                        commandId: recommendation.commandId,
                        observationId: recommendation.command.observationId,
                    });
                    break;
                case "await_stop_request":
                    if (this.#deadlineReached()) {
                        return this.#recordDeadlineNonResult(aggregate);
                    }
                    this.#adapter.requestStop({
                        requestId: this.#nextStableId("stop", {
                            reason: "bounded-search-exhausted",
                        }),
                        reason: "Autonomous runner confirmed the frozen bounded search space is exhausted.",
                        pauseRequested: false,
                    });
                    break;
                default:
                    throw new RuntimeIntegrityError(
                        "Kernel returned an operational command the runner does not implement",
                        { command: recommendation.command },
                    );
            }
        }
        throw new CrucibleRuntimeError(
            RUNTIME_ERROR_CODES.CHILD_CRASH,
            "Runner exceeded maxLoopIterations without a persisted outcome",
            { maxLoopIterations: this.#config.options.maxLoopIterations },
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
        const mainAttemptId = this.#nextStableId("attempt", {
            scope: "domain-command",
            commandId,
            command: commandRecord.command,
        });
        this.#adapter.reserveAttempt({
            attemptId: mainAttemptId,
            command: formatAttemptCommand("domain-command", {
                commandId,
                command: commandRecord.command,
            }),
            lease: this.#lease,
        });
        await this.#fault("after_reservation", { attemptId: mainAttemptId, commandId });

        if (commandRecord.status === "reserved") {
            this.#adapter.appendExternal(EVENT_TYPES.COMMAND_DISPATCHED, {
                commandId,
                capabilityEpochId: this.#config.runnerEpochId,
            });
        }
        this.#adapter.dispatchAttempt(mainAttemptId, this.#lease);
        await this.#fault("after_dispatch", { attemptId: mainAttemptId, commandId });

        const currentAggregate = this.#adapter.replay().aggregate;
        let observation;
        if (commandRecord.command.kind === "run_validation") {
            observation = await this.#runValidationCommand(
                currentAggregate,
                commandId,
                mainAttemptId,
            );
        } else if (commandRecord.command.kind === "search") {
            observation = await this.#runSearchCommand(
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

        this.#adapter.appendHarnessObservation(observation);
        await this.#fault("after_domain_observation", {
            attemptId: mainAttemptId,
            commandId,
            observationId: observation.observationId,
        });
        this.#adapter.observeAttempt(mainAttemptId, this.#lease);

        const afterObservation = this.#adapter.replay().aggregate;
        const commitRecommendation = decideNext(afterObservation);
        if (commitRecommendation.command?.kind !== "commit_evidence") {
            throw new RuntimeIntegrityError(
                "A harness observation was not followed by deterministic evidence commitment",
                { recommendation: commitRecommendation },
            );
        }
        this.#adapter.appendEvidenceCommit({
            evidenceId: commitRecommendation.command.evidenceId,
            observationId: commitRecommendation.command.observationId,
        });
        await this.#fault("after_evidence_commit", {
            attemptId: mainAttemptId,
            commandId,
            evidenceId: commitRecommendation.command.evidenceId,
        });
        this.#adapter.commitAttempt(mainAttemptId, this.#lease);
    }

    async #executeEffect(command, operation, persist = null) {
        const attemptId = this.#nextStableId("attempt", command);
        this.#adapter.reserveAttempt({
            attemptId,
            command: formatAttemptCommand("external-effect", command),
            lease: this.#lease,
        });
        await this.#fault("after_effect_reservation", { attemptId, command });
        this.#adapter.dispatchAttempt(attemptId, this.#lease);
        await this.#fault("after_effect_dispatch", { attemptId, command });

        let result;
        try {
            result = await operation(attemptId);
        } catch (error) {
            if (error?.leaveAttemptActive === true) {
                throw error;
            }
            this.#adapter.observeAttempt(attemptId, this.#lease);
            this.#adapter.ingestOperationalEvidence({
                attemptId,
                evidenceKind: "effect-failure",
                kind: "runtime:effect_failure",
                payload: {
                    command,
                    error: {
                        name: error?.name ?? "Error",
                        code: error?.code ?? null,
                        message: error?.message ?? String(error),
                    },
                },
            });
            this.#adapter.commitAttempt(attemptId, this.#lease);
            throw error;
        }

        this.#adapter.observeAttempt(attemptId, this.#lease);
        if (persist !== null) {
            await persist(result, attemptId);
        }
        this.#adapter.commitAttempt(attemptId, this.#lease);
        await this.#fault("after_effect_commit", { attemptId, command });
        return { attemptId, result };
    }

    async #runValidationCommand(aggregate, commandId, mainAttemptId) {
        const contract = aggregate.contract;
        const settledCases = await Promise.allSettled(contract.validationCases.map(async (validationCase) => {
            const command = {
                kind: "validation-measurement",
                commandId,
                caseId: validationCase.id,
                snapshot: validationCase.artifactHash,
            };
            const materialized = this.#materializeSnapshot(
                validationCase.artifactHash,
                `validation-${validationCase.id}`,
            );
            try {
                const effect = await this.#executeEffect(
                    command,
                    async (attemptId) => {
                        const verifiedEntry = this.#allowlist.verifyEntry(contract.harnessId);
                        return this.#executor.run({
                            verifiedEntry,
                            candidateSnapshot: Object.freeze({
                                path: materialized.dest,
                                hash: measurementSnapshotHash(validationCase.artifactHash),
                            }),
                            attemptId,
                            runnerEpochId: this.#config.runnerEpochId,
                        });
                    },
                    async (measurement, attemptId) => {
                        this.#persistMeasurement({
                            measurement,
                            attemptId,
                            purpose: "validation",
                            candidateId: validationCase.id,
                            snapshotId: validationCase.artifactHash,
                        });
                    },
                );
                const outcome = effect.result.parsed.pass ? "accept" : "reject";
                return {
                    id: validationCase.id,
                    artifactHash: validationCase.artifactHash,
                    expectation: validationCase.expectation,
                    outcome,
                    matched: outcome === validationCase.expectation,
                    attemptId: effect.attemptId,
                    parsed: effect.result.parsed,
                    receiptHash: ensureReceiptObservationHash(hashReceipt(effect.result.receipt)),
                    stdoutHash: effect.result.stdoutHash,
                    stderrHash: effect.result.stderrHash,
                };
            } finally {
                removeTreeInside(materialized.dest, this.#runTempRoot);
            }
        }));
        const validationFailures = settledCases.filter((item) => item.status === "rejected");
        if (validationFailures.length > 0) {
            const injectedCrash = validationFailures.find(
                (item) => item.reason?.leaveAttemptActive === true,
            );
            if (injectedCrash !== undefined) {
                throw injectedCrash.reason;
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
        const caseRuns = settledCases.map((item) => item.value);

        caseRuns.sort((left, right) => left.id.localeCompare(right.id));
        const caseMap = {};
        for (const item of caseRuns) {
            caseMap[item.id] = {
                artifactHash: item.artifactHash,
                expectation: item.expectation,
                outcome: item.outcome,
                matched: item.matched,
                attemptId: item.attemptId,
                parsed: item.parsed,
                receiptHash: item.receiptHash,
            };
        }
        const compositeReceiptHash = hashCanonical(
            {
                cases: caseRuns.map((item) => ({
                    id: item.id,
                    receiptHash: item.receiptHash,
                    attemptId: item.attemptId,
                })),
            },
            VALIDATION_RECEIPT_HASH_ALGORITHM,
        );
        const compositeArtifact = this.#persistJsonArtifact({
            attemptId: mainAttemptId,
            kind: "validation-composite-receipt",
            value: {
                caseMap,
                compositeReceiptHash,
            },
            contentType: "application/vnd.crucible.validation-receipt+json",
        });
        this.#adapter.ingestOperationalEvidence({
            attemptId: mainAttemptId,
            evidenceKind: "validation-composite",
            kind: "runtime:validation_composite",
            payload: {
                commandId,
                caseMap,
                compositeReceiptHash,
                artifactId: compositeArtifact.artifactId,
            },
        });

        return {
            commandId,
            observationId: this.#nextStableId("observation", {
                commandId,
                purpose: "validation",
            }),
            purpose: "validation",
            receipt: {
                attemptId: mainAttemptId,
                runnerEpochId: this.#config.runnerEpochId,
                rawStdoutHash: hashCanonical(
                    caseRuns.map((item) => ({ id: item.id, hash: item.stdoutHash })),
                    OBSERVATION_STREAM_HASH_ALGORITHM,
                ),
                rawStderrHash: hashCanonical(
                    caseRuns.map((item) => ({ id: item.id, hash: item.stderrHash })),
                    OBSERVATION_STREAM_HASH_ALGORITHM,
                ),
                candidateArtifactHash: null,
            },
            data: {
                caseResults: caseRuns.map((item) => ({
                    id: item.id,
                    artifactHash: item.artifactHash,
                    outcome: item.outcome,
                })),
                caseMap,
                compositeReceiptHash,
            },
        };
    }

    async #runSearchCommand(aggregate, commandId, mainAttemptId, command) {
        const requests = this.#buildSearchRequests(aggregate, commandId, mainAttemptId, command);
        const proposalSettled = await Promise.allSettled(requests.map((request) =>
            this.#executeEffect(
                {
                    kind: "sdk-proposal",
                    commandId,
                    round: command.round,
                    model: request.model,
                    sessionId: request.sessionId,
                    candidateId: request.allowedCandidateIds[0],
                },
                () => this.#getWorkerPool(aggregate).propose(request),
                async (proposal, attemptId) => {
                    const artifact = this.#persistJsonArtifact({
                        attemptId,
                        kind: `proposal-${proposal.candidateId}`,
                        value: proposal,
                        contentType: "application/vnd.crucible.candidate-proposal+json",
                    });
                    this.#adapter.ingestOperationalEvidence({
                        attemptId,
                        evidenceKind: `proposal:${proposal.candidateId}`,
                        kind: "runtime:model_proposal",
                        payload: {
                            commandId,
                            round: command.round,
                            candidateId: proposal.candidateId,
                            identity: proposal.identity,
                            artifactId: artifact.artifactId,
                        },
                    });
                },
            )));
        const proposalCrash = proposalSettled.find(
            (item) => item.status === "rejected" && item.reason?.leaveAttemptActive === true,
        );
        if (proposalCrash !== undefined) {
            throw proposalCrash.reason;
        }
        const proposals = proposalSettled
            .filter((item) => item.status === "fulfilled")
            .map((item) => item.value.result);
        if (proposals.length === 0) {
            const error = new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.NO_ELIGIBLE_CANDIDATE,
                "Every configured proposal session failed to submit a valid candidate",
                {
                    commandId,
                    failures: proposalSettled
                        .filter((item) => item.status === "rejected")
                        .map((item) => item.reason?.code ?? item.reason?.message ?? String(item.reason)),
                },
            );
            error.recoverable = true;
            throw error;
        }

        const measuredSettled = await Promise.allSettled(proposals.map(async (proposal) => {
            const snapshot = this.#ingestCandidate(proposal);
            const materialized = this.#materializeSnapshot(
                snapshot.snapshot,
                `candidate-${proposal.candidateId}`,
            );
            try {
                const effect = await this.#executeEffect(
                    {
                        kind: "candidate-measurement",
                        commandId,
                        round: command.round,
                        candidateId: proposal.candidateId,
                        snapshot: snapshot.snapshot,
                    },
                    async (attemptId) => {
                        const verifiedEntry = this.#allowlist.verifyEntry(aggregate.contract.harnessId);
                        return this.#executor.run({
                            verifiedEntry,
                            candidateSnapshot: Object.freeze({
                                path: materialized.dest,
                                hash: measurementSnapshotHash(snapshot.snapshot),
                            }),
                            attemptId,
                            runnerEpochId: this.#config.runnerEpochId,
                        });
                    },
                    async (measurement, attemptId) => {
                        this.#persistMeasurement({
                            measurement,
                            attemptId,
                            purpose: "candidate",
                            candidateId: proposal.candidateId,
                            snapshotId: snapshot.snapshot,
                        });
                    },
                );
                const metricValues = candidateMetricValues(
                    aggregate.contract.metrics,
                    effect.result.parsed,
                );
                if (metricValues === null) {
                    throw new CrucibleRuntimeError(
                        RUNTIME_ERROR_CODES.NO_ELIGIBLE_CANDIDATE,
                        "Measured candidate omitted one or more frozen ranking metrics",
                        { candidateId: proposal.candidateId },
                    );
                }
                return {
                    proposal,
                    snapshot,
                    measurement: effect.result,
                    measurementAttemptId: effect.attemptId,
                    metricValues,
                    accepted: acceptanceSatisfied(
                        aggregate.contract.acceptancePredicate,
                        effect.result.parsed,
                    ),
                };
            } finally {
                removeTreeInside(materialized.dest, this.#runTempRoot);
            }
        }));
        const measurementCrash = measuredSettled.find(
            (item) => item.status === "rejected" && item.reason?.leaveAttemptActive === true,
        );
        if (measurementCrash !== undefined) {
            throw measurementCrash.reason;
        }

        const measured = measuredSettled
            .filter((item) => item.status === "fulfilled")
            .map((item) => item.value);
        if (measured.length === 0) {
            for (const proposal of proposals) {
                this.#workerPool?.releaseCandidateId?.(proposal.candidateId);
            }
            const error = new CrucibleRuntimeError(
                RUNTIME_ERROR_CODES.NO_ELIGIBLE_CANDIDATE,
                "No submitted candidate produced domain-eligible harness evidence",
                {
                    commandId,
                    failures: measuredSettled
                        .filter((item) => item.status === "rejected")
                        .map((item) => item.reason?.code ?? item.reason?.message ?? String(item.reason)),
                },
            );
            error.recoverable = true;
            throw error;
        }

        const selected = selectCandidate(aggregate.contract, measured);
        for (const proposal of proposals) {
            if (proposal.candidateId !== selected.proposal.candidateId) {
                this.#workerPool?.releaseCandidateId?.(proposal.candidateId);
            }
        }
        this.#adapter.ingestOperationalEvidence({
            attemptId: mainAttemptId,
            evidenceKind: `selection:round-${command.round}`,
            kind: "runtime:candidate_selection",
            payload: {
                commandId,
                round: command.round,
                selectedCandidateId: selected.proposal.candidateId,
                measuredCandidates: measured.map((candidate) => ({
                    candidateId: candidate.proposal.candidateId,
                    accepted: candidate.accepted,
                    metrics: candidate.metricValues,
                    measurementAttemptId: candidate.measurementAttemptId,
                })),
            },
        });

        return {
            commandId,
            observationId: this.#nextStableId("observation", {
                commandId,
                candidateId: selected.proposal.candidateId,
            }),
            purpose: "candidate",
            round: command.round,
            candidateId: selected.proposal.candidateId,
            receipt: {
                attemptId: selected.measurementAttemptId,
                runnerEpochId: this.#config.runnerEpochId,
                rawStdoutHash: selected.measurement.stdoutHash,
                rawStderrHash: selected.measurement.stderrHash,
                candidateArtifactHash: measurementSnapshotHash(selected.snapshot.snapshot),
            },
            data: selected.measurement.parsed,
        };
    }

    #buildSearchRequests(aggregate, commandId, mainAttemptId, command) {
        const contract = aggregate.contract;
        const evidenced = new Set(
            harnessCandidateEvidenceItems(aggregate).map((item) => item.candidateId),
        );
        const slots = [];
        if (contract.boundedCandidateIds !== undefined) {
            const remaining = contract.boundedCandidateIds.filter((candidateId) => !evidenced.has(candidateId));
            for (const candidateId of remaining.slice(0, contract.candidatesPerRound)) {
                slots.push(candidateId);
            }
        } else {
            for (let slot = 0; slot < contract.candidatesPerRound; slot += 1) {
                slots.push(null);
            }
        }
        if (slots.length === 0) {
            throw new RuntimeIntegrityError("Search command has no remaining candidate slots", {
                commandId,
                round: command.round,
            });
        }
        return slots.map((boundedCandidateId, slot) => {
            const model = contract.workerModels[slot % contract.workerModels.length];
            const sessionHex = stableHex({
                investigationId: this.#config.investigationId,
                commandId,
                mainAttemptId,
                round: command.round,
                slot,
                model,
                runnerEpochId: this.#config.runnerEpochId,
            }).slice(0, 32);
            const sessionId = uuidFromHex(sessionHex);
            const candidateSessionHex = stableHex({
                round: command.round,
                model,
                sessionId,
            });
            const candidateId = boundedCandidateId
                ?? `r${command.round}-${model.replace(/[^A-Za-z0-9_-]/gu, "-").slice(0, 40)}-${candidateSessionHex.slice(0, 16)}`;
            const challengeNonce = stableHex({
                sessionId,
                nonce: this.#idFactory()(),
                commandId,
            });
            const searchContext = [
                `Frozen strategy revision: ${command.strategyRevision}`,
                `Frozen acceptance predicate: ${canonicalJson(contract.acceptancePredicate)}`,
                `Frozen ranking metrics: ${canonicalJson(contract.metrics)}`,
                this.#config.options.workerAdditionalContext,
            ].filter((item) => item !== null).join("\n");
            const prompt = buildProposalPrompt({
                objective: contract.objective,
                candidateId,
                challengeNonce,
                round: command.round,
                model,
                additionalContext: searchContext,
            });
            return {
                model,
                reasoningEffort: this.#config.options.reasoningEffort,
                sessionId,
                challengeNonce,
                allowedCandidateIds: [candidateId],
                prompt,
            };
        });
    }

    #getWorkerPool(aggregate) {
        if (this.#workerPool !== null) {
            return this.#workerPool;
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
            existingCandidateIds,
        });
        return this.#workerPool;
    }

    #ingestCandidate(proposal) {
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
            return this.#artifactStore.ingestDirectory({ sourceDir });
        } finally {
            removeTreeInside(sourceDir, sourceRoot);
        }
    }

    #materializeSnapshot(snapshotId, label) {
        const status = this.#artifactStore.verifySnapshot(snapshotId);
        if (!status.ok) {
            throw new RuntimeIntegrityError("Snapshot closure failed verification", {
                snapshotId,
                status,
            });
        }
        const root = ensureDirectory(path.join(this.#runTempRoot, "materialized"));
        const destDir = uniqueNonexistentPath(root, label, this.#idFactory());
        return this.#artifactStore.materializeSnapshot({
            snapshot: snapshotId,
            destDir,
            readOnly: true,
        });
    }

    #persistMeasurement({
        measurement,
        attemptId,
        purpose,
        candidateId,
        snapshotId,
    }) {
        const receiptArtifact = this.#persistJsonArtifact({
            attemptId,
            kind: `measurement-receipt-${candidateId}`,
            value: measurement.receipt,
            contentType: "application/vnd.crucible.measurement-receipt+json",
        });
        const snapshotArtifact = this.#registerCasObject({
            attemptId,
            kind: `snapshot-${candidateId}`,
            objectId: snapshotId,
            size: this.#artifactStore.readObject(snapshotId).length,
            contentType: "application/vnd.crucible.snapshot+json",
        });
        this.#adapter.ingestOperationalEvidence({
            attemptId,
            evidenceKind: `measurement:${purpose}:${candidateId}`,
            kind: "runtime:measurement",
            payload: {
                purpose,
                candidateId,
                parsed: measurement.parsed,
                receipt: measurement.receipt,
                receiptHash: hashReceipt(measurement.receipt),
                receiptArtifactId: receiptArtifact.artifactId,
                snapshotArtifactId: snapshotArtifact.artifactId,
                snapshotId,
                stdoutHash: measurement.stdoutHash,
                stderrHash: measurement.stderrHash,
            },
        });
    }

    #persistJsonArtifact({ attemptId, kind, value, contentType }) {
        const bytes = Buffer.from(canonicalJson(value), "utf8");
        const stored = this.#artifactStore.putBytes(bytes, { contentType });
        return this.#registerCasObject({
            attemptId,
            kind,
            objectId: stored.id,
            size: stored.size,
            contentType,
        });
    }

    #registerCasObject({ attemptId, kind, objectId, size, contentType }) {
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
            this.#repository.referenceArtifact({
                investigationId: this.#config.investigationId,
                artifactId,
            });
        } else if (existing.hashValue !== snapshotObjectHex(objectId)
            || existing.investigationId !== this.#config.investigationId) {
            throw new RuntimeIntegrityError("Artifact id collision", {
                artifactId,
                objectId,
            });
        }
        return { artifactId, objectId };
    }

    #recordDeadlineNonResult(aggregate) {
        const attemptId = this.#nextStableId("deadline", {
            seq: aggregate.lastSeq,
            deadlineMs: this.#config.deadlineMs,
        });
        let domainPausePersisted = false;
        const currentRecommendation = decideNext(aggregate);
        const boundedExhaustionWouldBecomeTerminal =
            currentRecommendation.command?.kind === "await_stop_request";
        if (!boundedExhaustionWouldBecomeTerminal) {
            try {
                const requested = this.#adapter.requestStop({
                    requestId: this.#nextStableId("stop", { reason: "deadline" }),
                    reason: "Autonomous runner deadline reached.",
                    pauseRequested: true,
                });
                if (requested.domainEvent !== null) {
                    const afterStop = requested.aggregate;
                    const recommendation = decideNext(afterStop);
                    if (recommendation.event?.type === EVENT_TYPES.INVESTIGATION_PAUSED) {
                        this.#adapter.appendKernelDecision();
                        domainPausePersisted = true;
                    }
                }
            } catch (error) {
                if (error?.code !== RUNTIME_ERROR_CODES.DOMAIN_EVENT_INVALID) {
                    throw error;
                }
            }
        }
        this.#adapter.recordOperationalNonResult({
            attemptId,
            code: "DEADLINE_EXCEEDED",
            reason: "The wall-clock deadline expired before a terminal result.",
            details: {
                deadlineMs: this.#config.deadlineMs,
                observedAt: this.#clock.isoNow(),
                domainPausePersisted,
                terminalEmitted: false,
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
        if (this.#workerPool !== null && typeof this.#workerPool.close === "function") {
            try {
                await this.#workerPool.close();
            } catch (error) {
                firstError ??= error;
            }
        }
        if (this.#repository !== null) {
            try {
                this.#repository.close();
            } catch (error) {
                firstError ??= error;
            }
        }
        if (this.#runTempRoot !== null) {
            try {
                removeTreeInside(this.#runTempRoot, this.#config.options.tempRoot);
            } catch (error) {
                firstError ??= error;
            }
        }
        return firstError;
    }
}

export async function runAutonomousInvestigation(config, dependencies = {}) {
    const runner = new AutonomousRunner(config, dependencies);
    const result = await runner.run();
    if (runner.config.resultPath !== null) {
        atomicWriteJson(runner.config.resultPath, { ok: true, result });
    }
    return result;
}
