import { hashCanonical } from "./canonical.mjs";
import { commandBudget } from "./contract.mjs";
import {
    EVENT_TYPES,
    NON_RESULT_CODES,
} from "./constants.mjs";
import {
    createImpossibilityMeasurementBinding,
    createImpossibilityVerificationPackage,
} from "./impossibility.mjs";
import {
    deriveReplicationSchedule,
    statisticalSubjectIndex,
} from "./replication.mjs";
import { DecisionError, ERROR_CODES } from "./errors.mjs";
import { detectPlateau, buildSearchCandidateCommand } from "./strategy.mjs";
import {
    deriveScientificConfirmationFreeze,
    deriveScientificConfirmationState,
    nextScientificConfirmationCommand,
} from "./confirmation.mjs";
import {
    assessTargetUnreachableReadiness,
    assessVerifiedResultReadiness,
} from "./scientific-readiness.mjs";
import {
    deriveTerminalEvidenceClosure,
} from "./terminal-closure.mjs";
import {
    activeCommand,
    boundedSearchExhaustion,
    candidateCohortState,
    currentValidationEvidence,
    impossibilityEvidenceItems,
    latestUnhandledStopRequest,
    latestApplicableImpossibilityEvidence,
    qualifyingCandidateCohort,
    qualifyingUnreachableEvidence,
    qualifyingValidationEvidence,
    searchProgress,
    uncommittedObservation,
    validationAttemptIndexes,
    validationEvidenceItems,
} from "./state.mjs";

function nextCommandId(aggregate) {
    return `cmd-${String(aggregate.commandOrder.length + 1).padStart(6, "0")}`;
}

function nextEvidenceId(aggregate) {
    return `evidence-${String(aggregate.evidenceOrder.length + 1).padStart(6, "0")}`;
}

function budgetIsExhausted(aggregate) {
    const budget = commandBudget(aggregate.contract);
    return budget !== null && aggregate.commandOrder.length >= budget;
}

function budgetRecommendation(aggregate, reason, details = null) {
    const budget = commandBudget(aggregate.contract);
    const payload = {
        code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
        reason,
        commandCount: aggregate.commandOrder.length,
        commandBudget: budget,
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        ...(details === null ? {} : { scientificState: details }),
    };
    return {
        kind: "NON_RESULT",
        ...payload,
        event: {
            type: EVENT_TYPES.NON_RESULT_RECORDED,
            payload,
        },
    };
}

function impossibilityNonResultRecommendation(aggregate, evidence) {
    const observation = aggregate.observations[evidence.observationId];
    const certificateVerdict = observation?.data?.certificateVerdict ?? "invalid";
    const checkerStatus = observation?.data?.checkerStatus ?? "INVALID";
    const payload = {
        code: NON_RESULT_CODES.IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE,
        reason: checkerStatus === "REJECTED"
            ? "The independent impossibility verifier rejected the proposed certificate."
            : checkerStatus === "INCONCLUSIVE"
                ? "The independent impossibility verifier could not close the frozen evidence."
                : "The independent impossibility verifier produced an invalid result.",
        commandCount: aggregate.commandOrder.length,
        commandBudget: commandBudget(aggregate.contract),
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        certificateVerdict,
        checkerStatus,
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
    };
    return {
        kind: "NON_RESULT",
        ...payload,
        event: {
            type: EVENT_TYPES.NON_RESULT_RECORDED,
            payload,
        },
    };
}

function impossibilityEvidenceIncompleteRecommendation(aggregate, verification) {
    const payload = {
        code: NON_RESULT_CODES.IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE,
        reason:
            "The frozen calibration, control, search, or alpha-ledger evidence is incomplete; the independent verifier was not run.",
        commandCount: aggregate.commandOrder.length,
        commandBudget: commandBudget(aggregate.contract),
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        certificateVerdict: "inconclusive",
        checkerStatus: "INCONCLUSIVE",
        missing: verification.missing,
    };
    return {
        kind: "NON_RESULT",
        ...payload,
        event: {
            type: EVENT_TYPES.NON_RESULT_RECORDED,
            payload,
        },
    };
}

function scientificConfirmationFailureRecommendation(
    aggregate,
    cohortEvidence,
    cohort,
    basis,
    readiness = assessVerifiedResultReadiness(aggregate, cohort),
    reason =
        "The frozen provisional cohort did not independently satisfy confirmation and challenge requirements.",
) {
    const candidateIds = cohortEvidence.map((evidence) => evidence.candidateId);
    const evidenceIds = cohortEvidence.map((evidence) => evidence.evidenceId);
    const evidenceHashes = cohortEvidence.map(
        (evidence) => evidence.commitEventHash,
    );
    const payload = {
        code: NON_RESULT_CODES.SCIENTIFIC_CONFIRMATION_FAILED,
        reason,
        commandCount: aggregate.commandOrder.length,
        commandBudget: commandBudget(aggregate.contract),
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        cohortStatus: cohort.status,
        candidateIds,
        evidenceIds,
        evidenceHashes,
        cohortComparisonHash: cohort.comparisonHash,
        relationEvidenceHash: cohort.relationEvidenceHash,
        ...(cohort.status === "UNIQUE_BEST"
            ? {
                candidateId: cohortEvidence[0].candidateId,
                evidenceId: cohortEvidence[0].evidenceId,
                evidenceHash: cohortEvidence[0].commitEventHash,
            }
            : {}),
        basis,
        readiness,
    };
    return {
        kind: "NON_RESULT",
        ...payload,
        event: {
            type: EVENT_TYPES.NON_RESULT_RECORDED,
            payload,
        },
    };
}

function scientificReadinessFailureRecommendation(
    aggregate,
    {
        code,
        reason,
        cohort = null,
        evidence = [],
        basis = null,
        readiness = null,
    },
) {
    const evidenceItems = Array.isArray(evidence) ? evidence : [];
    const payload = {
        code,
        reason,
        commandCount: aggregate.commandOrder.length,
        commandBudget: commandBudget(aggregate.contract),
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        cohortStatus: cohort?.status ?? null,
        candidateIds: evidenceItems.map((item) => item.candidateId),
        evidenceIds: evidenceItems.map((item) => item.evidenceId),
        evidenceHashes: evidenceItems.map((item) => item.commitEventHash),
        cohortComparisonHash: cohort?.comparisonHash ?? null,
        relationEvidenceHash: cohort?.relationEvidenceHash ?? null,
        basis,
        readiness,
    };
    return {
        kind: "NON_RESULT",
        ...payload,
        event: {
            type: EVENT_TYPES.NON_RESULT_RECORDED,
            payload,
        },
    };
}

function predictionReadinessFailureRecommendation(
    aggregate,
    cohort,
    basis,
    readiness,
) {
    const state = readiness.requiredPredictionState;
    const code = state === "REFUTED"
        ? NON_RESULT_CODES.SCIENTIFIC_PREDICTION_REFUTED
        : state === "INVALID"
            ? NON_RESULT_CODES.SCIENTIFIC_PREDICTION_INVALID
            : NON_RESULT_CODES.SCIENTIFIC_PREDICTION_UNRESOLVED;
    const evidence = (cohort?.cohort ?? [])
        .map((item) => aggregate.evidence[item.evidenceId] ?? null)
        .filter((item) => item !== null);
    return scientificReadinessFailureRecommendation(aggregate, {
        code,
        reason:
            `At least one preregistered prediction required for result closure is ${state.toLowerCase()}.`,
        cohort,
        evidence,
        basis,
        readiness,
    });
}

function blockedPredictionRecommendation(aggregate, cohort, basis) {
    const blocked = (aggregate.scientificReplay?.candidateSupport ?? [])
        .filter((candidate) =>
            candidate.active === true
            && candidate.acceptanceSatisfied === true
            && candidate.requiredState === "SUPPORTED"
            && candidate.predictionEvaluation?.requiredState !== undefined
            && candidate.predictionEvaluation.requiredState !== "SUPPORTED");
    if (blocked.length === 0) return null;
    const states = blocked.map((candidate) =>
        candidate.predictionEvaluation.requiredState);
    const state = states.includes("INVALID")
        ? "INVALID"
        : states.includes("REFUTED")
            ? "REFUTED"
            : "UNRESOLVED";
    const evidence = blocked
        .map((candidate) =>
            aggregate.evidence[candidate.evidenceId] ?? null)
        .filter((item) => item !== null);
    const code = state === "INVALID"
        ? NON_RESULT_CODES.SCIENTIFIC_PREDICTION_INVALID
        : state === "REFUTED"
            ? NON_RESULT_CODES.SCIENTIFIC_PREDICTION_REFUTED
            : NON_RESULT_CODES.SCIENTIFIC_PREDICTION_UNRESOLVED;
    return scientificReadinessFailureRecommendation(aggregate, {
        code,
        reason:
            `Search closed with statistically supported candidates whose required predictions remained ${state.toLowerCase()}.`,
        cohort,
        evidence,
        basis,
        readiness: {
            requiredPredictionState: state,
            blockedCandidateCount: blocked.length,
        },
    });
}

function unresolvedCohortRecommendation(aggregate, cohort, basis) {
    return scientificReadinessFailureRecommendation(aggregate, {
        code: NON_RESULT_CODES.SCIENTIFIC_COHORT_UNRESOLVED,
        reason:
            "The preregistered pairwise candidate relations did not resolve to a unique best candidate or supported equivalence cohort.",
        cohort,
        evidence: (cohort?.frontier ?? [])
            .map((item) => aggregate.evidence[item.evidenceId] ?? null)
            .filter((item) => item !== null),
        basis,
        readiness: {
            cohortStatus: cohort?.status ?? null,
            tieResolution: cohort?.tieResolution ?? null,
        },
    });
}

function freezeScientificConfirmationRecommendation(
    aggregate,
    cohortEvidence,
    cohort,
    basis,
) {
    let payload;
    try {
        payload = deriveScientificConfirmationFreeze({
            aggregate,
            cohort,
            cohortEvidence,
            basis,
        });
    } catch (error) {
        return scientificConfirmationFailureRecommendation(
            aggregate,
            cohortEvidence,
            cohort,
            basis,
            assessVerifiedResultReadiness(aggregate, cohort),
            error?.message
                ?? "The provisional cohort cannot fit the frozen confirmation allocation.",
        );
    }
    return {
        kind: "DECISION",
        decision: "SCIENTIFIC_CONFIRMATION_FROZEN",
        event: {
            type: EVENT_TYPES.SCIENTIFIC_CONFIRMATION_FROZEN,
            payload,
        },
    };
}

function independentVerificationRecommendation(aggregate, basis, readiness) {
    const payload = {
        code: NON_RESULT_CODES.INDEPENDENT_VERIFICATION_REQUIRED,
        reason:
            "Search-space exhaustion is not authority for TARGET_UNREACHABLE; an independent impossibility verifier must supply trusted evidence.",
        commandCount: aggregate.commandOrder.length,
        commandBudget: commandBudget(aggregate.contract),
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        basis,
        readiness,
    };
    return {
        kind: "NON_RESULT",
        ...payload,
        event: {
            type: EVENT_TYPES.NON_RESULT_RECORDED,
            payload,
        },
    };
}

function verifiedRecommendation(aggregate, cohortEvidence, cohort, basis) {
    const readiness = assessVerifiedResultReadiness(aggregate, cohort);
    if (!readiness.ready) {
        if (readiness.requiredPredictionState !== "SUPPORTED") {
            return predictionReadinessFailureRecommendation(
                aggregate,
                cohort,
                basis,
                readiness,
            );
        }
        return scientificConfirmationFailureRecommendation(
            aggregate,
            cohortEvidence,
            cohort,
            basis,
            readiness,
        );
    }
    const candidateIds = cohortEvidence.map((evidence) => evidence.candidateId);
    const evidenceIds = cohortEvidence.map((evidence) => evidence.evidenceId);
    const evidenceHashes = cohortEvidence.map(
        (evidence) => evidence.commitEventHash,
    );
    let evidenceClosure;
    try {
        evidenceClosure = deriveTerminalEvidenceClosure(aggregate, {
            basis,
            decisiveKind: "candidate_cohort",
            decisiveEvidence: cohortEvidence,
        });
    } catch (error) {
        return scientificReadinessFailureRecommendation(aggregate, {
            code:
                NON_RESULT_CODES.SCIENTIFIC_TERMINAL_CLOSURE_INCOMPLETE,
            reason:
                `The canonical scientific terminal closure could not be completed: ${
                    error?.message ?? String(error)
                }`,
            cohort,
            evidence: cohortEvidence,
            basis,
            readiness,
        });
    }
    const payload = {
        decision: "VERIFIED_RESULT",
        cohortStatus: cohort.status,
        candidateIds,
        evidenceIds,
        evidenceHashes,
        cohortComparisonHash: cohort.comparisonHash,
        relationEvidenceHash: cohort.relationEvidenceHash,
        ...(cohort.status === "UNIQUE_BEST"
            ? {
                candidateId: cohortEvidence[0].candidateId,
                evidenceId: cohortEvidence[0].evidenceId,
                evidenceHash: cohortEvidence[0].commitEventHash,
            }
            : {
                candidateId: null,
                evidenceId: null,
                evidenceHash: null,
            }),
        contractHash: aggregate.contractHash,
        basis,
        evidenceClosure,
    };
    return {
        kind: "TERMINAL",
        decision: "VERIFIED_RESULT",
        cohortStatus: cohort.status,
        candidateIds,
        evidenceIds,
        candidateId: payload.candidateId,
        evidenceId: payload.evidenceId,
        basis,
        event: {
            type: EVENT_TYPES.VERIFIED_RESULT,
            payload,
        },
    };
}

function unreachableRecommendation(aggregate) {
    if (aggregate.contract.hypothesisTopology === "open_generative") {
        return null;
    }
    if (aggregate.contract.hypothesisTopology !== "certified_impossibility") {
        const boundedBasis = boundedSearchExhaustion(aggregate);
        const progress = searchProgress(aggregate);
        const targetObserved = progress.candidates.some((evidence) =>
            evidence.acceptanceSatisfied === true);
        if (boundedBasis !== null
            || (progress.roundsExhausted && !targetObserved)) {
            const readiness = assessTargetUnreachableReadiness(
                aggregate,
                null,
            );
            return independentVerificationRecommendation(
                aggregate,
                boundedBasis ?? {
                    kind: "bounded_search_exhausted_without_terminal_grade_coverage",
                    topology: aggregate.contract.hypothesisTopology,
                    roundsExhausted: progress.roundsExhausted,
                    boundedComplete: progress.boundedComplete,
                    coverageComplete: readiness.coverageComplete,
                    missing: readiness.missing,
                },
                readiness,
            );
        }
    }

    const evidence = qualifyingUnreachableEvidence(aggregate);
    if (evidence === null) {
        return null;
    }
    const readiness = assessTargetUnreachableReadiness(aggregate, evidence);
    if (!readiness.ready) {
        return independentVerificationRecommendation(
            aggregate,
            evidence.unreachableBasis,
            readiness,
        );
    }
    const observation = aggregate.observations[evidence.observationId];
    const verifierCommand = aggregate.commands[observation.commandId].command;
    const validation = currentValidationEvidence(aggregate);
    const basis = {
        ...evidence.unreachableBasis,
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        validationEvidenceId: validation.evidenceId,
        validationEvidenceHash: validation.commitEventHash,
        enumerandCount: verifierCommand.request.enumerands.count,
        enumerandManifestRoot: verifierCommand.request.enumerands.merkleRoot,
        evidenceRoots: verifierCommand.request.evidence.roots,
        evidenceRootsHash: verifierCommand.request.evidence.rootsHash,
        coverageClosureRoot:
            verifierCommand.request.evidence.coverageClosureRoot,
        alphaLedgerRoot: verifierCommand.request.statistics.alphaLedgerRoot,
    };
    let evidenceClosure;
    try {
        evidenceClosure = deriveTerminalEvidenceClosure(aggregate, {
            basis,
            decisiveKind: "impossibility_certificate",
            decisiveEvidence: evidence,
        });
    } catch (error) {
        return scientificReadinessFailureRecommendation(aggregate, {
            code:
                NON_RESULT_CODES.SCIENTIFIC_TERMINAL_CLOSURE_INCOMPLETE,
            reason:
                `The canonical impossibility terminal closure could not be completed: ${
                    error?.message ?? String(error)
                }`,
            evidence: [evidence],
            basis,
            readiness,
        });
    }
    return {
        kind: "TERMINAL",
        decision: "TARGET_UNREACHABLE",
        basis,
        event: {
            type: EVENT_TYPES.TARGET_UNREACHABLE,
            payload: {
                decision: "TARGET_UNREACHABLE",
                basis,
                evidenceId: evidence.evidenceId,
                evidenceHash: evidence.commitEventHash,
                contractHash: aggregate.contractHash,
                evidenceClosure,
            },
        },
    };
}

function pauseRecommendation(stopRequest) {
    const payload = {
        reason: stopRequest.reason,
        sourceStopRequestSeq: stopRequest.seq,
    };
    return {
        kind: "NON_RESULT",
        code: NON_RESULT_CODES.INVESTIGATION_PAUSED,
        event: {
            type: EVENT_TYPES.INVESTIGATION_PAUSED,
            payload,
        },
    };
}

function validationSeries(contract, contractHash) {
    const groups = new Map();
    for (const role of contract.validationRoles) {
        const spec = contract.harnessSuite.roles[role];
        const identity = hashCanonical({
            harnessId: spec.harnessId,
            harnessEntryHash: spec.harnessEntryHash,
            executableHash: spec.executableHash,
            parser: spec.parser,
            dependencies: spec.dependencies,
            configHash: spec.configHash,
            observableSchemaHash: spec.observableSchemaHash,
            sandboxIdentity: spec.sandboxIdentity,
        }, "sha256:crucible-validation-execution-role-v1");
        const group = groups.get(identity) ?? [];
        group.push(role);
        groups.set(identity, group);
    }
    let ordinal = 0;
    return [...groups.entries()].flatMap(([executionIdentity, roles]) => {
        roles.sort();
        const role = roles[0];
        return contract.validationCases.map((validationCase) => {
            const seriesOrdinal = ordinal;
            ordinal += 1;
            const subjectId = `validation-${seriesOrdinal}-${validationCase.id}`;
            const subjectIdentity = hashCanonical({
                contractHash,
                executionIdentity,
                coveredRoles: roles,
                caseId: validationCase.id,
                artifactHash: validationCase.artifactHash,
            }, "sha256:crucible-validation-subject-v1");
            return {
                role,
                coveredRoles: roles,
                caseId: validationCase.id,
                artifactHash: validationCase.artifactHash,
                replicationSchedule: deriveReplicationSchedule({
                    contractHash,
                    statisticalPolicy: contract.statisticalPolicy,
                    subject: {
                        kind: "calibration",
                        index: statisticalSubjectIndex(
                            "calibration",
                            seriesOrdinal,
                        ),
                        id: subjectId,
                        identity: subjectIdentity,
                    },
                    arms: [{
                        armId: "candidate",
                        armIndex: 0,
                        logicalSubjectId: subjectId,
                        subjectKind: "calibration",
                        subjectIdentity,
                    }],
                }),
            };
        });
    });
}

function nextValidationAttemptIndex(aggregate) {
    const occupied = new Set(validationAttemptIndexes(aggregate));
    for (
        let index = 0;
        index < aggregate.contract.statisticalPolicy.maxBlocks;
        index += 1
    ) {
        if (!occupied.has(index)) return index;
    }
    return null;
}

function validationInconclusiveRecommendation(aggregate) {
    const attempts = validationEvidenceItems(aggregate);
    const latest = attempts.at(-1) ?? null;
    const payload = {
        code: NON_RESULT_CODES.VALIDATION_INCONCLUSIVE,
        reason:
            "The operator-signed calibration suite did not resolve every required role/case claim to its expected state within the frozen block limit.",
        commandCount: aggregate.commandOrder.length,
        commandBudget: commandBudget(aggregate.contract),
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        validationAttemptCount: attempts.length,
        maxValidationAttempts: aggregate.contract.statisticalPolicy.maxBlocks,
        latestValidationEvidenceId: latest?.evidenceId ?? null,
        latestValidationEvidenceHash: latest?.commitEventHash ?? null,
    };
    return {
        kind: "NON_RESULT",
        ...payload,
        event: {
            type: EVENT_TYPES.NON_RESULT_RECORDED,
            payload,
        },
    };
}

function reserveCommandRecommendation(aggregate) {
    const commandId = nextCommandId(aggregate);
    const validationEvidence = currentValidationEvidence(aggregate);
    let command;
    if (validationEvidence === null) {
        const attemptIndex = nextValidationAttemptIndex(aggregate);
        if (attemptIndex === null) {
            throw new DecisionError(
                ERROR_CODES.NO_DECISION_EVENT,
                "Validation attempts are exhausted",
            );
        }
        command = {
            kind: "run_validation",
            harnessRole: "suite_calibration",
            harnessId: aggregate.contract.harnessSuite.id,
            parserVersion:
                aggregate.contract.harnessSuite.roles.calibration.parser.version,
            attemptIndex,
            validationSeries: validationSeries(
                aggregate.contract,
                aggregate.contractHash,
            ),
        };
    } else {
        command = buildSearchCandidateCommand(aggregate, searchProgress(aggregate));
        if (command === null) {
            throw new DecisionError(
                ERROR_CODES.NO_DECISION_EVENT,
                "Search is exhausted and cannot reserve another candidate slot",
            );
        }
    }
    return {
        kind: "COMMAND",
        commandId,
        command,
        event: {
            type: EVENT_TYPES.COMMAND_RESERVED,
            payload: {
                commandId,
                command,
            },
        },
    };
}

function reserveFrozenScientificCommand(aggregate, command) {
    const commandId = nextCommandId(aggregate);
    return {
        kind: "COMMAND",
        commandId,
        command,
        event: {
            type: EVENT_TYPES.COMMAND_RESERVED,
            payload: {
                commandId,
                command,
            },
        },
    };
}

function buildImpossibilityVerificationCommand(
    aggregate,
    progress,
    verification = null,
) {
    const validation = currentValidationEvidence(aggregate);
    const attemptOrdinal = impossibilityEvidenceItems(
        aggregate,
        { includeInvalidated: true },
    ).length + 1;
    const prepared = verification ?? createImpossibilityVerificationPackage(
        aggregate,
        { attemptOrdinal, progress, validation },
    );
    if (!prepared.eligible) {
        throw new DecisionError(
            ERROR_CODES.NO_DECISION_EVENT,
            "Impossibility verification evidence is incomplete",
            { missing: prepared.missing },
        );
    }
    return {
        kind: "verify_impossibility",
        harnessRole: "impossibility_verifier",
        harnessId:
            aggregate.contract.harnessSuite.roles.impossibility_verifier.harnessId,
        parserVersion:
            aggregate.contract.harnessSuite.roles.impossibility_verifier.parser.version,
        attemptOrdinal,
        certificateVersion: aggregate.contract.impossibilityPolicy.certificateVersion,
        request: prepared.request,
        requestHash: prepared.requestHash,
        proposedCertificate: prepared.proposal,
        proposedCertificateArtifactHash:
            prepared.proposalArtifactHash,
        proofArtifact: prepared.proofArtifact,
        proofArtifactHash: prepared.proofArtifactHash,
        measurementBinding: createImpossibilityMeasurementBinding(
            aggregate.contract,
            prepared.requestHash,
            attemptOrdinal,
        ),
    };
}

function reserveImpossibilityRecommendation(aggregate, progress, verification) {
    const commandId = nextCommandId(aggregate);
    const command = buildImpossibilityVerificationCommand(
        aggregate,
        progress,
        verification,
    );
    return {
        kind: "COMMAND",
        commandId,
        command,
        event: {
            type: EVENT_TYPES.COMMAND_RESERVED,
            payload: {
                commandId,
                command,
            },
        },
    };
}

export function decideNext(aggregate) {
    if (aggregate?.contract === null || aggregate?.status === "empty") {
        throw new DecisionError(
            ERROR_CODES.INVESTIGATION_NOT_OPEN,
            "An investigation must be opened before a decision can be made",
        );
    }

    if (aggregate.terminal !== null) {
        return {
            kind: "TERMINAL",
            decision: aggregate.terminal.decision,
            recorded: true,
            event: null,
        };
    }
    if (aggregate.pause !== null) {
        return {
            kind: "NON_RESULT",
            code: NON_RESULT_CODES.INVESTIGATION_PAUSED,
            recorded: true,
            event: null,
        };
    }
    const recordedNonResult = aggregate.nonResults.at(-1) ?? null;
    if (recordedNonResult !== null) {
        return {
            kind: "NON_RESULT",
            code: recordedNonResult.code,
            recorded: true,
            event: null,
        };
    }

    const pendingObservation = uncommittedObservation(aggregate);
    if (pendingObservation !== null) {
        return {
            kind: "COMMAND",
            commandId: pendingObservation.commandId,
            command: {
                kind: "commit_evidence",
                observationId: pendingObservation.observationId,
                evidenceId: nextEvidenceId(aggregate),
            },
            event: null,
        };
    }

    const active = activeCommand(aggregate);
    if (active !== null) {
        return {
            kind: "COMMAND",
            commandId: active.commandId,
            command: active.status === "reserved"
                ? { kind: "dispatch_reserved", reservedCommand: active.command }
                : { kind: "await_observation", reservedCommand: active.command },
            event: null,
        };
    }

    const stopRequest = latestUnhandledStopRequest(aggregate);
    if (stopRequest !== null) {
        return pauseRecommendation(stopRequest);
    }

    const validationEvidence = qualifyingValidationEvidence(aggregate);
    const latestCompletion = aggregate.validation.completions.at(-1) ?? null;
    if (validationEvidence !== null
        && latestCompletion?.evidenceId !== validationEvidence.evidenceId) {
        const payload = {
            status: "passed",
            evidenceId: validationEvidence.evidenceId,
            evidenceHash: validationEvidence.commitEventHash,
        };
        return {
            kind: "DECISION",
            decision: "VALIDATION_COMPLETED",
            event: {
                type: EVENT_TYPES.VALIDATION_COMPLETED,
                payload,
            },
        };
    }

    const currentValidation = currentValidationEvidence(aggregate);
    const validationCurrent = currentValidation !== null
        && latestCompletion?.evidenceId === currentValidation.evidenceId;
    if (!validationCurrent) {
        if (nextValidationAttemptIndex(aggregate) === null) {
            return validationInconclusiveRecommendation(aggregate);
        }
        if (budgetIsExhausted(aggregate)) {
            return budgetRecommendation(
                aggregate,
                "Declared command budget was exhausted before current validation completed.",
            );
        }
        return reserveCommandRecommendation(aggregate);
    }

    const candidateCohort = candidateCohortState(aggregate);
    const cohortEvidence = qualifyingCandidateCohort(aggregate);
    const supportedCohort = candidateCohort?.resolved === true
        && cohortEvidence.length > 0;

    const unreachable = unreachableRecommendation(aggregate);
    if (unreachable !== null) {
        return unreachable;
    }

    const progress = searchProgress(aggregate);
    const targetObserved = progress.candidates.some(
        (evidence) => evidence.acceptanceSatisfied === true,
    );
    if (aggregate.contract.hypothesisTopology === "certified_impossibility"
        && !targetObserved
        && progress.roundsExhausted) {
        const certificateEvidence = latestApplicableImpossibilityEvidence(aggregate);
        if (certificateEvidence !== null) {
            return impossibilityNonResultRecommendation(aggregate, certificateEvidence);
        }
    }

    const frozenConfirmation = aggregate.confirmation?.freeze?.payload ?? null;
    if (frozenConfirmation !== null) {
        const confirmationState = deriveScientificConfirmationState(aggregate);
        const frozenEvidence = frozenConfirmation.members
            .map((member) => aggregate.evidence[member.evidenceId] ?? null)
            .filter((evidence) => evidence !== null);
        const frozenCohort = {
            status: frozenConfirmation.discoveryClosure.cohortStatus,
            resolved: true,
            comparisonHash:
                frozenConfirmation.discoveryClosure.cohortComparisonHash,
            relationEvidenceHash:
                frozenConfirmation.discoveryClosure.relationEvidenceHash,
            cohort: frozenConfirmation.members,
            provisionalWinner:
                frozenConfirmation.discoveryClosure.cohortStatus === "UNIQUE_BEST"
                    ? frozenConfirmation.members[0]
                    : null,
        };
        if (confirmationState.failed) {
            return scientificConfirmationFailureRecommendation(
                aggregate,
                frozenEvidence,
                frozenCohort,
                frozenConfirmation.discoveryClosure.basis,
                assessVerifiedResultReadiness(aggregate, frozenCohort),
                "At least one frozen cohort member was refuted, invalid, unresolved at its block limit, invalidated, or no longer bound to the frozen discovery closure.",
            );
        }
        const scientificCommand =
            nextScientificConfirmationCommand(aggregate);
        if (scientificCommand !== null) {
            if (budgetIsExhausted(aggregate)) {
                return scientificConfirmationFailureRecommendation(
                    aggregate,
                    frozenEvidence,
                    frozenCohort,
                    frozenConfirmation.discoveryClosure.basis,
                    assessVerifiedResultReadiness(aggregate, frozenCohort),
                    "The declared command budget was exhausted after discovery froze and before every confirmation/challenge role closed.",
                );
            }
            return reserveFrozenScientificCommand(
                aggregate,
                scientificCommand,
            );
        }
        if (confirmationState.ready) {
            return verifiedRecommendation(
                aggregate,
                cohortEvidence,
                candidateCohort,
                {
                    kind: "scientific_confirmation_closed",
                    discoveryBasis:
                        frozenConfirmation.discoveryClosure.basis,
                    confirmationFreezeHash:
                        frozenConfirmation.freezeHash,
                    confirmationClosureHash:
                        confirmationState.closureHash,
                },
            );
        }
        return scientificConfirmationFailureRecommendation(
            aggregate,
            frozenEvidence,
            frozenCohort,
            frozenConfirmation.discoveryClosure.basis,
            assessVerifiedResultReadiness(aggregate, frozenCohort),
            "The frozen confirmation protocol reached an impossible incomplete state.",
        );
    }

    if (budgetIsExhausted(aggregate)) {
        const basis = {
            kind: "budget_exhausted_without_supported_cohort",
            commandCount: aggregate.commandOrder.length,
            commandBudget: commandBudget(aggregate.contract),
        };
        if (!supportedCohort) {
            const predictionFailure = blockedPredictionRecommendation(
                aggregate,
                candidateCohort,
                basis,
            );
            if (predictionFailure !== null) return predictionFailure;
            if (candidateCohort?.tieResolution?.required === true) {
                return unresolvedCohortRecommendation(
                    aggregate,
                    candidateCohort,
                    basis,
                );
            }
            return budgetRecommendation(
                aggregate,
                "Declared command budget was exhausted without a supported candidate cohort.",
                candidateCohort,
            );
        }
        return freezeScientificConfirmationRecommendation(
            aggregate,
            cohortEvidence,
            candidateCohort,
            {
                kind: "budget_exhausted_with_supported_cohort",
                commandCount: aggregate.commandOrder.length,
                commandBudget: commandBudget(aggregate.contract),
                cohortComparisonHash:
                    candidateCohort.comparisonHash,
                relationEvidenceHash:
                    candidateCohort.relationEvidenceHash,
            },
        );
    }

    if (aggregate.contract.hypothesisTopology === "certified_impossibility"
        && !targetObserved
        && progress.roundsExhausted) {
        const attemptOrdinal = impossibilityEvidenceItems(
            aggregate,
            { includeInvalidated: true },
        ).length + 1;
        const verification = createImpossibilityVerificationPackage(
            aggregate,
            {
                attemptOrdinal,
                progress,
                validation: currentValidation,
            },
        );
        if (!verification.eligible) {
            return impossibilityEvidenceIncompleteRecommendation(
                aggregate,
                verification,
            );
        }
        return reserveImpossibilityRecommendation(
            aggregate,
            progress,
            verification,
        );
    }

    if (progress.roundsExhausted) {
        const basis = {
            kind: "rounds_exhausted_without_supported_cohort",
            maxRounds: aggregate.contract.maxRounds,
        };
        if (!supportedCohort) {
            const predictionFailure = blockedPredictionRecommendation(
                aggregate,
                candidateCohort,
                basis,
            );
            if (predictionFailure !== null) return predictionFailure;
            if (candidateCohort?.tieResolution?.required === true
                || candidateCohort?.tieResolution?.exhausted === true
                || candidateCohort?.status === "UNRESOLVED"
                || candidateCohort?.status === "INCOMPARABLE") {
                return unresolvedCohortRecommendation(
                    aggregate,
                    candidateCohort,
                    basis,
                );
            }
            return budgetRecommendation(
                aggregate,
                "Frozen search rounds were exhausted without a supported candidate cohort.",
                candidateCohort,
            );
        }
        return freezeScientificConfirmationRecommendation(
            aggregate,
            cohortEvidence,
            candidateCohort,
            {
                kind: "rounds_exhausted_with_supported_cohort",
                maxRounds: aggregate.contract.maxRounds,
                cohortStatus: candidateCohort.status,
                cohortComparisonHash:
                    candidateCohort.comparisonHash,
                relationEvidenceHash:
                    candidateCohort.relationEvidenceHash,
            },
        );
    }

    const plateau = detectPlateau(aggregate);
    if (supportedCohort && plateau.plateauComplete) {
        return freezeScientificConfirmationRecommendation(
            aggregate,
            cohortEvidence,
            candidateCohort,
            {
                kind: "plateau_after_mandatory_escape",
                triggerRound: plateau.triggerRound,
                escapeRoundsCompleted: plateau.escapeRoundsCompleted,
                mandatoryEscapeRounds: plateau.escapeRoundsRequired,
                cohortStatus: candidateCohort.status,
                cohortComparisonHash:
                    candidateCohort.comparisonHash,
                relationEvidenceHash:
                    candidateCohort.relationEvidenceHash,
            },
        );
    }

    return reserveCommandRecommendation(aggregate);
}
