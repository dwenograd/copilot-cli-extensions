import { commandBudget } from "./contract.mjs";
import {
    EVENT_TYPES,
    NON_RESULT_CODES,
} from "./constants.mjs";
import { DecisionError, ERROR_CODES } from "./errors.mjs";
import {
    activeCommand,
    boundedSearchExhaustion,
    candidateSelectionReady,
    currentValidationEvidence,
    latestUnhandledStopRequest,
    qualifyingCandidateEvidence,
    qualifyingCandidateEvidenceItems,
    qualifyingUnreachableEvidence,
    qualifyingValidationEvidence,
    searchProgress,
    uncommittedObservation,
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

function budgetRecommendation(aggregate, stopRequest = null) {
    const budget = commandBudget(aggregate.contract);
    return {
        kind: "NON_RESULT",
        code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
        reason: "Declared command budget was exhausted without terminal evidence.",
        commandCount: aggregate.commandOrder.length,
        commandBudget: budget,
        sourceStopRequestSeq: stopRequest?.seq ?? null,
        event: {
            type: EVENT_TYPES.NON_RESULT_RECORDED,
            payload: {
                code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
                reason: "Declared command budget was exhausted without terminal evidence.",
                commandCount: aggregate.commandOrder.length,
                commandBudget: budget,
                sourceStopRequestSeq: stopRequest?.seq ?? null,
            },
        },
    };
}

function unreachableRecommendation(aggregate, stopRequest) {
    const topology = aggregate.contract.hypothesisTopology;
    if (topology === "open_generative") {
        return null;
    }
    const boundedBasis = boundedSearchExhaustion(aggregate);
    if (boundedBasis !== null) {
        const basis = {
            ...boundedBasis,
            stopRequestSeq: stopRequest.seq,
        };
        return {
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
            basis,
            event: {
                type: EVENT_TYPES.TARGET_UNREACHABLE,
                payload: {
                    decision: "TARGET_UNREACHABLE",
                    basis,
                },
            },
        };
    }
    const evidence = qualifyingUnreachableEvidence(aggregate);
    if (evidence === null) {
        return null;
    }
    const basis = {
        ...evidence.unreachableBasis,
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        stopRequestSeq: stopRequest.seq,
    };

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
            },
        },
    };
}

function reserveCommandRecommendation(aggregate) {
    const validationEvidence = currentValidationEvidence(aggregate);
    const commandId = nextCommandId(aggregate);
    const command = validationEvidence === null
        ? {
            kind: "run_validation",
            harnessId: aggregate.contract.harnessId,
            parserVersion: aggregate.contract.parserVersion,
            validationCases: aggregate.contract.validationCases,
        }
        : {
            kind: "search",
            harnessId: aggregate.contract.harnessId,
            parserVersion: aggregate.contract.parserVersion,
            strategyRevision: aggregate.searchStrategy.revision,
            round: searchProgress(aggregate).nextRound,
            workerModels: aggregate.contract.workerModels,
            candidatesPerRound: aggregate.contract.candidatesPerRound,
        };
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
    if (validationCurrent) {
        const accepted = qualifyingCandidateEvidence(aggregate);
        if (accepted !== null && candidateSelectionReady(aggregate)) {
            const acceptedEvidence = qualifyingCandidateEvidenceItems(aggregate);
            const evidenceClosure = {
                validation: {
                    evidenceId: currentValidation.evidenceId,
                    evidenceHash: currentValidation.commitEventHash,
                },
                candidates: acceptedEvidence.map((evidence) => ({
                    candidateId: evidence.candidateId,
                    evidenceId: evidence.evidenceId,
                    evidenceHash: evidence.commitEventHash,
                })),
            };
            const payload = {
                decision: "VERIFIED_RESULT",
                candidateId: accepted.candidateId,
                evidenceId: accepted.evidenceId,
                evidenceHash: accepted.commitEventHash,
                contractHash: aggregate.contractHash,
                evidenceClosure,
            };
            return {
                kind: "TERMINAL",
                decision: "VERIFIED_RESULT",
                candidateId: accepted.candidateId,
                evidenceId: accepted.evidenceId,
                event: {
                    type: EVENT_TYPES.VERIFIED_RESULT,
                    payload,
                },
            };
        }

        const stopRequest = latestUnhandledStopRequest(aggregate);
        if (stopRequest !== null) {
            const unreachable = unreachableRecommendation(aggregate, stopRequest);
            if (unreachable !== null) {
                return unreachable;
            }
            if (budgetIsExhausted(aggregate)) {
                return budgetRecommendation(aggregate, stopRequest);
            }
            if (stopRequest.pauseRequested === true) {
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

            const payload = {
                revision: aggregate.searchStrategy.revision + 1,
                reason: "Stop criteria were not met; continue with a revised search strategy.",
                strategy: "continue_search",
                sourceStopRequestSeq: stopRequest.seq,
            };
            return {
                kind: "DECISION",
                decision: "SEARCH_STRATEGY_REVISED",
                event: {
                    type: EVENT_TYPES.SEARCH_STRATEGY_REVISED,
                    payload,
                },
            };
        }

        const boundedExhaustion = boundedSearchExhaustion(aggregate);
        if (boundedExhaustion !== null) {
            return {
                kind: "COMMAND",
                commandId: null,
                command: {
                    kind: "await_stop_request",
                    reason: "Bounded search space is exhausted; a stop request is required to trigger a terminal decision.",
                },
                event: null,
            };
        }
    }

    if (budgetIsExhausted(aggregate)) {
        return budgetRecommendation(aggregate);
    }

    if (currentValidationEvidence(aggregate) !== null && searchProgress(aggregate).roundsExhausted) {
        const maxRounds = aggregate.contract.maxRounds;
        const payload = {
            code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
            reason: "Frozen search rounds were exhausted without terminal evidence.",
            commandCount: aggregate.commandOrder.length,
            commandBudget: commandBudget(aggregate.contract),
            maxRounds,
            sourceStopRequestSeq: null,
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

    return reserveCommandRecommendation(aggregate);
}
