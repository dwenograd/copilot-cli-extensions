import { commandBudget } from "./contract.mjs";
import {
    EVENT_TYPES,
    NON_RESULT_CODES,
} from "./constants.mjs";
import { DecisionError, ERROR_CODES } from "./errors.mjs";
import { detectPlateau, buildSearchCandidateCommand } from "./strategy.mjs";
import {
    activeCommand,
    boundedSearchExhaustion,
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

function budgetRecommendation(aggregate, reason) {
    const budget = commandBudget(aggregate.contract);
    const payload = {
        code: NON_RESULT_CODES.BUDGET_EXHAUSTED_INCONCLUSIVE,
        reason,
        commandCount: aggregate.commandOrder.length,
        commandBudget: budget,
        maxRounds: aggregate.contract.maxRounds,
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

function evidenceClosure(aggregate) {
    const validation = currentValidationEvidence(aggregate);
    return {
        validation: {
            evidenceId: validation.evidenceId,
            evidenceHash: validation.commitEventHash,
        },
        candidates: qualifyingCandidateEvidenceItems(aggregate).map((evidence) => ({
            candidateId: evidence.candidateId,
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash,
        })),
    };
}

function verifiedRecommendation(aggregate, incumbent, basis) {
    const payload = {
        decision: "VERIFIED_RESULT",
        candidateId: incumbent.candidateId,
        evidenceId: incumbent.evidenceId,
        evidenceHash: incumbent.commitEventHash,
        contractHash: aggregate.contractHash,
        basis,
        evidenceClosure: evidenceClosure(aggregate),
    };
    return {
        kind: "TERMINAL",
        decision: "VERIFIED_RESULT",
        candidateId: incumbent.candidateId,
        evidenceId: incumbent.evidenceId,
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
    const boundedBasis = boundedSearchExhaustion(aggregate);
    if (boundedBasis !== null) {
        return {
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
            basis: boundedBasis,
            event: {
                type: EVENT_TYPES.TARGET_UNREACHABLE,
                payload: {
                    decision: "TARGET_UNREACHABLE",
                    basis: boundedBasis,
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

function reserveCommandRecommendation(aggregate) {
    const commandId = nextCommandId(aggregate);
    const validationEvidence = currentValidationEvidence(aggregate);
    let command;
    if (validationEvidence === null) {
        command = {
            kind: "run_validation",
            harnessId: aggregate.contract.harnessId,
            parserVersion: aggregate.contract.parserVersion,
            validationCases: aggregate.contract.validationCases,
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
        if (budgetIsExhausted(aggregate)) {
            return budgetRecommendation(
                aggregate,
                "Declared command budget was exhausted before current validation completed.",
            );
        }
        return reserveCommandRecommendation(aggregate);
    }

    const incumbent = qualifyingCandidateEvidence(aggregate);
    if (incumbent !== null && aggregate.contract.searchPolicy.stopOnFirstAccept) {
        return verifiedRecommendation(aggregate, incumbent, {
            kind: "first_passing_candidate",
            stopOnFirstAccept: true,
            round: incumbent.round,
            slotIndex: incumbent.slotIndex,
        });
    }

    const unreachable = unreachableRecommendation(aggregate);
    if (unreachable !== null) {
        return unreachable;
    }

    const progress = searchProgress(aggregate);
    if (budgetIsExhausted(aggregate)) {
        return incumbent === null
            ? budgetRecommendation(
                aggregate,
                "Declared command budget was exhausted without a qualifying incumbent.",
            )
            : verifiedRecommendation(aggregate, incumbent, {
                kind: "budget_exhausted_with_incumbent",
                commandCount: aggregate.commandOrder.length,
                commandBudget: commandBudget(aggregate.contract),
            });
    }

    if (progress.roundsExhausted) {
        return incumbent === null
            ? budgetRecommendation(
                aggregate,
                "Frozen search rounds were exhausted without a qualifying incumbent.",
            )
            : verifiedRecommendation(aggregate, incumbent, {
                kind: "rounds_exhausted_with_incumbent",
                maxRounds: aggregate.contract.maxRounds,
            });
    }

    const plateau = detectPlateau(aggregate);
    if (incumbent !== null && plateau.plateauComplete) {
        return verifiedRecommendation(aggregate, incumbent, {
            kind: "plateau_after_mandatory_escape",
            triggerRound: plateau.triggerRound,
            escapeRoundsCompleted: plateau.escapeRoundsCompleted,
            mandatoryEscapeRounds: plateau.escapeRoundsRequired,
        });
    }

    return reserveCommandRecommendation(aggregate);
}
