import { hashCanonical } from "./canonical.mjs";
import { commandBudget } from "./contract.mjs";
import {
    EVENT_TYPES,
    IMPOSSIBILITY_REQUEST_HASH_ALGORITHM,
    NON_RESULT_CODES,
} from "./constants.mjs";
import { impossibilitySearchEvidenceHash } from "./impossibility.mjs";
import { DecisionError, ERROR_CODES } from "./errors.mjs";
import { detectPlateau, buildSearchCandidateCommand } from "./strategy.mjs";
import { buildCandidateArchive } from "./archive.mjs";
import {
    assessTargetUnreachableReadiness,
    assessVerifiedResultReadiness,
} from "./scientific-readiness.mjs";
import {
    activeCommand,
    boundedSearchExhaustion,
    currentValidationEvidence,
    impossibilityEvidenceItems,
    latestUnhandledStopRequest,
    latestApplicableImpossibilityEvidence,
    qualifyingCandidateEvidence,
    qualifyingUnreachableEvidence,
    qualifyingValidationEvidence,
    searchProgress,
    uncommittedObservation,
} from "./state.mjs";

const TERMINAL_RECEIPT_ROOTS_HASH_ALGORITHM =
    "sha256:crucible-terminal-receipt-roots-v1";
const TERMINAL_FRONTIER_HASH_ALGORITHM =
    "sha256:crucible-terminal-frontier-v1";
const TERMINAL_ARCHIVE_HASH_ALGORITHM =
    "sha256:crucible-terminal-archive-v1";
const TERMINAL_BASIS_HASH_ALGORITHM =
    "sha256:crucible-terminal-basis-v1";
const TERMINAL_STRATEGY_HISTORY_HASH_ALGORITHM =
    "sha256:crucible-terminal-strategy-history-v1";
const TERMINAL_EVIDENCE_CLOSURE_HASH_ALGORITHM =
    "sha256:crucible-terminal-evidence-closure-v1";

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

function impossibilityNonResultRecommendation(aggregate, evidence) {
    const observation = aggregate.observations[evidence.observationId];
    const certificateVerdict = observation?.data?.certificateVerdict ?? "invalid";
    const payload = {
        code: NON_RESULT_CODES.IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE,
        reason: certificateVerdict === "not_proven"
            ? "The trusted impossibility verifier did not certify that the target is unreachable."
            : "The trusted impossibility verifier produced an invalid certificate verdict.",
        commandCount: aggregate.commandOrder.length,
        commandBudget: commandBudget(aggregate.contract),
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        certificateVerdict,
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

function scientificConfirmationRecommendation(
    aggregate,
    incumbent,
    basis,
    readiness = assessVerifiedResultReadiness(aggregate, incumbent),
) {
    const payload = {
        code: NON_RESULT_CODES.SCIENTIFIC_CONFIRMATION_REQUIRED,
        reason:
            "Search evidence identified an incumbent, but trusted confirmation, challenge, and any required prediction evaluations are not closed.",
        commandCount: aggregate.commandOrder.length,
        commandBudget: commandBudget(aggregate.contract),
        maxRounds: aggregate.contract.maxRounds,
        sourceStopRequestSeq: null,
        candidateId: incumbent.candidateId,
        evidenceId: incumbent.evidenceId,
        evidenceHash: incumbent.commitEventHash,
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

function evidenceReference(evidence) {
    return {
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        provenanceRoot: evidence.provenanceRoot,
    };
}

function projectArchiveEvidence(evidence) {
    return {
        candidateId: evidence.candidateId,
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.commitEventHash,
        provenanceRoot: evidence.provenanceRoot,
        outcomeClass: evidence.outcomeClass,
        rankable: evidence.rankable,
        metrics: evidence.metrics,
        round: evidence.round,
        slotIndex: evidence.slotIndex,
    };
}

function terminalEvidenceClosure(
    aggregate,
    {
        basis,
        decisiveKind,
        decisiveEvidence = null,
    },
) {
    const validation = currentValidationEvidence(aggregate);
    const receiptRoots = aggregate.evidenceOrder.flatMap((evidenceId) => {
        const evidence = aggregate.evidence[evidenceId];
        if (evidence.receipt?.provenance?.measurements === undefined) {
            return [];
        }
        return evidence.receipt.provenance.measurements.map((measurement) => ({
            evidenceId,
            evidenceHash: evidence.commitEventHash,
            provenanceRoot: evidence.provenanceRoot,
            subjectId: measurement.subjectId,
            measurementRoot: measurement.measurementRoot,
            invalidated: evidence.invalidated,
            invalidatedSeq: evidence.invalidatedSeq,
        }));
    });
    const progress = searchProgress(aggregate);
    const frontierProjection = {
        active: progress.candidates.map((evidence) => projectArchiveEvidence(evidence)),
        attempted: progress.attemptedCandidates.map((evidence) => ({
            evidenceId: evidence.evidenceId,
            evidenceHash: evidence.commitEventHash,
            provenanceRoot: evidence.provenanceRoot,
            invalidated: evidence.invalidated,
            invalidatedSeq: evidence.invalidatedSeq,
            round: evidence.round,
            slotIndex: evidence.slotIndex,
        })),
        completedRounds: progress.completedRounds,
        nextRound: progress.nextRound,
        nextSlot: progress.nextSlot,
        roundsExhausted: progress.roundsExhausted,
        boundedComplete: progress.boundedComplete,
        boundedAttempted: progress.boundedAttempted,
    };
    const archive = buildCandidateArchive(aggregate);
    const archiveProjection = {
        accepted: archive.accepted.map(projectArchiveEvidence),
        nearMisses: archive.nearMisses.map(projectArchiveEvidence),
        rejected: archive.rejected.map(projectArchiveEvidence),
        invalidMetrics: archive.invalidMetrics.map(projectArchiveEvidence),
        mechanismGroups: archive.mechanismGroups,
        lessonGroups: archive.lessonGroups,
        duplicateIndex: archive.duplicateIndex,
        incumbent: archive.incumbent === null
            ? null
            : projectArchiveEvidence(archive.incumbent),
    };
    const core = {
        version: 1,
        validation: evidenceReference(validation),
        decisive: {
            kind: decisiveKind,
            evidence: decisiveEvidence === null ? null : evidenceReference(decisiveEvidence),
        },
        termination: {
            kind: basis.kind,
            basisHash: hashCanonical(basis, TERMINAL_BASIS_HASH_ALGORITHM),
            strategyRevision: aggregate.searchStrategy.revision,
            strategyHistoryHash: hashCanonical(
                aggregate.searchStrategy.history,
                TERMINAL_STRATEGY_HISTORY_HASH_ALGORITHM,
            ),
        },
        receipts: {
            count: receiptRoots.length,
            evidenceCount: aggregate.evidenceOrder.length,
            root: hashCanonical(
                receiptRoots,
                TERMINAL_RECEIPT_ROOTS_HASH_ALGORITHM,
            ),
        },
        frontier: {
            activeCandidateCount: progress.candidates.length,
            attemptedCandidateCount: progress.attemptedCandidates.length,
            digest: hashCanonical(
                frontierProjection,
                TERMINAL_FRONTIER_HASH_ALGORITHM,
            ),
        },
        archive: {
            acceptedCount: archive.accepted.length,
            nearMissCount: archive.nearMisses.length,
            rejectedCount: archive.rejected.length,
            invalidMetricsCount: archive.invalidMetrics.length,
            digest: hashCanonical(
                archiveProjection,
                TERMINAL_ARCHIVE_HASH_ALGORITHM,
            ),
        },
    };
    return {
        ...core,
        closureRoot: hashCanonical(core, TERMINAL_EVIDENCE_CLOSURE_HASH_ALGORITHM),
    };
}

function verifiedRecommendation(aggregate, incumbent, basis) {
    const readiness = assessVerifiedResultReadiness(aggregate, incumbent);
    if (!readiness.ready) {
        return scientificConfirmationRecommendation(
            aggregate,
            incumbent,
            basis,
            readiness,
        );
    }
    const payload = {
        decision: "VERIFIED_RESULT",
        candidateId: incumbent.candidateId,
        evidenceId: incumbent.evidenceId,
        evidenceHash: incumbent.commitEventHash,
        contractHash: aggregate.contractHash,
        basis,
        evidenceClosure: terminalEvidenceClosure(aggregate, {
            basis,
            decisiveKind: "winner",
            decisiveEvidence: incumbent,
        }),
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
        return independentVerificationRecommendation(
            aggregate,
            boundedBasis,
            assessTargetUnreachableReadiness(aggregate, null),
        );
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
        candidateCount: verifierCommand.request.trigger.candidateCount,
        candidateEvidenceHash: verifierCommand.request.trigger.candidateEvidenceHash,
    };
    const evidenceClosure = terminalEvidenceClosure(aggregate, {
        basis,
        decisiveKind: "impossibility_certificate",
        decisiveEvidence: evidence,
    });
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

function reserveCommandRecommendation(aggregate) {
    const commandId = nextCommandId(aggregate);
    const validationEvidence = currentValidationEvidence(aggregate);
    let command;
    if (validationEvidence === null) {
        command = {
            kind: "run_validation",
            harnessRole: "calibration",
            harnessId: aggregate.contract.harnessSuite.roles.calibration.harnessId,
            parserVersion:
                aggregate.contract.harnessSuite.roles.calibration.parser.version,
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

function buildImpossibilityVerificationCommand(aggregate, progress) {
    const validation = currentValidationEvidence(aggregate);
    const attemptOrdinal = impossibilityEvidenceItems(
        aggregate,
        { includeInvalidated: true },
    ).length + 1;
    const candidateEvidenceHash = impossibilitySearchEvidenceHash(progress.candidates);
    const request = {
        version: aggregate.contract.impossibilityPolicy.requestVersion,
        contract: aggregate.contract,
        contractHash: aggregate.contractHash,
        attemptOrdinal,
        trigger: {
            kind: aggregate.contract.impossibilityPolicy.trigger,
            roundsExhausted: true,
            completedRounds: progress.completedRounds,
            maxRounds: aggregate.contract.maxRounds,
            candidatesPerRound: aggregate.contract.candidatesPerRound,
            candidateCount: progress.candidates.length,
            acceptanceSatisfiedCount: progress.candidates.filter(
                (evidence) => evidence.acceptanceSatisfied === true,
            ).length,
            candidateEvidenceHash,
            validationEvidenceId: validation.evidenceId,
            validationEvidenceHash: validation.commitEventHash,
        },
    };
    return {
        kind: "verify_impossibility",
        harnessRole: "impossibility_verifier",
        harnessId:
            aggregate.contract.harnessSuite.roles.impossibility_verifier.harnessId,
        parserVersion:
            aggregate.contract.harnessSuite.roles.impossibility_verifier.parser.version,
        attemptOrdinal,
        certificateVersion: aggregate.contract.impossibilityPolicy.certificateVersion,
        request,
        requestHash: hashCanonical(request, IMPOSSIBILITY_REQUEST_HASH_ALGORITHM),
    };
}

function reserveImpossibilityRecommendation(aggregate, progress) {
    const commandId = nextCommandId(aggregate);
    const command = buildImpossibilityVerificationCommand(aggregate, progress);
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

    const unreachable = unreachableRecommendation(aggregate);
    if (unreachable !== null) {
        return unreachable;
    }

    const progress = searchProgress(aggregate);
    const targetObserved = progress.candidates.some(
        (evidence) => evidence.acceptanceSatisfied === true,
    );
    if (aggregate.contract.hypothesisTopology === "certified_impossibility"
        && incumbent === null
        && !targetObserved
        && progress.roundsExhausted) {
        const certificateEvidence = latestApplicableImpossibilityEvidence(aggregate);
        if (certificateEvidence !== null) {
            return impossibilityNonResultRecommendation(aggregate, certificateEvidence);
        }
    }
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

    if (aggregate.contract.hypothesisTopology === "certified_impossibility"
        && incumbent === null
        && !targetObserved
        && progress.roundsExhausted) {
        return reserveImpossibilityRecommendation(aggregate, progress);
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
