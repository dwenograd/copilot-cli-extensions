import { hashCanonical } from "./canonical.mjs";
import { commandBudget } from "./contract.mjs";
import {
    EVENT_TYPES,
    IMPOSSIBILITY_REQUEST_HASH_ALGORITHM,
    NON_RESULT_CODES,
} from "./constants.mjs";
import { impossibilitySearchEvidenceHash } from "./impossibility.mjs";
import {
    deriveReplicationSchedule,
    statisticalSubjectIndex,
} from "./replication.mjs";
import { DecisionError, ERROR_CODES } from "./errors.mjs";
import { detectPlateau, buildSearchCandidateCommand } from "./strategy.mjs";
import { buildCandidateArchive } from "./archive.mjs";
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
    deriveScientificConclusion,
    scientificReplaySummary,
} from "./scientific-replay.mjs";
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
    "sha256:crucible-terminal-evidence-closure-v2";

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

export function deriveTerminalEvidenceClosure(
    aggregate,
    {
        basis,
        decisiveKind,
        decisiveEvidence = null,
    },
) {
    const decisiveEvidenceItems = Array.isArray(decisiveEvidence)
        ? decisiveEvidence
        : decisiveEvidence === null
            ? []
            : [decisiveEvidence];
    const candidateCohort = candidateCohortState(aggregate);
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
            evidence: decisiveEvidenceItems.length === 1
                ? evidenceReference(decisiveEvidenceItems[0])
                : null,
            cohort: decisiveEvidenceItems.map(evidenceReference),
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
        scientificReplay: scientificReplaySummary(
            aggregate.scientificReplay,
        ),
        scientificConfirmation:
            aggregate.scientificReplay?.confirmationState ?? null,
        candidateCohort: decisiveKind === "candidate_cohort"
            ? candidateCohort
            : null,
        relationEvidence: decisiveKind === "candidate_cohort"
            ? {
                comparisonHash: candidateCohort?.comparisonHash ?? null,
                relationEvidenceHash:
                    candidateCohort?.relationEvidenceHash ?? null,
                status: candidateCohort?.status ?? null,
                decisiveRelations:
                    candidateCohort?.decisiveRelations ?? [],
            }
            : null,
        scientificConclusion: decisiveKind === "winner"
            && decisiveEvidenceItems.length === 1
            ? deriveScientificConclusion(
                aggregate,
                decisiveEvidenceItems[0].evidenceId,
            )
            : null,
        scientificConclusions: decisiveKind === "candidate_cohort"
            ? decisiveEvidenceItems.map((evidence) =>
                deriveScientificConclusion(
                    aggregate,
                    evidence.evidenceId,
                ))
            : [],
    };
    return {
        ...core,
        closureRoot: hashCanonical(core, TERMINAL_EVIDENCE_CLOSURE_HASH_ALGORITHM),
    };
}

function verifiedRecommendation(aggregate, cohortEvidence, cohort, basis) {
    const readiness = assessVerifiedResultReadiness(aggregate, cohort);
    if (!readiness.ready) {
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
        evidenceClosure: deriveTerminalEvidenceClosure(aggregate, {
            basis,
            decisiveKind: "candidate_cohort",
            decisiveEvidence: cohortEvidence,
        }),
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
    const evidenceClosure = deriveTerminalEvidenceClosure(aggregate, {
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
        return !supportedCohort
            ? budgetRecommendation(
                aggregate,
                candidateCohort?.tieResolution?.required === true
                    ? "Declared command budget was exhausted before the preregistered candidate relations resolved."
                    : "Declared command budget was exhausted without a supported candidate cohort.",
                candidateCohort,
            )
            : freezeScientificConfirmationRecommendation(
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
        return reserveImpossibilityRecommendation(aggregate, progress);
    }

    if (progress.roundsExhausted) {
        return !supportedCohort
            ? budgetRecommendation(
                aggregate,
                candidateCohort?.tieResolution?.exhausted === true
                    ? "Frozen search and preregistered tie-resolution blocks were exhausted without a supported unique or equivalent cohort."
                    : "Frozen search rounds were exhausted without a supported candidate cohort.",
                candidateCohort,
            )
            : freezeScientificConfirmationRecommendation(
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
