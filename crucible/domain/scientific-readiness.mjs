import {
    canonicalEqual,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    deriveReplicationControlBinding,
    normalizeRawMeasurementSeries,
    normalizeReplicationSchedule,
    replicationBlockPlan,
} from "./replication.mjs";
import { evaluateReplicationProgress } from "./statistical-evaluation.mjs";
import {
    deriveScientificConclusion,
    scientificReplaySummary,
} from "./scientific-replay.mjs";
import { deriveScientificConfirmationState } from "./confirmation.mjs";

function requiredPredictions(evidenceItems) {
    return evidenceItems.flatMap((evidence) => {
        const predictions =
            evidence?.annotations?.hypotheses?.predictions;
        if (!Array.isArray(predictions)) return [];
        return predictions
            .filter((prediction) =>
                prediction?.requiredForResult === true)
            .map((prediction) => ({
                candidateId: evidence.candidateId,
                evidenceId: evidence.evidenceId,
                id: prediction.id,
                hypothesisIdentity:
                    evidence.annotations.hypotheses.identity,
            }));
    }).sort((left, right) =>
        `${left.evidenceId}\0${left.id}`.localeCompare(
            `${right.evidenceId}\0${right.id}`,
        ));
}

function ownEntry(record, key) {
    return record !== null
        && typeof record === "object"
        && typeof key === "string"
        && Object.hasOwn(record, key)
        ? record[key]
        : null;
}

function replicatedEvidenceIntegrity(aggregate, evidence) {
    try {
        if (evidence?.sourceKind !== "harness"
            || (evidence.purpose !== "candidate"
                && evidence.purpose !== "confirmation"
                && evidence.purpose !== "challenge")) {
            return false;
        }
        const observation = ownEntry(
            aggregate.observations,
            evidence.observationId,
        );
        const command = ownEntry(
            aggregate.commands,
            observation?.commandId,
        )?.command ?? null;
        const expectedKind = evidence.purpose === "candidate"
            ? "search_candidate"
            : evidence.purpose === "confirmation"
                ? "run_confirmation"
                : "run_challenge";
        if (command?.kind !== expectedKind
            || !Object.hasOwn(command, "hypotheses")
            || !canonicalEqual(
                command.hypotheses,
                observation?.annotations?.hypotheses ?? null,
            )
            || evidence.hypothesesIdentity
                !== (command.hypotheses?.identity ?? null)
            || !canonicalEqual(
                evidence.annotations?.hypotheses ?? null,
                command.hypotheses,
            )) {
            return false;
        }
        const role = evidence.purpose === "candidate"
            ? "search"
            : evidence.purpose;
        const normalized = normalizeRawMeasurementSeries(
            observation.data.series[0],
            {
                schedule: command.replicationSchedule,
                role,
                phase: role,
                caseId: null,
            },
        );
        const progress = evaluateReplicationProgress({
            contract: aggregate.contract,
            schedule: command.replicationSchedule,
            attempts: normalized.attempts,
        });
        if (progress.shouldContinue
            || !canonicalEqual(
                evidence.replication?.stopping ?? null,
                progress.stopping,
            )
            || evidence.replication?.stoppingDigest
                !== progress.stoppingDigest
            || evidence.replication?.scheduleHash
                !== progress.scheduleHash
            || evidence.replication?.minBlocks !== progress.minBlocks
            || evidence.replication?.maxBlocks !== progress.maxBlocks
            || evidence.replication?.blockCount !== progress.blockCount
            || evidence.replication?.attemptCount !== progress.attemptCount
            || evidence.replication?.blockLedgerHash
                !== evidence.statisticalEvaluation?.blockLedger?.hash) {
            return false;
        }
        const schedule = normalizeReplicationSchedule(
            command.replicationSchedule,
        );
        const measurementBySubject = new Map(
            observation.receipt.provenance.measurements.map((measurement) => [
                measurement.subjectId,
                measurement,
            ]),
        );
        const controlSnapshotHashes = normalized.series.completeBlocks.flatMap(
            (block) => replicationBlockPlan(
                schedule,
                block.blockIndex,
            ).arms.filter((arm) => arm.armId === "control")
                .map((arm) =>
                    measurementBySubject.get(arm.subjectId)
                        ?.snapshot?.snapshotHash ?? null),
        );
        if (controlSnapshotHashes.some((hash) => hash === null)) return false;
        const control = deriveReplicationControlBinding({
            contractHash: aggregate.contractHash,
            statisticalPolicy: aggregate.contract.statisticalPolicy,
            schedule,
            enumerandManifest: aggregate.contract.enumerandManifest ?? null,
            manifestOptions: {
                topology: aggregate.contract.hypothesisTopology,
                observableRegistry: aggregate.contract.observableRegistry,
                hypothesisPolicy: aggregate.contract.hypothesisPolicy,
            },
            controlSnapshotHashes,
            requireObservedControl: true,
        });
        return canonicalEqual(
            evidence.replication?.control ?? null,
            control,
        );
    } catch {
        return false;
    }
}

function validationEvidenceIntegrity(aggregate, evidence) {
    try {
        if (evidence?.sourceKind !== "harness"
            || evidence.purpose !== "validation") {
            return false;
        }
        const observation = ownEntry(
            aggregate.observations,
            evidence.observationId,
        );
        const command = ownEntry(
            aggregate.commands,
            observation?.commandId,
        )?.command ?? null;
        if (command?.kind !== "run_validation"
            || !Array.isArray(command.validationSeries)) {
            return false;
        }
        const bindings = command.validationSeries.map((series) =>
            deriveReplicationControlBinding({
                contractHash: aggregate.contractHash,
                statisticalPolicy: aggregate.contract.statisticalPolicy,
                schedule: series.replicationSchedule,
                enumerandManifest:
                    aggregate.contract.enumerandManifest ?? null,
                manifestOptions: {
                    topology: aggregate.contract.hypothesisTopology,
                    observableRegistry:
                        aggregate.contract.observableRegistry,
                    hypothesisPolicy:
                        aggregate.contract.hypothesisPolicy,
                },
            }));
        return canonicalEqual(
            evidence.validationControlBindings ?? [],
            bindings,
        );
    } catch {
        return false;
    }
}

function scientificEvidenceBindingsValid(aggregate) {
    if (!Array.isArray(aggregate.evidenceOrder)) return true;
    return aggregate.evidenceOrder.every((evidenceId) => {
        const evidence = ownEntry(aggregate.evidence, evidenceId);
        if (evidence?.sourceKind !== "harness") return true;
        if (evidence.purpose === "candidate"
            || evidence.purpose === "confirmation"
            || evidence.purpose === "challenge") {
            return replicatedEvidenceIntegrity(aggregate, evidence);
        }
        if (evidence.purpose === "validation") {
            return validationEvidenceIntegrity(aggregate, evidence);
        }
        return true;
    });
}

function terminalClosureBound(aggregate, terminal, decisiveKind) {
    let replaySummary;
    let conclusionBound = true;
    try {
        replaySummary = scientificReplaySummary(
            aggregate.scientificReplay,
        );
        if (decisiveKind === "winner") {
            conclusionBound = canonicalEqual(
                terminal?.evidenceClosure?.scientificConclusion,
                deriveScientificConclusion(
                    aggregate,
                    terminal?.evidenceId,
                ),
            );
        } else if (decisiveKind === "candidate_cohort") {
            const cohort = aggregate.scientificReplay?.candidateCohort;
            const evidenceIds = cohort?.cohort?.map(
                (candidate) => candidate.evidenceId,
            ) ?? [];
            conclusionBound = canonicalEqual(
                terminal?.evidenceClosure?.candidateCohort,
                cohort,
            ) && canonicalEqual(
                terminal?.evidenceClosure?.scientificConclusions,
                evidenceIds.map((evidenceId) =>
                    deriveScientificConclusion(aggregate, evidenceId)),
            ) && terminal?.evidenceClosure?.relationEvidence
                ?.comparisonHash === cohort?.comparisonHash
                && terminal.evidenceClosure.relationEvidence
                    .relationEvidenceHash === cohort?.relationEvidenceHash;
        }
    } catch {
        return false;
    }
    return terminal?.evidenceClosure !== null
        && typeof terminal?.evidenceClosure === "object"
        && terminal.evidenceClosure.decisive?.kind === decisiveKind
        && isAlgorithmTaggedSha256(terminal.evidenceClosure.closureRoot)
        && terminal.evidenceClosure.scientificReplay !== undefined
        && canonicalEqual(
            terminal.evidenceClosure.scientificReplay,
            replaySummary,
        )
        && scientificEvidenceBindingsValid(aggregate)
        && conclusionBound;
}

function resolvedCohortEvidence(aggregate, incumbent = null) {
    const cohort = aggregate?.scientificReplay?.candidateCohort ?? null;
    if (cohort?.resolved !== true
        || (cohort.status !== "UNIQUE_BEST"
            && cohort.status !== "TIE_COHORT")) {
        const legacyEvidence = incumbent?.evidenceId === undefined
            ? null
            : ownEntry(aggregate?.evidence, incumbent.evidenceId);
        const support = aggregate?.scientificReplay?.candidateSupport?.find(
            (item) => item.evidenceId === incumbent?.evidenceId,
        ) ?? null;
        if (legacyEvidence !== null
            && legacyEvidence?.invalidated !== true
            && support?.requiredState === "SUPPORTED"
            && support?.acceptanceSatisfied === true) {
            return {
                cohort: {
                    status: "UNIQUE_BEST",
                    resolved: true,
                    comparisonHash: null,
                    relationEvidenceHash: null,
                    provisionalWinner: {
                        evidenceId: legacyEvidence.evidenceId,
                    },
                    cohort: [{
                        candidateId: legacyEvidence.candidateId,
                        evidenceId: legacyEvidence.evidenceId,
                        evidenceHash: legacyEvidence.commitEventHash,
                    }],
                },
                evidence: [legacyEvidence],
            };
        }
        return { cohort, evidence: [] };
    }
    const evidence = cohort.cohort
        .map((candidate) => ownEntry(
            aggregate.evidence,
            candidate.evidenceId,
        ))
        .filter((item) =>
            item !== null && item.invalidated !== true);
    return { cohort, evidence };
}

export function assessVerifiedResultReadiness(aggregate, incumbent = null) {
    const policy = aggregate.contract.scientificTerminalPolicy;
    const resolved = resolvedCohortEvidence(aggregate, incumbent);
    const cohort = resolved.cohort;
    const cohortEvidence = resolved.evidence;
    const requestedEvidenceId = incumbent?.evidenceId
        ?? incumbent?.provisionalWinner?.evidenceId
        ?? null;
    const requestedCohortBound = requestedEvidenceId === null
        || (cohort?.status === "UNIQUE_BEST"
            && cohort.provisionalWinner?.evidenceId
                === requestedEvidenceId);
    const candidateEvidenceHashes = cohortEvidence.map(
        (evidence) => evidence.commitEventHash,
    );
    const freeze = aggregate.confirmation?.freeze?.payload ?? null;
    const confirmationState =
        aggregate.scientificReplay?.confirmationState
        ?? deriveScientificConfirmationState(aggregate);
    const modernClosureBound = freeze?.contractHash === aggregate.contractHash
        && freeze.discoveryClosure?.cohortComparisonHash
            === cohort?.comparisonHash
        && freeze.discoveryClosure?.relationEvidenceHash
            === cohort?.relationEvidenceHash
        && canonicalEqual(
            freeze.discoveryClosure?.candidateIds,
            cohortEvidence.map((evidence) => evidence.candidateId),
        )
        && canonicalEqual(
            freeze.discoveryClosure?.evidenceIds,
            cohortEvidence.map((evidence) => evidence.evidenceId),
        )
        && canonicalEqual(
            freeze.discoveryClosure?.evidenceHashes,
            candidateEvidenceHashes,
        )
        && confirmationState.freezeHash === freeze.freezeHash
        && isAlgorithmTaggedSha256(confirmationState.closureHash);
    const closureBound = requestedCohortBound
        && cohortEvidence.length === (cohort?.cohort?.length ?? -1)
        && modernClosureBound;
    const confirmationClosureReady = closureBound
        && confirmationState.status === "READY"
        && confirmationState.ready === true
        && confirmationState.failed === false;
    const confirmationSupported = confirmationClosureReady
        && confirmationState.members.length === cohortEvidence.length
        && confirmationState.members.every((member) =>
            member.roles.some((role) =>
                role.role === "confirmation"
                && role.status === "SUPPORTED"
                && isAlgorithmTaggedSha256(role.evidenceHash)));
    const challengeSupported = confirmationClosureReady
        && confirmationState.members.length === cohortEvidence.length
        && confirmationState.members.every((member) =>
            member.roles.some((role) =>
                role.role === "challenge"
                && role.status === "SUPPORTED"
                && isAlgorithmTaggedSha256(role.evidenceHash)));
    const required = requiredPredictions(cohortEvidence);
    const replaySupportByEvidence = new Map(
        (aggregate.scientificReplay?.candidateSupport ?? []).map(
            (item) => [item.evidenceId, item],
        ),
    );
    const predictionEvaluationsBound = required.every((prediction) => {
        const evidence = ownEntry(
            aggregate.evidence,
            prediction.evidenceId,
        );
        const evaluation = replaySupportByEvidence.get(
            prediction.evidenceId,
        )?.predictionEvaluation ?? null;
        return evaluation !== null
            && evaluation.hypothesesIdentity
                === prediction.hypothesisIdentity
            && evaluation.evidenceReference?.evidenceId
                === prediction.evidenceId
            && evaluation.evidenceReference?.evidenceHash
                === evidence?.commitEventHash;
    });
    const evaluations = new Map(
        cohortEvidence.flatMap((evidence) =>
            (replaySupportByEvidence.get(evidence.evidenceId)
                ?.predictionEvaluation?.predictions ?? [])
                .map((prediction) => [
                    `${evidence.evidenceId}\0${prediction.predictionId}`,
                    {
                        evidenceId: evidence.evidenceId,
                        candidateId: evidence.candidateId,
                        ...prediction,
                    },
                ])),
    );
    const predictionDisplayId = ({ evidenceId, id }) =>
        cohortEvidence.length === 1 ? id : `${evidenceId}:${id}`;
    const unsupportedRequiredPredictions = required
        .filter(({ evidenceId, id }) =>
            !predictionEvaluationsBound
            || evaluations.get(`${evidenceId}\0${id}`)?.status
                !== "SUPPORTED")
        .map(predictionDisplayId);
    const requiredStatuses = required.map(({ evidenceId, id }) =>
        evaluations.get(`${evidenceId}\0${id}`)?.status ?? "UNRESOLVED");
    const requiredPredictionState = required.length === 0
        ? "SUPPORTED"
        : !predictionEvaluationsBound
            ? "UNRESOLVED"
            : requiredStatuses.includes("INVALID")
                ? "INVALID"
                : requiredStatuses.includes("REFUTED")
                    ? "REFUTED"
                    : requiredStatuses.every((status) =>
                        status === "SUPPORTED")
                        ? "SUPPORTED"
                        : "UNRESOLVED";
    const missing = [];
    const scientificBindingsValid =
        scientificEvidenceBindingsValid(aggregate);
    const statisticalCohortSupported = cohort?.resolved === true
        && cohortEvidence.length > 0
        && cohortEvidence.length === cohort.cohort.length;
    if (!statisticalCohortSupported) {
        missing.push("statistical_candidate_cohort_support");
    }
    if (!scientificBindingsValid) {
        missing.push("trusted_command_hypothesis_control_stopping_bindings");
    }
    if (policy.verifiedResult.confirmationRequired && !confirmationSupported) {
        missing.push("trusted_confirmation_closure");
    }
    if (policy.verifiedResult.challengeRequired && !challengeSupported) {
        missing.push("trusted_challenge_closure");
    }
    if (policy.hypotheses.requiredForResultMustBeSupported
        && unsupportedRequiredPredictions.length > 0) {
        missing.push("trusted_required_prediction_evaluations");
    }
    return immutableCanonical({
        ready: missing.length === 0,
        policyVersion: policy.version,
        cohortStatus: cohort?.status ?? null,
        cohortSize: cohortEvidence.length,
        cohortComparisonHash: cohort?.comparisonHash ?? null,
        relationEvidenceHash: cohort?.relationEvidenceHash ?? null,
        confirmationFreezeHash: freeze?.freezeHash ?? null,
        confirmationClosureHash: confirmationState.closureHash,
        confirmationStatus: confirmationState.status,
        confirmationClosureReady,
        confirmationSupported,
        challengeSupported,
        statisticalCohortSupported,
        scientificBindingsValid,
        statisticalCandidateSupported:
            statisticalCohortSupported && cohortEvidence.length === 1,
        predictionEvaluationsBound,
        requiredPredictionState,
        requiredPredictionIds: required.map(predictionDisplayId),
        requiredPredictionRefs: required.map(
            ({ candidateId, evidenceId, id }) => ({
                candidateId,
                evidenceId,
                predictionId: id,
            }),
        ),
        unsupportedRequiredPredictionIds: unsupportedRequiredPredictions,
        predictionStatuses: [...evaluations.values()].map((prediction) => ({
            ...(cohortEvidence.length === 1
                ? {}
                : {
                    candidateId: prediction.candidateId,
                    evidenceId: prediction.evidenceId,
                }),
            id: prediction.predictionId,
            requiredForResult: prediction.requiredForResult,
            status: prediction.status,
        })),
        missing,
    });
}

export function assessTargetUnreachableReadiness(aggregate, evidence) {
    const policy = aggregate.contract.scientificTerminalPolicy;
    const observation = ownEntry(
        aggregate.observations,
        evidence?.observationId,
    );
    const command = ownEntry(
        aggregate.commands,
        observation?.commandId,
    )?.command ?? null;
    const verifierRole =
        aggregate.contract.harnessSuite.roles.impossibility_verifier ?? null;
    const independentVerifierRoleBound = verifierRole !== null
        && command?.kind === "verify_impossibility"
        && command.harnessRole === "impossibility_verifier"
        && command.harnessId === verifierRole.harnessId
        && command.parserVersion === verifierRole.parser.version
        && evidence?.harnessId === verifierRole.harnessId
        && evidence?.parserVersion === verifierRole.parser.version;
    const independentVerifierSupported = evidence !== null
        && evidence?.sourceKind === "harness"
        && evidence?.purpose === "impossibility"
        && evidence?.invalidated !== true
        && evidence?.unreachableBasis !== null
        && evidence?.unreachableBasis !== undefined
        && isAlgorithmTaggedSha256(evidence?.commitEventHash)
        && independentVerifierRoleBound;
    return immutableCanonical({
        ready: !policy.targetUnreachable.independentVerifierRequired
            || independentVerifierSupported,
        policyVersion: policy.version,
        independentVerifierSupported,
        independentVerifierRoleBound,
        missing: policy.targetUnreachable.independentVerifierRequired
                && !independentVerifierSupported
            ? ["independent_impossibility_verifier_evidence"]
            : [],
    });
}

export function assessPersistedTerminalReadiness(aggregate) {
    const terminal = aggregate?.terminal ?? null;
    if (terminal === null || aggregate?.contract === null) {
        return immutableCanonical({
            ready: false,
            decision: null,
            integrityBound: false,
            nonResultCode: "INTEGRITY_BLOCKED",
            missing: ["persisted_terminal"],
        });
    }

    const evidence = ownEntry(aggregate.evidence, terminal.evidenceId);
    const commonBound = terminal.contractHash === aggregate.contractHash
        && evidence !== null
        && evidence.invalidated !== true
        && terminal.evidenceId === evidence.evidenceId
        && terminal.evidenceHash === evidence.commitEventHash;

    if (terminal.decision === "VERIFIED_RESULT") {
        const resolved = resolvedCohortEvidence(aggregate, evidence);
        const cohort = resolved.cohort;
        const cohortEvidence = resolved.evidence;
        const modernBound = cohort?.resolved === true
            && cohortEvidence.length > 0
            && cohortEvidence.length === cohort.cohort.length
            && terminal.contractHash === aggregate.contractHash
            && Array.isArray(terminal.candidateIds)
            && canonicalEqual(
                terminal.candidateIds,
                cohortEvidence.map((item) => item.candidateId),
            )
            && Array.isArray(terminal.evidenceIds)
            && canonicalEqual(
                terminal.evidenceIds,
                cohortEvidence.map((item) => item.evidenceId),
            )
            && Array.isArray(terminal.evidenceHashes)
            && canonicalEqual(
                terminal.evidenceHashes,
                cohortEvidence.map((item) => item.commitEventHash),
            )
            && terminal.cohortComparisonHash === cohort.comparisonHash
            && terminal.relationEvidenceHash
                === cohort.relationEvidenceHash
            && terminalClosureBound(
                aggregate,
                terminal,
                "candidate_cohort",
            );
        const legacyBound = commonBound
            && evidence.sourceKind === "harness"
            && evidence.purpose === "candidate"
            && terminal.candidateId === evidence.candidateId
            && terminalClosureBound(aggregate, terminal, "winner");
        const integrityBound = modernBound || legacyBound;
        const scientific = integrityBound
            ? assessVerifiedResultReadiness(
                aggregate,
                modernBound ? cohort : evidence,
            )
            : null;
        return immutableCanonical({
            ready: integrityBound && scientific.ready,
            decision: terminal.decision,
            integrityBound,
            nonResultCode: integrityBound
                ? "SCIENTIFIC_CONFIRMATION_REQUIRED"
                : "INTEGRITY_BLOCKED",
            scientific,
            missing: integrityBound
                ? scientific.missing
                : ["persisted_verified_result_binding"],
        });
    }

    if (terminal.decision === "TARGET_UNREACHABLE") {
        const integrityBound = commonBound
            && evidence.sourceKind === "harness"
            && evidence.purpose === "impossibility"
            && terminalClosureBound(
                aggregate,
                terminal,
                "impossibility_certificate",
            );
        const scientific = integrityBound
            ? assessTargetUnreachableReadiness(aggregate, evidence)
            : null;
        return immutableCanonical({
            ready: integrityBound && scientific.ready,
            decision: terminal.decision,
            integrityBound,
            nonResultCode: integrityBound
                ? "INDEPENDENT_VERIFICATION_REQUIRED"
                : "INTEGRITY_BLOCKED",
            scientific,
            missing: integrityBound
                ? scientific.missing
                : ["persisted_target_unreachable_binding"],
        });
    }

    return immutableCanonical({
        ready: false,
        decision: null,
        integrityBound: false,
        nonResultCode: "INTEGRITY_BLOCKED",
        missing: ["unsupported_persisted_terminal_decision"],
    });
}
