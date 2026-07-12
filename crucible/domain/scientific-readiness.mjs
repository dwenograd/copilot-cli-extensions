import {
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";

function requiredPredictions(incumbent) {
    const predictions =
        incumbent?.annotations?.hypotheses?.predictions;
    if (!Array.isArray(predictions)) return [];
    return predictions
        .filter((prediction) => prediction?.requiredForResult === true)
        .map((prediction) => ({
            id: prediction.id,
            hypothesisIdentity:
                incumbent.annotations.hypotheses.identity,
        }))
        .sort((left, right) => left.id.localeCompare(right.id));
}

function trustedSupportedClosure(item) {
    return item?.trusted === true
        && item?.status === "supported"
        && isAlgorithmTaggedSha256(item?.evidenceHash);
}

function ownEntry(record, key) {
    return record !== null
        && typeof record === "object"
        && typeof key === "string"
        && Object.hasOwn(record, key)
        ? record[key]
        : null;
}

function terminalClosureBound(terminal, decisiveKind) {
    return terminal?.evidenceClosure !== null
        && typeof terminal?.evidenceClosure === "object"
        && terminal.evidenceClosure.decisive?.kind === decisiveKind
        && isAlgorithmTaggedSha256(terminal.evidenceClosure.closureRoot);
}

export function assessVerifiedResultReadiness(aggregate, incumbent) {
    const policy = aggregate.contract.scientificTerminalPolicy;
    const closure = aggregate.scientificTerminalClosure ?? null;
    const closureBound = closure?.contractHash === aggregate.contractHash
        && closure?.candidateEvidenceHash === incumbent?.commitEventHash;
    const confirmationSupported = closureBound
        && trustedSupportedClosure(closure?.confirmation);
    const challengeSupported = closureBound
        && trustedSupportedClosure(closure?.challenge);
    const required = requiredPredictions(incumbent);
    const evaluations = closureBound
        && closure?.predictionEvaluations !== null
        && typeof closure?.predictionEvaluations === "object"
        && !Array.isArray(closure.predictionEvaluations)
        ? closure.predictionEvaluations
        : {};
    const unsupportedRequiredPredictions = required
        .filter(({ id }) => !trustedSupportedClosure(evaluations[id]))
        .map(({ id }) => id);
    const missing = [];
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
        confirmationSupported,
        challengeSupported,
        requiredPredictionIds: required.map(({ id }) => id),
        unsupportedRequiredPredictionIds: unsupportedRequiredPredictions,
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
        const integrityBound = commonBound
            && evidence.sourceKind === "harness"
            && evidence.purpose === "candidate"
            && terminal.candidateId === evidence.candidateId
            && terminalClosureBound(terminal, "winner");
        const scientific = integrityBound
            ? assessVerifiedResultReadiness(aggregate, evidence)
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
            && terminalClosureBound(terminal, "impossibility_certificate");
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
