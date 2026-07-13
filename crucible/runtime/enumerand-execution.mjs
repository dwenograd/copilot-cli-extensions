import {
    assertEnumerandBinding,
    enumerandArtifactMeasurementHash,
    enumerandBindingHash,
    normalizeEnumerandManifest,
} from "../domain/enumerands.mjs";
import {
    canonicalEqual,
    immutableCanonical,
} from "../domain/canonical.mjs";
import {
    RuntimeIntegrityError,
} from "./errors.mjs";

export function resolveCommandEnumerand(contract, command) {
    const hasManifest = contract?.enumerandManifest !== undefined
        && contract.enumerandManifest !== null;
    const hasBinding = command?.enumerand !== undefined
        && command.enumerand !== null;
    if (!hasManifest && !hasBinding) {
        if (!Object.hasOwn(command ?? {}, "hypotheses")
            || command.hypotheses !== null) {
            throw new RuntimeIntegrityError(
                "Open-generative search commands must freeze hypotheses as null",
            );
        }
        return null;
    }
    if (hasManifest !== hasBinding) {
        throw new RuntimeIntegrityError(
            "Search command and contract must either both bind an enumerand or neither",
            { hasManifest, hasBinding },
        );
    }
    try {
        const manifestOptions = {
            topology: contract.enumerandManifest.topology,
            observableRegistry: contract.observableRegistry,
            hypothesisPolicy: contract.hypothesisPolicy,
        };
        const manifest = normalizeEnumerandManifest(
            contract.enumerandManifest,
            manifestOptions,
        );
        const binding = assertEnumerandBinding(
            manifest,
            command.enumerand,
            manifestOptions,
        );
        const globalSlot = (command.round - 1) * contract.candidatesPerRound
            + command.slotIndex;
        if (binding.ordinal !== globalSlot || binding.id !== command.candidateId) {
            throw new RuntimeIntegrityError(
                "Search command enumerand does not match its frozen slot and candidate id",
                {
                    expectedOrdinal: globalSlot,
                    actualOrdinal: binding.ordinal,
                    expectedCandidateId: binding.id,
                    actualCandidateId: command.candidateId,
                },
            );
        }
        if (!canonicalEqual(
            command.hypotheses ?? null,
            binding.hypotheses ?? null,
        )) {
            throw new RuntimeIntegrityError(
                "Search command hypotheses do not match the frozen enumerand",
                {
                    ordinal: binding.ordinal,
                    enumerandHash: binding.enumerandHash,
                },
            );
        }
        return immutableCanonical({
            manifest,
            binding,
            bindingHash: enumerandBindingHash(binding, manifestOptions),
            execution: binding.topology === "finite_enumerable"
                ? {
                    kind: "staged_snapshot",
                    artifactSnapshotHash: binding.artifactSnapshotHash,
                    candidateArtifactHash: enumerandArtifactMeasurementHash(
                        binding.artifactSnapshotHash,
                    ),
                }
                : {
                    kind: "bounded_parameter_generation",
                    parameterTuple: binding.parameterTuple,
                    parameterTupleHash: binding.parameterTupleHash,
                },
        });
    } catch (error) {
        if (error instanceof RuntimeIntegrityError) {
            throw error;
        }
        throw new RuntimeIntegrityError(
            "Search command enumerand failed frozen-manifest verification",
            {
                cause: error?.message ?? String(error),
            },
            { cause: error },
        );
    }
}

export function assertFiniteEnumerandSnapshot(plan, snapshotId, candidateArtifactHash) {
    if (plan?.execution?.kind !== "staged_snapshot") {
        throw new RuntimeIntegrityError(
            "Finite snapshot verification requires a staged-snapshot enumerand plan",
        );
    }
    if (snapshotId !== plan.execution.artifactSnapshotHash
        || candidateArtifactHash !== plan.execution.candidateArtifactHash) {
        throw new RuntimeIntegrityError(
            "Finite runner attempted to evaluate content outside its staged enumerand",
            {
                expectedSnapshot: plan.execution.artifactSnapshotHash,
                actualSnapshot: snapshotId,
                expectedCandidateArtifactHash:
                    plan.execution.candidateArtifactHash,
                actualCandidateArtifactHash: candidateArtifactHash,
            },
        );
    }
    return plan.binding;
}

export function assertBoundedEnumerandRequest(plan, request) {
    if (plan?.execution?.kind !== "bounded_parameter_generation") {
        throw new RuntimeIntegrityError(
            "Bounded request verification requires a parameterized enumerand plan",
        );
    }
    if (request?.enumerandBindingHash !== plan.bindingHash
        || request?.candidateId !== plan.binding.id) {
        throw new RuntimeIntegrityError(
            "Parameterized candidate request is not bound to its frozen tuple",
            {
                expectedBindingHash: plan.bindingHash,
                actualBindingHash: request?.enumerandBindingHash ?? null,
                expectedCandidateId: plan.binding.id,
                actualCandidateId: request?.candidateId ?? null,
            },
        );
    }
    return plan.binding;
}
