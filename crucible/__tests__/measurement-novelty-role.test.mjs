import { describe, expect, it } from "vitest";

import {
    createInvestigationContract,
    hashCanonical,
} from "../domain/index.mjs";
import {
    NOVELTY_MAX_STRUCTURAL_FEATURES,
    adaptNoveltyRoleAttempt,
    createNoveltyMeasurementBinding,
    noveltyRoleFingerprint,
    tryAdaptNoveltyRoleAttempt,
} from "../measurement/index.mjs";
import { makeV4ContractInput } from "./v4-contract-fixture.mjs";

function contract() {
    return createInvestigationContract(makeV4ContractInput({
        candidatesPerRound: 1,
        maxRounds: 1,
        workerModels: ["model-a"],
    }));
}

function fixture({
    features = { branchCount: 1, nodeCount: 2 },
    pass = true,
} = {}) {
    const frozen = contract();
    const snapshotHash = hashCanonical(
        { candidate: "snapshot" },
        "sha256:crucible-measurement-snapshot-v1",
    );
    const binding = createNoveltyMeasurementBinding({
        contract: frozen,
        candidateArtifactHash: snapshotHash,
    });
    const receiptHash = hashCanonical(
        { receipt: "novelty" },
        "sha256:crucible-measurement-receipt-v1",
    );
    const measurementRoot = hashCanonical(
        { measurement: "novelty" },
        "sha256:crucible-evidence-measurement-provenance-v1",
    );
    const parsed = {
        pass,
        metrics: features,
        observables: null,
        validationCases: null,
        searchSpaceExhausted: null,
        impossibilityCertificateHash: null,
        ...binding,
        parserVersion: frozen.harnessSuite.roles.novelty.parser.version,
    };
    const attempt = {
        version: 1,
        attemptId: "novelty-attempt",
        role: binding.role,
        phase: binding.phase,
        replicateIndex: binding.replicateIndex,
        blockIndex: binding.blockIndex,
        armIndex: binding.armIndex,
        armId: binding.armId,
        deterministicSeed: binding.deterministicSeed,
        subjectId: binding.subjectId,
        parsed,
        invalid: null,
        receiptHash,
        measurementRoot,
    };
    const role = frozen.harnessSuite.roles.novelty;
    const measurement = {
        subjectId: binding.subjectId,
        role: "novelty",
        phase: "novelty",
        receiptHash,
        measurementRoot,
        parserVersion: role.parser.version,
        harnessEntryHash: role.harnessEntryHash,
        executableHash: role.executableHash,
        snapshot: { snapshotHash },
        rawStdoutHash: hashCanonical(
            { text: "first formatting" },
            "sha256:crucible-measurement-stream-v1",
        ),
    };
    return {
        contract: frozen,
        snapshotHash,
        binding,
        attempt,
        measurement,
    };
}

describe("novelty role adapter", () => {
    it("derives a canonical structural fingerprint from bounded role facts", () => {
        const input = fixture();
        const first = adaptNoveltyRoleAttempt({
            attempt: input.attempt,
            measurement: input.measurement,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        });
        const second = adaptNoveltyRoleAttempt({
            attempt: structuredClone(input.attempt),
            measurement: structuredClone(input.measurement),
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        });

        expect(first).toEqual(second);
        expect(first.structuralFingerprint)
            .toMatch(/^sha256:crucible-novelty-structural-v1:[a-f0-9]{64}$/u);
        expect(first.roleFingerprint).toBe(noveltyRoleFingerprint(input.contract));
        expect(Object.isFrozen(first)).toBe(true);
    });

    it("ignores raw output text hashes while binding the receipt and role", () => {
        const input = fixture();
        const first = adaptNoveltyRoleAttempt({
            attempt: input.attempt,
            measurement: input.measurement,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        });
        const changedText = {
            ...input.measurement,
            rawStdoutHash: hashCanonical(
                { text: "different formatting and labels" },
                "sha256:crucible-measurement-stream-v1",
            ),
        };
        const second = adaptNoveltyRoleAttempt({
            attempt: input.attempt,
            measurement: changedText,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        });
        expect(second.structuralFingerprint).toBe(first.structuralFingerprint);

        expect(tryAdaptNoveltyRoleAttempt({
            attempt: input.attempt,
            measurement: {
                ...input.measurement,
                receiptHash: hashCanonical({ forged: true }),
            },
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        })).toBeNull();
    });

    it("changes only for trusted structural facts or the pinned role", () => {
        const input = fixture();
        const first = adaptNoveltyRoleAttempt({
            attempt: input.attempt,
            measurement: input.measurement,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        });
        const changed = fixture({
            features: { branchCount: 2, nodeCount: 2 },
        });
        const second = adaptNoveltyRoleAttempt({
            attempt: changed.attempt,
            measurement: changed.measurement,
            contract: changed.contract,
            candidateArtifactHash: changed.snapshotHash,
        });
        expect(second.structuralFingerprint).not.toBe(first.structuralFingerprint);

        const changedContract = structuredClone(input.contract);
        changedContract.harnessSuite.roles.novelty.configHash =
            hashCanonical({ config: "changed" });
        expect(noveltyRoleFingerprint(changedContract))
            .not.toBe(noveltyRoleFingerprint(input.contract));
    });

    it("fails closed on non-canonical or role-inappropriate parsed facts", () => {
        const input = fixture();
        const adapt = (parsed) => tryAdaptNoveltyRoleAttempt({
            attempt: {
               ...input.attempt,
               parsed,
            },
            measurement: input.measurement,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        });

        expect(adapt({
            ...input.attempt.parsed,
            model: "untrusted-label",
        })).toBeNull();
        expect(adapt({
            ...input.attempt.parsed,
            observables: { proseCode: "model-output" },
        })).toBeNull();
        expect(adapt({
            ...input.attempt.parsed,
            parserVersion: "forged-parser",
        })).toBeNull();
        expect(adapt({
            ...input.attempt.parsed,
            environmentIdentity: hashCanonical({ forged: "environment" }),
        })).toBeNull();
    });

    it("treats missing, invalid, failed, and oversized novelty as no novelty", () => {
        const input = fixture();
        expect(tryAdaptNoveltyRoleAttempt({
            attempt: {
                ...input.attempt,
                parsed: {
                    ...input.attempt.parsed,
                    metrics: null,
                },
            },
            measurement: input.measurement,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        })).toBeNull();
        expect(tryAdaptNoveltyRoleAttempt({
            attempt: {
                ...input.attempt,
                parsed: {
                    ...input.attempt.parsed,
                    pass: false,
                },
            },
            measurement: input.measurement,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        })).toBeNull();
        expect(tryAdaptNoveltyRoleAttempt({
            attempt: {
                ...input.attempt,
                parsed: null,
                invalid: { code: "PARSE_SCHEMA" },
            },
            measurement: input.measurement,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        })).toBeNull();
        const tooMany = Object.fromEntries(
            Array.from(
                { length: NOVELTY_MAX_STRUCTURAL_FEATURES + 1 },
                (_unused, index) => [`feature_${index}`, index],
            ),
        );
        expect(tryAdaptNoveltyRoleAttempt({
            attempt: {
                ...input.attempt,
                parsed: {
                    ...input.attempt.parsed,
                    metrics: tooMany,
                },
            },
            measurement: input.measurement,
            contract: input.contract,
            candidateArtifactHash: input.snapshotHash,
        })).toBeNull();
    });
});
