import { describe, expect, it } from "vitest";

import {
    assertEnumerandBinding,
    enumerandBinding,
    enumerandCoverage,
    enumerandExhaustion,
    enumerandIdentity,
    isEnumerandSpaceExhaustible,
    normalizeEnumerandManifest,
    resolveControlEnumerand,
    selectUntriedEnumerand,
} from "../domain/enumerands.mjs";
import { hashCanonical } from "../domain/canonical.mjs";
import { DEFAULT_SEARCH_POLICY } from "../domain/constants.mjs";
import { buildSearchCandidateCommand } from "../domain/strategy.mjs";
import {
    boundedSearchExhaustion,
    searchProgress,
} from "../domain/state.mjs";
import {
    materializeFiniteEnumerand,
    stageBoundedParameterizedManifest,
    stageFiniteEnumerandManifest,
    verifyStagedFiniteEnumerands,
} from "../persistence/enumerand-staging.mjs";
import {
    assertBoundedEnumerandRequest,
    assertFiniteEnumerandSnapshot,
    resolveCommandEnumerand,
} from "../runtime/enumerand-execution.mjs";
import {
    buildProposalPrompt,
    validateCandidateSubmission,
    validateWorkerProposal,
} from "../runtime/worker-pool.mjs";
import { fakeStatisticalPolicy } from "./v4-contract-fixture.mjs";

function snapshot(character) {
    return `sha256:${character.repeat(64)}`;
}

function finiteManifestInput() {
    return {
        topology: "finite_enumerable",
        entries: [
            { id: "candidate-a", ordinal: 0, artifactSnapshotHash: snapshot("a") },
            { id: "candidate-b", ordinal: 1, artifactSnapshotHash: snapshot("b") },
            { id: "candidate-c", ordinal: 2, artifactSnapshotHash: snapshot("c") },
        ],
        control: { kind: "enumerand", ordinal: 0 },
    };
}

function boundedManifestInput() {
    return {
        topology: "bounded_parameterized",
        entries: [
            {
                id: "tuple-a",
                ordinal: 0,
                parameterTuple: ["mode-a", { depth: 1, enabled: true }],
            },
            {
                id: "tuple-b",
                ordinal: 1,
                parameterTuple: ["mode-b", { depth: 2, enabled: false }],
            },
        ],
        control: {
            kind: "reference",
            referenceHash: "sha256:crucible-control-v1:"
                + "f".repeat(64),
        },
    };
}

const HYPOTHESIS_OPTIONS = Object.freeze({
    observableRegistry: Object.freeze([
        Object.freeze({
            key: "score",
            kind: "numeric",
            minimum: 0,
            maximum: 1,
        }),
    ]),
    hypothesisPolicy: Object.freeze({
        required: true,
        maxPredictions: 2,
        allowedKinds: Object.freeze(["threshold"]),
        allowRequiredForResult: true,
    }),
});

function frozenThresholdHypotheses(id, value) {
    return {
        predictions: [{
            id,
            kind: "threshold",
            observable: "score",
            operator: ">=",
            value,
            refutation: {
                kind: "threshold",
                operator: "<",
                value,
            },
            requiredForResult: true,
        }],
    };
}

describe("v4 immutable enumerand manifests", () => {
    it("freezes typed per-enumerand hypotheses and requires them under policy", () => {
        const input = finiteManifestInput();
        expect(() => normalizeEnumerandManifest(input, HYPOTHESIS_OPTIONS))
            .toThrow(/hypotheses are required/i);

        input.entries = input.entries.map((entry, index) => ({
            ...entry,
            hypotheses: frozenThresholdHypotheses(
                `prediction-${index}`,
                0.5 + index * 0.1,
            ),
        }));
        const manifest = normalizeEnumerandManifest(input, HYPOTHESIS_OPTIONS);
        expect(manifest.entries.every((entry) =>
            entry.hypotheses.identity.startsWith(
                "sha256:crucible-preregistered-hypotheses-v4:",
            ))).toBe(true);
        const binding = enumerandBinding(manifest, 1, HYPOTHESIS_OPTIONS);
        expect(binding.hypotheses).toEqual(manifest.entries[1].hypotheses);

        const mutated = structuredClone(manifest);
        mutated.entries[1].hypotheses.predictions[0].value = 0.95;
        mutated.entries[1].hypotheses.predictions[0].refutation.value = 0.95;
        expect(() => normalizeEnumerandManifest(mutated, HYPOTHESIS_OPTIONS))
            .toThrow(/mutated|Merkle root/u);
    });

    it("freezes canonical contents and rejects mutation under a stale root", () => {
        const manifest = normalizeEnumerandManifest(finiteManifestInput());
        expect(Object.isFrozen(manifest)).toBe(true);
        expect(Object.isFrozen(manifest.entries)).toBe(true);
        expect(Object.isFrozen(manifest.entries[0])).toBe(true);
        expect(() => {
            manifest.entries[0].id = "mutated";
        }).toThrow(TypeError);

        const mutated = JSON.parse(JSON.stringify(manifest));
        mutated.entries[0].artifactSnapshotHash = snapshot("d");
        delete mutated.entries[0].enumerandHash;
        delete mutated.control.enumerandHash;
        expect(() => normalizeEnumerandManifest(mutated))
            .toThrow(/Merkle root does not match/u);
    });

    it("normalizes reorderings without changing the Merkle root", () => {
        const first = normalizeEnumerandManifest(finiteManifestInput());
        const reordered = normalizeEnumerandManifest({
            ...first,
            entries: [...first.entries].reverse(),
        });
        expect(reordered.entries.map((entry) => entry.ordinal)).toEqual([0, 1, 2]);
        expect(reordered.merkleRoot).toBe(first.merkleRoot);
    });

    it("keeps content identity independent of labels and prevents re-IDs counting twice", () => {
        const manifest = normalizeEnumerandManifest(finiteManifestInput());
        const original = enumerandIdentity(manifest.entries[0], manifest.topology);
        const renamed = enumerandIdentity({
            ...manifest.entries[0],
            id: "renamed-label",
        }, manifest.topology);
        expect(renamed).toEqual(original);

        const attempts = [
            {
                candidateId: "candidate-a",
                enumerandOrdinal: 0,
                enumerandHash: original.enumerandHash,
                outcomeClass: "rejected",
            },
            {
                candidateId: "renamed-label",
                enumerandOrdinal: 0,
                enumerandHash: original.enumerandHash,
                outcomeClass: "rejected",
            },
        ];
        const coverage = enumerandCoverage(manifest, attempts);
        expect(coverage.coveredEnumerands).toBe(1);
        expect(coverage.duplicateAttempts).toEqual([{
            ordinal: 0,
            enumerandHash: original.enumerandHash,
            attemptCount: 2,
        }]);
    });

    it("rejects duplicate finite artifacts and duplicate bounded tuples", () => {
        const finite = finiteManifestInput();
        finite.entries[1].artifactSnapshotHash = finite.entries[0].artifactSnapshotHash;
        expect(() => normalizeEnumerandManifest(finite))
            .toThrow(/artifact snapshots must be unique/u);

        const bounded = boundedManifestInput();
        bounded.entries[1].parameterTuple = bounded.entries[0].parameterTuple;
        expect(() => normalizeEnumerandManifest(bounded))
            .toThrow(/parameter tuples must be unique/u);
    });

    it("binds bounded generation to the frozen tuple and rejects off-manifest content", () => {
        const manifest = normalizeEnumerandManifest(boundedManifestInput());
        const binding = enumerandBinding(manifest, 1);
        expect(assertEnumerandBinding(manifest, binding)).toEqual(binding);

        const changedTuple = JSON.parse(JSON.stringify(binding));
        changedTuple.parameterTuple[1].depth = 999;
        expect(() => assertEnumerandBinding(manifest, changedTuple))
            .toThrow(/parameterTupleHash does not match|outside the frozen manifest/u);

        const changedOrdinal = {
            ...binding,
            ordinal: 0,
        };
        expect(() => assertEnumerandBinding(manifest, changedOrdinal))
            .toThrow(/enumerandHash does not match|outside the frozen manifest/u);
    });

    it("reports coverage gaps and exhausts only complete hash/ordinal coverage", () => {
        const manifest = normalizeEnumerandManifest(finiteManifestInput());
        const attempts = manifest.entries.slice(0, 2).map((entry) => ({
            enumerandOrdinal: entry.ordinal,
            enumerandHash: entry.enumerandHash,
            evidenceId: `label-${entry.ordinal}`,
            outcomeClass: "rejected",
        }));
        const gap = enumerandCoverage(manifest, attempts);
        expect(gap.complete).toBe(false);
        expect(gap.missingOrdinals).toEqual([2]);
        expect(selectUntriedEnumerand(manifest, attempts).ordinal).toBe(2);
        expect(enumerandExhaustion(manifest, attempts)).toMatchObject({
            exhausted: false,
            reason: "coverage_gap",
        });

        const complete = [
            ...attempts,
            {
                enumerandOrdinal: 2,
                enumerandHash: manifest.entries[2].enumerandHash,
                outcomeClass: "rejected",
            },
        ];
        const exhausted = enumerandExhaustion(manifest, complete);
        expect(exhausted.exhausted).toBe(true);
        expect(exhausted.exhaustionHash).toMatch(
            /^sha256:crucible-enumerand-exhaustion-v1:[a-f0-9]{64}$/u,
        );
    });

    it("does not treat off-manifest or invalid-metric evidence as coverage", () => {
        const manifest = normalizeEnumerandManifest(finiteManifestInput());
        const coverage = enumerandCoverage(manifest, [
            {
                enumerandOrdinal: 0,
                enumerandHash: manifest.entries[1].enumerandHash,
                outcomeClass: "rejected",
            },
            {
                enumerandOrdinal: 1,
                enumerandHash: manifest.entries[1].enumerandHash,
                outcomeClass: "invalid_metrics",
            },
        ]);
        expect(coverage.coveredOrdinals).toEqual([]);
        expect(coverage.missingOrdinals).toEqual([0, 1, 2]);
        expect(coverage.offManifestAttempts).toHaveLength(1);
    });

    it("seals and resolves both enumerand and reference controls", () => {
        const finite = normalizeEnumerandManifest(finiteManifestInput());
        const control = resolveControlEnumerand(finite);
        expect(control).toEqual(enumerandBinding(finite, 0));

        const bounded = normalizeEnumerandManifest(boundedManifestInput());
        expect(resolveControlEnumerand(bounded)).toEqual(bounded.control);

        const stale = JSON.parse(JSON.stringify(finite));
        stale.control.ordinal = 1;
        delete stale.control.enumerandHash;
        expect(() => normalizeEnumerandManifest(stale))
            .toThrow(/Merkle root does not match/u);
    });

    it("keeps continuous spaces non-exhaustible until explicitly discretized", () => {
        expect(isEnumerandSpaceExhaustible({
            topology: "bounded_parameterized",
            parameterRanges: [{ name: "x", min: 0, max: 1 }],
        })).toBe(false);
        const manifest = normalizeEnumerandManifest(boundedManifestInput());
        expect(isEnumerandSpaceExhaustible({
            topology: "bounded_parameterized",
            enumerandManifest: manifest,
        })).toBe(true);
        expect(isEnumerandSpaceExhaustible({
            topology: "open_generative",
            enumerandManifest: manifest,
        })).toBe(false);
    });
});

describe("enumerand preflight staging", () => {
    function fakeStore() {
        const snapshots = new Map([
            ["source-a", snapshot("a")],
            ["source-b", snapshot("b")],
            ["control-source", snapshot("c")],
        ]);
        const materializations = [];
        return {
            materializations,
            ingestDirectory({ sourceDir }) {
                return { snapshot: snapshots.get(sourceDir) };
            },
            verifySnapshot(value) {
                return {
                    ok: [...snapshots.values()].includes(value),
                    snapshot: value,
                };
            },
            loadManifest(value) {
                return { version: 1, entries: [], snapshot: value };
            },
            materializeSnapshot(options) {
                materializations.push(options);
                return { fileCount: 1, totalBytes: 10, destDir: options.destDir };
            },
        };
    }

    it("stages finite sources before sealing and materializes the frozen snapshot", () => {
        const artifactStore = fakeStore();
        const staged = stageFiniteEnumerandManifest({
            artifactStore,
            entries: [
                { id: "a", ordinal: 0, sourceDir: "source-a" },
                { id: "b", ordinal: 1, sourceDir: "source-b" },
            ],
            control: { kind: "reference", sourceDir: "control-source" },
        });

        expect(staged.manifest.entries.map((entry) =>
            entry.artifactSnapshotHash)).toEqual([snapshot("a"), snapshot("b")]);
        expect(staged.manifest.control.referenceHash).toBe(snapshot("c"));
        expect(verifyStagedFiniteEnumerands({
            artifactStore,
            manifest: staged.manifest,
        }).snapshots).toHaveLength(2);

        const materialized = materializeFiniteEnumerand({
            artifactStore,
            manifest: staged.manifest,
            ordinal: 1,
            destDir: "dest-b",
        });
        expect(materialized.binding.artifactSnapshotHash).toBe(snapshot("b"));
        expect(artifactStore.materializations).toEqual([{
            snapshot: snapshot("b"),
            destDir: "dest-b",
            readOnly: true,
        }]);
    });

    it("seals bounded parameter tuples without accepting ranges", () => {
        const manifest = stageBoundedParameterizedManifest(
            boundedManifestInput(),
        );
        expect(manifest.topology).toBe("bounded_parameterized");
        expect(() => stageBoundedParameterizedManifest({
            entries: [],
            control: boundedManifestInput().control,
            parameterRanges: [{ min: 0, max: 1 }],
        })).toThrow();
    });
});

describe("enumerand strategy and runner plans", () => {
    function aggregateWithManifest(manifest) {
        return {
            contractHash: hashCanonical({ manifest: manifest.merkleRoot }),
            contract: {
                hypothesisTopology: manifest.topology,
                enumerandManifest: manifest,
                boundedCandidateIds: manifest.entries.map((entry) => entry.id),
                candidatesPerRound: 2,
                maxRounds: 2,
                workerModels: ["worker-a"],
                metrics: [],
                searchPolicy: DEFAULT_SEARCH_POLICY,
                statisticalPolicy: fakeStatisticalPolicy({
                    topology: manifest.topology,
                    searchSlots: manifest.entries.length,
                    manifest,
                }),
            },
            evidenceOrder: [],
            evidence: {},
        };
    }

    it("assigns a frozen enumerand rather than a label-only bounded id", () => {
        const manifest = normalizeEnumerandManifest(finiteManifestInput());
        const aggregate = aggregateWithManifest(manifest);
        const command = buildSearchCandidateCommand(aggregate, {
            nextRound: 1,
            nextSlot: 1,
        });
        expect(command.candidateId).toBe("candidate-b");
        expect(command.enumerand).toEqual(enumerandBinding(manifest, 1));

        const plan = resolveCommandEnumerand(aggregate.contract, command);
        expect(plan.execution).toEqual({
            kind: "staged_snapshot",
            artifactSnapshotHash: snapshot("b"),
            candidateArtifactHash:
                `sha256:crucible-measurement-snapshot-v1:${"b".repeat(64)}`,
        });
        expect(assertFiniteEnumerandSnapshot(
            plan,
            snapshot("b"),
            plan.execution.candidateArtifactHash,
        )).toEqual(command.enumerand);
        expect(() => assertFiniteEnumerandSnapshot(
            plan,
            snapshot("c"),
            plan.execution.candidateArtifactHash,
        )).toThrow(/outside its staged enumerand/u);
    });

    it("requires bounded generation requests to carry the exact tuple binding hash", () => {
        const manifest = normalizeEnumerandManifest(boundedManifestInput());
        const aggregate = aggregateWithManifest(manifest);
        const command = buildSearchCandidateCommand(aggregate, {
            nextRound: 1,
            nextSlot: 0,
        });
        const plan = resolveCommandEnumerand(aggregate.contract, command);
        expect(plan.execution).toMatchObject({
            kind: "bounded_parameter_generation",
            parameterTupleHash: manifest.entries[0].parameterTupleHash,
        });
        expect(assertBoundedEnumerandRequest(plan, {
            candidateId: command.candidateId,
            enumerandBindingHash: plan.bindingHash,
        })).toEqual(command.enumerand);
        expect(() => assertBoundedEnumerandRequest(plan, {
            candidateId: command.candidateId,
            enumerandBindingHash: "sha256:crucible-enumerand-binding-v1:"
                + "0".repeat(64),
        })).toThrow(/not bound to its frozen tuple/u);
    });

    it("derives kernel exhaustion from ordinal/hash coverage rather than evidence labels", () => {
        const manifest = normalizeEnumerandManifest(finiteManifestInput());
        const aggregate = aggregateWithManifest(manifest);
        const evidenceItems = manifest.entries.map((entry, index) => ({
            evidenceId: `evidence-label-${index}`,
            candidateId: index === 2 ? "re-id-does-not-authorize-coverage" : entry.id,
            sourceKind: "harness",
            purpose: "candidate",
            invalidated: false,
            round: Math.floor(index / aggregate.contract.candidatesPerRound) + 1,
            slotIndex: index % aggregate.contract.candidatesPerRound,
            enumerandOrdinal: entry.ordinal,
            enumerandHash: entry.enumerandHash,
            outcomeClass: "rejected",
            acceptanceSatisfied: false,
            commitEventHash: `sha256:crucible-event-v4:${String(index).repeat(64)}`,
            provenanceRoot: `sha256:crucible-evidence-provenance-v1:${String(index + 3).repeat(64)}`,
        }));
        aggregate.evidenceOrder = evidenceItems.map((item) => item.evidenceId);
        aggregate.evidence = Object.fromEntries(
            evidenceItems.map((item) => [item.evidenceId, item]),
        );

        const progress = searchProgress(aggregate);
        expect(progress.boundedComplete).toBe(true);
        expect(progress.enumerandCoverage.coveredOrdinals).toEqual([0, 1, 2]);
        const basis = boundedSearchExhaustion(aggregate);
        expect(basis).toMatchObject({
            searchSpaceExhausted: true,
            enumerandCount: 3,
            enumerandManifestRoot: manifest.merkleRoot,
        });
        expect(basis).not.toHaveProperty("boundedCandidateIdsHash");
    });
});

describe("enumerand worker boundaries", () => {
    const annotations = {
        mechanism: "Generate files from the frozen tuple.",
        hypothesis: null,
        expectedEffects: [],
        citedEvidenceIds: [],
        finding: null,
    };

    it("allows only trusted tuple generation, never worker-authored enumerand content", () => {
        const manifest = normalizeEnumerandManifest(boundedManifestInput());
        const binding = enumerandBinding(manifest, 0);
        const options = {
            challengeNonce: "challenge",
            allowedCandidateIds: [binding.id],
            visibleEvidenceIds: [],
            enumerandBinding: binding,
        };
        expect(() => validateCandidateSubmission({
            challenge: "challenge",
            candidateId: binding.id,
            annotations,
            files: [{ path: "candidate.txt", content: "generated" }],
        }, options)).toThrow(/cannot submit or change their files or parameters/u);
        expect(validateCandidateSubmission({
            challenge: "challenge",
            candidateId: binding.id,
            annotations,
            files: [{ path: "candidate.txt", content: "generated" }],
        }, {
            ...options,
            trustedParameterizedGenerator: true,
        })).toMatchObject({
            candidateId: binding.id,
        });
        expect(() => validateCandidateSubmission({
            challenge: "challenge",
            candidateId: binding.id,
            annotations,
            parameterTuple: binding.parameterTuple,
            files: [{ path: "candidate.txt", content: "generated" }],
        }, {
            ...options,
            trustedParameterizedGenerator: true,
        })).toThrow(/unknown field "parameterTuple"/u);
        expect(() => validateCandidateSubmission({
            challenge: "challenge",
            candidateId: "tuple-b",
            annotations,
            files: [{ path: "candidate.txt", content: "generated" }],
        }, {
            ...options,
            trustedParameterizedGenerator: true,
        })).toThrow(/outside the worker's assigned set|frozen enumerand/u);
    });

    it("forbids workers from submitting finite enumerand files", () => {
        const manifest = normalizeEnumerandManifest(finiteManifestInput());
        const binding = enumerandBinding(manifest, 0);
        expect(() => validateCandidateSubmission({
            challenge: "challenge",
            candidateId: binding.id,
            annotations,
            files: [{ path: "candidate.txt", content: "mutated" }],
        }, {
            challengeNonce: "challenge",
            allowedCandidateIds: [binding.id],
            visibleEvidenceIds: [],
            enumerandBinding: binding,
        })).toThrow(/cannot submit or change their files|staged snapshots/u);
        expect(() => buildProposalPrompt({
            objective: "evaluate fixed artifacts",
            candidateId: binding.id,
            challengeNonce: "challenge",
            enumerandBinding: binding,
        })).toThrow(/bypass content-submission workers/u);
    });

    it("rejects bounded worker prompts and proposal validation for frozen tuples", () => {
        const manifest = normalizeEnumerandManifest(boundedManifestInput());
        const binding = enumerandBinding(manifest, 0);
        expect(() => buildProposalPrompt({
            objective: "generate from tuple",
            candidateId: binding.id,
            challengeNonce: "challenge",
            model: "model-a",
            enumerandBinding: binding,
        })).toThrow(/bypass content-submission workers/u);
        const prompt = buildProposalPrompt({
            objective: "unbound generation",
            candidateId: binding.id,
            challengeNonce: "challenge",
            model: "model-a",
        });
        const request = {
            sessionId: "session-a",
            model: "model-a",
            challengeNonce: "challenge",
            prompt,
            promptContextHash: null,
            allowedCandidateIds: [binding.id],
            visibleEvidenceIds: [],
            enumerandBinding: binding,
        };
        const candidate = validateCandidateSubmission({
            challenge: "challenge",
            candidateId: binding.id,
            annotations,
            files: [{ path: "candidate.txt", content: "generated" }],
        }, {
            challengeNonce: request.challengeNonce,
            allowedCandidateIds: request.allowedCandidateIds,
            visibleEvidenceIds: request.visibleEvidenceIds,
            enumerandBinding: binding,
            trustedParameterizedGenerator: true,
        });
        const proposal = {
            ...candidate,
            identity: {
                invocationSessionId: request.sessionId,
                configuredModel: request.model,
                challengeNonce: request.challengeNonce,
                promptHash: hashCanonical(
                    { prompt },
                    "sha256:crucible-runtime-worker-prompt-v1",
                ),
                contextHash: null,
                annotationsHash: hashCanonical(
                    candidate.annotations,
                    "sha256:crucible-runtime-candidate-annotations-v1",
                ),
                payloadHash: hashCanonical(
                    candidate,
                    "sha256:crucible-runtime-candidate-payload-v1",
                ),
                enumerandBindingHash: hashCanonical(
                    binding,
                    "sha256:crucible-enumerand-binding-v1",
                ),
            },
        };
        expect(() => validateWorkerProposal(proposal, request))
            .toThrow(/cannot submit or change their files or parameters/u);
    });
});
