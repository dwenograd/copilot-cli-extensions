import { describe, expect, it } from "vitest";
import {
    DEFAULT_SEARCH_POLICY,
    ESCAPE_SEARCH_OPERATORS,
    adaptiveOperatorWeights,
    buildCandidateArchive,
    buildSearchCandidateCommand,
    contractHash,
    createInvestigationContract,
    hashCanonical,
    selectAdaptiveOperator,
} from "../domain/index.mjs";

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

function policy(overrides = {}) {
    return {
        ...DEFAULT_SEARCH_POLICY,
        ...overrides,
        operatorWeights: {
            ...DEFAULT_SEARCH_POLICY.operatorWeights,
            ...overrides.operatorWeights,
        },
        archiveCaps: {
            ...DEFAULT_SEARCH_POLICY.archiveCaps,
            ...overrides.archiveCaps,
        },
        promptCaps: {
            ...DEFAULT_SEARCH_POLICY.promptCaps,
            ...overrides.promptCaps,
        },
    };
}

function contract(searchPolicy = policy()) {
    return createInvestigationContract({
        objective: "exercise deterministic archive selection",
        acceptancePredicate: { kind: "harness_pass" },
        validationCases: [
            { id: "good", expectation: "accept", artifactHash: artifactHash("a") },
            { id: "bad", expectation: "reject", artifactHash: artifactHash("b") },
        ],
        harnessId: "harness",
        hypothesisTopology: "open_generative",
        criticality: "high",
        policyVersion: "policy-v2",
        parserVersion: "parser-v2",
        workerModels: ["model-a"],
        candidatesPerRound: 1,
        maxRounds: 10,
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        searchPolicy,
        declaredLimits: {},
    });
}

function evidence({
    evidenceId,
    committedSeq,
    score,
    outcomeClass,
    artifact,
    duplicateOf = null,
    mechanism = null,
    finding = null,
    round = 1,
    slotIndex = 0,
}) {
    return {
        evidenceId,
        committedSeq,
        sourceKind: "harness",
        purpose: "candidate",
        round,
        slotIndex,
        invalidated: false,
        rankable: outcomeClass !== "invalid_metrics",
        outcomeClass,
        metrics: outcomeClass === "invalid_metrics" ? {} : { score },
        receipt: { candidateArtifactHash: artifact },
        duplicateOf,
        annotations: {
            mechanism,
            hypothesis: null,
            expectedEffects: [],
            citedEvidenceIds: [],
            finding,
        },
    };
}

function aggregateFor(items, searchPolicy) {
    const frozenContract = contract(searchPolicy);
    return {
        contract: frozenContract,
        contractHash: contractHash(frozenContract),
        evidenceOrder: items.map((item) => item.evidenceId),
        evidence: Object.fromEntries(items.map((item) => [item.evidenceId, item])),
    };
}

describe("Crucible deterministic archive and strategy", () => {
    it("bounds archive classes deterministically and retains the best incumbent", () => {
        const searchPolicy = policy({
            archiveCaps: {
                accepted: 1,
                nearMisses: 1,
                rejected: 1,
                invalidMetrics: 1,
                mechanismGroups: 1,
                lessonGroups: 1,
            },
        });
        const sharedArtifact = hashCanonical({ shared: true });
        const items = [
            evidence({
                evidenceId: "accepted-low",
                committedSeq: 10,
                score: 10,
                outcomeClass: "accepted",
                artifact: hashCanonical({ artifact: "low" }),
                mechanism: "mechanism-b",
                finding: "lesson-b",
            }),
            evidence({
                evidenceId: "accepted-high",
                committedSeq: 20,
                score: 20,
                outcomeClass: "accepted",
                artifact: sharedArtifact,
                mechanism: "mechanism-a",
                finding: "lesson-a",
            }),
            evidence({
                evidenceId: "accepted-duplicate",
                committedSeq: 30,
                score: 100,
                outcomeClass: "accepted",
                artifact: sharedArtifact,
                duplicateOf: "accepted-high",
            }),
            evidence({
                evidenceId: "near",
                committedSeq: 40,
                score: 19,
                outcomeClass: "near_miss",
                artifact: hashCanonical({ artifact: "near" }),
            }),
            evidence({
                evidenceId: "rejected",
                committedSeq: 50,
                score: 1,
                outcomeClass: "rejected",
                artifact: hashCanonical({ artifact: "rejected" }),
            }),
            evidence({
                evidenceId: "invalid",
                committedSeq: 60,
                score: null,
                outcomeClass: "invalid_metrics",
                artifact: hashCanonical({ artifact: "invalid" }),
            }),
        ];

        const first = buildCandidateArchive(aggregateFor(items, searchPolicy));
        const second = buildCandidateArchive(aggregateFor([...items].reverse(), searchPolicy));
        expect(first).toEqual(second);
        expect(first.accepted.map((item) => item.evidenceId)).toEqual(["accepted-high"]);
        expect(first.nearMisses.map((item) => item.evidenceId)).toEqual(["near"]);
        expect(first.rejected.map((item) => item.evidenceId)).toEqual(["rejected"]);
        expect(first.invalidMetrics.map((item) => item.evidenceId)).toEqual(["invalid"]);
        expect(first.incumbent.evidenceId).toBe("accepted-high");
        expect(first.duplicateIndex[sharedArtifact]).toBe("accepted-high");
        expect(first.mechanismGroups).toHaveLength(1);
        expect(first.lessonGroups).toHaveLength(1);
    });

    it("uses deterministic integer/hash operator assignment and forces escape operators", () => {
        const searchPolicy = policy();
        const archive = {
            accepted: [],
            nearMisses: [{ evidenceId: "near-1" }, { evidenceId: "near-2" }],
            rejected: [],
            invalidMetrics: [],
            mechanismGroups: [{ mechanism: "m", representativeEvidenceId: "near-1" }],
            lessonGroups: [],
            duplicateIndex: {},
            incumbent: null,
        };
        const input = {
            searchPolicy,
            archive,
            contractHash: hashCanonical({ contract: true }),
            round: 4,
            slotIndex: 2,
        };
        const first = selectAdaptiveOperator(input);
        const second = selectAdaptiveOperator(input);
        expect(first).toBe(second);
        expect(Number.isSafeInteger(
            Object.values(adaptiveOperatorWeights(searchPolicy, archive))
                .reduce((sum, weight) => sum + weight, 0),
        )).toBe(true);

        const escape = selectAdaptiveOperator({ ...input, phase: "mandatory_escape" });
        expect(ESCAPE_SEARCH_OPERATORS).toContain(escape);
    });

    it("disables parent-dependent operators unless their distinct parents are eligible", () => {
        const searchPolicy = policy();
        const emptyArchive = {
            accepted: [],
            nearMisses: [],
            rejected: [],
            invalidMetrics: [],
            mechanismGroups: [],
            lessonGroups: [],
            duplicateIndex: {},
            incumbent: null,
        };
        const emptyWeights = adaptiveOperatorWeights(searchPolicy, emptyArchive);
        expect(emptyWeights.refinement).toBe(0);
        expect(emptyWeights.crossover).toBe(0);
        expect(emptyWeights.adversarial).toBe(0);

        const incumbent = evidence({
            evidenceId: "incumbent",
            committedSeq: 1,
            score: 100,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "incumbent" }),
            mechanism: "mechanism-a",
        });
        const oneParentArchive = buildCandidateArchive(aggregateFor([incumbent], searchPolicy));
        const oneParentWeights = adaptiveOperatorWeights(searchPolicy, oneParentArchive);
        expect(oneParentWeights.refinement).toBeGreaterThan(0);
        expect(oneParentWeights.adversarial).toBeGreaterThan(0);
        expect(oneParentWeights.crossover).toBe(0);
    });

    it("assigns crossover two distinct parents and prefers different mechanisms", () => {
        const crossoverPolicy = policy({
            operatorWeights: {
                fresh: 1,
                refinement: 0,
                crossover: 1_000_000,
                diversification: 1,
                adversarial: 0,
                restart: 1,
            },
        });
        const incumbent = evidence({
            evidenceId: "incumbent",
            committedSeq: 1,
            score: 100,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "incumbent" }),
            mechanism: "mechanism-a",
        });
        const near = evidence({
            evidenceId: "near",
            committedSeq: 2,
            score: 99,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "near" }),
            mechanism: "mechanism-b",
        });
        const aggregate = aggregateFor([incumbent, near], crossoverPolicy);
        let command = null;
        for (let round = 2; round < 100 && command?.operator !== "crossover"; round += 1) {
            command = buildSearchCandidateCommand(aggregate, {
                nextRound: round,
                nextSlot: 0,
            });
        }
        expect(command).not.toBeNull();
        expect(command.operator).toBe("crossover");
        expect(command.parentEvidenceIds).toEqual(["incumbent", "near"]);
        expect(new Set(command.parentEvidenceIds).size).toBe(2);
    });

    it("falls back deterministically when crossover cannot receive two parents", () => {
        const cappedPolicy = policy({
            promptCaps: { parentEvidenceIds: 1, promptContextRefs: 2 },
            operatorWeights: {
                fresh: 1,
                refinement: 0,
                crossover: 1_000_000,
                diversification: 0,
                adversarial: 0,
                restart: 1,
            },
        });
        const incumbent = evidence({
            evidenceId: "incumbent",
            committedSeq: 1,
            score: 100,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "incumbent" }),
            mechanism: "mechanism-a",
        });
        const near = evidence({
            evidenceId: "near",
            committedSeq: 2,
            score: 99,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "near" }),
            mechanism: "mechanism-b",
        });
        const aggregate = aggregateFor([incumbent, near], cappedPolicy);
        const command = buildSearchCandidateCommand(aggregate, {
            nextRound: 2,
            nextSlot: 0,
        });
        expect(["fresh", "diversification", "restart"]).toContain(command.operator);
        expect(command.operator).not.toBe("crossover");
        expect(command.parentEvidenceIds.length).toBeLessThanOrEqual(1);
    });
});
