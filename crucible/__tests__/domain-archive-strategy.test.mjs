import { describe, expect, it } from "vitest";
import {
    DEFAULT_SEARCH_POLICY,
    ESCAPE_SEARCH_OPERATORS,
    adaptiveOperatorWeights,
    buildCandidateArchive,
    buildSearchCandidateCommand,
    compareCandidateEvidence,
    contractHash,
    createInvestigationContract,
    hashCanonical,
    selectAdaptiveOperator,
} from "../domain/index.mjs";
import { fakeHarnessIdentity } from "./harness-identity-fixture.mjs";

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
        harnessIdentity: fakeHarnessIdentity({
            harnessId: "harness",
            parserVersion: "parser-v2",
        }),
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
    invalidated = false,
}) {
    return {
        evidenceId,
        committedSeq,
        sourceKind: "harness",
        purpose: "candidate",
        round,
        slotIndex,
        invalidated,
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

    it("ranks tiny-epsilon metrics without overflow and preserves lexicographic ties", () => {
        const searchPolicy = policy();
        const worse = evidence({
            evidenceId: "earlier-worse",
            committedSeq: 1,
            score: 1,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "earlier-worse" }),
        });
        const better = evidence({
            evidenceId: "later-better",
            committedSeq: 2,
            score: 2,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "later-better" }),
        });
        const tinyEpsilonContract = {
            ...contract(searchPolicy),
            metrics: [{ key: "score", direction: "max", epsilon: Number.MIN_VALUE }],
        };
        const aggregate = {
            contract: tinyEpsilonContract,
            contractHash: contractHash(tinyEpsilonContract),
            evidenceOrder: [worse.evidenceId, better.evidenceId],
            evidence: {
                [worse.evidenceId]: worse,
                [better.evidenceId]: better,
            },
        };

        expect(buildCandidateArchive(aggregate).incumbent.evidenceId).toBe("later-better");
        expect(compareCandidateEvidence(
            [{ key: "score", direction: "min", epsilon: Number.MIN_VALUE }],
            better,
            worse,
        )).toBeGreaterThan(0);

        const lexicographicMetrics = [
            { key: "primary", direction: "max", epsilon: 0.25 },
            { key: "secondary", direction: "min", epsilon: 0 },
        ];
        const lexicographicWinner = {
            evidenceId: "later-lexicographic-winner",
            committedSeq: 2,
            metrics: { primary: 1, secondary: 1 },
        };
        const earlierLoser = {
            evidenceId: "earlier-lexicographic-loser",
            committedSeq: 1,
            metrics: { primary: 1.0625, secondary: 2 },
        };
        expect(compareCandidateEvidence(
            lexicographicMetrics,
            lexicographicWinner,
            earlierLoser,
        )).toBeLessThan(0);
        expect(compareCandidateEvidence(
            lexicographicMetrics,
            earlierLoser,
            lexicographicWinner,
        )).toBeGreaterThan(0);
    });

    it("keeps one active artifact primary after the historical duplicate root is invalidated", () => {
        const searchPolicy = policy({
            archiveCaps: {
                accepted: 2,
                mechanismGroups: 8,
            },
        });
        const sharedArtifact = hashCanonical({ artifact: "shared-lineage" });
        const historicalRoot = evidence({
            evidenceId: "historical-root",
            committedSeq: 1,
            score: 5,
            outcomeClass: "accepted",
            artifact: sharedArtifact,
            mechanism: "mechanism-root",
            invalidated: true,
        });
        const activePrimary = evidence({
            evidenceId: "active-primary",
            committedSeq: 2,
            score: 20,
            outcomeClass: "accepted",
            artifact: sharedArtifact,
            duplicateOf: "historical-root",
            mechanism: "mechanism-a",
        });
        const activeClone = evidence({
            evidenceId: "active-clone",
            committedSeq: 3,
            score: 100,
            outcomeClass: "accepted",
            artifact: sharedArtifact,
            duplicateOf: "historical-root",
            mechanism: "mechanism-b",
        });
        const unique = evidence({
            evidenceId: "unique",
            committedSeq: 4,
            score: 10,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "unique" }),
            mechanism: "mechanism-c",
        });
        const items = [historicalRoot, activePrimary, activeClone, unique];

        const first = buildCandidateArchive(aggregateFor(items, searchPolicy));
        const replay = buildCandidateArchive(aggregateFor([...items].reverse(), searchPolicy));
        expect(first).toEqual(replay);
        expect(first.accepted.map((item) => item.evidenceId))
            .toEqual(["active-primary", "unique"]);
        expect(first.incumbent.evidenceId).toBe("active-primary");
        expect(first.duplicateIndex[sharedArtifact]).toBe("active-primary");
        const groupedIds = first.mechanismGroups.flatMap((group) => group.evidenceIds);
        expect(groupedIds).toContain("active-primary");
        expect(groupedIds).toContain("unique");
        expect(groupedIds).not.toContain("historical-root");
        expect(groupedIds).not.toContain("active-clone");
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

    it("uses an enabled parent-free escape operator when no incumbent exists", () => {
        const searchPolicy = contract(policy({
            operatorWeights: {
                fresh: 1,
                refinement: 0,
                crossover: 0,
                diversification: 1,
                adversarial: 1_000_000,
                restart: 0,
            },
        })).searchPolicy;
        const archive = {
            accepted: [],
            nearMisses: [],
            rejected: [],
            invalidMetrics: [],
            mechanismGroups: [],
            lessonGroups: [],
            duplicateIndex: {},
            incumbent: null,
        };
        const input = {
            searchPolicy,
            archive,
            contractHash: hashCanonical({ contract: "parent-free-escape" }),
            round: 4,
            slotIndex: 0,
            phase: "mandatory_escape",
        };

        expect(selectAdaptiveOperator(input)).toBe("diversification");
        expect(selectAdaptiveOperator(input)).toBe(selectAdaptiveOperator(input));
        expect(searchPolicy.operatorWeights[selectAdaptiveOperator(input)]).toBeGreaterThan(0);
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

    it("deduplicates archive parents and excludes invalidated parents from eligibility", () => {
        const searchPolicy = policy();
        const sharedArtifact = hashCanonical({ artifact: "parent-lineage" });
        const incumbent = evidence({
            evidenceId: "active-parent",
            committedSeq: 1,
            score: 100,
            outcomeClass: "accepted",
            artifact: sharedArtifact,
            duplicateOf: "historical-parent",
        });
        const clone = evidence({
            evidenceId: "active-parent-clone",
            committedSeq: 2,
            score: 99,
            outcomeClass: "accepted",
            artifact: sharedArtifact,
            duplicateOf: "historical-parent",
        });
        const invalidParent = evidence({
            evidenceId: "invalid-parent",
            committedSeq: 3,
            score: 98,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "invalid-parent" }),
            invalidated: true,
        });
        const archive = {
            accepted: [incumbent, clone, incumbent],
            nearMisses: [invalidParent],
            rejected: [],
            invalidMetrics: [],
            mechanismGroups: [],
            lessonGroups: [],
            duplicateIndex: {},
            incumbent,
        };

        const weights = adaptiveOperatorWeights(searchPolicy, archive);
        expect(weights.refinement).toBeGreaterThan(0);
        expect(weights.adversarial).toBeGreaterThan(0);
        expect(weights.crossover).toBe(0);

        const invalidOnlyArchive = {
            ...archive,
            accepted: [],
            nearMisses: [invalidParent],
            incumbent: invalidParent,
        };
        const invalidOnlyWeights = adaptiveOperatorWeights(searchPolicy, invalidOnlyArchive);
        expect(invalidOnlyWeights.refinement).toBe(0);
        expect(invalidOnlyWeights.crossover).toBe(0);
        expect(invalidOnlyWeights.adversarial).toBe(0);
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

    it("prefers two represented mechanism groups even when the incumbent has none", () => {
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
            evidenceId: "incumbent-without-mechanism",
            committedSeq: 1,
            score: 100,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "incumbent-without-mechanism" }),
        });
        const nearA = evidence({
            evidenceId: "near-a",
            committedSeq: 2,
            score: 99,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "near-a" }),
            mechanism: "mechanism-a",
        });
        const nearB = evidence({
            evidenceId: "near-b",
            committedSeq: 3,
            score: 98,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "near-b" }),
            mechanism: "mechanism-b",
        });
        const aggregate = aggregateFor([incumbent, nearA, nearB], crossoverPolicy);
        let command = null;
        for (let round = 2; round < 100 && command?.operator !== "crossover"; round += 1) {
            command = buildSearchCandidateCommand(aggregate, {
                nextRound: round,
                nextSlot: 0,
            });
        }
        expect(command.operator).toBe("crossover");
        expect(command.parentEvidenceIds).toEqual(["near-a", "near-b"]);
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

    it("replays the zero-weight fallback audit case without selecting disabled diversification", () => {
        const fallbackPolicy = policy({
            promptCaps: { parentEvidenceIds: 2, promptContextRefs: 2 },
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
            mechanism: "z-incumbent",
        });
        const acceptedSecond = evidence({
            evidenceId: "accepted-second",
            committedSeq: 2,
            score: 90,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "accepted-second" }),
            mechanism: "z-second",
        });
        const rejectedContext = evidence({
            evidenceId: "rejected-context",
            committedSeq: 3,
            score: 1,
            outcomeClass: "rejected",
            artifact: hashCanonical({ artifact: "rejected-context" }),
            mechanism: "a-rejected",
        });
        const aggregate = aggregateFor(
            [incumbent, acceptedSecond, rejectedContext],
            fallbackPolicy,
        );

        const first = buildSearchCandidateCommand(aggregate, {
            nextRound: 2,
            nextSlot: 0,
        });
        const replay = buildSearchCandidateCommand(aggregate, {
            nextRound: 2,
            nextSlot: 0,
        });
        expect(first).toEqual(replay);
        expect(first.promptContextRefs).toEqual(["incumbent", "rejected-context"]);
        expect(["fresh", "restart"]).toContain(first.operator);
        expect(fallbackPolicy.operatorWeights[first.operator]).toBeGreaterThan(0);
        expect(first.parentEvidenceIds).toEqual([]);
    });

    it.each([
        [
            "normal",
            {
                fresh: 0,
                refinement: 0,
                crossover: 0,
                diversification: 0,
                adversarial: 0,
                restart: 0,
            },
        ],
        [
            "mandatory_escape",
            {
                fresh: 1,
                refinement: 0,
                crossover: 0,
                diversification: 0,
                adversarial: 1,
                restart: 0,
            },
        ],
    ])("fails closed deterministically with no positive eligible operator in %s", (
        phase,
        operatorWeights,
    ) => {
        const input = {
            searchPolicy: policy({ operatorWeights }),
            archive: {
                accepted: [],
                nearMisses: [],
                rejected: [],
                invalidMetrics: [],
                mechanismGroups: [],
                lessonGroups: [],
                duplicateIndex: {},
                incumbent: null,
            },
            contractHash: hashCanonical({ contract: `no-eligible-${phase}` }),
            round: 1,
            slotIndex: 0,
            phase,
        };
        const capture = () => {
            try {
                selectAdaptiveOperator(input);
                return null;
            } catch (error) {
                return { name: error.name, message: error.message };
            }
        };

        const first = capture();
        expect(first).toEqual(capture());
        expect(first).toMatchObject({
            name: "DeterministicStrategyError",
            message: expect.stringContaining("no positive-weight eligible operators"),
        });
    });

});
