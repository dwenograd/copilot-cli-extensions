import { describe, expect, it } from "vitest";
import {
    DEFAULT_SEARCH_POLICY,
    ESCAPE_SEARCH_OPERATORS,
    CANDIDATE_NOVELTY_VERSION,
    LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
    SEARCH_STRATEGY_POLICY_VERSION,
    adaptiveOperatorWeights,
    buildCandidateArchive,
    buildSearchCandidateCommand,
    compareCandidateEvidence,
    contractHash,
    createInvestigationContract,
    contentNoveltySignature,
    hashCanonical,
    selectAdaptiveOperator,
    structuralRoleIdentity,
} from "../domain/index.mjs";
import { makeV4ContractInput } from "./v4-contract-fixture.mjs";

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

function structuralHash(label) {
    return hashCanonical(
        { structure: label },
        "sha256:crucible-novelty-structural-v1",
    );
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

function contract(
    searchPolicy = policy(),
    { workerModels = ["model-a"] } = {},
) {
    const input = makeV4ContractInput({
        objective: "exercise deterministic archive selection",
        acceptancePredicate: { kind: "harness_pass" },
        hypothesisTopology: "open_generative",
        criticality: "high",
        policyVersion: "policy-v2",
        workerModels,
        candidatesPerRound: 1,
        maxRounds: 10,
        searchPolicy,
    });
    input.statisticalPolicy.metrics[0].practicalEquivalenceDelta =
        Number.EPSILON;
    return createInvestigationContract(input);
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
    structuralSignature = null,
    behavioralSignature = null,
    round = 1,
    slotIndex = 0,
    invalidated = false,
}) {
    const novelty = {
        version: CANDIDATE_NOVELTY_VERSION,
        content: {
            snapshotHash: artifact,
            signature: contentNoveltySignature(artifact),
        },
        structural: structuralSignature === null
            ? null
            : { structuralFingerprint: structuralSignature },
        behavioral: behavioralSignature === null
            ? null
            : {
                signature: behavioralSignature,
                claims: [],
            },
    };
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
        novelty,
        annotations: {
            mechanism,
            hypothesis: null,
            expectedEffects: [],
            citedEvidenceIds: [],
            finding,
        },
    };
}

function aggregateFor(items, searchPolicy, contractOptions = {}) {
    const frozenContract = contract(searchPolicy, contractOptions);
    const roleFingerprint = structuralRoleIdentity(frozenContract);
    const normalizedItems = items.map((item) => {
        const structuralToken =
            item.novelty.structural?.structuralFingerprint ?? null;
        const structuralFeatures = structuralToken === null
            ? null
            : {
                structureCode: Number(BigInt(
                    `0x${structuralToken.slice(-12)}`,
                )),
            };
        return {
            ...item,
            novelty: {
                ...item.novelty,
                structural: structuralFeatures === null
                    ? null
                    : {
                        version: "crucible-novelty-role-adapter-v1",
                        roleFingerprint,
                        structuralFingerprint: hashCanonical({
                            version: "crucible-novelty-role-adapter-v1",
                            roleFingerprint,
                            observableSchemaHash:
                                frozenContract.harnessSuite.roles.novelty
                                    .observableSchemaHash,
                            features: structuralFeatures,
                        }, "sha256:crucible-novelty-structural-v1"),
                        features: structuralFeatures,
                        receiptHash: hashCanonical(
                            { evidenceId: item.evidenceId, receipt: "novelty" },
                            "sha256:crucible-measurement-receipt-v1",
                        ),
                        measurementRoot: hashCanonical(
                            {
                                evidenceId: item.evidenceId,
                                measurement: "novelty",
                            },
                            "sha256:crucible-evidence-measurement-provenance-v1",
                        ),
                        subjectId: `novelty-${
                            item.receipt.candidateArtifactHash
                                .split(":")
                                .at(-1)
                                .slice(0, 48)
                        }`,
                    },
            },
        };
    });
    return {
        contract: frozenContract,
        contractHash: contractHash(frozenContract),
        evidenceOrder: normalizedItems.map((item) => item.evidenceId),
        evidence: Object.fromEntries(
            normalizedItems.map((item) => [item.evidenceId, item]),
        ),
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

    it("does not treat a lone behavioral profile as a supported difference", () => {
        const searchPolicy = policy();
        const incumbent = evidence({
            evidenceId: "behavior-incumbent",
            committedSeq: 1,
            score: 100,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "behavior-incumbent" }),
        });
        const near = evidence({
            evidenceId: "behavior-near",
            committedSeq: 2,
            score: 99,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "behavior-near" }),
        });
        const archive = {
            accepted: [incumbent],
            nearMisses: [near],
            rejected: [],
            inconclusive: [],
            invalidMetrics: [],
            noveltyNiches: {
                content: [],
                structural: [],
                behavioral: [],
            },
            mechanismGroups: [],
            lessonGroups: [],
            duplicateIndex: {},
            incumbent,
        };
        const oneProfile = {
            ...archive,
            noveltyNiches: {
                ...archive.noveltyNiches,
                behavioral: [{
                    signature: hashCanonical(
                        { behavior: "profile" },
                        "sha256:crucible-behavioral-novelty-v1",
                    ),
                    representativeEvidenceId: incumbent.evidenceId,
                    evidenceIds: [incumbent.evidenceId, near.evidenceId],
                }],
            },
        };
        const selection = {
            searchPolicy,
            contractHash: hashCanonical({ contract: "behavior-profile" }),
            round: 2,
            slotIndex: 0,
        };
        expect(adaptiveOperatorWeights(searchPolicy, oneProfile))
            .toEqual(adaptiveOperatorWeights(searchPolicy, archive));
        expect(selectAdaptiveOperator({ ...selection, archive: oneProfile }))
            .toBe(selectAdaptiveOperator({ ...selection, archive }));
    });

    it("uses versioned history-weight adaptation without overriding frozen weights", () => {
        const searchPolicy = policy();
        const incumbent = evidence({
            evidenceId: "history-incumbent",
            committedSeq: 1,
            score: 100,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "history-incumbent" }),
        });
        const archive = buildCandidateArchive(
            aggregateFor([incumbent], searchPolicy),
        );
        const input = {
            searchPolicy,
            archive,
            contractHash: hashCanonical({ contract: "operator-history" }),
            round: 2,
            slotIndex: 0,
        };
        const baseWeights = adaptiveOperatorWeights(searchPolicy, archive);
        const counterfactualWeights = adaptiveOperatorWeights(
            searchPolicy,
            archive,
            "normal",
            ["fresh"],
        );
        const refinementWeights = adaptiveOperatorWeights(
            searchPolicy,
            archive,
            "normal",
            ["fresh", "adversarial"],
        );
        expect(counterfactualWeights.adversarial)
            .toBeGreaterThan(baseWeights.adversarial);
        expect(counterfactualWeights.fresh).toBe(baseWeights.fresh);
        expect(refinementWeights.refinement)
            .toBeGreaterThan(baseWeights.refinement);

        const {
            version: _version,
            ...legacySearchPolicy
        } = searchPolicy;
        expect(adaptiveOperatorWeights(
            legacySearchPolicy,
            archive,
            "normal",
            ["fresh"],
        )).toEqual(adaptiveOperatorWeights(
            legacySearchPolicy,
            archive,
            "normal",
        ));

        const extremePolicy = policy({
            operatorWeights: {
                fresh: 1_000_000,
                refinement: 0,
                crossover: 0,
                diversification: 1,
                adversarial: 1,
                restart: 1,
            },
        });
        const extremeWeights = adaptiveOperatorWeights(
            extremePolicy,
            archive,
            "normal",
            ["fresh"],
        );
        expect(extremeWeights.refinement).toBe(0);
        expect(extremeWeights.fresh).toBe(1_000_000);
        expect(extremeWeights.adversarial).toBeGreaterThan(1);
        expect(extremeWeights.adversarial).toBeLessThan(
            extremeWeights.fresh,
        );
        expect(extremePolicy.operatorWeights[
            selectAdaptiveOperator({
                ...input,
                searchPolicy: extremePolicy,
                operatorHistory: ["fresh"],
            })
        ]).toBeGreaterThan(0);
        expect(() => selectAdaptiveOperator({
            ...input,
            operatorHistory: ["unsupported"],
        })).toThrow(/operator history/u);
    });

    it("replays golden unversioned v1 commands and separates v2 authority", () => {
        function goldenContract(searchPolicy) {
            return createInvestigationContract(makeV4ContractInput({
                objective: "golden legacy operator replay",
                candidatesPerRound: 1,
                maxRounds: 64,
                searchPolicy,
            }));
        }
        function goldenAggregate(frozenContract) {
            const parent = {
                evidenceId: "legacy-parent",
                observationId: "legacy-observation",
                committedSeq: 1,
                sourceKind: "harness",
                purpose: "candidate",
                candidateId: "candidate-r000001-s000",
                round: 1,
                slotIndex: 0,
                invalidated: false,
                rankable: true,
                outcomeClass: "accepted",
                acceptanceSatisfied: true,
                metrics: { score: 75 },
                receipt: { candidateArtifactHash: null },
                duplicateOf: null,
                novelty: null,
                annotations: {
                    mechanism: null,
                    hypothesis: null,
                    expectedEffects: [],
                    citedEvidenceIds: [],
                    finding: null,
                },
            };
            return {
                contract: frozenContract,
                contractHash: contractHash(frozenContract),
                evidenceOrder: [parent.evidenceId],
                evidence: { [parent.evidenceId]: parent },
                observations: {
                    "legacy-observation": {
                        commandId: "legacy-command",
                    },
                },
                commands: {
                    "legacy-command": {
                        command: {
                            kind: "search_candidate",
                            operator: "fresh",
                        },
                    },
                },
            };
        }

        const {
            version: _version,
            ...legacySearchPolicy
        } = policy();
        const legacyContract = goldenContract(legacySearchPolicy);
        const legacy = buildSearchCandidateCommand(
            goldenAggregate(legacyContract),
            { nextRound: 2, nextSlot: 0 },
        );
        expect(legacyContract.searchPolicy).not.toHaveProperty("version");
        expect({
            strategyPolicyVersion:
                legacyContract.searchPolicy.version
                ?? LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
            operator: legacy.operator,
            seed: legacy.seed,
            subjectIndex: legacy.replicationSchedule.subject.index,
            scheduleHash: legacy.replicationSchedule.scheduleHash,
        }).toEqual({
            strategyPolicyVersion: LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
            operator: "fresh",
            seed: 522677298,
            subjectIndex: 3,
            scheduleHash:
                "sha256:crucible-replication-schedule-v1:48108a0c568034a54839dfe073918a601da79d7c5a21c8727de8f16f89a43fa4",
        });

        const currentContract = goldenContract(policy());
        const current = buildSearchCandidateCommand(
            goldenAggregate(currentContract),
            { nextRound: 2, nextSlot: 0 },
        );
        expect(currentContract.searchPolicy.version)
            .toBe(SEARCH_STRATEGY_POLICY_VERSION);
        expect({
            operator: current.operator,
            seed: current.seed,
            subjectIndex: current.replicationSchedule.subject.index,
            scheduleHash: current.replicationSchedule.scheduleHash,
        }).toEqual({
            operator: "adversarial",
            seed: 1122524115,
            subjectIndex: 3,
            scheduleHash:
                "sha256:crucible-replication-schedule-v1:f668285179a85cea5065571b1441da7b3f089510b57624a494ad7d1aef315cf1",
        });
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

    it("assigns crossover two distinct parents and prefers different structural signatures", () => {
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
            structuralSignature: structuralHash("a"),
        });
        const near = evidence({
            evidenceId: "near",
            committedSeq: 2,
            score: 99,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "near" }),
            mechanism: "mechanism-b",
            structuralSignature: structuralHash("b"),
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

    it("prefers two represented structural niches even when the incumbent has none", () => {
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
            structuralSignature: structuralHash("a"),
        });
        const nearB = evidence({
            evidenceId: "near-b",
            committedSeq: 3,
            score: 98,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "near-b" }),
            mechanism: "mechanism-b",
            structuralSignature: structuralHash("b"),
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

    it("keeps parent and operator policy neutral to labels, prose, output hashes, and arrival", () => {
        const searchPolicy = policy({
            operatorWeights: {
                fresh: 1,
                refinement: 1,
                crossover: 1_000,
                diversification: 1,
                adversarial: 1,
                restart: 1,
            },
        });
        const firstParent = evidence({
            evidenceId: "parent-a",
            committedSeq: 1,
            score: 100,
            outcomeClass: "accepted",
            artifact: hashCanonical({ artifact: "parent-a" }),
            mechanism: "first model label",
            finding: "first explanation",
            structuralSignature: structuralHash("a"),
        });
        const secondParent = evidence({
            evidenceId: "parent-b",
            committedSeq: 2,
            score: 99,
            outcomeClass: "near_miss",
            artifact: hashCanonical({ artifact: "parent-b" }),
            mechanism: "second model label",
            finding: "second explanation",
            structuralSignature: structuralHash("b"),
        });
        const baseline = aggregateFor(
            [firstParent, secondParent],
            searchPolicy,
        );
        const relabeledItems = [
            {
                ...secondParent,
                committedSeq: 20,
                model: "model-z",
                contentHash: hashCanonical({ outputText: "rewritten-b" }),
                annotations: {
                    ...secondParent.annotations,
                    mechanism: "paraphrased second label",
                    finding: "paraphrased second explanation",
                },
            },
            {
                ...firstParent,
                committedSeq: 10,
                model: "model-y",
                contentHash: hashCanonical({ outputText: "rewritten-a" }),
                annotations: {
                    ...firstParent.annotations,
                    mechanism: "paraphrased first label",
                    finding: "paraphrased first explanation",
                },
            },
        ];
        const relabeled = aggregateFor(relabeledItems, searchPolicy);
        const progress = { nextRound: 2, nextSlot: 0 };
        const first = buildSearchCandidateCommand(baseline, progress);
        const second = buildSearchCandidateCommand(relabeled, progress);

        expect({
            operator: second.operator,
            parentEvidenceIds: second.parentEvidenceIds,
            promptContextRefs: second.promptContextRefs,
            seed: second.seed,
        }).toEqual({
            operator: first.operator,
            parentEvidenceIds: first.parentEvidenceIds,
            promptContextRefs: first.promptContextRefs,
            seed: first.seed,
        });
    });

    it("keeps operator policy neutral to worker-model ordering", () => {
        const searchPolicy = policy({
            operatorWeights: {
                fresh: 1,
                refinement: 1,
                crossover: 10,
                diversification: 1,
                adversarial: 1,
                restart: 1,
            },
        });
        const items = [
            evidence({
                evidenceId: "parent-a",
                committedSeq: 1,
                score: 100,
                outcomeClass: "accepted",
                artifact: hashCanonical({ artifact: "model-order-a" }),
                structuralSignature: structuralHash("model-order-a"),
            }),
            evidence({
                evidenceId: "parent-b",
                committedSeq: 2,
                score: 99,
                outcomeClass: "near_miss",
                artifact: hashCanonical({ artifact: "model-order-b" }),
                structuralSignature: structuralHash("model-order-b"),
            }),
        ];
        const firstAggregate = aggregateFor(
            items,
            searchPolicy,
            { workerModels: ["model-a", "model-b"] },
        );
        const reorderedAggregate = aggregateFor(
            items,
            searchPolicy,
            { workerModels: ["model-b", "model-a"] },
        );
        expect(reorderedAggregate.contractHash)
            .not.toBe(firstAggregate.contractHash);

        const progress = { nextRound: 2, nextSlot: 0 };
        const first = buildSearchCandidateCommand(firstAggregate, progress);
        const reordered = buildSearchCandidateCommand(
            reorderedAggregate,
            progress,
        );
        expect({
            operator: reordered.operator,
            parentEvidenceIds: reordered.parentEvidenceIds,
            promptContextRefs: reordered.promptContextRefs,
        }).toEqual({
            operator: first.operator,
            parentEvidenceIds: first.parentEvidenceIds,
            promptContextRefs: first.promptContextRefs,
        });
        expect(reordered.model).not.toBe(first.model);
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
        expect(first.promptContextRefs).toEqual(["incumbent", "accepted-second"]);
        expect(first.operator).toBe("crossover");
        expect(fallbackPolicy.operatorWeights[first.operator]).toBeGreaterThan(0);
        expect(new Set(first.parentEvidenceIds))
            .toEqual(new Set(["incumbent", "accepted-second"]));
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
