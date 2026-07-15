import { describe, expect, it } from "vitest";

import {
    LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
    SEARCH_STRATEGY_POLICY_VERSION,
    contractHash,
    createInvestigationContract,
} from "../domain/index.mjs";
import {
    assertScientificSearchAlphaLanes,
} from "../domain/scientific-replay.mjs";
import { buildSearchCandidateCommand } from "../domain/strategy.mjs";
import { claimSetAlphaAllocation } from "../domain/statistics.mjs";
import { makeV4ContractInput } from "./v4-contract-fixture.mjs";

function contract({ legacy = false } = {}) {
    const input = makeV4ContractInput({
        candidatesPerRound: 1,
        maxRounds: 1,
    });
    if (legacy) {
        const {
            version: _version,
            ...legacySearchPolicy
        } = input.searchPolicy;
        input.searchPolicy = legacySearchPolicy;
    }
    return createInvestigationContract(input);
}

function invalidatedCandidate(index) {
    return {
        evidenceId: `invalidated-${index}`,
        observationId: `invalidated-observation-${index}`,
        sourceKind: "harness",
        purpose: "candidate",
        candidateId: index === 0
            ? "candidate-r000001-s000"
            : `candidate-r000001-s000-retry-${String(index).padStart(3, "0")}`,
        round: 1,
        slotIndex: 0,
        invalidated: true,
        rankable: false,
        outcomeClass: "inconclusive",
        metrics: {},
        receipt: { candidateArtifactHash: null },
        novelty: null,
    };
}

function strategyAggregate(frozenContract, invalidationCount) {
    const evidence = Array.from(
        { length: invalidationCount },
        (_unused, index) => invalidatedCandidate(index),
    );
    return {
        contract: frozenContract,
        contractHash: contractHash(frozenContract),
        evidenceOrder: evidence.map((item) => item.evidenceId),
        evidence: Object.fromEntries(
            evidence.map((item) => [item.evidenceId, item]),
        ),
        observations: {},
        commands: {},
    };
}

function alphaFor(frozenContract, command) {
    const claim = frozenContract.acceptanceClaimSet.claims[0];
    return claimSetAlphaAllocation({
        statisticalPolicy: frozenContract.statisticalPolicy,
        allocationClaims: frozenContract.acceptanceClaimSet.claims,
        claimId: claim.id,
        subject: command.replicationSchedule.subject,
        observableRegistry: frozenContract.observableRegistry,
    }).claim.alpha;
}

function replayAggregate(frozenContract, first, replacement) {
    return {
        contract: frozenContract,
        evidenceOrder: ["evidence-0", "evidence-1"],
        evidence: {
            "evidence-0": {
                evidenceId: "evidence-0",
                observationId: "observation-0",
                sourceKind: "harness",
                purpose: "candidate",
                candidateId: first.candidateId,
                round: first.round,
                slotIndex: first.slotIndex,
                invalidated: true,
            },
            "evidence-1": {
                evidenceId: "evidence-1",
                observationId: "observation-1",
                sourceKind: "harness",
                purpose: "candidate",
                candidateId: replacement.candidateId,
                round: replacement.round,
                slotIndex: replacement.slotIndex,
                invalidated: false,
            },
        },
        observations: {
            "observation-0": {
                observationId: "observation-0",
                commandId: "command-0",
            },
            "observation-1": {
                observationId: "observation-1",
                commandId: "command-1",
            },
        },
        commands: {
            "command-0": { command: first },
            "command-1": { command: replacement },
        },
    };
}

describe("Crucible preregistered search alpha lanes", () => {
    it("replays golden v1 retry commands and separates new v2 authority", () => {
        const legacyContract = contract({ legacy: true });
        const legacyFirst = buildSearchCandidateCommand(
            strategyAggregate(legacyContract, 0),
            { nextRound: 1, nextSlot: 0 },
        );
        const legacyReplacement = buildSearchCandidateCommand(
            strategyAggregate(legacyContract, 1),
            { nextRound: 1, nextSlot: 0 },
        );
        expect({
            strategyPolicyVersion:
                legacyContract.searchPolicy.version
                ?? LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
            first: {
                operator: legacyFirst.operator,
                seed: legacyFirst.seed,
                subjectIndex:
                    legacyFirst.replicationSchedule.subject.index,
            },
            replacement: {
                operator: legacyReplacement.operator,
                seed: legacyReplacement.seed,
                subjectIndex:
                    legacyReplacement.replicationSchedule.subject.index,
            },
        }).toEqual({
            strategyPolicyVersion: LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
            first: {
                operator: "fresh",
                seed: 1037780774,
                subjectIndex: 1,
            },
            replacement: {
                operator: "fresh",
                seed: 1048279631,
                subjectIndex: 1,
            },
        });
        expect(assertScientificSearchAlphaLanes(replayAggregate(
            legacyContract,
            legacyFirst,
            legacyReplacement,
        ))).toMatchObject({
            strategyPolicyVersion:
                LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
            laneCount: 2,
        });

        const currentContract = contract();
        const currentFirst = buildSearchCandidateCommand(
            strategyAggregate(currentContract, 0),
            { nextRound: 1, nextSlot: 0 },
        );
        const currentReplacement = buildSearchCandidateCommand(
            strategyAggregate(currentContract, 1),
            { nextRound: 1, nextSlot: 0 },
        );
        expect({
            strategyPolicyVersion: currentContract.searchPolicy.version,
            first: {
                operator: currentFirst.operator,
                seed: currentFirst.seed,
                subjectIndex:
                    currentFirst.replicationSchedule.subject.index,
            },
            replacement: {
                operator: currentReplacement.operator,
                seed: currentReplacement.seed,
                subjectIndex:
                    currentReplacement.replicationSchedule.subject.index,
            },
        }).toEqual({
            strategyPolicyVersion: SEARCH_STRATEGY_POLICY_VERSION,
            first: {
                operator: "fresh",
                seed: 1007262001,
                subjectIndex: 1,
            },
            replacement: {
                operator: "fresh",
                seed: 155517595,
                subjectIndex: 9,
            },
        });
    });

    it("spends a distinct bounded lane after every repeated invalidation", () => {
        const frozenContract = contract();
        const commands = Array.from({ length: 13 }, (_unused, index) =>
            buildSearchCandidateCommand(
                strategyAggregate(frozenContract, index),
                { nextRound: 1, nextSlot: 0 },
            ));
        const subjectIndices = commands.map(
            (command) => command.replicationSchedule.subject.index,
        );
        const claimAlphas = commands.map((command) =>
            alphaFor(frozenContract, command));
        const familyAlpha =
            frozenContract.statisticalPolicy.familyAllocations[0].alpha;

        expect(new Set(subjectIndices).size).toBe(commands.length);
        expect(subjectIndices[1]).toBeGreaterThan(7);
        expect(claimAlphas.slice(1).every((alpha) =>
            alpha < claimAlphas[0])).toBe(true);
        expect(claimAlphas.reduce((sum, alpha) => sum + alpha, 0))
            .toBeLessThan(familyAlpha);
        expect(claimAlphas.reduce((sum, alpha) => sum + alpha, 0))
            .toBeLessThan(claimAlphas[0] * commands.length);

        const recovered = strategyAggregate(frozenContract, 12);
        expect(buildSearchCandidateCommand(
            recovered,
            { nextRound: 1, nextSlot: 0 },
        )).toEqual(buildSearchCandidateCommand(
            recovered,
            { nextRound: 1, nextSlot: 0 },
        ));
    });

    it("rejects replayed lane reuse and replacement-lane substitution", () => {
        const frozenContract = contract();
        const first = buildSearchCandidateCommand(
            strategyAggregate(frozenContract, 0),
            { nextRound: 1, nextSlot: 0 },
        );
        const replacement = buildSearchCandidateCommand(
            strategyAggregate(frozenContract, 1),
            { nextRound: 1, nextSlot: 0 },
        );
        const valid = replayAggregate(frozenContract, first, replacement);

        expect(assertScientificSearchAlphaLanes(valid)).toMatchObject({
            laneCount: 2,
            lanes: [
                { replacementOrdinal: 0 },
                { replacementOrdinal: 1 },
            ],
        });

        const reused = structuredClone(valid);
        reused.commands["command-1"].command.replicationSchedule.subject.index =
            first.replicationSchedule.subject.index;
        expect(() => assertScientificSearchAlphaLanes(reused))
            .toThrow(/reused one preregistered alpha lane/u);

        const substituted = structuredClone(valid);
        substituted.commands["command-1"].command.replicationSchedule
            .subject.index += 2;
        expect(() => assertScientificSearchAlphaLanes(substituted))
            .toThrow(/substituted its preregistered alpha lane/u);

        const ordinalSubstitution = structuredClone(valid);
        ordinalSubstitution.commands["command-1"].command.replacementOrdinal =
            2;
        expect(() => assertScientificSearchAlphaLanes(ordinalSubstitution))
            .toThrow(/substituted its deterministic replacement ordinal/u);
    });
});
