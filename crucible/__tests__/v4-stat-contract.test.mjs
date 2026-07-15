import { describe, expect, it } from "vitest";

import {
    DEFAULT_SEARCH_POLICY,
    LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
    SEARCH_STRATEGY_POLICY_VERSION,
    contractHash,
    createInvestigationContract,
} from "../domain/index.mjs";
import { computeHarnessSuiteV4Identity } from "../measurement/index.mjs";
import {
    buildPromptContext,
    deriveRunnerExecutionLimits,
} from "../runtime/index.mjs";
import {
    fakeHarnessSuiteV4,
    makeV4ContractInput,
    snapshot,
} from "./v4-contract-fixture.mjs";

function clone(value) {
    return structuredClone(value);
}

describe("v4 frozen statistical contract", () => {
    it("versions new search authority while preserving unversioned v1 contracts", () => {
        const current = createInvestigationContract(makeV4ContractInput());
        expect(current.searchPolicy.version)
            .toBe(SEARCH_STRATEGY_POLICY_VERSION);

        const legacyInput = makeV4ContractInput();
        const {
            version: _version,
            ...legacySearchPolicy
        } = legacyInput.searchPolicy;
        legacyInput.searchPolicy = legacySearchPolicy;
        const legacy = createInvestigationContract(legacyInput);
        expect(legacy.searchPolicy).not.toHaveProperty("version");

        const explicitLegacyInput = makeV4ContractInput();
        explicitLegacyInput.searchPolicy.version =
            LEGACY_SEARCH_STRATEGY_POLICY_VERSION;
        expect(createInvestigationContract(explicitLegacyInput).searchPolicy)
            .toMatchObject({
                version: LEGACY_SEARCH_STRATEGY_POLICY_VERSION,
            });

        const unknown = makeV4ContractInput();
        unknown.searchPolicy.version = "crucible-search-strategy-v999";
        expect(() => createInvestigationContract(unknown))
            .toThrow(/searchPolicy\.version is unsupported/u);
    });

    it("canonicalizes unordered registries, metrics, alpha families, and tolerances", () => {
        const base = makeV4ContractInput({
            observableRegistry: [
                { key: "latency", kind: "numeric", minimum: 0, maximum: 1000 },
                { key: "score", kind: "numeric", minimum: 0, maximum: 1 },
            ],
        });
        base.statisticalPolicy.metrics = [
            {
                key: "latency",
                minimum: 0,
                maximum: 1000,
                estimand: "mean latency difference versus control",
                unit: "ms",
                direction: "min",
                acceptanceThreshold: 200,
                practicalEquivalenceDelta: 5,
                family: "secondary",
            },
            base.statisticalPolicy.metrics[0],
        ];
        base.statisticalPolicy.familyAllocations = [
            { family: "secondary", alpha: 0.02 },
            { family: "primary", alpha: 0.03 },
        ];
        base.statisticalPolicy.control.tolerances = [
            { metric: "latency", absolute: 2, relative: 0.01 },
            { metric: "score", absolute: 0.01, relative: 0 },
        ];

        const reordered = clone(base);
        reordered.observableRegistry.reverse();
        reordered.statisticalPolicy.metrics.reverse();
        reordered.statisticalPolicy.familyAllocations.reverse();
        reordered.statisticalPolicy.control.tolerances.reverse();

        const first = createInvestigationContract(base);
        const second = createInvestigationContract(reordered);
        expect(second).toEqual(first);
        expect(contractHash(second)).toBe(contractHash(first));
        expect(first.statisticalPolicy.metrics.map((metric) => metric.key))
            .toEqual(["latency", "score"]);
        expect(first.statisticalPolicy.metrics.map((metric) => metric.priority))
            .toEqual([0, 1]);
    });

    it("freezes explicit metric priority independently of key order", () => {
        const input = makeV4ContractInput({
            observableRegistry: [
                { key: "latency", kind: "numeric", minimum: 0, maximum: 1000 },
                { key: "score", kind: "numeric", minimum: 0, maximum: 1 },
            ],
        });
        input.statisticalPolicy.metrics = [
            {
                ...input.statisticalPolicy.metrics[0],
                priority: 0,
            },
            {
                key: "latency",
                priority: 1,
                minimum: 0,
                maximum: 1000,
                estimand: "mean latency difference versus control",
                unit: "ms",
                direction: "min",
                acceptanceThreshold: 200,
                practicalEquivalenceDelta: 5,
                family: "secondary",
            },
        ];
        input.statisticalPolicy.familyAllocations = [
            { family: "primary", alpha: 0.03 },
            { family: "secondary", alpha: 0.02 },
        ];
        input.statisticalPolicy.control.tolerances.push({
            metric: "latency",
            absolute: 2,
            relative: 0.01,
        });

        const contract = createInvestigationContract(input);
        expect(contract.statisticalPolicy.metrics.map((metric) => metric.key))
            .toEqual(["score", "latency"]);
        expect(contract.metrics).toEqual([
            {
                key: "score",
                priority: 0,
                direction: "max",
                epsilon: 0.01,
            },
            {
                key: "latency",
                priority: 1,
                direction: "min",
                epsilon: 5,
            },
        ]);
    });

    it("requires goal/topology roles, finite bounds, and the matching control", () => {
        const missingRole = makeV4ContractInput();
        delete missingRole.harnessSuite.roles.novelty;
        expect(() => createInvestigationContract(missingRole))
            .toThrow(/roles\.novelty is required|role "novelty" is required/u);

        const missingVerifier = makeV4ContractInput({
            hypothesisTopology: "certified_impossibility",
            harnessSuite: fakeHarnessSuiteV4({ includeVerifier: false }),
        });
        missingVerifier.harnessSuiteIdentity =
            computeHarnessSuiteV4Identity(missingVerifier.harnessSuite);
        expect(() => createInvestigationContract(missingVerifier))
            .toThrow(/impossibility_verifier/u);

        const unbounded = makeV4ContractInput();
        unbounded.observableRegistry[0].maximum = Number.POSITIVE_INFINITY;
        unbounded.statisticalPolicy.metrics[0].maximum =
            Number.POSITIVE_INFINITY;
        expect(() => createInvestigationContract(unbounded))
            .toThrow(/finite bounded number|finite number/u);

        const finite = makeV4ContractInput({
            hypothesisTopology: "finite_enumerable",
            candidatesPerRound: 1,
            maxRounds: 1,
        });
        finite.statisticalPolicy.control.identity =
            `sha256:crucible-wrong-control-v1:${"f".repeat(64)}`;
        expect(() => createInvestigationContract(finite))
            .toThrow(/must match the frozen enumerand manifest control/u);
    });

    it("rejects invalid alpha sums, ranges, and impossible capacity budgets", () => {
        const alpha = makeV4ContractInput();
        alpha.statisticalPolicy.familyAllocations[0].alpha = 0.04;
        expect(() => createInvestigationContract(alpha))
            .toThrow(/sum to investigationAlpha/u);

        const threshold = makeV4ContractInput();
        threshold.statisticalPolicy.metrics[0].acceptanceThreshold = 2;
        expect(() => createInvestigationContract(threshold))
            .toThrow(/acceptanceThreshold/u);

        const blocks = makeV4ContractInput();
        blocks.statisticalPolicy.minBlocks = 3;
        blocks.statisticalPolicy.maxBlocks = 2;
        expect(() => createInvestigationContract(blocks))
            .toThrow(/minBlocks cannot exceed maxBlocks/u);

        const evaluation = makeV4ContractInput();
        evaluation.statisticalPolicy.evaluationBudget.maxCandidateEvaluations = 1;
        expect(() => createInvestigationContract(evaluation))
            .toThrow(/cannot cover the frozen block\/search\/confirmation capacity/u);

        const bytes = makeV4ContractInput();
        bytes.statisticalPolicy.resourceBudget.perInvestigationCasBytes = 1;
        expect(() => createInvestigationContract(bytes))
            .toThrow(/resourceBudget.*impossible/u);
    });

    it("binds the runtime identity policy and initial root into the signed contract", () => {
        const input = makeV4ContractInput();
        const first = createInvestigationContract(input);
        expect(first.runtimeIdentityPolicyIdentity)
            .toBe(input.runtimeIdentityPolicyIdentity);
        expect(first.runtimeIdentityRoot).toBe(input.runtimeIdentityRoot);

        const changedRoot = makeV4ContractInput({
            runtimeIdentityRoot:
                `sha256:crucible-runtime-identity-root-v1:${"f".repeat(64)}`,
        });
        expect(contractHash(createInvestigationContract(changedRoot)))
            .not.toBe(contractHash(first));

        const changedPolicy = makeV4ContractInput();
        changedPolicy.runtimeIdentityPolicy = clone(
            changedPolicy.runtimeIdentityPolicy,
        );
        changedPolicy.runtimeIdentityPolicy.limits.maxFiles -= 1;
        expect(() => createInvestigationContract(changedPolicy))
            .toThrow(/runtimeIdentityPolicyIdentity/u);

        const wrongRootDomain = makeV4ContractInput({
            runtimeIdentityRoot:
                `sha256:wrong-runtime-root-v1:${"f".repeat(64)}`,
        });
        expect(() => createInvestigationContract(wrongRootDomain))
            .toThrow(/runtimeIdentityRoot must use/u);
    });

    it("rejects suite relabeling, manifest mutation, and all v3 contract fields", () => {
        const relabeled = makeV4ContractInput();
        relabeled.harnessSuite.operatorCorpus.cases["cal-accept"].expectation =
            "reject";
        expect(() => createInvestigationContract(relabeled))
            .toThrow(/identity does not match|relabel|expectation/iu);

        const mutatedManifest = clone(makeV4ContractInput({
            hypothesisTopology: "finite_enumerable",
            candidatesPerRound: 1,
            maxRounds: 1,
        }));
        mutatedManifest.enumerandManifest.entries[0].artifactSnapshotHash =
            snapshot("9");
        expect(() => createInvestigationContract(mutatedManifest))
            .toThrow(/Merkle root does not match|enumerandHash does not match/u);

        for (const legacyField of [
            ["harnessId", "legacy"],
            ["validationCases", []],
            ["boundedCandidateIds", ["label-only"]],
            ["metrics", []],
            ["declaredLimits", {}],
            ["parserVersion", "legacy"],
            ["harnessIdentity", {}],
        ]) {
            const input = makeV4ContractInput();
            input[legacyField[0]] = legacyField[1];
            expect(() => createInvestigationContract(input))
                .toThrow(/canonical fields/u);
        }

        const stopFirst = makeV4ContractInput();
        stopFirst.searchPolicy = {
            ...DEFAULT_SEARCH_POLICY,
            stopOnFirstAccept: true,
        };
        expect(() => createInvestigationContract(stopFirst))
            .toThrow(/searchPolicy.*canonical fields/u);
    });

    it("freezes operator validation states, required roles, and statistical claim sets", () => {
        const contract = createInvestigationContract(makeV4ContractInput());
        expect(contract.validationRoles).toEqual([
            "calibration",
            "search",
            "confirmation",
            "challenge",
        ]);
        expect(contract.validationCases).toEqual([
            {
                id: "cal-accept",
                expectation: "accept",
                expectedClaimState: "SUPPORTED",
                artifactHash: snapshot("1"),
            },
            {
                id: "cal-reject",
                expectation: "reject",
                expectedClaimState: "REFUTED",
                artifactHash: snapshot("2"),
            },
        ]);
        expect(contract.validationClaimSet).toMatchObject({
            requiredClaimIds: ["validation.harness_pass"],
            claims: [{
                id: "validation.harness_pass",
                kind: "harness_pass",
            }],
        });
        expect(contract.acceptanceClaimSet.requiredClaimIds)
            .toEqual(["metric.score.acceptance"]);

        const callerLabels = makeV4ContractInput();
        callerLabels.validationCases = [{
            id: "cal-accept",
            expectation: "reject",
            artifactHash: snapshot("1"),
        }];
        expect(() => createInvestigationContract(callerLabels))
            .toThrow(/canonical fields/u);

        const nonStatistical = makeV4ContractInput({
            acceptancePredicate: {
                kind: "field_equals",
                path: ["payload"],
                value: true,
            },
        });
        expect(() => createInvestigationContract(nonStatistical))
            .toThrow(/statistical claim set/u);
    });

    it("redacts held-out case ids/snapshots and control identity from worker context", () => {
        const contract = createInvestigationContract(makeV4ContractInput());
        const { context } = buildPromptContext({
            contract,
            archive: {},
            slot: {
                operator: "fresh",
                round: 1,
                slotIndex: 0,
                candidateId: "candidate-r000001-s000",
                model: "worker-a",
                seed: 1,
                parentEvidenceIds: [],
                promptContextRefs: [],
            },
        });
        const encoded = JSON.stringify(context);
        expect(encoded).not.toContain("challenge-case");
        expect(encoded).not.toContain(snapshot("5"));
        expect(encoded).not.toContain("confirmation-case");
        expect(context.harnessSuite.roles.challenge.caseManifest).toBeNull();
        expect(context.statisticalPolicy.control.identity).toBeNull();
        expect(context.observableRegistry).toEqual(contract.observableRegistry);
        expect(context.hypothesisPolicy).toEqual(contract.hypothesisPolicy);
    });

    it("derives loop/effect/output/CAS limits from the frozen policy", () => {
        const contract = createInvestigationContract(makeV4ContractInput());
        const limits = deriveRunnerExecutionLimits(contract);
        expect(limits.byteBudgets).toEqual(
            contract.statisticalPolicy.resourceBudget,
        );
        expect(limits.maxExternalEffects)
            .toBeGreaterThan(contract.statisticalPolicy.evaluationBudget.maxTotalEvaluations);
        expect(limits.maxLoopIterations).toBeGreaterThan(limits.maxExternalEffects);
    });
});
