import { describe, expect, it } from "vitest";

import { deriveRunnerExecutionLimits } from "../runtime/index.mjs";
import { createInvestigationContract } from "../domain/index.mjs";
import { makeV4ContractInput } from "./v4-contract-fixture.mjs";

describe("Crucible runner fast component limits", () => {
    it("derives deterministic bounded work from the frozen candidate topology", () => {
        const contract = createInvestigationContract(makeV4ContractInput({
            maxRounds: 3,
            candidatesPerRound: 2,
            hypothesisTopology: "open_generative",
        }));

        const first = deriveRunnerExecutionLimits(contract);
        expect(first).toEqual(deriveRunnerExecutionLimits(contract));
        expect(first).toMatchObject({
            candidateEvaluations: 6,
            confirmationRoleUnits: 3,
            replicatedRoleUnits: 9,
            scheduledBlocks: 9,
            replicationArmsPerBlock: 2,
            requiredCandidateEvaluations: 9,
            requiredControlEvaluations: 9,
            requiredReplicationEvaluations: 18,
            requiredMeasurementEvaluations: 26,
            expectedExternalEffects:
                contract.statisticalPolicy.evaluationBudget.maxTotalEvaluations
                + 6,
        });

        expect(first.safetyMargin).toBeGreaterThanOrEqual(64);
        expect(first.maxExternalEffects)
            .toBe(first.expectedExternalEffects + first.safetyMargin);
        expect(first.maxLoopIterations).toBeGreaterThan(first.maxExternalEffects);
        expect(Object.isFrozen(first)).toBe(true);
    });

    it("rejects runtime byte budgets below worst-case role × block × arm work", () => {
        const contract = structuredClone(createInvestigationContract(
            makeV4ContractInput({
                maxRounds: 2,
                candidatesPerRound: 2,
            }),
        ));
        contract.statisticalPolicy.resourceBudget.perInvestigationOutputBytes =
            contract.statisticalPolicy.resourceBudget.perAttemptOutputBytes;

        expect(() => deriveRunnerExecutionLimits(contract)).toThrow(
            /role × block × arm/u,
        );
    });

    it("reserves one additional bounded effect for certified impossibility", () => {
        const ordinaryContract = createInvestigationContract(makeV4ContractInput({
            hypothesisTopology: "finite_enumerable",
        }));
        const certifiedContract = createInvestigationContract(makeV4ContractInput({
            hypothesisTopology: "certified_impossibility",
        }));
        const ordinary = deriveRunnerExecutionLimits(ordinaryContract);
        const certified = deriveRunnerExecutionLimits(certifiedContract);

        expect(certified.expectedExternalEffects)
            .toBe(ordinary.expectedExternalEffects + 1);
        expect(certified.maxLoopIterations)
            .toBeGreaterThan(ordinary.maxLoopIterations);
    });

    it("budgets role-aware confirmation/challenge execution and recovery", () => {
        const oneInput = makeV4ContractInput();
        const twoInput = makeV4ContractInput();
        twoInput.statisticalPolicy.maxConfirmations = 2;
        const requirements = {
            ...twoInput.statisticalPolicy.evaluationBudget,
        };
        requirements.maxCandidateEvaluations += 3;
        requirements.maxControlEvaluations += 3;
        requirements.maxTotalEvaluations += 6;
        twoInput.statisticalPolicy.evaluationBudget = requirements;
        const one = deriveRunnerExecutionLimits(
            createInvestigationContract(oneInput),
        );
        const two = deriveRunnerExecutionLimits(
            createInvestigationContract(twoInput),
        );

        expect(one.confirmationRoleUnits).toBe(3);
        expect(two.confirmationRoleUnits).toBe(6);
        expect(two.requiredReplicationEvaluations
            - one.requiredReplicationEvaluations).toBe(6);
        expect(two.maxLoopIterations).toBeGreaterThan(one.maxLoopIterations);
        expect(two.maxRestarts).toBeGreaterThanOrEqual(one.maxRestarts);
    });
});
