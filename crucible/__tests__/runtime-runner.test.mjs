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
});
