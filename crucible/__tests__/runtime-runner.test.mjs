import { describe, expect, it } from "vitest";

import { deriveRunnerExecutionLimits } from "../runtime/index.mjs";

describe("Crucible runner fast component limits", () => {
    it("derives deterministic bounded work from the frozen candidate topology", () => {
        const contract = {
            maxRounds: 3,
            candidatesPerRound: 2,
            validationCases: [{ id: "good" }, { id: "bad" }],
            hypothesisTopology: "open_generative",
        };

        const first = deriveRunnerExecutionLimits(contract);
        expect(first).toEqual(deriveRunnerExecutionLimits(contract));
        expect(first).toMatchObject({
            candidateEvaluations: 6,
            expectedExternalEffects: 14,
            safetyMargin: 64,
            maxExternalEffects: 78,
        });
        expect(first.maxLoopIterations).toBeGreaterThan(first.maxExternalEffects);
        expect(Object.isFrozen(first)).toBe(true);
    });

    it("reserves one additional bounded effect for certified impossibility", () => {
        const base = {
            maxRounds: 1,
            candidatesPerRound: 1,
            validationCases: [{ id: "good" }, { id: "bad" }],
        };
        const ordinary = deriveRunnerExecutionLimits({
            ...base,
            hypothesisTopology: "finite_enumerable",
        });
        const certified = deriveRunnerExecutionLimits({
            ...base,
            hypothesisTopology: "certified_impossibility",
        });

        expect(certified.expectedExternalEffects)
            .toBe(ordinary.expectedExternalEffects + 1);
        expect(certified.maxLoopIterations)
            .toBeGreaterThan(ordinary.maxLoopIterations);
    });
});
