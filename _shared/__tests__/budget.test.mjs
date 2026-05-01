import { describe, expect, it } from "vitest";

import {
    checkBudget,
    computeWorstCaseCost,
    renderBudgetBlock,
} from "../budget.mjs";

describe("computeWorstCaseCost", () => {
    it("computes fixed-cost tools", () => {
        // 3 reviewers + 3 retries + 1 judge + 1 judge retry = 8.
        expect(computeWorstCaseCost("triple-duck", {})).toBe(8);
        expect(computeWorstCaseCost("triple-plan", {})).toBe(8);
    });

    it("computes debate costs with explicit and default rounds", () => {
        expect(computeWorstCaseCost("debate", { rounds: 1 })).toBe(5);
        expect(computeWorstCaseCost("debate", { rounds: 4 })).toBe(17);
        expect(computeWorstCaseCost("debate", {})).toBe(5);
    });

    it("computes triple-review costs with explicit and default max rounds", () => {
        // Pass-11 fix: synthesis cap is GLOBAL per round (1d auto + 1e accept
        // + retries all share the same SYNTH_CAP_PER_ROUND pool), so the
        // worst-case synthesis term is `synthCap`, NOT `synthCap * 2`.
        expect(computeWorstCaseCost("triple-review", { max_rounds: 3 })).toBe(3 * (6 + 10));
        expect(computeWorstCaseCost("triple-review", {})).toBe(3 * (6 + 10));
        expect(computeWorstCaseCost("triple-review", { max_rounds: 1 })).toBe(6 + 10);
    });

    it("throws for unknown tools", () => {
        expect(() => computeWorstCaseCost("unknown", {})).toThrow(TypeError);
    });
});

describe("checkBudget", () => {
    it("allows unspecified and sufficient caps", () => {
        expect(checkBudget("triple-duck", {})).toBeNull();
        expect(checkBudget("triple-duck", { max_premium_calls: 10 })).toBeNull();
    });

    it("rejects caps below worst-case cost", () => {
        const tripleDuckError = checkBudget("triple-duck", { max_premium_calls: 5 });
        expect(tripleDuckError).toContain("8");
        expect(tripleDuckError).toContain("5");

        const debateError = checkBudget("debate", { rounds: 4, max_premium_calls: 5 });
        expect(debateError).toContain("17");
        expect(debateError).toContain("5");
    });
});

describe("renderBudgetBlock", () => {
    it("renders the worst-case budget", () => {
        const block = renderBudgetBlock("triple-duck", {});
        expect(block).toContain("Budget cap:");
        expect(block).toContain("8 premium calls");
    });

    it("renders user-specified caps", () => {
        const block = renderBudgetBlock("triple-duck", { max_premium_calls: 10 });
        expect(block).toContain("8");
        expect(block).toContain("10");
    });
});


describe("computeWorstCaseCost — duck-council (pass 15)", () => {
    it("returns 14 for default (with judge)", () => {
        expect(computeWorstCaseCost("duck-council", {})).toBe(14);
    });

    it("returns 12 with skip_judge: true", () => {
        expect(computeWorstCaseCost("duck-council", { skip_judge: true })).toBe(12);
    });

    it("checkBudget rejects max_premium_calls=10 with judge but accepts 12 without", () => {
        // Default (with judge): worst case 14, cap 10 → reject.
        const errWithJudge = checkBudget("duck-council", { max_premium_calls: 10 });
        expect(errWithJudge).toBeTruthy();
        expect(errWithJudge).toMatch(/14/);
        // skip_judge: worst case 12, cap 12 → accept.
        const errNoJudge = checkBudget("duck-council", { skip_judge: true, max_premium_calls: 12 });
        expect(errNoJudge).toBeNull();
    });

    it("renderBudgetBlock includes the right cap for both judge configs", () => {
        const blockWithJudge = renderBudgetBlock("duck-council", {});
        expect(blockWithJudge).toContain("14 premium calls");
        const blockNoJudge = renderBudgetBlock("duck-council", { skip_judge: true });
        expect(blockNoJudge).toContain("12 premium calls");
    });
});
