import { describe, expect, it } from "vitest";

import {
    HYPOTHESES_IDENTITY_HASH_ALGORITHM,
    HYPOTHESES_VERSION,
    hypothesesIdentity,
    normalizeHypotheses,
    normalizeObservableRegistry,
    predictionIdentity,
} from "../domain/index.mjs";

const OBSERVABLES = [
    { key: "score", kind: "numeric", minimum: 0, maximum: 1 },
    { key: "latency_ms", kind: "numeric", minimum: 0, maximum: 10_000 },
    {
        key: "outcome",
        kind: "categorical",
        values: ["accepted", "rejected", "invalid"],
    },
];

const POLICY = {
    required: true,
    maxPredictions: 8,
    allowRequiredForResult: true,
};

const OPTIONS = {
    observableRegistry: OBSERVABLES,
    hypothesisPolicy: POLICY,
    assignedParentEvidenceIds: ["ev-parent"],
};

function predictionForms() {
    return [
        {
            id: "p-threshold",
            kind: "threshold",
            observable: "score",
            operator: ">=",
            value: 0.8,
            refutation: { kind: "threshold", operator: "<", value: 0.8 },
            requiredForResult: true,
        },
        {
            id: "p-interval",
            kind: "bounded_interval",
            observable: "latency_ms",
            lower: 50,
            upper: 150,
            refutation: { kind: "outside_interval" },
        },
        {
            id: "p-control-direction",
            kind: "direction",
            observable: "score",
            direction: "increase",
            reference: { kind: "control" },
            refutation: { kind: "direction", direction: "non_increase" },
        },
        {
            id: "p-parent-direction",
            kind: "direction",
            observable: "latency_ms",
            direction: "decrease",
            reference: { kind: "assigned_parent", evidenceId: "ev-parent" },
            refutation: { kind: "direction", direction: "non_decrease" },
        },
        {
            id: "p-outcome",
            kind: "categorical_outcome",
            observable: "outcome",
            outcome: "accepted",
            refutation: {
                kind: "categorical_outcome",
                operator: "not_equals",
                outcome: "accepted",
            },
        },
    ];
}

describe("v4 preregistered hypotheses", () => {
    it("normalizes, canonicalizes, and seals every supported prediction form", () => {
        const normalized = normalizeHypotheses({
            predictions: predictionForms().reverse(),
        }, OPTIONS);

        expect(normalized.version).toBe(HYPOTHESES_VERSION);
        expect(normalized.predictions.map((prediction) => prediction.id)).toEqual([
            "p-control-direction",
            "p-interval",
            "p-outcome",
            "p-parent-direction",
            "p-threshold",
        ]);
        expect(normalized.predictions.find((item) => item.id === "p-interval"))
            .toMatchObject({ lower: 50, upper: 150, requiredForResult: false });
        expect(normalized.identity).toMatch(
            new RegExp(`^${HYPOTHESES_IDENTITY_HASH_ALGORITHM}:[a-f0-9]{64}$`),
        );
        expect(Object.isFrozen(normalized)).toBe(true);
        expect(Object.isFrozen(normalized.predictions[0])).toBe(true);

        const reordered = normalizeHypotheses({
            predictions: predictionForms(),
        }, {
            ...OPTIONS,
            observableRegistry: [
                { ...OBSERVABLES[2], values: [...OBSERVABLES[2].values].reverse() },
                OBSERVABLES[1],
                OBSERVABLES[0],
            ],
        });
        expect(reordered).toEqual(normalized);
        expect(hypothesesIdentity({ predictions: predictionForms() }, OPTIONS))
            .toBe(normalized.identity);
        expect(predictionIdentity(predictionForms()[0], OPTIONS)).toMatch(
            /^sha256:crucible-preregistered-prediction-v4:[a-f0-9]{64}$/,
        );
    });

    it("rejects unknown observables, unbounded values, invalid categories, and unassigned parents", () => {
        const cases = [
            {
                ...predictionForms()[0],
                observable: "unknown_metric",
            },
            {
                ...predictionForms()[0],
                value: Number.POSITIVE_INFINITY,
                refutation: {
                    kind: "threshold",
                    operator: "<",
                    value: Number.POSITIVE_INFINITY,
                },
            },
            {
                ...predictionForms()[0],
                value: 2,
                refutation: { kind: "threshold", operator: "<", value: 2 },
            },
            {
                ...predictionForms()[3],
                reference: { kind: "assigned_parent", evidenceId: "ev-not-assigned" },
            },
            {
                ...predictionForms()[4],
                outcome: "unknown",
                refutation: {
                    kind: "categorical_outcome",
                    operator: "not_equals",
                    outcome: "unknown",
                },
            },
        ];
        for (const prediction of cases) {
            expect(() => normalizeHypotheses({ predictions: [prediction] }, OPTIONS)).toThrow();
        }
        expect(() => normalizeHypotheses({
            predictions: [{
                id: "missing-refutation",
                kind: "bounded_interval",
                observable: "score",
                lower: 0.2,
                upper: 0.4,
            }],
        }, OPTIONS)).toThrow(/refutation/);
        expect(() => normalizeObservableRegistry([
            { key: "unbounded", kind: "numeric", minimum: 0, maximum: Infinity },
        ])).toThrow(/finite bounded number/);
    });

    it("requires predictions only when policy says so and enforces strict caps", () => {
        expect(() => normalizeHypotheses(null, OPTIONS)).toThrow(/required/i);
        expect(normalizeHypotheses(null, {
            observableRegistry: OBSERVABLES,
            hypothesisPolicy: { required: false },
        })).toBeNull();
        expect(() => normalizeHypotheses({
            predictions: predictionForms().slice(0, 2),
        }, {
            ...OPTIONS,
            hypothesisPolicy: { ...POLICY, maxPredictions: 1 },
        })).toThrow(/at most 1/);
        expect(() => normalizeHypotheses({
            predictions: [{
                ...predictionForms()[0],
                extraVerdict: "VERIFIED_RESULT",
            }],
        }, OPTIONS)).toThrow(/unknown field/);
    });

});
