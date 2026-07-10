// crucible/__tests__/api-schema.test.mjs
//
// Proves the single-source schema/spec builder produces a Copilot JSON Schema
// and a runtime parser that are in lock-step (generation/parsing parity): the
// JSON Schema `required` list is exactly the set of arguments the parser
// enforces as required, property names match, and normalization (defaults,
// unknown-key rejection, range/enum/type checks) behaves as advertised.

import { describe, expect, it } from "vitest";

import { SchemaValidationError } from "../api/schema.mjs";
import {
    DEFAULT_SEARCH_POLICY,
} from "../domain/index.mjs";
import {
    PUBLIC_TOOL_NAMES,
    TOOL_SPECS,
    crucibleResultSpec,
    crucibleStartSpec,
    crucibleStatusSpec,
    crucibleStopSpec,
} from "../api/schema.mjs";

function validStartArgs(overrides = {}) {
    return {
        objective: "find a candidate scoring at least 90",
        project_dir: "C:\\proj",
        harness_id: "primary-harness",
        acceptance_predicate: { kind: "harness_pass" },
        hypothesis_topology: "finite_enumerable",
        validation_cases: [
            { id: "good", expectation: "accept", path: "cases/good" },
            { id: "bad", expectation: "reject", path: "cases/bad" },
        ],
        worker_models: ["model-a", "model-b"],
        candidates_per_round: 2,
        max_rounds: 3,
        ...overrides,
    };
}

const VALID_ARGS = {
    crucible_start: validStartArgs(),
    crucible_status: { investigation_id: "inv-abc123" },
    crucible_stop: { investigation_id: "inv-abc123" },
    crucible_result: { investigation_id: "inv-abc123" },
};

describe("crucible API schema (single source)", () => {
    it("exposes exactly the four public tools", () => {
        expect(PUBLIC_TOOL_NAMES).toEqual([
            "crucible_start",
            "crucible_status",
            "crucible_stop",
            "crucible_result",
        ]);
        expect(TOOL_SPECS).toHaveLength(4);
    });

    it("emits strict object JSON Schemas (additionalProperties:false)", () => {
        for (const spec of TOOL_SPECS) {
            expect(spec.parameters.type).toBe("object");
            expect(spec.parameters.additionalProperties).toBe(false);
            expect(Object.keys(spec.parameters.properties).length).toBeGreaterThan(0);
            expect(Array.isArray(spec.parameters.required)).toBe(true);
        }
    });

    // The core parity property: the JSON Schema `required` array is exactly the
    // set of keys the runtime parser rejects when missing, and every property
    // NOT listed as required parses fine when omitted.
    it.each(TOOL_SPECS.map((spec) => [spec.name, spec]))(
        "%s: JSON Schema required list matches the parser",
        (name, spec) => {
            const properties = Object.keys(spec.parameters.properties);
            const required = new Set(spec.parameters.required);
            const validArgs = VALID_ARGS[name];

            // Baseline: the canonical valid instance parses.
            expect(() => spec.parse(validArgs)).not.toThrow();

            for (const property of properties) {
                const withoutProperty = { ...validArgs };
                delete withoutProperty[property];
                if (required.has(property)) {
                    expect(() => spec.parse(withoutProperty)).toThrow(SchemaValidationError);
                } else {
                    expect(() => spec.parse(withoutProperty)).not.toThrow();
                }
            }

            // Every required key is a declared property (no dangling requires).
            for (const key of required) {
                expect(properties).toContain(key);
            }
        },
    );

    it("rejects unknown arguments", () => {
        expect(() => crucibleStatusSpec.parse({ investigation_id: "inv-1", extra: 1 }))
            .toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse(validStartArgs({ surprise: true })))
            .toThrow(SchemaValidationError);
    });

    it("rejects a non-object argument payload", () => {
        expect(() => crucibleStatusSpec.parse(null)).toThrow(SchemaValidationError);
        expect(() => crucibleStatusSpec.parse("nope")).toThrow(SchemaValidationError);
        expect(() => crucibleStatusSpec.parse([])).toThrow(SchemaValidationError);
    });

    it("applies the metrics default and preserves it as an empty array", () => {
        const parsed = crucibleStartSpec.parse(validStartArgs());
        expect(parsed.metrics).toEqual([]);
        // Default is cloned, not shared.
        parsed.metrics.push({ key: "x", direction: "max" });
        expect(crucibleStartSpec.parse(validStartArgs()).metrics).toEqual([]);
    });

    it("fills a canonical version-2 search policy by default", () => {
        const parsed = crucibleStartSpec.parse(validStartArgs());
        expect(parsed.search_policy).toEqual(DEFAULT_SEARCH_POLICY);
        expect(parsed.search_policy.stopOnFirstAccept).toBe(false);
        expect(parsed.search_policy.dedupPolicy).toBe("mark");

        parsed.search_policy.operatorWeights.fresh = 999;
        expect(crucibleStartSpec.parse(validStartArgs()).search_policy)
            .toEqual(DEFAULT_SEARCH_POLICY);
    });

    it("normalizes partial search-policy overrides and enforces strict ranges", () => {
        const parsed = crucibleStartSpec.parse(validStartArgs({
            search_policy: {
                stopOnFirstAccept: true,
                plateauWindow: 2,
                minRoundsBeforePlateau: 2,
                operatorWeights: { fresh: 5 },
            },
        }));
        expect(parsed.search_policy).toEqual({
            ...DEFAULT_SEARCH_POLICY,
            stopOnFirstAccept: true,
            plateauWindow: 2,
            minRoundsBeforePlateau: 2,
            operatorWeights: {
                ...DEFAULT_SEARCH_POLICY.operatorWeights,
                fresh: 5,
            },
        });

        for (const search_policy of [
            { plateauWindow: 0 },
            { plateauWindow: 3, minRoundsBeforePlateau: 2 },
            { mandatoryEscapeRounds: 0 },
            { operatorWeights: { fresh: 0 } },
            {
                operatorWeights: {
                    diversification: 0,
                    adversarial: 0,
                    restart: 0,
                },
            },
            { promptCaps: { parentEvidenceIds: 3, promptContextRefs: 2 } },
            { dedupPolicy: "drop" },
            { extra: true },
        ]) {
            expect(() => crucibleStartSpec.parse(validStartArgs({ search_policy })))
                .toThrow(SchemaValidationError);
        }
    });

    it("normalizes nested metric objects and rejects bad enums/ranges", () => {
        const parsed = crucibleStartSpec.parse(validStartArgs({
            metrics: [{ key: "score", direction: "max", epsilon: 0.5 }],
        }));
        expect(parsed.metrics).toEqual([{ key: "score", direction: "max", epsilon: 0.5 }]);

        expect(() => crucibleStartSpec.parse(validStartArgs({
            metrics: [{ key: "score", direction: "sideways" }],
        }))).toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse(validStartArgs({
            metrics: [{ key: "score", direction: "max", epsilon: -1 }],
        }))).toThrow(SchemaValidationError);
    });

    it("enforces validation_cases minItems and item shape", () => {
        expect(() => crucibleStartSpec.parse(validStartArgs({
            validation_cases: [{ id: "only", expectation: "accept", path: "cases/only" }],
        }))).toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse(validStartArgs({
            validation_cases: [
                { id: "good", expectation: "maybe", path: "cases/good" },
                { id: "bad", expectation: "reject", path: "cases/bad" },
            ],
        }))).toThrow(SchemaValidationError);
    });

    it("enforces worker_models uniqueness and bounds", () => {
        expect(() => crucibleStartSpec.parse(validStartArgs({ worker_models: ["dup", "dup"] })))
            .toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse(validStartArgs({ worker_models: [] })))
            .toThrow(SchemaValidationError);
    });

    it("enforces integer ranges for candidates_per_round and max_rounds", () => {
        expect(() => crucibleStartSpec.parse(validStartArgs({ candidates_per_round: 0 })))
            .toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse(validStartArgs({ candidates_per_round: 9 })))
            .toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse(validStartArgs({ max_rounds: 0 })))
            .toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse(validStartArgs({ candidates_per_round: 2.5 })))
            .toThrow(SchemaValidationError);
    });

    it("rejects a harness_id that looks like a filesystem path", () => {
        expect(() => crucibleStartSpec.parse(validStartArgs({ harness_id: "../escape" })))
            .toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse(validStartArgs({ harness_id: "a/b" })))
            .toThrow(SchemaValidationError);
    });

    it("accepts optional bounded_candidate_ids, deadline_iso, and reset_policy", () => {
        const parsed = crucibleStartSpec.parse(validStartArgs({
            bounded_candidate_ids: ["cand-a", "cand-b"],
            deadline_iso: "2026-07-10T09:00:00.000Z",
            reset_policy: "circuit_open",
        }));
        expect(parsed.bounded_candidate_ids).toEqual(["cand-a", "cand-b"]);
        expect(parsed.deadline_iso).toBe("2026-07-10T09:00:00.000Z");
        expect(parsed.reset_policy).toBe("circuit_open");
        expect(() => crucibleStartSpec.parse(validStartArgs({ reset_policy: "anything" })))
            .toThrow(SchemaValidationError);
    });

    it("documents and accepts the certified-impossibility verifier prerequisite", () => {
        const parsed = crucibleStartSpec.parse(validStartArgs({
            hypothesis_topology: "certified_impossibility",
        }));
        expect(parsed.hypothesis_topology).toBe("certified_impossibility");
        const description = crucibleStartSpec.parameters.properties
            .hypothesis_topology.description;
        expect(description).toContain("crucible-impossibility-request.json");
        expect(description).toContain("after validation");
    });

    it("carries the acceptance_predicate object through unchanged", () => {
        const predicate = { kind: "all", predicates: [{ kind: "harness_pass" }] };
        const parsed = crucibleStartSpec.parse(validStartArgs({ acceptance_predicate: predicate }));
        expect(parsed.acceptance_predicate).toEqual(predicate);
        expect(() => crucibleStartSpec.parse(validStartArgs({ acceptance_predicate: [] })))
            .toThrow(SchemaValidationError);
    });

    it("keeps crucible_status/stop/result minimal (only investigation_id, plus optional reason)", () => {
        expect(crucibleStatusSpec.parameters.required).toEqual(["investigation_id"]);
        expect(crucibleResultSpec.parameters.required).toEqual(["investigation_id"]);
        expect(crucibleStopSpec.parameters.required).toEqual(["investigation_id"]);
        expect(Object.keys(crucibleStopSpec.parameters.properties).sort())
            .toEqual(["investigation_id", "reason"]);
    });
});
