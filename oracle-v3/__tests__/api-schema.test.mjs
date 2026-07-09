// oracle-v3/__tests__/api-schema.test.mjs
//
// Proves the single-source schema/spec builder produces a Copilot JSON Schema
// and a runtime parser that are in lock-step (generation/parsing parity): the
// JSON Schema `required` list is exactly the set of arguments the parser
// enforces as required, property names match, and normalization (defaults,
// unknown-key rejection, range/enum/type checks) behaves as advertised.

import { describe, expect, it } from "vitest";

import { SchemaValidationError } from "../api/schema.mjs";
import {
    PUBLIC_TOOL_NAMES,
    TOOL_SPECS,
    oracleResultSpec,
    oracleStartSpec,
    oracleStatusSpec,
    oracleStopSpec,
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
    oracle_start: validStartArgs(),
    oracle_status: { investigation_id: "inv-abc123" },
    oracle_stop: { investigation_id: "inv-abc123" },
    oracle_result: { investigation_id: "inv-abc123" },
};

describe("oracle-v3 API schema (single source)", () => {
    it("exposes exactly the four public tools", () => {
        expect(PUBLIC_TOOL_NAMES).toEqual([
            "oracle_start",
            "oracle_status",
            "oracle_stop",
            "oracle_result",
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
        expect(() => oracleStatusSpec.parse({ investigation_id: "inv-1", extra: 1 }))
            .toThrow(SchemaValidationError);
        expect(() => oracleStartSpec.parse(validStartArgs({ surprise: true })))
            .toThrow(SchemaValidationError);
    });

    it("rejects a non-object argument payload", () => {
        expect(() => oracleStatusSpec.parse(null)).toThrow(SchemaValidationError);
        expect(() => oracleStatusSpec.parse("nope")).toThrow(SchemaValidationError);
        expect(() => oracleStatusSpec.parse([])).toThrow(SchemaValidationError);
    });

    it("applies the metrics default and preserves it as an empty array", () => {
        const parsed = oracleStartSpec.parse(validStartArgs());
        expect(parsed.metrics).toEqual([]);
        // Default is cloned, not shared.
        parsed.metrics.push({ key: "x", direction: "max" });
        expect(oracleStartSpec.parse(validStartArgs()).metrics).toEqual([]);
    });

    it("normalizes nested metric objects and rejects bad enums/ranges", () => {
        const parsed = oracleStartSpec.parse(validStartArgs({
            metrics: [{ key: "score", direction: "max", epsilon: 0.5 }],
        }));
        expect(parsed.metrics).toEqual([{ key: "score", direction: "max", epsilon: 0.5 }]);

        expect(() => oracleStartSpec.parse(validStartArgs({
            metrics: [{ key: "score", direction: "sideways" }],
        }))).toThrow(SchemaValidationError);
        expect(() => oracleStartSpec.parse(validStartArgs({
            metrics: [{ key: "score", direction: "max", epsilon: -1 }],
        }))).toThrow(SchemaValidationError);
    });

    it("enforces validation_cases minItems and item shape", () => {
        expect(() => oracleStartSpec.parse(validStartArgs({
            validation_cases: [{ id: "only", expectation: "accept", path: "cases/only" }],
        }))).toThrow(SchemaValidationError);
        expect(() => oracleStartSpec.parse(validStartArgs({
            validation_cases: [
                { id: "good", expectation: "maybe", path: "cases/good" },
                { id: "bad", expectation: "reject", path: "cases/bad" },
            ],
        }))).toThrow(SchemaValidationError);
    });

    it("enforces worker_models uniqueness and bounds", () => {
        expect(() => oracleStartSpec.parse(validStartArgs({ worker_models: ["dup", "dup"] })))
            .toThrow(SchemaValidationError);
        expect(() => oracleStartSpec.parse(validStartArgs({ worker_models: [] })))
            .toThrow(SchemaValidationError);
    });

    it("enforces integer ranges for candidates_per_round and max_rounds", () => {
        expect(() => oracleStartSpec.parse(validStartArgs({ candidates_per_round: 0 })))
            .toThrow(SchemaValidationError);
        expect(() => oracleStartSpec.parse(validStartArgs({ candidates_per_round: 9 })))
            .toThrow(SchemaValidationError);
        expect(() => oracleStartSpec.parse(validStartArgs({ max_rounds: 0 })))
            .toThrow(SchemaValidationError);
        expect(() => oracleStartSpec.parse(validStartArgs({ candidates_per_round: 2.5 })))
            .toThrow(SchemaValidationError);
    });

    it("rejects a harness_id that looks like a filesystem path", () => {
        expect(() => oracleStartSpec.parse(validStartArgs({ harness_id: "../escape" })))
            .toThrow(SchemaValidationError);
        expect(() => oracleStartSpec.parse(validStartArgs({ harness_id: "a/b" })))
            .toThrow(SchemaValidationError);
    });

    it("accepts optional bounded_candidate_ids, deadline_iso, and reset_policy", () => {
        const parsed = oracleStartSpec.parse(validStartArgs({
            bounded_candidate_ids: ["cand-a", "cand-b"],
            deadline_iso: "2026-07-10T09:00:00.000Z",
            reset_policy: "circuit_open",
        }));
        expect(parsed.bounded_candidate_ids).toEqual(["cand-a", "cand-b"]);
        expect(parsed.deadline_iso).toBe("2026-07-10T09:00:00.000Z");
        expect(parsed.reset_policy).toBe("circuit_open");
        expect(() => oracleStartSpec.parse(validStartArgs({ reset_policy: "anything" })))
            .toThrow(SchemaValidationError);
    });

    it("carries the acceptance_predicate object through unchanged", () => {
        const predicate = { kind: "all", predicates: [{ kind: "harness_pass" }] };
        const parsed = oracleStartSpec.parse(validStartArgs({ acceptance_predicate: predicate }));
        expect(parsed.acceptance_predicate).toEqual(predicate);
        expect(() => oracleStartSpec.parse(validStartArgs({ acceptance_predicate: [] })))
            .toThrow(SchemaValidationError);
    });

    it("keeps oracle_status/stop/result minimal (only investigation_id, plus optional reason)", () => {
        expect(oracleStatusSpec.parameters.required).toEqual(["investigation_id"]);
        expect(oracleResultSpec.parameters.required).toEqual(["investigation_id"]);
        expect(oracleStopSpec.parameters.required).toEqual(["investigation_id"]);
        expect(Object.keys(oracleStopSpec.parameters.properties).sort())
            .toEqual(["investigation_id", "reason"]);
    });
});
