import { describe, expect, it } from "vitest";

import {
    PUBLIC_TOOL_NAMES,
    TOOL_SPECS,
    SchemaValidationError,
    crucibleResultSpec,
    crucibleStartSpec,
    crucibleStatusSpec,
    crucibleStopSpec,
} from "../api/schema.mjs";

const RAW_AUTHORITY_FIELDS = Object.freeze([
    "objective",
    "project_dir",
    "harness_suite_id",
    "harness_suite_identity",
    "acceptance_predicate",
    "hypothesis_topology",
    "enumerand_manifest",
    "observable_registry",
    "hypothesis_policy",
    "statistical_policy",
    "worker_models",
    "candidates_per_round",
    "max_rounds",
    "search_policy",
]);

describe("crucible API schema", () => {
    it("exposes exactly four strict public tools", () => {
        expect(PUBLIC_TOOL_NAMES).toEqual([
            "crucible_start",
            "crucible_status",
            "crucible_stop",
            "crucible_result",
        ]);
        expect(TOOL_SPECS).toHaveLength(4);
        for (const spec of TOOL_SPECS) {
            expect(spec.parameters.type).toBe("object");
            expect(spec.parameters.additionalProperties).toBe(false);
        }
    });

    it("exposes only experiment selection for a new start", () => {
        const [newBranch, reattachBranch] = crucibleStartSpec.parameters.oneOf;
        expect(Object.keys(newBranch.properties).sort()).toEqual([
            "deadline_iso",
            "experiment_id",
        ]);
        expect(newBranch.required).toEqual(["experiment_id"]);
        expect(Object.keys(reattachBranch.properties).sort()).toEqual([
            "deadline_iso",
            "investigation_id",
            "reset_policy",
        ]);
        expect(reattachBranch.required).toEqual(["investigation_id"]);

        expect(crucibleStartSpec.parse({
            experiment_id: "approved-science-run",
            deadline_iso: "2030-01-01T00:00:00.000Z",
        })).toEqual({
            experiment_id: "approved-science-run",
            deadline_iso: "2030-01-01T00:00:00.000Z",
        });
        expect(crucibleStartSpec.parse({
            investigation_id: "crucible-v4-investigation",
            deadline_iso: "2030-01-01T00:00:00.000Z",
            reset_policy: "failed",
        })).toEqual({
            investigation_id: "crucible-v4-investigation",
            deadline_iso: "2030-01-01T00:00:00.000Z",
            reset_policy: "failed",
        });
    });

    it.each(RAW_AUTHORITY_FIELDS)(
        "rejects model-authored authority field %s",
        (field) => {
            expect(() => crucibleStartSpec.parse({
                experiment_id: "approved",
                [field]: field === "objective" ? "injected" : {},
            })).toThrow(SchemaValidationError);
            expect(() => crucibleStartSpec.parse({
                [field]: field === "objective" ? "injected" : {},
            })).toThrow(SchemaValidationError);
        },
    );

    it("rejects mixed new-investigation and reattach forms", () => {
        expect(() => crucibleStartSpec.parse({
            experiment_id: "approved",
            investigation_id: "crucible-v4-investigation",
        })).toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse({
            investigation_id: "crucible-v4-investigation",
            experiment_id: "approved",
        })).toThrow(SchemaValidationError);
    });

    it("validates experiment ids and operational deadline/reset fields", () => {
        for (const experiment_id of [
            "../escape",
            "UPPERCASE",
            "nested/path",
            "two..dots",
            "",
        ]) {
            expect(() => crucibleStartSpec.parse({ experiment_id }))
                .toThrow(SchemaValidationError);
        }
        expect(() => crucibleStartSpec.parse({
            experiment_id: "approved",
            deadline_iso: "2030-01-01",
        })).toThrow(SchemaValidationError);
        expect(() => crucibleStartSpec.parse({
            investigation_id: "crucible-v4-investigation",
            reset_policy: "terminal",
        })).toThrow(SchemaValidationError);
    });

    it("keeps status, stop, and result parsers strict", () => {
        expect(crucibleStatusSpec.parameters.properties.operation.enum)
            .toEqual(["get", "list"]);
        expect(crucibleStatusSpec.parameters.required)
            .toEqual(["operation"]);
        expect(crucibleStatusSpec.parameters.oneOf.map((branch) =>
            branch.properties.operation.enum[0]))
            .toEqual(["get", "list"]);
        expect(crucibleStopSpec.parameters.properties.operation.enum)
            .toEqual(["pause", "archive", "delete"]);
        expect(crucibleStopSpec.parameters.required)
            .toEqual(["operation"]);
        expect(crucibleStopSpec.parameters.oneOf.map((branch) =>
            branch.properties.operation.enum[0]))
            .toEqual(["pause", "archive", "delete"]);
        expect(crucibleStatusSpec.parse({
            operation: "get",
            investigation_id: "inv-1",
        })).toEqual({
            operation: "get",
            investigation_id: "inv-1",
        });
        expect(crucibleStatusSpec.parse({
            operation: "list",
        })).toEqual({
            operation: "list",
            limit: 50,
        });
        expect(crucibleStopSpec.parse({
            operation: "pause",
            investigation_id: "inv-1",
            reason: "operator pause",
        })).toEqual({
            operation: "pause",
            investigation_id: "inv-1",
            reason: "operator pause",
        });
        expect(crucibleStopSpec.parse({
            operation: "archive",
            investigation_id: "inv-1",
        })).toEqual({
            operation: "archive",
            investigation_id: "inv-1",
        });
        expect(crucibleStopSpec.parse({
            operation: "delete",
            investigation_id: "inv-1",
            expected_archive_digest: `sha256:${"a".repeat(64)}`,
        })).toEqual({
            operation: "delete",
            investigation_id: "inv-1",
            expected_archive_digest: `sha256:${"a".repeat(64)}`,
        });
        expect(crucibleResultSpec.parse({
            investigation_id: "inv-1",
        })).toEqual({ investigation_id: "inv-1" });
        for (const spec of [
            crucibleStatusSpec,
            crucibleStopSpec,
            crucibleResultSpec,
        ]) {
            expect(() => spec.parse({
                ...(spec === crucibleStatusSpec
                    ? { operation: "get" }
                    : spec === crucibleStopSpec
                        ? { operation: "pause" }
                        : {}),
                investigation_id: "inv-1",
                extra: true,
            })).toThrow(SchemaValidationError);
        }
        expect(() => crucibleStatusSpec.parse({
            investigation_id: "inv-1",
        })).toThrow(SchemaValidationError);
        expect(() => crucibleStopSpec.parse({
            investigation_id: "inv-1",
        })).toThrow(SchemaValidationError);
        expect(() => crucibleStatusSpec.parse({
            operation: "list",
            investigation_id: "inv-1",
        })).toThrow(SchemaValidationError);
        expect(() => crucibleStopSpec.parse({
            operation: "delete",
            investigation_id: "inv-1",
            expected_archive_digest: `sha256:${"a".repeat(64)}`,
            reason: "not valid for delete",
        })).toThrow(SchemaValidationError);
    });
});
