// crucible/__tests__/api-extension.test.mjs
//
// Registration tests for the public SDK payload: exactly four tools, no hooks,
// derived JSON Schemas, and structured boundary error handling.

import { describe, expect, it } from "vitest";

import { buildRegistration, runToolBoundary } from "../api/handlers.mjs";
import {
    PUBLIC_TOOL_NAMES,
    crucibleResultSpec,
    crucibleStartSpec,
    crucibleStatusSpec,
    crucibleStopSpec,
} from "../api/schema.mjs";
import { SandboxUnavailableApiError } from "../api/errors.mjs";
import {
    READ_PARENT_ARTIFACT_TOOL_NAME,
    SUBMIT_CANDIDATE_TOOL_NAME,
} from "../runtime/index.mjs";
const VALID_START_ARGS = Object.freeze({
    experiment_id: "approved-test-experiment",
});

const VALID_ARGS = Object.freeze({
    crucible_start: VALID_START_ARGS,
    crucible_status: { investigation_id: "inv-abc123" },
    crucible_stop: { investigation_id: "inv-abc123" },
    crucible_result: { investigation_id: "inv-abc123" },
});

describe("crucible API registration", () => {
    it("registers exactly four tools and no hooks", () => {
        const registration = buildRegistration({ env: {}, log: () => {} });
        expect(Object.keys(registration)).toEqual(["tools"]);
        expect(registration.tools).toHaveLength(4);
        expect(registration.tools.map((tool) => tool.name)).toEqual([
            "crucible_start",
            "crucible_status",
            "crucible_stop",
            "crucible_result",
        ]);
        expect(registration.tools.map((tool) => tool.name)).toEqual([...PUBLIC_TOOL_NAMES]);
        // No hooks under any key.
        expect(registration).not.toHaveProperty("hooks");
        expect(registration).not.toHaveProperty("aliases");
        for (const tool of registration.tools) {
            expect(tool).not.toHaveProperty("aliases");
        }
    });

    it("keeps internal worker tools extension-inaccessible", () => {
        const names = buildRegistration({ env: {}, log: () => {} })
            .tools.map((tool) => tool.name);
        expect(names).not.toContain(SUBMIT_CANDIDATE_TOOL_NAME);
        expect(names).not.toContain(READ_PARENT_ARTIFACT_TOOL_NAME);
    });

    it("gives every tool a name, description, JSON Schema, and boundary handler", () => {
        const registration = buildRegistration({ env: {}, log: () => {} });
        const names = new Set();
        for (const tool of registration.tools) {
            expect(typeof tool.name).toBe("string");
            expect(typeof tool.description).toBe("string");
            expect(tool.description.length).toBeGreaterThan(0);
            expect(tool.parameters.type).toBe("object");
            expect(tool.parameters.additionalProperties).toBe(false);
            expect(typeof tool.handler).toBe("function");
            expect(names.has(tool.name)).toBe(false);
            expect(tool.description).toContain("Crucible");
            names.add(tool.name);
        }
        const generatedSurface = registration.tools.map((tool) => ({
            name: tool.name,
            description: tool.description,
            parameters: tool.parameters,
        }));
        expect(JSON.stringify(generatedSurface)).not.toMatch(/oracle/iu);
        const start = registration.tools.find(
            (tool) => tool.name === "crucible_start",
        );
        expect(start.parameters.oneOf[0].required)
            .toEqual(["experiment_id"]);
        expect(start.parameters.oneOf[0].properties)
            .not.toHaveProperty("objective");
        expect(start.description).toContain(
            "operator-preapproved experiment_id",
        );
        expect(registration.tools.find(
            (tool) => tool.name === "crucible_result",
        ).description).toContain("scientific readiness");
    });

    it("rejects unknown fields through every generated schema and handler", async () => {
        const deps = new Proxy({
            env: {},
            log: () => {},
        }, {
            get(target, property, receiver) {
                if (Reflect.has(target, property)) {
                    return Reflect.get(target, property, receiver);
                }
                throw new Error(
                    `runtime dependency ${String(property)} must not be read for invalid args`,
                );
            },
        });
        const registration = buildRegistration({ deps });

        for (const tool of registration.tools) {
            const result = await tool.handler({
                ...VALID_ARGS[tool.name],
                hidden_alias_argument: true,
            });
            expect(result.resultType).toBe("failure");
            expect(JSON.parse(result.textResultForLlm)).toMatchObject({
                ok: false,
                is_result: false,
                code: "CRUCIBLE_API_SCHEMA_INVALID",
                tool: tool.name,
            });
        }
    });

    it("enforces result-only disclosure at the generated boundary", async () => {
        const deps = { log: () => {} };
        const forbidden = [
            [crucibleStartSpec, VALID_START_ARGS],
            [crucibleStatusSpec, VALID_ARGS.crucible_status],
            [crucibleStopSpec, VALID_ARGS.crucible_stop],
        ];
        for (const [spec, args] of forbidden) {
            const result = await runToolBoundary(
                spec,
                () => ({
                    is_result: true,
                    decision: "VERIFIED_RESULT",
                    evidence_hash: `sha256:${"a".repeat(64)}`,
                }),
                args,
                deps,
            );
            expect(result.resultType).toBe("failure");
            expect(JSON.parse(result.textResultForLlm)).toMatchObject({
                ok: false,
                is_result: false,
                code: "CRUCIBLE_API_PUBLIC_PAYLOAD_INVARIANT",
                tool: spec.name,
            });
        }

        const nonterminalResultLeak = await runToolBoundary(
            crucibleResultSpec,
            () => Promise.resolve({
                is_result: false,
                statistical_summary: { estimate: 1 },
            }),
            VALID_ARGS.crucible_result,
            deps,
        );
        expect(nonterminalResultLeak.resultType).toBe("failure");
        expect(JSON.parse(nonterminalResultLeak.textResultForLlm)).toMatchObject({
            ok: false,
            is_result: false,
            code: "CRUCIBLE_API_PUBLIC_PAYLOAD_INVARIANT",
            tool: "crucible_result",
        });
    });

    it("converts asynchronous start preflight failures at the SDK boundary", async () => {
        const deps = { log: () => {} };
        const result = await runToolBoundary(
            crucibleStartSpec,
            () => Promise.reject(new SandboxUnavailableApiError("sandbox unavailable")),
            {
                ...VALID_START_ARGS,
            },
            deps,
        );
        expect(result.resultType).toBe("failure");
        expect(JSON.parse(result.textResultForLlm)).toMatchObject({
            ok: false,
            code: "CRUCIBLE_API_SANDBOX_UNAVAILABLE",
            tool: "crucible_start",
        });
    });

});
