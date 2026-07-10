// crucible/__tests__/api-extension.test.mjs
//
// Registration/static test for the thin extension: the SDK registration payload
// exposes EXACTLY the four public tools and NO hooks, each tool carries a
// derived JSON Schema and a boundary handler, and the extension.mjs entrypoint
// stays thin (registration only) and never writes to stdout.

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildRegistration, runToolBoundary } from "../api/handlers.mjs";
import { PUBLIC_TOOL_NAMES, crucibleStartSpec } from "../api/schema.mjs";
import { SandboxUnavailableApiError } from "../api/errors.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXTENSION_PATH = path.join(HERE, "..", "extension.mjs");

describe("crucible thin extension registration", () => {
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
            names.add(tool.name);
        }
    });

    it("catches schema-invalid args at the boundary without touching runtime deps", () => {
        const trap = () => {
            throw new Error("runtime dependency must not be called for invalid args");
        };
        const deps = {
            env: {},
            log: () => {},
            isPidAlive: trap,
            loadHarnessAllowlist: trap,
            openRepository: trap,
            openArtifactStore: trap,
            createDomainRepositoryAdapter: trap,
            ensureSupervisor: trap,
            readStatus: trap,
            requestStop: trap,
            loadSupervisorConfig: trap,
        };
        const registration = buildRegistration({ deps });
        const statusTool = registration.tools.find((tool) => tool.name === "crucible_status");

        const result = statusTool.handler({});
        expect(result.resultType).toBe("failure");
        const parsed = JSON.parse(result.textResultForLlm);
        expect(parsed.ok).toBe(false);
        expect(parsed.is_result).toBe(false);
        expect(parsed.code).toBe("CRUCIBLE_API_SCHEMA_INVALID");
        expect(parsed.tool).toBe("crucible_status");
    });

    it("converts asynchronous start preflight failures at the SDK boundary", async () => {
        const deps = { log: () => {} };
        const result = await runToolBoundary(
            crucibleStartSpec,
            () => Promise.reject(new SandboxUnavailableApiError("sandbox unavailable")),
            {
                objective: "test objective",
                project_dir: "C:\\project",
                harness_id: "harness",
                acceptance_predicate: { kind: "harness_pass" },
                hypothesis_topology: "finite_enumerable",
                validation_cases: [
                    { id: "good", expectation: "accept", path: "cases/good" },
                    { id: "bad", expectation: "reject", path: "cases/bad" },
                ],
                worker_models: ["model-a"],
                candidates_per_round: 1,
                max_rounds: 1,
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

    it("keeps extension.mjs thin: registration only, no hooks, no stdout", () => {
        const source = fs.readFileSync(EXTENSION_PATH, "utf8");
        // Strip line comments so prose (e.g. the "NO hooks" note) does not trip
        // the code assertions below. The file uses only // comments.
        const code = source.replace(/\/\/.*$/gmu, "");
        // Imports the SDK join + the API registration builder.
        expect(source).toMatch(/joinSession/u);
        expect(source).toMatch(/buildRegistration/u);
        // The registration passed to joinSession comes solely from
        // buildRegistration (which is separately proven to expose no hooks).
        expect(code).toMatch(/joinSession\(\s*buildRegistration\(/u);
        // No hook registration of any kind in the executable code.
        expect(code).not.toMatch(/hooks/iu);
        expect(code).not.toMatch(/registerHook/iu);
        // Never writes to stdout/stderr directly; diagnostics go via session.log.
        expect(code).not.toMatch(/console\./u);
        expect(code).not.toMatch(/process\.stdout/u);
        expect(code).not.toMatch(/process\.stderr/u);
        // Thin: no inline tool objects (no `parameters:` literals here).
        expect(code).not.toMatch(/parameters\s*:/u);
    });
});
