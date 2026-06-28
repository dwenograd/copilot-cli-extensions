import { describe, expect, it } from "vitest";
import {
    LONG_CONTEXT_TIER,
    SPAWN_ALIASES,
    resolveSpawnSpec,
    renderSpawnArgs,
    displayModel,
    displayModels,
} from "../spawnSpec.mjs";

describe("resolveSpawnSpec", () => {
    it("passes a real base model ID through untouched (with global long context)", () => {
        expect(resolveSpawnSpec("claude-opus-4.8")).toEqual({
            model: "claude-opus-4.8",
            effort: null,
            context: LONG_CONTEXT_TIER,
        });
    });

    it("does NOT treat mai-code-1-flash-internal as an alias (its -internal is real)", () => {
        expect(resolveSpawnSpec("mai-code-1-flash-internal")).toEqual({
            model: "mai-code-1-flash-internal",
            effort: null,
            context: LONG_CONTEXT_TIER,
        });
    });

    it("maps a 1M-context alias to its base model (context is global, not per-alias)", () => {
        expect(resolveSpawnSpec("claude-opus-4.7-1m-internal")).toEqual({
            model: "claude-opus-4.7",
            effort: null,
            context: LONG_CONTEXT_TIER,
        });
        expect(resolveSpawnSpec("claude-opus-4.6-1m")).toEqual({
            model: "claude-opus-4.6",
            effort: null,
            context: LONG_CONTEXT_TIER,
        });
    });

    it("maps an effort alias to base model + reasoning effort", () => {
        expect(resolveSpawnSpec("claude-opus-4.7-xhigh")).toEqual({
            model: "claude-opus-4.7",
            effort: "xhigh",
            context: LONG_CONTEXT_TIER,
        });
        expect(resolveSpawnSpec("claude-opus-4.7-high")).toEqual({
            model: "claude-opus-4.7",
            effort: "high",
            context: LONG_CONTEXT_TIER,
        });
    });

    it("trims whitespace", () => {
        expect(resolveSpawnSpec("  claude-opus-4.8  ").model).toBe("claude-opus-4.8");
    });
});

describe("displayModel / displayModels — clean user-facing names", () => {
    it("collapses a context-window alias to its base model name", () => {
        expect(displayModel("claude-opus-4.7-1m-internal")).toBe("claude-opus-4.7");
        expect(displayModel("claude-opus-4.6-1m")).toBe("claude-opus-4.6");
    });

    it("keeps effort aliases intact (reasoning tier is meaningful to show)", () => {
        expect(displayModel("claude-opus-4.7-xhigh")).toBe("claude-opus-4.7-xhigh");
        expect(displayModel("claude-opus-4.7-high")).toBe("claude-opus-4.7-high");
    });

    it("passes real base IDs (including genuine -internal names) through untouched", () => {
        expect(displayModel("claude-opus-4.8")).toBe("claude-opus-4.8");
        expect(displayModel("gpt-5.5")).toBe("gpt-5.5");
        expect(displayModel("mai-code-1-flash-internal")).toBe("mai-code-1-flash-internal");
    });

    it("never surfaces a context-window (-1m) alias suffix", () => {
        for (const [alias, spec] of Object.entries(SPAWN_ALIASES)) {
            if (!spec.effort) {
                expect(displayModel(alias)).not.toContain("-internal");
                expect(displayModel(alias)).not.toMatch(/-1m\b/);
            }
        }
    });

    it("maps a whole trio for a banner line", () => {
        expect(
            displayModels(["claude-opus-4.8", "claude-opus-4.7-1m-internal", "gpt-5.5"]),
        ).toEqual(["claude-opus-4.8", "claude-opus-4.7", "gpt-5.5"]);
    });
});

describe("renderSpawnArgs", () => {
    it("renders a base model with the global context tier and no effort", () => {
        expect(renderSpawnArgs("gpt-5.5")).toBe(
            'model="gpt-5.5", context_tier="long_context"',
        );
    });

    it("renders a 1M alias as the base model + global context tier", () => {
        expect(renderSpawnArgs("claude-opus-4.7-1m-internal")).toBe(
            'model="claude-opus-4.7", context_tier="long_context"',
        );
    });

    it("renders an effort alias with reasoning_effort between model and context", () => {
        expect(renderSpawnArgs("claude-opus-4.7-xhigh")).toBe(
            'model="claude-opus-4.7", reasoning_effort="xhigh", context_tier="long_context"',
        );
    });

    it("never emits a suffixed (unavailable) model ID", () => {
        for (const alias of Object.keys(SPAWN_ALIASES)) {
            const rendered = renderSpawnArgs(alias);
            expect(rendered).not.toContain(`model="${alias}"`);
        }
    });
});

describe("renderSpawnArgs — elevated reasoning", () => {
    it("elevates an xhigh-capable model to xhigh on non-cheap spawns", () => {
        expect(renderSpawnArgs("claude-opus-4.8", { elevated: true })).toBe(
            'model="claude-opus-4.8", reasoning_effort="xhigh", context_tier="long_context"',
        );
        expect(renderSpawnArgs("gpt-5.5", { elevated: true })).toBe(
            'model="gpt-5.5", reasoning_effort="xhigh", context_tier="long_context"',
        );
    });

    it("does NOT elevate a model that lacks xhigh support", () => {
        // claude-opus-4.6 and claude-sonnet-4.6 are not in ELEVATED_EFFORT.
        expect(renderSpawnArgs("claude-opus-4.6", { elevated: true })).toBe(
            'model="claude-opus-4.6", context_tier="long_context"',
        );
        expect(renderSpawnArgs("claude-sonnet-4.6", { elevated: true })).toBe(
            'model="claude-sonnet-4.6", context_tier="long_context"',
        );
    });

    it("does not elevate when elevated is false/omitted (cheap spawns)", () => {
        expect(renderSpawnArgs("claude-opus-4.8")).toBe(
            'model="claude-opus-4.8", context_tier="long_context"',
        );
    });

    it("alias-pinned effort always wins over elevation", () => {
        expect(renderSpawnArgs("claude-opus-4.7-xhigh", { elevated: true })).toBe(
            'model="claude-opus-4.7", reasoning_effort="xhigh", context_tier="long_context"',
        );
        expect(renderSpawnArgs("claude-opus-4.7-high", { elevated: true })).toBe(
            'model="claude-opus-4.7", reasoning_effort="high", context_tier="long_context"',
        );
    });
});

describe("renderSpawnArgs — colon (object-literal) style", () => {
    it("emits model:/reasoning_effort:/context_tier: with colons", () => {
        expect(renderSpawnArgs("claude-opus-4.8", { elevated: true, colon: true })).toBe(
            'model:"claude-opus-4.8", reasoning_effort:"xhigh", context_tier:"long_context"',
        );
    });

    it("emits colon style without effort when not elevated", () => {
        expect(renderSpawnArgs("gpt-5.5", { colon: true })).toBe(
            'model:"gpt-5.5", context_tier:"long_context"',
        );
    });
});
