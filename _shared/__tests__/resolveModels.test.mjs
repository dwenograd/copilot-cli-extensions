import { describe, expect, it } from "vitest";
import { resolveModels, renderSubstitutionNote } from "../resolveModels.mjs";

describe("resolveModels", () => {
    it("returns available requested models unchanged with no substitutions", () => {
        const result = resolveModels(["claude-opus-4.7", "gpt-5.5"], {
            deprecated: new Set(),
            fallbackMap: {},
        });

        expect(result).toEqual({
            models: ["claude-opus-4.7", "gpt-5.5"],
            substitutions: [],
        });
    });

    it("substitutes a deprecated default model via its fallback chain", () => {
        const result = resolveModels(["deprecated-model", "available-model"], {
            deprecated: new Set(["deprecated-model"]),
            fallbackMap: {
                "deprecated-model": ["replacement-model", "second-choice"],
            },
        });

        expect(result.models).toEqual(["replacement-model", "available-model"]);
        expect(result.substitutions).toEqual([
            {
                requested: "deprecated-model",
                used: "replacement-model",
                reason: "deprecated-model is in KNOWN_DEPRECATED_MODELS; substituted with replacement-model",
            },
        ]);
    });

    it("returns the original model and records no-fallback reason when the chain is exhausted", () => {
        const result = resolveModels(["deprecated-model"], {
            deprecated: new Set(["deprecated-model", "also-deprecated"]),
            fallbackMap: {
                "deprecated-model": ["also-deprecated"],
            },
        });

        expect(result.models).toEqual(["deprecated-model"]);
        expect(result.substitutions).toEqual([
            {
                requested: "deprecated-model",
                used: "deprecated-model",
                reason: "no fallback available — proceeding with deprecated model",
            },
        ]);
    });

    it("honors user overrides without substituting deprecated models", () => {
        const result = resolveModels(["deprecated-model"], {
            isUserOverride: true,
            deprecated: new Set(["deprecated-model"]),
            fallbackMap: {
                "deprecated-model": ["replacement-model"],
            },
        });

        expect(result).toEqual({
            models: ["deprecated-model"],
            substitutions: [],
        });
    });

    it("trims whitespace in requested model IDs", () => {
        const result = resolveModels(["  model-a  ", "\tmodel-b\n"], {
            deprecated: new Set(),
            fallbackMap: {},
        });

        expect(result.models).toEqual(["model-a", "model-b"]);
        expect(result.substitutions).toEqual([]);
    });
});

describe("renderSubstitutionNote", () => {
    it("returns an empty string when there are no substitutions", () => {
        expect(renderSubstitutionNote([])).toBe("");
    });

    it("renders a note containing the substitution arrow", () => {
        const note = renderSubstitutionNote([
            {
                requested: "deprecated-model",
                used: "replacement-model",
                reason: "deprecated-model is in KNOWN_DEPRECATED_MODELS; substituted with replacement-model",
            },
        ]);

        expect(note).toContain("Note:");
        expect(note).toContain("deprecated-model → replacement-model");
    });

    it("includes a role prefix when the substitution carries a `role` tag", () => {
        // duck-council stamps each substitution with the role it came from so
        // the user can tell which of two same-default roles got demoted. The
        // existing positional-trio callers don't tag, so the prefix is
        // omitted in the no-role case (preserves backward compat).
        const note = renderSubstitutionNote([
            {
                role: "security",
                requested: "claude-opus-4.7-xhigh",
                used: "claude-opus-4.7-high",
                reason: "claude-opus-4.7-xhigh is in KNOWN_DEPRECATED_MODELS; substituted with claude-opus-4.7-high",
            },
            {
                role: "stability",
                requested: "claude-opus-4.7-xhigh",
                used: "claude-opus-4.7-high",
                reason: "claude-opus-4.7-xhigh is in KNOWN_DEPRECATED_MODELS; substituted with claude-opus-4.7-high",
            },
        ]);

        expect(note).toContain("security: claude-opus-4.7-xhigh → claude-opus-4.7-high");
        expect(note).toContain("stability: claude-opus-4.7-xhigh → claude-opus-4.7-high");
    });
});

describe("resolveModels per-role isUserOverride pattern (duck-council loop)", () => {
    // Mirrors the per-role loop in duck-council/handler.mjs. Without this
    // direct unit test, the handler's per-role `isUserOverride: input.roles?.[role] !== undefined`
    // plumbing has no coverage that's sensitive to the boolean — every council
    // default model is in `KNOWN_DEPRECATED_MODELS`-free territory today, so a
    // regression that always passed `isUserOverride: false` would silently
    // pass every existing handler/integration test.
    const fakeDeprecated = new Set(["dep-model"]);
    const fakeFallbackMap = { "dep-model": ["safe-model"] };

    it("substitutes a default-supplied deprecated model (isUserOverride=false)", () => {
        const r = resolveModels(["dep-model"], {
            isUserOverride: false,
            deprecated: fakeDeprecated,
            fallbackMap: fakeFallbackMap,
        });
        expect(r.models).toEqual(["safe-model"]);
        expect(r.substitutions).toHaveLength(1);
    });

    it("preserves a user-supplied deprecated model (isUserOverride=true)", () => {
        const r = resolveModels(["dep-model"], {
            isUserOverride: true,
            deprecated: fakeDeprecated,
            fallbackMap: fakeFallbackMap,
        });
        expect(r.models).toEqual(["dep-model"]);
        expect(r.substitutions).toEqual([]);
    });

    it("council-style loop substitutes only the role that wasn't user-overridden", () => {
        // Simulate two council roles with the same deprecated default — one
        // user-overrode the role explicitly to the same id, the other did
        // not. resolveModels must honor the override per-role.
        const userOverrides = { security: undefined, stability: "dep-model" };
        const baseAssignment = { security: "dep-model", stability: "dep-model" };

        const results = {};
        for (const role of ["security", "stability"]) {
            const isThisRoleUserOverride = userOverrides[role] !== undefined;
            const requested = userOverrides[role] ?? baseAssignment[role];
            results[role] = resolveModels([requested], {
                isUserOverride: isThisRoleUserOverride,
                deprecated: fakeDeprecated,
                fallbackMap: fakeFallbackMap,
            });
        }

        // security: default-supplied, deprecated → substituted to safe-model.
        expect(results.security.models).toEqual(["safe-model"]);
        expect(results.security.substitutions).toHaveLength(1);
        // stability: user-supplied, deprecated → preserved verbatim.
        expect(results.stability.models).toEqual(["dep-model"]);
        expect(results.stability.substitutions).toEqual([]);
    });
});
