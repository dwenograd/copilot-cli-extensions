import { describe, expect, it } from "vitest";

import {
    DEFAULT_WORKING_SET_POLICY,
    diagnosticOriginalDeletionAllowed,
    normalizeWorkingSetPolicy,
} from "../domain/index.mjs";

function policy(overrides = {}) {
    return {
        ...structuredClone(DEFAULT_WORKING_SET_POLICY),
        ...overrides,
        diagnosticRetention: {
            ...structuredClone(
                DEFAULT_WORKING_SET_POLICY.diagnosticRetention,
            ),
            ...(overrides.diagnosticRetention ?? {}),
        },
    };
}

describe("frozen working-set policy", () => {
    it("normalizes byte, checkpoint, segment, and retention thresholds", () => {
        expect(normalizeWorkingSetPolicy(DEFAULT_WORKING_SET_POLICY))
            .toEqual(DEFAULT_WORKING_SET_POLICY);
        expect(() => normalizeWorkingSetPolicy(policy({
            terminalReserveBytes:
                DEFAULT_WORKING_SET_POLICY.perInvestigationBytes,
        }))).toThrow(/reserved storage/u);
        expect(() => normalizeWorkingSetPolicy(policy({
            diagnosticRetention: {
                mode: "sealed_rollup",
                nonAuthoritativeContentTypes: [],
            },
        }))).toThrow(/explicit non-authoritative/u);
    });

    it("allows diagnostic deletion only after every frozen safety predicate", () => {
        const retention = policy({
            diagnosticRetention: {
                mode: "sealed_rollup",
                maxOriginalAgeMs: 60_000,
                maxOriginalBytes: 1_000,
                nonAuthoritativeContentTypes: [
                    "application/vnd.crucible.runtime-diagnostic+json",
                ],
                bundleRequiredContentTypes: [
                    "application/vnd.crucible.measurement-receipt+json",
                ],
            },
        });
        const safe = {
            contentType:
                "application/vnd.crucible.runtime-diagnostic+json",
            authoritative: false,
            bundleRequired: false,
            sealedSummary: true,
        };
        expect(diagnosticOriginalDeletionAllowed(retention, safe)).toBe(true);
        for (const unsafe of [
            { ...safe, authoritative: true },
            { ...safe, bundleRequired: true },
            { ...safe, sealedSummary: false },
            {
                ...safe,
                contentType:
                    "application/vnd.crucible.measurement-receipt+json",
            },
        ]) {
            expect(diagnosticOriginalDeletionAllowed(retention, unsafe))
                .toBe(false);
        }
        expect(diagnosticOriginalDeletionAllowed(
            DEFAULT_WORKING_SET_POLICY,
            safe,
        )).toBe(false);
    });
});
