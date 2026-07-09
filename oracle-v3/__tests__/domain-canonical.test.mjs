import { describe, expect, it } from "vitest";
import {
    CANONICAL_HASH_ALGORITHM,
    CanonicalizationError,
    canonicalJson,
    hashCanonical,
} from "../domain/index.mjs";

describe("Oracle v3 canonical JSON", () => {
    it("orders object keys recursively and produces algorithm-tagged SHA-256 hashes", () => {
        const left = {
            z: 1,
            a: {
                y: [3, { b: true, a: false }],
                x: "value",
            },
        };
        const right = {
            a: {
                x: "value",
                y: [3, { a: false, b: true }],
            },
            z: 1,
        };

        expect(canonicalJson(left)).toBe(
            '{"a":{"x":"value","y":[3,{"a":false,"b":true}]},"z":1}',
        );
        expect(canonicalJson(right)).toBe(canonicalJson(left));
        expect(hashCanonical(right)).toBe(hashCanonical(left));
        expect(hashCanonical(left)).toMatch(
            new RegExp(`^${CANONICAL_HASH_ALGORITHM}:[a-f0-9]{64}$`),
        );
    });

    it("fails closed for non-JSON and ambiguous values", () => {
        expect(() => canonicalJson({ bad: Number.NaN })).toThrow(CanonicalizationError);
        expect(() => canonicalJson({ bad: undefined })).toThrow(CanonicalizationError);
        expect(() => canonicalJson(new Date(0))).toThrow(CanonicalizationError);

        const sparse = [];
        sparse.length = 1;
        expect(() => canonicalJson(sparse)).toThrow(CanonicalizationError);
    });
});
