import { describe, expect, it } from "vitest";

import {
    MEASUREMENT_ERROR_CODES,
    PARSER_MAX_INPUT_BYTES,
    PARSER_VERSION,
    parseHarnessResult,
} from "../measurement/index.mjs";

function parseError(raw) {
    try {
        parseHarnessResult(raw);
    } catch (error) {
        return error;
    }
    throw new Error("expected parseHarnessResult to throw");
}

describe("parseHarnessResult", () => {
    it("normalizes and deeply freezes a complete result", () => {
        const certificate =
            `sha256:crucible-impossibility-v1:${"a".repeat(64)}`;
        const result = parseHarnessResult(JSON.stringify({
            pass: false,
            metrics: { latencyMs: 42.5, throughput: 1000, exact: 0 },
            observables: { category: "good", converged: true, ratio: 0.5 },
            validationCases: { "case-a": true, "case-b": false },
            searchSpaceExhausted: true,
            impossibilityCertificateHash: certificate,
        }));

        expect(result).toEqual({
            pass: false,
            metrics: { exact: 0, latencyMs: 42.5, throughput: 1000 },
            observables: { category: "good", converged: true, ratio: 0.5 },
            validationCases: { "case-a": true, "case-b": false },
            searchSpaceExhausted: true,
            impossibilityCertificateHash: certificate,
            role: null,
            phase: null,
            replicateIndex: null,
            blockIndex: null,
            armIndex: null,
            armId: null,
            deterministicSeed: null,
            subjectId: null,
            environmentIdentity: null,
            suiteIdentity: null,
            parserVersion: PARSER_VERSION,
        });
        expect(Object.isFrozen(result)).toBe(true);
        expect(Object.isFrozen(result.metrics)).toBe(true);
        expect(Object.isFrozen(result.observables)).toBe(true);
        expect(Object.isFrozen(result.validationCases)).toBe(true);
        expect(() => {
            result.metrics.exact = 1;
        }).toThrow(TypeError);
        expect(() => {
            result.validationCases["case-a"] = false;
        }).toThrow(TypeError);
        expect(() => {
            result.observables.category = "bad";
        }).toThrow(TypeError);
    });

    it("accepts the minimal result with surrounding whitespace", () => {
        const result = parseHarnessResult(' \n{"pass":true}\r\n\t');
        expect(result).toEqual({
            pass: true,
            metrics: null,
            observables: null,
            validationCases: null,
            searchSpaceExhausted: null,
            impossibilityCertificateHash: null,
            role: null,
            phase: null,
            replicateIndex: null,
            blockIndex: null,
            armIndex: null,
            armId: null,
            deterministicSeed: null,
            subjectId: null,
            environmentIdentity: null,
            suiteIdentity: null,
            parserVersion: PARSER_VERSION,
        });
    });

    it("uses exact empty, malformed, and trailing error codes", () => {
        for (const raw of ["", " \r\n\t"]) {
            expect(parseError(raw).code)
                .toBe(MEASUREMENT_ERROR_CODES.PARSE_EMPTY);
        }
        for (const raw of [
            '{"pass":',
            "{,}",
            "not-json-at-all",
            "01",
            '{"pass":tru}',
        ]) {
            expect(parseError(raw).code)
                .toBe(MEASUREMENT_ERROR_CODES.PARSE_MALFORMED);
        }
        for (const raw of [
            '"just a string"garbage',
            '{"pass":true} extra',
            '{"pass":true}{}',
            '{"pass":true} 123',
        ]) {
            expect(parseError(raw).code)
                .toBe(MEASUREMENT_ERROR_CODES.PARSE_TRAILING);
        }
    });

    it("rejects duplicate keys, including escaped and nested duplicates", () => {
        for (const raw of [
            '{"pass":true,"pass":false}',
            '{"pass":true,"\\u0070ass":false}',
            '{"pass":true,"metrics":{"count":1,"count":2}}',
            '{"pass":true,"observables":{"outcome":"a","outcome":"b"}}',
            '{"pass":true,"validationCases":{"case-a":true,"case-a":false}}',
        ]) {
            const error = parseError(raw);
            expect(error.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
            expect(error.message).toMatch(/duplicate JSON object key/u);
        }
    });

    it("rejects prototype-mutating record keys", () => {
        for (const raw of [
            '{"pass":true,"metrics":{"__proto__":1}}',
            '{"pass":true,"metrics":{"constructor":1}}',
            '{"pass":true,"observables":{"__proto__":"bad"}}',
            '{"pass":true,"validationCases":{"prototype":true}}',
        ]) {
            expect(parseError(raw).code)
                .toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
        }
    });

    it("rejects schema violations with PARSE_SCHEMA", () => {
        for (const raw of [
            "true",
            "123",
            '"str"',
            "null",
            '[{"pass":true}]',
            "{}",
            '{"pass":"true"}',
            '{"pass":true,"metadata":{}}',
            '{"pass":true,"metrics":{"x":"1.0"}}',
            '{"pass":true,"metrics":{"":0}}',
            '{"pass":true,"metrics":{"a":true}}',
            '{"pass":true,"observables":{"outcome":null}}',
            '{"pass":true,"observables":{"outcome":""}}',
            '{"pass":true,"metrics":{"score":1},"observables":{"score":1}}',
            '{"pass":true,"validationCases":{"good":1}}',
            '{"pass":true,"searchSpaceExhausted":"yes"}',
            '{"pass":true,"impossibilityCertificateHash":"abcd"}',
            '{"pass":true,"päss":false}',
        ]) {
            expect(parseError(raw).code)
                .toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
        }
    });

    it("measures the parser cap in UTF-8 bytes, not JavaScript characters", () => {
        const prefix = '{"pass":true,"unknown":"';
        const suffix = '"}';
        const remaining = PARSER_MAX_INPUT_BYTES
            - Buffer.byteLength(prefix + suffix, "utf8");
        const multibyte = "é".repeat(Math.floor(remaining / 2) + 1);
        const raw = `${prefix}${multibyte}${suffix}`;

        expect(raw.length).toBeLessThan(PARSER_MAX_INPUT_BYTES);
        expect(Buffer.byteLength(raw, "utf8"))
            .toBeGreaterThan(PARSER_MAX_INPUT_BYTES);
        expect(parseError(raw).code)
            .toBe(MEASUREMENT_ERROR_CODES.PARSE_OVERSIZED);
    });

    it("rejects non-string input with INVALID_ARGUMENT", () => {
        expect(parseError(Buffer.from('{"pass":true}')).code)
            .toBe(MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT);
    });

    it("binds suite role metadata and rejects mismatched or role-inappropriate fields", () => {
        const binding = {
            role: "confirmation",
            phase: "confirmation",
            replicateIndex: 2,
            blockIndex: 5,
            armIndex: 0,
            armId: "candidate",
            deterministicSeed: "seed-confirm-2",
            subjectId: "candidate-7",
            environmentIdentity:
                `sha256:crucible-harness-environment-v4:${"a".repeat(64)}`,
            suiteIdentity:
                `sha256:crucible-harness-suite-v4:${"b".repeat(64)}`,
        };
        const parsed = parseHarnessResult(JSON.stringify({
            pass: true,
            metrics: { score: 4 },
            ...binding,
        }), { expectedBinding: binding });
        expect(parsed).toMatchObject(binding);

        expect(() => parseHarnessResult(JSON.stringify({
            pass: true,
            ...binding,
            subjectId: "candidate-8",
        }), { expectedBinding: binding })).toThrow(expect.objectContaining({
            code: MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
        }));

        expect(parseError(JSON.stringify({
            pass: true,
            role: "search",
            phase: "search",
            replicateIndex: 0,
            blockIndex: 1,
            armIndex: 0,
            deterministicSeed: "seed",
            subjectId: "candidate-1",
            environmentIdentity: binding.environmentIdentity,
            suiteIdentity: binding.suiteIdentity,
        })).code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);

        expect(parseError(JSON.stringify({
            pass: false,
            searchSpaceExhausted: true,
            role: "challenge",
            phase: "challenge",
            replicateIndex: 0,
            blockIndex: 0,
            deterministicSeed: "seed",
            subjectId: "candidate-1",
            environmentIdentity: binding.environmentIdentity,
            suiteIdentity: binding.suiteIdentity,
        })).code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
    });
});
