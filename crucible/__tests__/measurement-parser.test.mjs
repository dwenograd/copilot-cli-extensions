// crucible/__tests__/measurement-parser.test.mjs
//
// Verifies the strict JSON result parser rejects everything it should.

import { describe, it, expect } from "vitest";

import {
    MEASUREMENT_ERROR_CODES,
    PARSER_MAX_INPUT_BYTES,
    PARSER_VERSION,
    parseHarnessResult,
} from "../measurement/index.mjs";

function catchIt(fn) {
    try { fn(); } catch (e) { return e; }
    throw new Error("expected to throw");
}

describe("parseHarnessResult — happy paths", () => {
    it("accepts the minimal { pass: true } document", () => {
        const r = parseHarnessResult('{"pass":true}');
        expect(r.pass).toBe(true);
        expect(r.metrics).toBeNull();
        expect(r.validationCases).toBeNull();
        expect(r.searchSpaceExhausted).toBeNull();
        expect(r.impossibilityCertificateHash).toBeNull();
        expect(r.parserVersion).toBe(PARSER_VERSION);
    });

    it("accepts a full document with metrics, validation cases, exhaustion, certificate", () => {
        const doc = {
            pass: false,
            metrics: { latencyMs: 42.5, throughput: 1000, exact: 0 },
            validationCases: { "case-a": true, "case-b": false },
            searchSpaceExhausted: true,
            impossibilityCertificateHash: "sha256:crucible-impossibility-v1:" + "a".repeat(64),
        };
        const r = parseHarnessResult(JSON.stringify(doc));
        expect(r.pass).toBe(false);
        expect(r.metrics).toEqual({ exact: 0, latencyMs: 42.5, throughput: 1000 });
        expect(r.validationCases).toEqual({ "case-a": true, "case-b": false });
        expect(r.searchSpaceExhausted).toBe(true);
        expect(r.impossibilityCertificateHash).toBe(doc.impossibilityCertificateHash);
    });

    it("allows leading and trailing whitespace around the JSON value", () => {
        const r = parseHarnessResult('   \n{"pass":true}\r\n\t  ');
        expect(r.pass).toBe(true);
    });
});

describe("parseHarnessResult — schema violations", () => {
    it("rejects an empty or whitespace-only result as PARSE_EMPTY", () => {
        const err = catchIt(() => parseHarnessResult(""));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_EMPTY);
        const err2 = catchIt(() => parseHarnessResult("   \n\t "));
        expect(err2.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_EMPTY);
    });

    it("rejects malformed JSON as PARSE_MALFORMED", () => {
        for (const bad of ['{"pass":', '{,}', '"just a string"garbage', 'not-json-at-all']) {
            const err = catchIt(() => parseHarnessResult(bad));
            expect([
                MEASUREMENT_ERROR_CODES.PARSE_MALFORMED,
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                MEASUREMENT_ERROR_CODES.PARSE_TRAILING,
            ]).toContain(err.code);
        }
    });

    it("rejects trailing non-whitespace after a valid JSON value", () => {
        for (const bad of ['{"pass":true} extra', '{"pass":true}{}', '{"pass":true} 123']) {
            const err = catchIt(() => parseHarnessResult(bad));
            expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_TRAILING);
        }
    });

    it("rejects non-object top-level values", () => {
        for (const bad of ['true', '123', '"str"', 'null', '[{"pass":true}]']) {
            const err = catchIt(() => parseHarnessResult(bad));
            expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
        }
    });

    it("rejects unknown top-level fields", () => {
        const err = catchIt(() => parseHarnessResult('{"pass":true,"metadata":{}}'));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
    });

    it("rejects missing or wrong-typed pass field", () => {
        for (const bad of ['{}', '{"pass":"true"}', '{"pass":1}', '{"pass":null}']) {
            const err = catchIt(() => parseHarnessResult(bad));
            expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
        }
    });

    it("rejects non-finite metrics (Infinity/NaN cannot be represented in JSON but stringified numbers/booleans should also fail)", () => {
        // JSON has no NaN/Infinity literal — they parse as JSON syntax
        // errors. What the harness might actually emit is a string metric,
        // which we reject as non-number.
        const err1 = catchIt(() => parseHarnessResult('{"pass":true,"metrics":{"x":"1.0"}}'));
        expect(err1.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
        // A metric key that is not a safe identifier.
        const err2 = catchIt(() => parseHarnessResult('{"pass":true,"metrics":{"":0}}'));
        expect(err2.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
        // A non-finite via naive JSON isn't representable, but a bool
        // masquerading as a metric must still be rejected.
        const err3 = catchIt(() => parseHarnessResult('{"pass":true,"metrics":{"a":true}}'));
        expect(err3.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
    });

    it("rejects wrong-shape validationCases", () => {
        const err = catchIt(() => parseHarnessResult('{"pass":true,"validationCases":{"good":1}}'));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
    });

    it("rejects malformed impossibilityCertificateHash", () => {
        for (const bad of [
            '{"pass":true,"impossibilityCertificateHash":"abcd"}',
            '{"pass":true,"impossibilityCertificateHash":"sha1:x:abcd"}',
            '{"pass":true,"impossibilityCertificateHash":123}',
        ]) {
            const err = catchIt(() => parseHarnessResult(bad));
            expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
        }
    });

    it("rejects wrong-typed searchSpaceExhausted", () => {
        const err = catchIt(() => parseHarnessResult('{"pass":true,"searchSpaceExhausted":"yes"}'));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
    });

    it("rejects oversized input", () => {
        // Build a valid-ish JSON string larger than the parser cap.
        const filler = "x".repeat(PARSER_MAX_INPUT_BYTES + 100);
        const doc = `{"pass":true,"impossibilityCertificateHash":"sha256:t:${"a".repeat(64)}","fill":"${filler}"}`;
        const err = catchIt(() => parseHarnessResult(doc));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_OVERSIZED);
    });
});
