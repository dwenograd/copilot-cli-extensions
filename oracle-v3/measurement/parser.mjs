// oracle-v3/measurement/parser.mjs
//
// Strict, bounded parser for a harness's single JSON result.
//
// The harness MUST write exactly one JSON value to stdout, followed only by
// optional trailing whitespace. Anything else — malformed JSON, extra
// trailing bytes, oversized output, a non-object top-level value, unknown
// top-level fields, non-finite metric numbers, wrong field types — is
// rejected with a typed ResultParseError. The parser NEVER coerces
// arguable-but-not-quite-schema output into "well, we'll accept that".

import {
    MEASUREMENT_ERROR_CODES,
    ResultParseError,
} from "./errors.mjs";
import { isAlgorithmTaggedSha256 } from "../domain/canonical.mjs";

export const PARSER_VERSION = "oracle-measurement-parser-v1";

// Absolute upper bound on parseable stdout, in bytes. This is a defensive
// second wall behind the per-entry maxStdoutBytes cap enforced during
// capture — even if a caller misconfigured the cap, we will not accept a
// pathologically large "JSON" input.
export const PARSER_MAX_INPUT_BYTES = 8 * 1024 * 1024;

const RESULT_ALLOWED_KEYS = new Set([
    "pass",
    "metrics",
    "validationCases",
    "searchSpaceExhausted",
    "impossibilityCertificateHash",
]);

// Names inside a metrics record must be safe identifiers so a caller cannot
// smuggle in exotic keys (empty string, whitespace, characters that break
// downstream JSON serialisation). Same policy as safe entry ids elsewhere.
const METRIC_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/u;
const VALIDATION_CASE_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/u;

function fail(code, message, details) {
    throw new ResultParseError(code, message, details);
}

function requireBoolean(value, field) {
    if (typeof value !== "boolean") {
        fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `${field} must be a boolean`, { got: typeof value });
    }
    return value;
}

function normalizeMetrics(metrics) {
    if (metrics === undefined) return null;
    if (metrics === null
        || typeof metrics !== "object"
        || Array.isArray(metrics)
        || Object.getPrototypeOf(metrics) !== Object.prototype) {
        fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, "metrics must be a plain object");
    }
    if (Object.getOwnPropertySymbols(metrics).length > 0) {
        fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, "metrics must not have symbol keys");
    }
    const keys = Object.keys(metrics);
    if (keys.length > 4096) {
        fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, "metrics has too many keys");
    }
    const out = {};
    for (const key of keys.sort()) {
        if (!METRIC_NAME.test(key)) {
            fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `metrics key ${JSON.stringify(key)} is not a safe identifier`);
        }
        const value = metrics[key];
        if (typeof value !== "number" || !Number.isFinite(value)) {
            fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `metrics.${key} must be a finite number`, {
                got: typeof value,
                stringified: value === undefined ? "undefined" : String(value),
            });
        }
        out[key] = value;
    }
    return out;
}

function normalizeValidationCases(validationCases) {
    if (validationCases === undefined) return null;
    if (validationCases === null
        || typeof validationCases !== "object"
        || Array.isArray(validationCases)
        || Object.getPrototypeOf(validationCases) !== Object.prototype) {
        fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, "validationCases must be a plain object");
    }
    const keys = Object.keys(validationCases);
    if (keys.length > 4096) {
        fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, "validationCases has too many keys");
    }
    const out = {};
    for (const key of keys.sort()) {
        if (!VALIDATION_CASE_NAME.test(key)) {
            fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `validationCases key ${JSON.stringify(key)} is not a safe id`);
        }
        const value = validationCases[key];
        if (typeof value !== "boolean") {
            fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `validationCases.${key} must be a boolean`, { got: typeof value });
        }
        out[key] = value;
    }
    return out;
}

// Parse `raw` (a UTF-8 string) as the harness's result document. Returns
// a fully normalised, frozen object with exactly the schema-allowed fields
// present.
export function parseHarnessResult(raw) {
    if (typeof raw !== "string") {
        fail(MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT ?? MEASUREMENT_ERROR_CODES.PARSE_MALFORMED, "parseHarnessResult input must be a string");
    }
    // Byte-length guard: UTF-8 encoded byte count is always >= character
    // count, so using Buffer.byteLength gives the true wire size.
    const byteLength = Buffer.byteLength(raw, "utf8");
    if (byteLength > PARSER_MAX_INPUT_BYTES) {
        fail(
            MEASUREMENT_ERROR_CODES.PARSE_OVERSIZED,
            `harness result exceeds parser maximum of ${PARSER_MAX_INPUT_BYTES} bytes`,
            { bytes: byteLength },
        );
    }

    // A completely empty (or whitespace-only) result is a distinct failure
    // from a malformed one; we want to distinguish "harness produced nothing"
    // from "harness produced garbage".
    const trimmed = raw.trimStart();
    if (trimmed.length === 0) {
        fail(MEASUREMENT_ERROR_CODES.PARSE_EMPTY, "harness produced no JSON output");
    }

    // We must accept only ONE JSON value plus optional trailing whitespace.
    // JSON.parse alone will happily consume "{}garbage" as "{}" — no it
    // won't, JSON.parse throws on trailing content. But it will accept
    // "{}\n{}" as an error too. Either way, to make the error message
    // precise we do a manual boundary scan first.
    //
    // Strategy: attempt JSON.parse on the full string. If it succeeds,
    // we're done. If it fails, we do NOT retry with a truncated view —
    // that would let a caller sneak trailing junk past us. Instead we
    // report PARSE_TRAILING if the first character before the failure
    // point is the end of a syntactically valid JSON value; otherwise
    // PARSE_MALFORMED.
    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (parseErr) {
        // Detect trailing-garbage-after-valid-JSON: try to parse only the
        // longest prefix that JSON accepts. This is a diagnostic aid only —
        // whether the trailing bytes are whitespace or something else, we
        // still refuse the result.
        const boundary = findJsonValueBoundary(raw);
        if (boundary > 0) {
            // Whatever comes after the boundary must be whitespace only for
            // the whole input to be accepted.
            const tail = raw.slice(boundary);
            if (/^\s*$/u.test(tail)) {
                // JSON.parse should have accepted this — retry to surface
                // any parser-specific quirk.
                try {
                    parsed = JSON.parse(raw.slice(0, boundary));
                } catch (innerErr) {
                    fail(
                        MEASUREMENT_ERROR_CODES.PARSE_MALFORMED,
                        `harness result is not valid JSON: ${innerErr?.message ?? String(innerErr)}`,
                    );
                }
            } else {
                fail(
                    MEASUREMENT_ERROR_CODES.PARSE_TRAILING,
                    "harness result contains trailing non-whitespace after the JSON value",
                    { trailing: truncateForError(tail) },
                );
            }
        } else {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_MALFORMED,
                `harness result is not valid JSON: ${parseErr?.message ?? String(parseErr)}`,
            );
        }
    }

    // Even on successful JSON.parse, verify there was no trailing content
    // (JSON.parse rejects trailing tokens but accepts trailing whitespace).
    // We enforce whitespace-only tails as our contract.
    // (JSON.parse itself already enforces this — comment kept for clarity.)

    if (parsed === null
        || typeof parsed !== "object"
        || Array.isArray(parsed)
        || Object.getPrototypeOf(parsed) !== Object.prototype) {
        fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, "harness result must be a plain JSON object");
    }
    for (const key of Object.keys(parsed)) {
        if (!RESULT_ALLOWED_KEYS.has(key)) {
            fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `unknown top-level result field ${JSON.stringify(key)}`, {
                allowed: [...RESULT_ALLOWED_KEYS],
            });
        }
    }

    const pass = requireBoolean(parsed.pass, "pass");
    const metrics = normalizeMetrics(parsed.metrics);
    const validationCases = normalizeValidationCases(parsed.validationCases);

    let searchSpaceExhausted = null;
    if (parsed.searchSpaceExhausted !== undefined) {
        searchSpaceExhausted = requireBoolean(parsed.searchSpaceExhausted, "searchSpaceExhausted");
    }

    let impossibilityCertificateHash = null;
    if (parsed.impossibilityCertificateHash !== undefined) {
        if (typeof parsed.impossibilityCertificateHash !== "string"
            || !isAlgorithmTaggedSha256(parsed.impossibilityCertificateHash)) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                "impossibilityCertificateHash must be an algorithm-tagged SHA-256 string",
            );
        }
        impossibilityCertificateHash = parsed.impossibilityCertificateHash;
    }

    // Build a canonical, frozen result object with fields in a fixed key
    // order — always the same keys present, never-present keys explicitly
    // null. This means a downstream canonical-JSON hash over the parsed
    // result is stable across harnesses that omit optional fields.
    const normalized = Object.freeze({
        pass,
        metrics,
        validationCases,
        searchSpaceExhausted,
        impossibilityCertificateHash,
        parserVersion: PARSER_VERSION,
    });
    return normalized;
}

// Return the character index at which a valid JSON value in `raw` ends
// (i.e., the exclusive-end offset of the longest prefix of `raw` that is
// itself valid JSON). Returns 0 if no valid prefix exists. This is a
// linear-time scanner limited to the value grammar we care about; it is
// used only to distinguish PARSE_TRAILING from PARSE_MALFORMED for a
// better error message.
function findJsonValueBoundary(raw) {
    // Skip leading whitespace.
    let i = 0;
    while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
    if (i >= raw.length) return 0;
    const start = i;
    try {
        i = scanValue(raw, i);
    } catch {
        return 0;
    }
    // Return exclusive end offset of the scanned value.
    return i > start ? i : 0;
}

function isWs(cc) {
    return cc === 0x20 || cc === 0x09 || cc === 0x0a || cc === 0x0d;
}

function scanValue(raw, i) {
    const cc = raw.charCodeAt(i);
    if (cc === 0x7b /* { */) return scanObject(raw, i);
    if (cc === 0x5b /* [ */) return scanArray(raw, i);
    if (cc === 0x22 /* " */) return scanString(raw, i);
    if (cc === 0x74 /* t */) return scanLiteral(raw, i, "true");
    if (cc === 0x66 /* f */) return scanLiteral(raw, i, "false");
    if (cc === 0x6e /* n */) return scanLiteral(raw, i, "null");
    if (cc === 0x2d /* - */ || (cc >= 0x30 && cc <= 0x39)) return scanNumber(raw, i);
    throw new Error("bad value");
}

function scanLiteral(raw, i, lit) {
    if (raw.slice(i, i + lit.length) !== lit) throw new Error("bad literal");
    return i + lit.length;
}

function scanString(raw, i) {
    if (raw.charCodeAt(i) !== 0x22) throw new Error("bad string");
    i += 1;
    while (i < raw.length) {
        const cc = raw.charCodeAt(i);
        if (cc === 0x22) return i + 1;
        if (cc === 0x5c) {
            i += 2;
            continue;
        }
        i += 1;
    }
    throw new Error("unterminated string");
}

function scanNumber(raw, i) {
    // Grammar approx: -?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?
    if (raw.charCodeAt(i) === 0x2d) i += 1;
    while (i < raw.length) {
        const cc = raw.charCodeAt(i);
        if (cc >= 0x30 && cc <= 0x39) { i += 1; continue; }
        break;
    }
    if (raw.charCodeAt(i) === 0x2e /* . */) {
        i += 1;
        while (i < raw.length) {
            const cc = raw.charCodeAt(i);
            if (cc >= 0x30 && cc <= 0x39) { i += 1; continue; }
            break;
        }
    }
    if (raw.charCodeAt(i) === 0x65 || raw.charCodeAt(i) === 0x45) {
        i += 1;
        if (raw.charCodeAt(i) === 0x2b || raw.charCodeAt(i) === 0x2d) i += 1;
        while (i < raw.length) {
            const cc = raw.charCodeAt(i);
            if (cc >= 0x30 && cc <= 0x39) { i += 1; continue; }
            break;
        }
    }
    return i;
}

function scanArray(raw, i) {
    i += 1;
    while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
    if (raw.charCodeAt(i) === 0x5d) return i + 1;
    // eslint-disable-next-line no-constant-condition
    while (true) {
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        i = scanValue(raw, i);
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        const cc = raw.charCodeAt(i);
        if (cc === 0x5d) return i + 1;
        if (cc !== 0x2c) throw new Error("bad array");
        i += 1;
    }
}

function scanObject(raw, i) {
    i += 1;
    while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
    if (raw.charCodeAt(i) === 0x7d) return i + 1;
    // eslint-disable-next-line no-constant-condition
    while (true) {
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        i = scanString(raw, i);
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        if (raw.charCodeAt(i) !== 0x3a) throw new Error("bad object");
        i += 1;
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        i = scanValue(raw, i);
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        const cc = raw.charCodeAt(i);
        if (cc === 0x7d) return i + 1;
        if (cc !== 0x2c) throw new Error("bad object");
        i += 1;
    }
}

function truncateForError(s) {
    const limit = 80;
    if (s.length <= limit) return s;
    return `${s.slice(0, limit)}... (+${s.length - limit} more bytes)`;
}
