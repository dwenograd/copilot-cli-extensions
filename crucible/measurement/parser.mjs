// crucible/measurement/parser.mjs
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

export const PARSER_VERSION = "crucible-measurement-parser-v2";

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
    "role",
    "phase",
    "replicateIndex",
    "blockIndex",
    "deterministicSeed",
    "subjectId",
    "environmentIdentity",
    "suiteIdentity",
]);

// Names inside a metrics record must be safe identifiers so a caller cannot
// smuggle in exotic keys (empty string, whitespace, characters that break
// downstream JSON serialisation). Same policy as safe entry ids elsewhere.
const METRIC_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/u;
const VALIDATION_CASE_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const SAFE_SUBJECT_ID = /^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$/u;
const BINDING_KEYS = Object.freeze([
    "role",
    "phase",
    "replicateIndex",
    "blockIndex",
    "deterministicSeed",
    "subjectId",
    "environmentIdentity",
    "suiteIdentity",
]);
const BINDING_KEY_SET = new Set(BINDING_KEYS);
const ROLE_BINDING_RULES = Object.freeze({
    calibration: Object.freeze({
        phase: "calibration",
        replicateIndex: "forbidden",
        blockIndex: "forbidden",
    }),
    search: Object.freeze({
        phase: "search",
        replicateIndex: "forbidden",
        blockIndex: "required",
    }),
    confirmation: Object.freeze({
        phase: "confirmation",
        replicateIndex: "required",
        blockIndex: "required",
    }),
    challenge: Object.freeze({
        phase: "challenge",
        replicateIndex: "required",
        blockIndex: "required",
    }),
    novelty: Object.freeze({
        phase: "novelty",
        replicateIndex: "required",
        blockIndex: "required",
    }),
    impossibility_verifier: Object.freeze({
        phase: "impossibility_verification",
        replicateIndex: "forbidden",
        blockIndex: "forbidden",
    }),
});
const FORBIDDEN_RECORD_KEYS = new Set([
    "__proto__",
    "constructor",
    "prototype",
]);

class DuplicateJsonKeyError extends Error {
    constructor(key) {
        super(`duplicate JSON object key ${JSON.stringify(key)}`);
        this.key = key;
    }
}

function fail(code, message, details) {
    throw new ResultParseError(code, message, details);
}

function requireBoolean(value, field) {
    if (typeof value !== "boolean") {
        fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `${field} must be a boolean`, { got: typeof value });
    }
    return value;
}

function requireBindingString(value, field, maxLength = 256) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > maxLength
        || value.includes("\0")) {
        fail(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            `${field} must be a non-empty string <= ${maxLength} characters`,
        );
    }
    return value;
}

function normalizeBindingIndex(value, field, rule) {
    if (rule === "forbidden") {
        if (value !== undefined && value !== null) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                `${field} is not valid for this harness role`,
            );
        }
        return null;
    }
    if (!Number.isSafeInteger(value) || value < 0) {
        fail(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            `${field} must be a non-negative safe integer`,
        );
    }
    return value;
}

function normalizeBindingObject(value, {
    field = "measurement binding",
    required = false,
    rejectUnknown = false,
} = {}) {
    if (value === null || value === undefined) {
        if (required) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                `${field} is required`,
            );
        }
        return null;
    }
    if (typeof value !== "object"
        || Array.isArray(value)
        || Object.getPrototypeOf(value) !== Object.prototype) {
        fail(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            `${field} must be a plain object`,
        );
    }
    if (rejectUnknown) {
        for (const key of Object.keys(value)) {
            if (!BINDING_KEY_SET.has(key)) {
                fail(
                    MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                    `${field} has unknown field ${JSON.stringify(key)}`,
                );
            }
        }
    }
    const present = BINDING_KEYS.filter((key) =>
        value[key] !== undefined && value[key] !== null);
    if (present.length === 0) {
        if (required) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                `${field} is required`,
            );
        }
        return null;
    }

    const role = requireBindingString(value.role, `${field}.role`, 64);
    const rules = ROLE_BINDING_RULES[role];
    if (rules === undefined) {
        fail(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            `${field}.role is not a HarnessSuiteV4 role`,
            { role },
        );
    }
    const phase = requireBindingString(value.phase, `${field}.phase`, 64);
    if (phase !== rules.phase) {
        fail(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            `${field}.phase is inappropriate for role ${role}`,
            { expected: rules.phase, actual: phase },
        );
    }
    const deterministicSeed = requireBindingString(
        value.deterministicSeed,
        `${field}.deterministicSeed`,
        256,
    );
    const subjectId = requireBindingString(
        value.subjectId,
        `${field}.subjectId`,
        128,
    );
    if (!SAFE_SUBJECT_ID.test(subjectId)) {
        fail(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            `${field}.subjectId is not a safe identifier`,
        );
    }
    const identityAlgorithms = {
        environmentIdentity: "sha256:crucible-harness-environment-v4:",
        suiteIdentity: "sha256:crucible-harness-suite-v4:",
    };
    for (const identityField of ["environmentIdentity", "suiteIdentity"]) {
        const identity = value[identityField];
        if (typeof identity !== "string"
            || !isAlgorithmTaggedSha256(identity)
            || !identity.startsWith(identityAlgorithms[identityField])) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                `${field}.${identityField} must use its HarnessSuiteV4 identity domain`,
            );
        }
    }
    return Object.freeze({
        role,
        phase,
        replicateIndex: normalizeBindingIndex(
            value.replicateIndex,
            `${field}.replicateIndex`,
            rules.replicateIndex,
        ),
        blockIndex: normalizeBindingIndex(
            value.blockIndex,
            `${field}.blockIndex`,
            rules.blockIndex,
        ),
        deterministicSeed,
        subjectId,
        environmentIdentity: value.environmentIdentity,
        suiteIdentity: value.suiteIdentity,
    });
}

export function normalizeHarnessResultBinding(value, options = {}) {
    return normalizeBindingObject(value, {
        field: options.field ?? "measurement binding",
        required: options.required === true,
        rejectUnknown: true,
    });
}

function bindingEqual(left, right) {
    return BINDING_KEYS.every((key) => left[key] === right[key]);
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
        if (!METRIC_NAME.test(key) || FORBIDDEN_RECORD_KEYS.has(key)) {
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
    return Object.freeze(out);
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
        if (!VALIDATION_CASE_NAME.test(key)
            || FORBIDDEN_RECORD_KEYS.has(key)) {
            fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `validationCases key ${JSON.stringify(key)} is not a safe id`);
        }
        const value = validationCases[key];
        if (typeof value !== "boolean") {
            fail(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA, `validationCases.${key} must be a boolean`, { got: typeof value });
        }
        out[key] = value;
    }
    return Object.freeze(out);
}

// Parse `raw` (a UTF-8 string) as the harness's result document. Returns
// a fully normalised, frozen object with exactly the schema-allowed fields
// present.
export function parseHarnessResult(raw, options = {}) {
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

    try {
        findJsonValueBoundary(raw, { rejectDuplicateKeys: true });
    } catch (error) {
        if (error instanceof DuplicateJsonKeyError) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                error.message,
                { key: error.key },
            );
        }
        fail(
            MEASUREMENT_ERROR_CODES.PARSE_MALFORMED,
            `harness result failed strict JSON scanning: ${error?.message ?? String(error)}`,
        );
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
    const binding = normalizeBindingObject(parsed, {
        field: "harness result binding",
        required: options.requireBinding === true
            || options.expectedBinding !== undefined,
    });
    if (options.expectedBinding !== undefined) {
        const expectedBinding = normalizeHarnessResultBinding(
            options.expectedBinding,
            {
                field: "expectedBinding",
                required: true,
            },
        );
        if (binding === null || !bindingEqual(binding, expectedBinding)) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                "harness result binding does not match the trusted execution binding",
                { expected: expectedBinding, actual: binding },
            );
        }
    }

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

    if (binding !== null) {
        if (binding.role !== "calibration" && validationCases !== null) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                `validationCases is not valid for role ${binding.role}`,
            );
        }
        if (binding.role !== "impossibility_verifier"
            && (searchSpaceExhausted !== null
                || impossibilityCertificateHash !== null)) {
            fail(
                MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
                `impossibility fields are not valid for role ${binding.role}`,
            );
        }
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
        role: binding?.role ?? null,
        phase: binding?.phase ?? null,
        replicateIndex: binding?.replicateIndex ?? null,
        blockIndex: binding?.blockIndex ?? null,
        deterministicSeed: binding?.deterministicSeed ?? null,
        subjectId: binding?.subjectId ?? null,
        environmentIdentity: binding?.environmentIdentity ?? null,
        suiteIdentity: binding?.suiteIdentity ?? null,
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
function findJsonValueBoundary(raw, options = {}) {
    // Skip leading whitespace.
    let i = 0;
    while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
    if (i >= raw.length) return 0;
    const start = i;
    try {
        i = scanValue(raw, i, options);
    } catch (error) {
        if (error instanceof DuplicateJsonKeyError) throw error;
        return 0;
    }
    // Return exclusive end offset of the scanned value.
    return i > start ? i : 0;
}

function isWs(cc) {
    return cc === 0x20 || cc === 0x09 || cc === 0x0a || cc === 0x0d;
}

function scanValue(raw, i, options) {
    const cc = raw.charCodeAt(i);
    if (cc === 0x7b /* { */) return scanObject(raw, i, options);
    if (cc === 0x5b /* [ */) return scanArray(raw, i, options);
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
    if (raw.charCodeAt(i) === 0x2d) i += 1;
    const first = raw.charCodeAt(i);
    if (first === 0x30) {
        i += 1;
        const next = raw.charCodeAt(i);
        if (next >= 0x30 && next <= 0x39) {
            throw new Error("leading zero in number");
        }
    } else if (first >= 0x31 && first <= 0x39) {
        i += 1;
        while (i < raw.length) {
            const cc = raw.charCodeAt(i);
            if (cc >= 0x30 && cc <= 0x39) { i += 1; continue; }
            break;
        }
    } else {
        throw new Error("number requires an integer component");
    }
    if (raw.charCodeAt(i) === 0x2e /* . */) {
        i += 1;
        const firstFraction = raw.charCodeAt(i);
        if (firstFraction < 0x30 || firstFraction > 0x39) {
            throw new Error("number fraction requires a digit");
        }
        while (i < raw.length) {
            const cc = raw.charCodeAt(i);
            if (cc >= 0x30 && cc <= 0x39) { i += 1; continue; }
            break;
        }
    }
    if (raw.charCodeAt(i) === 0x65 || raw.charCodeAt(i) === 0x45) {
        i += 1;
        if (raw.charCodeAt(i) === 0x2b || raw.charCodeAt(i) === 0x2d) i += 1;
        const firstExponent = raw.charCodeAt(i);
        if (firstExponent < 0x30 || firstExponent > 0x39) {
            throw new Error("number exponent requires a digit");
        }
        while (i < raw.length) {
            const cc = raw.charCodeAt(i);
            if (cc >= 0x30 && cc <= 0x39) { i += 1; continue; }
            break;
        }
    }
    return i;
}

function scanArray(raw, i, options) {
    i += 1;
    while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
    if (raw.charCodeAt(i) === 0x5d) return i + 1;
    // eslint-disable-next-line no-constant-condition
    while (true) {
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        i = scanValue(raw, i, options);
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        const cc = raw.charCodeAt(i);
        if (cc === 0x5d) return i + 1;
        if (cc !== 0x2c) throw new Error("bad array");
        i += 1;
    }
}

function scanObject(raw, i, options) {
    i += 1;
    const keys = options.rejectDuplicateKeys ? new Set() : null;
    while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
    if (raw.charCodeAt(i) === 0x7d) return i + 1;
    // eslint-disable-next-line no-constant-condition
    while (true) {
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        const keyStart = i;
        i = scanString(raw, i);
        if (keys !== null) {
            const key = JSON.parse(raw.slice(keyStart, i));
            if (keys.has(key)) throw new DuplicateJsonKeyError(key);
            keys.add(key);
        }
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        if (raw.charCodeAt(i) !== 0x3a) throw new Error("bad object");
        i += 1;
        while (i < raw.length && isWs(raw.charCodeAt(i))) i += 1;
        i = scanValue(raw, i, options);
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
