import {
    IMPOSSIBILITY_CHECKER_OUTPUT_VERSION,
    normalizeImpossibilityCheckerResult,
} from "../domain/index.mjs";
import {
    MEASUREMENT_ERROR_CODES,
    ResultParseError,
} from "./errors.mjs";

export const VERIFIER_PARSER_VERSION =
    "crucible-impossibility-verifier-parser-v1";
export const VERIFIER_PARSER_MAX_INPUT_BYTES = 8 * 1024 * 1024;

const RAW_KEYS = Object.freeze([
    "alphaLedgerRoot",
    "blockIndex",
    "certificate",
    "certificateFormat",
    "checkedEnumerandCount",
    "checkerEvidenceRoot",
    "complete",
    "coverageClosureRoot",
    "deterministicSeed",
    "disagreementCount",
    "enumerandCount",
    "enumerandManifestRoot",
    "enumerandResults",
    "enumerandResultsRoot",
    "environmentIdentity",
    "evidenceRoots",
    "independentFactsRoot",
    "mode",
    "phase",
    "proofArtifactHash",
    "proofCheckerIdentity",
    "proofValidationReceiptHash",
    "proposedCertificateArtifactHash",
    "requestHash",
    "role",
    "statisticalPolicyIdentity",
    "status",
    "subjectId",
    "suiteIdentity",
    "validatedProofArtifactHash",
    "version",
]);

function parseFailure(code, message, details = null) {
    throw new ResultParseError(code, message, details);
}

function strictJson(raw) {
    if (typeof raw !== "string") {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_MALFORMED,
            "verifier output must be a UTF-8 string",
        );
    }
    const bytes = Buffer.byteLength(raw, "utf8");
    if (bytes > VERIFIER_PARSER_MAX_INPUT_BYTES) {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_OVERSIZED,
            `verifier output exceeds ${VERIFIER_PARSER_MAX_INPUT_BYTES} bytes`,
            { bytes },
        );
    }
    if (raw.trim().length === 0) {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_EMPTY,
            "verifier produced no JSON output",
        );
    }
    let value;
    try {
        value = JSON.parse(raw);
    } catch (error) {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_MALFORMED,
            `verifier output is not valid JSON: ${error?.message ?? String(error)}`,
        );
    }
    const scanner = new DuplicateKeyScanner(raw);
    try {
        scanner.scanDocument();
    } catch (error) {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            `verifier output failed strict JSON scanning: ${
                error?.message ?? String(error)
            }`,
        );
    }
    return value;
}

class DuplicateKeyScanner {
    constructor(raw) {
        this.raw = raw;
        this.index = 0;
    }

    scanDocument() {
        this.skipWhitespace();
        this.scanValue();
        this.skipWhitespace();
        if (this.index !== this.raw.length) {
            throw new Error("trailing non-whitespace after the JSON value");
        }
    }

    skipWhitespace() {
        while (/\s/u.test(this.raw[this.index] ?? "")) this.index += 1;
    }

    scanValue() {
        const character = this.raw[this.index];
        if (character === "{") return this.scanObject();
        if (character === "[") return this.scanArray();
        if (character === "\"") return this.scanString();
        if (character === "t") return this.scanLiteral("true");
        if (character === "f") return this.scanLiteral("false");
        if (character === "n") return this.scanLiteral("null");
        return this.scanNumber();
    }

    scanObject() {
        this.index += 1;
        this.skipWhitespace();
        const keys = new Set();
        if (this.raw[this.index] === "}") {
            this.index += 1;
            return;
        }
        while (true) {
            const start = this.index;
            this.scanString();
            const key = JSON.parse(this.raw.slice(start, this.index));
            if (keys.has(key)) {
                throw new Error(`duplicate JSON object key ${JSON.stringify(key)}`);
            }
            keys.add(key);
            this.skipWhitespace();
            if (this.raw[this.index] !== ":") throw new Error("missing object colon");
            this.index += 1;
            this.skipWhitespace();
            this.scanValue();
            this.skipWhitespace();
            if (this.raw[this.index] === "}") {
                this.index += 1;
                return;
            }
            if (this.raw[this.index] !== ",") throw new Error("invalid object separator");
            this.index += 1;
            this.skipWhitespace();
        }
    }

    scanArray() {
        this.index += 1;
        this.skipWhitespace();
        if (this.raw[this.index] === "]") {
            this.index += 1;
            return;
        }
        while (true) {
            this.scanValue();
            this.skipWhitespace();
            if (this.raw[this.index] === "]") {
                this.index += 1;
                return;
            }
            if (this.raw[this.index] !== ",") throw new Error("invalid array separator");
            this.index += 1;
            this.skipWhitespace();
        }
    }

    scanString() {
        if (this.raw[this.index] !== "\"") throw new Error("expected JSON string");
        this.index += 1;
        while (this.index < this.raw.length) {
            const character = this.raw[this.index];
            if (character === "\"") {
                this.index += 1;
                return;
            }
            if (character === "\\") {
                this.index += 2;
            } else {
                this.index += 1;
            }
        }
        throw new Error("unterminated JSON string");
    }

    scanLiteral(literal) {
        if (this.raw.slice(this.index, this.index + literal.length) !== literal) {
            throw new Error("invalid JSON literal");
        }
        this.index += literal.length;
    }

    scanNumber() {
        const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(
            this.raw.slice(this.index),
        );
        if (match === null) throw new Error("invalid JSON value");
        this.index += match[0].length;
    }
}

export function parseImpossibilityVerifierResult(raw, options = {}) {
    const parsed = strictJson(raw);
    if (parsed === null
        || typeof parsed !== "object"
        || Array.isArray(parsed)
        || Object.getPrototypeOf(parsed) !== Object.prototype) {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            "verifier output must be a plain JSON object",
        );
    }
    const actualKeys = Object.keys(parsed).sort();
    if (JSON.stringify(actualKeys) !== JSON.stringify([...RAW_KEYS].sort())) {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            "verifier output must contain exactly the formal checker fields",
            { actualKeys, expectedKeys: RAW_KEYS },
        );
    }
    if (parsed.version !== IMPOSSIBILITY_CHECKER_OUTPUT_VERSION) {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            `verifier output version must be ${IMPOSSIBILITY_CHECKER_OUTPUT_VERSION}`,
        );
    }
    try {
        return normalizeImpossibilityCheckerResult({
            ...parsed,
            replicateIndex: null,
            armIndex: null,
            armId: null,
            parserVersion: VERIFIER_PARSER_VERSION,
        }, {
            request: options.request ?? null,
            requestHash: options.requestHash ?? null,
            binding: options.expectedBinding ?? null,
        });
    } catch (error) {
        parseFailure(
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
            error?.message ?? String(error),
            error?.details ?? null,
        );
    }
}
