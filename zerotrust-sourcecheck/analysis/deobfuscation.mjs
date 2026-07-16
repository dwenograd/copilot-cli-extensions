import { createHash } from "node:crypto";

import {
    detectArchiveFormat,
    getArchiveEntryBytes,
    readCompressedPayload,
} from "./archiveReaders.mjs";
import { EVASIVE_BLOCKERS } from "./evasiveSchemas.mjs";

export const DEOBFUSCATION_LIMITS = Object.freeze({
    maxSourceBytes: 1024 * 1024,
    maxCandidates: 256,
    maxLiteralChars: 256 * 1024,
    maxDecodedBytes: 8 * 1024 * 1024,
    maxTransformDepth: 8,
    maxArrayItems: 65_536,
    highEntropyMinimumBytes: 256,
    highEntropyThreshold: 7.5,
});

const HARD_LIMITS = Object.freeze({
    maxSourceBytes: 4 * 1024 * 1024,
    maxCandidates: 1_024,
    maxLiteralChars: 1024 * 1024,
    maxDecodedBytes: 32 * 1024 * 1024,
    maxTransformDepth: 16,
    maxArrayItems: 262_144,
    highEntropyMinimumBytes: 4 * 1024,
    highEntropyThreshold: 8,
});
const DECODED_BYTES = Symbol("zerotrust.decoded-bytes");

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function boundedNumber(value, fallback, maximum, name, minimum = 1) {
    if (value === undefined) return fallback;
    if (!Number.isFinite(value) || value < minimum || value > maximum) {
        throw new TypeError(`${name} must be between ${minimum} and ${maximum}`);
    }
    return value;
}

function normalizedLimits(overrides = {}) {
    return Object.freeze({
        maxSourceBytes: boundedNumber(
            overrides.maxSourceBytes,
            DEOBFUSCATION_LIMITS.maxSourceBytes,
            HARD_LIMITS.maxSourceBytes,
            "maxSourceBytes",
        ),
        maxCandidates: boundedNumber(
            overrides.maxCandidates,
            DEOBFUSCATION_LIMITS.maxCandidates,
            HARD_LIMITS.maxCandidates,
            "maxCandidates",
        ),
        maxLiteralChars: boundedNumber(
            overrides.maxLiteralChars,
            DEOBFUSCATION_LIMITS.maxLiteralChars,
            HARD_LIMITS.maxLiteralChars,
            "maxLiteralChars",
        ),
        maxDecodedBytes: boundedNumber(
            overrides.maxDecodedBytes,
            DEOBFUSCATION_LIMITS.maxDecodedBytes,
            HARD_LIMITS.maxDecodedBytes,
            "maxDecodedBytes",
        ),
        maxTransformDepth: boundedNumber(
            overrides.maxTransformDepth,
            DEOBFUSCATION_LIMITS.maxTransformDepth,
            HARD_LIMITS.maxTransformDepth,
            "maxTransformDepth",
        ),
        maxArrayItems: boundedNumber(
            overrides.maxArrayItems,
            DEOBFUSCATION_LIMITS.maxArrayItems,
            HARD_LIMITS.maxArrayItems,
            "maxArrayItems",
        ),
        highEntropyMinimumBytes: boundedNumber(
            overrides.highEntropyMinimumBytes,
            DEOBFUSCATION_LIMITS.highEntropyMinimumBytes,
            HARD_LIMITS.highEntropyMinimumBytes,
            "highEntropyMinimumBytes",
        ),
        highEntropyThreshold: boundedNumber(
            overrides.highEntropyThreshold,
            DEOBFUSCATION_LIMITS.highEntropyThreshold,
            HARD_LIMITS.highEntropyThreshold,
            "highEntropyThreshold",
            0,
        ),
    });
}

function uniqueSorted(values) {
    return Object.freeze([...new Set(values)].sort());
}

function sourceIdentity(sourceObject) {
    const objectId = sourceObject?.objectId;
    const path = sourceObject?.path;
    const identitySha256 = sourceObject?.hashes?.identitySha256;
    if (typeof objectId !== "string" || typeof path !== "string"
        || !/^[a-f0-9]{64}$/u.test(identitySha256 || "")) {
        throw new TypeError("static decoding requires a strict assurance source object identity");
    }
    return { objectId, path, identitySha256 };
}

function attachDecodedBytes(output, bytes) {
    Object.defineProperty(output, DECODED_BYTES, {
        value: bytes,
        enumerable: false,
        configurable: false,
        writable: false,
    });
    return Object.freeze(output);
}

export function getDecodedBytes(output) {
    return output?.[DECODED_BYTES] || null;
}

export function shannonEntropy(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) return 0;
    const counts = new Uint32Array(256);
    for (const byte of buffer) counts[byte] += 1;
    let entropy = 0;
    for (const count of counts) {
        if (count === 0) continue;
        const probability = count / buffer.length;
        entropy -= probability * Math.log2(probability);
    }
    return entropy;
}

function utf8Offset(text, characterOffset) {
    return Buffer.byteLength(text.slice(0, characterOffset), "utf8");
}

function sourceRange(text, start, end) {
    const rangeBytes = Buffer.from(text.slice(start, end), "utf8");
    return Object.freeze({
        startOffset: utf8Offset(text, start),
        endOffset: utf8Offset(text, end),
        rangeSha256: sha256(rangeBytes),
    });
}

function transform(kind, inputSha256, outputSha256) {
    return Object.freeze({ kind, inputSha256, outputSha256 });
}

function outputRecord({
    identity,
    range,
    decoderKind,
    bytes,
    transformChain,
    blockerCodes = [],
    entropy = shannonEntropy(bytes),
}) {
    const codes = uniqueSorted(blockerCodes);
    const contentSha256 = sha256(bytes);
    const derivationSha256 = sha256(Buffer.from(JSON.stringify({
        sourceObjectId: identity.objectId,
        sourceObjectSha256: identity.identitySha256,
        sourceRange: range,
        decoderKind,
        transformChain,
        contentSha256,
        blockerCodes: codes,
    }), "utf8"));
    return attachDecodedBytes({
        schemaVersion: 6,
        decoderId: `ztdec-${derivationSha256}`,
        sourceObjectId: identity.objectId,
        sourcePath: identity.path,
        sourceRange: range,
        rangeUnit: "utf8-byte",
        decoderKind,
        status: codes.length === 0 ? "decoded": "blocked",
        byteLength: bytes.length,
        transformChain: Object.freeze(transformChain),
        blockerCodes: codes,
        indicators: Object.freeze({
            entropyBitsPerByte: Number(entropy.toFixed(4)),
            printableAsciiRatio: printableAsciiRatio(bytes),
            archiveFormat: detectArchiveFormat(bytes) || null,
        }),
        hashes: Object.freeze({
            sourceObjectSha256: identity.identitySha256,
            sourceRangeSha256: range.rangeSha256,
            contentSha256,
            derivationSha256,
        }),
    }, bytes);
}

function printableAsciiRatio(buffer) {
    if (buffer.length === 0) return 0;
    let printable = 0;
    for (const byte of buffer) {
        if (byte === 0x09 || byte === 0x0a || byte === 0x0d
            || (byte >= 0x20 && byte <= 0x7e)) printable += 1;
    }
    return Number((printable / buffer.length).toFixed(4));
}

function scanQuotedLiterals(text, limits) {
    const literals = [];
    for (let index = 0; index < text.length && literals.length < limits.maxCandidates; index += 1) {
        const quote = text[index];
        if (quote !== "'" && quote !== "\"" && quote !== "`") continue;
        const start = index;
        let escaped = false;
        let closed = false;
        index += 1;
        for (; index < text.length; index += 1) {
            const char = text[index];
            if (char === "\r" || char === "\n") break;
            if (escaped) {
                escaped = false;
                continue;
            }
            if (char === "\\") {
                escaped = true;
                continue;
            }
            if (char === quote) {
                closed = true;
                break;
            }
            if (index - start > limits.maxLiteralChars) break;
        }
        if (!closed) continue;
        literals.push(Object.freeze({
            start,
            end: index + 1,
            quote,
            raw: text.slice(start + 1, index),
        }));
    }
    return literals;
}

function decodeEscapedLiteral(raw, quote) {
    let result = "";
    let transformed = false;
    for (let index = 0; index < raw.length; index += 1) {
        const char = raw[index];
        if (char !== "\\") {
            result += char;
            continue;
        }
        transformed = true;
        index += 1;
        if (index >= raw.length) throw new Error("trailing escape");
        const escaped = raw[index];
        const simple = {
            "\\": "\\",
            "'": "'",
            "\"": "\"",
            "`": "`",
            n: "\n",
            r: "\r",
            t: "\t",
            b: "\b",
            f: "\f",
            v: "\v",
            0: "\0",
        };
        if (Object.hasOwn(simple, escaped)) {
            if (escaped === "0" && /[0-9]/u.test(raw[index + 1] || "")) {
                throw new Error("ambiguous octal escape");
            }
            result += simple[escaped];
            continue;
        }
        if (escaped === "x") {
            const hex = raw.slice(index + 1, index + 3);
            if (!/^[a-f0-9]{2}$/iu.test(hex)) throw new Error("invalid hex escape");
            result += String.fromCharCode(Number.parseInt(hex, 16));
            index += 2;
            continue;
        }
        if (escaped === "u") {
            if (raw[index + 1] === "{") {
                const close = raw.indexOf("}", index + 2);
                const hex = close < 0 ? "": raw.slice(index + 2, close);
                if (!/^[a-f0-9]{1,6}$/iu.test(hex)) {
                    throw new Error("invalid unicode code-point escape");
                }
                const codePoint = Number.parseInt(hex, 16);
                if (codePoint > 0x10ffff) throw new Error("unicode code point out of range");
                result += String.fromCodePoint(codePoint);
                index = close;
                continue;
            }
            const hex = raw.slice(index + 1, index + 5);
            if (!/^[a-f0-9]{4}$/iu.test(hex)) throw new Error("invalid unicode escape");
            result += String.fromCharCode(Number.parseInt(hex, 16));
            index += 4;
            continue;
        }
        if (escaped === quote) {
            result += quote;
            continue;
        }
        throw new Error("unsupported escape sequence");
    }
    return { text: result, transformed };
}

function strictBase64(value) {
    if (value.length < 8) return null;
    if (value.length % 4 === 0
        && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
        const bytes = Buffer.from(value, "base64");
        if (bytes.toString("base64") === value) return bytes;
    }
    const unpadded = value.replace(/=+$/u, "");
    if (value.length % 4 !== 1 && /^[A-Za-z0-9_-]+={0,2}$/u.test(value)) {
        const bytes = Buffer.from(value, "base64url");
        if (bytes.toString("base64url") === unpadded) return bytes;
    }
    return null;
}

function strictHex(value) {
    const normalized = value.startsWith("0x") ? value.slice(2): value;
    if (normalized.length < 16 || normalized.length % 2 !== 0
        || !/^[a-f0-9]+$/iu.test(normalized)) return null;
    return Buffer.from(normalized, "hex");
}

function compressedFormatHint(text, start, end, bytes) {
    const detected = detectArchiveFormat(bytes);
    if (detected === "gzip") return "gzip";
    const context = text.slice(Math.max(0, start - 96), Math.min(text.length, end + 96));
    if (/\b(?:gunzip|gzip|gzdecode)\b/iu.test(context)) return "gzip";
    if (/\b(?:inflateRaw|deflateRaw)\b/iu.test(context)) return "deflate-raw";
    if (/\b(?:inflate|deflate|zlib)\b/iu.test(context)) return "deflate";
    if (/\b(?:brotli|brotliDecompress)\b/iu.test(context)) return "brotli";
    if (bytes.length >= 2 && (bytes[0] & 0x0f) === 8
        && ((bytes[0] << 8) + bytes[1]) % 31 === 0) return "deflate";
    return null;
}

function expandCompressed({
    text,
    start,
    end,
    bytes,
    chain,
    limits,
}) {
    const format = compressedFormatHint(text, start, end, bytes);
    if (!format) return { bytes, chain, blockerCodes: [] };
    const decoded = readCompressedPayload(bytes, {
        format,
        limits: {
            maxExpandedBytes: limits.maxDecodedBytes,
            maxEntryBytes: limits.maxDecodedBytes,
        },
    });
    if (decoded.status !== "decoded") {
        return {
            bytes,
            chain,
            blockerCodes: decoded.blockerCodes,
        };
    }
    const expanded = getArchiveEntryBytes(decoded.entries[0]);
    const expandedHash = sha256(expanded);
    return {
        bytes: expanded,
        chain: [
            ...chain,
            transform(format, sha256(bytes), expandedHash),
        ],
        blockerCodes: [],
    };
}

function entropyBlockers(bytes, limits, knownFormat) {
    if (knownFormat || bytes.length < limits.highEntropyMinimumBytes) return [];
    return shannonEntropy(bytes) >= limits.highEntropyThreshold
        ? [EVASIVE_BLOCKERS.DECODE_PACKED_OR_HIGH_ENTROPY]: [];
}

function emitLiteralCandidate({
    outputs,
    seen,
    text,
    identity,
    start,
    end,
    decodedText,
    initialKind,
    initialInputSha256,
    initialOutputSha256,
    limits,
}) {
    const range = sourceRange(text, start, end);
    const initialBytes = Buffer.from(decodedText, "utf8");
    const prefixChain = [
        transform(
            initialKind || "identity",
            initialInputSha256,
            initialOutputSha256,
        ),
    ];
    const candidates = [];
    const base64 = strictBase64(decodedText);
    if (base64) {
        candidates.push({
            kind: "base64",
            bytes: base64,
            chain: [
                ...prefixChain,
                transform("base64", initialOutputSha256, sha256(base64)),
            ],
        });
    }
    const hex = strictHex(decodedText);
    if (hex) {
        candidates.push({
            kind: "hex",
            bytes: hex,
            chain: [
                ...prefixChain,
                transform("hex", initialOutputSha256, sha256(hex)),
            ],
        });
    }
    if (initialKind && candidates.length === 0) {
        candidates.push({
            kind: initialKind,
            bytes: initialBytes,
            chain: prefixChain,
        });
    }
    for (const candidate of candidates) {
        if (outputs.length >= limits.maxCandidates) return;
        const expanded = expandCompressed({
            text,
            start,
            end,
            bytes: candidate.bytes,
            chain: candidate.chain,
            limits,
        });
        const knownFormat = detectArchiveFormat(expanded.bytes);
        const blockerCodes = [
            ...expanded.blockerCodes,
            ...entropyBlockers(expanded.bytes, limits, knownFormat),
        ];
        if (expanded.bytes.length > limits.maxDecodedBytes) {
            blockerCodes.push(EVASIVE_BLOCKERS.BOUNDS_EXCEEDED);
        }
        const key = `${range.startOffset}:${range.endOffset}:${sha256(expanded.bytes)}:${candidate.kind}`;
        if (seen.has(key)) continue;
        seen.add(key);
        outputs.push(outputRecord({
            identity,
            range,
            decoderKind: candidate.kind,
            bytes: expanded.bytes,
            transformChain: expanded.chain,
            blockerCodes,
        }));
    }
}

function literalGroups(text, literals, separatorPattern) {
    const groups = [];
    let current = [];
    for (const literal of literals) {
        if (current.length === 0) {
            current = [literal];
            continue;
        }
        const previous = current.at(-1);
        const gap = text.slice(previous.end, literal.start);
        if (separatorPattern.test(gap)) current.push(literal);
        else {
            if (current.length > 1) groups.push(current);
            current = [literal];
        }
        separatorPattern.lastIndex = 0;
    }
    if (current.length > 1) groups.push(current);
    return groups;
}

function decodeLiteralGroup(group) {
    let text = "";
    for (const literal of group) {
        text += decodeEscapedLiteral(literal.raw, literal.quote).text;
    }
    return text;
}

function isBracketedLiteralArray(text, group) {
    const start = group[0].start;
    const end = group.at(-1).end;
    const before = text.slice(0, start).match(/\S\s*$/u)?.[0]?.trim() || "";
    const after = text.slice(end).match(/^\s*\S/u)?.[0]?.trim() || "";
    return before === "[" && after === "]";
}

function scanByteArrays(text, identity, limits, outputs, seen) {
    const arrayPattern = /\[((?:\s*(?:0x[a-f0-9]{1,2}|[0-9]{1,3})\s*,){3,}\s*(?:0x[a-f0-9]{1,2}|[0-9]{1,3})\s*)\]/giu;
    for (const match of text.matchAll(arrayPattern)) {
        if (outputs.length >= limits.maxCandidates) break;
        const values = [...match[1].matchAll(/0x[a-f0-9]{1,2}|[0-9]{1,3}/giu)]
            .map((entry) => Number.parseInt(entry[0], entry[0].startsWith("0x") ? 16: 10));
        if (values.length > limits.maxArrayItems || values.some((value) => value > 255)) {
            continue;
        }
        const start = match.index;
        const end = start + match[0].length;
        const range = sourceRange(text, start, end);
        let bytes = Buffer.from(values);
        const arrayHash = sha256(bytes);
        const chain = [
            transform("literal-array", range.rangeSha256, arrayHash),
        ];
        let decoderKind = "literal-array";
        const tail = text.slice(end, Math.min(text.length, end + 160));
        const xorMatch = tail.match(
            /(?:\.map\s*\([^)]{0,120}\^\s*|,\s*)(0x[a-f0-9]{1,2}|[0-9]{1,3})/iu,
        );
        if (xorMatch) {
            const key = Number.parseInt(
                xorMatch[1],
                xorMatch[1].startsWith("0x") ? 16: 10,
            );
            if (key <= 255) {
                bytes = Buffer.from(bytes.map((value) => value ^ key));
                chain.push(transform("xor", arrayHash, sha256(bytes)));
                decoderKind = "xor";
            }
        }
        const expanded = expandCompressed({
            text,
            start,
            end,
            bytes,
            chain,
            limits,
        });
        const knownFormat = detectArchiveFormat(expanded.bytes);
        const blockerCodes = [
            ...expanded.blockerCodes,
            ...entropyBlockers(expanded.bytes, limits, knownFormat),
        ];
        const dedupeKey = `${range.startOffset}:${range.endOffset}:${sha256(expanded.bytes)}:${decoderKind}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        outputs.push(outputRecord({
            identity,
            range,
            decoderKind,
            bytes: expanded.bytes,
            transformChain: expanded.chain,
            blockerCodes,
        }));
    }
}

export function decodeStaticLiterals({
    text,
    sourceObject,
    limits: limitOverrides = {},
} = {}) {
    if (typeof text !== "string") throw new TypeError("static decoding requires source text");
    const limits = normalizedLimits(limitOverrides);
    const identity = sourceIdentity(sourceObject);
    const sourceBytes = Buffer.byteLength(text, "utf8");
    if (sourceBytes > limits.maxSourceBytes) {
        return Object.freeze({
            schemaVersion: 6,
            sourceObjectId: identity.objectId,
            status: "blocked",
            outputs: Object.freeze([]),
            blockerCodes: Object.freeze([EVASIVE_BLOCKERS.BOUNDS_EXCEEDED]),
            hashes: Object.freeze({
                sourceObjectSha256: identity.identitySha256,
                resultSha256: sha256(Buffer.from("bounds/exceeded", "utf8")),
            }),
        });
    }
    const outputs = [];
    const seen = new Set();
    const literals = scanQuotedLiterals(text, limits);
    for (const literal of literals) {
        if (outputs.length >= limits.maxCandidates) break;
        const range = sourceRange(text, literal.start, literal.end);
        let decoded;
        try {
            decoded = decodeEscapedLiteral(literal.raw, literal.quote);
        } catch {
            if (/\\(?:x|u|[0-7])/u.test(literal.raw)) {
                const bytes = Buffer.from(literal.raw, "utf8");
                outputs.push(outputRecord({
                    identity,
                    range,
                    decoderKind: "escaped-string",
                    bytes,
                    transformChain: [
                        transform("identity", range.rangeSha256, sha256(bytes)),
                    ],
                    blockerCodes: [EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL],
                }));
            }
            continue;
        }
        const decodedBytes = Buffer.from(decoded.text, "utf8");
        emitLiteralCandidate({
            outputs,
            seen,
            text,
            identity,
            start: literal.start,
            end: literal.end,
            decodedText: decoded.text,
            initialKind: decoded.transformed ? "escaped-string": null,
            initialInputSha256: range.rangeSha256,
            initialOutputSha256: sha256(decodedBytes),
            limits,
        });
    }

    for (const [groups, kind] of [
        [literalGroups(text, literals, /^\s*\+\s*$/u), "literal-concatenation"],
        [
            literalGroups(text, literals, /^\s*,\s*$/u)
                .filter((group) => isBracketedLiteralArray(text, group)),
            "literal-array",
        ],
    ]) {
        for (const group of groups) {
            if (outputs.length >= limits.maxCandidates) break;
            const start = group[0].start;
            const end = group.at(-1).end;
            const range = sourceRange(text, start, end);
            let decodedText;
            try {
                decodedText = decodeLiteralGroup(group);
            } catch {
                continue;
            }
            emitLiteralCandidate({
                outputs,
                seen,
                text,
                identity,
                start,
                end,
                decodedText,
                initialKind: kind,
                initialInputSha256: range.rangeSha256,
                initialOutputSha256: sha256(Buffer.from(decodedText, "utf8")),
                limits,
            });
        }
    }

    scanByteArrays(text, identity, limits, outputs, seen);
    const blockerCodes = outputs.length >= limits.maxCandidates
        ? [EVASIVE_BLOCKERS.BOUNDS_EXCEEDED]: [];
    const resultDescriptor = outputs.map((output) => ({
        decoderId: output.decoderId,
        status: output.status,
        byteLength: output.byteLength,
        blockerCodes: output.blockerCodes,
        contentSha256: output.hashes.contentSha256,
    }));
    return Object.freeze({
        schemaVersion: 6,
        sourceObjectId: identity.objectId,
        status: blockerCodes.length === 0
            && outputs.every((output) => output.status === "decoded")
            ? "decoded": "blocked",
        outputs: Object.freeze(outputs),
        blockerCodes: uniqueSorted([
            ...blockerCodes,
            ...outputs.flatMap((output) => output.blockerCodes),
        ]),
        hashes: Object.freeze({
            sourceObjectSha256: identity.identitySha256,
            resultSha256: sha256(Buffer.from(JSON.stringify(resultDescriptor), "utf8")),
        }),
    });
}

export const __internals = Object.freeze({
    normalizedLimits,
    scanQuotedLiterals,
    decodeEscapedLiteral,
    strictBase64,
    strictHex,
    printableAsciiRatio,
    compressedFormatHint,
});
