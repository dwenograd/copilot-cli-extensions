import { createHash } from "node:crypto";
import {
    brotliDecompressSync,
    gunzipSync,
    inflateRawSync,
    inflateSync,
} from "node:zlib";

import { EVASIVE_BLOCKERS } from "./evasiveSchemas.mjs";

export const ARCHIVE_FORMATS = Object.freeze([
    "tar",
    "tar.gz",
    "gzip",
    "deflate",
    "deflate-raw",
    "brotli",
    "zip",
]);

export const ARCHIVE_READER_LIMITS = Object.freeze({
    maxNestedDepth: 4,
    maxEntries: 2_048,
    maxExpandedBytes: 16 * 1024 * 1024,
    maxEntryBytes: 8 * 1024 * 1024,
    maxCompressionRatio: 100,
    maxPathBytes: 4_096,
    maxCentralDirectoryBytes: 4 * 1024 * 1024,
});

const HARD_LIMITS = Object.freeze({
    maxNestedDepth: 8,
    maxEntries: 10_000,
    maxExpandedBytes: 64 * 1024 * 1024,
    maxEntryBytes: 32 * 1024 * 1024,
    maxCompressionRatio: 1_000,
    maxPathBytes: 4_096,
    maxCentralDirectoryBytes: 16 * 1024 * 1024,
});
const ENTRY_BYTES = Symbol("zerotrust.archive-entry-bytes");
const UTF8_FATAL = new TextDecoder("utf-8", { fatal: true });
const ZIP_EOCD_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_SIGNATURE = 0x02014b50;
const ZIP_LOCAL_SIGNATURE = 0x04034b50;
const TAR_BLOCK_BYTES = 512;

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function cloneFrozen(value) {
    if (Array.isArray(value)) {
        return Object.freeze(value.map((entry) => cloneFrozen(entry)));
    }
    if (value && typeof value === "object" && !Buffer.isBuffer(value)) {
        const result = {};
        for (const [key, entry] of Object.entries(value)) {
            result[key] = cloneFrozen(entry);
        }
        return Object.freeze(result);
    }
    return value;
}

function boundedInteger(value, fallback, hardMaximum, name, minimum = 1) {
    if (value === undefined) return fallback;
    if (!Number.isSafeInteger(value) || value < minimum || value > hardMaximum) {
        throw new TypeError(`${name} must be an integer between ${minimum} and ${hardMaximum}`);
    }
    return value;
}

function normalizeLimits(overrides = {}) {
    return Object.freeze({
        maxNestedDepth: boundedInteger(
            overrides.maxNestedDepth,
            ARCHIVE_READER_LIMITS.maxNestedDepth,
            HARD_LIMITS.maxNestedDepth,
            "maxNestedDepth",
            0,
        ),
        maxEntries: boundedInteger(
            overrides.maxEntries,
            ARCHIVE_READER_LIMITS.maxEntries,
            HARD_LIMITS.maxEntries,
            "maxEntries",
        ),
        maxExpandedBytes: boundedInteger(
            overrides.maxExpandedBytes,
            ARCHIVE_READER_LIMITS.maxExpandedBytes,
            HARD_LIMITS.maxExpandedBytes,
            "maxExpandedBytes",
        ),
        maxEntryBytes: boundedInteger(
            overrides.maxEntryBytes,
            ARCHIVE_READER_LIMITS.maxEntryBytes,
            HARD_LIMITS.maxEntryBytes,
            "maxEntryBytes",
        ),
        maxCompressionRatio: boundedInteger(
            overrides.maxCompressionRatio,
            ARCHIVE_READER_LIMITS.maxCompressionRatio,
            HARD_LIMITS.maxCompressionRatio,
            "maxCompressionRatio",
        ),
        maxPathBytes: boundedInteger(
            overrides.maxPathBytes,
            ARCHIVE_READER_LIMITS.maxPathBytes,
            HARD_LIMITS.maxPathBytes,
            "maxPathBytes",
        ),
        maxCentralDirectoryBytes: boundedInteger(
            overrides.maxCentralDirectoryBytes,
            ARCHIVE_READER_LIMITS.maxCentralDirectoryBytes,
            HARD_LIMITS.maxCentralDirectoryBytes,
            "maxCentralDirectoryBytes",
        ),
    });
}

function uniqueSorted(values) {
    return Object.freeze([...new Set(values)].sort());
}

function blockedResult(format, buffer, blockerCodes, details = {}) {
    return cloneFrozen({
        schemaVersion: 6,
        format,
        status: "blocked",
        entries: [],
        blockerCodes: uniqueSorted(blockerCodes),
        totals: {
            inputBytes: buffer.length,
            compressedBytes: buffer.length,
            expandedBytes: 0,
            entries: 0,
            depth: details.depth || 0,
        },
        hashes: {
            inputSha256: sha256(buffer),
            inventorySha256: sha256(Buffer.from(
                JSON.stringify({ format, blockerCodes: uniqueSorted(blockerCodes) }),
                "utf8",
            )),
        },
        ...details,
    });
}

function attachEntryBytes(entry, bytes) {
    Object.defineProperty(entry, ENTRY_BYTES, {
        value: bytes,
        enumerable: false,
        configurable: false,
        writable: false,
    });
    return Object.freeze(entry);
}

export function getArchiveEntryBytes(entry) {
    return entry?.[ENTRY_BYTES] || null;
}

export function validateArchiveEntryPath(value, {
    maxPathBytes = ARCHIVE_READER_LIMITS.maxPathBytes,
} = {}) {
    if (typeof value !== "string") throw new Error("archive entry path is not text");
    let path = value;
    if (path.endsWith("/")) path = path.slice(0, -1);
    if (path.length === 0
        || Buffer.byteLength(path, "utf8") > maxPathBytes
        || path.startsWith("/")
        || path.startsWith("\\")
        || /^[A-Za-z]:/u.test(path)
        || path.includes("\\")
        || /[\u0000-\u001f\u007f]/u.test(path)
        || path.split("/").some((segment) =>
            segment.length === 0 || segment === "." || segment === "..")) {
        throw new Error(`unsafe archive entry path: ${JSON.stringify(value)}`);
    }
    return path.normalize("NFC");
}

function looksLikeTar(buffer) {
    if (buffer.length < TAR_BLOCK_BYTES) return false;
    const magic = buffer.subarray(257, 263).toString("ascii");
    if (magic === "ustar\0" || magic === "ustar ") return true;
    try {
        return tarChecksumValid(buffer.subarray(0, TAR_BLOCK_BYTES));
    } catch {
        return false;
    }
}

function pathFormatHint(path) {
    const lower = String(path || "").toLowerCase();
    if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) return "tar.gz";
    if (lower.endsWith(".tar")) return "tar";
    if (lower.endsWith(".zip") || lower.endsWith(".jar")
        || lower.endsWith(".nupkg") || lower.endsWith(".whl")) return "zip";
    if (lower.endsWith(".gz") || lower.endsWith(".gzip")) return "gzip";
    if (lower.endsWith(".deflate") || lower.endsWith(".zz")) return "deflate";
    if (lower.endsWith(".br")) return "brotli";
    return null;
}

export function detectArchiveFormat(buffer, {
    path = "",
    formatHint = null,
} = {}) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError("archive input must be a Buffer");
    if (formatHint !== null) {
        if (!ARCHIVE_FORMATS.includes(formatHint)) {
            throw new TypeError(`unsupported archive format hint: ${formatHint}`);
        }
        return formatHint;
    }
    if (buffer.length >= 4 && buffer.readUInt32LE(0) === ZIP_LOCAL_SIGNATURE) return "zip";
    if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
        return pathFormatHint(path) === "tar.gz" ? "tar.gz": "gzip";
    }
    if (looksLikeTar(buffer)) return "tar";
    return pathFormatHint(path);
}

function enforceDepth(depth, limits, format, buffer) {
    if (!Number.isSafeInteger(depth) || depth < 0) {
        throw new TypeError("archive depth must be a non-negative integer");
    }
    if (depth > limits.maxNestedDepth) {
        return blockedResult(format, buffer, [EVASIVE_BLOCKERS.NESTED_DEPTH_EXCEEDED], {
            depth,
        });
    }
    return null;
}

function compressionRatio(expandedBytes, compressedBytes) {
    if (expandedBytes === 0) return 0;
    if (compressedBytes === 0) return Number.POSITIVE_INFINITY;
    return expandedBytes / compressedBytes;
}

export function readCompressedPayload(buffer, {
    format,
    depth = 0,
    limits: limitOverrides = {},
} = {}) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError("compressed input must be a Buffer");
    const limits = normalizeLimits(limitOverrides);
    const depthBlock = enforceDepth(depth, limits, format, buffer);
    if (depthBlock) return depthBlock;
    if (!["gzip", "deflate", "deflate-raw", "brotli"].includes(format)) {
        return blockedResult(
            format || "unknown",
            buffer,
            [EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT],
            { depth },
        );
    }
    let output;
    try {
        const options = { maxOutputLength: limits.maxExpandedBytes };
        if (format === "gzip") output = gunzipSync(buffer, options);
        if (format === "deflate") output = inflateSync(buffer, options);
        if (format === "deflate-raw") output = inflateRawSync(buffer, options);
        if (format === "brotli") output = brotliDecompressSync(buffer, options);
    } catch {
        return blockedResult(
            format,
            buffer,
            [EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL],
            { depth },
        );
    }
    const ratio = compressionRatio(output.length, buffer.length);
    if (output.length > limits.maxExpandedBytes) {
        output.fill(0);
        return blockedResult(format, buffer, [EVASIVE_BLOCKERS.BOUNDS_EXCEEDED], { depth });
    }
    if (ratio > limits.maxCompressionRatio) {
        output.fill(0);
        return blockedResult(
            format,
            buffer,
            [EVASIVE_BLOCKERS.EXPANSION_RATIO_EXCEEDED],
            { depth },
        );
    }
    const inputSha256 = sha256(buffer);
    const outputSha256 = sha256(output);
    const entry = attachEntryBytes({
        path: "payload",
        entryKind: "file",
        status: "decoded",
        blockerCodes: Object.freeze([]),
        compressionMethod: format,
        compressedBytes: buffer.length,
        expandedBytes: output.length,
        sourceRange: Object.freeze({
            startOffset: 0,
            endOffset: buffer.length,
            rangeSha256: inputSha256,
        }),
        hashes: Object.freeze({
            compressedSha256: inputSha256,
            contentSha256: outputSha256,
        }),
    }, output);
    return Object.freeze({
        schemaVersion: 6,
        format,
        status: "decoded",
        entries: Object.freeze([entry]),
        blockerCodes: Object.freeze([]),
        totals: Object.freeze({
            inputBytes: buffer.length,
            compressedBytes: buffer.length,
            expandedBytes: output.length,
            entries: 1,
            depth,
            compressionRatio: ratio,
        }),
        hashes: Object.freeze({
            inputSha256,
            inventorySha256: sha256(Buffer.from(
                JSON.stringify({
                    format,
                    outputSha256,
                    expandedBytes: output.length,
                }),
                "utf8",
            )),
        }),
    });
}

function readNullTerminatedAscii(buffer, start, length) {
    const end = start + length;
    if (start < 0 || end > buffer.length) throw new Error("field exceeds input");
    const field = buffer.subarray(start, end);
    const nul = field.indexOf(0);
    const bytes = nul < 0 ? field: field.subarray(0, nul);
    if ([...bytes].some((byte) => byte > 0x7f || byte < 0x20)) {
        throw new Error("tar field is not bounded ASCII");
    }
    return bytes.toString("ascii");
}

function parseTarOctal(buffer, start, length) {
    const raw = buffer.subarray(start, start + length);
    if (raw.length !== length || (raw[0] & 0x80) !== 0) {
        throw new Error("unsupported tar numeric field");
    }
    const text = raw.toString("ascii").replace(/\0.*$/u, "").trim();
    if (text === "") return 0;
    if (!/^[0-7]+$/u.test(text)) throw new Error("malformed tar numeric field");
    const value = Number.parseInt(text, 8);
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error("tar numeric field is out of range");
    }
    return value;
}

function tarChecksumValid(header) {
    if (header.length !== TAR_BLOCK_BYTES) return false;
    const expected = parseTarOctal(header, 148, 8);
    let sum = 0;
    for (let index = 0; index < header.length; index += 1) {
        sum += index >= 148 && index < 156 ? 0x20: header[index];
    }
    return sum === expected;
}

function zeroBlock(buffer) {
    for (const byte of buffer) {
        if (byte !== 0) return false;
    }
    return true;
}

function makeArchiveResult(format, buffer, entries, blockers, totals, depth) {
    const inventory = entries.map((entry) => ({
        pathSha256: sha256(Buffer.from(entry.path, "utf8")),
        entryKind: entry.entryKind,
        status: entry.status,
        blockerCodes: entry.blockerCodes,
        compressedBytes: entry.compressedBytes,
        expandedBytes: entry.expandedBytes,
        contentSha256: entry.hashes.contentSha256,
    }));
    return Object.freeze({
        schemaVersion: 6,
        format,
        status: blockers.length === 0 ? "decoded": "blocked",
        entries: Object.freeze(entries),
        blockerCodes: uniqueSorted(blockers),
        totals: Object.freeze({
            inputBytes: buffer.length,
            compressedBytes: totals.compressedBytes,
            expandedBytes: totals.expandedBytes,
            entries: entries.length,
            depth,
            compressionRatio: compressionRatio(
                totals.expandedBytes,
                totals.compressedBytes,
            ),
        }),
        hashes: Object.freeze({
            inputSha256: sha256(buffer),
            inventorySha256: sha256(Buffer.from(JSON.stringify(inventory), "utf8")),
        }),
    });
}

function readTar(buffer, { depth, limits }) {
    const entries = [];
    const blockers = [];
    let offset = 0;
    let expandedBytes = 0;
    let sawTerminator = false;
    while (offset + TAR_BLOCK_BYTES <= buffer.length) {
        const header = buffer.subarray(offset, offset + TAR_BLOCK_BYTES);
        if (zeroBlock(header)) {
            sawTerminator = true;
            break;
        }
        if (entries.length >= limits.maxEntries) {
            blockers.push(EVASIVE_BLOCKERS.ARCHIVE_ENTRY_LIMIT_EXCEEDED);
            break;
        }
        let checksumValid = false;
        try {
            checksumValid = tarChecksumValid(header);
        } catch {
            checksumValid = false;
        }
        if (!checksumValid) {
            blockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
            break;
        }
        let name;
        let size;
        let type;
        try {
            const baseName = readNullTerminatedAscii(header, 0, 100);
            const prefix = readNullTerminatedAscii(header, 345, 155);
            name = validateArchiveEntryPath(
                prefix ? `${prefix}/${baseName}`: baseName,
                limits,
            );
        } catch {
            blockers.push(EVASIVE_BLOCKERS.DECODE_UNSAFE_ARCHIVE_PATH);
            break;
        }
        try {
            size = parseTarOctal(header, 124, 12);
            type = String.fromCharCode(header[156] || 0);
        } catch {
            blockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
            break;
        }
        const dataOffset = offset + TAR_BLOCK_BYTES;
        const dataEnd = dataOffset + size;
        const nextOffset = dataOffset + Math.ceil(size / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
        if (dataEnd > buffer.length || nextOffset > buffer.length) {
            blockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
            break;
        }
        const entryBlockers = [];
        let entryKind = "file";
        let bytes = null;
        if (type === "5") {
            entryKind = "directory";
            if (size !== 0) entryBlockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
        } else if (type === "\0" || type === "0") {
            if (size > limits.maxEntryBytes
                || expandedBytes + size > limits.maxExpandedBytes) {
                entryBlockers.push(EVASIVE_BLOCKERS.BOUNDS_EXCEEDED);
            } else {
                bytes = buffer.subarray(dataOffset, dataEnd);
                expandedBytes += size;
            }
        } else {
            entryKind = type === "1" ? "hardlink": type === "2" ? "symlink": "unsupported";
            entryBlockers.push(EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT);
        }
        blockers.push(...entryBlockers);
        const rangeBytes = buffer.subarray(dataOffset, dataEnd);
        const entry = {
            path: name,
            entryKind,
            status: entryBlockers.length === 0 ? "decoded": "blocked",
            blockerCodes: uniqueSorted(entryBlockers),
            compressionMethod: "stored",
            compressedBytes: size,
            expandedBytes: size,
            sourceRange: Object.freeze({
                startOffset: dataOffset,
                endOffset: dataEnd,
                rangeSha256: sha256(rangeBytes),
            }),
            hashes: Object.freeze({
                compressedSha256: sha256(rangeBytes),
                contentSha256: bytes ? sha256(bytes): sha256(rangeBytes),
            }),
        };
        entries.push(bytes ? attachEntryBytes(entry, bytes): Object.freeze(entry));
        offset = nextOffset;
    }
    if (!sawTerminator && blockers.length === 0) {
        blockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
    }
    return makeArchiveResult("tar", buffer, entries, blockers, {
        compressedBytes: buffer.length,
        expandedBytes,
    }, depth);
}

function findZipEocd(buffer) {
    const minimum = Math.max(0, buffer.length - 65_557);
    for (let offset = buffer.length - 22; offset >= minimum; offset -= 1) {
        if (buffer.readUInt32LE(offset) === ZIP_EOCD_SIGNATURE) return offset;
    }
    return -1;
}

function decodeZipName(bytes, utf8) {
    if (utf8) return UTF8_FATAL.decode(bytes);
    if ([...bytes].some((byte) => byte > 0x7f)) {
        throw new Error("non-UTF8 ZIP names require unsupported code-page decoding");
    }
    return bytes.toString("ascii");
}

function zipExtraHasAes(extra) {
    let offset = 0;
    while (offset + 4 <= extra.length) {
        const id = extra.readUInt16LE(offset);
        const size = extra.readUInt16LE(offset + 2);
        offset += 4;
        if (offset + size > extra.length) return true;
        if (id === 0x9901) return true;
        offset += size;
    }
    return offset !== extra.length;
}

let crcTable = null;
function crc32(buffer) {
    if (!crcTable) {
        crcTable = new Uint32Array(256);
        for (let index = 0; index < 256; index += 1) {
            let value = index;
            for (let bit = 0; bit < 8; bit += 1) {
                value = (value & 1) !== 0
                    ? 0xedb88320 ^ (value >>> 1): value >>> 1;
            }
            crcTable[index] = value >>> 0;
        }
    }
    let value = 0xffffffff;
    for (const byte of buffer) {
        value = crcTable[(value ^ byte) & 0xff] ^ (value >>> 8);
    }
    return (value ^ 0xffffffff) >>> 0;
}

function readZip(buffer, { depth, limits }) {
    const eocdOffset = findZipEocd(buffer);
    if (eocdOffset < 0) {
        return blockedResult(
            "zip",
            buffer,
            [EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL],
            { depth },
        );
    }
    const diskNumber = buffer.readUInt16LE(eocdOffset + 4);
    const centralDisk = buffer.readUInt16LE(eocdOffset + 6);
    const entriesOnDisk = buffer.readUInt16LE(eocdOffset + 8);
    const entryCount = buffer.readUInt16LE(eocdOffset + 10);
    const centralSize = buffer.readUInt32LE(eocdOffset + 12);
    const centralOffset = buffer.readUInt32LE(eocdOffset + 16);
    const commentLength = buffer.readUInt16LE(eocdOffset + 20);
    if (diskNumber !== 0 || centralDisk !== 0 || entriesOnDisk !== entryCount
        || entryCount === 0xffff || centralSize === 0xffffffff
        || centralOffset === 0xffffffff
        || eocdOffset + 22 + commentLength !== buffer.length
        || centralSize > limits.maxCentralDirectoryBytes
        || centralOffset + centralSize > eocdOffset) {
        return blockedResult(
            "zip",
            buffer,
            [EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT],
            { depth },
        );
    }
    if (entryCount > limits.maxEntries) {
        return blockedResult(
            "zip",
            buffer,
            [EVASIVE_BLOCKERS.ARCHIVE_ENTRY_LIMIT_EXCEEDED],
            { depth },
        );
    }
    const entries = [];
    const blockers = [];
    let centralCursor = centralOffset;
    let expandedBytes = 0;
    let compressedBytes = 0;
    for (let index = 0; index < entryCount; index += 1) {
        if (centralCursor + 46 > buffer.length
            || buffer.readUInt32LE(centralCursor) !== ZIP_CENTRAL_SIGNATURE) {
            blockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
            break;
        }
        const flags = buffer.readUInt16LE(centralCursor + 8);
        const method = buffer.readUInt16LE(centralCursor + 10);
        const expectedCrc = buffer.readUInt32LE(centralCursor + 16);
        const compressedSize = buffer.readUInt32LE(centralCursor + 20);
        const uncompressedSize = buffer.readUInt32LE(centralCursor + 24);
        const nameLength = buffer.readUInt16LE(centralCursor + 28);
        const extraLength = buffer.readUInt16LE(centralCursor + 30);
        const fileCommentLength = buffer.readUInt16LE(centralCursor + 32);
        const localOffset = buffer.readUInt32LE(centralCursor + 42);
        const centralEnd = centralCursor + 46 + nameLength
            + extraLength + fileCommentLength;
        if (centralEnd > centralOffset + centralSize || centralEnd > buffer.length) {
            blockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
            break;
        }
        const nameBytes = buffer.subarray(
            centralCursor + 46,
            centralCursor + 46 + nameLength,
        );
        const extra = buffer.subarray(
            centralCursor + 46 + nameLength,
            centralCursor + 46 + nameLength + extraLength,
        );
        let name;
        let directoryEntry = false;
        try {
            const decodedName = decodeZipName(nameBytes, (flags & 0x0800) !== 0);
            directoryEntry = decodedName.endsWith("/");
            name = validateArchiveEntryPath(decodedName, limits);
        } catch {
            blockers.push(EVASIVE_BLOCKERS.DECODE_UNSAFE_ARCHIVE_PATH);
            centralCursor = centralEnd;
            continue;
        }
        const entryBlockers = [];
        if ((flags & 0x0001) !== 0 || zipExtraHasAes(extra)) {
            entryBlockers.push(EVASIVE_BLOCKERS.DECODE_ENCRYPTED);
        }
        if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff
            || localOffset === 0xffffffff) {
            entryBlockers.push(EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT);
        }
        if (uncompressedSize > limits.maxEntryBytes
            || expandedBytes + uncompressedSize > limits.maxExpandedBytes) {
            entryBlockers.push(EVASIVE_BLOCKERS.BOUNDS_EXCEEDED);
        }
        if (compressionRatio(uncompressedSize, compressedSize)
            > limits.maxCompressionRatio) {
            entryBlockers.push(EVASIVE_BLOCKERS.EXPANSION_RATIO_EXCEEDED);
        }
        let dataOffset = localOffset;
        let dataEnd = localOffset;
        let compressed = Buffer.alloc(0);
        let output = null;
        if (entryBlockers.length === 0) {
            if (localOffset + 30 > buffer.length
                || buffer.readUInt32LE(localOffset) !== ZIP_LOCAL_SIGNATURE) {
                entryBlockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
            } else {
                const localFlags = buffer.readUInt16LE(localOffset + 6);
                const localMethod = buffer.readUInt16LE(localOffset + 8);
                const localNameLength = buffer.readUInt16LE(localOffset + 26);
                const localExtraLength = buffer.readUInt16LE(localOffset + 28);
                dataOffset = localOffset + 30 + localNameLength + localExtraLength;
                dataEnd = dataOffset + compressedSize;
                if (localFlags !== flags || localMethod !== method
                    || dataEnd > buffer.length) {
                    entryBlockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
                } else {
                    const localNameBytes = buffer.subarray(
                        localOffset + 30,
                        localOffset + 30 + localNameLength,
                    );
                    try {
                        const localName = validateArchiveEntryPath(
                            decodeZipName(localNameBytes, (localFlags & 0x0800) !== 0),
                            limits,
                        );
                        if (localName !== name) {
                            entryBlockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
                        }
                    } catch {
                        entryBlockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
                    }
                }
            }
        }
        if (entryBlockers.length === 0) {
            compressed = buffer.subarray(dataOffset, dataEnd);
            try {
                if (method === 0) output = compressed;
                else if (method === 8) {
                    output = inflateRawSync(compressed, {
                        maxOutputLength: Math.min(
                            limits.maxEntryBytes,
                            limits.maxExpandedBytes - expandedBytes,
                        ),
                    });
                } else {
                    entryBlockers.push(EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT);
                }
            } catch {
                entryBlockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
            }
        }
        if (output && (output.length !== uncompressedSize
            || crc32(output) !== expectedCrc)) {
            entryBlockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
            if (output !== compressed) output.fill(0);
            output = null;
        }
        if (output) {
            expandedBytes += output.length;
            compressedBytes += compressed.length;
        }
        blockers.push(...entryBlockers);
        const rangeBytes = dataEnd <= buffer.length
            ? buffer.subarray(dataOffset, dataEnd): Buffer.alloc(0);
        const entry = {
            path: name,
            entryKind: directoryEntry ? "directory": "file",
            status: entryBlockers.length === 0 ? "decoded": "blocked",
            blockerCodes: uniqueSorted(entryBlockers),
            compressionMethod: method === 0 ? "stored": method === 8 ? "deflate-raw": `zip-method-${method}`,
            compressedBytes: compressedSize,
            expandedBytes: uncompressedSize,
            sourceRange: Object.freeze({
                startOffset: dataOffset,
                endOffset: dataEnd,
                rangeSha256: sha256(rangeBytes),
            }),
            hashes: Object.freeze({
                compressedSha256: sha256(rangeBytes),
                contentSha256: output ? sha256(output): sha256(rangeBytes),
            }),
        };
        entries.push(output ? attachEntryBytes(entry, output): Object.freeze(entry));
        centralCursor = centralEnd;
    }
    if (centralCursor !== centralOffset + centralSize && blockers.length === 0) {
        blockers.push(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL);
    }
    return makeArchiveResult("zip", buffer, entries, blockers, {
        compressedBytes,
        expandedBytes,
    }, depth);
}

export function readArchive(buffer, {
    path = "",
    formatHint = null,
    depth = 0,
    limits: limitOverrides = {},
} = {}) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError("archive input must be a Buffer");
    const limits = normalizeLimits(limitOverrides);
    const format = detectArchiveFormat(buffer, { path, formatHint });
    if (!format) {
        return blockedResult(
            "unknown",
            buffer,
            [EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT],
            { depth },
        );
    }
    const depthBlock = enforceDepth(depth, limits, format, buffer);
    if (depthBlock) return depthBlock;
    if (format === "tar") return readTar(buffer, { depth, limits });
    if (format === "zip") return readZip(buffer, { depth, limits });
    if (format === "tar.gz") {
        const decompressed = readCompressedPayload(buffer, {
            format: "gzip",
            depth,
            limits,
        });
        if (decompressed.status !== "decoded") {
            return Object.freeze({ ...decompressed, format: "tar.gz" });
        }
        const payload = getArchiveEntryBytes(decompressed.entries[0]);
        if (!looksLikeTar(payload)) {
            payload.fill(0);
            return blockedResult(
                "tar.gz",
                buffer,
                [EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL],
                { depth },
            );
        }
        const tar = readTar(payload, { depth, limits });
        return Object.freeze({
            ...tar,
            format: "tar.gz",
            totals: Object.freeze({
                ...tar.totals,
                inputBytes: buffer.length,
                compressedBytes: buffer.length,
                compressionRatio: compressionRatio(
                    tar.totals.expandedBytes,
                    buffer.length,
                ),
            }),
            hashes: Object.freeze({
                inputSha256: sha256(buffer),
                inventorySha256: tar.hashes.inventorySha256,
                expandedContainerSha256: sha256(payload),
            }),
        });
    }
    return readCompressedPayload(buffer, {
        format,
        depth,
        limits,
    });
}

export const __internals = Object.freeze({
    normalizeLimits,
    compressionRatio,
    looksLikeTar,
    tarChecksumValid,
    crc32,
    findZipEocd,
});
