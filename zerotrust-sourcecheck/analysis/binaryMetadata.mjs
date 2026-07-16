import { createHash } from "node:crypto";

import { EVASIVE_BLOCKERS } from "./evasiveSchemas.mjs";

export const BINARY_FORMATS = Object.freeze([
    "pe",
    "pe-dotnet",
    "elf",
    "mach-o",
    "mach-o-fat",
    "wasm",
    "java-class",
    "java-jar",
    "dotnet-package",
    "zip-package",
    "unknown",
]);

export const BINARY_METADATA_LIMITS = Object.freeze({
    maxSections: 256,
    maxImports: 1_024,
    maxExports: 1_024,
    maxStrings: 512,
    maxUrls: 128,
    maxEntries: 2_048,
    maxIndicatorLength: 512,
    maxConstantPoolEntries: 65_535,
});

const PACKER_SECTION_RE =
    /^(?:UPX[0-9]*|MPRESS[0-9]*|ASPACK|PETITE|THEMIDA|VMProtect|\.packed)$/iu;
const URL_RE = /\bhttps?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'*+,;=%-]{1,500}/gu;

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function uniqueBounded(values, maximum) {
    if (typeof values === "string"
        || values === null
        || values === undefined
        || typeof values[Symbol.iterator] !== "function") {
        throw new TypeError("binary metadata values must be iterable");
    }
    return [...new Set([...values].filter((value) => typeof value === "string" && value))]
        .sort()
        .slice(0, maximum);
}

function safeIndicator(value, limits) {
    if (typeof value !== "string") return null;
    const normalized = value.normalize("NFKC").replace(/\0/gu, "").trim();
    if (normalized.length === 0 || normalized.length > limits.maxIndicatorLength
        || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(normalized)) {
        return null;
    }
    return normalized;
}

function sourceIdentity(sourceObject) {
    if (typeof sourceObject?.objectId !== "string"
        || typeof sourceObject?.path !== "string"
        || !/^[a-f0-9]{64}$/u.test(sourceObject?.hashes?.identitySha256 || "")) {
        throw new TypeError("binary metadata requires a strict assurance source object identity");
    }
    return {
        objectId: sourceObject.objectId,
        path: sourceObject.path,
        identitySha256: sourceObject.hashes.identitySha256,
    };
}

function wholeRange(buffer) {
    return Object.freeze({
        startOffset: 0,
        endOffset: buffer.length,
        rangeSha256: sha256(buffer),
    });
}

function ensureRange(value, buffer) {
    if (!value) return wholeRange(buffer);
    if (!Number.isSafeInteger(value.startOffset) || value.startOffset < 0
        || !Number.isSafeInteger(value.endOffset)
        || value.endOffset < value.startOffset
        || !/^[a-f0-9]{64}$/u.test(value.rangeSha256 || "")) {
        throw new TypeError("binary metadata sourceRange is invalid");
    }
    return Object.freeze({
        startOffset: value.startOffset,
        endOffset: value.endOffset,
        rangeSha256: value.rangeSha256,
    });
}

function readAsciiZ(buffer, offset, maximum = 512) {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset >= buffer.length) {
        throw new Error("string offset exceeds binary");
    }
    const endLimit = Math.min(buffer.length, offset + maximum);
    let end = offset;
    while (end < endLimit && buffer[end] !== 0) end += 1;
    if (end === endLimit && buffer[end] !== 0) throw new Error("unterminated string");
    const bytes = buffer.subarray(offset, end);
    if ([...bytes].some((byte) => byte < 0x20 || byte > 0x7e)) {
        throw new Error("non-ASCII metadata string");
    }
    return bytes.toString("ascii");
}

function scanStrings(buffer, limits) {
    const strings = [];
    let start = -1;
    for (let index = 0; index <= buffer.length; index += 1) {
        const byte = index < buffer.length ? buffer[index]: 0;
        if (byte >= 0x20 && byte <= 0x7e) {
            if (start < 0) start = index;
        } else if (start >= 0) {
            if (index - start >= 4) {
                const value = safeIndicator(
                    buffer.subarray(start, index).toString("ascii"),
                    limits,
                );
                if (value) strings.push(value);
            }
            start = -1;
        }
        if (strings.length >= limits.maxStrings * 2) break;
    }
    for (const littleEndian of [true, false]) {
        let run = [];
        for (let index = 0; index + 1 < buffer.length; index += 2) {
            const first = buffer[index];
            const second = buffer[index + 1];
            const value = littleEndian ? first: second;
            const zero = littleEndian ? second: first;
            if (zero === 0 && value >= 0x20 && value <= 0x7e) {
                run.push(value);
            } else {
                if (run.length >= 4) {
                    const text = safeIndicator(Buffer.from(run).toString("ascii"), limits);
                    if (text) strings.push(text);
                }
                run = [];
            }
            if (strings.length >= limits.maxStrings * 3) break;
        }
    }
    const bounded = uniqueBounded(strings, limits.maxStrings);
    const urls = [];
    for (const value of bounded) {
        for (const match of value.matchAll(URL_RE)) {
            const url = safeIndicator(match[0], limits);
            if (url) urls.push(url);
            if (urls.length >= limits.maxUrls) break;
        }
    }
    return {
        strings: bounded,
        urls: uniqueBounded(urls, limits.maxUrls),
    };
}

function machineName(kind, value) {
    const maps = {
        pe: {
            0x014c: "x86",
            0x8664: "x86-64",
            0x01c0: "arm",
            0xaa64: "arm64",
            0x0200: "ia64",
        },
        elf: {
            0x03: "x86",
            0x3e: "x86-64",
            0x28: "arm",
            0xb7: "arm64",
            0xf3: "riscv",
            0x08: "mips",
        },
        macho: {
            7: "x86",
            0x01000007: "x86-64",
            12: "arm",
            0x0100000c: "arm64",
            18: "powerpc",
            0x01000012: "powerpc64",
        },
    };
    return maps[kind]?.[value] || `machine-${value}`;
}

function parsePe(buffer, limits) {
    if (buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
        throw new Error("invalid DOS header");
    }
    const peOffset = buffer.readUInt32LE(0x3c);
    if (peOffset < 0x40 || peOffset + 24 > buffer.length
        || buffer.readUInt32LE(peOffset) !== 0x00004550) {
        throw new Error("invalid PE signature");
    }
    const machine = buffer.readUInt16LE(peOffset + 4);
    const sectionCount = buffer.readUInt16LE(peOffset + 6);
    const optionalSize = buffer.readUInt16LE(peOffset + 20);
    if (sectionCount > limits.maxSections || peOffset + 24 + optionalSize > buffer.length) {
        throw new Error("PE section or optional-header bounds exceeded");
    }
    const optionalOffset = peOffset + 24;
    const optionalMagic = buffer.readUInt16LE(optionalOffset);
    const is64 = optionalMagic === 0x20b;
    if (!is64 && optionalMagic !== 0x10b) throw new Error("unsupported PE optional header");
    const directoryOffset = optionalOffset + (is64 ? 112: 96);
    if (directoryOffset + 16 * 8 > optionalOffset + optionalSize) {
        throw new Error("truncated PE data directories");
    }
    const sections = [];
    const sectionOffset = optionalOffset + optionalSize;
    for (let index = 0; index < sectionCount; index += 1) {
        const offset = sectionOffset + index * 40;
        if (offset + 40 > buffer.length) throw new Error("truncated PE section table");
        const rawName = buffer.subarray(offset, offset + 8);
        const nul = rawName.indexOf(0);
        const name = safeIndicator(
            rawName.subarray(0, nul < 0 ? rawName.length: nul).toString("ascii"),
            limits,
        ) || `section-${index}`;
        sections.push({
            name,
            virtualSize: buffer.readUInt32LE(offset + 8),
            virtualAddress: buffer.readUInt32LE(offset + 12),
            rawSize: buffer.readUInt32LE(offset + 16),
            rawOffset: buffer.readUInt32LE(offset + 20),
            flags: `0x${buffer.readUInt32LE(offset + 36).toString(16)}`,
        });
    }
    function rvaToOffset(rva) {
        for (const section of sections) {
            const span = Math.max(section.virtualSize, section.rawSize);
            if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
                const offset = section.rawOffset + (rva - section.virtualAddress);
                if (offset < buffer.length) return offset;
            }
        }
        if (rva < buffer.length) return rva;
        throw new Error("PE RVA is outside mapped sections");
    }
    const exports = [];
    const exportRva = buffer.readUInt32LE(directoryOffset);
    const exportSize = buffer.readUInt32LE(directoryOffset + 4);
    if (exportRva !== 0 && exportSize !== 0) {
        const offset = rvaToOffset(exportRva);
        if (offset + 40 > buffer.length) throw new Error("truncated PE export directory");
        const namesCount = Math.min(buffer.readUInt32LE(offset + 24), limits.maxExports);
        const namesOffset = rvaToOffset(buffer.readUInt32LE(offset + 32));
        for (let index = 0; index < namesCount; index += 1) {
            if (namesOffset + index * 4 + 4 > buffer.length) break;
            const name = safeIndicator(
                readAsciiZ(buffer, rvaToOffset(buffer.readUInt32LE(namesOffset + index * 4))),
                limits,
            );
            if (name) exports.push(name);
        }
    }
    const imports = [];
    const importRva = buffer.readUInt32LE(directoryOffset + 8);
    const importSize = buffer.readUInt32LE(directoryOffset + 12);
    if (importRva !== 0 && importSize !== 0) {
        let descriptor = rvaToOffset(importRva);
        for (let count = 0; count < limits.maxImports; count += 1) {
            if (descriptor + 20 > buffer.length) throw new Error("truncated PE import table");
            const originalThunk = buffer.readUInt32LE(descriptor);
            const nameRva = buffer.readUInt32LE(descriptor + 12);
            const firstThunk = buffer.readUInt32LE(descriptor + 16);
            if (originalThunk === 0 && nameRva === 0 && firstThunk === 0) break;
            const library = safeIndicator(readAsciiZ(buffer, rvaToOffset(nameRva)), limits);
            if (!library) throw new Error("invalid PE import library name");
            let thunk = rvaToOffset(originalThunk || firstThunk);
            const width = is64 ? 8: 4;
            const ordinalMask = is64 ? 0x8000000000000000n: 0x80000000n;
            for (let item = 0; item < limits.maxImports - imports.length; item += 1) {
                if (thunk + width > buffer.length) throw new Error("truncated PE thunk table");
                const value = is64
                    ? buffer.readBigUInt64LE(thunk): BigInt(buffer.readUInt32LE(thunk));
                if (value === 0n) break;
                let imported;
                if ((value & ordinalMask) !== 0n) {
                    imported = `#${Number(value & 0xffffn)}`;
                } else {
                    const nameOffset = rvaToOffset(numberFromBigInt(value)) + 2;
                    imported = safeIndicator(readAsciiZ(buffer, nameOffset), limits);
                }
                if (imported) imports.push(`${library}!${imported}`);
                thunk += width;
            }
            descriptor += 20;
            if (imports.length >= limits.maxImports) break;
        }
    }
    const clrRva = buffer.readUInt32LE(directoryOffset + 14 * 8);
    const clrSize = buffer.readUInt32LE(directoryOffset + 14 * 8 + 4);
    const packed = sections.some((section) => PACKER_SECTION_RE.test(section.name));
    return {
        format: clrRva !== 0 && clrSize !== 0 ? "pe-dotnet": "pe",
        architecture: machineName("pe", machine),
        bitness: is64 ? 64: 32,
        endianness: "little",
        sections: sections.map(({ name, virtualSize, rawSize, flags }) => ({
            name,
            virtualSize,
            rawSize,
            flags,
        })),
        imports: uniqueBounded(imports, limits.maxImports),
        exports: uniqueBounded(exports, limits.maxExports),
        entries: clrRva !== 0 && clrSize !== 0 ? ["clr-header"]: [],
        packed,
    };
}

function numberFromBigInt(value) {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("binary offset exceeds safe range");
    return Number(value);
}

function parseElf(buffer, limits) {
    if (buffer.length < 52 || buffer.subarray(0, 4).toString("hex") !== "7f454c46") {
        throw new Error("invalid ELF header");
    }
    const elfClass = buffer[4];
    const data = buffer[5];
    const is64 = elfClass === 2;
    const little = data === 1;
    if (![1, 2].includes(elfClass) || ![1, 2].includes(data)) {
        throw new Error("unsupported ELF class or endianness");
    }
    const u16 = (offset) => little
        ? buffer.readUInt16LE(offset): buffer.readUInt16BE(offset);
    const u32 = (offset) => little
        ? buffer.readUInt32LE(offset): buffer.readUInt32BE(offset);
    const u64 = (offset) => numberFromBigInt(little
        ? buffer.readBigUInt64LE(offset): buffer.readBigUInt64BE(offset));
    const machine = u16(18);
    const shoff = is64 ? u64(40): u32(32);
    const shentsize = u16(is64 ? 58: 46);
    const shnum = u16(is64 ? 60: 48);
    const shstrndx = u16(is64 ? 62: 50);
    const minimumEntry = is64 ? 64: 40;
    if (shnum > limits.maxSections || shentsize < minimumEntry
        || shoff + shentsize * shnum > buffer.length || shstrndx >= shnum) {
        throw new Error("ELF section table exceeds bounds");
    }
    const rawSections = [];
    for (let index = 0; index < shnum; index += 1) {
        const offset = shoff + index * shentsize;
        rawSections.push({
            nameOffset: u32(offset),
            type: u32(offset + 4),
            offset: is64 ? u64(offset + 24): u32(offset + 16),
            size: is64 ? u64(offset + 32): u32(offset + 20),
            link: u32(offset + (is64 ? 40: 24)),
            entrySize: is64 ? u64(offset + 56): u32(offset + 36),
        });
    }
    const shstr = rawSections[shstrndx];
    if (shstr.offset + shstr.size > buffer.length) throw new Error("ELF shstrtab exceeds bounds");
    const sectionNames = buffer.subarray(shstr.offset, shstr.offset + shstr.size);
    const sections = rawSections.map((section, index) => {
        let name = `section-${index}`;
        if (section.nameOffset < sectionNames.length) {
            name = safeIndicator(readAsciiZ(sectionNames, section.nameOffset), limits) || name;
        }
        return { ...section, name };
    });
    const imports = [];
    const exports = [];
    for (const section of sections.filter((entry) => entry.type === 11)) {
        const strings = sections[section.link];
        if (!strings || strings.offset + strings.size > buffer.length
            || section.offset + section.size > buffer.length) {
            throw new Error("ELF dynamic symbol table exceeds bounds");
        }
        const stringBytes = buffer.subarray(strings.offset, strings.offset + strings.size);
        const entrySize = section.entrySize || (is64 ? 24: 16);
        const count = Math.min(
            Math.floor(section.size / entrySize),
            limits.maxImports + limits.maxExports,
        );
        for (let index = 0; index < count; index += 1) {
            const offset = section.offset + index * entrySize;
            const nameOffset = u32(offset);
            const info = buffer[offset + (is64 ? 4: 12)];
            const shndx = u16(offset + (is64 ? 6: 14));
            if ((info >> 4) === 0 || nameOffset === 0 || nameOffset >= stringBytes.length) {
                continue;
            }
            const name = safeIndicator(readAsciiZ(stringBytes, nameOffset), limits);
            if (!name) continue;
            if (shndx === 0) imports.push(name);
            else exports.push(name);
        }
    }
    const packed = sections.some((section) => PACKER_SECTION_RE.test(section.name));
    return {
        format: "elf",
        architecture: machineName("elf", machine),
        bitness: is64 ? 64: 32,
        endianness: little ? "little": "big",
        sections: sections.map((section) => ({
            name: section.name,
            type: section.type,
            size: section.size,
        })),
        imports: uniqueBounded(imports, limits.maxImports),
        exports: uniqueBounded(exports, limits.maxExports),
        entries: [],
        packed,
    };
}

function machInfo(buffer) {
    if (buffer.length < 4) return null;
    const bytes = buffer.subarray(0, 4).toString("hex");
    const map = {
        cefaedfe: { little: true, is64: false, fat: false },
        cffaedfe: { little: true, is64: true, fat: false },
        feedface: { little: false, is64: false, fat: false },
        feedfacf: { little: false, is64: true, fat: false },
        cafebabe: { little: false, is64: false, fat: true },
        bebafeca: { little: true, is64: false, fat: true },
    };
    return map[bytes] || null;
}

function parseMachO(buffer, limits) {
    const info = machInfo(buffer);
    if (!info) throw new Error("invalid Mach-O magic");
    const u32 = (offset) => info.little
        ? buffer.readUInt32LE(offset): buffer.readUInt32BE(offset);
    if (info.fat) {
        const count = u32(4);
        if (count > 64 || 8 + count * 20 > buffer.length) {
            throw new Error("fat Mach-O architecture table exceeds bounds");
        }
        const entries = [];
        for (let index = 0; index < count; index += 1) {
            entries.push(machineName("macho", u32(8 + index * 20)));
        }
        return {
            format: "mach-o-fat",
            architecture: "universal",
            bitness: null,
            endianness: info.little ? "little": "big",
            sections: [],
            imports: [],
            exports: [],
            entries: uniqueBounded(entries, limits.maxEntries),
            packed: false,
        };
    }
    const headerSize = info.is64 ? 32: 28;
    if (buffer.length < headerSize) throw new Error("truncated Mach-O header");
    const cpu = u32(4);
    const commandCount = u32(16);
    const commandBytes = u32(20);
    if (commandCount > limits.maxSections * 8
        || headerSize + commandBytes > buffer.length) {
        throw new Error("Mach-O load commands exceed bounds");
    }
    const sections = [];
    const imports = [];
    let symbolTable = null;
    let cursor = headerSize;
    for (let index = 0; index < commandCount; index += 1) {
        if (cursor + 8 > buffer.length) throw new Error("truncated Mach-O load command");
        const command = u32(cursor);
        const size = u32(cursor + 4);
        if (size < 8 || cursor + size > buffer.length) {
            throw new Error("invalid Mach-O load command size");
        }
        const baseCommand = command & 0x7fffffff;
        if (baseCommand === 1 || baseCommand === 0x19) {
            const is64Segment = baseCommand === 0x19;
            const countOffset = cursor + (is64Segment ? 64: 48);
            const sectionOffset = cursor + (is64Segment ? 72: 56);
            const sectionSize = is64Segment ? 80: 68;
            const count = u32(countOffset);
            if (count > limits.maxSections
                || sectionOffset + count * sectionSize > cursor + size) {
                throw new Error("Mach-O section table exceeds bounds");
            }
            for (let sectionIndex = 0; sectionIndex < count; sectionIndex += 1) {
                const offset = sectionOffset + sectionIndex * sectionSize;
                const rawName = buffer.subarray(offset, offset + 16);
                const nul = rawName.indexOf(0);
                const name = safeIndicator(
                    rawName.subarray(0, nul < 0 ? 16: nul).toString("ascii"),
                    limits,
                ) || `section-${sections.length}`;
                sections.push({
                    name,
                    size: info.is64
                        ? numberFromBigInt(info.little
                            ? buffer.readBigUInt64LE(offset + 40): buffer.readBigUInt64BE(offset + 40)): u32(offset + 36),
                });
            }
        } else if ([0x0c, 0x18, 0x1f, 0x20, 0x23].includes(baseCommand)) {
            const nameOffset = u32(cursor + 8);
            if (nameOffset >= size) throw new Error("Mach-O dylib name offset exceeds command");
            const name = safeIndicator(readAsciiZ(buffer, cursor + nameOffset), limits);
            if (name) imports.push(name);
        } else if (baseCommand === 2) {
            symbolTable = {
                symbolOffset: u32(cursor + 8),
                symbolCount: u32(cursor + 12),
                stringOffset: u32(cursor + 16),
                stringSize: u32(cursor + 20),
            };
        }
        cursor += size;
    }
    const exports = [];
    if (symbolTable) {
        const width = info.is64 ? 16: 12;
        if (symbolTable.symbolCount > limits.maxImports + limits.maxExports
            || symbolTable.symbolOffset + symbolTable.symbolCount * width > buffer.length
            || symbolTable.stringOffset + symbolTable.stringSize > buffer.length) {
            throw new Error("Mach-O symbol table exceeds bounds");
        }
        const strings = buffer.subarray(
            symbolTable.stringOffset,
            symbolTable.stringOffset + symbolTable.stringSize,
        );
        for (let index = 0; index < symbolTable.symbolCount; index += 1) {
            const offset = symbolTable.symbolOffset + index * width;
            const stringIndex = u32(offset);
            const type = buffer[offset + 4];
            if (stringIndex === 0 || stringIndex >= strings.length || (type & 1) === 0) continue;
            const name = safeIndicator(readAsciiZ(strings, stringIndex), limits);
            if (!name) continue;
            if ((type & 0x0e) === 0) imports.push(name);
            else exports.push(name);
        }
    }
    return {
        format: "mach-o",
        architecture: machineName("macho", cpu),
        bitness: info.is64 ? 64: 32,
        endianness: info.little ? "little": "big",
        sections,
        imports: uniqueBounded(imports, limits.maxImports),
        exports: uniqueBounded(exports, limits.maxExports),
        entries: [],
        packed: sections.some((section) => PACKER_SECTION_RE.test(section.name)),
    };
}

function readLeb(buffer, state, maximumBytes = 5) {
    let value = 0;
    let shift = 0;
    for (let count = 0; count < maximumBytes; count += 1) {
        if (state.offset >= buffer.length) throw new Error("truncated LEB128 value");
        const byte = buffer[state.offset++];
        value |= (byte & 0x7f) << shift;
        if ((byte & 0x80) === 0) return value >>> 0;
        shift += 7;
    }
    throw new Error("oversized LEB128 value");
}

function readWasmName(buffer, state, limits) {
    const length = readLeb(buffer, state);
    if (length > limits.maxIndicatorLength || state.offset + length > buffer.length) {
        throw new Error("Wasm name exceeds bounds");
    }
    const value = new TextDecoder("utf-8", { fatal: true })
        .decode(buffer.subarray(state.offset, state.offset + length));
    state.offset += length;
    return safeIndicator(value, limits);
}

function skipWasmLimits(buffer, state) {
    const flags = readLeb(buffer, state);
    readLeb(buffer, state);
    if ((flags & 1) !== 0) readLeb(buffer, state);
}

function parseWasm(buffer, limits) {
    if (buffer.length < 8 || buffer.subarray(0, 4).toString("hex") !== "0061736d"
        || buffer.readUInt32LE(4) !== 1) {
        throw new Error("invalid or unsupported WebAssembly header");
    }
    const sections = [];
    const imports = [];
    const exports = [];
    const entries = [];
    const state = { offset: 8 };
    while (state.offset < buffer.length) {
        const id = buffer[state.offset++];
        const size = readLeb(buffer, state);
        const end = state.offset + size;
        if (end > buffer.length || sections.length >= limits.maxSections) {
            throw new Error("WebAssembly section exceeds bounds");
        }
        let name = `section-${id}`;
        if (id === 0) {
            const custom = readWasmName(buffer, state, limits);
            name = custom ? `custom:${custom}`: "custom";
            entries.push(name);
        } else if (id === 2) {
            const count = readLeb(buffer, state);
            if (count > limits.maxImports) throw new Error("Wasm import count exceeds bounds");
            for (let index = 0; index < count; index += 1) {
                const module = readWasmName(buffer, state, limits);
                const field = readWasmName(buffer, state, limits);
                if (state.offset >= end) throw new Error("truncated Wasm import");
                const kind = buffer[state.offset++];
                if (kind === 0) readLeb(buffer, state);
                else if (kind === 1) {
                    state.offset += 1;
                    skipWasmLimits(buffer, state);
                } else if (kind === 2) skipWasmLimits(buffer, state);
                else if (kind === 3) state.offset += 2;
                else if (kind === 4) {
                    state.offset += 1;
                    readLeb(buffer, state);
                } else throw new Error("unsupported Wasm import kind");
                if (module && field) imports.push(`${module}.${field}`);
            }
        } else if (id === 7) {
            const count = readLeb(buffer, state);
            if (count > limits.maxExports) throw new Error("Wasm export count exceeds bounds");
            for (let index = 0; index < count; index += 1) {
                const nameValue = readWasmName(buffer, state, limits);
                state.offset += 1;
                readLeb(buffer, state);
                if (nameValue) exports.push(nameValue);
            }
        }
        if (state.offset > end) throw new Error("Wasm section parser crossed its boundary");
        state.offset = end;
        sections.push({ name, size });
    }
    return {
        format: "wasm",
        architecture: "wasm32",
        bitness: 32,
        endianness: "little",
        sections,
        imports: uniqueBounded(imports, limits.maxImports),
        exports: uniqueBounded(exports, limits.maxExports),
        entries: uniqueBounded(entries, limits.maxEntries),
        packed: false,
    };
}

class JavaReader {
    constructor(buffer) {
        this.buffer = buffer;
        this.offset = 0;
    }

    require(length) {
        if (this.offset + length > this.buffer.length) {
            throw new Error("truncated Java class");
        }
    }

    u1() {
        this.require(1);
        return this.buffer[this.offset++];
    }

    u2() {
        this.require(2);
        const value = this.buffer.readUInt16BE(this.offset);
        this.offset += 2;
        return value;
    }

    u4() {
        this.require(4);
        const value = this.buffer.readUInt32BE(this.offset);
        this.offset += 4;
        return value;
    }

    bytes(length) {
        this.require(length);
        const value = this.buffer.subarray(this.offset, this.offset + length);
        this.offset += length;
        return value;
    }
}

function skipJavaAttributes(reader, count) {
    for (let index = 0; index < count; index += 1) {
        reader.u2();
        const length = reader.u4();
        reader.bytes(length);
    }
}

function parseJavaClass(buffer, limits) {
    const reader = new JavaReader(buffer);
    if (reader.u4() !== 0xcafebabe) throw new Error("invalid Java class magic");
    const minor = reader.u2();
    const major = reader.u2();
    const count = reader.u2();
    if (count < 1 || count > limits.maxConstantPoolEntries) {
        throw new Error("Java constant pool exceeds bounds");
    }
    const pool = new Array(count);
    for (let index = 1; index < count; index += 1) {
        const tag = reader.u1();
        if (tag === 1) {
            const length = reader.u2();
            if (length > limits.maxIndicatorLength * 4) {
                throw new Error("Java UTF-8 constant exceeds bounds");
            }
            pool[index] = {
                tag,
                value: new TextDecoder("utf-8", { fatal: true }).decode(reader.bytes(length)),
            };
        } else if ([3, 4].includes(tag)) reader.bytes(4);
        else if ([5, 6].includes(tag)) {
            reader.bytes(8);
            index += 1;
        } else if ([7, 8, 16, 19, 20].includes(tag)) {
            pool[index] = { tag, index: reader.u2() };
        } else if ([9, 10, 11, 12, 17, 18].includes(tag)) {
            pool[index] = { tag, first: reader.u2(), second: reader.u2() };
        } else if (tag === 15) {
            reader.bytes(1);
            reader.bytes(2);
        } else {
            throw new Error(`unsupported Java constant-pool tag ${tag}`);
        }
    }
    reader.u2();
    const thisClass = reader.u2();
    reader.u2();
    const className = (classIndex) => {
        const entry = pool[classIndex];
        const utf = entry?.tag === 7 ? pool[entry.index]?.value: null;
        return safeIndicator(utf || "", limits);
    };
    const thisName = className(thisClass);
    const imports = [];
    for (const entry of pool) {
        if (entry?.tag !== 7) continue;
        const name = className(pool.indexOf(entry));
        if (name && name !== thisName && !name.startsWith("[")) imports.push(name);
    }
    const interfaceCount = reader.u2();
    reader.bytes(interfaceCount * 2);
    const exports = [];
    for (const kind of ["field", "method"]) {
        const memberCount = reader.u2();
        if (memberCount > limits.maxExports * 4) {
            throw new Error(`Java ${kind} count exceeds bounds`);
        }
        for (let index = 0; index < memberCount; index += 1) {
            const access = reader.u2();
            const nameIndex = reader.u2();
            reader.u2();
            const attributeCount = reader.u2();
            const name = safeIndicator(pool[nameIndex]?.value || "", limits);
            if (name && (access & 0x0005) !== 0) exports.push(`${kind}:${name}`);
            skipJavaAttributes(reader, attributeCount);
        }
    }
    skipJavaAttributes(reader, reader.u2());
    return {
        format: "java-class",
        architecture: "jvm",
        bitness: null,
        endianness: "big",
        sections: [{ name: "constant-pool", size: count - 1 }],
        imports: uniqueBounded(imports, limits.maxImports),
        exports: uniqueBounded(exports, limits.maxExports),
        entries: [
            `class-version:${major}.${minor}`,
            ...(thisName ? [`class:${thisName}`]: []),
        ],
        packed: false,
    };
}

function parsePackageSurface(archive, path, limits) {
    const paths = archive.entries.map((entry) => entry.path);
    const lower = paths.map((entry) => entry.toLowerCase());
    const jar = lower.includes("meta-inf/manifest.mf")
        || lower.some((entry) => entry.endsWith(".class"))
        || String(path || "").toLowerCase().endsWith(".jar");
    const dotnet = lower.some((entry) => entry.endsWith(".nuspec"))
        || lower.includes("[content_types].xml")
        || lower.some((entry) =>
            /^(?:lib|ref|runtimes)\/.+\.dll$/u.test(entry))
        || String(path || "").toLowerCase().endsWith(".nupkg");
    const entries = uniqueBounded(paths, limits.maxEntries);
    return {
        format: jar ? "java-jar": dotnet ? "dotnet-package": "zip-package",
        architecture: jar ? "jvm": dotnet ? "dotnet": "package",
        bitness: null,
        endianness: null,
        sections: [],
        imports: dotnet
            ? uniqueBounded(paths.filter((entry) =>
                /^(?:lib|ref|runtimes)\/.+\.dll$/iu.test(entry)), limits.maxImports): [],
        exports: jar
            ? uniqueBounded(paths.filter((entry) =>
                entry.toLowerCase().startsWith("meta-inf/services/")), limits.maxExports): [],
        entries,
        packed: false,
    };
}

export function detectBinaryFormat(buffer, { archive = null, path = "" } = {}) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError("binary input must be a Buffer");
    if (archive?.format === "zip") {
        return parsePackageSurface(archive, path, BINARY_METADATA_LIMITS).format;
    }
    if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) return "pe";
    if (buffer.length >= 4 && buffer.subarray(0, 4).toString("hex") === "7f454c46") {
        return "elf";
    }
    if (buffer.length >= 4 && buffer.subarray(0, 4).toString("hex") === "0061736d") {
        return "wasm";
    }
    if (buffer.length >= 10 && buffer.readUInt32BE(0) === 0xcafebabe
        && buffer.readUInt16BE(6) >= 45 && buffer.readUInt16BE(6) <= 100
        && buffer.readUInt16BE(8) >= 1) {
        return "java-class";
    }
    const mach = machInfo(buffer);
    if (mach) return mach.fat ? "mach-o-fat": "mach-o";
    return "unknown";
}

function parsedMetadata(buffer, archive, path, limits) {
    if (archive?.format === "zip") return parsePackageSurface(archive, path, limits);
    const format = detectBinaryFormat(buffer, { archive, path });
    if (format === "pe") return parsePe(buffer, limits);
    if (format === "elf") return parseElf(buffer, limits);
    if (format === "mach-o" || format === "mach-o-fat") {
        return parseMachO(buffer, limits);
    }
    if (format === "wasm") return parseWasm(buffer, limits);
    if (format === "java-class") return parseJavaClass(buffer, limits);
    throw new Error("unsupported binary format");
}

function resultHashPayload(metadata, strings) {
    return {
        ...metadata,
        strings,
    };
}

export function parseBinaryMetadata({
    buffer,
    sourceObject,
    sourceRange = null,
    transformChain = [],
    archive = null,
    path = sourceObject?.path || "",
    limits = BINARY_METADATA_LIMITS,
} = {}) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError("binary metadata requires a Buffer");
    const identity = sourceIdentity(sourceObject);
    const range = ensureRange(sourceRange, buffer);
    const blockerCodes = [...(archive?.blockerCodes || [])];
    let metadata;
    try {
        metadata = parsedMetadata(buffer, archive, path, limits);
        if (metadata.packed) {
            blockerCodes.push(EVASIVE_BLOCKERS.DECODE_PACKED_OR_HIGH_ENTROPY);
        }
    } catch (error) {
        const unsupported = error.message === "unsupported binary format";
        metadata = {
            format: "unknown",
            architecture: "unknown",
            bitness: null,
            endianness: null,
            sections: [],
            imports: [],
            exports: [],
            entries: [],
            packed: false,
        };
        blockerCodes.push(
            unsupported
                ? EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT: EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL,
        );
        if (unsupported && buffer.length >= 256) {
            const counts = new Uint32Array(256);
            for (const byte of buffer) counts[byte] += 1;
            let entropy = 0;
            for (const count of counts) {
                if (count === 0) continue;
                const probability = count / buffer.length;
                entropy -= probability * Math.log2(probability);
            }
            if (entropy >= 7.5) {
                blockerCodes.push(EVASIVE_BLOCKERS.DECODE_PACKED_OR_HIGH_ENTROPY);
            }
        }
    }
    const scanned = scanStrings(buffer, limits);
    metadata = {
        ...metadata,
        sections: metadata.sections.slice(0, limits.maxSections),
        imports: uniqueBounded(metadata.imports, limits.maxImports),
        exports: uniqueBounded(metadata.exports, limits.maxExports),
        entries: uniqueBounded(metadata.entries, limits.maxEntries),
        strings: scanned.strings,
        urls: scanned.urls,
    };
    const metadataSha256 = sha256(Buffer.from(
        JSON.stringify(resultHashPayload(metadata, scanned.strings)),
        "utf8",
    ));
    const priorChain = transformChain.map((entry) => Object.freeze({ ...entry }));
    const inputSha256 = priorChain.length > 0
        ? priorChain.at(-1).outputSha256: range.rangeSha256;
    const chain = Object.freeze([
        ...priorChain,
        Object.freeze({
            kind: "binary-metadata",
            inputSha256,
            outputSha256: metadataSha256,
        }),
    ]);
    const codes = Object.freeze([...new Set(blockerCodes)].sort());
    const derivationSha256 = sha256(Buffer.from(JSON.stringify({
        sourceObjectId: identity.objectId,
        sourceRange: range,
        transformChain: chain,
        metadataSha256,
        blockerCodes: codes,
    }), "utf8"));
    return Object.freeze({
        schemaVersion: 6,
        metadataId: `ztbm-${derivationSha256}`,
        sourceObjectId: identity.objectId,
        sourcePath: identity.path,
        sourceRange: range,
        transformChain: chain,
        status: codes.length === 0 ? "decoded": "blocked",
        blockerCodes: codes,
        analysisLevel: "metadata-only",
        disassemblyPerformed: false,
        format: metadata.format,
        architecture: metadata.architecture,
        bitness: metadata.bitness,
        endianness: metadata.endianness,
        sections: Object.freeze(metadata.sections.map((entry) => Object.freeze(entry))),
        imports: Object.freeze(metadata.imports),
        exports: Object.freeze(metadata.exports),
        strings: Object.freeze(metadata.strings),
        urls: Object.freeze(metadata.urls),
        entries: Object.freeze(metadata.entries),
        hashes: Object.freeze({
            sourceObjectSha256: identity.identitySha256,
            sourceRangeSha256: range.rangeSha256,
            binarySha256: sha256(buffer),
            metadataSha256,
            derivationSha256,
        }),
    });
}

export const __internals = Object.freeze({
    safeIndicator,
    scanStrings,
    parsePe,
    parseElf,
    parseMachO,
    parseWasm,
    parseJavaClass,
    parsePackageSurface,
    machInfo,
    readLeb,
});
