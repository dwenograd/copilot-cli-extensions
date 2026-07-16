import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
    brotliCompressSync,
    deflateRawSync,
    deflateSync,
    gzipSync,
} from "node:zlib";

import {
    EVASIVE_BLOCKERS,
    buildDerivedArtifacts,
    createInitialAssuranceStageState,
    createAssuranceAnalysisSnapshot,
    createEvasiveObjectInventoryRecord,
    decodeStaticLiterals,
    getArchiveEntryBytes,
    getDecodedBytes,
    parseBinaryMetadata,
    readArchive,
    readCompressedPayload,
    transitionAssuranceStageState,
    validateEvasiveDerivedArtifactRecord,
} from "../analysis/index.mjs";
import {
    __internals as archiveInternals,
} from "../analysis/archiveReaders.mjs";

const AUDIT_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_NAMESPACE = "github.com/example/repo@" + "a".repeat(40);

function sha256(buffer) {
    return createHash("sha256").update(buffer).digest("hex");
}

function sourceObject(buffer, path = "payload.bin", objectKind = "binary") {
    return createEvasiveObjectInventoryRecord({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        path,
        parentObjectId: null,
        objectKind,
        byteLength: buffer.length,
        status: "inventoried",
        blockerCodes: [],
        contentSha256: sha256(buffer),
        upstreamSha: null,
    });
}

function inventoriedSnapshot(object) {
    const acquired = createInitialAssuranceStageState({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
    });
    const stageState = transitionAssuranceStageState(acquired, {
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        from: "acquired",
        to: "inventoried",
    });
    return createAssuranceAnalysisSnapshot({
        auditId: AUDIT_ID,
        sourceNamespace: SOURCE_NAMESPACE,
        stageState,
        status: "incomplete",
        objectInventory: [object],
        derivedArtifacts: [],
        semanticReviewCoverage: [],
        redTeamCoverage: [],
        blockerCodes: [],
        sourceIdentitySha256: "b".repeat(64),
    });
}

function tarOctal(value, length) {
    return `${value.toString(8).padStart(length - 1, "0")}\0`;
}

function makeTar(entries) {
    const blocks = [];
    for (const [path, content] of entries) {
        const bytes = Buffer.from(content);
        const header = Buffer.alloc(512);
        header.write(path, 0, 100, "ascii");
        header.write(tarOctal(0o644, 8), 100, 8, "ascii");
        header.write(tarOctal(0, 8), 108, 8, "ascii");
        header.write(tarOctal(0, 8), 116, 8, "ascii");
        header.write(tarOctal(bytes.length, 12), 124, 12, "ascii");
        header.write(tarOctal(0, 12), 136, 12, "ascii");
        header.fill(0x20, 148, 156);
        header[156] = 0x30;
        header.write("ustar\0", 257, 6, "ascii");
        header.write("00", 263, 2, "ascii");
        let checksum = 0;
        for (const byte of header) checksum += byte;
        header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
        blocks.push(header, bytes);
        const padding = (512 - (bytes.length % 512)) % 512;
        if (padding) blocks.push(Buffer.alloc(padding));
    }
    blocks.push(Buffer.alloc(1024));
    return Buffer.concat(blocks);
}

function makeZip(entries, { deflate = false, encrypted = false } = {}) {
    const locals = [];
    const centrals = [];
    let localOffset = 0;
    for (const [path, content] of entries) {
        const name = Buffer.from(path, "utf8");
        const bytes = Buffer.from(content);
        const compressed = deflate ? deflateRawSync(bytes): bytes;
        const method = deflate ? 8: 0;
        const crc = archiveInternals.crc32(bytes);
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4);
        local.writeUInt16LE(0x0800 | (encrypted ? 1: 0), 6);
        local.writeUInt16LE(method, 8);
        local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(compressed.length, 18);
        local.writeUInt32LE(bytes.length, 22);
        local.writeUInt16LE(name.length, 26);
        const localRecord = Buffer.concat([local, name, compressed]);
        locals.push(localRecord);

        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0);
        central.writeUInt16LE(20, 4);
        central.writeUInt16LE(20, 6);
        central.writeUInt16LE(0x0800 | (encrypted ? 1: 0), 8);
        central.writeUInt16LE(method, 10);
        central.writeUInt32LE(crc, 16);
        central.writeUInt32LE(compressed.length, 20);
        central.writeUInt32LE(bytes.length, 24);
        central.writeUInt16LE(name.length, 28);
        central.writeUInt32LE(localOffset, 42);
        centrals.push(Buffer.concat([central, name]));
        localOffset += localRecord.length;
    }
    const centralBytes = Buffer.concat(centrals);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(entries.length, 8);
    eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(centralBytes.length, 12);
    eocd.writeUInt32LE(localOffset, 16);
    return Buffer.concat([...locals, centralBytes, eocd]);
}

function leb(value) {
    const bytes = [];
    do {
        let byte = value & 0x7f;
        value >>>= 7;
        if (value) byte |= 0x80;
        bytes.push(byte);
    } while (value);
    return Buffer.from(bytes);
}

function wasmWithImportExport() {
    const name = (value) => Buffer.concat([leb(value.length), Buffer.from(value)]);
    const imports = Buffer.concat([
        leb(1),
        name("env"),
        name("run"),
        Buffer.from([0]),
        leb(0),
    ]);
    const exports = Buffer.concat([
        leb(1),
        name("start"),
        Buffer.from([0]),
        leb(0),
    ]);
    return Buffer.concat([
        Buffer.from("0061736d01000000", "hex"),
        Buffer.from([2]),
        leb(imports.length),
        imports,
        Buffer.from([7]),
        leb(exports.length),
        exports,
    ]);
}

function minimalPe() {
    const buffer = Buffer.alloc(0x80 + 24 + 240);
    buffer.write("MZ", 0, "ascii");
    buffer.writeUInt32LE(0x80, 0x3c);
    buffer.writeUInt32LE(0x00004550, 0x80);
    buffer.writeUInt16LE(0x8664, 0x84);
    buffer.writeUInt16LE(0, 0x86);
    buffer.writeUInt16LE(240, 0x94);
    buffer.writeUInt16LE(0x20b, 0x98);
    return buffer;
}

function minimalElf() {
    const buffer = Buffer.alloc(129);
    Buffer.from("7f454c46", "hex").copy(buffer);
    buffer[4] = 2;
    buffer[5] = 1;
    buffer.writeUInt16LE(0x3e, 18);
    buffer.writeBigUInt64LE(64n, 40);
    buffer.writeUInt16LE(64, 58);
    buffer.writeUInt16LE(1, 60);
    buffer.writeUInt16LE(0, 62);
    buffer.writeUInt32LE(3, 68);
    buffer.writeBigUInt64LE(128n, 88);
    buffer.writeBigUInt64LE(1n, 96);
    return buffer;
}

function minimalMachO() {
    const buffer = Buffer.alloc(32);
    buffer.writeUInt32LE(0xfeedfacf, 0);
    buffer.writeUInt32LE(0x01000007, 4);
    return buffer;
}

function minimalJavaClass() {
    const buffer = Buffer.alloc(24);
    buffer.writeUInt32BE(0xcafebabe, 0);
    buffer.writeUInt16BE(61, 6);
    buffer.writeUInt16BE(1, 8);
    return buffer;
}

test("bounded archive readers inventory tar, tar.gz, gzip, deflate, brotli, and ZIP in memory", () => {
    const tar = makeTar([["nested/payload.txt", "hello"]]);
    const tarResult = readArchive(tar, { path: "fixture.tar" });
    assert.equal(tarResult.status, "decoded");
    assert.equal(getArchiveEntryBytes(tarResult.entries[0]).toString(), "hello");

    const tgz = readArchive(gzipSync(tar), { path: "fixture.tar.gz" });
    assert.equal(tgz.format, "tar.gz");
    assert.equal(tgz.entries[0].path, "nested/payload.txt");

    for (const [format, compressed] of [
        ["gzip", gzipSync(Buffer.from("gzip payload"))],
        ["deflate", deflateSync(Buffer.from("deflate payload"))],
        ["brotli", brotliCompressSync(Buffer.from("brotli payload"))],
    ]) {
        const result = readCompressedPayload(compressed, { format });
        assert.equal(result.status, "decoded");
        assert.ok(getArchiveEntryBytes(result.entries[0]).length > 0);
    }

    const zip = readArchive(makeZip([["bin/payload.bin", Buffer.from([1, 2, 3])]]), {
        path: "fixture.zip",
    });
    assert.equal(zip.status, "decoded");
    assert.equal(zip.entries[0].path, "bin/payload.bin");
    assert.equal(JSON.stringify(zip).includes("AQID"), false);
});

test("archive readers fail closed for malformed paths, malformed structure, and expansion ratios", () => {
    const unsafe = readArchive(makeZip([["../escape.txt", "no"]]), {
        path: "unsafe.zip",
    });
    assert.ok(unsafe.blockerCodes.includes(EVASIVE_BLOCKERS.DECODE_UNSAFE_ARCHIVE_PATH));

    const malformed = readArchive(Buffer.from("504b0304", "hex"), {
        path: "bad.zip",
    });
    assert.ok(malformed.blockerCodes.includes(EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL));

    const encrypted = readArchive(makeZip([["secret.bin", "ciphertext"]], {
        encrypted: true,
    }), { path: "encrypted.zip" });
    assert.ok(encrypted.blockerCodes.includes(EVASIVE_BLOCKERS.DECODE_ENCRYPTED));

    const tooMany = readArchive(makeZip([["a", "1"], ["b", "2"]]), {
        path: "entries.zip",
        limits: { maxEntries: 1 },
    });
    assert.ok(
        tooMany.blockerCodes.includes(EVASIVE_BLOCKERS.ARCHIVE_ENTRY_LIMIT_EXCEEDED),
    );

    const expandedCap = readArchive(makeZip([["large.bin", Buffer.alloc(64)]]), {
        path: "expanded.zip",
        limits: { maxExpandedBytes: 32 },
    });
    assert.ok(expandedCap.blockerCodes.includes(EVASIVE_BLOCKERS.BOUNDS_EXCEEDED));

    const bomb = readArchive(makeZip([["bomb.bin", Buffer.alloc(32_768)]], {
        deflate: true,
    }), {
        path: "bomb.zip",
        limits: { maxCompressionRatio: 2 },
    });
    assert.ok(bomb.blockerCodes.includes(EVASIVE_BLOCKERS.EXPANSION_RATIO_EXCEEDED));
    assert.equal(getArchiveEntryBytes(bomb.entries[0]), null);
});

test("static decoders preserve source ranges, transform hashes, XOR, compression, and entropy blockers", () => {
    const compressed = gzipSync(Buffer.from("compressed literal")).toString("base64");
    const entropy = Buffer.from(Array.from({ length: 512 }, (_, index) => index & 0xff))
        .toString("base64");
    const text = [
        "const a = \"SGVsbG8h\";",
        "const h = \"48656c6c6f20576f726c64\";",
        "const e = \"\\x48\\x69\";",
        "const c = \"U0dW\" + \"c2JHOGg=\";",
        "const x = [0x68, 0x45, 0x4c, 0x4c, 0x4f].map(v => v ^ 0x20);",
        `const gz = gunzip("${compressed}");`,
        `const packed = "${entropy}";`,
    ].join("\n");
    const bytes = Buffer.from(text);
    const decoded = decodeStaticLiterals({
        text,
        sourceObject: sourceObject(bytes, "encoded.mjs", "source-text"),
    });
    const kinds = new Set(decoded.outputs.map((output) => output.decoderKind));
    assert.ok(kinds.has("base64"));
    assert.ok(kinds.has("hex"));
    assert.ok(kinds.has("escaped-string"));
    assert.ok(kinds.has("xor"));
    assert.ok(decoded.outputs.some((output) =>
        output.transformChain.some((step) => step.kind === "literal-concatenation")));
    assert.ok(decoded.outputs.some((output) =>
        output.transformChain.some((step) => step.kind === "gzip")));
    assert.ok(decoded.outputs.some((output) =>
        output.blockerCodes.includes(EVASIVE_BLOCKERS.DECODE_PACKED_OR_HIGH_ENTROPY)));
    for (const output of decoded.outputs) {
        assert.equal(output.sourceObjectId.startsWith("zto-"), true);
        assert.equal(output.transformChain[0].inputSha256, output.sourceRange.rangeSha256);
        assert.equal(output.transformChain.at(-1).outputSha256, output.hashes.contentSha256);
        assert.ok(Buffer.isBuffer(getDecodedBytes(output)));
    }
});

test("metadata-only parsers cover PE, ELF, Mach-O, Wasm, Java class, JAR, and .NET ZIP surfaces", () => {
    for (const [expected, buffer] of [
        ["pe", minimalPe()],
        ["elf", minimalElf()],
        ["mach-o", minimalMachO()],
        ["wasm", wasmWithImportExport()],
        ["java-class", minimalJavaClass()],
    ]) {
        const metadata = parseBinaryMetadata({
            buffer,
            sourceObject: sourceObject(buffer, `${expected}.bin`),
        });
        assert.equal(metadata.format, expected);
        assert.equal(metadata.analysisLevel, "metadata-only");
        assert.equal(metadata.disassemblyPerformed, false);
        assert.equal(metadata.status, "decoded");
    }

    const wasm = wasmWithImportExport();
    const wasmMetadata = parseBinaryMetadata({
        buffer: wasm,
        sourceObject: sourceObject(wasm, "module.wasm"),
    });
    assert.ok(wasmMetadata.imports.includes("env.run"));
    assert.ok(wasmMetadata.exports.includes("start"));

    for (const [expected, path, entries] of [
        ["java-jar", "sample.jar", [["META-INF/MANIFEST.MF", "Manifest-Version: 1.0"]]],
        ["dotnet-package", "sample.nupkg", [
            ["sample.nuspec", "<package/>"],
            ["lib/net8.0/sample.dll", Buffer.from("MZ")],
        ]],
    ]) {
        const buffer = makeZip(entries);
        const archive = readArchive(buffer, { path });
        const metadata = parseBinaryMetadata({
            buffer,
            sourceObject: sourceObject(buffer, path),
            archive,
            path,
        });
        assert.equal(metadata.format, expected);
        assert.ok(metadata.entries.length > 0);
    }
});

test("derived records update assurance snapshots additively, cap recursion, and keep source text private", () => {
    let nested = Buffer.from("TOP_SECRET_MARKER");
    for (let depth = 0; depth < 5; depth += 1) {
        nested = makeZip([[`level-${depth}.zip`, nested]]);
    }
    const object = sourceObject(nested, "nested.zip");
    const built = buildDerivedArtifacts({
        snapshot: inventoriedSnapshot(object),
        path: object.path,
        buffer: nested,
        limits: { maxNestedDepth: 2 },
    });
    assert.ok(built.snapshot.derivedArtifacts.length > 0);
    assert.ok(built.summary.blockerCodes.includes(EVASIVE_BLOCKERS.NESTED_DEPTH_EXCEEDED));
    assert.equal(built.decodeComplete, false);
    assert.equal(JSON.stringify(built.summary).includes("TOP_SECRET_MARKER"), false);
    assert.equal(JSON.stringify(built.snapshot).includes("TOP_SECRET_MARKER"), false);
    for (const artifact of built.artifacts) {
        assert.deepEqual(validateEvasiveDerivedArtifactRecord(artifact), artifact);
        assert.ok(artifact.sourceRange);
        assert.ok(artifact.transformChain.length > 0);
    }
    assert.throws(() => validateEvasiveDerivedArtifactRecord({
            ...built.artifacts[0],
            transformChain: [{
                ...built.artifacts[0].transformChain[0],
                outputSha256: "f".repeat(64),
            }],
        }),
        /transform|deterministic/,
    );
});

test("unknown high-entropy binaries are blocked, never reported as benign metadata", () => {
    const buffer = Buffer.from(Array.from({ length: 1024 }, (_, index) => index & 0xff));
    const metadata = parseBinaryMetadata({
        buffer,
        sourceObject: sourceObject(buffer, "opaque.bin"),
    });
    assert.equal(metadata.status, "blocked");
    assert.ok(metadata.blockerCodes.includes(EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT));
    assert.ok(
        metadata.blockerCodes.includes(EVASIVE_BLOCKERS.DECODE_PACKED_OR_HIGH_ENTROPY),
    );
});
