import { createHash } from "node:crypto";

import {
    ARCHIVE_READER_LIMITS,
    detectArchiveFormat,
    getArchiveEntryBytes,
    readArchive,
} from "./archiveReaders.mjs";
import {
    BINARY_METADATA_LIMITS,
    detectBinaryFormat,
    parseBinaryMetadata,
} from "./binaryMetadata.mjs";
import {
    DEOBFUSCATION_LIMITS,
    decodeStaticLiterals,
    getDecodedBytes,
} from "./deobfuscation.mjs";
import {
    EVASIVE_BLOCKERS,
    EVASIVE_LIMITS,
    createAssuranceAnalysisSnapshot,
    createEvasiveDerivedArtifactRecord,
    validateAssuranceAnalysisSnapshot,
} from "./evasiveSchemas.mjs";

export const DERIVED_ARTIFACT_LIMITS = Object.freeze({
    maxArtifactsPerObject: 1_024,
    maxRecursivePayloads: 512,
    maxTotalDecodedBytes: 32 * 1024 * 1024,
    maxNestedDepth: ARCHIVE_READER_LIMITS.maxNestedDepth,
});

const HARD_LIMITS = Object.freeze({
    maxArtifactsPerObject: 4_096,
    maxRecursivePayloads: 2_048,
    maxTotalDecodedBytes: 64 * 1024 * 1024,
    maxNestedDepth: 8,
});

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function descriptorHash(value) {
    return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

function boundedInteger(value, fallback, maximum, name, minimum = 1) {
    if (value === undefined) return fallback;
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}`);
    }
    return value;
}

function normalizeLimits(overrides = {}) {
    return Object.freeze({
        maxArtifactsPerObject: boundedInteger(
            overrides.maxArtifactsPerObject,
            DERIVED_ARTIFACT_LIMITS.maxArtifactsPerObject,
            HARD_LIMITS.maxArtifactsPerObject,
            "maxArtifactsPerObject",
        ),
        maxRecursivePayloads: boundedInteger(
            overrides.maxRecursivePayloads,
            DERIVED_ARTIFACT_LIMITS.maxRecursivePayloads,
            HARD_LIMITS.maxRecursivePayloads,
            "maxRecursivePayloads",
        ),
        maxTotalDecodedBytes: boundedInteger(
            overrides.maxTotalDecodedBytes,
            DERIVED_ARTIFACT_LIMITS.maxTotalDecodedBytes,
            HARD_LIMITS.maxTotalDecodedBytes,
            "maxTotalDecodedBytes",
        ),
        maxNestedDepth: boundedInteger(
            overrides.maxNestedDepth,
            DERIVED_ARTIFACT_LIMITS.maxNestedDepth,
            HARD_LIMITS.maxNestedDepth,
            "maxNestedDepth",
            0,
        ),
    });
}

function uniqueSorted(values, maximum = 16) {
    return [...new Set(values)].sort().slice(0, maximum);
}

function wholeRange(buffer) {
    return Object.freeze({
        startOffset: 0,
        endOffset: buffer.length,
        rangeSha256: sha256(buffer),
    });
}

function transform(kind, inputSha256, outputSha256) {
    return Object.freeze({ kind, inputSha256, outputSha256 });
}

function decodeUtf8(buffer) {
    if (buffer.length === 0 || buffer.includes(0)) return null;
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    } catch {
        return null;
    }
}

function safeArtifactPath(sourcePath, artifactKind, contentSha256) {
    const suffix = `#derived-${artifactKind}-${contentSha256.slice(0, 24)}`;
    const maximumBase = 4_096 - suffix.length;
    return `${sourcePath.slice(0, maximumBase)}${suffix}`;
}

function toArtifact(sourceObject, item) {
    const blockerCodes = uniqueSorted(item.blockerCodes || []);
    return createEvasiveDerivedArtifactRecord({
        auditId: sourceObject.auditId,
        sourceNamespace: sourceObject.sourceNamespace,
        path: safeArtifactPath(
            sourceObject.path,
            item.artifactKind,
            item.contentSha256,
        ),
        sourceObjectId: sourceObject.objectId,
        artifactKind: item.artifactKind,
        producer: item.producer,
        producerVersion: "1.0.0",
        byteLength: item.byteLength,
        status: blockerCodes.length === 0 ? "decoded": "blocked",
        blockerCodes,
        contentSha256: item.contentSha256,
        sourceObjectSha256: sourceObject.hashes.identitySha256,
        sourceRange: item.sourceRange,
        transformChain: item.transformChain,
    });
}

function artifactSummary(snapshot, sourceObject, artifacts, details, blockerCodes) {
    const byKind = {};
    const byStatus = {};
    for (const artifact of artifacts) {
        byKind[artifact.artifactKind] = (byKind[artifact.artifactKind] || 0) + 1;
        byStatus[artifact.status] = (byStatus[artifact.status] || 0) + 1;
    }
    const artifactIds = artifacts.map((artifact) => artifact.artifactId).sort();
    const normalizedDetails = {
        formats: [...details.formats].sort(),
        transformKinds: [...details.transformKinds].sort(),
        sections: details.sections,
        imports: details.imports,
        exports: details.exports,
        strings: details.strings,
        urls: details.urls,
        entries: details.entries,
    };
    const base = {
        schemaVersion: 6,
        snapshotId: snapshot.snapshotId,
        stage: snapshot.stageState.current,
        sourceObjectId: sourceObject.objectId,
        status: blockerCodes.length === 0 ? "decoded": "blocked",
        artifactCount: artifacts.length,
        artifactIds: Object.freeze(artifactIds),
        countsByKind: Object.freeze(byKind),
        countsByStatus: Object.freeze(byStatus),
        formats: Object.freeze(normalizedDetails.formats),
        transformKinds: Object.freeze(normalizedDetails.transformKinds),
        indicatorCounts: Object.freeze({
            sections: details.sections,
            imports: details.imports,
            exports: details.exports,
            strings: details.strings,
            urls: details.urls,
            entries: details.entries,
        }),
        blockerCodes: Object.freeze(blockerCodes),
    };
    return Object.freeze({
        ...base,
        hashes: Object.freeze({
            sourceObjectSha256: sourceObject.hashes.identitySha256,
            derivedArtifactsSha256: snapshot.hashes.derivedArtifactsSha256,
            summarySha256: descriptorHash(base),
        }),
    });
}

export function rebindDerivedArtifactSummary(summary, snapshot) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    const base = {
        schemaVersion: summary.schemaVersion,
        snapshotId: current.snapshotId,
        stage: current.stageState.current,
        sourceObjectId: summary.sourceObjectId,
        status: summary.status,
        artifactCount: summary.artifactCount,
        artifactIds: summary.artifactIds,
        countsByKind: summary.countsByKind,
        countsByStatus: summary.countsByStatus,
        formats: summary.formats,
        transformKinds: summary.transformKinds,
        indicatorCounts: summary.indicatorCounts,
        blockerCodes: summary.blockerCodes,
    };
    return Object.freeze({
        ...base,
        hashes: Object.freeze({
            sourceObjectSha256: summary.hashes.sourceObjectSha256,
            derivedArtifactsSha256: current.hashes.derivedArtifactsSha256,
            summarySha256: descriptorHash(base),
        }),
    });
}

function findSourceObject(snapshot, path, contentSha256) {
    const matches = snapshot.objectInventory.filter((record) =>
        record.path === path
        && record.status === "inventoried"
        && record.hashes.contentSha256 === contentSha256);
    if (matches.length !== 1) {
        throw new Error("derived analysis requires one exact inventoried assurance object identity");
    }
    return matches[0];
}

function appendTransformKinds(details, chain) {
    for (const entry of chain) details.transformKinds.add(entry.kind);
}

function addItem(state, item) {
    if (state.items.length >= state.limits.maxArtifactsPerObject) {
        state.blockerCodes.add(EVASIVE_BLOCKERS.BOUNDS_EXCEEDED);
        return false;
    }
    state.items.push(item);
    appendTransformKinds(state.details, item.transformChain);
    for (const code of item.blockerCodes || []) state.blockerCodes.add(code);
    return true;
}

function bridgeChain(prefixChain, inputSha256, rangeSha256) {
    if (prefixChain.length === 0 || inputSha256 === rangeSha256) {
        return [...prefixChain];
    }
    return [
        ...prefixChain,
        transform("identity", inputSha256, rangeSha256),
    ];
}

function addPayloadIndex(state, buffer, sourceRange, prefixChain, blockerCodes = []) {
    const descriptor = {
        byteLength: buffer.length,
        contentSha256: sha256(buffer),
        depth: state.depth,
        blockerCodes: uniqueSorted(blockerCodes),
    };
    const contentSha256 = descriptorHash(descriptor);
    const inputSha256 = prefixChain.length > 0
        ? prefixChain.at(-1).outputSha256: sourceRange.rangeSha256;
    addItem(state, {
        artifactKind: "payload-index",
        producer: "zerotrust-derived-artifacts",
        byteLength: Buffer.byteLength(canonicalJson(descriptor), "utf8"),
        contentSha256,
        sourceRange,
        transformChain: [
            ...prefixChain,
            transform("payload-index", inputSha256, contentSha256),
        ],
        blockerCodes,
    });
}

function addBinaryMetadata(state, buffer, sourceRange, prefixChain, archive) {
    const metadata = parseBinaryMetadata({
        buffer,
        sourceObject: state.sourceObject,
        sourceRange,
        transformChain: prefixChain,
        archive,
        path: state.logicalPath,
        limits: BINARY_METADATA_LIMITS,
    });
    state.details.formats.add(metadata.format);
    state.details.sections += metadata.sections.length;
    state.details.imports += metadata.imports.length;
    state.details.exports += metadata.exports.length;
    state.details.strings += metadata.strings.length;
    state.details.urls += metadata.urls.length;
    state.details.entries += metadata.entries.length;
    addItem(state, {
        artifactKind: "binary-metadata",
        producer: "zerotrust-binary-metadata",
        byteLength: Buffer.byteLength(canonicalJson({
            format: metadata.format,
            architecture: metadata.architecture,
            bitness: metadata.bitness,
            endianness: metadata.endianness,
            counts: {
                sections: metadata.sections.length,
                imports: metadata.imports.length,
                exports: metadata.exports.length,
                strings: metadata.strings.length,
                urls: metadata.urls.length,
                entries: metadata.entries.length,
            },
        }), "utf8"),
        contentSha256: metadata.hashes.metadataSha256,
        sourceRange,
        transformChain: metadata.transformChain,
        blockerCodes: metadata.blockerCodes,
    });
}

function archiveEntryChain({
    archive,
    entry,
    buffer,
    sourceRange,
    prefixChain,
}) {
    const contentSha256 = entry.hashes.contentSha256;
    const entryTransformKind = archive.format === "zip"
        ? "zip-entry": ["gzip", "deflate", "deflate-raw", "brotli"].includes(archive.format)
            ? archive.format: "tar-entry";
    if (prefixChain.length === 0 && archive.format !== "tar.gz") {
        return {
            sourceRange: entry.sourceRange,
            transformChain: [
                transform(
                    entryTransformKind,
                    entry.sourceRange.rangeSha256,
                    contentSha256,
                ),
            ],
        };
    }
    let chain = [...prefixChain];
    let inputSha256 = chain.length > 0
        ? chain.at(-1).outputSha256: sourceRange.rangeSha256;
    if (archive.format === "tar.gz" && prefixChain.length === 0) {
        const expandedSha256 = archive.hashes.expandedContainerSha256;
        chain.push(transform("gzip", sha256(buffer), expandedSha256));
        inputSha256 = expandedSha256;
    }
    chain = bridgeChain(chain, inputSha256, entry.sourceRange.rangeSha256);
    chain.push(transform(
        entryTransformKind,
        entry.sourceRange.rangeSha256,
        contentSha256,
    ));
    return { sourceRange, transformChain: chain };
}

function processArchive(state, buffer, sourceRange, prefixChain, archive) {
    state.details.formats.add(archive.format);
    state.details.entries += archive.entries.length;
    const manifestSha256 = archive.hashes.inventorySha256;
    const inputSha256 = prefixChain.length > 0
        ? prefixChain.at(-1).outputSha256: sourceRange.rangeSha256;
    addItem(state, {
        artifactKind: "archive-manifest",
        producer: "zerotrust-archive-reader",
        byteLength: Buffer.byteLength(canonicalJson({
            format: archive.format,
            totals: archive.totals,
            entryHashes: archive.entries.map((entry) => entry.hashes.contentSha256),
        }), "utf8"),
        contentSha256: manifestSha256,
        sourceRange,
        transformChain: [
            ...prefixChain,
            transform("archive-manifest", inputSha256, manifestSha256),
        ],
        blockerCodes: archive.blockerCodes,
    });
    if (archive.format === "zip") {
        addBinaryMetadata(state, buffer, sourceRange, prefixChain, archive);
    }
    for (const entry of archive.entries) {
        if (entry.entryKind === "directory") continue;
        if (state.budget.payloads >= state.limits.maxRecursivePayloads) {
            state.blockerCodes.add(EVASIVE_BLOCKERS.BOUNDS_EXCEEDED);
            break;
        }
        const bound = archiveEntryChain({
            archive,
            entry,
            buffer,
            sourceRange,
            prefixChain,
        });
        const entryBytes = getArchiveEntryBytes(entry);
        addItem(state, {
            artifactKind: entryBytes && decodeUtf8(entryBytes)
                ? "decoded-text": "decoded-binary",
            producer: "zerotrust-archive-reader",
            byteLength: entry.expandedBytes,
            contentSha256: entry.hashes.contentSha256,
            sourceRange: bound.sourceRange,
            transformChain: bound.transformChain,
            blockerCodes: entry.blockerCodes,
        });
        if (!entryBytes || entry.blockerCodes.length > 0) continue;
        state.budget.payloads += 1;
        state.budget.totalDecodedBytes += entryBytes.length;
        if (state.budget.totalDecodedBytes > state.limits.maxTotalDecodedBytes) {
            state.blockerCodes.add(EVASIVE_BLOCKERS.BOUNDS_EXCEEDED);
            break;
        }
        processPayload({
            ...state,
            buffer: entryBytes,
            logicalPath: entry.path,
            sourceRange: bound.sourceRange,
            prefixChain: bound.transformChain,
            depth: state.depth + 1,
            addRootIndex: false,
            forceBinary: false,
        });
    }
}

function processDecoders(state, buffer, text, sourceRange, prefixChain) {
    const decoded = decodeStaticLiterals({
        text,
        sourceObject: state.sourceObject,
        limits: {
            ...DEOBFUSCATION_LIMITS,
            maxDecodedBytes: Math.min(
                DEOBFUSCATION_LIMITS.maxDecodedBytes,
                state.limits.maxTotalDecodedBytes,
            ),
            maxTransformDepth: state.limits.maxNestedDepth * 2 + 4,
        },
    });
    for (const code of decoded.blockerCodes) state.blockerCodes.add(code);
    for (const output of decoded.outputs) {
        if (state.items.length >= state.limits.maxArtifactsPerObject) break;
        const bytes = getDecodedBytes(output);
        let boundRange = output.sourceRange;
        let chain = output.transformChain;
        if (prefixChain.length > 0) {
            const inputSha256 = prefixChain.at(-1).outputSha256;
            chain = [
                ...bridgeChain(prefixChain, inputSha256, output.sourceRange.rangeSha256),
                ...output.transformChain,
            ];
            boundRange = sourceRange;
        }
        addItem(state, {
            artifactKind: output.indicators.printableAsciiRatio >= 0.8
                ? "deobfuscated-view": "decoded-binary",
            producer: "zerotrust-static-decoder",
            byteLength: output.byteLength,
            contentSha256: output.hashes.contentSha256,
            sourceRange: boundRange,
            transformChain: chain,
            blockerCodes: output.blockerCodes,
        });
        if (!bytes || output.blockerCodes.length > 0
            || state.budget.payloads >= state.limits.maxRecursivePayloads) continue;
        state.budget.payloads += 1;
        state.budget.totalDecodedBytes += bytes.length;
        if (state.budget.totalDecodedBytes > state.limits.maxTotalDecodedBytes) {
            state.blockerCodes.add(EVASIVE_BLOCKERS.BOUNDS_EXCEEDED);
            break;
        }
        processPayload({
            ...state,
            buffer: bytes,
            logicalPath: state.logicalPath,
            sourceRange: boundRange,
            prefixChain: chain,
            depth: state.depth + 1,
            addRootIndex: false,
            forceBinary: false,
        });
    }
}

function processPayload(state) {
    if (state.depth > state.limits.maxNestedDepth) {
        state.blockerCodes.add(EVASIVE_BLOCKERS.NESTED_DEPTH_EXCEEDED);
        addPayloadIndex(
            state,
            state.buffer,
            state.sourceRange,
            state.prefixChain,
            [EVASIVE_BLOCKERS.NESTED_DEPTH_EXCEEDED],
        );
        return;
    }
    const contentSha256 = sha256(state.buffer);
    const visitKey = `${contentSha256}:${state.depth}`;
    if (state.visited.has(visitKey)) return;
    state.visited.add(visitKey);
    if (state.addRootIndex) {
        addPayloadIndex(state, state.buffer, state.sourceRange, state.prefixChain);
    }
    const archiveFormat = detectArchiveFormat(state.buffer, {
        path: state.logicalPath,
    });
    if (archiveFormat) {
        const archive = readArchive(state.buffer, {
            path: state.logicalPath,
            depth: state.depth,
            limits: {
                maxNestedDepth: state.limits.maxNestedDepth,
                maxExpandedBytes: Math.min(
                    ARCHIVE_READER_LIMITS.maxExpandedBytes,
                    state.limits.maxTotalDecodedBytes,
                ),
            },
        });
        processArchive(state, state.buffer, state.sourceRange, state.prefixChain, archive);
        return;
    }
    const binaryFormat = detectBinaryFormat(state.buffer, {
        path: state.logicalPath,
    });
    if (binaryFormat !== "unknown" || state.forceBinary) {
        addBinaryMetadata(state, state.buffer, state.sourceRange, state.prefixChain, null);
    }
    const text = decodeUtf8(state.buffer);
    if (text !== null) {
        processDecoders(
            state,
            state.buffer,
            text,
            state.sourceRange,
            state.prefixChain,
        );
    }
}

export function applyDerivedArtifactsToSnapshot({
    snapshot,
    artifacts,
    blockerCodes = [],
    stageState = snapshot?.stageState,
} = {}) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    const merged = new Map(
        current.derivedArtifacts.map((artifact) => [artifact.artifactId, artifact]),
    );
    for (const artifact of artifacts || []) merged.set(artifact.artifactId, artifact);
    const records = [...merged.values()];
    if (records.length > EVASIVE_LIMITS.derivedArtifactRecords) {
        throw new Error("assurance derived artifact snapshot limit exceeded");
    }
    return createAssuranceAnalysisSnapshot({
        auditId: current.auditId,
        sourceNamespace: current.sourceNamespace,
        stageState,
        status: "incomplete",
        objectInventory: current.objectInventory,
        derivedArtifacts: records,
        semanticReviewCoverage: current.semanticReviewCoverage,
        semanticCandidateLedger: current.semanticCandidateLedger,
        redTeamCoverage: current.redTeamCoverage,
        blockerCodes: uniqueSorted([
            ...current.blockerCodes,
            ...blockerCodes,
            ...records.flatMap((artifact) => artifact.blockerCodes),
        ], EVASIVE_LIMITS.snapshotBlockerCodes),
        sourceIdentitySha256: current.hashes.sourceIdentitySha256,
    });
}

export function derivedSnapshotCanAdvance(snapshot) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    if (current.stageState.current !== "inventoried"
        || current.blockerCodes.length > 0) return false;
    const eligible = current.objectInventory.filter((record) =>
        record.status === "inventoried"
        && record.objectKind !== "tree"
        && record.hashes.contentSha256 !== null);
    if (eligible.length === 0) return true;
    const artifactsByObject = new Map();
    for (const artifact of current.derivedArtifacts) {
        if (!artifactsByObject.has(artifact.sourceObjectId)) {
            artifactsByObject.set(artifact.sourceObjectId, []);
        }
        artifactsByObject.get(artifact.sourceObjectId).push(artifact);
    }
    return eligible.every((object) => {
        const artifacts = artifactsByObject.get(object.objectId) || [];
        return artifacts.some((artifact) => artifact.artifactKind === "payload-index")
            && artifacts.every((artifact) => artifact.status === "decoded");
    });
}

export function buildDerivedArtifacts({
    snapshot,
    path,
    buffer,
    limits: limitOverrides = {},
} = {}) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError("derived analysis requires a Buffer");
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    const sourceObject = findSourceObject(current, path, sha256(buffer));
    const limits = normalizeLimits(limitOverrides);
    const shared = {
        sourceObject,
        limits,
        items: [],
        blockerCodes: new Set(),
        visited: new Set(),
        budget: {
            payloads: 0,
            totalDecodedBytes: buffer.length,
        },
        details: {
            formats: new Set(),
            transformKinds: new Set(),
            sections: 0,
            imports: 0,
            exports: 0,
            strings: 0,
            urls: 0,
            entries: 0,
        },
    };
    processPayload({
        ...shared,
        buffer,
        logicalPath: path,
        sourceRange: wholeRange(buffer),
        prefixChain: [],
        depth: 0,
        addRootIndex: true,
        forceBinary: ["binary", "opaque", "executable-blob", "release-asset"]
            .includes(sourceObject.objectKind),
    });
    const artifacts = shared.items.map((item) => toArtifact(sourceObject, item));
    const blockerCodes = uniqueSorted([
        ...shared.blockerCodes,
        ...artifacts.flatMap((artifact) => artifact.blockerCodes),
    ], EVASIVE_LIMITS.snapshotBlockerCodes);
    const nextSnapshot = applyDerivedArtifactsToSnapshot({
        snapshot: current,
        artifacts,
        blockerCodes,
    });
    return Object.freeze({
        snapshot: nextSnapshot,
        artifacts: Object.freeze(artifacts),
        summary: artifactSummary(
            nextSnapshot,
            sourceObject,
            artifacts,
            shared.details,
            blockerCodes,
        ),
        decodeComplete: derivedSnapshotCanAdvance(nextSnapshot),
    });
}

export const __internals = Object.freeze({
    canonicalJson,
    descriptorHash,
    normalizeLimits,
    wholeRange,
    safeArtifactPath,
    findSourceObject,
    archiveEntryChain,
    decodeUtf8,
});
