import { createHash } from "node:crypto";

import { validateAuditId } from "./schemas.mjs";
import { EXTRACTION_LIMITS, FACT_KINDS } from "./extractFacts.mjs";

export const ANALYSIS_INDEX_SCHEMA_REVISION = 1;

export const ANALYSIS_INDEX_LIMITS = Object.freeze({
    trackedFiles: 50_000,
    factsPerFile: EXTRACTION_LIMITS.factsPerFile,
    factsPerAudit: 20_000,
    blockers: 100,
    blockerMessage: 300,
    snapshotPaths: 50,
});

export const ANALYSIS_SOURCE_KINDS = Object.freeze([
    "api-direct",
    "local-source",
    "build-clone",
    "metadata-only",
]);

const COMPLETE_FILE_STATUSES = new Set(["indexed-text", "classified-binary"]);
const CLASSIFICATIONS = new Set(["text", "binary", "unknown"]);
const SHA256_RE = /^[a-f0-9]{64}$/u;
const BLOB_SHA_RE = /^[a-f0-9]{40}$/u;

function clone(value) {
    return structuredClone(value);
}

function normalizePath(path) {
    const normalized = String(path || "").replace(/\\/g, "/").replace(/^\.\/+/, "");
    if (!normalized || normalized.length > 1024 || normalized.startsWith("/")
        || normalized.endsWith("/") || normalized.includes("//")
        || normalized.split("/").some((segment) => segment === "." || segment === "..")
        || /[\u0000-\u001f\u007f]/u.test(normalized)) {
        throw new Error(`invalid analysis-index path: ${JSON.stringify(path)}`);
    }
    return normalized;
}

function normalizeEntry(entry) {
    if (!entry || typeof entry !== "object") throw new Error("index entry must be an object");
    const path = normalizePath(entry.path);
    const size = Number(entry.size);
    if (!Number.isSafeInteger(size) || size < 0) {
        throw new Error(`invalid analysis-index size for ${path}`);
    }
    const blobSha = entry.blobSha === null || entry.blobSha === undefined
        ? null: String(entry.blobSha).toLowerCase();
    if (blobSha !== null && !BLOB_SHA_RE.test(blobSha)) {
        throw new Error(`invalid analysis-index blob SHA for ${path}`);
    }
    return { path, size, blobSha };
}

function normalizeBlockerMessage(message) {
    return String(message || "analysis index incomplete")
        .replace(/[\u0000-\u001f\u007f]+/gu, " ")
        .replace(/\s+/gu, " ")
        .trim()
        .slice(0, ANALYSIS_INDEX_LIMITS.blockerMessage);
}

function appendBlocker(state, kind, message, path = null) {
    const normalized = {
        kind: String(kind || "index-incomplete").slice(0, 64),
        message: normalizeBlockerMessage(message),
        ...(path ? { path: normalizePath(path) }: {}),
    };
    const key = JSON.stringify(normalized);
    if (state.blockerKeys.has(key)) return;
    state.blockerKeys.add(key);
    if (state.blockers.length >= ANALYSIS_INDEX_LIMITS.blockers) {
        state.blockersTruncated = true;
        return;
    }
    state.blockers.push(normalized);
}

function clearPathBlockers(state, path) {
    state.blockers = state.blockers.filter((blocker) => blocker.path !== path);
    state.blockerKeys = new Set(state.blockers.map((blocker) => JSON.stringify(blocker)));
}

function ensureState(state) {
    if (!state || typeof state !== "object"
        || state.schemaVersion !== ANALYSIS_INDEX_SCHEMA_REVISION
        || !ANALYSIS_SOURCE_KINDS.includes(state.sourceKind)
        || !(state.fileIndex instanceof Map)
        || !(state.factIndex instanceof Map)
        || !(state.blockerKeys instanceof Set)) {
        throw new Error("invalid analysis-index state");
    }
    validateAuditId(state.auditId);
}

function normalizeFact(fact, expectedPath) {
    if (!fact || typeof fact !== "object") throw new Error("analysis fact must be an object");
    const allowed = new Set([
        "id", "kind", "path", "line", "endLine", "excerptHash", "name", "value",
    ]);
    for (const key of Object.keys(fact)) {
        if (!allowed.has(key)) throw new Error(`analysis fact contains forbidden field: ${key}`);
    }
    const kind = String(fact.kind || "");
    if (!FACT_KINDS.includes(kind)) throw new Error(`invalid analysis fact kind: ${kind}`);
    const path = normalizePath(fact.path);
    if (path !== expectedPath) throw new Error(`analysis fact path mismatch for ${expectedPath}`);
    const line = Number(fact.line);
    const endLine = Number(fact.endLine);
    if (!Number.isSafeInteger(line) || line < 1 || line > 10_000_000
        || !Number.isSafeInteger(endLine) || endLine < line || endLine > 10_000_000) {
        throw new Error(`invalid analysis fact line range for ${path}`);
    }
    const id = String(fact.id || "").toLowerCase();
    const hash = String(fact.excerptHash || "").toLowerCase();
    if (!SHA256_RE.test(id) || !SHA256_RE.test(hash)) {
        throw new Error(`invalid analysis fact hash for ${path}`);
    }
    const rawName = String(fact.name || "");
    const name = rawName.normalize("NFKC").slice(0, 128);
    if (!name || name !== rawName || !/^[A-Za-z0-9_$@./:+-]+$/u.test(name)) {
        throw new Error(`analysis fact name is not normalized for ${path}`);
    }
    const rawValue = fact.value === undefined ? undefined: String(fact.value);
    const value = rawValue === undefined
        ? undefined: rawValue.normalize("NFKC")
            .replace(/[\u0000-\u001f\u007f]+/gu, " ")
            .replace(/\s+/gu, " ")
            .trim()
            .slice(0, 256);
    if (rawValue !== undefined && value !== rawValue) {
        throw new Error(`analysis fact value is not normalized for ${path}`);
    }
    const expectedId = createHash("sha256")
        .update(`${kind}\0${path}\0${line}\0${name}\0${value || ""}`)
        .digest("hex");
    if (id !== expectedId) throw new Error(`analysis fact ID is not canonical for ${path}`);
    return Object.freeze({
        id,
        kind,
        path,
        line,
        endLine,
        excerptHash: hash,
        name,
        ...(value ? { value }: {}),
    });
}

export function createAnalysisIndexState({ auditId, sourceKind } = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    if (!ANALYSIS_SOURCE_KINDS.includes(sourceKind)) {
        throw new Error(`invalid analysis source kind: ${String(sourceKind)}`);
    }
    return {
        schemaVersion: ANALYSIS_INDEX_SCHEMA_REVISION,
        auditId: normalizedAuditId,
        sourceKind,
        enumeration: {
            attempts: 0,
            complete: sourceKind === "metadata-only",
            trackingTruncated: false,
            directories: 0,
            reparsePointsSkipped: 0,
            otherEntriesSkipped: 0,
        },
        files: [],
        fileIndex: new Map(),
        facts: [],
        factIndex: new Map(),
        factOverflow: false,
        perFileOverflowCount: 0,
        readAttempts: 0,
        readFailures: 0,
        blockers: [],
        blockerKeys: new Set(),
        blockersTruncated: false,
    };
}

export function recordIndexEnumeration(state, {
    entries = [],
    complete = false,
    trackingTruncated = false,
    directories = 0,
    reparsePointsSkipped = 0,
    otherEntriesSkipped = 0,
    blocker = null,
} = {}) {
    ensureState(state);
    if (!Array.isArray(entries)) throw new Error("analysis-index entries must be an array");
    state.enumeration.attempts += 1;
    state.enumeration.complete = complete === true;
    state.enumeration.trackingTruncated ||= trackingTruncated === true;
    state.enumeration.directories = Math.max(
        state.enumeration.directories,
        Number.isSafeInteger(directories) ? directories: 0,
    );
    state.enumeration.reparsePointsSkipped = Math.max(
        state.enumeration.reparsePointsSkipped,
        Number.isSafeInteger(reparsePointsSkipped) ? reparsePointsSkipped: 0,
    );
    state.enumeration.otherEntriesSkipped = Math.max(
        state.enumeration.otherEntriesSkipped,
        Number.isSafeInteger(otherEntriesSkipped) ? otherEntriesSkipped: 0,
    );

    for (const rawEntry of entries) {
        const entry = normalizeEntry(rawEntry);
        const existingIndex = state.fileIndex.get(entry.path);
        const existing = Number.isInteger(existingIndex) ? state.files[existingIndex]: null;
        if (existing) {
            if (existing.size !== entry.size
                || (existing.blobSha && entry.blobSha && existing.blobSha !== entry.blobSha)) {
                appendBlocker(
                    state,
                    "enumeration-identity-conflict",
                    "enumerated file identity changed during the audit",
                    entry.path,
                );
                throw new Error(`analysis-index enumeration identity conflict at ${entry.path}`);
            }
            continue;
        }
        if (state.files.length >= ANALYSIS_INDEX_LIMITS.trackedFiles) {
            state.enumeration.trackingTruncated = true;
            appendBlocker(
                state,
                "file-cap-exceeded",
                `analysis index file cap exceeded (${ANALYSIS_INDEX_LIMITS.trackedFiles})`,
            );
            continue;
        }
        const normalized = {
            ...entry,
            status: "pending",
            classification: null,
            contentSha256: null,
            factIds: [],
            factsOverflow: false,
            lineCount: null,
            invisibleUnicodeScanComplete: false,
            invisibleUnicodeMatchCount: 0,
        };
        state.fileIndex.set(entry.path, state.files.length);
        state.files.push(normalized);
    }

    if (state.enumeration.trackingTruncated) {
        appendBlocker(
            state,
            "enumeration-truncated",
            "source enumeration or index file tracking was truncated",
        );
    }
    if (blocker) appendBlocker(state, "enumeration-blocker", blocker);
    return buildAnalysisIndexSnapshot(state);
}

export function recordIndexReadFailure(state, { path, error } = {}) {
    ensureState(state);
    const normalizedPath = normalizePath(path);
    state.readAttempts += 1;
    state.readFailures += 1;
    const index = state.fileIndex.get(normalizedPath);
    if (Number.isInteger(index)) state.files[index].status = "read-failed";
    appendBlocker(
        state,
        "read-failed",
        error instanceof Error ? error.message: String(error || "source read failed"),
        normalizedPath,
    );
    return buildAnalysisIndexSnapshot(state);
}

export function recordIndexedFile(state, {
    path,
    size,
    classification,
    classificationComplete,
    contentTooLarge = false,
    textTruncated = false,
    contentSha256 = null,
    blobSha = null,
    facts = [],
    factsOverflow = false,
    lineCount = null,
    invisibleUnicodeScanComplete = false,
    invisibleUnicodeMatchCount = 0,
} = {}) {
    ensureState(state);
    const normalizedPath = normalizePath(path);
    const index = state.fileIndex.get(normalizedPath);
    if (!Number.isInteger(index)) {
        throw new Error(`analysis-index path was not enumerated: ${normalizedPath}`);
    }
    const file = state.files[index];
    const normalizedSize = Number(size);
    const normalizedBlobSha = blobSha === null || blobSha === undefined
        ? null: String(blobSha).toLowerCase();
    if (normalizedBlobSha !== null && !BLOB_SHA_RE.test(normalizedBlobSha)) {
        throw new Error(`invalid blob SHA at ${normalizedPath}`);
    }
    if (!Number.isSafeInteger(normalizedSize) || normalizedSize < 0) {
        throw new Error(`invalid analysis-index file size at ${normalizedPath}`);
    }
    if (normalizedSize !== file.size
        && !(state.sourceKind === "api-direct"
            && file.blobSha
            && normalizedBlobSha === file.blobSha)) {
        appendBlocker(
            state,
            "read-identity-conflict",
            "source file size changed after enumeration",
            normalizedPath,
        );
        throw new Error(`analysis-index file size mismatch at ${normalizedPath}`);
    }
    if (state.sourceKind === "api-direct" && normalizedSize !== file.size) {
        file.size = normalizedSize;
    }
    const normalizedClassification = String(classification || "unknown");
    if (!CLASSIFICATIONS.has(normalizedClassification)) {
        throw new Error(`invalid analysis classification: ${normalizedClassification}`);
    }
    const normalizedLineCount = lineCount === null || lineCount === undefined
        ? null: Number(lineCount);
    if (normalizedClassification === "text"
        && (!Number.isSafeInteger(normalizedLineCount)
            || normalizedLineCount < 1
            || normalizedLineCount > 10_000_000)) {
        throw new Error(`invalid or over-cap text line count at ${normalizedPath}`);
    }
    if (normalizedClassification !== "text" && normalizedLineCount !== null) {
        throw new Error(`line count is valid only for text at ${normalizedPath}`);
    }
    const normalizedContentSha = contentSha256 === null || contentSha256 === undefined
        ? null: String(contentSha256).toLowerCase();
    if (normalizedContentSha !== null && !SHA256_RE.test(normalizedContentSha)) {
        throw new Error(`invalid content SHA-256 at ${normalizedPath}`);
    }
    if (file.blobSha && normalizedBlobSha && file.blobSha !== normalizedBlobSha) {
        throw new Error(`analysis-index blob identity mismatch at ${normalizedPath}`);
    }
    if (state.sourceKind === "api-direct"
        && (!file.blobSha || normalizedBlobSha !== file.blobSha)) {
        throw new Error(`analysis-index API blob identity is missing or mismatched at ${normalizedPath}`);
    }

    state.readAttempts += 1;
    const normalizedFacts = facts.map((fact) => normalizeFact(fact, normalizedPath));
    if (normalizedFacts.length > ANALYSIS_INDEX_LIMITS.factsPerFile) {
        factsOverflow = true;
    }

    let status = "incomplete";
    if (classificationComplete === true && contentTooLarge !== true
        && normalizedContentSha
        && normalizedClassification === "binary") {
        status = "classified-binary";
    } else if (classificationComplete === true && contentTooLarge !== true
        && normalizedContentSha
        && textTruncated !== true
        && invisibleUnicodeScanComplete === true
        && normalizedClassification === "text") {
        status = factsOverflow ? "index-overflow": "indexed-text";
    }

    if (file.contentSha256 && normalizedContentSha
        && file.contentSha256 !== normalizedContentSha) {
        appendBlocker(
            state,
            "content-identity-conflict",
            "source content hash changed across reads",
            normalizedPath,
        );
        throw new Error(`analysis-index content identity conflict at ${normalizedPath}`);
    }
    if (COMPLETE_FILE_STATUSES.has(file.status)
        && file.status === status
        && file.contentSha256 === normalizedContentSha) {
        return buildAnalysisIndexSnapshot(state);
    }

    file.classification = normalizedClassification;
    file.contentSha256 = normalizedContentSha;
    file.lineCount = normalizedLineCount;
    if (normalizedBlobSha) file.blobSha = normalizedBlobSha;
    file.invisibleUnicodeMatchCount = Math.max(
        0,
        Number.isSafeInteger(invisibleUnicodeMatchCount) ? invisibleUnicodeMatchCount: 0,
    );
    file.invisibleUnicodeScanComplete = invisibleUnicodeScanComplete === true;
    file.factIds = [];

    if (factsOverflow) {
        if (!file.factsOverflow) state.perFileOverflowCount += 1;
        file.factsOverflow = true;
        appendBlocker(
            state,
            "per-file-fact-cap-exceeded",
            `per-file fact cap exceeded (${ANALYSIS_INDEX_LIMITS.factsPerFile})`,
            normalizedPath,
        );
    }

    for (const fact of normalizedFacts.slice(0, ANALYSIS_INDEX_LIMITS.factsPerFile)) {
        const existingFactIndex = state.factIndex.get(fact.id);
        if (Number.isInteger(existingFactIndex)) {
            const existing = state.facts[existingFactIndex];
            if (JSON.stringify(existing) !== JSON.stringify(fact)) {
                throw new Error(`analysis fact ID collision at ${normalizedPath}`);
            }
            file.factIds.push(fact.id);
            continue;
        }
        if (state.facts.length >= ANALYSIS_INDEX_LIMITS.factsPerAudit) {
            state.factOverflow = true;
            status = "index-overflow";
            appendBlocker(
                state,
                "audit-fact-cap-exceeded",
                `per-audit fact cap exceeded (${ANALYSIS_INDEX_LIMITS.factsPerAudit})`,
            );
            break;
        }
        state.factIndex.set(fact.id, state.facts.length);
        state.facts.push(fact);
        file.factIds.push(fact.id);
    }

    file.status = status;
    if (COMPLETE_FILE_STATUSES.has(status)) {
        clearPathBlockers(state, normalizedPath);
    } else {
        appendBlocker(
            state,
            status === "index-overflow" ? "index-overflow": "file-incomplete",
            status === "index-overflow"
                ? "fact extraction exceeded a configured index cap": "file was not fully classified and indexed",
            normalizedPath,
        );
    }
    return buildAnalysisIndexSnapshot(state);
}

export function listIndexedFacts(state, {
    path = null,
    kind = null,
    cursor = 0,
    limit = 256,
} = {}) {
    ensureState(state);
    const normalizedPath = path === null ? null: normalizePath(path);
    if (kind !== null && !FACT_KINDS.includes(kind)) {
        throw new Error(`invalid analysis fact kind: ${String(kind)}`);
    }
    const start = Number.isSafeInteger(cursor) && cursor >= 0 ? cursor: 0;
    const pageSize = Number.isSafeInteger(limit) && limit > 0
        ? Math.min(limit, 256): 256;
    const filtered = state.facts.filter((fact) =>
        (!normalizedPath || fact.path === normalizedPath)
        && (!kind || fact.kind === kind));
    return {
        facts: clone(filtered.slice(start, start + pageSize)),
        total: filtered.length,
        cursor: start,
        nextCursor: start + pageSize < filtered.length ? start + pageSize: null,
    };
}

export function buildAnalysisIndexSnapshot(state) {
    ensureState(state);
    const addBytes = (current, value) => {
        const next = current + value;
        if (!Number.isSafeInteger(next)) {
            byteCountSaturated = true;
            return Number.MAX_SAFE_INTEGER;
        }
        return next;
    };
    const statusCounts = {};
    const factKinds = Object.fromEntries(FACT_KINDS.map((kind) => [kind, 0]));
    const incompletePaths = [];
    let invisibleUnicodeMatchedFiles = 0;
    let invisibleUnicodeMatchCount = 0;
    let totalBytes = 0;
    let indexedTextBytes = 0;
    let classifiedBinaryBytes = 0;
    let incompleteBytes = 0;
    let byteCountSaturated = false;

    for (const file of state.files) {
        totalBytes = addBytes(totalBytes, file.size);
        statusCounts[file.status] = (statusCounts[file.status] || 0) + 1;
        if (!COMPLETE_FILE_STATUSES.has(file.status)
            && incompletePaths.length < ANALYSIS_INDEX_LIMITS.snapshotPaths) {
            incompletePaths.push({ path: file.path, status: file.status });
        }
        if (file.invisibleUnicodeMatchCount > 0) {
            invisibleUnicodeMatchedFiles += 1;
            invisibleUnicodeMatchCount += file.invisibleUnicodeMatchCount;
        }
        if (file.status === "indexed-text") {
            indexedTextBytes = addBytes(indexedTextBytes, file.size);
        } else if (file.status === "classified-binary") {
            classifiedBinaryBytes = addBytes(classifiedBinaryBytes, file.size);
        } else {
            incompleteBytes = addBytes(incompleteBytes, file.size);
        }
    }
    for (const fact of state.facts) factKinds[fact.kind] += 1;

    const allFilesComplete = state.files.every((file) =>
        COMPLETE_FILE_STATUSES.has(file.status));
    const complete = state.sourceKind === "metadata-only"
        || (state.enumeration.complete === true
            && state.enumeration.trackingTruncated !== true
            && state.factOverflow !== true
            && state.perFileOverflowCount === 0
            && !byteCountSaturated
            && allFilesComplete);

    const blockers = [...state.blockers];
    if (!state.enumeration.complete && state.sourceKind !== "metadata-only") {
        blockers.push({
            kind: "enumeration-incomplete",
            message: "source enumeration has not completed",
        });
    }
    if (!allFilesComplete && state.sourceKind !== "metadata-only") {
        blockers.push({
            kind: "file-index-incomplete",
            message: "one or more enumerated files are not fully classified and indexed",
        });
    }
    if (byteCountSaturated) {
        blockers.push({
            kind: "byte-count-overflow",
            message: "quantitative byte accounting exceeded Number.MAX_SAFE_INTEGER",
        });
    }

    return Object.freeze({
        schemaVersion: ANALYSIS_INDEX_SCHEMA_REVISION,
        auditId: state.auditId,
        sourceKind: state.sourceKind,
        complete,
        enumeration: Object.freeze({
            attempts: state.enumeration.attempts,
            complete: state.enumeration.complete,
            trackedFiles: state.files.length,
            totalBytes,
            byteCountSaturated,
            trackingTruncated: state.enumeration.trackingTruncated,
            directories: state.enumeration.directories,
            reparsePointsSkipped: state.enumeration.reparsePointsSkipped,
            otherEntriesSkipped: state.enumeration.otherEntriesSkipped,
        }),
        reads: Object.freeze({
            attempts: state.readAttempts,
            failures: state.readFailures,
            pendingFiles: statusCounts.pending || 0,
            indexedTextFiles: statusCounts["indexed-text"] || 0,
            classifiedBinaryFiles: statusCounts["classified-binary"] || 0,
            indexedTextBytes,
            classifiedBinaryBytes,
            incompleteBytes,
            incompleteFiles: state.files.length
                - (statusCounts["indexed-text"] || 0)
                - (statusCounts["classified-binary"] || 0),
            statusCounts: Object.freeze(statusCounts),
        }),
        facts: Object.freeze({
            total: state.facts.length,
            perFileCap: ANALYSIS_INDEX_LIMITS.factsPerFile,
            perAuditCap: ANALYSIS_INDEX_LIMITS.factsPerAudit,
            perFileOverflowCount: state.perFileOverflowCount,
            auditOverflow: state.factOverflow,
            byKind: Object.freeze(factKinds),
        }),
        invisibleUnicode: Object.freeze({
            matchedFiles: invisibleUnicodeMatchedFiles,
            matchCount: invisibleUnicodeMatchCount,
        }),
        blockers: Object.freeze(blockers.slice(0, ANALYSIS_INDEX_LIMITS.blockers)),
        blockersTruncated: state.blockersTruncated
            || blockers.length > ANALYSIS_INDEX_LIMITS.blockers,
        incompletePaths: Object.freeze(incompletePaths),
    });
}

export const __internals = Object.freeze({
    COMPLETE_FILE_STATUSES,
    normalizePath,
    normalizeEntry,
    normalizeFact,
    appendBlocker,
    clearPathBlockers,
});
