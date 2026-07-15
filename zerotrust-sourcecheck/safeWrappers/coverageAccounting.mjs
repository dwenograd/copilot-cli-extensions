import {
    BINARY_PREVIEW_BYTES,
    isKnownBinaryPath,
} from "./apiClient.mjs";

export const COVERAGE_SCOPES = Object.freeze(["mandatory", "council_sample"]);
export const FETCH_OUTCOMES = Object.freeze({
    FULL_TEXT: "full_text",
    TRUNCATED_TEXT: "truncated_text",
    BINARY_METADATA_ONLY: "binary_metadata_only",
    OVERSIZED_METADATA_ONLY: "oversized_metadata_only",
    METADATA_ONLY: "metadata_only",
    FAILURE: "failure",
});

const MAX_TRACKED_ENUMERATED_FILES = 50_000;
const MAX_TRACKED_FETCH_RECORDS = 50_000;
const MAX_TRACKED_FAILURE_EVENTS = 1_000;
const MAX_SNAPSHOT_ITEMS = 50;
const MAX_ERROR_LENGTH = 300;

const OUTCOME_RANK = new Map([
    [FETCH_OUTCOMES.FAILURE, 0],
    [FETCH_OUTCOMES.METADATA_ONLY, 1],
    [FETCH_OUTCOMES.OVERSIZED_METADATA_ONLY, 2],
    [FETCH_OUTCOMES.TRUNCATED_TEXT, 3],
    [FETCH_OUTCOMES.BINARY_METADATA_ONLY, 4],
    [FETCH_OUTCOMES.FULL_TEXT, 5],
]);

const INVISIBLE_UNICODE_RE = /[\u{E0000}-\u{E007F}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}\u{E000}-\u{F8FF}\u{F0000}-\u{FFFFD}\u{100000}-\u{10FFFD}\u{200B}-\u{200F}\u{2028}-\u{202F}\u{2060}-\u{206F}\u{FEFF}]/gu;

export function createCoverageState(commitSha, rootTreeSha) {
    const identity = normalizeIdentity(commitSha, rootTreeSha);
    return {
        schemaVersion: 2,
        ...identity,
        enumeratedFiles: [],
        enumeratedFileIndex: new Map(),
        enumeratedTrackingTruncated: false,
        duplicateEnumerationCount: 0,
        enumerationFailureAttempts: 0,
        enumerationFailures: [],
        enumerationFailuresTruncated: false,
        fetchRecords: [],
        fetchRecordIndex: new Map(),
        fetchTrackingTruncated: false,
        fetchAttempts: 0,
        duplicateFetchCalls: 0,
        fetchFailureAttempts: 0,
        fetchFailures: [],
        fetchFailuresTruncated: false,
    };
}

export function validateCoverageStateIdentity(state, commitSha, rootTreeSha) {
    if (!state || typeof state !== "object") return false;
    let expected;
    try {
        expected = normalizeIdentity(commitSha, rootTreeSha);
    } catch {
        return false;
    }
    return state.commitSha === expected.commitSha
        && state.rootTreeSha === expected.rootTreeSha;
}

export function isRequiredBlobPath(path) {
    return typeof path === "string"
        && path.length > 0;
}

export function annotateTreeEntry(entry) {
    return {
        ...entry,
        classificationRequired: entry?.type === "blob",
        likelyBinaryByExtension: entry?.type === "blob"
            ? isKnownBinaryPath(entry.path)
            : false,
    };
}

export function recordEnumeratedEntries(state, entries) {
    assertCoverageState(state);
    if (!Array.isArray(entries)) throw new Error("enumerated entries must be an array");

    if (!(state.enumeratedFileIndex instanceof Map)) {
        state.enumeratedFileIndex = new Map(
            state.enumeratedFiles.map((entry, index) => [entry.path, index]),
        );
    }
    for (const entry of entries) {
        if (entry?.type !== "blob") continue;
        validateBlobEntry(entry);
        const existingIndex = state.enumeratedFileIndex.get(entry.path);
        const existing = Number.isInteger(existingIndex)
            ? state.enumeratedFiles[existingIndex]
            : null;
        if (existing) {
            if (existing.sha !== entry.sha.toLowerCase()) {
                throw new Error(`coverage entry identity conflict at ${entry.path}`);
            }
            state.duplicateEnumerationCount += 1;
            continue;
        }
        if (state.enumeratedFiles.length >= MAX_TRACKED_ENUMERATED_FILES) {
            state.enumeratedTrackingTruncated = true;
            continue;
        }
        const normalized = {
            path: entry.path,
            sha: entry.sha.toLowerCase(),
            size: Number.isSafeInteger(entry.size) && entry.size >= 0 ? entry.size : 0,
            classificationRequired: true,
            likelyBinaryByExtension: isKnownBinaryPath(entry.path),
        };
        state.enumeratedFiles.push(normalized);
        state.enumeratedFileIndex.set(normalized.path, state.enumeratedFiles.length - 1);
    }
    return state;
}

export function recordEnumerationFailure(state, { path = "<root>", error } = {}) {
    assertCoverageState(state);
    state.enumerationFailureAttempts += 1;
    appendBoundedFailure(
        state.enumerationFailures,
        {
            path: normalizeDisplayPath(path),
            error: normalizeError(error),
        },
        state,
        "enumerationFailuresTruncated",
    );
    return state;
}

export function recordFetchResult(state, {
    path,
    scope,
    result,
} = {}) {
    assertCoverageState(state);
    validateFetchPath(path);
    const normalizedScope = normalizeScope(scope);
    if (!result || typeof result !== "object") {
        throw new Error("fetch result must be an object");
    }
    if (result.path !== undefined && result.path !== path) {
        throw new Error(`fetch result path mismatch: requested ${path}, received ${result.path}`);
    }
    if (!(state.enumeratedFileIndex instanceof Map)) {
        state.enumeratedFileIndex = new Map(
            state.enumeratedFiles.map((entry, index) => [entry.path, index]),
        );
    }
    const enumeratedIndex = state.enumeratedFileIndex.get(path);
    const enumerated = Number.isInteger(enumeratedIndex)
        ? state.enumeratedFiles[enumeratedIndex]
        : null;
    if (!enumerated) {
        throw new Error(`fetch result path was not enumerated from the pinned tree: ${path}`);
    }
    if (typeof result.blobSha !== "string"
        || !/^[a-f0-9]{40}$/i.test(result.blobSha)
        || result.blobSha.toLowerCase() !== enumerated.sha) {
        throw new Error(`fetch result blob identity mismatch at ${path}`);
    }

    const detail = classifyFetchResult(result);
    recordFetchAttempt(state, path, normalizedScope, detail);
    return detail;
}

export function recordFetchFailure(state, {
    path,
    scope,
    error,
} = {}) {
    assertCoverageState(state);
    validateFetchPath(path);
    const normalizedScope = normalizeScope(scope);
    const detail = {
        outcome: FETCH_OUTCOMES.FAILURE,
        sizeBytes: null,
        sha256: null,
        blobSha: null,
        encoding: null,
        contentReturned: false,
        textTruncated: false,
        contentTooLarge: false,
        invisibleUnicodeScan: {
            complete: false,
            matchCount: 0,
        },
        error: normalizeError(error),
    };
    state.fetchFailureAttempts += 1;
    appendBoundedFailure(
        state.fetchFailures,
        {
            path,
            scope: normalizedScope,
            error: detail.error,
        },
        state,
        "fetchFailuresTruncated",
    );
    recordFetchAttempt(state, path, normalizedScope, detail);
    return detail;
}

export function buildCoverageSnapshot(state, treeState, {
    maxItems = MAX_SNAPSHOT_ITEMS,
} = {}) {
    const itemLimit = Number.isSafeInteger(maxItems) && maxItems >= 0
        ? Math.min(maxItems, MAX_SNAPSHOT_ITEMS)
        : MAX_SNAPSHOT_ITEMS;
    const files = state?.enumeratedFiles
        ? [...state.enumeratedFiles].sort((a, b) => a.path.localeCompare(b.path))
        : [];
    const records = state?.fetchRecords
        ? [...state.fetchRecords].sort((a, b) => a.path.localeCompare(b.path))
        : [];
    const recordByPath = new Map(records.map((record) => [record.path, record]));
    const uniqueBlobShas = new Set(files.map((entry) => entry.sha));

    const observed = {
        fullTextFiles: 0,
        truncatedTextFiles: 0,
        binaryMetadataOnlyFiles: 0,
        oversizedMetadataOnlyFiles: 0,
        metadataOnlyFiles: 0,
        failureFiles: 0,
    };
    const best = {
        fullTextFiles: 0,
        truncatedTextFiles: 0,
        binaryMetadataOnlyFiles: 0,
        oversizedMetadataOnlyFiles: 0,
        metadataOnlyFiles: 0,
        failureOnlyFiles: 0,
    };
    let councilSampledFiles = 0;
    let mandatoryAttemptedFiles = 0;
    let invisibleUnicodeMatchedFiles = 0;
    let invisibleUnicodeMatchCount = 0;
    const invisibleUnicodeMatches = [];

    for (const record of records) {
        for (const outcome of record.seenOutcomes || []) {
            incrementOutcomeCounter(observed, outcome, false);
        }
        if (record.best) incrementOutcomeCounter(best, record.best.outcome, true);
        if ((record.scopes?.council_sample?.attempts || 0) > 0) councilSampledFiles += 1;
        if ((record.scopes?.mandatory?.attempts || 0) > 0) mandatoryAttemptedFiles += 1;
        const scan = record.best?.invisibleUnicodeScan;
        if (scan?.matchCount > 0) {
            invisibleUnicodeMatchedFiles += 1;
            invisibleUnicodeMatchCount += scan.matchCount;
            invisibleUnicodeMatches.push({
                path: record.path,
                matchCount: scan.matchCount,
                complete: scan.complete === true,
            });
        }
    }

    const missingOrIncomplete = [];
    const notFetched = [];
    let classifiedAndInspectedBlobs = 0;
    let fullyFetchedAndScannedTextBlobs = 0;
    let classifiedBinaryBlobs = 0;
    let sampleOnlyBlobs = 0;
    for (const entry of files) {
        const record = recordByPath.get(entry.path);
        const mandatory = record?.scopes?.mandatory || null;
        const mandatoryBest = mandatory?.best || null;
        const completionKind = mandatoryCompletionKind(mandatoryBest);
        if (completionKind === "text") {
            fullyFetchedAndScannedTextBlobs += 1;
            classifiedAndInspectedBlobs += 1;
            continue;
        }
        if (completionKind === "binary") {
            classifiedBinaryBlobs += 1;
            classifiedAndInspectedBlobs += 1;
            continue;
        }

        let status = "not_fetched";
        if (record && (!mandatory || mandatory.attempts === 0)) {
            status = "council_sample_only";
            sampleOnlyBlobs += 1;
        } else if (mandatoryBest) {
            status = incompleteStatus(mandatoryBest);
        } else if (mandatory) {
            status = "mandatory_attempt_unrecorded";
        }
        if (!record) notFetched.push(entry.path);
        missingOrIncomplete.push({
            path: entry.path,
            size: entry.size,
            likelyBinaryByExtension: entry.likelyBinaryByExtension === true,
            status,
        });
    }

    const unresolved = Array.isArray(treeState?.unresolvedSubtrees)
        ? [...treeState.unresolvedSubtrees].sort((a, b) => a.path.localeCompare(b.path))
        : [];
    const treeBlockers = Array.isArray(treeState?.coverageBlockers)
        ? treeState.coverageBlockers
        : [];
    const enumerationComplete = !!treeState
        && unresolved.length === 0
        && treeBlockers.length === 0
        && treeState.stateTrackingTruncated !== true
        && treeState.discoveryTruncated !== true;

    const blockers = [];
    if (!state) blockers.push({ kind: "acquisition_state_missing" });
    if (!treeState) blockers.push({ kind: "tree_enumeration_missing" });
    if (unresolved.length > 0) {
        blockers.push({ kind: "unresolved_subtrees", count: unresolved.length });
    }
    if (treeBlockers.length > 0) {
        blockers.push({ kind: "tree_coverage_blockers", count: treeBlockers.length });
    }
    if (treeState?.stateTrackingTruncated === true) {
        blockers.push({ kind: "tree_state_tracking_truncated" });
    }
    if (treeState?.discoveryTruncated === true) {
        blockers.push({ kind: "tree_discovery_truncated" });
    }
    if (state?.enumeratedTrackingTruncated === true) {
        blockers.push({ kind: "acquisition_enumeration_tracking_truncated" });
    }
    if (state?.fetchTrackingTruncated === true) {
        blockers.push({ kind: "acquisition_fetch_tracking_truncated" });
    }
    if (state?.enumerationFailuresTruncated === true || state?.fetchFailuresTruncated === true) {
        blockers.push({ kind: "acquisition_failure_tracking_truncated" });
    }
    if (missingOrIncomplete.length > 0) {
        blockers.push({
            kind: "mandatory_blob_classification_or_text_scan_incomplete",
            count: missingOrIncomplete.length,
        });
    }

    const requiredAcquisitionComplete = enumerationComplete
        && !!state
        && state.enumeratedTrackingTruncated !== true
        && state.fetchTrackingTruncated !== true
        && state.enumerationFailuresTruncated !== true
        && state.fetchFailuresTruncated !== true
        && missingOrIncomplete.length === 0;

    const boundedMissing = missingOrIncomplete.slice(0, itemLimit);
    const boundedNotFetched = notFetched.slice(0, itemLimit);
    const boundedUnresolved = unresolved.slice(0, itemLimit);
    const boundedFailures = (state?.fetchFailures || []).slice(0, itemLimit);
    const boundedEnumerationFailures = (state?.enumerationFailures || []).slice(0, itemLimit);
    const boundedInvisibleMatches = invisibleUnicodeMatches
        .sort((a, b) => a.path.localeCompare(b.path))
        .slice(0, itemLimit);

    return {
        schemaVersion: 2,
        commitSha: state?.commitSha || treeState?.commitSha || null,
        rootTreeSha: state?.rootTreeSha || treeState?.rootTreeSha || null,
        requiredAcquisitionComplete,
        enumeration: {
            complete: enumerationComplete,
            uniqueFiles: files.length,
            uniqueBlobShas: uniqueBlobShas.size,
            duplicateEntries: Math.max(
                Number(state?.duplicateEnumerationCount || 0),
                Number(treeState?.duplicateEntryCount || 0),
            ),
            unresolvedSubtrees: unresolved.length,
            coverageBlockers: treeBlockers.length,
            stateTrackingTruncated: treeState?.stateTrackingTruncated === true
                || state?.enumeratedTrackingTruncated === true,
            discoveryTruncated: treeState?.discoveryTruncated === true,
            failureAttempts: Number(state?.enumerationFailureAttempts || 0),
            likelyBinaryByExtension: files.filter((entry) =>
                entry.likelyBinaryByExtension === true).length,
        },
        acquisition: {
            uniqueFetchedFiles: records.length,
            fetchAttempts: Number(state?.fetchAttempts || 0),
            duplicateFetchCalls: Number(state?.duplicateFetchCalls || 0),
            fetchFailureAttempts: Number(state?.fetchFailureAttempts || 0),
            observedOutcomes: observed,
            bestOutcomes: best,
        },
        deterministicMandatory: {
            requiredBlobClassifications: files.length,
            mandatoryAttemptedBlobs: mandatoryAttemptedFiles,
            classifiedAndInspectedBlobs,
            fullyFetchedAndScannedTextBlobs,
            classifiedBinaryBlobs,
            missingOrIncomplete: missingOrIncomplete.length,
            notFetched: notFetched.length,
            councilSampleOnlyBlobs: sampleOnlyBlobs,
            invisibleUnicodeMatchedFiles,
            invisibleUnicodeMatchCount,
        },
        councilSampling: {
            uniqueSampledFiles: councilSampledFiles,
            satisfiesMandatoryCoverage: false,
        },
        blockers: blockers.slice(0, itemLimit),
        details: {
            missingOrIncomplete: boundedMissing,
            notFetched: boundedNotFetched,
            unresolvedSubtrees: boundedUnresolved,
            fetchFailures: boundedFailures,
            enumerationFailures: boundedEnumerationFailures,
            invisibleUnicodeMatches: boundedInvisibleMatches,
        },
        bounded: {
            maxItems: itemLimit,
            blockersTruncated: blockers.length > itemLimit,
            missingOrIncompleteTruncated: missingOrIncomplete.length > itemLimit,
            notFetchedTruncated: notFetched.length > itemLimit,
            unresolvedSubtreesTruncated: unresolved.length > itemLimit,
            fetchFailuresTruncated: (state?.fetchFailures || []).length > itemLimit
                || state?.fetchFailuresTruncated === true,
            enumerationFailuresTruncated: (state?.enumerationFailures || []).length > itemLimit
                || state?.enumerationFailuresTruncated === true,
            invisibleUnicodeMatchesTruncated: invisibleUnicodeMatches.length > itemLimit,
        },
    };
}

export function scanInvisibleUnicode(text, { complete = true } = {}) {
    if (typeof text !== "string") {
        return { complete: false, matchCount: 0 };
    }
    INVISIBLE_UNICODE_RE.lastIndex = 0;
    let matchCount = 0;
    while (INVISIBLE_UNICODE_RE.exec(text) !== null) matchCount += 1;
    return { complete: complete === true, matchCount };
}

function classifyFetchResult(result) {
    let outcome;
    if (result.contentTooLarge === true) {
        outcome = FETCH_OUTCOMES.OVERSIZED_METADATA_ONLY;
    } else if (result.encoding === "binary") {
        outcome = FETCH_OUTCOMES.BINARY_METADATA_ONLY;
    } else if (result.contentReturned === true && result.textTruncated === true) {
        outcome = FETCH_OUTCOMES.TRUNCATED_TEXT;
    } else if (result.contentReturned === true && typeof result.text === "string") {
        outcome = FETCH_OUTCOMES.FULL_TEXT;
    } else {
        outcome = FETCH_OUTCOMES.METADATA_ONLY;
    }

    const hasText = typeof result.text === "string";
    const byteClassification = result.classification === "text"
        || result.classification === "binary"
        ? result.classification
        : "unknown";
    const invisibleUnicodeScan = hasText
        ? scanInvisibleUnicode(result.text, { complete: outcome === FETCH_OUTCOMES.FULL_TEXT })
        : { complete: false, matchCount: 0 };
    return {
        outcome,
        sizeBytes: Number.isSafeInteger(result.sizeBytes) && result.sizeBytes >= 0
            ? result.sizeBytes
            : null,
        sha256: typeof result.sha256 === "string" ? result.sha256 : null,
        blobSha: typeof result.blobSha === "string" ? result.blobSha : null,
        byteClassification,
        classificationComplete: result.classificationComplete === true,
        classificationReason: typeof result.classificationReason === "string"
            ? result.classificationReason.slice(0, 100)
            : null,
        classificationBytesInspected:
            Number.isSafeInteger(result.classificationBytesInspected)
                && result.classificationBytesInspected >= 0
                ? result.classificationBytesInspected
                : null,
        encoding: typeof result.encoding === "string" ? result.encoding : null,
        contentReturned: result.contentReturned === true,
        textTruncated: result.textTruncated === true,
        contentTooLarge: result.contentTooLarge === true,
        previewBase64: typeof result.previewBase64 === "string"
            ? result.previewBase64
            : null,
        previewByteCount: Number.isSafeInteger(result.previewByteCount)
            && result.previewByteCount >= 0
            ? result.previewByteCount
            : null,
        invisibleUnicodeScan,
        error: null,
    };
}

function mandatoryCompletionKind(detail) {
    if (!detail || detail.classificationComplete !== true || !hasFetchedIdentity(detail)) {
        return null;
    }
    if (detail.outcome === FETCH_OUTCOMES.FULL_TEXT
        && detail.byteClassification === "text"
        && detail.invisibleUnicodeScan?.complete === true) {
        return "text";
    }
    if (detail.outcome === FETCH_OUTCOMES.BINARY_METADATA_ONLY
        && detail.byteClassification === "binary"
        && hasBoundedBinaryPreview(detail)) {
        return "binary";
    }
    return null;
}

function hasFetchedIdentity(detail) {
    return Number.isSafeInteger(detail.sizeBytes)
        && detail.sizeBytes >= 0
        && typeof detail.sha256 === "string"
        && /^[a-f0-9]{64}$/i.test(detail.sha256)
        && typeof detail.blobSha === "string"
        && /^[a-f0-9]{40}$/i.test(detail.blobSha)
        && detail.classificationBytesInspected === detail.sizeBytes;
}

function hasBoundedBinaryPreview(detail) {
    if (typeof detail.previewBase64 !== "string"
        || !Number.isSafeInteger(detail.previewByteCount)
        || detail.previewByteCount < 1
        || detail.previewByteCount > BINARY_PREVIEW_BYTES
        || detail.previewByteCount !== Math.min(detail.sizeBytes, BINARY_PREVIEW_BYTES)) {
        return false;
    }
    try {
        return Buffer.from(detail.previewBase64, "base64").length === detail.previewByteCount;
    } catch {
        return false;
    }
}

function incompleteStatus(detail) {
    if (detail.contentTooLarge === true) return detail.outcome;
    if (detail.classificationComplete !== true) return "byte_classification_incomplete";
    if (!hasFetchedIdentity(detail)) return "fetched_identity_incomplete";
    if (detail.byteClassification === "binary" && !hasBoundedBinaryPreview(detail)) {
        return "binary_preview_incomplete";
    }
    if (detail.byteClassification === "text"
        && detail.invisibleUnicodeScan?.complete !== true) {
        return "text_scan_incomplete";
    }
    return detail.outcome;
}

function recordFetchAttempt(state, path, scope, detail) {
    if (!(state.fetchRecordIndex instanceof Map)) {
        state.fetchRecordIndex = new Map(
            state.fetchRecords.map((item, index) => [item.path, index]),
        );
    }
    const existingIndex = state.fetchRecordIndex.get(path);
    let record = Number.isInteger(existingIndex)
        ? state.fetchRecords[existingIndex]
        : null;
    if (record) {
        assertConsistentFetchIdentity(record, detail, path);
    }
    state.fetchAttempts += 1;
    if (record) {
        state.duplicateFetchCalls += 1;
    } else {
        if (state.fetchRecords.length >= MAX_TRACKED_FETCH_RECORDS) {
            state.fetchTrackingTruncated = true;
            return;
        }
        record = {
            path,
            attempts: 0,
            failureAttempts: 0,
            seenOutcomes: [],
            best: null,
            identity: null,
            scopes: {
                mandatory: createScopeRecord(),
                council_sample: createScopeRecord(),
            },
        };
        state.fetchRecords.push(record);
        state.fetchRecordIndex.set(path, state.fetchRecords.length - 1);
    }

    if (detail.outcome !== FETCH_OUTCOMES.FAILURE && !record.identity) {
        record.identity = fetchIdentity(detail);
    }
    record.attempts += 1;
    if (detail.outcome === FETCH_OUTCOMES.FAILURE) record.failureAttempts += 1;
    if (!record.seenOutcomes.includes(detail.outcome)) record.seenOutcomes.push(detail.outcome);
    record.best = chooseBetter(record.best, detail);

    const scopeRecord = record.scopes[scope];
    scopeRecord.attempts += 1;
    if (detail.outcome === FETCH_OUTCOMES.FAILURE) scopeRecord.failureAttempts += 1;
    if (!scopeRecord.seenOutcomes.includes(detail.outcome)) {
        scopeRecord.seenOutcomes.push(detail.outcome);
    }

    function assertConsistentFetchIdentity(record, detail, path) {
        if (detail.outcome === FETCH_OUTCOMES.FAILURE) return;
        const candidate = fetchIdentity(detail);
        if (!record.identity || !candidate) return;
        if (record.identity.blobSha !== candidate.blobSha
            || record.identity.sha256 !== candidate.sha256
            || record.identity.sizeBytes !== candidate.sizeBytes) {
            throw new Error(`duplicate fetch identity conflict at ${path}`);
        }
    }

    function fetchIdentity(detail) {
        if (typeof detail.blobSha !== "string"
            || typeof detail.sha256 !== "string"
            || !Number.isSafeInteger(detail.sizeBytes)) {
            return null;
        }
        return {
            blobSha: detail.blobSha,
            sha256: detail.sha256,
            sizeBytes: detail.sizeBytes,
        };
    }
    scopeRecord.best = chooseBetter(scopeRecord.best, detail);
}

function createScopeRecord() {
    return {
        attempts: 0,
        failureAttempts: 0,
        seenOutcomes: [],
        best: null,
    };
}

function chooseBetter(current, candidate) {
    if (!current) return candidate;
    return (OUTCOME_RANK.get(candidate.outcome) ?? -1) > (OUTCOME_RANK.get(current.outcome) ?? -1)
        ? candidate
        : current;
}

function incrementOutcomeCounter(target, outcome, bestOnly) {
    switch (outcome) {
        case FETCH_OUTCOMES.FULL_TEXT:
            target.fullTextFiles += 1;
            break;
        case FETCH_OUTCOMES.TRUNCATED_TEXT:
            target.truncatedTextFiles += 1;
            break;
        case FETCH_OUTCOMES.BINARY_METADATA_ONLY:
            target.binaryMetadataOnlyFiles += 1;
            break;
        case FETCH_OUTCOMES.OVERSIZED_METADATA_ONLY:
            target.oversizedMetadataOnlyFiles += 1;
            break;
        case FETCH_OUTCOMES.METADATA_ONLY:
            target.metadataOnlyFiles += 1;
            break;
        case FETCH_OUTCOMES.FAILURE:
            target[bestOnly ? "failureOnlyFiles" : "failureFiles"] += 1;
            break;
        default:
            break;
    }
}

function appendBoundedFailure(list, item, state, truncatedField) {
    if (list.length >= MAX_TRACKED_FAILURE_EVENTS) {
        state[truncatedField] = true;
        return;
    }
    list.push(item);
}

function normalizeIdentity(commitSha, rootTreeSha) {
    const commit = String(commitSha || "").toLowerCase();
    const root = String(rootTreeSha || "").toLowerCase();
    if (!/^[a-f0-9]{40}$/.test(commit) || !/^[a-f0-9]{40}$/.test(root)) {
        throw new Error("coverage state requires valid commit and root-tree SHAs");
    }
    return { commitSha: commit, rootTreeSha: root };
}

function normalizeScope(scope) {
    if (!COVERAGE_SCOPES.includes(scope)) {
        throw new Error(`coverage_scope must be one of: ${COVERAGE_SCOPES.join(" | ")}`);
    }
    return scope;
}

function validateBlobEntry(entry) {
    if (typeof entry.path !== "string" || entry.path.length < 1 || entry.path.length > 1024
        || typeof entry.sha !== "string" || !/^[a-f0-9]{40}$/i.test(entry.sha)) {
        throw new Error("coverage received an invalid blob entry");
    }
}

function validateFetchPath(path) {
    if (typeof path !== "string" || path.length < 1 || path.length > 1024) {
        throw new Error("coverage fetch path must be a non-empty string");
    }
}

function normalizeDisplayPath(path) {
    return typeof path === "string" && path.length > 0
        ? path.slice(0, 1024)
        : "<root>";
}

function normalizeError(error) {
    const message = error instanceof Error ? error.message : String(error || "unknown error");
    return message.slice(0, MAX_ERROR_LENGTH);
}

function assertCoverageState(state) {
    if (!state || state.schemaVersion !== 2
        || !/^[a-f0-9]{40}$/.test(state.commitSha || "")
        || !/^[a-f0-9]{40}$/.test(state.rootTreeSha || "")) {
        throw new Error("invalid acquisition coverage state");
    }
}

export const __internals = {
    MAX_TRACKED_ENUMERATED_FILES,
    MAX_TRACKED_FETCH_RECORDS,
    MAX_TRACKED_FAILURE_EVENTS,
    MAX_SNAPSHOT_ITEMS,
    INVISIBLE_UNICODE_RE,
    classifyFetchResult,
};
