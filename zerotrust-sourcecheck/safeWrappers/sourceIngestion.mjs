import {
    closeSync,
    constants,
    fstatSync,
    lstatSync,
    openSync,
    readFileSync,
    readdirSync,
} from "node:fs";
import nodePath from "node:path";

import {
    getAnalysisIndexSnapshot,
    getAnalysisIndexState,
    getTrustedAuditContext,
    maybeAdvanceAnalysisPrepared,
    mutateAnalysisIndexState,
} from "../enforcement.mjs";
import { modeNeedsClone, modeUsesLocalSource } from "../modes.mjs";
import { extractFactsFromText } from "../analysis/extractFacts.mjs";
import {
    ANALYSIS_INDEX_LIMITS,
    listIndexedFacts,
    recordIndexEnumeration,
    recordIndexedFile,
    recordIndexReadFailure,
} from "../analysis/indexState.mjs";
import { __internals as apiClientInternals } from "./apiClient.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";

const MAX_OUTPUT_ENTRIES = 1_000;
const MAX_ENUMERATED_DIRECTORIES = 50_000;
const MAX_ENUMERATED_ENTRIES = 100_000;
const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024;
const HARD_MAX_FILE_BYTES = 50 * 1024 * 1024;
const INVISIBLE_UNICODE_RE = /[\u{E0000}-\u{E007F}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}\u{E000}-\u{F8FF}\u{F0000}-\u{FFFFD}\u{100000}-\u{10FFFD}\u{200B}-\u{200F}\u{2028}-\u{202F}\u{2060}-\u{206F}\u{FEFF}]/gu;

function pathsEqual(left, right) {
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function pathIsUnder(root, candidate) {
    const relative = nodePath.relative(nodePath.resolve(root), nodePath.resolve(candidate));
    return relative === ""
        || (!relative.startsWith("..") && !nodePath.isAbsolute(relative));
}

function normalizeRelativePath(path) {
    if (typeof path !== "string" || path.length < 1 || path.length > 1024
        || path.startsWith("/") || path.endsWith("/") || path.includes("\\")
        || path.includes("//") || /[\u0000-\u001f\u007f]/u.test(path)
        || path.split("/").some((segment) => segment === "." || segment === "..")) {
        throw new Error(`invalid source-relative path: ${JSON.stringify(path)}`);
    }
    return path;
}

function resolveBoundSource(ctx) {
    if (!ctx.hasActiveAudit) {
        throw new Error(
            "no active audit for this session (TTL expired or zerotrust_sourcecheck not invoked)",
        );
    }
    if (modeUsesLocalSource(ctx.mode)) {
        if (!ctx.localPath) throw new Error("local-source audit has no recorded local path");
        return {
            root: nodePath.resolve(ctx.localPath),
            sourceKind: "local-source",
        };
    }
    if (modeNeedsClone(ctx.mode)) {
        if (!ctx.resolvedClonePath) {
            throw new Error(
                "build-clone source is not bound yet; call zerotrust_safe_clone first",
            );
        }
        return {
            root: nodePath.resolve(ctx.resolvedClonePath),
            sourceKind: "build-clone",
        };
    }
    throw new Error(
        `active mode '${ctx.mode}' does not use wrapper-controlled on-disk source ingestion`,
    );
}

function assertSafeRoot(root) {
    const stats = lstatSync(root);
    if (stats.isSymbolicLink()) {
        throw new Error("bound source root became a symlink/reparse point; refusing to follow it");
    }
    if (!stats.isDirectory()) throw new Error("bound source root is no longer a directory");
}

function enumerateSource(root) {
    assertSafeRoot(root);
    const files = [];
    const stack = [{ absolute: root, relative: "" }];
    let directories = 0;
    let reparsePointsSkipped = 0;
    let otherEntriesSkipped = 0;
    let trackingTruncated = false;
    let entriesSeen = 0;

    enumeration:
    while (stack.length > 0) {
        if (directories >= MAX_ENUMERATED_DIRECTORIES) {
            trackingTruncated = true;
            break;
        }
        const current = stack.pop();
        directories += 1;
        const entries = readdirSync(current.absolute, { withFileTypes: true })
            .sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            entriesSeen += 1;
            if (entriesSeen > MAX_ENUMERATED_ENTRIES) {
                trackingTruncated = true;
                break enumeration;
            }
            if (current.relative === "" && entry.name === ".git") {
                otherEntriesSkipped += 1;
                continue;
            }
            const relative = current.relative
                ? `${current.relative}/${entry.name}`
                : entry.name;
            const normalized = normalizeRelativePath(relative.replace(/\\/g, "/"));
            const absolute = nodePath.resolve(root, ...normalized.split("/"));
            if (!pathIsUnder(root, absolute)) {
                throw new Error(`source enumeration escaped the bound root at ${normalized}`);
            }
            const stats = lstatSync(absolute);
            if (stats.isSymbolicLink()) {
                reparsePointsSkipped += 1;
                continue;
            }
            if (stats.isDirectory()) {
                stack.push({ absolute, relative: normalized });
                continue;
            }
            if (!stats.isFile()) {
                otherEntriesSkipped += 1;
                continue;
            }
            if (files.length >= ANALYSIS_INDEX_LIMITS.trackedFiles) {
                trackingTruncated = true;
                continue;
            }
            files.push({
                path: normalized,
                size: stats.size,
                blobSha: null,
            });
        }
    }

    files.sort((a, b) => a.path.localeCompare(b.path));
    return {
        files,
        directories,
        reparsePointsSkipped,
        otherEntriesSkipped,
        trackingTruncated,
    };
}

function assertPathChainNoReparse(root, relativePath) {
    assertSafeRoot(root);
    let current = root;
    const segments = normalizeRelativePath(relativePath).split("/");
    for (let index = 0; index < segments.length; index += 1) {
        current = nodePath.resolve(current, segments[index]);
        if (!pathIsUnder(root, current)) {
            throw new Error("source path escaped the exact active root");
        }
        const stats = lstatSync(current);
        if (stats.isSymbolicLink()) {
            throw new Error(`source path contains a symlink/reparse point: ${relativePath}`);
        }
        if (index < segments.length - 1 && !stats.isDirectory()) {
            throw new Error(`source path parent is not a directory: ${relativePath}`);
        }
        if (index === segments.length - 1 && !stats.isFile()) {
            throw new Error(`source path is not a regular file: ${relativePath}`);
        }
    }
    return current;
}

function invisibleUnicodeScan(text) {
    let matchCount = 0;
    INVISIBLE_UNICODE_RE.lastIndex = 0;
    while (INVISIBLE_UNICODE_RE.exec(text)) matchCount += 1;
    INVISIBLE_UNICODE_RE.lastIndex = 0;
    return { complete: true, matchCount };
}

function publicClassification(result) {
    return {
        path: result.path,
        sizeBytes: result.sizeBytes,
        sha256: result.sha256 || null,
        classification: result.classification,
        classificationComplete: result.classificationComplete === true,
        classificationReason: result.classificationReason || null,
        classificationBytesInspected: result.classificationBytesInspected || 0,
        likelyBinaryByExtension: result.likelyBinaryByExtension === true,
        contentTooLarge: result.contentTooLarge === true,
        textTruncated: result.textTruncated === true,
    };
}

export async function safeListSourceHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) return failure(ctx.error);

    let bound;
    try {
        bound = resolveBoundSource(ctx);
    } catch (err) {
        return failure(`safe_list_source refused: ${err.message}`);
    }

    const cursor = args.cursor === undefined ? 0 : Number(args.cursor);
    const pageSize = args.page_size === undefined
        ? MAX_OUTPUT_ENTRIES
        : Number(args.page_size);
    if (!Number.isSafeInteger(cursor) || cursor < 0) {
        return failure("cursor must be a non-negative integer");
    }
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > MAX_OUTPUT_ENTRIES) {
        return failure(`page_size must be between 1 and ${MAX_OUTPUT_ENTRIES}`);
    }

    let indexState = getAnalysisIndexState(sessionId);
    try {
        if (!indexState || indexState.sourceKind !== bound.sourceKind) {
            return failure("safe_list_source refused: analysis index source kind is not bound to this audit");
        }
        if (indexState.enumeration.attempts === 0) {
            const enumerated = enumerateSource(bound.root);
            const mutation = mutateAnalysisIndexState(sessionId, (state) =>
                recordIndexEnumeration(state, {
                    entries: enumerated.files,
                    complete: !enumerated.trackingTruncated,
                    trackingTruncated: enumerated.trackingTruncated,
                    directories: enumerated.directories,
                    reparsePointsSkipped: enumerated.reparsePointsSkipped,
                    otherEntriesSkipped: enumerated.otherEntriesSkipped,
                    blocker: enumerated.trackingTruncated
                        ? "source file count exceeded the bounded enumeration cap"
                        : null,
                }));
            if (!mutation.ok) {
                return failure("safe_list_source refused: could not persist source enumeration");
            }
            indexState = getAnalysisIndexState(sessionId);
        } else {
            assertSafeRoot(bound.root);
        }
    } catch (err) {
        return failure(`safe_list_source failed: ${err.message}`);
    }

    const page = indexState.files.slice(cursor, cursor + pageSize).map((file) => ({
        path: file.path,
        size: file.size,
        status: file.status,
    }));
    const nextCursor = cursor + pageSize < indexState.files.length
        ? cursor + pageSize
        : null;
    const preparation = maybeAdvanceAnalysisPrepared(sessionId);
    return success({
        sourceKind: bound.sourceKind,
        sourceRoot: bound.root,
        entries: page,
        cursor,
        nextCursor,
        totalFiles: indexState.files.length,
        analysisIndex: preparation?.analysisIndex || getAnalysisIndexSnapshot(sessionId),
        analysisStageState: preparation?.analysisStageState || ctx.analysisStageState,
        analysisPlugins: preparation?.analysisPlugins || ctx.analysisPlugins,
        behaviorGraph: preparation?.behaviorGraph || ctx.behaviorGraph,
    });
}

export async function safeIndexSourceFileHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) return failure(ctx.error);

    let bound;
    try {
        bound = resolveBoundSource(ctx);
    } catch (err) {
        return failure(`safe_index_source_file refused: ${err.message}`);
    }

    let relativePath;
    try {
        relativePath = normalizeRelativePath(args.path);
    } catch (err) {
        return failure(`safe_index_source_file refused: ${err.message}`);
    }
    const maxBytes = args.max_bytes === undefined
        ? DEFAULT_MAX_FILE_BYTES
        : Math.min(Number(args.max_bytes), HARD_MAX_FILE_BYTES);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
        return failure("max_bytes must be a positive integer");
    }

    const indexState = getAnalysisIndexState(sessionId);
    const fileIndex = indexState?.fileIndex?.get(relativePath);
    const enumerated = Number.isInteger(fileIndex) ? indexState.files[fileIndex] : null;
    if (!enumerated) {
        return failure(
            `safe_index_source_file refused: path was not enumerated by zerotrust_safe_list_source: ${relativePath}`,
        );
    }

    let absolutePath;
    let preOpenStats;
    try {
        absolutePath = assertPathChainNoReparse(bound.root, relativePath);
        if (!pathsEqual(absolutePath, nodePath.resolve(bound.root, ...relativePath.split("/")))) {
            throw new Error("source path did not resolve to the exact bound location");
        }
        preOpenStats = lstatSync(absolutePath);
        if (preOpenStats.size !== enumerated.size) {
            throw new Error(
                `source file size changed after enumeration (${enumerated.size} -> ${preOpenStats.size})`,
            );
        }
    } catch (err) {
        mutateAnalysisIndexState(sessionId, (state) =>
            recordIndexReadFailure(state, { path: relativePath, error: err }));
        return failure(`safe_index_source_file refused: ${err.message}`, {
            analysisIndex: getAnalysisIndexSnapshot(sessionId),
        });
    }

    if (enumerated.size > maxBytes) {
        try {
            mutateAnalysisIndexState(sessionId, (state) =>
                recordIndexedFile(state, {
                    path: relativePath,
                    size: enumerated.size,
                    classification: "unknown",
                    classificationComplete: false,
                    contentTooLarge: true,
                    facts: [],
                }));
        } catch (err) {
            return failure(`safe_index_source_file accounting failed: ${err.message}`);
        }
        return success({
            sourceKind: bound.sourceKind,
            sourceRoot: bound.root,
            path: relativePath,
            classification: "unknown",
            classificationComplete: false,
            contentTooLarge: true,
            note: `file exceeds max_bytes (${maxBytes}); no bytes were read and preparation remains incomplete`,
            analysisFacts: [],
            analysisIndex: getAnalysisIndexSnapshot(sessionId),
            analysisStageState: ctx.analysisStageState,
            analysisPlugins: ctx.analysisPlugins,
            behaviorGraph: ctx.behaviorGraph,
        });
    }

    let fd = null;
    let buffer = null;
    let fetchResult = null;
    let extraction = { facts: [], overflow: false, lineCount: null };
    let unicode = { complete: false, matchCount: 0 };
    try {
        fd = openSync(
            absolutePath,
            constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
        );
        const openedStats = fstatSync(fd);
        if (!openedStats.isFile() || openedStats.size !== enumerated.size) {
            throw new Error("source file identity changed while opening it");
        }
        if (Number.isSafeInteger(preOpenStats.ino) && Number.isSafeInteger(openedStats.ino)
            && preOpenStats.ino !== 0 && openedStats.ino !== 0
            && (preOpenStats.ino !== openedStats.ino
                || preOpenStats.dev !== openedStats.dev)) {
            throw new Error("source file inode changed while opening it");
        }
        const postOpenPath = assertPathChainNoReparse(bound.root, relativePath);
        const postOpenStats = lstatSync(postOpenPath);
        if (Number.isSafeInteger(postOpenStats.ino) && Number.isSafeInteger(openedStats.ino)
            && postOpenStats.ino !== 0 && openedStats.ino !== 0
            && (postOpenStats.ino !== openedStats.ino
                || postOpenStats.dev !== openedStats.dev)) {
            throw new Error("source path was replaced while opening it");
        }
        buffer = readFileSync(fd);
        if (buffer.length !== enumerated.size) {
            throw new Error("source file size changed while reading it");
        }
        fetchResult = apiClientInternals.buildFetchResultFromBuffer(
            relativePath,
            buffer,
            {
                maxBytes,
                maxTextBytes: maxBytes,
            },
        );
        const fullText = fetchResult.classification === "text"
            && fetchResult.classificationComplete === true
            && fetchResult.contentReturned === true
            && fetchResult.textTruncated !== true
            && typeof fetchResult.text === "string";
        if (fullText) {
            unicode = invisibleUnicodeScan(fetchResult.text);
            extraction = extractFactsFromText({
                path: relativePath,
                text: fetchResult.text,
            });
            delete fetchResult.text;
        }
    } catch (err) {
        mutateAnalysisIndexState(sessionId, (state) =>
            recordIndexReadFailure(state, { path: relativePath, error: err }));
        return failure(`safe_index_source_file failed: ${err.message}`, {
            analysisIndex: getAnalysisIndexSnapshot(sessionId),
        });
    } finally {
        if (fd !== null) closeSync(fd);
        if (buffer) buffer.fill(0);
    }

    let analysisFacts;
    try {
        const mutation = mutateAnalysisIndexState(sessionId, (state) => {
            recordIndexedFile(state, {
                path: relativePath,
                size: fetchResult.sizeBytes,
                classification: fetchResult.classification,
                classificationComplete: fetchResult.classificationComplete,
                contentTooLarge: fetchResult.contentTooLarge === true,
                textTruncated: fetchResult.textTruncated === true,
                contentSha256: fetchResult.sha256 || null,
                facts: extraction.facts,
                factsOverflow: extraction.overflow,
                lineCount: fetchResult.classification === "text"
                    ? extraction.lineCount
                    : null,
                invisibleUnicodeScanComplete: unicode.complete,
                invisibleUnicodeMatchCount: unicode.matchCount,
            });
            analysisFacts = listIndexedFacts(state, {
                path: relativePath,
                limit: 256,
            }).facts;
            return true;
        });
        if (!mutation.ok) {
            return failure("safe_index_source_file refused: could not persist analysis facts");
        }
    } catch (err) {
        return failure(`safe_index_source_file accounting failed: ${err.message}`);
    } finally {
        if (fetchResult && Object.hasOwn(fetchResult, "text")) delete fetchResult.text;
        extraction = null;
    }

    const preparation = maybeAdvanceAnalysisPrepared(sessionId);
    return success({
        sourceKind: bound.sourceKind,
        sourceRoot: bound.root,
        ...publicClassification(fetchResult),
        invisibleUnicodeScan: unicode,
        analysisFacts,
        analysisIndex: preparation?.analysisIndex || getAnalysisIndexSnapshot(sessionId),
        analysisStageState: preparation?.analysisStageState || ctx.analysisStageState,
        analysisPlugins: preparation?.analysisPlugins || ctx.analysisPlugins,
        behaviorGraph: preparation?.behaviorGraph || ctx.behaviorGraph,
    });
}

function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, ...data }, null, 2),
        resultType: "success",
    };
}

function failure(message, data = {}) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, error: message, ...data }, null, 2),
        resultType: "failure",
    };
}

export const __internals = Object.freeze({
    MAX_OUTPUT_ENTRIES,
    MAX_ENUMERATED_DIRECTORIES,
    MAX_ENUMERATED_ENTRIES,
    DEFAULT_MAX_FILE_BYTES,
    HARD_MAX_FILE_BYTES,
    pathsEqual,
    pathIsUnder,
    normalizeRelativePath,
    resolveBoundSource,
    assertSafeRoot,
    enumerateSource,
    assertPathChainNoReparse,
    invisibleUnicodeScan,
    publicClassification,
});
