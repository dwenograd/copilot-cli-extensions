import { randomUUID } from "node:crypto";
import {
    closeSync,
    constants,
    existsSync,
    fstatSync,
    fsyncSync,
    lstatSync,
    mkdirSync,
    openSync,
    readFileSync,
    readdirSync,
    renameSync,
    rmdirSync,
    unlinkSync,
    writeFileSync,
} from "node:fs";
import nodePath from "node:path";

import {
    CACHE_LIMITS,
    CACHE_SCHEMA_VERSION,
    CACHE_TOOL_VERSION,
    __internals as cacheInternals,
    buildCachePaths,
    buildCachePayload,
    canonicalJson,
    deriveCacheSourceIdentity,
    parseCacheEnvelope,
    selectReusableCache,
    serializeCacheEnvelope,
    validateCachePayload,
} from "../analysis/cache.mjs";
import {
    getAnalysisIndexState,
    getAnalysisPluginCacheRecords,
    getAnalysisStageState,
    getTrustedAuditContext,
} from "../enforcement.mjs";
import { validateAuditId } from "../analysis/schemas.mjs";
import { DEFAULT_BUILD_ROOT, resolveCacheRoot } from "./defaults.mjs";
import {
    clearCacheBinding,
    recordCacheBinding,
} from "./state.mjs";

const TEMP_FILE_RE = /^\.source-[a-f0-9]{64}\.json\.tmp-[0-9a-f-]{36}$/u;

function pathsEqual(left, right) {
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function pathIsUnder(parent, child) {
    const relative = nodePath.relative(nodePath.resolve(parent), nodePath.resolve(child));
    return !!relative && !relative.startsWith("..") && !nodePath.isAbsolute(relative);
}

function lstat(path) {
    try {
        return lstatSync(path);
    } catch (error) {
        if (error?.code === "ENOENT") return null;
        throw error;
    }
}

function assertPlainDirectory(path, label) {
    const stat = lstat(path);
    if (!stat) return false;
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
        throw new Error(`${label} is not a plain directory; symlinks/reparse points are refused`);
    }
    return true;
}

function ensureSafeDirectoryChain(buildRoot, target) {
    const root = nodePath.resolve(buildRoot);
    const destination = nodePath.resolve(target);
    if (!pathsEqual(root, destination) && !pathIsUnder(root, destination)) {
        throw new Error("cache directory escaped active build_root");
    }
    if (!existsSync(root)) mkdirSync(root, { recursive: true });
    assertPlainDirectory(root, "active build_root");
    if (pathsEqual(root, destination)) return;
    let current = root;
    const segments = nodePath.relative(root, destination).split(nodePath.sep).filter(Boolean);
    for (const segment of segments) {
        current = nodePath.join(current, segment);
        if (!existsSync(current)) {
            mkdirSync(current);
        }
        assertPlainDirectory(current, "cache directory");
    }
}

function listPlainEntries(directory) {
    if (!existsSync(directory)) return [];
    assertPlainDirectory(directory, "cache directory");
    return readdirSync(directory, { withFileTypes: true });
}

function safeUnlinkCacheEntry(filePath, namespacePath) {
    if (!pathIsUnder(namespacePath, filePath)
        || !pathsEqual(nodePath.dirname(filePath), namespacePath)) {
        throw new Error("cache entry deletion escaped its namespace");
    }
    const basename = nodePath.basename(filePath);
    if (!cacheInternals.CACHE_FILE_RE.test(basename) && !TEMP_FILE_RE.test(basename)) {
        throw new Error("cache entry deletion refused a non-cache filename");
    }
    const stat = lstat(filePath);
    if (!stat) return false;
    if (stat.isDirectory()) throw new Error("cache file path is unexpectedly a directory");
    unlinkSync(filePath);
    return !existsSync(filePath);
}

function readCacheFile(filePath, namespacePath) {
    if (!pathsEqual(nodePath.dirname(filePath), namespacePath)
        || !cacheInternals.CACHE_FILE_RE.test(nodePath.basename(filePath))) {
        throw new Error("cache read path is not canonical");
    }
    const before = lstat(filePath);
    if (!before) return null;
    if (before.isSymbolicLink() || !before.isFile()) {
        throw new Error("cache entry is not a plain file");
    }
    if (before.size > CACHE_LIMITS.fileBytes) {
        throw new Error(`cache entry exceeds ${CACHE_LIMITS.fileBytes} bytes`);
    }
    const noFollow = constants.O_NOFOLLOW || 0;
    const fd = openSync(filePath, constants.O_RDONLY | noFollow);
    try {
        const opened = fstatSync(fd);
        if (!opened.isFile()
            || opened.size !== before.size
            || (before.dev !== undefined && opened.dev !== before.dev)
            || (before.ino !== undefined && opened.ino !== before.ino)) {
            throw new Error("cache entry changed during validation");
        }
        const bytes = readFileSync(fd);
        let raw;
        try {
            raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        } catch {
            throw new Error("cache entry is not valid UTF-8");
        }
        return parseCacheEnvelope(raw);
    } finally {
        closeSync(fd);
    }
}

function listCanonicalCacheFiles(namespacePath) {
    const result = [];
    for (const entry of listPlainEntries(namespacePath)) {
        const filePath = nodePath.join(namespacePath, entry.name);
        if (TEMP_FILE_RE.test(entry.name)) {
            safeUnlinkCacheEntry(filePath, namespacePath);
            continue;
        }
        if (!cacheInternals.CACHE_FILE_RE.test(entry.name)) {
            throw new Error(`cache namespace contains an unexpected entry: ${entry.name}`);
        }
        const stat = lstat(filePath);
        if (!stat || stat.isSymbolicLink() || !stat.isFile()) {
            throw new Error(`cache namespace contains a non-plain entry: ${entry.name}`);
        }
        result.push({
            path: filePath,
            size: stat.size,
            mtimeMs: stat.mtimeMs,
        });
    }
    return result.sort((left, right) =>
        right.mtimeMs - left.mtimeMs || left.path.localeCompare(right.path));
}

function collectVersionCacheFiles(versionRoot) {
    const files = [];
    for (const namespaceEntry of listPlainEntries(versionRoot)) {
        if (!/^namespace-[a-f0-9]{64}$/u.test(namespaceEntry.name)) {
            throw new Error(`cache version root contains an unexpected entry: ${namespaceEntry.name}`);
        }
        const namespacePath = nodePath.join(versionRoot, namespaceEntry.name);
        if (!assertPlainDirectory(namespacePath, "cache namespace")) {
            throw new Error("cache namespace disappeared during enumeration");
        }
        for (const file of listCanonicalCacheFiles(namespacePath)) {
            files.push({ ...file, namespacePath });
        }
    }
    return files;
}

function collectAllCacheFiles(cacheRoot) {
    if (!existsSync(cacheRoot)) return [];
    const files = [];
    for (const schemaEntry of listPlainEntries(cacheRoot)) {
        if (!/^schema-[1-9][0-9]*$/u.test(schemaEntry.name)) {
            throw new Error(`cache root contains an unexpected entry: ${schemaEntry.name}`);
        }
        const schemaPath = nodePath.join(cacheRoot, schemaEntry.name);
        if (!assertPlainDirectory(schemaPath, "cache schema directory")) {
            throw new Error("cache schema directory disappeared during enumeration");
        }
        for (const toolEntry of listPlainEntries(schemaPath)) {
            if (!/^tool-[a-f0-9]{64}$/u.test(toolEntry.name)) {
                throw new Error(`cache schema directory contains an unexpected entry: ${toolEntry.name}`);
            }
            const versionRoot = nodePath.join(schemaPath, toolEntry.name);
            if (!assertPlainDirectory(versionRoot, "cache tool-version directory")) {
                throw new Error("cache tool-version directory disappeared during enumeration");
            }
            files.push(...collectVersionCacheFiles(versionRoot));
        }
    }
    return files;
}

function enforceCapsBeforeWrite(paths, targetBytes) {
    if (targetBytes > CACHE_LIMITS.fileBytes) {
        throw new Error(`serialized cache exceeds ${CACHE_LIMITS.fileBytes} bytes`);
    }
    let files = collectAllCacheFiles(paths.cacheRoot);
    const existing = files.find((entry) => pathsEqual(entry.path, paths.filePath)) || null;
    files = files.filter((entry) => !pathsEqual(entry.path, paths.filePath));
    let totalBytes = files.reduce((sum, entry) => sum + entry.size, 0) + targetBytes;
    let totalFiles = files.length + 1;
    let namespaceFiles = files.filter((entry) =>
        pathsEqual(entry.namespacePath, paths.namespacePath)).length + 1;

    while (totalBytes > CACHE_LIMITS.totalBytes
        || totalFiles > CACHE_LIMITS.totalFiles
        || namespaceFiles > CACHE_LIMITS.namespaceFiles) {
        const namespaceOverflow = namespaceFiles > CACHE_LIMITS.namespaceFiles;
        const candidates = files
            .filter((entry) =>
                !namespaceOverflow || pathsEqual(entry.namespacePath, paths.namespacePath))
            .sort((left, right) =>
                left.mtimeMs - right.mtimeMs || left.path.localeCompare(right.path));
        const victim = candidates[0];
        if (!victim) throw new Error("cache caps cannot be satisfied safely");
        if (!safeUnlinkCacheEntry(victim.path, victim.namespacePath)) {
            throw new Error("failed to evict an old cache entry");
        }
        files = files.filter((entry) => entry.path !== victim.path);
        totalBytes -= victim.size;
        totalFiles -= 1;
        if (pathsEqual(victim.namespacePath, paths.namespacePath)) namespaceFiles -= 1;
    }
    return {
        replacedExisting: !!existing,
        totalBytesAfterWrite: totalBytes,
        totalFilesAfterWrite: totalFiles,
        namespaceFilesAfterWrite: namespaceFiles,
    };
}

function atomicWriteCache(filePath, namespacePath, serialized) {
    ensureSafeDirectoryChain(nodePath.dirname(nodePath.dirname(nodePath.dirname(namespacePath))), namespacePath);
    const tempPath = nodePath.join(
        namespacePath,
        `.${nodePath.basename(filePath)}.tmp-${randomUUID()}`,
    );
    let fd = null;
    try {
        fd = openSync(
            tempPath,
            constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
            0o600,
        );
        writeFileSync(fd, serialized, { encoding: "utf8" });
        fsyncSync(fd);
        closeSync(fd);
        fd = null;
        const existing = lstat(filePath);
        if (existing && (existing.isSymbolicLink() || !existing.isFile())) {
            throw new Error("refusing to replace a non-plain cache entry");
        }
        renameSync(tempPath, filePath);
        const stored = readCacheFile(filePath, namespacePath);
        if (!stored) throw new Error("cache file disappeared after atomic write");
        return stored;
    } catch (error) {
        if (fd !== null) {
            try {
                closeSync(fd);
            } catch {
                // Best-effort descriptor cleanup.
            }
        }
        try {
            safeUnlinkCacheEntry(tempPath, namespacePath);
        } catch {
            // Preserve the original write error.
        }
        throw error;
    }
}

function validateCommonArgs(args, allowed) {
    args = args || {};
    if (!isPlainObject(args)) throw new Error("cache arguments must be an object");
    const unexpected = Object.keys(args).filter((key) => !allowed.includes(key));
    if (unexpected.length > 0) {
        throw new Error(`cache tool does not accept arguments: ${unexpected.join(", ")}`);
    }
    return args;
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function resolveActiveCacheContext(args, invocation) {
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) throw new Error("cache tools require an invocation sessionId");
    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) throw new Error(ctx.error);
    if (!ctx.hasActiveAudit) throw new Error("cache tools require an active audit");
    if (typeof args.audit_id !== "string") throw new Error("audit_id is required");
    const auditId = validateAuditId(args.audit_id);
    if (auditId !== ctx.auditId) {
        throw new Error("audit_id does not match the active audit generation");
    }
    const indexState = getAnalysisIndexState(sessionId, { auditId });
    const sourceIdentity = deriveCacheSourceIdentity(ctx, indexState);
    const cacheRoot = resolveCacheRoot(ctx.buildRoot);
    const paths = buildCachePaths(cacheRoot, sourceIdentity);
    recordCacheBinding(sessionId, {
        auditId,
        sourceKey: paths.sourceKey,
        namespaceKey: paths.namespaceKey,
        cachePath: paths.filePath,
    });
    return {
        sessionId,
        auditId,
        ctx,
        indexState,
        sourceIdentity,
        paths,
    };
}

function normalizePluginVersions(value) {
    if (value === undefined) return [];
    if (!Array.isArray(value)) throw new Error("plugin_versions must be an array");
    return value.map((entry) => ({
        pluginId: entry?.plugin_id,
        pluginVersion: entry?.plugin_version,
    }));
}

function buildActivePluginCacheRecords(sessionId, auditId) {
    return getAnalysisPluginCacheRecords(sessionId, { auditId }) || [];
}

function mergePluginCacheRecords(activeRecords, suppliedRecords) {
    const merged = new Map();
    for (const record of activeRecords) {
        merged.set(`${record.pluginId}\0${record.pluginVersion}`, record);
    }
    for (const record of suppliedRecords) {
        const key = `${String(record?.pluginId || "")}\0${String(record?.pluginVersion || "")}`;
        if (merged.has(key)) {
            throw new Error(`plugin_records duplicates active plugin cache record: ${record.pluginId}`);
        }
        merged.set(key, record);
    }
    return [...merged.values()];
}

function discardCorruptEntry(entry, namespacePath) {
    try {
        return safeUnlinkCacheEntry(entry.path, namespacePath);
    } catch {
        return false;
    }
}

function loadNamespaceEntries(paths) {
    const valid = [];
    const discarded = [];
    for (const entry of listCanonicalCacheFiles(paths.namespacePath)) {
        try {
            const envelope = readCacheFile(entry.path, paths.namespacePath);
            if (envelope) valid.push({ ...entry, ...envelope });
        } catch (error) {
            discarded.push({
                file: nodePath.basename(entry.path),
                reason: String(error?.message || error).slice(0, 300),
                removed: discardCorruptEntry(entry, paths.namespacePath),
            });
        }
    }
    return { valid, discarded };
}

export async function cacheListHandler(args, invocation) {
    try {
        args = validateCommonArgs(args, [
            "audit_id",
            "include_prior_sources",
            "build_root",
        ]);
        if (Object.hasOwn(args, "include_prior_sources")
            && typeof args.include_prior_sources !== "boolean") {
            throw new Error("include_prior_sources must be boolean");
        }
        let bound;
        try {
            bound = resolveActiveCacheContext(args, invocation);
        } catch (error) {
            if (/no stable cacheable source identity|requires complete source enumeration|requires every source file/u.test(String(error?.message))) {
                return success({
                    available: false,
                    reason: "active source identity is not cacheable yet",
                    entries: [],
                    discardedCorrupt: [],
                });
            }
            throw error;
        }
        const { valid, discarded } = loadNamespaceEntries(bound.paths);
        const includePrior = args.include_prior_sources === true;
        const entries = valid
            .filter((entry) =>
                includePrior || entry.payload.sourceKey === bound.paths.sourceKey)
            .map((entry) => ({
                sourceKey: entry.payload.sourceKey,
                exactSource: entry.payload.sourceKey === bound.paths.sourceKey,
                storedAt: entry.payload.storedAt,
                sourceSha: entry.payload.sourceIdentity.kind === "github"
                    ? entry.payload.sourceIdentity.sourceSha
                    : null,
                fileCount: entry.payload.files.length,
                pluginRecords: entry.payload.pluginRecords.map((record) => ({
                    pluginId: record.pluginId,
                    pluginVersion: record.pluginVersion,
                })),
                bytes: entry.size,
                integritySha256: entry.integritySha256,
            }));
        return success({
            available: entries.length > 0,
            cacheSchemaVersion: valid[0]?.payload.cacheSchemaVersion || CACHE_SCHEMA_VERSION,
            toolVersion: valid[0]?.payload.toolVersion || CACHE_TOOL_VERSION,
            activeSourceKey: bound.paths.sourceKey,
            entries,
            discardedCorrupt: discarded,
        });
    } catch (error) {
        return failure(error?.message || String(error));
    }
}

export async function cacheLoadHandler(args, invocation) {
    try {
        args = validateCommonArgs(args, [
            "audit_id",
            "plugin_versions",
            "include_prior_source_matches",
            "build_root",
        ]);
        if (Object.hasOwn(args, "include_prior_source_matches")
            && typeof args.include_prior_source_matches !== "boolean") {
            throw new Error("include_prior_source_matches must be boolean");
        }
        const pluginVersions = normalizePluginVersions(args.plugin_versions);
        let bound;
        try {
            bound = resolveActiveCacheContext(args, invocation);
        } catch (error) {
            if (/no stable cacheable source identity|requires complete source enumeration|requires every source file/u.test(String(error?.message))) {
                return success({
                    hit: false,
                    reason: "active source identity is not cacheable yet",
                    files: [],
                    pluginRecords: [],
                    stage: null,
                    coverage: [],
                    discardedCorrupt: [],
                });
            }
            throw error;
        }
        const { valid, discarded } = loadNamespaceEntries(bound.paths);
        const allowPrior = args.include_prior_source_matches !== false;
        const ordered = valid.sort((left, right) => {
            const leftExact = left.payload.sourceKey === bound.paths.sourceKey ? 0 : 1;
            const rightExact = right.payload.sourceKey === bound.paths.sourceKey ? 0 : 1;
            return leftExact - rightExact || right.mtimeMs - left.mtimeMs;
        });
        const files = new Map();
        const plugins = new Map();
        let selectedBytes = 0;
        let truncated = false;
        const loadBudget = CACHE_LIMITS.loadResultBytes - (64 * 1024);
        let stage = null;
        let coverage = [];
        let exactSourceHit = false;
        const reusedSourceKeys = [];
        for (const entry of ordered) {
            const exact = entry.payload.sourceKey === bound.paths.sourceKey;
            if (!exact && !allowPrior) continue;
            const reusable = selectReusableCache(entry.payload, {
                activeSourceIdentity: bound.sourceIdentity,
                indexState: bound.indexState,
                pluginVersions,
            });
            if (!reusable.matched) continue;
            reusedSourceKeys.push(entry.payload.sourceKey);
            if (reusable.exactSource) {
                exactSourceHit = true;
                stage = reusable.stage;
                coverage = reusable.coverage;
            }
            for (const file of reusable.files) {
                if (files.has(file.path)) continue;
                const bytes = Buffer.byteLength(canonicalJson(file), "utf8");
                if (selectedBytes + bytes > loadBudget) {
                    truncated = true;
                    continue;
                }
                selectedBytes += bytes;
                files.set(file.path, file);
            }
            for (const plugin of reusable.pluginRecords) {
                const key = `${plugin.pluginId}\0${plugin.pluginVersion}`;
                if (plugins.has(key)) continue;
                if (!plugin.sourceBlobs.every((sourceBlob) => files.has(sourceBlob.path))) {
                    truncated = true;
                    continue;
                }
                const bytes = Buffer.byteLength(canonicalJson(plugin), "utf8");
                if (selectedBytes + bytes > loadBudget) {
                    truncated = true;
                    continue;
                }
                selectedBytes += bytes;
                plugins.set(key, plugin);
            }
        }
        return success({
            hit: files.size > 0 || plugins.size > 0 || exactSourceHit,
            exactSourceHit,
            reusedPriorSource: reusedSourceKeys.some((key) => key !== bound.paths.sourceKey),
            activeSourceKey: bound.paths.sourceKey,
            reusedSourceKeys,
            files: [...files.values()],
            pluginRecords: [...plugins.values()],
            stage,
            coverage,
            truncated,
            selectedBytes,
            discardedCorrupt: discarded,
        });
    } catch (error) {
        return failure(error?.message || String(error));
    }
}

export async function cacheStoreHandler(args, invocation) {
    try {
        args = validateCommonArgs(args, [
            "audit_id",
            "plugin_records",
            "build_root",
        ]);
        if (args.plugin_records !== undefined && !Array.isArray(args.plugin_records)) {
            throw new Error("plugin_records must be an array");
        }
        const bound = resolveActiveCacheContext(args, invocation);
        const stageState = getAnalysisStageState(bound.sessionId, {
            auditId: bound.auditId,
        });
        const activePluginRecords = buildActivePluginCacheRecords(
            bound.sessionId,
            bound.auditId,
        );
        const suppliedPluginRecords = args.plugin_records || [];
        mergePluginCacheRecords(activePluginRecords, suppliedPluginRecords);
        let acceptedPluginRecords = [...suppliedPluginRecords];
        let payload = buildCachePayload({
            sourceIdentity: bound.sourceIdentity,
            indexState: bound.indexState,
            stageState,
            pluginRecords: acceptedPluginRecords,
        });
        const skippedActivePluginRecords = [];
        for (const activeRecord of activePluginRecords) {
            try {
                payload = buildCachePayload({
                    sourceIdentity: bound.sourceIdentity,
                    indexState: bound.indexState,
                    stageState,
                    pluginRecords: [...acceptedPluginRecords, activeRecord],
                });
                acceptedPluginRecords = [...acceptedPluginRecords, activeRecord];
            } catch (error) {
                skippedActivePluginRecords.push({
                    pluginId: activeRecord.pluginId,
                    pluginVersion: activeRecord.pluginVersion,
                    reason: String(error?.message || error).slice(0, 300),
                });
            }
        }
        const serialized = serializeCacheEnvelope(payload);
        ensureSafeDirectoryChain(bound.ctx.buildRoot, bound.paths.namespacePath);
        const caps = enforceCapsBeforeWrite(
            bound.paths,
            Buffer.byteLength(serialized, "utf8"),
        );
        const stored = atomicWriteCache(
            bound.paths.filePath,
            bound.paths.namespacePath,
            serialized,
        );
        return success({
            stored: true,
            sourceKey: payload.sourceKey,
            cacheFile: nodePath.basename(bound.paths.filePath),
            bytes: Buffer.byteLength(serialized, "utf8"),
            fileCount: payload.files.length,
            pluginRecordCount: payload.pluginRecords.length,
            skippedActivePluginRecords,
            integritySha256: stored.integritySha256,
            caps,
        });
    } catch (error) {
        return failure(error?.message || String(error));
    }
}

function removeEmptyCacheDirectories(paths) {
    for (const directory of [
        paths.namespacePath,
        paths.versionRoot,
        nodePath.dirname(paths.versionRoot),
        paths.cacheRoot,
    ]) {
        try {
            if (existsSync(directory)
                && assertPlainDirectory(directory, "cache directory")
                && readdirSync(directory).length === 0) {
                rmdirSync(directory);
            }
        } catch {
            // Empty-directory removal is best-effort; cache content deletion already succeeded.
        }
    }
}

export async function cacheCleanupHandler(args, invocation) {
    try {
        args = validateCommonArgs(args, [
            "audit_id",
            "scope",
            "build_root",
        ]);
        const scope = args.scope || "current_source";
        if (!["current_source", "source_namespace"].includes(scope)) {
            throw new Error("scope must be current_source or source_namespace");
        }
        let bound;
        try {
            bound = resolveActiveCacheContext(args, invocation);
        } catch (error) {
            if (/no stable cacheable source identity|requires complete source enumeration|requires every source file/u.test(String(error?.message))) {
                return success({
                    cleaned: true,
                    scope,
                    removed: [],
                    reason: "active source identity is not cacheable yet",
                });
            }
            throw error;
        }
        const removed = [];
        if (scope === "current_source") {
            if (safeUnlinkCacheEntry(bound.paths.filePath, bound.paths.namespacePath)) {
                removed.push(nodePath.basename(bound.paths.filePath));
            }
        } else {
            for (const entry of listCanonicalCacheFiles(bound.paths.namespacePath)) {
                if (safeUnlinkCacheEntry(entry.path, bound.paths.namespacePath)) {
                    removed.push(nodePath.basename(entry.path));
                }
            }
        }
        removeEmptyCacheDirectories(bound.paths);
        clearCacheBinding(bound.sessionId);
        return success({
            cleaned: true,
            scope,
            removed,
        });
    } catch (error) {
        return failure(error?.message || String(error));
    }
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
    TEMP_FILE_RE,
    pathsEqual,
    pathIsUnder,
    assertPlainDirectory,
    ensureSafeDirectoryChain,
    safeUnlinkCacheEntry,
    readCacheFile,
    listCanonicalCacheFiles,
    collectVersionCacheFiles,
    collectAllCacheFiles,
    enforceCapsBeforeWrite,
    atomicWriteCache,
    resolveActiveCacheContext,
    buildActivePluginCacheRecords,
    mergePluginCacheRecords,
});
