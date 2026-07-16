import { createHash } from "node:crypto";

import {
    EVASIVE_BLOCKERS,
    EVASIVE_LIMITS,
    createAssuranceAnalysisSnapshot,
    createEvasiveObjectInventoryRecord,
} from "./evasiveSchemas.mjs";

export const GIT_TREE_MODES = Object.freeze({
    TREE: "040000",
    BLOB: "100644",
    EXECUTABLE_BLOB: "100755",
    SYMLINK: "120000",
    GITLINK: "160000",
});

const MODE_BY_TYPE = Object.freeze({
    blob: GIT_TREE_MODES.BLOB,
    tree: GIT_TREE_MODES.TREE,
    commit: GIT_TREE_MODES.GITLINK,
});

const TYPE_BY_MODE = Object.freeze({
    [GIT_TREE_MODES.TREE]: "tree",
    [GIT_TREE_MODES.BLOB]: "blob",
    [GIT_TREE_MODES.EXECUTABLE_BLOB]: "blob",
    [GIT_TREE_MODES.SYMLINK]: "blob",
    [GIT_TREE_MODES.GITLINK]: "commit",
});

const KIND_BY_MODE = Object.freeze({
    [GIT_TREE_MODES.TREE]: "tree",
    [GIT_TREE_MODES.BLOB]: "blob",
    [GIT_TREE_MODES.EXECUTABLE_BLOB]: "executable-blob",
    [GIT_TREE_MODES.SYMLINK]: "symlink",
    [GIT_TREE_MODES.GITLINK]: "gitlink",
});

const SHA1_RE = /^[a-f0-9]{40}$/u;
const SHA256_RE = /^[a-f0-9]{64}$/u;
const MAX_BLOCKER_DETAILS = 100;
const MAX_LFS_POINTER_BYTES = 4096;
const BLOCKER_KEYS = new WeakMap();

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function hashSourceIdentity(domain, value) {
    return createHash("sha256")
        .update(domain, "utf8")
        .update("\0", "utf8")
        .update(JSON.stringify(value), "utf8")
        .digest("hex");
}

function normalizedPath(path) {
    const value = String(path || "").replace(/\\/gu, "/");
    if (!value || value.length > 4096 || value.startsWith("/")
        || value.endsWith("/") || value.includes("//")
        || /[\u0000-\u001f\u007f]/u.test(value)
        || value.split("/").some((segment) =>
            segment.length === 0 || segment === "." || segment === "..")) {
        throw new Error(`invalid object inventory path: ${JSON.stringify(path)}`);
    }
    return value;
}

function parentPath(path) {
    const index = path.lastIndexOf("/");
    return index < 0 ? "": path.slice(0, index);
}

function sortByDepthAndPath(left, right) {
    const leftDepth = left.path.split("/").length;
    const rightDepth = right.path.split("/").length;
    return leftDepth - rightDepth || left.path.localeCompare(right.path);
}

export function classifyGitTreeEntry({ type, mode } = {}) {
    if (!Object.hasOwn(MODE_BY_TYPE, type)) {
        throw new Error(`unsupported Git tree object type: ${JSON.stringify(type)}`);
    }
    const normalizedMode = mode === undefined || mode === null || mode === ""
        ? MODE_BY_TYPE[type]: String(mode);
    if (!Object.hasOwn(TYPE_BY_MODE, normalizedMode)) {
        throw new Error(`unsupported Git tree mode: ${JSON.stringify(mode)}`);
    }
    if (TYPE_BY_MODE[normalizedMode] !== type) {
        throw new Error(
            `Git tree mode/type mismatch: mode ${normalizedMode} cannot describe ${type}`,
        );
    }
    return Object.freeze({
        type,
        mode: normalizedMode,
        modeInferred: mode === undefined || mode === null || mode === "",
        objectKind: KIND_BY_MODE[normalizedMode],
        executable: normalizedMode === GIT_TREE_MODES.EXECUTABLE_BLOB,
        classificationRequired: type === "blob",
    });
}

export function computeGitBlobSha1(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new Error("computeGitBlobSha1 requires a Buffer");
    }
    return createHash("sha1")
        .update(`blob ${buffer.length}\0`, "utf8")
        .update(buffer)
        .digest("hex");
}

export function verifyGitBlobSha1(buffer, expectedSha, path = "<blob>") {
    const normalizedExpected = String(expectedSha || "").toLowerCase();
    if (!SHA1_RE.test(normalizedExpected)) {
        throw new Error(`invalid expected Git blob SHA for ${path}`);
    }
    const actual = computeGitBlobSha1(buffer);
    if (actual !== normalizedExpected) {
        throw new Error(
            `Git blob identity mismatch for ${path}: expected ${normalizedExpected}, recomputed ${actual}`,
        );
    }
    return actual;
}

export function parseGitSymlinkTarget(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new Error("parseGitSymlinkTarget requires a Buffer");
    }
    let target;
    try {
        target = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    } catch {
        return Object.freeze({
            valid: false,
            target: null,
            kind: "invalid",
            byteLength: buffer.length,
            targetSha256: sha256(buffer),
        });
    }
    const invalid = target.length === 0
        || target.includes("\0")
        || /[\r\n\u0000-\u001f\u007f]/u.test(target);
    let kind = "relative";
    if (invalid) {
        kind = "invalid";
    } else if (/^\\\\/u.test(target)) {
        kind = "unc";
    } else if (/^[A-Za-z]:[\\/]/u.test(target)) {
        kind = "absolute-windows";
    } else if (target.startsWith("/")) {
        kind = "absolute-posix";
    }
    return Object.freeze({
        valid: !invalid,
        target: invalid ? null: target,
        kind,
        byteLength: buffer.length,
        targetSha256: sha256(buffer),
    });
}

export function parseGitLfsPointer(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new Error("parseGitLfsPointer requires a Buffer");
    }
    if (buffer.length === 0 || buffer.length > MAX_LFS_POINTER_BYTES) return null;
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    } catch {
        return null;
    }
    const lines = text.replace(/\r\n/gu, "\n").replace(/\n$/u, "").split("\n");
    if (lines[0] !== "version https://git-lfs.github.com/spec/v1") return null;
    const oidMatch = lines[1]?.match(/^oid sha256:([a-f0-9]{64})$/u);
    const sizeMatch = lines[2]?.match(/^size (0|[1-9][0-9]*)$/u);
    const extensionsValid = lines.slice(3).every((line) =>
        /^ext-[A-Za-z0-9][A-Za-z0-9.-]{0,63} [^\u0000-\u001f\u007f]{1,1024}$/u.test(line));
    if (!oidMatch || !sizeMatch || !extensionsValid) {
        return Object.freeze({
            detected: true,
            valid: false,
            oidSha256: null,
            size: null,
        });
    }
    const size = Number(sizeMatch[1]);
    if (!Number.isSafeInteger(size)) {
        return Object.freeze({
            detected: true,
            valid: false,
            oidSha256: null,
            size: null,
        });
    }
    return Object.freeze({
        detected: true,
        valid: true,
        oidSha256: oidMatch[1],
        size,
    });
}

function fetchedDetailByPath(acquisitionState) {
    const result = new Map();
    for (const record of acquisitionState?.fetchRecords || []) {
        if (record?.best && typeof record.path === "string") {
            result.set(record.path, record.best);
        }
    }
    return result;
}

function normalizedTreeEntries(entries) {
    const byPath = new Map();
    for (const entry of entries || []) {
        const path = normalizedPath(entry.path);
        const classification = classifyGitTreeEntry(entry);
        const sha = String(entry.sha || "").toLowerCase();
        if (!SHA1_RE.test(sha)) {
            throw new Error(`invalid upstream Git object SHA at ${path}`);
        }
        const normalized = {
            path,
            type: classification.type,
            mode: classification.mode,
            modeInferred: classification.modeInferred,
            objectKind: classification.objectKind,
            executable: classification.executable,
            sha,
            size: Number.isSafeInteger(entry.size) && entry.size >= 0
                ? entry.size: 0,
        };
        const existing = byPath.get(path);
        if (existing && (existing.sha !== normalized.sha
            || existing.mode !== normalized.mode
            || existing.type !== normalized.type)) {
            throw new Error(`Git object inventory identity conflict at ${path}`);
        }
        if (!existing) byPath.set(path, normalized);
    }
    return [...byPath.values()].sort(sortByDepthAndPath);
}

function appendBlocker(blockers, blocker) {
    const key = JSON.stringify(blocker);
    let keys = BLOCKER_KEYS.get(blockers);
    if (!keys) {
        keys = new Set();
        BLOCKER_KEYS.set(blockers, keys);
    }
    if (keys.has(key)) return;
    keys.add(key);
    blockers.push(Object.freeze(blocker));
}

function boundRecords(records, blockers) {
    if (records.length <= EVASIVE_LIMITS.objectInventoryRecords) return records;
    appendBlocker(blockers, {
        code: EVASIVE_BLOCKERS.INVENTORY_TRUNCATED,
        path: "<object-inventory>",
    });
    return records.slice(0, EVASIVE_LIMITS.objectInventoryRecords);
}

function recordBlockerCodes(records, blockers) {
    const codes = new Set();
    for (const record of records) {
        for (const code of record.blockerCodes) codes.add(code);
    }
    for (const blocker of blockers) codes.add(blocker.code);
    return [...codes].sort();
}

function fetchedGitObjectKind(entry, detail) {
    if (entry.mode === GIT_TREE_MODES.EXECUTABLE_BLOB) return "executable-blob";
    if (entry.mode === GIT_TREE_MODES.SYMLINK) return "symlink";
    if (detail.byteClassification === "text") return "source-text";
    if (detail.byteClassification === "binary") return "binary";
    return "opaque";
}

function gitObjectRecord({
    auditId,
    sourceNamespace,
    entry,
    parentObjectId,
    parentUpstreamSha,
    detail,
}) {
    if (entry.mode === GIT_TREE_MODES.TREE) {
        return createEvasiveObjectInventoryRecord({
            auditId,
            sourceNamespace,
            path: entry.path,
            parentObjectId,
            objectKind: "tree",
            byteLength: 0,
            status: "inventoried",
            blockerCodes: [],
            contentSha256: null,
            upstreamSha: entry.sha,
            gitObjectType: "tree",
            gitMode: entry.mode,
            parentUpstreamSha,
            executable: false,
            symlinkTarget: null,
            lfsPointer: null,
        });
    }
    if (entry.mode === GIT_TREE_MODES.GITLINK) {
        return createEvasiveObjectInventoryRecord({
            auditId,
            sourceNamespace,
            path: entry.path,
            parentObjectId,
            objectKind: "gitlink",
            byteLength: 0,
            status: "blocked",
            blockerCodes: [EVASIVE_BLOCKERS.GITLINK_UNRESOLVED],
            contentSha256: null,
            upstreamSha: entry.sha,
            gitObjectType: "commit",
            gitMode: entry.mode,
            parentUpstreamSha,
            executable: false,
            symlinkTarget: null,
            lfsPointer: null,
        });
    }

    const verified = detail?.gitBlobSha1Verified === true
        && detail.gitBlobSha1 === entry.sha
        && typeof detail.sha256 === "string"
        && SHA256_RE.test(detail.sha256);
    const symlinkTarget = entry.mode === GIT_TREE_MODES.SYMLINK
        ? detail?.symlinkTarget || null: null;
    const malformedSymlink = entry.mode === GIT_TREE_MODES.SYMLINK
        && (!symlinkTarget || symlinkTarget.valid !== true);
    const malformedLfs = detail?.lfsPointer?.detected === true
        && detail.lfsPointer.valid !== true;
    const blockerCodes = [];
    if (!verified) blockerCodes.push(EVASIVE_BLOCKERS.NESTED_OBJECT_UNRESOLVED);
    if (malformedSymlink || malformedLfs) blockerCodes.push(EVASIVE_BLOCKERS.UNSUPPORTED_OBJECT);
    const inventoried = blockerCodes.length === 0;
    return createEvasiveObjectInventoryRecord({
        auditId,
        sourceNamespace,
        path: entry.path,
        parentObjectId,
        objectKind: fetchedGitObjectKind(entry, detail || {}),
        byteLength: Number.isSafeInteger(detail?.sizeBytes)
            ? detail.sizeBytes: entry.size,
        status: inventoried ? "inventoried": "blocked",
        blockerCodes,
        contentSha256: verified ? detail.sha256: null,
        upstreamSha: entry.sha,
        gitObjectType: "blob",
        gitMode: entry.mode,
        parentUpstreamSha,
        executable: entry.executable,
        symlinkTarget: symlinkTarget?.valid === true
            ? {
                kind: symlinkTarget.kind,
                byteLength: symlinkTarget.byteLength,
                targetSha256: symlinkTarget.targetSha256,
            }: null,
        lfsPointer: detail?.lfsPointer?.valid === true
            ? {
                oidSha256: detail.lfsPointer.oidSha256,
                size: detail.lfsPointer.size,
            }: null,
    });
}

function lfsPayloadRecord({ auditId, sourceNamespace, parent }) {
    return createEvasiveObjectInventoryRecord({
        auditId,
        sourceNamespace,
        path: `${parent.path}#git-lfs-object`,
        parentObjectId: parent.objectId,
        objectKind: "embedded-payload",
        byteLength: parent.lfsPointer.size,
        status: "blocked",
        blockerCodes: [EVASIVE_BLOCKERS.LFS_PAYLOAD_UNRESOLVED],
        contentSha256: parent.lfsPointer.oidSha256,
        upstreamSha: null,
        gitObjectType: null,
        gitMode: null,
        parentUpstreamSha: null,
        executable: false,
        symlinkTarget: null,
        lfsPointer: null,
    });
}

function createSnapshot({
    auditId,
    sourceNamespace,
    stageState,
    records,
    blockerCodes,
    sourceIdentitySha256,
    previousSnapshot,
}) {
    const nestedBlockerCodes = [
        ...(previousSnapshot?.derivedArtifacts || []),
        ...(previousSnapshot?.semanticReviewCoverage || []),
        ...(previousSnapshot?.redTeamCoverage || []),
    ].flatMap((record) => record.blockerCodes || []);
    return createAssuranceAnalysisSnapshot({
        auditId,
        sourceNamespace,
        stageState,
        status: "incomplete",
        objectInventory: records,
        derivedArtifacts: previousSnapshot?.derivedArtifacts || [],
        semanticReviewCoverage: previousSnapshot?.semanticReviewCoverage || [],
        semanticCandidateLedger: previousSnapshot?.semanticCandidateLedger || [],
        redTeamCoverage: previousSnapshot?.redTeamCoverage || [],
        blockerCodes: [...new Set([
            ...blockerCodes,
            ...nestedBlockerCodes,
        ])].sort(),
        sourceIdentitySha256,
    });
}

function inventorySummary(snapshot, complete, blockers, records) {
    const counts = {
        total: records.length,
        inventoried: records.filter((record) => record.status === "inventoried").length,
        blocked: records.filter((record) => record.status === "blocked").length,
        trees: records.filter((record) => record.objectKind === "tree").length,
        executableBlobs: records.filter((record) =>
            record.objectKind === "executable-blob").length,
        symlinks: records.filter((record) => record.objectKind === "symlink").length,
        gitlinks: records.filter((record) => record.objectKind === "gitlink").length,
        lfsPointers: records.filter((record) => record.lfsPointer !== null).length,
        reparsePoints: records.filter((record) =>
            record.objectKind === "reparse-point").length,
    };
    return Object.freeze({
        schemaVersion: 6,
        snapshotId: snapshot.snapshotId,
        stage: snapshot.stageState.current,
        complete,
        counts: Object.freeze(counts),
        blockerCodes: snapshot.blockerCodes,
        blockers: Object.freeze(blockers.slice(0, MAX_BLOCKER_DETAILS)),
        blockersTruncated: blockers.length > MAX_BLOCKER_DETAILS,
        inventorySha256: snapshot.hashes.inventorySha256,
        sourceIdentitySha256: snapshot.hashes.sourceIdentitySha256,
    });
}

export function buildGitObjectInventory({
    auditId,
    sourceNamespace,
    stageState,
    commitSha,
    rootTreeSha,
    treeState,
    acquisitionState,
    previousSnapshot = null,
} = {}) {
    const commit = String(commitSha || "").toLowerCase();
    const root = String(rootTreeSha || "").toLowerCase();
    if (!SHA1_RE.test(commit) || !SHA1_RE.test(root)) {
        throw new Error("Git object inventory requires pinned commit and root-tree SHAs");
    }
    const entries = normalizedTreeEntries(treeState?.entries || []);
    const details = fetchedDetailByPath(acquisitionState);
    const treeByPath = new Map(
        entries.filter((entry) => entry.mode === GIT_TREE_MODES.TREE)
            .map((entry) => [entry.path, entry]),
    );
    const treeRecordByPath = new Map();
    const records = [];
    const blockers = [];

    for (const entry of entries) {
        const parent = parentPath(entry.path);
        const parentTree = parent ? treeByPath.get(parent): null;
        const parentRecord = parent ? treeRecordByPath.get(parent): null;
        const parentUpstreamSha = parent ? parentTree?.sha: root;
        if (!parentUpstreamSha || (parent && !parentRecord)) {
            appendBlocker(blockers, {
                code: EVASIVE_BLOCKERS.NESTED_OBJECT_UNRESOLVED,
                path: entry.path,
                upstreamSha: entry.sha,
            });
            continue;
        }
        const record = gitObjectRecord({
            auditId,
            sourceNamespace,
            entry,
            parentObjectId: parentRecord?.objectId || null,
            parentUpstreamSha,
            detail: details.get(entry.path),
        });
        records.push(record);
        if (entry.mode === GIT_TREE_MODES.TREE) {
            treeRecordByPath.set(entry.path, record);
        }
        for (const code of record.blockerCodes) {
            appendBlocker(blockers, {
                code,
                path: record.path,
                upstreamSha: record.hashes.upstreamSha,
            });
        }
        if (record.lfsPointer) {
            const payload = lfsPayloadRecord({ auditId, sourceNamespace, parent: record });
            records.push(payload);
            appendBlocker(blockers, {
                code: EVASIVE_BLOCKERS.LFS_PAYLOAD_UNRESOLVED,
                path: payload.path,
                parentObjectId: record.objectId,
            });
        }
    }

    for (const unresolved of treeState?.unresolvedSubtrees || []) {
        appendBlocker(blockers, {
            code: EVASIVE_BLOCKERS.NESTED_OBJECT_UNRESOLVED,
            path: unresolved.path || "<root>",
            upstreamSha: unresolved.sha || null,
        });
    }
    if ((treeState?.coverageBlockers || []).length > 0) {
        appendBlocker(blockers, {
            code: EVASIVE_BLOCKERS.INVENTORY_INCOMPLETE,
            path: "<tree-enumeration>",
        });
    }
    if (treeState?.stateTrackingTruncated === true
        || treeState?.discoveryTruncated === true) {
        appendBlocker(blockers, {
            code: EVASIVE_BLOCKERS.INVENTORY_TRUNCATED,
            path: "<tree-enumeration>",
        });
    }
    const boundedRecords = boundRecords(records, blockers);
    const complete = blockers.length === 0
        && !!treeState
        && treeState.unresolvedSubtrees?.length === 0;
    const blockerCodes = recordBlockerCodes(boundedRecords, blockers);
    const snapshot = createSnapshot({
        auditId,
        sourceNamespace,
        stageState,
        records: boundedRecords,
        blockerCodes,
        sourceIdentitySha256: hashSourceIdentity(
            "zerotrust-git-source-identity",
            { commitSha: commit, rootTreeSha: root },
        ),
        previousSnapshot,
    });
    return Object.freeze({
        snapshot,
        summary: inventorySummary(snapshot, complete, blockers, boundedRecords),
    });
}

function localObjectKind(file) {
    if (file?.classification === "text") return "source-text";
    if (file?.classification === "binary") return "binary";
    return "local-file";
}

export function buildLocalObjectInventory({
    auditId,
    sourceNamespace,
    stageState,
    sourceRoot,
    enumeration,
    indexState,
    observations = null,
    previousSnapshot = null,
} = {}) {
    const priorRecords = previousSnapshot?.objectInventory || [];
    const priorByPath = new Map(priorRecords.map((record) => [record.path, record]));
    const priorDirectories = priorRecords
        .filter((record) => record.objectKind === "tree" && record.gitMode === null)
        .map((record) => ({ path: record.path, size: 0 }));
    const priorFiles = priorRecords
        .filter((record) => record.gitMode === null
            && !["tree", "reparse-point", "embedded-payload"].includes(record.objectKind))
        .map((record) => ({ path: record.path, size: record.byteLength }));
    const priorReparses = priorRecords
        .filter((record) => record.objectKind === "reparse-point")
        .map((record) => ({ path: record.path, size: record.byteLength }));
    const directories = [...(enumeration?.directoryEntries || priorDirectories)]
        .map((entry) => ({ path: normalizedPath(entry.path), size: 0 }))
        .sort(sortByDepthAndPath);
    const files = [...(enumeration?.files || priorFiles)]
        .map((entry) => ({
            path: normalizedPath(entry.path),
            size: Number.isSafeInteger(entry.size) && entry.size >= 0 ? entry.size: 0,
        }))
        .sort(sortByDepthAndPath);
    const reparses = [...(enumeration?.reparsePoints || priorReparses)]
        .map((entry) => ({
            path: normalizedPath(entry.path),
            size: Number.isSafeInteger(entry.size) && entry.size >= 0 ? entry.size: 0,
        }))
        .sort(sortByDepthAndPath);
    const indexedByPath = new Map(
        (indexState?.files || []).map((file) => [file.path, file]),
    );
    const directoryRecords = new Map();
    const records = [];
    const blockers = [];

    for (const directory of directories) {
        const parent = parentPath(directory.path);
        const parentRecord = parent ? directoryRecords.get(parent): null;
        if (parent && !parentRecord) {
            appendBlocker(blockers, {
                code: EVASIVE_BLOCKERS.NESTED_OBJECT_UNRESOLVED,
                path: directory.path,
            });
            continue;
        }
        const record = createEvasiveObjectInventoryRecord({
            auditId,
            sourceNamespace,
            path: directory.path,
            parentObjectId: parentRecord?.objectId || null,
            objectKind: "tree",
            byteLength: 0,
            status: "inventoried",
            blockerCodes: [],
            contentSha256: null,
            upstreamSha: null,
            executable: false,
        });
        directoryRecords.set(directory.path, record);
        records.push(record);
    }

    for (const file of files) {
        const parent = parentPath(file.path);
        const parentRecord = parent ? directoryRecords.get(parent): null;
        if (parent && !parentRecord) {
            appendBlocker(blockers, {
                code: EVASIVE_BLOCKERS.NESTED_OBJECT_UNRESOLVED,
                path: file.path,
            });
            continue;
        }
        const indexed = indexedByPath.get(file.path);
        const observation = observations instanceof Map
            ? observations.get(file.path): observations?.[file.path];
        const observedLfs = observation?.lfsPointer || null;
        const priorLfs = priorByPath.get(file.path)?.lfsPointer || null;
        const lfsPointer = observedLfs?.valid === true
            ? {
                oidSha256: observedLfs.oidSha256,
                size: observedLfs.size,
            }: priorLfs;
        const malformedLfs = observedLfs?.detected === true
            && observedLfs.valid !== true;
        const bytesInventoried = ["indexed-text", "classified-binary"].includes(indexed?.status)
            && typeof indexed.contentSha256 === "string"
            && SHA256_RE.test(indexed.contentSha256);
        const inventoried = bytesInventoried && !malformedLfs;
        const blockerCodes = [];
        if (!bytesInventoried) blockerCodes.push(EVASIVE_BLOCKERS.NESTED_OBJECT_UNRESOLVED);
        if (malformedLfs) blockerCodes.push(EVASIVE_BLOCKERS.UNSUPPORTED_OBJECT);
        const record = createEvasiveObjectInventoryRecord({
            auditId,
            sourceNamespace,
            path: file.path,
            parentObjectId: parentRecord?.objectId || null,
            objectKind: localObjectKind(indexed),
            byteLength: file.size,
            status: inventoried ? "inventoried": "blocked",
            blockerCodes,
            contentSha256: bytesInventoried ? indexed.contentSha256: null,
            upstreamSha: null,
            executable: false,
            lfsPointer,
        });
        records.push(record);
        for (const code of record.blockerCodes) {
            appendBlocker(blockers, {
                code,
                path: file.path,
            });
        }
        if (record.lfsPointer) {
            const payload = lfsPayloadRecord({ auditId, sourceNamespace, parent: record });
            records.push(payload);
            appendBlocker(blockers, {
                code: EVASIVE_BLOCKERS.LFS_PAYLOAD_UNRESOLVED,
                path: payload.path,
                parentObjectId: record.objectId,
            });
        }
    }

    for (const reparse of reparses) {
        const parent = parentPath(reparse.path);
        const parentRecord = parent ? directoryRecords.get(parent): null;
        const record = createEvasiveObjectInventoryRecord({
            auditId,
            sourceNamespace,
            path: reparse.path,
            parentObjectId: parentRecord?.objectId || null,
            objectKind: "reparse-point",
            byteLength: reparse.size,
            status: "blocked",
            blockerCodes: [EVASIVE_BLOCKERS.REPARSE_POINT_SKIPPED],
            contentSha256: null,
            upstreamSha: null,
            executable: false,
        });
        records.push(record);
        appendBlocker(blockers, {
            code: EVASIVE_BLOCKERS.REPARSE_POINT_SKIPPED,
            path: reparse.path,
        });
    }

    if (enumeration?.trackingTruncated === true
        || previousSnapshot?.blockerCodes?.includes(EVASIVE_BLOCKERS.INVENTORY_TRUNCATED)) {
        appendBlocker(blockers, {
            code: EVASIVE_BLOCKERS.INVENTORY_TRUNCATED,
            path: "<local-enumeration>",
        });
    }
    const boundedRecords = boundRecords(records, blockers);
    const complete = blockers.length === 0;
    const blockerCodes = recordBlockerCodes(boundedRecords, blockers);
    const snapshot = createSnapshot({
        auditId,
        sourceNamespace,
        stageState,
        records: boundedRecords,
        blockerCodes,
        sourceIdentitySha256: hashSourceIdentity(
            "zerotrust-local-source-identity",
            {
                auditId,
                sourceNamespace,
                rootSha256: sha256(String(sourceRoot || "")),
            },
        ),
        previousSnapshot,
    });
    return Object.freeze({
        snapshot,
        summary: inventorySummary(snapshot, complete, blockers, boundedRecords),
    });
}

export const __internals = Object.freeze({
    MAX_LFS_POINTER_BYTES,
    TYPE_BY_MODE,
    KIND_BY_MODE,
    normalizedPath,
    parentPath,
    hashSourceIdentity,
});
