import { createHash } from "node:crypto";
import nodePath from "node:path";

import {
    ANALYSIS_SCHEMA_REVISION,
    ANALYSIS_STAGES,
    CONFIDENCE_LEVELS,
    COVERAGE_SCOPES,
    FINDING_STATES,
    GRAPH_EDGE_KINDS,
    GRAPH_NODE_KINDS,
    MALICIOUS_PROJECT_FIT_LEVELS,
    SEVERITIES,
    SOURCE_IDENTITY_TYPES,
    computeFindingId,
    normalizeBehaviorSignature,
    validateAuditId,
    validateIdentifier,
} from "./schemas.mjs";
import { FACT_KINDS } from "./extractFacts.mjs";

// Optional, untrusted baseline analysis metadata reuse. The current cache
// schema is explicitly analysis-metadata-only: it excludes assurance state,
// source or excerpt text, prompts, credentials, verdicts, report bodies, and
// finalization state. Absence, schema mismatch, and corruption are normal misses.
export const CACHE_SCHEMA_REVISION = 2;
export const CACHE_FORMAT_ID = "analysis-metadata-only";
export const CACHE_CONTENT_SCOPE = "analysis-metadata-only";
export const ASSURANCE_CACHE_POLICY = "excluded-from-current-cache-schema";

export const CACHE_LIMITS = Object.freeze({
    fileBytes: 4 * 1024 * 1024,
    loadResultBytes: 2 * 1024 * 1024,
    totalBytes: 64 * 1024 * 1024,
    totalFiles: 512,
    namespaceFiles: 64,
    cachedSourceFiles: 50_000,
    pluginRecords: 128,
    pluginSourceBlobs: 4_096,
    factsPerFile: 256,
    factsPerPlugin: 20_000,
    graphNodesPerPlugin: 4_096,
    graphEdgesPerPlugin: 8_192,
    findingsPerPlugin: 2_048,
    decisionsPerPlugin: 4_096,
    coverageEntries: 128,
    identifier: 128,
    path: 1_024,
    namespace: 512,
    factValue: 256,
    pluginFactValue: 512,
});

const CACHE_FILE_RE = /^source-[a-f0-9]{64}\.json$/u;
const HASH_RE = /^[a-f0-9]{64}$/u;
const BLOB_SHA_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const COMMIT_SHA_RE = /^[a-f0-9]{40}$/u;
const PLUGIN_VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/u;
const OWNER_RE = /^[a-z0-9](?:[a-z0-9-]{0,38})$/u;
const REPO_RE = /^[a-z0-9_-][a-z0-9._-]{0,99}$/u;
const FACT_TOKEN_RE = /^[A-Za-z0-9_$@./:+?&=%#,-]+$/u;
const SAFE_METADATA_STRING_RE = /^[A-Za-z0-9_$@./:+-]*$/u;
const SECRET_PATTERNS = Object.freeze([
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
    /\bAKIA[0-9A-Z]{16}\b/u,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
    /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
    /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/u,
    /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
    /(?:password|passwd|secret|token|api[_-]?key|credential)\s*[:=]\s*[^\s,;]{4,}/iu,
    /:\/\/[^/\s:@]+:[^/\s@]+@/u,
]);

function fail(path, message) {
    throw new TypeError(`${path}: ${message}`);
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function strictObject(value, path, required, optional = []) {
    if (!isPlainObject(value)) fail(path, "must be a plain object");
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) fail(`${path}.${key}`, "unknown or non-cacheable field");
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "is required");
    }
}

function array(value, path, max) {
    if (!Array.isArray(value)) fail(path, "must be an array");
    if (value.length > max) fail(path, `must contain at most ${max} entries`);
    return value;
}

function integer(value, path, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
    if (!Number.isSafeInteger(value) || value < min || value > max) {
        fail(path, `must be a safe integer between ${min} and ${max}`);
    }
    return value;
}

function enumValue(value, path, values) {
    if (!values.includes(value)) fail(path, `must be one of: ${values.join(", ")}`);
    return value;
}

function string(value, path, {
    min = 1,
    max,
    pattern,
    lower = false,
    normalize = true,
} = {}) {
    if (typeof value !== "string") fail(path, "must be a string");
    let result = normalize ? value.normalize("NFKC").trim(): value;
    if (lower) result = result.toLowerCase();
    if (result.length < min || result.length > max) {
        fail(path, `length must be between ${min} and ${max}`);
    }
    if (/[\u0000-\u001f\u007f]/u.test(result)) fail(path, "contains control characters");
    if (pattern && !pattern.test(result)) fail(path, "has an invalid format");
    assertNoSecret(result, path);
    return result;
}

function boolean(value, path) {
    if (typeof value !== "boolean") fail(path, "must be boolean");
    return value;
}

function timestamp(value, path) {
    const result = string(value, path, { max: 64, normalize: false });
    if (!Number.isFinite(Date.parse(result)) || new Date(result).toISOString() !== result) {
        fail(path, "must be a canonical ISO-8601 timestamp");
    }
    return result;
}

function assertNoSecret(value, path) {
    for (const pattern of SECRET_PATTERNS) {
        if (pattern.test(value)) fail(path, "resembles credential or secret material");
    }
}

function frozen(value) {
    if (Array.isArray(value)) return Object.freeze(value.map((entry) => frozen(entry)));
    if (isPlainObject(value)) {
        const result = {};
        for (const [key, entry] of Object.entries(value)) result[key] = frozen(entry);
        return Object.freeze(result);
    }
    return value;
}

export function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

export function sha256Canonical(value) {
    return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function normalizeRepoPath(value, path = "path") {
    const normalized = string(value, path, {
        max: CACHE_LIMITS.path,
        normalize: true,
    }).replaceAll("\\", "/").replace(/^\.\/+/u, "");
    if (normalized.startsWith("/") || normalized.endsWith("/") || normalized.includes("//")
        || normalized.split("/").some((segment) => segment === "." || segment === "..")) {
        fail(path, "must be a normalized relative path without traversal");
    }
    return normalized;
}

function normalizeLocalPath(value, path = "sourceIdentity.path") {
    const resolved = nodePath.resolve(string(value, path, {
        max: 4_096,
        normalize: true,
    }));
    if (!nodePath.isAbsolute(resolved)) fail(path, "must be absolute");
    const normalized = resolved.replaceAll("\\", "/");
    return process.platform === "win32" ? normalized.toLowerCase(): normalized;
}

export function validateCacheSourceIdentity(value, path = "sourceIdentity") {
    strictObject(
        value,
        path,
        ["kind"],
        ["owner", "repo", "sourceSha", "path", "contentSetSha256"],
    );
    const kind = enumValue(value.kind, `${path}.kind`, ["github", "local"]);
    if (kind === "github") {
        for (const required of ["owner", "repo", "sourceSha"]) {
            if (!Object.hasOwn(value, required)) fail(`${path}.${required}`, "is required");
        }
        if (Object.hasOwn(value, "path") || Object.hasOwn(value, "contentSetSha256")) {
            fail(path, "github identity must not contain local fields");
        }
        return frozen({
            kind,
            owner: string(value.owner, `${path}.owner`, {
                max: 39,
                pattern: OWNER_RE,
                lower: true,
            }),
            repo: string(value.repo, `${path}.repo`, {
                max: 100,
                pattern: REPO_RE,
                lower: true,
            }),
            sourceSha: string(value.sourceSha, `${path}.sourceSha`, {
                max: 40,
                pattern: COMMIT_SHA_RE,
                lower: true,
            }),
        });
    }
    for (const required of ["path", "contentSetSha256"]) {
        if (!Object.hasOwn(value, required)) fail(`${path}.${required}`, "is required");
    }
    if (Object.hasOwn(value, "owner")
        || Object.hasOwn(value, "repo")
        || Object.hasOwn(value, "sourceSha")) {
        fail(path, "local identity must not contain GitHub fields");
    }
    return frozen({
        kind,
        path: normalizeLocalPath(value.path, `${path}.path`),
        contentSetSha256: string(value.contentSetSha256, `${path}.contentSetSha256`, {
            max: 64,
            pattern: HASH_RE,
            lower: true,
        }),
    });
}

export function cacheNamespaceIdentity(sourceIdentity) {
    const source = validateCacheSourceIdentity(sourceIdentity);
    return source.kind === "github"
        ? frozen({ kind: source.kind, owner: source.owner, repo: source.repo }): frozen({ kind: source.kind, path: source.path });
}

export function cacheNamespaceKey(sourceIdentity) {
    return sha256Canonical(cacheNamespaceIdentity(sourceIdentity));
}

export function cacheSourceKey(sourceIdentity) {
    const source = validateCacheSourceIdentity(sourceIdentity);
    return sha256Canonical({
        cacheSchemaRevision: CACHE_SCHEMA_REVISION,
        analysisSchemaRevision: ANALYSIS_SCHEMA_REVISION,
        formatId: CACHE_FORMAT_ID,
        contentScope: CACHE_CONTENT_SCOPE,
        sourceIdentity: source,
    });
}

function containedJoin(root, ...segments) {
    const resolvedRoot = nodePath.resolve(root);
    const result = nodePath.resolve(nodePath.join(resolvedRoot, ...segments));
    const relative = nodePath.relative(resolvedRoot, result);
    if (!relative || relative.startsWith("..") || nodePath.isAbsolute(relative)) {
        throw new Error("computed cache path escaped or collapsed to its trusted root");
    }
    return result;
}

export function buildCachePaths(cacheRoot, sourceIdentity) {
    if (typeof cacheRoot !== "string" || !nodePath.isAbsolute(cacheRoot)) {
        throw new Error("cacheRoot must be absolute");
    }
    const source = validateCacheSourceIdentity(sourceIdentity);
    const formatKey = sha256Canonical({ formatId: CACHE_FORMAT_ID });
    const namespaceKey = cacheNamespaceKey(source);
    const sourceKey = cacheSourceKey(source);
    const formatRoot = containedJoin(
        cacheRoot,
        `schema-${CACHE_SCHEMA_REVISION}`,
        `format-${formatKey}`,
    );
    const namespacePath = containedJoin(formatRoot, `namespace-${namespaceKey}`);
    const filePath = containedJoin(namespacePath, `source-${sourceKey}.json`);
    return frozen({
        cacheRoot: nodePath.resolve(cacheRoot),
        formatRoot,
        namespacePath,
        filePath,
        namespaceKey,
        sourceKey,
    });
}

function validateFact(value, path, expectedPath = null) {
    strictObject(
        value,
        path,
        ["id", "kind", "path", "line", "endLine", "excerptHash", "name"],
        ["value"],
    );
    const factPath = normalizeRepoPath(value.path, `${path}.path`);
    if (expectedPath !== null && factPath !== expectedPath) {
        fail(`${path}.path`, "does not match its cached source file");
    }
    const kind = enumValue(value.kind, `${path}.kind`, FACT_KINDS);
    const line = integer(value.line, `${path}.line`, { min: 1, max: 10_000_000 });
    const endLine = integer(value.endLine, `${path}.endLine`, {
        min: line,
        max: 10_000_000,
    });
    const name = string(value.name, `${path}.name`, {
        max: 128,
        pattern: FACT_TOKEN_RE,
    });
    const normalizedValue = Object.hasOwn(value, "value")
        ? string(value.value, `${path}.value`, {
            min: 1,
            max: CACHE_LIMITS.factValue,
            pattern: FACT_TOKEN_RE,
        }): null;
    const id = string(value.id, `${path}.id`, {
        max: 64,
        pattern: HASH_RE,
        lower: true,
    });
    const expectedId = createHash("sha256")
        .update(`${kind}\0${factPath}\0${line}\0${name}\0${normalizedValue || ""}`, "utf8")
        .digest("hex");
    if (id !== expectedId) fail(`${path}.id`, "is not canonical");
    return frozen({
        id,
        kind,
        path: factPath,
        line,
        endLine,
        excerptHash: string(value.excerptHash, `${path}.excerptHash`, {
            max: 64,
            pattern: HASH_RE,
            lower: true,
        }),
        name,
        ...(normalizedValue ? { value: normalizedValue }: {}),
    });
}

function validateCachedFile(value, path) {
    strictObject(value, path, [
        "path",
        "size",
        "status",
        "classification",
        "contentSha256",
        "facts",
        "invisibleUnicodeScanComplete",
        "invisibleUnicodeMatchCount",
    ], ["blobSha", "lineCount"]);
    const filePath = normalizeRepoPath(value.path, `${path}.path`);
    const classification = enumValue(
        value.classification,
        `${path}.classification`,
        ["text", "binary"],
    );
    const status = enumValue(
        value.status,
        `${path}.status`,
        ["indexed-text", "classified-binary"],
    );
    if ((classification === "text") !== (status === "indexed-text")) {
        fail(path, "classification and status disagree");
    }
    const facts = array(value.facts, `${path}.facts`, CACHE_LIMITS.factsPerFile)
        .map((fact, index) => validateFact(fact, `${path}.facts[${index}]`, filePath))
        .sort((left, right) => left.id.localeCompare(right.id));
    if (new Set(facts.map((fact) => fact.id)).size !== facts.length) {
        fail(`${path}.facts`, "contains duplicate IDs");
    }
    const result = {
        path: filePath,
        size: integer(value.size, `${path}.size`),
        status,
        classification,
        contentSha256: string(value.contentSha256, `${path}.contentSha256`, {
            max: 64,
            pattern: HASH_RE,
            lower: true,
        }),
        facts,
        invisibleUnicodeScanComplete: boolean(
            value.invisibleUnicodeScanComplete,
            `${path}.invisibleUnicodeScanComplete`,
        ),
        invisibleUnicodeMatchCount: integer(
            value.invisibleUnicodeMatchCount,
            `${path}.invisibleUnicodeMatchCount`,
        ),
    };
    if (Object.hasOwn(value, "blobSha")) {
        result.blobSha = string(value.blobSha, `${path}.blobSha`, {
            max: 64,
            pattern: BLOB_SHA_RE,
            lower: true,
        });
    }
    if (classification === "text") {
        if (!Object.hasOwn(value, "lineCount")) fail(`${path}.lineCount`, "is required for text");
        result.lineCount = integer(value.lineCount, `${path}.lineCount`, {
            min: 1,
            max: 10_000_000,
        });
        if (result.invisibleUnicodeScanComplete !== true) {
            fail(`${path}.invisibleUnicodeScanComplete`, "must be true for cached text facts");
        }
    } else {
        if (Object.hasOwn(value, "lineCount")) fail(`${path}.lineCount`, "is invalid for binary");
        if (result.facts.length > 0) fail(`${path}.facts`, "binary files cannot contain facts");
    }
    return frozen(result);
}

function validatePluginSourceBlob(value, path, fileMap) {
    strictObject(value, path, ["path", "contentSha256"], ["blobSha"]);
    const normalized = {
        path: normalizeRepoPath(value.path, `${path}.path`),
        contentSha256: string(value.contentSha256, `${path}.contentSha256`, {
            max: 64,
            pattern: HASH_RE,
            lower: true,
        }),
    };
    if (Object.hasOwn(value, "blobSha")) {
        normalized.blobSha = string(value.blobSha, `${path}.blobSha`, {
            max: 64,
            pattern: BLOB_SHA_RE,
            lower: true,
        });
    }
    const cachedFile = fileMap.get(normalized.path);
    if (!cachedFile
        || cachedFile.contentSha256 !== normalized.contentSha256
        || (normalized.blobSha
            && normalized.blobSha !== cachedFile.blobSha
            && normalized.blobSha !== cachedFile.contentSha256)) {
        fail(path, "does not match a complete cached source file");
    }
    return frozen(normalized);
}

function validateAnalysisSourceIdentity(value, path, sourceBlobMap) {
    strictObject(value, path, ["type", "namespace", "path", "contentSha256"], ["blobSha"]);
    const result = {
        type: enumValue(value.type, `${path}.type`, SOURCE_IDENTITY_TYPES),
        namespace: string(value.namespace, `${path}.namespace`, {
            max: CACHE_LIMITS.namespace,
            pattern: FACT_TOKEN_RE,
        }),
        path: normalizeRepoPath(value.path, `${path}.path`),
        contentSha256: string(value.contentSha256, `${path}.contentSha256`, {
            max: 64,
            pattern: HASH_RE,
            lower: true,
        }),
    };
    if (Object.hasOwn(value, "blobSha")) {
        result.blobSha = string(value.blobSha, `${path}.blobSha`, {
            max: 64,
            pattern: BLOB_SHA_RE,
            lower: true,
        });
    }
    const sourceBlob = sourceBlobMap.get(result.path);
    if (!sourceBlob
        || sourceBlob.contentSha256 !== result.contentSha256
        || (result.blobSha
            && result.blobSha !== sourceBlob.blobSha
            && result.blobSha !== sourceBlob.contentSha256)) {
        fail(path, "does not match the plugin record's declared source blobs");
    }
    return frozen(result);
}

function validateEvidence(value, path, sourceBlobMap) {
    strictObject(value, path, [
        "path",
        "startLine",
        "endLine",
        "blobSha",
        "excerptHash",
        "producer",
        "coverageScope",
    ]);
    const evidencePath = normalizeRepoPath(value.path, `${path}.path`);
    const blobSha = string(value.blobSha, `${path}.blobSha`, {
        max: 64,
        pattern: BLOB_SHA_RE,
        lower: true,
    });
    const sourceBlob = sourceBlobMap.get(evidencePath);
    if (!sourceBlob
        || (sourceBlob.blobSha !== blobSha && sourceBlob.contentSha256 !== blobSha)) {
        fail(path, "does not match a declared source blob");
    }
    const startLine = integer(value.startLine, `${path}.startLine`, {
        min: 1,
        max: 10_000_000,
    });
    return frozen({
        path: evidencePath,
        startLine,
        endLine: integer(value.endLine, `${path}.endLine`, {
            min: startLine,
            max: 10_000_000,
        }),
        blobSha,
        excerptHash: string(value.excerptHash, `${path}.excerptHash`, {
            max: 64,
            pattern: HASH_RE,
            lower: true,
        }),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        coverageScope: enumValue(
            value.coverageScope,
            `${path}.coverageScope`,
            COVERAGE_SCOPES,
        ),
    });
}

function validateEvidenceList(value, path, sourceBlobMap) {
    return array(value, path, 64).map((entry, index) =>
        validateEvidence(entry, `${path}[${index}]`, sourceBlobMap));
}

export function computeCachedPluginFactId(value) {
    const identity = {
        kind: value.kind,
        name: value.name,
        value: value.value,
        producer: value.producer,
        sourceIdentity: value.sourceIdentity,
        evidence: value.evidence,
        tags: value.tags,
    };
    return `zpcf-${sha256Canonical(identity)}`;
}

function validateCachedPluginFact(value, path, sourceBlobMap) {
    strictObject(value, path, [
        "id",
        "kind",
        "name",
        "value",
        "producer",
        "sourceIdentity",
        "evidence",
        "tags",
    ]);
    const normalized = {
        kind: validateIdentifier(value.kind, `${path}.kind`),
        name: validateIdentifier(value.name, `${path}.name`),
        value: string(value.value, `${path}.value`, {
            max: CACHE_LIMITS.pluginFactValue,
            pattern: FACT_TOKEN_RE,
        }),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        sourceIdentity: validateAnalysisSourceIdentity(
            value.sourceIdentity,
            `${path}.sourceIdentity`,
            sourceBlobMap,
        ),
        evidence: validateEvidenceList(value.evidence, `${path}.evidence`, sourceBlobMap),
        tags: array(value.tags, `${path}.tags`, 32)
            .map((entry, index) => validateIdentifier(entry, `${path}.tags[${index}]`))
            .sort(),
    };
    if (new Set(normalized.tags).size !== normalized.tags.length) {
        fail(`${path}.tags`, "contains duplicates");
    }
    const id = string(value.id, `${path}.id`, {
        max: 72,
        pattern: /^zpcf-[a-f0-9]{64}$/u,
        lower: true,
    });
    if (id !== computeCachedPluginFactId(normalized)) {
        fail(`${path}.id`, "is not canonically derived from cacheable plugin fact metadata");
    }
    return frozen({ id, ...normalized });
}

function validateGraphNode(value, path, sourceBlobMap) {
    strictObject(
        value,
        path,
        ["id", "kind", "producer", "evidence"],
        ["sourceIdentity", "behaviorSignature", "tags"],
    );
    const result = {
        id: validateIdentifier(value.id, `${path}.id`),
        kind: enumValue(value.kind, `${path}.kind`, GRAPH_NODE_KINDS),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        evidence: validateEvidenceList(value.evidence, `${path}.evidence`, sourceBlobMap),
    };
    if (Object.hasOwn(value, "sourceIdentity")) {
        result.sourceIdentity = validateAnalysisSourceIdentity(
            value.sourceIdentity,
            `${path}.sourceIdentity`,
            sourceBlobMap,
        );
    }
    if (Object.hasOwn(value, "behaviorSignature")) {
        result.behaviorSignature = normalizeBehaviorSignature(
            value.behaviorSignature,
            `${path}.behaviorSignature`,
        );
    }
    if (Object.hasOwn(value, "tags")) {
        result.tags = array(value.tags, `${path}.tags`, 32)
            .map((entry, index) => validateIdentifier(entry, `${path}.tags[${index}]`))
            .sort();
        if (new Set(result.tags).size !== result.tags.length) {
            fail(`${path}.tags`, "contains duplicates");
        }
    }
    return frozen(result);
}

function validateGraphEdge(value, path, sourceBlobMap) {
    strictObject(
        value,
        path,
        ["id", "kind", "from", "to", "producer", "evidence"],
        ["tags"],
    );
    const result = {
        id: validateIdentifier(value.id, `${path}.id`),
        kind: enumValue(value.kind, `${path}.kind`, GRAPH_EDGE_KINDS),
        from: validateIdentifier(value.from, `${path}.from`),
        to: validateIdentifier(value.to, `${path}.to`),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        evidence: validateEvidenceList(value.evidence, `${path}.evidence`, sourceBlobMap),
    };
    if (Object.hasOwn(value, "tags")) {
        result.tags = array(value.tags, `${path}.tags`, 32)
            .map((entry, index) => validateIdentifier(entry, `${path}.tags[${index}]`))
            .sort();
        if (new Set(result.tags).size !== result.tags.length) {
            fail(`${path}.tags`, "contains duplicates");
        }
    }
    return frozen(result);
}

function validateFinding(value, path, sourceBlobMap, nodeIds, edgeIds) {
    strictObject(value, path, [
        "id",
        "sourceIdentity",
        "behaviorSignature",
        "severity",
        "confidence",
        "maliciousProjectFit",
        "state",
        "evidence",
        "nodeIds",
        "edgeIds",
        "producer",
    ], ["tags"]);
    const sourceIdentity = validateAnalysisSourceIdentity(
        value.sourceIdentity,
        `${path}.sourceIdentity`,
        sourceBlobMap,
    );
    const behaviorSignature = normalizeBehaviorSignature(
        value.behaviorSignature,
        `${path}.behaviorSignature`,
    );
    const id = string(value.id, `${path}.id`, {
        max: 71,
        pattern: /^ztf-[a-f0-9]{64}$/u,
        lower: true,
    });
    if (id !== computeFindingId(sourceIdentity, behaviorSignature)) {
        fail(`${path}.id`, "is not derived from source identity and behavior signature");
    }
    const findingNodeIds = array(value.nodeIds, `${path}.nodeIds`, nodeIds.size)
        .map((entry, index) => validateIdentifier(entry, `${path}.nodeIds[${index}]`));
    const findingEdgeIds = array(value.edgeIds, `${path}.edgeIds`, edgeIds.size)
        .map((entry, index) => validateIdentifier(entry, `${path}.edgeIds[${index}]`));
    if (new Set(findingNodeIds).size !== findingNodeIds.length) {
        fail(`${path}.nodeIds`, "contains duplicates");
    }
    if (new Set(findingEdgeIds).size !== findingEdgeIds.length) {
        fail(`${path}.edgeIds`, "contains duplicates");
    }
    for (const nodeId of findingNodeIds) {
        if (!nodeIds.has(nodeId)) fail(`${path}.nodeIds`, `unknown node: ${nodeId}`);
    }
    for (const edgeId of findingEdgeIds) {
        if (!edgeIds.has(edgeId)) fail(`${path}.edgeIds`, `unknown edge: ${edgeId}`);
    }
    const result = {
        id,
        sourceIdentity,
        behaviorSignature,
        severity: enumValue(value.severity, `${path}.severity`, SEVERITIES),
        confidence: enumValue(value.confidence, `${path}.confidence`, CONFIDENCE_LEVELS),
        maliciousProjectFit: enumValue(
            value.maliciousProjectFit,
            `${path}.maliciousProjectFit`,
            MALICIOUS_PROJECT_FIT_LEVELS,
        ),
        state: enumValue(value.state, `${path}.state`, FINDING_STATES),
        evidence: validateEvidenceList(value.evidence, `${path}.evidence`, sourceBlobMap),
        nodeIds: findingNodeIds,
        edgeIds: findingEdgeIds,
        producer: validateIdentifier(value.producer, `${path}.producer`),
    };
    if (Object.hasOwn(value, "tags")) {
        result.tags = array(value.tags, `${path}.tags`, 32)
            .map((entry, index) => validateIdentifier(entry, `${path}.tags[${index}]`))
            .sort();
        if (new Set(result.tags).size !== result.tags.length) {
            fail(`${path}.tags`, "contains duplicates");
        }
    }
    return frozen(result);
}

function validateDecision(value, path, sourceBlobMap, findingIds) {
    strictObject(value, path, [
        "findingId",
        "decision",
        "severity",
        "confidence",
        "maliciousProjectFit",
        "rationaleCode",
        "evidence",
    ]);
    const findingId = string(value.findingId, `${path}.findingId`, {
        max: 71,
        pattern: /^ztf-[a-f0-9]{64}$/u,
        lower: true,
    });
    if (!findingIds.has(findingId)) fail(`${path}.findingId`, "does not name a cached finding");
    return frozen({
        findingId,
        decision: enumValue(
            value.decision,
            `${path}.decision`,
            ["validated", "refuted", "unresolved"],
        ),
        severity: enumValue(value.severity, `${path}.severity`, SEVERITIES),
        confidence: enumValue(value.confidence, `${path}.confidence`, CONFIDENCE_LEVELS),
        maliciousProjectFit: enumValue(
            value.maliciousProjectFit,
            `${path}.maliciousProjectFit`,
            MALICIOUS_PROJECT_FIT_LEVELS,
        ),
        rationaleCode: validateIdentifier(value.rationaleCode, `${path}.rationaleCode`),
        evidence: validateEvidenceList(value.evidence, `${path}.evidence`, sourceBlobMap),
    });
}

function validatePluginRecord(value, path, fileMap) {
    strictObject(value, path, [
        "pluginId",
        "pluginVersion",
        "sourceBlobs",
        "facts",
        "nodes",
        "edges",
        "findings",
        "validationDecisions",
    ]);
    const pluginId = validateIdentifier(value.pluginId, `${path}.pluginId`);
    const pluginVersion = string(value.pluginVersion, `${path}.pluginVersion`, {
        max: 64,
        pattern: PLUGIN_VERSION_RE,
    });
    const sourceBlobs = array(
        value.sourceBlobs,
        `${path}.sourceBlobs`,
        CACHE_LIMITS.pluginSourceBlobs,
    ).map((entry, index) =>
        validatePluginSourceBlob(entry, `${path}.sourceBlobs[${index}]`, fileMap))
        .sort((left, right) => left.path.localeCompare(right.path));
    if (sourceBlobs.length === 0) fail(`${path}.sourceBlobs`, "must not be empty");
    const sourceBlobMap = new Map(sourceBlobs.map((entry) => [entry.path, entry]));
    if (sourceBlobMap.size !== sourceBlobs.length) {
        fail(`${path}.sourceBlobs`, "contains duplicate paths");
    }
    const facts = array(value.facts, `${path}.facts`, CACHE_LIMITS.factsPerPlugin)
        .map((fact, index) =>
            validateCachedPluginFact(
                fact,
                `${path}.facts[${index}]`,
                sourceBlobMap,
            )).sort((left, right) => left.id.localeCompare(right.id));
    if (new Set(facts.map((fact) => fact.id)).size !== facts.length) {
        fail(`${path}.facts`, "contains duplicate IDs");
    }
    const nodes = array(value.nodes, `${path}.nodes`, CACHE_LIMITS.graphNodesPerPlugin)
        .map((node, index) =>
            validateGraphNode(node, `${path}.nodes[${index}]`, sourceBlobMap))
        .sort((left, right) => left.id.localeCompare(right.id));
    const nodeIds = new Set(nodes.map((node) => node.id));
    if (nodeIds.size !== nodes.length) fail(`${path}.nodes`, "contains duplicate IDs");
    const edges = array(value.edges, `${path}.edges`, CACHE_LIMITS.graphEdgesPerPlugin)
        .map((edge, index) =>
            validateGraphEdge(edge, `${path}.edges[${index}]`, sourceBlobMap))
        .sort((left, right) => left.id.localeCompare(right.id));
    const edgeIds = new Set(edges.map((edge) => edge.id));
    if (edgeIds.size !== edges.length) fail(`${path}.edges`, "contains duplicate IDs");
    for (const edge of edges) {
        if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) {
            fail(`${path}.edges`, `edge ${edge.id} references an unknown node`);
        }
    }
    const findings = array(
        value.findings,
        `${path}.findings`,
        CACHE_LIMITS.findingsPerPlugin,
    ).map((finding, index) =>
        validateFinding(
            finding,
            `${path}.findings[${index}]`,
            sourceBlobMap,
            nodeIds,
            edgeIds,
        )).sort((left, right) => left.id.localeCompare(right.id));
    const findingIds = new Set(findings.map((finding) => finding.id));
    if (findingIds.size !== findings.length) fail(`${path}.findings`, "contains duplicate IDs");
    const validationDecisions = array(
        value.validationDecisions,
        `${path}.validationDecisions`,
        CACHE_LIMITS.decisionsPerPlugin,
    ).map((decision, index) =>
        validateDecision(
            decision,
            `${path}.validationDecisions[${index}]`,
            sourceBlobMap,
            findingIds,
        )).sort((left, right) => left.findingId.localeCompare(right.findingId));
    if (new Set(validationDecisions.map((decision) => decision.findingId)).size
        !== validationDecisions.length) {
        fail(`${path}.validationDecisions`, "contains multiple decisions for one finding");
    }
    return frozen({
        pluginId,
        pluginVersion,
        sourceBlobs,
        facts,
        nodes,
        edges,
        findings,
        validationDecisions,
    });
}

function validateStage(value, path) {
    strictObject(value, path, ["current", "history"]);
    const cacheableStages = ANALYSIS_STAGES.filter((stage) => stage !== "finalized");
    const current = enumValue(value.current, `${path}.current`, cacheableStages);
    const history = array(value.history, `${path}.history`, ANALYSIS_STAGES.length)
        .map((entry, index) =>
            enumValue(entry, `${path}.history[${index}]`, cacheableStages));
    const expected = ANALYSIS_STAGES.slice(0, ANALYSIS_STAGES.indexOf(current) + 1);
    if (history.length !== expected.length
        || history.some((entry, index) => entry !== expected[index])) {
        fail(`${path}.history`, "must be the legal stage prefix ending at current");
    }
    return frozen({ current, history });
}

function validateCoverageEntry(value, path) {
    strictObject(value, path, ["key", "type", "value"]);
    const key = validateIdentifier(value.key, `${path}.key`);
    const type = enumValue(
        value.type,
        `${path}.type`,
        ["integer", "boolean", "string", "string-list"],
    );
    if (type === "integer") {
        return frozen({ key, type, value: integer(value.value, `${path}.value`) });
    }
    if (type === "boolean") {
        return frozen({ key, type, value: boolean(value.value, `${path}.value`) });
    }
    if (type === "string") {
        return frozen({
            key,
            type,
            value: string(value.value, `${path}.value`, {
                min: 0,
                max: CACHE_LIMITS.identifier,
                pattern: SAFE_METADATA_STRING_RE,
            }),
        });
    }
    return frozen({
        key,
        type,
        value: array(value.value, `${path}.value`, 64)
            .map((entry, index) => string(entry, `${path}.value[${index}]`, {
                min: 0,
                max: CACHE_LIMITS.identifier,
                pattern: SAFE_METADATA_STRING_RE,
            })).sort(),
    });
}

export function validateCachePayload(value, path = "cachePayload") {
    strictObject(value, path, [
        "cacheSchemaRevision",
        "analysisSchemaRevision",
        "formatId",
        "contentScope",
        "sourceIdentity",
        "sourceKey",
        "storedAt",
        "files",
        "pluginRecords",
        "stage",
        "coverage",
    ]);
    if (value.cacheSchemaRevision !== CACHE_SCHEMA_REVISION) {
        fail(`${path}.cacheSchemaRevision`, `must equal ${CACHE_SCHEMA_REVISION}`);
    }
    if (value.analysisSchemaRevision !== ANALYSIS_SCHEMA_REVISION) {
        fail(`${path}.analysisSchemaRevision`, `must equal ${ANALYSIS_SCHEMA_REVISION}`);
    }
    if (value.formatId !== CACHE_FORMAT_ID) {
        fail(`${path}.formatId`, `must equal ${CACHE_FORMAT_ID}`);
    }
    if (value.contentScope !== CACHE_CONTENT_SCOPE) {
        fail(`${path}.contentScope`, `must equal ${CACHE_CONTENT_SCOPE}`);
    }
    const sourceIdentity = validateCacheSourceIdentity(
        value.sourceIdentity,
        `${path}.sourceIdentity`,
    );
    const sourceKey = string(value.sourceKey, `${path}.sourceKey`, {
        max: 64,
        pattern: HASH_RE,
        lower: true,
    });
    if (sourceKey !== cacheSourceKey(sourceIdentity)) {
        fail(`${path}.sourceKey`, "does not match source identity and cache schema revisions");
    }
    const files = array(value.files, `${path}.files`, CACHE_LIMITS.cachedSourceFiles)
        .map((file, index) => validateCachedFile(file, `${path}.files[${index}]`))
        .sort((left, right) => left.path.localeCompare(right.path));
    const fileMap = new Map(files.map((file) => [file.path, file]));
    if (fileMap.size !== files.length) fail(`${path}.files`, "contains duplicate paths");
    const pluginRecords = array(
        value.pluginRecords,
        `${path}.pluginRecords`,
        CACHE_LIMITS.pluginRecords,
    ).map((record, index) =>
        validatePluginRecord(record, `${path}.pluginRecords[${index}]`, fileMap))
        .sort((left, right) =>
            `${left.pluginId}\0${left.pluginVersion}`.localeCompare(
                `${right.pluginId}\0${right.pluginVersion}`,
            ));
    const pluginKeys = new Set(
        pluginRecords.map((record) => `${record.pluginId}\0${record.pluginVersion}`),
    );
    if (pluginKeys.size !== pluginRecords.length) {
        fail(`${path}.pluginRecords`, "contains duplicate plugin ID/version pairs");
    }
    const coverage = array(
        value.coverage,
        `${path}.coverage`,
        CACHE_LIMITS.coverageEntries,
    ).map((entry, index) =>
        validateCoverageEntry(entry, `${path}.coverage[${index}]`))
        .sort((left, right) => left.key.localeCompare(right.key));
    if (new Set(coverage.map((entry) => entry.key)).size !== coverage.length) {
        fail(`${path}.coverage`, "contains duplicate keys");
    }
    return frozen({
        cacheSchemaRevision: CACHE_SCHEMA_REVISION,
        analysisSchemaRevision: ANALYSIS_SCHEMA_REVISION,
        formatId: CACHE_FORMAT_ID,
        contentScope: CACHE_CONTENT_SCOPE,
        sourceIdentity,
        sourceKey,
        storedAt: timestamp(value.storedAt, `${path}.storedAt`),
        files,
        pluginRecords,
        stage: validateStage(value.stage, `${path}.stage`),
        coverage,
    });
}

export function createCacheEnvelope(payload) {
    const normalized = validateCachePayload(payload);
    return frozen({
        integritySha256: sha256Canonical(normalized),
        payload: normalized,
    });
}

export function serializeCacheEnvelope(payload) {
    return `${canonicalJson(createCacheEnvelope(payload))}\n`;
}

export function parseCacheEnvelope(raw) {
    if (typeof raw !== "string") throw new TypeError("cache file must be UTF-8 text");
    if (Buffer.byteLength(raw, "utf8") > CACHE_LIMITS.fileBytes) {
        throw new RangeError(`cache file exceeds ${CACHE_LIMITS.fileBytes} bytes`);
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new TypeError("cache file is not valid JSON");
    }
    strictObject(parsed, "cacheEnvelope", ["integritySha256", "payload"]);
    const payload = validateCachePayload(parsed.payload);
    const integritySha256 = string(
        parsed.integritySha256,
        "cacheEnvelope.integritySha256",
        {
            max: 64,
            pattern: HASH_RE,
            lower: true,
        },
    );
    if (integritySha256 !== sha256Canonical(payload)) {
        throw new Error("cache integrity SHA-256 mismatch");
    }
    const canonical = `${canonicalJson({ integritySha256, payload })}\n`;
    if (raw !== canonical) throw new Error("cache file is not canonical JSON");
    return frozen({ integritySha256, payload });
}

function factsForFile(indexState, file) {
    const factMap = new Map((indexState.facts || []).map((fact) => [fact.id, fact]));
    return (file.factIds || []).map((id) => factMap.get(id)).filter(Boolean);
}

export function deriveCacheSourceIdentity(context, indexState) {
    if (!context || context.hasActiveAudit !== true) {
        throw new Error("cache identity requires an active audit");
    }
    validateAuditId(context.auditId);
    if (context.owner && context.repo && context.resolvedSha) {
        return validateCacheSourceIdentity({
            kind: "github",
            owner: context.owner,
            repo: context.repo,
            sourceSha: context.resolvedSha,
        });
    }
    if (context.localPath) {
        if (!indexState?.enumeration?.complete) {
            throw new Error("local cache identity requires complete source enumeration");
        }
        const identities = (indexState.files || []).map((file) => {
            if (!["indexed-text", "classified-binary"].includes(file.status)
                || !HASH_RE.test(String(file.contentSha256 || "").toLowerCase())) {
                throw new Error("local cache identity requires every source file to be hashed");
            }
            return {
                path: normalizeRepoPath(file.path),
                contentSha256: String(file.contentSha256).toLowerCase(),
            };
        }).sort((left, right) => left.path.localeCompare(right.path));
        return validateCacheSourceIdentity({
            kind: "local",
            path: context.localPath,
            contentSetSha256: sha256Canonical(identities),
        });
    }
    throw new Error("active audit has no stable cacheable source identity yet");
}

export function buildCachePayload({
    sourceIdentity,
    indexState,
    stageState,
    pluginRecords = [],
    storedAt = new Date().toISOString(),
} = {}) {
    const files = (indexState?.files || [])
        .filter((file) => ["indexed-text", "classified-binary"].includes(file.status))
        .map((file) => ({
            path: file.path,
            size: file.size,
            status: file.status,
            classification: file.classification,
            contentSha256: file.contentSha256,
            ...(file.blobSha ? { blobSha: file.blobSha }: {}),
            ...(file.lineCount !== null && file.lineCount !== undefined
                ? { lineCount: file.lineCount }: {}),
            facts: factsForFile(indexState, file),
            invisibleUnicodeScanComplete: file.invisibleUnicodeScanComplete === true,
            invisibleUnicodeMatchCount: Number.isSafeInteger(file.invisibleUnicodeMatchCount)
                ? file.invisibleUnicodeMatchCount: 0,
        }));
    const snapshot = indexState || {};
    const coverage = [
        { key: "source-kind", type: "string", value: String(snapshot.sourceKind || "") },
        {
            key: "enumeration-complete",
            type: "boolean",
            value: snapshot.enumeration?.complete === true,
        },
        {
            key: "enumeration-tracking-truncated",
            type: "boolean",
            value: snapshot.enumeration?.trackingTruncated === true,
        },
        { key: "tracked-files", type: "integer", value: (snapshot.files || []).length },
        { key: "cached-complete-files", type: "integer", value: files.length },
        { key: "facts", type: "integer", value: (snapshot.facts || []).length },
        { key: "read-failures", type: "integer", value: snapshot.readFailures || 0 },
        { key: "fact-overflow", type: "boolean", value: snapshot.factOverflow === true },
        {
            key: "blockers-truncated",
            type: "boolean",
            value: snapshot.blockersTruncated === true,
        },
    ];
    const requestedStage = stageState?.current || "acquired";
    const cacheableStage = requestedStage === "finalized"
        ? {
            current: "validated",
            history: ANALYSIS_STAGES.slice(0, ANALYSIS_STAGES.indexOf("validated") + 1),
        }: {
            current: requestedStage,
            history: stageState?.history || ["acquired"],
        };
    return validateCachePayload({
        cacheSchemaRevision: CACHE_SCHEMA_REVISION,
        analysisSchemaRevision: ANALYSIS_SCHEMA_REVISION,
        formatId: CACHE_FORMAT_ID,
        contentScope: CACHE_CONTENT_SCOPE,
        sourceIdentity,
        sourceKey: cacheSourceKey(sourceIdentity),
        storedAt,
        files,
        pluginRecords,
        stage: cacheableStage,
        coverage,
    });
}

function currentFileIdentityMap(indexState) {
    const result = new Map();
    for (const file of indexState?.files || []) {
        const path = normalizeRepoPath(file.path);
        const blobSha = file.blobSha
            ? String(file.blobSha).toLowerCase(): null;
        const contentSha256 = file.contentSha256
            ? String(file.contentSha256).toLowerCase(): null;
        result.set(path, { path, blobSha, contentSha256 });
    }
    return result;
}

function sourceBlobMatchesCurrent(sourceBlob, currentFiles) {
    const current = currentFiles.get(sourceBlob.path);
    if (!current) return false;
    if (sourceBlob.blobSha) {
        return sourceBlob.blobSha === current.blobSha
            || sourceBlob.blobSha === current.contentSha256;
    }
    return !!sourceBlob.contentSha256
        && !!current.contentSha256
        && sourceBlob.contentSha256 === current.contentSha256;
}

export function selectReusableCache(payload, {
    activeSourceIdentity,
    indexState,
    pluginVersions = [],
} = {}) {
    const cached = validateCachePayload(payload);
    const active = validateCacheSourceIdentity(activeSourceIdentity);
    if (cacheNamespaceKey(cached.sourceIdentity) !== cacheNamespaceKey(active)) {
        return frozen({
            matched: false,
            exactSource: false,
            files: [],
            pluginRecords: [],
            stage: null,
            coverage: [],
        });
    }
    const exactSource = cached.sourceKey === cacheSourceKey(active);
    const currentFiles = currentFileIdentityMap(indexState);
    const files = cached.files.filter((file) =>
        sourceBlobMatchesCurrent(file, currentFiles));
    const matchedPaths = new Set(files.map((file) => file.path));
    const normalizedPluginVersions =
        array(pluginVersions, "pluginVersions", CACHE_LIMITS.pluginRecords).map(
            (entry, index) => {
                strictObject(
                    entry,
                    `pluginVersions[${index}]`,
                    ["pluginId", "pluginVersion"],
                );
                return [
                    validateIdentifier(entry.pluginId, `pluginVersions[${index}].pluginId`),
                    string(entry.pluginVersion, `pluginVersions[${index}].pluginVersion`, {
                        max: 64,
                        pattern: PLUGIN_VERSION_RE,
                    }),
                ];
            },
        );
    const compatiblePlugins = new Map(normalizedPluginVersions);
    if (compatiblePlugins.size !== normalizedPluginVersions.length) {
        fail("pluginVersions", "contains duplicate plugin IDs");
    }
    const pluginRecords = cached.pluginRecords.filter((record) =>
        compatiblePlugins.get(record.pluginId) === record.pluginVersion
        && record.sourceBlobs.every((sourceBlob) =>
            matchedPaths.has(sourceBlob.path)
            && sourceBlobMatchesCurrent(sourceBlob, currentFiles)));
    return frozen({
        matched: exactSource || files.length > 0 || pluginRecords.length > 0,
        exactSource,
        files,
        pluginRecords,
        stage: exactSource ? cached.stage: null,
        coverage: exactSource ? cached.coverage: [],
    });
}

export const __internals = Object.freeze({
    CACHE_FILE_RE,
    SECRET_PATTERNS,
    normalizeRepoPath,
    normalizeLocalPath,
    validateFact,
    validateCachedPluginFact,
    validatePluginRecord,
    sourceBlobMatchesCurrent,
});
