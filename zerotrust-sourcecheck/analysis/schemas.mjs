import { createHash } from "node:crypto";

export const ANALYSIS_SCHEMA_VERSION = 5;

export const LIMITS = Object.freeze({
    auditId: 36,
    path: 4096,
    namespace: 512,
    identifier: 128,
    title: 256,
    summary: 2048,
    rationale: 4096,
    label: 256,
    tags: 32,
    tag: 64,
    evidencePerItem: 64,
    graphNodes: 4096,
    graphEdges: 8192,
    findings: 2048,
    validationDecisions: 4096,
    metadataDocuments: 512,
    metadataEntries: 128,
    metadataString: 2048,
    pluginWarnings: 64,
    pluginWarning: 1024,
    line: 10_000_000,
});

export const GRAPH_NODE_KINDS = Object.freeze([
    "activation",
    "trigger",
    "transform",
    "capability",
    "sensitive-source",
    "sink",
    "persistence",
    "propagation",
    "provenance",
    "dependency",
]);

export const GRAPH_EDGE_KINDS = Object.freeze([
    "activates",
    "triggers",
    "transforms",
    "reads-from",
    "writes-to",
    "invokes",
    "flows-to",
    "persists-as",
    "propagates-to",
    "provenance-of",
    "depends-on",
    "guards",
    "enables",
]);

export const FINDING_STATES = Object.freeze([
    "candidate",
    "validating",
    "validated",
    "refuted",
    "unresolved",
]);

export const SEVERITIES = Object.freeze([
    "info",
    "low",
    "medium",
    "high",
    "critical",
]);

export const CONFIDENCE_LEVELS = Object.freeze(["low", "medium", "high"]);

export const MALICIOUS_PROJECT_FIT_LEVELS = Object.freeze([
    "unknown",
    "unlikely",
    "ambiguous",
    "likely",
    "strong",
]);

export const COVERAGE_SCOPES = Object.freeze([
    "mandatory",
    "council_sample",
    "local_source",
    "release_asset",
    "dependency_metadata",
]);

export const SOURCE_IDENTITY_TYPES = Object.freeze([
    "git-blob",
    "local-file",
    "release-asset",
    "dependency",
]);

// Durable lifecycle states. The logical Dedupe/score phase runs while building
// the validated decision snapshot, so it is not a separately persisted state.
export const ANALYSIS_STAGES = Object.freeze([
    "acquired",
    "prepared",
    "scanned",
    "traced",
    "validated",
    "finalized",
]);

const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;
const BEHAVIOR_TOKEN_RE = /^[a-z][a-z0-9._:/-]{0,127}$/;
const FINDING_ID_RE = /^ztf-v5-[a-f0-9]{64}$/;
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const BLOB_SHA_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;

export class ContractValidationError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "ContractValidationError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new ContractValidationError(path, message);
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function objectShape(value, path, required, optional = []) {
    if (!isPlainObject(value)) fail(path, "must be a plain object");
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) fail(`${path}.${key}`, "unknown field");
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "is required");
    }
}

function boundedString(value, path, {
    min = 1,
    max,
    pattern,
    normalize = false,
} = {}) {
    if (typeof value !== "string") fail(path, "must be a string");
    const result = normalize ? value.normalize("NFKC").trim() : value;
    if (result.length < min || result.length > max) {
        fail(path, `length must be between ${min} and ${max}`);
    }
    if (result.includes("\0")) fail(path, "must not contain NUL");
    if (pattern && !pattern.test(result)) fail(path, "has an invalid format");
    return result;
}

function enumValue(value, path, values) {
    if (!values.includes(value)) fail(path, `must be one of: ${values.join(", ")}`);
    return value;
}

function boundedArray(value, path, max) {
    if (!Array.isArray(value)) fail(path, "must be an array");
    if (value.length > max) fail(path, `must contain at most ${max} entries`);
    return value;
}

function safeInteger(value, path, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
    if (!Number.isSafeInteger(value) || value < min || value > max) {
        fail(path, `must be a safe integer between ${min} and ${max}`);
    }
    return value;
}

function finiteNumber(value, path) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        fail(path, "must be a finite number");
    }
    return value;
}

function booleanValue(value, path) {
    if (typeof value !== "boolean") fail(path, "must be a boolean");
    return value;
}

function isoTimestamp(value, path) {
    const timestamp = boundedString(value, path, { max: 64 });
    const parsed = Date.parse(timestamp);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== timestamp) {
        fail(path, "must be a canonical ISO-8601 timestamp");
    }
    return timestamp;
}

function uniqueStrings(values, path, {
    maxItems,
    maxLength,
    pattern,
    normalize = false,
    sort = false,
} = {}) {
    const result = boundedArray(values, path, maxItems).map((value, index) =>
        boundedString(value, `${path}[${index}]`, {
            max: maxLength,
            pattern,
            normalize,
        }));
    if (new Set(result).size !== result.length) fail(path, "must not contain duplicates");
    return sort ? [...result].sort() : result;
}

function cloneFrozen(value) {
    if (Array.isArray(value)) {
        return Object.freeze(value.map((entry) => cloneFrozen(entry)));
    }
    if (isPlainObject(value)) {
        const result = {};
        for (const [key, entry] of Object.entries(value)) {
            result[key] = cloneFrozen(entry);
        }
        return Object.freeze(result);
    }
    return value;
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

export function validateAuditId(value, path = "auditId") {
    return boundedString(value, path, {
        max: LIMITS.auditId,
        pattern: UUID_V4_RE,
    }).toLowerCase();
}

export function validateIdentifier(value, path = "identifier") {
    return boundedString(value, path, {
        max: LIMITS.identifier,
        pattern: IDENTIFIER_RE,
        normalize: true,
    });
}

export function validateEvidenceReference(value, path = "evidence") {
    objectShape(value, path, [
        "path",
        "startLine",
        "endLine",
        "blobSha",
        "excerptHash",
        "producer",
        "coverageScope",
    ]);
    const startLine = safeInteger(value.startLine, `${path}.startLine`, {
        min: 1,
        max: LIMITS.line,
    });
    const endLine = safeInteger(value.endLine, `${path}.endLine`, {
        min: startLine,
        max: LIMITS.line,
    });
    return cloneFrozen({
        path: boundedString(value.path, `${path}.path`, {
            max: LIMITS.path,
            normalize: true,
        }).replaceAll("\\", "/"),
        startLine,
        endLine,
        blobSha: boundedString(value.blobSha, `${path}.blobSha`, {
            max: 64,
            pattern: BLOB_SHA_RE,
        }).toLowerCase(),
        excerptHash: boundedString(value.excerptHash, `${path}.excerptHash`, {
            max: 64,
            pattern: SHA256_RE,
        }).toLowerCase(),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        coverageScope: enumValue(
            value.coverageScope,
            `${path}.coverageScope`,
            COVERAGE_SCOPES,
        ),
    });
}

function validateEvidenceArray(value, path, max = LIMITS.evidencePerItem) {
    return boundedArray(value, path, max).map((entry, index) =>
        validateEvidenceReference(entry, `${path}[${index}]`));
}

export function validateSourceIdentity(value, path = "sourceIdentity") {
    objectShape(value, path, [
        "type",
        "namespace",
        "path",
        "contentSha256",
    ], ["blobSha"]);
    const result = {
        type: enumValue(value.type, `${path}.type`, SOURCE_IDENTITY_TYPES),
        namespace: boundedString(value.namespace, `${path}.namespace`, {
            max: LIMITS.namespace,
            normalize: true,
        }),
        path: boundedString(value.path, `${path}.path`, {
            max: LIMITS.path,
            normalize: true,
        }).replaceAll("\\", "/"),
        contentSha256: boundedString(value.contentSha256, `${path}.contentSha256`, {
            max: 64,
            pattern: SHA256_RE,
        }).toLowerCase(),
    };
    if (Object.hasOwn(value, "blobSha")) {
        result.blobSha = boundedString(value.blobSha, `${path}.blobSha`, {
            max: 64,
            pattern: BLOB_SHA_RE,
        }).toLowerCase();
    }
    return cloneFrozen(result);
}

function normalizeBehaviorToken(value, path) {
    const normalized = boundedString(value, path, {
        max: LIMITS.identifier,
        normalize: true,
    }).toLowerCase().replace(/\s+/g, "-");
    if (!BEHAVIOR_TOKEN_RE.test(normalized)) {
        fail(path, "must normalize to a semantic token, not prose or a source location");
    }
    return normalized;
}

export function normalizeBehaviorSignature(value, path = "behaviorSignature") {
    objectShape(value, path, [
        "action",
        "capability",
        "target",
    ], [
        "trigger",
        "mechanism",
        "persistence",
        "propagation",
        "qualifiers",
    ]);
    const result = {
        action: normalizeBehaviorToken(value.action, `${path}.action`),
        capability: normalizeBehaviorToken(value.capability, `${path}.capability`),
        target: normalizeBehaviorToken(value.target, `${path}.target`),
    };
    for (const key of ["trigger", "mechanism", "persistence", "propagation"]) {
        if (Object.hasOwn(value, key)) {
            result[key] = normalizeBehaviorToken(value[key], `${path}.${key}`);
        }
    }
    if (Object.hasOwn(value, "qualifiers")) {
        result.qualifiers = uniqueStrings(value.qualifiers, `${path}.qualifiers`, {
            maxItems: 16,
            maxLength: LIMITS.identifier,
            normalize: true,
        }).map((entry, index) =>
            normalizeBehaviorToken(entry, `${path}.qualifiers[${index}]`))
            .sort();
    }
    return cloneFrozen(result);
}

export function computeFindingId(sourceIdentity, behaviorSignature) {
    const source = validateSourceIdentity(sourceIdentity);
    const behavior = normalizeBehaviorSignature(behaviorSignature);
    const digest = createHash("sha256")
        .update("zerotrust-finding-v5\0", "utf8")
        .update(canonicalJson(source), "utf8")
        .update("\0", "utf8")
        .update(canonicalJson(behavior), "utf8")
        .digest("hex");
    return `ztf-v5-${digest}`;
}

export function validateGraphNode(value, path = "graphNode") {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "id",
        "kind",
        "label",
        "producer",
        "evidence",
    ], [
        "sourceIdentity",
        "behaviorSignature",
        "tags",
    ]);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) {
        fail(`${path}.schemaVersion`, `must equal ${ANALYSIS_SCHEMA_VERSION}`);
    }
    const result = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        id: validateIdentifier(value.id, `${path}.id`),
        kind: enumValue(value.kind, `${path}.kind`, GRAPH_NODE_KINDS),
        label: boundedString(value.label, `${path}.label`, {
            max: LIMITS.label,
            normalize: true,
        }),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        evidence: validateEvidenceArray(value.evidence, `${path}.evidence`),
    };
    if (Object.hasOwn(value, "sourceIdentity")) {
        result.sourceIdentity = validateSourceIdentity(
            value.sourceIdentity,
            `${path}.sourceIdentity`,
        );
    }
    if (Object.hasOwn(value, "behaviorSignature")) {
        result.behaviorSignature = normalizeBehaviorSignature(
            value.behaviorSignature,
            `${path}.behaviorSignature`,
        );
    }
    if (Object.hasOwn(value, "tags")) {
        result.tags = uniqueStrings(value.tags, `${path}.tags`, {
            maxItems: LIMITS.tags,
            maxLength: LIMITS.tag,
            pattern: IDENTIFIER_RE,
            normalize: true,
            sort: true,
        });
    }
    return cloneFrozen(result);
}

export function validateGraphEdge(value, path = "graphEdge") {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "id",
        "kind",
        "from",
        "to",
        "producer",
        "evidence",
    ], ["label", "tags"]);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) {
        fail(`${path}.schemaVersion`, `must equal ${ANALYSIS_SCHEMA_VERSION}`);
    }
    const result = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        id: validateIdentifier(value.id, `${path}.id`),
        kind: enumValue(value.kind, `${path}.kind`, GRAPH_EDGE_KINDS),
        from: validateIdentifier(value.from, `${path}.from`),
        to: validateIdentifier(value.to, `${path}.to`),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        evidence: validateEvidenceArray(value.evidence, `${path}.evidence`),
    };
    if (Object.hasOwn(value, "label")) {
        result.label = boundedString(value.label, `${path}.label`, {
            max: LIMITS.label,
            normalize: true,
        });
    }
    if (Object.hasOwn(value, "tags")) {
        result.tags = uniqueStrings(value.tags, `${path}.tags`, {
            maxItems: LIMITS.tags,
            maxLength: LIMITS.tag,
            pattern: IDENTIFIER_RE,
            normalize: true,
            sort: true,
        });
    }
    return cloneFrozen(result);
}

export function validateBehaviorGraphDocument(value, path = "behaviorGraph") {
    objectShape(value, path, ["schemaVersion", "auditId", "nodes", "edges"]);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) {
        fail(`${path}.schemaVersion`, `must equal ${ANALYSIS_SCHEMA_VERSION}`);
    }
    const auditId = validateAuditId(value.auditId, `${path}.auditId`);
    const nodes = boundedArray(value.nodes, `${path}.nodes`, LIMITS.graphNodes)
        .map((entry, index) => validateGraphNode(entry, `${path}.nodes[${index}]`));
    const edges = boundedArray(value.edges, `${path}.edges`, LIMITS.graphEdges)
        .map((entry, index) => validateGraphEdge(entry, `${path}.edges[${index}]`));
    const nodeIds = new Set();
    for (const node of nodes) {
        if (node.auditId !== auditId) fail(path, "node auditId does not match document");
        if (nodeIds.has(node.id)) fail(path, `duplicate node id: ${node.id}`);
        nodeIds.add(node.id);
    }
    const edgeIds = new Set();
    for (const edge of edges) {
        if (edge.auditId !== auditId) fail(path, "edge auditId does not match document");
        if (edgeIds.has(edge.id)) fail(path, `duplicate edge id: ${edge.id}`);
        edgeIds.add(edge.id);
        if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) {
            fail(path, `edge ${edge.id} references an unknown node`);
        }
    }
    return cloneFrozen({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        nodes,
        edges,
    });
}

export function validateCandidateFinding(value, path = "finding") {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "id",
        "sourceIdentity",
        "behaviorSignature",
        "title",
        "summary",
        "severity",
        "confidence",
        "maliciousProjectFit",
        "state",
        "evidence",
        "nodeIds",
        "edgeIds",
        "producer",
    ], ["tags"]);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) {
        fail(`${path}.schemaVersion`, `must equal ${ANALYSIS_SCHEMA_VERSION}`);
    }
    const sourceIdentity = validateSourceIdentity(
        value.sourceIdentity,
        `${path}.sourceIdentity`,
    );
    const behaviorSignature = normalizeBehaviorSignature(
        value.behaviorSignature,
        `${path}.behaviorSignature`,
    );
    const expectedId = computeFindingId(sourceIdentity, behaviorSignature);
    const id = boundedString(value.id, `${path}.id`, {
        max: 71,
        pattern: FINDING_ID_RE,
    });
    if (id !== expectedId) {
        fail(`${path}.id`, "must be derived from sourceIdentity and behaviorSignature");
    }
    const result = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        id,
        sourceIdentity,
        behaviorSignature,
        title: boundedString(value.title, `${path}.title`, {
            max: LIMITS.title,
            normalize: true,
        }),
        summary: boundedString(value.summary, `${path}.summary`, {
            max: LIMITS.summary,
            normalize: true,
        }),
        severity: enumValue(value.severity, `${path}.severity`, SEVERITIES),
        confidence: enumValue(
            value.confidence,
            `${path}.confidence`,
            CONFIDENCE_LEVELS,
        ),
        maliciousProjectFit: enumValue(
            value.maliciousProjectFit,
            `${path}.maliciousProjectFit`,
            MALICIOUS_PROJECT_FIT_LEVELS,
        ),
        state: enumValue(value.state, `${path}.state`, FINDING_STATES),
        evidence: validateEvidenceArray(value.evidence, `${path}.evidence`),
        nodeIds: uniqueStrings(value.nodeIds, `${path}.nodeIds`, {
            maxItems: LIMITS.graphNodes,
            maxLength: LIMITS.identifier,
            pattern: IDENTIFIER_RE,
        }),
        edgeIds: uniqueStrings(value.edgeIds, `${path}.edgeIds`, {
            maxItems: LIMITS.graphEdges,
            maxLength: LIMITS.identifier,
            pattern: IDENTIFIER_RE,
        }),
        producer: validateIdentifier(value.producer, `${path}.producer`),
    };
    if (Object.hasOwn(value, "tags")) {
        result.tags = uniqueStrings(value.tags, `${path}.tags`, {
            maxItems: LIMITS.tags,
            maxLength: LIMITS.tag,
            pattern: IDENTIFIER_RE,
            normalize: true,
            sort: true,
        });
    }
    return cloneFrozen(result);
}

export function validateValidationDecision(value, path = "validationDecision") {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "findingId",
        "validator",
        "decision",
        "severity",
        "confidence",
        "maliciousProjectFit",
        "rationaleCode",
        "rationale",
        "evidence",
    ]);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) {
        fail(`${path}.schemaVersion`, `must equal ${ANALYSIS_SCHEMA_VERSION}`);
    }
    return cloneFrozen({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        findingId: boundedString(value.findingId, `${path}.findingId`, {
            max: 71,
            pattern: FINDING_ID_RE,
        }),
        validator: validateIdentifier(value.validator, `${path}.validator`),
        decision: enumValue(value.decision, `${path}.decision`, [
            "validated",
            "refuted",
            "unresolved",
        ]),
        severity: enumValue(value.severity, `${path}.severity`, SEVERITIES),
        confidence: enumValue(
            value.confidence,
            `${path}.confidence`,
            CONFIDENCE_LEVELS,
        ),
        maliciousProjectFit: enumValue(
            value.maliciousProjectFit,
            `${path}.maliciousProjectFit`,
            MALICIOUS_PROJECT_FIT_LEVELS,
        ),
        rationaleCode: normalizeBehaviorToken(
            value.rationaleCode,
            `${path}.rationaleCode`,
        ),
        rationale: boundedString(value.rationale, `${path}.rationale`, {
            max: LIMITS.rationale,
            normalize: true,
        }),
        evidence: validateEvidenceArray(value.evidence, `${path}.evidence`),
    });
}

function validateMetadataEntry(value, path) {
    objectShape(value, path, ["key", "type", "value"]);
    const key = validateIdentifier(value.key, `${path}.key`);
    const type = enumValue(value.type, `${path}.type`, [
        "string",
        "integer",
        "number",
        "boolean",
        "string-list",
    ]);
    let normalizedValue;
    if (type === "string") {
        normalizedValue = boundedString(value.value, `${path}.value`, {
            min: 0,
            max: LIMITS.metadataString,
            normalize: true,
        });
    } else if (type === "integer") {
        normalizedValue = safeInteger(value.value, `${path}.value`, {
            min: Number.MIN_SAFE_INTEGER,
            max: Number.MAX_SAFE_INTEGER,
        });
    } else if (type === "number") {
        normalizedValue = finiteNumber(value.value, `${path}.value`);
    } else if (type === "boolean") {
        normalizedValue = booleanValue(value.value, `${path}.value`);
    } else {
        normalizedValue = uniqueStrings(value.value, `${path}.value`, {
            maxItems: 64,
            maxLength: LIMITS.metadataString,
            normalize: true,
        });
    }
    return cloneFrozen({ key, type, value: normalizedValue });
}

export function validateMetadataCacheDocument(value, path = "metadataDocument") {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "namespace",
        "key",
        "sourceIdentity",
        "producer",
        "capturedAt",
        "entries",
    ], ["expiresAt"]);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) {
        fail(`${path}.schemaVersion`, `must equal ${ANALYSIS_SCHEMA_VERSION}`);
    }
    const capturedAt = isoTimestamp(value.capturedAt, `${path}.capturedAt`);
    const entries = boundedArray(
        value.entries,
        `${path}.entries`,
        LIMITS.metadataEntries,
    ).map((entry, index) =>
        validateMetadataEntry(entry, `${path}.entries[${index}]`));
    const entryKeys = new Set();
    for (const entry of entries) {
        if (entryKeys.has(entry.key)) fail(`${path}.entries`, `duplicate key: ${entry.key}`);
        entryKeys.add(entry.key);
    }
    const result = {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        namespace: validateIdentifier(value.namespace, `${path}.namespace`),
        key: validateIdentifier(value.key, `${path}.key`),
        sourceIdentity: validateSourceIdentity(
            value.sourceIdentity,
            `${path}.sourceIdentity`,
        ),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        capturedAt,
        entries,
    };
    if (Object.hasOwn(value, "expiresAt")) {
        result.expiresAt = isoTimestamp(value.expiresAt, `${path}.expiresAt`);
        if (Date.parse(result.expiresAt) <= Date.parse(capturedAt)) {
            fail(`${path}.expiresAt`, "must be later than capturedAt");
        }
    }
    return cloneFrozen(result);
}

export function validatePluginOutput(value, path = "pluginOutput") {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "pluginId",
        "pluginVersion",
        "producer",
        "coverageScope",
        "nodes",
        "edges",
        "findings",
        "validationDecisions",
        "metadataDocuments",
        "warnings",
    ]);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) {
        fail(`${path}.schemaVersion`, `must equal ${ANALYSIS_SCHEMA_VERSION}`);
    }
    const auditId = validateAuditId(value.auditId, `${path}.auditId`);
    const nodes = boundedArray(value.nodes, `${path}.nodes`, LIMITS.graphNodes)
        .map((entry, index) => validateGraphNode(entry, `${path}.nodes[${index}]`));
    const edges = boundedArray(value.edges, `${path}.edges`, LIMITS.graphEdges)
        .map((entry, index) => validateGraphEdge(entry, `${path}.edges[${index}]`));
    const findings = boundedArray(value.findings, `${path}.findings`, LIMITS.findings)
        .map((entry, index) =>
            validateCandidateFinding(entry, `${path}.findings[${index}]`));
    const validationDecisions = boundedArray(
        value.validationDecisions,
        `${path}.validationDecisions`,
        LIMITS.validationDecisions,
    ).map((entry, index) =>
        validateValidationDecision(entry, `${path}.validationDecisions[${index}]`));
    const metadataDocuments = boundedArray(
        value.metadataDocuments,
        `${path}.metadataDocuments`,
        LIMITS.metadataDocuments,
    ).map((entry, index) =>
        validateMetadataCacheDocument(entry, `${path}.metadataDocuments[${index}]`));
    for (const [kind, entries] of [
        ["node", nodes],
        ["edge", edges],
        ["finding", findings],
        ["validation decision", validationDecisions],
        ["metadata document", metadataDocuments],
    ]) {
        for (const entry of entries) {
            if (entry.auditId !== auditId) {
                fail(path, `${kind} auditId does not match plugin output`);
            }
        }
    }
    for (const finding of findings) {
        if (finding.state !== "candidate") {
            fail(path, `plugin finding ${finding.id} must start in candidate state`);
        }
    }
    for (const [kind, entries] of [["node", nodes], ["edge", edges], ["finding", findings]]) {
        const ids = new Set();
        for (const entry of entries) {
            if (ids.has(entry.id)) fail(path, `duplicate ${kind} id: ${entry.id}`);
            ids.add(entry.id);
        }
    }
    return cloneFrozen({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        pluginId: validateIdentifier(value.pluginId, `${path}.pluginId`),
        pluginVersion: boundedString(value.pluginVersion, `${path}.pluginVersion`, {
            max: 64,
            pattern: /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/,
            normalize: true,
        }),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        coverageScope: enumValue(
            value.coverageScope,
            `${path}.coverageScope`,
            COVERAGE_SCOPES,
        ),
        nodes,
        edges,
        findings,
        validationDecisions,
        metadataDocuments,
        warnings: boundedArray(
            value.warnings,
            `${path}.warnings`,
            LIMITS.pluginWarnings,
        ).map((warning, index) =>
            boundedString(warning, `${path}.warnings[${index}]`, {
                max: LIMITS.pluginWarning,
                normalize: true,
            })),
    });
}

export function validateAnalysisStageState(value, path = "analysisStageState") {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "current",
        "history",
    ]);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) {
        fail(`${path}.schemaVersion`, `must equal ${ANALYSIS_SCHEMA_VERSION}`);
    }
    const current = enumValue(value.current, `${path}.current`, ANALYSIS_STAGES);
    const history = boundedArray(
        value.history,
        `${path}.history`,
        ANALYSIS_STAGES.length,
    ).map((stage, index) =>
        enumValue(stage, `${path}.history[${index}]`, ANALYSIS_STAGES));
    const expected = ANALYSIS_STAGES.slice(0, ANALYSIS_STAGES.indexOf(current) + 1);
    if (history.length !== expected.length
        || history.some((stage, index) => stage !== expected[index])) {
        fail(`${path}.history`, "must be the legal stage prefix ending at current");
    }
    return cloneFrozen({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        current,
        history,
    });
}

export function createInitialAnalysisStageState(auditId) {
    return validateAnalysisStageState({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId,
        current: "acquired",
        history: ["acquired"],
    });
}

export const __internals = Object.freeze({
    canonicalJson,
    cloneFrozen,
    FINDING_ID_RE,
    IDENTIFIER_RE,
});
