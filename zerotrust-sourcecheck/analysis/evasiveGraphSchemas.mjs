import { createHash } from "node:crypto";

import {
    EVASIVE_BLOCKER_CODES,
} from "./evasiveSchemas.mjs";
import { ASSURANCE_ANALYSIS_SCHEMA_REVISION } from "./assuranceState.mjs";

export const EVASIVE_GRAPH_SCHEMA_REVISION = 6;
export const EVASIVE_GRAPH_PLAN_KIND = "evasive-behavior-graph";

export const EVASIVE_GRAPH_NODE_KINDS = Object.freeze([
    "activation",
    "trigger",
    "condition",
    "gate",
    "source",
    "transform",
    "capability",
    "sink",
    "effect",
    "persistence",
    "propagation",
    "generated-artifact",
    "package",
    "archive-member",
    "binary-metadata",
    "binary-import",
    "binary-export",
    "submodule",
    "lfs",
    "release-asset",
    "unsupported-target",
    "dynamic-target",
]);

export const EVASIVE_GRAPH_EDGE_KINDS = Object.freeze([
    "imports",
    "calls",
    "selects",
    "decodes",
    "generates",
    "packages",
    "downloads",
    "loads",
    "executes",
    "reads",
    "writes",
    "publishes",
    "depends-on",
    "evidence-binding",
    "provenance-binding",
]);

export const EVASIVE_GRAPH_NODE_STATUSES = Object.freeze([
    "supported",
    "unsupported",
    "unresolved",
]);

export const EVASIVE_GRAPH_FINDING_ORIGINS = Object.freeze([
    "semantic-review",
    "red-team",
]);

export const EVASIVE_GRAPH_LIMITS = Object.freeze({
    nodes: 100_000,
    edges: 200_000,
    evidence: 100_000,
    findings: 10_000,
    conflicts: 4_096,
    bindingsPerRecord: 8_192,
    conflictRecords: 4_096,
});

const HARD_LIMITS = Object.freeze({
    nodes: 200_000,
    edges: 400_000,
    evidence: 200_000,
    findings: 20_000,
    conflicts: 8_192,
    bindingsPerRecord: 16_384,
    conflictRecords: 8_192,
});

const SHA256_RE = /^[a-f0-9]{64}$/u;
const GRAPH_ID_RE = /^ztbg-[a-f0-9]{64}$/u;
const NODE_ID_RE = /^ztgn-[a-f0-9]{64}$/u;
const EDGE_ID_RE = /^ztge-[a-f0-9]{64}$/u;
const CONFLICT_ID_RE = /^ztgc-[a-f0-9]{64}$/u;
const FINDING_ID_RE = /^(?:ztrf|ztsf)-[a-f0-9]{64}$/u;
const EVIDENCE_ID_RE = /^(?:ztre|ztve)-[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@#-]{0,255}$/u;
const AUDIT_ID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

if (EVASIVE_GRAPH_SCHEMA_REVISION !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
    throw new Error("assurance graph and analysis schema revisions must align");
}

export class EvasiveGraphContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "EvasiveGraphContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new EvasiveGraphContractError(path, message);
}

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
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

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function hashDomain(domain, value) {
    return createHash("sha256")
        .update(domain, "utf8")
        .update("\0", "utf8")
        .update(canonicalJson(value), "utf8")
        .digest("hex");
}

function cloneFrozen(value) {
    if (Array.isArray(value)) return Object.freeze(value.map(cloneFrozen));
    if (isPlainObject(value)) {
        const result = {};
        for (const [key, entry] of Object.entries(value)) result[key] = cloneFrozen(entry);
        return Object.freeze(result);
    }
    return value;
}

function boundedString(value, path, {
    max = 4_096,
    pattern = null,
    nullable = false,
} = {}) {
    if (nullable && value === null) return null;
    if (typeof value !== "string" || value.length < 1 || value.length > max
        || /[\u0000-\u001f\u007f]/u.test(value)
        || (pattern && !pattern.test(value))) {
        fail(path, "has an invalid bounded string value");
    }
    return value;
}

function enumValue(value, path, allowed) {
    if (!allowed.includes(value)) fail(path, `must be one of: ${allowed.join(", ")}`);
    return value;
}

function safeInteger(value, path) {
    if (!Number.isSafeInteger(value) || value < 0) {
        fail(path, "must be a non-negative safe integer");
    }
    return value;
}

function boundedArray(value, path, maximum) {
    if (!Array.isArray(value) || value.length > maximum) {
        fail(path, `must be an array with at most ${maximum} entries`);
    }
    return value;
}

function sortedUnique(value, path, {
    max = EVASIVE_GRAPH_LIMITS.bindingsPerRecord,
    pattern = IDENTIFIER_RE,
} = {}) {
    const entries = boundedArray(value, path, max).map((entry, index) =>
        boundedString(entry, `${path}[${index}]`, { max: 256, pattern }));
    if (new Set(entries).size !== entries.length) fail(path, "must not contain duplicates");
    return entries.sort();
}

function validateSha256(value, path) {
    return boundedString(value, path, { max: 64, pattern: SHA256_RE });
}

function validatePath(value, path) {
    const normalized = boundedString(value, path, { max: 4_096 })
        .replace(/\\/gu, "/");
    if (normalized.startsWith("/") || normalized.endsWith("/")
        || normalized.includes("//")
        || normalized.split("/").some((segment) =>
            segment.length === 0 || segment === "." || segment === "..")) {
        fail(path, "must be a normalized relative path");
    }
    return normalized;
}

export function normalizeEvasiveGraphLimits(value = {}, path = "evasiveGraphLimits") {
    if (!isPlainObject(value)) fail(path, "must be a plain object");
    const result = {};
    for (const key of Object.keys(EVASIVE_GRAPH_LIMITS)) {
        if (Object.hasOwn(value, key)
            && (!Number.isSafeInteger(value[key])
                || value[key] < 1
                || value[key] > HARD_LIMITS[key])) {
            fail(`${path}.${key}`, `must be an integer between 1 and ${HARD_LIMITS[key]}`);
        }
        result[key] = value[key] ?? EVASIVE_GRAPH_LIMITS[key];
    }
    for (const key of Object.keys(value)) {
        if (!Object.hasOwn(EVASIVE_GRAPH_LIMITS, key)) fail(`${path}.${key}`, "unknown field");
    }
    return cloneFrozen(result);
}

function normalizeBindings(value, path, fields, limits) {
    objectShape(value, path, fields);
    return cloneFrozen(Object.fromEntries(fields.map((field) => [
        field,
        sortedUnique(value[field], `${path}.${field}`, {
            max: limits.bindingsPerRecord,
            pattern: IDENTIFIER_RE,
        }),
    ])));
}

const NODE_BINDING_FIELDS = Object.freeze([
    "objectIds",
    "artifactIds",
    "factIds",
    "evidenceIds",
    "supplyChainNodeIds",
    "semanticReviewIds",
    "candidateIds",
    "redTeamGraphNodeIds",
]);

const EDGE_BINDING_FIELDS = Object.freeze([
    "artifactIds",
    "factIds",
    "evidenceIds",
    "supplyChainEdgeIds",
    "candidateIds",
    "redTeamGraphEdgeIds",
]);

export function createEvasiveGraphEvidenceRecord(value, path = "evasiveGraphEvidenceInput") {
    objectShape(value, path, [
        "evidenceId",
        "evidenceKind",
        "objectId",
        "artifactId",
        "factId",
        "supplyChainNodeId",
        "path",
        "startLine",
        "endLine",
        "excerptHash",
        "contentSha256",
    ]);
    const startLine = safeInteger(value.startLine, `${path}.startLine`);
    const endLine = safeInteger(value.endLine, `${path}.endLine`);
    if (endLine < startLine) fail(`${path}.endLine`, "must not precede startLine");
    return cloneFrozen({
        evidenceId: boundedString(value.evidenceId, `${path}.evidenceId`, {
            max: 72,
            pattern: EVIDENCE_ID_RE,
        }),
        evidenceKind: enumValue(value.evidenceKind, `${path}.evidenceKind`, [
            "object",
            "artifact",
            "fact",
            "supply-chain",
        ]),
        objectId: value.objectId === null
            ? null: boundedString(value.objectId, `${path}.objectId`, {
                max: 128,
                pattern: IDENTIFIER_RE,
            }),
        artifactId: value.artifactId === null
            ? null: boundedString(value.artifactId, `${path}.artifactId`, {
                max: 128,
                pattern: IDENTIFIER_RE,
            }),
        factId: value.factId === null
            ? null: boundedString(value.factId, `${path}.factId`, {
                max: 128,
                pattern: IDENTIFIER_RE,
            }),
        supplyChainNodeId: value.supplyChainNodeId === null
            ? null: boundedString(value.supplyChainNodeId, `${path}.supplyChainNodeId`, {
                max: 256,
                pattern: IDENTIFIER_RE,
            }),
        path: validatePath(value.path, `${path}.path`),
        startLine,
        endLine,
        excerptHash: value.excerptHash === null
            ? null: validateSha256(value.excerptHash, `${path}.excerptHash`),
        contentSha256: validateSha256(value.contentSha256, `${path}.contentSha256`),
    });
}

function normalizeEvasiveGraphNodeDescriptor(value, path, limits) {
    return {
        kind: enumValue(value.kind, `${path}.kind`, EVASIVE_GRAPH_NODE_KINDS),
        identityKind: enumValue(value.identityKind, `${path}.identityKind`, [
            "object",
            "artifact",
            "fact",
            "supply-chain",
            "finding",
            "target",
        ]),
        identity: boundedString(value.identity, `${path}.identity`, {
            max: 256,
            pattern: IDENTIFIER_RE,
        }),
        status: enumValue(value.status, `${path}.status`, EVASIVE_GRAPH_NODE_STATUSES),
        bindings: normalizeBindings(
            value.bindings,
            `${path}.bindings`,
            NODE_BINDING_FIELDS,
            limits,
        ),
    };
}

function buildEvasiveGraphNode(base) {
    const nodeSha256 = hashDomain("zerotrust-graph-node", {
        kind: base.kind,
        identityKind: base.identityKind,
        identity: base.identity,
    });
    return cloneFrozen({
        nodeId: `ztgn-${nodeSha256}`,
        ...base,
        hashes: { nodeSha256 },
    });
}

export function createEvasiveGraphNode(value, path = "evasiveGraphNodeInput", limits = EVASIVE_GRAPH_LIMITS) {
    objectShape(value, path, [
        "kind",
        "identityKind",
        "identity",
        "status",
        "bindings",
    ]);
    return buildEvasiveGraphNode(normalizeEvasiveGraphNodeDescriptor(value, path, limits));
}

export function validateEvasiveGraphNode(value, path = "evasiveGraphNode", limits = EVASIVE_GRAPH_LIMITS) {
    objectShape(value, path, [
        "nodeId",
        "kind",
        "identityKind",
        "identity",
        "status",
        "bindings",
        "hashes",
    ]);
    boundedString(value.nodeId, `${path}.nodeId`, { max: 72, pattern: NODE_ID_RE });
    objectShape(value.hashes, `${path}.hashes`, ["nodeSha256"]);
    validateSha256(value.hashes.nodeSha256, `${path}.hashes.nodeSha256`);
    const expected = buildEvasiveGraphNode(
        normalizeEvasiveGraphNodeDescriptor(value, path, limits),
    );
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic graph node identity");
    }
    return expected;
}

function normalizeEvasiveGraphEdgeDescriptor(value, path, limits) {
    return {
        kind: enumValue(value.kind, `${path}.kind`, EVASIVE_GRAPH_EDGE_KINDS),
        fromNodeId: boundedString(value.fromNodeId, `${path}.fromNodeId`, {
            max: 72,
            pattern: NODE_ID_RE,
        }),
        toNodeId: boundedString(value.toNodeId, `${path}.toNodeId`, {
            max: 72,
            pattern: NODE_ID_RE,
        }),
        bindings: normalizeBindings(
            value.bindings,
            `${path}.bindings`,
            EDGE_BINDING_FIELDS,
            limits,
        ),
    };
}

function buildEvasiveGraphEdge(base) {
    const edgeSha256 = hashDomain("zerotrust-graph-edge", base);
    return cloneFrozen({
        edgeId: `ztge-${edgeSha256}`,
        ...base,
        hashes: { edgeSha256 },
    });
}

export function createEvasiveGraphEdge(value, path = "evasiveGraphEdgeInput", limits = EVASIVE_GRAPH_LIMITS) {
    objectShape(value, path, [
        "kind",
        "fromNodeId",
        "toNodeId",
        "bindings",
    ]);
    return buildEvasiveGraphEdge(normalizeEvasiveGraphEdgeDescriptor(value, path, limits));
}

export function validateEvasiveGraphEdge(value, path = "evasiveGraphEdge", limits = EVASIVE_GRAPH_LIMITS) {
    objectShape(value, path, [
        "edgeId",
        "kind",
        "fromNodeId",
        "toNodeId",
        "bindings",
        "hashes",
    ]);
    boundedString(value.edgeId, `${path}.edgeId`, { max: 72, pattern: EDGE_ID_RE });
    objectShape(value.hashes, `${path}.hashes`, ["edgeSha256"]);
    validateSha256(value.hashes.edgeSha256, `${path}.hashes.edgeSha256`);
    const expected = buildEvasiveGraphEdge(
        normalizeEvasiveGraphEdgeDescriptor(value, path, limits),
    );
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic graph edge identity");
    }
    return expected;
}

function normalizeEvasiveGraphConflictDescriptor(value, path, limits) {
    const records = boundedArray(
        value.records,
        `${path}.records`,
        limits.conflictRecords,
    ).map((record, index) =>
        validateEvasiveGraphEdge(record, `${path}.records[${index}]`, limits))
        .sort((left, right) => left.edgeId.localeCompare(right.edgeId));
    const endpointNodeIds = sortedUnique(
        value.endpointNodeIds,
        `${path}.endpointNodeIds`,
        { max: 2, pattern: NODE_ID_RE },
    );
    if (endpointNodeIds.length !== 2 || records.length < 2) {
        fail(path, "requires two endpoints and at least two competing records");
    }
    const directions = new Set(records.map((record) =>
        `${record.fromNodeId}\0${record.toNodeId}`));
    if (directions.size < 2) fail(`${path}.records`, "must contain both direction variants");
    if (records.some((record) =>
        record.kind !== value.edgeKind
        || !endpointNodeIds.includes(record.fromNodeId)
        || !endpointNodeIds.includes(record.toNodeId))) {
        fail(path, "contains a record outside the unordered endpoint/kind bucket");
    }
    return {
        reasonCode: "contradictory-edge-direction",
        edgeKind: enumValue(value.edgeKind, `${path}.edgeKind`, EVASIVE_GRAPH_EDGE_KINDS),
        endpointNodeIds,
        records,
    };
}

function buildEvasiveGraphConflict(base) {
    const conflictSha256 = hashDomain("zerotrust-graph-conflict", base);
    return cloneFrozen({
        conflictId: `ztgc-${conflictSha256}`,
        ...base,
        hashes: { conflictSha256 },
    });
}

export function createEvasiveGraphConflict(value, path = "evasiveGraphConflictInput", limits = EVASIVE_GRAPH_LIMITS) {
    objectShape(value, path, [
        "edgeKind",
        "endpointNodeIds",
        "records",
    ]);
    return buildEvasiveGraphConflict(
        normalizeEvasiveGraphConflictDescriptor(value, path, limits),
    );
}

export function validateEvasiveGraphConflict(
    value,
    path = "evasiveGraphConflict",
    limits = EVASIVE_GRAPH_LIMITS,
) {
    objectShape(value, path, [
        "conflictId",
        "reasonCode",
        "edgeKind",
        "endpointNodeIds",
        "records",
        "hashes",
    ]);
    boundedString(value.conflictId, `${path}.conflictId`, {
        max: 72,
        pattern: CONFLICT_ID_RE,
    });
    if (value.reasonCode !== "contradictory-edge-direction") {
        fail(`${path}.reasonCode`, "is invalid");
    }
    objectShape(value.hashes, `${path}.hashes`, ["conflictSha256"]);
    validateSha256(value.hashes.conflictSha256, `${path}.hashes.conflictSha256`);
    const expected = buildEvasiveGraphConflict(
        normalizeEvasiveGraphConflictDescriptor(value, path, limits),
    );
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic conflict identity");
    }
    return expected;
}

function normalizeEvasiveGraphFindingDescriptor(value, path, limits) {
    const findingId = boundedString(value.findingId, `${path}.findingId`, {
        max: 72,
        pattern: FINDING_ID_RE,
    });
    return {
        findingId,
        origin: enumValue(value.origin, `${path}.origin`, EVASIVE_GRAPH_FINDING_ORIGINS),
        severity: enumValue(value.severity, `${path}.severity`, [
            "info", "low", "medium", "high", "critical",
        ]),
        objectIds: sortedUnique(value.objectIds, `${path}.objectIds`, {
            max: limits.bindingsPerRecord,
        }),
        artifactIds: sortedUnique(value.artifactIds, `${path}.artifactIds`, {
            max: limits.bindingsPerRecord,
        }),
        factIds: sortedUnique(value.factIds, `${path}.factIds`, {
            max: limits.bindingsPerRecord,
        }),
        evidenceIds: sortedUnique(value.evidenceIds, `${path}.evidenceIds`, {
            max: limits.bindingsPerRecord,
        }),
        nodeIds: sortedUnique(value.nodeIds, `${path}.nodeIds`, {
            max: limits.bindingsPerRecord,
            pattern: NODE_ID_RE,
        }),
        edgeIds: sortedUnique(value.edgeIds, `${path}.edgeIds`, {
            max: limits.bindingsPerRecord,
            pattern: EDGE_ID_RE,
        }),
        sourceRecordIds: sortedUnique(value.sourceRecordIds, `${path}.sourceRecordIds`, {
            max: limits.bindingsPerRecord,
        }),
    };
}

function buildEvasiveGraphFinding(base) {
    const findingSha256 = hashDomain("zerotrust-graph-finding", base);
    return cloneFrozen({
        ...base,
        hashes: { findingSha256 },
    });
}

export function createEvasiveGraphFinding(value, path = "evasiveGraphFindingInput", limits = EVASIVE_GRAPH_LIMITS) {
    objectShape(value, path, [
        "findingId",
        "origin",
        "severity",
        "objectIds",
        "artifactIds",
        "factIds",
        "evidenceIds",
        "nodeIds",
        "edgeIds",
        "sourceRecordIds",
    ]);
    return buildEvasiveGraphFinding(
        normalizeEvasiveGraphFindingDescriptor(value, path, limits),
    );
}

export function validateEvasiveGraphFinding(
    value,
    path = "evasiveGraphFinding",
    limits = EVASIVE_GRAPH_LIMITS,
) {
    objectShape(value, path, [
        "findingId",
        "origin",
        "severity",
        "objectIds",
        "artifactIds",
        "factIds",
        "evidenceIds",
        "nodeIds",
        "edgeIds",
        "sourceRecordIds",
        "hashes",
    ]);
    objectShape(value.hashes, `${path}.hashes`, ["findingSha256"]);
    validateSha256(value.hashes.findingSha256, `${path}.hashes.findingSha256`);
    const expected = buildEvasiveGraphFinding(
        normalizeEvasiveGraphFindingDescriptor(value, path, limits),
    );
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic finding identity");
    }
    return expected;
}

function uniqueRecords(records, idField, path) {
    const byId = new Map();
    for (const record of records) {
        const existing = byId.get(record[idField]);
        if (existing && canonicalJson(existing) !== canonicalJson(record)) {
            fail(path, `contains conflicting ${idField} records`);
        }
        byId.set(record[idField], record);
    }
    return [...byId.values()];
}

export function createEvasiveGraphPlan(value, path = "evasiveGraphPlanInput") {
    objectShape(value, path, [
        "auditId",
        "sourceNamespace",
        "snapshotId",
        "snapshotSha256",
        "nodes",
        "edges",
        "evidence",
        "findings",
        "conflicts",
        "unresolvedTargetNodeIds",
        "blockerCodes",
        "truncation",
        "limits",
    ]);
    const limits = normalizeEvasiveGraphLimits(value.limits, `${path}.limits`);
    const nodes = uniqueRecords(
        boundedArray(value.nodes, `${path}.nodes`, limits.nodes)
            .map((entry, index) =>
                validateEvasiveGraphNode(entry, `${path}.nodes[${index}]`, limits)),
        "nodeId",
        `${path}.nodes`,
    ).sort((left, right) => left.nodeId.localeCompare(right.nodeId));
    const edges = uniqueRecords(
        boundedArray(value.edges, `${path}.edges`, limits.edges)
            .map((entry, index) =>
                validateEvasiveGraphEdge(entry, `${path}.edges[${index}]`, limits)),
        "edgeId",
        `${path}.edges`,
    ).sort((left, right) => left.edgeId.localeCompare(right.edgeId));
    const evidence = uniqueRecords(
        boundedArray(value.evidence, `${path}.evidence`, limits.evidence)
            .map((entry, index) =>
                createEvasiveGraphEvidenceRecord(entry, `${path}.evidence[${index}]`)),
        "evidenceId",
        `${path}.evidence`,
    ).sort((left, right) => left.evidenceId.localeCompare(right.evidenceId));
    const findings = uniqueRecords(
        boundedArray(value.findings, `${path}.findings`, limits.findings)
            .map((entry, index) =>
                validateEvasiveGraphFinding(entry, `${path}.findings[${index}]`, limits)),
        "findingId",
        `${path}.findings`,
    ).sort((left, right) => left.findingId.localeCompare(right.findingId));
    const conflicts = uniqueRecords(
        boundedArray(value.conflicts, `${path}.conflicts`, limits.conflicts)
            .map((entry, index) =>
                validateEvasiveGraphConflict(entry, `${path}.conflicts[${index}]`, limits)),
        "conflictId",
        `${path}.conflicts`,
    ).sort((left, right) => left.conflictId.localeCompare(right.conflictId));
    const nodeIds = new Set(nodes.map((node) => node.nodeId));
    const edgeIds = new Set(edges.map((edge) => edge.edgeId));
    const evidenceIds = new Set(evidence.map((entry) => entry.evidenceId));
    for (const edge of edges) {
        if (!nodeIds.has(edge.fromNodeId) || !nodeIds.has(edge.toNodeId)) {
            fail(`${path}.edges`, `edge ${edge.edgeId} references an unknown node`);
        }
        if (edge.bindings.evidenceIds.some((id) => !evidenceIds.has(id))) {
            fail(`${path}.edges`, `edge ${edge.edgeId} references unknown evidence`);
        }
    }
    for (const node of nodes) {
        if (node.bindings.evidenceIds.some((id) => !evidenceIds.has(id))) {
            fail(`${path}.nodes`, `node ${node.nodeId} references unknown evidence`);
        }
    }
    for (const finding of findings) {
        if (finding.nodeIds.some((id) => !nodeIds.has(id))
            || finding.edgeIds.some((id) => !edgeIds.has(id))
            || finding.evidenceIds.some((id) => !evidenceIds.has(id))) {
            fail(`${path}.findings`, `finding ${finding.findingId} has an unknown binding`);
        }
    }
    for (const conflict of conflicts) {
        if (conflict.endpointNodeIds.some((id) => !nodeIds.has(id))
            || conflict.records.some((record) =>
                record.bindings.evidenceIds.some((id) => !evidenceIds.has(id)))) {
            fail(`${path}.conflicts`, `conflict ${conflict.conflictId} has an unknown binding`);
        }
    }
    const unresolvedTargetNodeIds = sortedUnique(
        value.unresolvedTargetNodeIds,
        `${path}.unresolvedTargetNodeIds`,
        { max: limits.nodes, pattern: NODE_ID_RE },
    );
    if (unresolvedTargetNodeIds.some((id) => !nodeIds.has(id))) {
        fail(`${path}.unresolvedTargetNodeIds`, "references an unknown node");
    }
    objectShape(value.truncation, `${path}.truncation`, [
        "nodes",
        "edges",
        "evidence",
        "findings",
        "conflicts",
        "bindings",
    ]);
    const truncation = {};
    for (const key of ["nodes", "edges", "evidence", "findings", "conflicts", "bindings"]) {
        if (typeof value.truncation[key] !== "boolean") {
            fail(`${path}.truncation.${key}`, "must be boolean");
        }
        truncation[key] = value.truncation[key];
    }
    const blockerCodes = sortedUnique(value.blockerCodes, `${path}.blockerCodes`, {
        max: 64,
        pattern: IDENTIFIER_RE,
    });
    if (blockerCodes.some((code) => !EVASIVE_BLOCKER_CODES.includes(code))) {
        fail(`${path}.blockerCodes`, "contains an unknown assurance blocker");
    }
    const base = {
        schemaVersion: EVASIVE_GRAPH_SCHEMA_REVISION,
        contractKind: EVASIVE_GRAPH_PLAN_KIND,
        auditId: boundedString(value.auditId, `${path}.auditId`, {
            max: 36,
            pattern: AUDIT_ID_RE,
        }).toLowerCase(),
        sourceNamespace: boundedString(
            value.sourceNamespace,
            `${path}.sourceNamespace`,
            { max: 512 },
        ),
        snapshotId: boundedString(value.snapshotId, `${path}.snapshotId`, {
            max: 72,
            pattern: /^zts-[a-f0-9]{64}$/u,
        }),
        nodes,
        edges,
        evidence,
        findings,
        conflicts,
        unresolvedTargetNodeIds,
        blockerCodes,
        truncation,
        limits,
    };
    const componentHashes = {
        snapshotSha256: validateSha256(
            value.snapshotSha256,
            `${path}.snapshotSha256`,
        ),
        nodesSha256: hashDomain("zerotrust-graph-nodes", nodes),
        edgesSha256: hashDomain("zerotrust-graph-edges", edges),
        evidenceSha256: hashDomain("zerotrust-graph-evidence", evidence),
        findingsSha256: hashDomain("zerotrust-graph-findings", findings),
        conflictsSha256: hashDomain("zerotrust-graph-conflicts", conflicts),
    };
    const graphSha256 = hashDomain("zerotrust-evasive-behavior-graph", {
        ...base,
        hashes: componentHashes,
    });
    return cloneFrozen({
        ...base,
        graphId: `ztbg-${graphSha256}`,
        hashes: {
            ...componentHashes,
            graphSha256,
        },
    });
}

export function validateEvasiveGraphPlan(value, path = "evasiveGraphPlan") {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "auditId",
        "sourceNamespace",
        "snapshotId",
        "graphId",
        "nodes",
        "edges",
        "evidence",
        "findings",
        "conflicts",
        "unresolvedTargetNodeIds",
        "blockerCodes",
        "truncation",
        "limits",
        "hashes",
    ]);
    if (value.schemaVersion !== EVASIVE_GRAPH_SCHEMA_REVISION
        || value.contractKind !== EVASIVE_GRAPH_PLAN_KIND) {
        fail(path, "has an invalid assurance graph contract");
    }
    boundedString(value.graphId, `${path}.graphId`, { max: 72, pattern: GRAPH_ID_RE });
    objectShape(value.hashes, `${path}.hashes`, [
        "snapshotSha256",
        "nodesSha256",
        "edgesSha256",
        "evidenceSha256",
        "findingsSha256",
        "conflictsSha256",
        "graphSha256",
    ]);
    const expected = createEvasiveGraphPlan({
        auditId: value.auditId,
        sourceNamespace: value.sourceNamespace,
        snapshotId: value.snapshotId,
        snapshotSha256: value.hashes.snapshotSha256,
        nodes: value.nodes,
        edges: value.edges,
        evidence: value.evidence,
        findings: value.findings,
        conflicts: value.conflicts,
        unresolvedTargetNodeIds: value.unresolvedTargetNodeIds,
        blockerCodes: value.blockerCodes,
        truncation: value.truncation,
        limits: value.limits,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic assurance graph hashes");
    }
    return expected;
}

export const __internals = Object.freeze({
    EDGE_BINDING_FIELDS,
    NODE_BINDING_FIELDS,
    canonicalJson,
    cloneFrozen,
    hashDomain,
});
