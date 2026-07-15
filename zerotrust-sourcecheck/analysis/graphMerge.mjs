import { createHash } from "node:crypto";

import {
    ANALYSIS_SCHEMA_VERSION,
    LIMITS,
    validateAuditId,
    validateCandidateFinding,
    validateGraphEdge,
    validateGraphNode,
} from "./schemas.mjs";

export const GRAPH_MERGE_LIMITS = Object.freeze({
    graphs: 16,
    nodes: LIMITS.graphNodes,
    edges: LIMITS.graphEdges,
    blockers: 128,
    conflicts: 256,
    unresolvedReferences: 256,
});

const FLOW_EDGE_KINDS = new Set([
    "activates",
    "triggers",
    "transforms",
    "reads-from",
    "writes-to",
    "invokes",
    "flows-to",
    "persists-as",
    "propagates-to",
    "enables",
]);

const EDGE_TRANSITIONS = Object.freeze({
    activates: {
        from: new Set(["activation", "trigger", "dependency", "provenance"]),
        to: new Set(["trigger", "transform", "capability"]),
    },
    triggers: {
        from: new Set(["activation", "trigger"]),
        to: new Set([
            "trigger",
            "transform",
            "capability",
            "sensitive-source",
            "sink",
            "persistence",
            "propagation",
        ]),
    },
    transforms: {
        from: new Set(["transform", "capability", "sensitive-source"]),
        to: new Set(["transform", "capability", "sink", "persistence", "propagation"]),
    },
    "reads-from": {
        from: new Set(["activation", "trigger", "transform", "capability"]),
        to: new Set(["sensitive-source", "dependency", "provenance"]),
    },
    "writes-to": {
        from: new Set(["transform", "capability"]),
        to: new Set(["sink", "persistence", "propagation"]),
    },
    invokes: {
        from: new Set(["activation", "trigger", "transform", "capability", "dependency"]),
        to: new Set([
            "transform",
            "capability",
            "sink",
            "persistence",
            "propagation",
            "dependency",
        ]),
    },
    "flows-to": {
        from: new Set([
            "activation",
            "trigger",
            "transform",
            "capability",
            "sensitive-source",
            "dependency",
        ]),
        to: new Set([
            "transform",
            "capability",
            "sensitive-source",
            "sink",
            "persistence",
            "propagation",
        ]),
    },
    "persists-as": {
        from: new Set(["transform", "capability"]),
        to: new Set(["persistence"]),
    },
    "propagates-to": {
        from: new Set(["transform", "capability", "sensitive-source"]),
        to: new Set(["propagation"]),
    },
    "provenance-of": {
        from: new Set(["provenance"]),
        to: null,
    },
    "depends-on": {
        from: null,
        to: new Set(["dependency", "provenance", "capability"]),
    },
    guards: {
        from: new Set(["activation", "trigger", "capability"]),
        to: null,
    },
    enables: {
        from: new Set([
            "activation",
            "trigger",
            "dependency",
            "provenance",
            "capability",
            "transform",
        ]),
        to: new Set(["transform", "capability", "sink", "persistence", "propagation"]),
    },
});

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function hash(prefix, value) {
    return createHash("sha256")
        .update(prefix, "utf8")
        .update("\0", "utf8")
        .update(canonicalJson(value), "utf8")
        .digest("hex");
}

function sameValue(left, right) {
    return canonicalJson(left) === canonicalJson(right);
}

function boundedLimit(value, fallback, maximum) {
    if (!Number.isSafeInteger(value) || value < 1) return fallback;
    return Math.min(value, maximum);
}

function normalizeLimits(value = {}) {
    return Object.freeze({
        graphs: boundedLimit(value.graphs, GRAPH_MERGE_LIMITS.graphs, GRAPH_MERGE_LIMITS.graphs),
        nodes: boundedLimit(value.nodes, GRAPH_MERGE_LIMITS.nodes, LIMITS.graphNodes),
        edges: boundedLimit(value.edges, GRAPH_MERGE_LIMITS.edges, LIMITS.graphEdges),
        blockers: boundedLimit(
            value.blockers,
            GRAPH_MERGE_LIMITS.blockers,
            GRAPH_MERGE_LIMITS.blockers,
        ),
        conflicts: boundedLimit(
            value.conflicts,
            GRAPH_MERGE_LIMITS.conflicts,
            GRAPH_MERGE_LIMITS.conflicts,
        ),
        unresolvedReferences: boundedLimit(
            value.unresolvedReferences,
            GRAPH_MERGE_LIMITS.unresolvedReferences,
            GRAPH_MERGE_LIMITS.unresolvedReferences,
        ),
    });
}

function evidenceSemantic(evidence) {
    return {
        path: evidence.path,
        startLine: evidence.startLine,
        endLine: evidence.endLine,
        blobSha: evidence.blobSha,
        excerptHash: evidence.excerptHash,
    };
}

function uniqueCanonical(values) {
    const entries = new Map();
    for (const value of values) entries.set(canonicalJson(value), value);
    return [...entries.values()].sort((left, right) =>
        canonicalJson(left).localeCompare(canonicalJson(right)));
}

function behaviorForKind(signature, kind) {
    if (!signature) return null;
    if (kind === "activation" || kind === "trigger") {
        return signature.trigger ? { trigger: signature.trigger } : null;
    }
    if (kind === "capability") {
        return {
            capability: signature.capability,
            ...(signature.mechanism ? { mechanism: signature.mechanism } : {}),
        };
    }
    if (kind === "transform") {
        return {
            action: signature.action,
            ...(signature.mechanism ? { mechanism: signature.mechanism } : {}),
            ...(signature.qualifiers ? { qualifiers: signature.qualifiers } : {}),
        };
    }
    if (kind === "persistence") {
        return {
            action: signature.action,
            target: signature.target,
            ...(signature.persistence ? { persistence: signature.persistence } : {}),
        };
    }
    if (kind === "propagation") {
        return {
            action: signature.action,
            target: signature.target,
            ...(signature.propagation ? { propagation: signature.propagation } : {}),
        };
    }
    return {
        action: signature.action,
        capability: signature.capability,
        target: signature.target,
    };
}

function expectedSourceType(sourceKind) {
    if (sourceKind === "local-source") return "local-file";
    if (sourceKind === "api-direct" || sourceKind === "build-clone") return "git-blob";
    return null;
}

function buildIndexCatalog(indexState, auditId) {
    if (!indexState || typeof indexState !== "object") {
        throw new TypeError("graph merge requires the active analysis index state");
    }
    if (indexState.auditId !== auditId) {
        throw new Error("analysis index auditId does not match graph merge auditId");
    }
    const files = new Map();
    for (const file of Array.isArray(indexState.files) ? indexState.files : []) {
        files.set(file.path, file);
    }
    const factsByPath = new Map();
    for (const fact of Array.isArray(indexState.facts) ? indexState.facts : []) {
        const list = factsByPath.get(fact.path) || [];
        list.push(fact);
        factsByPath.set(fact.path, list);
    }
    return {
        sourceKind: indexState.sourceKind,
        expectedType: expectedSourceType(indexState.sourceKind),
        files,
        factsByPath,
    };
}

function validateSourceIdentityAgainstCatalog(sourceIdentity, sourceNamespace, catalog) {
    if (sourceIdentity.namespace !== sourceNamespace) return "source-namespace-mismatch";
    if (catalog.expectedType && sourceIdentity.type !== catalog.expectedType) {
        return "source-type-mismatch";
    }
    const file = catalog.files.get(sourceIdentity.path);
    if (!file) return "source-path-not-indexed";
    if (file.status !== "indexed-text" && file.status !== "classified-binary") {
        return "source-path-incomplete";
    }
    if (sourceIdentity.contentSha256 !== file.contentSha256) {
        return "source-content-identity-mismatch";
    }
    const expectedBlob = catalog.sourceKind === "local-source"
        ? file.contentSha256
        : file.blobSha;
    if (expectedBlob) {
        if (sourceIdentity.blobSha !== expectedBlob) return "source-blob-identity-mismatch";
    } else if (Object.hasOwn(sourceIdentity, "blobSha")) {
        return "unexpected-source-blob-identity";
    }
    return null;
}

function validateEvidenceAgainstCatalog(evidence, catalog) {
    const file = catalog.files.get(evidence.path);
    if (!file) return "evidence-path-not-indexed";
    if (file.status !== "indexed-text" || file.classification !== "text") {
        return "evidence-source-not-indexed-text";
    }
    if (!Number.isSafeInteger(file.lineCount) || evidence.endLine > file.lineCount) {
        return "evidence-line-range-outside-index";
    }
    if (evidence.blobSha !== (file.blobSha || file.contentSha256)) {
        return "evidence-blob-identity-mismatch";
    }
    const facts = catalog.factsByPath.get(evidence.path) || [];
    const match = facts.some((fact) =>
        fact.line === evidence.startLine
        && fact.endLine === evidence.endLine
        && fact.excerptHash === evidence.excerptHash);
    return match ? null : "evidence-reference-not-indexed";
}

function graphDocument(raw) {
    const document = raw?.document || raw?.graph || raw;
    if (!isPlainObject(document)
        || !Array.isArray(document.nodes)
        || !Array.isArray(document.edges)) {
        throw new TypeError("graph input must contain nodes and edges arrays");
    }
    return document;
}

function graphDigest(document) {
    return hash("zerotrust-graph-input-v5", {
        schemaVersion: document.schemaVersion,
        auditId: document.auditId,
        nodes: [...document.nodes].sort((left, right) =>
            canonicalJson(left).localeCompare(canonicalJson(right))),
        edges: [...document.edges].sort((left, right) =>
            canonicalJson(left).localeCompare(canonicalJson(right))),
    });
}

function associationMaps(findings, auditId, catalog, sourceNamespace, issue) {
    const nodeAssociations = new Map();
    const edgeAssociations = new Map();
    const normalizedFindings = [];
    for (const rawFinding of Array.isArray(findings) ? findings : []) {
        let finding;
        try {
            finding = validateCandidateFinding(rawFinding);
        } catch {
            issue("invalid-finding-contract", { entryType: "finding" });
            continue;
        }
        if (finding.auditId !== auditId) {
            issue("finding-audit-id-mismatch", {
                entryType: "finding",
                entryId: finding.id,
            });
            continue;
        }
        const sourceError = validateSourceIdentityAgainstCatalog(
            finding.sourceIdentity,
            sourceNamespace,
            catalog,
        );
        if (sourceError) {
            issue(sourceError, { entryType: "finding", entryId: finding.id });
            continue;
        }
        const evidenceError = finding.evidence
            .map((evidence) => validateEvidenceAgainstCatalog(evidence, catalog))
            .find(Boolean);
        if (evidenceError) {
            issue(evidenceError, { entryType: "finding", entryId: finding.id });
            continue;
        }
        normalizedFindings.push(finding);
        for (const nodeId of finding.nodeIds) {
            const entries = nodeAssociations.get(nodeId) || [];
            entries.push(finding);
            nodeAssociations.set(nodeId, entries);
        }
        for (const edgeId of finding.edgeIds) {
            const entries = edgeAssociations.get(edgeId) || [];
            entries.push(finding);
            edgeAssociations.set(edgeId, entries);
        }
    }
    return { nodeAssociations, edgeAssociations, normalizedFindings };
}

function bindingForNode(node, associations) {
    const directSources = node.sourceIdentity ? [node.sourceIdentity] : [];
    const fallbackSources = associations.map((finding) => finding.sourceIdentity);
    const directEvidence = node.evidence || [];
    const fallbackEvidence = associations.flatMap((finding) => finding.evidence);
    const directBehaviors = node.behaviorSignature ? [node.behaviorSignature] : [];
    const fallbackBehaviors = associations
        .map((finding) => behaviorForKind(finding.behaviorSignature, node.kind))
        .filter(Boolean);
    return {
        sources: uniqueCanonical(directSources.length > 0 ? directSources : fallbackSources),
        evidence: uniqueCanonical(
            (directEvidence.length > 0 ? directEvidence : fallbackEvidence)
                .map(evidenceSemantic),
        ),
        behaviors: uniqueCanonical([...directBehaviors, ...fallbackBehaviors]),
        tags: [...(node.tags || [])].sort(),
    };
}

function bindingForEdge(edge, associations) {
    const directEvidence = edge.evidence || [];
    const fallbackEvidence = associations.flatMap((finding) => finding.evidence);
    return {
        evidence: uniqueCanonical(
            (directEvidence.length > 0 ? directEvidence : fallbackEvidence)
                .map(evidenceSemantic),
        ),
        tags: [...(edge.tags || [])].sort(),
    };
}

function nodeSemantic(node, binding) {
    return {
        kind: node.kind,
        sources: binding.sources,
        evidence: binding.evidence,
        behaviors: binding.behaviors,
        tags: binding.tags,
    };
}

function transitionCompatible(edge, fromNode, toNode) {
    const rule = EDGE_TRANSITIONS[edge.kind];
    if (!rule) return false;
    return (!rule.from || rule.from.has(fromNode.kind))
        && (!rule.to || rule.to.has(toNode.kind));
}

export function mergeBehaviorGraphs({
    auditId,
    sourceNamespace,
    indexState,
    graphs = [],
    findings = [],
    limits: limitOverrides = {},
} = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    if (typeof sourceNamespace !== "string" || sourceNamespace.length < 1
        || sourceNamespace.length > LIMITS.namespace) {
        throw new TypeError("graph merge requires a bounded active source namespace");
    }
    const limits = normalizeLimits(limitOverrides);
    const catalog = buildIndexCatalog(indexState, normalizedAuditId);
    const blockers = [];
    const conflicts = [];
    const unresolvedReferences = [];
    const blockedTransitions = [];
    const blockerKeys = new Set();
    let blockersTruncated = false;
    let conflictsTruncated = false;
    let unresolvedReferencesTruncated = false;
    let graphTruncated = false;
    let nodeTruncated = false;
    let edgeTruncated = false;
    let bindingTruncated = false;
    let identityMismatchCount = 0;

    const appendBlocker = (code, details = {}) => {
        const blocker = { code, ...details };
        const key = canonicalJson(blocker);
        if (blockerKeys.has(key)) return;
        blockerKeys.add(key);
        if (blockers.length >= limits.blockers) {
            blockersTruncated = true;
            return;
        }
        blockers.push(blocker);
    };
    const appendConflict = (reasonCode, details = {}) => {
        const semantic = { reasonCode, ...details };
        const conflict = {
            id: `ztv-v5-${hash("zerotrust-graph-conflict-v5", semantic)}`,
            ...semantic,
        };
        if (!conflicts.some((entry) => entry.id === conflict.id)) {
            if (conflicts.length >= limits.conflicts) {
                conflictsTruncated = true;
            } else {
                conflicts.push(conflict);
            }
        }
        appendBlocker("graph-conflict", {
            conflictId: conflict.id,
            reasonCode,
        });
        return conflict.id;
    };
    const appendUnresolved = (reasonCode, details = {}) => {
        const unresolved = { reasonCode, ...details };
        const key = canonicalJson(unresolved);
        if (!unresolvedReferences.some((entry) => canonicalJson(entry) === key)) {
            if (unresolvedReferences.length >= limits.unresolvedReferences) {
                unresolvedReferencesTruncated = true;
            } else {
                unresolvedReferences.push(unresolved);
            }
        }
        appendBlocker("unresolved-graph-reference", { reasonCode, ...details });
    };
    const identityIssue = (code, details = {}) => {
        identityMismatchCount += 1;
        appendBlocker("graph-identity-mismatch", { reasonCode: code, ...details });
    };

    const associations = associationMaps(
        findings,
        normalizedAuditId,
        catalog,
        sourceNamespace,
        identityIssue,
    );

    const uniqueGraphs = new Map();
    for (const rawGraph of Array.isArray(graphs) ? graphs : []) {
        let document;
        try {
            document = graphDocument(rawGraph);
        } catch {
            appendBlocker("invalid-graph-document");
            continue;
        }
        if (document.schemaVersion !== ANALYSIS_SCHEMA_VERSION
            || document.auditId !== normalizedAuditId) {
            identityIssue("graph-document-audit-mismatch");
            continue;
        }
        const digest = graphDigest(document);
        if (!uniqueGraphs.has(digest)) uniqueGraphs.set(digest, document);
    }
    const graphDocuments = [...uniqueGraphs.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([, document]) => document);
    if (graphDocuments.length > limits.graphs) {
        graphTruncated = true;
        appendBlocker("graph-cap-exceeded", { cap: limits.graphs });
        graphDocuments.length = limits.graphs;
    }

    const rawNodes = graphDocuments.flatMap((document) =>
        document.nodes.map((node) => ({ document, node })))
        .sort((left, right) =>
            String(left.node?.id || "").localeCompare(String(right.node?.id || ""))
            || canonicalJson(left.node).localeCompare(canonicalJson(right.node)));
    const nodesById = new Map();
    const rejectedNodeIds = new Set();

    for (const { document, node: rawNode } of rawNodes) {
        if (document.schemaVersion !== ANALYSIS_SCHEMA_VERSION
            || document.auditId !== normalizedAuditId) {
            identityIssue("graph-document-audit-mismatch");
            continue;
        }
        let node;
        try {
            node = validateGraphNode(rawNode);
        } catch {
            appendBlocker("invalid-graph-node-contract", {
                entryId: typeof rawNode?.id === "string" ? rawNode.id : undefined,
            });
            continue;
        }
        if (node.auditId !== normalizedAuditId) {
            identityIssue("graph-node-audit-mismatch", { entryId: node.id });
            rejectedNodeIds.add(node.id);
            nodesById.delete(node.id);
            continue;
        }
        const existing = nodesById.get(node.id);
        if (existing) {
            if (sameValue(existing.node, node)) continue;
            const conflictId = appendConflict("node-id-conflict", {
                nodeIds: [node.id],
            });
            blockedTransitions.push({
                conflictId,
                reasonCode: "node-id-conflict",
                nodeIds: [node.id],
                edgeIds: [],
            });
            rejectedNodeIds.add(node.id);
            nodesById.delete(node.id);
            continue;
        }
        if (rejectedNodeIds.has(node.id)) continue;
        const nodeAssociations = associations.nodeAssociations.get(node.id) || [];
        const sourceError = (node.sourceIdentity ? [node.sourceIdentity] : [])
            .map((source) =>
                validateSourceIdentityAgainstCatalog(source, sourceNamespace, catalog))
            .find(Boolean);
        const evidenceError = node.evidence
            .map((evidence) => validateEvidenceAgainstCatalog(evidence, catalog))
            .find(Boolean);
        if (sourceError || evidenceError) {
            identityIssue(sourceError || evidenceError, {
                entryType: "node",
                entryId: node.id,
            });
            rejectedNodeIds.add(node.id);
            continue;
        }
        const rawBinding = bindingForNode(node, nodeAssociations);
        if (rawBinding.sources.length > 64
            || rawBinding.evidence.length > LIMITS.evidencePerItem
            || rawBinding.behaviors.length > 64) {
            bindingTruncated = true;
            appendBlocker("graph-binding-cap-exceeded", { entryId: node.id });
        }
        const binding = {
            sources: rawBinding.sources.slice(0, 64),
            evidence: rawBinding.evidence.slice(0, LIMITS.evidencePerItem),
            behaviors: rawBinding.behaviors.slice(0, 64),
            tags: rawBinding.tags,
        };
        if (binding.sources.length === 0 && binding.evidence.length === 0) {
            identityIssue("unbound-graph-node", { entryType: "node", entryId: node.id });
            rejectedNodeIds.add(node.id);
            continue;
        }
        if (nodesById.size >= limits.nodes) {
            nodeTruncated = true;
            appendBlocker("graph-node-cap-exceeded", { cap: limits.nodes });
            rejectedNodeIds.add(node.id);
            continue;
        }
        const semantic = nodeSemantic(node, binding);
        nodesById.set(node.id, {
            node,
            binding,
            semantic,
            semanticKey: hash("zerotrust-graph-node-semantic-v5", semantic),
        });
    }

    const rawEdges = graphDocuments.flatMap((document) =>
        document.edges.map((edge) => ({ document, edge })))
        .sort((left, right) =>
            String(left.edge?.id || "").localeCompare(String(right.edge?.id || ""))
            || canonicalJson(left.edge).localeCompare(canonicalJson(right.edge)));
    const edgesById = new Map();
    const rejectedEdgeIds = new Set();

    for (const { document, edge: rawEdge } of rawEdges) {
        if (document.schemaVersion !== ANALYSIS_SCHEMA_VERSION
            || document.auditId !== normalizedAuditId) {
            identityIssue("graph-document-audit-mismatch");
            continue;
        }
        let edge;
        try {
            edge = validateGraphEdge(rawEdge);
        } catch {
            appendBlocker("invalid-graph-edge-contract", {
                entryId: typeof rawEdge?.id === "string" ? rawEdge.id : undefined,
            });
            continue;
        }
        if (edge.auditId !== normalizedAuditId) {
            identityIssue("graph-edge-audit-mismatch", { entryId: edge.id });
            rejectedEdgeIds.add(edge.id);
            edgesById.delete(edge.id);
            continue;
        }
        const existing = edgesById.get(edge.id);
        if (existing) {
            if (sameValue(existing.edge, edge)) continue;
            const conflictId = appendConflict("edge-id-conflict", {
                edgeIds: [edge.id],
            });
            blockedTransitions.push({
                conflictId,
                reasonCode: "edge-id-conflict",
                nodeIds: [edge.from, edge.to],
                edgeIds: [edge.id],
            });
            rejectedEdgeIds.add(edge.id);
            edgesById.delete(edge.id);
            continue;
        }
        if (rejectedEdgeIds.has(edge.id)) continue;
        const fromRecord = nodesById.get(edge.from);
        const toRecord = nodesById.get(edge.to);
        if (!fromRecord || !toRecord) {
            appendUnresolved("edge-references-unresolved-node", {
                edgeId: edge.id,
                from: edge.from,
                to: edge.to,
            });
            blockedTransitions.push({
                conflictId: null,
                reasonCode: "edge-references-unresolved-node",
                nodeIds: [edge.from, edge.to],
                edgeIds: [edge.id],
                ...(fromRecord ? { fromSemantic: fromRecord.semanticKey } : {}),
            });
            continue;
        }
        const evidenceError = edge.evidence
            .map((evidence) => validateEvidenceAgainstCatalog(evidence, catalog))
            .find(Boolean);
        if (evidenceError) {
            identityIssue(evidenceError, {
                entryType: "edge",
                entryId: edge.id,
            });
            continue;
        }
        if (!transitionCompatible(edge, fromRecord.node, toRecord.node)) {
            const conflictId = appendConflict("incompatible-edge-transition", {
                nodeIds: [edge.from, edge.to],
                edgeIds: [edge.id],
                edgeKind: edge.kind,
                fromKind: fromRecord.node.kind,
                toKind: toRecord.node.kind,
            });
            blockedTransitions.push({
                conflictId,
                reasonCode: "incompatible-edge-transition",
                nodeIds: [edge.from, edge.to],
                edgeIds: [edge.id],
                fromSemantic: fromRecord.semanticKey,
                toSemantic: toRecord.semanticKey,
            });
            continue;
        }
        const edgeAssociations = associations.edgeAssociations.get(edge.id) || [];
        const rawBinding = bindingForEdge(edge, edgeAssociations);
        if (rawBinding.evidence.length > LIMITS.evidencePerItem) {
            bindingTruncated = true;
            appendBlocker("graph-binding-cap-exceeded", { entryId: edge.id });
        }
        const binding = {
            evidence: rawBinding.evidence.slice(0, LIMITS.evidencePerItem),
            tags: rawBinding.tags,
        };
        if (binding.evidence.length === 0) {
            identityIssue("unbound-graph-edge", {
                entryType: "edge",
                entryId: edge.id,
            });
            continue;
        }
        if (edgesById.size >= limits.edges) {
            edgeTruncated = true;
            appendBlocker("graph-edge-cap-exceeded", { cap: limits.edges });
            continue;
        }
        const semantic = {
            kind: edge.kind,
            from: fromRecord.semanticKey,
            to: toRecord.semanticKey,
            evidence: binding.evidence,
            tags: binding.tags,
        };
        edgesById.set(edge.id, {
            edge,
            binding,
            semantic,
            semanticKey: hash("zerotrust-graph-edge-semantic-v5", semantic),
            fromSemantic: fromRecord.semanticKey,
            toSemantic: toRecord.semanticKey,
        });
    }

    const directional = new Map();
    for (const record of edgesById.values()) {
        if (!FLOW_EDGE_KINDS.has(record.edge.kind)) continue;
        const forward = `${record.fromSemantic}\0${record.toSemantic}\0${record.edge.kind}`;
        const reverse = `${record.toSemantic}\0${record.fromSemantic}\0${record.edge.kind}`;
        if (directional.has(reverse) && record.fromSemantic !== record.toSemantic) {
            const other = directional.get(reverse);
            const conflictId = appendConflict("contradictory-edge-direction", {
                nodeIds: [...new Set([
                    record.edge.from,
                    record.edge.to,
                    other.edge.from,
                    other.edge.to,
                ])].sort(),
                edgeIds: [record.edge.id, other.edge.id].sort(),
                edgeKind: record.edge.kind,
            });
            blockedTransitions.push({
                conflictId,
                reasonCode: "contradictory-edge-direction",
                nodeIds: [record.edge.from, record.edge.to],
                edgeIds: [record.edge.id, other.edge.id].sort(),
                fromSemantic: record.fromSemantic,
                toSemantic: record.toSemantic,
            });
            edgesById.delete(record.edge.id);
            edgesById.delete(other.edge.id);
        } else {
            directional.set(forward, record);
        }
    }

    const nodeRecords = [...nodesById.values()]
        .sort((left, right) => left.semanticKey.localeCompare(right.semanticKey)
            || left.node.id.localeCompare(right.node.id));
    const edgeRecords = [...edgesById.values()]
        .sort((left, right) => left.semanticKey.localeCompare(right.semanticKey)
            || left.edge.id.localeCompare(right.edge.id));
    const indexIdentity = {
        sourceKind: catalog.sourceKind,
        files: [...catalog.files.values()].map((file) => ({
            path: file.path,
            status: file.status,
            blobSha: file.blobSha,
            contentSha256: file.contentSha256,
        })).sort((left, right) => left.path.localeCompare(right.path)),
    };
    const inputFingerprint = hash("zerotrust-graph-merge-input-v5", {
        auditId: normalizedAuditId,
        sourceNamespace,
        graphs: [...uniqueGraphs.keys()].sort(),
        findings: associations.normalizedFindings
            .map((finding) => canonicalJson(finding))
            .sort(),
        indexIdentity,
    });
    const truncation = {
        graphs: graphTruncated,
        nodes: nodeTruncated,
        edges: edgeTruncated,
        bindings: bindingTruncated,
        blockers: blockersTruncated,
        conflicts: conflictsTruncated,
        unresolvedReferences: unresolvedReferencesTruncated,
    };
    const coverageComplete = !Object.values(truncation).some(Boolean)
        && conflicts.length === 0
        && unresolvedReferences.length === 0
        && identityMismatchCount === 0;

    return Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        auditId: normalizedAuditId,
        sourceNamespace,
        inputFingerprint,
        coverageComplete,
        counts: Object.freeze({
            inputGraphs: Array.isArray(graphs) ? graphs.length : 0,
            uniqueGraphs: uniqueGraphs.size,
            mergedGraphs: graphDocuments.length,
            nodes: nodeRecords.length,
            edges: edgeRecords.length,
            conflicts: conflicts.length,
            unresolvedReferences: unresolvedReferences.length,
            identityMismatches: identityMismatchCount,
        }),
        truncation: Object.freeze(truncation),
        blockers: Object.freeze(structuredClone(blockers)),
        conflicts: Object.freeze(structuredClone(conflicts)),
        unresolvedReferences: Object.freeze(structuredClone(unresolvedReferences)),
        blockedTransitions: Object.freeze(structuredClone(blockedTransitions)),
        nodeRecords: Object.freeze(nodeRecords),
        edgeRecords: Object.freeze(edgeRecords),
    });
}

export const __internals = Object.freeze({
    canonicalJson,
    hash,
    normalizeLimits,
    evidenceSemantic,
    behaviorForKind,
    transitionCompatible,
    validateSourceIdentityAgainstCatalog,
    validateEvidenceAgainstCatalog,
});
