import { createHash } from "node:crypto";
import nodePath from "node:path";

import {
    EVASIVE_BLOCKERS,
    validateAssuranceAnalysisSnapshot,
} from "./evasiveSchemas.mjs";
import {
    evaluateSemanticCoverage,
    validateSemanticCoveragePlan,
} from "./semanticCoverage.mjs";
import {
    evaluateRedTeamCoverage,
    validateRedTeamPlan,
} from "./redTeam.mjs";
import { validateSupplyChainGraph } from "./supplyChainGraph.mjs";
import {
    EVASIVE_GRAPH_EDGE_KINDS,
    EVASIVE_GRAPH_LIMITS,
    createEvasiveGraphConflict,
    createEvasiveGraphEdge,
    createEvasiveGraphEvidenceRecord,
    createEvasiveGraphFinding,
    createEvasiveGraphNode,
    createEvasiveGraphPlan,
    normalizeEvasiveGraphLimits,
    validateEvasiveGraphEdge,
    validateEvasiveGraphNode,
} from "./evasiveGraphSchemas.mjs";

const STATUS_RANK = Object.freeze({
    supported: 0,
    unresolved: 1,
    unsupported: 2,
});

const FACT_NODE_KIND = Object.freeze({
    activation: "activation",
    import: "capability",
    "dynamic-import": "capability",
    reflection: "capability",
    "dynamic-evaluation": "capability",
    "command-construction": "transform",
    source: "source",
    transform: "transform",
    sink: "sink",
    persistence: "persistence",
    "generated-code-hook": "trigger",
    "environment-gate": "gate",
    "platform-gate": "gate",
    "time-gate": "gate",
    "unresolved-dynamic-target": "dynamic-target",
});

const NON_FLOW_EDGE_KINDS = new Set([
    "evidence-binding",
    "provenance-binding",
]);

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

function unique(values) {
    if (typeof values === "string"
        || values === null
        || values === undefined
        || typeof values[Symbol.iterator] !== "function") {
        throw new TypeError("assurance graph unique values must be iterable");
    }
    return [...new Set([...values].filter(Boolean))].sort();
}

function sameValue(left, right) {
    return canonicalJson(left) === canonicalJson(right);
}

function emptyNodeBindings() {
    return {
        objectIds: [],
        artifactIds: [],
        factIds: [],
        evidenceIds: [],
        supplyChainNodeIds: [],
        semanticReviewIds: [],
        candidateIds: [],
        redTeamGraphNodeIds: [],
    };
}

function emptyEdgeBindings() {
    return {
        artifactIds: [],
        factIds: [],
        evidenceIds: [],
        supplyChainEdgeIds: [],
        candidateIds: [],
        redTeamGraphEdgeIds: [],
    };
}

function mergeBindings(left, right) {
    return Object.fromEntries(Object.keys(left).map((key) => [
        key,
        unique([...(left[key] || []), ...(right[key] || [])]),
    ]));
}

function mergeStatus(left, right) {
    return STATUS_RANK[left] >= STATUS_RANK[right] ? left: right;
}

function createGeneratedEvidence({
    evidenceKind,
    objectId = null,
    artifactId = null,
    factId = null,
    supplyChainNodeId = null,
    path,
    startLine = 0,
    endLine = 0,
    excerptHash = null,
    contentSha256,
}) {
    const descriptor = {
        evidenceKind,
        objectId,
        artifactId,
        factId,
        supplyChainNodeId,
        path,
        startLine,
        endLine,
        excerptHash,
        contentSha256,
    };
    return createEvasiveGraphEvidenceRecord({
        evidenceId: `ztve-${hashDomain("zerotrust-graph-evidence", descriptor)}`,
        ...descriptor,
    });
}

function collectRedTeamEvidence(redTeamPlan) {
    const byId = new Map();
    for (const category of redTeamPlan.categoryPlans) {
        for (const evidence of category.view.evidence || []) {
            const normalized = createEvasiveGraphEvidenceRecord({
                evidenceId: evidence.evidenceId,
                evidenceKind: evidence.evidenceKind,
                objectId: evidence.objectId,
                artifactId: evidence.artifactId,
                factId: evidence.factId,
                supplyChainNodeId: null,
                path: evidence.path,
                startLine: evidence.startLine,
                endLine: evidence.endLine,
                excerptHash: evidence.excerptHash,
                contentSha256: evidence.contentSha256,
            });
            const existing = byId.get(normalized.evidenceId);
            if (existing && !sameValue(existing, normalized)) {
                throw new Error(`red-team evidence identity conflict: ${normalized.evidenceId}`);
            }
            byId.set(normalized.evidenceId, normalized);
        }
    }
    return byId;
}

function collectSemanticEvidence(assignments, byId) {
    for (const assignment of assignments) {
        for (const evidence of assignment.semanticView.evidence || []) {
            const normalized = createEvasiveGraphEvidenceRecord({
                evidenceId: evidence.evidenceId,
                evidenceKind: evidence.evidenceKind,
                objectId: evidence.objectId,
                artifactId: evidence.artifactId,
                factId: evidence.factId,
                supplyChainNodeId: null,
                path: evidence.path,
                startLine: evidence.startLine,
                endLine: evidence.endLine,
                excerptHash: evidence.excerptHash,
                contentSha256: evidence.contentSha256,
            });
            const existing = byId.get(normalized.evidenceId);
            if (existing && !sameValue(existing, normalized)) {
                throw new Error(
                    `semantic evidence identity conflict: ${normalized.evidenceId}`,
                );
            }
            byId.set(normalized.evidenceId, normalized);
        }
    }
    return byId;
}

function factCorpus(scannerRecords, snapshot, evidenceById) {
    const objectById = new Map(
        snapshot.objectInventory.map((object) => [object.objectId, object]),
    );
    const artifactById = new Map(
        snapshot.derivedArtifacts.map((artifact) => [artifact.artifactId, artifact]),
    );
    const facts = new Map();
    for (const record of scannerRecords) {
        const object = objectById.get(record.objectId);
        if (!object) throw new Error("semantic scanner record references an unknown object");
        const artifact = record.artifactId === null
            ? null: artifactById.get(record.artifactId);
        if (record.artifactId !== null
            && (!artifact || artifact.sourceObjectId !== object.objectId)) {
            throw new Error("semantic scanner record references an unknown artifact");
        }
        const contentSha256 = artifact?.hashes.contentSha256
            || object.hashes.contentSha256
            || object.hashes.identitySha256;
        for (const fact of record.facts) {
            const normalized = cloneFrozen({
                ...fact,
                objectId: object.objectId,
                artifactId: artifact?.artifactId || null,
                scannerRecordId: record.scannerRecordId,
            });
            const existing = facts.get(fact.id);
            if (existing && !sameValue(existing, normalized)) {
                throw new Error(`semantic fact identity conflict: ${fact.id}`);
            }
            facts.set(fact.id, normalized);
            const existingEvidence = [...evidenceById.values()].find((entry) =>
                entry.factId === fact.id
                && entry.objectId === object.objectId
                && entry.artifactId === (artifact?.artifactId || null));
            if (!existingEvidence) {
                const evidence = createGeneratedEvidence({
                    evidenceKind: "fact",
                    objectId: object.objectId,
                    artifactId: artifact?.artifactId || null,
                    factId: fact.id,
                    path: fact.path,
                    startLine: fact.line,
                    endLine: fact.endLine,
                    excerptHash: fact.excerptHash,
                    contentSha256,
                });
                evidenceById.set(evidence.evidenceId, evidence);
            }
        }
    }
    return [...facts.values()].sort((left, right) => left.id.localeCompare(right.id));
}

function validateInputs({
    snapshot,
    redTeamBaseSnapshot,
    semanticBaseSnapshot,
    semanticPlan,
    semanticEvaluation,
    semanticScannerRecords,
    semanticReviewAssignments,
    semanticReviewRecords,
    redTeamPlan,
    redTeamAssignments,
    redTeamReviewRecords,
    redTeamEvaluation,
    supplyChainGraph,
}) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    if (current.stageState.current !== "red-teamed") {
        throw new Error("assurance graph preparation requires a red-teamed snapshot");
    }
    const semanticBase = validateAssuranceAnalysisSnapshot(semanticBaseSnapshot);
    const canonicalSemanticPlan = validateSemanticCoveragePlan(
        semanticPlan,
        semanticBase,
    );
    const canonicalSemanticEvaluation = evaluateSemanticCoverage({
        snapshot: semanticBase,
        plan: canonicalSemanticPlan,
        scannerRecords: semanticScannerRecords,
        reviewAssignments: semanticReviewAssignments,
        reviewRecords: semanticReviewRecords,
    });
    if (!sameValue(canonicalSemanticEvaluation, semanticEvaluation)
        || !canonicalSemanticEvaluation.complete) {
        throw new Error("assurance graph preparation requires canonical completed semantic coverage");
    }
    const redBase = validateAssuranceAnalysisSnapshot(redTeamBaseSnapshot);
    if (!sameValue(
        redBase.semanticCandidateLedger,
        canonicalSemanticEvaluation.candidateLedger,
    )) {
        throw new Error("red-team snapshot semantic candidate ledger is not canonical");
    }
    const redInputs = {
        snapshot: redBase,
        semanticBaseSnapshot: semanticBase,
        semanticPlan: canonicalSemanticPlan,
        semanticEvaluation: canonicalSemanticEvaluation,
        semanticScannerRecords,
        semanticReviewAssignments,
        semanticReviewRecords,
        supplyChainGraph,
    };
    const canonicalRedPlan = validateRedTeamPlan(redTeamPlan, redInputs);
    const canonicalRedEvaluation = evaluateRedTeamCoverage({
        plan: canonicalRedPlan,
        planInputs: redInputs,
        assignments: redTeamAssignments,
        reviewRecords: redTeamReviewRecords,
    });
    if (!sameValue(canonicalRedEvaluation, redTeamEvaluation)
        || !canonicalRedEvaluation.complete) {
        throw new Error("assurance graph preparation requires canonical completed red-team coverage");
    }
    if (current.auditId !== redBase.auditId
        || current.sourceNamespace !== redBase.sourceNamespace
        || current.hashes.inventorySha256 !== redBase.hashes.inventorySha256
        || current.hashes.derivedArtifactsSha256 !== redBase.hashes.derivedArtifactsSha256
        || current.hashes.semanticCoverageSha256 !== redBase.hashes.semanticCoverageSha256
        || current.hashes.semanticCandidatesSha256
           !== redBase.hashes.semanticCandidatesSha256
        || current.hashes.redTeamCoverageSha256
            !== hashDomain(
                "zerotrust-red-team-coverage-snapshot",
                canonicalRedEvaluation.coverageRecords,
            )) {
        throw new Error("red-teamed snapshot does not match completed discovery identities");
    }
    const supplyChain = supplyChainGraph === null || supplyChainGraph === undefined
        ? null: validateSupplyChainGraph(supplyChainGraph);
    if (supplyChain
        && (supplyChain.auditId !== current.auditId
            || supplyChain.sourceNamespace !== current.sourceNamespace)) {
        throw new Error("supply-chain graph does not match the assurance graph identity");
    }
    return {
        current,
        semanticPlan: canonicalSemanticPlan,
        semanticEvaluation: canonicalSemanticEvaluation,
        redTeamPlan: canonicalRedPlan,
        redTeamEvaluation: canonicalRedEvaluation,
        supplyChain,
    };
}

function objectNodeKind(object, binaryMetadataObjects) {
    if (object.gitMode === "160000" || object.objectKind === "gitlink") return "submodule";
    if (object.lfsPointer !== null) return "lfs";
    if (object.objectKind === "release-asset") return "release-asset";
    if (object.objectKind === "archive-entry"
        || object.objectKind === "embedded-payload") return "archive-member";
    if (object.objectKind === "generated-source") return "generated-artifact";
    if (["binary", "opaque", "executable-blob"].includes(object.objectKind)) {
        return binaryMetadataObjects.has(object.objectId)
            ? "binary-metadata": "unsupported-target";
    }
    if (object.status !== "inventoried" || object.objectKind === "reparse-point") {
        return "unsupported-target";
    }
    return "source";
}

function artifactNodeKind(artifact) {
    if (artifact.artifactKind === "binary-metadata") return "binary-metadata";
    if (artifact.artifactKind === "archive-manifest") return "archive-member";
    if (artifact.artifactKind === "release-comparison") return "release-asset";
    if (artifact.artifactKind === "dependency-graph") return "package";
    return "generated-artifact";
}

function factStatus(fact) {
    return fact.kind === "unresolved-dynamic-target"
        || fact.resolution === "dynamic"
        ? "unresolved": "supported";
}

function edgeKindForFacts(fromFact, toFact) {
    if (toFact.kind === "import") return "imports";
    if (toFact.kind === "dynamic-import") return "loads";
    if (toFact.kind === "source") return "reads";
    if (toFact.kind === "transform") {
        return /(?:decode|base64|hex|decompress|inflate|gzip|brotli)/iu.test(
            `${toFact.name} ${toFact.value || ""} ${toFact.target || ""}`,
        ) ? "decodes": "calls";
    }
    if (toFact.kind === "sink") {
        const tokens = `${toFact.name} ${toFact.value || ""} ${toFact.target || ""}`;
        if (/(?:exec|spawn|shell|eval|process|command)/iu.test(tokens)) return "executes";
        if (/(?:upload|send|publish|webhook|http|network)/iu.test(tokens)) {
            return "publishes";
        }
        return "writes";
    }
    if (toFact.kind === "persistence") return "writes";
    if (toFact.kind === "generated-code-hook") return "generates";
    if (["environment-gate", "platform-gate", "time-gate"].includes(toFact.kind)) {
        return "selects";
    }
    if (toFact.kind === "unresolved-dynamic-target") return "calls";
    if (fromFact.kind === "source") return "reads";
    return "calls";
}

function supplyNodeKind(node) {
    if (node.nodeKind === "package") return "package";
    if (node.nodeKind === "artifact") return "generated-artifact";
    return "source";
}

function supplyEdgeKind(edge) {
    const mapping = {
        "depends-on": "depends-on",
        "declared-in": "provenance-binding",
        "resolved-to": "packages",
        "fetched-from": "downloads",
        "verified-by": "provenance-binding",
        contains: "packages",
    };
    return mapping[edge.kind] || "depends-on";
}

function redEdgeKind(edge) {
    const mapping = {
        "derived-from": "generates",
        "observed-on": "evidence-binding",
        precedes: "calls",
        "cross-object-reference": "calls",
        reviewed: "evidence-binding",
    };
    return mapping[edge.kind] || "calls";
}

function candidateEffectEdge(candidate) {
    const tokens = `${candidate.behavior.action} ${candidate.behavior.target}`;
    if (/(?:exec|spawn|shell|eval|process|command)/iu.test(tokens)) return "executes";
    if (/(?:publish|upload|send|webhook|network|external)/iu.test(tokens)) {
        return "publishes";
    }
    return "writes";
}

function targetTokens(fact) {
    return unique([fact.target, fact.value, fact.name]
        .filter((entry) => typeof entry === "string")
        .flatMap((entry) => {
            const normalized = entry.replace(/\\/gu, "/").toLowerCase();
            const basename = nodePath.posix.basename(normalized);
            const stem = basename.replace(/\.[^.]+$/u, "");
            return [normalized, basename, stem];
        }));
}

function objectTargetTokens(object) {
    const path = object.path.toLowerCase();
    const basename = nodePath.posix.basename(path);
    return unique([path, basename, basename.replace(/\.[^.]+$/u, "")]);
}

function addBindingWithinCap(state, bindings) {
    for (const values of Object.values(bindings)) {
        if (values.length > state.limits.bindingsPerRecord) {
            state.truncation.bindings = true;
            state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
            return false;
        }
    }
    return true;
}

function normalizeNodeRecord(value, path, limits) {
    return value?.nodeId
        ? validateEvasiveGraphNode(value, path, limits): createEvasiveGraphNode(value, path, limits);
}

function normalizeEdgeRecord(value, path, limits) {
    return value?.edgeId
        ? validateEvasiveGraphEdge(value, path, limits): createEvasiveGraphEdge(value, path, limits);
}

function addNode(state, input) {
    const candidate = normalizeNodeRecord(input, "evasiveGraphNode", state.limits);
    const existing = state.nodes.get(candidate.nodeId);
    if (existing) {
        const bindings = mergeBindings(existing.bindings, candidate.bindings);
        addBindingWithinCap(state, bindings);
        const merged = createEvasiveGraphNode({
            kind: existing.kind,
            identityKind: existing.identityKind,
            identity: existing.identity,
            status: mergeStatus(existing.status, candidate.status),
            bindings: Object.fromEntries(Object.entries(bindings).map(([key, value]) => [
                key,
                value.slice(0, state.limits.bindingsPerRecord),
            ])),
        }, "evasiveGraphNode", state.limits);
        state.nodes.set(merged.nodeId, merged);
        return merged;
    }
    if (state.nodes.size >= state.limits.nodes) {
        state.truncation.nodes = true;
        state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
        return null;
    }
    state.nodes.set(candidate.nodeId, candidate);
    return candidate;
}

function addEvidence(state, evidence) {
    const normalized = createEvasiveGraphEvidenceRecord(evidence);
    const existing = state.evidence.get(normalized.evidenceId);
    if (existing) {
        if (!sameValue(existing, normalized)) {
            throw new Error(`assurance graph evidence conflict: ${normalized.evidenceId}`);
        }
        return existing;
    }
    if (state.evidence.size >= state.limits.evidence) {
        state.truncation.evidence = true;
        state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
        return null;
    }
    state.evidence.set(normalized.evidenceId, normalized);
    return normalized;
}

function proposeEdge(state, input) {
    if (!input.fromNodeId || !input.toNodeId) {
        state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_MISSING_TARGET);
        return null;
    }
    if (!EVASIVE_GRAPH_EDGE_KINDS.includes(input.kind)) {
        throw new Error(`unsupported assurance graph edge kind: ${input.kind}`);
    }
    const edge = normalizeEdgeRecord(input.edgeId
        ? input: {
            kind: input.kind,
            fromNodeId: input.fromNodeId,
            toNodeId: input.toNodeId,
            bindings: input.bindings || emptyEdgeBindings(),
        }, "evasiveGraphEdge", state.limits);
    state.proposedEdges.push(edge);
    return edge;
}

export function mergeEvasiveGraphRecords({
    auditId,
    sourceNamespace,
    snapshotId,
    snapshotSha256,
    nodes = [],
    proposedEdges = [],
    evidence = [],
    findingDescriptors = [],
    blockerCodes = [],
    unresolvedTargetNodeIds = [],
    truncation = {},
    limits: limitOverrides = {},
} = {}) {
    const limits = normalizeEvasiveGraphLimits(limitOverrides);
    const nodeMap = new Map();
    const evidenceMap = new Map();
    const activeBlockers = new Set(blockerCodes);
    const activeTruncation = {
        nodes: truncation.nodes === true,
        edges: truncation.edges === true,
        evidence: truncation.evidence === true,
        findings: truncation.findings === true,
        conflicts: truncation.conflicts === true,
        bindings: truncation.bindings === true,
    };
    for (const node of nodes) {
        const normalized = normalizeNodeRecord(node, "evasiveGraphNode", limits);
        const existing = nodeMap.get(normalized.nodeId);
        if (existing) {
            const bindings = mergeBindings(existing.bindings, normalized.bindings);
            if (Object.values(bindings).some((values) =>
                values.length > limits.bindingsPerRecord)) {
                activeTruncation.bindings = true;
                activeBlockers.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
            }
            nodeMap.set(normalized.nodeId, createEvasiveGraphNode({
                kind: normalized.kind,
                identityKind: normalized.identityKind,
                identity: normalized.identity,
                status: mergeStatus(existing.status, normalized.status),
                bindings: Object.fromEntries(Object.entries(bindings).map(([key, value]) => [
                    key,
                    value.slice(0, limits.bindingsPerRecord),
                ])),
            }, "evasiveGraphNode", limits));
        } else if (nodeMap.size < limits.nodes) {
            nodeMap.set(normalized.nodeId, normalized);
        } else {
            activeTruncation.nodes = true;
            activeBlockers.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
        }
    }
    for (const entry of evidence) {
        const normalized = createEvasiveGraphEvidenceRecord(entry);
        const existing = evidenceMap.get(normalized.evidenceId);
        if (existing && !sameValue(existing, normalized)) {
            throw new Error(`assurance graph evidence conflict: ${normalized.evidenceId}`);
        }
        if (!existing && evidenceMap.size >= limits.evidence) {
            activeTruncation.evidence = true;
            activeBlockers.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
            continue;
        }
        evidenceMap.set(normalized.evidenceId, normalized);
    }

    const edgeRecords = proposedEdges.map((edge) =>
        normalizeEdgeRecord(edge, "evasiveGraphEdge", limits));
    const buckets = new Map();
    const unresolvedTargets = new Set(unresolvedTargetNodeIds);
    for (const edge of edgeRecords) {
        if (!nodeMap.has(edge.fromNodeId) || !nodeMap.has(edge.toNodeId)) {
            activeBlockers.add(EVASIVE_BLOCKERS.TRACE_MISSING_TARGET);
            if (!nodeMap.has(edge.fromNodeId)) unresolvedTargets.add(edge.fromNodeId);
            if (!nodeMap.has(edge.toNodeId)) unresolvedTargets.add(edge.toNodeId);
            continue;
        }
        const endpoints = [edge.fromNodeId, edge.toNodeId].sort();
        const bucketKey = `${endpoints[0]}\0${endpoints[1]}\0${edge.kind}`;
        if (!buckets.has(bucketKey)) {
            buckets.set(bucketKey, {
                edgeKind: edge.kind,
                endpointNodeIds: endpoints,
                records: [],
            });
        }
        buckets.get(bucketKey).records.push(edge);
    }

    const activeEdges = [];
    const conflicts = [];
    for (const bucket of [...buckets.values()].sort((left, right) =>
        canonicalJson(left.endpointNodeIds).localeCompare(
            canonicalJson(right.endpointNodeIds),
        ) || left.edgeKind.localeCompare(right.edgeKind))) {
        const directions = new Set(bucket.records.map((edge) =>
            `${edge.fromNodeId}\0${edge.toNodeId}`));
        if (directions.size > 1 && bucket.endpointNodeIds[0] !== bucket.endpointNodeIds[1]) {
            activeBlockers.add(EVASIVE_BLOCKERS.TRACE_CONFLICT);
            if (conflicts.length >= limits.conflicts) {
                activeTruncation.conflicts = true;
                activeBlockers.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
                continue;
            }
            conflicts.push(createEvasiveGraphConflict({
                edgeKind: bucket.edgeKind,
                endpointNodeIds: bucket.endpointNodeIds,
                records: bucket.records.slice(0, limits.conflictRecords),
            }, "evasiveGraphConflict", limits));
            if (bucket.records.length > limits.conflictRecords) {
                activeTruncation.conflicts = true;
                activeBlockers.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
            }
            continue;
        }
        const byDirection = new Map();
        for (const edge of bucket.records) {
            const key = `${edge.fromNodeId}\0${edge.toNodeId}\0${edge.kind}`;
            const existing = byDirection.get(key);
            if (!existing) {
                byDirection.set(key, edge);
                continue;
            }
            const bindings = mergeBindings(existing.bindings, edge.bindings);
            if (Object.values(bindings).some((values) =>
                values.length > limits.bindingsPerRecord)) {
                activeTruncation.bindings = true;
                activeBlockers.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
            }
            byDirection.set(key, createEvasiveGraphEdge({
                kind: edge.kind,
                fromNodeId: edge.fromNodeId,
                toNodeId: edge.toNodeId,
                bindings: Object.fromEntries(Object.entries(bindings).map(([name, values]) => [
                    name,
                    values.slice(0, limits.bindingsPerRecord),
                ])),
            }, "evasiveGraphEdge", limits));
        }
        for (const edge of byDirection.values()) {
            if (activeEdges.length >= limits.edges) {
                activeTruncation.edges = true;
                activeBlockers.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
                break;
            }
            activeEdges.push(edge);
        }
    }
    activeEdges.sort((left, right) => left.edgeId.localeCompare(right.edgeId));

    const findings = [];
    for (const descriptor of findingDescriptors) {
        if (findings.length >= limits.findings) {
            activeTruncation.findings = true;
            activeBlockers.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
            break;
        }
        const candidateId = descriptor.findingId;
        const boundNodes = [...nodeMap.values()]
            .filter((node) => node.bindings.candidateIds.includes(candidateId))
            .map((node) => node.nodeId);
        const boundEdges = activeEdges
            .filter((edge) => edge.bindings.candidateIds.includes(candidateId))
            .map((edge) => edge.edgeId);
        findings.push(createEvasiveGraphFinding({
            ...descriptor,
            nodeIds: unique([...descriptor.nodeIds, ...boundNodes]),
            edgeIds: unique([...descriptor.edgeIds, ...boundEdges]),
        }, "evasiveGraphFinding", limits));
    }

    const knownNodeIds = new Set(nodeMap.keys());
    const knownUnresolved = [...unresolvedTargets].filter((id) => knownNodeIds.has(id));
    return createEvasiveGraphPlan({
        auditId,
        sourceNamespace,
        snapshotId,
        snapshotSha256,
        nodes: [...nodeMap.values()],
        edges: activeEdges,
        evidence: [...evidenceMap.values()],
        findings,
        conflicts,
        unresolvedTargetNodeIds: unique(knownUnresolved),
        blockerCodes: unique(activeBlockers),
        truncation: activeTruncation,
        limits,
    });
}

export function buildEvasiveGraph(inputs = {}) {
    const validated = validateInputs(inputs);
    const limits = normalizeEvasiveGraphLimits(inputs.limits || {});
    const evidenceById = collectRedTeamEvidence(validated.redTeamPlan);
    collectSemanticEvidence(inputs.semanticReviewAssignments, evidenceById);
    const facts = factCorpus(
        inputs.semanticScannerRecords,
        validated.current,
        evidenceById,
    );
    const state = {
        limits,
        nodes: new Map(),
        evidence: new Map(),
        proposedEdges: [],
        blockerCodes: new Set(),
        unresolvedTargetNodeIds: new Set(),
        truncation: {
            nodes: false,
            edges: false,
            evidence: false,
            findings: false,
            conflicts: false,
            bindings: false,
        },
    };
    for (const evidence of evidenceById.values()) addEvidence(state, evidence);

    const artifactsByObject = new Map();
    for (const artifact of validated.current.derivedArtifacts) {
        if (!artifactsByObject.has(artifact.sourceObjectId)) {
            artifactsByObject.set(artifact.sourceObjectId, []);
        }
        artifactsByObject.get(artifact.sourceObjectId).push(artifact);
    }
    const binaryMetadataObjects = new Set(
        validated.current.derivedArtifacts
            .filter((artifact) =>
                artifact.artifactKind === "binary-metadata"
                && artifact.status === "decoded")
            .map((artifact) => artifact.sourceObjectId),
    );
    const objectNodeById = new Map();
    const artifactNodeById = new Map();
    const factNodeById = new Map();
    const evidenceForObject = new Map();
    const evidenceForArtifact = new Map();
    const evidenceForFact = new Map();
    for (const evidence of state.evidence.values()) {
        if (evidence.objectId) {
            if (!evidenceForObject.has(evidence.objectId)) evidenceForObject.set(evidence.objectId, []);
            evidenceForObject.get(evidence.objectId).push(evidence.evidenceId);
        }
        if (evidence.artifactId) {
            if (!evidenceForArtifact.has(evidence.artifactId)) {
                evidenceForArtifact.set(evidence.artifactId, []);
            }
            evidenceForArtifact.get(evidence.artifactId).push(evidence.evidenceId);
        }
        if (evidence.factId) {
            if (!evidenceForFact.has(evidence.factId)) evidenceForFact.set(evidence.factId, []);
            evidenceForFact.get(evidence.factId).push(evidence.evidenceId);
        }
    }

    for (const object of validated.current.objectInventory) {
        if (object.objectKind === "tree") continue;
        const kind = objectNodeKind(object, binaryMetadataObjects);
        const unsupported = kind === "unsupported-target";
        const unresolved = kind === "submodule" || kind === "lfs";
        const node = addNode(state, {
            kind,
            identityKind: "object",
            identity: object.objectId,
            status: unsupported ? "unsupported": unresolved ? "unresolved": "supported",
            bindings: {
                ...emptyNodeBindings(),
                objectIds: [object.objectId],
                evidenceIds: evidenceForObject.get(object.objectId) || [],
            },
        });
        if (!node) continue;
        objectNodeById.set(object.objectId, node.nodeId);
        if (unsupported) state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT);
        if (unresolved) {
            state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED);
            state.unresolvedTargetNodeIds.add(node.nodeId);
        }
        if (object.status !== "inventoried") {
            state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT);
        }
    }

    for (const artifact of validated.current.derivedArtifacts) {
        const node = addNode(state, {
            kind: artifactNodeKind(artifact),
            identityKind: "artifact",
            identity: artifact.artifactId,
            status: artifact.status === "decoded" ? "supported": "unsupported",
            bindings: {
                ...emptyNodeBindings(),
                objectIds: [artifact.sourceObjectId],
                artifactIds: [artifact.artifactId],
                evidenceIds: evidenceForArtifact.get(artifact.artifactId) || [],
            },
        });
        if (!node) continue;
        artifactNodeById.set(artifact.artifactId, node.nodeId);
        const sourceNodeId = objectNodeById.get(artifact.sourceObjectId);
        proposeEdge(state, {
            kind: artifact.transformChain.length > 0 ? "decodes": "generates",
            fromNodeId: sourceNodeId,
            toNodeId: node.nodeId,
            bindings: {
                ...emptyEdgeBindings(),
                artifactIds: [artifact.artifactId],
                evidenceIds: evidenceForArtifact.get(artifact.artifactId) || [],
            },
        });
        if (artifact.status !== "decoded") {
            state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT);
        }
    }

    for (const object of validated.current.objectInventory) {
        if (object.parentObjectId === null) continue;
        const parent = objectNodeById.get(object.parentObjectId);
        const child = objectNodeById.get(object.objectId);
        if (parent && child) {
            proposeEdge(state, {
                kind: "packages",
                fromNodeId: parent,
                toNodeId: child,
                bindings: {
                    ...emptyEdgeBindings(),
                    evidenceIds: evidenceForObject.get(object.objectId) || [],
                },
            });
        }
    }

    for (const fact of facts) {
        const evidenceIds = evidenceForFact.get(fact.id) || [...state.evidence.values()]
            .filter((entry) => entry.factId === fact.id)
            .map((entry) => entry.evidenceId);
        const node = addNode(state, {
            kind: FACT_NODE_KIND[fact.kind],
            identityKind: "fact",
            identity: fact.id,
            status: factStatus(fact),
            bindings: {
                ...emptyNodeBindings(),
                objectIds: [fact.objectId],
                artifactIds: fact.artifactId ? [fact.artifactId]: [],
                factIds: [fact.id],
                evidenceIds,
            },
        });
        if (!node) continue;
        factNodeById.set(fact.id, node.nodeId);
        const subjectNodeId = fact.artifactId
            ? artifactNodeById.get(fact.artifactId): objectNodeById.get(fact.objectId);
        proposeEdge(state, {
            kind: "evidence-binding",
            fromNodeId: node.nodeId,
            toNodeId: subjectNodeId,
            bindings: {
                ...emptyEdgeBindings(),
                artifactIds: fact.artifactId ? [fact.artifactId]: [],
                factIds: [fact.id],
                evidenceIds,
            },
        });
        if (node.status === "unresolved") {
            state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED);
            state.unresolvedTargetNodeIds.add(node.nodeId);
        }
    }

    const factsBySubject = new Map();
    for (const fact of facts) {
        const subject = `${fact.objectId}\0${fact.artifactId || ""}`;
        if (!factsBySubject.has(subject)) factsBySubject.set(subject, []);
        factsBySubject.get(subject).push(fact);
    }
    for (const subjectFacts of factsBySubject.values()) {
        subjectFacts.sort((left, right) =>
            left.line - right.line
            || left.endLine - right.endLine
            || left.id.localeCompare(right.id));
        for (let index = 1; index < subjectFacts.length; index += 1) {
            const from = subjectFacts[index - 1];
            const to = subjectFacts[index];
            proposeEdge(state, {
                kind: edgeKindForFacts(from, to),
                fromNodeId: factNodeById.get(from.id),
                toNodeId: factNodeById.get(to.id),
                bindings: {
                    ...emptyEdgeBindings(),
                    artifactIds: unique([from.artifactId, to.artifactId]),
                    factIds: [from.id, to.id],
                    evidenceIds: unique([
                        ...(evidenceForFact.get(from.id) || []),
                        ...(evidenceForFact.get(to.id) || []),
                    ]),
                },
            });
        }
    }

    const objectTokenIndex = new Map();
    for (const object of validated.current.objectInventory) {
        if (!objectNodeById.has(object.objectId)) continue;
        for (const token of objectTargetTokens(object)) {
            if (!objectTokenIndex.has(token)) objectTokenIndex.set(token, []);
            objectTokenIndex.get(token).push(object.objectId);
        }
    }
    for (const fact of facts.filter((entry) =>
        ["import", "dynamic-import"].includes(entry.kind))) {
        const matchedObjectIds = unique(targetTokens(fact)
            .flatMap((token) => objectTokenIndex.get(token) || []))
            .filter((objectId) => objectId !== fact.objectId);
        if (fact.resolution === "dynamic" || matchedObjectIds.length === 0) {
            const targetIdentity = `target:${hashDomain("zerotrust-dynamic-target", {
                factId: fact.id,
                target: fact.target || fact.value || fact.name,
            })}`;
            const targetNode = addNode(state, {
                kind: "dynamic-target",
                identityKind: "target",
                identity: targetIdentity,
                status: "unresolved",
                bindings: {
                    ...emptyNodeBindings(),
                    objectIds: [fact.objectId],
                    factIds: [fact.id],
                    evidenceIds: evidenceForFact.get(fact.id) || [],
                },
            });
            if (targetNode) {
                state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED);
                state.unresolvedTargetNodeIds.add(targetNode.nodeId);
                proposeEdge(state, {
                    kind: fact.kind === "import" ? "imports": "loads",
                    fromNodeId: factNodeById.get(fact.id),
                    toNodeId: targetNode.nodeId,
                    bindings: {
                        ...emptyEdgeBindings(),
                        factIds: [fact.id],
                        evidenceIds: evidenceForFact.get(fact.id) || [],
                    },
                });
            }
            continue;
        }
        for (const objectId of matchedObjectIds) {
            const targetFacts = facts.filter((entry) =>
                entry.objectId === objectId
                && ["activation", "generated-code-hook", "source"].includes(entry.kind));
            const targets = targetFacts.length > 0
                ? targetFacts.map((entry) => factNodeById.get(entry.id)): [objectNodeById.get(objectId)];
            for (const targetNodeId of targets) {
                proposeEdge(state, {
                    kind: fact.kind === "import" ? "imports": "loads",
                    fromNodeId: factNodeById.get(fact.id),
                    toNodeId: targetNodeId,
                    bindings: {
                        ...emptyEdgeBindings(),
                        factIds: [fact.id],
                        evidenceIds: evidenceForFact.get(fact.id) || [],
                    },
                });
            }
        }
    }

    const supplyNodeMap = new Map();
    if (validated.supplyChain) {
        for (const supplyNode of validated.supplyChain.nodes) {
            const node = addNode(state, {
                kind: supplyNodeKind(supplyNode),
                identityKind: "supply-chain",
                identity: supplyNode.nodeId,
                status: supplyNode.status === "blocked" ? "unsupported": "supported",
                bindings: {
                    ...emptyNodeBindings(),
                    supplyChainNodeIds: [supplyNode.nodeId],
                },
            });
            if (node) supplyNodeMap.set(supplyNode.nodeId, node.nodeId);
            if (supplyNode.status === "blocked") {
                state.blockerCodes.add(EVASIVE_BLOCKERS.SUPPLY_CHAIN_INCOMPLETE);
            }
        }
        for (const supplyEdge of validated.supplyChain.edges) {
            proposeEdge(state, {
                kind: supplyEdgeKind(supplyEdge),
                fromNodeId: supplyNodeMap.get(supplyEdge.fromNodeId),
                toNodeId: supplyNodeMap.get(supplyEdge.toNodeId),
                bindings: {
                    ...emptyEdgeBindings(),
                    supplyChainEdgeIds: [supplyEdge.edgeId],
                },
            });
        }
        if (validated.supplyChain.blockerCodes.length > 0) {
            state.blockerCodes.add(EVASIVE_BLOCKERS.SUPPLY_CHAIN_INCOMPLETE);
        }
    }

    const redNodeMap = new Map();
    for (const category of validated.redTeamPlan.categoryPlans) {
        for (const redNode of category.view.graph.nodes || []) {
            let nodeId = null;
            if (redNode.kind === "object") nodeId = objectNodeById.get(redNode.identity);
            else if (redNode.kind === "artifact") nodeId = artifactNodeById.get(redNode.identity);
            else if (redNode.kind === "semantic-fact") {
                nodeId = factNodeById.get(redNode.identity);
            }
            if (nodeId) {
                const existing = state.nodes.get(nodeId);
                addNode(state, {
                    kind: existing.kind,
                    identityKind: existing.identityKind,
                    identity: existing.identity,
                    status: existing.status,
                    bindings: {
                        ...existing.bindings,
                        redTeamGraphNodeIds: unique([
                            ...existing.bindings.redTeamGraphNodeIds,
                            redNode.nodeId,
                        ]),
                    },
                });
                redNodeMap.set(redNode.nodeId, nodeId);
            }
        }
    }
    for (const category of validated.redTeamPlan.categoryPlans) {
        for (const redEdge of category.view.graph.edges || []) {
            const fromNodeId = redNodeMap.get(redEdge.fromNodeId);
            const toNodeId = redNodeMap.get(redEdge.toNodeId);
            if (fromNodeId && toNodeId) {
                proposeEdge(state, {
                    kind: redEdgeKind(redEdge),
                    fromNodeId,
                    toNodeId,
                    bindings: {
                        ...emptyEdgeBindings(),
                        redTeamGraphEdgeIds: [redEdge.edgeId],
                    },
                });
            }
        }
    }

    const findingDescriptors = [];
    // Canonical assurance semantic candidates only. Compatibility finding-code scaffolding is
    // intentionally not translated here and therefore cannot enter validation.
    const semanticReviewByAssignmentId = new Map(
        inputs.semanticReviewRecords.map((review) =>
            [review.assignmentId, review]),
    );
    for (const candidate of validated.semanticEvaluation.candidateLedger) {
        const review = semanticReviewByAssignmentId.get(
            candidate.producerAssignmentId,
        );
        const commonBindings = {
            ...emptyNodeBindings(),
            objectIds: candidate.objectIds,
            artifactIds: candidate.artifactIds,
            factIds: candidate.factIds,
            evidenceIds: candidate.evidenceIds,
            semanticReviewIds: review ? [review.reviewId]: [],
            candidateIds: [candidate.candidateId],
        };
        const trigger = addNode(state, {
            kind: "trigger",
            identityKind: "finding",
            identity: `${candidate.candidateId}:trigger`,
            status: "supported",
            bindings: commonBindings,
        });
        const capability = addNode(state, {
            kind: "capability",
            identityKind: "finding",
            identity: `${candidate.candidateId}:capability`,
            status: "supported",
            bindings: commonBindings,
        });
        const transform = addNode(state, {
            kind: "transform",
            identityKind: "finding",
            identity: `${candidate.candidateId}:action`,
            status: "supported",
            bindings: commonBindings,
        });
        const effect = addNode(state, {
            kind: "effect",
            identityKind: "finding",
            identity: `${candidate.candidateId}:target`,
            status: "supported",
            bindings: commonBindings,
        });
        const edgeBindings = {
            ...emptyEdgeBindings(),
            artifactIds: candidate.artifactIds,
            factIds: candidate.factIds,
            evidenceIds: candidate.evidenceIds,
            candidateIds: [candidate.candidateId],
        };
        proposeEdge(state, {
            kind: "calls",
            fromNodeId: trigger?.nodeId,
            toNodeId: capability?.nodeId,
            bindings: edgeBindings,
        });
        proposeEdge(state, {
            kind: "calls",
            fromNodeId: capability?.nodeId,
            toNodeId: transform?.nodeId,
            bindings: edgeBindings,
        });
        proposeEdge(state, {
            kind: candidateEffectEdge(candidate),
            fromNodeId: transform?.nodeId,
            toNodeId: effect?.nodeId,
            bindings: edgeBindings,
        });
        findingDescriptors.push({
            findingId: candidate.candidateId,
            origin: "semantic-review",
            severity: candidate.severity,
            objectIds: candidate.objectIds,
            artifactIds: candidate.artifactIds,
            factIds: candidate.factIds,
            evidenceIds: candidate.evidenceIds,
            nodeIds: unique([
                trigger?.nodeId,
                capability?.nodeId,
                transform?.nodeId,
                effect?.nodeId,
            ]),
            edgeIds: [],
            sourceRecordIds: unique([
                candidate.producerAssignmentId,
                review?.reviewId,
            ]),
        });
    }

    for (const candidate of validated.redTeamEvaluation.candidateLedger) {
        const commonBindings = {
            ...emptyNodeBindings(),
            objectIds: candidate.objectIds,
            artifactIds: candidate.artifactIds,
            factIds: candidate.factIds,
            evidenceIds: candidate.evidenceIds,
            candidateIds: [candidate.candidateId],
            redTeamGraphNodeIds: candidate.graphNodeIds,
        };
        const trigger = addNode(state, {
            kind: "trigger",
            identityKind: "finding",
            identity: `${candidate.candidateId}:trigger`,
            status: "supported",
            bindings: commonBindings,
        });
        const capability = addNode(state, {
            kind: "capability",
            identityKind: "finding",
            identity: `${candidate.candidateId}:capability`,
            status: "supported",
            bindings: commonBindings,
        });
        const transform = addNode(state, {
            kind: "transform",
            identityKind: "finding",
            identity: `${candidate.candidateId}:action`,
            status: "supported",
            bindings: commonBindings,
        });
        const effect = addNode(state, {
            kind: "effect",
            identityKind: "finding",
            identity: `${candidate.candidateId}:target`,
            status: "supported",
            bindings: commonBindings,
        });
        const edgeBindings = {
            ...emptyEdgeBindings(),
            artifactIds: candidate.artifactIds,
            factIds: candidate.factIds,
            evidenceIds: candidate.evidenceIds,
            candidateIds: [candidate.candidateId],
            redTeamGraphEdgeIds: candidate.graphEdgeIds,
        };
        proposeEdge(state, {
            kind: "calls",
            fromNodeId: trigger?.nodeId,
            toNodeId: capability?.nodeId,
            bindings: edgeBindings,
        });
        proposeEdge(state, {
            kind: "calls",
            fromNodeId: capability?.nodeId,
            toNodeId: transform?.nodeId,
            bindings: edgeBindings,
        });
        proposeEdge(state, {
            kind: candidateEffectEdge(candidate),
            fromNodeId: transform?.nodeId,
            toNodeId: effect?.nodeId,
            bindings: edgeBindings,
        });
        findingDescriptors.push({
            findingId: candidate.candidateId,
            origin: "red-team",
            severity: candidate.severity,
            objectIds: candidate.objectIds,
            artifactIds: candidate.artifactIds,
            factIds: candidate.factIds,
            evidenceIds: candidate.evidenceIds,
            nodeIds: unique([
                trigger?.nodeId,
                capability?.nodeId,
                transform?.nodeId,
                effect?.nodeId,
            ]),
            edgeIds: [],
            sourceRecordIds: [
                candidate.producerAssignmentId,
                ...candidate.graphNodeIds,
                ...candidate.graphEdgeIds,
            ],
        });
    }

    for (const node of state.nodes.values()) {
        if (node.kind === "dynamic-target") {
            state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED);
        }
        if (node.kind === "unsupported-target" || node.status === "unsupported") {
            state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT);
        }
    }
    if (state.proposedEdges.length > limits.edges * 2) {
        state.truncation.edges = true;
        state.blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
        state.proposedEdges.length = limits.edges * 2;
    }

    return mergeEvasiveGraphRecords({
        auditId: validated.current.auditId,
        sourceNamespace: validated.current.sourceNamespace,
        snapshotId: validated.current.snapshotId,
        snapshotSha256: validated.current.hashes.snapshotSha256,
        nodes: [...state.nodes.values()],
        proposedEdges: state.proposedEdges,
        evidence: [...state.evidence.values()],
        findingDescriptors,
        blockerCodes: [...state.blockerCodes],
        unresolvedTargetNodeIds: [...state.unresolvedTargetNodeIds],
        truncation: state.truncation,
        limits,
    });
}

export const __internals = Object.freeze({
    NON_FLOW_EDGE_KINDS,
    canonicalJson,
    edgeKindForFacts,
    emptyEdgeBindings,
    emptyNodeBindings,
    hashDomain,
    objectNodeKind,
    targetTokens,
});
