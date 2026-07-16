import { createHash } from "node:crypto";

import { EVASIVE_BLOCKERS } from "./evasiveSchemas.mjs";
import {
    EVASIVE_GRAPH_SCHEMA_REVISION,
    validateEvasiveGraphPlan,
} from "./evasiveGraphSchemas.mjs";

export const EVASIVE_TRACE_SCHEMA_REVISION = 6;
export const EVASIVE_TRACE_KIND = "evasive-behavior-trace";

export const EVASIVE_TRACE_LIMITS = Object.freeze({
    paths: 20_000,
    depth: 64,
    branches: 200_000,
    cycles: 4_096,
    nodesPerPath: 64,
    edgesPerPath: 63,
});

const HARD_LIMITS = Object.freeze({
    paths: 100_000,
    depth: 256,
    branches: 1_000_000,
    cycles: 20_000,
    nodesPerPath: 256,
    edgesPerPath: 255,
});

const EFFECT_KINDS = new Set([
    "sink",
    "effect",
    "persistence",
    "propagation",
]);
const NON_FLOW_EDGE_KINDS = new Set([
    "evidence-binding",
    "provenance-binding",
]);

if (EVASIVE_TRACE_SCHEMA_REVISION !== EVASIVE_GRAPH_SCHEMA_REVISION) {
    throw new Error("assurance graph and trace schema revisions must align");
}

export class EvasiveTraceContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "EvasiveTraceContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new EvasiveTraceContractError(path, message);
}

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
        throw new TypeError("assurance trace unique values must be iterable");
    }
    return [...new Set([...values].filter(Boolean))].sort();
}

function normalizeLimits(value = {}) {
    if (!isPlainObject(value)) fail("evasiveTraceLimits", "must be a plain object");
    const result = {};
    for (const key of Object.keys(EVASIVE_TRACE_LIMITS)) {
        if (Object.hasOwn(value, key)
            && (!Number.isSafeInteger(value[key])
                || value[key] < 1
                || value[key] > HARD_LIMITS[key])) {
            fail(`evasiveTraceLimits.${key}`, `must be between 1 and ${HARD_LIMITS[key]}`);
        }
        result[key] = value[key] ?? EVASIVE_TRACE_LIMITS[key];
    }
    for (const key of Object.keys(value)) {
        if (!Object.hasOwn(EVASIVE_TRACE_LIMITS, key)) {
            fail(`evasiveTraceLimits.${key}`, "unknown field");
        }
    }
    if (result.edgesPerPath >= result.nodesPerPath) {
        fail("evasiveTraceLimits.edgesPerPath", "must be less than nodesPerPath");
    }
    return cloneFrozen(result);
}

function pathRecord(rootNodeId, nodes, edges, status, unresolvedCodes) {
    const base = {
        rootNodeId,
        status,
        nodeIds: nodes.map((node) => node.nodeId),
        edgeIds: edges.map((edge) => edge.edgeId),
        effectNodeIds: nodes
            .filter((node) => EFFECT_KINDS.has(node.kind))
            .map((node) => node.nodeId),
        candidateIds: unique([
            ...nodes.flatMap((node) => node.bindings.candidateIds),
            ...edges.flatMap((edge) => edge.bindings.candidateIds),
        ]),
        evidenceIds: unique([
            ...nodes.flatMap((node) => node.bindings.evidenceIds),
            ...edges.flatMap((edge) => edge.bindings.evidenceIds),
        ]),
        unresolvedCodes: unique(unresolvedCodes),
    };
    const pathSha256 = hashDomain("zerotrust-trace-path", base);
    return cloneFrozen({
        pathId: `ztp-${pathSha256}`,
        ...base,
        hashes: { pathSha256 },
    });
}

function cycleRecord(rootNodeId, nodes, edges, repeatedNodeId) {
    const base = {
        rootNodeId,
        nodeIds: nodes.map((node) => node.nodeId),
        edgeIds: edges.map((edge) => edge.edgeId),
        repeatedNodeId,
    };
    const cycleSha256 = hashDomain("zerotrust-trace-cycle", base);
    return cloneFrozen({
        cycleId: `ztcycle-${cycleSha256}`,
        ...base,
        hashes: { cycleSha256 },
    });
}

export function traceEvasiveGraph(graph, {
    limits: limitOverrides = {},
} = {}) {
    const plan = validateEvasiveGraphPlan(graph);
    const limits = normalizeLimits(limitOverrides);
    const nodeById = new Map(plan.nodes.map((node) => [node.nodeId, node]));
    const adjacency = new Map();
    for (const edge of plan.edges) {
        if (NON_FLOW_EDGE_KINDS.has(edge.kind)) continue;
        if (!adjacency.has(edge.fromNodeId)) adjacency.set(edge.fromNodeId, []);
        adjacency.get(edge.fromNodeId).push(edge);
    }
    for (const edges of adjacency.values()) {
        edges.sort((left, right) => left.edgeId.localeCompare(right.edgeId));
    }
    const roots = plan.nodes
        .filter((node) => node.kind === "activation" || node.kind === "trigger")
        .sort((left, right) => left.nodeId.localeCompare(right.nodeId));
    const paths = new Map();
    const cycles = new Map();
    const blockerCodes = new Set(plan.blockerCodes);
    const truncation = {
        paths: false,
        depth: false,
        branches: false,
        cycles: false,
        pathNodes: false,
        pathEdges: false,
        graph: Object.values(plan.truncation).some(Boolean),
    };
    let branchCount = 0;

    const emit = (root, nodes, edges, status, unresolvedCodes = []) => {
        if (nodes.length > limits.nodesPerPath) {
            truncation.pathNodes = true;
            blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
        }
        if (edges.length > limits.edgesPerPath) {
            truncation.pathEdges = true;
            blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
        }
        const boundedNodes = nodes.slice(0, limits.nodesPerPath);
        const boundedEdges = edges.slice(0, limits.edgesPerPath);
        const record = pathRecord(
            root.nodeId,
            boundedNodes,
            boundedEdges,
            status,
            unresolvedCodes,
        );
        if (paths.has(record.pathId)) return;
        if (paths.size >= limits.paths) {
            truncation.paths = true;
            blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
            return;
        }
        paths.set(record.pathId, record);
    };

    const visit = (root, node, nodePath, edgePath, visited) => {
        const nextNodes = [...nodePath, node];
        if (nextNodes.length > limits.depth) {
            truncation.depth = true;
            blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
            emit(root, nextNodes, edgePath, "unresolved", ["trace-depth-cap"]);
            return;
        }
        if (node.kind === "dynamic-target" || node.status === "unresolved"
            || plan.unresolvedTargetNodeIds.includes(node.nodeId)) {
            blockerCodes.add(EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED);
            emit(root, nextNodes, edgePath, "unresolved", [
                EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED,
            ]);
            return;
        }
        if (node.kind === "unsupported-target" || node.status === "unsupported") {
            blockerCodes.add(EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT);
            emit(root, nextNodes, edgePath, "unresolved", [
                EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT,
            ]);
            return;
        }
        const outgoing = adjacency.get(node.nodeId) || [];
        const effectReached = EFFECT_KINDS.has(node.kind);
        if (effectReached) emit(root, nextNodes, edgePath, "complete-effect");
        if (outgoing.length === 0) {
            if (!effectReached) emit(root, nextNodes, edgePath, "benign-terminal");
            return;
        }
        for (const edge of outgoing) {
            branchCount += 1;
            if (branchCount > limits.branches) {
                truncation.branches = true;
                blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
                emit(root, nextNodes, edgePath, "unresolved", ["trace-branch-cap"]);
                return;
            }
            const target = nodeById.get(edge.toNodeId);
            if (!target) {
                blockerCodes.add(EVASIVE_BLOCKERS.TRACE_MISSING_TARGET);
                emit(root, nextNodes, [...edgePath, edge], "unresolved", [
                    EVASIVE_BLOCKERS.TRACE_MISSING_TARGET,
                ]);
                continue;
            }
            if (visited.has(target.nodeId)) {
                blockerCodes.add(EVASIVE_BLOCKERS.TRACE_CYCLE);
                const cycle = cycleRecord(
                    root.nodeId,
                    [...nextNodes, target],
                    [...edgePath, edge],
                    target.nodeId,
                );
                if (!cycles.has(cycle.cycleId)) {
                    if (cycles.size >= limits.cycles) {
                        truncation.cycles = true;
                        blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);
                    } else {
                        cycles.set(cycle.cycleId, cycle);
                    }
                }
                emit(root, nextNodes, [...edgePath, edge], "unresolved", [
                    EVASIVE_BLOCKERS.TRACE_CYCLE,
                ]);
                continue;
            }
            visit(
                root,
                target,
                nextNodes,
                [...edgePath, edge],
                new Set([...visited, target.nodeId]),
            );
        }
    };

    for (const root of roots) {
        visit(root, root, [], [], new Set([root.nodeId]));
    }
    if (roots.length === 0 && plan.nodes.length > 0) {
        blockerCodes.add(EVASIVE_BLOCKERS.TRACE_INCOMPLETE);
    }
    if (truncation.graph) blockerCodes.add(EVASIVE_BLOCKERS.TRACE_TRUNCATED);

    const orderedPaths = [...paths.values()].sort((left, right) =>
        left.pathId.localeCompare(right.pathId));
    const rootCoverage = roots.map((root) => {
        const rootPaths = orderedPaths
            .filter((path) => path.rootNodeId === root.nodeId)
            .map((path) => path.pathId);
        return cloneFrozen({
            rootNodeId: root.nodeId,
            pathIds: rootPaths,
            complete: rootPaths.length > 0,
        });
    });
    const allRootsTraced = rootCoverage.every((entry) => entry.complete);
    if (!allRootsTraced) blockerCodes.add(EVASIVE_BLOCKERS.TRACE_INCOMPLETE);
    const unresolvedPathCount = orderedPaths.filter((path) =>
        path.status === "unresolved").length;
    const complete = blockerCodes.size === 0
        && unresolvedPathCount === 0
        && !Object.values(truncation).some(Boolean)
        && allRootsTraced;
    if (!complete) blockerCodes.add(EVASIVE_BLOCKERS.TRACE_INCOMPLETE);

    const base = {
        schemaVersion: EVASIVE_TRACE_SCHEMA_REVISION,
        contractKind: EVASIVE_TRACE_KIND,
        auditId: plan.auditId,
        sourceNamespace: plan.sourceNamespace,
        snapshotId: plan.snapshotId,
        graphId: plan.graphId,
        complete,
        paths: orderedPaths,
        rootCoverage,
        cycles: [...cycles.values()].sort((left, right) =>
            left.cycleId.localeCompare(right.cycleId)),
        blockerCodes: unique(blockerCodes),
        truncation,
        counts: {
            roots: roots.length,
            tracedRoots: rootCoverage.filter((entry) => entry.complete).length,
            paths: orderedPaths.length,
            effectPaths: orderedPaths.filter((path) =>
                path.status === "complete-effect").length,
            benignPaths: orderedPaths.filter((path) =>
                path.status === "benign-terminal").length,
            unresolvedPaths: unresolvedPathCount,
            cycles: cycles.size,
            exploredBranches: branchCount,
        },
        limits,
    };
    const traceSha256 = hashDomain("zerotrust-evasive-behavior-trace", {
        ...base,
        graphSha256: plan.hashes.graphSha256,
    });
    return cloneFrozen({
        ...base,
        traceId: `zttrace-${traceSha256}`,
        hashes: {
            graphSha256: plan.hashes.graphSha256,
            traceSha256,
        },
    });
}

export function validateEvasiveTrace(
    value,
    graph,
    path = "evasiveTrace",
) {
    if (!isPlainObject(value)
        || value.schemaVersion !== EVASIVE_TRACE_SCHEMA_REVISION
        || value.contractKind !== EVASIVE_TRACE_KIND
        || typeof value.traceId !== "string"
        || !/^zttrace-[a-f0-9]{64}$/u.test(value.traceId)) {
        fail(path, "has an invalid trace contract");
    }
    const expected = traceEvasiveGraph(graph, { limits: value.limits });
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match the deterministic exhaustive trace");
    }
    return expected;
}

export function evasiveTraceCanAdvance(graph, trace) {
    const plan = validateEvasiveGraphPlan(graph);
    const result = validateEvasiveTrace(trace, plan);
    return result.complete
        && result.blockerCodes.length === 0
        && !Object.values(result.truncation).some(Boolean)
        && result.counts.roots === result.counts.tracedRoots;
}

export const __internals = Object.freeze({
    EFFECT_KINDS,
    NON_FLOW_EDGE_KINDS,
    canonicalJson,
    hashDomain,
    normalizeLimits,
});
