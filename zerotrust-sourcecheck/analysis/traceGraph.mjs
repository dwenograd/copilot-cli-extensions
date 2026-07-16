import { createHash } from "node:crypto";

import { ANALYSIS_SCHEMA_REVISION } from "./schemas.mjs";

export const TRACE_LIMITS = Object.freeze({
    chains: 128,
    depth: 16,
    branches: 8192,
    cycles: 256,
    validationItems: 256,
    evidencePerChain: 64,
    pathsPerChain: 32,
});

const EFFECT_KINDS = new Set(["sink", "persistence", "propagation"]);

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

function boundedLimit(value, fallback, maximum) {
    if (!Number.isSafeInteger(value) || value < 1) return fallback;
    return Math.min(value, maximum);
}

function normalizeLimits(value = {}) {
    return Object.freeze({
        chains: boundedLimit(value.chains, TRACE_LIMITS.chains, TRACE_LIMITS.chains),
        depth: boundedLimit(value.depth, TRACE_LIMITS.depth, TRACE_LIMITS.depth),
        branches: boundedLimit(value.branches, TRACE_LIMITS.branches, TRACE_LIMITS.branches),
        cycles: boundedLimit(value.cycles, TRACE_LIMITS.cycles, TRACE_LIMITS.cycles),
        validationItems: boundedLimit(
            value.validationItems,
            TRACE_LIMITS.validationItems,
            TRACE_LIMITS.validationItems,
        ),
        evidencePerChain: boundedLimit(
            value.evidencePerChain,
            TRACE_LIMITS.evidencePerChain,
            TRACE_LIMITS.evidencePerChain,
        ),
        pathsPerChain: boundedLimit(
            value.pathsPerChain,
            TRACE_LIMITS.pathsPerChain,
            TRACE_LIMITS.pathsPerChain,
        ),
    });
}

function unique(values) {
    return [...new Set(values)].sort();
}

function uniqueCanonical(values) {
    const entries = new Map();
    for (const value of values) entries.set(canonicalJson(value), value);
    return [...entries.values()].sort((left, right) =>
        canonicalJson(left).localeCompare(canonicalJson(right)));
}

function semanticTokens(node) {
    const tokens = [node.kind, ...(node.tags || [])];
    for (const behavior of node.behaviors || []) {
        for (const value of Object.values(behavior)) {
            if (Array.isArray(value)) tokens.push(...value);
            else tokens.push(value);
        }
    }
    return unique(tokens.map((value) => String(value || "").toLowerCase()).filter(Boolean));
}

function tokenMatches(node, expression) {
    return semanticTokens(node).some((token) => expression.test(token));
}

function orderedPositions(nodes, expressions) {
    const positions = [];
    let cursor = 0;
    for (const expression of expressions) {
        const relative = nodes.slice(cursor).findIndex((node) => tokenMatches(node, expression));
        if (relative < 0) return null;
        const absolute = cursor + relative;
        positions.push(absolute);
        cursor = absolute + 1;
    }
    return positions;
}

function classifyPattern(nodes) {
    const patterns = [
        {
            code: "install-fetch-decode-execute",
            priority: 1,
            expressions: [
                /(?:package-|npm|install|lifecycle)/u,
                /(?:fetch|download|remote|http|network-read)/u,
                /(?:decode|base64|deobfusc)/u,
                /(?:execute|process-spawn|shell|eval|dynamic-evaluation)/u,
            ],
        },
        {
            code: "credential-read-transform-send",
            priority: 2,
            expressions: [
                /(?:credential|secret|token|keychain|cookie|npmrc|aws|ssh)/u,
                /(?:transform|encode|compress|encrypt|serialize)/u,
                /(?:send|upload|webhook|external|network-write|exfil)/u,
            ],
        },
        {
            code: "startup-persistence",
            priority: 3,
            expressions: [
                /(?:startup|boot|login|activate|on-start)/u,
                /(?:persistence|scheduled-task|registry-run|cron|systemd|autostart)/u,
            ],
        },
        {
            code: "ai-instruction-tool-effect",
            priority: 4,
            expressions: [
                /(?:ai|prompt|instruction|model-output)/u,
                /(?:tool|invoke|function-call|agent-action)/u,
                /(?:filesystem|file-write|network|http|external)/u,
            ],
        },
        {
            code: "ci-trigger-secret-external-sink",
            priority: 5,
            expressions: [
                /(?:ci|github-actions|pull-request|workflow|pipeline)/u,
                /(?:credential|secret|token|environment-variable)/u,
                /(?:send|upload|webhook|external|network-write|exfil)/u,
            ],
        },
    ];
    for (const pattern of patterns) {
        if (orderedPositions(nodes, pattern.expressions)) return pattern;
    }
    return { code: "behavior-chain", priority: 100 };
}

function mergeSemanticNodes(nodeRecords) {
    const nodes = new Map();
    let truncated = false;
    for (const record of nodeRecords) {
        let merged = nodes.get(record.semanticKey);
        if (!merged) {
            merged = {
                semanticKey: record.semanticKey,
                kind: record.node.kind,
                nodeIds: [],
                sources: [],
                evidence: [],
                behaviors: [],
                tags: [],
            };
            nodes.set(record.semanticKey, merged);
        }
        merged.nodeIds.push(record.node.id);
        merged.sources.push(...record.binding.sources);
        merged.evidence.push(...record.binding.evidence);
        merged.behaviors.push(...record.binding.behaviors);
        merged.tags.push(...record.binding.tags);
    }
    for (const node of nodes.values()) {
        const nodeIds = unique(node.nodeIds);
        const sources = uniqueCanonical(node.sources);
        const evidence = uniqueCanonical(node.evidence);
        const behaviors = uniqueCanonical(node.behaviors);
        const tags = unique(node.tags);
        truncated ||= nodeIds.length > 64
            || sources.length > TRACE_LIMITS.pathsPerChain
            || evidence.length > TRACE_LIMITS.evidencePerChain
            || behaviors.length > 64
            || tags.length > 64;
        node.nodeIds = nodeIds.slice(0, 64);
        node.sources = sources.slice(0, TRACE_LIMITS.pathsPerChain);
        node.evidence = evidence.slice(0, TRACE_LIMITS.evidencePerChain);
        node.behaviors = behaviors.slice(0, 64);
        node.tags = tags.slice(0, 64);
    }
    return { nodes, truncated };
}

function mergeSemanticEdges(edgeRecords) {
    const edges = new Map();
    let truncated = false;
    for (const record of edgeRecords) {
        let merged = edges.get(record.semanticKey);
        if (!merged) {
            merged = {
                semanticKey: record.semanticKey,
                kind: record.edge.kind,
                from: record.fromSemantic,
                to: record.toSemantic,
                edgeIds: [],
                evidence: [],
                tags: [],
            };
            edges.set(record.semanticKey, merged);
        }
        merged.edgeIds.push(record.edge.id);
        merged.evidence.push(...record.binding.evidence);
        merged.tags.push(...record.binding.tags);
    }
    for (const edge of edges.values()) {
        const edgeIds = unique(edge.edgeIds);
        const evidence = uniqueCanonical(edge.evidence);
        const tags = unique(edge.tags);
        truncated ||= edgeIds.length > 64
            || evidence.length > TRACE_LIMITS.evidencePerChain
            || tags.length > 64;
        edge.edgeIds = edgeIds.slice(0, 64);
        edge.evidence = evidence.slice(0, TRACE_LIMITS.evidencePerChain);
        edge.tags = tags.slice(0, 64);
    }
    return { edges, truncated };
}

function chainIdentity(nodePath, edgePath, terminalIssue = null) {
    return {
        nodes: nodePath.map((node) => node.semanticKey),
        edges: edgePath.map((edge) => edge.semanticKey),
        ...(terminalIssue ? { terminalIssue }: {}),
    };
}

function pathsForNode(node) {
    return unique([
        ...node.sources.map((source) => source.path),
        ...node.evidence.map((evidence) => evidence.path),
    ]);
}

function buildValidationQueue(mergeResult, limit) {
    const entries = mergeResult.conflicts.map((conflict) => ({
        id: conflict.id,
        reasonCode: conflict.reasonCode,
        nodeIds: conflict.nodeIds || [],
        edgeIds: conflict.edgeIds || [],
        ...(conflict.edgeKind ? { edgeKind: conflict.edgeKind }: {}),
        ...(conflict.fromKind ? { fromKind: conflict.fromKind }: {}),
        ...(conflict.toKind ? { toKind: conflict.toKind }: {}),
    })).sort((left, right) => left.id.localeCompare(right.id));
    return {
        items: entries.slice(0, limit),
        truncated: entries.length > limit || mergeResult.truncation.conflicts,
    };
}

export function traceBehaviorGraph(mergeResult, {
    limits: limitOverrides = {},
} = {}) {
    if (!mergeResult || mergeResult.schemaVersion !== ANALYSIS_SCHEMA_REVISION) {
        throw new TypeError("trace requires a baseline analysis merged graph");
    }
    const limits = normalizeLimits(limitOverrides);
    const mergedNodes = mergeSemanticNodes(mergeResult.nodeRecords);
    const mergedEdges = mergeSemanticEdges(mergeResult.edgeRecords);
    const semanticNodes = mergedNodes.nodes;
    const semanticEdges = mergedEdges.edges;
    const adjacency = new Map();
    const incoming = new Map();
    for (const edge of semanticEdges.values()) {
        const list = adjacency.get(edge.from) || [];
        list.push(edge);
        adjacency.set(edge.from, list);
        incoming.set(edge.to, (incoming.get(edge.to) || 0) + 1);
    }
    for (const edges of adjacency.values()) {
        edges.sort((left, right) =>
            left.semanticKey.localeCompare(right.semanticKey));
    }
    const blockedByFrom = new Map();
    for (const blocked of mergeResult.blockedTransitions) {
        if (!blocked.fromSemantic) continue;
        const list = blockedByFrom.get(blocked.fromSemantic) || [];
        list.push(blocked);
        blockedByFrom.set(blocked.fromSemantic, list);
    }

    const allStarts = [...semanticNodes.values()]
        .filter((node) => node.kind === "activation" || node.kind === "trigger")
        .sort((left, right) => left.semanticKey.localeCompare(right.semanticKey));
    const roots = allStarts.filter((node) => !incoming.has(node.semanticKey));
    const starts = roots.length > 0 ? roots: allStarts;
    const chains = new Map();
    const cycles = [];
    const blockers = [...mergeResult.blockers];
    const validation = buildValidationQueue(mergeResult, limits.validationItems);
    let branchCount = 0;
    let chainsTruncated = false;
    let branchesTruncated = false;
    let depthTruncated = false;
    let cyclesTruncated = false;
    let evidenceTruncated = false;
    let pathsTruncated = false;
    let semanticBindingsTruncated = mergedNodes.truncated || mergedEdges.truncated;

    const emit = (nodePath, edgePath, {
        terminalIssue = null,
        contested = false,
        validationIds = [],
    } = {}) => {
        if (nodePath.length === 0) return;
        const identity = chainIdentity(nodePath, edgePath, terminalIssue);
        const id = `ztc-${hash("zerotrust-behavior-chain", identity)}`;
        if (chains.has(id)) return;
        if (chains.size >= limits.chains) {
            chainsTruncated = true;
            return;
        }
        const last = nodePath.at(-1);
        const complete = EFFECT_KINDS.has(last.kind) && !terminalIssue && !contested;
        const pattern = classifyPattern(nodePath);
        const allEvidence = uniqueCanonical([
            ...nodePath.flatMap((node) => node.evidence),
            ...edgePath.flatMap((edge) => edge.evidence),
        ]);
        const allPaths = unique([
            ...nodePath.flatMap(pathsForNode),
            ...edgePath.flatMap((edge) => edge.evidence.map((evidence) => evidence.path)),
        ]);
        if (allEvidence.length > limits.evidencePerChain) evidenceTruncated = true;
        if (allPaths.length > limits.pathsPerChain) pathsTruncated = true;
        const perStepEvidenceCap = Math.min(8, limits.evidencePerChain);
        const perStepPathCap = Math.min(8, limits.pathsPerChain);
        if (nodePath.some((node) =>
            node.evidence.length > perStepEvidenceCap
            || pathsForNode(node).length > perStepPathCap)
            || edgePath.some((edge) => edge.evidence.length > perStepEvidenceCap)) {
            semanticBindingsTruncated = true;
        }
        chains.set(id, {
            id,
            pattern: pattern.code,
            priority: pattern.priority,
            status: contested ? "contested": complete ? "complete": "unresolved",
            crossFile: allPaths.length > 1,
            steps: nodePath.map((node) => ({
                kind: node.kind,
                nodeIds: node.nodeIds,
                paths: pathsForNode(node).slice(0, perStepPathCap),
                tags: node.tags,
                evidence: node.evidence.slice(0, perStepEvidenceCap),
            })),
            links: edgePath.map((edge) => ({
                kind: edge.kind,
                edgeIds: edge.edgeIds,
                evidence: edge.evidence.slice(0, perStepEvidenceCap),
            })),
            evidence: allEvidence.slice(0, limits.evidencePerChain),
            evidenceTruncated: allEvidence.length > limits.evidencePerChain,
            paths: allPaths.slice(0, limits.pathsPerChain),
            pathsTruncated: allPaths.length > limits.pathsPerChain,
            effectKinds: unique(nodePath.filter((node) => EFFECT_KINDS.has(node.kind))
                .map((node) => node.kind)),
            unresolvedReasons: terminalIssue ? [terminalIssue.reasonCode]: [],
            validationIds: unique(validationIds),
        });
    };

    const visit = (node, nodePath, edgePath, visited) => {
        const nextNodePath = [...nodePath, node];
        if (nextNodePath.length >= limits.depth) {
            depthTruncated = true;
            emit(nextNodePath, edgePath, {
                terminalIssue: {
                    reasonCode: "trace-depth-cap",
                    node: node.semanticKey,
                },
            });
            return;
        }
        if (EFFECT_KINDS.has(node.kind)) {
            emit(nextNodePath, edgePath);
            return;
        }
        const outgoing = adjacency.get(node.semanticKey) || [];
        const blocked = blockedByFrom.get(node.semanticKey) || [];
        if (outgoing.length === 0) {
            emit(nextNodePath, edgePath, {
                terminalIssue: blocked.length > 0
                    ? {
                        reasonCode: "conflicting-or-unresolved-outgoing-edge",
                        transitionIds: blocked.map((entry) =>
                            entry.conflictId || entry.reasonCode).sort(),
                    }: {
                        reasonCode: "no-explicit-effect-edge",
                        node: node.semanticKey,
                    },
                contested: blocked.some((entry) => entry.conflictId),
                validationIds: blocked.map((entry) => entry.conflictId).filter(Boolean),
            });
            return;
        }
        for (const edge of outgoing) {
            branchCount += 1;
            if (branchCount > limits.branches) {
                branchesTruncated = true;
                emit(nextNodePath, edgePath, {
                    terminalIssue: {
                        reasonCode: "trace-branch-cap",
                        node: node.semanticKey,
                    },
                });
                return;
            }
            const target = semanticNodes.get(edge.to);
            if (!target) {
                emit(nextNodePath, edgePath, {
                    terminalIssue: {
                        reasonCode: "unresolved-semantic-target",
                        edge: edge.semanticKey,
                    },
                });
                continue;
            }
            if (visited.has(target.semanticKey)) {
                const cycleSemantic = {
                    nodes: [...visited, target.semanticKey],
                    edge: edge.semanticKey,
                };
                const cycleNodeIds = unique(
                    [...nextNodePath, target].flatMap((entry) => entry.nodeIds),
                );
                if (cycleNodeIds.length > 64) cyclesTruncated = true;
                const cycle = {
                    id: `ztcycle-${hash("zerotrust-behavior-cycle", cycleSemantic)}`,
                    nodeIds: cycleNodeIds.slice(0, 64),
                    edgeIds: edge.edgeIds,
                };
                if (!cycles.some((entry) => entry.id === cycle.id)) {
                    if (cycles.length >= limits.cycles) cyclesTruncated = true;
                    else cycles.push(cycle);
                }
                emit(nextNodePath, edgePath, {
                    terminalIssue: {
                        reasonCode: "cycle-detected",
                        edge: edge.semanticKey,
                        target: target.semanticKey,
                    },
                });
                continue;
            }
            visit(
                target,
                nextNodePath,
                [...edgePath, edge],
                new Set([...visited, target.semanticKey]),
            );
        }
    };

    for (const start of starts) {
        visit(start, [], [], new Set([start.semanticKey]));
    }

    const orderedChains = [...chains.values()].sort((left, right) =>
        left.priority - right.priority || left.id.localeCompare(right.id));
    const truncation = {
        ...mergeResult.truncation,
        chains: chainsTruncated,
        branches: branchesTruncated,
        depth: depthTruncated,
        cycles: cyclesTruncated,
        validationItems: validation.truncated,
        evidence: evidenceTruncated,
        paths: pathsTruncated,
        semanticBindings: semanticBindingsTruncated,
    };
    const missingStart = starts.length === 0 && semanticNodes.size > 0;
    const coverageComplete = mergeResult.coverageComplete
        && !Object.values(truncation).some(Boolean)
        && !missingStart;
    if (missingStart) {
        blockers.push({ code: "no-activation-or-trigger-root" });
    }
    if (chainsTruncated) blockers.push({ code: "trace-chain-cap-exceeded", cap: limits.chains });
    if (branchesTruncated) {
        blockers.push({ code: "trace-branch-cap-exceeded", cap: limits.branches });
    }
    if (depthTruncated) blockers.push({ code: "trace-depth-cap-exceeded", cap: limits.depth });
    if (cyclesTruncated) blockers.push({ code: "trace-cycle-cap-exceeded", cap: limits.cycles });
    if (evidenceTruncated) {
        blockers.push({ code: "trace-chain-evidence-cap-exceeded", cap: limits.evidencePerChain });
    }
    if (pathsTruncated) {
        blockers.push({ code: "trace-chain-path-cap-exceeded", cap: limits.pathsPerChain });
    }
    if (semanticBindingsTruncated) {
        blockers.push({ code: "trace-semantic-binding-cap-exceeded" });
    }

    return Object.freeze(structuredClone({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: mergeResult.auditId,
        sourceNamespace: mergeResult.sourceNamespace,
        inputFingerprint: mergeResult.inputFingerprint,
        coverageComplete,
        counts: {
            ...mergeResult.counts,
            semanticNodes: semanticNodes.size,
            semanticEdges: semanticEdges.size,
            chains: orderedChains.length,
            completeChains: orderedChains.filter((chain) => chain.status === "complete").length,
            unresolvedChains: orderedChains.filter((chain) => chain.status === "unresolved").length,
            contestedChains: orderedChains.filter((chain) => chain.status === "contested").length,
            cycles: cycles.length,
            exploredBranches: branchCount,
        },
        truncation,
        blockers,
        validationQueue: validation.items,
        cycles,
        chains: orderedChains,
    }));
}

export const __internals = Object.freeze({
    canonicalJson,
    hash,
    normalizeLimits,
    semanticTokens,
    orderedPositions,
    classifyPattern,
    mergeSemanticNodes,
    mergeSemanticEdges,
    chainIdentity,
});
