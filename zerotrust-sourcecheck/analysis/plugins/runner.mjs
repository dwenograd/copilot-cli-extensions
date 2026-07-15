import { createHash } from "node:crypto";

import { computeCachedPluginFactId } from "../cache.mjs";
import { buildAnalysisIndexSnapshot } from "../indexState.mjs";
import { validateAuditId } from "../schemas.mjs";
import { validatePluginExecutionResult } from "./contract.mjs";
import {
    PLUGIN_EXECUTION_LIMITS,
    buildPluginContext,
} from "./helpers.mjs";
import { PLUGIN_REGISTRY } from "./registry.mjs";

export const PLUGIN_RUNNER_SCHEMA_VERSION = 1;
export const PLUGIN_RUNNER_LIMITS = Object.freeze({
    blockers: 64,
    blockerMessage: 300,
    snapshotFacts: 1024,
});

function sanitizeMessage(value) {
    return String(value || "plugin execution failed")
        .normalize("NFKC")
        .replace(/[\u0000-\u001f\u007f]+/gu, " ")
        .replace(/\s+/gu, " ")
        .trim()
        .slice(0, PLUGIN_RUNNER_LIMITS.blockerMessage);
}

function pluginRecord(plugin) {
    return {
        pluginId: plugin.id,
        pluginVersion: plugin.version,
        supported: false,
        detected: false,
        completed: false,
        failed: false,
        truncated: false,
        nodeCount: 0,
        edgeCount: 0,
        factCount: 0,
        warningCount: 0,
        facts: [],
        nodes: [],
        edges: [],
        warnings: [],
        error: null,
    };
}

export function createPluginRunnerState({
    auditId,
    registry = PLUGIN_REGISTRY,
} = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    return {
        schemaVersion: PLUGIN_RUNNER_SCHEMA_VERSION,
        auditId: normalizedAuditId,
        runCount: 0,
        indexFingerprint: null,
        coverageComplete: false,
        plugins: registry.map(pluginRecord),
        blockers: [],
        blockersTruncated: false,
    };
}

function ensureState(state, auditId) {
    if (!state || state.schemaVersion !== PLUGIN_RUNNER_SCHEMA_VERSION
        || state.auditId !== validateAuditId(auditId)
        || !Array.isArray(state.plugins)
        || !Array.isArray(state.blockers)) {
        throw new TypeError("invalid audit-bound plugin runner state");
    }
}

function appendBlocker(state, pluginId, kind, message) {
    const blocker = {
        pluginId,
        kind,
        message: sanitizeMessage(message),
    };
    if (state.blockers.some((entry) => JSON.stringify(entry) === JSON.stringify(blocker))) return;
    if (state.blockers.length >= PLUGIN_RUNNER_LIMITS.blockers) {
        state.blockersTruncated = true;
        return;
    }
    state.blockers.push(blocker);
}

function indexFingerprint(indexState) {
    const hash = createHash("sha256").update(indexState.auditId, "utf8");
    for (const file of [...indexState.files].sort((left, right) =>
        left.path.localeCompare(right.path))) {
        hash.update("\0file\0", "utf8");
        hash.update(file.path, "utf8");
        hash.update("\0", "utf8");
        hash.update(file.status || "", "utf8");
        hash.update("\0", "utf8");
        hash.update(file.blobSha || "", "utf8");
        hash.update("\0", "utf8");
        hash.update(file.contentSha256 || "", "utf8");
    }
    for (const fact of [...indexState.facts].sort((left, right) =>
        left.id.localeCompare(right.id))) {
        hash.update("\0fact\0", "utf8");
        hash.update(fact.id, "utf8");
        hash.update("\0", "utf8");
        hash.update(fact.excerptHash, "utf8");
    }
    return hash.digest("hex");
}

function graphSummary(behaviorGraph) {
    return Object.freeze({
        auditId: behaviorGraph.auditId,
        nodeCount: behaviorGraph.nodeCount,
        edgeCount: behaviorGraph.edgeCount,
    });
}

function cacheFactValue(value) {
    const normalized = String(value || "")
        .normalize("NFKC")
        .replace(/[^A-Za-z0-9_$@./:+?&=%#,-]+/gu, "-")
        .replace(/-{2,}/gu, "-")
        .replace(/^-+|-+$/gu, "")
        .slice(0, 512);
    return normalized || "activation-surface";
}

function evidenceKey(value) {
    return `${value.path}\0${value.startLine ?? value.line}\0`
        + `${value.endLine}\0${value.excerptHash}`;
}

function pluginFactSummary(plugin, fact) {
    const node = plugin.nodes.find((entry) =>
        (entry.evidence || []).some((evidence) => evidenceKey(evidence) === evidenceKey(fact)));
    return {
        id: fact.id,
        pluginId: plugin.pluginId,
        pluginVersion: plugin.pluginVersion,
        kind: fact.kind,
        name: fact.name,
        ...(fact.value ? { value: fact.value } : {}),
        path: fact.path,
        line: fact.line,
        endLine: fact.endLine,
        excerptHash: fact.excerptHash,
        ...(node?.sourceIdentity ? { sourceIdentity: node.sourceIdentity } : {}),
    };
}

export function buildPluginRunnerSnapshot(state, behaviorGraph = null) {
    const detected = state.plugins.filter((plugin) => plugin.detected);
    const completed = state.plugins.filter((plugin) => plugin.completed);
    const failed = state.plugins.filter((plugin) => plugin.failed);
    const truncated = state.plugins.filter((plugin) => plugin.truncated);
    const allFacts = state.plugins.flatMap((plugin) =>
        plugin.facts.map((fact) => pluginFactSummary(plugin, fact)));
    return Object.freeze(structuredClone({
        schemaVersion: state.schemaVersion,
        auditId: state.auditId,
        runCount: state.runCount,
        indexFingerprint: state.indexFingerprint,
        coverageComplete: state.coverageComplete,
        counts: {
            registered: state.plugins.length,
            supported: state.plugins.filter((plugin) => plugin.supported).length,
            detected: detected.length,
            completed: completed.length,
            failed: failed.length,
            truncated: truncated.length,
        },
        plugins: state.plugins.map(({ facts, nodes, edges, ...plugin }) => plugin),
        facts: allFacts.slice(0, PLUGIN_RUNNER_LIMITS.snapshotFacts),
        factCount: allFacts.length,
        factsTruncated: allFacts.length > PLUGIN_RUNNER_LIMITS.snapshotFacts,
        blockers: state.blockers,
        blockersTruncated: state.blockersTruncated,
        behaviorGraph: behaviorGraph ? graphSummary(behaviorGraph) : null,
    }));
}

export function buildPluginCacheRecords(state) {
    ensureState(state, state?.auditId);
    const records = state.plugins
        .filter((plugin) =>
            plugin.detected
            && plugin.completed
            && !plugin.failed
            && !plugin.truncated
            && plugin.facts.length > 0)
        .map((plugin) => {
            const sourceBlobs = new Map();
            for (const node of plugin.nodes) {
                if (!node.sourceIdentity) continue;
                const sourceBlob = {
                    path: node.sourceIdentity.path,
                    contentSha256: node.sourceIdentity.contentSha256,
                    ...(node.sourceIdentity.blobSha
                        ? { blobSha: node.sourceIdentity.blobSha }
                        : {}),
                };
                sourceBlobs.set(sourceBlob.path, sourceBlob);
            }
            const nodes = plugin.nodes.map((node) => ({
                id: node.id,
                kind: node.kind,
                producer: node.producer,
                evidence: node.evidence,
                ...(node.sourceIdentity ? { sourceIdentity: node.sourceIdentity } : {}),
                ...(node.behaviorSignature ? { behaviorSignature: node.behaviorSignature } : {}),
                ...(node.tags ? { tags: node.tags } : {}),
            }));
            const edges = plugin.edges.map((edge) => ({
                id: edge.id,
                kind: edge.kind,
                from: edge.from,
                to: edge.to,
                producer: edge.producer,
                evidence: edge.evidence,
                ...(edge.tags ? { tags: edge.tags } : {}),
            }));
            const evidenceNodes = new Map();
            for (const node of plugin.nodes) {
                if (!node.sourceIdentity) continue;
                for (const evidence of node.evidence) {
                    if (!evidenceNodes.has(evidenceKey(evidence))) {
                        evidenceNodes.set(evidenceKey(evidence), node);
                    }
                }
            }
            const cachedFacts = new Map();
            for (const fact of plugin.facts) {
                const node = evidenceNodes.get(evidenceKey(fact));
                if (!node) {
                    throw new Error(
                        `${plugin.pluginId} cache fact has no evidence-bound graph node`,
                    );
                }
                const cachedFact = {
                    kind: "activation-surface",
                    name: fact.name,
                    value: cacheFactValue(fact.value || fact.name),
                    producer: plugin.pluginId,
                    sourceIdentity: node.sourceIdentity,
                    evidence: node.evidence,
                    tags: node.tags || [],
                };
                cachedFact.id = computeCachedPluginFactId(cachedFact);
                cachedFacts.set(cachedFact.id, cachedFact);
            }
            return {
                pluginId: plugin.pluginId,
                pluginVersion: plugin.pluginVersion,
                sourceBlobs: [...sourceBlobs.values()]
                    .sort((left, right) => left.path.localeCompare(right.path)),
                facts: [...cachedFacts.values()],
                nodes,
                edges,
                findings: [],
                validationDecisions: [],
            };
        })
        .filter((record) => record.sourceBlobs.length > 0);
    return Object.freeze(structuredClone(records));
}

export function runAnalysisPlugins({
    auditId,
    indexState,
    behaviorGraph,
    state,
    sourceNamespace,
    registry = PLUGIN_REGISTRY,
    limits = PLUGIN_EXECUTION_LIMITS,
} = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    ensureState(state, normalizedAuditId);
    if (!behaviorGraph || behaviorGraph.auditId !== normalizedAuditId) {
        throw new TypeError("plugin runner requires the matching active BehaviorGraph");
    }
    const index = buildAnalysisIndexSnapshot(indexState);
    if (index.auditId !== normalizedAuditId) {
        throw new TypeError("plugin runner analysis index auditId mismatch");
    }
    if (!index.complete) return buildPluginRunnerSnapshot(state, behaviorGraph);

    const fingerprint = indexFingerprint(indexState);
    if (state.runCount > 0 && state.indexFingerprint === fingerprint) {
        return buildPluginRunnerSnapshot(state, behaviorGraph);
    }
    if (state.runCount > 0 && state.indexFingerprint !== fingerprint) {
        state.coverageComplete = false;
        appendBlocker(
            state,
            "plugin-runner",
            "index-identity-changed",
            "analysis index identity changed after deterministic plugins ran",
        );
        return buildPluginRunnerSnapshot(state, behaviorGraph);
    }

    const context = buildPluginContext({
        auditId: normalizedAuditId,
        indexState,
        sourceNamespace,
    });
    state.runCount = 1;
    state.indexFingerprint = fingerprint;
    state.plugins = registry.map(pluginRecord);
    state.blockers = [];
    state.blockersTruncated = false;

    for (let indexPosition = 0; indexPosition < registry.length; indexPosition += 1) {
        const plugin = registry[indexPosition];
        const record = state.plugins[indexPosition];
        try {
            record.supported = plugin.supports(context) === true;
            if (!record.supported) {
                record.completed = true;
                continue;
            }
            try {
                record.detected = plugin.detect(context) === true;
            } catch (error) {
                record.detected = true;
                throw error;
            }
            if (!record.detected) {
                record.completed = true;
                continue;
            }
            const execution = validatePluginExecutionResult(
                plugin.run(context, { limits }),
                plugin,
            );
            if (execution.output.auditId !== normalizedAuditId
                || execution.output.coverageScope !== context.coverageScope) {
                throw new TypeError(`${plugin.id} output is not bound to the active audit coverage`);
            }
            behaviorGraph.mergePluginOutput(execution.output);
            record.completed = execution.truncated !== true;
            record.truncated = execution.truncated === true;
            record.nodeCount = execution.output.nodes.length;
            record.edgeCount = execution.output.edges.length;
            record.factCount = execution.facts.length;
            record.facts = execution.facts;
            record.nodes = execution.output.nodes;
            record.edges = execution.output.edges;
            record.warningCount = execution.output.warnings.length;
            record.warnings = execution.output.warnings;
            if (record.truncated) {
                appendBlocker(
                    state,
                    plugin.id,
                    "plugin-output-truncated",
                    "detected ecosystem plugin exceeded its bounded output",
                );
            }
        } catch (error) {
            record.failed = true;
            record.completed = false;
            record.error = sanitizeMessage(error instanceof Error ? error.message : error);
            appendBlocker(state, plugin.id, "plugin-failed", record.error);
        }
    }

    state.coverageComplete = state.plugins.every((plugin) =>
        !plugin.supported
        || !plugin.detected
        || (plugin.completed && !plugin.failed && !plugin.truncated));
    return buildPluginRunnerSnapshot(state, behaviorGraph);
}

export const __internals = Object.freeze({
    sanitizeMessage,
    appendBlocker,
    indexFingerprint,
    graphSummary,
    cacheFactValue,
    evidenceKey,
    pluginFactSummary,
    pluginRecord,
});
