import { createHash } from "node:crypto";

import {
    ANALYSIS_SCHEMA_VERSION,
    GRAPH_EDGE_KINDS,
    GRAPH_NODE_KINDS,
} from "../../analysis/schemas.mjs";
import {
    computePluginFactId,
    definePlugin,
} from "../../analysis/plugins/contract.mjs";

export const FIXTURE_PLUGIN_ID = "corpus.inert-markers";
export const FIXTURE_PLUGIN_VERSION = "1.0.0";
export const MARKER_FACT_NAME = "corpus-marker";

function stableId(kind, logicalId) {
    const digest = createHash("sha256")
        .update(`${kind}\0${logicalId}`, "utf8")
        .digest("hex")
        .slice(0, 32);
    return `${FIXTURE_PLUGIN_ID}.${kind}.${digest}`;
}

function tags(value) {
    if (!value) return [];
    return [...new Set(String(value).split(",").filter(Boolean))].sort();
}

function directive(fact) {
    if (fact.name !== MARKER_FACT_NAME || typeof fact.value !== "string") return null;
    const [kind, ...args] = fact.value.split("|");
    return { kind, args, fact };
}

function evidenceFor(context, fact) {
    return {
        path: fact.path,
        startLine: fact.line,
        endLine: fact.endLine,
        blobSha: fact.file.blobSha || fact.file.contentSha256,
        excerptHash: fact.excerptHash,
        producer: FIXTURE_PLUGIN_ID,
        coverageScope: context.coverageScope,
    };
}

function sourceIdentityFor(context, fact) {
    return {
        type: "local-file",
        namespace: context.sourceNamespace,
        path: fact.path,
        contentSha256: fact.file.contentSha256,
        blobSha: fact.file.blobSha || fact.file.contentSha256,
    };
}

function pluginFact(fact) {
    const normalized = {
        id: fact.id,
        kind: fact.kind,
        path: fact.path,
        line: fact.line,
        endLine: fact.endLine,
        excerptHash: fact.excerptHash,
        name: fact.name,
        value: fact.value,
    };
    if (computePluginFactId(normalized) !== normalized.id) {
        throw new Error(`fixture fact identity mismatch at ${fact.path}:${fact.line}`);
    }
    return normalized;
}

export const FIXTURE_PLUGIN = definePlugin({
    id: FIXTURE_PLUGIN_ID,
    version: FIXTURE_PLUGIN_VERSION,
    supports: (context) => context.sourceKind === "local-source",
    detect: (context) => context.facts.some((fact) => fact.name === MARKER_FACT_NAME),
    run(context) {
        const directives = context.facts.map(directive).filter(Boolean);
        const nodes = [];
        const edges = [];
        const nodeIds = new Map();

        for (const entry of directives.filter((item) => item.kind === "node")) {
            const [logicalId, kind, label, tagList = ""] = entry.args;
            if (!GRAPH_NODE_KINDS.includes(kind)) {
                throw new Error(`invalid fixture node kind: ${kind}`);
            }
            const id = stableId("node", logicalId);
            if (nodeIds.has(logicalId)) throw new Error(`duplicate fixture node: ${logicalId}`);
            nodeIds.set(logicalId, id);
            nodes.push({
                schemaVersion: ANALYSIS_SCHEMA_VERSION,
                auditId: context.auditId,
                id,
                kind,
                label,
                producer: FIXTURE_PLUGIN_ID,
                evidence: [evidenceFor(context, entry.fact)],
                sourceIdentity: sourceIdentityFor(context, entry.fact),
                tags: tags(tagList),
            });
        }

        for (const entry of directives.filter((item) => item.kind === "edge")) {
            const [logicalId, kind, from, to, tagList = ""] = entry.args;
            if (!GRAPH_EDGE_KINDS.includes(kind)) {
                throw new Error(`invalid fixture edge kind: ${kind}`);
            }
            edges.push({
                schemaVersion: ANALYSIS_SCHEMA_VERSION,
                auditId: context.auditId,
                id: stableId("edge", logicalId),
                kind,
                from: nodeIds.get(from) || stableId("node", from),
                to: nodeIds.get(to) || stableId("node", to),
                producer: FIXTURE_PLUGIN_ID,
                evidence: [evidenceFor(context, entry.fact)],
                tags: tags(tagList),
            });
        }

        return {
            output: {
                schemaVersion: ANALYSIS_SCHEMA_VERSION,
                auditId: context.auditId,
                pluginId: FIXTURE_PLUGIN_ID,
                pluginVersion: FIXTURE_PLUGIN_VERSION,
                producer: FIXTURE_PLUGIN_ID,
                coverageScope: context.coverageScope,
                nodes,
                edges,
                findings: [],
                validationDecisions: [],
                metadataDocuments: [],
                warnings: [
                    `Indexed ${directives.length} inert corpus marker declaration(s).`,
                ],
            },
            facts: directives.map((entry) => pluginFact(entry.fact)),
            truncated: false,
        };
    },
});

export const __internals = Object.freeze({
    stableId,
    tags,
    directive,
    evidenceFor,
    sourceIdentityFor,
    pluginFact,
});
