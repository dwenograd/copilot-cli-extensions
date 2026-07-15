import { createHash } from "node:crypto";
import nodePath from "node:path";

import {
    ANALYSIS_SCHEMA_VERSION,
    LIMITS,
    validateAuditId,
} from "../schemas.mjs";
import {
    computePluginFactId,
    definePlugin,
} from "./contract.mjs";

export const PLUGIN_EXECUTION_LIMITS = Object.freeze({
    nodesPerPlugin: 512,
    edgesPerPlugin: 512,
    factsPerPlugin: 512,
    warningsPerPlugin: LIMITS.pluginWarnings,
});

const SUPPORTED_SOURCE_KINDS = new Set([
    "api-direct",
    "local-source",
    "build-clone",
]);

const MANIFEST_BASENAMES = new Set([
    "package.json",
    "manifest.json",
    "extension.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "cargo.toml",
    "cargo.lock",
    "cmakelists.txt",
    "makefile",
    "gnumakefile",
    "dockerfile",
    "containerfile",
    "devcontainer.json",
]);

function cloneFrozen(value) {
    return Object.freeze(structuredClone(value));
}

function normalizeLabel(value) {
    return String(value || "")
        .normalize("NFKC")
        .replace(/[\u0000-\u001f\u007f]+/gu, " ")
        .replace(/\s+/gu, " ")
        .trim()
        .slice(0, LIMITS.label);
}

function normalizeTag(value) {
    const normalized = String(value || "")
        .normalize("NFKC")
        .toLowerCase()
        .replace(/[^a-z0-9._:/@-]+/gu, "-")
        .replace(/-{2,}/gu, "-")
        .replace(/^-+|-+$/gu, "")
        .slice(0, LIMITS.tag);
    return /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,63}$/u.test(normalized)
        ? normalized
        : null;
}

function stableId(pluginId, kind, parts) {
    const digest = createHash("sha256")
        .update(pluginId, "utf8")
        .update("\0", "utf8")
        .update(kind, "utf8")
        .update("\0", "utf8")
        .update(parts.join("\0"), "utf8")
        .digest("hex")
        .slice(0, 32);
    return `${pluginId}.${kind}.${digest}`;
}

function isManifestPath(path) {
    const normalized = path.toLowerCase();
    const base = nodePath.posix.basename(normalized);
    return MANIFEST_BASENAMES.has(base)
        || base.endsWith(".csproj")
        || base.endsWith(".props")
        || base.endsWith(".targets")
        || base.endsWith(".cmake")
        || base.endsWith(".mk")
        || normalized.startsWith(".github/workflows/")
        || normalized.startsWith(".devcontainer/");
}

export function defaultPluginSupports(context) {
    return SUPPORTED_SOURCE_KINDS.has(context.sourceKind);
}

export function buildPluginContext({
    auditId,
    indexState,
    sourceNamespace,
} = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    if (!indexState || indexState.auditId !== normalizedAuditId
        || !Array.isArray(indexState.files) || !Array.isArray(indexState.facts)) {
        throw new TypeError("plugin context requires the matching normalized analysis index");
    }
    const namespace = String(sourceNamespace || `audit:${normalizedAuditId}`)
        .normalize("NFKC")
        .slice(0, LIMITS.namespace);
    const fileByPath = new Map();
    const files = indexState.files.map((file) => {
        const normalized = Object.freeze({
            path: file.path,
            status: file.status,
            classification: file.classification,
            contentSha256: file.contentSha256,
            blobSha: file.blobSha || null,
            lineCount: file.lineCount,
        });
        fileByPath.set(normalized.path, normalized);
        return normalized;
    });
    const facts = indexState.facts.map((fact) => {
        const file = fileByPath.get(fact.path);
        if (!file || file.status !== "indexed-text" || !file.contentSha256) {
            throw new TypeError(`plugin fact is not tied to fully indexed text: ${fact.path}`);
        }
        return Object.freeze({ ...fact, file });
    });
    const factsByPath = new Map();
    for (const fact of facts) {
        const existing = factsByPath.get(fact.path) || [];
        existing.push(fact);
        factsByPath.set(fact.path, existing);
    }
    const manifests = files
        .filter((file) => isManifestPath(file.path))
        .map((file) => Object.freeze({
            ...file,
            facts: Object.freeze([...(factsByPath.get(file.path) || [])]),
        }));
    return Object.freeze({
        auditId: normalizedAuditId,
        sourceKind: indexState.sourceKind,
        sourceNamespace: namespace,
        coverageScope: indexState.sourceKind === "local-source"
            ? "local_source"
            : "mandatory",
        files: Object.freeze(files),
        facts: Object.freeze(facts),
        manifests: Object.freeze(manifests),
    });
}

function evidenceFor(context, pluginId, fact) {
    return Object.freeze({
        path: fact.path,
        startLine: fact.line,
        endLine: fact.endLine,
        blobSha: fact.file.blobSha || fact.file.contentSha256,
        excerptHash: fact.excerptHash,
        producer: pluginId,
        coverageScope: context.coverageScope,
    });
}

function sourceIdentityFor(context, fact) {
    const sourceIdentity = {
        type: context.sourceKind === "local-source" ? "local-file" : "git-blob",
        namespace: context.sourceNamespace,
        path: fact.path,
        contentSha256: fact.file.contentSha256,
    };
    if (fact.file.blobSha) {
        sourceIdentity.blobSha = fact.file.blobSha;
    } else if (context.sourceKind === "local-source") {
        sourceIdentity.blobSha = fact.file.contentSha256;
    }
    return Object.freeze(sourceIdentity);
}

export function createSeedCollector(context, plugin, limits = {}) {
    const maxNodes = Math.min(
        Number.isSafeInteger(limits.nodesPerPlugin)
            ? limits.nodesPerPlugin
            : PLUGIN_EXECUTION_LIMITS.nodesPerPlugin,
        PLUGIN_EXECUTION_LIMITS.nodesPerPlugin,
    );
    const maxEdges = Math.min(
        Number.isSafeInteger(limits.edgesPerPlugin)
            ? limits.edgesPerPlugin
            : PLUGIN_EXECUTION_LIMITS.edgesPerPlugin,
        PLUGIN_EXECUTION_LIMITS.edgesPerPlugin,
    );
    const maxFacts = Math.min(
        Number.isSafeInteger(limits.factsPerPlugin)
            ? limits.factsPerPlugin
            : PLUGIN_EXECUTION_LIMITS.factsPerPlugin,
        PLUGIN_EXECUTION_LIMITS.factsPerPlugin,
    );
    const nodes = new Map();
    const edges = new Map();
    const facts = new Map();
    const warnings = [];
    let truncated = false;

    const addWarning = (warning) => {
        const normalized = normalizeLabel(warning).slice(0, LIMITS.pluginWarning);
        if (!normalized || warnings.includes(normalized)) return;
        if (warnings.length >= PLUGIN_EXECUTION_LIMITS.warningsPerPlugin) {
            truncated = true;
            return;
        }
        warnings.push(normalized);
    };

    const addNode = (node) => {
        const existing = nodes.get(node.id);
        if (existing) {
            if (JSON.stringify(existing) !== JSON.stringify(node)) {
                throw new Error(`conflicting plugin node id: ${node.id}`);
            }
            return true;
        }
        if (nodes.size >= maxNodes) {
            truncated = true;
            return false;
        }
        nodes.set(node.id, Object.freeze(node));
        return true;
    };

    const addEdge = (edge) => {
        const existing = edges.get(edge.id);
        if (existing) {
            if (JSON.stringify(existing) !== JSON.stringify(edge)) {
                throw new Error(`conflicting plugin edge id: ${edge.id}`);
            }
            return;
        }
        if (edges.size >= maxEdges) {
            truncated = true;
            return;
        }
        edges.set(edge.id, Object.freeze(edge));
    };

    const addFact = ({ fact }) => {
        const pluginFact = {
            id: fact.id,
            kind: fact.kind,
            path: fact.path,
            line: fact.line,
            endLine: fact.endLine,
            excerptHash: fact.excerptHash,
            name: fact.name,
            ...(fact.value ? { value: fact.value } : {}),
        };
        if (pluginFact.id !== computePluginFactId(pluginFact)) {
            throw new Error(`non-canonical normalized fact: ${fact.id}`);
        }
        const existing = facts.get(pluginFact.id);
        if (existing) return existing;
        if (facts.size >= maxFacts) {
            truncated = true;
            return null;
        }
        const frozen = Object.freeze(pluginFact);
        facts.set(frozen.id, frozen);
        return frozen;
    };

    const addSurface = ({
        fact,
        key,
        activationKind = "activation",
        activationLabel,
        targetKind = "capability",
        targetLabel,
        edgeKind = "invokes",
        tags = [],
    }) => {
        if (!fact?.file || !context.facts.includes(fact)) {
            throw new TypeError(`${plugin.id} seed fact is not from its plugin context`);
        }
        const pluginFact = addFact({ fact });
        if (!pluginFact) return;
        const evidence = Object.freeze([evidenceFor(context, plugin.id, fact)]);
        const sourceIdentity = sourceIdentityFor(context, fact);
        const normalizedTags = [...new Set(tags.map(normalizeTag).filter(Boolean))].sort();
        const activationId = stableId(plugin.id, "node", [
            "activation",
            String(key),
            fact.id,
            sourceIdentity.contentSha256,
        ]);
        const targetId = stableId(plugin.id, "node", [
            "target",
            String(key),
            fact.id,
            sourceIdentity.contentSha256,
        ]);
        const activationAdded = addNode({
            schemaVersion: ANALYSIS_SCHEMA_VERSION,
            auditId: context.auditId,
            id: activationId,
            kind: activationKind,
            label: normalizeLabel(activationLabel),
            producer: plugin.id,
            evidence,
            sourceIdentity,
            tags: normalizedTags,
        });
        const targetAdded = addNode({
            schemaVersion: ANALYSIS_SCHEMA_VERSION,
            auditId: context.auditId,
            id: targetId,
            kind: targetKind,
            label: normalizeLabel(targetLabel),
            producer: plugin.id,
            evidence,
            sourceIdentity,
            tags: normalizedTags,
        });
        if (!activationAdded || !targetAdded) return;
        addEdge({
            schemaVersion: ANALYSIS_SCHEMA_VERSION,
            auditId: context.auditId,
            id: stableId(plugin.id, "edge", [activationId, edgeKind, targetId]),
            kind: edgeKind,
            from: activationId,
            to: targetId,
            producer: plugin.id,
            evidence,
            tags: normalizedTags,
        });
    };

    const finish = () => Object.freeze({
        output: {
            schemaVersion: ANALYSIS_SCHEMA_VERSION,
            auditId: context.auditId,
            pluginId: plugin.id,
            pluginVersion: plugin.version,
            producer: plugin.id,
            coverageScope: context.coverageScope,
            nodes: [...nodes.values()],
            edges: [...edges.values()],
            findings: [],
            validationDecisions: [],
            metadataDocuments: [],
            warnings,
        },
        facts: [...facts.values()],
        truncated,
    });

    return Object.freeze({ addSurface, addWarning, finish });
}

export function defineRulePlugin({
    id,
    version = "5.0.0",
    detect,
    select,
    seed,
    detectedWarning,
    emptyWarning,
}) {
    return definePlugin({
        id,
        version,
        supports: defaultPluginSupports,
        detect,
        run(context, runtime = {}) {
            const collector = createSeedCollector(context, { id, version }, runtime.limits);
            const matches = select(context);
            for (const fact of matches) collector.addSurface(seed(fact));
            collector.addWarning(matches.length > 0
                ? detectedWarning(matches.length)
                : emptyWarning);
            return collector.finish();
        },
    });
}

export function basename(path) {
    return nodePath.posix.basename(String(path || "").toLowerCase());
}

export function pathMatches(path, pattern) {
    return pattern.test(String(path || "").replace(/\\/g, "/").toLowerCase());
}

export const __internals = Object.freeze({
    normalizeLabel,
    normalizeTag,
    stableId,
    isManifestPath,
    evidenceFor,
    sourceIdentityFor,
    cloneFrozen,
});
