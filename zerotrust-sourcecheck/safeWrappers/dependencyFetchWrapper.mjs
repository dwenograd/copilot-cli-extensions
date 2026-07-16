import { createHash } from "node:crypto";
import https from "node:https";

import {
    DEPENDENCY_INVENTORY_LIMITS,
    DEPENDENCY_REGISTRY_HOSTS,
    parseDependencyManifests,
} from "../analysis/dependencyInventory.mjs";
import {
    SUPPLY_CHAIN_LIMITS,
    analyzeSupplyChain,
    applySupplyChainGraphToAssuranceSnapshot,
    buildSupplyChainGraph,
} from "../analysis/supplyChainGraph.mjs";
import {
    getAnalysisIndexState,
    getTrustedAuditContext,
    getAssuranceSnapshot,
    getAssuranceState,
    recordAssuranceSnapshot,
    recordAssuranceSupplyChainGraph,
} from "../enforcement.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";

const ALLOWED_ARGUMENTS = new Set([
    "audit_id",
    "manifests",
    "limits",
    "build_root",
]);

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function normalizeManifestPath(value) {
    const normalized = String(value || "").replace(/\\/gu, "/").replace(/^\.\/+/u, "");
    if (!normalized || normalized.length > 4_096 || normalized.startsWith("/")
        || normalized.endsWith("/") || normalized.includes("//")
        || /[\u0000-\u001f\u007f]/u.test(normalized)
        || normalized.split("/").some((part) => !part || part === "." || part === "..")) {
        throw new TypeError("manifest path must be a normalized relative path");
    }
    return normalized;
}

function decodeManifestInputs(manifests, indexState) {
    if (!Array.isArray(manifests) || manifests.length === 0
        || manifests.length > DEPENDENCY_INVENTORY_LIMITS.manifests) {
        throw new TypeError(
            `manifests must contain 1-${DEPENDENCY_INVENTORY_LIMITS.manifests} entries`,
        );
    }
    const indexedByPath = new Map(
        (indexState?.files || []).map((file) => [file.path, file]),
    );
    const seen = new Set();
    return manifests.map((manifest, index) => {
        if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
            throw new TypeError(`manifests[${index}] must be an object`);
        }
        const unexpected = Object.keys(manifest)
            .filter((key) => !["path", "content", "content_sha256"].includes(key));
        if (unexpected.length > 0) {
            throw new TypeError(`manifests[${index}] has unsupported fields`);
        }
        const path = normalizeManifestPath(manifest.path);
        if (seen.has(path)) throw new TypeError(`duplicate dependency manifest path: ${path}`);
        seen.add(path);
        if (typeof manifest.content !== "string"
            || Buffer.byteLength(manifest.content, "utf8")
                > DEPENDENCY_INVENTORY_LIMITS.manifestBytes) {
            throw new TypeError(`manifest content is missing or over cap: ${path}`);
        }
        const contentSha256 = sha256(Buffer.from(manifest.content, "utf8"));
        if (!/^[a-f0-9]{64}$/iu.test(String(manifest.content_sha256 || ""))
            || contentSha256 !== String(manifest.content_sha256).toLowerCase()) {
            throw new TypeError(`manifest content SHA-256 mismatch: ${path}`);
        }
        const indexed = indexedByPath.get(path);
        if (!indexed
            || indexed.status !== "indexed-text"
            || indexed.classification !== "text"
            || indexed.contentSha256 !== contentSha256
            || indexed.size !== Buffer.byteLength(manifest.content, "utf8")) {
            throw new TypeError(
                `manifest is not bound to exact fully indexed audit bytes: ${path}`,
            );
        }
        return {
            path,
            text: manifest.content,
            contentSha256,
        };
    });
}

function lowerOnlyLimits(value) {
    if (value === undefined || value === null) return {};
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError("limits must be an object");
    }
    const result = {};
    for (const [key, entry] of Object.entries(value)) {
        if (!Object.hasOwn(SUPPLY_CHAIN_LIMITS, key)) {
            throw new TypeError(`unsupported dependency limit: ${key}`);
        }
        const minimum = ["maxDepth", "maxRedirects", "maxArchiveDepth"].includes(key)
            ? 0: 1;
        if (!Number.isSafeInteger(entry)
            || entry < minimum
            || entry > SUPPLY_CHAIN_LIMITS[key]) {
            throw new TypeError(
                `${key} must be an integer from ${minimum} through ${SUPPLY_CHAIN_LIMITS[key]}`,
            );
        }
        result[key] = entry;
    }
    return result;
}

function safeDecodedBasename(pathname) {
    const raw = pathname.split("/").filter(Boolean).at(-1) || "";
    try {
        return decodeURIComponent(raw);
    } catch {
        return "";
    }
}

export function validateDependencyRegistryUrl(value, {
    kind = "artifact",
    expectedFileName = null,
} = {}) {
    let url;
    try {
        url = new URL(value);
    } catch {
        throw new TypeError("dependency URL is invalid");
    }
    const host = url.hostname.toLowerCase();
    if (url.protocol !== "https:"
        || url.username
        || url.password
        || (url.port && url.port !== "443")
        || url.hash
        || !DEPENDENCY_REGISTRY_HOSTS.includes(host)) {
        throw new TypeError("dependency URL is outside the strict HTTPS registry allowlist");
    }
    const path = url.pathname;
    const validPath = (
        ["registry.npmjs.org", "registry.yarnpkg.com"].includes(host)
            && (kind === "artifact" ? /\.tgz$/iu.test(path): path.length > 1)
    ) || (
        host === "pypi.org"
            && kind === "metadata"
            && /^\/pypi\/[^/]+\/[^/]+\/json$/u.test(path)
    ) || (
        host === "files.pythonhosted.org"
            && kind === "artifact"
            && /^\/packages\/[^?]+/u.test(path)
            && /\.(?:whl|zip|tar\.gz|tgz)$/iu.test(path)
    ) || (
        host === "static.crates.io"
            && kind === "artifact"
            && /^\/crates\/[^/]+\/[^/]+\.crate$/u.test(path)
    ) || (
        host === "api.nuget.org"
            && kind === "artifact"
            && /^\/v3-flatcontainer\/[^/]+\/[^/]+\/[^/]+\.nupkg$/iu.test(path)
    );
    if (!validPath) throw new TypeError("dependency URL path is not allowlisted");
    if (expectedFileName !== null
        && safeDecodedBasename(path) !== String(expectedFileName)) {
        throw new TypeError("dependency artifact filename does not match locked metadata");
    }
    return url;
}

function responseBuffer(response, {
    maxBytes,
    remainingTotalBytes,
}) {
    return new Promise((resolve, reject) => {
        const cap = Math.min(maxBytes, remainingTotalBytes);
        const declared = Number(response.headers["content-length"]);
        if (Number.isFinite(declared) && declared > cap) {
            response.resume();
            reject(new Error("dependency response exceeds the byte cap"));
            return;
        }
        const encoding = String(response.headers["content-encoding"] || "identity").toLowerCase();
        if (!["", "identity"].includes(encoding)) {
            response.resume();
            reject(new Error("compressed HTTP transfer encoding is not accepted"));
            return;
        }
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
            length += chunk.length;
            if (length > cap) {
                response.destroy(new Error("dependency response exceeded the byte cap"));
                return;
            }
            chunks.push(chunk);
        });
        response.once("end", () => resolve(Buffer.concat(chunks, length)));
        response.once("error", reject);
    });
}

export async function fetchDependencyHttpsBuffer(urlValue, {
    kind,
    packageRecord,
    expectedFileName = null,
    limits = SUPPLY_CHAIN_LIMITS,
    remainingTotalBytes = SUPPLY_CHAIN_LIMITS.maxTotalBytes,
    redirectCount = 0,
    requestImpl = https.request,
} = {}) {
    const url = validateDependencyRegistryUrl(urlValue, { kind, expectedFileName });
    if (!packageRecord
        || typeof packageRecord.packageId !== "string"
        || packageRecord.registryHost === null
        || packageRecord.registryHost === undefined) {
        throw new TypeError("dependency fetch requires a locked package record");
    }
    if (url.hostname.toLowerCase() !== packageRecord.registryHost
        && !(packageRecord.ecosystem === "python"
            && packageRecord.registryHost === "pypi.org"
            && url.hostname.toLowerCase() === "files.pythonhosted.org")) {
        throw new TypeError("dependency URL host does not match the locked registry");
    }
    const response = await new Promise((resolve, reject) => {
        const request = requestImpl(url, {
            method: "GET",
            headers: {
                "accept": kind === "metadata" ? "application/json": "application/octet-stream",
                "accept-encoding": "identity",
                "user-agent": "zerotrust-sourcecheck dependency-audit",
            },
            agent: false,
        }, resolve);
        request.once("error", reject);
        request.setTimeout(limits.requestTimeoutMs, () => {
            request.destroy(new Error("dependency request timed out"));
        });
        request.end();
    });
    const status = Number(response.statusCode || 0);
    if ([301, 302, 303, 307, 308].includes(status)) {
        response.resume();
        if (redirectCount >= limits.maxRedirects) {
            throw new Error("dependency redirect cap exceeded");
        }
        const location = response.headers.location;
        if (!location) throw new Error("dependency redirect omitted Location");
        const redirected = new URL(location, url);
        validateDependencyRegistryUrl(redirected, { kind, expectedFileName });
        return fetchDependencyHttpsBuffer(redirected, {
            kind,
            packageRecord,
            expectedFileName,
            limits,
            remainingTotalBytes,
            redirectCount: redirectCount + 1,
            requestImpl,
        });
    }
    if (status !== 200) {
        response.resume();
        throw new Error(`dependency registry returned HTTP ${status}`);
    }
    return responseBuffer(response, {
        maxBytes: limits.maxResponseBytes,
        remainingTotalBytes,
    });
}

function graphSummary(graph) {
    const packages = graph.nodes
        .filter((node) => node.nodeKind === "package")
        .slice(0, 100)
        .map((node) => ({
            packageId: node.packageId,
            ecosystem: node.ecosystem,
            name: node.name,
            version: node.version,
            sourceType: node.sourceType,
            registryHost: node.registryHost,
            status: node.status,
            lifecycleHooks: node.lifecycleHooks,
            buildHooks: node.buildHooks,
            blockerCodes: node.blockerCodes,
            artifactNodeId: node.analysis?.artifactNodeId || null,
            factCount: node.analysis?.factCount || 0,
        }));
    const provenance = graph.nodes
        .filter((node) => node.nodeKind === "provenance")
        .slice(0, 100)
        .map((node) => ({
            nodeId: node.nodeId,
            kind: node.kind,
            manifestId: node.manifestId || null,
            path: node.path || null,
            host: node.host || null,
            url: node.url || null,
        }));
    const edges = graph.edges.slice(0, 200).map((edge) => ({
        edgeId: edge.edgeId,
        kind: edge.kind,
        fromNodeId: edge.fromNodeId,
        toNodeId: edge.toNodeId,
    }));
    return {
        schemaVersion: graph.schemaVersion,
        graphId: graph.graphId,
        auditId: graph.auditId,
        sourceNamespace: graph.sourceNamespace,
        status: graph.status,
        blockerCodes: graph.blockerCodes,
        blockerDetails: graph.blockerDetails,
        counts: graph.counts,
        packages,
        packagesTruncated: graph.counts.packages > packages.length,
        provenance,
        provenanceTruncated: graph.counts.provenance > provenance.length,
        edges,
        edgesTruncated: graph.counts.edges > edges.length,
        hashes: graph.hashes,
    };
}

async function dependencyHandler(args, invocation, {
    fetchArtifacts,
    getContext = getTrustedAuditContext,
    getIndexState = getAnalysisIndexState,
    getAssuranceState: getState = getAssuranceState,
    getAssuranceSnapshot: getSnapshot = getAssuranceSnapshot,
    recordAssuranceSnapshot: recordSnapshot = recordAssuranceSnapshot,
    recordAssuranceSupplyChainGraph: recordSupplyChain = recordAssuranceSupplyChainGraph,
    fetchBuffer = fetchDependencyHttpsBuffer,
} = {}) {
    args = args || {};
    const unexpected = Object.keys(args).filter((key) => !ALLOWED_ARGUMENTS.has(key));
    if (unexpected.length > 0) {
        return failure(`dependency audit refused unsupported fields: ${unexpected.join(", ")}`);
    }
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) return failure("dependency audit requires an active audit session");
    const ctx = getContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok || !ctx.hasActiveAudit) {
        return failure(ctx.error || "dependency audit requires an active audit");
    }
    if (String(args.audit_id || "").toLowerCase() !== ctx.auditId) {
        return failure("dependency audit_id does not match the active audit");
    }

    let limits;
    let manifestInputs;
    let assuranceState;
    try {
        limits = lowerOnlyLimits(args.limits);
        const indexState = getIndexState(sessionId, { auditId: ctx.auditId });
        manifestInputs = decodeManifestInputs(args.manifests, indexState);
        assuranceState = getState(sessionId, { auditId: ctx.auditId });
    } catch (error) {
        return failure(error.message);
    }

    let inventorySet;
    let graph;
    try {
        inventorySet = parseDependencyManifests({
            auditId: ctx.auditId,
            sourceNamespace: assuranceState.sourceNamespace,
            manifests: manifestInputs,
        });
        graph = fetchArtifacts
            ? await analyzeSupplyChain({ inventorySet, fetchBuffer, limits }): buildSupplyChainGraph({ inventorySet, limits });
    } catch (error) {
        return failure(`dependency analysis failed: ${error.message}`);
    }

    let assuranceIntegration = {
        applied: false,
        reason: "the active audit has no assurance object snapshot yet",
        snapshotId: null,
        artifactIds: [],
    };
    try {
        const snapshot = getSnapshot(sessionId, { auditId: ctx.auditId });
        if (snapshot) {
            const integrated = applySupplyChainGraphToAssuranceSnapshot({ snapshot, graph });
            if (integrated.applied) {
                const recorded = recordSnapshot(sessionId, {
                    auditId: ctx.auditId,
                    snapshot: integrated.snapshot,
                });
                assuranceIntegration = {
                    applied: true,
                    reason: null,
                    snapshotId: recorded.snapshotId,
                    artifactIds: integrated.artifacts.map((artifact) => artifact.artifactId),
                };
            } else {
                assuranceIntegration = {
                    applied: false,
                    reason: integrated.reason,
                    snapshotId: snapshot.snapshotId,
                    artifactIds: [],
                };
            }
        }
    } catch (error) {
        return failure(`dependency graph built but assurance integration failed: ${error.message}`, {
            supplyChain: graphSummary(graph),
        });
    }
    try {
        recordSupplyChain(sessionId, {
            auditId: ctx.auditId,
            graph,
        });
    } catch (error) {
        return failure(`dependency graph built but assurance binding failed: ${error.message}`, {
            supplyChain: graphSummary(graph),
        });
    }

    return success({
        fetchedArtifacts: fetchArtifacts,
        supplyChain: graphSummary(graph),
        assuranceIntegration,
    });
}

export function safeInventoryDependenciesHandler(args, invocation, dependencies = {}) {
    return dependencyHandler(args, invocation, {
        ...dependencies,
        fetchArtifacts: false,
    });
}

export function safeAnalyzeDependenciesHandler(args, invocation, dependencies = {}) {
    return dependencyHandler(args, invocation, {
        ...dependencies,
        fetchArtifacts: true,
    });
}

export const __internals = Object.freeze({
    decodeManifestInputs,
    graphSummary,
    lowerOnlyLimits,
    responseBuffer,
    safeDecodedBasename,
});
