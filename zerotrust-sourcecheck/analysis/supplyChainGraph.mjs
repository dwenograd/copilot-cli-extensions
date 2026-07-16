import { createHash } from "node:crypto";

import {
    ARCHIVE_READER_LIMITS,
    detectArchiveFormat,
    getArchiveEntryBytes,
    readArchive,
} from "./archiveReaders.mjs";
import {
    DEPENDENCY_BLOCKERS,
    DEPENDENCY_BLOCKER_CODES,
    DEPENDENCY_INVENTORY_SCHEMA_REVISION,
    DEPENDENCY_REGISTRY_HOSTS,
} from "./dependencyInventory.mjs";
import { scanSourceText } from "./scanners/index.mjs";
import {
    EVASIVE_BLOCKERS,
    createEvasiveDerivedArtifactRecord,
    validateAssuranceAnalysisSnapshot,
} from "./evasiveSchemas.mjs";
import { applyDerivedArtifactsToSnapshot } from "./derivedArtifacts.mjs";

export const SUPPLY_CHAIN_GRAPH_SCHEMA_REVISION = 6;

export const SUPPLY_CHAIN_NODE_KINDS = Object.freeze([
    "package",
    "artifact",
    "provenance",
]);

export const SUPPLY_CHAIN_EDGE_KINDS = Object.freeze([
    "depends-on",
    "declared-in",
    "resolved-to",
    "fetched-from",
    "verified-by",
    "contains",
]);

export const SUPPLY_CHAIN_LIMITS = Object.freeze({
    maxDepth: 8,
    maxPackages: 512,
    maxRequests: 128,
    maxRedirects: 2,
    requestTimeoutMs: 15_000,
    maxResponseBytes: 16 * 1024 * 1024,
    maxTotalBytes: 64 * 1024 * 1024,
    maxArchiveEntries: 2_048,
    maxArchiveDepth: 4,
    maxScannedTextBytes: 8 * 1024 * 1024,
    maxFacts: 20_000,
});

const HARD_LIMITS = Object.freeze({
    maxDepth: 16,
    maxPackages: 2_000,
    maxRequests: 512,
    maxRedirects: 5,
    requestTimeoutMs: 60_000,
    maxResponseBytes: 32 * 1024 * 1024,
    maxTotalBytes: 256 * 1024 * 1024,
    maxArchiveEntries: 10_000,
    maxArchiveDepth: 8,
    maxScannedTextBytes: 32 * 1024 * 1024,
    maxFacts: 100_000,
});

function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function cloneFrozen(value) {
    if (Array.isArray(value)) return Object.freeze(value.map(cloneFrozen));
    if (value && typeof value === "object") {
        const result = {};
        for (const [key, entry] of Object.entries(value)) result[key] = cloneFrozen(entry);
        return Object.freeze(result);
    }
    return value;
}

function uniqueSorted(values, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(maximum) || maximum < 0) {
        throw new TypeError("uniqueSorted maximum must be a non-negative safe integer");
    }
    if (typeof values === "string"
        || values === null
        || values === undefined
        || typeof values[Symbol.iterator] !== "function") {
        throw new TypeError("uniqueSorted values must be an array, Set, or bounded iterable");
    }
    const bounded = Array.isArray(values) || values instanceof Set;
    if (!bounded && maximum === Number.MAX_SAFE_INTEGER) {
        throw new TypeError("uniqueSorted iterable requires an explicit finite maximum");
    }
    const unique = new Set();
    if (bounded) {
        for (const value of values) {
            if (value) unique.add(value);
        }
    } else {
        const iterator = values[Symbol.iterator]();
        for (let visited = 0; visited < maximum; visited += 1) {
            const next = iterator.next();
            if (next.done) break;
            if (next.value) unique.add(next.value);
        }
    }
    return [...unique].sort().slice(0, maximum);
}

function boundedInteger(value, fallback, hardMaximum, name, minimum = 0) {
    if (value === undefined) return fallback;
    if (!Number.isSafeInteger(value) || value < minimum || value > hardMaximum) {
        throw new TypeError(`${name} must be an integer between ${minimum} and ${hardMaximum}`);
    }
    return value;
}

function normalizeLimits(overrides = {}) {
    const result = {};
    for (const key of Object.keys(SUPPLY_CHAIN_LIMITS)) {
        const minimum = ["maxDepth", "maxRedirects", "maxArchiveDepth"].includes(key) ? 0: 1;
        result[key] = boundedInteger(
            overrides[key],
            SUPPLY_CHAIN_LIMITS[key],
            HARD_LIMITS[key],
            key,
            minimum,
        );
    }
    return Object.freeze(result);
}

function validateInventorySet(value) {
    if (!value || typeof value !== "object"
        || value.schemaVersion !== DEPENDENCY_INVENTORY_SCHEMA_REVISION
        || !Array.isArray(value.inventories)
        || value.inventories.length === 0) {
        throw new TypeError("supply-chain analysis requires a dependency inventory set");
    }
    const { auditId, sourceNamespace } = value;
    for (const inventory of value.inventories) {
        if (inventory.auditId !== auditId || inventory.sourceNamespace !== sourceNamespace) {
            throw new TypeError("dependency inventory set has mixed audit identities");
        }
    }
    return value;
}

function addNode(state, node) {
    const existing = state.nodes.get(node.nodeId);
    if (existing) return existing;
    state.nodes.set(node.nodeId, node);
    return node;
}

function addEdge(state, kind, fromNodeId, toNodeId, details = {}) {
    if (!SUPPLY_CHAIN_EDGE_KINDS.includes(kind)) {
        throw new TypeError(`unsupported supply-chain edge kind: ${kind}`);
    }
    const descriptor = { kind, fromNodeId, toNodeId, ...details };
    const edgeId = `ztsce-${sha256(Buffer.from(canonicalJson(descriptor), "utf8"))}`;
    if (!state.edges.has(edgeId)) state.edges.set(edgeId, { edgeId, ...descriptor });
    return edgeId;
}

function provenanceNode(state, inventory) {
    const descriptor = {
        kind: "manifest",
        manifestId: inventory.manifestId,
        path: inventory.path,
        contentSha256: inventory.hashes.manifestSha256,
        format: inventory.format,
        ecosystem: inventory.ecosystem,
    };
    return addNode(state, {
        nodeId: `ztscv-${sha256(Buffer.from(canonicalJson(descriptor), "utf8"))}`,
        nodeKind: "provenance",
        auditId: state.auditId,
        sourceNamespace: state.sourceNamespace,
        ...descriptor,
    });
}

function packageNode(state, record) {
    return addNode(state, {
        nodeId: record.packageId,
        nodeKind: "package",
        auditId: state.auditId,
        sourceNamespace: state.sourceNamespace,
        packageId: record.packageId,
        manifestId: record.manifestId,
        ecosystem: record.ecosystem,
        name: record.name,
        version: record.version,
        locator: record.locator,
        sourceType: record.sourceType,
        sourceUrl: record.sourceUrl,
        registryHost: record.registryHost,
        artifactUrl: record.artifactUrl,
        metadataUrl: record.metadataUrl,
        integrity: record.integrity,
        aliasFor: record.aliasFor,
        localPath: record.localPath,
        git: record.git,
        lifecycleHooks: [...record.lifecycleHooks],
        buildHooks: [...record.buildHooks],
        blockerCodes: [...record.blockerCodes],
        status: record.blockerCodes.length === 0 ? "inventoried": "blocked",
        analysis: null,
    });
}

function registryProvenanceNode(state, record, url, role) {
    const parsed = new URL(url);
    const descriptor = {
        kind: role,
        packageId: record.packageId,
        url,
        host: parsed.hostname.toLowerCase(),
    };
    return addNode(state, {
        nodeId: `ztscv-${sha256(Buffer.from(canonicalJson(descriptor), "utf8"))}`,
        nodeKind: "provenance",
        auditId: state.auditId,
        sourceNamespace: state.sourceNamespace,
        ...descriptor,
    });
}

function createGraphState(inventorySet, limits) {
    const state = {
        auditId: inventorySet.auditId,
        sourceNamespace: inventorySet.sourceNamespace,
        limits,
        inventories: inventorySet.inventories,
        nodes: new Map(),
        edges: new Map(),
        packages: new Map(),
        dependencyEdges: [],
        roots: new Set(),
        blockerCodes: new Set(inventorySet.blockerCodes || []),
        blockerDetails: [],
        budget: {
            requests: 0,
            bytes: 0,
            packagesAnalyzed: 0,
            archiveEntries: 0,
            scannedTextBytes: 0,
            facts: 0,
            deepestLevel: 0,
        },
    };
    for (const inventory of inventorySet.inventories) {
        const manifestNode = provenanceNode(state, inventory);
        for (const record of inventory.packages) {
            state.packages.set(record.packageId, record);
            packageNode(state, record);
            addEdge(state, "declared-in", record.packageId, manifestNode.nodeId);
        }
        for (const edge of inventory.edges) {
            state.dependencyEdges.push(edge);
            addEdge(
                state,
                "depends-on",
                edge.fromPackageId,
                edge.toPackageId,
                {
                    dependencyName: edge.dependencyName,
                    optional: edge.optional,
                },
            );
        }
        for (const rootPackageId of inventory.rootPackageIds) state.roots.add(rootPackageId);
    }
    return state;
}

function appendBlocker(state, code, subjectId = null) {
    if (!DEPENDENCY_BLOCKER_CODES.includes(code)) {
        throw new TypeError(`invalid supply-chain blocker code: ${code}`);
    }
    state.blockerCodes.add(code);
    if (state.blockerDetails.length < 256) {
        const key = `${code}\0${subjectId || ""}`;
        if (!state.blockerDetails.some((entry) =>
            `${entry.code}\0${entry.subjectId || ""}` === key)) {
            state.blockerDetails.push({ code, subjectId });
        }
    }
}

function graphDepths(state) {
    const outgoing = new Map();
    for (const edge of state.dependencyEdges) {
        if (!outgoing.has(edge.fromPackageId)) outgoing.set(edge.fromPackageId, []);
        outgoing.get(edge.fromPackageId).push(edge.toPackageId);
    }
    const roots = state.roots.size > 0
        ? [...state.roots]: [...state.packages.keys()];
    const depths = new Map();
    const queue = roots.map((packageId) => ({ packageId, depth: 0 }));
    while (queue.length > 0) {
        const current = queue.shift();
        if (!state.packages.has(current.packageId)) {
            appendBlocker(state, DEPENDENCY_BLOCKERS.TRANSITIVE_UNRESOLVED, current.packageId);
            continue;
        }
        const existing = depths.get(current.packageId);
        if (existing !== undefined && existing <= current.depth) continue;
        depths.set(current.packageId, current.depth);
        for (const target of outgoing.get(current.packageId) || []) {
            queue.push({ packageId: target, depth: current.depth + 1 });
        }
    }
    for (const packageId of state.packages.keys()) {
        if (!depths.has(packageId)) depths.set(packageId, 0);
    }
    return depths;
}

function integrityDigest(buffer, algorithm, encoding) {
    return createHash(algorithm).update(buffer).digest(encoding);
}

export function verifyDeclaredIntegrity(buffer, integrity) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError("integrity verification requires a Buffer");
    const candidates = Array.isArray(integrity) ? integrity: [];
    if (candidates.length === 0) {
        return Object.freeze({ verified: false, reason: "missing", matched: null });
    }
    for (const candidate of candidates) {
        if (!["sha1", "sha256", "sha384", "sha512"].includes(candidate.algorithm)
            || !["hex", "base64"].includes(candidate.encoding)) {
            continue;
        }
        const actual = integrityDigest(buffer, candidate.algorithm, candidate.encoding);
        const equal = candidate.encoding === "hex"
            ? actual.toLowerCase() === String(candidate.digest).toLowerCase(): actual.replace(/=+$/u, "") === String(candidate.digest).replace(/=+$/u, "");
        if (equal) {
            return cloneFrozen({
                verified: true,
                reason: "matched",
                matched: {
                    algorithm: candidate.algorithm,
                    encoding: candidate.encoding,
                    digest: candidate.digest,
                },
            });
        }
    }
    return Object.freeze({ verified: false, reason: "mismatch", matched: null });
}

function candidateDigestMatches(record, file, digests) {
    const declaredForFile = record.artifactCandidates
        .filter((candidate) => candidate.file === file)
        .flatMap((candidate) => candidate.integrity);
    const declared = declaredForFile.length > 0 ? declaredForFile: record.integrity;
    return declared.some((entry) => {
        const digest = digests?.[entry.algorithm];
        if (!digest) return false;
        return entry.encoding === "hex"
            ? String(digest).toLowerCase() === entry.digest.toLowerCase(): String(digest) === entry.digest;
    });
}

function pythonArtifactFromMetadata(record, buffer) {
    let metadata;
    try {
        metadata = JSON.parse(buffer.toString("utf8"));
    } catch {
        throw new Error("PyPI metadata was not valid JSON");
    }
    if (String(metadata?.info?.name || "").toLowerCase().replace(/[-_.]+/gu, "-")
            !== record.name.toLowerCase().replace(/[-_.]+/gu, "-")
        || String(metadata?.info?.version || "") !== String(record.version || "")) {
        throw new Error("PyPI metadata identity did not match the locked package");
    }
    const candidates = (metadata.urls || []).filter((entry) =>
        entry
        && typeof entry.url === "string"
        && typeof entry.filename === "string"
        && candidateDigestMatches(record, entry.filename, entry.digests || {}));
    candidates.sort((left, right) => {
        const rank = (entry) => entry.packagetype === "sdist" ? 0: /\.tar\.gz$|\.zip$/iu.test(entry.filename) ? 1: /\.whl$/iu.test(entry.filename) ? 2: 3;
        return rank(left) - rank(right) || left.filename.localeCompare(right.filename);
    });
    const selected = candidates[0];
    if (!selected) throw new Error("PyPI metadata had no artifact matching a locked hash");
    return {
        url: selected.url,
        fileName: selected.filename,
        integrity: record.artifactCandidates
            .filter((entry) => entry.file === selected.filename)
            .flatMap((entry) => entry.integrity)
            .concat(record.integrity),
    };
}

function artifactDescriptor(record, metadataBuffer = null) {
    if (record.metadataUrl) return pythonArtifactFromMetadata(record, metadataBuffer);
    if (!record.artifactUrl) throw new Error("locked dependency has no exact artifact URL");
    const parsed = new URL(record.artifactUrl);
    return {
        url: record.artifactUrl,
        fileName: parsed.pathname.split("/").filter(Boolean).at(-1) || "artifact.bin",
        integrity: record.integrity,
    };
}

function decodeUtf8(buffer) {
    if (buffer.length === 0 || buffer.includes(0)) return null;
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    } catch {
        return null;
    }
}

function scannerPath(packageId, archivePath) {
    const suffix = String(archivePath || "payload")
        .replace(/\\/gu, "/")
        .replace(/^\/+/u, "")
        .slice(0, 900);
    return `dependency/${packageId.slice(-24)}/${suffix}`;
}

function npmHooks(path, text, hooks) {
    if (!/(?:^|\/)package\.json$/iu.test(path)) return;
    try {
        const packageJson = JSON.parse(text);
        for (const name of [
            "preinstall",
            "install",
            "postinstall",
            "prepublish",
            "prepublishOnly",
            "prepare",
        ]) {
            if (typeof packageJson?.scripts?.[name] === "string") {
                hooks.lifecycle.add(`npm:${name}`);
            }
        }
        if (packageJson?.gypfile === true) hooks.build.add("npm:node-gyp");
    } catch {
        hooks.blocked = true;
    }
}

function cargoHooks(path, text, hooks) {
    if (/(?:^|\/)build\.rs$/iu.test(path)) hooks.build.add("cargo:build.rs");
    if (/(?:^|\/)cargo\.toml$/iu.test(path)
        && /^\s*build\s*=\s*["'][^"']+["']/mu.test(text)) {
        hooks.build.add("cargo:package-build");
    }
}

function pythonHooks(path, text, hooks) {
    const lower = path.toLowerCase();
    if (/(?:^|\/)setup\.py$/u.test(lower)) hooks.build.add("python:setup.py");
    if (/(?:^|\/)pyproject\.toml$/u.test(lower)
        && /^\s*build-backend\s*=/mu.test(text)) {
        hooks.build.add("python:build-backend");
    }
    if (/\.dist-info\/entry_points\.txt$/u.test(lower)) {
        hooks.lifecycle.add("python:entry-points");
    }
}

function nugetHooks(path, _text, hooks) {
    const lower = path.toLowerCase();
    if (/(?:^|\/)tools\/(?:install|init|uninstall)\.ps1$/u.test(lower)) {
        hooks.lifecycle.add(`nuget:${lower.split("/").at(-1)}`);
    }
    if (/(?:^|\/)build(?:transitive)?\/.*\.(?:targets|props)$/u.test(lower)) {
        hooks.build.add(`nuget:${lower.includes("/buildtransitive/") ? "buildTransitive": "build"}`);
    }
}

function recordHooks(record, path, text, hooks) {
    if (record.ecosystem === "npm") npmHooks(path, text, hooks);
    if (record.ecosystem === "cargo") cargoHooks(path, text, hooks);
    if (record.ecosystem === "python") pythonHooks(path, text, hooks);
    if (record.ecosystem === "nuget") nugetHooks(path, text, hooks);
}

function artifactFormatHint(path) {
    const lower = String(path || "").toLowerCase();
    if (lower.endsWith(".crate")) return "tar.gz";
    if (lower.endsWith(".whl") || lower.endsWith(".nupkg")) return "zip";
    return null;
}

function analyzeArchive(record, artifact, buffer, state) {
    const hooks = {
        lifecycle: new Set(record.lifecycleHooks),
        build: new Set(record.buildHooks),
        blocked: false,
    };
    const facts = [];
    const scannerCounts = {};
    const archiveFormats = new Set();
    const archiveBlockers = new Set();
    const visited = new Set();

    const walk = (payload, logicalPath, depth, forcedHint = null) => {
        const payloadHash = sha256(payload);
        const visitKey = `${payloadHash}:${depth}`;
        if (visited.has(visitKey)) return;
        visited.add(visitKey);
        if (depth > state.limits.maxArchiveDepth) {
            appendBlocker(state, DEPENDENCY_BLOCKERS.RECURSION_CAP, record.packageId);
            return;
        }
        const format = forcedHint || detectArchiveFormat(payload, { path: logicalPath });
        if (!format) return;
        const archive = readArchive(payload, {
            path: logicalPath,
            formatHint: forcedHint,
            depth,
            limits: {
                maxNestedDepth: state.limits.maxArchiveDepth,
                maxEntries: Math.min(
                    state.limits.maxArchiveEntries,
                    ARCHIVE_READER_LIMITS.maxEntries,
                ),
                maxExpandedBytes: Math.min(
                    state.limits.maxTotalBytes,
                    ARCHIVE_READER_LIMITS.maxExpandedBytes,
                ),
                maxEntryBytes: Math.min(
                    state.limits.maxResponseBytes,
                    ARCHIVE_READER_LIMITS.maxEntryBytes,
                ),
            },
        });
        archiveFormats.add(archive.format);
        for (const code of archive.blockerCodes) archiveBlockers.add(code);
        if (archive.status !== "decoded") {
            appendBlocker(
                state,
                DEPENDENCY_BLOCKERS.ARTIFACT_ANALYSIS_BLOCKED,
                record.packageId,
            );
        }
        for (const entry of archive.entries) {
            if (entry.entryKind !== "file") continue;
            state.budget.archiveEntries += 1;
            if (state.budget.archiveEntries > state.limits.maxArchiveEntries) {
                appendBlocker(state, DEPENDENCY_BLOCKERS.RECURSION_CAP, record.packageId);
                return;
            }
            const bytes = getArchiveEntryBytes(entry);
            if (!bytes) continue;
            const text = decodeUtf8(bytes);
            if (text !== null) {
                recordHooks(record, entry.path, text, hooks);
                if (state.budget.scannedTextBytes + bytes.length
                    <= state.limits.maxScannedTextBytes
                    && state.budget.facts < state.limits.maxFacts) {
                    const scan = scanSourceText({
                        path: scannerPath(record.packageId, entry.path),
                        text,
                        maxFacts: Math.min(
                            1_024,
                            state.limits.maxFacts - state.budget.facts,
                        ),
                    });
                    state.budget.scannedTextBytes += bytes.length;
                    state.budget.facts += scan.factCount;
                    scannerCounts[scan.scannerId] =
                        (scannerCounts[scan.scannerId] || 0) + 1;
                    for (const fact of scan.facts) {
                        if (facts.length >= state.limits.maxFacts) break;
                        facts.push({
                            id: fact.id,
                            kind: fact.kind,
                            path: fact.path,
                            scannerId: fact.scannerId,
                            language: fact.language,
                            name: fact.name,
                            resolution: fact.resolution || null,
                            tags: fact.tags || [],
                        });
                    }
                } else {
                    appendBlocker(state, DEPENDENCY_BLOCKERS.RECURSION_CAP, record.packageId);
                }
            }
            const nested = detectArchiveFormat(bytes, { path: entry.path });
            if (nested) walk(bytes, entry.path, depth + 1, null);
        }
    };

    walk(buffer, artifact.fileName, 0, artifactFormatHint(artifact.fileName));
    if (hooks.blocked) {
        appendBlocker(
            state,
            DEPENDENCY_BLOCKERS.ARTIFACT_ANALYSIS_BLOCKED,
            record.packageId,
        );
    }
    return {
        archiveFormats: uniqueSorted(archiveFormats),
        archiveBlockers: uniqueSorted(archiveBlockers),
        lifecycleHooks: uniqueSorted(hooks.lifecycle, 64),
        buildHooks: uniqueSorted(hooks.build, 64),
        scannerCounts,
        facts,
    };
}

function graphBase(state) {
    const nodes = [...state.nodes.values()].sort((a, b) => a.nodeId.localeCompare(b.nodeId));
    const edges = [...state.edges.values()].sort((a, b) => a.edgeId.localeCompare(b.edgeId));
    const blockerCodes = uniqueSorted(state.blockerCodes);
    const blockerDetails = [...state.blockerDetails].sort((a, b) =>
        a.code.localeCompare(b.code)
        || String(a.subjectId || "").localeCompare(String(b.subjectId || "")));
    const manifests = state.inventories.map((inventory) => ({
        manifestId: inventory.manifestId,
        path: inventory.path,
        format: inventory.format,
        ecosystem: inventory.ecosystem,
        contentSha256: inventory.hashes.manifestSha256,
    })).sort((a, b) => a.manifestId.localeCompare(b.manifestId));
    return {
        schemaVersion: SUPPLY_CHAIN_GRAPH_SCHEMA_REVISION,
        auditId: state.auditId,
        sourceNamespace: state.sourceNamespace,
        status: blockerCodes.length === 0 ? "complete": "blocked",
        manifests,
        rootPackageIds: [...state.roots].sort(),
        nodes,
        edges,
        blockerCodes,
        blockerDetails,
        counts: {
            manifests: manifests.length,
            packages: nodes.filter((node) => node.nodeKind === "package").length,
            artifacts: nodes.filter((node) => node.nodeKind === "artifact").length,
            provenance: nodes.filter((node) => node.nodeKind === "provenance").length,
            edges: edges.length,
            requests: state.budget.requests,
            fetchedBytes: state.budget.bytes,
            packagesAnalyzed: state.budget.packagesAnalyzed,
            archiveEntries: state.budget.archiveEntries,
            scannedTextBytes: state.budget.scannedTextBytes,
            facts: state.budget.facts,
            deepestLevel: state.budget.deepestLevel,
        },
    };
}

function finalizeGraph(state) {
    const base = graphBase(state);
    const componentHashes = {
        nodesSha256: sha256(Buffer.from(canonicalJson(base.nodes), "utf8")),
        edgesSha256: sha256(Buffer.from(canonicalJson(base.edges), "utf8")),
        provenanceSha256: sha256(Buffer.from(canonicalJson(base.manifests), "utf8")),
    };
    const graphSha256 = sha256(Buffer.from(canonicalJson({
        ...base,
        hashes: componentHashes,
    }), "utf8"));
    return cloneFrozen({
        ...base,
        graphId: `ztscg-${graphSha256}`,
        hashes: { ...componentHashes, graphSha256 },
    });
}

export function buildSupplyChainGraph({
    inventorySet,
    limits: limitOverrides = {},
} = {}) {
    const inventories = validateInventorySet(inventorySet);
    const state = createGraphState(inventories, normalizeLimits(limitOverrides));
    for (const code of state.blockerCodes) {
        if (DEPENDENCY_BLOCKER_CODES.includes(code)) appendBlocker(state, code);
    }
    return finalizeGraph(state);
}

async function boundedFetch(state, fetchBuffer, url, options) {
    if (state.budget.requests >= state.limits.maxRequests) {
        appendBlocker(state, DEPENDENCY_BLOCKERS.RECURSION_CAP, options.packageRecord.packageId);
        throw new Error("dependency request cap reached");
    }
    state.budget.requests += 1;
    const result = await fetchBuffer(url, {
        ...options,
        limits: state.limits,
        requestNumber: state.budget.requests,
        remainingTotalBytes: state.limits.maxTotalBytes - state.budget.bytes,
    });
    const buffer = Buffer.isBuffer(result) ? result: result?.buffer;
    if (!Buffer.isBuffer(buffer)) throw new Error("dependency fetcher did not return a Buffer");
    if (buffer.length > state.limits.maxResponseBytes
        || state.budget.bytes + buffer.length > state.limits.maxTotalBytes) {
        appendBlocker(state, DEPENDENCY_BLOCKERS.RECURSION_CAP, options.packageRecord.packageId);
        throw new Error("dependency byte cap reached");
    }
    state.budget.bytes += buffer.length;
    return buffer;
}

export async function analyzeSupplyChain({
    inventorySet,
    fetchBuffer,
    limits: limitOverrides = {},
} = {}) {
    if (typeof fetchBuffer !== "function") {
        throw new TypeError("analyzeSupplyChain requires a bounded fetchBuffer function");
    }
    const inventories = validateInventorySet(inventorySet);
    const state = createGraphState(inventories, normalizeLimits(limitOverrides));
    const depths = graphDepths(state);
    const ordered = [...state.packages.values()].sort((left, right) =>
        (depths.get(left.packageId) - depths.get(right.packageId))
        || left.packageId.localeCompare(right.packageId));
    if (ordered.length > state.limits.maxPackages) {
        appendBlocker(state, DEPENDENCY_BLOCKERS.RECURSION_CAP);
    }

    for (const record of ordered.slice(0, state.limits.maxPackages)) {
        const depth = depths.get(record.packageId) || 0;
        state.budget.deepestLevel = Math.max(state.budget.deepestLevel, depth);
        if (depth > state.limits.maxDepth) {
            appendBlocker(state, DEPENDENCY_BLOCKERS.RECURSION_CAP, record.packageId);
            continue;
        }
        const packageNodeRecord = state.nodes.get(record.packageId);
        const hardBlocker = record.blockerCodes.some((code) => [
            DEPENDENCY_BLOCKERS.MUTABLE_REF,
            DEPENDENCY_BLOCKERS.MISSING_INTEGRITY,
            DEPENDENCY_BLOCKERS.UNSUPPORTED_REGISTRY,
        ].includes(code));
        if (hardBlocker || ["local", "workspace"].includes(record.sourceType)) continue;

        let metadataBuffer = null;
        try {
            if (record.metadataUrl) {
                const metadataProvenance = registryProvenanceNode(
                    state,
                    record,
                    record.metadataUrl,
                    "registry-metadata",
                );
                addEdge(state, "resolved-to", record.packageId, metadataProvenance.nodeId);
                metadataBuffer = await boundedFetch(
                    state,
                    fetchBuffer,
                    record.metadataUrl,
                    { kind: "metadata", packageRecord: record },
                );
            }
            const descriptor = artifactDescriptor(record, metadataBuffer);
            const artifactProvenance = registryProvenanceNode(
                state,
                record,
                descriptor.url,
                "registry-artifact",
            );
            addEdge(state, "resolved-to", record.packageId, artifactProvenance.nodeId);
            const artifactBuffer = await boundedFetch(
                state,
                fetchBuffer,
                descriptor.url,
                {
                    kind: "artifact",
                    packageRecord: record,
                    expectedFileName: descriptor.fileName,
                },
            );
            const verified = verifyDeclaredIntegrity(artifactBuffer, descriptor.integrity);
            if (!verified.verified) {
                appendBlocker(
                    state,
                    verified.reason === "missing"
                        ? DEPENDENCY_BLOCKERS.MISSING_INTEGRITY: DEPENDENCY_BLOCKERS.HASH_MISMATCH,
                    record.packageId,
                );
                packageNodeRecord.status = "blocked";
                packageNodeRecord.blockerCodes = uniqueSorted([
                    ...packageNodeRecord.blockerCodes,
                    verified.reason === "missing"
                        ? DEPENDENCY_BLOCKERS.MISSING_INTEGRITY: DEPENDENCY_BLOCKERS.HASH_MISMATCH,
                ]);
                continue;
            }
            const contentSha256 = sha256(artifactBuffer);
            const artifactDescriptorBase = {
                packageId: record.packageId,
                fileName: descriptor.fileName,
                url: descriptor.url,
                byteLength: artifactBuffer.length,
                contentSha256,
            };
            const artifactNode = addNode(state, {
                nodeId: `ztsca-${sha256(Buffer.from(
                    canonicalJson(artifactDescriptorBase),
                    "utf8",
                ))}`,
                nodeKind: "artifact",
                auditId: state.auditId,
                sourceNamespace: state.sourceNamespace,
                ...artifactDescriptorBase,
                integrity: verified.matched,
                status: "verified",
                analysis: null,
            });
            addEdge(state, "resolved-to", record.packageId, artifactNode.nodeId);
            addEdge(state, "fetched-from", artifactNode.nodeId, artifactProvenance.nodeId);
            addEdge(state, "verified-by", artifactNode.nodeId, record.packageId, {
                algorithm: verified.matched.algorithm,
            });
            const analysis = analyzeArchive(
                record,
                { ...descriptor, contentSha256 },
                artifactBuffer,
                state,
            );
            artifactNode.analysis = analysis;
            artifactNode.status = analysis.archiveBlockers.length === 0
                ? "analyzed": "blocked";
            packageNodeRecord.lifecycleHooks = analysis.lifecycleHooks;
            packageNodeRecord.buildHooks = analysis.buildHooks;
            packageNodeRecord.analysis = {
                artifactNodeId: artifactNode.nodeId,
                scannerCounts: analysis.scannerCounts,
                factCount: analysis.facts.length,
                facts: analysis.facts,
                archiveFormats: analysis.archiveFormats,
            };
            packageNodeRecord.status = artifactNode.status === "analyzed"
                ? "analyzed": "blocked";
            state.budget.packagesAnalyzed += 1;
        } catch {
            appendBlocker(state, DEPENDENCY_BLOCKERS.FETCH_FAILED, record.packageId);
            packageNodeRecord.status = "blocked";
            packageNodeRecord.blockerCodes = uniqueSorted([
                ...packageNodeRecord.blockerCodes,
                DEPENDENCY_BLOCKERS.FETCH_FAILED,
            ]);
        } finally {
            if (metadataBuffer) metadataBuffer.fill(0);
        }
    }
    return finalizeGraph(state);
}

export function validateSupplyChainGraph(value) {
    if (!value || typeof value !== "object"
        || value.schemaVersion !== SUPPLY_CHAIN_GRAPH_SCHEMA_REVISION
        || typeof value.auditId !== "string"
        || typeof value.sourceNamespace !== "string"
        || !Array.isArray(value.nodes)
        || !Array.isArray(value.edges)
        || !Array.isArray(value.blockerCodes)
        || value.blockerCodes.some((code) => !DEPENDENCY_BLOCKER_CODES.includes(code))
        || !/^ztscg-[a-f0-9]{64}$/u.test(String(value.graphId || ""))
        || !/^[a-f0-9]{64}$/u.test(String(value.hashes?.graphSha256 || ""))) {
        throw new TypeError("invalid supply-chain graph");
    }
    if (value.graphId !== `ztscg-${value.hashes.graphSha256}`) {
        throw new TypeError("supply-chain graph ID does not match its hash");
    }
    const {
        graphId: _graphId,
        hashes,
        ...base
    } = value;
    const expectedComponents = {
        nodesSha256: sha256(Buffer.from(canonicalJson(base.nodes), "utf8")),
        edgesSha256: sha256(Buffer.from(canonicalJson(base.edges), "utf8")),
        provenanceSha256: sha256(Buffer.from(canonicalJson(base.manifests), "utf8")),
    };
    const expectedGraphSha256 = sha256(Buffer.from(canonicalJson({
        ...base,
        hashes: expectedComponents,
    }), "utf8"));
    if (canonicalJson(hashes) !== canonicalJson({
        ...expectedComponents,
        graphSha256: expectedGraphSha256,
    })) {
        throw new TypeError("supply-chain graph component hashes are not canonical");
    }
    return cloneFrozen(value);
}

export function applySupplyChainGraphToAssuranceSnapshot({
    snapshot,
    graph,
} = {}) {
    const current = validateAssuranceAnalysisSnapshot(snapshot);
    const supplyChain = validateSupplyChainGraph(graph);
    if (supplyChain.auditId !== current.auditId
        || supplyChain.sourceNamespace !== current.sourceNamespace) {
        throw new TypeError("supply-chain graph does not match the assurance snapshot identity");
    }
    const objectsByPath = new Map(
        current.objectInventory.map((record) => [record.path, record]),
    );
    const artifacts = [];
    for (const manifest of supplyChain.manifests) {
        const object = objectsByPath.get(manifest.path);
        if (!object
            || object.status !== "inventoried"
            || object.hashes.contentSha256 !== manifest.contentSha256) {
            continue;
        }
        const suffix =
            `#dependency-graph-${supplyChain.hashes.graphSha256.slice(0, 24)}`;
        artifacts.push(createEvasiveDerivedArtifactRecord({
            auditId: current.auditId,
            sourceNamespace: current.sourceNamespace,
            path: `${manifest.path.slice(0, 4_096 - suffix.length)}${suffix}`,
            sourceObjectId: object.objectId,
            artifactKind: "dependency-graph",
            producer: "zerotrust-supply-chain",
            producerVersion: "1.0.0",
            byteLength: Buffer.byteLength(canonicalJson(supplyChain), "utf8"),
            status: supplyChain.blockerCodes.length === 0 ? "decoded": "blocked",
            blockerCodes: supplyChain.blockerCodes.length === 0
                ? []: [EVASIVE_BLOCKERS.SUPPLY_CHAIN_INCOMPLETE],
            contentSha256: supplyChain.hashes.graphSha256,
            sourceObjectSha256: object.hashes.identitySha256,
        }));
    }
    if (artifacts.length === 0) {
        return Object.freeze({
            applied: false,
            reason: "no exact inventoried manifest object matched the graph",
            snapshot: current,
            artifacts: Object.freeze([]),
        });
    }
    const nextSnapshot = applyDerivedArtifactsToSnapshot({
        snapshot: current,
        artifacts,
        blockerCodes: supplyChain.blockerCodes.length === 0
            ? []: [EVASIVE_BLOCKERS.SUPPLY_CHAIN_INCOMPLETE],
    });
    return Object.freeze({
        applied: true,
        reason: null,
        snapshot: nextSnapshot,
        artifacts: Object.freeze(artifacts),
    });
}

export const __internals = Object.freeze({
    artifactDescriptor,
    artifactFormatHint,
    candidateDigestMatches,
    canonicalJson,
    graphDepths,
    normalizeLimits,
    pythonArtifactFromMetadata,
    registryProvenanceNode,
    uniqueSorted,
});
