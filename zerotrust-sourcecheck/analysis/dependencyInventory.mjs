import { createHash } from "node:crypto";
import nodePath from "node:path";

export const DEPENDENCY_INVENTORY_SCHEMA_REVISION = 6;

export const DEPENDENCY_ECOSYSTEMS = Object.freeze([
    "npm",
    "cargo",
    "python",
    "nuget",
]);

export const DEPENDENCY_SOURCE_TYPES = Object.freeze([
    "registry",
    "url",
    "git",
    "local",
    "workspace",
]);

export const DEPENDENCY_BLOCKERS = Object.freeze({
    MUTABLE_REF: "supply-chain/mutable-ref",
    MISSING_INTEGRITY: "supply-chain/missing-integrity",
    UNSUPPORTED_REGISTRY: "supply-chain/unsupported-registry",
    FETCH_FAILED: "supply-chain/fetch-failed",
    RECURSION_CAP: "supply-chain/recursion-cap",
    HASH_MISMATCH: "supply-chain/hash-mismatch",
    INVALID_LOCKFILE: "supply-chain/invalid-lockfile",
    TRANSITIVE_UNRESOLVED: "supply-chain/transitive-unresolved",
    ARTIFACT_ANALYSIS_BLOCKED: "supply-chain/artifact-analysis-blocked",
});

export const DEPENDENCY_BLOCKER_CODES = Object.freeze(
    Object.values(DEPENDENCY_BLOCKERS),
);

export const DEPENDENCY_REGISTRY_HOSTS = Object.freeze([
    "api.nuget.org",
    "files.pythonhosted.org",
    "pypi.org",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "static.crates.io",
]);

export const DEPENDENCY_INVENTORY_LIMITS = Object.freeze({
    manifests: 32,
    manifestBytes: 8 * 1024 * 1024,
    packages: 5_000,
    edges: 20_000,
    dependenciesPerPackage: 512,
    integrityValuesPerPackage: 32,
    artifactCandidatesPerPackage: 64,
    hooksPerPackage: 64,
});

const AUDIT_ID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256_RE = /^[a-f0-9]{64}$/iu;
const COMMIT_RE = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/iu;
const PACKAGE_NAME_RE = /^[^\u0000-\u001f\u007f]{1,512}$/u;

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

function normalizePath(value) {
    const normalized = String(value || "").replace(/\\/gu, "/").replace(/^\.\/+/u, "");
    if (!normalized || normalized.length > 4_096 || normalized.startsWith("/")
        || normalized.endsWith("/") || normalized.includes("//")
        || /[\u0000-\u001f\u007f]/u.test(normalized)
        || normalized.split("/").some((part) => !part || part === "." || part === "..")) {
        throw new TypeError("dependency manifest path must be a normalized relative path");
    }
    return normalized;
}

function validateIdentity({ auditId, sourceNamespace, path, text, contentSha256 }) {
    const normalizedAuditId = String(auditId || "").toLowerCase();
    if (!AUDIT_ID_RE.test(normalizedAuditId)) {
        throw new TypeError("dependency inventory requires a valid random auditId");
    }
    const namespace = String(sourceNamespace || "").normalize("NFKC").trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}$/u.test(namespace)) {
        throw new TypeError("dependency inventory sourceNamespace is invalid");
    }
    const manifestPath = normalizePath(path);
    if (typeof text !== "string"
        || Buffer.byteLength(text, "utf8") > DEPENDENCY_INVENTORY_LIMITS.manifestBytes) {
        throw new TypeError("dependency manifest text is missing or exceeds the byte cap");
    }
    const actualSha256 = sha256(Buffer.from(text, "utf8"));
    if (contentSha256 !== undefined && contentSha256 !== null
        && String(contentSha256).toLowerCase() !== actualSha256) {
        throw new TypeError("dependency manifest contentSha256 does not match text");
    }
    return {
        auditId: normalizedAuditId,
        sourceNamespace: namespace,
        path: manifestPath,
        contentSha256: actualSha256,
    };
}

function parseJson(text, path) {
    let value;
    try {
        value = JSON.parse(text);
    } catch {
        throw new TypeError(`invalid JSON dependency lockfile: ${path}`);
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError(`dependency lockfile root must be an object: ${path}`);
    }
    return value;
}

function safeUrl(value) {
    if (typeof value !== "string" || value.length === 0 || value.length > 4_096) {
        return null;
    }
    try {
        const url = new URL(value);
        if (url.username || url.password) return null;
        return url;
    } catch {
        return null;
    }
}

function registryHostForUrl(value) {
    const url = safeUrl(value);
    return url?.protocol === "https:" ? url.hostname.toLowerCase(): null;
}

function isAllowedRegistryUrl(value) {
    const host = registryHostForUrl(value);
    return host !== null && DEPENDENCY_REGISTRY_HOSTS.includes(host);
}

function normalizeIntegrity(values) {
    const result = [];
    for (const rawValue of Array.isArray(values) ? values: [values]) {
        if (typeof rawValue !== "string") continue;
        for (const token of rawValue.trim().split(/\s+/u)) {
            const sri = token.match(/^(sha(?:1|256|384|512))-([A-Za-z0-9+/=]+)(?:\?.*)?$/iu);
            const colon = token.match(/^(sha(?:1|256|384|512)):([a-f0-9]+)$/iu);
            const fragment = token.match(/^sha256=([a-f0-9]{64})$/iu);
            if (sri) {
                result.push({
                    algorithm: sri[1].toLowerCase(),
                    digest: sri[2],
                    encoding: "base64",
                    raw: token,
                });
            } else if (colon) {
                result.push({
                    algorithm: colon[1].toLowerCase(),
                    digest: colon[2].toLowerCase(),
                    encoding: "hex",
                    raw: token,
                });
            } else if (fragment) {
                result.push({
                    algorithm: "sha256",
                    digest: fragment[1].toLowerCase(),
                    encoding: "hex",
                    raw: token,
                });
            } else if (/^[a-f0-9]{64}$/iu.test(token)) {
                result.push({
                    algorithm: "sha256",
                    digest: token.toLowerCase(),
                    encoding: "hex",
                    raw: token,
                });
            }
        }
    }
    const seen = new Set();
    return result.filter((entry) => {
        const key = `${entry.algorithm}:${entry.encoding}:${entry.digest}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    }).slice(0, DEPENDENCY_INVENTORY_LIMITS.integrityValuesPerPackage);
}

function parseGitReference(value) {
    const raw = String(value || "");
    let normalized = raw.replace(/^git\+/iu, "");
    const pipSuffix = normalized.match(/^(https:\/\/[^#?]+?\.git)@([^#?]+)(.*)$/iu);
    const pipRef = pipSuffix?.[2] || "";
    if (pipSuffix) normalized = `${pipSuffix[1]}${pipSuffix[3]}`;
    const url = safeUrl(normalized);
    const fragment = url?.hash ? decodeURIComponent(url.hash.slice(1)): "";
    if (url) url.hash = "";
    const queryRev = url?.searchParams.get("rev") || url?.searchParams.get("ref") || "";
    const ref = fragment || queryRev || pipRef || null;
    const commit = ref && COMMIT_RE.test(ref) ? ref.toLowerCase(): null;
    return {
        url: url?.toString() || normalized.split("#", 1)[0] || null,
        ref,
        commit,
        mutable: commit === null,
    };
}

function npmArtifactUrl(name, version) {
    if (!name || !version) return null;
    const leaf = name.includes("/") ? name.slice(name.lastIndexOf("/") + 1): name;
    return `https://registry.npmjs.org/${encodeURIComponent(name)}/-/${encodeURIComponent(leaf)}-${encodeURIComponent(version)}.tgz`;
}

function cratesArtifactUrl(name, version) {
    if (!name || !version) return null;
    return `https://static.crates.io/crates/${encodeURIComponent(name)}/${encodeURIComponent(name)}-${encodeURIComponent(version)}.crate`;
}

function pypiMetadataUrl(name, version) {
    if (!name || !version) return null;
    return `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`;
}

function nugetArtifactUrl(name, version) {
    if (!name || !version) return null;
    const id = name.toLowerCase();
    const normalizedVersion = version.toLowerCase();
    return `https://api.nuget.org/v3-flatcontainer/${encodeURIComponent(id)}/${encodeURIComponent(normalizedVersion)}/${encodeURIComponent(id)}.${encodeURIComponent(normalizedVersion)}.nupkg`;
}

function classifySource({
    ecosystem,
    name,
    version,
    source,
    resolved,
    localPath,
}) {
    const candidate = String(resolved || source || "");
    if (localPath || /^(?:file:|link:|workspace:|path:|\.\.?[\\/])/iu.test(candidate)) {
        return {
            sourceType: candidate.startsWith("workspace:") ? "workspace": "local",
            sourceUrl: null,
            registryHost: null,
            artifactUrl: null,
            metadataUrl: null,
            localPath: String(localPath || candidate || ".").slice(0, 4_096),
            git: null,
        };
    }
    if (/^(?:git\+|git:|github:|https:\/\/github\.com\/)/iu.test(candidate)) {
        return {
            sourceType: "git",
            sourceUrl: candidate || null,
            registryHost: null,
            artifactUrl: null,
            metadataUrl: null,
            localPath: null,
            git: parseGitReference(candidate),
        };
    }
    if (ecosystem === "cargo" && candidate.startsWith("registry+")) {
        const registryUrl = safeUrl(candidate.slice("registry+".length));
        const cratesIo = registryUrl?.hostname.toLowerCase() === "github.com"
            && registryUrl.pathname.replace(/\.git$/iu, "")
                === "/rust-lang/crates.io-index";
        return {
            sourceType: "registry",
            sourceUrl: registryUrl?.toString() || candidate,
            registryHost: cratesIo ? "static.crates.io": registryUrl?.hostname.toLowerCase() || null,
            artifactUrl: cratesIo ? cratesArtifactUrl(name, version): null,
            metadataUrl: null,
            localPath: null,
            git: null,
        };
    }
    const direct = safeUrl(candidate);
    if (direct?.protocol === "https:") {
        if (/^#sha256=[a-f0-9]{64}$/iu.test(direct.hash)) direct.hash = "";
        return {
            sourceType: "url",
            sourceUrl: direct.toString(),
            registryHost: direct.hostname.toLowerCase(),
            artifactUrl: direct.toString(),
            metadataUrl: null,
            localPath: null,
            git: null,
        };
    }
    if (ecosystem === "npm") {
        const artifactUrl = npmArtifactUrl(name, version);
        return {
            sourceType: "registry",
            sourceUrl: "https://registry.npmjs.org/",
            registryHost: "registry.npmjs.org",
            artifactUrl,
            metadataUrl: null,
            localPath: null,
            git: null,
        };
    }
    if (ecosystem === "cargo") {
        const artifactUrl = cratesArtifactUrl(name, version);
        return {
            sourceType: "registry",
            sourceUrl: "https://github.com/rust-lang/crates.io-index",
            registryHost: "static.crates.io",
            artifactUrl,
            metadataUrl: null,
            localPath: null,
            git: null,
        };
    }
    if (ecosystem === "python") {
        return {
            sourceType: "registry",
            sourceUrl: "https://pypi.org/simple/",
            registryHost: "pypi.org",
            artifactUrl: null,
            metadataUrl: pypiMetadataUrl(name, version),
            localPath: null,
            git: null,
        };
    }
    if (ecosystem === "nuget") {
        return {
            sourceType: "registry",
            sourceUrl: "https://api.nuget.org/v3/index.json",
            registryHost: "api.nuget.org",
            artifactUrl: nugetArtifactUrl(name, version),
            metadataUrl: null,
            localPath: null,
            git: null,
        };
    }
    return {
        sourceType: "url",
        sourceUrl: candidate || null,
        registryHost: null,
        artifactUrl: null,
        metadataUrl: null,
        localPath: null,
        git: null,
    };
}

function createBuilder(identity, format, ecosystem) {
    const manifestBase = {
        schemaVersion: DEPENDENCY_INVENTORY_SCHEMA_REVISION,
        auditId: identity.auditId,
        sourceNamespace: identity.sourceNamespace,
        path: identity.path,
        format,
        ecosystem,
        contentSha256: identity.contentSha256,
    };
    const manifestId = `ztdm-${sha256(Buffer.from(
        canonicalJson(manifestBase),
        "utf8",
    ))}`;
    return {
        ...manifestBase,
        manifestId,
        packages: [],
        packageKeys: new Map(),
        edges: [],
        edgeKeys: new Set(),
        roots: new Set(),
        blockerCodes: new Set(),
    };
}

function addPackage(builder, value) {
    if (builder.packages.length >= DEPENDENCY_INVENTORY_LIMITS.packages) {
        builder.blockerCodes.add(DEPENDENCY_BLOCKERS.RECURSION_CAP);
        return null;
    }
    const name = String(value.name || "").normalize("NFKC").trim();
    if (!PACKAGE_NAME_RE.test(name)) {
        builder.blockerCodes.add(DEPENDENCY_BLOCKERS.INVALID_LOCKFILE);
        return null;
    }
    const version = value.version === null || value.version === undefined
        ? null: String(value.version).trim().slice(0, 512);
    const source = classifySource({
        ecosystem: builder.ecosystem,
        name: value.aliasFor || name,
        version,
        source: value.source,
        resolved: value.resolved,
        localPath: value.localPath,
    });
    const integrity = normalizeIntegrity(value.integrity || []);
    const blockerCodes = new Set(value.blockerCodes || []);
    if (source.git?.mutable) blockerCodes.add(DEPENDENCY_BLOCKERS.MUTABLE_REF);
    if (source.sourceType === "git") {
        blockerCodes.add(DEPENDENCY_BLOCKERS.UNSUPPORTED_REGISTRY);
    }
    if (["registry", "url"].includes(source.sourceType)) {
        if (integrity.length === 0) blockerCodes.add(DEPENDENCY_BLOCKERS.MISSING_INTEGRITY);
        const urls = [source.artifactUrl, source.metadataUrl].filter(Boolean);
        if (!source.registryHost
            || urls.length === 0
            || urls.some((url) => !isAllowedRegistryUrl(url))) {
            blockerCodes.add(DEPENDENCY_BLOCKERS.UNSUPPORTED_REGISTRY);
        }
    }
    const lifecycleHooks = uniqueSorted(
        value.lifecycleHooks || [],
        DEPENDENCY_INVENTORY_LIMITS.hooksPerPackage,
    );
    const buildHooks = uniqueSorted(
        value.buildHooks || [],
        DEPENDENCY_INVENTORY_LIMITS.hooksPerPackage,
    );
    const dependencies = (value.dependencies || [])
        .slice(0, DEPENDENCY_INVENTORY_LIMITS.dependenciesPerPackage)
        .map((entry) => ({
            name: String(entry.name || "").slice(0, 512),
            version: entry.version === undefined ? null: String(entry.version).slice(0, 512),
            source: entry.source === undefined ? null: String(entry.source).slice(0, 4_096),
            optional: entry.optional === true,
        }));
    if ((value.dependencies || []).length > dependencies.length) {
        blockerCodes.add(DEPENDENCY_BLOCKERS.RECURSION_CAP);
    }
    const artifactCandidates = (value.artifactCandidates || [])
        .slice(0, DEPENDENCY_INVENTORY_LIMITS.artifactCandidatesPerPackage)
        .map((entry) => ({
            file: String(entry.file || "").slice(0, 1_024),
            integrity: normalizeIntegrity(entry.integrity || []),
        }))
        .filter((entry) => entry.file && entry.integrity.length > 0);
    const locator = String(value.locator || `${name}@${version || "unknown"}`).slice(0, 4_096);
    const key = `${builder.ecosystem}\0${locator}`;
    if (builder.packageKeys.has(key)) return builder.packageKeys.get(key);
    const descriptor = {
        schemaVersion: DEPENDENCY_INVENTORY_SCHEMA_REVISION,
        auditId: builder.auditId,
        sourceNamespace: builder.sourceNamespace,
        manifestId: builder.manifestId,
        ecosystem: builder.ecosystem,
        name,
        version,
        locator,
        sourceType: source.sourceType,
        sourceUrl: source.sourceUrl,
        registryHost: source.registryHost,
        artifactUrl: source.artifactUrl,
        metadataUrl: source.metadataUrl,
        integrity,
        artifactCandidates,
        aliasFor: value.aliasFor ? String(value.aliasFor).slice(0, 512): null,
        localPath: source.localPath,
        git: source.git,
        lifecycleHooks,
        buildHooks,
        dependencies,
        blockerCodes: uniqueSorted(blockerCodes),
    };
    const packageId = `ztdp-${sha256(Buffer.from(canonicalJson(descriptor), "utf8"))}`;
    const record = cloneFrozen({ ...descriptor, packageId });
    builder.packages.push(record);
    builder.packageKeys.set(key, record);
    for (const code of record.blockerCodes) builder.blockerCodes.add(code);
    return record;
}

function addEdge(builder, fromPackageId, toPackageId, dependencyName, optional = false) {
    if (!fromPackageId || !toPackageId || fromPackageId === toPackageId) return;
    if (builder.edges.length >= DEPENDENCY_INVENTORY_LIMITS.edges) {
        builder.blockerCodes.add(DEPENDENCY_BLOCKERS.RECURSION_CAP);
        return;
    }
    const descriptor = {
        fromPackageId,
        toPackageId,
        dependencyName: String(dependencyName || "").slice(0, 512),
        optional: optional === true,
    };
    const key = canonicalJson(descriptor);
    if (builder.edgeKeys.has(key)) return;
    builder.edgeKeys.add(key);
    builder.edges.push(cloneFrozen({
        edgeId: `ztde-${sha256(Buffer.from(key, "utf8"))}`,
        ...descriptor,
    }));
}

function finalizeBuilder(builder) {
    if (builder.packages.length > 0 && builder.roots.size === 0) {
        for (const record of builder.packages) builder.roots.add(record.packageId);
    }
    const packages = [...builder.packages].sort((a, b) =>
        a.packageId.localeCompare(b.packageId));
    const edges = [...builder.edges].sort((a, b) => a.edgeId.localeCompare(b.edgeId));
    const rootPackageIds = [...builder.roots]
        .filter((id) => packages.some((record) => record.packageId === id))
        .sort();
    const blockerCodes = uniqueSorted(builder.blockerCodes);
    const hashesBase = {
        manifestSha256: builder.contentSha256,
        packagesSha256: sha256(Buffer.from(canonicalJson(packages), "utf8")),
        edgesSha256: sha256(Buffer.from(canonicalJson(edges), "utf8")),
    };
    const snapshotBase = {
        schemaVersion: DEPENDENCY_INVENTORY_SCHEMA_REVISION,
        auditId: builder.auditId,
        sourceNamespace: builder.sourceNamespace,
        manifestId: builder.manifestId,
        path: builder.path,
        format: builder.format,
        ecosystem: builder.ecosystem,
        status: blockerCodes.length === 0 ? "inventoried": "blocked",
        packages,
        edges,
        rootPackageIds,
        blockerCodes,
        hashes: hashesBase,
    };
    return cloneFrozen({
        ...snapshotBase,
        hashes: {
            ...hashesBase,
            inventorySha256: sha256(Buffer.from(canonicalJson(snapshotBase), "utf8")),
        },
    });
}

function npmNameFromInstallPath(installPath, fallback) {
    if (fallback) return fallback;
    const match = String(installPath).match(
        /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/u,
    );
    return match?.[1] || null;
}

function npmAlias(version) {
    const match = String(version || "").match(/^npm:((?:@[^/]+\/)?[^@]+)@(.+)$/u);
    return match ? { name: match[1], version: match[2] }: null;
}

function npmSource(entry) {
    return entry.resolved || entry.version || "";
}

function npmResolutionCandidates(parentPath, dependencyName) {
    const candidates = [];
    let base = String(parentPath || "");
    while (true) {
        candidates.push(
            base ? `${base}/node_modules/${dependencyName}`: `node_modules/${dependencyName}`,
        );
        const match = base.match(/^(.*?)(?:\/)?node_modules\/(?:@[^/]+\/)?[^/]+$/u);
        if (!match) break;
        base = match[1].replace(/\/$/u, "");
    }
    return uniqueSorted(candidates);
}

function parseNpmLock(identity, document) {
    const builder = createBuilder(identity, "npm-lock", "npm");
    if (document.packages && typeof document.packages === "object") {
        const byInstallPath = new Map();
        for (const [installPath, rawEntry] of Object.entries(document.packages)) {
            if (!installPath || !rawEntry || typeof rawEntry !== "object") continue;
            const alias = npmAlias(rawEntry.version);
            const name = npmNameFromInstallPath(installPath, rawEntry.name) || alias?.name;
            const version = alias?.version || rawEntry.version || null;
            const record = addPackage(builder, {
                locator: installPath,
                name,
                version,
                resolved: npmSource(rawEntry),
                integrity: rawEntry.integrity || [],
                aliasFor: alias?.name || null,
                localPath: rawEntry.link ? installPath: null,
                lifecycleHooks: rawEntry.hasInstallScript ? ["install-script-present"]: [],
                buildHooks: rawEntry.gypfile ? ["node-gyp"]: [],
                dependencies: Object.entries({
                    ...(rawEntry.dependencies || {}),
                    ...(rawEntry.optionalDependencies || {}),
                }).map(([dependencyName, dependencyVersion]) => ({
                    name: dependencyName,
                    version: dependencyVersion,
                    optional: Object.hasOwn(rawEntry.optionalDependencies || {}, dependencyName),
                })),
            });
            if (record) byInstallPath.set(installPath, record);
        }
        const rootEntry = document.packages[""] || {};
        for (const dependencyName of Object.keys({
            ...(rootEntry.dependencies || document.dependencies || {}),
            ...(rootEntry.optionalDependencies || {}),
            ...(rootEntry.devDependencies || {}),
        })) {
            const root = byInstallPath.get(`node_modules/${dependencyName}`);
            if (root) builder.roots.add(root.packageId);
        }
        for (const [installPath, record] of byInstallPath) {
            for (const dependency of record.dependencies) {
                const target = npmResolutionCandidates(installPath, dependency.name)
                    .map((candidate) => byInstallPath.get(candidate))
                    .find(Boolean);
                if (target) {
                    addEdge(
                        builder,
                        record.packageId,
                        target.packageId,
                        dependency.name,
                        dependency.optional,
                    );
                } else {
                    builder.blockerCodes.add(DEPENDENCY_BLOCKERS.TRANSITIVE_UNRESOLVED);
                }
            }
        }
        return finalizeBuilder(builder);
    }

    const walk = (dependencies, parent = null, pathPrefix = "") => {
        if (!dependencies || typeof dependencies !== "object") return;
        for (const [name, rawEntry] of Object.entries(dependencies)) {
            if (!rawEntry || typeof rawEntry !== "object") continue;
            const locator = `${pathPrefix}node_modules/${name}`;
            const alias = npmAlias(rawEntry.version);
            const record = addPackage(builder, {
                locator,
                name,
                version: alias?.version || rawEntry.version || null,
                resolved: npmSource(rawEntry),
                integrity: rawEntry.integrity || [],
                aliasFor: alias?.name || null,
                lifecycleHooks: rawEntry.hasInstallScript ? ["install-script-present"]: [],
                dependencies: Object.entries(rawEntry.requires || {}).map(
                    ([dependencyName, dependencyVersion]) => ({
                        name: dependencyName,
                        version: dependencyVersion,
                    }),
                ),
            });
            if (!record) continue;
            if (parent) addEdge(builder, parent.packageId, record.packageId, name);
            else builder.roots.add(record.packageId);
            walk(rawEntry.dependencies, record, `${locator}/`);
        }
    };
    walk(document.dependencies);
    return finalizeBuilder(builder);
}

function readTomlAssignments(block) {
    const assignments = new Map();
    const lines = String(block).split(/\r?\n/u);
    for (let index = 0; index < lines.length; index += 1) {
        const match = lines[index].match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/u);
        if (!match) continue;
        let value = match[2].trim();
        let square = (value.match(/\[/gu) || []).length - (value.match(/\]/gu) || []).length;
        let curly = (value.match(/\{/gu) || []).length - (value.match(/\}/gu) || []).length;
        while ((square > 0 || curly > 0) && index + 1 < lines.length) {
            index += 1;
            value += `\n${lines[index].trim()}`;
            square += (lines[index].match(/\[/gu) || []).length
                - (lines[index].match(/\]/gu) || []).length;
            curly += (lines[index].match(/\{/gu) || []).length
                - (lines[index].match(/\}/gu) || []).length;
        }
        assignments.set(match[1], value);
    }
    return assignments;
}

function tomlString(value) {
    if (typeof value !== "string") return null;
    const trimmed = value.trim();
    if (trimmed.startsWith("\"")) {
        try {
            return JSON.parse(trimmed);
        } catch {
            return null;
        }
    }
    if (trimmed.startsWith("'") && trimmed.endsWith("'")) return trimmed.slice(1, -1);
    return null;
}

function tomlStrings(value) {
    const result = [];
    const pattern = /"((?:\\.|[^"\\])*)"/gu;
    for (const match of String(value || "").matchAll(pattern)) {
        try {
            result.push(JSON.parse(`"${match[1]}"`));
        } catch {
            // Malformed strings are rejected by the missing required fields below.
        }
    }
    return result;
}

function tomlPackageBlocks(text) {
    const matches = [...String(text).matchAll(/^\[\[package\]\]\s*$/gmu)];
    return matches.map((match, index) => String(text).slice(
        match.index + match[0].length,
        matches[index + 1]?.index ?? String(text).length,
    ));
}

function cargoDependency(value) {
    const match = String(value).match(/^(.+?)\s+([^\s]+)(?:\s+\((.+)\))?$/u);
    return match
        ? { name: match[1], version: match[2], source: match[3] || null }: { name: String(value), version: null, source: null };
}

function parseCargoLock(identity, text) {
    const builder = createBuilder(identity, "cargo-lock", "cargo");
    const byKey = new Map();
    const localRecords = [];
    for (const [index, block] of tomlPackageBlocks(text).entries()) {
        const values = readTomlAssignments(block);
        const name = tomlString(values.get("name"));
        const version = tomlString(values.get("version"));
        const source = tomlString(values.get("source"));
        const checksum = tomlString(values.get("checksum"));
        const dependencies = tomlStrings(values.get("dependencies")).map(cargoDependency);
        const record = addPackage(builder, {
            locator: `${name}@${version}:${source || `workspace-${index}`}`,
            name,
            version,
            source: source || "workspace:",
            localPath: source ? null: ".",
            integrity: checksum ? [`sha256:${checksum}`]: [],
            dependencies,
        });
        if (!record) continue;
        if (!source) localRecords.push(record);
        const key = `${record.name}\0${record.version || ""}\0${source || ""}`;
        byKey.set(key, record);
    }
    for (const record of builder.packages) {
        for (const dependency of record.dependencies) {
            const exactKey = `${dependency.name}\0${dependency.version || ""}\0${dependency.source || ""}`;
            let target = byKey.get(exactKey);
            if (!target) {
                const candidates = builder.packages.filter((entry) =>
                    entry.name === dependency.name
                    && (!dependency.version || entry.version === dependency.version));
                if (candidates.length === 1) [target] = candidates;
            }
            if (target) addEdge(builder, record.packageId, target.packageId, dependency.name);
            else builder.blockerCodes.add(DEPENDENCY_BLOCKERS.TRANSITIVE_UNRESOLVED);
        }
    }
    for (const local of localRecords) {
        if (local.dependencies.length > 0) builder.roots.add(local.packageId);
    }
    return finalizeBuilder(builder);
}

function collapseRequirementLines(text) {
    const lines = [];
    let current = "";
    for (const rawLine of String(text).split(/\r?\n/u)) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        current = current ? `${current} ${line}`: line;
        if (current.endsWith("\\")) {
            current = current.slice(0, -1).trimEnd();
        } else {
            lines.push(current);
            current = "";
        }
    }
    if (current) lines.push(current);
    return lines;
}

function requirementHashes(line) {
    return [
        ...line.matchAll(/--hash(?:=|\s+)(sha(?:1|256|384|512):[A-Fa-f0-9]+)/gu),
        ...line.matchAll(/[#&](sha256=[A-Fa-f0-9]{64})(?:&|$)/gu),
    ].map((match) => match[1]);
}

function parseRequirementLine(line) {
    const cleaned = line
        .replace(/\s+--hash(?:=|\s+)sha(?:1|256|384|512):[A-Fa-f0-9]+/giu, "")
        .replace(/\s+--(?:index-url|extra-index-url|trusted-host)\s+\S+/giu, "")
        .trim();
    const direct = cleaned.match(
        /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*@\s*(\S+)/u,
    );
    if (direct) {
        const source = direct[2];
        return {
            name: direct[1],
            version: null,
            source,
            git: /^(?:git\+|git:)/iu.test(source),
        };
    }
    if (/^(?:git\+|git:)/iu.test(cleaned)) {
        const egg = cleaned.match(/[#&]egg=([A-Za-z0-9_.-]+)/u);
        return {
            name: egg?.[1] || "unnamed-git-dependency",
            version: null,
            source: cleaned,
            git: true,
        };
    }
    const pinned = cleaned.match(
        /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;]+)(?:\s*;.*)?$/u,
    );
    if (pinned) {
        return { name: pinned[1], version: pinned[2], source: null, git: false };
    }
    const url = cleaned.match(/^(https:\/\/\S+)/u);
    if (url) {
        const parsed = safeUrl(url[1]);
        const filename = parsed ? nodePath.posix.basename(parsed.pathname): "direct-url";
        return { name: filename, version: null, source: url[1], git: false };
    }
    return null;
}

function parseRequirements(identity, text) {
    const builder = createBuilder(identity, "requirements-lock", "python");
    for (const [index, line] of collapseRequirementLines(text).entries()) {
        if (/^(?:-r|--requirement|-c|--constraint)\b/u.test(line)) {
            builder.blockerCodes.add(DEPENDENCY_BLOCKERS.TRANSITIVE_UNRESOLVED);
            continue;
        }
        const parsed = parseRequirementLine(line);
        if (!parsed) {
            builder.blockerCodes.add(DEPENDENCY_BLOCKERS.INVALID_LOCKFILE);
            continue;
        }
        const hashes = requirementHashes(line);
        const git = parsed.git ? parseGitReference(parsed.source): null;
        const record = addPackage(builder, {
            locator: `requirement-${index}:${parsed.name}@${parsed.version || git?.ref || "direct"}`,
            name: parsed.name,
            version: parsed.version,
            source: parsed.source,
            integrity: hashes,
        });
        if (record) builder.roots.add(record.packageId);
    }
    return finalizeBuilder(builder);
}

function parsePipfileLock(identity, document) {
    const builder = createBuilder(identity, "pipfile-lock", "python");
    for (const section of ["default", "develop"]) {
        for (const [name, rawValue] of Object.entries(document[section] || {})) {
            const entry = typeof rawValue === "string" ? { version: rawValue }: rawValue;
            if (!entry || typeof entry !== "object") continue;
            const version = String(entry.version || "").replace(/^==/u, "") || null;
            const source = entry.git
                ? `${entry.git}${entry.ref ? `#${entry.ref}`: ""}`: entry.path || entry.file || null;
            const record = addPackage(builder, {
                locator: `${section}:${name}@${version || entry.ref || "direct"}`,
                name,
                version,
                source,
                localPath: entry.path || null,
                integrity: entry.hashes || [],
            });
            if (record) builder.roots.add(record.packageId);
        }
    }
    return finalizeBuilder(builder);
}

function poetryPackageSections(text) {
    const matches = [...String(text).matchAll(/^\[\[package\]\]\s*$/gmu)];
    return matches.map((match, index) => String(text).slice(
        match.index + match[0].length,
        matches[index + 1]?.index ?? String(text).length,
    ));
}

function poetryFiles(value) {
    const result = [];
    const pattern =
        /\{\s*file\s*=\s*"((?:\\.|[^"\\])*)"\s*,\s*hash\s*=\s*"((?:\\.|[^"\\])*)"\s*\}/gu;
    for (const match of String(value || "").matchAll(pattern)) {
        try {
            result.push({
                file: JSON.parse(`"${match[1]}"`),
                integrity: [JSON.parse(`"${match[2]}"`)],
            });
        } catch {
            // Malformed candidates are ignored and become missing-integrity blockers.
        }
    }
    return result;
}

function tomlSubtable(block, tableName) {
    const header = `[${tableName}]`;
    const lines = String(block).split(/\r?\n/u);
    const start = lines.findIndex((line) => line.trim() === header);
    if (start < 0) return "";
    const body = [];
    for (let index = start + 1; index < lines.length; index += 1) {
        if (/^\s*\[[^\]]+\]\s*$/u.test(lines[index])) break;
        body.push(lines[index]);
    }
    return body.join("\n");
}

function poetryDependencyNames(block) {
    return tomlSubtable(block, "package.dependencies").split(/\r?\n/u)
        .map((line) => line.match(/^([A-Za-z0-9_.-]+)\s*=/u)?.[1])
        .filter(Boolean);
}

function parsePoetryLock(identity, text) {
    const builder = createBuilder(identity, "poetry-lock", "python");
    const byName = new Map();
    for (const [index, block] of poetryPackageSections(text).entries()) {
        const packagePart = block.split(/^\[package\./mu, 1)[0];
        const values = readTomlAssignments(packagePart);
        const sourceValues = readTomlAssignments(
            tomlSubtable(block, "package.source"),
        );
        const name = tomlString(values.get("name"));
        const version = tomlString(values.get("version"));
        const sourceType = tomlString(sourceValues.get("type"));
        const sourceUrl = tomlString(sourceValues.get("url"));
        const sourceReference = tomlString(
            sourceValues.get("resolved_reference") || sourceValues.get("reference"),
        );
        let source = null;
        let localPath = null;
        if (sourceType === "git" && sourceUrl) {
            source = `${sourceUrl}${sourceReference ? `#${sourceReference}`: ""}`;
        } else if (["directory", "file"].includes(sourceType)) {
            localPath = sourceUrl || ".";
        } else if (sourceType === "url") {
            source = sourceUrl;
        }
        const artifactCandidates = poetryFiles(values.get("files"));
        const record = addPackage(builder, {
            locator: `poetry-${index}:${name}@${version}`,
            name,
            version,
            source,
            localPath,
            integrity: artifactCandidates.flatMap((entry) => entry.integrity),
            artifactCandidates,
            dependencies: poetryDependencyNames(block).map((dependencyName) => ({
                name: dependencyName,
            })),
        });
        if (!record) continue;
        if (!byName.has(record.name.toLowerCase())) byName.set(record.name.toLowerCase(), []);
        byName.get(record.name.toLowerCase()).push(record);
    }
    for (const record of builder.packages) {
        for (const dependency of record.dependencies) {
            const candidates = byName.get(dependency.name.toLowerCase()) || [];
            if (candidates.length === 1) {
                addEdge(builder, record.packageId, candidates[0].packageId, dependency.name);
            } else {
                builder.blockerCodes.add(DEPENDENCY_BLOCKERS.TRANSITIVE_UNRESOLVED);
            }
        }
    }
    const dependedOn = new Set(builder.edges.map((edge) => edge.toPackageId));
    for (const record of builder.packages) {
        if (!dependedOn.has(record.packageId)) builder.roots.add(record.packageId);
    }
    return finalizeBuilder(builder);
}

function parseNugetLock(identity, document) {
    const builder = createBuilder(identity, "nuget-packages-lock", "nuget");
    const byNameVersion = new Map();
    const pending = [];
    for (const [framework, packages] of Object.entries(document.dependencies || {})) {
        if (!packages || typeof packages !== "object") continue;
        for (const [name, rawEntry] of Object.entries(packages)) {
            if (!rawEntry || typeof rawEntry !== "object") continue;
            const version = rawEntry.resolved || rawEntry.version || null;
            const key = `${name.toLowerCase()}\0${String(version || "").toLowerCase()}`;
            let record = byNameVersion.get(key);
            if (!record) {
                record = addPackage(builder, {
                    locator: `${name}@${version}`,
                    name,
                    version,
                    integrity: rawEntry.contentHash ? [`sha512-${rawEntry.contentHash}`]: [],
                    dependencies: Object.entries(rawEntry.dependencies || {}).map(
                        ([dependencyName, dependencyVersion]) => ({
                            name: dependencyName,
                            version: dependencyVersion,
                        }),
                    ),
                });
                if (record) byNameVersion.set(key, record);
            }
            if (!record) continue;
            if (String(rawEntry.type || "").toLowerCase() === "direct") {
                builder.roots.add(record.packageId);
            }
            pending.push({ framework, record, dependencies: rawEntry.dependencies || {} });
        }
    }
    for (const { record, dependencies } of pending) {
        for (const [name, versionSpec] of Object.entries(dependencies)) {
            const normalizedName = name.toLowerCase();
            const exact = String(versionSpec).replace(/^[[(]\s*/u, "").split(/[,\s)\]]/u, 1)[0];
            let target = byNameVersion.get(`${normalizedName}\0${exact.toLowerCase()}`);
            if (!target) {
                const candidates = [...byNameVersion.entries()]
                    .filter(([key]) => key.startsWith(`${normalizedName}\0`))
                    .map(([, entry]) => entry);
                if (candidates.length === 1) [target] = candidates;
            }
            if (target) addEdge(builder, record.packageId, target.packageId, name);
            else builder.blockerCodes.add(DEPENDENCY_BLOCKERS.TRANSITIVE_UNRESOLVED);
        }
    }
    return finalizeBuilder(builder);
}

function decodeXml(value) {
    return String(value || "")
        .replace(/&quot;/gu, "\"")
        .replace(/&apos;/gu, "'")
        .replace(/&lt;/gu, "<")
        .replace(/&gt;/gu, ">")
        .replace(/&amp;/gu, "&");
}

function xmlAttribute(tag, name) {
    return decodeXml(tag.match(new RegExp(`\\b${name}\\s*=\\s*["']([^"']+)["']`, "iu"))?.[1]);
}

function parsePackagesConfig(identity, text) {
    const builder = createBuilder(identity, "nuget-packages-config", "nuget");
    for (const [index, match] of [...text.matchAll(/<package\b[^>]*\/?>/giu)].entries()) {
        const name = xmlAttribute(match[0], "id");
        const version = xmlAttribute(match[0], "version");
        const record = addPackage(builder, {
            locator: `packages-config-${index}:${name}@${version}`,
            name,
            version,
            integrity: [],
        });
        if (record) builder.roots.add(record.packageId);
    }
    if (builder.packages.length === 0) {
        builder.blockerCodes.add(DEPENDENCY_BLOCKERS.INVALID_LOCKFILE);
    }
    return finalizeBuilder(builder);
}

function detectFormat(path, text) {
    const base = nodePath.posix.basename(path).toLowerCase();
    if (["package-lock.json", "npm-shrinkwrap.json"].includes(base)) return "npm";
    if (base === "cargo.lock") return "cargo";
    if (base === "poetry.lock") return "poetry";
    if (base === "pipfile.lock") return "pipfile";
    if (base === "packages.lock.json") return "nuget-lock";
    if (base === "packages.config") return "packages-config";
    if (/^(?:requirements|constraints)(?:[._-].*)?\.(?:txt|in)$/u.test(base)
        || base === "requirements.txt") return "requirements";
    const trimmed = text.trimStart();
    if (trimmed.startsWith("{")) {
        const document = parseJson(text, path);
        if (document.lockfileVersion || document.packages) return "npm";
        if (document.default || document.develop) return "pipfile";
        if (document.dependencies) return "nuget-lock";
    }
    if (/^\[\[package\]\]/mu.test(text)) {
        return /\bchecksum\s*=/u.test(text) && /\bsource\s*=\s*"registry\+/u.test(text)
            ? "cargo": "poetry";
    }
    return null;
}

export function parseDependencyManifest({
    auditId,
    sourceNamespace,
    path,
    text,
    contentSha256 = null,
} = {}) {
    const identity = validateIdentity({
        auditId,
        sourceNamespace,
        path,
        text,
        contentSha256,
    });
    const format = detectFormat(identity.path, text);
    if (!format) {
        const builder = createBuilder(identity, "unsupported-lockfile", "python");
        builder.blockerCodes.add(DEPENDENCY_BLOCKERS.INVALID_LOCKFILE);
        return finalizeBuilder(builder);
    }
    if (format === "npm") return parseNpmLock(identity, parseJson(text, identity.path));
    if (format === "cargo") return parseCargoLock(identity, text);
    if (format === "poetry") return parsePoetryLock(identity, text);
    if (format === "pipfile") {
        return parsePipfileLock(identity, parseJson(text, identity.path));
    }
    if (format === "nuget-lock") {
        return parseNugetLock(identity, parseJson(text, identity.path));
    }
    if (format === "packages-config") return parsePackagesConfig(identity, text);
    return parseRequirements(identity, text);
}

export function parseDependencyManifests({
    auditId,
    sourceNamespace,
    manifests,
} = {}) {
    if (!Array.isArray(manifests) || manifests.length === 0
        || manifests.length > DEPENDENCY_INVENTORY_LIMITS.manifests) {
        throw new TypeError(
            `manifests must contain 1-${DEPENDENCY_INVENTORY_LIMITS.manifests} entries`,
        );
    }
    const inventories = manifests.map((manifest) => parseDependencyManifest({
        auditId,
        sourceNamespace,
        ...manifest,
    }));
    const blockerCodes = uniqueSorted(inventories.flatMap((entry) => entry.blockerCodes));
    return cloneFrozen({
        schemaVersion: DEPENDENCY_INVENTORY_SCHEMA_REVISION,
        auditId: inventories[0].auditId,
        sourceNamespace: inventories[0].sourceNamespace,
        status: blockerCodes.length === 0 ? "inventoried": "blocked",
        inventories,
        blockerCodes,
        hashes: {
            inventorySetSha256: sha256(Buffer.from(canonicalJson(inventories), "utf8")),
        },
    });
}

export const __internals = Object.freeze({
    canonicalJson,
    classifySource,
    collapseRequirementLines,
    cratesArtifactUrl,
    detectFormat,
    isAllowedRegistryUrl,
    normalizeIntegrity,
    npmArtifactUrl,
    npmResolutionCandidates,
    nugetArtifactUrl,
    parseGitReference,
    pypiMetadataUrl,
    readTomlAssignments,
    requirementHashes,
    tomlPackageBlocks,
    tomlSubtable,
    uniqueSorted,
});
