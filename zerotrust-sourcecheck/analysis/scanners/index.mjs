import {
    SCANNER_LIMITS,
    SCANNER_BLOCKER_CODES,
    SCANNER_SCHEMA_REVISION,
    SEMANTIC_FACT_KINDS,
    SEMANTIC_RESOLUTIONS,
    normalizeScannerPath,
    validateSemanticFact,
} from "./core.mjs";
import {
    SCANNER_REGISTRY,
    getScannerRegistry,
    selectScanner,
} from "./registry.mjs";

const SHA256_RE = /^[a-f0-9]{64}$/u;
const BLOB_SHA_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;

function cloneFrozen(value) {
    if (Array.isArray(value)) return Object.freeze(value.map(cloneFrozen));
    if (value && typeof value === "object") {
        const result = {};
        for (const [key, entry] of Object.entries(value)) result[key] = cloneFrozen(entry);
        return Object.freeze(result);
    }
    return value;
}

export function validateScannerResult(value, path = "scannerResult") {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError(`${path} must be an object`);
    }
    const allowed = new Set([
        "schemaVersion",
        "scannerId",
        "language",
        "path",
        "sourceSha256",
        "byteLength",
        "lineCount",
        "tokenCount",
        "facts",
        "factCount",
        "truncated",
        "blockers",
    ]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) throw new TypeError(`${path}.${key} is not allowed`);
    }
    if (value.schemaVersion !== SCANNER_SCHEMA_REVISION) {
        throw new TypeError(`${path}.schemaVersion must equal ${SCANNER_SCHEMA_REVISION}`);
    }
    if (!SHA256_RE.test(String(value.sourceSha256 || ""))) {
        throw new TypeError(`${path}.sourceSha256 is invalid`);
    }
    for (const field of ["byteLength", "lineCount", "tokenCount", "factCount"]) {
        if (!Number.isSafeInteger(value[field]) || value[field] < 0) {
            throw new TypeError(`${path}.${field} is invalid`);
        }
    }
    if (typeof value.truncated !== "boolean") {
        throw new TypeError(`${path}.truncated must be boolean`);
    }
    if (!Array.isArray(value.facts)
        || value.facts.length > SCANNER_LIMITS.factsPerFile
        || value.factCount !== value.facts.length) {
        throw new TypeError(`${path}.facts is invalid`);
    }
    const facts = value.facts.map((fact, index) =>
        validateSemanticFact(fact, `${path}.facts[${index}]`));
    if (new Set(facts.map((fact) => fact.id)).size !== facts.length) {
        throw new TypeError(`${path}.facts contains duplicate IDs`);
    }
    if (!Array.isArray(value.blockers) || value.blockers.length > 32
        || value.blockers.some((blocker) =>
            typeof blocker !== "string" || !SCANNER_BLOCKER_CODES.includes(blocker))
        || new Set(value.blockers).size !== value.blockers.length) {
        throw new TypeError(`${path}.blockers is invalid`);
    }
    const normalizedPath = normalizeScannerPath(value.path);
    if (facts.some((fact) =>
        fact.path !== normalizedPath
        || fact.scannerId !== value.scannerId
        || fact.language !== value.language)) {
        throw new TypeError(`${path}.facts scanner identity mismatch`);
    }
    return cloneFrozen({
        schemaVersion: SCANNER_SCHEMA_REVISION,
        scannerId: String(value.scannerId),
        language: String(value.language),
        path: normalizedPath,
        sourceSha256: String(value.sourceSha256).toLowerCase(),
        byteLength: value.byteLength,
        lineCount: value.lineCount,
        tokenCount: value.tokenCount,
        facts,
        factCount: facts.length,
        truncated: value.truncated,
        blockers: value.blockers,
    });
}

export function scanSourceText({
    path,
    text,
    maxFacts = SCANNER_LIMITS.factsPerFile,
    maxTokens = SCANNER_LIMITS.tokens,
    registry = SCANNER_REGISTRY,
} = {}) {
    const scanner = selectScanner(path, registry);
    return validateScannerResult(scanner.scan({
        path,
        text,
        maxFacts,
        maxTokens,
    }));
}

export function createSemanticPluginInput(scanResult, {
    blobSha = null,
} = {}) {
    const result = validateScannerResult(scanResult);
    const normalizedBlobSha = blobSha === null || blobSha === undefined
        ? null: String(blobSha).toLowerCase();
    if (normalizedBlobSha !== null && !BLOB_SHA_RE.test(normalizedBlobSha)) {
        throw new TypeError("semanticPluginInput.blobSha is invalid");
    }
    return cloneFrozen({
        schemaVersion: SCANNER_SCHEMA_REVISION,
        path: result.path,
        scannerId: result.scannerId,
        language: result.language,
        contentSha256: result.sourceSha256,
        blobSha: normalizedBlobSha,
        facts: result.facts,
        truncated: result.truncated,
        blockers: result.blockers,
    });
}

export function validateSemanticPluginInput(value, path = "semanticPluginInput") {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError(`${path} must be an object`);
    }
    const allowed = new Set([
        "schemaVersion",
        "path",
        "scannerId",
        "language",
        "contentSha256",
        "blobSha",
        "facts",
        "truncated",
        "blockers",
    ]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) throw new TypeError(`${path}.${key} is not allowed`);
    }
    if (value.schemaVersion !== SCANNER_SCHEMA_REVISION
        || !SHA256_RE.test(String(value.contentSha256 || "").toLowerCase())
        || (value.blobSha !== null && value.blobSha !== undefined
            && !BLOB_SHA_RE.test(String(value.blobSha).toLowerCase()))
        || typeof value.truncated !== "boolean"
        || !Array.isArray(value.facts)
        || value.facts.length > SCANNER_LIMITS.factsPerFile
        || !Array.isArray(value.blockers)
        || value.blockers.length > 32
        || value.blockers.some((blocker) => !SCANNER_BLOCKER_CODES.includes(blocker))
        || new Set(value.blockers).size !== value.blockers.length) {
        throw new TypeError(`${path} is invalid`);
    }
    const facts = value.facts.map((fact, index) =>
        validateSemanticFact(fact, `${path}.facts[${index}]`));
    const normalizedPath = normalizeScannerPath(value.path);
    if (facts.some((fact) =>
        fact.path !== normalizedPath
        || fact.scannerId !== value.scannerId
        || fact.language !== value.language)) {
        throw new TypeError(`${path}.facts scanner identity mismatch`);
    }
    return cloneFrozen({
        schemaVersion: SCANNER_SCHEMA_REVISION,
        path: normalizedPath,
        scannerId: String(value.scannerId),
        language: String(value.language),
        contentSha256: String(value.contentSha256).toLowerCase(),
        blobSha: value.blobSha === null || value.blobSha === undefined
            ? null: String(value.blobSha).toLowerCase(),
        facts,
        truncated: value.truncated,
        blockers: value.blockers,
    });
}

export {
    SCANNER_BLOCKER_CODES,
    SCANNER_LIMITS,
    SCANNER_REGISTRY,
    SCANNER_SCHEMA_REVISION,
    SEMANTIC_FACT_KINDS,
    SEMANTIC_RESOLUTIONS,
    getScannerRegistry,
    selectScanner,
    validateSemanticFact,
};

export { scanJavaScriptSource } from "./javascript.mjs";
export { scanJsonSource } from "./json.mjs";
export { scanPythonSource } from "./python.mjs";
export { scanShellSource } from "./shell.mjs";
export { scanCSharpSource, scanMsbuildXmlSource } from "./dotnet.mjs";
export { scanRustSource, scanCargoTomlSource } from "./rust.mjs";
export { scanYamlSource } from "./yaml.mjs";
export { scanDockerfileSource, scanDevcontainerSource } from "./container.mjs";
export { scanCmakeSource, scanMakeSource } from "./build.mjs";
export { scanGenericSource } from "./generic.mjs";
