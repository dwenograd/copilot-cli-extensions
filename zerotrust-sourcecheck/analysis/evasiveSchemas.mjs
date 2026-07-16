import { createHash } from "node:crypto";

import {
    ASSURANCE_BLOCKER_CODES,
    ASSURANCE_BLOCKERS,
    ASSURANCE_COVERAGE_STATUSES,
    ASSURANCE_LIMITS,
    ASSURANCE_SCHEMA_REVISION,
    EVASION_CLASS_VALUES,
} from "./assurance.mjs";
import {
    ASSURANCE_ANALYSIS_SCHEMA_REVISION,
    validateAssuranceStageState,
} from "./assuranceState.mjs";

if (ASSURANCE_ANALYSIS_SCHEMA_REVISION !== ASSURANCE_SCHEMA_REVISION) {
    throw new Error("assurance analysis and assurance schema revisions must remain aligned");
}

export const EVASIVE_OBJECT_KINDS = Object.freeze([
    "blob",
    "executable-blob",
    "symlink",
    "gitlink",
    "tree",
    "local-file",
    "reparse-point",
    "source-text",
    "binary",
    "archive",
    "archive-entry",
    "embedded-payload",
    "generated-source",
    "manifest",
    "dependency-metadata",
    "release-asset",
    "opaque",
]);

export const EVASIVE_GIT_OBJECT_TYPES = Object.freeze([
    "blob",
    "tree",
    "commit",
]);

export const EVASIVE_GIT_MODES = Object.freeze([
    "040000",
    "100644",
    "100755",
    "120000",
    "160000",
]);

export const EVASIVE_SYMLINK_TARGET_KINDS = Object.freeze([
    "relative",
    "absolute-posix",
    "absolute-windows",
    "unc",
    "invalid",
]);

export const EVASIVE_OBJECT_STATUSES = Object.freeze([
    "inventoried",
    "unsupported",
    "blocked",
]);

export const EVASIVE_DERIVED_ARTIFACT_KINDS = Object.freeze([
    "decoded-text",
    "decoded-binary",
    "abstract-syntax",
    "intermediate-representation",
    "deobfuscated-view",
    "archive-manifest",
    "binary-metadata",
    "dependency-graph",
    "build-graph",
    "payload-index",
    "release-comparison",
]);

export const EVASIVE_DERIVED_ARTIFACT_STATUSES = Object.freeze([
    "decoded",
    "partial",
    "unsupported",
    "blocked",
]);

export const EVASIVE_TRANSFORM_KINDS = Object.freeze([
    "identity",
    "base64",
    "hex",
    "escaped-string",
    "literal-concatenation",
    "literal-array",
    "xor",
    "gzip",
    "deflate",
    "deflate-raw",
    "brotli",
    "tar-entry",
    "zip-entry",
    "archive-manifest",
    "payload-index",
    "binary-metadata",
]);

export const EVASIVE_COVERAGE_STATUSES = ASSURANCE_COVERAGE_STATUSES;

export const EVASIVE_SNAPSHOT_STATUSES = Object.freeze([
    "incomplete",
    "complete",
]);

export const EVASIVE_SEMANTIC_CANDIDATE_SEVERITIES = Object.freeze([
    "info",
    "low",
    "medium",
    "high",
    "critical",
]);

export const EVASIVE_SEMANTIC_CANDIDATE_CONFIDENCE_LEVELS = Object.freeze([
    "low",
    "medium",
    "high",
]);

export const EVASIVE_SEMANTIC_CANDIDATE_FIT_LEVELS = Object.freeze([
    "unknown",
    "unlikely",
    "ambiguous",
    "likely",
    "strong",
]);

export const EVASIVE_SEMANTIC_BENIGN_HYPOTHESIS_CODES = Object.freeze([
    "expected-build-or-runtime-behavior",
    "test-or-development-only",
    "user-initiated-operation",
    "standard-dependency-resolution",
    "generated-code-pipeline",
    "platform-compatibility",
    "insufficient-context",
    "no-benign-hypothesis",
]);

export const EVASIVE_BLOCKER_NAMESPACES = Object.freeze({
    IDENTITY: "identity",
    INVENTORY: "inventory",
    DECODE: "decode",
    SEMANTIC: "semantic",
    SCAN: "scan",
    RED_TEAM: "red-team",
    TRACE: "trace",
    VALIDATION: "validation",
    SUPPLY_CHAIN: "supply-chain",
    BOUNDS: "bounds",
});

export const EVASIVE_BLOCKERS = Object.freeze({
    IDENTITY_NOT_PINNED: "identity/not-pinned",
    INVENTORY_INCOMPLETE: "inventory/incomplete",
    INVENTORY_TRUNCATED: "inventory/truncated",
    UNSUPPORTED_OBJECT: "inventory/unsupported-object",
    GITLINK_UNRESOLVED: "inventory/gitlink-unresolved",
    NESTED_OBJECT_UNRESOLVED: "inventory/nested-object-unresolved",
    REPARSE_POINT_SKIPPED: "inventory/reparse-point-skipped",
    LFS_PAYLOAD_UNRESOLVED: "inventory/lfs-payload-unresolved",
    BINARY_PAYLOAD_COVERAGE_INCOMPLETE:
        "inventory/binary-payload-coverage-incomplete",
    DECODE_INCOMPLETE: "decode/incomplete",
    DECODE_UNSUPPORTED_FORMAT: "decode/unsupported-format",
    DECODE_PARSER_DIFFERENTIAL: "decode/parser-differential",
    DECODE_ENCRYPTED: "decode/encrypted",
    DECODE_PACKED_OR_HIGH_ENTROPY: "decode/packed-or-high-entropy",
    DECODE_UNSAFE_ARCHIVE_PATH: "decode/unsafe-archive-path",
    SEMANTIC_INCOMPLETE: "semantic/incomplete",
    SEMANTIC_TRUNCATED: "semantic/truncated",
    SCAN_INCOMPLETE: "scan/incomplete",
    SCAN_DYNAMIC_BEHAVIOR_UNRESOLVED: "scan/dynamic-behavior-unresolved",
    SCAN_EXTERNAL_PAYLOAD_UNRESOLVED: "scan/external-payload-unresolved",
    RED_TEAM_INCOMPLETE: "red-team/incomplete",
    RED_TEAM_REVIEWER_MANIPULATION: "red-team/reviewer-manipulation",
    RED_TEAM_MISSING_CATEGORY: "red-team/missing-category",
    RED_TEAM_ASSIGNMENT_INCOMPLETE: "red-team/assignment-incomplete",
    RED_TEAM_TRUNCATED: "red-team/truncated",
    TRACE_INCOMPLETE: "trace/incomplete",
    TRACE_CONFLICT: "trace/conflict",
    TRACE_DYNAMIC_TARGET_UNRESOLVED: "trace/dynamic-target-unresolved",
    TRACE_UNSUPPORTED_ARTIFACT: "trace/unsupported-artifact",
    TRACE_MISSING_TARGET: "trace/missing-target",
    TRACE_CYCLE: "trace/cycle",
    TRACE_TRUNCATED: "trace/truncated",
    VALIDATION_INCOMPLETE: "validation/incomplete",
    VALIDATION_NO_FINDING_INCOMPLETE: "validation/no-finding-incomplete",
    VALIDATION_CANDIDATE_INCOMPLETE: "validation/candidate-incomplete",
    SUPPLY_CHAIN_INCOMPLETE: "supply-chain/incomplete",
    RELEASE_SOURCE_DIVERGENCE: "supply-chain/release-source-divergence",
    BOUNDS_EXCEEDED: "bounds/exceeded",
    NESTED_DEPTH_EXCEEDED: "bounds/nested-depth-exceeded",
    ARCHIVE_ENTRY_LIMIT_EXCEEDED: "bounds/archive-entry-limit-exceeded",
    EXPANSION_RATIO_EXCEEDED: "bounds/expansion-ratio-exceeded",
});

export const EVASIVE_BLOCKER_CODES = Object.freeze(Object.values(EVASIVE_BLOCKERS));

export const EVASIVE_BLOCKER_ASSURANCE_CODES = Object.freeze({
    [EVASIVE_BLOCKERS.IDENTITY_NOT_PINNED]: ASSURANCE_BLOCKERS.IDENTITY_NOT_PINNED,
    [EVASIVE_BLOCKERS.INVENTORY_INCOMPLETE]: ASSURANCE_BLOCKERS.INCOMPLETE_ACQUISITION,
    [EVASIVE_BLOCKERS.INVENTORY_TRUNCATED]: ASSURANCE_BLOCKERS.COVERAGE_TRUNCATED,
    [EVASIVE_BLOCKERS.UNSUPPORTED_OBJECT]: ASSURANCE_BLOCKERS.UNSUPPORTED_ARTIFACT,
    [EVASIVE_BLOCKERS.GITLINK_UNRESOLVED]: ASSURANCE_BLOCKERS.INCOMPLETE_SUPPLY_CHAIN,
    [EVASIVE_BLOCKERS.NESTED_OBJECT_UNRESOLVED]:
        ASSURANCE_BLOCKERS.INCOMPLETE_ACQUISITION,
    [EVASIVE_BLOCKERS.REPARSE_POINT_SKIPPED]:
        ASSURANCE_BLOCKERS.INCOMPLETE_ACQUISITION,
    [EVASIVE_BLOCKERS.LFS_PAYLOAD_UNRESOLVED]:
        ASSURANCE_BLOCKERS.UNRESOLVED_EXTERNAL_PAYLOAD,
    [EVASIVE_BLOCKERS.BINARY_PAYLOAD_COVERAGE_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_BINARY_PAYLOAD_COVERAGE,
    [EVASIVE_BLOCKERS.DECODE_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_SYNTACTIC_COVERAGE,
    [EVASIVE_BLOCKERS.DECODE_UNSUPPORTED_FORMAT]:
        ASSURANCE_BLOCKERS.UNSUPPORTED_ARTIFACT,
    [EVASIVE_BLOCKERS.DECODE_PARSER_DIFFERENTIAL]:
        ASSURANCE_BLOCKERS.UNRESOLVED_PARSER_DIFFERENTIAL,
    [EVASIVE_BLOCKERS.DECODE_ENCRYPTED]:
        ASSURANCE_BLOCKERS.UNSUPPORTED_ARTIFACT,
    [EVASIVE_BLOCKERS.DECODE_PACKED_OR_HIGH_ENTROPY]:
        ASSURANCE_BLOCKERS.UNSUPPORTED_ARTIFACT,
    [EVASIVE_BLOCKERS.DECODE_UNSAFE_ARCHIVE_PATH]:
        ASSURANCE_BLOCKERS.UNRESOLVED_PARSER_DIFFERENTIAL,
    [EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_SEMANTIC_COVERAGE,
    [EVASIVE_BLOCKERS.SEMANTIC_TRUNCATED]: ASSURANCE_BLOCKERS.COVERAGE_TRUNCATED,
    [EVASIVE_BLOCKERS.SCAN_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_ACTIVATION_COVERAGE,
    [EVASIVE_BLOCKERS.SCAN_DYNAMIC_BEHAVIOR_UNRESOLVED]:
        ASSURANCE_BLOCKERS.UNRESOLVED_DYNAMIC_BEHAVIOR,
    [EVASIVE_BLOCKERS.SCAN_EXTERNAL_PAYLOAD_UNRESOLVED]:
        ASSURANCE_BLOCKERS.UNRESOLVED_EXTERNAL_PAYLOAD,
    [EVASIVE_BLOCKERS.RED_TEAM_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_ACTIVATION_COVERAGE,
    [EVASIVE_BLOCKERS.RED_TEAM_REVIEWER_MANIPULATION]:
        ASSURANCE_BLOCKERS.UNRESOLVED_REVIEWER_MANIPULATION,
    [EVASIVE_BLOCKERS.RED_TEAM_MISSING_CATEGORY]:
        ASSURANCE_BLOCKERS.INCOMPLETE_ACTIVATION_COVERAGE,
    [EVASIVE_BLOCKERS.RED_TEAM_ASSIGNMENT_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_ACTIVATION_COVERAGE,
    [EVASIVE_BLOCKERS.RED_TEAM_TRUNCATED]:
        ASSURANCE_BLOCKERS.COVERAGE_TRUNCATED,
    [EVASIVE_BLOCKERS.TRACE_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_BEHAVIOR_TRACING,
    [EVASIVE_BLOCKERS.TRACE_CONFLICT]:
        ASSURANCE_BLOCKERS.INCOMPLETE_BEHAVIOR_TRACING,
    [EVASIVE_BLOCKERS.TRACE_DYNAMIC_TARGET_UNRESOLVED]:
        ASSURANCE_BLOCKERS.UNRESOLVED_DYNAMIC_BEHAVIOR,
    [EVASIVE_BLOCKERS.TRACE_UNSUPPORTED_ARTIFACT]:
        ASSURANCE_BLOCKERS.UNSUPPORTED_ARTIFACT,
    [EVASIVE_BLOCKERS.TRACE_MISSING_TARGET]:
        ASSURANCE_BLOCKERS.INCOMPLETE_BEHAVIOR_TRACING,
    [EVASIVE_BLOCKERS.TRACE_CYCLE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_BEHAVIOR_TRACING,
    [EVASIVE_BLOCKERS.TRACE_TRUNCATED]:
        ASSURANCE_BLOCKERS.COVERAGE_TRUNCATED,
    [EVASIVE_BLOCKERS.VALIDATION_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_VALIDATION,
    [EVASIVE_BLOCKERS.VALIDATION_NO_FINDING_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_VALIDATION,
    [EVASIVE_BLOCKERS.VALIDATION_CANDIDATE_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_VALIDATION,
    [EVASIVE_BLOCKERS.SUPPLY_CHAIN_INCOMPLETE]:
        ASSURANCE_BLOCKERS.INCOMPLETE_SUPPLY_CHAIN,
    [EVASIVE_BLOCKERS.RELEASE_SOURCE_DIVERGENCE]:
        ASSURANCE_BLOCKERS.UNRESOLVED_RELEASE_SOURCE_DIVERGENCE,
    [EVASIVE_BLOCKERS.BOUNDS_EXCEEDED]: ASSURANCE_BLOCKERS.COVERAGE_TRUNCATED,
    [EVASIVE_BLOCKERS.NESTED_DEPTH_EXCEEDED]:
        ASSURANCE_BLOCKERS.COVERAGE_TRUNCATED,
    [EVASIVE_BLOCKERS.ARCHIVE_ENTRY_LIMIT_EXCEEDED]:
        ASSURANCE_BLOCKERS.COVERAGE_TRUNCATED,
    [EVASIVE_BLOCKERS.EXPANSION_RATIO_EXCEEDED]:
        ASSURANCE_BLOCKERS.COVERAGE_TRUNCATED,
});

if (ASSURANCE_BLOCKER_CODES.some((code) =>
    !Object.values(EVASIVE_BLOCKER_ASSURANCE_CODES).includes(code))) {
    throw new Error("assurance blocker mapping must cover every assurance blocker code");
}

export const EVASIVE_LIMITS = Object.freeze({
    auditId: 36,
    sourceNamespace: 512,
    path: 4096,
    identifier: 128,
    producerVersion: 64,
    blockerCodesPerRecord: 16,
    transformStepsPerArtifact: 32,
    snapshotBlockerCodes: ASSURANCE_LIMITS.blockers,
    artifactReferencesPerCoverage: 64,
    objectInventoryRecords: 50_000,
    derivedArtifactRecords: 100_000,
    semanticCoverageRecords: 50_000,
    semanticCandidateRecords: 10_000,
    redTeamCoverageRecords: 50_000,
});

const AUDIT_ID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SOURCE_NAMESPACE_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;
const PRODUCER_VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const UPSTREAM_SHA_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;
const OBJECT_ID_RE = /^zto-[a-f0-9]{64}$/;
const ARTIFACT_ID_RE = /^zta-[a-f0-9]{64}$/;
const SEMANTIC_COVERAGE_ID_RE = /^ztsc-[a-f0-9]{64}$/;
const SEMANTIC_CANDIDATE_ID_RE = /^ztsf-[a-f0-9]{64}$/;
const SEMANTIC_ASSIGNMENT_ID_RE = /^ztsma-[a-f0-9]{64}$/;
const SEMANTIC_VIEW_ID_RE = /^ztsv-[a-f0-9]{64}$/;
const SEMANTIC_EVIDENCE_ID_RE = /^ztre-[a-f0-9]{64}$/;
const FACT_ID_RE = /^[a-f0-9]{64}$/;
const RED_TEAM_COVERAGE_ID_RE = /^ztrc-[a-f0-9]{64}$/;
const SNAPSHOT_ID_RE = /^zts-[a-f0-9]{64}$/;

export class EvasiveContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "EvasiveContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new EvasiveContractError(path, message);
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function objectShape(value, path, required, optional = []) {
    if (!isPlainObject(value)) fail(path, "must be a plain object");
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) fail(`${path}.${key}`, "unknown field");
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "is required");
    }
}

function boundedString(value, path, {
    max,
    pattern,
    normalize = false,
} = {}) {
    if (typeof value !== "string") fail(path, "must be a string");
    const normalized = normalize ? value.normalize("NFKC").trim(): value;
    if (normalized.length < 1 || normalized.length > max) {
        fail(path, `length must be between 1 and ${max}`);
    }
    if (normalized.includes("\0")) fail(path, "must not contain NUL");
    if (pattern && !pattern.test(normalized)) fail(path, "has an invalid format");
    return normalized;
}

function enumValue(value, path, allowed) {
    if (!allowed.includes(value)) {
        fail(path, `must be one of: ${allowed.join(", ")}`);
    }
    return value;
}

function boundedArray(value, path, max) {
    if (!Array.isArray(value)) fail(path, "must be an array");
    if (value.length > max) fail(path, `must contain at most ${max} entries`);
    return value;
}

function safeInteger(value, path) {
    if (!Number.isSafeInteger(value) || value < 0) {
        fail(path, "must be a non-negative safe integer");
    }
    return value;
}

function cloneFrozen(value) {
    if (Array.isArray(value)) {
        return Object.freeze(value.map((entry) => cloneFrozen(entry)));
    }
    if (isPlainObject(value)) {
        const result = {};
        for (const [key, entry] of Object.entries(value)) {
            result[key] = cloneFrozen(entry);
        }
        return Object.freeze(result);
    }
    return value;
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

function validateAuditId(value, path) {
    return boundedString(value, path, {
        max: EVASIVE_LIMITS.auditId,
        pattern: AUDIT_ID_RE,
    }).toLowerCase();
}

function validateSourceNamespace(value, path) {
    return boundedString(value, path, {
        max: EVASIVE_LIMITS.sourceNamespace,
        pattern: SOURCE_NAMESPACE_RE,
        normalize: true,
    });
}

function validatePath(value, path) {
    const normalized = boundedString(value, path, {
        max: EVASIVE_LIMITS.path,
    });
    if (normalized.startsWith("/")
        || /^[A-Za-z]:\//.test(normalized)
        || normalized.includes("\\")
        || /[\u0000-\u001f\u007f]/u.test(normalized)
        || normalized.split("/").some((segment) =>
            segment.length === 0 || segment === "." || segment === "..")) {
        fail(path, "must be a normalized relative object path");
    }
    return normalized;
}

function validateIdentifier(value, path) {
    return boundedString(value, path, {
        max: EVASIVE_LIMITS.identifier,
        pattern: IDENTIFIER_RE,
        normalize: true,
    });
}

function validateProducerVersion(value, path) {
    return boundedString(value, path, {
        max: EVASIVE_LIMITS.producerVersion,
        pattern: PRODUCER_VERSION_RE,
        normalize: true,
    });
}

function validateSha256(value, path) {
    return boundedString(value, path, {
        max: 64,
        pattern: SHA256_RE,
    }).toLowerCase();
}

function validateNullableUpstreamSha(value, path) {
    if (value === null) return null;
    return boundedString(value, path, {
        max: 64,
        pattern: UPSTREAM_SHA_RE,
    }).toLowerCase();
}

function validateNullableSha256(value, path) {
    if (value === null) return null;
    return validateSha256(value, path);
}

function validateNullableObjectId(value, path) {
    if (value === null) return null;
    return boundedString(value, path, {
        max: 71,
        pattern: OBJECT_ID_RE,
    });
}

function normalizeUniqueStrings(value, path, {
    max,
    pattern,
    allowed,
} = {}) {
    const normalized = boundedArray(value, path, max).map((entry, index) => {
        if (allowed) return enumValue(entry, `${path}[${index}]`, allowed);
        return boundedString(entry, `${path}[${index}]`, {
            max: 256,
            pattern,
        });
    });
    if (new Set(normalized).size !== normalized.length) {
        fail(path, "must not contain duplicates");
    }
    return [...normalized].sort();
}

function normalizeBlockerCodes(value, path, max = EVASIVE_LIMITS.blockerCodesPerRecord) {
    return normalizeUniqueStrings(value, path, {
        max,
        allowed: EVASIVE_BLOCKER_CODES,
    });
}

function normalizeArtifactIds(value, path) {
    return normalizeUniqueStrings(value, path, {
        max: EVASIVE_LIMITS.artifactReferencesPerCoverage,
        pattern: ARTIFACT_ID_RE,
    });
}

function normalizeEvasionClasses(value, path) {
    const normalized = normalizeUniqueStrings(value, path, {
        max: EVASION_CLASS_VALUES.length,
        allowed: EVASION_CLASS_VALUES,
    });
    if (normalized.length === 0) fail(path, "must contain at least one evasion class");
    return normalized;
}

function normalizeSymlinkTarget(value, path) {
    if (value === null || value === undefined) return null;
    objectShape(value, path, [
        "kind",
        "byteLength",
        "targetSha256",
    ]);
    return {
        kind: enumValue(value.kind, `${path}.kind`, EVASIVE_SYMLINK_TARGET_KINDS),
        byteLength: safeInteger(value.byteLength, `${path}.byteLength`),
        targetSha256: validateSha256(value.targetSha256, `${path}.targetSha256`),
    };
}

function normalizeLfsPointer(value, path) {
    if (value === null || value === undefined) return null;
    objectShape(value, path, [
        "oidSha256",
        "size",
    ]);
    return {
        oidSha256: validateSha256(value.oidSha256, `${path}.oidSha256`),
        size: safeInteger(value.size, `${path}.size`),
    };
}

function normalizeSourceRange(value, path) {
    if (value === null || value === undefined) return null;
    objectShape(value, path, [
        "startOffset",
        "endOffset",
        "rangeSha256",
    ]);
    const startOffset = safeInteger(value.startOffset, `${path}.startOffset`);
    const endOffset = safeInteger(value.endOffset, `${path}.endOffset`);
    if (endOffset < startOffset) {
        fail(`${path}.endOffset`, "must not precede startOffset");
    }
    return {
        startOffset,
        endOffset,
        rangeSha256: validateSha256(value.rangeSha256, `${path}.rangeSha256`),
    };
}

function normalizeTransformChain(value, path, sourceRange, contentSha256) {
    const chain = boundedArray(
        value ?? [],
        path,
        EVASIVE_LIMITS.transformStepsPerArtifact,
    ).map((entry, index) => {
        const entryPath = `${path}[${index}]`;
        objectShape(entry, entryPath, [
            "kind",
            "inputSha256",
            "outputSha256",
        ]);
        return {
            kind: enumValue(entry.kind, `${entryPath}.kind`, EVASIVE_TRANSFORM_KINDS),
            inputSha256: validateSha256(
                entry.inputSha256,
                `${entryPath}.inputSha256`,
            ),
            outputSha256: validateSha256(
                entry.outputSha256,
                `${entryPath}.outputSha256`,
            ),
        };
    });
    if (chain.length > 0) {
        if (sourceRange && chain[0].inputSha256 !== sourceRange.rangeSha256) {
            fail(path, "first transform input must match the source range hash");
        }
        for (let index = 1; index < chain.length; index += 1) {
            if (chain[index].inputSha256 !== chain[index - 1].outputSha256) {
                fail(path, "transform hashes must form a contiguous chain");
            }
        }
        if (chain.at(-1).outputSha256 !== contentSha256) {
            fail(path, "last transform output must match contentSha256");
        }
    }
    return chain;
}

function assertCanonicalRecord(actual, expected, path) {
    if (canonicalJson(actual) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic assurance identity and hashes");
    }
    return expected;
}

export function mapEvasiveBlockerToAssuranceCode(value, path = "evasiveBlockerCode") {
    const code = enumValue(value, path, EVASIVE_BLOCKER_CODES);
    return EVASIVE_BLOCKER_ASSURANCE_CODES[code];
}

export function createEvasiveObjectInventoryRecord(value, path = "objectInventoryInput") {
    objectShape(value, path, [
        "auditId",
        "sourceNamespace",
        "path",
        "parentObjectId",
        "objectKind",
        "byteLength",
        "status",
        "blockerCodes",
        "contentSha256",
        "upstreamSha",
    ], [
        "gitObjectType",
        "gitMode",
        "parentUpstreamSha",
        "executable",
        "symlinkTarget",
        "lfsPointer",
    ]);
    const normalized = {
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        sourceNamespace: validateSourceNamespace(
            value.sourceNamespace,
            `${path}.sourceNamespace`,
        ),
        path: validatePath(value.path, `${path}.path`),
        parentObjectId: validateNullableObjectId(
            value.parentObjectId,
            `${path}.parentObjectId`,
        ),
        objectKind: enumValue(
            value.objectKind,
            `${path}.objectKind`,
            EVASIVE_OBJECT_KINDS,
        ),
        byteLength: safeInteger(value.byteLength, `${path}.byteLength`),
        status: enumValue(value.status, `${path}.status`, EVASIVE_OBJECT_STATUSES),
        blockerCodes: normalizeBlockerCodes(
            value.blockerCodes,
            `${path}.blockerCodes`,
        ),
        contentSha256: validateNullableSha256(
            value.contentSha256,
            `${path}.contentSha256`,
        ),
        upstreamSha: validateNullableUpstreamSha(
            value.upstreamSha,
            `${path}.upstreamSha`,
        ),
        gitObjectType: value.gitObjectType === null
            || value.gitObjectType === undefined
            ? null: enumValue(
                value.gitObjectType,
                `${path}.gitObjectType`,
                EVASIVE_GIT_OBJECT_TYPES,
            ),
        gitMode: value.gitMode === null || value.gitMode === undefined
            ? null: enumValue(value.gitMode, `${path}.gitMode`, EVASIVE_GIT_MODES),
        parentUpstreamSha: validateNullableUpstreamSha(
            value.parentUpstreamSha ?? null,
            `${path}.parentUpstreamSha`,
        ),
        executable: value.executable === true,
        symlinkTarget: normalizeSymlinkTarget(
            value.symlinkTarget,
            `${path}.symlinkTarget`,
        ),
        lfsPointer: normalizeLfsPointer(value.lfsPointer, `${path}.lfsPointer`),
    };
    if (normalized.status !== "inventoried" && normalized.blockerCodes.length === 0) {
        fail(`${path}.blockerCodes`, "must explain a non-inventoried object status");
    }
    if (normalized.status === "inventoried" && normalized.blockerCodes.length > 0) {
        fail(`${path}.blockerCodes`, "inventoried objects must not carry blockers");
    }
    if (normalized.contentSha256 === null
        && normalized.status === "inventoried"
        && !["tree"].includes(normalized.objectKind)) {
        fail(`${path}.contentSha256`, "is required for inventoried non-tree objects");
    }
    const expectedGitTypeByMode = {
        "040000": "tree",
        "100644": "blob",
        "100755": "blob",
        "120000": "blob",
        "160000": "commit",
    };
    if (normalized.gitMode !== null) {
        if (normalized.gitObjectType !== expectedGitTypeByMode[normalized.gitMode]) {
            fail(`${path}.gitObjectType`, "does not match the Git tree mode");
        }
        if (normalized.upstreamSha === null || normalized.parentUpstreamSha === null) {
            fail(path, "Git objects require upstream and parent tree identities");
        }
    } else if (normalized.gitObjectType !== null
        || normalized.parentUpstreamSha !== null) {
        fail(`${path}.gitMode`, "is required when Git object metadata is present");
    }
    if (normalized.executable !== (normalized.gitMode === "100755")) {
        fail(`${path}.executable`, "must exactly reflect Git mode 100755");
    }
    if (normalized.gitMode === "040000" && normalized.objectKind !== "tree") {
        fail(`${path}.objectKind`, "Git tree mode requires object kind tree");
    }
    if (normalized.gitMode === "100755"
        && normalized.objectKind !== "executable-blob") {
        fail(`${path}.objectKind`, "Git executable mode requires executable-blob");
    }
    if (normalized.gitMode === "120000") {
        if (normalized.objectKind !== "symlink") {
            fail(`${path}.objectKind`, "Git symlink mode requires object kind symlink");
        }
        if (normalized.status === "inventoried" && normalized.symlinkTarget === null) {
            fail(`${path}.symlinkTarget`, "is required for an inventoried symlink");
        }
    } else if (normalized.symlinkTarget !== null) {
        fail(`${path}.symlinkTarget`, "is valid only for Git symlink objects");
    }
    if (normalized.gitMode === "160000") {
        if (normalized.objectKind !== "gitlink") {
            fail(`${path}.objectKind`, "Gitlink mode requires object kind gitlink");
        }
        if (normalized.status !== "blocked"
            || !normalized.blockerCodes.includes(EVASIVE_BLOCKERS.GITLINK_UNRESOLVED)) {
            fail(path, "Gitlinks must remain blocked until the submodule object is resolved");
        }
    }
    if (normalized.lfsPointer !== null
        && ![null, "100644", "100755"].includes(normalized.gitMode)) {
        fail(`${path}.lfsPointer`, "is valid only for regular file/blob objects");
    }
    const identitySha256 = hashDomain("zerotrust-object-identity", {
        auditId: normalized.auditId,
        sourceNamespace: normalized.sourceNamespace,
        path: normalized.path,
        parentObjectId: normalized.parentObjectId,
        objectKind: normalized.objectKind,
        byteLength: normalized.byteLength,
        contentSha256: normalized.contentSha256,
        upstreamSha: normalized.upstreamSha,
        gitObjectType: normalized.gitObjectType,
        gitMode: normalized.gitMode,
        parentUpstreamSha: normalized.parentUpstreamSha,
        executable: normalized.executable,
        symlinkTarget: normalized.symlinkTarget,
        lfsPointer: normalized.lfsPointer,
    });
    const objectId = `zto-${identitySha256}`;
    const recordSha256 = hashDomain("zerotrust-object-record", {
        ...normalized,
        objectId,
        identitySha256,
    });
    return cloneFrozen({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId: normalized.auditId,
        sourceNamespace: normalized.sourceNamespace,
        objectId,
        path: normalized.path,
        parentObjectId: normalized.parentObjectId,
        objectKind: normalized.objectKind,
        byteLength: normalized.byteLength,
        status: normalized.status,
        blockerCodes: normalized.blockerCodes,
        gitObjectType: normalized.gitObjectType,
        gitMode: normalized.gitMode,
        parentUpstreamSha: normalized.parentUpstreamSha,
        executable: normalized.executable,
        symlinkTarget: normalized.symlinkTarget,
        lfsPointer: normalized.lfsPointer,
        hashes: {
            contentSha256: normalized.contentSha256,
            upstreamSha: normalized.upstreamSha,
            identitySha256,
            recordSha256,
        },
    });
}

export function validateEvasiveObjectInventoryRecord(
    value,
    path = "objectInventoryRecord",
) {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "sourceNamespace",
        "objectId",
        "path",
        "parentObjectId",
        "objectKind",
        "byteLength",
        "status",
        "blockerCodes",
        "gitObjectType",
        "gitMode",
        "parentUpstreamSha",
        "executable",
        "symlinkTarget",
        "lfsPointer",
        "hashes",
    ]);
    if (value.schemaVersion !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
        fail(
            `${path}.schemaVersion`,
            `must equal ${ASSURANCE_ANALYSIS_SCHEMA_REVISION}; baseline inventory is not assurance inventory`,
        );
    }
    boundedString(value.objectId, `${path}.objectId`, {
        max: 71,
        pattern: OBJECT_ID_RE,
    });
    objectShape(value.hashes, `${path}.hashes`, [
        "contentSha256",
        "upstreamSha",
        "identitySha256",
        "recordSha256",
    ]);
    validateNullableSha256(value.hashes.contentSha256, `${path}.hashes.contentSha256`);
    validateSha256(value.hashes.identitySha256, `${path}.hashes.identitySha256`);
    validateSha256(value.hashes.recordSha256, `${path}.hashes.recordSha256`);
    const expected = createEvasiveObjectInventoryRecord({
        auditId: value.auditId,
        sourceNamespace: value.sourceNamespace,
        path: value.path,
        parentObjectId: value.parentObjectId,
        objectKind: value.objectKind,
        byteLength: value.byteLength,
        status: value.status,
        blockerCodes: value.blockerCodes,
        contentSha256: value.hashes.contentSha256,
        upstreamSha: value.hashes.upstreamSha,
        gitObjectType: value.gitObjectType,
        gitMode: value.gitMode,
        parentUpstreamSha: value.parentUpstreamSha,
        executable: value.executable,
        symlinkTarget: value.symlinkTarget,
        lfsPointer: value.lfsPointer,
    }, path);
    return assertCanonicalRecord(value, expected, path);
}

export function createEvasiveDerivedArtifactRecord(
    value,
    path = "derivedArtifactInput",
) {
    objectShape(value, path, [
        "auditId",
        "sourceNamespace",
        "path",
        "sourceObjectId",
        "artifactKind",
        "producer",
        "producerVersion",
        "byteLength",
        "status",
        "blockerCodes",
        "contentSha256",
        "sourceObjectSha256",
    ], [
        "sourceRange",
        "transformChain",
    ]);
    const contentSha256 = validateSha256(
        value.contentSha256,
        `${path}.contentSha256`,
    );
    const sourceRange = normalizeSourceRange(
        value.sourceRange,
        `${path}.sourceRange`,
    );
    const normalized = {
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        sourceNamespace: validateSourceNamespace(
            value.sourceNamespace,
            `${path}.sourceNamespace`,
        ),
        path: validatePath(value.path, `${path}.path`),
        sourceObjectId: boundedString(
            value.sourceObjectId,
            `${path}.sourceObjectId`,
            { max: 71, pattern: OBJECT_ID_RE },
        ),
        artifactKind: enumValue(
            value.artifactKind,
            `${path}.artifactKind`,
            EVASIVE_DERIVED_ARTIFACT_KINDS,
        ),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        producerVersion: validateProducerVersion(
            value.producerVersion,
            `${path}.producerVersion`,
        ),
        byteLength: safeInteger(value.byteLength, `${path}.byteLength`),
        status: enumValue(
            value.status,
            `${path}.status`,
            EVASIVE_DERIVED_ARTIFACT_STATUSES,
        ),
        blockerCodes: normalizeBlockerCodes(
            value.blockerCodes,
            `${path}.blockerCodes`,
        ),
        contentSha256,
        sourceObjectSha256: validateSha256(
            value.sourceObjectSha256,
            `${path}.sourceObjectSha256`,
        ),
        sourceRange,
        transformChain: normalizeTransformChain(
            value.transformChain,
            `${path}.transformChain`,
            sourceRange,
            contentSha256,
        ),
    };
    if (normalized.status !== "decoded" && normalized.blockerCodes.length === 0) {
        fail(`${path}.blockerCodes`, "must explain a non-decoded artifact status");
    }
    if (normalized.status === "decoded" && normalized.blockerCodes.length > 0) {
        fail(`${path}.blockerCodes`, "decoded artifacts must not carry blockers");
    }
    const derivationSha256 = hashDomain("zerotrust-derived-artifact-identity", {
        auditId: normalized.auditId,
        sourceNamespace: normalized.sourceNamespace,
        path: normalized.path,
        sourceObjectId: normalized.sourceObjectId,
        sourceObjectSha256: normalized.sourceObjectSha256,
        artifactKind: normalized.artifactKind,
        producer: normalized.producer,
        producerVersion: normalized.producerVersion,
        byteLength: normalized.byteLength,
        contentSha256: normalized.contentSha256,
        sourceRange: normalized.sourceRange,
        transformChain: normalized.transformChain,
    });
    const artifactId = `zta-${derivationSha256}`;
    const recordSha256 = hashDomain("zerotrust-derived-artifact-record", {
        ...normalized,
        artifactId,
        derivationSha256,
    });
    return cloneFrozen({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId: normalized.auditId,
        sourceNamespace: normalized.sourceNamespace,
        artifactId,
        sourceObjectId: normalized.sourceObjectId,
        path: normalized.path,
        artifactKind: normalized.artifactKind,
        producer: normalized.producer,
        producerVersion: normalized.producerVersion,
        byteLength: normalized.byteLength,
        status: normalized.status,
        blockerCodes: normalized.blockerCodes,
        sourceRange: normalized.sourceRange,
        transformChain: normalized.transformChain,
        hashes: {
            contentSha256: normalized.contentSha256,
            sourceObjectSha256: normalized.sourceObjectSha256,
            derivationSha256,
            recordSha256,
        },
    });
}

export function validateEvasiveDerivedArtifactRecord(
    value,
    path = "derivedArtifactRecord",
) {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "sourceNamespace",
        "artifactId",
        "sourceObjectId",
        "path",
        "artifactKind",
        "producer",
        "producerVersion",
        "byteLength",
        "status",
        "blockerCodes",
        "sourceRange",
        "transformChain",
        "hashes",
    ]);
    if (value.schemaVersion !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
        fail(`${path}.schemaVersion`, `must equal ${ASSURANCE_ANALYSIS_SCHEMA_REVISION}`);
    }
    boundedString(value.artifactId, `${path}.artifactId`, {
        max: 71,
        pattern: ARTIFACT_ID_RE,
    });
    objectShape(value.hashes, `${path}.hashes`, [
        "contentSha256",
        "sourceObjectSha256",
        "derivationSha256",
        "recordSha256",
    ]);
    validateSha256(value.hashes.derivationSha256, `${path}.hashes.derivationSha256`);
    validateSha256(value.hashes.recordSha256, `${path}.hashes.recordSha256`);
    const expected = createEvasiveDerivedArtifactRecord({
        auditId: value.auditId,
        sourceNamespace: value.sourceNamespace,
        path: value.path,
        sourceObjectId: value.sourceObjectId,
        artifactKind: value.artifactKind,
        producer: value.producer,
        producerVersion: value.producerVersion,
        byteLength: value.byteLength,
        status: value.status,
        blockerCodes: value.blockerCodes,
        contentSha256: value.hashes.contentSha256,
        sourceObjectSha256: value.hashes.sourceObjectSha256,
        sourceRange: value.sourceRange,
        transformChain: value.transformChain,
    }, path);
    return assertCanonicalRecord(value, expected, path);
}

function createCoverageRecord(value, path, {
    domain,
    idField,
    idPrefix,
}) {
    objectShape(value, path, [
        "auditId",
        "sourceNamespace",
        "path",
        "objectId",
        "artifactIds",
        "producer",
        "producerVersion",
        "status",
        "evasionClasses",
        "blockerCodes",
        "basisSha256",
        "objectIdentitySha256",
    ]);
    const normalized = {
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        sourceNamespace: validateSourceNamespace(
            value.sourceNamespace,
            `${path}.sourceNamespace`,
        ),
        path: validatePath(value.path, `${path}.path`),
        objectId: boundedString(value.objectId, `${path}.objectId`, {
            max: 71,
            pattern: OBJECT_ID_RE,
        }),
        artifactIds: normalizeArtifactIds(value.artifactIds, `${path}.artifactIds`),
        producer: validateIdentifier(value.producer, `${path}.producer`),
        producerVersion: validateProducerVersion(
            value.producerVersion,
            `${path}.producerVersion`,
        ),
        status: enumValue(value.status, `${path}.status`, EVASIVE_COVERAGE_STATUSES),
        evasionClasses: normalizeEvasionClasses(
            value.evasionClasses,
            `${path}.evasionClasses`,
        ),
        blockerCodes: normalizeBlockerCodes(
            value.blockerCodes,
            `${path}.blockerCodes`,
        ),
        basisSha256: validateSha256(value.basisSha256, `${path}.basisSha256`),
        objectIdentitySha256: validateSha256(
            value.objectIdentitySha256,
            `${path}.objectIdentitySha256`,
        ),
    };
    if (["unassessed", "partial"].includes(normalized.status)
        && normalized.blockerCodes.length === 0) {
        fail(`${path}.blockerCodes`, "must explain incomplete coverage");
    }
    const subjectSetSha256 = hashDomain(`${domain}-subjects`, {
        auditId: normalized.auditId,
        sourceNamespace: normalized.sourceNamespace,
        path: normalized.path,
        objectId: normalized.objectId,
        objectIdentitySha256: normalized.objectIdentitySha256,
        artifactIds: normalized.artifactIds,
    });
    const coverageSha256 = hashDomain(domain, {
        ...normalized,
        subjectSetSha256,
    });
    return cloneFrozen({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId: normalized.auditId,
        sourceNamespace: normalized.sourceNamespace,
        [idField]: `${idPrefix}-${coverageSha256}`,
        objectId: normalized.objectId,
        path: normalized.path,
        artifactIds: normalized.artifactIds,
        producer: normalized.producer,
        producerVersion: normalized.producerVersion,
        status: normalized.status,
        evasionClasses: normalized.evasionClasses,
        blockerCodes: normalized.blockerCodes,
        hashes: {
            basisSha256: normalized.basisSha256,
            objectIdentitySha256: normalized.objectIdentitySha256,
            subjectSetSha256,
            coverageSha256,
        },
    });
}

function validateCoverageRecord(value, path, {
    create,
    idField,
    idPattern,
}) {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "sourceNamespace",
        idField,
        "objectId",
        "path",
        "artifactIds",
        "producer",
        "producerVersion",
        "status",
        "evasionClasses",
        "blockerCodes",
        "hashes",
    ]);
    if (value.schemaVersion !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
        fail(`${path}.schemaVersion`, `must equal ${ASSURANCE_ANALYSIS_SCHEMA_REVISION}`);
    }
    boundedString(value[idField], `${path}.${idField}`, {
        max: 72,
        pattern: idPattern,
    });
    objectShape(value.hashes, `${path}.hashes`, [
        "basisSha256",
        "objectIdentitySha256",
        "subjectSetSha256",
        "coverageSha256",
    ]);
    validateSha256(value.hashes.subjectSetSha256, `${path}.hashes.subjectSetSha256`);
    validateSha256(value.hashes.coverageSha256, `${path}.hashes.coverageSha256`);
    const expected = create({
        auditId: value.auditId,
        sourceNamespace: value.sourceNamespace,
        path: value.path,
        objectId: value.objectId,
        artifactIds: value.artifactIds,
        producer: value.producer,
        producerVersion: value.producerVersion,
        status: value.status,
        evasionClasses: value.evasionClasses,
        blockerCodes: value.blockerCodes,
        basisSha256: value.hashes.basisSha256,
        objectIdentitySha256: value.hashes.objectIdentitySha256,
    }, path);
    return assertCanonicalRecord(value, expected, path);
}

export function createEvasiveSemanticReviewCoverageRecord(
    value,
    path = "semanticReviewCoverageInput",
) {
    return createCoverageRecord(value, path, {
        domain: "zerotrust-semantic-coverage",
        idField: "semanticCoverageId",
        idPrefix: "ztsc",
    });
}

export function validateEvasiveSemanticReviewCoverageRecord(
    value,
    path = "semanticReviewCoverageRecord",
) {
    return validateCoverageRecord(value, path, {
        create: createEvasiveSemanticReviewCoverageRecord,
        idField: "semanticCoverageId",
        idPattern: SEMANTIC_COVERAGE_ID_RE,
    });
}

export function createEvasiveRedTeamCoverageRecord(
    value,
    path = "redTeamCoverageInput",
) {
    return createCoverageRecord(value, path, {
        domain: "zerotrust-red-team-coverage",
        idField: "redTeamCoverageId",
        idPrefix: "ztrc",
    });
}

export function validateEvasiveRedTeamCoverageRecord(
    value,
    path = "redTeamCoverageRecord",
) {
    return validateCoverageRecord(value, path, {
        create: createEvasiveRedTeamCoverageRecord,
        idField: "redTeamCoverageId",
        idPattern: RED_TEAM_COVERAGE_ID_RE,
    });
}

export function createEvasiveSemanticCandidateRecord(
    value,
    path = "semanticCandidateInput",
) {
    objectShape(value, path, [
        "auditId",
        "sourceNamespace",
        "producerAssignmentId",
        "semanticViewId",
        "behavior",
        "severity",
        "confidence",
        "maliciousProjectFit",
        "benignHypothesisCode",
        "objectIds",
        "artifactIds",
        "factIds",
        "evidenceIds",
    ]);
    objectShape(value.behavior, `${path}.behavior`, [
        "trigger",
        "capability",
        "action",
        "target",
    ]);
    const behavior = {};
    for (const key of ["trigger", "capability", "action", "target"]) {
        behavior[key] = boundedString(
            value.behavior[key],
            `${path}.behavior.${key}`,
            { max: 128, pattern: IDENTIFIER_RE },
        );
    }
    const normalized = {
        auditId: validateAuditId(value.auditId, `${path}.auditId`),
        sourceNamespace: validateSourceNamespace(
            value.sourceNamespace,
            `${path}.sourceNamespace`,
        ),
        producerAssignmentId: boundedString(
            value.producerAssignmentId,
            `${path}.producerAssignmentId`,
            { max: 73, pattern: SEMANTIC_ASSIGNMENT_ID_RE },
        ),
        semanticViewId: boundedString(
            value.semanticViewId,
            `${path}.semanticViewId`,
            { max: 72, pattern: SEMANTIC_VIEW_ID_RE },
        ),
        behavior,
        severity: enumValue(
            value.severity,
            `${path}.severity`,
            EVASIVE_SEMANTIC_CANDIDATE_SEVERITIES,
        ),
        confidence: enumValue(
            value.confidence,
            `${path}.confidence`,
            EVASIVE_SEMANTIC_CANDIDATE_CONFIDENCE_LEVELS,
        ),
        maliciousProjectFit: enumValue(
            value.maliciousProjectFit,
            `${path}.maliciousProjectFit`,
            EVASIVE_SEMANTIC_CANDIDATE_FIT_LEVELS,
        ),
        benignHypothesisCode: enumValue(
            value.benignHypothesisCode,
            `${path}.benignHypothesisCode`,
            EVASIVE_SEMANTIC_BENIGN_HYPOTHESIS_CODES,
        ),
        objectIds: normalizeUniqueStrings(value.objectIds, `${path}.objectIds`, {
            max: EVASIVE_LIMITS.artifactReferencesPerCoverage,
            pattern: OBJECT_ID_RE,
        }),
        artifactIds: normalizeUniqueStrings(
            value.artifactIds,
            `${path}.artifactIds`,
            {
                max: EVASIVE_LIMITS.artifactReferencesPerCoverage,
                pattern: ARTIFACT_ID_RE,
            },
        ),
        factIds: normalizeUniqueStrings(value.factIds, `${path}.factIds`, {
            max: EVASIVE_LIMITS.artifactReferencesPerCoverage,
            pattern: FACT_ID_RE,
        }),
        evidenceIds: normalizeUniqueStrings(
            value.evidenceIds,
            `${path}.evidenceIds`,
            {
                max: EVASIVE_LIMITS.artifactReferencesPerCoverage,
                pattern: SEMANTIC_EVIDENCE_ID_RE,
            },
        ),
    };
    if (normalized.objectIds.length === 0
        || normalized.evidenceIds.length === 0
        || (normalized.artifactIds.length === 0
            && normalized.factIds.length === 0)) {
        fail(
            path,
            "must bind object/evidence identities and at least one artifact or fact",
        );
    }
    const candidateSha256 = hashDomain("zerotrust-semantic-candidate", normalized);
    return cloneFrozen({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        candidateId: `ztsf-${candidateSha256}`,
        ...normalized,
        hashes: {
            candidateSha256,
        },
    });
}

export function validateEvasiveSemanticCandidateRecord(
    value,
    path = "semanticCandidateRecord",
) {
    objectShape(value, path, [
        "schemaVersion",
        "candidateId",
        "auditId",
        "sourceNamespace",
        "producerAssignmentId",
        "semanticViewId",
        "behavior",
        "severity",
        "confidence",
        "maliciousProjectFit",
        "benignHypothesisCode",
        "objectIds",
        "artifactIds",
        "factIds",
        "evidenceIds",
        "hashes",
    ]);
    if (value.schemaVersion !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
        fail(`${path}.schemaVersion`, `must equal ${ASSURANCE_ANALYSIS_SCHEMA_REVISION}`);
    }
    boundedString(value.candidateId, `${path}.candidateId`, {
        max: 72,
        pattern: SEMANTIC_CANDIDATE_ID_RE,
    });
    objectShape(value.hashes, `${path}.hashes`, ["candidateSha256"]);
    validateSha256(value.hashes.candidateSha256, `${path}.hashes.candidateSha256`);
    const expected = createEvasiveSemanticCandidateRecord({
        auditId: value.auditId,
        sourceNamespace: value.sourceNamespace,
        producerAssignmentId: value.producerAssignmentId,
        semanticViewId: value.semanticViewId,
        behavior: value.behavior,
        severity: value.severity,
        confidence: value.confidence,
        maliciousProjectFit: value.maliciousProjectFit,
        benignHypothesisCode: value.benignHypothesisCode,
        objectIds: value.objectIds,
        artifactIds: value.artifactIds,
        factIds: value.factIds,
        evidenceIds: value.evidenceIds,
    }, path);
    return assertCanonicalRecord(value, expected, path);
}

function validateRecordArray(value, path, max, validate, idField) {
    const records = boundedArray(value, path, max).map((entry, index) =>
        validate(entry, `${path}[${index}]`));
    const ids = records.map((record) => record[idField]);
    if (new Set(ids).size !== ids.length) fail(path, `must not contain duplicate ${idField}s`);
    return [...records].sort((left, right) =>
        left[idField].localeCompare(right[idField]));
}

function requireSnapshotBinding(record, auditId, sourceNamespace, path) {
    if (record.auditId !== auditId) fail(`${path}.auditId`, "does not match snapshot");
    if (record.sourceNamespace !== sourceNamespace) {
        fail(`${path}.sourceNamespace`, "does not match snapshot");
    }
}

export function createAssuranceAnalysisSnapshot(value, path = "assuranceAnalysisSnapshotInput") {
    objectShape(value, path, [
        "auditId",
        "sourceNamespace",
        "stageState",
        "status",
        "objectInventory",
        "derivedArtifacts",
        "semanticReviewCoverage",
        "redTeamCoverage",
        "blockerCodes",
        "sourceIdentitySha256",
    ], [
        "semanticCandidateLedger",
    ]);
    const auditId = validateAuditId(value.auditId, `${path}.auditId`);
    const sourceNamespace = validateSourceNamespace(
        value.sourceNamespace,
        `${path}.sourceNamespace`,
    );
    const stageState = validateAssuranceStageState(value.stageState, `${path}.stageState`);
    if (stageState.auditId !== auditId) {
        fail(`${path}.stageState.auditId`, "does not match snapshot");
    }
    if (stageState.sourceNamespace !== sourceNamespace) {
        fail(`${path}.stageState.sourceNamespace`, "does not match snapshot");
    }
    const status = enumValue(value.status, `${path}.status`, EVASIVE_SNAPSHOT_STATUSES);
    const blockerCodes = normalizeBlockerCodes(
        value.blockerCodes,
        `${path}.blockerCodes`,
        EVASIVE_LIMITS.snapshotBlockerCodes,
    );
    if (status === "complete"
        && (stageState.current !== "finalized" || blockerCodes.length > 0)) {
        fail(
            `${path}.status`,
            "complete requires finalized stage state and no blockers",
        );
    }
    const objectInventory = validateRecordArray(
        value.objectInventory,
        `${path}.objectInventory`,
        EVASIVE_LIMITS.objectInventoryRecords,
        validateEvasiveObjectInventoryRecord,
        "objectId",
    );
    const derivedArtifacts = validateRecordArray(
        value.derivedArtifacts,
        `${path}.derivedArtifacts`,
        EVASIVE_LIMITS.derivedArtifactRecords,
        validateEvasiveDerivedArtifactRecord,
        "artifactId",
    );
    const semanticReviewCoverage = validateRecordArray(
        value.semanticReviewCoverage,
        `${path}.semanticReviewCoverage`,
        EVASIVE_LIMITS.semanticCoverageRecords,
        validateEvasiveSemanticReviewCoverageRecord,
        "semanticCoverageId",
    );
    const semanticCandidateLedger = validateRecordArray(
        value.semanticCandidateLedger ?? [],
        `${path}.semanticCandidateLedger`,
        EVASIVE_LIMITS.semanticCandidateRecords,
        validateEvasiveSemanticCandidateRecord,
        "candidateId",
    );
    const redTeamCoverage = validateRecordArray(
        value.redTeamCoverage,
        `${path}.redTeamCoverage`,
        EVASIVE_LIMITS.redTeamCoverageRecords,
        validateEvasiveRedTeamCoverageRecord,
        "redTeamCoverageId",
    );
    for (const [records, recordsPath] of [
        [objectInventory, `${path}.objectInventory`],
        [derivedArtifacts, `${path}.derivedArtifacts`],
        [semanticReviewCoverage, `${path}.semanticReviewCoverage`],
        [redTeamCoverage, `${path}.redTeamCoverage`],
    ]) {
        records.forEach((record, index) =>
            requireSnapshotBinding(record, auditId, sourceNamespace, `${recordsPath}[${index}]`));
    }
    const snapshotBlockerSet = new Set(blockerCodes);
    for (const record of [
        ...objectInventory,
        ...derivedArtifacts,
        ...semanticReviewCoverage,
        ...redTeamCoverage,
    ]) {
        for (const blockerCode of record.blockerCodes) {
            if (!snapshotBlockerSet.has(blockerCode)) {
                fail(
                    `${path}.blockerCodes`,
                    `must include nested record blocker: ${blockerCode}`,
                );
            }
        }
    }
    const objectsById = new Map(objectInventory.map((record) => [record.objectId, record]));
    for (const object of objectInventory) {
        if (object.parentObjectId !== null) {
            if (object.parentObjectId === object.objectId
                || !objectsById.has(object.parentObjectId)) {
                fail(
                    `${path}.objectInventory`,
                    `object ${object.objectId} has an unknown or self parent`,
                );
            }
        }
    }
    for (const object of objectInventory) {
        const ancestors = new Set([object.objectId]);
        let parentObjectId = object.parentObjectId;
        while (parentObjectId !== null) {
            if (ancestors.has(parentObjectId)) {
                fail(`${path}.objectInventory`, "object parent graph must be acyclic");
            }
            ancestors.add(parentObjectId);
            parentObjectId = objectsById.get(parentObjectId).parentObjectId;
        }
    }
    const artifactsById = new Map(
        derivedArtifacts.map((record) => [record.artifactId, record]),
    );
    for (const artifact of derivedArtifacts) {
        const object = objectsById.get(artifact.sourceObjectId);
        if (!object) {
            fail(
                `${path}.derivedArtifacts`,
                `artifact ${artifact.artifactId} references an unknown object`,
            );
        }
        if (artifact.hashes.sourceObjectSha256 !== object.hashes.identitySha256) {
            fail(
                `${path}.derivedArtifacts`,
                `artifact ${artifact.artifactId} has a mismatched object identity hash`,
            );
        }
    }
    for (const [records, recordsPath] of [
        [semanticReviewCoverage, `${path}.semanticReviewCoverage`],
        [redTeamCoverage, `${path}.redTeamCoverage`],
    ]) {
        for (const record of records) {
            const object = objectsById.get(record.objectId);
            if (!object
                || object.path !== record.path
                || object.hashes.identitySha256
                    !== record.hashes.objectIdentitySha256) {
                fail(
                    recordsPath,
                    `coverage ${record.semanticCoverageId || record.redTeamCoverageId} has a mismatched object binding`,
                );
            }
            for (const artifactId of record.artifactIds) {
                const artifact = artifactsById.get(artifactId);
                if (!artifact || artifact.sourceObjectId !== record.objectId) {
                    fail(
                        recordsPath,
                        `coverage references an unknown or cross-object artifact: ${artifactId}`,
                    );
                }
            }
        }
    }
    for (const [index, candidate] of semanticCandidateLedger.entries()) {
        requireSnapshotBinding(
            candidate,
            auditId,
            sourceNamespace,
            `${path}.semanticCandidateLedger[${index}]`,
        );
        if (candidate.objectIds.some((objectId) => !objectsById.has(objectId))) {
            fail(
                `${path}.semanticCandidateLedger[${index}].objectIds`,
                "references an unknown object",
            );
        }
        for (const artifactId of candidate.artifactIds) {
            const artifact = artifactsById.get(artifactId);
            if (!artifact || !candidate.objectIds.includes(artifact.sourceObjectId)) {
                fail(
                    `${path}.semanticCandidateLedger[${index}].artifactIds`,
                    "references an unknown or cross-object artifact",
                );
            }
        }
    }
    const sourceIdentitySha256 = validateSha256(
        value.sourceIdentitySha256,
        `${path}.sourceIdentitySha256`,
    );
    const inventorySha256 = hashDomain(
        "zerotrust-object-inventory-snapshot",
        objectInventory,
    );
    const derivedArtifactsSha256 = hashDomain(
        "zerotrust-derived-artifacts-snapshot",
        derivedArtifacts,
    );
    const semanticCoverageSha256 = hashDomain(
        "zerotrust-semantic-coverage-snapshot",
        semanticReviewCoverage,
    );
    const semanticCandidatesSha256 = hashDomain(
        "zerotrust-semantic-candidate-ledger-snapshot",
        semanticCandidateLedger,
    );
    const redTeamCoverageSha256 = hashDomain(
        "zerotrust-red-team-coverage-snapshot",
        redTeamCoverage,
    );
    const snapshotSha256 = hashDomain("zerotrust-analysis-snapshot", {
        auditId,
        sourceNamespace,
        sourceIdentitySha256,
        stageState,
        status,
        blockerCodes,
        inventorySha256,
        derivedArtifactsSha256,
        semanticCoverageSha256,
        semanticCandidatesSha256,
        redTeamCoverageSha256,
    });
    return cloneFrozen({
        schemaVersion: ASSURANCE_ANALYSIS_SCHEMA_REVISION,
        auditId,
        sourceNamespace,
        snapshotId: `zts-${snapshotSha256}`,
        stageState,
        status,
        objectInventory,
        derivedArtifacts,
        semanticReviewCoverage,
        semanticCandidateLedger,
        redTeamCoverage,
        blockerCodes,
        hashes: {
            sourceIdentitySha256,
            inventorySha256,
            derivedArtifactsSha256,
            semanticCoverageSha256,
            semanticCandidatesSha256,
            redTeamCoverageSha256,
            snapshotSha256,
        },
    });
}

export function validateAssuranceAnalysisSnapshot(
    value,
    path = "assuranceAnalysisSnapshot",
) {
    objectShape(value, path, [
        "schemaVersion",
        "auditId",
        "sourceNamespace",
        "snapshotId",
        "stageState",
        "status",
        "objectInventory",
        "derivedArtifacts",
        "semanticReviewCoverage",
        "semanticCandidateLedger",
        "redTeamCoverage",
        "blockerCodes",
        "hashes",
    ]);
    if (value.schemaVersion !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
        fail(
            `${path}.schemaVersion`,
            `must equal ${ASSURANCE_ANALYSIS_SCHEMA_REVISION}; baseline state is not an assurance snapshot`,
        );
    }
    boundedString(value.snapshotId, `${path}.snapshotId`, {
        max: 71,
        pattern: SNAPSHOT_ID_RE,
    });
    objectShape(value.hashes, `${path}.hashes`, [
        "sourceIdentitySha256",
        "inventorySha256",
        "derivedArtifactsSha256",
        "semanticCoverageSha256",
        "semanticCandidatesSha256",
        "redTeamCoverageSha256",
        "snapshotSha256",
    ]);
    for (const key of [
        "inventorySha256",
        "derivedArtifactsSha256",
        "semanticCoverageSha256",
        "semanticCandidatesSha256",
        "redTeamCoverageSha256",
        "snapshotSha256",
    ]) {
        validateSha256(value.hashes[key], `${path}.hashes.${key}`);
    }
    const expected = createAssuranceAnalysisSnapshot({
        auditId: value.auditId,
        sourceNamespace: value.sourceNamespace,
        stageState: value.stageState,
        status: value.status,
        objectInventory: value.objectInventory,
        derivedArtifacts: value.derivedArtifacts,
        semanticReviewCoverage: value.semanticReviewCoverage,
        semanticCandidateLedger: value.semanticCandidateLedger,
        redTeamCoverage: value.redTeamCoverage,
        blockerCodes: value.blockerCodes,
        sourceIdentitySha256: value.hashes.sourceIdentitySha256,
    }, path);
    return assertCanonicalRecord(value, expected, path);
}

export const __internals = Object.freeze({
    canonicalJson,
    cloneFrozen,
    hashDomain,
});
