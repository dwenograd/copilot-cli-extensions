import { createHash } from "node:crypto";

import { EVASION_CLASSES } from "./assurance.mjs";
import {
    EVASIVE_BLOCKERS,
    validateEvasiveObjectInventoryRecord,
} from "./evasiveSchemas.mjs";
import { ASSURANCE_ANALYSIS_SCHEMA_REVISION } from "./assuranceState.mjs";

// Additive assurance-only contracts. Current baseline packet and wrapper paths do not call
// these helpers until a later explicit wiring change.
export const PROMPT_RESILIENCE_SCHEMA_REVISION = 6;
export const PROMPT_NORMALIZED_VIEW_KIND = "prompt-normalized-view";
export const PROMPT_REVIEW_ASSIGNMENT_KIND =
    "prompt-normalized-review-assignment";
export const PROMPT_REVIEW_RECORD_KIND = "prompt-normalized-review-record";
export const PROMPT_REVIEW_COVERAGE_KIND = "prompt-normalized-review-coverage";
export const PROMPT_REVIEW_MODE = "independent-normalized-view";
export const PROMPT_REVIEW_ISSUER_ID = "zerotrust-sourcecheck-wrapper";
export const PROMPT_REVIEW_CANARY_MARKER =
    "zt-canary-bounded-normalized-view";
export const PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER =
    "zt-output-contract-json-only";

if (PROMPT_RESILIENCE_SCHEMA_REVISION !== ASSURANCE_ANALYSIS_SCHEMA_REVISION) {
    throw new Error("prompt-resilience and assurance analysis schema revisions must align");
}

export const PROMPT_SIGNAL_KINDS = Object.freeze([
    "instruction-override",
    "role-reassignment",
    "review-suppression",
    "tool-directive",
    "output-shaping",
    "boundary-spoofing",
    "credential-request",
    "prompt-metadata",
]);

export const PROMPT_FACT_OBJECT_KINDS = Object.freeze([
    "blob",
    "executable-blob",
    "local-file",
    "source-text",
    "archive-entry",
    "embedded-payload",
    "generated-source",
    "manifest",
    "dependency-metadata",
    "release-asset",
]);

export const PROMPT_REVIEW_DECISIONS = Object.freeze([
    "no-manipulation-supported",
    "manipulation-candidate",
    "incomplete",
]);

export const PROMPT_REVIEW_BLOCKERS = Object.freeze({
    ASSIGNMENT_MISSING: "assignment-missing",
    REVIEW_MISSING: "review-missing",
    REVIEW_INCOMPLETE: "review-incomplete",
});

export const PROMPT_REVIEW_BLOCKER_CODES = Object.freeze(
    Object.values(PROMPT_REVIEW_BLOCKERS),
);

export const PROMPT_RESILIENCE_LIMITS = Object.freeze({
    facts: 2048,
    metadataFacts: 2048,
    tokensPerFact: 64,
    tokenLength: 128,
    signals: 512,
    reviewSubjects: 50_000,
});

const AUDIT_ID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SOURCE_NAMESPACE_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}$/;
const OBJECT_ID_RE = /^zto-[a-f0-9]{64}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const INDEXED_FACT_ID_RE = /^[a-f0-9]{64}$/;
const METADATA_FACT_ID_RE = /^ztpmf-[a-f0-9]{64}$/;
const EVIDENCE_ID_RE = /^ztpe-[a-f0-9]{64}$/;
const SIGNAL_ID_RE = /^ztps-[a-f0-9]{64}$/;
const NORMALIZED_VIEW_ID_RE = /^ztpv-[a-f0-9]{64}$/;
const ASSIGNMENT_ID_RE = /^ztpa-[a-f0-9]{64}$/;
const ASSIGNMENT_TOKEN_RE = /^ztpt-[a-f0-9]{64}$/;
const REVIEW_ID_RE = /^ztpr-[a-f0-9]{64}$/;
const TOKEN_RE = /^[a-z0-9][a-z0-9_$@./:+-]{0,127}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;

const SIGNAL_RULES = Object.freeze([
    Object.freeze({
        kind: "instruction-override",
        signatures: Object.freeze([
            Object.freeze(["ignore", "previous", "instructions"]),
            Object.freeze(["ignore", "prior", "instructions"]),
            Object.freeze(["disregard", "previous", "instructions"]),
            Object.freeze(["disregard", "system", "prompt"]),
            Object.freeze(["override", "system", "message"]),
        ]),
    }),
    Object.freeze({
        kind: "role-reassignment",
        signatures: Object.freeze([
            Object.freeze(["you", "are", "now"]),
            Object.freeze(["act", "as"]),
            Object.freeze(["assume", "role"]),
            Object.freeze(["new", "system", "message"]),
        ]),
    }),
    Object.freeze({
        kind: "review-suppression",
        signatures: Object.freeze([
            Object.freeze(["do", "not", "report"]),
            Object.freeze(["do", "not", "inspect"]),
            Object.freeze(["skip", "this", "file"]),
            Object.freeze(["mark", "as", "safe"]),
            Object.freeze(["no", "findings"]),
        ]),
    }),
    Object.freeze({
        kind: "tool-directive",
        signatures: Object.freeze([
            Object.freeze(["call", "tool"]),
            Object.freeze(["run", "command"]),
            Object.freeze(["execute", "command"]),
            Object.freeze(["use", "powershell"]),
            Object.freeze(["write", "file"]),
            Object.freeze(["read", "secrets"]),
        ]),
    }),
    Object.freeze({
        kind: "output-shaping",
        signatures: Object.freeze([
            Object.freeze(["output", "only"]),
            Object.freeze(["respond", "only"]),
            Object.freeze(["return", "only", "json"]),
            Object.freeze(["emit", "exactly"]),
        ]),
    }),
    Object.freeze({
        kind: "boundary-spoofing",
        signatures: Object.freeze([
            Object.freeze(["user_input_begin"]),
            Object.freeze(["user_input_end"]),
            Object.freeze(["system_message_begin"]),
            Object.freeze(["system_message_end"]),
            Object.freeze(["output_contract"]),
        ]),
    }),
    Object.freeze({
        kind: "credential-request",
        signatures: Object.freeze([
            Object.freeze(["reveal", "secrets"]),
            Object.freeze(["expose", "credentials"]),
            Object.freeze(["print", "token"]),
            Object.freeze(["send", "secrets"]),
        ]),
    }),
]);

const PROMPT_METADATA_KINDS = Object.freeze({
    "prompt-fragment": "prompt-metadata",
    "instruction-fragment": "prompt-metadata",
    "reviewer-directive": "prompt-metadata",
    "system-message": "prompt-metadata",
    "output-contract": "prompt-metadata",
});

export class PromptResilienceContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "PromptResilienceContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new PromptResilienceContractError(path, message);
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function objectShape(value, path, required) {
    if (!isPlainObject(value)) fail(path, "must be a plain object");
    const allowed = new Set(required);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) fail(`${path}.${key}`, "unknown field");
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "is required");
    }
}

function boundedArray(value, path, max) {
    if (!Array.isArray(value)) fail(path, "must be an array");
    if (value.length > max) fail(path, `must contain at most ${max} entries`);
    return value;
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

function compareStrings(left, right) {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
}

function sortedUnique(values, path, {
    max,
    pattern,
    allowed,
} = {}) {
    const normalized = boundedArray(values, path, max).map((entry, index) => {
        if (allowed) return enumValue(entry, `${path}[${index}]`, allowed);
        return boundedString(entry, `${path}[${index}]`, {
            max: PROMPT_RESILIENCE_LIMITS.tokenLength,
            pattern,
        });
    });
    if (new Set(normalized).size !== normalized.length) {
        fail(path, "must not contain duplicates");
    }
    return [...normalized].sort(compareStrings);
}

function validatePath(value, path) {
    const normalized = boundedString(value, path, { max: 4096 });
    if (normalized.startsWith("/")
        || /^[A-Za-z]:[\\/]/u.test(normalized)
        || normalized.includes("\\")
        || normalized.split("/").some((segment) =>
            segment.length === 0 || segment === "." || segment === "..")
        || /[\u0000-\u001f\u007f]/u.test(normalized)) {
        fail(path, "must be a normalized relative path");
    }
    return normalized;
}

function validateLine(value, path, { allowZero = false } = {}) {
    const minimum = allowZero ? 0: 1;
    if (!Number.isSafeInteger(value) || value < minimum || value > 10_000_000) {
        fail(path, `must be a safe integer between ${minimum} and 10000000`);
    }
    return value;
}

function normalizeTokenArray(value, path) {
    const normalized = boundedArray(
        value,
        path,
        PROMPT_RESILIENCE_LIMITS.tokensPerFact,
    ).map((token, index) =>
        boundedString(token, `${path}[${index}]`, {
            max: PROMPT_RESILIENCE_LIMITS.tokenLength,
            pattern: TOKEN_RE,
        }).toLowerCase());
    if (new Set(normalized).size !== normalized.length) {
        fail(path, "must not contain duplicate tokens");
    }
    return normalized;
}

function tokenize(value) {
    const normalized = String(value || "")
        .normalize("NFKC")
        .toLowerCase()
        .replace(/\bdon['’]t\b/gu, "do not")
        .replace(/\bcan['’]t\b/gu, "can not");
    const matches = normalized.match(/[a-z0-9][a-z0-9_$@./:+-]{0,127}/gu) || [];
    const tokens = [];
    const seen = new Set();
    for (const token of matches) {
        if (seen.has(token)) continue;
        seen.add(token);
        tokens.push(token);
        if (tokens.length >= PROMPT_RESILIENCE_LIMITS.tokensPerFact) break;
    }
    return tokens;
}

function containsOrderedTokens(tokens, signature) {
    let cursor = 0;
    for (const token of tokens) {
        if (token === signature[cursor]) cursor += 1;
        if (cursor === signature.length) return true;
    }
    return false;
}

function validateEvidenceInput(value, path, expectedPath = null) {
    objectShape(value, path, ["path", "startLine", "endLine", "excerptHash"]);
    const normalized = {
        path: validatePath(value.path, `${path}.path`),
        startLine: validateLine(value.startLine, `${path}.startLine`),
        endLine: validateLine(value.endLine, `${path}.endLine`),
        excerptHash: boundedString(value.excerptHash, `${path}.excerptHash`, {
            max: 64,
            pattern: SHA256_RE,
        }).toLowerCase(),
    };
    if (normalized.endLine < normalized.startLine) {
        fail(`${path}.endLine`, "must be greater than or equal to startLine");
    }
    if (expectedPath !== null && normalized.path !== expectedPath) {
        fail(`${path}.path`, "does not match the assurance object path");
    }
    return normalized;
}

function evidenceIdentity(object, factId, evidence) {
    const evidenceSha256 = hashDomain("zerotrust-prompt-evidence", {
        objectId: object.objectId,
        objectIdentitySha256: object.hashes.identitySha256,
        factId,
        ...evidence,
    });
    return {
        evidenceId: `ztpe-${evidenceSha256}`,
        factId,
        ...evidence,
    };
}

export function createPromptMetadataFact(
    value,
    path = "promptMetadataFactInput",
) {
    objectShape(value, path, ["kind", "tokens", "evidence"]);
    const kind = boundedString(value.kind, `${path}.kind`, {
        max: 128,
        pattern: IDENTIFIER_RE,
        normalize: true,
    }).toLowerCase();
    const tokens = normalizeTokenArray(value.tokens, `${path}.tokens`);
    if (tokens.length === 0) fail(`${path}.tokens`, "must not be empty");
    const evidence = validateEvidenceInput(value.evidence, `${path}.evidence`);
    const factSha256 = hashDomain("zerotrust-prompt-metadata-fact", {
        kind,
        tokens,
        evidence,
    });
    return cloneFrozen({
        schemaVersion: PROMPT_RESILIENCE_SCHEMA_REVISION,
        contractKind: "prompt-metadata-fact",
        factId: `ztpmf-${factSha256}`,
        kind,
        tokens,
        evidence,
        hashes: {
            factSha256,
        },
    });
}

export function validatePromptMetadataFact(
    value,
    path = "promptMetadataFact",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "factId",
        "kind",
        "tokens",
        "evidence",
        "hashes",
    ]);
    if (value.schemaVersion !== PROMPT_RESILIENCE_SCHEMA_REVISION) {
        fail(`${path}.schemaVersion`, "must equal 6");
    }
    if (value.contractKind !== "prompt-metadata-fact") {
        fail(`${path}.contractKind`, "is invalid");
    }
    boundedString(value.factId, `${path}.factId`, {
        max: 73,
        pattern: METADATA_FACT_ID_RE,
    });
    objectShape(value.hashes, `${path}.hashes`, ["factSha256"]);
    boundedString(value.hashes.factSha256, `${path}.hashes.factSha256`, {
        max: 64,
        pattern: SHA256_RE,
    });
    const expected = createPromptMetadataFact({
        kind: value.kind,
        tokens: value.tokens,
        evidence: value.evidence,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic metadata-fact identity");
    }
    return expected;
}

function normalizeIndexedFact(value, path, object) {
    const required = [
        "id",
        "kind",
        "path",
        "line",
        "endLine",
        "excerptHash",
        "name",
    ];
    const allowed = new Set([...required, "value"]);
    if (!isPlainObject(value)) fail(path, "must be a plain object");
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) fail(`${path}.${key}`, "unknown field");
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "is required");
    }
    const factId = boundedString(value.id, `${path}.id`, {
        max: 64,
        pattern: INDEXED_FACT_ID_RE,
    }).toLowerCase();
    const kind = boundedString(value.kind, `${path}.kind`, {
        max: 128,
        pattern: IDENTIFIER_RE,
        normalize: true,
    }).toLowerCase();
    const evidence = validateEvidenceInput({
        path: value.path,
        startLine: value.line,
        endLine: value.endLine,
        excerptHash: value.excerptHash,
    }, `${path}.evidence`, object.path);
    const name = boundedString(value.name, `${path}.name`, {
        max: 128,
        normalize: true,
    });
    if (name !== value.name) {
        fail(`${path}.name`, "must already be source-normalized");
    }
    const factValue = value.value === undefined
        ? "": boundedString(value.value, `${path}.value`, {
            max: 256,
            normalize: true,
        });
    if (value.value !== undefined && factValue !== value.value) {
        fail(`${path}.value`, "must already be source-normalized");
    }
    const expectedFactId = createHash("sha256")
        .update(
            `${kind}\0${evidence.path}\0${evidence.startLine}\0`
            + `${name}\0${factValue}`,
            "utf8",
        )
        .digest("hex");
    if (factId !== expectedFactId) {
        fail(`${path}.id`, "does not match the canonical normalized fact");
    }
    return {
        factId,
        kind,
        tokens: tokenize(`${name} ${factValue}`),
        evidence: evidenceIdentity(object, factId, evidence),
    };
}

function normalizeMetadataFact(value, path, object) {
    const metadata = validatePromptMetadataFact(value, path);
    if (metadata.evidence.path !== object.path) {
        fail(`${path}.evidence.path`, "does not match the assurance object path");
    }
    return {
        factId: metadata.factId,
        kind: metadata.kind,
        tokens: [...metadata.tokens],
        evidence: evidenceIdentity(
            object,
            metadata.factId,
            metadata.evidence,
        ),
    };
}

function signalMatches(fact) {
    const matches = [];
    for (const rule of SIGNAL_RULES) {
        for (const signature of rule.signatures) {
            if (containsOrderedTokens(fact.tokens, signature)) {
                matches.push({
                    kind: rule.kind,
                    tokens: [...signature],
                });
            }
        }
    }
    const metadataKind = Object.hasOwn(PROMPT_METADATA_KINDS, fact.kind)
        ? PROMPT_METADATA_KINDS[fact.kind]: null;
    if (metadataKind) {
        matches.push({
            kind: metadataKind,
            tokens: [fact.kind],
        });
    }
    return matches;
}

function normalizedSignal(object, fact, match) {
    const signalSha256 = hashDomain("zerotrust-prompt-signal", {
        objectId: object.objectId,
        kind: match.kind,
        tokens: match.tokens,
        factIds: [fact.factId],
        evidenceIds: [fact.evidence.evidenceId],
    });
    return {
        signalId: `ztps-${signalSha256}`,
        kind: match.kind,
        tokens: match.tokens,
        factIds: [fact.factId],
        evidenceIds: [fact.evidence.evidenceId],
    };
}

export function detectPromptLikeSource(
    value,
    path = "promptDetectionInput",
) {
    objectShape(value, path, [
        "object",
        "detectorId",
        "detectorVersion",
        "facts",
        "metadataFacts",
    ]);
    const object = validateEvasiveObjectInventoryRecord(
        value.object,
        `${path}.object`,
    );
    if (!PROMPT_FACT_OBJECT_KINDS.includes(object.objectKind)) {
        fail(
            `${path}.object.objectKind`,
            "prompt detection requires a fact-bearing assurance object kind",
        );
    }
    const detector = {
        id: boundedString(value.detectorId, `${path}.detectorId`, {
            max: 128,
            pattern: IDENTIFIER_RE,
            normalize: true,
        }),
        version: boundedString(
            value.detectorVersion,
            `${path}.detectorVersion`,
            {
                max: 64,
                pattern: /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/,
                normalize: true,
            },
        ),
    };
    const facts = boundedArray(
        value.facts,
        `${path}.facts`,
        PROMPT_RESILIENCE_LIMITS.facts,
    ).map((fact, index) =>
        normalizeIndexedFact(fact, `${path}.facts[${index}]`, object));
    const metadataFacts = boundedArray(
        value.metadataFacts,
        `${path}.metadataFacts`,
        PROMPT_RESILIENCE_LIMITS.metadataFacts,
    ).map((fact, index) =>
        normalizeMetadataFact(
            fact,
            `${path}.metadataFacts[${index}]`,
            object,
        ));
    const allFacts = [...facts, ...metadataFacts];
    const factIds = allFacts.map((fact) => fact.factId);
    if (new Set(factIds).size !== factIds.length) {
        fail(path, "fact identities must be unique");
    }

    const signals = [];
    const factsById = new Map();
    const evidenceById = new Map();
    for (const fact of allFacts) {
        for (const match of signalMatches(fact)) {
            const signal = normalizedSignal(object, fact, match);
            if (signals.some((entry) => entry.signalId === signal.signalId)) continue;
            signals.push(signal);
            const existing = factsById.get(fact.factId);
            const matchedTokens = new Set(existing?.tokens || []);
            for (const token of match.tokens) matchedTokens.add(token);
            factsById.set(fact.factId, {
                factId: fact.factId,
                kind: fact.kind,
                tokens: [...matchedTokens].sort(compareStrings),
                evidenceId: fact.evidence.evidenceId,
            });
            evidenceById.set(fact.evidence.evidenceId, fact.evidence);
        }
    }
    signals.sort((left, right) => compareStrings(left.signalId, right.signalId));
    const normalizedFacts = [...factsById.values()]
        .sort((left, right) => compareStrings(left.factId, right.factId));
    const evidence = [...evidenceById.values()]
        .sort((left, right) => compareStrings(left.evidenceId, right.evidenceId));
    const signalKinds = [...new Set(signals.map((signal) => signal.kind))]
        .sort(compareStrings);
    const promptAffected = signals.length > 0;
    const factsSha256 = hashDomain("zerotrust-prompt-facts", normalizedFacts);
    const evidenceSha256 = hashDomain("zerotrust-prompt-evidence-set", evidence);
    const signalsSha256 = hashDomain("zerotrust-prompt-signals", signals);
    const normalizedViewSha256 = hashDomain("zerotrust-prompt-normalized-view", {
        auditId: object.auditId,
        sourceNamespace: object.sourceNamespace,
        objectId: object.objectId,
        path: object.path,
        objectIdentitySha256: object.hashes.identitySha256,
        detector,
        promptAffected,
        signalKinds,
        factsSha256,
        evidenceSha256,
        signalsSha256,
    });
    return cloneFrozen({
        schemaVersion: PROMPT_RESILIENCE_SCHEMA_REVISION,
        contractKind: PROMPT_NORMALIZED_VIEW_KIND,
        normalizedViewId: `ztpv-${normalizedViewSha256}`,
        auditId: object.auditId,
        sourceNamespace: object.sourceNamespace,
        objectId: object.objectId,
        path: object.path,
        detector,
        promptAffected,
        signalKinds,
        facts: normalizedFacts,
        evidence,
        signals,
        hashes: {
            objectIdentitySha256: object.hashes.identitySha256,
            factsSha256,
            evidenceSha256,
            signalsSha256,
            normalizedViewSha256,
        },
    });
}

function validateFactReference(value, path) {
    objectShape(value, path, ["factId", "kind", "tokens", "evidenceId"]);
    const factId = boundedString(value.factId, `${path}.factId`, {
        max: 73,
    });
    if (!INDEXED_FACT_ID_RE.test(factId) && !METADATA_FACT_ID_RE.test(factId)) {
        fail(`${path}.factId`, "has an invalid fact identity");
    }
    return {
        factId,
        kind: boundedString(value.kind, `${path}.kind`, {
            max: 128,
            pattern: IDENTIFIER_RE,
        }).toLowerCase(),
        tokens: sortedUnique(value.tokens, `${path}.tokens`, {
            max: PROMPT_RESILIENCE_LIMITS.tokensPerFact,
            pattern: TOKEN_RE,
        }),
        evidenceId: boundedString(value.evidenceId, `${path}.evidenceId`, {
            max: 72,
            pattern: EVIDENCE_ID_RE,
        }),
    };
}

function validateEvidenceReference(value, path, subject) {
    objectShape(value, path, [
        "evidenceId",
        "factId",
        "path",
        "startLine",
        "endLine",
        "excerptHash",
    ]);
    const factId = boundedString(value.factId, `${path}.factId`, { max: 73 });
    if (!INDEXED_FACT_ID_RE.test(factId) && !METADATA_FACT_ID_RE.test(factId)) {
        fail(`${path}.factId`, "has an invalid fact identity");
    }
    const evidence = validateEvidenceInput({
        path: value.path,
        startLine: value.startLine,
        endLine: value.endLine,
        excerptHash: value.excerptHash,
    }, path, subject.path);
    const expected = evidenceIdentity(subject, factId, evidence);
    boundedString(value.evidenceId, `${path}.evidenceId`, {
        max: 72,
        pattern: EVIDENCE_ID_RE,
    });
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic evidence identity");
    }
    return expected;
}

function signatureExists(kind, tokens) {
    if (kind === "prompt-metadata") {
        return tokens.length === 1
            && Object.hasOwn(PROMPT_METADATA_KINDS, tokens[0]);
    }
    const rule = SIGNAL_RULES.find((candidate) => candidate.kind === kind);
    return rule?.signatures.some((signature) =>
        canonicalJson(signature) === canonicalJson(tokens)) === true;
}

function validateSignal(value, path, subject) {
    objectShape(value, path, [
        "signalId",
        "kind",
        "tokens",
        "factIds",
        "evidenceIds",
    ]);
    const kind = enumValue(value.kind, `${path}.kind`, PROMPT_SIGNAL_KINDS);
    const tokens = normalizeTokenArray(value.tokens, `${path}.tokens`);
    if (!signatureExists(kind, tokens)) {
        fail(`${path}.tokens`, "do not match a deterministic signal signature");
    }
    const factIds = sortedUnique(value.factIds, `${path}.factIds`, {
        max: PROMPT_RESILIENCE_LIMITS.facts,
    });
    for (const factId of factIds) {
        if (!INDEXED_FACT_ID_RE.test(factId) && !METADATA_FACT_ID_RE.test(factId)) {
            fail(`${path}.factIds`, "contains an invalid fact identity");
        }
    }
    const evidenceIds = sortedUnique(value.evidenceIds, `${path}.evidenceIds`, {
        max: PROMPT_RESILIENCE_LIMITS.facts,
        pattern: EVIDENCE_ID_RE,
    });
    if (factIds.length === 0 || evidenceIds.length === 0) {
        fail(path, "must reference normalized facts and evidence");
    }
    const expectedId = `ztps-${hashDomain("zerotrust-prompt-signal", {
        objectId: subject.objectId,
        kind,
        tokens,
        factIds,
        evidenceIds,
    })}`;
    boundedString(value.signalId, `${path}.signalId`, {
        max: 72,
        pattern: SIGNAL_ID_RE,
    });
    if (value.signalId !== expectedId) {
        fail(`${path}.signalId`, "does not match its deterministic signal identity");
    }
    return {
        signalId: expectedId,
        kind,
        tokens,
        factIds,
        evidenceIds,
    };
}

export function validatePromptNormalizedView(
    value,
    path = "promptNormalizedView",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "normalizedViewId",
        "auditId",
        "sourceNamespace",
        "objectId",
        "path",
        "detector",
        "promptAffected",
        "signalKinds",
        "facts",
        "evidence",
        "signals",
        "hashes",
    ]);
    if (value.schemaVersion !== PROMPT_RESILIENCE_SCHEMA_REVISION) {
        fail(`${path}.schemaVersion`, "must equal 6; baseline prompt output is not assurance coverage");
    }
    if (value.contractKind !== PROMPT_NORMALIZED_VIEW_KIND) {
        fail(`${path}.contractKind`, "is invalid");
    }
    const subject = {
        auditId: boundedString(value.auditId, `${path}.auditId`, {
            max: 36,
            pattern: AUDIT_ID_RE,
        }).toLowerCase(),
        sourceNamespace: boundedString(
            value.sourceNamespace,
            `${path}.sourceNamespace`,
            { max: 512, pattern: SOURCE_NAMESPACE_RE, normalize: true },
        ),
        objectId: boundedString(value.objectId, `${path}.objectId`, {
            max: 71,
            pattern: OBJECT_ID_RE,
        }),
        path: validatePath(value.path, `${path}.path`),
    };
    objectShape(value.detector, `${path}.detector`, ["id", "version"]);
    const detector = {
        id: boundedString(value.detector.id, `${path}.detector.id`, {
            max: 128,
            pattern: IDENTIFIER_RE,
            normalize: true,
        }),
        version: boundedString(
            value.detector.version,
            `${path}.detector.version`,
            {
                max: 64,
                pattern: /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/,
                normalize: true,
            },
        ),
    };
    if (typeof value.promptAffected !== "boolean") {
        fail(`${path}.promptAffected`, "must be a boolean");
    }
    const signalKinds = sortedUnique(value.signalKinds, `${path}.signalKinds`, {
        max: PROMPT_SIGNAL_KINDS.length,
        allowed: PROMPT_SIGNAL_KINDS,
    });
    const facts = boundedArray(
        value.facts,
        `${path}.facts`,
        PROMPT_RESILIENCE_LIMITS.facts,
    ).map((fact, index) =>
        validateFactReference(fact, `${path}.facts[${index}]`))
        .sort((left, right) => compareStrings(left.factId, right.factId));
    const factIdSet = new Set(facts.map((fact) => fact.factId));
    if (factIdSet.size !== facts.length) fail(`${path}.facts`, "contains duplicate fact IDs");
    objectShape(value.hashes, `${path}.hashes`, [
        "objectIdentitySha256",
        "factsSha256",
        "evidenceSha256",
        "signalsSha256",
        "normalizedViewSha256",
    ]);
    const objectIdentitySha256 = boundedString(
        value.hashes.objectIdentitySha256,
        `${path}.hashes.objectIdentitySha256`,
        { max: 64, pattern: SHA256_RE },
    ).toLowerCase();
    const evidenceSubject = {
        objectId: subject.objectId,
        path: subject.path,
        hashes: { identitySha256: objectIdentitySha256 },
    };
    const evidence = boundedArray(
        value.evidence,
        `${path}.evidence`,
        PROMPT_RESILIENCE_LIMITS.facts,
    ).map((entry, index) =>
        validateEvidenceReference(
            entry,
            `${path}.evidence[${index}]`,
            evidenceSubject,
        ))
        .sort((left, right) => compareStrings(left.evidenceId, right.evidenceId));
    const evidenceIdSet = new Set(evidence.map((entry) => entry.evidenceId));
    if (evidenceIdSet.size !== evidence.length) {
        fail(`${path}.evidence`, "contains duplicate evidence IDs");
    }
    const evidenceById = new Map(
        evidence.map((entry) => [entry.evidenceId, entry]),
    );
    const signals = boundedArray(
        value.signals,
        `${path}.signals`,
        PROMPT_RESILIENCE_LIMITS.signals,
    ).map((signal, index) =>
        validateSignal(signal, `${path}.signals[${index}]`, subject))
        .sort((left, right) => compareStrings(left.signalId, right.signalId));
    if (new Set(signals.map((signal) => signal.signalId)).size !== signals.length) {
        fail(`${path}.signals`, "contains duplicate signal IDs");
    }
    for (const fact of facts) {
        if (!evidenceIdSet.has(fact.evidenceId)) {
            fail(`${path}.facts`, `references unknown evidence: ${fact.evidenceId}`);
        }
        if (evidenceById.get(fact.evidenceId).factId !== fact.factId) {
            fail(`${path}.facts`, "fact and evidence identities are not bound");
        }
    }
    for (const signal of signals) {
        for (const factId of signal.factIds) {
            if (!factIdSet.has(factId)) {
                fail(`${path}.signals`, `references unknown fact: ${factId}`);
            }
        }
        for (const evidenceId of signal.evidenceIds) {
            if (!evidenceIdSet.has(evidenceId)) {
                fail(`${path}.signals`, `references unknown evidence: ${evidenceId}`);
            }
        }
        const signalEvidenceFactIds = new Set(
            signal.evidenceIds.map((evidenceId) =>
                evidenceById.get(evidenceId).factId),
        );
        if (signal.factIds.some((factId) => !signalEvidenceFactIds.has(factId))) {
            fail(
                `${path}.signals`,
                "signal fact identities are not backed by its evidence identities",
            );
        }
    }
    const expectedKinds = [...new Set(signals.map((signal) => signal.kind))]
        .sort(compareStrings);
    if (canonicalJson(signalKinds) !== canonicalJson(expectedKinds)) {
        fail(`${path}.signalKinds`, "does not match the normalized signals");
    }
    if (value.promptAffected !== (signals.length > 0)) {
        fail(`${path}.promptAffected`, "does not match normalized signal presence");
    }
    const factsSha256 = hashDomain("zerotrust-prompt-facts", facts);
    const evidenceSha256 = hashDomain("zerotrust-prompt-evidence-set", evidence);
    const signalsSha256 = hashDomain("zerotrust-prompt-signals", signals);
    const normalizedViewSha256 = hashDomain("zerotrust-prompt-normalized-view", {
        ...subject,
        objectIdentitySha256,
        detector,
        promptAffected: value.promptAffected,
        signalKinds,
        factsSha256,
        evidenceSha256,
        signalsSha256,
    });
    const expected = cloneFrozen({
        schemaVersion: PROMPT_RESILIENCE_SCHEMA_REVISION,
        contractKind: PROMPT_NORMALIZED_VIEW_KIND,
        normalizedViewId: `ztpv-${normalizedViewSha256}`,
        ...subject,
        detector,
        promptAffected: value.promptAffected,
        signalKinds,
        facts,
        evidence,
        signals,
        hashes: {
            objectIdentitySha256,
            factsSha256,
            evidenceSha256,
            signalsSha256,
            normalizedViewSha256,
        },
    });
    boundedString(value.normalizedViewId, `${path}.normalizedViewId`, {
        max: 72,
        pattern: NORMALIZED_VIEW_ID_RE,
    });
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic normalized-view contract");
    }
    return expected;
}

export function createPromptReviewAssignment(
    value,
    path = "promptReviewAssignmentInput",
) {
    objectShape(value, path, [
        "normalizedView",
        "reviewerId",
        "reviewerVersion",
        "assignmentNonceSha256",
    ]);
    const normalizedView = validatePromptNormalizedView(
        value.normalizedView,
        `${path}.normalizedView`,
    );
    if (!normalizedView.promptAffected) {
        fail(`${path}.normalizedView`, "does not require a prompt-resilience review");
    }
    const reviewerId = boundedString(value.reviewerId, `${path}.reviewerId`, {
        max: 128,
        pattern: IDENTIFIER_RE,
        normalize: true,
    });
    if (reviewerId === normalizedView.detector.id) {
        fail(`${path}.reviewerId`, "must be independent from the detector");
    }
    const reviewerVersion = boundedString(
        value.reviewerVersion,
        `${path}.reviewerVersion`,
        {
            max: 64,
            pattern: /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/,
            normalize: true,
        },
    );
    const assignmentNonceSha256 = boundedString(
        value.assignmentNonceSha256,
        `${path}.assignmentNonceSha256`,
        { max: 64, pattern: SHA256_RE },
    ).toLowerCase();
    const markers = {
        canary: PROMPT_REVIEW_CANARY_MARKER,
        outputContract: PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER,
    };
    const assignmentSha256 = hashDomain("zerotrust-prompt-assignment", {
        issuerId: PROMPT_REVIEW_ISSUER_ID,
        reviewerId,
        reviewerVersion,
        reviewMode: PROMPT_REVIEW_MODE,
        normalizedViewId: normalizedView.normalizedViewId,
        normalizedViewSha256: normalizedView.hashes.normalizedViewSha256,
        markers,
    });
    const tokenBindingSha256 = hashDomain("zerotrust-prompt-assignment-token", {
        assignmentSha256,
        assignmentNonceSha256,
    });
    return cloneFrozen({
        schemaVersion: PROMPT_RESILIENCE_SCHEMA_REVISION,
        contractKind: PROMPT_REVIEW_ASSIGNMENT_KIND,
        assignmentId: `ztpa-${assignmentSha256}`,
        assignmentToken: `ztpt-${tokenBindingSha256}`,
        issuerId: PROMPT_REVIEW_ISSUER_ID,
        reviewerId,
        reviewerVersion,
        reviewMode: PROMPT_REVIEW_MODE,
        normalizedView,
        markers,
        hashes: {
            normalizedViewSha256: normalizedView.hashes.normalizedViewSha256,
            assignmentSha256,
            tokenBindingSha256,
        },
    });
}

export function validatePromptReviewAssignment(
    value,
    path = "promptReviewAssignment",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "assignmentId",
        "assignmentToken",
        "issuerId",
        "reviewerId",
        "reviewerVersion",
        "reviewMode",
        "normalizedView",
        "markers",
        "hashes",
    ]);
    if (value.schemaVersion !== PROMPT_RESILIENCE_SCHEMA_REVISION) {
        fail(`${path}.schemaVersion`, "must equal 6");
    }
    if (value.contractKind !== PROMPT_REVIEW_ASSIGNMENT_KIND) {
        fail(`${path}.contractKind`, "is invalid");
    }
    if (value.issuerId !== PROMPT_REVIEW_ISSUER_ID) {
        fail(`${path}.issuerId`, "must identify the wrapper contract issuer");
    }
    if (value.reviewMode !== PROMPT_REVIEW_MODE) {
        fail(`${path}.reviewMode`, "must require an independent normalized view");
    }
    const normalizedView = validatePromptNormalizedView(
        value.normalizedView,
        `${path}.normalizedView`,
    );
    if (!normalizedView.promptAffected) {
        fail(`${path}.normalizedView`, "does not require a prompt-resilience review");
    }
    const reviewerId = boundedString(value.reviewerId, `${path}.reviewerId`, {
        max: 128,
        pattern: IDENTIFIER_RE,
        normalize: true,
    });
    if (reviewerId === normalizedView.detector.id) {
        fail(`${path}.reviewerId`, "must be independent from the detector");
    }
    const reviewerVersion = boundedString(
        value.reviewerVersion,
        `${path}.reviewerVersion`,
        {
            max: 64,
            pattern: /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/,
            normalize: true,
        },
    );
    objectShape(value.markers, `${path}.markers`, ["canary", "outputContract"]);
    if (value.markers.canary !== PROMPT_REVIEW_CANARY_MARKER) {
        fail(`${path}.markers.canary`, "canary marker drifted");
    }
    if (value.markers.outputContract !== PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER) {
        fail(`${path}.markers.outputContract`, "output-contract marker drifted");
    }
    objectShape(value.hashes, `${path}.hashes`, [
        "normalizedViewSha256",
        "assignmentSha256",
        "tokenBindingSha256",
    ]);
    const normalizedViewSha256 = boundedString(
        value.hashes.normalizedViewSha256,
        `${path}.hashes.normalizedViewSha256`,
        { max: 64, pattern: SHA256_RE },
    ).toLowerCase();
    if (normalizedViewSha256 !== normalizedView.hashes.normalizedViewSha256) {
        fail(`${path}.hashes.normalizedViewSha256`, "does not match the payload");
    }
    const assignmentSha256 = hashDomain("zerotrust-prompt-assignment", {
        issuerId: PROMPT_REVIEW_ISSUER_ID,
        reviewerId,
        reviewerVersion,
        reviewMode: PROMPT_REVIEW_MODE,
        normalizedViewId: normalizedView.normalizedViewId,
        normalizedViewSha256,
        markers: value.markers,
    });
    const tokenBindingSha256 = boundedString(
        value.hashes.tokenBindingSha256,
        `${path}.hashes.tokenBindingSha256`,
        { max: 64, pattern: SHA256_RE },
    ).toLowerCase();
    boundedString(value.hashes.assignmentSha256, `${path}.hashes.assignmentSha256`, {
        max: 64,
        pattern: SHA256_RE,
    });
    boundedString(value.assignmentId, `${path}.assignmentId`, {
        max: 72,
        pattern: ASSIGNMENT_ID_RE,
    });
    boundedString(value.assignmentToken, `${path}.assignmentToken`, {
        max: 72,
        pattern: ASSIGNMENT_TOKEN_RE,
    });
    const expected = cloneFrozen({
        schemaVersion: PROMPT_RESILIENCE_SCHEMA_REVISION,
        contractKind: PROMPT_REVIEW_ASSIGNMENT_KIND,
        assignmentId: `ztpa-${assignmentSha256}`,
        assignmentToken: `ztpt-${tokenBindingSha256}`,
        issuerId: PROMPT_REVIEW_ISSUER_ID,
        reviewerId,
        reviewerVersion,
        reviewMode: PROMPT_REVIEW_MODE,
        normalizedView,
        markers: {
            canary: PROMPT_REVIEW_CANARY_MARKER,
            outputContract: PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER,
        },
        hashes: {
            normalizedViewSha256,
            assignmentSha256,
            tokenBindingSha256,
        },
    });
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its wrapper-issued assignment contract");
    }
    return expected;
}

function exactCoverageIds(value, path, expected, pattern) {
    const normalized = sortedUnique(value, path, {
        max: PROMPT_RESILIENCE_LIMITS.signals
            + PROMPT_RESILIENCE_LIMITS.facts,
        pattern,
    });
    for (const entry of normalized) {
        if (!expected.includes(entry)) {
            fail(path, `references an identity outside the assignment: ${entry}`);
        }
    }
    return normalized;
}

export function createPromptReviewRecord(
    value,
    path = "promptReviewRecordInput",
) {
    objectShape(value, path, [
        "assignment",
        "reviewerId",
        "assignmentToken",
        "reviewMode",
        "decision",
        "reviewedSignalIds",
        "factIds",
        "evidenceIds",
        "blockerCodes",
        "canaryMarker",
        "outputContractMarker",
    ]);
    const assignment = validatePromptReviewAssignment(
        value.assignment,
        `${path}.assignment`,
    );
    if (value.reviewerId !== assignment.reviewerId) {
        fail(`${path}.reviewerId`, "does not match the assignment");
    }
    if (value.assignmentToken !== assignment.assignmentToken) {
        fail(`${path}.assignmentToken`, "does not match the wrapper-issued token");
    }
    if (value.reviewMode !== PROMPT_REVIEW_MODE) {
        fail(`${path}.reviewMode`, "must be independent-normalized-view");
    }
    if (value.canaryMarker !== PROMPT_REVIEW_CANARY_MARKER) {
        fail(`${path}.canaryMarker`, "canary marker drifted");
    }
    if (value.outputContractMarker !== PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER) {
        fail(`${path}.outputContractMarker`, "output-contract marker drifted");
    }
    const decision = enumValue(
        value.decision,
        `${path}.decision`,
        PROMPT_REVIEW_DECISIONS,
    );
    const expectedSignalIds = assignment.normalizedView.signals
        .map((signal) => signal.signalId).sort(compareStrings);
    const expectedFactIds = assignment.normalizedView.facts
        .map((fact) => fact.factId).sort(compareStrings);
    const expectedEvidenceIds = assignment.normalizedView.evidence
        .map((evidence) => evidence.evidenceId).sort(compareStrings);
    const reviewedSignalIds = exactCoverageIds(
        value.reviewedSignalIds,
        `${path}.reviewedSignalIds`,
        expectedSignalIds,
        SIGNAL_ID_RE,
    );
    const factIds = exactCoverageIds(
        value.factIds,
        `${path}.factIds`,
        expectedFactIds,
    );
    const evidenceIds = exactCoverageIds(
        value.evidenceIds,
        `${path}.evidenceIds`,
        expectedEvidenceIds,
        EVIDENCE_ID_RE,
    );
    const blockerCodes = sortedUnique(
        value.blockerCodes,
        `${path}.blockerCodes`,
        {
            max: PROMPT_REVIEW_BLOCKER_CODES.length,
            allowed: PROMPT_REVIEW_BLOCKER_CODES,
        },
    );
    if (decision === "incomplete") {
        if (canonicalJson(blockerCodes)
            !== canonicalJson([PROMPT_REVIEW_BLOCKERS.REVIEW_INCOMPLETE])) {
            fail(
                `${path}.blockerCodes`,
                "must contain only the normalized review-incomplete blocker",
            );
        }
    } else {
        if (blockerCodes.length > 0) {
            fail(`${path}.blockerCodes`, "completed reviews must not carry blockers");
        }
        if (canonicalJson(reviewedSignalIds) !== canonicalJson(expectedSignalIds)
            || canonicalJson(factIds) !== canonicalJson(expectedFactIds)
            || canonicalJson(evidenceIds) !== canonicalJson(expectedEvidenceIds)) {
            fail(path, "completed review must cover every assigned normalized identity");
        }
    }
    const reviewSha256 = hashDomain("zerotrust-prompt-review-record", {
        assignmentId: assignment.assignmentId,
        assignmentToken: assignment.assignmentToken,
        reviewerId: assignment.reviewerId,
        reviewMode: PROMPT_REVIEW_MODE,
        normalizedViewId: assignment.normalizedView.normalizedViewId,
        decision,
        reviewedSignalIds,
        factIds,
        evidenceIds,
        blockerCodes,
        canaryMarker: PROMPT_REVIEW_CANARY_MARKER,
        outputContractMarker: PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER,
    });
    return cloneFrozen({
        schemaVersion: PROMPT_RESILIENCE_SCHEMA_REVISION,
        contractKind: PROMPT_REVIEW_RECORD_KIND,
        reviewId: `ztpr-${reviewSha256}`,
        assignmentId: assignment.assignmentId,
        assignmentToken: assignment.assignmentToken,
        reviewerId: assignment.reviewerId,
        reviewMode: PROMPT_REVIEW_MODE,
        normalizedViewId: assignment.normalizedView.normalizedViewId,
        decision,
        reviewedSignalIds,
        factIds,
        evidenceIds,
        blockerCodes,
        canaryMarker: PROMPT_REVIEW_CANARY_MARKER,
        outputContractMarker: PROMPT_REVIEW_OUTPUT_CONTRACT_MARKER,
        hashes: {
            assignmentSha256: assignment.hashes.assignmentSha256,
            normalizedViewSha256:
                assignment.normalizedView.hashes.normalizedViewSha256,
            reviewSha256,
        },
    });
}

export function validatePromptReviewRecord(
    value,
    assignmentValue,
    path = "promptReviewRecord",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "reviewId",
        "assignmentId",
        "assignmentToken",
        "reviewerId",
        "reviewMode",
        "normalizedViewId",
        "decision",
        "reviewedSignalIds",
        "factIds",
        "evidenceIds",
        "blockerCodes",
        "canaryMarker",
        "outputContractMarker",
        "hashes",
    ]);
    if (value.schemaVersion !== PROMPT_RESILIENCE_SCHEMA_REVISION) {
        fail(`${path}.schemaVersion`, "must equal 6");
    }
    if (value.contractKind !== PROMPT_REVIEW_RECORD_KIND) {
        fail(`${path}.contractKind`, "is invalid");
    }
    const assignment = validatePromptReviewAssignment(
        assignmentValue,
        `${path}.assignment`,
    );
    objectShape(value.hashes, `${path}.hashes`, [
        "assignmentSha256",
        "normalizedViewSha256",
        "reviewSha256",
    ]);
    boundedString(value.reviewId, `${path}.reviewId`, {
        max: 72,
        pattern: REVIEW_ID_RE,
    });
    const expected = createPromptReviewRecord({
        assignment,
        reviewerId: value.reviewerId,
        assignmentToken: value.assignmentToken,
        reviewMode: value.reviewMode,
        decision: value.decision,
        reviewedSignalIds: value.reviewedSignalIds,
        factIds: value.factIds,
        evidenceIds: value.evidenceIds,
        blockerCodes: value.blockerCodes,
        canaryMarker: value.canaryMarker,
        outputContractMarker: value.outputContractMarker,
    }, path);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match its deterministic normalized-review contract");
    }
    return expected;
}

export function evaluatePromptReviewCoverage(
    {
        normalizedViews = [],
        assignments = [],
        reviews = [],
    } = {},
    path = "promptReviewCoverageInput",
) {
    const views = boundedArray(
        normalizedViews,
        `${path}.normalizedViews`,
        PROMPT_RESILIENCE_LIMITS.reviewSubjects,
    ).map((view, index) =>
        validatePromptNormalizedView(
            view,
            `${path}.normalizedViews[${index}]`,
        ));
    const viewById = new Map();
    for (const view of views) {
        if (viewById.has(view.normalizedViewId)) {
            fail(`${path}.normalizedViews`, "contains duplicate normalized-view IDs");
        }
        viewById.set(view.normalizedViewId, view);
    }
    const assignmentByViewId = new Map();
    const assignmentById = new Map();
    for (const [index, rawAssignment] of boundedArray(
        assignments,
        `${path}.assignments`,
        PROMPT_RESILIENCE_LIMITS.reviewSubjects,
    ).entries()) {
        const assignment = validatePromptReviewAssignment(
            rawAssignment,
            `${path}.assignments[${index}]`,
        );
        const canonicalView = viewById.get(assignment.normalizedView.normalizedViewId);
        if (!canonicalView
            || canonicalJson(canonicalView) !== canonicalJson(assignment.normalizedView)) {
            fail(
                `${path}.assignments[${index}].normalizedView`,
                "is not one of the supplied normalized views",
            );
        }
        if (assignmentByViewId.has(canonicalView.normalizedViewId)) {
            fail(`${path}.assignments`, "contains duplicate assignments for a view");
        }
        if (assignmentById.has(assignment.assignmentId)) {
            fail(`${path}.assignments`, "contains duplicate assignment IDs");
        }
        assignmentByViewId.set(canonicalView.normalizedViewId, assignment);
        assignmentById.set(assignment.assignmentId, assignment);
    }
    const reviewByAssignmentId = new Map();
    for (const [index, rawReview] of boundedArray(
        reviews,
        `${path}.reviews`,
        PROMPT_RESILIENCE_LIMITS.reviewSubjects,
    ).entries()) {
        if (!isPlainObject(rawReview)) {
            fail(`${path}.reviews[${index}]`, "must be a structured review record");
        }
        const assignment = assignmentById.get(rawReview.assignmentId);
        if (!assignment) {
            fail(
                `${path}.reviews[${index}].assignmentId`,
                "does not reference a supplied assignment",
            );
        }
        const review = validatePromptReviewRecord(
            rawReview,
            assignment,
            `${path}.reviews[${index}]`,
        );
        if (reviewByAssignmentId.has(review.assignmentId)) {
            fail(`${path}.reviews`, "contains duplicate reviews for an assignment");
        }
        reviewByAssignmentId.set(review.assignmentId, review);
    }

    const requiredNormalizedViewIds = views
        .filter((view) => view.promptAffected)
        .map((view) => view.normalizedViewId)
        .sort(compareStrings);
    const coveredNormalizedViewIds = [];
    const blockers = [];
    for (const normalizedViewId of requiredNormalizedViewIds) {
        const assignment = assignmentByViewId.get(normalizedViewId);
        if (!assignment) {
            blockers.push({
                code: PROMPT_REVIEW_BLOCKERS.ASSIGNMENT_MISSING,
                normalizedViewId,
            });
            continue;
        }
        const review = reviewByAssignmentId.get(assignment.assignmentId);
        if (!review) {
            blockers.push({
                code: PROMPT_REVIEW_BLOCKERS.REVIEW_MISSING,
                normalizedViewId,
            });
            continue;
        }
        if (review.decision === "incomplete") {
            blockers.push({
                code: PROMPT_REVIEW_BLOCKERS.REVIEW_INCOMPLETE,
                normalizedViewId,
            });
            continue;
        }
        coveredNormalizedViewIds.push(normalizedViewId);
    }
    blockers.sort((left, right) =>
        compareStrings(left.normalizedViewId, right.normalizedViewId)
        || compareStrings(left.code, right.code));
    const complete = blockers.length === 0;
    const evasiveBlockerCodes = complete
        ? []: [
            EVASIVE_BLOCKERS.RED_TEAM_REVIEWER_MANIPULATION,
            EVASIVE_BLOCKERS.SEMANTIC_INCOMPLETE,
        ].sort(compareStrings);
    const basisSha256 = hashDomain("zerotrust-prompt-review-coverage", {
        requiredNormalizedViewIds,
        coveredNormalizedViewIds,
        assignmentIds: [...assignmentById.keys()].sort(compareStrings),
        reviewIds: [...reviewByAssignmentId.values()]
            .map((review) => review.reviewId)
            .sort(compareStrings),
        blockers,
        evasiveBlockerCodes,
    });
    return cloneFrozen({
        schemaVersion: PROMPT_RESILIENCE_SCHEMA_REVISION,
        contractKind: PROMPT_REVIEW_COVERAGE_KIND,
        complete,
        status: complete ? "comprehensive": "partial",
        evasionClasses: [
            EVASION_CLASSES.REVIEWER_MANIPULATION_AND_PROMPT_INJECTION,
        ],
        requiredNormalizedViewIds,
        coveredNormalizedViewIds,
        blockers,
        evasiveBlockerCodes,
        hashes: {
            basisSha256,
        },
    });
}

export function validatePromptReviewCoverage(
    value,
    inputs,
    path = "promptReviewCoverage",
) {
    objectShape(value, path, [
        "schemaVersion",
        "contractKind",
        "complete",
        "status",
        "evasionClasses",
        "requiredNormalizedViewIds",
        "coveredNormalizedViewIds",
        "blockers",
        "evasiveBlockerCodes",
        "hashes",
    ]);
    const expected = evaluatePromptReviewCoverage(inputs, `${path}.inputs`);
    if (canonicalJson(value) !== canonicalJson(expected)) {
        fail(path, "does not match deterministic structured review coverage");
    }
    return expected;
}

export const __internals = Object.freeze({
    SIGNAL_RULES,
    PROMPT_METADATA_KINDS,
    canonicalJson,
    hashDomain,
    tokenize,
    containsOrderedTokens,
});
