import nodePath from "node:path";

import { EVASION_CLASS_VALUES } from "../../analysis/assurance.mjs";
import { METAMORPHIC_TRANSFORMS } from "./metamorphicTransforms.mjs";

export const EXPECTATION_SCHEMA = "zerotrust-evaluation-expectation";
export const EXPECTATION_SCHEMA_REVISION = 1;

export const STAGES = Object.freeze([
    "acquired",
    "prepared",
    "scanned",
    "traced",
    "validated",
    "finalized",
]);
export const SEVERITIES = Object.freeze([
    "none",
    "info",
    "low",
    "medium",
    "high",
    "critical",
]);
export const CONFIDENCES = Object.freeze(["none", "low", "medium", "high"]);
export const PROJECT_FITS = Object.freeze([
    "none",
    "unknown",
    "unlikely",
    "ambiguous",
    "likely",
    "strong",
]);
export const FAILURE_STAGES = Object.freeze([
    "prepare",
    "scan",
    "trace",
    "validate",
    "finalize",
]);
export const ARTIFACT_CLASSES = Object.freeze([
    "source-text",
    "generated-source",
    "submodule",
    "lfs-pointer",
    "archive",
    "binary",
    "release-asset",
]);
export const LANGUAGE_CLASSES = Object.freeze([
    "javascript",
    "typescript",
    "json",
    "jsonc",
    "python",
    "powershell",
    "shell",
    "c",
    "cpp",
    "csharp",
    "msbuild",
    "rust",
    "yaml",
    "github-actions",
    "docker",
    "devcontainer",
    "cmake",
    "make",
    "go",
    "git",
    "markdown",
    "generic",
]);
export const SIZE_CLASSES = Object.freeze(["small", "medium", "large"]);

const TOKEN_RE = /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u;
const SLUG_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/u;

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, required, optional, label) {
    if (!isPlainObject(value)) throw new TypeError(`${label} must be an object`);
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) throw new TypeError(`${label}.${key} is not allowed`);
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
    }
}

function token(value, label) {
    const normalized = String(value || "").trim().toLowerCase();
    if (!TOKEN_RE.test(normalized)) throw new TypeError(`${label} must be a generic token`);
    return normalized;
}

function tokenList(value, label) {
    if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
    const normalized = value.map((entry, index) => token(entry, `${label}[${index}]`));
    if (new Set(normalized).size !== normalized.length) {
        throw new TypeError(`${label} must not contain duplicates`);
    }
    return normalized;
}

function boundedCount(value, label) {
    if (Number.isSafeInteger(value)) {
        if (value < 0) throw new TypeError(`${label} must be non-negative`);
        return { min: value, max: value };
    }
    exactKeys(value, ["min", "max"], [], label);
    if (!Number.isSafeInteger(value.min) || value.min < 0
        || !Number.isSafeInteger(value.max) || value.max < value.min) {
        throw new TypeError(`${label} must contain a valid min/max count`);
    }
    return { min: value.min, max: value.max };
}

function range(value, values, label) {
    exactKeys(value, ["min", "max"], [], label);
    if (!values.includes(value.min) || !values.includes(value.max)
        || values.indexOf(value.min) > values.indexOf(value.max)) {
        throw new TypeError(`${label} must contain an ordered min/max range`);
    }
    return { min: value.min, max: value.max };
}

function factExpectation(value, label) {
    exactKeys(value, ["required", "minimum"], [], label);
    if (!Number.isSafeInteger(value.minimum) || value.minimum < 0) {
        throw new TypeError(`${label}.minimum must be non-negative`);
    }
    return {
        required: tokenList(value.required, `${label}.required`),
        minimum: value.minimum,
    };
}

function source(value, label) {
    exactKeys(value, ["type"], ["path", "url"], label);
    if (!["local", "github"].includes(value.type)) {
        throw new TypeError(`${label}.type must be local or github`);
    }
    if (value.type === "local") {
        if (typeof value.path !== "string" || !value.path.trim()) {
            throw new TypeError(`${label}.path is required for local fixtures`);
        }
        const normalized = value.path.replace(/\\/gu, "/");
        if (nodePath.posix.isAbsolute(normalized)
            || normalized.split("/").some((segment) => segment === "..")) {
            throw new TypeError(`${label}.path must stay inside the corpus root`);
        }
        return { type: "local", path: normalized };
    }
    if (typeof value.url !== "string" || !value.url.startsWith("https://github.com/")) {
        throw new TypeError(`${label}.url must be a GitHub HTTPS URL`);
    }
    return { type: "github", url: value.url };
}

function allowedTokenList(value, allowed, label) {
    const normalized = tokenList(value, label);
    for (const entry of normalized) {
        if (!allowed.includes(entry)) {
            throw new TypeError(`${label} contains unsupported value: ${entry}`);
        }
    }
    return normalized;
}

function dimensions(value, label) {
    if (value === undefined) {
        return {
            evasion_classes: [],
            artifact_classes: [],
            languages: [],
            size: null,
            known_coverage_blockers: false,
            metamorphic_transforms: [],
        };
    }
    exactKeys(value, [
        "evasion_classes",
        "artifact_classes",
        "languages",
        "size",
    ], [
        "known_coverage_blockers",
        "metamorphic_transforms",
    ], label);
    if (!SIZE_CLASSES.includes(value.size)) {
        throw new TypeError(`${label}.size must be small, medium, or large`);
    }
    if (Object.hasOwn(value, "known_coverage_blockers")
        && typeof value.known_coverage_blockers !== "boolean") {
        throw new TypeError(`${label}.known_coverage_blockers must be boolean`);
    }
    return {
        evasion_classes: allowedTokenList(
            value.evasion_classes,
            EVASION_CLASS_VALUES,
            `${label}.evasion_classes`,
        ),
        artifact_classes: allowedTokenList(
            value.artifact_classes,
            ARTIFACT_CLASSES,
            `${label}.artifact_classes`,
        ),
        languages: allowedTokenList(
            value.languages,
            LANGUAGE_CLASSES,
            `${label}.languages`,
        ),
        size: value.size,
        known_coverage_blockers: value.known_coverage_blockers === true,
        metamorphic_transforms: allowedTokenList(
            value.metamorphic_transforms || [],
            METAMORPHIC_TRANSFORMS,
            `${label}.metamorphic_transforms`,
        ),
    };
}

export function validateExpectation(value, label = "expectation") {
    exactKeys(value, [
        "schema",
        "schema_version",
        "slug",
        "kind",
        "source",
        "expected",
    ], ["notes", "dimensions"], label);
    if (value.schema !== EXPECTATION_SCHEMA
        || value.schema_version !== EXPECTATION_SCHEMA_REVISION) {
        throw new TypeError(`${label} must use ${EXPECTATION_SCHEMA}`);
    }
    const slug = String(value.slug || "").trim().toLowerCase();
    if (!SLUG_RE.test(slug)) throw new TypeError(`${label}.slug is invalid`);
    const normalizedSource = source(value.source, `${label}.source`);
    const expected = value.expected;
    exactKeys(expected, [
        "stage",
        "activation_facts",
        "plugin_facts",
        "counts",
        "chains",
        "scores",
        "tags",
        "acceptable_blockers",
        "failure_stage",
    ], [], `${label}.expected`);

    exactKeys(expected.stage, ["required", "final"], [], `${label}.expected.stage`);
    const requiredStages = expected.stage.required.map((stage, index) => {
        if (!STAGES.includes(stage)) {
            throw new TypeError(`${label}.expected.stage.required[${index}] is invalid`);
        }
        return stage;
    });
    if (new Set(requiredStages).size !== requiredStages.length) {
        throw new TypeError(`${label}.expected.stage.required must not contain duplicates`);
    }
    if (!STAGES.includes(expected.stage.final)) {
        throw new TypeError(`${label}.expected.stage.final is invalid`);
    }

    exactKeys(expected.counts, [
        "candidate",
        "validated",
        "refuted",
        "unresolved",
    ], [], `${label}.expected.counts`);

    exactKeys(expected.chains, [
        "required",
        "complete_required",
        "forbidden",
    ], [], `${label}.expected.chains`);

    exactKeys(expected.scores, [
        "severity",
        "confidence",
        "project_fit",
    ], [], `${label}.expected.scores`);

    exactKeys(expected.tags, ["required", "forbidden"], [], `${label}.expected.tags`);
    const failureStage = expected.failure_stage;
    if (failureStage !== null && !FAILURE_STAGES.includes(failureStage)) {
        throw new TypeError(`${label}.expected.failure_stage is invalid`);
    }

    return Object.freeze(structuredClone({
        schema: EXPECTATION_SCHEMA,
        schema_version: EXPECTATION_SCHEMA_REVISION,
        slug,
        kind: token(value.kind, `${label}.kind`),
        source: normalizedSource,
        dimensions: dimensions(value.dimensions, `${label}.dimensions`),
        expected: {
            stage: {
                required: requiredStages,
                final: expected.stage.final,
            },
            activation_facts: factExpectation(
                expected.activation_facts,
                `${label}.expected.activation_facts`,
            ),
            plugin_facts: factExpectation(
                expected.plugin_facts,
                `${label}.expected.plugin_facts`,
            ),
            counts: Object.fromEntries(
                ["candidate", "validated", "refuted", "unresolved"].map((key) => [
                    key,
                    boundedCount(expected.counts[key], `${label}.expected.counts.${key}`),
                ]),
            ),
            chains: {
                required: tokenList(
                    expected.chains.required,
                    `${label}.expected.chains.required`,
                ),
                complete_required: tokenList(
                    expected.chains.complete_required,
                    `${label}.expected.chains.complete_required`,
                ),
                forbidden: tokenList(
                    expected.chains.forbidden,
                    `${label}.expected.chains.forbidden`,
                ),
            },
            scores: {
                severity: range(
                    expected.scores.severity,
                    SEVERITIES,
                    `${label}.expected.scores.severity`,
                ),
                confidence: range(
                    expected.scores.confidence,
                    CONFIDENCES,
                    `${label}.expected.scores.confidence`,
                ),
                project_fit: range(
                    expected.scores.project_fit,
                    PROJECT_FITS,
                    `${label}.expected.scores.project_fit`,
                ),
            },
            tags: {
                required: tokenList(
                    expected.tags.required,
                    `${label}.expected.tags.required`,
                ),
                forbidden: tokenList(
                    expected.tags.forbidden,
                    `${label}.expected.tags.forbidden`,
                ),
            },
            acceptable_blockers: tokenList(
                expected.acceptable_blockers,
                `${label}.expected.acceptable_blockers`,
            ),
            failure_stage: failureStage,
        },
        ...(typeof value.notes === "string" ? { notes: value.notes.trim() }: {}),
    }));
}

export const __internals = Object.freeze({
    isPlainObject,
    exactKeys,
    token,
    tokenList,
    boundedCount,
    range,
    factExpectation,
    source,
    allowedTokenList,
    dimensions,
});
