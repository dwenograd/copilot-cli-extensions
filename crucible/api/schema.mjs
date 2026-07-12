// crucible/api/schema.mjs
//
// Single-source declarative schema/spec builder for the Crucible four-tool
// API. Each field is described ONCE as a small descriptor that knows how to
// (a) emit a Copilot JSON Schema fragment and (b) parse + normalize a runtime
// value. Tool argument objects compose those descriptors, so the JSON Schema
// advertised to Copilot and the runtime parser can never drift apart — there
// is no hand-maintained duplicate JSON Schema or Zod schema anywhere.
//
// This module imports only pure domain/runtime constants and the API's own
// typed error. It never touches I/O.

import {
    CONTRACT_LIMITS,
    DEFAULT_SEARCH_POLICY,
    GOAL_MODES,
    HYPOTHESIS_TOPOLOGIES,
    MISSINGNESS_MODES,
    SEARCH_POLICY_LIMITS,
    STATISTICAL_METRIC_DIRECTIONS,
    STATISTICAL_POLICY_VERSION,
} from "../domain/constants.mjs";
import {
    HYPOTHESIS_LIMITS,
    PREDICTION_KINDS,
} from "../domain/hypotheses.mjs";
import { STRICT_ISO_TIMESTAMP_PATTERN_SOURCE } from "../runtime/config-validation.mjs";
import { SchemaValidationError } from "./errors.mjs";

// Re-exported so the schema module's public surface includes the error its
// parser throws (callers/tests import it from here, the single source).
export { SchemaValidationError };
export { DEFAULT_SEARCH_POLICY };

export const MAX_OBJECTIVE_CHARACTERS = CONTRACT_LIMITS.objectiveCharacters;
export const MAX_OBJECTIVE_BYTES = CONTRACT_LIMITS.objectiveBytes;
export const MAX_ACCEPTANCE_PREDICATE_BYTES =
    CONTRACT_LIMITS.acceptancePredicateBytes;

const IDENTIFIER_PATTERN = "^(?!.*\\.\\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$";
const IDENTIFIER_RE = /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;
const LOWER_IDENTIFIER_PATTERN = "^(?!.*\\.\\.)[a-z0-9][a-z0-9._-]{0,127}$";
const LOWER_IDENTIFIER_RE = /^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$/u;

function fail(pathLabel, message, extra = {}) {
    throw new SchemaValidationError(`${pathLabel}: ${message}`, { path: pathLabel, ...extra });
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function cloneDefault(value) {
    return value === undefined ? undefined : structuredClone(value);
}

// --- field descriptors -----------------------------------------------------
//
// A descriptor is `{ jsonSchema, optional, hasDefault, defaultValue, parse }`.
// `parse(value, pathLabel)` returns the normalized value or throws.

function makeField({ jsonSchema, parse, optional = false, hasDefault = false, defaultValue = undefined }) {
    return Object.freeze({ jsonSchema, parse, optional, hasDefault, defaultValue });
}

function commonOptions(base, { description } = {}) {
    return description === undefined ? base : { ...base, description };
}

export function string({
    description,
    minLength = 1,
    maxLength = 4096,
    maxBytes = Number.MAX_SAFE_INTEGER,
    pattern,
    format,
    optional = false,
    default: defaultValue,
} = {}) {
    const jsonSchema = commonOptions(
        {
            type: "string",
            minLength,
            maxLength,
            ...(pattern === undefined ? {} : { pattern }),
            ...(format === undefined ? {} : { format }),
        },
        { description },
    );
    const compiled = pattern === undefined ? null : new RegExp(pattern, "u");
    return makeField({
        jsonSchema,
        optional,
        hasDefault: defaultValue !== undefined,
        defaultValue: cloneDefault(defaultValue),
        parse(value, pathLabel) {
            if (typeof value !== "string") {
                fail(pathLabel, "must be a string");
            }
            if (value.length < minLength || value.length > maxLength) {
                fail(pathLabel, `must be ${minLength}..${maxLength} characters`);
            }
            const bytes = Buffer.byteLength(value, "utf8");
            if (bytes > maxBytes) {
                fail(pathLabel, `must be at most ${maxBytes} UTF-8 bytes`, {
                    bytes,
                    maxBytes,
                });
            }
            if (compiled !== null && !compiled.test(value)) {
                fail(pathLabel, `must match ${pattern}`);
            }
            return value;
        },
    });
}

export function identifier({ description, optional = false } = {}) {
    return makeField({
        jsonSchema: commonOptions(
            { type: "string", minLength: 1, maxLength: 128, pattern: IDENTIFIER_PATTERN },
            { description },
        ),
        optional,
        parse(value, pathLabel) {
            if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
                fail(pathLabel, "must be a safe identifier (not a filesystem path)");
            }
            return value;
        },
    });
}

export function lowerIdentifier({ description, optional = false } = {}) {
    return makeField({
        jsonSchema: commonOptions(
            { type: "string", minLength: 1, maxLength: 128, pattern: LOWER_IDENTIFIER_PATTERN },
            { description },
        ),
        optional,
        parse(value, pathLabel) {
            if (typeof value !== "string" || !LOWER_IDENTIFIER_RE.test(value)) {
                fail(pathLabel, "must be a lowercase safe identifier (not a filesystem path)");
            }
            return value;
        },
    });
}

export function enumField(values, {
    description,
    optional = false,
    default: defaultValue,
} = {}) {
    const allowed = Object.freeze([...values]);
    return makeField({
        jsonSchema: commonOptions({ type: "string", enum: allowed }, { description }),
        optional,
        hasDefault: defaultValue !== undefined,
        defaultValue,
        parse(value, pathLabel) {
            if (typeof value !== "string" || !allowed.includes(value)) {
                fail(pathLabel, `must be one of ${allowed.join(", ")}`);
            }
            return value;
        },
    });
}

export function integer({
    description,
    minimum,
    maximum,
    optional = false,
    default: defaultValue,
} = {}) {
    const jsonSchema = commonOptions(
        {
            type: "integer",
            ...(minimum === undefined ? {} : { minimum }),
            ...(maximum === undefined ? {} : { maximum }),
        },
        { description },
    );
    return makeField({
        jsonSchema,
        optional,
        hasDefault: defaultValue !== undefined,
        defaultValue,
        parse(value, pathLabel) {
            if (!Number.isSafeInteger(value)) {
                fail(pathLabel, "must be a safe integer");
            }
            if (minimum !== undefined && value < minimum) {
                fail(pathLabel, `must be >= ${minimum}`);
            }
            if (maximum !== undefined && value > maximum) {
                fail(pathLabel, `must be <= ${maximum}`);
            }
            return value;
        },
    });
}

export function number({
    description,
    minimum,
    maximum,
    optional = false,
    default: defaultValue,
} = {}) {
    const jsonSchema = commonOptions(
        {
            type: "number",
            ...(minimum === undefined ? {} : { minimum }),
            ...(maximum === undefined ? {} : { maximum }),
        },
        { description },
    );
    return makeField({
        jsonSchema,
        optional,
        hasDefault: defaultValue !== undefined,
        defaultValue,
        parse(value, pathLabel) {
            if (typeof value !== "number" || !Number.isFinite(value)) {
                fail(pathLabel, "must be a finite number");
            }
            if (minimum !== undefined && value < minimum) {
                fail(pathLabel, `must be >= ${minimum}`);
            }
            if (maximum !== undefined && value > maximum) {
                fail(pathLabel, `must be <= ${maximum}`);
            }
            return value;
        },
    });
}

export function boolean({ description, optional = false, default: defaultValue } = {}) {
    return makeField({
        jsonSchema: commonOptions({ type: "boolean" }, { description }),
        optional,
        hasDefault: defaultValue !== undefined,
        defaultValue,
        parse(value, pathLabel) {
            if (typeof value !== "boolean") {
                fail(pathLabel, "must be a boolean");
            }
            return value;
        },
    });
}

export function array(item, {
    description,
    minItems,
    maxItems,
    uniqueItems = false,
    uniqueBy,
    optional = false,
    default: defaultValue,
} = {}) {
    const jsonSchema = commonOptions(
        {
            type: "array",
            items: item.jsonSchema,
            ...(minItems === undefined ? {} : { minItems }),
            ...(maxItems === undefined ? {} : { maxItems }),
            ...(uniqueItems || uniqueBy !== undefined ? { uniqueItems: true } : {}),
        },
        { description },
    );
    return makeField({
        jsonSchema,
        optional,
        hasDefault: defaultValue !== undefined,
        defaultValue: cloneDefault(defaultValue),
        parse(value, pathLabel) {
            if (!Array.isArray(value)) {
                fail(pathLabel, "must be an array");
            }
            if (minItems !== undefined && value.length < minItems) {
                fail(pathLabel, `must contain at least ${minItems} item(s)`);
            }
            if (maxItems !== undefined && value.length > maxItems) {
                fail(pathLabel, `must contain at most ${maxItems} item(s)`);
            }
            const parsed = value.map((entry, index) => item.parse(entry, `${pathLabel}[${index}]`));
            if (uniqueItems || uniqueBy !== undefined) {
                const seen = new Set();
                for (let index = 0; index < parsed.length; index += 1) {
                    const key = uniqueBy === undefined
                        ? JSON.stringify(parsed[index])
                        : parsed[index]?.[uniqueBy];
                    if (seen.has(key)) {
                        fail(
                            `${pathLabel}[${index}]`,
                            uniqueBy === undefined
                                ? "must be unique"
                                : `${uniqueBy} must be unique`,
                        );
                    }
                    seen.add(key);
                }
            }
            return parsed;
        },
    });
}

// Passthrough object field: shape is validated by a downstream domain
// normalizer (e.g. the acceptance-predicate grammar), so the JSON Schema only
// asserts "an object" and the parser only guards against non-objects and
// prototype pollution. The single source of truth for the nested shape stays
// in the domain, not duplicated here.
export function rawObject({
    description,
    optional = false,
    maxBytes = Number.MAX_SAFE_INTEGER,
} = {}) {
    return makeField({
        jsonSchema: commonOptions({ type: "object", additionalProperties: true }, { description }),
        optional,
        parse(value, pathLabel) {
            if (!isPlainObject(value)) {
                fail(pathLabel, "must be a JSON object");
            }
            let bytes;
            try {
                bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
            } catch {
                fail(pathLabel, "must be JSON-serializable");
            }
            if (bytes > maxBytes) {
                fail(pathLabel, `must serialize to at most ${maxBytes} UTF-8 bytes`, {
                    bytes,
                    maxBytes,
                });
            }
            return value;
        },
    });
}

// Compose a set of named field descriptors into an object descriptor that
// yields BOTH a strict Copilot JSON Schema and a runtime parser.
export function object(fields, {
    description,
    optional = false,
    default: defaultValue,
} = {}) {
    const entries = Object.entries(fields);

    function toJsonSchema() {
        const properties = {};
        const required = [];
        for (const [name, field] of entries) {
            properties[name] = field.jsonSchema;
            if (!field.optional && !field.hasDefault) {
                required.push(name);
            }
        }
        return {
            type: "object",
            additionalProperties: false,
            ...(description === undefined ? {} : { description }),
            properties,
            required,
        };
    }

    function parse(rawArgs, pathLabel = "args") {
        if (!isPlainObject(rawArgs)) {
            fail(pathLabel, "must be a JSON object");
        }
        const known = new Set(entries.map(([name]) => name));
        for (const key of Object.keys(rawArgs)) {
            if (!known.has(key)) {
                fail(`${pathLabel}.${key}`, "is not a recognized argument");
            }
        }
        const out = {};
        for (const [name, field] of entries) {
            const present = Object.hasOwn(rawArgs, name) && rawArgs[name] !== undefined;
            if (present) {
                out[name] = field.parse(rawArgs[name], `${pathLabel}.${name}`);
            } else if (field.hasDefault) {
                out[name] = cloneDefault(field.defaultValue);
            } else if (!field.optional) {
                fail(`${pathLabel}.${name}`, "is required");
            }
        }
        return out;
    }

    return Object.freeze({
        entries,
        toJsonSchema,
        jsonSchema: toJsonSchema(),
        optional,
        hasDefault: defaultValue !== undefined,
        defaultValue: cloneDefault(defaultValue),
        parse,
    });
}

// A tool spec is the single source for one Copilot tool: name + description +
// derived JSON Schema (`parameters`) + derived `parse`.
export function defineTool({ name, description, args }) {
    return Object.freeze({
        name,
        description,
        args,
        parameters: args.toJsonSchema(),
        parse(rawArgs) {
            return args.parse(rawArgs);
        },
    });
}

function discriminatedObjectUnion({
    discriminant,
    present,
    absent,
    description,
}) {
    const mergedProperties = {
        ...absent.jsonSchema.properties,
        ...present.jsonSchema.properties,
    };
    const jsonSchema = {
        type: "object",
        additionalProperties: false,
        ...(description === undefined ? {} : { description }),
        properties: mergedProperties,
        required: [],
        oneOf: [
            absent.jsonSchema,
            present.jsonSchema,
        ],
    };
    return Object.freeze({
        jsonSchema,
        toJsonSchema: () => structuredClone(jsonSchema),
        parse(rawArgs, pathLabel = "args") {
            if (!isPlainObject(rawArgs)) {
                fail(pathLabel, "must be a JSON object");
            }
            return Object.hasOwn(rawArgs, discriminant)
                ? present.parse(rawArgs, pathLabel)
                : absent.parse(rawArgs, pathLabel);
        },
    });
}

// --- the four public tool specs -------------------------------------------

const searchPolicyShape = object({
    plateauWindow: integer({
        description: "Consecutive completed non-improving rounds required to detect a plateau.",
        minimum: 1,
        maximum: SEARCH_POLICY_LIMITS.plateauWindow,
        default: DEFAULT_SEARCH_POLICY.plateauWindow,
    }),
    minRoundsBeforePlateau: integer({
        description: "Minimum completed rounds before plateau detection is permitted.",
        minimum: 1,
        maximum: SEARCH_POLICY_LIMITS.minRoundsBeforePlateau,
        default: DEFAULT_SEARCH_POLICY.minRoundsBeforePlateau,
    }),
    plateauMinImprovement: number({
        description: "Minimum primary ranking-metric improvement that resets plateau detection.",
        minimum: 0,
        maximum: Number.MAX_SAFE_INTEGER,
        default: DEFAULT_SEARCH_POLICY.plateauMinImprovement,
    }),
    mandatoryEscapeRounds: integer({
        description: "Full escape-phase rounds required after plateau detection.",
        minimum: 1,
        maximum: SEARCH_POLICY_LIMITS.mandatoryEscapeRounds,
        default: DEFAULT_SEARCH_POLICY.mandatoryEscapeRounds,
    }),
    operatorWeights: object({
        fresh: integer({ minimum: 0, maximum: 1000000, default: DEFAULT_SEARCH_POLICY.operatorWeights.fresh }),
        refinement: integer({ minimum: 0, maximum: 1000000, default: DEFAULT_SEARCH_POLICY.operatorWeights.refinement }),
        crossover: integer({ minimum: 0, maximum: 1000000, default: DEFAULT_SEARCH_POLICY.operatorWeights.crossover }),
        diversification: integer({ minimum: 0, maximum: 1000000, default: DEFAULT_SEARCH_POLICY.operatorWeights.diversification }),
        adversarial: integer({ minimum: 0, maximum: 1000000, default: DEFAULT_SEARCH_POLICY.operatorWeights.adversarial }),
        restart: integer({ minimum: 0, maximum: 1000000, default: DEFAULT_SEARCH_POLICY.operatorWeights.restart }),
    }, { default: DEFAULT_SEARCH_POLICY.operatorWeights }),
    archiveCaps: object({
        accepted: integer({ minimum: 1, maximum: SEARCH_POLICY_LIMITS.archiveCaps.accepted, default: DEFAULT_SEARCH_POLICY.archiveCaps.accepted }),
        nearMisses: integer({ minimum: 1, maximum: SEARCH_POLICY_LIMITS.archiveCaps.nearMisses, default: DEFAULT_SEARCH_POLICY.archiveCaps.nearMisses }),
        rejected: integer({ minimum: 1, maximum: SEARCH_POLICY_LIMITS.archiveCaps.rejected, default: DEFAULT_SEARCH_POLICY.archiveCaps.rejected }),
        invalidMetrics: integer({ minimum: 1, maximum: SEARCH_POLICY_LIMITS.archiveCaps.invalidMetrics, default: DEFAULT_SEARCH_POLICY.archiveCaps.invalidMetrics }),
        mechanismGroups: integer({ minimum: 1, maximum: SEARCH_POLICY_LIMITS.archiveCaps.mechanismGroups, default: DEFAULT_SEARCH_POLICY.archiveCaps.mechanismGroups }),
        lessonGroups: integer({ minimum: 1, maximum: SEARCH_POLICY_LIMITS.archiveCaps.lessonGroups, default: DEFAULT_SEARCH_POLICY.archiveCaps.lessonGroups }),
        duplicateIndex: integer({ minimum: 1, maximum: SEARCH_POLICY_LIMITS.archiveCaps.duplicateIndex, default: DEFAULT_SEARCH_POLICY.archiveCaps.duplicateIndex }),
    }, { default: DEFAULT_SEARCH_POLICY.archiveCaps }),
    promptCaps: object({
        parentEvidenceIds: integer({
            minimum: 1,
            maximum: SEARCH_POLICY_LIMITS.promptCaps.parentEvidenceIds,
            default: DEFAULT_SEARCH_POLICY.promptCaps.parentEvidenceIds,
        }),
        promptContextRefs: integer({
            minimum: 1,
            maximum: SEARCH_POLICY_LIMITS.promptCaps.promptContextRefs,
            default: DEFAULT_SEARCH_POLICY.promptCaps.promptContextRefs,
        }),
    }, { default: DEFAULT_SEARCH_POLICY.promptCaps }),
    dedupPolicy: enumField(["mark"], {
        description: "Duplicate candidate artifacts are committed and linked, never silently dropped.",
        default: "mark",
    }),
});

const searchPolicyField = makeField({
    jsonSchema: searchPolicyShape.jsonSchema,
    hasDefault: true,
    defaultValue: DEFAULT_SEARCH_POLICY,
    parse(value, pathLabel) {
        const parsed = searchPolicyShape.parse(value, pathLabel);
        if (parsed.minRoundsBeforePlateau < parsed.plateauWindow) {
            fail(
                `${pathLabel}.minRoundsBeforePlateau`,
                "must be at least plateauWindow",
            );
        }
        if (parsed.operatorWeights.fresh < 1) {
            fail(`${pathLabel}.operatorWeights.fresh`, "must be at least 1");
        }
        if (parsed.operatorWeights.diversification
            + parsed.operatorWeights.adversarial
            + parsed.operatorWeights.restart < 1) {
            fail(
                `${pathLabel}.operatorWeights`,
                "must enable at least one mandatory-escape operator",
            );
        }
        if (parsed.promptCaps.parentEvidenceIds > parsed.promptCaps.promptContextRefs) {
            fail(
                `${pathLabel}.promptCaps.parentEvidenceIds`,
                "cannot exceed promptContextRefs",
            );
        }
        return parsed;
    },
});

const investigationIdField = identifier({
    description:
        "The investigationId returned by crucible_start. Deterministic v4-namespaced slug + SHA-256 suffix; resolves to local state under the Crucible state root.",
});
const experimentIdField = lowerIdentifier({
    description:
        "An operator-preapproved experiment id from the local Crucible experiment registry.",
});

function jsonValueField({ description, arrayOnly = false } = {}) {
    return makeField({
        jsonSchema: commonOptions(arrayOnly ? { type: "array" } : {}, { description }),
        parse(value, pathLabel) {
            if (arrayOnly && !Array.isArray(value)) {
                fail(pathLabel, "must be an array");
            }
            let encoded;
            try {
                encoded = JSON.stringify(value);
            } catch {
                fail(pathLabel, "must be JSON-serializable");
            }
            if (encoded === undefined) {
                fail(pathLabel, "must be a JSON value");
            }
            return structuredClone(value);
        },
    });
}

function taggedHashField({ description } = {}) {
    return string({
        description,
        maxLength: 256,
        pattern: "^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$",
    });
}

function snapshotHashField({ description } = {}) {
    return string({
        description,
        maxLength: 71,
        pattern: "^sha256:[a-f0-9]{64}$",
    });
}

function discriminatedField(discriminant, alternatives, description) {
    const byValue = new Map(alternatives.map((item) => [item.value, item.shape]));
    const jsonSchema = {
        oneOf: alternatives.map((item) => item.shape.jsonSchema),
        ...(description === undefined ? {} : { description }),
    };
    return makeField({
        jsonSchema,
        parse(value, pathLabel) {
            if (!isPlainObject(value)) {
                fail(pathLabel, "must be a JSON object");
            }
            const selected = byValue.get(value[discriminant]);
            if (selected === undefined) {
                fail(
                    `${pathLabel}.${discriminant}`,
                    `must be one of ${[...byValue.keys()].join(", ")}`,
                );
            }
            return selected.parse(value, pathLabel);
        },
    });
}

const categoricalValueField = makeField({
    jsonSchema: {
        oneOf: [
            { type: "string", minLength: 1, maxLength: HYPOTHESIS_LIMITS.categoryCharacters },
            { type: "boolean" },
        ],
    },
    parse(value, pathLabel) {
        if (typeof value === "boolean") return value;
        if (typeof value !== "string"
            || value.length < 1
            || value.length > HYPOTHESIS_LIMITS.categoryCharacters) {
            fail(pathLabel, "must be a bounded string or boolean");
        }
        return value;
    },
});

const observableRegistryItem = discriminatedField("kind", [
    {
        value: "numeric",
        shape: object({
            key: identifier(),
            kind: enumField(["numeric"]),
            minimum: number(),
            maximum: number(),
        }),
    },
    {
        value: "categorical",
        shape: object({
            key: identifier(),
            kind: enumField(["categorical"]),
            values: array(categoricalValueField, {
                minItems: 1,
                maxItems: HYPOTHESIS_LIMITS.maxCategoriesPerObservable,
                uniqueItems: true,
            }),
        }),
    },
], "Frozen observables available to preregistered worker predictions.");

const observableRegistryField = array(observableRegistryItem, {
    minItems: 1,
    maxItems: HYPOTHESIS_LIMITS.maxObservableRegistryEntries,
    uniqueBy: "key",
});

const hypothesisPolicyField = object({
    required: boolean(),
    maxPredictions: integer({
        minimum: 1,
        maximum: HYPOTHESIS_LIMITS.maxPredictions,
    }),
    allowedKinds: array(enumField(PREDICTION_KINDS), {
        minItems: 1,
        maxItems: PREDICTION_KINDS.length,
        uniqueItems: true,
    }),
    allowRequiredForResult: boolean(),
});

const finiteEnumerandEntry = object({
    id: identifier(),
    ordinal: integer({
        minimum: 0,
        maximum: CONTRACT_LIMITS.boundedCandidateIds - 1,
    }),
    artifactSnapshotHash: snapshotHashField({
        description:
            "Snapshot already present in the durable operator case/enumerand store; preflight verifies and stages it.",
    }),
    hypotheses: rawObject({
        description:
            "Optional operator-frozen typed hypotheses for this enumerand. Required on every enumerand when hypothesis_policy.required is true.",
        optional: true,
        maxBytes: HYPOTHESIS_LIMITS.hypothesesBytes,
    }),
});

const boundedEnumerandEntry = object({
    id: identifier(),
    ordinal: integer({
        minimum: 0,
        maximum: CONTRACT_LIMITS.boundedCandidateIds - 1,
    }),
    parameterTuple: jsonValueField({
        description: "Canonical finite parameter tuple for this enumerand.",
        arrayOnly: true,
    }),
    hypotheses: rawObject({
        description:
            "Optional operator-frozen typed hypotheses for this enumerand. Required on every enumerand when hypothesis_policy.required is true.",
        optional: true,
        maxBytes: HYPOTHESIS_LIMITS.hypothesesBytes,
    }),
});

const manifestControlField = discriminatedField("kind", [
    {
        value: "enumerand",
        shape: object({
            kind: enumField(["enumerand"]),
            ordinal: integer({
                minimum: 0,
                maximum: CONTRACT_LIMITS.boundedCandidateIds - 1,
            }),
        }),
    },
    {
        value: "snapshot",
        shape: object({
            kind: enumField(["snapshot"]),
            snapshotHash: snapshotHashField(),
        }),
    },
], "A frozen enumerand or durable operator-owned snapshot control.");

const finiteEnumerandManifestShape = object({
    topology: enumField(["finite_enumerable"]),
    entries: array(finiteEnumerandEntry, {
        minItems: 1,
        maxItems: CONTRACT_LIMITS.boundedCandidateIds,
        uniqueBy: "id",
    }),
    control: manifestControlField,
});

const boundedEnumerandManifestShape = object({
    topology: enumField(["bounded_parameterized"]),
    entries: array(boundedEnumerandEntry, {
        minItems: 1,
        maxItems: CONTRACT_LIMITS.boundedCandidateIds,
        uniqueBy: "id",
    }),
    control: manifestControlField,
});

const enumerandManifestField = discriminatedField("topology", [
    { value: "finite_enumerable", shape: finiteEnumerandManifestShape },
    { value: "bounded_parameterized", shape: boundedEnumerandManifestShape },
], "Complete immutable enumerand manifest. Labels-only candidate-id lists are forbidden.");
const optionalEnumerandManifestField = makeField({
    ...enumerandManifestField,
    optional: true,
});

const statisticalMetricShape = object({
    key: identifier(),
    minimum: number(),
    maximum: number(),
    estimand: string({ maxLength: 256, maxBytes: 512 }),
    unit: string({ maxLength: 128, maxBytes: 256 }),
    direction: enumField(STATISTICAL_METRIC_DIRECTIONS),
    acceptanceThreshold: number(),
    practicalEquivalenceDelta: number({ minimum: Number.MIN_VALUE }),
    family: identifier(),
});

const familyAllocationShape = object({
    family: identifier(),
    alpha: number({ minimum: Number.MIN_VALUE, maximum: 1 }),
});

const controlToleranceShape = object({
    metric: identifier(),
    absolute: number({ minimum: 0 }),
    relative: number({ minimum: 0, maximum: 1 }),
});

const statisticalControlField = discriminatedField("kind", [
    {
        value: "enumerand",
        shape: object({
            kind: enumField(["enumerand"]),
            tolerances: array(controlToleranceShape, {
                minItems: 1,
                maxItems: CONTRACT_LIMITS.metrics,
                uniqueBy: "metric",
            }),
        }),
    },
    {
        value: "snapshot",
        shape: object({
            kind: enumField(["snapshot"]),
            identity: snapshotHashField(),
            tolerances: array(controlToleranceShape, {
                minItems: 1,
                maxItems: CONTRACT_LIMITS.metrics,
                uniqueBy: "metric",
            }),
        }),
    },
], "Control identity and per-metric drift tolerances.");

const statisticalPolicyField = object({
    version: enumField([STATISTICAL_POLICY_VERSION]),
    goalMode: enumField(GOAL_MODES),
    metrics: array(statisticalMetricShape, {
        minItems: 1,
        maxItems: CONTRACT_LIMITS.metrics,
        uniqueBy: "key",
    }),
    investigationAlpha: number({
        minimum: Number.MIN_VALUE,
        maximum: 1 - Number.EPSILON,
    }),
    familyAllocations: array(familyAllocationShape, {
        minItems: 1,
        maxItems: CONTRACT_LIMITS.statisticalFamilies,
        uniqueBy: "family",
    }),
    minBlocks: integer({ minimum: 1, maximum: CONTRACT_LIMITS.maxBlocks }),
    maxBlocks: integer({ minimum: 1, maximum: CONTRACT_LIMITS.maxBlocks }),
    control: statisticalControlField,
    missingness: object({
        mode: enumField(MISSINGNESS_MODES),
        maxMissingPerBlock: integer({
            minimum: 0,
            maximum: CONTRACT_LIMITS.maxStatisticalEvaluations,
        }),
        maxMissingFraction: number({ minimum: 0, maximum: 1 }),
    }),
    deterministicBlockSeed: string({ maxLength: 256, maxBytes: 512 }),
    maxConfirmations: integer({
        minimum: 1,
        maximum: CONTRACT_LIMITS.maxConfirmations,
    }),
    evaluationBudget: object({
        maxCandidateEvaluations: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxStatisticalEvaluations,
        }),
        maxControlEvaluations: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxStatisticalEvaluations,
        }),
        maxTotalEvaluations: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxStatisticalEvaluations,
        }),
    }),
    resourceBudget: object({
        perAttemptOutputBytes: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxResourceBytes,
        }),
        perInvestigationOutputBytes: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxResourceBytes,
        }),
        perAttemptReceiptBytes: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxResourceBytes,
        }),
        perInvestigationReceiptBytes: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxResourceBytes,
        }),
        perAttemptCasBytes: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxResourceBytes,
        }),
        perInvestigationCasBytes: integer({
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxResourceBytes,
        }),
    }),
});

const operatorExperimentConfigShape = object({
        experiment_id: experimentIdField,
        objective: string({
            description: "The falsifiable objective under investigation. Part of the deterministic investigationId.",
            maxLength: MAX_OBJECTIVE_CHARACTERS,
            maxBytes: MAX_OBJECTIVE_BYTES,
        }),
        project_dir: string({
            description: "Absolute local project directory identifying the investigation scope. Part of the deterministic investigationId.",
            maxLength: 32767,
        }),
        harness_suite_id: lowerIdentifier({
            description:
                "Id of an operator-owned durable HarnessSuiteV4. Preflight freezes its complete suite identity and role corpus.",
        }),
        harness_suite_identity: string({
            description:
                "Optional expected HarnessSuiteV4 identity. Configuration fails if the allowlisted suite does not match it.",
            maxLength: 256,
            pattern: "^sha256:crucible-harness-suite-v4:[a-f0-9]{64}$",
            optional: true,
        }),
        acceptance_predicate: rawObject({
            description: "Acceptance-predicate grammar object (harness_pass / metric_compare / field_equals / all / any / not ...). Validated by the domain contract.",
            maxBytes: MAX_ACCEPTANCE_PREDICATE_BYTES,
        }),
        hypothesis_topology: enumField(HYPOTHESIS_TOPOLOGIES, {
            description:
                "Search topology. Finite/bounded starts require enumerand_manifest. Open generative is non-exhaustible. Certified impossibility additionally requires the suite verifier role.",
        }),
        enumerand_manifest: optionalEnumerandManifestField,
        observable_registry: observableRegistryField,
        hypothesis_policy: hypothesisPolicyField,
        statistical_policy: statisticalPolicyField,
        worker_models: array(
            identifier({ description: "A proposer/worker model id." }),
            {
                description: "1..8 distinct worker model ids used to propose candidates.",
                minItems: 1,
                maxItems: CONTRACT_LIMITS.workerModels,
                uniqueItems: true,
            },
        ),
        candidates_per_round: integer({
            description: "Candidates generated per search round (1..8).",
            minimum: 1,
            maximum: CONTRACT_LIMITS.candidatesPerRound,
        }),
        max_rounds: integer({
            description:
                "Maximum number of frozen search rounds (>= 1). For certified_impossibility, verification is eligible only after all slots in these rounds have qualifying non-invalidated candidate evidence.",
            minimum: 1,
            maximum: CONTRACT_LIMITS.maxRounds,
        }),
        search_policy: searchPolicyField,
    });

const BOUNDED_HYPOTHESIS_TOPOLOGIES = Object.freeze([
    "finite_enumerable",
    "bounded_parameterized",
]);
const boundedTopologySchemaRule = Object.freeze({
    if: {
        properties: {
            hypothesis_topology: { enum: BOUNDED_HYPOTHESIS_TOPOLOGIES },
        },
        required: ["hypothesis_topology"],
    },
    then: { required: ["enumerand_manifest"] },
    else: { not: { required: ["enumerand_manifest"] } },
});
const operatorExperimentConfigSchema = Object.freeze({
    ...operatorExperimentConfigShape.jsonSchema,
    allOf: [boundedTopologySchemaRule],
});
export const operatorExperimentConfigSpec = Object.freeze({
    name: "configure_experiment",
    description:
        "Strict operator-only authoring schema for a preapproved Crucible v4 experiment.",
    parameters: structuredClone(operatorExperimentConfigSchema),
    parse(rawArgs) {
        return operatorExperimentConfigArgs.parse(rawArgs);
    },
});
const operatorExperimentConfigArgs = Object.freeze({
    ...operatorExperimentConfigShape,
    jsonSchema: operatorExperimentConfigSchema,
    toJsonSchema: () => structuredClone(operatorExperimentConfigSchema),
    parse(rawArgs, pathLabel = "args") {
        const parsed = operatorExperimentConfigShape.parse(rawArgs, pathLabel);
        const requiresManifest = BOUNDED_HYPOTHESIS_TOPOLOGIES.includes(
            parsed.hypothesis_topology,
        );
        if (requiresManifest && parsed.enumerand_manifest === undefined) {
            fail(
                `${pathLabel}.enumerand_manifest`,
                "is required for finite_enumerable and bounded_parameterized topologies",
            );
        }
        if (!requiresManifest && parsed.enumerand_manifest !== undefined) {
            fail(
                `${pathLabel}.enumerand_manifest`,
                "is only valid for finite_enumerable and bounded_parameterized topologies",
            );
        }
        if (parsed.enumerand_manifest !== undefined
            && parsed.enumerand_manifest.topology !== parsed.hypothesis_topology) {
            fail(
                `${pathLabel}.enumerand_manifest.topology`,
                "must match hypothesis_topology",
            );
        }
        if (parsed.statistical_policy.control.kind === "enumerand"
            && parsed.enumerand_manifest?.control.kind !== "enumerand") {
            fail(
                `${pathLabel}.statistical_policy.control.kind`,
                "enumerand control requires an enumerand manifest control",
            );
        }
        if (!requiresManifest
            && parsed.statistical_policy.control.kind !== "snapshot") {
            fail(
                `${pathLabel}.statistical_policy.control.kind`,
                "non-enumerated investigations require a snapshot control",
            );
        }
        return parsed;
    },
});

const newInvestigationStartArgs = object({
    experiment_id: experimentIdField,
    deadline_iso: string({
        description:
            "Optional wall-clock ISO-8601 operational deadline for this run. It does not alter the preapproved experiment contract.",
        maxLength: 64,
        pattern: STRICT_ISO_TIMESTAMP_PATTERN_SOURCE,
        format: "date-time",
        optional: true,
    }),
});

const reattachStartArgs = object({
    investigation_id: investigationIdField,
    deadline_iso: string({
        description:
            "Optional later wall-clock ISO-8601 deadline. It must be in the future and later than the persisted deadline/recovery deadline.",
        maxLength: 64,
        pattern: STRICT_ISO_TIMESTAMP_PATTERN_SOURCE,
        format: "date-time",
        optional: true,
    }),
    reset_policy: enumField(["circuit_open", "failed"], {
        description:
            "Explicit operational reset for a reattach. circuit_open resets a persisted circuit breaker; failed resets a non-recoverable failed supervisor. It never resumes a terminal/domain non-result.",
        optional: true,
    }),
});

const crucibleStartArgs = discriminatedObjectUnion({
    discriminant: "investigation_id",
    absent: newInvestigationStartArgs,
    present: reattachStartArgs,
    description:
        "Exactly one form is accepted: an operator-preapproved experiment_id, or an investigation_id reattach with only an optional later deadline/reset policy.",
});

export const crucibleStartSpec = defineTool({
    name: "crucible_start",
    description:
        "Start a new persistent Crucible investigation from an existing operator-preapproved experiment_id, or reattach/resume one by investigation_id using its persisted contract/config/snapshots. Models cannot author acceptance, topology, enumerands, hypotheses, or statistics through this tool. All admission checks complete before durable mutation. This is NOT a result — poll crucible_status and only crucible_result may emit a terminal decision.",
    args: crucibleStartArgs,
});

export const crucibleStatusSpec = defineTool({
    name: "crucible_status",
    description:
        "Read-only progress for a Crucible investigation. V3/non-v4 state is reported as legacy_incompatible and restart-required without kernel replay. V4 state is replayed and integrity-checked; terminal state exposes only terminal_available. Never a result.",
    args: object({ investigation_id: investigationIdField }),
});

export const crucibleStopSpec = defineTool({
    name: "crucible_stop",
    description:
        "Request a Crucible PAUSE through the runtime. Reports resumable:true only after the kernel-owned pause transition is durably persisted; terminal/non-result calls remain non-resumable. It never manufactures a terminal decision.",
    args: object({
        investigation_id: investigationIdField,
        reason: string({
            description: "Optional operator note recorded with the pause request.",
            maxLength: 4096,
            optional: true,
        }),
    }),
});

export const crucibleResultSpec = defineTool({
    name: "crucible_result",
    description:
        "The ONLY tool that may emit a terminal Crucible result. Replays and verifies compatible v4 state, artifact integrity, and frozen scientific readiness/confirmation closure; legacy, synthetic, search-only, or scientifically incomplete terminals return is_result:false with no winner/evidence/hash payload.",
    args: object({ investigation_id: investigationIdField }),
});

export const PUBLIC_TOOL_NAMES = Object.freeze([
    "crucible_start",
    "crucible_status",
    "crucible_stop",
    "crucible_result",
]);

const TOOL_SPEC_BY_NAME = Object.freeze({
    crucible_start: crucibleStartSpec,
    crucible_status: crucibleStatusSpec,
    crucible_stop: crucibleStopSpec,
    crucible_result: crucibleResultSpec,
});

export const TOOL_SPECS = Object.freeze(
    PUBLIC_TOOL_NAMES.map((name) => TOOL_SPEC_BY_NAME[name]),
);
