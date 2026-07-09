// oracle-v3/api/schema.mjs
//
// Single-source declarative schema/spec builder for the Oracle v3 four-tool
// API. Each field is described ONCE as a small descriptor that knows how to
// (a) emit a Copilot JSON Schema fragment and (b) parse + normalize a runtime
// value. Tool argument objects compose those descriptors, so the JSON Schema
// advertised to Copilot and the runtime parser can never drift apart — there
// is no hand-maintained duplicate JSON Schema or Zod schema anywhere.
//
// Dependency-free: this module imports only the domain topology vocabulary
// (a shared constant) and the API's own typed error. It never touches I/O.

import { HYPOTHESIS_TOPOLOGIES } from "../domain/constants.mjs";
import { SchemaValidationError } from "./errors.mjs";

// Re-exported so the schema module's public surface includes the error its
// parser throws (callers/tests import it from here, the single source).
export { SchemaValidationError };

const IDENTIFIER_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$";
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;

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
    pattern,
    optional = false,
    default: defaultValue,
} = {}) {
    const jsonSchema = commonOptions(
        {
            type: "string",
            minLength,
            maxLength,
            ...(pattern === undefined ? {} : { pattern }),
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
            if (typeof value !== "string" || !IDENTIFIER_RE.test(value) || value.includes("..")) {
                fail(pathLabel, "must be a safe identifier (not a filesystem path)");
            }
            return value;
        },
    });
}

export function enumField(values, { description, optional = false } = {}) {
    const allowed = Object.freeze([...values]);
    return makeField({
        jsonSchema: commonOptions({ type: "string", enum: allowed }, { description }),
        optional,
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
    optional = false,
    default: defaultValue,
} = {}) {
    const jsonSchema = commonOptions(
        { type: "number", ...(minimum === undefined ? {} : { minimum }) },
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
    optional = false,
    default: defaultValue,
} = {}) {
    const jsonSchema = commonOptions(
        {
            type: "array",
            items: item.jsonSchema,
            ...(minItems === undefined ? {} : { minItems }),
            ...(maxItems === undefined ? {} : { maxItems }),
            ...(uniqueItems ? { uniqueItems: true } : {}),
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
            if (uniqueItems) {
                const seen = new Set();
                for (let index = 0; index < parsed.length; index += 1) {
                    const key = JSON.stringify(parsed[index]);
                    if (seen.has(key)) {
                        fail(`${pathLabel}[${index}]`, "must be unique");
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
export function rawObject({ description, optional = false } = {}) {
    return makeField({
        jsonSchema: commonOptions({ type: "object", additionalProperties: true }, { description }),
        optional,
        parse(value, pathLabel) {
            if (!isPlainObject(value)) {
                fail(pathLabel, "must be a JSON object");
            }
            return value;
        },
    });
}

// Compose a set of named field descriptors into an object descriptor that
// yields BOTH a strict Copilot JSON Schema and a runtime parser.
export function object(fields, { description } = {}) {
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

    return Object.freeze({ entries, toJsonSchema, parse });
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

// --- the four public tool specs -------------------------------------------

const investigationIdField = identifier({
    description:
        "The investigationId returned by oracle_start. Deterministic slug + SHA-256 suffix; resolves to local state under the Oracle v3 state root.",
});

export const oracleStartSpec = defineTool({
    name: "oracle_start",
    description:
        "Start (or idempotently re-attach to) a persistent Oracle v3 investigation: freeze an immutable contract, ingest the validation-case directories into the content-addressed ArtifactStore, and launch the detached supervisor/runner. Returns the investigationId, contractHash, and local state/status paths. This is NOT a result — poll oracle_status and only oracle_result may emit a terminal decision.",
    args: object({
        objective: string({
            description: "The falsifiable objective under investigation. Part of the deterministic investigationId.",
            maxLength: 8192,
        }),
        project_dir: string({
            description: "Absolute local project directory. Validation-case paths must resolve inside it. Part of the deterministic investigationId.",
            maxLength: 32767,
        }),
        harness_id: identifier({
            description: "Id of an operator-owned harness allowlist entry (the terminal measurement authority). Must already exist in the allowlist; never a path or command.",
        }),
        acceptance_predicate: rawObject({
            description: "Acceptance-predicate grammar object (harness_pass / metric_compare / field_equals / all / any / not ...). Validated by the domain contract.",
        }),
        hypothesis_topology: enumField(HYPOTHESIS_TOPOLOGIES, {
            description: "Search topology: finite_enumerable, bounded_parameterized, open_generative, or certified_impossibility.",
        }),
        validation_cases: array(
            object({
                id: identifier({ description: "Stable id for this validation case." }),
                expectation: enumField(["accept", "reject"], {
                    description: "Whether the harness must accept or reject this case.",
                }),
                path: string({
                    description: "Local directory path (inside project_dir) ingested immutably into the ArtifactStore; only its content hash enters the contract.",
                    maxLength: 32767,
                }),
            }),
            {
                description: "At least one accept and one reject case. Each path is ingested immediately; symlinks/traversal are refused.",
                minItems: 2,
            },
        ),
        metrics: array(
            object({
                key: identifier({ description: "Metric key as emitted by the harness." }),
                direction: enumField(["min", "max"], {
                    description: "min = lower is better; max = higher is better.",
                }),
                epsilon: number({
                    description: "Optional non-negative tie tolerance.",
                    minimum: 0,
                    optional: true,
                }),
            }),
            { description: "Ranking metrics the harness emits. Order = priority.", default: [] },
        ),
        worker_models: array(
            identifier({ description: "A proposer/worker model id." }),
            {
                description: "1..8 distinct worker model ids used to propose candidates.",
                minItems: 1,
                maxItems: 8,
                uniqueItems: true,
            },
        ),
        candidates_per_round: integer({
            description: "Candidates generated per search round (1..8).",
            minimum: 1,
            maximum: 8,
        }),
        max_rounds: integer({
            description: "Maximum number of frozen search rounds (>= 1).",
            minimum: 1,
            maximum: 100000,
        }),
        bounded_candidate_ids: array(
            identifier({ description: "A declared candidate id for a finite/bounded search space." }),
            {
                description: "Optional exhaustive candidate id set for finite_enumerable / bounded_parameterized topologies.",
                minItems: 1,
                uniqueItems: true,
                optional: true,
            },
        ),
        deadline_iso: string({
            description: "Optional wall-clock ISO-8601 deadline for the run.",
            maxLength: 64,
            optional: true,
        }),
        reset_policy: enumField(["circuit_open", "failed"], {
            description:
                "Explicit operational reset for an idempotent reattach. circuit_open resets a persisted circuit breaker; failed resets a non-recoverable failed supervisor. It never resumes a terminal/domain non-result.",
            optional: true,
        }),
    }),
});

export const oracleStatusSpec = defineTool({
    name: "oracle_status",
    description:
        "Read-only progress for an Oracle v3 investigation. Replays and integrity-checks domain plus operational evidence, exposes only terminal_available for terminal state (never the decision/winner/evidence), and restarts a missing supervisor only when no terminal or non-result blocks recovery. Never a result.",
    args: object({ investigation_id: investigationIdField }),
});

export const oracleStopSpec = defineTool({
    name: "oracle_stop",
    description:
        "Request a PAUSE through the runtime. Reports resumable:true only after the kernel-owned pause transition is durably persisted; terminal/non-result calls remain non-resumable. It never manufactures a terminal decision.",
    args: object({
        investigation_id: investigationIdField,
        reason: string({
            description: "Optional operator note recorded with the pause request.",
            maxLength: 4096,
            optional: true,
        }),
    }),
});

export const oracleResultSpec = defineTool({
    name: "oracle_result",
    description:
        "The ONLY tool that may emit a terminal Oracle v3 result. Replays and verifies repository/domain integrity. If a VERIFIED_RESULT or TARGET_UNREACHABLE decision is persisted it returns is_result:true with the exact terminal decision and hashes behind a prominent banner. For every other state it returns is_result:false and 'NOT A RESULT — DO NOT REPORT AS COMPLETE' with no winner payload. It never recomputes scoring or policy.",
    args: object({ investigation_id: investigationIdField }),
});

export const TOOL_SPECS = Object.freeze([
    oracleStartSpec,
    oracleStatusSpec,
    oracleStopSpec,
    oracleResultSpec,
]);

export const PUBLIC_TOOL_NAMES = Object.freeze(TOOL_SPECS.map((spec) => spec.name));
