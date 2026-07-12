import {
    canonicalEqual,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import { ContractError } from "./errors.mjs";

export const HYPOTHESES_VERSION = "crucible-preregistered-hypotheses-v4";
export const HYPOTHESES_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-preregistered-hypotheses-v4";
export const PREDICTION_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-preregistered-prediction-v4";
export const OBSERVABLE_REGISTRY_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-observable-registry-v4";
export const HYPOTHESIS_POLICY_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-hypothesis-policy-v4";

export const PREDICTION_KINDS = Object.freeze([
    "threshold",
    "bounded_interval",
    "direction",
    "categorical_outcome",
]);

export const HYPOTHESIS_LIMITS = Object.freeze({
    maxPredictions: 16,
    maxObservableRegistryEntries: 64,
    maxCategoriesPerObservable: 32,
    maxAssignedParentEvidenceIds: 8,
    identifierCharacters: 128,
    identifierBytes: 128,
    categoryCharacters: 128,
    categoryBytes: 256,
    registryBytes: 8 * 1024,
    hypothesesBytes: 8 * 1024,
    maximumNumericMagnitude: Number.MAX_SAFE_INTEGER,
});

export const DEFAULT_HYPOTHESIS_POLICY = Object.freeze({
    required: false,
    maxPredictions: HYPOTHESIS_LIMITS.maxPredictions,
    allowedKinds: PREDICTION_KINDS,
    allowRequiredForResult: true,
});

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@-]*$/u;
const THRESHOLD_OPERATORS = Object.freeze(["<", "<=", ">=", ">"]);
const THRESHOLD_COMPLEMENTS = Object.freeze({
    "<": ">=",
    "<=": ">",
    ">": "<=",
    ">=": "<",
});
const DIRECTIONS = Object.freeze(["increase", "decrease"]);
const DIRECTION_REFUTATIONS = Object.freeze({
    increase: "non_increase",
    decrease: "non_decrease",
});

function fail(message, details = null) {
    throw new ContractError(message, details);
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function requirePlainObject(value, field) {
    if (!isPlainObject(value)) {
        fail(`${field} must be a plain object`, { field });
    }
    return value;
}

function requireExactKeys(value, field, required, optional = []) {
    requirePlainObject(value, field);
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail(`${field} has unknown field ${JSON.stringify(key)}`, { field, key });
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail(`${field}.${key} is required`, { field: `${field}.${key}` });
        }
    }
    return value;
}

function hasUnpairedSurrogate(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) {
                return true;
            }
            index += 1;
        } else if (code >= 0xdc00 && code <= 0xdfff) {
            return true;
        }
    }
    return false;
}

function boundedText(value, field, maximumCharacters, maximumBytes) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > maximumCharacters
        || value.includes("\u0000")
        || hasUnpairedSurrogate(value)
        || Buffer.byteLength(value, "utf8") > maximumBytes) {
        fail(`${field} must be non-empty bounded text`, {
            field,
            maximumCharacters,
            maximumBytes,
        });
    }
    return value.normalize("NFC");
}

function identifier(value, field) {
    const normalized = boundedText(
        value,
        field,
        HYPOTHESIS_LIMITS.identifierCharacters,
        HYPOTHESIS_LIMITS.identifierBytes,
    );
    if (!SAFE_IDENTIFIER.test(normalized) || normalized.includes("..")) {
        fail(`${field} must be a safe identifier`, { field, value });
    }
    return normalized;
}

function finiteBoundedNumber(value, field) {
    if (typeof value !== "number"
        || !Number.isFinite(value)
        || Math.abs(value) > HYPOTHESIS_LIMITS.maximumNumericMagnitude) {
        fail(`${field} must be a finite bounded number`, {
            field,
            maximumMagnitude: HYPOTHESIS_LIMITS.maximumNumericMagnitude,
        });
    }
    return Object.is(value, -0) ? 0 : value;
}

function canonicalBytes(value) {
    return Buffer.byteLength(canonicalJson(value), "utf8");
}

function requireBoolean(value, field) {
    if (typeof value !== "boolean") {
        fail(`${field} must be boolean`, { field });
    }
    return value;
}

function normalizeCategoricalValue(value, field) {
    if (typeof value === "boolean") {
        return value;
    }
    return boundedText(
        value,
        field,
        HYPOTHESIS_LIMITS.categoryCharacters,
        HYPOTHESIS_LIMITS.categoryBytes,
    );
}

function normalizedRegistryIdentity(observableRegistry) {
    return hashCanonical(
        {
            version: HYPOTHESES_VERSION,
            observables: observableRegistry,
        },
        OBSERVABLE_REGISTRY_IDENTITY_HASH_ALGORITHM,
    );
}

function normalizedPolicyIdentity(policy) {
    return hashCanonical(
        {
            version: HYPOTHESES_VERSION,
            policy,
        },
        HYPOTHESIS_POLICY_IDENTITY_HASH_ALGORITHM,
    );
}

function normalizedPredictionIdentity(prediction, registryIdentity, policyIdentity) {
    return hashCanonical(
        {
            version: HYPOTHESES_VERSION,
            observableRegistryIdentity: registryIdentity,
            policyIdentity,
            prediction,
        },
        PREDICTION_IDENTITY_HASH_ALGORITHM,
    );
}

function normalizedHypothesesIdentity(core) {
    return hashCanonical(core, HYPOTHESES_IDENTITY_HASH_ALGORITHM);
}

export function normalizeObservableRegistry(value = []) {
    if (!Array.isArray(value)) {
        fail("observableRegistry must be an array");
    }
    if (value.length > HYPOTHESIS_LIMITS.maxObservableRegistryEntries) {
        fail(
            `observableRegistry may contain at most ${HYPOTHESIS_LIMITS.maxObservableRegistryEntries} entries`,
        );
    }

    const seen = new Set();
    const normalized = value.map((entry, index) => {
        const field = `observableRegistry[${index}]`;
        requirePlainObject(entry, field);
        const key = identifier(entry.key, `${field}.key`);
        if (seen.has(key)) {
            fail("observableRegistry keys must be unique", { key });
        }
        seen.add(key);

        if (entry.kind === "numeric") {
            requireExactKeys(entry, field, ["key", "kind", "minimum", "maximum"]);
            const minimum = finiteBoundedNumber(entry.minimum, `${field}.minimum`);
            const maximum = finiteBoundedNumber(entry.maximum, `${field}.maximum`);
            if (minimum >= maximum) {
                fail(`${field}.minimum must be less than maximum`, { minimum, maximum });
            }
            return {
                key,
                kind: "numeric",
                minimum,
                maximum,
            };
        }

        if (entry.kind === "categorical") {
            requireExactKeys(entry, field, ["key", "kind", "values"]);
            if (!Array.isArray(entry.values)
                || entry.values.length === 0
                || entry.values.length > HYPOTHESIS_LIMITS.maxCategoriesPerObservable) {
                fail(
                    `${field}.values must contain 1..${HYPOTHESIS_LIMITS.maxCategoriesPerObservable} categories`,
                );
            }
            const values = entry.values.map((item, valueIndex) =>
                normalizeCategoricalValue(item, `${field}.values[${valueIndex}]`));
            const keys = values.map((item) => canonicalJson(item));
            if (new Set(keys).size !== keys.length) {
                fail(`${field}.values must be unique`);
            }
            values.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
            return {
                key,
                kind: "categorical",
                values,
            };
        }

        fail(`${field}.kind is not supported`, { kind: entry.kind ?? null });
    });

    normalized.sort((left, right) => left.key.localeCompare(right.key));
    const result = immutableCanonical(normalized);
    const bytes = canonicalBytes(result);
    if (bytes > HYPOTHESIS_LIMITS.registryBytes) {
        fail(`observableRegistry exceeds ${HYPOTHESIS_LIMITS.registryBytes} UTF-8 bytes`, {
            bytes,
        });
    }
    return result;
}

export function observableRegistryIdentity(value = []) {
    return normalizedRegistryIdentity(normalizeObservableRegistry(value));
}

export function normalizeHypothesisPolicy(value = {}) {
    requireExactKeys(
        value,
        "hypothesisPolicy",
        [],
        ["required", "maxPredictions", "allowedKinds", "allowRequiredForResult"],
    );
    const required = Object.hasOwn(value, "required")
        ? requireBoolean(value.required, "hypothesisPolicy.required")
        : DEFAULT_HYPOTHESIS_POLICY.required;
    const maxPredictions = Object.hasOwn(value, "maxPredictions")
        ? value.maxPredictions
        : DEFAULT_HYPOTHESIS_POLICY.maxPredictions;
    if (!Number.isSafeInteger(maxPredictions)
        || maxPredictions < 1
        || maxPredictions > HYPOTHESIS_LIMITS.maxPredictions) {
        fail(
            `hypothesisPolicy.maxPredictions must be within 1..${HYPOTHESIS_LIMITS.maxPredictions}`,
        );
    }
    const allowedKindsInput = Object.hasOwn(value, "allowedKinds")
        ? value.allowedKinds
        : PREDICTION_KINDS;
    if (!Array.isArray(allowedKindsInput) || allowedKindsInput.length === 0) {
        fail("hypothesisPolicy.allowedKinds must be a non-empty array");
    }
    const allowedKinds = PREDICTION_KINDS.filter((kind) => allowedKindsInput.includes(kind));
    if (allowedKinds.length !== allowedKindsInput.length
        || new Set(allowedKindsInput).size !== allowedKindsInput.length) {
        fail("hypothesisPolicy.allowedKinds contains an unknown or duplicate kind");
    }
    const allowRequiredForResult = Object.hasOwn(value, "allowRequiredForResult")
        ? requireBoolean(
            value.allowRequiredForResult,
            "hypothesisPolicy.allowRequiredForResult",
        )
        : DEFAULT_HYPOTHESIS_POLICY.allowRequiredForResult;

    return immutableCanonical({
        required,
        maxPredictions,
        allowedKinds,
        allowRequiredForResult,
    });
}

export function hypothesisPolicyIdentity(value = {}) {
    return normalizedPolicyIdentity(normalizeHypothesisPolicy(value));
}

function normalizeAssignedParentEvidenceIds(value = []) {
    if (!Array.isArray(value)
        || value.length > HYPOTHESIS_LIMITS.maxAssignedParentEvidenceIds) {
        fail(
            `assignedParentEvidenceIds must contain at most ${HYPOTHESIS_LIMITS.maxAssignedParentEvidenceIds} ids`,
        );
    }
    const normalized = value.map((item, index) =>
        identifier(item, `assignedParentEvidenceIds[${index}]`));
    if (new Set(normalized).size !== normalized.length) {
        fail("assignedParentEvidenceIds must be unique");
    }
    return new Set(normalized);
}

function predictionContext(options) {
    const observableRegistry = normalizeObservableRegistry(options.observableRegistry ?? []);
    const hypothesisPolicy = normalizeHypothesisPolicy(options.hypothesisPolicy ?? {});
    return {
        observableRegistry,
        observableByKey: new Map(observableRegistry.map((item) => [item.key, item])),
        hypothesisPolicy,
        assignedParentEvidenceIds: normalizeAssignedParentEvidenceIds(
            options.assignedParentEvidenceIds ?? [],
        ),
        registryIdentity: normalizedRegistryIdentity(observableRegistry),
        policyIdentity: normalizedPolicyIdentity(hypothesisPolicy),
    };
}

function normalizeRequiredForResult(value, field, policy) {
    if (value === undefined) {
        return false;
    }
    const normalized = requireBoolean(value, `${field}.requiredForResult`);
    if (normalized && !policy.allowRequiredForResult) {
        fail("hypothesisPolicy forbids requiredForResult predictions", { field });
    }
    return normalized;
}

function requireObservable(input, field, context, expectedKind) {
    const observable = identifier(input.observable, `${field}.observable`);
    const registration = context.observableByKey.get(observable);
    if (registration === undefined) {
        fail(`${field}.observable is not registered`, { observable });
    }
    if (registration.kind !== expectedKind) {
        fail(`${field}.observable has incompatible kind`, {
            observable,
            expectedKind,
            actualKind: registration.kind,
        });
    }
    return { observable, registration };
}

function requireWithinObservable(value, registration, field) {
    const normalized = finiteBoundedNumber(value, field);
    if (normalized < registration.minimum || normalized > registration.maximum) {
        fail(`${field} is outside the registered observable bounds`, {
            value: normalized,
            minimum: registration.minimum,
            maximum: registration.maximum,
        });
    }
    return normalized;
}

function normalizeThreshold(input, field, context, base) {
    requireExactKeys(
        input,
        field,
        ["id", "kind", "observable", "operator", "value", "refutation"],
        ["requiredForResult"],
    );
    const { observable, registration } = requireObservable(input, field, context, "numeric");
    if (!THRESHOLD_OPERATORS.includes(input.operator)) {
        fail(`${field}.operator is not supported`, { operator: input.operator ?? null });
    }
    const value = requireWithinObservable(input.value, registration, `${field}.value`);
    requireExactKeys(
        input.refutation,
        `${field}.refutation`,
        ["kind", "operator", "value"],
    );
    const refutationValue = requireWithinObservable(
        input.refutation.value,
        registration,
        `${field}.refutation.value`,
    );
    if (input.refutation.kind !== "threshold"
        || input.refutation.operator !== THRESHOLD_COMPLEMENTS[input.operator]
        || refutationValue !== value) {
        fail(`${field}.refutation must be the explicit complement of the threshold`, {
            expected: {
                kind: "threshold",
                operator: THRESHOLD_COMPLEMENTS[input.operator],
                value,
            },
        });
    }
    return {
        ...base,
        observable,
        operator: input.operator,
        value,
        refutation: {
            kind: "threshold",
            operator: input.refutation.operator,
            value: refutationValue,
        },
    };
}

function normalizeBoundedInterval(input, field, context, base) {
    requireExactKeys(
        input,
        field,
        ["id", "kind", "observable", "lower", "upper", "refutation"],
        ["requiredForResult"],
    );
    const { observable, registration } = requireObservable(input, field, context, "numeric");
    const lower = requireWithinObservable(input.lower, registration, `${field}.lower`);
    const upper = requireWithinObservable(input.upper, registration, `${field}.upper`);
    if (lower >= upper) {
        fail(`${field}.lower must be less than upper`, { lower, upper });
    }
    requireExactKeys(input.refutation, `${field}.refutation`, ["kind"]);
    if (input.refutation.kind !== "outside_interval") {
        fail(`${field}.refutation.kind must be outside_interval`);
    }
    return {
        ...base,
        observable,
        lower,
        upper,
        refutation: { kind: "outside_interval" },
    };
}

function normalizeDirectionReference(value, field, assignedParentEvidenceIds) {
    requirePlainObject(value, field);
    if (value.kind === "control") {
        requireExactKeys(value, field, ["kind"]);
        return { kind: "control" };
    }
    if (value.kind === "assigned_parent") {
        requireExactKeys(value, field, ["kind", "evidenceId"]);
        const evidenceId = identifier(value.evidenceId, `${field}.evidenceId`);
        if (!assignedParentEvidenceIds.has(evidenceId)) {
            fail(`${field}.evidenceId is not an assigned parent`, { evidenceId });
        }
        return { kind: "assigned_parent", evidenceId };
    }
    fail(`${field}.kind must be control or assigned_parent`, {
        kind: value.kind ?? null,
    });
}

function normalizeDirection(input, field, context, base) {
    requireExactKeys(
        input,
        field,
        ["id", "kind", "observable", "direction", "reference", "refutation"],
        ["requiredForResult"],
    );
    const { observable } = requireObservable(input, field, context, "numeric");
    if (!DIRECTIONS.includes(input.direction)) {
        fail(`${field}.direction is not supported`, { direction: input.direction ?? null });
    }
    const reference = normalizeDirectionReference(
        input.reference,
        `${field}.reference`,
        context.assignedParentEvidenceIds,
    );
    requireExactKeys(
        input.refutation,
        `${field}.refutation`,
        ["kind", "direction"],
    );
    const expectedRefutation = DIRECTION_REFUTATIONS[input.direction];
    if (input.refutation.kind !== "direction"
        || input.refutation.direction !== expectedRefutation) {
        fail(`${field}.refutation must explicitly negate the predicted direction`, {
            expected: {
                kind: "direction",
                direction: expectedRefutation,
            },
        });
    }
    return {
        ...base,
        observable,
        direction: input.direction,
        reference,
        refutation: {
            kind: "direction",
            direction: expectedRefutation,
        },
    };
}

function normalizeCategoricalOutcome(input, field, context, base) {
    requireExactKeys(
        input,
        field,
        ["id", "kind", "observable", "outcome", "refutation"],
        ["requiredForResult"],
    );
    const { observable, registration } = requireObservable(
        input,
        field,
        context,
        "categorical",
    );
    const outcome = normalizeCategoricalValue(input.outcome, `${field}.outcome`);
    const registeredValues = new Set(registration.values.map((item) => canonicalJson(item)));
    if (!registeredValues.has(canonicalJson(outcome))) {
        fail(`${field}.outcome is not registered`, { observable, outcome });
    }
    requireExactKeys(
        input.refutation,
        `${field}.refutation`,
        ["kind", "operator", "outcome"],
    );
    const refutationOutcome = normalizeCategoricalValue(
        input.refutation.outcome,
        `${field}.refutation.outcome`,
    );
    if (input.refutation.kind !== "categorical_outcome"
        || input.refutation.operator !== "not_equals"
        || !canonicalEqual(refutationOutcome, outcome)) {
        fail(`${field}.refutation must explicitly reject the predicted outcome`, {
            expected: {
                kind: "categorical_outcome",
                operator: "not_equals",
                outcome,
            },
        });
    }
    return {
        ...base,
        observable,
        outcome,
        refutation: {
            kind: "categorical_outcome",
            operator: "not_equals",
            outcome,
        },
    };
}

function normalizePredictionWithContext(value, context, field = "prediction") {
    requirePlainObject(value, field);
    const id = identifier(value.id, `${field}.id`);
    if (!PREDICTION_KINDS.includes(value.kind)
        || !context.hypothesisPolicy.allowedKinds.includes(value.kind)) {
        fail(`${field}.kind is not allowed`, { kind: value.kind ?? null });
    }
    const base = {
        id,
        kind: value.kind,
        requiredForResult: normalizeRequiredForResult(
            value.requiredForResult,
            field,
            context.hypothesisPolicy,
        ),
    };

    switch (value.kind) {
        case "threshold":
            return immutableCanonical(normalizeThreshold(value, field, context, base));
        case "bounded_interval":
            return immutableCanonical(normalizeBoundedInterval(value, field, context, base));
        case "direction":
            return immutableCanonical(normalizeDirection(value, field, context, base));
        case "categorical_outcome":
            return immutableCanonical(normalizeCategoricalOutcome(value, field, context, base));
        default:
            fail(`${field}.kind is not supported`, { kind: value.kind ?? null });
    }
}

export function normalizePrediction(value, options = {}) {
    return normalizePredictionWithContext(value, predictionContext(options));
}

export function predictionIdentity(value, options = {}) {
    const context = predictionContext(options);
    const prediction = normalizePredictionWithContext(value, context);
    return normalizedPredictionIdentity(
        prediction,
        context.registryIdentity,
        context.policyIdentity,
    );
}

export function normalizeHypotheses(value, options = {}) {
    const context = predictionContext(options);
    if (value === undefined || value === null) {
        if (context.hypothesisPolicy.required) {
            fail("Preregistered hypotheses are required by policy");
        }
        return null;
    }

    requirePlainObject(value, "hypotheses");
    const rawKeys = Object.keys(value).sort();
    const rawForm = canonicalEqual(rawKeys, ["predictions"]);
    const sealedKeys = [
        "identity",
        "observableRegistryIdentity",
        "policyIdentity",
        "predictions",
        "version",
    ];
    const sealedForm = canonicalEqual(rawKeys, sealedKeys);
    if (!rawForm && !sealedForm) {
        fail(
            "hypotheses must be an unsealed { predictions } object or an exact sealed hypothesis set",
            { keys: rawKeys },
        );
    }
    if (options.requireSealed === true && !sealedForm) {
        fail("Hypotheses must be sealed in the proposal before any measurement observation");
    }
    if (!Array.isArray(value.predictions)) {
        fail("hypotheses.predictions must be an array");
    }
    if (value.predictions.length > context.hypothesisPolicy.maxPredictions) {
        fail(
            `hypotheses.predictions may contain at most ${context.hypothesisPolicy.maxPredictions} items`,
        );
    }
    if (context.hypothesisPolicy.required && value.predictions.length === 0) {
        fail("At least one preregistered prediction is required by policy");
    }

    const predictions = value.predictions.map((prediction, index) =>
        normalizePredictionWithContext(
            prediction,
            context,
            `hypotheses.predictions[${index}]`,
        ));
    const predictionIds = predictions.map((prediction) => prediction.id);
    if (new Set(predictionIds).size !== predictionIds.length) {
        fail("hypotheses.predictions ids must be unique");
    }
    predictions.sort((left, right) => left.id.localeCompare(right.id));

    const core = immutableCanonical({
        version: HYPOTHESES_VERSION,
        observableRegistryIdentity: context.registryIdentity,
        policyIdentity: context.policyIdentity,
        predictions,
    });
    const normalized = immutableCanonical({
        ...core,
        identity: normalizedHypothesesIdentity(core),
    });
    const bytes = canonicalBytes(normalized);
    if (bytes > HYPOTHESIS_LIMITS.hypothesesBytes) {
        fail(`hypotheses exceed ${HYPOTHESIS_LIMITS.hypothesesBytes} UTF-8 bytes`, {
            bytes,
        });
    }

    if (sealedForm && !canonicalEqual(value, normalized)) {
        fail("Sealed hypotheses were mutated or do not match the injected registry/policy", {
            expectedIdentity: normalized.identity,
            actualIdentity: value.identity ?? null,
        });
    }
    return normalized;
}

export function hypothesesIdentity(value, options = {}) {
    return normalizeHypotheses(value, options)?.identity ?? null;
}

export function normalizeSealedHypotheses(value, options = {}) {
    return normalizeHypotheses(value, { ...options, requireSealed: true });
}
