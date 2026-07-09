import {
    CONTRACT_HASH_ALGORITHM,
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import { HYPOTHESIS_TOPOLOGIES } from "./constants.mjs";
import { ContractError, ERROR_CODES } from "./errors.mjs";

const COMPARISON_OPERATORS = Object.freeze(["<", "<=", "==", ">=", ">"]);
const VALIDATION_EXPECTATIONS = Object.freeze(["accept", "reject"]);
const METRIC_DIRECTIONS = Object.freeze(["min", "max"]);

function requireNonEmptyString(value, field, maximum = 4096) {
    if (typeof value !== "string" || value.trim().length === 0 || value.length > maximum) {
        throw new ContractError(`${field} must be a non-empty string of at most ${maximum} characters`, {
            field,
        });
    }
    return value;
}

function requireIdentifier(value, field) {
    requireNonEmptyString(value, field, 128);
    if (!/^[A-Za-z0-9][A-Za-z0-9._@-]*$/u.test(value)
        || value === "."
        || value === ".."
        || value.includes("..")) {
        throw new ContractError(`${field} must be an identifier, not a filesystem path`, {
            field,
            value,
        });
    }
    return value;
}

function requirePositiveSafeInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        throw new ContractError(`${field} must be a positive safe integer no greater than ${maximum}`, {
            field,
            value,
        });
    }
    return value;
}

function requireArtifactHash(value, field) {
    if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value)) {
        throw new ContractError(`${field} must be a sha256:<64hex> artifact hash`, {
            field,
            value,
        });
    }
    return value;
}

function normalizePath(path, field) {
    const segments = typeof path === "string" ? path.split(".") : path;
    if (!Array.isArray(segments)
        || segments.length === 0
        || segments.some((segment) => typeof segment !== "string" || segment.length === 0)) {
        throw new ContractError(`${field} must be a non-empty field path`, {
            field,
        }, ERROR_CODES.INVALID_ACCEPTANCE_PREDICATE);
    }
    return [...segments];
}

function predicateError(message, details = null) {
    throw new ContractError(message, details, ERROR_CODES.INVALID_ACCEPTANCE_PREDICATE);
}

function normalizePredicate(predicate, depth = 0) {
    if (depth > 32) {
        predicateError("Acceptance predicate exceeds maximum nesting depth");
    }
    if (predicate === null || typeof predicate !== "object" || Array.isArray(predicate)) {
        predicateError("Acceptance predicate must be an object");
    }

    switch (predicate.kind) {
        case "harness_pass":
            return { kind: "harness_pass" };
        case "constant":
            if (typeof predicate.value !== "boolean") {
                predicateError("constant predicate value must be boolean");
            }
            return { kind: "constant", value: predicate.value };
        case "field_equals":
            return {
                kind: "field_equals",
                path: normalizePath(predicate.path, "acceptancePredicate.path"),
                value: immutableCanonical(predicate.value),
            };
        case "number_compare":
            if (!COMPARISON_OPERATORS.includes(predicate.operator)) {
                predicateError("number_compare predicate has an unsupported operator", {
                    operator: predicate.operator,
                });
            }
            if (typeof predicate.value !== "number" || !Number.isFinite(predicate.value)) {
                predicateError("number_compare predicate value must be finite");
            }
            return {
                kind: "number_compare",
                path: normalizePath(predicate.path, "acceptancePredicate.path"),
                operator: predicate.operator,
                value: predicate.value,
            };
        case "metric_compare":
            requireNonEmptyString(predicate.metric, "acceptancePredicate.metric", 128);
            if (!COMPARISON_OPERATORS.includes(predicate.operator)) {
                predicateError("metric_compare predicate has an unsupported operator", {
                    operator: predicate.operator,
                });
            }
            if (typeof predicate.value !== "number" || !Number.isFinite(predicate.value)) {
                predicateError("metric_compare predicate value must be finite");
            }
            return {
                kind: "metric_compare",
                metric: predicate.metric,
                operator: predicate.operator,
                value: predicate.value,
            };
        case "all":
        case "any":
            if (!Array.isArray(predicate.predicates) || predicate.predicates.length === 0) {
                predicateError(`${predicate.kind} predicate requires at least one child`);
            }
            return {
                kind: predicate.kind,
                predicates: predicate.predicates.map((child) => normalizePredicate(child, depth + 1)),
            };
        case "not":
            return {
                kind: "not",
                predicate: normalizePredicate(predicate.predicate, depth + 1),
            };
        default:
            predicateError("Unknown acceptance predicate kind", {
                kind: predicate.kind ?? null,
            });
    }
}

function valueAtPath(root, path) {
    let current = root;
    for (const segment of path) {
        if (current === null
            || typeof current !== "object"
            || !Object.hasOwn(current, segment)) {
            return { found: false, value: null };
        }
        current = current[segment];
    }
    return { found: true, value: current };
}

function compareNumbers(actual, operator, expected) {
    if (typeof actual !== "number" || !Number.isFinite(actual)) {
        return false;
    }
    switch (operator) {
        case "<": return actual < expected;
        case "<=": return actual <= expected;
        case "==": return actual === expected;
        case ">=": return actual >= expected;
        case ">": return actual > expected;
        default: return false;
    }
}

function evaluatePredicate(predicate, result) {
    switch (predicate.kind) {
        case "harness_pass":
            return result?.pass === true;
        case "constant":
            return predicate.value;
        case "field_equals": {
            const actual = valueAtPath(result, predicate.path);
            return actual.found && canonicalEqual(actual.value, predicate.value);
        }
        case "number_compare": {
            const actual = valueAtPath(result, predicate.path);
            return actual.found && compareNumbers(actual.value, predicate.operator, predicate.value);
        }
        case "metric_compare":
            return compareNumbers(result?.metrics?.[predicate.metric], predicate.operator, predicate.value);
        case "all":
            return predicate.predicates.every((child) => evaluatePredicate(child, result));
        case "any":
            return predicate.predicates.some((child) => evaluatePredicate(child, result));
        case "not":
            return !evaluatePredicate(predicate.predicate, result);
        default:
            return false;
    }
}

function normalizeDeclaredLimits(limits) {
    if (limits === null || typeof limits !== "object" || Array.isArray(limits)) {
        throw new ContractError("declaredLimits must be an object");
    }
    const normalized = immutableCanonical(limits);
    for (const field of ["maxCommands", "commandBudget", "maxEvidence", "maxSearchRevisions"]) {
        if (Object.hasOwn(normalized, field)
            && (!Number.isSafeInteger(normalized[field]) || normalized[field] < 1)) {
            throw new ContractError(`declaredLimits.${field} must be a positive safe integer`);
        }
    }
    return normalized;
}

function normalizeValidationCases(cases) {
    if (!Array.isArray(cases) || cases.length < 2) {
        throw new ContractError("validationCases must contain at least one accept and one reject case");
    }
    const ids = new Set();
    const expectations = new Set();
    const normalized = cases.map((item, index) => {
        if (item === null || typeof item !== "object" || Array.isArray(item)) {
            throw new ContractError(`validationCases[${index}] must be an object`);
        }
        const id = requireIdentifier(item.id, `validationCases[${index}].id`);
        if (ids.has(id)) {
            throw new ContractError("validationCases IDs must be unique", { id });
        }
        ids.add(id);
        if (!VALIDATION_EXPECTATIONS.includes(item.expectation)) {
            throw new ContractError(
                `validationCases[${index}].expectation must be accept or reject`,
            );
        }
        expectations.add(item.expectation);
        return {
            id,
            expectation: item.expectation,
            artifactHash: requireArtifactHash(
                item.artifactHash,
                `validationCases[${index}].artifactHash`,
            ),
        };
    });
    if (!expectations.has("accept") || !expectations.has("reject")) {
        throw new ContractError("validationCases must contain at least one accept and one reject case");
    }
    return normalized;
}

function normalizeIdentifierArray(value, field, minimum, maximum) {
    if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
        throw new ContractError(`${field} must contain between ${minimum} and ${maximum} identifiers`);
    }
    const normalized = value.map((item, index) => requireIdentifier(item, `${field}[${index}]`));
    if (new Set(normalized).size !== normalized.length) {
        throw new ContractError(`${field} must contain unique identifiers`);
    }
    return normalized;
}

function normalizeSearch(search, topology) {
    if (search === null || typeof search !== "object" || Array.isArray(search)) {
        throw new ContractError("search must be an object");
    }
    const normalized = {
        workerModels: normalizeIdentifierArray(search.workerModels, "search.workerModels", 1, 8),
        candidatesPerRound: requirePositiveSafeInteger(
            search.candidatesPerRound,
            "search.candidatesPerRound",
            8,
        ),
        maxRounds: requirePositiveSafeInteger(search.maxRounds, "search.maxRounds"),
    };
    if (search.boundedCandidateIds !== undefined && search.boundedCandidateIds !== null) {
        if (topology !== "finite_enumerable" && topology !== "bounded_parameterized") {
            throw new ContractError(
                "search.boundedCandidateIds is only valid for finite or bounded topologies",
            );
        }
        normalized.boundedCandidateIds = normalizeIdentifierArray(
            search.boundedCandidateIds,
            "search.boundedCandidateIds",
            1,
            Number.MAX_SAFE_INTEGER,
        );
        if (normalized.boundedCandidateIds.length
            > normalized.candidatesPerRound * normalized.maxRounds) {
            throw new ContractError(
                "search capacity must cover every boundedCandidateId",
            );
        }
    }
    return normalized;
}

function normalizeMetrics(metrics) {
    if (metrics === undefined || metrics === null) {
        return [];
    }
    if (!Array.isArray(metrics)) {
        throw new ContractError("metrics must be an array");
    }
    const keys = new Set();
    return metrics.map((metric, index) => {
        if (metric === null || typeof metric !== "object" || Array.isArray(metric)) {
            throw new ContractError(`metrics[${index}] must be an object`);
        }
        const key = requireIdentifier(metric.key, `metrics[${index}].key`);
        if (keys.has(key)) {
            throw new ContractError("metrics keys must be unique", { key });
        }
        keys.add(key);
        if (!METRIC_DIRECTIONS.includes(metric.direction)) {
            throw new ContractError(`metrics[${index}].direction must be min or max`);
        }
        const epsilon = metric.epsilon ?? 0;
        if (typeof epsilon !== "number" || !Number.isFinite(epsilon) || epsilon < 0) {
            throw new ContractError(`metrics[${index}].epsilon must be a finite non-negative number`);
        }
        return {
            key,
            direction: metric.direction,
            epsilon,
        };
    });
}

export function createInvestigationContract(input) {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
        throw new ContractError("Investigation contract input must be an object");
    }

    const objective = requireNonEmptyString(input.objective, "objective");
    const harnessId = requireIdentifier(input.harnessId, "harnessId");
    if (!HYPOTHESIS_TOPOLOGIES.includes(input.hypothesisTopology)) {
        throw new ContractError("hypothesisTopology is not supported", {
            hypothesisTopology: input.hypothesisTopology ?? null,
        });
    }

    const search = normalizeSearch(input.search ?? input, input.hypothesisTopology);
    const contract = {
        objective,
        acceptancePredicate: normalizePredicate(input.acceptancePredicate),
        validationCases: normalizeValidationCases(input.validationCases),
        harnessId,
        hypothesisTopology: input.hypothesisTopology,
        criticality: requireNonEmptyString(input.criticality, "criticality", 64),
        policyVersion: requireIdentifier(input.policyVersion, "policyVersion"),
        parserVersion: requireIdentifier(input.parserVersion, "parserVersion"),
        workerModels: search.workerModels,
        candidatesPerRound: search.candidatesPerRound,
        maxRounds: search.maxRounds,
        ...(search.boundedCandidateIds === undefined
            ? {}
            : { boundedCandidateIds: search.boundedCandidateIds }),
        metrics: normalizeMetrics(input.metrics),
        declaredLimits: normalizeDeclaredLimits(input.declaredLimits),
    };

    return immutableCanonical(contract);
}

export function acceptanceSatisfied(acceptancePredicate, harnessResult) {
    const normalized = normalizePredicate(acceptancePredicate);
    return evaluatePredicate(normalized, harnessResult);
}

export function validationSatisfied(validationCases, harnessResult) {
    const results = harnessResult?.caseResults;
    if (!Array.isArray(results) || results.length !== validationCases.length) {
        return false;
    }
    const byId = new Map();
    for (const result of results) {
        if (result === null
            || typeof result !== "object"
            || Array.isArray(result)
            || typeof result.id !== "string"
            || byId.has(result.id)) {
            return false;
        }
        byId.set(result.id, result);
    }
    return validationCases.every((validationCase) => {
        const result = byId.get(validationCase.id);
        return result !== undefined
            && result.artifactHash === validationCase.artifactHash
            && result.outcome === validationCase.expectation;
    });
}

export function candidateMetricValues(metrics, harnessResult) {
    const values = {};
    for (const metric of metrics) {
        const value = harnessResult?.metrics?.[metric.key];
        if (typeof value !== "number" || !Number.isFinite(value)) {
            return null;
        }
        values[metric.key] = value;
    }
    return immutableCanonical(values);
}

export function contractHash(contract) {
    return hashCanonical(contract, CONTRACT_HASH_ALGORITHM);
}

export function commandBudget(contract) {
    return contract.declaredLimits.maxCommands
        ?? contract.declaredLimits.commandBudget
        ?? null;
}
