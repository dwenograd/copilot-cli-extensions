import {
    CONTRACT_HASH_ALGORITHM,
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import {
    DEFAULT_IMPOSSIBILITY_POLICY,
    DEFAULT_SEARCH_POLICY,
    ESCAPE_SEARCH_OPERATORS,
    HYPOTHESIS_TOPOLOGIES,
    SEARCH_OPERATORS,
} from "./constants.mjs";
import { ContractError, ERROR_CODES } from "./errors.mjs";

const COMPARISON_OPERATORS = Object.freeze(["<", "<=", "==", ">=", ">"]);
const VALIDATION_EXPECTATIONS = Object.freeze(["accept", "reject"]);
const METRIC_DIRECTIONS = Object.freeze(["min", "max"]);
const SEARCH_POLICY_KEYS = Object.freeze([
    "archiveCaps",
    "dedupPolicy",
    "mandatoryEscapeRounds",
    "minRoundsBeforePlateau",
    "operatorWeights",
    "plateauMinImprovement",
    "plateauWindow",
    "promptCaps",
    "stopOnFirstAccept",
]);
const ARCHIVE_CAP_KEYS = Object.freeze([
    "accepted",
    "duplicateIndex",
    "invalidMetrics",
    "lessonGroups",
    "mechanismGroups",
    "nearMisses",
    "rejected",
]);
const PROMPT_CAP_KEYS = Object.freeze([
    "parentEvidenceIds",
    "promptContextRefs",
]);

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

function requireSafeIntegerInRange(value, field, minimum, maximum) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new ContractError(
            `${field} must be a safe integer between ${minimum} and ${maximum}`,
            { field, value, minimum, maximum },
        );
    }
    return value;
}

function requireFiniteNumberInRange(value, field, minimum, maximum) {
    if (typeof value !== "number"
        || !Number.isFinite(value)
        || value < minimum
        || value > maximum) {
        throw new ContractError(
            `${field} must be a finite number between ${minimum} and ${maximum}`,
            { field, value, minimum, maximum },
        );
    }
    return value;
}

function requireExactObjectKeys(value, field, expectedKeys) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new ContractError(`${field} must be an object`, { field });
    }
    const actual = Object.keys(value).sort();
    const expected = [...expectedKeys].sort();
    if (!canonicalEqual(actual, expected)) {
        throw new ContractError(`${field} must contain exactly the canonical fields`, {
            field,
            expected,
            actual,
        });
    }
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

function numericFailureDistance(actual, operator, expected) {
    if (typeof actual !== "number" || !Number.isFinite(actual)) {
        return null;
    }
    let gap;
    switch (operator) {
        case "<":
            gap = actual < expected ? 0 : actual - expected + Number.EPSILON;
            break;
        case "<=":
            gap = actual <= expected ? 0 : actual - expected;
            break;
        case "==":
            gap = Math.abs(actual - expected);
            break;
        case ">=":
            gap = actual >= expected ? 0 : expected - actual;
            break;
        case ">":
            gap = actual > expected ? 0 : expected - actual + Number.EPSILON;
            break;
        default:
            return null;
    }
    return gap / Math.max(1, Math.abs(expected));
}

function assessPredicate(predicate, result) {
    switch (predicate.kind) {
        case "harness_pass":
            return {
                satisfied: result?.pass === true,
                near: false,
                distance: result?.pass === true ? 0 : null,
                failedLeaves: result?.pass === true ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: result?.pass !== true,
            };
        case "constant":
            return {
                satisfied: predicate.value,
                near: false,
                distance: predicate.value ? 0 : null,
                failedLeaves: predicate.value ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
        case "field_equals": {
            const actual = valueAtPath(result, predicate.path);
            const satisfied = actual.found && canonicalEqual(actual.value, predicate.value);
            return {
                satisfied,
                near: false,
                distance: satisfied ? 0 : null,
                failedLeaves: satisfied ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
        }
        case "number_compare": {
            const actual = valueAtPath(result, predicate.path);
            const satisfied = actual.found
                && compareNumbers(actual.value, predicate.operator, predicate.value);
            const distance = actual.found
                ? numericFailureDistance(actual.value, predicate.operator, predicate.value)
                : null;
            return {
                satisfied,
                near: !satisfied && distance !== null && distance <= 0.1,
                distance,
                failedLeaves: satisfied ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
        }
        case "metric_compare": {
            const actual = result?.metrics?.[predicate.metric];
            const satisfied = compareNumbers(actual, predicate.operator, predicate.value);
            const distance = numericFailureDistance(actual, predicate.operator, predicate.value);
            return {
                satisfied,
                near: !satisfied && distance !== null && distance <= 0.1,
                distance,
                failedLeaves: satisfied ? 0 : 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
        }
        case "all": {
            const children = predicate.predicates.map((child) => assessPredicate(child, result));
            const failed = children.filter((child) => !child.satisfied);
            const booleanGateOnly = failed.length === 1
                && failed[0].booleanGateFailure
                && children.length > 1;
            return {
                satisfied: failed.length === 0,
                near: failed.length === 1 && (failed[0].near || booleanGateOnly),
                distance: failed.length === 0
                    ? 0
                    : failed.length === 1
                        ? failed[0].distance
                        : null,
                failedLeaves: children.reduce((sum, child) => sum + child.failedLeaves, 0),
                leafCount: children.reduce((sum, child) => sum + child.leafCount, 0),
                booleanGateFailure: false,
            };
        }
        case "any": {
            const children = predicate.predicates.map((child) => assessPredicate(child, result));
            const satisfied = children.some((child) => child.satisfied);
            const nearChildren = children.filter((child) => child.near);
            const distances = nearChildren
                .map((child) => child.distance)
                .filter((distance) => distance !== null);
            return {
                satisfied,
                near: !satisfied && nearChildren.length > 0,
                distance: distances.length > 0 ? Math.min(...distances) : null,
                failedLeaves: satisfied
                    ? 0
                    : Math.min(...children.map((child) => child.failedLeaves)),
                leafCount: children.reduce((sum, child) => sum + child.leafCount, 0),
                booleanGateFailure: false,
            };
        }
        case "not": {
            const child = assessPredicate(predicate.predicate, result);
            return {
                satisfied: !child.satisfied,
                near: false,
                distance: !child.satisfied ? 0 : null,
                failedLeaves: !child.satisfied ? 0 : 1,
                leafCount: child.leafCount,
                booleanGateFailure: false,
            };
        }
        default:
            return {
                satisfied: false,
                near: false,
                distance: null,
                failedLeaves: 1,
                leafCount: 1,
                booleanGateFailure: false,
            };
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

function normalizeImpossibilityPolicy(input, topology) {
    if (topology !== "certified_impossibility") {
        if (input !== undefined && input !== null) {
            throw new ContractError(
                "impossibilityPolicy is only valid for certified_impossibility topology",
            );
        }
        return null;
    }
    const policy = input ?? DEFAULT_IMPOSSIBILITY_POLICY;
    requireExactObjectKeys(
        policy,
        "impossibilityPolicy",
        ["certificateVersion", "requestVersion", "trigger"],
    );
    if (policy.trigger !== DEFAULT_IMPOSSIBILITY_POLICY.trigger
        || policy.requestVersion !== DEFAULT_IMPOSSIBILITY_POLICY.requestVersion
        || policy.certificateVersion !== DEFAULT_IMPOSSIBILITY_POLICY.certificateVersion) {
        throw new ContractError(
            "impossibilityPolicy must use the canonical certified-impossibility policy",
        );
    }
    return immutableCanonical(policy);
}

export function createSearchPolicy(input) {
    requireExactObjectKeys(input, "searchPolicy", SEARCH_POLICY_KEYS);
    if (typeof input.stopOnFirstAccept !== "boolean") {
        throw new ContractError("searchPolicy.stopOnFirstAccept must be boolean");
    }

    const plateauWindow = requireSafeIntegerInRange(
        input.plateauWindow,
        "searchPolicy.plateauWindow",
        1,
        1000,
    );
    const minRoundsBeforePlateau = requireSafeIntegerInRange(
        input.minRoundsBeforePlateau,
        "searchPolicy.minRoundsBeforePlateau",
        1,
        100000,
    );
    if (minRoundsBeforePlateau < plateauWindow) {
        throw new ContractError(
            "searchPolicy.minRoundsBeforePlateau must be at least plateauWindow",
        );
    }
    const plateauMinImprovement = requireFiniteNumberInRange(
        input.plateauMinImprovement,
        "searchPolicy.plateauMinImprovement",
        0,
        Number.MAX_SAFE_INTEGER,
    );
    const mandatoryEscapeRounds = requireSafeIntegerInRange(
        input.mandatoryEscapeRounds,
        "searchPolicy.mandatoryEscapeRounds",
        1,
        1000,
    );

    requireExactObjectKeys(
        input.operatorWeights,
        "searchPolicy.operatorWeights",
        SEARCH_OPERATORS,
    );
    const operatorWeights = {};
    for (const operator of SEARCH_OPERATORS) {
        operatorWeights[operator] = requireSafeIntegerInRange(
            input.operatorWeights[operator],
            `searchPolicy.operatorWeights.${operator}`,
            0,
            1000000,
        );
    }
    if (operatorWeights.fresh < 1) {
        throw new ContractError("searchPolicy.operatorWeights.fresh must be at least 1");
    }
    if (ESCAPE_SEARCH_OPERATORS.reduce(
        (sum, operator) => sum + operatorWeights[operator],
        0,
    ) < 1) {
        throw new ContractError(
            "searchPolicy.operatorWeights must enable at least one mandatory-escape operator",
        );
    }

    requireExactObjectKeys(
        input.archiveCaps,
        "searchPolicy.archiveCaps",
        ARCHIVE_CAP_KEYS,
    );
    const archiveCaps = {};
    for (const key of ARCHIVE_CAP_KEYS) {
        archiveCaps[key] = requireSafeIntegerInRange(
            input.archiveCaps[key],
            `searchPolicy.archiveCaps.${key}`,
            1,
            100000,
        );
    }

    requireExactObjectKeys(
        input.promptCaps,
        "searchPolicy.promptCaps",
        PROMPT_CAP_KEYS,
    );
    const promptCaps = {
        parentEvidenceIds: requireSafeIntegerInRange(
            input.promptCaps.parentEvidenceIds,
            "searchPolicy.promptCaps.parentEvidenceIds",
            1,
            16,
        ),
        promptContextRefs: requireSafeIntegerInRange(
            input.promptCaps.promptContextRefs,
            "searchPolicy.promptCaps.promptContextRefs",
            1,
            256,
        ),
    };
    if (promptCaps.parentEvidenceIds > promptCaps.promptContextRefs) {
        throw new ContractError(
            "searchPolicy.promptCaps.parentEvidenceIds cannot exceed promptContextRefs",
        );
    }

    if (input.dedupPolicy !== "mark") {
        throw new ContractError("searchPolicy.dedupPolicy must be mark");
    }

    return immutableCanonical({
        stopOnFirstAccept: input.stopOnFirstAccept,
        plateauWindow,
        minRoundsBeforePlateau,
        plateauMinImprovement,
        mandatoryEscapeRounds,
        operatorWeights,
        archiveCaps,
        promptCaps,
        dedupPolicy: "mark",
    });
}

export function defaultSearchPolicy() {
    return createSearchPolicy(DEFAULT_SEARCH_POLICY);
}

export const normalizeSearchPolicy = createSearchPolicy;

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

    if (!Object.hasOwn(input, "searchPolicy")) {
        throw new ContractError(
            "searchPolicy is required; callers must provide the canonical version-2 search policy",
        );
    }
    const searchPolicy = createSearchPolicy(input.searchPolicy);
    if (!canonicalEqual(searchPolicy, input.searchPolicy)) {
        throw new ContractError("searchPolicy must already be in canonical kernel form");
    }

    const search = normalizeSearch(input.search ?? input, input.hypothesisTopology);
    const impossibilityPolicy = normalizeImpossibilityPolicy(
        input.impossibilityPolicy,
        input.hypothesisTopology,
    );
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
        searchPolicy,
        ...(impossibilityPolicy === null ? {} : { impossibilityPolicy }),
        declaredLimits: normalizeDeclaredLimits(input.declaredLimits),
    };

    return immutableCanonical(contract);
}

export function acceptanceSatisfied(acceptancePredicate, harnessResult) {
    const normalized = normalizePredicate(acceptancePredicate);
    return evaluatePredicate(normalized, harnessResult);
}

export function assessAcceptancePredicate(acceptancePredicate, harnessResult) {
    return immutableCanonical(assessPredicate(
        normalizePredicate(acceptancePredicate),
        harnessResult,
    ));
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
        if (typeof value === "number" && Number.isFinite(value)) {
            values[metric.key] = value;
        }
    }
    return immutableCanonical(values);
}

export function candidateMetricsRankable(metrics, metricValues) {
    return metrics.every((metric) =>
        typeof metricValues?.[metric.key] === "number"
        && Number.isFinite(metricValues[metric.key]));
}

export const availableCandidateMetricValues = candidateMetricValues;

export function contractHash(contract) {
    return hashCanonical(contract, CONTRACT_HASH_ALGORITHM);
}

export function commandBudget(contract) {
    return contract.declaredLimits.maxCommands
        ?? contract.declaredLimits.commandBudget
        ?? null;
}
