import {
    CONTRACT_HASH_ALGORITHM,
    canonicalEqual,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import {
    CONTRACT_LIMITS,
    DEFAULT_IMPOSSIBILITY_POLICY,
    DEFAULT_SEARCH_POLICY,
    DEFAULT_SCIENTIFIC_TERMINAL_POLICY,
    DOMAIN_VERSION,
    ESCAPE_SEARCH_OPERATORS,
    GOAL_MODES,
    HYPOTHESIS_TOPOLOGIES,
    MISSINGNESS_MODES,
    SEARCH_POLICY_LIMITS,
    SEARCH_OPERATORS,
    SEARCH_STRATEGY_POLICY_VERSION,
    STATISTICAL_POLICY_HASH_ALGORITHM,
    STATISTICAL_METRIC_DIRECTIONS,
    STATISTICAL_POLICY_VERSION,
    VALIDATION_HARNESS_ROLES,
} from "./constants.mjs";
import {
    normalizeEnumerandManifest,
} from "./enumerands.mjs";
import {
    hypothesisPolicyIdentity,
    normalizeHypothesisPolicy,
    normalizeObservableRegistry,
    observableRegistryIdentity,
} from "./hypotheses.mjs";
import {
    ContractError,
    DomainVersionRestartRequiredError,
    ERROR_CODES,
} from "./errors.mjs";
import {
    computeHarnessSuiteV4Identity,
    normalizeHarnessSuiteV4,
} from "../measurement/harness-suite.mjs";
import {
    StatisticsError,
    statisticalAcceptanceClaimSet,
} from "./statistics.mjs";
import {
    RUNTIME_IDENTITY_ROOT_ALGORITHM,
    normalizeRuntimeIdentityPolicy,
    runtimeIdentityPolicyIdentity,
} from "./runtime-authority.mjs";
import {
    normalizeWorkingSetPolicy,
} from "./working-set-policy.mjs";

const COMPARISON_OPERATORS = Object.freeze(["<", "<=", "==", ">=", ">"]);
const VALIDATION_EXPECTATIONS = Object.freeze(["accept", "reject"]);
const TAGGED_SHA256 = /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const SNAPSHOT_HASH = /^sha256:[a-f0-9]{64}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@-]*$/u;
const FORBIDDEN_IDENTIFIERS = new Set([
    "__proto__",
    "constructor",
    "prototype",
]);
const SEARCH_POLICY_KEYS = Object.freeze([
    "archiveCaps",
    "dedupPolicy",
    "mandatoryEscapeRounds",
    "minRoundsBeforePlateau",
    "operatorWeights",
    "plateauMinImprovement",
    "plateauWindow",
    "promptCaps",
    "version",
]);
const ARCHIVE_CAP_KEYS = Object.freeze([
    "accepted",
    "duplicateIndex",
    "inconclusive",
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
const CONTRACT_INPUT_REQUIRED_KEYS = Object.freeze([
    "acceptancePredicate",
    "candidatesPerRound",
    "criticality",
    "harnessSuite",
    "harnessSuiteIdentity",
    "hypothesisPolicy",
    "hypothesisTopology",
    "maxRounds",
    "objective",
    "observableRegistry",
    "policyVersion",
    "runtimeIdentityPolicy",
    "runtimeIdentityPolicyIdentity",
    "runtimeIdentityRoot",
    "searchPolicy",
    "statisticalPolicy",
    "workingSetPolicy",
    "workerModels",
]);
const CONTRACT_INPUT_OPTIONAL_KEYS = Object.freeze([
    "domainVersion",
    "enumerandManifest",
    "impossibilityPolicy",
]);
const CONTRACT_OUTPUT_REQUIRED_KEYS = Object.freeze([
    "acceptanceClaimSet",
    "acceptancePredicate",
    "candidatesPerRound",
    "criticality",
    "declaredLimits",
    "domainVersion",
    "harnessId",
    "harnessSuite",
    "harnessSuiteIdentity",
    "hypothesisPolicy",
    "hypothesisPolicyIdentity",
    "hypothesisTopology",
    "maxRounds",
    "metrics",
    "objective",
    "observableRegistry",
    "observableRegistryIdentity",
    "parserVersion",
    "policyVersion",
    "runtimeIdentityPolicy",
    "runtimeIdentityPolicyIdentity",
    "runtimeIdentityRoot",
    "searchPolicy",
    "scientificTerminalPolicy",
    "statisticalPolicy",
    "statisticalPolicyIdentity",
    "validationCases",
    "validationClaimSet",
    "validationRoles",
    "workingSetPolicy",
    "workerModels",
]);
const CONTRACT_OUTPUT_OPTIONAL_KEYS = Object.freeze([
    "enumerandManifest",
    "impossibilityPolicy",
]);
const STATISTICAL_POLICY_KEYS = Object.freeze([
    "control",
    "deterministicBlockSeed",
    "evaluationBudget",
    "familyAllocations",
    "goalMode",
    "investigationAlpha",
    "maxBlocks",
    "maxConfirmations",
    "metrics",
    "minBlocks",
    "missingness",
    "resourceBudget",
    "version",
]);
const STATISTICAL_METRIC_KEYS = Object.freeze([
    "acceptanceThreshold",
    "direction",
    "estimand",
    "family",
    "key",
    "maximum",
    "minimum",
    "practicalEquivalenceDelta",
    "unit",
]);
const STATISTICAL_METRIC_OPTIONAL_KEYS = Object.freeze(["priority"]);
const FAMILY_ALLOCATION_KEYS = Object.freeze(["alpha", "family"]);
const CONTROL_KEYS = Object.freeze(["identity", "kind", "tolerances"]);
const CONTROL_TOLERANCE_KEYS = Object.freeze([
    "absolute",
    "metric",
    "relative",
]);
const MISSINGNESS_KEYS = Object.freeze([
    "maxMissingFraction",
    "maxMissingPerBlock",
    "mode",
]);
const EVALUATION_BUDGET_KEYS = Object.freeze([
    "maxCandidateEvaluations",
    "maxControlEvaluations",
    "maxTotalEvaluations",
]);
const RESOURCE_BUDGET_KEYS = Object.freeze([
    "perAttemptCasBytes",
    "perAttemptOutputBytes",
    "perAttemptReceiptBytes",
    "perInvestigationCasBytes",
    "perInvestigationOutputBytes",
    "perInvestigationReceiptBytes",
]);

function requireNonEmptyString(value, field, maximum = 4096) {
    if (typeof value !== "string" || value.trim().length === 0 || value.length > maximum) {
        throw new ContractError(`${field} must be a non-empty string of at most ${maximum} characters`, {
            field,
        });
    }
    return value;
}

function requireBoundedText(value, field, maximumCharacters, maximumBytes) {
    if (typeof value !== "string"
        || value.trim().length === 0
        || value.length > maximumCharacters
        || Buffer.byteLength(value, "utf8") > maximumBytes) {
        throw new ContractError(
            `${field} must be non-empty text of at most ${maximumCharacters} characters and ${maximumBytes} UTF-8 bytes`,
            { field, maximumCharacters, maximumBytes },
        );
    }
    return value;
}

export function isSafeDomainIdentifier(value) {
    return typeof value === "string"
        && value.length > 0
        && value.length <= 128
        && SAFE_IDENTIFIER.test(value)
        && value !== "."
        && value !== ".."
        && !value.endsWith(".")
        && !value.includes("..")
        && !FORBIDDEN_IDENTIFIERS.has(value.toLowerCase());
}

function requireIdentifier(value, field) {
    if (!isSafeDomainIdentifier(value)) {
        throw new ContractError(
            `${field} must be a safe identifier, not a filesystem path or prototype key`,
            {
                field,
                value,
            },
        );
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

function requireObjectKeys(value, field, requiredKeys, optionalKeys = []) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new ContractError(`${field} must be an object`, { field });
    }
    const allowed = new Set([...requiredKeys, ...optionalKeys]);
    const actual = Object.keys(value);
    const missing = requiredKeys.filter((key) => !Object.hasOwn(value, key));
    const unknown = actual.filter((key) => !allowed.has(key));
    if (missing.length > 0 || unknown.length > 0) {
        throw new ContractError(`${field} must contain only the canonical fields`, {
            field,
            missing,
            unknown,
            required: [...requiredKeys],
            optional: [...optionalKeys],
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

function requireTaggedSha256(value, field) {
    if (typeof value !== "string" || !TAGGED_SHA256.test(value)) {
        throw new ContractError(`${field} must be an algorithm-tagged SHA-256`, {
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
        || segments.length > CONTRACT_LIMITS.acceptancePathSegments
        || segments.some((segment) =>
            typeof segment !== "string"
            || segment.length === 0
            || segment.length > CONTRACT_LIMITS.acceptancePathSegmentCharacters
            || Buffer.byteLength(segment, "utf8")
                > CONTRACT_LIMITS.acceptanceValueStringBytes)) {
        throw new ContractError(`${field} must be a non-empty field path`, {
            field,
            maximumSegments: CONTRACT_LIMITS.acceptancePathSegments,
            maximumSegmentCharacters:
                CONTRACT_LIMITS.acceptancePathSegmentCharacters,
        }, ERROR_CODES.INVALID_ACCEPTANCE_PREDICATE);
    }
    return [...segments];
}

function predicateError(message, details = null) {
    throw new ContractError(message, details, ERROR_CODES.INVALID_ACCEPTANCE_PREDICATE);
}

function normalizeAcceptanceValue(value, field, state, depth = 0) {
    if (depth > CONTRACT_LIMITS.acceptanceValueDepth) {
        predicateError("Acceptance predicate comparison value exceeds maximum nesting depth", {
            field,
            maximumDepth: CONTRACT_LIMITS.acceptanceValueDepth,
        });
    }
    state.nodes += 1;
    if (state.nodes > CONTRACT_LIMITS.acceptanceValueNodes) {
        predicateError("Acceptance predicate comparison value exceeds maximum complexity", {
            field,
            maximumNodes: CONTRACT_LIMITS.acceptanceValueNodes,
        });
    }
    if (value === null || typeof value === "boolean") {
        return value;
    }
    if (typeof value === "number") {
        if (!Number.isFinite(value)) {
            predicateError("Acceptance predicate comparison numbers must be finite", { field });
        }
        return value;
    }
    if (typeof value === "string") {
        if (value.length > CONTRACT_LIMITS.acceptanceValueStringCharacters
            || Buffer.byteLength(value, "utf8")
                > CONTRACT_LIMITS.acceptanceValueStringBytes) {
            predicateError("Acceptance predicate comparison string exceeds its bound", {
                field,
                maximumCharacters:
                    CONTRACT_LIMITS.acceptanceValueStringCharacters,
                maximumBytes: CONTRACT_LIMITS.acceptanceValueStringBytes,
            });
        }
        return value;
    }
    if (Array.isArray(value)) {
        if (value.length > CONTRACT_LIMITS.acceptanceValueArrayItems) {
            predicateError("Acceptance predicate comparison array exceeds its item bound", {
                field,
                maximumItems: CONTRACT_LIMITS.acceptanceValueArrayItems,
            });
        }
        return value.map((item, index) =>
            normalizeAcceptanceValue(item, `${field}[${index}]`, state, depth + 1));
    }
    if (value === null || typeof value !== "object") {
        predicateError("Acceptance predicate comparison value must be canonical JSON", {
            field,
        });
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        predicateError("Acceptance predicate comparison objects must be plain objects", {
            field,
        });
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
        predicateError("Acceptance predicate comparison objects cannot have symbol keys", {
            field,
        });
    }
    const keys = Object.keys(value);
    if (keys.length > CONTRACT_LIMITS.acceptanceValueObjectProperties) {
        predicateError("Acceptance predicate comparison object exceeds its property bound", {
            field,
            maximumProperties:
                CONTRACT_LIMITS.acceptanceValueObjectProperties,
        });
    }
    const output = {};
    for (const key of keys) {
        if (key.length > CONTRACT_LIMITS.acceptanceValueStringCharacters
            || Buffer.byteLength(key, "utf8")
                > CONTRACT_LIMITS.acceptanceValueStringBytes) {
            predicateError("Acceptance predicate comparison object key exceeds its bound", {
                field,
                key,
            });
        }
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) {
            predicateError("Acceptance predicate comparison objects cannot use accessors", {
                field,
                key,
            });
        }
        output[key] = normalizeAcceptanceValue(
            descriptor.value,
            `${field}.${key}`,
            state,
            depth + 1,
        );
    }
    return output;
}

function normalizePredicateNode(predicate, state, depth = 0) {
    if (depth > CONTRACT_LIMITS.acceptancePredicateDepth) {
        predicateError("Acceptance predicate exceeds maximum nesting depth");
    }
    if (predicate === null || typeof predicate !== "object" || Array.isArray(predicate)) {
        predicateError("Acceptance predicate must be an object");
    }
    state.nodes += 1;
    if (state.nodes > CONTRACT_LIMITS.acceptancePredicateNodes) {
        predicateError("Acceptance predicate exceeds maximum node complexity", {
            maximumNodes: CONTRACT_LIMITS.acceptancePredicateNodes,
        });
    }

    switch (predicate.kind) {
        case "harness_pass":
            requireObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind"],
                ["family", "probabilityThreshold"],
            );
            return {
                kind: "harness_pass",
                ...(predicate.family === undefined
                    ? {}
                    : {
                        family: requireIdentifier(
                            predicate.family,
                            "acceptancePredicate.family",
                        ),
                    }),
                ...(predicate.probabilityThreshold === undefined
                    ? {}
                    : {
                        probabilityThreshold: requireFiniteNumberInRange(
                            predicate.probabilityThreshold,
                            "acceptancePredicate.probabilityThreshold",
                            Number.MIN_VALUE,
                            1 - Number.EPSILON,
                        ),
                    }),
            };
        case "constant":
            requireExactObjectKeys(predicate, "acceptancePredicate", ["kind", "value"]);
            if (typeof predicate.value !== "boolean") {
                predicateError("constant predicate value must be boolean");
            }
            return { kind: "constant", value: predicate.value };
        case "field_equals":
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "path", "value"],
            );
            return {
                kind: "field_equals",
                path: normalizePath(predicate.path, "acceptancePredicate.path"),
                value: normalizeAcceptanceValue(
                    predicate.value,
                    "acceptancePredicate.value",
                    { nodes: 0 },
                ),
            };
        case "number_compare":
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "operator", "path", "value"],
            );
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
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "metric", "operator", "value"],
            );
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
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "predicates"],
            );
            if (!Array.isArray(predicate.predicates)
                || predicate.predicates.length === 0
                || predicate.predicates.length
                    > CONTRACT_LIMITS.acceptancePredicateChildren) {
                predicateError(`${predicate.kind} predicate requires at least one child`);
            }
            return {
                kind: predicate.kind,
                predicates: predicate.predicates.map((child) =>
                    normalizePredicateNode(child, state, depth + 1)),
            };
        case "not":
            requireExactObjectKeys(
                predicate,
                "acceptancePredicate",
                ["kind", "predicate"],
            );
            return {
                kind: "not",
                predicate: normalizePredicateNode(predicate.predicate, state, depth + 1),
            };
        default:
            predicateError("Unknown acceptance predicate kind", {
                kind: predicate.kind ?? null,
            });
    }
}

function normalizePredicate(predicate) {
    const normalized = normalizePredicateNode(predicate, { nodes: 0 });
    const bytes = Buffer.byteLength(canonicalJson(normalized), "utf8");
    if (bytes > CONTRACT_LIMITS.acceptancePredicateBytes) {
        predicateError("Acceptance predicate exceeds maximum serialized size", {
            bytes,
            maximumBytes: CONTRACT_LIMITS.acceptancePredicateBytes,
        });
    }
    return normalized;
}

function normalizeValidationCases(cases) {
    if (!Array.isArray(cases)
        || cases.length < 2
        || cases.length > CONTRACT_LIMITS.validationCases) {
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
            expectedClaimState: item.expectation === "accept"
                ? "SUPPORTED"
                : "REFUTED",
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
        workerModels: normalizeIdentifierArray(
            search.workerModels,
            "search.workerModels",
            1,
            CONTRACT_LIMITS.workerModels,
        ),
        candidatesPerRound: requirePositiveSafeInteger(
            search.candidatesPerRound,
            "search.candidatesPerRound",
            CONTRACT_LIMITS.candidatesPerRound,
        ),
        maxRounds: requirePositiveSafeInteger(
            search.maxRounds,
            "search.maxRounds",
            CONTRACT_LIMITS.maxRounds,
        ),
    };
    if (normalized.candidatesPerRound * normalized.maxRounds
        > CONTRACT_LIMITS.maxEvaluations) {
        throw new ContractError(
            `search capacity cannot exceed ${CONTRACT_LIMITS.maxEvaluations} candidate evaluations`,
        );
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
    requireExactObjectKeys(
        input,
        "searchPolicy",
        SEARCH_POLICY_KEYS,
    );
    if (input.version !== SEARCH_STRATEGY_POLICY_VERSION) {
        throw new ContractError("searchPolicy.version is unsupported", {
            expected: SEARCH_STRATEGY_POLICY_VERSION,
            actual: typeof input.version === "string" ? input.version : null,
        });
    }

    const plateauWindow = requireSafeIntegerInRange(
        input.plateauWindow,
        "searchPolicy.plateauWindow",
        1,
        SEARCH_POLICY_LIMITS.plateauWindow,
    );
    const minRoundsBeforePlateau = requireSafeIntegerInRange(
        input.minRoundsBeforePlateau,
        "searchPolicy.minRoundsBeforePlateau",
        1,
        SEARCH_POLICY_LIMITS.minRoundsBeforePlateau,
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
        SEARCH_POLICY_LIMITS.mandatoryEscapeRounds,
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
    if (operatorWeights.diversification + operatorWeights.restart < 1) {
        throw new ContractError(
            "searchPolicy.operatorWeights must enable a parent-free mandatory-escape fallback",
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
            SEARCH_POLICY_LIMITS.archiveCaps[key],
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
            SEARCH_POLICY_LIMITS.promptCaps.parentEvidenceIds,
        ),
        promptContextRefs: requireSafeIntegerInRange(
            input.promptCaps.promptContextRefs,
            "searchPolicy.promptCaps.promptContextRefs",
            1,
            SEARCH_POLICY_LIMITS.promptCaps.promptContextRefs,
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
        version: SEARCH_STRATEGY_POLICY_VERSION,
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

function requireNonNegativeSafeInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
        throw new ContractError(
            `${field} must be a non-negative safe integer no greater than ${maximum}`,
            { field, value, maximum },
        );
    }
    return value;
}

function checkedProduct(values, field) {
    let result = 1;
    for (const value of values) {
        if (!Number.isSafeInteger(value) || value < 0
            || (value !== 0 && result > Number.MAX_SAFE_INTEGER / value)) {
            throw new ContractError(`${field} is not a safe integer`, {
                field,
                values,
            });
        }
        result *= value;
    }
    return result;
}

function checkedSum(values, field) {
    let result = 0;
    for (const value of values) {
        if (!Number.isSafeInteger(value) || value < 0
            || result > Number.MAX_SAFE_INTEGER - value) {
            throw new ContractError(`${field} is not a safe integer`, {
                field,
                values,
            });
        }
        result += value;
    }
    return result;
}

function compensatedFiniteSum(values) {
    let sum = 0;
    let correction = 0;
    for (const value of values) {
        const next = sum + value;
        correction += Math.abs(sum) >= Math.abs(value)
            ? (sum - next) + value
            : (value - next) + sum;
        sum = next;
    }
    const result = sum + correction;
    return Object.is(result, -0) ? 0 : result;
}

export function harnessSuiteRoleCases(value, role) {
    const suite = normalizeHarnessSuiteV4(value?.harnessSuite ?? value);
    const roleId = requireIdentifier(role, "role");
    const roleSpec = suite.roles[roleId];
    if (roleSpec === undefined) {
        throw new ContractError(`HarnessSuiteV4 role ${JSON.stringify(roleId)} is unavailable`, {
            role: roleId,
        });
    }
    return immutableCanonical(roleSpec.caseManifest.map((caseRef) => {
        const corpusCase = suite.operatorCorpus.cases[caseRef.id];
        if (corpusCase === undefined
            || corpusCase.snapshotHash !== caseRef.snapshotHash) {
            throw new ContractError(
                `HarnessSuiteV4 role ${JSON.stringify(roleId)} has an invalid corpus binding`,
                { role: roleId, caseId: caseRef.id },
            );
        }
        return {
            id: caseRef.id,
            expectation: corpusCase.expectation,
            artifactHash: caseRef.snapshotHash,
        };
    }));
}

export function requiredHarnessRoles(goalMode, topology) {
    if (!GOAL_MODES.includes(goalMode)) {
        throw new ContractError("goalMode must be satisfice or optimize", { goalMode });
    }
    if (!HYPOTHESIS_TOPOLOGIES.includes(topology)) {
        throw new ContractError("hypothesisTopology is not supported", {
            hypothesisTopology: topology ?? null,
        });
    }
    return Object.freeze([
        "calibration",
        "search",
        "confirmation",
        "challenge",
        ...(topology === "certified_impossibility"
            ? ["impossibility_verifier"]
            : []),
    ]);
}

function normalizeHarnessSuiteContract(value, identity, goalMode, topology) {
    let suite;
    try {
        suite = normalizeHarnessSuiteV4(value);
    } catch (error) {
        throw new ContractError(
            `harnessSuite is not a valid HarnessSuiteV4: ${error?.message ?? String(error)}`,
            { cause: error?.code ?? null, details: error?.details ?? null },
        );
    }
    const actualIdentity = computeHarnessSuiteV4Identity(suite);
    if (requireTaggedSha256(identity, "harnessSuiteIdentity") !== actualIdentity) {
        throw new ContractError(
            "harnessSuiteIdentity does not match the canonical HarnessSuiteV4",
            { expected: actualIdentity, actual: identity },
        );
    }
    for (const role of requiredHarnessRoles(goalMode, topology)) {
        if (suite.roles[role] === undefined) {
            throw new ContractError(
                `HarnessSuiteV4 role ${JSON.stringify(role)} is required for this goal/topology`,
                { role, goalMode, topology },
            );
        }
    }
    const primaryParserVersions = new Set(
        [
            "calibration",
            "search",
            "confirmation",
            "challenge",
        ].map((role) => suite.roles[role].parser.version),
    );
    if (primaryParserVersions.size !== 1) {
        throw new ContractError(
            "HarnessSuiteV4 primary roles must use one trusted parser version",
            { parserVersions: [...primaryParserVersions].sort() },
        );
    }
    const verifierParser =
        suite.roles.impossibility_verifier?.parser.version ?? null;
    if (verifierParser !== null
        && primaryParserVersions.has(verifierParser)) {
        throw new ContractError(
            "HarnessSuiteV4 impossibility verifier must use a distinct parser implementation",
            { verifierParser },
        );
    }
    return { suite, identity: actualIdentity };
}

function normalizeStatisticalMetrics(value, observableRegistry) {
    if (!Array.isArray(value)
        || value.length < 1
        || value.length > CONTRACT_LIMITS.metrics) {
        throw new ContractError(
            `statisticalPolicy.metrics must contain 1..${CONTRACT_LIMITS.metrics} items`,
        );
    }
    const observableByKey = new Map(
        observableRegistry.map((observable) => [observable.key, observable]),
    );
    const keys = new Set();
    const hasExplicitPriority = value.some((metric) =>
        metric !== null
        && typeof metric === "object"
        && Object.hasOwn(metric, "priority"));
    if (hasExplicitPriority
        && value.some((metric) =>
            metric === null
            || typeof metric !== "object"
            || !Object.hasOwn(metric, "priority"))) {
        throw new ContractError(
            "statisticalPolicy.metrics must either all declare priority or all omit it",
        );
    }
    const metrics = value.map((metric, index) => {
        const field = `statisticalPolicy.metrics[${index}]`;
        requireObjectKeys(
            metric,
            field,
            STATISTICAL_METRIC_KEYS,
            STATISTICAL_METRIC_OPTIONAL_KEYS,
        );
        const key = requireIdentifier(metric.key, `${field}.key`);
        if (keys.has(key)) {
            throw new ContractError("statisticalPolicy.metrics keys must be unique", {
                key,
            });
        }
        keys.add(key);
        const minimum = requireFiniteNumberInRange(
            metric.minimum,
            `${field}.minimum`,
            -Number.MAX_SAFE_INTEGER,
            Number.MAX_SAFE_INTEGER,
        );
        const maximum = requireFiniteNumberInRange(
            metric.maximum,
            `${field}.maximum`,
            -Number.MAX_SAFE_INTEGER,
            Number.MAX_SAFE_INTEGER,
        );
        if (minimum >= maximum) {
            throw new ContractError(`${field}.minimum must be less than maximum`, {
                minimum,
                maximum,
            });
        }
        const observable = observableByKey.get(key);
        if (observable?.kind !== "numeric"
            || observable.minimum !== minimum
            || observable.maximum !== maximum) {
            throw new ContractError(
                `${field} must exactly match a numeric observable registry entry`,
                { key, minimum, maximum, observable: observable ?? null },
            );
        }
        if (!STATISTICAL_METRIC_DIRECTIONS.includes(metric.direction)) {
            throw new ContractError(`${field}.direction must be min or max`);
        }
        const acceptanceThreshold = requireFiniteNumberInRange(
            metric.acceptanceThreshold,
            `${field}.acceptanceThreshold`,
            minimum,
            maximum,
        );
        const practicalEquivalenceDelta = requireFiniteNumberInRange(
            metric.practicalEquivalenceDelta,
            `${field}.practicalEquivalenceDelta`,
            Number.MIN_VALUE,
            maximum - minimum,
        );
        return {
            key,
            priority: hasExplicitPriority
                ? requireNonNegativeSafeInteger(
                    metric.priority,
                    `${field}.priority`,
                    value.length - 1,
                )
                : null,
            minimum,
            maximum,
            estimand: requireBoundedText(
                metric.estimand,
                `${field}.estimand`,
                256,
                512,
            ),
            unit: requireBoundedText(metric.unit, `${field}.unit`, 128, 256),
            direction: metric.direction,
            acceptanceThreshold,
            practicalEquivalenceDelta,
            family: requireIdentifier(metric.family, `${field}.family`),
        };
    });
    if (hasExplicitPriority) {
        const priorities = metrics.map((metric) => metric.priority);
        if (new Set(priorities).size !== metrics.length
            || priorities.some((priority) =>
                priority < 0 || priority >= metrics.length)) {
            throw new ContractError(
                "statisticalPolicy.metrics priorities must be unique and contiguous from zero",
                { priorities },
            );
        }
        metrics.sort((left, right) =>
            left.priority - right.priority
            || left.key.localeCompare(right.key));
    } else {
        metrics.sort((left, right) => left.key.localeCompare(right.key));
        metrics.forEach((metric, priority) => {
            metric.priority = priority;
        });
    }
    return immutableCanonical(metrics);
}

function normalizeFamilyAllocations(value, investigationAlpha, metrics) {
    if (!Array.isArray(value)
        || value.length < 1
        || value.length > CONTRACT_LIMITS.statisticalFamilies) {
        throw new ContractError(
            `statisticalPolicy.familyAllocations must contain 1..${CONTRACT_LIMITS.statisticalFamilies} items`,
        );
    }
    const seen = new Set();
    const allocations = value.map((allocation, index) => {
        const field = `statisticalPolicy.familyAllocations[${index}]`;
        requireExactObjectKeys(allocation, field, FAMILY_ALLOCATION_KEYS);
        const family = requireIdentifier(allocation.family, `${field}.family`);
        if (seen.has(family)) {
            throw new ContractError(
                "statisticalPolicy family allocations must be disjoint and uniquely named",
                { family },
            );
        }
        seen.add(family);
        return {
            family,
            alpha: requireFiniteNumberInRange(
                allocation.alpha,
                `${field}.alpha`,
                Number.MIN_VALUE,
                investigationAlpha,
            ),
        };
    });
    allocations.sort((left, right) => left.family.localeCompare(right.family));
    const sum = compensatedFiniteSum(
        allocations.map((allocation) => allocation.alpha),
    );
    const tolerance = Math.max(1e-12, investigationAlpha * 1e-12);
    if (!Number.isFinite(sum) || Math.abs(sum - investigationAlpha) > tolerance) {
        throw new ContractError(
            "statisticalPolicy family alpha allocations must sum to investigationAlpha",
            { investigationAlpha, allocationSum: sum, tolerance },
        );
    }
    const metricFamilies = new Set(metrics.map((metric) => metric.family));
    const allocationFamilies = new Set(allocations.map((allocation) => allocation.family));
    const missing = [...metricFamilies].filter((family) => !allocationFamilies.has(family));
    const unused = [...allocationFamilies].filter((family) => !metricFamilies.has(family));
    if (missing.length > 0 || unused.length > 0) {
        throw new ContractError(
            "statisticalPolicy family allocations must partition exactly the metric families",
            { missing: missing.sort(), unused: unused.sort() },
        );
    }
    return immutableCanonical(allocations);
}

function expectedControlFromManifest(enumerandManifest) {
    if (enumerandManifest === null) return null;
    const resolved = enumerandManifest.control.kind === "reference"
        ? enumerandManifest.control
        : enumerandManifest.entries[enumerandManifest.control.ordinal];
    return resolved.kind === "reference"
        ? { kind: "snapshot", identity: resolved.referenceHash }
        : { kind: "enumerand", identity: resolved.enumerandHash };
}

function normalizeStatisticalControl(value, metrics, enumerandManifest) {
    requireExactObjectKeys(value, "statisticalPolicy.control", CONTROL_KEYS);
    if (value.kind !== "snapshot" && value.kind !== "enumerand") {
        throw new ContractError(
            "statisticalPolicy.control.kind must be snapshot or enumerand",
        );
    }
    const identity = value.kind === "snapshot"
        ? requireArtifactHash(value.identity, "statisticalPolicy.control.identity")
        : requireTaggedSha256(value.identity, "statisticalPolicy.control.identity");
    const expected = expectedControlFromManifest(enumerandManifest);
    if (expected !== null
        && (expected.kind !== value.kind || expected.identity !== identity)) {
        throw new ContractError(
            "statisticalPolicy.control must match the frozen enumerand manifest control",
            { expected, actual: { kind: value.kind, identity } },
        );
    }
    if (expected === null && value.kind !== "snapshot") {
        throw new ContractError(
            "Non-enumerated investigations require a frozen control snapshot",
        );
    }
    if (!Array.isArray(value.tolerances)
        || value.tolerances.length !== metrics.length) {
        throw new ContractError(
            "statisticalPolicy.control.tolerances must contain exactly one entry per metric",
        );
    }
    const metricByKey = new Map(metrics.map((metric) => [metric.key, metric]));
    const seen = new Set();
    const tolerances = value.tolerances.map((tolerance, index) => {
        const field = `statisticalPolicy.control.tolerances[${index}]`;
        requireExactObjectKeys(tolerance, field, CONTROL_TOLERANCE_KEYS);
        const metric = requireIdentifier(tolerance.metric, `${field}.metric`);
        if (seen.has(metric) || !metricByKey.has(metric)) {
            throw new ContractError(
                `${field}.metric must name one previously unused statistical metric`,
                { metric },
            );
        }
        seen.add(metric);
        const range = metricByKey.get(metric).maximum - metricByKey.get(metric).minimum;
        return {
            metric,
            absolute: requireFiniteNumberInRange(
                tolerance.absolute,
                `${field}.absolute`,
                0,
                range,
            ),
            relative: requireFiniteNumberInRange(
                tolerance.relative,
                `${field}.relative`,
                0,
                1,
            ),
        };
    });
    tolerances.sort((left, right) => left.metric.localeCompare(right.metric));
    return immutableCanonical({ kind: value.kind, identity, tolerances });
}

function normalizeMissingness(value) {
    requireExactObjectKeys(value, "statisticalPolicy.missingness", MISSINGNESS_KEYS);
    if (!MISSINGNESS_MODES.includes(value.mode)) {
        throw new ContractError(
            "statisticalPolicy.missingness.mode must be fail_closed or bounded",
        );
    }
    const maxMissingPerBlock = requireNonNegativeSafeInteger(
        value.maxMissingPerBlock,
        "statisticalPolicy.missingness.maxMissingPerBlock",
        CONTRACT_LIMITS.maxStatisticalEvaluations,
    );
    const maxMissingFraction = requireFiniteNumberInRange(
        value.maxMissingFraction,
        "statisticalPolicy.missingness.maxMissingFraction",
        0,
        1,
    );
    if (value.mode === "fail_closed"
        && (maxMissingPerBlock !== 0 || maxMissingFraction !== 0)) {
        throw new ContractError(
            "fail_closed missingness requires zero missing-count and missing-fraction tolerances",
        );
    }
    if (value.mode === "bounded"
        && maxMissingPerBlock === 0
        && maxMissingFraction === 0) {
        throw new ContractError(
            "bounded missingness must permit a positive bounded amount",
        );
    }
    return immutableCanonical({
        mode: value.mode,
        maxMissingPerBlock,
        maxMissingFraction,
    });
}

export function statisticalEvaluationRequirements({
    searchSlots,
    maxBlocks,
    maxConfirmations,
    validationCaseCount,
    validationRoleCount = VALIDATION_HARNESS_ROLES.length,
    hypothesisTopology,
}) {
    const validationSeriesCount = checkedProduct(
        [validationCaseCount, validationRoleCount],
        "statistical validation series",
    );
    const requiredValidationEvaluations = checkedProduct(
        [validationSeriesCount, maxBlocks],
        "required validation evaluations",
    );
    const confirmationRoleSlots = checkedProduct(
        [maxConfirmations, 3],
        "statistical confirmation role slots",
    );
    const experimentalSlots = checkedSum(
        [searchSlots, confirmationRoleSlots],
        "statistical experimental slots",
    );
    const requiredCandidateEvaluations = checkedProduct(
        [experimentalSlots, maxBlocks],
        "required candidate evaluations",
    );
    const requiredControlEvaluations = checkedProduct(
        [experimentalSlots, maxBlocks],
        "required control evaluations",
    );
    const verifierEvaluations = hypothesisTopology === "certified_impossibility" ? 1 : 0;
    const requiredTotalEvaluations = checkedSum(
        [
            requiredValidationEvaluations,
            requiredCandidateEvaluations,
            requiredControlEvaluations,
            verifierEvaluations,
        ],
        "required total evaluations",
    );
    return immutableCanonical({
        searchSlots,
        confirmationRoleSlots,
        requiredCandidateEvaluations,
        requiredControlEvaluations,
        validationCaseCount,
        validationRoleCount,
        validationSeriesCount,
        requiredValidationEvaluations,
        verifierEvaluations,
        requiredTotalEvaluations,
    });
}

function normalizeEvaluationBudget(value, requirements) {
    requireExactObjectKeys(
        value,
        "statisticalPolicy.evaluationBudget",
        EVALUATION_BUDGET_KEYS,
    );
    const budget = {
        maxCandidateEvaluations: requirePositiveSafeInteger(
            value.maxCandidateEvaluations,
            "statisticalPolicy.evaluationBudget.maxCandidateEvaluations",
            CONTRACT_LIMITS.maxStatisticalEvaluations,
        ),
        maxControlEvaluations: requirePositiveSafeInteger(
            value.maxControlEvaluations,
            "statisticalPolicy.evaluationBudget.maxControlEvaluations",
            CONTRACT_LIMITS.maxStatisticalEvaluations,
        ),
        maxTotalEvaluations: requirePositiveSafeInteger(
            value.maxTotalEvaluations,
            "statisticalPolicy.evaluationBudget.maxTotalEvaluations",
            CONTRACT_LIMITS.maxStatisticalEvaluations,
        ),
    };
    if (budget.maxCandidateEvaluations < requirements.requiredCandidateEvaluations
        || budget.maxControlEvaluations < requirements.requiredControlEvaluations) {
        throw new ContractError(
            "statisticalPolicy evaluation budgets cannot cover the frozen block/search/confirmation capacity",
            { requirements, budget },
        );
    }
    const allocatedTotal = checkedSum(
        [
            budget.maxCandidateEvaluations,
            budget.maxControlEvaluations,
            requirements.requiredValidationEvaluations,
            requirements.verifierEvaluations,
        ],
        "allocated total evaluations",
    );
    if (budget.maxTotalEvaluations < allocatedTotal
        || budget.maxTotalEvaluations < requirements.requiredTotalEvaluations) {
        throw new ContractError(
            "statisticalPolicy.evaluationBudget.maxTotalEvaluations is below its allocated capacity",
            { allocatedTotal, requirements, budget },
        );
    }
    return immutableCanonical(budget);
}

function normalizeResourceBudget(value, maxTotalEvaluations) {
    requireExactObjectKeys(
        value,
        "statisticalPolicy.resourceBudget",
        RESOURCE_BUDGET_KEYS,
    );
    const budget = {};
    for (const key of RESOURCE_BUDGET_KEYS) {
        budget[key] = requirePositiveSafeInteger(
            value[key],
            `statisticalPolicy.resourceBudget.${key}`,
            CONTRACT_LIMITS.maxResourceBytes,
        );
    }
    for (const kind of ["Output", "Receipt", "Cas"]) {
        const perAttempt = budget[`perAttempt${kind}Bytes`];
        const perInvestigation = budget[`perInvestigation${kind}Bytes`];
        if (perInvestigation < perAttempt
            || perInvestigation < maxTotalEvaluations) {
            throw new ContractError(
                `statisticalPolicy.resourceBudget.perInvestigation${kind}Bytes is impossible for the frozen attempt/evaluation budget`,
                {
                    perAttempt,
                    perInvestigation,
                    maxTotalEvaluations,
                },
            );
        }
    }
    return immutableCanonical(budget);
}

export function createStatisticalPolicy(input, context = {}) {
    requireObjectKeys(
        input,
        "statisticalPolicy",
        STATISTICAL_POLICY_KEYS,
        [],
    );
    if (input.version !== STATISTICAL_POLICY_VERSION) {
        throw new ContractError("statisticalPolicy.version is unsupported", {
            expected: STATISTICAL_POLICY_VERSION,
            actual: input.version,
        });
    }
    if (!GOAL_MODES.includes(input.goalMode)) {
        throw new ContractError("statisticalPolicy.goalMode must be satisfice or optimize");
    }
    const observableRegistry = normalizeObservableRegistry(
        context.observableRegistry ?? [],
    );
    const metrics = normalizeStatisticalMetrics(input.metrics, observableRegistry);
    const investigationAlpha = requireFiniteNumberInRange(
        input.investigationAlpha,
        "statisticalPolicy.investigationAlpha",
        Number.MIN_VALUE,
        1 - Number.EPSILON,
    );
    const familyAllocations = normalizeFamilyAllocations(
        input.familyAllocations,
        investigationAlpha,
        metrics,
    );
    const minBlocks = requirePositiveSafeInteger(
        input.minBlocks,
        "statisticalPolicy.minBlocks",
        CONTRACT_LIMITS.maxBlocks,
    );
    const maxBlocks = requirePositiveSafeInteger(
        input.maxBlocks,
        "statisticalPolicy.maxBlocks",
        CONTRACT_LIMITS.maxBlocks,
    );
    if (minBlocks > maxBlocks) {
        throw new ContractError(
            "statisticalPolicy.minBlocks cannot exceed maxBlocks",
            { minBlocks, maxBlocks },
        );
    }
    const maxConfirmations = requirePositiveSafeInteger(
        input.maxConfirmations,
        "statisticalPolicy.maxConfirmations",
        CONTRACT_LIMITS.maxConfirmations,
    );
    const requirements = statisticalEvaluationRequirements({
        searchSlots: context.searchSlots,
        maxBlocks,
        maxConfirmations,
        validationCaseCount: context.validationCaseCount,
        validationRoleCount: context.validationRoleCount,
        hypothesisTopology: context.hypothesisTopology,
    });
    const evaluationBudget = normalizeEvaluationBudget(
        input.evaluationBudget,
        requirements,
    );
    const resourceBudget = normalizeResourceBudget(
        input.resourceBudget,
        evaluationBudget.maxTotalEvaluations,
    );
    return immutableCanonical({
        version: STATISTICAL_POLICY_VERSION,
        goalMode: input.goalMode,
        metrics,
        investigationAlpha,
        familyAllocations,
        minBlocks,
        maxBlocks,
        control: normalizeStatisticalControl(
            input.control,
            metrics,
            context.enumerandManifest ?? null,
        ),
        missingness: normalizeMissingness(input.missingness),
        deterministicBlockSeed: requireBoundedText(
            input.deterministicBlockSeed,
            "statisticalPolicy.deterministicBlockSeed",
            256,
            512,
        ),
        maxConfirmations,
        evaluationBudget,
        resourceBudget,
    });
}

function normalizeEnumerandContract(
    input,
    topology,
    capacity,
    observableRegistry,
    hypothesisPolicy,
) {
    const requiresManifest =
        topology === "finite_enumerable"
        || topology === "bounded_parameterized"
        || topology === "certified_impossibility";
    const hasManifest = input !== undefined && input !== null;
    if (requiresManifest !== hasManifest) {
        throw new ContractError(
            requiresManifest
                ? "enumerandManifest is required for finite_enumerable, bounded_parameterized, and certified_impossibility topologies"
                : "enumerandManifest is forbidden for non-enumerable topologies",
        );
    }
    if (!hasManifest) return null;
    const enumerandTopology = topology === "certified_impossibility"
        ? input?.topology
        : topology;
    if (topology === "certified_impossibility"
        && enumerandTopology !== "finite_enumerable"
        && enumerandTopology !== "bounded_parameterized") {
        throw new ContractError(
            "certified_impossibility enumerandManifest must declare finite_enumerable or bounded_parameterized topology",
        );
    }
    const manifest = normalizeEnumerandManifest(input, {
        topology: enumerandTopology,
        observableRegistry,
        hypothesisPolicy,
    });
    if (manifest.entries.length > capacity) {
        throw new ContractError(
            "search capacity must cover every immutable enumerand",
            { enumerands: manifest.entries.length, capacity },
        );
    }
    return manifest;
}

export function createInvestigationContract(input) {
    if (input !== null
        && typeof input === "object"
        && !Array.isArray(input)
        && Object.hasOwn(input, "statisticalPolicyIdentity")) {
        requireObjectKeys(
            input,
            "Sealed investigation contract",
            CONTRACT_OUTPUT_REQUIRED_KEYS,
            CONTRACT_OUTPUT_OPTIONAL_KEYS,
        );
        const normalized = createInvestigationContract({
            domainVersion: input.domainVersion,
            objective: input.objective,
            acceptancePredicate: input.acceptancePredicate,
            harnessSuite: input.harnessSuite,
            harnessSuiteIdentity: input.harnessSuiteIdentity,
            hypothesisTopology: input.hypothesisTopology,
            criticality: input.criticality,
            policyVersion: input.policyVersion,
            runtimeIdentityPolicy: input.runtimeIdentityPolicy,
            runtimeIdentityPolicyIdentity: input.runtimeIdentityPolicyIdentity,
            runtimeIdentityRoot: input.runtimeIdentityRoot,
            workerModels: input.workerModels,
            candidatesPerRound: input.candidatesPerRound,
            maxRounds: input.maxRounds,
            searchPolicy: input.searchPolicy,
            observableRegistry: input.observableRegistry,
            hypothesisPolicy: input.hypothesisPolicy,
            statisticalPolicy: input.statisticalPolicy,
            workingSetPolicy: input.workingSetPolicy,
            ...(input.enumerandManifest === undefined
                ? {}
                : { enumerandManifest: input.enumerandManifest }),
            ...(input.impossibilityPolicy === undefined
                ? {}
                : { impossibilityPolicy: input.impossibilityPolicy }),
        });
        if (!canonicalEqual(normalized, input)) {
            throw new ContractError(
                "Sealed investigation contract was mutated or is not canonical",
                {
                    expectedHash: contractHash(normalized),
                    actualHash: hashCanonical(input, CONTRACT_HASH_ALGORITHM),
                },
            );
        }
        return normalized;
    }
    requireObjectKeys(
        input,
        "Investigation contract input",
        CONTRACT_INPUT_REQUIRED_KEYS,
        CONTRACT_INPUT_OPTIONAL_KEYS,
    );
    if (Object.hasOwn(input, "domainVersion")
        && input.domainVersion !== DOMAIN_VERSION) {
        throw new DomainVersionRestartRequiredError(
            "Investigation contract uses an incompatible domain version; start a new investigation",
            {
                expectedDomainVersion: DOMAIN_VERSION,
                actualDomainVersion: input.domainVersion ?? null,
            },
        );
    }
    if (!HYPOTHESIS_TOPOLOGIES.includes(input.hypothesisTopology)) {
        throw new ContractError("hypothesisTopology is not supported", {
            hypothesisTopology: input.hypothesisTopology ?? null,
        });
    }

    const objective = requireBoundedText(
        input.objective,
        "objective",
        CONTRACT_LIMITS.objectiveCharacters,
        CONTRACT_LIMITS.objectiveBytes,
    );
    const observableRegistry = normalizeObservableRegistry(input.observableRegistry);
    const hypothesisPolicy = normalizeHypothesisPolicy(input.hypothesisPolicy);
    if (hypothesisPolicy.required && observableRegistry.length === 0) {
        throw new ContractError(
            "A required hypothesisPolicy needs at least one registered observable",
        );
    }
    const search = normalizeSearch(input, input.hypothesisTopology);
    const searchCapacity = checkedProduct(
        [search.candidatesPerRound, search.maxRounds],
        "search capacity",
    );
    const enumerandManifest = normalizeEnumerandContract(
        input.enumerandManifest,
        input.hypothesisTopology,
        searchCapacity,
        observableRegistry,
        hypothesisPolicy,
    );
    if (hypothesisPolicy.required && enumerandManifest === null) {
        throw new ContractError(
            "A required hypothesisPolicy needs operator-frozen enumerand hypotheses",
        );
    }
    const harness = normalizeHarnessSuiteContract(
        input.harnessSuite,
        input.harnessSuiteIdentity,
        input.statisticalPolicy?.goalMode,
        input.hypothesisTopology,
    );
    const validationCases = normalizeValidationCases(
        harnessSuiteRoleCases(harness.suite, "calibration"),
    );
    const validationRoles = immutableCanonical([...VALIDATION_HARNESS_ROLES]);
    const statisticalPolicy = createStatisticalPolicy(input.statisticalPolicy, {
        observableRegistry,
        enumerandManifest,
        searchSlots: enumerandManifest?.entries.length ?? searchCapacity,
        validationCaseCount: validationCases.length,
        validationRoleCount: validationRoles.length,
        hypothesisTopology: input.hypothesisTopology,
    });
    const searchPolicy = createSearchPolicy(input.searchPolicy);
    if (!canonicalEqual(searchPolicy, input.searchPolicy)) {
        throw new ContractError("searchPolicy must already be in canonical kernel form");
    }
    const impossibilityPolicy = normalizeImpossibilityPolicy(
        input.impossibilityPolicy,
        input.hypothesisTopology,
    );
    const runtimeIdentityPolicy = normalizeRuntimeIdentityPolicy(
        input.runtimeIdentityPolicy,
    );
    const workingSetPolicy = normalizeWorkingSetPolicy(
        input.workingSetPolicy,
    );
    const normalizedRuntimeIdentityPolicyIdentity =
        runtimeIdentityPolicyIdentity(runtimeIdentityPolicy);
    if (input.runtimeIdentityPolicyIdentity
        !== normalizedRuntimeIdentityPolicyIdentity) {
        throw new ContractError(
            "runtimeIdentityPolicyIdentity does not match the frozen runtime identity policy",
            {
                expected: normalizedRuntimeIdentityPolicyIdentity,
                actual: input.runtimeIdentityPolicyIdentity ?? null,
            },
        );
    }
    const runtimeIdentityRoot = requireTaggedSha256(
        input.runtimeIdentityRoot,
        "runtimeIdentityRoot",
    );
    if (!runtimeIdentityRoot.startsWith(`${RUNTIME_IDENTITY_ROOT_ALGORITHM}:`)) {
        throw new ContractError(
            `runtimeIdentityRoot must use ${RUNTIME_IDENTITY_ROOT_ALGORITHM}`,
            { actual: runtimeIdentityRoot },
        );
    }
    const parserVersion = requireIdentifier(
        harness.suite.roles.search.parser.version,
        "harnessSuite.roles.search.parser.version",
    );
    const rankingMetrics = statisticalPolicy.metrics.map((metric) => ({
        key: metric.key,
        priority: metric.priority,
        direction: metric.direction,
        epsilon: metric.practicalEquivalenceDelta,
    }));
    const acceptancePredicate = normalizePredicate(input.acceptancePredicate);
    let acceptanceClaimSet;
    try {
        acceptanceClaimSet = statisticalAcceptanceClaimSet({
            acceptancePredicate,
            statisticalPolicy,
        });
    } catch (error) {
        if (!(error instanceof StatisticsError)) throw error;
        throw new ContractError(
            `acceptancePredicate is not a valid frozen statistical claim set: ${error.message}`,
            { cause: error.code, details: error.details ?? null },
        );
    }
    const validationFamily = statisticalPolicy.familyAllocations[0].family;
    const validationClaimSet = immutableCanonical({
        claims: [{
            id: "validation.harness_pass",
            kind: "harness_pass",
            expected: true,
            family: validationFamily,
            source: "operator_signed_validation_corpus",
        }],
        requiredClaimIds: ["validation.harness_pass"],
    });
    const contract = {
        domainVersion: DOMAIN_VERSION,
        objective,
        acceptancePredicate,
        acceptanceClaimSet,
        validationCases,
        validationClaimSet,
        validationRoles,
        harnessSuite: harness.suite,
        harnessSuiteIdentity: harness.identity,
        harnessId: harness.suite.roles.search.harnessId,
        hypothesisTopology: input.hypothesisTopology,
        criticality: requireNonEmptyString(input.criticality, "criticality", 64),
        policyVersion: requireIdentifier(input.policyVersion, "policyVersion"),
        runtimeIdentityPolicy,
        runtimeIdentityPolicyIdentity:
            normalizedRuntimeIdentityPolicyIdentity,
        runtimeIdentityRoot,
        parserVersion,
        workerModels: search.workerModels,
        candidatesPerRound: search.candidatesPerRound,
        maxRounds: search.maxRounds,
        ...(enumerandManifest === null ? {} : { enumerandManifest }),
        metrics: rankingMetrics,
        observableRegistry,
        observableRegistryIdentity: observableRegistryIdentity(observableRegistry),
        hypothesisPolicy,
        hypothesisPolicyIdentity: hypothesisPolicyIdentity(hypothesisPolicy),
        statisticalPolicy,
        statisticalPolicyIdentity: hashCanonical(
            statisticalPolicy,
            STATISTICAL_POLICY_HASH_ALGORITHM,
        ),
        workingSetPolicy,
        searchPolicy,
        scientificTerminalPolicy: DEFAULT_SCIENTIFIC_TERMINAL_POLICY,
        ...(impossibilityPolicy === null ? {} : { impossibilityPolicy }),
        declaredLimits: {},
    };

    return immutableCanonical(contract);
}

export function contractHash(contract) {
    return hashCanonical(contract, CONTRACT_HASH_ALGORITHM);
}
