export const ASSURANCE_SCHEMA_REVISION = 6;

export const ASSURANCE_LEVELS = Object.freeze([
    "unsupported",
    "partial",
    "bounded-static",
    "comprehensive-static",
    "comprehensive-static-with-supply-chain",
]);

export const EVASION_CLASSES = Object.freeze({
    UNSUPPORTED_OR_OPAQUE_ARTIFACTS: "unsupported-or-opaque-artifacts",
    ENCODING_AND_PARSER_DIFFERENTIALS: "encoding-and-parser-differentials",
    OBFUSCATION_GENERATION_AND_SELF_MODIFICATION:
        "obfuscation-generation-and-self-modification",
    INDIRECTION_REFLECTION_AND_DATA_DRIVEN_EXECUTION:
        "indirection-reflection-and-data-driven-execution",
    ENVIRONMENT_TIME_AND_STATE_GATED_ACTIVATION:
        "environment-time-and-state-gated-activation",
    DYNAMIC_CODE_AND_EXTERNAL_PAYLOAD_LOADING:
        "dynamic-code-and-external-payload-loading",
    BINARY_AND_EMBEDDED_PAYLOADS: "binary-and-embedded-payloads",
    CROSS_LANGUAGE_AND_BUILD_GRAPH_INDIRECTION:
        "cross-language-and-build-graph-indirection",
    REVIEWER_MANIPULATION_AND_PROMPT_INJECTION:
        "reviewer-manipulation-and-prompt-injection",
    DEPENDENCY_RESOLUTION_AND_PACKAGE_SUBSTITUTION:
        "dependency-resolution-and-package-substitution",
    RELEASE_SOURCE_AND_ARTIFACT_DIVERGENCE:
        "release-source-and-artifact-divergence",
});

export const EVASION_CLASS_VALUES = Object.freeze(Object.values(EVASION_CLASSES));

export const SUPPLY_CHAIN_EVASION_CLASSES = Object.freeze([
    EVASION_CLASSES.DEPENDENCY_RESOLUTION_AND_PACKAGE_SUBSTITUTION,
    EVASION_CLASSES.RELEASE_SOURCE_AND_ARTIFACT_DIVERGENCE,
]);

export const ASSURANCE_COVERAGE_STATUSES = Object.freeze([
    "unassessed",
    "partial",
    "bounded",
    "comprehensive",
]);

export const ARTIFACT_SUPPORT_LEVELS = Object.freeze([
    "supported",
    "unsupported",
]);

export const ASSURANCE_BLOCKERS = Object.freeze({
    UNSUPPORTED_ARTIFACT: "unsupported-artifact",
    IDENTITY_NOT_PINNED: "identity-not-pinned",
    INCOMPLETE_ACQUISITION: "incomplete-acquisition",
    COVERAGE_TRUNCATED: "coverage-truncated",
    INCOMPLETE_SYNTACTIC_COVERAGE: "incomplete-syntactic-coverage",
    INCOMPLETE_SEMANTIC_COVERAGE: "incomplete-semantic-coverage",
    INCOMPLETE_ACTIVATION_COVERAGE: "incomplete-activation-coverage",
    INCOMPLETE_BEHAVIOR_TRACING: "incomplete-behavior-tracing",
    INCOMPLETE_VALIDATION: "incomplete-validation",
    UNRESOLVED_PARSER_DIFFERENTIAL: "unresolved-parser-differential",
    UNRESOLVED_DYNAMIC_BEHAVIOR: "unresolved-dynamic-behavior",
    UNRESOLVED_EXTERNAL_PAYLOAD: "unresolved-external-payload",
    INCOMPLETE_BINARY_PAYLOAD_COVERAGE: "incomplete-binary-payload-coverage",
    UNRESOLVED_REVIEWER_MANIPULATION: "unresolved-reviewer-manipulation",
    INCOMPLETE_SUPPLY_CHAIN: "incomplete-supply-chain",
    UNRESOLVED_RELEASE_SOURCE_DIVERGENCE:
        "unresolved-release-source-divergence",
});

export const ASSURANCE_BLOCKER_CODES = Object.freeze(
    Object.values(ASSURANCE_BLOCKERS),
);

export const ASSURANCE_LIMITS = Object.freeze({
    blockers: 64,
});

const SUPPLY_CHAIN_CLASS_SET = new Set(SUPPLY_CHAIN_EVASION_CLASSES);
const CORE_EVASION_CLASSES = Object.freeze(
    EVASION_CLASS_VALUES.filter((value) => !SUPPLY_CHAIN_CLASS_SET.has(value)),
);
const UNSUPPORTED_BLOCKER_SET = new Set([
    ASSURANCE_BLOCKERS.UNSUPPORTED_ARTIFACT,
]);
const SUPPLY_CHAIN_BLOCKER_SET = new Set([
    ASSURANCE_BLOCKERS.INCOMPLETE_SUPPLY_CHAIN,
    ASSURANCE_BLOCKERS.UNRESOLVED_RELEASE_SOURCE_DIVERGENCE,
]);
const COVERAGE_RANK = Object.freeze({
    unassessed: 0,
    partial: 0,
    bounded: 1,
    comprehensive: 2,
});

const ASSURANCE_WORDING = Object.freeze({
    unsupported: Object.freeze({
        label: "Assurance: unsupported",
        summary:
            "Assurance could not be established because the artifact is outside the supported static-analysis contract.",
    }),
    partial: Object.freeze({
        label: "Assurance: partial",
        summary:
            "Assurance is partial because required static-analysis coverage or resolution remains incomplete.",
    }),
    "bounded-static": Object.freeze({
        label: "Assurance: bounded static",
        summary:
            "The audit achieved bounded static assurance over the declared evasion classes and recorded evidence.",
    }),
    "comprehensive-static": Object.freeze({
        label: "Assurance: comprehensive static",
        summary:
            "The audit achieved comprehensive static assurance over the declared non-supply-chain evasion classes.",
    }),
    "comprehensive-static-with-supply-chain": Object.freeze({
        label: "Assurance: comprehensive static with supply-chain coverage",
        summary:
            "The audit achieved comprehensive static assurance over the declared evasion classes, including supply-chain coverage.",
    }),
});

const WORDING_DISTINCTION =
    "The findings verdict reports supported malicious-behavior findings; assurance reports evidence and evasion-class coverage.";
const WORDING_LIMITATION =
    "This static result is not a guarantee about runtime behavior or an absence of malicious behavior. Host build execution is neither isolation nor assurance evidence.";

export class AssuranceContractError extends TypeError {
    constructor(path, message) {
        super(`${path}: ${message}`);
        this.name = "AssuranceContractError";
        this.path = path;
    }
}

function fail(path, message) {
    throw new AssuranceContractError(path, message);
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

function enumValue(value, path, allowed) {
    if (!allowed.includes(value)) {
        fail(path, `must be one of: ${allowed.join(", ")}`);
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

function compareTokens(left, right) {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
}

function normalizeCoverage(value, path) {
    objectShape(value, path, EVASION_CLASS_VALUES);
    const normalized = {};
    for (const evasionClass of EVASION_CLASS_VALUES) {
        normalized[evasionClass] = enumValue(
            value[evasionClass],
            `${path}.${evasionClass}`,
            ASSURANCE_COVERAGE_STATUSES,
        );
    }
    return cloneFrozen(normalized);
}

function normalizeBlockers(value, path) {
    if (!Array.isArray(value)) fail(path, "must be an array");
    if (value.length > ASSURANCE_LIMITS.blockers) {
        fail(path, `must contain at most ${ASSURANCE_LIMITS.blockers} entries`);
    }
    const normalized = value.map((blocker, index) => {
        const blockerPath = `${path}[${index}]`;
        objectShape(blocker, blockerPath, ["code", "evasionClass"]);
        return {
            code: enumValue(
                blocker.code,
                `${blockerPath}.code`,
                ASSURANCE_BLOCKER_CODES,
            ),
            evasionClass: enumValue(
                blocker.evasionClass,
                `${blockerPath}.evasionClass`,
                EVASION_CLASS_VALUES,
            ),
        };
    });
    const identities = normalized.map((blocker) =>
        `${blocker.code}\0${blocker.evasionClass}`);
    if (new Set(identities).size !== identities.length) {
        fail(path, "must not contain duplicate blocker identities");
    }
    normalized.sort((left, right) =>
        compareTokens(left.code, right.code)
        || compareTokens(left.evasionClass, right.evasionClass));
    return cloneFrozen(normalized);
}

function aggregateCoverage(coverage, evasionClasses) {
    let minimum = 2;
    for (const evasionClass of evasionClasses) {
        minimum = Math.min(minimum, COVERAGE_RANK[coverage[evasionClass]]);
    }
    if (minimum === 0) return "incomplete";
    if (minimum === 1) return "bounded";
    return "comprehensive";
}

function computeLevel(normalized, basis) {
    if (normalized.artifactSupport === "unsupported"
        || normalized.blockers.some((blocker) =>
            UNSUPPORTED_BLOCKER_SET.has(blocker.code))) {
        return "unsupported";
    }
    if (basis.blockerCap === "partial"
        || basis.staticCoverage === "incomplete") {
        return "partial";
    }
    if (basis.staticCoverage === "bounded") return "bounded-static";
    if (basis.supplyChainCoverage !== "comprehensive"
        || basis.blockerCap === "comprehensive-static") {
        return "comprehensive-static";
    }
    return "comprehensive-static-with-supply-chain";
}

function buildBasis(normalized) {
    let blockerCap = null;
    if (normalized.artifactSupport === "unsupported"
        || normalized.blockers.some((blocker) =>
            UNSUPPORTED_BLOCKER_SET.has(blocker.code))) {
        blockerCap = "unsupported";
    } else if (normalized.blockers.some((blocker) =>
        !SUPPLY_CHAIN_BLOCKER_SET.has(blocker.code))) {
        blockerCap = "partial";
    } else if (normalized.blockers.length > 0) {
        blockerCap = "comprehensive-static";
    }
    return cloneFrozen({
        staticCoverage: aggregateCoverage(
            normalized.coverage,
            CORE_EVASION_CLASSES,
        ),
        supplyChainCoverage: aggregateCoverage(
            normalized.coverage,
            SUPPLY_CHAIN_EVASION_CLASSES,
        ),
        blockerCap,
        analysisScope: "static-only",
        hostBuildEvidence: "not-isolation-or-assurance-evidence",
    });
}

export function renderAssuranceWording(assuranceLevel) {
    const level = enumValue(
        assuranceLevel,
        "assuranceLevel",
        ASSURANCE_LEVELS,
    );
    return cloneFrozen({
        ...ASSURANCE_WORDING[level],
        distinction: WORDING_DISTINCTION,
        limitation: WORDING_LIMITATION,
    });
}

export function normalizeAssuranceInputs(value, path = "assuranceInputs") {
    objectShape(value, path, [
        "schemaVersion",
        "artifactSupport",
        "coverage",
        "blockers",
    ]);
    if (value.schemaVersion !== ASSURANCE_SCHEMA_REVISION) {
        fail(
            `${path}.schemaVersion`,
            `must equal ${ASSURANCE_SCHEMA_REVISION}; baseline state is not assurance state`,
        );
    }
    return cloneFrozen({
        schemaVersion: ASSURANCE_SCHEMA_REVISION,
        artifactSupport: enumValue(
            value.artifactSupport,
            `${path}.artifactSupport`,
            ARTIFACT_SUPPORT_LEVELS,
        ),
        coverage: normalizeCoverage(value.coverage, `${path}.coverage`),
        blockers: normalizeBlockers(value.blockers, `${path}.blockers`),
    });
}

export function computeAssurance(value) {
    const normalized = normalizeAssuranceInputs(value);
    const basis = buildBasis(normalized);
    const assuranceLevel = computeLevel(normalized, basis);
    return cloneFrozen({
        ...normalized,
        assuranceLevel,
        basis,
        wording: renderAssuranceWording(assuranceLevel),
    });
}

export function validateAssuranceResult(value, path = "assuranceResult") {
    objectShape(value, path, [
        "schemaVersion",
        "artifactSupport",
        "coverage",
        "blockers",
        "assuranceLevel",
        "basis",
        "wording",
    ]);
    enumValue(
        value.assuranceLevel,
        `${path}.assuranceLevel`,
        ASSURANCE_LEVELS,
    );
    const expected = computeAssurance({
        schemaVersion: value.schemaVersion,
        artifactSupport: value.artifactSupport,
        coverage: value.coverage,
        blockers: value.blockers,
    });

    objectShape(value.basis, `${path}.basis`, [
        "staticCoverage",
        "supplyChainCoverage",
        "blockerCap",
        "analysisScope",
        "hostBuildEvidence",
    ]);
    objectShape(value.wording, `${path}.wording`, [
        "label",
        "summary",
        "distinction",
        "limitation",
    ]);
    if (value.assuranceLevel !== expected.assuranceLevel
        || value.basis.staticCoverage !== expected.basis.staticCoverage
        || value.basis.supplyChainCoverage
            !== expected.basis.supplyChainCoverage
        || value.basis.blockerCap !== expected.basis.blockerCap
        || value.basis.analysisScope !== expected.basis.analysisScope
        || value.basis.hostBuildEvidence !== expected.basis.hostBuildEvidence
        || value.wording.label !== expected.wording.label
        || value.wording.summary !== expected.wording.summary
        || value.wording.distinction !== expected.wording.distinction
        || value.wording.limitation !== expected.wording.limitation) {
        fail(path, "must match the deterministic assurance computation");
    }
    return expected;
}

export const __internals = Object.freeze({
    CORE_EVASION_CLASSES,
    SUPPLY_CHAIN_BLOCKER_CODES: Object.freeze([...SUPPLY_CHAIN_BLOCKER_SET]),
});
