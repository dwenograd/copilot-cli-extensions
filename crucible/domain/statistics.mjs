// Pure v4 bounded-inference kernel. It consumes only a sealed statistical
// policy, a complete frozen claim set, stable candidate/enumerand indices, and
// raw indexed blocks. Runtime scheduling deliberately does not live here.
//
// Family alpha is split by the telescoping subject schedule 1/(k(k+1)), then
// equally across the frozen claims in that family. At look n, the claim alpha
// is split again as alpha_n = alpha_claim/(n(n+1)). Two-sided Hoeffding bounds
// at each look plus the union bound therefore form an anytime-valid sequence.
// Missing values allowed by policy remain worst-case intervals; they are never
// silently dropped or imputed with a point estimate.

import {
    canonicalEqual,
    immutableCanonical,
} from "./canonical.mjs";
import {
    CONTRACT_LIMITS,
    STATISTICAL_ALLOCATION_SCHEDULE,
    STATISTICAL_CLAIM_STATES,
    STATISTICAL_DEFAULT_SUCCESS_PROBABILITY_THRESHOLD,
    STATISTICAL_ERROR_CODES,
    STATISTICAL_KERNEL_VERSION,
    STATISTICAL_POLICY_VERSION,
} from "./constants.mjs";

const CLAIM_STATE = Object.freeze(
    Object.fromEntries(STATISTICAL_CLAIM_STATES.map((state) => [state, state])),
);
const THRESHOLD_OPERATORS = new Set(["<", "<=", ">=", ">"]);
const DIRECTIONS = new Set(["increase", "decrease"]);
const SAFE_IDENTIFIER = /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;
// Confirmation reserves confirmation, challenge, and guard lanes per member.
export const SEARCH_ALPHA_CONFIRMATION_LANES_PER_MEMBER = 3;

export class StatisticsError extends Error {
    constructor(code, message, details = null) {
        super(message);
        this.name = "StatisticsError";
        this.code = code;
        this.details = details;
    }
}

function fail(code, message, details = null) {
    throw new StatisticsError(code, message, details);
}

function cleanNumber(value) {
    return Object.is(value, -0) ? 0 : value;
}

function lexicalCompare(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

function clamp(value, lower, upper) {
    return cleanNumber(Math.min(upper, Math.max(lower, value)));
}

function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function requirePlainObject(value, field, code = STATISTICAL_ERROR_CODES.INVALID_ARGUMENT) {
    if (!isPlainObject(value)) {
        fail(code, `${field} must be a plain object`, { field });
    }
    return value;
}

function requireIdentifier(value, field, code = STATISTICAL_ERROR_CODES.INVALID_CLAIM) {
    if (typeof value !== "string" || !SAFE_IDENTIFIER.test(value)) {
        fail(code, `${field} must be a safe identifier`, { field });
    }
    return value;
}

function requireFinite(value, field, code = STATISTICAL_ERROR_CODES.INVALID_ARGUMENT) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        fail(code, `${field} must be finite`, {
            field,
            received: typeof value === "number" ? "nonfinite_number" : typeof value,
        });
    }
    return cleanNumber(value);
}

function requirePositiveAlpha(value, field) {
    const alpha = requireFinite(
        value,
        field,
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    if (!(alpha > 0 && alpha < 1)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            `${field} must be strictly between zero and one`,
            { field },
        );
    }
    return alpha;
}

function requireNonNegativeSafeInteger(
    value,
    field,
    maximum = Number.MAX_SAFE_INTEGER,
    code = STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
        fail(code, `${field} must be a non-negative safe integer`, {
            field,
            maximum,
        });
    }
    return value;
}

function requirePositiveSafeInteger(
    value,
    field,
    maximum = Number.MAX_SAFE_INTEGER,
    code = STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        fail(code, `${field} must be a positive safe integer`, {
            field,
            maximum,
        });
    }
    return value;
}

function compensatedSum(values) {
    let sum = 0;
    let correction = 0;
    for (const value of values) {
        const next = sum + value;
        correction += Math.abs(sum) >= Math.abs(value)
            ? (sum - next) + value
            : (value - next) + sum;
        sum = next;
    }
    return cleanNumber(sum + correction);
}

function representableProbability(logProbability) {
    if (logProbability < Math.log(Number.MIN_VALUE)) {
        return {
            probability: 0,
            underflowed: true,
        };
    }
    const probability = Math.exp(logProbability);
    return {
        probability: cleanNumber(probability),
        underflowed: probability === 0,
    };
}

function normalizeBounds(bounds, field = "bounds") {
    requirePlainObject(bounds, field);
    const minimum = requireFinite(
        bounds.minimum,
        `${field}.minimum`,
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    const maximum = requireFinite(
        bounds.maximum,
        `${field}.maximum`,
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    if (!(minimum < maximum)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            `${field}.minimum must be less than maximum`,
            { field, minimum, maximum },
        );
    }
    return { minimum, maximum, range: maximum - minimum };
}

export function normalizeBoundedObservation(value, bounds) {
    const normalizedBounds = normalizeBounds(bounds);
    const observation = requireFinite(
        value,
        "observation",
        STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
    );
    if (observation < normalizedBounds.minimum
        || observation > normalizedBounds.maximum) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
            "observation is outside its frozen finite bounds",
            {
                minimum: normalizedBounds.minimum,
                maximum: normalizedBounds.maximum,
                relation: observation < normalizedBounds.minimum ? "below" : "above",
            },
        );
    }
    if (observation === normalizedBounds.minimum) return 0;
    if (observation === normalizedBounds.maximum) return 1;
    return clamp(
        (observation - normalizedBounds.minimum) / normalizedBounds.range,
        0,
        1,
    );
}

export function normalizeBinaryObservation(value) {
    if (value === false || value === 0) return 0;
    if (value === true || value === 1) return 1;
    fail(
        STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
        "binary observation must be boolean or exactly zero/one",
        { received: typeof value },
    );
}

export function statisticalScheduleWeight(index) {
    const scheduleIndex = requirePositiveSafeInteger(
        index,
        "schedule index",
        CONTRACT_LIMITS.maxStatisticalEvaluations + 1,
    );
    return cleanNumber((1 / scheduleIndex) / (scheduleIndex + 1));
}

export function searchAlphaSubjectOrdinal({
    searchSlots,
    maxConfirmations,
    globalSlot,
    replacementOrdinal,
}) {
    const normalizedSearchSlots = requirePositiveSafeInteger(
        searchSlots,
        "searchSlots",
        CONTRACT_LIMITS.maxStatisticalEvaluations,
    );
    const normalizedMaxConfirmations = requirePositiveSafeInteger(
        maxConfirmations,
        "maxConfirmations",
        CONTRACT_LIMITS.maxConfirmations,
    );
    const normalizedGlobalSlot = requireNonNegativeSafeInteger(
        globalSlot,
        "globalSlot",
        normalizedSearchSlots - 1,
    );
    const normalizedReplacementOrdinal = requireNonNegativeSafeInteger(
        replacementOrdinal,
        "replacementOrdinal",
    );
    const ordinal = normalizedReplacementOrdinal === 0
        ? BigInt(normalizedGlobalSlot)
        : BigInt(normalizedSearchSlots)
            + BigInt(normalizedMaxConfirmations)
                * BigInt(SEARCH_ALPHA_CONFIRMATION_LANES_PER_MEMBER)
            + BigInt(normalizedReplacementOrdinal - 1)
                * BigInt(normalizedSearchSlots)
            + BigInt(normalizedGlobalSlot);
    const maximumOrdinal = BigInt(Math.floor(
        (CONTRACT_LIMITS.maxStatisticalEvaluations - 2) / 2,
    ));
    if (ordinal > maximumOrdinal) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "search allocation exhausts the preregistered statistical subject lanes",
            {
                searchSlots: normalizedSearchSlots,
                maxConfirmations: normalizedMaxConfirmations,
                globalSlot: normalizedGlobalSlot,
                replacementOrdinal: normalizedReplacementOrdinal,
                maximumOrdinal: Number(maximumOrdinal),
            },
        );
    }
    return Number(ordinal);
}

function inspectStatisticalPolicy(statisticalPolicy) {
    requirePlainObject(
        statisticalPolicy,
        "statisticalPolicy",
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    if (statisticalPolicy.version !== STATISTICAL_POLICY_VERSION) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy.version is not the frozen v4 policy",
            {
                expected: STATISTICAL_POLICY_VERSION,
                actual: typeof statisticalPolicy.version === "string"
                    ? statisticalPolicy.version
                    : null,
            },
        );
    }
    const investigationAlpha = requirePositiveAlpha(
        statisticalPolicy.investigationAlpha,
        "statisticalPolicy.investigationAlpha",
    );
    if (!Array.isArray(statisticalPolicy.familyAllocations)
        || statisticalPolicy.familyAllocations.length === 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy.familyAllocations must be non-empty",
        );
    }
    const familyAllocations = statisticalPolicy.familyAllocations.map(
        (allocation, index) => {
            requirePlainObject(
                allocation,
                `statisticalPolicy.familyAllocations[${index}]`,
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
            );
            const family = requireIdentifier(
                allocation.family,
                `statisticalPolicy.familyAllocations[${index}].family`,
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
            );
            const alpha = requirePositiveAlpha(
                allocation.alpha,
                `statisticalPolicy.familyAllocations[${index}].alpha`,
            );
            if (alpha > investigationAlpha) {
                fail(
                    STATISTICAL_ERROR_CODES.INVALID_POLICY,
                    "statisticalPolicy family alpha exceeds investigation alpha",
                    { family },
                );
            }
            return {
                family,
                alpha,
            };
        },
    ).sort((left, right) => lexicalCompare(left.family, right.family));
    const familyByName = new Map();
    for (const allocation of familyAllocations) {
        if (familyByName.has(allocation.family)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
                "statisticalPolicy family names must be unique",
                { family: allocation.family },
            );
        }
        familyByName.set(allocation.family, allocation);
    }
    const nominalFamilySum = compensatedSum(
        familyAllocations.map((allocation) => allocation.alpha),
    );
    const familySumTolerance = Math.max(
        1e-12,
        investigationAlpha * 1e-12,
    );
    if (Math.abs(nominalFamilySum - investigationAlpha)
        > familySumTolerance) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy family allocations do not sum to investigation alpha",
            {
                investigationAlpha,
                nominalFamilySum,
                tolerance: familySumTolerance,
            },
        );
    }
    const familyScale = nominalFamilySum > investigationAlpha
        ? cleanNumber(
            (investigationAlpha / nominalFamilySum)
                * (1 - 8 * Number.EPSILON),
        )
        : 1;
    if (!(familyScale > 0 && familyScale <= 1)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy family alpha normalization is invalid",
        );
    }

    if (!Array.isArray(statisticalPolicy.metrics)
        || statisticalPolicy.metrics.length === 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy.metrics must be non-empty",
        );
    }
    const metricByKey = new Map();
    const metrics = statisticalPolicy.metrics.map((metric, index) => {
        requirePlainObject(
            metric,
            `statisticalPolicy.metrics[${index}]`,
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
        );
        const key = requireIdentifier(
            metric.key,
            `statisticalPolicy.metrics[${index}].key`,
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
        );
        if (metricByKey.has(key)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
                "statisticalPolicy metric keys must be unique",
                { key },
            );
        }
        const bounds = normalizeBounds(
            metric,
            `statisticalPolicy.metrics[${index}]`,
        );
        const family = requireIdentifier(
            metric.family,
            `statisticalPolicy.metrics[${index}].family`,
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
        );
        if (!familyByName.has(family)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
                "statisticalPolicy metric names an unallocated family",
                { key, family },
            );
        }
        if (metric.direction !== "min" && metric.direction !== "max") {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
                "statisticalPolicy metric direction must be min or max",
                { key },
            );
        }
        const acceptanceThreshold = requireFinite(
            metric.acceptanceThreshold,
            `statisticalPolicy.metrics[${index}].acceptanceThreshold`,
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
        );
        if (acceptanceThreshold < bounds.minimum
            || acceptanceThreshold > bounds.maximum) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
                "statisticalPolicy acceptance threshold is outside metric bounds",
                { key },
            );
        }
        const practicalEquivalenceDelta = requireFinite(
            metric.practicalEquivalenceDelta,
            `statisticalPolicy.metrics[${index}].practicalEquivalenceDelta`,
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
        );
        if (!(practicalEquivalenceDelta > 0
            && practicalEquivalenceDelta <= bounds.range)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
                "statisticalPolicy practical equivalence delta is invalid",
                { key },
            );
        }
        const normalized = {
            ...bounds,
            key,
            family,
            direction: metric.direction,
            acceptanceThreshold,
            practicalEquivalenceDelta,
        };
        metricByKey.set(key, normalized);
        return normalized;
    }).sort((left, right) => lexicalCompare(left.key, right.key));
    const metricFamilies = new Set(metrics.map((metric) => metric.family));
    const unusedFamilies = familyAllocations
        .map((allocation) => allocation.family)
        .filter((family) => !metricFamilies.has(family));
    if (unusedFamilies.length > 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy family allocations must exactly partition metric families",
            { unusedFamilies },
        );
    }

    const minBlocks = requirePositiveSafeInteger(
        statisticalPolicy.minBlocks,
        "statisticalPolicy.minBlocks",
        CONTRACT_LIMITS.maxBlocks,
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    const maxBlocks = requirePositiveSafeInteger(
        statisticalPolicy.maxBlocks,
        "statisticalPolicy.maxBlocks",
        CONTRACT_LIMITS.maxBlocks,
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    if (minBlocks > maxBlocks) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy.minBlocks exceeds maxBlocks",
        );
    }
    requirePlainObject(
        statisticalPolicy.missingness,
        "statisticalPolicy.missingness",
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    const missingness = statisticalPolicy.missingness;
    if (missingness.mode !== "fail_closed" && missingness.mode !== "bounded") {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy missingness mode is invalid",
        );
    }
    const maxMissingPerBlock = requireNonNegativeSafeInteger(
        missingness.maxMissingPerBlock,
        "statisticalPolicy.missingness.maxMissingPerBlock",
        CONTRACT_LIMITS.maxStatisticalEvaluations,
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    const maxMissingFraction = requireFinite(
        missingness.maxMissingFraction,
        "statisticalPolicy.missingness.maxMissingFraction",
        STATISTICAL_ERROR_CODES.INVALID_POLICY,
    );
    if (maxMissingFraction < 0 || maxMissingFraction > 1) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "statisticalPolicy missingness fraction is invalid",
        );
    }
    if (missingness.mode === "fail_closed"
        && (maxMissingPerBlock !== 0 || maxMissingFraction !== 0)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "fail_closed missingness requires zero tolerances",
        );
    }
    if (missingness.mode === "bounded"
        && maxMissingPerBlock === 0
        && maxMissingFraction === 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
            "bounded missingness must permit a positive bounded amount",
        );
    }

    return {
        investigationAlpha,
        familyAllocations,
        familyByName,
        nominalFamilySum,
        familyScale,
        metrics,
        metricByKey,
        minBlocks,
        maxBlocks,
        missingness: {
            mode: missingness.mode,
            maxMissingPerBlock,
            maxMissingFraction,
        },
    };
}

function normalizeSubject(subject) {
    requirePlainObject(subject, "subject");
    if (subject.kind !== "candidate"
        && subject.kind !== "enumerand"
        && subject.kind !== "calibration") {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "subject.kind must be candidate, enumerand, or calibration",
            { actual: typeof subject.kind === "string" ? subject.kind : null },
        );
    }
    return {
        kind: subject.kind,
        index: requireNonNegativeSafeInteger(
            subject.index,
            "subject.index",
            CONTRACT_LIMITS.maxStatisticalEvaluations - 1,
        ),
    };
}

export function claimAlphaAllocation({
    statisticalPolicy,
    family,
    subject,
    claimIndex,
    claimCount,
    lookIndex = null,
}) {
    const inspected = inspectStatisticalPolicy(statisticalPolicy);
    const normalizedFamily = requireIdentifier(family, "family");
    const familyAllocation = inspected.familyByName.get(normalizedFamily);
    if (familyAllocation === undefined) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "claim family has no frozen alpha allocation",
            { family: normalizedFamily },
        );
    }
    const normalizedSubject = normalizeSubject(subject);
    const normalizedClaimCount = requirePositiveSafeInteger(
        claimCount,
        "claimCount",
        CONTRACT_LIMITS.maxStatisticalEvaluations,
    );
    const normalizedClaimIndex = requireNonNegativeSafeInteger(
        claimIndex,
        "claimIndex",
        normalizedClaimCount - 1,
    );
    const subjectScheduleIndex = normalizedSubject.index + 1;
    const subjectWeight = statisticalScheduleWeight(subjectScheduleIndex);
    const claimWeight = cleanNumber(1 / normalizedClaimCount);
    const effectiveFamilyAlpha = cleanNumber(
        familyAllocation.alpha * inspected.familyScale,
    );
    const logFamilyAlpha =
        Math.log(familyAllocation.alpha) + Math.log(inspected.familyScale);
    const logClaimAlpha =
        logFamilyAlpha + Math.log(subjectWeight) + Math.log(claimWeight);
    const representedClaimAlpha = representableProbability(logClaimAlpha);

    const ledger = [
        {
            scope: "investigation",
            alphaUpperBound: inspected.investigationAlpha,
            proof: "effective family allocations sum to no more than investigation alpha",
        },
        {
            scope: "family",
            family: normalizedFamily,
            nominalAlpha: familyAllocation.alpha,
            effectiveAlpha: effectiveFamilyAlpha,
            normalizationFactor: inspected.familyScale,
            nominalFamilySum: inspected.nominalFamilySum,
            effectiveFamilySumUpperBound: inspected.investigationAlpha,
        },
        {
            scope: "subject",
            subjectKind: normalizedSubject.kind,
            subjectIndex: normalizedSubject.index,
            scheduleIndex: subjectScheduleIndex,
            schedule: STATISTICAL_ALLOCATION_SCHEDULE,
            weight: subjectWeight,
            infiniteScheduleWeightSumUpperBound: 1,
            proof: "sum_{k=1..infinity} 1/(k(k+1)) = 1",
        },
        {
            scope: "claim",
            claimIndex: normalizedClaimIndex,
            claimCount: normalizedClaimCount,
            weight: claimWeight,
            finiteClaimWeightSum: 1,
            alpha: representedClaimAlpha.probability,
            logAlpha: logClaimAlpha,
            alphaUnderflowed: representedClaimAlpha.underflowed,
        },
    ];

    let look = null;
    if (lookIndex !== null) {
        const normalizedLookIndex = requirePositiveSafeInteger(
            lookIndex,
            "lookIndex",
            CONTRACT_LIMITS.maxBlocks,
        );
        const lookWeight = statisticalScheduleWeight(normalizedLookIndex);
        const logLookAlpha = logClaimAlpha + Math.log(lookWeight);
        const representedLookAlpha = representableProbability(logLookAlpha);
        const cumulativeLookWeight = cleanNumber(
            normalizedLookIndex / (normalizedLookIndex + 1),
        );
        const logCumulativeAlpha =
            logClaimAlpha + Math.log(cumulativeLookWeight);
        const representedCumulativeAlpha =
            representableProbability(logCumulativeAlpha);
        look = {
            index: normalizedLookIndex,
            schedule: STATISTICAL_ALLOCATION_SCHEDULE,
            weight: lookWeight,
            alpha: representedLookAlpha.probability,
            logAlpha: logLookAlpha,
            alphaUnderflowed: representedLookAlpha.underflowed,
            cumulativeWeight: cumulativeLookWeight,
            cumulativeAlpha: representedCumulativeAlpha.probability,
            cumulativeAlphaUnderflowed:
                representedCumulativeAlpha.underflowed,
            infiniteScheduleWeightSumUpperBound: 1,
        };
        ledger.push({
            scope: "look",
            lookIndex: normalizedLookIndex,
            schedule: STATISTICAL_ALLOCATION_SCHEDULE,
            weight: lookWeight,
            alpha: representedLookAlpha.probability,
            logAlpha: logLookAlpha,
            alphaUnderflowed: representedLookAlpha.underflowed,
            cumulativeWeight: cumulativeLookWeight,
            infiniteScheduleWeightSumUpperBound: 1,
            proof: "alpha_n = alpha_claim/(n(n+1)); cumulative weight through n is n/(n+1)",
        });
    }

    return immutableCanonical({
        version: STATISTICAL_KERNEL_VERSION,
        family: normalizedFamily,
        investigationAlpha: inspected.investigationAlpha,
        effectiveFamilyAlpha,
        subject: normalizedSubject,
        claim: {
            index: normalizedClaimIndex,
            count: normalizedClaimCount,
            weight: claimWeight,
            alpha: representedClaimAlpha.probability,
            logAlpha: logClaimAlpha,
            alphaUnderflowed: representedClaimAlpha.underflowed,
        },
        look,
        ledger,
        totalFamilywiseAlphaUpperBound: inspected.investigationAlpha,
    });
}

function resolveLogClaimAlpha({ allocation, alphaClaim, logAlphaClaim }) {
    if (allocation !== undefined && allocation !== null) {
        requirePlainObject(allocation, "allocation");
        const value = allocation.claim?.logAlpha;
        if (typeof value !== "number" || !Number.isFinite(value)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
                "allocation.claim.logAlpha must be finite",
            );
        }
        return value;
    }
    if (logAlphaClaim !== undefined) {
        const value = requireFinite(logAlphaClaim, "logAlphaClaim");
        if (!(value < 0)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
                "logAlphaClaim must be negative",
            );
        }
        return value;
    }
    return Math.log(requirePositiveAlpha(alphaClaim, "alphaClaim"));
}

function normalizeObservationInterval(value, lowerBound, upperBound, field) {
    if (typeof value === "number") {
        const observation = requireFinite(
            value,
            field,
            STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
        );
        if (observation < lowerBound || observation > upperBound) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
                `${field} is outside the confidence-sequence bounds`,
                { field, lowerBound, upperBound },
            );
        }
        return { lower: observation, upper: observation };
    }
    requirePlainObject(
        value,
        field,
        STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
    );
    const lower = requireFinite(
        value.lower,
        `${field}.lower`,
        STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
    );
    const upper = requireFinite(
        value.upper,
        `${field}.upper`,
        STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
    );
    if (lower < lowerBound || upper > upperBound || lower > upper) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
            `${field} is not a valid bounded observation interval`,
            { field, lowerBound, upperBound },
        );
    }
    return { lower, upper };
}

function hoeffdingIntervalConfidenceSequence({
    observations,
    lowerBound,
    upperBound,
    allocation,
    alphaClaim,
    logAlphaClaim,
}) {
    if (!Array.isArray(observations) || observations.length === 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "observations must be a non-empty array",
        );
    }
    const normalizedLower = requireFinite(lowerBound, "lowerBound");
    const normalizedUpper = requireFinite(upperBound, "upperBound");
    if (!(normalizedLower < normalizedUpper)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "lowerBound must be less than upperBound",
        );
    }
    const intervals = observations.map((observation, index) =>
        normalizeObservationInterval(
            observation,
            normalizedLower,
            normalizedUpper,
            `observations[${index}]`,
        ));
    const n = intervals.length;
    if (n > CONTRACT_LIMITS.maxBlocks) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "observation count exceeds the frozen maximum block count",
        );
    }
    const resolvedLogClaimAlpha = resolveLogClaimAlpha({
        allocation,
        alphaClaim,
        logAlphaClaim,
    });
    const lookWeight = statisticalScheduleWeight(n);
    const logLookAlpha = resolvedLogClaimAlpha + Math.log(lookWeight);
    const logHoeffdingTerm = Math.LN2 - logLookAlpha;
    const range = normalizedUpper - normalizedLower;
    const radius = cleanNumber(
        range * Math.sqrt(logHoeffdingTerm / (2 * n)),
    );
    const empiricalLower = cleanNumber(
        compensatedSum(intervals.map((interval) => interval.lower)) / n,
    );
    const empiricalUpper = cleanNumber(
        compensatedSum(intervals.map((interval) => interval.upper)) / n,
    );
    const lower = clamp(
        empiricalLower - radius,
        normalizedLower,
        normalizedUpper,
    );
    const upper = clamp(
        empiricalUpper + radius,
        normalizedLower,
        normalizedUpper,
    );
    const allObserved = intervals.every(
        (interval) => interval.lower === interval.upper,
    );
    const pointEstimate = allObserved ? empiricalLower : null;
    const representedLookAlpha = representableProbability(logLookAlpha);
    const representedClaimAlpha =
        representableProbability(resolvedLogClaimAlpha);

    return immutableCanonical({
        version: STATISTICAL_KERNEL_VERSION,
        method: "two_sided_hoeffding_alpha_spending_confidence_sequence",
        n,
        bounds: {
            lower: normalizedLower,
            upper: normalizedUpper,
            range,
        },
        empiricalIdentificationInterval: {
            lower: empiricalLower,
            upper: empiricalUpper,
        },
        pointEstimate,
        confidenceSequence: { lower, upper },
        radius,
        alpha: {
            claim: representedClaimAlpha.probability,
            claimLog: resolvedLogClaimAlpha,
            claimUnderflowed: representedClaimAlpha.underflowed,
            look: representedLookAlpha.probability,
            lookLog: logLookAlpha,
            lookUnderflowed: representedLookAlpha.underflowed,
            lookWeight,
            schedule: STATISTICAL_ALLOCATION_SCHEDULE,
            infiniteLookSumUpperBound: representedClaimAlpha.underflowed
                ? null
                : representedClaimAlpha.probability,
            infiniteLookSumLogUpperBound: resolvedLogClaimAlpha,
        },
        missingObservationCount: intervals.filter(
            (interval) => interval.lower !== interval.upper,
        ).length,
    });
}

export function hoeffdingMeanConfidenceSequence({
    observations,
    allocation,
    alphaClaim,
    logAlphaClaim,
}) {
    return hoeffdingIntervalConfidenceSequence({
        observations,
        lowerBound: 0,
        upperBound: 1,
        allocation,
        alphaClaim,
        logAlphaClaim,
    });
}

export function hoeffdingPairedDifferenceConfidenceSequence({
    pairs,
    allocation,
    alphaClaim,
    logAlphaClaim,
}) {
    if (!Array.isArray(pairs) || pairs.length === 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "pairs must be a non-empty array",
        );
    }
    const differences = pairs.map((pair, index) => {
        let candidate;
        let reference;
        if (Array.isArray(pair) && pair.length === 2) {
            [candidate, reference] = pair;
        } else {
            requirePlainObject(pair, `pairs[${index}]`);
            candidate = pair.candidate;
            reference = pair.reference ?? pair.control;
        }
        const normalizedCandidate = normalizeObservationInterval(
            candidate,
            0,
            1,
            `pairs[${index}].candidate`,
        );
        const normalizedReference = normalizeObservationInterval(
            reference,
            0,
            1,
            `pairs[${index}].reference`,
        );
        return {
            lower: cleanNumber(
                normalizedCandidate.lower - normalizedReference.upper,
            ),
            upper: cleanNumber(
                normalizedCandidate.upper - normalizedReference.lower,
            ),
        };
    });
    return hoeffdingIntervalConfidenceSequence({
        observations: differences,
        lowerBound: -1,
        upperBound: 1,
        allocation,
        alphaClaim,
        logAlphaClaim,
    });
}

export function hoeffdingIndependentDifferenceConfidenceSequence({
    candidateObservations,
    referenceObservations,
    allocation,
    alphaClaim,
    logAlphaClaim,
}) {
    if (!Array.isArray(candidateObservations)
        || !Array.isArray(referenceObservations)
        || candidateObservations.length === 0
        || candidateObservations.length !== referenceObservations.length) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "independent candidate/reference observations must be non-empty equal-length arrays",
        );
    }
    const resolvedLogClaimAlpha = resolveLogClaimAlpha({
        allocation,
        alphaClaim,
        logAlphaClaim,
    });
    const splitLogAlpha = resolvedLogClaimAlpha - Math.LN2;
    const candidate = hoeffdingMeanConfidenceSequence({
        observations: candidateObservations,
        logAlphaClaim: splitLogAlpha,
    });
    const reference = hoeffdingMeanConfidenceSequence({
        observations: referenceObservations,
        logAlphaClaim: splitLogAlpha,
    });
    const empiricalLower = cleanNumber(
        candidate.empiricalIdentificationInterval.lower
        - reference.empiricalIdentificationInterval.upper,
    );
    const empiricalUpper = cleanNumber(
        candidate.empiricalIdentificationInterval.upper
        - reference.empiricalIdentificationInterval.lower,
    );
    const pointEstimate = candidate.pointEstimate === null
        || reference.pointEstimate === null
        ? null
        : cleanNumber(candidate.pointEstimate - reference.pointEstimate);
    return immutableCanonical({
        version: STATISTICAL_KERNEL_VERSION,
        method:
            "two_sample_independent_hoeffding_alpha_spending_confidence_sequence",
        n: candidateObservations.length,
        bounds: { lower: -1, upper: 1, range: 2 },
        empiricalIdentificationInterval: {
            lower: empiricalLower,
            upper: empiricalUpper,
        },
        pointEstimate,
        confidenceSequence: {
            lower: clamp(
                candidate.confidenceSequence.lower
                    - reference.confidenceSequence.upper,
                -1,
                1,
            ),
            upper: clamp(
                candidate.confidenceSequence.upper
                    - reference.confidenceSequence.lower,
                -1,
                1,
            ),
        },
        componentConfidenceSequences: {
            candidate,
            reference,
        },
        alpha: {
            claim: representableProbability(resolvedLogClaimAlpha).probability,
            claimLog: resolvedLogClaimAlpha,
            armSplit: "equal_bonferroni",
            componentLogAlpha: splitLogAlpha,
        },
        missingObservationCount:
            candidate.missingObservationCount
            + reference.missingObservationCount,
    });
}

function normalizeConfidenceInterval(interval) {
    requirePlainObject(interval, "confidence interval");
    const lower = requireFinite(interval.lower, "confidence interval lower");
    const upper = requireFinite(interval.upper, "confidence interval upper");
    if (lower > upper) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "confidence interval lower exceeds upper",
        );
    }
    return { lower, upper };
}

export function evaluateThresholdClaim(interval, operator, value) {
    const confidence = normalizeConfidenceInterval(interval);
    if (!THRESHOLD_OPERATORS.has(operator)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "threshold operator is not supported",
            { operator: typeof operator === "string" ? operator : null },
        );
    }
    const threshold = requireFinite(
        value,
        "threshold",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    let supported;
    let refuted;
    switch (operator) {
        case ">=":
            supported = confidence.lower >= threshold;
            refuted = confidence.upper < threshold;
            break;
        case ">":
            supported = confidence.lower > threshold;
            refuted = confidence.upper <= threshold;
            break;
        case "<=":
            supported = confidence.upper <= threshold;
            refuted = confidence.lower > threshold;
            break;
        case "<":
            supported = confidence.upper < threshold;
            refuted = confidence.lower >= threshold;
            break;
        default:
            supported = false;
            refuted = false;
    }
    return supported
        ? CLAIM_STATE.SUPPORTED
        : refuted
            ? CLAIM_STATE.REFUTED
            : CLAIM_STATE.UNRESOLVED;
}

export function evaluateIntervalClaim(interval, targetLower, targetUpper) {
    const confidence = normalizeConfidenceInterval(interval);
    const lower = requireFinite(
        targetLower,
        "targetLower",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    const upper = requireFinite(
        targetUpper,
        "targetUpper",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    if (!(lower < upper)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "targetLower must be less than targetUpper",
        );
    }
    if (confidence.lower >= lower && confidence.upper <= upper) {
        return CLAIM_STATE.SUPPORTED;
    }
    if (confidence.upper < lower || confidence.lower > upper) {
        return CLAIM_STATE.REFUTED;
    }
    return CLAIM_STATE.UNRESOLVED;
}

export function supportsPracticalMargin(interval, {
    direction,
    margin = 0,
} = {}) {
    const confidence = normalizeConfidenceInterval(interval);
    if (!DIRECTIONS.has(direction)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "practical-margin direction must be increase or decrease",
        );
    }
    const normalizedMargin = requireFinite(
        margin,
        "margin",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    if (normalizedMargin < 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "practical margin must be non-negative",
        );
    }
    return direction === "increase"
        ? confidence.lower > normalizedMargin
        : confidence.upper < -normalizedMargin;
}

export function evaluateDirectionClaim(interval, {
    direction,
    practicalMargin = 0,
} = {}) {
    const confidence = normalizeConfidenceInterval(interval);
    if (supportsPracticalMargin(confidence, {
        direction,
        margin: practicalMargin,
    })) {
        return CLAIM_STATE.SUPPORTED;
    }
    if (direction === "increase" && confidence.upper <= 0) {
        return CLAIM_STATE.REFUTED;
    }
    if (direction === "decrease" && confidence.lower >= 0) {
        return CLAIM_STATE.REFUTED;
    }
    return CLAIM_STATE.UNRESOLVED;
}

export function evaluatePracticalEquivalence(interval, {
    center = 0,
    margin,
} = {}) {
    const confidence = normalizeConfidenceInterval(interval);
    const normalizedCenter = requireFinite(
        center,
        "center",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    const normalizedMargin = requireFinite(
        margin,
        "margin",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    if (!(normalizedMargin > 0)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "equivalence margin must be positive",
        );
    }
    const lower = normalizedCenter - normalizedMargin;
    const upper = normalizedCenter + normalizedMargin;
    if (confidence.lower >= lower && confidence.upper <= upper) {
        return CLAIM_STATE.SUPPORTED;
    }
    if (confidence.upper < lower || confidence.lower > upper) {
        return CLAIM_STATE.REFUTED;
    }
    return CLAIM_STATE.UNRESOLVED;
}

export function supportsPracticalEquivalence(interval, options) {
    return evaluatePracticalEquivalence(interval, options)
        === CLAIM_STATE.SUPPORTED;
}

export function statisticalMetricClaims(statisticalPolicy) {
    const inspected = inspectStatisticalPolicy(statisticalPolicy);
    return immutableCanonical(inspected.metrics.map((metric) => {
        const descriptiveId = `metric.${metric.key}.acceptance`;
        return {
            id: descriptiveId.length <= 128 ? descriptiveId : metric.key,
            kind: "threshold",
            observable: metric.key,
            operator: metric.direction === "max" ? ">=" : "<=",
            value: metric.acceptanceThreshold,
            family: metric.family,
            source: "frozen_statistical_policy",
        };
    }));
}

function acceptancePredicateLeaves(predicate, leaves) {
    requirePlainObject(
        predicate,
        "acceptancePredicate",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    if (predicate.kind === "all") {
        if (!Array.isArray(predicate.predicates) || predicate.predicates.length === 0) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "acceptancePredicate.all requires at least one statistical child",
            );
        }
        for (const child of predicate.predicates) {
            acceptancePredicateLeaves(child, leaves);
        }
        return;
    }
    if (predicate.kind === "metric_compare" || predicate.kind === "harness_pass") {
        leaves.push(predicate);
        return;
    }
    fail(
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
        "candidate acceptance must be a metric_compare, harness_pass, or all of those statistical claims",
        { kind: typeof predicate.kind === "string" ? predicate.kind : null },
    );
}

export function statisticalAcceptanceClaimSet(contract) {
    requirePlainObject(
        contract,
        "contract",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    const inspected = inspectStatisticalPolicy(contract.statisticalPolicy);
    const metricClaims = statisticalMetricClaims(contract.statisticalPolicy);
    const metricClaimByKey = new Map(
        metricClaims.map((claim) => [claim.observable, claim]),
    );
    const leaves = [];
    acceptancePredicateLeaves(contract.acceptancePredicate, leaves);
    const requiredClaimIds = [];
    const requiredMetricClaims = [];
    const seen = new Set();
    let harnessPassClaim = null;
    for (const leaf of leaves) {
        if (leaf.kind === "metric_compare") {
            const claim = metricClaimByKey.get(leaf.metric);
            if (claim === undefined) {
                fail(
                    STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                    "acceptancePredicate.metric_compare must name a frozen statistical metric",
                    { metric: leaf.metric ?? null },
                );
            }
            if (leaf.operator !== claim.operator || leaf.value !== claim.value) {
                fail(
                    STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                    "acceptancePredicate.metric_compare must exactly match the frozen statistical acceptance claim",
                    {
                        metric: leaf.metric,
                        expectedOperator: claim.operator,
                        expectedValue: claim.value,
                        actualOperator: leaf.operator ?? null,
                        actualValue: Number.isFinite(leaf.value) ? leaf.value : null,
                    },
                );
            }
            if (seen.has(claim.id)) {
                fail(
                    STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                    "acceptancePredicate contains a duplicate statistical claim",
                    { claimId: claim.id },
                );
            }
            seen.add(claim.id);
            requiredClaimIds.push(claim.id);
            requiredMetricClaims.push(claim);
            continue;
        }
        const family = leaf.family
            ?? (inspected.familyAllocations.length === 1
                ? inspected.familyAllocations[0].family
                : null);
        if (family === null || !inspected.familyByName.has(family)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "harness_pass acceptance requires an explicit frozen family when multiple families exist",
                { family },
            );
        }
        const claim = {
            id: "acceptance.harness_pass",
            kind: "harness_pass",
            expected: true,
            family,
            ...(leaf.probabilityThreshold === undefined
                ? {}
                : { probabilityThreshold: leaf.probabilityThreshold }),
            source: "frozen_acceptance_predicate",
        };
        if (seen.has(claim.id)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "acceptancePredicate contains a duplicate statistical claim",
                { claimId: claim.id },
            );
        }
        seen.add(claim.id);
        requiredClaimIds.push(claim.id);
        harnessPassClaim = claim;
    }
    const claims = [
        ...requiredMetricClaims,
        ...(harnessPassClaim === null ? [] : [harnessPassClaim]),
    ].sort((left, right) => lexicalCompare(left.id, right.id));
    return immutableCanonical({
        claims,
        requiredClaimIds: [...requiredClaimIds].sort(lexicalCompare),
    });
}

export function aggregateRequiredClaimState(evaluation, requiredClaimIds) {
    requirePlainObject(
        evaluation,
        "evaluation",
        STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
    );
    if (!Array.isArray(requiredClaimIds) || requiredClaimIds.length === 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "requiredClaimIds must be a non-empty claim id array",
        );
    }
    const byId = new Map(
        (Array.isArray(evaluation.claims) ? evaluation.claims : [])
            .map((claim) => [claim.id, claim.state]),
    );
    const states = requiredClaimIds.map((id) => {
        requireIdentifier(id, "requiredClaimIds item");
        return byId.get(id) ?? CLAIM_STATE.INVALID;
    });
    return states.includes(CLAIM_STATE.INVALID)
        ? CLAIM_STATE.INVALID
        : states.includes(CLAIM_STATE.REFUTED)
            ? CLAIM_STATE.REFUTED
            : states.every((state) => state === CLAIM_STATE.SUPPORTED)
                ? CLAIM_STATE.SUPPORTED
                : CLAIM_STATE.UNRESOLVED;
}

function registryByKey(observableRegistry) {
    if (observableRegistry === undefined || observableRegistry === null) {
        return new Map();
    }
    if (!Array.isArray(observableRegistry)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_ARGUMENT,
            "observableRegistry must be an array when supplied",
        );
    }
    const result = new Map();
    for (let index = 0; index < observableRegistry.length; index += 1) {
        const observable = observableRegistry[index];
        requirePlainObject(
            observable,
            `observableRegistry[${index}]`,
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
        );
        const key = requireIdentifier(
            observable.key,
            `observableRegistry[${index}].key`,
            STATISTICAL_ERROR_CODES.INVALID_POLICY,
        );
        if (result.has(key)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_POLICY,
                "observableRegistry keys must be unique",
                { key },
            );
        }
        result.set(key, observable);
    }
    return result;
}

function resolveNonMetricFamily(claim, inspected) {
    if (claim.family !== undefined) {
        const family = requireIdentifier(claim.family, `${claim.id}.family`);
        if (!inspected.familyByName.has(family)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "claim family has no frozen allocation",
                { claimId: claim.id, family },
            );
        }
        return family;
    }
    if (inspected.familyAllocations.length === 1) {
        return inspected.familyAllocations[0].family;
    }
    fail(
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
        "non-metric claims require a frozen family when multiple families exist",
        { claimId: claim.id },
    );
}

function registeredNumericMetric(claim, inspected, registry, observable) {
    const registration = registry.get(observable);
    if (registration?.kind !== "numeric") {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "numeric claim observable is neither a frozen statistical metric nor a registered bounded numeric observable",
            { claimId: claim.id, observable },
        );
    }
    const bounds = normalizeBounds(
        registration,
        `${claim.id}.registeredObservable`,
    );
    const family = resolveNonMetricFamily(claim, inspected);
    const practicalEquivalenceDelta = claim.practicalEquivalenceDelta === undefined
        ? 0
        : requireFinite(
            claim.practicalEquivalenceDelta,
            `${claim.id}.practicalEquivalenceDelta`,
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
        );
    if (practicalEquivalenceDelta < 0
        || practicalEquivalenceDelta > bounds.range) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "registered-observable practical equivalence delta is outside its bounds",
            { claimId: claim.id, practicalEquivalenceDelta },
        );
    }
    const direction = claim.direction === "decrease"
        || claim.operator === "<"
        || claim.operator === "<="
        ? "min"
        : "max";
    return {
        observable,
        family,
        metric: {
            key: observable,
            ...bounds,
            estimand: `mean ${observable}`,
            unit: "registered_observable",
            direction,
            acceptanceThreshold: null,
            practicalEquivalenceDelta,
            family,
        },
        boundSource: "frozen_observable_registry",
    };
}

function resolveMetricClaimBase(claim, inspected, registry) {
    const observable = requireIdentifier(
        claim.observable ?? claim.metric,
        `${claim.id}.observable`,
    );
    const metric = inspected.metricByKey.get(observable);
    if (metric === undefined) {
        return registeredNumericMetric(
            claim,
            inspected,
            registry,
            observable,
        );
    }
    if (claim.family !== undefined && claim.family !== metric.family) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "numeric claim family does not match its frozen metric family",
            { claimId: claim.id, expected: metric.family },
        );
    }
    return {
        observable,
        metric,
        family: metric.family,
        boundSource: "frozen_statistical_policy",
    };
}

function normalizeProbabilityThreshold(claim) {
    const threshold = claim.probabilityThreshold
        ?? STATISTICAL_DEFAULT_SUCCESS_PROBABILITY_THRESHOLD;
    const normalized = requireFinite(
        threshold,
        `${claim.id}.probabilityThreshold`,
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    if (!(normalized > 0 && normalized < 1)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "probabilityThreshold must be strictly between zero and one",
            { claimId: claim.id },
        );
    }
    return normalized;
}

function normalizeClaim(claim, inspected, registry) {
    requirePlainObject(
        claim,
        "claim",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    const id = requireIdentifier(
        claim.id,
        "claim.id",
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
    );
    const kind = claim.kind;
    if (kind === "threshold") {
        const base = resolveMetricClaimBase({ ...claim, id }, inspected, registry);
        if (!THRESHOLD_OPERATORS.has(claim.operator)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "threshold claim operator is invalid",
                { claimId: id },
            );
        }
        const value = requireFinite(
            claim.value,
            `${id}.value`,
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
        );
        if (value < base.metric.minimum || value > base.metric.maximum) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "threshold claim value is outside metric bounds",
                { claimId: id },
            );
        }
        return {
            id,
            kind: "threshold",
            ...base,
            operator: claim.operator,
            value,
        };
    }
    if (kind === "bounded_interval" || kind === "interval") {
        const base = resolveMetricClaimBase({ ...claim, id }, inspected, registry);
        const lower = requireFinite(
            claim.lower,
            `${id}.lower`,
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
        );
        const upper = requireFinite(
            claim.upper,
            `${id}.upper`,
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
        );
        if (!(lower < upper)
            || lower < base.metric.minimum
            || upper > base.metric.maximum) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "interval claim is outside metric bounds or empty",
                { claimId: id },
            );
        }
        return {
            id,
            kind: "interval",
            ...base,
            lower,
            upper,
        };
    }
    if (kind === "direction"
        || kind === "direction_vs_control"
        || kind === "direction_vs_parent") {
        const base = resolveMetricClaimBase({ ...claim, id }, inspected, registry);
        if (!DIRECTIONS.has(claim.direction)) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "direction claim must predict increase or decrease",
                { claimId: id },
            );
        }
        let referenceKind;
        let parentEvidenceId = null;
        if (kind === "direction_vs_control") {
            referenceKind = "control";
        } else if (kind === "direction_vs_parent") {
            referenceKind = "assigned_parent";
            parentEvidenceId = requireIdentifier(
                claim.parentEvidenceId ?? claim.evidenceId,
                `${id}.parentEvidenceId`,
            );
        } else {
            requirePlainObject(
                claim.reference,
                `${id}.reference`,
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            );
            if (claim.reference.kind === "control") {
                referenceKind = "control";
            } else if (claim.reference.kind === "assigned_parent") {
                referenceKind = "assigned_parent";
                parentEvidenceId = requireIdentifier(
                    claim.reference.evidenceId,
                    `${id}.reference.evidenceId`,
                );
            } else {
                fail(
                    STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                    "direction claim reference is invalid",
                    { claimId: id },
                );
            }
        }
        const referenceSampling =
            claim.referenceSampling ?? "paired_within_block";
        if (referenceSampling !== "paired_within_block"
            && referenceSampling !== "independent_replay_blocks") {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "direction claim referenceSampling is invalid",
                { claimId: id, referenceSampling },
            );
        }
        return {
            id,
            kind: referenceKind === "control"
                ? "direction_vs_control"
                : "direction_vs_parent",
            ...base,
            direction: claim.direction,
            referenceKind,
            parentEvidenceId,
            referenceSampling,
            practicalMargin: base.metric.practicalEquivalenceDelta,
        };
    }
    if (kind === "categorical_outcome" || kind === "categorical") {
        const observable = requireIdentifier(
            claim.observable,
            `${id}.observable`,
        );
        const registration = registry.get(observable);
        if (registration === undefined) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "categorical claims require the frozen observable registry",
                { claimId: id, observable },
            );
        }
        if (registration.kind !== "categorical") {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "categorical claim observable is not categorical",
                { claimId: id, observable },
            );
        }
        if (typeof claim.outcome !== "string" && typeof claim.outcome !== "boolean") {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "categorical claim outcome must be string or boolean",
                { claimId: id },
            );
        }
        if (!Array.isArray(registration.values)
            || !registration.values.some((value) =>
                canonicalEqual(value, claim.outcome))) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "categorical claim outcome is not registered",
                { claimId: id, observable },
            );
        }
        return {
            id,
            kind: "categorical",
            observable,
            family: resolveNonMetricFamily({ ...claim, id }, inspected),
            outcome: claim.outcome,
            probabilityThreshold: normalizeProbabilityThreshold({ ...claim, id }),
            registration,
        };
    }
    if (kind === "binary" || kind === "harness_pass") {
        const observable = kind === "harness_pass"
            ? "harness_pass"
            : requireIdentifier(
                claim.observable ?? "harness_pass",
                `${id}.observable`,
            );
        const expected = claim.expected ?? true;
        if (typeof expected !== "boolean") {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "binary claim expected value must be boolean",
                { claimId: id },
            );
        }
        return {
            id,
            kind: "binary",
            observable,
            family: resolveNonMetricFamily({ ...claim, id }, inspected),
            expected,
            probabilityThreshold: normalizeProbabilityThreshold({ ...claim, id }),
        };
    }
    fail(
        STATISTICAL_ERROR_CODES.INVALID_CLAIM,
        "claim kind is not supported by the bounded statistics kernel",
        { claimId: id, kind: typeof kind === "string" ? kind : null },
    );
}

function normalizeClaims(claims, inspected, registry) {
    if (!Array.isArray(claims) || claims.length === 0) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "claims must be a non-empty frozen claim set",
        );
    }
    const normalized = claims.map((claim) =>
        normalizeClaim(claim, inspected, registry));
    normalized.sort((left, right) => lexicalCompare(left.id, right.id));
    for (let index = 1; index < normalized.length; index += 1) {
        if (normalized[index - 1].id === normalized[index].id) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "claim ids must be unique",
                { claimId: normalized[index].id },
            );
        }
    }
    const counts = new Map();
    for (const claim of normalized) {
        counts.set(claim.family, (counts.get(claim.family) ?? 0) + 1);
    }
    const ordinals = new Map();
    for (const claim of normalized) {
        const ordinal = ordinals.get(claim.family) ?? 0;
        claim.familyClaimIndex = ordinal;
        claim.familyClaimCount = counts.get(claim.family);
        ordinals.set(claim.family, ordinal + 1);
    }
    return normalized;
}

function claimDefinition(claim) {
    const {
        familyClaimIndex: _familyClaimIndex,
        familyClaimCount: _familyClaimCount,
        ...definition
    } = claim;
    return definition;
}

function bindClaimsToAllocationSet(
    requestedClaims,
    allocationClaims,
    inspected,
    registry,
) {
    const allocationSet = normalizeClaims(
        allocationClaims,
        inspected,
        registry,
    );
    const allocationById = new Map(
        allocationSet.map((claim) => [claim.id, claim]),
    );
    const requested = normalizeClaims(
        requestedClaims,
        inspected,
        registry,
    );
    for (const claim of requested) {
        const allocated = allocationById.get(claim.id);
        if (allocated === undefined
            || !canonicalEqual(
                claimDefinition(claim),
                claimDefinition(allocated),
            )) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_CLAIM,
                "evaluated claim is absent from or differs from the frozen allocation claim set",
                { claimId: claim.id },
            );
        }
        claim.familyClaimIndex = allocated.familyClaimIndex;
        claim.familyClaimCount = allocated.familyClaimCount;
    }
    return { requested, allocationSet };
}

export function claimSetAlphaAllocation({
    statisticalPolicy,
    allocationClaims,
    claimId,
    subject,
    lookIndex = null,
    observableRegistry = undefined,
}) {
    const inspected = inspectStatisticalPolicy(statisticalPolicy);
    const registry = registryByKey(observableRegistry);
    const normalized = normalizeClaims(
        allocationClaims,
        inspected,
        registry,
    );
    const target = normalized.find((claim) => claim.id === claimId);
    if (target === undefined) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_CLAIM,
            "claimId is not present in the frozen allocation claim set",
            { claimId },
        );
    }
    return claimAlphaAllocation({
        statisticalPolicy,
        family: target.family,
        subject,
        claimIndex: target.familyClaimIndex,
        claimCount: target.familyClaimCount,
        lookIndex,
    });
}

function normalizeBlocks(blocks, maxBlocks) {
    if (!Array.isArray(blocks)) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_BLOCK,
            "blocks must be an array",
        );
    }
    if (blocks.length > maxBlocks) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_BLOCK,
            "block count exceeds statisticalPolicy.maxBlocks",
            { maxBlocks, blockCount: blocks.length },
        );
    }
    const normalized = blocks.map((block, index) => {
        requirePlainObject(
            block,
            `blocks[${index}]`,
            STATISTICAL_ERROR_CODES.INVALID_BLOCK,
        );
        const blockIndex = requireNonNegativeSafeInteger(
            block.blockIndex,
            `blocks[${index}].blockIndex`,
            maxBlocks - 1,
            STATISTICAL_ERROR_CODES.INVALID_BLOCK,
        );
        return { blockIndex, block };
    }).sort((left, right) => left.blockIndex - right.blockIndex);
    for (let index = 0; index < normalized.length; index += 1) {
        if (normalized[index].blockIndex !== index) {
            fail(
                STATISTICAL_ERROR_CODES.INVALID_BLOCK,
                "block indices must be unique and contiguous from zero",
                {
                    expected: index,
                    actual: normalized[index].blockIndex,
                },
            );
        }
    }
    return normalized;
}

function claimCellDescriptors(claims) {
    const descriptors = new Map();
    const add = (role, referenceId, claim) => {
        const mode = claim.metric !== undefined
            ? "numeric"
            : claim.kind === "binary"
                ? "binary"
                : "categorical";
        const key = `${role}\u0000${referenceId ?? ""}\u0000${claim.observable}\u0000${mode}`;
        if (!descriptors.has(key)) {
            descriptors.set(key, {
                key,
                role,
                referenceId,
                observable: claim.observable,
                mode,
                metric: claim.metric ?? null,
                registration: claim.registration ?? null,
            });
        }
    };
    for (const claim of claims) {
        add("candidate", null, claim);
        if (claim.referenceKind === "control") {
            add("control", null, claim);
        } else if (claim.referenceKind === "assigned_parent") {
            add("parent", claim.parentEvidenceId, claim);
        }
    }
    return [...descriptors.values()].sort((left, right) =>
        lexicalCompare(left.key, right.key));
}

function roleRecord(block, descriptor) {
    if (descriptor.role === "candidate") return block.candidate ?? null;
    if (descriptor.role === "control") return block.control ?? null;
    const parents = block.parents;
    if (parents === undefined || parents === null) return null;
    requirePlainObject(
        parents,
        "block.parents",
        STATISTICAL_ERROR_CODES.INVALID_BLOCK,
    );
    return Object.hasOwn(parents, descriptor.referenceId)
        ? parents[descriptor.referenceId]
        : null;
}

function rawRecordValue(record, observable) {
    if (record === null || record === undefined) return { missing: true };
    requirePlainObject(
        record,
        "observation record",
        STATISTICAL_ERROR_CODES.INVALID_BLOCK,
    );
    if (observable === "harness_pass") {
        if (Object.hasOwn(record, "pass")) {
            return record.pass === null || record.pass === undefined
                ? { missing: true }
                : { missing: false, value: record.pass };
        }
        if (Object.hasOwn(record, "harness_pass")) {
            return record.harness_pass === null
                || record.harness_pass === undefined
                ? { missing: true }
                : { missing: false, value: record.harness_pass };
        }
        return { missing: true };
    }
    for (const containerName of ["metrics", "observables"]) {
        const container = record[containerName];
        if (container === undefined || container === null) continue;
        requirePlainObject(
            container,
            `observation record.${containerName}`,
            STATISTICAL_ERROR_CODES.INVALID_BLOCK,
        );
        if (Object.hasOwn(container, observable)) {
            return container[observable] === null
                || container[observable] === undefined
                ? { missing: true }
                : { missing: false, value: container[observable] };
        }
    }
    if (Object.hasOwn(record, observable)) {
        return record[observable] === null || record[observable] === undefined
            ? { missing: true }
            : { missing: false, value: record[observable] };
    }
    return { missing: true };
}

function normalizeCellValue(raw, descriptor) {
    if (descriptor.mode === "numeric") {
        return normalizeBoundedObservation(raw, descriptor.metric);
    }
    if (descriptor.mode === "binary") {
        return normalizeBinaryObservation(raw);
    }
    if (typeof raw !== "string" && typeof raw !== "boolean") {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
            "categorical observation must be string or boolean",
            { observable: descriptor.observable },
        );
    }
    if (descriptor.registration !== null
        && (!Array.isArray(descriptor.registration.values)
            || !descriptor.registration.values.some((value) =>
                canonicalEqual(value, raw)))) {
        fail(
            STATISTICAL_ERROR_CODES.INVALID_OBSERVATION,
            "categorical observation is outside the frozen registry",
            { observable: descriptor.observable },
        );
    }
    return raw;
}

function materializeCells(blocks, descriptors) {
    const cellsByBlock = new Map();
    const missingByBlock = [];
    let totalMissing = 0;
    for (const item of blocks) {
        const cells = new Map();
        let missing = 0;
        for (const descriptor of descriptors) {
            const raw = rawRecordValue(
                roleRecord(item.block, descriptor),
                descriptor.observable,
            );
            if (raw.missing) {
                cells.set(descriptor.key, { missing: true, value: null });
                missing += 1;
                totalMissing += 1;
            } else {
                cells.set(descriptor.key, {
                    missing: false,
                    value: normalizeCellValue(raw.value, descriptor),
                });
            }
        }
        cellsByBlock.set(item.blockIndex, cells);
        missingByBlock.push({
            blockIndex: item.blockIndex,
            expected: descriptors.length,
            missing,
        });
    }
    return {
        cellsByBlock,
        missingByBlock,
        totalExpected: blocks.length * descriptors.length,
        totalMissing,
    };
}

function enforceMissingness(policy, materialized) {
    const missingFraction = materialized.totalExpected === 0
        ? 0
        : cleanNumber(
            materialized.totalMissing / materialized.totalExpected,
        );
    if (policy.mode === "fail_closed" && materialized.totalMissing > 0) {
        fail(
            STATISTICAL_ERROR_CODES.MISSINGNESS_POLICY_VIOLATION,
            "fail_closed statistical policy rejects every missing observation",
            {
                totalMissing: materialized.totalMissing,
                totalExpected: materialized.totalExpected,
            },
        );
    }
    if (policy.mode === "bounded") {
        const excessiveBlock = materialized.missingByBlock.find(
            (block) => block.missing > policy.maxMissingPerBlock,
        );
        if (excessiveBlock !== undefined
            || missingFraction > policy.maxMissingFraction) {
            fail(
                STATISTICAL_ERROR_CODES.MISSINGNESS_POLICY_VIOLATION,
                "bounded missingness exceeds the frozen policy",
                {
                    totalMissing: materialized.totalMissing,
                    totalExpected: materialized.totalExpected,
                    missingFraction,
                    maxMissingFraction: policy.maxMissingFraction,
                    excessiveBlock: excessiveBlock ?? null,
                },
            );
        }
    }
    return {
        mode: policy.mode,
        treatment: policy.mode === "fail_closed"
            ? "reject_any_missing"
            : "worst_case_bounded_identification_intervals",
        totalExpected: materialized.totalExpected,
        totalMissing: materialized.totalMissing,
        missingFraction,
        perBlock: materialized.missingByBlock,
        maxMissingPerBlock: policy.maxMissingPerBlock,
        maxMissingFraction: policy.maxMissingFraction,
    };
}

function descriptorKeyForClaim(claim, role, referenceId = null) {
    const mode = claim.metric !== undefined
        ? "numeric"
        : claim.kind === "binary"
            ? "binary"
            : "categorical";
    return `${role}\u0000${referenceId ?? ""}\u0000${claim.observable}\u0000${mode}`;
}

function cellInterval(cell, claim) {
    if (cell.missing) return { lower: 0, upper: 1 };
    if (claim.kind === "categorical") {
        const indicator = canonicalEqual(cell.value, claim.outcome) ? 1 : 0;
        return { lower: indicator, upper: indicator };
    }
    if (claim.kind === "binary") {
        const indicator = cell.value === (claim.expected ? 1 : 0) ? 1 : 0;
        return { lower: indicator, upper: indicator };
    }
    return { lower: cell.value, upper: cell.value };
}

function claimObservations(claim, blocks, materialized) {
    const candidateKey = descriptorKeyForClaim(claim, "candidate");
    if (claim.referenceKind === undefined) {
        return blocks.map((item) =>
            cellInterval(
                materialized.cellsByBlock.get(item.blockIndex).get(candidateKey),
                claim,
            ));
    }
    const referenceKey = claim.referenceKind === "control"
        ? descriptorKeyForClaim(claim, "control")
        : descriptorKeyForClaim(
            claim,
            "parent",
            claim.parentEvidenceId,
        );
    return blocks.map((item) => {
        const cells = materialized.cellsByBlock.get(item.blockIndex);
        return {
            candidate: cellInterval(cells.get(candidateKey), claim),
            reference: cellInterval(cells.get(referenceKey), claim),
        };
    });
}

function scaleMeanConfidence(confidence, metric) {
    const convert = (value) => value === null
        ? null
        : cleanNumber(metric.minimum + value * metric.range);
    return {
        scale: "original_metric",
        bounds: { lower: metric.minimum, upper: metric.maximum },
        pointEstimate: convert(confidence.pointEstimate),
        empiricalIdentificationInterval: {
            lower: convert(confidence.empiricalIdentificationInterval.lower),
            upper: convert(confidence.empiricalIdentificationInterval.upper),
        },
        confidenceSequence: {
            lower: clamp(
                convert(confidence.confidenceSequence.lower),
                metric.minimum,
                metric.maximum,
            ),
            upper: clamp(
                convert(confidence.confidenceSequence.upper),
                metric.minimum,
                metric.maximum,
            ),
        },
    };
}

function scaleDifferenceConfidence(confidence, metric) {
    const convert = (value) => value === null
        ? null
        : cleanNumber(value * metric.range);
    return {
        scale: "original_metric_difference",
        bounds: { lower: -metric.range, upper: metric.range },
        pointEstimate: convert(confidence.pointEstimate),
        empiricalIdentificationInterval: {
            lower: convert(confidence.empiricalIdentificationInterval.lower),
            upper: convert(confidence.empiricalIdentificationInterval.upper),
        },
        confidenceSequence: {
            lower: clamp(
                convert(confidence.confidenceSequence.lower),
                -metric.range,
                metric.range,
            ),
            upper: clamp(
                convert(confidence.confidenceSequence.upper),
                -metric.range,
                metric.range,
            ),
        },
    };
}

function probabilityConfidence(confidence) {
    return {
        scale: "probability",
        bounds: { lower: 0, upper: 1 },
        pointEstimate: confidence.pointEstimate,
        empiricalIdentificationInterval:
            confidence.empiricalIdentificationInterval,
        confidenceSequence: confidence.confidenceSequence,
    };
}

function calibrationPointState(claim, observation) {
    const pointInterval = (interval, scale = null) => {
        if (interval.lower !== interval.upper) return null;
        const value = scale === null
            ? interval.lower
            : scale.minimum + interval.lower * scale.range;
        return { lower: value, upper: value };
    };
    if (claim.referenceKind !== undefined) {
        const candidate = pointInterval(observation.candidate);
        const reference = pointInterval(observation.reference);
        if (candidate === null || reference === null) {
            return CLAIM_STATE.UNRESOLVED;
        }
        const difference = (candidate.lower - reference.lower)
            * claim.metric.range;
        return evaluateDirectionClaim(
            { lower: difference, upper: difference },
            {
                direction: claim.direction,
                practicalMargin: claim.practicalMargin,
            },
        );
    }
    const point = pointInterval(
        observation,
        claim.metric === undefined ? null : claim.metric,
    );
    if (point === null) return CLAIM_STATE.UNRESOLVED;
    if (claim.kind === "threshold") {
        return evaluateThresholdClaim(point, claim.operator, claim.value);
    }
    if (claim.kind === "interval") {
        return evaluateIntervalClaim(point, claim.lower, claim.upper);
    }
    return evaluateThresholdClaim(
        point,
        ">",
        claim.probabilityThreshold,
    );
}

function calibrationReplicatedClaimState(claim, observations) {
    const states = observations.map((observation) =>
        calibrationPointState(claim, observation));
    if (states.every((state) => state === CLAIM_STATE.SUPPORTED)) {
        return CLAIM_STATE.SUPPORTED;
    }
    if (states.every((state) => state === CLAIM_STATE.REFUTED)) {
        return CLAIM_STATE.REFUTED;
    }
    return CLAIM_STATE.UNRESOLVED;
}

function evaluateOneClaim(claim, {
    statisticalPolicy,
    subject,
    blocks,
    materialized,
    minBlocks,
}) {
    const lookIndex = blocks.length === 0 ? null : blocks.length;
    const allocation = claimAlphaAllocation({
        statisticalPolicy,
        family: claim.family,
        subject,
        claimIndex: claim.familyClaimIndex,
        claimCount: claim.familyClaimCount,
        lookIndex,
    });
    if (blocks.length === 0) {
        return {
            id: claim.id,
            kind: claim.kind,
            observable: claim.observable,
            family: claim.family,
            boundSource: claim.boundSource ?? null,
            state: CLAIM_STATE.UNRESOLVED,
            reference: claim.referenceKind === undefined
                ? null
                : claim.referenceKind === "control"
                    ? { kind: "control" }
                    : {
                        kind: "assigned_parent",
                        evidenceId: claim.parentEvidenceId,
                    },
            referenceSampling: claim.referenceKind === undefined
                ? null
                : claim.referenceSampling,
            allocation,
            estimate: null,
            normalizedConfidenceSequence: null,
            decision: {
                confidenceState: CLAIM_STATE.UNRESOLVED,
                gatedByMinimumBlocks: true,
                reason: "no_blocks",
            },
            practical: null,
        };
    }
    const observations = claimObservations(claim, blocks, materialized);
    const confidence = claim.referenceKind === undefined
        ? hoeffdingMeanConfidenceSequence({
            observations,
            allocation,
        })
        : claim.referenceSampling === "independent_replay_blocks"
            ? hoeffdingIndependentDifferenceConfidenceSequence({
                candidateObservations: observations.map(
                    (observation) => observation.candidate,
                ),
                referenceObservations: observations.map(
                    (observation) => observation.reference,
                ),
                allocation,
            })
            : hoeffdingPairedDifferenceConfidenceSequence({
                pairs: observations,
                allocation,
            });
    let estimate;
    let confidenceState;
    let practical = null;
    if (claim.kind === "threshold") {
        estimate = scaleMeanConfidence(confidence, claim.metric);
        confidenceState = evaluateThresholdClaim(
            estimate.confidenceSequence,
            claim.operator,
            claim.value,
        );
        practical = {
            equivalenceDelta: claim.metric.practicalEquivalenceDelta,
            threshold: claim.value,
            marginSupported: claim.metric.direction === "max"
                ? estimate.confidenceSequence.lower
                    >= claim.value + claim.metric.practicalEquivalenceDelta
                : estimate.confidenceSequence.upper
                    <= claim.value - claim.metric.practicalEquivalenceDelta,
        };
    } else if (claim.kind === "interval") {
        estimate = scaleMeanConfidence(confidence, claim.metric);
        confidenceState = evaluateIntervalClaim(
            estimate.confidenceSequence,
            claim.lower,
            claim.upper,
        );
        practical = {
            interval: { lower: claim.lower, upper: claim.upper },
            equivalenceSupported:
                confidenceState === CLAIM_STATE.SUPPORTED,
        };
    } else if (claim.kind === "direction_vs_control"
        || claim.kind === "direction_vs_parent") {
        estimate = scaleDifferenceConfidence(confidence, claim.metric);
        confidenceState = evaluateDirectionClaim(
            estimate.confidenceSequence,
            {
                direction: claim.direction,
                practicalMargin: claim.practicalMargin,
            },
        );
        practical = {
            direction: claim.direction,
            margin: claim.practicalMargin,
            marginSupported: supportsPracticalMargin(
                estimate.confidenceSequence,
                {
                    direction: claim.direction,
                    margin: claim.practicalMargin,
                },
            ),
            equivalenceState: claim.practicalMargin > 0
                ? evaluatePracticalEquivalence(
                    estimate.confidenceSequence,
                    { center: 0, margin: claim.practicalMargin },
                )
                : null,
        };
    } else {
        estimate = probabilityConfidence(confidence);
        confidenceState = evaluateThresholdClaim(
            estimate.confidenceSequence,
            ">",
            claim.probabilityThreshold,
        );
        practical = {
            probabilityThreshold: claim.probabilityThreshold,
            target: claim.kind === "categorical"
                ? claim.outcome
                : claim.expected,
        };
    }
    const gated = blocks.length < minBlocks;
    const calibrationState = subject.kind === "calibration"
        ? calibrationReplicatedClaimState(claim, observations)
        : null;
    const decisionState = calibrationState ?? confidenceState;
    return {
        id: claim.id,
        kind: claim.kind,
        observable: claim.observable,
        family: claim.family,
        boundSource: claim.boundSource ?? null,
        state: gated ? CLAIM_STATE.UNRESOLVED : decisionState,
        reference: claim.referenceKind === undefined
            ? null
            : claim.referenceKind === "control"
                ? { kind: "control" }
                : {
                    kind: "assigned_parent",
                    evidenceId: claim.parentEvidenceId,
                },
        referenceSampling: claim.referenceKind === undefined
            ? null
            : claim.referenceSampling,
        allocation,
        estimate,
        normalizedConfidenceSequence: confidence,
        decision: {
            confidenceState,
            replicatedCalibrationState: calibrationState,
            gatedByMinimumBlocks: gated,
            reason: gated
                ? "minimum_blocks_not_met"
                : calibrationState === null
                    ? "confidence_sequence"
                    : "replicated_calibration_claim",
        },
        practical,
    };
}

function assumptionMetadata(inspected, missingness, claims) {
    const additionalNumericBounds = claims
        .filter((claim) =>
            claim.metric !== undefined
            && claim.boundSource === "frozen_observable_registry")
        .map((claim) => ({
            key: claim.observable,
            minimum: claim.metric.minimum,
            maximum: claim.metric.maximum,
        }))
        .filter((item, index, items) =>
            items.findIndex((candidate) => candidate.key === item.key) === index)
        .sort((left, right) => lexicalCompare(left.key, right.key));
    const referenceSamplingModes = [...new Set(
        claims
            .map((claim) => claim.referenceSampling)
            .filter((mode) => mode !== undefined),
    )].sort(lexicalCompare);
    return {
        bounds: {
            source: "frozen_v4_statistical_policy",
            observedValuesChecked: true,
            missingValuesRetainedAsWorstCaseBoundedIntervals:
                inspected.missingness.mode === "bounded",
            metrics: inspected.metrics.map((metric) => ({
                key: metric.key,
                minimum: metric.minimum,
                maximum: metric.maximum,
            })),
            registeredPredictionObservables: additionalNumericBounds,
            binaryAndCategoricalIndicators: {
                minimum: 0,
                maximum: 1,
            },
        },
        alpha: {
            source: "frozen_v4_investigation_and_family_allocations",
            investigationAlpha: inspected.investigationAlpha,
            nominalFamilyAllocations:
                inspected.familyAllocations.map((allocation) => ({
                    family: allocation.family,
                    alpha: allocation.alpha,
                })),
            numericalFamilyNormalizationFactor: inspected.familyScale,
            subjectSchedule: STATISTICAL_ALLOCATION_SCHEDULE,
            lookSchedule: STATISTICAL_ALLOCATION_SCHEDULE,
            claimsWithinFamily: "finite_equal_bonferroni_partition",
            completeFrozenClaimSet:
                "allocation_claim_ids_supplied_and_definition_matched_by_kernel",
            familywiseUpperBound: inspected.investigationAlpha,
        },
        sampling: {
            independenceAcrossIndexedBlocks:
                "assumed_for_coverage_not_proven_by_kernel",
            stabilityAcrossSequentialLooks:
                "assumed_for_coverage_not_proven_by_kernel",
            subjectIndexAssignment:
                "required_to_be_stable_and_not_outcome_selected_not_proven_by_kernel",
            fixedBlockIdentityAndNoOutcomeDependentDeletion:
                "required_by_contiguous_unique_indices_but_not_causal_proof",
            referenceSamplingModes,
            pairedWithinBlock:
                referenceSamplingModes.includes("paired_within_block"),
            independentReplayBlocks:
                referenceSamplingModes.includes("independent_replay_blocks"),
        },
        missingness: {
            frozenMode: inspected.missingness.mode,
            mechanismRandomness: "not_assumed",
            handling: missingness.treatment,
            policyCompliance: "checked_from_supplied_raw_blocks",
        },
        interpretation:
            "These are explicit conditions for the guarantee; metadata records them and does not assert they are empirically proven.",
    };
}

function invalidClaimsFromInput(claims, error) {
    if (!Array.isArray(claims)) return [];
    const ids = [];
    for (const claim of claims) {
        if (isPlainObject(claim)
            && typeof claim.id === "string"
            && SAFE_IDENTIFIER.test(claim.id)) {
            ids.push(claim.id);
        }
    }
    ids.sort(lexicalCompare);
    return ids.map((id) => ({
        id,
        state: CLAIM_STATE.INVALID,
        reason: error.code,
    }));
}

function safeErrorDetails(details) {
    if (!isPlainObject(details)) return null;
    const safe = {};
    for (const [key, value] of Object.entries(details)) {
        if (value === null
            || typeof value === "string"
            || typeof value === "boolean"
            || (typeof value === "number" && Number.isFinite(value))) {
            safe[key] = value;
        } else if (isPlainObject(value)) {
            safe[key] = safeErrorDetails(value);
        }
    }
    return safe;
}

export function evaluateStatisticalClaims({
    statisticalPolicy,
    claims = undefined,
    allocationClaims = undefined,
    blocks,
    subject,
    observableRegistry = undefined,
}) {
    let requestedClaims = claims;
    try {
        const inspected = inspectStatisticalPolicy(statisticalPolicy);
        const normalizedSubject = normalizeSubject(subject);
        if (requestedClaims === undefined) {
            requestedClaims = statisticalMetricClaims(statisticalPolicy);
        }
        const registry = registryByKey(observableRegistry);
        const allocationInput = allocationClaims === undefined
            ? requestedClaims
            : allocationClaims;
        const {
            requested: normalizedClaims,
            allocationSet,
        } = bindClaimsToAllocationSet(
            requestedClaims,
            allocationInput,
            inspected,
            registry,
        );
        const normalizedBlocks = normalizeBlocks(blocks, inspected.maxBlocks);
        const descriptors = claimCellDescriptors(normalizedClaims);
        const materialized = materializeCells(
            normalizedBlocks,
            descriptors,
        );
        const missingness = enforceMissingness(
            inspected.missingness,
            materialized,
        );
        const claimResults = normalizedClaims.map((claim) =>
            evaluateOneClaim(claim, {
                statisticalPolicy,
                subject: normalizedSubject,
                blocks: normalizedBlocks,
                materialized,
                minBlocks: inspected.minBlocks,
            }));
        const counts = Object.fromEntries(STATISTICAL_CLAIM_STATES.map(
            (state) => [
                state,
                claimResults.filter((claim) => claim.state === state).length,
            ],
        ));
        const overallState = counts.INVALID > 0
            ? CLAIM_STATE.INVALID
            : counts.REFUTED > 0
                ? CLAIM_STATE.REFUTED
                : counts.SUPPORTED === claimResults.length
                    ? CLAIM_STATE.SUPPORTED
                    : CLAIM_STATE.UNRESOLVED;
        const assumptions = assumptionMetadata(
            inspected,
            missingness,
            normalizedClaims,
        );
        return immutableCanonical({
            version: STATISTICAL_KERNEL_VERSION,
            overallState,
            subject: normalizedSubject,
            blockCount: normalizedBlocks.length,
            claims: claimResults,
            summary: {
                claimCount: claimResults.length,
                counts,
                aggregation: "all_claims_supported_else_any_refuted_else_unresolved",
            },
            missingness,
            assumptions,
            allocationClaimIds: allocationSet.map((claim) => claim.id),
            invalid: null,
        });
    } catch (error) {
        if (!(error instanceof StatisticsError)) throw error;
        return immutableCanonical({
            version: STATISTICAL_KERNEL_VERSION,
            overallState: CLAIM_STATE.INVALID,
            subject: isPlainObject(subject)
                && (subject.kind === "candidate"
                    || subject.kind === "enumerand"
                    || subject.kind === "calibration")
                && Number.isSafeInteger(subject.index)
                && subject.index >= 0
                ? { kind: subject.kind, index: subject.index }
                : null,
            blockCount: Array.isArray(blocks) ? blocks.length : 0,
            claims: invalidClaimsFromInput(requestedClaims, error),
            summary: {
                claimCount: Array.isArray(requestedClaims)
                    ? requestedClaims.length
                    : 0,
                counts: {
                    SUPPORTED: 0,
                    REFUTED: 0,
                    UNRESOLVED: 0,
                    INVALID: Array.isArray(requestedClaims)
                        ? requestedClaims.length
                        : 0,
                },
                aggregation: "invalid_input_or_policy",
            },
            missingness: null,
            assumptions: {
                interpretation:
                    "No inferential claim is emitted because policy, claims, blocks, or observations were invalid.",
            },
            allocationClaimIds: Array.isArray(allocationClaims)
                ? allocationClaims
                    .map((claim) => claim?.id)
                    .filter((id) => typeof id === "string")
                    .sort(lexicalCompare)
                : Array.isArray(requestedClaims)
                    ? requestedClaims
                        .map((claim) => claim?.id)
                        .filter((id) => typeof id === "string")
                        .sort(lexicalCompare)
                    : [],
            invalid: {
                code: error.code,
                message: error.message,
                details: safeErrorDetails(error.details),
            },
        });
    }
}
