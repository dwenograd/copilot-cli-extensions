import { RuntimeConfigError } from "./errors.mjs";

const SUPERVISOR_HEARTBEAT_OPERATION_MARGIN_MS = 1_000;
const RUNNER_BUDGET_MINIMUM_SAFETY_MARGIN = 64;

export const STRICT_ISO_TIMESTAMP_PATTERN_SOURCE =
    String.raw`^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`;
const STRICT_ISO_TIMESTAMP_RE = new RegExp(STRICT_ISO_TIMESTAMP_PATTERN_SOURCE, "u");

function assertValidIsoCalendar(value, field) {
    const match = /^(\d{4})-(\d{2})-(\d{2})T/u.exec(value);
    if (match === null) {
        throw new RuntimeConfigError(`${field} must be a complete ISO-8601 timestamp`, {
            field,
            value,
        });
    }
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const daysInMonth = [
        31,
        leapYear ? 29 : 28,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][month - 1];
    if (day > daysInMonth) {
        throw new RuntimeConfigError(`${field} is not a valid calendar timestamp`, {
            field,
            value,
        });
    }
}

export function normalizeStartDeadline(
    value,
    {
        field = "deadline_iso",
        now = Date.now(),
        afterMs = null,
    } = {},
) {
    if (value === undefined || value === null) {
        return Object.freeze({ deadlineIso: null, deadlineMs: null });
    }
    if (typeof value !== "string" || !STRICT_ISO_TIMESTAMP_RE.test(value)) {
        throw new RuntimeConfigError(
            `${field} must be a complete ISO-8601 timestamp with an explicit timezone`,
            { field, value },
        );
    }
    assertValidIsoCalendar(value, field);
    const deadlineMs = Date.parse(value);
    if (!Number.isFinite(deadlineMs)) {
        throw new RuntimeConfigError(`${field} is not a valid ISO-8601 timestamp`, {
            field,
            value,
        });
    }
    if (!Number.isFinite(now)) {
        throw new RuntimeConfigError("current time must be finite", { now });
    }
    if (deadlineMs <= now) {
        throw new RuntimeConfigError(`${field} must be in the future`, {
            field,
            value,
            deadlineMs,
            now,
        });
    }
    if (afterMs !== null && afterMs !== undefined) {
        if (!Number.isFinite(afterMs)) {
            throw new RuntimeConfigError(`${field} comparison deadline must be finite`, {
                field,
                afterMs,
            });
        }
        if (deadlineMs <= afterMs) {
            throw new RuntimeConfigError(`${field} must be later than the previous deadline`, {
                field,
                value,
                deadlineMs,
                previousDeadlineMs: afterMs,
            });
        }
    }
    return Object.freeze({
        deadlineIso: new Date(deadlineMs).toISOString(),
        deadlineMs,
    });
}

export function validateSupervisorTimingConstraints({
    heartbeatIntervalMs,
    staleLockMs,
    baseBackoffMs,
    maxBackoffMs,
}) {
    const jitterOperationMarginMs = Math.max(
        SUPERVISOR_HEARTBEAT_OPERATION_MARGIN_MS,
        Math.ceil(heartbeatIntervalMs / 2),
    );
    const minimumExclusiveStaleLockMs = heartbeatIntervalMs + jitterOperationMarginMs;
    if (staleLockMs <= minimumExclusiveStaleLockMs) {
        throw new RuntimeConfigError(
            "staleLockMs must exceed heartbeatIntervalMs plus the supervisor jitter/operation margin",
            {
                heartbeatIntervalMs,
                staleLockMs,
                jitterOperationMarginMs,
                minimumExclusiveStaleLockMs,
            },
        );
    }

    if (maxBackoffMs < baseBackoffMs) {
        throw new RuntimeConfigError("maxBackoffMs must be greater than or equal to baseBackoffMs", {
            baseBackoffMs,
            maxBackoffMs,
        });
    }
    return Object.freeze({
        jitterOperationMarginMs,
        minimumExclusiveStaleLockMs,
    });
}

export function deriveRunnerExecutionLimits(contract) {
    if (contract === null || typeof contract !== "object" || Array.isArray(contract)) {
        throw new RuntimeConfigError("contract is required to derive runner execution limits");
    }
    const maxRounds = contract.maxRounds;
    const candidatesPerRound = contract.candidatesPerRound;
    if (!Number.isSafeInteger(maxRounds)
        || maxRounds < 1
        || !Number.isSafeInteger(candidatesPerRound)
        || candidatesPerRound < 1) {
        throw new RuntimeConfigError(
            "contract maxRounds/candidatesPerRound must be positive safe integers",
            { maxRounds, candidatesPerRound },
        );
    }
    const searchCapacity = maxRounds * candidatesPerRound;
    if (!Number.isSafeInteger(searchCapacity)) {
        throw new RuntimeConfigError("contract candidate evaluation capacity is not a safe integer");
    }
    const candidateEvaluations = Array.isArray(contract.enumerandManifest?.entries)
        ? contract.enumerandManifest.entries.length
        : searchCapacity;
    if (!Number.isSafeInteger(candidateEvaluations)
        || candidateEvaluations < 1
        || candidateEvaluations > searchCapacity) {
        throw new RuntimeConfigError(
            "contract enumerand/search capacity is impossible",
            { candidateEvaluations, searchCapacity },
        );
    }
    const validationEffects = Array.isArray(contract.validationCases)
        ? contract.validationCases.length
        : 0;
    const impossibilityEffects =
        contract.hypothesisTopology === "certified_impossibility" ? 1 : 0;
    const statisticalPolicy = contract.statisticalPolicy;
    const evaluationBudget = statisticalPolicy?.evaluationBudget;
    const byteBudgets = statisticalPolicy?.resourceBudget;
    if (evaluationBudget === null
        || typeof evaluationBudget !== "object"
        || !Number.isSafeInteger(evaluationBudget.maxTotalEvaluations)
        || evaluationBudget.maxTotalEvaluations
            < validationEffects + candidateEvaluations + impossibilityEffects) {
        throw new RuntimeConfigError(
            "frozen statistical evaluation budget cannot cover runtime execution",
            {
                evaluationBudget: evaluationBudget ?? null,
                validationEffects,
                candidateEvaluations,
                impossibilityEffects,
            },
        );
    }
    if (byteBudgets === null || typeof byteBudgets !== "object") {
        throw new RuntimeConfigError(
            "frozen statistical resource budget is required",
        );
    }
    const proposalEffects = candidateEvaluations;
    const expectedExternalEffects = evaluationBudget.maxTotalEvaluations
        + proposalEffects;
    const effectSafetyMargin = Math.max(
        RUNNER_BUDGET_MINIMUM_SAFETY_MARGIN,
        Math.ceil(expectedExternalEffects / 4),
    );
    const maxExternalEffects = expectedExternalEffects + effectSafetyMargin;

    const domainCommands = 1 + candidateEvaluations + impossibilityEffects;
    const expectedKernelIterations = (domainCommands * 2)
        + maxRounds
        + 4;
    const maxLoopIterations = expectedKernelIterations
        + maxExternalEffects
        + RUNNER_BUDGET_MINIMUM_SAFETY_MARGIN;
    if (!Number.isSafeInteger(maxLoopIterations)
        || maxLoopIterations > 1_000_000) {
        throw new RuntimeConfigError(
            "derived runner loop budget is not a supported safe integer",
            { maxLoopIterations, maximum: 1_000_000 },
        );
    }
    const maxRestarts = Math.min(
        12,
        2 + Math.ceil(expectedExternalEffects / 256),
    );
    return Object.freeze({
        candidateEvaluations,
        expectedExternalEffects,
        maxExternalEffects,
        maxLoopIterations,
        maxRestarts,
        safetyMargin: effectSafetyMargin,
        byteBudgets: Object.freeze({ ...byteBudgets }),
    });
}
