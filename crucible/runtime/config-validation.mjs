import { createHash } from "node:crypto";

import {
    normalizeWorkingSetPolicy,
} from "../domain/working-set-policy.mjs";
import { RuntimeConfigError } from "./errors.mjs";

const SUPERVISOR_HEARTBEAT_OPERATION_MARGIN_MS = 1_000;
const RUNNER_BUDGET_MINIMUM_SAFETY_MARGIN = 64;
const REPLICATION_ARMS_PER_BLOCK = 2;
const CONFIRMATION_ROLE_COUNT = 3;

function checkedProduct(values, field) {
    let result = 1;
    for (const value of values) {
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new RuntimeConfigError(`${field} contains an invalid integer`, {
                field,
                value,
            });
        }
        result *= value;
        if (!Number.isSafeInteger(result)) {
            throw new RuntimeConfigError(`${field} exceeds safe integer capacity`, {
                field,
                values,
            });
        }
    }
    return result;
}

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
    const validationSeries = Array.isArray(contract.validationCases)
        && Array.isArray(contract.validationRoles)
        ? checkedProduct(
            [contract.validationCases.length, contract.validationRoles.length],
            "validation role/case series",
        )
        : 0;
    const impossibilityEffects =
        contract.hypothesisTopology === "certified_impossibility" ? 1 : 0;
    const statisticalPolicy = contract.statisticalPolicy;
    let workingSetPolicy;
    try {
        workingSetPolicy = normalizeWorkingSetPolicy(
            contract.workingSetPolicy,
        );
    } catch (error) {
        throw new RuntimeConfigError(
            `frozen working-set policy is invalid: ${
                error?.message ?? String(error)
            }`,
            { cause: error?.code ?? null },
        );
    }
    const evaluationBudget = statisticalPolicy?.evaluationBudget;
    const byteBudgets = statisticalPolicy?.resourceBudget;
    const maxBlocks = statisticalPolicy?.maxBlocks;
    const maxConfirmations = statisticalPolicy?.maxConfirmations;
    if (!Number.isSafeInteger(maxBlocks)
        || maxBlocks < 1
        || !Number.isSafeInteger(maxConfirmations)
        || maxConfirmations < 1) {
        throw new RuntimeConfigError(
            "frozen statistical block/confirmation limits are required",
            { maxBlocks, maxConfirmations },
        );
    }
    const confirmationRoleUnits = checkedProduct(
        [maxConfirmations, CONFIRMATION_ROLE_COUNT],
        "confirmation role units",
    );
    const replicatedRoleUnits = candidateEvaluations + confirmationRoleUnits;
    const scheduledBlocks = checkedProduct(
        [replicatedRoleUnits, maxBlocks],
        "replication block capacity",
    );
    const requiredCandidateEvaluations = scheduledBlocks;
    const requiredControlEvaluations = scheduledBlocks;
    const requiredReplicationEvaluations = checkedProduct(
        [scheduledBlocks, REPLICATION_ARMS_PER_BLOCK],
        "replication arm capacity",
    );
    const validationEffects = checkedProduct(
        [validationSeries, maxBlocks],
        "validation replicated attempts",
    );
    const requiredMeasurementEvaluations = validationEffects
        + impossibilityEffects
        + requiredReplicationEvaluations;
    if (evaluationBudget === null
        || typeof evaluationBudget !== "object"
        || !Number.isSafeInteger(evaluationBudget.maxCandidateEvaluations)
        || evaluationBudget.maxCandidateEvaluations
            < requiredCandidateEvaluations
        || !Number.isSafeInteger(evaluationBudget.maxControlEvaluations)
        || evaluationBudget.maxControlEvaluations
            < requiredControlEvaluations
        || !Number.isSafeInteger(evaluationBudget.maxTotalEvaluations)
        || evaluationBudget.maxTotalEvaluations
            < requiredMeasurementEvaluations) {
        throw new RuntimeConfigError(
            "frozen statistical evaluation budget cannot cover role × block × arm execution",
            {
                evaluationBudget: evaluationBudget ?? null,
                validationEffects,
                candidateEvaluations,
                confirmationRoleUnits,
                scheduledBlocks,
                requiredCandidateEvaluations,
                requiredControlEvaluations,
                requiredReplicationEvaluations,
                requiredMeasurementEvaluations,
                impossibilityEffects,
            },
        );
    }
    if (byteBudgets === null || typeof byteBudgets !== "object") {
        throw new RuntimeConfigError(
            "frozen statistical resource budget is required",
        );
    }
    const minimumByteBudgets = {};
    for (const kind of ["Output", "Receipt", "Cas"]) {
        const perAttempt = byteBudgets[`perAttempt${kind}Bytes`];
        const perInvestigation = byteBudgets[`perInvestigation${kind}Bytes`];
        const required = checkedProduct(
            [perAttempt, requiredMeasurementEvaluations],
            `required investigation ${kind.toLowerCase()} bytes`,
        );
        if (perInvestigation < required) {
            throw new RuntimeConfigError(
                `frozen per-investigation ${kind.toLowerCase()} budget cannot cover worst-case role × block × arm attempts`,
                {
                    kind,
                    perAttempt,
                    perInvestigation,
                    required,
                    requiredMeasurementEvaluations,
                },
            );
        }
        minimumByteBudgets[`perInvestigation${kind}Bytes`] = required;
    }
    const proposalEffects = candidateEvaluations;
    const expectedExternalEffects = requiredMeasurementEvaluations
        + proposalEffects;
    const effectSafetyMargin = Math.max(
        RUNNER_BUDGET_MINIMUM_SAFETY_MARGIN,
        Math.ceil(expectedExternalEffects / 4),
    );
    const maxExternalEffects = expectedExternalEffects + effectSafetyMargin;

    const domainCommands = maxBlocks
        + candidateEvaluations
        + confirmationRoleUnits
        + impossibilityEffects;
    const expectedKernelIterations = (domainCommands * 2)
        + maxRounds
        + scheduledBlocks
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
        confirmationRoleUnits,
        replicatedRoleUnits,
        scheduledBlocks,
        replicationArmsPerBlock: REPLICATION_ARMS_PER_BLOCK,
        requiredCandidateEvaluations,
        requiredControlEvaluations,
        requiredReplicationEvaluations,
        requiredMeasurementEvaluations,
        expectedExternalEffects,
        maxExternalEffects,
        maxLoopIterations,
        maxRestarts,
        safetyMargin: effectSafetyMargin,
        minimumByteBudgets: Object.freeze(minimumByteBudgets),
        byteBudgets: Object.freeze({ ...byteBudgets }),
        workingSetPolicy,
    });
}

export const RESOURCE_BROKER_CONFIG_VERSION =
    "crucible-resource-broker-config-v2";
export const MODEL_COST_POLICY_VERSION =
    "crucible-model-cost-units-v1";
const DEFAULT_GLOBAL_RESOURCE_UNITS = 8_000_000_000_000_000;
const DEFAULT_SDK_PROPOSAL_BYTES = 1024 * 1024;
const DEFAULT_SDK_PROMPT_BYTES = 32 * 1024;

export const RESOURCE_KEYS = Object.freeze({
    SDK_SESSIONS: "sdk_sessions",
    SANDBOX_PROCESSES: "sandbox_processes",
    OUTPUT_BYTES: "output_bytes",
    RECEIPT_BYTES: "receipt_bytes",
    CAS_BYTES: "cas_bytes",
    STORAGE_BYTES: "storage_bytes",
    MODEL_COST_UNITS: "model_cost_units",
});

const RESOURCE_CAPACITY_KEYS = Object.freeze([
    "sdkSessions",
    "sandboxProcesses",
    "cpuSlots",
    "gpuSlots",
    "outputBytes",
    "receiptBytes",
    "casBytes",
    "storageBytes",
    "modelCostUnits",
]);
const RESOURCE_CAPACITY_KEY_SET = new Set(RESOURCE_CAPACITY_KEYS);
const BROKER_CONFIG_KEYS = new Set([
    "version",
    "lease",
    "capacities",
    "costPolicy",
]);
const LEASE_CONFIG_KEYS = new Set(["defaultTtlMs", "maxTtlMs"]);
const COST_POLICY_KEYS = new Set([
    "version",
    "baseUnits",
    "promptByteUnits",
    "maxOutputTokenUnits",
    "sdkInputTokenUnits",
    "sdkCachedInputTokenUnits",
    "sdkOutputTokenUnits",
    "sdkReasoningTokenUnits",
    "defaultModelMultiplierBps",
    "modelMultipliersBps",
    "effortMultipliersBps",
]);
const EFFORT_KEYS = Object.freeze([
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
]);
const EFFORT_KEY_SET = new Set(EFFORT_KEYS);
const NAMED_RESOURCE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const MODEL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/u;
const BASIS_POINTS = 10_000;

export const DEFAULT_MODEL_COST_POLICY = Object.freeze({
    version: MODEL_COST_POLICY_VERSION,
    baseUnits: 256,
    promptByteUnits: 1,
    maxOutputTokenUnits: 16,
    sdkInputTokenUnits: 4,
    sdkCachedInputTokenUnits: 1,
    sdkOutputTokenUnits: 16,
    sdkReasoningTokenUnits: 16,
    defaultModelMultiplierBps: BASIS_POINTS,
    modelMultipliersBps: Object.freeze({}),
    effortMultipliersBps: Object.freeze({
        minimal: BASIS_POINTS,
        low: 11_000,
        medium: 12_500,
        high: 15_000,
        xhigh: 20_000,
    }),
});

export const DEFAULT_RESOURCE_BROKER_CONFIG = Object.freeze({
    version: RESOURCE_BROKER_CONFIG_VERSION,
    lease: Object.freeze({
        defaultTtlMs: 60_000,
        maxTtlMs: 10 * 60_000,
    }),
    capacities: Object.freeze({
        sdkSessions: 4,
        sandboxProcesses: 4,
        cpuSlots: Object.freeze({ general: 4 }),
        gpuSlots: Object.freeze({}),
        outputBytes: DEFAULT_GLOBAL_RESOURCE_UNITS,
        receiptBytes: DEFAULT_GLOBAL_RESOURCE_UNITS,
        casBytes: DEFAULT_GLOBAL_RESOURCE_UNITS,
        storageBytes: DEFAULT_GLOBAL_RESOURCE_UNITS,
        modelCostUnits: DEFAULT_GLOBAL_RESOURCE_UNITS,
    }),
    costPolicy: DEFAULT_MODEL_COST_POLICY,
});

function configPlainObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)) {
        throw new RuntimeConfigError(`${field} must be a plain object`, { field });
    }
    return value;
}

function rejectConfigUnknownKeys(value, allowed, field) {
    configPlainObject(value, field);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            throw new RuntimeConfigError(
                `${field} has unknown key ${JSON.stringify(key)}`,
                { field, key },
            );
        }
    }
}

function requireExactConfigKeys(value, keys, field) {
    rejectConfigUnknownKeys(value, new Set(keys), field);
    for (const key of keys) {
        if (!Object.hasOwn(value, key)) {
            throw new RuntimeConfigError(
                `${field} is missing required key ${JSON.stringify(key)}`,
                { field, key },
            );
        }
    }
}

function configInteger(
    value,
    field,
    {
        minimum = 0,
        maximum = Number.MAX_SAFE_INTEGER,
    } = {},
) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new RuntimeConfigError(
            `${field} must be a safe integer in ${minimum}..${maximum}`,
            { field, value },
        );
    }
    return value;
}

function normalizeNamedCapacities(value, field, {
    allowEmpty = true,
    minimum = 1,
} = {}) {
    const input = configPlainObject(value, field);
    const keys = Object.keys(input).sort();
    if (!allowEmpty && keys.length === 0) {
        throw new RuntimeConfigError(`${field} must define at least one named slot`);
    }
    if (keys.length > 64) {
        throw new RuntimeConfigError(`${field} cannot define more than 64 slots`, {
            field,
            count: keys.length,
        });
    }
    const output = {};
    for (const key of keys) {
        if (!NAMED_RESOURCE_RE.test(key)
            || key === "."
            || key === ".."
            || key.includes("..")) {
            throw new RuntimeConfigError(
                `${field} contains an unsafe resource name`,
                { field, key },
            );
        }
        output[key] = configInteger(
            input[key],
            `${field}.${key}`,
            { minimum },
        );
    }
    return Object.freeze(output);
}

function normalizeMultiplierMap(value, field) {
    const input = configPlainObject(value, field);
    const keys = Object.keys(input).sort();
    if (keys.length > 64) {
        throw new RuntimeConfigError(
            `${field} cannot contain more than 64 model multipliers`,
            { field, count: keys.length },
        );
    }
    const output = {};
    for (const key of keys) {
        if (!MODEL_ID_RE.test(key)) {
            throw new RuntimeConfigError(
                `${field} contains an unsafe model id`,
                { field, key },
            );
        }
        output[key] = configInteger(input[key], `${field}.${key}`, {
            minimum: BASIS_POINTS,
            maximum: 1_000_000,
        });
    }
    return Object.freeze(output);
}

function normalizeEffortMultipliers(value, field) {
    requireExactConfigKeys(value, EFFORT_KEYS, field);
    const output = {};
    for (const key of EFFORT_KEYS) {
        output[key] = configInteger(value[key], `${field}.${key}`, {
            minimum: BASIS_POINTS,
            maximum: 1_000_000,
        });
    }
    return Object.freeze(output);
}

function normalizeModelCostPolicy(value) {
    if (value === undefined) {
        return DEFAULT_MODEL_COST_POLICY;
    }
    requireExactConfigKeys(value, [...COST_POLICY_KEYS], "costPolicy");
    if (value.version !== MODEL_COST_POLICY_VERSION) {
        throw new RuntimeConfigError(
            `costPolicy.version must be ${MODEL_COST_POLICY_VERSION}`,
            { version: value.version },
        );
    }
    return Object.freeze({
        version: MODEL_COST_POLICY_VERSION,
        baseUnits: configInteger(value.baseUnits, "costPolicy.baseUnits", {
            minimum: 1,
        }),
        promptByteUnits: configInteger(
            value.promptByteUnits,
            "costPolicy.promptByteUnits",
            { minimum: 1 },
        ),
        maxOutputTokenUnits: configInteger(
            value.maxOutputTokenUnits,
            "costPolicy.maxOutputTokenUnits",
            { minimum: 1 },
        ),
        sdkInputTokenUnits: configInteger(
            value.sdkInputTokenUnits,
            "costPolicy.sdkInputTokenUnits",
            { minimum: 1 },
        ),
        sdkCachedInputTokenUnits: configInteger(
            value.sdkCachedInputTokenUnits,
            "costPolicy.sdkCachedInputTokenUnits",
            { minimum: 1 },
        ),
        sdkOutputTokenUnits: configInteger(
            value.sdkOutputTokenUnits,
            "costPolicy.sdkOutputTokenUnits",
            { minimum: 1 },
        ),
        sdkReasoningTokenUnits: configInteger(
            value.sdkReasoningTokenUnits,
            "costPolicy.sdkReasoningTokenUnits",
            { minimum: 1 },
        ),
        defaultModelMultiplierBps: configInteger(
            value.defaultModelMultiplierBps,
            "costPolicy.defaultModelMultiplierBps",
            { minimum: BASIS_POINTS, maximum: 1_000_000 },
        ),
        modelMultipliersBps: normalizeMultiplierMap(
            value.modelMultipliersBps,
            "costPolicy.modelMultipliersBps",
        ),
        effortMultipliersBps: normalizeEffortMultipliers(
            value.effortMultipliersBps,
            "costPolicy.effortMultipliersBps",
        ),
    });
}

export function normalizeResourceBrokerConfig(input) {
    rejectConfigUnknownKeys(input, BROKER_CONFIG_KEYS, "resource broker config");
    if (input.version !== RESOURCE_BROKER_CONFIG_VERSION) {
        throw new RuntimeConfigError(
            `resource broker config version must be ${RESOURCE_BROKER_CONFIG_VERSION}`,
            { version: input.version },
        );
    }
    requireExactConfigKeys(
        input.capacities,
        RESOURCE_CAPACITY_KEYS,
        "resource broker capacities",
    );
    const lease = input.lease === undefined
        ? Object.freeze({
            defaultTtlMs: 30_000,
            maxTtlMs: 5 * 60_000,
        })
        : (() => {
            requireExactConfigKeys(input.lease, [...LEASE_CONFIG_KEYS], "resource broker lease");
            const defaultTtlMs = configInteger(
                input.lease.defaultTtlMs,
                "resource broker lease.defaultTtlMs",
                { minimum: 1, maximum: 24 * 60 * 60_000 },
            );
            const maxTtlMs = configInteger(
                input.lease.maxTtlMs,
                "resource broker lease.maxTtlMs",
                { minimum: 1, maximum: 24 * 60 * 60_000 },
            );
            if (defaultTtlMs > maxTtlMs) {
                throw new RuntimeConfigError(
                    "resource broker default lease TTL cannot exceed its maximum",
                    { defaultTtlMs, maxTtlMs },
                );
            }
            return Object.freeze({ defaultTtlMs, maxTtlMs });
        })();
    return Object.freeze({
        version: RESOURCE_BROKER_CONFIG_VERSION,
        lease,
        capacities: Object.freeze({
            sdkSessions: configInteger(
                input.capacities.sdkSessions,
                "resource broker capacities.sdkSessions",
                { minimum: 1 },
            ),
            sandboxProcesses: configInteger(
                input.capacities.sandboxProcesses,
                "resource broker capacities.sandboxProcesses",
                { minimum: 1 },
            ),
            cpuSlots: normalizeNamedCapacities(
                input.capacities.cpuSlots,
                "resource broker capacities.cpuSlots",
                { allowEmpty: false },
            ),
            gpuSlots: normalizeNamedCapacities(
                input.capacities.gpuSlots,
                "resource broker capacities.gpuSlots",
            ),
            outputBytes: configInteger(
                input.capacities.outputBytes,
                "resource broker capacities.outputBytes",
                { minimum: 1 },
            ),
            receiptBytes: configInteger(
                input.capacities.receiptBytes,
                "resource broker capacities.receiptBytes",
                { minimum: 1 },
            ),
            casBytes: configInteger(
                input.capacities.casBytes,
                "resource broker capacities.casBytes",
                { minimum: 1 },
            ),
            storageBytes: configInteger(
                input.capacities.storageBytes,
                "resource broker capacities.storageBytes",
                { minimum: 1 },
            ),
            modelCostUnits: configInteger(
                input.capacities.modelCostUnits,
                "resource broker capacities.modelCostUnits",
                { minimum: 1 },
            ),
        }),
        costPolicy: normalizeModelCostPolicy(input.costPolicy),
    });
}

function canonicalConfigValue(value) {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map(canonicalConfigValue).join(",")}]`;
    }
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) =>
        `${JSON.stringify(key)}:${canonicalConfigValue(value[key])}`).join(",")}}`;
}

function fingerprintConfig(algorithm, value) {
    return `${algorithm}:${
        createHash("sha256").update(canonicalConfigValue(value)).digest("hex")
    }`;
}

export function resourceBrokerConfigFingerprint(config) {
    const normalized = normalizeResourceBrokerConfig(config);
    return fingerprintConfig(
        "sha256:crucible-resource-broker-config-v2",
        normalized,
    );
}

export function resourceDefinitionsFromConfig(config) {
    const normalized = normalizeResourceBrokerConfig(config);
    const definitions = [
        {
            resourceKey: RESOURCE_KEYS.SDK_SESSIONS,
            resourceFamily: "sdk_session",
            resourceName: null,
            resourceMode: "concurrency",
            capacityUnits: normalized.capacities.sdkSessions,
        },
        {
            resourceKey: RESOURCE_KEYS.SANDBOX_PROCESSES,
            resourceFamily: "sandbox_process",
            resourceName: null,
            resourceMode: "concurrency",
            capacityUnits: normalized.capacities.sandboxProcesses,
        },
        {
            resourceKey: RESOURCE_KEYS.OUTPUT_BYTES,
            resourceFamily: "output_bytes",
            resourceName: null,
            resourceMode: "consumable",
            capacityUnits: normalized.capacities.outputBytes,
        },
        {
            resourceKey: RESOURCE_KEYS.RECEIPT_BYTES,
            resourceFamily: "receipt_bytes",
            resourceName: null,
            resourceMode: "consumable",
            capacityUnits: normalized.capacities.receiptBytes,
        },
        {
            resourceKey: RESOURCE_KEYS.CAS_BYTES,
            resourceFamily: "cas_bytes",
            resourceName: null,
            resourceMode: "consumable",
            capacityUnits: normalized.capacities.casBytes,
        },
        {
            resourceKey: RESOURCE_KEYS.STORAGE_BYTES,
            resourceFamily: "storage_bytes",
            resourceName: null,
            resourceMode: "consumable",
            capacityUnits: normalized.capacities.storageBytes,
        },
        {
            resourceKey: RESOURCE_KEYS.MODEL_COST_UNITS,
            resourceFamily: "model_cost_units",
            resourceName: null,
            resourceMode: "consumable",
            capacityUnits: normalized.capacities.modelCostUnits,
        },
    ];
    for (const [name, capacityUnits] of Object.entries(
        normalized.capacities.cpuSlots,
    )) {
        definitions.push({
            resourceKey: `cpu_slot:${name}`,
            resourceFamily: "cpu_slot",
            resourceName: name,
            resourceMode: "concurrency",
            capacityUnits,
        });
    }
    for (const [name, capacityUnits] of Object.entries(
        normalized.capacities.gpuSlots,
    )) {
        definitions.push({
            resourceKey: `gpu_slot:${name}`,
            resourceFamily: "gpu_slot",
            resourceName: name,
            resourceMode: "concurrency",
            capacityUnits,
        });
    }
    return Object.freeze(definitions
        .sort((left, right) => left.resourceKey.localeCompare(right.resourceKey))
        .map((definition) => Object.freeze(definition)));
}

function limitScalar(value, field, maximum) {
    return configInteger(value, field, {
        minimum: 0,
        maximum,
    });
}

function normalizeNamedLimits(value, field, globalSlots) {
    const input = configPlainObject(value, field);
    for (const key of Object.keys(input)) {
        if (!Object.hasOwn(globalSlots, key)) {
            throw new RuntimeConfigError(
                `${field} names a slot absent from global resource configuration`,
                { field, key },
            );
        }
    }
    const output = {};
    for (const [key, maximum] of Object.entries(globalSlots)) {
        output[key] = limitScalar(
            Object.hasOwn(input, key) ? input[key] : 0,
            `${field}.${key}`,
            maximum,
        );
    }
    return Object.freeze(output);
}

export function normalizeInvestigationResourceLimits(input, config) {
    requireExactConfigKeys(
        input,
        RESOURCE_CAPACITY_KEYS,
        "investigation resource limits",
    );
    const normalizedConfig = normalizeResourceBrokerConfig(config);
    const capacities = normalizedConfig.capacities;
    return Object.freeze({
        sdkSessions: limitScalar(
            input.sdkSessions,
            "investigation resource limits.sdkSessions",
            capacities.sdkSessions,
        ),
        sandboxProcesses: limitScalar(
            input.sandboxProcesses,
            "investigation resource limits.sandboxProcesses",
            capacities.sandboxProcesses,
        ),
        cpuSlots: normalizeNamedLimits(
            input.cpuSlots,
            "investigation resource limits.cpuSlots",
            capacities.cpuSlots,
        ),
        gpuSlots: normalizeNamedLimits(
            input.gpuSlots,
            "investigation resource limits.gpuSlots",
            capacities.gpuSlots,
        ),
        outputBytes: limitScalar(
            input.outputBytes,
            "investigation resource limits.outputBytes",
            capacities.outputBytes,
        ),
        receiptBytes: limitScalar(
            input.receiptBytes,
            "investigation resource limits.receiptBytes",
            capacities.receiptBytes,
        ),
        casBytes: limitScalar(
            input.casBytes,
            "investigation resource limits.casBytes",
            capacities.casBytes,
        ),
        storageBytes: limitScalar(
            input.storageBytes,
            "investigation resource limits.storageBytes",
            capacities.storageBytes,
        ),
        modelCostUnits: limitScalar(
            input.modelCostUnits,
            "investigation resource limits.modelCostUnits",
            capacities.modelCostUnits,
        ),
    });
}

export function investigationResourceLimitsFingerprint(limits, config) {
    const normalized = normalizeInvestigationResourceLimits(limits, config);
    return fingerprintConfig(
        "sha256:crucible-investigation-resource-limits-v2",
        {
            limits: normalized,
            entries: resourceLimitEntries(normalized, config),
        },
    );
}

export function resourceLimitEntries(limits, config) {
    const normalizedConfig = normalizeResourceBrokerConfig(config);
    const normalized = normalizeInvestigationResourceLimits(
        limits,
        normalizedConfig,
    );
    const entries = [
        { resourceKey: RESOURCE_KEYS.SDK_SESSIONS, units: normalized.sdkSessions },
        {
            resourceKey: RESOURCE_KEYS.SANDBOX_PROCESSES,
            units: normalized.sandboxProcesses,
        },
        { resourceKey: RESOURCE_KEYS.OUTPUT_BYTES, units: normalized.outputBytes },
        {
            resourceKey: RESOURCE_KEYS.RECEIPT_BYTES,
            units: normalized.receiptBytes,
        },
        { resourceKey: RESOURCE_KEYS.CAS_BYTES, units: normalized.casBytes },
        {
            resourceKey: RESOURCE_KEYS.STORAGE_BYTES,
            units: normalized.storageBytes,
        },
        {
            resourceKey: RESOURCE_KEYS.MODEL_COST_UNITS,
            units: normalized.modelCostUnits,
        },
    ];
    for (const [name, units] of Object.entries(normalized.cpuSlots)) {
        entries.push({ resourceKey: `cpu_slot:${name}`, units });
    }
    for (const [name, units] of Object.entries(normalized.gpuSlots)) {
        entries.push({ resourceKey: `gpu_slot:${name}`, units });
    }
    return Object.freeze(entries
        .sort((left, right) => left.resourceKey.localeCompare(right.resourceKey))
        .map((entry) => Object.freeze(entry)));
}

function normalizeOptionalReservationScalar(input, key, field) {
    if (!Object.hasOwn(input, key)) return 0;
    return configInteger(input[key], `${field}.${key}`, { minimum: 0 });
}

function normalizeOptionalNamedReservation(input, key, field, globalSlots) {
    if (!Object.hasOwn(input, key)) return Object.freeze({});
    const value = configPlainObject(input[key], `${field}.${key}`);
    const output = {};
    for (const name of Object.keys(value).sort()) {
        if (!Object.hasOwn(globalSlots, name)) {
            throw new RuntimeConfigError(
                `${field}.${key} names an unknown slot`,
                { field, key, name },
            );
        }
        output[name] = configInteger(
            value[name],
            `${field}.${key}.${name}`,
            { minimum: 0 },
        );
    }
    return Object.freeze(output);
}

export function normalizeResourceReservation(input, config) {
    rejectConfigUnknownKeys(input, RESOURCE_CAPACITY_KEY_SET, "resource reservation");
    const normalizedConfig = normalizeResourceBrokerConfig(config);
    const normalized = Object.freeze({
        sdkSessions: normalizeOptionalReservationScalar(
            input,
            "sdkSessions",
            "resource reservation",
        ),
        sandboxProcesses: normalizeOptionalReservationScalar(
            input,
            "sandboxProcesses",
            "resource reservation",
        ),
        cpuSlots: normalizeOptionalNamedReservation(
            input,
            "cpuSlots",
            "resource reservation",
            normalizedConfig.capacities.cpuSlots,
        ),
        gpuSlots: normalizeOptionalNamedReservation(
            input,
            "gpuSlots",
            "resource reservation",
            normalizedConfig.capacities.gpuSlots,
        ),
        outputBytes: normalizeOptionalReservationScalar(
            input,
            "outputBytes",
            "resource reservation",
        ),
        receiptBytes: normalizeOptionalReservationScalar(
            input,
            "receiptBytes",
            "resource reservation",
        ),
        casBytes: normalizeOptionalReservationScalar(
            input,
            "casBytes",
            "resource reservation",
        ),
        storageBytes: normalizeOptionalReservationScalar(
            input,
            "storageBytes",
            "resource reservation",
        ),
        modelCostUnits: normalizeOptionalReservationScalar(
            input,
            "modelCostUnits",
            "resource reservation",
        ),
    });
    if (resourceReservationEntries(normalized, normalizedConfig).length === 0) {
        throw new RuntimeConfigError(
            "resource reservation must request at least one positive unit",
        );
    }
    return normalized;
}

export function resourceReservationEntries(reservation, config) {
    const normalizedConfig = normalizeResourceBrokerConfig(config);
    rejectConfigUnknownKeys(
        reservation,
        RESOURCE_CAPACITY_KEY_SET,
        "resource reservation",
    );
    const entries = [];
    const push = (resourceKey, units) => {
        const normalizedUnits = configInteger(
            units,
            `resource reservation.${resourceKey}`,
            { minimum: 0 },
        );
        if (normalizedUnits > 0) {
            entries.push(Object.freeze({ resourceKey, units: normalizedUnits }));
        }
    };
    push(RESOURCE_KEYS.SDK_SESSIONS, reservation.sdkSessions ?? 0);
    push(RESOURCE_KEYS.SANDBOX_PROCESSES, reservation.sandboxProcesses ?? 0);
    push(RESOURCE_KEYS.OUTPUT_BYTES, reservation.outputBytes ?? 0);
    push(RESOURCE_KEYS.RECEIPT_BYTES, reservation.receiptBytes ?? 0);
    push(RESOURCE_KEYS.CAS_BYTES, reservation.casBytes ?? 0);
    push(RESOURCE_KEYS.STORAGE_BYTES, reservation.storageBytes ?? 0);
    push(RESOURCE_KEYS.MODEL_COST_UNITS, reservation.modelCostUnits ?? 0);
    const cpu = reservation.cpuSlots ?? {};
    const gpu = reservation.gpuSlots ?? {};
    for (const [name, units] of Object.entries(cpu)) {
        if (!Object.hasOwn(normalizedConfig.capacities.cpuSlots, name)) {
            throw new RuntimeConfigError(
                "resource reservation names an unknown CPU slot",
                { name },
            );
        }
        push(`cpu_slot:${name}`, units);
    }
    for (const [name, units] of Object.entries(gpu)) {
        if (!Object.hasOwn(normalizedConfig.capacities.gpuSlots, name)) {
            throw new RuntimeConfigError(
                "resource reservation names an unknown GPU slot",
                { name },
            );
        }
        push(`gpu_slot:${name}`, units);
    }
    return Object.freeze(entries.sort((left, right) =>
        left.resourceKey.localeCompare(right.resourceKey)));
}

const USAGE_KEYS = new Set([
    "outputBytes",
    "receiptBytes",
    "casBytes",
    "storageBytes",
    "modelCostUnits",
]);

export function resourceUsageEntries(input = {}) {
    rejectConfigUnknownKeys(input, USAGE_KEYS, "resource usage");
    const mapping = [
        ["outputBytes", RESOURCE_KEYS.OUTPUT_BYTES],
        ["receiptBytes", RESOURCE_KEYS.RECEIPT_BYTES],
        ["casBytes", RESOURCE_KEYS.CAS_BYTES],
        ["storageBytes", RESOURCE_KEYS.STORAGE_BYTES],
        ["modelCostUnits", RESOURCE_KEYS.MODEL_COST_UNITS],
    ];
    const entries = [];
    for (const [key, resourceKey] of mapping) {
        if (Object.hasOwn(input, key)) {
            entries.push(Object.freeze({
                resourceKey,
                units: configInteger(input[key], `resource usage.${key}`, {
                    minimum: 0,
                }),
            }));
        }
    }
    return Object.freeze(entries);
}

function modelId(value, field) {
    if (typeof value !== "string" || !MODEL_ID_RE.test(value)) {
        throw new RuntimeConfigError(`${field} must be a safe model id`, {
            field,
            value,
        });
    }
    return value;
}

function ceilDivide(value, divisor) {
    return (value + divisor - 1n) / divisor;
}

function safeCostNumber(value, field) {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new RuntimeConfigError(
            `${field} exceeds safe model cost-unit range`,
            { field },
        );
    }
    return Number(value);
}

function modelMultiplier(policy, model) {
    return policy.modelMultipliersBps[model]
        ?? policy.defaultModelMultiplierBps;
}

function scaledCostUnits(rawUnits, multipliers, field) {
    let value = rawUnits;
    for (const multiplier of multipliers) {
        value = ceilDivide(value * BigInt(multiplier), BigInt(BASIS_POINTS));
    }
    return safeCostNumber(value, field);
}

export function estimateDeterministicModelCostUnits(input, policyInput = undefined) {
    const value = configPlainObject(input, "model cost estimate");
    const allowed = new Set([
        "model",
        "promptBytes",
        "maxOutputTokens",
        "maxOutputBytes",
        "reasoningEffort",
    ]);
    rejectConfigUnknownKeys(value, allowed, "model cost estimate");
    const policy = policyInput === undefined
        ? DEFAULT_MODEL_COST_POLICY
        : normalizeModelCostPolicy(policyInput);
    const model = modelId(value.model, "model cost estimate.model");
    const promptBytes = configInteger(
        value.promptBytes,
        "model cost estimate.promptBytes",
        { minimum: 0 },
    );
    const maxOutputTokens = value.maxOutputTokens === undefined
        ? 0
        : configInteger(
            value.maxOutputTokens,
            "model cost estimate.maxOutputTokens",
            { minimum: 0 },
        );
    const maxOutputBytes = value.maxOutputBytes === undefined
        ? 0
        : configInteger(
            value.maxOutputBytes,
            "model cost estimate.maxOutputBytes",
            { minimum: 0 },
        );
    if (maxOutputTokens === 0 && maxOutputBytes === 0) {
        throw new RuntimeConfigError(
            "model cost estimate requires a positive output token or byte bound",
        );
    }
    const reasoningEffort = value.reasoningEffort ?? "medium";
    if (!EFFORT_KEY_SET.has(reasoningEffort)) {
        throw new RuntimeConfigError(
            "model cost estimate reasoningEffort is unsupported",
            { reasoningEffort },
        );
    }
    const conservativeOutputTokens = Math.max(
        maxOutputTokens,
        maxOutputBytes,
    );
    const raw = BigInt(policy.baseUnits)
        + (BigInt(promptBytes) * BigInt(policy.promptByteUnits))
        + (BigInt(conservativeOutputTokens)
            * BigInt(policy.maxOutputTokenUnits));
    return scaledCostUnits(
        raw,
        [
            policy.effortMultipliersBps[reasoningEffort],
            modelMultiplier(policy, model),
        ],
        "model cost estimate",
    );
}

export function sdkUsageToModelCostUnits(input, policyInput = undefined) {
    const value = configPlainObject(input, "SDK model usage");
    const allowed = new Set([
        "model",
        "inputTokens",
        "cachedInputTokens",
        "outputTokens",
        "reasoningTokens",
        "totalTokens",
    ]);
    rejectConfigUnknownKeys(value, allowed, "SDK model usage");
    const policy = policyInput === undefined
        ? DEFAULT_MODEL_COST_POLICY
        : normalizeModelCostPolicy(policyInput);
    const model = modelId(value.model, "SDK model usage.model");
    const inputTokens = configInteger(
        value.inputTokens ?? 0,
        "SDK model usage.inputTokens",
        { minimum: 0 },
    );
    const cachedInputTokens = configInteger(
        value.cachedInputTokens ?? 0,
        "SDK model usage.cachedInputTokens",
        { minimum: 0 },
    );
    const outputTokens = configInteger(
        value.outputTokens ?? 0,
        "SDK model usage.outputTokens",
        { minimum: 0 },
    );
    const reasoningTokens = configInteger(
        value.reasoningTokens ?? 0,
        "SDK model usage.reasoningTokens",
        { minimum: 0 },
    );
    const totalTokens = configInteger(
        value.totalTokens ?? 0,
        "SDK model usage.totalTokens",
        { minimum: 0 },
    );
    const componentTotal =
        inputTokens + cachedInputTokens + outputTokens + reasoningTokens;
    if (!Number.isSafeInteger(componentTotal)) {
        throw new RuntimeConfigError(
            "SDK model usage token total exceeds safe integer range",
        );
    }
    if (componentTotal === 0 && totalTokens === 0) {
        throw new RuntimeConfigError(
            "SDK model usage must report at least one token",
        );
    }
    const maximumTokenWeight = Math.max(
        policy.sdkInputTokenUnits,
        policy.sdkCachedInputTokenUnits,
        policy.sdkOutputTokenUnits,
        policy.sdkReasoningTokenUnits,
    );
    const unclassifiedTokens = Math.max(0, totalTokens - componentTotal);
    const raw = BigInt(policy.baseUnits)
        + (BigInt(inputTokens) * BigInt(policy.sdkInputTokenUnits))
        + (BigInt(cachedInputTokens)
            * BigInt(policy.sdkCachedInputTokenUnits))
        + (BigInt(outputTokens) * BigInt(policy.sdkOutputTokenUnits))
        + (BigInt(reasoningTokens)
            * BigInt(policy.sdkReasoningTokenUnits))
        + (BigInt(unclassifiedTokens) * BigInt(maximumTokenWeight));
    return scaledCostUnits(
        raw,
        [modelMultiplier(policy, model)],
        "SDK model usage",
    );
}

export function deriveRuntimeResourceAdmission({
    executionLimits,
    deadlineMs = null,
    brokerConfig = DEFAULT_RESOURCE_BROKER_CONFIG,
    model = "gpt-5.4",
    reasoningEffort = "xhigh",
    candidateOutputBytes = DEFAULT_SDK_PROPOSAL_BYTES,
} = {}) {
    const limits = configPlainObject(
        executionLimits,
        "runtime resource execution limits",
    );
    const byteBudgets = configPlainObject(
        limits.byteBudgets,
        "runtime resource execution limits.byteBudgets",
    );
    const config = normalizeResourceBrokerConfig(brokerConfig);
    const retryAttempts = deadlineMs === null ? 1 : 3;
    const reservedCostUnitsPerAttempt = estimateDeterministicModelCostUnits({
        model,
        promptBytes: DEFAULT_SDK_PROMPT_BYTES,
        maxOutputBytes: configInteger(
            candidateOutputBytes,
            "candidateOutputBytes",
            { minimum: 1 },
        ),
        reasoningEffort,
    }, config.costPolicy);
    const maxCostUnits = checkedProduct(
        [reservedCostUnitsPerAttempt, retryAttempts],
        "SDK retry operation cost budget",
    );
    const investigationModelCostUnits = checkedProduct(
        [
            maxCostUnits,
            configInteger(
                limits.candidateEvaluations,
                "runtime resource execution limits.candidateEvaluations",
                { minimum: 1 },
            ),
        ],
        "investigation model cost budget",
    );
    const investigationLimits = normalizeInvestigationResourceLimits({
        sdkSessions: 1,
        sandboxProcesses: 1,
        cpuSlots: { general: 1 },
        gpuSlots: {},
        outputBytes: byteBudgets.perInvestigationOutputBytes,
        receiptBytes: byteBudgets.perInvestigationReceiptBytes,
        casBytes: byteBudgets.perInvestigationCasBytes,
        storageBytes:
            limits.workingSetPolicy?.perInvestigationBytes
            ?? byteBudgets.perInvestigationCasBytes,
        modelCostUnits: investigationModelCostUnits,
    }, config);
    const sdkRetryPolicy = Object.freeze({
        maxAttempts: retryAttempts,
        baseDelayMs: retryAttempts === 1 ? 0 : 250,
        maxDelayMs: retryAttempts === 1 ? 0 : 4_000,
        maxCumulativeDelayMs: retryAttempts === 1 ? 0 : 10_000,
        jitterBps: retryAttempts === 1 ? 0 : 2_000,
        reservedCostUnitsPerAttempt,
        maxCostUnits,
    });
    return Object.freeze({
        config,
        configFingerprint: resourceBrokerConfigFingerprint(config),
        investigationLimits,
        limitsFingerprint: investigationResourceLimitsFingerprint(
            investigationLimits,
            config,
        ),
        sdkRetryPolicy,
    });
}
