import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
} from "../domain/index.mjs";
import {
    CrucibleRuntimeError,
    InjectedCrashError,
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
    SdkFailureError,
    SdkRetryExhaustedError,
    SdkSubmissionConflictError,
    WorkerProtocolError,
} from "./errors.mjs";
import {
    checkedSafeIntegerSum,
    delay,
    deterministicFraction,
    parseDeadline,
    remainingDeadlineMs,
    requireIdentifier,
    requirePlainObject,
    requireString,
} from "./utils.mjs";

export const SDK_RETRY_BUDGET_VERSION = 1;
export const SDK_SUBMISSION_COMMIT_VERSION = 1;
export const SDK_OPERATIONAL_EVIDENCE_VERSION = 1;

export const SDK_OPERATION_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-sdk-operation-identity-v1";
export const SDK_RETRY_BUDGET_HASH_ALGORITHM =
    "sha256:crucible-sdk-retry-budget-v1";
export const SDK_SUBMISSION_HASH_ALGORITHM =
    "sha256:crucible-sdk-tool-submission-v1";
export const SDK_SUBMISSION_COMMIT_HASH_ALGORITHM =
    "sha256:crucible-sdk-submission-commit-v1";
export const SDK_OPERATIONAL_EVIDENCE_HASH_ALGORITHM =
    "sha256:crucible-sdk-operational-evidence-v1";

export const SDK_FAILURE_CLASSIFICATIONS = Object.freeze({
    TRANSIENT_TRANSPORT: "transient_transport",
    TRANSIENT_RATE_LIMIT: "transient_rate_limit",
    TRANSIENT_STARTUP: "transient_startup",
    SESSION_RECREATE: "session_recreate",
    PERMANENT_AUTH: "permanent_auth",
    PERMANENT_MODEL: "permanent_model",
    PERMANENT_CONFIG: "permanent_config",
    PERMANENT_SCHEMA: "permanent_schema",
    PERMANENT_POLICY: "permanent_policy",
    PROTOCOL_INVALID: "protocol_invalid",
    UNKNOWN: "unknown",
});

const RETRYABLE_CLASSIFICATIONS = new Set([
    SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_TRANSPORT,
    SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_RATE_LIMIT,
    SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_STARTUP,
    SDK_FAILURE_CLASSIFICATIONS.SESSION_RECREATE,
]);

const SDK_RETRY_POLICY_KEYS = new Set([
    "maxAttempts",
    "baseDelayMs",
    "maxDelayMs",
    "maxCumulativeDelayMs",
    "jitterBps",
    "reservedCostUnitsPerAttempt",
    "maxCostUnits",
]);

const OPERATIONAL_EVENT_TYPES = new Set([
    "attempt_started",
    "attempt_failed",
    "retry_scheduled",
    "submission_sealed",
    "submission_recovered",
    "response_quarantined",
    "cost_reconciled",
]);

const NODE_TRANSPORT_CODES = new Set([
    "ABORT_ERR",
    "ECONNABORTED",
    "ECONNREFUSED",
    "ECONNRESET",
    "EHOSTUNREACH",
    "EPIPE",
    "ETIMEDOUT",
    "ENETDOWN",
    "ENETRESET",
    "ENETUNREACH",
    "EAI_AGAIN",
    "ERR_STREAM_PREMATURE_CLOSE",
    "UND_ERR_CONNECT_TIMEOUT",
    "UND_ERR_HEADERS_TIMEOUT",
    "UND_ERR_SOCKET",
]);

const SESSION_RECREATE_CODES = new Set([
    "SESSION_CLOSED",
    "SESSION_DISCONNECTED",
    "SESSION_NOT_FOUND",
    "ERR_SESSION_CLOSED",
    "ERR_SESSION_DISCONNECTED",
    "ERR_SESSION_NOT_FOUND",
]);

const PROTOCOL_ERROR_CODES = new Set([
    RUNTIME_ERROR_CODES.WORKER_PROTOCOL,
    RUNTIME_ERROR_CODES.WORKER_NO_SUBMISSION,
    RUNTIME_ERROR_CODES.WORKER_MULTIPLE_SUBMISSIONS,
    RUNTIME_ERROR_CODES.WORKER_WRONG_NONCE,
    RUNTIME_ERROR_CODES.WORKER_SESSION_MISMATCH,
    RUNTIME_ERROR_CODES.WORKER_DUPLICATE_CANDIDATE,
    RUNTIME_ERROR_CODES.WORKER_INVALID_CANDIDATE,
]);

export const DEFAULT_SDK_RETRY_POLICY = Object.freeze({
    maxAttempts: 3,
    baseDelayMs: 250,
    maxDelayMs: 4_000,
    maxCumulativeDelayMs: 10_000,
    jitterBps: 2_000,
    reservedCostUnitsPerAttempt: 0,
    maxCostUnits: null,
});

export const SDK_RETRY_DISABLED_POLICY = Object.freeze({
    ...DEFAULT_SDK_RETRY_POLICY,
    maxAttempts: 1,
    baseDelayMs: 0,
    maxDelayMs: 0,
    maxCumulativeDelayMs: 0,
    jitterBps: 0,
});

function nonNegativeInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
        throw new RuntimeConfigError(
            `${field} must be a non-negative safe integer <= ${maximum}`,
            { field, value },
        );
    }
    return value;
}

function positiveInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        throw new RuntimeConfigError(
            `${field} must be a positive safe integer <= ${maximum}`,
            { field, value },
        );
    }
    return value;
}

function rejectUnknownKeys(value, allowed, field) {
    requirePlainObject(value, field);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            throw new RuntimeConfigError(`${field} has unknown key ${JSON.stringify(key)}`, {
                field,
                key,
            });
        }
    }
}

function checkedProduct(left, right, field) {
    const value = BigInt(left) * BigInt(right);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new RuntimeConfigError(`${field} exceeds safe integer capacity`, { field });
    }
    return Number(value);
}

function optionalFunction(value, field) {
    if (value !== null && value !== undefined && typeof value !== "function") {
        throw new RuntimeConfigError(`${field} must be a function or null`, { field });
    }
    return value ?? null;
}

export function normalizeSdkRetryPolicy(input = {}) {
    rejectUnknownKeys(input, SDK_RETRY_POLICY_KEYS, "SDK retry policy");
    const maxAttempts = positiveInteger(
        input.maxAttempts ?? DEFAULT_SDK_RETRY_POLICY.maxAttempts,
        "SDK retry policy.maxAttempts",
        16,
    );
    const baseDelayMs = nonNegativeInteger(
        input.baseDelayMs ?? DEFAULT_SDK_RETRY_POLICY.baseDelayMs,
        "SDK retry policy.baseDelayMs",
        60_000,
    );
    const maxDelayMs = nonNegativeInteger(
        input.maxDelayMs ?? DEFAULT_SDK_RETRY_POLICY.maxDelayMs,
        "SDK retry policy.maxDelayMs",
        300_000,
    );
    if (maxDelayMs < baseDelayMs) {
        throw new RuntimeConfigError(
            "SDK retry policy.maxDelayMs must be >= baseDelayMs",
            { baseDelayMs, maxDelayMs },
        );
    }
    const maxCumulativeDelayMs = nonNegativeInteger(
        input.maxCumulativeDelayMs
            ?? DEFAULT_SDK_RETRY_POLICY.maxCumulativeDelayMs,
        "SDK retry policy.maxCumulativeDelayMs",
        3_600_000,
    );
    const jitterBps = nonNegativeInteger(
        input.jitterBps ?? DEFAULT_SDK_RETRY_POLICY.jitterBps,
        "SDK retry policy.jitterBps",
        10_000,
    );
    const reservedCostUnitsPerAttempt = nonNegativeInteger(
        input.reservedCostUnitsPerAttempt
            ?? DEFAULT_SDK_RETRY_POLICY.reservedCostUnitsPerAttempt,
        "SDK retry policy.reservedCostUnitsPerAttempt",
    );
    let maxCostUnits = input.maxCostUnits
        ?? DEFAULT_SDK_RETRY_POLICY.maxCostUnits;
    if (maxCostUnits === null && reservedCostUnitsPerAttempt > 0) {
        maxCostUnits = checkedProduct(
            reservedCostUnitsPerAttempt,
            maxAttempts,
            "SDK retry policy default cost budget",
        );
    } else if (maxCostUnits !== null) {
        maxCostUnits = nonNegativeInteger(
            maxCostUnits,
            "SDK retry policy.maxCostUnits",
        );
    }
    if (maxCostUnits !== null && maxCostUnits < reservedCostUnitsPerAttempt) {
        throw new RuntimeConfigError(
            "SDK retry policy.maxCostUnits cannot fund even one reserved attempt",
            { maxCostUnits, reservedCostUnitsPerAttempt },
        );
    }
    return immutableCanonical({
        maxAttempts,
        baseDelayMs,
        maxDelayMs,
        maxCumulativeDelayMs,
        jitterBps,
        reservedCostUnitsPerAttempt,
        maxCostUnits,
    });
}

export function normalizeSdkOperationIdentity(input) {
    requirePlainObject(input, "SDK operation identity");
    const body = immutableCanonical({
        proposalSlotId: requireIdentifier(
            input.proposalSlotId,
            "SDK operation identity.proposalSlotId",
        ),
        commandId: requireIdentifier(
            input.commandId,
            "SDK operation identity.commandId",
        ),
        logicalEffectId: requireIdentifier(
            input.logicalEffectId,
            "SDK operation identity.logicalEffectId",
        ),
    });
    return immutableCanonical({
        ...body,
        operationHash: hashCanonical(
            body,
            SDK_OPERATION_IDENTITY_HASH_ALGORITHM,
        ),
    });
}

export function createSdkRetryBudget({
    policy: policyInput = DEFAULT_SDK_RETRY_POLICY,
    operationIdentity,
    deadlineMs,
} = {}) {
    const policy = normalizeSdkRetryPolicy(policyInput);
    const identity = normalizeSdkOperationIdentity(operationIdentity);
    const normalizedDeadline = parseDeadline(deadlineMs, "SDK retry deadline");
    if (policy.maxAttempts > 1 && normalizedDeadline === null) {
        throw new RuntimeConfigError(
            "Retryable SDK operations require a finite absolute deadline",
        );
    }
    if (policy.maxAttempts > 1
        && (policy.reservedCostUnitsPerAttempt < 1
            || policy.maxCostUnits === null)) {
        throw new RuntimeConfigError(
            "Retryable SDK operations require a positive frozen per-attempt cost reserve and total cost budget",
        );
    }
    const body = immutableCanonical({
        type: "crucible.sdk_retry_budget",
        version: SDK_RETRY_BUDGET_VERSION,
        operationHash: identity.operationHash,
        deadlineMs: normalizedDeadline,
        ...policy,
    });
    return immutableCanonical({
        ...body,
        budgetHash: hashCanonical(body, SDK_RETRY_BUDGET_HASH_ALGORITHM),
    });
}

function normalizeExistingSdkRetryBudget(input, operationIdentity) {
    requirePlainObject(input, "SDK retry budget");
    const identity = normalizeSdkOperationIdentity(operationIdentity);
    const canonical = createSdkRetryBudget({
        policy: {
            maxAttempts: input.maxAttempts,
            baseDelayMs: input.baseDelayMs,
            maxDelayMs: input.maxDelayMs,
            maxCumulativeDelayMs: input.maxCumulativeDelayMs,
            jitterBps: input.jitterBps,
            reservedCostUnitsPerAttempt: input.reservedCostUnitsPerAttempt,
            maxCostUnits: input.maxCostUnits,
        },
        operationIdentity: identity,
        deadlineMs: input.deadlineMs,
    });
    if (input.type !== canonical.type
        || input.version !== canonical.version
        || input.operationHash !== canonical.operationHash
        || input.budgetHash !== canonical.budgetHash) {
        throw new RuntimeConfigError("SDK retry budget is not canonical", {
            expectedBudgetHash: canonical.budgetHash,
            actualBudgetHash: input.budgetHash ?? null,
        });
    }
    return canonical;
}

function retryAfterFromHeaders(headers, nowMs) {
    if (headers === null || headers === undefined) return null;
    let value = null;
    if (typeof headers.get === "function") {
        value = headers.get("retry-after");
    } else if (typeof headers === "object") {
        value = headers["retry-after"] ?? headers["Retry-After"] ?? null;
    }
    if (value === null || value === undefined) return null;
    const seconds = Number(value);
    if (Number.isFinite(seconds) && seconds >= 0) {
        return Math.ceil(seconds * 1_000);
    }
    const timestamp = Date.parse(String(value));
    return Number.isFinite(timestamp) ? Math.max(0, Math.ceil(timestamp - nowMs)) : null;
}

function retryAfterFromValue(value, nowMs) {
    if (value === null || value === undefined) return null;
    for (const [field, multiplier] of [
        ["retryAfterMs", 1],
        ["retry_after_ms", 1],
        ["retryAfterSeconds", 1_000],
        ["retry_after_seconds", 1_000],
    ]) {
        const candidate = value?.[field];
        if (Number.isFinite(candidate) && candidate >= 0) {
            return Math.ceil(candidate * multiplier);
        }
    }
    return retryAfterFromHeaders(value?.headers ?? value?.response?.headers, nowMs);
}

function collectFailureSignals(error, context, nowMs) {
    const codes = new Set();
    const types = new Set();
    const names = new Set();
    const messages = [];
    const statuses = new Set();
    const badRequestKinds = new Set();
    const finishReasons = new Set();
    let contentFilterTriggered = false;
    const retryAfterValues = [];
    const visited = new Set();

    const visit = (value, depth = 0) => {
        if (value === null || value === undefined || depth > 5) return;
        if (typeof value === "string") {
            messages.push(value.toLowerCase());
            return;
        }
        if (typeof value !== "object" || visited.has(value)) return;
        visited.add(value);
        for (const field of ["code", "errorCode"]) {
            if (typeof value[field] === "string") {
                codes.add(value[field].toUpperCase());
            }
        }
        for (const field of ["type", "errorType"]) {
            if (typeof value[field] === "string") {
                types.add(value[field].toLowerCase());
            }
        }
        if (typeof value.name === "string") names.add(value.name.toLowerCase());
        for (const field of ["message", "errorMessage"]) {
            if (typeof value[field] === "string") {
                messages.push(value[field].toLowerCase());
            }
        }
        for (const field of ["status", "statusCode"]) {
            if (Number.isSafeInteger(value[field])) statuses.add(value[field]);
        }
        if (typeof value.badRequestKind === "string") {
            badRequestKinds.add(value.badRequestKind.toLowerCase());
        }
        if (typeof value.finishReason === "string") {
            finishReasons.add(value.finishReason.toLowerCase());
        }
        if (value.contentFilterTriggered === true) {
            contentFilterTriggered = true;
        }
        const retryAfter = retryAfterFromValue(value, nowMs);
        if (retryAfter !== null) retryAfterValues.push(retryAfter);
        visit(value.data, depth + 1);
        visit(value.details, depth + 1);
        visit(value.response, depth + 1);
        visit(value.cause, depth + 1);
        visit(value.originalError, depth + 1);
    };

    visit(error);
    for (const event of context.sdkEvents ?? []) visit(event);
    return {
        codes,
        types,
        names,
        messages,
        statuses,
        badRequestKinds,
        finishReasons,
        contentFilterTriggered,
        retryAfterMs: retryAfterValues.length === 0
            ? null
            : Math.max(...retryAfterValues),
        hasSdkEvents: Array.isArray(context.sdkEvents)
            && context.sdkEvents.length > 0,
    };
}

function includesAny(values, patterns) {
    return values.some((value) => patterns.some((pattern) => pattern.test(value)));
}

function classificationResult(classification, signals, source) {
    const statusCode = signals.statuses.size === 1
        ? [...signals.statuses][0]
        : null;
    const errorCode = signals.codes.size === 1 ? [...signals.codes][0] : null;
    const errorType = signals.types.size === 1 ? [...signals.types][0] : null;
    return immutableCanonical({
        classification,
        retryable: RETRYABLE_CLASSIFICATIONS.has(classification),
        recreateSession:
            classification === SDK_FAILURE_CLASSIFICATIONS.SESSION_RECREATE,
        retryAfterMs: signals.retryAfterMs,
        statusCode,
        errorCode,
        errorType,
        source,
    });
}

export function classifySdkFailure(error, context = {}) {
    const nowMs = Number.isFinite(context.nowMs) ? context.nowMs : Date.now();
    const signals = collectFailureSignals(error, context, nowMs);
    const stage = String(context.stage ?? error?.sdkFailureContext?.stage ?? "")
        .toLowerCase();
    const protocol = error instanceof WorkerProtocolError
        || PROTOCOL_ERROR_CODES.has(error?.code)
        || [...signals.codes].some((code) => PROTOCOL_ERROR_CODES.has(code));
    const joinedMessages = signals.messages;

    if (signals.statuses.has(401)
        || signals.statuses.has(403)
        || [...signals.types].some((type) =>
            ["authentication", "authorization", "auth"].includes(type))
        || includesAny(joinedMessages, [
            /\bunauthenticated\b/u,
            /\bunauthorized\b/u,
            /\binvalid (?:access )?token\b/u,
            /\blogin required\b/u,
            /\bnot authenticated\b/u,
            /\bforbidden\b/u,
        ])) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_AUTH,
            signals,
            "auth_signal",
        );
    }

    if (signals.statuses.has(429)
        || signals.types.has("rate_limit")
        || [...signals.codes].some((code) => code.includes("RATE_LIMIT"))
        || includesAny(joinedMessages, [/\brate limit(?:ed)?\b/u, /\btoo many requests\b/u])) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_RATE_LIMIT,
            signals,
            "rate_limit_signal",
        );
    }

    if (protocol && !signals.hasSdkEvents) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.PROTOCOL_INVALID,
            signals,
            "worker_protocol",
        );
    }

    if (signals.contentFilterTriggered
        || signals.finishReasons.has("content_filter")
        || [...signals.types].some((type) =>
        ["policy", "quota", "content_filter", "safety", "moderation"].includes(type))
        || [...signals.codes].some((code) =>
            code.includes("QUOTA")
            || code.includes("POLICY")
            || code.includes("CONTENT_FILTER"))
        || includesAny(joinedMessages, [
            /\bcontent filter\b/u,
            /\bpolicy violation\b/u,
            /\bsafety policy\b/u,
            /\bmoderation\b/u,
            /\bbilling not configured\b/u,
            /\bquota exceeded\b/u,
        ])) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_POLICY,
            signals,
            "policy_signal",
        );
    }

    if ([...signals.codes].some((code) => code.includes("MODEL"))
        || [...signals.types].some((type) => type === "model")
        || includesAny(joinedMessages, [
            /\bunknown model\b/u,
            /\bunsupported model\b/u,
            /\bmodel .{0,80}\bnot found\b/u,
            /\bmodel .{0,80}\bdisabled\b/u,
            /\binvalid model\b/u,
        ])) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_MODEL,
            signals,
            "model_signal",
        );
    }

    if ([...signals.codes].some((code) => SESSION_RECREATE_CODES.has(code))
        || includesAny(joinedMessages, [
            /\bsession .{0,60}\bnot found\b/u,
            /\bsession .{0,60}\bclosed\b/u,
            /\bsession .{0,60}\bdisconnected\b/u,
            /\bno active session\b/u,
            /\bsession .{0,60}\bdisposed\b/u,
        ])) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.SESSION_RECREATE,
            signals,
            "session_signal",
        );
    }

    if (signals.badRequestKinds.has("structured_error")
        || [...signals.types].some((type) =>
            ["schema", "validation", "structured_error"].includes(type))
        || [...signals.codes].some((code) =>
            code.includes("SCHEMA") || code.includes("VALIDATION"))
        || includesAny(joinedMessages, [
            /\bjson schema\b/u,
            /\btool schema\b/u,
            /\bschema validation\b/u,
            /\bmalformed request\b/u,
        ])) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_SCHEMA,
            signals,
            "schema_signal",
        );
    }

    if (signals.statuses.has(400)
        || signals.statuses.has(404)
        || signals.statuses.has(409)
        || signals.statuses.has(422)
        || [...signals.types].some((type) =>
            ["context_limit", "configuration", "config", "query"].includes(type))
        || includesAny(joinedMessages, [
            /\binvalid (?:argument|configuration|config|request)\b/u,
            /\bcontext (?:window )?limit\b/u,
            /\bprompt too long\b/u,
            /\bmax prompt tokens\b/u,
        ])) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.PERMANENT_CONFIG,
            signals,
            "config_signal",
        );
    }

    if (protocol) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.PROTOCOL_INVALID,
            signals,
            "worker_protocol",
        );
    }

    if (stage.includes("startup")
        || error?.code === RUNTIME_ERROR_CODES.WORKER_STARTUP) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_STARTUP,
            signals,
            "startup_stage",
        );
    }

    if (signals.badRequestKinds.has("bodyless")
        || [...signals.codes].some((code) => NODE_TRANSPORT_CODES.has(code))
        || [...signals.statuses].some((status) =>
            status === 408 || status === 425 || (status >= 500 && status <= 599))
        || error?.code === RUNTIME_ERROR_CODES.CHILD_CRASH
        || includesAny(joinedMessages, [
            /\bnetwork error\b/u,
            /\bconnection (?:reset|closed|lost|refused)\b/u,
            /\bsocket hang up\b/u,
            /\bgateway timeout\b/u,
            /\btemporarily unavailable\b/u,
            /\bfetch failed\b/u,
        ])) {
        return classificationResult(
            SDK_FAILURE_CLASSIFICATIONS.TRANSIENT_TRANSPORT,
            signals,
            "transport_signal",
        );
    }

    return classificationResult(
        SDK_FAILURE_CLASSIFICATIONS.UNKNOWN,
        signals,
        "fail_closed",
    );
}

export function computeSdkRetryDelay(policyInput, {
    operationIdentity,
    failedAttempt,
    retryAfterMs = null,
} = {}) {
    const policy = normalizeSdkRetryPolicy(policyInput);
    const identity = normalizeSdkOperationIdentity(operationIdentity);
    positiveInteger(failedAttempt, "failedAttempt", policy.maxAttempts);
    const exponential = Math.min(
        policy.maxDelayMs,
        policy.baseDelayMs * (2 ** Math.min(30, failedAttempt - 1)),
    );
    const spread = Math.floor((exponential * policy.jitterBps) / 10_000);
    const unit = deterministicFraction(
        `${identity.operationHash}:${failedAttempt}:sdk-retry-jitter-v1`,
    );
    const signed = (unit * 2) - 1;
    const jittered = Math.max(
        0,
        Math.min(policy.maxDelayMs, Math.round(exponential + (signed * spread))),
    );
    const serverMinimumMs = retryAfterMs === null
        ? 0
        : nonNegativeInteger(retryAfterMs, "retryAfterMs", 3_600_000);
    return immutableCanonical({
        delayMs: Math.max(jittered, Math.min(serverMinimumMs, policy.maxDelayMs)),
        exponentialDelayMs: exponential,
        jitteredDelayMs: jittered,
        serverMinimumMs,
        admissible: serverMinimumMs <= policy.maxDelayMs,
    });
}

export function reconcileSdkCost({
    reservedCostUnitsPerAttempt,
    attemptedCount,
    sdkReportedCostUnits = [],
    priorChargedCostUnits = 0,
    maxCostUnits = null,
} = {}) {
    const perAttempt = nonNegativeInteger(
        reservedCostUnitsPerAttempt,
        "reservedCostUnitsPerAttempt",
    );
    const attempts = nonNegativeInteger(attemptedCount, "attemptedCount", 16);
    const reservedCostUnits = checkedProduct(
        perAttempt,
        attempts,
        "reserved SDK retry cost",
    );
    const reportedCostUnits = checkedSafeIntegerSum(
        sdkReportedCostUnits,
        "SDK reported cost units",
    );
    const prior = nonNegativeInteger(
        priorChargedCostUnits,
        "priorChargedCostUnits",
    );
    const maximum = maxCostUnits === null
        ? null
        : nonNegativeInteger(maxCostUnits, "maxCostUnits");
    const chargedCostUnits = Math.max(
        reservedCostUnits,
        reportedCostUnits,
        prior,
    );
    return immutableCanonical({
        attemptedCount: attempts,
        reservedCostUnits,
        reportedCostUnits,
        priorChargedCostUnits: prior,
        chargedCostUnits,
        maxCostUnits: maximum,
        overBudget: maximum !== null && chargedCostUnits > maximum,
    });
}

function sdkUsageCount(value, field) {
    if (value === undefined || value === null) return 0;
    return nonNegativeInteger(value, field);
}

export function normalizeSdkUsageEvent(event, fallbackModel = null) {
    if (event === null || typeof event !== "object") return null;
    const data = event.type === "assistant.usage" ? event.data : event;
    if (data === null || typeof data !== "object") return null;
    const model = typeof data.model === "string" && data.model.length > 0
        ? data.model
        : fallbackModel;
    if (typeof model !== "string" || model.length === 0) return null;
    const inputTokens = sdkUsageCount(data.inputTokens, "SDK usage inputTokens");
    const cachedInputTokens = checkedSafeIntegerSum([
        sdkUsageCount(data.cacheReadTokens, "SDK usage cacheReadTokens"),
        sdkUsageCount(data.cacheWriteTokens, "SDK usage cacheWriteTokens"),
    ], "SDK cached input tokens");
    const outputTokens = sdkUsageCount(data.outputTokens, "SDK usage outputTokens");
    const reasoningTokens = sdkUsageCount(
        data.reasoningTokens,
        "SDK usage reasoningTokens",
    );
    const totalTokens = checkedSafeIntegerSum([
        inputTokens,
        cachedInputTokens,
        outputTokens,
        reasoningTokens,
    ], "SDK usage totalTokens");
    return immutableCanonical({
        model: requireString(model, "SDK usage model", { max: 128 }),
        inputTokens,
        cachedInputTokens,
        outputTokens,
        reasoningTokens,
        totalTokens,
    });
}

export function createSdkUsageAccumulator({ model = null } = {}) {
    const reports = new Map();
    const calls = [];
    const seen = new Set();
    let invalidEventCount = 0;
    let eventCount = 0;
    return Object.freeze({
        observe(event) {
            const key = typeof event?.id === "string"
                ? `event:${event.id}`
                : typeof event?.data?.apiCallId === "string"
                    ? `call:${event.data.apiCallId}`
                    : null;
            if (key !== null && seen.has(key)) return false;
            let normalized;
            try {
                normalized = normalizeSdkUsageEvent(event, model);
            } catch {
                invalidEventCount += 1;
                return false;
            }
            if (normalized === null) {
                invalidEventCount += 1;
                return false;
            }
            if (key !== null) seen.add(key);
            calls.push(normalized);
            eventCount += 1;
            const prior = reports.get(normalized.model) ?? {
                model: normalized.model,
                inputTokens: 0,
                cachedInputTokens: 0,
                outputTokens: 0,
                reasoningTokens: 0,
                totalTokens: 0,
            };
            for (const field of [
                "inputTokens",
                "cachedInputTokens",
                "outputTokens",
                "reasoningTokens",
                "totalTokens",
            ]) {
                prior[field] = checkedSafeIntegerSum(
                    [prior[field], normalized[field]],
                    `aggregated SDK usage ${field}`,
                );
            }
            reports.set(normalized.model, prior);
            return true;
        },
        snapshot() {
            return immutableCanonical({
                calls,
                reports: [...reports.values()]
                    .sort((left, right) => left.model.localeCompare(right.model)),
                eventCount,
                invalidEventCount,
            });
        },
    });
}

export function createSdkOperationalEvidence({
    eventType,
    operationIdentity,
    attempt = 0,
    observedAtMs,
    classification = null,
    reason = null,
    details = {},
} = {}) {
    if (!OPERATIONAL_EVENT_TYPES.has(eventType)) {
        throw new RuntimeConfigError("Unsupported SDK operational evidence event type", {
            eventType,
        });
    }
    const identity = normalizeSdkOperationIdentity(operationIdentity);
    const body = immutableCanonical({
        type: "crucible.sdk_operational_evidence",
        version: SDK_OPERATIONAL_EVIDENCE_VERSION,
        eventType,
        operationHash: identity.operationHash,
        proposalSlotId: identity.proposalSlotId,
        commandId: identity.commandId,
        logicalEffectId: identity.logicalEffectId,
        attempt: nonNegativeInteger(attempt, "SDK evidence attempt", 16),
        observedAtMs: nonNegativeInteger(
            observedAtMs,
            "SDK evidence observedAtMs",
        ),
        classification,
        reason,
        details: immutableCanonical(details),
    });
    return immutableCanonical({
        ...body,
        evidenceHash: hashCanonical(
            body,
            SDK_OPERATIONAL_EVIDENCE_HASH_ALGORITHM,
        ),
    });
}

export function createSdkQuarantineRecord(input = {}) {
    return createSdkOperationalEvidence({
        ...input,
        eventType: "response_quarantined",
    });
}

export function normalizeSdkSubmissionJournal(input) {
    requirePlainObject(input, "SDK submission journal");
    if (typeof input.recover !== "function" || typeof input.commit !== "function") {
        throw new RuntimeConfigError(
            "SDK submission journal must expose recover() and commit()",
        );
    }
    if (input.durable === true && typeof input.quarantine !== "function") {
        throw new RuntimeConfigError(
            "Durable SDK submission journals must persist quarantine records",
        );
    }
    return Object.freeze({
        durable: input.durable === true,
        recover: input.recover.bind(input),
        commit: input.commit.bind(input),
        quarantine: optionalFunction(
            input.quarantine,
            "SDK submission journal.quarantine",
        ) ?? (async () => undefined),
        recordEvidence: optionalFunction(
            input.recordEvidence,
            "SDK submission journal.recordEvidence",
        ) ?? (async () => undefined),
    });
}


function createSubmissionCommitRecord({
    operationIdentity,
    retryBudget,
    submission,
    attempt,
    invocation,
    sealedAtMs,
}) {
    const identity = normalizeSdkOperationIdentity(operationIdentity);
    const budget = normalizeExistingSdkRetryBudget(retryBudget, identity);
    const submissionHash = hashCanonical(
        submission,
        SDK_SUBMISSION_HASH_ALGORITHM,
    );
    const body = immutableCanonical({
        type: "crucible.sdk_submission_commit",
        version: SDK_SUBMISSION_COMMIT_VERSION,
        operationHash: identity.operationHash,
        proposalSlotId: identity.proposalSlotId,
        commandId: identity.commandId,
        logicalEffectId: identity.logicalEffectId,
        budgetHash: budget.budgetHash,
        submissionHash,
        submission,
        attempt: positiveInteger(attempt, "submission attempt", 16),
        invocation: immutableCanonical({
            sessionId: requireString(
                invocation?.sessionId,
                "submission invocation.sessionId",
                { max: 256 },
            ),
            toolCallId: invocation?.toolCallId === undefined
                || invocation?.toolCallId === null
                ? null
                : requireString(
                    invocation.toolCallId,
                    "submission invocation.toolCallId",
                    { max: 256 },
                ),
            toolName: requireString(
                invocation?.toolName,
                "submission invocation.toolName",
                { max: 256 },
            ),
        }),
        sealedAtMs: nonNegativeInteger(sealedAtMs, "submission sealedAtMs"),
    });
    return immutableCanonical({
        ...body,
        commitHash: hashCanonical(body, SDK_SUBMISSION_COMMIT_HASH_ALGORITHM),
    });
}

function validateSubmissionCommitRecord(record, {
    operationIdentity,
    retryBudget,
    validateSubmission,
}) {
    requirePlainObject(record, "SDK submission commit record");
    const expectedKeys = [
        "attempt",
        "budgetHash",
        "commandId",
        "commitHash",
        "invocation",
        "logicalEffectId",
        "operationHash",
        "proposalSlotId",
        "sealedAtMs",
        "submission",
        "submissionHash",
        "type",
        "version",
    ];
    const actualKeys = Object.keys(record).sort();
    if (actualKeys.length !== expectedKeys.length
        || actualKeys.some((key, index) => key !== expectedKeys[index])) {
        throw new SdkSubmissionConflictError(
            "Recovered SDK submission commit has an invalid schema",
            { keys: actualKeys },
        );
    }
    const identity = normalizeSdkOperationIdentity(operationIdentity);
    if (record.type !== "crucible.sdk_submission_commit"
        || record.version !== SDK_SUBMISSION_COMMIT_VERSION
        || record.operationHash !== identity.operationHash
        || record.proposalSlotId !== identity.proposalSlotId
        || record.commandId !== identity.commandId
        || record.logicalEffectId !== identity.logicalEffectId
        || record.budgetHash !== retryBudget.budgetHash) {
        throw new SdkSubmissionConflictError(
            "Recovered SDK submission is bound to different operation authority",
            {
                expectedOperationHash: identity.operationHash,
                actualOperationHash: record.operationHash ?? null,
                expectedBudgetHash: retryBudget.budgetHash,
                actualBudgetHash: record.budgetHash ?? null,
            },
        );
    }
    positiveInteger(
        record.attempt,
        "recovered submission attempt",
        retryBudget.maxAttempts,
    );
    nonNegativeInteger(record.sealedAtMs, "recovered submission sealedAtMs");
    requirePlainObject(record.invocation, "recovered submission invocation");
    const invocationKeys = Object.keys(record.invocation).sort();
    const expectedInvocationKeys = ["sessionId", "toolCallId", "toolName"];
    if (invocationKeys.length !== expectedInvocationKeys.length
        || invocationKeys.some((key, index) =>
            key !== expectedInvocationKeys[index])) {
        throw new SdkSubmissionConflictError(
            "Recovered SDK submission invocation has an invalid schema",
            { keys: invocationKeys },
        );
    }
    requireString(
        record.invocation.sessionId,
        "recovered submission invocation.sessionId",
        { max: 256 },
    );
    requireString(
        record.invocation.toolName,
        "recovered submission invocation.toolName",
        { max: 256 },
    );
    if (record.invocation.toolCallId !== null) {
        requireString(
            record.invocation.toolCallId,
            "recovered submission invocation.toolCallId",
            { max: 256 },
        );
    }
    const submission = validateSubmission(record.submission);
    const submissionHash = hashCanonical(
        submission,
        SDK_SUBMISSION_HASH_ALGORITHM,
    );
    if (record.submissionHash !== submissionHash) {
        throw new SdkSubmissionConflictError(
            "Recovered SDK submission hash does not match its payload",
            {
                expected: submissionHash,
                actual: record.submissionHash ?? null,
            },
        );
    }
    const body = { ...record };
    delete body.commitHash;
    const commitHash = hashCanonical(body, SDK_SUBMISSION_COMMIT_HASH_ALGORITHM);
    if (record.commitHash !== commitHash) {
        throw new SdkSubmissionConflictError(
            "Recovered SDK submission commit hash is invalid",
            { expected: commitHash, actual: record.commitHash ?? null },
        );
    }
    return Object.freeze({ record, submission });
}

function isInjectedCrash(error, visited = new Set()) {
    if (error === null
        || error === undefined
        || typeof error !== "object"
        || visited.has(error)) {
        return false;
    }
    visited.add(error);
    return error instanceof InjectedCrashError
        || error.code === RUNTIME_ERROR_CODES.INJECTED_CRASH
        || isInjectedCrash(error.cause, visited)
        || isInjectedCrash(error.originalError, visited);
}

export function createSdkSubmissionGate({
    operationIdentity,
    retryBudget,
    journal: journalInput,
    validateSubmission = (submission) => submission,
    clock = { now: () => Date.now() },
} = {}) {
    const identity = normalizeSdkOperationIdentity(operationIdentity);
    const budget = normalizeExistingSdkRetryBudget(retryBudget, identity);
    const journal = normalizeSdkSubmissionJournal(journalInput);
    if (typeof validateSubmission !== "function") {
        throw new RuntimeConfigError("validateSubmission must be a function");
    }
    if (typeof clock?.now !== "function") {
        throw new RuntimeConfigError("submission gate clock must expose now()");
    }
    let sealed = null;
    let commitInFlight = null;
    let closed = false;

    const quarantine = async ({
        attempt,
        reason,
        classification = null,
        details = {},
    }) => {
        const record = createSdkQuarantineRecord({
            operationIdentity: identity,
            attempt,
            observedAtMs: Math.max(0, Math.floor(clock.now())),
            classification,
            reason,
            details: {
                budgetHash: budget.budgetHash,
                ...details,
            },
        });
        await journal.quarantine(record);
        return record;
    };

    const recover = async () => {
        if (sealed !== null) return sealed;
        const recovered = await journal.recover({ operationIdentity: identity });
        if (recovered === null || recovered === undefined) return null;
        sealed = validateSubmissionCommitRecord(recovered, {
            operationIdentity: identity,
            retryBudget: budget,
            validateSubmission,
        });
        return sealed;
    };

    return Object.freeze({
        durable: journal.durable,
        get sealed() {
            return sealed;
        },
        async recover() {
            return recover();
        },
        async seal({ submission, attempt, invocation } = {}) {
            if (closed || sealed !== null || commitInFlight !== null) {
                await quarantine({
                    attempt,
                    reason: closed ? "late_tool_callback" : "duplicate_tool_callback",
                    details: {
                        sealedSubmissionHash: sealed?.record?.submissionHash ?? null,
                        commitInFlight: commitInFlight !== null,
                    },
                });
                return Object.freeze({ status: "quarantined", sealed });
            }
            const validated = validateSubmission(submission);
            const record = createSubmissionCommitRecord({
                operationIdentity: identity,
                retryBudget: budget,
                submission: validated,
                attempt,
                invocation,
                sealedAtMs: Math.max(0, Math.floor(clock.now())),
            });
            commitInFlight = (async () => {
                let outcome;
                try {
                    outcome = await journal.commit(record);
                } catch (error) {
                    if (isInjectedCrash(error)) throw error;
                    const recovered = await recover();
                    if (recovered !== null
                        && recovered.record.submissionHash === record.submissionHash) {
                        return Object.freeze({
                            status: "recovered_after_ambiguous_commit",
                            ...recovered,
                        });
                    }
                    throw new CrucibleRuntimeError(
                        RUNTIME_ERROR_CODES.UNCERTAIN_EXTERNAL_EFFECT,
                        "SDK submission commit failed without a matching durable recovery",
                        {
                            operationHash: identity.operationHash,
                            submissionHash: record.submissionHash,
                        },
                        { cause: error },
                    );
                }
                if (outcome === null
                    || typeof outcome !== "object"
                    || !["committed", "existing"].includes(outcome.status)
                    || outcome.record === null
                    || typeof outcome.record !== "object") {
                    throw new RuntimeConfigError(
                        "SDK submission journal.commit() returned an invalid outcome",
                    );
                }
                const accepted = validateSubmissionCommitRecord(outcome.record, {
                    operationIdentity: identity,
                    retryBudget: budget,
                    validateSubmission,
                });
                if (accepted.record.submissionHash !== record.submissionHash
                    || !canonicalEqual(accepted.submission, validated)) {
                    await quarantine({
                        attempt,
                        reason: "conflicting_durable_submission",
                        details: {
                            attemptedSubmissionHash: record.submissionHash,
                            sealedSubmissionHash: accepted.record.submissionHash,
                        },
                    });
                    throw new SdkSubmissionConflictError(
                        "A different SDK tool submission is already sealed for this effect",
                        {
                            operationHash: identity.operationHash,
                            attemptedSubmissionHash: record.submissionHash,
                            sealedSubmissionHash: accepted.record.submissionHash,
                        },
                    );
                }
                sealed = accepted;
                return Object.freeze({ status: outcome.status, ...accepted });
            })();
            try {
                return await commitInFlight;
            } finally {
                commitInFlight = null;
            }
        },
        async quarantine(input) {
            return quarantine(input);
        },
        close() {
            closed = true;
        },
    });
}

function classifiedFailureError(error, classification, context) {
    const original = error?.originalError ?? error?.cause ?? error;
    if (classification.classification === SDK_FAILURE_CLASSIFICATIONS.PROTOCOL_INVALID
        && original instanceof CrucibleRuntimeError) {
        original.details = {
            ...(original.details ?? {}),
            sdkFailure: classification,
            sdkRetry: context,
        };
        return original;
    }
    return new SdkFailureError(
        `SDK operation failed permanently (${classification.classification})`,
        {
            classification,
            ...context,
            originalCode: original?.code ?? null,
            originalName: original?.name ?? null,
        },
        { cause: original },
    );
}

function retryExhausted(reason, {
    identity,
    budget,
    attempts,
    cumulativeDelayMs,
    classification,
    accounting,
    error,
}) {
    return new SdkRetryExhaustedError(
        `SDK retry budget exhausted: ${reason}`,
        {
            reason,
            operationHash: identity.operationHash,
            proposalSlotId: identity.proposalSlotId,
            commandId: identity.commandId,
            logicalEffectId: identity.logicalEffectId,
            budgetHash: budget.budgetHash,
            attempts,
            cumulativeDelayMs,
            classification,
            accounting,
        },
        error === undefined ? undefined : { cause: error },
    );
}

export function createRetryingSdkClient(client, {
    policy: policyInput = DEFAULT_SDK_RETRY_POLICY,
    clock = { now: () => Date.now() },
    sleep = null,
    timers = globalThis,
    evidenceSink = null,
} = {}) {
    if (client === null || typeof client !== "object") {
        throw new RuntimeConfigError("retrying SDK client requires a client object");
    }
    const policy = normalizeSdkRetryPolicy(policyInput);
    if (typeof clock?.now !== "function") {
        throw new RuntimeConfigError("retrying SDK client clock must expose now()");
    }
    const sleeper = sleep === null
        ? (milliseconds) => delay(milliseconds, timers)
        : sleep;
    if (typeof sleeper !== "function") {
        throw new RuntimeConfigError("retrying SDK client sleep must be a function");
    }
    optionalFunction(evidenceSink, "retrying SDK client evidenceSink");

    return Object.freeze({
        client,
        policy,
        async execute({
            operationIdentity,
            deadlineMs,
            operation,
            recover = null,
            classifyFailure = classifySdkFailure,
            getSdkReportedCostUnits = () => [],
            priorChargedCostUnits = 0,
        } = {}) {
            if (typeof operation !== "function") {
                throw new RuntimeConfigError("SDK retry operation must be a function");
            }
            optionalFunction(recover, "SDK retry recover");
            if (typeof classifyFailure !== "function"
                || typeof getSdkReportedCostUnits !== "function") {
                throw new RuntimeConfigError(
                    "SDK retry classifyFailure/getSdkReportedCostUnits must be functions",
                );
            }
            const identity = normalizeSdkOperationIdentity(operationIdentity);
            const budget = createSdkRetryBudget({
                policy,
                operationIdentity: identity,
                deadlineMs,
            });
            const emitted = [];
            const emit = async (eventType, attempt, fields = {}) => {
                const event = createSdkOperationalEvidence({
                    eventType,
                    operationIdentity: identity,
                    attempt,
                    observedAtMs: Math.max(0, Math.floor(clock.now())),
                    ...fields,
                    details: {
                        budgetHash: budget.budgetHash,
                        ...(fields.details ?? {}),
                    },
                });
                emitted.push(event);
                if (evidenceSink !== null) await evidenceSink(event);
                return event;
            };
            const recoverValue = async (attempt) => {
                if (recover === null) return null;
                const recovered = await recover({
                    attempt,
                    operationIdentity: identity,
                    retryBudget: budget,
                });
                if (recovered !== null && recovered !== undefined) {
                    const envelope = recovered?.recovered === true
                        && Object.hasOwn(recovered, "value")
                        ? recovered
                        : { value: recovered, attemptedCount: attempt };
                    const attemptedCount = nonNegativeInteger(
                        envelope.attemptedCount ?? attempt,
                        "recovered SDK attemptedCount",
                        budget.maxAttempts,
                    );
                    await emit("submission_recovered", attempt, {
                        reason: attempt === 0
                            ? "recovered_before_sdk_call"
                            : "recovered_after_sdk_failure",
                        details: { attemptedCount },
                    });
                    return Object.freeze({
                        value: envelope.value,
                        attemptedCount,
                    });
                }
                return null;
            };

            const initial = await recoverValue(0);
            if (initial !== null) {
                return Object.freeze({
                    value: initial.value,
                    attempts: initial.attemptedCount,
                    recovered: true,
                    retryBudget: budget,
                    accounting: reconcileSdkCost({
                        reservedCostUnitsPerAttempt:
                            budget.reservedCostUnitsPerAttempt,
                        attemptedCount: initial.attemptedCount,
                        sdkReportedCostUnits: getSdkReportedCostUnits(),
                        priorChargedCostUnits,
                        maxCostUnits: budget.maxCostUnits,
                    }),
                    evidence: Object.freeze(emitted),
                });
            }

            let attempts = 0;
            let cumulativeDelayMs = 0;
            let lastClassification = null;
            let lastError = null;
            while (attempts < budget.maxAttempts) {
                const nextAttempt = attempts + 1;
                const projectedReserved = checkedProduct(
                    budget.reservedCostUnitsPerAttempt,
                    nextAttempt,
                    "projected SDK retry cost",
                );
                const accountingBeforeAttempt = reconcileSdkCost({
                    reservedCostUnitsPerAttempt:
                        budget.reservedCostUnitsPerAttempt,
                    attemptedCount: attempts,
                    sdkReportedCostUnits: getSdkReportedCostUnits(),
                    priorChargedCostUnits,
                    maxCostUnits: budget.maxCostUnits,
                });
                const projectedChargedCostUnits = Math.max(
                    projectedReserved,
                    checkedSafeIntegerSum(
                        [
                            accountingBeforeAttempt.chargedCostUnits,
                            budget.reservedCostUnitsPerAttempt,
                        ],
                        "projected SDK retry charged cost",
                    ),
                );
                if (budget.maxCostUnits !== null
                    && projectedChargedCostUnits > budget.maxCostUnits) {
                    throw retryExhausted("cost_budget", {
                        identity,
                        budget,
                        attempts,
                        cumulativeDelayMs,
                        classification: lastClassification,
                        accounting: accountingBeforeAttempt,
                        error: lastError,
                    });
                }
                if (remainingDeadlineMs(budget.deadlineMs, clock.now()) === 0) {
                    throw retryExhausted("absolute_deadline", {
                        identity,
                        budget,
                        attempts,
                        cumulativeDelayMs,
                        classification: lastClassification,
                        accounting: accountingBeforeAttempt,
                        error: lastError,
                    });
                }
                attempts = nextAttempt;
                await emit("attempt_started", attempts, {
                    details: { projectedReservedCostUnits: projectedReserved },
                });
                try {
                    const value = await operation(client, {
                        attempt: attempts,
                        operationIdentity: identity,
                        retryBudget: budget,
                    });
                    const accounting = reconcileSdkCost({
                        reservedCostUnitsPerAttempt:
                            budget.reservedCostUnitsPerAttempt,
                        attemptedCount: attempts,
                        sdkReportedCostUnits: getSdkReportedCostUnits(),
                        priorChargedCostUnits,
                        maxCostUnits: budget.maxCostUnits,
                    });
                    await emit("cost_reconciled", attempts, {
                        reason: accounting.overBudget
                            ? "observed_usage_over_budget"
                            : "conservative_maximum",
                        details: accounting,
                    });
                    return Object.freeze({
                        value,
                        attempts,
                        recovered: false,
                        retryBudget: budget,
                        accounting,
                        evidence: Object.freeze(emitted),
                    });
                } catch (error) {
                    if (isInjectedCrash(error)) throw error;
                    lastError = error;
                    const recovered = await recoverValue(attempts);
                    if (recovered !== null) {
                        const recoveredAttempts = Math.max(
                            attempts,
                            recovered.attemptedCount,
                        );
                        const accounting = reconcileSdkCost({
                            reservedCostUnitsPerAttempt:
                                budget.reservedCostUnitsPerAttempt,
                            attemptedCount: recoveredAttempts,
                            sdkReportedCostUnits: getSdkReportedCostUnits(),
                            priorChargedCostUnits,
                            maxCostUnits: budget.maxCostUnits,
                        });
                        return Object.freeze({
                            value: recovered.value,
                            attempts: recoveredAttempts,
                            recovered: true,
                            retryBudget: budget,
                            accounting,
                            evidence: Object.freeze(emitted),
                        });
                    }
                    const failureContext = error?.sdkFailureContext ?? {};
                    const classification = classifyFailure(error, {
                        ...failureContext,
                        nowMs: clock.now(),
                    });
                    lastClassification = classification;
                    await emit("attempt_failed", attempts, {
                        classification: classification.classification,
                        reason: classification.source,
                        details: {
                            retryable: classification.retryable,
                            recreateSession: classification.recreateSession,
                            retryAfterMs: classification.retryAfterMs,
                            statusCode: classification.statusCode,
                            errorCode: classification.errorCode,
                            errorType: classification.errorType,
                        },
                    });
                    if (!classification.retryable) {
                        throw classifiedFailureError(error, classification, {
                            attempts,
                            cumulativeDelayMs,
                            budgetHash: budget.budgetHash,
                        });
                    }
                    const accounting = reconcileSdkCost({
                        reservedCostUnitsPerAttempt:
                            budget.reservedCostUnitsPerAttempt,
                        attemptedCount: attempts,
                        sdkReportedCostUnits: getSdkReportedCostUnits(),
                        priorChargedCostUnits,
                        maxCostUnits: budget.maxCostUnits,
                    });
                    if (attempts >= budget.maxAttempts) {
                        throw retryExhausted("attempt_budget", {
                            identity,
                            budget,
                            attempts,
                            cumulativeDelayMs,
                            classification,
                            accounting,
                            error,
                        });
                    }
                    const nextReserved = checkedProduct(
                        budget.reservedCostUnitsPerAttempt,
                        attempts + 1,
                        "next SDK retry reserved cost",
                    );
                    const nextCharged = Math.max(
                        nextReserved,
                        checkedSafeIntegerSum(
                            [
                                accounting.chargedCostUnits,
                                budget.reservedCostUnitsPerAttempt,
                            ],
                            "next SDK retry charged cost",
                        ),
                    );
                    if (budget.maxCostUnits !== null
                        && nextCharged > budget.maxCostUnits) {
                        throw retryExhausted("cost_budget", {
                            identity,
                            budget,
                            attempts,
                            cumulativeDelayMs,
                            classification,
                            accounting,
                            error,
                        });
                    }
                    const backoff = computeSdkRetryDelay(policy, {
                        operationIdentity: identity,
                        failedAttempt: attempts,
                        retryAfterMs: classification.retryAfterMs,
                    });
                    if (!backoff.admissible) {
                        throw retryExhausted("server_delay_exceeds_budget", {
                            identity,
                            budget,
                            attempts,
                            cumulativeDelayMs,
                            classification,
                            accounting,
                            error,
                        });
                    }
                    if (cumulativeDelayMs + backoff.delayMs
                        > budget.maxCumulativeDelayMs) {
                        throw retryExhausted("delay_budget", {
                            identity,
                            budget,
                            attempts,
                            cumulativeDelayMs,
                            classification,
                            accounting,
                            error,
                        });
                    }
                    if (remainingDeadlineMs(budget.deadlineMs, clock.now())
                        <= backoff.delayMs) {
                        throw retryExhausted("absolute_deadline", {
                            identity,
                            budget,
                            attempts,
                            cumulativeDelayMs,
                            classification,
                            accounting,
                            error,
                        });
                    }
                    await emit("retry_scheduled", attempts, {
                        classification: classification.classification,
                        reason: "bounded_exponential_backoff",
                        details: backoff,
                    });
                    await sleeper(backoff.delayMs);
                    cumulativeDelayMs += backoff.delayMs;
                }
            }
            throw retryExhausted("attempt_budget", {
                identity,
                budget,
                attempts,
                cumulativeDelayMs,
                classification: lastClassification,
                accounting: reconcileSdkCost({
                    reservedCostUnitsPerAttempt:
                        budget.reservedCostUnitsPerAttempt,
                    attemptedCount: attempts,
                    sdkReportedCostUnits: getSdkReportedCostUnits(),
                    priorChargedCostUnits,
                    maxCostUnits: budget.maxCostUnits,
                }),
                error: lastError,
            });
        },
    });
}

export function withSdkFailureContext(error, context = {}) {
    const wrapped = new Error(
        error?.message ?? String(error),
        { cause: error },
    );
    wrapped.name = "SdkAttemptFailure";
    wrapped.originalError = error;
    wrapped.sdkFailureContext = immutableCanonical({
        stage: context.stage ?? null,
        sdkEvents: context.sdkEvents ?? [],
    });
    return wrapped;
}
