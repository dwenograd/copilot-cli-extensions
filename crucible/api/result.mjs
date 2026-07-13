// crucible/api/result.mjs
//
// Structured result helpers for the Crucible API boundary. Every tool returns
// JSON (never prose) as `{ textResultForLlm, resultType }` so the orchestrating
// agent can only relay what the code computed, never reinterpret a verdict.
//
// The two banners encode the load-bearing result/non-result boundary:
//   * TERMINAL_BANNER prefixes a genuine, persisted terminal decision.
//   * NON_RESULT_BANNER marks everything else, and its exact text is a contract
//     the calling agent is instructed to honor: do NOT report as complete.

export const TERMINAL_BANNER = "===== CRUCIBLE TERMINAL RESULT =====";
export const NON_RESULT_BANNER = "NOT A RESULT — DO NOT REPORT AS COMPLETE";
export const INTEGRITY_NON_RESULT_BANNER =
    "===== CRUCIBLE INTEGRITY BLOCKED — NOT A RESULT =====";

const TERMINAL_DECISION_VALUES = Object.freeze([
    "VERIFIED_RESULT",
    "TARGET_UNREACHABLE",
]);

const RESULT_ONLY_FIELD_NAMES = new Set([
    "basis",
    "artifact_closure",
    "assumptions",
    "authority_closure",
    "candidate_id",
    "candidate_ids",
    "cohort_status",
    "decision",
    "discovery_stop",
    "evidence_closure",
    "evidence_hash",
    "evidence_hashes",
    "evidence_id",
    "evidence_ids",
    "held_out_state",
    "integrity_verified",
    "limitations",
    "performance_claims",
    "prediction_outcomes",
    "scientific_replay",
    "scientific_conclusion",
    "scientific_conclusions",
    "statistical_summaries",
    "statistical_summary",
    "statistics",
    "relation_evidence",
    "relation_evidence_hash",
    "terminal_closure",
    "terminal_decision",
    "terminal_event_hash",
    "terminal_seq",
    "unreachable_verifier",
    "winner_cohort_id",
    "winner_cohort_ids",
    "winner_id",
    "winner_ids",
]);

const RESULT_ONLY_FIELD_PATTERNS = Object.freeze([
    /^(?:winner|winning)(?:_|$)/u,
    /^cohort(?:_|$)/u,
    /^evidence(?:_|$)/u,
    /^statistical(?:_|$)/u,
]);

function publicPayloadInvariant(message, details = {}) {
    const error = new Error(`Crucible public payload invariant failed: ${message}`);
    error.code = "CRUCIBLE_API_PUBLIC_PAYLOAD_INVARIANT";
    error.details = details;
    return error;
}

function isResultOnlyField(name) {
    return RESULT_ONLY_FIELD_NAMES.has(name)
        || RESULT_ONLY_FIELD_PATTERNS.some((pattern) => pattern.test(name));
}

function findRestrictedResultData(value, path = "$", seen = new WeakSet()) {
    if (TERMINAL_DECISION_VALUES.includes(value)) {
        return { path, kind: "terminal_decision_value" };
    }
    if (value === null || typeof value !== "object") {
        return null;
    }
    if (seen.has(value)) {
        return null;
    }
    seen.add(value);
    if (Array.isArray(value)) {
        for (let index = 0; index < value.length; index += 1) {
            const restricted = findRestrictedResultData(
                value[index],
                `${path}[${index}]`,
                seen,
            );
            if (restricted !== null) return restricted;
        }
        return null;
    }
    for (const [key, nested] of Object.entries(value)) {
        const nestedPath = `${path}.${key}`;
        if (isResultOnlyField(key)) {
            return { path: nestedPath, kind: "result_only_field" };
        }
        const restricted = findRestrictedResultData(nested, nestedPath, seen);
        if (restricted !== null) return restricted;
    }
    return null;
}

export function terminalAvailable(investigationId) {
    return {
        is_result: false,
        investigation_id: investigationId,
        terminal_available: true,
    };
}

export function assertPublicToolPayload(toolName, data) {
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
        throw publicPayloadInvariant(`${toolName} returned a non-object payload`);
    }
    if (typeof data.is_result !== "boolean") {
        throw publicPayloadInvariant(`${toolName} omitted boolean is_result`);
    }

    const hasTerminalAuthority = toolName === "crucible_result";
    if (data.is_result && !hasTerminalAuthority) {
        throw publicPayloadInvariant(
            `${toolName} attempted to claim terminal-result authority`,
        );
    }

    if (!hasTerminalAuthority || data.is_result === false) {
        const restricted = findRestrictedResultData(data);
        if (restricted !== null) {
            throw publicPayloadInvariant(
                `${toolName} exposed result-only data at ${restricted.path}`,
                restricted,
            );
        }
    }

    if (!hasTerminalAuthority && data.terminal_available === true) {
        const keys = Object.keys(data).sort();
        const allowed = ["investigation_id", "is_result", "terminal_available"];
        if (JSON.stringify(keys) !== JSON.stringify(allowed)
            || typeof data.investigation_id !== "string") {
            throw publicPayloadInvariant(
                `${toolName} exposed terminal state beyond terminal_available`,
                { keys },
            );
        }
    }
    return data;
}

export function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ...data, ok: true }, null, 2),
        resultType: "success",
    };
}

export function toolSuccess(toolName, data) {
    return success(assertPublicToolPayload(toolName, data));
}

export function failure(message, extra = {}) {
    return {
        textResultForLlm: JSON.stringify({
            ...extra,
            ok: false,
            is_result: false,
            error: message,
        }, null, 2),
        resultType: "failure",
    };
}
