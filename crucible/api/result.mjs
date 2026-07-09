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

export const TERMINAL_BANNER = "===== ORACLE V3 TERMINAL RESULT =====";
export const NON_RESULT_BANNER = "NOT A RESULT — DO NOT REPORT AS COMPLETE";

export function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, ...data }, null, 2),
        resultType: "success",
    };
}

export function failure(message, extra = {}) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, is_result: false, error: message, ...extra }, null, 2),
        resultType: "failure",
    };
}
