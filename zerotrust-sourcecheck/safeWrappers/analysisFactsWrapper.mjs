import {
    getAnalysisIndexSnapshot,
    getAnalysisStageState,
    getTrustedAuditContext,
    listAnalysisFacts,
} from "../enforcement.mjs";
import { FACT_KINDS } from "../analysis/extractFacts.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";

const READABLE_STAGES = new Set([
    "prepared",
    "scanned",
    "traced",
    "validated",
    "remediated",
    "finalized",
]);

export async function safeListAnalysisFactsHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) return failure(ctx.error);
    if (!ctx.hasActiveAudit || !sessionId) {
        return failure(
            "safe_list_analysis_facts refused: an active session-bound audit is required",
        );
    }
    if (typeof args.audit_id !== "string" || args.audit_id !== ctx.auditId) {
        return failure(
            "safe_list_analysis_facts refused: audit_id must exactly match the active audit",
        );
    }
    if (ctx.analysisIndex?.sourceKind === "metadata-only") {
        return failure("safe_list_analysis_facts refused: metadata-only audits have no source index");
    }
    const stage = getAnalysisStageState(sessionId, { auditId: ctx.auditId });
    if (!READABLE_STAGES.has(stage?.current)) {
        return failure(
            `safe_list_analysis_facts refused: source preparation is not complete (current stage: ${stage?.current || "missing"})`,
            {
                analysisIndex: getAnalysisIndexSnapshot(sessionId, {
                    auditId: ctx.auditId,
                }),
            },
        );
    }
    if (args.path !== undefined && args.path !== null && typeof args.path !== "string") {
        return failure("path must be a string when provided");
    }
    if (args.kind !== undefined && args.kind !== null
        && !FACT_KINDS.includes(args.kind)) {
        return failure(`kind must be one of: ${FACT_KINDS.join(" | ")}`);
    }
    const cursor = args.cursor === undefined ? 0 : Number(args.cursor);
    const limit = args.limit === undefined ? 256 : Number(args.limit);
    if (!Number.isSafeInteger(cursor) || cursor < 0) {
        return failure("cursor must be a non-negative integer");
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 256) {
        return failure("limit must be between 1 and 256");
    }

    try {
        const page = listAnalysisFacts(sessionId, {
            auditId: ctx.auditId,
            path: args.path ?? null,
            kind: args.kind ?? null,
            cursor,
            limit,
        });
        return success({
            ...page,
            analysisIndex: getAnalysisIndexSnapshot(sessionId, {
                auditId: ctx.auditId,
            }),
            analysisStageState: stage,
        });
    } catch (err) {
        return failure(`safe_list_analysis_facts refused: ${err.message}`);
    }
}

function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, ...data }, null, 2),
        resultType: "success",
    };
}

function failure(message, data = {}) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, error: message, ...data }, null, 2),
        resultType: "failure",
    };
}

export const __internals = Object.freeze({
    READABLE_STAGES,
});
