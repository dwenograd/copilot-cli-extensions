import {
    getActiveAudit,
    traceAnalysisGraph,
} from "../enforcement.mjs";
import { failure, success } from "./result.mjs";

export async function traceBehaviorGraphHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) {
        return failure("trace_behavior_graph requires a real sessionId and active audit");
    }
    if (!args || typeof args !== "object" || Array.isArray(args)) {
        return failure("trace_behavior_graph arguments must be an object");
    }
    const fields = Object.keys(args);
    if (fields.some((field) => field !== "audit_id")) {
        return failure("trace_behavior_graph accepts only audit_id");
    }
    const audit = getActiveAudit(sessionId);
    if (!audit) return failure("trace_behavior_graph requires an active audit");
    if (typeof args.audit_id !== "string" || args.audit_id !== audit.auditId) {
        return failure(
            "trace_behavior_graph audit_id does not match the current active audit",
            { audit_id: audit.auditId },
        );
    }
    try {
        const trace = traceAnalysisGraph(sessionId, { auditId: args.audit_id });
        return success({
            action: "trace",
            audit_id: audit.auditId,
            traced: trace.analysisStageAfter === "traced",
            ...trace,
        });
    } catch (error) {
        return failure(`trace_behavior_graph refused: ${error.message}`, {
            audit_id: audit.auditId,
        });
    }
}
