import {
    getTrustedAuditContext,
    getEvasiveGraphState,
    prepareEvasiveGraph,
    traceEvasiveGraphState,
} from "../enforcement.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";

function activeContext(args, invocation, operation) {
    const sessionId = invocation?.sessionId || null;
    const context = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!context.ok) return { error: failure(context.error) };
    if (!context.hasActiveAudit || !sessionId) {
        return {
            error: failure(`${operation} refused: an active session-bound audit is required`),
        };
    }
    if (typeof args.audit_id !== "string" || args.audit_id !== context.auditId) {
        return {
            error: failure(`${operation} refused: audit_id must exactly match the active audit`),
        };
    }
    return { sessionId, context };
}

export async function prepareEvasiveGraphHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance graph preparation");
    if (active.error) return active.error;
    try {
        const state = prepareEvasiveGraph(active.sessionId, {
            auditId: args.audit_id,
        });
        return success({
            graph: state.graphPlan,
            blockers: state.graphPlan?.blockerCodes || [],
            conflicts: state.graphPlan?.conflicts || [],
            stageState: state.stageState,
        });
    } catch (error) {
        return failure(`assurance graph preparation refused: ${error.message}`);
    }
}

export async function traceEvasiveGraphHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance graph trace");
    if (active.error) return active.error;
    try {
        const result = traceEvasiveGraphState(active.sessionId, {
            auditId: args.audit_id,
        });
        return success({
            advanced: result.advanced,
            trace: result.trace,
            blockers: result.trace?.blockerCodes || [],
            stageState: result.state.stageState,
            analysisSnapshot: result.state.analysisSnapshot,
        });
    } catch (error) {
        return failure(`assurance graph trace refused: ${error.message}`);
    }
}

export async function getEvasiveGraphHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance graph read");
    if (active.error) return active.error;
    try {
        return success(getEvasiveGraphState(active.sessionId, {
            auditId: args.audit_id,
        }) || {});
    } catch (error) {
        return failure(`assurance graph read refused: ${error.message}`);
    }
}
