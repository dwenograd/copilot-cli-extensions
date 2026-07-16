import {
    finalizeRedTeam,
    getTrustedAuditContext,
    getRedTeamState,
    issueRedTeamAssignment,
    prepareRedTeam,
    recordRedTeamReview,
} from "../enforcement.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";

const MAX_REVIEW_JSON_BYTES = 8 * 1024 * 1024;
const REVIEW_FIELDS = new Set([
    "contractKind",
    "assignmentId",
    "assignmentToken",
    "reviewerId",
    "decision",
    "reviewedObjectIds",
    "reviewedArtifactIds",
    "reviewedFactIds",
    "reviewedEvidenceIds",
    "reviewedGraphNodeIds",
    "reviewedGraphEdgeIds",
    "falsificationChecks",
    "negativeEvidenceCodes",
    "candidates",
    "blockerCodes",
    "canaryMarker",
    "outputContractMarker",
]);

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

function parseReviewJson(value) {
    if (typeof value !== "string"
        || Buffer.byteLength(value, "utf8") > MAX_REVIEW_JSON_BYTES) {
        throw new TypeError("review_json must be bounded JSON text");
    }
    let parsed;
    try {
        parsed = JSON.parse(value);
    } catch {
        throw new TypeError("review_json must be valid JSON");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new TypeError("review_json must encode an object");
    }
    const unexpected = Object.keys(parsed).filter((key) => !REVIEW_FIELDS.has(key));
    if (unexpected.length > 0) {
        throw new TypeError(
            `review_json contains unsupported fields: ${unexpected.join(", ")}`,
        );
    }
    for (const field of REVIEW_FIELDS) {
        if (!Object.hasOwn(parsed, field)) {
            throw new TypeError(`review_json.${field} is required`);
        }
    }
    return parsed;
}

export async function prepareRedTeamHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance red-team preparation");
    if (active.error) return active.error;
    try {
        const state = prepareRedTeam(active.sessionId, {
            auditId: args.audit_id,
        });
        return success({
            plan: state.redTeamPlan,
            evaluation: state.redTeamEvaluation,
            candidateLedger: state.redTeamEvaluation?.candidateLedger || [],
            stageState: state.stageState,
            analysisSnapshot: state.analysisSnapshot,
        });
    } catch (error) {
        return failure(`assurance red-team preparation refused: ${error.message}`);
    }
}

export async function assignRedTeamHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance red-team assignment");
    if (active.error) return active.error;
    try {
        const assignment = issueRedTeamAssignment(active.sessionId, {
            auditId: args.audit_id,
            categoryId: args.category_id,
            reviewerId: args.reviewer_id,
            reviewerVersion: args.reviewer_version,
            modelId: args.model_id,
        });
        return success({ assignment });
    } catch (error) {
        return failure(`assurance red-team assignment refused: ${error.message}`);
    }
}

export async function recordRedTeamReviewHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance red-team review recording");
    if (active.error) return active.error;
    try {
        const review = parseReviewJson(args.review_json);
        if (review.assignmentId !== args.assignment_id) {
            throw new TypeError(
                "review_json.assignmentId must match assignment_id",
            );
        }
        const result = recordRedTeamReview(active.sessionId, {
            auditId: args.audit_id,
            assignmentId: args.assignment_id,
            review,
        });
        return success({
            reviewRecord: result.record,
            evaluation: result.state.redTeamEvaluation,
            candidateLedger:
                result.state.redTeamEvaluation?.candidateLedger || [],
            stageState: result.state.stageState,
        });
    } catch (error) {
        return failure(`assurance red-team review recording refused: ${error.message}`);
    }
}

export async function getRedTeamHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance red-team read");
    if (active.error) return active.error;
    try {
        return success(getRedTeamState(active.sessionId, {
            auditId: args.audit_id,
        }) || {});
    } catch (error) {
        return failure(`assurance red-team read refused: ${error.message}`);
    }
}

export async function finalizeRedTeamHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance red-team finalization");
    if (active.error) return active.error;
    try {
        const result = finalizeRedTeam(active.sessionId, {
            auditId: args.audit_id,
        });
        return success({
            advanced: result.advanced,
            evaluation: result.state.redTeamEvaluation,
            candidateLedger:
                result.state.redTeamEvaluation?.candidateLedger || [],
            stageState: result.state.stageState,
            analysisSnapshot: result.state.analysisSnapshot,
            blockers: result.state.redTeamEvaluation?.blockerCodes || [],
        });
    } catch (error) {
        return failure(`assurance red-team finalization refused: ${error.message}`);
    }
}

export const __internals = Object.freeze({
    MAX_REVIEW_JSON_BYTES,
    REVIEW_FIELDS,
    parseReviewJson,
});
