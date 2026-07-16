import {
    getTrustedAuditContext,
    getSemanticCoverageState,
    issueSemanticReviewAssignment,
    prepareSemanticCoverage,
    recordSemanticReview,
    recordSemanticScannerCoverage,
} from "../enforcement.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";

const MAX_CONTRACT_JSON_BYTES = 8 * 1024 * 1024;

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

function parseContractJson(value, name, { array = false, nullable = false } = {}) {
    if (nullable && (value === undefined || value === null)) return null;
    if (typeof value !== "string" || value.length > MAX_CONTRACT_JSON_BYTES) {
        throw new TypeError(`${name} must be bounded JSON text`);
    }
    let parsed;
    try {
        parsed = JSON.parse(value);
    } catch {
        throw new TypeError(`${name} must be valid JSON`);
    }
    if (array !== Array.isArray(parsed)) {
        throw new TypeError(`${name} must encode ${array ? "an array": "an object"}`);
    }
    if (!array && (parsed === null || typeof parsed !== "object")) {
        throw new TypeError(`${name} must encode an object`);
    }
    return parsed;
}

export async function prepareSemanticCoverageHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance semantic coverage preparation");
    if (active.error) return active.error;
    try {
        const normalizedViews = parseContractJson(
            args.normalized_views_json,
            "normalized_views_json",
            { array: true },
        );
        const state = prepareSemanticCoverage(active.sessionId, {
            auditId: args.audit_id,
            normalizedViews,
            scannerShardCount: args.scanner_shard_count ?? 16,
            modelShardCount: args.model_shard_count ?? 16,
        });
        return success({
            plan: state.semanticCoveragePlan,
            evaluation: state.semanticCoverageEvaluation,
            stageState: state.stageState,
        });
    } catch (error) {
        return failure(`assurance semantic coverage preparation refused: ${error.message}`);
    }
}

export async function recordSemanticScannerHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance semantic scanner recording");
    if (active.error) return active.error;
    try {
        const scannerResult = parseContractJson(
            args.scanner_result_json,
            "scanner_result_json",
        );
        const result = recordSemanticScannerCoverage(active.sessionId, {
            auditId: args.audit_id,
            assignmentId: args.assignment_id,
            assignmentToken: args.assignment_token,
            scannerResult,
        });
        return success({
            scannerRecord: result.record,
            evaluation: result.state.semanticCoverageEvaluation,
            stageState: result.state.stageState,
        });
    } catch (error) {
        return failure(`assurance semantic scanner recording refused: ${error.message}`);
    }
}

export async function assignSemanticReviewHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance semantic review assignment");
    if (active.error) return active.error;
    try {
        const assignment = issueSemanticReviewAssignment(active.sessionId, {
            auditId: args.audit_id,
            objectId: args.object_id,
            reviewerSlot: args.reviewer_slot,
            reviewerId: args.reviewer_id,
            reviewerVersion: args.reviewer_version,
        });
        return success({ assignment });
    } catch (error) {
        return failure(`assurance semantic review assignment refused: ${error.message}`);
    }
}

export async function recordSemanticReviewHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance semantic review recording");
    if (active.error) return active.error;
    try {
        const promptReviewRecord = parseContractJson(
            args.prompt_review_json,
            "prompt_review_json",
            { nullable: true },
        );
        const result = recordSemanticReview(active.sessionId, {
            auditId: args.audit_id,
            assignmentId: args.assignment_id,
            assignmentToken: args.assignment_token,
            reviewerId: args.reviewer_id,
            objectId: args.object_id,
            artifactIds: args.artifact_ids,
            semanticViewId: args.semantic_view_id,
            semanticViewSha256: args.semantic_view_sha256,
            reviewedFactIds: args.reviewed_fact_ids,
            reviewedArtifactIds: args.reviewed_artifact_ids,
            decision: args.decision,
            checks: args.checks,
            negativeEvidenceCodes: args.negative_evidence_codes,
            candidates: args.candidates,
            blockerCodes: args.blocker_codes,
            promptReviewRecord,
        });
        return success({
            reviewRecord: result.record,
            evaluation: result.state.semanticCoverageEvaluation,
            stageState: result.state.stageState,
            analysisSnapshot: result.state.analysisSnapshot,
        });
    } catch (error) {
        return failure(`assurance semantic review recording refused: ${error.message}`);
    }
}

export async function getSemanticCoverageHandler(args, invocation) {
    args = args || {};
    const active = activeContext(args, invocation, "assurance semantic coverage read");
    if (active.error) return active.error;
    try {
        const state = getSemanticCoverageState(active.sessionId, {
            auditId: args.audit_id,
        });
        return success(state || {});
    } catch (error) {
        return failure(`assurance semantic coverage read refused: ${error.message}`);
    }
}

export const __internals = Object.freeze({
    MAX_CONTRACT_JSON_BYTES,
    parseContractJson,
});
