import {
    finalizeAssuranceValidation,
    getTrustedAuditContext,
    prepareAssuranceValidation,
    recordAssuranceValidation,
} from "../enforcement.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";

const MAX_RECORD_JSON_BYTES = 32 * 1024 * 1024;
const RECORD_FIELDS = new Set([
    "assignmentToken",
    "validatorId",
    "conclusion",
    "reviewedNodeIds",
    "reviewedEdgeIds",
    "reviewedPathIds",
    "reviewedEvidenceIds",
    "reviewedBasisIds",
    "checks",
    "negativeEvidenceCodes",
    "blockerCodes",
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

function parseRecordJson(value) {
    if (typeof value !== "string"
        || Buffer.byteLength(value, "utf8") > MAX_RECORD_JSON_BYTES) {
        throw new TypeError("record_json must be bounded JSON text");
    }
    let parsed;
    try {
        parsed = JSON.parse(value);
    } catch {
        throw new TypeError("record_json must be valid JSON");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new TypeError("record_json must encode an object");
    }
    const unexpected = Object.keys(parsed).filter((key) => !RECORD_FIELDS.has(key));
    if (unexpected.length > 0) {
        throw new TypeError(
            `record_json contains unsupported fields: ${unexpected.join(", ")}`,
        );
    }
    for (const field of RECORD_FIELDS) {
        if (!Object.hasOwn(parsed, field)) {
            throw new TypeError(`record_json.${field} is required`);
        }
    }
    return parsed;
}

export async function prepareAssuranceValidationHandler(args, invocation) {
    args = args || {};
    const active = activeContext(
        args,
        invocation,
        "assurance validation preparation",
    );
    if (active.error) return active.error;
    try {
        const state = prepareAssuranceValidation(active.sessionId, {
            auditId: args.audit_id,
            validatorIds: {
                noFinding: args.no_finding_validator_id,
                confirm: args.confirm_validator_id,
                refute: args.refute_validator_id,
            },
            validatorVersion: args.validator_version,
        });
        return success({
            plan: state.assuranceValidationPlan,
            evaluation: state.assuranceValidationEvaluation,
            stageState: state.stageState,
        });
    } catch (error) {
        return failure(`assurance validation preparation refused: ${error.message}`);
    }
}

export async function recordAssuranceValidationHandler(args, invocation) {
    args = args || {};
    const active = activeContext(
        args,
        invocation,
        "assurance validation recording",
    );
    if (active.error) return active.error;
    try {
        const record = parseRecordJson(args.record_json);
        const result = recordAssuranceValidation(active.sessionId, {
            auditId: args.audit_id,
            assignmentId: args.assignment_id,
            record,
        });
        return success({
            record: result.record,
            evaluation: result.state.assuranceValidationEvaluation,
            stageState: result.state.stageState,
        });
    } catch (error) {
        return failure(`assurance validation recording refused: ${error.message}`);
    }
}

export async function finalizeAssuranceValidationHandler(args, invocation) {
    args = args || {};
    const active = activeContext(
        args,
        invocation,
        "assurance validation finalization",
    );
    if (active.error) return active.error;
    try {
        const result = finalizeAssuranceValidation(active.sessionId, {
            auditId: args.audit_id,
        });
        return success({
            advanced: result.advanced,
            evaluation: result.state.assuranceValidationEvaluation,
            blockers:
                result.state.assuranceValidationEvaluation?.blockerCodes || [],
            stageState: result.state.stageState,
            analysisSnapshot: result.state.analysisSnapshot,
        });
    } catch (error) {
        return failure(`assurance validation finalization refused: ${error.message}`);
    }
}

export const __internals = Object.freeze({
    MAX_RECORD_JSON_BYTES,
    RECORD_FIELDS,
    parseRecordJson,
});
