import {
    adjudicateAnalysisValidation,
    finalizeAnalysisValidation,
    getActiveAudit,
    prepareAnalysisValidation,
    submitAnalysisValidationDecision,
} from "../enforcement.mjs";

export const VALIDATION_WRAPPER_LIMITS = Object.freeze({
    serializedBytes: 64 * 1024,
});

const PREPARE_FIELDS = Object.freeze([
    "action",
    "schemaVersion",
    "audit_id",
    "cursor",
    "limit",
]);
const FINALIZE_FIELDS = Object.freeze([
    "action",
    "schemaVersion",
    "audit_id",
]);

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function exactFields(value, allowed, label) {
    if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain object`);
    const fields = new Set(allowed);
    for (const key of Object.keys(value)) {
        if (!fields.has(key)) throw new TypeError(`${label}.${key} is not allowed`);
    }
    for (const key of ["action", "schemaVersion", "audit_id"]) {
        if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
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

export async function recordValidationHandler(args, invocation) {
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) {
        return failure("record_validation requires a real sessionId and active audit");
    }
    if (!isPlainObject(args)) {
        return failure("record_validation arguments must be a plain object");
    }
    let serializedBytes;
    try {
        serializedBytes = Buffer.byteLength(JSON.stringify(args), "utf8");
    } catch {
        return failure("validation input must be JSON-serializable");
    }
    if (serializedBytes > VALIDATION_WRAPPER_LIMITS.serializedBytes) {
        return failure(
            `validation input exceeds ${VALIDATION_WRAPPER_LIMITS.serializedBytes} serialized bytes`,
        );
    }
    const audit = getActiveAudit(sessionId);
    if (!audit) return failure("record_validation requires an active audit");
    if (args.schemaVersion !== 5) return failure("schemaVersion must equal 5");
    if (args.audit_id !== audit.auditId) {
        return failure(
            "record_validation audit_id does not match the current active audit",
            { audit_id: audit.auditId },
        );
    }

    try {
        if (args.action === "prepare") {
            exactFields(args, PREPARE_FIELDS, "validation preparation");
            return success({
                action: "prepare",
                audit_id: audit.auditId,
                ...prepareAnalysisValidation(sessionId, {
                    auditId: args.audit_id,
                    cursor: args.cursor ?? 0,
                    limit: args.limit ?? 8,
                }),
            });
        }
        if (args.action === "submit") {
            return success({
                action: "submit",
                audit_id: audit.auditId,
                ...submitAnalysisValidationDecision(sessionId, args),
            });
        }
        if (args.action === "adjudicate") {
            return success({
                action: "adjudicate",
                audit_id: audit.auditId,
                ...adjudicateAnalysisValidation(sessionId, args),
            });
        }
        if (args.action === "finalize") {
            exactFields(args, FINALIZE_FIELDS, "validation finalization");
            return success({
                action: "finalize",
                audit_id: audit.auditId,
                ...finalizeAnalysisValidation(sessionId, {
                    auditId: args.audit_id,
                }),
            });
        }
        return failure("action must be prepare, submit, adjudicate, or finalize");
    } catch (error) {
        return failure(`record_validation refused: ${error.message}`, {
            audit_id: audit.auditId,
        });
    }
}

export const __internals = Object.freeze({
    PREPARE_FIELDS,
    FINALIZE_FIELDS,
    exactFields,
});
