export const RUNTIME_ERROR_CODES = Object.freeze({
    INVALID_CONFIG: "CRUCIBLE_RUNTIME_INVALID_CONFIG",
    RUNTIME_FAILURE: "CRUCIBLE_RUNTIME_FAILURE",
    INTEGRITY_FAILURE: "CRUCIBLE_RUNTIME_INTEGRITY_FAILURE",
    INVESTIGATION_NOT_OPEN: "CRUCIBLE_RUNTIME_INVESTIGATION_NOT_OPEN",
    DOMAIN_SEQUENCE_MISMATCH: "CRUCIBLE_RUNTIME_DOMAIN_SEQUENCE_MISMATCH",
    DOMAIN_EVENT_INVALID: "CRUCIBLE_RUNTIME_DOMAIN_EVENT_INVALID",
    LEGACY_INCOMPATIBLE: "CRUCIBLE_RUNTIME_LEGACY_INCOMPATIBLE",
    HARNESS_CONFIGURATION_INVALID: "CRUCIBLE_RUNTIME_HARNESS_CONFIGURATION_INVALID",
    WORKER_PROTOCOL: "CRUCIBLE_RUNTIME_WORKER_PROTOCOL",
    WORKER_NO_SUBMISSION: "CRUCIBLE_RUNTIME_WORKER_NO_SUBMISSION",
    WORKER_MULTIPLE_SUBMISSIONS: "CRUCIBLE_RUNTIME_WORKER_MULTIPLE_SUBMISSIONS",
    WORKER_WRONG_NONCE: "CRUCIBLE_RUNTIME_WORKER_WRONG_NONCE",
    WORKER_SESSION_MISMATCH: "CRUCIBLE_RUNTIME_WORKER_SESSION_MISMATCH",
    WORKER_DUPLICATE_CANDIDATE: "CRUCIBLE_RUNTIME_WORKER_DUPLICATE_CANDIDATE",
    WORKER_INVALID_CANDIDATE: "CRUCIBLE_RUNTIME_WORKER_INVALID_CANDIDATE",
    WORKER_STARTUP: "CRUCIBLE_RUNTIME_WORKER_STARTUP",
    NO_ELIGIBLE_CANDIDATE: "CRUCIBLE_RUNTIME_NO_ELIGIBLE_CANDIDATE",
    DEADLINE_EXCEEDED: "CRUCIBLE_RUNTIME_DEADLINE_EXCEEDED",
    PAUSED: "CRUCIBLE_RUNTIME_PAUSED",
    STOPPED: "CRUCIBLE_RUNTIME_STOPPED",
    LOCK_HELD: "CRUCIBLE_RUNTIME_LOCK_HELD",
    LOCK_INVALID: "CRUCIBLE_RUNTIME_LOCK_INVALID",
    CIRCUIT_OPEN: "CRUCIBLE_RUNTIME_CIRCUIT_OPEN",
    CHILD_CRASH: "CRUCIBLE_RUNTIME_CHILD_CRASH",
    NON_QUIESCENT: "CRUCIBLE_RUNTIME_NON_QUIESCENT",
    RESULT_MISSING: "CRUCIBLE_RUNTIME_RESULT_MISSING",
    UNCERTAIN_EXTERNAL_EFFECT: "CRUCIBLE_RUNTIME_UNCERTAIN_EXTERNAL_EFFECT",
    PATH_ESCAPE: "CRUCIBLE_RUNTIME_PATH_ESCAPE",
    SDK_FAILURE: "CRUCIBLE_RUNTIME_SDK_FAILURE",
    SDK_RETRY_EXHAUSTED: "CRUCIBLE_RUNTIME_SDK_RETRY_EXHAUSTED",
    SDK_SUBMISSION_CONFLICT: "CRUCIBLE_RUNTIME_SDK_SUBMISSION_CONFLICT",
    RESOURCE_UNAVAILABLE: "CRUCIBLE_RUNTIME_RESOURCE_UNAVAILABLE",
    STORAGE_BUDGET_EXHAUSTED: "CRUCIBLE_RUNTIME_STORAGE_BUDGET_EXHAUSTED",
    RUNTIME_DRIFT: "RUNTIME_DRIFT",
    INJECTED_CRASH: "CRUCIBLE_RUNTIME_INJECTED_CRASH",
});

export class CrucibleRuntimeError extends Error {
    constructor(code, message, details = undefined, options = undefined) {
        super(message, options);
        this.name = new.target.name;
        this.code = code;
        if (details !== undefined) {
            this.details = details;
        }
    }
}

export class RuntimeConfigError extends CrucibleRuntimeError {
    constructor(message, details) {
        super(RUNTIME_ERROR_CODES.INVALID_CONFIG, message, details);
    }
}

export class RuntimeIntegrityError extends CrucibleRuntimeError {
    constructor(message, details, options) {
        super(RUNTIME_ERROR_CODES.INTEGRITY_FAILURE, message, details, options);
    }
}

export class RuntimeDriftError extends CrucibleRuntimeError {
    constructor(message, details, options) {
        super(RUNTIME_ERROR_CODES.RUNTIME_DRIFT, message, {
            restartRequired: true,
            forkRequired: true,
            inPlaceRepinAllowed: false,
            requiredAction: "start_new_or_forked_investigation",
            ...details,
        }, options);
    }
}

export class LegacyIncompatibleRuntimeError extends CrucibleRuntimeError {
    constructor(message, details) {
        super(RUNTIME_ERROR_CODES.LEGACY_INCOMPATIBLE, message, {
            compatibility: "legacy_incompatible",
            legacyIncompatible: true,
            restartRequired: true,
            requiredAction: "start_new_investigation",
            ...details,
        });
    }
}

export class WorkerProtocolError extends CrucibleRuntimeError {
    constructor(code, message, details) {
        super(code, message, details);
    }
}

export class SdkFailureError extends CrucibleRuntimeError {
    constructor(message, details, options) {
        super(RUNTIME_ERROR_CODES.SDK_FAILURE, message, details, options);
    }
}

export class SdkRetryExhaustedError extends CrucibleRuntimeError {
    constructor(message, details, options) {
        super(RUNTIME_ERROR_CODES.SDK_RETRY_EXHAUSTED, message, details, options);
    }
}

export class SdkSubmissionConflictError extends CrucibleRuntimeError {
    constructor(message, details, options) {
        super(RUNTIME_ERROR_CODES.SDK_SUBMISSION_CONFLICT, message, details, options);
    }
}

export class SupervisorLockError extends CrucibleRuntimeError {
    constructor(code, message, details) {
        super(code, message, details);
    }
}

export class InjectedCrashError extends CrucibleRuntimeError {
    constructor(point, details = undefined) {
        super(
            RUNTIME_ERROR_CODES.INJECTED_CRASH,
            `Injected runtime crash at ${point}`,
            { point, ...details },
        );
        this.recoverable = true;
        this.leaveAttemptActive = true;
    }
}

export function isRecoverableRuntimeError(error) {
    if (error?.recoverable === true) {
        return true;
    }
    return [
        RUNTIME_ERROR_CODES.CHILD_CRASH,
        RUNTIME_ERROR_CODES.RESULT_MISSING,
        RUNTIME_ERROR_CODES.WORKER_NO_SUBMISSION,
        RUNTIME_ERROR_CODES.NO_ELIGIBLE_CANDIDATE,
        RUNTIME_ERROR_CODES.INJECTED_CRASH,
    ].includes(error?.code);
}

export function serializeRuntimeError(error) {
    return {
        name: typeof error?.name === "string" ? error.name : "Error",
        code: typeof error?.code === "string" ? error.code : "UNEXPECTED_ERROR",
        message: typeof error?.message === "string" ? error.message : String(error),
        details: error?.details ?? null,
        recoverable: isRecoverableRuntimeError(error),
    };
}
