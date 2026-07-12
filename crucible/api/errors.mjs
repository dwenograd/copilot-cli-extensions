// crucible/api/errors.mjs
//
// Typed errors for the Crucible thin-extension API layer.
//
// The load-bearing rule for the API layer's error handling: internal modules
// (schema, environment, handlers) THROW these typed errors; only the single SDK
// boundary in api/handlers.mjs catches them and converts them to a structured
// `{ textResultForLlm, resultType }` failure. Every error carries a stable
// machine `code` so the boundary can surface it without leaking a stack trace.

export const API_ERROR_CODES = Object.freeze({
    SCHEMA_INVALID: "CRUCIBLE_API_SCHEMA_INVALID",
    ENV_UNAVAILABLE: "CRUCIBLE_API_ENV_UNAVAILABLE",
    INVESTIGATION_NOT_FOUND: "CRUCIBLE_API_INVESTIGATION_NOT_FOUND",
    CONTRACT_CONFLICT: "CRUCIBLE_API_CONTRACT_CONFLICT",
    HARNESS_NOT_ALLOWLISTED: "CRUCIBLE_API_HARNESS_NOT_ALLOWLISTED",
    VALIDATION_CASE_PATH: "CRUCIBLE_API_VALIDATION_CASE_PATH",
    INVESTIGATION_NOT_OPEN: "CRUCIBLE_API_INVESTIGATION_NOT_OPEN",
    PREFLIGHT_FAILED: "CRUCIBLE_API_PREFLIGHT_FAILED",
    HARNESS_CONFIGURATION_INVALID: "CRUCIBLE_API_HARNESS_CONFIGURATION_INVALID",
    SANDBOX_UNAVAILABLE: "CRUCIBLE_API_SANDBOX_UNAVAILABLE",
    START_FAILED: "CRUCIBLE_API_START_FAILED",
    INVESTIGATION_NOT_RESUMABLE: "CRUCIBLE_API_INVESTIGATION_NOT_RESUMABLE",
    OPERATIONAL_RESET_REQUIRED: "CRUCIBLE_API_OPERATIONAL_RESET_REQUIRED",
    LEGACY_INCOMPATIBLE: "CRUCIBLE_API_LEGACY_INCOMPATIBLE",
    EXPERIMENT_REGISTRY_INVALID: "CRUCIBLE_API_EXPERIMENT_REGISTRY_INVALID",
    EXPERIMENT_NOT_FOUND: "CRUCIBLE_API_EXPERIMENT_NOT_FOUND",
    EXPERIMENT_AUTHORITY_MISMATCH:
        "CRUCIBLE_API_EXPERIMENT_AUTHORITY_MISMATCH",
});

export class CrucibleApiError extends Error {
    constructor(code, message, details = null, options = {}) {
        super(message, options);
        this.name = "CrucibleApiError";
        this.code = code;
        this.details = details;
    }
}

export class SchemaValidationError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.SCHEMA_INVALID, message, details);
        this.name = "SchemaValidationError";
    }
}

export class EnvironmentError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.ENV_UNAVAILABLE, message, details);
        this.name = "EnvironmentError";
    }
}

export class InvestigationNotFoundError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.INVESTIGATION_NOT_FOUND, message, details);
        this.name = "InvestigationNotFoundError";
    }
}

export class ContractConflictError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.CONTRACT_CONFLICT, message, details);
        this.name = "ContractConflictError";
    }
}

export class HarnessNotAllowlistedError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.HARNESS_NOT_ALLOWLISTED, message, details);
        this.name = "HarnessNotAllowlistedError";
    }
}

export class ValidationCasePathError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.VALIDATION_CASE_PATH, message, details);
        this.name = "ValidationCasePathError";
    }
}

export class StartPreflightError extends CrucibleApiError {
    constructor(message, details = null, options = {}) {
        super(API_ERROR_CODES.PREFLIGHT_FAILED, message, details, options);
        this.name = "StartPreflightError";
    }
}

export class HarnessConfigurationError extends CrucibleApiError {
    constructor(message, details = null, options = {}) {
        super(API_ERROR_CODES.HARNESS_CONFIGURATION_INVALID, message, details, options);
        this.name = "HarnessConfigurationError";
    }
}

export class SandboxUnavailableApiError extends CrucibleApiError {
    constructor(message, details = null, options = {}) {
        super(API_ERROR_CODES.SANDBOX_UNAVAILABLE, message, details, options);
        this.name = "SandboxUnavailableApiError";
    }
}

export class StartFailedError extends CrucibleApiError {
    constructor(message, details = null, options = {}) {
        super(API_ERROR_CODES.START_FAILED, message, details, options);
        this.name = "StartFailedError";
    }
}

export class InvestigationNotResumableError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.INVESTIGATION_NOT_RESUMABLE, message, details);
        this.name = "InvestigationNotResumableError";
    }
}

export class OperationalResetRequiredError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.OPERATIONAL_RESET_REQUIRED, message, details);
        this.name = "OperationalResetRequiredError";
    }
}

export class LegacyIncompatibleApiError extends CrucibleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.LEGACY_INCOMPATIBLE, message, {
            compatibility: "legacy_incompatible",
            legacyIncompatible: true,
            restartRequired: true,
            requiredAction: "start_new_investigation",
            ...details,
        });
        this.name = "LegacyIncompatibleApiError";
    }
}

export class ExperimentRegistryApiError extends CrucibleApiError {
    constructor(message, details = null, options = {}) {
        super(API_ERROR_CODES.EXPERIMENT_REGISTRY_INVALID, message, details, options);
        this.name = "ExperimentRegistryApiError";
    }
}

export class ExperimentNotFoundApiError extends CrucibleApiError {
    constructor(message, details = null, options = {}) {
        super(API_ERROR_CODES.EXPERIMENT_NOT_FOUND, message, details, options);
        this.name = "ExperimentNotFoundApiError";
    }
}

export class ExperimentAuthorityMismatchApiError extends CrucibleApiError {
    constructor(message, details = null, options = {}) {
        super(API_ERROR_CODES.EXPERIMENT_AUTHORITY_MISMATCH, message, {
            restartRequired: true,
            requiredAction: "start_new_investigation",
            ...details,
        }, options);
        this.name = "ExperimentAuthorityMismatchApiError";
    }
}
