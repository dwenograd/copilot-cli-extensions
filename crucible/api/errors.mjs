// oracle-v3/api/errors.mjs
//
// Typed errors for the Oracle v3 thin-extension API layer.
//
// The load-bearing rule for the API layer's error handling: internal modules
// (schema, environment, handlers) THROW these typed errors; only the single SDK
// boundary in api/handlers.mjs catches them and converts them to a structured
// `{ textResultForLlm, resultType }` failure. Every error carries a stable
// machine `code` so the boundary can surface it without leaking a stack trace.

export const API_ERROR_CODES = Object.freeze({
    SCHEMA_INVALID: "ORACLE_V3_API_SCHEMA_INVALID",
    ENV_UNAVAILABLE: "ORACLE_V3_API_ENV_UNAVAILABLE",
    INVESTIGATION_NOT_FOUND: "ORACLE_V3_API_INVESTIGATION_NOT_FOUND",
    CONTRACT_CONFLICT: "ORACLE_V3_API_CONTRACT_CONFLICT",
    HARNESS_NOT_ALLOWLISTED: "ORACLE_V3_API_HARNESS_NOT_ALLOWLISTED",
    VALIDATION_CASE_PATH: "ORACLE_V3_API_VALIDATION_CASE_PATH",
    INVESTIGATION_NOT_OPEN: "ORACLE_V3_API_INVESTIGATION_NOT_OPEN",
    START_FAILED: "ORACLE_V3_API_START_FAILED",
    INVESTIGATION_NOT_RESUMABLE: "ORACLE_V3_API_INVESTIGATION_NOT_RESUMABLE",
    OPERATIONAL_RESET_REQUIRED: "ORACLE_V3_API_OPERATIONAL_RESET_REQUIRED",
});

export class OracleApiError extends Error {
    constructor(code, message, details = null, options = {}) {
        super(message, options);
        this.name = "OracleApiError";
        this.code = code;
        this.details = details;
    }
}

export class SchemaValidationError extends OracleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.SCHEMA_INVALID, message, details);
        this.name = "SchemaValidationError";
    }
}

export class EnvironmentError extends OracleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.ENV_UNAVAILABLE, message, details);
        this.name = "EnvironmentError";
    }
}

export class InvestigationNotFoundError extends OracleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.INVESTIGATION_NOT_FOUND, message, details);
        this.name = "InvestigationNotFoundError";
    }
}

export class ContractConflictError extends OracleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.CONTRACT_CONFLICT, message, details);
        this.name = "ContractConflictError";
    }
}

export class HarnessNotAllowlistedError extends OracleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.HARNESS_NOT_ALLOWLISTED, message, details);
        this.name = "HarnessNotAllowlistedError";
    }
}

export class ValidationCasePathError extends OracleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.VALIDATION_CASE_PATH, message, details);
        this.name = "ValidationCasePathError";
    }
}

export class InvestigationNotResumableError extends OracleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.INVESTIGATION_NOT_RESUMABLE, message, details);
        this.name = "InvestigationNotResumableError";
    }
}

export class OperationalResetRequiredError extends OracleApiError {
    constructor(message, details = null) {
        super(API_ERROR_CODES.OPERATIONAL_RESET_REQUIRED, message, details);
        this.name = "OperationalResetRequiredError";
    }
}
