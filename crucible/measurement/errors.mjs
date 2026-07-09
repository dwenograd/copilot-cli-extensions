// oracle-v3/measurement/errors.mjs
//
// Typed errors for the trusted-measurement boundary. Every failure path in
// this subsystem throws one of these with a stable machine-readable `code`
// drawn from MEASUREMENT_ERROR_CODES. There is intentionally NO broad
// catch-and-fallback that hides a failure — each error either propagates
// unchanged or is re-thrown as one of these typed errors.

export const MEASUREMENT_ERROR_CODES = Object.freeze({
    // Construction / configuration.
    INVALID_ARGUMENT: "ORACLE_MEASURE_INVALID_ARGUMENT",

    // Allowlist load / validation.
    ALLOWLIST_LOAD: "ORACLE_MEASURE_ALLOWLIST_LOAD",
    ALLOWLIST_INVALID: "ORACLE_MEASURE_ALLOWLIST_INVALID",
    ALLOWLIST_ENTRY_NOT_FOUND: "ORACLE_MEASURE_ALLOWLIST_ENTRY_NOT_FOUND",

    // File-system verification.
    FILE_NOT_LOCAL: "ORACLE_MEASURE_FILE_NOT_LOCAL",
    FILE_NOT_REGULAR: "ORACLE_MEASURE_FILE_NOT_REGULAR",
    FILE_SYMLINK: "ORACLE_MEASURE_FILE_SYMLINK",
    FILE_REPARSE_POINT: "ORACLE_MEASURE_FILE_REPARSE_POINT",
    FILE_NOT_FOUND: "ORACLE_MEASURE_FILE_NOT_FOUND",
    FILE_HASH_MISMATCH: "ORACLE_MEASURE_FILE_HASH_MISMATCH",
    FILE_IDENTITY_UNAVAILABLE: "ORACLE_MEASURE_FILE_IDENTITY_UNAVAILABLE",
    FILE_CHANGED_DURING_VERIFICATION: "ORACLE_MEASURE_FILE_CHANGED_DURING_VERIFICATION",

    // Verification-to-execution binding.
    UNDECLARED_ARGV_FILE: "ORACLE_MEASURE_UNDECLARED_ARGV_FILE",
    STAGING_REFUSED: "ORACLE_MEASURE_STAGING_REFUSED",

    // Sandbox boundary.
    SANDBOX_REQUIRED: "ORACLE_MEASURE_SANDBOX_REQUIRED",
    SANDBOX_REFUSED: "ORACLE_MEASURE_SANDBOX_REFUSED",
    SANDBOX_MALFORMED: "ORACLE_MEASURE_SANDBOX_MALFORMED",

    // Runtime.
    SPAWN_FAILED: "ORACLE_MEASURE_SPAWN_FAILED",
    STDIN_UNAVAILABLE: "ORACLE_MEASURE_STDIN_UNAVAILABLE",
    OUTPUT_OVERFLOW: "ORACLE_MEASURE_OUTPUT_OVERFLOW",
    TIMEOUT: "ORACLE_MEASURE_TIMEOUT",
    NONZERO_EXIT: "ORACLE_MEASURE_NONZERO_EXIT",

    // Result parsing.
    PARSE_EMPTY: "ORACLE_MEASURE_PARSE_EMPTY",
    PARSE_MALFORMED: "ORACLE_MEASURE_PARSE_MALFORMED",
    PARSE_TRAILING: "ORACLE_MEASURE_PARSE_TRAILING",
    PARSE_SCHEMA: "ORACLE_MEASURE_PARSE_SCHEMA",
    PARSE_OVERSIZED: "ORACLE_MEASURE_PARSE_OVERSIZED",
});

export class MeasurementError extends Error {
    constructor(code, message, details = null) {
        super(message);
        this.name = "MeasurementError";
        this.code = code;
        if (details !== null && details !== undefined) {
            this.details = details;
        }
    }
}

// A hard, standalone error type for the fail-closed sandbox gate. It is a
// subclass of MeasurementError but carries its own name so operator-facing
// tooling and tests can branch on `instanceof SandboxRequiredError` without
// re-checking a string code (though the code is also stable).
export class SandboxRequiredError extends MeasurementError {
    constructor(message, details = null) {
        super(MEASUREMENT_ERROR_CODES.SANDBOX_REQUIRED, message, details);
        this.name = "SandboxRequiredError";
    }
}

export class SandboxRefusedError extends MeasurementError {
    constructor(message, details = null) {
        super(MEASUREMENT_ERROR_CODES.SANDBOX_REFUSED, message, details);
        this.name = "SandboxRefusedError";
    }
}

export class AllowlistInvalidError extends MeasurementError {
    constructor(message, details = null) {
        super(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID, message, details);
        this.name = "AllowlistInvalidError";
    }
}

export class FileVerificationError extends MeasurementError {
    constructor(code, message, details = null) {
        super(code, message, details);
        this.name = "FileVerificationError";
    }
}

export class StagingRefusedError extends MeasurementError {
    constructor(message, details = null) {
        super(MEASUREMENT_ERROR_CODES.STAGING_REFUSED, message, details);
        this.name = "StagingRefusedError";
    }
}

export class ResultParseError extends MeasurementError {
    constructor(code, message, details = null) {
        super(code, message, details);
        this.name = "ResultParseError";
    }
}
