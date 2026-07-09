// crucible/measurement/errors.mjs
//
// Typed errors for the trusted-measurement boundary. Every failure path in
// this subsystem throws one of these with a stable machine-readable `code`
// drawn from MEASUREMENT_ERROR_CODES. There is intentionally NO broad
// catch-and-fallback that hides a failure — each error either propagates
// unchanged or is re-thrown as one of these typed errors.

export const MEASUREMENT_ERROR_CODES = Object.freeze({
    // Construction / configuration.
    INVALID_ARGUMENT: "CRUCIBLE_MEASURE_INVALID_ARGUMENT",

    // Allowlist load / validation.
    ALLOWLIST_LOAD: "CRUCIBLE_MEASURE_ALLOWLIST_LOAD",
    ALLOWLIST_INVALID: "CRUCIBLE_MEASURE_ALLOWLIST_INVALID",
    ALLOWLIST_ENTRY_NOT_FOUND: "CRUCIBLE_MEASURE_ALLOWLIST_ENTRY_NOT_FOUND",

    // File-system verification.
    FILE_NOT_LOCAL: "CRUCIBLE_MEASURE_FILE_NOT_LOCAL",
    FILE_NOT_REGULAR: "CRUCIBLE_MEASURE_FILE_NOT_REGULAR",
    FILE_SYMLINK: "CRUCIBLE_MEASURE_FILE_SYMLINK",
    FILE_REPARSE_POINT: "CRUCIBLE_MEASURE_FILE_REPARSE_POINT",
    FILE_NOT_FOUND: "CRUCIBLE_MEASURE_FILE_NOT_FOUND",
    FILE_HASH_MISMATCH: "CRUCIBLE_MEASURE_FILE_HASH_MISMATCH",
    FILE_IDENTITY_UNAVAILABLE: "CRUCIBLE_MEASURE_FILE_IDENTITY_UNAVAILABLE",
    FILE_CHANGED_DURING_VERIFICATION: "CRUCIBLE_MEASURE_FILE_CHANGED_DURING_VERIFICATION",

    // Verification-to-execution binding.
    UNDECLARED_ARGV_FILE: "CRUCIBLE_MEASURE_UNDECLARED_ARGV_FILE",
    STAGING_REFUSED: "CRUCIBLE_MEASURE_STAGING_REFUSED",

    // Sandbox boundary.
    SANDBOX_REQUIRED: "CRUCIBLE_MEASURE_SANDBOX_REQUIRED",
    SANDBOX_REFUSED: "CRUCIBLE_MEASURE_SANDBOX_REFUSED",
    SANDBOX_MALFORMED: "CRUCIBLE_MEASURE_SANDBOX_MALFORMED",

    // Runtime.
    SPAWN_FAILED: "CRUCIBLE_MEASURE_SPAWN_FAILED",
    STDIN_UNAVAILABLE: "CRUCIBLE_MEASURE_STDIN_UNAVAILABLE",
    OUTPUT_OVERFLOW: "CRUCIBLE_MEASURE_OUTPUT_OVERFLOW",
    TIMEOUT: "CRUCIBLE_MEASURE_TIMEOUT",
    NONZERO_EXIT: "CRUCIBLE_MEASURE_NONZERO_EXIT",

    // Result parsing.
    PARSE_EMPTY: "CRUCIBLE_MEASURE_PARSE_EMPTY",
    PARSE_MALFORMED: "CRUCIBLE_MEASURE_PARSE_MALFORMED",
    PARSE_TRAILING: "CRUCIBLE_MEASURE_PARSE_TRAILING",
    PARSE_SCHEMA: "CRUCIBLE_MEASURE_PARSE_SCHEMA",
    PARSE_OVERSIZED: "CRUCIBLE_MEASURE_PARSE_OVERSIZED",
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
