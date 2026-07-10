// crucible/persistence/errors.mjs
//
// Typed errors for the Crucible event repository. Every failure path in the
// repository throws one of these with a stable machine-readable `code` drawn
// from ERROR_CODES. There is intentionally NO broad catch-and-success
// fallback anywhere in the persistence layer: an operation either completes
// and returns, or it throws a typed error. Callers branch on `.code`.

export const ERROR_CODES = Object.freeze({
    // Construction / configuration.
    INVALID_ARGUMENT: "CRUCIBLE_PERSIST_INVALID_ARGUMENT",
    LOCAL_PATH_REQUIRED: "CRUCIBLE_PERSIST_LOCAL_PATH_REQUIRED",
    SCHEMA_VERSION_MISMATCH: "CRUCIBLE_PERSIST_SCHEMA_VERSION_MISMATCH",

    // Lookups.
    NOT_FOUND: "CRUCIBLE_PERSIST_NOT_FOUND",
    INVESTIGATION_NOT_FOUND: "CRUCIBLE_PERSIST_INVESTIGATION_NOT_FOUND",
    LEASE_NOT_FOUND: "CRUCIBLE_PERSIST_LEASE_NOT_FOUND",
    ARTIFACT_NOT_FOUND: "CRUCIBLE_PERSIST_ARTIFACT_NOT_FOUND",

    // Event log / CAS.
    CAS_CONFLICT: "CRUCIBLE_PERSIST_CAS_CONFLICT",
    SEQUENCE_CONFLICT: "CRUCIBLE_PERSIST_SEQUENCE_CONFLICT",
    PREV_HASH_MISMATCH: "CRUCIBLE_PERSIST_PREV_HASH_MISMATCH",
    EVENT_HASH_MISMATCH: "CRUCIBLE_PERSIST_EVENT_HASH_MISMATCH",
    TERMINAL_EXISTS: "CRUCIBLE_PERSIST_TERMINAL_EXISTS",
    EVIDENCE_CONFLICT: "CRUCIBLE_PERSIST_EVIDENCE_CONFLICT",

    // Command lifecycle / fencing.
    ILLEGAL_TRANSITION: "CRUCIBLE_PERSIST_ILLEGAL_TRANSITION",
    FENCE_REJECTED: "CRUCIBLE_PERSIST_FENCE_REJECTED",
    ATTEMPT_IDENTITY_MISMATCH: "CRUCIBLE_PERSIST_ATTEMPT_IDENTITY_MISMATCH",
    RESERVATION_CONFLICT: "CRUCIBLE_PERSIST_RESERVATION_CONFLICT",

    // Artifacts.
    ARTIFACT_NOT_DURABLE: "CRUCIBLE_PERSIST_ARTIFACT_NOT_DURABLE",
    ARTIFACT_CONFLICT: "CRUCIBLE_PERSIST_ARTIFACT_CONFLICT",

    // Integrity.
    INTEGRITY_VIOLATION: "CRUCIBLE_PERSIST_INTEGRITY_VIOLATION",

    // Wrapped storage/engine error we did not expect.
    STORAGE_ERROR: "CRUCIBLE_PERSIST_STORAGE_ERROR",
});

export class CruciblePersistenceError extends Error {
    constructor(code, message, details = undefined) {
        super(message);
        this.name = "CruciblePersistenceError";
        this.code = code;
        if (details !== undefined) {
            this.details = details;
        }
    }
}

// Path is not a safe local-file path (UNC / mapped-network / cloud-sync root).
export class LocalPathError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.LOCAL_PATH_REQUIRED, message, details);
        this.name = "LocalPathError";
    }
}

export class SchemaVersionError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.SCHEMA_VERSION_MISMATCH, message, details);
        this.name = "SchemaVersionError";
    }
}

export class InvalidArgumentError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.INVALID_ARGUMENT, message, details);
        this.name = "InvalidArgumentError";
    }
}

export class NotFoundError extends CruciblePersistenceError {
    constructor(code, message, details) {
        super(code, message, details);
        this.name = "NotFoundError";
    }
}

export class CasConflictError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.CAS_CONFLICT, message, details);
        this.name = "CasConflictError";
    }
}

export class TerminalExistsError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.TERMINAL_EXISTS, message, details);
        this.name = "TerminalExistsError";
    }
}

export class IllegalTransitionError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.ILLEGAL_TRANSITION, message, details);
        this.name = "IllegalTransitionError";
    }
}

export class FenceRejectedError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.FENCE_REJECTED, message, details);
        this.name = "FenceRejectedError";
    }
}

export class AttemptIdentityError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.ATTEMPT_IDENTITY_MISMATCH, message, details);
        this.name = "AttemptIdentityError";
    }
}

export class ArtifactNotDurableError extends CruciblePersistenceError {
    constructor(message, details) {
        super(ERROR_CODES.ARTIFACT_NOT_DURABLE, message, details);
        this.name = "ArtifactNotDurableError";
    }
}

// Wrap an unexpected node:sqlite engine error without swallowing it. We keep
// the original error and its extended result code (`errcode`) for diagnosis
// rather than collapsing the failure into a success.
export class StorageError extends CruciblePersistenceError {
    constructor(message, cause) {
        super(ERROR_CODES.STORAGE_ERROR, message, {
            sqliteCode: cause?.code,
            sqliteErrcode: cause?.errcode,
        });
        this.name = "StorageError";
        this.cause = cause;
    }
}

// SQLite extended result codes we branch on. These are stable numeric codes
// exposed by node:sqlite as `error.errcode`.
export const SQLITE_ERRCODE = Object.freeze({
    CONSTRAINT_PRIMARYKEY: 1555,
    CONSTRAINT_UNIQUE: 2067,
    CONSTRAINT_FOREIGNKEY: 787,
    CONSTRAINT_CHECK: 275,
    READONLY: 8,
    BUSY: 5,
});
