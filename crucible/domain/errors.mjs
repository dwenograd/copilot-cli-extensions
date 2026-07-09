export const ERROR_CODES = Object.freeze({
    INVALID_CANONICAL_VALUE: "INVALID_CANONICAL_VALUE",
    INVALID_CONTRACT: "INVALID_CONTRACT",
    INVALID_ACCEPTANCE_PREDICATE: "INVALID_ACCEPTANCE_PREDICATE",
    INVALID_EVENT: "INVALID_EVENT",
    EVENT_SEQUENCE_MISMATCH: "EVENT_SEQUENCE_MISMATCH",
    EVENT_PREV_HASH_MISMATCH: "EVENT_PREV_HASH_MISMATCH",
    EVENT_HASH_MISMATCH: "EVENT_HASH_MISMATCH",
    UNKNOWN_EVENT_TYPE: "UNKNOWN_EVENT_TYPE",
    ILLEGAL_TRANSITION: "ILLEGAL_TRANSITION",
    DUPLICATE_ID: "DUPLICATE_ID",
    TERMINAL_STATE: "TERMINAL_STATE",
    UNAUTHORIZED_DECISION: "UNAUTHORIZED_DECISION",
    EVIDENCE_NOT_FOUND: "EVIDENCE_NOT_FOUND",
    INVALID_EVIDENCE: "INVALID_EVIDENCE",
    NO_DECISION_EVENT: "NO_DECISION_EVENT",
    INVESTIGATION_NOT_OPEN: "INVESTIGATION_NOT_OPEN",
});

export class DomainError extends Error {
    constructor(code, message, details = null) {
        super(message);
        this.name = new.target.name;
        this.code = code;
        this.details = details;
    }
}

export class CanonicalizationError extends DomainError {
    constructor(message, details = null) {
        super(ERROR_CODES.INVALID_CANONICAL_VALUE, message, details);
    }
}

export class ContractError extends DomainError {
    constructor(message, details = null, code = ERROR_CODES.INVALID_CONTRACT) {
        super(code, message, details);
    }
}

export class EventChainError extends DomainError {
    constructor(code, message, details = null) {
        super(code, message, details);
    }
}

export class TransitionError extends DomainError {
    constructor(code, message, details = null) {
        super(code, message, details);
    }
}

export class DecisionError extends DomainError {
    constructor(code, message, details = null) {
        super(code, message, details);
    }
}
