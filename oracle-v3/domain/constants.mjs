export const DOMAIN_VERSION = 1;

export const HYPOTHESIS_TOPOLOGIES = Object.freeze([
    "finite_enumerable",
    "bounded_parameterized",
    "open_generative",
    "certified_impossibility",
]);

export const EVENT_TYPES = Object.freeze({
    INVESTIGATION_OPENED: "investigation_opened",
    CAPABILITY_EPOCH_RECORDED: "capability_epoch_recorded",
    COMMAND_RESERVED: "command_reserved",
    COMMAND_DISPATCHED: "command_dispatched",
    COMMAND_OBSERVED: "command_observed",
    EVIDENCE_COMMITTED: "evidence_committed",
    EVIDENCE_INVALIDATED: "evidence_invalidated",
    VALIDATION_COMPLETED: "validation_completed",
    SEARCH_STRATEGY_REVISED: "search_strategy_revised",
    STOP_REQUESTED: "stop_requested",
    INVESTIGATION_PAUSED: "investigation_paused",
    INVESTIGATION_RESUMED: "investigation_resumed",
    NON_RESULT_RECORDED: "non_result_recorded",
    VERIFIED_RESULT: "verified_result",
    TARGET_UNREACHABLE: "target_unreachable",
});

export const EVENT_VOCABULARY = Object.freeze(Object.values(EVENT_TYPES));

export const EXTERNAL_EVENT_TYPES = Object.freeze([
    EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
    EVENT_TYPES.COMMAND_DISPATCHED,
    EVENT_TYPES.EVIDENCE_INVALIDATED,
    EVENT_TYPES.STOP_REQUESTED,
]);

export const KERNEL_DECISION_EVENT_TYPES = Object.freeze([
    EVENT_TYPES.COMMAND_RESERVED,
    EVENT_TYPES.VALIDATION_COMPLETED,
    EVENT_TYPES.SEARCH_STRATEGY_REVISED,
    EVENT_TYPES.INVESTIGATION_PAUSED,
    EVENT_TYPES.NON_RESULT_RECORDED,
    EVENT_TYPES.VERIFIED_RESULT,
    EVENT_TYPES.TARGET_UNREACHABLE,
]);

export const KERNEL_CONTROL_EVENT_TYPES = Object.freeze([
    EVENT_TYPES.INVESTIGATION_RESUMED,
]);

export const EVIDENCE_EVENT_TYPES = Object.freeze([
    EVENT_TYPES.COMMAND_OBSERVED,
    EVENT_TYPES.EVIDENCE_COMMITTED,
    EVENT_TYPES.EVIDENCE_INVALIDATED,
]);

export const TERMINAL_EVENT_TYPES = Object.freeze([
    EVENT_TYPES.VERIFIED_RESULT,
    EVENT_TYPES.TARGET_UNREACHABLE,
]);

export const EVENT_CATEGORIES = Object.freeze({
    observations: Object.freeze([
        EVENT_TYPES.INVESTIGATION_OPENED,
        EVENT_TYPES.CAPABILITY_EPOCH_RECORDED,
        EVENT_TYPES.COMMAND_DISPATCHED,
        EVENT_TYPES.COMMAND_OBSERVED,
        EVENT_TYPES.STOP_REQUESTED,
    ]),
    evidence: EVIDENCE_EVENT_TYPES,
    decisions: Object.freeze([
        ...KERNEL_DECISION_EVENT_TYPES,
        ...KERNEL_CONTROL_EVENT_TYPES,
    ]),
    terminalDecisions: TERMINAL_EVENT_TYPES,
});

export const SOURCE_KINDS = Object.freeze([
    "harness",
    "model_review",
    "operator_observation",
]);

export const EVIDENCE_PURPOSES = Object.freeze([
    "validation",
    "candidate",
    "impossibility",
]);

export const NON_RESULT_CODES = Object.freeze({
    BUDGET_EXHAUSTED_INCONCLUSIVE: "BUDGET_EXHAUSTED_INCONCLUSIVE",
    VALIDATION_INCONCLUSIVE: "VALIDATION_INCONCLUSIVE",
    INVESTIGATION_PAUSED: "INVESTIGATION_PAUSED",
});
