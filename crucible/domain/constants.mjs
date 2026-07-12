export const DOMAIN_VERSION = 4;

export const CONTRACT_LIMITS = Object.freeze({
    objectiveCharacters: 2048,
    objectiveBytes: 2048,
    acceptancePredicateBytes: 4096,
    acceptancePredicateDepth: 16,
    acceptancePredicateNodes: 128,
    acceptancePredicateChildren: 32,
    acceptancePathSegments: 16,
    acceptancePathSegmentCharacters: 128,
    acceptanceValueDepth: 8,
    acceptanceValueNodes: 128,
    acceptanceValueArrayItems: 32,
    acceptanceValueObjectProperties: 32,
    acceptanceValueStringCharacters: 1024,
    acceptanceValueStringBytes: 2048,
    metrics: 12,
    validationCases: 64,
    workerModels: 8,
    candidatesPerRound: 8,
    maxRounds: 64,
    maxEvaluations: 512,
    boundedCandidateIds: 512,
    statisticalFamilies: 32,
    maxBlocks: 4096,
    maxConfirmations: 64,
    maxStatisticalEvaluations: 100000,
    maxResourceBytes: 4 * 1024 * 1024 * 1024,
});

export const SEARCH_POLICY_LIMITS = Object.freeze({
    plateauWindow: CONTRACT_LIMITS.maxRounds,
    minRoundsBeforePlateau: CONTRACT_LIMITS.maxRounds,
    mandatoryEscapeRounds: CONTRACT_LIMITS.maxRounds,
    archiveCaps: Object.freeze({
        accepted: 32,
        nearMisses: 32,
        rejected: 32,
        invalidMetrics: 32,
        mechanismGroups: 32,
        lessonGroups: 32,
        duplicateIndex: 256,
    }),
    promptCaps: Object.freeze({
        parentEvidenceIds: 4,
        promptContextRefs: 12,
    }),
});

export const HYPOTHESIS_TOPOLOGIES = Object.freeze([
    "finite_enumerable",
    "bounded_parameterized",
    "open_generative",
    "certified_impossibility",
]);

export const STATISTICAL_POLICY_VERSION = "crucible-statistical-policy-v4";
export const STATISTICAL_POLICY_HASH_ALGORITHM =
    "sha256:crucible-statistical-policy-v4";
export const GOAL_MODES = Object.freeze(["satisfice", "optimize"]);
export const STATISTICAL_METRIC_DIRECTIONS = Object.freeze(["min", "max"]);
export const MISSINGNESS_MODES = Object.freeze(["fail_closed", "bounded"]);
export const SCIENTIFIC_TERMINAL_POLICY_VERSION =
    "crucible-scientific-terminal-readiness-v1";
export const DEFAULT_SCIENTIFIC_TERMINAL_POLICY = Object.freeze({
    version: SCIENTIFIC_TERMINAL_POLICY_VERSION,
    verifiedResult: Object.freeze({
        confirmationRequired: true,
        challengeRequired: true,
    }),
    targetUnreachable: Object.freeze({
        independentVerifierRequired: true,
    }),
    hypotheses: Object.freeze({
        requiredForResultMustBeSupported: true,
    }),
});

export const IMPOSSIBILITY_REQUEST_VERSION = "crucible-impossibility-request-v1";
export const IMPOSSIBILITY_CERTIFICATE_VERSION = "crucible-impossibility-certificate-v1";
export const IMPOSSIBILITY_REQUEST_HASH_ALGORITHM =
    "sha256:crucible-impossibility-request-v1";
export const IMPOSSIBILITY_SEARCH_EVIDENCE_HASH_ALGORITHM =
    "sha256:crucible-impossibility-search-evidence-v1";
export const IMPOSSIBILITY_VERDICTS = Object.freeze([
    "target_unreachable",
    "not_proven",
    "invalid",
]);
export const DEFAULT_IMPOSSIBILITY_POLICY = Object.freeze({
    trigger: "search_exhausted",
    requestVersion: IMPOSSIBILITY_REQUEST_VERSION,
    certificateVersion: IMPOSSIBILITY_CERTIFICATE_VERSION,
});

export const CANDIDATE_OUTCOME_CLASSES = Object.freeze([
    "accepted",
    "near_miss",
    "rejected",
    "invalid_metrics",
]);

export const SEARCH_OPERATORS = Object.freeze([
    "fresh",
    "refinement",
    "crossover",
    "diversification",
    "adversarial",
    "restart",
]);

export const ESCAPE_SEARCH_OPERATORS = Object.freeze([
    "diversification",
    "adversarial",
    "restart",
]);

export const DEFAULT_SEARCH_POLICY = Object.freeze({
    plateauWindow: 3,
    minRoundsBeforePlateau: 3,
    plateauMinImprovement: 0,
    mandatoryEscapeRounds: 2,
    operatorWeights: Object.freeze({
        fresh: 30,
        refinement: 25,
        crossover: 15,
        diversification: 15,
        adversarial: 10,
        restart: 5,
    }),
    archiveCaps: Object.freeze({
        accepted: 8,
        nearMisses: 16,
        rejected: 8,
        invalidMetrics: 8,
        mechanismGroups: 12,
        lessonGroups: 12,
        duplicateIndex: 256,
    }),
    promptCaps: Object.freeze({
        parentEvidenceIds: 2,
        promptContextRefs: 12,
    }),
    dedupPolicy: "mark",
});

export const ANNOTATION_LIMITS = Object.freeze({
    mechanismLength: 256,
    mechanismBytes: 256,
    hypothesisLength: 2048,
    hypothesisBytes: 4096,
    expectedEffectCount: 16,
    expectedEffectLength: 512,
    expectedEffectBytes: 512,
    citedEvidenceCount: SEARCH_POLICY_LIMITS.promptCaps.promptContextRefs,
    findingLength: 1024,
    findingBytes: 1024,
    totalBytes: 16 * 1024,
});

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
    IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE: "IMPOSSIBILITY_CERTIFICATE_INCONCLUSIVE",
    INDEPENDENT_VERIFICATION_REQUIRED: "INDEPENDENT_VERIFICATION_REQUIRED",
    SCIENTIFIC_CONFIRMATION_REQUIRED: "SCIENTIFIC_CONFIRMATION_REQUIRED",
    VALIDATION_INCONCLUSIVE: "VALIDATION_INCONCLUSIVE",
    INVESTIGATION_PAUSED: "INVESTIGATION_PAUSED",
});
