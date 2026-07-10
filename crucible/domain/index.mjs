export {
    CANONICAL_HASH_ALGORITHM,
    CANONICAL_JSON_VERSION,
    CONTRACT_HASH_ALGORITHM,
    EVENT_HASH_ALGORITHM,
    canonicalClone,
    canonicalEqual,
    canonicalJson,
    deepFreeze,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";

export {
    acceptanceSatisfied,
    availableCandidateMetricValues,
    assessAcceptancePredicate,
    candidateMetricValues,
    candidateMetricsRankable,
    commandBudget,
    contractHash,
    createInvestigationContract,
    createSearchPolicy,
    defaultSearchPolicy,
    normalizeSearchPolicy,
    validationSatisfied,
} from "./contract.mjs";

export {
    ANNOTATION_LIMITS,
    CANDIDATE_OUTCOME_CLASSES,
    DEFAULT_SEARCH_POLICY,
    DOMAIN_VERSION,
    ESCAPE_SEARCH_OPERATORS,
    EVIDENCE_EVENT_TYPES,
    EVIDENCE_PURPOSES,
    EVENT_CATEGORIES,
    EVENT_TYPES,
    EVENT_VOCABULARY,
    EXTERNAL_EVENT_TYPES,
    HYPOTHESIS_TOPOLOGIES,
    KERNEL_DECISION_EVENT_TYPES,
    KERNEL_CONTROL_EVENT_TYPES,
    NON_RESULT_CODES,
    SEARCH_OPERATORS,
    SOURCE_KINDS,
    TERMINAL_EVENT_TYPES,
} from "./constants.mjs";

export { decideNext } from "./decision.mjs";

export {
    computeEventHash,
    constructEvidenceCommittedEvent,
    constructHarnessObservedEvent,
    constructInvestigationResumedEvent,
    constructKernelDecisionEvent,
    constructModelObservedEvent,
    createExternalEvent,
    createInvestigationOpenedEvent,
} from "./events.mjs";

export {
    CanonicalizationError,
    ContractError,
    DecisionError,
    DomainVersionRestartRequiredError,
    DomainError,
    ERROR_CODES,
    EventChainError,
    RestartRequiredError,
    TransitionError,
} from "./errors.mjs";

export {
    boundedSelect,
    buildArchive,
    buildCandidateArchive,
    buildDuplicateIndex,
    classifyCandidateOutcome,
    classifyOutcome,
    compareCandidateEvidence,
    createCandidateArchive,
    duplicateEvidenceId,
    metricImprovement,
    selectArchive,
    selectIncumbent,
    selectPromptEvidence,
} from "./archive.mjs";

export {
    adaptiveOperatorWeights,
    analyzePlateau,
    assignSearchOperator,
    buildSearchCandidateCommand,
    createSearchCandidateCommand,
    deriveSearchCandidateCommand,
    detectPlateau,
    detectSearchPlateau,
    deterministicHashInteger,
    deterministicSeed,
    selectAdaptiveOperator,
    selectOperator,
} from "./strategy.mjs";

export {
    reduceEvent,
    replayEvents,
    verifyEventChain,
} from "./reducer.mjs";

export {
    activeCommand,
    boundedSearchExhaustion,
    candidateSelectionReady,
    createInitialAggregate,
    currentValidationEvidence,
    harnessCandidateEvidenceItems,
    latestUnhandledStopRequest,
    qualifyingCandidateEvidence,
    qualifyingCandidateEvidenceItems,
    qualifyingUnreachableEvidence,
    qualifyingValidationEvidence,
    searchProgress,
    uncommittedObservation,
} from "./state.mjs";
