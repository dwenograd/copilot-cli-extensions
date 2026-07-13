export {
    RUNTIME_ERROR_CODES,
    CrucibleRuntimeError,
    LegacyIncompatibleRuntimeError,
    RuntimeConfigError,
    RuntimeDriftError,
    RuntimeIntegrityError,
    SdkFailureError,
    SdkRetryExhaustedError,
    SdkSubmissionConflictError,
    WorkerProtocolError,
    SupervisorLockError,
    InjectedCrashError,
    isRecoverableRuntimeError,
    serializeRuntimeError,
} from "./errors.mjs";

export {
    DEFAULT_SDK_RETRY_POLICY,
    SDK_FAILURE_CLASSIFICATIONS,
    SDK_OPERATIONAL_EVIDENCE_HASH_ALGORITHM,
    SDK_OPERATIONAL_EVIDENCE_VERSION,
    SDK_OPERATION_IDENTITY_HASH_ALGORITHM,
    SDK_RETRY_BUDGET_HASH_ALGORITHM,
    SDK_RETRY_BUDGET_VERSION,
    SDK_RETRY_DISABLED_POLICY,
    SDK_RETRY_INTEGRATION_NOTES,
    SDK_RETRY_POLICY_VERSION,
    SDK_SUBMISSION_COMMIT_HASH_ALGORITHM,
    SDK_SUBMISSION_COMMIT_VERSION,
    SDK_SUBMISSION_HASH_ALGORITHM,
    classifySdkFailure,
    computeSdkRetryDelay,
    createInMemorySdkSubmissionJournal,
    createRetryingSdkClient,
    createSdkOperationalEvidence,
    createSdkOperationIdentity,
    createSdkQuarantineRecord,
    createSdkRetryBudget,
    createSdkSubmissionGate,
    createSdkUsageAccumulator,
    normalizeSdkOperationIdentity,
    normalizeSdkRetryPolicy,
    normalizeSdkSubmissionJournal,
    normalizeSdkUsageEvent,
    reconcileSdkCost,
    withSdkFailureContext,
} from "./retry-policy.mjs";

export {
    RUNTIME_IDENTITY_POLICY_HASH_ALGORITHM,
    RUNTIME_IDENTITY_RESULT_CODES,
    RUNTIME_IDENTITY_ROOT_ALGORITHM,
    assertRuntimeIdentityVerified,
    buildRuntimeIdentity,
    collectRuntimeAssumptions,
    createRuntimeIdentityHashCache,
    reverifyRuntimeIdentity,
    runtimeIdentityBuildInputFromIdentity,
    runtimeIdentityPolicyIdentity,
    runtimeIdentityRoot,
    verifyRuntimeIdentity,
} from "./runtime-identity.mjs";

export {
    normalizeRunnerConfig,
    loadRunnerConfig,
    normalizeSupervisorConfig,
    coerceSupervisorConfig,
    loadSupervisorConfig,
    supervisorPaths,
    supervisorConfigDocument,
    supervisorConfigFingerprint,
} from "./config.mjs";

export {
    assertSupervisorConfigMatchesRuntimeAuthority,
    buildRuntimeConfigAuthority,
    supervisorConfigFromRuntimeAuthority,
    verifyRuntimeConfigAuthority,
} from "./config-authority.mjs";

export {
    ACTIVE_QUIESCENT_STOP_STATES,
    QUIESCENT_STOP_INTEGRATION_NOTES,
    QUIESCENT_STOP_PROTOCOL_VERSION,
    QUIESCENT_STOP_STATES,
    buildQuiescenceSnapshot,
    consumeRunnerStopSignal,
    consumeSupervisorStopSignal,
    ensureStopDomainIntent,
    isActiveQuiescentStop,
    ownerScopedControlPath,
    persistPausePending,
    persistPausedQuiescent,
    persistQuiescentStopBarrier,
    runnerScopedControlPath,
    stopControlPaths,
    waitForQuiescentStopAcknowledgement,
    writeRunnerStopSignal,
    writeSupervisorStopSignal,
} from "./control-channel.mjs";

export {
    DEFAULT_RESOURCE_BROKER_CONFIG,
    DEFAULT_MODEL_COST_POLICY,
    MODEL_COST_POLICY_VERSION,
    RESOURCE_BROKER_CONFIG_VERSION,
    RESOURCE_KEYS,
    STRICT_ISO_TIMESTAMP_PATTERN_SOURCE,
    deriveRunnerExecutionLimits,
    deriveRuntimeResourceAdmission,
    estimateDeterministicModelCostUnits,
    investigationResourceLimitsFingerprint,
    normalizeInvestigationResourceLimits,
    normalizeResourceBrokerConfig,
    normalizeResourceReservation,
    normalizeStartDeadline,
    resourceBrokerConfigFingerprint,
    resourceDefinitionsFromConfig,
    resourceLimitEntries,
    resourceReservationEntries,
    resourceUsageEntries,
    sdkUsageToModelCostUnits,
    validateSupervisorTimingConstraints,
} from "./config-validation.mjs";

export {
    RESOURCE_BROKER_INTEGRATION_NOTES,
    RESOURCE_CATALOG_FILENAME,
    ResourceBroker,
    openResourceBroker,
    resourceCatalogPath,
} from "./resource-broker.mjs";

export {
    SUBMIT_CANDIDATE_TOOL_NAME,
    READ_PARENT_ARTIFACT_TOOL_NAME,
    MAX_PROPOSAL_PROMPT_BYTES,
    MAX_TRUSTED_OPERATOR_CONTEXT_BYTES,
    DEFAULT_CANDIDATE_LIMITS,
    DEFAULT_PARENT_READ_LIMITS,
    SdkWorkerPool,
    createBoundedParentReadAuthority,
    createSdkWorkerPool,
    normalizeParentReadLimits,
    validateCandidateSubmission,
    validateWorkerProposal,
    buildProposalPrompt,
} from "./worker-pool.mjs";

export {
    assertBoundedEnumerandRequest,
    assertFiniteEnumerandSnapshot,
    resolveCommandEnumerand,
} from "./enumerand-execution.mjs";

export {
    REPLICATION_CONTROL_TOLERANCE_HASH_ALGORITHM,
    REPLICATION_SCHEDULE_ALGORITHM,
    REPLICATION_SCHEDULE_HASH_ALGORITHM,
    REPLICATION_SCHEDULE_VERSION,
    REPLICATION_STATISTICAL_SUMMARY_HASH_ALGORITHM,
    ReplicationScheduleError,
    analyzeReplicationAttempts,
    assertReplicationScheduleMatches,
    deriveControlToleranceMetadata,
    deriveReplicationSchedule,
    deriveReplicationSubjectIdentity,
    evaluateReplicationProgress,
    expectedReplicationSubjects,
    normalizeReplicationSchedule,
    replicationAttemptKey,
    replicationBlockPlan,
} from "./measurement-scheduler.mjs";

export {
    PROMPT_CONTEXT_VERSION,
    PROMPT_CONTEXT_HASH_ALGORITHM,
    DEFAULT_PROMPT_CONTEXT_BYTE_CAP,
    assertPromptContractCoreFits,
    buildPromptContext,
    createPromptContext,
} from "./prompt-context.mjs";

export {
    DomainRepositoryAdapter,
    assertInvestigationDomainCompatible,
    createDomainRepositoryAdapter,
    inspectInvestigationDomainCompatibility,
    openDomainRepositoryAdapter,
    formatAttemptCommand,
} from "./domain-adapter.mjs";

export {
    AutonomousRunner,
    inspectFrozenImpossibilityVerifierExecution,
    runAutonomousInvestigation,
} from "./runner.mjs";

export {
    isExactPidAlive,
    acquireSupervisorLock,
    readSupervisorLock,
    releaseSupervisorLock,
    runSupervisor,
    readSupervisorStatus,
    terminateExactSupervisor,
} from "./supervisor.mjs";

export {
    startSupervisor,
    readStatus,
    requestStop,
    resolveNodeExecutable,
    ensureSupervisor,
    waitForSupervisorAcknowledgement,
    waitForStopAcknowledgement,
    terminateSupervisor,
    validateSupervisorAdmission,
} from "./extension-adapter.mjs";
