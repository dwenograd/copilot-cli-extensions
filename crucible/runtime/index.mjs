export {
    RUNTIME_ERROR_CODES,
    CrucibleRuntimeError,
    LegacyIncompatibleRuntimeError,
    RuntimeConfigError,
    RuntimeIntegrityError,
    WorkerProtocolError,
    SupervisorLockError,
    InjectedCrashError,
    isRecoverableRuntimeError,
    serializeRuntimeError,
} from "./errors.mjs";

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
    STRICT_ISO_TIMESTAMP_PATTERN_SOURCE,
    deriveRunnerExecutionLimits,
    normalizeStartDeadline,
    validateSupervisorTimingConstraints,
} from "./config-validation.mjs";

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
    terminateSupervisor,
    validateSupervisorAdmission,
} from "./extension-adapter.mjs";
