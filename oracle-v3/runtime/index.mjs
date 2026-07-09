export {
    RUNTIME_ERROR_CODES,
    OracleRuntimeError,
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
} from "./config.mjs";

export {
    SUBMIT_CANDIDATE_TOOL_NAME,
    DEFAULT_CANDIDATE_LIMITS,
    SdkWorkerPool,
    createSdkWorkerPool,
    validateCandidateSubmission,
    buildProposalPrompt,
    assertWorkerSessionsAreNonTerminal,
} from "./worker-pool.mjs";

export {
    DomainRepositoryAdapter,
    createDomainRepositoryAdapter,
    openDomainRepositoryAdapter,
    formatAttemptCommand,
} from "./domain-adapter.mjs";

export {
    AutonomousRunner,
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
    ensureSupervisor,
    terminateSupervisor,
} from "./extension-adapter.mjs";
