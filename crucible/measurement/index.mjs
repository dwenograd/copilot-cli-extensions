// crucible/measurement/index.mjs
//
// Public surface of the Crucible trusted-measurement boundary.

export {
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
    SandboxCapabilityError,
    SandboxRequiredError,
    SandboxUnavailableError,
    SandboxRefusedError,
    AllowlistInvalidError,
    FileVerificationError,
    StagingRefusedError,
    ResultParseError,
} from "./errors.mjs";

export {
    FILE_HASH_ALGORITHM,
    STREAM_HASH_ALGORITHM,
    normalizeExpectedHash,
    sha256Bytes,
    sha256File,
    verifyAndHashFile,
    verifyLocalRegularFile,
} from "./fs-verify.mjs";

export {
    ALLOWLIST_HASH_ALGORITHM,
    ALLOWED_ENV_HASH_ALGORITHM,
    ARGV_PLACEHOLDERS,
    ARGV_TEMPLATE_HASH_ALGORITHM,
    ENTRY_HASH_ALGORITHM,
    HARNESS_IDENTITY_VERSION,
    PARSER_SOURCE_HASH_ALGORITHM,
    PARSER_VERSION_HASH_ALGORITHM,
    SANDBOX_POLICY_IDENTITY_HASH_ALGORITHM,
    buildFrozenHarnessIdentity,
    isVerifiedHarnessEntry,
    loadHarnessAllowlist,
    validateHarnessValidationCases,
    verifyFrozenHarnessIdentity,
    verifyHarnessPreflight,
} from "./allowlist.mjs";

export {
    PARSER_MAX_INPUT_BYTES,
    PARSER_VERSION,
    normalizeHarnessResultBinding,
    parseHarnessResult,
} from "./parser.mjs";

export {
    NOVELTY_BINDING_SEED_ALGORITHM,
    NOVELTY_MAX_STRUCTURAL_FEATURES,
    NOVELTY_ROLE_ADAPTER_VERSION,
    NOVELTY_ROLE_FINGERPRINT_ALGORITHM,
    NOVELTY_STRUCTURAL_FINGERPRINT_ALGORITHM,
    NoveltyRoleError,
    adaptNoveltyRoleAttempt,
    createNoveltyMeasurementBinding,
    normalizeNoveltyRoleAttempt,
    noveltyRoleFingerprint,
    tryAdaptNoveltyRoleAttempt,
} from "./novelty-role.mjs";

export {
    HARNESS_SUITE_V4_CASE_MANIFEST_ALGORITHM,
    HARNESS_SUITE_V4_CONFIG_ALGORITHM,
    HARNESS_SUITE_V4_CORPUS_ALGORITHM,
    HARNESS_SUITE_V4_ENVIRONMENT_ALGORITHM,
    HARNESS_SUITE_V4_HIDDEN_CASE_ROLES,
    HARNESS_SUITE_V4_IDENTITY_ALGORITHM,
    HARNESS_SUITE_V4_KIND,
    HARNESS_SUITE_V4_OBSERVABLE_SCHEMA_ALGORITHM,
    HARNESS_SUITE_V4_OPTIONAL_ROLES,
    HARNESS_SUITE_V4_REQUIRED_ROLES,
    HARNESS_SUITE_V4_ROLES,
    HARNESS_SUITE_V4_VERSION,
    HarnessSuiteV4Error,
    computeHarnessSuiteV4Identity,
    hashHarnessEnvironmentV4,
    hashHarnessObservableSchemaV4,
    hashHarnessRoleConfigV4,
    harnessSuiteV4Identity,
    identifyHarnessSuiteV4,
    normalizeHarnessRoleConfigV4,
    normalizeHarnessSuiteV4,
    projectHarnessSuiteV4ForWorker,
    validateHarnessSuiteV4,
    validateHarnessSuiteV4CaseClaims,
} from "./harness-suite.mjs";

export {
    ARGV_HASH_ALGORITHM,
    ENV_HASH_ALGORITHM,
    HARNESS_SUITE_RECEIPT_DETERMINISM_KEYS,
    HARNESS_SUITE_RECEIPT_VERSION,
    RECEIPT_DETERMINISM_KEYS,
    RECEIPT_HASH_ALGORITHM,
    RECEIPT_VERSION,
    buildMeasurementReceipt,
    canonicalizeReceipt,
    hashArgv,
    hashEnv,
    hashReceipt,
    projectDeterministicReceipt,
} from "./receipt.mjs";

export {
    createSandboxProvider,
    describeSandboxProviderPolicy,
} from "./sandbox.mjs";

export { createDefaultProcessAdapter } from "./windows-adapter.mjs";

export {
    WINDOWS_SANDBOX_POLICY_ID,
    WINDOWS_SANDBOX_PRIMITIVE,
    WINDOWS_SANDBOX_LIMITATIONS,
    createWindowsSandboxProvider,
    probeWindowsSandboxAvailability,
} from "./windows-sandbox-provider.mjs";

export {
    DEFAULT_MEASUREMENT_BYTE_BUDGETS,
    createMeasurementExecutor,
    toFileUrl,
} from "./executor.mjs";
