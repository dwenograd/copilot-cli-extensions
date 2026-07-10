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
    parseHarnessResult,
} from "./parser.mjs";

export {
    ARGV_HASH_ALGORITHM,
    ENV_HASH_ALGORITHM,
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

export { createMeasurementExecutor, toFileUrl } from "./executor.mjs";
