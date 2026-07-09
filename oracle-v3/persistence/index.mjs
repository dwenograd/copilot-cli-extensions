// oracle-v3/persistence/index.mjs
//
// Public surface of the Oracle v3 persistence layer.

export { EventRepository, openRepository } from "./repository.mjs";
export {
    ERROR_CODES,
    SQLITE_ERRCODE,
    OraclePersistenceError,
    LocalPathError,
    SchemaVersionError,
    InvalidArgumentError,
    NotFoundError,
    CasConflictError,
    TerminalExistsError,
    IllegalTransitionError,
    FenceRejectedError,
    ArtifactNotDurableError,
    StorageError,
} from "./errors.mjs";
export { assertLocalDatabasePath, isNetworkOrUncPath } from "./paths.mjs";
export { canonicalize, computeEventHash, sha256Hex, GENESIS_PREV_HASH } from "./canonical.mjs";
export { SCHEMA_VERSION, COMMAND_STATES, TERMINAL_KINDS } from "./schema.mjs";

// Immutable content-addressed artifact store (filesystem CAS).
export {
    ArtifactStore,
    openArtifactStore,
    ARTIFACT_STORE_ERROR_CODES,
    ArtifactStoreError,
    UnsafePathError,
    SymlinkRejectedError,
    LimitExceededError,
    ObjectNotFoundError,
    ObjectCorruptError,
    DestinationExistsError,
    SnapshotInvalidError,
    SourceChangedError,
    objectIdFor,
    parseObjectId,
    objectRelPath,
} from "./artifact-store.mjs";

// Self-contained audit bundle export/import.
export {
    exportBundle,
    importBundle,
    readBundleManifest,
    BUNDLE_ERROR_CODES,
    BundleError,
    BundleDestinationExistsError,
    BundleTamperError,
    BundleInventoryError,
} from "./bundle.mjs";
