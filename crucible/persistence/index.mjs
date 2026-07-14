// crucible/persistence/index.mjs
//
// Public surface of the Crucible persistence layer.

export {
    EventRepository,
    openRepository,
    openRepositoryReadOnly,
} from "./repository.mjs";
export {
    ERROR_CODES,
    SQLITE_ERRCODE,
    CruciblePersistenceError,
    LocalPathError,
    SchemaVersionError,
    SchemaIntegrityError,
    DatabaseIntegrityError,
    InvalidArgumentError,
    CanonicalPayloadError,
    NotFoundError,
    CasConflictError,
    TerminalExistsError,
    SegmentIntegrityError,
    SegmentRotationError,
    WalCheckpointUnsafeError,
    IllegalTransitionError,
    FenceRejectedError,
    AttemptIdentityError,
    ArtifactNotDurableError,
    StorageError,
} from "./errors.mjs";
export { assertLocalDatabasePath, isNetworkOrUncPath } from "./paths.mjs";
export {
    canonicalize,
    inspectCanonicalJson,
    parseCanonicalJson,
    computeEventHash,
    sha256Hex,
    GENESIS_PREV_HASH,
} from "./canonical.mjs";
export {
    SCHEMA_VERSION,
    SCHEMA_FINGERPRINT,
    EVENT_HASH_VERSION,
    COMMAND_STATES,
    TERMINAL_KINDS,
    verifyDatabaseIntegrity,
} from "./schema.mjs";
export {
    EventSegmentManager,
    SEGMENT_CATALOG_TYPE,
    SEGMENT_CATALOG_VERSION,
    SEGMENT_SCHEMA_VERSION,
    SEGMENT_SEAL_STAGES,
    SEGMENT_MANAGER_INTEGRATION_NOTES,
    DEFAULT_SEGMENT_EVENT_THRESHOLD,
    DEFAULT_SEGMENT_BYTE_THRESHOLD,
    segmentCatalogPathFor,
    inspectSegmentStorage,
} from "./segment-manager.mjs";

export {
    WORKING_SET_INTEGRATION_NOTES,
    WorkingSetController,
    collectWorkingSetReferences,
    createWorkingSetController,
    evaluateStorageBudget,
    publicWorkingSetTelemetry,
    reconcileWorkingSetArtifacts,
} from "./working-set.mjs";

export {
    ResourceCatalogRepository,
    openResourceCatalog,
    openResourceCatalogReadOnly,
    readStoredResourceCatalogConfiguration,
} from "./resource-catalog.mjs";
export {
    RESOURCE_CATALOG_SCHEMA_VERSION,
    RESOURCE_CATALOG_SCHEMA_FINGERPRINT,
    RESOURCE_CATALOG_SCHEMA_HASH_ALGORITHM,
    RESOURCE_CATALOG_CONFIG_HASH_ALGORITHM,
    RESOURCE_LIMITS_HASH_ALGORITHM,
    verifyResourceCatalogSchema,
} from "./resource-catalog-schema.mjs";

// Immutable content-addressed artifact store (filesystem CAS).
export {
    ArtifactStore,
    openArtifactStore,
    openArtifactStoreReadOnly,
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
    JournalCorruptError,
    objectIdFor,
    parseObjectId,
    objectRelPath,
} from "./artifact-store.mjs";

export {
    materializeFiniteEnumerand,
    stageBoundedParameterizedManifest,
    stageFiniteEnumerandManifest,
    verifyStagedFiniteEnumerands,
} from "./enumerand-staging.mjs";

// Self-contained audit bundle export/import.
export {
    exportBundle,
    importBundle,
    verifyBundleInPlace,
    removeVerifiedBundle,
    readBundleManifest,
    BUNDLE_TYPE,
    BUNDLE_VERSION,
    BUNDLE_ERROR_CODES,
    BundleError,
    BundleDestinationExistsError,
    BundleTamperError,
    BundleInventoryError,
    BundleManifestError,
    BundleDomainVersionMismatchError,
    BundleAuthenticationError,
    BundleSourceChangedError,
    BundleUnsafePathError,
} from "./bundle.mjs";

export {
    TOMBSTONE_TYPE,
    TOMBSTONE_VERSION,
    TOMBSTONE_KEY_TYPE,
    TOMBSTONE_KEY_VERSION,
    TOMBSTONE_KEY_FINGERPRINT_ALGORITHM,
    writeSignedTombstone,
    verifySignedTombstone,
    measureRetainedTree,
    removeRetainedTree,
} from "./retention.mjs";
