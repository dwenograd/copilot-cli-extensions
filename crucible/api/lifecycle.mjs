import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
    DOMAIN_VERSION,
    assessPersistedTerminalReadiness,
} from "../domain/index.mjs";
import {
    exportBundle,
    importBundle,
    measureRetainedTree,
    canonicalize,
    openArtifactStoreReadOnly,
    openRepositoryReadOnly,
    removeRetainedTree,
    removeVerifiedBundle,
    verifyBundleInPlace,
    verifySignedTombstone,
    writeSignedTombstone,
} from "../persistence/index.mjs";
import {
    createDomainRepositoryAdapter,
    createProcessIdentityAdapter,
    inspectInvestigationDomainCompatibility,
    openResourceBrokerFromStateRoot,
    openResourceBrokerReadOnlyFromStateRoot,
    resourceCatalogPath,
    supervisorPaths,
} from "../runtime/index.mjs";
import { verifyExperimentAuthority } from "./experiment-authority.mjs";
import {
    resolveArchiveTrustPolicy,
    resolveCatalogRetentionPath,
    resolveInvestigationPaths,
    resolveRetentionPaths,
    resolveStateRoot,
} from "./environment.mjs";
import {
    InvestigationNotFoundError,
    InvestigationNotResumableError,
    SchemaValidationError,
} from "./errors.mjs";

const CURSOR_VERSION = 1;
const INVESTIGATION_ID_RE =
    /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;
const ARCHIVE_ELIGIBILITY_STATES = Object.freeze([
    "terminal",
    "domain_non_result",
    "paused_quiescent",
]);

function lifecycleProcessIdentity(deps) {
    return deps.lifecycleProcessIdentity
        ?? createProcessIdentityAdapter();
}

function lifecycleOwner(deps) {
    const identity = lifecycleProcessIdentity(deps);
    return Object.freeze({
        processId: process.pid,
        processStartId: identity.current(process.pid),
    });
}

function reclaimStaleLifecycleFence(
    broker,
    entry,
    deps,
    requestedKind,
) {
    const operation = entry?.lifecycleOperation ?? null;
    if (operation === null) {
        return Object.freeze({
            entry,
            reclaimed: false,
            reclaimedOperation: null,
        });
    }
    if (operation.operationKind !== requestedKind) {
        throw new InvestigationNotResumableError(
            `a pending ${operation.operationKind} lifecycle must be retried before ${requestedKind}`,
            {
                investigationId: entry.investigationId,
                pendingOperationKind: operation.operationKind,
                requestedOperationKind: requestedKind,
            },
        );
    }
    const identity = lifecycleProcessIdentity(deps);
    if (identity.isAlive({
        processId: operation.ownerProcessId,
        processStartId: operation.ownerProcessStartId,
    })) {
        throw new InvestigationNotResumableError(
            "another live process owns the investigation lifecycle fence",
            {
                investigationId: entry.investigationId,
                operationKind: operation.operationKind,
            },
        );
    }
    broker.abortLifecycleOperation({
        investigationId: entry.investigationId,
        operationToken: operation.operationToken,
    });
    return Object.freeze({
        entry: broker.getInvestigation(entry.investigationId),
        reclaimed: true,
        reclaimedOperation: operation,
    });
}

function mutationCatalogFactory(deps) {
    return deps.openResourceBrokerFromStateRoot
        ?? openResourceBrokerFromStateRoot;
}

function readCatalogFactory(deps) {
    return deps.openResourceBrokerReadOnlyFromStateRoot
        ?? openResourceBrokerReadOnlyFromStateRoot;
}

function pathExists(deps, candidate) {
    return (deps.pathExists ?? fs.existsSync)(candidate);
}

function catalogExists(deps, stateRoot, injectedFactory) {
    const catalogPath =
        (deps.resourceCatalogPath ?? resourceCatalogPath)(stateRoot);
    return injectedFactory
        || typeof deps.resourceCatalogPath === "function"
        ? pathExists(deps, catalogPath)
        : fs.existsSync(catalogPath);
}

function openCatalogForMutation(deps, stateRoot) {
    if (!catalogExists(
        deps,
        stateRoot,
        typeof deps.openResourceBrokerFromStateRoot === "function",
    )) return null;
    return mutationCatalogFactory(deps)({
        stateRoot,
        env: deps.env,
    });
}

function openCatalogForRead(deps, stateRoot) {
    if (!catalogExists(
        deps,
        stateRoot,
        typeof deps.openResourceBrokerReadOnlyFromStateRoot
            === "function",
    )) return null;
    return readCatalogFactory(deps)({
        stateRoot,
        env: deps.env,
    });
}

function safeClose(value) {
    try {
        value?.close?.();
    } catch {
        // Preserve the lifecycle operation result.
    }
}

function isUncatalogedLegacyInvestigation(deps, investigationId, paths) {
    if (!(deps.pathExists ?? fs.existsSync)(paths.eventsDbPath)) {
        return false;
    }
    if (typeof deps.inspectUncatalogedLegacyInvestigation === "function") {
        return deps.inspectUncatalogedLegacyInvestigation({
            investigationId,
            paths,
        }) === true;
    }
    const repository = (deps.openRepositoryReadOnly ?? openRepositoryReadOnly)({
        file: paths.eventsDbPath,
        env: deps.env,
    });
    try {
        const compatibility = inspectInvestigationDomainCompatibility({
            repository,
            investigationId,
        });
        return compatibility.present
            && compatibility.compatibility === "legacy_incompatible";
    } finally {
        safeClose(repository);
    }
}

const CLEANUP_MARKER_FILENAME = ".crucible-delete-cleanup.json";

function deleteAuthority(entry) {
    if (entry.lifecycleState === "archived"
        && entry.archive !== null) {
        return Object.freeze({
            archiveDigest: entry.archive.digest,
            domainVersion: entry.archive.domainVersion,
            domainHead: entry.archive.domainHead,
        });
    }
    if (entry.lifecycleState === "tombstoned"
        && entry.tombstone !== null) {
        return Object.freeze({
            archiveDigest: entry.tombstone.archiveDigest,
            domainVersion: entry.tombstone.domainVersion,
            domainHead: entry.tombstone.domainHead,
        });
    }
    throw new InvestigationNotResumableError(
        "investigation has no delete authority",
        { investigationId: entry.investigationId },
    );
}

function fsyncDirectory(directory) {
    let descriptor;
    try {
        descriptor = fs.openSync(
            directory,
            process.platform === "win32" ? "r+" : "r",
        );
        fs.fsyncSync(descriptor);
    } finally {
        if (descriptor !== undefined) fs.closeSync(descriptor);
    }
}

function fsyncDeleteCleanupRoots({
    archiveRoot,
    cleanupDir,
    deps,
}) {
    if (typeof deps.fsyncDeleteCleanupRoots === "function") {
        return deps.fsyncDeleteCleanupRoots({
            archiveRoot,
            cleanupParent: path.dirname(cleanupDir),
        });
    }
    fs.mkdirSync(archiveRoot, { recursive: true });
    const directories = new Map();
    for (const directory of [
        archiveRoot,
        path.dirname(cleanupDir),
    ]) {
        directories.set(
            process.platform === "win32"
                ? path.resolve(directory).toLowerCase()
                : path.resolve(directory),
            directory,
        );
    }
    for (const directory of directories.values()) {
        fsyncDirectory(directory);
    }
    return true;
}

function cleanupMarkerInput(entry, cleanup) {
    return {
        investigationId: entry.investigationId,
        archiveRelativePath: cleanup.archiveRelativePath,
        cleanupRelativePath: cleanup.cleanupRelativePath,
        archiveDigest: cleanup.archiveDigest,
        nonce: cleanup.cleanupMarkerNonce,
    };
}

function ensureCleanupOwnershipMarker({
    root,
    entry,
    cleanup,
    deps,
}) {
    if (cleanup.archiveRelativePath === null
        || cleanup.cleanupMarkerDigest === null) {
        throw new InvestigationNotResumableError(
            "cleanup marker authority is incomplete",
            { investigationId: entry.investigationId },
        );
    }
    const rootStat = fs.lstatSync(root);
    if (rootStat.isSymbolicLink()
        || !rootStat.isDirectory()
        || !sameLocalPath(fs.realpathSync.native(root), root)) {
        throw new InvestigationNotResumableError(
            "cleanup marker root is not a canonical directory",
            { investigationId: entry.investigationId, root },
        );
    }
    const markerFile = path.join(root, CLEANUP_MARKER_FILENAME);
    const expectedBytes = cleanupMarkerBytes(
        cleanupMarkerInput(entry, cleanup),
    );
    const expectedDigest = cleanupMarkerDigest(
        cleanupMarkerInput(entry, cleanup),
    );
    if (expectedDigest !== cleanup.cleanupMarkerDigest) {
        throw new InvestigationNotResumableError(
            "cleanup marker digest does not match catalog authority",
            { investigationId: entry.investigationId },
        );
    }
    if (pathExists(deps, markerFile)) {
        const markerStat = fs.lstatSync(markerFile);
        if (!markerStat.isFile()
            || markerStat.isSymbolicLink()
            || markerStat.size !== expectedBytes.length) {
            throw new InvestigationNotResumableError(
                "cleanup ownership marker has invalid file identity",
                { investigationId: entry.investigationId },
            );
        }
        const actual = fs.readFileSync(markerFile);
        if (!actual.equals(expectedBytes)) {
            throw new InvestigationNotResumableError(
                "cleanup ownership marker does not match catalog authority",
                { investigationId: entry.investigationId },
            );
        }
        return markerFile;
    }
    let descriptor;
    try {
        descriptor = fs.openSync(markerFile, "wx", 0o600);
        fs.writeFileSync(descriptor, expectedBytes);
        fs.fsyncSync(descriptor);
    } finally {
        if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    fsyncDirectory(root);
    return markerFile;
}

function renameMarkedArchiveForCleanup({
    source,
    destination,
    archiveRoot,
    deps,
}) {
    if (typeof deps.renameMarkedArchiveForCleanup === "function") {
        return deps.renameMarkedArchiveForCleanup({
            source,
            destination,
            archiveRoot,
        });
    }
    if (!sameLocalPath(path.dirname(source), archiveRoot)
        || !sameLocalPath(path.dirname(destination), archiveRoot)
        || sameLocalPath(source, destination)) {
        throw new InvestigationNotResumableError(
            "archive cleanup rename escaped its canonical root",
            { source, destination, archiveRoot },
        );
    }
    const sourceExists = fs.existsSync(source);
    const destinationExists = fs.existsSync(destination);
    if (sourceExists && destinationExists) {
        throw new InvestigationNotResumableError(
            "archive and cleanup paths both exist",
            { source, destination },
        );
    }
    if (!sourceExists) {
        return Object.freeze({
            moved: false,
            destinationExists,
        });
    }
    const sourceStat = fs.lstatSync(source);
    if (sourceStat.isSymbolicLink()
        || !sourceStat.isDirectory()
        || !sameLocalPath(fs.realpathSync.native(source), source)) {
        throw new InvestigationNotResumableError(
            "marked archive source is not a canonical directory",
            { source },
        );
    }
    fs.renameSync(source, destination);
    fsyncDirectory(archiveRoot);
    if (fs.existsSync(source) || !fs.existsSync(destination)) {
        throw new InvestigationNotResumableError(
            "atomic archive cleanup rename could not be confirmed",
            { source, destination },
        );
    }
    return Object.freeze({
        moved: true,
        destinationExists: true,
    });
}

function assertDeleteTombstoneBinding(
    entry,
    tombstone,
    {
        cleanup = null,
        stateRoot,
        retention,
    },
) {
    const authority = deleteAuthority(entry);
    const deletedAtMs = Date.parse(tombstone?.payload?.deletedAt ?? "");
    const relativePath = retentionRelativePath(
        stateRoot,
        tombstone?.file ?? retention.tombstonePath,
    );
    if (tombstone?.verified !== true
        || tombstone.payload?.investigationId !== entry.investigationId
        || tombstone.payload?.createdAtMs !== entry.registeredAtMs
        || tombstone.payload?.archiveDigest !== authority.archiveDigest
        || tombstone.payload?.domainVersion !== authority.domainVersion
        || tombstone.payload?.domainHead?.seq
            !== authority.domainHead.seq
        || tombstone.payload?.domainHead?.eventHash
            !== authority.domainHead.eventHash
        || !Number.isSafeInteger(deletedAtMs)
        || deletedAtMs < entry.registeredAtMs
        || (cleanup !== null
            && (relativePath !== cleanup.tombstoneRelativePath
                || tombstone.digest !== cleanup.tombstoneDigest
                || tombstone.signingKeyFingerprint
                    !== cleanup.signingKeyFingerprint
                || tombstone.signature !== cleanup.signature
                || tombstone.sizeBytes !== cleanup.tombstoneSizeBytes
                || deletedAtMs !== cleanup.deletedAtMs))) {
        throw new InvestigationNotResumableError(
            "signed tombstone does not match persisted delete authority",
            { investigationId: entry.investigationId },
        );
    }
    return deletedAtMs;
}

function ensureDeleteCleanupTombstone({
    entry,
    cleanup,
    stateRoot,
    retention,
    deps,
}) {
    const authority = deleteAuthority(entry);
    const file = resolveCatalogRetentionPath(
        stateRoot,
        cleanup.tombstoneRelativePath,
        { kind: "tombstone", env: deps.env },
    );
    const tombstone = pathExists(deps, file)
        ? (deps.verifySignedTombstone ?? verifySignedTombstone)({
            file,
            keyRoot: retention.tombstoneKeyRoot,
            expectedDigest: cleanup.tombstoneDigest,
            expectedInvestigationId: entry.investigationId,
            env: deps.env,
        })
        : (deps.writeSignedTombstone ?? writeSignedTombstone)({
            file,
            keyRoot: retention.tombstoneKeyRoot,
            env: deps.env,
            payload: {
                investigationId: entry.investigationId,
                createdAtMs: entry.registeredAtMs,
                deletedAt: new Date(cleanup.deletedAtMs).toISOString(),
                domainVersion: authority.domainVersion,
                archiveDigest: authority.archiveDigest,
                domainHead: authority.domainHead,
            },
        });
    assertDeleteTombstoneBinding(entry, tombstone, {
        cleanup,
        stateRoot,
        retention,
    });
    return tombstone;
}

function cleanupCommitOptions({
    entry,
    cleanup,
    operationToken,
    ...changes
}) {
    return {
        investigationId: entry.investigationId,
        operationToken,
        expectedArchiveDigest: cleanup.archiveDigest,
        cleanupRelativePath: cleanup.cleanupRelativePath,
        cleanupMarkerNonce: cleanup.cleanupMarkerNonce,
        cleanupMarkerDigest: cleanup.cleanupMarkerDigest,
        tombstoneRelativePath: cleanup.tombstoneRelativePath,
        tombstoneDigest: cleanup.tombstoneDigest,
        signingKeyFingerprint: cleanup.signingKeyFingerprint,
        signature: cleanup.signature,
        tombstoneSizeBytes: cleanup.tombstoneSizeBytes,
        deletedAtMs: cleanup.deletedAtMs,
        sourceAuthority: cleanup.sourceAuthority,
        archiveAbsent: cleanup.archiveAbsent,
        ...changes,
    };
}

function completedDeleteResponse(
    entry,
    expectedArchiveDigest,
    stateRoot,
    deps,
) {
    if (entry.tombstone?.archiveDigest !== expectedArchiveDigest) {
        throw new InvestigationNotResumableError(
            "expected archive digest does not match committed tombstone",
            { investigationId: entry.investigationId },
        );
    }
    verifyCatalogTombstone(entry, stateRoot, deps);
    return {
        is_result: false,
        investigation_id: entry.investigationId,
        lifecycle_state: "tombstoned",
        deleted: true,
        archive_removed: entry.deleteCleanup === null,
        tombstone_digest: entry.tombstone.digest,
        integrity_status: "verified",
        terminal_available: false,
    };
}

function discoverLegacyArchive({
    broker,
    snapshot,
    entry,
    stateRoot,
    retention,
    deps,
    attempt = 0,
}) {
    const cleanup = entry.deleteCleanup;
    if (cleanup?.sourceAuthority !== "legacy_discovery") {
        return entry;
    }
    const cleanupDir = resolveCatalogRetentionPath(
        stateRoot,
        cleanup.cleanupRelativePath,
        { kind: "archive", env: deps.env },
    );
    if (pathExists(deps, cleanupDir)) {
        throw new InvestigationNotResumableError(
            "legacy cleanup target exists before archive discovery",
            { investigationId: entry.investigationId },
        );
    }
    const owned = new Set();
    for (const candidate of snapshot) {
        if (candidate.archive?.relativePath) {
            owned.add(candidate.archive.relativePath);
        }
        if (candidate.lifecycleOperation?.operationKind === "archive"
            && candidate.lifecycleOperation.archiveRelativePath) {
            owned.add(
                candidate.lifecycleOperation.archiveRelativePath,
            );
        }
        if (candidate.deleteCleanup?.archiveRelativePath) {
            owned.add(
                candidate.deleteCleanup.archiveRelativePath,
            );
        }
        if (candidate.deleteCleanup?.cleanupRelativePath) {
            owned.add(
                candidate.deleteCleanup.cleanupRelativePath,
            );
        }
    }
    const unowned = safeDirectoryEntries(
        retention.archiveRoot,
        "Crucible archive root",
    ).filter((child) =>
        !owned.has(retentionRelativePath(stateRoot, child.path)));
    const matches = [];
    const rejected = [];
    for (const child of unowned) {
        if (!child.directory) {
            rejected.push(child.path);
            continue;
        }
        try {
            const verified = (deps.verifyBundleInPlace
                ?? verifyBundleInPlace)({
                bundleDir: child.path,
                expectedDigest: cleanup.archiveDigest,
                expectedInvestigationId: entry.investigationId,
                requiredDomainVersion: DOMAIN_VERSION,
            });
            if (verified.digest !== cleanup.archiveDigest
                || verified.investigationId !== entry.investigationId
                || verified.verified !== true
                || verified.authenticated !== true) {
                rejected.push(child.path);
            } else {
                matches.push(child);
            }
        } catch {
            rejected.push(child.path);
        }
    }
    const generation = snapshotGeneration(snapshot);
    const confirmation = broker.listInvestigations({ limit: 1 });
    const confirmedGeneration = snapshotGeneration(confirmation);
    if (generation !== null && confirmedGeneration !== generation) {
        if (attempt >= 3) {
            throw new InvestigationNotResumableError(
                "catalog changed during legacy archive discovery",
                { investigationId: entry.investigationId },
            );
        }
        const refreshed = broker.listInvestigations({ limit: null });
        const refreshedEntry = refreshed.find((candidate) =>
            candidate.investigationId === entry.investigationId);
        if (refreshedEntry === undefined) {
            throw new InvestigationNotResumableError(
                "legacy cleanup authority disappeared during discovery",
                { investigationId: entry.investigationId },
            );
        }
        return discoverLegacyArchive({
            broker,
            snapshot: refreshed,
            entry: refreshedEntry,
            stateRoot,
            retention,
            deps,
            attempt: attempt + 1,
        });
    }
    if (matches.length > 1
        || rejected.length !== 0
        || (matches.length === 0 && unowned.length !== 0)) {
        throw new InvestigationNotResumableError(
            "legacy archive discovery is ambiguous",
            {
                investigationId: entry.investigationId,
                matches: matches.map((candidate) => candidate.path),
                rejected,
            },
        );
    }
    if (matches.length === 0) {
        return broker.commitDelete(cleanupCommitOptions({
            entry,
            cleanup,
            operationToken: null,
            archiveAbsent: true,
        })).investigation;
    }
    const archiveRelativePath = retentionRelativePath(
        stateRoot,
        matches[0].path,
    );
    const markerDigest = cleanupMarkerDigest({
        investigationId: entry.investigationId,
        archiveRelativePath,
        cleanupRelativePath: cleanup.cleanupRelativePath,
        archiveDigest: cleanup.archiveDigest,
        nonce: cleanup.cleanupMarkerNonce,
    });
    return broker.commitDelete(cleanupCommitOptions({
        entry,
        cleanup,
        operationToken: null,
        discoveredArchiveRelativePath: archiveRelativePath,
        cleanupMarkerDigest: markerDigest,
    })).investigation;
}

function retentionRelativePath(stateRoot, target) {
    const relative = path.relative(stateRoot, target)
        .split(path.sep)
        .join("/");
    return process.platform === "win32"
        ? relative.toLowerCase()
        : relative;
}

function deleteCleanupRelativePath(investigationId, archiveDigest) {
    const digest = createHash("sha256")
        .update("crucible-delete-cleanup-v2\0")
        .update(investigationId)
        .update("\0")
        .update(archiveDigest)
        .digest("hex");
    return `.retention/archives/cleanup-${digest}`;
}

function cleanupMarkerDocument({
    investigationId,
    archiveRelativePath,
    cleanupRelativePath,
    archiveDigest,
    nonce,
}) {
    return {
        type: "crucible-delete-cleanup-marker",
        version: 1,
        investigationId,
        archiveRelativePath,
        cleanupRelativePath,
        archiveDigest,
        nonce,
    };
}

function cleanupMarkerBytes(input) {
    return Buffer.from(
        `${canonicalize(cleanupMarkerDocument(input))}\n`,
        "utf8",
    );
}

function cleanupMarkerDigest(input) {
    return `sha256:${createHash("sha256")
        .update(cleanupMarkerBytes(input))
        .digest("hex")}`;
}

function sameLocalPath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function safeDirectoryEntries(root, label) {
    if (!fs.existsSync(root)) return [];
    const stat = fs.lstatSync(root);
    const real = fs.realpathSync.native(root);
    if (stat.isSymbolicLink()
        || !stat.isDirectory()
        || !sameLocalPath(real, root)) {
        throw new InvestigationNotResumableError(
            `${label} is not a safe canonical directory`,
            { path: root },
        );
    }
    return fs.readdirSync(root).map((name) => {
        const child = path.join(root, name);
        const childStat = fs.lstatSync(child);
        if (childStat.isSymbolicLink()) {
            throw new InvestigationNotResumableError(
                `${label} contains a link or reparse point`,
                { path: child },
            );
        }
        if (childStat.isDirectory()) {
            const childReal = fs.realpathSync.native(child);
            if (!sameLocalPath(childReal, child)
                || !sameLocalPath(path.dirname(childReal), root)) {
                throw new InvestigationNotResumableError(
                    `${label} contains a non-canonical directory`,
                    { path: child },
                );
            }
        }
        return Object.freeze({
            name,
            path: child,
            directory: childStat.isDirectory(),
            file: childStat.isFile(),
        });
    });
}

function assertStateRootTrulyEmpty(stateRoot) {
    if (!fs.existsSync(stateRoot)) return;
    const entries = safeDirectoryEntries(
        stateRoot,
        "Crucible state root",
    );
    if (entries.length !== 0) {
        throw new InvestigationNotResumableError(
            "Crucible state exists without global catalog authority",
            {
                stateRoot,
                retainedEntries: entries.map((entry) => entry.name),
            },
        );
    }
}

function assertCatalogStorageAuthority(stateRoot, entries, deps) {
    const activePaths = new Set();
    const archivePaths = new Set();
    const tombstonePaths = new Set();
    const catalogFiles = new Set([
        "resource-catalog.sqlite",
        "resource-catalog.sqlite-wal",
        "resource-catalog.sqlite-shm",
    ]);
    for (const entry of entries) {
        if (entry.deleteCleanup?.sourceAuthority
            === "legacy_discovery"
            && entry.deleteCleanup.archiveAbsent !== true) {
            throw new InvestigationNotResumableError(
                "legacy archive discovery requires an explicit lifecycle mutation",
                { investigationId: entry.investigationId },
            );
        }
        if (entry.lifecycleState !== "tombstoned") {
            activePaths.add(retentionRelativePath(
                stateRoot,
                resolveInvestigationPaths(
                    stateRoot,
                    entry.investigationId,
                ).investigationDir,
            ));
        }
        if (entry.archive !== null && entry.archive !== undefined) {
            archivePaths.add(entry.archive.relativePath);
        }
        if (entry.lifecycleOperation?.operationKind === "archive"
            && typeof entry.lifecycleOperation.archiveRelativePath
                === "string") {
            archivePaths.add(
                entry.lifecycleOperation.archiveRelativePath,
            );
        }
        if (entry.lifecycleOperation?.operationKind === "delete") {
            tombstonePaths.add(retentionRelativePath(
                stateRoot,
                resolveRetentionPaths(
                    stateRoot,
                    entry.investigationId,
                    { env: deps.env },
                ).tombstonePath,
            ));
        }
        if (entry.deleteCleanup !== null
            && entry.deleteCleanup !== undefined) {
            if (entry.deleteCleanup.archiveRelativePath !== null) {
                archivePaths.add(
                    entry.deleteCleanup.archiveRelativePath,
                );
            }
            archivePaths.add(
                entry.deleteCleanup.cleanupRelativePath,
            );
            tombstonePaths.add(
                entry.deleteCleanup.tombstoneRelativePath,
            );
        }
        if (entry.tombstone !== null
            && entry.tombstone !== undefined) {
            tombstonePaths.add(entry.tombstone.relativePath);
        }
    }
    for (const child of safeDirectoryEntries(
        stateRoot,
        "Crucible state root",
    )) {
        const recognizedInvestigation =
            INVESTIGATION_ID_RE.test(child.name);
        const cataloged = child.directory
            && activePaths.has(retentionRelativePath(
                stateRoot,
                child.path,
            ));
        const verifiedLegacy = recognizedInvestigation
            && child.directory
            && !cataloged
            && isUncatalogedLegacyInvestigation(
                deps,
                child.name,
                resolveInvestigationPaths(stateRoot, child.name),
            );
        if (!catalogFiles.has(child.name)
            && recognizedInvestigation
            && (!child.directory || (!cataloged && !verifiedLegacy))) {
            throw new InvestigationNotResumableError(
                "active Crucible state has no catalog authority",
                { path: child.path },
            );
        }
    }
    const retention = resolveRetentionPaths(
        stateRoot,
        "catalog-authority-probe",
        { env: deps.env },
    );
    for (const child of safeDirectoryEntries(
        retention.archiveRoot,
        "Crucible archive root",
    )) {
        const relative = retentionRelativePath(
            stateRoot,
            child.path,
        );
        if (!child.directory || !archivePaths.has(relative)) {
            throw new InvestigationNotResumableError(
                "retained Crucible archive has no catalog authority",
                { path: child.path },
            );
        }
    }
    for (const child of safeDirectoryEntries(
        retention.tombstoneRoot,
        "Crucible tombstone root",
    )) {
        const relative = retentionRelativePath(
            stateRoot,
            child.path,
        );
        if (!child.file || !tombstonePaths.has(relative)) {
            throw new InvestigationNotResumableError(
                "retained Crucible tombstone has no catalog authority",
                { path: child.path },
            );
        }
    }
}

function snapshotGeneration(snapshot) {
    const direct = snapshot?.catalogGeneration;
    if (Number.isSafeInteger(direct)) return direct;
    const entry = snapshot?.[0]?.catalogGeneration;
    return Number.isSafeInteger(entry) ? entry : null;
}

function readStableCatalogSnapshot(broker, stateRoot, deps) {
    let lastError = null;
    for (let attempt = 0; attempt < 4; attempt += 1) {
        const snapshot = broker.listInvestigations({ limit: null });
        const generation = snapshotGeneration(snapshot);
        let scanError = null;
        try {
            assertCatalogStorageAuthority(stateRoot, snapshot, deps);
        } catch (error) {
            scanError = error;
        }
        const confirmation = broker.listInvestigations({ limit: 1 });
        const confirmedGeneration = snapshotGeneration(confirmation);
        if (generation !== null
            && confirmedGeneration !== generation) {
            lastError = scanError;
            continue;
        }
        if (scanError === null) {
            return snapshot;
        }
        if (scanError?.code !== "ENOENT"
            || generation === null) {
            throw scanError;
        }
        lastError = scanError;
    }
    throw lastError ?? new InvestigationNotResumableError(
        "lifecycle catalog changed during filesystem authority scan",
    );
}

function standaloneTombstoneTarget(
    deps,
    stateRoot,
    investigationId,
) {
    const retention = resolveRetentionPaths(
        stateRoot,
        investigationId,
        { env: deps.env },
    );
    if (!fs.existsSync(retention.tombstonePath)) return null;
    const verification = (deps.verifySignedTombstone
        ?? verifySignedTombstone)({
        file: retention.tombstonePath,
        keyRoot: retention.tombstoneKeyRoot,
        expectedInvestigationId: investigationId,
        env: deps.env,
    });
    const deletedAtMs = Date.parse(verification.payload.deletedAt);
    const entry = Object.freeze({
        investigationId,
        registeredAtMs: verification.payload.createdAtMs,
        authorityUpdatedAtMs: deletedAtMs,
        lifecycleState: "tombstoned",
        lifecycleUpdatedAtMs: deletedAtMs,
        lifecycleReasonCode: "operator_delete",
        lifecycleOperation: null,
        archive: null,
        tombstone: Object.freeze({
            relativePath: retentionRelativePath(
                stateRoot,
                retention.tombstonePath,
            ),
            digest: verification.digest,
            signingKeyFingerprint:
                verification.signingKeyFingerprint,
            signature: verification.signature,
            archiveDigest:
                verification.payload.archiveDigest,
            domainVersion:
                verification.payload.domainVersion,
            domainHead: verification.payload.domainHead,
            sizeBytes: verification.sizeBytes,
            deletedAtMs,
            integrityStatus: "verified",
        }),
    });
    return Object.freeze({
        stateRoot,
        state: "tombstoned",
        entry,
        verification,
        paths: null,
    });
}

function inject(deps, point, details = {}) {
    deps.lifecycleFaultInjector?.({ point, ...details });
}

function canonicalCursorPayload(lastId, stateFilter) {
    return {
        version: CURSOR_VERSION,
        lastId,
        stateFilter: stateFilter ?? null,
    };
}

function encodeCursor(lastId, stateFilter) {
    return Buffer.from(
        JSON.stringify(canonicalCursorPayload(lastId, stateFilter)),
        "utf8",
    ).toString("base64url");
}

function decodeCursor(cursor, stateFilter) {
    if (cursor === undefined) return null;
    let bytes;
    let payload;
    try {
        bytes = Buffer.from(cursor, "base64url");
        if (bytes.toString("base64url") !== cursor) throw new Error("non-canonical");
        payload = JSON.parse(bytes.toString("utf8"));
    } catch {
        throw new SchemaValidationError(
            "cursor is not a canonical Crucible lifecycle cursor",
        );
    }
    const keys = payload !== null
        && typeof payload === "object"
        && !Array.isArray(payload)
        ? Object.keys(payload).sort()
        : [];
    if (keys.length !== 3
        || keys[0] !== "lastId"
        || keys[1] !== "stateFilter"
        || keys[2] !== "version"
        || payload.version !== CURSOR_VERSION
        || typeof payload.lastId !== "string"
        || !INVESTIGATION_ID_RE.test(payload.lastId)
        || payload.stateFilter !== (stateFilter ?? null)) {
        throw new SchemaValidationError(
            "cursor does not match the requested lifecycle catalog view",
        );
    }
    return payload.lastId;
}

function isoFromMs(value) {
    if (!Number.isSafeInteger(value) || value < 0) return null;
    try {
        return new Date(value).toISOString();
    } catch {
        return null;
    }
}

function publicSummary({
    investigationId,
    state,
    createdAtMs,
    updatedAtMs,
    domainVersion,
    terminalAvailable,
    integrityStatus,
    sizeBytes,
}) {
    return Object.freeze({
        investigation_id: investigationId,
        state,
        created_at: isoFromMs(createdAtMs),
        updated_at: isoFromMs(updatedAtMs),
        domain_version:
            Number.isSafeInteger(domainVersion) ? domainVersion : null,
        terminal_available: terminalAvailable === true,
        integrity_status: integrityStatus,
        size_bytes: Number.isSafeInteger(sizeBytes) && sizeBytes >= 0
            ? sizeBytes
            : null,
    });
}

function assertTombstoneCatalogBinding(entry, verified) {
    const tombstone = entry.tombstone;
    if (verified.digest !== tombstone.digest
        || verified.sizeBytes !== tombstone.sizeBytes
        || verified.signingKeyFingerprint
            !== tombstone.signingKeyFingerprint
        || verified.signature !== tombstone.signature
        || verified.payload.createdAtMs !== entry.registeredAtMs
        || verified.payload.archiveDigest !== tombstone.archiveDigest
        || verified.payload.domainVersion !== tombstone.domainVersion
        || verified.payload.domainHead?.seq
            !== tombstone.domainHead.seq
        || verified.payload.domainHead?.eventHash
            !== tombstone.domainHead.eventHash
        || Date.parse(verified.payload.deletedAt)
            !== tombstone.deletedAtMs) {
        throw new Error(
            "signed tombstone does not match its catalog binding",
        );
    }
}

function assertArchiveCatalogBinding(entry, verified) {
    const archive = entry.archive;
    if (archive.integrityStatus !== "verified"
        || verified.digest !== archive.digest
        || verified.investigationId !== entry.investigationId
        || verified.domainVersion !== archive.domainVersion
        || verified.domainHead?.seq !== archive.domainHead.seq
        || verified.domainHead?.eventHash
            !== archive.domainHead.eventHash) {
        throw new Error(
            "verified archive does not match its catalog binding",
        );
    }
}

function verifyCatalogTombstone(entry, stateRoot, deps) {
    if (entry.tombstone === null || entry.tombstone === undefined) {
        throw new Error(
            "tombstoned catalog entry has no durable tombstone record",
        );
    }
    const file = resolveCatalogRetentionPath(
        stateRoot,
        entry.tombstone.relativePath,
        { kind: "tombstone", env: deps.env },
    );
    const retention = resolveRetentionPaths(
        stateRoot,
        entry.investigationId,
        { env: deps.env },
    );
    const verified = (deps.verifySignedTombstone
        ?? verifySignedTombstone)({
        file,
        keyRoot: retention.tombstoneKeyRoot,
        expectedDigest: entry.tombstone.digest,
        expectedInvestigationId: entry.investigationId,
        env: deps.env,
    });
    assertTombstoneCatalogBinding(entry, verified);
    return verified;
}

function verifyArchivedImmutableRead(entry, bundleDir, deps) {
    const repository = (deps.openRepositoryReadOnly
        ?? openRepositoryReadOnly)({
        file: path.join(bundleDir, "db", "database.sqlite"),
        env: deps.env,
        immutable: true,
    });
    let artifactStore = null;
    try {
        if (repository.readOnly !== true) {
            throw new Error(
                "archived catalog read did not open an immutable read-only repository",
            );
        }
        artifactStore = (deps.openArtifactStoreReadOnly
            ?? openArtifactStoreReadOnly)({
            root: bundleDir,
            env: deps.env,
        });
        if (artifactStore.readOnly !== true) {
            throw new Error(
                "archived catalog read did not open a read-only artifact store",
            );
        }
        const adapter = (deps.createDomainRepositoryAdapter
            ?? createDomainRepositoryAdapter)({
            repository,
            artifactStore,
            investigationId: entry.investigationId,
            ensure: false,
        });
        let replay = adapter.replay();
        const authority = replay.aggregate.experimentAuthority;
        const payload = authority?.manifest?.experimentPayload;
        if (authority === null
            || authority === undefined
            || replay.aggregate.experimentAuthorityIdentity === null
            || replay.aggregate.experimentAuthorityIdentity === undefined
            || authority.identity
                !== replay.aggregate.experimentAuthorityIdentity) {
            throw new Error(
                "archived investigation has no current signed experiment authority",
            );
        }
        (deps.verifyExperimentAuthority ?? verifyExperimentAuthority)({
            authority,
            experimentId: payload?.experimentId,
            projectDir: payload?.projectDir,
            harnessSuiteId: payload?.harnessSuiteId,
            contract: replay.aggregate.contract,
            investigationId: entry.investigationId,
            env: deps.env,
        });
        if (replay.aggregate.terminal !== null
            && replay.aggregate.terminal !== undefined) {
            replay = adapter.verifyTerminalArtifactClosure({
                artifactStore,
            });
        }
        const head = typeof repository.getHead === "function"
            ? repository.getHead(entry.investigationId)
            : {
                seq: replay.aggregate.lastSeq,
                eventHash: replay.aggregate.lastEventHash,
            };
        if (head?.seq !== entry.archive.domainHead.seq
            || head?.eventHash !== entry.archive.domainHead.eventHash) {
            throw new Error(
                "archived immutable read head differs from catalog binding",
            );
        }
        const readiness = replay.aggregate.terminal === null
            || replay.aggregate.terminal === undefined
            ? { ready: false }
            : (deps.assessPersistedTerminalReadiness
                ?? assessPersistedTerminalReadiness)(replay.aggregate);
        return Object.freeze({
            terminalAvailable: readiness.ready === true,
        });
    } finally {
        safeClose(repository);
        safeClose(artifactStore);
    }
}

function tombstoneSummary(entry, stateRoot, deps) {
    try {
        const verified = verifyCatalogTombstone(entry, stateRoot, deps);
        return publicSummary({
            investigationId: entry.investigationId,
            state: "tombstoned",
            createdAtMs: entry.registeredAtMs,
            updatedAtMs: entry.lifecycleUpdatedAtMs,
            domainVersion: entry.tombstone.domainVersion,
            terminalAvailable: false,
            integrityStatus: verified.verified ? "verified" : "blocked",
            sizeBytes: entry.tombstone.sizeBytes,
        });
    } catch {
        return publicSummary({
            investigationId: entry.investigationId,
            state: "tombstoned",
            createdAtMs: entry.registeredAtMs,
            updatedAtMs: entry.lifecycleUpdatedAtMs,
            domainVersion: entry.tombstone?.domainVersion ?? null,
            terminalAvailable: false,
            integrityStatus: "blocked",
            sizeBytes: entry.tombstone?.sizeBytes ?? null,
        });
    }
}

function archiveSummary(entry, stateRoot, deps) {
    try {
        if (entry.archive === null
            || entry.archive === undefined
            || (entry.deleteCleanup !== null
                && entry.deleteCleanup !== undefined)
            || entry.lifecycleOperation?.operationKind === "delete") {
            throw new Error(
                "archived catalog authority is incomplete or cleanup-pending",
            );
        }
        const bundleDir = resolveCatalogRetentionPath(
            stateRoot,
            entry.archive.relativePath,
            { kind: "archive", env: deps.env },
        );
        const verified = (deps.verifyBundleInPlace
            ?? verifyBundleInPlace)({
            bundleDir,
            expectedDigest: entry.archive.digest,
            expectedInvestigationId: entry.investigationId,
            requiredDomainVersion: DOMAIN_VERSION,
        });
        assertArchiveCatalogBinding(entry, verified);
        if (verified.verified !== true
            || verified.authenticated !== true) {
            throw new Error(
                "archived bundle lacks authenticated immutable authority",
            );
        }
        const measured = (deps.measureRetainedTree
            ?? measureRetainedTree)(bundleDir, { env: deps.env });
        if (measured.sizeBytes !== entry.archive.sizeBytes) {
            throw new Error("archive size differs from the catalog");
        }
        const immutableRead = verifyArchivedImmutableRead(
            entry,
            bundleDir,
            deps,
        );
        return publicSummary({
            investigationId: entry.investigationId,
            state: "archived",
            createdAtMs: entry.registeredAtMs,
            updatedAtMs: entry.lifecycleUpdatedAtMs,
            domainVersion: verified.domainVersion,
            terminalAvailable: immutableRead.terminalAvailable,
            integrityStatus: "verified",
            sizeBytes: entry.archive.sizeBytes,
        });
    } catch {
        return publicSummary({
            investigationId: entry.investigationId,
            state: "archived",
            createdAtMs: entry.registeredAtMs,
            updatedAtMs: entry.lifecycleUpdatedAtMs,
            domainVersion: entry.archive?.domainVersion ?? null,
            terminalAvailable: false,
            integrityStatus: "blocked",
            sizeBytes: entry.archive?.sizeBytes ?? null,
        });
    }
}

export function resolveLifecycleTarget({
    deps,
    investigationId,
    verifyArchive = true,
} = {}) {
    const stateRoot = resolveStateRoot(deps.env);
    const activePaths = resolveInvestigationPaths(
        stateRoot,
        investigationId,
    );
    const broker = openCatalogForRead(deps, stateRoot);
    if (broker === null) {
        if (standaloneTombstoneTarget(
            deps,
            stateRoot,
            investigationId,
        ) !== null) {
            throw new InvestigationNotResumableError(
                "signed tombstone has no committed catalog binding",
                {
                    investigationId,
                    source: "uncommitted_signed_tombstone",
                },
            );
        }
        if (isUncatalogedLegacyInvestigation(
            deps,
            investigationId,
            activePaths,
        )) {
            return Object.freeze({
                stateRoot,
                state: "active",
                entry: null,
                paths: activePaths,
                verification: null,
            });
        }
        assertStateRootTrulyEmpty(stateRoot);
        return Object.freeze({
            stateRoot,
            state: "active",
            entry: null,
            paths: activePaths,
            verification: null,
        });
    }
    try {
        const entries = readStableCatalogSnapshot(
            broker,
            stateRoot,
            deps,
        );
        const entry = entries.find((candidate) =>
            candidate.investigationId === investigationId) ?? null;
        if (entry === null) {
            if (standaloneTombstoneTarget(
                deps,
                stateRoot,
                investigationId,
            ) !== null) {
                throw new InvestigationNotResumableError(
                    "signed tombstone has no committed catalog binding",
                    {
                        investigationId,
                        source: "uncommitted_signed_tombstone",
                    },
                );
            }
            if ((deps.pathExists ?? fs.existsSync)(activePaths.eventsDbPath)
                && !isUncatalogedLegacyInvestigation(
                    deps,
                    investigationId,
                    activePaths,
                )) {
                throw new InvestigationNotResumableError(
                    "active investigation has no catalog authority",
                    { investigationId, source: "uncataloged_active_state" },
                );
            }
            return Object.freeze({
                stateRoot,
                state: "active",
                entry: null,
                paths: activePaths,
                verification: null,
            });
        }
        if (entry.lifecycleState === "active") {
            return Object.freeze({
                stateRoot,
                state: "active",
                entry,
                paths: activePaths,
                verification: null,
            });
        }
        if (entry.lifecycleState === "archived") {
            if (entry.archive === null) {
                throw new Error(
                    "archived catalog entry has no verified archive record",
                );
            }
            const archiveDir = resolveCatalogRetentionPath(
                stateRoot,
                entry.archive.relativePath,
                { kind: "archive", env: deps.env },
            );
            const verification = verifyArchive
                ? (deps.verifyBundleInPlace ?? verifyBundleInPlace)({
                    bundleDir: archiveDir,
                    expectedDigest: entry.archive.digest,
                    expectedInvestigationId: investigationId,
                    requiredDomainVersion: DOMAIN_VERSION,
                })
                : null;
            if (verification !== null) {
                assertArchiveCatalogBinding(entry, verification);
            }
            return Object.freeze({
                stateRoot,
                state: "archived",
                entry,
                verification,
                paths: Object.freeze({
                    investigationDir: archiveDir,
                    stateDir: path.join(archiveDir, "db"),
                    artifactRoot: archiveDir,
                    eventsDbPath: path.join(
                        archiveDir,
                        "db",
                        "database.sqlite",
                    ),
                }),
            });
        }

        if (entry.lifecycleState === "tombstoned") {
            const verification = verifyCatalogTombstone(
                entry,
                stateRoot,
                deps,
            );
            return Object.freeze({
                stateRoot,
                state: "tombstoned",
                entry,
                verification,
                paths: null,
            });
        }
        throw new Error("catalog lifecycle state is invalid");
    } finally {
        safeClose(broker);
    }
}

export function verifyArchivedTarget(target, deps) {
    if (target?.state !== "archived"
        || target.entry?.archive === null
        || (target.entry?.deleteCleanup !== null
            && target.entry?.deleteCleanup !== undefined)
        || target.entry?.lifecycleOperation?.operationKind === "delete"
        || target.paths === null) {
        throw new TypeError(
            "verifyArchivedTarget requires an archived target without pending delete cleanup",
        );
    }
    const verification = (deps.verifyBundleInPlace
        ?? verifyBundleInPlace)({
        bundleDir: target.paths.investigationDir,
        expectedDigest: target.entry.archive.digest,
        expectedInvestigationId: target.entry.investigationId,
        requiredDomainVersion: DOMAIN_VERSION,
    });
    assertArchiveCatalogBinding(target.entry, verification);
    return verification;
}

export function statusTombstonePayload(target) {
    return {
        is_result: false,
        investigation_id: target.entry.investigationId,
        state: "tombstoned",
        status: "deleted",
        deleted: true,
        integrity_status:
            target.verification?.verified === true
                ? "verified"
                : "blocked",
        terminal_available: false,
        non_result: true,
        non_result_code: "INVESTIGATION_TOMBSTONED",
        paused: false,
        resumable: false,
        note:
            "This deterministic investigation identity was deleted and is durably tombstoned; it cannot be resumed or recreated.",
    };
}

export function resultTombstonePayload(target) {
    return {
        is_result: false,
        investigation_id: target.entry.investigationId,
        state: "tombstoned",
        status: "deleted",
        deleted: true,
        integrity_status:
            target.verification?.verified === true
                ? "verified"
                : "blocked",
        non_result: true,
        non_result_code: "INVESTIGATION_TOMBSTONED",
        reason:
            "The archived investigation was deleted under its exact digest and this identity is permanently tombstoned.",
    };
}

export function listLifecycleInvestigations(
    args,
    deps,
    { probeActive } = {},
) {
    const stateRoot = resolveStateRoot(deps.env);
    const pageLimit = args.limit ?? 50;
    const afterId = decodeCursor(args.cursor, args.state_filter);
    const broker = openCatalogForRead(deps, stateRoot);
    if (broker === null) {
        assertStateRootTrulyEmpty(stateRoot);
        return {
            is_result: false,
            operation: "list",
            investigations: [],
            next_cursor: null,
            has_more: false,
        };
    }
    let page;
    try {
        const snapshot = readStableCatalogSnapshot(
            broker,
            stateRoot,
            deps,
        );
        page = snapshot.filter((entry) =>
            (args.state_filter === undefined
                || entry.lifecycleState === args.state_filter)
            && (afterId === null
                || entry.investigationId > afterId))
            .slice(0, pageLimit + 1);
    } finally {
        safeClose(broker);
    }
    const hasMore = page.length > pageLimit;
    const selected = page.slice(0, pageLimit);
    const summarize = (entry) => {
        if (entry.lifecycleState === "archived") {
            return archiveSummary(entry, stateRoot, deps);
        }
        if (entry.lifecycleState === "tombstoned") {
            return tombstoneSummary(entry, stateRoot, deps);
        }
        if (typeof probeActive !== "function") {
            return publicSummary({
                investigationId: entry.investigationId,
                state: "active",
                createdAtMs: entry.registeredAtMs,
                updatedAtMs: Math.max(
                    entry.lifecycleUpdatedAtMs ?? 0,
                    entry.authorityUpdatedAtMs ?? 0,
                ),
                domainVersion: DOMAIN_VERSION,
                terminalAvailable: false,
                integrityStatus: "unknown",
                sizeBytes: null,
            });
        }
        return probeActive(entry, stateRoot);
    };
    const summaries = selected.map(summarize);
    const finish = (investigations) => ({
        is_result: false,
        operation: "list",
        investigations,
        next_cursor: hasMore
            ? encodeCursor(
                selected.at(-1).investigationId,
                args.state_filter,
            )
            : null,
        has_more: hasMore,
    });
    return summaries.some((summary) =>
        summary !== null
        && (typeof summary === "object" || typeof summary === "function")
        && typeof summary.then === "function")
        ? Promise.all(summaries).then(finish)
        : finish(summaries);
}

function archiveEligibility(read) {
    const { aggregate, operationalNonResult, quiescentStop } = read;
    if (aggregate.terminal !== null) return "terminal";
    if (aggregate.nonResults.length > 0) return "domain_non_result";
    if (aggregate.pause !== null
        && quiescentStop?.state === "PAUSED_QUIESCENT"
        && quiescentStop.quiescent === true) {
        return "paused_quiescent";
    }
    if (operationalNonResult !== null) return null;
    return null;
}

function verifiedProofFromStop(stop) {
    const proof = stop?.details?.proof ?? null;
    return proof?.verified === true
        && proof?.quiescent === true
        && Array.isArray(proof.missingVerifications)
        && proof.missingVerifications.length === 0
        && proof.supervisorStatus?.verified === true
        && proof.processes?.verified === true
        && Array.isArray(proof.processes.activePids)
        && proof.processes.activePids.length === 0
        && proof.sdkSessions?.verified === true
        && proof.sdkSessions.activeCount === 0
        && proof.runnerChild?.verified === true
        && proof.runnerChild.active === false
        && proof.resourceBroker?.verified === true
        && proof.resourceBroker.authorityRetired === true
        && Array.isArray(proof.resourceBroker.activeLeases)
        && proof.resourceBroker.activeLeases.length === 0
        && proof.activeRunnerLease === null
        && Array.isArray(proof.committableAttempts)
        && proof.committableAttempts.length === 0
        && Array.isArray(proof.activePids)
        && proof.activePids.length === 0
        && proof.activeSdkSessions === 0
        && Array.isArray(proof.activeResourceLeases)
        && proof.activeResourceLeases.length === 0;
}

function assertArchiveQuiescent(read, broker, investigationId) {
    const stop = read.quiescentStop;
    const pausedQuiescent = stop?.state === "PAUSED_QUIESCENT"
        && stop.quiescent === true
        && verifiedProofFromStop(stop);
    const terminalOrNonResultQuiescent =
        stop?.state === "STOP_SUPERSEDED"
        && verifiedProofFromStop(stop);
    if (!pausedQuiescent && !terminalOrNonResultQuiescent) {
        throw new InvestigationNotResumableError(
            "archive requires a durable zero-active-resource quiescence proof",
            {
                investigationId,
                stopState: stop?.state ?? null,
            },
        );
    }
    const activeLeases = broker.listActiveLeases({ investigationId });
    if (activeLeases.length !== 0) {
        throw new InvestigationNotResumableError(
            "archive requires zero active global resource leases",
            { investigationId, activeLeaseCount: activeLeases.length },
        );
    }
}

function assertNoActiveResources(
    deps,
    broker,
    investigationId,
    activePaths,
) {
    const activeLeases = broker.listActiveLeases({ investigationId });
    if (activeLeases.length !== 0) {
        throw new InvestigationNotResumableError(
            "delete requires zero active global resource leases",
            { investigationId, activeLeaseCount: activeLeases.length },
        );
    }
    if (!pathExists(deps, activePaths.investigationDir)) return;
    if (typeof deps.verifyNoActiveResources === "function") {
        const verified = deps.verifyNoActiveResources({
            investigationId,
            paths: activePaths,
            broker,
        });
        if (verified?.verified !== true
            || verified?.quiescent !== true) {
            throw new InvestigationNotResumableError(
                "delete could not prove zero active resources",
                { investigationId },
            );
        }
        return;
    }
    let status = null;
    let lock = null;
    try {
        status = deps.readStatus?.({
            stateDir: activePaths.stateDir,
            investigationId,
        }) ?? null;
    } catch {
        status = null;
    }
    try {
        lock = deps.readSupervisorLock?.(
            supervisorPaths(
                activePaths.stateDir,
                investigationId,
            ).lockPath,
        ) ?? null;
    } catch {
        lock = null;
    }
    const isPidAlive = deps.isPidAlive ?? (() => false);
    for (const pid of [status?.pid, status?.childPid, lock?.pid]) {
        if (Number.isSafeInteger(pid)
            && pid > 0
            && isPidAlive(pid)) {
            throw new InvestigationNotResumableError(
                "delete refused because an active lifecycle process remains",
                { investigationId, pid },
            );
        }
    }
    if (pathExists(deps, activePaths.eventsDbPath)
        && typeof deps.openRepositoryReadOnly === "function") {
        const repository = deps.openRepositoryReadOnly({
            file: activePaths.eventsDbPath,
            env: deps.env,
        });
        try {
            const activeLease =
                typeof repository.getActiveLease === "function"
                    ? repository.getActiveLease(investigationId)
                    : null;
            const committable =
                typeof repository.listCommittableAttempts === "function"
                    ? repository.listCommittableAttempts(
                        investigationId,
                    )
                    : [];
            if (activeLease !== null || committable.length !== 0) {
                throw new InvestigationNotResumableError(
                    "delete refused because active repository resources remain",
                    {
                        investigationId,
                        activeRunnerLease: activeLease !== null,
                        committableAttemptCount: committable.length,
                    },
                );
            }
        } finally {
            repository.close();
        }
    }
}

function cleanupUnpublishedArchive({
    deps,
    paths,
    archiveDigest,
    finalPublished,
    rawExported,
}) {
    if (finalPublished && pathExists(deps, paths.archiveDir)) {
        try {
            (deps.removeVerifiedBundle ?? removeVerifiedBundle)({
                bundleDir: paths.archiveDir,
                expectedDigest: archiveDigest,
                expectedInvestigationId:
                    path.basename(paths.investigationDir),
                requiredDomainVersion: DOMAIN_VERSION,
            });
        } catch {
            (deps.removeRetainedTree ?? removeRetainedTree)({
                target: paths.archiveDir,
                containmentRoot: paths.archiveRoot,
                env: deps.env,
            });
        }
    }
    if (rawExported !== null && pathExists(deps, rawExported)) {
        (deps.removeRetainedTree ?? removeRetainedTree)({
            target: rawExported,
            containmentRoot: paths.stagingRoot,
            env: deps.env,
        });
    }
}

function cleanupStaleArchiveStaging(
    deps,
    paths,
    investigationId,
    operationToken,
) {
    if (!pathExists(deps, paths.stagingRoot)) return;
    const expected = `${investigationId}.${operationToken}.export`;
    for (const name of fs.readdirSync(paths.stagingRoot)) {
        if (name !== expected) continue;
        (deps.removeRetainedTree ?? removeRetainedTree)({
            target: path.join(paths.stagingRoot, name),
            containmentRoot: paths.stagingRoot,
            env: deps.env,
        });
    }
}

export async function archiveInvestigation(
    args,
    deps,
    { readActive } = {},
) {
    if (typeof readActive !== "function") {
        throw new TypeError("archive lifecycle requires readActive");
    }
    const investigationId = args.investigation_id;
    const stateRoot = resolveStateRoot(deps.env);
    const paths = resolveRetentionPaths(stateRoot, investigationId, {
        authenticatedBundleDestination:
            args.authenticated_bundle_destination ?? null,
        env: deps.env,
    });
    const trustPolicy = resolveArchiveTrustPolicy(deps.env);
    if (args.authenticated_bundle_destination !== undefined
        && trustPolicy !== "authenticated") {
        throw new TypeError(
            "authenticated_bundle_destination requires authenticated archive trust policy",
        );
    }
    const broker = openCatalogForMutation(deps, stateRoot);
    if (broker === null) {
        throw new InvestigationNotFoundError(
            "investigation is absent from the global lifecycle catalog",
            { investigationId },
        );
    }
    const operationToken = `archive-${randomUUID()}`;
    let operationBegun = false;
    let catalogCommitted = false;
    let rawExported = null;
    let finalPublished = false;
    let exportedDigest = null;
    try {
        const snapshot = readStableCatalogSnapshot(
            broker,
            stateRoot,
            deps,
        );
        let catalogEntry = snapshot.find((entry) =>
            entry.investigationId === investigationId) ?? null;
        if (catalogEntry === null) {
            throw new InvestigationNotFoundError(
                "no Crucible investigation with this id",
                { investigationId },
            );
        }
        const recoveredFence = reclaimStaleLifecycleFence(
            broker,
            catalogEntry,
            deps,
            "archive",
        );
        catalogEntry = recoveredFence.entry;
        if (catalogEntry.lifecycleState === "archived"
            && catalogEntry.archive !== null) {
            if (args.authenticated_bundle_destination !== undefined
                && catalogEntry.archive.relativePath
                    !== paths.relativeArchivePath) {
                throw new InvestigationNotResumableError(
                    "archived investigation is already bound to a different retention destination",
                    { investigationId },
                );
            }
            const catalogArchiveDir = resolveCatalogRetentionPath(
                stateRoot,
                catalogEntry.archive.relativePath,
                { kind: "archive", env: deps.env },
            );
            const verification = (deps.verifyBundleInPlace
                ?? verifyBundleInPlace)({
                bundleDir: catalogArchiveDir,
                expectedDigest: catalogEntry.archive.digest,
                expectedInvestigationId: investigationId,
                requiredDomainVersion: DOMAIN_VERSION,
            });
            assertArchiveCatalogBinding(
                catalogEntry,
                verification,
            );
            const measured = (deps.measureRetainedTree
                ?? measureRetainedTree)(
                catalogArchiveDir,
                { env: deps.env },
            );
            if (measured.sizeBytes
                !== catalogEntry.archive.sizeBytes) {
                throw new Error(
                    "archive size differs from the catalog",
                );
            }
            if (pathExists(deps, paths.investigationDir)) {
                assertNoActiveResources(
                    deps,
                    broker,
                    investigationId,
                    paths,
                );
                (deps.removeRetainedTree ?? removeRetainedTree)({
                    target: paths.investigationDir,
                    containmentRoot: stateRoot,
                    env: deps.env,
                });
            }
            return {
                is_result: false,
                investigation_id: investigationId,
                lifecycle_state: "archived",
                archived: true,
                idempotent: true,
                archive_digest: verification.digest,
                archive_trust_level:
                    catalogEntry.archive.trustLevel,
                size_bytes: catalogEntry.archive.sizeBytes,
                active_cleanup_complete:
                    !pathExists(deps, paths.investigationDir),
            };
        }
        if (catalogEntry.lifecycleState !== "active") {
            throw new InvestigationNotResumableError(
                "only an active investigation can be archived",
                {
                    investigationId,
                    lifecycleState: catalogEntry.lifecycleState,
                },
            );
        }
        const destinationOwner = broker.listInvestigations({
            lifecycleState: "archived",
        }).find((entry) =>
            entry.investigationId !== investigationId
            && entry.archive?.relativePath
                === paths.relativeArchivePath);
        if (destinationOwner !== undefined) {
            throw new InvestigationNotResumableError(
                "archive destination is already owned by another catalog investigation",
                {
                    investigationId,
                    destinationInvestigationId:
                        destinationOwner.investigationId,
                },
            );
        }
        let read = await readActive(investigationId, paths);
        const eligibility = archiveEligibility(read);
        if (!ARCHIVE_ELIGIBILITY_STATES.includes(eligibility)) {
            throw new InvestigationNotResumableError(
                "archive requires a terminal, domain non-result, or PAUSED_QUIESCENT investigation",
                {
                    investigationId,
                    status: read.aggregate.status,
                },
            );
        }
        if (args.expected_head !== undefined
            && read.aggregate.lastEventHash !== args.expected_head
            && read.repositoryHead?.eventHash !== args.expected_head) {
            throw new InvestigationNotResumableError(
                "investigation head changed before archive",
                {
                    investigationId,
                    expectedHead: args.expected_head,
                    actualHead: read.aggregate.lastEventHash,
                },
            );
        }
        if (!(
            (read.quiescentStop?.state === "PAUSED_QUIESCENT"
                && read.quiescentStop.quiescent === true
                && verifiedProofFromStop(read.quiescentStop))
            || (read.quiescentStop?.state === "STOP_SUPERSEDED"
                && verifiedProofFromStop(read.quiescentStop))
        )) {
            const stop = await Promise.resolve(deps.requestStop({
                stateDir: paths.stateDir,
                artifactRoot: paths.artifactRoot,
                investigationId,
                reason: "Archive requested via crucible_stop.",
                pauseRequested: false,
                forceQuiescence: true,
            }));
            if (stop?.stop?.requestId
                && typeof deps.waitForStopAcknowledgement === "function"
                && !["PAUSED_QUIESCENT", "STOP_SUPERSEDED"].includes(
                    stop.stop.state,
                )) {
                await deps.waitForStopAcknowledgement({
                    stateDir: paths.stateDir,
                    investigationId,
                    requestId: stop.stop.requestId,
                });
            }
            read = await readActive(investigationId, paths);
        }
        assertArchiveQuiescent(read, broker, investigationId);
        inject(deps, "after-quiescence", { investigationId });
        const owner = lifecycleOwner(deps);
        broker.beginLifecycleOperation({
            investigationId,
            operationKind: "archive",
            operationToken,
            ownerProcessId: owner.processId,
            ownerProcessStartId: owner.processStartId,
            archiveRelativePath: paths.relativeArchivePath,
        });
        operationBegun = true;
        inject(deps, "after-catalog-fence", { investigationId });
        if (recoveredFence.reclaimedOperation !== null) {
            cleanupStaleArchiveStaging(
                deps,
                paths,
                investigationId,
                recoveredFence.reclaimedOperation.operationToken,
            );
        }
        rawExported = path.join(
            paths.stagingRoot,
            `${investigationId}.${operationToken}.export`,
        );
        const store = deps.openArtifactStoreReadOnly({
            root: paths.artifactRoot,
            env: deps.env,
        });
        const exported = (deps.exportBundle ?? exportBundle)({
            store,
            dbFile: paths.eventsDbPath,
            destDir: rawExported,
            investigationId,
            now: () => new Date(
                Number.isFinite(read.updatedAtMs)
                    ? read.updatedAtMs
                    : catalogEntry.lifecycleUpdatedAtMs
                        ?? catalogEntry.registeredAtMs,
            ).toISOString(),
            metadata: {
                lifecycle: "archive",
                archiveEligibility: eligibility,
            },
        });
        exportedDigest = exported.digest;
        inject(deps, "after-export", {
            investigationId,
            digest: exported.digest,
        });
        let imported;
        if (pathExists(deps, paths.archiveDir)) {
            try {
                const existing = (deps.verifyBundleInPlace
                    ?? verifyBundleInPlace)({
                    bundleDir: paths.archiveDir,
                    expectedDigest: exported.digest,
                    expectedInvestigationId: investigationId,
                    requiredDomainVersion: DOMAIN_VERSION,
                });
                imported = {
                    ...existing,
                    trustLevel: trustPolicy,
                };
            } catch {
                (deps.removeRetainedTree ?? removeRetainedTree)({
                    target: paths.archiveDir,
                    containmentRoot: paths.archiveRoot,
                    env: deps.env,
                });
            }
        }
        imported ??= (deps.importBundle ?? importBundle)({
            bundleDir: rawExported,
            destDir: paths.archiveDir,
            ...(trustPolicy === "authenticated"
                ? { expectedDigest: exported.digest }
                : { allowUnauthenticated: true }),
        });
        finalPublished = true;
        if (imported.digest !== exported.digest
            || imported.investigationId !== investigationId
            || imported.domainVersion !== DOMAIN_VERSION
            || imported.domainHead?.seq !== exported.domainHead?.seq
            || imported.domainHead?.eventHash
                !== exported.domainHead?.eventHash) {
            throw new Error(
                "imported archive does not match the exported investigation",
            );
        }
        inject(deps, "after-import", {
            investigationId,
            digest: imported.digest,
        });
        const measured = (deps.measureRetainedTree
            ?? measureRetainedTree)(paths.archiveDir, { env: deps.env });
        const readiness = read.aggregate.terminal === null
            ? { ready: false }
            : (deps.assessPersistedTerminalReadiness
                ?? assessPersistedTerminalReadiness)(read.aggregate);
        if (pathExists(deps, rawExported)) {
            (deps.removeRetainedTree ?? removeRetainedTree)({
                target: rawExported,
                containmentRoot: paths.stagingRoot,
                env: deps.env,
            });
            fsyncDirectory(paths.stagingRoot);
            rawExported = null;
            inject(deps, "after-staging-cleanup", { investigationId });
        }
        broker.commitArchive({
            investigationId,
            operationToken,
            archiveRelativePath: paths.relativeArchivePath,
            archiveDigest: imported.digest,
            trustLevel: imported.trustLevel,
            domainVersion: imported.domainVersion,
            terminalAvailable: readiness.ready === true,
            integrityStatus: "verified",
            sizeBytes: measured.sizeBytes,
            domainHead: imported.domainHead,
        });
        catalogCommitted = true;
        operationBegun = false;
        inject(deps, "after-catalog-commit", {
            investigationId,
            digest: imported.digest,
        });
        (deps.removeRetainedTree ?? removeRetainedTree)({
            target: paths.investigationDir,
            containmentRoot: stateRoot,
            env: deps.env,
        });
        inject(deps, "after-active-cleanup", { investigationId });
        return {
            is_result: false,
            investigation_id: investigationId,
            lifecycle_state: "archived",
            archived: true,
            idempotent: false,
            archive_digest: imported.digest,
            archive_trust_level: imported.trustLevel,
            size_bytes: measured.sizeBytes,
        };
    } catch (error) {
        if (!catalogCommitted) {
            try {
                cleanupUnpublishedArchive({
                    deps,
                    paths,
                    archiveDigest: exportedDigest,
                    finalPublished,
                    rawExported,
                });
            } catch (cleanupError) {
                error.cleanupError = cleanupError;
            }
            if (operationBegun) {
                try {
                    broker.abortLifecycleOperation({
                        investigationId,
                        operationToken,
                    });
                } catch (cleanupError) {
                    error.catalogCleanupError = cleanupError;
                }
            }
        } else if (rawExported !== null && pathExists(deps, rawExported)) {
            try {
                (deps.removeRetainedTree ?? removeRetainedTree)({
                    target: rawExported,
                    containmentRoot: paths.stagingRoot,
                    env: deps.env,
                });
            } catch (cleanupError) {
                error.stagingCleanupError = cleanupError;
            }
        }
        throw error;
    } finally {
        safeClose(broker);
    }
}

export function deleteInvestigation(args, deps) {
    const investigationId = args.investigation_id;
    const stateRoot = resolveStateRoot(deps.env);
    const retention = resolveRetentionPaths(
        stateRoot,
        investigationId,
        { env: deps.env },
    );
    const broker = openCatalogForMutation(deps, stateRoot);
    if (broker === null) {
        assertStateRootTrulyEmpty(stateRoot);
        throw new InvestigationNotFoundError(
            "investigation is absent from the global lifecycle catalog",
            { investigationId },
        );
    }
    const operationToken = `delete-${randomUUID()}`;
    let operationBegun = false;
    let cleanupPersisted = false;
    let tombstone = null;
    let archiveDir = null;
    let cleanupDir = null;
    try {
        const rawSnapshot = broker.listInvestigations({ limit: null });
        let entry = rawSnapshot.find((candidate) =>
            candidate.investigationId === investigationId) ?? null;
        if (entry === null) {
            throw new InvestigationNotFoundError(
                "no Crucible investigation with this id",
                { investigationId },
            );
        }
        if (entry.deleteCleanup?.sourceAuthority
            === "legacy_discovery") {
            entry = discoverLegacyArchive({
                broker,
                snapshot: rawSnapshot,
                entry,
                stateRoot,
                retention,
                deps,
            });
        }
        const snapshot = readStableCatalogSnapshot(
            broker,
            stateRoot,
            deps,
        );
        entry = snapshot.find((candidate) =>
            candidate.investigationId === investigationId) ?? entry;
        if (entry.lifecycleState !== "tombstoned") {
            entry = reclaimStaleLifecycleFence(
                broker,
                entry,
                deps,
                "delete",
            ).entry;
        }
        if (!["archived", "tombstoned"].includes(
            entry.lifecycleState,
        )) {
            throw new InvestigationNotResumableError(
                "delete is permitted only for a verified archived investigation",
                {
                    investigationId,
                    lifecycleState: entry.lifecycleState,
                },
            );
        }
        const authority = deleteAuthority(entry);
        if (authority.archiveDigest
            !== args.expected_archive_digest) {
            throw new InvestigationNotResumableError(
                "expected archive digest does not match the catalog",
                {
                    investigationId,
                    expectedArchiveDigest:
                        args.expected_archive_digest,
                    actualArchiveDigest: authority.archiveDigest,
                },
            );
        }
        if (entry.lifecycleState === "tombstoned") {
            verifyCatalogTombstone(entry, stateRoot, deps);
            if (entry.deleteCleanup === null) {
                return completedDeleteResponse(
                    entry,
                    args.expected_archive_digest,
                    stateRoot,
                    deps,
                );
            }
        }
        let cleanup = entry.deleteCleanup ?? null;
        cleanupPersisted = cleanup !== null;
        const cleanupRelativePath = cleanup?.cleanupRelativePath
            ?? deleteCleanupRelativePath(
                investigationId,
                args.expected_archive_digest,
            );
        cleanupDir = resolveCatalogRetentionPath(
            stateRoot,
            cleanupRelativePath,
            { kind: "archive", env: deps.env },
        );
        if (cleanup?.archiveRelativePath !== null
            && cleanup?.archiveRelativePath !== undefined) {
            archiveDir = resolveCatalogRetentionPath(
                stateRoot,
                cleanup.archiveRelativePath,
                { kind: "archive", env: deps.env },
            );
        } else if (entry.archive !== null) {
            archiveDir = resolveCatalogRetentionPath(
                stateRoot,
                entry.archive.relativePath,
                { kind: "archive", env: deps.env },
            );
        }
        if (entry.lifecycleState === "archived") {
            assertNoActiveResources(
                deps,
                broker,
                investigationId,
                resolveInvestigationPaths(stateRoot, investigationId),
            );
            const owner = lifecycleOwner(deps);
            broker.beginLifecycleOperation({
                investigationId,
                operationKind: "delete",
                operationToken,
                ownerProcessId: owner.processId,
                ownerProcessStartId: owner.processStartId,
                expectedArchiveDigest: args.expected_archive_digest,
            });
            operationBegun = true;
            inject(deps, "after-delete-fence", { investigationId });
        }
        if (cleanup === null) {
            if (archiveDir === null || !pathExists(deps, archiveDir)) {
                throw new InvestigationNotResumableError(
                    "archived bundle is missing before cleanup reservation",
                    { investigationId },
                );
            }
            const verified = (deps.verifyBundleInPlace
                ?? verifyBundleInPlace)({
                bundleDir: archiveDir,
                expectedDigest: args.expected_archive_digest,
                expectedInvestigationId: investigationId,
                requiredDomainVersion: DOMAIN_VERSION,
            });
            assertArchiveCatalogBinding(entry, verified);
            const archiveSize = (deps.measureRetainedTree
                ?? measureRetainedTree)(archiveDir, { env: deps.env });
            if (archiveSize.sizeBytes !== entry.archive.sizeBytes) {
                throw new InvestigationNotResumableError(
                    "archived bundle size does not match the catalog",
                    { investigationId },
                );
            }
            const activePaths = resolveInvestigationPaths(
                stateRoot,
                investigationId,
            );
            if (pathExists(deps, activePaths.investigationDir)) {
                (deps.removeRetainedTree ?? removeRetainedTree)({
                    target: activePaths.investigationDir,
                    containmentRoot: stateRoot,
                    env: deps.env,
                });
                fsyncDirectory(stateRoot);
                inject(deps, "after-delete-active-cleanup", {
                    investigationId,
                });
            }
            const deletedAt = new Date(
                deps.now?.() ?? Date.now(),
            ).toISOString();
            tombstone = (deps.writeSignedTombstone
                ?? writeSignedTombstone)({
                file: retention.tombstonePath,
                keyRoot: retention.tombstoneKeyRoot,
                env: deps.env,
                payload: {
                    investigationId,
                    createdAtMs: entry.registeredAtMs,
                    deletedAt,
                    domainVersion: authority.domainVersion,
                    archiveDigest: authority.archiveDigest,
                    domainHead: authority.domainHead,
                },
            });
            const deletedAtMs = assertDeleteTombstoneBinding(
                entry,
                tombstone,
                { stateRoot, retention },
            );
            inject(deps, "after-tombstone", { investigationId });
            const nonce = randomBytes(32).toString("hex");
            const archiveRelativePath = entry.archive.relativePath;
            const markerDigest = cleanupMarkerDigest({
                investigationId,
                archiveRelativePath,
                cleanupRelativePath,
                archiveDigest: authority.archiveDigest,
                nonce,
            });
            entry = broker.commitDelete({
                investigationId,
                operationToken,
                expectedArchiveDigest: authority.archiveDigest,
                cleanupRelativePath,
                cleanupMarkerNonce: nonce,
                cleanupMarkerDigest: markerDigest,
                tombstoneRelativePath: retentionRelativePath(
                    stateRoot,
                    tombstone.file,
                ),
                tombstoneDigest: tombstone.digest,
                signingKeyFingerprint:
                    tombstone.signingKeyFingerprint,
                signature: tombstone.signature,
                tombstoneSizeBytes: tombstone.sizeBytes,
                deletedAtMs,
            }).investigation;
            cleanup = entry.deleteCleanup;
            cleanupPersisted = true;
        } else {
            tombstone = ensureDeleteCleanupTombstone({
                entry,
                cleanup,
                stateRoot,
                retention,
                deps,
            });
        }
        inject(deps, "after-delete-catalog-commit", {
            investigationId,
        });

        if (cleanup.archiveAbsent !== true
            && cleanup.cleanupState === "reserved") {
            const sourceExists = archiveDir !== null
                && pathExists(deps, archiveDir);
            const cleanupExists = pathExists(deps, cleanupDir);
            if (sourceExists && cleanupExists) {
                throw new InvestigationNotResumableError(
                    "archive and cleanup paths both exist",
                    { investigationId },
                );
            }
            const markerRoot = sourceExists
                ? archiveDir
                : cleanupExists
                    ? cleanupDir
                    : null;
            if (markerRoot === null) {
                if (cleanup.sourceAuthority !== "legacy_preverified") {
                    throw new InvestigationNotResumableError(
                        "cleanup reservation lost both owned paths",
                        { investigationId },
                    );
                }
                entry = broker.commitDelete(cleanupCommitOptions({
                    entry,
                    cleanup,
                    operationToken:
                        entry.lifecycleState === "archived"
                            ? operationToken
                            : null,
                    nextCleanupState: "durability_pending",
                })).investigation;
                cleanup = entry.deleteCleanup;
            } else {
                if (sourceExists
                    && cleanup.sourceAuthority === "verified_bundle"
                    && !pathExists(
                        deps,
                        path.join(
                            markerRoot,
                            CLEANUP_MARKER_FILENAME,
                        ),
                    )) {
                    const verified = (deps.verifyBundleInPlace
                        ?? verifyBundleInPlace)({
                        bundleDir: markerRoot,
                        expectedDigest: cleanup.archiveDigest,
                        expectedInvestigationId: investigationId,
                        requiredDomainVersion: DOMAIN_VERSION,
                    });
                    if (entry.lifecycleState === "archived") {
                        assertArchiveCatalogBinding(entry, verified);
                    } else if (verified.digest !== cleanup.archiveDigest
                        || verified.investigationId !== investigationId) {
                        throw new InvestigationNotResumableError(
                            "discovered archive no longer matches cleanup authority",
                            { investigationId },
                        );
                    }
                }
                ensureCleanupOwnershipMarker({
                    root: markerRoot,
                    entry,
                    cleanup,
                    deps,
                });
                entry = broker.commitDelete(cleanupCommitOptions({
                    entry,
                    cleanup,
                    operationToken:
                        entry.lifecycleState === "archived"
                            ? operationToken
                            : null,
                    nextCleanupState: "marked",
                })).investigation;
                cleanup = entry.deleteCleanup;
            }
        }
        if (cleanup.cleanupState === "marked") {
            const sourceExists = archiveDir !== null
                && pathExists(deps, archiveDir);
            const cleanupExists = pathExists(deps, cleanupDir);
            if (sourceExists && cleanupExists) {
                throw new InvestigationNotResumableError(
                    "archive and cleanup paths both exist",
                    { investigationId },
                );
            }
            if (sourceExists) {
                ensureCleanupOwnershipMarker({
                    root: archiveDir,
                    entry,
                    cleanup,
                    deps,
                });
                renameMarkedArchiveForCleanup({
                    source: archiveDir,
                    destination: cleanupDir,
                    archiveRoot: retention.archiveRoot,
                    deps,
                });
                inject(deps, "after-archive-rename", {
                    investigationId,
                });
            } else if (cleanupExists) {
                ensureCleanupOwnershipMarker({
                    root: cleanupDir,
                    entry,
                    cleanup,
                    deps,
                });
            } else {
                throw new InvestigationNotResumableError(
                    "marked cleanup lost both owned paths",
                    { investigationId },
                );
            }
            entry = broker.commitDelete(cleanupCommitOptions({
                entry,
                cleanup,
                operationToken:
                    entry.lifecycleState === "archived"
                        ? operationToken
                        : null,
                nextCleanupState: "moved",
            })).investigation;
            cleanup = entry.deleteCleanup;
            inject(deps, "after-cleanup-moved", { investigationId });
        }
        if (cleanup.cleanupState === "moved") {
            if (archiveDir !== null && pathExists(deps, archiveDir)) {
                throw new InvestigationNotResumableError(
                    "source archive reappeared after cleanup move",
                    { investigationId },
                );
            }
            if (pathExists(deps, cleanupDir)) {
                let removed;
                try {
                    removed = (deps.removeDeleteCleanup
                        ?? removeRetainedTree)({
                        target: cleanupDir,
                        containmentRoot: retention.archiveRoot,
                        env: deps.env,
                    });
                } catch (error) {
                    if (!pathExists(deps, cleanupDir)
                        && (archiveDir === null
                            || !pathExists(deps, archiveDir))) {
                        entry = broker.commitDelete(
                            cleanupCommitOptions({
                                entry,
                                cleanup,
                                operationToken:
                                    entry.lifecycleState === "archived"
                                        ? operationToken
                                        : null,
                                nextCleanupState:
                                    "durability_pending",
                            }),
                        ).investigation;
                        cleanup = entry.deleteCleanup;
                        error.cleanupDurabilityPending = true;
                    }
                    throw error;
                }
                if (removed !== true && pathExists(deps, cleanupDir)) {
                    throw new InvestigationNotResumableError(
                        "cleanup-owned archive removal did not complete",
                        { investigationId },
                    );
                }
            }
            if ((archiveDir !== null && pathExists(deps, archiveDir))
                || pathExists(deps, cleanupDir)) {
                throw new InvestigationNotResumableError(
                    "archive removal could not be confirmed",
                    { investigationId },
                );
            }
            entry = broker.commitDelete(cleanupCommitOptions({
                entry,
                cleanup,
                operationToken:
                    entry.lifecycleState === "archived"
                        ? operationToken
                        : null,
                nextCleanupState: "durability_pending",
            })).investigation;
            cleanup = entry.deleteCleanup;
            inject(deps, "after-archive-delete", { investigationId });
        }
        if (!["durability_pending", "durable"].includes(
            cleanup.cleanupState,
        )) {
            throw new InvestigationNotResumableError(
                "delete cleanup did not reach durability barrier",
                { investigationId },
            );
        }
        if ((archiveDir !== null && pathExists(deps, archiveDir))
            || pathExists(deps, cleanupDir)) {
            throw new InvestigationNotResumableError(
                "archive path exists at durability barrier",
                { investigationId },
            );
        }
        readStableCatalogSnapshot(broker, stateRoot, deps);
        fsyncDeleteCleanupRoots({
            archiveRoot: retention.archiveRoot,
            cleanupDir,
            deps,
        });
        inject(deps, "after-cleanup-fsync", { investigationId });
        if (cleanup.cleanupState === "durability_pending") {
            entry = broker.commitDelete(cleanupCommitOptions({
                entry,
                cleanup,
                operationToken:
                    entry.lifecycleState === "archived"
                        ? operationToken
                        : null,
                nextCleanupState: "durable",
            })).investigation;
            cleanup = entry.deleteCleanup;
        }
        tombstone = ensureDeleteCleanupTombstone({
            entry,
            cleanup,
            stateRoot,
            retention,
            deps,
        });
        if ((archiveDir !== null && pathExists(deps, archiveDir))
            || pathExists(deps, cleanupDir)) {
            throw new InvestigationNotResumableError(
                "archive path reappeared after durability confirmation",
                { investigationId },
            );
        }
        const committed = broker.commitDelete(cleanupCommitOptions({
            entry,
            cleanup,
            operationToken:
                entry.lifecycleState === "archived"
                    ? operationToken
                    : null,
            archiveRemoved: true,
        }));
        operationBegun = false;
        return {
            is_result: false,
            investigation_id: investigationId,
            lifecycle_state: "tombstoned",
            deleted: true,
            archive_removed: true,
            tombstone_digest:
                committed.investigation.tombstone.digest,
            integrity_status: "verified",
            terminal_available: false,
        };
    } catch (error) {
        if (operationBegun) {
            try {
                broker.abortLifecycleOperation({
                    investigationId,
                    operationToken,
                });
            } catch (cleanupError) {
                error.catalogCleanupError = cleanupError;
            }
        }
        if (!cleanupPersisted
            && tombstone !== null
            && pathExists(deps, tombstone.file)) {
            try {
                (deps.removeRetainedTree ?? removeRetainedTree)({
                    target: tombstone.file,
                    containmentRoot: retention.tombstoneRoot,
                    env: deps.env,
                });
            } catch (cleanupError) {
                error.tombstoneCleanupError = cleanupError;
            }
        }
        throw error;
    } finally {
        safeClose(broker);
    }
}

export function assertInvestigationIdentityAvailable({
    deps,
    stateRoot,
    investigationId,
} = {}) {
    const broker = openCatalogForRead(deps, stateRoot);
    if (broker === null) {
        if (standaloneTombstoneTarget(
            deps,
            stateRoot,
            investigationId,
        ) !== null) {
            throw new InvestigationNotResumableError(
                "an uncommitted signed tombstone blocks deterministic identity reuse",
                {
                    investigationId,
                    source: "uncommitted_signed_tombstone",
                },
            );
        }
        const activePaths = resolveInvestigationPaths(
            stateRoot,
            investigationId,
        );
        if (isUncatalogedLegacyInvestigation(
            deps,
            investigationId,
            activePaths,
        )) {
            return null;
        }
        assertStateRootTrulyEmpty(stateRoot);
        return null;
    }
    try {
        const entries = readStableCatalogSnapshot(
            broker,
            stateRoot,
            deps,
        );
        const entry = entries.find((candidate) =>
            candidate.investigationId === investigationId) ?? null;
        if (entry?.lifecycleState === "tombstoned") {
            verifyCatalogTombstone(entry, stateRoot, deps);
            throw new InvestigationNotResumableError(
                "this deterministic investigation identity is durably tombstoned and cannot be recreated",
                {
                    investigationId,
                    lifecycleState: "tombstoned",
                },
            );
        }
        if (entry?.lifecycleState === "archived") {
            throw new InvestigationNotResumableError(
                "this deterministic investigation identity is archived and cannot be resumed in place",
                {
                    investigationId,
                    lifecycleState: "archived",
                },
            );
        }
        if (entry?.lifecycleOperation !== null
            && entry?.lifecycleOperation !== undefined) {
            throw new InvestigationNotResumableError(
                "this investigation is fenced by an archive/delete lifecycle operation",
                {
                    investigationId,
                    lifecycleState: entry.lifecycleState,
                    operationKind:
                        entry.lifecycleOperation.operationKind,
                },
            );
        }
        if (entry === null
            && standaloneTombstoneTarget(
                deps,
                stateRoot,
                investigationId,
            ) !== null) {
            throw new InvestigationNotResumableError(
                "an uncommitted signed tombstone blocks deterministic identity reuse",
                {
                    investigationId,
                    source: "uncommitted_signed_tombstone",
                },
            );
        }
        return entry;
    } finally {
        safeClose(broker);
    }
}

export function activeCatalogSummary({
    entry,
    stateRoot,
    read,
    integrityStatus,
    deps,
    domainVersion = DOMAIN_VERSION,
}) {
    let sizeBytes = null;
    let publicIntegrityStatus = integrityStatus;
    try {
        sizeBytes = (deps.measureRetainedTree ?? measureRetainedTree)(
            resolveInvestigationPaths(
                stateRoot,
                entry.investigationId,
            ).investigationDir,
            { env: deps.env },
        ).sizeBytes;
    } catch {
        publicIntegrityStatus = "blocked";
    }
    const readiness = read?.aggregate?.terminal === null
        || read?.aggregate?.terminal === undefined
        ? { ready: false }
        : (deps.assessPersistedTerminalReadiness
            ?? assessPersistedTerminalReadiness)(read.aggregate);
    return publicSummary({
        investigationId: entry.investigationId,
        state: "active",
        createdAtMs: entry.registeredAtMs,
        updatedAtMs: entry.lifecycleUpdatedAtMs,
        domainVersion,
        terminalAvailable:
            publicIntegrityStatus === "verified"
            && readiness.ready === true,
        integrityStatus: publicIntegrityStatus,
        sizeBytes,
    });
}
