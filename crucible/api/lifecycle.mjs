import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

import {
    DOMAIN_VERSION,
    assessPersistedTerminalReadiness,
} from "../domain/index.mjs";
import {
    exportBundle,
    importBundle,
    measureRetainedTree,
    removeRetainedTree,
    removeVerifiedBundle,
    verifyBundleInPlace,
    verifySignedTombstone,
    writeSignedTombstone,
} from "../persistence/index.mjs";
import {
    createProcessIdentityAdapter,
    openResourceBrokerFromStateRoot,
    resourceCatalogPath,
    supervisorPaths,
} from "../runtime/index.mjs";
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
        return Object.freeze({ entry, reclaimed: false });
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
    });
}

function catalogFactory(deps) {
    return deps.openResourceBrokerFromStateRoot
        ?? openResourceBrokerFromStateRoot;
}

function pathExists(deps, candidate) {
    return (deps.pathExists ?? fs.existsSync)(candidate);
}

function openCatalog(deps, stateRoot) {
    const catalogPath =
        (deps.resourceCatalogPath ?? resourceCatalogPath)(stateRoot);
    const exists = typeof deps.openResourceBrokerFromStateRoot === "function"
        ? pathExists(deps, catalogPath)
        : fs.existsSync(catalogPath);
    if (!exists) {
        return null;
    }
    return catalogFactory(deps)({
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

function retentionRelativePath(stateRoot, target) {
    const relative = path.relative(stateRoot, target)
        .split(path.sep)
        .join("/");
    return process.platform === "win32"
        ? relative.toLowerCase()
        : relative;
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
    if (verified.sizeBytes !== tombstone.sizeBytes
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

function tombstoneSummary(entry, stateRoot, deps) {
    try {
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
        const measured = (deps.measureRetainedTree
            ?? measureRetainedTree)(bundleDir, { env: deps.env });
        if (measured.sizeBytes !== entry.archive.sizeBytes) {
            throw new Error("archive size differs from the catalog");
        }
        return publicSummary({
            investigationId: entry.investigationId,
            state: "archived",
            createdAtMs: entry.registeredAtMs,
            updatedAtMs: entry.lifecycleUpdatedAtMs,
            domainVersion: verified.domainVersion,
            terminalAvailable: entry.archive.terminalAvailable,
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
    const standaloneTombstone = standaloneTombstoneTarget(
        deps,
        stateRoot,
        investigationId,
    );
    if (standaloneTombstone !== null) {
        return standaloneTombstone;
    }
    const broker = openCatalog(deps, stateRoot);
    if (broker === null) {
        return Object.freeze({
            stateRoot,
            state: "active",
            entry: null,
            paths: activePaths,
            verification: null,
        });
    }
    try {
        const entry = broker.getInvestigation(investigationId);
        if (entry === null) {
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
            if (entry.tombstone === null) {
                throw new Error(
                    "tombstoned catalog entry has no durable tombstone record",
                );
            }
            const retention = resolveRetentionPaths(
                stateRoot,
                investigationId,
                { env: deps.env },
            );
            const tombstonePath = resolveCatalogRetentionPath(
                stateRoot,
                entry.tombstone.relativePath,
                { kind: "tombstone", env: deps.env },
            );
            const verification = (deps.verifySignedTombstone
                ?? verifySignedTombstone)({
                file: tombstonePath,
                keyRoot: retention.tombstoneKeyRoot,
                expectedDigest: entry.tombstone.digest,
                expectedInvestigationId: investigationId,
                env: deps.env,
            });
            assertTombstoneCatalogBinding(entry, verification);
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
        || target.paths === null) {
        throw new TypeError(
            "verifyArchivedTarget requires an archived lifecycle target",
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
    const broker = openCatalog(deps, stateRoot);
    if (broker === null) {
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
        page = broker.listInvestigations({
            lifecycleState: args.state_filter ?? null,
            excludeFenced: false,
            afterInvestigationId: afterId,
            limit: pageLimit + 1,
        });
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
                    Number.isFinite(read?.updatedAtMs)
                        ? read.updatedAtMs
                        : 0,
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

function cleanupStaleArchiveStaging(deps, paths, investigationId) {
    if (!pathExists(deps, paths.stagingRoot)) return;
    const prefix = `${investigationId}.archive-`;
    for (const name of fs.readdirSync(paths.stagingRoot)) {
        if (!name.startsWith(prefix) || !name.endsWith(".export")) {
            continue;
        }
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
    const broker = openCatalog(deps, stateRoot);
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
        let catalogEntry = broker.getInvestigation(investigationId);
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
            cleanupStaleArchiveStaging(
                deps,
                paths,
                investigationId,
            );
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
        if (recoveredFence.reclaimed) {
            cleanupStaleArchiveStaging(
                deps,
                paths,
                investigationId,
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
        if (pathExists(deps, rawExported)) {
            (deps.removeRetainedTree ?? removeRetainedTree)({
                target: rawExported,
                containmentRoot: paths.stagingRoot,
                env: deps.env,
            });
        }
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
    const broker = openCatalog(deps, stateRoot);
    if (broker === null) {
        throw new InvestigationNotFoundError(
            "investigation is absent from the global lifecycle catalog",
            { investigationId },
        );
    }
    const operationToken = `delete-${randomUUID()}`;
    let operationBegun = false;
    let catalogCommitted = false;
    let tombstone = null;
    let archiveDir = null;
    try {
        let entry = broker.getInvestigation(investigationId);
        if (entry === null) {
            throw new InvestigationNotFoundError(
                "no Crucible investigation with this id",
                { investigationId },
            );
        }
        entry = reclaimStaleLifecycleFence(
            broker,
            entry,
            deps,
            "delete",
        ).entry;
        if (entry.lifecycleState !== "archived"
            || entry.archive === null) {
            throw new InvestigationNotResumableError(
                "delete is permitted only for a verified archived investigation",
                {
                    investigationId,
                    lifecycleState: entry.lifecycleState,
                },
            );
        }
        if (entry.archive.digest !== args.expected_archive_digest) {
            throw new InvestigationNotResumableError(
                "expected archive digest does not match the catalog",
                {
                    investigationId,
                    expectedArchiveDigest:
                        args.expected_archive_digest,
                    actualArchiveDigest: entry.archive.digest,
                },
            );
        }
        archiveDir = resolveCatalogRetentionPath(
            stateRoot,
            entry.archive.relativePath,
            { kind: "archive", env: deps.env },
        );
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
                domainVersion: verified.domainVersion,
                archiveDigest: verified.digest,
                domainHead: verified.domainHead,
            },
        });
        inject(deps, "after-tombstone", { investigationId });
        const tombstoneRelativePath = retentionRelativePath(
            stateRoot,
            tombstone.file,
        );
        const committed = broker.commitDelete({
            investigationId,
            operationToken,
            expectedArchiveDigest: args.expected_archive_digest,
            tombstoneRelativePath,
            tombstoneDigest: tombstone.digest,
            signingKeyFingerprint: tombstone.signingKeyFingerprint,
            signature: tombstone.signature,
            tombstoneSizeBytes: tombstone.sizeBytes,
            deletedAtMs: Date.parse(
                tombstone.payload?.deletedAt ?? deletedAt,
            ),
        });
        catalogCommitted = true;
        operationBegun = false;
        inject(deps, "after-delete-catalog-commit", {
            investigationId,
        });
        (deps.removeVerifiedBundle ?? removeVerifiedBundle)({
            bundleDir: archiveDir,
            expectedDigest: args.expected_archive_digest,
            expectedInvestigationId: investigationId,
            requiredDomainVersion: DOMAIN_VERSION,
        });
        inject(deps, "after-archive-delete", { investigationId });
        return {
            is_result: false,
            investigation_id: investigationId,
            lifecycle_state: "tombstoned",
            deleted: true,
            archive_removed: !pathExists(deps, archiveDir),
            tombstone_digest:
                committed.investigation.tombstone.digest,
            integrity_status: "verified",
            terminal_available: false,
        };
    } catch (error) {
        if (!catalogCommitted) {
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
            if (tombstone !== null && pathExists(deps, tombstone.file)) {
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
        } else if (archiveDir !== null && pathExists(deps, archiveDir)) {
            try {
                (deps.removeVerifiedBundle ?? removeVerifiedBundle)({
                    bundleDir: archiveDir,
                    expectedDigest: args.expected_archive_digest,
                    expectedInvestigationId: investigationId,
                    requiredDomainVersion: DOMAIN_VERSION,
                });
            } catch (cleanupError) {
                error.archiveCleanupError = cleanupError;
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
    const standalone = standaloneTombstoneTarget(
        deps,
        stateRoot,
        investigationId,
    );
    if (standalone !== null) {
        throw new InvestigationNotResumableError(
            "this deterministic investigation identity is durably tombstoned and cannot be recreated",
            {
                investigationId,
                lifecycleState: "tombstoned",
                source: "signed_tombstone",
            },
        );
    }
    const broker = openCatalog(deps, stateRoot);
    if (broker === null) return null;
    try {
        const entry = broker.getInvestigation(investigationId);
        if (entry?.lifecycleState === "tombstoned") {
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
