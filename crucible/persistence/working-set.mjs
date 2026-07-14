import fs from "node:fs";
import path from "node:path";

import {
    normalizeWorkingSetPolicy,
} from "../domain/working-set-policy.mjs";
import {
    InvalidArgumentError,
} from "./errors.mjs";
import {
    readBundleManifest,
} from "./bundle.mjs";

const CAS_OBJECT_ID_RE = /^sha256:[0-9a-f]{64}$/u;
const MAX_REFERENCE_SCAN_NODES = 2_000_000;
const EFFECT_RECOVERY_CAPSULE_CONTENT_TYPE =
    "application/vnd.crucible.effect-recovery+json";

export const WORKING_SET_INTEGRATION_NOTES = Object.freeze({
    checkpoint:
        "Active WAL checkpoints run only outside repository transactions. Transaction commits trigger a bounded threshold/interval probe; segment rotation forces a TRUNCATE checkpoint after its commit.",
    references:
        "CAS reconciliation acquires the store generation lock before scanning repository metadata, active and sealed event payloads, bundle manifests, transient unresolved-effect recovery capsules, and private installation state. Any incomplete reference scan defers deletion; resolved capsules become eligible only after their reference is released and orphan retention is satisfied.",
    budgets:
        "The signed workingSetPolicy freezes per-attempt/per-investigation bytes and maintenance thresholds. The resource broker storage_bytes lane atomically reserves global growth before effects; physical telemetry remains the current working-set authority.",
    diagnostics:
        "Referenced diagnostics remain evidence. Original deletion is deferred unless the signed diagnostic policy explicitly permits sealed_rollup and a caller supplies a sealed summary plus non-authoritative and non-bundle-required attestations.",
});

function requirePositiveSafeInteger(value, field, { allowZero = false } = {}) {
    const minimum = allowZero ? 0 : 1;
    if (!Number.isSafeInteger(value) || value < minimum) {
        throw new InvalidArgumentError(
            `${field} must be a safe integer >= ${minimum}`,
            { field, value },
        );
    }
    return value;
}

function isDisappearedTreeEntry(error) {
    return error?.code === "ENOENT" || error?.code === "ENOTDIR";
}

function samePath(left, right) {
    const resolvedLeft = path.resolve(left);
    const resolvedRight = path.resolve(right);
    return process.platform === "win32"
        ? resolvedLeft.toLowerCase() === resolvedRight.toLowerCase()
        : resolvedLeft === resolvedRight;
}

function isPathInside(candidate, root) {
    const relative = path.relative(path.resolve(root), path.resolve(candidate));
    return relative === ""
        || (!relative.startsWith(`..${path.sep}`)
            && relative !== ".."
            && !path.isAbsolute(relative));
}

function regularTreeTelemetry(root) {
    const telemetry = {
        bytes: 0,
        files: 0,
        directories: 0,
        unsafeEntries: 0,
    };
    const stack = [path.resolve(root)];
    while (stack.length > 0) {
        const current = stack.pop();
        let stat;
        try {
            stat = fs.lstatSync(current);
        } catch (error) {
            if (isDisappearedTreeEntry(error)) continue;
            throw error;
        }
        if (stat.isSymbolicLink()) {
            telemetry.unsafeEntries += 1;
            continue;
        }
        if (stat.isDirectory()) {
            let names;
            try {
                names = fs.readdirSync(current).sort();
            } catch (error) {
                if (isDisappearedTreeEntry(error)) continue;
                throw error;
            }
            telemetry.directories += 1;
            for (const name of names) {
                stack.push(path.join(current, name));
            }
            continue;
        }
        if (!stat.isFile()) {
            telemetry.unsafeEntries += 1;
            continue;
        }
        telemetry.files += 1;
        telemetry.bytes += stat.size;
        if (!Number.isSafeInteger(telemetry.bytes)) {
            throw new InvalidArgumentError(
                "working-set byte telemetry exceeds the safe integer range",
                { root },
            );
        }
    }
    return telemetry;
}

function scanObjectIds(value, output, counter = { nodes: 0 }) {
    counter.nodes += 1;
    if (counter.nodes > MAX_REFERENCE_SCAN_NODES) {
        throw new InvalidArgumentError(
            "artifact reference scan exceeded its bounded node count",
            { maximum: MAX_REFERENCE_SCAN_NODES },
        );
    }
    if (typeof value === "string") {
        if (CAS_OBJECT_ID_RE.test(value)) output.add(value);
        return;
    }
    if (value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
        for (const item of value) scanObjectIds(item, output, counter);
        return;
    }
    for (const key of Object.keys(value).sort()) {
        scanObjectIds(value[key], output, counter);
    }
}

export function collectWorkingSetReferences({
    repository,
    investigationId,
    bundleDirs = [],
} = {}) {
    if (repository === null
        || typeof repository !== "object"
        || typeof repository.listArtifactRefs !== "function"
        || typeof repository.listEvents !== "function") {
        throw new InvalidArgumentError(
            "collectWorkingSetReferences requires an event repository",
        );
    }
    if (typeof investigationId !== "string" || investigationId.length === 0) {
        throw new InvalidArgumentError("investigationId is required");
    }
    if (!Array.isArray(bundleDirs)) {
        throw new InvalidArgumentError("bundleDirs must be an array");
    }

    const referenced = new Set();
    const transientReferenced = new Set();
    const snapshots = new Set();
    const artifactIds = new Set();
    const refs = repository.listArtifactRefs(investigationId);
    for (const ref of refs) {
        artifactIds.add(ref.artifactId);
        const artifact = repository.getArtifact(ref.artifactId);
        if (artifact === null || artifact.investigationId !== investigationId) {
            throw new InvalidArgumentError(
                "artifact reference scan encountered missing or cross-investigation metadata",
                { artifactId: ref.artifactId },
            );
        }
        if (artifact.storage === "external"
            && artifact.hashAlgo === "sha256"
            && typeof artifact.hashValue === "string") {
            const objectId = `sha256:${artifact.hashValue}`;
            if (!CAS_OBJECT_ID_RE.test(objectId)) {
                throw new InvalidArgumentError(
                    "artifact metadata contains an invalid CAS identity",
                    { artifactId: artifact.artifactId },
                );
            }
            if (ref.seq === null
                && artifact.contentType
                    === EFFECT_RECOVERY_CAPSULE_CONTENT_TYPE) {
                if (!referenced.has(objectId)) {
                    transientReferenced.add(objectId);
                }
            } else {
                referenced.add(objectId);
                transientReferenced.delete(objectId);
            }
            if (artifact.contentType
                === "application/vnd.crucible.snapshot+json") {
                snapshots.add(objectId);
            }
        }
    }

    const events = repository.listEvents(investigationId);
    for (const event of events) {
        scanObjectIds(event.payload, referenced);
    }
    for (const objectId of referenced) {
        transientReferenced.delete(objectId);
    }

    let bundleObjectCount = 0;
    for (const bundleDir of [...new Set(bundleDirs.map((item) =>
        path.resolve(item)))].sort()) {
        const manifest = readBundleManifest(bundleDir);
        if (manifest.investigation.id !== investigationId) continue;
        for (const object of manifest.objects) {
            referenced.add(object.id);
            transientReferenced.delete(object.id);
            bundleObjectCount += 1;
        }
        for (const snapshot of manifest.snapshots) snapshots.add(snapshot);
    }

    return Object.freeze({
        referenced: Object.freeze([...referenced].sort()),
        transientReferenced:
            Object.freeze([...transientReferenced].sort()),
        snapshots: Object.freeze([...snapshots].sort()),
        counts: Object.freeze({
            repositoryArtifactRefs: refs.length,
            repositoryArtifacts: artifactIds.size,
            scannedEvents: events.length,
            bundleCount: bundleDirs.length,
            bundleObjects: bundleObjectCount,
            referencedObjects: referenced.size + transientReferenced.size,
            transientRecoveryCapsules: transientReferenced.size,
            snapshotRoots: snapshots.size,
        }),
    });
}

export function reconcileWorkingSetArtifacts({
    repository,
    artifactStore,
    investigationId,
    bundleDirs = [],
    olderThanMs,
    now = Date.now(),
    dryRun = false,
} = {}) {
    if (artifactStore === null
        || typeof artifactStore !== "object"
        || typeof artifactStore.reconcile !== "function") {
        throw new InvalidArgumentError(
            "reconcileWorkingSetArtifacts requires an artifact store",
        );
    }
    requirePositiveSafeInteger(olderThanMs, "olderThanMs", { allowZero: true });
    if (!Number.isFinite(now)) {
        throw new InvalidArgumentError("now must be finite epoch milliseconds");
    }
    if (dryRun || artifactStore.readOnly === true) {
        let scan;
        try {
            scan = collectWorkingSetReferences({
                repository,
                investigationId,
                bundleDirs,
            });
        } catch (error) {
            return Object.freeze({
                deferred: true,
                reason: "reference_scan_failed",
                errorCode: error?.code ?? null,
                scan: null,
                reconciliation: null,
            });
        }
        return Object.freeze({
            deferred: artifactStore.readOnly === true,
            reason: artifactStore.readOnly === true ? "read_only" : null,
            scan: scan.counts,
            reconciliation: artifactStore.readOnly === true
                ? null
                : artifactStore.reconcile({
                    referenced: scan.referenced,
                    transientReferenced: scan.transientReferenced,
                    snapshots: scan.snapshots,
                    olderThanMs,
                    now,
                    dryRun: true,
                }),
        });
    }
    return artifactStore.withGenerationLock(({ generation }) => {
        let scan;
        try {
            scan = collectWorkingSetReferences({
                repository,
                investigationId,
                bundleDirs,
            });
        } catch (error) {
            return Object.freeze({
                deferred: true,
                reason: "reference_scan_failed",
                errorCode: error?.code ?? null,
                generation,
                scan: null,
                reconciliation: null,
            });
        }
        const reconciliation = artifactStore.reconcile({
            referenced: scan.referenced,
            transientReferenced: scan.transientReferenced,
            snapshots: scan.snapshots,
            olderThanMs,
            now,
            removeQuarantine: false,
            referenceProbe: (objectId) => {
                const latest = collectWorkingSetReferences({
                    repository,
                    investigationId,
                    bundleDirs: [],
                });
                if (latest.referenced.includes(objectId)) return true;
                for (const snapshotId of latest.snapshots) {
                    const manifest = artifactStore.loadManifest(snapshotId);
                    if (manifest.entries.some((entry) =>
                        entry.object === objectId)) {
                        return true;
                    }
                }
                return false;
            },
            transientReferenceProbe: (objectId) => {
                const latest = collectWorkingSetReferences({
                    repository,
                    investigationId,
                    bundleDirs: [],
                });
                return latest.transientReferenced.includes(objectId);
            },
        });
        return Object.freeze({
            deferred: false,
            reason: null,
            generation,
            scan: scan.counts,
            reconciliation,
        });
    });
}

export function evaluateStorageBudget({
    currentBytes,
    requestedBytes = 0,
    limitBytes,
    warningBasisPoints,
    terminalReserveBytes = 0,
    terminalReady = false,
} = {}) {
    const current = requirePositiveSafeInteger(
        currentBytes,
        "currentBytes",
        { allowZero: true },
    );
    const requested = requirePositiveSafeInteger(
        requestedBytes,
        "requestedBytes",
        { allowZero: true },
    );
    const limit = requirePositiveSafeInteger(limitBytes, "limitBytes");
    const warning = requirePositiveSafeInteger(
        warningBasisPoints,
        "warningBasisPoints",
    );
    const reserve = requirePositiveSafeInteger(
        terminalReserveBytes,
        "terminalReserveBytes",
        { allowZero: true },
    );
    if (warning > 10_000 || reserve >= limit) {
        throw new InvalidArgumentError("storage budget thresholds are invalid", {
            warningBasisPoints: warning,
            terminalReserveBytes: reserve,
            limitBytes: limit,
        });
    }
    const effectiveLimit = terminalReady ? limit : limit - reserve;
    const projectedBytes = current + requested;
    if (!Number.isSafeInteger(projectedBytes)) {
        throw new InvalidArgumentError(
            "projected storage exceeds the safe integer range",
        );
    }
    const warningBytesBigInt =
        (BigInt(limit) * BigInt(warning)) / 10_000n;
    const exhausted = projectedBytes > effectiveLimit;
    const approaching = !exhausted
        && BigInt(projectedBytes) >= warningBytesBigInt;
    return Object.freeze({
        currentBytes: current,
        requestedBytes: requested,
        projectedBytes,
        limitBytes: limit,
        effectiveLimitBytes: effectiveLimit,
        terminalReserveBytes: reserve,
        warningBytes: Number(warningBytesBigInt),
        remainingBytes: Math.max(0, effectiveLimit - current),
        projectedRemainingBytes: Math.max(0, effectiveLimit - projectedBytes),
        pressure: exhausted
            ? "exhausted"
            : approaching
                ? "approaching"
                : "normal",
        admitted: !exhausted,
        exactBoundary: projectedBytes === effectiveLimit,
    });
}

export class WorkingSetController {
    #repository;
    #artifactStore;
    #investigationId;
    #investigationDir;
    #stateRoot;
    #policy;
    #globalLimitBytes;
    #bundleDirs;
    #now;
    #resourceBroker;
    #resourceAuthority;
    #reconciliationCounter = 0;
    #lastMaintenanceMs = null;
    #lastMaintenance = null;

    constructor({
        repository,
        artifactStore,
        investigationId,
        investigationDir,
        stateRoot,
        policy,
        globalLimitBytes,
        bundleDirs = [],
        now = Date.now,
        resourceBroker = null,
        resourceAuthority = null,
    } = {}) {
        if (repository === null || typeof repository !== "object") {
            throw new InvalidArgumentError("repository is required");
        }
        if (artifactStore === null || typeof artifactStore !== "object") {
            throw new InvalidArgumentError("artifactStore is required");
        }
        if (typeof investigationId !== "string" || investigationId.length === 0) {
            throw new InvalidArgumentError("investigationId is required");
        }
        for (const [field, value] of [
            ["investigationDir", investigationDir],
            ["stateRoot", stateRoot],
        ]) {
            if (typeof value !== "string" || !path.isAbsolute(value)) {
                throw new InvalidArgumentError(`${field} must be absolute`);
            }
        }
        if (typeof now !== "function") {
            throw new InvalidArgumentError("now must be a function");
        }
        const resolvedInvestigationDir = path.resolve(investigationDir);
        const resolvedStateRoot = path.resolve(stateRoot);
        if (!samePath(resolvedInvestigationDir, resolvedStateRoot)
            && !samePath(
                resolvedInvestigationDir,
                path.join(resolvedStateRoot, investigationId),
            )) {
            throw new InvalidArgumentError(
                "investigationDir must be the controller-owned root or its investigation child",
                {
                    investigationId,
                    investigationDir: resolvedInvestigationDir,
                    stateRoot: resolvedStateRoot,
                },
            );
        }
        if (typeof repository.databaseFile === "string"
            && !isPathInside(repository.databaseFile, resolvedInvestigationDir)) {
            throw new InvalidArgumentError(
                "repository database must remain inside investigationDir",
                {
                    databaseFile: repository.databaseFile,
                    investigationDir: resolvedInvestigationDir,
                },
            );
        }
        if (typeof artifactStore.root === "string"
            && !isPathInside(artifactStore.root, resolvedInvestigationDir)) {
            throw new InvalidArgumentError(
                "artifact store must remain inside investigationDir",
                {
                    artifactRoot: artifactStore.root,
                    investigationDir: resolvedInvestigationDir,
                },
            );
        }
        this.#repository = repository;
        this.#artifactStore = artifactStore;
        this.#investigationId = investigationId;
        this.#investigationDir = resolvedInvestigationDir;
        this.#stateRoot = resolvedStateRoot;
        this.#policy = normalizeWorkingSetPolicy(policy);
        if (typeof repository.configureWorkingSet === "function") {
            repository.configureWorkingSet(this.#policy);
        }
        this.#globalLimitBytes = requirePositiveSafeInteger(
            globalLimitBytes,
            "globalLimitBytes",
        );
        this.#bundleDirs = Object.freeze([...new Set(bundleDirs.map((item) =>
            path.resolve(item)))].sort());
        this.#now = now;
        this.#resourceBroker = resourceBroker;
        this.#resourceAuthority = resourceAuthority;
        if ((resourceBroker === null) !== (resourceAuthority === null)) {
            throw new InvalidArgumentError(
                "resourceBroker and resourceAuthority must be provided together",
            );
        }
        if (resourceBroker !== null
            && typeof resourceBroker.reconcileStorageUsage !== "function") {
            this.#resourceBroker = null;
            this.#resourceAuthority = null;
        }
    }

    get policy() {
        return this.#policy;
    }

    #reconcileBrokerStorage(telemetry, stage) {
        if (this.#resourceBroker === null) return null;
        this.#reconciliationCounter += 1;
        return this.#resourceBroker.reconcileStorageUsage({
            investigationId: this.#investigationId,
            supervisorGeneration:
                this.#resourceAuthority.supervisorGeneration,
            runnerIncarnation:
                this.#resourceAuthority.runnerIncarnation,
            actualBytes: telemetry.investigation.bytes,
            reconciliationId:
                `working-set-${stage}-${this.#reconciliationCounter}`,
            source: "working_set_measurement",
        });
    }

    telemetry() {
        const investigation = regularTreeTelemetry(this.#investigationDir);
        const global = regularTreeTelemetry(this.#stateRoot);
        const repository = typeof this.#repository.getStorageTelemetry === "function"
            ? this.#repository.getStorageTelemetry(this.#investigationId)
            : null;
        const artifacts = typeof this.#artifactStore.storageTelemetry === "function"
            ? this.#artifactStore.storageTelemetry()
            : null;
        const investigationBudget = evaluateStorageBudget({
            currentBytes: investigation.bytes,
            limitBytes: this.#policy.perInvestigationBytes,
            warningBasisPoints: this.#policy.warningBasisPoints,
            terminalReserveBytes: this.#policy.terminalReserveBytes,
        });
        const globalBudget = evaluateStorageBudget({
            currentBytes: global.bytes,
            limitBytes: this.#globalLimitBytes,
            warningBasisPoints: this.#policy.warningBasisPoints,
        });
        return Object.freeze({
            investigation: Object.freeze({
                bytes: investigation.bytes,
                files: investigation.files,
                directories: investigation.directories,
                unsafeEntries: investigation.unsafeEntries,
                budget: investigationBudget,
            }),
            global: Object.freeze({
                bytes: global.bytes,
                files: global.files,
                directories: global.directories,
                unsafeEntries: global.unsafeEntries,
                budget: globalBudget,
            }),
            repository,
            artifacts,
            thresholds: Object.freeze({
                perAttemptBytes: this.#policy.perAttemptBytes,
                perInvestigationBytes:
                    this.#policy.perInvestigationBytes,
                globalBytes: this.#globalLimitBytes,
                warningBasisPoints:
                    this.#policy.warningBasisPoints,
                terminalReserveBytes:
                    this.#policy.terminalReserveBytes,
                walCheckpointBytes:
                    this.#policy.walCheckpointBytes,
                segmentEventThreshold:
                    this.#policy.segmentEventThreshold,
                segmentByteThreshold:
                    this.#policy.segmentByteThreshold,
                orphanGraceMs: this.#policy.orphanGraceMs,
            }),
            diagnostics: Object.freeze({
                retentionMode:
                    this.#policy.diagnosticRetention.mode,
                cleanupDeferred:
                    this.#policy.diagnosticRetention.mode === "defer",
            }),
            lastMaintenance: this.#lastMaintenance,
        });
    }

    maintain({
        force = false,
        quiescent = false,
    } = {}) {
        const nowMs = this.#now();
        if (!Number.isFinite(nowMs)) {
            throw new InvalidArgumentError("now must return finite epoch milliseconds");
        }
        const due = force
            || this.#lastMaintenanceMs === null
            || nowMs - this.#lastMaintenanceMs >= this.#policy.maintenanceIntervalMs;
        if (!due) {
            return Object.freeze({
                performed: false,
                reason: "interval_not_reached",
                telemetry: this.telemetry(),
            });
        }
        this.telemetry();
        let rotation = null;
        let checkpoint = null;
        let artifacts = null;
        if (this.#repository.readOnly !== true) {
            if (quiescent && typeof this.#repository.rotateEventSegment === "function") {
                rotation = this.#repository.rotateEventSegment({
                    investigationId: this.#investigationId,
                    quiescent: true,
                    eventThreshold: this.#policy.segmentEventThreshold,
                    byteThreshold: this.#policy.segmentByteThreshold,
                });
                checkpoint = rotation.checkpoint ?? null;
            } else if (typeof this.#repository.checkpointWal === "function") {
                checkpoint = this.#repository.checkpointWal({
                    force,
                    reason: force ? "working_set_forced" : "working_set_periodic",
                });
            }
        }
        if (this.#artifactStore.readOnly !== true) {
            artifacts = reconcileWorkingSetArtifacts({
                repository: this.#repository,
                artifactStore: this.#artifactStore,
                investigationId: this.#investigationId,
                bundleDirs: this.#bundleDirs,
                olderThanMs: this.#policy.orphanGraceMs,
                now: nowMs,
            });
        }
        const finalTelemetry = this.telemetry();
        const brokerReconciliation = this.#reconcileBrokerStorage(
            finalTelemetry,
            "maintenance",
        );
        this.#lastMaintenanceMs = nowMs;
        this.#lastMaintenance = Object.freeze({
            atMs: nowMs,
            checkpointed: checkpoint?.checkpointed === true,
            rotated: rotation?.rotated === true,
            removedObjects:
                artifacts?.reconciliation?.removedObjects?.length ?? 0,
            removedStaging:
                artifacts?.reconciliation?.removedStaging?.length ?? 0,
            deletionDeferred: artifacts?.deferred === true,
        });
        return Object.freeze({
            performed: true,
            checkpoint,
            rotation,
            artifacts,
            brokerReconciliation,
            telemetry: finalTelemetry,
        });
    }

    prepareWrite({
        bytes,
        terminalReady = false,
        authoritative = true,
        quiescent = true,
    } = {}) {
        const requestedBytes = requirePositiveSafeInteger(bytes, "bytes", {
            allowZero: true,
        });
        let telemetry = this.telemetry();
        let investigation = evaluateStorageBudget({
            currentBytes: telemetry.investigation.bytes,
            requestedBytes,
            limitBytes: this.#policy.perInvestigationBytes,
            warningBasisPoints: this.#policy.warningBasisPoints,
            terminalReserveBytes: this.#policy.terminalReserveBytes,
            terminalReady,
        });
        let global = evaluateStorageBudget({
            currentBytes: telemetry.global.bytes,
            requestedBytes,
            limitBytes: this.#globalLimitBytes,
            warningBasisPoints: this.#policy.warningBasisPoints,
            terminalReady,
        });
        let maintenance = null;
        if (investigation.pressure !== "normal" || global.pressure !== "normal") {
            maintenance = this.maintain({ force: true, quiescent });
            telemetry = maintenance.telemetry;
            investigation = evaluateStorageBudget({
                currentBytes: telemetry.investigation.bytes,
                requestedBytes,
                limitBytes: this.#policy.perInvestigationBytes,
                warningBasisPoints: this.#policy.warningBasisPoints,
                terminalReserveBytes: this.#policy.terminalReserveBytes,
                terminalReady,
            });
            global = evaluateStorageBudget({
                currentBytes: telemetry.global.bytes,
                requestedBytes,
                limitBytes: this.#globalLimitBytes,
                warningBasisPoints: this.#policy.warningBasisPoints,
                terminalReady,
            });
        }
        const exhausted = !investigation.admitted || !global.admitted;
        const throttle = !exhausted
            && authoritative === false
            && (investigation.pressure === "approaching"
                || global.pressure === "approaching");
        const brokerReconciliation = this.#reconcileBrokerStorage(
            telemetry,
            "reserve",
        );
        return Object.freeze({
            status: exhausted
                ? "exhausted"
                : throttle
                    ? "throttle"
                    : "admitted",
            admitted: !exhausted && !throttle,
            terminalReady,
            authoritative,
            requestedBytes,
            investigation,
            global,
            maintenance,
            brokerReconciliation,
            baseline: Object.freeze({
                investigationBytes: telemetry.investigation.bytes,
                globalBytes: telemetry.global.bytes,
            }),
        });
    }

    reconcileWrite(reservation) {
        if (reservation === null
            || typeof reservation !== "object"
            || reservation.baseline === null
            || typeof reservation.baseline !== "object") {
            throw new InvalidArgumentError("storage reservation is invalid");
        }
        const telemetry = this.telemetry();
        const brokerReconciliation = this.#reconcileBrokerStorage(
            telemetry,
            "write",
        );
        return Object.freeze({
            investigationDeltaBytes: Math.max(
                0,
                telemetry.investigation.bytes
                    - reservation.baseline.investigationBytes,
            ),
            globalDeltaBytes: Math.max(
                0,
                telemetry.global.bytes - reservation.baseline.globalBytes,
            ),
            brokerReconciliation,
            telemetry,
        });
    }
}

export function createWorkingSetController(options = {}) {
    return new WorkingSetController(options);
}

export function publicWorkingSetTelemetry(telemetry) {
    if (telemetry === null || typeof telemetry !== "object") return null;
    const budget = (value) => value === null || typeof value !== "object"
        ? null
        : {
            current_bytes: value.currentBytes,
            limit_bytes: value.limitBytes,
            effective_limit_bytes: value.effectiveLimitBytes,
            remaining_bytes: value.remainingBytes,
            warning_bytes: value.warningBytes,
            pressure: value.pressure,
        };
    return Object.freeze({
        investigation: Object.freeze({
            bytes: telemetry.investigation.bytes,
            files: telemetry.investigation.files,
            directories: telemetry.investigation.directories,
            unsafe_entries: telemetry.investigation.unsafeEntries,
            budget: budget(telemetry.investigation.budget),
        }),
        global: Object.freeze({
            bytes: telemetry.global.bytes,
            files: telemetry.global.files,
            directories: telemetry.global.directories,
            unsafe_entries: telemetry.global.unsafeEntries,
            budget: budget(telemetry.global.budget),
        }),
        repository: telemetry.repository === null
            ? null
            : Object.freeze({
                database_bytes: telemetry.repository.databaseBytes,
                wal_bytes: telemetry.repository.walBytes,
                shared_memory_bytes:
                    telemetry.repository.sharedMemoryBytes,
                sealed_segment_bytes:
                    telemetry.repository.sealedSegmentBytes,
                sealed_segment_count:
                    telemetry.repository.sealedSegmentCount,
                active_event_count:
                    telemetry.repository.activeEventCount,
                active_stored_bytes:
                    telemetry.repository.activeStoredBytes,
                thresholds: telemetry.repository.thresholds,
            }),
        artifacts: telemetry.artifacts === null
            ? null
            : Object.freeze({
                total_bytes: telemetry.artifacts.totalBytes,
                total_files: telemetry.artifacts.totalFiles,
                object_bytes: telemetry.artifacts.objectBytes,
                object_count: telemetry.artifacts.objectCount,
                staging_bytes: telemetry.artifacts.stagingBytes,
                staging_count: telemetry.artifacts.stagingCount,
                journal_bytes: telemetry.artifacts.journalBytes,
                journal_count: telemetry.artifacts.journalCount,
                quarantine_bytes: telemetry.artifacts.quarantineBytes,
                quarantine_count: telemetry.artifacts.quarantineCount,
            }),
        thresholds: telemetry.thresholds,
        diagnostics: telemetry.diagnostics,
    });
}
