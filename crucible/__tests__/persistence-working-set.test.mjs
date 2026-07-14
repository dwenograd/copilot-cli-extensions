import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
    DEFAULT_WORKING_SET_POLICY,
} from "../domain/index.mjs";
import {
    ERROR_CODES,
    canonicalize,
    createWorkingSetController,
    evaluateStorageBudget,
    exportBundle,
    openArtifactStore,
    openRepository,
    publicWorkingSetTelemetry,
    reconcileWorkingSetArtifacts,
} from "../persistence/index.mjs";
import {
    assertPublicToolPayload,
} from "../api/result.mjs";
import {
    DEFAULT_RESOURCE_BROKER_CONFIG,
    formatAttemptCommand,
    openResourceBroker,
} from "../runtime/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const INVESTIGATION_ID = "working-set-investigation";
const roots = [];

afterEach(() => {
    vi.restoreAllMocks();
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 20,
            retryDelay: 25,
        });
    }
});

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.working-set-${label}-`),
    );
    roots.push(root);
    return root;
}

function layout(root, label = INVESTIGATION_ID) {
    const investigationDir = path.join(root, label);
    const stateDir = path.join(investigationDir, "state");
    const artifactRoot = path.join(investigationDir, "artifacts");
    fs.mkdirSync(stateDir, { recursive: true });
    return {
        investigationDir,
        stateDir,
        artifactRoot,
        dbFile: path.join(stateDir, "events.sqlite"),
    };
}

function workingSetPolicy(overrides = {}) {
    return {
        ...structuredClone(DEFAULT_WORKING_SET_POLICY),
        perAttemptBytes: 1024 * 1024,
        perInvestigationBytes: 128 * 1024 * 1024,
        terminalReserveBytes: 1024 * 1024,
        walCheckpointBytes: 1,
        walCheckpointIntervalMs: 1,
        segmentEventThreshold: 1,
        segmentByteThreshold: 1,
        maintenanceIntervalMs: 1,
        orphanGraceMs: 0,
        ...overrides,
        diagnosticRetention: {
            ...structuredClone(
                DEFAULT_WORKING_SET_POLICY.diagnosticRetention,
            ),
            ...(overrides.diagnosticRetention ?? {}),
        },
    };
}

function openFixture(root, {
    storeOptions = {},
    repositoryOptions = {},
} = {}) {
    const paths = layout(root);
    const repository = openRepository({
        file: paths.dbFile,
        segmentEventThreshold: 1,
        walCheckpointBytes: 64 * 1024 * 1024,
        ...repositoryOptions,
    });
    repository.ensureInvestigation({
        investigationId: INVESTIGATION_ID,
        metadata: { domainVersion: 4 },
    });
    const store = openArtifactStore({
        root: paths.artifactRoot,
        ...storeOptions,
    });
    return { paths, repository, store };
}

function registerExternal(repository, store, bytes, artifactId, contentType) {
    const stored = store.putBytes(bytes, { contentType });
    repository.registerExternalArtifact({
        investigationId: INVESTIGATION_ID,
        artifactId,
        algo: "sha256",
        hash: stored.hash,
        sizeBytes: stored.size,
        contentType,
    });
    repository.markArtifactDurable(artifactId);
    return stored;
}

function age(file, milliseconds = 120_000) {
    const old = new Date(Date.now() - milliseconds);
    fs.utimesSync(file, old, old);
}

function appendReferencedEvent(repository, artifactIds, payload = {}) {
    return repository.appendEvents({
        investigationId: INVESTIGATION_ID,
        expectedHead: repository.getHead(INVESTIGATION_ID).eventHash,
        events: [{
            kind: "evidence",
            payload,
            artifactIds,
        }],
    }).events[0];
}

function controller(root, paths, repository, store, overrides = {}) {
    return createWorkingSetController({
        repository,
        artifactStore: store,
        investigationId: INVESTIGATION_ID,
        investigationDir: paths.investigationDir,
        stateRoot: root,
        policy: workingSetPolicy(overrides.policy),
        globalLimitBytes: overrides.globalLimitBytes
            ?? 256 * 1024 * 1024,
        bundleDirs: overrides.bundleDirs ?? [],
    });
}

describe("bounded active working set", () => {
    it("checkpoints WAL outside transactions and exposes active thresholds", () => {
        const root = makeRoot("wal");
        let repository;
        let probeUnsafe = false;
        let unsafeError = null;
        const clock = { value: 0 };
        const fixture = openFixture(root, {
            repositoryOptions: {
                wallClock: () => clock.value,
                walCheckpointBytes: 64 * 1024 * 1024,
                walCheckpointIntervalMs: 10,
                now: () => {
                    if (probeUnsafe) {
                        probeUnsafe = false;
                        try {
                            repository.checkpointWal({ force: true });
                        } catch (error) {
                            unsafeError = error;
                        }
                    }
                    return "2026-07-13T12:00:00.000Z";
                },
            },
        });
        ({ repository } = fixture);
        try {
            probeUnsafe = true;
            repository.putInlineArtifact({
                investigationId: INVESTIGATION_ID,
                artifactId: "inline-wal",
                bytes: Buffer.alloc(256 * 1024, 0x41),
            });
            expect(unsafeError).toMatchObject({
                code: ERROR_CODES.WAL_CHECKPOINT_UNSAFE,
            });
            const before = repository.getStorageTelemetry(
                INVESTIGATION_ID,
            );
            expect(before.walBytes).toBeGreaterThan(0);
            expect(before.thresholds).toMatchObject({
                walCheckpointBytes: 64 * 1024 * 1024,
                walCheckpointIntervalMs: 10,
                segmentEventCount: 1,
            });

            const forced = repository.checkpointWal({
                force: true,
                mode: "TRUNCATE",
                reason: "test",
            });
            expect(forced).toMatchObject({
                checkpointed: true,
                reason: "test",
                mode: "TRUNCATE",
                busy: 0,
            });
            expect(forced.afterBytes).toBeLessThanOrEqual(
                forced.beforeBytes,
            );

            clock.value = 20;
            repository.putInlineArtifact({
                investigationId: INVESTIGATION_ID,
                artifactId: "inline-periodic",
                bytes: Buffer.from("periodic"),
            });
            expect(repository.getStorageTelemetry(INVESTIGATION_ID)
                .lastCheckpoint).toMatchObject({
                    checkpointed: true,
                    reason: "transaction",
                });
        } finally {
            repository.close();
        }
    });

    it("preserves every referenced evidence class across sealed segments and removes only an orphan", () => {
        const root = makeRoot("evidence");
        const { paths, repository, store } = openFixture(root);
        const contentTypes = [
            "application/vnd.crucible.proposal+json",
            "application/vnd.crucible.measurement-receipt+json",
            "application/vnd.crucible.measurement-stdout",
            "application/vnd.crucible.control+json",
            "application/vnd.crucible.confirmation+json",
            "application/vnd.crucible.proof+json",
        ];
        const artifacts = contentTypes.map((contentType, index) =>
            registerExternal(
                repository,
                store,
                Buffer.from(`evidence-${index}`),
                `artifact-${index}`,
                contentType,
            ));
        const orphan = store.putBytes(Buffer.from("true-orphan"));
        for (const artifact of [...artifacts, orphan]) age(artifact.path);
        appendReferencedEvent(
            repository,
            artifacts.map((_artifact, index) => `artifact-${index}`),
            {
                proposalObject: artifacts[0].id,
                rawBlockObject: artifacts[2].id,
                controlObject: artifacts[3].id,
                confirmationObject: artifacts[4].id,
                proofObject: artifacts[5].id,
            },
        );
        repository.rotateEventSegment({
            investigationId: INVESTIGATION_ID,
            quiescent: true,
        });
        try {
            const maintained = controller(
                root,
                paths,
                repository,
                store,
            ).maintain({ force: true, quiescent: true });
            expect(maintained.artifacts.reconciliation.removedObjects)
                .toContain(orphan.id);
            for (const artifact of artifacts) {
                expect(store.verifyObject(artifact.id).ok).toBe(true);
                expect(maintained.artifacts.reconciliation.removedObjects)
                    .not.toContain(artifact.id);
            }
            expect(maintained.telemetry.repository.sealedSegmentCount)
                .toBeGreaterThanOrEqual(1);
        } finally {
            repository.close();
        }
    });

    it("protects an unresolved recovery capsule at zero grace and releases it only after recovery commit", () => {
        const root = makeRoot("recovery-capsule");
        const fixture = openFixture(root);
        const { paths, store } = fixture;
        let repository = fixture.repository;
        try {
        const logicalEffectKey =
            `sha256:crucible-runtime-logical-effect-v1:${"a".repeat(64)}`;
        const effect = {
            kind: "replicate-measurement",
            commandId: "cmd-recovery-capsule",
            blockIndex: 0,
            armIndex: 0,
        };
        const attemptId = "effect-attempt";
        const artifactId = "runtime-effect-capsule-test";
        const attemptCommand = canonicalize(formatAttemptCommand("external-effect", {
            logicalEffectKey,
            effect,
        }));
        const firstLease = repository.acquireLease({
            investigationId: INVESTIGATION_ID,
            leaseId: "lease-1",
            owner: "runner-1",
        });
        const firstAuthority = {
            investigationId: INVESTIGATION_ID,
            attemptId,
            leaseId: firstLease.leaseId,
            fencingToken: firstLease.fencingToken,
            owner: firstLease.owner,
        };
        repository.reserveCommand({
            ...firstAuthority,
            command: attemptCommand,
        });
        repository.dispatchCommand(firstAuthority);
        repository.observeCommand(firstAuthority);

        const capsuleBytes = Buffer.from(JSON.stringify({
            kind: "crucible-runtime-effect-recovery",
            logicalEffectKey,
            effectAttemptId: attemptId,
        }));
        let stored;
        store.withGenerationLock(() => {
            stored = store.putBytes(capsuleBytes, {
                contentType:
                    "application/vnd.crucible.effect-recovery+json",
            });
            expect(() => repository.bindRecoveryCapsuleArtifact({
                ...firstAuthority,
                attemptCommand,
                logicalEffectKey: `${logicalEffectKey}-wrong`,
                artifactId: `${artifactId}-unbound`,
                algo: "sha256",
                hash: stored.hash,
                sizeBytes: stored.size,
            })).toThrow();
            expect(repository.getArtifact(`${artifactId}-unbound`)).toBeNull();
            repository.bindRecoveryCapsuleArtifact({
                ...firstAuthority,
                attemptCommand,
                logicalEffectKey,
                artifactId,
                algo: "sha256",
                hash: stored.hash,
                sizeBytes: stored.size,
            });
        });
        expect(repository.getArtifact(artifactId)).toMatchObject({
            durable: true,
            hashValue: stored.hash,
        });
        expect(repository.listArtifactRefs(INVESTIGATION_ID)).toEqual([
            expect.objectContaining({
                artifactId,
                seq: null,
            }),
        ]);
        age(stored.path);

        repository.close();
        repository = openRepository({ file: paths.dbFile });
        const recoveredStore = openArtifactStore({
            root: paths.artifactRoot,
        });
        const workingSet = controller(
            root,
            paths,
            repository,
            recoveredStore,
            { policy: { orphanGraceMs: 0 } },
        );
        const startup = workingSet.maintain({
                force: true,
                quiescent: true,
            });
            expect(startup.artifacts.scan).toMatchObject({
                transientRecoveryCapsules: 1,
            });
            expect(startup.artifacts.reconciliation.installations
                .transientReferenced).toContain(stored.id);
            expect(recoveredStore.verifyObject(stored.id).ok).toBe(true);

            const recoveryLease = repository.acquireLease({
                investigationId: INVESTIGATION_ID,
                leaseId: "lease-2",
                owner: "runner-2",
            });
            const recoveryAuthority = {
                investigationId: INVESTIGATION_ID,
                leaseId: recoveryLease.leaseId,
                fencingToken: recoveryLease.fencingToken,
                owner: recoveryLease.owner,
            };
            repository.abandonStaleCommand({
                ...recoveryAuthority,
                attemptId,
            });
            const resolutionAttemptId = "effect-recovery-attempt";
            const resolutionCommand = canonicalize(formatAttemptCommand(
                "external-effect",
                {
                    logicalEffectKey,
                    effect,
                    recoveredFromAttemptId: attemptId,
                    recoveryCapsuleArtifactId: artifactId,
                },
            ));
            const resolutionAuthority = {
                ...recoveryAuthority,
                attemptId: resolutionAttemptId,
            };
            repository.reserveCommand({
                ...resolutionAuthority,
                command: resolutionCommand,
            });
            repository.dispatchCommand(resolutionAuthority);
            repository.observeCommand(resolutionAuthority);
            repository.commitCommand(resolutionAuthority);
            const released = repository.releaseRecoveryCapsuleReference({
                investigationId: INVESTIGATION_ID,
                sourceAttemptId: attemptId,
                resolutionAttemptId,
                logicalEffectKey,
                artifactId,
            });
            expect(released).toMatchObject({
                released: true,
                releasedReferences: 1,
            });
            expect(repository.listArtifactRefs(INVESTIGATION_ID)).toEqual([]);

            const resolved = workingSet.maintain({
                force: true,
                quiescent: true,
            });
            expect(resolved.artifacts.reconciliation.removedObjects)
                .toContain(stored.id);
            expect(recoveredStore.verifyObject(stored.id).ok).toBe(false);
        } finally {
            try {
                repository.close();
            } catch {
                // The simulated crash closes the first repository instance.
            }
        }
    });

    it("recovers a journal crash, protects current staging, and removes stale unowned staging", () => {
        const root = makeRoot("journal");
        const paths = layout(root);
        const repository = openRepository({ file: paths.dbFile });
        repository.ensureInvestigation({
            investigationId: INVESTIGATION_ID,
            metadata: { domainVersion: 4 },
        });
        const bytes = Buffer.from("journalled-reference");
        const objectId = `sha256:${
            createHash("sha256").update(bytes).digest("hex")
        }`;
        let injected = false;
        const crashing = openArtifactStore({
            root: paths.artifactRoot,
            faultInjector(event) {
                if (!injected
                    && event.point === "staging-journal-durable") {
                    injected = true;
                    throw new Error("crash");
                }
            },
        });
        expect(() => crashing.putBytes(bytes)).toThrow();
        appendReferencedEvent(repository, [], {
            journalledObject: objectId,
        });

        const stale = path.join(
            paths.artifactRoot,
            "staging",
            "stale-unowned.tmp",
        );
        fs.writeFileSync(stale, "stale");
        age(stale);
        const recovered = openArtifactStore({ root: paths.artifactRoot });
        try {
            const report = reconcileWorkingSetArtifacts({
                repository,
                artifactStore: recovered,
                investigationId: INVESTIGATION_ID,
                olderThanMs: 0,
                now: Date.now(),
            });
            expect(report.reconciliation.referenced.ok)
                .toContain(objectId);
            expect(recovered.verifyObject(objectId).ok).toBe(true);
            expect(report.reconciliation.removedStaging)
                .toContain("stale-unowned.tmp");
        } finally {
            repository.close();
        }
    });

    it("does not sweep staging owned by a current installation journal", () => {
        const root = makeRoot("current-staging");
        const { repository, store: _unusedStore, paths } =
            openFixture(root);
        let injected = false;
        const crashing = openArtifactStore({
            root: paths.artifactRoot,
            faultInjector(event) {
                if (!injected
                    && event.point === "staging-journal-durable") {
                    injected = true;
                    throw new Error("crash");
                }
            },
        });
        expect(() => crashing.putBytes(
            Buffer.from("current-journal-stage"),
        )).toThrow();
        const stagingBefore = fs.readdirSync(
            path.join(paths.artifactRoot, "staging"),
        ).filter((name) => name.endsWith(".tmp"));
        const quarantine = path.join(
            paths.artifactRoot,
            ".crucible",
            "quarantine",
            "operational-diagnostic.corrupt",
        );
        fs.writeFileSync(quarantine, "diagnostic");
        age(quarantine, 2 * 60 * 60 * 1000);
        const recovered = openArtifactStore({ root: paths.artifactRoot });
        try {
            const report = reconcileWorkingSetArtifacts({
                repository,
                artifactStore: recovered,
                investigationId: INVESTIGATION_ID,
                olderThanMs: 60 * 60 * 1000,
                now: Date.now(),
            });
            expect(report.reconciliation.installations.pending)
                .toHaveLength(1);
            expect(report.reconciliation.removedStaging)
                .toEqual([]);
            expect(report.reconciliation.installations.deferredQuarantine)
                .toContain("operational-diagnostic.corrupt");
            expect(fs.existsSync(quarantine)).toBe(true);
            for (const name of stagingBefore) {
                expect(fs.existsSync(path.join(
                    paths.artifactRoot,
                    "staging",
                    name,
                ))).toBe(true);
            }
        } finally {
            repository.close();
        }
    });

    it("rechecks repository references after a CAS deletion race", () => {
        const root = makeRoot("race");
        const paths = layout(root);
        const repository = openRepository({ file: paths.dbFile });
        repository.ensureInvestigation({
            investigationId: INVESTIGATION_ID,
            metadata: { domainVersion: 4 },
        });
        const writer = openArtifactStore({ root: paths.artifactRoot });
        const stored = registerExternal(
            repository,
            writer,
            Buffer.from("raced-reference"),
            "race-artifact",
            "application/octet-stream",
        );
        age(stored.path);
        let raced = false;
        const sweeper = openArtifactStore({
            root: paths.artifactRoot,
            faultInjector(event) {
                if (!raced
                    && event.point === "before-reconcile-object-delete"
                    && event.object === stored.id) {
                    raced = true;
                    repository.referenceArtifact({
                        investigationId: INVESTIGATION_ID,
                        artifactId: "race-artifact",
                    });
                }
            },
        });
        try {
            const report = reconcileWorkingSetArtifacts({
                repository,
                artifactStore: sweeper,
                investigationId: INVESTIGATION_ID,
                olderThanMs: 0,
                now: Date.now(),
            });
            expect(raced).toBe(true);
            expect(report.reconciliation.removedObjects)
                .not.toContain(stored.id);
            expect(sweeper.verifyObject(stored.id).ok).toBe(true);
        } finally {
            repository.close();
        }
    });

    it("expands a snapshot closure introduced during the final deletion race probe", () => {
        const root = makeRoot("snapshot-race");
        const paths = layout(root);
        const repository = openRepository({ file: paths.dbFile });
        repository.ensureInvestigation({
            investigationId: INVESTIGATION_ID,
            metadata: { domainVersion: 4 },
        });
        const writer = openArtifactStore({ root: paths.artifactRoot });
        const source = path.join(root, "snapshot-source");
        fs.mkdirSync(source);
        fs.writeFileSync(path.join(source, "candidate.bin"), "candidate");
        const snapshot = writer.ingestDirectory({ sourceDir: source });
        const childId = snapshot.manifest.entries[0].object;
        repository.registerExternalArtifact({
            investigationId: INVESTIGATION_ID,
            artifactId: "snapshot-manifest-artifact",
            algo: "sha256",
            hash: snapshot.snapshot.slice("sha256:".length),
            sizeBytes: writer.verifyObject(snapshot.snapshot).size,
            contentType: "application/vnd.crucible.snapshot+json",
        });
        repository.markArtifactDurable("snapshot-manifest-artifact");
        age(writer.objectPath(childId));

        let raced = false;
        const sweeper = openArtifactStore({
            root: paths.artifactRoot,
            faultInjector(event) {
                if (!raced
                    && event.point === "before-reconcile-object-delete"
                    && event.object === childId) {
                    raced = true;
                    repository.referenceArtifact({
                        investigationId: INVESTIGATION_ID,
                        artifactId: "snapshot-manifest-artifact",
                    });
                }
            },
        });
        try {
            const report = reconcileWorkingSetArtifacts({
                repository,
                artifactStore: sweeper,
                investigationId: INVESTIGATION_ID,
                olderThanMs: 60_000,
                now: Date.now(),
            });
            expect(raced).toBe(true);
            expect(report.reconciliation.removedObjects)
                .not.toContain(childId);
            expect(sweeper.verifyObject(childId).ok).toBe(true);
            expect(sweeper.verifyObject(snapshot.snapshot).ok).toBe(true);
        } finally {
            repository.close();
        }
    });

    it("preserves CAS objects referenced only by an authenticated bundle catalog scan", () => {
        const root = makeRoot("bundle");
        const sourceRoot = path.join(root, "source");
        const targetRoot = path.join(root, "target");
        fs.mkdirSync(sourceRoot, { recursive: true });
        fs.mkdirSync(targetRoot, { recursive: true });
        const source = openFixture(sourceRoot);
        const target = openFixture(targetRoot);
        const bytes = Buffer.from("bundle-only-reference");
        const sourceObject = registerExternal(
            source.repository,
            source.store,
            bytes,
            "bundle-artifact",
            "application/octet-stream",
        );
        appendReferencedEvent(source.repository, ["bundle-artifact"]);
        const bundleDir = path.join(root, "bundle");
        exportBundle({
            store: source.store,
            dbFile: source.paths.dbFile,
            destDir: bundleDir,
            investigationId: INVESTIGATION_ID,
        });
        const targetObject = target.store.putBytes(bytes);
        age(targetObject.path);
        try {
            const maintained = controller(
                targetRoot,
                target.paths,
                target.repository,
                target.store,
                { bundleDirs: [bundleDir] },
            ).maintain({ force: true, quiescent: true });
            expect(targetObject.id).toBe(sourceObject.id);
            expect(maintained.artifacts.reconciliation.removedObjects)
                .not.toContain(targetObject.id);
            expect(target.store.verifyObject(targetObject.id).ok).toBe(true);

            const deferredOrphan = target.store.putBytes(
                Buffer.from("defer-on-risk"),
            );
            age(deferredOrphan.path);
            fs.writeFileSync(
                path.join(bundleDir, "manifest.json"),
                "{\"tampered\":true}\n",
            );
            const deferred = reconcileWorkingSetArtifacts({
                repository: target.repository,
                artifactStore: target.store,
                investigationId: INVESTIGATION_ID,
                bundleDirs: [bundleDir],
                olderThanMs: 0,
                now: Date.now(),
            });
            expect(deferred).toMatchObject({
                deferred: true,
                reason: "reference_scan_failed",
                reconciliation: null,
            });
            expect(target.store.verifyObject(deferredOrphan.id).ok)
                .toBe(true);
        } finally {
            source.repository.close();
            target.repository.close();
        }
    });

    it("treats concurrent telemetry removals and directory replacement as disappeared entries", () => {
        const root = makeRoot("telemetry-race");
        const { paths, repository, store } = openFixture(root);
        const removedFile = path.join(
            paths.investigationDir,
            "supervisor-atomic-remove.tmp",
        );
        const replacedDir = path.join(
            paths.investigationDir,
            "supervisor-atomic-directory",
        );
        const replacedChild = path.join(replacedDir, "child.tmp");
        fs.writeFileSync(removedFile, "remove");
        fs.mkdirSync(replacedDir);
        fs.writeFileSync(replacedChild, "replace");
        const originalLstat = fs.lstatSync.bind(fs);
        let removalObserved = false;
        let replacementObserved = false;
        const regularSpy = vi.spyOn(fs, "lstatSync")
            .mockImplementation((candidate, ...args) => {
                const resolved = path.resolve(String(candidate));
                if (!removalObserved && resolved === path.resolve(removedFile)) {
                    removalObserved = true;
                    fs.rmSync(removedFile);
                } else if (!replacementObserved
                    && resolved === path.resolve(replacedChild)) {
                    replacementObserved = true;
                    fs.renameSync(replacedDir, `${replacedDir}.moved`);
                    fs.writeFileSync(replacedDir, "replacement-file");
                }
                return originalLstat(candidate, ...args);
            });
        try {
            expect(() => controller(
                root,
                paths,
                repository,
                store,
            ).telemetry()).not.toThrow();
            expect(removalObserved).toBe(true);
            expect(replacementObserved).toBe(true);
        } finally {
            regularSpy.mockRestore();
        }

        const artifactTemp = path.join(
            paths.artifactRoot,
            "staging",
            "supervisor-atomic-rename.tmp",
        );
        fs.writeFileSync(artifactTemp, "rename");
        let renameObserved = false;
        const artifactSpy = vi.spyOn(fs, "lstatSync")
            .mockImplementation((candidate, ...args) => {
                const resolved = path.resolve(String(candidate));
                if (!renameObserved && resolved === path.resolve(artifactTemp)) {
                    renameObserved = true;
                    fs.renameSync(artifactTemp, `${artifactTemp}.renamed`);
                }
                return originalLstat(candidate, ...args);
            });
        try {
            expect(() => store.storageTelemetry()).not.toThrow();
            expect(renameObserved).toBe(true);
        } finally {
            artifactSpy.mockRestore();
            repository.close();
        }
    });

    it("fails before deletion when telemetry encounters a non-disappearance error", () => {
        const root = makeRoot("telemetry-fail-closed");
        const { paths, repository, store } = openFixture(root);
        const orphan = store.putBytes(Buffer.from("must-survive-scan-error"));
        age(orphan.path);
        const originalLstat = fs.lstatSync.bind(fs);
        const blockedPath = path.resolve(orphan.path);
        const spy = vi.spyOn(fs, "lstatSync")
            .mockImplementation((candidate, ...args) => {
                if (path.resolve(String(candidate)) === blockedPath) {
                    throw Object.assign(new Error("access denied"), {
                        code: "EACCES",
                    });
                }
                return originalLstat(candidate, ...args);
            });
        try {
            expect(() => controller(
                root,
                paths,
                repository,
                store,
            ).maintain({
                force: true,
                quiescent: true,
            })).toThrow(/access denied/u);
            expect(fs.existsSync(orphan.path)).toBe(true);
        } finally {
            spy.mockRestore();
            repository.close();
        }
    });

    it("keeps fixture-owned working-set roots from scanning sibling test roots", () => {
        const sharedRoot = makeRoot("root-ownership");
        const investigationDir = path.join(sharedRoot, "fixture-owned-root");
        const stateDir = path.join(investigationDir, "state");
        const artifactRoot = path.join(investigationDir, "artifacts");
        const unrelatedRoot = path.join(sharedRoot, "unrelated-test-root");
        fs.mkdirSync(stateDir, { recursive: true });
        fs.mkdirSync(unrelatedRoot);
        fs.writeFileSync(
            path.join(unrelatedRoot, "must-not-be-scanned.bin"),
            Buffer.alloc(4 * 1024 * 1024, 0x5a),
        );
        const repository = openRepository({
            file: path.join(stateDir, "events.sqlite"),
        });
        repository.ensureInvestigation({
            investigationId: INVESTIGATION_ID,
        });
        const store = openArtifactStore({ root: artifactRoot });
        const options = {
            repository,
            artifactStore: store,
            investigationId: INVESTIGATION_ID,
            investigationDir,
            policy: workingSetPolicy(),
            globalLimitBytes: 256 * 1024 * 1024,
        };
        try {
            expect(() => createWorkingSetController({
                ...options,
                stateRoot: sharedRoot,
            })).toThrow(/controller-owned root/u);
            const telemetry = createWorkingSetController({
                ...options,
                stateRoot: investigationDir,
            }).telemetry();
            expect(telemetry.global.bytes).toBe(telemetry.investigation.bytes);
            expect(telemetry.global.bytes).toBeLessThan(4 * 1024 * 1024);
        } finally {
            repository.close();
        }
    });

    it("admits the exact physical boundary, preserves terminal reserve, and redacts status telemetry", () => {
        expect(evaluateStorageBudget({
            currentBytes: 90,
            requestedBytes: 5,
            limitBytes: 100,
            warningBasisPoints: 9_000,
            terminalReserveBytes: 5,
        })).toMatchObject({
            admitted: true,
            exactBoundary: true,
            projectedBytes: 95,
            effectiveLimitBytes: 95,
        });
        expect(evaluateStorageBudget({
            currentBytes: 90,
            requestedBytes: 6,
            limitBytes: 100,
            warningBasisPoints: 9_000,
            terminalReserveBytes: 5,
        })).toMatchObject({
            admitted: false,
            pressure: "exhausted",
        });
        expect(evaluateStorageBudget({
            currentBytes: 96,
            requestedBytes: 4,
            limitBytes: 100,
            warningBasisPoints: 9_000,
            terminalReserveBytes: 5,
            terminalReady: true,
        })).toMatchObject({
            admitted: true,
            exactBoundary: true,
        });

        const storage = publicWorkingSetTelemetry({
            investigation: {
                bytes: 42,
                files: 3,
                directories: 2,
                unsafeEntries: 0,
                budget: evaluateStorageBudget({
                    currentBytes: 42,
                    limitBytes: 100,
                    warningBasisPoints: 9_000,
                    terminalReserveBytes: 5,
                }),
            },
            global: {
                bytes: 84,
                files: 6,
                directories: 4,
                unsafeEntries: 0,
                budget: evaluateStorageBudget({
                    currentBytes: 84,
                    limitBytes: 200,
                    warningBasisPoints: 9_000,
                }),
            },
            repository: {
                databaseBytes: 10,
                walBytes: 2,
                sharedMemoryBytes: 1,
                sealedSegmentBytes: 8,
                sealedSegmentCount: 2,
                activeEventCount: 3,
                activeStoredBytes: 4,
                thresholds: {
                    walCheckpointBytes: 16,
                    segmentEventCount: 10,
                    segmentStoredBytes: 100,
                },
            },
            artifacts: {
                totalBytes: 20,
                totalFiles: 2,
                objectBytes: 15,
                objectCount: 1,
                stagingBytes: 0,
                stagingCount: 0,
                journalBytes: 0,
                journalCount: 0,
                quarantineBytes: 0,
                quarantineCount: 0,
            },
            thresholds: {
                perAttemptBytes: 10,
                perInvestigationBytes: 100,
                globalBytes: 200,
            },
            diagnostics: {
                retentionMode: "defer",
                cleanupDeferred: true,
            },
        });
        const payload = assertPublicToolPayload("crucible_status", {
            is_result: false,
            investigation_id: INVESTIGATION_ID,
            terminal_available: false,
            storage,
        });
        expect(payload.storage.investigation.bytes).toBe(42);
        const serialized = JSON.stringify(payload);
        for (const forbidden of [
            "candidate_id",
            "winner",
            "evidence_id",
            "evidence_hash",
            "decision",
            "VERIFIED_RESULT",
            "TARGET_UNREACHABLE",
        ]) {
            expect(serialized).not.toContain(forbidden);
        }
    });

    it("reconciles current physical bytes downward through the global broker", () => {
        const root = makeRoot("broker-reconcile");
        const { paths, repository, store } = openFixture(root);
        const broker = openResourceBroker({
            stateRoot: root,
            config: DEFAULT_RESOURCE_BROKER_CONFIG,
        });
        broker.registerInvestigation({
            investigationId: INVESTIGATION_ID,
            limits: {
                sdkSessions: 1,
                sandboxProcesses: 1,
                cpuSlots: { general: 1 },
                gpuSlots: {},
                outputBytes: 16 * 1024 * 1024,
                receiptBytes: 16 * 1024 * 1024,
                casBytes: 64 * 1024 * 1024,
                storageBytes: 128 * 1024 * 1024,
                modelCostUnits: 1_000_000,
            },
            supervisorGeneration: 1,
            supervisorNonce: "working-set-supervisor",
            runnerIncarnation: "working-set-runner-1",
        });
        const workingSet = createWorkingSetController({
            repository,
            artifactStore: store,
            investigationId: INVESTIGATION_ID,
            investigationDir: paths.investigationDir,
            stateRoot: root,
            policy: workingSetPolicy(),
            globalLimitBytes:
                DEFAULT_RESOURCE_BROKER_CONFIG.capacities.storageBytes,
            resourceBroker: broker,
            resourceAuthority: {
                supervisorGeneration: 1,
                runnerIncarnation: "working-set-runner-1",
            },
        });
        const diagnostic = path.join(
            paths.investigationDir,
            "non-authoritative-diagnostic.bin",
        );
        try {
            fs.writeFileSync(diagnostic, Buffer.alloc(256 * 1024, 0x5a));
            const high = workingSet.maintain({
                force: true,
                quiescent: true,
            }).telemetry.investigation.bytes;
            expect(broker.getStorageBudgetSnapshot(INVESTIGATION_ID)
                .investigation.committedUnits).toBe(high);

            fs.rmSync(diagnostic);
            const low = workingSet.maintain({
                force: true,
                quiescent: true,
            }).telemetry.investigation.bytes;
            expect(low).toBeLessThan(high);
            expect(broker.getStorageBudgetSnapshot(INVESTIGATION_ID)
                .investigation.committedUnits).toBe(low);
        } finally {
            broker.close();
            repository.close();
        }
    });
});
