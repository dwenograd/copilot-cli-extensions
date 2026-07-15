import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";

import { afterEach, describe, expect, it } from "vitest";

import {
    archiveInvestigation,
    assertInvestigationIdentityAvailable,
    deleteInvestigation,
    listLifecycleInvestigations,
    resolveLifecycleTarget,
} from "../api/lifecycle.mjs";
import { resolveRetentionPaths } from "../api/environment.mjs";
import {
    canonicalize,
    writeSignedTombstone,
} from "../persistence/index.mjs";

const roots = [];
const DIGEST = `sha256:${"a".repeat(64)}`;
const HEAD = Object.freeze({
    seq: 2,
    eventHash: `sha256:crucible-event-v4:${"b".repeat(64)}`,
});

function cleanupRelativePath(investigationId, archiveDigest) {
    const digest = createHash("sha256")
        .update("crucible-delete-cleanup-v2\0")
        .update(investigationId)
        .update("\0")
        .update(archiveDigest)
        .digest("hex");
    return `.retention/archives/cleanup-${digest}`;
}

function markerDigest({
    investigationId,
    archiveRelativePath,
    cleanupRelativePath: cleanupPath,
    archiveDigest,
    nonce,
}) {
    const document = {
        type: "crucible-delete-cleanup-marker",
        version: 1,
        investigationId,
        archiveRelativePath,
        cleanupRelativePath: cleanupPath,
        archiveDigest,
        nonce,
    };
    return `sha256:${createHash("sha256")
        .update(`${canonicalize(document)}\n`)
        .digest("hex")}`;
}

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(os.tmpdir(), `crucible-api-lifecycle-${label}-`),
    );
    roots.push(root);
    return root;
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 10,
            retryDelay: 20,
        });
    }
});

function archiveEntry(investigationId, overrides = {}) {
    return {
        investigationId,
        registeredAtMs: 1_000,
        lifecycleUpdatedAtMs: 2_000,
        lifecycleState: "archived",
        catalogGeneration: 1,
        lifecycleOperation: null,
        archive: {
            relativePath:
                `.retention/archives/${investigationId}`,
            digest: DIGEST,
            trustLevel: "authenticated",
            domainVersion: 4,
            terminalAvailable: false,
            integrityStatus: "verified",
            sizeBytes: 100,
            domainHead: HEAD,
            archivedAtMs: 2_000,
        },
        deleteCleanup: null,
        tombstone: null,
        ...overrides,
    };
}

function tombstoneEntry(investigationId) {
    return {
        investigationId,
        registeredAtMs: 1_000,
        lifecycleUpdatedAtMs: 3_000,
        lifecycleState: "tombstoned",
        catalogGeneration: 1,
        lifecycleOperation: null,
        archive: null,
        deleteCleanup: null,
        tombstone: {
            relativePath:
                `.retention/tombstones/${investigationId}.json`,
            digest: `sha256:${"c".repeat(64)}`,
            signingKeyFingerprint:
                `sha256:crucible-tombstone-signing-key-v1:${
                    "d".repeat(64)
                }`,
            signature: "secret-signature",
            archiveDigest: DIGEST,
            domainVersion: 4,
            domainHead: HEAD,
            sizeBytes: 90,
            deletedAtMs: 3_000,
            integrityStatus: "verified",
        },
    };
}

function listBroker(entries) {
    return {
        close() {},
        getInvestigation(investigationId) {
            return entries.find((entry) =>
                entry.investigationId === investigationId) ?? null;
        },
        listInvestigations({
            lifecycleState = null,
            afterInvestigationId = null,
            limit = 50,
        } = {}) {
            const selected = entries
                .filter((entry) =>
                    (lifecycleState === null
                        || entry.lifecycleState === lifecycleState)
                    && (afterInvestigationId === null
                        || entry.investigationId
                            > afterInvestigationId))
                .sort((left, right) =>
                    left.investigationId < right.investigationId
                        ? -1
                        : 1);
            const result = limit === null
                ? selected
                : selected.slice(0, limit);
            Object.defineProperty(result, "catalogGeneration", {
                value: 1,
                enumerable: false,
            });
            return result;
        },
    };
}

function generationPage(entries, generation) {
    const page = [...entries];
    Object.defineProperty(page, "catalogGeneration", {
        value: generation,
        enumerable: false,
    });
    return page;
}

function archivedAuthorityDeps() {
    const authority = {
        identity: "signed-authority",
        manifest: {
            experimentPayload: {
                experimentId: "experiment",
                projectDir: "project",
                harnessSuiteId: "harness",
            },
        },
    };
    return {
        openRepositoryReadOnly: () => ({
            readOnly: true,
            getHead: () => HEAD,
            close() {},
        }),
        openArtifactStoreReadOnly: () => ({ readOnly: true }),
        createDomainRepositoryAdapter: () => ({
            replay: () => ({
                aggregate: {
                    experimentAuthority: authority,
                    experimentAuthorityIdentity: authority.identity,
                    contract: {},
                    terminal: { decision: "VERIFIED_RESULT" },
                    lastSeq: HEAD.seq,
                    lastEventHash: HEAD.eventHash,
                },
            }),
            verifyTerminalArtifactClosure: () => ({
                aggregate: {
                    experimentAuthority: authority,
                    experimentAuthorityIdentity: authority.identity,
                    contract: {},
                    terminal: { decision: "VERIFIED_RESULT" },
                    lastSeq: HEAD.seq,
                    lastEventHash: HEAD.eventHash,
                },
            }),
        }),
        verifyExperimentAuthority: () => true,
        assessPersistedTerminalReadiness: () => ({ ready: true }),
    };
}

describe("lifecycle status catalog", () => {
    it("paginates deterministically and redacts archive/tombstone internals", async () => {
        const stateRoot = makeRoot("list");
        const entries = [
            archiveEntry("catalog-c"),
            tombstoneEntry("catalog-b"),
            archiveEntry("catalog-a"),
        ];
        const deps = {
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
            pathExists: () => true,
            openResourceBrokerReadOnlyFromStateRoot: () =>
                listBroker(entries),
            ...archivedAuthorityDeps(),
            verifyBundleInPlace: ({ expectedInvestigationId }) => ({
                investigationId: expectedInvestigationId,
                domainVersion: 4,
                domainHead: HEAD,
                digest: DIGEST,
                trustLevel: "authenticated",
                authenticated: true,
                verified: true,
            }),
            verifySignedTombstone: () => ({
                verified: true,
                digest: `sha256:${"c".repeat(64)}`,
                sizeBytes: 90,
                signingKeyFingerprint:
                    `sha256:crucible-tombstone-signing-key-v1:${
                        "d".repeat(64)
                    }`,
                signature: "secret-signature",
                payload: {
                    createdAtMs: 1_000,
                    archiveDigest: DIGEST,
                    domainVersion: 4,
                    domainHead: HEAD,
                    deletedAt: new Date(3_000).toISOString(),
                },
            }),
            measureRetainedTree: () => ({
                sizeBytes: 100,
                fileCount: 2,
            }),
        };

        const first = await listLifecycleInvestigations({
            operation: "list",
            limit: 2,
        }, deps);
        expect(first.investigations.map((entry) =>
            entry.investigation_id)).toEqual([
            "catalog-a",
            "catalog-b",
        ]);
        expect(first).toMatchObject({
            is_result: false,
            operation: "list",
            has_more: true,
        });
        expect(typeof first.next_cursor).toBe("string");
        for (const entry of first.investigations) {
            expect(Object.keys(entry).sort()).toEqual([
                "created_at",
                "domain_version",
                "integrity_status",
                "investigation_id",
                "size_bytes",
                "state",
                "terminal_available",
                "updated_at",
            ]);
        }
        const serialized = JSON.stringify(first);
        for (const forbidden of [
            "secret-signature",
            "archiveDigest",
            "domainHead",
            "decision",
            "candidate",
            "cohort",
            "evidence",
            "statistics",
        ]) {
            expect(serialized).not.toContain(forbidden);
        }

        const second = await listLifecycleInvestigations({
            operation: "list",
            cursor: first.next_cursor,
            limit: 2,
        }, deps);
        expect(second.investigations.map((entry) =>
            entry.investigation_id)).toEqual(["catalog-c"]);
        expect(second).toMatchObject({
            next_cursor: null,
            has_more: false,
        });
        expect(() => listLifecycleInvestigations({
            operation: "list",
            cursor: first.next_cursor,
            limit: 2,
            state_filter: "archived",
        }, deps)).toThrow(/does not match/u);
    });

    it("retries a filesystem authority scan when catalog generation changes", () => {
        const stateRoot = makeRoot("generation-race");
        const investigationId = "generation-investigation";
        const archiveDir = path.join(
            stateRoot,
            ".retention",
            "archives",
            investigationId,
        );
        fs.mkdirSync(archiveDir, { recursive: true });
        fs.writeFileSync(path.join(archiveDir, "bundle"), "archive");
        const archived = archiveEntry(investigationId, {
            catalogGeneration: 1,
        });
        const tombstoned = tombstoneEntry(investigationId);
        tombstoned.catalogGeneration = 2;
        let call = 0;
        const broker = {
            close() {},
            listInvestigations() {
                call += 1;
                if (call === 1) {
                    return generationPage([archived], 1);
                }
                if (call === 2) {
                    fs.rmSync(archiveDir, {
                        recursive: true,
                        force: true,
                    });
                }
                return generationPage([tombstoned], 2);
            },
        };
        const result = listLifecycleInvestigations({
            operation: "list",
        }, {
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
            pathExists: () => true,
            openResourceBrokerReadOnlyFromStateRoot: () => broker,
            verifySignedTombstone: () => ({
                verified: true,
                digest: tombstoned.tombstone.digest,
                sizeBytes: tombstoned.tombstone.sizeBytes,
                signingKeyFingerprint:
                    tombstoned.tombstone.signingKeyFingerprint,
                signature: tombstoned.tombstone.signature,
                payload: {
                    createdAtMs: tombstoned.registeredAtMs,
                    archiveDigest:
                        tombstoned.tombstone.archiveDigest,
                    domainVersion:
                        tombstoned.tombstone.domainVersion,
                    domainHead: tombstoned.tombstone.domainHead,
                    deletedAt: new Date(
                        tombstoned.tombstone.deletedAtMs,
                    ).toISOString(),
                },
            }),
        });
        expect(result.investigations).toEqual([
            expect.objectContaining({
                investigation_id: investigationId,
                state: "tombstoned",
            }),
        ]);
        expect(call).toBeGreaterThanOrEqual(4);
    });

    it("retries a transient false orphan after a concurrent archive reservation", () => {
        const stateRoot = makeRoot("generation-orphan-race");
        const investigationId = "concurrent-archive";
        const archiveDir = path.join(
            stateRoot,
            ".retention",
            "archives",
            investigationId,
        );
        const archived = archiveEntry(investigationId, {
            catalogGeneration: 2,
        });
        let call = 0;
        const broker = {
            close() {},
            listInvestigations() {
                call += 1;
                if (call === 1) {
                    fs.mkdirSync(archiveDir, { recursive: true });
                    fs.writeFileSync(
                        path.join(archiveDir, "bundle"),
                        "archive",
                    );
                    return generationPage([], 1);
                }
                return generationPage([archived], 2);
            },
        };
        const result = listLifecycleInvestigations({
            operation: "list",
        }, {
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
            pathExists: () => true,
            openResourceBrokerReadOnlyFromStateRoot: () => broker,
            ...archivedAuthorityDeps(),
            verifyBundleInPlace: () => ({
                investigationId,
                domainVersion: 4,
                domainHead: HEAD,
                digest: DIGEST,
                authenticated: true,
                verified: true,
            }),
            measureRetainedTree: () => ({ sizeBytes: 100 }),
        });
        expect(result.investigations).toEqual([
            expect.objectContaining({
                investigation_id: investigationId,
                state: "archived",
            }),
        ]);
        expect(call).toBeGreaterThanOrEqual(4);
    });
});

class LifecycleBroker {
    constructor(investigationId) {
        this.investigationId = investigationId;
        this.entry = {
            investigationId,
            registeredAtMs: 1_000,
            lifecycleUpdatedAtMs: 1_000,
            lifecycleState: "active",
            catalogGeneration: 1,
            lifecycleOperation: null,
            archive: null,
            deleteCleanup: null,
            tombstone: null,
        };
        this.operation = null;
    }

    close() {}

    getInvestigation(investigationId) {
        return investigationId === this.investigationId
            ? this.entry
            : null;
    }

    listActiveLeases() {
        return [];
    }

    listInvestigations({ lifecycleState = null } = {}) {
        const result = lifecycleState === null
            || this.entry.lifecycleState === lifecycleState
            ? [this.entry]
            : [];
        Object.defineProperty(result, "catalogGeneration", {
            value: 1,
            enumerable: false,
        });
        return result;
    }

    beginLifecycleOperation(input) {
        if (input.operationKind === "delete"
            && this.entry.lifecycleState !== "archived") {
            throw new Error("delete requires lifecycle state archived");
        }
        if (input.operationKind === "delete"
            && input.expectedArchiveDigest
                !== this.entry.archive?.digest) {
            throw new Error("expected archive digest mismatch");
        }
        this.operation = { ...input };
        this.entry.lifecycleOperation = this.operation;
        return { created: true, operation: this.operation };
    }

    abortLifecycleOperation({ operationToken }) {
        if (this.operation?.operationToken === operationToken) {
            this.operation = null;
            this.entry.lifecycleOperation = null;
            return { changed: true };
        }
        return { changed: false };
    }

    commitArchive(input) {
        if (this.operation?.operationToken !== input.operationToken) {
            throw new Error("archive fence lost");
        }
        this.operation = null;
        this.entry = archiveEntry(this.investigationId, {
            registeredAtMs: 1_000,
            lifecycleUpdatedAtMs: 2_000,
            archive: {
                relativePath: input.archiveRelativePath,
                digest: input.archiveDigest,
                trustLevel: input.trustLevel,
                domainVersion: input.domainVersion,
                terminalAvailable: input.terminalAvailable,
                integrityStatus: input.integrityStatus,
                sizeBytes: input.sizeBytes,
                domainHead: input.domainHead,
                archivedAtMs: 2_000,
            },
        });
        return { changed: true, investigation: this.entry };
    }

    commitDelete(input) {
        const legacy = this.entry.lifecycleState === "tombstoned";
        if (!legacy
            && this.operation?.operationToken !== input.operationToken) {
            throw new Error("delete fence lost");
        }
        if (legacy
            && this.entry.deleteCleanup?.sourceAuthority
                === "legacy_discovery") {
            if (input.discoveredArchiveRelativePath !== undefined) {
                this.entry.deleteCleanup = {
                    ...this.entry.deleteCleanup,
                    sourceAuthority: "verified_bundle",
                    archiveRelativePath:
                        input.discoveredArchiveRelativePath,
                    cleanupMarkerDigest:
                        input.cleanupMarkerDigest,
                };
            } else if (input.archiveAbsent === true) {
                this.entry.deleteCleanup = {
                    ...this.entry.deleteCleanup,
                    archiveAbsent: true,
                    cleanupState: "durability_pending",
                };
            }
            return { changed: true, investigation: this.entry };
        }
        if (this.entry.deleteCleanup === null) {
            this.entry = {
                ...this.entry,
                deleteCleanup: {
                    investigationId: this.investigationId,
                    authorityKind: "pending_delete",
                    sourceAuthority:
                        input.sourceAuthority ?? "verified_bundle",
                    cleanupState: "reserved",
                    archiveRelativePath:
                        this.entry.archive.relativePath,
                    cleanupRelativePath:
                        input.cleanupRelativePath,
                    archiveAbsent: false,
                    archiveDigest: input.expectedArchiveDigest,
                    cleanupMarkerNonce:
                        input.cleanupMarkerNonce,
                    cleanupMarkerDigest:
                        input.cleanupMarkerDigest,
                    tombstoneRelativePath:
                        input.tombstoneRelativePath,
                    tombstoneDigest: input.tombstoneDigest,
                    signingKeyFingerprint:
                        input.signingKeyFingerprint,
                    signature: input.signature,
                    tombstoneSizeBytes:
                        input.tombstoneSizeBytes,
                    deletedAtMs: input.deletedAtMs,
                    preparedAtMs: input.deletedAtMs,
                },
            };
            return {
                changed: true,
                cleanupPending: true,
                investigation: this.entry,
            };
        }
        if (input.nextCleanupState !== undefined) {
            this.entry = {
                ...this.entry,
                deleteCleanup: {
                    ...this.entry.deleteCleanup,
                    cleanupState: input.nextCleanupState,
                },
            };
            return {
                changed: true,
                cleanupPending: true,
                investigation: this.entry,
            };
        }
        if (input.archiveRemoved !== true) {
            return {
                changed: false,
                cleanupPending: true,
                investigation: this.entry,
            };
        }
        if (legacy) {
            this.entry = { ...this.entry, deleteCleanup: null };
            return { changed: true, investigation: this.entry };
        }
        const cleanup = this.entry.deleteCleanup;
        this.operation = null;
        this.entry = tombstoneEntry(this.investigationId);
        this.entry.tombstone = {
            ...this.entry.tombstone,
            relativePath: cleanup.tombstoneRelativePath,
            digest: cleanup.tombstoneDigest,
            signingKeyFingerprint: cleanup.signingKeyFingerprint,
            signature: cleanup.signature,
            sizeBytes: cleanup.tombstoneSizeBytes,
            deletedAtMs: cleanup.deletedAtMs,
        };
        return { changed: true, investigation: this.entry };
    }
}

function archiveDeps({
    stateRoot,
    broker,
    faultPoint = null,
    importFailure = null,
}) {
    const investigationId = broker.investigationId;
    const activeDir = path.join(stateRoot, investigationId);
    fs.mkdirSync(path.join(activeDir, "state"), { recursive: true });
    fs.mkdirSync(path.join(activeDir, "artifacts"), { recursive: true });
    fs.writeFileSync(
        path.join(activeDir, "state", "events.sqlite"),
        "active-state",
    );
    return {
        env: {
            CRUCIBLE_STATE_ROOT: stateRoot,
            CRUCIBLE_ARCHIVE_TRUST_POLICY: "authenticated",
        },
        pathExists(candidate) {
            return path.basename(candidate) === "resource-catalog.sqlite"
                || fs.existsSync(candidate);
        },
        openResourceBrokerFromStateRoot: () => broker,
        resourceCatalogPath: () =>
            path.join(stateRoot, "resource-catalog.sqlite"),
        lifecycleProcessIdentity: {
            current: () => "test-process-start",
            isAlive: () => false,
        },
        openArtifactStoreReadOnly: () => ({}),
        assessPersistedTerminalReadiness: () => ({ ready: true }),
        lifecycleFaultInjector({ point }) {
            if (point === faultPoint) {
                throw new Error(`injected ${point}`);
            }
        },
        exportBundle({ destDir }) {
            fs.mkdirSync(destDir, { recursive: true });
            fs.writeFileSync(path.join(destDir, "bundle"), "export");
            return {
                digest: DIGEST,
                investigationId,
                domainVersion: 4,
                domainHead: HEAD,
            };
        },
        importBundle({ destDir }) {
            if (importFailure !== null) throw importFailure;
            fs.mkdirSync(destDir, { recursive: true });
            fs.writeFileSync(path.join(destDir, "bundle"), "import");
            return {
                digest: DIGEST,
                investigationId,
                domainVersion: 4,
                domainHead: HEAD,
                trustLevel: "authenticated",
            };
        },
        verifyBundleInPlace: () => ({
            digest: DIGEST,
            investigationId,
            domainVersion: 4,
            domainHead: HEAD,
            trustLevel: "authenticated",
        }),
        measureRetainedTree: () => ({
            sizeBytes: 6,
            fileCount: 1,
        }),
        removeVerifiedBundle({ bundleDir }) {
            fs.rmSync(bundleDir, { recursive: true, force: true });
            return { removed: true };
        },
    };
}

function terminalRead() {
    return {
        aggregate: {
            status: "terminal",
            lastEventHash: HEAD.eventHash,
            terminal: { decision: "VERIFIED_RESULT" },
            pause: null,
            nonResults: [],
        },
        operationalNonResult: null,
        quiescentStop: {
            state: "STOP_SUPERSEDED",
            quiescent: false,
            details: {
                proof: {
                    verified: true,
                    quiescent: true,
                    missingVerifications: [],
                    supervisorStatus: { verified: true },
                    processes: {
                        verified: true,
                        activePids: [],
                    },
                    sdkSessions: {
                        verified: true,
                        activeCount: 0,
                    },
                    runnerChild: {
                        verified: true,
                        active: false,
                    },
                    resourceBroker: {
                        verified: true,
                        authorityRetired: true,
                        activeLeases: [],
                    },
                    activeRunnerLease: null,
                    committableAttempts: [],
                    activePids: [],
                    activeSdkSessions: 0,
                    activeResourceLeases: [],
                },
            },
        },
    };
}

describe("archive lifecycle transaction", () => {
    it.each([
        "after-quiescence",
        "after-catalog-fence",
        "after-export",
        "after-import",
    ])("leaves active state recoverable after failure at %s", async (point) => {
        const stateRoot = makeRoot(point);
        const broker = new LifecycleBroker("archive-investigation");
        const deps = archiveDeps({
            stateRoot,
            broker,
            faultPoint: point,
        });

        await expect(archiveInvestigation({
            operation: "archive",
            investigation_id: broker.investigationId,
        }, deps, {
            readActive: () => terminalRead(),
        })).rejects.toThrow(`injected ${point}`);
        expect(broker.entry.lifecycleState).toBe("active");
        expect(broker.operation).toBeNull();
        expect(fs.existsSync(path.join(
            stateRoot,
            broker.investigationId,
        ))).toBe(true);
        expect(fs.existsSync(path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        ))).toBe(false);
        const staging = path.join(stateRoot, ".retention", "staging");
        expect(fs.existsSync(staging)
            ? fs.readdirSync(staging)
            : []).toEqual([]);
    });

    it.each([
        new Error("corrupted exported bundle"),
        Object.assign(new Error("wrong archive authentication"), {
            code: "CRUCIBLE_BUNDLE_AUTHENTICATION_FAILED",
        }),
    ])("does not publish a rejected imported bundle", async (failure) => {
        const stateRoot = makeRoot("bad-import");
        const broker = new LifecycleBroker("archive-investigation");
        const deps = archiveDeps({
            stateRoot,
            broker,
            importFailure: failure,
        });
        await expect(archiveInvestigation({
            operation: "archive",
            investigation_id: broker.investigationId,
        }, deps, {
            readActive: () => terminalRead(),
        })).rejects.toThrow(failure.message);
        expect(broker.entry.lifecycleState).toBe("active");
        expect(fs.existsSync(path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        ))).toBe(false);
    });

    it("keeps a committed archive and recoverable active copy on post-commit failure", async () => {
        const stateRoot = makeRoot("post-commit");
        const broker = new LifecycleBroker("archive-investigation");
        const deps = archiveDeps({
            stateRoot,
            broker,
            faultPoint: "after-catalog-commit",
        });
        await expect(archiveInvestigation({
            operation: "archive",
            investigation_id: broker.investigationId,
        }, deps, {
            readActive: () => terminalRead(),
        })).rejects.toThrow("after-catalog-commit");
        expect(broker.entry.lifecycleState).toBe("archived");
        expect(fs.existsSync(path.join(
            stateRoot,
            broker.investigationId,
        ))).toBe(true);
        expect(fs.existsSync(path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        ))).toBe(true);
        deps.lifecycleFaultInjector = () => {};
        const retry = await archiveInvestigation({
            operation: "archive",
            investigation_id: broker.investigationId,
        }, deps, {
            readActive: () => terminalRead(),
        });
        expect(retry).toMatchObject({
            idempotent: true,
            active_cleanup_complete: true,
        });
        expect(fs.existsSync(path.join(
            stateRoot,
            broker.investigationId,
        ))).toBe(false);
    });

    it("leaves a complete published archive after post-cleanup failure", async () => {
        const stateRoot = makeRoot("post-cleanup");
        const broker = new LifecycleBroker("archive-investigation");
        const deps = archiveDeps({
            stateRoot,
            broker,
            faultPoint: "after-active-cleanup",
        });
        await expect(archiveInvestigation({
            operation: "archive",
            investigation_id: broker.investigationId,
        }, deps, {
            readActive: () => terminalRead(),
        })).rejects.toThrow("after-active-cleanup");
        expect(broker.entry.lifecycleState).toBe("archived");
        expect(fs.existsSync(path.join(
            stateRoot,
            broker.investigationId,
        ))).toBe(false);
        expect(fs.existsSync(path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        ))).toBe(true);
    });

    it("publishes the archive then removes active and staging state", async () => {
        const stateRoot = makeRoot("success");
        const broker = new LifecycleBroker("archive-investigation");
        const deps = archiveDeps({ stateRoot, broker });
        const result = await archiveInvestigation({
            operation: "archive",
            investigation_id: broker.investigationId,
            expected_head: HEAD.eventHash,
        }, deps, {
            readActive: () => terminalRead(),
        });
        expect(result).toMatchObject({
            is_result: false,
            lifecycle_state: "archived",
            archive_digest: DIGEST,
            archive_trust_level: "authenticated",
        });
        expect(broker.entry.lifecycleState).toBe("archived");
        expect(fs.existsSync(path.join(
            stateRoot,
            broker.investigationId,
        ))).toBe(false);
        expect(fs.existsSync(path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        ))).toBe(true);
    });

    it("reclaims a dead process lifecycle fence before retrying archive", async () => {
        const stateRoot = makeRoot("stale-fence");
        const broker = new LifecycleBroker("archive-investigation");
        broker.operation = {
            investigationId: broker.investigationId,
            operationKind: "archive",
            operationToken: "dead-operation",
            ownerProcessId: 999,
            ownerProcessStartId: "dead-process-start",
            archiveRelativePath:
                `.retention/archives/${broker.investigationId}`,
        };
        broker.entry.lifecycleOperation = broker.operation;
        const deps = archiveDeps({ stateRoot, broker });
        const staleStage = path.join(
            stateRoot,
            ".retention",
            "staging",
            `${broker.investigationId}.dead-operation.export`,
        );
        fs.mkdirSync(staleStage, { recursive: true });
        fs.writeFileSync(path.join(staleStage, "partial"), "partial");
        const result = await archiveInvestigation({
            operation: "archive",
            investigation_id: broker.investigationId,
        }, deps, {
            readActive: () => terminalRead(),
        });
        expect(result.archived).toBe(true);
        expect(broker.entry.lifecycleState).toBe("archived");
        expect(fs.existsSync(staleStage)).toBe(false);
    });

    it("reuses an unreferenced verified archive left by a dead operation", async () => {
        const stateRoot = makeRoot("staged-recovery");
        const broker = new LifecycleBroker("archive-investigation");
        broker.operation = {
            investigationId: broker.investigationId,
            operationKind: "archive",
            operationToken: "dead-operation",
            ownerProcessId: 999,
            ownerProcessStartId: "dead-process-start",
            archiveRelativePath:
                `.retention/archives/${broker.investigationId}`,
        };
        broker.entry.lifecycleOperation = broker.operation;
        const deps = archiveDeps({ stateRoot, broker });
        const archiveDir = path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        );
        fs.mkdirSync(archiveDir, { recursive: true });
        fs.writeFileSync(path.join(archiveDir, "bundle"), "verified");
        deps.verifyBundleInPlace = () => ({
            digest: DIGEST,
            investigationId: broker.investigationId,
            domainVersion: 4,
            domainHead: HEAD,
            trustLevel: "authenticated",
        });
        deps.importBundle = () => {
            throw new Error("verified staged archive must be reused");
        };
        const result = await archiveInvestigation({
            operation: "archive",
            investigation_id: broker.investigationId,
        }, deps, {
            readActive: () => terminalRead(),
        });
        expect(result.archived).toBe(true);
        expect(fs.existsSync(archiveDir)).toBe(true);
    });
});

function deleteDeps({ stateRoot, broker, control }) {
    return {
        env: { CRUCIBLE_STATE_ROOT: stateRoot },
        pathExists(candidate) {
            return path.basename(candidate) === "resource-catalog.sqlite"
                || fs.existsSync(candidate);
        },
        openResourceBrokerFromStateRoot: () => broker,
        resourceCatalogPath: () =>
            path.join(stateRoot, "resource-catalog.sqlite"),
        lifecycleProcessIdentity: {
            current: () => "test-process-start",
            isAlive: () => false,
        },
        verifyBundleInPlace: ({ bundleDir }) => {
            control.verificationCalls =
                (control.verificationCalls ?? 0) + 1;
            if (control.verifyByPath instanceof Map
                && control.verifyByPath.has(bundleDir)) {
                const value = control.verifyByPath.get(bundleDir);
                if (value instanceof Error) throw value;
                return value;
            }
            if (control.verificationError !== null
                && control.verificationError !== undefined) {
                throw control.verificationError;
            }
            return {
                digest: DIGEST,
                investigationId: broker.investigationId,
                domainVersion: 4,
                domainHead: HEAD,
                authenticated: true,
                verified: true,
            };
        },
        measureRetainedTree: () => ({
            sizeBytes: 100,
            fileCount: 1,
        }),
        now: () => Date.parse("2026-07-14T00:00:00.000Z"),
        writeSignedTombstone({ file, payload }) {
            fs.mkdirSync(path.dirname(file), { recursive: true });
            fs.writeFileSync(file, "signed tombstone");
            control.tombstone = {
                file,
                digest: `sha256:${"c".repeat(64)}`,
                signingKeyFingerprint:
                    `sha256:crucible-tombstone-signing-key-v1:${
                        "d".repeat(64)
                    }`,
                signature: "signed-tombstone",
                sizeBytes: 16,
                payload,
                verified: true,
            };
            return control.tombstone;
        },
        verifySignedTombstone: () => control.tombstone,
        renameMarkedArchiveForCleanup({ source, destination }) {
            control.renameCalls = (control.renameCalls ?? 0) + 1;
            fs.renameSync(source, destination);
            return { moved: true, destinationExists: true };
        },
        removeDeleteCleanup({ target }) {
            control.removalCalls =
                (control.removalCalls ?? 0) + 1;
            if (control.removeThenFail === true) {
                control.removeThenFail = false;
                fs.rmSync(target, { recursive: true, force: true });
                throw new Error("parent fsync failed");
            }
            if (control.removalError) throw control.removalError;
            fs.rmSync(target, { recursive: true, force: true });
            return true;
        },
        fsyncDeleteCleanupRoots() {
            control.fsyncCalls = (control.fsyncCalls ?? 0) + 1;
            if (control.fsyncFailures > 0) {
                control.fsyncFailures -= 1;
                throw new Error("cleanup root fsync failed");
            }
            return true;
        },
        lifecycleFaultInjector({ point }) {
            if (point === control.faultPoint) {
                throw new Error(`injected ${point}`);
            }
        },
    };
}

describe("delete and tombstone lifecycle", () => {
    it("refuses active deletion and an incorrect archived digest", () => {
        const stateRoot = makeRoot("delete-refusal");
        const broker = new LifecycleBroker("delete-investigation");
        const deps = {
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
            pathExists: () => true,
            openResourceBrokerFromStateRoot: () => broker,
            resourceCatalogPath: () =>
                path.join(stateRoot, "resource-catalog.sqlite"),
            lifecycleProcessIdentity: {
                current: () => "test-process-start",
                isAlive: () => false,
            },
        };
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toThrow(/only for a verified archived/u);
        broker.entry = archiveEntry(broker.investigationId);
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: `sha256:${"f".repeat(64)}`,
        }, deps)).toThrow(/does not match/u);
    });

    it("does not let one lifecycle operation reclaim another kind", () => {
        const stateRoot = makeRoot("operation-kind");
        const broker = new LifecycleBroker("delete-investigation");
        broker.operation = {
            investigationId: broker.investigationId,
            operationKind: "archive",
            operationToken: "dead-archive",
            ownerProcessId: 999,
            ownerProcessStartId: "dead-process-start",
        };
        broker.entry.lifecycleOperation = broker.operation;
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, {
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
            pathExists: () => true,
            openResourceBrokerFromStateRoot: () => broker,
            resourceCatalogPath: () =>
                path.join(stateRoot, "resource-catalog.sqlite"),
            lifecycleProcessIdentity: {
                current: () => "test-process-start",
                isAlive: () => false,
            },
        })).toThrow(/pending archive lifecycle/u);
        expect(broker.operation).not.toBeNull();
    });

    it("refuses archived deletion while active resources remain", () => {
        const stateRoot = makeRoot("delete-live");
        const broker = new LifecycleBroker("delete-investigation");
        broker.entry = archiveEntry(broker.investigationId);
        const archiveDir = path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        );
        fs.mkdirSync(archiveDir, { recursive: true });
        fs.mkdirSync(path.join(
            stateRoot,
            broker.investigationId,
        ), { recursive: true });
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, {
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
            pathExists(candidate) {
                return path.basename(candidate)
                    === "resource-catalog.sqlite"
                    || fs.existsSync(candidate);
            },
            openResourceBrokerFromStateRoot: () => broker,
            resourceCatalogPath: () =>
                path.join(stateRoot, "resource-catalog.sqlite"),
            lifecycleProcessIdentity: {
                current: () => "test-process-start",
                isAlive: () => false,
            },
            verifyBundleInPlace: () => ({
                digest: DIGEST,
                investigationId: broker.investigationId,
                domainVersion: 4,
                domainHead: HEAD,
            }),
            measureRetainedTree: () => ({
                sizeBytes: 100,
                fileCount: 1,
            }),
            verifyNoActiveResources: () => ({
                verified: true,
                quiescent: false,
            }),
        })).toThrow(/could not prove zero active resources/u);
    });

    it("removes an exact verified archive and leaves a tombstone", () => {
        const stateRoot = makeRoot("delete-success");
        const broker = new LifecycleBroker("delete-investigation");
        broker.entry = archiveEntry(broker.investigationId);
        const archiveDir = path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        );
        fs.mkdirSync(archiveDir, { recursive: true });
        fs.writeFileSync(path.join(archiveDir, "bundle"), "archive");
        const activeDir = path.join(
            stateRoot,
            broker.investigationId,
        );
        fs.mkdirSync(activeDir, { recursive: true });
        fs.writeFileSync(path.join(activeDir, "stale-active"), "active");
        let archiveVerified = false;
        const deps = {
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
            pathExists(candidate) {
                return path.basename(candidate) === "resource-catalog.sqlite"
                    || fs.existsSync(candidate);
            },
            openResourceBrokerFromStateRoot: () => broker,
            resourceCatalogPath: () =>
                path.join(stateRoot, "resource-catalog.sqlite"),
            lifecycleProcessIdentity: {
                current: () => "test-process-start",
                isAlive: () => false,
            },
            verifyBundleInPlace: () => {
                if (!archiveVerified) {
                    throw new Error("corrupt archive fixture");
                }
                return {
                    digest: DIGEST,
                    investigationId: broker.investigationId,
                    domainVersion: 4,
                    domainHead: HEAD,
                };
            },
            measureRetainedTree: () => ({
                sizeBytes: 100,
                fileCount: 1,
            }),
            now: () => Date.parse("2026-07-14T00:00:00.000Z"),
            writeSignedTombstone({ file, payload }) {
                fs.mkdirSync(path.dirname(file), { recursive: true });
                fs.writeFileSync(file, "signed tombstone");
                return {
                    file,
                    digest: `sha256:${"c".repeat(64)}`,
                    signingKeyFingerprint:
                        `sha256:crucible-tombstone-signing-key-v1:${
                            "d".repeat(64)
                        }`,
                    signature: "signed-tombstone",
                    sizeBytes: 16,
                    payload,
                    verified: true,
                };
            },
            verifySignedTombstone({ file }) {
                return {
                    file,
                    digest: `sha256:${"c".repeat(64)}`,
                    signingKeyFingerprint:
                        `sha256:crucible-tombstone-signing-key-v1:${
                            "d".repeat(64)
                        }`,
                    signature: "signed-tombstone",
                    sizeBytes: 16,
                    payload: {
                        investigationId: broker.investigationId,
                        createdAtMs: 1_000,
                        deletedAt:
                            "2026-07-14T00:00:00.000Z",
                        domainVersion: 4,
                        archiveDigest: DIGEST,
                        domainHead: HEAD,
                    },
                    verified: true,
                };
            },
        };
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toThrow(/corrupt archive fixture/u);
        expect(fs.existsSync(activeDir)).toBe(true);
        archiveVerified = true;
        const result = deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps);
        expect(result).toMatchObject({
            is_result: false,
            lifecycle_state: "tombstoned",
            deleted: true,
            archive_removed: true,
            integrity_status: "verified",
        });
        expect(broker.entry.lifecycleState).toBe("tombstoned");
        expect(fs.existsSync(archiveDir)).toBe(false);
        expect(fs.existsSync(activeDir)).toBe(false);
    });

    it("requires the catalog-bound cleanup marker before idempotent deletion", () => {
        const stateRoot = makeRoot("cleanup-marker");
        const broker = new LifecycleBroker("delete-investigation");
        broker.entry = archiveEntry(broker.investigationId);
        const archiveDir = path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        );
        const cleanupDir = path.join(
            stateRoot,
            ...cleanupRelativePath(
                broker.investigationId,
                DIGEST,
            ).split("/"),
        );
        fs.mkdirSync(archiveDir, { recursive: true });
        fs.writeFileSync(path.join(archiveDir, "bundle"), "archive");
        const control = {
            faultPoint: "after-archive-rename",
            fsyncFailures: 0,
            tombstone: null,
        };
        const deps = deleteDeps({ stateRoot, broker, control });
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toThrow("injected after-archive-rename");
        expect(broker.entry.deleteCleanup).toMatchObject({
            cleanupState: "marked",
        });
        fs.writeFileSync(
            path.join(
                cleanupDir,
                ".crucible-delete-cleanup.json",
            ),
            "forged marker",
        );
        control.faultPoint = null;
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toThrow(/cleanup ownership marker/u);
        expect(fs.existsSync(cleanupDir)).toBe(true);
        expect(control.removalCalls ?? 0).toBe(0);
    });

    it("persists durability-pending when deletion succeeds but fsync fails", () => {
        const stateRoot = makeRoot("cleanup-fsync");
        const broker = new LifecycleBroker("delete-investigation");
        broker.entry = archiveEntry(broker.investigationId);
        const archiveDir = path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        );
        const cleanupDir = path.join(
            stateRoot,
            ...cleanupRelativePath(
                broker.investigationId,
                DIGEST,
            ).split("/"),
        );
        fs.mkdirSync(archiveDir, { recursive: true });
        fs.writeFileSync(path.join(archiveDir, "bundle"), "archive");
        const control = {
            faultPoint: null,
            removeThenFail: true,
            fsyncFailures: 1,
            tombstone: null,
        };
        const deps = deleteDeps({ stateRoot, broker, control });
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toThrow("parent fsync failed");
        expect(fs.existsSync(archiveDir)).toBe(false);
        expect(fs.existsSync(cleanupDir)).toBe(false);
        expect(broker.entry).toMatchObject({
            lifecycleState: "archived",
            deleteCleanup: {
                cleanupState: "durability_pending",
            },
        });
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toThrow("cleanup root fsync failed");
        expect(broker.entry.deleteCleanup.cleanupState)
            .toBe("durability_pending");
        expect(deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toMatchObject({
            lifecycle_state: "tombstoned",
            archive_removed: true,
        });
        expect(control.fsyncCalls).toBe(2);
    });

    it("discovers one verified custom v4 archive and rejects ambiguity", () => {
        const stateRoot = makeRoot("legacy-custom-discovery");
        const broker = new LifecycleBroker("delete-investigation");
        const entry = tombstoneEntry(broker.investigationId);
        const cleanupPath = cleanupRelativePath(
            broker.investigationId,
            DIGEST,
        );
        entry.deleteCleanup = {
            investigationId: broker.investigationId,
            authorityKind: "legacy_tombstone",
            sourceAuthority: "legacy_discovery",
            cleanupState: "reserved",
            archiveRelativePath: null,
            cleanupRelativePath: cleanupPath,
            archiveAbsent: false,
            archiveDigest: DIGEST,
            cleanupMarkerNonce: "f".repeat(64),
            cleanupMarkerDigest: null,
            tombstoneRelativePath:
                entry.tombstone.relativePath,
            tombstoneDigest: entry.tombstone.digest,
            signingKeyFingerprint:
                entry.tombstone.signingKeyFingerprint,
            signature: entry.tombstone.signature,
            tombstoneSizeBytes: entry.tombstone.sizeBytes,
            deletedAtMs: entry.tombstone.deletedAtMs,
            preparedAtMs: entry.tombstone.deletedAtMs,
        };
        broker.entry = entry;
        const first = path.join(
            stateRoot,
            ".retention",
            "archives",
            "custom-v4-one",
        );
        const second = path.join(
            stateRoot,
            ".retention",
            "archives",
            "custom-v4-two",
        );
        for (const directory of [first, second]) {
            fs.mkdirSync(directory, { recursive: true });
            fs.writeFileSync(path.join(directory, "bundle"), "archive");
        }
        const tombstonePath = path.join(
            stateRoot,
            ...entry.tombstone.relativePath.split("/"),
        );
        fs.mkdirSync(path.dirname(tombstonePath), { recursive: true });
        fs.writeFileSync(tombstonePath, "tombstone");
        const control = {
            faultPoint: null,
            fsyncFailures: 0,
            tombstone: {
                file: tombstonePath,
                digest: entry.tombstone.digest,
                signingKeyFingerprint:
                    entry.tombstone.signingKeyFingerprint,
                signature: entry.tombstone.signature,
                sizeBytes: entry.tombstone.sizeBytes,
                payload: {
                    investigationId: broker.investigationId,
                    createdAtMs: entry.registeredAtMs,
                    deletedAt: new Date(
                        entry.tombstone.deletedAtMs,
                    ).toISOString(),
                    domainVersion:
                        entry.tombstone.domainVersion,
                    archiveDigest: DIGEST,
                    domainHead: entry.tombstone.domainHead,
                },
                verified: true,
            },
            verifyByPath: new Map([
                [first, {
                    digest: DIGEST,
                    investigationId: broker.investigationId,
                    domainVersion: 4,
                    domainHead: HEAD,
                    authenticated: true,
                    verified: true,
                }],
                [second, {
                    digest: DIGEST,
                    investigationId: broker.investigationId,
                    domainVersion: 4,
                    domainHead: HEAD,
                    authenticated: true,
                    verified: true,
                }],
            ]),
        };
        const deps = deleteDeps({ stateRoot, broker, control });
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toThrow(/discovery is ambiguous/u);
        fs.rmSync(second, { recursive: true, force: true });
        expect(deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deps)).toMatchObject({
            lifecycle_state: "tombstoned",
            archive_removed: true,
        });
        expect(broker.entry.deleteCleanup).toBeNull();
    });

    it("resumes a migrated v5 partial tree without bundle re-verification", () => {
        const stateRoot = makeRoot("v5-partial-tree");
        const broker = new LifecycleBroker("delete-investigation");
        const archiveRelativePath =
            ".retention/archives/custom-v5-partial";
        const cleanupPath = cleanupRelativePath(
            broker.investigationId,
            DIGEST,
        );
        const nonce = "f".repeat(64);
        broker.entry = archiveEntry(broker.investigationId, {
            archive: {
                ...archiveEntry(broker.investigationId).archive,
                relativePath: archiveRelativePath,
            },
            deleteCleanup: {
                investigationId: broker.investigationId,
                authorityKind: "pending_delete",
                sourceAuthority: "legacy_preverified",
                cleanupState: "reserved",
                archiveRelativePath,
                cleanupRelativePath: cleanupPath,
                archiveAbsent: false,
                archiveDigest: DIGEST,
                cleanupMarkerNonce: nonce,
                cleanupMarkerDigest: markerDigest({
                    investigationId: broker.investigationId,
                    archiveRelativePath,
                    cleanupRelativePath: cleanupPath,
                    archiveDigest: DIGEST,
                    nonce,
                }),
                tombstoneRelativePath:
                    `.retention/tombstones/${broker.investigationId}.json`,
                tombstoneDigest: `sha256:${"c".repeat(64)}`,
                signingKeyFingerprint:
                    `sha256:crucible-tombstone-signing-key-v1:${
                        "d".repeat(64)
                    }`,
                signature: "signed-tombstone",
                tombstoneSizeBytes: 16,
                deletedAtMs:
                    Date.parse("2026-07-14T00:00:00.000Z"),
                preparedAtMs: 1_000,
            },
        });
        const archiveDir = path.join(
            stateRoot,
            ...archiveRelativePath.split("/"),
        );
        fs.mkdirSync(archiveDir, { recursive: true });
        fs.writeFileSync(
            path.join(archiveDir, "partial-fragment"),
            "partial",
        );
        const control = {
            faultPoint: null,
            fsyncFailures: 0,
            verificationError:
                new Error("partial tree must not be reverified"),
            tombstone: null,
        };
        expect(deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, deleteDeps({ stateRoot, broker, control }))).toMatchObject({
            lifecycle_state: "tombstoned",
            archive_removed: true,
        });
        expect(control.verificationCalls ?? 0).toBe(0);
    });

    it("cleans an unpublished tombstone after delete failure", () => {
        const stateRoot = makeRoot("delete-cleanup");
        const broker = new LifecycleBroker("delete-investigation");
        broker.entry = archiveEntry(broker.investigationId);
        const archiveDir = path.join(
            stateRoot,
            ".retention",
            "archives",
            broker.investigationId,
        );
        fs.mkdirSync(archiveDir, { recursive: true });
        const tombstonePath = path.join(
            stateRoot,
            ".retention",
            "tombstones",
            `${broker.investigationId}.json`,
        );
        expect(() => deleteInvestigation({
            operation: "delete",
            investigation_id: broker.investigationId,
            expected_archive_digest: DIGEST,
        }, {
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
            pathExists(candidate) {
                return path.basename(candidate)
                    === "resource-catalog.sqlite"
                    || fs.existsSync(candidate);
            },
            openResourceBrokerFromStateRoot: () => broker,
            resourceCatalogPath: () =>
                path.join(stateRoot, "resource-catalog.sqlite"),
            lifecycleProcessIdentity: {
                current: () => "test-process-start",
                isAlive: () => false,
            },
            verifyBundleInPlace: () => ({
                digest: DIGEST,
                investigationId: broker.investigationId,
                domainVersion: 4,
                domainHead: HEAD,
            }),
            measureRetainedTree: () => ({
                sizeBytes: 100,
                fileCount: 1,
            }),
            now: () => Date.parse("2026-07-14T00:00:00.000Z"),
            writeSignedTombstone({ file, payload }) {
                fs.mkdirSync(path.dirname(file), { recursive: true });
                fs.writeFileSync(file, "unpublished");
                return {
                    file,
                    digest: `sha256:${"c".repeat(64)}`,
                    signingKeyFingerprint:
                        `sha256:crucible-tombstone-signing-key-v1:${
                            "d".repeat(64)
                        }`,
                    signature: "signed-tombstone",
                    sizeBytes: 11,
                    payload,
                    verified: true,
                };
            },
            lifecycleFaultInjector({ point }) {
                if (point === "after-tombstone") {
                    throw new Error("delete crash after tombstone");
                }
            },
        })).toThrow("delete crash after tombstone");
        expect(broker.entry.lifecycleState).toBe("archived");
        expect(broker.operation).toBeNull();
        expect(fs.existsSync(archiveDir)).toBe(true);
        expect(fs.existsSync(tombstonePath)).toBe(false);
    });

    it("blocks deterministic identity resurrection from the catalog", () => {
        const stateRoot = makeRoot("resurrection");
        const entry = tombstoneEntry("deleted-investigation");
        expect(() => assertInvestigationIdentityAvailable({
            deps: {
                env: { CRUCIBLE_STATE_ROOT: stateRoot },
                pathExists: () => true,
                openResourceBrokerReadOnlyFromStateRoot: () =>
                    listBroker([entry]),
                resourceCatalogPath: () =>
                    path.join(stateRoot, "resource-catalog.sqlite"),
                verifySignedTombstone: () => ({
                    verified: true,
                    digest: entry.tombstone.digest,
                    sizeBytes: entry.tombstone.sizeBytes,
                    signingKeyFingerprint:
                        entry.tombstone.signingKeyFingerprint,
                    signature: entry.tombstone.signature,
                    payload: {
                        createdAtMs: entry.registeredAtMs,
                        archiveDigest:
                            entry.tombstone.archiveDigest,
                        domainVersion:
                            entry.tombstone.domainVersion,
                        domainHead: entry.tombstone.domainHead,
                        deletedAt: new Date(
                            entry.tombstone.deletedAtMs,
                        ).toISOString(),
                    },
                }),
            },
            stateRoot,
            investigationId: entry.investigationId,
        })).toThrow(/durably tombstoned/u);
    });

    it("fails closed on a signed tombstone without catalog authority", () => {
        const stateRoot = makeRoot("standalone-tombstone");
        const investigationId = "deleted-investigation";
        const env = { CRUCIBLE_STATE_ROOT: stateRoot };
        const retention = resolveRetentionPaths(
            stateRoot,
            investigationId,
            { env },
        );
        writeSignedTombstone({
            file: retention.tombstonePath,
            keyRoot: retention.tombstoneKeyRoot,
            env,
            payload: {
                investigationId,
                createdAtMs: 1_000,
                deletedAt: "2026-07-14T00:00:00.000Z",
                domainVersion: 4,
                archiveDigest: DIGEST,
                domainHead: HEAD,
            },
        });
        const deps = { env };
        expect(() => resolveLifecycleTarget({
            deps,
            investigationId,
        })).toThrow(/no committed catalog binding/u);
        expect(() => assertInvestigationIdentityAvailable({
            deps,
            stateRoot,
            investigationId,
        })).toThrow(/uncommitted signed tombstone/u);
    });

    it("blocks start reattachment while a lifecycle fence is active", () => {
        const stateRoot = makeRoot("start-fence");
        const entry = {
            investigationId: "fenced-investigation",
            registeredAtMs: 1_000,
            catalogGeneration: 1,
            lifecycleState: "active",
            lifecycleOperation: {
                operationKind: "archive",
                operationToken: "live-fence",
            },
            archive: null,
            deleteCleanup: null,
            tombstone: null,
        };
        expect(() => assertInvestigationIdentityAvailable({
            deps: {
                env: { CRUCIBLE_STATE_ROOT: stateRoot },
                pathExists: () => true,
                openResourceBrokerReadOnlyFromStateRoot: () =>
                    listBroker([entry]),
                resourceCatalogPath: () =>
                    path.join(stateRoot, "resource-catalog.sqlite"),
            },
            stateRoot,
            investigationId: entry.investigationId,
        })).toThrow(/fenced by an archive\/delete/u);
    });
});
