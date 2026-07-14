import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    archiveInvestigation,
    assertInvestigationIdentityAvailable,
    deleteInvestigation,
    listLifecycleInvestigations,
    resolveLifecycleTarget,
} from "../api/lifecycle.mjs";
import { resolveRetentionPaths } from "../api/environment.mjs";
import { writeSignedTombstone } from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
const DIGEST = `sha256:${"a".repeat(64)}`;
const HEAD = Object.freeze({
    seq: 2,
    eventHash: `sha256:crucible-event-v4:${"b".repeat(64)}`,
});

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.api-lifecycle-${label}-`),
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
        archive: null,
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
            return entries
                .filter((entry) =>
                    (lifecycleState === null
                        || entry.lifecycleState === lifecycleState)
                    && (afterInvestigationId === null
                        || entry.investigationId
                            > afterInvestigationId))
                .sort((left, right) =>
                    left.investigationId < right.investigationId
                        ? -1
                        : 1)
                .slice(0, limit);
        },
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
            openResourceBrokerFromStateRoot: () =>
                listBroker(entries),
            verifyBundleInPlace: ({ expectedInvestigationId }) => ({
                investigationId: expectedInvestigationId,
                domainVersion: 4,
                domainHead: HEAD,
                digest: DIGEST,
                trustLevel: "authenticated",
            }),
            verifySignedTombstone: () => ({
                verified: true,
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
});

class LifecycleBroker {
    constructor(investigationId) {
        this.investigationId = investigationId;
        this.entry = {
            investigationId,
            registeredAtMs: 1_000,
            lifecycleUpdatedAtMs: 1_000,
            lifecycleState: "active",
            lifecycleOperation: null,
            archive: null,
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
        return lifecycleState === null
            || this.entry.lifecycleState === lifecycleState
            ? [this.entry]
            : [];
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
        if (this.operation?.operationToken !== input.operationToken) {
            throw new Error("delete fence lost");
        }
        this.operation = null;
        this.entry = tombstoneEntry(this.investigationId);
        this.entry.tombstone = {
            ...this.entry.tombstone,
            relativePath: input.tombstoneRelativePath,
            digest: input.tombstoneDigest,
            signingKeyFingerprint: input.signingKeyFingerprint,
            signature: input.signature,
            sizeBytes: input.tombstoneSizeBytes,
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
        };
        broker.entry.lifecycleOperation = broker.operation;
        const deps = archiveDeps({ stateRoot, broker });
        const staleStage = path.join(
            stateRoot,
            ".retention",
            "staging",
            `${broker.investigationId}.archive-dead.export`,
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
            writeSignedTombstone({ file }) {
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
                };
            },
            removeVerifiedBundle({ bundleDir }) {
                fs.rmSync(bundleDir, { recursive: true, force: true });
                return { removed: true };
            },
        };
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
            writeSignedTombstone({ file }) {
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
                openResourceBrokerFromStateRoot: () =>
                    listBroker([entry]),
                resourceCatalogPath: () =>
                    path.join(stateRoot, "resource-catalog.sqlite"),
            },
            stateRoot,
            investigationId: entry.investigationId,
        })).toThrow(/durably tombstoned/u);
    });

    it("honors a signed tombstone even if catalog references are lost", () => {
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
        expect(resolveLifecycleTarget({
            deps,
            investigationId,
        })).toMatchObject({
            state: "tombstoned",
            entry: {
                investigationId,
                lifecycleState: "tombstoned",
            },
            verification: { verified: true },
        });
        expect(() => assertInvestigationIdentityAvailable({
            deps,
            stateRoot,
            investigationId,
        })).toThrow(/durably tombstoned/u);
    });

    it("blocks start reattachment while a lifecycle fence is active", () => {
        const stateRoot = makeRoot("start-fence");
        const entry = {
            investigationId: "fenced-investigation",
            lifecycleState: "active",
            lifecycleOperation: {
                operationKind: "archive",
                operationToken: "live-fence",
            },
        };
        expect(() => assertInvestigationIdentityAvailable({
            deps: {
                env: { CRUCIBLE_STATE_ROOT: stateRoot },
                pathExists: () => true,
                openResourceBrokerFromStateRoot: () =>
                    listBroker([entry]),
                resourceCatalogPath: () =>
                    path.join(stateRoot, "resource-catalog.sqlite"),
            },
            stateRoot,
            investigationId: entry.investigationId,
        })).toThrow(/fenced by an archive\/delete/u);
    });
});
