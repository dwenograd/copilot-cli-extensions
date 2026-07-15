import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";

import { afterEach, describe, expect, it } from "vitest";

import {
    RESOURCE_BROKER_CONFIG_VERSION,
    openResourceBroker,
    openResourceBrokerFromStateRoot,
    openResourceBrokerReadOnlyFromStateRoot,
    readResourceBrokerConfiguration,
} from "../runtime/index.mjs";
import { canonicalize } from "../persistence/canonical.mjs";
import { DatabaseSync } from "../persistence/sqlite.mjs";

const roots = [];
const brokers = [];

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
        path.join(os.tmpdir(), `crucible-recovery-catalog-${label}-`),
    );
    roots.push(root);
    return root;
}

function config() {
    return {
        version: RESOURCE_BROKER_CONFIG_VERSION,
        lease: {
            defaultTtlMs: 1_000,
            maxTtlMs: 10_000,
        },
        capacities: {
            sdkSessions: 2,
            sandboxProcesses: 2,
            cpuSlots: { general: 2 },
            gpuSlots: {},
            outputBytes: 10_000,
            receiptBytes: 10_000,
            casBytes: 10_000,
            storageBytes: 20_000,
            modelCostUnits: 100_000,
        },
    };
}

function limits() {
    return {
        sdkSessions: 1,
        sandboxProcesses: 1,
        cpuSlots: { general: 1 },
        gpuSlots: {},
        outputBytes: 5_000,
        receiptBytes: 5_000,
        casBytes: 5_000,
        storageBytes: 10_000,
        modelCostUnits: 50_000,
    };
}

function openBroker(options) {
    const broker = openResourceBroker(options);
    brokers.push(broker);
    return broker;
}

function register(broker, investigationId = "recovery-investigation") {
    return broker.registerInvestigation({
        investigationId,
        limits: limits(),
        supervisorGeneration: 1,
        supervisorNonce: `supervisor-nonce-${investigationId}`,
        runnerIncarnation: `runner-incarnation-${investigationId}`,
    });
}

function archiveCatalogInvestigation(
    broker,
    investigationId,
    {
        digest = `sha256:${"a".repeat(64)}`,
        archiveRelativePath =
            `.retention/archives/${investigationId}`,
    } = {},
) {
    broker.beginLifecycleOperation({
        investigationId,
        operationKind: "archive",
        operationToken: `archive-${investigationId}`,
        ownerProcessId: 100,
        ownerProcessStartId: `archive-owner-${investigationId}`,
        archiveRelativePath,
    });
    broker.commitArchive({
        investigationId,
        operationToken: `archive-${investigationId}`,
        archiveRelativePath,
        archiveDigest: digest,
        trustLevel: "authenticated",
        domainVersion: 4,
        terminalAvailable: false,
        sizeBytes: 100,
        domainHead: {
            seq: 1,
            eventHash: "b".repeat(64),
        },
    });
    return { digest, archiveRelativePath };
}

function deleteOptions(
    investigationId,
    {
        digest,
        archiveRelativePath,
        operationToken = `delete-${investigationId}`,
        deletedAtMs = Date.now(),
    },
) {
    const cleanupPath = cleanupRelativePath(
        investigationId,
        digest,
    );
    const nonce = "f".repeat(64);
    return {
        investigationId,
        operationToken,
        expectedArchiveDigest: digest,
        cleanupRelativePath: cleanupPath,
        cleanupMarkerNonce: nonce,
        cleanupMarkerDigest: markerDigest({
            investigationId,
            archiveRelativePath,
            cleanupRelativePath: cleanupPath,
            archiveDigest: digest,
            nonce,
        }),
        tombstoneRelativePath:
            `.retention/tombstones/${investigationId}.json`,
        tombstoneDigest: `sha256:${"d".repeat(64)}`,
        signingKeyFingerprint: "test-signing-key",
        signature: "test-signature",
        tombstoneSizeBytes: 64,
        deletedAtMs,
    };
}

afterEach(() => {
    for (const broker of brokers.splice(0)) {
        try {
            broker.close();
        } catch {
            // A test may close a broker before reopening it.
        }
    }
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 20,
            retryDelay: 20,
        });
    }
});

describe("recovery catalog authority", () => {
    it("fences one daemon per state root with non-reusable generations", () => {
        let now = 1_000;
        const broker = openBroker({
            stateRoot: makeRoot("singleton"),
            config: config(),
            now: () => now,
        });
        register(broker);

        const first = broker.acquireRecoveryDaemonLease({
            daemonIncarnation: "daemon-incarnation-1",
            leaseNonce: "daemon-nonce-1",
            ownerProcessId: 101,
            ownerProcessStartId: "daemon-process-1",
            ttlMs: 1_000,
        });
        expect(first).toMatchObject({
            acquired: true,
            lease: {
                daemonGeneration: 1,
                daemonIncarnation: "daemon-incarnation-1",
            },
        });

        const held = broker.acquireRecoveryDaemonLease({
            daemonIncarnation: "daemon-incarnation-2",
            leaseNonce: "daemon-nonce-2",
            ownerProcessId: 102,
            ownerProcessStartId: "daemon-process-2",
            ttlMs: 1_000,
        });
        expect(held).toMatchObject({
            acquired: false,
            reason: "held",
            lease: { daemonGeneration: 1 },
        });

        now += 1_001;
        const replacement = broker.acquireRecoveryDaemonLease({
            daemonIncarnation: "daemon-incarnation-2",
            leaseNonce: "daemon-nonce-2",
            ownerProcessId: 102,
            ownerProcessStartId: "daemon-process-2",
            ttlMs: 1_000,
        });
        expect(replacement).toMatchObject({
            acquired: true,
            reason: "reclaimed",
            lease: {
                daemonGeneration: 2,
                daemonIncarnation: "daemon-incarnation-2",
            },
        });
        expect(() => broker.recordRecoveryOperation({
            lease: first.lease,
            investigationId: "recovery-investigation",
            state: "eligible",
            code: "STALE_DAEMON_MUST_NOT_WRITE",
        })).toThrow(/stale/u);

        const operation = broker.recordRecoveryOperation({
            lease: replacement.lease,
            investigationId: "recovery-investigation",
            state: "started",
            code: "SUPERVISOR_STARTED",
            supervisorGeneration: 2,
            runnerIncarnation: "runner-incarnation-2",
        });
        expect(operation).toMatchObject({
            daemonGeneration: 2,
            state: "started",
            code: "SUPERVISOR_STARTED",
            attemptCount: 1,
        });
    });

    it("takes over immediately when exact same-user process identity is gone", () => {
        const broker = openBroker({
            stateRoot: makeRoot("dead-owner"),
            config: config(),
            isRecoveryOwnerAlive: ({ processStartId }) =>
                processStartId !== "dead-process-start",
        });
        register(broker);
        const dead = broker.acquireRecoveryDaemonLease({
            daemonIncarnation: "dead-daemon",
            leaseNonce: "dead-daemon-nonce",
            ownerProcessId: 200,
            ownerProcessStartId: "dead-process-start",
            ttlMs: 10_000,
        });
        expect(dead.acquired).toBe(true);
        const replacement = broker.acquireRecoveryDaemonLease({
            daemonIncarnation: "live-daemon",
            leaseNonce: "live-daemon-nonce",
            ownerProcessId: 201,
            ownerProcessStartId: "live-process-start",
            ttlMs: 10_000,
        });
        expect(replacement).toMatchObject({
            acquired: true,
            reason: "reclaimed",
            lease: {
                daemonGeneration: 2,
                daemonIncarnation: "live-daemon",
            },
        });
    });

    it("excludes archived and tombstoned catalog investigations", () => {
        const broker = openBroker({
            stateRoot: makeRoot("lifecycle"),
            config: config(),
        });
        register(broker, "active-investigation");
        register(broker, "archived-investigation");
        register(broker, "tombstoned-investigation");

        broker.setInvestigationLifecycle({
            investigationId: "archived-investigation",
            lifecycleState: "archived",
            reasonCode: "operator_archive",
        });
        broker.setInvestigationLifecycle({
            investigationId: "tombstoned-investigation",
            lifecycleState: "tombstoned",
            reasonCode: "operator_tombstone",
        });

        expect(broker.listInvestigations({ lifecycleState: "active" })
            .map((entry) => entry.investigationId))
            .toEqual(["active-investigation"]);
        expect(() => broker.setInvestigationLifecycle({
            investigationId: "tombstoned-investigation",
            lifecycleState: "active",
        })).toThrow(/cannot be reactivated/u);
    });

    it("publishes verified archives and prunes them to durable tombstones", () => {
        let now = 10_000;
        const broker = openBroker({
            stateRoot: makeRoot("archive-delete"),
            config: config(),
            now: () => now,
        });
        register(broker, "lifecycle-investigation");
        const digest = `sha256:${"a".repeat(64)}`;
        const cleanupPath = cleanupRelativePath(
            "lifecycle-investigation",
            digest,
        );
        const markerNonce = "f".repeat(64);
        const marker = markerDigest({
            investigationId: "lifecycle-investigation",
            archiveRelativePath:
                ".retention/archives/lifecycle-investigation",
            cleanupRelativePath: cleanupPath,
            archiveDigest: digest,
            nonce: markerNonce,
        });
        const head = {
            seq: 2,
            eventHash: "b".repeat(64),
        };

        broker.beginLifecycleOperation({
            investigationId: "lifecycle-investigation",
            operationKind: "archive",
            operationToken: "archive-token",
            ownerProcessId: 100,
            ownerProcessStartId: "archive-process-start",
            archiveRelativePath:
                ".retention/archives/lifecycle-investigation",
        });
        expect(broker.listInvestigations({
            lifecycleState: "active",
            excludeFenced: true,
        })).toEqual([]);
        register(broker, "competing-archive-investigation");
        expect(() => broker.beginLifecycleOperation({
            investigationId: "competing-archive-investigation",
            operationKind: "archive",
            operationToken: "competing-archive-token",
            ownerProcessId: 101,
            ownerProcessStartId: "competing-process-start",
            archiveRelativePath:
                ".retention/archives/lifecycle-investigation",
        })).toThrow();
        now += 1;
        const archived = broker.commitArchive({
            investigationId: "lifecycle-investigation",
            operationToken: "archive-token",
            archiveRelativePath:
                ".retention/archives/lifecycle-investigation",
            archiveDigest: digest,
            trustLevel: "authenticated",
            domainVersion: 4,
            terminalAvailable: true,
            sizeBytes: 1234,
            domainHead: head,
        });
        expect(archived.investigation).toMatchObject({
            lifecycleState: "archived",
            archive: {
                digest,
                domainVersion: 4,
                terminalAvailable: true,
                sizeBytes: 1234,
                domainHead: head,
            },
        });
        expect(broker.getUsageSnapshot({
            investigationId: "lifecycle-investigation",
        }).find((row) => row.resourceKey === "storage_bytes"))
            .toMatchObject({ committedUnits: 1234 });
        expect(() => broker.setInvestigationLifecycle({
            investigationId: "lifecycle-investigation",
            lifecycleState: "active",
        })).toThrow(/cannot be reactivated/u);
        expect(() => broker.beginLifecycleOperation({
            investigationId: "competing-archive-investigation",
            operationKind: "archive",
            operationToken: "competing-after-commit-token",
            ownerProcessId: 101,
            ownerProcessStartId: "competing-process-start",
            archiveRelativePath:
                ".retention/archives/lifecycle-investigation",
        })).toThrow(/already owned/u);
        expect(broker.listInvestigations({
            lifecycleState: "archived",
        }).map((entry) => entry.investigationId))
            .toEqual(["lifecycle-investigation"]);
        expect(() => broker.beginLifecycleOperation({
            investigationId: "lifecycle-investigation",
            operationKind: "delete",
            operationToken: "wrong-delete-token",
            ownerProcessId: 100,
            ownerProcessStartId: "delete-process-start",
            expectedArchiveDigest: `sha256:${"c".repeat(64)}`,
        })).toThrow(/digest does not match/u);

        broker.beginLifecycleOperation({
            investigationId: "lifecycle-investigation",
            operationKind: "delete",
            operationToken: "delete-token",
            ownerProcessId: 100,
            ownerProcessStartId: "delete-process-start",
            expectedArchiveDigest: digest,
        });
        now += 1;
        const deleteOptions = {
            investigationId: "lifecycle-investigation",
            operationToken: "delete-token",
            expectedArchiveDigest: digest,
            cleanupRelativePath: cleanupPath,
            cleanupMarkerNonce: markerNonce,
            cleanupMarkerDigest: marker,
            tombstoneRelativePath:
                ".retention/tombstones/lifecycle-investigation.json",
            tombstoneDigest: `sha256:${"d".repeat(64)}`,
            signingKeyFingerprint:
                `sha256:crucible-tombstone-signing-key-v1:${
                    "e".repeat(64)
                }`,
            signature: "signed-tombstone",
            tombstoneSizeBytes: 512,
            deletedAtMs: now,
        };
        const pending = broker.commitDelete(deleteOptions);
        expect(pending.investigation.deleteCleanup).toMatchObject({
            cleanupState: "reserved",
            cleanupRelativePath: cleanupPath,
            cleanupMarkerDigest: marker,
        });
        for (const nextCleanupState of [
            "marked",
            "moved",
            "durability_pending",
            "durable",
        ]) {
            broker.commitDelete({
                ...deleteOptions,
                nextCleanupState,
            });
        }
        const deleted = broker.commitDelete({
            ...deleteOptions,
            archiveRemoved: true,
        });
        expect(deleted.investigation).toMatchObject({
            investigationId: "lifecycle-investigation",
            lifecycleState: "tombstoned",
            tombstone: {
                archiveDigest: digest,
                domainVersion: 4,
                domainHead: head,
                sizeBytes: 512,
            },
        });
        expect(broker.listInvestigations({
            lifecycleState: "tombstoned",
        }).map((entry) => entry.investigationId))
            .toEqual(["lifecycle-investigation"]);
        expect(() => register(
            broker,
            "lifecycle-investigation",
        )).toThrow(/cannot be registered again/u);
    });

    it("reserves cleanup paths exclusively across archive operations and cleanup authority", () => {
        const broker = openBroker({
            stateRoot: makeRoot("cross-table-paths"),
            config: config(),
        });
        for (const investigationId of [
            "cleanup-owner",
            "archive-competitor",
            "later-competitor",
        ]) {
            register(broker, investigationId);
        }
        const archived = archiveCatalogInvestigation(
            broker,
            "cleanup-owner",
            {
                archiveRelativePath:
                    ".retention/archives/custom-authenticated-owner",
            },
        );
        const options = deleteOptions("cleanup-owner", archived);
        broker.beginLifecycleOperation({
            investigationId: "archive-competitor",
            operationKind: "archive",
            operationToken: "competing-cleanup-reservation",
            ownerProcessId: 200,
            ownerProcessStartId: "competing-owner",
            archiveRelativePath: options.cleanupRelativePath,
        });
        broker.beginLifecycleOperation({
            investigationId: "cleanup-owner",
            operationKind: "delete",
            operationToken: options.operationToken,
            ownerProcessId: 201,
            ownerProcessStartId: "delete-owner",
            expectedArchiveDigest: archived.digest,
        });
        expect(() => broker.commitDelete(options))
            .toThrow(/retention path is already owned/u);
        broker.abortLifecycleOperation({
            investigationId: "archive-competitor",
            operationToken: "competing-cleanup-reservation",
        });
        expect(broker.commitDelete(options).investigation)
            .toMatchObject({
                deleteCleanup: {
                    cleanupRelativePath: options.cleanupRelativePath,
                },
            });
        expect(() => broker.beginLifecycleOperation({
            investigationId: "later-competitor",
            operationKind: "archive",
            operationToken: "later-competing-reservation",
            ownerProcessId: 202,
            ownerProcessStartId: "later-owner",
            archiveRelativePath: options.cleanupRelativePath,
        })).toThrow(/retention path is already owned/u);
    });

    it("paginates lifecycle catalog identities in deterministic order", () => {
        const broker = openBroker({
            stateRoot: makeRoot("pagination"),
            config: config(),
        });
        for (const investigationId of ["catalog-c", "catalog-a", "catalog-b"]) {
            register(broker, investigationId);
        }
        expect(broker.listInvestigations({ limit: 2 })
            .map((entry) => entry.investigationId))
            .toEqual(["catalog-a", "catalog-b"]);
        expect(broker.listInvestigations({
            afterInvestigationId: "catalog-b",
            limit: 2,
        }).map((entry) => entry.investigationId))
            .toEqual(["catalog-c"]);
    });

    it("materializes list entries from one deferred snapshot while generation advances", () => {
        const root = makeRoot("snapshot-generation");
        const writer = openBroker({
            stateRoot: root,
            config: config(),
        });
        register(writer, "snapshot-investigation");
        const reader = openResourceBrokerReadOnlyFromStateRoot({
            stateRoot: root,
        });
        brokers.push(reader);
        const listed = reader.listInvestigations({
            onSnapshotEstablished() {
                writer.beginLifecycleOperation({
                    investigationId: "snapshot-investigation",
                    operationKind: "archive",
                    operationToken: "snapshot-archive",
                    ownerProcessId: 300,
                    ownerProcessStartId: "snapshot-owner",
                    archiveRelativePath:
                        ".retention/archives/snapshot-investigation",
                });
            },
        });
        expect(listed).toEqual([
            expect.objectContaining({
                investigationId: "snapshot-investigation",
                lifecycleOperation: null,
            }),
        ]);
        expect(listed.catalogGeneration).toBe(1);
        expect(writer.getInvestigation("snapshot-investigation"))
            .toMatchObject({
                catalogGeneration: 2,
                lifecycleOperation: {
                    operationKind: "archive",
                },
            });
    });

    it("reopens the broker from its verified on-disk singleton config", () => {
        const root = makeRoot("reopen");
        const broker = openBroker({ stateRoot: root, config: config() });
        register(broker);
        const stored = readResourceBrokerConfiguration({ stateRoot: root });
        expect(stored.configFingerprint).toBe(broker.configFingerprint);
        broker.close();

        const reopened = openResourceBrokerFromStateRoot({ stateRoot: root });
        brokers.push(reopened);
        expect(reopened.getInvestigation("recovery-investigation"))
            .toMatchObject({
                lifecycleState: "active",
                supervisorGeneration: 1,
            });
    });

    it("migrates the canonical v2 catalog in place", () => {
        const root = makeRoot("migrate-v2");
        const broker = openBroker({ stateRoot: root, config: config() });
        register(broker);
        broker.close();

        const file = path.join(root, "resource-catalog.sqlite");
        const db = new DatabaseSync(file);
        try {
            db.exec(`
                PRAGMA foreign_keys = OFF;
                DROP TABLE investigation_delete_cleanup;
                DROP TABLE investigation_tombstones;
                DROP TABLE investigation_archives;
                DROP TABLE lifecycle_operations;
                DROP TABLE recovery_operations;
                DROP TABLE recovery_daemon_authority;
                DROP TABLE recovery_daemon_incarnations;
                DROP TABLE investigation_lifecycle;
            `);
            const manifest = db.prepare(`
                SELECT type, name, tbl_name, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                  AND sql IS NOT NULL
                ORDER BY type, name
            `).all().map((row) => ({
                type: row.type,
                name: row.name,
                table: row.tbl_name,
                sql: String(row.sql).replace(/\s+/gu, " ").trim(),
            }));
            const digest = createHash("sha256")
                .update(canonicalize({ version: 2, manifest }))
                .digest("hex");
            db.prepare(`
                UPDATE schema_meta
                SET value = '2'
                WHERE key = 'schema_version'
            `).run();
            db.prepare(`
                UPDATE schema_meta
                SET value = ?
                WHERE key = 'schema_fingerprint'
            `).run(
                `sha256:crucible-resource-catalog-schema-v2:${digest}`,
            );
            db.prepare(`
                DELETE FROM schema_meta
                WHERE key = 'recovery_schema_migrated_at_ms'
            `).run();
            db.exec("PRAGMA user_version = 2;");
        } finally {
            db.close();
        }

        const migrated = openResourceBrokerFromStateRoot({ stateRoot: root });
        brokers.push(migrated);
        expect(migrated.verifyIntegrity()).toMatchObject({ version: 6 });
        expect(migrated.getInvestigation("recovery-investigation"))
            .toMatchObject({ lifecycleState: "active" });
    });

    it("migrates the canonical v3 recovery catalog in place", () => {
        const root = makeRoot("migrate-v3");
        const broker = openBroker({ stateRoot: root, config: config() });
        register(broker);
        broker.close();

        const file = path.join(root, "resource-catalog.sqlite");
        const db = new DatabaseSync(file);
        try {
            db.exec(`
                PRAGMA foreign_keys = OFF;
                DROP TABLE investigation_delete_cleanup;
                DROP TABLE investigation_tombstones;
                DROP TABLE investigation_archives;
                DROP TABLE lifecycle_operations;
            `);
            const manifest = db.prepare(`
                SELECT type, name, tbl_name, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                  AND sql IS NOT NULL
                ORDER BY type, name
            `).all().map((row) => ({
                type: row.type,
                name: row.name,
                table: row.tbl_name,
                sql: String(row.sql).replace(/\s+/gu, " ").trim(),
            }));
            const digest = createHash("sha256")
                .update(canonicalize({ version: 3, manifest }))
                .digest("hex");
            db.prepare(`
                UPDATE schema_meta
                SET value = '3'
                WHERE key = 'schema_version'
            `).run();
            db.prepare(`
                UPDATE schema_meta
                SET value = ?
                WHERE key = 'schema_fingerprint'
            `).run(
                `sha256:crucible-resource-catalog-schema-v3:${digest}`,
            );
            db.prepare(`
                DELETE FROM schema_meta
                WHERE key = 'lifecycle_schema_migrated_at_ms'
            `).run();
            db.exec("PRAGMA user_version = 3;");
        } finally {
            db.close();
        }

        const migrated = openResourceBrokerFromStateRoot({ stateRoot: root });
        brokers.push(migrated);
        expect(migrated.verifyIntegrity()).toMatchObject({ version: 6 });
        expect(migrated.getInvestigation("recovery-investigation"))
            .toMatchObject({ lifecycleState: "active" });
    });

    it("migrates v4 tombstones without inventing an archive destination", () => {
        const root = makeRoot("migrate-v4-custom");
        const broker = openBroker({ stateRoot: root, config: config() });
        const investigationId = "legacy-custom";
        register(broker, investigationId);
        const archived = archiveCatalogInvestigation(
            broker,
            investigationId,
            {
                archiveRelativePath:
                    ".retention/archives/custom-v4-destination",
            },
        );
        const options = deleteOptions(investigationId, archived);
        broker.beginLifecycleOperation({
            investigationId,
            operationKind: "delete",
            operationToken: options.operationToken,
            ownerProcessId: 400,
            ownerProcessStartId: "legacy-delete-owner",
            expectedArchiveDigest: archived.digest,
        });
        broker.commitDelete(options);
        for (const nextCleanupState of [
            "marked",
            "moved",
            "durability_pending",
            "durable",
        ]) {
            broker.commitDelete({
                ...options,
                nextCleanupState,
            });
        }
        broker.commitDelete({
            ...options,
            archiveRemoved: true,
        });
        broker.close();

        const file = path.join(root, "resource-catalog.sqlite");
        const db = new DatabaseSync(file);
        try {
            db.exec(`
                PRAGMA foreign_keys = OFF;
                DROP TABLE investigation_delete_cleanup;
            `);
            const manifest = db.prepare(`
                SELECT type, name, tbl_name, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                  AND sql IS NOT NULL
                ORDER BY type, name
            `).all().map((row) => ({
                type: row.type,
                name: row.name,
                table: row.tbl_name,
                sql: String(row.sql).replace(/\s+/gu, " ").trim(),
            }));
            const digest = createHash("sha256")
                .update(canonicalize({ version: 4, manifest }))
                .digest("hex");
            db.prepare(`
                UPDATE schema_meta
                SET value = '4'
                WHERE key = 'schema_version'
            `).run();
            db.prepare(`
                UPDATE schema_meta
                SET value = ?
                WHERE key = 'schema_fingerprint'
            `).run(
                `sha256:crucible-resource-catalog-schema-v4:${digest}`,
            );
            db.exec("PRAGMA user_version = 4;");
        } finally {
            db.close();
        }
        expect(() => openResourceBrokerReadOnlyFromStateRoot({
            stateRoot: root,
        })).toThrow(/schema version mismatch/u);
        const migrated = openResourceBrokerFromStateRoot({
            stateRoot: root,
        });
        brokers.push(migrated);
        expect(migrated.getInvestigation(investigationId))
            .toMatchObject({
                lifecycleState: "tombstoned",
                deleteCleanup: {
                    authorityKind: "legacy_tombstone",
                    sourceAuthority: "legacy_discovery",
                    archiveRelativePath: null,
                    archiveAbsent: false,
                    archiveDigest: archived.digest,
                },
            });
    });

    it("migrates v5 partial cleanup as exact preverified authority and rejects path injection", () => {
        const root = makeRoot("migrate-v5-partial");
        const broker = openBroker({ stateRoot: root, config: config() });
        const investigationId = "v5-partial";
        register(broker, investigationId);
        const archived = archiveCatalogInvestigation(
            broker,
            investigationId,
            {
                archiveRelativePath:
                    ".retention/archives/custom-v5-partial",
            },
        );
        const options = deleteOptions(investigationId, archived);
        broker.beginLifecycleOperation({
            investigationId,
            operationKind: "delete",
            operationToken: options.operationToken,
            ownerProcessId: 500,
            ownerProcessStartId: "v5-delete-owner",
            expectedArchiveDigest: archived.digest,
        });
        broker.commitDelete(options);
        broker.close();

        const file = path.join(root, "resource-catalog.sqlite");
        const db = new DatabaseSync(file);
        try {
            const pending = db.prepare(`
                SELECT *
                FROM investigation_delete_cleanup
                WHERE investigation_id = ?
            `).get(investigationId);
            db.exec(`
                PRAGMA foreign_keys = OFF;
                DROP INDEX ix_investigation_delete_cleanup_state;
                DROP TABLE investigation_delete_cleanup;
                CREATE TABLE investigation_delete_cleanup (
                    investigation_id TEXT PRIMARY KEY
                        REFERENCES investigations(investigation_id),
                    archive_relpath TEXT NOT NULL UNIQUE,
                    archive_digest TEXT NOT NULL UNIQUE,
                    tombstone_relpath TEXT NOT NULL UNIQUE,
                    tombstone_digest TEXT NOT NULL UNIQUE,
                    signing_key_fingerprint TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    tombstone_size_bytes INTEGER NOT NULL
                        CHECK (tombstone_size_bytes > 0),
                    deleted_at_ms INTEGER NOT NULL
                        CHECK (deleted_at_ms >= 0),
                    prepared_at_ms INTEGER NOT NULL
                        CHECK (prepared_at_ms >= 0)
                );
                CREATE INDEX ix_investigation_delete_cleanup_prepared
                    ON investigation_delete_cleanup(prepared_at_ms, investigation_id);
            `);
            db.prepare(`
                INSERT INTO investigation_delete_cleanup(
                    investigation_id, archive_relpath,
                    archive_digest, tombstone_relpath,
                    tombstone_digest, signing_key_fingerprint,
                    signature, tombstone_size_bytes,
                    deleted_at_ms, prepared_at_ms)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                investigationId,
                pending.archive_relpath,
                pending.archive_digest,
                pending.tombstone_relpath,
                pending.tombstone_digest,
                pending.signing_key_fingerprint,
                pending.signature,
                pending.tombstone_size_bytes,
                pending.deleted_at_ms,
                pending.prepared_at_ms,
            );
            const manifest = db.prepare(`
                SELECT type, name, tbl_name, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                  AND sql IS NOT NULL
                ORDER BY type, name
            `).all().map((row) => ({
                type: row.type,
                name: row.name,
                table: row.tbl_name,
                sql: String(row.sql).replace(/\s+/gu, " ").trim(),
            }));
            const digest = createHash("sha256")
                .update(canonicalize({ version: 5, manifest }))
                .digest("hex");
            db.prepare(`
                UPDATE schema_meta
                SET value = '5'
                WHERE key = 'schema_version'
            `).run();
            db.prepare(`
                UPDATE schema_meta
                SET value = ?
                WHERE key = 'schema_fingerprint'
            `).run(
                `sha256:crucible-resource-catalog-schema-v5:${digest}`,
            );
            db.exec("PRAGMA user_version = 5;");
        } finally {
            db.close();
        }
        expect(() => openResourceBrokerReadOnlyFromStateRoot({
            stateRoot: root,
        })).toThrow(/schema version mismatch/u);
        const tampered = new DatabaseSync(file);
        try {
            tampered.prepare(`
                UPDATE investigation_delete_cleanup
                SET archive_relpath =
                    '.retention/archives/attacker-injected'
                WHERE investigation_id = ?
            `).run(investigationId);
        } finally {
            tampered.close();
        }
        expect(() => openResourceBrokerFromStateRoot({
            stateRoot: root,
        })).toThrow(/lacks exact archived authority/u);
        const restored = new DatabaseSync(file);
        try {
            expect(restored.prepare("PRAGMA user_version;").get()
                .user_version).toBe(5);
            restored.prepare(`
                UPDATE investigation_delete_cleanup
                SET archive_relpath = ?
                WHERE investigation_id = ?
            `).run(archived.archiveRelativePath, investigationId);
        } finally {
            restored.close();
        }
        const migrated = openResourceBrokerFromStateRoot({
            stateRoot: root,
        });
        brokers.push(migrated);
        expect(migrated.getInvestigation(investigationId))
            .toMatchObject({
                deleteCleanup: {
                    sourceAuthority: "legacy_preverified",
                    cleanupState: "reserved",
                    archiveRelativePath:
                        archived.archiveRelativePath,
                    archiveDigest: archived.digest,
                },
            });
    });
});
