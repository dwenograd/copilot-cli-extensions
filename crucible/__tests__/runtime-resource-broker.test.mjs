import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { DatabaseSync } from "../persistence/sqlite.mjs";
import {
    ERROR_CODES,
    RESOURCE_CATALOG_SCHEMA_FINGERPRINT,
} from "../persistence/index.mjs";
import {
    RESOURCE_BROKER_CONFIG_VERSION,
    DEFAULT_RESOURCE_BROKER_CONFIG,
    deriveRuntimeResourceAdmission,
    estimateDeterministicModelCostUnits,
    investigationResourceLimitsFingerprint,
    normalizeResourceBrokerConfig,
    openResourceBroker,
    sdkUsageToModelCostUnits,
} from "../runtime/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
const brokers = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.resource-broker-${label}-`),
    );
    roots.push(root);
    return root;
}

function openBroker(options) {
    const broker = openResourceBroker(options);
    brokers.push(broker);
    return broker;
}

afterEach(() => {
    const failures = [];
    for (const broker of brokers.splice(0)) {
        try {
            broker.close();
        } catch {
            // A test may already have closed the handle.
        }
    }
    for (const root of roots.splice(0)) {
        try {
            fs.rmSync(root, {
                recursive: true,
                force: true,
                maxRetries: 20,
                retryDelay: 25,
            });
        } catch (error) {
            failures.push(error);
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            "resource broker test cleanup failed",
        );
    }
});

function brokerConfig(overrides = {}) {
    const capacities = {
        sdkSessions: 2,
        sandboxProcesses: 2,
        cpuSlots: { general: 2 },
        gpuSlots: { gpu0: 1 },
        outputBytes: 1_000,
        receiptBytes: 1_000,
        casBytes: 2_000,
        modelCostUnits: 100_000,
        ...(overrides.capacities ?? {}),
    };
    return {
        version: RESOURCE_BROKER_CONFIG_VERSION,
        lease: {
            defaultTtlMs: 100,
            maxTtlMs: 1_000,
            ...(overrides.lease ?? {}),
        },
        capacities,
        ...(overrides.costPolicy === undefined
            ? {}
            : { costPolicy: overrides.costPolicy }),
    };
}

function investigationLimits(config, overrides = {}) {
    return {
        sdkSessions: Math.min(1, config.capacities.sdkSessions),
        sandboxProcesses: Math.min(1, config.capacities.sandboxProcesses),
        cpuSlots: { general: Math.min(1, config.capacities.cpuSlots.general) },
        gpuSlots: Object.hasOwn(config.capacities.gpuSlots, "gpu0")
            ? { gpu0: Math.min(1, config.capacities.gpuSlots.gpu0) }
            : {},
        outputBytes: Math.min(500, config.capacities.outputBytes),
        receiptBytes: Math.min(500, config.capacities.receiptBytes),
        casBytes: Math.min(1_000, config.capacities.casBytes),
        modelCostUnits: Math.min(50_000, config.capacities.modelCostUnits),
        ...overrides,
    };
}

function register(broker, investigationId, limits, {
    generation = 1,
    nonce = `nonce-${investigationId}`,
    incarnation = `incarnation-${investigationId}-1`,
} = {}) {
    return broker.registerInvestigation({
        investigationId,
        limits,
        supervisorGeneration: generation,
        supervisorNonce: nonce,
        runnerIncarnation: incarnation,
    });
}

function acquire(broker, investigationId, reservation, {
    generation = 1,
    incarnation = `incarnation-${investigationId}-1`,
    ownerId = `owner-${investigationId}`,
    attemptId = `attempt-${investigationId}`,
    logicalEffectId = `effect-${investigationId}`,
    ...rest
} = {}) {
    return broker.acquire({
        investigationId,
        ownerId,
        supervisorGeneration: generation,
        runnerIncarnation: incarnation,
        attemptId,
        logicalEffectId,
        reservation,
        ...rest,
    });
}

function allocation(lease, resourceKey) {
    return lease.allocations.find(
        (entry) => entry.resourceKey === resourceKey,
    );
}

describe("resource broker configuration and catalog", () => {
    it("validates deterministic cost policy and rejects malformed capacities", () => {
        const config = brokerConfig();
        expect(normalizeResourceBrokerConfig(config)).toMatchObject({
            version: RESOURCE_BROKER_CONFIG_VERSION,
            capacities: {
                sdkSessions: 2,
                gpuSlots: { gpu0: 1 },
            },
        });
        const estimate = estimateDeterministicModelCostUnits({
            model: "model-a",
            promptBytes: 100,
            maxOutputTokens: 200,
            reasoningEffort: "high",
        });
        expect(estimate).toBeGreaterThan(3_000);
        expect(estimateDeterministicModelCostUnits({
            model: "model-a",
            promptBytes: 100,
            maxOutputTokens: 200,
            reasoningEffort: "high",
        })).toBe(estimate);
        expect(sdkUsageToModelCostUnits({
            model: "model-a",
            inputTokens: 100,
            outputTokens: 300,
            totalTokens: 450,
        })).toBeGreaterThan(estimate);

        expect(() => normalizeResourceBrokerConfig({
            ...config,
            capacities: {
                ...config.capacities,
                cpuSlots: {},
            },
        })).toThrow(/at least one named slot/u);
        expect(() => normalizeResourceBrokerConfig({
            ...config,
            capacities: {
                ...config.capacities,
                surprise: 1,
            },
        })).toThrow(/unknown key/u);

        const admission = deriveRuntimeResourceAdmission({
            executionLimits: {
                candidateEvaluations: 2,
                byteBudgets: {
                    perInvestigationOutputBytes: 500,
                    perInvestigationReceiptBytes: 500,
                    perInvestigationCasBytes: 1_000,
                },
            },
            deadlineMs: Date.now() + 10_000,
            brokerConfig: DEFAULT_RESOURCE_BROKER_CONFIG,
        });
        expect(admission.sdkRetryPolicy).toMatchObject({
            maxAttempts: 3,
            maxCostUnits: expect.any(Number),
        });
        expect(admission.investigationLimits).toMatchObject({
            sdkSessions: 1,
            sandboxProcesses: 1,
            cpuSlots: { general: 1 },
            outputBytes: 500,
            receiptBytes: 500,
            casBytes: 1_000,
        });
    });

    it("creates a local WAL catalog with a verified schema and immutable singleton config", () => {
        const root = makeRoot("catalog");
        const config = brokerConfig();
        const broker = openBroker({ stateRoot: root, config });
        const file = broker.databaseFile;
        const catalogLimits = investigationLimits(config);
        register(
            broker,
            "catalog-inv",
            catalogLimits,
        );
        expect(broker.getInvestigation("catalog-inv").limitsFingerprint)
            .toBe(investigationResourceLimitsFingerprint(
                catalogLimits,
                config,
            ));
        expect(broker.verifyIntegrity()).toEqual({
            version: 1,
            fingerprint: RESOURCE_CATALOG_SCHEMA_FINGERPRINT,
        });

        const raw = new DatabaseSync(file, { readOnly: true });
        try {
            expect(raw.prepare("PRAGMA journal_mode").get().journal_mode)
                .toBe("wal");
            expect(raw.prepare("PRAGMA user_version").get().user_version)
                .toBe(1);
            expect(raw.prepare(`
                SELECT value
                FROM schema_meta
                WHERE key = 'schema_fingerprint'
            `).get().value).toBe(RESOURCE_CATALOG_SCHEMA_FINGERPRINT);
            expect(raw.prepare(
                "SELECT COUNT(*) AS count FROM catalog_config",
            ).get().count).toBe(1);
            expect(raw.prepare(
                "SELECT config_fingerprint FROM catalog_config",
            ).get().config_fingerprint).toBe(broker.configFingerprint);
            expect(raw.prepare(
                "SELECT COUNT(*) AS count FROM resource_definitions",
            ).get().count).toBe(8);
        } finally {
            raw.close();
        }
        broker.close();

        const reopened = openBroker({ stateRoot: root, config });
        reopened.close();
        expect(() => openBroker({
            stateRoot: root,
            config: brokerConfig({
                capacities: { outputBytes: 999 },
            }),
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.SCHEMA_INTEGRITY_VIOLATION,
        }));

        const tampered = new DatabaseSync(file);
        tampered.prepare(`
            UPDATE investigation_limits
            SET limit_units = limit_units - 1
            WHERE investigation_id = 'catalog-inv'
              AND resource_key = 'output_bytes'
        `).run();
        tampered.close();
        expect(() => openBroker({ stateRoot: root, config }))
            .toThrow(expect.objectContaining({
                code: ERROR_CODES.SCHEMA_INTEGRITY_VIOLATION,
            }));
    });
});

describe("transactional admission and fencing", () => {
    it("serializes global named-slot capacity, returns throttle, and never reuses a logical effect", () => {
        const root = makeRoot("capacity");
        const config = brokerConfig();
        const brokerA = openBroker({ stateRoot: root, config });
        const brokerB = openBroker({ stateRoot: root, config });
        register(
            brokerA,
            "inv-a",
            investigationLimits(config),
        );
        register(
            brokerA,
            "inv-b",
            investigationLimits(config),
        );

        const first = acquire(
            brokerA,
            "inv-a",
            {
                sdkSessions: 1,
                sandboxProcesses: 1,
                cpuSlots: { general: 1 },
                gpuSlots: { gpu0: 1 },
            },
        );
        expect(first.status).toBe("acquired");
        expect(brokerA.renew({
            lease: first.lease,
            ttlMs: 500,
        })).toMatchObject({
            status: "active",
            renewed: true,
        });
        const blocked = acquire(
            brokerB,
            "inv-b",
            { gpuSlots: { gpu0: 1 } },
        );
        expect(blocked).toMatchObject({
            status: "throttle",
            operational: true,
            scientificConclusion: false,
            terminal: false,
            deficit: {
                resourceKey: "gpu_slot:gpu0",
                scope: "global",
            },
        });

        expect(brokerA.release({ lease: first.lease }).status).toBe("released");
        const second = acquire(
            brokerB,
            "inv-b",
            { gpuSlots: { gpu0: 1 } },
        );
        expect(second.status).toBe("acquired");
        expect(second.lease.fencingToken).toBeGreaterThan(
            first.lease.fencingToken,
        );

        const replay = acquire(
            brokerA,
            "inv-a",
            {
                sdkSessions: 1,
                sandboxProcesses: 1,
                cpuSlots: { general: 1 },
                gpuSlots: { gpu0: 1 },
            },
        );
        expect(replay).toMatchObject({
            status: "already_finalized",
            deduplicated: true,
            lease: {
                fencingToken: first.lease.fencingToken,
                status: "released",
            },
        });
        expect(() => brokerB.renew({
            lease: {
                ...second.lease,
                fencingToken: first.lease.fencingToken,
            },
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.FENCE_REJECTED,
        }));

        brokerB.release({ lease: second.lease });
        expect(brokerA.listActiveLeases()).toEqual([]);
        expect(brokerA.getUsageSnapshot()
            .filter((row) => row.resourceMode === "concurrency")
            .every((row) => row.totalUnits === 0)).toBe(true);
        brokerB.close();
        brokerA.close();
    });

    it("distinguishes temporary reservations from exhausted frozen budgets", () => {
        const root = makeRoot("budgets");
        const config = brokerConfig({
            capacities: {
                outputBytes: 200,
                modelCostUnits: 20_000,
            },
        });
        const broker = openBroker({ stateRoot: root, config });
        register(broker, "inv-a", investigationLimits(config, {
            outputBytes: 100,
            modelCostUnits: 10_000,
        }));
        register(broker, "inv-b", investigationLimits(config, {
            outputBytes: 150,
            modelCostUnits: 10_000,
        }));
        const estimatedCost = broker.estimateModelCost({
            model: "model-a",
            promptBytes: 10,
            maxOutputTokens: 100,
            reasoningEffort: "medium",
        });
        const first = acquire(
            broker,
            "inv-a",
            {
                outputBytes: 80,
                receiptBytes: 40,
                casBytes: 70,
                modelCostUnits: estimatedCost,
            },
        );
        expect(first.status).toBe("acquired");

        const temporary = acquire(
            broker,
            "inv-a",
            { outputBytes: 30 },
            {
                attemptId: "attempt-inv-a-2",
                logicalEffectId: "effect-inv-a-2",
            },
        );
        expect(temporary).toMatchObject({
            status: "throttle",
            deficit: {
                scope: "investigation",
                resourceKey: "output_bytes",
                committedUnits: 0,
                heldUnits: 80,
            },
        });

        broker.release({
            lease: first.lease,
            usage: {
                outputBytes: 50,
                receiptBytes: 20,
                casBytes: 30,
                modelCostUnits: 0,
            },
        });
        expect(allocation(
            broker.getLease(first.lease.leaseId),
            "model_cost_units",
        ).chargedUnits).toBe(estimatedCost);
        expect(allocation(
            broker.getLease(first.lease.leaseId),
            "receipt_bytes",
        ).chargedUnits).toBe(20);
        expect(allocation(
            broker.getLease(first.lease.leaseId),
            "cas_bytes",
        ).chargedUnits).toBe(30);

        const sdkUnits = sdkUsageToModelCostUnits({
            model: "model-a",
            inputTokens: 100,
            outputTokens: 200,
        }, broker.config.costPolicy);
        broker.reconcileModelUsage({
            lease: first.lease,
            sdkUsage: {
                model: "model-a",
                inputTokens: 100,
                outputTokens: 200,
            },
            reconciliationId: "sdk-final",
        });
        expect(allocation(
            broker.getLease(first.lease.leaseId),
            "model_cost_units",
        ).chargedUnits).toBe(Math.max(estimatedCost, sdkUnits));
        broker.reconcileModelUsage({
            lease: first.lease,
            sdkUsage: {
                model: "model-a",
                inputTokens: 1,
                outputTokens: 1,
            },
            reconciliationId: "sdk-late-lower",
        });
        expect(allocation(
            broker.getLease(first.lease.leaseId),
            "model_cost_units",
        ).chargedUnits).toBe(Math.max(estimatedCost, sdkUnits));

        const permanent = acquire(
            broker,
            "inv-a",
            { outputBytes: 60 },
            {
                attemptId: "attempt-inv-a-3",
                logicalEffectId: "effect-inv-a-3",
            },
        );
        expect(permanent).toMatchObject({
            status: "pause",
            operational: true,
            scientificConclusion: false,
            terminal: false,
            deficit: {
                scope: "investigation",
                resourceKey: "output_bytes",
                committedUnits: 50,
            },
        });

        const global = acquire(
            broker,
            "inv-b",
            { outputBytes: 151 },
            {
                attemptId: "attempt-inv-b-2",
                logicalEffectId: "effect-inv-b-2",
            },
        );
        expect(global.status).toBe("pause");
        expect(global.deficits.some((deficit) =>
            deficit.scope === "global"
            && deficit.resourceKey === "output_bytes")).toBe(true);
        expect(broker.listActiveLeases()).toEqual([]);
        broker.close();
    });

    it("reclaims superseded, expired, and exactly-dead owners without ABA or leaks", () => {
        const root = makeRoot("reclaim");
        const clock = {
            value: 10_000,
            now() {
                return this.value;
            },
            advance(delta) {
                this.value += delta;
            },
        };
        const dead = new Set();
        const config = brokerConfig({
            capacities: {
                sdkSessions: 1,
                outputBytes: 500,
            },
        });
        const broker = openBroker({
            stateRoot: root,
            config,
            now: () => clock.now(),
            isOwnerAlive: ({ processId, processStartId }) =>
                !dead.has(`${processId}:${processStartId}`),
        });
        register(broker, "inv-a", investigationLimits(config, {
            outputBytes: 250,
        }), {
            nonce: "supervisor-a",
            incarnation: "inc-a-1",
        });
        register(broker, "inv-b", investigationLimits(config, {
            outputBytes: 250,
        }), {
            nonce: "supervisor-b",
            incarnation: "inc-b-1",
        });

        const first = acquire(
            broker,
            "inv-a",
            { sdkSessions: 1, outputBytes: 20 },
            {
                incarnation: "inc-a-1",
                ownerProcessId: 101,
                ownerProcessStartId: "process-a-1",
            },
        );
        const claimed = broker.claimAuthority({
            investigationId: "inv-a",
            supervisorGeneration: 1,
            supervisorNonce: "supervisor-a",
            runnerIncarnation: "inc-a-2",
        });
        expect(claimed.reclaimed).toEqual([first.lease.fencingToken]);
        expect(broker.getLease(first.lease.leaseId)).toMatchObject({
            status: "reclaimed",
            finalizationReason: "superseded_authority",
        });
        expect(allocation(
            broker.getLease(first.lease.leaseId),
            "output_bytes",
        ).chargedUnits).toBe(20);
        expect(() => broker.claimAuthority({
            investigationId: "inv-a",
            supervisorGeneration: 1,
            supervisorNonce: "supervisor-a",
            runnerIncarnation: "inc-a-1",
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.FENCE_REJECTED,
        }));
        expect(() => acquire(
            broker,
            "inv-a",
            { sdkSessions: 1 },
            {
                incarnation: "inc-a-1",
                attemptId: "stale-attempt",
                logicalEffectId: "stale-effect",
            },
        )).toThrow(expect.objectContaining({
            code: ERROR_CODES.FENCE_REJECTED,
        }));

        const expiring = acquire(
            broker,
            "inv-a",
            { sdkSessions: 1 },
            {
                incarnation: "inc-a-2",
                attemptId: "expiring-attempt",
                logicalEffectId: "expiring-effect",
            },
        );
        clock.advance(101);
        const afterExpiry = acquire(
            broker,
            "inv-b",
            { sdkSessions: 1 },
            {
                incarnation: "inc-b-1",
                attemptId: "after-expiry-attempt",
                logicalEffectId: "after-expiry-effect",
            },
        );
        expect(afterExpiry.status).toBe("acquired");
        expect(afterExpiry.reclaimed).toContainEqual({
            fencingToken: expiring.lease.fencingToken,
            reason: "expired",
        });
        expect(broker.renew({ lease: expiring.lease })).toMatchObject({
            renewed: false,
            status: "reclaimed",
        });
        expect(broker.listActiveLeases({ investigationId: "inv-b" }))
            .toEqual([
                expect.objectContaining({
                    leaseId: afterExpiry.lease.leaseId,
                    status: "active",
                }),
            ]);
        broker.release({ lease: afterExpiry.lease });

        const doomed = acquire(
            broker,
            "inv-a",
            { sdkSessions: 1, outputBytes: 15 },
            {
                incarnation: "inc-a-2",
                attemptId: "dead-attempt",
                logicalEffectId: "dead-effect",
                ownerProcessId: 202,
                ownerProcessStartId: "process-a-2",
            },
        );
        dead.add("202:process-a-2");
        const afterDeath = acquire(
            broker,
            "inv-b",
            { sdkSessions: 1 },
            {
                incarnation: "inc-b-1",
                attemptId: "after-death-attempt",
                logicalEffectId: "after-death-effect",
            },
        );
        expect(afterDeath.status).toBe("acquired");
        expect(afterDeath.lease.fencingToken).toBeGreaterThan(
            doomed.lease.fencingToken,
        );
        expect(afterDeath.reclaimed).toContainEqual({
            fencingToken: doomed.lease.fencingToken,
            reason: "owner_dead",
        });
        expect(allocation(
            broker.getLease(doomed.lease.leaseId),
            "output_bytes",
        ).chargedUnits).toBe(15);
        expect(broker.renew({ lease: doomed.lease })).toMatchObject({
            renewed: false,
            status: "reclaimed",
        });
        broker.release({ lease: afterDeath.lease });
        expect(broker.listActiveLeases()).toEqual([]);
        broker.close();
    });
});
