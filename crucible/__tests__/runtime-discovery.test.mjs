import path from "node:path";
import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
    DEFAULT_RESOURCE_BROKER_CONFIG,
    RECOVERY_DISCOVERY_CODES,
    classifyRecoveryAggregate,
    discoverCatalogInvestigations,
    evaluateRecoveryBrokerCapacity,
    inspectRecoveryInvestigation,
    recoveryReservationForCommand,
    verifyInvestigationArtifactIntegrity,
} from "../runtime/index.mjs";

function aggregate(overrides = {}) {
    return {
        contract: {
            workerModels: ["model-a", "model-b"],
        },
        terminal: null,
        pause: null,
        nonResults: [],
        experimentAuthority: {
            identity: "authority-identity",
            manifest: {
                experimentPayload: {
                    experimentId: "experiment-a",
                    projectDir: "C:\\project",
                    harnessSuiteId: "suite-a",
                },
            },
        },
        experimentAuthorityIdentity: "authority-identity",
        runtimeConfigAuthority: {
            fingerprint: "runtime-fingerprint",
            sandbox: { required: false },
        },
        runtimeConfigFingerprint: "runtime-fingerprint",
        ...overrides,
    };
}

function inspectSetup(overrides = {}) {
    const stateRoot = path.resolve("recovery-discovery-state");
    const investigationId = "recovery-discovery-investigation";
    const config = {
        runner: {
            investigationId,
            stateDir: path.join(stateRoot, investigationId, "state"),
            artifactRoot: path.join(
                stateRoot,
                investigationId,
                "artifacts",
            ),
            sdkPath: path.join(stateRoot, "sdk"),
            cliPath: path.join(stateRoot, "copilot.exe"),
            deadlineMs: Date.now() + 60_000,
            options: {
                sdkRetryPolicy: {
                    maxCostUnits: 1,
                    reservedCostUnitsPerAttempt: 1,
                },
            },
            resourceBroker: {
                stateRoot,
                configFingerprint: "broker-fingerprint",
                limitsFingerprint: "limits-fingerprint",
            },
        },
        paths: {
            lockPath: path.join(stateRoot, "supervisor.lock.json"),
        },
        staleLockMs: 30_000,
    };
    const replayAggregate = overrides.replayAggregate ?? aggregate();
    const repository = {
        verifyInvestigation: () => ({ ok: true }),
        close() {},
    };
    const artifactStore = {};
    const dependencies = {
        pathExists: () => true,
        openRepositoryReadOnly: () => repository,
        openArtifactStoreReadOnly: () => artifactStore,
        createDomainRepositoryAdapter: () => ({
            replay: () => ({ aggregate: replayAggregate }),
            latestOperationalNonResult: () =>
                overrides.operationalNonResult ?? null,
        }),
        verifyArtifactIntegrity: () => ({ verified: true }),
        verifyExperimentAuthority: () => {},
        loadSupervisorConfig: () => config,
        assertSupervisorConfigMatchesRuntimeAuthority: () => config,
        verifyRuntimeConfigAuthority: () => {},
        readSupervisorStatus: () => null,
        readSupervisorLock: () => null,
        isPidAlive: () => false,
        buildRecoveryReservation: () => ({ sdkSessions: 1 }),
        evaluateBrokerCapacity: () => ({
            ok: true,
            code: RECOVERY_DISCOVERY_CODES.ELIGIBLE,
        }),
        probeSdkAvailability: async () => ({
            ok: true,
            code: "SDK_AVAILABLE",
        }),
        ...overrides.dependencies,
    };
    return {
        input: {
            stateRoot,
            catalogInvestigation: {
                investigationId,
                lifecycleState: "active",
                limitsFingerprint: "limits-fingerprint",
            },
            broker: {
                configFingerprint: "broker-fingerprint",
            },
            daemonLease: {
                daemonGeneration: 1,
                daemonIncarnation: "daemon-1",
            },
            nowMs: Date.now(),
        },
        dependencies,
    };
}

describe("recovery discovery eligibility", () => {
    it("queries only unfenced active catalog investigations", () => {
        let observed = null;
        const result = discoverCatalogInvestigations({
            listInvestigations(options) {
                observed = options;
                return [
                    { investigationId: "active-b" },
                    { investigationId: "active-a" },
                ];
            },
        });
        expect(observed).toEqual({
            lifecycleState: "active",
            excludeFenced: true,
        });
        expect(result.map((entry) => entry.investigationId))
            .toEqual(["active-a", "active-b"]);
    });

    it("excludes paused, terminal, archived, tombstoned, and non-result runs", () => {
        expect(classifyRecoveryAggregate({
            lifecycleState: "active",
            aggregate: aggregate({ pause: { reason: "operator" } }),
        }).code).toBe(RECOVERY_DISCOVERY_CODES.PAUSED);
        expect(classifyRecoveryAggregate({
            lifecycleState: "active",
            aggregate: aggregate({ terminal: { opaque: true } }),
        }).code).toBe(RECOVERY_DISCOVERY_CODES.TERMINAL);
        expect(classifyRecoveryAggregate({
            lifecycleState: "archived",
            aggregate: aggregate(),
        }).code).toBe(RECOVERY_DISCOVERY_CODES.LIFECYCLE_ARCHIVED);
        expect(classifyRecoveryAggregate({
            lifecycleState: "tombstoned",
            aggregate: aggregate(),
        }).code).toBe(RECOVERY_DISCOVERY_CODES.LIFECYCLE_TOMBSTONED);
        expect(classifyRecoveryAggregate({
            lifecycleState: "active",
            aggregate: aggregate({ nonResults: [{ code: "FAILED" }] }),
        }).code).toBe(RECOVERY_DISCOVERY_CODES.NON_RESULT);
    });

    it("verifies referenced inline and external artifact bytes", () => {
        const bytes = Buffer.from("inline artifact", "utf8");
        const inlineHash = createHash("sha256").update(bytes).digest("hex");
        const repository = {
            listArtifactRefs: () => [
                { artifactId: "external-artifact" },
                { artifactId: "inline-artifact" },
            ],
            getArtifact: (artifactId) => artifactId === "external-artifact"
                ? {
                    artifactId,
                    investigationId: "investigation",
                    durable: true,
                    sizeBytes: 4,
                    hashAlgo: "sha256",
                    hashValue:
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    storage: "external",
                }
                : {
                    artifactId,
                    investigationId: "investigation",
                    durable: true,
                    sizeBytes: bytes.length,
                    hashAlgo: "sha256",
                    hashValue: inlineHash,
                    storage: "inline",
                },
            getInlineArtifact: () => ({ bytes }),
        };
        const artifactStore = {
            verifyObject: () => ({ ok: true, size: 4 }),
        };
        expect(verifyInvestigationArtifactIntegrity({
            repository,
            artifactStore,
            investigationId: "investigation",
        })).toEqual({ verified: true, artifactCount: 2 });
        artifactStore.verifyObject = () => ({ ok: false, reason: "corrupt" });
        expect(() => verifyInvestigationArtifactIntegrity({
            repository,
            artifactStore,
            investigationId: "investigation",
        })).toThrow(/external artifact/u);
    });

    it("accounts for target-owned stale concurrency while blocking true capacity exhaustion", () => {
        let targetLeases = [];
        const row = {
            resourceKey: "sdk_sessions",
            resourceMode: "concurrency",
            limitUnits: 1,
            committedUnits: 0,
            heldUnits: 1,
            totalUnits: 1,
            availableUnits: 0,
            overdrawnUnits: 0,
        };
        const broker = {
            config: DEFAULT_RESOURCE_BROKER_CONFIG,
            verifyIntegrity() {},
            reclaimStale: () => [],
            getInvestigation: () => ({ lifecycleState: "active" }),
            getUsageSnapshot: () => [row],
            listActiveLeases: () => targetLeases,
        };
        expect(evaluateRecoveryBrokerCapacity({
            broker,
            investigationId: "investigation",
            reservation: { sdkSessions: 1 },
        })).toMatchObject({
            ok: false,
            code: RECOVERY_DISCOVERY_CODES.BROKER_CAPACITY_BLOCKED,
        });
        targetLeases = [{
            allocations: [{
                resourceKey: "sdk_sessions",
                reservedUnits: 1,
            }],
        }];
        expect(evaluateRecoveryBrokerCapacity({
            broker,
            investigationId: "investigation",
            reservation: { sdkSessions: 1 },
        })).toMatchObject({ ok: true });
    });

    it("probes capacity for the next external effect kind only", () => {
        const executionLimits = {
            byteBudgets: {
                perAttemptOutputBytes: 10,
                perAttemptReceiptBytes: 20,
                perAttemptCasBytes: 30,
            },
            workingSetPolicy: {
                perAttemptBytes: 40,
            },
        };
        const options = {
            executionLimits,
            sdkRetryPolicy: {
                maxCostUnits: 50,
                reservedCostUnitsPerAttempt: 25,
            },
        };
        expect(recoveryReservationForCommand({
            kind: "search_candidate",
        }, options)).toEqual({
            outputBytes: 10,
            receiptBytes: 20,
            casBytes: 30,
            storageBytes: 40,
            sdkSessions: 1,
            modelCostUnits: 50,
        });
        expect(recoveryReservationForCommand({
            kind: "dispatch_reserved",
            reservedCommand: { kind: "run_validation" },
        }, options)).toMatchObject({
            sandboxProcesses: 1,
            cpuSlots: { general: 1 },
        });
        expect(recoveryReservationForCommand({
            kind: "commit_evidence",
        }, options)).toEqual({});
    });

    it("fails closed for runtime drift, unavailable auth, and broker limits", async () => {
        const runtimeDrift = inspectSetup({
            dependencies: {
                verifyRuntimeConfigAuthority: () => {
                    throw Object.assign(new Error("drift"), {
                        code: "CRUCIBLE_RUNTIME_DRIFT",
                    });
                },
            },
        });
        expect(await inspectRecoveryInvestigation(
            runtimeDrift.input,
            runtimeDrift.dependencies,
        )).toMatchObject({
            eligible: false,
            code: RECOVERY_DISCOVERY_CODES.RUNTIME_DRIFT,
        });

        const authUnavailable = inspectSetup({
            dependencies: {
                probeSdkAvailability: async () => ({
                    ok: false,
                    code: "SDK_AUTH_UNAVAILABLE",
                }),
            },
        });
        expect(await inspectRecoveryInvestigation(
            authUnavailable.input,
            authUnavailable.dependencies,
        )).toMatchObject({
            eligible: false,
            code: RECOVERY_DISCOVERY_CODES.SDK_AUTH_UNAVAILABLE,
        });

        const capacity = inspectSetup({
            dependencies: {
                evaluateBrokerCapacity: () => ({
                    ok: false,
                    code:
                        RECOVERY_DISCOVERY_CODES.BROKER_CAPACITY_BLOCKED,
                }),
            },
        });
        expect(await inspectRecoveryInvestigation(
            capacity.input,
            capacity.dependencies,
        )).toMatchObject({
            eligible: false,
            code: RECOVERY_DISCOVERY_CODES.BROKER_CAPACITY_BLOCKED,
        });
    });

    it("returns only a verified supervisor config for an eligible missing run", async () => {
        const setup = inspectSetup();
        const result = await inspectRecoveryInvestigation(
            setup.input,
            setup.dependencies,
        );
        expect(result).toMatchObject({
            eligible: true,
            state: "eligible",
            code: RECOVERY_DISCOVERY_CODES.ELIGIBLE,
        });
        expect(result.config).toBeDefined();
        expect(JSON.stringify(result)).not.toContain("decision");
        expect(JSON.stringify(result)).not.toContain("candidate");
    });
});
