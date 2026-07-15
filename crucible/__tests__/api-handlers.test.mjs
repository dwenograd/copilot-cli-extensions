import path from "node:path";

import { describe, expect, it } from "vitest";

import {
    buildRegistration,
    resultInvestigation,
    runToolBoundary,
    statusInvestigation,
    stopInvestigation,
} from "../api/handlers.mjs";
import {
    PUBLIC_TOOL_NAMES,
    TOOL_SPECS,
    crucibleStartSpec,
} from "../api/schema.mjs";
import {
    INTEGRITY_NON_RESULT_BANNER,
    NON_RESULT_BANNER,
} from "../api/result.mjs";

const INVESTIGATION_ID = "fast-investigation";

function aggregate(overrides = {}) {
    return {
        experimentAuthority: {
            identity: "authority-v1",
            manifest: {
                experimentPayload: {
                    experimentId: "approved-experiment",
                    projectDir: "C:\\approved-project",
                    harnessSuiteId: "approved-suite",
                },
            },
        },
        experimentAuthorityIdentity: "authority-v1",
        contract: {},
        contractHash: "contract-secret",
        terminal: null,
        pause: null,
        nonResults: [],
        status: "running",
        lastSeq: 3,
        lastEventHash: "event-secret",
        ...overrides,
    };
}

function makeReadDeps({
    replayAggregate = aggregate(),
    readiness = {
        ready: true,
        integrityBound: true,
        nonResultCode: null,
        missing: [],
    },
    requestStop = () => {
        throw new Error("unexpected stop request");
    },
    waitForStopAcknowledgement = undefined,
    verifyAuthority = () => {},
    quiescentStop = null,
    storageTelemetry = null,
    catalogEntry = null,
} = {}) {
    const repository = {
        close() {},
        getQuiescentStop: () => quiescentStop,
    };
    const adapter = {
        replay: () => ({ aggregate: replayAggregate }),
        verifyTerminalArtifactClosure: () => ({
            aggregate: replayAggregate,
            artifactClosureReport: { verified: true },
        }),
        latestOperationalNonResult: () => null,
    };
    return {
        env: {
            CRUCIBLE_STATE_ROOT: path.resolve("crucible-fast-test-state"),
        },
        log: () => {},
        pathExists: () => true,
        inspectUncatalogedLegacyInvestigation: () => false,
        openRepositoryReadOnly: () => repository,
        createDomainRepositoryAdapter: () => adapter,
        openArtifactStoreReadOnly: () => ({}),
        verifyExperimentAuthority: verifyAuthority,
        assessPersistedTerminalReadiness: () => readiness,
        requestStop,
        ...(waitForStopAcknowledgement === undefined
            ? {}
            : { waitForStopAcknowledgement }),
        readStatus: () => null,
        readSupervisorLock: () => null,
        isPidAlive: () => false,
        ...(storageTelemetry === null
            ? {}
            : { readWorkingSetTelemetry: () => storageTelemetry }),
        ...(catalogEntry === null
            ? {}
            : {
                resourceCatalogPath: () =>
                    path.resolve("resource-catalog.sqlite"),
                openResourceBrokerFromStateRoot: () => ({
                    close() {},
                    getInvestigation: () => catalogEntry,
                    listInvestigations: () => {
                        const entries = [catalogEntry];
                        Object.defineProperty(entries, "catalogGeneration", {
                            value: 1,
                        });
                        return entries;
                    },
                }),
                openResourceBrokerReadOnlyFromStateRoot: () => ({
                    close() {},
                    getInvestigation: () => catalogEntry,
                    listInvestigations: () => {
                        const entries = [catalogEntry];
                        Object.defineProperty(entries, "catalogGeneration", {
                            value: 1,
                        });
                        return entries;
                    },
                }),
                verifyBundleInPlace: () => ({
                    digest: catalogEntry.archive?.digest ?? null,
                    investigationId: INVESTIGATION_ID,
                    domainVersion: 4,
                    domainHead: {
                        seq: replayAggregate.lastSeq,
                        eventHash: replayAggregate.lastEventHash,
                    },
                    trustLevel: "authenticated",
                }),
                verifySignedTombstone: () => ({
                    verified: true,
                    digest: catalogEntry.tombstone?.digest ?? null,
                    sizeBytes:
                        catalogEntry.tombstone?.sizeBytes ?? null,
                    signingKeyFingerprint:
                        catalogEntry.tombstone
                            ?.signingKeyFingerprint ?? null,
                    signature:
                        catalogEntry.tombstone?.signature ?? null,
                    payload: catalogEntry.tombstone === null
                        ? null
                        : {
                            createdAtMs:
                                catalogEntry.registeredAtMs,
                            archiveDigest:
                                catalogEntry.tombstone.archiveDigest,
                            domainVersion:
                                catalogEntry.tombstone.domainVersion,
                            domainHead:
                                catalogEntry.tombstone.domainHead,
                            deletedAt: new Date(
                                catalogEntry.tombstone.deletedAtMs,
                            ).toISOString(),
                        },
                }),
            }),
    };
}

function parseBoundary(response) {
    return JSON.parse(response.textResultForLlm);
}

describe("compact four-tool API boundary", () => {
    it("registers exactly four tools and reserves result authority to crucible_result", () => {
        const registration = buildRegistration({ deps: makeReadDeps() });
        expect(registration.tools.map((tool) => tool.name))
            .toEqual(PUBLIC_TOOL_NAMES);

        const validArgs = {
            crucible_start: { experiment_id: "approved-experiment" },
            crucible_status: {
                operation: "get",
                investigation_id: INVESTIGATION_ID,
            },
            crucible_stop: {
                operation: "pause",
                investigation_id: INVESTIGATION_ID,
            },
            crucible_result: { investigation_id: INVESTIGATION_ID },
        };
        for (const spec of TOOL_SPECS) {
            const response = runToolBoundary(
                spec,
                () => ({
                    is_result: true,
                    investigation_id: INVESTIGATION_ID,
                    decision: "VERIFIED_RESULT",
                }),
                validArgs[spec.name],
                makeReadDeps(),
            );
            const payload = parseBoundary(response);
            if (spec.name === "crucible_result") {
                expect(response.resultType).toBe("success");
                expect(payload).toMatchObject({
                    ok: true,
                    is_result: true,
                    decision: "VERIFIED_RESULT",
                });
            } else {
                expect(response.resultType).toBe("failure");
                expect(payload).toMatchObject({
                    ok: false,
                    is_result: false,
                    code: "CRUCIBLE_API_PUBLIC_PAYLOAD_INVARIANT",
                    tool: spec.name,
                });
                expect(payload).not.toHaveProperty("decision");
            }
        }
    });

    it("parses the operator-owned experiment_id start form without legacy model inputs", () => {
        let parsed = null;
        const response = runToolBoundary(
            crucibleStartSpec,
            (args) => {
                parsed = args;
                return {
                    is_result: false,
                    investigation_id: INVESTIGATION_ID,
                    experiment_id: args.experiment_id,
                };
            },
            { experiment_id: "approved-experiment" },
            makeReadDeps(),
        );

        expect(response.resultType).toBe("success");
        expect(parsed).toEqual({ experiment_id: "approved-experiment" });
        expect(parseBoundary(response)).toMatchObject({
            ok: true,
            is_result: false,
            experiment_id: "approved-experiment",
        });

        const rejected = runToolBoundary(
            crucibleStartSpec,
            () => ({ is_result: false }),
            {
                experiment_id: "approved-experiment",
                objective: "model-authored objective",
            },
            makeReadDeps(),
        );
        expect(rejected.resultType).toBe("failure");
    });
});

describe("compact handler safety guarantees", () => {
    it("redacts a ready terminal from status to the exact availability allowlist", () => {
        const status = statusInvestigation(
            {
                operation: "get",
                investigation_id: INVESTIGATION_ID,
            },
            makeReadDeps({
                replayAggregate: aggregate({
                    status: "terminal",
                    terminal: {
                        decision: "VERIFIED_RESULT",
                        candidateId: "winner-secret",
                        evidenceHash: "evidence-secret",
                    },
                }),
            }),
        );

        expect(status).toEqual({
            is_result: false,
            investigation_id: INVESTIGATION_ID,
            terminal_available: true,
        });

        expect(JSON.stringify(status)).not.toContain("winner-secret");
        expect(JSON.stringify(status)).not.toContain("evidence-secret");
    });

    it("verifies archived bundles in place for status and result", () => {
        const terminalAggregate = aggregate({
            status: "terminal",
            terminal: {
                decision: "VERIFIED_RESULT",
                candidateId: "archived-winner",
                evidenceHash: "archived-evidence",
                seq: 3,
                eventHash: "event-secret",
            },
        });

        const catalogEntry = {
            investigationId: INVESTIGATION_ID,
            lifecycleState: "archived",
            registeredAtMs: 1_000,
            lifecycleUpdatedAtMs: 2_000,
            archive: {
                relativePath:
                    `.retention/archives/${INVESTIGATION_ID}`,
                digest: `sha256:${"a".repeat(64)}`,
                trustLevel: "authenticated",
                domainVersion: 4,
                terminalAvailable: true,
                integrityStatus: "verified",
                sizeBytes: 100,
                domainHead: {
                    seq: 3,
                    eventHash: "event-secret",
                },
                archivedAtMs: 2_000,
            },
            tombstone: null,
        };
        const deps = makeReadDeps({
            replayAggregate: terminalAggregate,
            catalogEntry,
        });
        expect(statusInvestigation({
            operation: "get",
            investigation_id: INVESTIGATION_ID,
        }, deps)).toEqual({
            is_result: false,
            investigation_id: INVESTIGATION_ID,
            terminal_available: true,
        });
        expect(resultInvestigation({
            investigation_id: INVESTIGATION_ID,
        }, deps)).toMatchObject({
            is_result: true,
            investigation_id: INVESTIGATION_ID,
            decision: "VERIFIED_RESULT",
            candidate_id: "archived-winner",
        });
    });

    it("reports a verified tombstone without reviving result authority", () => {
        const catalogEntry = {
            investigationId: INVESTIGATION_ID,
            lifecycleState: "tombstoned",
            registeredAtMs: 1_000,
            lifecycleUpdatedAtMs: 2_000,
            archive: null,
            tombstone: {
                relativePath:
                    `.retention/tombstones/${INVESTIGATION_ID}.json`,
                digest: `sha256:${"a".repeat(64)}`,
                signingKeyFingerprint:
                    `sha256:crucible-tombstone-signing-key-v1:${
                        "b".repeat(64)
                    }`,
                signature: "signed",
                archiveDigest: `sha256:${"c".repeat(64)}`,
                domainVersion: 4,
                domainHead: {
                    seq: 3,
                    eventHash: "event-secret",
                },
                sizeBytes: 100,
                deletedAtMs: 2_000,
                integrityStatus: "verified",
            },
        };
        const deps = makeReadDeps({ catalogEntry });
        expect(statusInvestigation({
            operation: "get",
            investigation_id: INVESTIGATION_ID,
        }, deps)).toMatchObject({
            is_result: false,
            state: "tombstoned",
            deleted: true,
            integrity_status: "verified",
            terminal_available: false,
        });
        const result = resultInvestigation({
            investigation_id: INVESTIGATION_ID,
        }, deps);
        expect(result).toMatchObject({
            is_result: false,
            state: "tombstoned",
            deleted: true,
            non_result_code: "INVESTIGATION_TOMBSTONED",
        });
        expect(result).not.toHaveProperty("decision");
        expect(result).not.toHaveProperty("evidence_hash");
    });

    it("claims resumability only after pause and quiescence are durable", async () => {
        const pending = await stopInvestigation(
            {
                operation: "pause",
                investigation_id: INVESTIGATION_ID,
            },
            makeReadDeps({
                requestStop: () => ({
                    appended: true,
                    pausePersisted: false,
                    aggregate: aggregate(),
                    operationalNonResult: null,
                    stop: {
                        state: "STOP_BARRIER_PERSISTED",
                        quiescent: false,
                        interventionRequired: false,
                        nonResultCode: null,
                    },
                }),
            }),
        );
        expect(pending).toMatchObject({
            stop_state: "pause_requested",
            pause_requested: true,
            pause_in_flight: true,
            pause_persisted: false,
            quiescent: false,
            resumable: false,
        });

        const persisted = await stopInvestigation(
            {
                operation: "pause",
                investigation_id: INVESTIGATION_ID,
            },
            makeReadDeps({
                requestStop: () => ({
                    appended: true,
                    pausePersisted: true,
                    aggregate: aggregate({
                        status: "paused",
                        pause: { reason: "operator pause" },
                    }),
                    operationalNonResult: null,
                    stop: {
                        state: "PAUSED_QUIESCENT",
                        quiescent: true,
                        interventionRequired: false,
                        nonResultCode: null,
                    },
                }),
            }),
        );
        expect(persisted).toMatchObject({
            stop_state: "pause_persisted",
            pause_in_flight: false,
            pause_persisted: true,
            quiescent: true,
            resumable: true,
        });
    });

    it("reports pause-pending status as non-quiescent and non-resumable", () => {
        const status = statusInvestigation(
            {
                operation: "get",
                investigation_id: INVESTIGATION_ID,
            },
            makeReadDeps({
                replayAggregate: aggregate({
                    contract: null,
                    status: "paused",
                    pause: { reason: "stop requested" },
                }),
                quiescentStop: {
                    state: "PAUSE_PENDING",
                    quiescent: false,
                    interventionRequired: true,
                },
            }),
        );

        expect(status).toMatchObject({
            paused: true,
            quiescent: false,
            resumable: false,
            stop_state: "PAUSE_PENDING",
            intervention_required: true,
        });
    });

    it("keeps public status read-only when the supervisor is absent", () => {
        let ensureCalls = 0;
        const status = statusInvestigation(
            {
                operation: "get",
                investigation_id: INVESTIGATION_ID,
            },
            {
                ...makeReadDeps({
                    replayAggregate: aggregate({
                        contract: null,
                        status: "running",
                    }),
                }),
                ensureSupervisor() {
                    ensureCalls += 1;
                    throw new Error("status must not launch a supervisor");
                },
            },
        );
        expect(ensureCalls).toBe(0);
        expect(status.supervisor_health).toMatchObject({
            present: false,
            alive: false,
            ensure_action: null,
        });
    });

    it("exposes aggregate storage telemetry without result details", () => {
            const budget = {
                currentBytes: 42,
                limitBytes: 100,
                effectiveLimitBytes: 95,
                remainingBytes: 53,
                warningBytes: 90,
                pressure: "normal",
            };
            const status = statusInvestigation(
                {
                    operation: "get",
                    investigation_id: INVESTIGATION_ID,
                },
                makeReadDeps({
                    replayAggregate: aggregate({
                        contract: null,
                        status: "paused",
                        pause: { reason: "storage telemetry test" },
                    }),
                    storageTelemetry: {
                        investigation: {
                            bytes: 42,
                            files: 3,
                            directories: 2,
                            unsafeEntries: 0,
                            budget,
                        },
                        global: {
                            bytes: 84,
                            files: 6,
                            directories: 4,
                            unsafeEntries: 0,
                            budget: {
                                ...budget,
                                currentBytes: 84,
                                limitBytes: 200,
                                effectiveLimitBytes: 200,
                                remainingBytes: 116,
                                warningBytes: 180,
                            },
                        },
                        repository: null,
                        artifacts: null,
                        thresholds: {
                            perAttemptBytes: 10,
                            perInvestigationBytes: 100,
                            globalBytes: 200,
                        },
                        diagnostics: {
                            retentionMode: "defer",
                            cleanupDeferred: true,
                        },
                    },
                }),
            );
            expect(status.storage).toMatchObject({
                investigation: {
                    bytes: 42,
                    files: 3,
                    budget: {
                        limit_bytes: 100,
                        pressure: "normal",
                    },
                },
                global: {
                    bytes: 84,
                },
            });
            const serialized = JSON.stringify(status);
            for (const forbidden of [
                "winner",
                "candidate_id",
                "evidence_id",
                "evidence_hash",
                "VERIFIED_RESULT",
                "TARGET_UNREACHABLE",
            ]) {
                expect(serialized).not.toContain(forbidden);
            }
    });

    it("reports bounded acknowledgement timeout as non-quiescent and non-resumable", async () => {
        const stopped = await stopInvestigation(
            {
                operation: "pause",
                investigation_id: INVESTIGATION_ID,
            },
            makeReadDeps({
                requestStop: () => ({
                    appended: true,
                    pausePersisted: false,
                    aggregate: aggregate(),
                    operationalNonResult: null,
                    stop: {
                        requestId: "stop-timeout",
                        state: "STOP_BARRIER_PERSISTED",
                        quiescent: false,
                        interventionRequired: false,
                        nonResultCode: null,
                    },
                }),
                waitForStopAcknowledgement: async () => ({
                    acknowledged: true,
                    timedOut: true,
                    stop: {
                        requestId: "stop-timeout",
                        state: "PAUSE_PENDING",
                        quiescent: false,
                        interventionRequired: true,
                        nonResultCode:
                            "CRUCIBLE_RUNTIME_NON_QUIESCENT",
                    },
                }),
            }),
        );

        expect(stopped).toMatchObject({
            stop_state: "pause_pending",
            pause_in_flight: true,
            pause_persisted: false,
            quiescent: false,
            resumable: false,
            intervention_required: true,
            acknowledgement_timed_out: true,
            non_result_code: "CRUCIBLE_RUNTIME_NON_QUIESCENT",
        });
    });

    it("blocks terminal disclosure when frozen scientific readiness is incomplete", () => {
        const result = resultInvestigation(
            { investigation_id: INVESTIGATION_ID },
            makeReadDeps({
                replayAggregate: aggregate({
                    status: "terminal",
                    terminal: {
                        decision: "VERIFIED_RESULT",
                        candidateId: "winner-secret",
                        evidenceHash: "evidence-secret",
                    },
                }),
                readiness: {
                    ready: false,
                    integrityBound: true,
                    nonResultCode: "SCIENTIFIC_CONFIRMATION_REQUIRED",
                    missing: ["held_out_confirmation"],
                },
            }),
        );

        expect(result).toMatchObject({
            is_result: false,
            banner: NON_RESULT_BANNER,
            integrity_blocked: false,
            scientific_blocked: true,
            terminal_available: false,
            non_result_code: "SCIENTIFIC_CONFIRMATION_REQUIRED",
        });
        expect(result).not.toHaveProperty("decision");
        expect(result).not.toHaveProperty("candidate_id");
        expect(result).not.toHaveProperty("evidence_hash");
    });

    it("fails closed when persisted experiment authority cannot be verified", () => {
        const result = resultInvestigation(
            { investigation_id: INVESTIGATION_ID },
            makeReadDeps({
                verifyAuthority: () => {
                    throw new Error("authority signature mismatch");
                },
            }),
        );

        expect(result).toMatchObject({
            is_result: false,
            banner: INTEGRITY_NON_RESULT_BANNER,
            integrity_blocked: true,
            non_result_code: "INTEGRITY_BLOCKED",
        });
        expect(result).not.toHaveProperty("contract_hash");
        expect(result).not.toHaveProperty("decision");
    });
});
