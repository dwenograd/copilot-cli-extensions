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
            crucible_status: { investigation_id: INVESTIGATION_ID },
            crucible_stop: { investigation_id: INVESTIGATION_ID },
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

    it("claims resumability only after pause and quiescence are durable", async () => {
        const pending = await stopInvestigation(
            { investigation_id: INVESTIGATION_ID },
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
            { investigation_id: INVESTIGATION_ID },
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
            { investigation_id: INVESTIGATION_ID },
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

    it("reports bounded acknowledgement timeout as non-quiescent and non-resumable", async () => {
        const stopped = await stopInvestigation(
            { investigation_id: INVESTIGATION_ID },
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
