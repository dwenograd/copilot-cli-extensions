import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    ERROR_CODES,
    openRepository,
} from "../persistence/index.mjs";
import {
    QUIESCENT_STOP_STATES,
    buildQuiescenceSnapshot,
    consumeSupervisorStopSignal,
    persistPausedQuiescent,
    persistQuiescentStopBarrier,
    stopControlPaths,
    writeSupervisorStopSignal,
} from "../runtime/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
const INVESTIGATION_ID = "quiescent-stop-investigation";

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.runtime-control-${label}-`),
    );
    roots.push(root);
    return root;
}

function setupAuthority(label) {
    const root = makeRoot(label);
    const stateDir = path.join(root, "state");
    fs.mkdirSync(stateDir, { recursive: true });
    const repository = openRepository({
        file: path.join(stateDir, "events.sqlite"),
    });
    repository.ensureInvestigation({
        investigationId: INVESTIGATION_ID,
    });
    repository.claimSupervisorGeneration({
        investigationId: INVESTIGATION_ID,
        supervisorGeneration: 1,
        supervisorNonce: "owner-one",
    });
    repository.issueRunnerIncarnation({
        investigationId: INVESTIGATION_ID,
        supervisorGeneration: 1,
        supervisorNonce: "owner-one",
        runnerIncarnation: "runner-one",
    });
    const lease = repository.acquireLease({
        investigationId: INVESTIGATION_ID,
        leaseId: "lease-one",
        owner: "runner-owner",
        supervisorGeneration: 1,
        runnerIncarnation: "runner-one",
    });
    return {
        root,
        stateDir,
        repository,
        lease,
        owner: {
            pid: 4101,
            nonce: "owner-one",
            supervisorGeneration: 1,
        },
    };
}

function reserve(repository, lease, attemptId, command, state = "reserved") {
    repository.reserveCommand({
        investigationId: INVESTIGATION_ID,
        attemptId,
        command,
        leaseId: lease.leaseId,
        fencingToken: lease.fencingToken,
        owner: lease.owner,
        supervisorGeneration: lease.supervisorGeneration,
        runnerIncarnation: lease.runnerIncarnation,
    });
    if (["dispatched", "observed"].includes(state)) {
        repository.dispatchCommand({
            investigationId: INVESTIGATION_ID,
            attemptId,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration,
            runnerIncarnation: lease.runnerIncarnation,
        });
    }
    if (state === "observed") {
        repository.observeCommand({
            investigationId: INVESTIGATION_ID,
            attemptId,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration,
            runnerIncarnation: lease.runnerIncarnation,
        });
    }
}

function barrier(setup, requestId = "stop-one") {
    return persistQuiescentStopBarrier({
        repository: setup.repository,
        investigationId: INVESTIGATION_ID,
        requestId,
        reason: "operator requested quiescence",
        owner: setup.owner,
        runnerPid: 5101,
    });
}

function quiescenceProof(setup, overrides = {}) {
    return buildQuiescenceSnapshot({
        repository: setup.repository,
        investigationId: INVESTIGATION_ID,
        supervisorStatus: {
            verified: true,
            pid: setup.owner.pid,
            supervisorGeneration: setup.owner.supervisorGeneration,
            supervisorNonce: setup.owner.nonce,
            runnerIncarnation: "runner-one",
            state: "stopping",
            ...(overrides.supervisorStatus ?? {}),
        },
        processes: {
            verified: true,
            activePids: [],
            ...(overrides.processes ?? {}),
        },
        sdkSessions: {
            verified: true,
            activeCount: 0,
            ...(overrides.sdkSessions ?? {}),
        },
        runnerChild: {
            verified: true,
            active: false,
            pid: 5101,
            runnerIncarnation: "runner-one",
            ...(overrides.runnerChild ?? {}),
        },
        resourceBroker: {
            verified: true,
            configured: false,
            authorityRetired: true,
            activeLeases: [],
            ...(overrides.resourceBroker ?? {}),
        },
    });
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

describe("v4 quiescent-stop persistence barrier", () => {
    it("fences the launch race before another incarnation or lease can start", () => {
        const setup = setupAuthority("launch-race");
        try {
            const stop = barrier(setup);
            expect(stop).toMatchObject({
                state: QUIESCENT_STOP_STATES.BARRIER_PERSISTED,
                targetSupervisorGeneration: 1,
                targetRunnerIncarnation: "runner-one",
                targetFencingToken: 1,
            });
            expect(setup.repository.getActiveLease(INVESTIGATION_ID)).toBeNull();

            expect(() => setup.repository.issueRunnerIncarnation({
                investigationId: INVESTIGATION_ID,
                supervisorGeneration: 1,
                supervisorNonce: "owner-one",
                runnerIncarnation: "runner-after-stop",
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.FENCE_REJECTED,
                details: expect.objectContaining({
                    stopRequestId: "stop-one",
                }),
            }));
            expect(() => setup.repository.acquireLease({
                investigationId: INVESTIGATION_ID,
                leaseId: "lease-after-stop",
                owner: "runner-after-stop",
                supervisorGeneration: 1,
                runnerIncarnation: "runner-one",
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.FENCE_REJECTED,
            }));
        } finally {
            setup.repository.close();
        }
    });

    it("quarantines the receipt race and rejects post-barrier observation", () => {
        const setup = setupAuthority("receipt-race");
        try {
            reserve(
                setup.repository,
                setup.lease,
                "attempt-receipt",
                "receipt-command",
                "dispatched",
            );
            const stop = barrier(setup);
            expect(stop.fencedAttempts).toEqual([
                expect.objectContaining({
                    attemptId: "attempt-receipt",
                    previousState: "dispatched",
                }),
            ]);
            expect(setup.repository.getCommandAttempt("attempt-receipt").state)
                .toBe("abandoned");
            expect(() => setup.repository.observeCommand({
                investigationId: INVESTIGATION_ID,
                attemptId: "attempt-receipt",
                leaseId: setup.lease.leaseId,
                fencingToken: setup.lease.fencingToken,
                owner: setup.lease.owner,
                supervisorGeneration: 1,
                runnerIncarnation: "runner-one",
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.FENCE_REJECTED,
            }));
        } finally {
            setup.repository.close();
        }
    });

    it("rejects the commit race with zero post-stop evidence", () => {
        const setup = setupAuthority("commit-race");
        try {
            reserve(
                setup.repository,
                setup.lease,
                "attempt-commit",
                "commit-command",
                "observed",
            );
            const before = setup.repository.countEvents(INVESTIGATION_ID);
            barrier(setup);
            expect(() =>
                setup.repository.ingestEvidenceBatchWithAttemptTransition({
                    investigationId: INVESTIGATION_ID,
                    authorityInvestigationId: INVESTIGATION_ID,
                    attemptId: "attempt-commit",
                    attemptCommand: "commit-command",
                    leaseId: setup.lease.leaseId,
                    fencingToken: setup.lease.fencingToken,
                    owner: setup.lease.owner,
                    supervisorGeneration: 1,
                    runnerIncarnation: "runner-one",
                    fromState: "observed",
                    toState: "committed",
                    evidence: [{
                        evidenceKind: "late-receipt",
                        kind: "runtime:test-evidence",
                        payload: { forbidden: true },
                    }],
                })).toThrow(expect.objectContaining({
                    code: ERROR_CODES.FENCE_REJECTED,
                }));
            expect(setup.repository.countEvents(INVESTIGATION_ID)).toBe(before);
            expect(setup.repository.listCommittableAttempts(INVESTIGATION_ID))
                .toEqual([]);
        } finally {
            setup.repository.close();
        }
    });

    it("atomically rejects PAUSED_QUIESCENT when an older non-final attempt remains", () => {
        const setup = setupAuthority("atomic-attempt-recheck");
        try {
            reserve(
                setup.repository,
                setup.lease,
                "orphaned-attempt",
                "orphaned-command",
                "dispatched",
            );
            setup.repository.issueRunnerIncarnation({
                investigationId: INVESTIGATION_ID,
                supervisorGeneration: 1,
                supervisorNonce: "owner-one",
                runnerIncarnation: "runner-two",
            });
            setup.repository.acquireLease({
                investigationId: INVESTIGATION_ID,
                leaseId: "lease-two",
                owner: "runner-owner-two",
                supervisorGeneration: 1,
                runnerIncarnation: "runner-two",
            });
            const stop = barrier(setup);
            const proof = quiescenceProof(setup, {
                supervisorStatus: {
                    runnerIncarnation: "runner-two",
                },
                runnerChild: {
                    runnerIncarnation: "runner-two",
                },
            });
            expect(proof).toMatchObject({
                verified: true,
                quiescent: true,
                committableAttempts: [],
            });
            expect(() => setup.repository.completeQuiescentStop({
                investigationId: INVESTIGATION_ID,
                requestId: stop.requestId,
                state: QUIESCENT_STOP_STATES.PAUSED_QUIESCENT,
                quiescent: true,
                interventionRequired: false,
                details: { proof },
                quiescenceProof: proof,
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.FENCE_REJECTED,
                details: expect.objectContaining({
                    activeAttemptCount: 1,
                }),
            }));
        } finally {
            setup.repository.close();
        }
    });

    it("rejects a stale or wrong-generation stop without changing authority", () => {
        const setup = setupAuthority("wrong-generation");
        try {
            expect(() => persistQuiescentStopBarrier({
                repository: setup.repository,
                investigationId: INVESTIGATION_ID,
                requestId: "wrong-generation-stop",
                reason: "stale caller",
                owner: {
                    pid: 4102,
                    nonce: "owner-two",
                    supervisorGeneration: 2,
                },
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.FENCE_REJECTED,
            }));
            expect(setup.repository.getQuiescentStop(INVESTIGATION_ID))
                .toBeNull();
            expect(setup.repository.getActiveLease(INVESTIGATION_ID))
                .toMatchObject({ leaseId: "lease-one", releasedAt: null });
        } finally {
            setup.repository.close();
        }
    });

    it("allows a later generation only after PAUSED_QUIESCENT persisted", () => {
        const setup = setupAuthority("resume-generation");
        try {
            const stop = barrier(setup);
            const proof = quiescenceProof(setup);
            setup.repository.completeQuiescentStop({
                investigationId: INVESTIGATION_ID,
                requestId: stop.requestId,
                state: QUIESCENT_STOP_STATES.PAUSED_QUIESCENT,
                quiescent: true,
                interventionRequired: false,
                details: { proof },
                quiescenceProof: proof,
            });
            setup.repository.claimSupervisorGeneration({
                investigationId: INVESTIGATION_ID,
                supervisorGeneration: 2,
                supervisorNonce: "owner-two",
            });
            expect(setup.repository.issueRunnerIncarnation({
                investigationId: INVESTIGATION_ID,
                supervisorGeneration: 2,
                supervisorNonce: "owner-two",
                runnerIncarnation: "runner-two",
            })).toMatchObject({
                supervisorGeneration: 2,
                runnerIncarnation: "runner-two",
            });
        } finally {
            setup.repository.close();
        }
    });

    it("marks a terminal race superseded instead of manufacturing a pause", () => {
        const setup = setupAuthority("terminal-race");
        try {
            const stop = barrier(setup);
            const proof = quiescenceProof(setup);
            const completed = persistPausedQuiescent({
                repository: setup.repository,
                adapter: {
                    replay: () => ({
                        aggregate: {
                            terminal: { decision: "VERIFIED_RESULT" },
                            nonResults: [],
                        },
                    }),
                },
                stop,
                proof,
            });
            expect(completed).toMatchObject({
                state: QUIESCENT_STOP_STATES.SUPERSEDED,
                quiescent: false,
                interventionRequired: false,
                details: { supersededBy: "terminal" },
            });
        } finally {
            setup.repository.close();
        }
    });
});

describe("owner-scoped stop control and quiescence proof", () => {
    it("signals and consumes only the exact supervisor owner", () => {
        const setup = setupAuthority("exact-control");
        try {
            const stop = barrier(setup);
            const paths = stopControlPaths(
                setup.stateDir,
                INVESTIGATION_ID,
            );
            const signal = writeSupervisorStopSignal({
                paths,
                stop,
                owner: setup.owner,
                clock: {
                    isoNow: () => "2026-07-13T20:00:00.000Z",
                },
            });
            expect(fs.existsSync(signal.file)).toBe(true);
            expect(consumeSupervisorStopSignal({
                paths,
                stop,
                owner: {
                    pid: 4102,
                    nonce: "owner-two",
                    supervisorGeneration: 2,
                },
            })).toBeNull();
            expect(fs.existsSync(signal.file)).toBe(true);
            expect(consumeSupervisorStopSignal({
                paths,
                stop,
                owner: setup.owner,
            })).toMatchObject({
                requestId: stop.requestId,
                target: {
                    pid: setup.owner.pid,
                    supervisorGeneration: 1,
                },
            });
            expect(fs.existsSync(signal.file)).toBe(false);
        } finally {
            setup.repository.close();
        }
    });

    it("requires every lease, process, SDK session, and broker lease to be zero", () => {
        const setup = setupAuthority("zero-proof");
        try {
            expect(buildQuiescenceSnapshot({
                repository: setup.repository,
                investigationId: INVESTIGATION_ID,
            }).quiescent).toBe(false);
            barrier(setup);
            expect(quiescenceProof(setup)).toMatchObject({
                verified: true,
                quiescent: true,
                activeRunnerLease: null,
                activePids: [],
                activeSdkSessions: 0,
                activeResourceLeases: [],
            });
            expect(quiescenceProof(setup, {
                processes: { activePids: [7001] },
            }).quiescent).toBe(false);
            expect(quiescenceProof(setup, {
                sdkSessions: { activeCount: 1 },
            }).quiescent).toBe(false);
            expect(quiescenceProof(setup, {
                resourceBroker: {
                    activeLeases: [{ leaseId: "broker-lease" }],
                },
            }).quiescent).toBe(false);
            expect(quiescenceProof(setup, {
                supervisorStatus: {
                    verified: false,
                    reason: "missing status",
                },
            })).toMatchObject({
                verified: false,
                quiescent: false,
                activePids: [],
                activeSdkSessions: 0,
            });
            expect(() => persistPausedQuiescent({
                repository: setup.repository,
                adapter: null,
                stop: setup.repository.getQuiescentStop(
                    INVESTIGATION_ID,
                ),
                proof: { verified: false, quiescent: false },
            })).toThrow(expect.objectContaining({
                code: "CRUCIBLE_RUNTIME_NON_QUIESCENT",
            }));
        } finally {
            setup.repository.close();
        }
    });
});
