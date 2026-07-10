// crucible/__tests__/persistence-commands.test.mjs
//
// Durable command lifecycle: reserved -> dispatched -> observed -> committed,
// illegal-transition rejection, and fencing-token / lease-ownership checks at
// every transition.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { openRepository, ERROR_CODES } from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

let dir;
let repo;

beforeEach(() => {
    dir = fs.mkdtempSync(path.join(HERE, ".persist-tmp-"));
    repo = openRepository({ file: path.join(dir, "events.sqlite") });
    repo.ensureInvestigation({ investigationId: "inv-1" });
});

afterEach(() => {
    try {
        repo?.close();
    } catch {
        // already closed
    }
    fs.rmSync(dir, { recursive: true, force: true });
});

function catchCode(fn) {
    try {
        fn();
    } catch (err) {
        return err;
    }
    throw new Error("expected the operation to throw");
}

function acquire(leaseId, owner) {
    return repo.acquireLease({ investigationId: "inv-1", leaseId, owner });
}

describe("command lifecycle transition legality", () => {
    it("walks the full legal lifecycle and stamps timestamps", () => {
        acquire("lease-1", "runner-A");
        repo.reserveCommand({
            investigationId: "inv-1",
            attemptId: "cmd-1",
            command: "probe endpoint",
            leaseId: "lease-1",
            fencingToken: 1,
            owner: "runner-A",
        });
        expect(repo.getCommandAttempt("cmd-1").state).toBe("reserved");

        repo.dispatchCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 });
        expect(repo.getCommandAttempt("cmd-1").state).toBe("dispatched");

        repo.observeCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 });
        expect(repo.getCommandAttempt("cmd-1").state).toBe("observed");

        const committed = repo.commitCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 });
        expect(committed.state).toBe("committed");
        expect(committed.dispatchedAt).not.toBeNull();
        expect(committed.observedAt).not.toBeNull();
        expect(committed.committedAt).not.toBeNull();
    });

    it("rejects skipping a state (reserved -> observed)", () => {
        acquire("lease-1", "runner-A");
        repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "c",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        });
        const err = catchCode(() => repo.observeCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 }));
        expect(err.code).toBe(ERROR_CODES.ILLEGAL_TRANSITION);
        expect(err.details).toMatchObject({ from: "reserved", to: "observed", expected: "dispatched" });
        expect(repo.getCommandAttempt("cmd-1").state).toBe("reserved");
    });

    it("rejects a backward / repeated transition (committed has no successor)", () => {
        acquire("lease-1", "runner-A");
        repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "c",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        });
        repo.dispatchCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 });
        repo.observeCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 });
        repo.commitCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 });

        const err = catchCode(() => repo.commitCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 }));
        expect(err.code).toBe(ERROR_CODES.ILLEGAL_TRANSITION);
    });
});

describe("fencing token / lease ownership", () => {
    it("issues monotonically increasing fencing tokens per investigation", () => {
        expect(acquire("lease-1", "runner-A").fencingToken).toBe(1);
        expect(acquire("lease-2", "runner-B").fencingToken).toBe(2);
        expect(acquire("lease-3", "runner-A").fencingToken).toBe(3);
        expect(repo.getActiveLease("inv-1").fencingToken).toBe(3);
    });

    it("fences out a stale reservation once a newer lease is acquired", () => {
        acquire("lease-1", "runner-A");
        acquire("lease-2", "runner-B"); // supersedes lease-1 (token 2)

        const err = catchCode(() => repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "c",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        }));
        expect(err.code).toBe(ERROR_CODES.FENCE_REJECTED);
    });

    it("fences a transition when a newer lease was acquired after reservation", () => {
        acquire("lease-1", "runner-A");
        repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "c",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        });
        repo.dispatchCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 });

        // A new runner takes the lease; the old runner's token is now stale.
        acquire("lease-2", "runner-B");

        const err = catchCode(() => repo.observeCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 1 }));
        expect(err.code).toBe(ERROR_CODES.FENCE_REJECTED);
        expect(repo.getCommandAttempt("cmd-1").state).toBe("dispatched"); // unchanged
    });

    it("rejects a transition presenting a token other than the reserving one", () => {
        acquire("lease-1", "runner-A");
        repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "c",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        });
        const err = catchCode(() => repo.dispatchCommand({ investigationId: "inv-1", attemptId: "cmd-1", fencingToken: 2 }));
        expect(err.code).toBe(ERROR_CODES.FENCE_REJECTED);
    });

    it("rejects a reservation whose owner does not match the lease owner", () => {
        acquire("lease-1", "runner-A");
        const err = catchCode(() => repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "c",
            leaseId: "lease-1", fencingToken: 1, owner: "impostor",
        }));
        expect(err.code).toBe(ERROR_CODES.FENCE_REJECTED);
    });

    it("rejects reserving against an unknown lease", () => {
        const err = catchCode(() => repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "c",
            leaseId: "ghost", fencingToken: 1, owner: "runner-A",
        }));
        expect(err.code).toBe(ERROR_CODES.LEASE_NOT_FOUND);
    });

    it("prevents a duplicate active reservation for the same command", () => {
        acquire("lease-1", "runner-A");
        repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "same",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        });
        const err = catchCode(() => repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-2", command: "same",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        }));
        expect(err.code).toBe(ERROR_CODES.RESERVATION_CONFLICT);
    });

    it("distinguishes duplicate attempt ids from command conflicts", () => {
        acquire("lease-1", "runner-A");
        repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "first",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        });
        const err = catchCode(() => repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-1", command: "different",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        }));
        expect(err.code).toBe(ERROR_CODES.INVALID_ARGUMENT);
    });

    it("lets a newer lease abandon a stale attempt and reserve the command again", () => {
        acquire("lease-1", "runner-A");
        repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-old", command: "same",
            leaseId: "lease-1", fencingToken: 1, owner: "runner-A",
        });
        repo.dispatchCommand({ investigationId: "inv-1", attemptId: "cmd-old", fencingToken: 1 });
        acquire("lease-2", "runner-B");

        const abandoned = repo.abandonStaleCommand({
            investigationId: "inv-1",
            attemptId: "cmd-old",
            leaseId: "lease-2",
            fencingToken: 2,
            owner: "runner-B",
        });
        expect(abandoned.state).toBe("abandoned");
        expect(abandoned.abandonedAt).not.toBeNull();

        const replacement = repo.reserveCommand({
            investigationId: "inv-1", attemptId: "cmd-new", command: "same",
            leaseId: "lease-2", fencingToken: 2, owner: "runner-B",
        });
        expect(replacement.state).toBe("reserved");
    });

    it("binds supervisor generation and attempt logical identity to atomic persistence", () => {
        repo.ensureInvestigation({ investigationId: "inv-1.runtime-evidence" });
        repo.claimSupervisorGeneration({
            investigationId: "inv-1",
            supervisorGeneration: 7,
            supervisorNonce: "supervisor-generation-7",
        });
        repo.issueRunnerIncarnation({
            investigationId: "inv-1",
            supervisorGeneration: 7,
            supervisorNonce: "supervisor-generation-7",
            runnerIncarnation: "runner-incarnation-7a",
        });
        const lease = repo.acquireLease({
            investigationId: "inv-1",
            leaseId: "lease-generation-7",
            owner: "runner-A",
            supervisorGeneration: 7,
            runnerIncarnation: "runner-incarnation-7a",
        });
        const command = JSON.stringify({
            scope: "external-effect",
            logicalEffectKey: "effect-1",
        });
        repo.reserveCommand({
            investigationId: "inv-1",
            attemptId: "effect-attempt",
            command,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration,
            runnerIncarnation: lease.runnerIncarnation,
        });
        repo.dispatchCommand({
            investigationId: "inv-1",
            attemptId: "effect-attempt",
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration,
            runnerIncarnation: lease.runnerIncarnation,
        });
        repo.observeCommand({
            investigationId: "inv-1",
            attemptId: "effect-attempt",
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration,
            runnerIncarnation: lease.runnerIncarnation,
        });

        expect(() => repo.ingestEvidenceBatchWithAttemptTransition({
            investigationId: "inv-1.runtime-evidence",
            authorityInvestigationId: "inv-1",
            attemptId: "effect-attempt",
            attemptCommand: JSON.stringify({ scope: "wrong-effect" }),
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration,
            runnerIncarnation: lease.runnerIncarnation,
            fromState: "observed",
            toState: "committed",
            evidence: [{
                evidenceKind: "proposal",
                kind: "runtime:model_proposal",
                payload: { logicalEffectKey: "effect-1" },
            }],
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.ATTEMPT_IDENTITY_MISMATCH,
        }));
        expect(repo.countEvents("inv-1.runtime-evidence")).toBe(0);
        expect(repo.getCommandAttempt("effect-attempt").state).toBe("observed");

        expect(() => repo.ingestEvidenceBatchWithAttemptTransition({
            investigationId: "inv-1.runtime-evidence",
            authorityInvestigationId: "inv-1",
            attemptId: "effect-attempt",
            attemptCommand: command,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            fromState: "observed",
            toState: "committed",
            evidence: [{
                evidenceKind: "proposal",
                kind: "runtime:model_proposal",
                payload: { logicalEffectKey: "effect-1" },
            }],
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.FENCE_REJECTED,
        }));
        expect(repo.countEvents("inv-1.runtime-evidence")).toBe(0);
        expect(repo.getCommandAttempt("effect-attempt").state).toBe("observed");

        const committed = repo.ingestEvidenceBatchWithAttemptTransition({
            investigationId: "inv-1.runtime-evidence",
            authorityInvestigationId: "inv-1",
            attemptId: "effect-attempt",
            attemptCommand: command,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration,
            runnerIncarnation: lease.runnerIncarnation,
            fromState: "observed",
            toState: "committed",
            evidence: [
                {
                    evidenceKind: "proposal",
                    kind: "runtime:model_proposal",
                    payload: { logicalEffectKey: "effect-1" },
                },
                {
                    evidenceKind: "receipt",
                    kind: "runtime:measurement",
                    payload: { logicalEffectKey: "effect-1", score: 95 },
                },
            ],
        });
        expect(committed.deduplicated).toBe(false);
        expect(committed.events).toHaveLength(2);
        expect(committed.attempt.state).toBe("committed");

        const retry = repo.ingestEvidenceBatchWithAttemptTransition({
            investigationId: "inv-1.runtime-evidence",
            authorityInvestigationId: "inv-1",
            attemptId: "effect-attempt",
            attemptCommand: command,
            leaseId: lease.leaseId,
            fencingToken: lease.fencingToken,
            owner: lease.owner,
            supervisorGeneration: lease.supervisorGeneration,
            runnerIncarnation: lease.runnerIncarnation,
            fromState: "observed",
            toState: "committed",
            evidence: [
                {
                    evidenceKind: "proposal",
                    kind: "runtime:model_proposal",
                    payload: { logicalEffectKey: "effect-1" },
                },
                {
                    evidenceKind: "receipt",
                    kind: "runtime:measurement",
                    payload: { logicalEffectKey: "effect-1", score: 95 },
                },
            ],
        });
        expect(retry.deduplicated).toBe(true);
        expect(repo.countEvents("inv-1.runtime-evidence")).toBe(2);
        expect(repo.getCommandAttempt("effect-attempt").state).toBe("committed");
    });

    it("fences delayed generations and single-use incarnations across two repositories", () => {
        const repoB = openRepository({ file: repo.databaseFile });
        try {
            repo.claimSupervisorGeneration({
                investigationId: "inv-1",
                supervisorGeneration: 1,
                supervisorNonce: "supervisor-one",
            });
            repo.issueRunnerIncarnation({
                investigationId: "inv-1",
                supervisorGeneration: 1,
                supervisorNonce: "supervisor-one",
                runnerIncarnation: "generation-one-delayed-launch",
            });
            repoB.claimSupervisorGeneration({
                investigationId: "inv-1",
                supervisorGeneration: 2,
                supervisorNonce: "supervisor-two",
            });
            repoB.issueRunnerIncarnation({
                investigationId: "inv-1",
                supervisorGeneration: 2,
                supervisorNonce: "supervisor-two",
                runnerIncarnation: "generation-two-launch-one",
            });

            expect(() => repo.acquireLease({
                investigationId: "inv-1",
                leaseId: "delayed-generation-one",
                owner: "runner-generation-one",
                supervisorGeneration: 1,
                runnerIncarnation: "generation-one-delayed-launch",
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.FENCE_REJECTED,
            }));
            expect(repoB.getActiveLease("inv-1")).toBeNull();
            expect(repoB.countEvents("inv-1")).toBe(0);

            const firstCurrentLease = repoB.acquireLease({
                investigationId: "inv-1",
                leaseId: "generation-two-lease-one",
                owner: "runner-generation-two-one",
                supervisorGeneration: 2,
                runnerIncarnation: "generation-two-launch-one",
            });
            expect(firstCurrentLease.fencingToken).toBe(1);
            const command = "same-generation-restart-command";
            repoB.reserveCommand({
                investigationId: "inv-1",
                attemptId: "same-generation-old-attempt",
                command,
                leaseId: firstCurrentLease.leaseId,
                fencingToken: firstCurrentLease.fencingToken,
                owner: firstCurrentLease.owner,
                supervisorGeneration: firstCurrentLease.supervisorGeneration,
                runnerIncarnation: firstCurrentLease.runnerIncarnation,
            });
            repoB.dispatchCommand({
                investigationId: "inv-1",
                attemptId: "same-generation-old-attempt",
                leaseId: firstCurrentLease.leaseId,
                fencingToken: firstCurrentLease.fencingToken,
                owner: firstCurrentLease.owner,
                supervisorGeneration: firstCurrentLease.supervisorGeneration,
                runnerIncarnation: firstCurrentLease.runnerIncarnation,
            });

            repoB.issueRunnerIncarnation({
                investigationId: "inv-1",
                supervisorGeneration: 2,
                supervisorNonce: "supervisor-two",
                runnerIncarnation: "generation-two-launch-two",
            });
            const activeBeforeRejection = repoB.getActiveLease("inv-1");
            const eventsBeforeRejection = repoB.countEvents("inv-1");
            expect(() => repo.appendEventsWithAttemptTransition({
                investigationId: "inv-1",
                expectedHead: null,
                events: [{ kind: "stale-domain-event", payload: { stale: true } }],
                attemptId: "same-generation-old-attempt",
                attemptCommand: command,
                leaseId: firstCurrentLease.leaseId,
                fencingToken: firstCurrentLease.fencingToken,
                owner: firstCurrentLease.owner,
                supervisorGeneration: firstCurrentLease.supervisorGeneration,
                runnerIncarnation: firstCurrentLease.runnerIncarnation,
                fromState: "dispatched",
                toState: "observed",
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.FENCE_REJECTED,
            }));
            expect(repoB.countEvents("inv-1")).toBe(eventsBeforeRejection);
            expect(repoB.getCommandAttempt("same-generation-old-attempt").state)
                .toBe("dispatched");
            expect(repoB.getActiveLease("inv-1")).toEqual(activeBeforeRejection);

            expect(() => repo.acquireLease({
                investigationId: "inv-1",
                leaseId: "same-generation-old-reacquire",
                owner: "runner-generation-two-old",
                supervisorGeneration: 2,
                runnerIncarnation: "generation-two-launch-one",
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.FENCE_REJECTED,
            }));
            expect(repoB.countEvents("inv-1")).toBe(eventsBeforeRejection);
            expect(repoB.getActiveLease("inv-1")).toEqual(activeBeforeRejection);

            const currentLease = repoB.acquireLease({
                investigationId: "inv-1",
                leaseId: "generation-two-lease-two",
                owner: "runner-generation-two-two",
                supervisorGeneration: 2,
                runnerIncarnation: "generation-two-launch-two",
            });
            expect(currentLease.fencingToken).toBe(2);
            repoB.abandonStaleCommand({
                investigationId: "inv-1",
                attemptId: "same-generation-old-attempt",
                leaseId: currentLease.leaseId,
                fencingToken: currentLease.fencingToken,
                owner: currentLease.owner,
                supervisorGeneration: currentLease.supervisorGeneration,
                runnerIncarnation: currentLease.runnerIncarnation,
            });
            repoB.reserveCommand({
                investigationId: "inv-1",
                attemptId: "same-generation-current-attempt",
                command,
                leaseId: currentLease.leaseId,
                fencingToken: currentLease.fencingToken,
                owner: currentLease.owner,
                supervisorGeneration: currentLease.supervisorGeneration,
                runnerIncarnation: currentLease.runnerIncarnation,
            });
            repoB.dispatchCommand({
                investigationId: "inv-1",
                attemptId: "same-generation-current-attempt",
                leaseId: currentLease.leaseId,
                fencingToken: currentLease.fencingToken,
                owner: currentLease.owner,
                supervisorGeneration: currentLease.supervisorGeneration,
                runnerIncarnation: currentLease.runnerIncarnation,
            });
            repoB.appendEventsWithAttemptTransition({
                investigationId: "inv-1",
                expectedHead: null,
                events: [{ kind: "current-domain-event", payload: { current: true } }],
                attemptId: "same-generation-current-attempt",
                attemptCommand: command,
                leaseId: currentLease.leaseId,
                fencingToken: currentLease.fencingToken,
                owner: currentLease.owner,
                supervisorGeneration: currentLease.supervisorGeneration,
                runnerIncarnation: currentLease.runnerIncarnation,
                fromState: "dispatched",
                toState: "observed",
            });
            expect(repoB.countEvents("inv-1")).toBe(1);
            expect(repoB.getCommandAttempt("same-generation-current-attempt").state)
                .toBe("observed");
        } finally {
            repoB.close();
        }
    });
});
