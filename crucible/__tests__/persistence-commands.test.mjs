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
});
