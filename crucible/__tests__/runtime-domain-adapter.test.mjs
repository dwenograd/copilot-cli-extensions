import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    DEFAULT_SEARCH_POLICY,
    createInvestigationContract,
} from "../domain/index.mjs";
import { PARSER_VERSION } from "../measurement/index.mjs";
import { openRepository } from "../persistence/index.mjs";
import {
    createDomainRepositoryAdapter,
    formatAttemptCommand,
} from "../runtime/index.mjs";
import { fakeHarnessIdentity } from "./harness-identity-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(() => {
    const failures = [];
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
        if (fs.existsSync(root)) {
            failures.push(new Error(`domain adapter root survived cleanup: ${root}`));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "domain adapter cleanup failed");
    }
});

function artifactHash(character) {
    return `sha256:${character.repeat(64)}`;
}

function contract() {
    return createInvestigationContract({
        objective: "exercise runtime domain adapter fencing",
        acceptancePredicate: { kind: "harness_pass" },
        validationCases: [
            { id: "good", expectation: "accept", artifactHash: artifactHash("a") },
            { id: "bad", expectation: "reject", artifactHash: artifactHash("b") },
        ],
        harnessId: "fixture-harness",
        hypothesisTopology: "finite_enumerable",
        boundedCandidateIds: ["candidate-a"],
        criticality: "high",
        policyVersion: "policy-v1",
        parserVersion: PARSER_VERSION,
        harnessIdentity: fakeHarnessIdentity({
            harnessId: "fixture-harness",
            parserVersion: PARSER_VERSION,
        }),
        workerModels: ["model-a"],
        candidatesPerRound: 1,
        maxRounds: 1,
        metrics: [],
        searchPolicy: DEFAULT_SEARCH_POLICY,
        declaredLimits: { maxCommands: 4 },
    });
}

function openAdapter(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.runtime-adapter-fast-${label}-`));
    roots.push(root);
    const repository = openRepository({ file: path.join(root, "events.sqlite") });
    const adapter = createDomainRepositoryAdapter({
        repository,
        investigationId: "inv-runtime-fast",
    });
    adapter.openInvestigation(contract());
    return { repository, adapter };
}

describe("Crucible domain repository adapter fast component coverage", () => {
    it("abandons stale reserved and dispatched attempts before replacement work", () => {
        const { repository, adapter } = openAdapter("recovery");
        try {
            const first = adapter.acquireRunnerLease({
                leaseId: "lease-one",
                owner: "runner-one",
            });
            adapter.reserveAttempt({
                attemptId: "attempt-reserved",
                command: formatAttemptCommand("test", { id: 1 }),
                lease: first.lease,
            });
            adapter.reserveAttempt({
                attemptId: "attempt-dispatched",
                command: formatAttemptCommand("test", { id: 2 }),
                lease: first.lease,
            });
            adapter.dispatchAttempt("attempt-dispatched", first.lease);

            const second = adapter.acquireRunnerLease({
                leaseId: "lease-two",
                owner: "runner-two",
            });
            expect(second.recovery).toMatchObject({
                abandonedCount: 2,
                uncertainDispatched: 1,
            });
            expect(repository.getCommandAttempt("attempt-reserved").state)
                .toBe("abandoned");
            expect(repository.getCommandAttempt("attempt-dispatched").state)
                .toBe("abandoned");
        } finally {
            repository.close();
        }
    });

    it("keeps operational evidence outside the domain sequence", () => {
        const { repository, adapter } = openAdapter("operational");
        try {
            const before = adapter.replay().aggregate.seq;
            adapter.ingestOperationalEvidence({
                attemptId: "attempt-fast",
                evidenceKind: "component",
                kind: "runtime:test",
                payload: { bounded: true },
            });

            expect(adapter.replay().aggregate.seq).toBe(before);
            expect(adapter.listOperationalEvidence()).toHaveLength(1);
        } finally {
            repository.close();
        }
    });
});
