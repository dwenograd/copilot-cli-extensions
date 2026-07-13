import fs from "node:fs";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";
import {
    createDomainRepositoryAdapter,
} from "../runtime/index.mjs";
import {
    cleanupImpossibilityRunnerFixture,
    cloneImpossibilityRunnerFixture,
    replayImpossibilityRunnerFixture,
    runImpossibilityRunnerFixture,
    setupImpossibilityRunnerFixture,
} from "./impossibility-runner-fixture.mjs";

const fixtures = [];

function track(setup) {
    fixtures.push(setup);
    return setup;
}

afterEach(async () => {
    for (const setup of fixtures.splice(0).reverse()) {
        await cleanupImpossibilityRunnerFixture(setup);
    }
}, 30_000);

function impossibilityObservation(aggregate) {
    return aggregate.observationOrder
        .map((id) => aggregate.observations[id])
        .find((observation) => observation.purpose === "impossibility");
}

function corruptObject(setup, objectId, mutation = "tampered") {
    const store = openArtifactStore({ root: setup.artifactRoot });
    fs.appendFileSync(store.objectPath(objectId), mutation);
}

function removeObject(setup, objectId) {
    const store = openArtifactStore({ root: setup.artifactRoot });
    fs.rmSync(store.objectPath(objectId), { force: true });
}

function expectReplayFailure(setup, pattern) {
    const repository = openRepository({
        file: path.join(setup.stateDir, "events.sqlite"),
    });
    const artifactStore = openArtifactStore({ root: setup.artifactRoot });
    const adapter = createDomainRepositoryAdapter({
        repository,
        artifactStore,
        investigationId: setup.config.investigationId,
    });
    try {
        expect(() => adapter.replay()).toThrow(pattern);
    } finally {
        repository.close();
    }
}

describe("runner-supervised impossibility verification", () => {
    it("persists code-verified per-enumerand observations and complete receipts", async () => {
        const setup = track(setupImpossibilityRunnerFixture("valid"));
        const { result } = await runImpossibilityRunnerFixture(setup);
        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
        });

        const replay = replayImpossibilityRunnerFixture(setup);
        try {
            expect(replay.aggregate.pause).toBeNull();
            expect(replay.aggregate.stopRequests).toEqual([]);
            expect(replay.adapter.latestOperationalNonResult()).toBeNull();
            expect(replay.repository.getQuiescentStop(
                setup.config.investigationId,
            )).toBeNull();
            const observation =
                impossibilityObservation(replay.aggregate);
            const execution = observation.verifierExecution;
            expect(execution).toMatchObject({
                version: "crucible-verified-impossibility-execution-v1",
                facts: {
                    mode: "enumerand_reexecution",
                    status: "VERIFIED",
                    complete: true,
                    disagreementCount: 0,
                    enumerandObservations: [{
                        ordinal: 0,
                        checkerReceipt: {
                            receiptHash: expect.stringMatching(
                                /^sha256:crucible-verified-impossibility-checker-receipt-v1:/u,
                            ),
                        },
                    }],
                },
                effectBinding: {
                    effectAttempt: {
                        leaseId: expect.any(String),
                        fencingToken: expect.any(Number),
                        supervisorGeneration: null,
                    },
                    observationAttempt: {
                        leaseId: expect.any(String),
                        fencingToken: expect.any(Number),
                        supervisorGeneration: null,
                    },
                },
            });
            const receipt = JSON.parse(replay.artifactStore.readObject(
                execution.measurement.receiptArtifact.objectId,
                { verify: true },
            ).toString("utf8"));
            expect(receipt).toMatchObject({
                version: 8,
                harnessId: "verifier-harness",
                role: "impossibility_verifier",
                parserIdentity:
                    setup.contract.harnessSuite.roles.impossibility_verifier
                        .parser,
                sandbox: {
                    capabilityLaunchUsed: true,
                    policyIdentity: {
                        securityContext: {
                            appContainer: true,
                            lowIntegrity: true,
                            capabilities: [],
                        },
                    },
                },
            });
        } finally {
            replay.repository.close();
        }
    }, 30_000);

    it("persists actual proof bytes and an adapter-derived certificate checker receipt", async () => {
        const setup = track(setupImpossibilityRunnerFixture(
            "certificate",
            { mode: "certificate_validation" },
        ));
        const { result } = await runImpossibilityRunnerFixture(setup);
        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
        });

        const replay = replayImpossibilityRunnerFixture(setup);
        let execution;
        try {
            execution =
                impossibilityObservation(replay.aggregate).verifierExecution;
            expect(execution.proof.sizeBytes).toBeGreaterThan(0);
            expect(replay.artifactStore.readObject(
                execution.proof.artifact.objectId,
                { verify: true },
            ).length).toBe(execution.proof.sizeBytes);
            expect(execution.facts).toMatchObject({
                mode: "certificate_validation",
                proofCheckerReceipt: {
                    proofArtifactHash: execution.proof.artifactHash,
                    receiptHash: expect.stringMatching(
                        /^sha256:crucible-verified-impossibility-checker-receipt-v1:/u,
                    ),
                },
            });
        } finally {
            replay.repository.close();
        }

        const receiptTamper = track(cloneImpossibilityRunnerFixture(
            setup,
            "receipt",
        ));
        corruptObject(
            receiptTamper,
            execution.measurement.receiptArtifact.objectId,
        );
        expectReplayFailure(
            receiptTamper,
            /Domain hash-chain|receipt|checksum|corrupt/u,
        );

        const outputTamper = track(cloneImpossibilityRunnerFixture(
            setup,
            "stdout",
        ));
        corruptObject(
            outputTamper,
            execution.measurement.rawStdoutArtifact.objectId,
        );
        expectReplayFailure(
            outputTamper,
            /Domain hash-chain|stdout|checksum|corrupt/u,
        );

        const missingProof = track(cloneImpossibilityRunnerFixture(
            setup,
            "proof",
        ));
        removeObject(missingProof, execution.proof.artifact.objectId);
        expectReplayFailure(
            missingProof,
            /Domain hash-chain|proof|missing|corrupt/u,
        );
    }, 30_000);
});
