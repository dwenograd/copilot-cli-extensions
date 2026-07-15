import fs from "node:fs";
import path from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";

import { afterEach, describe, expect, it } from "vitest";

import {
    cleanupImpossibilityRunnerFixture,
    replayImpossibilityRunnerFixture,
    runImpossibilityRunnerFixture,
    setupImpossibilityRunnerFixture,
} from "../impossibility-runner-fixture.mjs";

const fixtures = [];

afterEach(async () => {
    for (const fixture of fixtures.splice(0).reverse()) {
        await cleanupImpossibilityRunnerFixture(fixture);
    }
}, 180_000);

function overfitProcessAdapter(acceptanceThreshold) {
    let nextPid = 12_000;
    const children = new Map();
    return {
        spawn(_executable, _argv, options) {
            const child = new EventEmitter();
            child.pid = ++nextPid;
            child.stdout = new PassThrough();
            child.stderr = new PassThrough();
            const state = { child, closed: false };
            children.set(child.pid, state);
            setImmediate(() => {
                const snapshotPath =
                    options.env.CANDIDATE_SNAPSHOT_PATH;
                const raw = fs.readFileSync(
                    path.join(snapshotPath, "score.txt"),
                    "utf8",
                ).trim();
                const phase = options.env.CRUCIBLE_PHASE;
                const armId = options.env.CRUCIBLE_ARM_ID;
                let score = Number(raw);
                if (armId === "candidate" && phase === "search") {
                    score = 100;
                } else if (
                    armId === "candidate"
                    && (phase === "confirmation" || phase === "challenge")
                ) {
                    score = 101;
                }
                const novelty = phase === "novelty";
                child.stdout.end(Buffer.from(JSON.stringify({
                    pass: novelty || score >= acceptanceThreshold,
                    metrics: novelty ? { score: 1 } : { score },
                }), "utf8"));
                child.stderr.end();
                state.closed = true;
                children.delete(child.pid);
                child.emit("close", 0, null);
            });
            return child;
        },
        terminateTree(pid) {
            const state = children.get(pid);
            if (state === undefined || state.closed) return false;
            state.child.stdout.end();
            state.child.stderr.end();
            state.closed = true;
            children.delete(pid);
            setImmediate(() => state.child.emit("close", null, "SIGKILL"));
            return true;
        },
    };
}

describe("v4 science gate through the autonomous runner", () => {
    it("reaches TARGET_UNREACHABLE only after the real independent verifier", async () => {
        const setup = setupImpossibilityRunnerFixture("science-verified");
        fixtures.push(setup);
        const { result } = await runImpossibilityRunnerFixture(setup);
        expect(result).toMatchObject({
            kind: "TERMINAL",
            decision: "TARGET_UNREACHABLE",
        });

        const replay = replayImpossibilityRunnerFixture(setup);
        try {
            const verifierObservation = replay.aggregate.observationOrder
                .map((id) => replay.aggregate.observations[id])
                .find((observation) =>
                    observation.purpose === "impossibility");
            expect(verifierObservation.verifierExecution.facts).toMatchObject({
                status: "VERIFIED",
                complete: true,
                disagreementCount: 0,
            });
        } finally {
            replay.repository.close();
        }
    }, 180_000);

    it("lets discovery pass but fails closed on an invalid held-out observation", async () => {
        const acceptanceThreshold = 50;
        const setup = setupImpossibilityRunnerFixture(
            "science-overfit",
            {
                maxBlocks: 17,
                alpha: 0.99,
                acceptanceThreshold,
            },
        );
        fixtures.push(setup);
        setup.config.deadline = Date.now() + 300_000;
        const { result } = await runImpossibilityRunnerFixture(setup, {
            processAdapter: overfitProcessAdapter(acceptanceThreshold),
        });
        const replay = replayImpossibilityRunnerFixture(setup);
        let candidate;
        let confirmationState;
        let heldOut;
        try {
            candidate = replay.aggregate.evidenceOrder
                .map((id) => replay.aggregate.evidence[id])
                .find((evidence) => evidence.purpose === "candidate");
            confirmationState =
                replay.aggregate.scientificReplay.confirmationState;
            heldOut = replay.aggregate.evidenceOrder
                .map((id) => replay.aggregate.evidence[id])
                .filter((evidence) =>
                    evidence.purpose === "confirmation"
                    || evidence.purpose === "challenge");
        } finally {
            replay.repository.close();
        }
        expect(candidate.statisticalEvaluation.requiredState)
            .toBe("SUPPORTED");
        expect(result).toMatchObject({
            kind: "NON_RESULT",
            code: "SCIENTIFIC_CONFIRMATION_FAILED",
        });
        expect(confirmationState).toMatchObject({
            status: "FAILED",
            failed: true,
        });
        expect(heldOut.map((evidence) => [
            evidence.purpose,
            evidence.statisticalEvaluation.requiredState,
        ])).toEqual([
            ["confirmation", "INVALID"],
        ]);
    }, 300_000);
});
