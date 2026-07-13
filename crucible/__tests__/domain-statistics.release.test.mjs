import { describe, expect, it } from "vitest";

import {
    evaluateThresholdClaim,
    hoeffdingMeanConfidenceSequence,
} from "../domain/index.mjs";

function mulberry32(seed) {
    let state = seed >>> 0;
    return () => {
        state += 0x6d2b79f5;
        let value = state;
        value = Math.imul(value ^ (value >>> 15), value | 1);
        value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
        return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
    };
}

function optionalPeekingTrial(random, probability, peeks, alphaClaim) {
    const observations = [];
    let nextPeek = 0;
    for (let index = 1; index <= peeks.at(-1); index += 1) {
        observations.push(random() < probability ? 1 : 0);
        if (index !== peeks[nextPeek]) continue;
        const confidence = hoeffdingMeanConfidenceSequence({
            observations,
            alphaClaim,
        });
        if (evaluateThresholdClaim(
            confidence.confidenceSequence,
            ">",
            0.5,
        ) === "SUPPORTED") {
            return true;
        }
        nextPeek += 1;
    }
    return false;
}

describe("v4 bounded statistics deterministic science simulations", () => {
    it("controls null false positives under optional peeking and retains known-effect power", () => {
        const random = mulberry32(0x5eedc0de);
        const peeks = [16, 32, 64, 128, 256, 512];
        const alphaClaim = 0.025;
        const nullTrials = 2_000;
        let falsePositives = 0;
        for (let trial = 0; trial < nullTrials; trial += 1) {
            if (optionalPeekingTrial(random, 0.5, peeks, alphaClaim)) {
                falsePositives += 1;
            }
        }
        const conservativeNinetyFivePercentUpperBound =
            (falsePositives + 3) / nullTrials;
        expect(falsePositives).toBeLessThanOrEqual(2);
        expect(conservativeNinetyFivePercentUpperBound).toBeLessThan(0.01);

        const effectTrials = 500;
        let detections = 0;
        for (let trial = 0; trial < effectTrials; trial += 1) {
            if (optionalPeekingTrial(random, 0.75, peeks, alphaClaim)) {
                detections += 1;
            }
        }
        expect(detections / effectTrials).toBeGreaterThan(0.9);
    });
});
