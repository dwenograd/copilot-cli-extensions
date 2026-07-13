import { describe, expect, it } from "vitest";

import {
    createInvestigationContract,
    createRawMeasurementSeries,
    deriveReplicationSchedule,
    deriveStatisticalCacheDigest,
    evaluateReplicatedStatisticalClaims,
    evaluateReplicationProgress,
    hashCanonical,
    normalizeRawMeasurementSeries,
    replicationBlockPlan,
} from "../domain/index.mjs";
import {
    fakeStatisticalPolicy,
    makeV4ContractInput,
} from "./v4-contract-fixture.mjs";

function fixture() {
    const contract = createInvestigationContract(makeV4ContractInput({
        statisticalPolicy: fakeStatisticalPolicy({
            minBlocks: 1,
            maxBlocks: 2,
        }),
    }));
    const schedule = deriveReplicationSchedule({
        contractHash: hashCanonical(contract),
        statisticalPolicy: contract.statisticalPolicy,
        subject: {
            kind: "candidate",
            index: 0,
            id: "candidate-fast",
            identity: hashCanonical({
                kind: "candidate",
                id: "candidate-fast",
            }),
        },
    });
    return { contract, schedule };
}

function attemptsFor(schedule, blockCount = 2) {
    return Array.from({ length: blockCount }, (_unused, blockIndex) =>
        replicationBlockPlan(schedule, blockIndex).arms.map((arm) => {
            const score = arm.armId === "candidate" ? 1 : 0;
            return {
                ...arm,
                attemptId: `attempt-${blockIndex}-${arm.armIndex}`,
                parsed: {
                    pass: score >= 0.8,
                    metrics: { score },
                    role: "search",
                    phase: "search",
                    replicateIndex: arm.replicateIndex,
                    blockIndex: arm.blockIndex,
                    armIndex: arm.armIndex,
                    armId: arm.armId,
                    deterministicSeed: arm.deterministicSeed,
                    subjectId: arm.subjectId,
                },
                invalid: null,
                receiptHash: hashCanonical({
                    kind: "receipt",
                    subjectId: arm.subjectId,
                }),
                measurementRoot: hashCanonical({
                    kind: "measurement",
                    subjectId: arm.subjectId,
                }),
            };
        })).flat();
}

function makeSeries(schedule, attempts = attemptsFor(schedule)) {
    return createRawMeasurementSeries({
        schedule,
        attempts,
        role: "search",
        phase: "search",
        caseId: null,
    });
}

function normalizeSeries(schedule, series) {
    return normalizeRawMeasurementSeries(series, {
        schedule,
        role: "search",
        phase: "search",
        caseId: null,
    });
}

function statisticalCacheCore(contract, schedule, series) {
    const attempts = normalizeSeries(schedule, series).attempts;
    const evaluation = evaluateReplicatedStatisticalClaims({
        contract,
        schedule,
        attempts,
    });
    const progress = evaluateReplicationProgress({
        contract,
        schedule,
        attempts,
    });
    const accepted = evaluation.requiredState === "SUPPORTED";
    return {
        version: 2,
        purpose: "candidate",
        replication: {
            version: 3,
            scheduleHash: evaluation.scheduleHash,
            minBlocks: schedule.minBlocks,
            maxBlocks: schedule.maxBlocks,
            blockCount: evaluation.blockCount,
            attemptCount: evaluation.attemptCount,
            blockLedgerHash: evaluation.blockLedger.hash,
            statisticalState: evaluation.requiredState,
            evaluationHash: evaluation.evaluationHash,
            stopping: progress.stopping,
            stoppingDigest: progress.stoppingDigest,
            control: null,
            controlTolerance: evaluation.controlTolerance,
        },
        metrics: evaluation.metrics,
        rankable: contract.metrics.every((metric) =>
            Number.isFinite(evaluation.metrics[metric.key])),
        outcomeClass: accepted ? "accepted" : "rejected",
        acceptanceSatisfied: accepted,
        statisticalEvaluation: evaluation,
        predictionEvaluation: null,
    };
}

describe("v4 raw-block replay statistics", () => {
    it("derives canonical raw blocks from unordered attempts", () => {
        const { schedule } = fixture();
        const series = makeSeries(
            schedule,
            attemptsFor(schedule).reverse(),
        );

        expect(series.completeBlocks.map((block) => block.blockIndex))
            .toEqual([0, 1]);
        for (const block of series.completeBlocks) {
            expect(block.observations.map((item) => item.armIndex))
                .toEqual([0, 1]);
        }
        expect(normalizeSeries(schedule, series).attempts).toHaveLength(4);
    });

    it("changes the statistical cache digest when raw block facts change", () => {
        const { contract, schedule } = fixture();
        const original = makeSeries(schedule);
        const staleDigest = deriveStatisticalCacheDigest(
            statisticalCacheCore(contract, schedule, original),
        );
        const changed = structuredClone(original);
        const candidate = changed.completeBlocks[0].observations.find(
            (item) => item.armId === "candidate",
        );
        candidate.parsed.pass = false;
        candidate.parsed.metrics.score = 0.25;

        expect(deriveStatisticalCacheDigest(
            statisticalCacheCore(contract, schedule, changed),
        )).not.toBe(staleDigest);
    });

    it("rejects a raw block with a missing scheduled arm", () => {
        const { schedule } = fixture();
        const incomplete = structuredClone(makeSeries(schedule));
        incomplete.completeBlocks[0].observations.pop();

        expect(() => normalizeSeries(schedule, incomplete))
            .toThrow(/every scheduled arm/u);
    });

    it("rejects non-canonical complete-block order", () => {
        const { schedule } = fixture();
        const reordered = structuredClone(makeSeries(schedule));
        reordered.completeBlocks.reverse();

        expect(() => normalizeSeries(schedule, reordered))
            .toThrow(/strictly ordered/u);
    });
});
