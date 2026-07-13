import { describe, expect, it } from "vitest";

import {
    createInvestigationContract,
    deriveReplicationControlBinding,
    enumerandArtifactMeasurementHash,
    hashCanonical,
} from "../domain/index.mjs";
import {
    analyzeReplicationAttempts,
    deriveControlToleranceMetadata,
    deriveReplicationSchedule,
    evaluateReplicationProgress,
    replicationBlockPlan,
} from "../runtime/index.mjs";
import {
    fakeStatisticalPolicy,
    fakeEnumerandManifest,
    makeV4ContractInput,
} from "./v4-contract-fixture.mjs";

function contractWithPolicy({
    minBlocks = 1,
    maxBlocks = 3,
    threshold = 0.8,
    controlTolerance = { absolute: 0, relative: 0 },
    goalMode = "optimize",
} = {}) {
    const policy = fakeStatisticalPolicy({ minBlocks, maxBlocks });
    policy.goalMode = goalMode;
    policy.metrics[0].acceptanceThreshold = threshold;
    policy.control.tolerances = [{
        metric: "score",
        ...controlTolerance,
    }];
    return createInvestigationContract(makeV4ContractInput({
        statisticalPolicy: policy,
        acceptancePredicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: threshold,
        },
    }));
}

function scheduleFor(contract, overrides = {}) {
    return deriveReplicationSchedule({
        contractHash: hashCanonical(
            contract,
            "sha256:crucible-test-contract-v1",
        ),
        statisticalPolicy: contract.statisticalPolicy,
        subject: {
            kind: "candidate",
            index: 0,
            id: "candidate-0",
            identity: hashCanonical(
                { candidate: 0 },
                "sha256:crucible-test-subject-v1",
            ),
        },
        ...overrides,
    });
}

function attemptsForBlock(schedule, blockIndex, {
    candidate = { pass: true, metrics: { score: 1 } },
    control = { pass: true, metrics: { score: 0 } },
    invalidArm = null,
    omitArm = null,
} = {}) {
    return replicationBlockPlan(schedule, blockIndex).arms
        .filter((arm) => arm.armId !== omitArm)
        .map((arm) => ({
            ...arm,
            attemptId: `attempt-${blockIndex}-${arm.armIndex}`,
            parsed: arm.armId === "candidate" ? candidate : control,
            invalid: arm.armId === invalidArm
                ? { code: "FIXTURE_INVALID", message: "invalid fixture arm" }
                : null,
            receiptHash: hashCanonical({
                blockIndex,
                armIndex: arm.armIndex,
                kind: "receipt",
            }),
            measurementRoot: hashCanonical({
                blockIndex,
                armIndex: arm.armIndex,
                kind: "measurement",
            }),
        }));
}

describe("deterministic blocked measurement scheduler", () => {
    it("derives stable balanced candidate/control and multi-arm orders", () => {
        const contract = contractWithPolicy({ maxBlocks: 6 });
        const first = scheduleFor(contract);
        expect(first).toEqual(scheduleFor(contract));
        expect(Object.isFrozen(first)).toBe(true);

        const orders = Array.from({ length: 6 }, (_unused, blockIndex) =>
            replicationBlockPlan(first, blockIndex).executionOrder);
        expect(orders[1]).toEqual([...orders[0]].reverse());
        expect(orders[2]).toEqual(orders[0]);
        for (const blockIndex of [0, 1]) {
            const plan = replicationBlockPlan(first, blockIndex);
            expect(plan.arms.map((arm) => arm.armId).sort())
                .toEqual(["candidate", "control"]);
            for (const arm of plan.arms) {
                expect(arm).toMatchObject({
                    blockIndex,
                    replicateIndex: blockIndex,
                    armIndex: expect.any(Number),
                    deterministicSeed: expect.stringMatching(
                        /^sha256:crucible-replication-arm-seed-v1:[a-f0-9]{64}$/u,
                    ),
                    subjectId: expect.stringMatching(
                        /^rep-b\d{6}-a\d{2}-[a-f0-9]{12}$/u,
                    ),
                });
            }
        }

        const multi = scheduleFor(contract, {
            arms: ["candidate", "control", "parent"].map((armId, armIndex) => ({
                armId,
                armIndex,
                logicalSubjectId: armId,
                subjectKind: armId === "candidate"
                    ? "candidate"
                    : armId === "control"
                        ? contract.statisticalPolicy.control.kind
                        : "assigned_parent",
                subjectIdentity: armId === "control"
                    ? contract.statisticalPolicy.control.identity
                    : hashCanonical(
                        { armId },
                        "sha256:crucible-test-arm-v1",
                    ),
            })),
        });
        const positions = new Map();
        for (let blockIndex = 0; blockIndex < 3; blockIndex += 1) {
            replicationBlockPlan(multi, blockIndex).arms.forEach((arm) => {
                const values = positions.get(arm.armId) ?? [];
                values.push(arm.executionOrdinal);
                positions.set(arm.armId, values);
            });
        }
        for (const values of positions.values()) {
            expect([...values].sort()).toEqual([0, 1, 2]);
        }
    });

    it("continues unresolved claims through min blocks and stops at max", () => {
        const contract = contractWithPolicy({ minBlocks: 2, maxBlocks: 3 });
        const schedule = scheduleFor(contract);
        const oneBlock = attemptsForBlock(schedule, 0, {
            candidate: { pass: true, metrics: { score: 0.8 } },
            control: { pass: true, metrics: { score: 0.8 } },
        });
        const minimumPending = evaluateReplicationProgress({
            contract,
            schedule,
            attempts: oneBlock,
        });
        expect(minimumPending).toMatchObject({
            blockCount: 1,
            minimumMet: false,
            shouldContinue: true,
            stoppingReason: null,
        });

        const all = [
            ...oneBlock,
            ...attemptsForBlock(schedule, 1, {
                candidate: { pass: true, metrics: { score: 0.8 } },
                control: { pass: true, metrics: { score: 0.8 } },
            }),
            ...attemptsForBlock(schedule, 2, {
                candidate: { pass: true, metrics: { score: 0.8 } },
                control: { pass: true, metrics: { score: 0.8 } },
            }),
        ];
        expect(evaluateReplicationProgress({
            contract,
            schedule,
            attempts: all,
        })).toMatchObject({
            blockCount: 3,
            claimsResolved: false,
            shouldContinue: false,
            stoppingReason: "max_blocks",
            statistics: { overallState: "UNRESOLVED" },
        });
    });

    it("stops early after minimum blocks once all claims resolve", () => {
        const contract = contractWithPolicy({
            minBlocks: 1,
            maxBlocks: 5,
            threshold: 0,
            goalMode: "satisfice",
        });
        const schedule = scheduleFor(contract);
        const progress = evaluateReplicationProgress({
            contract,
            schedule,
            attempts: attemptsForBlock(schedule, 0),
        });
        expect(progress).toMatchObject({
            blockCount: 1,
            claimsResolved: true,
            shouldContinue: false,
            stoppingReason: "claims_resolved",
            statistics: { overallState: "SUPPORTED" },
        });
    });

    it("uses remaining preregistered blocks for optimize-mode tie resolution", () => {
        const contract = contractWithPolicy({
            minBlocks: 1,
            maxBlocks: 2,
            threshold: 0,
            goalMode: "optimize",
        });
        const schedule = scheduleFor(contract);
        const first = evaluateReplicationProgress({
            contract,
            schedule,
            attempts: attemptsForBlock(schedule, 0),
        });
        expect(first).toMatchObject({
            blockCount: 1,
            claimsResolved: true,
            tieResolutionBlocksPending: true,
            shouldContinue: true,
            stoppingReason: null,
        });
        expect(evaluateReplicationProgress({
            contract,
            schedule,
            attempts: [
                ...attemptsForBlock(schedule, 0),
                ...attemptsForBlock(schedule, 1),
            ],
        })).toMatchObject({
            blockCount: 2,
            tieResolutionBlocksPending: false,
            shouldContinue: false,
            stoppingReason: "claims_resolved",
        });
    });

    it("never consumes a partial block and applies missingness to invalid arms", () => {
        const contract = contractWithPolicy({ minBlocks: 1, maxBlocks: 2 });
        const schedule = scheduleFor(contract);
        const partial = attemptsForBlock(schedule, 0, { omitArm: "control" });
        const analyzed = analyzeReplicationAttempts({
            schedule,
            attempts: partial,
        });
        expect(analyzed).toMatchObject({
            contiguousCompleteBlockCount: 0,
            invalidIncompleteBlock: true,
            firstIncompleteBlock: {
                blockIndex: 0,
                presentArmCount: 1,
                missingArmCount: 1,
            },
            nextArm: { armId: "control" },
        });

        const invalidControl = attemptsForBlock(schedule, 0, {
            invalidArm: "control",
        });
        expect(evaluateReplicationProgress({
            contract,
            schedule,
            attempts: invalidControl,
        })).toMatchObject({
            blockCount: 1,
            stoppingReason: "claims_resolved",
            statistics: {
                overallState: "INVALID",
                invalid: {
                    code: "CRUCIBLE_STATISTICS_MISSINGNESS_POLICY_VIOLATION",
                },
            },
        });
    });

    it("routes control drift through missingness so it cannot validate", () => {
        const contract = contractWithPolicy({
            maxBlocks: 2,
            controlTolerance: { absolute: 0.05, relative: 0 },
        });
        const schedule = scheduleFor(contract);
        const attempts = [
            ...attemptsForBlock(schedule, 0, {
                control: { pass: true, metrics: { score: 0.2 } },
            }),
            ...attemptsForBlock(schedule, 1, {
                control: { pass: true, metrics: { score: 0.3 } },
            }),
        ];
        const analysis = analyzeReplicationAttempts({ schedule, attempts });
        const metadata = deriveControlToleranceMetadata({
            statisticalPolicy: contract.statisticalPolicy,
            blocks: analysis.completeBlocks.map((block) =>
                block.statisticalBlock),
        });
        expect(metadata).toMatchObject({
            status: "drift_detected",
            driftDetected: true,
            invalidObservation: false,
            metrics: [{
                metric: "score",
                absoluteTolerance: 0.05,
                baselineValue: 0.2,
                driftDetected: true,
            }],
        });
        expect(evaluateReplicationProgress({
            contract,
            schedule,
            attempts,
        })).toMatchObject({
            shouldContinue: false,
            statistics: {
                overallState: "INVALID",
                invalid: {
                    code: "CRUCIBLE_STATISTICS_MISSINGNESS_POLICY_VIOLATION",
                },
            },
            evaluation: {
                requiredState: "INVALID",
                completeValidBlocks: false,
                controlTolerance: {
                    driftDetected: true,
                },
            },
        });
    });

    it("is invariant to replay input order when block indexes are fixed", () => {
        const contract = contractWithPolicy({ minBlocks: 2, maxBlocks: 2 });
        const schedule = scheduleFor(contract);
        const attempts = [
            ...attemptsForBlock(schedule, 0),
            ...attemptsForBlock(schedule, 1),
        ];
        const forward = evaluateReplicationProgress({
            contract,
            schedule,
            attempts,
        });
        const reversed = evaluateReplicationProgress({
            contract,
            schedule,
            attempts: [...attempts].reverse(),
        });
        expect(reversed.statistics).toEqual(forward.statistics);
        expect(reversed.statisticalSummaryHash)
            .toBe(forward.statisticalSummaryHash);
        expect(reversed.controlTolerance).toEqual(forward.controlTolerance);
    });

    it("stops unresolved work at an exhausted evaluation budget", () => {
        const contract = contractWithPolicy({ minBlocks: 1, maxBlocks: 3 });
        const schedule = scheduleFor(contract);
        expect(evaluateReplicationProgress({
            contract,
            schedule,
            attempts: attemptsForBlock(schedule, 0, {
                candidate: { pass: true, metrics: { score: 0.8 } },
                control: { pass: true, metrics: { score: 0.8 } },
            }),
            budgetRemaining: false,
        })).toMatchObject({
            stoppingReason: "budget_exhausted",
            shouldContinue: false,
            statistics: { overallState: "UNRESOLVED" },
        });
    });

    it("binds the stopping digest to every committed block", () => {
        const contract = contractWithPolicy({
            minBlocks: 1,
            maxBlocks: 2,
            threshold: 0,
            goalMode: "optimize",
        });
        const schedule = scheduleFor(contract);
        const firstAttempts = attemptsForBlock(schedule, 0);
        const truncated = evaluateReplicationProgress({
            contract,
            schedule,
            attempts: firstAttempts,
        });
        const complete = evaluateReplicationProgress({
            contract,
            schedule,
            attempts: [
                ...firstAttempts,
                ...attemptsForBlock(schedule, 1, {
                    candidate: { pass: false, metrics: { score: 0 } },
                    control: { pass: true, metrics: { score: 1 } },
                }),
            ],
        });
        expect(truncated).toMatchObject({
            shouldContinue: true,
            minBlocks: 1,
            maxBlocks: 2,
        });
        expect(complete).toMatchObject({
            shouldContinue: false,
            blockCount: 2,
        });
        expect(complete.stoppingDigest).not.toBe(truncated.stoppingDigest);
        expect(complete.stopping.blockLedgerHash)
            .not.toBe(truncated.stopping.blockLedgerHash);
    });

    it("binds snapshot, enumerand, and calibration schedules to the signed control", () => {
        const snapshotContract = contractWithPolicy();
        const snapshotSchedule = scheduleFor(snapshotContract);
        const expectedSnapshot =
            `sha256:crucible-measurement-snapshot-v1:${
                snapshotContract.statisticalPolicy.control.identity
                    .slice("sha256:".length)
            }`;
        expect(deriveReplicationControlBinding({
            contractHash: snapshotSchedule.contractHash,
            statisticalPolicy: snapshotContract.statisticalPolicy,
            schedule: snapshotSchedule,
            controlSnapshotHashes: [expectedSnapshot],
            requireObservedControl: true,
        })).toMatchObject({
            kind: "snapshot",
            identity: snapshotContract.statisticalPolicy.control.identity,
            artifactHash: expectedSnapshot,
        });
        expect(() => deriveReplicationControlBinding({
            contractHash: snapshotSchedule.contractHash,
            statisticalPolicy: snapshotContract.statisticalPolicy,
            schedule: snapshotSchedule,
            controlSnapshotHashes: [
                `sha256:crucible-measurement-snapshot-v1:${"9".repeat(64)}`,
            ],
            requireObservedControl: true,
        })).toThrow(/outside the frozen control/u);

        const manifest = fakeEnumerandManifest(
            "finite_enumerable",
            ["control-enumerand"],
        );
        const enumerandPolicy = fakeStatisticalPolicy({
            topology: "finite_enumerable",
            manifest,
            searchSlots: 1,
        });
        const enumerandContract = createInvestigationContract(
            makeV4ContractInput({
                hypothesisTopology: "finite_enumerable",
                enumerandManifest: manifest,
                statisticalPolicy: enumerandPolicy,
            }),
        );
        const enumerandSchedule = scheduleFor(enumerandContract);
        const enumerandArtifact = enumerandArtifactMeasurementHash(
            manifest.entries[0].artifactSnapshotHash,
        );
        expect(deriveReplicationControlBinding({
            contractHash: enumerandSchedule.contractHash,
            statisticalPolicy: enumerandContract.statisticalPolicy,
            schedule: enumerandSchedule,
            enumerandManifest: enumerandContract.enumerandManifest,
            manifestOptions: {
                topology: enumerandContract.hypothesisTopology,
                observableRegistry: enumerandContract.observableRegistry,
                hypothesisPolicy: enumerandContract.hypothesisPolicy,
            },
            controlSnapshotHashes: [enumerandArtifact],
            requireObservedControl: true,
        })).toMatchObject({
            kind: "enumerand",
            identity: enumerandContract.statisticalPolicy.control.identity,
            artifactHash: enumerandArtifact,
        });

        const attackerPolicy = structuredClone(
            snapshotContract.statisticalPolicy,
        );
        attackerPolicy.control.identity = `sha256:${"8".repeat(64)}`;
        const calibrationSchedule = deriveReplicationSchedule({
            contractHash: snapshotSchedule.contractHash,
            statisticalPolicy: attackerPolicy,
            subject: {
                kind: "calibration",
                index: 0,
                id: "calibration-case",
                identity: hashCanonical({ calibration: true }),
            },
            arms: [{
                armId: "candidate",
                armIndex: 0,
                logicalSubjectId: "calibration-case",
                subjectKind: "calibration",
                subjectIdentity: hashCanonical({ calibration: true }),
            }],
        });
        expect(() => deriveReplicationControlBinding({
            contractHash: snapshotSchedule.contractHash,
            statisticalPolicy: snapshotContract.statisticalPolicy,
            schedule: calibrationSchedule,
        })).toThrow(/frozen statistical policy/u);
    });
});
