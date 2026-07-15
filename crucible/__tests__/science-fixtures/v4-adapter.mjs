import {
    assessAcceptancePredicate,
    buildCandidateArchive,
    canonicalJson,
    contractHash,
    createCandidateStatisticalClaimPlan,
    createInvestigationContract,
    deriveBehavioralNovelty,
    deriveCandidateCohortComparison,
    deriveCandidateNovelty,
    deriveImpossibilityVerdict,
    deriveReplicationSchedule,
    deriveReplicationSubjectIdentity,
    deriveScientificConclusion,
    detectPlateau,
    deterministicHashInteger,
    evaluateReplicatedStatisticalClaims,
    evaluateSealedPredictions,
    evaluateStatisticalClaims,
    evaluateThresholdClaim,
    hashCanonical,
    hoeffdingMeanConfidenceSequence,
    isEnumerandSpaceExhaustible,
    normalizeHypotheses,
    replicationBlockPlan,
    SEARCH_STRATEGY_POLICY_VERSION,
    SEARCH_STRATEGY_V2_ADAPTATION,
    selectAdaptiveOperator,
    statisticalMetricClaims,
    statisticalSubjectIndex,
    supportedBehavioralDifference,
} from "../../domain/index.mjs";
import {
    adaptNoveltyRoleAttempt,
    createNoveltyMeasurementBinding,
    parseHarnessResult,
    parseImpossibilityVerifierResult,
} from "../../measurement/index.mjs";
import {
    fakeStatisticalPolicy,
    makeV4ContractInput,
} from "../v4-contract-fixture.mjs";
import { createV4VerifierFixture } from "./v4-verifier-fixture.mjs";

const NULL_ALPHA = 0.05;
const NULL_TOLERANCE = 0.01;
const POWER_TARGET = 0.9;
const V3_OPTIMIZATION_BASELINE_PERCENT = 86.7;
const V4_OPTIMIZATION_MEDIAN_TARGET_PERCENT = 95;
const V4_OPTIMIZATION_CONTROL_ADVANTAGE_MARGIN_PERCENT = 0.1;
const OPTIMIZATION_BOOTSTRAP_REPLICATES = 4_096;
const OPTIMIZATION_BOOTSTRAP_SEED = 0x0b0057a9;
const OPTIMIZATION_ADVANTAGE_BOOTSTRAP_SEED = 0x51a7c0de;
const OPTIMIZATION_FIXED_CONTROLS = Object.freeze([
    "diversification",
    "restart",
]);
const ONE_SIDED_NINETY_FIVE_PERCENT_Z = 1.6448536269514722;

function round(value, digits = 6) {
    const scale = 10 ** digits;
    return Math.round((value + Number.EPSILON) * scale) / scale;
}

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

function median(values) {
    const ordered = [...values].sort((left, right) => left - right);
    const middle = Math.floor(ordered.length / 2);
    return ordered.length % 2 === 0
        ? (ordered[middle - 1] + ordered[middle]) / 2
        : ordered[middle];
}

function quantile(values, probability) {
    const ordered = [...values].sort((left, right) => left - right);
    const index = Math.max(
        0,
        Math.min(
            ordered.length - 1,
            Math.floor(probability * ordered.length),
        ),
    );
    return ordered[index];
}

function bootstrapMedianLower95(values, seed) {
    const random = mulberry32(seed);
    const bootstrapMedians = [];
    for (
        let replicate = 0;
        replicate < OPTIMIZATION_BOOTSTRAP_REPLICATES;
        replicate += 1
    ) {
        const sample = Array.from(
            { length: values.length },
            () => values[Math.floor(random() * values.length)],
        );
        bootstrapMedians.push(median(sample));
    }
    return quantile(bootstrapMedians, 0.05);
}

function wilsonBound(successes, trials, side) {
    const z = ONE_SIDED_NINETY_FIVE_PERCENT_Z;
    const proportion = successes / trials;
    const denominator = 1 + (z ** 2) / trials;
    const center = (
        proportion + (z ** 2) / (2 * trials)
    ) / denominator;
    const radius = z * Math.sqrt(
        (proportion * (1 - proportion) / trials)
        + (z ** 2) / (4 * trials ** 2),
    ) / denominator;
    return side === "lower"
        ? Math.max(0, center - radius)
        : Math.min(1, center + radius);
}

function parsedResult({
    pass,
    metrics = null,
    observables = null,
    binding = null,
}) {
    const raw = {
        pass,
        ...(metrics === null ? {} : { metrics }),
        ...(observables === null ? {} : { observables }),
        ...(binding === null ? {} : binding),
    };
    return parseHarnessResult(
        JSON.stringify(raw),
        binding === null ? {} : { expectedBinding: binding },
    );
}

function metricDefinition({
    key = "score",
    minimum = 0,
    maximum = 1,
    threshold = 0.5,
    delta = 0.05,
    direction = "max",
    priority = undefined,
}) {
    return {
        key,
        ...(priority === undefined ? {} : { priority }),
        minimum,
        maximum,
        estimand: `mean ${key}`,
        unit: key,
        direction,
        acceptanceThreshold: threshold,
        practicalEquivalenceDelta: delta,
        family: "primary",
    };
}

function makeScienceContract({
    metrics = [metricDefinition({})],
    minBlocks = 1,
    maxBlocks = 512,
    alpha = NULL_ALPHA,
    candidatesPerRound = 1,
    maxRounds = 1,
    controlTolerance = null,
    hypothesisTopology = "open_generative",
} = {}) {
    const searchSlots = candidatesPerRound * maxRounds;
    const statisticalPolicy = fakeStatisticalPolicy({
        topology: hypothesisTopology,
        searchSlots,
        minBlocks,
        maxBlocks,
        metrics,
    });
    statisticalPolicy.investigationAlpha = alpha;
    statisticalPolicy.familyAllocations = [{
        family: "primary",
        alpha,
    }];
    statisticalPolicy.control.tolerances = metrics.map((metric) => ({
        metric: metric.key,
        absolute: controlTolerance?.absolute ?? 0,
        relative: controlTolerance?.relative ?? 0,
    }));
    const observableRegistry = metrics.map((metric) => ({
        key: metric.key,
        kind: "numeric",
        minimum: metric.minimum,
        maximum: metric.maximum,
    }));
    const primaryMetric = [...metrics]
        .sort((left, right) => (left.priority ?? 0) - (right.priority ?? 0))[0];
    return createInvestigationContract(makeV4ContractInput({
        candidatesPerRound,
        maxRounds,
        hypothesisTopology,
        observableRegistry,
        statisticalPolicy,
        acceptancePredicate: {
            kind: "metric_compare",
            metric: primaryMetric.key,
            operator: primaryMetric.direction === "min" ? "<=" : ">=",
            value: primaryMetric.acceptanceThreshold,
        },
    }));
}

function constantMetricEvaluation(
    contract,
    values,
    {
        claims = undefined,
        subjectIndex = 0,
        metricRecords = null,
    } = {},
) {
    const blocks = values.map((value, blockIndex) => ({
        blockIndex,
        candidate: parsedResult({
            pass: true,
            metrics: metricRecords === null
                ? { score: value }
                : metricRecords(value, blockIndex),
        }),
    }));
    return evaluateStatisticalClaims({
        statisticalPolicy: contract.statisticalPolicy,
        observableRegistry: contract.observableRegistry,
        subject: { kind: "candidate", index: subjectIndex },
        blocks,
        ...(claims === undefined ? {} : { claims }),
    });
}

function replicateBinding(contract, role, phase, arm) {
    return {
        role,
        phase,
        replicateIndex: arm.replicateIndex,
        blockIndex: arm.blockIndex,
        armIndex: arm.armIndex,
        armId: arm.armId,
        deterministicSeed: arm.deterministicSeed,
        subjectId: arm.subjectId,
        environmentIdentity: contract.harnessSuite.environmentIdentity,
        suiteIdentity: contract.harnessSuiteIdentity,
    };
}

function buildReplicatedFixture({
    contract,
    candidateId,
    subjectIndex,
    role = "search",
    phase = "search",
    valueForArm,
}) {
    const frozenContractHash = contractHash(contract);
    const schedule = deriveReplicationSchedule({
        contractHash: frozenContractHash,
        statisticalPolicy: contract.statisticalPolicy,
        subject: {
            kind: "candidate",
            index: statisticalSubjectIndex("candidate", subjectIndex),
            id: candidateId,
            identity: deriveReplicationSubjectIdentity({
                contractHash: frozenContractHash,
                candidateId,
                candidateSeed: subjectIndex + 1001,
                enumerandHash: null,
            }),
        },
    });
    const attempts = [];
    const measurements = [];
    for (
        let blockIndex = 0;
        blockIndex < schedule.maxBlocks;
        blockIndex += 1
    ) {
        for (const arm of replicationBlockPlan(schedule, blockIndex).arms) {
            const value = valueForArm(arm);
            const binding = replicateBinding(contract, role, phase, arm);
            const parsed = parsedResult({
                pass: typeof value === "number" && value >= 0.5,
                metrics: { score: value },
                binding,
            });
            const receiptHash = hashCanonical(
                { candidateId, subjectId: arm.subjectId, receipt: true },
                "sha256:crucible-measurement-receipt-v1",
            );
            const measurementRoot = hashCanonical(
                { candidateId, subjectId: arm.subjectId, measurement: true },
                "sha256:crucible-evidence-measurement-provenance-v1",
            );
            attempts.push({
                ...arm,
                attemptId: `${candidateId}-${arm.subjectId}`,
                parsed,
                invalid: null,
                receiptHash,
                measurementRoot,
            });
            measurements.push({
                role,
                phase,
                subjectId: arm.subjectId,
                receiptHash,
                measurementRoot,
                rawStdoutHash: hashCanonical(
                    { candidateId, subjectId: arm.subjectId, value },
                    "sha256:crucible-measurement-stream-v1",
                ),
            });
        }
    }
    return {
        schedule,
        attempts,
        measurements,
    };
}

export function characterizeNullAndPower() {
    const nullTrials = 1_000;
    const powerTrials = 512;
    const maximumLooks = 256;
    let falseVerified = 0;
    let detections = 0;

    for (let trial = 0; trial < nullTrials; trial += 1) {
        const random = mulberry32((0x51a7e000 + trial) >>> 0);
        const observations = [];
        let verified = false;
        for (let look = 1; look <= maximumLooks; look += 1) {
            const parsed = parsedResult({
                pass: true,
                metrics: { score: random() < 0.5 ? 1 : 0 },
            });
            observations.push(parsed.metrics.score);
            const confidence = hoeffdingMeanConfidenceSequence({
                observations,
                alphaClaim: NULL_ALPHA,
            });
            if (evaluateThresholdClaim(
                confidence.confidenceSequence,
                ">",
                0.5,
            ) === "SUPPORTED") {
                verified = true;
                break;
            }
        }
        if (verified) falseVerified += 1;
    }

    for (let trial = 0; trial < powerTrials; trial += 1) {
        const random = mulberry32((0xc0ffee00 + trial) >>> 0);
        const observations = [];
        let detected = false;
        for (let look = 1; look <= maximumLooks; look += 1) {
            const parsed = parsedResult({
                pass: true,
                metrics: { score: random() < 0.9 ? 1 : 0 },
            });
            observations.push(parsed.metrics.score);
            const confidence = hoeffdingMeanConfidenceSequence({
                observations,
                alphaClaim: NULL_ALPHA,
            });
            if (evaluateThresholdClaim(
                confidence.confidenceSequence,
                ">",
                0.6,
            ) === "SUPPORTED") {
                detected = true;
                break;
            }
        }
        if (detected) detections += 1;
    }

    const falseVerifiedRate = falseVerified / nullTrials;
    const falseVerifiedUpper95 =
        wilsonBound(falseVerified, nullTrials, "upper");
    const power = detections / powerTrials;
    const powerLower95 = wilsonBound(detections, powerTrials, "lower");
    return {
        null: {
            trials: nullTrials,
            continuousLooks: maximumLooks,
            familywiseAlpha: NULL_ALPHA,
            tolerance: NULL_TOLERANCE,
            falseVerified,
            falseVerifiedRate: round(falseVerifiedRate),
            upperConfidenceBound95: round(falseVerifiedUpper95),
            acceptedUpperBound: round(NULL_ALPHA + NULL_TOLERANCE),
            passed:
                falseVerifiedUpper95 <= NULL_ALPHA + NULL_TOLERANCE,
        },
        power: {
            trials: powerTrials,
            continuousLooks: maximumLooks,
            nullMean: 0.5,
            practicalMargin: 0.1,
            trueMean: 0.9,
            detections,
            empiricalPower: round(power),
            lowerConfidenceBound95: round(powerLower95),
            preregisteredPower: POWER_TARGET,
            passed: powerLower95 >= POWER_TARGET,
        },
    };
}

export function characterizeEnvironmentFailures() {
    const metrics = [metricDefinition({
        threshold: 0.5,
        delta: 0.05,
    })];
    const strict = makeScienceContract({
        metrics,
        minBlocks: 1,
        maxBlocks: 32,
        alpha: 0.1,
    });
    const driftFixture = buildReplicatedFixture({
        contract: strict,
        candidateId: "drift-candidate",
        subjectIndex: 0,
        valueForArm: (arm) => {
            if (arm.armId === "candidate") return 1;
            return arm.blockIndex < 16 ? 0 : 0.25;
        },
    });
    const drift = evaluateReplicatedStatisticalClaims({
        contract: strict,
        ...driftFixture,
    });

    const invalidFixture = buildReplicatedFixture({
        contract: strict,
        candidateId: "invalid-control-candidate",
        subjectIndex: 1,
        valueForArm: (arm) => arm.armId === "candidate" ? 1 : 1.25,
    });
    const invalidControl = evaluateReplicatedStatisticalClaims({
        contract: strict,
        ...invalidFixture,
    });

    const correlated = makeScienceContract({
        metrics,
        minBlocks: 1,
        maxBlocks: 128,
        alpha: 0.1,
        controlTolerance: { absolute: 1, relative: 0 },
    });
    const correlatedFixture = buildReplicatedFixture({
        contract: correlated,
        candidateId: "correlated-candidate",
        subjectIndex: 2,
        valueForArm: (arm) => arm.blockIndex % 2,
    });
    const correlatedEvaluation = evaluateReplicatedStatisticalClaims({
        contract: correlated,
        ...correlatedFixture,
        claims: [{
            id: "increase-vs-control",
            kind: "direction_vs_control",
            observable: "score",
            direction: "increase",
        }],
        requiredClaimIds: ["increase-vs-control"],
    });

    return {
        drift: {
            controlStatus: drift.controlTolerance.status,
            requiredState: drift.requiredState,
            exclusionCodes: [...new Set(
                drift.exclusions.map((item) => item.code),
            )].sort(),
            passed:
                drift.requiredState !== "SUPPORTED"
                && drift.controlTolerance.status === "drift_detected",
        },
        invalidControl: {
            controlStatus: invalidControl.controlTolerance.status,
            requiredState: invalidControl.requiredState,
            exclusionCodes: [...new Set(
                invalidControl.exclusions.map((item) => item.code),
            )].sort(),
            passed: invalidControl.requiredState !== "SUPPORTED",
        },
        correlation: {
            correlation: "perfect shared block signal",
            requiredState: correlatedEvaluation.requiredState,
            claimState:
                correlatedEvaluation.statistics.claims[0]?.state ?? null,
            passed: correlatedEvaluation.requiredState !== "SUPPORTED",
        },
    };
}

export function characterizePredicateDisagreement() {
    const predicate = {
        kind: "metric_compare",
        metric: "score",
        operator: ">=",
        value: 0.8,
    };
    const harnessPassPredicateFail = parsedResult({
        pass: true,
        metrics: { score: 0.2 },
    });
    const harnessFailPredicatePass = parsedResult({
        pass: false,
        metrics: { score: 0.9 },
    });
    const first = assessAcceptancePredicate(
        predicate,
        harnessPassPredicateFail,
    );
    const second = assessAcceptancePredicate(
        predicate,
        harnessFailPredicatePass,
    );
    return {
        cases: [{
            id: "harness-pass-predicate-fail",
            harnessPass: harnessPassPredicateFail.pass,
            predicateSatisfied: first.satisfied,
        }, {
            id: "harness-fail-predicate-pass",
            harnessPass: harnessFailPredicatePass.pass,
            predicateSatisfied: second.satisfied,
        }],
        predicateIsAuthoritative:
            first.satisfied === false && second.satisfied === true,
        passed: first.satisfied === false && second.satisfied === true,
    };
}

export function characterizePredictionsAndConclusion() {
    const contract = makeScienceContract({
        metrics: [metricDefinition({
            threshold: 0.5,
            delta: 0.05,
        })],
        minBlocks: 1,
        maxBlocks: 1_024,
        alpha: 0.05,
    });
    const hypotheses = normalizeHypotheses({
        predictions: [{
            id: "true-prediction",
            kind: "threshold",
            observable: "score",
            operator: ">=",
            value: 0.8,
            refutation: {
                kind: "threshold",
                operator: "<",
                value: 0.8,
            },
            requiredForResult: true,
        }, {
            id: "false-prediction",
            kind: "threshold",
            observable: "score",
            operator: "<=",
            value: 0.2,
            refutation: {
                kind: "threshold",
                operator: ">",
                value: 0.2,
            },
            requiredForResult: false,
        }],
    }, {
        observableRegistry: contract.observableRegistry,
        hypothesisPolicy: contract.hypothesisPolicy,
    });
    const claimPlan = createCandidateStatisticalClaimPlan({
        contract,
        hypotheses,
    });
    const replicated = buildReplicatedFixture({
        contract,
        candidateId: "prediction-candidate",
        subjectIndex: 0,
        valueForArm: (arm) => arm.armId === "candidate" ? 1 : 0,
    });
    const performance = evaluateReplicatedStatisticalClaims({
        contract,
        ...replicated,
        claims: claimPlan.acceptanceClaims,
        requiredClaimIds: claimPlan.acceptanceClaimIds,
        allocationClaims: claimPlan.allocationClaims,
    });
    const evidenceId = "prediction-evidence";
    const evidenceHash = hashCanonical(
        { evidenceId },
        "sha256:crucible-event-v4",
    );
    const rawAuthorityDigest = hashCanonical(
        { candidateId: "prediction-candidate", kind: "raw" },
        "sha256:crucible-raw-observation-authority-v1",
    );
    const predictionEvaluation = evaluateSealedPredictions({
        contract,
        ...replicated,
        claimPlan,
        evidenceId,
        rawAuthorityDigest,
    });
    const evidence = {
        evidenceId,
        candidateId: "prediction-candidate",
        commitEventHash: evidenceHash,
        sourceKind: "harness",
        purpose: "candidate",
        annotations: {
            hypothesis: "MODEL PROSE IS NOT THE FINAL CONCLUSION",
            hypotheses,
        },
        statisticalEvaluation: performance,
    };
    const support = {
        evidenceId,
        evidenceHash,
        candidateId: evidence.candidateId,
        active: true,
        requiredState: performance.requiredState,
        acceptanceSatisfied: performance.requiredState === "SUPPORTED",
        outcomeClass: "accepted",
        metrics: performance.metrics,
        novelty: null,
        hypothesesIdentity: hypotheses.identity,
        predictionEvaluation,
    };
    const aggregate = {
        contract,
        contractHash: contractHash(contract),
        evidence: { [evidenceId]: evidence },
        scientificReplay: {
            closureRoot: hashCanonical(
                { candidateId: evidence.candidateId, kind: "science-closure" },
                "sha256:crucible-scientific-replay-closure-v1",
            ),
            candidateSupport: [support],
            confirmationState: {
                members: [{
                    evidenceId,
                    status: "READY",
                    roles: [{
                        role: "confirmation",
                        status: "SUPPORTED",
                    }, {
                        role: "challenge",
                        status: "SUPPORTED",
                    }],
                }],
            },
        },
    };
    const conclusion = deriveScientificConclusion(aggregate, evidenceId);
    const statuses = Object.fromEntries(
        predictionEvaluation.predictions.map((prediction) => [
            prediction.predictionId,
            prediction.status,
        ]),
    );
    return {
        statuses,
        overallState: predictionEvaluation.overallState,
        requiredState: predictionEvaluation.requiredState,
        performanceState: performance.requiredState,
        conclusion,
        conclusionHash: conclusion.conclusionHash,
        excludesModelProse:
            !canonicalJson(conclusion).includes("MODEL PROSE"),
        passed:
            statuses["true-prediction"] === "SUPPORTED"
            && statuses["false-prediction"] === "REFUTED"
            && predictionEvaluation.requiredState === "SUPPORTED"
            && conclusion.authority === "replay_derived_statistical_kernel"
            && !canonicalJson(conclusion).includes("MODEL PROSE"),
    };
}

function noveltyStructuralAttempt(contract, snapshotHash, features, label) {
    const binding = createNoveltyMeasurementBinding({
        contract,
        candidateArtifactHash: snapshotHash,
    });
    const parsed = parsedResult({
        pass: true,
        metrics: features,
        binding,
    });
    const receiptHash = hashCanonical(
        { label, kind: "novelty-receipt" },
        "sha256:crucible-measurement-receipt-v1",
    );
    const measurementRoot = hashCanonical(
        { label, kind: "novelty-measurement" },
        "sha256:crucible-evidence-measurement-provenance-v1",
    );
    const role = contract.harnessSuite.roles.novelty;
    const attempt = {
        version: 1,
        attemptId: `novelty-${label}`,
        role: binding.role,
        phase: binding.phase,
        replicateIndex: binding.replicateIndex,
        blockIndex: binding.blockIndex,
        armIndex: binding.armIndex,
        armId: binding.armId,
        deterministicSeed: binding.deterministicSeed,
        subjectId: binding.subjectId,
        parsed,
        invalid: null,
        receiptHash,
        measurementRoot,
    };
    const measurement = {
        subjectId: binding.subjectId,
        role: "novelty",
        phase: "novelty",
        receiptHash,
        measurementRoot,
        parserVersion: role.parser.version,
        harnessEntryHash: role.harnessEntryHash,
        executableHash: role.executableHash,
        snapshot: { snapshotHash },
        rawStdoutHash: hashCanonical(
            { label, formatting: "first" },
            "sha256:crucible-measurement-stream-v1",
        ),
    };
    return {
        binding,
        attempt,
        measurement,
        structural: adaptNoveltyRoleAttempt({
            attempt,
            measurement,
            contract,
            candidateArtifactHash: snapshotHash,
        }),
    };
}

function behavioralNoveltyFixture({
    contract,
    candidateId,
    subjectIndex,
    candidateValue,
    structural,
    relabel = false,
}) {
    const replicated = buildReplicatedFixture({
        contract,
        candidateId,
        subjectIndex,
        valueForArm: (arm) =>
            arm.armId === "candidate" ? candidateValue : 0.5,
    });
    const evaluation = evaluateReplicatedStatisticalClaims({
        contract,
        ...replicated,
    });
    const snapshotHash = hashCanonical(
        { artifact: "stable-artifact" },
        "sha256:crucible-measurement-snapshot-v1",
    );
    const observationId = `observation-${candidateId}`;
    const commandId = `command-${candidateId}`;
    const evidence = {
        evidenceId: relabel ? "renamed-evidence" : `evidence-${candidateId}`,
        candidateId: relabel ? "renamed-candidate" : candidateId,
        model: relabel ? "renamed-model" : "model-a",
        observationId,
        sourceKind: "harness",
        purpose: "candidate",
        receipt: { candidateArtifactHash: snapshotHash },
        annotations: {
            mechanism: relabel ? "paraphrased mechanism" : "first mechanism",
            finding: relabel ? "paraphrased finding" : "first finding",
        },
    };
    const observation = {
        observationId,
        commandId,
        sourceKind: "harness",
        purpose: "candidate",
        receipt: {
            candidateArtifactHash: snapshotHash,
            provenance: {
                measurements: [
                    ...replicated.measurements.map((measurement) => ({
                        ...measurement,
                        rawStdoutHash: relabel
                            ? hashCanonical(
                                {
                                    subjectId: measurement.subjectId,
                                    formatting: "changed",
                                },
                                "sha256:crucible-measurement-stream-v1",
                            )
                            : measurement.rawStdoutHash,
                    })),
                    structural.measurement,
                ],
            },
        },
        data: {
            novelty: structural.attempt,
        },
        annotations: evidence.annotations,
    };
    const aggregate = {
        contract,
        contractHash: contractHash(contract),
        evidenceOrder: [evidence.evidenceId],
        evidence: { [evidence.evidenceId]: evidence },
        observations: { [observationId]: observation },
        commands: {
            [commandId]: {
                command: {
                    kind: "search_candidate",
                    candidateId,
                    seed: subjectIndex + 1001,
                    replicationSchedule: replicated.schedule,
                },
            },
        },
    };
    return {
        evaluation,
        novelty: deriveCandidateNovelty({
            aggregate,
            evidence,
            observation,
            command: aggregate.commands[commandId].command,
            candidateEvaluation: evaluation,
        }),
        behavioral: deriveBehavioralNovelty({
            aggregate,
            evidence,
            observation,
            command: aggregate.commands[commandId].command,
            evaluation,
        }),
    };
}

export function characterizeNovelty() {
    const contract = makeScienceContract({
        metrics: [metricDefinition({
            threshold: 0.5,
            delta: 0.05,
        })],
        minBlocks: 2_048,
        maxBlocks: 2_048,
        alpha: 0.05,
        candidatesPerRound: 4,
    });
    const snapshotHash = hashCanonical(
        { artifact: "stable-artifact" },
        "sha256:crucible-measurement-snapshot-v1",
    );
    const structuralA = noveltyStructuralAttempt(
        contract,
        snapshotHash,
        { branchCount: 1, nodeCount: 2 },
        "structure-a",
    );
    const structuralB = noveltyStructuralAttempt(
        contract,
        snapshotHash,
        { branchCount: 2, nodeCount: 2 },
        "structure-b",
    );
    const original = behavioralNoveltyFixture({
        contract,
        candidateId: "candidate-high",
        subjectIndex: 0,
        candidateValue: 1,
        structural: structuralA,
    });
    const relabeled = behavioralNoveltyFixture({
        contract,
        candidateId: "candidate-high",
        subjectIndex: 0,
        candidateValue: 1,
        structural: structuralA,
        relabel: true,
    });
    const low = behavioralNoveltyFixture({
        contract,
        candidateId: "candidate-low",
        subjectIndex: 1,
        candidateValue: 0,
        structural: structuralA,
    });
    return {
        relabeling: {
            contentUnchanged:
                relabeled.novelty.content.signature
                === original.novelty.content.signature,
            structuralUnchanged:
                relabeled.novelty.structural.structuralFingerprint
                === original.novelty.structural.structuralFingerprint,
            behavioralUnchanged:
                relabeled.novelty.behavioral.signature
                === original.novelty.behavioral.signature,
        },
        structuralDifference:
            structuralA.structural.structuralFingerprint
            !== structuralB.structural.structuralFingerprint,
        behavioralDifference:
            supportedBehavioralDifference(
                original.behavioral,
                low.behavioral,
            ),
        passed:
            relabeled.novelty.content.signature
                === original.novelty.content.signature
            && relabeled.novelty.structural.structuralFingerprint
                === original.novelty.structural.structuralFingerprint
            && relabeled.novelty.behavioral.signature
                === original.novelty.behavioral.signature
            && structuralA.structural.structuralFingerprint
                !== structuralB.structural.structuralFingerprint
            && supportedBehavioralDifference(
                original.behavioral,
                low.behavioral,
            ),
    };
}

function cohortCandidate(id, evaluation, blockCount) {
    return {
        candidateId: id,
        evidenceId: `evidence-${id}`,
        evidenceHash: hashCanonical(
            { id, kind: "cohort-evidence" },
            "sha256:crucible-event-v4",
        ),
        active: true,
        invalidated: false,
        requiredState: "SUPPORTED",
        completeValidBlocks: true,
        acceptanceSatisfied: true,
        rankable: true,
        replication: {
            blockCount,
            scheduleHash: hashCanonical(
                { id, kind: "cohort-schedule" },
                "sha256:crucible-replication-schedule-v1",
            ),
        },
        statisticalEvaluation: {
            blockCount,
            statistics: evaluation,
        },
        hypothesesIdentity: hashCanonical(
            { id, kind: "cohort-hypotheses" },
            "sha256:crucible-preregistered-hypotheses-v4",
        ),
        predictionEvaluation: {
            requiredState: "SUPPORTED",
            predictions: [],
        },
        novelty: null,
    };
}

export function characterizeCohorts() {
    const oneMetric = [metricDefinition({
        threshold: 0.5,
        delta: 0.15,
        priority: 0,
    })];
    const precise = makeScienceContract({
        metrics: oneMetric,
        minBlocks: 1,
        maxBlocks: 4_096,
        candidatesPerRound: 4,
    });
    const preciseCount = 4_096;
    const high = constantMetricEvaluation(
        precise,
        Array.from({ length: preciseCount }, () => 0.95),
        { subjectIndex: 0 },
    );
    const lower = constantMetricEvaluation(
        precise,
        Array.from({ length: preciseCount }, () => 0.65),
        { subjectIndex: 1 },
    );
    const tied = constantMetricEvaluation(
        precise,
        Array.from({ length: preciseCount }, () => 0.8),
        { subjectIndex: 2 },
    );
    const unique = deriveCandidateCohortComparison({
        contract: precise,
        candidates: [
            cohortCandidate("high", high, preciseCount),
            cohortCandidate("lower", lower, preciseCount),
        ],
    });
    const practicalTie = deriveCandidateCohortComparison({
        contract: precise,
        candidates: [
            cohortCandidate("tie-a", tied, preciseCount),
            cohortCandidate("tie-b", tied, preciseCount),
        ],
    });

    const coarseCount = 64;
    const coarse = makeScienceContract({
        metrics: oneMetric,
        minBlocks: 1,
        maxBlocks: coarseCount,
        candidatesPerRound: 2,
    });
    const unresolvedLeft = constantMetricEvaluation(
        coarse,
        Array.from({ length: coarseCount }, () => 0.8),
        { subjectIndex: 0 },
    );
    const unresolvedRight = constantMetricEvaluation(
        coarse,
        Array.from({ length: coarseCount }, () => 0.81),
        { subjectIndex: 1 },
    );
    const unresolved = deriveCandidateCohortComparison({
        contract: coarse,
        candidates: [
            cohortCandidate("unresolved-a", unresolvedLeft, coarseCount),
            cohortCandidate("unresolved-b", unresolvedRight, coarseCount),
        ],
    });

    const multiMetrics = [
        metricDefinition({
            key: "score",
            threshold: 0.5,
            delta: 0.15,
            priority: 0,
        }),
        metricDefinition({
            key: "latency",
            minimum: 0,
            maximum: 1,
            threshold: 0.8,
            delta: 0.15,
            direction: "min",
            priority: 1,
        }),
    ];
    const multi = makeScienceContract({
        metrics: multiMetrics,
        minBlocks: 1,
        maxBlocks: preciseCount,
        candidatesPerRound: 2,
    });
    const claims = statisticalMetricClaims(multi.statisticalPolicy);
    const scoreClaim = claims.filter((claim) => claim.observable === "score");
    const left = constantMetricEvaluation(
        multi,
        Array.from({ length: preciseCount }, () => 0.8),
        {
            claims: scoreClaim,
            subjectIndex: 0,
            metricRecords: () => ({ score: 0.8 }),
        },
    );
    const right = constantMetricEvaluation(
        multi,
        Array.from({ length: preciseCount }, () => 0.8),
        {
            claims,
            subjectIndex: 1,
            metricRecords: () => ({ latency: 0.2, score: 0.8 }),
        },
    );
    const incomparable = deriveCandidateCohortComparison({
        contract: multi,
        candidates: [
            cohortCandidate("incomparable-a", left, preciseCount),
            cohortCandidate("incomparable-b", right, preciseCount),
        ],
    });
    return {
        uniqueBest: unique.status,
        uniqueCandidateId: unique.provisionalWinner?.candidateId ?? null,
        practicalTie: practicalTie.status,
        tieCandidateIds:
            practicalTie.cohort.map((candidate) => candidate.candidateId),
        unresolved: unresolved.status,
        incomparable: incomparable.status,
        passed:
            unique.status === "UNIQUE_BEST"
            && unique.provisionalWinner?.candidateId === "high"
            && practicalTie.status === "TIE_COHORT"
            && unresolved.status === "UNRESOLVED"
            && incomparable.status === "INCOMPARABLE",
    };
}

export function characterizeOverfit() {
    const contract = makeScienceContract({
        metrics: [metricDefinition({
            threshold: 0.5,
            delta: 0.05,
        })],
        minBlocks: 1,
        maxBlocks: 512,
        candidatesPerRound: 2,
    });
    const count = 512;
    const evaluate = (value, subjectIndex) => constantMetricEvaluation(
        contract,
        Array.from({ length: count }, () => value),
        { subjectIndex },
    ).overallState;
    const candidates = {
        overfit: {
            discovery: evaluate(1, 0),
            heldOut: evaluate(0, 0),
            challenge: evaluate(0, 0),
        },
        generalizer: {
            discovery: evaluate(0.9, 1),
            heldOut: evaluate(0.9, 1),
            challenge: evaluate(0.9, 1),
        },
    };
    return {
        candidates,
        discoveryWinner: "overfit",
        confirmationWinner: "generalizer",
        passed:
            candidates.overfit.discovery === "SUPPORTED"
            && candidates.overfit.heldOut === "REFUTED"
            && candidates.overfit.challenge === "REFUTED"
            && Object.values(candidates.generalizer)
                .every((state) => state === "SUPPORTED"),
    };
}

export function characterizeImpossibility() {
    const verifiedFixture = createV4VerifierFixture();
    const verified = parseImpossibilityVerifierResult(
        JSON.stringify(verifiedFixture.output),
        {
            expectedBinding: verifiedFixture.binding,
            request: verifiedFixture.request,
            requestHash: verifiedFixture.requestHash,
        },
    );
    const incompleteFixture = createV4VerifierFixture({
        status: "INCONCLUSIVE",
    });
    const incomplete = parseImpossibilityVerifierResult(
        JSON.stringify(incompleteFixture.output),
        {
            expectedBinding: incompleteFixture.binding,
            request: incompleteFixture.request,
            requestHash: incompleteFixture.requestHash,
        },
    );
    const disagreementFixture = createV4VerifierFixture();
    disagreementFixture.output.disagreementCount = 1;
    let disagreementRejected = false;
    try {
        parseImpossibilityVerifierResult(
            JSON.stringify(disagreementFixture.output),
        );
    } catch {
        disagreementRejected = true;
    }
    const open = makeScienceContract();
    const finite = makeScienceContract({
        hypothesisTopology: "certified_impossibility",
    });
    const exhaustibilityInput = (contract) => ({
        topology: contract.hypothesisTopology,
        enumerandManifest: contract.enumerandManifest,
        observableRegistry: contract.observableRegistry,
        hypothesisPolicy: contract.hypothesisPolicy,
    });
    const finiteImmutableExhaustible = isEnumerandSpaceExhaustible(
        exhaustibilityInput(finite),
    );
    const openGenerativeExhaustible = isEnumerandSpaceExhaustible(
        exhaustibilityInput(open),
    );
    return {
        verifiedStatus: verified.status,
        verifiedVerdict: deriveImpossibilityVerdict(verified),
        incompleteStatus: incomplete.status,
        incompleteVerdict: deriveImpossibilityVerdict(incomplete),
        disagreementRejected,
        finiteImmutableExhaustible,
        openGenerativeExhaustible,
        passed:
            verified.status === "VERIFIED"
            && deriveImpossibilityVerdict(verified) === "target_unreachable"
            && incomplete.status === "INCONCLUSIVE"
            && deriveImpossibilityVerdict(incomplete) === "inconclusive"
            && disagreementRejected
            && finiteImmutableExhaustible
            && !openGenerativeExhaustible,
    };
}

function deceptiveLandscapeScore(x) {
    const local = 86.7 - 220 * ((x - 0.2) ** 2);
    const global = 100 - 800 * ((x - 0.82) ** 2);
    return Math.max(0, Math.min(100, Math.max(local, global)));
}

function unitEntropy(seed, roundIndex, operator, lane) {
    return deterministicHashInteger({
        suite: "crucible-v4-deceptive-optimization",
        seed,
        roundIndex,
        operator,
        lane,
    }, 1_000_000_000) / 1_000_000_000;
}

function operatorCandidate({
    operator,
    seed,
    roundIndex,
    incumbent,
    top,
}) {
    const u = unitEntropy(seed, roundIndex, operator, "primary");
    const jitter = unitEntropy(seed, roundIndex, operator, "jitter") - 0.5;
    let x;
    switch (operator) {
        case "fresh":
            x = 0.14 + 0.12 * u;
            break;
        case "refinement":
            x = (incumbent?.x ?? 0.2) + 0.08 * jitter;
            break;
        case "crossover":
            x = top.length >= 2
                ? (top[0].x + top[1].x) / 2 + 0.06 * jitter
                : 0.14 + 0.12 * u;
            break;
        case "diversification":
            x = u;
            break;
        case "adversarial":
            x = 1 - (incumbent?.x ?? 0.2) + 0.04 * jitter;
            break;
        case "restart":
            x = u;
            break;
        default:
            throw new TypeError(`unknown search operator ${operator}`);
    }
    return Math.max(0, Math.min(1, x));
}

function optimizationEvidence({
    contract,
    seed,
    roundIndex,
    operator,
    x,
    score,
}) {
    const parsed = parsedResult({
        pass: score >= 0,
        metrics: { score },
    });
    const statistics = evaluateStatisticalClaims({
        statisticalPolicy: contract.statisticalPolicy,
        observableRegistry: contract.observableRegistry,
        subject: { kind: "candidate", index: roundIndex - 1 },
        blocks: [{
            blockIndex: 0,
            candidate: parsed,
        }],
    });
    const measuredScore =
        statistics.claims[0].estimate.pointEstimate;
    const evidenceId = `optimization-${seed}-${roundIndex}`;
    return {
        evidenceId,
        candidateId: `candidate-${seed}-${roundIndex}`,
        committedSeq: roundIndex,
        round: roundIndex,
        slotIndex: 0,
        sourceKind: "harness",
        purpose: "candidate",
        invalidated: false,
        rankable: true,
        outcomeClass: "accepted",
        acceptanceSatisfied: true,
        metrics: { score: measuredScore },
        receipt: {
            candidateArtifactHash: hashCanonical(
                { seed, roundIndex, operator, x: round(x, 12) },
                "sha256:crucible-measurement-snapshot-v1",
            ),
        },
        duplicateOf: null,
        novelty: null,
        annotations: {
            mechanism: operator,
            finding: `measured score ${round(measuredScore, 6)}`,
            hypothesis: null,
            expectedEffects: [],
            citedEvidenceIds: [],
        },
    };
}

function runDeceptiveSeed(
    contract,
    seed,
    rounds = 16,
    fixedOperator = null,
) {
    const aggregate = {
        contract,
        contractHash: hashCanonical(
            { suite: "crucible-v4-deceptive-optimization", seed },
            "sha256:crucible-contract-v4",
        ),
        evidenceOrder: [],
        evidence: {},
        observations: {},
        commands: {},
    };
    const coordinates = new Map();
    const trace = [];
    for (let roundIndex = 1; roundIndex <= rounds; roundIndex += 1) {
        const archive = buildCandidateArchive(aggregate);
        const phase = detectPlateau(aggregate).phase;
        const operator = fixedOperator ?? selectAdaptiveOperator({
            searchPolicy: contract.searchPolicy,
            archive,
            policyIdentity: aggregate.contractHash,
            round: roundIndex,
            slotIndex: 0,
            phase,
            operatorHistory: trace.map((item) => item.operator),
        });
        const ranked = aggregate.evidenceOrder
            .map((evidenceId) => aggregate.evidence[evidenceId])
            .map((evidence) => ({
                evidence,
                x: coordinates.get(evidence.evidenceId),
            }))
            .sort((left, right) =>
                right.evidence.metrics.score - left.evidence.metrics.score);
        const incumbentEvidence = archive.incumbent;
        const incumbent = incumbentEvidence === null
            ? null
            : {
                evidence: incumbentEvidence,
                x: coordinates.get(incumbentEvidence.evidenceId),
            };
        const x = operatorCandidate({
            operator,
            seed,
            roundIndex,
            incumbent,
            top: ranked.slice(0, 2).map((item) => ({
                x: item.x,
                score: item.evidence.metrics.score,
            })),
        });
        const score = deceptiveLandscapeScore(x);
        const evidence = optimizationEvidence({
            contract,
            seed,
            roundIndex,
            operator,
            x,
            score,
        });
        aggregate.evidenceOrder.push(evidence.evidenceId);
        aggregate.evidence[evidence.evidenceId] = evidence;
        coordinates.set(evidence.evidenceId, x);
        trace.push({
            round: roundIndex,
            operator,
            x: round(x, 6),
            score: round(evidence.metrics.score, 6),
        });
    }
    const best = trace.reduce(
        (current, item) => item.score > current.score ? item : current,
        trace[0],
    );
    return {
        seed,
        bestScore: best.score,
        percentOfKnownOptimum: best.score,
        bestOperator: best.operator,
        bestRound: best.round,
        trace,
    };
}

function summarizeOptimizationResults(results, bootstrapSeed) {
    const percentages = results.map((result) =>
        result.percentOfKnownOptimum);
    const globalBasinCount = percentages.filter((value) => value >= 95).length;
    const observedMedianPercent = median(percentages);
    const bootstrapMedianLower95Percent = bootstrapMedianLower95(
        percentages,
        bootstrapSeed,
    );
    return {
        raw: {
            observedMedianPercent,
            bootstrapMedianLower95Percent,
        },
        observedMedianPercent: round(observedMedianPercent),
        bootstrapMedianLower95Percent: round(
            bootstrapMedianLower95Percent,
        ),
        globalBasinCount,
        globalBasinRate: round(globalBasinCount / percentages.length),
        minimumPercent: round(Math.min(...percentages)),
        maximumPercent: round(Math.max(...percentages)),
        weakestSeeds: [...results]
            .sort((left, right) =>
                left.percentOfKnownOptimum - right.percentOfKnownOptimum
                || left.seed - right.seed)
            .slice(0, 8)
            .map((result) => ({
                seed: result.seed,
                percentOfKnownOptimum: round(
                    result.percentOfKnownOptimum,
                ),
                bestOperator: result.bestOperator,
                bestRound: result.bestRound,
            })),
        perSeed: results.map((result) => ({
            seed: result.seed,
            percentOfKnownOptimum: round(result.percentOfKnownOptimum),
            bestOperator: result.bestOperator,
            bestRound: result.bestRound,
        })),
    };
}

export function characterizeOptimization() {
    const contract = makeScienceContract({
        metrics: [metricDefinition({
            minimum: 0,
            maximum: 100,
            threshold: 0,
            delta: 0.5,
        })],
        minBlocks: 1,
        maxBlocks: 1,
        alpha: 0.05,
    });
    const seeds = Array.from({ length: 64 }, (_unused, index) => index + 1);
    const results = seeds.map((seed) => runDeceptiveSeed(contract, seed));
    const adaptive = summarizeOptimizationResults(
        results,
        OPTIMIZATION_BOOTSTRAP_SEED,
    );
    const controls = OPTIMIZATION_FIXED_CONTROLS.map(
        (operator, controlIndex) => {
            const controlResults = seeds.map((seed) =>
                runDeceptiveSeed(contract, seed, 16, operator));
            return {
                policy: `fixed_${operator}`,
                operator,
                ...summarizeOptimizationResults(
                    controlResults,
                    OPTIMIZATION_BOOTSTRAP_SEED + controlIndex + 1,
                ),
                results: controlResults,
            };
        },
    );
    const strongestControl = [...controls].sort((left, right) =>
        right.raw.observedMedianPercent - left.raw.observedMedianPercent
        || left.policy.localeCompare(right.policy))[0];
    const controlAdvantages = controls.map((control, controlIndex) => {
        const pairedAdvantages = results.map((result, index) =>
            result.percentOfKnownOptimum
            - control.results[index].percentOfKnownOptimum);
        const observedMedianAdvantagePercent = median(pairedAdvantages);
        const bootstrapMedianAdvantageLower95Percent =
            bootstrapMedianLower95(
                pairedAdvantages,
                OPTIMIZATION_ADVANTAGE_BOOTSTRAP_SEED + controlIndex,
            );
        return {
            controlPolicy: control.policy,
            raw: {
                observedMedianAdvantagePercent,
                bootstrapMedianAdvantageLower95Percent,
            },
            observedMedianAdvantagePercent: round(
                observedMedianAdvantagePercent,
            ),
            bootstrapMedianAdvantageLower95Percent: round(
                bootstrapMedianAdvantageLower95Percent,
            ),
            adaptiveSeedWins: pairedAdvantages.filter(
                (value) => value > 0,
            ).length,
            adaptiveSeedTies: pairedAdvantages.filter(
                (value) => value === 0,
            ).length,
        };
    });
    const strongestControlAdvantage = controlAdvantages.find(
        (item) => item.controlPolicy === strongestControl.policy,
    );
    const { raw: _adaptiveRaw, ...reportedAdaptive } = adaptive;
    const reportedControls = controls.map(({
        raw: _raw,
        results: _results,
        ...control
    }) => control);
    const reportedControlAdvantages = controlAdvantages.map(({
        raw: _raw,
        ...advantage
    }) => advantage);
    return {
        benchmark: "deterministic one-dimensional deceptive dual-basin landscape",
        strategyUnderTest:
            "buildCandidateArchive + detectPlateau + selectAdaptiveOperator",
        strategyPolicyVersion: contract.searchPolicy.version,
        adaptiveWeightPolicy: SEARCH_STRATEGY_V2_ADAPTATION,
        proposalEnvironment:
            "deterministic operator-conditioned simulator; excludes model-quality claims",
        bootstrapStatistic:
            "one-sided 95% lower percentile bound for the across-seed median",
        controlComparisonStatistic:
            "paired one-sided 95% lower percentile bound for the across-seed median adaptive-minus-control advantage",
        controlSelectionRule:
            "strongest preregistered fixed policy is the control with the highest across-seed observed median",
        knownOptimum: 100,
        v3BaselinePercent: V3_OPTIMIZATION_BASELINE_PERCENT,
        seedCount: seeds.length,
        roundsPerSeed: 16,
        adaptive: reportedAdaptive,
        controls: reportedControls,
        strongestControl: {
            policy: strongestControl.policy,
            observedMedianPercent: strongestControl.observedMedianPercent,
            bootstrapMedianLower95Percent:
                strongestControl.bootstrapMedianLower95Percent,
        },
        controlAdvantages: reportedControlAdvantages,
        declaredAdvantageMarginPercent:
            V4_OPTIMIZATION_CONTROL_ADVANTAGE_MARGIN_PERCENT,
        bootstrapMedianAdvantageOverStrongestControlLower95Percent:
            strongestControlAdvantage
                .bootstrapMedianAdvantageLower95Percent,
        observedMedianPercent: adaptive.observedMedianPercent,
        bootstrapMedianLower95Percent:
            adaptive.bootstrapMedianLower95Percent,
        globalBasinCount: adaptive.globalBasinCount,
        globalBasinRate: adaptive.globalBasinRate,
        minimumPercent: adaptive.minimumPercent,
        maximumPercent: adaptive.maximumPercent,
        weakestSeeds: adaptive.weakestSeeds,
        perSeed: adaptive.perSeed,
        passed:
            adaptive.raw.bootstrapMedianLower95Percent
                > V3_OPTIMIZATION_BASELINE_PERCENT
            && adaptive.raw.observedMedianPercent
                >= V4_OPTIMIZATION_MEDIAN_TARGET_PERCENT
            && controlAdvantages.every((advantage) =>
                advantage.raw.bootstrapMedianAdvantageLower95Percent
                    >= V4_OPTIMIZATION_CONTROL_ADVANTAGE_MARGIN_PERCENT),
    };
}

export function buildV4ScienceBenchmark() {
    const nullAndPower = characterizeNullAndPower();
    const environment = characterizeEnvironmentFailures();
    const predicate = characterizePredicateDisagreement();
    const predictions = characterizePredictionsAndConclusion();
    const novelty = characterizeNovelty();
    const cohorts = characterizeCohorts();
    const overfit = characterizeOverfit();
    const impossibility = characterizeImpossibility();
    const optimization = characterizeOptimization();
    const checks = {
        nullFalseVerified: nullAndPower.null.passed,
        knownEffectPower: nullAndPower.power.passed,
        environmentFailClosed: Object.values(environment)
            .every((item) => item.passed),
        predicateDisagreement: predicate.passed,
        predictionsAndConclusion: predictions.passed,
        novelty: novelty.passed,
        cohorts: cohorts.passed,
        overfit: overfit.passed,
        impossibility: impossibility.passed,
        optimization: optimization.passed,
    };
    return {
        runnerVersion: 1,
        suite: "crucible-v4-science-gate",
        parserPath: "crucible-measurement-parser-v3",
        statisticsPath: "crucible-bounded-statistics-v4",
        checks,
        passed: Object.values(checks).every(Boolean),
        metrics: {
            nullAndPower,
            environment,
            predicate,
            predictions: {
                statuses: predictions.statuses,
                overallState: predictions.overallState,
                requiredState: predictions.requiredState,
                performanceState: predictions.performanceState,
                conclusionHash: predictions.conclusionHash,
                excludesModelProse: predictions.excludesModelProse,
            },
            novelty,
            cohorts,
            overfit,
            impossibility,
            optimization,
        },
    };
}

export const V4_SCIENCE_THRESHOLDS = Object.freeze({
    nullFamilywiseAlpha: NULL_ALPHA,
    nullTolerance: NULL_TOLERANCE,
    preregisteredPower: POWER_TARGET,
    v3OptimizationBaselinePercent: V3_OPTIMIZATION_BASELINE_PERCENT,
    v4OptimizationMedianTargetPercent:
        V4_OPTIMIZATION_MEDIAN_TARGET_PERCENT,
    v4OptimizationControlAdvantageMarginPercent:
        V4_OPTIMIZATION_CONTROL_ADVANTAGE_MARGIN_PERCENT,
    strategyPolicyVersion: SEARCH_STRATEGY_POLICY_VERSION,
});
