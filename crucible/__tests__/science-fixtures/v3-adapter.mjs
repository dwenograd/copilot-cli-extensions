import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    ERROR_CODES,
    acceptanceSatisfied,
    canonicalJson,
    classifyCandidateOutcome,
    compareCandidateEvidence,
    contractHash,
    createInvestigationContract,
    decideNext,
    deriveImpossibilityVerdict,
    hashCanonical,
    metricImprovement,
    selectIncumbent,
} from "../../domain/index.mjs";
import { SCIENCE_FIXTURES, SCIENCE_FIXTURE_VERSION } from "./fixtures.mjs";
import { buildScienceOracle } from "./oracle.mjs";
import {
    commitCandidate,
    commitImpossibility,
    contractInput,
    invalidateEvidence,
    openInvestigation,
    pauseAndResume,
    reserveAndDispatch,
    searchPolicy,
    validateInvestigation,
} from "./v3-domain-harness.mjs";

const BASELINE_PATH = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "baseline.v3.json",
);

function round(value, digits = 12) {
    const scale = 10 ** digits;
    return Math.round((value + Number.EPSILON) * scale) / scale;
}

function metricContract({
    predicate,
    metric = "score",
    topology = "open_generative",
    boundedCandidateIds,
    candidatesPerRound = 1,
    maxRounds = 4,
    stopOnFirstAccept = false,
} = {}) {
    return createInvestigationContract(contractInput({
        acceptancePredicate: predicate ?? {
            kind: "metric_compare",
            metric,
            operator: ">=",
            value: 0,
        },
        metrics: [{ key: metric, direction: "max", epsilon: 0 }],
        hypothesisTopology: topology,
        ...(boundedCandidateIds === undefined ? {} : { boundedCandidateIds }),
        candidatesPerRound,
        maxRounds,
        searchPolicy: searchPolicy({ stopOnFirstAccept }),
    }));
}

function candidateEvidence(candidate, outcomeClass, metric = "score") {
    return {
        evidenceId: `${candidate.id}-evidence`,
        candidateId: candidate.id,
        committedSeq: candidate.committedSeq,
        outcomeClass,
        rankable: true,
        metrics: { [metric]: candidate.score },
        receipt: {
            candidateArtifactHash: hashCanonical({
                fixtureCandidate: candidate.id,
            }),
        },
        invalidated: false,
        duplicateOf: null,
    };
}

export function characterizeNullNoise() {
    const fixture = SCIENCE_FIXTURES.nullNoise;
    const context = validateInvestigation(openInvestigation({
        acceptancePredicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: fixture.acceptanceThreshold,
        },
        metrics: [{ key: "score", direction: "max", epsilon: 0 }],
        candidatesPerRound: 1,
        maxRounds: fixture.observations.length,
        searchPolicy: searchPolicy({ stopOnFirstAccept: true }),
    }));
    let terminal = null;
    let acceptedObservationIndex = null;
    for (const [index, score] of fixture.observations.entries()) {
        commitCandidate(context, {
            label: `null-${String(index).padStart(2, "0")}`,
            data: {
                pass: score >= fixture.acceptanceThreshold,
                metrics: { score },
            },
        });
        const recommendation = decideNext(context.aggregate);
        if (recommendation.kind === "TERMINAL") {
            terminal = recommendation;
            acceptedObservationIndex = index;
            break;
        }
    }
    if (terminal === null) {
        throw new Error("Null/noise fixture did not produce its deterministic lucky pass");
    }
    return {
        seed: fixture.seed,
        observationCountBeforeVerification: acceptedObservationIndex + 1,
        acceptedObservationIndex,
        acceptedScore: fixture.observations[acceptedObservationIndex],
        decision: terminal.decision,
        basisKind: terminal.basis.kind,
        replicationCount: 1,
    };
}

export function characterizeEffectAndTie() {
    const fixture = SCIENCE_FIXTURES.effectAndTie;
    const contract = metricContract({
        predicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: fixture.acceptanceThreshold,
        },
    });
    const effectEvidence = fixture.trueEffectCandidates.map((candidate) => {
        const result = {
            pass: candidate.score >= fixture.acceptanceThreshold,
            metrics: { score: candidate.score },
        };
        return candidateEvidence(
            candidate,
            classifyCandidateOutcome(contract, result),
        );
    });
    const effectWinner = selectIncumbent(contract, effectEvidence);
    const tieEvidence = fixture.equalCandidates.map((candidate) =>
        candidateEvidence(candidate, "accepted"));
    const tieComparison = compareCandidateEvidence(
        contract.metrics,
        tieEvidence[0],
        tieEvidence[1],
    );
    const tieWinner = selectIncumbent(contract, tieEvidence);
    return {
        trueEffectWinnerId: effectWinner?.candidateId ?? null,
        trueEffectWinnerScore: effectWinner?.metrics.score ?? null,
        tieComparisonSign: Math.sign(tieComparison),
        tieWinnerId: tieWinner?.candidateId ?? null,
        tieSurfaced: false,
        tieBreakBasis: "committed_event_order",
    };
}

export function characterizeDrift() {
    const fixture = SCIENCE_FIXTURES.drift;
    const contract = metricContract({
        predicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: fixture.acceptanceThreshold,
        },
    });
    const flattened = fixture.blocks.flatMap((block) =>
        block.observations.map((observation) => ({
            ...observation,
            blockId: block.id,
        })));
    const evidence = flattened.map((observation, index) => {
        const result = {
            pass: observation.score >= fixture.acceptanceThreshold,
            metrics: { score: observation.score },
            blockId: observation.blockId,
        };
        return candidateEvidence(
            {
                id: observation.id,
                score: observation.score,
                committedSeq: 200 + index,
            },
            classifyCandidateOutcome(contract, result),
        );
    });
    const relabeledEvidence = flattened.map((observation, index) => {
        const result = {
            pass: observation.score >= fixture.acceptanceThreshold,
            metrics: { score: observation.score },
            blockId: `relabel-${flattened.length - index}`,
        };
        return candidateEvidence(
            {
                id: observation.id,
                score: observation.score,
                committedSeq: 200 + index,
            },
            classifyCandidateOutcome(contract, result),
        );
    });
    const winner = selectIncumbent(contract, evidence);
    return {
        acceptedIds: evidence
            .filter((item) => item.outcomeClass === "accepted")
            .map((item) => item.candidateId),
        winnerId: winner?.candidateId ?? null,
        winnerScore: winner?.metrics.score ?? null,
        blockRelabelingChangesOutcome:
            canonicalJson(evidence.map((item) => item.outcomeClass))
            !== canonicalJson(relabeledEvidence.map((item) => item.outcomeClass)),
        blockAdjustmentApplied: false,
    };
}

export function characterizePredicateDisagreement() {
    return {
        cases: SCIENCE_FIXTURES.predicateDisagreement.cases.map((item) => {
            const contract = metricContract({
                predicate: item.predicate,
            });
            return {
                id: item.id,
                harnessPass: item.result.pass,
                acceptanceSatisfied: acceptanceSatisfied(
                    item.predicate,
                    item.result,
                ),
                outcomeClass: classifyCandidateOutcome(contract, item.result),
            };
        }),
        acceptanceAuthority: "acceptance_predicate",
    };
}

export function characterizeTypedPredictions() {
    const fixture = SCIENCE_FIXTURES.typedPredictions;
    const contract = metricContract({
        predicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: fixture.acceptanceThreshold,
        },
    });
    const evidence = fixture.candidates.map((candidate) => {
        const withoutPrediction = classifyCandidateOutcome(contract, candidate.result);
        const withPrediction = classifyCandidateOutcome(contract, {
            ...candidate.result,
            intendedPrediction: candidate.intendedPrediction,
        });
        return {
            evidence: candidateEvidence(candidate, withPrediction),
            withoutPrediction,
            withPrediction,
        };
    });
    const winner = selectIncumbent(
        contract,
        evidence.map((item) => item.evidence),
    );
    return {
        outcomes: Object.fromEntries(evidence.map((item) => [
            item.evidence.candidateId,
            item.withPrediction,
        ])),
        predictionChangesOutcome: evidence.some((item) =>
            item.withPrediction !== item.withoutPrediction),
        winnerId: winner?.candidateId ?? null,
        predictionsScored: false,
    };
}

export function characterizeOverfit() {
    const fixture = SCIENCE_FIXTURES.overfit;
    const context = validateInvestigation(openInvestigation({
        acceptancePredicate: {
            kind: "metric_compare",
            metric: "discovery_score",
            operator: ">=",
            value: fixture.acceptanceThreshold,
        },
        metrics: [{ key: "discovery_score", direction: "max", epsilon: 0 }],
        hypothesisTopology: "bounded_parameterized",
        boundedCandidateIds: fixture.candidates.map((candidate) => candidate.id),
        candidatesPerRound: 1,
        maxRounds: fixture.candidates.length,
        searchPolicy: searchPolicy({ stopOnFirstAccept: false }),
    }));
    for (const candidate of fixture.candidates) {
        commitCandidate(context, {
            label: `overfit-${candidate.id}`,
            data: {
                pass: candidate.discovery.pass,
                metrics: { discovery_score: candidate.discovery.score },
                heldOut: candidate.heldOut,
                challenge: candidate.challenge,
            },
        });
    }
    const terminal = decideNext(context.aggregate);
    return {
        decision: terminal.decision,
        basisKind: terminal.basis.kind,
        winnerId: terminal.candidateId,
        heldOutConsulted: false,
        challengeConsulted: false,
    };
}

export function characterizeBoundedEnumerands() {
    const fixture = SCIENCE_FIXTURES.boundedEnumerands;
    let duplicateError = null;
    try {
        createInvestigationContract(contractInput({
            hypothesisTopology: "finite_enumerable",
            boundedCandidateIds: fixture.duplicateIds,
            candidatesPerRound: 2,
            maxRounds: 1,
        }));
    } catch (error) {
        duplicateError = {
            code: error.code ?? null,
            message: error.message,
        };
    }

    const originalContract = createInvestigationContract(contractInput({
        hypothesisTopology: "finite_enumerable",
        boundedCandidateIds: fixture.boundedIds,
        candidatesPerRound: 1,
        maxRounds: 1,
        enumerandContents: fixture.originalEnumerands,
    }));
    const mutatedContract = createInvestigationContract(contractInput({
        hypothesisTopology: "finite_enumerable",
        boundedCandidateIds: fixture.boundedIds,
        candidatesPerRound: 1,
        maxRounds: 1,
        enumerandContents: fixture.mutatedEnumerands,
    }));

    const context = validateInvestigation(openInvestigation({
        hypothesisTopology: "finite_enumerable",
        boundedCandidateIds: fixture.boundedIds,
        candidatesPerRound: 1,
        maxRounds: 1,
    }));
    const original = commitCandidate(context, {
        label: "bounded-original",
        data: { pass: false },
        candidateArtifactHash: hashCanonical({ enumerand: "enum-a", revision: 1 }),
    });
    invalidateEvidence(
        context,
        original.evidence.evidenceId,
        fixture.invalidationReason,
    );
    const retryRecommendation = decideNext(context.aggregate);
    const replacement = commitCandidate(context, {
        label: "bounded-replacement",
        data: { pass: false },
        candidateArtifactHash: hashCanonical({ enumerand: "enum-a", revision: 2 }),
    });

    return {
        duplicateIdsRejected: duplicateError?.code === ERROR_CODES.INVALID_CONTRACT,
        duplicateErrorCode: duplicateError?.code ?? null,
        duplicateErrorMentionsUnique:
            duplicateError?.message.includes("unique identifiers") ?? false,
        mutatedContentsChangeContractHash:
            contractHash(originalContract) !== contractHash(mutatedContract),
        enumerandContentsFrozenInContract:
            Object.hasOwn(originalContract, "enumerandContents"),
        retryCandidateId: retryRecommendation.command?.candidateId ?? null,
        retryReplacementOrdinal:
            retryRecommendation.command?.replacementOrdinal ?? null,
        replacementCandidateId: replacement.command.candidateId,
        replacementArtifactChanged:
            original.evidence.receipt.candidateArtifactHash
            !== replacement.evidence.receipt.candidateArtifactHash,
    };
}

function impossibleContext(rawCandidateData) {
    const context = validateInvestigation(openInvestigation({
        hypothesisTopology: "certified_impossibility",
        candidatesPerRound: 1,
        maxRounds: 1,
    }));
    commitCandidate(context, {
        label: `impossible-${context.history.length}`,
        data: rawCandidateData,
    });
    return context;
}

export function characterizeImpossibility() {
    const fixture = SCIENCE_FIXTURES.impossibility;

    const selfContext = impossibleContext(fixture.rawCandidateClaim);
    const rawClaimRecommendation = decideNext(selfContext.aggregate);
    const selfVerifier = reserveAndDispatch(selfContext);
    commitImpossibility(
        selfContext,
        selfVerifier,
        "self-certified",
        fixture.selfCertifiedFacts,
    );
    const selfCertifiedTerminal = decideNext(selfContext.aggregate);

    const invalidContext = impossibleContext({ pass: false });
    const invalidVerifier = reserveAndDispatch(invalidContext);
    const invalidEvidence = commitImpossibility(
        invalidContext,
        invalidVerifier,
        "invalid",
        fixture.invalidFacts,
    );
    const invalidRecommendation = decideNext(invalidContext.aggregate);

    const disagreeingContext = impossibleContext({ pass: false });
    const firstVerifier = reserveAndDispatch(disagreeingContext);
    const firstEvidence = commitImpossibility(
        disagreeingContext,
        firstVerifier,
        "disagree-first",
        fixture.disagreeingAttempts[0],
    );
    invalidateEvidence(
        disagreeingContext,
        firstEvidence.evidenceId,
        "fixture permits a second disagreeing verifier attempt",
    );
    const secondRecommendation = decideNext(disagreeingContext.aggregate);
    const secondVerifier = reserveAndDispatch(disagreeingContext);
    const secondEvidence = commitImpossibility(
        disagreeingContext,
        secondVerifier,
        "disagree-second",
        fixture.disagreeingAttempts[1],
    );
    const disagreeingTerminal = decideNext(disagreeingContext.aggregate);
    const verdictOf = (context, evidence) =>
        context.aggregate.observations[evidence.observationId]
            .data.certificateVerdict;

    return {
        rawCandidateClaimRecommendation: {
            kind: rawClaimRecommendation.kind,
            commandKind: rawClaimRecommendation.command?.kind ?? null,
        },
        selfCertifiedVerdict:
            deriveImpossibilityVerdict(fixture.selfCertifiedFacts),
        selfCertifiedDecision: selfCertifiedTerminal.decision,
        generatorEqualsVerifier:
            fixture.selfCertificationMetadata.generatorId
            === fixture.selfCertificationMetadata.verifierId,
        independentVerifierRequired: false,
        invalidVerdict: verdictOf(invalidContext, invalidEvidence),
        invalidRecommendation: {
            kind: invalidRecommendation.kind,
            code: invalidRecommendation.code,
        },
        disagreeingVerdicts: [
            verdictOf(disagreeingContext, firstEvidence),
            verdictOf(disagreeingContext, secondEvidence),
        ],
        secondAttemptOrdinal:
            secondRecommendation.command?.attemptOrdinal ?? null,
        disagreeingFinalDecision: disagreeingTerminal.decision,
        consensusRequired: false,
    };
}

export function characterizeLifecycleMetadata() {
    const fixture = SCIENCE_FIXTURES.lifecycleMetadata;
    const base = createInvestigationContract(contractInput());
    const withMetadata = createInvestigationContract(contractInput({
        rebootRecovery: fixture.rebootRecovery,
        rollover: fixture.rollover,
        resourceContention: fixture.resourceContention,
    }));
    const context = validateInvestigation(openInvestigation());
    const { resumed } = pauseAndResume(context);
    return {
        lifecycleMetadataChangesContractHash:
            contractHash(base) !== contractHash(withMetadata),
        normalizedContractFieldsPresent: {
            rebootRecovery: Object.hasOwn(withMetadata, "rebootRecovery"),
            rollover: Object.hasOwn(withMetadata, "rollover"),
            resourceContention: Object.hasOwn(withMetadata, "resourceContention"),
        },
        resumePayloadKeys: Object.keys(resumed.payload).sort(),
        rebootRecoveryBound: false,
        eventLogRolloverBound: false,
        resourceContentionBound: false,
    };
}

export function characterizeOptimization() {
    const fixture = SCIENCE_FIXTURES.optimization;
    const contract = metricContract({
        predicate: { kind: "constant", value: true },
    });
    const evidence = fixture.candidates.map((candidate) =>
        candidateEvidence(candidate, "accepted"));
    const winner = selectIncumbent(contract, evidence);
    const initial = evidence.find((item) => item.candidateId === "opt-initial");
    return {
        seed: fixture.seed,
        reconstructionStatus: fixture.reconstructionStatus,
        sourceNote: fixture.sourceNote,
        winnerId: winner?.candidateId ?? null,
        winnerScore: winner?.metrics.score ?? null,
        knownOptimum: fixture.knownOptimum,
        percentOfKnownOptimum: round(
            ((winner?.metrics.score ?? 0) / fixture.knownOptimum) * 100,
            1,
        ),
        rawMetricImprovement: round(
            metricImprovement(contract.metrics, winner, initial),
            1,
        ),
        relativeImprovementPercent: round(
            (((winner?.metrics.score ?? 0) - fixture.initialScore)
                / fixture.initialScore) * 100,
            12,
        ),
    };
}

const CASE_DEFINITIONS = [
    {
        id: SCIENCE_FIXTURES.nullNoise.id,
        characterization:
            "One threshold-crossing sample from a declared null stream reaches VERIFIED_RESULT.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizeNullNoise,
        oracleKey: "nullNoise",
    },
    {
        id: SCIENCE_FIXTURES.effectAndTie.id,
        characterization:
            "A known effect is selected, while exact equal candidates are silently ordered by commit sequence.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizeEffectAndTie,
        oracleKey: "effectAndTie",
    },
    {
        id: SCIENCE_FIXTURES.drift.id,
        characterization:
            "Raw late-block scores are accepted without block or correlation adjustment.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizeDrift,
        oracleKey: "drift",
    },
    {
        id: SCIENCE_FIXTURES.predicateDisagreement.id,
        characterization:
            "The acceptance predicate remains authoritative when parsed harness pass disagrees.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizePredicateDisagreement,
        oracleKey: "predicateDisagreement",
    },
    {
        id: SCIENCE_FIXTURES.typedPredictions.id,
        characterization:
            "Structured supported/refuted predictions do not affect outcome or ranking.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizeTypedPredictions,
        oracleKey: "typedPredictions",
    },
    {
        id: SCIENCE_FIXTURES.overfit.id,
        characterization:
            "Discovery winner is verified despite failing held-out and challenge observations.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizeOverfit,
        oracleKey: "overfit",
    },
    {
        id: SCIENCE_FIXTURES.boundedEnumerands.id,
        characterization:
            "IDs are unique, but enumerand content is not contract-bound and a retry can mutate content under one ID.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizeBoundedEnumerands,
        oracleKey: "boundedEnumerands",
    },
    {
        id: SCIENCE_FIXTURES.impossibility.id,
        characterization:
            "A self-certified proof and latest surviving disagreeing attempt can establish unreachability without consensus.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizeImpossibility,
        oracleKey: "impossibility",
    },
    {
        id: SCIENCE_FIXTURES.lifecycleMetadata.id,
        characterization:
            "Reboot recovery, event-log rollover, and resource contention remain unbound fixture metadata.",
        expectedToChangeInV4: true,
        notDesiredBehavior: true,
        observed: characterizeLifecycleMetadata,
        oracleKey: "lifecycleMetadata",
    },
    {
        id: SCIENCE_FIXTURES.optimization.id,
        characterization:
            "Reconstructed deterministic optimization baseline reaches 86.7% of the known optimum.",
        expectedToChangeInV4: false,
        notDesiredBehavior: false,
        observed: characterizeOptimization,
        oracleKey: "optimization",
    },
];

export function buildV3ScienceBaseline() {
    return JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8"));
}
