import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    normalizeRawMeasurementSeries,
} from "./replication.mjs";
import {
    evaluateReplicatedStatisticalClaims,
} from "./statistical-evaluation.mjs";
import {
    NOVELTY_MAX_STRUCTURAL_FEATURES,
    NOVELTY_ROLE_ADAPTER_VERSION,
    NOVELTY_STRUCTURAL_FINGERPRINT_ALGORITHM,
    createNoveltyMeasurementBinding,
    noveltyRoleFingerprint,
    tryAdaptNoveltyRoleAttempt,
} from "../measurement/novelty-role.mjs";

export const CANDIDATE_NOVELTY_VERSION = "crucible-candidate-novelty-v1";
export const CONTENT_NOVELTY_SIGNATURE_ALGORITHM =
    "sha256:crucible-content-novelty-v1";
export const BEHAVIORAL_ROLE_FINGERPRINT_ALGORITHM =
    "sha256:crucible-behavioral-role-v1";
export const BEHAVIORAL_NOVELTY_SIGNATURE_ALGORITHM =
    "sha256:crucible-behavioral-novelty-v1";
export const BEHAVIORAL_NOVELTY_BASIS_ALGORITHM =
    "sha256:crucible-behavioral-novelty-basis-v1";
const STRUCTURAL_FEATURE_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/u;

function ownEntry(record, key) {
    return record !== null
        && typeof record === "object"
        && typeof key === "string"
        && Object.hasOwn(record, key)
        ? record[key]
        : null;
}

function plainObject(value) {
    return value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        && (Object.getPrototypeOf(value) === Object.prototype
            || Object.getPrototypeOf(value) === null);
}

function finite(value) {
    return typeof value === "number" && Number.isFinite(value);
}

function cleanNumber(value) {
    return Object.is(value, -0) ? 0 : value;
}

function exactKeys(value, expected) {
    return plainObject(value)
        && canonicalEqual(
            Object.keys(value).sort(),
            [...expected].sort(),
        );
}

function algorithmHash(value, algorithm) {
    return typeof value === "string"
        && value.startsWith(`${algorithm}:`)
        && value.length === algorithm.length + 65
        && /^[a-f0-9]{64}$/u.test(value.slice(-64));
}

function boundedText(value, maximum = 256) {
    return typeof value === "string"
        && value.length > 0
        && value.length <= maximum
        && !value.includes("\0");
}

function resolvedClaimState(value) {
    return value === "SUPPORTED" || value === "REFUTED";
}

function candidateArtifactHash(evidence, observation = null) {
    const value = observation?.receipt?.candidateArtifactHash
        ?? evidence?.receipt?.candidateArtifactHash
        ?? null;
    return isAlgorithmTaggedSha256(value) ? value : null;
}

export function contentNoveltySignature(snapshotHash) {
    if (!isAlgorithmTaggedSha256(snapshotHash)) return null;
    return hashCanonical({
        version: CANDIDATE_NOVELTY_VERSION,
        snapshotHash,
    }, CONTENT_NOVELTY_SIGNATURE_ALGORITHM);
}

function roleFingerprint(contract, roleName) {
    const role = contract?.harnessSuite?.roles?.[roleName];
    if (!plainObject(role)) return null;
    return hashCanonical({
        version: CANDIDATE_NOVELTY_VERSION,
        role: roleName,
        suiteIdentity: contract.harnessSuiteIdentity ?? null,
        environmentIdentity:
            contract.harnessSuite?.environmentIdentity ?? null,
        roleSpec: role,
    }, BEHAVIORAL_ROLE_FINGERPRINT_ALGORITHM);
}

export function behavioralRoleIdentity(contract) {
    return roleFingerprint(contract, "search");
}

function replayCandidateEvaluation(aggregate, evidence, observation, command) {
    const raw = observation?.data?.series?.[0];
    if (!plainObject(raw) || !plainObject(command?.replicationSchedule)) {
        return null;
    }
    try {
        const normalized = normalizeRawMeasurementSeries(raw, {
            schedule: command.replicationSchedule,
            role: "search",
            phase: "search",
            caseId: null,
        });
        return evaluateReplicatedStatisticalClaims({
            contract: aggregate.contract,
            schedule: command.replicationSchedule,
            attempts: normalized.attempts,
        });
    } catch {
        return null;
    }
}

function metricPolicy(contract, observable) {
    return contract?.statisticalPolicy?.metrics?.find(
        (metric) => metric.key === observable,
    ) ?? null;
}

function practicalMargin(contract, claim) {
    const metric = metricPolicy(contract, claim.observable);
    if (finite(metric?.practicalEquivalenceDelta)
        && metric.practicalEquivalenceDelta > 0) {
        return metric.practicalEquivalenceDelta;
    }
    if (finite(claim?.practical?.margin) && claim.practical.margin > 0) {
        return claim.practical.margin;
    }
    return 0;
}

function identifiedBand(contract, claim, confidence) {
    const margin = practicalMargin(contract, claim);
    const metric = metricPolicy(contract, claim.observable);
    if (!(margin > 0) || !finite(metric?.minimum) || !finite(metric?.maximum)) {
        return null;
    }
    const lower = Math.max(metric.minimum, confidence.lower);
    const upper = Math.min(metric.maximum, confidence.upper);
    if (lower > upper) return null;
    const lowerBand = Math.floor((lower - metric.minimum) / margin);
    const upperBand = Math.floor((upper - metric.minimum) / margin);
    return Number.isSafeInteger(lowerBand)
        && lowerBand === upperBand
        ? lowerBand
        : null;
}

function claimPracticalSummary(claim) {
    const practical = claim?.practical;
    if (!plainObject(practical)) return null;
    const summary = {};
    for (const key of [
        "equivalenceState",
        "equivalenceSupported",
        "marginSupported",
    ]) {
        if (typeof practical[key] === "boolean"
            || typeof practical[key] === "string") {
            summary[key] = practical[key];
        }
    }
    return Object.keys(summary).length === 0 ? null : summary;
}

function behavioralClaim(contract, claim) {
    const confidence = claim?.estimate?.confidenceSequence;
    if (!finite(confidence?.lower)
        || !finite(confidence?.upper)
        || confidence.lower > confidence.upper
        || typeof claim?.id !== "string"
        || typeof claim?.kind !== "string"
        || typeof claim?.state !== "string") {
        return null;
    }
    const margin = practicalMargin(contract, claim);
    const referenceKind = claim.reference?.kind ?? null;
    const resolved = claim.state === "SUPPORTED" || claim.state === "REFUTED";
    return {
        key: `${claim.id}\0${claim.kind}\0${claim.observable ?? ""}\0${
            referenceKind ?? ""
        }`,
        id: claim.id,
        kind: claim.kind,
        observable: claim.observable ?? null,
        referenceKind,
        state: claim.state,
        confidenceSequence: {
            lower: cleanNumber(confidence.lower),
            upper: cleanNumber(confidence.upper),
        },
        practicalMargin: cleanNumber(margin),
        fingerprintFeature: resolved
            ? {
                id: claim.id,
                kind: claim.kind,
                observable: claim.observable ?? null,
                referenceKind,
                state: claim.state,
                identifiedBand: identifiedBand(contract, claim, confidence),
                practical: claimPracticalSummary(claim),
            }
            : null,
    };
}

function behavioralBasis(observation, evaluation) {
    const measurements = observation?.receipt?.provenance?.measurements;
    if (!Array.isArray(measurements)) return null;
    const search = measurements
        .filter((measurement) =>
            measurement?.role === undefined
            || measurement.role === "search")
        .map((measurement) => ({
            measurementRoot: measurement.measurementRoot,
            receiptHash: measurement.receiptHash,
            subjectId: measurement.subjectId,
        }))
        .filter((measurement) =>
            isAlgorithmTaggedSha256(measurement.measurementRoot)
            && isAlgorithmTaggedSha256(measurement.receiptHash)
            && typeof measurement.subjectId === "string")
        .sort((left, right) =>
            left.subjectId < right.subjectId
                ? -1
                : left.subjectId > right.subjectId
                    ? 1
                    : 0);
    if (search.length === 0) return null;
    return hashCanonical({
        version: CANDIDATE_NOVELTY_VERSION,
        evaluationHash: evaluation.evaluationHash,
        measurements: search,
    }, BEHAVIORAL_NOVELTY_BASIS_ALGORITHM);
}

export function deriveBehavioralNovelty({
    aggregate,
    evidence,
    observation = null,
    command = null,
    evaluation = null,
}) {
    const resolvedObservation = observation
        ?? ownEntry(aggregate?.observations, evidence?.observationId);
    const resolvedCommand = command
        ?? ownEntry(
            aggregate?.commands,
            resolvedObservation?.commandId,
        )?.command
        ?? null;
    const resolvedEvaluation = evaluation ?? replayCandidateEvaluation(
        aggregate,
        evidence,
        resolvedObservation,
        resolvedCommand,
    );
    if (resolvedEvaluation === null
        || resolvedEvaluation.completeValidBlocks !== true) {
        return null;
    }
    const claims = (resolvedEvaluation.statistics?.claims ?? [])
        .map((claim) => behavioralClaim(aggregate.contract, claim))
        .filter((claim) => claim !== null)
        .sort((left, right) =>
            left.key < right.key ? -1 : left.key > right.key ? 1 : 0);
    if (claims.length === 0) return null;
    const role = roleFingerprint(aggregate.contract, "search");
    const fingerprintFeatures = claims
        .map((claim) => claim.fingerprintFeature)
        .filter((feature) => feature !== null);
    const signature = role === null || fingerprintFeatures.length === 0
        ? null
        : hashCanonical({
            version: CANDIDATE_NOVELTY_VERSION,
            roleFingerprint: role,
            statisticalPolicyIdentity:
                aggregate.contract.statisticalPolicyIdentity ?? null,
            features: fingerprintFeatures,
        }, BEHAVIORAL_NOVELTY_SIGNATURE_ALGORITHM);
    return immutableCanonical({
        signature,
        roleFingerprint: role,
        basisHash: behavioralBasis(resolvedObservation, resolvedEvaluation),
        evaluationHash: resolvedEvaluation.evaluationHash,
        features: fingerprintFeatures,
        claims: claims.map((claim) => ({
            id: claim.id,
            kind: claim.kind,
            observable: claim.observable,
            referenceKind: claim.referenceKind,
            state: claim.state,
            confidenceSequence: claim.confidenceSequence,
            practicalMargin: claim.practicalMargin,
        })),
    });
}

export function supportedBehavioralDifference(left, right) {
    if (!plainObject(left)
        || !plainObject(right)
        || !algorithmHash(
            left.signature,
            BEHAVIORAL_NOVELTY_SIGNATURE_ALGORITHM,
        )
        || !algorithmHash(
            right.signature,
            BEHAVIORAL_NOVELTY_SIGNATURE_ALGORITHM,
        )
        || !algorithmHash(
            left.roleFingerprint,
            BEHAVIORAL_ROLE_FINGERPRINT_ALGORITHM,
        )
        || left.roleFingerprint !== right.roleFingerprint) {
        return false;
    }
    const rightByKey = new Map(
        (right.claims ?? []).map((claim) => [
            `${claim.id}\0${claim.kind}\0${claim.observable ?? ""}\0${
                claim.referenceKind ?? ""
            }`,
            claim,
        ]),
    );
    for (const claim of left.claims ?? []) {
        const key = `${claim.id}\0${claim.kind}\0${claim.observable ?? ""}\0${
            claim.referenceKind ?? ""
        }`;
        const other = rightByKey.get(key);
        if (other === undefined
            || !resolvedClaimState(claim.state)
            || !resolvedClaimState(other.state)) {
            continue;
        }
        const leftInterval = claim.confidenceSequence;
        const rightInterval = other.confidenceSequence;
        if (!finite(leftInterval?.lower)
            || !finite(leftInterval?.upper)
            || !finite(rightInterval?.lower)
            || !finite(rightInterval?.upper)) {
            continue;
        }
        const margin = Math.max(
            finite(claim.practicalMargin) ? claim.practicalMargin : 0,
            finite(other.practicalMargin) ? other.practicalMargin : 0,
        );
        if (leftInterval.lower > rightInterval.upper + margin
            || rightInterval.lower > leftInterval.upper + margin) {
            return true;
        }
    }
    return false;
}

function structuralNovelty(contract, observation, snapshotHash) {
    const attempt = observation?.data?.novelty ?? null;
    const measurements = observation?.receipt?.provenance?.measurements;
    if (!plainObject(attempt) || !Array.isArray(measurements)) return null;
    const measurement = measurements.find(
        (item) => item?.subjectId === attempt.subjectId,
    );
    if (measurement === undefined) return null;
    return tryAdaptNoveltyRoleAttempt({
        attempt,
        measurement,
        contract,
        candidateArtifactHash: snapshotHash,
    });
}

function normalizedStructuralFeatures(value) {
    if (!plainObject(value)) return null;
    const keys = Object.keys(value).sort();
    if (keys.length === 0 || keys.length > NOVELTY_MAX_STRUCTURAL_FEATURES) {
        return null;
    }
    const features = {};
    for (const key of keys) {
        if (!STRUCTURAL_FEATURE_NAME.test(key)
            || key === "__proto__"
            || key === "constructor"
            || key === "prototype"
            || !finite(value[key])) {
            return null;
        }
        features[key] = cleanNumber(value[key]);
    }
    return immutableCanonical(features);
}

function normalizedCachedStructural(contract, value, snapshotHash) {
    if (value === null) return null;
    const expectedRoleFingerprint = structuralRoleIdentity(contract);
    if (!plainObject(value)
        || expectedRoleFingerprint === null
        || value.roleFingerprint !== expectedRoleFingerprint
        || !algorithmHash(
            value.structuralFingerprint,
            NOVELTY_STRUCTURAL_FINGERPRINT_ALGORITHM,
        )) {
        return null;
    }
    if (!exactKeys(value, [
        "features",
        "measurementRoot",
        "receiptHash",
        "roleFingerprint",
        "structuralFingerprint",
        "subjectId",
        "version",
    ])
        || value.version !== NOVELTY_ROLE_ADAPTER_VERSION
        || !isAlgorithmTaggedSha256(value.receiptHash)
        || !isAlgorithmTaggedSha256(value.measurementRoot)
        || !boundedText(value.subjectId, 128)) {
        return null;
    }
    const features = normalizedStructuralFeatures(value.features);
    const role = contract?.harnessSuite?.roles?.novelty;
    let expectedBinding;
    try {
        expectedBinding = createNoveltyMeasurementBinding({
            contract,
            candidateArtifactHash: snapshotHash,
        });
    } catch {
        return null;
    }
    if (features === null
        || !plainObject(role)
        || value.subjectId !== expectedBinding.subjectId) {
        return null;
    }
    const expectedFingerprint = hashCanonical({
        version: NOVELTY_ROLE_ADAPTER_VERSION,
        roleFingerprint: expectedRoleFingerprint,
        observableSchemaHash: role.observableSchemaHash,
        features,
    }, NOVELTY_STRUCTURAL_FINGERPRINT_ALGORITHM);
    if (value.structuralFingerprint !== expectedFingerprint) return null;
    return immutableCanonical({
        version: NOVELTY_ROLE_ADAPTER_VERSION,
        roleFingerprint: expectedRoleFingerprint,
        structuralFingerprint: expectedFingerprint,
        features,
        receiptHash: value.receiptHash,
        measurementRoot: value.measurementRoot,
        subjectId: value.subjectId,
    });
}

function normalizedNullableText(value, maximum = 256) {
    return value === null
        ? null
        : boundedText(value, maximum)
            ? value
            : undefined;
}

function normalizedBehavioralClaim(value) {
    if (!exactKeys(value, [
        "confidenceSequence",
        "id",
        "kind",
        "observable",
        "practicalMargin",
        "referenceKind",
        "state",
    ])
        || !boundedText(value.id)
        || !boundedText(value.kind)
        || normalizedNullableText(value.observable) === undefined
        || normalizedNullableText(value.referenceKind) === undefined
        || !["SUPPORTED", "REFUTED", "UNRESOLVED", "INVALID"]
            .includes(value.state)
        || !exactKeys(value.confidenceSequence, ["lower", "upper"])
        || !finite(value.confidenceSequence.lower)
        || !finite(value.confidenceSequence.upper)
        || value.confidenceSequence.lower > value.confidenceSequence.upper
        || !finite(value.practicalMargin)
        || value.practicalMargin < 0) {
        return null;
    }
    return immutableCanonical({
        id: value.id,
        kind: value.kind,
        observable: value.observable,
        referenceKind: value.referenceKind,
        state: value.state,
        confidenceSequence: {
            lower: cleanNumber(value.confidenceSequence.lower),
            upper: cleanNumber(value.confidenceSequence.upper),
        },
        practicalMargin: cleanNumber(value.practicalMargin),
    });
}

function normalizedBehavioralClaims(value) {
    if (!Array.isArray(value) || value.length === 0 || value.length > 4096) {
        return null;
    }
    const claims = value.map(normalizedBehavioralClaim);
    if (claims.some((claim) => claim === null)) return null;
    claims.sort((left, right) => {
        const leftKey = `${left.id}\0${left.kind}\0${left.observable ?? ""}\0${
            left.referenceKind ?? ""
        }`;
        const rightKey = `${right.id}\0${right.kind}\0${right.observable ?? ""}\0${
            right.referenceKind ?? ""
        }`;
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
    const keys = claims.map((claim) =>
        `${claim.id}\0${claim.kind}\0${claim.observable ?? ""}\0${
            claim.referenceKind ?? ""
        }`);
    return new Set(keys).size === keys.length
        ? immutableCanonical(claims)
        : null;
}

function normalizedPracticalSummary(value) {
    if (value === null) return null;
    if (!plainObject(value)) return undefined;
    const allowed = new Set([
        "equivalenceState",
        "equivalenceSupported",
        "marginSupported",
    ]);
    const summary = {};
    for (const key of Object.keys(value).sort()) {
        if (!allowed.has(key)
            || (typeof value[key] !== "boolean"
                && !boundedText(value[key], 128))) {
            return undefined;
        }
        summary[key] = value[key];
    }
    return Object.keys(summary).length === 0
        ? null
        : immutableCanonical(summary);
}

function normalizedBehavioralFeature(value, claimsByKey) {
    if (!exactKeys(value, [
        "id",
        "identifiedBand",
        "kind",
        "observable",
        "practical",
        "referenceKind",
        "state",
    ])
        || !boundedText(value.id)
        || !boundedText(value.kind)
        || normalizedNullableText(value.observable) === undefined
        || normalizedNullableText(value.referenceKind) === undefined
        || !resolvedClaimState(value.state)
        || (value.identifiedBand !== null
            && (!Number.isSafeInteger(value.identifiedBand)
                || value.identifiedBand < 0))) {
        return null;
    }
    const practical = normalizedPracticalSummary(value.practical);
    if (practical === undefined) return null;
    const key = `${value.id}\0${value.kind}\0${value.observable ?? ""}\0${
        value.referenceKind ?? ""
    }`;
    const claim = claimsByKey.get(key);
    if (claim === undefined || claim.state !== value.state) return null;
    return immutableCanonical({
        id: value.id,
        kind: value.kind,
        observable: value.observable,
        referenceKind: value.referenceKind,
        state: value.state,
        identifiedBand: value.identifiedBand,
        practical,
    });
}

function normalizedCachedBehavioral(contract, value) {
    if (value === null) return null;
    const expectedRoleFingerprint = behavioralRoleIdentity(contract);
    if (!plainObject(value)
        || expectedRoleFingerprint === null
        || value.roleFingerprint !== expectedRoleFingerprint
        || (value.signature !== null
            && !algorithmHash(
                value.signature,
                BEHAVIORAL_NOVELTY_SIGNATURE_ALGORITHM,
            ))) {
        return null;
    }
    const claims = normalizedBehavioralClaims(value.claims);
    if (claims === null || !canonicalEqual(value.claims, claims)) return null;
    if (!exactKeys(value, [
        "basisHash",
        "claims",
        "evaluationHash",
        "features",
        "roleFingerprint",
        "signature",
    ])
        || (value.basisHash !== null
            && !algorithmHash(
                value.basisHash,
                BEHAVIORAL_NOVELTY_BASIS_ALGORITHM,
            ))
        || !isAlgorithmTaggedSha256(value.evaluationHash)
        || !Array.isArray(value.features)
        || value.features.length > claims.length) {
        return null;
    }
    const claimsByKey = new Map(claims.map((claim) => [
        `${claim.id}\0${claim.kind}\0${claim.observable ?? ""}\0${
            claim.referenceKind ?? ""
        }`,
        claim,
    ]));
    const features = value.features.map((feature) =>
        normalizedBehavioralFeature(feature, claimsByKey));
    if (features.some((feature) => feature === null)) return null;
    features.sort((left, right) => {
        const leftKey = `${left.id}\0${left.kind}\0${left.observable ?? ""}\0${
            left.referenceKind ?? ""
        }`;
        const rightKey = `${right.id}\0${right.kind}\0${right.observable ?? ""}\0${
            right.referenceKind ?? ""
        }`;
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
    if (!canonicalEqual(value.features, features)) return null;
    const expectedSignature = features.length === 0
        ? null
        : hashCanonical({
            version: CANDIDATE_NOVELTY_VERSION,
            roleFingerprint: expectedRoleFingerprint,
            statisticalPolicyIdentity:
                contract?.statisticalPolicyIdentity ?? null,
            features,
        }, BEHAVIORAL_NOVELTY_SIGNATURE_ALGORITHM);
    if (value.signature !== expectedSignature) return null;
    return immutableCanonical({
        signature: expectedSignature,
        roleFingerprint: expectedRoleFingerprint,
        basisHash: value.basisHash,
        evaluationHash: value.evaluationHash,
        features,
        claims,
    });
}

function cachedRecord(value, snapshotHash, contract) {
    const expectedContentSignature = contentNoveltySignature(snapshotHash);
    if (!exactKeys(value, [
        "behavioral",
        "content",
        "structural",
        "version",
    ])
        || value.version !== CANDIDATE_NOVELTY_VERSION
        || !exactKeys(value.content, ["signature", "snapshotHash"])
        || value.content.snapshotHash !== snapshotHash
        || value.content.signature !== expectedContentSignature) {
        return null;
    }
    return immutableCanonical({
        version: CANDIDATE_NOVELTY_VERSION,
        content: {
            snapshotHash,
            signature: expectedContentSignature,
        },
        structural: normalizedCachedStructural(
            contract,
            value.structural,
            snapshotHash,
        ),
        behavioral: normalizedCachedBehavioral(
            contract,
            value.behavioral,
        ),
    });
}

export function deriveCandidateNovelty({
    aggregate,
    evidence,
    observation = null,
    command = null,
    candidateEvaluation = null,
}) {
    const resolvedObservation = observation
        ?? ownEntry(aggregate?.observations, evidence?.observationId);
    const snapshotHash = candidateArtifactHash(evidence, resolvedObservation);
    if (snapshotHash === null) return null;
    const content = {
        snapshotHash,
        signature: contentNoveltySignature(snapshotHash),
    };
    if (resolvedObservation === null) {
        const cached = cachedRecord(
            evidence?.novelty,
            snapshotHash,
            aggregate?.contract,
        );
        return cached ?? immutableCanonical({
            version: CANDIDATE_NOVELTY_VERSION,
            content,
            structural: null,
            behavioral: null,
        });
    }
    return immutableCanonical({
        version: CANDIDATE_NOVELTY_VERSION,
        content,
        structural: structuralNovelty(
            aggregate.contract,
            resolvedObservation,
            snapshotHash,
        ),
        behavioral: deriveBehavioralNovelty({
            aggregate,
            evidence,
            observation: resolvedObservation,
            command,
            evaluation: candidateEvaluation,
        }),
    });
}

export function replayDerivedCandidateNovelty(aggregate, evidence) {
    if (evidence?.sourceKind !== "harness"
        || evidence?.purpose !== "candidate") {
        return evidence;
    }
    const snapshotHash = candidateArtifactHash(evidence);
    let novelty = null;
    if (snapshotHash !== null) {
        const cached = cachedRecord(
            evidence.novelty,
            snapshotHash,
            aggregate?.contract,
        );
        const observation = ownEntry(
            aggregate?.observations,
            evidence.observationId,
        );
        if (observation === null) {
            novelty = cached ?? deriveCandidateNovelty({
                aggregate,
                evidence,
            });
        } else {
            novelty = deriveCandidateNovelty({
                aggregate,
                evidence,
                observation,
            });
            if (evidence.novelty !== null
                && evidence.novelty !== undefined
                && (cached === null || !canonicalEqual(cached, novelty))) {
                throw new TypeError(
                    `candidate evidence ${evidence.evidenceId} has an invalid novelty replay cache`,
                );
            }
        }
    }
    return immutableCanonical({
        ...evidence,
        novelty,
    });
}

export function candidateNoveltySignatures(evidence) {
    const values = [
        evidence?.novelty?.content?.signature,
        evidence?.novelty?.structural?.structuralFingerprint,
        evidence?.novelty?.behavioral?.signature,
    ].filter((value, index) => algorithmHash(
        value,
        [
            CONTENT_NOVELTY_SIGNATURE_ALGORITHM,
            NOVELTY_STRUCTURAL_FINGERPRINT_ALGORITHM,
            BEHAVIORAL_NOVELTY_SIGNATURE_ALGORITHM,
        ][index],
    ));
    return immutableCanonical([...new Set(values)].sort());
}

export function structuralRoleIdentity(contract) {
    try {
        return noveltyRoleFingerprint(contract);
    } catch {
        return null;
    }
}
