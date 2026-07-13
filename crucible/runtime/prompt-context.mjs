// crucible/runtime/prompt-context.mjs
//
// Pure, deterministic construction of the bounded semantic context that the
// adaptive proposal prompt is rendered from.
//
// This module takes a single reserved command slot plus already-curated
// archive / plateau material (produced by the trusted domain kernel and passed
// in by the runner) and folds it into a canonical, byte-capped "semantic
// context" object plus its content hash. It performs no I/O, reads no clocks,
// and consults no randomness: identical inputs always yield an identical
// context and hash.
//
// The byte cap is enforced by dropping *whole* low-priority entries (never by
// truncating inside an entry), so every surviving entry retains its exact,
// verifiable meaning. Dropped counts are reported back in `omissions` so the
// worker is told how much history it is not seeing.
//
// The context separates trusted kernel/operator material (objective, acceptance
// predicate, ranking metrics, this slot's assignment, plateau notice) from
// `priorWork`, which is derived from earlier *model-authored* candidate content
// (mechanisms, findings, hypotheses). The prompt renderer is responsible for
// wrapping `priorWork` in nonce-delimited untrusted-data framing.

import {
    ANNOTATION_LIMITS,
    CONTRACT_LIMITS,
    SEARCH_POLICY_LIMITS,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
    metricImprovement,
} from "../domain/index.mjs";
import { projectHarnessSuiteV4ForWorker } from "../measurement/index.mjs";
import { RuntimeConfigError } from "./errors.mjs";
import { requirePlainObject } from "./utils.mjs";

export const PROMPT_CONTEXT_VERSION = "crucible-runtime-prompt-context-v1";
export const PROMPT_CONTEXT_HASH_ALGORITHM = "sha256:crucible-runtime-prompt-context-v1";

export const DEFAULT_PROMPT_CONTEXT_BYTE_CAP = 24 * 1024;
const MIN_PROMPT_CONTEXT_BYTE_CAP = 2 * 1024;
const MAX_PROMPT_CONTEXT_BYTE_CAP = 1024 * 1024;

// Buckets are dropped in this order (front = dropped first). Each surviving
// entry is kept whole; the byte cap never splits an entry. Ordering keeps the
// highest-signal history (near-misses, then elites) the longest.
const DROP_ORDER = Object.freeze([
    "duplicateHashes",
    "failures",
    "deltas",
    "lessons",
    "elites",
    "nearMisses",
    "predictionFindings",
]);

function asArray(value) {
    return Array.isArray(value) ? value : [];
}

function finiteNumberOrNull(value) {
    return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringOrNull(value) {
    return typeof value === "string" && value.length > 0 ? value : null;
}

function boundedStringOrNull(value, field, maximumCharacters, maximumBytes) {
    const normalized = stringOrNull(value);
    if (normalized === null) {
        return null;
    }
    const bytes = Buffer.byteLength(normalized, "utf8");
    if (normalized.length > maximumCharacters || bytes > maximumBytes) {
        throw new RuntimeConfigError(`${field} exceeds its prompt-context bound`, {
            field,
            characters: normalized.length,
            bytes,
            maximumCharacters,
            maximumBytes,
        });
    }
    return normalized;
}

function integerOrNull(value) {
    return Number.isSafeInteger(value) ? value : null;
}

function byteLength(value) {
    return Buffer.byteLength(canonicalJson(value), "utf8");
}

function assertArrayBound(value, maximum, field) {
    const list = asArray(value);
    if (list.length > maximum) {
        throw new RuntimeConfigError(`${field} exceeds its prompt-context item bound`, {
            field,
            count: list.length,
            maximum,
        });
    }
    return list;
}

function archiveCap(contract, key) {
    const configured = contract.searchPolicy?.archiveCaps?.[key];
    return Number.isSafeInteger(configured)
        ? Math.min(configured, SEARCH_POLICY_LIMITS.archiveCaps[key])
        : SEARCH_POLICY_LIMITS.archiveCaps[key];
}

function promptCap(contract, key) {
    const configured = contract.searchPolicy?.promptCaps?.[key];
    return Number.isSafeInteger(configured)
        ? Math.min(configured, SEARCH_POLICY_LIMITS.promptCaps[key])
        : SEARCH_POLICY_LIMITS.promptCaps[key];
}

function assertArchiveBounds(contract, archive) {
    for (const key of [
        "accepted",
        "nearMisses",
        "rejected",
        "inconclusive",
        "invalidMetrics",
    ]) {
        assertArrayBound(archive[key], archiveCap(contract, key), `archive.${key}`);
    }
    assertArrayBound(
        archive.mechanismGroups,
        archiveCap(contract, "mechanismGroups"),
        "archive.mechanismGroups",
    );
    assertArrayBound(
        archive.lessonGroups,
        archiveCap(contract, "lessonGroups"),
        "archive.lessonGroups",
    );
    const noveltyNiches = archive.noveltyNiches;
    if (noveltyNiches !== undefined && noveltyNiches !== null) {
        requirePlainObject(noveltyNiches, "archive.noveltyNiches");
        assertArrayBound(
            noveltyNiches.content,
            archiveCap(contract, "duplicateIndex"),
            "archive.noveltyNiches.content",
        );
        assertArrayBound(
            noveltyNiches.structural,
            archiveCap(contract, "mechanismGroups"),
            "archive.noveltyNiches.structural",
        );
        assertArrayBound(
            noveltyNiches.behavioral,
            archiveCap(contract, "lessonGroups"),
            "archive.noveltyNiches.behavioral",
        );
    }
    const duplicateIndex = archive.duplicateIndex;
    if (duplicateIndex !== undefined
        && duplicateIndex !== null
        && (typeof duplicateIndex !== "object"
            || Array.isArray(duplicateIndex)
            || Object.keys(duplicateIndex).length
                > archiveCap(contract, "duplicateIndex"))) {
        throw new RuntimeConfigError("archive.duplicateIndex exceeds its prompt-context bound", {
            maximum: archiveCap(contract, "duplicateIndex"),
        });
    }
}

function normalizeByteCap(byteCap) {
    if (byteCap === undefined || byteCap === null) {
        return DEFAULT_PROMPT_CONTEXT_BYTE_CAP;
    }
    if (!Number.isSafeInteger(byteCap)
        || byteCap < MIN_PROMPT_CONTEXT_BYTE_CAP
        || byteCap > MAX_PROMPT_CONTEXT_BYTE_CAP) {
        throw new RuntimeConfigError(
            `byteCap must be a safe integer within ${MIN_PROMPT_CONTEXT_BYTE_CAP}..${MAX_PROMPT_CONTEXT_BYTE_CAP}`,
            { byteCap },
        );
    }
    return byteCap;
}

function metricKeys(metrics) {
    return asArray(metrics)
        .map((metric) => (metric && typeof metric.key === "string" ? metric.key : null))
        .filter((key) => key !== null);
}

function selectMetricValues(source, keys) {
    const values = {};
    if (source && typeof source === "object") {
        for (const key of keys) {
            const value = finiteNumberOrNull(source[key]);
            if (value !== null) {
                values[key] = value;
            }
        }
    }
    return values;
}

function summarizeCandidate(evidence, keys) {
    if (evidence === null || typeof evidence !== "object") {
        return null;
    }
    const annotations = evidence.annotations && typeof evidence.annotations === "object"
        ? evidence.annotations
        : {};
    const novelty = {
        contentSignature:
            stringOrNull(evidence.novelty?.content?.signature),
        structuralSignature:
            stringOrNull(
                evidence.novelty?.structural?.structuralFingerprint,
            ),
        behavioralSignature:
            stringOrNull(evidence.novelty?.behavioral?.signature),
    };
    const hasNovelty = Object.values(novelty).some((value) => value !== null);
    return {
        evidenceId: stringOrNull(evidence.evidenceId),
        outcomeClass: stringOrNull(evidence.outcomeClass),
        round: integerOrNull(evidence.round),
        slotIndex: integerOrNull(evidence.slotIndex),
        metrics: selectMetricValues(evidence.metrics, keys),
        mechanism: boundedStringOrNull(
            annotations.mechanism,
            "evidence.annotations.mechanism",
            ANNOTATION_LIMITS.mechanismLength,
            ANNOTATION_LIMITS.mechanismBytes,
        ),
        finding: boundedStringOrNull(
            annotations.finding,
            "evidence.annotations.finding",
            ANNOTATION_LIMITS.findingLength,
            ANNOTATION_LIMITS.findingBytes,
        ),
        artifactHash: stringOrNull(evidence.receipt?.candidateArtifactHash),
        ...(hasNovelty ? { novelty } : {}),
    };
}

function summarizeList(list, keys) {
    return asArray(list)
        .map((evidence) => summarizeCandidate(evidence, keys))
        .filter((summary) => summary !== null && summary.evidenceId !== null);
}

function predictionFinding(evidence, prediction) {
    if (prediction?.status !== "SUPPORTED"
        && prediction?.status !== "REFUTED") {
        return null;
    }
    return {
        evidenceId: evidence.evidenceId,
        candidateId: evidence.candidateId,
        hypothesesIdentity:
            evidence.predictionEvaluation?.hypothesesIdentity ?? null,
        predictionId: prediction.predictionId,
        predictionIdentity: prediction.predictionIdentity,
        requiredForResult: prediction.requiredForResult === true,
        kind: prediction.prediction?.kind ?? null,
        observable: prediction.prediction?.observable ?? null,
        prediction: prediction.prediction ?? null,
        status: prediction.status,
        estimate: prediction.estimate,
        confidenceBounds: prediction.confidenceBounds,
        confidenceMethod: prediction.confidenceMethod ?? null,
        evidenceReference: prediction.evidenceReference,
        blockReference: prediction.blockReference,
        alphaReference: prediction.alphaReference,
        reference: prediction.reference,
        limitations: prediction.limitations,
    };
}

function buildPredictionFindings(evidenceItems) {
    const seen = new Set();
    const findings = [];
    for (const evidence of asArray(evidenceItems)) {
        if (evidence === null
            || typeof evidence !== "object"
            || seen.has(evidence.evidenceId)) {
            continue;
        }
        seen.add(evidence.evidenceId);
        for (const prediction of asArray(
            evidence.predictionEvaluation?.predictions,
        )) {
            const finding = predictionFinding(evidence, prediction);
            if (finding !== null) findings.push(finding);
        }
    }
    return findings.sort((left, right) =>
        `${left.evidenceId}\0${left.predictionId}`.localeCompare(
            `${right.evidenceId}\0${right.predictionId}`,
        ));
}

function orientedImprovement(metric, candidateValue, incumbentValue) {
    return metric.direction === "min"
        ? incumbentValue - candidateValue
        : candidateValue - incumbentValue;
}

function buildDeltas(metrics, incumbent, candidateSummaries) {
    if (incumbent === null) {
        return [];
    }
    const deltas = [];
    for (const candidate of candidateSummaries) {
        if (candidate.evidenceId === incumbent.evidenceId) {
            continue;
        }
        const metricDeltas = {};
        let comparable = false;
        for (const metric of metrics) {
            const candidateValue = finiteNumberOrNull(candidate.metrics[metric.key]);
            const incumbentValue = finiteNumberOrNull(incumbent.metrics[metric.key]);
            if (candidateValue !== null && incumbentValue !== null) {
                metricDeltas[metric.key] = orientedImprovement(
                    metric,
                    candidateValue,
                    incumbentValue,
                );
                comparable = true;
            }
        }
        if (!comparable) {
            continue;
        }
        deltas.push({
            evidenceId: candidate.evidenceId,
            outcomeClass: candidate.outcomeClass,
            accepted: candidate.outcomeClass === "accepted",
            metricDeltas,
            improvedOverIncumbent: metricImprovement(
                metrics,
                { metrics: candidate.metrics },
                { metrics: incumbent.metrics },
            ) > 0,
        });
    }
    return deltas;
}

function buildLessons(lessonGroups) {
    return asArray(lessonGroups)
        .map((group) => {
            const finding = boundedStringOrNull(
                group?.finding,
                "archive.lessonGroups.finding",
                ANNOTATION_LIMITS.findingLength,
                ANNOTATION_LIMITS.findingBytes,
            );
            if (finding === null) {
                return null;
            }
            const evidenceIds = asArray(group.evidenceIds).filter(
                (id) => typeof id === "string" && id.length > 0,
            );
            return { finding, evidenceIds };
        })
        .filter((lesson) => lesson !== null);
}

function buildDuplicateHashes(duplicateIndex) {
    if (duplicateIndex === null || typeof duplicateIndex !== "object") {
        return [];
    }
    return Object.keys(duplicateIndex)
        .sort()
        .map((artifactHash) => ({
            artifactHash,
            evidenceId: stringOrNull(duplicateIndex[artifactHash]),
        }));
}

function plateauNotice(plateau) {
    if (plateau === null) {
        return {
            phase: "normal",
            plateauDetected: false,
            stagnantRounds: 0,
            escapeRoundsCompleted: 0,
            escapeRoundsRequired: 0,
            escapeComplete: false,
            triggerRound: null,
            notice: "No plateau detected. Run the standard search for the assigned operator.",
        };
    }
    const phase = typeof plateau.phase === "string" ? plateau.phase : "normal";
    const escapeRoundsCompleted = integerOrNull(plateau.escapeRoundsCompleted) ?? 0;
    const escapeRoundsRequired = integerOrNull(plateau.escapeRoundsRequired) ?? 0;
    const triggerRound = integerOrNull(plateau.triggerRound);
    let notice;
    if (phase === "mandatory_escape") {
        notice = `Plateau detected${triggerRound === null ? "" : ` at round ${triggerRound}`}. `
            + `You are in a mandatory escape phase (${escapeRoundsCompleted} of ${escapeRoundsRequired} `
            + "escape rounds complete). Propose a structurally different approach; avoid minor tweaks "
            + "to existing candidates.";
    } else if (phase === "plateau") {
        notice = "The search remains on a plateau after the escape budget. A trusted structural "
            + "fingerprint or statistically supported behavioral difference is required; "
            + "annotation-only relabeling is not novelty.";
    } else {
        notice = "No plateau detected. Run the standard search for the assigned operator.";
    }
    return {
        phase,
        plateauDetected: plateau.plateauDetected === true,
        stagnantRounds: integerOrNull(plateau.stagnantRounds) ?? 0,
        escapeRoundsCompleted,
        escapeRoundsRequired,
        escapeComplete: plateau.escapeComplete === true,
        triggerRound,
        notice,
    };
}

function normalizeAssignment(slot) {
    requirePlainObject(slot, "slot");
    const round = integerOrNull(slot.round);
    const slotIndex = integerOrNull(slot.slotIndex);
    if (round === null || round < 1 || slotIndex === null || slotIndex < 0) {
        throw new RuntimeConfigError("slot.round/slot.slotIndex must be valid positions", {
            round: slot.round ?? null,
            slotIndex: slot.slotIndex ?? null,
        });
    }
    const parentEvidenceIds = assertArrayBound(
        slot.parentEvidenceIds,
        SEARCH_POLICY_LIMITS.promptCaps.parentEvidenceIds,
        "slot.parentEvidenceIds",
    ).filter((id) => typeof id === "string" && id.length > 0);
    const promptContextRefs = assertArrayBound(
        slot.promptContextRefs,
        SEARCH_POLICY_LIMITS.promptCaps.promptContextRefs,
        "slot.promptContextRefs",
    ).filter((id) => typeof id === "string" && id.length > 0);
    const assignment = {
        operator: stringOrNull(slot.operator) ?? "fresh",
        round,
        slotIndex,
        candidateId: stringOrNull(slot.candidateId),
        model: stringOrNull(slot.model),
        seed: integerOrNull(slot.seed),
        parentEvidenceIds,
        promptContextRefs,
    };
    if (stringOrNull(slot.boundedCandidateId) !== null) {
        assignment.boundedCandidateId = slot.boundedCandidateId;
    }
    return assignment;
}

// Enforce the byte cap by dropping whole entries from the tail of the
// lowest-priority non-empty bucket until the serialized body fits. Returns the
// per-bucket omission counts. Deterministic: buckets are already sorted best
// first by the domain archive, so tail drops remove the least valuable entries.
function enforceByteCap(body, byteCap, initialOmissions = {}) {
    const omissions = {
        elites: 0,
        nearMisses: 0,
        failures: 0,
        lessons: 0,
        deltas: 0,
        duplicateHashes: 0,
        ...initialOmissions,
    };
    while (byteLength({ ...body, omissions }) > byteCap) {
        let dropped = false;
        for (const bucket of DROP_ORDER) {
            const entries = bucket === "predictionFindings"
                ? body.codeDerivedFindings?.predictions ?? []
                : body.priorWork[bucket];
            if (Array.isArray(entries) && entries.length > 0) {
                entries.pop();
                omissions[bucket] += 1;
                dropped = true;
                break;
            }
        }
        if (!dropped) {
            const coreBytes = byteLength({ ...body, omissions });
            throw new RuntimeConfigError(
                "Irreducible prompt context exceeds the frozen byte cap",
                { coreBytes, byteCap },
            );
        }
    }
    return omissions;
}

export function buildPromptContext(input = {}) {
    requirePlainObject(input, "prompt-context input");
    const contract = requirePlainObject(input.contract ?? {}, "contract");
    const archive = requirePlainObject(input.archive ?? {}, "archive");
    const byteCap = normalizeByteCap(input.byteCap);
    assertArchiveBounds(contract, archive);

    const objective = boundedStringOrNull(
        contract.objective,
        "contract.objective",
        CONTRACT_LIMITS.objectiveCharacters,
        CONTRACT_LIMITS.objectiveBytes,
    );
    if (objective === null) {
        throw new RuntimeConfigError("contract.objective must be a non-empty string");
    }
    const predicate = contract.acceptancePredicate ?? { kind: "harness_pass" };
    const predicateBytes = byteLength(predicate);
    if (predicateBytes > CONTRACT_LIMITS.acceptancePredicateBytes) {
        throw new RuntimeConfigError("contract.acceptancePredicate exceeds its byte bound", {
            predicateBytes,
            maximumBytes: CONTRACT_LIMITS.acceptancePredicateBytes,
        });
    }
    const metrics = assertArrayBound(
        contract.metrics,
        CONTRACT_LIMITS.metrics,
        "contract.metrics",
    )
        .filter((metric) => metric && typeof metric.key === "string")
        .map((metric) => ({
            key: metric.key,
            direction: metric.direction === "min" ? "min" : "max",
            epsilon: finiteNumberOrNull(metric.epsilon) ?? 0,
        }));
    const keys = metricKeys(metrics);
    let harnessSuite = null;
    if (contract.harnessSuite !== undefined) {
        try {
            harnessSuite = projectHarnessSuiteV4ForWorker(contract.harnessSuite);
        } catch (error) {
            throw new RuntimeConfigError(
                `contract.harnessSuite is invalid: ${error?.message ?? String(error)}`,
                { cause: error?.code ?? null },
            );
        }
    }
    let statisticalPolicy = null;
    if (contract.statisticalPolicy !== undefined) {
        const frozenStatisticalPolicy = requirePlainObject(
            contract.statisticalPolicy,
            "contract.statisticalPolicy",
        );
        statisticalPolicy = {
            ...frozenStatisticalPolicy,
            control: {
                ...requirePlainObject(
                    frozenStatisticalPolicy.control,
                    "contract.statisticalPolicy.control",
                ),
                identity: null,
            },
        };
    }
    const observableRegistry = contract.observableRegistry === undefined
        ? null
        : assertArrayBound(
            contract.observableRegistry,
            64,
            "contract.observableRegistry",
        );
    const hypothesisPolicy = contract.hypothesisPolicy === undefined
        ? null
        : requirePlainObject(
            contract.hypothesisPolicy,
            "contract.hypothesisPolicy",
        );

    const assignment = normalizeAssignment(input.slot);
    if (assignment.parentEvidenceIds.length > promptCap(contract, "parentEvidenceIds")
        || assignment.promptContextRefs.length > promptCap(contract, "promptContextRefs")) {
        throw new RuntimeConfigError("slot prompt references exceed the frozen contract caps", {
            parentEvidenceIds: assignment.parentEvidenceIds.length,
            promptContextRefs: assignment.promptContextRefs.length,
            parentEvidenceIdCap: promptCap(contract, "parentEvidenceIds"),
            promptContextRefCap: promptCap(contract, "promptContextRefs"),
        });
    }
    const visibleEvidenceIds = new Set(assignment.promptContextRefs);
    const visibleEvidence = (evidence) =>
        evidence !== null
        && typeof evidence === "object"
        && visibleEvidenceIds.has(evidence.evidenceId);
    const visibleList = (items) => asArray(items).filter(visibleEvidence);
    const visibleGroups = (groups) => asArray(groups)
        .map((group) => ({
            ...group,
            evidenceIds: asArray(group?.evidenceIds).filter((evidenceId) =>
                visibleEvidenceIds.has(evidenceId)),
        }))
        .filter((group) => group.evidenceIds.length > 0);
    const visibleDuplicateIndex = Object.fromEntries(
        Object.entries(
            archive.duplicateIndex !== null && typeof archive.duplicateIndex === "object"
                ? archive.duplicateIndex
                : {},
        ).filter(([, evidenceId]) => visibleEvidenceIds.has(evidenceId)),
    );

    const incumbentSource = visibleEvidence(archive.incumbent) ? archive.incumbent : null;
    const incumbent = summarizeCandidate(incumbentSource, keys);
    const incumbentEvidenceId = incumbent?.evidenceId ?? null;
    const visibleAccepted = visibleList(archive.accepted);
    const visibleNearMisses = visibleList(archive.nearMisses);
    const visibleRejected = visibleList(archive.rejected);
    const visibleInconclusive = visibleList(archive.inconclusive);
    const visibleInvalidMetrics = visibleList(archive.invalidMetrics);
    const visibleLessonGroups = visibleGroups(archive.lessonGroups);
    const elites = summarizeList(visibleAccepted, keys)
        .filter((summary) => summary.evidenceId !== incumbentEvidenceId);
    const nearMisses = summarizeList(visibleNearMisses, keys);
    const failures = [
        ...summarizeList(visibleRejected, keys),
        ...summarizeList(visibleInconclusive, keys),
        ...summarizeList(visibleInvalidMetrics, keys),
    ];
    const deltas = buildDeltas(metrics, incumbent, [...nearMisses, ...elites]);
    const lessons = buildLessons(visibleLessonGroups);
    const duplicateHashes = buildDuplicateHashes(visibleDuplicateIndex);
    const allCandidateEvidence = [
        ...asArray(archive.accepted),
        ...asArray(archive.nearMisses),
        ...asArray(archive.rejected),
        ...asArray(archive.inconclusive),
        ...asArray(archive.invalidMetrics),
    ];
    const candidateById = new Map(
        allCandidateEvidence
            .filter((evidence) =>
                evidence !== null
                && typeof evidence === "object"
                && typeof evidence.evidenceId === "string")
            .map((evidence) => [evidence.evidenceId, evidence]),
    );
    const trustedNoveltyParents = assignment.parentEvidenceIds
        .map((evidenceId) => candidateById.get(evidenceId) ?? null)
        .filter((evidence) => evidence !== null)
        .map((evidence) => ({
            evidenceId: evidence.evidenceId,
            contentSignature:
                stringOrNull(evidence.novelty?.content?.signature),
            structuralSignature:
                stringOrNull(
                    evidence.novelty?.structural?.structuralFingerprint,
                ),
            behavioralSignature:
                stringOrNull(evidence.novelty?.behavioral?.signature),
        }));
    const visibleCandidateEvidence = allCandidateEvidence.filter(
        visibleEvidence,
    );
    const allPredictionFindings =
        buildPredictionFindings(allCandidateEvidence);
    const predictionFindings =
        buildPredictionFindings(visibleCandidateEvidence);
    const initialOmissions = {
        elites: Math.max(
            0,
            summarizeList(archive.accepted, keys)
                .filter((summary) => summary.evidenceId !== archive.incumbent?.evidenceId)
                .length - elites.length,
        ),
        nearMisses: Math.max(0, summarizeList(archive.nearMisses, keys).length - nearMisses.length),
        failures: Math.max(
            0,
            summarizeList(archive.rejected, keys).length
                + summarizeList(archive.inconclusive, keys).length
                + summarizeList(archive.invalidMetrics, keys).length
                - failures.length,
        ),
        lessons: Math.max(0, buildLessons(archive.lessonGroups).length - lessons.length),
        deltas: 0,
        duplicateHashes: Math.max(
            0,
            buildDuplicateHashes(archive.duplicateIndex).length - duplicateHashes.length,
        ),
        ...(allPredictionFindings.length === 0
            ? {}
            : {
                predictionFindings: Math.max(
                    0,
                    allPredictionFindings.length
                        - predictionFindings.length,
                ),
            }),
    };

    const body = {
        version: PROMPT_CONTEXT_VERSION,
        objective,
        predicate,
        metrics,
        ...(statisticalPolicy === null ? {} : { statisticalPolicy }),
        ...(observableRegistry === null ? {} : { observableRegistry }),
        ...(hypothesisPolicy === null ? {} : { hypothesisPolicy }),
        ...(harnessSuite === null ? {} : { harnessSuite }),
        assignment,
        plateau: plateauNotice(input.plateau ?? null),
        trustedNovelty: {
            parentCandidates: trustedNoveltyParents,
            archiveNicheCounts: {
                content: asArray(archive.noveltyNiches?.content).length,
                structural:
                    asArray(archive.noveltyNiches?.structural).length,
                behavioral:
                    asArray(archive.noveltyNiches?.behavioral).length,
            },
            annotationAuthority: "untrusted_explanatory_only",
        },
        ...(allPredictionFindings.length === 0
            ? {}
            : {
                codeDerivedFindings: {
                    authority: "replay_derived_statistical_kernel",
                    predictions: predictionFindings,
                },
            }),
        priorWork: {
            incumbent,
            elites,
            nearMisses,
            failures,
            lessons,
            deltas,
            duplicateHashes,
        },
    };

    const omissions = enforceByteCap(body, byteCap, initialOmissions);
    const context = immutableCanonical({ ...body, omissions });
    const serializedBytes = byteLength(context);
    if (serializedBytes > byteCap) {
        throw new RuntimeConfigError("Prompt context exceeds the frozen byte cap", {
            serializedBytes,
            byteCap,
        });
    }
    const hash = hashCanonical(context, PROMPT_CONTEXT_HASH_ALGORITHM);
    return { context, hash };
}

export function assertPromptContractCoreFits(
    contract,
    { byteCap = DEFAULT_PROMPT_CONTEXT_BYTE_CAP } = {},
) {
    requirePlainObject(contract, "contract");
    const normalizedCap = normalizeByteCap(byteCap);
    const workerModels = asArray(contract.workerModels)
        .filter((model) => typeof model === "string" && model.length > 0);
    const boundedCandidateIds = asArray(contract.enumerandManifest?.entries)
        .map((entry) => entry?.id)
        .filter((candidateId) => typeof candidateId === "string" && candidateId.length > 0);
    const longest = (values, fallback) => values.reduce(
        (current, value) => (value.length > current.length ? value : current),
        fallback,
    );
    const candidateId = longest(
        boundedCandidateIds,
        "candidate-r999999-s007-retry-999",
    );
    const model = longest(workerModels, "worker");
    const makeIdentifier = (prefix, index) => {
        const base = `${prefix}-${String(index).padStart(3, "0")}-`;
        return base.padEnd(128, String(index % 10));
    };
    const promptContextRefs = Array.from(
        { length: promptCap(contract, "promptContextRefs") },
        (_unused, index) => makeIdentifier("evidence", index),
    );
    const parentEvidenceIds = promptContextRefs.slice(
        0,
        promptCap(contract, "parentEvidenceIds"),
    );
    const incumbent = promptContextRefs.length === 0
        ? null
        : {
            evidenceId: promptContextRefs[0],
            outcomeClass: "accepted",
            round: Number.isSafeInteger(contract.maxRounds) ? contract.maxRounds : 1,
            slotIndex: Number.isSafeInteger(contract.candidatesPerRound)
                ? Math.max(0, contract.candidatesPerRound - 1)
                : 0,
            metrics: Object.fromEntries(asArray(contract.metrics).map((metric) => [
                metric.key,
                Number.MAX_SAFE_INTEGER,
            ])),
            annotations: {
                mechanism: "m".repeat(ANNOTATION_LIMITS.mechanismBytes),
                finding: "f".repeat(ANNOTATION_LIMITS.findingBytes),
            },
            receipt: {
                candidateArtifactHash: `sha256:${"f".repeat(64)}`,
            },
        };
    const { context } = buildPromptContext({
        contract,
        archive: incumbent === null
            ? {}
            : { incumbent, accepted: [incumbent] },
        slot: {
            operator: "adversarial",
            round: Number.isSafeInteger(contract.maxRounds) ? contract.maxRounds : 1,
            slotIndex: Number.isSafeInteger(contract.candidatesPerRound)
                ? Math.max(0, contract.candidatesPerRound - 1)
                : 0,
            candidateId,
            model,
            seed: 0x7fffffff,
            parentEvidenceIds,
            promptContextRefs,
            ...(boundedCandidateIds.length === 0 ? {} : { boundedCandidateId: candidateId }),
        },
        plateau: {
            phase: "mandatory_escape",
            escapeRoundsCompleted: 0,
            escapeRoundsRequired:
                contract.searchPolicy?.mandatoryEscapeRounds ?? 0,
            escapeComplete: false,
            triggerRound: contract.searchPolicy?.minRoundsBeforePlateau ?? null,
        },
        byteCap: normalizedCap,
    });
    const coreBytes = byteLength(context);
    if (coreBytes > normalizedCap) {
        throw new RuntimeConfigError(
            "The frozen contract core and required prompt metadata exceed the runtime prompt-context byte cap",
            { coreBytes, byteCap: normalizedCap },
        );
    }
    return Object.freeze({ coreBytes, byteCap: normalizedCap });
}

export const createPromptContext = buildPromptContext;
