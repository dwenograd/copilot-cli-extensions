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
    canonicalJson,
    hashCanonical,
    immutableCanonical,
    metricImprovement,
} from "../domain/index.mjs";
import { RuntimeConfigError } from "./errors.mjs";
import { requirePlainObject } from "./utils.mjs";

export const PROMPT_CONTEXT_VERSION = "crucible-runtime-prompt-context-v1";
export const PROMPT_CONTEXT_HASH_ALGORITHM = "sha256:crucible-runtime-prompt-context-v1";

export const DEFAULT_PROMPT_CONTEXT_BYTE_CAP = 16 * 1024;
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

function integerOrNull(value) {
    return Number.isSafeInteger(value) ? value : null;
}

function byteLength(value) {
    return Buffer.byteLength(canonicalJson(value), "utf8");
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
    return {
        evidenceId: stringOrNull(evidence.evidenceId),
        outcomeClass: stringOrNull(evidence.outcomeClass),
        round: integerOrNull(evidence.round),
        slotIndex: integerOrNull(evidence.slotIndex),
        metrics: selectMetricValues(evidence.metrics, keys),
        mechanism: stringOrNull(annotations.mechanism),
        finding: stringOrNull(annotations.finding),
        artifactHash: stringOrNull(evidence.receipt?.candidateArtifactHash),
    };
}

function summarizeList(list, keys) {
    return asArray(list)
        .map((evidence) => summarizeCandidate(evidence, keys))
        .filter((summary) => summary !== null && summary.evidenceId !== null);
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
            const finding = stringOrNull(group?.finding);
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
        notice = "The search remains on a plateau after the escape budget. A fundamentally novel "
            + "mechanism is required; incremental refinement has been exhausted.";
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
    const assignment = {
        operator: stringOrNull(slot.operator) ?? "fresh",
        round,
        slotIndex,
        candidateId: stringOrNull(slot.candidateId),
        model: stringOrNull(slot.model),
        seed: integerOrNull(slot.seed),
        parentEvidenceIds: asArray(slot.parentEvidenceIds).filter(
            (id) => typeof id === "string" && id.length > 0,
        ),
        promptContextRefs: asArray(slot.promptContextRefs).filter(
            (id) => typeof id === "string" && id.length > 0,
        ),
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
            const entries = body.priorWork[bucket];
            if (Array.isArray(entries) && entries.length > 0) {
                entries.pop();
                omissions[bucket] += 1;
                dropped = true;
                break;
            }
        }
        if (!dropped) {
            // Only irreducible trusted core remains; stop rather than loop.
            break;
        }
    }
    return omissions;
}

export function buildPromptContext(input = {}) {
    requirePlainObject(input, "prompt-context input");
    const contract = requirePlainObject(input.contract ?? {}, "contract");
    const archive = requirePlainObject(input.archive ?? {}, "archive");
    const byteCap = normalizeByteCap(input.byteCap);

    const objective = stringOrNull(contract.objective);
    if (objective === null) {
        throw new RuntimeConfigError("contract.objective must be a non-empty string");
    }
    const metrics = asArray(contract.metrics)
        .filter((metric) => metric && typeof metric.key === "string")
        .map((metric) => ({
            key: metric.key,
            direction: metric.direction === "min" ? "min" : "max",
            epsilon: finiteNumberOrNull(metric.epsilon) ?? 0,
        }));
    const keys = metricKeys(metrics);

    const assignment = normalizeAssignment(input.slot);
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
    const visibleInvalidMetrics = visibleList(archive.invalidMetrics);
    const visibleLessonGroups = visibleGroups(archive.lessonGroups);
    const elites = summarizeList(visibleAccepted, keys)
        .filter((summary) => summary.evidenceId !== incumbentEvidenceId);
    const nearMisses = summarizeList(visibleNearMisses, keys);
    const failures = [
        ...summarizeList(visibleRejected, keys),
        ...summarizeList(visibleInvalidMetrics, keys),
    ];
    const deltas = buildDeltas(metrics, incumbent, [...nearMisses, ...elites]);
    const lessons = buildLessons(visibleLessonGroups);
    const duplicateHashes = buildDuplicateHashes(visibleDuplicateIndex);
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
                + summarizeList(archive.invalidMetrics, keys).length
                - failures.length,
        ),
        lessons: Math.max(0, buildLessons(archive.lessonGroups).length - lessons.length),
        deltas: 0,
        duplicateHashes: Math.max(
            0,
            buildDuplicateHashes(archive.duplicateIndex).length - duplicateHashes.length,
        ),
    };

    const body = {
        version: PROMPT_CONTEXT_VERSION,
        objective,
        predicate: contract.acceptancePredicate ?? { kind: "harness_pass" },
        metrics,
        assignment,
        plateau: plateauNotice(input.plateau ?? null),
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
    const boundedCandidateIds = asArray(contract.boundedCandidateIds)
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
    const { context } = buildPromptContext({
        contract,
        archive: {},
        slot: {
            operator: "adversarial",
            round: Number.isSafeInteger(contract.maxRounds) ? contract.maxRounds : 1,
            slotIndex: Number.isSafeInteger(contract.candidatesPerRound)
                ? Math.max(0, contract.candidatesPerRound - 1)
                : 0,
            candidateId,
            model,
            seed: 0x7fffffff,
            parentEvidenceIds: [],
            promptContextRefs: [],
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
            "The objective, acceptance predicate, metrics, and required prompt metadata exceed the runtime prompt-context byte cap",
            { coreBytes, byteCap: normalizedCap },
        );
    }
    return Object.freeze({ coreBytes, byteCap: normalizedCap });
}

export const createPromptContext = buildPromptContext;
