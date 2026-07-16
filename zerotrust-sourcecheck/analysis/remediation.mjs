import { createHash } from "node:crypto";

import {
    ANALYSIS_SCHEMA_REVISION,
    GRAPH_EDGE_KINDS,
    GRAPH_NODE_KINDS,
    LIMITS,
    validateAuditId,
    validateIdentifier,
} from "./schemas.mjs";

export const REMEDIATION_LIMITS = Object.freeze({
    candidates: 512,
    guidance: 512,
    sourceFindingIds: 128,
    chainIds: 64,
    edgeIds: 64,
    evidence: LIMITS.evidencePerItem,
    sharedChainIds: 64,
    alternateChainIds: 64,
    blockers: 128,
});

const SHA256_RE = /^[a-f0-9]{64}$/u;
const BLOB_SHA_RE = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const REMEDIATION_ID_RE = /^ztr-baseline-[a-f0-9]{64}$/u;
const GUIDANCE_ID_RE = /^ztri-baseline-[a-f0-9]{64}$/u;
const PLAN_ID_RE = /^ztrp-baseline-[a-f0-9]{64}$/u;
const RISK_LEVELS = Object.freeze(["low", "medium", "high"]);
const RISK_CODES = Object.freeze([
    "single-purpose-edge",
    "multiple-edge-identities",
    "shared-with-other-complete-chain",
    "shared-with-other-unresolved-chain",
]);
const VERIFICATION_OUTCOMES = Object.freeze([
    "breaks-all-known-chains",
    "alternate-path-remains",
    "graph-incomplete",
]);
const VERIFICATION_CRITERIA = Object.freeze([
    "target-edges-not-traversable",
    "evidence-locations-reindexed",
    "no-alternate-activation-effect-chain",
    "full-sourcecheck-rerun-required",
]);
const GUIDANCE_CODES = Object.freeze([
    "inspect-evidence-bound-locations",
    "resolve-validation-disagreement",
    "confirm-edge-reachability",
    "complete-trusted-behavior-chain",
]);
const BLOCKER_CODES = Object.freeze([
    "canonical-finding-cap-exceeded",
    "validated-finding-without-complete-chain",
    "validated-finding-without-targetable-edge",
    "remediation-detail-cap-exceeded",
]);

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (isPlainObject(value)) {
        return `{${Object.keys(value).sort().map((key) =>
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}

function digest(prefix, value) {
    return createHash("sha256")
        .update(prefix, "utf8")
        .update("\0", "utf8")
        .update(canonicalJson(value), "utf8")
        .digest("hex");
}

function exactObject(value, required, optional, label) {
    if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain object`);
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) throw new TypeError(`${label}.${key} is not allowed`);
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
    }
}

function enumValue(value, allowed, label) {
    if (!allowed.includes(value)) {
        throw new TypeError(`${label} must be one of: ${allowed.join(", ")}`);
    }
    return value;
}

function booleanValue(value, label) {
    if (typeof value !== "boolean") throw new TypeError(`${label} must be boolean`);
    return value;
}

function nullableBoolean(value, label) {
    if (value !== null && typeof value !== "boolean") {
        throw new TypeError(`${label} must be boolean or null`);
    }
    return value;
}

function hashValue(value, label) {
    if (typeof value !== "string" || !SHA256_RE.test(value)) {
        throw new TypeError(`${label} must be a lowercase SHA-256`);
    }
    return value;
}

function uniqueIdentifiers(value, label, maxItems) {
    if (!Array.isArray(value) || value.length > maxItems) {
        throw new TypeError(`${label} must contain at most ${maxItems} entries`);
    }
    const result = value.map((entry, index) =>
        validateIdentifier(entry, `${label}[${index}]`));
    if (new Set(result).size !== result.length) {
        throw new TypeError(`${label} must not contain duplicates`);
    }
    return Object.freeze([...result].sort());
}

function uniqueEnums(value, allowed, label, maxItems) {
    if (!Array.isArray(value) || value.length > maxItems) {
        throw new TypeError(`${label} must contain at most ${maxItems} entries`);
    }
    const result = value.map((entry, index) =>
        enumValue(entry, allowed, `${label}[${index}]`));
    if (new Set(result).size !== result.length) {
        throw new TypeError(`${label} must not contain duplicates`);
    }
    return Object.freeze([...result].sort());
}

function evidenceKey(value) {
    return canonicalJson(value);
}

function normalizeEvidenceLocation(value, label) {
    exactObject(value, [
        "path",
        "startLine",
        "endLine",
        "blobSha",
        "excerptHash",
    ], ["producer", "coverageScope"], label);
    if (typeof value.path !== "string"
        || value.path.length < 1
        || value.path.length > LIMITS.path
        || value.path.includes("\0")) {
        throw new TypeError(`${label}.path is invalid`);
    }
    if (!Number.isSafeInteger(value.startLine)
        || !Number.isSafeInteger(value.endLine)
        || value.startLine < 1
        || value.endLine < value.startLine
        || value.endLine > LIMITS.line) {
        throw new TypeError(`${label} line range is invalid`);
    }
    if (typeof value.blobSha !== "string" || !BLOB_SHA_RE.test(value.blobSha)) {
        throw new TypeError(`${label}.blobSha is invalid`);
    }
    if (typeof value.excerptHash !== "string" || !SHA256_RE.test(value.excerptHash)) {
        throw new TypeError(`${label}.excerptHash is invalid`);
    }
    return Object.freeze({
        path: value.path,
        startLine: value.startLine,
        endLine: value.endLine,
        blobSha: value.blobSha,
        excerptHash: value.excerptHash,
    });
}

function uniqueEvidence(value, label) {
    if (!Array.isArray(value) || value.length > REMEDIATION_LIMITS.evidence) {
        throw new TypeError(
            `${label} must contain at most ${REMEDIATION_LIMITS.evidence} entries`,
        );
    }
    const byIdentity = new Map();
    for (const [index, entry] of value.entries()) {
        const evidence = normalizeEvidenceLocation(entry, `${label}[${index}]`);
        const key = evidenceKey(evidence);
        if (byIdentity.has(key)) throw new TypeError(`${label} must not contain duplicates`);
        byIdentity.set(key, evidence);
    }
    return Object.freeze([...byIdentity.values()].sort((left, right) =>
        evidenceKey(left).localeCompare(evidenceKey(right))));
}

function boundedEntries(value, label, maxItems) {
    if (!Array.isArray(value) || value.length > maxItems) {
        throw new TypeError(`${label} must contain at most ${maxItems} entries`);
    }
    return value;
}

function unique(values) {
    return [...new Set(values)].sort();
}

function flattenChainEdgeIds(chain) {
    return unique((chain?.links || []).flatMap((link) => link.edgeIds || []));
}

function flattenChainNodeIds(chain) {
    return unique((chain?.steps || []).flatMap((step) => step.nodeIds || []));
}

function chainContainsTarget(chain, targetEdgeIds) {
    const edges = new Set(flattenChainEdgeIds(chain));
    return targetEdgeIds.some((edgeId) => edges.has(edgeId));
}

function finalEffectNodeIds(chain) {
    const steps = chain?.steps || [];
    for (let index = steps.length - 1; index >= 0; index -= 1) {
        if (["sink", "persistence", "propagation"].includes(steps[index].kind)) {
            return unique(steps[index].nodeIds || []);
        }
    }
    return [];
}

function sharesEffectIdentity(left, right) {
    const rightIds = new Set(finalEffectNodeIds(right));
    return finalEffectNodeIds(left).some((id) => rightIds.has(id));
}

function graphIsIncomplete(traceSnapshot, canonicalFinding) {
    return traceSnapshot.coverageComplete !== true
        || Object.values(traceSnapshot.truncation || {}).some(Boolean)
        || Object.values(canonicalFinding.truncation || {}).some(Boolean);
}

function evidenceForTarget(link, chain, canonicalFinding) {
    const entries = [
        ...(link.evidence || []),
        ...(chain.evidence || []),
        ...(canonicalFinding.evidence || []),
    ];
    const byIdentity = new Map();
    for (const entry of entries) {
        const normalized = normalizeEvidenceLocation(entry, "targetEvidence");
        byIdentity.set(evidenceKey(normalized), normalized);
    }
    return [...byIdentity.values()]
        .sort((left, right) => evidenceKey(left).localeCompare(evidenceKey(right)))
        .slice(0, REMEDIATION_LIMITS.evidence);
}

function normalizeCanonicalFinding(finding, index) {
    const label = `decisionSnapshot.canonicalFindings[${index}]`;
    if (!isPlainObject(finding)) throw new TypeError(`${label} must be a plain object`);
    const canonicalId = validateIdentifier(finding.canonicalId, `${label}.canonicalId`);
    const stateClass = enumValue(
        finding.stateClass,
        ["validated", "refuted", "unresolved"],
        `${label}.stateClass`,
    );
    const aliases = boundedEntries(
        finding.aliases || [],
        `${label}.aliases`,
        REMEDIATION_LIMITS.sourceFindingIds,
    );
    const sourceFindingIds = uniqueIdentifiers(
        aliases.map((alias) => alias?.findingId),
        `${label}.aliases.findingIds`,
        REMEDIATION_LIMITS.sourceFindingIds,
    );
    const chainIds = uniqueIdentifiers(
        finding.chainIds || [],
        `${label}.chainIds`,
        REMEDIATION_LIMITS.chainIds,
    );
    const validatedChainIds = uniqueIdentifiers(
        finding.validatedChainIds || [],
        `${label}.validatedChainIds`,
        REMEDIATION_LIMITS.chainIds,
    );
    if (validatedChainIds.some((id) => !chainIds.includes(id))) {
        throw new TypeError(`${label}.validatedChainIds must be a subset of chainIds`);
    }
    return Object.freeze({
        ...finding,
        canonicalId,
        stateClass,
        sourceFindingIds,
        chainIds,
        validatedChainIds,
        trustedValidatedChain:
            finding.scores?.trustedValidatedChain === true,
    });
}

function chooseTargetLink(primaryChain, relevantChains, allChains) {
    const relevantIds = new Set(relevantChains.map((chain) => chain.id));
    const options = (primaryChain.links || []).map((link, index) => {
        const edgeIds = unique(link.edgeIds || []);
        if (edgeIds.length === 0 || edgeIds.length > REMEDIATION_LIMITS.edgeIds) return null;
        const remaining = relevantChains.filter((chain) =>
            !chainContainsTarget(chain, edgeIds));
        const shared = allChains.filter((chain) =>
            !relevantIds.has(chain.id) && chainContainsTarget(chain, edgeIds));
        return {
            link,
            index,
            edgeIds,
            remaining,
            shared,
        };
    }).filter(Boolean);
    options.sort((left, right) =>
        left.remaining.length - right.remaining.length
        || left.shared.filter((chain) => chain.status === "complete").length
            - right.shared.filter((chain) => chain.status === "complete").length
        || left.edgeIds.length - right.edgeIds.length
        || right.index - left.index
        || left.edgeIds.join("\0").localeCompare(right.edgeIds.join("\0")));
    return options[0] || null;
}

function riskForTarget(option) {
    const sharedComplete = option.shared
        .filter((chain) => chain.status === "complete")
        .map((chain) => chain.id);
    const sharedUnresolved = option.shared
        .filter((chain) => chain.status !== "complete")
        .map((chain) => chain.id);
    const riskCodes = [];
    if (sharedComplete.length > 0) riskCodes.push("shared-with-other-complete-chain");
    if (sharedUnresolved.length > 0) riskCodes.push("shared-with-other-unresolved-chain");
    if (option.edgeIds.length > 1) riskCodes.push("multiple-edge-identities");
    if (riskCodes.length === 0) riskCodes.push("single-purpose-edge");
    return {
        level: sharedComplete.length > 0
            ? "high": sharedUnresolved.length > 0 || option.edgeIds.length > 1
                ? "medium": "low",
        riskCodes: unique(riskCodes),
        sharedChainIds: unique([...sharedComplete, ...sharedUnresolved])
            .slice(0, REMEDIATION_LIMITS.sharedChainIds),
    };
}

function createCandidate({
    auditId,
    canonicalFinding,
    traceSnapshot,
    chainsById,
}) {
    const validatedChains = canonicalFinding.validatedChainIds
        .map((id) => chainsById.get(id))
        .filter((chain) => chain?.status === "complete")
        .sort((left, right) =>
            (left.links?.length || 0) - (right.links?.length || 0)
            || left.id.localeCompare(right.id));
    if (!canonicalFinding.trustedValidatedChain || validatedChains.length === 0) {
        return {
            candidate: null,
            blocker: {
                code: "validated-finding-without-complete-chain",
                canonicalFindingId: canonicalFinding.canonicalId,
            },
        };
    }

    const primaryChain = validatedChains[0];
    const allChains = traceSnapshot.chains || [];
    const relevantIds = new Set(canonicalFinding.chainIds);
    const relevantChains = allChains.filter((chain) =>
        chain.status === "complete"
        && (relevantIds.has(chain.id) || sharesEffectIdentity(chain, primaryChain)));
    const target = chooseTargetLink(primaryChain, relevantChains, allChains);
    if (!target) {
        return {
            candidate: null,
            blocker: {
                code: "validated-finding-without-targetable-edge",
                canonicalFindingId: canonicalFinding.canonicalId,
            },
        };
    }

    const targetEvidence = evidenceForTarget(target.link, primaryChain, canonicalFinding);
    if (targetEvidence.length === 0) {
        return {
            candidate: null,
            blocker: {
                code: "validated-finding-without-targetable-edge",
                canonicalFindingId: canonicalFinding.canonicalId,
            },
        };
    }
    const incomplete = graphIsIncomplete(traceSnapshot, canonicalFinding);
    const alternateChainIds = unique(target.remaining.map((chain) => chain.id))
        .slice(0, REMEDIATION_LIMITS.alternateChainIds);
    const outcome = incomplete
        ? "graph-incomplete": alternateChainIds.length > 0
            ? "alternate-path-remains": "breaks-all-known-chains";
    const risk = riskForTarget(target);
    const expectedBehaviorRemoved = {
        chainIds: unique(relevantChains
            .filter((chain) => chainContainsTarget(chain, target.edgeIds))
            .map((chain) => chain.id))
            .slice(0, REMEDIATION_LIMITS.chainIds),
        linkKind: target.link.kind,
        fromKind: primaryChain.steps?.[target.index]?.kind,
        toKind: primaryChain.steps?.[target.index + 1]?.kind,
        effectKinds: unique(primaryChain.effectKinds || []),
        behaviorIntentHash: digest(
            "zerotrust-remediation-behavior-intent-baseline",
            canonicalFinding.signature || {
                canonicalFindingId: canonicalFinding.canonicalId,
            },
        ),
    };
    const targetMetadata = {
        strategy: "remove-or-guard-edge",
        chainId: primaryChain.id,
        edgeIds: target.edgeIds,
        linkKind: target.link.kind,
        evidence: targetEvidence,
        locationHash: digest("zerotrust-remediation-locations-baseline", targetEvidence),
    };
    const staticVerification = {
        graphCoverage: incomplete ? "incomplete": "complete",
        outcome,
        maliciousChainRemains: incomplete ? null: alternateChainIds.length > 0,
        fixClaimAllowed: outcome === "breaks-all-known-chains",
        alternateChainIds,
        criteriaCodes: unique(VERIFICATION_CRITERIA),
    };
    const legitimateFunctionalityRisk = {
        level: risk.level,
        riskCodes: risk.riskCodes,
        sharedChainIds: risk.sharedChainIds,
    };
    const candidateWithoutIdentity = {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId,
        canonicalFindingId: canonicalFinding.canonicalId,
        sourceFindingIds: canonicalFinding.sourceFindingIds,
        target: targetMetadata,
        expectedBehaviorRemoved,
        legitimateFunctionalityRisk,
        staticVerification,
    };
    const intentHash = digest(
        "zerotrust-remediation-intent-baseline",
        {
            canonicalFindingId: candidateWithoutIdentity.canonicalFindingId,
            target: targetMetadata,
            expectedBehaviorRemoved,
            staticVerification: {
                outcome,
                criteriaCodes: staticVerification.criteriaCodes,
            },
        },
    );
    const id = `ztr-baseline-${digest("zerotrust-remediation-candidate-baseline", {
        ...candidateWithoutIdentity,
        intentHash,
    })}`;
    return {
        candidate: Object.freeze(structuredClone({
            ...candidateWithoutIdentity,
            id,
            intentHash,
        })),
        blocker: null,
    };
}

function createGuidance(auditId, canonicalFinding) {
    const evidence = uniqueEvidence(
        (canonicalFinding.evidence || []).slice(0, REMEDIATION_LIMITS.evidence),
        "investigationGuidance.evidence",
    );
    const guidanceWithoutIdentity = {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId,
        canonicalFindingId: canonicalFinding.canonicalId,
        sourceFindingIds: canonicalFinding.sourceFindingIds,
        evidence,
        guidanceCodes: unique(GUIDANCE_CODES),
        confidentPatchAllowed: false,
        locationHash: digest("zerotrust-remediation-guidance-locations-baseline", evidence),
    };
    return Object.freeze({
        ...guidanceWithoutIdentity,
        id: `ztri-baseline-${digest(
            "zerotrust-remediation-investigation-guidance-baseline",
            guidanceWithoutIdentity,
        )}`,
    });
}

export function generateRemediationPlan({
    auditId,
    decisionSnapshot,
    traceSnapshot,
} = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    if (!decisionSnapshot || decisionSnapshot.auditId !== normalizedAuditId) {
        throw new Error("remediation decision snapshot auditId mismatch");
    }
    if (!traceSnapshot || traceSnapshot.auditId !== normalizedAuditId) {
        throw new Error("remediation trace snapshot auditId mismatch");
    }

    const rawCanonicalFindings = decisionSnapshot.canonicalFindings || [];
    const canonicalFindings = rawCanonicalFindings
        .slice(0, REMEDIATION_LIMITS.candidates)
        .map(normalizeCanonicalFinding);
    const chainsById = new Map((traceSnapshot.chains || []).map((chain) => [
        validateIdentifier(chain.id, "traceSnapshot.chains.id"),
        chain,
    ]));
    const candidates = [];
    const investigationGuidance = [];
    const blockers = [];
    if (rawCanonicalFindings.length > REMEDIATION_LIMITS.candidates) {
        blockers.push({
            code: "canonical-finding-cap-exceeded",
            cap: REMEDIATION_LIMITS.candidates,
            observed: rawCanonicalFindings.length,
        });
    }
    for (const finding of canonicalFindings) {
        if (finding.stateClass === "refuted") continue;
        if (finding.stateClass === "unresolved") {
            if (investigationGuidance.length < REMEDIATION_LIMITS.guidance) {
                investigationGuidance.push(createGuidance(normalizedAuditId, finding));
            } else {
                blockers.push({
                    code: "remediation-detail-cap-exceeded",
                    cap: REMEDIATION_LIMITS.guidance,
                });
            }
            continue;
        }
        const result = createCandidate({
            auditId: normalizedAuditId,
            canonicalFinding: finding,
            traceSnapshot,
            chainsById,
        });
        if (result.candidate) candidates.push(result.candidate);
        if (result.blocker) blockers.push(result.blocker);
    }

    const truncation = {
        canonicalFindings: rawCanonicalFindings.length > REMEDIATION_LIMITS.candidates,
        candidates: candidates.length > REMEDIATION_LIMITS.candidates,
        guidance: investigationGuidance.length > REMEDIATION_LIMITS.guidance,
        blockers: blockers.length > REMEDIATION_LIMITS.blockers,
    };
    const boundedCandidates = candidates.slice(0, REMEDIATION_LIMITS.candidates);
    const boundedGuidance = investigationGuidance.slice(0, REMEDIATION_LIMITS.guidance);
    const boundedBlockers = blockers.slice(0, REMEDIATION_LIMITS.blockers);
    const inputFingerprint = digest("zerotrust-remediation-input-baseline", {
        auditId: normalizedAuditId,
        decisionId: decisionSnapshot.decisionId || null,
        traceInputFingerprint: traceSnapshot.inputFingerprint || null,
        canonicalFindings: canonicalFindings.map((finding) => ({
            canonicalId: finding.canonicalId,
            stateClass: finding.stateClass,
            sourceFindingIds: finding.sourceFindingIds,
            chainIds: finding.chainIds,
            validatedChainIds: finding.validatedChainIds,
            trustedValidatedChain: finding.trustedValidatedChain,
        })),
        traceCoverageComplete: traceSnapshot.coverageComplete === true,
        traceTruncation: traceSnapshot.truncation || {},
    });
    const planWithoutId = {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: normalizedAuditId,
        inputFingerprint,
        coverageComplete: traceSnapshot.coverageComplete === true
            && !Object.values(traceSnapshot.truncation || {}).some(Boolean)
            && !Object.values(truncation).some(Boolean)
            && boundedBlockers.length === 0,
        candidates: boundedCandidates,
        investigationGuidance: boundedGuidance,
        truncation,
        blockers: boundedBlockers,
    };
    return validateRemediationPlan({
        ...planWithoutId,
        id: `ztrp-baseline-${digest("zerotrust-remediation-plan-baseline", planWithoutId)}`,
    });
}

export function validateRemediationCandidate(value, label = "remediationCandidate") {
    exactObject(value, [
        "schemaVersion",
        "auditId",
        "id",
        "canonicalFindingId",
        "sourceFindingIds",
        "target",
        "expectedBehaviorRemoved",
        "legitimateFunctionalityRisk",
        "staticVerification",
        "intentHash",
    ], [], label);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_REVISION) {
        throw new TypeError(`${label}.schemaVersion must equal ${ANALYSIS_SCHEMA_REVISION}`);
    }
    exactObject(value.target, [
        "strategy",
        "chainId",
        "edgeIds",
        "linkKind",
        "evidence",
        "locationHash",
    ], [], `${label}.target`);
    if (value.target.strategy !== "remove-or-guard-edge") {
        throw new TypeError(`${label}.target.strategy is invalid`);
    }
    exactObject(value.expectedBehaviorRemoved, [
        "chainIds",
        "linkKind",
        "fromKind",
        "toKind",
        "effectKinds",
        "behaviorIntentHash",
    ], [], `${label}.expectedBehaviorRemoved`);
    exactObject(value.legitimateFunctionalityRisk, [
        "level",
        "riskCodes",
        "sharedChainIds",
    ], [], `${label}.legitimateFunctionalityRisk`);
    exactObject(value.staticVerification, [
        "graphCoverage",
        "outcome",
        "maliciousChainRemains",
        "fixClaimAllowed",
        "alternateChainIds",
        "criteriaCodes",
    ], [], `${label}.staticVerification`);

    const normalized = {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: validateAuditId(value.auditId, `${label}.auditId`),
        id: typeof value.id === "string" && REMEDIATION_ID_RE.test(value.id)
            ? value.id: (() => { throw new TypeError(`${label}.id is invalid`); }),
        canonicalFindingId: validateIdentifier(
            value.canonicalFindingId,
            `${label}.canonicalFindingId`,
        ),
        sourceFindingIds: uniqueIdentifiers(
            value.sourceFindingIds,
            `${label}.sourceFindingIds`,
            REMEDIATION_LIMITS.sourceFindingIds,
        ),
        target: {
            strategy: "remove-or-guard-edge",
            chainId: validateIdentifier(value.target.chainId, `${label}.target.chainId`),
            edgeIds: uniqueIdentifiers(
                value.target.edgeIds,
                `${label}.target.edgeIds`,
                REMEDIATION_LIMITS.edgeIds,
            ),
            linkKind: enumValue(
                value.target.linkKind,
                GRAPH_EDGE_KINDS,
                `${label}.target.linkKind`,
            ),
            evidence: uniqueEvidence(value.target.evidence, `${label}.target.evidence`),
            locationHash: hashValue(
                value.target.locationHash,
                `${label}.target.locationHash`,
            ),
        },
        expectedBehaviorRemoved: {
            chainIds: uniqueIdentifiers(
                value.expectedBehaviorRemoved.chainIds,
                `${label}.expectedBehaviorRemoved.chainIds`,
                REMEDIATION_LIMITS.chainIds,
            ),
            linkKind: enumValue(
                value.expectedBehaviorRemoved.linkKind,
                GRAPH_EDGE_KINDS,
                `${label}.expectedBehaviorRemoved.linkKind`,
            ),
            fromKind: enumValue(
                value.expectedBehaviorRemoved.fromKind,
                GRAPH_NODE_KINDS,
                `${label}.expectedBehaviorRemoved.fromKind`,
            ),
            toKind: enumValue(
                value.expectedBehaviorRemoved.toKind,
                GRAPH_NODE_KINDS,
                `${label}.expectedBehaviorRemoved.toKind`,
            ),
            effectKinds: uniqueEnums(
                value.expectedBehaviorRemoved.effectKinds,
                ["sink", "persistence", "propagation"],
                `${label}.expectedBehaviorRemoved.effectKinds`,
                3,
            ),
            behaviorIntentHash: hashValue(
                value.expectedBehaviorRemoved.behaviorIntentHash,
                `${label}.expectedBehaviorRemoved.behaviorIntentHash`,
            ),
        },
        legitimateFunctionalityRisk: {
            level: enumValue(
                value.legitimateFunctionalityRisk.level,
                RISK_LEVELS,
                `${label}.legitimateFunctionalityRisk.level`,
            ),
            riskCodes: uniqueEnums(
                value.legitimateFunctionalityRisk.riskCodes,
                RISK_CODES,
                `${label}.legitimateFunctionalityRisk.riskCodes`,
                RISK_CODES.length,
            ),
            sharedChainIds: uniqueIdentifiers(
                value.legitimateFunctionalityRisk.sharedChainIds,
                `${label}.legitimateFunctionalityRisk.sharedChainIds`,
                REMEDIATION_LIMITS.sharedChainIds,
            ),
        },
        staticVerification: {
            graphCoverage: enumValue(
                value.staticVerification.graphCoverage,
                ["complete", "incomplete"],
                `${label}.staticVerification.graphCoverage`,
            ),
            outcome: enumValue(
                value.staticVerification.outcome,
                VERIFICATION_OUTCOMES,
                `${label}.staticVerification.outcome`,
            ),
            maliciousChainRemains: nullableBoolean(
                value.staticVerification.maliciousChainRemains,
                `${label}.staticVerification.maliciousChainRemains`,
            ),
            fixClaimAllowed: booleanValue(
                value.staticVerification.fixClaimAllowed,
                `${label}.staticVerification.fixClaimAllowed`,
            ),
            alternateChainIds: uniqueIdentifiers(
                value.staticVerification.alternateChainIds,
                `${label}.staticVerification.alternateChainIds`,
                REMEDIATION_LIMITS.alternateChainIds,
            ),
            criteriaCodes: uniqueEnums(
                value.staticVerification.criteriaCodes,
                VERIFICATION_CRITERIA,
                `${label}.staticVerification.criteriaCodes`,
                VERIFICATION_CRITERIA.length,
            ),
        },
        intentHash: hashValue(value.intentHash, `${label}.intentHash`),
    };
    if (normalized.sourceFindingIds.length === 0) {
        throw new TypeError(`${label}.sourceFindingIds must not be empty`);
    }
    if (normalized.target.edgeIds.length === 0 || normalized.target.evidence.length === 0) {
        throw new TypeError(`${label}.target must contain edge IDs and evidence locations`);
    }
    if (normalized.expectedBehaviorRemoved.chainIds.length === 0
        || normalized.expectedBehaviorRemoved.effectKinds.length === 0) {
        throw new TypeError(`${label}.expectedBehaviorRemoved must identify chains and effects`);
    }
    if (!normalized.expectedBehaviorRemoved.chainIds.includes(normalized.target.chainId)
        || normalized.expectedBehaviorRemoved.linkKind !== normalized.target.linkKind) {
        throw new TypeError(`${label}.target does not match expected behavior removal intent`);
    }
    if (normalized.legitimateFunctionalityRisk.riskCodes.length === 0) {
        throw new TypeError(`${label}.legitimateFunctionalityRisk must identify risk`);
    }
    if (canonicalJson(normalized.staticVerification.criteriaCodes)
        !== canonicalJson(unique(VERIFICATION_CRITERIA))) {
        throw new TypeError(`${label}.staticVerification criteria are incomplete`);
    }
    const expectedLocationHash = digest(
        "zerotrust-remediation-locations-baseline",
        normalized.target.evidence,
    );
    if (normalized.target.locationHash !== expectedLocationHash) {
        throw new TypeError(`${label}.target.locationHash does not match evidence locations`);
    }
    if (normalized.staticVerification.graphCoverage === "incomplete") {
        if (normalized.staticVerification.outcome !== "graph-incomplete"
            || normalized.staticVerification.maliciousChainRemains !== null
            || normalized.staticVerification.fixClaimAllowed) {
            throw new TypeError(`${label}.staticVerification overclaims an incomplete graph`);
        }
    } else if (normalized.staticVerification.outcome === "graph-incomplete") {
        throw new TypeError(`${label}.staticVerification graph completeness is inconsistent`);
    }
    if (normalized.staticVerification.outcome === "alternate-path-remains") {
        if (normalized.staticVerification.alternateChainIds.length === 0
            || normalized.staticVerification.maliciousChainRemains !== true
            || normalized.staticVerification.fixClaimAllowed) {
            throw new TypeError(`${label}.staticVerification must preserve alternate paths`);
        }
    }
    if (normalized.staticVerification.outcome === "breaks-all-known-chains") {
        if (normalized.staticVerification.alternateChainIds.length !== 0
            || normalized.staticVerification.maliciousChainRemains !== false
            || !normalized.staticVerification.fixClaimAllowed) {
            throw new TypeError(`${label}.staticVerification fixed claim is inconsistent`);
        }
    }
    const expectedIntentHash = digest("zerotrust-remediation-intent-baseline", {
        canonicalFindingId: normalized.canonicalFindingId,
        target: normalized.target,
        expectedBehaviorRemoved: normalized.expectedBehaviorRemoved,
        staticVerification: {
            outcome: normalized.staticVerification.outcome,
            criteriaCodes: normalized.staticVerification.criteriaCodes,
        },
    });
    if (normalized.intentHash !== expectedIntentHash) {
        throw new TypeError(`${label}.intentHash does not match candidate intent`);
    }
    const expectedId = `ztr-baseline-${digest("zerotrust-remediation-candidate-baseline", {
        schemaVersion: normalized.schemaVersion,
        auditId: normalized.auditId,
        canonicalFindingId: normalized.canonicalFindingId,
        sourceFindingIds: normalized.sourceFindingIds,
        target: normalized.target,
        expectedBehaviorRemoved: normalized.expectedBehaviorRemoved,
        legitimateFunctionalityRisk: normalized.legitimateFunctionalityRisk,
        staticVerification: normalized.staticVerification,
        intentHash: normalized.intentHash,
    })}`;
    if (normalized.id !== expectedId) {
        throw new TypeError(`${label}.id does not match candidate identity`);
    }
    return Object.freeze(structuredClone(normalized));
}

export function validateInvestigationGuidance(value, label = "investigationGuidance") {
    exactObject(value, [
        "schemaVersion",
        "auditId",
        "id",
        "canonicalFindingId",
        "sourceFindingIds",
        "evidence",
        "guidanceCodes",
        "confidentPatchAllowed",
        "locationHash",
    ], [], label);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_REVISION) {
        throw new TypeError(`${label}.schemaVersion must equal ${ANALYSIS_SCHEMA_REVISION}`);
    }
    const normalized = {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: validateAuditId(value.auditId, `${label}.auditId`),
        id: typeof value.id === "string" && GUIDANCE_ID_RE.test(value.id)
            ? value.id: (() => { throw new TypeError(`${label}.id is invalid`); }),
        canonicalFindingId: validateIdentifier(
            value.canonicalFindingId,
            `${label}.canonicalFindingId`,
        ),
        sourceFindingIds: uniqueIdentifiers(
            value.sourceFindingIds,
            `${label}.sourceFindingIds`,
            REMEDIATION_LIMITS.sourceFindingIds,
        ),
        evidence: uniqueEvidence(value.evidence, `${label}.evidence`),
        guidanceCodes: uniqueEnums(
            value.guidanceCodes,
            GUIDANCE_CODES,
            `${label}.guidanceCodes`,
            GUIDANCE_CODES.length,
        ),
        confidentPatchAllowed: booleanValue(
            value.confidentPatchAllowed,
            `${label}.confidentPatchAllowed`,
        ),
        locationHash: hashValue(value.locationHash, `${label}.locationHash`),
    };
    if (normalized.sourceFindingIds.length === 0 || normalized.confidentPatchAllowed) {
        throw new TypeError(`${label} cannot authorize a confident patch`);
    }
    if (normalized.evidence.length === 0 || normalized.guidanceCodes.length === 0) {
        throw new TypeError(`${label} must contain evidence locations and guidance criteria`);
    }
    if (normalized.locationHash !== digest(
        "zerotrust-remediation-guidance-locations-baseline",
        normalized.evidence,
    )) {
        throw new TypeError(`${label}.locationHash does not match evidence locations`);
    }
    const expectedId = `ztri-baseline-${digest(
        "zerotrust-remediation-investigation-guidance-baseline",
        {
            schemaVersion: normalized.schemaVersion,
            auditId: normalized.auditId,
            canonicalFindingId: normalized.canonicalFindingId,
            sourceFindingIds: normalized.sourceFindingIds,
            evidence: normalized.evidence,
            guidanceCodes: normalized.guidanceCodes,
            confidentPatchAllowed: normalized.confidentPatchAllowed,
            locationHash: normalized.locationHash,
        },
    )}`;
    if (normalized.id !== expectedId) {
        throw new TypeError(`${label}.id does not match guidance identity`);
    }
    return Object.freeze(structuredClone(normalized));
}

export function validateRemediationPlan(value, label = "remediationPlan") {
    exactObject(value, [
        "schemaVersion",
        "auditId",
        "id",
        "inputFingerprint",
        "coverageComplete",
        "candidates",
        "investigationGuidance",
        "truncation",
        "blockers",
    ], [], label);
    if (value.schemaVersion !== ANALYSIS_SCHEMA_REVISION) {
        throw new TypeError(`${label}.schemaVersion must equal ${ANALYSIS_SCHEMA_REVISION}`);
    }
    const auditId = validateAuditId(value.auditId, `${label}.auditId`);
    const candidates = boundedEntries(
        value.candidates,
        `${label}.candidates`,
        REMEDIATION_LIMITS.candidates,
    ).map((entry, index) =>
        validateRemediationCandidate(entry, `${label}.candidates[${index}]`));
    const guidance = boundedEntries(
        value.investigationGuidance,
        `${label}.investigationGuidance`,
        REMEDIATION_LIMITS.guidance,
    ).map((entry, index) =>
        validateInvestigationGuidance(entry, `${label}.investigationGuidance[${index}]`));
    const candidateIds = new Set();
    const canonicalIds = new Set();
    const sourceFindingIds = new Set();
    for (const candidate of candidates) {
        if (candidate.auditId !== auditId) throw new TypeError(`${label} candidate auditId mismatch`);
        if (candidateIds.has(candidate.id)) throw new TypeError(`${label} has duplicate candidate id`);
        if (canonicalIds.has(candidate.canonicalFindingId)) {
            throw new TypeError(`${label} has multiple candidates for one canonical finding`);
        }
        candidateIds.add(candidate.id);
        canonicalIds.add(candidate.canonicalFindingId);
        for (const findingId of candidate.sourceFindingIds) {
            if (sourceFindingIds.has(findingId)) {
                throw new TypeError(`${label} has multiple candidates for one source finding`);
            }
            sourceFindingIds.add(findingId);
        }
    }
    for (const entry of guidance) {
        if (entry.auditId !== auditId) throw new TypeError(`${label} guidance auditId mismatch`);
        if (canonicalIds.has(entry.canonicalFindingId)) {
            throw new TypeError(`${label} cannot patch and investigate the same finding`);
        }
        canonicalIds.add(entry.canonicalFindingId);
        for (const findingId of entry.sourceFindingIds) {
            if (sourceFindingIds.has(findingId)) {
                throw new TypeError(`${label} repeats a source finding`);
            }
            sourceFindingIds.add(findingId);
        }
    }
    exactObject(value.truncation, [
        "canonicalFindings",
        "candidates",
        "guidance",
        "blockers",
    ], [], `${label}.truncation`);
    const truncation = Object.freeze({
        canonicalFindings: booleanValue(
            value.truncation.canonicalFindings,
            `${label}.truncation.canonicalFindings`,
        ),
        candidates: booleanValue(
            value.truncation.candidates,
            `${label}.truncation.candidates`,
        ),
        guidance: booleanValue(
            value.truncation.guidance,
            `${label}.truncation.guidance`,
        ),
        blockers: booleanValue(
            value.truncation.blockers,
            `${label}.truncation.blockers`,
        ),
    });
    const blockers = boundedEntries(
        value.blockers,
        `${label}.blockers`,
        REMEDIATION_LIMITS.blockers,
    ).map((blocker, index) => {
        exactObject(
            blocker,
            ["code"],
            ["canonicalFindingId", "cap", "observed"],
            `${label}.blockers[${index}]`,
        );
        const normalized = {
            code: enumValue(
                blocker.code,
                BLOCKER_CODES,
                `${label}.blockers[${index}].code`,
            ),
        };
        if (Object.hasOwn(blocker, "canonicalFindingId")) {
            normalized.canonicalFindingId = validateIdentifier(
                blocker.canonicalFindingId,
                `${label}.blockers[${index}].canonicalFindingId`,
            );
        }
        for (const numeric of ["cap", "observed"]) {
            if (Object.hasOwn(blocker, numeric)) {
                if (!Number.isSafeInteger(blocker[numeric]) || blocker[numeric] < 0) {
                    throw new TypeError(`${label}.blockers[${index}].${numeric} is invalid`);
                }
                normalized[numeric] = blocker[numeric];
            }
        }
        return Object.freeze(normalized);
    });
    const normalized = {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId,
        id: typeof value.id === "string" && PLAN_ID_RE.test(value.id)
            ? value.id: (() => { throw new TypeError(`${label}.id is invalid`); }),
        inputFingerprint: hashValue(value.inputFingerprint, `${label}.inputFingerprint`),
        coverageComplete: booleanValue(value.coverageComplete, `${label}.coverageComplete`),
        candidates: Object.freeze(candidates),
        investigationGuidance: Object.freeze(guidance),
        truncation,
        blockers: Object.freeze(blockers),
    };
    if (normalized.coverageComplete && Object.values(truncation).some(Boolean)) {
        throw new TypeError(`${label}.coverageComplete cannot ignore truncation`);
    }
    if (normalized.coverageComplete
        && (normalized.blockers.length > 0
            || normalized.candidates.some((candidate) =>
                candidate.staticVerification.graphCoverage !== "complete"))) {
        throw new TypeError(`${label}.coverageComplete cannot ignore remediation blockers`);
    }
    const expectedId = `ztrp-baseline-${digest("zerotrust-remediation-plan-baseline", {
        schemaVersion: normalized.schemaVersion,
        auditId: normalized.auditId,
        inputFingerprint: normalized.inputFingerprint,
        coverageComplete: normalized.coverageComplete,
        candidates: normalized.candidates,
        investigationGuidance: normalized.investigationGuidance,
        truncation: normalized.truncation,
        blockers: normalized.blockers,
    })}`;
    if (normalized.id !== expectedId) {
        throw new TypeError(`${label}.id does not match remediation plan identity`);
    }
    return Object.freeze(structuredClone(normalized));
}

export const __internals = Object.freeze({
    canonicalJson,
    digest,
    flattenChainEdgeIds,
    flattenChainNodeIds,
    chainContainsTarget,
    finalEffectNodeIds,
    sharesEffectIdentity,
    chooseTargetLink,
    riskForTarget,
});
