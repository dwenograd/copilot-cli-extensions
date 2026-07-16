import { createHash } from "node:crypto";

import {
    ANALYSIS_SCHEMA_REVISION,
    CONFIDENCE_LEVELS,
    LIMITS,
    MALICIOUS_PROJECT_FIT_LEVELS,
    SEVERITIES,
    validateAuditId,
    validateEvidenceReference,
    validateIdentifier,
} from "./schemas.mjs";

export const VALIDATION_MIN_SEVERITIES = Object.freeze([
    "high",
    "medium",
    "low",
    "info",
]);

export const VALIDATION_LIMITS = Object.freeze({
    pageSize: 8,
    chainsPerFinding: 16,
    nodesPerFinding: 64,
    edgesPerFinding: 128,
    factsPerFinding: 128,
    evidencePerFinding: LIMITS.evidencePerItem,
    referencesPerDecision: 64,
    checksPerDecision: 32,
    rationale: LIMITS.rationale,
    checkText: 512,
});

const SEVERITY_RANK = Object.freeze({
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
});

const REFUTE_CHECK_KEYS = Object.freeze([
    "deadOrUnreachableCode",
    "docsOrTestsOnlyContext",
    "activationGating",
    "sanitizationOrNeutralization",
    "brokenGraphEdges",
    "legitimateProjectFit",
]);

const REFUTE_CHECK_RESULTS = Object.freeze([
    "supports-refutation",
    "does-not-refute",
    "unresolved",
]);

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function exactObject(value, required, label) {
    if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain object`);
    const allowed = new Set(required);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) throw new TypeError(`${label}.${key} is not allowed`);
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
    }
}

function boundedString(value, label, max) {
    if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
    const normalized = value.normalize("NFKC").trim();
    if (!normalized || normalized.length > max || normalized.includes("\0")) {
        throw new TypeError(`${label} must contain 1-${max} characters and no NUL`);
    }
    return normalized;
}

function enumValue(value, values, label) {
    if (!values.includes(value)) {
        throw new TypeError(`${label} must be one of: ${values.join(", ")}`);
    }
    return value;
}

function uniqueIdentifiers(value, label, max = VALIDATION_LIMITS.referencesPerDecision) {
    if (!Array.isArray(value) || value.length > max) {
        throw new TypeError(`${label} must be an array with at most ${max} entries`);
    }
    const normalized = value.map((entry, index) =>
        validateIdentifier(entry, `${label}[${index}]`));
    if (new Set(normalized).size !== normalized.length) {
        throw new TypeError(`${label} must not contain duplicates`);
    }
    return normalized;
}

function evidenceKey(value) {
    return JSON.stringify({
        path: value.path,
        startLine: value.startLine,
        endLine: value.endLine,
        blobSha: value.blobSha,
        excerptHash: value.excerptHash,
        producer: value.producer,
        coverageScope: value.coverageScope,
    });
}

function uniqueEvidence(values) {
    const entries = new Map();
    for (const value of values) entries.set(evidenceKey(value), value);
    return [...entries.values()].sort((left, right) =>
        evidenceKey(left).localeCompare(evidenceKey(right)));
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

function sameValue(left, right) {
    return canonicalJson(left) === canonicalJson(right);
}

function arrayIntersection(left, right) {
    const rightSet = new Set(right);
    return left.some((value) => rightSet.has(value));
}

function flattenChainNodeIds(chain) {
    return [...new Set(chain.steps.flatMap((step) => step.nodeIds || []))].sort();
}

function flattenChainEdgeIds(chain) {
    return [...new Set(chain.links.flatMap((link) => link.edgeIds || []))].sort();
}

function stripNode(node) {
    return {
        id: node.id,
        kind: node.kind,
        producer: node.producer,
        evidence: node.evidence,
        ...(node.sourceIdentity ? { sourceIdentity: node.sourceIdentity }: {}),
        ...(node.behaviorSignature ? { behaviorSignature: node.behaviorSignature }: {}),
        ...(node.tags ? { tags: node.tags }: {}),
    };
}

function stripEdge(edge) {
    return {
        id: edge.id,
        kind: edge.kind,
        from: edge.from,
        to: edge.to,
        producer: edge.producer,
        evidence: edge.evidence,
        ...(edge.tags ? { tags: edge.tags }: {}),
    };
}

export function normalizeValidationMinSeverity(value = "high") {
    return enumValue(value, VALIDATION_MIN_SEVERITIES, "validationMinSeverity");
}

export function findingRequiresValidation(finding, minSeverity = "high") {
    const minimum = normalizeValidationMinSeverity(minSeverity);
    if (finding.severity === "critical" || finding.severity === "high") return true;
    return SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[minimum];
}

export function buildValidationPlan({
    auditId,
    minSeverity = "high",
    findings = [],
    candidateContexts = [],
    traceSnapshot,
    graphDocuments = [],
    indexState,
} = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    const normalizedMinSeverity = normalizeValidationMinSeverity(minSeverity);
    if (!traceSnapshot || traceSnapshot.auditId !== normalizedAuditId
        || traceSnapshot.coverageComplete !== true) {
        throw new Error("validation requires a complete audit-bound behavior trace");
    }
    if (Object.values(traceSnapshot.truncation || {}).some(Boolean)) {
        throw new Error("validation requires an untruncated behavior trace");
    }
    if (!indexState || indexState.auditId !== normalizedAuditId) {
        throw new Error("validation requires the active audit analysis index");
    }

    const contextsByFinding = new Map(
        candidateContexts.map((entry) => [entry.findingId, entry]),
    );
    const nodesById = new Map();
    const edgesById = new Map();
    for (const document of graphDocuments) {
        if (!document || document.auditId !== normalizedAuditId) {
            throw new Error("validation graph document auditId mismatch");
        }
        for (const node of document.nodes || []) {
            const existing = nodesById.get(node.id);
            if (existing && !sameValue(existing, node)) {
                throw new Error(`validation graph node identity conflict: ${node.id}`);
            }
            nodesById.set(node.id, node);
        }
        for (const edge of document.edges || []) {
            const existing = edgesById.get(edge.id);
            if (existing && !sameValue(existing, edge)) {
                throw new Error(`validation graph edge identity conflict: ${edge.id}`);
            }
            edgesById.set(edge.id, edge);
        }
    }

    const requiredFindings = findings
        .filter((finding) => findingRequiresValidation(finding, normalizedMinSeverity))
        .sort((left, right) => left.id.localeCompare(right.id));
    const validationContexts = [];
    let contextsTruncated = false;

    for (const finding of requiredFindings) {
        if (finding.auditId !== normalizedAuditId) {
            throw new Error(`validation finding auditId mismatch: ${finding.id}`);
        }
        if (finding.state !== "candidate" && finding.state !== "validating") {
            throw new Error(`validation finding is not a candidate: ${finding.id}`);
        }
        const candidateNodeIds = [...finding.nodeIds];
        const candidateEdgeIds = [...finding.edgeIds];
        const associatedChains = (traceSnapshot.chains || []).filter((chain) => {
            const chainNodeIds = flattenChainNodeIds(chain);
            const chainEdgeIds = flattenChainEdgeIds(chain);
            return arrayIntersection(candidateNodeIds, chainNodeIds)
                || arrayIntersection(candidateEdgeIds, chainEdgeIds);
        });
        const chainsTruncated = associatedChains.length
            > VALIDATION_LIMITS.chainsPerFinding;
        const chains = associatedChains.slice(0, VALIDATION_LIMITS.chainsPerFinding);
        const allowedNodeIds = [...new Set([
            ...candidateNodeIds,
            ...chains.flatMap(flattenChainNodeIds),
        ])].sort();
        const allowedEdgeIds = [...new Set([
            ...candidateEdgeIds,
            ...chains.flatMap(flattenChainEdgeIds),
        ])].sort();
        const nodesTruncated = allowedNodeIds.length > VALIDATION_LIMITS.nodesPerFinding;
        const edgesTruncated = allowedEdgeIds.length > VALIDATION_LIMITS.edgesPerFinding;
        const nodeIds = allowedNodeIds.slice(0, VALIDATION_LIMITS.nodesPerFinding);
        const edgeIds = allowedEdgeIds.slice(0, VALIDATION_LIMITS.edgesPerFinding);
        const nodes = nodeIds.map((id) => nodesById.get(id)).filter(Boolean).map(stripNode);
        const edges = edgeIds.map((id) => edgesById.get(id)).filter(Boolean).map(stripEdge);
        const allowedEvidenceUnbounded = uniqueEvidence([
            ...finding.evidence,
            ...nodes.flatMap((node) => node.evidence || []),
            ...edges.flatMap((edge) => edge.evidence || []),
        ]);
        const evidenceTruncated = allowedEvidenceUnbounded.length
            > VALIDATION_LIMITS.evidencePerFinding;
        const allowedEvidence = allowedEvidenceUnbounded.slice(
            0,
            VALIDATION_LIMITS.evidencePerFinding,
        );
        const allowedEvidenceSemantic = new Set(allowedEvidence.map((evidence) =>
            `${evidence.path}\0${evidence.startLine}\0${evidence.endLine}\0${evidence.excerptHash}`));
        const factsUnbounded = (indexState.facts || []).filter((fact) =>
            allowedEvidenceSemantic.has(
                `${fact.path}\0${fact.line}\0${fact.endLine}\0${fact.excerptHash}`,
            ));
        const factsTruncated = factsUnbounded.length > VALIDATION_LIMITS.factsPerFinding;
        const facts = factsUnbounded.slice(0, VALIDATION_LIMITS.factsPerFinding);
        const truncated = chainsTruncated || nodesTruncated || edgesTruncated
            || evidenceTruncated || factsTruncated
            || nodes.length !== nodeIds.length || edges.length !== edgeIds.length;
        contextsTruncated ||= truncated;
        validationContexts.push(Object.freeze({
            finding: Object.freeze({
                ...finding,
                state: "validating",
            }),
            strongestBenignHypothesis:
                contextsByFinding.get(finding.id)?.strongestBenignHypothesis || null,
            chains: Object.freeze(structuredClone(chains)),
            graphNeighborhood: Object.freeze({
                nodes: Object.freeze(structuredClone(nodes)),
                edges: Object.freeze(structuredClone(edges)),
            }),
            facts: Object.freeze(structuredClone(facts)),
            allowedEvidence: Object.freeze(structuredClone(allowedEvidence)),
            allowedNodeIds: Object.freeze(nodeIds),
            allowedEdgeIds: Object.freeze(edgeIds),
            truncation: Object.freeze({
                chains: chainsTruncated,
                nodes: nodesTruncated || nodes.length !== nodeIds.length,
                edges: edgesTruncated || edges.length !== edgeIds.length,
                evidence: evidenceTruncated,
                facts: factsTruncated,
            }),
            truncated,
        }));
    }

    const inputFingerprint = digest("zerotrust-validation-input-baseline", {
        auditId: normalizedAuditId,
        minSeverity: normalizedMinSeverity,
        traceInputFingerprint: traceSnapshot.inputFingerprint,
        findings: requiredFindings,
        contexts: validationContexts,
    });
    return Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: normalizedAuditId,
        minSeverity: normalizedMinSeverity,
        inputFingerprint,
        contexts: Object.freeze(validationContexts),
        truncation: Object.freeze({
            contexts: contextsTruncated,
        }),
    });
}

export function createValidationState(plan) {
    if (!plan || plan.schemaVersion !== ANALYSIS_SCHEMA_REVISION) {
        throw new TypeError("validation state requires a baseline analysis validation plan");
    }
    const auditId = validateAuditId(plan.auditId);
    const contexts = new Map(plan.contexts.map((context) => [
        context.finding.id,
        context,
    ]));
    return {
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId,
        minSeverity: normalizeValidationMinSeverity(plan.minSeverity),
        inputFingerprint: plan.inputFingerprint,
        requiredFindingIds: Object.freeze([...contexts.keys()]),
        contexts,
        decisions: new Map(),
        adjudications: new Map(),
        truncation: plan.truncation,
        finalization: null,
    };
}

export function buildValidationSnapshot(state) {
    if (!state) return null;
    const required = state.requiredFindingIds.length;
    const confirmDecisions = state.requiredFindingIds.filter((findingId) =>
        state.decisions.has(`${findingId}:confirm`)).length;
    const refuteDecisions = state.requiredFindingIds.filter((findingId) =>
        state.decisions.has(`${findingId}:refute`)).length;
    const adjudications = state.requiredFindingIds.filter((findingId) =>
        state.adjudications.has(findingId)).length;
    const complete = confirmDecisions === required
        && refuteDecisions === required
        && adjudications === required
        && !Object.values(state.truncation || {}).some(Boolean);
    return Object.freeze(structuredClone({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: state.auditId,
        minSeverity: state.minSeverity,
        inputFingerprint: state.inputFingerprint,
        requiredFindingIds: state.requiredFindingIds,
        counts: {
            requiredCandidates: required,
            confirmDecisions,
            refuteDecisions,
            adjudications,
        },
        completion: {
            confirmComplete: confirmDecisions === required,
            refuteComplete: refuteDecisions === required,
            adjudicationComplete: adjudications === required,
            complete,
        },
        truncation: state.truncation,
        finalization: state.finalization,
        decisions: [...state.decisions.values()].map((entry) => entry.decision),
        adjudications: [...state.adjudications.values()].map((entry) => entry.decision),
    }));
}

export function pageValidationContexts(state, {
    cursor = 0,
    limit = VALIDATION_LIMITS.pageSize,
} = {}) {
    if (!Number.isSafeInteger(cursor) || cursor < 0) {
        throw new TypeError("validation cursor must be a non-negative integer");
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > VALIDATION_LIMITS.pageSize) {
        throw new TypeError(
            `validation limit must be between 1 and ${VALIDATION_LIMITS.pageSize}`,
        );
    }
    const contexts = state.requiredFindingIds
        .map((findingId) => state.contexts.get(findingId))
        .slice(cursor, cursor + limit);
    return Object.freeze(structuredClone({
        contexts,
        cursor,
        nextCursor: cursor + limit < state.requiredFindingIds.length
            ? cursor + limit: null,
        total: state.requiredFindingIds.length,
    }));
}

function validateEvidenceSubset(value, context, label) {
    if (!Array.isArray(value) || value.length > VALIDATION_LIMITS.evidencePerFinding) {
        throw new TypeError(
            `${label} must be an array with at most ${VALIDATION_LIMITS.evidencePerFinding} entries`,
        );
    }
    const normalized = value.map((entry, index) =>
        validateEvidenceReference(entry, `${label}[${index}]`));
    if (new Set(normalized.map(evidenceKey)).size !== normalized.length) {
        throw new TypeError(`${label} must not contain duplicates`);
    }
    const allowed = new Set(context.allowedEvidence.map(evidenceKey));
    for (const evidence of normalized) {
        if (!allowed.has(evidenceKey(evidence))) {
            throw new Error(`${label} introduces evidence outside the prepared validation context`);
        }
    }
    return normalized;
}

function validateReferenceSubset(value, allowedValues, label) {
    const normalized = uniqueIdentifiers(value, label);
    const allowed = new Set(allowedValues);
    for (const id of normalized) {
        if (!allowed.has(id)) {
            throw new Error(`${label} references an ID outside the prepared validation context`);
        }
    }
    return normalized;
}

function validateConfirmChecks(value) {
    const fields = [
        "activationReachable",
        "effectReachable",
        "sourceToEffectPath",
        "gatingConsidered",
        "brokenEdgesConsidered",
    ];
    exactObject(value, fields, "checks");
    const normalized = {};
    for (const field of fields) {
        if (typeof value[field] !== "boolean") {
            throw new TypeError(`checks.${field} must be boolean`);
        }
        normalized[field] = value[field];
    }
    return normalized;
}

function validateRefuteChecks(value) {
    exactObject(value, REFUTE_CHECK_KEYS, "checks");
    return Object.fromEntries(REFUTE_CHECK_KEYS.map((field) => [
        field,
        enumValue(value[field], REFUTE_CHECK_RESULTS, `checks.${field}`),
    ]));
}

export function validateStaticDecisionSubmission(input, {
    context,
    otherDecision = null,
} = {}) {
    exactObject(input, [
        "action",
        "schemaVersion",
        "audit_id",
        "finding_id",
        "validator_id",
        "decision_type",
        "conclusion",
        "chain_ids",
        "node_ids",
        "edge_ids",
        "evidence",
        "rationale_code",
        "rationale",
        "checks",
    ], "validation decision");
    if (input.action !== "submit") throw new TypeError("action must be submit");
    if (input.schemaVersion !== ANALYSIS_SCHEMA_REVISION) {
        throw new TypeError(`schemaVersion must equal ${ANALYSIS_SCHEMA_REVISION}`);
    }
    const auditId = validateAuditId(input.audit_id);
    if (auditId !== context.finding.auditId) {
        throw new Error("validation decision audit_id does not match its finding");
    }
    if (input.finding_id !== context.finding.id) {
        throw new Error("validation decision finding_id does not match its context");
    }
    const validatorId = validateIdentifier(input.validator_id, "validator_id");
    if (otherDecision?.validatorId === validatorId) {
        throw new Error("confirm and refute decisions require independent validator IDs");
    }
    const decisionType = enumValue(
        input.decision_type,
        ["confirm", "refute"],
        "decision_type",
    );
    const conclusions = decisionType === "confirm"
        ? ["confirmed", "not-confirmed", "unresolved"]: ["refuted", "not-refuted", "unresolved"];
    const conclusion = enumValue(input.conclusion, conclusions, "conclusion");
    const allowedChainIds = context.chains.map((chain) => chain.id);
    const chainIds = validateReferenceSubset(input.chain_ids, allowedChainIds, "chain_ids");
    const nodeIds = validateReferenceSubset(
        input.node_ids,
        context.allowedNodeIds,
        "node_ids",
    );
    const edgeIds = validateReferenceSubset(
        input.edge_ids,
        context.allowedEdgeIds,
        "edge_ids",
    );
    const evidence = validateEvidenceSubset(input.evidence, context, "evidence");
    if (evidence.length === 0) {
        throw new Error("validation decisions require at least one existing evidence reference");
    }
    const checks = decisionType === "confirm"
        ? validateConfirmChecks(input.checks): validateRefuteChecks(input.checks);

    if (decisionType === "confirm" && conclusion === "confirmed") {
        if (!checks.activationReachable || !checks.effectReachable
            || !checks.sourceToEffectPath) {
            throw new Error(
                "confirmed decisions must establish activation, effect reachability, and a source-to-effect path",
            );
        }
        const selectedChains = context.chains.filter((chain) => chainIds.includes(chain.id));
        const establishesPath = selectedChains.some((chain) => {
            const requiredNodes = flattenChainNodeIds(chain);
            const requiredEdges = flattenChainEdgeIds(chain);
            return chain.status === "complete"
                && (chain.steps[0]?.kind === "activation" || chain.steps[0]?.kind === "trigger")
                && Array.isArray(chain.effectKinds) && chain.effectKinds.length > 0
                && requiredNodes.every((id) => nodeIds.includes(id))
                && requiredEdges.every((id) => edgeIds.includes(id));
        });
        if (!establishesPath) {
            throw new Error(
                "confirmed decisions require one existing complete chain with its full node/edge path",
            );
        }
    }

    if (decisionType === "refute") {
        const supports = Object.values(checks).filter((value) =>
            value === "supports-refutation").length;
        if (conclusion === "refuted" && supports === 0) {
            throw new Error("refuted decisions require at least one concrete refutation test");
        }
        if (conclusion === "not-refuted" && supports > 0) {
            throw new Error("not-refuted decisions cannot contain a supporting refutation test");
        }
        if (checks.brokenGraphEdges === "supports-refutation"
            && edgeIds.length === 0 && chainIds.length === 0) {
            throw new Error(
                "broken-edge refutation requires an existing edge or chain reference",
            );
        }
    }

    return Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId,
        findingId: context.finding.id,
        validatorId,
        decisionType,
        conclusion,
        chainIds: Object.freeze(chainIds),
        nodeIds: Object.freeze(nodeIds),
        edgeIds: Object.freeze(edgeIds),
        evidence: Object.freeze(evidence),
        rationaleCode: validateIdentifier(input.rationale_code, "rationale_code"),
        rationale: boundedString(input.rationale, "rationale", VALIDATION_LIMITS.rationale),
        checks: Object.freeze(checks),
    });
}

export function storeStaticDecision(state, decision) {
    const key = `${decision.findingId}:${decision.decisionType}`;
    const decisionDigest = digest("zerotrust-static-validation-decision-baseline", decision);
    const existing = state.decisions.get(key);
    if (existing) {
        if (existing.digest !== decisionDigest) {
            throw new Error(
                `${decision.decisionType} decision is immutable after first submission`,
            );
        }
        return { idempotent: true, decision: existing.decision };
    }
    if (state.decisions.size >= LIMITS.validationDecisions) {
        throw new RangeError(
            `static validation decision cap exceeded (${LIMITS.validationDecisions})`,
        );
    }
    state.decisions.set(key, Object.freeze({
        digest: decisionDigest,
        decision,
    }));
    return { idempotent: false, decision };
}

function confidenceRank(value) {
    return CONFIDENCE_LEVELS.indexOf(value);
}

export function validateAdjudicationSubmission(input, {
    context,
    confirmDecision,
    refuteDecision,
} = {}) {
    exactObject(input, [
        "action",
        "schemaVersion",
        "audit_id",
        "finding_id",
        "adjudicator_id",
        "decision",
        "severity",
        "confidence",
        "malicious_project_fit",
        "rationale_code",
        "rationale",
        "chain_ids",
        "node_ids",
        "edge_ids",
        "evidence",
    ], "validation adjudication");
    if (input.action !== "adjudicate") throw new TypeError("action must be adjudicate");
    if (input.schemaVersion !== ANALYSIS_SCHEMA_REVISION) {
        throw new TypeError(`schemaVersion must equal ${ANALYSIS_SCHEMA_REVISION}`);
    }
    const auditId = validateAuditId(input.audit_id);
    if (auditId !== context.finding.auditId || input.finding_id !== context.finding.id) {
        throw new Error("validation adjudication identity does not match its context");
    }
    if (!confirmDecision || !refuteDecision) {
        throw new Error("adjudication requires both confirm and refute decisions");
    }
    const adjudicatorId = validateIdentifier(input.adjudicator_id, "adjudicator_id");
    if ([confirmDecision.validatorId, refuteDecision.validatorId].includes(adjudicatorId)) {
        throw new Error("adjudicator must be independent from both validators");
    }
    const decision = enumValue(
        input.decision,
        ["validated", "refuted", "unresolved"],
        "decision",
    );
    const severity = enumValue(input.severity, SEVERITIES, "severity");
    const confidence = enumValue(input.confidence, CONFIDENCE_LEVELS, "confidence");
    const maliciousProjectFit = enumValue(
        input.malicious_project_fit,
        MALICIOUS_PROJECT_FIT_LEVELS,
        "malicious_project_fit",
    );
    const unionChainIds = [...new Set([
        ...confirmDecision.chainIds,
        ...refuteDecision.chainIds,
    ])];
    const unionNodeIds = [...new Set([
        ...confirmDecision.nodeIds,
        ...refuteDecision.nodeIds,
    ])];
    const unionEdgeIds = [...new Set([
        ...confirmDecision.edgeIds,
        ...refuteDecision.edgeIds,
    ])];
    const unionEvidence = uniqueEvidence([
        ...confirmDecision.evidence,
        ...refuteDecision.evidence,
    ]);
    const adjudicationContext = {
        ...context,
        allowedEvidence: unionEvidence,
    };
    const chainIds = validateReferenceSubset(input.chain_ids, unionChainIds, "chain_ids");
    const nodeIds = validateReferenceSubset(input.node_ids, unionNodeIds, "node_ids");
    const edgeIds = validateReferenceSubset(input.edge_ids, unionEdgeIds, "edge_ids");
    const evidence = validateEvidenceSubset(input.evidence, adjudicationContext, "evidence");
    if (evidence.length === 0) {
        throw new Error("adjudication requires existing validator evidence");
    }

    const confirm = confirmDecision.conclusion;
    const refute = refuteDecision.conclusion;
    const directDisagreement = confirm === "confirmed" && refute === "refuted";
    let permittedDecision = "unresolved";
    let confidenceCeiling = "medium";
    if (confirm === "confirmed" && refute === "not-refuted") {
        permittedDecision = "validated";
        confidenceCeiling = "high";
    } else if (confirm === "not-confirmed" && refute === "refuted") {
        permittedDecision = "refuted";
        confidenceCeiling = "high";
    } else if (confirm === "confirmed" && refute === "unresolved") {
        permittedDecision = "validated";
    } else if (confirm === "unresolved" && refute === "refuted") {
        permittedDecision = "refuted";
    } else if (directDisagreement) {
        confidenceCeiling = "low";
    }
    if (decision !== "unresolved" && decision !== permittedDecision) {
        throw new Error(
            `adjudication decision ${decision} conflicts with confirm/refute outcomes; expected ${permittedDecision} or unresolved`,
        );
    }
    if (decision === "unresolved" && confidence === "high") {
        throw new Error("unresolved adjudications cannot retain high confidence");
    }
    if (confidenceRank(confidence) > confidenceRank(confidenceCeiling)) {
        throw new Error(
            `adjudication confidence must be ${confidenceCeiling} or lower for this validator outcome`,
        );
    }

    return Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId,
        findingId: context.finding.id,
        adjudicatorId,
        decision,
        severity,
        confidence,
        maliciousProjectFit,
        rationaleCode: validateIdentifier(input.rationale_code, "rationale_code"),
        rationale: boundedString(input.rationale, "rationale", VALIDATION_LIMITS.rationale),
        chainIds: Object.freeze(chainIds),
        nodeIds: Object.freeze(nodeIds),
        edgeIds: Object.freeze(edgeIds),
        evidence: Object.freeze(evidence),
    });
}

export function storeAdjudication(state, adjudication) {
    const adjudicationDigest = digest(
        "zerotrust-validation-adjudication-baseline",
        adjudication,
    );
    const existing = state.adjudications.get(adjudication.findingId);
    if (existing) {
        if (existing.digest !== adjudicationDigest) {
            throw new Error("validation adjudication is immutable after first submission");
        }
        return { idempotent: true, decision: existing.decision };
    }
    state.adjudications.set(adjudication.findingId, Object.freeze({
        digest: adjudicationDigest,
        decision: adjudication,
    }));
    return { idempotent: false, decision: adjudication };
}

export function finalizeValidationState(state) {
    const snapshot = buildValidationSnapshot(state);
    if (!snapshot.completion.complete) {
        throw new Error(
            `validation is incomplete: confirm=${snapshot.counts.confirmDecisions}/${snapshot.counts.requiredCandidates}, refute=${snapshot.counts.refuteDecisions}/${snapshot.counts.requiredCandidates}, adjudication=${snapshot.counts.adjudications}/${snapshot.counts.requiredCandidates}`,
        );
    }
    if (Object.values(snapshot.truncation || {}).some(Boolean)) {
        throw new Error("validation truncation prevents finalization");
    }
    const finalization = Object.freeze({
        digest: digest("zerotrust-validation-finalization-baseline", {
            auditId: state.auditId,
            inputFingerprint: state.inputFingerprint,
            decisions: snapshot.decisions,
            adjudications: snapshot.adjudications,
        }),
        requiredCandidates: snapshot.counts.requiredCandidates,
    });
    if (state.finalization) {
        if (state.finalization.digest !== finalization.digest) {
            throw new Error("validation finalization identity changed");
        }
        return { idempotent: true, finalization: state.finalization };
    }
    state.finalization = finalization;
    return { idempotent: false, finalization };
}

export const __internals = Object.freeze({
    canonicalJson,
    digest,
    evidenceKey,
    flattenChainNodeIds,
    flattenChainEdgeIds,
    REFUTE_CHECK_KEYS,
    REFUTE_CHECK_RESULTS,
});
