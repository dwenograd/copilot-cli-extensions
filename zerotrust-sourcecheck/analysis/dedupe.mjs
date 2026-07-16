import { createHash } from "node:crypto";

import {
    ANALYSIS_SCHEMA_REVISION,
    CONFIDENCE_LEVELS,
    LIMITS,
    MALICIOUS_PROJECT_FIT_LEVELS,
    SEVERITIES,
    normalizeBehaviorSignature,
    validateAuditId,
    validateCandidateFinding,
} from "./schemas.mjs";

export const DEDUPE_LIMITS = Object.freeze({
    canonicalFindings: 512,
    aliasesPerFinding: 128,
    evidencePerFinding: LIMITS.evidencePerItem,
    pathsPerFinding: 128,
    producersPerFinding: 128,
    chainsPerFinding: 64,
    nodeIdsPerFinding: 256,
    edgeIdsPerFinding: 512,
    blockers: 128,
});

const SEVERITY_RANK = Object.freeze(Object.fromEntries(
    SEVERITIES.map((severity, index) => [severity, index]),
));

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

function boundedLimit(value, fallback, maximum) {
    if (!Number.isSafeInteger(value) || value < 1) return fallback;
    return Math.min(value, maximum);
}

function normalizeLimits(value = {}) {
    return Object.freeze(Object.fromEntries(
        Object.entries(DEDUPE_LIMITS).map(([key, maximum]) => [
            key,
            boundedLimit(value[key], maximum, maximum),
        ]),
    ));
}

function unique(values) {
    return [...new Set(values)].sort();
}

function uniqueCanonical(values) {
    const entries = new Map();
    for (const value of values) entries.set(canonicalJson(value), value);
    return [...entries.values()].sort((left, right) =>
        canonicalJson(left).localeCompare(canonicalJson(right)));
}

function stateClass(state) {
    if (state === "validated") return "validated";
    if (state === "refuted") return "refuted";
    return "unresolved";
}

function flattenChainNodeIds(chain) {
    return unique((chain.steps || []).flatMap((step) => step.nodeIds || []));
}

function flattenChainEdgeIds(chain) {
    return unique((chain.links || []).flatMap((link) => link.edgeIds || []));
}

function chainDescriptor(chain) {
    return Object.freeze({
        status: String(chain.status || "unresolved"),
        pattern: String(chain.pattern || "behavior-chain"),
        stepKinds: Object.freeze((chain.steps || []).map((step) => String(step.kind))),
        linkKinds: Object.freeze((chain.links || []).map((link) => String(link.kind))),
        effectKinds: Object.freeze(unique(chain.effectKinds || [])),
        unresolvedReasons: Object.freeze(unique(chain.unresolvedReasons || [])),
    });
}

function associatedChains(finding, traceSnapshot) {
    const nodeIds = new Set(finding.nodeIds);
    const edgeIds = new Set(finding.edgeIds);
    return (traceSnapshot?.chains || []).filter((chain) =>
        flattenChainNodeIds(chain).some((id) => nodeIds.has(id))
        || flattenChainEdgeIds(chain).some((id) => edgeIds.has(id)));
}

function normalizedMaliciousBehaviorSignature(finding, chains) {
    const behavior = normalizeBehaviorSignature(finding.behaviorSignature);
    const neighborhoods = uniqueCanonical(chains.map(chainDescriptor));
    return Object.freeze({
        activationVector: behavior.trigger || "unspecified",
        capability: behavior.capability,
        effect: Object.freeze({
            action: behavior.action,
            target: behavior.target,
            ...(behavior.persistence ? { persistence: behavior.persistence }: {}),
            ...(behavior.propagation ? { propagation: behavior.propagation }: {}),
        }),
        graphNeighborhood: Object.freeze(neighborhoods.length > 0
            ? neighborhoods: [{
                status: "unmapped",
                pattern: "unmapped",
                stepKinds: [],
                linkKinds: [],
                effectKinds: [],
                unresolvedReasons: [],
            }]),
    });
}

function validationAdjudications(validationSnapshot, auditId) {
    if (!validationSnapshot) return new Map();
    if (validationSnapshot.auditId !== auditId) {
        throw new Error("validation snapshot auditId does not match dedupe auditId");
    }
    return new Map((validationSnapshot.adjudications || []).map((entry) => [
        entry.findingId,
        entry,
    ]));
}

function aliasRecord(finding, chains, adjudication) {
    const chainIds = unique(chains.map((chain) => chain.id));
    const completeChainIds = unique(chains
        .filter((chain) => chain.status === "complete")
        .map((chain) => chain.id));
    const validationChainIds = unique(adjudication?.chainIds || []);
    return Object.freeze({
        findingId: finding.id,
        state: finding.state,
        severity: finding.severity,
        confidence: finding.confidence,
        maliciousProjectFit: finding.maliciousProjectFit,
        sourcePath: finding.sourceIdentity.path,
        producer: finding.producer,
        chainIds: Object.freeze(chainIds),
        completeChainIds: Object.freeze(completeChainIds),
        validationChainIds: Object.freeze(validationChainIds),
        validatedChainIds: Object.freeze(validationChainIds.filter((id) =>
            completeChainIds.includes(id))),
    });
}

function strongestSeverity(findings) {
    return findings.reduce((strongest, finding) =>
        SEVERITY_RANK[finding.severity] > SEVERITY_RANK[strongest]
            ? finding.severity: strongest, "info");
}

function canonicalGroup(group, limits) {
    const orderedMembers = [...group.members].sort((left, right) =>
        left.finding.id.localeCompare(right.finding.id));
    const findings = orderedMembers.map((member) => member.finding);
    const aliasesUnbounded = orderedMembers.map((member) =>
        aliasRecord(member.finding, member.chains, member.adjudication));
    const evidenceUnbounded = uniqueCanonical(findings.flatMap((finding) => finding.evidence));
    const pathsUnbounded = unique([
        ...findings.map((finding) => finding.sourceIdentity.path),
        ...evidenceUnbounded.map((evidence) => evidence.path),
    ]);
    const producersUnbounded = unique([
        ...findings.map((finding) => finding.producer),
        ...evidenceUnbounded.map((evidence) => evidence.producer),
    ]);
    const chainIdsUnbounded = unique(orderedMembers.flatMap((member) =>
        member.chains.map((chain) => chain.id)));
    const nodeIdsUnbounded = unique(findings.flatMap((finding) => finding.nodeIds));
    const edgeIdsUnbounded = unique(findings.flatMap((finding) => finding.edgeIds));
    const validationChainIds = unique(aliasesUnbounded.flatMap((alias) =>
        alias.validationChainIds));
    const validatedChainIds = unique(aliasesUnbounded.flatMap((alias) =>
        alias.validatedChainIds));
    const truncation = Object.freeze({
        aliases: aliasesUnbounded.length > limits.aliasesPerFinding,
        evidence: evidenceUnbounded.length > limits.evidencePerFinding,
        paths: pathsUnbounded.length > limits.pathsPerFinding,
        producers: producersUnbounded.length > limits.producersPerFinding,
        chains: chainIdsUnbounded.length > limits.chainsPerFinding,
        nodeIds: nodeIdsUnbounded.length > limits.nodeIdsPerFinding,
        edgeIds: edgeIdsUnbounded.length > limits.edgeIdsPerFinding,
    });
    return Object.freeze({
        canonicalId: `ztcanon-${digest("zerotrust-canonical-finding", {
            auditId: group.auditId,
            signature: group.signature,
            stateClass: group.stateClass,
        })}`,
        signature: group.signature,
        stateClass: group.stateClass,
        aliases: Object.freeze(aliasesUnbounded.slice(0, limits.aliasesPerFinding)),
        observedStates: Object.freeze(unique(findings.map((finding) => finding.state))),
        observedSeverities: Object.freeze(unique(findings.map((finding) => finding.severity))
            .sort((left, right) => SEVERITY_RANK[right] - SEVERITY_RANK[left])),
        observedConfidences: Object.freeze(unique(findings.map((finding) => finding.confidence))
            .sort((left, right) =>
                CONFIDENCE_LEVELS.indexOf(right) - CONFIDENCE_LEVELS.indexOf(left))),
        observedProjectFits: Object.freeze(unique(findings
            .map((finding) => finding.maliciousProjectFit))
            .sort((left, right) =>
                MALICIOUS_PROJECT_FIT_LEVELS.indexOf(right)
                - MALICIOUS_PROJECT_FIT_LEVELS.indexOf(left))),
        strongestObservedSeverity: strongestSeverity(findings),
        evidence: Object.freeze(evidenceUnbounded.slice(0, limits.evidencePerFinding)),
        independentPaths: Object.freeze(pathsUnbounded.slice(0, limits.pathsPerFinding)),
        provenance: Object.freeze({
            findingIds: Object.freeze(findings.map((finding) => finding.id)
                .slice(0, limits.aliasesPerFinding)),
            producers: Object.freeze(producersUnbounded.slice(0, limits.producersPerFinding)),
            crossValidationCount: unique(findings.map((finding) => finding.producer)).length,
            independentPathCount: pathsUnbounded.length,
        }),
        chainIds: Object.freeze(chainIdsUnbounded.slice(0, limits.chainsPerFinding)),
        validationChainIds: Object.freeze(validationChainIds.slice(0, limits.chainsPerFinding)),
        validatedChainIds: Object.freeze(validatedChainIds.slice(0, limits.chainsPerFinding)),
        nodeIds: Object.freeze(nodeIdsUnbounded.slice(0, limits.nodeIdsPerFinding)),
        edgeIds: Object.freeze(edgeIdsUnbounded.slice(0, limits.edgeIdsPerFinding)),
        truncation,
    });
}

function groupPriority(group) {
    const severity = SEVERITY_RANK[group.strongestObservedSeverity];
    const active = group.stateClass === "refuted" ? 0: 1;
    const state = group.stateClass === "validated" ? 2: group.stateClass === "unresolved" ? 1: 0;
    return { active, severity, state };
}

export function dedupeFindings({
    auditId,
    findings = [],
    traceSnapshot = null,
    validationSnapshot = null,
    limits: limitOverrides = {},
} = {}) {
    const normalizedAuditId = validateAuditId(auditId);
    if (traceSnapshot && traceSnapshot.auditId !== normalizedAuditId) {
        throw new Error("trace snapshot auditId does not match dedupe auditId");
    }
    const limits = normalizeLimits(limitOverrides);
    const adjudications = validationAdjudications(validationSnapshot, normalizedAuditId);
    const groups = new Map();
    const normalizedFindings = findings.map((entry, index) => {
        const finding = validateCandidateFinding(entry, `findings[${index}]`);
        if (finding.auditId !== normalizedAuditId) {
            throw new Error(`finding auditId does not match dedupe auditId: ${finding.id}`);
        }
        return finding;
    });

    for (const finding of normalizedFindings) {
        const chains = associatedChains(finding, traceSnapshot);
        const signature = normalizedMaliciousBehaviorSignature(finding, chains);
        const findingStateClass = stateClass(finding.state);
        const key = canonicalJson({ signature, stateClass: findingStateClass });
        let group = groups.get(key);
        if (!group) {
            group = {
                auditId: normalizedAuditId,
                signature,
                stateClass: findingStateClass,
                members: [],
            };
            groups.set(key, group);
        }
        group.members.push({
            finding,
            chains,
            adjudication: adjudications.get(finding.id) || null,
        });
    }

    const canonicalUnbounded = [...groups.values()]
        .map((group) => canonicalGroup(group, limits))
        .sort((left, right) => {
            const a = groupPriority(left);
            const b = groupPriority(right);
            return b.active - a.active
                || b.severity - a.severity
                || b.state - a.state
                || left.canonicalId.localeCompare(right.canonicalId);
        });
    const canonicalTruncated = canonicalUnbounded.length > limits.canonicalFindings;
    const canonicalFindings = canonicalUnbounded.slice(0, limits.canonicalFindings);
    const stateCounts = {
        candidate: 0,
        validating: 0,
        validated: 0,
        refuted: 0,
        unresolved: 0,
    };
    for (const finding of normalizedFindings) stateCounts[finding.state] += 1;
    const itemTruncated = canonicalFindings.some((finding) =>
        Object.values(finding.truncation).some(Boolean));
    const blockers = [];
    if (canonicalTruncated) {
        blockers.push({
            code: "canonical-finding-cap-exceeded",
            cap: limits.canonicalFindings,
            observed: canonicalUnbounded.length,
        });
    }
    if (itemTruncated) blockers.push({ code: "canonical-finding-detail-cap-exceeded" });
    const boundedBlockers = blockers.slice(0, limits.blockers);
    const blockersTruncated = blockers.length > boundedBlockers.length;
    const truncation = Object.freeze({
        canonicalFindings: canonicalTruncated,
        canonicalDetails: itemTruncated,
        blockers: blockersTruncated,
    });
    const inputFingerprint = digest("zerotrust-dedupe-input", {
        auditId: normalizedAuditId,
        findings: normalizedFindings,
        traceInputFingerprint: traceSnapshot?.inputFingerprint || null,
        validationInputFingerprint: validationSnapshot?.inputFingerprint || null,
        adjudications: validationSnapshot?.adjudications || [],
    });

    return Object.freeze(structuredClone({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: normalizedAuditId,
        inputFingerprint,
        coverageComplete: !Object.values(truncation).some(Boolean),
        counts: {
            sourceFindings: normalizedFindings.length,
            canonicalFindings: canonicalFindings.length,
            aliasesMerged: normalizedFindings.length - canonicalUnbounded.length,
        },
        stateCounts,
        truncation,
        blockers: boundedBlockers,
        canonicalFindings,
    }));
}

export const __internals = Object.freeze({
    canonicalJson,
    digest,
    normalizeLimits,
    stateClass,
    chainDescriptor,
    normalizedMaliciousBehaviorSignature,
    associatedChains,
});
