import { createHash } from "node:crypto";
import nodePath from "node:path";

import {
    ANALYSIS_SCHEMA_REVISION,
    BehaviorGraph,
    FindingLedger,
    computeFindingId,
    validateCandidateFinding,
    validateGraphEdge,
    validateGraphNode,
    validateSourceIdentity,
} from "../analysis/index.mjs";
import { ROLES } from "../council/roster.mjs";
import {
    advanceAnalysisStage,
    getAcquisitionCoverageState,
    getActiveAudit,
    getAnalysisIndexSnapshot,
    getAnalysisStageState,
    getIndexedSourceFile,
    getTreeEnumerationState,
    validateIndexedEvidenceReference,
} from "../enforcement.mjs";
import {
    modeUsesApiDirect,
    modeUsesCouncil,
    modeUsesLocalSource,
} from "../modes.mjs";
import { buildCoverageSnapshot } from "./coverageAccounting.mjs";
import {
    getCouncilLedgerSnapshot,
    mutateCouncilLedgerState,
} from "./state.mjs";
import { failure, success } from "./result.mjs";

export const COUNCIL_INGESTION_LIMITS = Object.freeze({
    serializedBytes: 128 * 1024,
    candidatesPerBatch: 32,
    nodesPerCandidate: 16,
    edgesPerCandidate: 32,
    nodesPerBatch: 256,
    edgesPerBatch: 512,
    coveragePerformed: 64,
    coverageSkipped: 64,
    coverageEntry: 512,
    benignHypothesis: 2048,
});

const SUBMIT_FIELDS = Object.freeze([
    "action",
    "schemaVersion",
    "audit_id",
    "producer_role_id",
    "producer_category",
    "source_identity",
    "coverage_performed",
    "coverage_skipped",
    "candidates",
]);
const FINALIZE_FIELDS = Object.freeze([
    "action",
    "schemaVersion",
    "audit_id",
    "successful_role_ids",
    "failed_role_ids",
    "deterministic_baseline_complete",
]);
const CANDIDATE_FIELDS = Object.freeze([
    "finding",
    "strongestBenignHypothesis",
    "coveragePerformed",
    "graph",
]);
const GRAPH_FIELDS = Object.freeze(["nodes", "edges"]);
const EFFECT_NODE_KINDS = new Set([
    "sink",
    "sensitive-source",
    "persistence",
    "propagation",
    "transform",
]);

function isPlainObject(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function assertExactFields(value, required, label, optional = []) {
    if (!isPlainObject(value)) throw new Error(`${label} must be a plain object`);
    const allowed = new Set([...required, ...optional]);
    for (const field of Object.keys(value)) {
        if (!allowed.has(field)) throw new Error(`${label}.${field} is not allowed`);
    }
    for (const field of required) {
        if (!Object.hasOwn(value, field)) throw new Error(`${label}.${field} is required`);
    }
}

function assertVersion(value) {
    if (value !== ANALYSIS_SCHEMA_REVISION) {
        throw new Error(`schemaVersion must equal ${ANALYSIS_SCHEMA_REVISION}`);
    }
}

function boundedString(value, label, max) {
    if (typeof value !== "string") throw new Error(`${label} must be a string`);
    const normalized = value.normalize("NFKC").trim();
    if (!normalized || normalized.length > max || normalized.includes("\0")) {
        throw new Error(`${label} must contain 1-${max} characters and no NUL`);
    }
    return normalized;
}

function boundedStringArray(value, label, maxItems) {
    if (!Array.isArray(value) || value.length > maxItems) {
        throw new Error(`${label} must be an array with at most ${maxItems} entries`);
    }
    const normalized = value.map((entry, index) =>
        boundedString(entry, `${label}[${index}]`, COUNCIL_INGESTION_LIMITS.coverageEntry));
    if (new Set(normalized).size !== normalized.length) {
        throw new Error(`${label} must not contain duplicate entries`);
    }
    return normalized;
}

function normalizeRoleIds(value, label) {
    if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
    const normalized = value.map((entry, index) =>
        boundedString(entry, `${label}[${index}]`, 64));
    if (new Set(normalized).size !== normalized.length) {
        throw new Error(`${label} must not contain duplicates`);
    }
    return normalized;
}

function pathsEqual(left, right) {
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase(): a === b;
}

function roleManifestForAudit(audit) {
    const configured = audit.councilRoleManifest || audit.councilRoles;
    const roles = Array.isArray(configured) && configured.length > 0
        ? configured: ROLES;
    return roles.map((role) => ({
        id: role.id,
        category: role.category,
        mandatory: role.mandatory === true,
    }));
}

function expectedNamespace(audit) {
    if (modeUsesLocalSource(audit.mode)) return `local-audit:${audit.auditId}`;
    return `github.com/${audit.owner}/${audit.repo}@${audit.resolvedSha}`;
}

function normalizeCurrentSourceIdentity(value, audit) {
    if (modeUsesLocalSource(audit.mode)) {
        assertExactFields(value, ["kind", "local_path"], "source_identity");
        if (value.kind !== "local") throw new Error("source_identity.kind must be local");
        if (typeof value.local_path !== "string"
            || !audit.localPath
            || !pathsEqual(value.local_path, audit.localPath)) {
            throw new Error("source_identity.local_path does not match the active audit");
        }
        return Object.freeze({
            kind: "local",
            local_path: nodePath.resolve(audit.localPath),
        });
    }

    assertExactFields(
        value,
        ["kind", "owner", "repo", "resolved_sha"],
        "source_identity",
    );
    if (value.kind !== "git") throw new Error("source_identity.kind must be git");
    if (!audit.owner || !audit.repo || !audit.resolvedSha) {
        throw new Error("active URL audit is not bound to owner/repo/full SHA");
    }
    const normalized = {
        kind: "git",
        owner: String(value.owner).toLowerCase(),
        repo: String(value.repo).toLowerCase(),
        resolved_sha: String(value.resolved_sha).toLowerCase(),
    };
    if (normalized.owner !== audit.owner
        || normalized.repo !== audit.repo
        || normalized.resolved_sha !== audit.resolvedSha) {
        throw new Error("source_identity does not match the active audit");
    }
    return Object.freeze(normalized);
}

function validateEvidenceReferenceAgainstIndex(evidence, {
    audit,
    sessionId,
    producerRoleId,
}) {
    if (evidence.producer !== producerRoleId) {
        throw new Error(`evidence producer must equal ${producerRoleId}`);
    }
    const expectedScope = modeUsesLocalSource(audit.mode)
        ? "local_source": "council_sample";
    if (evidence.coverageScope !== expectedScope) {
        throw new Error(
            `evidence coverageScope must be ${expectedScope}; candidate ingestion never satisfies mandatory acquisition`,
        );
    }
    return validateIndexedEvidenceReference(sessionId, {
        auditId: audit.auditId,
        path: evidence.path,
        startLine: evidence.startLine,
        endLine: evidence.endLine,
        excerptHash: evidence.excerptHash,
        blobSha: evidence.blobSha,
    });
}

function validateSourceIdentityAgainstIndex(sourceIdentity, {
    audit,
    sessionId,
}) {
    const normalized = validateSourceIdentity(sourceIdentity);
    const expectedType = modeUsesLocalSource(audit.mode) ? "local-file": "git-blob";
    if (normalized.type !== expectedType) {
        throw new Error(`finding sourceIdentity.type must be ${expectedType}`);
    }
    if (normalized.namespace !== expectedNamespace(audit)) {
        throw new Error("finding sourceIdentity.namespace does not match the active source");
    }
    const file = getIndexedSourceFile(sessionId, {
        auditId: audit.auditId,
        path: normalized.path,
    });
    if (!["indexed-text", "classified-binary"].includes(file.status)) {
        throw new Error(`finding source path is not fully indexed: ${normalized.path}`);
    }
    if (normalized.contentSha256 !== file.contentSha256) {
        throw new Error(`finding contentSha256 mismatch at ${normalized.path}`);
    }
    const expectedSourceBlobSha = modeUsesLocalSource(audit.mode)
        ? file.contentSha256: file.blobSha;
    if (expectedSourceBlobSha) {
        if (normalized.blobSha !== expectedSourceBlobSha) {
            throw new Error(`finding blob/content identity mismatch at ${normalized.path}`);
        }
    } else if (Object.hasOwn(normalized, "blobSha")) {
        throw new Error(
            `finding sourceIdentity.blobSha must be omitted when the indexed source has no Git blob identity: ${normalized.path}`,
        );
    }
    return normalized;
}

function validateAllEvidence(entries, context, label) {
    if (!Array.isArray(entries)) throw new Error(`${label} must be an array`);
    for (const evidence of entries) {
        validateEvidenceReferenceAgainstIndex(evidence, context);
    }
}

function canonicalizeCandidate(rawCandidate, context, candidateIndex) {
    const label = `candidates[${candidateIndex}]`;
    assertExactFields(rawCandidate, CANDIDATE_FIELDS, label);
    assertExactFields(rawCandidate.graph, GRAPH_FIELDS, `${label}.graph`);
    const strongestBenignHypothesis = boundedString(
        rawCandidate.strongestBenignHypothesis,
        `${label}.strongestBenignHypothesis`,
        COUNCIL_INGESTION_LIMITS.benignHypothesis,
    );
    const coveragePerformed = boundedStringArray(
        rawCandidate.coveragePerformed,
        `${label}.coveragePerformed`,
        COUNCIL_INGESTION_LIMITS.coveragePerformed,
    );
    if (coveragePerformed.length === 0) {
        throw new Error(`${label}.coveragePerformed must not be empty`);
    }

    if (!Array.isArray(rawCandidate.graph.nodes)
        || rawCandidate.graph.nodes.length < 3
        || rawCandidate.graph.nodes.length > COUNCIL_INGESTION_LIMITS.nodesPerCandidate) {
        throw new Error(
            `${label}.graph.nodes must contain 3-${COUNCIL_INGESTION_LIMITS.nodesPerCandidate} entries`,
        );
    }
    if (!Array.isArray(rawCandidate.graph.edges)
        || rawCandidate.graph.edges.length < 2
        || rawCandidate.graph.edges.length > COUNCIL_INGESTION_LIMITS.edgesPerCandidate) {
        throw new Error(
            `${label}.graph.edges must contain 2-${COUNCIL_INGESTION_LIMITS.edgesPerCandidate} entries`,
        );
    }

    const nodes = rawCandidate.graph.nodes.map((entry, index) => {
        const node = validateGraphNode(entry, `${label}.graph.nodes[${index}]`);
        if (node.auditId !== context.audit.auditId) {
            throw new Error(`${label}.graph.nodes[${index}] auditId mismatch`);
        }
        if (node.producer !== context.producerRoleId) {
            throw new Error(`${label}.graph.nodes[${index}] producer mismatch`);
        }
        validateAllEvidence(node.evidence, context, `${label}.graph.nodes[${index}].evidence`);
        if (node.sourceIdentity) {
            validateSourceIdentityAgainstIndex(node.sourceIdentity, context);
        }
        return node;
    });
    const nodeIds = new Set(nodes.map((node) => node.id));
    if (nodeIds.size !== nodes.length) throw new Error(`${label}.graph.nodes has duplicate IDs`);
    const hasActivation = nodes.some((node) =>
        node.kind === "activation" || node.kind === "trigger");
    const hasCapability = nodes.some((node) => node.kind === "capability");
    const hasEffect = nodes.some((node) => EFFECT_NODE_KINDS.has(node.kind));
    if (!hasActivation || !hasCapability || !hasEffect) {
        throw new Error(
            `${label}.graph must contain activation/trigger, capability, and effect/target nodes`,
        );
    }

    const edges = rawCandidate.graph.edges.map((entry, index) => {
        const edge = validateGraphEdge(entry, `${label}.graph.edges[${index}]`);
        if (edge.auditId !== context.audit.auditId) {
            throw new Error(`${label}.graph.edges[${index}] auditId mismatch`);
        }
        if (edge.producer !== context.producerRoleId) {
            throw new Error(`${label}.graph.edges[${index}] producer mismatch`);
        }
        if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) {
            throw new Error(`${label}.graph.edges[${index}] leaves its candidate graph fragment`);
        }
        validateAllEvidence(edge.evidence, context, `${label}.graph.edges[${index}].evidence`);
        return edge;
    });
    if (new Set(edges.map((edge) => edge.id)).size !== edges.length) {
        throw new Error(`${label}.graph.edges has duplicate IDs`);
    }

    if (!isPlainObject(rawCandidate.finding)) {
        throw new Error(`${label}.finding must be a plain object`);
    }
    const behaviorSignature = rawCandidate.finding.behaviorSignature;
    if (!isPlainObject(behaviorSignature)
        || typeof behaviorSignature.trigger !== "string"
        || typeof behaviorSignature.capability !== "string"
        || typeof behaviorSignature.action !== "string"
        || typeof behaviorSignature.target !== "string") {
        throw new Error(
            `${label}.finding.behaviorSignature requires activation(trigger), capability, effect(action), and target`,
        );
    }
    const sourceIdentity = validateSourceIdentityAgainstIndex(
        rawCandidate.finding.sourceIdentity,
        context,
    );
    const expectedId = computeFindingId(sourceIdentity, behaviorSignature);
    if (Object.hasOwn(rawCandidate.finding, "id")
        && rawCandidate.finding.id !== expectedId) {
        throw new Error(`${label}.finding.id conflicts with the derived finding ID`);
    }
    const finding = validateCandidateFinding({
        ...rawCandidate.finding,
        id: expectedId,
    }, `${label}.finding`);
    if (finding.auditId !== context.audit.auditId) {
        throw new Error(`${label}.finding auditId mismatch`);
    }
    if (finding.producer !== context.producerRoleId) {
        throw new Error(`${label}.finding producer mismatch`);
    }
    if (finding.state !== "candidate") {
        throw new Error(`${label}.finding must start in candidate state`);
    }
    if (finding.evidence.length === 0) {
        throw new Error(`${label}.finding.evidence must not be empty`);
    }
    validateAllEvidence(finding.evidence, context, `${label}.finding.evidence`);
    if (finding.nodeIds.length !== nodeIds.size
        || finding.nodeIds.some((id) => !nodeIds.has(id))) {
        throw new Error(`${label}.finding.nodeIds must exactly match its graph nodes`);
    }
    const edgeIds = new Set(edges.map((edge) => edge.id));
    if (finding.edgeIds.length !== edgeIds.size
        || finding.edgeIds.some((id) => !edgeIds.has(id))) {
        throw new Error(`${label}.finding.edgeIds must exactly match its graph edges`);
    }

    return Object.freeze({
        finding,
        strongestBenignHypothesis,
        coveragePerformed: Object.freeze(coveragePerformed),
        graph: Object.freeze({
            nodes: Object.freeze(nodes),
            edges: Object.freeze(edges),
        }),
    });
}

function digest(value) {
    return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function rebuildLedger(state, candidates, contexts) {
    const findingLedger = new FindingLedger({ auditId: state.auditId });
    const behaviorGraph = new BehaviorGraph({ auditId: state.auditId });
    for (const node of state.behaviorGraph.toDocument().nodes) behaviorGraph.addNode(node);
    for (const edge of state.behaviorGraph.toDocument().edges) behaviorGraph.addEdge(edge);
    for (const finding of state.findingLedger.toDocument().findings) {
        findingLedger.addCandidate(finding);
    }

    for (const candidate of candidates) {
        for (const node of candidate.graph.nodes) behaviorGraph.addNode(node);
        for (const edge of candidate.graph.edges) behaviorGraph.addEdge(edge);
        findingLedger.addCandidate(candidate.finding);
        const existingContext = contexts.get(candidate.finding.id);
        const nextContext = {
            producerRoleId: candidate.finding.producer,
            strongestBenignHypothesis: candidate.strongestBenignHypothesis,
            coveragePerformed: candidate.coveragePerformed,
        };
        if (existingContext
            && JSON.stringify(existingContext) !== JSON.stringify(nextContext)) {
            throw new Error(`conflicting candidate context for ${candidate.finding.id}`);
        }
        contexts.set(candidate.finding.id, nextContext);
    }
    return { findingLedger, behaviorGraph };
}

function handleSubmit(args, sessionId, audit, roles) {
    assertExactFields(args, SUBMIT_FIELDS, "candidate batch");
    assertVersion(args.schemaVersion);
    if (args.audit_id !== audit.auditId) {
        throw new Error("audit_id does not match the current active audit");
    }
    const role = roles.find((entry) => entry.id === args.producer_role_id);
    if (!role) throw new Error(`unknown council producer role: ${String(args.producer_role_id)}`);
    if (args.producer_category !== role.category) {
        throw new Error(
            `producer category mismatch for ${role.id}: expected ${role.category}`,
        );
    }
    const sourceIdentity = normalizeCurrentSourceIdentity(args.source_identity, audit);
    const coveragePerformed = boundedStringArray(
        args.coverage_performed,
        "coverage_performed",
        COUNCIL_INGESTION_LIMITS.coveragePerformed,
    );
    if (coveragePerformed.length === 0) {
        throw new Error("coverage_performed must not be empty");
    }
    const coverageSkipped = boundedStringArray(
        args.coverage_skipped,
        "coverage_skipped",
        COUNCIL_INGESTION_LIMITS.coverageSkipped,
    );
    if (!Array.isArray(args.candidates)
        || args.candidates.length > COUNCIL_INGESTION_LIMITS.candidatesPerBatch) {
        throw new Error(
            `candidates must contain at most ${COUNCIL_INGESTION_LIMITS.candidatesPerBatch} entries`,
        );
    }
    const stage = getAnalysisStageState(sessionId, { auditId: audit.auditId });
    if (!stage || !["prepared", "scanned", "traced", "validated", "finalized"].includes(stage.current)) {
        throw new Error(
            `invalid council ingestion stage: expected prepared or later, current is ${stage?.current || "missing"}`,
        );
    }
    const indexSnapshot = getAnalysisIndexSnapshot(sessionId, {
        auditId: audit.auditId,
    });
    if (indexSnapshot?.complete !== true) {
        throw new Error("analysis index is incomplete; council candidates require prepared source facts");
    }
    const context = {
        audit,
        sessionId,
        producerRoleId: role.id,
    };
    const candidates = args.candidates.map((candidate, index) =>
        canonicalizeCandidate(candidate, context, index));
    const nodeCount = candidates.reduce((sum, candidate) =>
        sum + candidate.graph.nodes.length, 0);
    const edgeCount = candidates.reduce((sum, candidate) =>
        sum + candidate.graph.edges.length, 0);
    if (nodeCount > COUNCIL_INGESTION_LIMITS.nodesPerBatch) {
        throw new Error(`batch graph node limit exceeded (${COUNCIL_INGESTION_LIMITS.nodesPerBatch})`);
    }
    if (edgeCount > COUNCIL_INGESTION_LIMITS.edgesPerBatch) {
        throw new Error(`batch graph edge limit exceeded (${COUNCIL_INGESTION_LIMITS.edgesPerBatch})`);
    }

    const canonicalBatch = Object.freeze({
        schemaVersion: ANALYSIS_SCHEMA_REVISION,
        auditId: audit.auditId,
        producerRoleId: role.id,
        producerCategory: role.category,
        sourceIdentity,
        coveragePerformed: Object.freeze(coveragePerformed),
        coverageSkipped: Object.freeze(coverageSkipped),
        candidates: Object.freeze(candidates),
    });
    const batchDigest = digest(canonicalBatch);

    let result;
    mutateCouncilLedgerState(sessionId, {
        auditId: audit.auditId,
        roles,
    }, (state) => {
        const existing = state.submissions.get(role.id);
        if (existing) {
            if (existing.digest !== batchDigest) {
                throw new Error(
                    `role ${role.id} already submitted a different immutable candidate batch`,
                );
            }
            result = {
                idempotent: true,
                candidateCount: existing.candidateCount,
                findingIds: existing.findingIds,
            };
            return;
        }
        if (state.finalization) {
            throw new Error("council scan is already finalized; new submissions are refused");
        }
        const contexts = new Map(state.candidateContexts);
        const rebuilt = rebuildLedger(state, candidates, contexts);
        state.findingLedger = rebuilt.findingLedger;
        state.behaviorGraph = rebuilt.behaviorGraph;
        state.candidateContexts = contexts;
        const findingIds = candidates.map((candidate) => candidate.finding.id);
        state.submissions.set(role.id, {
            digest: batchDigest,
            candidateCount: candidates.length,
            coveragePerformedCount: coveragePerformed.length,
            findingIds,
        });
        result = {
            idempotent: false,
            candidateCount: candidates.length,
            findingIds,
        };
    });

    const snapshot = getCouncilLedgerSnapshot(sessionId, { auditId: audit.auditId });
    return success({
        action: "submit",
        audit_id: audit.auditId,
        producer_role_id: role.id,
        producer_category: role.category,
        recorded: true,
        idempotent: result.idempotent,
        candidate_count: result.candidateCount,
        finding_ids: result.findingIds,
        total_recorded_roles: snapshot.submissions.length,
        total_findings: snapshot.findingLedger.findings.length,
        total_graph_nodes: snapshot.behaviorGraph.nodes.length,
        total_graph_edges: snapshot.behaviorGraph.edges.length,
        mandatory_acquisition_satisfied_by_ingestion: false,
        analysis_stage: stage.current,
    });
}

function handleFinalize(args, sessionId, audit, roles) {
    assertExactFields(args, FINALIZE_FIELDS, "scan finalization");
    assertVersion(args.schemaVersion);
    if (args.audit_id !== audit.auditId) {
        throw new Error("audit_id does not match the current active audit");
    }
    if (args.deterministic_baseline_complete !== true) {
        throw new Error("deterministic_baseline_complete must be true");
    }
    const successfulRoleIds = normalizeRoleIds(
        args.successful_role_ids,
        "successful_role_ids",
    );
    const failedRoleIds = normalizeRoleIds(args.failed_role_ids, "failed_role_ids");
    const successful = new Set(successfulRoleIds);
    const failed = new Set(failedRoleIds);
    for (const roleId of successful) {
        if (failed.has(roleId)) throw new Error(`role appears in both partitions: ${roleId}`);
    }
    const expectedIds = roles.map((role) => role.id);
    const provided = [...successful, ...failed];
    if (provided.length !== expectedIds.length
        || expectedIds.some((roleId) => !successful.has(roleId) && !failed.has(roleId))
        || provided.some((roleId) => !expectedIds.includes(roleId))) {
        throw new Error("successful_role_ids and failed_role_ids must partition the active council manifest");
    }

    const mandatoryMissing = roles
        .filter((role) => role.mandatory && !successful.has(role.id))
        .map((role) => role.id);
    const categories = [...new Set(roles.map((role) => role.category))].sort();
    const missingCategories = categories.filter((category) =>
        !roles.some((role) => role.category === category && successful.has(role.id)));
    const coverageFloor = Math.ceil(roles.length * 0.9);
    if (mandatoryMissing.length > 0
        || missingCategories.length > 0
        || successful.size < coverageFloor) {
        throw new Error(
            `council gates failed: mandatoryMissing=${mandatoryMissing.join(",") || "none"}; missingCategories=${missingCategories.join(",") || "none"}; successful=${successful.size}/${roles.length}; required=${coverageFloor}`,
        );
    }

    const snapshot = getCouncilLedgerSnapshot(sessionId, { auditId: audit.auditId });
    const recordedRoles = new Set(snapshot?.submissions.map((entry) => entry.roleId) || []);
    if (recordedRoles.size !== successful.size
        || [...successful].some((roleId) => !recordedRoles.has(roleId))) {
        throw new Error("candidate submissions are incomplete for the successful role set");
    }
    if (modeUsesApiDirect(audit.mode)) {
        const acquisitionCoverage = buildCoverageSnapshot(
            getAcquisitionCoverageState(sessionId),
            getTreeEnumerationState(sessionId),
        );
        if (acquisitionCoverage.requiredAcquisitionComplete !== true) {
            throw new Error(
                "mandatory acquisition is incomplete; candidate ingestion does not satisfy it",
            );
        }
    }
    const indexSnapshot = getAnalysisIndexSnapshot(sessionId, {
        auditId: audit.auditId,
    });
    if (indexSnapshot?.complete !== true) {
        throw new Error("analysis index is incomplete; council scan cannot be finalized");
    }

    const finalization = Object.freeze({
        successfulRoleIds: Object.freeze([...successfulRoleIds]),
        failedRoleIds: Object.freeze([...failedRoleIds]),
        deterministicBaselineComplete: true,
    });
    const finalizationDigest = digest(finalization);
    let idempotent = false;
    let stage;
    mutateCouncilLedgerState(sessionId, {
        auditId: audit.auditId,
        roles,
    }, (state) => {
        if (state.finalization) {
            if (state.finalization.digest !== finalizationDigest) {
                throw new Error("council scan finalization is immutable");
            }
            idempotent = true;
            stage = getAnalysisStageState(sessionId, { auditId: audit.auditId });
            return;
        }
        const current = getAnalysisStageState(sessionId, { auditId: audit.auditId });
        if (current?.current !== "prepared") {
            throw new Error(
                `illegal council scan transition: expected prepared, current is ${current?.current || "missing"}`,
            );
        }
        stage = advanceAnalysisStage(sessionId, {
            auditId: audit.auditId,
            from: "prepared",
            to: "scanned",
        });
        state.finalization = Object.freeze({
            ...finalization,
            digest: finalizationDigest,
        });
    });

    const finalSnapshot = getCouncilLedgerSnapshot(sessionId, { auditId: audit.auditId });
    return success({
        action: "finalize",
        audit_id: audit.auditId,
        finalized: true,
        idempotent,
        analysis_stage: stage.current,
        successful_roles: successfulRoleIds.length,
        failed_roles: failedRoleIds.length,
        coverage_floor: coverageFloor,
        mandatory_roles_complete: true,
        categories_complete: true,
        candidate_submissions_complete: true,
        deterministic_baseline_complete: true,
        total_findings: finalSnapshot.findingLedger.findings.length,
        total_graph_nodes: finalSnapshot.behaviorGraph.nodes.length,
        total_graph_edges: finalSnapshot.behaviorGraph.edges.length,
        mandatory_acquisition_satisfied_by_ingestion: false,
    });
}

export async function recordCouncilCandidatesHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) {
        return failure(
            "record_council_candidates requires a real sessionId and active audit",
        );
    }
    let serializedBytes;
    try {
        serializedBytes = Buffer.byteLength(JSON.stringify(args), "utf8");
    } catch {
        return failure("candidate input must be JSON-serializable");
    }
    if (serializedBytes > COUNCIL_INGESTION_LIMITS.serializedBytes) {
        return failure(
            `candidate input exceeds ${COUNCIL_INGESTION_LIMITS.serializedBytes} serialized bytes`,
        );
    }
    const audit = getActiveAudit(sessionId);
    if (!audit) return failure("record_council_candidates requires an active audit");
    if (!modeUsesCouncil(audit.mode)) {
        return failure("record_council_candidates is available only in council modes");
    }
    const roles = roleManifestForAudit(audit);
    try {
        if (args.action === "submit") {
            return handleSubmit(args, sessionId, audit, roles);
        }
        if (args.action === "finalize") {
            return handleFinalize(args, sessionId, audit, roles);
        }
        return failure("action must be submit or finalize");
    } catch (err) {
        return failure(`record_council_candidates refused: ${err.message}`, {
            audit_id: audit.auditId,
        });
    }
}

export const __internals = Object.freeze({
    SUBMIT_FIELDS,
    FINALIZE_FIELDS,
    CANDIDATE_FIELDS,
    GRAPH_FIELDS,
    EFFECT_NODE_KINDS,
    assertExactFields,
    boundedStringArray,
    expectedNamespace,
    normalizeCurrentSourceIdentity,
    validateEvidenceReferenceAgainstIndex,
    validateSourceIdentityAgainstIndex,
    canonicalizeCandidate,
    digest,
});
