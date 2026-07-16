// safeWrappers/state.mjs
//
// Module-level session state shared by the safe-wrapper tools. This is
// the substitutional-safety counterpart to enforcement.mjs::activeAudits.
// activeAudits guards a hook that doesn't actually fire in
// the current Copilot CLI runtime (Step 0.2 finding), this state guards
// behavior INSIDE the wrapper tool implementations themselves. The agent
// must call our tools, our tools own the dangerous commands, our tools
// check this state before executing.

import {
    BehaviorGraph,
    FindingLedger,
    buildValidationSnapshot,
    validateAuditId,
} from "../analysis/index.mjs";

const recordedOutcomes = new Map(); // sessionId -> council result bound to one immutable audit identity
const councilLedgers = new Map(); // sessionId -> audit-bound baseline candidate/graph state
const cacheBindings = new Map(); // sessionId -> active-audit-derived cache identity/path metadata

/**
 * Record the council's outcome for a session. The first write for an audit
 * identity is immutable; exact normalized retries are idempotent.
 */
export function recordCouncilOutcome(sessionId, {
    auditId,
    owner = null,
    repo = null,
    resolvedSha = null,
    verdict,
    criticalCount,
    highCount,
    complete,
}) {
    if (!sessionId) throw new Error("recordCouncilOutcome requires sessionId");
    if (typeof auditId !== "string" || auditId.length === 0) {
        throw new Error("recordCouncilOutcome requires auditId");
    }
    const normalizedSha = resolvedSha === null ? null: String(resolvedSha).toLowerCase();
    if (normalizedSha !== null && !/^[a-f0-9]{40}$/.test(normalizedSha)) {
        throw new Error("recordCouncilOutcome resolvedSha must be null or a full 40-character SHA");
    }
    const normalized = {
        auditId,
        owner: owner === null ? null: String(owner).toLowerCase(),
        repo: repo === null ? null: String(repo).toLowerCase(),
        resolvedSha: normalizedSha,
        verdict: String(verdict || ""),
        criticalCount: Number(criticalCount) || 0,
        highCount: Number(highCount) || 0,
        complete: !!complete,
        recordedAt: Date.now(),
    };
    const existing = recordedOutcomes.get(sessionId);
    if (existing) {
        const immutableFields = [
            "auditId",
            "owner",
            "repo",
            "resolvedSha",
            "verdict",
            "criticalCount",
            "highCount",
            "complete",
        ];
        const identical = immutableFields.every((field) => existing[field] === normalized[field]);
        if (identical) return existing;
        throw new Error("council outcome is immutable after first write for this audit identity");
    }
    recordedOutcomes.set(sessionId, normalized);
    return normalized;
}

export function councilOutcomeMatchesAudit(outcome, audit) {
    if (!outcome || !audit) return false;
    return outcome.auditId === audit.auditId
        && outcome.owner === (audit.owner || null)
        && outcome.repo === (audit.repo || null)
        && outcome.resolvedSha === (audit.resolvedSha || null);
}

export function getRecordedOutcome(sessionId) {
    return recordedOutcomes.get(sessionId) || null;
}

export function clearRecordedOutcome(sessionId) {
    return recordedOutcomes.delete(sessionId);
}

export function recordCacheBinding(sessionId, {
    auditId,
    sourceKey,
    namespaceKey,
    cachePath,
} = {}) {
    if (!sessionId) throw new Error("cache binding requires sessionId");
    const normalizedAuditId = validateAuditId(auditId);
    if (!/^[a-f0-9]{64}$/u.test(String(sourceKey || ""))) {
        throw new Error("cache binding requires a canonical sourceKey");
    }
    if (!/^[a-f0-9]{64}$/u.test(String(namespaceKey || ""))) {
        throw new Error("cache binding requires a canonical namespaceKey");
    }
    if (typeof cachePath !== "string" || cachePath.length === 0) {
        throw new Error("cache binding requires cachePath");
    }
    const normalized = Object.freeze({
        auditId: normalizedAuditId,
        sourceKey,
        namespaceKey,
        cachePath,
    });
    const existing = cacheBindings.get(sessionId);
    if (existing && JSON.stringify(existing) !== JSON.stringify(normalized)) {
        throw new Error("cache binding is immutable for the active audit identity");
    }
    cacheBindings.set(sessionId, normalized);
    return structuredClone(normalized);
}

export function getCacheBinding(sessionId, { auditId } = {}) {
    const binding = cacheBindings.get(sessionId);
    if (!binding) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== binding.auditId) {
        throw new Error("cache binding auditId does not match requested audit");
    }
    return structuredClone(binding);
}

export function clearCacheBinding(sessionId) {
    return cacheBindings.delete(sessionId);
}

function normalizeCouncilRoles(roles) {
    if (!Array.isArray(roles) || roles.length === 0) {
        throw new Error("council ledger requires a non-empty role manifest");
    }
    const seen = new Set();
    return Object.freeze(roles.map((role, index) => {
        const id = String(role?.id || "");
        const category = String(role?.category || "");
        if (!/^[a-z][a-z0-9-]{2,63}$/.test(id)) {
            throw new Error(`invalid council role id at index ${index}`);
        }
        if (!/^[A-G]$/.test(category)) {
            throw new Error(`invalid council role category for ${id}`);
        }
        if (seen.has(id)) throw new Error(`duplicate council role id: ${id}`);
        seen.add(id);
        return Object.freeze({
            id,
            category,
            mandatory: role?.mandatory === true,
        });
    }));
}

function roleManifestsMatch(left, right) {
    return JSON.stringify(left) === JSON.stringify(right);
}

function createCouncilLedgerState(auditId, roles) {
    return {
        auditId,
        roles,
        findingLedger: new FindingLedger({ auditId }),
        behaviorGraph: new BehaviorGraph({ auditId }),
        submissions: new Map(),
        candidateContexts: new Map(),
        finalization: null,
        validationState: null,
        decisionSnapshot: null,
    };
}

/**
 * Mutate the current audit identity's candidate ledger synchronously.
 * The wrapper owns validation and atomic replacement of ledger/graph objects;
 * this function owns session/audit/role-manifest binding.
 */
export function mutateCouncilLedgerState(sessionId, {
    auditId,
    roles,
} = {}, mutator) {
    if (!sessionId) throw new Error("council ledger requires sessionId");
    if (typeof mutator !== "function") throw new Error("council ledger requires mutator");
    const normalizedAuditId = validateAuditId(auditId);
    const normalizedRoles = normalizeCouncilRoles(roles);
    let state = councilLedgers.get(sessionId);
    if (!state) {
        state = createCouncilLedgerState(normalizedAuditId, normalizedRoles);
        councilLedgers.set(sessionId, state);
    } else {
        if (state.auditId !== normalizedAuditId) {
            throw new Error("council ledger auditId does not match current audit identity");
        }
        if (!roleManifestsMatch(state.roles, normalizedRoles)) {
            throw new Error("council ledger role manifest is immutable for this audit identity");
        }
    }
    return mutator(state);
}

export function getCouncilLedgerSnapshot(sessionId, { auditId } = {}) {
    const state = councilLedgers.get(sessionId);
    if (!state) return null;
    if (auditId !== undefined && validateAuditId(auditId) !== state.auditId) {
        throw new Error("council ledger auditId does not match requested audit");
    }
    return structuredClone({
        auditId: state.auditId,
        roles: state.roles,
        submissions: [...state.submissions.entries()].map(([roleId, submission]) => ({
            roleId,
            digest: submission.digest,
            candidateCount: submission.candidateCount,
            coveragePerformedCount: submission.coveragePerformedCount,
        })),
        candidateContexts: [...state.candidateContexts.entries()].map(([findingId, context]) => ({
            findingId,
            ...context,
        })),
        findingLedger: state.findingLedger.toDocument(),
        behaviorGraph: state.behaviorGraph.toDocument(),
        finalization: state.finalization,
        validation: buildValidationSnapshot(state.validationState),
        decisionSnapshot: state.decisionSnapshot,
    });
}

export function clearCouncilLedgerState(sessionId) {
    return councilLedgers.delete(sessionId);
}

/**
 * Deprecated compatibility evaluator for caller-recorded baseline outcomes.
 * Host builds no longer consume this state; they require the durable report
 * finalization record and its finalizer-derived trusted outcome.
 */
export function evaluateCouncilGate(outcome) {
    if (!outcome) {
        return {
            passes: false,
            reason: "deprecated council outcome not recorded",
        };
    }
    if (!outcome.complete) {
        return {
            passes: false,
            reason: "deprecated council outcome is incomplete",
        };
    }
    if (outcome.verdict === "critical"
        || outcome.verdict === "high"
        || outcome.criticalCount > 0
        || outcome.highCount > 0) {
        return {
            passes: false,
            reason:
                `deprecated council outcome contains critical/high behavior (verdict=${outcome.verdict})`,
        };
    }
    return {
        passes: true,
        reason:
            `deprecated council outcome is complete without critical/high behavior (verdict=${outcome.verdict})`,
    };
}

export const __internals = {
    recordedOutcomes,
    councilLedgers,
    cacheBindings,
};
