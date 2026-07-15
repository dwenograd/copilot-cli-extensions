// safeWrappers/state.mjs
//
// Module-level session state shared by the safe-wrapper tools. This is
// the substitutional-safety equivalent of v2's enforcement.mjs::activeAudits
// — but where activeAudits guards a hook that doesn't actually fire in
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
const councilLedgers = new Map(); // sessionId -> audit-bound v5 candidate/graph state
const cacheBindings = new Map(); // sessionId -> active-audit-derived cache identity/path metadata

const COMPLETE_VERDICTS_THAT_PASS = new Set([
    "no red flags found",
    "low",
]);

/**
 * Record the council's outcome for a session. The first write for an audit
 * generation is immutable; exact normalized retries are idempotent.
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
    const normalizedSha = resolvedSha === null ? null : String(resolvedSha).toLowerCase();
    if (normalizedSha !== null && !/^[a-f0-9]{40}$/.test(normalizedSha)) {
        throw new Error("recordCouncilOutcome resolvedSha must be null or a full 40-character SHA");
    }
    const normalized = {
        auditId,
        owner: owner === null ? null : String(owner).toLowerCase(),
        repo: repo === null ? null : String(repo).toLowerCase(),
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
        throw new Error("council outcome is immutable after first write for this audit generation");
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
        throw new Error("cache binding is immutable for the active audit generation");
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
 * Mutate the current audit generation's candidate ledger synchronously.
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
            throw new Error("council ledger auditId does not match current audit generation");
        }
        if (!roleManifestsMatch(state.roles, normalizedRoles)) {
            throw new Error("council ledger role manifest is immutable for this audit generation");
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
 * Decide whether a recorded council outcome passes the build-council gate.
 *
 * The two override flags are STRICTLY ORTHOGONAL:
 *   - `overrideOnFailure` (`proceed_on_council_failure: true`) bypasses ONLY
 *     the incompleteness check. After it bypasses incompleteness, the
 *     severity-verdict check still applies — so an incomplete-council audit
 *     that nonetheless emitted `verdict: "critical"` will STILL be blocked
 *     unless `override` (`council_build_override: true`) is also set.
 *   - `override` bypasses ONLY the severity check. It does NOT bypass
 *     incompleteness on its own.
 *
 * Both flags must be set explicitly to bypass both protections — one flag
 * cannot accidentally bypass the other (per Triple-Duck Finding #3 + the
 * gpt-5.5 reviewer's confirmation in the v3.1 hardening pass).
 */
export function evaluateCouncilGate(outcome, { override = false, overrideOnFailure = false } = {}) {
    if (!outcome) {
        return {
            passes: false,
            reason: "council outcome not recorded — call zerotrust_record_council_outcome first",
        };
    }

    const incomplete = !outcome.complete;
    if (incomplete && !overrideOnFailure) {
        return {
            passes: false,
            reason: "council INCOMPLETE; gate stays closed unless proceed_on_council_failure: true",
        };
    }

    // At this point: either the council is complete, OR overrideOnFailure
    // bypassed the incompleteness gate. Either way, we still apply the
    // severity-verdict check.
    const severityPasses = COMPLETE_VERDICTS_THAT_PASS.has(outcome.verdict);
    if (severityPasses) {
        const completionNote = incomplete
            ? `INCOMPLETE; opened via proceed_on_council_failure`
            : `complete`;
        return {
            passes: true,
            reason: `council ${completionNote}; verdict=${outcome.verdict}, critical=${outcome.criticalCount}, high=${outcome.highCount}`,
        };
    }
    if (override) {
        const completionNote = incomplete
            ? `INCOMPLETE; opened via proceed_on_council_failure + council_build_override`
            : `complete`;
        return {
            passes: true,
            reason: `council ${completionNote}; verdict=${outcome.verdict} bypassed via council_build_override (critical=${outcome.criticalCount}, high=${outcome.highCount})`,
        };
    }
    const completionNote = incomplete ? "INCOMPLETE (proceed_on_council_failure was set)" : "complete";
    return {
        passes: false,
        reason: `council ${completionNote} but verdict ${outcome.verdict} (critical=${outcome.criticalCount}, high=${outcome.highCount}) does not pass; gate closed unless council_build_override: true`,
    };
}

export const __internals = {
    recordedOutcomes,
    councilLedgers,
    cacheBindings,
    COMPLETE_VERDICTS_THAT_PASS,
};
