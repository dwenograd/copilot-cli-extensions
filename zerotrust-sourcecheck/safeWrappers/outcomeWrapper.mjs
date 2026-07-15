// safeWrappers/outcomeWrapper.mjs — zerotrust_record_council_outcome tool.
//
// Every council mode calls this after synthesis (or its incomplete fallback)
// and before report finalization. Council-build modes additionally need the
// same immutable outcome before zerotrust_safe_build.

import { recordCouncilOutcome } from "./state.mjs";
import {
    getAcquisitionCoverageState,
    getActiveAudit,
    getAnalysisStageState,
    getTreeEnumerationState,
} from "../enforcement.mjs";
import { modeUsesApiDirect } from "../modes.mjs";
import { buildCoverageSnapshot } from "./coverageAccounting.mjs";

const VERDICTS = new Set([
    "critical",
    "high",
    "medium",
    "low",
    "no red flags found",
    "incomplete",
]);

export async function recordOutcomeHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) {
        return failure("internal: sessionId not provided to record_council_outcome; refusing to record outcome under shared-key bucket");
    }
    if (typeof args.verdict !== "string" || !VERDICTS.has(args.verdict)) {
        return failure(`verdict must be one of: ${[...VERDICTS].join(" | ")}`);
    }
    if (!Number.isInteger(args.critical_count) || args.critical_count < 0) {
        return failure("critical_count must be a non-negative integer");
    }
    if (!Number.isInteger(args.high_count) || args.high_count < 0) {
        return failure("high_count must be a non-negative integer");
    }
    if (typeof args.complete !== "boolean") {
        return failure("complete must be boolean");
    }

    // Round-10 hardening (gpt-5.5 R10 F1): reject the logically-impossible
    // combination `verdict: "incomplete"` + `complete: true`. The
    // "incomplete" verdict is supposed to mean the council aborted before
    // producing a real verdict; recording it as `complete=true` would let
    // a `council_build_override` (severity-only) bypass open the gate
    // without `proceed_on_council_failure` (incompleteness) being set.
    if (args.verdict === "incomplete" && args.complete !== false) {
        return failure(`inconsistent outcome: verdict 'incomplete' must be recorded with complete=false`);
    }

    // Round-3 hardening (gpt-5.5 F1): reject inconsistent verdict/counts.
    // The meta-judge is supposed to set verdict and counts together, but
    // a buggy or compromised judge could record { verdict: "low",
    // critical_count: 5 } and the gate would still pass. Reject when the
    // verdict is in the auto-pass set but counts indicate severe findings.
    const PASS_VERDICTS = new Set(["no red flags found", "low"]);
    if (PASS_VERDICTS.has(args.verdict) && (args.critical_count > 0 || args.high_count > 0)) {
        return failure(`inconsistent outcome: verdict '${args.verdict}' but critical_count=${args.critical_count}, high_count=${args.high_count}. Pass-verdicts must have critical=0 AND high=0.`);
    }
    // Symmetrically: critical/high verdicts must have nonzero counts of that severity
    if (args.verdict === "critical" && args.critical_count === 0) {
        return failure(`inconsistent outcome: verdict 'critical' but critical_count=0`);
    }
    if (args.verdict === "high" && args.critical_count === 0 && args.high_count === 0) {
        return failure(`inconsistent outcome: verdict 'high' but critical_count=0 AND high_count=0`);
    }

    const activeAudit = getActiveAudit(sessionId);
    if (!activeAudit) {
        return failure("record_council_outcome requires an active audit for this session");
    }
    if (typeof args.audit_id !== "string" || args.audit_id.length === 0) {
        return failure("audit_id is required and must be the immutable audit ID returned in the sourcecheck packet");
    }
    if (args.audit_id !== activeAudit.auditId) {
        return failure(
            `record_council_outcome refused: audit_id ${JSON.stringify(args.audit_id)} does not match the current active audit`,
        );
    }
    if (!activeAudit.localPath
        && (!activeAudit.owner || !activeAudit.repo || !activeAudit.resolvedSha)) {
        return failure(
            "record_council_outcome refused: active URL audit is not fully bound to owner/repo/full resolved SHA",
        );
    }
    if (activeAudit.councilRoleManifest && args.complete === true) {
        const stage = getAnalysisStageState(sessionId, {
            auditId: activeAudit.auditId,
        });
        const completedValidationStages = new Set(["validated", "finalized"]);
        if (!stage || !completedValidationStages.has(stage.current)) {
            return failure(
                "record_council_outcome refused: a complete council outcome requires successful audit-bound candidate submission, graph tracing, and independent confirm/refute/adjudication (analysis stage validated or later)",
            );
        }
    }

    let acquisitionCoverage = null;
    if (activeAudit && modeUsesApiDirect(activeAudit.mode)) {
        acquisitionCoverage = buildCoverageSnapshot(
            getAcquisitionCoverageState(sessionId),
            getTreeEnumerationState(sessionId),
        );
        if (acquisitionCoverage.requiredAcquisitionComplete !== true
            && (args.verdict !== "incomplete" || args.complete !== false)) {
            return failure(
                "inconsistent outcome: incomplete mandatory acquisition coverage permits only verdict 'incomplete' with complete=false. Fetch every enumerated blob with coverage_scope='mandatory'; each must be byte-classified, and every text result must be fully returned and invisible-Unicode scanned. Otherwise record an incomplete outcome.",
                { acquisitionCoverage },
            );
        }
    }

    let recorded;
    try {
        recorded = recordCouncilOutcome(sessionId, {
            auditId: activeAudit.auditId,
            owner: activeAudit.owner || null,
            repo: activeAudit.repo || null,
            resolvedSha: activeAudit.resolvedSha || null,
            verdict: args.verdict,
            criticalCount: args.critical_count,
            highCount: args.high_count,
            complete: args.complete,
        });
    } catch (err) {
        return failure(`record failed: ${err.message}`);
    }

    return success({
        verdict: args.verdict,
        critical_count: args.critical_count,
        high_count: args.high_count,
        complete: args.complete,
        immutable: true,
        recordedAt: recorded.recordedAt,
        audit_id: activeAudit.auditId,
        sessionId: sessionId.slice(0, 12),
        ...(acquisitionCoverage ? { acquisitionCoverage } : {}),
    });
}

function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, recorded: true, ...data }, null, 2),
        resultType: "success",
    };
}

function failure(message, data = {}) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, error: message, ...data }, null, 2),
        resultType: "failure",
    };
}

export const __internals = {
    VERDICTS,
};
