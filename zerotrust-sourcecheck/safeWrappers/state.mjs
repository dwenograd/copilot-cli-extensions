// safeWrappers/state.mjs
//
// Module-level session state shared by the safe-wrapper tools. This is
// the substitutional-safety equivalent of v2's enforcement.mjs::activeAudits
// — but where activeAudits guards a hook that doesn't actually fire in
// the current Copilot CLI runtime (Step 0.2 finding), this state guards
// behavior INSIDE the wrapper tool implementations themselves. The agent
// must call our tools, our tools own the dangerous commands, our tools
// check this state before executing.

const recordedOutcomes = new Map(); // sessionId -> { verdict, criticalCount, highCount, complete, recordedAt }

const COMPLETE_VERDICTS_THAT_PASS = new Set([
    "no red flags found",
    "low",
]);

/**
 * Record the council's outcome for a session.
 */
export function recordCouncilOutcome(sessionId, { verdict, criticalCount, highCount, complete }) {
    if (!sessionId) throw new Error("recordCouncilOutcome requires sessionId");
    recordedOutcomes.set(sessionId, {
        verdict: String(verdict || ""),
        criticalCount: Number(criticalCount) || 0,
        highCount: Number(highCount) || 0,
        complete: !!complete,
        recordedAt: Date.now(),
    });
}

export function getRecordedOutcome(sessionId) {
    return recordedOutcomes.get(sessionId) || null;
}

export function clearRecordedOutcome(sessionId) {
    recordedOutcomes.delete(sessionId);
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
    COMPLETE_VERDICTS_THAT_PASS,
};
