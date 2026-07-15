import { modeUsesCouncil } from "../modes.mjs";

export function renderTraceStage(context = {}) {
    if (!modeUsesCouncil(context.mode)) return "";
    const auditId = context.auditId || "<unavailable: no session identity>";
    return `

---

## Required trace stage — audit-bound behavior graph (before validators)

After \`zerotrust_record_council_candidates({ action: "finalize", ... })\`
successfully records stage \`scanned\`, and **before** launching category
sub-judges, the meta-judge, or any other validator, call:

\`\`\`
const traceResult = zerotrust_trace_behavior_graph({
  audit_id: ${JSON.stringify(auditId)}
})
\`\`\`

The wrapper merges the deterministic plugin graph seeds with the finalized
council graph fragments. It revalidates exact audit, source namespace,
content/blob identity, indexed line range, and excerpt-hash identity. Identical
nodes/edges and identical retries are idempotent. It never returns source text.

Require all of these before treating synthesis as complete:

- \`traceResult.coverageComplete === true\`
- \`traceResult.analysisStageAfter === "traced"\`
- every value in \`traceResult.gates\` is \`true\`
- every \`traceResult.truncation\` flag is \`false\`

The tracer explicitly prioritizes these stable semantic chain classes:

1. \`install-fetch-decode-execute\`
2. \`credential-read-transform-send\`
3. \`startup-persistence\`
4. \`ai-instruction-tool-effect\`
5. \`ci-trigger-secret-external-sink\`

Chain IDs are derived from normalized node/edge semantics and exact evidence
identity, never labels, summaries, or model prose. Cross-file chains are valid
only when explicit submitted edges connect them. Partial paths remain
\`status: "unresolved"\`; do not add a missing fetch/decode/send/effect edge.
Cycles are bounded and surfaced as unresolved rather than recursively expanded.

\`traceResult.validationQueue\` contains contradictory IDs or edge transitions
that the merger quarantined. Validators must adjudicate those entries using the
referenced node/edge IDs and evidence; they must not select the more alarming
narrative. A contested edge is never traversed as if it were established.

Pass this structured handoff to every category sub-judge and the meta-judge:

\`\`\`json
{
  "traceCoverageComplete": "<traceResult.coverageComplete>",
  "traceCounts": "<traceResult.counts>",
  "chains": "<traceResult.chains>",
  "validationQueue": "<traceResult.validationQueue>",
  "cycles": "<traceResult.cycles>",
  "traceBlockers": "<traceResult.blockers>",
  "traceTruncation": "<traceResult.truncation>"
}
\`\`\`

Validators may cluster or refute chains, but must preserve each chain ID,
status, ordered steps/links, exact evidence pointers, cross-file flag, and
unresolved reason. They must not manufacture graph topology from prose.

If tracing is refused, incomplete, conflicted, identity-mismatched, or
truncated, stop trusted synthesis. Preserve the returned partial chains and
validation queue in the report as incomplete evidence, record only
\`verdict: "incomplete", complete: false\`, and do not claim a trusted
critical/high/medium/low/no-red-flags verdict.
`;
}
