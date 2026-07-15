import { renderSpawnArgs } from "../../_shared/index.mjs";
import { modeUsesCouncil } from "../modes.mjs";

export function renderValidateStage(context = {}) {
    if (!modeUsesCouncil(context.mode)) return "";
    const auditId = context.auditId || "<unavailable: no session identity>";
    const minSeverity = context.validationMinSeverity || "high";
    const confirmModel = context.councilJudgeModel || "gpt-5.6-sol";
    const refuteModel = context.councilSubJudgeModel || "claude-opus-4.8";
    const adjudicatorModel = context.councilJudgeModel || "gpt-5.6-sol";
    return `

---

## Required validation stage — independent confirm, refute, adjudicate

This stage runs immediately after the trace wrapper records \`traced\` and
**before** category sub-judges or the meta-judge. The audit's immutable
validation floor is \`${minSeverity}\`: every critical/high candidate is always
required, and lower candidates at or above that configured floor are also
required.

### Step V1 — Prepare the audit-bound validation queue

Call:

\`\`\`
let validationCursor = 0
const validationPages = []
do {
  const page = zerotrust_record_validation({
    action: "prepare",
    schemaVersion: 5,
    audit_id: ${JSON.stringify(auditId)},
    cursor: validationCursor,
    limit: 8
  })
  validationPages.push(page)
  validationCursor = page.page.nextCursor
} while (validationCursor !== null)
\`\`\`

Preparation rechecks the exact audit, candidate ledger, complete untruncated
trace, graph identities, and index identities. It atomically moves every
required finding \`candidate → validating\`. Each returned context is bounded
and source-text-free: candidate metadata, existing evidence pointers, associated
chain IDs, a graph neighborhood without labels/snippets, and normalized index
facts. If \`validation.truncation\` contains any true value, trusted validation
cannot finish; retain the candidates as unresolved partial evidence and record
only an incomplete council outcome.

### Step V2 — Launch two independent static validators per candidate

For each returned context, materialize the strict prompts from
\`council/validationPromptTemplate.mjs\`: one CONFIRM prompt and one REFUTE
prompt. Generate a fresh injection nonce per prompt. Both prompts must begin
with the no-tools/no-execution/no-file-write rules and must include only that
wrapper-returned context.

- CONFIRM validator: model \`${renderSpawnArgs(confirmModel, { elevated: true })}\`
- REFUTE validator: model \`${renderSpawnArgs(refuteModel, { elevated: true })}\`

Use distinct validator IDs and separate task agents. Launch in bounded parallel
batches of at most **8 task calls per tool block** (therefore at most 4
candidates' confirm/refute pairs per block). Use \`agent_type="general-purpose"\`
and \`mode="sync"\`. Validators call no tools, execute nothing, create no PoCs,
run no builds/fuzzing/shells, and write no files.

The confirm side may return \`confirmed\` only when it cites an existing complete
chain and the full supplied activation/trigger → effect node/edge path. The
refute side must explicitly test all six alternatives: dead/unreachable code,
docs/tests-only context, activation gating, sanitization/neutralization, broken
edges, and legitimate project fit. Neither side may add source evidence, graph
topology, or chain IDs.

Parse each strict JSON output and submit it unchanged:

\`\`\`
zerotrust_record_validation(<confirm-or-refute JSON>)
\`\`\`

Retry a malformed/refused validator once with the same prompt. Identical
submissions are idempotent. A changed retry, duplicate decision type, reused
validator ID across confirm/refute, unknown evidence/chain/node/edge ID, or
source-text field is refused. A failed or missing side leaves the finding in
\`validating\`; it never deletes the candidate.

### Step V3 — Independent adjudication

Only after both sides were recorded, launch one new adjudicator per candidate
with model \`${renderSpawnArgs(adjudicatorModel, { elevated: true })}\`, in
batches of at most 8 parallel task calls. Use the strict adjudication prompt
from \`council/validationPromptTemplate.mjs\`, a fresh nonce, the same bounded
candidate context, and the two recorded decision objects. The adjudicator calls
no tools and writes no files.

Submit each strict adjudication object through
\`zerotrust_record_validation\`. It records exactly one terminal finding state:
\`validated\`, \`refuted\`, or \`unresolved\`, plus severity, confidence,
malicious project fit, rationale, and existing evidence references. It cannot
introduce evidence or graph IDs not already cited by the two validators. Direct
confirm/refute disagreement must remain unresolved with low confidence; a
single unresolved side caps a decisive result at medium confidence.

### Step V4 — Finalize validation and advance the stage

After every required candidate has both decision types and one adjudication,
call:

\`\`\`
const validationFinal = zerotrust_record_validation({
  action: "finalize",
  schemaVersion: 5,
  audit_id: ${JSON.stringify(auditId)}
})
\`\`\`

Require:

- \`validationFinal.validation.completion.complete === true\`
- every validation truncation flag is false
- \`validationFinal.analysisStageAfter === "validated"\`
- \`validationFinal.decisionSnapshot.auditId === ${JSON.stringify(auditId)}\`
- every decision-snapshot truncation flag is false
- \`validationFinal.decisionSnapshot.overallVerdictEligibility\` is present
- \`validationFinal.remediation.auditId === ${JSON.stringify(auditId)}\`
- every remediation candidate is unique to one validated active canonical
  finding and contains only edge IDs, evidence locations/hashes, intent hashes,
  risk codes, and static verification metadata — never source text or a stored
  diff

Zero required candidates is a valid completed queue and still requires this
finalize call. Only the wrapper may advance \`traced → validated\`. Missing
confirm/refute/adjudication, changed identities, caps, truncation, or prior
stage/coverage failure keeps the stage before validated. In that case skip
trusted synthesis and record only \`verdict: "incomplete", complete: false\`.

Pass \`validationFinal.decisionSnapshot\` with the final source-text-free
validation snapshot to category sub-judges, the meta-judge, outcome recording,
and finalization handoff. Also retain \`validationFinal.remediation\` for the
pre-finalization operator flow. Refuted findings have no remediation entry.
Unresolved findings may appear only in \`investigationGuidance\`, where
\`confidentPatchAllowed\` is false. A candidate whose static verification says
\`alternate-path-remains\` or \`graph-incomplete\` is not a fixed finding and
must never be presented as one. Its canonical finding IDs, aliases, state/severity
counts, separate impact/confidence/project-fit scores, blockers, rationale
codes, and verdict eligibility are authoritative. Judges may organize
structured decision references, but must not render report prose, re-dedupe,
severity-average, resurrect refuted findings, or silently drop unresolved
findings. Judge output is limited to exact decision ID, verdict/count fields,
canonical finding IDs, blocker codes, and completion state. The finalizer
deterministically renders REPORT.md and source-text-free FINDINGS.json from the
exact trusted snapshot and structured operator decisions. This is the logical
**Dedupe/score** phase: semantic aliases are grouped deterministically and impact
severity, evidence confidence, and malicious-project-fit likelihood remain
separate axes before Finalize.
`;
}
