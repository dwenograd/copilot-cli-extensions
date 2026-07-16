import { renderSpawnArgs } from "../../_shared/index.mjs";
import {
    modeIsBuild,
    modeUsesCouncil,
    modeUsesLocalSource,
} from "../modes.mjs";
import { renderTraceStage } from "./trace.mjs";
import { renderValidateStage } from "./validate.mjs";

export function renderCurrentAssuranceStage(context = {}) {
    if (context.mode === "metadata_only") return "";

    const auditId = context.auditId || "<unavailable: no session identity>";
    const semanticModel = context.councilJudgeModel || "gpt-5.6-sol";
    const secondarySemanticModel =
        context.councilSubJudgeModel || "claude-opus-4.8";
    const councilNote = modeUsesCouncil(context.mode)
        ? "Use recorded council candidates only as discovery leads. A lead counts only after current scanner facts and wrapper-issued semantic/red-team records substantiate it.": "This mode omits the 32-role discovery council, but it still must run every required semantic and evasive red-team model assignment. Otherwise assurance is partial/incomplete and cannot authorize a build.";
    const remediationTarget = modeUsesLocalSource(context.mode)
        ? `The pinned project path for this audit is **exactly** \`${context.localPath}\`. A
\`delete-project\` decision may delete only that root. A \`defang\` decision may
modify only the exact evidence-bound file beneath it.`
        : modeIsBuild(context.mode)
            ? `The pinned project path for remediation is **exactly**
\`cloneResult.boundContext.clonePath\`, as returned by \`zerotrust_safe_clone\`.
Never substitute the placeholder path, reconstruct a path, or accept another
root. A \`delete-project\` decision may delete only that bound clone.`
            : `This API-direct audit has no on-disk source tree to modify or delete.
Record \`defang\` or \`delete-project\` as requested operator intent only, then
re-invoke against an explicitly acknowledged local path or build clone before
performing any source mutation.`;

    return `
---

## Section 5c — Continuous current assurance lifecycle

The normal audit activation already owns the current assurance state. There is
one assurance contract. Continue from the wrapper-maintained \`decoded\`
snapshot produced by mandatory acquisition, object inventory, and
derived-artifact decoding.

${councilNote}

### Step A — Dependency inventory and static closure analysis

Before semantic preparation, collect every supported dependency manifest from
the exact fully indexed bytes. Call \`zerotrust_inventory_dependencies\`, then
\`zerotrust_analyze_dependencies\`, with manifest content plus its exact
SHA-256. Never run a package manager. Missing integrity, mutable refs,
unsupported registries, unresolved transitives, fetch/hash failures, hooks, and
caps remain explicit supply-chain blockers. If no supported manifest exists,
record that fact accurately; do not invent an empty successful graph.

### Step B — Prepare semantic coverage

Create the complete set of prompt normalized views required by executable and
configuration subjects. These views must be source-text-free and bound to the
current object identities. Pass \`[]\` only when no object requires a prompt
assessment.

\`\`\`
const semantic = zerotrust_prepare_semantic_coverage({
  audit_id: ${JSON.stringify(auditId)},
  normalized_views_json: JSON.stringify(normalizedViews)
})
\`\`\`

For every \`semantic.plan.scannerAssignments\` entry, run the trusted
deterministic scanner selected by its exact \`scannerId\` over the assignment's
exact content identity. Do not model-synthesize scanner facts. Record the exact
scanner result:

\`\`\`
zerotrust_record_semantic_scanner({
  audit_id: ${JSON.stringify(auditId)},
  assignment_id: scannerAssignment.assignmentId,
  assignment_token: scannerAssignment.assignmentToken,
  scanner_result_json: JSON.stringify(scannerResult)
})
\`\`\`

Every scanner assignment must have one immutable, untruncated, blocker-free
record before model review. Unsupported or unavailable exact bytes remain a
semantic blocker rather than being silently skipped.

### Step C — Complete model semantic review

For every classified object with \`modelReviewRequired: true\`, issue each
required reviewer slot through \`zerotrust_assign_semantic_review\`. High-risk
objects require two distinct reviewer IDs. Launch the returned assignment as a
no-tools, no-source-text, no-file-write \`general-purpose\` task using
\`${renderSpawnArgs(semanticModel, { elevated: true })}\`; use
\`${renderSpawnArgs(secondarySemanticModel, { elevated: true })}\` for the
second high-risk slot. The prompt must follow
\`council/semanticReviewPrompt.mjs\`.

Submit each exact JSON result through
\`zerotrust_record_semantic_review\`. Structured candidates must preserve
assignment-bound object/artifact/fact/evidence identities and submitted
severity. Empty results require the complete negative-evidence contract. Keep
assigning/recording until \`zerotrust_get_semantic_coverage\` reports complete
coverage and stage \`semantically-covered\`.

### Step D — Mandatory evasive red team

Call \`zerotrust_prepare_red_team\`. For every mandatory category in its plan,
call \`zerotrust_assign_red_team_review\`, launch the wrapper-issued assignment
as a no-tools/no-source-text/no-file-write task using the model specified by the
assignment, and submit the exact JSON through
\`zerotrust_record_red_team_review\`.

All categories are mandatory. Empty results count only with exact subject
arrays, falsification checks, negative-evidence codes, canary, output marker,
and no blockers. Require at least 90% assignment coverage and every mandatory
category, then call \`zerotrust_finalize_red_team\`. Proceed only when it
advances to \`red-teamed\`.

${renderTraceStage(context)}

${renderValidateStage(context)}

### Step E — Remediation decisions before finalization

Use only \`validationFinal.analysisSnapshot\`, validated graph findings, and
their exact evidence identities. Refuted findings have no remediation entry.
For every active non-refuted finding, regardless of impact severity, present
one finding at a time and ask the operator to choose **defang**,
**delete-project**, **keep-as-is**, **investigate**, or **no-action**. Do NOT
collapse MEDIUM/LOW/INFO findings into an advisory bucket. NEVER auto-apply and
NEVER batch findings or edits.

For \`defang\`, view the exact evidence-bound file, propose one bounded diff,
and ask: "Approve this one finding's proposed diff exactly as shown? (yes/no)".
Apply nothing without explicit one-finding approval. Before writing, create a
\`.zerotrust-backup-<utc-ts>\` copy beside the file. Never execute project code,
and never use build output as proof that remediation succeeded. Refuse
\`keep-as-is\` without a written rationale.

${remediationTarget}

Any source modification occurs after the audited snapshot and therefore cannot
make this audit claim the finding is removed. Record the operator decision,
finish the current deterministic report, and recommend re-running
\`zerotrust_sourcecheck\` as a fresh invocation over the changed bytes before
claiming remediation succeeded. If an alternate path remains active, the graph
is incomplete, or a confident patch is not allowed, record
\`alternate-path-remains\`, \`graph-incomplete\`, or
\`confidentPatchAllowed: false\` rather than overstating the edit.

Initialize structured \`operatorDecisions = []\` and retain only final human
choices for the single \`zerotrust_finalize_report\` call. Do NOT call
\`zerotrust_finalize_report\` inside this block. The finalizer derives the
trusted findings verdict, assurance result, counts, prose, and durable outcome.
Do NOT write REPORT.md/FINDINGS.json directly.
`;
}
