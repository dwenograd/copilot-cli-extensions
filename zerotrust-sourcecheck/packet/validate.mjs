import { renderSpawnArgs } from "../../_shared/index.mjs";

export function renderValidateStage(context = {}) {
    const auditId = context.auditId || "<unavailable: no session identity>";
    const confirmModel = context.councilJudgeModel || "gpt-5.6-sol";
    const refuteModel = context.councilSubJudgeModel || "claude-opus-4.8";
    return `
### Independent assurance validation

After the evasive graph reaches \`traced\`, call:

\`\`\`
const validationPlan = zerotrust_prepare_assurance_validation({
  audit_id: ${JSON.stringify(auditId)},
  no_finding_validator_id: "assurance-no-finding",
  confirm_validator_id: "assurance-confirm",
  refute_validator_id: "assurance-refute",
  validator_version: "current"
})
\`\`\`

When there are no active findings, the wrapper issues one no-finding proof
assignment covering semantic coverage, every red-team category, supply chain,
unsupported objects, alternate paths, dynamic targets, activation roots, and
truncation. Otherwise it issues independent confirm/refute assignments for
every active severity.

Launch each assignment as a no-tools, no-source-text, no-file-write
\`general-purpose\` task. Use distinct validator identities. Prefer
\`${renderSpawnArgs(confirmModel, { elevated: true })}\` for confirm/no-finding
assignments and \`${renderSpawnArgs(refuteModel, { elevated: true })}\` for
refute assignments. Submit each exact structured result through
\`zerotrust_record_assurance_validation\`; validators may cite only IDs already
present in the assignment.

Then call:

\`\`\`
const validationFinal = zerotrust_finalize_assurance_validation({
  audit_id: ${JSON.stringify(auditId)}
})
\`\`\`

Only \`validationFinal.advanced === true\`, stage \`validated\`, complete
independent records, no unresolved outcome, and no blocker permit deterministic
report finalization. Missing or truncated proof means incomplete assurance and
must never be described as comprehensive.

Preserve \`validationFinal.analysisSnapshot\` as the trusted validated handoff.
Do not rebuild findings, severity counts, assurance, or a verdict from council
or validator prose. The Section 7 finalizer reads the wrapper-owned validated
assurance state and deterministically renders REPORT.md plus the source-text-free
FINDINGS.json pair.
`;
}
