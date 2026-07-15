// Shared pure helpers for packet renderers.

const FINDING_SEVERITIES = Object.freeze([
    "critical",
    "high",
    "medium",
    "low",
    "info",
]);
const REQUIRED_FINDING_FIELDS = Object.freeze([
    "severity",
    "confidence",
    "exploit_prerequisites",
    "benign_context_explanation",
    "verification_step",
]);
const DYNAMIC_EVALUATION_RE = /\b(?:eval|Function|exec|compile|Invoke-Expression|vm\.runInNewContext)\s*\(/iu;
const REMOTE_FETCH_RE = /\b(?:curl|wget|Invoke-WebRequest|iwr|fetch|requests?\.get|urllib\.request|Net\.WebClient)\b/iu;
const DECODER_RE = /\b(?:atob|base64|fromBase64|Buffer\.from|Convert\.FromBase64String|decode)\b/iu;
const COMMAND_EXECUTION_RE = /\b(?:powershell|pwsh|cmd(?:\.exe)?|sh|bash|zsh|node|python|ruby|perl|Start-Process|child_process|subprocess|os\.system)\b/iu;
const EXTENDED_PICTOGRAPHIC_RE = /\p{Extended_Pictographic}/u;

/**
 * Deterministic verdict mapping. Finding counts and cross-validation counts
 * never average down a credible singleton: the highest credible severity wins.
 * Coverage incompleteness takes precedence over every trusted verdict.
 */
export function mapOverallVerdict(findings, {
    mandatoryAcquisitionComplete = true,
    councilCoverageComplete = true,
} = {}) {
    if (mandatoryAcquisitionComplete !== true || councilCoverageComplete !== true) {
        return "incomplete";
    }
    let highestIndex = FINDING_SEVERITIES.length;
    for (const finding of Array.isArray(findings) ? findings : []) {
        if (!finding || finding.credible === false || finding.dismissed === true) continue;
        const severity = String(finding.severity || "").toLowerCase();
        const index = FINDING_SEVERITIES.indexOf(severity);
        if (index >= 0 && index < highestIndex) highestIndex = index;
    }
    if (highestIndex === 0) return "critical";
    if (highestIndex === 1) return "high";
    if (highestIndex === 2) return "medium";
    if (highestIndex === 3 || highestIndex === 4) return "low";
    return "no red flags found";
}

export function validateFindingContract(finding, { councilDerived = false } = {}) {
    const missingFields = REQUIRED_FINDING_FIELDS.filter((field) => {
        const value = finding?.[field];
        return typeof value !== "string" || value.trim().length === 0;
    });
    if (!FINDING_SEVERITIES.includes(String(finding?.severity || "").toLowerCase())) {
        if (!missingFields.includes("severity")) missingFields.push("severity");
    }
    if (!["high", "medium", "low"].includes(String(finding?.confidence || "").toLowerCase())) {
        if (!missingFields.includes("confidence")) missingFields.push("confidence");
    }
    if (councilDerived
        && (!Number.isInteger(finding?.cross_validation_count)
            || finding.cross_validation_count < 1)) {
        missingFields.push("cross_validation_count");
    }
    return {
        valid: missingFields.length === 0,
        missingFields,
    };
}

/**
 * Score a repository filter declaration together with any discovered driver
 * commands. A normal Git LFS declaration is expected metadata, not a finding.
 */
export function scoreGitAttributesFilter({
    attributesLine = "",
    cleanCommand = "",
    smudgeCommand = "",
    processCommand = "",
} = {}) {
    const match = String(attributesLine).match(/(?:^|\s)filter=([^\s]+)/iu);
    if (!match) {
        return { finding: false, severity: null, classification: "no-filter" };
    }
    const filterName = match[1].toLowerCase();
    const commands = [cleanCommand, smudgeCommand, processCommand]
        .map((value) => String(value || "").trim())
        .filter(Boolean);
    const canonicalLfs = commands.every((command) =>
        /^git-lfs\s+(?:clean|smudge|filter-process)(?:\s|$)/iu.test(command));
    if (filterName === "lfs" && canonicalLfs) {
        return {
            finding: false,
            severity: null,
            classification: "standard-git-lfs",
            confidence: "high",
        };
    }

    const commandText = commands.join("\n");
    const fetches = REMOTE_FETCH_RE.test(commandText);
    const decodes = DECODER_RE.test(commandText);
    const dynamicallyEvaluates = DYNAMIC_EVALUATION_RE.test(commandText)
        || /\b(?:Invoke-Expression|iex)\b/iu.test(commandText);
    const executes = COMMAND_EXECUTION_RE.test(commandText) || dynamicallyEvaluates;
    let severity = "low";
    if (commands.length > 0) severity = "medium";
    if (fetches || executes) severity = "high";
    if ((fetches || decodes) && executes) severity = "critical";
    return {
        finding: true,
        severity,
        classification: commands.length > 0
            ? "custom-filter-with-driver"
            : "custom-filter-declaration",
        confidence: commands.length > 0 ? "high" : "medium",
    };
}

function invisibleKind(codePoint) {
    if (codePoint >= 0xE0000 && codePoint <= 0xE007F) return "tags";
    if ((codePoint >= 0xFE00 && codePoint <= 0xFE0F)
        || (codePoint >= 0xE0100 && codePoint <= 0xE01EF)) return "variation-selector";
    if ((codePoint >= 0xE000 && codePoint <= 0xF8FF)
        || (codePoint >= 0xF0000 && codePoint <= 0xFFFFD)
        || (codePoint >= 0x100000 && codePoint <= 0x10FFFD)) return "private-use";
    if (codePoint >= 0x202A && codePoint <= 0x202E) return "bidi";
    if (codePoint >= 0x2066 && codePoint <= 0x2069) return "bidi";
    if ((codePoint >= 0x200B && codePoint <= 0x200F)
        || (codePoint >= 0x2028 && codePoint <= 0x202F)
        || (codePoint >= 0x2060 && codePoint <= 0x206F)) return "control";
    if (codePoint === 0xFEFF) return "bom";
    return null;
}

function adjacentCodePoint(text, index, direction) {
    if (direction < 0) {
        const prefix = text.slice(0, index);
        const chars = Array.from(prefix);
        return chars.length > 0 ? chars.at(-1) : "";
    }
    const codePoint = text.codePointAt(index);
    const width = codePoint === undefined ? 0 : String.fromCodePoint(codePoint).length;
    return Array.from(text.slice(index + width))[0] || "";
}

/**
 * Contextual invisible-Unicode scoring used by the packet's deterministic
 * rules. The byte scanner remains broad; this classifier separates expected
 * presentation characters from payload-shaped or control-flow abuse.
 */
export function scoreInvisibleUnicode(text, { filePath = "" } = {}) {
    const source = String(text || "");
    const suspicious = [];
    const counts = {};
    let currentRun = 0;
    let maxRun = 0;
    for (let index = 0; index < source.length;) {
        const codePoint = source.codePointAt(index);
        const char = String.fromCodePoint(codePoint);
        const kind = invisibleKind(codePoint);
        if (!kind) {
            currentRun = 0;
            index += char.length;
            continue;
        }
        let benign = kind === "bom" && index === 0;
        if (kind === "variation-selector") {
            const previous = adjacentCodePoint(source, index, -1);
            benign = EXTENDED_PICTOGRAPHIC_RE.test(previous);
        } else if (kind === "control" && codePoint === 0x200D) {
            const previous = adjacentCodePoint(source, index, -1);
            const next = adjacentCodePoint(source, index, 1);
            benign = EXTENDED_PICTOGRAPHIC_RE.test(previous)
                && EXTENDED_PICTOGRAPHIC_RE.test(next);
        }
        if (benign) {
            currentRun = 0;
        } else {
            suspicious.push({ index, codePoint, kind });
            counts[kind] = (counts[kind] || 0) + 1;
            currentRun += 1;
            maxRun = Math.max(maxRun, currentRun);
        }
        index += char.length;
    }

    if (suspicious.length === 0) {
        return {
            finding: false,
            severity: null,
            confidence: "high",
            suspiciousCount: 0,
            maxRun: 0,
            counts: {},
        };
    }

    const payloadShaped = maxRun >= 8 || suspicious.length >= 16;
    const dynamicEvaluation = DYNAMIC_EVALUATION_RE.test(source);
    const executionSensitivePath = /(?:^|[\\/])(?:package\.json|build\.rs|setup\.py|extension\.[cm]?[jt]s|scripts?)(?:$|[\\/])/iu.test(filePath);
    let severity = "medium";
    if (counts.tags > 0 || counts.bidi > 0) severity = "high";
    if (payloadShaped || (dynamicEvaluation && suspicious.length > 0)
        || (executionSensitivePath && counts.tags > 0)) {
        severity = "critical";
    }
    return {
        finding: true,
        severity,
        confidence: severity === "critical" ? "high" : "medium",
        suspiciousCount: suspicious.length,
        maxRun,
        counts,
        payloadShaped,
        dynamicEvaluation,
    };
}

// Shared lifecycle/remediation prose used by URL and local packets.

/**
 * Section-9 remediation block: per HIGH/CRITICAL finding, walk the user
 * through defang / delete-project / keep-as-is. Rendered into:
 *   - the local-source packet (always)
 *   - the URL-driven packet IF the mode wrote source to disk (build modes)
 *
 * `pinnedPath` is the path the agent is allowed to operate on for delete /
 * defang: `localPath` for local-source audits, `expectedClonePath` for
 * build modes. The packet refuses any other path.
 */
export function renderRemediationBlock({
    pinnedPath,
    modeLabel,
    remediationSource = null,
}) {
    const ledgerFlow = remediationSource
        ? `Use \`${remediationSource}\` as the authoritative remediation ledger.
Require its audit ID to match the active audit. It contains at most one
source-text-free candidate per validated active canonical finding:
target behavior-chain edge IDs, evidence-bound paths/lines and hashes, expected
behavior removed, legitimate-functionality risk, and static verification
criteria. Refuted findings have no entry. Unresolved findings may have only
\`investigationGuidance\` with \`confidentPatchAllowed: false\`.

Reject duplicate candidate IDs, multiple candidates for the same canonical or
source finding, identity mismatch, cap/truncation flags, or any unexpected
source/snippet/diff field. The persistent ledger stores locations, hashes, and
intent only. A bounded diff proposal is assembled ephemerally in the parent
conversation after \`view\`; never write that proposal back into the ledger or
REPORT.md/FINDINGS.json.`
        : `This non-council flow has no validated remediation ledger. Treat the
report finding as the single remediation identity and retain the same
one-finding approval, path, backup, and re-audit rules below. Do not infer that a
local edit breaks every activation-to-effect path; only a fresh full audit can
establish that.`;
    return `## Section 9b — Remediation: defang, delete, or knowingly keep (pre-finalization)

${remediationSource
        ? `Run this block while \`validationFinal.decisionSnapshot\`, the
source-text-free remediation ledger, and structured \`operatorDecisions\` are in
memory and **before** the single finalizer call. Do not assemble or write
REPORT.md/FINDINGS.json directly.`
        : `Run this block while the complete report is still held in the
in-memory \`reportMarkdown\` draft and **before** the single finalizer call. Do
not create, append, edit, or otherwise write REPORT.md directly.`}

${ledgerFlow}

If ${remediationSource
        ? "\`validationFinal.decisionSnapshot.canonicalFindings\` contains any active finding whose impact severity is HIGH or CRITICAL"
        : "the report draft contains ANY finding at severity HIGH or CRITICAL"},
walk the user through this decision flow **per finding**. Do NOT batch
findings; prompt for one at a time. Preserve one-finding approval and
one-finding/one-approval sequencing throughout.

For each HIGH/CRITICAL finding:

1. **Present exactly one finding.** ${remediationSource
        ? `Use its canonical ID, impact severity, state, evidence references/hashes,
   chain IDs, and scoring axes directly from
   \`validationFinal.decisionSnapshot\`; do not invent a title or quote source
   text. Show the matching ledger candidate's target edge IDs,
   evidence locations, expected behavior removed, legitimate-functionality
   risk, and static verification outcome. If the outcome is
   \`alternate-path-remains\`, say plainly that another malicious
   activation-to-effect chain remains. If it is \`graph-incomplete\`, say that
   reachability is unknown. In either case, NEVER claim the finding is fixed or
   offer the candidate as a sufficient defang.`
        : "Read its title, severity, file reference(s), and one-sentence summary verbatim from `reportMarkdown`. Do NOT paraphrase."}

${remediationSource ? `If this active finding has only
\`investigationGuidance\` (state \`unresolved\`) and no candidate, present the
bounded evidence locations and guidance codes, but do not synthesize a diff or
offer a confident **defang**. The operator may investigate later, delete the
project, or keep it with a written rationale. Refuted findings are not presented
for remediation at all.

` : ""}2. **Ask the user to pick one of:**

   - **defang** — surgically remove this specific finding from the tree,
     keeping the rest of the project intact. ${remediationSource ? `Offer a
     confident defang only when
     \`candidate.staticVerification.fixClaimAllowed === true\`. Otherwise this
     option is only a partial hardening/investigation step and the finding stays
     active. Skip this branch entirely for guidance-only unresolved findings.`
        : ""} First call \`view\` on every evidence-bound affected file
     and exact line range. Then assemble one bounded concrete diff in the parent
     conversation, limited to the candidate's target edge(s). Do not include
     unrelated cleanup. Ask exactly:

     **"Approve this one finding's proposed diff exactly as shown? (yes/no)"**

     **Wait for that one approval before any write.** Then apply via a single
     \`edit\` (or \`Remove-Item\` for one whole-file deletion).
     **Before every write, copy the original file to
     \`<file>.zerotrust-backup-<utc-ts>\`** (where \`<utc-ts>\` is a single
     timestamp generated at the start of this remediation pass — re-use
     it across all backups in the same pass so the user can identify the
     set) so the change is reversible without git. **NEVER auto-apply.
     NEVER batch multiple defangs together** — one finding, one edit,
     one acknowledgement.

   - **delete project** — \`Remove-Item -Recurse -Force <pinned-path>\`.
     The pinned path for this audit is **exactly** \`${pinnedPath}\`.
     Confirm the path with the user one more time before running.
     **Refuse if the user requests a different path** even by one
     character — re-state the pinned path and ask them to confirm or
     pick a different option. ${remediationSource
        ? "The structured `operatorDecisions` remain in memory and the canonical REPORT.md/FINDINGS.json pair will later be finalized under `_reports\\`, outside the pinned path."
        : "The not-yet-written report draft remains in memory and will later be finalized under `_reports\\`, outside the pinned path."}

   - **keep as-is** — the user has decided to accept this finding.
     ${remediationSource
        ? `Append one \`operatorDecisions\` record with the canonical
     \`finding_id\`, \`action: "kept-as-is"\`, and one predefined
     \`rationale_category\` (\`accepted-risk\`, \`required-functionality\`,
     \`false-positive-suspected\`, \`deferred-review\`, or \`other\`). Use
     \`operator_rationale\` only for the user's own short one-line words; never
     paraphrase, expand, or substitute model prose. The finalizer labels it
     user-supplied and rejects code/backticks, URLs, control characters, long
     encoded tokens, finding/verdict claims, and known source-derived text.`
        : "Append a `## Operator decision` block to the in-memory `reportMarkdown` draft with the finding's title, severity, and the user's one-line rationale."}
     **Refuse "keep" without a written rationale** — re-ask if they say "just
     keep it" without explanation. This becomes the immutable audit trail when
     the finalizer writes the canonical artifact(s) once.

${remediationSource ? `For every completed choice, add exactly one structured
\`operatorDecisions\` record for that canonical finding. Use
\`action: "defanged"\` with \`rationale_category: "remediation-applied"\` only
when the trusted candidate allowed a fix claim and the approved edit completed;
use \`action: "investigate"\` with \`alternate-path-remains\`,
\`graph-incomplete\`, or \`deferred-review\` for partial work; and use
\`action: "delete-project"\` with \`project-deleted\` after confirmed deletion.
Do not record model-authored rationales or claim that an unverified edit fixed a
finding.` : ""}

3. Findings at MEDIUM/LOW/INFO severity are summarised in a single
   "review at your leisure" ${remediationSource
        ? "deterministic finalizer summary; do not add model prose or synthetic operator decisions"
        : "block in the in-memory report draft"} — do NOT
   individually prompt for them. ${remediationSource ? `Retain their structured
   candidates only as source-text-free future guidance; do not auto-apply them.`
        : ""}

4. After all HIGH/CRITICAL decisions are made, ${remediationSource
       ? `retain only one structured record per decided canonical finding.
   Do not add a free-form aggregate summary or backup-file names; the finalizer
   derives action counts deterministically from \`operatorDecisions\`.`
       : `append this final summary to \`reportMarkdown\`:
   "Of N high-severity findings: defanged X, kept Y, deleted project Z."
   List any \`.zerotrust-backup-<utc-ts>\` files written. If \`delete
   project\` was chosen, note that the audit pinned path is now gone and
   the report will be finalized outside it.`}

**Safety invariants (DO NOT VIOLATE):**

- Do NOT propose a defang you cannot describe concretely from the candidate's
  exact edge IDs and evidence locations. "Sanitize this somehow" is not a
  defang.
- Do NOT touch ANY path outside \`${pinnedPath}\`. The agent's
  ${modeLabel} sandbox boundary is the pinned path; reaching outside
  defeats it.
- Do NOT delete files that were not flagged in ${remediationSource
        ? "the trusted decision/remediation ledgers"
        : "REPORT.md"}, even if you think they look related.
- One \`edit\`/\`Remove-Item\` per user acknowledgement. NO BATCH mode.
  If the user says "yes, do all of them," refuse — re-prompt one
  finding at a time.
- Do NOT call \`zerotrust_finalize_report\` inside this block. Finalization
  happens once, after every decision has been incorporated into
  ${remediationSource ? "structured `operatorDecisions`" : "the draft"}.
- NEVER auto-apply. Never execute project code, run install/build/test commands,
  create a PoC, or treat build output as proof that remediation worked.
  Static source/graph checks and the full re-audit are the only permitted
  verification here.
- Simulate removal/guard of the targeted edge IDs against every known complete
  activation/trigger-to-effect chain. If any non-targeted path remains, retain
  the finding and say \`alternate-path-remains\`. If graph coverage or topology
  is incomplete, say \`graph-incomplete\`. Never claim fixed in either case.
- If user picks "delete project", confirm the pinned path one more
  time before running \`Remove-Item\`. Refuse if the path the user
  confirms back is different.

**Re-audit recommendation:** After all defangs are applied, suggest
the user re-run the same \`zerotrust_sourcecheck\` invocation. Do not mark a
finding remediated until that fresh audit re-indexes the edited bytes, rebuilds
the behavior graph, and confirms no alternate activation-to-effect chain.

---
`;
}

export function renderSweepAndCloseBlock({ buildRoot }) {
    return `### Sweep scratch, then close audit state

Run the normal sandbox-only sweep with parent sweeping explicitly disabled:

\`\`\`
zerotrust_sweep_audit_scratch({
  // build_root defaults to the active audit's trusted build_root
  also_sweep_parent: false
})
\`\`\`

Parent sweeping is opt-in and may affect unrelated files. Only if
\`${buildRoot}\`'s parent is dedicated audit scratch, first inspect it:

\`\`\`
zerotrust_sweep_audit_scratch({
  also_sweep_parent: true,
  dry_run: true
})
\`\`\`

After reviewing that candidate list, an explicit parent sweep may be run with
\`also_sweep_parent: true\` and \`dry_run: false\`.

If any cleanup or sweep call fails, **do not close the audit**. Report the
error and retry while the trusted audit context is still active. After every
requested destructive cleanup step succeeds, close state:

\`\`\`
zerotrust_close_audit({})
\`\`\`

\`zerotrust_close_audit\` is non-destructive and idempotent.`;
}
