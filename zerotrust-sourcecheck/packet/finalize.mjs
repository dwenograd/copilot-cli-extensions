// Build, release, final report, remediation, and lifecycle renderers.
// Pure: emits instructions only and performs no I/O.

import {
    BUILD_MODE_TAXONOMY_NOTE,
    modeIsBuild,
    modeIsCouncilBuild,
    modeIsFullBuild,
    modeIsSafeBuild,
    modeUsesApiDirect,
    modeUsesCouncil,
} from "../modes.mjs";
import { renderRemediationBlock, renderSweepAndCloseBlock } from "./shared.mjs";

function renderBuildSection(context) {
    const { mode, expectedClonePath, buildExecAck, unsafeAck } = context;

    // Pre-build Section 6 (build) conditional on mode. For non-build modes
    // we OMIT the section entirely (v4 design: don't even mention build to
    // the agent unless it's a build mode — the user must explicitly opt
    // in to builds, see Section 9 epilogue).
    let buildSection;
    if (!modeIsBuild(mode)) {
        buildSection = ""; // omit entirely; not even a "skipped" placeholder
    } else {
        const sharedBuildInstructions = `${BUILD_MODE_TAXONOMY_NOTE}

Use \`zerotrust_safe_install\` for installs and \`zerotrust_safe_build\` for builds; do not run package-manager commands directly. These are the expected wrapper-backed operations per ecosystem:

- **npm:** \`cd ${expectedClonePath}; npm ci --ignore-scripts; npm run build --if-present\`
- **yarn:** \`cd ${expectedClonePath}; yarn install --ignore-scripts --frozen-lockfile; yarn build\`
- **pnpm:** \`cd ${expectedClonePath}; pnpm install --ignore-scripts --frozen-lockfile; pnpm build\`
- **pip:** \`cd ${expectedClonePath}; pip install --only-binary=:all: -r requirements.txt\` (refuse if no wheel-only install is possible)
- **cargo:** \`cd ${expectedClonePath}; cargo build --locked --offline\` (after a separate \`cargo fetch --locked\` to populate the cache)
- **dotnet:** \`cd ${expectedClonePath}; dotnet build --no-restore\` (after \`dotnet restore --locked-mode --force-evaluate\`)

When invoking \`zerotrust_safe_build\`, pass \`mode: "${mode}"\` so the wrapper can apply the council-build gate when relevant.

For ANY ecosystem, before invoking the build, **list and report** the build-config files that may execute as part of the build (\`package.json\` build scripts, \`vite.config.js\`, \`webpack.config.*\`, \`build.rs\`, MSBuild \`.targets\`/\`.props\`, \`tsup.config.*\`, etc.). Surface them in the report as "build-time code execution surfaces."`;
        let modeBody;
        if (modeIsSafeBuild(mode)) {
            const ackLine = buildExecAck
                ? "User has acknowledged that build steps execute repo-controlled code."
                : "**STOP**. The user did NOT pass i_understand_build_executes_code: true. Inform them and refuse to build.";
            modeBody = `**Safe-build mode.** ${ackLine}

${sharedBuildInstructions}`;
        } else if (modeIsFullBuild(mode)) {
            const ackLine = (buildExecAck && unsafeAck)
                ? "Both required acknowledgement flags are set."
                : "**STOP**. Full-build mode requires BOTH i_understand_build_executes_code: true AND unsafe: true. Refuse to build.";
            modeBody = `**Full-build mode (host code-execution risk).** ${ackLine}

${sharedBuildInstructions}

The \`unsafe\` acknowledgement currently selects stricter admission/warning posture only. It does not select a less-restricted installer or enable install lifecycle scripts. Treat the build command as live repo-controlled code on a non-sandboxed host, exactly as in safe-build mode.`;
        } else {
            modeBody = `**Unknown build mode.** STOP and report that packet.mjs did not recognize mode \`${mode}\`.`;
        }
        const councilBuildGateParagraph = modeIsCouncilBuild(mode) ? `
**Council-build gate:** Section 5c.5 records the immutable council outcome
exactly once before this build. The build wrapper will REFUSE the build if no
outcome is recorded, if it belongs to another audit ID/owner/repo/SHA, if its
verdict is \`medium\`/\`high\`/\`critical\` (unless
\`council_build_override:true\`), or if it is incomplete (unless
\`proceed_on_council_failure:true\`). Do not record a second or replacement
outcome here.` : "";
        buildSection = `---

## Section 6 — Build (${mode})

${modeBody}
${councilBuildGateParagraph}

After build, hash all output binaries:
\`\`\`powershell
Get-ChildItem '${expectedClonePath}\\dist','${expectedClonePath}\\build','${expectedClonePath}\\target','${expectedClonePath}\\out','${expectedClonePath}\\bin' -Recurse -File -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256 | Select-Object Hash, Path
\`\`\`
Record the manifest in the report.`;
    }

    return buildSection;
}

export function renderFinalizeReportLifecycleStage(context) {
    const { mode, owner, repo, canonicalUrl, buildRoot, expectedClonePath } = context;
    const buildSection = renderBuildSection(context);

    // Pre-build Section 7 (release verification) conditional on URL kind / mode.
    const releaseSectionApplies = mode === "verify_release";
    const releaseSection = releaseSectionApplies ? `Run only after Section 4 has returned the bound release/source identity.

1. **List the already-bound release through the wrapper — never re-resolve it.**
   \`\`\`
   const releaseAssets = zerotrust_safe_list_release_assets({
     owner: "${owner}",
     repo: "${repo}",
     release_id: releaseIdentity.releaseId,
     tag_name: releaseIdentity.tagName,
     source_sha: releaseIdentity.sourceCommitSha
   })
   \`\`\`
   The wrapper calls only the numeric bound release ID, rejects any ID/tag/source mismatch, records duplicates and the zero-assets case, and never calls \`/releases/latest\` or a tag-resolution endpoint. If \`releaseAssets.releaseAssetCoverage.enumeration.complete\` is false, the audit can finalize only as \`incomplete\`.

2. **Fetch every discovered asset through the wrapper.** For each entry in \`releaseAssets.assets\`:
   \`\`\`
   const fetchedAsset = zerotrust_safe_fetch_release_asset({
     asset_id: "<numeric id from releaseAssets.assets>",
     // max_bytes may lower, but never raise, the 100 MB hard cap
   })
   \`\`\`
   Never pass an asset name, URL, or path. The wrapper derives the active release identity and canonical quarantine, writes only the safe numeric filename \`<asset-id>.bin\`, verifies the listed/downloaded/written byte counts, computes SHA-256, returns bounded magic/preview metadata, and records success/failure. Asset names are attacker-controlled display metadata only.

3. **Coverage gate.** Continue until the latest \`releaseAssetCoverage.requiredReleaseAssetAcquisitionComplete\` is true. This is true for a successfully listed zero-asset release, or when every enumerated unique asset was downloaded and hashed. Oversized, failed, byte-mismatched, skipped, truncated, or undiscovered assets keep it false. Duplicate fetch calls never inflate unique coverage.

4. **Inspect ONLY.** Do NOT \`Start-Process\`, \`Invoke-Item\`, \`Mount-DiskImage\`, rename, or extract a quarantined file. For Windows signature inspection, pass only the exact numeric \`fetchedAsset.assetPath\` returned by the wrapper to \`Get-AuthenticodeSignature\`. Surface signer/status in the report.

5. **Hash compare to local build outputs** only when a separately authorized build audit produced outputs and the project documents reproducible builds. A mismatch means binary integrity could not be reproduced from source; it is not proof of malware.`
        : `SKIP release-asset acquisition in mode \`${mode}\`. Raw release asset enumeration/download is forbidden. Re-invoke the release URL with \`mode: "verify_release"\` to use the active-audit-bound release wrappers.`;

    const releaseTitleSuffix = mode === "verify_release" ? " (this is the headline mode for this URL)" : "";

    const buildExecutedNote = modeIsBuild(mode)
        ? "executed and may have run repo-controlled code"
        : "NOT executed";

    return `${buildSection}

---

## Section 7 — Release verification${releaseTitleSuffix}

${releaseSection}

---

## Section 8 — Final report

${modeUsesCouncil(mode) ? `Do not assemble REPORT.md or FINDINGS.json and do not
copy any judge prose into either artifact. Judges output structured decision
data only; the finalizer reads the active version-5 ledger, validated decision
snapshot, dedupe/scoring state, graph chains, validation decisions, remediation
state, coverage, stage, and cache metadata. It deterministically renders the
executive summary, recommendation, every Markdown finding row/state/severity,
operator-decision audit trail, and the sole verdict from the same snapshot
serialized to FINDINGS.json, so the two outputs cannot disagree.

The only caller-authored version-5 content is \`operator_decisions\`: bounded records
that reference canonical finding IDs and use predefined action/rationale
categories. A short \`operator_rationale\` is allowed only when it is genuinely
human-authored and explicitly user-supplied; never place judge/model prose in
that field. If any required gate is
incomplete, the wrapper emits **INCOMPLETE — DO NOT TRUST**, verdict
\`incomplete\`, and the exact trusted blockers. A trusted verdict requires the
\`validated\` stage and every acquisition/council/trace/validation/release gate.` : `
If Section 5c already assembled \`reportMarkdown\` (complete or incomplete),
use that draft and add any remaining provenance/build/release sections below.
Otherwise assemble \`reportMarkdown\` now. Keep the complete report in memory:
do NOT create a report directory and do NOT use \`New-Item\`, shell
redirection, \`Out-File\`, \`Set-Content\`, \`edit\`, or \`create\` for
REPORT.md.

This is legacy version-4 compatibility. Its caller-authored Markdown is marked
\`trusted:false\` in FINDINGS.json and is explicitly outside the version-5
durable-output privacy guarantee.

Required structure:

\`\`\`markdown
# zerotrust-sourcecheck report

- **URL:** ${canonicalUrl}
- **Pinned SHA:** <RESOLVED_FULL_SHA>
- **Root tree SHA:** <BOUND_ROOT_TREE_SHA>
- **Release identity (if applicable):** id=<BOUND_RELEASE_ID>, tag=<BOUND_RELEASE_TAG>, source=<BOUND_SOURCE_COMMIT_SHA>
- **Mode:** ${mode}
- **Audited at:** <ISO-8601 timestamp>
- **Verdict:** <critical | high | medium | low | no red flags found | incomplete | reconnaissance only>
- **Mandatory acquisition complete:** <true | false | n/a>
- **Council coverage complete:** <true | false | n/a>

## Summary
<2-3 sentences explaining the verdict and the most important findings.>

## Findings

### F-001 — <concise title>
- **Severity:** <critical | high | medium | low | info>
- **Confidence:** <high | medium | low>
- **Category / source:** <category and deterministic check or council role IDs>
- **File:line:** <repo-relative path:line>
- **Quoted evidence:** <verbatim bounded evidence>
- **Activation/execution prerequisites:** <specific conditions, privileges, user actions, and execution path>
- **Benign-context explanation:** <plausible legitimate context, or "none plausible">
- **Concrete verification step:** <one safe, read-only confirmation/refutation step>
- **Cross-validation count:** <distinct corroborating council roles; n/a for deterministic-only findings>
- **Reasoning:** <why the evidence supports this severity and confidence>

Repeat one complete block per finding, severity-sorted descending. Every field is
mandatory. A missing confidence/prerequisites/benign-context/verification field
is a malformed finding, not permission to omit it from synthesis.

## Provenance
- Signed commits: <count> / 30 most-recent (<list of signers>)
- Tag signature: <Good | Bad | None | n/a>
- GH attestation: <Verified | None | Failed>
- Authenticode (release binaries): <list of files + status>
- Workflow-run cross-check: <Match | Mismatch | n/a>

## Acquisition coverage (API-direct; n/a for other modes)
- Required acquisition complete: <true | false>
- Unique files / unique blob SHAs enumerated: <enumeration.uniqueFiles> / <enumeration.uniqueBlobShas>
- Tree unresolved subtrees / blockers: <enumeration.unresolvedSubtrees> / <enumeration.coverageBlockers>
- Unique fetched files / fetch attempts / duplicate calls: <acquisition.uniqueFetchedFiles> / <acquisition.fetchAttempts> / <acquisition.duplicateFetchCalls>
- Full text / truncated text observed: <acquisition.observedOutcomes.fullTextFiles> / <acquisition.observedOutcomes.truncatedTextFiles>
- Binary metadata-only / oversized metadata-only observed: <acquisition.observedOutcomes.binaryMetadataOnlyFiles> / <acquisition.observedOutcomes.oversizedMetadataOnlyFiles>
- Fetch failure attempts: <acquisition.fetchFailureAttempts>
- Mandatory blobs classified+inspected / required: <deterministicMandatory.classifiedAndInspectedBlobs> / <deterministicMandatory.requiredBlobClassifications>
- Mandatory text blobs fully fetched+scanned / binary blobs classified with bounded preview: <deterministicMandatory.fullyFetchedAndScannedTextBlobs> / <deterministicMandatory.classifiedBinaryBlobs>
- Mandatory missing/incomplete / never fetched / council-sample-only: <deterministicMandatory.missingOrIncomplete> / <deterministicMandatory.notFetched> / <deterministicMandatory.councilSampleOnlyBlobs>
- Council sampled files (advisory, non-gating): <councilSampling.uniqueSampledFiles>
- Invisible-Unicode matched files / total matches: <deterministicMandatory.invisibleUnicodeMatchedFiles> / <deterministicMandatory.invisibleUnicodeMatchCount>
- Bounded blockers and gap paths: <copy acquisitionCoverage.blockers and acquisitionCoverage.details; state explicitly when any list is truncated>

## Build manifest (if Section 6 ran)
| File | Size | SHA256 |
|---|---|---|
| ... | ... | ... |

## Release-asset hashes (if Section 7 ran)
| Asset | Size | SHA256 | Authenticode | Local build match |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## Release-asset coverage (verify_release only)
- Required release-asset acquisition complete: <true | false>
- Unique enumerated / downloaded+hashed: <enumeration.uniqueAssets> / <acquisition.uniqueDownloadedAndHashedAssets>
- Zero-assets release: <enumeration.zeroAssets>
- Duplicates / skipped / oversized / failed / byte-mismatch: <enumeration.duplicateAssets> / <acquisition.skippedAssets> / <acquisition.oversizedAssets> / <acquisition.failedAssets> / <acquisition.byteMismatchAssets>
- Bounded blockers/details: <copy releaseAssetCoverage.blockers/details and state when lists are truncated>

## Known misses / out of scope
- Static analysis cannot detect environment-gated payloads, polyglot files, or sufficiently obfuscated malware that doesn't match any pattern in this audit.
- Dependency provenance was checked for **npm only** in v1; <other ecosystems detected> were NOT audited at the dependency level.
- Build steps were ${buildExecutedNote}.
- This audit reflects the SHA pinned above. The repo could be republished or force-pushed at any time.

## What was actively scanned (use this to gauge confidence)
- [x/✗] Hardened clone with submodules/symlinks/hooks/LFS disabled
- [x/✗] Build/install hook scan (npm scripts, MSBuild targets, build.rs, gradle init, Makefiles, GH workflows)
- [x/✗] Obfuscation pattern scan (base64, packed JS, eval/Function dynamic args, eval(atob(...)) compound)
- [x/✗] **Required blob byte classification plus Invisible-Unicode scan over every text-classified blob — <classifiedAndInspectedBlobs>/<requiredBlobClassifications> mandatory blobs; text scanned=<fullyFetchedAndScannedTextBlobs>; binary metadata+preview inspected=<classifiedBinaryBlobs>; requiredAcquisitionComplete=<true|false>**
- [x/✗] Pre-built binaries in source tree
- [x/✗] Suspicious runtime patterns (network/process/fs/registry/credential reads)
- [x/✗] **Unconventional C2 channels (Solana RPC, Google Calendar API, gist/pastebin/IPFS/Telegram/Discord/DNS-TXT)**
- [x/✗] VS Code extension scrutiny (if applicable)
- [x/✗] npm lockfile typosquat / suspicious-dep heuristics
- [x/✗] Recent-changes lens (last 10 commits)
- [x/✗] Provenance: signed commits, signed tag, GH attestation, Authenticode, workflow-run cross-check

Mark each as ✗ with a one-line reason if you skipped it (e.g., "rate-limited", "no manifest found", "ecosystem not supported in v1").

If mandatory source acquisition is not complete, required release-asset
acquisition is not complete, or council coverage is required and not complete,
the report title must include **INCOMPLETE — DO NOT TRUST**, the
sole overall verdict must be \`incomplete\`, and all confirmed findings must be
labelled partial evidence rather than a trusted overall verdict.

## Recommendation
<"What I would do if I were you" — 1-2 sentences. Be honest. If the verdict is "no red flags found" but you only ran metadata_only, say so.>
\`\`\`

The finalizer appends a **Trusted acquisition coverage snapshot** generated
from active-audit state and, for \`verify_release\`, a **Trusted release-asset
coverage snapshot**. Do not fabricate, replace, or manually write either
snapshot. Use the latest wrapper snapshots for the human-readable summaries
above; the appended trusted snapshots are authoritative.
`}

${modeIsBuild(mode) ? renderRemediationBlock({
       pinnedPath: expectedClonePath,
       modeLabel: "build-mode",
       remediationSource: modeUsesCouncil(mode)
           ? "validationFinal.remediation"
           : null,
   }) : ""}

${modeUsesCouncil(mode)
        ? `If the trusted decision is ineligible, skip remediation. Otherwise,
after the pre-finalization remediation block is complete (or not applicable),
call. Initialize \`operatorDecisions = []\` before remediation and append only
human operator choices using the structured contract described above:

\`\`\`
const finalizeResult = zerotrust_finalize_report({
  owner: "${owner}",
  repo: "${repo}",
  resolved_sha: "<RESOLVED_FULL_SHA>",
  operator_decisions: operatorDecisions
})
\`\`\`

Do not pass \`markdown_body\` in a council flow. The wrapper atomically
finalizes the canonical REPORT.md + FINDINGS.json pair from trusted state.`
        : `If \`reportMarkdown\` is an incomplete fallback, skip remediation. Otherwise,
after the pre-finalization remediation block is complete (or not applicable),
call:

\`\`\`
const finalizeResult = zerotrust_finalize_report({
  owner: "${owner}",
  repo: "${repo}",
  resolved_sha: "<RESOLVED_FULL_SHA>",
  markdown_body: reportMarkdown
})
\`\`\``}

Call \`zerotrust_finalize_report\` **exactly once**. A same-audit retry is
idempotent: it verifies and returns the already-recorded canonical pair without
rewriting, even if retry decision data differs. An unrecorded pre-existing
\`REPORT.md\` or \`FINDINGS.json\` is a hard failure and is never overwritten or adopted. Always
pass the full 40-character SHA returned by \`zerotrust_safe_list_tree\` or
\`zerotrust_safe_clone\`; never pass or derive a short SHA yourself. The
wrapper rejects any owner/repo/SHA mismatch, derives the hashed identity path internally,
appends bounded trusted acquisition coverage when available, enforces the
artifact size caps, records both paths and hashes together, and writes only
under the active build root.

Preserve \`finalizeResult.reportPath\` and \`finalizeResult.findingsPath\` and
use those canonical returned paths for every later user-facing message. If a wrapper result
provided \`boundContext.reportPath\`, require
\`finalizeResult.reportPath === boundContext.reportPath + path-separator +
"REPORT.md"\` and \`finalizeResult.findingsPath === boundContext.reportPath +
path-separator + "FINDINGS.json"\`; on mismatch, stop and report the identity error. If
finalization fails, report the refusal verbatim and do not close the audit.

---

## Section 9 — Audit cleanup + post-audit options

${mode === "verify_release" ? `**This was a verify_release audit.** No source clone exists, but release assets may be present in the canonical quarantine. Remove them through the active-audit-bound wrapper rather than raw shell deletion:

\`\`\`
zerotrust_cleanup_quarantine({})
\`\`\`

The wrapper derives the only permitted target from the active audit's trusted build root and resolved SHA. A missing quarantine directory is an idempotent success.` : modeUsesApiDirect(mode) ? `**This was an API-direct audit.** No wrapper-created source tree or release quarantine exists for this mode. REPORT.md and FINDINGS.json at the returned finalizer paths are preserved.` : modeIsBuild(mode) ? `**This was a BUILD mode.** Use the exact hashed owner/repo/full-SHA-bound clone path returned by \`zerotrust_safe_clone\`. Now that report finalization and any pre-finalization remediation are complete, call \`zerotrust_cleanup_audit\`:

\`\`\`
zerotrust_cleanup_audit({
  clone_path: ${modeUsesCouncil(mode) ? "runtimeContext.clonePath" : "cloneResult.clonePath"},
  // also_delete_report defaults to false — REPORT.md + FINDINGS.json are preserved
  // also_delete_quarantine defaults to true
})
\`\`\`

If the agent crashed mid-audit and a partial clone exists, the auto-purge logic inside \`zerotrust_safe_clone\` will eventually pick it up on the next audit (default 24h), but calling cleanup explicitly here is faster and less surprising.` : `**This was metadata_only.** The metadata short-circuit already performed lifecycle closure.`}

${mode === "metadata_only" ? "" : renderSweepAndCloseBlock({ buildRoot })}

Then **TELL THE USER**:
- The report path: \`finalizeResult.reportPath\`
- The findings ledger path: \`finalizeResult.findingsPath\`
- A one-sentence summary of the verdict
- Suggest they read the report when they have a chance

${modeUsesApiDirect(mode) ? `### Post-audit option: build verification

If the audit verdict is clean (or low-severity) and the user explicitly wants to build/install this project for runtime verification (e.g., to verify the prebuilt release binary matches a from-source rebuild), tell them:

> "If you want to also build/install this for verification, that's a separate operation. Re-invoke \`zerotrust_sourcecheck\` with \`mode: 'audit_and_safe_build'\` and \`i_understand_build_executes_code: true\`. That will clone source to \`${buildRoot}\` and use the wrapper-controlled install/build commands. Install lifecycle scripts stay suppressed, but repo-controlled npm build scripts, build.rs, and MSBuild targets may execute. \`audit_and_full_build\` currently uses the same wrappers and additionally requires \`unsafe: true\`; it changes admission/warning posture only and reserves a future distinction."

**Do NOT offer this preemptively.** Wait for the user to ask. The default audit answer is "I read the source via API and here's what I found"; builds are a separate, opt-in operation.` : ""}

---

## What you must NOT do (wrapper-required operations)

${modeUsesApiDirect(mode) ? `- Run \`git clone\` (or \`gh repo clone\`) **at all** — this is an API-direct audit mode. There is no on-disk clone, none is needed, and \`zerotrust_safe_clone\` will refuse for this mode. **There is no runtime backstop:** if you bypass the wrappers and run raw \`git clone\` via \`powershell\`, nothing on the host will stop you — but you will silently invalidate the audit (the report would no longer reflect bytes that came through the trusted-context flow). Respect this instruction; it is your only guard rail. Read source via \`zerotrust_safe_fetch_file\` instead.
- Run \`zerotrust_safe_clone\` (the wrapper itself) — it will refuse for this mode.` : `- Run \`git clone\` to anywhere outside \`${buildRoot}\`, or via \`gh repo clone\` (which bypasses our safe-clone hardening flags). Use \`zerotrust_safe_clone\` (preferred) or raw \`git clone\` with the hardening flags applied.`}
- Run \`npm install\` / \`yarn\` / \`pnpm install\` / \`pip install\` / \`cargo install\` without the wrapper-required safety flags in any build mode
- Run any package-manager install at all, OUTSIDE of build modes
- \`Start-Process\` / \`Invoke-Item\` / \`Mount-DiskImage\` any path under \`${buildRoot}\`
- Directly invoke any \`.exe\` / \`.dll\` / \`.msi\` / \`.bat\` / \`.cmd\` / \`.ps1\` under \`${buildRoot}\`

If a wrapper refuses an operation, **stop and tell the user** with the refusal reason verbatim — don't try a workaround.

Begin Section 1 now.
`;
}

export const __internals = { renderBuildSection };
