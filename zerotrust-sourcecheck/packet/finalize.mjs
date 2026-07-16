// Build, release, final report, remediation, and lifecycle renderers.
// Pure: emits instructions only and performs no I/O.

import {
    BUILD_MODE_TAXONOMY_NOTE,
    modeIsBuild,
    modeIsFullBuild,
    modeIsSafeBuild,
    modeUsesApiDirect,
} from "../modes.mjs";
import { renderSweepAndCloseBlock } from "./shared.mjs";

function renderBuildSection(context) {
    const { mode, buildExecAck, unsafeAck } = context;

    // For non-build modes, omit host execution entirely. The user must
    // explicitly select a build mode before this surface is available.
    let buildSection;
    if (!modeIsBuild(mode)) {
        buildSection = ""; // omit entirely; not even a "skipped" placeholder
    } else {
        const sharedBuildInstructions = `${BUILD_MODE_TAXONOMY_NOTE}

Use \`zerotrust_safe_install\` for installs and \`zerotrust_safe_build\` for builds; do not run package-manager commands directly. Begin only after \`zerotrust_finalize_report\` has returned the durable canonical pair. These are the expected wrapper-backed operations per ecosystem:

- **npm:** \`npm ci --ignore-scripts; npm run build --if-present\`
- **yarn:** \`yarn install --ignore-scripts --frozen-lockfile; yarn build\`
- **pnpm:** \`pnpm install --ignore-scripts --frozen-lockfile; pnpm build\`
- **pip:** \`pip install --only-binary=:all: -r requirements.txt\` (refuse if no wheel-only install is possible)
- **cargo:** \`cargo build --locked --offline\` (after a separate \`cargo fetch --locked\` to populate the cache)
- **dotnet:** \`dotnet build --no-restore\` (after \`dotnet restore --locked-mode --force-evaluate\`)

Pass \`clone_path: cloneResult.boundContext.clonePath\` to the install/build
wrappers. When invoking \`zerotrust_safe_build\`, pass \`mode: "${mode}"\` as
advisory metadata. Trusted active-audit state and the finalized report record
remain authoritative.

For ANY ecosystem, before invoking the build, **list and report** the build-config files that may execute as part of the build (\`package.json\` build scripts, \`vite.config.js\`, \`webpack.config.*\`, \`build.rs\`, MSBuild \`.targets\`/\`.props\`, \`tsup.config.*\`, etc.). Surface them in the report as "build-time code execution surfaces."`;
        let modeBody;
        if (modeIsSafeBuild(mode)) {
            const ackLine = buildExecAck
                ? "User has acknowledged that build steps execute repo-controlled code.": "**STOP**. The user did NOT pass i_understand_build_executes_code: true. Inform them and refuse to build.";
            modeBody = `**Safe-build mode.** ${ackLine}

${sharedBuildInstructions}`;
        } else if (modeIsFullBuild(mode)) {
            const ackLine = (buildExecAck && unsafeAck)
                ? "Both required acknowledgement flags are set.": "**STOP**. Full-build mode requires BOTH i_understand_build_executes_code: true AND unsafe: true. Refuse to build.";
            modeBody = `**Full-build mode (host code-execution risk).** ${ackLine}

${sharedBuildInstructions}

The \`unsafe\` acknowledgement currently selects stricter admission/warning posture only. It does not select a less-restricted installer or enable install lifecycle scripts. Treat the build command as live repo-controlled code on a non-sandboxed host, exactly as in safe-build mode.`;
        } else {
            modeBody = `**Unknown build mode.** STOP and report that packet.mjs did not recognize mode \`${mode}\`.`;
        }
        const finalizedReportGateParagraph = `
**Finalized-report host gate:** the build wrapper refuses unless the canonical
REPORT.md + FINDINGS.json pair is durable, identity-matching, and sealed at the
finalized stage with a finalizer-derived trusted outcome. Incomplete findings,
incomplete assurance, and supported critical/high malicious behavior close the
gate. There are no caller bypass fields.`;
        buildSection = `---

## Section 8 — Hazardous post-audit host execution (${mode})

${modeBody}
${finalizedReportGateParagraph}

After build, hash all output binaries:
\`\`\`powershell
Set-Location '<exact cloneResult.boundContext.clonePath>'
Get-ChildItem '.\\dist','.\\build','.\\target','.\\out','.\\bin' -Recurse -File -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256 | Select-Object Hash, Path
\`\`\`
Return the output manifest separately to the operator. Do not modify the already
finalized report, do not treat build success or output hashes as assurance
evidence, and do not raise the assurance level.`;
    }

    return buildSection;
}

export function renderFinalizeReportLifecycleStage(context) {
    const { mode, owner, repo, buildRoot } = context;
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

5. **Hash compare to local build outputs** only when a separately authorized build audit produced outputs and the project documents reproducible builds. A mismatch means binary integrity could not be reproduced from source; it is not proof of malware.`: `SKIP release-asset acquisition in mode \`${mode}\`. Raw release asset enumeration/download is forbidden. Re-invoke the release URL with \`mode: "verify_release"\` to use the active-audit-bound release wrappers.`;

    const releaseTitleSuffix = mode === "verify_release" ? " (this is the headline mode for this URL)": "";

    return `---

## Section 6 — Release verification${releaseTitleSuffix}

${releaseSection}

---

## Section 7 — Final report

${mode !== "metadata_only" ? `Do not assemble REPORT.md or FINDINGS.json and do not copy model prose into either artifact. The current assurance lifecycle must already be validated. The finalizer reads the semantic scanner/reviewer records, semantic and red-team candidate ledgers, dependency/supply-chain state, evasive graph and exhaustive trace, independent assurance validation, coverage, and structured operator decisions. It deterministically derives the findings verdict, separate assurance result, counts, executive summary, recommendation, finding rows, and the canonical REPORT.md + FINDINGS.json pair.

The only caller-authored content is \`operator_decisions\`: bounded records referencing active validated graph finding IDs. If any required gate is incomplete, do not call the finalizer as though assurance were complete; preserve the blocker and finish the missing current stage. A build is forbidden until validated assurance is finalized.`: `This reconnaissance-only mode has no source assurance state. Keep the bounded metadata report draft in memory and pass it as \`markdown_body\`. The resulting artifact must say reconnaissance only and must not claim source-level assurance.`}

${mode !== "metadata_only"
        ? `After current assurance validation and remediation decisions are complete, call:

\`\`\`
const finalizeResult = zerotrust_finalize_report({
  owner: "${owner}",
  repo: "${repo}",
  resolved_sha: "<RESOLVED_FULL_SHA>",
  operator_decisions: operatorDecisions
})
\`\`\`

Do not pass \`markdown_body\` for a source audit.`: `Call:

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

${buildSection}

---

## Section 9 — Audit cleanup + post-audit options

${mode === "verify_release" ? `**This was a verify_release audit.** No source clone exists, but release assets may be present in the canonical quarantine. Remove them through the active-audit-bound wrapper rather than raw shell deletion:

\`\`\`
zerotrust_cleanup_quarantine({})
\`\`\`

The wrapper derives the only permitted target from the active audit's trusted build root and resolved SHA. A missing quarantine directory is an idempotent success.`: modeUsesApiDirect(mode) ? `**This was an API-direct audit.** No wrapper-created source tree or release quarantine exists for this mode. REPORT.md and FINDINGS.json at the returned finalizer paths are preserved.`: modeIsBuild(mode) ? `**This was a BUILD mode.** Use the exact hashed owner/repo/full-SHA-bound clone path returned by \`zerotrust_safe_clone\`. Now that report finalization and any pre-finalization remediation are complete, call \`zerotrust_cleanup_audit\`:

\`\`\`
zerotrust_cleanup_audit({
  clone_path: cloneResult.boundContext.clonePath,
  // also_delete_report defaults to false — REPORT.md + FINDINGS.json are preserved
  // also_delete_quarantine defaults to true
})
\`\`\`

If the agent crashed mid-audit and a partial clone exists, the auto-purge logic inside \`zerotrust_safe_clone\` will eventually pick it up on the next audit (default 24h), but calling cleanup explicitly here is faster and less surprising.`: `**This was metadata_only.** The metadata short-circuit already performed lifecycle closure.`}

${mode === "metadata_only" ? "": renderSweepAndCloseBlock({ buildRoot })}

Then **TELL THE USER**:
- The report path: \`finalizeResult.reportPath\`
- The findings ledger path: \`finalizeResult.findingsPath\`
- A one-sentence summary of the verdict
- Suggest they read the report when they have a chance

${modeUsesApiDirect(mode) ? `### Post-audit option: hazardous host execution

If the findings verdict reports no supported malicious behavior (or only
low-severity supported behavior) and the user explicitly wants to build/install
this project, tell them:

> "If you want hazardous post-audit host execution, that's a separate operation. Re-invoke \`zerotrust_sourcecheck\` with \`mode: 'audit_and_safe_build'\` and \`i_understand_build_executes_code: true\`. The audit/report finalizes before the shared wrapper-controlled install/build commands. Install lifecycle scripts stay suppressed, but repo-controlled npm build scripts, build.rs, and MSBuild targets may execute. Safe/full names are compatibility aliases for identical wrappers; full additionally requires \`unsafe: true\` and changes admission/warning posture only."

**Do NOT offer this preemptively.** Wait for the user to ask. The default audit answer is "I read the source via API and here's what I found"; builds are a separate, opt-in operation.`: ""}

---

## What you must NOT do (wrapper-required operations)

${modeUsesApiDirect(mode) ? `- Run \`git clone\` (or \`gh repo clone\`) **at all** — this is an API-direct audit mode. There is no on-disk clone, none is needed, and \`zerotrust_safe_clone\` will refuse for this mode. **There is no runtime backstop:** if you bypass the wrappers and run raw \`git clone\` via \`powershell\`, nothing on the host will stop you — but you will silently invalidate the audit (the report would no longer reflect bytes that came through the trusted-context flow). Respect this instruction; it is your only guard rail. Read source via \`zerotrust_safe_fetch_file\` instead.
- Run \`zerotrust_safe_clone\` (the wrapper itself) — it will refuse for this mode.`: `- Run \`git clone\` to anywhere outside \`${buildRoot}\`, or via \`gh repo clone\` (which bypasses our safe-clone security flags). Use \`zerotrust_safe_clone\` (preferred) or raw \`git clone\` with the security flags applied.`}
- Run \`npm install\` / \`yarn\` / \`pnpm install\` / \`pip install\` / \`cargo install\` without the wrapper-required safety flags in any build mode
- Run any package-manager install at all, OUTSIDE of build modes
- \`Start-Process\` / \`Invoke-Item\` / \`Mount-DiskImage\` any path under \`${buildRoot}\`
- Directly invoke any \`.exe\` / \`.dll\` / \`.msi\` / \`.bat\` / \`.cmd\` / \`.ps1\` under \`${buildRoot}\`

If a wrapper refuses an operation, **stop and tell the user** with the refusal reason verbatim — don't try a workaround.

Begin Section 1 now.
`;
}

export const __internals = { renderBuildSection };
