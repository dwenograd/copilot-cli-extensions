// Section 4 acquisition renderer. Pure: emits wrapper instructions only.

import { modeNeedsClone, modeUsesApiDirect } from "../modes.mjs";

// Cross-platform "discard hooks" path. NUL on Windows, /dev/null on
// POSIX. See cloneWrapper.mjs for the rationale.
const NULL_HOOKS_PATH = process.platform === "win32" ? "NUL" : "/dev/null";

const HARDENED_CLONE_FLAGS = [
    "-c protocol.file.allow=never",
    "-c protocol.allow=https",
    "-c core.symlinks=false",
    "-c core.fsmonitor=false",
    `-c core.hooksPath=${NULL_HOOKS_PATH}`,
    "-c core.longpaths=true",
].join(" ");

const HARDENED_CLONE_TAIL = "--no-recurse-submodules --no-tags --filter=blob:none --no-checkout";

export function renderAcquisitionStage(context) {
    const { mode, owner, repo, canonicalUrl, parsed, expectedClonePath } = context;

    const cloneCommand =
        `git ${HARDENED_CLONE_FLAGS} clone ${HARDENED_CLONE_TAIL} ${canonicalUrl} ${expectedClonePath}`;

    const checkoutCommand = `git -C ${expectedClonePath} checkout <RESOLVED_FULL_SHA>`;

    const ENV_PRELUDE = "$env:GIT_LFS_SKIP_SMUDGE=1; $env:GIT_TERMINAL_PROMPT='0'";


    // Pre-build Section 4. Three flavors:
    //   - mode is metadata_only: no clone, no API enumeration (recon-only).
    //   - mode is API-direct (audit_source / audit_source_council / verify_release):
    //     fetch via gh api without intentionally creating source files.
    //   - mode is build: hardened on-disk clone.
    let cloneSection;
    if (modeUsesApiDirect(mode)) {
        cloneSection = `---

## Section 4 — API-direct file enumeration (NO wrapper-created source files)

This mode obtains source through the GitHub API. The wrappers do not intentionally create source files, although Copilot CLI/session logging may retain returned text. Finalization writes the canonical REPORT.md + FINDINGS.json pair; \`verify_release\` additionally writes fetched assets to its canonical quarantine. Do NOT call \`zerotrust_safe_clone\` (it will refuse for this mode).

**Step A — list the tree.** Call:

\`\`\`
zerotrust_safe_list_tree({ url: "${canonicalUrl}"${parsed.ref ? `, ref: "${parsed.ref}"` : ""} })
\`\`\`

This returns the pinned commit \`sha\`, distinct \`rootTreeSha\`, bounded current-call \`entries\`, \`entriesTruncated\`, merged/deduped aggregate counts, \`unresolvedSubtrees: [{path, sha}]\`, \`coverageBlockers\`, and aggregate \`coverageComplete\`. Every blob entry has \`classificationRequired: true\`; \`likelyBinaryByExtension\` is only a fetch-order hint and never an exclusion. The result includes bounded \`acquisitionCoverage\` accounting. Release audits also return \`releaseIdentity: {releaseId, tagName, sourceCommitSha, rootTreeSha, ...}\` plus \`boundContext.reportPath\` / \`boundContext.quarantinePath\`. Pin EVERY downstream source operation to \`sha\`; for releases, use ONLY that returned release id/tag and those bound paths.

**Coverage gate (mandatory):** if \`coverageComplete !== true\`, call the actual subtree API for each returned unresolved item, one at a time:

\`\`\`
zerotrust_safe_list_tree({ owner: "${owner}", repo: "${repo}", subtree_path: "<path from unresolvedSubtrees>" })
# or, when the SHA maps to exactly one path:
zerotrust_safe_list_tree({ owner: "${owner}", repo: "${repo}", tree_sha: "<sha from unresolvedSubtrees>" })
\`\`\`

The wrapper accepts only subtree identities already discovered from the pinned commit, prefixes subtree-relative paths, merges/dedupes them into audit state, and returns updated unresolved/coverage fields. Continue until \`coverageComplete === true\`. If \`coverageBlockers\` remains non-empty, \`unresolvedSubtreesTruncated === true\`, or coverage otherwise cannot complete, **you MUST NOT issue a "no red flags found" verdict**; report the audit as incomplete with those exact blockers.

**Step B — collect the mandatory deterministic set.** Across EVERY root/subtree response, retain every blob entry where \`classificationRequired === true\` — that is, every enumerated blob. Filename suffixes do not establish content type: plain-text payloads named \`.png\`, \`.exe\`, or anything else must still be returned as text and scanned. \`likelyBinaryByExtension\` may be used only to prioritize likely binaries earlier. **Every enumerated blob must be fetched as mandatory and byte-classified; every blob classified as text must also be fully returned and scanned, or the audit must report acquisition incomplete.**

Use the priorities below only to decide fetch ORDER and where to spend deeper semantic review; they do not reduce the mandatory whole-tree invisible-Unicode set:
- **Manifests:** \`package.json\`, \`package-lock.json\`, \`yarn.lock\`, \`pnpm-lock.yaml\`, \`requirements.txt\`, \`pyproject.toml\`, \`Pipfile.lock\`, \`Cargo.toml\`, \`Cargo.lock\`, \`go.mod\`, \`go.sum\`, \`*.csproj\`, \`packages.config\`, \`Gemfile.lock\`.
- **Install / build hooks:** anything matching \`*.sh\` / \`*.ps1\` in repo root or \`scripts/\`; \`build.rs\`; MSBuild \`.targets\` / \`.props\`; \`Makefile\`; \`.github/workflows/*\`.
- **VS Code extension manifests:** \`extension.json\`, \`package.json\` with \`activationEvents\`.
- **README + LICENSE** for sanity check.
- **Recently changed source files** — fetch the last 10 commits via \`gh api repos/${owner}/${repo}/commits?per_page=10&sha=<RESOLVED_SHA>\` and prioritize files those touched.

**Step C — fetch every enumerated blob as mandatory** with:

\`\`\`
zerotrust_safe_fetch_file({ owner: "${owner}", repo: "${repo}", sha: "<RESOLVED_SHA>", path: "<repo-relative-path>", coverage_scope: "mandatory", max_text_bytes: 1048576 })
\`\`\`

The wrapper classifies the actual fetched bytes, scans every returned text body for the mandatory invisible-Unicode ranges, extracts bounded normalized \`analysisFacts\` (never source excerpts), and returns \`classification\`, \`classificationComplete\`, \`invisibleUnicodeScan: {complete, matchCount}\`, \`analysisIndex\`, and the running \`acquisitionCoverage\` snapshot. Duplicate calls increment attempt/duplicate counters but never inflate unique-blob coverage. In council modes, role-owned calls that omit \`coverage_scope\` default to \`council_sample\`; council samples are advisory and **never** satisfy the parent's mandatory set or the preparation index.

**Text bytes under any filename** up to the requested 1MB inline cap return full \`text\` and receive the deterministic scan. Larger text returns truncated text and remains an explicit coverage gap.

**True binary bytes** NEVER return full content. A within-cap binary may satisfy mandatory classification with \`{sizeBytes, sha256, blobSha, classification: "binary", classificationComplete: true, encoding: "binary", previewBase64, previewByteCount}\`; its preview is capped at 256 bytes and no Unicode text scan is required. This preserves output bounds while proving that actual bytes, not the suffix, were inspected.

For an audit finding on a true binary in source, the tree path/size plus the wrapper's blob SHA, SHA256, byte-classification reason, and bounded preview are sufficient. **Do not request full binary content**.

Over-ceiling blobs return only bounded fields available on that GitHub API path. They remain incomplete even if a bounded preview or byte classification is available. Unfetchable, identity-mismatched, metadata-only, truncated-text, not-fetched, and council-sample-only blobs likewise remain explicit gaps.

**Step D — enforce acquisition + index + plugin coverage, then analyze.** Continue until the latest snapshot has \`acquisitionCoverage.requiredAcquisitionComplete === true\`, \`analysisIndex.complete === true\`, and \`analysisPlugins.coverageComplete === true\`, and \`analysisStageState.current\` has advanced to \`prepared\`. The wrapper advances \`acquired → prepared\` only after every enumerated blob is fully classified, every full text blob is indexed, no per-file/per-audit fact cap overflow occurred, and every detected ecosystem plugin completed without failure or truncation. The plugins consume only normalized facts/manifests, seed the audit-bound BehaviorGraph, and emit bounded normalized plugin facts and warnings — never source text, findings, validation decisions, or verdicts. If any coverage surface remains false, preserve its bounded blockers/details in REPORT.md and use verdict \`incomplete\`; **"no red flags found" is forbidden**. Use the graph seeds and normalized facts for deterministic preparation and fetched content for the existing v4 checklist. Council sampling remains separate from mandatory deterministic acquisition. The stage remains \`prepared\` until later council/scan/trace work explicitly advances it.

**Why API-direct + binary-never-returned:** the wrappers do not create an on-disk source tree, and true binaries return only bounded metadata/preview rather than full bodies. This materially reduces AV exposure, but Copilot CLI logs or oversized-output spill may still persist returned text and host AV may scan it. (Build modes are a separate explicit invocation that runs its own audit packet before using an on-disk clone.)`;
    } else if (modeNeedsClone(mode)) {
        cloneSection = `---

## Section 4 — Hardened clone (build mode)

You're in a BUILD mode (${mode}). The audit needs source on disk so it can run install/build steps. Use \`zerotrust_safe_clone\` — the wrapper hardcodes the hardening flags below:

\`\`\`powershell
${ENV_PRELUDE}
${cloneCommand}
${checkoutCommand}
\`\`\`

Notes on the flags (do not strip any):
- \`-c protocol.file.allow=never\` blocks file:// fetches that submodule CVEs have abused.
- \`-c core.symlinks=false\` prevents symlink-based work-tree escapes.
- \`-c core.hooksPath=${NULL_HOOKS_PATH}\` neutralizes any \`.git/hooks/\` payloads (\`NUL\` on Windows / \`/dev/null\` on POSIX discards hook paths so no scripts can be found).
- \`-c core.longpaths=true\` allows >MAX_PATH paths.
- \`--no-recurse-submodules --no-tags --filter=blob:none --no-checkout\` defers all blob fetch and checkout until you explicitly \`git checkout <SHA>\` — gives full commit metadata for the recent-changes lens with minimal initial network/disk.
- \`GIT_LFS_SKIP_SMUDGE=1\` defers LFS pulls.

Preserve the wrapper-returned \`boundContext.clonePath\`. It is the only source
root authorized for this audit; never reconstruct it from the placeholder path
printed above and never read a sibling directory under \`build_root\`.

**Mandatory deterministic preparation:** enumerate only the exact clone path recorded by \`zerotrust_safe_clone\`:

\`\`\`
zerotrust_safe_list_source({})
\`\`\`

Page through every returned entry using \`cursor\`, then call:

\`\`\`
zerotrust_safe_index_source_file({ path: "<returned repo-relative path>" })
\`\`\`

for every enumerated file. These wrappers do not execute repository code, do not follow symlinks/reparse points, never return source text, and refuse any root other than the active audit's exact recorded clone. Continue until \`analysisIndex.complete === true\`, \`analysisPlugins.coverageComplete === true\`, and \`analysisStageState.current === "prepared"\`. The bounded audit-bound plugins consume only normalized index facts/manifests, seed the active BehaviorGraph, and emit normalized plugin facts/warnings rather than findings, validation decisions, or verdicts. Any enumeration/read/classification/fact-cap blocker, or any detected ecosystem plugin failure/truncation, makes preparation incomplete and forbids a trusted verdict. Preparation stops at \`prepared\`; later scan/trace work owns later stage transitions.

If \`.gitmodules\` or \`.gitattributes\` appears in the wrapper enumeration,
inspect it only at \`boundContext.clonePath\` (the exact path returned by
\`zerotrust_safe_clone\`). Do NOT auto-init submodules. A standard
\`filter=lfs diff=lfs merge=lfs -text\` declaration is benign/expected. For any
custom filter, locate the corresponding \`filter.<name>.clean\`,
\`filter.<name>.smudge\`, or \`filter.<name>.process\` configuration and score
the command's actual execution behavior; shell/interpreter or network execution
is high, and fetch/decode+execute is critical.`;
    } else {
        cloneSection = ""; // metadata_only: no source enumeration at all
    }

    return cloneSection;
}

export { HARDENED_CLONE_FLAGS, HARDENED_CLONE_TAIL };
