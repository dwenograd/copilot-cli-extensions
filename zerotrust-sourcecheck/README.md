# zerotrust-sourcecheck

Copilot CLI extension that audits a GitHub URL (or an already-on-disk
directory) for source-level malware indicators. API-direct wrappers do
not intentionally create source files, but returned tool text can still
be retained in Copilot CLI session logs or oversized-tool-output storage.
Build modes clone a pinned commit under a contained directory and run
wrapper-controlled install/build commands. Safe/full modes currently use the
same wrappers: install lifecycle scripts stay suppressed, while repo-controlled
npm build scripts, `build.rs`, and MSBuild targets may execute in both.

This is the "would you trust this dependency / installer / random new
repo from someone on the internet" tool. Its objective is to find and
statically prove source-level malicious behavior chains: how attacker-controlled
content activates, what capability it reaches, and what effect or target follows.
It is not a generic vulnerability, exploit-development, lint, license, or broad
dependency-CVE scanner.

## Tools registered

| Tool | Purpose |
|---|---|
| `zerotrust_sourcecheck` | Main entry point. Returns an instruction packet the orchestrator follows. |
| `zerotrust_safe_list_tree` | GitHub-API tree listing at a pinned SHA (API-direct mode). |
| `zerotrust_safe_fetch_file` | GitHub-API source fetch returned through the tool result; no source file is intentionally created by the wrapper. |
| `zerotrust_safe_list_source` | Enumerates only the active local root or recorded build clone without following symlinks/reparse points; returns metadata, not source text. |
| `zerotrust_safe_index_source_file` | Indexes one enumerated local/build file with exact containment, classification, hashes, and bounded normalized facts; never returns source text. |
| `zerotrust_safe_list_analysis_facts` | Pages exact audit-bound indexed fact references (path, line range, identity, excerpt hash) without source text or excerpts. |
| `zerotrust_record_council_candidates` | Validates and records one structured role batch with exact indexed evidence, then gates `prepared → scanned`. |
| `zerotrust_trace_behavior_graph` | Audit-bound merge and bounded trace of deterministic plugin seeds plus finalized council graph fragments; returns source-text-free chains and validation conflicts. |
| `zerotrust_record_validation` | Paged audit-bound static validation: prepares required candidates, records independent confirm/refute decisions, records a separate adjudication, and advances `traced → validated` only when complete and untruncated. |
| `zerotrust_safe_list_release_assets` | Lists assets only for the active audit's already-bound numeric release ID/tag/source SHA and records bounded coverage. |
| `zerotrust_safe_fetch_release_asset` | Downloads one previously discovered numeric asset ID to the canonical quarantine, verifies byte counts, hashes it, and records coverage (100 MB hard maximum). |
| `zerotrust_cache_list` | Lists strictly revalidated metadata-cache entries for the exact active source namespace; absence is normal. |
| `zerotrust_cache_load` | Loads exact-source metadata or unchanged blob/content records from a prior source SHA, with exact plugin-version compatibility. |
| `zerotrust_cache_store` | Atomically stores only normalized, bounded derived index/plugin metadata in the canonical versioned cache. |
| `zerotrust_cache_cleanup` | Removes only the active source entry or active source namespace; accepts no raw path. |
| `zerotrust_safe_clone` | Hardened git clone (no submodules / hooks / LFS smudge / symlinks). Build modes only. |
| `zerotrust_safe_install` | `npm`, `npm-install`, `yarn`, `pnpm`, `pip`, `cargo`, or `dotnet` dependency operation with hardcoded flags. Build modes only. |
| `zerotrust_safe_build` | Build step gated on prior council outcome (council-build modes). |
| `zerotrust_record_council_outcome` | Immutably records a verdict bound to the current audit ID + owner/repo/full SHA; required before finalization in every council mode. |
| `zerotrust_finalize_report` | Exactly-once canonical `REPORT.md` + source-text-free `FINDINGS.json` finalization. Council artifacts render from one trusted ledger snapshot. |
| `zerotrust_cleanup_audit` | Removes only the active build audit's exact recorded hashed-identity clone; preserves the report/findings pair unless explicitly deleted. |
| `zerotrust_cleanup_quarantine` | Removes the canonical `verify_release` quarantine derived from active audit state; accepts no raw deletion path. |
| `zerotrust_sweep_audit_scratch` | Deletes unrecognized top-level files in `build_root`; parent sweeping is available but defaults off and must be dry-run first. |
| `zerotrust_close_audit` | Cleanup-aware close; refuses to strand a live clone/quarantine unless `abandon_artifacts:true` explicitly acknowledges that choice. |

## Quick start

The extension lives in this repo's `zerotrust-sourcecheck/` subdirectory.
After cloning the workspace per the repo root README, restart the
Copilot CLI (or `extensions_reload`) and you can invoke:

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo>
```

That defaults to `audit_source_council` mode — a 32-role multi-model
security council audit, API-direct (no wrapper-created source tree). The
council is thorough but launches many sub-agents in parallel and can
take several minutes for a small repo.

For a lighter first run (deterministic checklist only, no council):

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo> mode=audit_source
```

or set `ZEROTRUST_DETERMINISTIC_ONLY=1` in your environment to make the
deterministic mode the workspace default. All other modes are opt-in
— see [Modes](#modes) below.

## Version 5 malicious-source pipeline

Council modes retain the fixed **32-role discovery backbone**. Optional extra
roles are additive; they do not replace the required roster or its
mandatory/category/90% completion gates.

The logical pipeline is:

1. **Prepare** — API-direct, local-source, and build-clone inputs enter one
   audit-bound analysis index. Local/build enumeration and reads are
   exact-active-root wrapper operations that refuse traversal and reparse
   following. Deterministic activation plugins consume only normalized indexed
   facts/manifests and seed graph nodes/edges; they do not emit findings or
   verdicts.
2. **Scan** — the deterministic baseline and all successful discovery roles
   submit bounded candidate findings and graph fragments. Every evidence
   reference must match an enumerated file, exact indexed line range, current
   blob/content identity, and excerpt SHA-256.
3. **Trace** — deterministic plugin seeds and council fragments are merged into
   bounded activation/trigger-to-effect behavior chains. Missing, contradictory,
   or truncated topology remains unresolved and blocks a trusted verdict.
4. **Validate** — independent confirm and refute passes, then a separate
   adjudication, use only existing source-text-free evidence/graph IDs. This is
   **static-only proof**: validators execute no repository code, run no builds or
   fuzzers, create no PoCs, and cannot introduce evidence or graph edges.
5. **Dedupe / score** — validated, refuted, and unresolved candidates are
   grouped by semantic behavior identity. Impact severity, evidence confidence,
   and malicious-project-fit likelihood remain separate axes.
6. **Finalize** — the wrapper deterministically renders the canonical
   `REPORT.md` + source-text-free `FINDINGS.json` pair from one trusted snapshot.
   Only structured operator decisions may be added. Remediation is never
   auto-applied.

The durable stage state is `acquired → prepared → scanned → traced → validated
→ finalized`; dedupe/scoring occurs deterministically while constructing the
validated decision snapshot. Any incomplete acquisition, index, plugin,
council, trace, validation, release, identity, or output-bound gate preserves
the exact blockers and permits only verdict `incomplete`.

Finding state is `candidate → validating → validated | refuted | unresolved`.
Behavior-chain status is `complete | unresolved | contested`. Validation records
one independent `confirm` and one `refute` decision before the separate
`validated | refuted | unresolved` adjudication.

## API-direct by default

`audit_source`, `audit_source_council`, and `verify_release` obtain source
context through the GitHub API. `metadata_only` stops at metadata and does not
read source. The API-direct audit pipeline:

1. `zerotrust_safe_list_tree` enumerates the repo's file tree at a pinned
   SHA via `gh api`. Truncated/capped listings return identity-bound
   `unresolvedSubtrees`; call the wrapper again with a returned `subtree_path`
   or unambiguous `tree_sha`. Results merge and deduplicate until aggregate
   `coverageComplete` is true or exact blockers force an incomplete verdict.
2. Every enumerated blob is marked `classificationRequired`. The parent calls
   `zerotrust_safe_fetch_file` with `coverage_scope:"mandatory"` for every blob;
   filename extensions are ordering hints only, never exclusions. Valid UTF-8
   and supported BOM-marked UTF-16 are text and must be fully scanned.
   Structurally verified binaries return metadata plus a 256-byte magic-byte
   preview. Invalid UTF-8 without trusted magic or strong binary byte evidence
   remains unknown and incomplete; it is never lossy-decoded or accepted as
   binary. Oversized/metadata-only, truncated-text, failed, identity-mismatched,
   unfetched, and council-sample-only blobs keep quantitative
   `requiredAcquisitionComplete:false`.
3. The deterministic checklist + all 32 discovery roles reason about the
   returned content. Council-role samples are advisory and never satisfy the
   parent's mandatory acquisition ledger.
4. Candidate graphs are traced without execution. Every critical/high candidate
   (plus lower severities selected by `validation_min_severity`) receives
   independent static confirm and refute decisions followed by a separate
   adjudication. Validators receive bounded source-text-free graph/fact context
   and cannot add evidence or graph edges.
5. Finalization writes the canonical `REPORT.md` + `FINDINGS.json` pair.
   Version-5 council flows render both deterministically from trusted ledger
   state. Non-council compatibility flows still accept caller-authored Markdown,
   but their paired findings ledger is explicitly `legacy-v4` and
   `trusted:false`. The optional metadata-cache tools can persist normalized
   derived metadata when explicitly called, but current flows do not require or
   automatically populate the cache. `verify_release` additionally calls
   `zerotrust_safe_list_release_assets`, then
   `zerotrust_safe_fetch_release_asset` once per discovered numeric ID. The
   fetch wrapper ignores attacker-controlled names for path construction and
   writes only `<asset-id>.bin` under the canonical quarantine.
6. Release listing is bounded to 512 tracked unique assets. Downloads default
   to, and can never exceed, 100 MB per asset. A zero-asset release completes
   the release gate after a successful identity-bound list. Any truncated,
   skipped, oversized, failed, or byte-mismatched asset keeps
   `requiredReleaseAssetAcquisitionComplete:false`.

The wrapper itself does not create source files in these modes. This is
not a guarantee that source bytes never reach disk: Copilot CLI may retain
tool results/conversation logs, and large outputs may be spilled to host
temporary storage. Binary responses are deliberately tiny to reduce that
risk, not eliminate it.

**Build modes** (`audit_and_safe_build`, `audit_and_full_build`,
`audit_and_*_build_council`) DO write source to a sandbox dir and run
the build. **They are NOT offered by default audits** — the agent should not
preemptively suggest building. Invoke a build mode explicitly with the
required acknowledgement. A separate prior audit/report is recommended,
but the code does not enforce or authenticate one; a build-mode invocation
runs its own audit packet before the build section.

## Local-path mode — audit an already-downloaded directory

If you've already cloned a repo locally (or got a snapshot via archive
/ USB / NAS) and want to audit those exact on-disk bytes without
re-fetching from GitHub, use **local-path mode**:

```text
@zerotrust_sourcecheck local_path="<absolute-path-to-your-copy>"
                       i_understand_local_path_reads_my_disk=true
```

This activates `audit_local_source_council` (or pass
`mode="audit_local_source"` for the non-council variant). The 32-role
council runs against the local tree via `view`/`grep`/`glob` — no
clone, no GitHub API calls, no SHA pinning.

### Safety boundary for local mode

- Deterministic enumeration and indexing are wrapper-enforced against the exact
  active `local_path`. Callers cannot redirect the root; traversal, symlinks,
  junctions, and other reparse points are refused or skipped, repository code is
  never executed, and only bounded normalized facts/hashes are retained.
- Council roles may use `view`/`grep`/`glob` for deeper review under a separate
  prompt-level path rule. Built-in tools are not intercepted by a runtime hook,
  but role output cannot enter the trusted ledger unless its evidence exactly
  matches the wrapper-owned index identity, line range, and excerpt hash.
- `local_path` itself is validated: must be absolute, must exist, must
  be a directory, no `..` segments, no UNC / `\\?\` prefix, no
  credential-store paths (`.ssh`, `.aws`, `.docker`, `.kube`,
  `.gnupg`, `.password-store`, `Microsoft\Credentials`,
  `Microsoft\Vault`, `Microsoft\Protect`), no root-level symlinks.
- Wrappers (`safe_clone`, `safe_install`, `safe_build`) refuse with
  an explicit local-mode message when the active audit is local —
  there's no clone to install or build against.

## Section 9b — defang / delete / keep (build modes + local mode)

Build modes and local-source modes include a Section 9b remediation flow in
their packet. API-direct `verify_release` can create quarantine files but does
not apply this source-edit flow. In a v5 council flow, remediation starts only
from a validated, source-text-free candidate that identifies graph edges,
evidence locations/hashes, risk codes, and static verification criteria. No
stored diff or source text enters the ledger. Per HIGH/CRITICAL source finding,
the agent walks you through three choices:

- **defang** — surgical edit (specific files + lines, in diff form).
  Agent calls `view` first to show you the proposed change, waits for
  your OK before any write, copies the original to
  `<file>.zerotrust-backup-<utc-ts>` first. **Never auto-applies,
  never batches multiple defangs.** One finding, one acknowledgement,
  one edit.
- **delete project** — `Remove-Item -Recurse -Force` against the
  audit's pinned path (either `local_path` for local audits or the
  sandbox clone for build audits). Confirmed twice; refuses any
  other path even one character off. The canonical report/findings pair
  (outside the pinned path) survives.
- **keep as-is** — in v5, add one structured `operator_decisions` record
  referencing the canonical finding ID and a predefined rationale category.
  An optional one-line rationale must be the operator's own words and is labeled
  user-supplied, not evidence. Legacy v4 compatibility appends the equivalent
  block only to the in-memory Markdown draft before finalization. **Refuses
  "keep" without a written rationale.**

After all defangs, the agent suggests re-running the same audit on
the defanged tree to verify findings no longer trigger (mitigates
the "missed a second copy of the same payload elsewhere" risk).

## What it's for

The "clean source / infected binary" attack class — and its inverse,
source poisoning via supply-chain compromise — are the two big GitHub
threats this extension targets. Common patterns it actively looks for:

- **Install / build hooks** that fetch + execute remote scripts
  (`postinstall`, `build.rs`, MSBuild `BeforeTargets`, etc.)
- **Invisible-Unicode obfuscation (GlassWorm-class)** — payloads hidden
  in Tags / Variation Selectors / PUA / zero-width / bidi characters
  that don't render in editors and that visual code review CANNOT
  catch. Byte-level Unicode-range scans are mandatory.
- **`eval(atob(...))`** / `Function(atob(...))()` compound payloads
- **Unconventional C2 channels** — Solana blockchain RPC reads in
  non-crypto projects, Google Calendar / Drive API in non-calendar
  projects, Pastebin / Gist / IPFS / Telegram / Discord, DNS-TXT
  lookups
- **Pre-built binaries** in source trees outside `vendor/`
- **Credential-store reads** of `.aws`, `.npmrc`, browser cookies, SSH
  keys, OpenVSX / npm publish tokens
- **Persistence mechanisms** — registry Run keys, scheduled tasks,
  cron, systemd, autostart folders
- **Supply chain** — typosquats, packages with very recent first-publish
  dates, git/url/path deps in lockfiles, missing integrity hashes
- **CI workflow exfil patterns** — `pull_request_target` misuse,
  unpinned third-party action references, secrets echoed to logs
- **Provenance signal** — signed commits / signed tags, GitHub
  attestations, Authenticode on Windows binaries, `workflow_run`
  cross-check between release asset and source SHA

## What it explicitly does NOT do

- **Sandboxed dynamic analysis.** Build modes execute repo-controlled npm build
  scripts, `build.rs`, MSBuild targets, and other build-time code on the real
  host in both safe and full modes. The wrapper constrains argv/path selection;
  it is not an OS sandbox or network monitor.
- **Decompiling release binaries.**
- **Network behavior monitoring.**
- **Proving "this repo is safe."** Static analysis catches patterns,
  not all malware. The verdict is always "no red flags found at
  SHA X" — never "clean."
- **Evading or coexisting with host antivirus.** This is important
  enough to deserve its own section ↓.

## ⚠️ Real malware samples + Windows Defender = noise (or dead audit)

The hardened-clone and install wrappers suppress checkout/install-time
execution surfaces (no symlinks, submodules, LFS smudge filters, git hooks, or
install lifecycle scripts). A later build command may still execute
repo-controlled build-time code in either safe or full mode. The wrappers do
**not** — and cannot — protect against your host antivirus signature-scanning
the cloned source files.

If you point this tool at a known-distributed malware sample (e.g., a
keylogger, RAT, or stealer source repo) on a Windows host with Defender
real-time protection enabled, **Defender will quarantine the source
files mid-clone**. The audit will fail or produce a partial report
against whatever survived. This is Defender working as intended;
nothing in this extension can or should change that.

Specifically:

- Prebuilt `.exe` / `.dll` / `.pfx` / signed installer binaries inside
  a malware repo will trigger high-confidence signature matches.
- `.cs` / `.py` / `.js` / `.ps1` source containing well-known malware
  patterns may also match heuristically.
- Source-code text excerpts that this tool's audit pipeline writes to
  agent conversation logs and oversized-tool-output temp files (under
  `%LOCALAPPDATA%\Temp\` and your CLI session-state directory) are
  **also subject to Defender pattern matching** even though they are
  inert text. Those quarantines look scarier than they are — text bytes
  on disk cannot execute — but they will spam your Defender history.

**The right host for a real malware audit is an isolated VM (or a
machine without real-time AV).** This tool is fine for clean-control
verification, suspected-but-unconfirmed supply-chain compromise
hunting, educational security work on small benign-with-postinstall-hook
samples, and any of the deterministic / council audits against repos
you don't have prior reason to suspect contain *known-distributed*
malware.

For known-distributed malware: clone in a VM, audit there, copy the canonical
`REPORT.md` + `FINDINGS.json` pair back. Don't use your host machine.

## How it works

The extension follows the same instruction-packet pattern as the rest
of this workspace: the registered tool returns a natural-language playbook,
which the calling agent orchestrates. Safety-sensitive identity, acquisition,
indexing, plugin execution, candidate ingestion, tracing, validation state,
cache handling, and finalization are owned by registered wrappers rather than
free-form report assembly.

### Defense-in-depth

The packet is the **primary** control. The wrapper tools are
**substitutional controls** for calls routed through them; they do not
intercept raw built-in `powershell`, `view`, `grep`, `glob`, or network
tool calls. There is no registered pre-tool hook.

Trusted-context binding is an in-memory, session-scoped control. Production
SDK calls normally carry a `sessionId`; with one present, clone/install/build/
fetch/list wrappers refuse an absent or expired active audit. Direct no-session
callers (used by some tests/backward-compatible paths) can fall back to
argument/default-root checks, and therefore do not receive the full
operator-ack/mode binding. The wrappers are not a general authorization
boundary outside the registered tool flow.

- `zerotrust_safe_clone` resolves the ref to a SHA via `git ls-remote`,
  refuses non-GitHub / SSH / credentialled URLs, binds the active
  owner/repo/ref/SHA, and refuses clones outside `build_root`. Exact flags
  are documented under [Hardened clone](#hardened-clone).
- `zerotrust_safe_install` supports:
  - `npm` → `npm ci --ignore-scripts --no-audit --no-fund`
  - `npm-install` → `npm install --ignore-scripts --no-audit --no-fund`
  - `yarn` → `yarn install --ignore-scripts --frozen-lockfile`
  - `pnpm` → `pnpm install --ignore-scripts --frozen-lockfile`
  - `pip` → `pip install --only-binary=:all: --no-deps`
  - `cargo` → `cargo fetch --locked`
  - `dotnet` → `dotnet restore --locked-mode`
  It also binds the active clone and resolves the package-manager binary
  outside the audit tree. Install option values must use a single
  `--flag=value` token; split `--flag value` forms are rejected because the
  second token is positional.
- `zerotrust_safe_build` runs the build with the same containment +
  injection-resistance rules. In council-build modes it consults the
  recorded council outcome and **refuses to build** if the council
  didn't pass. Selectors are:
  - `npm` → `npm run build --if-present`
  - `yarn` → `yarn build`
  - `pnpm` → `pnpm build`
  - `cargo` → `cargo build --locked --offline`
  - `dotnet` → `dotnet build --no-restore`
  - `dotnet-publish` → `dotnet publish --no-restore`
- `zerotrust_safe_list_release_assets` accepts the owner/repo/numeric release
  ID/tag/full source SHA returned by the bound tree operation and rejects any
  mismatch. It never re-resolves `latest` or a tag, tracks zero assets and
  duplicates, and does not expose an attacker-controlled download path.
- `zerotrust_safe_fetch_release_asset` accepts only a previously enumerated
  numeric asset ID plus an optional lower `max_bytes`. It downloads through
  the GitHub asset-ID endpoint, verifies listed/downloaded/written byte counts,
  computes SHA-256, returns bounded magic/preview metadata, and writes only the
  numeric `.bin` filename produced under the canonical quarantine path builder.
- `zerotrust_finalize_report` writes the canonical pair
  `<build_root>/_reports/zt-v1-<sha256-identity>/{REPORT.md,FINDINGS.json}`.
  Council flows serialize only whitelisted source-text-free identity,
  path/line/hash, enum, count, status, topology, validation, remediation, and
  structured operator-decision fields from one trusted version-5 ledger
  snapshot. Plugin fact `name`/`value`, warning/error prose, source-controlled
  free strings, model output, and source snippets are not report-artifact
  fields. REPORT.md's executive summary, recommendation, finding rows,
  states/severities, operator-decision audit trail, and verdict are all rendered
  deterministically from the same FINDINGS.json snapshot. V5 rejects
  model-authored report prose. Callers may supply only `operator_decisions`
  referencing canonical finding IDs with predefined action/rationale categories.
  An optional short `operator_rationale` is explicitly labeled user-supplied,
  is not trusted evidence, and is rejected if it resembles code, a URL, an
  encoded token, a finding/verdict claim, or known source-derived text. Legacy
  non-council flows retain `markdown_body` compatibility, are marked
  `trusted:false`, and are outside this v5 durable-output privacy guarantee.
  Same-directory durable temp files are published exclusively; partial creation
  is rolled back where possible. Both paths, byte counts, and hashes are
  recorded together. Same-audit retries verify and return the existing pair
  without rewriting; missing/tampered recorded files and unrecorded pre-existing
  files fail closed. Trusted council verdicts require stage `validated` plus all
  source/release/council/trace/validation gates. Incomplete artifacts remain
  available with exact blockers. Only after both files are durable and recorded
  does the stage advance `validated → finalized`.
- `zerotrust_sweep_audit_scratch` deletes top-level unrecognized files
  left in `build_root`. Its immediate parent is included only when
  `also_sweep_parent:true` is passed.
  Sub-agents have been observed writing source bytes / path
  enumerations to disk via PowerShell `Out-File` / `Set-Content` /
  `iwr -OutFile` in violation of the API-direct contract; this wrapper
  is the active cleanup layer. Only deletes top-level **files**, never
  directories, with a finite whitelist of known-good filenames
  (README, package.json, .gitignore, Makefile, Cargo.toml, backup files
  matching `<orig>.zerotrust-backup-<utc-ts>`, etc.). The packet's
  epilogue instructs the agent to call this before lifecycle closure.
  Parent sweeping defaults off because the parent may contain unrelated
  files; dry-run before explicitly enabling it.
- `zerotrust_cleanup_quarantine` derives the canonical `verify_release`
  quarantine path from the active audit's trusted build root and resolved
  SHA. It accepts no raw path, and deletion failures keep the audit active
  for retry.
- `zerotrust_close_audit` performs no filesystem deletion, but checks whether
  the active build clone or `verify_release` quarantine still exists. It
  refuses closure until cleanup succeeds. `abandon_artifacts:true` explicitly
  leaves those paths on disk and relinquishes active cleanup authority.

If the agent tries to call `git clone` / `npm install` / `cargo build`
directly via the shell instead of through these wrappers, **nothing
stops it today** (see *Honest disclosure* below). The packet is
explicit about this — and the wrappers are the only correct path.

### Honest disclosure: no `onPreToolUse` hook is registered

Earlier versions of this extension registered an `onPreToolUse` hook in
`extension.mjs` to DENY dangerous shell calls as a backstop if the agent
strayed from the packet. Empirical probes against Copilot CLI **1.0.x**
(May 2026) showed that `onPreToolUse` and `onPostToolUse` do NOT fire
for built-in tools (`powershell`, `view`, `glob`, `grep`, etc.) — the
SDK's `types.d.ts` documents the contract, but the tested runtime did not
honor it. This repository does not record a public issue URL, so there is
no issue link to cite here.

As of v4-r3 we go further: **the hook is no longer registered at all.**
Registering any `hooks: {}` block triggers an "extension wants elevated
permissions: register hooks" confirmation prompt at every CLI launch.
That capability class is genuinely powerful — a hook can see every
tool input, modify tool inputs in flight, and execute arbitrary code
on every invocation — and we don't want to ask operators for a
capability the extension doesn't actually exercise.

The `preToolUseHook` function still lives in `enforcement.mjs` and is
still unit-tested as an executable specification of the deny policy. If
a future CLI release adds an opt-in, narrowly-scoped deny-only hook
surface, the policy is already written and can be re-wired by adding
the `hooks: {}` block back to `extension.mjs`.

The **substitutional-safety wrappers** described above are the actual
enforcement mechanism — they always have been, even when the hook was
registered.

#### How to re-enable the hook if/when the runtime changes

If a future SDK/runtime provides a tested opt-in deny-only hook surface
without the broad elevated-permissions prompt, the existing policy could
be wired back into `extension.mjs`:

```js
// near the top, with the other imports
import { preToolUseHook } from "./enforcement.mjs";

// inside joinSession({ ... }), after the `tools: [ ... ],` array
hooks: {
    onPreToolUse: (input, invocation) => preToolUseHook(input, invocation),
},
```

Only the deny hook should be reconsidered here. Lifecycle state must continue
through `zerotrust_close_audit`; do not restore unconditional `onSessionEnd`
deactivation, which would discard retry authority after cleanup failures.
`preToolUseHook`, `inspectToolCall`, and the deny-policy patterns remain
present and unit-tested, but any future wiring must be revalidated against
that SDK/runtime version.

For the specific case of sub-agents leaving scratch files in
`build_root` after an audit, the active mitigation is
`zerotrust_sweep_audit_scratch`. The packet instructs the agent to
call it in the audit epilogue.

## Modes

| Mode | What it does | Default for |
|---|---|---|
| `metadata_only` | GH API recon only, no clone. NOT a security audit. | (explicit) |
| `audit_source` | Recon + static audit via GH API (no clone) + verdict. | repo / commit / tree / pull URLs when `ZEROTRUST_DETERMINISTIC_ONLY=1` is set |
| `audit_source_council` | `audit_source` plus all 32 discovery roles, bounded graph tracing, independent confirm/refute/adjudication, and meta-judge synthesis. | **Default** for repo / commit / tree / pull URLs |
| `audit_local_source` | Same as `audit_source` but against an already-on-disk path. | (explicit; `local_path=...`) |
| `audit_local_source_council` | Council audit against an on-disk path. | **Default when `local_path` is supplied** |
| `verify_release` | Release-artifact provenance: signed tag, attestations, Authenticode, `workflow_run` cross-check. | `/releases/...` URLs |
| `audit_and_safe_build` | `audit_source` + shared install/build wrappers. Install lifecycle scripts stay suppressed; build-time repo code may execute. Requires `i_understand_build_executes_code`. | (explicit) |
| `audit_and_full_build` | Same wrappers as safe-build; additionally requires `unsafe` for admission/warning posture and reserves a future distinction. | (explicit) |
| `audit_and_safe_build_council` | Council audit + shared install/build wrappers. The build wrapper refuses to proceed until a passing council outcome is recorded, unless the explicit wrapper override is supplied. | (explicit) |
| `audit_and_full_build_council` | Same wrappers and recorded-outcome gate as the safe council build; additionally requires `unsafe`. | (explicit) |

### Safe vs full build: current behavior

The `unsafe` acknowledgement changes admission and warning text, but it does
not select a different installer implementation. Both safe and full modes call
the same `zerotrust_safe_install` and `zerotrust_safe_build` wrappers. Install
lifecycle scripts remain suppressed by the hardcoded install flags. Build
scripts/`build.rs`/MSBuild targets may execute in **both** modes because the
build command itself is arbitrary repo-controlled code. Full mode currently
reserves a future distinction only; it is not a less-restricted installer.

### Council-build overrides are orthogonal

- `proceed_on_council_failure:true` bypasses only the incomplete-council gate.
- `council_build_override:true` bypasses only the severity gate.
- Both are required to bypass both conditions.
- Neither flag bypasses the requirement to record an outcome first.
- Every recording must include the exact immutable `audit_id` printed in the
  current sourcecheck packet. The recorder stores it with owner/repo/full SHA,
  and the build gate rejects stale or cross-audit outcomes.
- Outcome recording is first-write-wins for that audit generation. Exact
  normalized retries are idempotent; changed verdicts, counts, completion, or
  identity are refused. Starting a new audit generation clears the old outcome.

The recorder accepts only `critical`, `high`, `medium`, `low`,
`no red flags found`, or `incomplete`. `info` is a finding severity, not an
overall recorded verdict, and `reconnaissance only` is a metadata-report label,
not a recordable council verdict.
The recorder also rejects inconsistent severity counts and requires
`verdict:"incomplete"` to use `complete:false`.

The first successful outcome write is immutable. An identical retry is
idempotent; a different verdict/count/completion payload is refused. Every
council mode records before final report finalization, not only council-build
modes. The finalizer requires the stored verdict, critical/high counts, and
completion state to exactly match the deterministic trusted ledger decision.
Incomplete council artifacts use verdict `incomplete`, `complete:false`, and
retain the ledger's partial severity counts. Deterministic legacy modes do not
use this gate.

### Council role tool whitelists

| Source mode | Source-inspection roles | Provenance roles |
|---|---|---|
| API-direct URL | `zerotrust_safe_list_analysis_facts`, `zerotrust_safe_fetch_file`, `web_fetch`; the parent supplies the pinned SHA, bounded paths, and coverage snapshot, and roles must not call `zerotrust_safe_list_tree` | Same, plus `gh api` metadata verification without re-resolving the source tree |
| Build-mode clone | `zerotrust_safe_list_analysis_facts`, `zerotrust_safe_index_source_file`, `view`, `grep`, `glob`, `web_fetch` | Same, plus git verification commands and GitHub CLI |
| Local source | `zerotrust_safe_list_analysis_facts`, `zerotrust_safe_index_source_file`, `view`, `grep`, `glob` under `local_path` only | Same, plus `web_fetch` only for external advisory/CVE lookup |

These are prompt-enforced whitelists, not runtime interception of built-in
tools.

### Default-mode env vars

The current default strategy is **opt-out** — if `mode` is omitted for a
repo, tree, commit, or pull-request URL, the extension selects
`audit_source_council` (the 32-role council audit). This is the
recommended setting because the council catches threat classes the
deterministic checklist alone doesn't surface.

To force the deterministic-only baseline (skip the council) for those
URL kinds, set:

```text
ZEROTRUST_DETERMINISTIC_ONLY=1
```

This downgrades omitted-mode repo/tree/commit/pull URLs to
`audit_source` (deterministic only, no council). Release URLs are
unaffected — they always default to `verify_release`.

The companion flag `ZEROTRUST_DEFAULT_COUNCIL=1` is recognised for
backward compatibility but is a no-op when the council is already the
default. If both env vars are set, `ZEROTRUST_DETERMINISTIC_ONLY=1`
wins (the safety-conservative choice).

## Tool schema

```text
zerotrust_sourcecheck({
  // EITHER url (URL mode) OR local_path (local mode)
  url?: "https://github.com/<owner>/<repo>[/...]",
  local_path?: string,                              // absolute path
  i_understand_local_path_reads_my_disk?: boolean,  // required with local_path

  mode?: "metadata_only" | "audit_source" | "audit_source_council" |
         "verify_release" | "audit_local_source" |
         "audit_local_source_council" | "audit_and_safe_build" |
         "audit_and_full_build" | "audit_and_safe_build_council" |
         "audit_and_full_build_council",
  ref?: string,                                   // override URL ref
  focus?: string,                                 // free-text emphasis
  build_root?: string,                            // see Storage layout
  i_understand_build_executes_code?: boolean,     // required for build modes
  unsafe?: boolean,                               // required for full-build modes
  i_understand_private_repo_risk?: boolean,       // required for private repos
  roles?: object,                                 // council modes only
  extra_roles?: object[],                         // council modes only
  judge?: string,                                 // council modes only
  max_premium_calls?: number,                     // council modes only
})
```

## Version-5 migration and compatibility

- The existing 10 mode names remain accepted; version 5 adds staged analysis
  contracts and tools without renaming the public mode taxonomy.
- Non-council finalization remains an explicit legacy-v4 compatibility path.
  It accepts `markdown_body`, writes the dual artifact pair, and marks the
  findings verdict `trusted:false`.
- Missing, old-version, incompatible, or corrupt metadata cache entries are
  normal misses. They never block an otherwise valid audit.
- Existing `_reports` directories or files are not imported as version-5 state.
  Only the active audit's in-memory finalization record authorizes an idempotent
  retry; unrecorded canonical `REPORT.md` or `FINDINGS.json` files fail closed.

## Storage layout

For an audit of `owner/repo` at SHA
`abcdef0123456789abcdef0123456789abcdef01`, all artefacts live under
`build_root`:

```text
<build_root>/
  zt-v1-<64-hex-sha256-identity>/ ← cloned source
  _reports/
    zt-v1-<64-hex-sha256-identity>/
      REPORT.md                 ← audit report
      FINDINGS.json             ← canonical source-text-free findings ledger
  _quarantine/
    zt-v1-<64-hex-sha256-identity>/
      <asset-id>.bin            ← downloaded release binaries (Windows MOTW removed when present)
  _cache/
    schema-1/
      tool-<64-hex-tool-version-hash>/
        namespace-<64-hex-source-namespace-hash>/
          source-<64-hex-versioned-source-identity-hash>.json
```

Reports are written **outside** the cloned tree so they are not repo-controlled
files and the clone can be deleted independently. Their conclusions still
depend on audit coverage and model/tool behavior.

The basename is `zt-v1-` plus the SHA-256 digest of an unambiguous,
case-normalized tuple `(owner, repo, full resolved SHA)`. This prevents the
delimiter collisions possible with flattened owner/repo names while keeping
clone/report/quarantine paths as immediate children of their required roots.
Age-gated auto-purge recognizes legacy full-SHA and 7-character clone
directories only as non-active orphans. It deletes stale clone directories
only; reports and quarantine are preserved for explicit active-bound cleanup.

### Metadata cache privacy and trust boundary

The metadata cache is **optional, untrusted derived data**, not an audit
result. No current v4/v5 packet path requires a cache hit. Every list/load
revalidates strict schema, schema/tool/plugin versions, canonical JSON, the
SHA-256 integrity digest, source namespace, and active source identity.
Corrupt regular files are discarded and treated as a miss. Cache directories
and files must be plain filesystem objects; symlinks and reparse points are
never followed.

Cache payloads may contain only:

- normalized relative paths and bounded identifiers;
- Git blob and content SHA hashes (plus line-identity hashes, never excerpts);
- normalized deterministic/plugin facts;
- graph node/edge topology without free-form labels;
- finding state/severity/confidence/source-reference metadata, without
  titles or summaries;
- structured validation decisions without free-form rationale;
- bounded stage and quantitative coverage metadata.

They must never contain source text, excerpt text, snippets, prompts,
credentials/secrets, raw unbounded repository strings, verdicts, report
bodies/finalization, or free-form model output. Unknown fields and
snippet-capable free-text fields fail validation. Cache writes use canonical
JSON, an integrity SHA-256, same-directory atomic replacement, a 4 MB
per-file cap, 64 MB/512-file total cap, and a 64-file per-source-namespace
cap. Cache-load payload selection is additionally bounded to 2 MB and reports
`truncated:true` rather than emitting an unbounded metadata result.

`zerotrust_cache_store` consumes the active analysis-plugin cache-record API
directly. That API already returns audit-ID/label-free topology and
cache-stable plugin-fact IDs in the exact persisted shape; the cache wrapper
revalidates those records without re-deriving them. Optional caller-supplied
records use the same strict persisted schema and cannot override an active
plugin ID/version record. A non-cacheable active plugin record is reported in
`skippedActivePluginRecords` and omitted rather than weakening the cache
privacy contract.

The cache privacy contract is separate from the stricter version-5 report
artifact contract. Cache records may retain validated normalized plugin
metadata values needed for exact reuse. `REPORT.md` and `FINDINGS.json` never
copy those values; they retain only plugin fact IDs/kinds, plugin
ID/version/producer, source identity, path/line/endLine, excerpt hash, bounded
enum tags when applicable, and quantitative/topology state.

GitHub cache identity includes normalized owner/repo plus the full resolved
source SHA. A later source SHA may reuse only records whose current
path/blob (or content) identity is unchanged; prior-source stage/coverage,
verdict, and finalized status are never carried forward. Plugin records
require an exact plugin ID/version requested by the caller. Local-source
identity additionally requires a complete set of current content hashes, so
cache absence before local indexing is expected.

Disk cache entries persist across `zerotrust_close_audit` and build-clone
cleanup. Closure clears only the in-memory active-audit cache binding and
does not treat a cache entry as a blocking artifact. Use
`zerotrust_cache_cleanup` explicitly to remove the current source entry or
the current source namespace; neither `zerotrust_cleanup_audit` nor stale
clone auto-purge deletes metadata cache entries.

### `build_root` default

Resolves in this order (first non-empty wins):

1. The `ZEROTRUST_BUILD_ROOT` environment variable
2. `<homedir>/.copilot/zerotrust-sandbox` (cross-platform; created on
   first use)

Override per-call with the `build_root:` argument:

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo>
                       build_root="/path/to/your/sandbox"
```

The default directory is created automatically the first time the
extension's handler runs.

### Cleanup sequence

1. In every council mode, record the immutable outcome before any report
   finalization (and before the build in council-build modes).
2. Write/finalize the canonical `REPORT.md` + `FINDINGS.json` pair.
3. For build modes, call `zerotrust_cleanup_audit` to remove the canonical
   clone. It deletes the matching quarantine directory by default and keeps
   the report/findings pair by default.
4. For API-direct `verify_release`, there is no clone path, so
   call `zerotrust_cleanup_quarantine`; it computes the canonical target from
   active audit state and does not accept an agent-supplied deletion path.
5. Call `zerotrust_sweep_audit_scratch` with
   `also_sweep_parent:false`.
6. Optionally call `zerotrust_cache_cleanup` if derived metadata should not
   persist. Cache retention is otherwise independent of clone/quarantine
   cleanup.
7. After every requested cleanup succeeds, call `zerotrust_close_audit`.
   Cleanup failures return failure and retain trusted state for retry. Closure
   itself refuses a still-existing clone/quarantine. Use
   `abandon_artifacts:true` only when intentionally leaving those artifacts.

The sweep's runtime default is `also_sweep_parent:false`. The parent sweep
remains available for dedicated audit scratch areas, but the filename
whitelist is not exhaustive: first call with `also_sweep_parent:true` and
`dry_run:true`, inspect the candidates, then explicitly run the destructive
parent sweep.

## Hardened clone

The packet uses this exact command (substitute variants — missing
hardening flags, wrong destination path, or a non-GitHub URL — are
refused by `zerotrust_safe_clone` and by the `inspectToolCall` policy
in `enforcement.mjs`; the latter is the *spec*, not a runtime hook,
since `onPreToolUse` is no longer registered — see "Honest disclosure"
above). `<NULL>` is `NUL` on Windows and `/dev/null` on POSIX — chosen
at runtime so git can never find a hook script via that path on either
platform:

```text
git \
  -c protocol.file.allow=never \
  -c protocol.ext.allow=never \
  -c protocol.allow=never \
  -c protocol.https.allow=always \
  -c core.symlinks=false \
  -c core.fsmonitor=false \
  -c core.hooksPath=<NULL> \
  -c core.longpaths=true \
  clone --no-recurse-submodules --no-tags --filter=blob:none --no-checkout \
  <canonical-url> <build_path>

git -C <build_path> \
  -c protocol.file.allow=never \
  -c protocol.ext.allow=never \
  -c protocol.allow=never \
  -c protocol.https.allow=always \
  -c core.symlinks=false \
  -c core.fsmonitor=false \
  -c core.hooksPath=<NULL> \
  -c core.longpaths=true \
  checkout <RESOLVED_FULL_SHA>
```

Both calls set `GIT_TERMINAL_PROMPT=0` and `GIT_LFS_SKIP_SMUDGE=1`.
This neutralises:

- File-protocol fetches that submodule CVEs have abused
- Symlink-based work-tree escapes
- Hostile `.git/hooks/` payloads (via `core.hooksPath=<NULL>`)
- LFS smudge filters
- `.gitattributes` filter directives (inspected as text only)
- Pre-checkout submodule init

The wrapper does not enforce a minimum Git version. If the installed Git does
not support one of these flags, the clone fails rather than silently dropping
the flag.

## `extra_args` restrictions

Both install and build wrappers cap `extra_args` at 32 strings of 256
characters and allow only `[A-Za-z0-9._=:@/\\-]+`.

- **Install:** every argument must start with `-`; positional package specs,
  URLs, paths, version pins, registry/index redirects, output/root/cwd/project
  redirects, traversal, absolute paths, and flags that negate the hardcoded
  safety options are refused. Values must be inline (`--flag=value`), not split
  into a following positional token.
- **Build:** redirect/negation flags, URL schemes, traversal, and absolute path
  values are refused. Unlike install, the build validator does not impose the
  blanket "must start with `-`" rule, so benign relative positional tokens can
  pass if they satisfy the remaining checks.

## What's deferred

- **Full ecosystem-specific dependency-audit parsers.** Currently
  ships npm-only lockfile heuristics. Other ecosystems (PyPI, Cargo,
  Go, NuGet, Gradle/Maven) are flagged in the report as
  "dependency-audit not yet implemented for this ecosystem."
- **Broader ecosystem-specific evaluation fixtures.** Version 5 now ships an
  AV-safe deterministic corpus for clean controls, benign lookalikes, generic
  cross-file behavior-chain shapes, incomplete graphs, and broken references.
  It intentionally does not ship live malware or executable payload samples.
- **`_shared/resolveModels()` integration** for automatic model
  fallback in the council. Currently zerotrust hard-fails at runtime
  if a default model is unavailable; the orchestrator extensions
  silently substitute via the workspace `MODEL_FALLBACK_MAP`. See
  [Model availability](#model-availability) for the operator
  workaround.
- **`/sandbox` integration as a third defense layer.** Recent Copilot CLI
  releases provide a session-level `/sandbox` toggle that runs
  the agent's built-in shell tool calls inside a sandbox layer, with
  filesystem and network access individually constrained
  (`settings.json` → `sandbox`). This is potentially the runtime-level
  backstop that the unregistered `onPreToolUse` hook (see [Honest
  disclosure](#honest-disclosure-no-onpretooluse-hook-is-registered))
  was supposed to provide: a containment layer that catches the agent
  shelling out to `git clone` / `npm install` / `cargo build` directly
  via the built-in `powershell` tool, bypassing the safe wrappers. With
  a strict config (working dir excluded, outbound connections off,
  local network off), even a wrapper-bypass would execute inside
  containment instead of with full user privileges.

  **Not adopting yet** because `/sandbox` is a session-global setting
  the operator must remember to enable with the correct multi-toggle
  config *before* invoking zerotrust. Defaults are wrong for this use
  case (working dir auto-included, outbound connections allowed). One
  forgotten toggle = no containment. The whole point of this extension
  is to be the thing you don't have to trust yourself to remember; a
  load-bearing user-discipline assumption defeats that. Revisit when
  the Copilot CLI provides at least one of: per-project sandbox policy
  enforcement (e.g., a `.copilot/settings.json` scope override),
  session-startup hooks that can refuse to start when sandbox config
  doesn't match a required policy, or a way to declare a required
  sandbox policy from the extension manifest.

## Layout

```text
zerotrust-sourcecheck/
  extension.mjs           ← thin shell, joinSession + tool registrations (no `hooks: {}` block — see "Honest disclosure")
  handler.mjs             ← runHandler entry: validate, scrub, build packet
  urlParser.mjs           ← pure URL/owner/repo/ref/path validation
  localPathValidator.mjs  ← local-path validation for local-mode audits
  enforcement.mjs         ← audit-in-progress state machine (used by wrappers) + unregistered preToolUseHook policy
  packet.mjs              ← stable packet assembly surface
  packet/                 ← prepare / acquisition / scan / trace / validate / finalize renderers
  modes.mjs               ← mode enum + per-mode policy helpers
  analysis/validation.mjs ← static validator/adjudication contracts + bounded validation state
  analysis/cache.mjs      ← strict metadata-cache schema, canonical JSON, identity/path derivation
  analysis/reportLedger.mjs ← source-text-free FINDINGS.json serialization + shared Markdown rendering
  council/                ← discovery-role and validation/adjudication prompt templates
  safeWrappers/           ← clone / install / build / report / cache / validation / cleanup / sweep / fetch / list-tree
  __corpus__/             ← regression corpus harness (see its own README)
  __tests__/              ← node:test in-process suite
  AGENTS.md               ← agent design notes (read before modifying sub-agent prompts)
```

## Running the unit tests

This extension uses Node's built-in `node:test` runner (not vitest like
the rest of the workspace), because most of its tests pre-date the
shared workspace tooling. From inside `zerotrust-sourcecheck/`:

```text
node --test "__tests__/*.test.mjs"
```

(Pass the glob explicitly — `node --test __tests__/` errors with
"cannot find module".)

The command runs the checked-in `node:test` suite: parser/handler, packet,
state, wrapper, and in-process integration coverage. It is not a live
end-to-end guarantee: API-direct tests do not call GitHub, build-wrapper tests
do not establish an OS sandbox, the unregistered hook is not exercised by the
Copilot runtime, and host AV behavior is not automated. A Windows symlink case
may skip when the host cannot create symlinks.

## Contributing

PRs and issues welcome at the repo root:
<https://github.com/dwenograd/copilot-cli-extensions>. The most useful
contributions right now are:

- New ecosystem dependency-audit parsers (PyPI, Cargo, Go, NuGet, Maven)
- Additional council roles for under-covered threat classes
- New AV-safe deterministic corpus shapes and expectation refinements (see
  `__corpus__/README.md` for the inert-marker and live-run safety contract)
- Wiring `_shared/resolveModels()` into the council role assignment
  (currently zerotrust hard-fails on unavailable models rather than
  silently falling back — see [Model availability](#model-availability))

Before modifying sub-agent prompt templates (`council/promptTemplate.mjs`,
`packet.mjs` Section 5 preambles, role manifests), read
[`AGENTS.md`](./AGENTS.md) — there are non-obvious constraints around
file-write prevention, `Set-Location`, and the `git diff` hung-shell
pattern that the rest of the workspace also enforces.

## Model availability

The council role defaults assume access to GitHub Models / Anthropic /
OpenAI tiers. If your provider doesn't offer a specific default model
(e.g. `claude-opus-4.8`), the underlying `task` call will **fail
loudly at runtime** rather than silently substituting — zerotrust does
not currently wire through the `_shared/resolveModels()` fallback chain
that the other extensions in this workspace use.

Category sub-judges default to `claude-opus-4.8`; the meta-judge defaults to
`gpt-5.6-sol`. Zero Trust renders every council/judge spawn with
`context_tier:"long_context"` and requests elevated effort for supported base
models. Roster entries such as `claude-opus-4.7-1m-internal` are capability
aliases; `task()` receives the translated base model plus separate
context/effort arguments.

To work around an unavailable default, pass an explicit `roles`
override (the value is the model ID as a flat string, not a nested
object) and/or override the judge:

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo>
                       roles={"install-build-hook": "claude-opus-4.7"}
                       judge="claude-opus-4.7"
```

You can override one role, several, or none. `judge` is a separate
top-level parameter and can be overridden independently:

```text
# Just swap the judge, leave all roles at defaults
@zerotrust_sourcecheck https://github.com/<owner>/<repo>
                       judge="claude-opus-4.7"

# Swap multiple roles
@zerotrust_sourcecheck https://github.com/<owner>/<repo>
                       roles={"obfuscation": "gpt-5.5", "install-build-hook": "claude-opus-4.7"}
```

The full list of allowed model IDs is in `council/roster.mjs`
(`ALLOWED_MODEL_IDS`). For the per-role default assignments, see the
same file's role manifest.

## License

MIT — see the workspace root [`LICENSE`](../LICENSE) file. By
contributing to this extension you agree to license your contribution
under the same terms.
