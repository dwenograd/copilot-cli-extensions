# zerotrust-sourcecheck — agent design notes

This file documents non-obvious constraints around sub-agent
orchestration and prompt-template design. Read it before modifying the
`packet/` stage renderers, `council/promptTemplate.mjs`, or any role manifest.

## Sub-agents MUST NOT write files

This rule mirrors the `triple-review` / `duck-council` "no `git diff`"
rule for a related class of failure: sub-agents writing PoC test files,
scratch dumps, or downloaded source bytes into the operator's workspace
and never cleaning up.

**The rule:** every sub-agent prompt this extension emits (council role
prompts, recursive `task`-tool launches, helper agent prompts) MUST
include an explicit "no file writes" preamble. The `packet/scan.mjs` and
`packet/validate.mjs` sub-agent preambles already do — if you add a launch
site, mirror the wording.

**Specifically forbidden patterns** (already called out in `packet.mjs`):

- `iwr -OutFile <path>` / `curl -o <path>` / `wget -O <path>`
- `Out-File`, `Set-Content`, `Tee-Object`, `> <path>`, `>> <path>`
- `edit` / `create` tool calls (the agent-side built-in tools, not
  the zerotrust safe wrappers — those are fine because they enforce
  their own path/size containment)
- `Invoke-Item`, `Start-Process`, `notepad`, `code` (default-handler
  launches that may also write side-effect files)
- Recursive `task`-tool launches for "verification" or "PoC" purposes
  (the agent must report what it would have wanted to test as text in
  its reply, not write a test file)

**Why this matters:**

- Sub-agents have full `edit`/`create`/`powershell` access. Without an
  explicit ban, they reach for those tools to "verify" findings or
  drop "evidence" files. The result is scratch files (often hundreds
  of KB of repo source) littering the workspace root.
- The catalysing incident: a multi-agent offensive-security audit of
  a large C++ project, where 24 parallel role agents left 6 files
  (~590KB) at the workspace root because their cwd was the workspace
  root, not the audit sandbox.
- The fix is layered:
  1. **Prompt-level ban** in the scan/validation packet preambles
     (the "Do NOT write files to disk for any reason" block).
  2. **`Set-Location $build_root`** required as the first line of
     every `powershell` call the sub-agent makes — so any accidental
     cwd-relative write lands inside the swept sandbox, not at the
     workspace root.
  3. **Post-hoc sweep** via `zerotrust_sweep_audit_scratch` — the
    orchestrator calls a non-dry-run build-root sweep before lifecycle
    closure. Parent sweeping defaults off; if explicitly enabled, dry-run
    first and use it only when the parent is dedicated scratch.

## `Set-Location $build_root` must be the first line of every `powershell` call

Belt-and-braces for the above. Even with the no-file-write ban, if a
sub-agent disobeys, the damage is contained to a directory the sweep
wrapper can clean. Without `Set-Location`, the disobedient write lands
at the orchestrator's cwd — often the operator's workspace root — and
sweep can't safely clean that (it would risk deleting real personal
files).

If a mode/tier permits a sub-agent `powershell` call, the preamble MUST
include `Set-Location '${buildRoot}';` (or equivalent) first. API-direct
source roles and local-source roles do not permit `powershell` at all.
Pin new prompt paths with a snapshot test in
`__tests__/v4r2r2Hardening.test.mjs` (see the `round-17:` tests for
the existing pattern).

## DO NOT use shell-based `git` commands inside reviewer prompts

This mirrors the `triple-review/AGENTS.md` and `duck-council/AGENTS.md`
rule. Same root cause (hung-shell deadlocks when sub-agent PowerShell
tools fail to drain `git diff` stdout buffers): role prompts forbid
reviewer-owned diff commands and use the already-available source/tree
context instead.

**The rule:** sub-agents spawned by this extension MUST NOT run
`git diff`, `git show`, `git log -p`, `git status`, or any other `git`
command via the powershell tool. They `view` file paths directly
instead. The council role prompts at `council/promptTemplate.mjs`
already constrain the tool whitelist to `view/grep/glob` (no
`powershell`) for the `source-inspection` tier — the `provenance` tier
gets `gh` for commit/tag metadata but is similarly forbidden from
piping git output through `Select-Object -First`.

## Mode-specific role tool whitelists

Keep `council/promptTemplate.mjs` and user documentation aligned:

| Mode | Source-inspection | Provenance |
|---|---|---|
| API-direct | `zerotrust_safe_list_analysis_facts` + safe fetch wrapper + `web_fetch` for external context; parent supplies the pinned SHA, coverage snapshot, and bounded candidate paths | same + `gh api` metadata (never re-resolve the source tree) |
| Build clone | `zerotrust_safe_list_analysis_facts` / `zerotrust_safe_index_source_file` + `view`/`grep`/`glob`/`web_fetch` | same + git verification/GitHub CLI |
| Local source | `zerotrust_safe_list_analysis_facts` / `zerotrust_safe_index_source_file` + `view`/`grep`/`glob` under `localPath` only | same + `web_fetch` for external advisories only |

These are prompt rules. No registered hook enforces built-in tool use.

Deterministic local/build preparation is stronger than those role rules:
`zerotrust_safe_list_source` and `zerotrust_safe_index_source_file` derive the
root from active audit state, refuse traversal/reparse following, execute
nothing, and retain only bounded normalized facts/hashes. Direct role reads
remain prompt-confined, but no role evidence becomes trusted unless it matches
the exact wrapper index identity, line range, and excerpt hash.

## Version-5 malicious-source contract

The objective is source-level malicious-behavior discovery and static proof,
not generic vulnerability/exploit scanning. Council modes keep the 32-role
discovery backbone and run the logical phases:

`Prepare → Scan → Trace → Validate → Dedupe/score → Finalize`

The durable state names are `acquired → prepared → scanned → traced → validated
→ finalized`; dedupe/scoring is part of constructing the validated decision
snapshot rather than a separate persisted stage.

Finding states are `candidate → validating → validated | refuted | unresolved`;
chain statuses are `complete | unresolved | contested`; validation records
independent `confirm` and `refute` decisions before terminal adjudication.

- Prepare uses one contained API/local/build analysis index plus deterministic
  activation plugins. Plugins consume normalized facts/manifests and emit graph
  seeds/context only, never findings or verdicts.
- Scan accepts structured candidates only with exact enumerated/indexed
  evidence identity.
- Trace preserves partial/contradictory chains as unresolved.
- Validate is static-only confirm/refute/adjudication. Validators execute no
  repository code, create no PoCs, and cannot introduce evidence/topology.
- Dedupe/score separates impact severity, evidence confidence, and
  malicious-project-fit likelihood.
- Finalize deterministically writes `REPORT.md` and source-text-free
  `FINDINGS.json` from one ledger snapshot. Model-authored report prose is
  refused; operator input is limited to structured decisions.

Any incomplete acquisition/index/plugin/council/trace/validation/release,
identity, truncation, or output-bound gate permits only `incomplete` and must
preserve the exact blockers. Remediation candidates are source-text-free
edge-breaking guidance. They are never auto-applied; one finding, one displayed
diff, and one explicit operator approval remain mandatory.

## Build-mode taxonomy wording is load-bearing

Safe and full build modes currently use the same install/build wrappers.
Install lifecycle scripts remain suppressed in both. Build commands may execute
repo-controlled npm build scripts, `build.rs`, and MSBuild targets in both.
Full mode still requires `unsafe`, but today that changes admission/warning
posture only and reserves a future distinction; it does not select a
less-restricted installer.

Keep this wording aligned across `modes.mjs`, `handler.mjs`, `extension.mjs`,
the build and post-audit sections of `packet.mjs`, and `README.md`. Focused
tests intentionally pin those surfaces against drift.

## `build_root` resolution (centralised)

The default `build_root` is resolved in one place:
`safeWrappers/defaults.mjs`. Override order:

1. `ZEROTRUST_BUILD_ROOT` env var
2. `<homedir>/.copilot/zerotrust-sandbox` (created on first use)

If you add a new wrapper or destructive operation, import
`DEFAULT_BUILD_ROOT` from `safeWrappers/defaults.mjs` — do NOT
re-introduce the previous Windows-only literal. The destructive-op
defence-in-depth check (round-17 pattern) also relies on this single
constant — see `sweepWrapper.mjs` and `reportWrapper.mjs` for the
template:

```js
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";

// ...inside the handler, after getTrustedAuditContext returns:
if (args.build_root && !ctx.hasActiveAudit) {
    const argResolved = nodePath.resolve(String(args.build_root)).toLowerCase();
    const defaultResolved = nodePath.resolve(DEFAULT_BUILD_ROOT).toLowerCase();
    if (argResolved !== defaultResolved) {
        return failure(`<wrapper> refused: ...`);
    }
}
```

Tests use fixed sandbox paths (the `process.platform === "win32" ?
"<windows-fixture>" : "/tmp/zerotrust-sourcecheck"` ternaries you'll
see in `__tests__/*`) that are deliberately decoupled from the
production default. They give tests stable, predictable paths to
activate audits against — those paths get registered with
`activateAudit({buildPath: BR, ...})` so the wrapper sees them as the
active-audit anchor. Don't try to thread the production
`DEFAULT_BUILD_ROOT` into those test fixtures; the decoupling is
intentional.

## Metadata cache is untrusted, source-text-free derived data

The optional cache lives under the active audit's trusted `build_root`:

```text
_cache/schema-<cache-version>/tool-<sha256(tool-version)>/
  namespace-<sha256(normalized-source-namespace)>/
    source-<sha256(schema+tool+full-source-identity)>.json
```

Do not add a caller-supplied cache path. `safeWrappers/cacheWrapper.mjs`
must derive every path from active audit state and the canonical helpers in
`analysis/cache.mjs`. Every access requires the exact active `auditId`.
Cache absence or a schema/tool/plugin-version miss is normal and must not
make an existing v4/v5 flow fail.

The cache is not trusted merely because this extension wrote it. Every load
must re-check strict schema, canonical JSON bytes, the payload SHA-256,
source identity, compatible plugin versions, caps, and plain-file/plain-dir
status. Never follow a symlink, junction, or other reparse point. Corrupt
regular cache files are discarded and treated as misses.

Persist only structured normalized paths/identifiers, blob/content and
line-identity hashes, facts, graph topology, finding metadata, structured
validation decisions, and bounded stage/coverage metadata. Never add fields
for source/excerpt/snippet text, prompts, credentials/secrets, raw unbounded
repo strings, report bodies, verdicts/finalization, free-form labels,
summaries, rationales, warnings, or model output. Free-form strings are the
main privacy regression risk: cache contracts intentionally omit them even
when the live analysis contracts contain them.

Cross-source-SHA reuse is limited to records whose current path/blob or
content identity is unchanged. Prior-source stage/coverage is not returned,
and verdict/finalized state is not cacheable at all. Plugin records require
an exact plugin ID/version supplied to `zerotrust_cache_load`.
`zerotrust_cache_store` reads `getAnalysisPluginCacheRecords` rather than
reaching into `analysis/plugins/` state. That getter already returns the exact
persisted cache record shape with cache-stable IDs and stripped topology; the
cache wrapper must revalidate and consume it directly, never re-derive it.
Keep that API coordination boundary intact when plugin contracts change.

## V5 durable report artifacts are stricter than cache

`analysis/reportLedger.mjs` must construct `FINDINGS.json` through explicit
whitelisting, not broad `structuredClone` of live analysis snapshots. In
particular, never persist plugin fact `name`/`value`, warnings/errors, node
labels, behavior signatures, finding titles/summaries, validation rationales,
model output, source snippets, or source-controlled arbitrary strings.
Permitted report fields are bounded identities/enums, source identity,
paths/lines/hashes, counts/status/topology, structured validation/remediation
state, and structured operator decisions.

V5 `REPORT.md` prose is deterministic. Judges return structured decision data
only; they do not author summaries, recommendations, or operator context.
`zerotrust_finalize_report` accepts only `operator_decisions` for v5. Each
record references a canonical finding ID and predefined action/rationale
category. The optional short `operator_rationale` is a human-authored exception:
label it user-supplied, never trusted evidence, and reject code/backticks, URLs,
control characters, long opaque tokens, finding/verdict claims, and matches
against known source-derived values. Preserve the keep-as-is audit trail through
these records, not free-form model prose.

Legacy non-council `markdown_body` behavior remains supported, but its
FINDINGS.json verdict is `trusted:false` and the flow is explicitly outside the
v5 durable-output privacy guarantee. Cache absence, an old cache schema, or a
corrupt cache file is a normal miss, never a migration failure. Existing report
directories/files are not v5 state: only the active in-memory finalization
record authorizes an idempotent retry, and unrecorded canonical artifacts are
refused rather than adopted.

Writes must remain canonical, integrity-hashed, same-directory atomic, and
bounded by the file/count/total-byte caps. `zerotrust_close_audit` clears the
in-memory cache binding but preserves disk cache. Clone cleanup and stale
clone auto-purge also preserve cache. Only `zerotrust_cache_cleanup` removes
the active source entry/namespace; it accepts no raw path.

## The `onPreToolUse` hook is intentionally NOT registered

Copilot CLI 1.0.x does not invoke `onPreToolUse` for built-in tools
(`powershell`, `view`, `glob`, `grep`). The hook code in
`enforcement.mjs::preToolUseHook` is correct and tested — when the
runtime starts firing it, it could provide a true second layer of
defence. But as of v4-r3 we no longer register it in `extension.mjs`.

Reason: any `hooks: {}` block triggers an "extension wants elevated
permissions: register hooks" confirmation prompt at every CLI launch.
The hook capability class includes see-every-tool-input, modify-tool-
input, and run arbitrary code on every invocation — strong enough that
asking an operator to grant it for a hook the runtime ignores is a bad
trade. Operator-elevated-permission minimization wins over forward-
compat insurance.

When working on `enforcement.mjs`:
- `preToolUseHook` is still exported and still unit-tested as an
  executable specification of the deny policy. Don't delete it; if a
  future CLI release exposes a narrower opt-in deny-only hook surface,
  this is the policy that gets re-wired.
- The active-audit state machine (`activateAudit` /
  `getActiveAudit` / `deactivateAudit` / `recordResolvedClonePath` /
  `recordResolvedSha` / `getTrustedAuditContext`) is the load-bearing
  half of this file — the `safeWrappers/*` tools call into it.
- Full binding assumes an SDK-provided `sessionId`. Some no-session
  compatibility/test paths fall back to default/argument-root checks; do not
  describe wrappers as a universal authorization boundary. Destructive
  `cleanup_audit`, report finalization, council outcome recording, and lifecycle
  closure are exceptions: they require a real active session identity.
- The README's "Honest disclosure" section spells this out for users;
  preserve that wording when editing.

Operationally, per-session cleanup that used to happen in the now-
removed `onSessionEnd` hook is performed by
`safeWrappers/lifecycleWrapper.mjs::closeAuditHandler`. Cleanup and sweep
wrappers never deactivate state: deletion failures return failure and keep
the trusted audit anchor available for a safe retry. The packet routes every
terminal path (including metadata-only, private-repo refusal, local-source,
API-direct, and incomplete council outcomes) through
`zerotrust_close_audit`, after any destructive cleanup. Per-mode TTL inside
`getActiveAudit` is the secondary safety net for sessions that never close;
expired entries are deleted on next access and that path also dispatches
`clearRecordedOutcome`, `clearCouncilLedgerState`, and `clearCacheBinding`.
Worst case: a session that ends without reaching close AND without
further audit access leaves a few hundred bytes of stale Map state
until the extension process exits — bounded and trivial.

Every activation also creates a cryptographically random immutable `auditId`.
Council outcomes must echo that ID and are stored with owner/repo/full SHA;
`safe_build` requires an exact match to the current active generation. A late
outcome from an earlier audit in the same session is never reusable. Recording
is first-write-wins within a generation; only an identical normalized retry is
idempotent, and activating a new audit clears the prior outcome.

`zerotrust_cleanup_audit` is build-clone cleanup and runs **before** sweep.
API-direct `verify_release` has no clone path, so its quarantine directory
is removed by the active-audit-bound `zerotrust_cleanup_quarantine` wrapper.
`zerotrust_close_audit` is the final, cleanup-aware deactivation point. It
refuses to close while a recorded build clone or canonical `verify_release`
quarantine still exists. `abandon_artifacts:true` explicitly acknowledges that
those artifacts will be left on disk and cleanup authority relinquished.

Report finalization is exactly once per active audit. The first call uses
exclusive pair creation and records both canonical identities/hashes in active
state. Retries verify and return the pair without rewriting. A pre-existing
unrecorded `REPORT.md` or `FINDINGS.json` is never overwritten or adopted.

Every council mode records one immutable outcome before finalization. An
identical recorder retry is idempotent; replacement verdict/count/completion
data is refused. The report finalizer cross-checks the active audit identity,
requires exactly the recorded overall verdict and council completion boolean,
and permits an incomplete council to finalize only `incomplete`. Deterministic
modes remain outside this gate.

`verify_release` owns a second active-audit ledger for release assets. Asset
enumeration must use the already-bound numeric release ID/tag/source SHA; never
re-resolve `latest` or a tag. Fetch accepts only a discovered numeric asset ID,
uses `buildQuarantinePath` rather than spelling artifact directories, writes
only `<asset-id>.bin`, enforces the documented 100 MB maximum, verifies byte
counts, hashes bytes, and records duplicate/failure/oversize coverage. A
successful zero-asset list completes the asset gate. Any other unresolved asset
forces final verdict `incomplete`, and the finalizer appends the bounded trusted
release-asset coverage snapshot.

## Test seam: `__internals` exports

Several modules export an `__internals` object for test access (e.g.
`safeWrappers/sweepWrapper.mjs` exposes `ALLOWED_TOP_LEVEL_FILES`,
`isAllowedFilename`, `listScratchFiles`, `DEFAULT_BUILD_ROOT`).

When adding new internal helpers that tests need to reach, prefer
adding to `__internals` over exporting from the module's public
surface. The convention keeps the "what the tool registers vs what
tests poke" boundary visible.

## Test runner: `node:test`, not vitest

This extension uses Node's built-in `node:test` because most of the
tests pre-date the workspace-wide vitest adoption. Run with:

```text
node --test "__tests__/*.test.mjs"
```

The glob must be explicit — `node --test __tests__/` errors with
"cannot find module". The suite is in-process coverage; it does not prove
live GitHub API behavior, Copilot hook delivery, host AV behavior, or OS-level
build containment.

## Grains, hashed artifact basenames, and other invariants

If you touch wrapper code, preserve these invariants — they have tests
guarding them but the rationale is non-obvious:

- **URL artifact basename construction:** `zt-v1-` plus the SHA-256 digest of
  an unambiguous, case-normalized `(owner, repo, full resolved SHA)` tuple for
  clone, report, and quarantine directories. Cleanup validates immediate-child
  placement, the canonical hashed regex, and exact equality with active state.
  Legacy flattened full-SHA and 7-character names are recognized only by
  age-gated clone-only auto-purge; active cleanup and all new creation use the
  hashed identity. Auto-purge never deletes reports or quarantine.
- **`_reports/` and `_quarantine/` are immediate children of
  `build_root`.** Anything starting with `_` is refused as a clone
  basename (defends meta-dirs from being mistaken for clones).
- **Backup-file naming convention:** `<original>.zerotrust-backup-<utc-ts>`
  where `utc-ts` matches `[A-Za-z0-9_:-]+` (deliberately excludes `.`
  to prevent `evil.zerotrust-backup-DROP.exe` masquerading as a backup
  and evading the sweep wrapper's whitelist).
- **Charge-units convention** — this extension doesn't deal with mass
  units, but consistency with the rest of the workspace matters: if a
  future feature touches numeric data, follow whatever convention the
  surrounding code uses; don't invent a new one mid-file.
