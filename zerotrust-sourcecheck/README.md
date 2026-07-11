# zerotrust-sourcecheck

Copilot CLI extension that audits a GitHub URL (or an already-on-disk
directory) for source-level malware indicators. API-direct wrappers do
not intentionally create source files, but returned tool text can still
be retained in Copilot CLI session logs or oversized-tool-output storage.
Build modes clone a pinned commit under a contained directory and run
wrapper-controlled install/build commands.

This is the "would you trust this dependency / installer / random new
repo from someone on the internet" tool. It surfaces the patterns that
matter (install hooks, invisible-Unicode obfuscation, unconventional
C2 channels, credential-store reads, persistence, supply-chain) and
gives the orchestrator a tight playbook for triaging them.

## Tools registered

| Tool | Purpose |
|---|---|
| `zerotrust_sourcecheck` | Main entry point. Returns an instruction packet the orchestrator follows. |
| `zerotrust_safe_list_tree` | GitHub-API tree listing at a pinned SHA (API-direct mode). |
| `zerotrust_safe_fetch_file` | GitHub-API source fetch returned through the tool result; no source file is intentionally created by the wrapper. |
| `zerotrust_safe_clone` | Hardened git clone (no submodules / hooks / LFS smudge / symlinks). Build modes only. |
| `zerotrust_safe_install` | `npm`, `npm-install`, `yarn`, `pnpm`, `pip`, `cargo`, or `dotnet` dependency operation with hardcoded flags. Build modes only. |
| `zerotrust_safe_build` | Build step gated on prior council outcome (council-build modes). |
| `zerotrust_record_council_outcome` | In-memory pass/fail recording the build-gate consults. |
| `zerotrust_finalize_report` | Canonical-path `REPORT.md` write under `<build_root>/_reports/`. |
| `zerotrust_cleanup_audit` | Removes a canonical build-mode clone and matching quarantine directory; preserves the report unless explicitly asked to delete it. |
| `zerotrust_sweep_audit_scratch` | Deletes unrecognized top-level files in `build_root` and, by default, its parent. Dry-run first; parent sweeping can affect unrelated files. |

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

## API-direct by default

`audit_source`, `audit_source_council`, and `verify_release` obtain source
context through the GitHub API. `metadata_only` stops at metadata and does not
read source. The API-direct audit pipeline:

1. `zerotrust_safe_list_tree` enumerates the repo's file tree at a pinned
   SHA via `gh api`. It returns `coverageComplete`; this is false when GitHub
   truncates the tree or the wrapper's 5,000-entry anti-spill cap fires. A
   no-red-flags verdict is not valid until the gap is drilled into or reported.
2. `zerotrust_safe_fetch_file` fetches each interesting file (manifests,
   lockfiles, install/build hooks, recently-changed files) from the
   GitHub API. Text is returned through the tool result; binaries return
   metadata plus a 256-byte magic-byte preview. Files above the fetch
   ceiling return metadata-only or a bounded preview, depending on which
   GitHub API response path supplied the size/content. Text above the inline
   cap is truncated; there is currently no ranged follow-up API, so unresolved
   truncation must be reported as a coverage limitation.
3. The deterministic checklist + 32-role council overlay reason about
   the returned content.
4. The extension intentionally writes only `REPORT.md` for ordinary source
   audits. `verify_release` additionally downloads release artifacts into
   `_quarantine/` for hash and magic-byte verification.

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

- Each role's prompt enforces a **CONTAINMENT** rule: every path
  passed to `view`/`grep`/`glob` MUST start with `local_path`. Symlinks
  whose target resolves outside `local_path` are noted as artifacts
  but NOT followed. This is **prompt-time discipline**, not
  wrapper-enforced; if a role agent misbehaves it could in principle
  read outside the path.
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
not apply this source-edit flow. Per HIGH/CRITICAL source finding, the agent
walks you through three choices:

- **defang** — surgical edit (specific files + lines, in diff form).
  Agent calls `view` first to show you the proposed change, waits for
  your OK before any write, copies the original to
  `<file>.zerotrust-backup-<utc-ts>` first. **Never auto-applies,
  never batches multiple defangs.** One finding, one acknowledgement,
  one edit.
- **delete project** — `Remove-Item -Recurse -Force` against the
  audit's pinned path (either `local_path` for local audits or the
  sandbox clone for build audits). Confirmed twice; refuses any
  other path even one character off. `REPORT.md` (outside the pinned
  path) survives.
- **keep as-is** — append `## Operator decision` block to `REPORT.md`
  with the finding title + your one-line rationale. **Refuses
  "keep" without a written rationale** — the audit trail is the
  point. This is "I knew about this and chose to keep it anyway."

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

- **Sandboxed dynamic analysis.** Build modes execute repo-controlled build
  code on the real host. The wrapper constrains argv/path selection; it is not
  an OS sandbox or network monitor.
- **Decompiling release binaries.**
- **Network behavior monitoring.**
- **Proving "this repo is safe."** Static analysis catches patterns,
  not all malware. The verdict is always "no red flags found at
  SHA X" — never "clean."
- **Evading or coexisting with host antivirus.** This is important
  enough to deserve its own section ↓.

## ⚠️ Real malware samples + Windows Defender = noise (or dead audit)

The hardened-clone wrapper protects against **execution** of
repo-controlled code (no symlinks, no submodules, no LFS smudge filters,
no git hooks, no lifecycle scripts). It does **not** — and cannot —
protect against your host antivirus signature-scanning the cloned source
files.

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

For known-distributed malware: clone in a VM, audit there, copy the
`REPORT.md` back. Don't use your host machine.

## How it works

The extension follows the same instruction-packet pattern as the rest
of this workspace: the registered tool returns a long natural-language
playbook, which the calling agent executes using its existing tools
(clone, grep, view, web_fetch, sub-agents, powershell). All of the
heavy lifting happens in the agent loop, not inside the extension
process.

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
- `zerotrust_finalize_report` writes `REPORT.md` only to the canonical
  `<build_root>/_reports/<owner>-<repo>-<short-sha>/REPORT.md` path. Refuses
  oversized writes (>1MB) and any agent-supplied `build_root` that
  doesn't match either the active audit's `buildPath` or the default
  (defence against destructive arbitrary-write via missing sessionId).
- `zerotrust_sweep_audit_scratch` deletes top-level unrecognized files
  left in `build_root` and, by default, its immediate parent directory.
  Sub-agents have been observed writing source bytes / path
  enumerations to disk via PowerShell `Out-File` / `Set-Content` /
  `iwr -OutFile` in violation of the API-direct contract; this wrapper
  is the active cleanup layer. Only deletes top-level **files**, never
  directories, with a finite whitelist of known-good filenames
  (README, package.json, .gitignore, Makefile, Cargo.toml, backup files
  matching `<orig>.zerotrust-backup-<utc-ts>`, etc.). The packet's
  epilogue instructs the agent to call this at end-of-audit. Because the
  parent may contain unrelated files, run `dry_run:true` first and normally
  pass `also_sweep_parent:false` unless the parent is a dedicated audit area.

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
import { preToolUseHook, deactivateAudit } from "./enforcement.mjs";
import { clearRecordedOutcome } from "./safeWrappers/state.mjs";

// inside joinSession({ ... }), after the `tools: [ ... ],` array
hooks: {
    onPreToolUse: (input, invocation) => preToolUseHook(input, invocation),
    onSessionEnd: async (_input, invocation) => {
        if (invocation?.sessionId) {
            deactivateAudit(invocation.sessionId);
            clearRecordedOutcome(invocation.sessionId);
        }
    },
},
```

Those are the current integration points. `preToolUseHook`,
`deactivateAudit`, `clearRecordedOutcome`, `inspectToolCall`, and the
deny-policy patterns remain present and unit-tested, but any future wiring
must be revalidated against that SDK/runtime version.

For the specific case of sub-agents leaving scratch files in
`build_root` after an audit, the active mitigation is
`zerotrust_sweep_audit_scratch`. The packet instructs the agent to
call it in the audit epilogue.

## Modes

| Mode | What it does | Default for |
|---|---|---|
| `metadata_only` | GH API recon only, no clone. NOT a security audit. | (explicit) |
| `audit_source` | Recon + static audit via GH API (no clone) + verdict. | repo / commit / tree / pull URLs when `ZEROTRUST_DETERMINISTIC_ONLY=1` is set |
| `audit_source_council` | `audit_source` plus the 32-role council and meta-judge synthesis. | **Default** for repo / commit / tree / pull URLs |
| `audit_local_source` | Same as `audit_source` but against an already-on-disk path. | (explicit; `local_path=...`) |
| `audit_local_source_council` | Council audit against an on-disk path. | **Default when `local_path` is supplied** |
| `verify_release` | Release-artifact provenance: signed tag, attestations, Authenticode, `workflow_run` cross-check. | `/releases/...` URLs |
| `audit_and_safe_build` | `audit_source` + safe build (mandates `--ignore-scripts` etc.). Requires `i_understand_build_executes_code`. | (explicit) |
| `audit_and_full_build` | Build mode requiring both acknowledgements. It currently uses the same install/build wrappers as safe mode; see below. | (explicit) |
| `audit_and_safe_build_council` | Council audit + safe build. The build wrapper refuses to proceed until a passing council outcome is recorded, unless the explicit wrapper override is supplied. | (explicit) |
| `audit_and_full_build_council` | Council build requiring both acknowledgements and the recorded-outcome gate; wrapper commands remain the same as safe mode. | (explicit) |

### Safe vs full build: current behavior

The `unsafe` acknowledgement changes admission and warning text, but it does
not select a different installer implementation. Both safe and full modes call
the same `zerotrust_safe_install` and `zerotrust_safe_build` wrappers. Install
lifecycle scripts remain suppressed by the hardcoded install flags. Build
scripts/`build.rs`/MSBuild targets may execute in **both** modes because the
build command itself is arbitrary repo-controlled code.

### Council-build overrides are orthogonal

- `proceed_on_council_failure:true` bypasses only the incomplete-council gate.
- `council_build_override:true` bypasses only the severity gate.
- Both are required to bypass both conditions.
- Neither flag bypasses the requirement to record an outcome first.

The recorder accepts only `critical`, `high`, `medium`, `low`,
`no red flags found`, or `incomplete`. `info` is a finding severity, not an
overall recorded verdict. The local-source report template also contains older
`clean / suspicious / malicious` prose; translate it to the canonical
vocabulary before calling `zerotrust_record_council_outcome`. Likewise,
`reconnaissance only` is a report label, not a recordable council verdict.
The recorder also rejects inconsistent severity counts and requires
`verdict:"incomplete"` to use `complete:false`.

### Council role tool whitelists

| Source mode | Source-inspection roles | Provenance roles |
|---|---|---|
| API-direct URL | `zerotrust_safe_fetch_file`, `zerotrust_safe_list_tree`, `web_fetch` for external context | Same, plus `gh api` metadata verification |
| Build-mode clone | `view`, `grep`, `glob`, `web_fetch` | Same, plus git verification commands and GitHub CLI |
| Local source | `view`, `grep`, `glob` under `local_path` only | Same, plus `web_fetch` only for external advisory/CVE lookup |

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
  unsafe?: boolean,                               // required for full-build mode
  i_understand_private_repo_risk?: boolean,       // required for private repos
  roles?: object,                                 // council modes only
  extra_roles?: object[],                         // council modes only
  judge?: string,                                 // council modes only
  max_premium_calls?: number,                     // council modes only
})
```

## Storage layout

For an audit of `owner/repo` at SHA `abc1234`, all artefacts live
under `build_root`:

```text
<build_root>/
  owner-repo-abc1234/           ← cloned source (untrusted; do not execute)
  _reports/
    owner-repo-abc1234/
      REPORT.md                 ← audit report
  _quarantine/
    owner-repo-abc1234/
      <asset>.bin               ← downloaded release binaries (Windows MOTW removed when present)
```

Reports are written **outside** the cloned tree so they are not repo-controlled
files and the clone can be deleted independently. Their conclusions still
depend on audit coverage and model/tool behavior.

The basename is constructed literally as
`<owner>-<repo>-<sha.slice(0,7)>`. Because owner/repo names may contain
hyphens, wrappers do not reverse-parse that string into owner and repo; active
audit state binds the exact resolved path.

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

1. Write/finalize `REPORT.md`.
2. For council builds, ensure the council outcome was recorded before the
   build; recording is not an end-of-audit cleanup step.
3. For build modes, call `zerotrust_cleanup_audit` to remove the canonical
   clone. It deletes the matching quarantine directory by default and keeps
   the report by default.
4. For API-direct `verify_release`, there is no clone path, so
   `zerotrust_cleanup_audit` cannot be used. Delete the canonical
   `_quarantine/<owner>-<repo>-<short-sha>/` directory manually when finished.
5. Call a **non-dry-run** `zerotrust_sweep_audit_scratch` last; that call closes
   the in-memory audit state.

The sweep's runtime default is `also_sweep_parent:true`. That parent can hold
unrelated files, and the filename whitelist is not exhaustive. Prefer
`dry_run:true` first and `also_sweep_parent:false` unless the parent directory
is dedicated to audit scratch.

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
- **Synthetic malicious-fixture corpus** for regression testing of
  the audit logic. Currently ships unit tests for the deterministic
  pieces (URL parser, `preToolUseHook` / `inspectToolCall` deny-policy
  spec, safe wrappers) plus a clean-control corpus harness — but no
  adversarial fixtures.
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
  packet.mjs              ← long instruction-packet template
  modes.mjs               ← mode enum + per-mode policy helpers
  council/                ← role manifest + per-role prompt templates
  safeWrappers/           ← clone / install / build / report / cleanup / sweep / fetch / list-tree
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
- New deterministic-corpus fixtures (clean-control URLs only — see
  `__corpus__/README.md` for the AV-safety contract)
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
