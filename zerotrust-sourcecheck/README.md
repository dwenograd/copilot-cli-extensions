# zerotrust-sourcecheck

Copilot CLI extension that audits a GitHub URL (or an already-on-disk
directory) for source-level malware indicators **without source files
ever touching your disk during URL audits**, and — only when you
explicitly ask — builds it from a pinned commit under a contained
sandbox directory with hardened install/build flags.

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
| `zerotrust_safe_fetch_file` | GitHub-API source byte fetch, in-memory only (API-direct mode). |
| `zerotrust_safe_clone` | Hardened git clone (no submodules / hooks / LFS smudge / symlinks). Build modes only. |
| `zerotrust_safe_install` | `npm/pip/cargo/dotnet` install with hardcoded safe flags. Build modes only. |
| `zerotrust_safe_build` | Build step gated on prior council outcome (council-build modes). |
| `zerotrust_record_council_outcome` | In-memory pass/fail recording the build-gate consults. |
| `zerotrust_finalize_report` | Canonical-path `REPORT.md` write under `<build_root>/_reports/`. |
| `zerotrust_cleanup_audit` | Removes the clone + report + quarantine artefacts. |
| `zerotrust_sweep_audit_scratch` | Deletes stray scratch files at the top of `build_root` + parent. |

## Quick start

The extension lives in this repo's `zerotrust-sourcecheck/` subdirectory.
After cloning the workspace per the repo root README, restart the
Copilot CLI (or `extensions_reload`) and you can invoke:

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo>
```

That defaults to `audit_source_council` mode — a 32-role multi-model
security council audit, API-direct (no source files on disk). The
council is thorough but launches many sub-agents in parallel and can
take several minutes for a small repo.

For a lighter first run (deterministic checklist only, no council):

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo> mode=audit_source
```

or set `ZEROTRUST_DETERMINISTIC_ONLY=1` in your environment to make the
deterministic mode the workspace default. All other modes are opt-in
— see [Modes](#modes) below.

## API-direct by default — no files on disk for audits

Default audit modes (`audit_source`, `audit_source_council`,
`verify_release`, `metadata_only`) operate entirely via the GitHub API.
The audit pipeline:

1. `zerotrust_safe_list_tree` enumerates the repo's file tree at a pinned
   SHA via `gh api`. Returns `{sha, entries: [...]}` in memory.
2. `zerotrust_safe_fetch_file` fetches each interesting file (manifests,
   lockfiles, install/build hooks, recently-changed files) from the
   GitHub API. Returns text or base64 in memory. Files >5MB return
   `{contentTooLarge, sha256, sizeBytes, previewBase64}` instead.
3. The deterministic checklist + 32-role council overlay reason about
   the in-memory content.
4. The final `REPORT.md` is the **only** thing written to disk.

This means: Defender / EDR never sees a source byte. Even if the audited
repo is known-distributed malware, the audit can complete cleanly
without triggering AV on your machine.

**Build modes** (`audit_and_safe_build`, `audit_and_full_build`,
`audit_and_*_build_council`) DO write source to a sandbox dir and run
the build. **They are NOT offered by default audits** — the agent will
NOT preemptively suggest building. You must explicitly invoke them as a
follow-up step (`mode: 'audit_and_safe_build'` + the appropriate ack
flag) AFTER reviewing the audit's `REPORT.md` and deciding you want
runtime verification.

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

Any audit mode that produces on-disk content includes a Section 9b
remediation flow in its packet: per HIGH/CRITICAL finding, the agent
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

- **Dynamic analysis / sandbox execution** — there is no sandbox; the
  build step (when run) executes on your real host.
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

The packet is the **primary** control. The **second** layer is the set
of `zerotrust_safe_*` wrapper tools listed at the top of this README
— the packet directs the agent to perform every dangerous operation
through these wrappers, with hardened flags hardcoded:

- `zerotrust_safe_clone` resolves the ref to a SHA via `git ls-remote`,
  refuses non-GitHub / SSH / credentialled URLs, refuses clones
  outside `build_root`, and clones with
  `protocol.file.allow=never`, `core.symlinks=false`,
  `core.hooksPath=NUL` (on Windows; `/dev/null` on POSIX),
  `--no-recurse-submodules --no-tags
  --filter=blob:none --no-checkout`, `GIT_LFS_SKIP_SMUDGE=1`, then an
  explicit checkout. Submodules, LFS smudge filters, symlinks, and
  client-side hooks are all neutralized before any repo-controlled file
  hits disk.
- `zerotrust_safe_install` hardcodes `--ignore-scripts` for npm / yarn /
  pnpm, `--only-binary=:all: --no-deps` for pip, `--locked` for cargo,
  `--locked-mode` for dotnet. Refuses paths outside `build_root`.
  Refuses install args that don't match `[A-Za-z0-9._=:@/\-]+`, capped
  at 32 entries × 256 chars (no shell-injection surface).
- `zerotrust_safe_build` runs the build with the same containment +
  injection-resistance rules. In council-build modes it consults the
  recorded council outcome and **refuses to build** if the council
  didn't pass.
- `zerotrust_finalize_report` writes `REPORT.md` only to the canonical
  `<build_root>/_reports/<owner>-<repo>-<sha>/REPORT.md` path. Refuses
  oversized writes (>1MB) and any agent-supplied `build_root` that
  doesn't match either the active audit's `buildPath` or the default
  (defence against destructive arbitrary-write via missing sessionId).
- `zerotrust_sweep_audit_scratch` deletes top-level stray scratch files
  left in `build_root` and (optionally) its immediate parent directory.
  Sub-agents have been observed writing source bytes / path
  enumerations to disk via PowerShell `Out-File` / `Set-Content` /
  `iwr -OutFile` in violation of the API-direct contract; this wrapper
  is the active cleanup layer. Only deletes top-level **files**, never
  directories, with a generous whitelist of known-good filenames
  (README, package.json, .gitignore, Makefile, Cargo.toml, backup files
  matching `<orig>.zerotrust-backup-<utc-ts>`, etc.). The packet's
  epilogue instructs the agent to call this at end-of-audit.

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
SDK's `types.d.ts` documents the contract, but the runtime doesn't
honor it. A bug report has been filed with the GitHub Copilot CLI team.

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

#### How to re-enable the hook if/when the runtime fix lands

When [the Copilot CLI bug](https://github.com/) is fixed (or if a future
SDK release introduces an opt-in deny-only hook surface that doesn't
require the broad elevated-permissions prompt), restore the second-layer
defence by adding back to `extension.mjs`:

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

That's the entire diff. `preToolUseHook`, `deactivateAudit`,
`clearRecordedOutcome`, `inspectToolCall`, and the full deny-policy
pattern set in `enforcement.mjs` are all still present, exported, and
unit-tested by `__tests__/enforcement.test.mjs` — no other code changes
needed.

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
| `audit_local_source_council` | Council audit against an on-disk path. | (explicit; `local_path=...`) |
| `verify_release` | Release-artifact provenance: signed tag, attestations, Authenticode, `workflow_run` cross-check. | `/releases/...` URLs |
| `audit_and_safe_build` | `audit_source` + safe build (mandates `--ignore-scripts` etc.). Requires `i_understand_build_executes_code`. | (explicit) |
| `audit_and_full_build` | `audit_source` + lifecycle-script build. Requires `i_understand_build_executes_code` AND `unsafe`. | (explicit) |
| `audit_and_safe_build_council` | Council audit + safe build. The build wrapper refuses to proceed until a passing council outcome is recorded, unless the explicit wrapper override is supplied. | (explicit) |
| `audit_and_full_build_council` | Council audit + full build. Requires both build acknowledgements and the same recorded-outcome gate. | (explicit) |

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
      <asset>.bin               ← downloaded release binaries (MOTW-stripped)
```

Reports are written **outside** the cloned tree so the report can be
trusted and the clone can be deleted independently.

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
git -c protocol.file.allow=never -c protocol.allow=https \
    -c core.symlinks=false -c core.fsmonitor=false \
    -c core.hooksPath=<NULL> -c core.longpaths=true \
    clone --no-recurse-submodules --no-tags --filter=blob:none --no-checkout \
    <canonical-url> <build_path>
git -C <build_path> checkout <RESOLVED_FULL_SHA>
```

Plus `GIT_LFS_SKIP_SMUDGE=1` in the environment. This neutralises:

- File-protocol fetches that submodule CVEs have abused
- Symlink-based work-tree escapes
- Hostile `.git/hooks/` payloads (via `core.hooksPath=<NULL>`)
- LFS smudge filters
- `.gitattributes` filter directives (inspected as text only)
- Pre-checkout submodule init

Minimum git version: 2.39.

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
  __tests__/              ← node:test unit + integration tests
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

Current test suite: 753 tests, 752 passing, 1 skipped (Windows-only
dev-mode symlink test), 0 failing.

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
(e.g. `claude-opus-4.7-xhigh`), the underlying `task` call will **fail
loudly at runtime** rather than silently substituting — zerotrust does
not currently wire through the `_shared/resolveModels()` fallback chain
that the other extensions in this workspace use.

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
