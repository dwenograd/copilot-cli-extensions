# zerotrust-sourcecheck — agent design notes

This file documents non-obvious constraints around sub-agent
orchestration and prompt-template design. Read it before modifying
`packet.mjs` Section 5 preambles, `council/promptTemplate.mjs`, or any
of the role manifests.

## Sub-agents MUST NOT write files

This rule mirrors the `triple-review` / `duck-council` "no `git diff`"
rule for a related class of failure: sub-agents writing PoC test files,
scratch dumps, or downloaded source bytes into the operator's workspace
and never cleaning up.

**The rule:** every sub-agent prompt this extension emits (council role
prompts, recursive `task`-tool launches, helper agent prompts) MUST
include an explicit "no file writes" preamble. Both `packet.mjs` Section
5 sub-agent preambles already do — if you add a new sub-agent launch
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
  1. **Prompt-level ban** in `packet.mjs` Section 5 preambles
     (the "Do NOT write files to disk for any reason" block).
  2. **`Set-Location $build_root`** required as the first line of
     every `powershell` call the sub-agent makes — so any accidental
     cwd-relative write lands inside the swept sandbox, not at the
     workspace root.
  3. **Post-hoc sweep** via `zerotrust_sweep_audit_scratch` — the
     orchestrator calls a non-dry-run sweep last to close audit state.
     Parent sweeping defaults on, so use dry-run and normally disable it
     unless the parent is dedicated scratch.

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
| API-direct | safe fetch/list wrappers + `web_fetch` for external context | same + `gh api` metadata |
| Build clone | `view`/`grep`/`glob`/`web_fetch` | same + git verification/GitHub CLI |
| Local source | `view`/`grep`/`glob` under `localPath` only | same + `web_fetch` for external advisories only |

These are prompt rules. No registered hook enforces built-in tool use.

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
  describe wrappers as a universal authorization boundary.
- The README's "Honest disclosure" section spells this out for users;
  preserve that wording when editing.

Operationally, per-session cleanup that used to happen in the now-
removed `onSessionEnd` hook is now performed by the canonical
end-of-audit close in `safeWrappers/sweepWrapper.mjs`. The packet's
Section 9 instructs the agent to call `zerotrust_sweep_audit_scratch`
(REQUIRED) for **every** mode (build, audit-only, API-direct,
metadata_only, local-source). Sweep runs strictly after cleanup, so on
a successful (non-dry-run) sweep the wrapper calls
`clearRecordedOutcome + deactivateAudit` to close the audit-state Map
entries cleanly. (Note: deactivate intentionally lives in sweep, not
cleanup — calling it in cleanup would null out `getTrustedAuditContext`
for the subsequent sweep call and silently retarget sweep at
`DEFAULT_BUILD_ROOT`. See `cleanupWrapper.mjs:144-152` for the same
note.) Per-mode TTL inside `getActiveAudit` is the secondary safety
net for sessions that never reach sweep — expired entries are deleted
on next access and that path also dispatches `clearRecordedOutcome`.
Worst case: a session that ends without reaching sweep AND without
further audit access leaves a few hundred bytes of stale Map state
until the extension process exits — bounded and trivial.

`zerotrust_cleanup_audit` is build-clone cleanup and runs **before** sweep.
API-direct `verify_release` has no clone path, so its quarantine directory
must be removed manually. A successful non-dry-run sweep is the final
deactivation point.

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

## Grains, owner-repo-sha basenames, and other invariants

If you touch wrapper code, preserve these invariants — they have tests
guarding them but the rationale is non-obvious:

- **Clone basename construction:** literal
  `<owner>-<repo>-<sha.slice(0,7)>`. Because owner/repo may contain hyphens,
  the basename is not reversibly parsed into components. Cleanup validates
  immediate-child placement, the broad canonical regex, and (during an active
  audit) exact equality with the recorded resolved clone path.
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
