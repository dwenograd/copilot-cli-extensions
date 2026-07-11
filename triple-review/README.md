# triple-review

User-level Copilot CLI extension that registers a `triple-review` tool — a multi-model code review pattern with iterative consensus.

## What it does

`triple-review` launches three `code-review` sub-agents in parallel against a
materialized git diff, or current files in `paths:` mode. It clusters findings
by consensus, synthesizes applicable fixes, verifies patch preconditions,
applies them, then runs project validation before iterating.

Default reviewer preset aliases: `claude-opus-4.8`, `gpt-5.6-sol`,
`claude-opus-4.7-1m-internal` (the third spawns base `claude-opus-4.7`).
Synthesis model: **GPT-5.6 Sol**.

The tool's handler does NOT spawn agents. It returns an instruction packet that the calling agent executes via its built-in `task` and `edit` tools. This keeps orchestration adaptive (multi-round, with user-interactive gates) and avoids re-implementing agent lifecycle in the extension process.

## When to use this vs. `triple-duck`

| | `triple-duck` | `triple-review` |
|---|---|---|
| **Input** | A plan, design, or approach (prose) | A git diff, or current files via `paths:` |
| **Output** | Critique of the design, ranked by consensus | Findings + auto-applied fixes + final report |
| **Iterates?** | No — single pass | Yes — up to `max_rounds` |
| **Modifies code?** | No | Yes (with synthesis + validation gate) |
| **Best used** | BEFORE implementing a change | AFTER implementing a change |

Both follow the same architectural pattern (instruction packet → calling agent runs parallel `task` calls → consensus merge).

## Tool signature

```
triple-review({
  scope?: string,             // "staged" | "unstaged" | "all-uncommitted" |
                              //   "branch:<base>" | "commit:<sha>" |
                              //   "files:<comma-paths>" |
                              //   "paths:<comma-paths>" (no-git mode —
                              //     reviewers `view` files directly,
                              //     no diff baseline; for non-git dirs
                              //     OR reviewing current state without
                              //     a baseline)
                              // default: auto-detect (with disambiguation)
  models?: string[],          // exactly 3 distinct model IDs
                              // default: claude-opus-4.8,
                              //          gpt-5.6-sol,
                              //          claude-opus-4.7-1m-internal alias
  focus?: string,             // e.g., "security, error handling"
  max_rounds?: number,        // 1..10, default 3
  severity_threshold?: string // "critical"|"high"|"medium"|"low"|"nit"
                              // default "high" (early-stop when no unresolved
                              // finding at/above this remains and none is new)
  cheap?: boolean,            // Optional. Use cheap trio (see Cheap mode below).
                              // Mutually exclusive with `models`.
  max_premium_calls?: number  // Optional worst-case call cap:
                              // max_rounds × 16 (48 at the default 3 rounds).
})
```

## Cheap mode

Pass `cheap: true` (or invoke as "triple review cheap") to swap the default reviewer trio for **cheaper model presets**:

| Slot | Default trio | Cheap trio |
|---|---|---|
| 1 | claude-opus-4.8 | claude-opus-4.7 |
| 2 | gpt-5.6-sol | claude-opus-4.6 |
| 3 | claude-opus-4.7 (`-1m-internal` preset alias) | gpt-5.5 |

**Synthesis base model is unchanged in cheap mode** (`gpt-5.6-sol`), but cheap mode suppresses its automatic elevated reasoning effort.

**Spawn parameters:**
- Every reviewer and synthesis agent gets `context_tier:"long_context"`.
- Full-quality mode requests elevated (`xhigh`) effort only for supported resolved base models.
- Cheap mode suppresses automatic elevation for both reviewers and synthesis.
- Context aliases such as `claude-opus-4.7-1m-internal` are translated to base model IDs before `task()` is called.

**For maximum savings**, pair `cheap: true` with `max_rounds: 1`.

`cheap` and `models` are **mutually exclusive** — pass one or the other.

## Protocol summary (what the calling agent executes)

**Step 0 — Pre-flight**
1. Verify git repo (bail if not — UNLESS `scope: "paths:..."`, which skips this and the steps below that depend on git)
2. Resolve scope (auto-detect asks whenever more than one of staged,
   unstaged, or untracked is non-empty; untracked-only state is not silently omitted)
3. Diff-size sanity gate (warn >1500 lines; force `max_rounds=1` <30 lines) — skipped in `paths:` mode
4. Non-destructive tracked-file backup (`git stash create` + `git update-ref`) with restore metadata — skipped in `paths:` mode. `git stash create` does not modify the working tree, but it also does **not** capture untracked files.
5. Cost preview to user

**Step 1 — Round loop (1..max_rounds)**

- **1a** Launch 3 parallel `code-review` agents (single tool-calls block, no narration between them)
- **1b** Reviewer-failure handling: retry once; if <3 succeed, downgrade round to advisory-only
- **1c** Cluster findings: same file + overlapping/±10 lines + root-cause keyword overlap; cluster severity = **MAX**
- **1d** For each 3/3 cluster: pre-check conflicts → synthesis agent merges 3 fixes → validate `before`-block matches → show diff → apply via `edit` → run validation gate (typecheck/lint/test). Stop loop on validation failure.
- **1e** Present top 10 of 2/3 + 1/3 + demoted-contested findings batched per file (accept / reject / defer). Auto-defer the rest.
- **1f** Stop at `max_rounds`, or early when no deferred/unresolved finding
  meets the threshold and no new cluster was introduced.

**Step 2 — Final report**

Auto-applied / accepted / deferred / rejected lists, validation status per round, total premium calls used, and restore commands (`git reset --hard <preReviewHead>` + `git stash apply <backupSha>`). In `paths:` mode there is no backup — the report says so explicitly.

## Safety features

- **Synthesis-then-apply:** never directly applies a single reviewer's prose-form fix as "consensus." A separate agent merges all 3 proposed fixes into one canonical patch.
- **`before`-block validation:** synthesized patches must match current file content exactly before applying.
- **Validation gate:** typecheck/lint/test runs after each round's auto-applies. Loop stops on failure.
- **Backup snapshot (non-destructive, tracked files only):** `git stash create` captures tracked staged/unstaged state without touching the working tree. It does not capture untracked files. The packet's POSIX example writes a timestamped `refs/triple-review/backup-...` ref, while its PowerShell/final-report examples use `refs/triple-review/backup`; record the exact ref and SHA actually created rather than assuming one name. Skipped in `paths:` mode.
- **Scope disambiguation:** asks when multiple staged/unstaged/untracked sets are non-empty; untracked files are never silently treated as part of a git diff.
- **Rejected findings tracked across rounds:** users aren't pestered to re-decide.
- **Deferred findings passed to round 2+ reviewers:** so they don't waste calls re-flagging.
- **Round 2+ reviewers see applied diffs but NOT prior commentary:** preserves independence.
- **Prompt cap (10/round):** prevents user fatigue.

## Example invocations

```
# Review whatever's currently staged with defaults
triple-review()

# Review unstaged changes, focus on security
triple-review({ scope: "unstaged", focus: "security, input validation" })

# Review the current branch vs main, allow up to 5 rounds
triple-review({ scope: "branch:main", max_rounds: 5 })

# Quick single-pass review with cheap-mode preset
triple-review({ cheap: true, max_rounds: 1 })

# Review specific files only
triple-review({ scope: "files:src/auth.ts,src/session.ts" })
```

## Cost expectations

**Per round (worst case):** 3 reviewer calls + up to 3 reviewer retries + up to 10 synthesis calls (the synthesis cap is GLOBAL per round and includes any retries) = **16 premium calls**.

**Default `max_rounds: 3`:** worst case = `3 × 16 = 48` premium calls. The handler enforces this; if you pass `max_premium_calls: 15`, the request is rejected before any sub-agent launches.

**Typical happy-path** (one well-scoped diff, ~3 findings, validation passes round 1, early-stop): **3-6 reviewer calls + a handful of synthesis calls** — much lower than the cap.

The protocol previews the worst-case cost before round 1, so you can abort.

## Installation

This extension lives at `~/.copilot/extensions/triple-review/` (Windows: `%USERPROFILE%\.copilot\extensions\triple-review\`) and is auto-discovered on CLI startup. After edits, run `extensions_reload` from inside Copilot CLI to pick up changes.

---

## Hardening (added in v2)

This extension uses input validation (zod), prompt-injection wrapping, secrets scrubbing, cost-ceiling enforcement, and static model fallback. Most logic lives in shared _shared/ modules; the per-extension files are a thin handler + packet composer.

Run tests from the workspace root:
```bash
cd ~/.copilot/extensions
npm test
```

See the workspace `README.md` for an overview of all eight extensions.
