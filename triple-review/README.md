# triple-review

User-level Copilot CLI extension that registers a `triple-review` tool — a multi-model code review pattern with iterative consensus.

## What it does

`triple-review` launches three `code-review` sub-agents in parallel against the same diff, clusters their findings by consensus (3/3, 2/3, 1/3 agreement), runs a fourth **synthesis agent** to merge the 3 reviewer-proposed fixes for each 3/3 cluster into one canonical patch, validates and auto-applies, then iterates until findings stabilize.

Default reviewer trio: **Claude Opus 4.7 (xhigh reasoning)**, **Claude Opus 4.6 (1M)**, **GPT-5.5**.
Synthesis model: **Claude Sonnet 4.6** (cheaper, lower-latency).

The tool's handler does NOT spawn agents. It returns an instruction packet that the calling agent executes via its built-in `task` and `edit` tools. This keeps orchestration adaptive (multi-round, with user-interactive gates) and avoids re-implementing agent lifecycle in the extension process.

## When to use this vs. `triple-duck`

| | `triple-duck` | `triple-review` |
|---|---|---|
| **Input** | A plan, design, or approach (prose) | A code diff (staged/unstaged/branch/commit) |
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
                              // default: claude-opus-4.7-xhigh,
                              //          claude-opus-4.6-1m, gpt-5.5
  focus?: string,             // e.g., "security, error handling"
  max_rounds?: number,        // 1..10, default 3
  severity_threshold?: string // "critical"|"high"|"medium"|"low"|"nit"
                              // default "high" (stop when no open ≥ this remain)
  cheap?: boolean,            // Optional. Use cheap trio (see Cheap mode below).
                              // Mutually exclusive with `models`.
})
```

## Cheap mode

Pass `cheap: true` (or invoke as "triple review cheap") to swap the default reviewer trio for the **standard-reasoning, non-1M-context variants**:

| Slot | Default trio | Cheap trio |
|---|---|---|
| 1 | claude-opus-4.7-xhigh (extra-high reasoning, ~200k ctx) | claude-opus-4.7 (7.5×) |
| 2 | claude-opus-4.6-1m (6×) | claude-opus-4.6 (3×) |
| 3 | gpt-5.5 (7.5×) | gpt-5.5 (7.5×) |

**Synthesis model is unchanged** (claude-sonnet-4.6 — already cheap).

**Tradeoffs:**
- The default's slot-1 (xhigh) catches subtler bugs than standard reasoning, at ~200k context. For diffs that genuinely exceed 200k tokens, override `models` with a 1M-context variant in slot 1 (use whatever your provider offers).
- Cheap mode's slot-1 (`claude-opus-4.7`) is standard reasoning, 200k context — meaningfully weaker but cheaper.

**For maximum savings**, pair `cheap: true` with `max_rounds: 1`.

`cheap` and `models` are **mutually exclusive** — pass one or the other.

## Protocol summary (what the calling agent executes)

**Step 0 — Pre-flight**
1. Verify git repo (bail if not — UNLESS `scope: "paths:..."`, which skips this and the steps below that depend on git)
2. Resolve scope (with disambiguation when staged + unstaged overlap)
3. Diff-size sanity gate (warn >1500 lines; force `max_rounds=1` <30 lines) — skipped in `paths:` mode
4. Non-destructive backup snapshot (`git stash create` + `git update-ref refs/triple-review/backup` — does NOT modify the working tree, unlike `git stash push`) with restore command in final report — skipped in `paths:` mode (no backup is created and auto-applied edits are NOT recoverable through this protocol)
5. Cost preview to user

**Step 1 — Round loop (1..max_rounds)**

- **1a** Launch 3 parallel `code-review` agents (single tool-calls block, no narration between them)
- **1b** Reviewer-failure handling: retry once; if <3 succeed, downgrade round to advisory-only
- **1c** Cluster findings: same file + overlapping/±10 lines + root-cause keyword overlap; cluster severity = **MAX**
- **1d** For each 3/3 cluster: pre-check conflicts → synthesis agent merges 3 fixes → validate `before`-block matches → show diff → apply via `edit` → run validation gate (typecheck/lint/test). Stop loop on validation failure.
- **1e** Present top 10 of 2/3 + 1/3 + demoted-contested findings batched per file (accept / reject / defer). Auto-defer the rest.
- **1f** Stop if `(round ≥ max_rounds) OR (no open ≥ threshold AND zero new clusters introduced)`. Otherwise increment round and re-review.

**Step 2 — Final report**

Auto-applied / accepted / deferred / rejected lists, validation status per round, total premium calls used, and restore commands (`git reset --hard <preReviewHead>` + `git stash apply <backupSha>`). In `paths:` mode there is no backup — the report says so explicitly.

## Safety features

- **Synthesis-then-apply:** never directly applies a single reviewer's prose-form fix as "consensus." A separate agent merges all 3 proposed fixes into one canonical patch.
- **`before`-block validation:** synthesized patches must match current file content exactly before applying.
- **Validation gate:** typecheck/lint/test runs after each round's auto-applies. Loop stops on failure.
- **Backup snapshot (non-destructive):** `git stash create` + `git update-ref refs/triple-review/backup` before any modification — this captures the working tree as a stash COMMIT without touching the working tree itself (unlike `git stash push`). Restore command in final report. Skipped in `paths:` mode.
- **Scope disambiguation:** asks the user when staged + unstaged changes overlap (no silent prioritization).
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

See the workspace `README.md` for an overview of all five extensions.
