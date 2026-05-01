# duck-council

Critique a topic with **6 role-specialized rubber-duck reviewers + 1 judge synthesis pass.** Sibling to `triple-duck` — use this when you want different ANGLES of critique rather than consensus across the same angle.

## When to use vs `triple-duck`

| Want… | Use |
|---|---|
| Three independent sanity checks on the same plan, and consensus matters | `triple-duck` |
| Differentiated angles (security AND perf AND skeptic AND user POV) | `duck-council` |
| Cheap quick check | `triple-duck cheap: true` |
| Highest-stakes pre-implementation review of something you'll ship | `duck-council` (default) |
| You only have a small change to review | `triple-duck` (council is overkill) |

`duck-council` costs ~2× a triple-duck in worst-case (14 calls vs 8 — both numbers are retry-inclusive maxima from the budget formulas) for ~6× the role coverage. Worth it for high-stakes designs; overkill for small changes.

## Roles

The "ignore X" lines in each prompt are load-bearing — they prevent every duck from drifting into generic critique.

- 🛡 **security** — attack surface, secrets, authn/authz, injection, supply chain, data exposure. *Ignores* perf/maintainability/UX.
- 🧪 **stability** — bugs that cause crashes/hangs/data corruption/wrong results. Edge cases, race conditions, off-by-one, null propagation. *Ignores* security/perf/UX.
- ⚡ **performance** — latency, throughput, complexity, hot paths, N+1, allocations, blocking I/O. *Ignores* security/maintainability/UX.
- 🔧 **maintainer** — coupling, naming, surprise factor, test-ability, implicit contracts, missing docs. *Ignores* security/perf/stability/UX.
- 🤔 **skeptic** — argues this should NOT be built or should be built smaller. YAGNI, scope creep, unvalidated assumptions, simpler alternatives.
- 👤 **user** — surprising behavior, error messages, defaults, silent failures, accessibility, breaking changes. *Ignores* implementation details.

## Default models (TIERED, not all-xhigh)

Tiered for cost/quality balance. Family-diverse: 4 Claude + 2 GPT among reviewers + Claude judge.

| Role | Default | Cheap mode |
|---|---|---|
| security | `claude-opus-4.7-xhigh` | `claude-opus-4.7` |
| stability | `claude-opus-4.7-xhigh` | `claude-opus-4.6-1m` |
| performance | `gpt-5.5` | `gpt-5.5` |
| maintainer | `claude-opus-4.6-1m` | `claude-opus-4.6` |
| skeptic | `gpt-5.4` | `gpt-5.4` |
| user | `claude-sonnet-4.6` | `claude-sonnet-4.6` |
| **judge** | `claude-opus-4.7-xhigh` | `claude-opus-4.7` |

Why tiered: an artist-grade UX duck doesn't need xhigh; security/stability do. The judge is highest-stakes (adjudicating 6 critiques + finding what they all missed) and gets xhigh by default.

## Judge pass

The judge does FOUR things, in this exact order:

1. **Cross-role contradictions** — finds them and ADJUDICATES (security says "validate this," perf says "validation costs 12ms" — pick the side that should win).
2. **Top priorities (ranked)** — opinionated ranked list across all roles, tagged with the roles that raised each.
3. **Premise challenge** — the most valuable section: "what did all 6 ducks miss because each had a sub-domain?" Names the unstated assumption nobody challenged.
4. **Executive summary** — 3 sentences max: fix-first / defer / ignore.

Raw 6 role outputs are preserved verbatim in a collapsible `<details>` appendix below the judge verdict (no information loss).

Bail-out gates:
- 0 valid role outputs → STOP, no judge.
- 1-2 valid → present raw, judge skipped (honesty-check on too few critiques is wasteful).
- 3-6 valid → judge runs (told which roles failed so it doesn't ask "where's the security duck?").

## Parameters

```ts
duck-council({
  topic: required string,             // what to critique — be SPECIFIC
  context?: string,                   // file paths, prior decisions, constraints
  focus?: string,                     // cross-cutting focus areas
  roles?: {                           // PARTIAL override; merges over defaults
    security?:    modelId,
    stability?:   modelId,
    performance?: modelId,
    maintainer?:  modelId,
    skeptic?:     modelId,
    user?:        modelId,
  },
  judge?: modelId,                    // override the judge model
  skip_judge?: boolean,               // true = raw outputs only (saves 2 calls)
  cheap?: boolean,                    // mutually exclusive with `roles` (empty `{}` is allowed)
  max_premium_calls?: integer,        // worst-case cap (default: no cap)
})
```

`roles` is an OBJECT (not a positional array) so you can't accidentally swap roles. Only the roles you specify are overridden; the rest use defaults.

## Cost

- Default (judge ON): **6 reviewers + 6 retries + 1 judge + 1 judge retry = 14 max premium calls.**
- `skip_judge: true`: **6 + 6 = 12 max.**

Handler enforces `max_premium_calls` BEFORE building the packet — you'll get a clear rejection if your cap is too low.

## Examples

**Default — high-stakes pre-ship review:**
```
duck-council(topic: "We're about to merge a rewrite of the auth flow that uses signed cookies instead of JWTs. Should we ship this on Friday?",
             context: "rewrite at src/auth/cookies.ts; existing JWT impl at src/auth/jwt.ts (to be deleted); load balancer is sticky-session; we have 50k DAU")
```

**Cheap mode — quick gut check:**
```
duck-council(topic: "Should I add a Redis cache layer for the catalog endpoint?",
             cheap: true)
```

**Skip judge — power-user, want to read raw critiques:**
```
duck-council(topic: "Critique this README rewrite",
             context: "...",
             skip_judge: true)
```

**Per-role override — heavier security bench:**
```
duck-council(topic: "Should this endpoint be public?",
             roles: { security: "claude-opus-4.7-xhigh", maintainer: "claude-opus-4.7-xhigh" })
```

## Implementation notes

- Pure pipeline: `parse → checkBudget → scrub → applyInjectionPolicy (per-call nonce, shared across all 3 free-text fields) → resolveModels per-role → buildInstructionPacket`.
- Free-text inputs (`topic`, `context`, `focus`) are scrubbed for credential patterns and wrapped in nonce-bounded USER_INPUT envelopes before being shown to sub-agents.
- All model IDs validated against `safeModelId` allowlist (prevents packet-injection via model-name field).
- Per the hung-shell fix in `triple-review` (pass-14), reviewer prompts explicitly forbid `git diff` / `git show` / `Select-Object -First N` patterns. Reviewers `view` files directly instead.

## Tests

```
npm test
```

16 duck-council tests (14 handler integration + 2 packet snapshots) on top of the broader 183-test workspace suite (199 total).
