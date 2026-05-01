# debate

Adversarial multi-model debate: two agents argue **opposing** positions on a contested question, then an independent judge model renders a verdict.

This is the **opposite** pattern from `triple-duck`. Triple-duck seeks consensus; debate deliberately maximizes divergence to surface the strongest case for each side.

## What it does

1. **Opening round (parallel):** Debater A makes the strongest case for Position A; Debater B makes the strongest case for Position B.
2. **Optional rebuttal rounds (parallel):** Each debater sees the other's prior round and rebuts.
3. **Judge:** A third model reads the full transcript and renders a verdict including: strongest/weakest arguments per side, cruxes, verdict, confidence, and what would change its mind.

## Tool

- `debate(question, position_a?, position_b?, context?, rounds?, debaters?, judge?, cheap?)`

`position_a` and `position_b` must be supplied **together** or **neither** (otherwise the debate is unbalanced). If neither is supplied, the orchestrator infers both opposing positions from the question.

## When to use

Use when:
- The right answer is genuinely contested and multiple defensible views exist
- You want to stress-test a decision before committing
- Consensus-style critique (`triple-duck`) would prematurely converge

Don't use for questions with a clear right answer — debate forces both sides to be argued, which wastes calls if one side has no merit.

## Cost

- `rounds: 1` (default): **3 typical premium calls** — opening A + opening B + judge
- `rounds: 2`: **5 typical calls** — adds 1 rebuttal round
- `rounds: N`: `2N + 1` typical calls

**Worst case** (with retries): `4N + 1` calls — the handler reserves one retry per debater call. If you set `max_premium_calls`, it MUST satisfy the worst-case formula or the handler rejects the request.

`cheap: true` swaps in non-1M-context variants.

## Defaults

- Debaters: `claude-opus-4.7-xhigh` vs `gpt-5.5` (different model families maximize divergence; xhigh = extra-high reasoning, ~200k ctx)
- Judge: `claude-opus-4.6-1m` (different family from debater A, 1M ctx for full transcript handling)
- Cheap debaters: `claude-opus-4.7` vs `gpt-5.5`; cheap judge: `claude-opus-4.6`

**xhigh tradeoff:** for very long debates with extensive context, override `debaters` with a 1M-context model variant (use whatever your provider offers).

---

## Hardening (added in v2)

This extension uses input validation (zod), prompt-injection wrapping, secrets scrubbing, cost-ceiling enforcement, and static model fallback. Most logic lives in shared _shared/ modules; the per-extension files are a thin handler + packet composer.

Run tests from the workspace root:
```bash
cd ~/.copilot/extensions
npm test
```

See the workspace `README.md` for an overview of all five extensions.
