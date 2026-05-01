// _shared/models.mjs
//
// Single source of truth for model presets across the five extensions.
//
// ---------------------------------------------------------------------------
// FALLBACK TABLE DRIFT POLICY (read this if you touch MODEL_FALLBACK_MAP):
// ---------------------------------------------------------------------------
// The fallback table is hand-maintained because the extension SDK does not
// expose a model-listing API to extension code (verified against
// CopilotSession in the SDK type defs — listModels exists only on
// CopilotClient, which extensions cannot reach).
//
// Review and update this table when ANY of these triggers fire:
//   1. The user observes "default model unavailable" / opaque task failure
//      that turns out to be a deprecated model.
//   2. A `[fallback]` log entry appears in the user's session — that means a
//      real substitution happened; investigate whether the chain still
//      terminates at a working model.
//   3. The model provider (GitHub Models / Anthropic / OpenAI) announces a
//      deprecation that affects any model in MODEL_FALLBACK_MAP or
//      KNOWN_DEPRECATED_MODELS.
//   4. Otherwise: review monthly.
// ---------------------------------------------------------------------------

// Three-model trios — used by triple-duck, triple-plan, triple-review.
//
// `claude-opus-4.7-xhigh` is the default because pass-7 of the iterative
// triple-review surfaced 2 real medium bugs (cross-extension consistency gap
// + a prompt-injection vector via model overrides) that 6 prior passes with
// 1M-context defaults missed. The extra-high reasoning earns its cost.
//
// Trade-off vs a 1M-context default: xhigh has ~200k context (sufficient for
// the vast majority of invocations) instead of 1M. For genuinely huge inputs
// (multi-megabyte diffs, very large plans), pass an explicit `models: [...]`
// override using a 1M-context model variant if your provider offers one.
export const DEFAULT_MODELS = [
    "claude-opus-4.7-xhigh",
    "claude-opus-4.6-1m",
    "gpt-5.5",
];

// Cheap-mode trio: same model families, non-1M-context variants, no
// reasoning-tier upgrade. ~23% reviewer-cost savings vs default; reviewers
// have ~200k context.
export const CHEAP_MODELS = [
    "claude-opus-4.7",
    "claude-opus-4.6",
    "gpt-5.5",
];

// Debate-specific defaults: 2 debaters from different model families
// (maximize divergence) + 1 independent judge. xhigh upgrade applied to the
// Opus 4.7 debater for the same reason as DEFAULT_MODELS above.
export const DEFAULT_DEBATERS = [
    "claude-opus-4.7-xhigh",
    "gpt-5.5",
];
export const DEFAULT_JUDGE = "claude-opus-4.6-1m";

export const CHEAP_DEBATERS = [
    "claude-opus-4.7",
    "gpt-5.5",
];
export const CHEAP_JUDGE = "claude-opus-4.6";

// duck-council: 6 role-specialized reviewers + 1 judge synthesis pass.
// Tiered model assignment (NOT all-xhigh) per pass-15 triple-plan synthesis:
// - reasoning-heavy roles (security, stability) get xhigh
// - pattern-matching roles (performance) get cross-family GPT
// - context-heavy roles (maintainer) get 1M-context Opus
// - prior-diverse roles (skeptic) get a different GPT variant
// - intuition-heavy roles (user/UX) get a cheaper tier
// Family balance: 4 Claude + 2 GPT reviewers + Claude judge.
export const COUNCIL_ROLE_NAMES = ["security", "stability", "performance", "maintainer", "skeptic", "user"];
export const DEFAULT_COUNCIL_ROLES = Object.freeze({
    security: "claude-opus-4.7-xhigh",
    stability: "claude-opus-4.7-xhigh",
    performance: "gpt-5.5",
    maintainer: "claude-opus-4.6-1m",
    skeptic: "gpt-5.4",
    user: "claude-sonnet-4.6",
});
export const CHEAP_COUNCIL_ROLES = Object.freeze({
    security: "claude-opus-4.7",
    stability: "claude-opus-4.6-1m",
    performance: "gpt-5.5",
    maintainer: "claude-opus-4.6",
    skeptic: "gpt-5.4",
    user: "claude-sonnet-4.6",
});
export const DEFAULT_COUNCIL_JUDGE = "claude-opus-4.7-xhigh";
export const CHEAP_COUNCIL_JUDGE = "claude-opus-4.7";

// Triple-review's synthesis model (used for merging 3/3 reviewer fixes).
export const SYNTHESIS_MODEL = "claude-sonnet-4.6";

// Triple-duck judge: synthesizes 3 reviewer critiques into a unified, consensus-
// ranked output. Critiques are typically small (<10k each), so xhigh's ~200k
// context window is plenty; the win is the extra-high reasoning tier for
// nuanced cluster-and-conflict-resolution work.
export const DEFAULT_TRIPLE_DUCK_JUDGE = "claude-opus-4.7-xhigh";
// Cheap variant: standard reasoning, ~200k context. Cheap mode targets ~23%
// reviewer-cost savings; the judge stays on the highest model the cheap-mode
// theme allows (no reasoning-tier upgrade).
export const CHEAP_TRIPLE_DUCK_JUDGE = "claude-opus-4.7";

// Triple-plan judge: plans can be 30-50k tokens each, so 3 plans + judge
// instructions can easily exceed 150k. Default to a 1M-context variant to
// avoid silent truncation. Users who don't need 1M can override with
// `judge: "claude-opus-4.7-xhigh"` (deeper reasoning, smaller window).
export const DEFAULT_TRIPLE_PLAN_JUDGE = "claude-opus-4.6-1m";
export const CHEAP_TRIPLE_PLAN_JUDGE = "claude-opus-4.7";

// Triple-review severity ranking: index 0 = highest severity.
export const VALID_SEVERITIES = ["critical", "high", "medium", "low", "nit"];

// Models the user has observed as deprecated/unavailable. EMPTY by default;
// add IDs here as substitutions are observed in the wild. Only models in this
// set trigger automatic fallback substitution; everything else is presumed
// available (fail-fast at task-call time if not).
export const KNOWN_DEPRECATED_MODELS = new Set([
    // example: "claude-opus-4.6-1m",
]);

// Fallback chains. resolveModels() walks each chain when a default model is
// in KNOWN_DEPRECATED_MODELS, picking the first non-deprecated entry.
export const MODEL_FALLBACK_MAP = {
    "claude-opus-4.7-xhigh": ["claude-opus-4.7-high", "claude-opus-4.7", "claude-opus-4.6"],
    "claude-opus-4.7-high": ["claude-opus-4.7", "claude-opus-4.6"],
    "claude-opus-4.6-1m": ["claude-opus-4.6", "claude-sonnet-4.6"],
    "claude-opus-4.7": ["claude-opus-4.6", "claude-sonnet-4.6"],
    "claude-opus-4.6": ["claude-sonnet-4.6"],
    "claude-sonnet-4.6": ["claude-sonnet-4.5", "claude-sonnet-4"],
    "gpt-5.5": ["gpt-5.4", "gpt-5.2"],
    "gpt-5.4": ["gpt-5.2"],
};
