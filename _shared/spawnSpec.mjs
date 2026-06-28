// _shared/spawnSpec.mjs
//
// Translates the capability-alias model strings used in the model presets into
// the concrete arguments the CLI `task` tool accepts at spawn time.
//
// WHY: the CLI no longer encodes reasoning effort or context-window size in the
// model ID. Those are SEPARATE task() parameters now:
//   - reasoning_effort: "low" | "medium" | "high" | "xhigh" | "max"
//   - context_tier:     "default" | "long_context"
// Suffix-encoded IDs (e.g. "claude-opus-4.7-xhigh", "claude-opus-4.7-1m-internal")
// are REJECTED by the spawner as unknown models (verified empirically). We keep
// human-readable capability aliases in the presets — so logs, notes, and the
// fallback map stay readable — and translate them HERE, at the single boundary
// where a sub-agent is actually spawned (the packets + zerotrust spawn code).
//
// Long context is enabled GLOBALLY (LONG_CONTEXT_TIER) because every available
// model accepts `context_tier:"long_context"` at no cost — verified by probing
// every model family. So the legacy "-1m"/"-1m-internal" aliases only need to
// map to their BASE model; the 1M window comes from the global tier applied to
// every spawn.

// Applied to every spawned sub-agent. There is no cost difference and every
// model supports it, so there is no reason to leave any agent on the small
// window.
export const LONG_CONTEXT_TIER = "long_context";

// alias -> { model, effort? }. Only EFFORT needs per-alias handling now that
// context is global.
//
// NOTE: "mai-code-1-flash-internal" is a REAL base model ID (its "-internal"
// suffix is part of the actual name), NOT an alias. Exact-match keying here
// means it (and every other real base ID) passes through untouched.
export const SPAWN_ALIASES = Object.freeze({
    "claude-opus-4.7-1m-internal": { model: "claude-opus-4.7" },
    "claude-opus-4.6-1m": { model: "claude-opus-4.6" },
    "claude-opus-4.7-xhigh": { model: "claude-opus-4.7", effort: "xhigh" },
    "claude-opus-4.7-high": { model: "claude-opus-4.7", effort: "high" },
});

// Models that support the `xhigh` reasoning tier. Reasoning-heavy DEFAULT
// (non-cheap) spawns are elevated to xhigh on these — the "extra reasoning"
// these orchestrators benefit from. Passing reasoning_effort to a model that
// doesn't list xhigh is silently ignored by the spawner (verified), so this
// map's only job is to elevate where it actually changes behavior. Cheap-mode
// spawns are deliberately NOT elevated (cheap = economy). `max` exists above
// xhigh on the Opus tiers; we standardize on xhigh to match the historical
// `-xhigh` intent (override a slot with a `max`-bearing config if you want more).
export const ELEVATED_EFFORT = Object.freeze({
    "claude-opus-4.8": "xhigh",
    "claude-opus-4.7": "xhigh",
    "gpt-5.5": "xhigh",
    "gpt-5.4": "xhigh",
    "gpt-5.3-codex": "xhigh",
    "gpt-5.4-mini": "xhigh",
});

/**
 * Resolve a preset/alias model string to concrete spawn parameters.
 *
 * @param {string} modelId An alias or a real base model ID.
 * @param {object} [options]
 * @param {boolean} [options.elevated=false] When true, reasoning-capable models
 *   get their elevated (xhigh) reasoning tier — unless the alias already pins an
 *   effort, which always wins. Use for non-cheap / full-quality spawns.
 * @returns {{ model: string, effort: string|null, context: string }}
 */
export function resolveSpawnSpec(modelId, { elevated = false } = {}) {
    const id = String(modelId).trim();
    const alias = SPAWN_ALIASES[id];
    const model = alias ? alias.model : id;
    // Alias-pinned effort (e.g. a `-xhigh` override) always wins; otherwise
    // elevate reasoning-capable models for non-cheap spawns.
    let effort = alias && alias.effort ? alias.effort : null;
    if (!effort && elevated && ELEVATED_EFFORT[model]) {
        effort = ELEVATED_EFFORT[model];
    }
    return { model, effort, context: LONG_CONTEXT_TIER };
}

/**
 * Clean, user-facing name for a preset/alias model string.
 *
 * The presets carry CAPABILITY ALIASES that are meaningful in source and the
 * fallback map but read as jargon — and are sometimes misleading — when surfaced
 * to the user in an "invoked — reviewers: …" banner. This normalizes ONLY the
 * context-window aliases ("-1m", "-1m-internal"): that suffix encodes a context
 * window now applied GLOBALLY to every spawn, so it conveys nothing the user can
 * act on and never spawns under that literal ID. It collapses to the real base
 * model that actually spawns (`claude-opus-4.7-1m-internal` -> `claude-opus-4.7`).
 *
 * Effort aliases ("-xhigh", "-high") are LEFT INTACT — the reasoning tier is a
 * real, user-meaningful capability worth showing in the banner. Real base IDs
 * (including genuine `-internal` model names like "mai-code-1-flash-internal")
 * also pass through untouched.
 *
 * @param {string} modelId An alias or a real base model ID.
 * @returns {string} A clean, user-facing model name.
 */
export function displayModel(modelId) {
    const id = String(modelId).trim();
    const alias = SPAWN_ALIASES[id];
    // Strip only context-window aliases (no pinned effort); keep effort aliases
    // and real base IDs verbatim.
    if (alias && !alias.effort) {
        return alias.model;
    }
    return id;
}

/**
 * displayModel for a list. Convenience for banner lines that join a trio/roster.
 *
 * @param {string[]} modelIds
 * @returns {string[]}
 */
export function displayModels(modelIds) {
    return modelIds.map(displayModel);
}

/**
 * Render the model-related arguments for a `task()` call from a preset/alias
 * model string: always `model` and `context_tier`, plus `reasoning_effort`
 * when the alias pins one or the slot is elevated.
 *
 * @param {string} modelId
 * @param {object} [options]
 * @param {boolean} [options.elevated=false] See resolveSpawnSpec.
 * @param {boolean} [options.colon=false] Emit object-literal style
 *   (`model:"x"`) instead of kwargs style (`model="x"`). For packets that
 *   write `task({ ... })`.
 * @returns {string} e.g. `model="claude-opus-4.8", reasoning_effort="xhigh", context_tier="long_context"`
 */
export function renderSpawnArgs(modelId, { elevated = false, colon = false } = {}) {
    const spec = resolveSpawnSpec(modelId, { elevated });
    const sep = colon ? ":" : "=";
    let out = `model${sep}${JSON.stringify(spec.model)}`;
    if (spec.effort) {
        out += `, reasoning_effort${sep}${JSON.stringify(spec.effort)}`;
    }
    out += `, context_tier${sep}${JSON.stringify(spec.context)}`;
    return out;
}
