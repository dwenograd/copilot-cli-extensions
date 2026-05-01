// _shared/index.mjs — barrel export. Each extension imports from this single
// file; sub-modules are split for testability and focus.

export {
    DEFAULT_MODELS,
    CHEAP_MODELS,
    DEFAULT_DEBATERS,
    CHEAP_DEBATERS,
    DEFAULT_JUDGE,
    CHEAP_JUDGE,
    DEFAULT_TRIPLE_DUCK_JUDGE,
    CHEAP_TRIPLE_DUCK_JUDGE,
    DEFAULT_TRIPLE_PLAN_JUDGE,
    CHEAP_TRIPLE_PLAN_JUDGE,
    SYNTHESIS_MODEL,
    VALID_SEVERITIES,
    KNOWN_DEPRECATED_MODELS,
    MODEL_FALLBACK_MAP,
    COUNCIL_ROLE_NAMES,
    DEFAULT_COUNCIL_ROLES,
    CHEAP_COUNCIL_ROLES,
    DEFAULT_COUNCIL_JUDGE,
    CHEAP_COUNCIL_JUDGE,
} from "./models.mjs";

// safeFence removed in pass 3 — verified dead code (no packet.mjs uses it; the
// new architecture wraps user content via applyInjectionPolicy's USER_INPUT
// envelope, not markdown fences).
export {
    applyInjectionPolicy,
    generateNonce,
    injectionInstructionForSubAgents,
    renderInjectionPreamble,
} from "./policy.mjs";
export { scrub } from "./scrub.mjs";
export { resolveModels, renderSubstitutionNote } from "./resolveModels.mjs";
export { formatZodError } from "./formatZodError.mjs";
export {
    SYNTH_CAP_PER_ROUND,
    computeWorstCaseCost,
    checkBudget,
    renderBudgetBlock,
} from "./budget.mjs";
// schemas.mjs is imported directly (named exports added in step 5).
