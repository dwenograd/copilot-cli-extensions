import { KNOWN_DEPRECATED_MODELS, MODEL_FALLBACK_MAP } from "./models.mjs";

/**
 * Resolve model IDs, applying static fallback substitutions for deprecated defaults.
 *
 * @param {string[]} requested Model IDs to resolve. IDs are trimmed defensively.
 * @param {object} [options]
 * @param {boolean} [options.isUserOverride=false] When true, return trimmed inputs unchanged.
 * @param {Set<string>} [options.deprecated] Optional deprecated-model set for tests/injection.
 * @param {Record<string, string[]>} [options.fallbackMap] Optional fallback map for tests/injection.
 * @returns {{ models: string[], substitutions: Array<{ requested: string, used: string, reason: string }> }}
 */
export function resolveModels(requested, options = {}) {
    const models = requested.map((model) => model.trim());

    if (options.isUserOverride === true) {
        return { models, substitutions: [] };
    }

    const deprecated = options.deprecated || KNOWN_DEPRECATED_MODELS;
    const fallbackMap = options.fallbackMap || MODEL_FALLBACK_MAP;
    const substitutions = [];

    const resolved = models.map((model) => {
        if (!deprecated.has(model)) {
            return model;
        }

        const fallback = (fallbackMap[model] || []).find((candidate) => !deprecated.has(candidate));

        if (!fallback) {
            substitutions.push({
                requested: model,
                used: model,
                reason: "no fallback available — proceeding with deprecated model",
            });
            return model;
        }

        substitutions.push({
            requested: model,
            used: fallback,
            reason: `${model} is in KNOWN_DEPRECATED_MODELS; substituted with ${fallback}`,
        });
        return fallback;
    });

    return { models: resolved, substitutions };
}

/**
 * Render a one-line packet note for static model substitutions.
 *
 * @param {Array<{ requested: string, used: string, reason: string }>} substitutions
 * @returns {string}
 */
export function renderSubstitutionNote(substitutions) {
    if (substitutions.length === 0) {
        return "";
    }

    const rendered = substitutions
        .map(({ requested, used, reason, role }) => {
            const prefix = role ? `${role}: ` : "";
            return `${prefix}${requested} → ${used} (${reason})`;
        })
        .join(", ");

    return `> **Note:** model substitution(s) applied — ${rendered}`;
}
