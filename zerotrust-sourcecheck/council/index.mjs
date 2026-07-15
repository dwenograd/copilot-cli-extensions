// council/index.mjs — barrel + resolveRoles helper.

import {
    ROLES,
    ROLE_IDS_IN_ORDER,
    MANDATORY_ROLE_IDS,
    CATEGORIES_IN_ROSTER,
    ALLOWED_MODEL_IDS,
    DEFAULT_SUB_JUDGE_MODEL,
    DEFAULT_META_JUDGE_MODEL,
} from "./roster.mjs";

export {
    ROLES,
    ROLE_IDS_IN_ORDER,
    MANDATORY_ROLE_IDS,
    CATEGORIES_IN_ROSTER,
    ALLOWED_MODEL_IDS,
    DEFAULT_SUB_JUDGE_MODEL,
    DEFAULT_META_JUDGE_MODEL,
};
export {
    renderRolePrompt,
    materializeCouncilManifest,
    normalizeCoverageSnapshot,
    selectRoleCandidatePaths,
} from "./promptTemplate.mjs";
export { validateExtraRoles } from "./extraRolesValidator.mjs";
export {
    renderConfirmValidatorPrompt,
    renderRefuteValidatorPrompt,
    renderValidationAdjudicationPrompt,
} from "./validationPromptTemplate.mjs";

/**
 * Resolve the effective roster from the defaults plus user overrides.
 *
 * @param {object} [options]
 * @param {Record<string, string>} [options.roles]        per-role-id model overrides
 * @param {Array<object>} [options.extraRoles]            already-validated extra-role objects
 * @returns {{ roles: Array<object>, errors: Array<string> }}
 */
export function resolveRoles({ roles: overrides = {}, extraRoles = [] } = {}) {
    const errors = [];
    const seenIds = new Set();
    const resolved = [];

    for (const role of ROLES) {
        if (seenIds.has(role.id)) {
            errors.push(`duplicate role id in default roster: ${role.id}`);
            continue;
        }
        seenIds.add(role.id);
        const overrideModel = overrides[role.id];
        if (overrideModel !== undefined) {
            if (!ALLOWED_MODEL_IDS.includes(overrideModel)) {
                errors.push(`roles.${role.id}: unknown model id ${JSON.stringify(overrideModel)}`);
                resolved.push({ ...role });
                continue;
            }
            resolved.push({ ...role, model: overrideModel });
        } else {
            resolved.push({ ...role });
        }
    }

    for (const extra of extraRoles) {
        if (seenIds.has(extra.id)) {
            errors.push(`extra_roles.${extra.id}: id collides with default role`);
            continue;
        }
        seenIds.add(extra.id);
        resolved.push(extra);
    }

    return { roles: resolved, errors };
}
