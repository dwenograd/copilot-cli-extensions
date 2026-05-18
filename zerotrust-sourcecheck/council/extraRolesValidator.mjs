// council/extraRolesValidator.mjs
//
// Validates user-supplied `extra_roles` parameter from the tool call.
// Each entry is free-text from the caller, so it must be:
//   - schema-validated (id regex, model allowlist, length cap)
//   - control-character scrubbed
//   - wrapped in USER_INPUT envelopes so downstream auditor models
//     treat the free-text content as untrusted data, not instructions
//
// Returns the canonical role-object shape on success, or a clear error
// message on the first validation failure.

import { ALLOWED_MODEL_IDS } from "./roster.mjs";

const ID_REGEX = /^[a-z][a-z0-9-]{2,63}$/;
const MAX_TEXT_LEN = 2048;
const CONTROL_CHARS_RE = /[\x00-\x08\x0B-\x1F\x7F]/;

function wrapAsUntrusted(text, fieldName, nonce) {
    return `<<<${nonce}>>>USER_INPUT_BEGIN field="${fieldName}"<<<${nonce}>>>\n${text}\n<<<${nonce}>>>USER_INPUT_END field="${fieldName}"<<<${nonce}>>>`;
}

/**
 * @param {unknown} input  raw extra_roles parameter value
 * @param {object} ctx     { nonce: string, defaultRoleIds: Set<string> }
 * @returns {{ ok: true, validated: Array<object> } | { ok: false, error: string }}
 */
export function validateExtraRoles(input, { nonce, defaultRoleIds } = {}) {
    if (input === undefined || input === null) return { ok: true, validated: [] };
    if (!Array.isArray(input)) {
        return { ok: false, error: "extra_roles must be an array (or omitted)" };
    }
    if (!nonce || typeof nonce !== "string") {
        throw new Error("validateExtraRoles requires nonce");
    }
    if (!(defaultRoleIds instanceof Set)) {
        throw new Error("validateExtraRoles requires defaultRoleIds Set");
    }

    const seenIds = new Set();
    const validated = [];

    for (let i = 0; i < input.length; i++) {
        const entry = input[i];
        const where = `extra_roles[${i}]`;
        if (!entry || typeof entry !== "object") {
            return { ok: false, error: `${where} must be an object` };
        }
        const { id, model, description, angle } = entry;

        if (typeof id !== "string" || !ID_REGEX.test(id)) {
            return { ok: false, error: `${where}.id must match ${ID_REGEX} — got ${JSON.stringify(id)}` };
        }
        if (defaultRoleIds.has(id)) {
            return { ok: false, error: `${where}.id ${JSON.stringify(id)} collides with a default role; pick a different id` };
        }
        if (seenIds.has(id)) {
            return { ok: false, error: `${where}.id ${JSON.stringify(id)} is duplicated within extra_roles` };
        }
        seenIds.add(id);

        if (typeof model !== "string" || !ALLOWED_MODEL_IDS.includes(model)) {
            return { ok: false, error: `${where}.model must be a known model id (one of: ${ALLOWED_MODEL_IDS.join(", ")}) — got ${JSON.stringify(model)}` };
        }

        for (const [field, val] of [["description", description], ["angle", angle]]) {
            if (typeof val !== "string") {
                return { ok: false, error: `${where}.${field} must be a string — got ${typeof val}` };
            }
            if (val.length > MAX_TEXT_LEN) {
                return { ok: false, error: `${where}.${field} exceeds ${MAX_TEXT_LEN} characters` };
            }
            if (CONTROL_CHARS_RE.test(val)) {
                return { ok: false, error: `${where}.${field} contains control characters` };
            }
        }

        // Wrap the free-text in USER_INPUT envelopes — downstream sub-agents
        // see this as untrusted data, not as instructions.
        const safeAngle = wrapAsUntrusted(angle, `extra_roles[${i}].angle`, nonce);
        const safeDescription = wrapAsUntrusted(description, `extra_roles[${i}].description`, nonce);

        validated.push({
            id,
            category: "G",          // ad-hoc roles slot into adversarial category
            model,
            tier: "source-inspection",
            mandatory: false,
            angle: `${safeAngle}\n\nThe user describes this role as: ${safeDescription}`,
            ignore_clauses: ["scope of any default role — defer to that role unless the user's description specifically asks you to overlap"],
        });
    }

    return { ok: true, validated };
}

export const __internals = {
    ID_REGEX,
    MAX_TEXT_LEN,
    CONTROL_CHARS_RE,
    wrapAsUntrusted,
};
