// duck-council/handler.mjs
//
// Pure handler function — orchestrates the validation/scrub/policy/resolve
// pipeline and calls the packet builder. Exported separately from
// extension.mjs so it can be unit-tested without spinning up joinSession().
//
// duck-council differs from triple-duck in that it has 6 ROLE-SPECIALIZED
// reviewers + 1 judge synthesis pass. Each role gets its own model (tiered
// for cost/quality balance) and its own role-specific prompt that narrows
// what to look for and explicitly says which concerns to ignore.

import {
    COUNCIL_ROLE_NAMES,
    scrub,
    applyInjectionPolicy,
    generateNonce,
    renderInjectionPreamble,
    injectionInstructionForSubAgents,
    resolveModels,
    renderSubstitutionNote,
    formatZodError,
} from "../_shared/index.mjs";
import { duckCouncilSchema } from "../_shared/schemas.mjs";
import { checkBudget, renderBudgetBlock } from "../_shared/budget.mjs";
import { buildInstructionPacket } from "./packet.mjs";

const TOOL = "duck-council";

export async function runHandler(args, deps = {}) {
    const log = deps.log || (async () => {});

    // 1. Schema parse (input validation, trimming, length caps, mutual exclusion).
    const parsed = duckCouncilSchema.safeParse(args);
    if (!parsed.success) {
        return {
            textResultForLlm: `${TOOL} error: ${formatZodError(parsed.error)}`,
            resultType: "failure",
        };
    }
    const input = parsed.data;

    // 2. Budget check — handler-side authoritative gate.
    const budgetError = checkBudget(TOOL, input);
    if (budgetError) {
        return { textResultForLlm: budgetError, resultType: "failure" };
    }

    // 3. Scrub each user-supplied free-text field BEFORE policy wrap.
    const scrubbedTopic = scrub(input.topic);
    const scrubbedContext = input.context ? scrub(input.context) : { text: "", redactions: [] };
    const scrubbedFocus = input.focus ? scrub(input.focus) : { text: "", redactions: [] };
    const allRedactions = [
        ...scrubbedTopic.redactions,
        ...scrubbedContext.redactions,
        ...scrubbedFocus.redactions,
    ];

    // 4. Apply injection policy + USER_INPUT envelope (per-call nonce, shared
    //    across all 3 free-text fields).
    const nonce = generateNonce();
    const topicPolicy = applyInjectionPolicy(scrubbedTopic.text, "topic", nonce);
    if (!topicPolicy.ok) {
        return { textResultForLlm: `${TOOL} error: ${topicPolicy.reason}`, resultType: "failure" };
    }
    let contextPolicy = { ok: true, wrapped: "", warnings: [] };
    if (scrubbedContext.text) {
        contextPolicy = applyInjectionPolicy(scrubbedContext.text, "context", nonce);
        if (!contextPolicy.ok) {
            return { textResultForLlm: `${TOOL} error: ${contextPolicy.reason}`, resultType: "failure" };
        }
    }
    let focusPolicy = { ok: true, wrapped: "", warnings: [] };
    if (scrubbedFocus.text) {
        focusPolicy = applyInjectionPolicy(scrubbedFocus.text, "focus", nonce);
        if (!focusPolicy.ok) {
            return { textResultForLlm: `${TOOL} error: ${focusPolicy.reason}`, resultType: "failure" };
        }
    }
    const injectionWarnings = [
        ...topicPolicy.warnings,
        ...contextPolicy.warnings,
        ...focusPolicy.warnings,
    ];

    // 5. Resolve models per role. Each role's model goes through resolveModels
    //    independently. User-supplied roles override defaults; we pass
    //    isUserOverride per role so the resolver doesn't silently substitute
    //    a model the user explicitly asked for.
    const isAnyRolesOverride = input.roles !== undefined;
    const resolvedRoles = {};
    const allSubstitutions = [];
    for (const role of COUNCIL_ROLE_NAMES) {
        const requested = input.effectiveRoles[role];
        const isThisRoleUserOverride = isAnyRolesOverride && input.roles[role] !== undefined;
        const r = resolveModels([requested], { isUserOverride: isThisRoleUserOverride });
        resolvedRoles[role] = r.models[0];
        for (const sub of r.substitutions) {
            allSubstitutions.push({ ...sub, role });
        }
    }

    // 5b. Resolve the judge.
    const isJudgeUserOverride = input.judge !== undefined;
    const resolvedJudge = resolveModels([input.effectiveJudge], {
        isUserOverride: isJudgeUserOverride,
    });
    const effectiveJudge = resolvedJudge.models[0];
    for (const sub of resolvedJudge.substitutions) {
        allSubstitutions.push({ ...sub, role: "judge" });
    }

    // 6. Build the protocol packet from the prepared pieces.
    const packet = buildInstructionPacket({
        roleAssignment: resolvedRoles,
        effectiveJudge,
        skipJudge: input.skip_judge === true,
        cheap: input.cheap === true && !isAnyRolesOverride,
        topicWrapped: topicPolicy.wrapped,
        contextWrapped: contextPolicy.wrapped,
        focusWrapped: focusPolicy.wrapped,
        budgetBlock: renderBudgetBlock(TOOL, input),
        substitutionNote: renderSubstitutionNote(allSubstitutions),
        injectionPreamble: renderInjectionPreamble(),
        scrubNote: allRedactions.length > 0
            ? `> **Note:** scrubbed ${allRedactions.reduce((s, r) => s + r.count, 0)} high-confidence credential(s) from input before sending to sub-agents.`
            : "",
        injectionWarnings,
        subAgentInstruction: injectionInstructionForSubAgents(),
    });

    // 7. Operational logging — every substitution gets a [fallback] entry.
    if (allRedactions.length > 0) {
        await log(`[scrub] ${JSON.stringify(allRedactions)}`);
    }
    for (const sub of allSubstitutions) {
        await log(`[fallback] ${sub.role}: ${sub.requested} -> ${sub.used}: ${sub.reason}`);
    }
    const rolesSummary = COUNCIL_ROLE_NAMES.map((r) => `${r}=${resolvedRoles[r]}`).join(", ");
    await log(
        `${TOOL} invoked — ${input.cheap && !isAnyRolesOverride ? "CHEAP mode — " : ""}roles: ${rolesSummary}, judge: ${effectiveJudge}, skip_judge=${input.skip_judge === true}`,
    );

    return { textResultForLlm: packet, resultType: "success" };
}
