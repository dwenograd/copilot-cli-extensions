// triple-duck/handler.mjs
//
// Pure handler function — orchestrates the validation/scrub/policy/resolve
// pipeline and calls the packet builder. Exported separately from
// extension.mjs so it can be unit-tested without spinning up joinSession().

import {
    DEFAULT_MODELS,
    CHEAP_MODELS,
    scrub,
    applyInjectionPolicy,
    generateNonce,
    renderInjectionPreamble,
    injectionInstructionForSubAgents,
    resolveModels,
    renderSubstitutionNote,
    formatZodError,
} from "../_shared/index.mjs";
import { tripleDuckSchema } from "../_shared/schemas.mjs";
import { checkBudget, renderBudgetBlock } from "../_shared/budget.mjs";
import { buildInstructionPacket } from "./packet.mjs";

const TOOL = "triple-duck";

export async function runHandler(args, deps = {}) {
    const log = deps.log || (async () => {});

    // 1. Schema parse (input validation, trimming, length caps, mutual exclusion).
    const parsed = tripleDuckSchema.safeParse(args);
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

    // 4. Apply injection policy + USER_INPUT envelope (per-call nonce).
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

    // 5. Resolve models (substitute deprecated defaults; honor user overrides verbatim).
    const isUserOverride = input.models !== undefined;
    const requestedTrio = input.models
        ?? (input.cheap ? CHEAP_MODELS : DEFAULT_MODELS);
    const resolved = resolveModels(requestedTrio, { isUserOverride });

    // 5b. Resolve the judge separately. The judge default depends on cheap
    // mode; user override (input.judge) takes precedence over both defaults.
    const isJudgeUserOverride = input.judge !== undefined;
    const resolvedJudge = resolveModels([input.effectiveJudge], {
        isUserOverride: isJudgeUserOverride,
    });
    const effectiveJudge = resolvedJudge.models[0];
    const allSubstitutions = [
        ...resolved.substitutions,
        ...resolvedJudge.substitutions,
    ];

    // 6. Build the protocol packet from the prepared pieces.
    const packet = buildInstructionPacket({
        trio: resolved.models,
        effectiveJudge,
        cheap: input.cheap === true && !isUserOverride,
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
        await log(`[fallback] ${sub.requested} -> ${sub.used}: ${sub.reason}`);
    }
    await log(
        `${TOOL} invoked — ${input.cheap && !isUserOverride ? "CHEAP mode — " : ""}reviewers: ${resolved.models.join(", ")}, judge: ${effectiveJudge}`,
    );

    return { textResultForLlm: packet, resultType: "success" };
}
