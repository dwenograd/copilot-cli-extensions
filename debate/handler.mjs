// debate/handler.mjs
//
// Pure handler function — orchestrates the validation/scrub/policy/resolve
// pipeline and calls the packet builder. Exported separately from
// extension.mjs so it can be unit-tested without spinning up joinSession().

import {
    scrub,
    applyInjectionPolicy,
    generateNonce,
    renderInjectionPreamble,
    injectionInstructionForSubAgents,
    resolveModels,
    renderSubstitutionNote,
    formatZodError,
} from "../_shared/index.mjs";
import { debateSchema } from "../_shared/schemas.mjs";
import { checkBudget, renderBudgetBlock } from "../_shared/budget.mjs";
import { buildInstructionPacket } from "./packet.mjs";

const TOOL = "debate";

const emptyScrub = { text: "", redactions: [] };
const emptyPolicy = { ok: true, wrapped: "", warnings: [] };

function scrubOptional(value) {
    return value ? scrub(value) : emptyScrub;
}

function applyOptionalPolicy(scrubbed, fieldName, nonce) {
    if (!scrubbed.text) {
        return emptyPolicy;
    }
    return applyInjectionPolicy(scrubbed.text, fieldName, nonce);
}

export async function runHandler(args, deps = {}) {
    const log = deps.log || (async () => {});

    // 1. Schema parse (input validation, trimming, length caps, defaults,
    // both-or-neither positions, and judge/debater independence).
    const parsedResult = debateSchema.safeParse(args);
    if (!parsedResult.success) {
        return {
            textResultForLlm: `${TOOL} error: ${formatZodError(parsedResult.error)}`,
            resultType: "failure",
        };
    }
    const input = parsedResult.data;

    // 2. Budget check — handler-side authoritative gate.
    const budgetError = checkBudget(TOOL, input);
    if (budgetError) {
        return { textResultForLlm: budgetError, resultType: "failure" };
    }

    // 3. Scrub each user-supplied free-text field BEFORE policy wrap.
    const scrubbedQuestion = scrub(input.question);
    const scrubbedPositionA = scrubOptional(input.position_a);
    const scrubbedPositionB = scrubOptional(input.position_b);
    const scrubbedContext = scrubOptional(input.context);
    const allRedactions = [
        ...scrubbedQuestion.redactions,
        ...scrubbedPositionA.redactions,
        ...scrubbedPositionB.redactions,
        ...scrubbedContext.redactions,
    ];

    // 4. Apply injection policy + USER_INPUT envelope (per-call nonce).
    const nonce = generateNonce();
    const questionPolicy = applyInjectionPolicy(scrubbedQuestion.text, "question", nonce);
    if (!questionPolicy.ok) {
        return { textResultForLlm: `${TOOL} error: ${questionPolicy.reason}`, resultType: "failure" };
    }

    const positionAPolicy = applyOptionalPolicy(scrubbedPositionA, "position_a", nonce);
    if (!positionAPolicy.ok) {
        return { textResultForLlm: `${TOOL} error: ${positionAPolicy.reason}`, resultType: "failure" };
    }

    const positionBPolicy = applyOptionalPolicy(scrubbedPositionB, "position_b", nonce);
    if (!positionBPolicy.ok) {
        return { textResultForLlm: `${TOOL} error: ${positionBPolicy.reason}`, resultType: "failure" };
    }

    const contextPolicy = applyOptionalPolicy(scrubbedContext, "context", nonce);
    if (!contextPolicy.ok) {
        return { textResultForLlm: `${TOOL} error: ${contextPolicy.reason}`, resultType: "failure" };
    }

    const injectionWarnings = [
        ...questionPolicy.warnings,
        ...positionAPolicy.warnings,
        ...positionBPolicy.warnings,
        ...contextPolicy.warnings,
    ];

    // 5. Resolve models (substitute deprecated defaults; honor user overrides verbatim).
    const resolvedDebaters = resolveModels(input.effectiveDebaters, {
        isUserOverride: input.debaters !== undefined,
    });
    const resolvedJudge = resolveModels([input.effectiveJudge], {
        isUserOverride: input.judge !== undefined,
    });
    const effectiveJudge = resolvedJudge.models[0];
    const substitutions = [
        ...resolvedDebaters.substitutions,
        ...resolvedJudge.substitutions,
    ];

    if (resolvedDebaters.models.includes(effectiveJudge)) {
        return {
            textResultForLlm: `${TOOL} error: judge must differ from both debaters to remain independent`,
            resultType: "failure",
        };
    }

    // 6. Build the protocol packet from the prepared pieces.
    const packet = buildInstructionPacket({
        effectiveDebaters: resolvedDebaters.models,
        effectiveJudge,
        cheap: input.cheap === true && input.debaters === undefined && input.judge === undefined,
        rounds: input.rounds,
        questionWrapped: questionPolicy.wrapped,
        positionAWrapped: positionAPolicy.wrapped,
        positionBWrapped: positionBPolicy.wrapped,
        contextWrapped: contextPolicy.wrapped,
        budgetBlock: renderBudgetBlock(TOOL, input),
        substitutionNote: renderSubstitutionNote(substitutions),
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
    for (const sub of substitutions) {
        await log(`[fallback] ${sub.requested} -> ${sub.used}: ${sub.reason}`);
    }
    await log(
        `${TOOL} invoked — ${input.cheap && input.debaters === undefined && input.judge === undefined ? "CHEAP mode — " : ""}${input.rounds} round(s), debaters: ${resolvedDebaters.models.join(" vs ")}, judge: ${effectiveJudge}`,
    );

    return { textResultForLlm: packet, resultType: "success" };
}
