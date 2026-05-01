// triple-plan/handler.mjs
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
import { triplePlanSchema } from "../_shared/schemas.mjs";
import { checkBudget, renderBudgetBlock } from "../_shared/budget.mjs";
import { buildInstructionPacket } from "./packet.mjs";

const TOOL = "triple-plan";

export async function runHandler(args, deps = {}) {
    const log = deps.log || (async () => {});

    // 1. Schema parse (input validation, trimming, length caps, mutual exclusion).
    const parsed = triplePlanSchema.safeParse(args);
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
    const scrubbedTask = scrub(input.task);
    const scrubbedContext = input.context ? scrub(input.context) : { text: "", redactions: [] };
    const scrubbedConstraints = input.constraints ? scrub(input.constraints) : { text: "", redactions: [] };
    const allRedactions = [
        ...scrubbedTask.redactions,
        ...scrubbedContext.redactions,
        ...scrubbedConstraints.redactions,
    ];

    // 4. Apply injection policy + USER_INPUT envelope (per-call nonce).
    const nonce = generateNonce();
    const taskPolicy = applyInjectionPolicy(scrubbedTask.text, "task", nonce);
    if (!taskPolicy.ok) {
        return { textResultForLlm: `${TOOL} error: ${taskPolicy.reason}`, resultType: "failure" };
    }
    let contextPolicy = { ok: true, wrapped: "", warnings: [] };
    if (scrubbedContext.text) {
        contextPolicy = applyInjectionPolicy(scrubbedContext.text, "context", nonce);
        if (!contextPolicy.ok) {
            return { textResultForLlm: `${TOOL} error: ${contextPolicy.reason}`, resultType: "failure" };
        }
    }
    let constraintsPolicy = { ok: true, wrapped: "", warnings: [] };
    if (scrubbedConstraints.text) {
        constraintsPolicy = applyInjectionPolicy(scrubbedConstraints.text, "constraints", nonce);
        if (!constraintsPolicy.ok) {
            return { textResultForLlm: `${TOOL} error: ${constraintsPolicy.reason}`, resultType: "failure" };
        }
    }
    const injectionWarnings = [
        ...taskPolicy.warnings,
        ...contextPolicy.warnings,
        ...constraintsPolicy.warnings,
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
        judgeOverridden: isJudgeUserOverride,
        taskWrapped: taskPolicy.wrapped,
        contextWrapped: contextPolicy.wrapped,
        constraintsWrapped: constraintsPolicy.wrapped,
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
        `${TOOL} invoked — ${input.cheap && !isUserOverride ? "CHEAP mode — " : ""}planners: ${resolved.models.join(", ")}, judge: ${effectiveJudge}`,
    );

    return { textResultForLlm: packet, resultType: "success" };
}
