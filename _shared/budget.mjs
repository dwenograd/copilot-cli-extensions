// _shared/budget.mjs
// Handler-side authoritative cost ceiling helpers; packets render the same
// values as advisory instructions for the orchestrating agent.

export const SYNTH_CAP_PER_ROUND = 10;

const DEFAULT_DEBATE_ROUNDS = 1;
const DEFAULT_TRIPLE_REVIEW_MAX_ROUNDS = 3;

function options(args) {
    return args && typeof args === "object" ? args : {};
}

function numericOption(args, key, defaultValue) {
    const value = options(args)[key];
    return value === undefined || value === null ? defaultValue : Number(value);
}

function hasBudgetCap(args) {
    const value = options(args).max_premium_calls;
    return value !== undefined && value !== null;
}

// Worst-case premium model call count for a given tool invocation.
// Throws TypeError if `toolName` is unknown.
export function computeWorstCaseCost(toolName, args = {}) {
    switch (toolName) {
        case "triple-duck":
            // 3 reviewers + 3 reviewer retries + 1 judge + 1 judge retry.
            return 3 + 3 + 1 + 1;
        case "triple-plan":
            // Same shape as triple-duck.
            return 3 + 3 + 1 + 1;
        case "debate": {
            const rounds = numericOption(args, "rounds", DEFAULT_DEBATE_ROUNDS);
            return 4 * rounds + 1;
        }
        case "triple-review": {
            const maxRounds = numericOption(args, "max_rounds", DEFAULT_TRIPLE_REVIEW_MAX_ROUNDS);
            // Per round: 3 reviewers + up to 3 reviewer retries (one per
            // failed reviewer) + up to SYNTH_CAP_PER_ROUND synthesis calls.
            // Synthesis is GLOBALLY capped per round (1d auto + 1e accept +
            // retries all share the same SYNTH_CAP_PER_ROUND pool — see
            // triple-review/packet.mjs synthCapLine), so total synthesis
            // calls per round ≤ SYNTH_CAP_PER_ROUND, NOT SYNTH_CAP_PER_ROUND * 2.
            return maxRounds * (6 + SYNTH_CAP_PER_ROUND);
        }
        case "duck-council": {
            // 6 role-specialized reviewers + 6 reviewer retries (one each) +
            // 1 judge + 1 judge retry = 14 worst-case. `skip_judge: true`
            // drops the +2 judge calls (14 worst-case becomes 12).
            const judgeCalls = options(args).skip_judge === true ? 0 : 2;
            return 6 + 6 + judgeCalls;
        }
        default:
            throw new TypeError(`Unknown toolName: ${toolName}`);
    }
}

// Returns null if budget is satisfied or undefined; otherwise returns an error
// string suitable for textResultForLlm.
export function checkBudget(toolName, args = {}) {
    if (!hasBudgetCap(args)) {
        return null;
    }

    const cap = options(args).max_premium_calls;
    const worstCase = computeWorstCaseCost(toolName, args);
    if (worstCase <= Number(cap)) {
        return null;
    }

    return `${toolName} error: max_premium_calls=${cap} cannot satisfy worst-case run cost (${worstCase} calls). Either lower max_rounds/rounds or raise max_premium_calls (or omit it for no cap).`;
}

// Markdown block embedded at the top of protocol packets.
export function renderBudgetBlock(toolName, args = {}) {
    const worstCase = computeWorstCaseCost(toolName, args);
    const cap = options(args).max_premium_calls;
    const effectiveCap = hasBudgetCap(args) ? Math.min(worstCase, Number(cap)) : worstCase;
    const lines = [
        `**Budget cap:** ${worstCase} premium calls (worst-case for this run)`,
    ];

    if (hasBudgetCap(args)) {
        lines.push(`**User-specified cap:** ${cap} calls`);
    }

    lines.push(
        `**Track:** initialize \`actualPremiumCalls = 0\` and increment by 1 for every sub-agent or synthesis call you launch (INCLUDING retries). Before EVERY launch, check \`actualPremiumCalls + 1 <= ${effectiveCap}\`. If the next call would exceed, STOP and report what was completed.`,
        "**Note:** the handler enforces the cap before this packet was built (overspend is structurally prevented if you respect this counter).",
    );

    return lines.join("\n");
}
