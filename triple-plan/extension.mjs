// Extension: triple-plan
// Multi-model planning: launches 3 planning agents in parallel and merges
// their plans into a single canonical plan, with disagreements surfaced.
//
// This file is a thin shell — handler.mjs holds the orchestration logic
// (validation, scrub, injection policy, budget check, model resolution).
// The split exists so handler.mjs can be unit-tested without joinSession().

import { joinSession } from "@github/copilot-sdk/extension";
import { runHandler } from "./handler.mjs";

const session = await joinSession({
    tools: [
        {
            name: "triple-plan",
            description:
                "Launch three planning agents in parallel using different models, then have a dedicated judge agent (highest-quality model) merge their plans into a single canonical plan with consensus, alternatives, and contested decisions surfaced. Use BEFORE starting non-trivial implementation work to get a high-confidence plan that's been pressure-tested across models. Returns an instruction packet — the calling agent then executes the pattern using the built-in `task` tool.",
            parameters: {
                type: "object",
                properties: {
                    task: {
                        type: "string",
                        description:
                            "What needs to be planned. Be specific about scope and goal — vague tasks produce vague plans. Include the user-facing goal AND any technical hints you already have.",
                    },
                    context: {
                        type: "string",
                        description:
                            "Optional. Additional context the planners need: file paths to consider, prior decisions, what's already been tried, environment quirks, etc.",
                    },
                    constraints: {
                        type: "string",
                        description:
                            "Optional. Hard constraints every plan MUST respect (e.g., 'must not break existing API X', 'must use library Y', 'must be backwards compatible with Z').",
                    },
                    models: {
                        type: "array",
                        items: { type: "string" },
                        minItems: 3,
                        maxItems: 3,
                        description:
                            "Optional. Exactly 3 model IDs to override the default planner trio. Defaults to claude-opus-4.7-xhigh, claude-opus-4.6-1m, gpt-5.5. (xhigh = extra-high reasoning, ~200k context; pass a 1M-context model variant here if you need it.)",
                    },
                    judge: {
                        type: "string",
                        description:
                            "Optional. Model ID for the judge that merges the 3 planner outputs into one canonical plan. Defaults to `claude-opus-4.6-1m` (1M context — three full plans easily exceed the 200k window of `-xhigh`). Pass `claude-opus-4.7-xhigh` for deeper reasoning when your plans are small enough to fit. Compatible with `cheap: true` (cheap planner trio + premium judge is a sensible config).",
                    },
                    cheap: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. When true, use the cheap planner trio (claude-opus-4.7, claude-opus-4.6, gpt-5.5 — non-1M-context variants). ~23% planner-cost savings, but planners have ~200k context instead of 1M. Judge defaults to `claude-opus-4.7` in cheap mode unless overridden via `judge`. Set this when the user invokes 'triple plan cheap <task>' or asks for cheap mode. MUTUALLY EXCLUSIVE with `models` (but compatible with explicit `judge`).",
                    },
                    max_premium_calls: {
                        type: "integer",
                        minimum: 1,
                        description:
                            "Optional. Hard cap on premium model calls for this invocation (counted against the worst-case formula: 3 planners + 3 retries + 1 judge + 1 judge retry = 8). The handler rejects the request before building the packet if the cap is too low to satisfy the worst case. Omit for no cap.",
                    },
                },
                required: ["task"],
            },
            handler: (args) => runHandler(args, { log: (msg) => session.log(msg) }),
        },
    ],
});
