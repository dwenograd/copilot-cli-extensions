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
                "Launch three planning agents in parallel using different models, then have a configured judge merge their plans into a canonical plan with consensus, alternatives, and contested decisions surfaced. Use BEFORE starting non-trivial implementation work. Returns an instruction packet — the calling agent executes the pattern using the built-in `task` tool.",
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
                            "Optional. Exactly 3 model preset IDs. Defaults to claude-opus-4.8, gpt-5.6-sol, and capability alias claude-opus-4.7-1m-internal (spawned as base claude-opus-4.7). Every planner gets context_tier:\"long_context\"; full-quality mode adds elevated effort only for supported base models.",
                    },
                    judge: {
                        type: "string",
                        description:
                            "Optional. Judge model preset. Defaults to gpt-5.6-sol. Every judge gets context_tier:\"long_context\"; full-quality mode requests elevated effort when supported. Compatible with cheap:true, but a plain base-model override still inherits cheap effort suppression.",
                    },
                    cheap: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. Use the cheap planner trio (claude-opus-4.7, claude-opus-4.6, gpt-5.5). Long context remains enabled, but automatic elevated reasoning is suppressed; an explicit effort alias still pins its effort. Judge defaults to claude-opus-4.7 unless overridden. Mutually exclusive with models, compatible with judge.",
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
