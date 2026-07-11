// Extension: triple-duck
// Multi-model rubber-duck critique: returns a packet for 3 parallel reviewers
// plus a separate judge synthesis.
//
// This file is a thin shell — handler.mjs holds the orchestration logic
// (validation, scrub, injection policy, budget check, model resolution).
// The split exists so handler.mjs can be unit-tested without joinSession().

import { joinSession } from "@github/copilot-sdk/extension";
import { runHandler } from "./handler.mjs";

const session = await joinSession({
    tools: [
        {
            name: "triple-duck",
            description:
                "Launch three rubber-duck critique agents in parallel using different models, then have a configured judge cluster findings by consensus (3/3, 2/3, 1/3 agreement) and produce the final unified critique. Use BEFORE implementing non-trivial changes to get multi-model design feedback. Returns an instruction packet — the calling agent executes the pattern using the built-in `task` tool.",
            parameters: {
                type: "object",
                properties: {
                    topic: {
                        type: "string",
                        description:
                            "What to critique. A plan, design, approach, or implementation summary. Be specific — vague topics produce vague critiques.",
                    },
                    context: {
                        type: "string",
                        description:
                            "Optional. Additional context the reviewers need: file paths to consider, constraints, prior decisions, what's already been tried, etc.",
                    },
                    models: {
                        type: "array",
                        items: { type: "string" },
                        minItems: 3,
                        maxItems: 3,
                        description:
                            "Optional. Exactly 3 model preset IDs. Defaults to claude-opus-4.8, gpt-5.6-sol, and the capability alias claude-opus-4.7-1m-internal (spawned as base claude-opus-4.7). Every reviewer gets context_tier:\"long_context\"; full-quality mode adds elevated effort only for supported base models.",
                    },
                    judge: {
                        type: "string",
                        description:
                            "Optional. Judge model preset. Defaults to gpt-5.6-sol. Every judge gets context_tier:\"long_context\"; full-quality mode requests elevated effort when supported. Compatible with cheap:true, but a plain base-model override still inherits cheap effort suppression.",
                    },
                    focus: {
                        type: "string",
                        description:
                            "Optional. Comma-separated focus areas (e.g., 'security, error handling, edge cases'). If omitted, reviewers do a general critique.",
                    },
                    cheap: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. Use the cheap reviewer trio (claude-opus-4.7, claude-opus-4.6, gpt-5.5). Long context remains enabled, but automatic elevated reasoning is suppressed; an explicit effort alias still pins its effort. Judge defaults to claude-opus-4.7 unless overridden. Mutually exclusive with models, compatible with judge.",
                    },
                    max_premium_calls: {
                        type: "integer",
                        minimum: 1,
                        description:
                            "Optional. Hard cap on premium model calls for this invocation (counted against the worst-case formula: 3 reviewers + 3 retries + 1 judge + 1 judge retry = 8). The handler rejects the request before building the packet if the cap is too low to satisfy the worst case. Omit for no cap.",
                    },
                },
                required: ["topic"],
            },
            handler: (args) => runHandler(args, { log: (msg) => session.log(msg) }),
        },
    ],
});
