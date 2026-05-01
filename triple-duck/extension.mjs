// Extension: triple-duck
// Multi-model rubber-duck critique: launches 3 rubber-duck agents in parallel
// and merges findings by consensus.
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
                "Launch three rubber-duck critique agents in parallel using different models, then have a dedicated judge agent (highest-quality model) cluster findings by consensus (3/3, 2/3, 1/3 agreement) and produce the final unified critique. Use BEFORE implementing non-trivial changes to get high-confidence design feedback. Returns an instruction packet — the calling agent then executes the pattern using the built-in `task` tool.",
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
                            "Optional. Exactly 3 model IDs to override the default reviewer trio. Defaults to claude-opus-4.7-xhigh, claude-opus-4.6-1m, gpt-5.5. (xhigh = extra-high reasoning, ~200k context; pass a 1M-context model variant here if you need it for very large inputs.)",
                    },
                    judge: {
                        type: "string",
                        description:
                            "Optional. Model ID for the judge that synthesizes the 3 reviewer critiques into the final unified output. Defaults to `claude-opus-4.7-xhigh` (highest-quality reasoning available, ~200k context — sufficient for typical critique sizes). Pass a 1M-context model variant if your reviewer outputs are unusually large. Compatible with `cheap: true` (cheap reviewer trio + premium judge is a sensible config).",
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
                            "Optional. When true, use the cheap reviewer trio (claude-opus-4.7, claude-opus-4.6, gpt-5.5 — non-1M-context variants) instead of the default heavy trio. ~23% reviewer-cost savings, but reviewers have ~200k context instead of 1M. Judge defaults to `claude-opus-4.7` in cheap mode unless overridden via `judge`. MUTUALLY EXCLUSIVE with `models` (but compatible with explicit `judge`).",
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
