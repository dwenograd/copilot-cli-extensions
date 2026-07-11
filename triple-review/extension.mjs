// Extension: triple-review
// Multi-model code review with iterative consensus loop.
//
// This file is a thin shell — handler.mjs holds the orchestration logic
// (validation, scrub, injection policy, budget check, scope/model resolution).
// The split exists so handler.mjs can be unit-tested without joinSession().

import { joinSession } from "@github/copilot-sdk/extension";
import { runHandler } from "./handler.mjs";

const session = await joinSession({
    tools: [
        {
            name: "triple-review",
            description:
                "Multi-model code review with an iterative consensus loop. Launches 3 code-review agents against a materialized git diff, or current files in `paths:` mode; clusters findings, synthesizes applicable fixes, verifies patch preconditions, applies, then runs project validation before iterating. Returns an instruction packet for the calling agent.",
            parameters: {
                type: "object",
                properties: {
                    scope: {
                        type: "string",
                        description:
                            "Optional. One of staged, unstaged, all-uncommitted, branch:<base>, commit:<sha>, files:<comma-paths>, or paths:<comma-paths>. paths: is current-state/no-baseline mode and does not require git. Default auto-detect checks staged, unstaged, and untracked sets; asks if multiple are non-empty, refuses an untracked-only silent omission, and falls back to the last commit only when the tree is otherwise clean.",
                    },
                    models: {
                        type: "array",
                        items: { type: "string" },
                        minItems: 3,
                        maxItems: 3,
                        description:
                            "Optional. Exactly 3 model preset IDs. Defaults to claude-opus-4.8, gpt-5.6-sol, and capability alias claude-opus-4.7-1m-internal (spawned as base claude-opus-4.7). Every reviewer gets context_tier:\"long_context\"; full-quality mode adds elevated effort only for supported base models.",
                    },
                    focus: {
                        type: "string",
                        description:
                            "Optional. Comma-separated focus areas passed to every reviewer (e.g., 'security, error handling, race conditions'). If omitted, reviewers do a general critique.",
                    },
                    max_rounds: {
                        type: "integer",
                        minimum: 1,
                        maximum: 10,
                        description:
                            "Optional. Maximum review rounds before stopping (default 3). Each round = 3 reviewer calls + capped synthesis calls.",
                    },
                    severity_threshold: {
                        type: "string",
                        enum: ["critical", "high", "medium", "low", "nit"],
                        description:
                            "Optional. Stop iterating when no open findings have severity >= this threshold (and no new findings are introduced). Default: 'high'.",
                    },
                    cheap: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. Use the cheap reviewer trio (claude-opus-4.7, claude-opus-4.6, gpt-5.5). The synthesis base model remains gpt-5.6-sol. Long context remains enabled, but automatic elevated reasoning is suppressed for reviewers and synthesis. Mutually exclusive with models.",
                    },
                    max_premium_calls: {
                        type: "integer",
                        minimum: 1,
                        description:
                            "Optional. Hard cap on premium model calls for this invocation. Worst-case formula is `max_rounds × (6 + SYNTH_CAP_PER_ROUND) = max_rounds × 16` (default `max_rounds=3` → cap of 48), counting 3 reviewers + up to 3 reviewer retries + up to 10 synthesis calls per round (the synthesis cap is GLOBAL per round and includes retries). Typical runs use far less. The handler rejects the request before building the packet if `max_premium_calls` is below this worst case. Omit for no cap.",
                    },
                },
                required: [],
            },
            handler: (args) => runHandler(args, { log: (msg) => session.log(msg) }),
        },
    ],
});
