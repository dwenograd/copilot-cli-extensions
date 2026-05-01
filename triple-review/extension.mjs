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
                "Multi-model code review with iterative consensus loop. Launches 3 code-review agents in parallel on the same diff, clusters findings by consensus (3/3, 2/3, 1/3), uses a 4th synthesis agent to merge 3/3 fixes into a single canonical patch, auto-applies after validation, and iterates until findings stabilize. Use AFTER implementing changes to find bugs in actual code (vs. triple-duck which critiques plans/designs). Returns an instruction packet — the calling agent then executes the multi-round protocol via the built-in `task` and `edit` tools.",
            parameters: {
                type: "object",
                properties: {
                    scope: {
                        type: "string",
                        description:
                            "Optional. What to review. One of: 'staged' | 'unstaged' | 'all-uncommitted' | 'branch:<base>' (e.g. 'branch:main') | 'commit:<sha>' (e.g. 'commit:HEAD') | 'files:<comma-separated-paths>' | 'paths:<comma-separated-paths>' (no-git mode — reviewers `view` files directly with no diff baseline; required for non-git directories or when reviewing current file state without a baseline). Default: auto-detect (staged > unstaged > last commit), with disambiguation gate if both staged and unstaged overlap.",
                    },
                    models: {
                        type: "array",
                        items: { type: "string" },
                        minItems: 3,
                        maxItems: 3,
                        description:
                            "Optional. Exactly 3 model IDs for the reviewer trio. Default: claude-opus-4.7-xhigh, claude-opus-4.6-1m, gpt-5.5. (xhigh = extra-high reasoning, ~200k context; pass a 1M-context model variant here if reviewing a very large diff.)",
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
                            "Optional. When true, use the cheap reviewer trio (claude-opus-4.7, claude-opus-4.6, gpt-5.5 — non-1M-context variants) instead of the default heavy trio. ~23% per-round reviewer-cost savings; synthesis model unchanged. Reviewers have ~200k context instead of 1M — for large diffs (>500 lines) the default trio's full-context comprehension is meaningfully better. Set this when the user invokes 'triple review cheap' or asks for cheap mode. MUTUALLY EXCLUSIVE with `models` — pass one or the other, not both. Combine with `max_rounds: 1` for maximum savings.",
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
