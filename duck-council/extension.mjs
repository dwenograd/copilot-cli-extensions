// Extension: duck-council
//
// 6 role-specialized rubber-duck reviewers (security / stability / performance
// / maintainer / skeptic / user) + 1 judge synthesis pass. Sibling to
// triple-duck — use this when you want different ANGLES of critique rather
// than consensus across the same angle.
//
// Architecture mirrors the other extensions: thin SDK shell here, pure
// pipeline in handler.mjs, pure markdown composer in packet.mjs.

import { joinSession } from "@github/copilot-sdk/extension";
import { runHandler } from "./handler.mjs";

const session = await joinSession({
    tools: [
        {
            name: "duck-council",
            description:
                "Critique a topic with 6 role-specialized rubber-duck reviewers (security / stability / performance / maintainer / skeptic / user) plus an optional judge synthesis pass. Use instead of triple-duck when you want different angles rather than same-lens consensus. With the judge enabled, the output includes contradiction adjudication, ranked priorities, a premise challenge, an executive summary, and raw-role appendix. Returns an instruction packet — the calling agent executes it with the built-in `task` tool.",
            parameters: {
                type: "object",
                properties: {
                    topic: {
                        type: "string",
                        description:
                            "What to critique. Be specific — vague topics produce vague critiques.",
                    },
                    context: {
                        type: "string",
                        description:
                            "Optional. Additional context for all 6 reviewers: file paths, prior decisions, constraints, what's been tried.",
                    },
                    focus: {
                        type: "string",
                        description:
                            "Optional. Cross-cutting focus areas to emphasize across all roles (e.g., 'production readiness', 'we're shipping this Friday'). Each role still applies its own lens.",
                    },
                    roles: {
                        type: "object",
                        description:
                            "Optional. Per-role model overrides — partial object, not all 6 required. E.g. `{ security: \"claude-opus-4.8\", performance: \"gpt-5.6-sol\" }`. Roles you don't specify use the tiered defaults. MUTUALLY EXCLUSIVE with `cheap` (an empty `{}` is treated as no override).",
                        additionalProperties: false,
                        properties: {
                            security: { type: "string" },
                            stability: { type: "string" },
                            performance: { type: "string" },
                            maintainer: { type: "string" },
                            skeptic: { type: "string" },
                            user: { type: "string" },
                        },
                    },
                    judge: {
                        type: "string",
                        description:
                            "Optional. Override the judge model. Default is gpt-5.6-sol (cheap mode: claude-opus-4.7). Every judge gets context_tier:\"long_context\"; full-quality mode requests elevated effort when supported.",
                    },
                    skip_judge: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. Skip judge synthesis and present raw role outputs. Removes one normal judge call and its one-call retry allowance: successful runs save one actual call; worst-case reservation drops from 14 to 12.",
                    },
                    cheap: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. Use the cheap-tier role presets. Every role still gets context_tier:\"long_context\", but automatic elevated reasoning is suppressed. An explicit judge effort alias remains pinned because judge overrides are compatible with cheap mode. The stability alias claude-opus-4.6-1m spawns base claude-opus-4.6. Mutually exclusive with non-empty roles overrides.",
                    },
                    max_premium_calls: {
                        type: "integer",
                        minimum: 1,
                        description:
                            "Optional. Hard cap on premium model calls. Worst-case is `6 reviewers + 6 retries + 2 judge slots = 14` (or 12 with `skip_judge: true`). The handler rejects the request before building the packet if the cap is too low. Omit for no cap.",
                    },
                },
                required: ["topic"],
            },
            handler: (args) => runHandler(args, { log: (msg) => session.log(msg) }),
        },
    ],
});
