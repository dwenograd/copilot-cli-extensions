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
                "Critique a topic with 6 role-specialized rubber-duck reviewers (security / stability / performance / maintainer / skeptic / user) + a judge synthesis pass. Each role uses a tiered model (xhigh for reasoning-heavy roles, GPT for cross-family diversity, Sonnet for UX). Use INSTEAD of triple_duck when you want different angles, not consensus. The judge produces cross-role contradiction adjudication + ranked top priorities + a premise challenge (\"what no duck noticed\") + executive summary; raw role outputs preserved in an appendix. Returns an instruction packet — the calling agent then executes the pattern using the built-in `task` tool.",
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
                            "Optional. Per-role model overrides — partial object, not all 6 required. E.g. `{ security: \"claude-opus-4.7-xhigh\", performance: \"gpt-5.5\" }`. Roles you don't specify use the tiered defaults. MUTUALLY EXCLUSIVE with `cheap` (an empty `{}` is treated as no override).",
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
                            "Optional. Override the judge model. Default is claude-opus-4.7-xhigh (cheap mode: claude-opus-4.7).",
                    },
                    skip_judge: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. When true, skip the judge synthesis pass and present the 6 raw role outputs directly. Saves 2 premium calls (one judge + one retry slot). Use when you want to read the raw critiques yourself.",
                    },
                    cheap: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. Use cheap-tier role models — drops xhigh/high reasoning upgrades to save cost. Note: cheap stability default keeps `claude-opus-4.6-1m` to preserve large-context support for big code reviews; cheap performance/skeptic/user defaults are unchanged from defaults. MUTUALLY EXCLUSIVE with `roles` (an empty `roles: {}` object is treated as no override and is allowed alongside `cheap`).",
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
