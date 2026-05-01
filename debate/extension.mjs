// Extension: debate
// Adversarial multi-model debate: two agents argue opposing positions on a
// contested question, optionally with rebuttals, then a judge agent renders
// a verdict. Use when the right answer is contested or when you want to
// stress-test a decision rather than seek consensus.
//
// This file is a thin shell — handler.mjs holds the orchestration logic
// (validation, scrub, injection policy, budget check, model resolution).
// The split exists so handler.mjs can be unit-tested without joinSession().

import { joinSession } from "@github/copilot-sdk/extension";
import { runHandler } from "./handler.mjs";

const session = await joinSession({
    tools: [
        {
            name: "debate",
            description:
                "Run an adversarial multi-model debate: two agents argue opposing positions on a contested question (with optional rebuttal rounds), then a third independent judge model renders a verdict. Use this INSTEAD of triple-duck when the right answer is genuinely contested and you want the strongest case for each side stress-tested, not consensus. Returns an instruction packet — the calling agent then executes the pattern using the built-in `task` tool.",
            parameters: {
                type: "object",
                properties: {
                    question: {
                        type: "string",
                        description:
                            "The contested question to debate. Should be a real decision with two defensible answers (e.g., 'Should we use a state machine or plain conditionals for the wizard flow?'). Vague or one-sided questions produce poor debates.",
                    },
                    position_a: {
                        type: "string",
                        description:
                            "Optional. The position debater A will argue. If omitted, the orchestrator will infer the two opposing positions from the question. Specify both position_a and position_b together if you have specific framings in mind.",
                    },
                    position_b: {
                        type: "string",
                        description:
                            "Optional. The position debater B will argue (opposing position_a). If omitted, the orchestrator infers it.",
                    },
                    context: {
                        type: "string",
                        description:
                            "Optional. Shared context that both debaters and the judge will see: file paths, constraints, prior decisions, environment details.",
                    },
                    rounds: {
                        type: "integer",
                        default: 1,
                        minimum: 1,
                        maximum: 4,
                        description:
                            "Optional. Number of debate rounds. 1 = opening arguments only (3 typical / 5 worst-case calls). 2 = opening + 1 rebuttal round (5 typical / 9 worst-case). Each additional round adds 2 typical / 4 worst-case calls. The handler reserves one retry per debater call when enforcing `max_premium_calls`. Default 1.",
                    },
                    debaters: {
                        type: "array",
                        items: { type: "string" },
                        minItems: 2,
                        maxItems: 2,
                        description:
                            "Optional. Exactly 2 distinct model IDs for the two debaters. Defaults to claude-opus-4.7-xhigh and gpt-5.5 (different model families maximize divergence; xhigh = extra-high reasoning, ~200k context).",
                    },
                    judge: {
                        type: "string",
                        description:
                            "Optional. Model ID for the judge. Should differ from both debaters to stay independent. Defaults to claude-opus-4.6-1m.",
                    },
                    cheap: {
                        type: "boolean",
                        default: false,
                        description:
                            "Optional. When true, use cheap variants (claude-opus-4.7, gpt-5.5 debaters; claude-opus-4.6 judge — non-1M-context). Set when the user invokes 'debate cheap <question>'. MUTUALLY EXCLUSIVE with explicit `debaters` or `judge`.",
                    },
                    max_premium_calls: {
                        type: "integer",
                        minimum: 1,
                        description:
                            "Optional. Hard cap on premium model calls for this invocation (counted against the worst-case formula: 4*rounds + 1). The handler rejects the request before building the packet if the cap is too low to satisfy the worst case. Omit for no cap.",
                    },
                },
                required: ["question"],
            },
            handler: (args) => runHandler(args, { log: (msg) => session.log(msg) }),
        },
    ],
});
