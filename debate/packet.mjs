// debate/packet.mjs
//
// Composes the markdown protocol packet from pre-processed pieces. Pure
// function — no SDK imports, no I/O. The handler does all orchestration
// (validation, scrub, policy wrap, model resolution, budget check) and
// passes the prepared pieces to this composer.

export function buildInstructionPacket({
    effectiveDebaters,
    effectiveJudge,
    cheap,
    rounds,
    questionWrapped,
    positionAWrapped,
    positionBWrapped,
    contextWrapped,
    budgetBlock,
    substitutionNote,
    injectionPreamble,
    scrubNote,
    injectionWarnings,
    subAgentInstruction,
}) {
    const modeLine = cheap
        ? `\n**Mode:** cheap (non-1M-context variants)\n`
        : "";

    const warningsBlock = injectionWarnings && injectionWarnings.length > 0
        ? `\n${injectionWarnings.map((w) => `> ⚠️ ${w}`).join("\n")}\n`
        : "";

    const contextBlock = contextWrapped
        ? `\n**Shared context (both debaters and judge see this):**\n${contextWrapped}\n`
        : "";

    const positionABlock = positionAWrapped
        ? positionAWrapped
        : `_(unspecified — debater A must articulate the strongest case for ONE side of the question, then argue it)_`;
    const positionBBlock = positionBWrapped
        ? positionBWrapped
        : `_(unspecified — debater B must articulate the strongest case for the OPPOSING side from debater A, then argue it)_`;

    const expectedCalls = 2 * rounds + 1; // debaters per round + 1 judge

    // Handler enforces both-or-neither, so this branch fires only when BOTH
    // positions are unspecified.
    const positionInferenceNote = (!positionAWrapped || !positionBWrapped)
        ? `\n**Note on unspecified positions:** No positions were specified. You (the orchestrator) must FIRST decide the two opposing positions yourself based on the question, then pass them explicitly to the debaters. Do NOT let each debater pick their own side independently — they could end up on the same side. Write the two positions out before launching agents.\n`
        : "";

    let roundsSection = "";
    for (let r = 1; r <= rounds; r++) {
        if (r === 1) {
            roundsSection += `
### Round ${r} — Opening arguments (parallel)

In a SINGLE response, make two \`task\` tool calls in parallel:

\`\`\`
task(agent_type="general-purpose", mode="sync", model=${JSON.stringify(effectiveDebaters[0])},
     name="debater-A-r1",
     description="Debate round ${r} — Position A",
     prompt=<see below>)

task(agent_type="general-purpose", mode="sync", model=${JSON.stringify(effectiveDebaters[1])},
     name="debater-B-r1",
     description="Debate round ${r} — Position B",
     prompt=<see below>)
\`\`\`

Each opening prompt must contain:
- The question (verbatim, INCLUDING the USER_INPUT envelope markers — do not strip them)
- Any shared context (verbatim, INCLUDING envelope markers)
- The debater's assigned position (Position A for debater A, Position B for debater B; preserve any envelope markers)
- Instruction: "You are an advocate. Make the STRONGEST possible case for your assigned position. Investigate the codebase if needed to find concrete evidence. Address the most likely counterarguments preemptively. Output: (1) Thesis, (2) Numbered list of arguments with evidence, (3) Anticipated rebuttals and your responses. Do NOT acknowledge the other side's strengths beyond what's needed to rebut them. Stay in role."
- ${subAgentInstruction}
- Tell the debater their model identity is hidden from the other side.
`;
        } else {
            roundsSection += `
### Round ${r} — Rebuttals (parallel)

Each debater now sees the OTHER side's previous round and rebuts. **Every rebuttal prompt MUST restate the original framing** (question, shared context, both positions, the debater's assigned role) — these are stateless agents, so they only know what you put in the prompt. Then append transcripts and the rebut instruction.

Each rebuttal prompt MUST contain:
- The question (verbatim, INCLUDING the USER_INPUT envelope markers — do not strip them)
- Any shared context (verbatim, INCLUDING envelope markers)
- Both positions (verbatim, INCLUDING envelope markers)
- The debater's assigned role (A argues Position A; B argues Position B)
- That debater's full prior transcript (rounds 1..${r - 1}, labeled by round)
- The opposing debater's full prior transcript (rounds 1..${r - 1}, labeled by round)
- Instruction to rebut the opponent's strongest points and reinforce the assigned position; concede only what's strictly necessary; stay in role.
- ${subAgentInstruction}

In a SINGLE response, make two parallel \`task\` calls:

\`\`\`
task(agent_type="general-purpose", mode="sync", model=${JSON.stringify(effectiveDebaters[0])},
     name="debater-A-r${r}",
     description="Debate round ${r} — A rebuts B",
     prompt=<question verbatim + shared context verbatim + Position A verbatim + Position B verbatim + "You are debater A; you argue Position A. You are 1 of 2 advocates; the judge is independent." + debater A's full prior transcript (rounds 1..${r - 1}, labeled by round) + the OPPOSING debater's full prior transcript (rounds 1..${r - 1}, labeled by round) + "Rebut B's strongest points and reinforce your assigned Position A. Concede only what's strictly necessary; redirect everything else. Stay in role.">)

task(agent_type="general-purpose", mode="sync", model=${JSON.stringify(effectiveDebaters[1])},
     name="debater-B-r${r}",
     description="Debate round ${r} — B rebuts A",
     prompt=<question verbatim + shared context verbatim + Position A verbatim + Position B verbatim + "You are debater B; you argue Position B. You are 1 of 2 advocates; the judge is independent." + debater B's full prior transcript (rounds 1..${r - 1}, labeled by round) + the OPPOSING debater's full prior transcript (rounds 1..${r - 1}, labeled by round) + "Rebut A's strongest points and reinforce your assigned Position B. Concede only what's strictly necessary; redirect everything else. Stay in role.">)
\`\`\`
`;
        }
    }

    return `# DEBATE PROTOCOL
${modeLine}
${budgetBlock}
${substitutionNote ? substitutionNote + "\n" : ""}${scrubNote ? scrubNote + "\n" : ""}${warningsBlock}
${injectionPreamble}

You invoked \`debate\`. Execute the following protocol exactly.

## Question
${questionWrapped}

## Positions

**Position A:**
${positionABlock}

**Position B:**
${positionBBlock}
${positionInferenceNote}${contextBlock}
## Roles
- **Debater A:** ${effectiveDebaters[0]} — argues Position A
- **Debater B:** ${effectiveDebaters[1]} — argues Position B
- **Judge:** ${effectiveJudge} — independent, sees both sides only at the end
- **Rounds:** ${rounds}${rounds > 1 ? " (1 opening + " + (rounds - 1) + " rebuttal round(s))" : " (opening only — no rebuttals)"}
- **Expected total premium calls:** ${expectedCalls} (${2 * rounds} debater + 1 judge)

## Step 1 — Run debate rounds
${roundsSection}
### Round-failure handling

Track \`actualPremiumCalls\`; start at 0. Increment by 1 for every debater or judge call you launch, INCLUDING retries.

If any debater call fails OR refuses to take its assigned position:
- Retry that debater ONCE with the same model (and increment \`actualPremiumCalls\`).
- If still failing, the debate cannot continue meaningfully — STOP and tell the user which model failed.
- If a debater "breaks character" (e.g., concedes the entire argument or refuses to advocate), retry once with an explicit reminder that they are role-playing an advocate; if it still won't engage, STOP.

## Step 2 — Judge

Make ONE \`task\` call to the judge:

\`\`\`
task(agent_type="general-purpose", mode="sync", model=${JSON.stringify(effectiveJudge)},
     name="debate-judge",
     description="Debate judge",
     prompt=<see below>)
\`\`\`

The judge's prompt must contain:
- The question (verbatim, INCLUDING the USER_INPUT envelope markers — do not strip them)
- Any shared context (verbatim, INCLUDING envelope markers)
- The two positions (verbatim, INCLUDING envelope markers)
- The FULL transcript: every round's output from both debaters, clearly labeled
- ${subAgentInstruction}
- Instruction:
  > "You are an impartial judge. The two debaters are advocates — they will not present a balanced view. Your job is to weigh the actual EVIDENCE and ARGUMENTS, not the rhetoric. Render a verdict in this exact structure:
  >
  > 1. **Strongest argument from each side** (one each, with reasoning)
  > 2. **Weakest argument from each side** (one each, with reasoning)
  > 3. **Cruxes** — what facts, if true, would decide the question?
  > 4. **Verdict** — Position A wins / Position B wins / It depends (with explicit conditions)
  > 5. **Confidence** — how confident you are in the verdict and why
  > 6. **What evidence would change your mind**
  >
  > Do NOT default to splitting the difference. Pick a side unless the question genuinely depends on a missing fact, in which case say what fact is missing."

## Step 3 — Present to the user

\`\`\`
## Debate: <question summary>

**Position A** (${effectiveDebaters[0]}): <one-line summary>
**Position B** (${effectiveDebaters[1]}): <one-line summary>
**Judge** (${effectiveJudge})

### Strongest arguments
- A: ...
- B: ...

### Cruxes
- ...

### Verdict
<judge's verdict>

### Confidence & what would change the verdict
...

### Recommendation
<your synthesis — what should the user actually do given the verdict?>
\`\`\`

Optionally include a "Full transcript" collapsible section if the user might want to read the rounds verbatim.

## Step 4 — Be honest about cost

End with "(Debate used <actualPremiumCalls> premium model calls across ${rounds} round(s) + judge<, with N retries> if applicable.)"

---

**Begin Step 1 now. Do not summarize this protocol back to the user — just execute it.**`;
}
