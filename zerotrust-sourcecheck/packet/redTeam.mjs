import {
    RED_TEAM_PLAN_KIND,
    RED_TEAM_SCHEMA_REVISION,
} from "../analysis/redTeam.mjs";
import { renderRedTeamPrompt } from "../council/redTeamPrompt.mjs";

export const RED_TEAM_WIRING_STATUS = "required-current-stage";

export function renderRedTeamScaffold({
    plan,
    assignments = [],
} = {}) {
    if (!plan
        || plan.schemaVersion !== RED_TEAM_SCHEMA_REVISION
        || plan.contractKind !== RED_TEAM_PLAN_KIND) {
        throw new TypeError("renderRedTeamScaffold requires a red-team plan");
    }
    if (!Array.isArray(assignments)) {
        throw new TypeError("assignments must be an array");
    }
    for (const assignment of assignments) {
        if (assignment?.planId !== plan.planId) {
            throw new TypeError("red-team assignment does not belong to the plan");
        }
    }
    const prompts = assignments.length === 0
        ? "(no red-team assignments supplied)": assignments.map((assignment, index) =>
            `### Evasive red-team review ${index + 1}\n\n`
            + renderRedTeamPrompt(assignment)).join("\n\n");
    return `## Evasive red-team scaffold

Wiring status: \`${RED_TEAM_WIRING_STATUS}\`.
Plan: \`${plan.planId}\`; scanned snapshot: \`${plan.snapshotId}\`.
Initial structured discovery handoff:
\`${plan.initialDiscoveryHandoff.handoffId}\`.
Supply-chain binding:
\`${plan.supplyChainBinding.hashes.bindingSha256}\`.

The prepare wrapper owns the persisted \`semantically-covered → scanned\`
transition and inserts a red-team incompleteness blocker. The finalize wrapper
alone may remove that blocker and advance \`scanned → red-teamed\`.

All ${plan.categoryPlans.length} evasion categories are mandatory. Finalization
requires every mandatory category, deterministic assignment/review identity,
at least 90% assignment coverage, complete assigned subjects, exact
falsification checks, and immutable negative-evidence proof for empty results.
There is no caller-supplied completeness boolean.

Each assignment is audit, scanned-snapshot, semantic-plan/evaluation, initial
handoff, and supply-chain bound. It embeds only source-text-free normalized
semantic views, graph/artifact/dependency metadata, prompt signals, and exact
identities. New candidates enter the candidate ledger through immutable
review records before trace.

${prompts}`;
}
