import {
    SEMANTIC_COVERAGE_PLAN_KIND,
    SEMANTIC_COVERAGE_SCHEMA_REVISION,
} from "../analysis/semanticCoverage.mjs";
import { renderSemanticReviewPrompt } from "../council/semanticReviewPrompt.mjs";

export const SEMANTIC_COVERAGE_WIRING_STATUS = "required-current-stage";

export function renderSemanticCoverageScaffold({
    plan,
    assignments = [],
} = {}) {
    if (!plan
        || plan.schemaVersion !== SEMANTIC_COVERAGE_SCHEMA_REVISION
        || plan.contractKind !== SEMANTIC_COVERAGE_PLAN_KIND) {
        throw new TypeError("renderSemanticCoverageScaffold requires a semantic plan");
    }
    if (!Array.isArray(assignments)) {
        throw new TypeError("assignments must be an array");
    }
    for (const assignment of assignments) {
        if (assignment?.planId !== plan.planId) {
            throw new TypeError("semantic assignment does not belong to the plan");
        }
    }
    const scannerShards = [...new Set(
        plan.scannerAssignments.map((assignment) => assignment.scannerShard),
    )].sort((left, right) => left - right);
    const modelShards = [...new Set(
        plan.modelReviewShards.map((assignment) => assignment.modelShard),
    )].sort((left, right) => left - right);
    const renderedReviews = assignments.length === 0
        ? "(no model-review assignments supplied)": assignments.map((assignment, index) =>
            `### Semantic review ${index + 1}\n\n`
            + renderSemanticReviewPrompt(assignment)).join("\n\n");

    return `## Semantic-coverage scaffold

Wiring status: \`${SEMANTIC_COVERAGE_WIRING_STATUS}\`.
Plan: \`${plan.planId}\`; decoded snapshot: \`${plan.snapshotId}\`.
Scanner shards: ${JSON.stringify(scannerShards)}.
Model shards: ${JSON.stringify(modelShards)}.

The safe wrappers own assignment tokens and immutable recording. Every required
scanner assignment must resolve without truncation/blockers. Every executable
or configuration subject requires scanner coverage and at least one completed
model semantic review; high-risk subjects require two independent reviewer IDs.
Prompt-affected subjects additionally require the normalized-view review
contract. Duplicate reviews never increase reviewer counts.

Each model assignment contains a deterministic source-text-free semanticView
derived only from immutable scanner facts and snapshot artifact metadata. Empty
findings count only when the wrapper validates the exact assignment token,
object/artifact and semanticView identities, complete normalized fact/artifact
coverage, all bounded checks, and the complete negative-evidence code set.
Empty, unresolved, blocked, or truncated semantic views cannot complete.
Findings are admitted only as bounded behavior/severity/confidence/fit
candidates with exact semanticView object/artifact/fact/evidence bindings; the
wrapper derives immutable candidate IDs and the semantic candidate ledger.
Opaque finding codes and prose-only coverage claims never count.

${renderedReviews}`;
}
