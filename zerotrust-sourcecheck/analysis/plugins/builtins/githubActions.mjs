import { defineRulePlugin, pathMatches } from "../helpers.mjs";

const TRIGGERS = new Set([
    "pull_request",
    "pull_request_target",
    "push",
    "schedule",
    "workflow_call",
    "workflow_dispatch",
    "workflow_run",
    "repository_dispatch",
    "release",
]);

function isWorkflow(fact) {
    return pathMatches(fact.path, /^\.github\/workflows\/.+\.ya?ml$/u);
}

function relevant(fact) {
    const name = String(fact.name || "").toLowerCase();
    return (fact.kind === "config-key" && TRIGGERS.has(name))
        || (fact.kind === "execution-registration"
            && ["workflow-run", "workflow-uses"].includes(name))
        || (fact.kind === "sensitive-resource"
            && ["environment-variable", "secret-material"].includes(name));
}

export default defineRulePlugin({
    id: "builtin.github-actions",
    detect: (context) => context.manifests.some((file) =>
        pathMatches(file.path, /^\.github\/workflows\/.+\.ya?ml$/u)),
    select: (context) => context.facts.filter((fact) => isWorkflow(fact) && relevant(fact)),
    seed: (fact) => {
        const isSecret = fact.kind === "sensitive-resource";
        const isActionRef = fact.name === "workflow-uses";
        return {
            fact,
            key: `actions:${fact.kind}:${fact.name}:${fact.value || ""}`,
            activationKind: fact.kind === "config-key" ? "trigger" : "activation",
            activationLabel: fact.kind === "config-key"
                ? `GitHub Actions trigger: ${fact.name}`
                : `GitHub Actions registration: ${fact.name}`,
            targetKind: isSecret ? "sensitive-source" : isActionRef ? "dependency" : "capability",
            targetLabel: isSecret
                ? `Workflow secret/environment reference: ${fact.value || fact.name}`
                : isActionRef
                    ? `Workflow action reference: ${fact.value}`
                    : `Workflow command surface: ${fact.value || fact.name}`,
            edgeKind: isSecret ? "reads-from" : isActionRef ? "depends-on" : "invokes",
            tags: ["github-actions", isSecret ? "secret-reference" : "workflow-activation"],
        };
    },
    detectedWarning: (count) =>
        `GitHub Actions definitions detected; indexed ${count} trigger, secret, command, or action-reference surface(s).`,
    emptyWarning:
        "GitHub Actions definitions were detected, but no normalized trigger, secret, run, or action-reference fact was available.",
});
