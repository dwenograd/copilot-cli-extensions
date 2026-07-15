import { basename, defineRulePlugin } from "../helpers.mjs";

const BROWSER_KEYS = new Set([
    "background",
    "service_worker",
    "content_scripts",
    "externally_connectable",
    "host_permissions",
    "permissions",
]);

function relevant(fact) {
    if (fact.kind === "execution-registration") {
        return fact.name === "activation-event" || fact.name === "contributed-command";
    }
    return (fact.kind === "manifest-key" || fact.kind === "config-key")
        && BROWSER_KEYS.has(String(fact.name || "").toLowerCase());
}

export default defineRulePlugin({
    id: "builtin.extension-activation",
    detect: (context) => context.facts.some((fact) =>
        ["package.json", "manifest.json", "extension.json"].includes(basename(fact.path))
        && relevant(fact)),
    select: (context) => context.facts.filter((fact) =>
        ["package.json", "manifest.json", "extension.json"].includes(basename(fact.path))
        && relevant(fact)),
    seed: (fact) => ({
        fact,
        key: `extension:${fact.name}:${fact.value || ""}`,
        activationLabel: fact.name === "activation-event"
            ? `VS Code activation event: ${fact.value}`
            : `Extension activation surface: ${fact.name}`,
        targetLabel: fact.name === "contributed-command"
            ? `Contributed command: ${fact.value}`
            : "Extension runtime entry surface",
        edgeKind: "activates",
        tags: ["browser-extension", "vscode-extension", "activation"],
    }),
    detectedWarning: (count) =>
        `VS Code/browser extension activation metadata detected; indexed ${count} activation surface(s).`,
    emptyWarning:
        "Extension metadata was detected, but no bounded normalized activation fact was available.",
});
