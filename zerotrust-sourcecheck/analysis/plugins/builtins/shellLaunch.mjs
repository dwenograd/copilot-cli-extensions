import { defineRulePlugin, pathMatches } from "../helpers.mjs";

const SHELL_PATH = /(?:^|\/)[^/]+\.(?:ps1|psm1|psd1|sh|bash|zsh|fish|cmd|bat)$/u;

export default defineRulePlugin({
    id: "builtin.shell-launch",
    detect: (context) => context.files.some((file) => pathMatches(file.path, SHELL_PATH)),
    select: (context) => context.facts.filter((fact) =>
        pathMatches(fact.path, SHELL_PATH)
        && ["command-construction", "execution-registration", "sink-hint", "import"]
            .includes(fact.kind)),
    seed: (fact) => ({
        fact,
        key: `shell:${fact.path}:${fact.kind}:${fact.name}:${fact.value || ""}`,
        activationLabel: `Shell launch surface: ${fact.name}`,
        targetLabel: `Shell command/module target: ${fact.value || fact.name}`,
        edgeKind: fact.kind === "import" ? "depends-on" : "invokes",
        tags: ["powershell", "shell", "process-launch"],
    }),
    detectedWarning: (count) =>
        `PowerShell/shell files detected; indexed ${count} command, import, or execution registration surface(s).`,
    emptyWarning:
        "PowerShell/shell files were detected, but no normalized launch or execution fact was available.",
});
