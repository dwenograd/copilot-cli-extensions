import { basename, defineRulePlugin, pathMatches } from "../helpers.mjs";

function containerPath(path) {
    const base = basename(path);
    return base === "dockerfile"
        || base === "containerfile"
        || /^docker-compose(?:\.[^.]+)?\.ya?ml$/u.test(base)
        || pathMatches(path, /^\.devcontainer\/.+/u)
        || base === "devcontainer.json";
}

export default defineRulePlugin({
    id: "builtin.container-devcontainer",
    detect: (context) => context.manifests.some((file) => containerPath(file.path)),
    select: (context) => context.facts.filter((fact) =>
        containerPath(fact.path)
        && ["manifest-key", "config-key", "execution-registration", "command-construction", "import"]
            .includes(fact.kind)),
    seed: (fact) => ({
        fact,
        key: `container:${fact.path}:${fact.kind}:${fact.name}`,
        activationLabel: `Container/devcontainer definition: ${fact.name}`,
        targetLabel: `Container build/start capability: ${fact.value || fact.name}`,
        edgeKind: fact.kind === "import" ? "depends-on": "invokes",
        tags: ["container", "devcontainer", "build-definition"],
    }),
    detectedWarning: (count) =>
        `Container/devcontainer definitions detected; indexed ${count} build/start/configuration surface(s).`,
    emptyWarning:
        "Container/devcontainer definitions were detected, but no normalized build/start fact was available.",
});
