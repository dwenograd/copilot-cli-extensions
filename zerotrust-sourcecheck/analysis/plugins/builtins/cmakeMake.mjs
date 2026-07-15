import { basename, defineRulePlugin } from "../helpers.mjs";

function buildPath(path) {
    const base = basename(path);
    return base === "cmakelists.txt"
        || base === "makefile"
        || base === "gnumakefile"
        || base.endsWith(".cmake")
        || base.endsWith(".mk");
}

export default defineRulePlugin({
    id: "builtin.cmake-make",
    detect: (context) => context.manifests.some((file) => buildPath(file.path)),
    select: (context) => context.facts.filter((fact) =>
        buildPath(fact.path)
        && ["config-key", "execution-registration", "command-construction", "sink-hint", "import"]
            .includes(fact.kind)),
    seed: (fact) => ({
        fact,
        key: `native-build:${fact.path}:${fact.kind}:${fact.name}`,
        activationLabel: `CMake/Make build surface: ${fact.name}`,
        targetLabel: `Native build recipe capability: ${fact.value || fact.name}`,
        edgeKind: fact.kind === "import" ? "depends-on" : "invokes",
        tags: ["cmake", "make", "native-build"],
    }),
    detectedWarning: (count) =>
        `CMake/Make definitions detected; indexed ${count} recipe, command, or dependency surface(s).`,
    emptyWarning:
        "CMake/Make definitions were detected, but no normalized recipe or command fact was available.",
});
