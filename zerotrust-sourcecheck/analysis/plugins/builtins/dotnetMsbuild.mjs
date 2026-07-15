import { basename, defineRulePlugin } from "../helpers.mjs";

const MSBUILD_KEYS = new Set([
    "target",
    "exec",
    "usingtask",
    "codetaskfactory",
    "beforetargets",
    "aftertargets",
]);

function msbuildPath(path) {
    const base = basename(path);
    return base.endsWith(".csproj") || base.endsWith(".props") || base.endsWith(".targets");
}

export default defineRulePlugin({
    id: "builtin.dotnet-msbuild",
    detect: (context) => context.manifests.some((file) => msbuildPath(file.path)),
    select: (context) => context.facts.filter((fact) =>
        msbuildPath(fact.path)
        && ((fact.kind === "config-key"
                && MSBUILD_KEYS.has(String(fact.name || "").toLowerCase()))
            || fact.kind === "command-construction"
            || fact.kind === "sink-hint")),
    seed: (fact) => ({
        fact,
        key: `msbuild:${fact.path}:${fact.kind}:${fact.name}`,
        activationLabel: `MSBuild registration: ${fact.name}`,
        targetLabel: `MSBuild target/task capability: ${fact.value || fact.name}`,
        edgeKind: "invokes",
        tags: ["dotnet", "msbuild", "build-target"],
    }),
    detectedWarning: (count) =>
        `.NET/MSBuild definitions detected; indexed ${count} target/task activation surface(s).`,
    emptyWarning:
        ".NET/MSBuild definitions were detected, but no normalized target/task activation fact was available.",
});
