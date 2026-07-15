import { basename, defineRulePlugin } from "../helpers.mjs";

function cargoPath(path) {
    const base = basename(path);
    return base === "cargo.toml" || base === "build.rs";
}

function relevant(fact) {
    const name = String(fact.name || "").toLowerCase();
    return (basename(fact.path) === "cargo.toml"
            && ["build", "build-dependencies"].includes(name))
        || (basename(fact.path) === "build.rs"
            && ["command-construction", "sink-hint", "import"].includes(fact.kind));
}

export default defineRulePlugin({
    id: "builtin.cargo-build",
    detect: (context) => context.manifests.some((file) => cargoPath(file.path))
        || context.files.some((file) => basename(file.path) === "build.rs"),
    select: (context) => context.facts.filter((fact) => cargoPath(fact.path) && relevant(fact)),
    seed: (fact) => ({
        fact,
        key: `cargo:${fact.path}:${fact.kind}:${fact.name}`,
        activationLabel: basename(fact.path) === "build.rs"
            ? "Cargo build.rs execution surface"
            : `Cargo build registration: ${fact.name}`,
        targetLabel: fact.value
            ? `Cargo build target: ${fact.value}`
            : "Cargo build-time capability",
        edgeKind: "invokes",
        tags: ["cargo", "rust", "build-script"],
    }),
    detectedWarning: (count) =>
        `Cargo metadata/build.rs detected; indexed ${count} build-time activation surface(s).`,
    emptyWarning:
        "Cargo metadata or build.rs was detected, but no normalized build-time activation fact was available.",
});
