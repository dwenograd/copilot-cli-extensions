import { basename, defineRulePlugin } from "../helpers.mjs";

const PYTHON_MANIFESTS = new Set(["pyproject.toml", "setup.py", "setup.cfg"]);
const BUILD_KEYS = new Set([
    "build-backend",
    "build-system",
    "setup_requires",
    "cmdclass",
    "entry_points",
]);

function relevant(fact) {
    const name = String(fact.name || "").toLowerCase();
    const value = String(fact.value || "").toLowerCase();
    return ((fact.kind === "config-key" || fact.kind === "manifest-key")
            && BUILD_KEYS.has(name))
        || (fact.kind === "import"
            && /(setuptools|distutils|hatchling|poetry|flit|mesonpy|scikit_build)/u.test(value))
        || fact.kind === "command-construction";
}

export default defineRulePlugin({
    id: "builtin.python-packaging",
    detect: (context) => context.manifests.some((file) =>
        PYTHON_MANIFESTS.has(basename(file.path))),
    select: (context) => context.facts.filter((fact) =>
        PYTHON_MANIFESTS.has(basename(fact.path)) && relevant(fact)),
    seed: (fact) => ({
        fact,
        key: `python-build:${fact.kind}:${fact.name}:${fact.value || ""}`,
        activationLabel: `Python packaging/build registration: ${fact.name}`,
        targetLabel: `Python build backend or setup surface: ${fact.value || fact.name}`,
        edgeKind: "invokes",
        tags: ["python", "packaging", "build-backend"],
    }),
    detectedWarning: (count) =>
        `Python packaging metadata detected; indexed ${count} build-backend/setup activation surface(s).`,
    emptyWarning:
        "Python packaging metadata was detected, but no normalized build-backend or setup activation fact was available.",
});
