import { basename, defineRulePlugin } from "../helpers.mjs";

const LIFECYCLE_SCRIPTS = new Set([
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishonly",
    "postpublish",
    "prepack",
    "postpack",
]);

export default defineRulePlugin({
    id: "builtin.node-lifecycle",
    detect: (context) => context.manifests.some((file) => basename(file.path) === "package.json"),
    select: (context) => context.facts.filter((fact) =>
        basename(fact.path) === "package.json"
        && fact.kind === "execution-registration"
        && fact.name === "package-script"
        && LIFECYCLE_SCRIPTS.has(String(fact.value || "").toLowerCase())),
    seed: (fact) => ({
        fact,
        key: `npm:${fact.value}`,
        activationLabel: `npm lifecycle registration: ${fact.value}`,
        targetLabel: "npm package lifecycle command",
        edgeKind: "invokes",
        tags: ["node", "npm", "package-lifecycle"],
    }),
    detectedWarning: (count) =>
        `Node/npm ecosystem detected; indexed ${count} install/publish lifecycle activation surface(s).`,
    emptyWarning:
        "Node/npm ecosystem detected; no lifecycle activation registration was present in normalized manifest facts.",
});
