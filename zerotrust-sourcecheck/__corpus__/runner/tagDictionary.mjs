// __corpus__/runner/tagDictionary.mjs
// Category-letter and generic-word tagger. This file intentionally avoids
// literal attack-pattern fragments; keep tags broad and AV-safe.

export const CATEGORY_TAGS = Object.freeze({
    A: ["remote-fetch", "code-execution", "network"],
    B: ["code-execution"],
    C: ["credential-store-read", "credential"],
    D: ["persistence"],
    E: ["obfuscation"],
    F: ["supply-chain"],
    G: ["ci-workflow"],
});

const WORD_TAGS = Object.freeze([
    { words: ["remote", "fetch", "download"], tags: ["remote-fetch", "network"] },
    { words: ["network", "socket", "http", "request"], tags: ["network"] },
    { words: ["execute", "execution", "script", "runtime"], tags: ["code-execution"] },
    { words: ["credential", "secret", "token", "key"], tags: ["credential-store-read", "credential"] },
    { words: ["persist", "persistence", "startup", "autostart"], tags: ["persistence"] },
    { words: ["obfuscation", "obfuscated", "unicode", "hidden", "encoded"], tags: ["obfuscation"] },
    { words: ["package", "dependency", "lockfile", "install", "publish"], tags: ["supply-chain"] },
    { words: ["workflow", "action", "runner", "ci"], tags: ["ci-workflow"] },
    { words: ["binary", "artifact"], tags: ["binary-artifact"] },
    { words: ["provenance", "signature", "attestation"], tags: ["provenance"] },
    { words: ["hook", "hooks"], tags: ["hook"] },
]);

function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function wordRegex(word) {
    return new RegExp(`(^|[^A-Za-z0-9_-])${escapeRegex(word)}([^A-Za-z0-9_-]|$)`, "i");
}

export function tagsForCategory(category) {
    const letter = normalizeCategory(category);
    return letter ? [...CATEGORY_TAGS[letter]] : [];
}

export function normalizeCategory(category) {
    if (typeof category !== "string") return null;
    const letter = category.trim().toUpperCase();
    return Object.hasOwn(CATEGORY_TAGS, letter) ? letter : null;
}

export function deriveTags({ category = null, text = "", extraTags = [] } = {}) {
    const tags = new Set();
    for (const tag of tagsForCategory(category)) tags.add(tag);

    const haystack = String(text || "");
    for (const entry of WORD_TAGS) {
        if (entry.words.some((word) => wordRegex(word).test(haystack))) {
            for (const tag of entry.tags) tags.add(tag);
        }
    }

    for (const tag of extraTags) {
        if (typeof tag === "string" && tag.trim()) tags.add(normalizeTag(tag));
    }

    return [...tags].sort();
}

export function normalizeTag(tag) {
    return String(tag).trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
}

export const __internals = {
    WORD_TAGS,
    escapeRegex,
    wordRegex,
};
