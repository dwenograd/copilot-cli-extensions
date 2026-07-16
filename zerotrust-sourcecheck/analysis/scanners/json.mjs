import {
    commandTarget,
    createScannerContext,
    rangeFromTokens,
    tokenizeSource,
} from "./core.mjs";

const COMMAND_KEYS = new Set([
    "command",
    "entrypoint",
    "postattachcommand",
    "postcreatecommand",
    "poststartcommand",
    "initializecommand",
    "oncreatecommand",
    "updatecontentcommand",
    "waitfor",
]);

const ACTIVATION_KEYS = new Set([
    "activationevents",
    "commands",
    "entrypoint",
    "main",
    "browser",
    "bin",
    "scripts",
    "postcreatecommand",
    "poststartcommand",
    "postattachcommand",
    "initializecommand",
    "oncreatecommand",
    "updatecontentcommand",
]);

function scalarValue(token) {
    if (!token) return null;
    if (token.type === "string" && token.literal !== null) return token.literal;
    if (["identifier", "number"].includes(token.type)) return token.value;
    return null;
}

function parseJsonTokens(tokens, {
    maxNodes = 20_000,
    maxDepth = 64,
} = {}) {
    let nodes = 0;
    let truncated = false;

    function parseValue(index, path, depth) {
        if (nodes >= maxNodes || depth > maxDepth) {
            truncated = true;
            return { node: null, next: index + 1 };
        }
        const token = tokens[index];
        if (!token) return { node: null, next: index };
        nodes += 1;
        if (token.value === "{") {
            const entries = [];
            let cursor = index + 1;
            while (cursor < tokens.length && tokens[cursor].value !== "}") {
                if (tokens[cursor].value === ",") {
                    cursor += 1;
                    continue;
                }
                const keyToken = tokens[cursor];
                const key = scalarValue(keyToken);
                if (key === null || tokens[cursor + 1]?.value !== ":") {
                    cursor += 1;
                    continue;
                }
                const parsed = parseValue(cursor + 2, [...path, String(key)], depth + 1);
                const valueNode = parsed.node;
                const endToken = valueNode
                    ? tokens[valueNode.endTokenIndex]: tokens[cursor + 1];
                entries.push({
                    key: String(key),
                    keyTokenIndex: cursor,
                    value: valueNode,
                    startTokenIndex: cursor,
                    endTokenIndex: valueNode?.endTokenIndex ?? cursor + 1,
                    start: keyToken.start,
                    end: endToken.end,
                    path: [...path, String(key)],
                });
                cursor = Math.max(parsed.next, cursor + 2);
            }
            const closeIndex = tokens[cursor]?.value === "}" ? cursor: Math.max(index, cursor - 1);
            return {
                node: {
                    type: "object",
                    entries,
                    path,
                    startTokenIndex: index,
                    endTokenIndex: closeIndex,
                    start: token.start,
                    end: tokens[closeIndex]?.end ?? token.end,
                },
                next: closeIndex + 1,
            };
        }
        if (token.value === "[") {
            const items = [];
            let cursor = index + 1;
            let itemIndex = 0;
            while (cursor < tokens.length && tokens[cursor].value !== "]") {
                if (tokens[cursor].value === ",") {
                    cursor += 1;
                    continue;
                }
                const parsed = parseValue(cursor, [...path, String(itemIndex)], depth + 1);
                if (parsed.node) items.push(parsed.node);
                itemIndex += 1;
                cursor = Math.max(parsed.next, cursor + 1);
            }
            const closeIndex = tokens[cursor]?.value === "]" ? cursor: Math.max(index, cursor - 1);
            return {
                node: {
                    type: "array",
                    items,
                    path,
                    startTokenIndex: index,
                    endTokenIndex: closeIndex,
                    start: token.start,
                    end: tokens[closeIndex]?.end ?? token.end,
                },
                next: closeIndex + 1,
            };
        }
        return {
            node: {
                type: "scalar",
                value: scalarValue(token),
                dynamic: token.type === "string" && token.dynamic === true,
                path,
                startTokenIndex: index,
                endTokenIndex: index,
                start: token.start,
                end: token.end,
            },
            next: index + 1,
        };
    }

    const parsed = parseValue(0, [], 0);
    return Object.freeze({
        root: parsed.node,
        nodeCount: nodes,
        truncated,
    });
}

function walk(node, visit) {
    if (!node) return;
    visit(node);
    if (node.type === "object") {
        for (const entry of node.entries) {
            visit(entry);
            walk(entry.value, visit);
        }
    } else if (node.type === "array") {
        for (const item of node.items) walk(item, visit);
    }
}

function pathLower(node) {
    return (node.path || []).map((part) => String(part).toLowerCase());
}

function rangeForNode(node) {
    return { startOffset: node.start, endOffset: node.end };
}

function addCommand(context, node, name, tags) {
    if (node?.type !== "scalar" || typeof node.value !== "string") return;
    const target = commandTarget(node.value);
    context.addFact("command-construction", name, rangeForNode(node), {
        target,
        resolution: node.dynamic || /\$\{|\$\(|%\w+%/u.test(node.value)
            ? "dynamic": "literal",
        tags,
    });
    context.addFact("sink", "process-execution", rangeForNode(node), {
        target,
        resolution: target ? "literal": "dynamic",
        tags: [...tags, "process-execution"],
    });
    if (!target || node.dynamic || /\$\{|\$\(|%\w+%/u.test(node.value)) {
        context.addFact("unresolved-dynamic-target", name, rangeForNode(node), {
            value: "command-construction",
            resolution: "dynamic",
            tags: [...tags, "dynamic-target"],
        });
    }
    if (/(?:^|[-_:])(pre|post)?(?:build|compile|generate|codegen|prepare)(?:$|[-_:])/iu
        .test(name)) {
        context.addFact("generated-code-hook", "generated-code-command", rangeForNode(node), {
            target,
            tags: [...tags, "generated-code"],
        });
    }
}

function scanTree(context, tree) {
    walk(tree.root, (node) => {
        if (!node || !Array.isArray(node.path)) return;
        const path = pathLower(node);
        const key = String(node.key || "").toLowerCase();
        const parent = path[path.length - 2] || "";
        const leaf = path[path.length - 1] || key;

        if (node.key && ACTIVATION_KEYS.has(key)) {
            context.addFact("activation", "manifest-registration", rangeForNode(node), {
                value: key,
                tags: ["json", "manifest", "activation"],
            });
        }

        if (node.type === "scalar" && typeof node.value === "string") {
            if (parent === "scripts") {
                context.addFact("activation", "package-script", rangeForNode(node), {
                    value: leaf,
                    tags: ["json", "package-script"],
                });
                addCommand(context, node, leaf, ["json", "package-script"]);
            }
            if (parent === "activationevents") {
                context.addFact("activation", "activation-event", rangeForNode(node), {
                    value: node.value,
                    tags: ["json", "extension-activation"],
                });
            }
            if (COMMAND_KEYS.has(leaf)) {
                context.addFact("activation", "command-registration", rangeForNode(node), {
                    value: leaf,
                    tags: ["json", "command-registration"],
                });
                addCommand(context, node, leaf, ["json", "command-registration"]);
            }
            if (["main", "browser"].includes(leaf)) {
                context.addFact("import", "entry-module", rangeForNode(node), {
                    target: node.value,
                    resolution: "literal",
                    tags: ["json", "module-entry"],
                });
            }
            if (leaf === "dockerfile") {
                context.addFact("import", "dockerfile", rangeForNode(node), {
                    target: node.value,
                    resolution: "literal",
                    tags: ["json", "devcontainer", "container-build"],
                });
            }
            if (["when", "condition", "if"].includes(leaf)) {
                const value = node.value.toLowerCase();
                if (/(?:env|environment|secret|variable)/u.test(value)) {
                    context.addFact("environment-gate", "manifest-condition", rangeForNode(node), {
                        value: "conditional-activation",
                        tags: ["json", "gate", "environment"],
                    });
                }
                if (/(?:platform|os|arch|windows|linux|darwin|mac)/u.test(value)) {
                    context.addFact("platform-gate", "manifest-condition", rangeForNode(node), {
                        value: "conditional-activation",
                        tags: ["json", "gate", "platform"],
                    });
                }
                if (/(?:time|date|cron|schedule)/u.test(value)) {
                    context.addFact("time-gate", "manifest-condition", rangeForNode(node), {
                        value: "conditional-activation",
                        tags: ["json", "gate", "time"],
                    });
                }
            }
        }
    });
}

export function scanJsonSource({
    path,
    text,
    maxFacts,
    maxTokens,
    scannerId = "scanner.json-jsonc",
    language = "json-jsonc",
} = {}) {
    const context = createScannerContext({
        path,
        text,
        scannerId,
        language,
        maxFacts,
        maxTokens,
    });
    const tokenization = tokenizeSource(context.text, {
        dialect: "jsonc",
        maxTokens: context.maxTokens,
    });
    const structuralTokens = tokenization.tokens.filter((token) => token.type !== "newline");
    const tree = parseJsonTokens(structuralTokens);
    scanTree(context, tree);
    return context.finish({
        tokenCount: tokenization.tokens.length,
        tokensTruncated: tokenization.truncated,
        propagationTruncated: tree.truncated,
        blockers: tree.root ? []: ["decode/incomplete"],
    });
}

export const __internals = Object.freeze({
    parseJsonTokens,
    walk,
    scanTree,
    scalarValue,
    rangeFromTokens,
});
