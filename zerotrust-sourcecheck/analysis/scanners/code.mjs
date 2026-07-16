import {
    addCallPatternFacts,
    addQualifiedReferenceFacts,
    collectLiteralBindings,
    createScannerContext,
    evaluateLiteralExpression,
    findCallSites,
    findMatchingToken,
    matchesQualifiedName,
    rangeFromTokens,
    resolveCallTarget,
    splitStatements,
    tokenizeSource,
} from "./core.mjs";

function tokenValue(token) {
    return String(token?.value || "").toLowerCase();
}

export function conditionRange(tokens, index) {
    let startIndex = index;
    let endIndex = index;
    const next = tokens[index + 1];
    if (next?.value === "(") {
        const close = findMatchingToken(tokens, index + 1, "(", ")");
        endIndex = close >= 0 ? close: index + 1;
    } else {
        for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
            if (tokens[cursor].type === "newline"
                || [":", "{", ";"].includes(tokens[cursor].value)) {
                break;
            }
            endIndex = cursor;
        }
    }
    return { startIndex, endIndex };
}

export function addConditionGateFacts(context, tokens, {
    environment = [],
    platform = [],
    time = [],
} = {}) {
    const conditions = new Set(["if", "elif", "elseif", "unless", "while", "match", "when"]);
    for (let index = 0; index < tokens.length; index += 1) {
        if (!conditions.has(tokenValue(tokens[index]))) continue;
        const range = conditionRange(tokens, index);
        const condition = tokens
            .slice(range.startIndex, range.endIndex + 1)
            .map((token) => tokenValue(token))
            .join(" ");
        const exact = rangeFromTokens(tokens, range.startIndex, range.endIndex);
        if (environment.some((pattern) => pattern.test(condition))) {
            context.addFact("environment-gate", "environment-condition", exact, {
                value: "conditional-activation",
                tags: ["gate", "environment"],
            });
        }
        if (platform.some((pattern) => pattern.test(condition))) {
            context.addFact("platform-gate", "platform-condition", exact, {
                value: "conditional-activation",
                tags: ["gate", "platform"],
            });
        }
        if (time.some((pattern) => pattern.test(condition))) {
            context.addFact("time-gate", "time-condition", exact, {
                value: "conditional-activation",
                tags: ["gate", "time"],
            });
        }
        index = range.endIndex;
    }
}

export function addStaticKeywordImports(context, tokens, {
    keywords,
    terminators = new Set([";", "\n"]),
    name = "module",
    tags = [],
} = {}) {
    const normalizedKeywords = new Set(keywords.map((entry) => entry.toLowerCase()));
    for (let index = 0; index < tokens.length; index += 1) {
        if (!normalizedKeywords.has(tokenValue(tokens[index]))) continue;
        let targetIndex = index + 1;
        if (tokenValue(tokens[targetIndex]) === "type") targetIndex += 1;
        let target = null;
        let endIndex = targetIndex;
        for (let cursor = targetIndex; cursor < tokens.length; cursor += 1) {
            const token = tokens[cursor];
            if (token.type === "newline" || terminators.has(token.value)) break;
            if (token.type === "string" && token.literal !== null) {
                target = token.literal;
                endIndex = cursor;
                break;
            }
            if (token.type === "identifier") {
                const parts = [token.value];
                endIndex = cursor;
                for (let nested = cursor + 1; nested + 1 < tokens.length; nested += 2) {
                    if (![".", "::", "/"].includes(tokens[nested].value)
                        || tokens[nested + 1].type !== "identifier") {
                        break;
                    }
                    parts.push(tokens[nested + 1].value);
                    endIndex = nested + 1;
                }
                target = parts.join(".");
                break;
            }
        }
        if (!target) continue;
        context.addFact("import", name, rangeFromTokens(tokens, index, endIndex), {
            target,
            resolution: "literal",
            tags,
        });
    }
}

export function addAssignmentCommandFacts(context, tokens, bindings, {
    commandNames = /(?:command|cmd|program|executable|shell|script|tool)/iu,
    tags = [],
} = {}) {
    for (const statement of splitStatements(tokens)) {
        const equals = statement.findIndex((token) => ["=", ":="].includes(token.value));
        if (equals < 1) continue;
        const nameToken = [...statement.slice(0, equals)].reverse()
            .find((token) => token.type === "identifier");
        if (!nameToken || !commandNames.test(nameToken.value)) continue;
        const resolved = evaluateLiteralExpression(statement.slice(equals + 1), bindings);
        if (resolved?.kind !== "string") continue;
        context.addFact(
            "command-construction",
            "command-binding",
            {
                startOffset: statement[0].start,
                endOffset: statement[statement.length - 1].end,
            },
            {
                target: resolved.value,
                resolution: resolved.resolution,
                tags: [...tags, "literal-propagation"],
            },
        );
    }
}

export function addDynamicTargetFactsForCalls(context, tokens, calls, bindings, {
    names,
    kind,
    factName,
    argumentIndex = 0,
    tags = [],
} = {}) {
    for (const call of calls) {
        const matched = names.some((name) =>
            matchesQualifiedName(call.normalizedName, name));
        if (!matched) continue;
        const resolved = resolveCallTarget(call, bindings, argumentIndex);
        const range = rangeFromTokens(tokens, call.startIndex, call.closeIndex);
        context.addFact(kind, factName || call.name, range, {
            target: resolved?.target,
            resolution: resolved?.resolution || "dynamic",
            tags,
        });
        if (!resolved) {
            context.addFact("unresolved-dynamic-target", factName || call.name, range, {
                value: kind,
                resolution: "dynamic",
                tags: [...tags, "dynamic-target"],
            });
        }
    }
}

export function scanConfiguredCode({
    path,
    text,
    scannerId,
    language,
    dialect,
    maxFacts,
    maxTokens,
    callPatterns = [],
    references = [],
    gatePatterns = {},
    scan = null,
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
        dialect,
        maxTokens: context.maxTokens,
    });
    const propagation = collectLiteralBindings(tokenization.tokens);
    const calls = findCallSites(tokenization.tokens);
    const state = Object.freeze({
        tokens: tokenization.tokens,
        calls,
        bindings: propagation.bindings,
    });
    addCallPatternFacts(
        context,
        state.tokens,
        state.calls,
        state.bindings,
        callPatterns,
    );
    addQualifiedReferenceFacts(context, state.tokens, references);
    addConditionGateFacts(context, state.tokens, gatePatterns);
    addAssignmentCommandFacts(context, state.tokens, state.bindings, {
        tags: [language],
    });
    if (typeof scan === "function") scan(context, state);
    return context.finish({
        tokenCount: state.tokens.length,
        tokensTruncated: tokenization.truncated,
        propagationTruncated: propagation.truncated,
    });
}

export const __internals = Object.freeze({
    tokenValue,
});
