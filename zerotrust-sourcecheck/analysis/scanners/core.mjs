import { createHash } from "node:crypto";
import nodePath from "node:path";

export const SCANNER_SCHEMA_REVISION = 6;

export const SEMANTIC_FACT_KINDS = Object.freeze([
    "activation",
    "import",
    "dynamic-import",
    "reflection",
    "dynamic-evaluation",
    "command-construction",
    "source",
    "transform",
    "sink",
    "persistence",
    "generated-code-hook",
    "environment-gate",
    "platform-gate",
    "time-gate",
    "unresolved-dynamic-target",
]);

export const SEMANTIC_RESOLUTIONS = Object.freeze([
    "literal",
    "propagated",
    "lookup",
    "dynamic",
]);

export const SCANNER_BLOCKER_CODES = Object.freeze([
    "bounds/exceeded",
    "decode/incomplete",
    "decode/parser-differential",
    "semantic/incomplete",
    "semantic/truncated",
    "scan/dynamic-behavior-unresolved",
    "scan/external-payload-unresolved",
]);

export const SCANNER_LIMITS = Object.freeze({
    sourceBytes: 2_000_000,
    sourceCharacters: 1_000_000,
    tokens: 100_000,
    factsPerFile: 1_024,
    factName: 128,
    factValue: 256,
    path: 1_024,
    tagsPerFact: 12,
    tag: 64,
    propagationBindings: 512,
    propagationPasses: 4,
    expressionTokens: 256,
    collectionEntries: 128,
    nestingDepth: 32,
});

const IDENTIFIER_RE = /^[A-Za-z_$][A-Za-z0-9_$-]*$/u;
const SAFE_NAME_RE = /[^A-Za-z0-9_$@./:+-]+/gu;
const OPAQUE_TOKEN_RE = /\b[A-Za-z0-9+/=_-]{48,}\b/gu;

function clampInteger(value, fallback, min, max) {
    return Number.isSafeInteger(value) ? Math.max(min, Math.min(value, max)): fallback;
}

export function normalizeScannerPath(path) {
    const normalized = String(path || "")
        .replace(/\\/g, "/")
        .replace(/^\.\/+/, "")
        .slice(0, SCANNER_LIMITS.path);
    if (!normalized || normalized.startsWith("/") || normalized.endsWith("/")
        || normalized.includes("//")
        || normalized.split("/").some((segment) => segment === "." || segment === "..")
        || /[\u0000-\u001f\u007f]/u.test(normalized)) {
        throw new TypeError("scanner path must be a normalized relative path");
    }
    return normalized;
}

export function normalizeFactName(value) {
    return String(value || "")
        .normalize("NFKC")
        .replace(SAFE_NAME_RE, "-")
        .replace(/-{2,}/gu, "-")
        .replace(/^-+|-+$/gu, "")
        .slice(0, SCANNER_LIMITS.factName);
}

export function normalizeFactValue(value) {
    if (value === null || value === undefined) return null;
    let normalized = String(value)
        .normalize("NFKC")
        .replace(/[\u0000-\u001f\u007f]+/gu, " ")
        .replace(/\s+/gu, " ")
        .trim();
    normalized = normalized.replace(
        /\bhttps?:\/\/([^/\s?#]+)(?:[^\s]*)/giu,
        (_match, host) => `https://${String(host).toLowerCase()}/`,
    );
    normalized = normalized.replace(OPAQUE_TOKEN_RE, "[opaque]");
    return normalized.slice(0, SCANNER_LIMITS.factValue) || null;
}

function normalizeTag(value) {
    const normalized = String(value || "")
        .normalize("NFKC")
        .toLowerCase()
        .replace(/[^a-z0-9._:/@-]+/gu, "-")
        .replace(/-{2,}/gu, "-")
        .replace(/^-+|-+$/gu, "")
        .slice(0, SCANNER_LIMITS.tag);
    return /^[a-z0-9][a-z0-9._:/@-]{0,63}$/u.test(normalized) ? normalized: null;
}

export function sha256Text(value) {
    return createHash("sha256").update(String(value), "utf8").digest("hex");
}

export function buildLineStarts(text) {
    const starts = [0];
    for (let index = 0; index < text.length; index += 1) {
        if (text.charCodeAt(index) === 10) starts.push(index + 1);
    }
    return starts;
}

export function positionAt(lineStarts, offset) {
    let low = 0;
    let high = lineStarts.length - 1;
    while (low <= high) {
        const middle = Math.floor((low + high) / 2);
        if (lineStarts[middle] <= offset) {
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }
    const lineIndex = Math.max(0, high);
    return {
        line: lineIndex + 1,
        column: offset - lineStarts[lineIndex] + 1,
    };
}

export function rangeFromOffsets(context, startOffset, endOffset) {
    const start = Math.max(0, Math.min(Number(startOffset) || 0, context.text.length));
    const end = Math.max(start, Math.min(Number(endOffset) || start, context.text.length));
    const startPosition = positionAt(context.lineStarts, start);
    const endPosition = positionAt(context.lineStarts, end);
    return Object.freeze({
        startOffset: start,
        endOffset: end,
        line: startPosition.line,
        startColumn: startPosition.column,
        endLine: endPosition.line,
        endColumn: endPosition.column,
    });
}

export function rangeFromTokens(tokens, startIndex, endIndex = startIndex) {
    const start = tokens[startIndex];
    const end = tokens[endIndex];
    if (!start || !end) return null;
    return { startOffset: start.start, endOffset: end.end };
}

function computeSemanticFactId(fact) {
    return createHash("sha256")
        .update([
            fact.schemaVersion,
            fact.kind,
            fact.path,
            fact.scannerId,
            fact.language,
            fact.startOffset,
            fact.endOffset,
            fact.name,
            fact.value || "",
            fact.target || "",
            fact.resolution || "",
        ].join("\0"), "utf8")
        .digest("hex");
}

export function validateSemanticFact(value, path = "semanticFact") {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError(`${path} must be an object`);
    }
    const allowed = new Set([
        "schemaVersion",
        "id",
        "kind",
        "path",
        "scannerId",
        "language",
        "startOffset",
        "endOffset",
        "line",
        "startColumn",
        "endLine",
        "endColumn",
        "excerptHash",
        "name",
        "value",
        "target",
        "resolution",
        "tags",
    ]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) throw new TypeError(`${path}.${key} is not allowed`);
    }
    if (value.schemaVersion !== SCANNER_SCHEMA_REVISION) {
        throw new TypeError(`${path}.schemaVersion must equal ${SCANNER_SCHEMA_REVISION}`);
    }
    if (!SEMANTIC_FACT_KINDS.includes(value.kind)) {
        throw new TypeError(`${path}.kind is invalid`);
    }
    const normalized = {
        schemaVersion: SCANNER_SCHEMA_REVISION,
        id: String(value.id || "").toLowerCase(),
        kind: value.kind,
        path: normalizeScannerPath(value.path),
        scannerId: normalizeFactName(value.scannerId),
        language: normalizeFactName(value.language),
        startOffset: Number(value.startOffset),
        endOffset: Number(value.endOffset),
        line: Number(value.line),
        startColumn: Number(value.startColumn),
        endLine: Number(value.endLine),
        endColumn: Number(value.endColumn),
        excerptHash: String(value.excerptHash || "").toLowerCase(),
        name: normalizeFactName(value.name),
    };
    if (!normalized.scannerId || !normalized.language || !normalized.name) {
        throw new TypeError(`${path} scannerId, language, and name are required`);
    }
    if (!Number.isSafeInteger(normalized.startOffset) || normalized.startOffset < 0
        || !Number.isSafeInteger(normalized.endOffset)
        || normalized.endOffset <= normalized.startOffset
        || !Number.isSafeInteger(normalized.line) || normalized.line < 1
        || !Number.isSafeInteger(normalized.endLine) || normalized.endLine < normalized.line
        || !Number.isSafeInteger(normalized.startColumn) || normalized.startColumn < 1
        || !Number.isSafeInteger(normalized.endColumn) || normalized.endColumn < 1) {
        throw new TypeError(`${path} has an invalid source range`);
    }
    if (!/^[a-f0-9]{64}$/u.test(normalized.excerptHash)
        || !/^[a-f0-9]{64}$/u.test(normalized.id)) {
        throw new TypeError(`${path} hashes are invalid`);
    }
    for (const field of ["value", "target", "resolution"]) {
        if (Object.hasOwn(value, field)) {
            const entry = normalizeFactValue(value[field]);
            if (!entry || entry !== value[field]) {
                throw new TypeError(`${path}.${field} must be normalized`);
            }
            normalized[field] = entry;
        }
    }
    if (normalized.resolution && !SEMANTIC_RESOLUTIONS.includes(normalized.resolution)) {
        throw new TypeError(`${path}.resolution is invalid`);
    }
    if (Object.hasOwn(value, "tags")) {
        if (!Array.isArray(value.tags) || value.tags.length > SCANNER_LIMITS.tagsPerFact) {
            throw new TypeError(`${path}.tags is invalid`);
        }
        normalized.tags = Object.freeze(value.tags.map((tag) => {
            const entry = normalizeTag(tag);
            if (!entry || entry !== tag) throw new TypeError(`${path}.tags is not normalized`);
            return entry;
        }));
    }
    if (normalized.id !== computeSemanticFactId(normalized)) {
        throw new TypeError(`${path}.id is not canonical`);
    }
    return Object.freeze(normalized);
}

export function createScannerContext({
    path,
    text,
    scannerId,
    language,
    maxFacts = SCANNER_LIMITS.factsPerFile,
    maxTokens = SCANNER_LIMITS.tokens,
} = {}) {
    if (typeof text !== "string") throw new TypeError("scanner text must be a string");
    const normalizedPath = normalizeScannerPath(path);
    const normalizedScannerId = normalizeFactName(scannerId);
    const normalizedLanguage = normalizeFactName(language);
    if (!normalizedScannerId || !normalizedLanguage) {
        throw new TypeError("scannerId and language are required");
    }
    const factLimit = clampInteger(
        maxFacts,
        SCANNER_LIMITS.factsPerFile,
        1,
        SCANNER_LIMITS.factsPerFile,
    );
    const tokenLimit = clampInteger(
        maxTokens,
        SCANNER_LIMITS.tokens,
        1,
        SCANNER_LIMITS.tokens,
    );
    const byteLength = Buffer.byteLength(text, "utf8");
    const sourceBoundExceeded = byteLength > SCANNER_LIMITS.sourceBytes
        || text.length > SCANNER_LIMITS.sourceCharacters;
    const boundedText = sourceBoundExceeded
        ? text.slice(0, SCANNER_LIMITS.sourceCharacters): text;
    const lineStarts = buildLineStarts(boundedText);
    const facts = [];
    const factIds = new Set();
    let factsTruncated = false;

    const context = {
        schemaVersion: SCANNER_SCHEMA_REVISION,
        path: normalizedPath,
        text: boundedText,
        byteLength,
        scannerId: normalizedScannerId,
        language: normalizedLanguage,
        lineStarts,
        maxFacts: factLimit,
        maxTokens: tokenLimit,
        sourceBoundExceeded,
        addFact(kind, name, range, options = {}) {
            if (!SEMANTIC_FACT_KINDS.includes(kind)) return null;
            const normalizedName = normalizeFactName(name || kind);
            if (!normalizedName || !range) return null;
            const exactRange = rangeFromOffsets(
                context,
                range.startOffset,
                range.endOffset,
            );
            if (exactRange.endOffset <= exactRange.startOffset) return null;
            const fact = {
                schemaVersion: SCANNER_SCHEMA_REVISION,
                kind,
                path: normalizedPath,
                scannerId: normalizedScannerId,
                language: normalizedLanguage,
                ...exactRange,
                excerptHash: sha256Text(
                    boundedText.slice(exactRange.startOffset, exactRange.endOffset),
                ),
                name: normalizedName,
            };
            for (const field of ["value", "target", "resolution"]) {
                const normalized = normalizeFactValue(options[field]);
                if (normalized) fact[field] = normalized;
            }
            const tags = [...new Set((options.tags || []).map(normalizeTag).filter(Boolean))]
                .sort()
                .slice(0, SCANNER_LIMITS.tagsPerFact);
            if (tags.length > 0) fact.tags = tags;
            fact.id = computeSemanticFactId(fact);
            if (factIds.has(fact.id)) return facts.find((entry) => entry.id === fact.id) || null;
            if (facts.length >= factLimit) {
                factsTruncated = true;
                return null;
            }
            const validated = validateSemanticFact(fact);
            factIds.add(validated.id);
            facts.push(validated);
            return validated;
        },
        finish({
            tokenCount = 0,
            tokensTruncated = false,
            propagationTruncated = false,
            blockers = [],
        } = {}) {
            const normalizedBlockers = [...new Set([
                ...(sourceBoundExceeded || tokensTruncated || factsTruncated
                    || propagationTruncated ? ["bounds/exceeded"]: []),
                ...(tokensTruncated || factsTruncated || propagationTruncated
                    ? ["semantic/truncated"]: []),
                ...(facts.some((fact) => fact.kind === "unresolved-dynamic-target")
                    ? ["scan/dynamic-behavior-unresolved"]: []),
                ...blockers.map((entry) => normalizeFactValue(entry)).filter(Boolean),
            ])].slice(0, 32);
            const truncated = sourceBoundExceeded
                || tokensTruncated
                || factsTruncated
                || propagationTruncated;
            return Object.freeze({
                schemaVersion: SCANNER_SCHEMA_REVISION,
                scannerId: normalizedScannerId,
                language: normalizedLanguage,
                path: normalizedPath,
                sourceSha256: sha256Text(text),
                byteLength,
                lineCount: lineStarts.length,
                tokenCount,
                facts: Object.freeze([...facts]),
                factCount: facts.length,
                truncated,
                blockers: Object.freeze(normalizedBlockers),
            });
        },
    };
    return context;
}

function decodeEscape(character, next) {
    if (character !== "\\") return null;
    return {
        n: "\n",
        r: "\r",
        t: "\t",
        b: "\b",
        f: "\f",
        v: "\v",
        0: "\0",
        "\\": "\\",
        "\"": "\"",
        "'": "'",
        "`": "`",
    }[next] ?? next;
}

function decodeStringRaw(raw, quoteLength = 1) {
    const body = raw.slice(quoteLength, raw.length - quoteLength);
    let value = "";
    for (let index = 0; index < body.length; index += 1) {
        if (body[index] === "\\" && index + 1 < body.length) {
            value += decodeEscape("\\", body[index + 1]);
            index += 1;
        } else {
            value += body[index];
        }
        if (value.length >= SCANNER_LIMITS.factValue * 4) break;
    }
    return value;
}

function isIdentifierStart(character) {
    return /[A-Za-z_$]/u.test(character || "");
}

function isIdentifierPart(character) {
    return /[A-Za-z0-9_$-]/u.test(character || "");
}

function skipQuoted(text, start, quote, triple, verbatim) {
    const quoteLength = triple ? 3: 1;
    let index = start + quoteLength;
    while (index < text.length) {
        if (triple && text.startsWith(quote.repeat(3), index)) return index + 3;
        if (!triple && text[index] === quote) {
            if (verbatim && text[index + 1] === quote) {
                index += 2;
                continue;
            }
            return index + 1;
        }
        if (!verbatim && text[index] === "\\") {
            index += 2;
        } else {
            index += 1;
        }
    }
    return text.length;
}

export function tokenizeSource(text, {
    dialect = "generic",
    maxTokens = SCANNER_LIMITS.tokens,
} = {}) {
    const limit = clampInteger(maxTokens, SCANNER_LIMITS.tokens, 1, SCANNER_LIMITS.tokens);
    const tokens = [];
    let index = 0;
    let truncated = false;

    const add = (type, start, end, value = text.slice(start, end), extra = {}) => {
        if (tokens.length >= limit) {
            truncated = true;
            return false;
        }
        tokens.push(Object.freeze({ type, value, start, end, ...extra }));
        return true;
    };

    while (index < text.length && !truncated) {
        const start = index;
        const character = text[index];
        if (character === "\r" || character === "\n") {
            if (character === "\r" && text[index + 1] === "\n") index += 1;
            index += 1;
            add("newline", start, index, "\n");
            continue;
        }
        if (/\s/u.test(character)) {
            index += 1;
            while (index < text.length && /[^\S\r\n]/u.test(text[index])) index += 1;
            continue;
        }
        const hashComments = ["python", "shell", "powershell", "yaml"].includes(dialect);
        if (hashComments && character === "#") {
            while (index < text.length && !/[\r\n]/u.test(text[index])) index += 1;
            continue;
        }
        if (["javascript", "jsonc", "csharp", "rust", "generic"].includes(dialect)
            && text.startsWith("//", index)) {
            while (index < text.length && !/[\r\n]/u.test(text[index])) index += 1;
            continue;
        }
        if (["javascript", "jsonc", "csharp", "rust", "generic"].includes(dialect)
            && text.startsWith("/*", index)) {
            const close = text.indexOf("*/", index + 2);
            index = close >= 0 ? close + 2: text.length;
            continue;
        }
        if (dialect === "powershell" && text.startsWith("<#", index)) {
            const close = text.indexOf("#>", index + 2);
            index = close >= 0 ? close + 2: text.length;
            continue;
        }

        let prefix = "";
        let quoteStart = index;
        let quote = character;
        let verbatim = false;
        if (dialect === "python") {
            const prefixMatch = text.slice(index).match(/^(?:r|u|b|f|br|rb|fr|rf){1,2}(?=["'])/iu);
            if (prefixMatch) {
                prefix = prefixMatch[0];
                quoteStart += prefix.length;
                quote = text[quoteStart];
            }
        } else if (dialect === "csharp") {
            const prefixMatch = text.slice(index).match(/^(?:\$@|@\$|\$|@)(?=")/u);
            if (prefixMatch) {
                prefix = prefixMatch[0];
                quoteStart += prefix.length;
                quote = "\"";
                verbatim = prefix.includes("@");
            }
        }
        if (["\"", "'", "`"].includes(quote)) {
            const triple = dialect === "python"
                && text.startsWith(quote.repeat(3), quoteStart);
            const quoteLength = triple ? 3: 1;
            const end = skipQuoted(text, quoteStart, quote, triple, verbatim);
            index = end;
            const raw = text.slice(start, end);
            const interpolation = (quote === "`" && raw.includes("${"))
                || (dialect === "python" && prefix.toLowerCase().includes("f"))
                || (dialect === "csharp" && prefix.includes("$"))
                || (["shell", "powershell"].includes(dialect)
                    && quote === "\"" && /\$(?:\{|[A-Za-z_])/u.test(raw));
            const literal = interpolation
                ? null: decodeStringRaw(text.slice(quoteStart, end), quoteLength);
            add("string", start, end, literal ?? raw, {
                literal,
                dynamic: interpolation,
                quote,
                prefix,
            });
            continue;
        }

        if (isIdentifierStart(character)) {
            index += 1;
            while (index < text.length && isIdentifierPart(text[index])) index += 1;
            add("identifier", start, index);
            continue;
        }
        if (/[0-9]/u.test(character)) {
            index += 1;
            while (index < text.length && /[A-Za-z0-9_.]/u.test(text[index])) index += 1;
            add("number", start, index);
            continue;
        }
        const pair = text.slice(index, index + 2);
        const triple = text.slice(index, index + 3);
        if (["===", "!==", "=>", "??=", "**="].includes(triple)) {
            index += 3;
            add("punctuation", start, index);
            continue;
        }
        if ([
            "::", "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--",
            "+=", "-=", "*=", "/=", ":=", "-join",
        ].includes(pair)) {
            index += 2;
            add("punctuation", start, index);
            continue;
        }
        index += 1;
        add("punctuation", start, index);
    }

    return Object.freeze({
        tokens: Object.freeze(tokens),
        truncated,
    });
}

function stripOuter(tokens) {
    let current = tokens.filter((token) => token.type !== "newline");
    let changed = true;
    while (changed && current.length >= 2) {
        changed = false;
        const pairs = new Map([["(", ")"]]);
        const closing = pairs.get(current[0].value);
        if (closing && current[current.length - 1].value === closing) {
            const match = findMatchingToken(current, 0, current[0].value, closing);
            if (match === current.length - 1) {
                current = current.slice(1, -1);
                changed = true;
            }
        }
    }
    return current;
}

export function findMatchingToken(tokens, startIndex, open = "(", close = ")") {
    let depth = 0;
    for (let index = startIndex; index < tokens.length; index += 1) {
        if (tokens[index].value === open) depth += 1;
        if (tokens[index].value === close) depth -= 1;
        if (depth === 0) return index;
        if (depth > SCANNER_LIMITS.nestingDepth) return -1;
    }
    return -1;
}

export function splitTopLevel(tokens, separators = new Set([","])) {
    const parts = [];
    let start = 0;
    let depth = 0;
    for (let index = 0; index < tokens.length; index += 1) {
        const value = tokens[index].value;
        if (["(", "[", "{"].includes(value)) depth += 1;
        if ([")", "]", "}"].includes(value)) depth -= 1;
        if (depth === 0 && separators.has(value)) {
            parts.push(tokens.slice(start, index));
            start = index + 1;
        }
    }
    parts.push(tokens.slice(start));
    return parts;
}

function cloneLiteral(value, resolution = "propagated") {
    if (!value) return null;
    if (value.kind === "string") {
        return { kind: "string", value: value.value, resolution };
    }
    if (value.kind === "array") {
        return {
            kind: "array",
            value: value.value.map((entry) => cloneLiteral(entry, resolution)),
            resolution,
        };
    }
    if (value.kind === "map") {
        return {
            kind: "map",
            value: new Map([...value.value].map(([key, entry]) => [
                key,
                cloneLiteral(entry, resolution),
            ])),
            resolution,
        };
    }
    return null;
}

function interpolateString(token, env) {
    if (!token.dynamic) return token.literal === null ? null: {
        kind: "string",
        value: token.literal,
        resolution: "literal",
    };
    let raw = String(token.value || "");
    const quoteIndex = raw.search(/["'`]/u);
    if (quoteIndex >= 0) raw = raw.slice(quoteIndex + 1, -1);
    let unresolved = false;
    raw = raw.replace(/\$\{?([A-Za-z_$][A-Za-z0-9_$-]*)\}?/gu, (_match, name) => {
        const resolved = env.get(name) || env.get(`$${name}`);
        if (resolved?.kind === "string") return resolved.value;
        unresolved = true;
        return "";
    });
    raw = raw.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/gu, (_match, name) => {
        const resolved = env.get(name);
        if (resolved?.kind === "string") return resolved.value;
        unresolved = true;
        return "";
    });
    return unresolved ? null: { kind: "string", value: raw, resolution: "propagated" };
}

function evaluateCollection(tokens, env, open, close) {
    if (tokens[0]?.value !== open || tokens[tokens.length - 1]?.value !== close) return null;
    const entries = splitTopLevel(tokens.slice(1, -1));
    if (entries.length > SCANNER_LIMITS.collectionEntries) return null;
    const isMap = open === "{";
    if (isMap) {
        const map = new Map();
        for (const entry of entries) {
            if (entry.length === 0) continue;
            const pair = splitTopLevel(entry, new Set([":", "=>"]));
            if (pair.length !== 2) return null;
            const key = pair[0].length === 1 && pair[0][0].type === "identifier"
                ? {
                    kind: "string",
                    value: pair[0][0].value,
                    resolution: "literal",
                }: evaluateLiteralExpression(pair[0], env);
            const value = evaluateLiteralExpression(pair[1], env);
            if (key?.kind !== "string" || !value) return null;
            map.set(key.value, value);
        }
        return { kind: "map", value: map, resolution: "literal" };
    }
    const values = [];
    for (const entry of entries) {
        if (entry.length === 0) continue;
        const value = evaluateLiteralExpression(entry, env);
        if (!value) return null;
        values.push(value);
    }
    return { kind: "array", value: values, resolution: "literal" };
}

function findTopLevelOperator(tokens, operators) {
    let depth = 0;
    for (let index = 0; index < tokens.length; index += 1) {
        const value = tokens[index].value;
        if (["(", "[", "{"].includes(value)) depth += 1;
        if ([")", "]", "}"].includes(value)) depth -= 1;
        if (depth === 0 && operators.has(value)) return index;
    }
    return -1;
}

function trailingLookup(tokens) {
    let depth = 0;
    for (let index = 0; index < tokens.length; index += 1) {
        const value = tokens[index].value;
        if (value === "[" && depth === 0 && index > 0) {
            const closeIndex = findMatchingToken(tokens, index, "[", "]");
            if (closeIndex === tokens.length - 1) {
                return { base: tokens.slice(0, index), key: tokens.slice(index + 1, closeIndex) };
            }
        }
        if (["(", "[", "{"].includes(value)) depth += 1;
        if ([")", "]", "}"].includes(value)) depth -= 1;
    }
    return null;
}

function trailingJoin(tokens) {
    let depth = 0;
    for (let index = 0; index + 3 < tokens.length; index += 1) {
        const value = tokens[index].value;
        if (index > 0
            && depth === 0
            && value === "."
            && String(tokens[index + 1]?.value || "").toLowerCase() === "join"
            && tokens[index + 2]?.value === "(") {
            const closeIndex = findMatchingToken(tokens, index + 2, "(", ")");
            if (closeIndex === tokens.length - 1) {
                return {
                    base: tokens.slice(0, index),
                    separator: tokens.slice(index + 3, closeIndex),
                };
            }
        }
        if (["(", "[", "{"].includes(value)) depth += 1;
        if ([")", "]", "}"].includes(value)) depth -= 1;
    }
    return null;
}

function joinLiteralArray(base, separatorTokens, env) {
    if (base?.kind !== "array"
        || !base.value.every((entry) => entry?.kind === "string")) {
        return null;
    }
    const separator = separatorTokens.length === 0
        ? { kind: "string", value: ",", resolution: "literal" }: evaluateLiteralExpression(separatorTokens, env);
    if (separator?.kind !== "string") return null;
    return {
        kind: "string",
        value: base.value.map((entry) => entry.value).join(separator.value),
        resolution: "propagated",
    };
}

export function evaluateLiteralExpression(rawTokens, env = new Map()) {
    const boundedTokens = rawTokens.filter((token) => token.type !== "newline");
    if (boundedTokens.length > SCANNER_LIMITS.expressionTokens) return null;
    let tokens = stripOuter(boundedTokens);
    if (tokens.length === 0) return null;
    if (tokens[0]?.value === "@" && tokens[1]?.value === "("
        && tokens[tokens.length - 1]?.value === ")") {
        tokens = tokens.slice(2, -1);
    }
    if (tokens.length === 1) {
        const token = tokens[0];
        if (token.type === "string") return interpolateString(token, env);
        if (token.type === "number") {
            return { kind: "string", value: token.value, resolution: "literal" };
        }
        if (token.type === "identifier") {
            return cloneLiteral(env.get(token.value), "propagated");
        }
    }

    const array = evaluateCollection(tokens, env, "[", "]");
    if (array) return array;
    const map = evaluateCollection(tokens, env, "{", "}");
    if (map) return map;
    const commaParts = splitTopLevel(tokens);
    if (commaParts.length > 1) {
        if (commaParts.length > SCANNER_LIMITS.collectionEntries) return null;
        const values = commaParts.map((entry) => evaluateLiteralExpression(entry, env));
        if (values.every(Boolean)) {
            return { kind: "array", value: values, resolution: "literal" };
        }
    }

    for (const operator of ["+", "."]) {
        const operatorIndex = findTopLevelOperator(tokens, new Set([operator]));
        if (operatorIndex > 0 && operatorIndex < tokens.length - 1) {
            const left = evaluateLiteralExpression(tokens.slice(0, operatorIndex), env);
            const right = evaluateLiteralExpression(tokens.slice(operatorIndex + 1), env);
            if (left?.kind === "string" && right?.kind === "string") {
                return {
                    kind: "string",
                    value: `${left.value}${right.value}`,
                    resolution: "propagated",
                };
            }
            if (left?.kind === "array" && right?.kind === "array") {
                if (left.value.length + right.value.length
                    > SCANNER_LIMITS.collectionEntries) {
                    return null;
                }
                return {
                    kind: "array",
                    value: [...left.value, ...right.value],
                    resolution: "propagated",
                };
            }
        }
    }

    const lookup = trailingLookup(tokens);
    if (lookup) {
        const base = evaluateLiteralExpression(lookup.base, env);
        const key = evaluateLiteralExpression(lookup.key, env);
        if (base?.kind === "array" && key?.kind === "string" && /^\d+$/u.test(key.value)) {
            const index = Number(key.value);
            if (Number.isSafeInteger(index) && index < base.value.length) {
                return cloneLiteral(base.value[index], "lookup");
            }
        }
        if (base?.kind === "map" && key?.kind === "string") {
            return cloneLiteral(base.value.get(key.value), "lookup");
        }
    }

    const join = trailingJoin(tokens);
    if (join) {
        const resolved = joinLiteralArray(
            evaluateLiteralExpression(join.base, env),
            join.separator,
            env,
        );
        if (resolved) return resolved;
    }

    if (tokens.length >= 6
        && tokens[0].type === "string"
        && tokens[1].value === "."
        && tokens[2].value.toLowerCase() === "join"
        && tokens[3].value === "("
        && tokens[tokens.length - 1].value === ")") {
        const separator = interpolateString(tokens[0], env);
        const base = tokens[4]?.type === "identifier" ? env.get(tokens[4].value): null;
        if (separator?.kind === "string" && base?.kind === "array"
            && base.value.every((entry) => entry?.kind === "string")) {
            return {
                kind: "string",
                value: base.value.map((entry) => entry.value).join(separator.value),
                resolution: "propagated",
            };
        }
    }

    const powerShellJoinName = tokens[0]?.value === "-"
        && String(tokens[1]?.value || "").toLowerCase() === "join"
        ? tokens[2]?.value: tokens[0]?.value === "-join"
            ? tokens[1]?.value: null;
    if (powerShellJoinName) {
        const base = env.get(powerShellJoinName);
        if (base?.kind === "array" && base.value.every((entry) => entry?.kind === "string")) {
            return {
                kind: "string",
                value: base.value.map((entry) => entry.value).join(""),
                resolution: "propagated",
            };
        }
    }

    if (tokens[0]?.value === "concat" && tokens[1]?.value === "!"
        && tokens[2]?.value === "(" && tokens[tokens.length - 1]?.value === ")") {
        const entries = splitTopLevel(tokens.slice(3, -1));
        if (entries.length > SCANNER_LIMITS.collectionEntries) return null;
        const values = entries.map((entry) => evaluateLiteralExpression(entry, env));
        if (values.every((entry) => entry?.kind === "string")) {
            return {
                kind: "string",
                value: values.map((entry) => entry.value).join(""),
                resolution: "propagated",
            };
        }
    }

    return null;
}

export function splitStatements(tokens) {
    const statements = [];
    let start = 0;
    let depth = 0;
    for (let index = 0; index < tokens.length; index += 1) {
        const value = tokens[index].value;
        if (["(", "["].includes(value)) depth += 1;
        if ([")", "]"].includes(value)) depth -= 1;
        if (depth === 0 && (value === ";" || tokens[index].type === "newline")) {
            if (index > start) statements.push(tokens.slice(start, index));
            start = index + 1;
        }
    }
    if (start < tokens.length) statements.push(tokens.slice(start));
    return statements.filter((statement) => statement.length > 0);
}

function assignmentParts(statement) {
    let depth = 0;
    for (let index = 0; index < statement.length; index += 1) {
        const value = statement[index].value;
        if (["(", "[", "{"].includes(value)) depth += 1;
        if ([")", "]", "}"].includes(value)) depth -= 1;
        if (depth === 0 && ["=", ":="].includes(value)) {
            const left = statement.slice(0, index);
            const right = statement.slice(index + 1);
            const nameToken = [...left].reverse().find((token) =>
                token.type === "identifier" && IDENTIFIER_RE.test(token.value));
            return nameToken && right.length > 0 ? { name: nameToken.value, right }: null;
        }
    }
    return null;
}

export function collectLiteralBindings(tokens, {
    maxBindings = SCANNER_LIMITS.propagationBindings,
    maxPasses = SCANNER_LIMITS.propagationPasses,
} = {}) {
    const bindingLimit = clampInteger(
        maxBindings,
        SCANNER_LIMITS.propagationBindings,
        1,
        SCANNER_LIMITS.propagationBindings,
    );
    const passes = clampInteger(
        maxPasses,
        SCANNER_LIMITS.propagationPasses,
        1,
        SCANNER_LIMITS.propagationPasses,
    );
    const statements = splitStatements(tokens);
    const env = new Map();
    let truncated = false;
    for (let pass = 0; pass < passes; pass += 1) {
        let changed = false;
        for (const statement of statements) {
            const assignment = assignmentParts(statement);
            if (!assignment) continue;
            const value = evaluateLiteralExpression(assignment.right, env);
            if (!value) continue;
            if (!env.has(assignment.name) && env.size >= bindingLimit) {
                truncated = true;
                continue;
            }
            const before = env.get(assignment.name);
            if (JSON.stringify(before, (_key, entry) =>
                entry instanceof Map ? [...entry]: entry) !== JSON.stringify(
                value,
                (_key, entry) => entry instanceof Map ? [...entry]: entry,
            )) {
                env.set(assignment.name, value);
                changed = true;
            }
        }
        if (!changed) break;
    }
    return Object.freeze({ bindings: env, truncated });
}

export function qualifiedNameAt(tokens, index) {
    if (tokens[index]?.type !== "identifier") return null;
    const parts = [tokens[index].value];
    let cursor = index + 1;
    while (cursor + 1 < tokens.length
        && [".", "::", "?."].includes(tokens[cursor].value)
        && tokens[cursor + 1].type === "identifier") {
        parts.push(tokens[cursor + 1].value);
        cursor += 2;
    }
    return {
        name: parts.join(tokens[index + 1]?.value === "::" ? "::": "."),
        startIndex: index,
        endIndex: cursor - 1,
        nextIndex: cursor,
    };
}

export function findCallSites(tokens) {
    const calls = [];
    for (let index = 0; index < tokens.length; index += 1) {
        const qualified = qualifiedNameAt(tokens, index);
        if (!qualified || tokens[qualified.nextIndex]?.value !== "(") continue;
        const closeIndex = findMatchingToken(tokens, qualified.nextIndex, "(", ")");
        const boundedClose = closeIndex >= 0 ? closeIndex: qualified.nextIndex;
        const argumentsTokens = closeIndex >= 0
            ? splitTopLevel(tokens.slice(qualified.nextIndex + 1, closeIndex)): [];
        calls.push(Object.freeze({
            name: qualified.name,
            normalizedName: qualified.name.toLowerCase(),
            startIndex: index,
            nameEndIndex: qualified.endIndex,
            openIndex: qualified.nextIndex,
            closeIndex: boundedClose,
            arguments: Object.freeze(argumentsTokens),
        }));
        index = qualified.endIndex;
    }
    return Object.freeze(calls);
}

export function resolveCallTarget(call, bindings, argumentIndex = 0) {
    const expression = call.arguments[argumentIndex] || [];
    const resolved = evaluateLiteralExpression(expression, bindings);
    if (resolved?.kind !== "string") return null;
    const target = normalizeFactValue(resolved.value);
    return target ? { target, resolution: resolved.resolution || "propagated" }: null;
}

export function commandTarget(value) {
    const normalized = normalizeFactValue(value);
    if (!normalized) return null;
    const unquoted = normalized.replace(/^["'`]+|["'`]+$/gu, "");
    const first = unquoted.split(/\s+/u)[0] || "";
    if (!/^[A-Za-z0-9_.@/\\:+-]{1,256}$/u.test(first)) return null;
    return nodePath.posix.basename(first.replace(/\\/g, "/")).toLowerCase();
}

export function matchesQualifiedName(actual, expected) {
    if (typeof expected !== "string") return expected.test(actual);
    const normalized = expected.toLowerCase();
    return actual === normalized
        || (!normalized.includes(".") && !normalized.includes("::")
            && (actual.endsWith(`.${normalized}`) || actual.endsWith(`::${normalized}`)));
}

export function addCallPatternFacts(context, tokens, calls, bindings, patterns) {
    for (const call of calls) {
        const matchedPatterns = patterns.filter((entry) =>
            entry.names.some((name) => matchesQualifiedName(call.normalizedName, name)));
        for (const pattern of matchedPatterns) {
            const range = rangeFromTokens(tokens, call.startIndex, call.closeIndex);
            const resolved = resolveCallTarget(call, bindings, pattern.argumentIndex || 0);
            const target = resolved && pattern.commandTarget
                ? commandTarget(resolved.target): resolved?.target;
            context.addFact(pattern.kind, pattern.name || call.name, range, {
                value: pattern.value,
                target,
                resolution: resolved?.resolution,
                tags: pattern.tags,
            });
            if (pattern.dynamicTarget && !target) {
                context.addFact(
                    "unresolved-dynamic-target",
                    pattern.unresolvedName || call.name,
                    range,
                    {
                        value: pattern.kind,
                        resolution: "dynamic",
                        tags: [...(pattern.tags || []), "dynamic-target"],
                    },
                );
            }
        }
    }
}

export function addQualifiedReferenceFacts(context, tokens, references) {
    for (let index = 0; index < tokens.length; index += 1) {
        const qualified = qualifiedNameAt(tokens, index);
        if (!qualified) continue;
        const normalized = qualified.name.toLowerCase();
        const reference = references.find((entry) =>
            entry.names.some((name) => matchesQualifiedName(normalized, name)));
        if (!reference) continue;
        context.addFact(
            reference.kind,
            reference.name || qualified.name,
            rangeFromTokens(tokens, index, qualified.endIndex),
            {
                value: reference.value,
                tags: reference.tags,
            },
        );
        index = qualified.endIndex;
    }
}

export const __internals = Object.freeze({
    computeSemanticFactId,
    normalizeTag,
    decodeStringRaw,
    interpolateString,
    assignmentParts,
    stripOuter,
    matchesQualifiedName,
});
