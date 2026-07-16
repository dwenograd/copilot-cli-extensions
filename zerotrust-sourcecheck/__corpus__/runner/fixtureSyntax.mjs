const MARKER_LINE_RE =
    /^marker\.(fact|node|edge|finding|comment|blocker)\((.*)\);?$/u;
const SAFE_BYTES_RE = /^[\x09\x0a\x0d\x20-\x7e]*$/u;
const ARGUMENT_TOKEN_RE = /^[a-z0-9][a-z0-9._:/@,-]{0,127}$/u;
const ARGUMENT_FRAGMENT_RE = /^[a-z0-9._:/@,-]{1,128}$/u;

export const EXPECTED_ARGUMENTS = Object.freeze({
    fact: 3,
    node: 4,
    edge: 5,
    finding: 9,
    comment: 1,
    blocker: 2,
});

function skipWhitespace(text, cursor) {
    let next = cursor;
    while (next < text.length && /[ \t]/u.test(text[next])) next += 1;
    return next;
}

function parseQuotedFragment(text, cursor) {
    if (text[cursor] !== "\"") return null;
    const end = text.indexOf("\"", cursor + 1);
    if (end < 0) return null;
    const value = text.slice(cursor + 1, end);
    if (!ARGUMENT_FRAGMENT_RE.test(value)) return null;
    return { value, cursor: end + 1 };
}

export function parseMarkerArguments(text) {
    const args = [];
    let cursor = skipWhitespace(text, 0);
    while (cursor < text.length) {
        let parsed = parseQuotedFragment(text, cursor);
        if (!parsed) return null;
        let value = parsed.value;
        cursor = skipWhitespace(text, parsed.cursor);
        while (text[cursor] === "+") {
            cursor = skipWhitespace(text, cursor + 1);
            parsed = parseQuotedFragment(text, cursor);
            if (!parsed) return null;
            value += parsed.value;
            cursor = skipWhitespace(text, parsed.cursor);
        }
        if (!ARGUMENT_TOKEN_RE.test(value)) return null;
        args.push(value);
        if (cursor === text.length) break;
        if (text[cursor] !== ",") return null;
        cursor = skipWhitespace(text, cursor + 1);
    }
    return args;
}

export function parseMarkerLine(line, { path, lineNumber }) {
    const trimmed = line.trim();
    if (!trimmed) return null;
    const match = MARKER_LINE_RE.exec(trimmed);
    if (!match) throw new Error(`${path}:${lineNumber}: invalid inert marker syntax`);
    const args = parseMarkerArguments(match[2]);
    if (!args || args.length !== EXPECTED_ARGUMENTS[match[1]]) {
        throw new Error(`${path}:${lineNumber}: invalid inert marker arguments`);
    }
    return Object.freeze({
        kind: match[1],
        args: Object.freeze(args),
        path,
        line: lineNumber,
        raw: trimmed,
    });
}

export function validateFixtureText(text, path) {
    if (!SAFE_BYTES_RE.test(text)) {
        throw new Error(`${path}: fixture must contain printable ASCII only`);
    }
    if (/https?:|file:|data:/iu.test(text)) {
        throw new Error(`${path}: fixture must not contain URLs or payload schemes`);
    }
    const markers = [];
    for (const [index, line] of text.split(/\r?\n/u).entries()) {
        const marker = parseMarkerLine(line, { path, lineNumber: index + 1 });
        if (marker) markers.push(marker);
    }
    return markers;
}

function splitArgument(value) {
    const preferred = ["-", "_", ".", "/", ":"]
        .map((separator) => value.indexOf(separator, 2))
        .find((index) => index >= 2 && index <= value.length - 2);
    const midpoint = Math.max(1, Math.min(value.length - 1, Math.floor(value.length / 2)));
    const index = preferred ?? midpoint;
    return [value.slice(0, index), value.slice(index)];
}

export function renderMarker(kind, args, {
    splitArguments = new Set(),
    spaced = false,
    indent = "",
} = {}) {
    if (!Object.hasOwn(EXPECTED_ARGUMENTS, kind)
        || args.length !== EXPECTED_ARGUMENTS[kind]) {
        throw new TypeError(`cannot render invalid marker.${kind} declaration`);
    }
    const separator = spaced ? ", ": ",";
    const rendered = args.map((value, index) => {
        if (!splitArguments.has(index) || value.length < 2) return `"${value}"`;
        const fragments = splitArgument(value);
        return fragments.map((fragment) => `"${fragment}"`).join(spaced ? " + ": "+");
    });
    return `${indent}marker.${kind}(${rendered.join(separator)});`;
}

export const __internals = Object.freeze({
    MARKER_LINE_RE,
    SAFE_BYTES_RE,
    ARGUMENT_TOKEN_RE,
    ARGUMENT_FRAGMENT_RE,
    skipWhitespace,
    parseQuotedFragment,
    splitArgument,
});
