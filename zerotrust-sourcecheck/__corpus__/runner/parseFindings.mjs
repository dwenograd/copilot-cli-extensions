// __corpus__/runner/parseFindings.mjs
// Converts markdown reports into normalized finding metadata. Evidence prose is
// hashed, never returned or persisted as plain text by this parser.

import { createHash } from "node:crypto";

import { deriveTags, normalizeCategory, normalizeTag } from "./tagDictionary.mjs";

export const SEVERITIES = Object.freeze(["none", "info", "low", "medium", "high", "critical"]);

const SEVERITY_RE = /\b(critical|high|medium|low|info|informational)\b/i;
const CATEGORY_RE = /\bcategory\s*[:#-]?\s*([A-G])\b/i;
const FILE_FIELD_RE = /\b(?:file|path)\s*[:=]\s*`?([^`\s,;]+)`?/i;
const LINE_RE = /\bline\s*[:#= ]\s*(\d{1,7})\b/i;
const FILE_LINE_RE = /`?([A-Za-z0-9_.@()\\/-]+\.[A-Za-z0-9_+-]{1,12})`?:(\d{1,7})\b/;
const TAGS_RE = /\btags?\s*[:=]\s*([^\r\n]+)/i;
const PATH_TOKEN_RE = /`?([A-Za-z0-9_.@()\\/-]+\.[A-Za-z0-9_+-]{1,12})`?/;

function hashEvidence(text) {
    return createHash("sha256").update(String(text).trim().replace(/\s+/g, " ")).digest("hex");
}

function normalizeSeverity(severity) {
    if (!severity) return "info";
    const s = String(severity).toLowerCase();
    return s === "informational" ? "info" : s;
}

function parseTags(block) {
    const m = TAGS_RE.exec(block);
    if (!m) return [];
    return m[1]
        .split(/[;,]/)
        .map((s) => normalizeTag(s))
        .filter(Boolean);
}

function parseFileAndLine(block) {
    const fileLine = FILE_LINE_RE.exec(block);
    if (fileLine) {
        return { file: fileLine[1], line: Number(fileLine[2]) };
    }

    const field = FILE_FIELD_RE.exec(block);
    const pathToken = field || PATH_TOKEN_RE.exec(block);
    const lineMatch = LINE_RE.exec(block);
    return {
        file: pathToken ? pathToken[1] : null,
        line: lineMatch ? Number(lineMatch[1]) : null,
    };
}

function splitFindingBlocks(markdown) {
    const text = String(markdown || "").replace(/\r\n/g, "\n");
    const blocks = [];
    let current = [];

    for (const line of text.split("\n")) {
        const startsFinding = /^(#{2,6}\s+|[-*]\s+)/.test(line) && CATEGORY_RE.test(line);
        if (startsFinding && current.length > 0) {
            blocks.push(current.join("\n"));
            current = [line];
        } else if (startsFinding) {
            current = [line];
        } else if (current.length > 0) {
            current.push(line);
        }
    }

    if (current.length > 0) blocks.push(current.join("\n"));
    if (blocks.length > 0) return blocks;

    return text
        .split(/\n\s*\n+/)
        .filter((block) => CATEGORY_RE.test(block));
}

export function parseFindings(markdown, { source = "REPORT.md" } = {}) {
    const text = String(markdown || "");
    if (/\bno\s+red\s+flags\s+found\b/i.test(text) && !CATEGORY_RE.test(text)) {
        return [];
    }

    const findings = [];
    for (const block of splitFindingBlocks(text)) {
        const category = normalizeCategory(CATEGORY_RE.exec(block)?.[1]);
        if (!category) continue;

        const severity = normalizeSeverity(SEVERITY_RE.exec(block)?.[1]);
        const { file, line } = parseFileAndLine(block);
        const explicitTags = parseTags(block);
        const tags = deriveTags({ category, text: block, extraTags: explicitTags });

        findings.push({
            severity,
            category,
            file,
            line,
            tags,
            evidenceHash: hashEvidence(block),
            source,
        });
    }

    return findings;
}

export const __internals = {
    CATEGORY_RE,
    SEVERITY_RE,
    hashEvidence,
    normalizeSeverity,
    parseFileAndLine,
    splitFindingBlocks,
};
