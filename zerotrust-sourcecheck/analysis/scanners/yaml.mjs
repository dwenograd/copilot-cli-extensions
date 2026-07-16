import {
    commandTarget,
    createScannerContext,
} from "./core.mjs";

const WORKFLOW_TRIGGERS = new Set([
    "branch_protection_rule",
    "check_run",
    "check_suite",
    "create",
    "delete",
    "deployment",
    "deployment_status",
    "discussion",
    "discussion_comment",
    "fork",
    "gollum",
    "issue_comment",
    "issues",
    "label",
    "merge_group",
    "milestone",
    "page_build",
    "project",
    "project_card",
    "project_column",
    "public",
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
    "pull_request_target",
    "push",
    "registry_package",
    "release",
    "repository_dispatch",
    "schedule",
    "status",
    "watch",
    "workflow_call",
    "workflow_dispatch",
    "workflow_run",
]);

function yamlLines(text, maxLines = 100_000) {
    const rawLines = text.split(/\r?\n/u);
    const lines = [];
    let offset = 0;
    for (let index = 0; index < Math.min(rawLines.length, maxLines); index += 1) {
        const raw = rawLines[index];
        lines.push({
            raw,
            start: offset,
            end: offset + raw.length,
            line: index + 1,
            indent: raw.match(/^\s*/u)?.[0].length || 0,
        });
        offset += raw.length + (text.slice(offset + raw.length, offset + raw.length + 2) === "\r\n"
            ? 2: 1);
    }
    return { lines, truncated: rawLines.length > maxLines };
}

function stripYamlComment(line) {
    let quote = null;
    for (let index = 0; index < line.length; index += 1) {
        const character = line[index];
        if (quote && character === "\\") {
            index += 1;
            continue;
        }
        if (["\"", "'"].includes(character)) {
            quote = quote === character ? null: quote || character;
            continue;
        }
        if (!quote && character === "#"
            && (index === 0 || /\s/u.test(line[index - 1]))) {
            return line.slice(0, index);
        }
    }
    return line;
}

function unquoteYaml(value) {
    const trimmed = String(value || "").trim();
    if ((trimmed.startsWith("\"") && trimmed.endsWith("\""))
        || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
        return trimmed.slice(1, -1);
    }
    return trimmed;
}

function parseYamlEntries(text) {
    const parsed = yamlLines(text);
    const entries = [];
    const stack = [];
    for (let index = 0; index < parsed.lines.length; index += 1) {
        const line = parsed.lines[index];
        const content = stripYamlComment(line.raw);
        if (!content.trim()) continue;
        const match = content.match(/^(\s*)(?:-\s*)?([A-Za-z0-9_.${}<>-]+)\s*:\s*(.*?)\s*$/u);
        if (!match) continue;
        const indent = match[1].length;
        while (stack.length > 0 && stack[stack.length - 1].indent >= indent) stack.pop();
        const key = match[2];
        const value = unquoteYaml(match[3]);
        const keyIndex = content.indexOf(key);
        const valueIndex = match[3]
            ? content.lastIndexOf(match[3]): content.length;
        const entry = {
            key,
            value,
            path: [...stack.map((item) => item.key), key],
            indent,
            start: line.start + keyIndex,
            keyEnd: line.start + keyIndex + key.length,
            valueStart: line.start + Math.max(0, valueIndex),
            end: line.end,
            lineIndex: index,
            block: null,
        };
        if (["|", ">", "|-", ">-", "|+", ">+"].includes(value)) {
            let blockEnd = line.end;
            let blockStart = null;
            const blockLines = [];
            for (let cursor = index + 1; cursor < parsed.lines.length; cursor += 1) {
                const nested = parsed.lines[cursor];
                if (nested.raw.trim() && nested.indent <= indent) break;
                if (blockStart === null && nested.raw.trim()) {
                    blockStart = nested.start + nested.indent;
                }
                if (nested.raw.trim()) blockLines.push(nested.raw.trim());
                blockEnd = nested.end;
            }
            entry.block = {
                value: blockLines.join(value.startsWith(">") ? " ": "\n"),
                start: blockStart ?? entry.valueStart,
                end: blockEnd,
            };
            entry.end = blockEnd;
        }
        entries.push(entry);
        if (!value || ["|", ">", "|-", ">-", "|+", ">+"].includes(value)) {
            stack.push({ key, indent });
        }
    }
    return { ...parsed, entries };
}

function entryRange(entry, valueOnly = false) {
    if (valueOnly && entry.block) {
        return { startOffset: entry.block.start, endOffset: entry.block.end };
    }
    if (valueOnly && entry.value) {
        return { startOffset: entry.valueStart, endOffset: entry.end };
    }
    return { startOffset: entry.start, endOffset: entry.end };
}

function addYamlCommand(context, entry) {
    const value = entry.block?.value || entry.value;
    if (!value) return;
    const target = commandTarget(value);
    const dynamic = /\$\{\{|\$\(|\$\{|%\w+%/u.test(value);
    const range = entryRange(entry, true);
    context.addFact("command-construction", "workflow-command", range, {
        target,
        resolution: dynamic || !target ? "dynamic": "literal",
        tags: ["yaml", "command"],
    });
    context.addFact("sink", "process-execution", range, {
        target,
        tags: ["yaml", "process-execution"],
    });
    if (dynamic || !target) {
        context.addFact("unresolved-dynamic-target", "workflow-command", range, {
            value: "command-construction",
            resolution: "dynamic",
            tags: ["yaml", "dynamic-target"],
        });
    }
    if (/(?:generate|codegen|compile|transpile|build|emit)/iu.test(value)) {
        context.addFact("generated-code-hook", "workflow-generated-code", range, {
            target,
            tags: ["yaml", "generated-code"],
        });
    }
    if (/(?:schtasks|register-scheduledtask|crontab|systemctl\s+enable|launchctl\s+load|runonce)/iu
        .test(value)) {
        context.addFact("persistence", "workflow-persistence-command", range, {
            target,
            tags: ["yaml", "persistence"],
        });
    }
    if (/(?:curl|wget|invoke-webrequest|requests?\s)/iu.test(value)) {
        context.addFact("source", "workflow-network-source", range, {
            tags: ["yaml", "network-source"],
        });
    }
    if (/(?:base64|fromjson|gunzip|inflate|decrypt|openssl)/iu.test(value)) {
        context.addFact("transform", "workflow-transform", range, {
            tags: ["yaml", "transform"],
        });
    }
}

function scanYamlEntry(context, entry, isWorkflow) {
    const key = entry.key.toLowerCase();
    const path = entry.path.map((part) => String(part).toLowerCase());
    const parent = path[path.length - 2] || "";
    const value = entry.block?.value || entry.value;

    if (isWorkflow && (parent === "on" || (path.length === 1 && key === "on"))
        && (WORKFLOW_TRIGGERS.has(key) || key === "on")) {
        context.addFact("activation", "github-actions-trigger", entryRange(entry), {
            value: key,
            tags: ["yaml", "github-actions", "trigger"],
        });
        if (key === "schedule") {
            context.addFact("time-gate", "scheduled-trigger", entryRange(entry), {
                value: "schedule",
                tags: ["yaml", "github-actions", "time"],
            });
        }
    }
    if (isWorkflow && WORKFLOW_TRIGGERS.has(key) && path.includes("on")) {
        context.addFact("activation", "github-actions-trigger", entryRange(entry), {
            value: key,
            tags: ["yaml", "github-actions", "trigger"],
        });
        if (key === "schedule") {
            context.addFact("time-gate", "scheduled-trigger", entryRange(entry), {
                value: "schedule",
                tags: ["yaml", "github-actions", "time"],
            });
        }
    }
    if (["run", "command", "entrypoint"].includes(key)) {
        context.addFact("activation", "workflow-step", entryRange(entry), {
            value: key,
            tags: ["yaml", isWorkflow ? "github-actions": "yaml", "activation"],
        });
        addYamlCommand(context, entry);
    }
    if (key === "uses" && value) {
        const dynamic = /\$\{\{/u.test(value);
        context.addFact(dynamic ? "dynamic-import": "import", "workflow-action", entryRange(
            entry,
            true,
        ), {
            target: value,
            resolution: dynamic ? "dynamic": "literal",
            tags: ["yaml", "github-actions", "action-reference"],
        });
        if (dynamic) {
            context.addFact("unresolved-dynamic-target", "workflow-action", entryRange(
                entry,
                true,
            ), {
                value: "dynamic-import",
                resolution: "dynamic",
                tags: ["yaml", "dynamic-target"],
            });
        }
    }
    if (key === "if" && value) {
        const lower = value.toLowerCase();
        if (/(?:env\.|secrets\.|vars\.)/u.test(lower)) {
            context.addFact("environment-gate", "workflow-condition", entryRange(entry, true), {
                value: "conditional-activation",
                tags: ["yaml", "gate", "environment"],
            });
        }
        if (/(?:runner\.os|matrix\.os|matrix\.arch|windows|linux|macos)/u.test(lower)) {
            context.addFact("platform-gate", "workflow-condition", entryRange(entry, true), {
                value: "conditional-activation",
                tags: ["yaml", "gate", "platform"],
            });
        }
        if (/(?:time|date|schedule|cron)/u.test(lower)) {
            context.addFact("time-gate", "workflow-condition", entryRange(entry, true), {
                value: "conditional-activation",
                tags: ["yaml", "gate", "time"],
            });
        }
    }
    if (key === "shell" && value) {
        context.addFact("activation", "workflow-shell", entryRange(entry, true), {
            value,
            tags: ["yaml", "shell-selection"],
        });
    }
    if (["env", "secrets", "vars"].includes(parent) || /\$\{\{\s*secrets\./iu.test(value)) {
        context.addFact("source", "workflow-secret-or-environment", entryRange(entry), {
            value: key,
            tags: ["yaml", "environment-source"],
        });
    }
    if (/(?:fromjson|base64|decode|decompress)/iu.test(value)) {
        context.addFact("transform", "workflow-expression-transform", entryRange(entry, true), {
            tags: ["yaml", "transform"],
        });
    }
}

export function scanYamlSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    const normalizedPath = String(path || "").replace(/\\/g, "/").toLowerCase();
    const isWorkflow = /^\.github\/workflows\/.+\.ya?ml$/u.test(normalizedPath)
        || /(?:^|\/)action\.ya?ml$/u.test(normalizedPath);
    const context = createScannerContext({
        path,
        text,
        scannerId: "scanner.yaml-github-actions",
        language: isWorkflow ? "github-actions-yaml": "yaml",
        maxFacts,
        maxTokens,
    });
    const parsed = parseYamlEntries(context.text);
    for (const entry of parsed.entries.slice(0, context.maxTokens)) {
        scanYamlEntry(context, entry, isWorkflow);
    }
    return context.finish({
        tokenCount: parsed.entries.length,
        tokensTruncated: parsed.truncated || parsed.entries.length > context.maxTokens,
    });
}

export const __internals = Object.freeze({
    yamlLines,
    stripYamlComment,
    parseYamlEntries,
    scanYamlEntry,
    addYamlCommand,
});
