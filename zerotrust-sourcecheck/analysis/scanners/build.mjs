import {
    commandTarget,
    createScannerContext,
} from "./core.mjs";

function scanCmakeCalls(text, visit, maxCalls = 50_000) {
    let index = 0;
    let count = 0;
    let truncated = false;
    while (index < text.length) {
        if (count >= maxCalls) {
            truncated = true;
            break;
        }
        if (text[index] === "#") {
            while (index < text.length && !/[\r\n]/u.test(text[index])) index += 1;
            continue;
        }
        if (!/[A-Za-z_]/u.test(text[index])) {
            index += 1;
            continue;
        }
        const start = index;
        index += 1;
        while (index < text.length && /[A-Za-z0-9_]/u.test(text[index])) index += 1;
        const name = text.slice(start, index);
        let cursor = index;
        while (cursor < text.length && /\s/u.test(text[cursor])) cursor += 1;
        if (text[cursor] !== "(") {
            index = cursor;
            continue;
        }
        let depth = 0;
        let quote = null;
        let end = cursor;
        for (; end < text.length; end += 1) {
            const character = text[end];
            if (quote && character === "\\") {
                end += 1;
                continue;
            }
            if (["\"", "'"].includes(character)) {
                quote = quote === character ? null: quote || character;
                continue;
            }
            if (quote) continue;
            if (character === "#") {
                while (end < text.length && !/[\r\n]/u.test(text[end])) end += 1;
                continue;
            }
            if (character === "(") depth += 1;
            if (character === ")") depth -= 1;
            if (depth === 0) {
                end += 1;
                break;
            }
        }
        count += 1;
        visit({
            name,
            argument: text.slice(cursor + 1, Math.max(cursor + 1, end - 1)),
            start,
            argumentStart: cursor + 1,
            end,
        });
        index = Math.max(end, cursor + 1);
    }
    return { count, truncated };
}

function cmakeArguments(value) {
    const tokens = [];
    const pattern = /"((?:\\.|[^"])*)"|'((?:\\.|[^'])*)'|([^\s]+)/gu;
    for (const match of String(value || "").matchAll(pattern)) {
        tokens.push(match[1] ?? match[2] ?? match[3]);
    }
    return tokens;
}

function dynamicBuildValue(value) {
    return /\$\{|\$\(|\$ENV\{/u.test(String(value || ""));
}

function addCmakeCommand(context, call, tokens) {
    const commandIndex = tokens.findIndex((token) => token.toUpperCase() === "COMMAND");
    const rawTarget = commandIndex >= 0 ? tokens[commandIndex + 1]: tokens[0];
    const target = commandTarget(rawTarget);
    const range = { startOffset: call.start, endOffset: call.end };
    context.addFact("command-construction", "cmake-command", range, {
        target,
        resolution: !target || dynamicBuildValue(rawTarget) ? "dynamic": "literal",
        tags: ["cmake", "process-execution"],
    });
    context.addFact("sink", "process-execution", range, {
        target,
        tags: ["cmake", "process-execution"],
    });
    if (!target || dynamicBuildValue(rawTarget)) {
        context.addFact("unresolved-dynamic-target", "cmake-command", range, {
            value: "command-construction",
            resolution: "dynamic",
            tags: ["cmake", "dynamic-target"],
        });
    }
}

function scanCmakeCall(context, call) {
    const name = call.name.toLowerCase();
    const tokens = cmakeArguments(call.argument);
    const range = { startOffset: call.start, endOffset: call.end };
    if (["add_custom_command", "add_custom_target", "execute_process"].includes(name)) {
        context.addFact("activation", "cmake-build-hook", range, {
            value: name,
            tags: ["cmake", "build-hook"],
        });
        addCmakeCommand(context, call, tokens);
    }
    if (["include", "add_subdirectory", "find_package"].includes(name)) {
        const target = tokens[0];
        context.addFact("import", "cmake-include", range, {
            target,
            resolution: dynamicBuildValue(target) ? "dynamic": "literal",
            tags: ["cmake", "import"],
        });
        if (!target || dynamicBuildValue(target)) {
            context.addFact("unresolved-dynamic-target", "cmake-include", range, {
                value: "import",
                resolution: "dynamic",
                tags: ["cmake", "dynamic-target"],
            });
        }
    }
    if (/^(?:fetchcontent|externalproject)_/u.test(name)
        || ["file", "configure_file"].includes(name)
        && /(?:download|read)/iu.test(call.argument)) {
        context.addFact("source", "cmake-external-or-file-source", range, {
            tags: ["cmake", "source"],
        });
    }
    if (name === "file" && /(?:write|append|generate|configure)/iu.test(call.argument)) {
        context.addFact("sink", "cmake-file-effect", range, {
            tags: ["cmake", "effect"],
        });
        context.addFact("generated-code-hook", "cmake-generated-file", range, {
            tags: ["cmake", "generated-code"],
        });
    }
    if (["configure_file", "file", "string"].includes(name)
        && /(?:configure|generate|regex|replace|base64|hash)/iu.test(call.argument)) {
        context.addFact("transform", "cmake-transform", range, {
            tags: ["cmake", "transform"],
        });
    }
    if (name === "install") {
        context.addFact("activation", "cmake-install-hook", range, {
            tags: ["cmake", "install-activation"],
        });
    }
    if (["if", "elseif", "while"].includes(name)) {
        const lower = call.argument.toLowerCase();
        if (/(?:defined\s+env|\$env\{|environment)/u.test(lower)) {
            context.addFact("environment-gate", "cmake-condition", range, {
                value: "conditional-activation",
                tags: ["cmake", "gate", "environment"],
            });
        }
        if (/(?:win32|unix|apple|cmake_system_name|cmake_host_system)/u.test(lower)) {
            context.addFact("platform-gate", "cmake-condition", range, {
                value: "conditional-activation",
                tags: ["cmake", "gate", "platform"],
            });
        }
        if (/(?:timestamp|date|time|epoch)/u.test(lower)) {
            context.addFact("time-gate", "cmake-condition", range, {
                value: "conditional-activation",
                tags: ["cmake", "gate", "time"],
            });
        }
    }
}

export function scanCmakeSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    const context = createScannerContext({
        path,
        text,
        scannerId: "scanner.cmake-make",
        language: "cmake",
        maxFacts,
        maxTokens,
    });
    const scanned = scanCmakeCalls(
        context.text,
        (call) => scanCmakeCall(context, call),
        context.maxTokens,
    );
    return context.finish({
        tokenCount: scanned.count,
        tokensTruncated: scanned.truncated,
    });
}

function makeLines(text, maxLines = 100_000) {
    const rawLines = text.split(/\r?\n/u);
    const lines = [];
    let offset = 0;
    for (let index = 0; index < Math.min(rawLines.length, maxLines); index += 1) {
        const raw = rawLines[index];
        const parts = [raw];
        const start = offset;
        let end = offset + raw.length;
        while (/\\\s*$/u.test(parts[parts.length - 1]) && index + 1 < rawLines.length) {
            offset += rawLines[index].length
                + (text.slice(offset + rawLines[index].length,
                    offset + rawLines[index].length + 2) === "\r\n" ? 2: 1);
            index += 1;
            parts.push(rawLines[index]);
            end = offset + rawLines[index].length;
        }
        lines.push({ raw: parts.join("\n"), start, end });
        offset = end + (text.slice(end, end + 2) === "\r\n" ? 2: 1);
    }
    return { lines, truncated: rawLines.length > maxLines };
}

function resolveMakeValue(value, bindings, maxExpansions = 32) {
    let result = String(value || "").trim();
    let expansions = 0;
    result = result.replace(/\$\(([^]+)\)|\$\{([^{}]+)\}/gu, (match, first, second) => {
        if (expansions >= maxExpansions) return match;
        expansions += 1;
        const key = String(first || second).trim();
        return bindings.has(key) ? bindings.get(key): match;
    });
    return {
        value: result,
        dynamic: /\$\(|\$\{/u.test(result),
        truncated: expansions >= maxExpansions,
    };
}

function addMakeRecipe(context, line, value, bindings) {
    const resolved = resolveMakeValue(value, bindings);
    const target = commandTarget(resolved.value.replace(/^[@+-]+/u, ""));
    const range = { startOffset: line.start, endOffset: line.end };
    context.addFact("command-construction", "make-recipe", range, {
        target,
        resolution: resolved.dynamic || !target ? "dynamic": "propagated",
        tags: ["make", "recipe"],
    });
    context.addFact("sink", "process-execution", range, {
        target,
        tags: ["make", "process-execution"],
    });
    if (resolved.dynamic || !target) {
        context.addFact("unresolved-dynamic-target", "make-recipe", range, {
            value: "command-construction",
            resolution: "dynamic",
            tags: ["make", "dynamic-target"],
        });
    }
    if (/(?:generate|codegen|compile|build|emit)/iu.test(resolved.value)) {
        context.addFact("generated-code-hook", "make-generated-code", range, {
            target,
            tags: ["make", "generated-code"],
        });
    }
    if (/(?:curl|wget|git\s+clone|pip\s+install|npm\s+install)/iu.test(resolved.value)) {
        context.addFact("source", "make-external-source", range, {
            tags: ["make", "network-source"],
        });
    }
    if (/(?:base64|gunzip|inflate|decrypt|openssl)/iu.test(resolved.value)) {
        context.addFact("transform", "make-transform", range, {
            tags: ["make", "transform"],
        });
    }
    return resolved.truncated;
}

export function scanMakeSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    const context = createScannerContext({
        path,
        text,
        scannerId: "scanner.cmake-make",
        language: "make",
        maxFacts,
        maxTokens,
    });
    const parsed = makeLines(context.text);
    const bindings = new Map();
    let propagationTruncated = false;
    for (const line of parsed.lines.slice(0, context.maxTokens)) {
        if (!line.raw.trim() || line.raw.trimStart().startsWith("#")) continue;
        const assignment = line.raw.match(/^\s*([A-Za-z0-9_.-]+)\s*(?::|\?|!)?=\s*(.*)$/u);
        if (assignment && bindings.size < 512) {
            const resolved = resolveMakeValue(assignment[2], bindings);
            if (!resolved.dynamic) bindings.set(assignment[1], resolved.value);
            propagationTruncated ||= resolved.truncated;
            if (/\$\(\s*shell\b/iu.test(assignment[2])) {
                const range = { startOffset: line.start, endOffset: line.end };
                context.addFact("dynamic-evaluation", "make-shell-expansion", range, {
                    tags: ["make", "dynamic-code"],
                });
                context.addFact("command-construction", "make-shell-expansion", range, {
                    resolution: "dynamic",
                    tags: ["make", "process-execution"],
                });
                context.addFact("unresolved-dynamic-target", "make-shell-expansion", range, {
                    value: "command-construction",
                    resolution: "dynamic",
                    tags: ["make", "dynamic-target"],
                });
            }
            continue;
        }
        const include = line.raw.match(/^\s*-?include\s+(.+)$/u);
        if (include) {
            const resolved = resolveMakeValue(include[1], bindings);
            context.addFact(resolved.dynamic ? "dynamic-import": "import", "make-include", {
                startOffset: line.start,
                endOffset: line.end,
            }, {
                target: resolved.value,
                resolution: resolved.dynamic ? "dynamic": "propagated",
                tags: ["make", "import"],
            });
            if (resolved.dynamic) {
                context.addFact("unresolved-dynamic-target", "make-include", {
                    startOffset: line.start,
                    endOffset: line.end,
                }, {
                    value: "dynamic-import",
                    resolution: "dynamic",
                    tags: ["make", "dynamic-target"],
                });
            }
            continue;
        }
        const target = line.raw.match(/^([^:=\s][^:=]*?)\s*:(?![=])\s*(.*)$/u);
        if (target) {
            const targetName = target[1].trim();
            context.addFact("activation", "make-target", {
                startOffset: line.start,
                endOffset: line.end,
            }, {
                value: targetName,
                tags: ["make", "build-target"],
            });
            if (/(?:generate|codegen|compile|build|install)/iu.test(targetName)) {
                context.addFact("generated-code-hook", "make-target-hook", {
                    startOffset: line.start,
                    endOffset: line.end,
                }, {
                    value: targetName,
                    tags: ["make", "generated-code"],
                });
            }
            continue;
        }
        if (/^\t/u.test(line.raw)) {
            propagationTruncated ||= addMakeRecipe(
                context,
                line,
                line.raw.slice(1),
                bindings,
            );
            continue;
        }
        if (/^\s*(?:ifeq|ifneq|ifdef|ifndef)\b/iu.test(line.raw)) {
            const lower = line.raw.toLowerCase();
            const range = { startOffset: line.start, endOffset: line.end };
            if (/(?:env|environment|secret)/u.test(lower)) {
                context.addFact("environment-gate", "make-condition", range, {
                    value: "conditional-activation",
                    tags: ["make", "gate", "environment"],
                });
            }
            if (/(?:os|arch|windows|linux|darwin|uname)/u.test(lower)) {
                context.addFact("platform-gate", "make-condition", range, {
                    value: "conditional-activation",
                    tags: ["make", "gate", "platform"],
                });
            }
            if (/(?:date|time|epoch)/u.test(lower)) {
                context.addFact("time-gate", "make-condition", range, {
                    value: "conditional-activation",
                    tags: ["make", "gate", "time"],
                });
            }
        }
    }
    return context.finish({
        tokenCount: parsed.lines.length,
        tokensTruncated: parsed.truncated || parsed.lines.length > context.maxTokens,
        propagationTruncated,
    });
}

export const __internals = Object.freeze({
    scanCmakeCalls,
    cmakeArguments,
    scanCmakeCall,
    makeLines,
    resolveMakeValue,
    addMakeRecipe,
});
