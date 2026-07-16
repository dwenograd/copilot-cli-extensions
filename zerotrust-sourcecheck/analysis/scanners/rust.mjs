import {
    commandTarget,
    createScannerContext,
    rangeFromTokens,
} from "./core.mjs";
import {
    addDynamicTargetFactsForCalls,
    scanConfiguredCode,
} from "./code.mjs";

const RUST_CALL_PATTERNS = Object.freeze([
    {
        names: [
            "std::process::command::new",
            "process::command::new",
            "command::new",
        ],
        kind: "command-construction",
        name: "process-command",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["rust", "process-execution"],
    },
    {
        names: [
            "std::process::command::new",
            "process::command::new",
            "command::new",
        ],
        kind: "sink",
        name: "process-execution",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["rust", "process-execution"],
    },
    {
        names: [
            "libloading::library::new",
            "library::new",
            "dlopen::raw::library::open",
        ],
        kind: "dynamic-import",
        name: "runtime-library-load",
        dynamicTarget: true,
        tags: ["rust", "dynamic-import"],
    },
    {
        names: [
            "libloading::library::get",
            "library::get",
            "std::mem::transmute",
            "core::mem::transmute",
        ],
        kind: "reflection",
        name: "dynamic-symbol-or-cast",
        dynamicTarget: true,
        tags: ["rust", "reflection"],
    },
    {
        names: [
            "std::fs::read",
            "std::fs::read_to_string",
            "reqwest::get",
            "ureq::get",
        ],
        kind: "source",
        name: "file-or-network-read",
        tags: ["rust", "source"],
    },
    {
        names: [
            "base64::decode",
            "base64::engine::general_purpose::standard::decode",
            "flate2::read::gzdecoder::new",
            "serde_json::from_str",
            "bincode::deserialize",
        ],
        kind: "transform",
        name: "decode-or-transform",
        tags: ["rust", "transform"],
    },
    {
        names: [
            "std::fs::write",
            "reqwest::blocking::client::post",
            "std::net::tcpstream::write",
        ],
        kind: "sink",
        name: "write-or-send",
        tags: ["rust", "effect"],
    },
    {
        names: ["std::fs::write", "std::process::command::new"],
        kind: "generated-code-hook",
        name: "build-generated-output",
        tags: ["rust", "generated-code"],
    },
]);

const RUST_REFERENCES = Object.freeze([
    {
        names: ["std::env::var", "std::env::vars", "std::env::args"],
        kind: "source",
        name: "environment-or-process-input",
        tags: ["rust", "environment-source"],
    },
    {
        names: ["std::env::consts::os", "std::env::consts::arch"],
        kind: "platform-gate",
        name: "platform-reference",
        tags: ["rust", "platform"],
    },
    {
        names: ["std::time::systemtime::now", "std::time::instant::now"],
        kind: "time-gate",
        name: "time-reference",
        tags: ["rust", "time"],
    },
]);

function rustImports(context, { tokens }) {
    for (let index = 0; index < tokens.length; index += 1) {
        const keyword = String(tokens[index].value || "").toLowerCase();
        if (keyword !== "use"
            && !(keyword === "extern"
                && String(tokens[index + 1]?.value || "").toLowerCase() === "crate")) {
            continue;
        }
        const startIndex = index;
        let cursor = keyword === "extern" ? index + 2: index + 1;
        const parts = [];
        let endIndex = cursor;
        while (cursor < tokens.length) {
            const token = tokens[cursor];
            if (token.type === "newline" || token.value === ";"
                || ["{", "*"].includes(token.value)) {
                break;
            }
            if (token.type === "identifier" || token.value === "::") {
                parts.push(token.value);
                endIndex = cursor;
            }
            cursor += 1;
        }
        const target = parts.join("").replace(/::$/u, "");
        if (!target) continue;
        context.addFact("import", "crate-or-module", rangeFromTokens(
            tokens,
            startIndex,
            endIndex,
        ), {
            target,
            resolution: "literal",
            tags: ["rust", "static-import"],
        });
    }
}

function rustMacros(context, state) {
    const { tokens, bindings } = state;
    for (let index = 0; index + 2 < tokens.length; index += 1) {
        if (tokens[index].type !== "identifier"
            || tokens[index + 1].value !== "!"
            || tokens[index + 2].value !== "(") {
            continue;
        }
        const name = String(tokens[index].value).toLowerCase();
        let closeIndex = index + 2;
        let depth = 0;
        for (let cursor = index + 2; cursor < tokens.length; cursor += 1) {
            if (tokens[cursor].value === "(") depth += 1;
            if (tokens[cursor].value === ")") depth -= 1;
            if (depth === 0) {
                closeIndex = cursor;
                break;
            }
        }
        const range = rangeFromTokens(tokens, index, closeIndex);
        const argument = tokens.slice(index + 3, closeIndex);
        const literalToken = argument.find((token) => token.type === "string"
            && token.literal !== null);
        const target = literalToken?.literal
            || (argument[0]?.type === "identifier"
                ? bindings.get(argument[0].value)?.value: null);
        if (["include", "include_str", "include_bytes"].includes(name)) {
            context.addFact("generated-code-hook", "compile-time-include", range, {
                target,
                resolution: target ? "literal": "dynamic",
                tags: ["rust", "generated-code", "compile-time"],
            });
            context.addFact("dynamic-import", "compile-time-include", range, {
                target,
                resolution: target ? "literal": "dynamic",
                tags: ["rust", "compile-time-import"],
            });
            if (!target) {
                context.addFact("unresolved-dynamic-target", "compile-time-include", range, {
                    value: "dynamic-import",
                    resolution: "dynamic",
                    tags: ["rust", "dynamic-target"],
                });
            }
        }
        if (["env", "option_env"].includes(name)) {
            context.addFact("source", "compile-time-environment", range, {
                value: target,
                tags: ["rust", "environment-source", "compile-time"],
            });
            context.addFact("environment-gate", "compile-time-environment", range, {
                value: "conditional-activation",
                tags: ["rust", "gate", "environment"],
            });
        }
    }
}

function rustActivations(context, { tokens }) {
    for (let index = 0; index < tokens.length; index += 1) {
        const value = String(tokens[index].value || "").toLowerCase();
        if (value === "main" && tokens[index + 1]?.value === "(") {
            context.addFact("activation", "rust-main", rangeFromTokens(tokens, index, index), {
                value: "main",
                tags: ["rust", "entrypoint"],
            });
        }
        if (tokens[index].value === "#"
            && tokens[index + 1]?.value === "["
            && /^(?:ctor|tokio::main|async_std::main|test)$/iu
                .test(String(tokens[index + 2]?.value || ""))) {
            context.addFact("activation", "attribute-activation", rangeFromTokens(
                tokens,
                index,
                Math.min(tokens.length - 1, index + 3),
            ), {
                value: tokens[index + 2].value,
                tags: ["rust", "attribute", "activation"],
            });
        }
    }
}

export function scanRustSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    return scanConfiguredCode({
        path,
        text,
        scannerId: "scanner.rust",
        language: "rust",
        dialect: "rust",
        maxFacts,
        maxTokens,
        callPatterns: RUST_CALL_PATTERNS,
        references: RUST_REFERENCES,
        gatePatterns: {
            environment: [/\bstd:: env:: var\b/u, /\benv !\b/u, /\boption_env !\b/u],
            platform: [/\bcfg !\b/u, /\btarget_os\b/u, /\btarget_arch\b/u],
            time: [/\bsystemtime:: now\b/u, /\binstant:: now\b/u],
        },
        scan(context, state) {
            rustImports(context, state);
            rustMacros(context, state);
            rustActivations(context, state);
            addDynamicTargetFactsForCalls(
                context,
                state.tokens,
                state.calls,
                state.bindings,
                {
                    names: ["library::new", "libloading::library::new"],
                    kind: "dynamic-import",
                    factName: "runtime-library-load",
                    tags: ["rust", "dynamic-import"],
                },
            );
        },
    });
}

function tomlLines(text, maxLines = 100_000) {
    const result = [];
    let offset = 0;
    const lines = text.split(/\r?\n/u);
    for (let index = 0; index < Math.min(lines.length, maxLines); index += 1) {
        const raw = lines[index];
        result.push({ raw, start: offset, end: offset + raw.length, line: index + 1 });
        offset += raw.length + (text.slice(offset + raw.length, offset + raw.length + 2) === "\r\n"
            ? 2: 1);
    }
    return { lines: result, truncated: lines.length > maxLines };
}

function stripTomlComment(line) {
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
        if (!quote && character === "#") return line.slice(0, index);
    }
    return line;
}

export function scanCargoTomlSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    const context = createScannerContext({
        path,
        text,
        scannerId: "scanner.cargo-toml",
        language: "cargo-toml",
        maxFacts,
        maxTokens,
    });
    const parsed = tomlLines(context.text);
    let section = "";
    let tokens = 0;
    for (const line of parsed.lines) {
        const content = stripTomlComment(line.raw);
        const sectionMatch = content.match(/^\s*\[([^\]]+)\]\s*$/u);
        if (sectionMatch) {
            section = sectionMatch[1].trim().toLowerCase();
            tokens += 1;
            if (/^target\./u.test(section)) {
                context.addFact("platform-gate", "cargo-target-section", {
                    startOffset: line.start + sectionMatch.index,
                    endOffset: line.start + sectionMatch.index + sectionMatch[0].length,
                }, {
                    value: "target-conditional",
                    tags: ["cargo", "platform", "gate"],
                });
            }
            if (/(?:build-dependencies|target\..*\.dependencies)/u.test(section)) {
                context.addFact("activation", "cargo-build-dependencies", {
                    startOffset: line.start + sectionMatch.index,
                    endOffset: line.start + sectionMatch.index + sectionMatch[0].length,
                }, {
                    value: section,
                    tags: ["cargo", "build-dependency"],
                });
            }
            continue;
        }
        const assignment = content.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$/u);
        if (!assignment) continue;
        tokens += 2;
        const key = assignment[1].toLowerCase();
        const rawValue = assignment[2].trim();
        const keyStart = line.start + content.indexOf(assignment[1]);
        const valueStart = line.start + content.indexOf(assignment[2], assignment.index);
        const value = rawValue.replace(/^["']|["']$/gu, "");
        const range = {
            startOffset: keyStart,
            endOffset: valueStart + assignment[2].length,
        };
        if (key === "build" && section === "package") {
            context.addFact("activation", "cargo-build-script", range, {
                target: value,
                resolution: /\$\{|\$\(/u.test(value) ? "dynamic": "literal",
                tags: ["cargo", "build-script"],
            });
            context.addFact("generated-code-hook", "cargo-build-script", range, {
                target: value,
                tags: ["cargo", "generated-code", "build-script"],
            });
        }
        if (["runner", "linker"].includes(key) || key.endsWith("rustflags")) {
            const target = commandTarget(value);
            context.addFact("command-construction", "cargo-tool-command", range, {
                target,
                resolution: target ? "literal": "dynamic",
                tags: ["cargo", "tool-command"],
            });
            if (!target) {
                context.addFact("unresolved-dynamic-target", "cargo-tool-command", range, {
                    value: "command-construction",
                    resolution: "dynamic",
                    tags: ["cargo", "dynamic-target"],
                });
            }
        }
        if (/(?:build-dependencies|dependencies)$/u.test(section)) {
            context.addFact("import", "cargo-dependency", range, {
                target: key,
                resolution: "literal",
                tags: ["cargo", "dependency"],
            });
        }
    }
    return context.finish({
        tokenCount: tokens,
        tokensTruncated: parsed.truncated || tokens > context.maxTokens,
    });
}

export const __internals = Object.freeze({
    rustImports,
    rustMacros,
    rustActivations,
    tomlLines,
    stripTomlComment,
});
