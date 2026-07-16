import {
    commandTarget,
    evaluateLiteralExpression,
    rangeFromTokens,
    splitStatements,
} from "./core.mjs";
import { scanConfiguredCode } from "./code.mjs";

const PROCESS_COMMANDS = new Set([
    "start-process",
    "invoke-command",
    "powershell",
    "pwsh",
    "cmd",
    "cmd.exe",
    "bash",
    "sh",
    "zsh",
    "fish",
    "nohup",
    "xargs",
]);

const DYNAMIC_EVAL = new Set([
    "invoke-expression",
    "iex",
    "eval",
]);

const IMPORT_COMMANDS = new Set([
    "import-module",
    "using",
    "source",
]);

const ACTIVATION_COMMANDS = new Set([
    "trap",
    "register-objectevent",
    "register-engineevent",
    "register-wmievent",
    "register-scheduledjob",
    "set-psbreakpoint",
]);

const SOURCE_COMMANDS = new Set([
    "get-content",
    "read-host",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "curl",
    "wget",
    "cat",
]);

const TRANSFORM_COMMANDS = new Set([
    "convertfrom-json",
    "expand-archive",
    "base64",
    "openssl",
    "gzip",
    "gunzip",
]);

const SINK_COMMANDS = new Set([
    "set-content",
    "add-content",
    "out-file",
    "tee-object",
    "invoke-restmethod",
    "curl",
    "wget",
]);

const PERSISTENCE_COMMANDS = new Set([
    "register-scheduledtask",
    "new-scheduledtask",
    "schtasks",
    "crontab",
    "systemctl",
    "launchctl",
    "new-itemproperty",
    "set-itemproperty",
]);

function statementCommand(statement) {
    let index = 0;
    while (index < statement.length && ["{", "}", "(", ")"].includes(statement[index].value)) {
        index += 1;
    }
    if (statement[index]?.value === "&" || statement[index]?.value === ".") {
        return {
            name: statement[index].value,
            nameIndex: index,
            argumentIndex: index + 1,
        };
    }
    if (statement[index]?.type !== "identifier") return null;
    return {
        name: String(statement[index].value).toLowerCase(),
        nameIndex: index,
        argumentIndex: index + 1,
    };
}

function resolveStatementTarget(statement, argumentIndex, bindings) {
    const expression = statement.slice(argumentIndex);
    const resolved = evaluateLiteralExpression(expression, bindings)
        || evaluateLiteralExpression(expression.slice(0, 1), bindings);
    return resolved?.kind === "string"
        ? { target: resolved.value, resolution: resolved.resolution }: null;
}

function addCommandFact(context, statement, command, state) {
    const range = {
        startOffset: statement[command.nameIndex].start,
        endOffset: statement[statement.length - 1].end,
    };
    const resolved = resolveStatementTarget(statement, command.argumentIndex, state.bindings);
    const target = resolved ? commandTarget(resolved.target): null;
    const name = command.name;

    if (PROCESS_COMMANDS.has(name) || name === "&") {
        context.addFact("command-construction", "process-command", range, {
            target,
            resolution: resolved?.resolution || "dynamic",
            tags: ["shell", "process-execution"],
        });
        context.addFact("sink", "process-execution", range, {
            target,
            resolution: resolved?.resolution || "dynamic",
            tags: ["shell", "process-execution"],
        });
        if (!target) {
            context.addFact("unresolved-dynamic-target", "process-command", range, {
                value: "command-construction",
                resolution: "dynamic",
                tags: ["shell", "dynamic-target"],
            });
        }
    }
    if (DYNAMIC_EVAL.has(name)) {
        context.addFact("dynamic-evaluation", "dynamic-code-evaluation", range, {
            target: resolved?.target,
            resolution: resolved?.resolution || "dynamic",
            tags: ["shell", "dynamic-code"],
        });
        if (!resolved) {
            context.addFact("unresolved-dynamic-target", "dynamic-code-evaluation", range, {
                value: "dynamic-evaluation",
                resolution: "dynamic",
                tags: ["shell", "dynamic-target"],
            });
        }
    }
    if (IMPORT_COMMANDS.has(name) || name === ".") {
        context.addFact(name === "." ? "dynamic-import": "import", "module-or-script", range, {
            target: resolved?.target,
            resolution: resolved?.resolution || "dynamic",
            tags: ["shell", "module-load"],
        });
        if (!resolved) {
            context.addFact("unresolved-dynamic-target", "module-or-script", range, {
                value: "dynamic-import",
                resolution: "dynamic",
                tags: ["shell", "dynamic-target"],
            });
        }
    }
    if (ACTIVATION_COMMANDS.has(name)) {
        context.addFact("activation", "event-or-job-registration", range, {
            target: resolved?.target,
            tags: ["shell", "activation"],
        });
    }
    if (SOURCE_COMMANDS.has(name)) {
        context.addFact("source", "file-network-or-input", range, {
            target: resolved?.target,
            tags: ["shell", "source"],
        });
    }
    if (TRANSFORM_COMMANDS.has(name)) {
        context.addFact("transform", "decode-or-transform", range, {
            tags: ["shell", "transform"],
        });
    }
    if (SINK_COMMANDS.has(name)) {
        context.addFact("sink", "write-or-send", range, {
            target: resolved?.target,
            tags: ["shell", "effect"],
        });
    }
    if (PERSISTENCE_COMMANDS.has(name)) {
        context.addFact("persistence", "persistence-registration", range, {
            target: resolved?.target,
            tags: ["shell", "persistence"],
        });
    }
}

function scanStatements(context, state) {
    for (const statement of splitStatements(state.tokens)) {
        const command = statementCommand(statement);
        if (command) addCommandFact(context, statement, command, state);
    }
}

function scanReferences(context, state) {
    const { tokens } = state;
    for (let index = 0; index < tokens.length; index += 1) {
        const value = String(tokens[index].value || "").toLowerCase();
        if (value === "$env" && tokens[index + 1]?.value === ":"
            && tokens[index + 2]?.type === "identifier") {
            context.addFact("source", "environment-variable", rangeFromTokens(
                tokens,
                index,
                index + 2,
            ), {
                value: tokens[index + 2].value,
                tags: ["shell", "environment-source"],
            });
        }
        if (["$iswindows", "$islinux", "$ismacos", "$psversiontable"].includes(value)
            || ["ostype", "uname"].includes(value)) {
            context.addFact("platform-gate", "platform-reference", rangeFromTokens(
                tokens,
                index,
                index,
            ), {
                tags: ["shell", "platform"],
            });
        }
        if (["get-date", "date", "sleep", "start-sleep"].includes(value)) {
            context.addFact("time-gate", "time-reference", rangeFromTokens(
                tokens,
                index,
                index,
            ), {
                tags: ["shell", "time"],
            });
        }
        if (value === "frombase64string") {
            context.addFact("transform", "base64-decode", rangeFromTokens(
                tokens,
                index,
                index,
            ), {
                tags: ["powershell", "transform"],
            });
        }
    }
}

export function scanShellSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    const isPowerShell = /\.(?:ps1|psm1|psd1)$/iu.test(String(path || ""));
    return scanConfiguredCode({
        path,
        text,
        scannerId: "scanner.powershell-shell",
        language: isPowerShell ? "powershell": "shell",
        dialect: isPowerShell ? "powershell": "shell",
        maxFacts,
        maxTokens,
        gatePatterns: {
            environment: [/\$env\b/u, /\benv\b/u],
            platform: [/\$is(?:windows|linux|macos)\b/u, /\bostype\b/u, /\buname\b/u],
            time: [/\bget-date\b/u, /\bdate\b/u, /\bsleep\b/u],
        },
        scan(context, state) {
            scanStatements(context, state);
            scanReferences(context, state);
        },
    });
}

export const __internals = Object.freeze({
    statementCommand,
    resolveStatementTarget,
    scanStatements,
    scanReferences,
});
