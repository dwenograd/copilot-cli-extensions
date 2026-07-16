import {
    rangeFromTokens,
    resolveCallTarget,
} from "./core.mjs";
import {
    addDynamicTargetFactsForCalls,
    scanConfiguredCode,
} from "./code.mjs";

const COMMAND_CALLS = Object.freeze([
    {
        names: [
            "child_process.exec",
            "child_process.execsync",
            "child_process.execfile",
            "child_process.execfilesync",
            "child_process.spawn",
            "child_process.spawnsync",
            "child_process.fork",
            "exec",
            "execsync",
            "execfile",
            "spawn",
            "spawnsync",
            "execa",
            "shell.exec",
        ],
        kind: "command-construction",
        name: "process-command",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["javascript", "process-execution"],
    },
]);

const CALL_PATTERNS = Object.freeze([
    ...COMMAND_CALLS,
    {
        names: COMMAND_CALLS[0].names,
        kind: "sink",
        name: "process-execution",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["javascript", "process-execution"],
    },
    {
        names: ["eval", "function", "vm.runincontext", "vm.runinnewcontext", "vm.runinthiscontext"],
        kind: "dynamic-evaluation",
        name: "dynamic-code-evaluation",
        dynamicTarget: true,
        tags: ["javascript", "dynamic-code"],
    },
    {
        names: [
            "reflect.apply",
            "reflect.construct",
            "reflect.get",
            "proxy",
            "webassembly.compile",
            "webassembly.instantiate",
        ],
        kind: "reflection",
        name: "reflective-dispatch",
        dynamicTarget: true,
        tags: ["javascript", "reflection"],
    },
    {
        names: [
            "addeventlistener",
            "on",
            "once",
            "prependlistener",
            "registercommand",
            "registertexteditcommand",
            "settimeout",
            "setinterval",
            "queueMicrotask",
        ],
        kind: "activation",
        name: "event-or-timer-registration",
        tags: ["javascript", "activation"],
    },
    {
        names: ["fs.readfile", "fs.readfilesync", "readfile", "readfilesync"],
        kind: "source",
        name: "file-read",
        tags: ["javascript", "file-source"],
    },
    {
        names: ["fetch", "axios.get", "axios.request", "http.get", "https.get"],
        kind: "source",
        name: "network-response",
        tags: ["javascript", "network-source"],
    },
    {
        names: [
            "buffer.from",
            "atob",
            "decodeuricomponent",
            "json.parse",
            "zlib.gunzip",
            "zlib.gunzipsync",
            "zlib.inflate",
            "zlib.inflatesync",
            "crypto.createdecipheriv",
        ],
        kind: "transform",
        name: "decode-or-transform",
        tags: ["javascript", "transform"],
    },
    {
        names: [
            "fs.writefile",
            "fs.writefilesync",
            "fs.appendfile",
            "fs.appendfilesync",
            "fetch",
            "axios.post",
            "axios.put",
            "axios.patch",
            "socket.write",
            "process.stdout.write",
        ],
        kind: "sink",
        name: "write-or-send",
        tags: ["javascript", "effect"],
    },
    {
        names: [
            "registerscheduledtask",
            "createscheduledtask",
            "registry.setvalue",
            "winreg.setvalue",
        ],
        kind: "persistence",
        name: "persistence-registration",
        tags: ["javascript", "persistence"],
    },
    {
        names: [
            "eval",
            "function",
            "vm.script",
            "typescript.transpile",
            "babel.transform",
            "webpack",
        ],
        kind: "generated-code-hook",
        name: "generated-code-hook",
        tags: ["javascript", "generated-code"],
    },
]);

const REFERENCES = Object.freeze([
    {
        names: [/^process\.env(?:\.|$)/u, /^import\.meta\.env(?:\.|$)/u],
        kind: "source",
        name: "environment-variable",
        tags: ["javascript", "environment-source"],
    },
    {
        names: ["process.argv", "process.stdin"],
        kind: "source",
        name: "process-input",
        tags: ["javascript", "process-source"],
    },
    {
        names: ["process.platform", "process.arch", "navigator.platform"],
        kind: "platform-gate",
        name: "platform-reference",
        tags: ["javascript", "platform"],
    },
    {
        names: ["date.now", "performance.now"],
        kind: "time-gate",
        name: "time-reference",
        tags: ["javascript", "time"],
    },
]);

function staticImports(context, { tokens }) {
    for (let index = 0; index < tokens.length; index += 1) {
        const keyword = String(tokens[index].value || "").toLowerCase();
        if (!["import", "export"].includes(keyword)) continue;
        if (tokens[index + 1]?.value === "(") continue;
        let moduleToken = null;
        let endIndex = index;
        for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
            if (tokens[cursor].type === "newline" || tokens[cursor].value === ";") break;
            if (tokens[cursor].type === "string" && tokens[cursor].literal !== null) {
                moduleToken = tokens[cursor];
                endIndex = cursor;
            }
        }
        if (!moduleToken) continue;
        context.addFact("import", "module", rangeFromTokens(tokens, index, endIndex), {
            target: moduleToken.literal,
            resolution: "literal",
            tags: ["javascript", "static-import"],
        });
    }
}

function dynamicImports(context, state) {
    addDynamicTargetFactsForCalls(
        context,
        state.tokens,
        state.calls,
        state.bindings,
        {
            names: ["import", "require", "module.createrequire"],
            kind: "dynamic-import",
            factName: "runtime-module-load",
            tags: ["javascript", "dynamic-import"],
        },
    );
}

function activationExports(context, { tokens }) {
    for (let index = 0; index + 2 < tokens.length; index += 1) {
        const first = String(tokens[index].value || "").toLowerCase();
        const second = String(tokens[index + 1].value || "").toLowerCase();
        const third = String(tokens[index + 2].value || "").toLowerCase();
        const activateFunction = first === "function" && second === "activate";
        const exportedActivate = first === "export"
            && ["function", "async"].includes(second)
            && (third === "activate" || tokens[index + 3]?.value === "activate");
        if (!activateFunction && !exportedActivate) continue;
        const endIndex = exportedActivate && tokens[index + 3]?.value === "activate"
            ? index + 3: index + 1;
        context.addFact("activation", "extension-activate", rangeFromTokens(
            tokens,
            index,
            endIndex,
        ), {
            value: "activate",
            tags: ["javascript", "extension-activation"],
        });
    }
}

function commandAliases(context, state) {
    for (const call of state.calls) {
        if (!/(?:^|\.)(?:exec|execsync|spawn|spawnsync|fork|execfile)$/u
            .test(call.normalizedName)) {
            continue;
        }
        const resolved = resolveCallTarget(call, state.bindings);
        if (resolved) continue;
        context.addFact(
            "unresolved-dynamic-target",
            "process-command",
            rangeFromTokens(state.tokens, call.startIndex, call.closeIndex),
            {
                value: "command-construction",
                resolution: "dynamic",
                tags: ["javascript", "process-execution"],
            },
        );
    }
}

export function scanJavaScriptSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    return scanConfiguredCode({
        path,
        text,
        scannerId: "scanner.javascript-typescript",
        language: "javascript-typescript",
        dialect: "javascript",
        maxFacts,
        maxTokens,
        callPatterns: CALL_PATTERNS,
        references: REFERENCES,
        gatePatterns: {
            environment: [/\bprocess \. env\b/u, /\bimport \. meta \. env\b/u],
            platform: [/\bprocess \. (?:platform|arch)\b/u, /\bnavigator \. platform\b/u],
            time: [/\bdate \. now\b/u, /\bnew date\b/u, /\bperformance \. now\b/u],
        },
        scan(context, state) {
            staticImports(context, state);
            dynamicImports(context, state);
            activationExports(context, state);
            commandAliases(context, state);
        },
    });
}

export const __internals = Object.freeze({
    staticImports,
    dynamicImports,
    activationExports,
});
