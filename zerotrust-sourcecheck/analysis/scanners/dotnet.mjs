import {
    commandTarget,
    createScannerContext,
    rangeFromTokens,
    tokenizeSource,
} from "./core.mjs";
import {
    addDynamicTargetFactsForCalls,
    scanConfiguredCode,
} from "./code.mjs";

const CSHARP_CALL_PATTERNS = Object.freeze([
    {
        names: ["system.diagnostics.process.start", "process.start"],
        kind: "command-construction",
        name: "process-command",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["csharp", "process-execution"],
    },
    {
        names: ["system.diagnostics.process.start", "process.start"],
        kind: "sink",
        name: "process-execution",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["csharp", "process-execution"],
    },
    {
        names: [
            "system.reflection.assembly.load",
            "system.reflection.assembly.loadfrom",
            "system.reflection.assembly.loadfile",
            "assembly.load",
            "assembly.loadfrom",
            "assembly.loadfile",
        ],
        kind: "dynamic-import",
        name: "runtime-assembly-load",
        dynamicTarget: true,
        tags: ["csharp", "dynamic-import"],
    },
    {
        names: [
            "system.type.gettype",
            "type.gettype",
            "activator.createinstance",
            "methodinfo.invoke",
            "delegate.dynamicinvoke",
            "propertyinfo.getvalue",
            "fieldinfo.getvalue",
        ],
        kind: "reflection",
        name: "reflective-dispatch",
        dynamicTarget: true,
        tags: ["csharp", "reflection"],
    },
    {
        names: [
            "microsoft.codeanalysis.csharp.scripting.csharpscript.evaluateasync",
            "csharpscript.evaluateasync",
            "codedomprovider.compileassemblyfromsource",
            "csharpcompilation.create",
        ],
        kind: "dynamic-evaluation",
        name: "dynamic-code-evaluation",
        dynamicTarget: true,
        tags: ["csharp", "dynamic-code"],
    },
    {
        names: [
            "file.readalltext",
            "file.readallbytes",
            "streamreader.readtoend",
            "httpclient.getstringasync",
            "httpclient.getbytearrayasync",
        ],
        kind: "source",
        name: "file-or-network-read",
        tags: ["csharp", "source"],
    },
    {
        names: [
            "convert.frombase64string",
            "gzipstream",
            "deflatestream",
            "jsonserializer.deserialize",
            "protecteddata.unprotect",
        ],
        kind: "transform",
        name: "decode-or-transform",
        tags: ["csharp", "transform"],
    },
    {
        names: [
            "file.writealltext",
            "file.writeallbytes",
            "streamwriter.write",
            "httpclient.postasync",
            "httpclient.sendasync",
            "registrykey.setvalue",
        ],
        kind: "sink",
        name: "write-or-send",
        tags: ["csharp", "effect"],
    },
    {
        names: ["registrykey.setvalue", "taskscheduler.registertaskdefinition"],
        kind: "persistence",
        name: "persistence-registration",
        tags: ["csharp", "persistence"],
    },
    {
        names: [
            "codedomprovider.compileassemblyfromsource",
            "csharpcompilation.create",
            "assemblybuilder.defineDynamicAssembly",
            "dynamicmethod",
        ],
        kind: "generated-code-hook",
        name: "generated-code-hook",
        tags: ["csharp", "generated-code"],
    },
]);

const CSHARP_REFERENCES = Object.freeze([
    {
        names: ["environment.getenvironmentvariable", "environment.getcommandlineargs"],
        kind: "source",
        name: "environment-or-process-input",
        tags: ["csharp", "environment-source"],
    },
    {
        names: ["runtimeinformation.isosplatform", "operatingsystem.iswindows", "environment.is64bitprocess"],
        kind: "platform-gate",
        name: "platform-reference",
        tags: ["csharp", "platform"],
    },
    {
        names: ["datetime.now", "datetime.utcnow", "datetimeoffset.now", "environment.tickcount"],
        kind: "time-gate",
        name: "time-reference",
        tags: ["csharp", "time"],
    },
]);

function csharpImports(context, { tokens }) {
    for (let index = 0; index < tokens.length; index += 1) {
        if (String(tokens[index].value || "").toLowerCase() !== "using") continue;
        if (tokens[index + 1]?.value === "(") continue;
        const parts = [];
        let endIndex = index;
        for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
            if (tokens[cursor].type === "newline" || tokens[cursor].value === ";") break;
            if (tokens[cursor].type === "identifier" || tokens[cursor].value === ".") {
                parts.push(tokens[cursor].value);
                endIndex = cursor;
            }
        }
        const target = parts.join("");
        if (!target) continue;
        context.addFact("import", "namespace", rangeFromTokens(tokens, index, endIndex), {
            target,
            resolution: "literal",
            tags: ["csharp", "static-import"],
        });
    }
}

function csharpActivations(context, { tokens }) {
    for (let index = 0; index < tokens.length; index += 1) {
        const value = String(tokens[index].value || "").toLowerCase();
        if (value === "main" && tokens[index + 1]?.value === "(") {
            context.addFact("activation", "application-entrypoint", rangeFromTokens(
                tokens,
                index,
                index,
            ), {
                value: "Main",
                tags: ["csharp", "entrypoint"],
            });
        }
        if (tokens[index + 1]?.value === "+=") {
            context.addFact("activation", "event-handler-registration", rangeFromTokens(
                tokens,
                index,
                Math.min(tokens.length - 1, index + 2),
            ), {
                value: tokens[index].value,
                tags: ["csharp", "event-handler"],
            });
        }
    }
}

export function scanCSharpSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    return scanConfiguredCode({
        path,
        text,
        scannerId: "scanner.csharp",
        language: "csharp",
        dialect: "csharp",
        maxFacts,
        maxTokens,
        callPatterns: CSHARP_CALL_PATTERNS,
        references: CSHARP_REFERENCES,
        gatePatterns: {
            environment: [/\benvironment \. getenvironmentvariable\b/u],
            platform: [
                /\bruntimeinformation \. isosplatform\b/u,
                /\boperatingsystem \. is(?:windows|linux|macos)\b/u,
            ],
            time: [/\bdatetime(?:offset)? \. (?:now|utcnow)\b/u, /\benvironment \. tickcount\b/u],
        },
        scan(context, state) {
            csharpImports(context, state);
            csharpActivations(context, state);
            addDynamicTargetFactsForCalls(
                context,
                state.tokens,
                state.calls,
                state.bindings,
                {
                    names: ["assembly.load", "assembly.loadfrom", "type.gettype"],
                    kind: "dynamic-import",
                    factName: "runtime-assembly-load",
                    tags: ["csharp", "dynamic-import"],
                },
            );
        },
    });
}

function decodeXmlValue(value) {
    return String(value || "")
        .replace(/&quot;/giu, "\"")
        .replace(/&apos;/giu, "'")
        .replace(/&lt;/giu, "<")
        .replace(/&gt;/giu, ">")
        .replace(/&amp;/giu, "&");
}

function scanXmlTags(text, visit, {
    maxTags = 50_000,
    maxAttributes = 250_000,
} = {}) {
    const tagPattern = /<(?![!?/])([A-Za-z_][A-Za-z0-9_.:-]*)([^<>]*?)\/?>/gu;
    let tagCount = 0;
    let attributeCount = 0;
    let truncated = false;
    for (const match of text.matchAll(tagPattern)) {
        if (tagCount >= maxTags) {
            truncated = true;
            break;
        }
        tagCount += 1;
        const tagStart = match.index;
        const tagEnd = tagStart + match[0].length;
        const nameStart = tagStart + 1;
        const attributesStart = nameStart + match[1].length;
        const attributes = [];
        const attributePattern =
            /([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(["'])([\s\S]*?)\2/gu;
        for (const attribute of match[2].matchAll(attributePattern)) {
            if (attributeCount >= maxAttributes) {
                truncated = true;
                break;
            }
            attributeCount += 1;
            const start = attributesStart + attribute.index;
            attributes.push({
                name: attribute[1],
                value: decodeXmlValue(attribute[3]),
                start,
                end: start + attribute[0].length,
            });
        }
        visit({
            name: match[1],
            start: tagStart,
            end: tagEnd,
            attributes,
        });
    }
    return { tagCount, attributeCount, truncated };
}

function attribute(tag, name) {
    return tag.attributes.find((entry) =>
        entry.name.toLowerCase() === name.toLowerCase()) || null;
}

function dynamicMsbuildValue(value) {
    return /\$\(|@\(|%\(/u.test(String(value || ""));
}

function addMsbuildCommand(context, tag, command) {
    const target = commandTarget(command.value);
    const range = { startOffset: command.start, endOffset: command.end };
    context.addFact("command-construction", "msbuild-exec-command", range, {
        target,
        resolution: dynamicMsbuildValue(command.value) ? "dynamic": "literal",
        tags: ["msbuild", "process-execution"],
    });
    context.addFact("sink", "process-execution", range, {
        target,
        tags: ["msbuild", "process-execution"],
    });
    if (!target || dynamicMsbuildValue(command.value)) {
        context.addFact("unresolved-dynamic-target", "msbuild-exec-command", range, {
            value: "command-construction",
            resolution: "dynamic",
            tags: ["msbuild", "dynamic-target"],
        });
    }
}

function scanMsbuildTag(context, tag) {
    const name = tag.name.toLowerCase();
    const nameAttribute = attribute(tag, "Name");
    const command = attribute(tag, "Command");
    const condition = attribute(tag, "Condition");
    const assemblyFile = attribute(tag, "AssemblyFile")
        || attribute(tag, "AssemblyName")
        || attribute(tag, "Project");
    const taskFactory = attribute(tag, "TaskFactory");

    if (name === "target") {
        context.addFact("activation", "msbuild-target", {
            startOffset: tag.start,
            endOffset: tag.end,
        }, {
            value: nameAttribute?.value || "target",
            tags: ["msbuild", "build-target"],
        });
        for (const hookName of ["BeforeTargets", "AfterTargets"]) {
            const hook = attribute(tag, hookName);
            if (hook) {
                context.addFact("activation", "msbuild-target-hook", {
                    startOffset: hook.start,
                    endOffset: hook.end,
                }, {
                    value: hookName.toLowerCase(),
                    tags: ["msbuild", "build-hook"],
                });
            }
        }
    }
    if (name === "exec" && command) {
        addMsbuildCommand(context, tag, command);
        context.addFact("generated-code-hook", "msbuild-exec-hook", {
            startOffset: tag.start,
            endOffset: tag.end,
        }, {
            value: command.value,
            tags: ["msbuild", "build-hook", "generated-code"],
        });
    }
    if (["usingtask", "import"].includes(name) && assemblyFile) {
        context.addFact(name === "import" ? "import": "dynamic-import", "msbuild-task-import", {
            startOffset: assemblyFile.start,
            endOffset: assemblyFile.end,
        }, {
            target: assemblyFile.value,
            resolution: dynamicMsbuildValue(assemblyFile.value) ? "dynamic": "literal",
            tags: ["msbuild", "task-import"],
        });
        if (dynamicMsbuildValue(assemblyFile.value)) {
            context.addFact("unresolved-dynamic-target", "msbuild-task-import", {
                startOffset: assemblyFile.start,
                endOffset: assemblyFile.end,
            }, {
                value: "dynamic-import",
                resolution: "dynamic",
                tags: ["msbuild", "dynamic-target"],
            });
        }
    }
    if (taskFactory || /(?:code|compile|generate|writecodefragment)/iu.test(tag.name)) {
        context.addFact("generated-code-hook", "msbuild-generated-code", {
            startOffset: tag.start,
            endOffset: tag.end,
        }, {
            value: taskFactory?.value || tag.name,
            tags: ["msbuild", "generated-code"],
        });
    }
    if (["downloadfile", "readlinesfromfile"].includes(name)) {
        context.addFact("source", "msbuild-input", {
            startOffset: tag.start,
            endOffset: tag.end,
        }, {
            tags: ["msbuild", "source"],
        });
    }
    if (["writelinestofile", "copy", "delete", "move"].includes(name)) {
        context.addFact("sink", "msbuild-file-effect", {
            startOffset: tag.start,
            endOffset: tag.end,
        }, {
            tags: ["msbuild", "effect"],
        });
    }
    if (condition) {
        const value = condition.value.toLowerCase();
        if (/\$\((?:environment|env|configuration|secret)/u.test(value)) {
            context.addFact("environment-gate", "msbuild-condition", {
                startOffset: condition.start,
                endOffset: condition.end,
            }, {
                value: "conditional-activation",
                tags: ["msbuild", "gate", "environment"],
            });
        }
        if (/(?:os|platform|runtimeidentifier|windows|linux|osx|darwin)/u.test(value)) {
            context.addFact("platform-gate", "msbuild-condition", {
                startOffset: condition.start,
                endOffset: condition.end,
            }, {
                value: "conditional-activation",
                tags: ["msbuild", "gate", "platform"],
            });
        }
        if (/(?:date|time|ticks|utcnow)/u.test(value)) {
            context.addFact("time-gate", "msbuild-condition", {
                startOffset: condition.start,
                endOffset: condition.end,
            }, {
                value: "conditional-activation",
                tags: ["msbuild", "gate", "time"],
            });
        }
    }
}

export function scanMsbuildXmlSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    const context = createScannerContext({
        path,
        text,
        scannerId: "scanner.msbuild-xml",
        language: "msbuild-xml",
        maxFacts,
        maxTokens,
    });
    const scanned = scanXmlTags(context.text, (tag) => scanMsbuildTag(context, tag));
    return context.finish({
        tokenCount: scanned.tagCount + scanned.attributeCount,
        tokensTruncated: scanned.truncated,
    });
}

export const __internals = Object.freeze({
    csharpImports,
    csharpActivations,
    decodeXmlValue,
    scanXmlTags,
    scanMsbuildTag,
    dynamicMsbuildValue,
    tokenizeSource,
});
