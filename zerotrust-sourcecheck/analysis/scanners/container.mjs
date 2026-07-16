import {
    commandTarget,
    createScannerContext,
} from "./core.mjs";
import { scanJsonSource } from "./json.mjs";

function dockerLines(text, maxLines = 100_000) {
    const rawLines = text.split(/\r?\n/u);
    const physical = [];
    let offset = 0;
    for (let index = 0; index < Math.min(rawLines.length, maxLines); index += 1) {
        const raw = rawLines[index];
        physical.push({
            raw,
            start: offset,
            end: offset + raw.length,
            line: index + 1,
        });
        offset += raw.length + (text.slice(offset + raw.length, offset + raw.length + 2) === "\r\n"
            ? 2: 1);
    }
    const logical = [];
    for (let index = 0; index < physical.length; index += 1) {
        const first = physical[index];
        if (!first.raw.trim() || first.raw.trimStart().startsWith("#")) continue;
        const parts = [first.raw];
        let end = first.end;
        while (/\\\s*$/u.test(parts[parts.length - 1]) && index + 1 < physical.length) {
            index += 1;
            parts.push(physical[index].raw);
            end = physical[index].end;
        }
        const joined = parts.join("\n");
        const match = joined.match(/^\s*([A-Za-z]+)\s+([\s\S]*?)\s*$/u);
        if (!match) continue;
        const instructionStart = first.start + joined.indexOf(match[1]);
        const argumentStart = first.start + joined.indexOf(match[2], joined.indexOf(match[1]));
        logical.push({
            instruction: match[1].toUpperCase(),
            argument: match[2],
            start: instructionStart,
            argumentStart,
            end,
        });
    }
    return { instructions: logical, truncated: rawLines.length > maxLines };
}

function dynamicDockerValue(value) {
    return /\$(?:\{|[A-Za-z_])/u.test(String(value || ""));
}

function addDockerCommand(context, instruction) {
    const target = commandTarget(instruction.argument.replace(/^\[|\]$/gu, ""));
    const range = {
        startOffset: instruction.argumentStart,
        endOffset: instruction.end,
    };
    const dynamic = dynamicDockerValue(instruction.argument);
    context.addFact("command-construction", "container-command", range, {
        target,
        resolution: dynamic || !target ? "dynamic": "literal",
        tags: ["docker", "container-command"],
    });
    context.addFact("sink", "process-execution", range, {
        target,
        tags: ["docker", "process-execution"],
    });
    if (dynamic || !target) {
        context.addFact("unresolved-dynamic-target", "container-command", range, {
            value: "command-construction",
            resolution: "dynamic",
            tags: ["docker", "dynamic-target"],
        });
    }
    if (/(?:generate|codegen|compile|transpile|build|emit)/iu.test(instruction.argument)) {
        context.addFact("generated-code-hook", "container-generated-code", range, {
            target,
            tags: ["docker", "generated-code"],
        });
    }
    if (/(?:schtasks|crontab|systemctl\s+enable|launchctl\s+load|runonce)/iu
        .test(instruction.argument)) {
        context.addFact("persistence", "container-persistence-command", range, {
            target,
            tags: ["docker", "persistence"],
        });
    }
    if (/(?:curl|wget|invoke-webrequest|git\s+clone|apt(?:-get)?\s+install|pip\s+install)/iu
        .test(instruction.argument)) {
        context.addFact("source", "container-external-source", range, {
            tags: ["docker", "network-source"],
        });
    }
    if (/(?:base64|gunzip|inflate|decrypt|openssl)/iu.test(instruction.argument)) {
        context.addFact("transform", "container-transform", range, {
            tags: ["docker", "transform"],
        });
    }
}

function scanDockerInstruction(context, instruction) {
    const range = {
        startOffset: instruction.start,
        endOffset: instruction.end,
    };
    const argumentRange = {
        startOffset: instruction.argumentStart,
        endOffset: instruction.end,
    };
    switch (instruction.instruction) {
        case "FROM": {
            const target = instruction.argument.split(/\s+AS\s+/iu)[0].trim();
            context.addFact("import", "container-base-image", argumentRange, {
                target,
                resolution: dynamicDockerValue(target) ? "dynamic": "literal",
                tags: ["docker", "base-image"],
            });
            if (dynamicDockerValue(target)) {
                context.addFact("unresolved-dynamic-target", "container-base-image", argumentRange, {
                    value: "import",
                    resolution: "dynamic",
                    tags: ["docker", "dynamic-target"],
                });
            }
            break;
        }
        case "RUN":
            context.addFact("activation", "container-build-step", range, {
                value: "RUN",
                tags: ["docker", "build-activation"],
            });
            addDockerCommand(context, instruction);
            break;
        case "CMD":
        case "ENTRYPOINT":
            context.addFact("activation", "container-entrypoint", range, {
                value: instruction.instruction.toLowerCase(),
                tags: ["docker", "runtime-activation"],
            });
            addDockerCommand(context, instruction);
            break;
        case "ONBUILD":
            context.addFact("activation", "container-onbuild", range, {
                value: "onbuild",
                tags: ["docker", "deferred-activation"],
            });
            context.addFact("generated-code-hook", "container-onbuild", range, {
                tags: ["docker", "generated-code", "deferred-build"],
            });
            break;
        case "ADD":
        case "COPY":
            context.addFact("source", "container-file-source", range, {
                tags: ["docker", "file-source"],
            });
            if (/https?:\/\//iu.test(instruction.argument)) {
                context.addFact("source", "container-network-source", argumentRange, {
                    tags: ["docker", "network-source"],
                });
            }
            break;
        case "ARG":
        case "ENV":
            context.addFact("source", "container-environment", range, {
                value: instruction.argument.split(/[=\s]/u)[0],
                tags: ["docker", "environment-source"],
            });
            context.addFact("environment-gate", "container-build-environment", range, {
                value: "conditional-build",
                tags: ["docker", "gate", "environment"],
            });
            break;
        case "SHELL":
            context.addFact("activation", "container-shell-selection", range, {
                value: "shell",
                tags: ["docker", "shell-selection"],
            });
            addDockerCommand(context, instruction);
            break;
        case "HEALTHCHECK":
            context.addFact("activation", "container-healthcheck", range, {
                value: "healthcheck",
                tags: ["docker", "periodic-activation"],
            });
            context.addFact("time-gate", "container-healthcheck-interval", range, {
                value: "periodic-activation",
                tags: ["docker", "gate", "time"],
            });
            break;
        default:
            break;
    }
}

export function scanDockerfileSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    const context = createScannerContext({
        path,
        text,
        scannerId: "scanner.docker-devcontainer",
        language: "dockerfile",
        maxFacts,
        maxTokens,
    });
    const parsed = dockerLines(context.text);
    for (const instruction of parsed.instructions.slice(0, context.maxTokens)) {
        scanDockerInstruction(context, instruction);
    }
    return context.finish({
        tokenCount: parsed.instructions.length,
        tokensTruncated: parsed.truncated || parsed.instructions.length > context.maxTokens,
    });
}

export function scanDevcontainerSource(options = {}) {
    return scanJsonSource({
        ...options,
        scannerId: "scanner.docker-devcontainer",
        language: "devcontainer-json",
    });
}

export const __internals = Object.freeze({
    dockerLines,
    dynamicDockerValue,
    scanDockerInstruction,
    addDockerCommand,
});
