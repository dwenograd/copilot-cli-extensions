import {
    commandTarget,
    rangeFromTokens,
    splitStatements,
} from "./core.mjs";
import { scanConfiguredCode } from "./code.mjs";

const GENERIC_CALL_PATTERNS = Object.freeze([
    {
        names: [
            /(?:^|\.)(?:exec|execsync|spawn|spawnsync|popen|system|startprocess|process\.start)$/u,
            /(?:^|::)command::new$/u,
        ],
        kind: "command-construction",
        name: "process-command",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["generic", "process-execution"],
    },
    {
        names: [/(?:^|\.)(?:eval|exec|compile|evaluate|runincontext)$/u],
        kind: "dynamic-evaluation",
        name: "dynamic-code-evaluation",
        dynamicTarget: true,
        tags: ["generic", "dynamic-code"],
    },
    {
        names: [/(?:reflect|assembly\.load|type\.gettype|activator|dynamicinvoke|dlopen)/u],
        kind: "reflection",
        name: "reflective-dispatch",
        dynamicTarget: true,
        tags: ["generic", "reflection"],
    },
    {
        names: [/(?:^|\.)(?:require|import_module|loadlibrary|loadfrom|dlopen)$/u],
        kind: "dynamic-import",
        name: "runtime-module-load",
        dynamicTarget: true,
        tags: ["generic", "dynamic-import"],
    },
    {
        names: [/(?:read|readfile|readalltext|open|getenv|fetch|request|get)$/u],
        kind: "source",
        name: "generic-input",
        tags: ["generic", "source"],
    },
    {
        names: [/(?:decode|decompress|inflate|gunzip|deserialize|decrypt|frombase64)/u],
        kind: "transform",
        name: "generic-transform",
        tags: ["generic", "transform"],
    },
    {
        names: [/(?:write|writefile|send|post|upload|setvalue)$/u],
        kind: "sink",
        name: "generic-effect",
        tags: ["generic", "effect"],
    },
    {
        names: [/(?:register|addeventlistener|subscribe|schedule|timer)$/u],
        kind: "activation",
        name: "generic-registration",
        tags: ["generic", "activation"],
    },
]);

const GENERIC_REFERENCES = Object.freeze([
    {
        names: [/(?:^|\.)(?:env|environ|environment)$/u],
        kind: "source",
        name: "environment-reference",
        tags: ["generic", "environment-source"],
    },
    {
        names: [/(?:platform|operatingsystem|runtimeidentifier|architecture|uname)/u],
        kind: "platform-gate",
        name: "platform-reference",
        tags: ["generic", "platform"],
    },
    {
        names: [/(?:datetime|date\.now|time\.now|systemtime|clock)/u],
        kind: "time-gate",
        name: "time-reference",
        tags: ["generic", "time"],
    },
]);

function genericStatements(context, state) {
    for (const statement of splitStatements(state.tokens)) {
        const normalized = statement.map((token) => String(token.value).toLowerCase()).join(" ");
        const range = {
            startOffset: statement[0].start,
            endOffset: statement[statement.length - 1].end,
        };
        if (/(?:schtasks|scheduledtask|crontab|systemctl enable|launchctl load|runonce|startup)/u
            .test(normalized)) {
            context.addFact("persistence", "persistence-registration", range, {
                tags: ["generic", "persistence"],
            });
        }
        if (/(?:codegen|generate source|compile source|emit assembly|dynamicmethod)/u
            .test(normalized)) {
            context.addFact("generated-code-hook", "generated-code-hook", range, {
                tags: ["generic", "generated-code"],
            });
        }
        if (/^(?:import|include|require|using|use)\b/u.test(normalized)) {
            const literal = statement.find((token) =>
                token.type === "string" && token.literal !== null);
            const identifier = statement.slice(1).find((token) => token.type === "identifier");
            const target = literal?.literal || identifier?.value;
            context.addFact("import", "module", range, {
                target,
                resolution: target ? "literal": "dynamic",
                tags: ["generic", "static-import"],
            });
        }
        const commandLiteral = statement.find((token) =>
            token.type === "string"
            && /(?:powershell|pwsh|cmd(?:\.exe)?|bash|sh|python|node|curl|wget)/iu
                .test(token.literal || ""));
        if (commandLiteral) {
            context.addFact("command-construction", "command-literal", rangeFromTokens(
                statement,
                statement.indexOf(commandLiteral),
                statement.indexOf(commandLiteral),
            ), {
                target: commandTarget(commandLiteral.literal),
                resolution: "literal",
                tags: ["generic", "command-literal"],
            });
        }
    }
}

export function scanGenericSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    return scanConfiguredCode({
        path,
        text,
        scannerId: "scanner.generic",
        language: "generic",
        dialect: "generic",
        maxFacts,
        maxTokens,
        callPatterns: GENERIC_CALL_PATTERNS,
        references: GENERIC_REFERENCES,
        gatePatterns: {
            environment: [/\benv(?:ironment)?\b/u],
            platform: [/\bplatform\b/u, /\boperating system\b/u, /\barch(?:itecture)?\b/u],
            time: [/\bdate\b/u, /\btime\b/u, /\bclock\b/u],
        },
        scan: genericStatements,
    });
}

export const __internals = Object.freeze({
    genericStatements,
});
