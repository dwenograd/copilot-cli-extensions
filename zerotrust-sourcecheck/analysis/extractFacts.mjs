import { createHash } from "node:crypto";
import nodePath from "node:path";

export const FACT_KINDS = Object.freeze([
    "manifest-key",
    "config-key",
    "declaration",
    "import",
    "execution-registration",
    "command-construction",
    "url",
    "domain",
    "sensitive-resource",
    "source-hint",
    "sink-hint",
]);

export const EXTRACTION_LIMITS = Object.freeze({
    factsPerFile: 256,
    factName: 128,
    factValue: 256,
    path: 1024,
});

const IDENTIFIER = "[A-Za-z_$][A-Za-z0-9_$.-]*";
const URL_RE = /\bhttps?:\/\/[^\s"'`<>{}\[\]]+/giu;

const SOURCE_HINTS = Object.freeze([
    ["environment", /\b(?:process\.env(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])|os\.environ|std::env::var|Environment\.GetEnvironmentVariable)\b/u],
    ["file-read", /\b(?:readFile(?:Sync)?|File\.ReadAll(?:Text|Bytes)|open\s*\([^,\n]+,\s*["']r|fs\.read|read_to_(?:string|end))\b/u],
    ["network-response", /\b(?:fetch\s*\(|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.(?:get|request)|Invoke-WebRequest|curl_easy_perform)\b/u],
    ["process-arguments", /\b(?:process\.argv|sys\.argv|Environment\.GetCommandLineArgs|std::env::args)\b/u],
    ["standard-input", /\b(?:process\.stdin|sys\.stdin|Console\.ReadLine|std::io::stdin)\b/u],
    ["clipboard", /\b(?:clipboard|Get-Clipboard|UIPasteboard|NSPasteboard)\b/iu],
    ["registry-read", /\b(?:Registry\.(?:GetValue|OpenSubKey)|winreg\.(?:OpenKey|QueryValue)|RegGetValue)\b/u],
    ["browser-storage", /\b(?:localStorage|sessionStorage|document\.cookie|cookies?\.(?:get|all))\b/u],
]);

const SINK_HINTS = Object.freeze([
    ["process-execution", /\b(?:child_process\.(?:exec|execFile|spawn|fork)|execSync|spawnSync|subprocess\.(?:Popen|run|call)|os\.system|Process\.Start|Runtime\.getRuntime\(\)\.exec|Command::new|Start-Process)\b/u],
    ["dynamic-evaluation", /\b(?:eval|new\s+Function|vm\.runIn|exec\s*\(|compile\s*\()\b/u],
    ["network-send", /\b(?:fetch\s*\([^,\n]+,\s*\{|axios\.(?:post|put|patch)|requests\.(?:post|put)|http\.(?:request|post)|Invoke-RestMethod|WebClient\.Upload)\b/u],
    ["file-write", /\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|File\.WriteAll(?:Text|Bytes)|Set-Content|Out-File|write_all|createWriteStream)\b/u],
    ["registry-write", /\b(?:Registry\.SetValue|winreg\.SetValue|RegSetValue|New-ItemProperty|Set-ItemProperty)\b/u],
    ["persistence", /\b(?:schtasks|Register-ScheduledTask|systemctl\s+enable|launchctl\s+load|RunOnce|StartupFolder|crontab)\b/iu],
]);

const SENSITIVE_RESOURCES = Object.freeze([
    ["credential-store", /(?:^|[/\\])(?:\.ssh|\.aws|\.docker|\.kube|\.gnupg|\.password-store)(?:[/\\]|$)/iu],
    ["credential-file", /\b(?:id_rsa|id_ed25519|credentials|known_hosts|authorized_keys|kubeconfig|\.npmrc|\.pypirc|netrc)\b/iu],
    ["cloud-metadata", /\b(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b/iu],
    ["browser-secrets", /\b(?:Login Data|Cookies|Local State|Web Data|key4\.db|logins\.json)\b/iu],
    ["system-account-data", /\b(?:\/etc\/(?:passwd|shadow)|SAM|SECURITY|SYSTEM)\b/iu],
    ["secret-material", /\b(?:private[_-]?key|access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|password|credential)\b/iu],
]);

function normalizePath(path) {
    return String(path || "").replace(/\\/g, "/").replace(/^\.\/+/, "").slice(0, EXTRACTION_LIMITS.path);
}

function normalizeText(value, max) {
    return String(value || "")
        .normalize("NFKC")
        .replace(/[\u0000-\u001f\u007f]+/gu, " ")
        .replace(/\s+/gu, " ")
        .trim()
        .slice(0, max);
}

function normalizeToken(value) {
    return normalizeText(value, EXTRACTION_LIMITS.factName)
        .replace(/[^A-Za-z0-9_$@./:+-]+/gu, "-")
        .replace(/-{2,}/gu, "-")
        .replace(/^-+|-+$/gu, "");
}

function excerptHash(line) {
    return createHash("sha256").update(String(line), "utf8").digest("hex");
}

function lineForKey(lines, key) {
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const pattern = new RegExp(`(?:^|[{"'\\s,])${escaped}(?:["'\\s]*[:=]|\\s*$)`, "u");
    const index = lines.findIndex((line) => pattern.test(line));
    return index >= 0 ? index + 1: 1;
}

function safeJson(text) {
    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}

function walkJsonKeys(value, visit, prefix = "", depth = 0) {
    if (!value || typeof value !== "object" || depth > 12) return true;
    if (Array.isArray(value)) {
        for (const item of value.slice(0, 512)) {
            if (!walkJsonKeys(item, visit, prefix, depth + 1)) return false;
        }
        return true;
    }
    for (const key of Object.keys(value).slice(0, 2048)) {
        const qualified = prefix ? `${prefix}.${key}`: key;
        if (visit(key, qualified) === false) return false;
        if (!walkJsonKeys(value[key], visit, qualified, depth + 1)) return false;
    }
    return true;
}

function normalizeUrl(raw) {
    try {
        const parsed = new URL(raw.replace(/[),.;]+$/u, ""));
        if (!["http:", "https:"].includes(parsed.protocol)) return null;
        parsed.username = "";
        parsed.password = "";
        parsed.search = "";
        parsed.hash = "";
        return {
            url: `${parsed.protocol}//${parsed.host}${parsed.pathname}`.slice(
                0,
                EXTRACTION_LIMITS.factValue,
            ),
            domain: parsed.hostname.toLowerCase().slice(0, EXTRACTION_LIMITS.factValue),
        };
    } catch {
        return null;
    }
}

function commandTarget(fragment) {
    const match = fragment.match(/["'`]([^"'`\r\n]{1,256})["'`]/u);
    const candidate = match ? match[1]: String(fragment || "").trim();
    const first = candidate.split(/\s+/u)[0] || "";
    if (!/^[A-Za-z0-9_.@/\\:+-]{1,256}$/u.test(first)) return null;
    return normalizeToken(nodePath.basename(first.replace(/\\/g, "/"))).toLowerCase() || null;
}

export function extractFactsFromText({
    path,
    text,
    maxFacts = EXTRACTION_LIMITS.factsPerFile,
} = {}) {
    if (typeof text !== "string") throw new TypeError("text must be a string");
    if (!Number.isSafeInteger(maxFacts) || maxFacts < 1
        || maxFacts > EXTRACTION_LIMITS.factsPerFile) {
        throw new RangeError(
            `maxFacts must be between 1 and ${EXTRACTION_LIMITS.factsPerFile}`,
        );
    }

    const normalizedPath = normalizePath(path);
    const lines = text.split(/\r?\n/u);
    const facts = [];
    const seen = new Set();
    let overflow = false;

    const add = (kind, name, value, lineNumber, lineText) => {
        if (!FACT_KINDS.includes(kind)) return true;
        const normalizedName = normalizeToken(name);
        const normalizedValue = value === null || value === undefined
            ? null: normalizeText(value, EXTRACTION_LIMITS.factValue);
        if (!normalizedName && !normalizedValue) return true;
        const line = Math.max(1, Math.min(Number(lineNumber) || 1, 10_000_000));
        const key = `${kind}\0${normalizedName}\0${normalizedValue || ""}\0${line}`;
        if (seen.has(key)) return true;
        if (facts.length >= maxFacts) {
            overflow = true;
            return false;
        }
        seen.add(key);
        const fact = {
            kind,
            path: normalizedPath,
            line,
            endLine: line,
            excerptHash: excerptHash(lineText ?? lines[line - 1] ?? ""),
            name: normalizedName || kind,
        };
        if (normalizedValue) fact.value = normalizedValue;
        fact.id = createHash("sha256")
            .update(`${fact.kind}\0${fact.path}\0${fact.line}\0${fact.name}\0${fact.value || ""}`)
            .digest("hex");
        facts.push(Object.freeze(fact));
        return true;
    };

    const base = nodePath.basename(normalizedPath).toLowerCase();
    const isJson = base.endsWith(".json") || base.endsWith(".jsonc");
    const parsedJson = isJson ? safeJson(text): null;
    if (parsedJson) {
        walkJsonKeys(parsedJson, (key, qualified) => {
            const line = lineForKey(lines, key);
            return add(
                ["package.json", "manifest.json", "extension.json"].includes(base)
                    ? "manifest-key": "config-key",
                key,
                qualified,
                line,
                lines[line - 1],
            );
        });
        if (parsedJson.scripts && typeof parsedJson.scripts === "object"
            && !Array.isArray(parsedJson.scripts)) {
            for (const key of Object.keys(parsedJson.scripts)) {
                const line = lineForKey(lines, key);
                add("execution-registration", "package-script", key, line, lines[line - 1]);
                const target = commandTarget(String(parsedJson.scripts[key] || ""));
                if (target) {
                    add("command-construction", "package-script-command", target, line, lines[line - 1]);
                }
            }
        }
        if (Array.isArray(parsedJson.activationEvents)) {
            for (const event of parsedJson.activationEvents) {
                if (typeof event !== "string") continue;
                const line = lineForKey(lines, "activationEvents");
                add("execution-registration", "activation-event", event, line, lines[line - 1]);
            }
        }
        const commands = parsedJson?.contributes?.commands;
        if (Array.isArray(commands)) {
            for (const command of commands) {
                if (typeof command?.command !== "string") continue;
                const line = lineForKey(lines, "commands");
                add("execution-registration", "contributed-command", command.command, line, lines[line - 1]);
            }
        }
    }

    for (let index = 0; index < lines.length; index += 1) {
        const lineText = lines[index];
        const line = index + 1;

        const config = lineText.match(
            new RegExp(`^\\s*["']?(${IDENTIFIER})["']?\\s*[:=]`, "u"),
        );
        if (config) add("config-key", config[1], null, line, lineText);

        const xmlConfig = lineText.match(/^\s*<([A-Za-z_][A-Za-z0-9_.:-]{0,127})(?:\s|>)/u);
        if (xmlConfig) add("config-key", xmlConfig[1], null, line, lineText);

        const declarations = [
            /\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)/u,
            /\b(?:class|interface|enum|struct|trait|type|namespace|module)\s+([A-Za-z_$][A-Za-z0-9_$]*)/u,
            /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/u,
            /^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)/u,
            /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)/u,
            /^\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)/u,
        ];
        for (const pattern of declarations) {
            const match = lineText.match(pattern);
            if (match) add("declaration", match[1], null, line, lineText);
        }

        const imports = [
            /\bimport\s+(?:[^"'`]+?\s+from\s+)?["'`]([^"'`]+)["'`]/u,
            /\brequire\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/u,
            /^\s*from\s+([A-Za-z0-9_.]+)\s+import\b/u,
            /^\s*import\s+([A-Za-z0-9_.]+)\s*$/u,
            /^\s*using\s+([A-Za-z0-9_.]+)\s*;/u,
            /^\s*use\s+([A-Za-z0-9_:]+)\s*;/u,
            /^\s*#\s*include\s*[<"]([^>"]+)[>"]/u,
            /^\s*Import-Module\s+["']?([A-Za-z0-9_.@/-]+)/iu,
        ];
        for (const pattern of imports) {
            const match = lineText.match(pattern);
            if (match) add("import", "module", match[1], line, lineText);
        }

        const listener = lineText.match(/\.(?:on|once|addEventListener)\s*\(\s*["'`]([^"'`]+)["'`]/u);
        if (listener) {
            add("execution-registration", "event-listener", listener[1], line, lineText);
        }
        const workflow = lineText.match(/^\s*-?\s*(run|uses)\s*:\s*([^\r\n#]+)/u);
        if (workflow) {
            const target = workflow[1] === "run" ? commandTarget(workflow[2]): workflow[2];
            add("execution-registration", `workflow-${workflow[1]}`, target || workflow[1], line, lineText);
        }
        if (base === ".gitattributes") {
            for (const match of lineText.matchAll(/\bfilter=([A-Za-z0-9_.-]{1,128})/gu)) {
                add("execution-registration", "git-attribute-filter", match[1], line, lineText);
            }
        }

        const command = lineText.match(
            /\b(child_process\.(?:exec|execFile|spawn|fork)|execSync|spawnSync|subprocess\.(?:Popen|run|call)|os\.system|Process\.Start|Runtime\.getRuntime\(\)\.exec|Command::new|Start-Process)\s*\((.*)$/u,
        );
        if (command) {
            add(
                "command-construction",
                command[1],
                commandTarget(command[2]),
                line,
                lineText,
            );
        }

        for (const match of lineText.matchAll(URL_RE)) {
            const normalized = normalizeUrl(match[0]);
            if (!normalized) continue;
            add("url", "http-url", normalized.url, line, lineText);
            add("domain", "network-domain", normalized.domain, line, lineText);
        }

        const envRefs = [
            ...lineText.matchAll(/\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)/gu),
            ...lineText.matchAll(/\b(?:getenv|std::env::var|Environment\.GetEnvironmentVariable)\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/gu),
        ];
        for (const match of envRefs) {
            add("sensitive-resource", "environment-variable", match[1], line, lineText);
        }
        for (const [name, pattern] of SENSITIVE_RESOURCES) {
            if (pattern.test(lineText)) add("sensitive-resource", name, null, line, lineText);
        }
        for (const [name, pattern] of SOURCE_HINTS) {
            if (pattern.test(lineText)) add("source-hint", name, null, line, lineText);
        }
        for (const [name, pattern] of SINK_HINTS) {
            if (pattern.test(lineText)) add("sink-hint", name, null, line, lineText);
        }
    }

    return Object.freeze({
        facts: Object.freeze(facts),
        overflow,
        factCount: facts.length,
        lineCount: lines.length,
    });
}

export const __internals = Object.freeze({
    normalizePath,
    normalizeText,
    normalizeToken,
    normalizeUrl,
    commandTarget,
    excerptHash,
});

// The baseline extractor above serves the earlier index stage; semantic scanner
// output feeds the current assurance stages.
export {
    SCANNER_BLOCKER_CODES,
    SCANNER_LIMITS,
    SCANNER_REGISTRY,
    SCANNER_SCHEMA_REVISION,
    SEMANTIC_FACT_KINDS,
    SEMANTIC_RESOLUTIONS,
    createSemanticPluginInput,
    getScannerRegistry,
    scanSourceText,
    scanSourceText as extractSemanticFactsFromText,
    selectScanner,
    validateScannerResult,
    validateSemanticFact,
    validateSemanticPluginInput,
} from "./scanners/index.mjs";
