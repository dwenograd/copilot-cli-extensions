import { rangeFromTokens } from "./core.mjs";
import {
    addDynamicTargetFactsForCalls,
    scanConfiguredCode,
} from "./code.mjs";

const CALL_PATTERNS = Object.freeze([
    {
        names: [
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.popen",
            "os.system",
            "os.popen",
        ],
        kind: "command-construction",
        name: "process-command",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["python", "process-execution"],
    },
    {
        names: [
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.popen",
            "os.system",
            "os.popen",
        ],
        kind: "sink",
        name: "process-execution",
        dynamicTarget: true,
        commandTarget: true,
        tags: ["python", "process-execution"],
    },
    {
        names: ["eval", "exec", "compile", "ast.literal_eval"],
        kind: "dynamic-evaluation",
        name: "dynamic-code-evaluation",
        dynamicTarget: true,
        tags: ["python", "dynamic-code"],
    },
    {
        names: [
            "getattr",
            "setattr",
            "delattr",
            "globals",
            "locals",
            "types.methodtype",
            "marshal.loads",
        ],
        kind: "reflection",
        name: "reflective-dispatch",
        dynamicTarget: true,
        tags: ["python", "reflection"],
    },
    {
        names: [
            "atexit.register",
            "signal.signal",
            "asyncio.create_task",
            "threading.timer",
            "app.route",
            "router.add_route",
        ],
        kind: "activation",
        name: "callback-registration",
        tags: ["python", "activation"],
    },
    {
        names: ["open", "pathlib.path.read_text", "pathlib.path.read_bytes"],
        kind: "source",
        name: "file-read",
        tags: ["python", "file-source"],
    },
    {
        names: [
            "requests.get",
            "requests.request",
            "httpx.get",
            "urllib.request.urlopen",
            "socket.recv",
        ],
        kind: "source",
        name: "network-response",
        tags: ["python", "network-source"],
    },
    {
        names: [
            "base64.b64decode",
            "binascii.a2b_base64",
            "codecs.decode",
            "zlib.decompress",
            "gzip.decompress",
            "bz2.decompress",
            "lzma.decompress",
            "marshal.loads",
            "pickle.loads",
            "json.loads",
        ],
        kind: "transform",
        name: "decode-or-transform",
        tags: ["python", "transform"],
    },
    {
        names: [
            "pathlib.path.write_text",
            "pathlib.path.write_bytes",
            "requests.post",
            "requests.put",
            "httpx.post",
            "socket.send",
            "socket.sendall",
        ],
        kind: "sink",
        name: "write-or-send",
        tags: ["python", "effect"],
    },
    {
        names: [
            "winreg.setvalue",
            "winreg.setvalueex",
            "crontab.write",
            "scheduler.add_job",
        ],
        kind: "persistence",
        name: "persistence-registration",
        tags: ["python", "persistence"],
    },
    {
        names: [
            "compile",
            "exec",
            "setuptools.setup",
            "cythonize",
            "jinja2.template.render",
        ],
        kind: "generated-code-hook",
        name: "generated-code-hook",
        tags: ["python", "generated-code"],
    },
]);

const REFERENCES = Object.freeze([
    {
        names: [/^os\.environ(?:\.|$)/u, /^os\.getenv$/u],
        kind: "source",
        name: "environment-variable",
        tags: ["python", "environment-source"],
    },
    {
        names: ["sys.argv", "sys.stdin"],
        kind: "source",
        name: "process-input",
        tags: ["python", "process-source"],
    },
    {
        names: ["sys.platform", "os.name", "platform.system", "platform.machine"],
        kind: "platform-gate",
        name: "platform-reference",
        tags: ["python", "platform"],
    },
    {
        names: ["time.time", "datetime.datetime.now", "datetime.date.today"],
        kind: "time-gate",
        name: "time-reference",
        tags: ["python", "time"],
    },
    {
        names: ["sys.meta_path", "sys.path_hooks"],
        kind: "generated-code-hook",
        name: "import-hook",
        tags: ["python", "import-hook"],
    },
]);

function staticImports(context, { tokens }) {
    for (let index = 0; index < tokens.length; index += 1) {
        const keyword = String(tokens[index].value || "").toLowerCase();
        if (!["import", "from"].includes(keyword)) continue;
        let cursor = index + 1;
        const parts = [];
        while (cursor < tokens.length) {
            const token = tokens[cursor];
            if (token.type === "newline" || token.value === ";") break;
            if (keyword === "from" && String(token.value).toLowerCase() === "import") break;
            if (token.type === "identifier") parts.push(token.value);
            else if (token.value === ".") parts.push(".");
            else if (token.value === ",") break;
            cursor += 1;
        }
        const target = parts.join("").replace(/\.+$/u, "");
        if (!target) continue;
        context.addFact("import", "module", rangeFromTokens(tokens, index, Math.max(index, cursor - 1)), {
            target,
            resolution: "literal",
            tags: ["python", "static-import"],
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
            names: [
                "__import__",
                "importlib.import_module",
                "importlib.util.spec_from_file_location",
                "runpy.run_module",
                "runpy.run_path",
            ],
            kind: "dynamic-import",
            factName: "runtime-module-load",
            tags: ["python", "dynamic-import"],
        },
    );
}

function mainActivation(context, { tokens }) {
    for (let index = 0; index < tokens.length; index += 1) {
        if (String(tokens[index].value || "").toLowerCase() !== "if") continue;
        let endIndex = index;
        let condition = "";
        for (let cursor = index + 1; cursor < tokens.length; cursor += 1) {
            if (tokens[cursor].type === "newline" || tokens[cursor].value === ":") {
                endIndex = cursor;
                break;
            }
            condition += `${tokens[cursor].value} `;
            endIndex = cursor;
        }
        if (!/__name__.*__main__/u.test(condition)) continue;
        context.addFact("activation", "python-main", rangeFromTokens(tokens, index, endIndex), {
            value: "__main__",
            tags: ["python", "entrypoint"],
        });
    }
}

function decorators(context, { tokens }) {
    for (let index = 0; index + 1 < tokens.length; index += 1) {
        if (tokens[index].value !== "@" || tokens[index + 1].type !== "identifier") continue;
        let endIndex = index + 1;
        while (endIndex + 2 < tokens.length
            && tokens[endIndex + 1].value === "."
            && tokens[endIndex + 2].type === "identifier") {
            endIndex += 2;
        }
        const name = tokens.slice(index + 1, endIndex + 1)
            .map((token) => token.value)
            .join("");
        if (!/(?:route|handler|receiver|hook|task|command|listener|callback)/iu.test(name)) continue;
        context.addFact("activation", "decorator-registration", rangeFromTokens(
            tokens,
            index,
            endIndex,
        ), {
            value: name,
            tags: ["python", "decorator", "activation"],
        });
    }
}

export function scanPythonSource({
    path,
    text,
    maxFacts,
    maxTokens,
} = {}) {
    return scanConfiguredCode({
        path,
        text,
        scannerId: "scanner.python",
        language: "python",
        dialect: "python",
        maxFacts,
        maxTokens,
        callPatterns: CALL_PATTERNS,
        references: REFERENCES,
        gatePatterns: {
            environment: [/\bos \. environ\b/u, /\bos \. getenv\b/u],
            platform: [/\bsys \. platform\b/u, /\bos \. name\b/u, /\bplatform \./u],
            time: [/\btime \. time\b/u, /\bdatetime \./u, /\bdate \. today\b/u],
        },
        scan(context, state) {
            staticImports(context, state);
            dynamicImports(context, state);
            mainActivation(context, state);
            decorators(context, state);
        },
    });
}

export const __internals = Object.freeze({
    staticImports,
    dynamicImports,
    mainActivation,
    decorators,
});
