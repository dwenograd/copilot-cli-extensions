import nodePath from "node:path";

import { scanCmakeSource, scanMakeSource } from "./build.mjs";
import { scanDevcontainerSource, scanDockerfileSource } from "./container.mjs";
import { scanCSharpSource, scanMsbuildXmlSource } from "./dotnet.mjs";
import { scanGenericSource } from "./generic.mjs";
import { scanJavaScriptSource } from "./javascript.mjs";
import { scanJsonSource } from "./json.mjs";
import { scanPythonSource } from "./python.mjs";
import { scanCargoTomlSource, scanRustSource } from "./rust.mjs";
import { scanShellSource } from "./shell.mjs";
import { scanYamlSource } from "./yaml.mjs";

function normalizedPath(path) {
    return String(path || "").replace(/\\/g, "/").toLowerCase();
}

function basename(path) {
    return nodePath.posix.basename(normalizedPath(path));
}

function definition(id, language, supports, scan) {
    return Object.freeze({ id, language, supports, scan });
}

const JAVASCRIPT_EXTENSIONS =
    /\.(?:js|cjs|mjs|jsx|ts|cts|mts|tsx)$/u;
const SHELL_EXTENSIONS =
    /\.(?:ps1|psm1|psd1|sh|bash|zsh|fish|ksh|cmd|bat)$/u;
const MSBUILD_EXTENSIONS =
    /\.(?:csproj|fsproj|vbproj|vcxproj|props|targets|proj)$/u;

export const SCANNER_REGISTRY = Object.freeze([
    definition(
        "scanner.docker-devcontainer",
        "devcontainer-json",
        (path) => normalizedPath(path).startsWith(".devcontainer/")
            && basename(path).endsWith(".json"),
        scanDevcontainerSource,
    ),
    definition(
        "scanner.docker-devcontainer",
        "dockerfile",
        (path) => /^(?:dockerfile|containerfile)(?:\..+)?$/u.test(basename(path)),
        scanDockerfileSource,
    ),
    definition(
        "scanner.msbuild-xml",
        "msbuild-xml",
        (path) => MSBUILD_EXTENSIONS.test(normalizedPath(path))
            || ["directory.build.props", "directory.build.targets"].includes(basename(path)),
        scanMsbuildXmlSource,
    ),
    definition(
        "scanner.cargo-toml",
        "cargo-toml",
        (path) => basename(path) === "cargo.toml"
            || normalizedPath(path).endsWith("/.cargo/config.toml")
            || normalizedPath(path) === ".cargo/config.toml",
        scanCargoTomlSource,
    ),
    definition(
        "scanner.cmake-make",
        "cmake",
        (path) => basename(path) === "cmakelists.txt"
            || basename(path).endsWith(".cmake"),
        scanCmakeSource,
    ),
    definition(
        "scanner.cmake-make",
        "make",
        (path) => ["makefile", "gnumakefile", "bsdmakefile"].includes(basename(path))
            || basename(path).endsWith(".mk"),
        scanMakeSource,
    ),
    definition(
        "scanner.yaml-github-actions",
        "yaml",
        (path) => /\.ya?ml$/u.test(normalizedPath(path)),
        scanYamlSource,
    ),
    definition(
        "scanner.json-jsonc",
        "json-jsonc",
        (path) => /\.jsonc?$/u.test(normalizedPath(path)),
        scanJsonSource,
    ),
    definition(
        "scanner.javascript-typescript",
        "javascript-typescript",
        (path) => JAVASCRIPT_EXTENSIONS.test(normalizedPath(path)),
        scanJavaScriptSource,
    ),
    definition(
        "scanner.python",
        "python",
        (path) => /\.(?:py|pyw|pyi)$/u.test(normalizedPath(path))
            || basename(path) === "sconstruct",
        scanPythonSource,
    ),
    definition(
        "scanner.powershell-shell",
        "powershell-shell",
        (path) => SHELL_EXTENSIONS.test(normalizedPath(path)),
        scanShellSource,
    ),
    definition(
        "scanner.csharp",
        "csharp",
        (path) => /\.(?:cs|csx)$/u.test(normalizedPath(path)),
        scanCSharpSource,
    ),
    definition(
        "scanner.rust",
        "rust",
        (path) => /\.rs$/u.test(normalizedPath(path)),
        scanRustSource,
    ),
    definition(
        "scanner.generic",
        "generic", () => true,
        scanGenericSource,
    ),
]);

export function selectScanner(path, registry = SCANNER_REGISTRY) {
    if (!Array.isArray(registry)) throw new TypeError("scanner registry must be an array");
    const scanner = registry.find((entry) => entry.supports(path) === true);
    if (!scanner) throw new Error("scanner registry must include a generic fallback");
    return scanner;
}

export function getScannerRegistry() {
    return SCANNER_REGISTRY;
}

export const __internals = Object.freeze({
    normalizedPath,
    basename,
    definition,
});
