import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const PROCESS_IDENTITY_VERSION = 1;
const COMMAND_IDENTITY_PREFIX = "sha256:crucible-process-command-v1:";

function requirePid(pid) {
    if (!Number.isSafeInteger(pid) || pid < 1) {
        throw new TypeError("process id must be a positive safe integer");
    }
    return pid;
}

function samePath(left, right, platform) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function normalizedExecutablePath(value, platform) {
    if (typeof value !== "string" || !path.isAbsolute(value)) {
        throw new Error("process executable path is unavailable");
    }
    const resolved = path.resolve(value);
    return platform === "win32" ? resolved.toLowerCase() : resolved;
}

function commandIdentity(executablePath, argv, platform) {
    const document = JSON.stringify({
        version: PROCESS_IDENTITY_VERSION,
        executablePath: normalizedExecutablePath(executablePath, platform),
        argv,
    });
    return `${COMMAND_IDENTITY_PREFIX}${
        createHash("sha256").update(document, "utf8").digest("hex")
    }`;
}

export function parseWindowsCommandLine(commandLine) {
    if (typeof commandLine !== "string") {
        throw new TypeError("Windows command line must be a string");
    }
    const argv = [];
    let index = 0;
    while (index < commandLine.length) {
        while (index < commandLine.length
            && /[\t ]/u.test(commandLine[index])) {
            index += 1;
        }
        if (index >= commandLine.length) break;

        let value = "";
        let quoted = false;
        while (index < commandLine.length) {
            if (!quoted && /[\t ]/u.test(commandLine[index])) break;
            let slashes = 0;
            while (commandLine[index] === "\\") {
                slashes += 1;
                index += 1;
            }
            if (commandLine[index] === "\"") {
                value += "\\".repeat(Math.floor(slashes / 2));
                if (slashes % 2 === 1) {
                    value += "\"";
                    index += 1;
                } else {
                    index += 1;
                    if (quoted && commandLine[index] === "\"") {
                        value += "\"";
                        index += 1;
                    } else {
                        quoted = !quoted;
                    }
                }
                continue;
            }
            value += "\\".repeat(slashes);
            if (index >= commandLine.length) break;
            value += commandLine[index];
            index += 1;
        }
        argv.push(value);
        while (index < commandLine.length
            && /[\t ]/u.test(commandLine[index])) {
            index += 1;
        }
    }
    return Object.freeze(argv);
}

function windowsProcessStartId(pid, dependencies) {
    const command =
        `$p=Get-Process -Id ${pid} -ErrorAction SilentlyContinue; `
        + "if ($null -eq $p) { "
        + "[Console]::Out.Write('missing') "
        + "} else { "
        + "[Console]::Out.Write('windows-start-ticks:' + "
        + "$p.StartTime.ToUniversalTime().Ticks.ToString("
        + "[System.Globalization.CultureInfo]::InvariantCulture)) "
        + "}";
    const output = (dependencies.execFileSync ?? execFileSync)(
        dependencies.powershellPath ?? "powershell.exe",
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        {
            encoding: "utf8",
            windowsHide: true,
            stdio: ["ignore", "pipe", "ignore"],
            timeout: 5_000,
        },
    ).trim();
    if (output === "missing") return null;
    if (!/^windows-start-ticks:\d+$/u.test(output)) {
        throw new Error("Windows process identity probe returned invalid output");
    }
    return output;
}

function windowsObservedProcessIdentity(pid, dependencies) {
    const command =
        `$instance=Get-CimInstance -ClassName Win32_Process `
        + `-Filter "ProcessId = ${pid}" -ErrorAction Stop; `
        + "if ($null -eq $instance) { "
        + "[ordered]@{state='missing'} | ConvertTo-Json -Compress "
        + "} else { "
        + `$process=Get-Process -Id ${pid} -ErrorAction Stop; `
        + "$start='windows-start-ticks:' + "
        + "$process.StartTime.ToUniversalTime().Ticks.ToString("
        + "[System.Globalization.CultureInfo]::InvariantCulture); "
        + "[ordered]@{state='ok';processStartId=$start;"
        + "executablePath=[string]$instance.ExecutablePath;"
        + "commandLine=[string]$instance.CommandLine} "
        + "| ConvertTo-Json -Compress "
        + "}";
    const output = (dependencies.execFileSync ?? execFileSync)(
        dependencies.powershellPath ?? "powershell.exe",
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        {
            encoding: "utf8",
            windowsHide: true,
            stdio: ["ignore", "pipe", "ignore"],
            timeout: 5_000,
        },
    ).trim();
    let record;
    try {
        record = JSON.parse(output);
    } catch (error) {
        throw new Error(
            "Windows process identity probe returned invalid JSON",
            { cause: error },
        );
    }
    if (record?.state === "missing") return null;
    if (record?.state !== "ok"
        || !/^windows-start-ticks:\d+$/u.test(
            record.processStartId ?? "",
        )
        || typeof record.executablePath !== "string"
        || !path.isAbsolute(record.executablePath)
        || typeof record.commandLine !== "string"
        || record.commandLine.length === 0) {
        throw new Error("Windows process identity probe is incomplete");
    }
    const parsed = parseWindowsCommandLine(record.commandLine);
    if (parsed.length === 0) {
        throw new Error("Windows process command identity is unavailable");
    }
    return {
        processId: pid,
        processStartId: record.processStartId,
        executablePath: path.resolve(record.executablePath),
        argv: [...parsed.slice(1)],
    };
}

function linuxProcessStartId(pid, dependencies) {
    const readFile = dependencies.readFileSync ?? fs.readFileSync;
    let stat;
    try {
        stat = readFile(`/proc/${pid}/stat`, "utf8");
    } catch (error) {
        if (error?.code === "ENOENT" || error?.code === "ESRCH") return null;
        throw error;
    }
    const close = stat.lastIndexOf(")");
    if (close < 0) {
        throw new Error("Linux process stat record is malformed");
    }
    const fields = stat.slice(close + 1).trim().split(/\s+/u);
    const startTicks = fields[19];
    if (!/^\d+$/u.test(startTicks ?? "")) {
        throw new Error("Linux process start identity is missing");
    }
    const bootId = String(readFile(
        "/proc/sys/kernel/random/boot_id",
        "utf8",
    )).trim();
    if (!/^[a-f0-9-]{16,64}$/iu.test(bootId)) {
        throw new Error("Linux boot identity is invalid");
    }
    return `linux-start-ticks:${bootId.toLowerCase()}:${startTicks}`;
}

function linuxObservedProcessIdentity(pid, dependencies) {
    const readFile = dependencies.readFileSync ?? fs.readFileSync;
    const readlink = dependencies.readlinkSync ?? fs.readlinkSync;
    const processStartId = linuxProcessStartId(pid, dependencies);
    if (processStartId === null) return null;
    let executablePath;
    let commandBytes;
    try {
        executablePath = readlink(`/proc/${pid}/exe`);
        commandBytes = readFile(`/proc/${pid}/cmdline`);
    } catch (error) {
        if (error?.code === "ENOENT" || error?.code === "ESRCH") return null;
        throw error;
    }
    const commandLine = Buffer.isBuffer(commandBytes)
        ? commandBytes.toString("utf8")
        : String(commandBytes);
    const argv = commandLine.split("\0");
    if (argv.at(-1) === "") argv.pop();
    if (!path.isAbsolute(executablePath) || argv.length === 0) {
        throw new Error("Linux process command identity is unavailable");
    }
    return {
        processId: pid,
        processStartId,
        executablePath: path.resolve(executablePath),
        argv: argv.slice(1),
    };
}

function posixProcessStartId(pid, dependencies) {
    let output;
    try {
        output = (dependencies.execFileSync ?? execFileSync)(
            dependencies.psPath ?? "ps",
            ["-p", String(pid), "-o", "lstart="],
            {
                encoding: "utf8",
                windowsHide: true,
                stdio: ["ignore", "pipe", "ignore"],
                timeout: 5_000,
            },
        ).trim();
    } catch (error) {
        if (error?.status === 1) return null;
        throw error;
    }
    if (output.length === 0) return null;
    return `posix-start:${output.replace(/\s+/gu, " ")}`;
}

function observedProcessIdentity(pid, dependencies = {}) {
    const processId = requirePid(pid);
    const platform = dependencies.platform ?? process.platform;
    if (platform === "win32") {
        return windowsObservedProcessIdentity(processId, dependencies);
    }
    if (platform === "linux") {
        return linuxObservedProcessIdentity(processId, dependencies);
    }
    return null;
}

function publicProcessIdentity(observed, platform) {
    if (observed === null) return null;
    return Object.freeze({
        version: PROCESS_IDENTITY_VERSION,
        processId: observed.processId,
        processStartId: observed.processStartId,
        executablePath: path.resolve(observed.executablePath),
        commandIdentity: commandIdentity(
            observed.executablePath,
            observed.argv,
            platform,
        ),
    });
}

export function normalizeProcessIdentity(value) {
    const keys = value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        ? Object.keys(value).sort()
        : [];
    if (keys.length !== 5
        || keys[0] !== "commandIdentity"
        || keys[1] !== "executablePath"
        || keys[2] !== "processId"
        || keys[3] !== "processStartId"
        || keys[4] !== "version"
        || value.version !== PROCESS_IDENTITY_VERSION
        || !Number.isSafeInteger(value.processId)
        || value.processId < 1
        || typeof value.processStartId !== "string"
        || value.processStartId.length === 0
        || typeof value.executablePath !== "string"
        || !path.isAbsolute(value.executablePath)
        || typeof value.commandIdentity !== "string"
        || !/^sha256:crucible-process-command-v1:[a-f0-9]{64}$/u.test(
            value.commandIdentity,
        )) {
        throw new TypeError("process identity is invalid");
    }
    return Object.freeze({
        version: PROCESS_IDENTITY_VERSION,
        processId: value.processId,
        processStartId: value.processStartId,
        executablePath: path.resolve(value.executablePath),
        commandIdentity: value.commandIdentity,
    });
}

export function readProcessIdentity(pid, dependencies = {}) {
    const platform = dependencies.platform ?? process.platform;
    return publicProcessIdentity(
        observedProcessIdentity(pid, dependencies),
        platform,
    );
}

export function captureProcessIdentity({
    processId,
    executablePath,
    argv,
} = {}, dependencies = {}) {
    if (typeof executablePath !== "string" || !path.isAbsolute(executablePath)) {
        throw new TypeError("expected process executable path must be absolute");
    }
    if (!Array.isArray(argv)
        || argv.some((value) => typeof value !== "string")) {
        throw new TypeError("expected process argv must be an array of strings");
    }
    const platform = dependencies.platform ?? process.platform;
    const observed = observedProcessIdentity(processId, dependencies);
    if (observed === null) {
        throw new Error("launched process identity is unavailable");
    }
    if (!samePath(observed.executablePath, executablePath, platform)
        || observed.argv.length !== argv.length
        || observed.argv.some((value, index) => value !== argv[index])) {
        throw new Error(
            "launched process executable or command differs from the requested runner",
        );
    }
    return publicProcessIdentity(observed, platform);
}

export function readProcessStartId(
    pid,
    dependencies = {},
) {
    const processId = requirePid(pid);
    const platform = dependencies.platform ?? process.platform;
    if (platform === "win32") {
        return windowsProcessStartId(processId, dependencies);
    }
    if (platform === "linux") {
        return linuxProcessStartId(processId, dependencies);
    }
    return posixProcessStartId(processId, dependencies);
}

export function createProcessIdentityAdapter(dependencies = {}) {
    return Object.freeze({
        current(processId = process.pid) {
            const identity = readProcessStartId(processId, dependencies);
            if (identity === null) {
                throw new Error("current process identity is unavailable");
            }
            return identity;
        },
        isAlive({ processId, processStartId } = {}) {
            if (typeof processStartId !== "string"
                || processStartId.length < 1) {
                throw new TypeError("processStartId is required");
            }
            const current = readProcessStartId(processId, dependencies);
            return current !== null && current === processStartId;
        },
        inspect(processId) {
            return readProcessIdentity(processId, dependencies);
        },
        capture(input) {
            return captureProcessIdentity(input, dependencies);
        },
        matches(value) {
            const expected = normalizeProcessIdentity(value);
            let current;
            try {
                current = readProcessIdentity(
                    expected.processId,
                    dependencies,
                );
            } catch (error) {
                return Object.freeze({
                    matched: false,
                    active: null,
                    reason: "identity_probe_failed",
                    error,
                });
            }
            if (current === null) {
                return Object.freeze({
                    matched: false,
                    active: false,
                    reason: "missing",
                    current: null,
                });
            }
            const platform = dependencies.platform ?? process.platform;
            const matched = current.processId === expected.processId
                && current.processStartId === expected.processStartId
                && samePath(
                    current.executablePath,
                    expected.executablePath,
                    platform,
                )
                && current.commandIdentity === expected.commandIdentity;
            return Object.freeze({
                matched,
                active: true,
                reason: matched ? "matched" : "identity_mismatch",
                current,
            });
        },
    });
}
