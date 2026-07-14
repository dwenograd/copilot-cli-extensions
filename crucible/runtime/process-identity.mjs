import fs from "node:fs";
import { execFileSync } from "node:child_process";

function requirePid(pid) {
    if (!Number.isSafeInteger(pid) || pid < 1) {
        throw new TypeError("process id must be a positive safe integer");
    }
    return pid;
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
    });
}
