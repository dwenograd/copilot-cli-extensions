// crucible/measurement/windows-adapter.mjs
//
// A tiny process-lifecycle adapter for the measurement executor.
//
// The executor MUST NOT talk to `child_process` directly. Instead it goes
// through this adapter, which exposes exactly two operations:
//
//   - spawn(executable, argv, options): start a child process on Windows
//     with shell:false, windowsHide:true, an explicit cwd, an explicit env,
//     and its own process group (detached:true on Windows creates a new
//     process group we can then tree-terminate by PID).
//
//   - terminateTree(pid, policy): stop the child and descendants **by exact
//     PID**, never by name. Windows uses bounded taskkill.exe calls, first
//     without `/F` for drain and then with `/F` for escalation. Other
//     platforms target the detached process group with SIGTERM/SIGKILL.
//
// Tests pass a fake adapter to the executor to observe termination calls
// without actually spawning processes. Production code uses the real
// adapter returned by createDefaultProcessAdapter().

import { spawn as childSpawn } from "node:child_process";
import path from "node:path";

import {
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
    SandboxRequiredError,
} from "./errors.mjs";

// System path to taskkill.exe. We resolve it via SystemRoot rather than
// trusting PATH — the whole point of the boundary is to not depend on
// PATH lookups for security-critical binaries.
function resolveTaskkill() {
    const systemRoot = process.env.SystemRoot || process.env.SYSTEMROOT || "C:\\Windows";
    return path.join(systemRoot, "System32", "taskkill.exe");
}

export function createDefaultProcessAdapter(options = {}) {
    const platform = options.platform ?? process.platform;
    const isWindows = platform === "win32";
    const spawnProcess = options.spawnProcess ?? childSpawn;
    const timers = options.timers ?? globalThis;
    const defaultTerminationTimeoutMs = options.terminationTimeoutMs ?? 5_000;
    if (!Number.isSafeInteger(defaultTerminationTimeoutMs)
        || defaultTerminationTimeoutMs < 1
        || defaultTerminationTimeoutMs > 60_000) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "terminationTimeoutMs must be a positive integer <= 60000",
        );
    }
    return Object.freeze({
        platform,
        spawn(executable, argv, options) {
            if (options?.executesCandidateCode !== false
                || options?.launchPath !== "host-process-adapter") {
                throw new SandboxRequiredError(
                    "ordinary host process adapters cannot launch candidate code",
                    {
                        executesCandidateCode:
                            options?.executesCandidateCode ?? null,
                        launchPath: options?.launchPath ?? null,
                    },
                );
            }
            if (typeof executable !== "string" || !path.isAbsolute(executable)) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                    "adapter.spawn requires an absolute executable path",
                );
            }
            if (!Array.isArray(argv)) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                    "adapter.spawn requires an argv array",
                );
            }
            const spawnOptions = {
                cwd: options.cwd,
                env: options.env,
                stdio: options.stdio ?? ["ignore", "pipe", "pipe"],
                // HARDCODED FAIL-CLOSED: never let the caller enable a shell,
                // and never let the caller un-hide the child window on Windows.
                shell: false,
                windowsHide: true,
                // A new process group so terminateTree can target it precisely.
                detached: true,
            };
            let child;
            try {
                child = spawnProcess(executable, argv, spawnOptions);
            } catch (err) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                    `failed to spawn ${executable}: ${err?.message ?? String(err)}`,
                    { executable, cause: err?.code ?? null },
                );
            }
            return child;
        },
        async terminateTree(pid, termination = {}) {
            if (!Number.isInteger(pid) || pid <= 0) return false;
            const force = termination?.force !== false;
            const timeoutMs = Number.isSafeInteger(termination?.timeoutMs)
                && termination.timeoutMs > 0
                ? Math.min(termination.timeoutMs, 60_000)
                : defaultTerminationTimeoutMs;
            if (isWindows) {
                try {
                    const args = [
                        ...(force ? ["/F"] : []),
                        "/T",
                        "/PID",
                        String(pid),
                    ];
                    const killer = spawnProcess(
                        resolveTaskkill(),
                        args,
                        {
                            shell: false,
                            windowsHide: true,
                            stdio: "ignore",
                            detached: false,
                        },
                    );
                    return await new Promise((resolve) => {
                        let settled = false;
                        let timer = null;
                        const finish = (value) => {
                            if (settled) return;
                            settled = true;
                            timers.clearTimeout?.(timer);
                            resolve(value);
                        };
                        killer.once("error", () => finish(false));
                        killer.once("close", (code) => finish(code === 0 || code === 128));
                        timer = timers.setTimeout(() => {
                            try { killer.kill(); } catch { /* bounded failure */ }
                            finish(false);
                        }, timeoutMs);
                        timer?.unref?.();
                    });
                } catch {
                    return false;
                }
            }
            try {
                // Negative pid targets the process group created by detached:true.
                process.kill(-pid, force ? "SIGKILL" : "SIGTERM");
                return true;
            } catch {
                try {
                    process.kill(pid, force ? "SIGKILL" : "SIGTERM");
                    return true;
                } catch {
                    return false;
                }
            }
        },
    });
}
