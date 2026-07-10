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
//   - terminateTree(pid): kill the child and its descendants **by exact
//     PID**, never by name. On Windows this shells out to taskkill.exe with
//     `/F /T /PID <pid>`; taskkill itself is spawned with shell:false. On
//     other platforms we use process.kill(-pid, "SIGKILL") targeting the
//     process group we created via detached:true.
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

export function createDefaultProcessAdapter() {
    const isWindows = process.platform === "win32";
    return Object.freeze({
        platform: process.platform,
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
                child = childSpawn(executable, argv, spawnOptions);
            } catch (err) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                    `failed to spawn ${executable}: ${err?.message ?? String(err)}`,
                    { executable, cause: err?.code ?? null },
                );
            }
            return child;
        },
        async terminateTree(pid) {
            if (!Number.isInteger(pid) || pid <= 0) return false;
            if (isWindows) {
                try {
                    const killer = childSpawn(
                        resolveTaskkill(),
                        ["/F", "/T", "/PID", String(pid)],
                        {
                            shell: false,
                            windowsHide: true,
                            stdio: "ignore",
                            detached: false,
                        },
                    );
                    return await new Promise((resolve) => {
                        let settled = false;
                        const finish = (value) => {
                            if (settled) return;
                            settled = true;
                            resolve(value);
                        };
                        killer.once("error", () => finish(false));
                        killer.once("close", (code) => finish(code === 0 || code === 128));
                    });
                } catch {
                    return false;
                }
            }
            try {
                // Negative pid targets the process group created by detached:true.
                process.kill(-pid, "SIGKILL");
                return true;
            } catch {
                try {
                    process.kill(pid, "SIGKILL");
                    return true;
                } catch {
                    return false;
                }
            }
        },
    });
}
