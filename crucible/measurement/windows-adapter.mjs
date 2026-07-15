// crucible/measurement/windows-adapter.mjs
//
// A tiny process-lifecycle adapter for the measurement executor.
//
// The executor MUST NOT talk to `child_process` directly. Instead it goes
// through this adapter, whose stop-facing operations are:
//
//   - spawn(executable, argv, options): start a child process with an explicit
//     cwd/env and no shell. On Windows a native owner creates the child
//     suspended, assigns it to a kill-on-close Job Object, then resumes it.
//     The owner also watches the caller PID, so parent death cannot orphan the
//     harness or descendants. POSIX uses a detached process group.
//
//   - terminateTree(pid, policy): stop the child and descendants **by exact
//     PID**, never by name. Owned Windows launches stop through their Job
//     Object owner; exact-PID taskkill remains the bounded fallback for
//     externally supplied PIDs. Other platforms target the detached process
//     group with SIGTERM/SIGKILL.
//
//   - closeJobObject(pid, policy): close only the Job Object owner for an
//     adapter-owned exact PID. It never falls back to a name or unrelated PID.
//
//   - activeOwnedPids()/close(): prove and drain all adapter-owned process trees.
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
import { createWindowsJobProcessAdapter } from "./windows-job-process-adapter.mjs";

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
    const jobAdapter = isWindows
        ? (options.jobProcessAdapter
            ?? createWindowsJobProcessAdapter({
                platform,
                controlRoot: options.controlRoot,
                spawnProcess,
                spawnCompiler: options.spawnCompiler,
            }))
        : null;
    const directChildren = new Map();

    const waitForDirectChildClose = (pid, child, timeoutMs) => {
        if (!directChildren.has(pid)
            || child?.exitCode !== null
            || child?.signalCode !== null) {
            return Promise.resolve(true);
        }
        return new Promise((resolve) => {
            let settled = false;
            const finish = (value) => {
                if (settled) return;
                settled = true;
                timers.clearTimeout?.(timer);
                resolve(value);
            };
            child.once("close", () => finish(true));
            const timer = timers.setTimeout(() => finish(!directChildren.has(pid)), timeoutMs);
            timer?.unref?.();
        });
    };

    const terminateTree = async (pid, termination = {}) => {
        if (!Number.isInteger(pid) || pid <= 0) return false;
        const force = termination?.force !== false;
        const timeoutMs = Number.isSafeInteger(termination?.timeoutMs)
            && termination.timeoutMs > 0
            ? Math.min(termination.timeoutMs, 60_000)
            : defaultTerminationTimeoutMs;
        if (jobAdapter?.owns(pid)) {
            return jobAdapter.terminate(pid, { ...termination, timeoutMs });
        }
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
    };

    const closeJobObject = async (pid, termination = {}) => {
        if (!Number.isSafeInteger(pid) || pid < 1 || jobAdapter === null) {
            return false;
        }
        if (!jobAdapter.owns(pid)) return false;
        const timeoutMs = Number.isSafeInteger(termination?.timeoutMs)
            && termination.timeoutMs > 0
            ? Math.min(termination.timeoutMs, 60_000)
            : defaultTerminationTimeoutMs;
        if (typeof jobAdapter.closeJobObject === "function") {
            return jobAdapter.closeJobObject(pid, {
                ...termination,
                timeoutMs,
            });
        }
        return jobAdapter.terminate(pid, {
            ...termination,
            timeoutMs,
        });
    };

    const adapter = {
        spawn(executable, argv, launchOptions) {
            if (launchOptions?.executesCandidateCode !== false
                || launchOptions?.launchPath !== "host-process-adapter") {
                throw new SandboxRequiredError(
                    "ordinary host process adapters cannot launch candidate code",
                    {
                        executesCandidateCode:
                            launchOptions?.executesCandidateCode ?? null,
                        launchPath: launchOptions?.launchPath ?? null,
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
            if (isWindows) {
                return jobAdapter.spawn(executable, argv, launchOptions);
            }
            const spawnOptions = {
                cwd: launchOptions.cwd,
                env: launchOptions.env,
                stdio: launchOptions.stdio ?? ["ignore", "pipe", "pipe"],
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
            if (Number.isSafeInteger(child?.pid) && child.pid > 0) {
                directChildren.set(child.pid, child);
                child.once("close", () => directChildren.delete(child.pid));
            }
            return child;
        },
        terminateTree,
        closeJobObject,
        activeOwnedPids() {
            const jobPids = typeof jobAdapter?.activePids === "function"
                ? jobAdapter.activePids()
                : [];
            return Object.freeze(
                [...new Set([...jobPids, ...directChildren.keys()])]
                    .sort((left, right) => left - right),
            );
        },
        async close(termination = {}) {
            let firstError = null;
            const timeoutMs = Number.isSafeInteger(termination?.timeoutMs)
                && termination.timeoutMs > 0
                ? Math.min(termination.timeoutMs, 60_000)
                : defaultTerminationTimeoutMs;
            if (jobAdapter !== null) {
                try {
                    await jobAdapter.close({ ...termination, timeoutMs });
                } catch (error) {
                    firstError = error;
                }
            }
            const directRecords = [...directChildren.entries()];
            const terminationResults = await Promise.all(
                directRecords.map(([pid]) => terminateTree(pid, {
                    force: true,
                    timeoutMs,
                    ...termination,
                })),
            );
            const closeResults = await Promise.all(
                directRecords.map(([pid, child]) =>
                    waitForDirectChildClose(pid, child, timeoutMs)),
            );
            if (firstError !== null) throw firstError;
            const activePids = adapter.activeOwnedPids();
            if (terminationResults.some((result) => result !== true)
                || closeResults.some((result) => result !== true)
                || activePids.length > 0) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
                    "Process adapter did not terminate every owned child tree",
                    { activePids },
                );
            }
            return true;
        },
    };
    return Object.freeze(adapter);
}
