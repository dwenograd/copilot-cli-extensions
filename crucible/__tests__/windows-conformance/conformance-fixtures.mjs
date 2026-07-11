import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { threadId } from "node:worker_threads";

const systemRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT ?? "C:\\Windows";
const REG_EXE = path.join(systemRoot, "System32", "reg.exe");
const ICACLS_EXE = path.join(systemRoot, "System32", "icacls.exe");
const REGISTRY_BASE = "HKCU\\Software\\CrucibleSandboxConformance";
const PACKAGES_ROOT = path.join(
    process.env.LOCALAPPDATA ?? "",
    "Packages",
);
const SANDBOX_PROFILE_PREFIX =
    `crucible.sandbox.${process.pid}.${threadId}.`.toLowerCase();
const PROBE_PROFILE_PREFIX = "crucible.probe.";

function runNative(executable, argv, options = {}) {
    return spawnSync(executable, argv, {
        encoding: "utf8",
        windowsHide: true,
        timeout: 15_000,
        ...options,
    });
}

export function listOwnedProfiles() {
    if (!fs.existsSync(PACKAGES_ROOT)) return [];
    return fs.readdirSync(PACKAGES_ROOT)
        .filter((name) => {
            const lower = name.toLowerCase();
            return lower.startsWith(SANDBOX_PROFILE_PREFIX)
                || lower.startsWith(PROBE_PROFILE_PREFIX);
        })
        .sort();
}

export function listProviderScratch(controlRoot) {
    if (!fs.existsSync(controlRoot)) return [];
    return fs.readdirSync(controlRoot)
        .filter((name) =>
            name.startsWith("attempt-")
            || name.startsWith("probe-")
            || name.startsWith(".native-build-")
            || name.startsWith(".helper-"))
        .sort();
}

export function pidAlive(pid) {
    if (!Number.isSafeInteger(pid) || pid < 1) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

export async function waitForPidExit(pid, timeoutMs = 10_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (!pidAlive(pid)) return true;
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return !pidAlive(pid);
}

function forceKillPid(pid) {
    if (!pidAlive(pid)) return;
    try {
        process.kill(pid, "SIGKILL");
    } catch {
        // The independent assertion records the leak before cleanup.
    }
}

function normalizeRegistryKey(key) {
    const prefix = "HKCU\\Software\\CrucibleSandboxConformance\\";
    if (typeof key !== "string"
        || !key.toLowerCase().startsWith(prefix.toLowerCase())) {
        throw new Error(`registry fixture escaped owned prefix: ${key}`);
    }
    return key;
}

export function createRegistrySecret(key, value) {
    const ownedKey = normalizeRegistryKey(key);
    const result = runNative(REG_EXE, [
        "ADD",
        ownedKey,
        "/v",
        "Secret",
        "/t",
        "REG_SZ",
        "/d",
        value,
        "/f",
    ]);
    if (result.status !== 0) {
        throw new Error(`failed to create registry fixture: ${result.stderr}`);
    }
}

export function readRegistrySecret(key) {
    const ownedKey = normalizeRegistryKey(key);
    const result = runNative(REG_EXE, [
        "QUERY",
        ownedKey,
        "/v",
        "Secret",
    ]);
    if (result.status !== 0) return null;
    const match = /^\s*Secret\s+REG_SZ\s+(.*)$/imu.exec(result.stdout);
    return match?.[1]?.trim() ?? null;
}

function deleteRegistryTree(key) {
    const ownedKey = normalizeRegistryKey(key);
    runNative(REG_EXE, ["DELETE", ownedKey, "/f"]);
}

export function registryKeyExists(key) {
    const ownedKey = normalizeRegistryKey(key);
    return runNative(REG_EXE, ["QUERY", ownedKey]).status === 0;
}

function aclFingerprint(target) {
    const result = runNative(ICACLS_EXE, [target]);
    if (result.status !== 0) {
        throw new Error(`icacls failed for ${target}: ${result.stderr}`);
    }
    return result.stdout
        .replaceAll(target, "<PATH>")
        .replace(/\r\n/gu, "\n")
        .trim();
}

function walkExisting(root) {
    if (!fs.existsSync(root)) return [];
    const paths = [root];
    const stack = [root];
    while (stack.length > 0) {
        const current = stack.pop();
        const stat = fs.lstatSync(current);
        if (!stat.isDirectory() || stat.isSymbolicLink()) continue;
        for (const name of fs.readdirSync(current)) {
            const child = path.join(current, name);
            paths.push(child);
            stack.push(child);
        }
    }
    return paths.sort();
}

export class ConformanceResources {
    #aclBaselines = new Map();
    #cleanups = [];
    #controlRoot;
    #ephemeralRoots = new Set();
    #pids = new Set();
    #profileBaseline;
    #registryKeys = new Set();
    #roots = new Set();

    constructor(controlRoot) {
        this.#controlRoot = controlRoot;
        this.#profileBaseline = listOwnedProfiles();
    }

    trackRoot(root) {
        this.#roots.add(path.resolve(root));
        return root;
    }

    trackEphemeralRoot(root) {
        this.#ephemeralRoots.add(path.resolve(root));
        return root;
    }

    trackPid(pid) {
        if (Number.isSafeInteger(pid) && pid > 0) this.#pids.add(pid);
        return pid;
    }

    trackRegistryKey(key) {
        this.#registryKeys.add(normalizeRegistryKey(key));
        return key;
    }

    trackAclTree(root) {
        for (const target of walkExisting(root)) {
            this.#aclBaselines.set(target, aclFingerprint(target));
        }
    }

    trackCleanup(cleanup) {
        this.#cleanups.push(cleanup);
    }

    async cleanupAndAssert() {
        const failures = [];
        const capture = (condition, message) => {
            if (!condition) failures.push(message);
        };

        for (const pid of this.#pids) {
            capture(!pidAlive(pid), `tracked PID ${pid} survived containment`);
        }
        capture(
            JSON.stringify(listProviderScratch(this.#controlRoot)) === "[]",
            `provider scratch leaked: ${JSON.stringify(listProviderScratch(this.#controlRoot))}`,
        );
        capture(
            JSON.stringify(listOwnedProfiles())
                === JSON.stringify(this.#profileBaseline),
            `AppContainer profiles changed: before=${JSON.stringify(this.#profileBaseline)} after=${JSON.stringify(listOwnedProfiles())}`,
        );
        for (const root of this.#ephemeralRoots) {
            capture(!fs.existsSync(root), `ephemeral root survived: ${root}`);
        }
        for (const [target, expected] of this.#aclBaselines) {
            if (!fs.existsSync(target)) {
                failures.push(`ACL-tracked path disappeared: ${target}`);
                continue;
            }
            try {
                capture(
                    aclFingerprint(target) === expected,
                    `ACL changed for ${target}`,
                );
            } catch (error) {
                failures.push(error?.message ?? String(error));
            }
        }

        for (const cleanup of this.#cleanups.reverse()) {
            try {
                await cleanup();
            } catch (error) {
                failures.push(`cleanup callback failed: ${error?.message ?? String(error)}`);
            }
        }
        for (const pid of this.#pids) forceKillPid(pid);
        for (const pid of this.#pids) {
            if (!await waitForPidExit(pid, 5_000)) {
                failures.push(`tracked PID ${pid} could not be terminated`);
            }
        }
        for (const key of this.#registryKeys) {
            deleteRegistryTree(key);
            if (registryKeyExists(key)) {
                failures.push(`registry key survived cleanup: ${key}`);
            }
        }
        for (const root of [...this.#roots]
            .sort((left, right) => right.length - left.length)) {
            try {
                fs.rmSync(root, {
                    recursive: true,
                    force: true,
                    maxRetries: 20,
                    retryDelay: 25,
                });
            } catch (error) {
                failures.push(`root cleanup failed for ${root}: ${
                    error?.message ?? String(error)
                }`);
            }
            if (fs.existsSync(root)) failures.push(`root survived cleanup: ${root}`);
        }

        if (failures.length > 0) {
            throw new AggregateError(
                failures.map((message) => new Error(message)),
                "Windows conformance resource cleanup failed",
            );
        }
    }
}

export function removeOwnedRegistryRoot(key) {
    deleteRegistryTree(key);
    if (registryKeyExists(key)) {
        throw new Error(`owned registry root survived cleanup: ${key}`);
    }
}

export function removeOwnedRegistryBaseIfEmpty() {
    const query = runNative(REG_EXE, ["QUERY", REGISTRY_BASE]);
    if (query.status !== 0) return true;
    const canonicalHeader =
        "HKEY_CURRENT_USER\\Software\\CrucibleSandboxConformance";
    const content = query.stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) =>
            line.length > 0
            && line.toLowerCase() !== canonicalHeader.toLowerCase());
    if (content.length > 0) return false;
    const removed = runNative(REG_EXE, ["DELETE", REGISTRY_BASE, "/f"]);
    if (removed.status !== 0
        || runNative(REG_EXE, ["QUERY", REGISTRY_BASE]).status === 0) {
        throw new Error("empty conformance registry base survived cleanup");
    }
    return true;
}
