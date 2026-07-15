import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    parseRecoveryLauncherAction,
} from "../crucible/tools/recovery-launcher.mjs";
import {
    acquireRecoveryTaskConformanceLock,
    cleanupRecoveryTaskFixtureRoots,
    releaseRecoveryTaskConformanceLock,
} from "../crucible/__tests__/windows-conformance/recovery-task-fixture.mjs";
import { removeTreeRobust } from "../crucible/__tests__/test-cleanup.mjs";

export const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CRUCIBLE = path.join(ROOT, "crucible");
const TESTS = path.join(CRUCIBLE, "__tests__");
const WINDOWS_CONFORMANCE = path.join(TESTS, "windows-conformance");
const VITEST = path.join(ROOT, "node_modules", "vitest", "vitest.mjs");
const TEST_ROOT_MARKER = ".crucible-test-root.json";
const INVENTORY_PARENTS = Object.freeze([
    ROOT,
    CRUCIBLE,
    TESTS,
    WINDOWS_CONFORMANCE,
]);
const OWNED_ROOT_INVENTORY = Object.freeze([
    Object.freeze({
        parent: ROOT,
        prefixes: Object.freeze([".e-"]),
        markerRequired: true,
    }),
    Object.freeze({
        parent: CRUCIBLE,
        prefixes: Object.freeze([".e-"]),
        markerRequired: true,
    }),
    Object.freeze({
        parent: TESTS,
        prefixes: Object.freeze([
            ".api-lifecycle-",
            ".api-preflight-",
            ".measure-tmp-",
            ".persist-tmp-",
            ".recovery-catalog-",
            ".recovery-daemon-release-",
            ".recovery-task-",
            ".resource-broker-release-",
            ".runtime-control-",
            ".runtime-identity-",
            ".runtime-runner-",
            ".runtime-supervisor-",
            ".sdk-retry-",
            ".segments-release-",
            ".v4-unattended-",
            ".working-set-",
        ]),
    }),
    Object.freeze({
        parent: WINDOWS_CONFORMANCE,
        prefixes: Object.freeze([
            ".recovery-identity-task-conformance-",
            ".recovery-task-conformance-",
        ]),
    }),
]);
const TEST_PROCESS_MARKERS = Object.freeze([
    "vitest.crucible-unattended.config.mjs",
    "runtime-runner.release.test.mjs",
    "run-crucible-integration.mjs",
    "runtime-sdk-cli.integration.test.mjs",
    "run-crucible-windows-conformance.mjs",
    "runtime-runner-kill-worker.mjs",
    "supervisor-kill-worker.mjs",
    "segment-rotation-kill-worker.mjs",
    "resource-broker-process.mjs",
    "recovery-daemon-kill-worker.mjs",
]);

export function listOwnedRoots() {
    const roots = [];
    for (const parent of INVENTORY_PARENTS) {
        if (!fs.existsSync(parent)) continue;
        for (const entry of fs.readdirSync(parent, { withFileTypes: true })) {
            if (entry.isDirectory()
                || entry.isSymbolicLink()
                || entry.name.startsWith(".")) {
                roots.push(path.join(parent, entry.name));
            }
        }
    }
    return [...new Set(roots)].sort();
}

function immediateChildName(parent, candidate) {
    const relative = path.relative(parent, path.resolve(candidate));
    if (relative.length === 0
        || relative === ".."
        || relative.startsWith(`..${path.sep}`)
        || path.isAbsolute(relative)
        || relative.includes(path.sep)) {
        return null;
    }
    return relative;
}

export function isRecognizedOwnedRoot(candidate) {
    return OWNED_ROOT_INVENTORY.some(({
        parent,
        prefixes,
        markerRequired = false,
    }) => {
        const name = immediateChildName(parent, candidate);
        return name !== null
            && prefixes.some((prefix) => name.startsWith(prefix))
            && (!markerRequired || hasTestRootMarker(candidate));
    });
}

function hasTestRootMarker(candidate) {
    const marker = path.join(candidate, TEST_ROOT_MARKER);
    try {
        const stat = fs.lstatSync(marker);
        if (!stat.isFile() || stat.isSymbolicLink()) return false;
        const value = JSON.parse(fs.readFileSync(marker, "utf8"));
        const expected = process.platform === "win32"
            ? path.resolve(candidate).toLowerCase()
            : path.resolve(candidate);
        const observed = process.platform === "win32"
            ? path.resolve(value?.root ?? "").toLowerCase()
            : path.resolve(value?.root ?? "");
        return value?.version === 1
            && value?.kind === "crucible-api-e2e-test-root"
            && observed === expected;
    } catch {
        return false;
    }
}

export function listRecognizedOwnedRoots() {
    const roots = [];
    for (const {
        parent,
        prefixes,
        markerRequired = false,
    } of OWNED_ROOT_INVENTORY) {
        if (!fs.existsSync(parent)) continue;
        for (const entry of fs.readdirSync(parent, { withFileTypes: true })) {
            if ((entry.isDirectory() || entry.isSymbolicLink())
                && prefixes.some((prefix) => entry.name.startsWith(prefix))) {
                const candidate = path.join(parent, entry.name);
                if (!markerRequired || hasTestRootMarker(candidate)) {
                    roots.push(candidate);
                }
            }
        }
    }
    return [...new Set(roots)].sort();
}

export function isTestOwnedTask(task) {
    try {
        const parsed = parseRecoveryLauncherAction(task?.arguments);
        const args = parsed.manifest.arguments;
        const stateRootIndex = args.indexOf("--state-root");
        return stateRootIndex >= 0
            && typeof args[stateRootIndex + 1] === "string"
            && isRecognizedOwnedRoot(args[stateRootIndex + 1]);
    } catch {
        return false;
    }
}

export function isTestOwnedProcess(processRecord, ownedRoots = []) {
    const command = String(processRecord?.command ?? "").toLowerCase();
    if (ownedRoots.some((root) =>
        command.includes(path.resolve(root).toLowerCase()))) {
        return true;
    }
    return TEST_PROCESS_MARKERS.some((marker) =>
        command.includes(marker.toLowerCase()));
}

function testOwnedProcesses(records, ownedRoots = []) {
    const owned = new Map();
    for (const record of records) {
        if (isTestOwnedProcess(record, ownedRoots)) {
            owned.set(record.pid, record);
        }
    }
    for (;;) {
        let changed = false;
        for (const record of records) {
            if (!owned.has(record.pid) && owned.has(record.parentPid)) {
                owned.set(record.pid, record);
                changed = true;
            }
        }
        if (!changed) return [...owned.values()];
    }
}

function powershellSnapshot() {
    if (process.platform !== "win32") {
        return {
            tasks: [],
            processes: [],
            profiles: [],
            registry: "",
            userEnvironment: null,
        };
    }
    const command = String.raw`
$ErrorActionPreference = "Stop"
$root = $env:CRUCIBLE_UNATTENDED_EXTENSION_ROOT
$tasks = @(
    Get-ScheduledTask -TaskPath "\Crucible\" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $action = @($_.Actions)[0]
            [ordered]@{
                identity = "$($_.TaskPath)$($_.TaskName)"
                execute = [string]$action.Execute
                arguments = [string]$action.Arguments
            }
        }
)
$processes = @(
    Get-CimInstance Win32_Process |
        Where-Object {
            $null -ne $_.CommandLine -and
            $_.CommandLine.Contains($root)
        } |
        ForEach-Object {
            [ordered]@{
                pid = [int]$_.ProcessId
                parentPid = [int]$_.ParentProcessId
                name = [string]$_.Name
                creationDate = [string]$_.CreationDate
                command = [string]$_.CommandLine
            }
        }
)
$packages = Join-Path $env:LOCALAPPDATA "Packages"
$profiles = if (Test-Path -LiteralPath $packages) {
    @(
        Get-ChildItem -LiteralPath $packages -Directory |
            Where-Object {
                $_.Name -like "crucible.sandbox.*" -or
                $_.Name -like "crucible.probe.*"
            } |
            ForEach-Object { $_.Name }
    )
}
else { @() }
$registryPath = "Registry::HKEY_CURRENT_USER\Software\CrucibleSandboxConformance"
$registry = if (Test-Path -LiteralPath $registryPath) {
    (& reg.exe QUERY "HKCU\Software\CrucibleSandboxConformance" /s) -join [Environment]::NewLine
}
else { "" }
$environmentKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $false)
try {
    $environmentValue = if ($null -eq $environmentKey) {
        [ordered]@{ exists = $false; kind = $null; value = $null }
    }
    else {
        $name = "CRUCIBLE_EXPERIMENT_PUBLIC_KEY"
        $value = $environmentKey.GetValue(
            $name,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        if ($null -eq $value) {
            [ordered]@{ exists = $false; kind = $null; value = $null }
        }
        else {
            [ordered]@{
                exists = $true
                kind = [string]$environmentKey.GetValueKind($name)
                value = [string]$value
            }
        }
    }
}
finally {
    if ($null -ne $environmentKey) { $environmentKey.Dispose() }
}
[ordered]@{
    tasks = @($tasks | Sort-Object identity)
    processes = @($processes | Sort-Object pid)
    profiles = @($profiles | Sort-Object)
    registry = [string]$registry
    userEnvironment = $environmentValue
} | ConvertTo-Json -Depth 5 -Compress
`;
    const result = spawnSync(
        "powershell.exe",
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        {
            encoding: "utf8",
            env: {
                ...process.env,
                CRUCIBLE_UNATTENDED_EXTENSION_ROOT: ROOT,
            },
            windowsHide: true,
            maxBuffer: 16 * 1024 * 1024,
        },
    );
    if (result.error !== undefined || result.status !== 0) {
        const cause = result.error ?? new Error(
            `PowerShell snapshot exited ${result.status ?? "null"}; `
            + `signal=${result.signal ?? "none"}; stderr=${result.stderr}`,
        );
        throw new Error(
            "failed to capture unattended host state",
            { cause },
        );
    }
    return JSON.parse(result.stdout);
}

function pidAlive(pid) {
    if (!Number.isSafeInteger(pid) || pid < 1) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

async function terminateOwnedProcesses(records) {
    const failures = [];
    for (const record of records) {
        if (record.pid === process.pid) continue;
        try {
            process.kill(record.pid, "SIGKILL");
        } catch (error) {
            if (error?.code !== "ESRCH") failures.push(error);
        }
    }
    const deadline = Date.now() + 10_000;
    let remaining = records.filter((record) =>
        record.pid !== process.pid && pidAlive(record.pid));
    while (remaining.length > 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 50));
        remaining = remaining.filter((record) => pidAlive(record.pid));
    }
    if (remaining.length > 0) {
        failures.push(new Error(
            `test-owned processes could not be terminated: ${
                JSON.stringify(remaining)
            }`,
        ));
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            "Crucible unattended process cleanup failed",
        );
    }
}

function clearRegistryFixture() {
    if (process.platform !== "win32") return;
    const command = String.raw`
$ErrorActionPreference = "Stop"
$path = "Registry::HKEY_CURRENT_USER\Software\CrucibleSandboxConformance"
if (Test-Path -LiteralPath $path) {
    Remove-Item -LiteralPath $path -Recurse -Force
}
if (Test-Path -LiteralPath $path) {
    throw "Crucible conformance registry fixture survived cleanup"
}
`;
    const result = spawnSync(
        "powershell.exe",
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        {
            encoding: "utf8",
            windowsHide: true,
        },
    );
    if (result.error !== undefined || result.status !== 0) {
        throw new Error(
            "failed to remove the Crucible conformance registry fixture",
            {
                cause: result.error ?? new Error(
                    `registry cleanup exited ${
                        result.status ?? "null"
                    }; stderr=${result.stderr}`,
                ),
            },
        );
    }
}

export function assertCleanOwnedHost(state) {
    const failures = [];
    const roots = state.roots.filter(isRecognizedOwnedRoot);
    if (roots.length > 0) {
        failures.push(new Error(
            `test-owned roots remain: ${JSON.stringify(roots)}`,
        ));
    }
    const processes = testOwnedProcesses(state.processes, roots);
    if (processes.length > 0) {
        failures.push(new Error(
            `test-owned processes remain: ${JSON.stringify(processes)}`,
        ));
    }
    const tasks = state.tasks.filter(isTestOwnedTask);
    if (tasks.length > 0) {
        failures.push(new Error(
            `test-owned scheduled tasks remain: ${JSON.stringify(tasks)}`,
        ));
    }
    if (state.profiles.length > 0) {
        failures.push(new Error(
            `test-owned AppContainer profiles remain: ${
                JSON.stringify(state.profiles)
            }`,
        ));
    }
    if (state.registry.length > 0) {
        failures.push(new Error(
            "test-owned conformance registry state remains",
        ));
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            "Crucible unattended host is not clean",
        );
    }
}

async function cleanupRecognizedOwnedArtifacts() {
    const roots = listRecognizedOwnedRoots();
    const initial = powershellSnapshot();
    const processes = testOwnedProcesses(initial.processes, roots);
    const failures = [];
    try {
        await terminateOwnedProcesses(processes);
    } catch (error) {
        failures.push(error);
    }
    for (const root of roots) {
        try {
            await removeTreeRobust(root, {
                label: "unattended test-owned root",
                timeoutMs: 30_000,
            });
        } catch (error) {
            failures.push(error);
        }
    }
    try {
        clearRegistryFixture();
    } catch (error) {
        failures.push(error);
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            "Crucible unattended cleanup was incomplete",
        );
    }
}

export function snapshot() {
    return {
        roots: listOwnedRoots(),
        ...powershellSnapshot(),
    };
}

function canonical(value) {
    return JSON.stringify(value);
}

export function assertNoLeaks(before, after) {
    const failures = [];
    for (const key of ["roots", "tasks", "profiles", "userEnvironment"]) {
        if (canonical(after[key]) !== canonical(before[key])) {
            failures.push(new Error(
                `${key} changed: before=${canonical(before[key])} after=${
                    canonical(after[key])
                }`,
            ));
        }
    }
    const beforeProcesses = new Set(before.processes.map((entry) =>
        `${entry.pid}:${entry.creationDate ?? ""}`));
    const newProcesses = after.processes.filter((entry) =>
        !beforeProcesses.has(`${entry.pid}:${entry.creationDate ?? ""}`));
    if (newProcesses.length > 0) {
        failures.push(new Error(
            `test-owned processes survived: ${canonical(newProcesses)}`,
        ));
    }
    if (after.registry !== before.registry) {
        failures.push(new Error("test-owned registry state changed"));
    }
    if (failures.length > 0) {
        throw new AggregateError(
            failures,
            "Crucible unattended release cleanup failed",
        );
    }
}

function tail(value, limit = 8_000) {
    const text = typeof value === "string" ? value : "";
    return text.length <= limit ? text : text.slice(-limit);
}

export function runPhase(label, executable, args, env = process.env) {
    process.stdout.write(`[crucible unattended] ${label}\n`);
    const result = spawnSync(executable, args, {
        cwd: ROOT,
        encoding: "utf8",
        env,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
        maxBuffer: 64 * 1024 * 1024,
    });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error !== undefined) {
        throw new Error(`${label} failed to start`, {
            cause: result.error,
        });
    }
    if (result.status !== 0) {
        const diagnostics = new Error(
            `${label} child diagnostics: status=${
                result.status ?? "null"
            }; signal=${result.signal ?? "none"}; stdoutTail=${
                JSON.stringify(tail(result.stdout))
            }; stderrTail=${JSON.stringify(tail(result.stderr))}`,
        );
        throw new Error(
            `${label} failed with exit ${result.status ?? "unknown"}${
                result.signal === null ? "" : ` and signal ${result.signal}`
            }`,
            { cause: diagnostics },
        );
    }
}

export function formatFailure(error, indent = "") {
    if (!(error instanceof Error)) return `${indent}${String(error)}`;
    const lines = [
        `${indent}${error.stack ?? `${error.name}: ${error.message}`}`,
    ];
    if (error instanceof AggregateError) {
        error.errors.forEach((nested, index) => {
            lines.push(`${indent}  [error ${index + 1}]`);
            lines.push(formatFailure(nested, `${indent}    `));
        });
    }
    if (error.cause !== undefined) {
        lines.push(`${indent}  [cause]`);
        lines.push(formatFailure(error.cause, `${indent}    `));
    }
    return lines.join("\n");
}

async function cleanupSchedulerFixtures() {
    const lock = await acquireRecoveryTaskConformanceLock(
        WINDOWS_CONFORMANCE,
        180_000,
    );
    try {
        return await cleanupRecoveryTaskFixtureRoots(WINDOWS_CONFORMANCE);
    } finally {
        releaseRecoveryTaskConformanceLock(lock);
    }
}

export async function cleanOwnedHost() {
    await cleanupSchedulerFixtures();
    await cleanupRecognizedOwnedArtifacts();
    const state = snapshot();
    assertCleanOwnedHost(state);
    return state;
}

export async function main(argv = process.argv.slice(2)) {
    const safeOnly = argv.includes("--safe-only");
    let before = null;
    let primaryFailure = null;
    try {
        before = await cleanOwnedHost();
        runPhase(
            "credential-free lifecycle/recovery matrix",
            process.execPath,
            [
                VITEST,
                "run",
                "--config",
                path.join(ROOT, "vitest.crucible-unattended.config.mjs"),
            ],
        );
        runPhase(
            "runner hard-kill and ambiguous-effect matrix",
            process.execPath,
            [
                VITEST,
                "run",
                "--config",
                path.join(ROOT, "vitest.crucible-release.config.mjs"),
                "crucible/__tests__/runtime-runner.release.test.mjs",
                "--testNamePattern",
                "recovers deterministically after a hard kill|owns the exact harness process tree|blocks automatic replay after an uncertain",
            ],
        );
        if (!safeOnly) {
            runPhase(
                "authenticated Copilot SDK/CLI integration",
                process.execPath,
                [path.join(ROOT, "scripts", "run-crucible-integration.mjs")],
            );
            runPhase(
                "Windows containment and Task Scheduler conformance",
                process.execPath,
                [
                    path.join(
                        ROOT,
                        "scripts",
                        "run-crucible-windows-conformance.mjs",
                    ),
                ],
                {
                    ...process.env,
                    CRUCIBLE_RUN_TASK_SCHEDULER_CONFORMANCE: "1",
                },
            );
        }
    } catch (error) {
        primaryFailure = error;
    } finally {
        const cleanupFailures = [];
        let after = null;
        try {
            after = await cleanOwnedHost();
        } catch (error) {
            cleanupFailures.push(error);
        }
        if (before !== null && after !== null) {
            try {
                assertNoLeaks(before, after);
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (cleanupFailures.length > 0) {
            const cleanupError = new AggregateError(
                cleanupFailures,
                "Crucible unattended release fail-safe cleanup failed",
            );
            primaryFailure = primaryFailure === null
                ? cleanupError
                : new AggregateError(
                    [primaryFailure, cleanupError],
                    "Crucible unattended release failed",
                );
        }
    }

    if (primaryFailure !== null) {
        process.stderr.write(
            `[crucible unattended] ${formatFailure(primaryFailure)}\n`,
        );
        return 1;
    }
    process.stdout.write(
        `[crucible unattended] ${
            safeOnly ? "release-safe" : "full"
        } gate passed with no test-owned leaks\n`,
    );
    return 0;
}

const isEntrypoint = process.argv[1] !== undefined
    && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
    process.exitCode = await main();
}
