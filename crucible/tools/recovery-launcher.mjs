import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";

import { canonicalize } from "../persistence/canonical.mjs";
import {
    DEFAULT_RUNTIME_IDENTITY_POLICY,
} from "../domain/runtime-authority.mjs";
import { parseWindowsCommandLine } from "../runtime/process-identity.mjs";

export const RECOVERY_LAUNCH_MANIFEST_KIND =
    "crucible-recovery-launch-manifest";
export const RECOVERY_LAUNCH_MANIFEST_VERSION = 1;
export const RECOVERY_LAUNCH_TRUST_ENVIRONMENT_KEYS = Object.freeze([
    "CRUCIBLE_EXPERIMENT_PUBLIC_KEY",
    "CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH",
    "CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT",
]);
export const RECOVERY_LAUNCHER_AUTHORITY_BOUNDARY = Object.freeze({
    trustedBeforeVerification: Object.freeze([
        "exact-task-action",
        "windows-powershell-dotnet-host",
    ]),
    pinnedAndHeldOpen: Object.freeze([
        "launcher-host",
        "node-executable",
        "crucible-production-esm",
    ]),
    excludedFromTaskManifest: Object.freeze([
        "node-builtins",
        "windows-loader-dependencies",
        "per-investigation-signed-runtime-inputs",
    ]),
});

const HASH_RE = /^sha256:[a-f0-9]{64}$/u;
const EXCLUDED_TOP_LEVEL_DIRECTORIES = new Set([
    "__tests__",
    "scripts",
    "tools",
]);
const POWERSHELL_ARGUMENT_PREFIX = Object.freeze([
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
]);
const MAX_ACTION_ARGUMENT_CHARACTERS = 32_000;
const MAX_ENVIRONMENT_VALUE_CHARACTERS = 32_768;
const RECOVERY_ENVIRONMENT_KEYS = Object.freeze([
    ...DEFAULT_RUNTIME_IDENTITY_POLICY.environmentKeys,
    ...RECOVERY_LAUNCH_TRUST_ENVIRONMENT_KEYS.filter((name) =>
        !DEFAULT_RUNTIME_IDENTITY_POLICY.environmentKeys.includes(name)),
]);
const POWERSHELL_ENVIRONMENT_NAMES =
    RECOVERY_ENVIRONMENT_KEYS
        .map((name) => `'${name}'`)
        .join(",");

function sha256Bytes(bytes) {
    return `sha256:${
        createHash("sha256").update(bytes).digest("hex")
    }`;
}

function samePath(left, right, platform = process.platform) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function requireAbsolutePath(value, field) {
    if (typeof value !== "string" || !path.isAbsolute(value)) {
        throw new TypeError(`${field} must be an absolute path`);
    }
    return path.resolve(value);
}

function resolveRegularPath(value, field) {
    const requested = requireAbsolutePath(value, field);
    const stat = fs.lstatSync(requested, { bigint: true });
    const real = fs.realpathSync.native(requested);
    if (!stat.isFile()
        || stat.isSymbolicLink()
        || !samePath(requested, real)) {
        throw new Error(
            `${field} must be a regular file without symlink or reparse traversal`,
        );
    }
    return Object.freeze({ path: requested, stat });
}

function resolveRegularDirectory(value, field) {
    const requested = requireAbsolutePath(value, field);
    const stat = fs.lstatSync(requested, { bigint: true });
    const real = fs.realpathSync.native(requested);
    if (!stat.isDirectory()
        || stat.isSymbolicLink()
        || !samePath(requested, real)) {
        throw new Error(
            `${field} must be a regular directory without symlink or reparse traversal`,
        );
    }
    return requested;
}

function statIdentity(stat) {
    return [
        stat.dev,
        stat.ino,
        stat.size,
        stat.mtimeNs,
        stat.ctimeNs,
        stat.birthtimeNs,
    ].map(String).join(":");
}

function hashOpenRegularFile(file, initialStat) {
    const fd = fs.openSync(file, "r");
    try {
        const openedBefore = fs.fstatSync(fd, { bigint: true });
        if (statIdentity(initialStat) !== statIdentity(openedBefore)) {
            throw new Error("recovery runtime file changed before hashing");
        }
        const hash = createHash("sha256");
        const buffer = Buffer.allocUnsafe(1024 * 1024);
        let offset = 0;
        for (;;) {
            const bytes = fs.readSync(
                fd,
                buffer,
                0,
                buffer.length,
                offset,
            );
            if (bytes === 0) break;
            hash.update(buffer.subarray(0, bytes));
            offset += bytes;
        }
        const openedAfter = fs.fstatSync(fd, { bigint: true });
        if (statIdentity(openedBefore) !== statIdentity(openedAfter)) {
            throw new Error("recovery runtime file changed while hashing");
        }
        return Object.freeze({
            sha256: `sha256:${hash.digest("hex")}`,
            size: Number(openedAfter.size),
        });
    } finally {
        fs.closeSync(fd);
    }
}

export function hashRecoveryLaunchFile(file, field = "recovery launch file") {
    const resolved = resolveRegularPath(file, field);
    return Object.freeze({
        path: resolved.path,
        ...hashOpenRegularFile(resolved.path, resolved.stat),
    });
}

function manifestRelativePath(root, file) {
    const relative = path.relative(root, file);
    if (relative.length === 0
        || relative.startsWith("..")
        || path.isAbsolute(relative)) {
        throw new Error("recovery runtime file escaped its manifest root");
    }
    return relative.split(path.sep).join("/");
}

function collectProductionEsmFiles(root) {
    const files = [];
    const walk = (directory, relativeSegments) => {
        const entries = fs.readdirSync(directory, { withFileTypes: true })
            .sort((left, right) => left.name.localeCompare(right.name));
        for (const entry of entries) {
            const absolute = path.join(directory, entry.name);
            const relative = [...relativeSegments, entry.name];
            const stat = fs.lstatSync(absolute, { bigint: true });
            const real = fs.realpathSync.native(absolute);
            if (stat.isSymbolicLink() || !samePath(absolute, real)) {
                throw new Error(
                    "recovery runtime closure contains a symlink or reparse point",
                );
            }
            if (entry.isDirectory()) {
                if (relative.length === 1
                    && EXCLUDED_TOP_LEVEL_DIRECTORIES.has(entry.name)) {
                    continue;
                }
                walk(absolute, relative);
                continue;
            }
            if (!entry.isFile()
                || path.extname(entry.name).toLowerCase() !== ".mjs"
                || (relative.length === 1
                    && entry.name === "extension.mjs")) {
                continue;
            }
            const identity = hashOpenRegularFile(absolute, stat);
            files.push(Object.freeze({
                path: manifestRelativePath(root, absolute),
                sha256: identity.sha256,
                size: identity.size,
            }));
        }
    };
    walk(root, []);
    return Object.freeze(files.sort((left, right) =>
        left.path.localeCompare(right.path)));
}

function normalizeArguments(values) {
    if (!Array.isArray(values)
        || values.some((value) =>
            typeof value !== "string"
            || value.length > 32_768
            || value.includes("\0"))) {
        throw new TypeError(
            "recovery daemon arguments must be bounded strings",
        );
    }
    return Object.freeze([...values]);
}

function environmentValue(env, name) {
    if (Object.hasOwn(env, name) && typeof env[name] === "string") {
        return env[name];
    }
    const actual = Object.keys(env).find((key) =>
        key.toLowerCase() === name.toLowerCase()
        && typeof env[key] === "string");
    return actual === undefined ? null : env[actual];
}

export function captureRecoveryLaunchEnvironment(env = process.env) {
    const variables = RECOVERY_ENVIRONMENT_KEYS
        .map((name) => {
            const value = environmentValue(env, name);
            if (value !== null
                && (value.length > MAX_ENVIRONMENT_VALUE_CHARACTERS
                    || value.includes("\0"))) {
                throw new TypeError(
                    `recovery environment ${name} is invalid`,
                );
            }
            if (["NODE_OPTIONS", "NODE_PATH"].includes(name)
                && value !== null
                && value.length > 0) {
                throw new Error(
                    `${name} must be absent for scheduled recovery`,
                );
            }
            return Object.freeze({
                name,
                present: value !== null,
                value,
            });
        });
    return Object.freeze({
        variables: Object.freeze(variables),
    });
}

function exactKeys(value, expected) {
    return value !== null
        && typeof value === "object"
        && !Array.isArray(value)
        && JSON.stringify(Object.keys(value).sort())
            === JSON.stringify([...expected].sort());
}

export function validateRecoveryLaunchManifest(value) {
    if (!exactKeys(value, [
        "arguments",
        "authorityBoundary",
        "entry",
        "environment",
        "files",
        "kind",
        "launcherHost",
        "node",
        "root",
        "version",
    ])
        || value.version !== RECOVERY_LAUNCH_MANIFEST_VERSION
        || value.kind !== RECOVERY_LAUNCH_MANIFEST_KIND
        || !exactKeys(value.authorityBoundary, [
            "excludedFromTaskManifest",
            "pinnedAndHeldOpen",
            "trustedBeforeVerification",
        ])
        || JSON.stringify(
            value.authorityBoundary.trustedBeforeVerification,
        ) !== JSON.stringify(
            RECOVERY_LAUNCHER_AUTHORITY_BOUNDARY
                .trustedBeforeVerification,
        )
        || JSON.stringify(
            value.authorityBoundary.pinnedAndHeldOpen,
        ) !== JSON.stringify(
            RECOVERY_LAUNCHER_AUTHORITY_BOUNDARY.pinnedAndHeldOpen,
        )
        || JSON.stringify(
            value.authorityBoundary.excludedFromTaskManifest,
        ) !== JSON.stringify(
            RECOVERY_LAUNCHER_AUTHORITY_BOUNDARY
                .excludedFromTaskManifest,
        )
        || typeof value.root !== "string"
        || !path.isAbsolute(value.root)
        || typeof value.entry !== "string"
        || path.isAbsolute(value.entry)
        || value.entry.includes("\\")
        || value.entry.split("/").some((part) =>
            part.length === 0 || part === "." || part === "..")
        || !Array.isArray(value.files)
        || value.files.length < 1
        || value.files.length > 512
        || !exactKeys(value.environment, ["variables"])
        || !Array.isArray(value.environment.variables)
        || value.environment.variables.length
            !== RECOVERY_ENVIRONMENT_KEYS.length
        || !exactKeys(value.node, ["path", "sha256", "size"])
        || !exactKeys(value.launcherHost, ["path", "sha256", "size"])
        || typeof value.node.path !== "string"
        || !path.isAbsolute(value.node.path)
        || typeof value.launcherHost.path !== "string"
        || !path.isAbsolute(value.launcherHost.path)
        || !HASH_RE.test(value.node.sha256 ?? "")
        || !HASH_RE.test(value.launcherHost.sha256 ?? "")
        || !Number.isSafeInteger(value.node.size)
        || value.node.size < 1
        || !Number.isSafeInteger(value.launcherHost.size)
        || value.launcherHost.size < 1) {
        throw new TypeError("recovery launch manifest is invalid");
    }
    normalizeArguments(value.arguments);
    const environmentNames = new Set();
    for (const [index, variable] of
        value.environment.variables.entries()) {
        const expectedName = RECOVERY_ENVIRONMENT_KEYS[index];
        if (!exactKeys(variable, ["name", "present", "value"])
            || variable.name !== expectedName
            || typeof variable.present !== "boolean"
            || (variable.present
                ? (typeof variable.value !== "string"
                    || variable.value.length
                        > MAX_ENVIRONMENT_VALUE_CHARACTERS
                    || variable.value.includes("\0"))
                : variable.value !== null)
            || environmentNames.has(variable.name)
            || (["NODE_OPTIONS", "NODE_PATH"].includes(variable.name)
                && variable.present
                && variable.value.length > 0)) {
            throw new TypeError(
                "recovery launch environment is invalid",
            );
        }
        environmentNames.add(variable.name);
    }
    const seen = new Set();
    let entryFound = false;
    for (const record of value.files) {
        if (!exactKeys(record, ["path", "sha256", "size"])
            || typeof record.path !== "string"
            || path.isAbsolute(record.path)
            || record.path.includes("\\")
            || record.path.split("/").some((part) =>
                part.length === 0 || part === "." || part === "..")
            || path.extname(record.path).toLowerCase() !== ".mjs"
            || !HASH_RE.test(record.sha256 ?? "")
            || !Number.isSafeInteger(record.size)
            || record.size < 1
            || seen.has(record.path)) {
            throw new TypeError(
                "recovery launch manifest file record is invalid",
            );
        }
        seen.add(record.path);
        entryFound ||= record.path === value.entry;
    }
    if (!entryFound) {
        throw new TypeError(
            "recovery launch manifest does not contain its entry point",
        );
    }
    return Object.freeze(value);
}

export function buildRecoveryLaunchManifest({
    runtimeRoot,
    entryPath,
    node,
    launcherHost,
    arguments: daemonArguments,
    environment = captureRecoveryLaunchEnvironment(),
} = {}) {
    const root = resolveRegularDirectory(
        runtimeRoot,
        "recovery runtime root",
    );
    const entry = resolveRegularPath(
        entryPath,
        "recovery daemon entry point",
    ).path;
    const relativeEntry = manifestRelativePath(root, entry);
    const files = collectProductionEsmFiles(root);
    const manifest = {
        version: RECOVERY_LAUNCH_MANIFEST_VERSION,
        kind: RECOVERY_LAUNCH_MANIFEST_KIND,
        authorityBoundary: RECOVERY_LAUNCHER_AUTHORITY_BOUNDARY,
        root,
        entry: relativeEntry,
        files,
        environment,
        node: {
            path: requireAbsolutePath(node?.path, "Node executable"),
            sha256: node?.sha256,
            size: node?.size,
        },
        launcherHost: {
            path: requireAbsolutePath(
                launcherHost?.path,
                "recovery launcher host",
            ),
            sha256: launcherHost?.sha256,
            size: launcherHost?.size,
        },
        arguments: normalizeArguments(daemonArguments),
    };
    validateRecoveryLaunchManifest(manifest);
    const bytes = Buffer.from(canonicalize(manifest), "utf8");
    return Object.freeze({
        manifest: Object.freeze(manifest),
        bytes,
        sha256: sha256Bytes(bytes),
        gzipBase64: gzipSync(bytes, { level: 9 }).toString("base64"),
    });
}

function windowsQuote(value) {
    const text = String(value);
    if (text.length === 0) return "\"\"";
    if (!/[\s"]/u.test(text)) return text;
    let result = "\"";
    let slashes = 0;
    for (const character of text) {
        if (character === "\\") {
            slashes += 1;
        } else if (character === "\"") {
            result += "\\".repeat((slashes * 2) + 1);
            result += "\"";
            slashes = 0;
        } else {
            result += "\\".repeat(slashes);
            result += character;
            slashes = 0;
        }
    }
    result += "\\".repeat(slashes * 2);
    return `${result}"`;
}

function recoveryLauncherScript(packetBase64, packetSha256) {
    return String.raw`Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$CruciblePacketBase64 = '${packetBase64}'
$CruciblePacketSha256 = '${packetSha256}'
$HeldStreams = [System.Collections.Generic.List[System.IDisposable]]::new()
$ExitCode = 70
function Fail([string]$Message) { throw "Crucible recovery launcher: $Message" }
function Hex-Sha256([byte[]]$Bytes) {
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return 'sha256:' + ([System.BitConverter]::ToString(
            $algorithm.ComputeHash($Bytes)
        ) -replace '-', '').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}
function Assert-ExactProperties($Value, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Value) { Fail "$Label is missing" }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join [char]0) -cne ($wanted -join [char]0)) {
        Fail "$Label has an invalid schema"
    }
}
function Same-Path([string]$Left, [string]$Right) {
    return [System.IO.Path]::GetFullPath($Left).TrimEnd('\') -ieq
        [System.IO.Path]::GetFullPath($Right).TrimEnd('\')
}
function Assert-NoReparsePath([string]$Value, [string]$Label) {
    if (-not [System.IO.Path]::IsPathRooted($Value)) {
        Fail "$Label is not absolute"
    }
    $full = [System.IO.Path]::GetFullPath($Value)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrEmpty($root) -or $root.StartsWith('\\')) {
        Fail "$Label is not on a local drive"
    }
    $current = $root
    $tail = $full.Substring($root.Length)
    foreach ($part in $tail.Split(
        [char[]]@('\'),
        [System.StringSplitOptions]::RemoveEmptyEntries
    )) {
        $current = [System.IO.Path]::Combine($current, $part)
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band
            [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "$Label traverses a reparse point"
        }
    }
    return $full
}
try {
    $compressed = [System.Convert]::FromBase64String(
        $CruciblePacketBase64
    )
    $compressedStream = [System.IO.MemoryStream]::new(
        $compressed,
        $false
    )
    $decodedStream = [System.IO.MemoryStream]::new()
    try {
        $gzip = [System.IO.Compression.GZipStream]::new(
            $compressedStream,
            [System.IO.Compression.CompressionMode]::Decompress
        )
        try { $gzip.CopyTo($decodedStream) }
        finally { $gzip.Dispose() }
        $packetBytes = $decodedStream.ToArray()
    }
    finally {
        $decodedStream.Dispose()
        $compressedStream.Dispose()
    }
    if ((Hex-Sha256 $packetBytes) -cne $CruciblePacketSha256) {
        Fail 'manifest hash differs from the task definition'
    }
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $Packet = $utf8.GetString($packetBytes) | ConvertFrom-Json
    Assert-ExactProperties $Packet @(
        'arguments','authorityBoundary','entry','environment','files','kind',
        'launcherHost','node','root','version'
    ) 'manifest'
    if ([int]$Packet.version -ne 1 -or
        [string]$Packet.kind -cne
            'crucible-recovery-launch-manifest') {
        Fail 'manifest type is invalid'
    }
    Assert-ExactProperties $Packet.authorityBoundary @(
        'excludedFromTaskManifest','pinnedAndHeldOpen',
        'trustedBeforeVerification'
    ) 'authority boundary'
    if ((@($Packet.authorityBoundary.trustedBeforeVerification) -join ',') -cne
            'exact-task-action,windows-powershell-dotnet-host' -or
        (@($Packet.authorityBoundary.pinnedAndHeldOpen) -join ',') -cne
            'launcher-host,node-executable,crucible-production-esm' -or
        (@($Packet.authorityBoundary.excludedFromTaskManifest) -join ',') -cne
            'node-builtins,windows-loader-dependencies,per-investigation-signed-runtime-inputs') {
        Fail 'authority boundary is invalid'
    }
    Assert-ExactProperties $Packet.node @(
        'path','sha256','size'
    ) 'Node identity'
    Assert-ExactProperties $Packet.launcherHost @(
        'path','sha256','size'
    ) 'launcher host identity'
    Assert-ExactProperties $Packet.environment @(
        'variables'
    ) 'launch environment'
    $expectedEnvironmentNames = @(${POWERSHELL_ENVIRONMENT_NAMES})
    $environmentVariables = @($Packet.environment.variables)
    if ($environmentVariables.Count -ne $expectedEnvironmentNames.Count) {
        Fail 'launch environment variable count is invalid'
    }
    for ($environmentIndex = 0;
        $environmentIndex -lt $expectedEnvironmentNames.Count;
        $environmentIndex += 1) {
        $variable = $environmentVariables[$environmentIndex]
        Assert-ExactProperties $variable @(
            'name','present','value'
        ) 'launch environment variable'
        if ([string]$variable.name -cne
            $expectedEnvironmentNames[$environmentIndex] -or
            $variable.present -isnot [bool] -or
            ([bool]$variable.present -and
                ($variable.value -isnot [string] -or
                    ([string]$variable.value).Contains([char]0))) -or
            (-not [bool]$variable.present -and
                $null -ne $variable.value) -or
            (([string]$variable.name -ceq 'NODE_OPTIONS' -or
                [string]$variable.name -ceq 'NODE_PATH') -and
                [bool]$variable.present -and
                ([string]$variable.value).Length -gt 0)) {
            Fail 'launch environment variable is invalid'
        }
    }
    if (@($Packet.files).Count -lt 1 -or
        @($Packet.files).Count -gt 512) {
        Fail 'manifest file count is invalid'
    }
    if (-not ('CrucibleRecoveryNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class CrucibleRecoveryNative {
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const int JobObjectExtendedLimitInformation = 9;
    const uint INFINITE = 0xffffffff;

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFinalPathNameByHandle(
        SafeFileHandle handle,
        StringBuilder path,
        uint capacity,
        uint flags
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(
        IntPtr attributes,
        string name
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        uint length
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(
        IntPtr job,
        IntPtr process
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcess(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(
        IntPtr handle,
        uint milliseconds
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(
        IntPtr process,
        out uint exitCode
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(
        IntPtr process,
        uint exitCode
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    static string Quote(string value) {
        if (value.Length == 0) return "\"\"";
        if (value.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) {
            return value;
        }
        var output = new StringBuilder("\"");
        var slashes = 0;
        foreach (var character in value) {
            if (character == '\\') {
                slashes += 1;
            } else if (character == '"') {
                output.Append('\\', (slashes * 2) + 1);
                output.Append('"');
                slashes = 0;
            } else {
                output.Append('\\', slashes);
                output.Append(character);
                slashes = 0;
            }
        }
        output.Append('\\', slashes * 2);
        output.Append('"');
        return output.ToString();
    }

    static void ThrowLastError(string action) {
        throw new Win32Exception(
            Marshal.GetLastWin32Error(),
            action
        );
    }

    public static int RunInKillOnCloseJob(
        string application,
        string[] arguments,
        string currentDirectory
    ) {
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) ThrowLastError("CreateJobObject failed");
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        var created = false;
        try {
            var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                ref limits,
                (uint)Marshal.SizeOf(limits)
            )) {
                ThrowLastError("SetInformationJobObject failed");
            }
            var command = new StringBuilder(Quote(application));
            foreach (var argument in arguments) {
                command.Append(' ');
                command.Append(Quote(argument));
            }
            var startup = new STARTUPINFO();
            startup.cb = (uint)Marshal.SizeOf(startup);
            if (!CreateProcess(
                application,
                command,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero,
                currentDirectory,
                ref startup,
                out process
            )) {
                ThrowLastError("CreateProcess failed");
            }
            created = true;
            if (!AssignProcessToJobObject(job, process.hProcess)) {
                ThrowLastError("AssignProcessToJobObject failed");
            }
            if (ResumeThread(process.hThread) == 0xffffffff) {
                ThrowLastError("ResumeThread failed");
            }
            if (WaitForSingleObject(process.hProcess, INFINITE)
                == 0xffffffff) {
                ThrowLastError("WaitForSingleObject failed");
            }
            uint exitCode;
            if (!GetExitCodeProcess(process.hProcess, out exitCode)) {
                ThrowLastError("GetExitCodeProcess failed");
            }
            return unchecked((int)exitCode);
        }
        catch {
            if (created && process.hProcess != IntPtr.Zero) {
                TerminateProcess(process.hProcess, 70);
            }
            throw;
        }
        finally {
            if (process.hThread != IntPtr.Zero) {
                CloseHandle(process.hThread);
            }
            if (process.hProcess != IntPtr.Zero) {
                CloseHandle(process.hProcess);
            }
            CloseHandle(job);
        }
    }
}
'@
    }
    function Final-Path([System.IO.FileStream]$Stream) {
        $builder = [System.Text.StringBuilder]::new(32768)
        $count = [CrucibleRecoveryNative]::GetFinalPathNameByHandle(
            $Stream.SafeFileHandle,
            $builder,
            [uint32]$builder.Capacity,
            0
        )
        if ($count -eq 0 -or $count -ge $builder.Capacity) {
            Fail 'could not resolve an opened file handle'
        }
        $value = $builder.ToString()
        if ($value.StartsWith('\\?\UNC\')) {
            return '\\' + $value.Substring(8)
        }
        if ($value.StartsWith('\\?\')) {
            return $value.Substring(4)
        }
        return $value
    }
    function Open-PinnedFile(
        [string]$Value,
        [string]$ExpectedHash,
        [long]$ExpectedSize,
        [string]$Label
    ) {
        if ($ExpectedHash -cnotmatch '^sha256:[a-f0-9]{64}$' -or
            $ExpectedSize -lt 1) {
            Fail "$Label identity is invalid"
        }
        $full = Assert-NoReparsePath $Value $Label
        $stream = [System.IO.File]::Open(
            $full,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        try {
            if (-not (Same-Path (Final-Path $stream) $full)) {
                Fail "$Label handle resolved to a different path"
            }
            if ($stream.Length -ne $ExpectedSize) {
                Fail "$Label size changed"
            }
            $algorithm = [System.Security.Cryptography.SHA256]::Create()
            try {
                $actual = 'sha256:' + (
                    [System.BitConverter]::ToString(
                        $algorithm.ComputeHash($stream)
                    ) -replace '-', ''
                ).ToLowerInvariant()
            }
            finally { $algorithm.Dispose() }
            if ($actual -cne $ExpectedHash) {
                Fail "$Label hash changed"
            }
            $stream.Position = 0
            $HeldStreams.Add($stream)
            return $full
        }
        catch {
            $stream.Dispose()
            throw
        }
    }
    $root = Assert-NoReparsePath ([string]$Packet.root) 'runtime root'
    if (-not (Get-Item -LiteralPath $root -Force).PSIsContainer) {
        Fail 'runtime root is not a directory'
    }
    $seen = @{}
    $entryFound = $false
    foreach ($record in @($Packet.files)) {
        Assert-ExactProperties $record @(
            'path','sha256','size'
        ) 'manifest file'
        $relative = [string]$record.path
        $parts = @($relative.Split('/'))
        if ([string]::IsNullOrEmpty($relative) -or
            [System.IO.Path]::IsPathRooted($relative) -or
            $relative.Contains('\') -or
            $parts -contains '' -or
            $parts -contains '.' -or
            $parts -contains '..' -or
            -not $relative.EndsWith('.mjs',
                [System.StringComparison]::OrdinalIgnoreCase) -or
            $seen.ContainsKey($relative)) {
            Fail 'manifest contains an invalid relative file path'
        }
        $seen[$relative] = $true
        if ($relative -ceq [string]$Packet.entry) {
            $entryFound = $true
        }
        $absolute = [System.IO.Path]::GetFullPath(
            [System.IO.Path]::Combine(
                $root,
                $relative.Replace('/', '\')
            )
        )
        $rootPrefix = $root.TrimEnd('\') + '\'
        if (-not $absolute.StartsWith(
            $rootPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            Fail 'manifest file escaped the runtime root'
        }
        $null = Open-PinnedFile $absolute ([string]$record.sha256) (
            [long]$record.size
        ) "runtime file $relative"
    }
    if (-not $entryFound) {
        Fail 'manifest entry point is absent from the closure'
    }
    $currentHost = [System.Diagnostics.Process]::GetCurrentProcess(
    ).MainModule.FileName
    if (-not (Same-Path $currentHost ([string]$Packet.launcherHost.path))) {
        Fail 'launcher host path differs from the task definition'
    }
    $null = Open-PinnedFile ([string]$Packet.launcherHost.path) (
        [string]$Packet.launcherHost.sha256
    ) ([long]$Packet.launcherHost.size) 'launcher host'
    $nodePath = Open-PinnedFile ([string]$Packet.node.path) (
        [string]$Packet.node.sha256
    ) ([long]$Packet.node.size) 'Node executable'
    if ([System.IO.Path]::IsPathRooted([string]$Packet.entry) -or
        ([string]$Packet.entry).Contains('\') -or
        -not $seen.ContainsKey([string]$Packet.entry)) {
        Fail 'manifest entry point is invalid'
    }
    $entryPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine(
            $root,
            ([string]$Packet.entry).Replace('/', '\')
        )
    )
    foreach ($variable in $environmentVariables) {
        $name = [string]$variable.name
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        if ([bool]$variable.present) {
            Set-Item -LiteralPath "Env:$name" -Value (
                [string]$variable.value
            )
        }
    }
    $daemonArguments = @($Packet.arguments | ForEach-Object {
        if ($_ -isnot [string] -or ([string]$_).Contains([char]0)) {
            Fail 'daemon argument is invalid'
        }
        [string]$_
    })
    $childArguments = @($entryPath) + $daemonArguments
    $ExitCode = [CrucibleRecoveryNative]::RunInKillOnCloseJob(
        $nodePath,
        [string[]]$childArguments,
        $root
    )
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $ExitCode = 70
}
finally {
    for ($index = $HeldStreams.Count - 1; $index -ge 0; $index -= 1) {
        try { $HeldStreams[$index].Dispose() } catch {}
    }
}
exit $ExitCode`;
}

export function buildRecoveryLauncherAction(binding) {
    const manifest = validateRecoveryLaunchManifest(binding?.manifest);
    if (typeof binding?.gzipBase64 !== "string"
        || !/^[A-Za-z0-9+/]+={0,2}$/u.test(binding.gzipBase64)
        || !HASH_RE.test(binding?.sha256 ?? "")) {
        throw new TypeError("recovery launch binding is invalid");
    }
    const decoded = gunzipSync(
        Buffer.from(binding.gzipBase64, "base64"),
    );
    if (sha256Bytes(decoded) !== binding.sha256
        || canonicalize(manifest) !== decoded.toString("utf8")) {
        throw new Error("recovery launch binding does not match its manifest");
    }
    const script = recoveryLauncherScript(
        binding.gzipBase64,
        binding.sha256,
    );
    const launcherScriptSha256 = sha256Bytes(
        Buffer.from(script, "utf8"),
    );
    const argumentsList = [...POWERSHELL_ARGUMENT_PREFIX, script];
    const argumentsText = argumentsList.map(windowsQuote).join(" ");
    if (argumentsText.length > MAX_ACTION_ARGUMENT_CHARACTERS) {
        throw new Error(
            "recovery launcher exceeds the Windows task action limit",
        );
    }
    return Object.freeze({
        execute: manifest.launcherHost.path,
        arguments: argumentsText,
        workingDirectory: manifest.root,
        launcherScriptSha256,
        manifestSha256: binding.sha256,
    });
}

export function parseRecoveryLauncherAction(argumentsText) {
    const argv = parseWindowsCommandLine(argumentsText);
    if (argv.length !== POWERSHELL_ARGUMENT_PREFIX.length + 1
        || POWERSHELL_ARGUMENT_PREFIX.some((value, index) =>
            argv[index] !== value)) {
        throw new TypeError("recovery launcher action arguments are invalid");
    }
    const script = argv.at(-1);
    const packetMatch = /^\$CruciblePacketBase64 = '([A-Za-z0-9+/]+={0,2})'$/mu
        .exec(script);
    const hashMatch = /^\$CruciblePacketSha256 = '(sha256:[a-f0-9]{64})'$/mu
        .exec(script);
    if (packetMatch === null || hashMatch === null) {
        throw new TypeError("recovery launcher binding is missing");
    }
    const bytes = gunzipSync(Buffer.from(packetMatch[1], "base64"));
    if (sha256Bytes(bytes) !== hashMatch[1]) {
        throw new Error("recovery launcher manifest hash is invalid");
    }
    let manifest;
    try {
        manifest = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
        throw new TypeError(
            "recovery launcher manifest JSON is invalid",
            { cause: error },
        );
    }
    validateRecoveryLaunchManifest(manifest);
    if (canonicalize(manifest) !== bytes.toString("utf8")
        || recoveryLauncherScript(packetMatch[1], hashMatch[1])
            !== script) {
        throw new Error("recovery launcher script is not canonical");
    }
    return Object.freeze({
        manifest: Object.freeze(manifest),
        bytes,
        gzipBase64: packetMatch[1],
        sha256: hashMatch[1],
        launcherScriptSha256: sha256Bytes(
            Buffer.from(script, "utf8"),
        ),
    });
}
