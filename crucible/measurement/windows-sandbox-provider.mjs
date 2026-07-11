// crucible/measurement/windows-sandbox-provider.mjs
//
// Native Windows containment for allowlisted harnesses that execute candidate
// code. The candidate is launched in a zero-capability AppContainer (lowbox)
// and an unbreakable Job Object. A hash-pinned C# helper is compiled from the
// trusted source embedded below with the inbox .NET Framework compiler. The
// helper owns profile creation, ACL journaling/restoration, CreateProcessW,
// Job Object lifetime, parent-death monitoring, termination, and cleanup.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { threadId } from "node:worker_threads";

import { canonicalJson } from "../domain/canonical.mjs";
import {
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
    SandboxUnavailableError,
} from "./errors.mjs";
import { hashEnv } from "./receipt.mjs";
import { createSandboxProvider } from "./sandbox.mjs";

export const WINDOWS_SANDBOX_PRIMITIVE =
    "windows-appcontainer-lowbox+job-object";
export const WINDOWS_SANDBOX_POLICY_ID =
    "windows-appcontainer-lowbox-job-v3";

const PROVIDER_ID = "windows-native-appcontainer";
const PROVIDER_VERSION = "v3";
const POLICY_HASH_TAG = "sha256:crucible-windows-appcontainer-policy-v3";
const FILE_HASH_TAG = "sha256:crucible-windows-native-file-v1";
const HELPER_SOURCE_HASH_TAG = "sha256:crucible-windows-helper-source-v1";
const HELPER_LAUNCHER_SCRIPT_HASH_TAG =
    "sha256:crucible-windows-helper-launcher-script-v1";
const HELPER_LAUNCHER_ID = "powershell-loadfrom-no-ui-v1";
const MANAGED_HELPER_READY = "CRUCIBLE_MANAGED_HELPER_READY";
const HELPER_SOURCE_SHA256 =
    "7fa036e9e89941900796e966255df58c45b01cd748d0df3391cfc036c5e7d63f";
const HELPER_BUILD_DIR = "windows-appcontainer-helper-v3";
const HELPER_SOURCE_NAME = "CrucibleWindowsSandbox.cs";
const HELPER_EXE_NAME = "CrucibleWindowsSandbox.exe";
const HELPER_MANIFEST_NAME = "helper-manifest.json";
const HELPER_MANIFEST_VERSION = 2;
const HELPER_BINARY_NORMALIZATION_VERSION = 1;
const HELPER_BINARY_NORMALIZATION_TAG =
    "crucible-windows-helper-binary-normalization-v1";
const HELPER_OUTPUT_CAP = 1024 * 1024;
const WINDOWS_POLICY_VERSION = 3;
const SYSTEM_CLOCK = Object.freeze({
    now: () => Date.now(),
});

const DEFAULT_LIMITS = Object.freeze({
    activeProcessLimit: 8,
    processMemoryBytes: 512 * 1024 * 1024,
    jobMemoryBytes: 768 * 1024 * 1024,
    cpuRatePercent: 50,
    cpuTimeMs: 30_000,
    wallTimeMs: 120_000,
    terminationGraceMs: 5_000,
});

const LIMIT_RANGES = Object.freeze({
    activeProcessLimit: [1, 64],
    processMemoryBytes: [64 * 1024 * 1024, 8 * 1024 * 1024 * 1024],
    jobMemoryBytes: [64 * 1024 * 1024, 16 * 1024 * 1024 * 1024],
    cpuRatePercent: [1, 100],
    cpuTimeMs: [100, 60 * 60 * 1000],
    wallTimeMs: [100, 60 * 60 * 1000],
    terminationGraceMs: [100, 60_000],
});

const HELPER_LAUNCHER_SCRIPT = String.raw`
$ErrorActionPreference = "Stop"
try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
    $helperPath = $env:CRUCIBLE_MANAGED_HELPER_PATH
    $argumentsPath = $env:CRUCIBLE_MANAGED_HELPER_ARGUMENTS_PATH
    $expectedArgumentsHash = $env:CRUCIBLE_MANAGED_HELPER_ARGUMENTS_HASH
    if ([String]::IsNullOrWhiteSpace($helperPath) -or
        [String]::IsNullOrWhiteSpace($argumentsPath) -or
        [String]::IsNullOrWhiteSpace($expectedArgumentsHash)) {
        throw "managed helper launch environment is incomplete"
    }
    $argumentBytes = [IO.File]::ReadAllBytes($argumentsPath)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $actualArgumentsHash = [BitConverter]::ToString(
            $hasher.ComputeHash($argumentBytes)
        ).Replace("-", "").ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
    if ($actualArgumentsHash -ne $expectedArgumentsHash) {
        throw "managed helper argument file hash did not match"
    }
    $decoded = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($argumentBytes))
    [string[]]$managedArguments = @($decoded | ForEach-Object { [string]$_ })
    $assembly = [Reflection.Assembly]::LoadFrom($helperPath)
    $helperType = $assembly.GetType("CrucibleWindowsSandbox", $true)
    $flags = [Reflection.BindingFlags]::Static -bor
        [Reflection.BindingFlags]::Public -bor
        [Reflection.BindingFlags]::NonPublic
    $configure = $helperType.GetMethod("ConfigureNoUi", $flags)
    if ($null -eq $configure) {
        throw "managed helper no-UI bootstrap is unavailable"
    }
    $null = $configure.Invoke($null, @())
    [Console]::Out.WriteLine("CRUCIBLE_MANAGED_HELPER_READY")
    [Console]::Out.Flush()
    $invokeArguments = New-Object object[] 1
    $invokeArguments[0] = $managedArguments
    $result = $assembly.EntryPoint.Invoke($null, $invokeArguments)
    exit [int]$result
} catch {
    $message = [string]$_.Exception.GetBaseException().Message
    $message = $message.Replace([string][char]13, " ").Replace(
        [string][char]10,
        " "
    )
    if ($message.Length -gt 2048) { $message = $message.Substring(0, 2048) }
    [Console]::Error.WriteLine(
        "CRUCIBLE_MANAGED_HELPER_START_ERROR " + $message
    )
    [Console]::Error.Flush()
    exit 111
}
`.trim();

const HELPER_LAUNCHER_SCRIPT_HASH = taggedHash(
    HELPER_LAUNCHER_SCRIPT_HASH_TAG,
    Buffer.from(HELPER_LAUNCHER_SCRIPT, "utf8"),
);
const HELPER_LAUNCHER_ENCODED = Buffer.from(
    HELPER_LAUNCHER_SCRIPT,
    "utf16le",
).toString("base64");

export const WINDOWS_SANDBOX_LIMITATIONS = Object.freeze([
    "AppContainer can read Windows resources explicitly ACLed to ALL APPLICATION PACKAGES.",
    "Permissive host IPC endpoints ACLed for AppContainers remain reachable.",
    "The provider requires the inbox .NET Framework C# compiler and NTFS ACL support.",
    "The provider requires inbox Windows PowerShell as a hidden managed-assembly launcher.",
    "Paths unsupported by the inbox .NET Framework runtime fail admission rather than falling back.",
    "A same-user process outside the candidate Job Object is outside this containment boundary.",
]);

function sha256Hex(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

function taggedHash(tag, bytes) {
    return `${tag}:${sha256Hex(bytes)}`;
}

function hashFile(file) {
    return sha256Hex(fs.readFileSync(file));
}

function localFileIdentity(file, label) {
    const stat = fs.lstatSync(file, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink()) {
        throw unavailable(`${label} is not a regular local file`, { file });
    }
    const real = fs.realpathSync.native(file);
    if (real.toLowerCase() !== path.resolve(file).toLowerCase()) {
        throw unavailable(`${label} resolves through a reparse point`, {
            file,
            real,
        });
    }
    return Object.freeze({
        real,
        dev: stat.dev.toString(),
        ino: stat.ino.toString(),
        size: stat.size.toString(),
        mode: stat.mode.toString(),
        mtimeNs: stat.mtimeNs.toString(),
        ctimeNs: stat.ctimeNs.toString(),
    });
}

function sameLocalFileIdentity(left, right) {
    return left.real.toLowerCase() === right.real.toLowerCase()
        && left.dev === right.dev
        && left.ino === right.ino
        && left.size === right.size
        && left.mode === right.mode
        && left.mtimeNs === right.mtimeNs
        && left.ctimeNs === right.ctimeNs;
}

function stageHelperInvocation(helper, root, label) {
    const invocationRoot = path.join(
        root,
        `.helper-${label}-${process.pid}-${randomBytes(8).toString("hex")}`,
    );
    fs.mkdirSync(invocationRoot, { recursive: false, mode: 0o700 });
    const destination = path.join(invocationRoot, HELPER_EXE_NAME);
    let sourceFd;
    let destinationFd;
    let pinnedFd;
    try {
        const sourceBefore = localFileIdentity(
            helper.path,
            "Windows sandbox helper",
        );
        sourceFd = fs.openSync(helper.path, "r");
        const sourceHandleBefore = fs.fstatSync(sourceFd, { bigint: true });
        destinationFd = fs.openSync(destination, "wx", 0o500);
        const hash = createHash("sha256");
        const buffer = Buffer.allocUnsafe(64 * 1024);
        let position = 0;
        while (true) {
            const bytes = fs.readSync(
                sourceFd,
                buffer,
                0,
                buffer.length,
                position,
            );
            if (bytes <= 0) break;
            hash.update(buffer.subarray(0, bytes));
            let offset = 0;
            while (offset < bytes) {
                offset += fs.writeSync(
                    destinationFd,
                    buffer,
                    offset,
                    bytes - offset,
                );
            }
            position += bytes;
        }
        fs.fsyncSync(destinationFd);
        fs.closeSync(destinationFd);
        destinationFd = undefined;
        const copiedHash = hash.digest("hex");
        if (copiedHash !== helper.hash) {
            throw unavailable(
                "Windows sandbox helper changed while its private launch copy was made",
                { expected: helper.hash, actual: copiedHash },
            );
        }
        const sourceHandleAfter = fs.fstatSync(sourceFd, { bigint: true });
        const sourceAfter = localFileIdentity(
            helper.path,
            "Windows sandbox helper",
        );
        if (sourceHandleBefore.dev !== sourceHandleAfter.dev
            || sourceHandleBefore.ino !== sourceHandleAfter.ino
            || sourceHandleBefore.size !== sourceHandleAfter.size
            || !sameLocalFileIdentity(sourceBefore, sourceAfter)) {
            throw unavailable(
                "Windows sandbox helper identity changed while staging its launch copy",
            );
        }
        fs.closeSync(sourceFd);
        sourceFd = undefined;
        try { fs.chmodSync(destination, 0o500); } catch { /* ACLs govern Windows */ }
        const identity = localFileIdentity(
            destination,
            "private Windows sandbox helper",
        );
        pinnedFd = fs.openSync(destination, "r");
        const invocation = {
            path: identity.real,
            root: invocationRoot,
            hash: copiedHash,
            identity,
            fd: pinnedFd,
            closed: false,
        };
        pinnedFd = undefined;
        return invocation;
    } catch (error) {
        try { fs.rmSync(invocationRoot, { recursive: true, force: true }); } catch {}
        throw error;
    } finally {
        if (sourceFd !== undefined) fs.closeSync(sourceFd);
        if (destinationFd !== undefined) fs.closeSync(destinationFd);
        if (pinnedFd !== undefined) fs.closeSync(pinnedFd);
    }
}

function verifyHelperInvocation(invocation) {
    if (invocation.closed) {
        throw unavailable("private Windows sandbox helper launch copy is closed");
    }
    const handle = fs.fstatSync(invocation.fd, { bigint: true });
    const current = localFileIdentity(
        invocation.path,
        "private Windows sandbox helper",
    );
    if (handle.dev.toString() !== invocation.identity.dev
        || handle.ino.toString() !== invocation.identity.ino
        || handle.size.toString() !== invocation.identity.size
        || !sameLocalFileIdentity(invocation.identity, current)
        || hashFile(invocation.path) !== invocation.hash) {
        throw unavailable(
            "private Windows sandbox helper identity changed immediately before launch",
            { helperPath: invocation.path },
        );
    }
}

function closeHelperInvocation(invocation, { remove = true } = {}) {
    if (invocation === null || invocation === undefined || invocation.closed) return;
    invocation.closed = true;
    try { fs.closeSync(invocation.fd); } finally {
        if (remove) {
            fs.rmSync(invocation.root, {
                recursive: true,
                force: true,
                maxRetries: 100,
                retryDelay: 50,
            });
        }
    }
}

function deterministicHelperGuid(sourceHash, compilerHash) {
    const bytes = createHash("sha256")
        .update(HELPER_BINARY_NORMALIZATION_TAG, "utf8")
        .update("\0", "utf8")
        .update(sourceHash, "utf8")
        .update("\0", "utf8")
        .update(compilerHash, "utf8")
        .digest()
        .subarray(0, 16);
    const guid = Buffer.from(bytes);
    guid[6] = (guid[6] & 0x0f) | 0x50;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    const hex = guid.toString("hex").toUpperCase();
    return [
        hex.slice(0, 8),
        hex.slice(8, 12),
        hex.slice(12, 16),
        hex.slice(16, 20),
        hex.slice(20),
    ].join("-");
}

function dotNetGuidBytes(guidText) {
    const bytes = Buffer.from(guidText.replaceAll("-", ""), "hex");
    return Buffer.from([
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        ...bytes.subarray(8),
    ]);
}

function replaceSingleBufferOccurrence(buffer, needle, replacement, label) {
    const first = buffer.indexOf(needle);
    if (first < 0 || buffer.indexOf(needle, first + 1) >= 0) {
        throw unavailable(
            `Compiled Windows sandbox helper has an unexpected ${label} layout`,
            { occurrences: first < 0 ? 0 : "multiple" },
        );
    }
    replacement.copy(buffer, first);
}

function normalizeCompiledHelperBinary(file, { sourceHash, compilerHash }) {
    const binary = fs.readFileSync(file);
    if (binary.length < 0x40 || binary.readUInt16LE(0) !== 0x5a4d) {
        throw unavailable("Compiled Windows sandbox helper is not a valid PE image");
    }
    const peOffset = binary.readUInt32LE(0x3c);
    if (peOffset < 0x40
        || peOffset + 12 > binary.length
        || binary.toString("latin1", peOffset, peOffset + 4) !== "PE\0\0") {
        throw unavailable("Compiled Windows sandbox helper has an invalid PE header");
    }

    const text = binary.toString("latin1");
    const matches = [...text.matchAll(
        /<PrivateImplementationDetails>\{([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\}/gu,
    )];
    if (matches.length !== 1) {
        throw unavailable(
            "Compiled Windows sandbox helper has an unexpected managed metadata identity layout",
            { occurrences: matches.length },
        );
    }

    const originalGuid = matches[0][1];
    const normalizedGuid = deterministicHelperGuid(sourceHash, compilerHash);
    binary.writeUInt32LE(0, peOffset + 8);
    replaceSingleBufferOccurrence(
        binary,
        Buffer.from(originalGuid, "ascii"),
        Buffer.from(normalizedGuid, "ascii"),
        "metadata GUID string",
    );
    replaceSingleBufferOccurrence(
        binary,
        dotNetGuidBytes(originalGuid),
        dotNetGuidBytes(normalizedGuid),
        "module GUID",
    );
    fs.writeFileSync(file, binary);
}

function unavailable(message, details = null) {
    return new SandboxUnavailableError(message, details);
}

function validatePinnedSource() {
    const actual = sha256Hex(Buffer.from(HELPER_SOURCE, "utf8"));
    if (actual !== HELPER_SOURCE_SHA256) {
        throw unavailable(
            "Windows sandbox helper source hash does not match its pinned digest",
            {
                expected: `${HELPER_SOURCE_HASH_TAG}:${HELPER_SOURCE_SHA256}`,
                actual: `${HELPER_SOURCE_HASH_TAG}:${actual}`,
            },
        );
    }
    return actual;
}

function normalizeInteger(value, field, fallback) {
    const actual = value === undefined ? fallback : value;
    const [minimum, maximum] = LIMIT_RANGES[field];
    if (!Number.isSafeInteger(actual) || actual < minimum || actual > maximum) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${field} must be an integer between ${minimum} and ${maximum}`,
            { field, value: actual },
        );
    }
    return actual;
}

function normalizeLimits(value = {}) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "Windows sandbox limits must be an object",
        );
    }
    const unknown = Object.keys(value).filter((key) =>
        !Object.hasOwn(DEFAULT_LIMITS, key));
    if (unknown.length > 0) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "Windows sandbox limits contain unknown keys",
            { unknown },
        );
    }
    const limits = {};
    for (const [key, fallback] of Object.entries(DEFAULT_LIMITS)) {
        limits[key] = normalizeInteger(value[key], key, fallback);
    }
    if (limits.jobMemoryBytes < limits.processMemoryBytes) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "jobMemoryBytes must be greater than or equal to processMemoryBytes",
        );
    }
    return Object.freeze(limits);
}

function defaultControlRoot() {
    const local = process.env.LOCALAPPDATA;
    if (typeof local === "string" && path.isAbsolute(local)) {
        return path.join(local, "Crucible", "WindowsSandbox");
    }
    return path.join(os.homedir(), "AppData", "Local", "Crucible", "WindowsSandbox");
}

function normalizeControlRoot(value) {
    const requested = value ?? defaultControlRoot();
    if (typeof requested !== "string" || !path.isAbsolute(requested)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "Windows sandbox controlRoot must be an absolute path",
            { controlRoot: requested ?? null },
        );
    }
    fs.mkdirSync(requested, { recursive: true, mode: 0o700 });
    const stat = fs.lstatSync(requested);
    if (stat.isSymbolicLink()) {
        throw unavailable(
            "Windows sandbox controlRoot is a reparse point",
            { controlRoot: requested },
        );
    }
    if (!stat.isDirectory()) {
        throw unavailable("Windows sandbox controlRoot is not a regular directory", {
            controlRoot: requested,
        });
    }
    const resolved = path.resolve(requested);
    const real = fs.realpathSync.native(requested);
    if (resolved.toLowerCase() !== real.toLowerCase()) {
        throw unavailable(
            "Windows sandbox controlRoot resolves through a reparse point",
            { controlRoot: requested, real },
        );
    }
    return real;
}

function resolveCompiler() {
    const systemRoot = process.env.SystemRoot
        ?? process.env.SYSTEMROOT
        ?? "C:\\Windows";
    const candidates = [
        path.join(
            systemRoot,
            "Microsoft.NET",
            "Framework64",
            "v4.0.30319",
            "csc.exe",
        ),
        path.join(
            systemRoot,
            "Microsoft.NET",
            "Framework",
            "v4.0.30319",
            "csc.exe",
        ),
    ];
    for (const candidate of candidates) {
        try {
            const stat = fs.lstatSync(candidate);
            if (stat.isFile() && !stat.isSymbolicLink()) {
                return fs.realpathSync.native(candidate);
            }
        } catch {
            // Continue to the next inbox compiler path.
        }
    }
    throw unavailable(
        "The inbox .NET Framework C# compiler required by the Windows sandbox is unavailable",
        { candidates },
    );
}

function resolvePowerShell() {
    const systemRoot = process.env.SystemRoot
        ?? process.env.SYSTEMROOT
        ?? "C:\\Windows";
    const candidate = path.join(
        systemRoot,
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    );
    try {
        const identity = localFileIdentity(
            candidate,
            "Windows PowerShell helper launcher",
        );
        return Object.freeze({
            path: identity.real,
            hash: hashFile(identity.real),
            identity,
        });
    } catch (error) {
        if (error instanceof MeasurementError) throw error;
        throw unavailable(
            "The inbox Windows PowerShell launcher required by the sandbox is unavailable",
            { candidate, cause: error?.code ?? error?.message ?? null },
        );
    }
}

function runProcess(executable, argv, {
    cwd,
    env = process.env,
    timeoutMs = 60_000,
    stdin = "ignore",
    outputCap = HELPER_OUTPUT_CAP,
    beforeSpawn = null,
    afterSpawn = null,
    timeoutError = null,
} = {}) {
    return new Promise((resolve, reject) => {
        let child;
        let effectiveTimeoutMs;
        try {
            const resolveTimeoutMs = () => {
                const value = typeof timeoutMs === "function"
                    ? timeoutMs()
                    : timeoutMs;
                if (!Number.isSafeInteger(value) || value < 1) {
                    throw new MeasurementError(
                        MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                        "Windows sandbox process timeout must be a positive safe integer",
                        { timeoutMs: value },
                    );
                }
                return value;
            };
            resolveTimeoutMs();
            beforeSpawn?.();
            effectiveTimeoutMs = resolveTimeoutMs();
            child = spawn(executable, argv, {
                cwd,
                env,
                stdio: [stdin, "pipe", "pipe"],
                shell: false,
                windowsHide: true,
                detached: false,
            });
            afterSpawn?.(child);
        } catch (error) {
            if (child !== undefined) {
                try { child.kill(); } catch { /* best effort */ }
            }
            reject(error);
            return;
        }
        const stdout = [];
        const stderr = [];
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let overflow = false;
        let forcedError = null;
        let settled = false;
        let timer = null;
        let killTimer = null;
        const finish = (error, result) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            clearTimeout(killTimer);
            if (error) reject(error);
            else resolve(result);
        };
        const append = (chunks, chunk, kind) => {
            const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            if (kind === "stdout") stdoutBytes += bytes.length;
            else stderrBytes += bytes.length;
            if (stdoutBytes > outputCap || stderrBytes > outputCap) {
                overflow = true;
                try { child.kill(); } catch { /* best effort */ }
                return;
            }
            chunks.push(bytes);
        };
        child.stdout.on("data", (chunk) => append(stdout, chunk, "stdout"));
        child.stderr.on("data", (chunk) => append(stderr, chunk, "stderr"));
        child.once("error", (error) => finish(error));
        child.once("close", (code, signal) => {
            if (forcedError !== null) {
                finish(forcedError);
                return;
            }
            const result = {
                code,
                signal,
                stdout: Buffer.concat(stdout).toString("utf8"),
                stderr: Buffer.concat(stderr).toString("utf8"),
            };
            if (overflow) {
                finish(new Error("native helper output exceeded its trusted cap"));
                return;
            }
            finish(null, result);
        });
        timer = setTimeout(() => {
            try {
                forcedError = typeof timeoutError === "function"
                    ? timeoutError(effectiveTimeoutMs)
                    : new Error(
                        `native helper exceeded ${effectiveTimeoutMs}ms`,
                    );
            } catch (error) {
                forcedError = error;
            }
            try { child.kill(); } catch { /* best effort */ }
            killTimer = setTimeout(() => finish(forcedError), 5_000);
            killTimer.unref?.();
        }, effectiveTimeoutMs);
        timer.unref?.();
    });
}

function helperFailure(operation, result, details = {}) {
    const stderr = result?.stderr?.trim();
    return unavailable(
        `Windows sandbox native helper ${operation} failed`,
        {
            operation,
            exitCode: result?.code ?? null,
            signal: result?.signal ?? null,
            stderr: stderr?.slice(0, 2048) ?? null,
            ...details,
        },
    );
}

async function compileHelper(controlRoot) {
    const sourceHash = validatePinnedSource();
    const compiler = resolveCompiler();
    const compilerHash = hashFile(compiler);
    const launcher = resolvePowerShell();
    const finalRoot = path.join(controlRoot, HELPER_BUILD_DIR);
    const sourcePath = path.join(finalRoot, HELPER_SOURCE_NAME);
    const helperPath = path.join(finalRoot, HELPER_EXE_NAME);
    const manifestPath = path.join(finalRoot, HELPER_MANIFEST_NAME);

    try {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        if (manifest.version === HELPER_MANIFEST_VERSION
            && manifest.normalizationVersion === HELPER_BINARY_NORMALIZATION_VERSION
            && manifest.sourceHash === sourceHash
            && manifest.compilerHash === compilerHash
            && manifest.helperHash === hashFile(helperPath)
            && fs.readFileSync(sourcePath, "utf8") === HELPER_SOURCE) {
            return Object.freeze({
                path: fs.realpathSync.native(helperPath),
                hash: manifest.helperHash,
                sourceHash,
                compiler,
                compilerHash,
                launcher,
            });
        }
    } catch {
        // Missing or stale cache: rebuild from the pinned source.
    }

    const buildRoot = path.join(
        controlRoot,
        `.native-build-${process.pid}-${randomBytes(8).toString("hex")}`,
    );
    fs.mkdirSync(buildRoot, { recursive: false, mode: 0o700 });
    const buildSource = path.join(buildRoot, HELPER_SOURCE_NAME);
    const buildHelper = path.join(buildRoot, HELPER_EXE_NAME);
    try {
        fs.writeFileSync(buildSource, HELPER_SOURCE, {
            encoding: "utf8",
            flag: "wx",
            mode: 0o600,
        });
        if (hashFile(buildSource) !== sourceHash) {
            throw unavailable("Generated Windows sandbox helper source failed hash verification");
        }
        const result = await runProcess(
            compiler,
            [
                "/nologo",
                "/target:exe",
                "/optimize+",
                "/platform:anycpu",
                `/out:${buildHelper}`,
                "/r:System.Web.Extensions.dll",
                buildSource,
            ],
            { cwd: buildRoot, timeoutMs: 120_000 },
        );
        if (result.code !== 0 || !fs.existsSync(buildHelper)) {
            throw helperFailure("compilation", result, { compiler });
        }
        normalizeCompiledHelperBinary(buildHelper, { sourceHash, compilerHash });
        const helperHash = hashFile(buildHelper);
        fs.writeFileSync(
            path.join(buildRoot, HELPER_MANIFEST_NAME),
            `${JSON.stringify({
                version: HELPER_MANIFEST_VERSION,
                normalizationVersion: HELPER_BINARY_NORMALIZATION_VERSION,
                sourceHash,
                compilerHash,
                helperHash,
            }, null, 2)}\n`,
            { encoding: "utf8", flag: "wx", mode: 0o600 },
        );

        try {
            fs.rmSync(finalRoot, { recursive: true, force: true });
            fs.renameSync(buildRoot, finalRoot);
        } catch (error) {
            if (!fs.existsSync(helperPath)) throw error;
        }
        const finalHash = hashFile(helperPath);
        if (finalHash !== helperHash
            || hashFile(sourcePath) !== sourceHash) {
            throw unavailable("Installed Windows sandbox helper failed hash verification");
        }
        return Object.freeze({
            path: fs.realpathSync.native(helperPath),
            hash: finalHash,
            sourceHash,
            compiler,
            compilerHash,
            launcher,
        });
    } finally {
        fs.rmSync(buildRoot, { recursive: true, force: true });
    }
}

function verifyHelper(helper) {
    const actual = hashFile(helper.path);
    if (actual !== helper.hash) {
        throw unavailable("Windows sandbox helper binary changed after verification", {
            helperPath: helper.path,
            expected: `${FILE_HASH_TAG}:${helper.hash}`,
            actual: `${FILE_HASH_TAG}:${actual}`,
        });
    }
}

function helperEnvironment() {
    const env = {};
    for (const key of [
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
    ]) {
        const value = process.env[key];
        if (typeof value === "string" && value.length > 0) env[key] = value;
    }
    return env;
}

function prepareManagedHelperLaunch(
    helper,
    invocation,
    argv,
    { helperPath = invocation.path } = {},
) {
    const bytes = Buffer.from(JSON.stringify(argv), "utf8");
    const argumentsPath = path.join(invocation.root, "managed-arguments.json");
    const fd = fs.openSync(argumentsPath, "wx", 0o400);
    try {
        let offset = 0;
        while (offset < bytes.length) {
            offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
        }
        fs.fsyncSync(fd);
    } finally {
        fs.closeSync(fd);
    }
    try { fs.chmodSync(argumentsPath, 0o400); } catch { /* ACLs govern Windows */ }
    const env = {
        ...helperEnvironment(),
        CRUCIBLE_MANAGED_HELPER_PATH: helperPath,
        CRUCIBLE_MANAGED_HELPER_ARGUMENTS_PATH:
            fs.realpathSync.native(argumentsPath),
        CRUCIBLE_MANAGED_HELPER_ARGUMENTS_HASH: sha256Hex(bytes),
    };
    return Object.freeze({
        executable: helper.launcher.path,
        argv: Object.freeze([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            HELPER_LAUNCHER_ENCODED,
        ]),
        cwd: invocation.root,
        env: Object.freeze(env),
    });
}

function stripManagedReady(stdout) {
    const normalized = stdout.replaceAll("\r\n", "\n");
    const marker = `${MANAGED_HELPER_READY}\n`;
    const index = normalized.indexOf(marker);
    return index < 0 ? null : normalized.slice(index + marker.length);
}

function stripInitialPowerShellClixml(stderr) {
    const normalized = stderr.replaceAll("\r\n", "\n");
    if (!normalized.startsWith("#< CLIXML\n")) return stderr;
    const body = normalized.slice("#< CLIXML\n".length);
    const start = body.indexOf("<Objs ");
    const end = body.indexOf("</Objs>", start);
    if (start < 0 || end < 0) return body;
    return `${body.slice(0, start)}${body.slice(end + "</Objs>".length)}`;
}

function managedChildProxy(child, stdout, stderr) {
    const events = new EventEmitter();
    let closeEvent = null;
    let errorEvent = null;
    child.on("error", (error) => {
        errorEvent = error;
        if (events.listenerCount("error") > 0) {
            events.emit("error", error);
        }
    });
    child.on("close", (code, signal) => {
        closeEvent = [code, signal];
        events.emit("close", code, signal);
    });
    let proxy;
    proxy = {
        pid: child.pid,
        stdin: child.stdin,
        stdout,
        stderr,
        get exitCode() {
            return child.exitCode;
        },
        get signalCode() {
            return child.signalCode;
        },
        kill(signal) {
            return child.kill(signal);
        },
        on(eventName, listener) {
            if (eventName === "error" && errorEvent !== null) {
                setImmediate(() => listener(errorEvent));
                return proxy;
            }
            if (eventName === "close" && closeEvent !== null) {
                setImmediate(() => listener(...closeEvent));
                return proxy;
            }
            events.on(eventName, listener);
            return proxy;
        },
        once(eventName, listener) {
            if (eventName === "error" && errorEvent !== null) {
                setImmediate(() => listener(errorEvent));
                return proxy;
            }
            if (eventName === "close" && closeEvent !== null) {
                setImmediate(() => listener(...closeEvent));
                return proxy;
            }
            events.once(eventName, listener);
            return proxy;
        },
    };
    return proxy;
}

function pipeWithoutInitialPowerShellClixml(source, destination) {
    let pending = Buffer.alloc(0);
    let decided = false;
    const onData = (chunk) => {
        pending = Buffer.concat([
            pending,
            Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
        ]);
        const normalized = pending.toString("utf8").replaceAll("\r\n", "\n");
        if (!normalized.startsWith("#< CLIXML\n")) {
            decided = true;
            source.off("data", onData);
            if (pending.length > 0) destination.write(pending);
            source.pipe(destination);
            return;
        }
        const body = normalized.slice("#< CLIXML\n".length);
        const start = body.indexOf("<Objs ");
        const end = body.indexOf("</Objs>", start);
        if ((start < 0 || end < 0) && pending.length <= 64 * 1024) return;
        decided = true;
        source.off("data", onData);
        if (start >= 0 && end >= 0) {
            const remainder = `${body.slice(0, start)}${
                body.slice(end + "</Objs>".length)
            }`;
            if (remainder.length > 0) destination.write(remainder);
        } else if (body.length > 0) {
            destination.write(body);
        }
        source.pipe(destination);
    };
    source.on("data", onData);
    source.once("end", () => {
        if (!decided && pending.length > 0) {
            destination.write(stripInitialPowerShellClixml(
                pending.toString("utf8"),
            ));
        }
        destination.end();
    });
}

async function waitForManagedHelperReady(child, timeoutMs = 10_000) {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    pipeWithoutInitialPowerShellClixml(child.stderr, stderr);
    const proxy = managedChildProxy(child, stdout, stderr);
    const marker = Buffer.from(`${MANAGED_HELPER_READY}\n`, "utf8");
    let pending = Buffer.alloc(0);
    let settled = false;
    return new Promise((resolve, reject) => {
        const finish = (error = null) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            child.stdout.off("data", onData);
            child.off("error", onError);
            child.off("close", onClose);
            if (error !== null) {
                reject(error);
                return;
            }
            resolve(proxy);
        };
        const onData = (chunk) => {
            pending = Buffer.concat([
                pending,
                Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
            ]);
            if (pending.length > 64 * 1024) {
                finish(unavailable(
                    "Windows sandbox managed helper startup diagnostics exceeded their bound",
                    { bytes: pending.length },
                ));
                return;
            }
            const normalized = Buffer.from(
                pending.toString("utf8").replaceAll("\r\n", "\n"),
                "utf8",
            );
            const index = normalized.indexOf(marker);
            if (index < 0) return;
            const remainder = normalized.subarray(index + marker.length);
            if (remainder.length > 0) stdout.write(remainder);
            child.stdout.off("data", onData);
            child.stdout.pipe(stdout);
            finish();
        };
        const startupFailure = (kind, details = {}) => unavailable(
            `Windows sandbox managed helper failed before startup acknowledgement (${kind})`,
            {
                ...details,
                stdout: pending.toString("utf8").slice(0, 2048),
            },
        );
        const onError = (error) =>
            finish(startupFailure("process-error", {
                cause: error?.code ?? error?.message ?? null,
            }));
        const onClose = (code, signal) =>
            finish(startupFailure("early-exit", { exitCode: code, signal }));
        child.stdout.on("data", onData);
        child.once("error", onError);
        child.once("close", onClose);
        const timer = setTimeout(() => {
            try { child.kill(); } catch { /* best effort */ }
            finish(startupFailure("timeout", { timeoutMs }));
        }, timeoutMs);
        timer.unref?.();
    });
}

async function runHelperJson(helper, operation, argv, options = {}) {
    verifyHelper(helper);
    const invocation = stageHelperInvocation(
        helper,
        options.invocationRoot ?? path.dirname(helper.path),
        operation,
    );
    let result;
    try {
        const resolveTimeoutMs = () => {
            const value = typeof options.timeoutMs === "function"
                ? options.timeoutMs()
                : options.timeoutMs ?? 60_000;
            if (!Number.isSafeInteger(value) || value < 1) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                    "Windows sandbox helper timeout must be a positive safe integer",
                    { operation, timeoutMs: value },
                );
            }
            return value;
        };
        let timeoutMs = resolveTimeoutMs();
        await options.beforeSpawn?.(Object.freeze({
            operation,
            helperPath: invocation.path,
            helperRoot: invocation.root,
            timeoutMs,
        }));
        resolveTimeoutMs();
        const managed = prepareManagedHelperLaunch(
            helper,
            invocation,
            [operation, ...argv],
        );
        result = await runProcess(
            managed.executable,
            managed.argv,
            {
                cwd: managed.cwd,
                env: managed.env,
                timeoutMs: resolveTimeoutMs,
                timeoutError: options.timeoutError,
                beforeSpawn() {
                    verifyHelperInvocation(invocation);
                    verifyHelper(helper);
                },
                afterSpawn() {
                    options.afterSpawn?.(Object.freeze({
                        operation,
                        helperPath: invocation.path,
                        helperRoot: invocation.root,
                    }));
                    verifyHelperInvocation(invocation);
                    verifyHelper(helper);
                },
            },
        );
    } finally {
        closeHelperInvocation(invocation);
    }
    const strippedStdout = stripManagedReady(result.stdout);
    if (strippedStdout === null) {
        throw unavailable(
            `Windows sandbox native helper ${operation} failed before managed startup completed`,
            {
                operation,
                exitCode: result.code,
                signal: result.signal,
                stderr: stripInitialPowerShellClixml(result.stderr).slice(0, 2048),
            },
        );
    }
    result = {
        ...result,
        stdout: strippedStdout,
        stderr: stripInitialPowerShellClixml(result.stderr),
    };
    if (result.code !== 0) {
        throw helperFailure(operation, result);
    }
    try {
        const parsed = JSON.parse(result.stdout);
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("response is not an object");
        }
        return parsed;
    } catch (error) {
        throw unavailable(
            `Windows sandbox native helper ${operation} returned malformed JSON`,
            {
                operation,
                stdout: result.stdout.slice(0, 2048),
                cause: error?.message ?? String(error),
            },
        );
    }
    const launcherIdentity = localFileIdentity(
        helper.launcher.path,
        "Windows PowerShell helper launcher",
    );
    if (!sameLocalFileIdentity(helper.launcher.identity, launcherIdentity)
        || hashFile(helper.launcher.path) !== helper.launcher.hash) {
        throw unavailable(
            "Windows PowerShell helper launcher identity changed after verification",
            {
                launcherPath: helper.launcher.path,
                expected: `${FILE_HASH_TAG}:${helper.launcher.hash}`,
            },
        );
    }
}

async function probeWithHelper(helper, controlRoot, limits) {
    const result = await runHelperJson(
        helper,
        "probe",
        [
            controlRoot,
            String(process.pid),
            String(limits.activeProcessLimit),
            String(limits.processMemoryBytes),
            String(limits.jobMemoryBytes),
            String(limits.cpuRatePercent),
            String(limits.cpuTimeMs),
            String(limits.wallTimeMs),
        ],
        { timeoutMs: Math.min(limits.wallTimeMs + 30_000, 180_000) },
    );
    if (result.available !== true
        || result.appContainer !== true
        || result.lowIntegrity !== true
        || result.zeroCapabilities !== true
        || result.networkDenied !== true
        || result.secretDenied !== true
        || result.registryDenied !== true
        || result.outputWriteAllowed !== true
        || result.jobObjectConfigured !== true) {
        throw unavailable(
            "Windows sandbox native capability probe did not prove every required invariant",
            { probe: result },
        );
    }
    return result;
}

function freezeAvailability(result) {
    return Object.freeze({
        available: result.available,
        code: result.code ?? null,
        reason: result.reason ?? null,
        details: result.details ?? null,
        primitive: WINDOWS_SANDBOX_PRIMITIVE,
        policyId: WINDOWS_SANDBOX_POLICY_ID,
        helperSourceHash: result.helperSourceHash ?? null,
        helperBinaryHash: result.helperBinaryHash ?? null,
        launcherId: result.launcherId ?? null,
        launcherBinaryHash: result.launcherBinaryHash ?? null,
        launcherScriptHash: result.launcherScriptHash ?? null,
        policyIdentity: result.policyIdentity ?? null,
        limitations: WINDOWS_SANDBOX_LIMITATIONS,
        probe: result.probe ?? null,
        helper: result.helper ?? null,
        controlRoot: result.controlRoot ?? null,
    });
}

async function createAvailability(options) {
    if (process.platform !== "win32") {
        return freezeAvailability({
            available: false,
            code: MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE,
            reason: `Windows AppContainer containment is unavailable on ${process.platform}`,
        });
    }
    try {
        const controlRoot = normalizeControlRoot(options.controlRoot);
        const helper = await compileHelper(controlRoot);
        const probe = await probeWithHelper(helper, controlRoot, options.limits);
        return freezeAvailability({
            available: true,
            helperSourceHash:
                `${HELPER_SOURCE_HASH_TAG}:${helper.sourceHash}`,
            helperBinaryHash: `${FILE_HASH_TAG}:${helper.hash}`,
            launcherId: HELPER_LAUNCHER_ID,
            launcherBinaryHash: `${FILE_HASH_TAG}:${helper.launcher.hash}`,
            launcherScriptHash: HELPER_LAUNCHER_SCRIPT_HASH,
            policyIdentity: buildPolicyIdentity(helper, options.limits),
            probe,
            helper,
            controlRoot,
        });
    } catch (error) {
        const typed = error instanceof SandboxUnavailableError
            ? error
            : unavailable(
                `Windows sandbox probe failed: ${error?.message ?? String(error)}`,
                { cause: error?.code ?? null },
            );
        return freezeAvailability({
            available: false,
            code: MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE,
            reason: typed.message,
            details: typed.details ?? null,
        });
    }
}

export async function probeWindowsSandboxAvailability(options = {}) {
    const limits = normalizeLimits(options.limits);
    const result = await createAvailability({
        controlRoot: options.controlRoot,
        limits,
    });
    return Object.freeze({
        available: result.available,
        code: result.code,
        reason: result.reason,
        details: result.details,
        primitive: result.primitive,
        policyId: result.policyId,
        helperSourceHash: result.helperSourceHash,
        helperBinaryHash: result.helperBinaryHash,
        launcherId: result.launcherId,
        launcherBinaryHash: result.launcherBinaryHash,
        launcherScriptHash: result.launcherScriptHash,
        policyIdentity: result.policyIdentity,
        limitations: result.limitations,
        probe: result.probe,
    });
}

function requireAvailability(availability) {
    if (availability.available !== true) {
        throw unavailable(
            availability.reason ?? "Windows sandbox is unavailable",
            {
                primitive: WINDOWS_SANDBOX_PRIMITIVE,
                code: availability.code,
                limitations: WINDOWS_SANDBOX_LIMITATIONS,
            },
        );
    }
    return availability;
}

function stateHash(file) {
    return hashFile(file);
}

function ensureStateHash(file, expected) {
    if (!fs.existsSync(file)) return false;
    const actual = stateHash(file);
    if (actual !== expected) {
        throw unavailable("Windows sandbox recovery state changed unexpectedly", {
            statePath: file,
            expected: `${FILE_HASH_TAG}:${expected}`,
            actual: `${FILE_HASH_TAG}:${actual}`,
        });
    }
    return true;
}

function sandboxProfileEnvironment(outputRoot) {
    const userProfile = path.join(outputRoot, "Profile");
    const localAppData = process.env.LOCALAPPDATA;
    if (typeof localAppData !== "string"
        || !path.isAbsolute(localAppData)) {
        throw unavailable(
            "Windows sandbox host profile mapping paths are unavailable",
        );
    }
    const root = path.parse(outputRoot).root;
    // AppContainer process creation maps the host LOCALAPPDATA and TEMP
    // preimages into this profile. Passing the profile path for those keys
    // would map it a second time; USERPROFILE/APPDATA are not auto-mapped.
    return Object.freeze({
        USERPROFILE: userProfile,
        LOCALAPPDATA: localAppData,
        APPDATA: path.join(outputRoot, "Roaming"),
        HOME: userProfile,
        HOMEDRIVE: root.replace(/[\\/]$/u, ""),
        HOMEPATH: userProfile.slice(root.length - 1),
        TEMP: path.join(localAppData, "Temp"),
        TMP: path.join(localAppData, "Temp"),
    });
}

function effectiveEnvironment(requestEnv, outputRoot) {
    const env = { ...requestEnv };
    const profile = sandboxProfileEnvironment(outputRoot);
    for (const [key, value] of Object.entries(profile)) {
        env[key] = value;
    }

    env.CRUCIBLE_SANDBOX_OUTPUT = outputRoot;
    const nodePathFlags = "--preserve-symlinks --preserve-symlinks-main";
    env.NODE_OPTIONS = typeof env.NODE_OPTIONS === "string"
        && env.NODE_OPTIONS.length > 0
        ? `${env.NODE_OPTIONS} ${nodePathFlags}`
        : nodePathFlags;
    return Object.freeze(env);
}

function buildPolicyIdentity(helper, limits) {
    return Object.freeze({
        required: true,
        primitive: WINDOWS_SANDBOX_PRIMITIVE,
        providerId: PROVIDER_ID,
        providerVersion: PROVIDER_VERSION,
        policyId: WINDOWS_SANDBOX_POLICY_ID,
        helperSourceHash: `${HELPER_SOURCE_HASH_TAG}:${helper.sourceHash}`,
        helperBinaryHash: `${FILE_HASH_TAG}:${helper.hash}`,
        launcherId: HELPER_LAUNCHER_ID,
        launcherBinaryHash: `${FILE_HASH_TAG}:${helper.launcher.hash}`,
        launcherScriptHash: HELPER_LAUNCHER_SCRIPT_HASH,
        securityContext: Object.freeze({
            appContainer: true,
            lowIntegrity: true,
            capabilities: Object.freeze([]),
            loopbackExemptionRejected: true,
        }),
        network: Object.freeze({
            mode: "deny-by-default",
            enforcement:
                "zero-capability AppContainer token with no loopback exemption",
        }),
        filesystem: Object.freeze({
            stagedHarness: "exact-manifest-read-execute",
            immutableCandidate: "private-staged-copy-read-only",
            outputTemp: "appcontainer-profile-only",
            aclJournalRestored: true,
            exactLaunchClosure: true,
            hostWriteDenied: true,
        }),
        job: Object.freeze({
            killOnJobClose: true,
            descendantsContained: true,
            uiRestrictions: true,
            ...limits,
        }),
    });
}

function normalizeClock(clock) {
    const resolved = clock ?? SYSTEM_CLOCK;
    if (resolved === null
        || typeof resolved !== "object"
        || typeof resolved.now !== "function") {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "Windows sandbox clock must expose now()",
        );
    }
    return resolved;
}

function clockNowMs(clock) {
    const value = clock.now();
    if (!Number.isFinite(value)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "Windows sandbox clock.now() must return finite epoch milliseconds",
            { observedAtMs: value },
        );
    }
    return Math.floor(value);
}

function requestStageTimeout(request, stage, clock) {
    const deadlineMs = request?.launch?.deadlineMs;
    const observedAtMs = clockNowMs(clock);
    return new MeasurementError(
        MEASUREMENT_ERROR_CODES.TIMEOUT,
        `sandbox timeout expired during ${stage}`,
        {
            deadlineExceeded: deadlineMs !== null
                && deadlineMs !== undefined
                && observedAtMs >= Math.floor(deadlineMs),
            deadlineMs: deadlineMs ?? null,
            observedAtMs,
            stage,
        },
    );
}

function requestDeadlineTimeout(
    request,
    maximum,
    stage,
    budgetStartedAtMs = null,
    clock = SYSTEM_CLOCK,
) {
    const requested = request?.launch?.timeoutMs;
    const deadlineMs = request?.launch?.deadlineMs;
    const maximumMs = Math.floor(maximum);
    if (!Number.isSafeInteger(maximumMs) || maximumMs < 1) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "Windows sandbox timeout maximum must be a positive safe integer",
            { maximum, stage },
        );
    }
    if (deadlineMs !== null && deadlineMs !== undefined) {
        if (!Number.isFinite(deadlineMs)) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                "sandbox launch deadlineMs must be finite epoch milliseconds or null",
                { deadlineMs },
            );
        }
    }
    const observedAtMs = clockNowMs(clock);
    const elapsedBudgetMs = Number.isFinite(budgetStartedAtMs)
        ? Math.max(0, observedAtMs - Math.floor(budgetStartedAtMs))
        : 0;
    let timeoutMs = Number.isSafeInteger(requested) && requested > 0
        ? Math.min(maximumMs, requested)
        : maximumMs;
    timeoutMs -= elapsedBudgetMs;
    if (deadlineMs !== null && deadlineMs !== undefined) {
        timeoutMs = Math.min(
            timeoutMs,
            Math.floor(deadlineMs - observedAtMs),
        );
    }
    if (timeoutMs < 1) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.TIMEOUT,
            `sandbox deadline expired during ${stage}`,
            {
                deadlineExceeded: true,
                deadlineMs: deadlineMs ?? null,
                elapsedBudgetMs,
                observedAtMs,
                stage,
            },
        );
    }
    return timeoutMs;
}

function pathInside(candidate, root) {
    const relative = path.relative(root, candidate);
    return relative === ""
        || (!path.isAbsolute(relative)
            && relative !== ".."
            && !relative.startsWith(`..${path.sep}`));
}

function buildNativeLaunchManifest(request) {
    const stageRoot = request.stagedRoots[0];
    const candidateRoot = request.candidateSnapshot.path;
    const launch = request.launch;
    if (!Array.isArray(launch?.launchFiles)
        || launch.launchFiles.length === 0) {
        throw unavailable(
            "Windows sandbox admission requires exact launch-file bindings",
        );
    }
    const directories = new Set([stageRoot]);
    const addDirectory = (directory) => {
        let current = path.resolve(directory);
        if (!pathInside(current, stageRoot)) {
            throw unavailable(
                "Windows sandbox launch manifest directory escaped the staged root",
                { directory: current, stageRoot },
            );
        }
        while (true) {
            directories.add(current);
            if (current.toLowerCase() === stageRoot.toLowerCase()) break;
            current = path.dirname(current);
        }
    };
    addDirectory(launch.cwd);
    addDirectory(candidateRoot);
    const files = launch.launchFiles.map((file) => {
        if (!pathInside(file.path, stageRoot)) {
            throw unavailable(
                "Windows sandbox launch manifest file escaped the staged root",
                { file: file.path, stageRoot },
            );
        }
        addDirectory(path.dirname(file.path));
        return {
            path: file.path,
            role: file.role,
            sha256: file.sha256.split(":").pop(),
        };
    }).sort((left, right) =>
        left.path.toLowerCase().localeCompare(right.path.toLowerCase()));
    return Object.freeze({
        version: 1,
        stageRoot,
        candidateRoot,
        executable: launch.executable,
        currentDirectory: launch.cwd,
        directories: [...directories].sort((left, right) =>
            left.toLowerCase().localeCompare(right.toLowerCase())),
        files,
    });
}

function writeNativeLaunchManifest(attemptRoot, request) {
    const manifest = buildNativeLaunchManifest(request);
    const bytes = Buffer.from(canonicalJson(manifest), "utf8");
    const manifestPath = path.join(attemptRoot, "launch-manifest.json");
    const fd = fs.openSync(manifestPath, "wx", 0o400);
    try {
        let offset = 0;
        while (offset < bytes.length) {
            offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
        }
        fs.fsyncSync(fd);
    } finally {
        fs.closeSync(fd);
    }
    try { fs.chmodSync(manifestPath, 0o400); } catch { /* ACLs govern Windows */ }
    return Object.freeze({
        path: fs.realpathSync.native(manifestPath),
        hash: sha256Hex(bytes),
        manifest,
    });
}

function waitForChildClose(child, timeoutMs) {
    if (child.exitCode !== null || child.signalCode !== null) {
        return Promise.resolve(true);
    }
    return new Promise((resolve) => {
        let settled = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve(value);
        };
        child.once("close", () => finish(true));
        const timer = setTimeout(() => finish(false), timeoutMs);
        timer.unref?.();
    });
}

async function requestHelperTermination(child, graceMs) {
    if (child === null
        || child === undefined
        || child.exitCode !== null
        || child.signalCode !== null) {
        return true;
    }
    try {
        child.stdin?.write(Buffer.from([0x4b]));
        child.stdin?.end();
    } catch {
        // The helper may already be exiting.
    }
    if (await waitForChildClose(child, graceMs)) return true;
    try { child.kill(); } catch { /* recovery helper handles cleanup */ }
    return waitForChildClose(child, graceMs);
}

function buildPolicy({
    helper,
    limits,
    configuredLimits,
    request,
    prepared,
    profileEnvironment,
}) {
    const identity = buildPolicyIdentity(helper, configuredLimits);
    const policy = {
        version: WINDOWS_POLICY_VERSION,
        identity,
        filesystem: {
            outputRootHash: taggedHash(
                FILE_HASH_TAG,
                Buffer.from(prepared.outputRoot, "utf8"),
            ),
        },
        effectiveJob: { ...limits },
        launchBinding: {
            candidateSnapshotHash: request.candidateSnapshot.hash,
            argvHash: request.launch.argvHash,
            requestedEnvHash: request.launch.envHash,
            effectiveEnvironment:
                "requested environment with AppContainer-remapped local/temp paths, provider-owned home/roaming paths, and Node no-realpath overrides",
            profileEnvironmentHash: taggedHash(
                FILE_HASH_TAG,
                Buffer.from(canonicalJson(profileEnvironment), "utf8"),
            ),
            stagedRootsHash: taggedHash(
                FILE_HASH_TAG,
                Buffer.from(canonicalJson(request.stagedRoots), "utf8"),
            ),
            appContainerSidHash: taggedHash(
                FILE_HASH_TAG,
                Buffer.from(prepared.appContainerSid, "utf8"),
            ),
        },
    };
    return Object.freeze({
        identity,
        policy,
        digest: taggedHash(
            POLICY_HASH_TAG,
            Buffer.from(canonicalJson(policy), "utf8"),
        ),
    });
}

export function createWindowsSandboxProvider(options = {}) {
    const limits = normalizeLimits(options.limits);
    const clock = normalizeClock(options.clock);
    const testHooks = options.testHooks ?? {};
    if (testHooks === null
        || typeof testHooks !== "object"
        || Array.isArray(testHooks)
        || Object.keys(testHooks).some((key) =>
            ![
                "beforeHelperSpawn",
                "failAssignProcessToJobObject",
                "invalidManagedHelperStartup",
            ].includes(key))
        || (testHooks.beforeHelperSpawn !== undefined
            && typeof testHooks.beforeHelperSpawn !== "function")
        || (testHooks.failAssignProcessToJobObject !== undefined
            && typeof testHooks.failAssignProcessToJobObject !== "boolean")
        || (testHooks.invalidManagedHelperStartup !== undefined
            && typeof testHooks.invalidManagedHelperStartup !== "boolean")) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "Windows sandbox testHooks are malformed",
        );
    }
    const requestedControlRoot = options.controlRoot;
    let availabilityPromise = null;
    const availability = () => {
        availabilityPromise ??= createAvailability({
            controlRoot: requestedControlRoot,
            limits,
        });
        return availabilityPromise;
    };

    return createSandboxProvider({
        providerId: PROVIDER_ID,
        providerVersion: PROVIDER_VERSION,
        async describePolicyIdentity() {
            const available = requireAvailability(await availability());
            verifyHelper(available.helper);
            return buildPolicyIdentity(available.helper, limits);
        },
        async admitAndPrepare(request, issueLaunchCapability) {
            requestDeadlineTimeout(
                request,
                120_000,
                "native sandbox preparation",
                null,
                clock,
            );
            const available = requireAvailability(await availability());
            const budgetStartedAtMs = clockNowMs(clock);
            const helper = available.helper;
            const controlRoot = available.controlRoot;
            if (request.stagedRoots.length !== 1) {
                throw unavailable(
                    "Windows AppContainer provider requires exactly one private staged root",
                    { stagedRoots: request.stagedRoots },
                );
            }
            verifyHelper(helper);
            const token = randomBytes(16).toString("hex");
            const capabilityId = `winac-${token}`;
            const profileName =
                `Crucible.Sandbox.${process.pid}.${threadId}.${token}`;
            const attemptRoot = path.join(controlRoot, `attempt-${token}`);
            fs.mkdirSync(attemptRoot, { recursive: false, mode: 0o700 });
            const statePath = path.join(attemptRoot, "sandbox-state.json");
            const launchManifest = writeNativeLaunchManifest(
                attemptRoot,
                request,
            );
            let prepared;
            let expectedStateHash = null;
            let child = null;
            let launchHelperInvocation = null;
            let cleaned = false;
            let prepareHelperLaunched = false;
            try {
                prepared = await runHelperJson(
                    helper,
                    "prepare",
                    [
                        statePath,
                        profileName,
                        request.stagedRoots[0],
                        request.candidateSnapshot.path,
                        helper.sourceHash,
                        launchManifest.path,
                        launchManifest.hash,
                    ],
                    {
                        timeoutMs: () => requestDeadlineTimeout(
                            request,
                            120_000,
                            "native sandbox preparation",
                            budgetStartedAtMs,
                            clock,
                        ),
                        timeoutError: () => requestStageTimeout(
                            request,
                            "native sandbox preparation",
                            clock,
                        ),
                        invocationRoot: attemptRoot,
                        beforeSpawn: testHooks.beforeHelperSpawn,
                        afterSpawn() {
                            prepareHelperLaunched = true;
                        },
                    },
                );
                if (prepared.prepared !== true
                    || typeof prepared.appContainerSid !== "string"
                    || typeof prepared.outputRoot !== "string"
                    || !path.isAbsolute(prepared.outputRoot)) {
                    throw unavailable(
                        "Windows sandbox preparation returned an invalid attestation",
                        { prepared },
                    );
                }
                expectedStateHash = stateHash(statePath);
                const profileEnvironment =
                    sandboxProfileEnvironment(prepared.outputRoot);
                const effectiveLimits = Object.freeze({
                    ...limits,
                    wallTimeMs: requestDeadlineTimeout(
                        request,
                        limits.wallTimeMs,
                        "native sandbox policy issuance",
                        budgetStartedAtMs,
                        clock,
                    ),
                });
                const policy = buildPolicy({
                    helper,
                    limits: effectiveLimits,
                    configuredLimits: limits,
                    request,
                    prepared,
                    profileEnvironment,
                });

                return issueLaunchCapability({
                    capabilityId,
                    policyId: WINDOWS_SANDBOX_POLICY_ID,
                    policyDigest: policy.digest,
                    policyIdentity: policy.identity,
                    policy: policy.policy,
                    permittedStagedRoots: request.stagedRoots,
                    async launch(launchRequest) {
                        verifyHelper(helper);
                        ensureStateHash(statePath, expectedStateHash);
                        if (launchRequest.policyDigest !== policy.digest) {
                            throw unavailable(
                                "Windows sandbox launch policy binding changed",
                                {
                                    expected: policy.digest,
                                    actual: launchRequest.policyDigest,
                                },
                            );
                        }
                        const effectiveEnv = effectiveEnvironment(
                            launchRequest.options.env,
                            prepared.outputRoot,
                        );
                        const actualRequestedEnvHash = hashEnv(
                            launchRequest.options.env,
                        );
                        if (actualRequestedEnvHash !== request.launch.envHash) {
                            throw unavailable(
                                "Windows sandbox requested environment binding changed",
                                {
                                    expected: request.launch.envHash,
                                    actual: actualRequestedEnvHash,
                                },
                            );
                        }
                        const envPayload = Buffer.from(
                            JSON.stringify(effectiveEnv),
                            "utf8",
                        ).toString("base64");
                        launchHelperInvocation = stageHelperInvocation(
                            helper,
                            attemptRoot,
                            "launch",
                        );
                        try {
                            const resolveHelperTimeoutMs = () => Math.min(
                                effectiveLimits.wallTimeMs,
                                requestDeadlineTimeout(
                                    request,
                                    limits.wallTimeMs,
                                    "native sandbox helper launch",
                                    budgetStartedAtMs,
                                    clock,
                                ),
                            );
                            let helperTimeoutMs = resolveHelperTimeoutMs();
                            await testHooks.beforeHelperSpawn?.(Object.freeze({
                                operation: "launch",
                                helperPath: launchHelperInvocation.path,
                                helperRoot: launchHelperInvocation.root,
                                launchManifestPath: launchManifest.path,
                                statePath,
                                launchRequest,
                                timeoutMs: helperTimeoutMs,
                            }));
                            verifyHelperInvocation(launchHelperInvocation);
                            verifyHelper(helper);
                            let managedHelperPath =
                                launchHelperInvocation.path;
                            if (testHooks.invalidManagedHelperStartup === true) {
                                managedHelperPath = path.join(
                                    launchHelperInvocation.root,
                                    "invalid-managed-helper.exe",
                                );
                                fs.writeFileSync(
                                    managedHelperPath,
                                    Buffer.from("not-a-managed-assembly", "utf8"),
                                    { flag: "wx", mode: 0o400 },
                                );
                            }
                            helperTimeoutMs = resolveHelperTimeoutMs();
                            const helperArgv = [
                                    "launch",
                                    statePath,
                                    expectedStateHash,
                                    String(process.pid),
                                    launchRequest.executable,
                                    launchRequest.options.cwd,
                                    envPayload,
                                    String(effectiveLimits.activeProcessLimit),
                                    String(effectiveLimits.processMemoryBytes),
                                    String(effectiveLimits.jobMemoryBytes),
                                    String(effectiveLimits.cpuRatePercent),
                                    String(effectiveLimits.cpuTimeMs),
                                    String(helperTimeoutMs),
                                    testHooks.failAssignProcessToJobObject === true
                                        ? "1"
                                        : "0",
                                    "--",
                                    ...launchRequest.argv,
                            ];
                            const managed = prepareManagedHelperLaunch(
                                helper,
                                launchHelperInvocation,
                                helperArgv,
                                { helperPath: managedHelperPath },
                            );
                            child = spawn(
                                managed.executable,
                                managed.argv,
                                {
                                cwd: managed.cwd,
                                env: managed.env,
                                stdio: ["pipe", "pipe", "pipe"],
                                shell: false,
                                windowsHide: true,
                                detached: false,
                                },
                            );
                            verifyHelper(helper);
                            if (testHooks.invalidManagedHelperStartup !== true) {
                                verifyHelperInvocation(launchHelperInvocation);
                            }
                            child = await waitForManagedHelperReady(
                                child,
                                Math.min(5_000, helperTimeoutMs),
                            );
                        } catch (error) {
                            await requestHelperTermination(child, 1_000);
                            closeHelperInvocation(launchHelperInvocation);
                            launchHelperInvocation = null;
                            throw error;
                        }
                        child.once("error", () => {
                            // Executor observes the child error. Recovery remains
                            // capability-owned and runs from cleanup().
                        });
                        return child;
                    },
                    async terminate() {
                        return requestHelperTermination(
                            child,
                            limits.terminationGraceMs,
                        );
                    },
                    async cleanup() {
                        if (cleaned) return true;
                        const stopped = await requestHelperTermination(
                            child,
                            limits.terminationGraceMs,
                        );
                        if (!stopped) {
                            throw new Error(
                                "Windows sandbox helper did not terminate within the cleanup grace period",
                            );
                        }
                        if (launchHelperInvocation !== null) {
                            closeHelperInvocation(launchHelperInvocation);
                            launchHelperInvocation = null;
                        }
                        if (expectedStateHash !== null && fs.existsSync(statePath)) {
                            ensureStateHash(statePath, expectedStateHash);
                        }
                        const result = await runHelperJson(
                            helper,
                            "cleanup",
                            [
                                statePath,
                                expectedStateHash ?? "",
                                profileName,
                                prepared.outputRoot,
                            ],
                            {
                                timeoutMs: 120_000,
                                invocationRoot: attemptRoot,
                                beforeSpawn: testHooks.beforeHelperSpawn,
                            },
                        );
                        if (result.cleaned !== true
                            || fs.existsSync(prepared.outputRoot)) {
                            throw new Error(
                                "Windows sandbox native cleanup did not remove the AppContainer profile",
                            );
                        }
                        fs.rmSync(attemptRoot, { recursive: true, force: true });
                        cleaned = true;
                        return true;
                    },
                });
            } catch (error) {
                if (!prepareHelperLaunched
                    && prepared === undefined
                    && !fs.existsSync(statePath)) {
                    fs.rmSync(attemptRoot, { recursive: true, force: true });
                    throw error;
                }
                let recoveryError = null;
                try {
                    const recoveryHash = fs.existsSync(statePath)
                        ? expectedStateHash ?? stateHash(statePath)
                        : "";
                    await runHelperJson(
                        helper,
                        "cleanup",
                        [
                            statePath,
                            recoveryHash,
                            profileName,
                            prepared?.outputRoot ?? "",
                        ],
                        { timeoutMs: 120_000 },
                    );
                } catch (cleanupError) {
                    recoveryError = cleanupError;
                }
                if (recoveryError === null) {
                    fs.rmSync(attemptRoot, { recursive: true, force: true });
                } else {
                    throw unavailable(
                        "Windows sandbox admission failed and native rollback could not be completed",
                        {
                            admissionError:
                                error?.message ?? String(error),
                            rollbackError:
                                recoveryError?.message ?? String(recoveryError),
                            rollbackDetails: recoveryError?.details ?? null,
                            recoveryState: statePath,
                        },
                    );
                }
                throw error;
            }
        },
    });
}

const HELPER_SOURCE = String.raw`using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class CrucibleWindowsSandbox
{
    private const int StateVersion = 2;
    private const int ProcThreadAttributeHandleList = 0x00020002;
    private const int ProcThreadAttributeSecurityCapabilities = 0x00020009;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 0x00000102;
    private const uint Synchronize = 0x00100000;
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint TokenQuery = 0x0008;
    private const int TokenIntegrityLevel = 25;
    private const int TokenIsAppContainer = 29;
    private const int TokenCapabilities = 30;
    private const int SecurityMandatoryLowRid = 0x1000;
    private const int JobObjectBasicUiRestrictions = 4;
    private const int JobInfoExtendedLimits = 9;
    private const int JobInfoCpuRateControl = 15;
    private const uint JobObjectLimitJobTime = 0x00000004;
    private const uint JobObjectLimitActiveProcess = 0x00000008;
    private const uint JobObjectLimitDieOnUnhandledException = 0x00000400;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectLimitProcessMemory = 0x00000100;
    private const uint JobObjectLimitJobMemory = 0x00000200;
    private const uint JobObjectCpuRateControlEnable = 0x1;
    private const uint JobObjectCpuRateControlHardCap = 0x4;
    private const uint JobObjectUiLimitHandles = 0x1;
    private const uint JobObjectUiLimitReadClipboard = 0x2;
    private const uint JobObjectUiLimitWriteClipboard = 0x4;
    private const uint JobObjectUiLimitSystemParameters = 0x8;
    private const uint JobObjectUiLimitDisplaySettings = 0x10;
    private const uint JobObjectUiLimitGlobalAtoms = 0x20;
    private const uint JobObjectUiLimitDesktop = 0x40;
    private const uint JobObjectUiLimitExitWindows = 0x80;
    private const uint FileReadAttributes = 0x80;
    private const uint FileWriteAttributes = 0x100;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x1;
    private const uint FileShareWrite = 0x2;
    private const uint FileShareDelete = 0x4;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint HandleFlagInherit = 0x1;
    private const int StdOutputHandle = -11;
    private const int StdErrorHandle = -12;
    private const uint ErrorFileNotFound = 2;
    private const uint ErrorPathNotFound = 3;
    private const uint ErrorNotFound = 1168;
    private const uint SemFailCriticalErrors = 0x0001;
    private const uint SemNoGpFaultErrorBox = 0x0002;
    private const uint SemNoOpenFileErrorBox = 0x8000;
    private const uint WerFaultReportingNoUi = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityCapabilities
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
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
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectCpuRateControlInformation
    {
        public uint ControlFlags;
        public uint CpuRate;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenMandatoryLabel
    {
        public SidAndAttributes Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfo
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    private sealed class JournalEntry
    {
        public string Path { get; set; }
        public bool Directory { get; set; }
        public bool ExecuteAllowed { get; set; }
        public string Sddl { get; set; }
        public long CreationTime { get; set; }
        public long LastAccessTime { get; set; }
        public long LastWriteTime { get; set; }
        public long ChangeTime { get; set; }
        public uint FileAttributes { get; set; }
    }

    private sealed class SandboxState
    {
        public int Version { get; set; }
        public string SourceHash { get; set; }
        public string ProfileName { get; set; }
        public string AppContainerSid { get; set; }
        public string ProfileRoot { get; set; }
        public string OutputRoot { get; set; }
        public string StageRoot { get; set; }
        public string CandidateRoot { get; set; }
        public List<JournalEntry> Journal { get; set; }
        public List<string> LaunchDirectories { get; set; }
        public List<LaunchFileRecord> LaunchFiles { get; set; }
    }

    private sealed class LaunchManifest
    {
        public int Version { get; set; }
        public string StageRoot { get; set; }
        public string CandidateRoot { get; set; }
        public string Executable { get; set; }
        public string CurrentDirectory { get; set; }
        public List<string> Directories { get; set; }
        public List<LaunchFileSpec> Files { get; set; }
    }

    private sealed class LaunchFileSpec
    {
        public string Path { get; set; }
        public string Role { get; set; }
        public string Sha256 { get; set; }
    }

    private sealed class LaunchFileRecord
    {
        public string Path { get; set; }
        public string Role { get; set; }
        public string Sha256 { get; set; }
        public uint VolumeSerialNumber { get; set; }
        public uint FileIndexHigh { get; set; }
        public uint FileIndexLow { get; set; }
        public uint FileSizeHigh { get; set; }
        public uint FileSizeLow { get; set; }
    }

    private sealed class PinnedLaunchFile : IDisposable
    {
        public LaunchFileRecord Expected { get; set; }
        public FileStream Stream { get; set; }

        public void Dispose()
        {
            if (Stream != null) Stream.Dispose();
            Stream = null;
        }
    }

    private sealed class ProbeResult
    {
        public bool available { get; set; }
        public bool appContainer { get; set; }
        public bool lowIntegrity { get; set; }
        public bool zeroCapabilities { get; set; }
        public bool networkDenied { get; set; }
        public bool secretDenied { get; set; }
        public bool registryDenied { get; set; }
        public bool outputWriteAllowed { get; set; }
        public bool jobObjectConfigured { get; set; }
    }

    private sealed class ChildProbeResult
    {
        public bool AppContainer { get; set; }
        public bool LowIntegrity { get; set; }
        public bool ZeroCapabilities { get; set; }
        public bool NetworkDenied { get; set; }
        public bool SecretDenied { get; set; }
        public bool RegistryDenied { get; set; }
        public bool OutputWriteAllowed { get; set; }
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int CreateAppContainerProfile(
        string name,
        string displayName,
        string description,
        IntPtr capabilities,
        uint capabilityCount,
        out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeleteAppContainerProfile(string name);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(
        string name,
        out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int GetAppContainerFolderPath(
        string appContainerSid,
        out IntPtr path);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertSidToStringSid(
        IntPtr sid,
        out IntPtr stringSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool EqualSid(IntPtr left, IntPtr right);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr process,
        uint desiredAccess,
        out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr token,
        int informationClass,
        IntPtr information,
        int informationLength,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    [DllImport("FirewallAPI.dll", SetLastError = true)]
    private static extern uint NetworkIsolationGetAppContainerConfig(
        out uint count,
        out IntPtr appContainerSids);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr value);

    [DllImport("ole32.dll")]
    private static extern void CoTaskMemFree(IntPtr value);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        IntPtr file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetInformationJobObject")]
    private static extern bool SetInformationJobObjectCpu(
        IntPtr job,
        int informationClass,
        ref JobObjectCpuRateControlInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetInformationJobObject")]
    private static extern bool SetInformationJobObjectUi(
        IntPtr job,
        int informationClass,
        ref uint information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(
        IntPtr job,
        IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr list,
        int count,
        int flags,
        ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr list,
        uint flags,
        IntPtr attribute,
        IntPtr value,
        IntPtr size,
        IntPtr previous,
        IntPtr returned);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcess(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        [In] ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        IntPtr handle,
        uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForMultipleObjects(
        uint count,
        IntPtr[] handles,
        bool waitAll,
        uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(
        IntPtr process,
        out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint desiredAccess,
        bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll")]
    private static extern uint SetErrorMode(uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadErrorMode(uint mode, out uint oldMode);

    [DllImport("wer.dll", SetLastError = true)]
    private static extern int WerSetFlags(uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEvent(
        IntPtr attributes,
        bool manualReset,
        bool initialState,
        string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        IntPtr file,
        int informationClass,
        out FileBasicInfo information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        IntPtr file,
        int informationClass,
        ref FileBasicInfo information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(
        IntPtr handle,
        uint mask,
        uint flags);

    private static JavaScriptSerializer Serializer()
    {
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        serializer.MaxJsonLength = 16 * 1024 * 1024;
        serializer.RecursionLimit = 256;
        return serializer;
    }

    internal static void ConfigureNoUi()
    {
        uint mode = SemFailCriticalErrors
            | SemNoGpFaultErrorBox
            | SemNoOpenFileErrorBox;
        SetErrorMode(mode);
        try
        {
            uint oldMode;
            SetThreadErrorMode(mode, out oldMode);
        }
        catch { }
        try { WerSetFlags(WerFaultReportingNoUi); }
        catch { }
    }

    private static void WriteJson(object value)
    {
        Console.Out.Write(Serializer().Serialize(value));
    }

    private static string FullPath(string value, string field)
    {
        if (String.IsNullOrWhiteSpace(value) || !Path.IsPathRooted(value))
            throw new InvalidOperationException(field + " must be absolute");
        return Path.GetFullPath(value);
    }

    private static bool SamePath(string left, string right)
    {
        return String.Equals(
            Path.GetFullPath(left).TrimEnd('\\'),
            Path.GetFullPath(right).TrimEnd('\\'),
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool InsidePath(string value, string root)
    {
        string pathValue = Path.GetFullPath(value).TrimEnd('\\');
        string pathRoot = Path.GetFullPath(root).TrimEnd('\\');
        return SamePath(pathValue, pathRoot)
            || pathValue.StartsWith(pathRoot + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static string Sha256File(string file)
    {
        using (FileStream stream = new FileStream(
            file,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read))
        using (SHA256 hash = SHA256.Create())
            return BitConverter.ToString(hash.ComputeHash(stream))
                .Replace("-", "")
                .ToLowerInvariant();
    }

    private static string Sha256Stream(FileStream stream)
    {
        long original = stream.Position;
        try
        {
            stream.Position = 0;
            using (SHA256 hash = SHA256.Create())
                return BitConverter.ToString(hash.ComputeHash(stream))
                    .Replace("-", "")
                    .ToLowerInvariant();
        }
        finally
        {
            stream.Position = original;
        }
    }

    private static ByHandleFileInformation HandleIdentity(FileStream stream)
    {
        ByHandleFileInformation information;
        if (!GetFileInformationByHandle(
            stream.SafeFileHandle.DangerousGetHandle(),
            out information))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return information;
    }

    private static LaunchFileRecord CaptureLaunchFile(LaunchFileSpec spec)
    {
        string file = FullPath(spec.Path, "launch file");
        if (String.IsNullOrWhiteSpace(spec.Role)
            || String.IsNullOrWhiteSpace(spec.Sha256)
            || spec.Sha256.Length != 64)
            throw new InvalidOperationException(
                "launch file binding is malformed");
        FileAttributes attributes = File.GetAttributes(file);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException(
                "launch file is a reparse point: " + file);
        using (FileStream stream = new FileStream(
            file,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read))
        {
            ByHandleFileInformation identity = HandleIdentity(stream);
            string hash = Sha256Stream(stream);
            if (!String.Equals(hash, spec.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "launch file hash did not match: " + file);
            return new LaunchFileRecord
            {
                Path = file,
                Role = spec.Role,
                Sha256 = hash,
                VolumeSerialNumber = identity.VolumeSerialNumber,
                FileIndexHigh = identity.FileIndexHigh,
                FileIndexLow = identity.FileIndexLow,
                FileSizeHigh = identity.FileSizeHigh,
                FileSizeLow = identity.FileSizeLow
            };
        }
    }

    private static bool SameLaunchIdentity(
        LaunchFileRecord expected,
        ByHandleFileInformation actual)
    {
        return expected.VolumeSerialNumber == actual.VolumeSerialNumber
            && expected.FileIndexHigh == actual.FileIndexHigh
            && expected.FileIndexLow == actual.FileIndexLow
            && expected.FileSizeHigh == actual.FileSizeHigh
            && expected.FileSizeLow == actual.FileSizeLow;
    }

    private static List<PinnedLaunchFile> OpenPinnedLaunchFiles(
        IEnumerable<LaunchFileRecord> records)
    {
        List<PinnedLaunchFile> pinned = new List<PinnedLaunchFile>();
        try
        {
            foreach (LaunchFileRecord record in records)
            {
                FileStream stream = new FileStream(
                    record.Path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read);
                PinnedLaunchFile item = new PinnedLaunchFile
                {
                    Expected = record,
                    Stream = stream
                };
                pinned.Add(item);
                ByHandleFileInformation identity = HandleIdentity(stream);
                if (!SameLaunchIdentity(record, identity)
                    || !String.Equals(
                        Sha256Stream(stream),
                        record.Sha256,
                        StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        "launch file identity changed: " + record.Path);
            }
            return pinned;
        }
        catch
        {
            foreach (PinnedLaunchFile item in pinned) item.Dispose();
            throw;
        }
    }

    private static void VerifyPinnedLaunchFiles(
        IEnumerable<PinnedLaunchFile> pinned)
    {
        foreach (PinnedLaunchFile item in pinned)
        {
            ByHandleFileInformation identity = HandleIdentity(item.Stream);
            if (!SameLaunchIdentity(item.Expected, identity)
                || !String.Equals(
                    Sha256Stream(item.Stream),
                    item.Expected.Sha256,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "launch file changed immediately before CreateProcess: "
                    + item.Expected.Path);
        }
    }

    private static LaunchManifest ReadLaunchManifest(
        string manifestPath,
        string expectedHash)
    {
        manifestPath = FullPath(manifestPath, "launch manifest");
        string json;
        using (FileStream stream = new FileStream(
            manifestPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read))
        {
            if (!String.Equals(
                Sha256Stream(stream),
                expectedHash,
                StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "launch manifest hash did not match");
            stream.Position = 0;
            using (StreamReader reader = new StreamReader(
                stream,
                Encoding.UTF8,
                true,
                4096,
                true))
                json = reader.ReadToEnd();
        }
        LaunchManifest manifest =
            Serializer().Deserialize<LaunchManifest>(json);
        if (manifest == null
            || manifest.Version != 1
            || manifest.Directories == null
            || manifest.Files == null
            || manifest.Files.Count == 0)
            throw new InvalidOperationException(
                "launch manifest is malformed");
        manifest.StageRoot = FullPath(manifest.StageRoot, "manifest stage root");
        manifest.CandidateRoot =
            FullPath(manifest.CandidateRoot, "manifest candidate root");
        manifest.Executable =
            FullPath(manifest.Executable, "manifest executable");
        manifest.CurrentDirectory =
            FullPath(manifest.CurrentDirectory, "manifest current directory");
        manifest.Directories = manifest.Directories
            .Select(delegate(string directory) {
                return FullPath(directory, "manifest directory");
            })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(delegate(string directory) { return directory; },
                StringComparer.OrdinalIgnoreCase)
            .ToList();
        manifest.Files = manifest.Files
            .OrderBy(delegate(LaunchFileSpec file) { return file.Path; },
                StringComparer.OrdinalIgnoreCase)
            .ToList();
        return manifest;
    }

    private static void VerifyExactLaunchTree(
        string stageRoot,
        IEnumerable<string> expectedDirectories,
        IEnumerable<string> expectedFiles)
    {
        stageRoot = FullPath(stageRoot, "stage root");
        HashSet<string> directories = new HashSet<string>(
            expectedDirectories.Select(delegate(string value) {
                return FullPath(value, "expected launch directory");
            }),
            StringComparer.OrdinalIgnoreCase);
        HashSet<string> files = new HashSet<string>(
            expectedFiles.Select(delegate(string value) {
                return FullPath(value, "expected launch file");
            }),
            StringComparer.OrdinalIgnoreCase);
        if (!directories.Contains(stageRoot))
            throw new InvalidOperationException(
                "launch manifest omitted the stage root");
        foreach (string directory in directories)
        {
            if (!InsidePath(directory, stageRoot)
                || !Directory.Exists(directory)
                || (File.GetAttributes(directory)
                    & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException(
                    "launch directory binding is invalid: " + directory);
        }
        foreach (string file in files)
        {
            if (!InsidePath(file, stageRoot)
                || !File.Exists(file)
                || (File.GetAttributes(file)
                    & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException(
                    "launch file binding is invalid: " + file);
        }
        HashSet<string> actualDirectories = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);
        HashSet<string> actualFiles = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);
        Stack<string> pending = new Stack<string>();
        pending.Push(stageRoot);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            actualDirectories.Add(directory);
            foreach (string child in Directory.GetFileSystemEntries(directory))
            {
                FileAttributes attributes = File.GetAttributes(child);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException(
                        "launch tree contains a reparse point: " + child);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    pending.Push(Path.GetFullPath(child));
                    continue;
                }
                actualFiles.Add(Path.GetFullPath(child));
            }
        }
        if (!actualDirectories.SetEquals(directories)
            || !actualFiles.SetEquals(files))
            throw new InvalidOperationException(
                "launch tree contains substituted or unlisted paths");
    }

    private static string SidString(IntPtr sid)
    {
        IntPtr text = IntPtr.Zero;
        try
        {
            if (!ConvertSidToStringSid(sid, out text))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return Marshal.PtrToStringUni(text);
        }
        finally
        {
            if (text != IntPtr.Zero) LocalFree(text);
        }
    }

    private static IntPtr SidPointer(string sidString)
    {
        SecurityIdentifier sid = new SecurityIdentifier(sidString);
        byte[] bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, pointer, bytes.Length);
        return pointer;
    }

    private static string CreateProfile(string profileName)
    {
        IntPtr sid = IntPtr.Zero;
        int hr = CreateAppContainerProfile(
            profileName,
            "Crucible candidate sandbox",
            "Ephemeral zero-capability Crucible candidate sandbox",
            IntPtr.Zero,
            0,
            out sid);
        if (hr < 0) Marshal.ThrowExceptionForHR(hr);
        try
        {
            string sidString = SidString(sid);
            if (IsLoopbackExempt(sid))
                throw new InvalidOperationException(
                    "new AppContainer unexpectedly has a loopback exemption");
            return sidString;
        }
        finally
        {
            if (sid != IntPtr.Zero) FreeSid(sid);
        }
    }

    private static string ProfileRoot(string sidString)
    {
        IntPtr profilePath = IntPtr.Zero;
        int hr = GetAppContainerFolderPath(sidString, out profilePath);
        if (hr < 0) Marshal.ThrowExceptionForHR(hr);
        try
        {
            string value = Marshal.PtrToStringUni(profilePath);
            if (String.IsNullOrWhiteSpace(value) || !Path.IsPathRooted(value))
                throw new InvalidOperationException(
                    "GetAppContainerFolderPath returned an invalid path");
            return Path.GetFullPath(value);
        }
        finally
        {
            if (profilePath != IntPtr.Zero) CoTaskMemFree(profilePath);
        }
    }

    private static bool IsLoopbackExempt(IntPtr appContainerSid)
    {
        uint count;
        IntPtr values;
        uint error = NetworkIsolationGetAppContainerConfig(out count, out values);
        if (error != 0)
            throw new Win32Exception((int)error);
        try
        {
            int size = Marshal.SizeOf(typeof(SidAndAttributes));
            for (uint index = 0; index < count; index++)
            {
                IntPtr item = new IntPtr(values.ToInt64() + ((long)index * size));
                SidAndAttributes current =
                    (SidAndAttributes)Marshal.PtrToStructure(
                        item,
                        typeof(SidAndAttributes));
                if (EqualSid(appContainerSid, current.Sid)) return true;
            }
            return false;
        }
        finally
        {
            if (values != IntPtr.Zero) LocalFree(values);
        }
    }

    private static bool ProfileNotFound(int hr)
    {
        uint code = unchecked((uint)hr) & 0xffff;
        return code == ErrorFileNotFound
            || code == ErrorPathNotFound
            || code == ErrorNotFound;
    }

    private static string ResolveProfileRoot(
        string profileName,
        string profileRoot)
    {
        if (!String.IsNullOrWhiteSpace(profileRoot))
            return Path.GetFullPath(profileRoot);
        if (String.IsNullOrWhiteSpace(profileName)) return null;
        IntPtr sid = IntPtr.Zero;
        int hr = DeriveAppContainerSidFromAppContainerName(
            profileName,
            out sid);
        if (hr < 0)
        {
            if (ProfileNotFound(hr)) return null;
            Marshal.ThrowExceptionForHR(hr);
        }
        try
        {
            return ProfileRoot(SidString(sid));
        }
        finally
        {
            if (sid != IntPtr.Zero) FreeSid(sid);
        }
    }

    private static void DeleteProfileDirectory(string profileRoot)
    {
        if (String.IsNullOrWhiteSpace(profileRoot)) return;
        Exception last = null;
        for (int attempt = 0; attempt < 50; attempt++)
        {
            if (!Directory.Exists(profileRoot)) return;
            try
            {
                Directory.Delete(profileRoot, true);
                if (!Directory.Exists(profileRoot)) return;
            }
            catch (IOException error) { last = error; }
            catch (UnauthorizedAccessException error) { last = error; }
            Thread.Sleep(100);
        }
        if (Directory.Exists(profileRoot))
            throw new IOException(
                "AppContainer filesystem profile could not be removed: "
                + profileRoot,
                last);
    }

    private static void DeleteProfile(string profileName, string profileRoot)
    {
        Exception first = null;
        string resolvedRoot = profileRoot;
        try { resolvedRoot = ResolveProfileRoot(profileName, profileRoot); }
        catch (Exception error) { first = error; }
        if (!String.IsNullOrWhiteSpace(profileName))
        {
            int hr = DeleteAppContainerProfile(profileName);
            if (hr < 0 && !ProfileNotFound(hr))
            {
                try { Marshal.ThrowExceptionForHR(hr); }
                catch (Exception error) { if (first == null) first = error; }
            }
        }
        try { DeleteProfileDirectory(resolvedRoot); }
        catch (Exception error) { if (first == null) first = error; }
        if (first != null && !ProfileNotFound(first.HResult)) throw first;
    }

    private static FileBasicInfo ReadBasicInfo(string item, bool directory)
    {
        IntPtr handle = CreateFile(
            item,
            FileReadAttributes | FileWriteAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            directory ? FileFlagBackupSemantics : 0,
            IntPtr.Zero);
        if (handle == new IntPtr(-1))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            FileBasicInfo info;
            if (!GetFileInformationByHandleEx(
                handle,
                0,
                out info,
                (uint)Marshal.SizeOf(typeof(FileBasicInfo))))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return info;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static void WriteBasicInfo(
        string item,
        bool directory,
        FileBasicInfo info)
    {
        if (!File.Exists(item) && !Directory.Exists(item)) return;
        IntPtr handle = CreateFile(
            item,
            FileReadAttributes | FileWriteAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            directory ? FileFlagBackupSemantics : 0,
            IntPtr.Zero);
        if (handle == new IntPtr(-1))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (!SetFileInformationByHandle(
                handle,
                0,
                ref info,
                (uint)Marshal.SizeOf(typeof(FileBasicInfo))))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static string GetSddl(string item, bool directory)
    {
        FileSystemSecurity security = directory
            ? (FileSystemSecurity)Directory.GetAccessControl(
                item,
                AccessControlSections.Access)
            : (FileSystemSecurity)File.GetAccessControl(
                item,
                AccessControlSections.Access);
        return security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
    }

    private static void SetSddl(string item, bool directory, string sddl)
    {
        if (!File.Exists(item) && !Directory.Exists(item)) return;
        if (directory)
        {
            DirectorySecurity security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(
                sddl,
                AccessControlSections.Access);
            Directory.SetAccessControl(item, security);
        }
        else
        {
            FileSecurity security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(
                sddl,
                AccessControlSections.Access);
            File.SetAccessControl(item, security);
        }
    }

    private static JournalEntry CaptureEntry(
        string item,
        bool directory,
        bool executeAllowed)
    {
        FileAttributes attributes = File.GetAttributes(item);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException(
                "reparse points are forbidden in sandbox-readable roots: " + item);
        FileBasicInfo info = ReadBasicInfo(item, directory);
        return new JournalEntry
        {
            Path = Path.GetFullPath(item),
            Directory = directory,
            ExecuteAllowed = executeAllowed,
            Sddl = GetSddl(item, directory),
            CreationTime = info.CreationTime,
            LastAccessTime = info.LastAccessTime,
            LastWriteTime = info.LastWriteTime,
            ChangeTime = info.ChangeTime,
            FileAttributes = info.FileAttributes
        };
    }

    private static List<JournalEntry> CaptureTree(
        string root,
        bool executeAllowed)
    {
        root = FullPath(root, "read root");
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException(root);
        List<JournalEntry> entries = new List<JournalEntry>();
        Stack<string> pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            entries.Add(CaptureEntry(
                directory,
                true,
                executeAllowed));
            string[] children = Directory.GetFileSystemEntries(directory);
            Array.Sort(children, StringComparer.OrdinalIgnoreCase);
            for (int index = children.Length - 1; index >= 0; index--)
            {
                string child = children[index];
                FileAttributes attributes = File.GetAttributes(child);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException(
                        "reparse points are forbidden in sandbox-readable roots: "
                        + child);
                if ((attributes & FileAttributes.Directory) != 0)
                    pending.Push(child);
                else
                    entries.Add(CaptureEntry(
                        child,
                        false,
                        executeAllowed));
            }
        }
        return entries;
    }

    private static List<JournalEntry> CaptureLaunchJournal(
        LaunchManifest manifest)
    {
        List<JournalEntry> entries = new List<JournalEntry>();
        foreach (string directory in manifest.Directories)
            entries.Add(CaptureEntry(directory, true, true));
        foreach (LaunchFileSpec file in manifest.Files)
            entries.Add(CaptureEntry(
                file.Path,
                false,
                !String.Equals(
                    file.Role,
                    "candidate",
                    StringComparison.OrdinalIgnoreCase)));
        return MergeJournal(entries);
    }

    private static List<JournalEntry> MergeJournal(
        params IEnumerable<JournalEntry>[] groups)
    {
        Dictionary<string, JournalEntry> byPath =
            new Dictionary<string, JournalEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (IEnumerable<JournalEntry> group in groups)
        {
            foreach (JournalEntry entry in group)
            {
                if (!byPath.ContainsKey(entry.Path))
                    byPath[entry.Path] = entry;
            }
        }
        return byPath.Values
            .OrderBy(delegate(JournalEntry entry) {
                return entry.Path.Count(delegate(char value) { return value == '\\'; });
            })
            .ThenBy(delegate(JournalEntry entry) { return entry.Path; },
                StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static FileBasicInfo BasicInfo(JournalEntry entry)
    {
        return new FileBasicInfo
        {
            CreationTime = entry.CreationTime,
            LastAccessTime = entry.LastAccessTime,
            LastWriteTime = entry.LastWriteTime,
            ChangeTime = entry.ChangeTime,
            FileAttributes = entry.FileAttributes
        };
    }

    private static void GrantReadExecute(
        JournalEntry entry,
        SecurityIdentifier appContainerSid)
    {
        FileSystemRights rights = entry.Directory || entry.ExecuteAllowed
            ? FileSystemRights.ReadAndExecute
                | FileSystemRights.ReadAttributes
                | FileSystemRights.ReadExtendedAttributes
                | FileSystemRights.ReadPermissions
                | FileSystemRights.Synchronize
            : FileSystemRights.Read
                | FileSystemRights.ReadAttributes
                | FileSystemRights.ReadExtendedAttributes
                | FileSystemRights.ReadPermissions
                | FileSystemRights.Synchronize;
        FileSystemAccessRule rule = new FileSystemAccessRule(
            appContainerSid,
            rights,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow);
        SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User;
        FileSystemRights hostRights = entry.Directory || entry.ExecuteAllowed
            ? FileSystemRights.ReadAndExecute
                | FileSystemRights.ReadAttributes
                | FileSystemRights.ReadExtendedAttributes
                | FileSystemRights.WriteAttributes
                | FileSystemRights.WriteExtendedAttributes
                | FileSystemRights.ReadPermissions
                | FileSystemRights.ChangePermissions
                | FileSystemRights.Synchronize
            : FileSystemRights.Read
                | FileSystemRights.ReadAttributes
                | FileSystemRights.ReadExtendedAttributes
                | FileSystemRights.WriteAttributes
                | FileSystemRights.WriteExtendedAttributes
                | FileSystemRights.ReadPermissions
                | FileSystemRights.ChangePermissions
                | FileSystemRights.Synchronize;
        FileSystemAccessRule hostRule = new FileSystemAccessRule(
            currentUser,
            hostRights,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow);
        if (entry.Directory)
        {
            DirectorySecurity security = new DirectorySecurity();
            security.SetOwner(currentUser);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(hostRule);
            security.AddAccessRule(rule);
            Directory.SetAccessControl(entry.Path, security);
        }
        else
        {
            FileSecurity security = new FileSecurity();
            security.SetOwner(currentUser);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(hostRule);
            security.AddAccessRule(rule);
            File.SetAccessControl(entry.Path, security);
        }
    }

    private static void RestoreJournal(IEnumerable<JournalEntry> entries)
    {
        List<JournalEntry> reverse = entries.Reverse().ToList();
        Exception first = null;
        foreach (JournalEntry entry in reverse)
        {
            try
            {
                if (!File.Exists(entry.Path) && !Directory.Exists(entry.Path))
                    continue;
                SetSddl(entry.Path, entry.Directory, entry.Sddl);
            }
            catch (Exception error)
            {
                if (first == null) first = error;
            }
        }
        foreach (JournalEntry entry in reverse)
        {
            try
            {
                if (!File.Exists(entry.Path) && !Directory.Exists(entry.Path))
                    continue;
                FileBasicInfo info = BasicInfo(entry);
                WriteBasicInfo(entry.Path, entry.Directory, info);
            }
            catch (Exception error)
            {
                if (first == null) first = error;
            }
        }
        if (first != null) throw first;
    }

    private static void WriteState(string statePath, SandboxState state)
    {
        string serialized = Serializer().Serialize(state);
        string temporary = statePath + ".new";
        if (File.Exists(temporary)) File.Delete(temporary);
        using (FileStream stream = new FileStream(
            temporary,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None))
        using (StreamWriter writer = new StreamWriter(
            stream,
            new UTF8Encoding(false)))
        {
            writer.Write(serialized);
            writer.Flush();
            stream.Flush(true);
        }
        if (File.Exists(statePath))
            throw new InvalidOperationException("sandbox state already exists");
        File.Move(temporary, statePath);
    }

    private static SandboxState ReadState(
        string statePath,
        string expectedHash = null)
    {
        string json;
        using (FileStream stream = new FileStream(
            statePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read))
        {
            if (!String.IsNullOrWhiteSpace(expectedHash)
                && !String.Equals(
                    Sha256Stream(stream),
                    expectedHash,
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "sandbox state hash did not match");
            stream.Position = 0;
            using (StreamReader reader = new StreamReader(
                stream,
                Encoding.UTF8,
                true,
                4096,
                true))
                json = reader.ReadToEnd();
        }
        SandboxState state =
            Serializer().Deserialize<SandboxState>(json);
        if (state == null
            || state.Version != StateVersion
            || state.Journal == null
            || state.LaunchDirectories == null
            || state.LaunchFiles == null
            || state.LaunchFiles.Count == 0
            || String.IsNullOrWhiteSpace(state.ProfileName)
            || String.IsNullOrWhiteSpace(state.AppContainerSid))
            throw new InvalidOperationException("sandbox state is malformed");
        return state;
    }

    private static void CleanupState(string statePath, bool deleteState)
    {
        if (!File.Exists(statePath)) return;
        SandboxState state = ReadState(statePath);
        Exception first = null;
        try { RestoreJournal(state.Journal); }
        catch (Exception error) { first = error; }
        try { DeleteProfile(state.ProfileName, state.ProfileRoot); }
        catch (Exception error) { if (first == null) first = error; }
        if (deleteState && first == null)
        {
            try { File.Delete(statePath); }
            catch (Exception error) { if (first == null) first = error; }
        }
        if (first != null) throw first;
    }

    private static IntPtr ConfigureJob(
        int activeProcessLimit,
        ulong processMemoryBytes,
        ulong jobMemoryBytes,
        int cpuRatePercent,
        int cpuTimeMs)
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            JobObjectExtendedLimitInformation limits =
                new JobObjectExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags =
                JobObjectLimitKillOnJobClose
                | JobObjectLimitActiveProcess
                | JobObjectLimitProcessMemory
                | JobObjectLimitJobMemory
                | JobObjectLimitJobTime
                | JobObjectLimitDieOnUnhandledException;
            limits.BasicLimitInformation.ActiveProcessLimit =
                (uint)activeProcessLimit;
            limits.BasicLimitInformation.PerJobUserTimeLimit =
                checked((long)cpuTimeMs * 10000L);
            limits.ProcessMemoryLimit = new UIntPtr(processMemoryBytes);
            limits.JobMemoryLimit = new UIntPtr(jobMemoryBytes);
            if (!SetInformationJobObject(
                job,
                JobInfoExtendedLimits,
                ref limits,
                (uint)Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation))))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            JobObjectCpuRateControlInformation cpu =
                new JobObjectCpuRateControlInformation();
            cpu.ControlFlags =
                JobObjectCpuRateControlEnable | JobObjectCpuRateControlHardCap;
            cpu.CpuRate = checked((uint)cpuRatePercent * 100U);
            if (!SetInformationJobObjectCpu(
                job,
                JobInfoCpuRateControl,
                ref cpu,
                (uint)Marshal.SizeOf(typeof(JobObjectCpuRateControlInformation))))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            uint ui = JobObjectUiLimitHandles
                | JobObjectUiLimitReadClipboard
                | JobObjectUiLimitWriteClipboard
                | JobObjectUiLimitSystemParameters
                | JobObjectUiLimitDisplaySettings
                | JobObjectUiLimitGlobalAtoms
                | JobObjectUiLimitDesktop
                | JobObjectUiLimitExitWindows;
            if (!SetInformationJobObjectUi(
                job,
                JobObjectBasicUiRestrictions,
                ref ui,
                sizeof(uint)))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return job;
        }
        catch
        {
            CloseHandle(job);
            throw;
        }
    }

    private static string QuoteArgument(string value)
    {
        if (value.Length > 0
            && value.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0)
            return value;
        StringBuilder output = new StringBuilder();
        output.Append('"');
        int slashes = 0;
        foreach (char character in value)
        {
            if (character == '\\')
            {
                slashes++;
                continue;
            }
            if (character == '"')
            {
                output.Append('\\', slashes * 2 + 1);
                output.Append('"');
                slashes = 0;
                continue;
            }
            output.Append('\\', slashes);
            slashes = 0;
            output.Append(character);
        }
        output.Append('\\', slashes * 2);
        output.Append('"');
        return output.ToString();
    }

    private static StringBuilder CommandLine(
        string executable,
        IEnumerable<string> arguments)
    {
        StringBuilder command = new StringBuilder(QuoteArgument(executable));
        foreach (string argument in arguments)
        {
            if (argument.IndexOf('\0') >= 0)
                throw new InvalidOperationException(
                    "candidate argv contains a NUL");
            command.Append(' ');
            command.Append(QuoteArgument(argument));
        }
        return command;
    }

    private static IntPtr EnvironmentBlock(
        IDictionary<string, string> input)
    {
        SortedDictionary<string, string> environment =
            new SortedDictionary<string, string>(
                input,
                StringComparer.OrdinalIgnoreCase);
        StringBuilder block = new StringBuilder();
        foreach (KeyValuePair<string, string> item in environment)
        {
            if (String.IsNullOrWhiteSpace(item.Key)
                || item.Key.IndexOf('=') >= 0
                || item.Key.IndexOf('\0') >= 0
                || item.Value == null
                || item.Value.IndexOf('\0') >= 0)
                throw new InvalidOperationException(
                    "candidate environment is malformed");
            block.Append(item.Key);
            block.Append('=');
            block.Append(item.Value);
            block.Append('\0');
        }
        block.Append('\0');
        return Marshal.StringToHGlobalUni(block.ToString());
    }

    private static Dictionary<string, string> DecodeEnvironment(
        string base64,
        string outputRoot)
    {
        string json = Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        Dictionary<string, string> parsed =
            Serializer().Deserialize<Dictionary<string, string>>(json);
        Dictionary<string, string> environment =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (parsed != null)
        {
            foreach (KeyValuePair<string, string> item in parsed)
                environment[item.Key] = item.Value;
        }
        string userProfile = Path.Combine(outputRoot, "Profile");
        string containerLocal = Path.Combine(outputRoot, "Local");
        string containerRoaming = Path.Combine(outputRoot, "Roaming");
        string containerTemp = Path.Combine(outputRoot, "Temp");
        string localAppData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        string roamingAppData = containerRoaming;
        string temp = Path.Combine(localAppData, "Temp");
        // CreateProcess remaps host-local standard paths into the AppContainer
        // profile. Direct profile paths for these variables are double-mapped.
        Directory.CreateDirectory(userProfile);
        Directory.CreateDirectory(containerLocal);
        Directory.CreateDirectory(containerRoaming);
        Directory.CreateDirectory(containerTemp);
        environment["TEMP"] = temp;
        environment["TMP"] = temp;
        environment["HOME"] = userProfile;
        environment["USERPROFILE"] = userProfile;
        environment["LOCALAPPDATA"] = localAppData;
        environment["APPDATA"] = roamingAppData;
        string pathRoot = Path.GetPathRoot(outputRoot);
        if (!String.IsNullOrWhiteSpace(pathRoot))
        {
            environment["HOMEDRIVE"] = pathRoot.TrimEnd('\\');
            environment["HOMEPATH"] =
                userProfile.Substring(Math.Max(0, pathRoot.Length - 1));
        }
        environment["CRUCIBLE_SANDBOX_OUTPUT"] = outputRoot;
        const string nodePathFlags =
            "--preserve-symlinks --preserve-symlinks-main";
        string existingNodeOptions;
        environment.TryGetValue("NODE_OPTIONS", out existingNodeOptions);
        if (String.IsNullOrWhiteSpace(existingNodeOptions))
            environment["NODE_OPTIONS"] = nodePathFlags;
        else if (existingNodeOptions.IndexOf(
                nodePathFlags,
                StringComparison.Ordinal) < 0)
            environment["NODE_OPTIONS"] =
                existingNodeOptions + " " + nodePathFlags;
        return environment;
    }

    private static ProcessInformation CreateLowboxProcess(
        string appContainerSid,
        string executable,
        IList<string> arguments,
        string currentDirectory,
        IDictionary<string, string> environment)
    {
        IntPtr sid = IntPtr.Zero;
        IntPtr security = IntPtr.Zero;
        IntPtr attributes = IntPtr.Zero;
        IntPtr handles = IntPtr.Zero;
        IntPtr environmentBlock = IntPtr.Zero;
        IntPtr nullInput = IntPtr.Zero;
        bool attributesInitialized = false;
        try
        {
            sid = SidPointer(appContainerSid);
            SecurityCapabilities capabilities = new SecurityCapabilities();
            capabilities.AppContainerSid = sid;
            capabilities.Capabilities = IntPtr.Zero;
            capabilities.CapabilityCount = 0;
            capabilities.Reserved = 0;
            security = Marshal.AllocHGlobal(
                Marshal.SizeOf(typeof(SecurityCapabilities)));
            Marshal.StructureToPtr(capabilities, security, false);

            nullInput = CreateFile(
                "NUL",
                GenericRead,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                0,
                IntPtr.Zero);
            if (nullInput == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr stdout = GetStdHandle(StdOutputHandle);
            IntPtr stderr = GetStdHandle(StdErrorHandle);
            if (stdout == IntPtr.Zero || stdout == new IntPtr(-1)
                || stderr == IntPtr.Zero || stderr == new IntPtr(-1))
                throw new InvalidOperationException(
                    "native helper stdout/stderr handles are unavailable");
            foreach (IntPtr handle in new IntPtr[] { nullInput, stdout, stderr })
            {
                if (!SetHandleInformation(
                    handle,
                    HandleFlagInherit,
                    HandleFlagInherit))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            IntPtr attributeBytes = IntPtr.Zero;
            InitializeProcThreadAttributeList(
                IntPtr.Zero,
                2,
                0,
                ref attributeBytes);
            attributes = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(
                attributes,
                2,
                0,
                ref attributeBytes))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            attributesInitialized = true;
            if (!UpdateProcThreadAttribute(
                attributes,
                0,
                new IntPtr(ProcThreadAttributeSecurityCapabilities),
                security,
                new IntPtr(Marshal.SizeOf(typeof(SecurityCapabilities))),
                IntPtr.Zero,
                IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            IntPtr[] inherited = new IntPtr[] { nullInput, stdout, stderr };
            handles = Marshal.AllocHGlobal(IntPtr.Size * inherited.Length);
            Marshal.Copy(inherited, 0, handles, inherited.Length);
            if (!UpdateProcThreadAttribute(
                attributes,
                0,
                new IntPtr(ProcThreadAttributeHandleList),
                handles,
                new IntPtr(IntPtr.Size * inherited.Length),
                IntPtr.Zero,
                IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            environmentBlock = EnvironmentBlock(environment);
            StartupInfoEx startup = new StartupInfoEx();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(StartupInfoEx));
            startup.StartupInfo.dwFlags = (int)StartfUseStdHandles;
            startup.StartupInfo.hStdInput = nullInput;
            startup.StartupInfo.hStdOutput = stdout;
            startup.StartupInfo.hStdError = stderr;
            startup.AttributeList = attributes;
            ProcessInformation process;
            if (!CreateProcess(
                executable,
                CommandLine(executable, arguments),
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                ExtendedStartupInfoPresent
                    | CreateUnicodeEnvironment
                    | CreateSuspended
                    | CreateNoWindow,
                environmentBlock,
                currentDirectory,
                ref startup,
                out process))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return process;
        }
        finally
        {
            if (environmentBlock != IntPtr.Zero)
                Marshal.FreeHGlobal(environmentBlock);
            if (attributesInitialized)
                DeleteProcThreadAttributeList(attributes);
            if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (security != IntPtr.Zero) Marshal.FreeHGlobal(security);
            if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
            if (nullInput != IntPtr.Zero && nullInput != new IntPtr(-1))
                CloseHandle(nullInput);
        }
    }

    private static uint RunContained(
        SandboxState state,
        uint parentPid,
        string executable,
        IList<string> arguments,
        string currentDirectory,
        IDictionary<string, string> environment,
        int activeProcessLimit,
        ulong processMemoryBytes,
        ulong jobMemoryBytes,
        int cpuRatePercent,
        int cpuTimeMs,
        int wallTimeMs,
        bool monitorControlInput,
        bool failAssignProcessToJobObject)
    {
        executable = FullPath(executable, "executable");
        currentDirectory = FullPath(currentDirectory, "current directory");
        if (!InsidePath(executable, state.StageRoot)
            || !InsidePath(currentDirectory, state.StageRoot))
            throw new InvalidOperationException(
                "candidate launch escaped the staged root");
        if (!SamePath(executable, state.LaunchFiles
            .Single(delegate(LaunchFileRecord file) {
                return String.Equals(
                    file.Role,
                    "executable",
                    StringComparison.OrdinalIgnoreCase);
            }).Path))
            throw new InvalidOperationException(
                "candidate executable did not match the launch manifest");
        VerifyExactLaunchTree(
            state.StageRoot,
            state.LaunchDirectories,
            state.LaunchFiles.Select(
                delegate(LaunchFileRecord file) { return file.Path; }));
        IntPtr parent = OpenProcess(
            Synchronize | ProcessQueryLimitedInformation,
            false,
            parentPid);
        if (parent == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr stopEvent = CreateEvent(
            IntPtr.Zero,
            true,
            false,
            null);
        if (stopEvent == IntPtr.Zero)
        {
            CloseHandle(parent);
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        List<PinnedLaunchFile> pinned;
        try
        {
            pinned = OpenPinnedLaunchFiles(state.LaunchFiles);
        }
        catch
        {
            CloseHandle(stopEvent);
            CloseHandle(parent);
            throw;
        }
        IntPtr job = IntPtr.Zero;
        ProcessInformation process = new ProcessInformation();
        bool assignedToJob = false;
        try
        {
            job = ConfigureJob(
                activeProcessLimit,
                processMemoryBytes,
                jobMemoryBytes,
                cpuRatePercent,
                cpuTimeMs);
            VerifyExactLaunchTree(
                state.StageRoot,
                state.LaunchDirectories,
                state.LaunchFiles.Select(
                    delegate(LaunchFileRecord file) { return file.Path; }));
            VerifyPinnedLaunchFiles(pinned);
            process = CreateLowboxProcess(
                state.AppContainerSid,
                executable,
                arguments,
                currentDirectory,
                environment);
            if (failAssignProcessToJobObject)
            {
                Console.Error.WriteLine(
                    "CRUCIBLE_TEST_ASSIGN_FAILURE_PID " + process.ProcessId);
                throw new InvalidOperationException(
                    "injected AssignProcessToJobObject failure");
            }
            if (!AssignProcessToJobObject(job, process.Process))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            assignedToJob = true;
            if (ResumeThread(process.Thread) == UInt32.MaxValue)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (monitorControlInput)
            {
                Thread control = new Thread(delegate()
                {
                    try { Console.OpenStandardInput().ReadByte(); }
                    catch { }
                    SetEvent(stopEvent);
                });
                control.IsBackground = true;
                control.Start();
            }

            IntPtr[] waits = monitorControlInput
                ? new IntPtr[] { process.Process, parent, stopEvent }
                : new IntPtr[] { process.Process, parent };
            uint wait = WaitForMultipleObjects(
                (uint)waits.Length,
                waits,
                false,
                (uint)wallTimeMs);
            if (wait == WaitTimeout)
            {
                TerminateJobObject(job, 0x43524354);
                WaitForSingleObject(process.Process, 5000);
                return 124;
            }
            if (wait == WaitObject0 + 1
                || (monitorControlInput && wait == WaitObject0 + 2))
            {
                TerminateJobObject(job, 0x4352434b);
                WaitForSingleObject(process.Process, 5000);
                return 125;
            }
            if (wait != WaitObject0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            uint exitCode;
            if (!GetExitCodeProcess(process.Process, out exitCode))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return exitCode;
        }
        catch
        {
            if (process.Process != IntPtr.Zero)
            {
                if (assignedToJob && job != IntPtr.Zero)
                    TerminateJobObject(job, 0x43524346);
                else
                    TerminateProcess(process.Process, 0x43524346);
                WaitForSingleObject(process.Process, 5000);
            }
            throw;
        }
        finally
        {
            if (job != IntPtr.Zero) CloseHandle(job);
            if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
            if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
            CloseHandle(stopEvent);
            CloseHandle(parent);
            foreach (PinnedLaunchFile item in pinned) item.Dispose();
        }
    }

    private static int Prepare(string[] args)
    {
        if (args.Length != 8)
            throw new InvalidOperationException(
                "prepare requires state, profile, stage, candidate, source hash, and launch manifest");
        string statePath = FullPath(args[1], "state path");
        string profileName = args[2];
        string stageRoot = FullPath(args[3], "stage root");
        string candidateRoot = FullPath(args[4], "candidate root");
        string sourceHash = args[5];
        LaunchManifest manifest = ReadLaunchManifest(args[6], args[7]);
        if (!SamePath(stageRoot, manifest.StageRoot)
            || !SamePath(candidateRoot, manifest.CandidateRoot)
            || !InsidePath(candidateRoot, stageRoot)
            || manifest.Files.Count(delegate(LaunchFileSpec file) {
                return String.Equals(
                    file.Role,
                    "executable",
                    StringComparison.OrdinalIgnoreCase);
            }) != 1
            || !SamePath(
                manifest.Executable,
                manifest.Files.Single(delegate(LaunchFileSpec file) {
                    return String.Equals(
                        file.Role,
                        "executable",
                        StringComparison.OrdinalIgnoreCase);
                }).Path))
            throw new InvalidOperationException(
                "launch manifest binding did not match preparation arguments");
        VerifyExactLaunchTree(
            stageRoot,
            manifest.Directories,
            manifest.Files.Select(
                delegate(LaunchFileSpec file) { return file.Path; }));
        List<LaunchFileRecord> launchFiles = manifest.Files
            .Select(CaptureLaunchFile)
            .ToList();
        if (File.Exists(statePath))
            throw new InvalidOperationException("sandbox state already exists");
        Directory.CreateDirectory(Path.GetDirectoryName(statePath));
        string sidString = null;
        string profileRoot = null;
        SandboxState state = null;
        try
        {
            sidString = CreateProfile(profileName);
            profileRoot = ProfileRoot(sidString);
            string outputRoot = profileRoot;
            Directory.CreateDirectory(Path.Combine(outputRoot, "Temp"));

            List<JournalEntry> journal = CaptureLaunchJournal(manifest);
            state = new SandboxState
            {
                Version = StateVersion,
                SourceHash = sourceHash,
                ProfileName = profileName,
                AppContainerSid = sidString,
                ProfileRoot = profileRoot,
                OutputRoot = outputRoot,
                StageRoot = stageRoot,
                CandidateRoot = candidateRoot,
                Journal = journal,
                LaunchDirectories = manifest.Directories,
                LaunchFiles = launchFiles
            };
            WriteState(statePath, state);
            SecurityIdentifier sid = new SecurityIdentifier(sidString);
            foreach (JournalEntry entry in journal.AsEnumerable().Reverse())
                GrantReadExecute(entry, sid);
            WriteJson(new
            {
                prepared = true,
                appContainerSid = sidString,
                outputRoot = outputRoot,
                zeroCapabilities = true,
                loopbackExempt = false
            });
            return 0;
        }
        catch
        {
            if (File.Exists(statePath))
            {
                try { CleanupState(statePath, true); }
                catch { }
            }
            else if (sidString != null)
            {
                try { DeleteProfile(profileName, profileRoot); }
                catch { }
            }
            throw;
        }
    }

    private static int Cleanup(string[] args)
    {
        if (args.Length != 5)
            throw new InvalidOperationException(
                "cleanup requires state path, state hash, profile, and profile root");
        string statePath = FullPath(args[1], "state path");
        string profileName = args[3];
        string profileRoot = String.IsNullOrWhiteSpace(args[4])
            ? null
            : FullPath(args[4], "profile root");
        bool stateMissing = !File.Exists(statePath);
        if (stateMissing)
        {
            DeleteProfile(profileName, profileRoot);
        }
        else
        {
            SandboxState state = ReadState(statePath, args[2]);
            if (!String.Equals(
                state.ProfileName,
                profileName,
                StringComparison.Ordinal)
                || (profileRoot != null
                    && !SamePath(state.ProfileRoot, profileRoot)))
                throw new InvalidOperationException(
                    "cleanup profile binding did not match sandbox state");
            profileRoot = state.ProfileRoot;
            CleanupState(statePath, true);
        }
        if (!String.IsNullOrWhiteSpace(profileRoot)
            && Directory.Exists(profileRoot))
            throw new IOException(
                "AppContainer filesystem profile remains after cleanup: "
                + profileRoot);
        WriteJson(new { cleaned = true, stateMissing = stateMissing });
        return 0;
    }

    private static int Launch(string[] args)
    {
        if (args.Length < 15 || args[14] != "--")
            throw new InvalidOperationException("launch arguments are malformed");
        string statePath = FullPath(args[1], "state path");
        SandboxState state = ReadState(statePath, args[2]);
        uint parentPid = UInt32.Parse(args[3]);
        string executable = FullPath(args[4], "executable");
        string currentDirectory = FullPath(args[5], "current directory");
        Dictionary<string, string> environment =
            DecodeEnvironment(args[6], state.OutputRoot);
        int activeProcessLimit = Int32.Parse(args[7]);
        ulong processMemoryBytes = UInt64.Parse(args[8]);
        ulong jobMemoryBytes = UInt64.Parse(args[9]);
        int cpuRatePercent = Int32.Parse(args[10]);
        int cpuTimeMs = Int32.Parse(args[11]);
        int wallTimeMs = Int32.Parse(args[12]);
        bool failAssignProcessToJobObject = args[13] == "1";
        List<string> candidateArgs = args.Skip(15).ToList();
        uint exitCode = RunContained(
            state,
            parentPid,
            executable,
            candidateArgs,
            currentDirectory,
            environment,
            activeProcessLimit,
            processMemoryBytes,
            jobMemoryBytes,
            cpuRatePercent,
            cpuTimeMs,
            wallTimeMs,
            true,
            failAssignProcessToJobObject);
        return unchecked((int)exitCode);
    }

    private static bool TokenBoolean(int informationClass)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            IntPtr buffer = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                int returned;
                if (!GetTokenInformation(
                    token,
                    informationClass,
                    buffer,
                    sizeof(int),
                    out returned))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return Marshal.ReadInt32(buffer) != 0;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(token); }
    }

    private static bool IsLowIntegrity()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            int required;
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                IntPtr.Zero,
                0,
                out required);
            IntPtr buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(
                    token,
                    TokenIntegrityLevel,
                    buffer,
                    required,
                    out required))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                TokenMandatoryLabel label =
                    (TokenMandatoryLabel)Marshal.PtrToStructure(
                        buffer,
                        typeof(TokenMandatoryLabel));
                byte count = Marshal.ReadByte(
                    GetSidSubAuthorityCount(label.Label.Sid));
                int rid = Marshal.ReadInt32(
                    GetSidSubAuthority(label.Label.Sid, (uint)(count - 1)));
                return rid <= SecurityMandatoryLowRid;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(token); }
    }

    private static bool HasZeroCapabilities()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            int required;
            GetTokenInformation(
                token,
                TokenCapabilities,
                IntPtr.Zero,
                0,
                out required);
            IntPtr buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(
                    token,
                    TokenCapabilities,
                    buffer,
                    required,
                    out required))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return Marshal.ReadInt32(buffer) == 0;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(token); }
    }

    private static int ProbeChild(string[] args)
    {
        if (args.Length != 5)
            throw new InvalidOperationException(
                "probe-child requires secret, output, port, and registry key");
        string secret = FullPath(args[1], "probe secret");
        string output = FullPath(args[2], "probe output");
        int port = Int32.Parse(args[3]);
        string registryKey = args[4];
        ChildProbeResult result = new ChildProbeResult();
        result.AppContainer = TokenBoolean(TokenIsAppContainer);
        result.LowIntegrity = IsLowIntegrity();
        result.ZeroCapabilities = HasZeroCapabilities();
        try
        {
            File.ReadAllText(secret);
            result.SecretDenied = false;
        }
        catch (UnauthorizedAccessException) { result.SecretDenied = true; }
        catch (IOException) { result.SecretDenied = true; }
        try
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(registryKey))
            {
                object value = key == null ? null : key.GetValue("Secret");
                result.RegistryDenied =
                    !String.Equals(
                        value as string,
                        "host-registry-secret",
                        StringComparison.Ordinal);
            }
        }
        catch (UnauthorizedAccessException) { result.RegistryDenied = true; }
        catch (System.Security.SecurityException) {
            result.RegistryDenied = true;
        }
        try
        {
            File.WriteAllText(output, "appcontainer-output");
            result.OutputWriteAllowed = File.ReadAllText(output)
                == "appcontainer-output";
        }
        catch { result.OutputWriteAllowed = false; }
        try
        {
            using (TcpClient client = new TcpClient())
            {
                IAsyncResult connect = client.BeginConnect(
                    IPAddress.Loopback,
                    port,
                    null,
                    null);
                bool completed = connect.AsyncWaitHandle.WaitOne(1000);
                if (completed)
                {
                    client.EndConnect(connect);
                    result.NetworkDenied = !client.Connected;
                }
                else result.NetworkDenied = true;
            }
        }
        catch (SocketException) { result.NetworkDenied = true; }
        catch (UnauthorizedAccessException) { result.NetworkDenied = true; }
        File.WriteAllText(
            Path.Combine(Path.GetDirectoryName(output), "probe-result.json"),
            Serializer().Serialize(result));
        return result.AppContainer
            && result.LowIntegrity
            && result.ZeroCapabilities
            && result.NetworkDenied
            && result.SecretDenied
            && result.RegistryDenied
            && result.OutputWriteAllowed
            ? 0
            : 1;
    }

    private static int Probe(string[] args)
    {
        if (args.Length != 9)
            throw new InvalidOperationException("probe arguments are malformed");
        string controlRoot = FullPath(args[1], "control root");
        uint parentPid = UInt32.Parse(args[2]);
        int activeProcessLimit = Int32.Parse(args[3]);
        ulong processMemoryBytes = UInt64.Parse(args[4]);
        ulong jobMemoryBytes = UInt64.Parse(args[5]);
        int cpuRatePercent = Int32.Parse(args[6]);
        int cpuTimeMs = Int32.Parse(args[7]);
        int wallTimeMs = Int32.Parse(args[8]);
        string root = Path.Combine(
            controlRoot,
            "probe-" + Guid.NewGuid().ToString("N"));
        string allowed = Path.Combine(root, "allowed");
        string secret = Path.Combine(root, "secret.txt");
        string childExe = Path.Combine(allowed, "probe-child.exe");
        string statePath = Path.Combine(root, "probe-state.json");
        Directory.CreateDirectory(allowed);
        File.WriteAllText(secret, "host-secret");
        File.Copy(
            typeof(CrucibleWindowsSandbox).Assembly.Location,
            childExe,
            false);
        TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string profileName =
            "Crucible.Probe." + Guid.NewGuid().ToString("N");
        string registrySubKey =
            "Software\\CrucibleSandboxProbe\\" + Guid.NewGuid().ToString("N");
        string profileRoot = null;
        bool profileCreated = false;
        try
        {
            using (RegistryKey key =
                Registry.CurrentUser.CreateSubKey(registrySubKey))
                key.SetValue("Secret", "host-registry-secret");
            string sid = CreateProfile(profileName);
            profileCreated = true;
            profileRoot = ProfileRoot(sid);
            string outputRoot = profileRoot;
            Directory.CreateDirectory(outputRoot);
            Directory.CreateDirectory(Path.Combine(outputRoot, "Temp"));
            string output = Path.Combine(outputRoot, "probe-output.txt");
            List<JournalEntry> journal = MergeJournal(
                CaptureTree(allowed, true));
            List<LaunchFileRecord> launchFiles = new List<LaunchFileRecord> {
                CaptureLaunchFile(new LaunchFileSpec {
                    Path = childExe,
                    Role = "executable",
                    Sha256 = Sha256File(childExe)
                })
            };
            SandboxState state = new SandboxState
            {
                Version = StateVersion,
                SourceHash = "probe",
                ProfileName = profileName,
                AppContainerSid = sid,
                ProfileRoot = profileRoot,
                OutputRoot = outputRoot,
                StageRoot = allowed,
                CandidateRoot = allowed,
                Journal = journal,
                LaunchDirectories = new List<string> { allowed },
                LaunchFiles = launchFiles
            };
            WriteState(statePath, state);
            SecurityIdentifier securityIdentifier =
                new SecurityIdentifier(sid);
            foreach (JournalEntry entry in journal.AsEnumerable().Reverse())
                GrantReadExecute(entry, securityIdentifier);
            Dictionary<string, string> environment =
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            if (!String.IsNullOrWhiteSpace(systemRoot))
                environment["SystemRoot"] = systemRoot;
            uint exit = RunContained(
                state,
                parentPid,
                childExe,
                new List<string> {
                    "probe-child",
                    secret,
                    output,
                    port.ToString(),
                    registrySubKey
                },
                allowed,
                DecodeEnvironment(
                    Convert.ToBase64String(
                        Encoding.UTF8.GetBytes(
                            Serializer().Serialize(environment))),
                    outputRoot),
                activeProcessLimit,
                processMemoryBytes,
                jobMemoryBytes,
                cpuRatePercent,
                cpuTimeMs,
                wallTimeMs,
                false,
                false);
            string resultPath = Path.Combine(outputRoot, "probe-result.json");
            if (exit != 0 || !File.Exists(resultPath))
                throw new InvalidOperationException(
                    "AppContainer child probe failed with exit " + exit);
            ChildProbeResult child = Serializer()
                .Deserialize<ChildProbeResult>(
                    File.ReadAllText(resultPath, Encoding.UTF8));
            ProbeResult result = new ProbeResult
            {
                available = true,
                appContainer = child.AppContainer,
                lowIntegrity = child.LowIntegrity,
                zeroCapabilities = child.ZeroCapabilities,
                networkDenied = child.NetworkDenied,
                secretDenied = child.SecretDenied,
                registryDenied = child.RegistryDenied,
                outputWriteAllowed = child.OutputWriteAllowed,
                jobObjectConfigured = true
            };
            CleanupState(statePath, true);
            WriteJson(result);
            return 0;
        }
        finally
        {
            listener.Stop();
            if (File.Exists(statePath))
            {
                try { CleanupState(statePath, true); }
                catch { }
            }
            else if (profileCreated)
            {
                try { DeleteProfile(profileName, profileRoot); }
                catch { }
            }
            try { Directory.Delete(root, true); }
            catch { }
            try { Registry.CurrentUser.DeleteSubKeyTree(registrySubKey, false); }
            catch { }
            try {
                Registry.CurrentUser.DeleteSubKey(
                    "Software\\CrucibleSandboxProbe",
                    false);
            }
            catch { }
        }
    }

    public static int Main(string[] args)
    {
        ConfigureNoUi();
        try
        {
            if (args.Length == 0)
                throw new InvalidOperationException("operation is required");
            switch (args[0])
            {
                case "prepare": return Prepare(args);
                case "launch": return Launch(args);
                case "cleanup": return Cleanup(args);
                case "probe": return Probe(args);
                case "probe-child": return ProbeChild(args);
                default:
                    throw new InvalidOperationException(
                        "unknown operation: " + args[0]);
            }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(
                "CRUCIBLE_WINDOWS_SANDBOX_ERROR "
                + error.GetType().FullName
                + ": "
                + error.Message);
            Console.Error.WriteLine(error.StackTrace);
            return 111;
        }
    }
}
`;
