import {
    spawn as childSpawn,
    spawnSync,
} from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
} from "./errors.mjs";

const JOB_HELPER_VERSION = 1;
const JOB_HELPER_SOURCE_NAME = "CrucibleWindowsJobOwner.cs";
const JOB_HELPER_EXE_NAME = "CrucibleWindowsJobOwner.exe";
const JOB_HELPER_MANIFEST_NAME = "helper-manifest.json";
const JOB_HELPER_SOURCE_SHA256 =
    "2668acc245c8fd745a2f07f74c846865c457623212206a658b5f8fb1e486ec91";
const JOB_HELPER_SOURCE = String.raw`
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class CrucibleWindowsJobOwner
{
    private const int RequestVersion = 1;
    private const int ProcThreadAttributeHandleList = 0x00020002;
    private const int JobInfoExtendedLimits = 9;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 0x00000102;
    private const uint Synchronize = 0x00100000;
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint JobObjectLimitDieOnUnhandledException = 0x00000400;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x1;
    private const uint FileShareWrite = 0x2;
    private const uint OpenExisting = 3;
    private const uint HandleFlagInherit = 0x1;
    private const int StdOutputHandle = -11;
    private const int StdErrorHandle = -12;
    private const uint SemFailCriticalErrors = 0x0001;
    private const uint SemNoGpFaultErrorBox = 0x0002;
    private const uint SemNoOpenFileErrorBox = 0x8000;
    private const uint WerFaultReportingNoUi = 0x0004;

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

    private sealed class LaunchRequest
    {
        public int Version { get; set; }
        public int ParentPid { get; set; }
        public string Executable { get; set; }
        public string[] Argv { get; set; }
        public string Cwd { get; set; }
        public Dictionary<string, string> Env { get; set; }
        public int TimeoutMs { get; set; }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateJobObject(
        IntPtr attributes,
        string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(
        IntPtr job,
        IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(
        IntPtr job,
        uint exitCode);

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

    [DllImport(
        "kernel32.dll",
        SetLastError = true,
        CharSet = CharSet.Unicode,
        EntryPoint = "CreateProcessW")]
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(
        IntPtr process,
        uint exitCode);

    [DllImport("kernel32.dll")]
    private static extern uint SetErrorMode(uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadErrorMode(
        uint mode,
        out uint oldMode);

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
    private static extern IntPtr GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(
        IntPtr handle,
        uint mask,
        uint flags);

    private static JavaScriptSerializer Serializer()
    {
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        serializer.MaxJsonLength = 4 * 1024 * 1024;
        serializer.RecursionLimit = 64;
        return serializer;
    }

    private static void ConfigureNoUi()
    {
        uint mode =
            SemFailCriticalErrors
            | SemNoGpFaultErrorBox
            | SemNoOpenFileErrorBox;
        SetErrorMode(mode);
        uint ignored;
        SetThreadErrorMode(mode, out ignored);
        try { WerSetFlags(WerFaultReportingNoUi); }
        catch { }
    }

    private static string FullPath(string value, string label)
    {
        if (String.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException(label + " is required");
        string full = Path.GetFullPath(value);
        if (!Path.IsPathRooted(full))
            throw new InvalidOperationException(label + " must be absolute");
        return full;
    }

    private static string Sha256(byte[] bytes)
    {
        using (SHA256 hash = SHA256.Create())
            return String.Concat(
                hash.ComputeHash(bytes)
                    .Select(delegate(byte value) {
                        return value.ToString("x2");
                    }));
    }

    private static LaunchRequest ReadRequest(
        string requestPath,
        string expectedHash)
    {
        requestPath = FullPath(requestPath, "request path");
        byte[] bytes = File.ReadAllBytes(requestPath);
        if (!String.Equals(
            Sha256(bytes),
            expectedHash,
            StringComparison.Ordinal))
            throw new InvalidOperationException(
                "launch request hash did not match");
        LaunchRequest request = Serializer()
            .Deserialize<LaunchRequest>(Encoding.UTF8.GetString(bytes));
        if (request == null
            || request.Version != RequestVersion
            || request.ParentPid < 1
            || request.TimeoutMs < 1
            || request.Argv == null
            || request.Env == null)
            throw new InvalidOperationException(
                "launch request is malformed");
        request.Executable = FullPath(
            request.Executable,
            "request executable");
        request.Cwd = FullPath(request.Cwd, "request cwd");
        return request;
    }

    private static string QuoteArgument(string value)
    {
        if (value == null)
            throw new InvalidOperationException("argv cannot contain null");
        if (value.IndexOf('\0') >= 0)
            throw new InvalidOperationException("argv contains a NUL");
        if (value.Length > 0
            && value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            return value;
        StringBuilder output = new StringBuilder();
        output.Append('"');
        int slashes = 0;
        foreach (char character in value)
        {
            if (character == '\\')
            {
                slashes += 1;
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
                StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, string> item in input)
            environment[item.Key] = item.Value;
        StringBuilder block = new StringBuilder();
        foreach (KeyValuePair<string, string> item in environment)
        {
            if (String.IsNullOrWhiteSpace(item.Key)
                || item.Key.IndexOf('=') >= 0
                || item.Key.IndexOf('\0') >= 0
                || item.Value == null
                || item.Value.IndexOf('\0') >= 0)
                throw new InvalidOperationException(
                    "environment is malformed");
            block.Append(item.Key);
            block.Append('=');
            block.Append(item.Value);
            block.Append('\0');
        }
        block.Append('\0');
        return Marshal.StringToHGlobalUni(block.ToString());
    }

    private static IntPtr ConfigureJob()
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
                | JobObjectLimitDieOnUnhandledException;
            if (!SetInformationJobObject(
                job,
                JobInfoExtendedLimits,
                ref limits,
                (uint)Marshal.SizeOf(
                    typeof(JobObjectExtendedLimitInformation))))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return job;
        }
        catch
        {
            CloseHandle(job);
            throw;
        }
    }

    private static ProcessInformation CreateSuspendedProcess(
        LaunchRequest request)
    {
        IntPtr attributes = IntPtr.Zero;
        IntPtr handles = IntPtr.Zero;
        IntPtr environmentBlock = IntPtr.Zero;
        IntPtr nullInput = IntPtr.Zero;
        bool attributesInitialized = false;
        try
        {
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
                    "owner stdout/stderr handles are unavailable");
            foreach (IntPtr handle in new IntPtr[] {
                nullInput,
                stdout,
                stderr
            })
            {
                if (!SetHandleInformation(
                    handle,
                    HandleFlagInherit,
                    HandleFlagInherit))
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error());
            }

            IntPtr attributeBytes = IntPtr.Zero;
            InitializeProcThreadAttributeList(
                IntPtr.Zero,
                1,
                0,
                ref attributeBytes);
            attributes = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(
                attributes,
                1,
                0,
                ref attributeBytes))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            attributesInitialized = true;
            IntPtr[] inherited = new IntPtr[] {
                nullInput,
                stdout,
                stderr
            };
            handles = Marshal.AllocHGlobal(
                IntPtr.Size * inherited.Length);
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

            environmentBlock = EnvironmentBlock(request.Env);
            StartupInfoEx startup = new StartupInfoEx();
            startup.StartupInfo.cb =
                Marshal.SizeOf(typeof(StartupInfoEx));
            startup.StartupInfo.dwFlags = (int)StartfUseStdHandles;
            startup.StartupInfo.hStdInput = nullInput;
            startup.StartupInfo.hStdOutput = stdout;
            startup.StartupInfo.hStdError = stderr;
            startup.AttributeList = attributes;
            ProcessInformation process;
            if (!CreateProcess(
                request.Executable,
                CommandLine(request.Executable, request.Argv),
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                ExtendedStartupInfoPresent
                    | CreateUnicodeEnvironment
                    | CreateSuspended
                    | CreateNoWindow,
                environmentBlock,
                request.Cwd,
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
            if (handles != IntPtr.Zero)
                Marshal.FreeHGlobal(handles);
            if (attributes != IntPtr.Zero)
                Marshal.FreeHGlobal(attributes);
            if (nullInput != IntPtr.Zero
                && nullInput != new IntPtr(-1))
                CloseHandle(nullInput);
        }
    }

    private static int Run(LaunchRequest request)
    {
        IntPtr parent = OpenProcess(
            Synchronize | ProcessQueryLimitedInformation,
            false,
            (uint)request.ParentPid);
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
        IntPtr job = IntPtr.Zero;
        ProcessInformation process = new ProcessInformation();
        bool assigned = false;
        try
        {
            job = ConfigureJob();
            process = CreateSuspendedProcess(request);
            if (!AssignProcessToJobObject(job, process.Process))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            assigned = true;
            if (ResumeThread(process.Thread) == UInt32.MaxValue)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            Thread control = new Thread(delegate()
            {
                try { Console.OpenStandardInput().ReadByte(); }
                catch { }
                SetEvent(stopEvent);
            });
            control.IsBackground = true;
            control.Start();

            IntPtr[] waits = new IntPtr[] {
                process.Process,
                parent,
                stopEvent
            };
            uint wait = WaitForMultipleObjects(
                (uint)waits.Length,
                waits,
                false,
                (uint)request.TimeoutMs);
            if (wait == WaitTimeout)
            {
                TerminateJobObject(job, 0x43524354);
                WaitForSingleObject(process.Process, 5000);
                return 124;
            }
            if (wait == WaitObject0 + 1 || wait == WaitObject0 + 2)
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
            if (!TerminateJobObject(job, 0x43524344))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return unchecked((int)exitCode);
        }
        catch
        {
            if (process.Process != IntPtr.Zero)
            {
                if (assigned && job != IntPtr.Zero)
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
            if (process.Thread != IntPtr.Zero)
                CloseHandle(process.Thread);
            if (process.Process != IntPtr.Zero)
                CloseHandle(process.Process);
            CloseHandle(stopEvent);
            CloseHandle(parent);
        }
    }

    public static int Main(string[] args)
    {
        ConfigureNoUi();
        try
        {
            if (args.Length != 2)
                throw new InvalidOperationException(
                    "request path and hash are required");
            return Run(ReadRequest(args[0], args[1]));
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(
                "CRUCIBLE_WINDOWS_JOB_OWNER_ERROR "
                + error.GetType().FullName
                + ": "
                + error.Message);
            Console.Error.WriteLine(error.StackTrace);
            return 111;
        }
    }
}
`.trim();

function sha256Bytes(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

function hashFile(file) {
    return sha256Bytes(fs.readFileSync(file));
}

function defaultControlRoot() {
    const local = process.env.LOCALAPPDATA;
    if (typeof local === "string" && path.isAbsolute(local)) {
        return path.join(local, "Crucible", "WindowsJobOwner");
    }
    return path.join(
        os.homedir(),
        "AppData",
        "Local",
        "Crucible",
        "WindowsJobOwner",
    );
}

function normalizeDirectory(directory, field) {
    if (typeof directory !== "string" || !path.isAbsolute(directory)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${field} must be an absolute path`,
            { [field]: directory ?? null },
        );
    }
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
            `${field} must be a regular local directory`,
            { [field]: directory },
        );
    }
    const resolved = path.resolve(directory);
    const real = fs.realpathSync.native(directory);
    if (resolved.toLowerCase() !== real.toLowerCase()) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
            `${field} cannot resolve through a reparse point`,
            { [field]: directory, real },
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
            // Continue to the next inbox compiler.
        }
    }
    throw new MeasurementError(
        MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
        "The inbox .NET Framework compiler required for Windows Job Object ownership is unavailable",
        { candidates },
    );
}

function validatePinnedSource() {
    const actual = sha256Bytes(Buffer.from(JOB_HELPER_SOURCE, "utf8"));
    if (actual !== JOB_HELPER_SOURCE_SHA256) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
            "Windows Job Object helper source hash does not match its pinned digest",
            { expected: JOB_HELPER_SOURCE_SHA256, actual },
        );
    }
    return actual;
}

function readValidHelper(finalRoot, sourceHash, compilerHash) {
    const sourcePath = path.join(finalRoot, JOB_HELPER_SOURCE_NAME);
    const helperPath = path.join(finalRoot, JOB_HELPER_EXE_NAME);
    const manifestPath = path.join(finalRoot, JOB_HELPER_MANIFEST_NAME);
    try {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        if (manifest.version !== JOB_HELPER_VERSION
            || manifest.sourceHash !== sourceHash
            || manifest.compilerHash !== compilerHash
            || manifest.helperHash !== hashFile(helperPath)
            || fs.readFileSync(sourcePath, "utf8") !== JOB_HELPER_SOURCE) {
            return null;
        }
        return Object.freeze({
            path: fs.realpathSync.native(helperPath),
            hash: manifest.helperHash,
            sourceHash,
        });
    } catch {
        return null;
    }
}

function compileHelper(controlRoot, spawnCompiler = spawnSync) {
    const sourceHash = validatePinnedSource();
    const compiler = resolveCompiler();
    const compilerHash = hashFile(compiler);
    const finalRoot = path.join(
        controlRoot,
        `helper-v${JOB_HELPER_VERSION}-${sourceHash.slice(0, 16)}-${
            compilerHash.slice(0, 16)
        }`,
    );
    const cached = readValidHelper(finalRoot, sourceHash, compilerHash);
    if (cached !== null) return cached;

    const buildRoot = path.join(
        controlRoot,
        `.job-helper-build-${process.pid}-${randomBytes(8).toString("hex")}`,
    );
    fs.mkdirSync(buildRoot, { recursive: false, mode: 0o700 });
    const sourcePath = path.join(buildRoot, JOB_HELPER_SOURCE_NAME);
    const helperPath = path.join(buildRoot, JOB_HELPER_EXE_NAME);
    try {
        fs.writeFileSync(sourcePath, JOB_HELPER_SOURCE, {
            encoding: "utf8",
            flag: "wx",
            mode: 0o600,
        });
        const compiled = spawnCompiler(
            compiler,
            [
                "/nologo",
                "/target:exe",
                "/optimize+",
                "/platform:anycpu",
                `/out:${helperPath}`,
                "/r:System.Web.Extensions.dll",
                sourcePath,
            ],
            {
                cwd: buildRoot,
                shell: false,
                windowsHide: true,
                encoding: "utf8",
                timeout: 120_000,
                maxBuffer: 1024 * 1024,
            },
        );
        if (compiled.error !== undefined
            || compiled.status !== 0
            || !fs.existsSync(helperPath)) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                "Windows Job Object helper compilation failed",
                {
                    status: compiled.status ?? null,
                    signal: compiled.signal ?? null,
                    error: compiled.error?.message ?? null,
                    stderr: String(compiled.stderr ?? "").slice(0, 2048),
                },
            );
        }
        const helperHash = hashFile(helperPath);
        fs.writeFileSync(
            path.join(buildRoot, JOB_HELPER_MANIFEST_NAME),
            `${JSON.stringify({
                version: JOB_HELPER_VERSION,
                sourceHash,
                compilerHash,
                helperHash,
            }, null, 2)}\n`,
            { encoding: "utf8", flag: "wx", mode: 0o600 },
        );
        try {
            fs.renameSync(buildRoot, finalRoot);
        } catch (error) {
            const raced = readValidHelper(finalRoot, sourceHash, compilerHash);
            if (raced === null) throw error;
            return raced;
        }
        const installed = readValidHelper(finalRoot, sourceHash, compilerHash);
        if (installed === null) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                "Installed Windows Job Object helper failed verification",
            );
        }
        return installed;
    } finally {
        fs.rmSync(buildRoot, { recursive: true, force: true });
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
    ]) {
        const value = process.env[key];
        if (typeof value === "string" && value.length > 0) env[key] = value;
    }
    return env;
}

function waitForClose(child, timeoutMs) {
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

async function terminateOwnedChild(record, timeoutMs) {
    if (record.child.exitCode !== null || record.child.signalCode !== null) {
        return true;
    }
    try {
        record.child.stdin?.write(Buffer.from([0x4b]));
        record.child.stdin?.end();
    } catch {
        // The owner may already be exiting.
    }
    const graceMs = Math.max(1, Math.min(timeoutMs, 5_000));
    if (await waitForClose(record.child, graceMs)) return true;
    try { record.child.kill("SIGKILL"); } catch { /* exact helper may be gone */ }
    return waitForClose(record.child, graceMs);
}

export function createWindowsJobProcessAdapter(options = {}) {
    if ((options.platform ?? process.platform) !== "win32") {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "Windows Job Object process ownership is only available on win32",
        );
    }
    const controlRoot = normalizeDirectory(
        options.controlRoot ?? defaultControlRoot(),
        "controlRoot",
    );
    const spawnProcess = options.spawnProcess ?? childSpawn;
    const spawnCompiler = options.spawnCompiler ?? spawnSync;
    const active = new Map();
    const cleanupErrors = [];
    let helper = null;
    let closed = false;

    const preparedHelper = () => {
        helper ??= compileHelper(controlRoot, spawnCompiler);
        if (hashFile(helper.path) !== helper.hash) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                "Windows Job Object helper binary changed after verification",
                { helperPath: helper.path },
            );
        }
        return helper;
    };

    return Object.freeze({
        platform: "win32",
        containment: "windows-job-object",
        owns(pid) {
            return active.has(pid);
        },
        spawn(executable, argv, launchOptions) {
            if (closed) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                    "Windows Job Object process adapter is closed",
                );
            }
            const ownerRoot = normalizeDirectory(
                launchOptions?.ownerRoot ?? controlRoot,
                "ownerRoot",
            );
            const timeoutMs = launchOptions?.timeoutMs;
            if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                    "Windows Job Object launch requires a positive timeoutMs",
                    { timeoutMs: timeoutMs ?? null },
                );
            }
            const invocationRoot = fs.mkdtempSync(path.join(
                ownerRoot,
                `.crucible-job-owner-${process.pid}-`,
            ));
            const request = {
                Version: JOB_HELPER_VERSION,
                ParentPid: process.pid,
                Executable: executable,
                Argv: [...argv],
                Cwd: launchOptions.cwd,
                Env: { ...launchOptions.env },
                TimeoutMs: timeoutMs,
            };
            const requestBytes = Buffer.from(JSON.stringify(request), "utf8");
            const requestPath = path.join(invocationRoot, "launch-request.json");
            const fd = fs.openSync(requestPath, "wx", 0o400);
            try {
                let offset = 0;
                while (offset < requestBytes.length) {
                    offset += fs.writeSync(
                        fd,
                        requestBytes,
                        offset,
                        requestBytes.length - offset,
                    );
                }
                fs.fsyncSync(fd);
            } finally {
                fs.closeSync(fd);
            }

            let child;
            try {
                const owner = preparedHelper();
                child = spawnProcess(
                    owner.path,
                    [requestPath, sha256Bytes(requestBytes)],
                    {
                        cwd: invocationRoot,
                        env: helperEnvironment(),
                        stdio: [
                            "pipe",
                            launchOptions.stdio?.[1] ?? "pipe",
                            launchOptions.stdio?.[2] ?? "pipe",
                        ],
                        shell: false,
                        windowsHide: true,
                        detached: false,
                    },
                );
            } catch (error) {
                fs.rmSync(invocationRoot, { recursive: true, force: true });
                if (error instanceof MeasurementError) throw error;
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                    `failed to launch Windows Job Object owner: ${
                        error?.message ?? String(error)
                    }`,
                    { cause: error?.code ?? null },
                );
            }
            if (!Number.isSafeInteger(child?.pid) || child.pid < 1) {
                try { child?.kill?.("SIGKILL"); } catch {}
                fs.rmSync(invocationRoot, { recursive: true, force: true });
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                    "Windows Job Object owner did not expose a valid pid",
                );
            }
            const record = { child, invocationRoot };
            active.set(child.pid, record);
            child.once("close", () => {
                active.delete(child.pid);
                try {
                    fs.rmSync(invocationRoot, {
                        recursive: true,
                        force: true,
                        maxRetries: 100,
                        retryDelay: 25,
                    });
                } catch (error) {
                    cleanupErrors.push(error);
                }
            });
            return child;
        },
        async terminate(pid, termination = {}) {
            const record = active.get(pid);
            if (record === undefined) return false;
            const timeoutMs = Number.isSafeInteger(termination?.timeoutMs)
                && termination.timeoutMs > 0
                ? Math.min(termination.timeoutMs, 60_000)
                : 5_000;
            return terminateOwnedChild(record, timeoutMs);
        },
        async close(termination = {}) {
            closed = true;
            const timeoutMs = Number.isSafeInteger(termination?.timeoutMs)
                && termination.timeoutMs > 0
                ? Math.min(termination.timeoutMs, 60_000)
                : 5_000;
            const records = [...active.values()];
            const results = await Promise.all(
                records.map((record) => terminateOwnedChild(record, timeoutMs)),
            );
            if (results.some((result) => result !== true)) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
                    "Windows Job Object owner did not terminate every active process",
                    {
                        activePids: [...active.keys()],
                        timeoutMs,
                    },
                );
            }
            if (cleanupErrors.length > 0) {
                const error = cleanupErrors[0];
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
                    "Windows Job Object owner cleanup left protected invocation files",
                    {
                        cause: error?.code ?? null,
                        message: error?.message ?? String(error),
                    },
                );
            }
            return true;
        },
    });
}
