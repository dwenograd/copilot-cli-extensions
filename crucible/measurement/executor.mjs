// crucible/measurement/executor.mjs
//
// MeasurementExecutor: the fail-closed trusted-measurement boundary.
//
// Contract for one run:
//   - Caller supplies a *verified* harness entry issued by the exact allowlist
//     instance bound to this executor. The executor reopens/re-hashes it for
//     this run; you cannot hand it a raw executable path or a token from a
//     different allowlist instance.
//   - The executable and every declared dependency are copied from their
//     verified open handles into a private per-attempt directory, fsync'd,
//     re-hashed, and only those staged paths reach spawn().
//   - Caller supplies a materialised candidate directory plus the immutable
//     snapshot id, canonical manifest, and expected CAS object closure. Every
//     path is identity-pinned and hashed before spawn, held open through the
//     run, then identity-checked and re-hashed before any result is accepted.
//   - If executesCandidateCode is true and no SandboxProvider was
//     configured, the executor throws SandboxRequiredError immediately —
//     before any spawn. cwd/env/timeout ARE NOT a sandbox.
//   - Spawn is via the injected process adapter with shell:false,
//     windowsHide:true, an explicit absolute executable, an explicit cwd
//     (the entry's cwd or a temp scratch dir), and a minimal env built
//     ONLY from the entry's allowedEnv plus a small fixed set of
//     platform-required keys (SystemRoot, ComSpec on Windows).
//   - Output is captured with hard byte caps; exceeding either cap
//     triggers a process-tree termination and OUTPUT_OVERFLOW. Similarly
//     for the timeout.
//   - On completion the raw stdout bytes are parsed by the strict result
//     parser and a full receipt is built.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { immutableCanonical } from "../domain/canonical.mjs";
import {
    ARGV_PLACEHOLDERS,
    acquireVerifiedHarnessRun,
    isLoadedHarnessAllowlist,
    isVerifiedHarnessEntry,
    releaseVerifiedHarnessRun,
    stageVerifiedHarnessRun,
} from "./allowlist.mjs";
import {
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
    SandboxRefusedError,
    SandboxRequiredError,
    StagingRefusedError,
} from "./errors.mjs";
import {
    closeVerifiedSnapshotClosure,
    openVerifiedSnapshotClosure,
    reverifySnapshotClosure,
    sha256Bytes,
    STREAM_HASH_ALGORITHM,
} from "./fs-verify.mjs";
import { PARSER_VERSION, parseHarnessResult } from "./parser.mjs";
import {
    buildMeasurementReceipt,
    hashArgv,
    hashEnv,
} from "./receipt.mjs";
import { normalizeAdmission } from "./sandbox.mjs";
import { createDefaultProcessAdapter } from "./windows-adapter.mjs";

const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const HASH_TAG = /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;

// Minimal fixed env keys we always pass through so the child process can
// find fundamental system resources. NOT candidate for allowedEnv override:
// these are OS-required and constant per host.
const WINDOWS_ALWAYS_KEYS = ["SystemRoot", "SYSTEMROOT", "ComSpec", "TEMP", "TMP"];
const POSIX_ALWAYS_KEYS = ["PATH"]; // POSIX children usually need PATH to exec other tools

function buildBaseEnv() {
    const src = process.env;
    const out = {};
    if (process.platform === "win32") {
        for (const key of WINDOWS_ALWAYS_KEYS) {
            const v = src[key];
            if (typeof v === "string" && v.length > 0) out[key] = v;
        }
    } else {
        for (const key of POSIX_ALWAYS_KEYS) {
            const v = src[key];
            if (typeof v === "string" && v.length > 0) out[key] = v;
        }
    }
    return out;
}

function substituteArgv(template, substitutions) {
    return template.map((raw) => raw.replace(/\{\{([^}]+)\}\}/gu, (_, name) => {
        if (!ARGV_PLACEHOLDERS.includes(name)) {
            // Should not reach here: allowlist normalizer already rejected
            // unknown placeholders at load time. Belt-and-suspenders.
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                `unknown argv placeholder {{${name}}}`,
            );
        }
        const value = substitutions[name];
        if (typeof value !== "string" || value.length === 0) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                `argv placeholder {{${name}}} has no substitution value`,
            );
        }
        return value;
    }));
}

function validateCandidateSnapshot(snapshot) {
    if (snapshot === null || typeof snapshot !== "object" || Array.isArray(snapshot)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "candidate snapshot must be an object",
        );
    }
    if (typeof snapshot.path !== "string" || snapshot.path.length === 0 || !path.isAbsolute(snapshot.path)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "candidate snapshot.path must be an absolute string path",
        );
    }
    if (typeof snapshot.hash !== "string" || !HASH_TAG.test(snapshot.hash)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "candidate snapshot.hash must be an algorithm-tagged SHA-256",
        );
    }
    if (!Object.isFrozen(snapshot)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "candidate snapshot must be frozen (immutable)",
        );
    }
    return snapshot;
}

function validateIdentifier(value, field) {
    if (typeof value !== "string" || !SAFE_ID.test(value)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${field} must be a safe identifier matching /^[a-z0-9][a-z0-9._-]{0,127}$/`,
        );
    }
    return value;
}

// Build a MeasurementExecutor. Options:
//   sandboxProvider    : { admitAndPrepare(entry, snapshot) } | null
//   processAdapter     : injected for tests; defaults to real Windows adapter
//   clock              : { now(): number, isoNow(): string } for tests
//   scratchRoot        : operator-owned root for private per-attempt staging
export function createMeasurementExecutor(options = {}) {
    const allowlist = options.allowlist;
    if (!isLoadedHarnessAllowlist(allowlist)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "MeasurementExecutor requires the loaded HarnessAllowlist instance it is bound to",
        );
    }
    const sandboxProvider = options.sandboxProvider ?? null;
    if (sandboxProvider !== null) {
        if (typeof sandboxProvider !== "object" || typeof sandboxProvider.admitAndPrepare !== "function") {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                "sandboxProvider must expose admitAndPrepare(entry, snapshot)",
            );
        }
    }
    const adapter = options.processAdapter ?? createDefaultProcessAdapter();
    if (typeof adapter?.spawn !== "function" || typeof adapter?.terminateTree !== "function") {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "processAdapter must expose spawn() and terminateTree()",
        );
    }
    const clock = options.clock ?? {
        now: () => Date.now(),
        isoNow: () => new Date().toISOString(),
    };
    if (typeof clock.now !== "function" || typeof clock.isoNow !== "function") {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "clock must expose now() and isoNow()",
        );
    }
    const scratchRoot = normalizeScratchRoot(options.scratchRoot);

    return Object.freeze({
        sandboxProvider,
        processAdapter: adapter,

        async run(runInput) {
            return runOnce({
                runInput,
                sandboxProvider,
                adapter,
                clock,
                scratchRoot,
                allowlist,
            });
        },
    });
}

function normalizeScratchRoot(value) {
    if (typeof value !== "string" || !path.isAbsolute(value)) {
        throw new StagingRefusedError(
            "MeasurementExecutor requires an absolute operator-owned scratchRoot for private staging",
            { scratchRoot: value ?? null },
        );
    }
    try {
        fs.mkdirSync(value, { recursive: true, mode: 0o700 });
        const lst = fs.lstatSync(value);
        if (lst.isSymbolicLink() || !lst.isDirectory()) {
            throw new Error("scratchRoot is not a regular directory");
        }
        const real = fs.realpathSync.native(value);
        const resolved = path.resolve(value);
        const same = process.platform === "win32"
            ? real.toLowerCase() === resolved.toLowerCase()
            : real === resolved;
        if (!same) {
            throw new Error("scratchRoot resolves through a symlink or reparse point");
        }
        return real;
    } catch (error) {
        if (error instanceof MeasurementError) throw error;
        throw new StagingRefusedError(
            `scratchRoot cannot provide private staging: ${error?.message ?? String(error)}`,
            { scratchRoot: value, cause: error?.code ?? null },
        );
    }
}

function makeAttemptStage(scratchRoot, attemptId) {
    try {
        const stage = path.join(scratchRoot, `.crucible-stage-${attemptId}`);
        fs.mkdirSync(stage, { recursive: false, mode: 0o700 });
        try { fs.chmodSync(stage, 0o700); } catch { /* Windows ACLs govern access */ }
        return stage;
    } catch (error) {
        throw new StagingRefusedError(
            `failed to create private per-attempt staging: ${error?.message ?? String(error)}`,
            { scratchRoot, attemptId, cause: error?.code ?? null },
        );
    }
}

function rewriteDependencyArgv(entry, concreteArgv, stagedDependencies) {
    const rewritten = [...concreteArgv];
    for (const ref of entry.argvDependencyRefs) {
        const staged = stagedDependencies[ref.dependencyIndex];
        if (staged === undefined) {
            throw new StagingRefusedError(
                "allowlist dependency mapping could not be staged safely",
                { argvIndex: ref.argvIndex, dependencyIndex: ref.dependencyIndex },
            );
        }
        rewritten[ref.argvIndex] = `${ref.prefix}${staged.path}`;
    }
    return rewritten;
}

async function runOnce({
    runInput,
    sandboxProvider,
    adapter,
    clock,
    scratchRoot,
    allowlist,
}) {
    if (runInput === null || typeof runInput !== "object" || Array.isArray(runInput)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "run() input must be an object",
        );
    }
    const verifiedEntry = runInput.verifiedEntry;
    if (!isVerifiedHarnessEntry(verifiedEntry)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "run() requires a verifiedEntry produced by HarnessAllowlist.verifyEntry()",
        );
    }
    const snapshot = validateCandidateSnapshot(runInput.candidateSnapshot);
    const attemptId = validateIdentifier(runInput.attemptId, "attemptId");
    const runnerEpochId = validateIdentifier(runInput.runnerEpochId, "runnerEpochId");
    let runLease = null;
    let stageRoot = null;
    let snapshotLease = null;
    try {
        // Re-open and re-hash through the issuing allowlist instance for this
        // exact run, then keep those verified handles live through staging.
        runLease = acquireVerifiedHarnessRun(verifiedEntry, allowlist);
        stageRoot = makeAttemptStage(scratchRoot, attemptId);
        const stagedRun = stageVerifiedHarnessRun(runLease, stageRoot);
        const entry = stagedRun.entry;
        snapshotLease = openVerifiedSnapshotClosure(snapshot);

        // Fail-closed sandbox gate.
        let admission = null;
        if (entry.executesCandidateCode) {
            if (sandboxProvider === null) {
                throw new SandboxRequiredError(
                    `harness ${JSON.stringify(entry.id)} executes candidate code; a SandboxProvider is required`,
                    { harnessId: entry.id },
                );
            }
        }
        if (sandboxProvider !== null) {
            let raw;
            try {
                raw = sandboxProvider.admitAndPrepare(verifiedEntry, snapshot);
            } catch (err) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SANDBOX_REFUSED,
                    `SandboxProvider threw: ${err?.message ?? String(err)}`,
                    { cause: err?.code ?? null },
                );
            }
            const normalized = normalizeAdmission(raw);
            if (!normalized.admitted) {
                throw new SandboxRefusedError(
                    `SandboxProvider refused: ${normalized.reason}`,
                    { harnessId: entry.id, reason: normalized.reason },
                );
            }
            if (normalized.wrap !== null) {
                throw new StagingRefusedError(
                    "sandbox wrapper executables are refused unless the sandbox is enforced by the process adapter; source-path wrapper execution is forbidden",
                    { harnessId: entry.id },
                );
            }
            admission = normalized;
        }

        // Substitute only data placeholders, then replace every declared
        // static file reference with its private staged path.
        const concreteArgv = substituteArgv(entry.argvTemplate, {
            candidatePath: snapshot.path,
            attemptId,
        });
        const spawnExecutable = stagedRun.executable.path;
        const spawnArgv = rewriteDependencyArgv(
            entry,
            concreteArgv,
            stagedRun.dependencies,
        );

        // The child never receives a source cwd. Any required relative layout
        // was preserved under stagedRun.cwd or the configuration was refused.
        const cwd = stagedRun.cwd;

        // Build a minimal, explicit env. `allowedEnv` from the entry is the
        // authoritative caller-facing surface; we add the platform's
        // always-required keys.
        const env = { ...buildBaseEnv() };
        for (const [k, v] of Object.entries(entry.allowedEnv)) {
            env[k] = v;
        }
        env.CANDIDATE_SNAPSHOT_PATH = snapshot.path;
        env.CRUCIBLE_ATTEMPT_ID = attemptId;
        env.CRUCIBLE_RUNNER_EPOCH_ID = runnerEpochId;

        const argvHash = hashArgv(spawnArgv);
        const envHash = hashEnv(env);

        const startedAt = clock.isoNow();
        const startTimeMs = clock.now();

        let child;
        try {
            child = adapter.spawn(spawnExecutable, spawnArgv, {
                cwd,
                env,
                stdio: ["ignore", "pipe", "pipe"],
            });
        } catch (err) {
            throw new StagingRefusedError(
                `staged executable cannot be launched on this platform: ${err?.message ?? String(err)}`,
                {
                    executable: spawnExecutable,
                    cause: err?.code ?? null,
                    originalCode: err instanceof MeasurementError ? err.code : null,
                },
            );
        }
        if (child?.pid === undefined || child?.pid === null) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                "adapter.spawn did not return a child with a pid",
            );
        }

        const outcome = await captureChild(child, {
            pid: child.pid,
            maxStdoutBytes: entry.maxStdoutBytes,
            maxStderrBytes: entry.maxStderrBytes,
            timeoutMs: entry.timeoutMs,
            adapter,
        });
        const snapshotBinding = reverifySnapshotClosure(snapshotLease);

        const completedAt = clock.isoNow();
        const durationMs = clock.now() - startTimeMs;

        const stdoutBytes = outcome.stdout;
        const stderrBytes = outcome.stderr;
        const stdoutHash = sha256Bytes(stdoutBytes, STREAM_HASH_ALGORITHM);
        const stderrHash = sha256Bytes(stderrBytes, STREAM_HASH_ALGORITHM);

    // Timeout / overflow: reject BEFORE attempting to parse. Even if the
    // partial output happens to contain valid JSON, the run itself was not
    // a valid measurement.
        if (outcome.timedOut) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.TIMEOUT,
            `harness ${entry.id} exceeded timeout of ${entry.timeoutMs}ms`,
            {
                harnessId: entry.id,
                timeoutMs: entry.timeoutMs,
                stdoutBytes: stdoutBytes.length,
                stderrBytes: stderrBytes.length,
            },
        );
        }
        if (outcome.overflowStream !== null) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW,
            `harness ${entry.id} exceeded ${outcome.overflowStream} cap`,
            {
                harnessId: entry.id,
                stream: outcome.overflowStream,
                capBytes: outcome.overflowStream === "stdout"
                    ? entry.maxStdoutBytes
                    : entry.maxStderrBytes,
            },
        );
        }
        if (outcome.exit.error !== undefined) {
            throw new StagingRefusedError(
                `staged executable failed during platform launch: ${outcome.exit.error}`,
                { harnessId: entry.id, executable: spawnExecutable },
            );
        }
        if (outcome.exit.code !== 0 || outcome.exit.signal !== null) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
            `harness ${entry.id} exited non-zero`,
            {
                harnessId: entry.id,
                exit: outcome.exit,
                stderr: safeStderrPreview(stderrBytes),
            },
        );
        }

    // Parse result. The parser is strict — anything wrong throws
    // ResultParseError which the caller sees directly.
        const rawStdoutText = stdoutBytes.toString("utf8");
        const parsed = parseHarnessResult(rawStdoutText);

        const receipt = buildMeasurementReceipt({
        allowlistFileHash: stagedRun.allowlistFileHash,
        harnessEntryHash: stagedRun.entryHash,
        executableHash: stagedRun.executable.sourceHash,
        stagedExecutableHash: stagedRun.executable.stagedHash,
        dependencyHashes: stagedRun.dependencies.map((d) => ({
            path: d.sourcePath,
            role: d.role,
            sha256: d.sourceHash,
        })),
        stagedDependencyHashes: stagedRun.dependencies.map((d) => ({
            path: d.path,
            role: d.role,
            sha256: d.stagedHash,
        })),
        argvHash,
        envHash,
        candidateSnapshotHash: snapshot.hash,
        candidateSnapshotPreClosureHash: snapshotBinding.preClosureHash,
        candidateSnapshotPostClosureHash: snapshotBinding.postClosureHash,
        candidateSnapshotIdentitySummary: snapshotBinding.identitySummary,
        candidateSnapshotMutationCheck: snapshotBinding.mutationCheck,
        stdoutHash,
        stderrHash,
        parserVersion: PARSER_VERSION,
        sandbox: admission === null
            ? null
            : {
                sandboxId: admission.sandboxId,
                environmentHash: admission.environmentHash,
            },
        attemptId,
        runnerEpochId,
        startedAt,
        completedAt,
        durationMs,
        exit: {
            code: outcome.exit.code,
            signal: outcome.exit.signal,
            timedOut: false,
        },
        parsed,
        });

        return immutableCanonical({
        receipt,
        parsed,
        exit: outcome.exit,
        stdoutBytes: stdoutBytes.length,
        stderrBytes: stderrBytes.length,
        stdoutHash,
        stderrHash,
        // NB: we do NOT expose the raw stdout/stderr text in the result.
        // Callers that need it can hash-check against stdoutHash/stderrHash
        // by re-capturing from their own log. Keeping raw output out of the
        // return prevents accidental persistence of unvetted bytes.
        });
    } finally {
        try {
            if (snapshotLease !== null) {
                closeVerifiedSnapshotClosure(snapshotLease);
            }
        } finally {
            try {
                if (runLease !== null) {
                    releaseVerifiedHarnessRun(runLease);
                }
            } finally {
                if (stageRoot !== null) {
                    fs.rmSync(stageRoot, { recursive: true, force: true });
                }
            }
        }
    }
}

function safeStderrPreview(bytes) {
    const s = bytes.toString("utf8");
    return s.length > 512 ? `${s.slice(0, 512)}... (+${s.length - 512} more)` : s;
}

// Consume a child process's stdout/stderr up to per-stream byte caps, with
// a wall-clock timeout, terminating the process tree via `adapter` on
// overflow or timeout. Resolves with { stdout, stderr, exit, timedOut,
// overflowStream } — never rejects for these reasons; the executor
// interprets the shape.
function captureChild(child, { pid, maxStdoutBytes, maxStderrBytes, timeoutMs, adapter }) {
    return new Promise((resolve) => {
        const stdoutChunks = [];
        const stderrChunks = [];
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let overflowStream = null;
        let timedOut = false;
        let settled = false;
        let exit = { code: null, signal: null };

        const timer = setTimeout(() => {
            timedOut = true;
            adapter.terminateTree(pid);
        }, timeoutMs);
        timer.unref?.();

        function finalize() {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve({
                stdout: Buffer.concat(stdoutChunks, stdoutBytes),
                stderr: Buffer.concat(stderrChunks, stderrBytes),
                exit,
                timedOut,
                overflowStream,
            });
        }

        function attachStream(stream, chunks, sinkName, cap) {
            stream.on("data", (chunk) => {
                const remaining = cap - (sinkName === "stdout" ? stdoutBytes : stderrBytes);
                if (remaining <= 0) return;
                let toAppend = chunk;
                if (chunk.length > remaining) {
                    toAppend = chunk.subarray(0, remaining);
                }
                chunks.push(toAppend);
                if (sinkName === "stdout") stdoutBytes += toAppend.length;
                else stderrBytes += toAppend.length;
                // If the original chunk overflowed the cap, tree-kill and mark.
                if (chunk.length > remaining) {
                    if (overflowStream === null) overflowStream = sinkName;
                    adapter.terminateTree(pid);
                }
            });
            stream.on("error", () => { /* surfaced via child.on('error') */ });
        }

        if (child.stdout) attachStream(child.stdout, stdoutChunks, "stdout", maxStdoutBytes);
        if (child.stderr) attachStream(child.stderr, stderrChunks, "stderr", maxStderrBytes);

        child.on("error", (err) => {
            // Spawn/comm-level error before or during run. Record it as a
            // non-zero exit so the executor's downstream check surfaces it.
            exit = { code: exit.code ?? -1, signal: exit.signal ?? null, error: err?.message ?? String(err) };
            adapter.terminateTree(pid);
            // Give any pending data events a tick to flush.
            setImmediate(finalize);
        });
        child.on("close", (code, signal) => {
            exit = { code: code ?? null, signal: signal ?? null };
            // Wait a tick for late data events.
            setImmediate(finalize);
        });
    });
}

// Small convenience for tests / callers that need a file:// URL from an
// absolute path (harnesses sometimes want a URL-form snapshot pointer).
export function toFileUrl(absPath) {
    return pathToFileURL(absPath).href;
}
