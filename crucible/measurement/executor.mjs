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
//   - If executesCandidateCode is true, launch is possible only through a
//     genuine one-shot SandboxLaunchCapability issued by the configured
//     SandboxProvider for this exact attempt and staged root. The ordinary
//     host process adapter is never used for that path.
//   - Non-candidate-code launch is via the injected host process adapter with
//     shell:false, windowsHide:true, an explicit absolute executable, an
//     explicit cwd, and a minimal env.
//   - Output is captured with hard byte caps; exceeding either cap
//     triggers a process-tree termination and OUTPUT_OVERFLOW. Similarly
//     for the timeout.
//   - On completion the raw stdout bytes are parsed by the strict result
//     parser and a full receipt is built.

import fs from "node:fs";
import path from "node:path";

import { canonicalJson, immutableCanonical } from "../domain/canonical.mjs";
import {
    ARGV_PLACEHOLDERS,
    acquireVerifiedHarnessRun,
    isLoadedHarnessAllowlist,
    isVerifiedHarnessEntry,
    releaseVerifiedHarnessRun,
    reverifyStagedHarnessRun,
    stageVerifiedHarnessRun,
    trustedParserIdentity,
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
    closeStagedSnapshotClosure,
    openVerifiedSnapshotClosure,
    reverifyStagedSnapshotClosure,
    reverifySnapshotClosure,
    sha256Bytes,
    stageVerifiedSnapshotClosure,
    STREAM_HASH_ALGORITHM,
} from "./fs-verify.mjs";
import {
    PARSER_MAX_INPUT_BYTES,
    PARSER_VERSION,
    normalizeHarnessResultBinding,
    parseHarnessResult,
} from "./parser.mjs";
import {
    VERIFIER_PARSER_VERSION,
    parseImpossibilityVerifierResult,
} from "./verifier-parser.mjs";
import { MEASUREMENT_LIFECYCLE_ADAPTER } from "./private-adapters.mjs";
import {
    buildMeasurementReceipt,
    hashArgv,
    hashEnv,
} from "./receipt.mjs";
import {
    cleanupSandboxCapability,
    describeSandboxCapability,
    isSandboxProvider,
    isSandboxRefusal,
    launchSandboxCapability,
    terminateSandboxCapability,
} from "./sandbox.mjs";
import { createDefaultProcessAdapter } from "./windows-adapter.mjs";

const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const HASH_TAG = /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const DEFAULT_TERMINATION_DRAIN_TIMEOUT_MS = 5_000;
const DEFAULT_CAPABILITY_CLEANUP_TIMEOUT_MS = 10_000;
const EXECUTOR_OPTION_KEYS = new Set([
    "allowlist",
    "sandboxProvider",
    "processAdapter",
    "clock",
    "scratchRoot",
    "onCapturedOutput",
    "terminationDrainMs",
    "capabilityCleanupTimeoutMs",
    "byteBudgets",
    "initialByteUsage",
]);
const LIFECYCLE_ADAPTER_METHODS = Object.freeze([
    "afterHarnessStaging",
    "beforeHarnessLaunch",
    "afterHarnessLaunch",
    "afterHarnessExit",
]);
export const DEFAULT_MEASUREMENT_BYTE_BUDGETS = Object.freeze({
    perAttemptOutputBytes: 16 * 1024 * 1024,
    perInvestigationOutputBytes: 256 * 1024 * 1024,
    perAttemptReceiptBytes: 2 * 1024 * 1024,
    perInvestigationReceiptBytes: 64 * 1024 * 1024,
    perAttemptCasBytes: 32 * 1024 * 1024,
    perInvestigationCasBytes: 2 * 1024 * 1024 * 1024,
});

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

function bindingArgv(binding) {
    return [
        `--crucible-role=${binding.role}`,
        `--crucible-phase=${binding.phase}`,
        `--crucible-replicate-index=${binding.replicateIndex}`,
        `--crucible-block-index=${binding.blockIndex}`,
        `--crucible-arm-index=${binding.armIndex}`,
        `--crucible-arm-id=${binding.armId}`,
        `--crucible-deterministic-seed=${binding.deterministicSeed}`,
        `--crucible-subject-id=${binding.subjectId}`,
        `--crucible-environment-identity=${binding.environmentIdentity}`,
        `--crucible-suite-identity=${binding.suiteIdentity}`,
    ];
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

function candidateCasCharge(snapshot, maximumBytes) {
    const manifest = snapshot.manifest;
    if (manifest === null
        || typeof manifest !== "object"
        || Array.isArray(manifest)
        || !Array.isArray(manifest.entries)
        || !Number.isSafeInteger(manifest.totalBytes)
        || manifest.totalBytes < 0) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "candidate snapshot manifest counters are malformed",
        );
    }
    let fileBytes = 0;
    let minimumManifestBytes = 128;
    for (const [index, entry] of manifest.entries.entries()) {
        if (entry === null
            || typeof entry !== "object"
            || Array.isArray(entry)
            || typeof entry.path !== "string"
            || !Number.isSafeInteger(entry.size)
            || entry.size < 0) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                "candidate snapshot manifest entry is malformed",
                { index },
            );
        }
        fileBytes = boundedAdd(fileBytes, entry.size);
        minimumManifestBytes = boundedAdd(
            minimumManifestBytes,
            128 + Buffer.byteLength(entry.path, "utf8"),
        );
    }
    if (fileBytes !== manifest.totalBytes) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
            "candidate snapshot manifest totalBytes is inconsistent",
            { expected: manifest.totalBytes, actual: fileBytes },
        );
    }
    const lowerBound = boundedAdd(fileBytes, minimumManifestBytes);
    if (lowerBound > maximumBytes) {
        return lowerBound;
    }
    return boundedAdd(
        fileBytes,
        Buffer.byteLength(canonicalJson(manifest), "utf8"),
    );
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

function normalizeDeadline(value) {
    if (value === null || value === undefined) return null;
    if (!Number.isFinite(value)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "deadlineMs must be finite epoch milliseconds or null",
            { deadlineMs: value },
        );
    }
    return value;
}

function normalizeAbortSignal(value) {
    if (value === null || value === undefined) return null;
    if (typeof value !== "object"
        || typeof value.aborted !== "boolean"
        || typeof value.addEventListener !== "function"
        || typeof value.removeEventListener !== "function") {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "run().signal must be an AbortSignal",
        );
    }
    return value;
}

function throwIfAborted(signal, stage) {
    if (signal?.aborted !== true) return;
    if (signal.reason instanceof Error) {
        throw signal.reason;
    }
    throw new MeasurementError(
        MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
        `measurement aborted during ${stage}`,
        { stage, aborted: true },
    );
}

function remainingDeadlineMs(deadlineMs, clock) {
    return deadlineMs === null
        ? Number.POSITIVE_INFINITY
        : Math.max(0, Math.floor(deadlineMs - clock.now()));
}

function deadlineTimeout(deadlineMs, clock, stage) {
    return new MeasurementError(
        MEASUREMENT_ERROR_CODES.TIMEOUT,
        `measurement deadline expired during ${stage}`,
        {
            deadlineExceeded: true,
            deadlineMs,
            observedAtMs: clock.now(),
            stage,
        },
    );
}

function assertDeadline(deadlineMs, clock, stage) {
    if (remainingDeadlineMs(deadlineMs, clock) === 0) {
        throw deadlineTimeout(deadlineMs, clock, stage);
    }
}

function settleWithin(operation, timeoutMs) {
    let promise;
    try {
        promise = Promise.resolve().then(operation);
    } catch (error) {
        promise = Promise.reject(error);
    }
    return new Promise((resolve) => {
        let settled = false;
        const finish = (result) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve(result);
        };
        const timer = setTimeout(
            () => finish({ status: "timed_out" }),
            Math.max(1, timeoutMs),
        );
        timer.unref?.();
        promise.then(
            (value) => finish({ status: "fulfilled", value }),
            (error) => finish({ status: "rejected", error }),
        );
    });
}

async function cleanupCapabilityWithinBound(capability, binding, timeoutMs) {
    const outcome = await settleWithin(
        () => cleanupSandboxCapability(capability, binding),
        timeoutMs,
    );
    if (outcome.status === "rejected") {
        throw outcome.error;
    }
    if (outcome.status === "timed_out") {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
            "Sandbox capability cleanup exceeded its final bound",
            { timeoutMs },
        );
    }
}

function normalizeLifecycleTimeout(value, fallback, field) {
    const actual = value ?? fallback;
    if (!Number.isSafeInteger(actual) || actual < 1 || actual > 60_000) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${field} must be a positive integer <= 60000`,
            { field, value: actual },
        );
    }
    return actual;
}

function normalizePositiveByteBudget(value, fallback, field) {
    const actual = value ?? fallback;
    if (!Number.isSafeInteger(actual) || actual < 1 || actual > 4 * 1024 * 1024 * 1024) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            `${field} must be a positive safe integer <= 4 GiB`,
            { field, value: actual },
        );
    }
    return actual;
}

function normalizeMeasurementByteBudgets(value = {}) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "byteBudgets must be an object",
        );
    }
    const unknown = Object.keys(value).filter((key) =>
        !Object.hasOwn(DEFAULT_MEASUREMENT_BYTE_BUDGETS, key));
    if (unknown.length > 0) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "byteBudgets contain unknown keys",
            { unknown },
        );
    }
    const normalized = {};
    for (const [key, fallback] of Object.entries(DEFAULT_MEASUREMENT_BYTE_BUDGETS)) {
        normalized[key] = normalizePositiveByteBudget(
            value[key],
            fallback,
            `byteBudgets.${key}`,
        );
    }
    if (normalized.perInvestigationOutputBytes < normalized.perAttemptOutputBytes
        || normalized.perInvestigationReceiptBytes < normalized.perAttemptReceiptBytes) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "per-investigation byte budgets must be at least their per-attempt budgets",
        );
    }
    if (normalized.perInvestigationCasBytes < normalized.perAttemptCasBytes) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "perInvestigationCasBytes must be at least perAttemptCasBytes",
        );
    }
    return Object.freeze(normalized);
}

function normalizeInitialByteUsage(value = {}) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "initialByteUsage must be an object",
        );
    }
    const allowed = new Set(["outputBytes", "receiptBytes", "casBytes"]);
    const unknown = Object.keys(value).filter((key) => !allowed.has(key));
    if (unknown.length > 0) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "initialByteUsage contains unknown keys",
            { unknown },
        );
    }
    const normalize = (field) => {
        const actual = value[field] ?? 0;
        if (!Number.isSafeInteger(actual) || actual < 0) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
                `initialByteUsage.${field} must be a non-negative safe integer`,
                { value: actual },
            );
        }
        return actual;
    };
    return Object.freeze({
        outputBytes: normalize("outputBytes"),
        receiptBytes: normalize("receiptBytes"),
        casBytes: normalize("casBytes"),
    });
}

function boundedAdd(left, right) {
    if (!Number.isSafeInteger(right) || right < 0) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "byte count must be a non-negative safe integer",
            { bytes: right },
        );
    }
    return left > Number.MAX_SAFE_INTEGER - right
        ? Number.MAX_SAFE_INTEGER
        : left + right;
}

function createMeasurementByteLedger(budgets, initialUsage) {
    let investigationOutputBytes = initialUsage.outputBytes;
    let investigationReceiptBytes = initialUsage.receiptBytes;
    let investigationCasBytes = initialUsage.casBytes;
    const attempts = new Map();
    const attempt = (attemptId) => {
        let value = attempts.get(attemptId);
        if (value === undefined) {
            value = { outputBytes: 0, receiptBytes: 0, casBytes: 0 };
            attempts.set(attemptId, value);
        }
        return value;
    };
    const consume = (attemptId, bytes, kind) => {
        const state = attempt(attemptId);
        const attemptField = `${kind}Bytes`;
        const attemptLimit = kind === "output"
            ? budgets.perAttemptOutputBytes
            : kind === "receipt"
                ? budgets.perAttemptReceiptBytes
                : budgets.perAttemptCasBytes;
        const investigationLimit = kind === "output"
            ? budgets.perInvestigationOutputBytes
            : kind === "receipt"
                ? budgets.perInvestigationReceiptBytes
                : budgets.perInvestigationCasBytes;
        const nextAttempt = boundedAdd(state[attemptField], bytes);
        const currentInvestigation = kind === "output"
            ? investigationOutputBytes
            : kind === "receipt"
                ? investigationReceiptBytes
                : investigationCasBytes;
        const nextInvestigation = boundedAdd(currentInvestigation, bytes);
        state[attemptField] = nextAttempt;
        if (kind === "output") investigationOutputBytes = nextInvestigation;
        else if (kind === "receipt") {
            investigationReceiptBytes = nextInvestigation;
        } else {
            investigationCasBytes = nextInvestigation;
        }
        return Object.freeze({
            allowed: nextAttempt <= attemptLimit
                && nextInvestigation <= investigationLimit,
            kind,
            bytes,
            attemptBytes: nextAttempt,
            attemptLimit,
            investigationBytes: nextInvestigation,
            investigationLimit,
        });
    };
    return Object.freeze({
        consumeOutput(attemptId, bytes) {
            return consume(attemptId, bytes, "output");
        },
        consumeReceipt(attemptId, bytes) {
            return consume(attemptId, bytes, "receipt");
        },
        consumeCas(attemptId, bytes) {
            return consume(attemptId, bytes, "cas");
        },
        snapshot(attemptId) {
            const state = attempt(attemptId);
            return immutableCanonical({
                limits: budgets,
                attempt: state,
                investigation: {
                    outputBytes: investigationOutputBytes,
                    receiptBytes: investigationReceiptBytes,
                    casBytes: investigationCasBytes,
                },
            });
        },
    });
}

function byteBudgetError(result, attemptId, stage) {
    return new MeasurementError(
        MEASUREMENT_ERROR_CODES.BYTE_BUDGET_EXCEEDED,
        `measurement ${result.kind} byte budget exceeded during ${stage}`,
        {
            attemptId,
            stage,
            ...result,
        },
    );
}

// Build a MeasurementExecutor. Options:
//   sandboxProvider    : registered provider from createSandboxProvider() | null
//   processAdapter     : injected for tests; defaults to real Windows adapter
//   clock              : { now(): number, isoNow(): string } for tests
//   scratchRoot        : operator-owned root for private per-attempt staging
//   onCapturedOutput   : trusted raw-output observer used by the runtime runner
//   terminationDrainMs : final child-output drain bound after termination
//   capabilityCleanupTimeoutMs : final sandbox cleanup / Job Object close bound
export function createMeasurementExecutor(options = {}) {
    if (options === null
        || typeof options !== "object"
        || Array.isArray(options)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "MeasurementExecutor options must be an object",
        );
    }
    const unknownOptions = Object.keys(options)
        .filter((key) => !EXECUTOR_OPTION_KEYS.has(key));
    const unknownSymbols = Object.getOwnPropertySymbols(options)
        .filter((key) => key !== MEASUREMENT_LIFECYCLE_ADAPTER);
    if (unknownOptions.length > 0 || unknownSymbols.length > 0) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "MeasurementExecutor received unknown options",
            {
                unknownOptions,
                unknownSymbolCount: unknownSymbols.length,
            },
        );
    }
    const allowlist = options.allowlist;
    if (!isLoadedHarnessAllowlist(allowlist)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "MeasurementExecutor requires the loaded HarnessAllowlist instance it is bound to",
        );
    }
    const sandboxProvider = options.sandboxProvider ?? null;
    if (sandboxProvider !== null && !isSandboxProvider(sandboxProvider)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "sandboxProvider must be an opaque provider created by createSandboxProvider()",
        );
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
    const onCapturedOutput = options.onCapturedOutput ?? null;
    if (onCapturedOutput !== null && typeof onCapturedOutput !== "function") {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "onCapturedOutput must be a function or null",
        );
    }
    const lifecycleAdapter = normalizeLifecycleAdapter(
        options[MEASUREMENT_LIFECYCLE_ADAPTER],
    );
    const scratchRoot = normalizeScratchRoot(options.scratchRoot);
    const terminationDrainMs = normalizeLifecycleTimeout(
        options.terminationDrainMs,
        DEFAULT_TERMINATION_DRAIN_TIMEOUT_MS,
        "terminationDrainMs",
    );
    const capabilityCleanupTimeoutMs = normalizeLifecycleTimeout(
        options.capabilityCleanupTimeoutMs,
        DEFAULT_CAPABILITY_CLEANUP_TIMEOUT_MS,
        "capabilityCleanupTimeoutMs",
    );
    const byteBudgets = normalizeMeasurementByteBudgets(options.byteBudgets);
    const initialByteUsage = normalizeInitialByteUsage(options.initialByteUsage);
    if (initialByteUsage.outputBytes > byteBudgets.perInvestigationOutputBytes
        || initialByteUsage.receiptBytes > byteBudgets.perInvestigationReceiptBytes
        || initialByteUsage.casBytes > byteBudgets.perInvestigationCasBytes) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.BYTE_BUDGET_EXCEEDED,
            "initial measurement byte usage already exceeds the investigation budget",
            { byteBudgets, initialByteUsage },
        );
    }
    const byteLedger = createMeasurementByteLedger(byteBudgets, initialByteUsage);

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
                onCapturedOutput,
                lifecycleAdapter,
                terminationDrainMs,
                capabilityCleanupTimeoutMs,
                byteLedger,
            });
        },
        async close(closeOptions = {}) {
            if (typeof adapter.close !== "function") return true;
            return adapter.close(closeOptions);
        },
    });
}

function normalizeLifecycleAdapter(value) {
    if (value === undefined || value === null) return null;
    if (typeof value !== "object" || Array.isArray(value)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "measurement lifecycle adapter must be an object",
        );
    }
    const unknown = Object.keys(value)
        .filter((key) => !LIFECYCLE_ADAPTER_METHODS.includes(key));
    if (unknown.length > 0
        || LIFECYCLE_ADAPTER_METHODS.some((key) =>
            value[key] !== undefined && typeof value[key] !== "function")) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "measurement lifecycle adapter is malformed",
            { unknown },
        );
    }
    return Object.freeze(Object.fromEntries(
        LIFECYCLE_ADAPTER_METHODS
            .filter((key) => value[key] !== undefined)
            .map((key) => [key, value[key]]),
    ));
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

function makeStageWritable(stageRoot) {
    if (!fs.existsSync(stageRoot)) return;
    const visit = (directory) => {
        let entries = [];
        try {
            entries = fs.readdirSync(directory, { withFileTypes: true });
        } catch {
            return;
        }
        for (const entry of entries) {
            const item = path.join(directory, entry.name);
            if (entry.isDirectory()) {
                visit(item);
                try { fs.chmodSync(item, 0o700); } catch { /* best effort */ }
            } else {
                try { fs.chmodSync(item, 0o600); } catch { /* best effort */ }
            }
        }
        try { fs.chmodSync(directory, 0o700); } catch { /* best effort */ }
    };
    visit(stageRoot);
}

async function removeAttemptStage(stageRoot) {
    let lastError = null;
    for (let attempt = 0; attempt < 200; attempt += 1) {
        try {
            fs.rmSync(stageRoot, { recursive: true, force: true });
            return;
        } catch (error) {
            lastError = error;
            if (!["EBUSY", "ENOTEMPTY", "EPERM"].includes(error?.code)) {
                throw error;
            }
            if (attempt === 0) makeStageWritable(stageRoot);
            await new Promise((resolve) => setTimeout(resolve, 50));
        }
    }
    throw lastError;
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
    onCapturedOutput,
    lifecycleAdapter,
    terminationDrainMs,
    capabilityCleanupTimeoutMs,
    byteLedger,
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
    const measurementBinding = normalizeHarnessResultBinding(
        runInput.measurementBinding,
        {
            field: "run().measurementBinding",
        },
    );
    const verifierParser = measurementBinding.role === "impossibility_verifier";
    const resultParserContext = verifierParser
        ? runInput.resultParserContext
        : null;
    if (verifierParser
        && (resultParserContext === null
            || typeof resultParserContext !== "object"
            || Array.isArray(resultParserContext)
            || resultParserContext.request === null
            || typeof resultParserContext.request !== "object"
            || Array.isArray(resultParserContext.request)
            || typeof resultParserContext.requestHash !== "string"
            || !HASH_TAG.test(resultParserContext.requestHash))) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "impossibility verifier runs require resultParserContext",
        );
    }
    const parserVersion = verifierParser
        ? VERIFIER_PARSER_VERSION
        : PARSER_VERSION;
    const parserIdentity = trustedParserIdentity(parserVersion);
    const deadlineMs = normalizeDeadline(runInput.deadlineMs);
    const signal = normalizeAbortSignal(runInput.signal);
    const budgetLimits = byteLedger.snapshot(attemptId).limits;
    const casBudget = byteLedger.consumeCas(
        attemptId,
        candidateCasCharge(
            snapshot,
            Math.min(
                budgetLimits.perAttemptCasBytes,
                budgetLimits.perInvestigationCasBytes,
            ),
        ),
    );
    if (!casBudget.allowed) {
        throw byteBudgetError(
            casBudget,
            attemptId,
            "candidate snapshot admission",
        );
    }
    let runLease = null;
    let stageRoot = null;
    let snapshotLease = null;
    let stagedSnapshot = null;
    let capability = null;
    let capabilityBinding = null;
    let capabilityCleaned = false;
    let abortHandler = null;
    try {
        throwIfAborted(signal, "measurement admission");
        assertDeadline(deadlineMs, clock, "measurement admission");
        // Re-open and re-hash through the issuing allowlist instance for this
        // exact run, then keep those verified handles live through staging.
        runLease = acquireVerifiedHarnessRun(verifiedEntry, allowlist);
        stageRoot = makeAttemptStage(scratchRoot, attemptId);
        const stagedRun = stageVerifiedHarnessRun(runLease, stageRoot);
        const entry = stagedRun.entry;
        snapshotLease = openVerifiedSnapshotClosure(snapshot);
        stagedSnapshot = stageVerifiedSnapshotClosure(
            snapshotLease,
            path.join(stageRoot, "candidate"),
        );
        assertDeadline(deadlineMs, clock, "harness staging");

        // Substitute only data placeholders, then replace every declared
        // static file reference with its private staged path.
        const concreteArgv = substituteArgv(entry.argvTemplate, {
            candidatePath: stagedSnapshot.path,
            attemptId,
            role: measurementBinding.role,
            phase: measurementBinding.phase,
            replicateIndex: String(measurementBinding.replicateIndex),
            blockIndex: String(measurementBinding.blockIndex),
            armIndex: String(measurementBinding.armIndex),
            armId: measurementBinding.armId,
            deterministicSeed: measurementBinding.deterministicSeed,
            subjectId: measurementBinding.subjectId,
            environmentIdentity: measurementBinding.environmentIdentity,
            suiteIdentity: measurementBinding.suiteIdentity,
        });
        const spawnExecutable = stagedRun.executable.path;
        const spawnArgv = [
            ...rewriteDependencyArgv(
            entry,
            concreteArgv,
            stagedRun.dependencies,
            ),
            ...bindingArgv(measurementBinding),
        ];

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
        env.CANDIDATE_SNAPSHOT_PATH = stagedSnapshot.path;
        env.CRUCIBLE_ATTEMPT_ID = attemptId;
        env.CRUCIBLE_RUNNER_EPOCH_ID = runnerEpochId;
        env.CRUCIBLE_ROLE = measurementBinding.role;
        env.CRUCIBLE_PHASE = measurementBinding.phase;
        env.CRUCIBLE_REPLICATE_INDEX =
            String(measurementBinding.replicateIndex);
        env.CRUCIBLE_BLOCK_INDEX = String(measurementBinding.blockIndex);
        env.CRUCIBLE_ARM_INDEX = String(measurementBinding.armIndex);
        env.CRUCIBLE_ARM_ID = measurementBinding.armId;
        env.CRUCIBLE_DETERMINISTIC_SEED =
            measurementBinding.deterministicSeed;
        env.CRUCIBLE_SUBJECT_ID = measurementBinding.subjectId;
        env.CRUCIBLE_ENVIRONMENT_IDENTITY =
            measurementBinding.environmentIdentity;
        env.CRUCIBLE_SUITE_IDENTITY = measurementBinding.suiteIdentity;

        const argvHash = hashArgv(spawnArgv);
        const envHash = hashEnv(env);
        const stagedPaths = [
            stagedRun.executable.path,
            stagedRun.cwd,
            ...stagedRun.dependencies.map((dependency) => dependency.path),
            stagedSnapshot.path,
            ...stagedSnapshot.directories,
            ...stagedSnapshot.files.map((file) => file.absPath),
        ];
        const launchFiles = Object.freeze([
            Object.freeze({
                path: stagedRun.executable.path,
                sha256: stagedRun.executable.stagedHash,
                role: "executable",
                identity: stagedRun.executable.identity,
            }),
            ...stagedRun.dependencies.map((dependency) => Object.freeze({
                path: dependency.path,
                sha256: dependency.stagedHash,
                role: dependency.role,
                identity: dependency.identity,
            })),
            ...stagedSnapshot.files.map((file) => Object.freeze({
                path: file.absPath,
                sha256: file.stagedHash,
                role: "candidate",
                identity: file.identity,
            })),
        ]);
        const executionSnapshot = Object.freeze({
            ...snapshot,
            path: stagedSnapshot.path,
        });
        await lifecycleAdapter?.afterHarnessStaging?.(Object.freeze({
            attemptId,
            runnerEpochId,
            harnessId: entry.id,
            stageRoot,
            executable: spawnExecutable,
            dependencies: Object.freeze(
                stagedRun.dependencies.map((dependency) => dependency.path),
            ),
            candidateRoot: stagedSnapshot.path,
            candidateFiles: Object.freeze(
                stagedSnapshot.files.map((file) => file.absPath),
            ),
        }));
        reverifyStagedHarnessRun(stagedRun);
        reverifyStagedSnapshotClosure(stagedSnapshot);
        const admissionTimeoutMs = Math.max(
            1,
            Math.min(entry.timeoutMs, remainingDeadlineMs(deadlineMs, clock)),
        );

        // Fail closed before launch. A successful provider result must be the
        // opaque capability issued for this exact admission; ordinary objects
        // and host process adapters cannot satisfy the private capability
        // identity check.
        if (entry.executesCandidateCode) {
            if (sandboxProvider === null) {
                throw new SandboxRequiredError(
                    `harness ${JSON.stringify(entry.id)} executes candidate code; a SandboxProvider is required`,
                    { harnessId: entry.id },
                );
            }
            let admission;
            try {
                admission = await sandboxProvider.admitAndPrepare(Object.freeze({
                    verifiedEntry,
                    candidateSnapshot: executionSnapshot,
                    attemptId,
                    runnerEpochId,
                    harnessId: entry.id,
                    stagedRoots: Object.freeze([stageRoot]),
                    launch: Object.freeze({
                        executable: spawnExecutable,
                        argv: Object.freeze([...spawnArgv]),
                        argvHash,
                        cwd,
                        envHash,
                        deadlineMs,
                        timeoutMs: admissionTimeoutMs,
                        stagedPaths: Object.freeze([...stagedPaths]),
                        launchFiles,
                    }),
                }));
            } catch (error) {
                if (error instanceof MeasurementError) throw error;
                throw new SandboxRefusedError(
                    `SandboxProvider threw: ${error?.message ?? String(error)}`,
                    { harnessId: entry.id, cause: error?.code ?? null },
                );
            }
            if (isSandboxRefusal(admission)) {
                throw new SandboxRefusedError(
                    `SandboxProvider refused: ${admission.reason}`,
                    { harnessId: entry.id, reason: admission.reason },
                );
            }
            capability = admission;
            capabilityBinding = Object.freeze({
                provider: sandboxProvider,
                attemptId,
                runnerEpochId,
                harnessId: entry.id,
                stagedRoots: Object.freeze([stageRoot]),
            });
            // Validate identity and staged-root binding before any launch.
            describeSandboxCapability(capability, capabilityBinding);
            assertDeadline(deadlineMs, clock, "sandbox admission");
        }

        assertDeadline(deadlineMs, clock, "harness launch");
        const effectiveTimeoutMs = Math.max(
            1,
            Math.min(entry.timeoutMs, remainingDeadlineMs(deadlineMs, clock)),
        );
        const startedAt = clock.isoNow();
        const startTimeMs = clock.now();
        await lifecycleAdapter?.beforeHarnessLaunch?.(Object.freeze({
            attemptId,
            runnerEpochId,
            harnessId: entry.id,
            stageRoot,
            executable: spawnExecutable,
            dependencies: Object.freeze(
                stagedRun.dependencies.map((dependency) => dependency.path),
            ),
            candidateRoot: stagedSnapshot.path,
            candidateFiles: Object.freeze(
                stagedSnapshot.files.map((file) => file.absPath),
            ),
        }));
        throwIfAborted(signal, "harness launch");
        reverifyStagedHarnessRun(stagedRun);
        reverifyStagedSnapshotClosure(stagedSnapshot);

        let child;
        let terminationController;
        if (capability !== null) {
            child = await launchSandboxCapability(
                capability,
                capabilityBinding,
                {
                    executable: spawnExecutable,
                    argv: spawnArgv,
                    cwd,
                    env,
                    deadlineMs,
                    timeoutMs: effectiveTimeoutMs,
                    stagedPaths,
                    launchFiles,
                },
            );
            terminationController = Object.freeze({
                terminate(pid, reason) {
                    return terminateSandboxCapability(
                        capability,
                        capabilityBinding,
                        { pid, reason },
                    );
                },
            });
        } else {
            try {
                child = await adapter.spawn(spawnExecutable, spawnArgv, {
                    cwd,
                    env,
                    stdio: ["ignore", "pipe", "pipe"],
                    executesCandidateCode: false,
                    launchPath: "host-process-adapter",
                    deadlineMs,
                    timeoutMs: effectiveTimeoutMs,
                    ownerRoot: path.join(
                        scratchRoot,
                        ".crucible-process-owners",
                    ),
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
            terminationController = Object.freeze({
                terminate(pid) {
                    return adapter.terminateTree(pid);
                },
            });
        }
        if (child?.pid === undefined || child?.pid === null) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SPAWN_FAILED,
                "adapter.spawn did not return a child with a pid",
            );
        }

        const capture = captureChild(child, {
            pid: child.pid,
            maxStdoutBytes: Math.min(
                entry.maxStdoutBytes,
                PARSER_MAX_INPUT_BYTES,
            ),
            maxStderrBytes: entry.maxStderrBytes,
            timeoutMs: effectiveTimeoutMs,
            terminationDrainMs,
            terminationController,
            attemptId,
            byteLedger,
        });
        if (signal !== null) {
            abortHandler = () => {
                capture.terminate("external-effect-authority-lost");
            };
            signal.addEventListener("abort", abortHandler, { once: true });
            if (signal.aborted) {
                abortHandler();
            }
        }
        try {
            await lifecycleAdapter?.afterHarnessLaunch?.(Object.freeze({
                attemptId,
                runnerEpochId,
                harnessId: entry.id,
                pid: child.pid,
            }));
        } catch (error) {
            capture.terminate("fault-after-harness-launch");
            let drained = await settleWithin(
                Promise.all([capture.outcome, capture.closed]),
                Math.max(terminationDrainMs * 2, terminationDrainMs + 1),
            );
            if (drained.status === "timed_out") {
                try {
                    child.kill?.("SIGKILL");
                } catch {
                    // The launch owner remains authoritative for cleanup.
                }
                drained = await settleWithin(capture.closed, terminationDrainMs);
            }
            throw error;
        }
        const outcome = await capture.outcome;
        throwIfAborted(signal, "measurement output acceptance");
        await lifecycleAdapter?.afterHarnessExit?.(Object.freeze({
            attemptId,
            runnerEpochId,
            harnessId: entry.id,
            pid: child.pid,
            exit: outcome.exit,
            timedOut: outcome.timedOut,
            overflowStreams: Object.freeze([...outcome.overflowStreams]),
        }));

        // Containment cleanup is part of the measured operation. Complete it
        // before the post-run candidate closure check so cleanup cannot mutate
        // candidate bytes outside the receipt's before/after binding.
        if (capability !== null) {
            await cleanupCapabilityWithinBound(
                capability,
                capabilityBinding,
                capabilityCleanupTimeoutMs,
            );
            capabilityCleaned = true;
        }
        const stagedSnapshotBinding =
            reverifyStagedSnapshotClosure(stagedSnapshot);
        const snapshotBinding = reverifySnapshotClosure(snapshotLease);
        assertDeadline(deadlineMs, clock, "measurement fact acceptance");

        const completedAt = clock.isoNow();
        const durationMs = clock.now() - startTimeMs;

        const stdoutBytes = outcome.stdout;
        const stderrBytes = outcome.stderr;
        const stdoutHash = sha256Bytes(stdoutBytes, STREAM_HASH_ALGORITHM);
        const stderrHash = sha256Bytes(stderrBytes, STREAM_HASH_ALGORITHM);
        const outputCapture = immutableCanonical(outcome.outputCapture);
        const sandbox = capability === null
            ? null
            : describeSandboxCapability(capability, capabilityBinding);
        if (sandbox !== null && sandbox.capabilityLaunchUsed !== true) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
                "Sandbox receipt cannot attest a capability launch that was not used",
                { attemptId, capabilityId: sandbox.capabilityId },
            );
        }
        const buildReceiptFor = (parsed, timedOut = outcome.timedOut) => {
            const receipt = buildMeasurementReceipt({
                harnessId: entry.id,
                allowlistFileHash: stagedRun.allowlistFileHash,
                harnessEntryHash: stagedRun.entryHash,
                executableHash: stagedRun.executable.sourceHash,
                stagedExecutableHash: stagedRun.executable.stagedHash,
                dependencyHashes: stagedRun.dependencies.map((d) => ({
                    path: d.sourcePath,
                    role: d.role,
                    sha256: d.sourceHash,
                })),
                launchFileBindings: launchFiles.map((file) => ({
                    path: file.path,
                    role: file.role,
                    sha256: file.sha256,
                    identity: file.identity,
                })),
                stagedDependencyHashes: stagedRun.dependencies.map((d) => ({
                    path: d.path,
                    role: d.role,
                    sha256: d.stagedHash,
                })),
                argvHash,
                envHash,
                candidateSnapshotHash: snapshot.hash,
                stagedCandidateSnapshotHash: stagedSnapshot.hash,
                stagedCandidateSnapshotClosureHash:
                    stagedSnapshotBinding.closureHash,
                stagedCandidateSnapshotIdentitySummary:
                    stagedSnapshotBinding.identitySummary,
                candidateSnapshotPreClosureHash: snapshotBinding.preClosureHash,
                candidateSnapshotPostClosureHash: snapshotBinding.postClosureHash,
                candidateSnapshotIdentitySummary: snapshotBinding.identitySummary,
                candidateSnapshotMutationCheck: snapshotBinding.mutationCheck,
                stdoutHash,
                stderrHash,
                outputCapture,
                parserVersion,
                parserIdentity,
                sandbox,
                measurementBinding,
                attemptId,
                runnerEpochId,
                startedAt,
                completedAt,
                durationMs,
                exit: {
                    code: outcome.exit.code,
                    signal: outcome.exit.signal,
                    timedOut,
                },
                parsed,
            });
            const receiptBytes = Buffer.byteLength(canonicalJson(receipt), "utf8");
            const receiptBudget =
                byteLedger.consumeReceipt(attemptId, receiptBytes);
            if (!receiptBudget.allowed) {
                throw byteBudgetError(
                    receiptBudget,
                    attemptId,
                    "receipt construction",
                );
            }
            return receipt;
        };
        let capturedOutputPublished = false;
        const publishCapturedOutput = async () => {
            if (capturedOutputPublished || onCapturedOutput === null) return;
            await onCapturedOutput(Object.freeze({
                attemptId,
                runnerEpochId,
                stdout: Buffer.from(stdoutBytes),
                stderr: Buffer.from(stderrBytes),
                stdoutHash,
                stderrHash,
                outputCapture,
            }));
            capturedOutputPublished = true;
        };

        // Timeout / overflow: reject BEFORE attempting to parse. Even if the
        // partial output happens to contain valid JSON, the run itself was not
        // a valid measurement.
        if (outcome.byteBudgetExceeded !== null) {
            throw byteBudgetError(
                outcome.byteBudgetExceeded,
                attemptId,
                "streaming output capture",
            );
        }
        if (outcome.timedOut) {
            const receipt = buildReceiptFor(null, true);
            await publishCapturedOutput();
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.TIMEOUT,
                `harness ${entry.id} exceeded timeout of ${effectiveTimeoutMs}ms`,
                {
                    harnessId: entry.id,
                    timeoutMs: effectiveTimeoutMs,
                    deadlineMs,
                    deadlineExceeded: deadlineMs !== null
                        && remainingDeadlineMs(deadlineMs, clock) === 0,
                    stdoutBytes: stdoutBytes.length,
                    stderrBytes: stderrBytes.length,
                    outputCapture,
                    receipt,
                    terminationError: outcome.terminationError?.message ?? null,
                },
            );
        }
        if (outcome.overflowStream !== null) {
            const receipt = buildReceiptFor(null, false);
            await publishCapturedOutput();
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW,
                `harness ${entry.id} exceeded ${outcome.overflowStream} cap`,
                {
                    harnessId: entry.id,
                    stream: outcome.overflowStream,
                    capBytes: outcome.overflowStream === "stdout"
                        ? outputCapture.stdout.capBytes
                        : outputCapture.stderr.capBytes,
                    streams: outcome.overflowStreams,
                    outputCapture,
                    receipt,
                    terminationError: outcome.terminationError?.message ?? null,
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
            const receipt = buildReceiptFor(null, false);
            await publishCapturedOutput();
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
                `harness ${entry.id} exited non-zero`,
                {
                    harnessId: entry.id,
                    exit: outcome.exit,
                    stderr: safeStderrPreview(stderrBytes),
                    outputCapture,
                    receipt,
                },
            );
        }

        // Parse result. The parser is strict — anything wrong throws
        // ResultParseError which the caller sees directly.
        const rawStdoutText = stdoutBytes.toString("utf8");
        let parsed;
        try {
            if (verifierParser) {
                parsed = parseImpossibilityVerifierResult(rawStdoutText, {
                    expectedBinding: measurementBinding,
                    request: resultParserContext.request,
                    requestHash: resultParserContext.requestHash,
                });
            } else {
                parsed = parseHarnessResult(rawStdoutText, {
                    expectedBinding: measurementBinding,
                });
            }
        } catch (error) {
            const receipt = buildReceiptFor(null, false);
            await publishCapturedOutput();
            error.details = {
                ...(error?.details ?? {}),
                receipt,
                outputCapture,
            };
            throw error;
        }
        const receipt = buildReceiptFor(parsed, false);
        await publishCapturedOutput();

        return immutableCanonical({
            receipt,
            parsed,
            exit: outcome.exit,
            stdoutBytes: stdoutBytes.length,
            stderrBytes: stderrBytes.length,
            stdoutTotalObservedBytes:
                outputCapture.stdout.totalObservedBytes,
            stderrTotalObservedBytes:
                outputCapture.stderr.totalObservedBytes,
            outputCapture,
            stdoutHash,
            stderrHash,
            // NB: we do NOT expose the raw stdout/stderr text in the result.
            // The trusted observer receives byte copies before this canonical
            // result is built; raw unvetted output is not persisted here.
        });
    } finally {
        if (signal !== null && abortHandler !== null) {
            signal.removeEventListener("abort", abortHandler);
        }
        try {
            if (capability !== null && !capabilityCleaned) {
                await cleanupCapabilityWithinBound(
                    capability,
                    capabilityBinding,
                    capabilityCleanupTimeoutMs,
                );
            }
        } finally {
            try {
                if (stagedSnapshot !== null) {
                    closeStagedSnapshotClosure(stagedSnapshot);
                    stagedSnapshot = null;
                }
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
                        await removeAttemptStage(stageRoot);
                    }
                }
            }
        }
    }
}

function safeStderrPreview(bytes) {
    const preview = bytes.subarray(0, Math.min(bytes.length, 512)).toString("utf8");
    return bytes.length > 512
        ? `${preview}... (+${bytes.length - 512} more bytes)`
        : preview;
}

// Consume a child process's stdout/stderr up to per-stream byte caps, with
// a wall-clock timeout, terminating the process through its launch owner on
// overflow or timeout. Resolves with retained stdout/stderr, exact observed
// byte counters, exit, timeout, and per-stream overflow state — never rejects
// for these reasons; the executor
// interprets the shape.
function captureChild(
    child,
    {
        pid,
        maxStdoutBytes,
        maxStderrBytes,
        timeoutMs,
        terminationDrainMs,
        terminationController,
        attemptId,
        byteLedger,
    },
) {
    let terminate = () => {};
    let resolveClosed;
    let closeRecorded = false;
    const closed = new Promise((resolve) => {
        resolveClosed = resolve;
    });
    const recordClosed = (value) => {
        if (closeRecorded) return;
        closeRecorded = true;
        resolveClosed(value);
    };
    const outcome = new Promise((resolve) => {
        const stdoutChunks = [];
        const stderrChunks = [];
        let stdoutRetainedBytes = 0;
        let stderrRetainedBytes = 0;
        let stdoutTotalObservedBytes = 0;
        let stderrTotalObservedBytes = 0;
        const overflowStreams = new Set();
        let byteBudgetExceeded = null;
        let timedOut = false;
        let settled = false;
        let exit = { code: null, signal: null };
        let terminationError = null;
        const terminationPromises = [];
        let forcedFinalizeTimer = null;

        function requestTermination(reason) {
            try {
                const pending = settleWithin(
                    () => terminationController.terminate(pid, reason),
                    terminationDrainMs,
                ).then((outcome) => {
                    if (outcome.status === "rejected") {
                        terminationError = outcome.error;
                    } else if (outcome.status === "timed_out") {
                        terminationError = new Error(
                            `process termination exceeded ${terminationDrainMs}ms`,
                        );
                    }
                });
                terminationPromises.push(pending);
            } catch (error) {
                terminationError = error;
            }
        }

        function armForcedFinalize() {
            if (forcedFinalizeTimer !== null) return;
            forcedFinalizeTimer = setTimeout(() => {
                void finalize();
            }, terminationDrainMs);
            forcedFinalizeTimer.unref?.();
        }
        terminate = (reason) => {
            requestTermination(reason);
            armForcedFinalize();
        };

        const timer = setTimeout(() => {
            timedOut = true;
            requestTermination("timeout");
            armForcedFinalize();
        }, timeoutMs);
        timer.unref?.();

        async function finalize() {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            clearTimeout(forcedFinalizeTimer);
            await Promise.all(terminationPromises);
            resolve({
                stdout: Buffer.concat(stdoutChunks, stdoutRetainedBytes),
                stderr: Buffer.concat(stderrChunks, stderrRetainedBytes),
                exit,
                timedOut,
                overflowStream: [...overflowStreams][0] ?? null,
                overflowStreams: [...overflowStreams],
                byteBudgetExceeded,
                outputCapture: {
                    stdout: {
                        capBytes: maxStdoutBytes,
                        totalObservedBytes: stdoutTotalObservedBytes,
                        retainedBytes: stdoutRetainedBytes,
                        overflowed: stdoutTotalObservedBytes > maxStdoutBytes,
                        truncated: stdoutRetainedBytes < stdoutTotalObservedBytes,
                    },
                    stderr: {
                        capBytes: maxStderrBytes,
                        totalObservedBytes: stderrTotalObservedBytes,
                        retainedBytes: stderrRetainedBytes,
                        overflowed: stderrTotalObservedBytes > maxStderrBytes,
                        truncated: stderrRetainedBytes < stderrTotalObservedBytes,
                    },
                    overflowed: overflowStreams.size > 0,
                    truncated: stdoutRetainedBytes < stdoutTotalObservedBytes
                        || stderrRetainedBytes < stderrTotalObservedBytes,
                },
                terminationError,
            });
        }

        function attachStream(stream, chunks, sinkName, cap) {
            stream.on("data", (chunk) => {
                const bytes = Buffer.isBuffer(chunk)
                    ? chunk
                    : (ArrayBuffer.isView(chunk)
                        ? Buffer.from(
                            chunk.buffer,
                            chunk.byteOffset,
                            chunk.byteLength,
                        )
                        : Buffer.from(String(chunk), "utf8"));
                if (bytes.length === 0) return;
                const budget = byteLedger.consumeOutput(attemptId, bytes.length);
                const priorAttemptBytes = budget.attemptBytes - bytes.length;
                const priorInvestigationBytes =
                    budget.investigationBytes - bytes.length;
                const budgetRemaining = Math.max(
                    0,
                    Math.min(
                        budget.attemptLimit - priorAttemptBytes,
                        budget.investigationLimit - priorInvestigationBytes,
                    ),
                );
                if (sinkName === "stdout") {
                    stdoutTotalObservedBytes =
                        boundedAdd(stdoutTotalObservedBytes, bytes.length);
                } else {
                    stderrTotalObservedBytes =
                        boundedAdd(stderrTotalObservedBytes, bytes.length);
                }
                const retainedBytes = sinkName === "stdout"
                    ? stdoutRetainedBytes
                    : stderrRetainedBytes;
                const remaining = Math.min(
                    cap - retainedBytes,
                    budgetRemaining,
                );
                if (remaining <= 0) {
                    if (!budget.allowed && byteBudgetExceeded === null) {
                        byteBudgetExceeded = budget;
                        requestTermination("cumulative-output-byte-budget");
                        armForcedFinalize();
                        return;
                    }
                    const firstOverflow = overflowStreams.size === 0;
                    overflowStreams.add(sinkName);
                    if (firstOverflow) {
                        requestTermination(`${sinkName}-overflow`);
                        armForcedFinalize();
                    }
                    return;
                }
                let toAppend = bytes;
                if (bytes.length > remaining) {
                    toAppend = bytes.subarray(0, remaining);
                }
                chunks.push(toAppend);
                if (sinkName === "stdout") stdoutRetainedBytes += toAppend.length;
                else stderrRetainedBytes += toAppend.length;
                // If the original chunk overflowed the cap, tree-kill and mark.
                if (bytes.length > remaining) {
                    if (!budget.allowed && byteBudgetExceeded === null) {
                        byteBudgetExceeded = budget;
                        requestTermination("cumulative-output-byte-budget");
                        armForcedFinalize();
                    } else {
                        const firstOverflow = overflowStreams.size === 0;
                        overflowStreams.add(sinkName);
                        if (firstOverflow) {
                            requestTermination(`${sinkName}-overflow`);
                            armForcedFinalize();
                        }
                    }
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
            requestTermination("child-error");
            armForcedFinalize();
            // Give any pending data events a tick to flush.
            setImmediate(() => { void finalize(); });
        });
        child.on("close", (code, signal) => {
            exit = { code: code ?? null, signal: signal ?? null };
            recordClosed({ kind: "close", code: code ?? null, signal: signal ?? null });
            // Wait a tick for late data events.
            setImmediate(() => { void finalize(); });
        });
    });
    return Object.freeze({ outcome, closed, terminate });
}
