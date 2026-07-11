import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    assertLocalDatabasePath,
    canonicalize,
    sha256Hex,
} from "../persistence/index.mjs";
import { RuntimeConfigError } from "./errors.mjs";
import { validateSupervisorTimingConstraints } from "./config-validation.mjs";
import { MAX_TRUSTED_OPERATOR_CONTEXT_BYTES } from "./worker-pool.mjs";
import {
    assertPathInside,
    isPathInside,
    parseDeadline,
    readJsonFile,
    rejectUnknownKeys,
    requireAbsolutePath,
    requireIdentifier,
    requireLowerIdentifier,
    requirePlainObject,
    requirePositiveInteger,
    requireString,
    safeFileToken,
} from "./utils.mjs";

const RUNNER_KEYS = new Set([
    "investigationId",
    "stateDir",
    "artifactRoot",
    "allowlistPath",
    "sdkPath",
    "copilotSdkPath",
    "cliPath",
    "copilotCliPath",
    "runnerEpochId",
    "supervisorGeneration",
    "supervisorNonce",
    "runnerIncarnation",
    "deadline",
    "options",
    "resultPath",
]);

const RUNNER_OPTION_KEYS = new Set([
    "sessionTimeoutMs",
    "shutdownTimeoutMs",
    "maxLoopIterations",
    "reasoningEffort",
    "candidateLimits",
    "workerAdditionalContext",
    "tempRoot",
    "supervisorAuthority",
]);

const SUPERVISOR_AUTHORITY_KEYS = new Set([
    "supervisorGeneration",
    "supervisorNonce",
    "runnerIncarnation",
]);

const CANDIDATE_LIMIT_KEYS = new Set([
    "maxFiles",
    "maxPathBytes",
    "maxMechanismBytes",
    "maxFileBytes",
    "maxTotalBytes",
]);

const CANDIDATE_LIMIT_MAXIMA = Object.freeze({
    maxFiles: 32,
    maxPathBytes: 512,
    maxMechanismBytes: 16 * 1024,
    maxFileBytes: 256 * 1024,
    maxTotalBytes: 1024 * 1024,
});

const SUPERVISOR_KEYS = new Set([
    "runner",
    "runnerCliPath",
    "supervisorEpochId",
    "maxRestarts",
    "baseBackoffMs",
    "maxBackoffMs",
    "heartbeatIntervalMs",
    "staleLockMs",
    "circuitWindowMs",
]);

function optionalPositiveInteger(value, field, fallback, maximum = Number.MAX_SAFE_INTEGER) {
    return value === undefined
        ? fallback
        : requirePositiveInteger(value, field, maximum);
}

function normalizeTrustedOperatorContext(value) {
    const normalized = requireString(
        value,
        "options.workerAdditionalContext",
        {
            max: MAX_TRUSTED_OPERATOR_CONTEXT_BYTES,
            allowLineBreaks: true,
        },
    );
    const bytes = Buffer.byteLength(normalized, "utf8");
    if (bytes > MAX_TRUSTED_OPERATOR_CONTEXT_BYTES) {
        throw new RuntimeConfigError(
            `options.workerAdditionalContext must not exceed ${MAX_TRUSTED_OPERATOR_CONTEXT_BYTES} UTF-8 bytes`,
            { bytes, maximumBytes: MAX_TRUSTED_OPERATOR_CONTEXT_BYTES },
        );
    }
    return normalized;
}

function requireNonNegativeInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
        throw new RuntimeConfigError(`${field} must be a non-negative safe integer <= ${maximum}`, {
            field,
            value,
        });
    }
    return value;
}

function requireLocalAbsolutePath(value, field, env) {
    const absolute = requireAbsolutePath(value, field);
    try {
        return assertLocalDatabasePath(absolute, { env });
    } catch (error) {
        throw new RuntimeConfigError(`${field} must be on a trusted local filesystem`, {
            field,
            path: absolute,
            cause: error?.code ?? null,
            reason: error?.details?.reason ?? null,
        });
    }
}

function normalizeCandidateLimits(value) {
    if (value === undefined) {
        return {};
    }
    rejectUnknownKeys(value, CANDIDATE_LIMIT_KEYS, "options.candidateLimits");
    const output = {};
    for (const [key, item] of Object.entries(value)) {
        output[key] = requirePositiveInteger(
            item,
            `options.candidateLimits.${key}`,
            CANDIDATE_LIMIT_MAXIMA[key],
        );
    }
    return output;
}

function normalizeSupervisorAuthority(value, field = "options.supervisorAuthority") {
    if (value === undefined || value === null) {
        return null;
    }
    const authority = requirePlainObject(value, field);
    rejectUnknownKeys(authority, SUPERVISOR_AUTHORITY_KEYS, field);
    return Object.freeze({
        supervisorGeneration: requirePositiveInteger(
            authority.supervisorGeneration,
            `${field}.supervisorGeneration`,
        ),
        supervisorNonce: requireString(
            authority.supervisorNonce,
            `${field}.supervisorNonce`,
            { max: 256 },
        ),
        runnerIncarnation: requireString(
            authority.runnerIncarnation,
            `${field}.runnerIncarnation`,
            { max: 256 },
        ),
    });
}

export function normalizeRunnerConfig(input, { env = process.env } = {}) {
    rejectUnknownKeys(input, RUNNER_KEYS, "runner config");
    const investigationId = requireIdentifier(input.investigationId, "investigationId");
    const stateDir = requireLocalAbsolutePath(input.stateDir, "stateDir", env);
    const artifactRoot = requireLocalAbsolutePath(input.artifactRoot, "artifactRoot", env);
    const allowlistPath = requireLocalAbsolutePath(input.allowlistPath, "allowlistPath", env);
    const sdkPath = requireLocalAbsolutePath(
        input.copilotSdkPath ?? input.sdkPath ?? env.COPILOT_SDK_PATH,
        "copilotSdkPath",
        env,
    );
    const cliPath = requireLocalAbsolutePath(
        input.copilotCliPath ?? input.cliPath ?? env.COPILOT_CLI_PATH,
        "copilotCliPath",
        env,
    );
    if (input.copilotSdkPath !== undefined && input.sdkPath !== undefined) {
        throw new RuntimeConfigError("Specify only one of copilotSdkPath or sdkPath");
    }
    if (input.copilotCliPath !== undefined && input.cliPath !== undefined) {
        throw new RuntimeConfigError("Specify only one of copilotCliPath or cliPath");
    }
    const runnerEpochId = requireLowerIdentifier(input.runnerEpochId, "runnerEpochId");
    const options = input.options === undefined ? {} : requirePlainObject(input.options, "options");
    rejectUnknownKeys(options, RUNNER_OPTION_KEYS, "options");
    const nestedAuthority = normalizeSupervisorAuthority(options.supervisorAuthority);
    const topAuthorityValues = [
        input.supervisorGeneration,
        input.supervisorNonce,
        input.runnerIncarnation,
    ];
    const hasTopAuthority = topAuthorityValues.some((value) => value !== undefined);
    if (hasTopAuthority && topAuthorityValues.some((value) => value === undefined)) {
        throw new RuntimeConfigError(
            "supervisorGeneration, supervisorNonce, and runnerIncarnation must be provided together",
        );
    }
    const topAuthority = hasTopAuthority
        ? normalizeSupervisorAuthority({
            supervisorGeneration: input.supervisorGeneration,
            supervisorNonce: input.supervisorNonce,
            runnerIncarnation: input.runnerIncarnation,
        }, "runner authority")
        : null;
    if (topAuthority !== null && nestedAuthority !== null
        && (topAuthority.supervisorGeneration !== nestedAuthority.supervisorGeneration
            || topAuthority.supervisorNonce !== nestedAuthority.supervisorNonce
            || topAuthority.runnerIncarnation !== nestedAuthority.runnerIncarnation)) {
        throw new RuntimeConfigError(
            "top-level runner authority must match options.supervisorAuthority",
        );
    }
    const supervisorAuthority = topAuthority ?? nestedAuthority;
    const supervisorGeneration = supervisorAuthority?.supervisorGeneration ?? null;
    const supervisorNonce = supervisorAuthority?.supervisorNonce ?? null;
    const runnerIncarnation = supervisorAuthority?.runnerIncarnation ?? null;
    if (isPathInside(stateDir, artifactRoot)) {
        throw new RuntimeConfigError(
            "stateDir cannot be equal to or nested inside artifactRoot",
            { stateDir, artifactRoot },
        );
    }
    if (isPathInside(path.join(stateDir, "supervisor"), artifactRoot)) {
        throw new RuntimeConfigError(
            "artifactRoot cannot contain the reserved supervisor state directory",
            { stateDir, artifactRoot },
        );
    }
    const tempRoot = options.tempRoot === undefined
        ? path.join(stateDir, "runtime-temp")
        : assertPathInside(requireAbsolutePath(options.tempRoot, "options.tempRoot"), stateDir, "options.tempRoot");
    if (isPathInside(tempRoot, artifactRoot)) {
        throw new RuntimeConfigError("options.tempRoot cannot be inside artifactRoot", {
            tempRoot,
            artifactRoot,
        });
    }
    const resultPath = input.resultPath === undefined
        ? null
        : assertPathInside(requireAbsolutePath(input.resultPath, "resultPath"), stateDir, "resultPath");
    if (resultPath !== null) {
        if (path.extname(resultPath).toLowerCase() !== ".json") {
            throw new RuntimeConfigError("resultPath must name a .json file", { resultPath });
        }
        if (path.basename(resultPath).toLowerCase().startsWith("events.sqlite")
            || isPathInside(resultPath, artifactRoot)
            || isPathInside(resultPath, tempRoot)) {
            throw new RuntimeConfigError(
                "resultPath conflicts with runtime database, artifact, or temporary storage",
                { resultPath },
            );
        }
    }
    return Object.freeze({
        investigationId,
        stateDir,
        artifactRoot,
        allowlistPath,
        sdkPath,
        cliPath,
        runnerEpochId,
        supervisorGeneration,
        supervisorNonce,
        runnerIncarnation,
        deadlineMs: parseDeadline(input.deadline),
        resultPath,
        options: Object.freeze({
            sessionTimeoutMs: optionalPositiveInteger(
                options.sessionTimeoutMs,
                "options.sessionTimeoutMs",
                120_000,
                60 * 60 * 1000,
            ),
            shutdownTimeoutMs: optionalPositiveInteger(
                options.shutdownTimeoutMs,
                "options.shutdownTimeoutMs",
                30_000,
                60 * 1000,
            ),
            maxLoopIterations: optionalPositiveInteger(
                options.maxLoopIterations,
                "options.maxLoopIterations",
                10_000,
                1_000_000,
            ),
            reasoningEffort: options.reasoningEffort === undefined
                || options.reasoningEffort === null
                ? null
                : requireString(options.reasoningEffort, "options.reasoningEffort", { max: 32 }),
            candidateLimits: Object.freeze(normalizeCandidateLimits(options.candidateLimits)),
            workerAdditionalContext: options.workerAdditionalContext === undefined
                || options.workerAdditionalContext === null
                ? null
                : normalizeTrustedOperatorContext(options.workerAdditionalContext),
            tempRoot,
            ...(supervisorAuthority === null
                ? {}
                : { supervisorAuthority }),
        }),
    });
}

export function loadRunnerConfig(file, options) {
    return normalizeRunnerConfig(readJsonFile(file, "runner config"), options);
}

export function supervisorPaths(stateDir, investigationId) {
    const token = safeFileToken(investigationId);
    const directory = path.join(path.resolve(stateDir), "supervisor");
    return Object.freeze({
        directory,
        lockPath: path.join(directory, `${token}.lock.json`),
        statusPath: path.join(directory, `${token}.status.json`),
        generationPath: path.join(directory, `${token}.generation.json`),
        configPath: path.join(directory, `${token}.config.json`),
        childConfigPath: path.join(directory, `${token}.runner.json`),
        childResultPath: path.join(directory, `${token}.runner-result.json`),
        stopRequestPath: path.join(directory, `${token}.stop-request.json`),
    });
}

export function supervisorConfigDocument(input, options = {}) {
    const config = coerceSupervisorConfig(input, options);
    return {
        runner: {
            investigationId: config.runner.investigationId,
            stateDir: config.runner.stateDir,
            artifactRoot: config.runner.artifactRoot,
            allowlistPath: config.runner.allowlistPath,
            copilotSdkPath: config.runner.sdkPath,
            copilotCliPath: config.runner.cliPath,
            runnerEpochId: config.runner.runnerEpochId,
            deadline: config.runner.deadlineMs,
            options: config.runner.options,
        },
        runnerCliPath: config.runnerCliPath,
        supervisorEpochId: config.supervisorEpochId,
        maxRestarts: config.maxRestarts,
        baseBackoffMs: config.baseBackoffMs,
        maxBackoffMs: config.maxBackoffMs,
        heartbeatIntervalMs: config.heartbeatIntervalMs,
        staleLockMs: config.staleLockMs,
        circuitWindowMs: config.circuitWindowMs,
    };
}

export function supervisorConfigFingerprint(input, options = {}) {
    const document = supervisorConfigDocument(input, options);
    return `sha256:crucible-supervisor-config-v1:${
        sha256Hex(Buffer.from(canonicalize(document), "utf8"))
    }`;
}

export function normalizeSupervisorConfig(input, options = {}) {
    rejectUnknownKeys(input, SUPERVISOR_KEYS, "supervisor config");
    const runner = normalizeRunnerConfig(requirePlainObject(input.runner, "runner"), options);
    if (runner.supervisorGeneration !== null
        || runner.supervisorNonce !== null
        || runner.runnerIncarnation !== null) {
        throw new RuntimeConfigError(
            "supervisor runner ownership is allocated at runtime and cannot be preconfigured",
        );
    }
    const runnerCliPath = requireLocalAbsolutePath(
        input.runnerCliPath ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "runner-cli.mjs"),
        "runnerCliPath",
        options.env ?? process.env,
    );
    const heartbeatIntervalMs = optionalPositiveInteger(
        input.heartbeatIntervalMs,
        "heartbeatIntervalMs",
        1_000,
        60 * 1000,
    );
    const staleLockMs = optionalPositiveInteger(
        input.staleLockMs,
        "staleLockMs",
        30_000,
        24 * 60 * 60 * 1000,
    );
    const baseBackoffMs = optionalPositiveInteger(
        input.baseBackoffMs,
        "baseBackoffMs",
        250,
        60 * 1000,
    );
    const maxBackoffMs = optionalPositiveInteger(
        input.maxBackoffMs,
        "maxBackoffMs",
        30_000,
        10 * 60 * 1000,
    );
    validateSupervisorTimingConstraints({
        heartbeatIntervalMs,
        staleLockMs,
        baseBackoffMs,
        maxBackoffMs,
    });
    return Object.freeze({
        runner,
        runnerCliPath,
        supervisorEpochId: input.supervisorEpochId === undefined
            ? `supervisor-${runner.runnerEpochId}`
            : requireLowerIdentifier(input.supervisorEpochId, "supervisorEpochId"),
        maxRestarts: input.maxRestarts === undefined
            ? 3
            : requireNonNegativeInteger(input.maxRestarts, "maxRestarts", 100),
        baseBackoffMs,
        maxBackoffMs,
        heartbeatIntervalMs,
        staleLockMs,
        circuitWindowMs: optionalPositiveInteger(
            input.circuitWindowMs,
            "circuitWindowMs",
            5 * 60 * 1000,
            24 * 60 * 60 * 1000,
        ),
        paths: supervisorPaths(runner.stateDir, runner.investigationId),
    });
}

export function loadSupervisorConfig(file, options) {
    return normalizeSupervisorConfig(readJsonFile(file, "supervisor config"), options);
}

export function coerceSupervisorConfig(input, options = {}) {
    if (input?.paths === undefined) {
        return normalizeSupervisorConfig(input, options);
    }
    return normalizeSupervisorConfig({
        runner: {
            investigationId: input.runner.investigationId,
            stateDir: input.runner.stateDir,
            artifactRoot: input.runner.artifactRoot,
            allowlistPath: input.runner.allowlistPath,
            copilotSdkPath: input.runner.sdkPath,
            copilotCliPath: input.runner.cliPath,
            runnerEpochId: input.runner.runnerEpochId,
            deadline: input.runner.deadlineMs,
            resultPath: input.runner.resultPath ?? undefined,
            options: input.runner.options,
        },
        runnerCliPath: input.runnerCliPath,
        supervisorEpochId: input.supervisorEpochId,
        maxRestarts: input.maxRestarts,
        baseBackoffMs: input.baseBackoffMs,
        maxBackoffMs: input.maxBackoffMs,
        heartbeatIntervalMs: input.heartbeatIntervalMs,
        staleLockMs: input.staleLockMs,
        circuitWindowMs: input.circuitWindowMs,
    }, options);
}
