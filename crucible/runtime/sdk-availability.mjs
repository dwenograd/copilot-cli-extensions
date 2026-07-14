import path from "node:path";
import { pathToFileURL } from "node:url";

import { assertLocalDatabasePath } from "../persistence/paths.mjs";
import { RuntimeConfigError } from "./errors.mjs";

export const SDK_AVAILABILITY_CODES = Object.freeze({
    AVAILABLE: "SDK_AVAILABLE",
    AUTH_UNAVAILABLE: "SDK_AUTH_UNAVAILABLE",
    MODEL_UNAVAILABLE: "SDK_MODEL_UNAVAILABLE",
    PROBE_FAILED: "SDK_PROBE_FAILED",
});

function boundedTimeout(value, field, fallback, maximum) {
    const normalized = value ?? fallback;
    if (!Number.isSafeInteger(normalized)
        || normalized < 1
        || normalized > maximum) {
        throw new RuntimeConfigError(
            `${field} must be a positive integer <= ${maximum}`,
            { field, value: normalized },
        );
    }
    return normalized;
}

function normalizeModels(value) {
    if (!Array.isArray(value)) {
        throw new RuntimeConfigError("requiredModels must be an array");
    }
    const models = [...new Set(value.map((model, index) => {
        if (typeof model !== "string"
            || model.length < 1
            || model.length > 128
            || /[\u0000-\u001f\u007f]/u.test(model)) {
            throw new RuntimeConfigError(
                `requiredModels[${index}] is invalid`,
            );
        }
        return model;
    }))].sort();
    return Object.freeze(models);
}

async function within(promiseFactory, timeoutMs, label, timers = globalThis) {
    let timeout = null;
    try {
        return await Promise.race([
            Promise.resolve().then(promiseFactory),
            new Promise((_, reject) => {
                timeout = timers.setTimeout(() => {
                    reject(new RuntimeConfigError(
                        `${label} exceeded its noninteractive timeout`,
                        { timeoutMs },
                    ));
                }, timeoutMs);
            }),
        ]);
    } finally {
        if (timeout !== null) timers.clearTimeout(timeout);
    }
}

async function defaultSdkLoader(sdkPath) {
    return import(pathToFileURL(path.join(sdkPath, "index.js")).href);
}

function localPath(value, field, env) {
    if (typeof value !== "string" || !path.isAbsolute(value)) {
        throw new RuntimeConfigError(`${field} must be an absolute path`);
    }
    return assertLocalDatabasePath(path.resolve(value), { env });
}

export async function probeNoninteractiveSdkAvailability({
    sdkPath,
    cliPath,
    workingDirectory,
    requiredModels = [],
    startupTimeoutMs = 15_000,
    shutdownTimeoutMs = 5_000,
    env = process.env,
} = {}, dependencies = {}) {
    const localSdkPath = localPath(sdkPath, "sdkPath", env);
    const localCliPath = localPath(cliPath, "cliPath", env);
    const localWorkingDirectory = localPath(
        workingDirectory,
        "workingDirectory",
        env,
    );
    const models = normalizeModels(requiredModels);
    const startupTimeout = boundedTimeout(
        startupTimeoutMs,
        "startupTimeoutMs",
        15_000,
        60_000,
    );
    const shutdownTimeout = boundedTimeout(
        shutdownTimeoutMs,
        "shutdownTimeoutMs",
        5_000,
        30_000,
    );
    const timers = dependencies.timers ?? globalThis;
    const sdkLoader = dependencies.sdkLoader ?? defaultSdkLoader;
    let client = null;
    try {
        const sdk = await within(
            () => sdkLoader(localSdkPath),
            startupTimeout,
            "Copilot SDK module load",
            timers,
        );
        const { CopilotClient, RuntimeConnection } = sdk ?? {};
        if (typeof CopilotClient !== "function"
            || typeof RuntimeConnection?.forStdio !== "function") {
            throw new RuntimeConfigError(
                "COPILOT_SDK_PATH does not export CopilotClient and RuntimeConnection",
            );
        }
        const clientOptions = {
            connection: RuntimeConnection.forStdio({ path: localCliPath }),
            mode: "empty",
            workingDirectory: localWorkingDirectory,
            logLevel: "error",
            useLoggedInUser: true,
        };
        client = dependencies.clientFactory === undefined
            ? new CopilotClient(clientOptions)
            : await dependencies.clientFactory({
                CopilotClient,
                RuntimeConnection,
                clientOptions,
            });
        if (typeof client?.start !== "function"
            || typeof client.getAuthStatus !== "function"
            || typeof client.listModels !== "function"
            || typeof client.stop !== "function"
            || typeof client.forceStop !== "function") {
            throw new RuntimeConfigError(
                "Copilot SDK client does not expose the noninteractive probe API",
            );
        }
        await within(
            () => client.start(),
            startupTimeout,
            "Copilot SDK startup",
            timers,
        );
        const auth = await within(
            () => client.getAuthStatus(),
            startupTimeout,
            "Copilot SDK authentication probe",
            timers,
        );
        if (auth?.isAuthenticated !== true) {
            return Object.freeze({
                ok: false,
                code: SDK_AVAILABILITY_CODES.AUTH_UNAVAILABLE,
                authenticated: false,
                requiredModelCount: models.length,
                availableModelCount: 0,
                missingModels: models,
            });
        }
        const available = await within(
            () => client.listModels(),
            startupTimeout,
            "Copilot SDK model probe",
            timers,
        );
        if (!Array.isArray(available)) {
            throw new RuntimeConfigError(
                "Copilot SDK model probe did not return an array",
            );
        }
        const availableIds = new Set(available
            .map((model) => model?.id)
            .filter((id) => typeof id === "string" && id.length > 0));
        const missingModels = models.filter((model) => !availableIds.has(model));
        return Object.freeze({
            ok: missingModels.length === 0,
            code: missingModels.length === 0
                ? SDK_AVAILABILITY_CODES.AVAILABLE
                : SDK_AVAILABILITY_CODES.MODEL_UNAVAILABLE,
            authenticated: true,
            requiredModelCount: models.length,
            availableModelCount: availableIds.size,
            missingModels: Object.freeze(missingModels),
        });
    } catch (error) {
        return Object.freeze({
            ok: false,
            code: SDK_AVAILABILITY_CODES.PROBE_FAILED,
            authenticated: false,
            requiredModelCount: models.length,
            availableModelCount: 0,
            missingModels: models,
            errorCode: error?.code ?? null,
        });
    } finally {
        if (client !== null) {
            try {
                const cleanupErrors = await within(
                    () => client.stop(),
                    shutdownTimeout,
                    "Copilot SDK probe shutdown",
                    timers,
                );
                if (Array.isArray(cleanupErrors)
                    && cleanupErrors.length > 0) {
                    throw new Error(
                        "Copilot SDK probe shutdown reported cleanup failures",
                    );
                }
            } catch {
                try {
                    await within(
                        () => client.forceStop(),
                        shutdownTimeout,
                        "Copilot SDK probe forced shutdown",
                        timers,
                    );
                } catch {
                    // The caller records the probe failure without exposing credentials.
                }
            }
        }
    }
}
