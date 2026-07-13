import {
    RUNTIME_ERROR_CODES,
    RuntimeConfigError,
    isRecoverableRuntimeError,
} from "./errors.mjs";
import { isPlainObject } from "./utils.mjs";

const SUCCESS_STATES = new Set([
    "terminal",
    "non_result",
    "pause",
    "quiesced",
]);

function codeOrNull(value) {
    return typeof value === "string" && value.length > 0 ? value : null;
}

export function projectRunnerOutcome(result) {
    let state;
    let terminalAvailable = false;
    let nonResultCode = null;
    switch (result?.kind) {
        case "TERMINAL":
            state = "terminal";
            terminalAvailable = true;
            break;
        case "NON_RESULT":
            state = "non_result";
            nonResultCode = codeOrNull(result.code) ?? "CRUCIBLE_RUNTIME_NON_RESULT";
            break;
        case "PAUSE":
            state = "pause";
            nonResultCode = codeOrNull(result.code) ?? "INVESTIGATION_PAUSED";
            break;
        case "QUIESCED":
            state = "quiesced";
            nonResultCode = codeOrNull(result.code) ?? "INVESTIGATION_PAUSED";
            break;
        default:
            throw new RuntimeConfigError("Runner returned an unsupported opaque outcome", {
                kind: result?.kind ?? null,
            });
    }
    return Object.freeze({
        version: 1,
        ok: true,
        state,
        terminal_available: terminalAvailable,
        non_result_code: nonResultCode,
    });
}

export function projectRunnerFailure(error) {
    return Object.freeze({
        version: 1,
        ok: false,
        state: "failed",
        terminal_available: false,
        non_result_code: codeOrNull(error?.code) ?? RUNTIME_ERROR_CODES.RUNTIME_FAILURE,
        recoverable: isRecoverableRuntimeError(error),
    });
}

export function normalizeRunnerOutcomeEnvelope(value) {
    if (!isPlainObject(value)
        || value.version !== 1
        || typeof value.ok !== "boolean"
        || typeof value.state !== "string"
        || typeof value.terminal_available !== "boolean"
        || !(value.non_result_code === null
            || (typeof value.non_result_code === "string"
                && value.non_result_code.length > 0))) {
        throw new RuntimeConfigError("Runner outcome envelope is malformed");
    }
    const expectedKeys = value.ok
        ? ["non_result_code", "ok", "state", "terminal_available", "version"]
        : [
            "non_result_code",
            "ok",
            "recoverable",
            "state",
            "terminal_available",
            "version",
        ];
    const actualKeys = Object.keys(value).sort();
    if (actualKeys.length !== expectedKeys.length
        || actualKeys.some((key, index) => key !== expectedKeys[index])) {
        throw new RuntimeConfigError("Runner outcome envelope contains non-opaque fields");
    }
    if (value.ok) {
        if (!SUCCESS_STATES.has(value.state)
            || value.terminal_available !== (value.state === "terminal")
            || (value.state === "terminal" && value.non_result_code !== null)
            || (value.state !== "terminal" && value.non_result_code === null)
            || Object.hasOwn(value, "recoverable")) {
            throw new RuntimeConfigError("Runner success outcome is inconsistent");
        }
    } else if (value.state !== "failed"
        || value.terminal_available
        || value.non_result_code === null
        || typeof value.recoverable !== "boolean") {
        throw new RuntimeConfigError("Runner failure outcome is inconsistent");
    }
    return Object.freeze({
        version: 1,
        ok: value.ok,
        state: value.state,
        terminal_available: value.terminal_available,
        non_result_code: value.non_result_code,
        ...(value.ok ? {} : { recoverable: value.recoverable }),
    });
}
