// crucible/measurement/sandbox.mjs
//
// SandboxProvider is the *interface only* between the measurement executor
// and whatever real isolation mechanism the operator wires up (WSL2 rootfs,
// Windows AppContainer / Job Object, Docker with a dropped-privileges
// profile, etc.). This module contains NO implementation of a sandbox —
// pretending that cwd/env/timeout is a sandbox would be a lie, and the
// executor already provides those in every run whether or not a sandbox
// is present.
//
// A SandboxProvider is any object with:
//
//   admitAndPrepare(verifiedEntry, candidateSnapshot) => Admission
//
// where Admission is one of:
//
//   { admitted: false, reason: string }
//     — the sandbox refuses to accept this run (unsupported harness,
//       unsupported snapshot layout, out of capacity, policy denial, ...).
//       The executor MUST NOT run the harness and MUST throw a typed
//       SandboxRefusedError to the caller.
//
//   { admitted: true, sandboxId: string, environmentHash: string,
//     wrap?: { executable: string, argvPrefix: string[] } }
//     — the sandbox admits the run. `sandboxId` and `environmentHash` are
//       recorded in the receipt so that a later verifier can decide
//       whether *that specific* sandbox+environment is trusted. The current
//       executor refuses `wrap` because a wrapper would itself need the same
//       handle-bound staging contract. Providers should enforce isolation via
//       the injected process adapter until pinned wrapper staging is defined.
//
// Callers who do NOT supply a SandboxProvider get fail-closed behaviour
// against entries with executesCandidateCode=true: SANDBOX_REQUIRED.

import {
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
} from "./errors.mjs";

const SANDBOX_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const HASH_TAG = /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;

// Normalise + validate an admission returned by a SandboxProvider. Called
// by the executor before it commits to the run. Any deviation from the
// documented shape produces a SANDBOX_MALFORMED error — better to refuse
// than to guess a well-meaning provider's intent.
export function normalizeAdmission(admission) {
    if (admission === null
        || typeof admission !== "object"
        || Array.isArray(admission)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.SANDBOX_MALFORMED,
            "SandboxProvider admission must be an object",
        );
    }
    if (admission.admitted === false) {
        const reason = typeof admission.reason === "string" && admission.reason.length > 0
            ? admission.reason
            : "sandbox refused with no reason";
        return Object.freeze({ admitted: false, reason });
    }
    if (admission.admitted !== true) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.SANDBOX_MALFORMED,
            "SandboxProvider admission.admitted must be true or false",
        );
    }
    if (typeof admission.sandboxId !== "string" || !SANDBOX_ID.test(admission.sandboxId)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.SANDBOX_MALFORMED,
            "SandboxProvider admission.sandboxId is not a safe id",
        );
    }
    if (typeof admission.environmentHash !== "string" || !HASH_TAG.test(admission.environmentHash)) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.SANDBOX_MALFORMED,
            "SandboxProvider admission.environmentHash must be an algorithm-tagged SHA-256",
        );
    }
    let wrap = null;
    if (admission.wrap !== undefined && admission.wrap !== null) {
        if (typeof admission.wrap !== "object" || Array.isArray(admission.wrap)) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SANDBOX_MALFORMED,
                "SandboxProvider admission.wrap must be an object",
            );
        }
        if (typeof admission.wrap.executable !== "string" || admission.wrap.executable.length === 0) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SANDBOX_MALFORMED,
                "SandboxProvider admission.wrap.executable must be a non-empty string",
            );
        }
        if (!Array.isArray(admission.wrap.argvPrefix)) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.SANDBOX_MALFORMED,
                "SandboxProvider admission.wrap.argvPrefix must be an array",
            );
        }
        for (let i = 0; i < admission.wrap.argvPrefix.length; i += 1) {
            const item = admission.wrap.argvPrefix[i];
            if (typeof item !== "string") {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.SANDBOX_MALFORMED,
                    `SandboxProvider admission.wrap.argvPrefix[${i}] must be a string`,
                );
            }
        }
        wrap = Object.freeze({
            executable: admission.wrap.executable,
            argvPrefix: Object.freeze([...admission.wrap.argvPrefix]),
        });
    }
    return Object.freeze({
        admitted: true,
        sandboxId: admission.sandboxId,
        environmentHash: admission.environmentHash,
        wrap,
    });
}
