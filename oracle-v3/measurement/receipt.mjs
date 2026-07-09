// oracle-v3/measurement/receipt.mjs
//
// A measurement receipt is the tamper-evident record of one attempt to run
// a harness inside the trusted boundary. It contains every input that
// determined the run's outcome, canonically hashed:
//
//   - allowlistFileHash    : hash of the on-disk allowlist file at load
//   - harnessEntryHash     : hash of the (canonical) allowlist entry object
//   - executableHash / dependencyHashes: verified source-file hashes
//   - stagedExecutableHash / stagedDependencyHashes: re-hashes of the exact
//     private copies used for execution
//   - argvHash             : hash of the *concrete* argv passed to spawn
//   - envHash              : hash of the *concrete* env passed to spawn
//   - candidateSnapshotHash: hash of the immutable candidate snapshot
//   - stdoutHash / stderrHash: hashes of raw output bytes actually captured
//   - parserVersion        : version tag of the parser that produced facts
//   - sandbox              : { sandboxId, environmentHash } | null
//   - attemptId / runnerEpochId: caller-supplied stable identifiers
//   - startedAt / completedAt / durationMs
//   - exit                 : { code | signal | timedOut }
//   - parsed               : the normalised harness result (facts)
//
// Two runs with identical inputs (same entry, same snapshot, same env, same
// attemptId, same epoch, same wall-time) produce byte-identical receipts.
// Callers that need a strict determinism check should elide the timing
// fields (startedAt/completedAt/durationMs) before hashing; the module
// exposes RECEIPT_DETERMINISM_KEYS for that purpose.

import {
    CANONICAL_HASH_ALGORITHM,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
} from "../domain/canonical.mjs";

export const RECEIPT_HASH_ALGORITHM = "sha256:oracle-measurement-receipt-v1";
export const ARGV_HASH_ALGORITHM = "sha256:oracle-measurement-argv-v1";
export const ENV_HASH_ALGORITHM = "sha256:oracle-measurement-env-v1";
export const RECEIPT_VERSION = 2;

// Keys within the receipt that are input-derived (deterministic given the
// same inputs). Timing fields are excluded so callers can prove determinism
// across two runs that happened to take different wall-clock durations.
export const RECEIPT_DETERMINISM_KEYS = Object.freeze([
    "version",
    "allowlistFileHash",
    "harnessEntryHash",
    "executableHash",
    "stagedExecutableHash",
    "dependencyHashes",
    "stagedDependencyHashes",
    "argvHash",
    "envHash",
    "candidateSnapshotHash",
    "stdoutHash",
    "stderrHash",
    "parserVersion",
    "sandbox",
    "attemptId",
    "runnerEpochId",
    "exit",
    "parsed",
]);

export function hashArgv(argv) {
    return hashCanonical(argv, ARGV_HASH_ALGORITHM);
}

export function hashEnv(env) {
    // Canonicalise env by key. `env` is a plain object at this point (the
    // executor built it from the entry's allowedEnv, sorted by key).
    return hashCanonical(env, ENV_HASH_ALGORITHM);
}

export function hashReceipt(receipt) {
    return hashCanonical(receipt, RECEIPT_HASH_ALGORITHM);
}

// Extract the deterministic subset of a receipt (used by tests and by
// external verifiers who want to compare two runs modulo timing).
export function projectDeterministicReceipt(receipt) {
    const out = {};
    for (const key of RECEIPT_DETERMINISM_KEYS) {
        if (Object.hasOwn(receipt, key)) {
            out[key] = receipt[key];
        }
    }
    return immutableCanonical(out);
}

// Build the receipt object. All hash-typed fields are algorithm-tagged
// SHA-256 strings. Timing fields are ISO strings + a numeric duration.
export function buildMeasurementReceipt(input) {
    const receipt = {
        version: RECEIPT_VERSION,
        allowlistFileHash: input.allowlistFileHash,
        harnessEntryHash: input.harnessEntryHash,
        executableHash: input.executableHash,
        stagedExecutableHash: input.stagedExecutableHash,
        dependencyHashes: [...input.dependencyHashes].map((d) => ({
            path: d.path,
            role: d.role,
            sha256: d.sha256,
        })).sort((a, b) => a.path.localeCompare(b.path)),
        stagedDependencyHashes: [...input.stagedDependencyHashes].map((d) => ({
            path: d.path,
            role: d.role,
            sha256: d.sha256,
        })).sort((a, b) => a.path.localeCompare(b.path)),
        argvHash: input.argvHash,
        envHash: input.envHash,
        candidateSnapshotHash: input.candidateSnapshotHash,
        stdoutHash: input.stdoutHash,
        stderrHash: input.stderrHash,
        parserVersion: input.parserVersion,
        sandbox: input.sandbox === null
            ? null
            : {
                sandboxId: input.sandbox.sandboxId,
                environmentHash: input.sandbox.environmentHash,
            },
        attemptId: input.attemptId,
        runnerEpochId: input.runnerEpochId,
        startedAt: input.startedAt,
        completedAt: input.completedAt,
        durationMs: input.durationMs,
        exit: {
            code: input.exit.code,
            signal: input.exit.signal,
            timedOut: input.exit.timedOut,
        },
        parsed: input.parsed,
    };
    return immutableCanonical(receipt);
}

// Convenience: canonical-JSON serialisation with a stable per-domain tag.
export function canonicalizeReceipt(receipt) {
    // Use the domain's own canonical hash tag for the outer serialisation
    // check when needed. Kept separate from receipt-hash: the receipt hash
    // is what identifies THIS receipt across runs; the canonical form is
    // the bytes-on-the-wire representation.
    return canonicalJson(receipt);
}

export { CANONICAL_HASH_ALGORITHM };
