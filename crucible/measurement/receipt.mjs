// crucible/measurement/receipt.mjs
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
//   - launchFileBindings   : identities/hashes of every pinned executable,
//                            dependency, and staged candidate file
//   - argvHash             : hash of the *concrete* argv passed to spawn
//   - envHash              : hash of the *concrete* env passed to spawn
//   - candidateSnapshotHash: hash of the immutable candidate snapshot
//   - candidateSnapshotPreClosureHash / PostClosureHash: exact on-disk
//     closure hashes surrounding execution
//   - candidateSnapshotIdentitySummary: stable root/directory/file identities
//     observed before and after execution
//   - candidateSnapshotMutationCheck: fail-closed post-run verification status
//   - stdoutHash / stderrHash: hashes of retained raw output bytes
//   - outputCapture        : per-stream cap, observed/retained byte totals, and
//                            overflow/truncation state
//   - parserVersion        : version tag of the parser that produced facts
//   - sandbox              : enforced capability/provider/full policy binding
//                            (including explicit Job limits) | null
//   - role / phase / replicateIndex / blockIndex / deterministicSeed /
//     subjectId / environmentIdentity / suiteIdentity: HarnessSuiteV4 binding
//   - attemptId / runnerEpochId: caller-supplied stable identifiers
//   - startedAt / completedAt / durationMs
//   - exit                 : { code | signal | timedOut }
//   - parsed               : the normalised harness result (facts)
//
// Physical staged-file identities and timing are intentionally per-run.
// Callers that need a strict input/output determinism check should project the
// receipt through RECEIPT_DETERMINISM_KEYS before hashing.

import {
    CANONICAL_HASH_ALGORITHM,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
} from "../domain/canonical.mjs";
import { normalizeHarnessResultBinding } from "./parser.mjs";

export const RECEIPT_HASH_ALGORITHM = "sha256:crucible-measurement-receipt-v1";
export const ARGV_HASH_ALGORITHM = "sha256:crucible-measurement-argv-v1";
export const ENV_HASH_ALGORITHM = "sha256:crucible-measurement-env-v1";
export const RECEIPT_VERSION = 5;
export const HARNESS_SUITE_RECEIPT_VERSION = 7;

const MEASUREMENT_BINDING_KEYS = Object.freeze([
    "role",
    "phase",
    "replicateIndex",
    "blockIndex",
    "armIndex",
    "armId",
    "deterministicSeed",
    "subjectId",
    "environmentIdentity",
    "suiteIdentity",
]);

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
    "stagedCandidateSnapshotHash",
    "stagedCandidateSnapshotClosureHash",
    "candidateSnapshotPreClosureHash",
    "candidateSnapshotPostClosureHash",
    "candidateSnapshotIdentitySummary",
    "candidateSnapshotMutationCheck",
    "stdoutHash",
    "stderrHash",
    "outputCapture",
    "parserVersion",
    "sandbox",
    "attemptId",
    "runnerEpochId",
    "exit",
    "parsed",
]);
export const HARNESS_SUITE_RECEIPT_DETERMINISM_KEYS = Object.freeze([
    ...RECEIPT_DETERMINISM_KEYS,
    ...MEASUREMENT_BINDING_KEYS,
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
    const keys = receipt?.version === HARNESS_SUITE_RECEIPT_VERSION
        ? HARNESS_SUITE_RECEIPT_DETERMINISM_KEYS
        : RECEIPT_DETERMINISM_KEYS;
    for (const key of keys) {
        if (Object.hasOwn(receipt, key)) {
            out[key] = receipt[key];
        }
    }
    return immutableCanonical(out);
}

function normalizeStreamCapture(value, field) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError(`${field} must be an object`);
    }
    const capBytes = value.capBytes;
    const totalObservedBytes = value.totalObservedBytes;
    const retainedBytes = value.retainedBytes;
    if (!Number.isSafeInteger(capBytes)
        || capBytes < 1
        || !Number.isSafeInteger(totalObservedBytes)
        || totalObservedBytes < 0
        || !Number.isSafeInteger(retainedBytes)
        || retainedBytes < 0
        || retainedBytes > capBytes
        || retainedBytes > totalObservedBytes) {
        throw new TypeError(`${field} byte counters are inconsistent`);
    }
    const overflowed = totalObservedBytes > capBytes;
    const truncated = retainedBytes < totalObservedBytes;
    if (value.overflowed !== overflowed || value.truncated !== truncated) {
        throw new TypeError(`${field} overflow/truncation state is inconsistent`);
    }
    return {
        capBytes,
        totalObservedBytes,
        retainedBytes,
        overflowed,
        truncated,
    };
}

function normalizeOutputCapture(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError("outputCapture must be an object");
    }
    const stdout = normalizeStreamCapture(value.stdout, "outputCapture.stdout");
    const stderr = normalizeStreamCapture(value.stderr, "outputCapture.stderr");
    const overflowed = stdout.overflowed || stderr.overflowed;
    const truncated = stdout.truncated || stderr.truncated;
    if (value.overflowed !== overflowed || value.truncated !== truncated) {
        throw new TypeError("outputCapture aggregate state is inconsistent");
    }
    return {
        stdout,
        stderr,
        overflowed,
        truncated,
    };
}

function pickMeasurementBinding(value) {
    if (value === null || value === undefined || typeof value !== "object") {
        return null;
    }
    const picked = {};
    let present = false;
    for (const key of MEASUREMENT_BINDING_KEYS) {
        const fieldValue = value[key];
        picked[key] = fieldValue ?? null;
        if (fieldValue !== undefined && fieldValue !== null) {
            present = true;
        }
    }
    return present ? picked : null;
}

function bindingEqual(left, right) {
    return MEASUREMENT_BINDING_KEYS.every((key) => left[key] === right[key]);
}

function normalizeReceiptBinding(input) {
    const candidates = [
        pickMeasurementBinding(input.measurementBinding),
        pickMeasurementBinding(input),
        pickMeasurementBinding(input.parsed),
    ].filter((value) => value !== null)
        .map((value) => normalizeHarnessResultBinding(value, {
            field: "measurement receipt binding",
            required: true,
        }));
    if (candidates.length === 0) return null;
    const binding = candidates[0];
    for (const candidate of candidates.slice(1)) {
        if (!bindingEqual(binding, candidate)) {
            throw new TypeError(
                "measurement receipt binding disagrees with the parsed harness result",
            );
        }
    }
    return binding;
}

// Build the receipt object. All hash-typed fields are algorithm-tagged
// SHA-256 strings. Timing fields are ISO strings + a numeric duration.
export function buildMeasurementReceipt(input) {
    const measurementBinding = normalizeReceiptBinding(input);
    const receipt = {
        version: measurementBinding === null
            ? RECEIPT_VERSION
            : HARNESS_SUITE_RECEIPT_VERSION,
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
        launchFileBindings: [...input.launchFileBindings].map((file) => ({
            path: file.path,
            role: file.role,
            sha256: file.sha256,
            identity: {
                dev: file.identity.dev,
                ino: file.identity.ino,
                size: file.identity.size,
                mode: file.identity.mode,
                mtimeNs: file.identity.mtimeNs,
                ctimeNs: file.identity.ctimeNs,
            },
        })).sort((a, b) => a.path.localeCompare(b.path)),
        argvHash: input.argvHash,
        envHash: input.envHash,
        candidateSnapshotHash: input.candidateSnapshotHash,
        stagedCandidateSnapshotHash: input.stagedCandidateSnapshotHash,
        stagedCandidateSnapshotClosureHash:
            input.stagedCandidateSnapshotClosureHash,
        stagedCandidateSnapshotIdentitySummary:
            input.stagedCandidateSnapshotIdentitySummary,
        candidateSnapshotPreClosureHash: input.candidateSnapshotPreClosureHash,
        candidateSnapshotPostClosureHash: input.candidateSnapshotPostClosureHash,
        candidateSnapshotIdentitySummary: input.candidateSnapshotIdentitySummary,
        candidateSnapshotMutationCheck: input.candidateSnapshotMutationCheck,
        stdoutHash: input.stdoutHash,
        stderrHash: input.stderrHash,
        outputCapture: normalizeOutputCapture(input.outputCapture),
        parserVersion: input.parserVersion,
        sandbox: input.sandbox === null
            ? null
            : {
                sandboxId: input.sandbox.sandboxId,
                environmentHash: input.sandbox.environmentHash,
                providerId: input.sandbox.providerId,
                providerVersion: input.sandbox.providerVersion,
                policyId: input.sandbox.policyId,
                policyDigest: input.sandbox.policyDigest,
                policyIdentity: input.sandbox.policyIdentity,
                policy: input.sandbox.policy,
                capabilityId: input.sandbox.capabilityId,
                launchPath: input.sandbox.launchPath,
                capabilityLaunchUsed: input.sandbox.capabilityLaunchUsed,
                permittedStagedRoots: [...input.sandbox.permittedStagedRoots],
            },
        ...(measurementBinding === null
            ? {}
            : {
                role: measurementBinding.role,
                phase: measurementBinding.phase,
                replicateIndex: measurementBinding.replicateIndex,
                blockIndex: measurementBinding.blockIndex,
                armIndex: measurementBinding.armIndex,
                armId: measurementBinding.armId,
                deterministicSeed: measurementBinding.deterministicSeed,
                subjectId: measurementBinding.subjectId,
                environmentIdentity: measurementBinding.environmentIdentity,
                suiteIdentity: measurementBinding.suiteIdentity,
            }),
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
