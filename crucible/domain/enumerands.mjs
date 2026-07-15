import {
    canonicalEqual,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import { CONTRACT_LIMITS } from "./constants.mjs";
import { ContractError } from "./errors.mjs";
import { normalizeHypotheses } from "./hypotheses.mjs";

export const ENUMERAND_MANIFEST_VERSION = "crucible-enumerand-manifest-v1";
export const ENUMERAND_PARAMETER_TUPLE_HASH_ALGORITHM =
    "sha256:crucible-enumerand-parameter-tuple-v1";
export const ENUMERAND_IDENTITY_HASH_ALGORITHM =
    "sha256:crucible-enumerand-identity-v1";
export const ENUMERAND_LEAF_HASH_ALGORITHM =
    "sha256:crucible-enumerand-leaf-v1";
export const ENUMERAND_NODE_HASH_ALGORITHM =
    "sha256:crucible-enumerand-node-v1";
export const ENUMERAND_MANIFEST_ROOT_HASH_ALGORITHM =
    "sha256:crucible-enumerand-manifest-root-v1";
export const ENUMERAND_BINDING_HASH_ALGORITHM =
    "sha256:crucible-enumerand-binding-v1";
export const ENUMERAND_COVERAGE_HASH_ALGORITHM =
    "sha256:crucible-enumerand-coverage-v1";
export const ENUMERAND_EXHAUSTION_HASH_ALGORITHM =
    "sha256:crucible-enumerand-exhaustion-v1";

const MANIFEST_TOPOLOGIES = Object.freeze([
    "finite_enumerable",
    "bounded_parameterized",
]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;
const SNAPSHOT_HASH = /^sha256:[a-f0-9]{64}$/u;
const MAX_PARAMETER_TUPLE_BYTES = 16 * 1024;
const MAX_PARAMETER_TUPLE_ITEMS = 128;
const MAX_PARAMETER_TUPLE_DEPTH = 16;
const MAX_PARAMETER_TUPLE_NODES = 1024;
const MAX_PARAMETER_OBJECT_PROPERTIES = 128;

function fail(message, details = null) {
    throw new ContractError(message, details);
}

function requirePlainObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)) {
        fail(`${field} must be a plain object`, { field });
    }
    return value;
}

function requireExactKeys(value, field, required, optional = []) {
    requirePlainObject(value, field);
    const requiredSet = new Set(required);
    const allowed = new Set([...required, ...optional]);
    const actual = Object.keys(value);
    const missing = required.filter((key) => !Object.hasOwn(value, key));
    const unknown = actual.filter((key) => !allowed.has(key));
    if (missing.length > 0 || unknown.length > 0) {
        fail(`${field} must contain exactly the canonical fields`, {
            field,
            missing,
            unknown,
            required: [...requiredSet],
            optional,
        });
    }
}

function requireIdentifier(value, field) {
    if (typeof value !== "string"
        || !IDENTIFIER.test(value)
        || value === "."
        || value === ".."
        || value.includes("..")) {
        fail(`${field} must be a safe identifier`, { field, value });
    }
    return value;
}

function requireOrdinal(value, field) {
    if (!Number.isSafeInteger(value)
        || value < 0
        || value >= CONTRACT_LIMITS.boundedCandidateIds) {
        fail(
            `${field} must be a non-negative safe integer below `
                + CONTRACT_LIMITS.boundedCandidateIds,
            { field, value },
        );
    }
    return value;
}

function requireSnapshotHash(value, field) {
    if (typeof value !== "string" || !SNAPSHOT_HASH.test(value)) {
        fail(`${field} must be a content-addressed artifact snapshot hash`, {
            field,
            value,
        });
    }
    return value;
}

function requireTaggedHash(value, field) {
    if (!isAlgorithmTaggedSha256(value)) {
        fail(`${field} must be an algorithm-tagged SHA-256 hash`, {
            field,
            value,
        });
    }
    return value;
}

function requireReferenceHash(value, field) {
    if (typeof value !== "string"
        || (!SNAPSHOT_HASH.test(value) && !isAlgorithmTaggedSha256(value))) {
        fail(
            `${field} must be a content-addressed snapshot or algorithm-tagged SHA-256 hash`,
            { field, value },
        );
    }
    return value;
}

function topologyOf(value, field = "topology") {
    if (!MANIFEST_TOPOLOGIES.includes(value)) {
        fail(`${field} must be finite_enumerable or bounded_parameterized`, {
            field,
            value,
        });
    }
    return value;
}

export function normalizeParameterTuple(value, field = "parameterTuple") {
    if (!Array.isArray(value) || value.length > MAX_PARAMETER_TUPLE_ITEMS) {
        fail(
            `${field} must be a canonical JSON tuple with at most `
                + MAX_PARAMETER_TUPLE_ITEMS
                + " items",
            { field },
        );
    }
    const stack = value.map((item, index) => ({
        value: item,
        path: `${field}[${index}]`,
        depth: 1,
    }));
    let nodes = 1;
    while (stack.length > 0) {
        const current = stack.pop();
        nodes += 1;
        if (nodes > MAX_PARAMETER_TUPLE_NODES) {
            fail(`${field} exceeds the canonical node bound`, {
                field,
                maximumNodes: MAX_PARAMETER_TUPLE_NODES,
            });
        }
        if (current.depth > MAX_PARAMETER_TUPLE_DEPTH) {
            fail(`${field} exceeds the canonical depth bound`, {
                field,
                maximumDepth: MAX_PARAMETER_TUPLE_DEPTH,
            });
        }
        if (current.value === null
            || typeof current.value === "string"
            || typeof current.value === "boolean") {
            continue;
        }
        if (typeof current.value === "number") {
            if (!Number.isFinite(current.value)) {
                fail(`${current.path} must be a finite number`, {
                    field: current.path,
                });
            }
            continue;
        }
        if (typeof current.value !== "object") {
            fail(`${current.path} is not a canonical JSON value`, {
                field: current.path,
            });
        }
        if (Array.isArray(current.value)) {
            if (current.value.length > MAX_PARAMETER_TUPLE_ITEMS) {
                fail(`${current.path} exceeds the array item bound`, {
                    field: current.path,
                    maximumItems: MAX_PARAMETER_TUPLE_ITEMS,
                });
            }
            for (let index = 0; index < current.value.length; index += 1) {
                if (!Object.hasOwn(current.value, index)) {
                    fail(`${current.path} must not contain sparse array slots`, {
                        field: current.path,
                    });
                }
                stack.push({
                    value: current.value[index],
                    path: `${current.path}[${index}]`,
                    depth: current.depth + 1,
                });
            }
            continue;
        }
        const prototype = Object.getPrototypeOf(current.value);
        if (prototype !== Object.prototype && prototype !== null) {
            fail(`${current.path} must be a plain object`, {
                field: current.path,
            });
        }
        if (Object.getOwnPropertySymbols(current.value).length > 0) {
            fail(`${current.path} must not contain symbol keys`, {
                field: current.path,
            });
        }
        const keys = Object.keys(current.value);
        if (keys.length > MAX_PARAMETER_OBJECT_PROPERTIES) {
            fail(`${current.path} exceeds the object property bound`, {
                field: current.path,
                maximumProperties: MAX_PARAMETER_OBJECT_PROPERTIES,
            });
        }
        for (const key of keys) {
            const descriptor = Object.getOwnPropertyDescriptor(current.value, key);
            if (!descriptor || !Object.hasOwn(descriptor, "value")) {
                fail(`${current.path}.${key} must be a data property`, {
                    field: `${current.path}.${key}`,
                });
            }
            stack.push({
                value: descriptor.value,
                path: `${current.path}.${key}`,
                depth: current.depth + 1,
            });
        }
    }
    let normalized;
    try {
        normalized = JSON.parse(canonicalJson(value));
    } catch (error) {
        fail(`${field} must contain only canonical JSON values`, {
            field,
            cause: error?.message ?? String(error),
        });
    }
    const bytes = Buffer.byteLength(canonicalJson(normalized), "utf8");
    if (bytes > MAX_PARAMETER_TUPLE_BYTES) {
        fail(`${field} exceeds the canonical byte bound`, {
            field,
            bytes,
            maximumBytes: MAX_PARAMETER_TUPLE_BYTES,
        });
    }
    return immutableCanonical(normalized);
}

export function parameterTupleHash(tuple) {
    return hashCanonical(
        normalizeParameterTuple(tuple),
        ENUMERAND_PARAMETER_TUPLE_HASH_ALGORITHM,
    );
}

function entryContentHash(entry, topology) {
    return topology === "finite_enumerable"
        ? entry.artifactSnapshotHash
        : entry.parameterTupleHash;
}

function computedEnumerandHash({ topology, ordinal, contentHash }) {
    return hashCanonical({
        topology,
        ordinal,
        contentHash,
    }, ENUMERAND_IDENTITY_HASH_ALGORITHM);
}

function normalizeEntry(input, topology, field, options = {}) {
    const finite = topology === "finite_enumerable";
    requireExactKeys(
        input,
        field,
        finite
            ? ["artifactSnapshotHash", "id", "ordinal"]
            : ["id", "ordinal", "parameterTuple"],
        finite
            ? ["enumerandHash", "hypotheses"]
            : ["enumerandHash", "hypotheses", "parameterTupleHash"],
    );
    const id = requireIdentifier(input.id, `${field}.id`);
    const ordinal = requireOrdinal(input.ordinal, `${field}.ordinal`);
    const hypotheses = normalizeHypotheses(input.hypotheses, {
        observableRegistry: options.observableRegistry ?? [],
        hypothesisPolicy: options.hypothesisPolicy ?? {},
        assignedParentEvidenceIds: [],
    });
    if (finite) {
        const artifactSnapshotHash = requireSnapshotHash(
            input.artifactSnapshotHash,
            `${field}.artifactSnapshotHash`,
        );
        const enumerandHash = computedEnumerandHash({
            topology,
            ordinal,
            contentHash: artifactSnapshotHash,
        });
        if (input.enumerandHash !== undefined
            && requireTaggedHash(input.enumerandHash, `${field}.enumerandHash`)
                !== enumerandHash) {
            fail(`${field}.enumerandHash does not match the frozen artifact and ordinal`, {
                field,
                expected: enumerandHash,
                actual: input.enumerandHash,
            });
        }
        return immutableCanonical({
            id,
            ordinal,
            artifactSnapshotHash,
            enumerandHash,
            ...(hypotheses === null ? {} : { hypotheses }),
        });
    }

    const tuple = normalizeParameterTuple(
        input.parameterTuple,
        `${field}.parameterTuple`,
    );
    const tupleHash = parameterTupleHash(tuple);
    if (input.parameterTupleHash !== undefined
        && requireTaggedHash(
            input.parameterTupleHash,
            `${field}.parameterTupleHash`,
        ) !== tupleHash) {
        fail(`${field}.parameterTupleHash does not match parameterTuple`, {
            field,
            expected: tupleHash,
            actual: input.parameterTupleHash,
        });
    }
    const enumerandHash = computedEnumerandHash({
        topology,
        ordinal,
        contentHash: tupleHash,
    });
    if (input.enumerandHash !== undefined
        && requireTaggedHash(input.enumerandHash, `${field}.enumerandHash`)
            !== enumerandHash) {
        fail(`${field}.enumerandHash does not match the frozen tuple and ordinal`, {
            field,
            expected: enumerandHash,
            actual: input.enumerandHash,
        });
    }
    return immutableCanonical({
        id,
        ordinal,
        parameterTuple: tuple,
        parameterTupleHash: tupleHash,
        enumerandHash,
        ...(hypotheses === null ? {} : { hypotheses }),
    });
}

function normalizeEntries(value, topology, options = {}) {
    if (!Array.isArray(value)
        || value.length < 1
        || value.length > CONTRACT_LIMITS.boundedCandidateIds) {
        fail(
            `enumerand manifest entries must contain 1..`
                + CONTRACT_LIMITS.boundedCandidateIds
                + " items",
        );
    }
    const normalized = value
        .map((entry, index) =>
            normalizeEntry(entry, topology, `entries[${index}]`, options))
        .sort((left, right) =>
            left.ordinal - right.ordinal
            || left.id.localeCompare(right.id, "en-US"));

    const ids = new Set();
    const ordinals = new Set();
    const contentHashes = new Set();
    for (const [index, entry] of normalized.entries()) {
        if (ids.has(entry.id)) {
            fail("enumerand manifest ids must be unique", { id: entry.id });
        }
        if (ordinals.has(entry.ordinal)) {
            fail("enumerand manifest ordinals must be unique", {
                ordinal: entry.ordinal,
            });
        }
        const contentHash = entryContentHash(entry, topology);
        if (contentHashes.has(contentHash)) {
            fail(
                topology === "finite_enumerable"
                    ? "finite enumerand artifact snapshots must be unique"
                    : "bounded enumerand parameter tuples must be unique",
                { contentHash },
            );
        }
        if (entry.ordinal !== index) {
            fail("enumerand manifest ordinals must be contiguous from zero", {
                expectedOrdinal: index,
                actualOrdinal: entry.ordinal,
            });
        }
        ids.add(entry.id);
        ordinals.add(entry.ordinal);
        contentHashes.add(contentHash);
    }
    return immutableCanonical(normalized);
}

function normalizeControl(input, entries) {
    requirePlainObject(input, "control");
    if (input.kind === "enumerand") {
        requireExactKeys(
            input,
            "control",
            ["kind", "ordinal"],
            ["enumerandHash"],
        );
        const ordinal = requireOrdinal(input.ordinal, "control.ordinal");
        const entry = entries[ordinal];
        if (entry === undefined || entry.ordinal !== ordinal) {
            fail("control enumerand ordinal is outside the manifest", {
                ordinal,
            });
        }
        if (input.enumerandHash !== undefined
            && requireTaggedHash(input.enumerandHash, "control.enumerandHash")
                !== entry.enumerandHash) {
            fail("control enumerand hash does not match its manifest entry", {
                ordinal,
                expected: entry.enumerandHash,
                actual: input.enumerandHash,
            });
        }
        return immutableCanonical({
            kind: "enumerand",
            ordinal,
            enumerandHash: entry.enumerandHash,
        });
    }
    if (input.kind === "reference") {
        requireExactKeys(input, "control", ["kind", "referenceHash"]);
        return immutableCanonical({
            kind: "reference",
            referenceHash: requireReferenceHash(
                input.referenceHash,
                "control.referenceHash",
            ),
        });
    }
    fail("control.kind must be enumerand or reference", {
        kind: input.kind,
    });
}

function merkleTreeRoot(topology, entries) {
    let level = entries.map((entry) =>
        hashCanonical({
            version: ENUMERAND_MANIFEST_VERSION,
            topology,
            entry,
        }, ENUMERAND_LEAF_HASH_ALGORITHM));
    while (level.length > 1) {
        const next = [];
        for (let index = 0; index < level.length; index += 2) {
            const left = level[index];
            const right = level[index + 1] ?? left;
            next.push(hashCanonical({ left, right }, ENUMERAND_NODE_HASH_ALGORITHM));
        }
        level = next;
    }
    return level[0];
}

function manifestRoot(topology, entries, control) {
    return hashCanonical({
        version: ENUMERAND_MANIFEST_VERSION,
        topology,
        entryCount: entries.length,
        treeRoot: merkleTreeRoot(topology, entries),
        control,
    }, ENUMERAND_MANIFEST_ROOT_HASH_ALGORITHM);
}

export function normalizeEnumerandManifest(input, options = {}) {
    requireExactKeys(
        input,
        "enumerandManifest",
        ["control", "entries", "topology"],
        ["merkleRoot", "version"],
    );
    if (input.version !== undefined
        && input.version !== ENUMERAND_MANIFEST_VERSION) {
        fail("enumerand manifest version is unsupported", {
            expected: ENUMERAND_MANIFEST_VERSION,
            actual: input.version,
        });
    }
    const topology = topologyOf(input.topology, "enumerandManifest.topology");
    if (options.topology !== undefined
        && topologyOf(options.topology, "options.topology") !== topology) {
        fail("enumerand manifest topology does not match its contract", {
            manifestTopology: topology,
            contractTopology: options.topology,
        });
    }
    const entries = normalizeEntries(input.entries, topology, options);
    const control = normalizeControl(input.control, entries);
    const merkleRoot = manifestRoot(topology, entries, control);
    if (input.merkleRoot !== undefined
        && requireTaggedHash(input.merkleRoot, "enumerandManifest.merkleRoot")
            !== merkleRoot) {
        fail("enumerand manifest Merkle root does not match its canonical contents", {
            expected: merkleRoot,
            actual: input.merkleRoot,
        });
    }
    return immutableCanonical({
        version: ENUMERAND_MANIFEST_VERSION,
        topology,
        entries,
        control,
        merkleRoot,
    });
}

export function enumerandIdentity(entry, topology, options = {}) {
    const normalizedTopology = topologyOf(topology);
    const normalized = normalizeEntry(
        entry,
        normalizedTopology,
        "enumerand",
        options,
    );
    return immutableCanonical({
        ordinal: normalized.ordinal,
        contentHash: entryContentHash(normalized, normalizedTopology),
        enumerandHash: normalized.enumerandHash,
    });
}

export function enumerandBinding(manifest, entryOrOrdinal, options = {}) {
    const normalizedManifest = normalizeEnumerandManifest(manifest, options);
    const entry = Number.isSafeInteger(entryOrOrdinal)
        ? normalizedManifest.entries[entryOrOrdinal]
        : entryOrOrdinal;
    if (entry === undefined || entry === null) {
        fail("enumerand binding references an absent manifest ordinal", {
            ordinal: entryOrOrdinal,
        });
    }
    const canonicalEntry = normalizedManifest.entries[entry.ordinal];
    if (canonicalEntry === undefined
        || !canonicalEqual(canonicalEntry, normalizeEntry(
            entry,
            normalizedManifest.topology,
            "enumerand",
            options,
        ))) {
        fail("enumerand binding entry is not in the manifest", {
            ordinal: entry.ordinal,
        });
    }
    return immutableCanonical({
        manifestRoot: normalizedManifest.merkleRoot,
        topology: normalizedManifest.topology,
        ...canonicalEntry,
    });
}

export function normalizeEnumerandBinding(input, options = {}) {
    requirePlainObject(input, "enumerandBinding");
    const topology = topologyOf(input.topology, "enumerandBinding.topology");
    const finite = topology === "finite_enumerable";
    requireExactKeys(
        input,
        "enumerandBinding",
        finite
            ? [
                "artifactSnapshotHash",
                "enumerandHash",
                "id",
                "manifestRoot",
                "ordinal",
                "topology",
            ]
            : [
                "enumerandHash",
                "id",
                "manifestRoot",
                "ordinal",
                "parameterTuple",
                "parameterTupleHash",
                "topology",
            ],
        ["hypotheses"],
    );
    requireTaggedHash(input.manifestRoot, "enumerandBinding.manifestRoot");
    const entry = normalizeEntry(
        finite
            ? {
                id: input.id,
                ordinal: input.ordinal,
                artifactSnapshotHash: input.artifactSnapshotHash,
                enumerandHash: input.enumerandHash,
                ...(input.hypotheses === undefined
                    ? {}
                    : { hypotheses: input.hypotheses }),
            }
            : {
                id: input.id,
                ordinal: input.ordinal,
                parameterTuple: input.parameterTuple,
                parameterTupleHash: input.parameterTupleHash,
                enumerandHash: input.enumerandHash,
                ...(input.hypotheses === undefined
                    ? {}
                    : { hypotheses: input.hypotheses }),
            },
        topology,
        "enumerandBinding",
        options,
    );
    return immutableCanonical({
        manifestRoot: input.manifestRoot,
        topology,
        ...entry,
    });
}

export function enumerandBindingHash(binding, options = {}) {
    return hashCanonical(
        normalizeEnumerandBinding(binding, options),
        ENUMERAND_BINDING_HASH_ALGORITHM,
    );
}

export function assertEnumerandBinding(manifest, binding, options = {}) {
    const normalizedManifest = normalizeEnumerandManifest(manifest, options);
    const normalizedBinding = normalizeEnumerandBinding(binding, options);
    if (normalizedBinding.manifestRoot !== normalizedManifest.merkleRoot
        || normalizedBinding.topology !== normalizedManifest.topology) {
        fail("enumerand binding does not target the frozen manifest", {
            expectedManifestRoot: normalizedManifest.merkleRoot,
            actualManifestRoot: normalizedBinding.manifestRoot,
            expectedTopology: normalizedManifest.topology,
            actualTopology: normalizedBinding.topology,
        });
    }
    const expected = normalizedManifest.entries[normalizedBinding.ordinal];
    if (expected === undefined
        || !canonicalEqual(
            normalizedBinding,
            {
                manifestRoot: normalizedManifest.merkleRoot,
                topology: normalizedManifest.topology,
                ...expected,
            },
        )) {
        fail("enumerand binding content is outside the frozen manifest", {
            ordinal: normalizedBinding.ordinal,
            enumerandHash: normalizedBinding.enumerandHash,
        });
    }
    return normalizedBinding;
}

export function enumerandArtifactMeasurementHash(artifactSnapshotHash) {
    const snapshot = requireSnapshotHash(
        artifactSnapshotHash,
        "artifactSnapshotHash",
    );
    return `sha256:crucible-measurement-snapshot-v1:${snapshot.slice("sha256:".length)}`;
}

function normalizedAttempt(attempt, index) {
    requirePlainObject(attempt, `attempts[${index}]`);
    const ordinal = attempt.enumerandOrdinal ?? attempt.ordinal;
    const enumerandHashValue = attempt.enumerandHash;
    const invalidated = attempt.invalidated === true;
    const completed = attempt.completed !== false;
    const invalidMetrics = attempt.outcomeClass === "invalid_metrics";
    return {
        index,
        ordinal: Number.isSafeInteger(ordinal) && ordinal >= 0 ? ordinal : null,
        enumerandHash: isAlgorithmTaggedSha256(enumerandHashValue)
            ? enumerandHashValue
            : null,
        invalidated,
        completed,
        invalidMetrics,
        acceptanceSatisfied: attempt.acceptanceSatisfied === true,
    };
}

export function enumerandCoverage(manifest, attempts = [], options = {}) {
    const normalizedManifest = normalizeEnumerandManifest(manifest, options);
    if (!Array.isArray(attempts)) {
        fail("enumerand coverage attempts must be an array");
    }
    const countInvalidMetrics = options.countInvalidMetrics === true;
    const covered = new Map();
    const duplicateCounts = new Map();
    const offManifest = [];
    const accepted = new Set();
    for (const [index, rawAttempt] of attempts.entries()) {
        const attempt = normalizedAttempt(rawAttempt, index);
        if (attempt.invalidated || !attempt.completed
            || (attempt.invalidMetrics && !countInvalidMetrics)) {
            continue;
        }
        const expected = attempt.ordinal === null
            ? undefined
            : normalizedManifest.entries[attempt.ordinal];
        if (expected === undefined
            || attempt.enumerandHash === null
            || attempt.enumerandHash !== expected.enumerandHash) {
            offManifest.push({
                attemptIndex: index,
                ordinal: attempt.ordinal,
                enumerandHash: attempt.enumerandHash,
                reason: expected === undefined
                    ? "ordinal_outside_manifest"
                    : "enumerand_hash_mismatch",
            });
            continue;
        }
        const key = `${expected.ordinal}:${expected.enumerandHash}`;
        if (covered.has(key)) {
            duplicateCounts.set(key, (duplicateCounts.get(key) ?? 1) + 1);
        } else {
            covered.set(key, expected);
        }
        if (attempt.acceptanceSatisfied) {
            accepted.add(key);
        }
    }
    const coveredEntries = [...covered.values()]
        .sort((left, right) => left.ordinal - right.ordinal);
    const missingEntries = normalizedManifest.entries.filter((entry) =>
        !covered.has(`${entry.ordinal}:${entry.enumerandHash}`));
    const duplicates = [...duplicateCounts.entries()]
        .map(([key, count]) => {
            const separator = key.indexOf(":");
            return {
                ordinal: Number.parseInt(key.slice(0, separator), 10),
                enumerandHash: key.slice(separator + 1),
                attemptCount: count,
            };
        })
        .sort((left, right) => left.ordinal - right.ordinal);
    const closure = coveredEntries.map((entry) => ({
        ordinal: entry.ordinal,
        enumerandHash: entry.enumerandHash,
    }));
    return immutableCanonical({
        manifestRoot: normalizedManifest.merkleRoot,
        topology: normalizedManifest.topology,
        totalEnumerands: normalizedManifest.entries.length,
        coveredEnumerands: coveredEntries.length,
        coveredOrdinals: coveredEntries.map((entry) => entry.ordinal),
        missingOrdinals: missingEntries.map((entry) => entry.ordinal),
        acceptedOrdinals: coveredEntries
            .filter((entry) => accepted.has(`${entry.ordinal}:${entry.enumerandHash}`))
            .map((entry) => entry.ordinal),
        duplicateAttempts: duplicates,
        offManifestAttempts: offManifest,
        complete: missingEntries.length === 0,
        coverageHash: hashCanonical({
            manifestRoot: normalizedManifest.merkleRoot,
            closure,
        }, ENUMERAND_COVERAGE_HASH_ALGORITHM),
    });
}

export function selectUntriedEnumerand(manifest, attempts = [], options = {}) {
    const normalizedManifest = normalizeEnumerandManifest(manifest, options);
    const coverage = enumerandCoverage(normalizedManifest, attempts, options);
    const ordinal = coverage.missingOrdinals[0];
    return ordinal === undefined
        ? null
        : normalizedManifest.entries[ordinal];
}

export function enumerandExhaustion(manifest, attempts = [], options = {}) {
    const normalizedManifest = normalizeEnumerandManifest(manifest, options);
    const coverage = enumerandCoverage(normalizedManifest, attempts, options);
    const exhausted = coverage.complete && coverage.acceptedOrdinals.length === 0;
    const closure = normalizedManifest.entries.map((entry) => ({
        ordinal: entry.ordinal,
        enumerandHash: entry.enumerandHash,
    }));
    return immutableCanonical({
        manifestRoot: normalizedManifest.merkleRoot,
        topology: normalizedManifest.topology,
        exhausted,
        reason: !coverage.complete
            ? "coverage_gap"
            : coverage.acceptedOrdinals.length > 0
                ? "accepted_enumerand"
                : "all_enumerands_evaluated_without_acceptance",
        coverage,
        exhaustionHash: exhausted
            ? hashCanonical({
                manifestRoot: normalizedManifest.merkleRoot,
                closure,
            }, ENUMERAND_EXHAUSTION_HASH_ALGORITHM)
            : null,
    });
}

export function resolveControlEnumerand(manifest, options = {}) {
    const normalizedManifest = normalizeEnumerandManifest(manifest, options);
    if (normalizedManifest.control.kind === "reference") {
        return normalizedManifest.control;
    }
    return enumerandBinding(
        normalizedManifest,
        normalizedManifest.control.ordinal,
        options,
    );
}

export function isEnumerandSpaceExhaustible(input) {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
        return false;
    }
    const topology = input.topology === "certified_impossibility"
        ? input.enumerandManifest?.topology
        : input.topology;
    if (!MANIFEST_TOPOLOGIES.includes(topology)
        || input.enumerandManifest === undefined
        || input.enumerandManifest === null) {
        return false;
    }
    try {
        normalizeEnumerandManifest(input.enumerandManifest, {
            topology,
            observableRegistry: input.observableRegistry ?? [],
            hypothesisPolicy: input.hypothesisPolicy ?? {},
        });
        return true;
    } catch {
        return false;
    }
}
