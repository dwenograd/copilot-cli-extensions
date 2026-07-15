import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    duplicateEvidenceId,
} from "./archive.mjs";
import { ERROR_CODES, TransitionError } from "./errors.mjs";
import {
    ReplicationScheduleError,
    analyzeReplicationAttempts,
    deriveReplicationControlBinding,
    expectedReplicationSubjects,
    normalizeRawMeasurementSeries,
    normalizeReplicationSchedule,
    replicationBlockPlan,
} from "./replication.mjs";
import {
    createCandidateStatisticalClaimPlan,
    evaluateReplicationProgress,
    evaluateReplicatedStatisticalClaims,
    evaluateSealedPredictions,
    prepareReplicatedStatisticalEvaluation,
} from "./statistical-evaluation.mjs";
import {
    verifiedImpossibilityExecutionFor,
} from "./private-verifier-execution.mjs";

export const EVIDENCE_PROVENANCE_VERSION = 2;
export const SNAPSHOT_PROVENANCE_HASH_ALGORITHM =
    "sha256:crucible-evidence-snapshot-provenance-v1";
export const MEASUREMENT_PROVENANCE_HASH_ALGORITHM =
    "sha256:crucible-evidence-measurement-provenance-v1";
export const EVIDENCE_PROVENANCE_HASH_ALGORITHM =
    "sha256:crucible-evidence-provenance-v2";
export const SNAPSHOT_EXECUTION_HASH_ALGORITHM =
    "sha256:crucible-evidence-snapshot-execution-v1";
export const OBSERVATION_STREAM_HASH_ALGORITHM =
    "sha256:crucible-runtime-observation-streams-v1";
export const RAW_OBSERVATION_AUTHORITY_HASH_ALGORITHM =
    "sha256:crucible-raw-observation-authority-v1";
export const STATISTICAL_CACHE_HASH_ALGORITHM =
    "sha256:crucible-statistical-cache-v1";

export function deriveStatisticalCacheDigest(cacheCore) {
    return hashCanonical(cacheCore, STATISTICAL_CACHE_HASH_ALGORITHM);
}

const OBJECT_ID_RE = /^sha256:([a-f0-9]{64})$/u;
const SNAPSHOT_HASH_RE =
    /^sha256:crucible-measurement-snapshot-v1:([a-f0-9]{64})$/u;
const SAFE_IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]*$/u;
const FORBIDDEN_IDENTIFIERS = new Set(["__proto__", "constructor", "prototype"]);
const ARTIFACT_REF_KEYS = Object.freeze(["artifactId", "objectId"]);
const SNAPSHOT_KEYS = Object.freeze([
    "closureRoot",
    "manifestArtifact",
    "objectArtifacts",
    "snapshotHash",
]);
const DEPENDENCY_KEYS = Object.freeze(["path", "role", "sha256"]);
const SANDBOX_KEYS = Object.freeze(["environmentHash", "kind", "sandboxId"]);
const MEASUREMENT_KEYS = Object.freeze([
    "allowlistFileHash",
    "argvHash",
    "dependencyHashes",
    "envHash",
    "executableHash",
    "harnessEntryHash",
    "measurementRoot",
    "parserVersion",
    "phase",
    "rawStderrArtifact",
    "rawStderrHash",
    "rawStdoutArtifact",
    "rawStdoutHash",
    "receiptArtifact",
    "receiptHash",
    "role",
    "sandboxPolicy",
    "snapshot",
    "snapshotExecutionHash",
    "stagedDependencyHashes",
    "stagedExecutableHash",
    "subjectId",
]);
const PROVENANCE_KEYS = Object.freeze([
    "closureRoot",
    "impossibilityCertificateArtifact",
    "measurementReuseArtifact",
    "measurements",
    "promptContextHash",
    "proposalArtifact",
    "replicationCompositeArtifact",
    "replicationScheduleArtifact",
    "validationCompositeArtifact",
    "version",
]);

function fail(message, details = null) {
    throw new TransitionError(ERROR_CODES.INVALID_EVENT, message, details);
}

function requirePlainObject(value, field) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        fail(`${field} must be an object`, { field });
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        fail(`${field} must be a plain object`, { field });
    }
    return value;
}

function requireExactKeys(value, field, expectedKeys) {
    const object = requirePlainObject(value, field);
    const actual = Object.keys(object).sort();
    const expected = [...expectedKeys].sort();
    if (!canonicalEqual(actual, expected)) {
        fail(`${field} must contain exactly the canonical fields`, {
            field,
            expected,
            actual,
        });
    }
    return object;
}

function requireIdentifier(value, field) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > 128
        || !SAFE_IDENTIFIER_RE.test(value)
        || value === "."
        || value === ".."
        || value.endsWith(".")
        || value.includes("..")
        || FORBIDDEN_IDENTIFIERS.has(value.toLowerCase())) {
        fail(`${field} must be a safe identifier`, { field });
    }
    return value;
}

function requireText(value, field, maximum = 32768) {
    if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
        fail(`${field} must be a non-empty bounded string`, { field });
    }
    return value;
}

function requireTaggedHash(value, field) {
    if (!isAlgorithmTaggedSha256(value)) {
        fail(`${field} must be an algorithm-tagged SHA-256 hash`, { field });
    }
    return value;
}

function requireObjectId(value, field) {
    if (typeof value !== "string" || !OBJECT_ID_RE.test(value)) {
        fail(`${field} must be a sha256:<64hex> object id`, { field });
    }
    return value;
}

function digestOfTaggedHash(value) {
    return value.split(":").at(-1);
}

function objectIdMatchesTaggedHash(artifact, taggedHash) {
    return artifact.objectId.slice("sha256:".length) === digestOfTaggedHash(taggedHash);
}

function normalizeArtifactRef(value, field) {
    const input = requireExactKeys(value, field, ARTIFACT_REF_KEYS);
    return {
        artifactId: requireIdentifier(input.artifactId, `${field}.artifactId`),
        objectId: requireObjectId(input.objectId, `${field}.objectId`),
    };
}

function optionalArtifactRef(value, field) {
    return value === null ? null : normalizeArtifactRef(value, field);
}

function compareArtifactRefs(left, right) {
    const leftKey = `${left.objectId}\0${left.artifactId}`;
    const rightKey = `${right.objectId}\0${right.artifactId}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
}

function normalizeSnapshotCore(value, field) {
    const input = requireExactKeys(value, field, SNAPSHOT_KEYS);
    const manifestArtifact = normalizeArtifactRef(
        input.manifestArtifact,
        `${field}.manifestArtifact`,
    );
    if (!Array.isArray(input.objectArtifacts)) {
        fail(`${field}.objectArtifacts must be an array`);
    }
    const objectArtifacts = input.objectArtifacts
        .map((item, index) =>
            normalizeArtifactRef(item, `${field}.objectArtifacts[${index}]`))
        .sort(compareArtifactRefs);
    const objectIds = objectArtifacts.map((item) => item.objectId);
    const artifactIds = objectArtifacts.map((item) => item.artifactId);
    if (new Set(objectIds).size !== objectIds.length
        || new Set(artifactIds).size !== artifactIds.length) {
        fail(`${field}.objectArtifacts must identify a unique object closure`);
    }
    const snapshotHash = requireTaggedHash(input.snapshotHash, `${field}.snapshotHash`);
    const snapshotMatch = SNAPSHOT_HASH_RE.exec(snapshotHash);
    const manifestMatch = OBJECT_ID_RE.exec(manifestArtifact.objectId);
    if (snapshotMatch === null
        || manifestMatch === null
        || snapshotMatch[1] !== manifestMatch[1]) {
        fail(`${field}.snapshotHash must bind the manifest object bytes`);
    }
    return {
        manifestArtifact,
        objectArtifacts,
        snapshotHash,
    };
}

export function deriveSnapshotProvenanceRoot(snapshot) {
    return hashCanonical({
        manifestArtifact: snapshot.manifestArtifact,
        objectArtifacts: snapshot.objectArtifacts,
        snapshotHash: snapshot.snapshotHash,
    }, SNAPSHOT_PROVENANCE_HASH_ALGORITHM);
}

function normalizeSnapshotProvenance(value, field) {
    const core = normalizeSnapshotCore(value, field);
    const expectedRoot = deriveSnapshotProvenanceRoot(core);
    if (value.closureRoot !== expectedRoot) {
        fail(`${field}.closureRoot is not derived from the canonical snapshot closure`, {
            expected: expectedRoot,
            actual: value.closureRoot ?? null,
        });
    }
    return {
        ...core,
        closureRoot: expectedRoot,
    };
}

export function createSnapshotProvenance(input) {
    const core = normalizeSnapshotCore({
        ...input,
        closureRoot: input.closureRoot ?? "pending",
    }, "snapshot");
    return immutableCanonical({
        ...core,
        closureRoot: deriveSnapshotProvenanceRoot(core),
    });
}

function normalizeDependencyHashes(value, field) {
    if (!Array.isArray(value) || value.length > 64) {
        fail(`${field} must be an array with at most 64 entries`, { field });
    }
    const normalized = value.map((item, index) => {
        const input = requireExactKeys(item, `${field}[${index}]`, DEPENDENCY_KEYS);
        return {
            path: requireText(input.path, `${field}[${index}].path`),
            role: requireText(input.role, `${field}[${index}].role`, 128),
            sha256: requireTaggedHash(input.sha256, `${field}[${index}].sha256`),
        };
    }).sort((left, right) => {
        const leftKey = `${left.path}\0${left.role}\0${left.sha256}`;
        const rightKey = `${right.path}\0${right.role}\0${right.sha256}`;
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
    if (new Set(normalized.map((item) => item.path)).size !== normalized.length) {
        fail(`${field} must not contain duplicate paths`, { field });
    }
    return normalized;
}

function dependencyIdentity(items) {
    return items
        .map((item) => ({ role: item.role, sha256: item.sha256 }))
        .sort((left, right) => {
            const leftKey = `${left.role}\0${left.sha256}`;
            const rightKey = `${right.role}\0${right.sha256}`;
            return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
        });
}

function normalizeSandboxPolicy(value, field) {
    const input = requireExactKeys(value, field, SANDBOX_KEYS);
    if (input.kind === "none") {
        if (input.sandboxId !== null || input.environmentHash !== null) {
            fail(`${field} kind=none requires null sandbox identity fields`);
        }
        return { kind: "none", sandboxId: null, environmentHash: null };
    }
    if (input.kind !== "sandbox") {
        fail(`${field}.kind must be "none" or "sandbox"`);
    }
    return {
        kind: "sandbox",
        sandboxId: requireIdentifier(input.sandboxId, `${field}.sandboxId`),
        environmentHash: requireTaggedHash(
            input.environmentHash,
            `${field}.environmentHash`,
        ),
    };
}

function normalizeMeasurementCore(value, field) {
    const input = requireExactKeys(value, field, MEASUREMENT_KEYS);
    const receiptArtifact = normalizeArtifactRef(
        input.receiptArtifact,
        `${field}.receiptArtifact`,
    );
    const rawStdoutArtifact = normalizeArtifactRef(
        input.rawStdoutArtifact,
        `${field}.rawStdoutArtifact`,
    );
    const rawStderrArtifact = normalizeArtifactRef(
        input.rawStderrArtifact,
        `${field}.rawStderrArtifact`,
    );
    const receiptHash = requireTaggedHash(input.receiptHash, `${field}.receiptHash`);
    const rawStdoutHash = requireTaggedHash(
        input.rawStdoutHash,
        `${field}.rawStdoutHash`,
    );
    const rawStderrHash = requireTaggedHash(
        input.rawStderrHash,
        `${field}.rawStderrHash`,
    );
    if (!objectIdMatchesTaggedHash(receiptArtifact, receiptHash)
        || !objectIdMatchesTaggedHash(rawStdoutArtifact, rawStdoutHash)
        || !objectIdMatchesTaggedHash(rawStderrArtifact, rawStderrHash)) {
        fail(`${field} artifact object ids do not bind the receipt/output byte hashes`);
    }
    const dependencyHashes = normalizeDependencyHashes(
        input.dependencyHashes,
        `${field}.dependencyHashes`,
    );
    const stagedDependencyHashes = normalizeDependencyHashes(
        input.stagedDependencyHashes,
        `${field}.stagedDependencyHashes`,
    );
    const executableHash = requireTaggedHash(
        input.executableHash,
        `${field}.executableHash`,
    );
    const stagedExecutableHash = requireTaggedHash(
        input.stagedExecutableHash,
        `${field}.stagedExecutableHash`,
    );
    if (executableHash !== stagedExecutableHash
        || !canonicalEqual(
            dependencyIdentity(dependencyHashes),
            dependencyIdentity(stagedDependencyHashes),
        )) {
        fail(`${field} staged harness hashes do not match the frozen source hashes`);
    }
    return {
        subjectId: requireIdentifier(input.subjectId, `${field}.subjectId`),
        role: requireIdentifier(input.role, `${field}.role`),
        phase: requireIdentifier(input.phase, `${field}.phase`),
        receiptArtifact,
        receiptHash,
        rawStdoutArtifact,
        rawStdoutHash,
        rawStderrArtifact,
        rawStderrHash,
        parserVersion: requireIdentifier(input.parserVersion, `${field}.parserVersion`),
        allowlistFileHash: requireTaggedHash(
            input.allowlistFileHash,
            `${field}.allowlistFileHash`,
        ),
        harnessEntryHash: requireTaggedHash(
            input.harnessEntryHash,
            `${field}.harnessEntryHash`,
        ),
        executableHash,
        stagedExecutableHash,
        dependencyHashes,
        stagedDependencyHashes,
        argvHash: requireTaggedHash(input.argvHash, `${field}.argvHash`),
        envHash: requireTaggedHash(input.envHash, `${field}.envHash`),
        sandboxPolicy: normalizeSandboxPolicy(
            input.sandboxPolicy,
            `${field}.sandboxPolicy`,
        ),
        snapshot: normalizeSnapshotProvenance(input.snapshot, `${field}.snapshot`),
        snapshotExecutionHash: requireTaggedHash(
            input.snapshotExecutionHash,
            `${field}.snapshotExecutionHash`,
        ),
    };
}

export function deriveMeasurementProvenanceRoot(measurement) {
    const { measurementRoot: _excluded, ...core } = measurement;
    return hashCanonical(core, MEASUREMENT_PROVENANCE_HASH_ALGORITHM);
}

function normalizeMeasurementProvenance(value, field) {
    const core = normalizeMeasurementCore(value, field);
    const expectedRoot = deriveMeasurementProvenanceRoot(core);
    if (value.measurementRoot !== expectedRoot) {
        fail(`${field}.measurementRoot is not derived from the canonical receipt closure`, {
            expected: expectedRoot,
            actual: value.measurementRoot ?? null,
        });
    }
    return {
        ...core,
        measurementRoot: expectedRoot,
    };
}

export function createMeasurementProvenance(input) {
    const core = normalizeMeasurementCore({
        ...input,
        measurementRoot: input.measurementRoot ?? "pending",
    }, "measurement");
    return immutableCanonical({
        ...core,
        measurementRoot: deriveMeasurementProvenanceRoot(core),
    });
}

function provenanceCore(value) {
    const {
        closureRoot: _excluded,
        ...core
    } = value;
    return core;
}

export function deriveEvidenceProvenanceRoot(provenance) {
    return hashCanonical(provenanceCore(provenance), EVIDENCE_PROVENANCE_HASH_ALGORITHM);
}

function expectedMeasurementSubjects(purpose, command, contract) {
    if (purpose === "validation") {
        return (command?.validationSeries ?? [])
            .flatMap((series) =>
                replicationBlockPlan(
                    series.replicationSchedule,
                    command.attemptIndex,
                ).arms.map((arm) => arm.subjectId))
            .sort();
    }
    if (purpose === "impossibility") {
        return [`impossibility-${command?.attemptOrdinal ?? ""}`];
    }
    return [];
}

function replicatedCandidatePurpose(purpose) {
    return purpose === "candidate"
        || purpose === "confirmation"
        || purpose === "challenge";
}

function replicatedRole(purpose, command) {
    return purpose === "candidate"
        ? "search"
        : command?.harnessRole ?? purpose;
}

function replicatedPhase(purpose, command) {
    return purpose === "candidate"
        ? "search"
        : command?.harnessRole ?? purpose;
}

function assertPurposeShape(provenance, { purpose, command, contract }) {
    const subjects = provenance.measurements.map((item) => item.subjectId);
    const expectedSubjects = expectedMeasurementSubjects(purpose, command, contract);
    if (!replicatedCandidatePurpose(purpose)
        && !canonicalEqual(subjects, expectedSubjects)) {
        fail("receipt.provenance measurements do not match the reserved command subjects", {
            purpose,
            subjects,
            expectedSubjects,
        });
    }
    for (const measurement of provenance.measurements) {
        const role = contract?.harnessSuite?.roles?.[measurement.role];
        const parserVersion = role?.parser?.version
            ?? contract?.parserVersion;
        if (parserVersion === undefined
            || measurement.parserVersion !== parserVersion
            || (contract?.harnessSuite !== undefined && role === undefined)) {
            fail("receipt.provenance role identity does not match the frozen contract", {
                role: measurement.role,
                subjectId: measurement.subjectId,
            });
        }
    }
    if (purpose === "validation") {
        if (provenance.proposalArtifact !== null
            || provenance.promptContextHash !== null
            || provenance.impossibilityCertificateArtifact !== null
            || provenance.measurementReuseArtifact !== null
            || provenance.replicationScheduleArtifact !== null
            || provenance.replicationCompositeArtifact !== null
            || provenance.validationCompositeArtifact === null) {
            fail("Validation provenance has an invalid purpose-specific artifact shape");
        }
        const bySubject = new Map(
            (command?.validationSeries ?? []).flatMap((series) =>
                replicationBlockPlan(
                    series.replicationSchedule,
                    command.attemptIndex,
                ).arms.map((arm) => [
                    arm.subjectId,
                    {
                        artifactHash: series.artifactHash,
                        role: series.role,
                    },
                ])),
        );
        for (const measurement of provenance.measurements) {
            const expected = bySubject.get(measurement.subjectId);
            if (measurement.role !== expected?.role
                || measurement.phase !== "calibration"
                || measurement.snapshot.manifestArtifact.objectId
                    !== expected?.artifactHash) {
                fail("Validation provenance snapshot does not match the frozen case artifact");
            }
        }
        return;
    }
    if (purpose === "candidate") {
        const schedule = normalizeReplicationSchedule(
            command?.replicationSchedule,
        );
        const searchMeasurements = provenance.measurements.filter(
            (measurement) => measurement.role === "search",
        );
        if (searchMeasurements.length !== provenance.measurements.length) {
            fail("Candidate provenance contains an unsupported measurement role");
        }
        if (searchMeasurements.some((measurement) =>
            measurement.phase !== "search")) {
            fail("Candidate provenance measurement phases do not match their roles");
        }
        if (searchMeasurements.length % schedule.arms.length !== 0) {
            fail("Candidate provenance must contain complete replicate blocks");
        }
        const blockCount = searchMeasurements.length / schedule.arms.length;
        if (blockCount < schedule.minBlocks || blockCount > schedule.maxBlocks) {
            fail("Candidate provenance block count is outside the frozen schedule", {
                blockCount,
                minBlocks: schedule.minBlocks,
                maxBlocks: schedule.maxBlocks,
            });
        }
        const scheduledSubjects = [...expectedReplicationSubjects(
            schedule,
            blockCount,
        )].sort();
        const searchSubjects = searchMeasurements
            .map((measurement) => measurement.subjectId)
            .sort();
        if (!canonicalEqual(searchSubjects, scheduledSubjects)) {
            fail("Candidate provenance measurements do not match the frozen replicate schedule", {
                subjects: searchSubjects,
                expectedSubjects: scheduledSubjects,
            });
        }
        if (provenance.proposalArtifact === null
            || provenance.promptContextHash === null
            || provenance.replicationScheduleArtifact === null
            || provenance.replicationCompositeArtifact === null
            || provenance.validationCompositeArtifact !== null
            || provenance.impossibilityCertificateArtifact !== null) {
            fail("Candidate provenance has an invalid purpose-specific artifact shape");
        }
        return;
    }
    if (purpose === "confirmation" || purpose === "challenge") {
        const schedule = normalizeReplicationSchedule(
            command?.replicationSchedule,
        );
        const role = replicatedRole(purpose, command);
        const phase = replicatedPhase(purpose, command);
        if (provenance.measurements.some((measurement) =>
            measurement.role !== role || measurement.phase !== phase)) {
            fail(
                `${purpose} provenance measurement phases do not match the frozen role`,
            );
        }
        if (provenance.measurements.length % schedule.arms.length !== 0) {
            fail(`${purpose} provenance must contain complete replicate blocks`);
        }
        const blockCount = provenance.measurements.length / schedule.arms.length;
        if (blockCount < schedule.minBlocks || blockCount > schedule.maxBlocks) {
            fail(`${purpose} provenance block count is outside the frozen schedule`, {
                blockCount,
                minBlocks: schedule.minBlocks,
                maxBlocks: schedule.maxBlocks,
            });
        }
        const scheduledSubjects = [...expectedReplicationSubjects(
            schedule,
            blockCount,
        )].sort();
        if (!canonicalEqual([...subjects].sort(), scheduledSubjects)) {
            fail(
                `${purpose} provenance measurements do not match the frozen replicate schedule`,
            );
        }
        if (provenance.proposalArtifact !== null
            || provenance.promptContextHash !== null
            || provenance.validationCompositeArtifact !== null
            || provenance.impossibilityCertificateArtifact !== null
            || provenance.measurementReuseArtifact !== null
            || provenance.replicationScheduleArtifact === null
            || provenance.replicationCompositeArtifact === null) {
            fail(`${purpose} provenance has an invalid purpose-specific artifact shape`);
        }
        return;
    }
    if (purpose === "impossibility") {
        if (provenance.proposalArtifact !== null
            || provenance.promptContextHash !== null
            || provenance.validationCompositeArtifact !== null
            || provenance.measurementReuseArtifact !== null
            || provenance.replicationScheduleArtifact !== null
            || provenance.replicationCompositeArtifact !== null
            || provenance.impossibilityCertificateArtifact === null) {
            fail("Impossibility provenance has an invalid purpose-specific artifact shape");
        }
    }
}

export function normalizeEvidenceProvenance(
    value,
    { purpose, command = null, contract = null } = {},
) {
    const input = requireExactKeys(value, "receipt.provenance", PROVENANCE_KEYS);
    if (input.version !== EVIDENCE_PROVENANCE_VERSION) {
        fail(`receipt.provenance.version must be ${EVIDENCE_PROVENANCE_VERSION}`);
    }
    if (!Array.isArray(input.measurements) || input.measurements.length === 0) {
        fail("receipt.provenance.measurements must be a non-empty array");
    }
    const measurements = input.measurements
        .map((item, index) =>
            normalizeMeasurementProvenance(
                item,
                `receipt.provenance.measurements[${index}]`,
            ))
        .sort((left, right) =>
            left.subjectId < right.subjectId ? -1 : left.subjectId > right.subjectId ? 1 : 0);
    if (new Set(measurements.map((item) => item.subjectId)).size !== measurements.length) {
        fail("receipt.provenance.measurements must have unique subject ids");
    }
    const normalized = {
        version: EVIDENCE_PROVENANCE_VERSION,
        proposalArtifact: optionalArtifactRef(
            input.proposalArtifact,
            "receipt.provenance.proposalArtifact",
        ),
        promptContextHash: input.promptContextHash === null
            ? null
            : requireTaggedHash(
                input.promptContextHash,
                "receipt.provenance.promptContextHash",
            ),
        validationCompositeArtifact: optionalArtifactRef(
            input.validationCompositeArtifact,
            "receipt.provenance.validationCompositeArtifact",
        ),
        impossibilityCertificateArtifact: optionalArtifactRef(
            input.impossibilityCertificateArtifact,
            "receipt.provenance.impossibilityCertificateArtifact",
        ),
        measurementReuseArtifact: optionalArtifactRef(
            input.measurementReuseArtifact,
            "receipt.provenance.measurementReuseArtifact",
        ),
        replicationScheduleArtifact: optionalArtifactRef(
            input.replicationScheduleArtifact,
            "receipt.provenance.replicationScheduleArtifact",
        ),
        replicationCompositeArtifact: optionalArtifactRef(
            input.replicationCompositeArtifact,
            "receipt.provenance.replicationCompositeArtifact",
        ),
        measurements,
    };
    assertPurposeShape(normalized, { purpose, command, contract });
    const closureRoot = deriveEvidenceProvenanceRoot(normalized);
    if (input.closureRoot !== closureRoot) {
        fail("receipt.provenance.closureRoot is not derived from the canonical artifact closure", {
            expected: closureRoot,
            actual: input.closureRoot ?? null,
        });
    }
    return immutableCanonical({
        ...normalized,
        closureRoot,
    });
}

export function createEvidenceProvenance(input, context = {}) {
    const normalized = {
        version: EVIDENCE_PROVENANCE_VERSION,
        proposalArtifact: optionalArtifactRef(
            input.proposalArtifact ?? null,
            "receipt.provenance.proposalArtifact",
        ),
        promptContextHash: input.promptContextHash ?? null,
        validationCompositeArtifact: optionalArtifactRef(
            input.validationCompositeArtifact ?? null,
            "receipt.provenance.validationCompositeArtifact",
        ),
        impossibilityCertificateArtifact: optionalArtifactRef(
            input.impossibilityCertificateArtifact ?? null,
            "receipt.provenance.impossibilityCertificateArtifact",
        ),
        measurementReuseArtifact: optionalArtifactRef(
            input.measurementReuseArtifact ?? null,
            "receipt.provenance.measurementReuseArtifact",
        ),
        replicationScheduleArtifact: optionalArtifactRef(
            input.replicationScheduleArtifact ?? null,
            "receipt.provenance.replicationScheduleArtifact",
        ),
        replicationCompositeArtifact: optionalArtifactRef(
            input.replicationCompositeArtifact ?? null,
            "receipt.provenance.replicationCompositeArtifact",
        ),
        measurements: input.measurements
            .map((item, index) =>
                normalizeMeasurementProvenance(
                    item,
                    `receipt.provenance.measurements[${index}]`,
                ))
            .sort((left, right) =>
                left.subjectId < right.subjectId ? -1 : left.subjectId > right.subjectId ? 1 : 0),
    };
    if (normalized.promptContextHash !== null) {
        normalized.promptContextHash = requireTaggedHash(
            normalized.promptContextHash,
            "receipt.provenance.promptContextHash",
        );
    }
    assertPurposeShape(normalized, context);
    return immutableCanonical({
        ...normalized,
        closureRoot: deriveEvidenceProvenanceRoot(normalized),
    });
}

export function artifactRefsFromProvenance(provenance) {
    const refs = [];
    const add = (artifact) => {
        if (artifact !== null) refs.push(artifact);
    };
    add(provenance.proposalArtifact);
    add(provenance.validationCompositeArtifact);
    add(provenance.impossibilityCertificateArtifact);
    add(provenance.measurementReuseArtifact);
    add(provenance.replicationScheduleArtifact);
    add(provenance.replicationCompositeArtifact);
    for (const measurement of provenance.measurements) {
        add(measurement.receiptArtifact);
        add(measurement.rawStdoutArtifact);
        add(measurement.rawStderrArtifact);
        add(measurement.snapshot.manifestArtifact);
        for (const artifact of measurement.snapshot.objectArtifacts) add(artifact);
    }
    const unique = new Map();
    for (const artifact of refs) {
        const existing = unique.get(artifact.artifactId);
        if (existing !== undefined && existing.objectId !== artifact.objectId) {
            fail("One provenance closure maps an artifact id to multiple object ids", {
                artifactId: artifact.artifactId,
            });
        }
        unique.set(artifact.artifactId, artifact);
    }
    return immutableCanonical([...unique.values()].sort(compareArtifactRefs));
}

function ownEntry(record, key) {
    return Object.hasOwn(record, key) ? record[key] : null;
}

export function deriveRawObservationAuthorityDigest(
    aggregate,
    observation,
    command = ownEntry(
        aggregate.commands,
        observation.commandId,
    )?.command ?? null,
) {
    const {
        observedSeq: _observedSeq,
        evidenceId: _evidenceId,
        rawAuthorityDigest: _rawAuthorityDigest,
        ...rawObservation
    } = observation;
    return hashCanonical({
        contractHash: aggregate.contractHash,
        statisticalPolicyIdentity:
            aggregate.contract?.statisticalPolicyIdentity ?? null,
        command,
        observation: rawObservation,
    }, RAW_OBSERVATION_AUTHORITY_HASH_ALGORITHM);
}

function normalizedReplicatedCandidateAttempts(observation, command) {
    const role = replicatedRole(observation.purpose, command);
    const phase = replicatedPhase(observation.purpose, command);
    return normalizeRawMeasurementSeries(
        observation.data.series[0],
        {
            schedule: command.replicationSchedule,
            role,
            phase,
            caseId: null,
        },
    ).attempts;
}

function normalizedCandidateEvaluation(
    aggregate,
    command,
    attempts,
    claimPlan,
    parentEvidence,
    prepared,
) {
    return evaluateReplicatedStatisticalClaims({
        contract: aggregate.contract,
        schedule: command.replicationSchedule,
        attempts,
        claims: claimPlan.acceptanceClaims,
        requiredClaimIds: claimPlan.acceptanceClaimIds,
        allocationClaims: claimPlan.allocationClaims,
        parentEvidence,
        prepared,
    });
}

function replicationControlBinding(
    aggregate,
    command,
    attempts,
    provenance,
) {
    const schedule = normalizeReplicationSchedule(command.replicationSchedule);
    const analysis = analyzeReplicationAttempts({ schedule, attempts });
    const measurementBySubject = new Map(
        provenance.measurements.map((measurement) => [
            measurement.subjectId,
            measurement,
        ]),
    );
    const controlSnapshotHashes = analysis.completeBlocks.flatMap(
        (block) => replicationBlockPlan(
            schedule,
            block.blockIndex,
        ).arms.filter((arm) => arm.armId === "control")
            .map((arm) =>
                measurementBySubject.get(arm.subjectId)
                    ?.snapshot?.snapshotHash ?? null),
    );
    if (controlSnapshotHashes.some((hash) => hash === null)) {
        throw new ReplicationScheduleError(
            "replicated evidence is missing a scheduled control artifact",
        );
    }
    return deriveReplicationControlBinding({
        contractHash: aggregate.contractHash,
        statisticalPolicy: aggregate.contract.statisticalPolicy,
        schedule,
        enumerandManifest:
            aggregate.contract.enumerandManifest ?? null,
        manifestOptions: {
            topology: aggregate.contract.enumerandManifest?.topology
                ?? aggregate.contract.hypothesisTopology,
            observableRegistry:
                aggregate.contract.observableRegistry,
            hypothesisPolicy:
                aggregate.contract.hypothesisPolicy,
        },
        controlSnapshotHashes,
        requireObservedControl: true,
    });
}

function validationControlBindings(aggregate, command) {
    try {
        return command.validationSeries.map((series) =>
            deriveReplicationControlBinding({
                contractHash: aggregate.contractHash,
                statisticalPolicy: aggregate.contract.statisticalPolicy,
                schedule: series.replicationSchedule,
                enumerandManifest:
                    aggregate.contract.enumerandManifest ?? null,
                manifestOptions: {
                    topology: aggregate.contract.enumerandManifest?.topology
                        ?? aggregate.contract.hypothesisTopology,
                    observableRegistry:
                        aggregate.contract.observableRegistry,
                    hypothesisPolicy:
                        aggregate.contract.hypothesisPolicy,
                },
            }));
    } catch (error) {
        if (!(error instanceof ReplicationScheduleError)) throw error;
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            `Validation control binding is invalid: ${error.message}`,
            error.details ?? null,
        );
    }
}

function parentPredictionEvidence(aggregate, claimPlan) {
    const parentIds = [...new Set(
        claimPlan.predictionBindings
            .map((binding) =>
                binding.reference?.kind === "assigned_parent"
                    ? binding.reference.evidenceId
                    : null)
            .filter((evidenceId) => evidenceId !== null),
    )].sort();
    const result = {};
    for (const evidenceId of parentIds) {
        const evidence = ownEntry(aggregate.evidence, evidenceId);
        const observation = evidence === null
            ? null
            : ownEntry(aggregate.observations, evidence.observationId);
        const command = observation === null
            ? null
            : ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
        if (evidence === null
            || observation === null
            || command?.kind !== "search_candidate"
            || observation.data?.series?.[0] === undefined) {
            result[evidenceId] = {
                evidenceId,
                evidenceHash: evidence?.commitEventHash ?? null,
                rawAuthorityDigest: evidence?.rawAuthorityDigest ?? null,
                scheduleHash: command?.replicationSchedule?.scheduleHash ?? null,
                invalidated: true,
                blocks: [],
            };
            continue;
        }
        const attempts = normalizedReplicatedCandidateAttempts(
            observation,
            command,
        );
        const analysis = analyzeReplicationAttempts({
            schedule: command.replicationSchedule,
            attempts,
        });
        const excluded = new Set(
            (evidence.statisticalEvaluation?.exclusions ?? [])
                .map((item) => item.blockIndex),
        );
        result[evidenceId] = {
            evidenceId,
            evidenceHash: evidence.commitEventHash,
            rawAuthorityDigest: evidence.rawAuthorityDigest,
            scheduleHash: command.replicationSchedule.scheduleHash,
            invalidated: evidence.invalidated === true,
            blocks: analysis.completeBlocks.map((block) => ({
                ...block.statisticalBlock,
                candidate: excluded.has(block.blockIndex)
                    ? null
                    : block.statisticalBlock.candidate,
            })),
        };
    }
    return result;
}

function validationAttemptInputs(aggregate, observation, evidenceId) {
    const prior = aggregate.validation.attemptEvidenceIds
        .map((priorEvidenceId) => ownEntry(aggregate.evidence, priorEvidenceId))
        .filter((evidence) =>
            evidence !== null
            && !evidence.invalidated
            && evidence.sourceKind === "harness"
            && evidence.purpose === "validation")
        .map((evidence) => ({
            evidenceId: evidence.evidenceId,
            observation: ownEntry(aggregate.observations, evidence.observationId),
        }));
    return [...prior, { evidenceId, observation }]
        .sort((left, right) =>
            left.observation.data.attemptIndex
            - right.observation.data.attemptIndex);
}

function validationEvaluation(aggregate, observation, evidenceId, command) {
    const attempts = validationAttemptInputs(
        aggregate,
        observation,
        evidenceId,
    );
    const caseById = new Map(
        aggregate.contract.validationCases.map((item) => [item.id, item]),
    );
    const evaluations = command.validationSeries.flatMap((series) => {
        const seriesAttempts = attempts.flatMap((item) => {
            const commandRecord = ownEntry(
                aggregate.commands,
                item.observation.commandId,
            )?.command ?? command;
            const commandSeries = commandRecord.validationSeries.find(
                (candidate) =>
                    candidate.role === series.role
                    && candidate.caseId === series.caseId,
            );
            const raw = item.observation.data.series.find(
                (candidate) =>
                    candidate.role === series.role
                    && candidate.caseId === series.caseId,
            );
            return normalizeRawMeasurementSeries(raw, {
                schedule: commandSeries.replicationSchedule,
                role: series.role,
                phase: "calibration",
                caseId: series.caseId,
            }).attempts;
        });
        const evaluation = evaluateReplicatedStatisticalClaims({
            contract: aggregate.contract,
            schedule: series.replicationSchedule,
            attempts: seriesAttempts,
            claims: aggregate.contract.validationClaimSet.claims,
            requiredClaimIds:
                aggregate.contract.validationClaimSet.requiredClaimIds,
        });
        const validationCase = caseById.get(series.caseId);
        const expectedState = validationCase.expectedClaimState;
        return series.coveredRoles.map((role) => ({
            role,
            executionRole: series.role,
            caseId: series.caseId,
            expectedState,
            actualState: evaluation.requiredState,
            satisfied: evaluation.completeValidBlocks
                && evaluation.requiredState === expectedState,
            evaluation,
        }));
    }).sort((left, right) =>
        `${left.role}\0${left.caseId}`.localeCompare(
            `${right.role}\0${right.caseId}`,
        ));
    const basisEvidenceIds = attempts.map((item) => item.evidenceId);
    return immutableCanonical({
        attemptIndex: observation.data.attemptIndex,
        attemptCount: attempts.length,
        basisEvidenceIds,
        satisfied: evaluations.length > 0
            && evaluations.every((item) => item.satisfied),
        evaluations,
    });
}

function candidateOutcome(evaluation) {
    if (evaluation.requiredState === "SUPPORTED") return "accepted";
    if (evaluation.requiredState === "REFUTED") return "rejected";
    if (evaluation.requiredState === "INVALID") return "invalid_metrics";
    return "inconclusive";
}

function candidateObservationContent(data) {
    return data.series[0].completeBlocks.map((block) => {
        const candidate = block.observations.find(
            (observation) => observation.armId === "candidate",
        );
        if (candidate?.parsed === null || candidate?.parsed === undefined) {
            return null;
        }
        const {
            role: _role,
            phase: _phase,
            replicateIndex: _replicateIndex,
            blockIndex: _blockIndex,
            armIndex: _armIndex,
            armId: _armId,
            deterministicSeed: _deterministicSeed,
            subjectId: _subjectId,
            environmentIdentity: _environmentIdentity,
            suiteIdentity: _suiteIdentity,
            parserVersion: _parserVersion,
            ...raw
        } = candidate.parsed;
        return raw;
    });
}

export function deriveEvidencePayload(aggregate, observation, evidenceId) {
    const harnessEvidence = observation.sourceKind === "harness";
    const candidateEvidence = harnessEvidence && observation.purpose === "candidate";
    const scientificRoleEvidence = harnessEvidence
        && (observation.purpose === "confirmation"
            || observation.purpose === "challenge");
    const replicatedEvidence = candidateEvidence || scientificRoleEvidence;
    const validationEvidence = harnessEvidence && observation.purpose === "validation";
    const command = ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
    const rawAuthorityDigest = harnessEvidence
        ? deriveRawObservationAuthorityDigest(
            aggregate,
            observation,
            command,
        )
        : null;
    const candidateAttempts = replicatedEvidence
        ? normalizedReplicatedCandidateAttempts(observation, command)
        : null;
    if (replicatedEvidence
        && (!Object.hasOwn(command, "hypotheses")
            || !canonicalEqual(
                observation.annotations?.hypotheses ?? null,
                command.hypotheses,
            ))) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Replicated evidence hypotheses do not match the kernel-frozen command",
        );
    }
    const claimPlan = replicatedEvidence
        ? createCandidateStatisticalClaimPlan({
            contract: aggregate.contract,
            hypotheses: command.hypotheses,
            assignedParentEvidenceIds:
                candidateEvidence ? command.parentEvidenceIds : [],
        })
        : null;
    const parentEvidence = candidateEvidence
        ? parentPredictionEvidence(aggregate, claimPlan)
        : {};
    const preparedCandidateEvaluation = replicatedEvidence
        ? prepareReplicatedStatisticalEvaluation({
            contract: aggregate.contract,
            schedule: command.replicationSchedule,
            attempts: candidateAttempts,
            parentEvidence,
        })
        : null;
    const candidateEvaluation = replicatedEvidence
        ? normalizedCandidateEvaluation(
            aggregate,
            command,
            candidateAttempts,
            claimPlan,
            parentEvidence,
            preparedCandidateEvaluation,
        )
        : null;
    const replicationProgress = replicatedEvidence
        ? evaluateReplicationProgress({
            contract: aggregate.contract,
            schedule: command.replicationSchedule,
            attempts: candidateAttempts,
            claims: claimPlan.acceptanceClaims,
            requiredClaimIds: claimPlan.acceptanceClaimIds,
        })
        : null;
    if (replicatedEvidence && replicationProgress.shouldContinue) {
        throw new TransitionError(
            ERROR_CODES.INVALID_EVIDENCE,
            "Replicated evidence stopped before its preregistered statistical stopping rule",
            {
                purpose: observation.purpose,
                blockCount: replicationProgress.blockCount,
                minBlocks: replicationProgress.minBlocks,
                maxBlocks: replicationProgress.maxBlocks,
                statisticalState: replicationProgress.statisticalState,
                goalMode:
                    aggregate.contract.statisticalPolicy.goalMode,
                stoppingDigest: replicationProgress.stoppingDigest,
            },
        );
    }
    let controlBinding = null;
    if (replicatedEvidence) {
        try {
            controlBinding = replicationControlBinding(
                aggregate,
                command,
                candidateAttempts,
                observation.receipt.provenance,
            );
        } catch (error) {
            if (!(error instanceof ReplicationScheduleError)) throw error;
            throw new TransitionError(
                ERROR_CODES.INVALID_EVIDENCE,
                `Replicated control binding is invalid: ${error.message}`,
                error.details ?? null,
            );
        }
    }
    const predictionEvaluation = candidateEvidence
        ? evaluateSealedPredictions({
            contract: aggregate.contract,
            schedule: command.replicationSchedule,
            attempts: candidateAttempts,
            claimPlan,
            parentEvidence,
            prepared: preparedCandidateEvaluation,
            evidenceId,
            rawAuthorityDigest,
        })
        : null;
    const accepted = candidateEvaluation?.requiredState === "SUPPORTED";
    const metrics = replicatedEvidence ? candidateEvaluation.metrics : null;
    const rankable = replicatedEvidence
        && aggregate.contract.metrics.every((metric) =>
            typeof metrics?.[metric.key] === "number"
            && Number.isFinite(metrics[metric.key]));
    const allPriorCandidates = aggregate.evidenceOrder
        .map((existingId) => ownEntry(aggregate.evidence, existingId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
            && evidence.purpose === "candidate");
    const outcomeClass = replicatedEvidence
        ? candidateOutcome(candidateEvaluation)
        : null;
    const validation = validationEvidence
        ? validationEvaluation(
            aggregate,
            observation,
            evidenceId,
            command,
        )
        : null;
    const validationControls = validationEvidence
        ? validationControlBindings(aggregate, command)
        : [];
    const candidateArtifactHash = replicatedEvidence
        ? observation.receipt.candidateArtifactHash
        : null;
    const replication = replicatedEvidence
        ? {
            version: 3,
            scheduleHash: candidateEvaluation.scheduleHash,
            minBlocks: replicationProgress.minBlocks,
            maxBlocks: replicationProgress.maxBlocks,
            blockCount: candidateEvaluation.blockCount,
            attemptCount: candidateEvaluation.attemptCount,
            blockLedgerHash:
                candidateEvaluation.blockLedger.hash,
            statisticalState: candidateEvaluation.requiredState,
            evaluationHash: candidateEvaluation.evaluationHash,
            stopping: replicationProgress.stopping,
            stoppingDigest: replicationProgress.stoppingDigest,
            control: controlBinding,
            controlTolerance: candidateEvaluation.controlTolerance,
        }
        : null;
    const statisticalCacheCore = replicatedEvidence
        ? {
            version: 2,
            purpose: observation.purpose,
            replication,
            metrics,
            rankable,
            outcomeClass,
            acceptanceSatisfied: accepted,
            statisticalEvaluation: candidateEvaluation,
            predictionEvaluation,
        }
        : validationEvidence
            ? {
                version: 1,
                purpose: "validation",
                validationAttemptIndex: validation.attemptIndex,
                validationBasisEvidenceIds: validation.basisEvidenceIds,
                validationEvaluation: validation,
                validationSatisfied: validation.satisfied,
                validationControlBindings: validationControls,
            }
            : null;
    return {
        evidenceId,
        observationId: observation.observationId,
        sourceKind: observation.sourceKind,
        purpose: observation.purpose,
        harnessId: observation.harnessId,
        parserVersion: observation.parserVersion,
        receipt: observation.receipt,
        provenanceRoot: harnessEvidence
            ? observation.receipt.provenance.closureRoot
            : null,
        contentHash: hashCanonical(
            replicatedEvidence
                ? candidateObservationContent(observation.data)
                : observation.data,
        ),
        round: candidateEvidence ? observation.round : null,
        slotIndex: candidateEvidence ? observation.slotIndex : null,
        candidateId: replicatedEvidence ? observation.candidateId : null,
        model: candidateEvidence ? command.model : null,
        operator: candidateEvidence ? command.operator : null,
        parentEvidenceIds: candidateEvidence ? command.parentEvidenceIds : [],
        promptContextRefs: candidateEvidence ? command.promptContextRefs : [],
        seed: candidateEvidence ? command.seed : null,
        rawAuthorityDigest,
        statisticalCacheDigest: statisticalCacheCore === null
            ? null
            : deriveStatisticalCacheDigest(statisticalCacheCore),
        replication,
        boundedCandidateId: candidateEvidence ? (command.boundedCandidateId ?? null) : null,
        ...(candidateEvidence && command?.enumerand !== undefined
            ? {
                enumerandOrdinal: command.enumerand.ordinal,
                enumerandHash: command.enumerand.enumerandHash,
                enumerandManifestRoot: command.enumerand.manifestRoot,
            }
            : {}),
        metrics,
        rankable,
        outcomeClass,
        acceptanceSatisfied: accepted,
        statisticalEvaluation: candidateEvaluation,
        hypothesesIdentity:
            claimPlan?.hypothesesIdentity ?? null,
        predictionEvaluation,
        annotations: replicatedEvidence ? observation.annotations : null,
        duplicateOf: candidateEvidence
            ? duplicateEvidenceId(allPriorCandidates, candidateArtifactHash)
            : null,
        ...(scientificRoleEvidence
            ? {
                confirmationFreezeHash:
                    command.confirmationFreezeHash,
                candidateEvidenceId: command.candidateEvidenceId,
                candidateEvidenceHash: command.candidateEvidenceHash,
                roleManifestHash: command.roleManifestHash,
                protocolManifestHash: command.protocolManifestHash,
            }
            : {}),
        validationAttemptIndex: validation?.attemptIndex ?? null,
        validationBasisEvidenceIds: validation?.basisEvidenceIds ?? [],
        validationEvaluation: validation,
        validationSatisfied: validation?.satisfied ?? false,
        validationControlBindings: validationControls,
        unreachableBasis: deriveCertificateBasis(aggregate, observation),
    };
}

function deriveCertificateBasis(aggregate, observation) {
    if (observation.sourceKind !== "harness" || observation.purpose !== "impossibility") {
        return null;
    }
    const command = ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
    const data = observation.data;
    const receipt = observation.receipt;
    const measurement = receipt.provenance.measurements[0];
    const certificateArtifact = receipt.provenance.impossibilityCertificateArtifact;
    const execution = verifiedImpossibilityExecutionFor(
        aggregate,
        observation.observationId,
        observation.verifierExecution ?? null,
    );
    const facts = execution?.facts ?? null;
    if (aggregate.contract.hypothesisTopology === "certified_impossibility"
        && command?.kind === "verify_impossibility"
        && execution !== null
        && data?.checkerStatus === "VERIFIED"
        && data?.certificateVerdict === "target_unreachable"
        && facts?.status === "VERIFIED"
        && facts?.verdict === "target_unreachable"
        && data.certificateVersion === aggregate.contract.impossibilityPolicy?.certificateVersion
        && data.verificationRequestHash === command.requestHash
        && data.proposedCertificateArtifactHash
            === command.proposedCertificateArtifactHash
        && facts.requestHash === command.requestHash
        && facts.proposedCertificateArtifactHash
            === command.proposedCertificateArtifactHash
        && facts.proofArtifactHash === command.proofArtifactHash
        && command.proofArtifactHash
            !== command.proposedCertificateArtifactHash
        && facts.coverageClosureRoot
            === command.request.evidence.coverageClosureRoot
        && facts.complete === true
        && facts.disagreementCount === 0
        && isAlgorithmTaggedSha256(facts.factsRoot)
        && data.certificateArtifactHash === receipt?.certificateArtifactHash
        && data.measurementReceiptHash === receipt?.measurementReceiptHash
        && data.verificationSnapshotHash === receipt?.verificationSnapshotHash
        && isAlgorithmTaggedSha256(data.certificateArtifactHash)
        && isAlgorithmTaggedSha256(data.measurementReceiptHash)
        && isAlgorithmTaggedSha256(data.verificationRequestHash)
        && isAlgorithmTaggedSha256(data.verificationSnapshotHash)
        && isAlgorithmTaggedSha256(data.proposedCertificateArtifactHash)
        && isAlgorithmTaggedSha256(receipt.measurementReceiptArtifactHash)
        && isAlgorithmTaggedSha256(receipt.rawStdoutArtifactHash)
        && isAlgorithmTaggedSha256(receipt.rawStderrArtifactHash)
        && certificateArtifact !== null
        && objectIdMatchesTaggedHash(certificateArtifact, data.certificateArtifactHash)
        && objectIdMatchesTaggedHash(
            measurement.receiptArtifact,
            receipt.measurementReceiptArtifactHash,
        )
        && objectIdMatchesTaggedHash(
            measurement.rawStdoutArtifact,
            receipt.rawStdoutArtifactHash,
        )
        && objectIdMatchesTaggedHash(
            measurement.rawStderrArtifact,
            receipt.rawStderrArtifactHash,
        )
        && execution.measurement.receiptHash
            === measurement.receiptHash
        && execution.measurement.rawStdoutArtifact.artifactId
            === measurement.rawStdoutArtifact.artifactId
        && execution.measurement.rawStderrArtifact.artifactId
            === measurement.rawStderrArtifact.artifactId
        && execution.certificate.artifact.artifactId
            === certificateArtifact.artifactId) {
        return {
            kind: "v4_unreachable",
            topology: "certified_impossibility",
            checkerStatus: data.checkerStatus,
            certificateVersion: data.certificateVersion,
            certificateVerdict: data.certificateVerdict,
            verificationMode: facts.mode,
            verifierRoleIdentity:
                command.request.verifier.roleIdentity,
            independenceAttestation:
                command.request.verifier.independenceAttestation,
            independenceClassification:
                "operator_attested_separate_implementation",
            mathematicalIndependenceProven: false,
            verifierExecutionIdentity:
                execution.executionIdentity.identity,
            verifierFactsRoot: facts.factsRoot,
            certificateArtifactHash: data.certificateArtifactHash,
            certificateArtifactId: certificateArtifact.artifactId,
            measurementReceiptHash: data.measurementReceiptHash,
            measurementReceiptArtifactHash: receipt.measurementReceiptArtifactHash,
            measurementReceiptArtifactId: measurement.receiptArtifact.artifactId,
            rawStdoutArtifactHash: receipt.rawStdoutArtifactHash,
            rawStdoutArtifactId: measurement.rawStdoutArtifact.artifactId,
            rawStderrArtifactHash: receipt.rawStderrArtifactHash,
            rawStderrArtifactId: measurement.rawStderrArtifact.artifactId,
            verificationRequestHash: data.verificationRequestHash,
            proposedCertificateArtifactHash:
                data.proposedCertificateArtifactHash,
            proofArtifactHash: facts.proofArtifactHash,
            proofArtifactId: execution.proof.artifact.artifactId,
            proofCheckerIdentity:
                facts.proofCheckerReceipt?.proofCheckerIdentity ?? null,
            proofValidationReceiptHash:
                facts.proofCheckerReceipt?.receiptHash ?? null,
            validatedProofArtifactHash:
                facts.mode === "certificate_validation"
                    ? facts.proofArtifactHash
                    : null,
            verificationSnapshotHash: data.verificationSnapshotHash,
            coverageClosureRoot: facts.coverageClosureRoot,
            enumerandManifestRoot: facts.enumerandManifestRoot,
            enumerandCount: facts.enumerandCount,
            checkedEnumerandCount: facts.checkedEnumerandCount,
            evidenceRoots: facts.evidenceRoots,
            alphaLedgerRoot: facts.alphaLedgerRoot,
            checkerEvidenceRoot: facts.checkerEvidenceRoot,
            enumerandResultsRoot: hashCanonical(
                facts.enumerandObservations,
                "sha256:crucible-verified-impossibility-enumerand-results-v1",
            ),
            receiptRoot: measurement.measurementRoot,
            provenanceRoot: receipt.provenance.closureRoot,
        };
    }
    return null;
}
