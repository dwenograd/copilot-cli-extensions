import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    acceptanceSatisfied,
    candidateMetricValues,
    candidateMetricsRankable,
    validationSatisfied,
} from "./contract.mjs";
import {
    classifyCandidateOutcome,
    duplicateEvidenceId,
} from "./archive.mjs";
import { ERROR_CODES, TransitionError } from "./errors.mjs";

export const EVIDENCE_PROVENANCE_VERSION = 1;
export const SNAPSHOT_PROVENANCE_HASH_ALGORITHM =
    "sha256:crucible-evidence-snapshot-provenance-v1";
export const MEASUREMENT_PROVENANCE_HASH_ALGORITHM =
    "sha256:crucible-evidence-measurement-provenance-v1";
export const EVIDENCE_PROVENANCE_HASH_ALGORITHM =
    "sha256:crucible-evidence-provenance-v1";
export const SNAPSHOT_EXECUTION_HASH_ALGORITHM =
    "sha256:crucible-evidence-snapshot-execution-v1";
export const OBSERVATION_STREAM_HASH_ALGORITHM =
    "sha256:crucible-runtime-observation-streams-v1";

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
    "rawStderrArtifact",
    "rawStderrHash",
    "rawStdoutArtifact",
    "rawStdoutHash",
    "receiptArtifact",
    "receiptHash",
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
        return (command?.validationCases ?? contract?.validationCases ?? [])
            .map((item) => item.id)
            .sort();
    }
    if (purpose === "candidate") {
        return [command?.candidateId ?? null];
    }
    if (purpose === "impossibility") {
        return [`impossibility-${command?.attemptOrdinal ?? ""}`];
    }
    return [];
}

function assertPurposeShape(provenance, { purpose, command, contract }) {
    const subjects = provenance.measurements.map((item) => item.subjectId);
    const expectedSubjects = expectedMeasurementSubjects(purpose, command, contract);
    if (!canonicalEqual(subjects, expectedSubjects)) {
        fail("receipt.provenance measurements do not match the reserved command subjects", {
            purpose,
            subjects,
            expectedSubjects,
        });
    }
    if (provenance.measurements.some((item) =>
        item.parserVersion !== contract?.parserVersion)) {
        fail("receipt.provenance parser identity does not match the frozen contract");
    }
    if (purpose === "validation") {
        if (provenance.proposalArtifact !== null
            || provenance.promptContextHash !== null
            || provenance.impossibilityCertificateArtifact !== null
            || provenance.measurementReuseArtifact !== null
            || provenance.validationCompositeArtifact === null) {
            fail("Validation provenance has an invalid purpose-specific artifact shape");
        }
        const byId = new Map(
            (command?.validationCases ?? contract?.validationCases ?? [])
                .map((item) => [item.id, item]),
        );
        for (const measurement of provenance.measurements) {
            if (measurement.snapshot.manifestArtifact.objectId
                !== byId.get(measurement.subjectId)?.artifactHash) {
                fail("Validation provenance snapshot does not match the frozen case artifact");
            }
        }
        return;
    }
    if (purpose === "candidate") {
        if (provenance.proposalArtifact === null
            || provenance.promptContextHash === null
            || provenance.validationCompositeArtifact !== null
            || provenance.impossibilityCertificateArtifact !== null) {
            fail("Candidate provenance has an invalid purpose-specific artifact shape");
        }
        return;
    }
    if (purpose === "impossibility") {
        if (provenance.proposalArtifact !== null
            || provenance.promptContextHash !== null
            || provenance.validationCompositeArtifact !== null
            || provenance.measurementReuseArtifact !== null
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

export function artifactIdsFromProvenance(provenance) {
    return artifactRefsFromProvenance(provenance)
        .map((artifact) => artifact.artifactId)
        .sort();
}

function ownEntry(record, key) {
    return Object.hasOwn(record, key) ? record[key] : null;
}

export function deriveEvidencePayload(aggregate, observation, evidenceId) {
    const harnessEvidence = observation.sourceKind === "harness";
    const candidateEvidence = harnessEvidence && observation.purpose === "candidate";
    const validationEvidence = harnessEvidence && observation.purpose === "validation";
    const accepted = candidateEvidence
        && acceptanceSatisfied(aggregate.contract.acceptancePredicate, observation.data);
    const metrics = candidateEvidence
        ? candidateMetricValues(aggregate.contract.metrics, observation.data)
        : null;
    const rankable = candidateEvidence
        && candidateMetricsRankable(aggregate.contract.metrics, metrics);
    const allPriorCandidates = aggregate.evidenceOrder
        .map((existingId) => ownEntry(aggregate.evidence, existingId))
        .filter((evidence) =>
            evidence !== null
            && evidence.sourceKind === "harness"
            && evidence.purpose === "candidate");
    const priorCandidates = allPriorCandidates.filter((evidence) => !evidence.invalidated);
    const outcomeClass = candidateEvidence
        ? classifyCandidateOutcome(aggregate.contract, observation.data, {
            metrics,
            rankable,
            accepted,
            priorCandidates,
        })
        : null;
    const command = ownEntry(aggregate.commands, observation.commandId)?.command ?? null;
    const candidateArtifactHash = candidateEvidence
        ? observation.receipt.candidateArtifactHash
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
        contentHash: hashCanonical(observation.data),
        round: candidateEvidence ? observation.round : null,
        slotIndex: candidateEvidence ? observation.slotIndex : null,
        candidateId: candidateEvidence ? observation.candidateId : null,
        model: candidateEvidence ? command.model : null,
        operator: candidateEvidence ? command.operator : null,
        parentEvidenceIds: candidateEvidence ? command.parentEvidenceIds : [],
        promptContextRefs: candidateEvidence ? command.promptContextRefs : [],
        seed: candidateEvidence ? command.seed : null,
        boundedCandidateId: candidateEvidence ? (command.boundedCandidateId ?? null) : null,
        metrics,
        rankable,
        outcomeClass,
        acceptanceSatisfied: accepted,
        annotations: candidateEvidence ? observation.annotations : null,
        duplicateOf: candidateEvidence
            ? duplicateEvidenceId(allPriorCandidates, candidateArtifactHash)
            : null,
        validationSatisfied: validationEvidence
            && validationSatisfied(aggregate.contract.validationCases, observation.data),
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
    if (aggregate.contract.hypothesisTopology === "certified_impossibility"
        && command?.kind === "verify_impossibility"
        && data?.certificateVerdict === "target_unreachable"
        && data.certificateVersion === aggregate.contract.impossibilityPolicy?.certificateVersion
        && data.verificationRequestHash === command.requestHash
        && data.certificateArtifactHash === receipt?.certificateArtifactHash
        && data.measurementReceiptHash === receipt?.measurementReceiptHash
        && data.verificationSnapshotHash === receipt?.verificationSnapshotHash
        && isAlgorithmTaggedSha256(data.certificateArtifactHash)
        && isAlgorithmTaggedSha256(data.measurementReceiptHash)
        && isAlgorithmTaggedSha256(data.verificationRequestHash)
        && isAlgorithmTaggedSha256(data.verificationSnapshotHash)
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
        )) {
        return {
            kind: "verified_impossibility_certificate",
            topology: "certified_impossibility",
            certificateVersion: data.certificateVersion,
            certificateVerdict: data.certificateVerdict,
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
            verificationSnapshotHash: data.verificationSnapshotHash,
            receiptRoot: measurement.measurementRoot,
            provenanceRoot: receipt.provenance.closureRoot,
        };
    }
    return null;
}
