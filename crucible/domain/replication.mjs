import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "./canonical.mjs";
import {
    enumerandArtifactMeasurementHash,
    enumerandBindingHash,
    resolveControlEnumerand,
} from "./enumerands.mjs";

export const REPLICATION_SCHEDULE_VERSION = 1;
export const REPLICATION_SCHEDULE_ALGORITHM =
    "balanced-cyclic-blocks-v1";
export const REPLICATION_SCHEDULE_HASH_ALGORITHM =
    "sha256:crucible-replication-schedule-v1";
export const REPLICATION_SUBJECT_HASH_ALGORITHM =
    "sha256:crucible-replication-subject-v1";
export const REPLICATION_SCHEDULE_SEED_HASH_ALGORITHM =
    "sha256:crucible-replication-schedule-seed-v1";
export const REPLICATION_BLOCK_SEED_HASH_ALGORITHM =
    "sha256:crucible-replication-block-seed-v1";
export const REPLICATION_ARM_SEED_HASH_ALGORITHM =
    "sha256:crucible-replication-arm-seed-v1";
export const REPLICATION_MEASUREMENT_SUBJECT_HASH_ALGORITHM =
    "sha256:crucible-replication-measurement-subject-v1";
export const REPLICATION_CONTROL_BINDING_HASH_ALGORITHM =
    "sha256:crucible-replication-control-binding-v1";
export const RAW_MEASUREMENT_SERIES_VERSION = 1;

const SAFE_ID = /^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$/u;
const OBJECT_ID = /^sha256:[a-f0-9]{64}$/u;
const SUBJECT_KINDS = new Set([
    "calibration",
    "candidate",
    "enumerand",
    "snapshot",
    "assigned_parent",
]);
const SCHEDULE_KEYS = Object.freeze([
    "algorithm",
    "arms",
    "baseArmOrder",
    "contractHash",
    "control",
    "frozenBlockSeed",
    "maxBlocks",
    "minBlocks",
    "scheduleHash",
    "scheduleSeed",
    "subject",
    "version",
]);
const SUBJECT_KEYS = Object.freeze(["id", "identity", "index", "kind"]);
const CONTROL_KEYS = Object.freeze(["identity", "kind"]);
const ARM_KEYS = Object.freeze([
    "armId",
    "armIndex",
    "logicalSubjectId",
    "subjectIdentity",
    "subjectKind",
]);

export class ReplicationScheduleError extends Error {
    constructor(message, details = null) {
        super(message);
        this.name = "ReplicationScheduleError";
        this.code = "CRUCIBLE_REPLICATION_SCHEDULE_INVALID";
        if (details !== null) this.details = details;
    }
}

function fail(message, details = null) {
    throw new ReplicationScheduleError(message, details);
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

function requireExactKeys(value, field, keys) {
    const input = requirePlainObject(value, field);
    const actual = Object.keys(input).sort();
    const expected = [...keys].sort();
    if (!canonicalEqual(actual, expected)) {
        fail(`${field} must contain exactly the canonical fields`, {
            field,
            expected,
            actual,
        });
    }
    return input;
}

function requireSafeId(value, field) {
    if (typeof value !== "string"
        || !SAFE_ID.test(value)
        || value === "."
        || value === ".."
        || value.endsWith(".")) {
        fail(`${field} must be a safe lowercase identifier`, { field, value });
    }
    return value;
}

function requirePositiveInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        fail(`${field} must be a positive safe integer`, { field, value, maximum });
    }
    return value;
}

function requireNonNegativeInteger(value, field) {
    if (!Number.isSafeInteger(value) || value < 0) {
        fail(`${field} must be a non-negative safe integer`, { field, value });
    }
    return value;
}

function requireHash(value, field) {
    if (!isAlgorithmTaggedSha256(value) && !OBJECT_ID.test(value)) {
        fail(`${field} must be a SHA-256 identity`, { field, value });
    }
    return value;
}

function requireText(value, field, maximum = 512) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > maximum
        || value.includes("\0")) {
        fail(`${field} must be a non-empty bounded string`, { field });
    }
    return value;
}

function normalizeSubject(value, field = "subject") {
    const input = requireExactKeys(value, field, SUBJECT_KEYS);
    if (input.kind !== "candidate"
        && input.kind !== "enumerand"
        && input.kind !== "calibration") {
        fail(`${field}.kind must be candidate, enumerand, or calibration`, {
            field,
            value: input.kind,
        });
    }
    return {
        kind: input.kind,
        index: requireNonNegativeInteger(input.index, `${field}.index`),
        id: requireSafeId(input.id, `${field}.id`),
        identity: requireHash(input.identity, `${field}.identity`),
    };
}

function normalizeControl(value, field = "control") {
    const input = requireExactKeys(value, field, CONTROL_KEYS);
    if (input.kind !== "snapshot" && input.kind !== "enumerand") {
        fail(`${field}.kind must be snapshot or enumerand`, {
            field,
            value: input.kind,
        });
    }
    return {
        kind: input.kind,
        identity: requireHash(input.identity, `${field}.identity`),
    };
}

function normalizeArm(value, index, field = `arms[${index}]`) {
    const input = requireExactKeys(value, field, ARM_KEYS);
    if (!SUBJECT_KINDS.has(input.subjectKind)) {
        fail(`${field}.subjectKind is not supported`, {
            field,
            value: input.subjectKind,
        });
    }
    return {
        armId: requireSafeId(input.armId, `${field}.armId`),
        armIndex: requireNonNegativeInteger(input.armIndex, `${field}.armIndex`),
        logicalSubjectId: requireSafeId(
            input.logicalSubjectId,
            `${field}.logicalSubjectId`,
        ),
        subjectKind: input.subjectKind,
        subjectIdentity: requireHash(
            input.subjectIdentity,
            `${field}.subjectIdentity`,
        ),
    };
}

function normalizeArms(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
        fail("arms must contain 1..16 declared measurement arms");
    }
    const arms = value.map((arm, index) => normalizeArm(arm, index))
        .sort((left, right) => left.armIndex - right.armIndex);
    for (let index = 0; index < arms.length; index += 1) {
        if (arms[index].armIndex !== index) {
            fail("arm indexes must be unique and contiguous from zero", {
                expected: index,
                actual: arms[index].armIndex,
            });
        }
    }
    if (new Set(arms.map((arm) => arm.armId)).size !== arms.length
        || new Set(arms.map((arm) => arm.logicalSubjectId)).size !== arms.length) {
        fail("arm ids and logical subject ids must be unique");
    }
    return arms;
}

function stableArmPermutation(scheduleSeed, arms) {
    return arms.map((arm) => ({
        armIndex: arm.armIndex,
        rank: hashCanonical({
            scheduleSeed,
            armId: arm.armId,
            armIndex: arm.armIndex,
            subjectIdentity: arm.subjectIdentity,
        }, "sha256:crucible-replication-arm-order-v1"),
    })).sort((left, right) => {
        const rank = left.rank.localeCompare(right.rank);
        return rank === 0 ? left.armIndex - right.armIndex : rank;
    }).map((item) => item.armIndex);
}

function scheduleCore({
    contractHash,
    subject,
    control,
    frozenBlockSeed,
    minBlocks,
    maxBlocks,
    arms,
}) {
    const scheduleSeed = hashCanonical({
        algorithm: REPLICATION_SCHEDULE_ALGORITHM,
        contractHash,
        subject,
        control,
        frozenBlockSeed,
        minBlocks,
        maxBlocks,
        arms,
    }, REPLICATION_SCHEDULE_SEED_HASH_ALGORITHM);
    return {
        version: REPLICATION_SCHEDULE_VERSION,
        algorithm: REPLICATION_SCHEDULE_ALGORITHM,
        contractHash,
        subject,
        control,
        frozenBlockSeed,
        minBlocks,
        maxBlocks,
        scheduleSeed,
        arms,
        baseArmOrder: stableArmPermutation(scheduleSeed, arms),
    };
}

export function deriveReplicationSubjectIdentity({
    contractHash,
    candidateId,
    candidateSeed,
    enumerandHash = null,
}) {
    requireHash(contractHash, "contractHash");
    requireSafeId(candidateId, "candidateId");
    if (enumerandHash !== null) {
        return requireHash(enumerandHash, "enumerandHash");
    }

    if ((typeof candidateSeed !== "string" || candidateSeed.length === 0)
        && (!Number.isSafeInteger(candidateSeed) || candidateSeed < 0)) {
        fail("candidateSeed must be a non-empty string or non-negative safe integer", {
            candidateSeed,
        });
    }
    return hashCanonical({
        contractHash,
        candidateId,
        candidateSeed,
    }, REPLICATION_SUBJECT_HASH_ALGORITHM);
}

export function statisticalSubjectIndex(kind, index) {
    if (!Number.isSafeInteger(index) || index < 0) {
        fail("statistical subject index input must be a non-negative safe integer", {
            kind,
            index,
        });
    }
    if (kind !== "calibration"
        && kind !== "candidate"
        && kind !== "enumerand") {
        fail("statistical subject kind is unsupported", { kind });
    }
    const doubled = index * 2;
    const result = kind === "calibration" ? doubled : doubled + 1;
    if (!Number.isSafeInteger(result)) {
        fail("statistical subject index is not a safe integer", { kind, index });
    }
    return result;
}

export function deriveReplicationSchedule({
    contractHash,
    statisticalPolicy,
    subject,
    arms = null,
}) {
    const normalizedContractHash = requireHash(contractHash, "contractHash");
    const policy = requirePlainObject(statisticalPolicy, "statisticalPolicy");
    const normalizedSubject = normalizeSubject(subject);
    const control = normalizeControl({
        kind: policy.control?.kind,
        identity: policy.control?.identity,
    }, "statisticalPolicy.control");
    const minBlocks = requirePositiveInteger(
        policy.minBlocks,
        "statisticalPolicy.minBlocks",
    );
    const maxBlocks = requirePositiveInteger(
        policy.maxBlocks,
        "statisticalPolicy.maxBlocks",
    );
    if (minBlocks > maxBlocks) {
        fail("statisticalPolicy.minBlocks cannot exceed maxBlocks");
    }
    const frozenBlockSeed = requireText(
        policy.deterministicBlockSeed,
        "statisticalPolicy.deterministicBlockSeed",
    );
    const normalizedArms = normalizeArms(arms ?? [
        {
            armId: "candidate",
            armIndex: 0,
            logicalSubjectId: normalizedSubject.id,
            subjectKind: normalizedSubject.kind,
            subjectIdentity: normalizedSubject.identity,
        },
        {
            armId: "control",
            armIndex: 1,
            logicalSubjectId: "control",
            subjectKind: control.kind,
            subjectIdentity: control.identity,
        },
    ]);
    const controlArms = normalizedArms.filter((arm) => arm.armId === "control");
    if (controlArms.some((arm) =>
        arm.logicalSubjectId !== "control"
        || arm.subjectKind !== control.kind
        || arm.subjectIdentity !== control.identity)) {
        fail("control arms must match the frozen statistical control identity", {
            control,
            controlArms,
        });
    }
    const core = scheduleCore({
        contractHash: normalizedContractHash,
        subject: normalizedSubject,
        control,
        frozenBlockSeed,
        minBlocks,
        maxBlocks,
        arms: normalizedArms,
    });
    return immutableCanonical({
        ...core,
        scheduleHash: hashCanonical(core, REPLICATION_SCHEDULE_HASH_ALGORITHM),
    });
}

export function normalizeReplicationSchedule(value) {
    const input = requireExactKeys(value, "replicationSchedule", SCHEDULE_KEYS);
    if (input.version !== REPLICATION_SCHEDULE_VERSION
        || input.algorithm !== REPLICATION_SCHEDULE_ALGORITHM) {
        fail("replicationSchedule version or algorithm is unsupported", {
            version: input.version,
            algorithm: input.algorithm,
        });
    }
    const subject = normalizeSubject(input.subject, "replicationSchedule.subject");
    const control = normalizeControl(input.control, "replicationSchedule.control");
    const minBlocks = requirePositiveInteger(
        input.minBlocks,
        "replicationSchedule.minBlocks",
    );
    const maxBlocks = requirePositiveInteger(
        input.maxBlocks,
        "replicationSchedule.maxBlocks",
    );
    if (minBlocks > maxBlocks) {
        fail("replicationSchedule.minBlocks cannot exceed maxBlocks");
    }
    const arms = normalizeArms(input.arms);
    if (!Array.isArray(input.baseArmOrder)
        || input.baseArmOrder.length !== arms.length
        || input.baseArmOrder.some((item) =>
            !Number.isSafeInteger(item) || item < 0 || item >= arms.length)
        || new Set(input.baseArmOrder).size !== arms.length) {
        fail("replicationSchedule.baseArmOrder must be a complete arm permutation");
    }
    const core = scheduleCore({
        contractHash: requireHash(
            input.contractHash,
            "replicationSchedule.contractHash",
        ),
        subject,
        control,
        frozenBlockSeed: requireText(
            input.frozenBlockSeed,
            "replicationSchedule.frozenBlockSeed",
        ),
        minBlocks,
        maxBlocks,
        arms,
    });
    if (input.scheduleSeed !== core.scheduleSeed
        || !canonicalEqual(input.baseArmOrder, core.baseArmOrder)) {
        fail("replicationSchedule seed or balanced base order is not derived canonically");
    }
    const scheduleHash = hashCanonical(core, REPLICATION_SCHEDULE_HASH_ALGORITHM);
    if (input.scheduleHash !== scheduleHash) {
        fail("replicationSchedule.scheduleHash is invalid", {
            expected: scheduleHash,
            actual: input.scheduleHash,
        });
    }
    return immutableCanonical({ ...core, scheduleHash });
}

export function assertReplicationScheduleMatches({
    schedule,
    contractHash,
    statisticalPolicy,
    subject,
    arms = null,
}) {
    const normalized = normalizeReplicationSchedule(schedule);
    const expected = deriveReplicationSchedule({
        contractHash,
        statisticalPolicy,
        subject,
        arms,
    });
    if (!canonicalEqual(normalized, expected)) {
        fail("replication schedule does not match the frozen contract and subject");
    }
    return normalized;
}

export function assertReplicationSchedulePolicyBinding({
    schedule,
    contractHash,
    statisticalPolicy,
}) {
    const normalized = normalizeReplicationSchedule(schedule);
    const policy = requirePlainObject(statisticalPolicy, "statisticalPolicy");
    const control = normalizeControl({
        kind: policy.control?.kind,
        identity: policy.control?.identity,
    }, "statisticalPolicy.control");
    const minBlocks = requirePositiveInteger(
        policy.minBlocks,
        "statisticalPolicy.minBlocks",
    );
    const maxBlocks = requirePositiveInteger(
        policy.maxBlocks,
        "statisticalPolicy.maxBlocks",
    );
    const frozenBlockSeed = requireText(
        policy.deterministicBlockSeed,
        "statisticalPolicy.deterministicBlockSeed",
    );
    const controlArms = normalized.arms.filter((arm) => arm.armId === "control");
    if (normalized.contractHash !== requireHash(contractHash, "contractHash")
        || normalized.minBlocks !== minBlocks
        || normalized.maxBlocks !== maxBlocks
        || normalized.frozenBlockSeed !== frozenBlockSeed
        || !canonicalEqual(normalized.control, control)
        || controlArms.some((arm) =>
            arm.logicalSubjectId !== "control"
            || arm.subjectKind !== control.kind
            || arm.subjectIdentity !== control.identity)) {
        fail("replication schedule is not bound to the frozen statistical policy", {
            scheduleHash: normalized.scheduleHash,
            expected: {
                contractHash,
                control,
                minBlocks,
                maxBlocks,
                frozenBlockSeed,
            },
        });
    }
    return normalized;
}

export function deriveReplicationControlBinding({
    contractHash,
    statisticalPolicy,
    schedule,
    enumerandManifest = null,
    manifestOptions = {},
    controlSnapshotHashes = [],
    requireObservedControl = false,
}) {
    const normalizedSchedule = assertReplicationSchedulePolicyBinding({
        schedule,
        contractHash,
        statisticalPolicy,
    });
    if (!Array.isArray(controlSnapshotHashes)) {
        fail("controlSnapshotHashes must be an array");
    }
    const observed = controlSnapshotHashes.map((value, index) =>
        requireHash(value, `controlSnapshotHashes[${index}]`));
    const uniqueObserved = [...new Set(observed)].sort();
    const hasControlArm = normalizedSchedule.arms.some(
        (arm) => arm.armId === "control",
    );
    if (uniqueObserved.length > 1
        || (requireObservedControl
            && (!hasControlArm || uniqueObserved.length !== 1))
        || (!hasControlArm && uniqueObserved.length !== 0)) {
        fail("control measurements do not identify one stable frozen control artifact", {
            scheduleHash: normalizedSchedule.scheduleHash,
            hasControlArm,
            controlSnapshotHashes: uniqueObserved,
        });
    }

    const policyControl = normalizedSchedule.control;
    let expectedArtifactHash = null;
    let manifestRoot = null;
    let bindingHash = null;
    if (policyControl.kind === "snapshot") {
        expectedArtifactHash = enumerandArtifactMeasurementHash(
            policyControl.identity,
        );
    } else {
        if (enumerandManifest === null || enumerandManifest === undefined) {
            fail("enumerand control requires the frozen enumerand manifest");
        }
        const binding = resolveControlEnumerand(
            enumerandManifest,
            manifestOptions,
        );
        if (binding.kind === "reference"
            || binding.enumerandHash !== policyControl.identity) {
            fail("frozen control enumerand does not match the statistical policy", {
                expected: policyControl,
                actual: binding,
            });
        }
        manifestRoot = binding.manifestRoot;
        bindingHash = enumerandBindingHash(binding, manifestOptions);
        if (binding.topology === "finite_enumerable") {
            expectedArtifactHash = enumerandArtifactMeasurementHash(
                binding.artifactSnapshotHash,
            );
        }
    }
    const artifactHash = uniqueObserved[0] ?? null;
    if (expectedArtifactHash !== null
        && artifactHash !== null
        && artifactHash !== expectedArtifactHash) {
        fail("control measurement used an artifact outside the frozen control", {
            expectedArtifactHash,
            actualArtifactHash: artifactHash,
            control: policyControl,
        });
    }
    const core = {
        version: 1,
        scheduleHash: normalizedSchedule.scheduleHash,
        kind: policyControl.kind,
        identity: policyControl.identity,
        manifestRoot,
        bindingHash,
        expectedArtifactHash,
        artifactHash,
    };
    return immutableCanonical({
        ...core,
        controlBindingHash: hashCanonical(
            core,
            REPLICATION_CONTROL_BINDING_HASH_ALGORITHM,
        ),
    });
}

function paddedOrdinal(value, width) {
    return String(value).padStart(width, "0");
}

export function replicationBlockPlan(schedule, blockIndex) {
    const normalized = normalizeReplicationSchedule(schedule);
    requireNonNegativeInteger(blockIndex, "blockIndex");
    if (blockIndex >= normalized.maxBlocks) {
        fail("blockIndex is outside the frozen replication schedule", {
            blockIndex,
            maxBlocks: normalized.maxBlocks,
        });
    }
    const replicateIndex = blockIndex;
    const rotation = blockIndex % normalized.arms.length;
    const executionOrder = [
        ...normalized.baseArmOrder.slice(rotation),
        ...normalized.baseArmOrder.slice(0, rotation),
    ];
    const blockSeed = hashCanonical({
        scheduleHash: normalized.scheduleHash,
        scheduleSeed: normalized.scheduleSeed,
        blockIndex,
        replicateIndex,
    }, REPLICATION_BLOCK_SEED_HASH_ALGORITHM);
    const byIndex = new Map(normalized.arms.map((arm) => [arm.armIndex, arm]));
    const arms = executionOrder.map((armIndex, executionOrdinal) => {
        const arm = byIndex.get(armIndex);
        const deterministicSeed = hashCanonical({
            scheduleHash: normalized.scheduleHash,
            blockSeed,
            blockIndex,
            replicateIndex,
            armId: arm.armId,
            armIndex: arm.armIndex,
            subjectIdentity: arm.subjectIdentity,
        }, REPLICATION_ARM_SEED_HASH_ALGORITHM);
        const subjectDigest = hashCanonical({
            scheduleHash: normalized.scheduleHash,
            blockIndex,
            armIndex: arm.armIndex,
            armId: arm.armId,
            subjectIdentity: arm.subjectIdentity,
        }, REPLICATION_MEASUREMENT_SUBJECT_HASH_ALGORITHM)
            .split(":").at(-1).slice(0, 12);
        return {
            ...arm,
            blockIndex,
            replicateIndex,
            executionOrdinal,
            deterministicSeed,
            subjectId:
                `rep-b${paddedOrdinal(blockIndex, 6)}-a${
                    paddedOrdinal(arm.armIndex, 2)
                }-${subjectDigest}`,
        };
    });
    return immutableCanonical({
        scheduleHash: normalized.scheduleHash,
        blockIndex,
        replicateIndex,
        blockSeed,
        executionOrder,
        arms,
    });
}

export function replicationAttemptKey(value) {
    const input = requirePlainObject(value, "replication attempt");
    const blockIndex = requireNonNegativeInteger(input.blockIndex, "blockIndex");
    const armIndex = requireNonNegativeInteger(input.armIndex, "armIndex");
    return `${blockIndex}:${armIndex}`;
}

export function expectedReplicationSubjects(schedule, blockCount) {
    const normalized = normalizeReplicationSchedule(schedule);
    if (!Number.isSafeInteger(blockCount)
        || blockCount < 0
        || blockCount > normalized.maxBlocks) {
        fail("blockCount is outside the frozen replication schedule", {
            blockCount,
            maxBlocks: normalized.maxBlocks,
        });
    }
    const subjects = [];
    for (let blockIndex = 0; blockIndex < blockCount; blockIndex += 1) {
        const plan = replicationBlockPlan(normalized, blockIndex);
        subjects.push(...[...plan.arms]
            .sort((left, right) => left.armIndex - right.armIndex)
            .map((arm) => arm.subjectId));
    }
    return immutableCanonical(subjects);
}

function normalizeReplicationAttempt(value, index, schedule) {
    const input = requirePlainObject(value, `attempts[${index}]`);
    const blockIndex = requireNonNegativeInteger(
        input.blockIndex,
        `attempts[${index}].blockIndex`,
    );
    const armIndex = requireNonNegativeInteger(
        input.armIndex,
        `attempts[${index}].armIndex`,
    );
    const plan = replicationBlockPlan(schedule, blockIndex);
    const expected = plan.arms.find((arm) => arm.armIndex === armIndex);
    if (expected === undefined
        || input.armId !== expected.armId
        || input.replicateIndex !== expected.replicateIndex
        || input.deterministicSeed !== expected.deterministicSeed
        || input.subjectId !== expected.subjectId) {
        fail("replication attempt does not match its frozen block/arm binding", {
            index,
            expected: expected ?? null,
            actual: {
                armId: input.armId ?? null,
                armIndex,
                blockIndex,
                replicateIndex: input.replicateIndex ?? null,
                deterministicSeed: input.deterministicSeed ?? null,
                subjectId: input.subjectId ?? null,
            },
        });
    }
    if (typeof input.attemptId !== "string" || input.attemptId.length === 0) {
        fail(`attempts[${index}].attemptId must be a non-empty string`);
    }
    const parsed = input.parsed === undefined ? null : input.parsed;
    if (parsed !== null) requirePlainObject(parsed, `attempts[${index}].parsed`);
    const invalid = input.invalid === undefined ? null : input.invalid;
    if (invalid !== null) requirePlainObject(invalid, `attempts[${index}].invalid`);
    return {
        ...expected,
        attemptId: input.attemptId,
        parsed,
        invalid,
        receiptHash: input.receiptHash ?? null,
        measurementRoot: input.measurementRoot ?? null,
        measurementProvenance: input.measurementProvenance ?? null,
    };
}

function sortedByBlockAndArm(attempts) {
    return [...attempts].sort((left, right) =>
        left.blockIndex - right.blockIndex
        || left.armIndex - right.armIndex);
}

function statisticalBlock(blockIndex, attempts) {
    const byArm = new Map(attempts.map((attempt) => [attempt.armId, attempt]));
    const record = (armId) => {
        const attempt = byArm.get(armId) ?? null;
        return attempt === null || attempt.invalid !== null
            ? null
            : attempt.parsed;
    };
    const parents = Object.fromEntries(
        [...byArm.values()]
            .filter((attempt) => attempt.subjectKind === "assigned_parent")
            .map((attempt) => [
                attempt.logicalSubjectId,
                attempt.invalid === null ? attempt.parsed : null,
            ]),
    );
    const extraArms = Object.fromEntries(
        [...byArm.entries()]
            .filter(([armId]) => armId !== "candidate" && armId !== "control")
            .map(([armId, attempt]) => [
                armId,
                attempt.invalid === null ? attempt.parsed : null,
            ]),
    );
    return {
        blockIndex,
        candidate: record("candidate"),
        control: record("control"),
        ...(Object.keys(parents).length === 0 ? {} : { parents }),
        ...(Object.keys(extraArms).length === 0 ? {} : { arms: extraArms }),
    };
}

export function analyzeReplicationAttempts({ schedule, attempts }) {
    const normalizedSchedule = normalizeReplicationSchedule(schedule);
    if (!Array.isArray(attempts)) {
        fail("attempts must be an array");
    }
    const normalizedAttempts = attempts.map((attempt, index) =>
        normalizeReplicationAttempt(attempt, index, normalizedSchedule));
    const byKey = new Map();
    for (const attempt of normalizedAttempts) {
        const key = replicationAttemptKey(attempt);
        if (byKey.has(key)) {
            fail("replication attempts contain a duplicate block/arm", {
                key,
                attemptIds: [byKey.get(key).attemptId, attempt.attemptId],
            });
        }
        byKey.set(key, attempt);
    }

    const completeBlocks = [];
    let firstIncompleteBlock = null;
    let nextArm = null;
    for (
        let blockIndex = 0;
        blockIndex < normalizedSchedule.maxBlocks;
        blockIndex += 1
    ) {
        const plan = replicationBlockPlan(normalizedSchedule, blockIndex);
        const blockAttempts = plan.arms
            .map((arm) => byKey.get(`${blockIndex}:${arm.armIndex}`) ?? null);
        const missing = blockAttempts.filter((attempt) => attempt === null).length;
        if (missing > 0) {
            firstIncompleteBlock = {
                blockIndex,
                presentArmCount: blockAttempts.length - missing,
                missingArmCount: missing,
                expectedArmCount: blockAttempts.length,
            };
            nextArm = plan.arms.find((arm) =>
                !byKey.has(`${blockIndex}:${arm.armIndex}`)) ?? null;
            break;
        }
        const sorted = sortedByBlockAndArm(blockAttempts);
        completeBlocks.push({
            blockIndex,
            attempts: sorted,
            statisticalBlock: statisticalBlock(blockIndex, sorted),
        });
    }

    const firstGap = firstIncompleteBlock?.blockIndex
        ?? normalizedSchedule.maxBlocks;
    const attemptsAfterGap = normalizedAttempts.filter(
        (attempt) => attempt.blockIndex > firstGap,
    );
    if (attemptsAfterGap.length > 0) {
        fail("replication attempts exist after the first incomplete block", {
            firstIncompleteBlock,
            attemptIds: attemptsAfterGap.map((attempt) => attempt.attemptId),
        });
    }

    return immutableCanonical({
        scheduleHash: normalizedSchedule.scheduleHash,
        attempts: sortedByBlockAndArm(normalizedAttempts),
        completeBlocks,
        contiguousCompleteBlockCount: completeBlocks.length,
        firstIncompleteBlock,
        invalidIncompleteBlock:
            firstIncompleteBlock !== null
            && firstIncompleteBlock.presentArmCount > 0,
        nextArm,
    });
}

function rawObservation(attempt, role, phase) {
    return {
        attemptId: attempt.attemptId,
        blockIndex: attempt.blockIndex,
        replicateIndex: attempt.replicateIndex,
        armIndex: attempt.armIndex,
        armId: attempt.armId,
        logicalSubjectId: attempt.logicalSubjectId,
        subjectId: attempt.subjectId,
        deterministicSeed: attempt.deterministicSeed,
        role,
        phase,
        parsed: attempt.parsed,
        invalid: attempt.invalid,
        receiptHash: attempt.receiptHash,
        measurementRoot: attempt.measurementRoot,
    };
}

export function createRawMeasurementSeries({
    schedule,
    attempts,
    role,
    phase,
    caseId = null,
}) {
    const normalizedSchedule = normalizeReplicationSchedule(schedule);
    const normalizedRole = requireSafeId(role, "role");
    const normalizedPhase = requireSafeId(phase, "phase");
    const normalizedCaseId = caseId === null
        ? null
        : requireSafeId(caseId, "caseId");
    if (!Array.isArray(attempts)) {
        fail("attempts must be an array");
    }
    const normalizedAttempts = attempts.map((attempt, index) =>
        normalizeReplicationAttempt(attempt, index, normalizedSchedule));
    const byBlock = new Map();
    for (const attempt of normalizedAttempts) {
        const list = byBlock.get(attempt.blockIndex) ?? [];
        list.push(attempt);
        byBlock.set(attempt.blockIndex, list);
    }
    const completeBlocks = [...byBlock.entries()]
        .sort(([left], [right]) => left - right)
        .map(([blockIndex, blockAttempts]) => {
            const plan = replicationBlockPlan(normalizedSchedule, blockIndex);
            const sorted = sortedByBlockAndArm(blockAttempts);
            if (sorted.length !== plan.arms.length
                || sorted.some((attempt, index) => attempt.armIndex !== index)) {
                fail("raw measurement series block must contain every scheduled arm", {
                    blockIndex,
                });
            }
            return {
                blockIndex,
                observations: sorted.map((attempt) =>
                    rawObservation(attempt, normalizedRole, normalizedPhase)),
            };
        });
    return immutableCanonical({
        version: RAW_MEASUREMENT_SERIES_VERSION,
        role: normalizedRole,
        phase: normalizedPhase,
        caseId: normalizedCaseId,
        scheduleHash: normalizedSchedule.scheduleHash,
        completeBlocks,
    });
}

export function normalizeRawMeasurementSeries(value, {
    schedule,
    role,
    phase,
    caseId = null,
} = {}) {
    const input = requireExactKeys(value, "rawMeasurementSeries", [
        "caseId",
        "completeBlocks",
        "phase",
        "role",
        "scheduleHash",
        "version",
    ]);
    if (input.version !== RAW_MEASUREMENT_SERIES_VERSION) {
        fail("rawMeasurementSeries.version is unsupported");
    }
    const normalizedSchedule = normalizeReplicationSchedule(schedule);
    const expectedRole = requireSafeId(role, "role");
    const expectedPhase = requireSafeId(phase, "phase");
    const expectedCaseId = caseId === null
        ? null
        : requireSafeId(caseId, "caseId");
    if (input.role !== expectedRole
        || input.phase !== expectedPhase
        || input.caseId !== expectedCaseId
        || input.scheduleHash !== normalizedSchedule.scheduleHash
        || !Array.isArray(input.completeBlocks)) {
        fail("raw measurement series does not match its frozen command binding");
    }
    const attempts = [];
    let previousBlockIndex = -1;
    for (
        let blockOrdinal = 0;
        blockOrdinal < input.completeBlocks.length;
        blockOrdinal += 1
    ) {
        const block = requireExactKeys(
            input.completeBlocks[blockOrdinal],
            `rawMeasurementSeries.completeBlocks[${blockOrdinal}]`,
            ["blockIndex", "observations"],
        );
        const blockIndex = requireNonNegativeInteger(
            block.blockIndex,
            `rawMeasurementSeries.completeBlocks[${blockOrdinal}].blockIndex`,
        );
        if (blockIndex <= previousBlockIndex) {
            fail("raw measurement complete blocks must be strictly ordered");
        }
        previousBlockIndex = blockIndex;
        const plan = replicationBlockPlan(normalizedSchedule, blockIndex);
        const expectedArms = [...plan.arms].sort(
            (left, right) => left.armIndex - right.armIndex,
        );
        if (!Array.isArray(block.observations)
            || block.observations.length !== expectedArms.length) {
            fail("raw measurement block must contain every scheduled arm");
        }
        const sorted = [...block.observations].sort(
            (left, right) => left.armIndex - right.armIndex,
        );
        for (let armOrdinal = 0; armOrdinal < sorted.length; armOrdinal += 1) {
            const observation = requireExactKeys(
                sorted[armOrdinal],
                `rawMeasurementSeries.completeBlocks[${blockOrdinal}].observations[${armOrdinal}]`,
                [
                    "armId",
                    "armIndex",
                    "attemptId",
                    "blockIndex",
                    "deterministicSeed",
                    "invalid",
                    "logicalSubjectId",
                    "measurementRoot",
                    "parsed",
                    "phase",
                    "receiptHash",
                    "replicateIndex",
                    "role",
                    "subjectId",
                ],
            );
            const expected = expectedArms[armOrdinal];
            if (observation.role !== expectedRole
                || observation.phase !== expectedPhase
                || observation.blockIndex !== expected.blockIndex
                || observation.replicateIndex !== expected.replicateIndex
                || observation.armIndex !== expected.armIndex
                || observation.armId !== expected.armId
                || observation.logicalSubjectId !== expected.logicalSubjectId
                || observation.subjectId !== expected.subjectId
                || observation.deterministicSeed !== expected.deterministicSeed
                || typeof observation.attemptId !== "string"
                || observation.attemptId.length === 0
                || typeof observation.receiptHash !== "string"
                || observation.receiptHash.length === 0
                || typeof observation.measurementRoot !== "string"
                || observation.measurementRoot.length === 0
                || (observation.parsed !== null
                    && !canonicalEqual(
                        {
                            role: observation.parsed.role,
                            phase: observation.parsed.phase,
                            replicateIndex: observation.parsed.replicateIndex,
                            blockIndex: observation.parsed.blockIndex,
                            armIndex: observation.parsed.armIndex,
                            armId: observation.parsed.armId,
                            deterministicSeed:
                                observation.parsed.deterministicSeed,
                            subjectId: observation.parsed.subjectId,
                        },
                        {
                            role: expectedRole,
                            phase: expectedPhase,
                            replicateIndex: expected.replicateIndex,
                            blockIndex: expected.blockIndex,
                            armIndex: expected.armIndex,
                            armId: expected.armId,
                            deterministicSeed: expected.deterministicSeed,
                            subjectId: expected.subjectId,
                        },
                    ))) {
                fail("raw measurement observation does not match its scheduled role/block/arm");
            }
            if (observation.parsed !== null) {
                requirePlainObject(
                    observation.parsed,
                    "raw measurement observation parsed value",
                );
            }
            if (observation.invalid !== null) {
                requirePlainObject(
                    observation.invalid,
                    "raw measurement observation invalid value",
                );
            }
            attempts.push({
                ...expected,
                attemptId: observation.attemptId,
                parsed: observation.parsed,
                invalid: observation.invalid,
                receiptHash: observation.receiptHash,
                measurementRoot: observation.measurementRoot,
            });
        }
    }
    return immutableCanonical({
        series: createRawMeasurementSeries({
            schedule: normalizedSchedule,
            attempts,
            role: expectedRole,
            phase: expectedPhase,
            caseId: expectedCaseId,
        }),
        attempts: sortedByBlockAndArm(attempts),
    });
}
