import {
    canonicalEqual,
    hashCanonical,
    immutableCanonical,
    isAlgorithmTaggedSha256,
} from "../domain/canonical.mjs";
import { normalizeHarnessResultBinding } from "./parser.mjs";

export const NOVELTY_ROLE_ADAPTER_VERSION =
    "crucible-novelty-role-adapter-v1";
export const NOVELTY_ROLE_FINGERPRINT_ALGORITHM =
    "sha256:crucible-novelty-role-v1";
export const NOVELTY_STRUCTURAL_FINGERPRINT_ALGORITHM =
    "sha256:crucible-novelty-structural-v1";
export const NOVELTY_BINDING_SEED_ALGORITHM =
    "sha256:crucible-novelty-binding-seed-v1";
export const NOVELTY_MAX_STRUCTURAL_FEATURES = 128;

const ATTEMPT_KEYS = Object.freeze([
    "armId",
    "armIndex",
    "attemptId",
    "blockIndex",
    "deterministicSeed",
    "invalid",
    "measurementRoot",
    "parsed",
    "phase",
    "receiptHash",
    "replicateIndex",
    "role",
    "subjectId",
    "version",
]);
const PARSED_KEYS = Object.freeze([
    "armId",
    "armIndex",
    "blockIndex",
    "deterministicSeed",
    "environmentIdentity",
    "impossibilityCertificateHash",
    "metrics",
    "observables",
    "parserVersion",
    "pass",
    "phase",
    "replicateIndex",
    "role",
    "searchSpaceExhausted",
    "subjectId",
    "suiteIdentity",
    "validationCases",
]);
const STRUCTURAL_FEATURE_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/u;

export class NoveltyRoleError extends TypeError {
    constructor(message, details = null) {
        super(message);
        this.name = "NoveltyRoleError";
        this.code = "CRUCIBLE_NOVELTY_ROLE_INVALID";
        if (details !== null) this.details = details;
    }
}

function fail(message, details = null) {
    throw new NoveltyRoleError(message, details);
}

function plainObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)) {
        fail(`${field} must be a plain object`);
    }
    return value;
}

function exactKeys(value, expected, field) {
    const actual = Object.keys(plainObject(value, field)).sort();
    const wanted = [...expected].sort();
    if (!canonicalEqual(actual, wanted)) {
        fail(`${field} must contain exactly the canonical fields`, {
            actual,
            expected: wanted,
        });
    }
}

function taggedHash(value, field) {
    if (!isAlgorithmTaggedSha256(value)) {
        fail(`${field} must be an algorithm-tagged SHA-256 hash`);
    }
    return value;
}

function nonEmptyText(value, field, maximum = 256) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > maximum
        || value.includes("\0")) {
        fail(`${field} must be a non-empty bounded string`);
    }
    return value;
}

function nonNegativeInteger(value, field) {
    if (!Number.isSafeInteger(value) || value < 0) {
        fail(`${field} must be a non-negative safe integer`);
    }
    return value;
}

function noveltyRoleSpec(value) {
    const suite = value?.harnessSuite ?? value;
    const role = suite?.roles?.novelty;
    if (role === null || typeof role !== "object" || Array.isArray(role)) {
        fail("the frozen HarnessSuiteV4 novelty role is unavailable");
    }
    return {
        suite,
        role,
        suiteIdentity: value?.harnessSuiteIdentity
            ?? suite?.identity
            ?? null,
    };
}

export function noveltyRoleFingerprint(value) {
    const { role, suite, suiteIdentity } = noveltyRoleSpec(value);
    return hashCanonical({
        version: NOVELTY_ROLE_ADAPTER_VERSION,
        role: "novelty",
        suiteIdentity,
        environmentIdentity: suite.environmentIdentity ?? null,
        roleSpec: role,
    }, NOVELTY_ROLE_FINGERPRINT_ALGORITHM);
}

export function createNoveltyMeasurementBinding({
    contract,
    candidateArtifactHash,
}) {
    taggedHash(candidateArtifactHash, "candidateArtifactHash");
    const { suite } = noveltyRoleSpec(contract);
    const roleFingerprint = noveltyRoleFingerprint(contract);
    const digest = candidateArtifactHash.split(":").at(-1);
    return immutableCanonical({
        role: "novelty",
        phase: "novelty",
        replicateIndex: 0,
        blockIndex: 0,
        armIndex: 0,
        armId: "candidate",
        deterministicSeed: hashCanonical({
            version: NOVELTY_ROLE_ADAPTER_VERSION,
            candidateArtifactHash,
            roleFingerprint,
        }, NOVELTY_BINDING_SEED_ALGORITHM),
        subjectId: `novelty-${digest.slice(0, 48)}`,
        environmentIdentity: suite.environmentIdentity,
        suiteIdentity: contract.harnessSuiteIdentity,
    });
}

function normalizeAttemptBinding(value, field) {
    try {
        return normalizeHarnessResultBinding({
            role: value.role,
            phase: value.phase,
            replicateIndex: value.replicateIndex,
            blockIndex: value.blockIndex,
            armIndex: value.armIndex,
            armId: value.armId,
            deterministicSeed: value.deterministicSeed,
            subjectId: value.subjectId,
            environmentIdentity: value.environmentIdentity,
            suiteIdentity: value.suiteIdentity,
        }, {
            field,
            required: true,
        });
    } catch (error) {
        fail(`${field} is invalid`, {
            cause: error?.code ?? error?.name ?? null,
            message: error?.message ?? String(error),
        });
    }
}

function normalizedAttemptCore(value) {
    exactKeys(value, ATTEMPT_KEYS, "novelty attempt");
    if (value.version !== 1) {
        fail("novelty attempt.version must be 1");
    }
    const binding = {
        role: nonEmptyText(value.role, "novelty attempt.role", 64),
        phase: nonEmptyText(value.phase, "novelty attempt.phase", 64),
        replicateIndex: nonNegativeInteger(
            value.replicateIndex,
            "novelty attempt.replicateIndex",
        ),
        blockIndex: nonNegativeInteger(
            value.blockIndex,
            "novelty attempt.blockIndex",
        ),
        armIndex: nonNegativeInteger(
            value.armIndex,
            "novelty attempt.armIndex",
        ),
        armId: nonEmptyText(value.armId, "novelty attempt.armId", 128),
        deterministicSeed: nonEmptyText(
            value.deterministicSeed,
            "novelty attempt.deterministicSeed",
        ),
        subjectId: nonEmptyText(value.subjectId, "novelty attempt.subjectId", 128),
    };
    if (binding.role !== "novelty"
        || binding.phase !== "novelty"
        || binding.replicateIndex !== 0
        || binding.blockIndex !== 0
        || binding.armIndex !== 0
        || binding.armId !== "candidate") {
        fail("novelty attempt has an invalid role binding", { binding });
    }
    const parsed = value.parsed === null
        ? null
        : plainObject(value.parsed, "novelty attempt.parsed");
    const invalid = value.invalid === null
        ? null
        : plainObject(value.invalid, "novelty attempt.invalid");
    if ((parsed === null) === (invalid === null)) {
        fail("novelty attempt must contain either parsed facts or invalid metadata");
    }
    return {
        version: 1,
        attemptId: nonEmptyText(value.attemptId, "novelty attempt.attemptId"),
        ...binding,
        parsed,
        invalid,
        receiptHash: taggedHash(
            value.receiptHash,
            "novelty attempt.receiptHash",
        ),
        measurementRoot: taggedHash(
            value.measurementRoot,
            "novelty attempt.measurementRoot",
        ),
    };
}

export function normalizeNoveltyRoleAttempt(value, options = {}) {
    const normalized = normalizedAttemptCore(value);
    const expectedBinding = options.expectedBinding === undefined
        ? null
        : normalizeAttemptBinding(
            options.expectedBinding,
            "expected novelty binding",
        );
    const actualBinding = normalizeAttemptBinding({
        ...normalized,
        environmentIdentity: options.environmentIdentity
            ?? normalized.parsed?.environmentIdentity,
        suiteIdentity: options.suiteIdentity
            ?? normalized.parsed?.suiteIdentity,
    }, "novelty attempt binding");
    if (expectedBinding !== null && !canonicalEqual(actualBinding, expectedBinding)) {
        fail("novelty attempt does not match its frozen execution binding", {
            actual: actualBinding,
            expected: expectedBinding,
        });
    }
    if (normalized.parsed !== null) {
        exactKeys(
            normalized.parsed,
            PARSED_KEYS,
            "novelty attempt.parsed",
        );
        const parsedBinding = normalizeAttemptBinding(
            normalized.parsed,
            "novelty parsed binding",
        );
        if (!canonicalEqual(parsedBinding, actualBinding)) {
            fail("novelty parsed facts do not match the receipt binding");
        }
    }
    return immutableCanonical(normalized);
}

function normalizeStructuralFeatures(parsed, parserVersion) {
    if (parsed.pass !== true
        || parsed.observables !== null
        || parsed.validationCases !== null
        || parsed.searchSpaceExhausted !== null
        || parsed.impossibilityCertificateHash !== null
        || parsed.parserVersion !== parserVersion) {
        fail("novelty role output is not a successful structural observation");
    }
    const metrics = plainObject(parsed.metrics, "novelty output.metrics");
    const keys = Object.keys(metrics).sort();
    if (keys.length === 0 || keys.length > NOVELTY_MAX_STRUCTURAL_FEATURES) {
        fail(
            `novelty output.metrics must contain 1..${NOVELTY_MAX_STRUCTURAL_FEATURES} features`,
        );
    }
    const features = {};
    for (const key of keys) {
        if (!STRUCTURAL_FEATURE_NAME.test(key)
            || key === "__proto__"
            || key === "constructor"
            || key === "prototype") {
            fail(`novelty output.metrics key ${JSON.stringify(key)} is invalid`);
        }
        const value = metrics[key];
        if (typeof value !== "number" || !Number.isFinite(value)) {
            fail(`novelty output.metrics.${key} must be finite`);
        }
        features[key] = Object.is(value, -0) ? 0 : value;
    }
    return features;
}

export function adaptNoveltyRoleAttempt({
    attempt,
    measurement,
    contract,
    candidateArtifactHash,
}) {
    const { role, suite } = noveltyRoleSpec(contract);
    const expectedBinding = createNoveltyMeasurementBinding({
        contract,
        candidateArtifactHash,
    });
    const normalized = normalizeNoveltyRoleAttempt(attempt, {
        expectedBinding,
        environmentIdentity: suite.environmentIdentity,
        suiteIdentity: contract.harnessSuiteIdentity,
    });
    if (normalized.invalid !== null || normalized.parsed === null) return null;
    const provenance = plainObject(measurement, "novelty measurement provenance");
    if (provenance.role !== "novelty"
        || provenance.phase !== "novelty"
        || provenance.subjectId !== normalized.subjectId
        || provenance.receiptHash !== normalized.receiptHash
        || provenance.measurementRoot !== normalized.measurementRoot
        || provenance.parserVersion !== role.parser.version
        || provenance.harnessEntryHash !== role.harnessEntryHash
        || provenance.executableHash !== role.executableHash
        || provenance.snapshot?.snapshotHash !== candidateArtifactHash) {
        fail("novelty measurement provenance does not match the frozen role/receipt binding");
    }
    const features = normalizeStructuralFeatures(
        normalized.parsed,
        role.parser.version,
    );
    const roleFingerprint = noveltyRoleFingerprint(contract);
    return immutableCanonical({
        version: NOVELTY_ROLE_ADAPTER_VERSION,
        roleFingerprint,
        structuralFingerprint: hashCanonical({
            version: NOVELTY_ROLE_ADAPTER_VERSION,
            roleFingerprint,
            observableSchemaHash: role.observableSchemaHash,
            features,
        }, NOVELTY_STRUCTURAL_FINGERPRINT_ALGORITHM),
        features,
        receiptHash: normalized.receiptHash,
        measurementRoot: normalized.measurementRoot,
        subjectId: normalized.subjectId,
    });
}

export function tryAdaptNoveltyRoleAttempt(input) {
    try {
        return adaptNoveltyRoleAttempt(input);
    } catch (error) {
        if (error instanceof NoveltyRoleError) return null;
        throw error;
    }
}
