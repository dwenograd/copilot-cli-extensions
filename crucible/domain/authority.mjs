import {
    canonicalEqual,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import { ContractError } from "./errors.mjs";
import {
    contractHash,
    createInvestigationContract,
} from "./contract.mjs";
import path from "node:path";
import { createHash } from "node:crypto";

export const EXPERIMENT_AUTHORITY_MANIFEST_VERSION = 1;
export const EXPERIMENT_AUTHORITY_VERSION = 1;
export const EXPERIMENT_AUTHORITY_MANIFEST_KIND =
    "CrucibleExperimentAuthorityManifest";
export const EXPERIMENT_AUTHORITY_ALGORITHM = "Ed25519";
export const EXPERIMENT_AUTHORITY_MANIFEST_IDENTITY_ALGORITHM =
    "sha256:crucible-experiment-authority-manifest-v1";
export const EXPERIMENT_AUTHORITY_IDENTITY_ALGORITHM =
    "sha256:crucible-experiment-authority-v1";
export const EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ALGORITHM =
    "sha256:crucible-experiment-public-key-v1";

const SAFE_ID = /^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$/u;
const TAGGED_SHA256 =
    /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const MANIFEST_KEYS = Object.freeze([
    "contractHash",
    "enumerandRoot",
    "experimentPayload",
    "harnessSuiteIdentity",
    "hypothesisPolicyIdentity",
    "investigationId",
    "kind",
    "statisticalPolicyIdentity",
    "trustFingerprint",
    "version",
]);
const PAYLOAD_KEYS = Object.freeze([
    "contract",
    "experimentId",
    "harnessSuiteId",
    "projectDir",
    "version",
]);
const AUTHORITY_KEYS = Object.freeze([
    "algorithm",
    "identity",
    "manifest",
    "manifestIdentity",
    "signature",
    "trustFingerprint",
    "version",
]);

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

function requireExactKeys(value, field, expected) {
    requirePlainObject(value, field);
    const expectedSet = new Set(expected);
    const missing = expected.filter((key) => !Object.hasOwn(value, key));
    const unknown = Object.keys(value).filter((key) => !expectedSet.has(key));
    if (missing.length > 0 || unknown.length > 0) {
        fail(`${field} must contain exactly the canonical fields`, {
            field,
            missing,
            unknown,
        });
    }
}

function requireSafeId(value, field) {
    if (typeof value !== "string" || !SAFE_ID.test(value)) {
        fail(`${field} must be a safe lowercase identifier`, { field, value });
    }
    return value;
}

function requireNonEmptyString(value, field, maximum = 32767) {
    if (typeof value !== "string"
        || value.length === 0
        || value.length > maximum
        || value.includes("\0")) {
        fail(`${field} must be a non-empty string`, { field });
    }
    return value;
}

function canonicalObjective(value) {
    return requireNonEmptyString(value, "experiment authority objective")
        .trim()
        .replace(/\s+/gu, " ");
}

function normalizeProjectDirForHash(projectDir) {
    return path.resolve(projectDir).replace(/\//gu, "\\").toLowerCase();
}

function slugify(text) {
    return text
        .toLowerCase()
        .replace(/[^a-z0-9]+/gu, "-")
        .replace(/^-+|-+$/gu, "")
        .slice(0, 40)
        .replace(/-+$/gu, "");
}

export function deriveAuthorizedInvestigationId({
    experimentId,
    objective,
    projectDir,
    harnessSuiteId,
    harnessSuiteIdentity,
    contractHash,
    trustFingerprint,
}) {
    const normalizedExperimentId = requireSafeId(
        experimentId,
        "experiment authority experimentId",
    );
    const normalizedObjective = canonicalObjective(objective);
    const normalizedProjectDir = requireNonEmptyString(
        projectDir,
        "experiment authority projectDir",
    );
    const normalizedHarnessSuiteId = requireSafeId(
        harnessSuiteId,
        "experiment authority harnessSuiteId",
    );
    const normalizedHarnessSuiteIdentity = requireTaggedHash(
        harnessSuiteIdentity,
        "experiment authority harnessSuiteIdentity",
        "sha256:crucible-harness-suite-v4",
    );
    const normalizedContractHash = requireTaggedHash(
        contractHash,
        "experiment authority contractHash",
        "sha256:crucible-contract-v4",
    );
    const normalizedTrustFingerprint = requireTaggedHash(
        trustFingerprint,
        "experiment authority trustFingerprint",
        EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ALGORITHM,
    );
    const material = [
        "crucible-authorized-investigation-domain-v4",
        normalizedExperimentId,
        normalizedHarnessSuiteId,
        normalizedHarnessSuiteIdentity,
        normalizedContractHash,
        normalizedTrustFingerprint,
        normalizedObjective,
        normalizeProjectDirForHash(normalizedProjectDir),
    ].join("\u0000");
    const suffix = createHash("sha256")
        .update(material, "utf8")
        .digest("hex")
        .slice(0, 16);
    const slug = slugify(normalizedObjective);
    return slug.length > 0 ? `${slug}-${suffix}` : `inv-${suffix}`;
}

function requireTaggedHash(value, field, algorithm = null) {
    if (typeof value !== "string" || !TAGGED_SHA256.test(value)) {
        fail(`${field} must be an algorithm-tagged SHA-256 identity`, {
            field,
            value,
        });
    }
    if (algorithm !== null && !value.startsWith(`${algorithm}:`)) {
        fail(`${field} must use ${algorithm}`, { field, value });
    }
    return value;
}

function normalizeSignature(value) {
    if (typeof value !== "string" || !BASE64.test(value)) {
        fail("experiment authority signature must be canonical base64");
    }
    const bytes = Buffer.from(value, "base64");
    if (bytes.length !== 64 || bytes.toString("base64") !== value) {
        fail("experiment authority signature must encode exactly 64 Ed25519 bytes");
    }
    return value;
}

function normalizeExperimentPayload(value) {
    requireExactKeys(value, "experiment authority payload", PAYLOAD_KEYS);
    if (value.version !== 1) {
        fail("experiment authority payload version must be 1", {
            actual: value.version ?? null,
        });
    }
    requirePlainObject(value.contract, "experiment authority payload.contract");
    return immutableCanonical({
        version: 1,
        experimentId: requireSafeId(
            value.experimentId,
            "experiment authority payload.experimentId",
        ),
        projectDir: requireNonEmptyString(
            value.projectDir,
            "experiment authority payload.projectDir",
        ),
        harnessSuiteId: requireSafeId(
            value.harnessSuiteId,
            "experiment authority payload.harnessSuiteId",
        ),
        contract: value.contract,
    });
}

export function normalizeExperimentAuthorityManifest(value) {
    requireExactKeys(value, "experiment authority manifest", MANIFEST_KEYS);
    if (value.version !== EXPERIMENT_AUTHORITY_MANIFEST_VERSION) {
        fail(
            `experiment authority manifest version must be ${
                EXPERIMENT_AUTHORITY_MANIFEST_VERSION
            }`,
            { actual: value.version ?? null },
        );
    }
    if (value.kind !== EXPERIMENT_AUTHORITY_MANIFEST_KIND) {
        fail(
            `experiment authority manifest kind must be ${
                EXPERIMENT_AUTHORITY_MANIFEST_KIND
            }`,
            { actual: value.kind ?? null },
        );
    }
    const enumerandRoot = value.enumerandRoot === null
        ? null
        : requireTaggedHash(
            value.enumerandRoot,
            "experiment authority manifest.enumerandRoot",
            "sha256:crucible-enumerand-manifest-root-v1",
        );
    const experimentPayload = normalizeExperimentPayload(value.experimentPayload);
    const contractHash = requireTaggedHash(
        value.contractHash,
        "experiment authority manifest.contractHash",
        "sha256:crucible-contract-v4",
    );
    const harnessSuiteIdentity = requireTaggedHash(
        value.harnessSuiteIdentity,
        "experiment authority manifest.harnessSuiteIdentity",
        "sha256:crucible-harness-suite-v4",
    );
    const trustFingerprint = requireTaggedHash(
        value.trustFingerprint,
        "experiment authority manifest.trustFingerprint",
        EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ALGORITHM,
    );
    const investigationId = requireSafeId(
        value.investigationId,
        "experiment authority manifest.investigationId",
    );
    const expectedInvestigationId = deriveAuthorizedInvestigationId({
        experimentId: experimentPayload.experimentId,
        objective: experimentPayload.contract.objective,
        projectDir: experimentPayload.projectDir,
        harnessSuiteId: experimentPayload.harnessSuiteId,
        harnessSuiteIdentity,
        contractHash,
        trustFingerprint,
    });
    if (investigationId !== expectedInvestigationId) {
        fail("experiment authority investigationId does not match its signed payload", {
            expected: expectedInvestigationId,
            actual: investigationId,
        });
    }
    return immutableCanonical({
        version: EXPERIMENT_AUTHORITY_MANIFEST_VERSION,
        kind: EXPERIMENT_AUTHORITY_MANIFEST_KIND,
        experimentPayload,
        contractHash,
        harnessSuiteIdentity,
        enumerandRoot,
        statisticalPolicyIdentity: requireTaggedHash(
            value.statisticalPolicyIdentity,
            "experiment authority manifest.statisticalPolicyIdentity",
            "sha256:crucible-statistical-policy-v4",
        ),
        hypothesisPolicyIdentity: requireTaggedHash(
            value.hypothesisPolicyIdentity,
            "experiment authority manifest.hypothesisPolicyIdentity",
            "sha256:crucible-hypothesis-policy-v4",
        ),
        trustFingerprint,
        investigationId,
    });
}

export function experimentAuthorityManifestBytes(manifest) {
    return Buffer.from(
        canonicalJson(normalizeExperimentAuthorityManifest(manifest)),
        "utf8",
    );
}

export function experimentAuthorityManifestIdentity(manifest) {
    return hashCanonical(
        normalizeExperimentAuthorityManifest(manifest),
        EXPERIMENT_AUTHORITY_MANIFEST_IDENTITY_ALGORITHM,
    );
}

function authorityCore(authority) {
    return {
        version: authority.version,
        algorithm: authority.algorithm,
        manifest: authority.manifest,
        manifestIdentity: authority.manifestIdentity,
        signature: authority.signature,
        trustFingerprint: authority.trustFingerprint,
    };
}

export function experimentAuthorityIdentity(authority) {
    return hashCanonical(
        authorityCore(authority),
        EXPERIMENT_AUTHORITY_IDENTITY_ALGORITHM,
    );
}

export function normalizeExperimentAuthority(value) {
    requireExactKeys(value, "experiment authority", AUTHORITY_KEYS);
    if (value.version !== EXPERIMENT_AUTHORITY_VERSION) {
        fail(`experiment authority version must be ${EXPERIMENT_AUTHORITY_VERSION}`, {
            actual: value.version ?? null,
        });
    }
    if (value.algorithm !== EXPERIMENT_AUTHORITY_ALGORITHM) {
        fail(`experiment authority algorithm must be ${EXPERIMENT_AUTHORITY_ALGORITHM}`, {
            actual: value.algorithm ?? null,
        });
    }
    const manifest = normalizeExperimentAuthorityManifest(value.manifest);
    const manifestIdentity = experimentAuthorityManifestIdentity(manifest);
    if (value.manifestIdentity !== manifestIdentity) {
        fail("experiment authority manifest identity does not match its exact payload", {
            expected: manifestIdentity,
            actual: value.manifestIdentity ?? null,
        });
    }
    const core = {
        version: EXPERIMENT_AUTHORITY_VERSION,
        algorithm: EXPERIMENT_AUTHORITY_ALGORITHM,
        manifest,
        manifestIdentity,
        signature: normalizeSignature(value.signature),
        trustFingerprint: requireTaggedHash(
            value.trustFingerprint,
            "experiment authority trustFingerprint",
            EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ALGORITHM,
        ),
    };
    if (core.trustFingerprint !== manifest.trustFingerprint) {
        fail("experiment authority trust fingerprint is not bound by its signed manifest", {
            manifestTrustFingerprint: manifest.trustFingerprint,
            envelopeTrustFingerprint: core.trustFingerprint,
        });
    }
    const identity = experimentAuthorityIdentity(core);
    if (value.identity !== identity) {
        fail("experiment authority identity does not match its signed envelope", {
            expected: identity,
            actual: value.identity ?? null,
        });
    }
    return immutableCanonical({ ...core, identity });
}

export function assertExperimentAuthorityContractBinding(
    value,
    contract,
    investigationId = null,
) {
    const authority = normalizeExperimentAuthority(value);
    const normalizedContract = createInvestigationContract(contract);
    const manifest = authority.manifest;
    const expectedContractHash = contractHash(normalizedContract);
    const expectedEnumerandRoot =
        normalizedContract.enumerandManifest?.merkleRoot ?? null;
    if (!canonicalEqual(
        manifest.experimentPayload.contract,
        normalizedContract,
    )
        || manifest.experimentPayload.harnessSuiteId
            !== normalizedContract.harnessSuite.id
        || manifest.contractHash !== expectedContractHash
        || manifest.harnessSuiteIdentity
            !== normalizedContract.harnessSuiteIdentity
        || manifest.enumerandRoot !== expectedEnumerandRoot
        || manifest.statisticalPolicyIdentity
            !== normalizedContract.statisticalPolicyIdentity
        || manifest.hypothesisPolicyIdentity
            !== normalizedContract.hypothesisPolicyIdentity) {
        fail("experiment authority is not bound to the exact v4 contract", {
            expectedContractHash,
            actualContractHash: manifest.contractHash,
        });
    }
    if (investigationId !== null
        && manifest.investigationId !== investigationId) {
        fail("experiment authority belongs to a different investigation", {
            expected: investigationId,
            actual: manifest.investigationId,
        });
    }
    return authority;
}
