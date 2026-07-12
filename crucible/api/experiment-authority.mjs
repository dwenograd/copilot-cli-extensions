import fs from "node:fs";
import path from "node:path";
import {
    createHash,
    createPublicKey,
    verify as verifyEd25519,
} from "node:crypto";

import {
    canonicalEqual,
    contractHash,
    deriveAuthorizedInvestigationId,
    experimentAuthorityIdentity,
    experimentAuthorityManifestBytes,
    experimentAuthorityManifestIdentity,
    normalizeExperimentAuthority,
    normalizeExperimentAuthorityManifest,
    EXPERIMENT_AUTHORITY_ALGORITHM,
    EXPERIMENT_AUTHORITY_MANIFEST_KIND,
    EXPERIMENT_AUTHORITY_MANIFEST_VERSION,
    EXPERIMENT_AUTHORITY_VERSION,
    EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ALGORITHM,
} from "../domain/index.mjs";
import {
    sha256Bytes,
    verifyAndHashFile,
    verifyLocalRegularFile,
} from "../measurement/index.mjs";
import { assertLocalDatabasePath } from "../persistence/index.mjs";

export const EXPERIMENT_PUBLIC_KEY_ENV = "CRUCIBLE_EXPERIMENT_PUBLIC_KEY";
export const EXPERIMENT_PUBLIC_KEY_PATH_ENV =
    "CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH";
export const EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV =
    "CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT";

const MAX_PUBLIC_KEY_BYTES = 64 * 1024;
const MAX_SIGNATURE_FILE_BYTES = 16 * 1024;
const ED25519_RAW_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const TRUSTED_KEYS = new WeakSet();
const VERIFIED_EXPERIMENT_AUTHORITIES = new WeakSet();
const VERIFIED_EXPERIMENT_AUTHORITY_BINDINGS = new WeakMap();
const VERIFIED_EXPERIMENT_AUTHORITY_ISSUER = Object.freeze({});

class VerifiedExperimentAuthority {
    constructor(issuer, binding) {
        if (issuer !== VERIFIED_EXPERIMENT_AUTHORITY_ISSUER) {
            throw new TypeError(
                "VerifiedExperimentAuthority cannot be constructed directly",
            );
        }
        VERIFIED_EXPERIMENT_AUTHORITIES.add(this);
        VERIFIED_EXPERIMENT_AUTHORITY_BINDINGS.set(this, binding);
        Object.freeze(this);
    }
}

export const EXPERIMENT_AUTHORITY_ERROR_CODES = Object.freeze({
    AUTHORITY_REQUIRED: "CRUCIBLE_EXPERIMENT_AUTHORITY_REQUIRED",
    AUTHORITY_INVALID: "CRUCIBLE_EXPERIMENT_AUTHORITY_INVALID",
    TRUST_NOT_CONFIGURED: "CRUCIBLE_EXPERIMENT_TRUST_NOT_CONFIGURED",
    TRUST_CONFIGURATION_INVALID:
        "CRUCIBLE_EXPERIMENT_TRUST_CONFIGURATION_INVALID",
    TRUST_FINGERPRINT_MISMATCH:
        "CRUCIBLE_EXPERIMENT_TRUST_FINGERPRINT_MISMATCH",
    SIGNATURE_INVALID: "CRUCIBLE_EXPERIMENT_SIGNATURE_INVALID",
});

export class ExperimentAuthorityError extends Error {
    constructor(code, message, details = null, options = {}) {
        super(message, options);
        this.name = "ExperimentAuthorityError";
        this.code = code;
        if (details !== null && details !== undefined) {
            this.details = details;
        }
    }
}

function fail(code, message, details = null, options = {}) {
    throw new ExperimentAuthorityError(code, message, details, options);
}

function hasText(value) {
    return typeof value === "string" && value.trim().length > 0;
}

function strictBase64Bytes(value, label) {
    const normalized = value.trim();
    if (!BASE64.test(normalized)) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            `${label} must be PEM or canonical base64`,
        );
    }
    const bytes = Buffer.from(normalized, "base64");
    if (bytes.toString("base64") !== normalized) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            `${label} is not canonical base64`,
        );
    }
    return bytes;
}

function parsePublicKeyBytes(bytes, label) {
    if (!Buffer.isBuffer(bytes)
        || bytes.length === 0
        || bytes.length > MAX_PUBLIC_KEY_BYTES) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            `${label} is empty or exceeds ${MAX_PUBLIC_KEY_BYTES} bytes`,
        );
    }
    const text = bytes.toString("utf8").trim();
    const attempts = [];
    if (text.startsWith("-----BEGIN")) {
        attempts.push(() => createPublicKey(text));
    } else {
        attempts.push(() => createPublicKey({
            key: bytes,
            format: "der",
            type: "spki",
        }));
        if (bytes.length === 32) {
            attempts.push(() => createPublicKey({
                key: Buffer.concat([ED25519_RAW_SPKI_PREFIX, bytes]),
                format: "der",
                type: "spki",
            }));
        }
        if (BASE64.test(text)) {
            const decoded = strictBase64Bytes(text, label);
            if (decoded.toString("utf8").trim().startsWith("-----BEGIN")) {
                attempts.push(() => createPublicKey(decoded.toString("utf8")));
            }
            attempts.push(() => createPublicKey({
                key: decoded,
                format: "der",
                type: "spki",
            }));
            if (decoded.length === 32) {
                attempts.push(() => createPublicKey({
                    key: Buffer.concat([ED25519_RAW_SPKI_PREFIX, decoded]),
                    format: "der",
                    type: "spki",
                }));
            }
        }
    }
    let lastError = null;
    for (const attempt of attempts) {
        try {
            const key = attempt();
            if (key.asymmetricKeyType !== "ed25519") {
                fail(
                    EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
                    `${label} must contain an Ed25519 public key`,
                    { asymmetricKeyType: key.asymmetricKeyType ?? null },
                );
            }
            return key;
        } catch (error) {
            if (error instanceof ExperimentAuthorityError) throw error;
            lastError = error;
        }
    }
    fail(
        EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
        `${label} is not a valid Ed25519 public key`,
        { cause: lastError?.code ?? null },
        { cause: lastError },
    );
}

function publicKeyFingerprint(publicKey) {
    const der = publicKey.export({ format: "der", type: "spki" });
    const digest = createHash("sha256").update(der).digest("hex");
    return `${EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ALGORITHM}:${digest}`;
}

function validateExpectedFingerprint(value, required) {
    if (!hasText(value)) {
        if (required) {
            fail(
                EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
                `${EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV} is required when the trusted key is loaded from a path`,
                { variable: EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV },
            );
        }
        return null;
    }
    if (!/^sha256:crucible-experiment-public-key-v1:[a-f0-9]{64}$/u.test(
        value,
    )) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            `${EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV} must be an exact tagged SHA-256 fingerprint`,
            { value },
        );
    }
    return value;
}

function trustedKeyRecord(publicKey, {
    expectedFingerprint = null,
    source,
    sourceFileHash = null,
}) {
    const fingerprint = publicKeyFingerprint(publicKey);
    if (expectedFingerprint !== null && expectedFingerprint !== fingerprint) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_FINGERPRINT_MISMATCH,
            "trusted experiment public key does not match the expected fingerprint",
            {
                expected: expectedFingerprint,
                actual: fingerprint,
                source,
            },
        );
    }
    const trust = Object.freeze({
        algorithm: EXPERIMENT_AUTHORITY_ALGORITHM,
        publicKey,
        fingerprint,
        source,
        sourceFileHash,
    });
    TRUSTED_KEYS.add(trust);
    return trust;
}

export function resolveExperimentTrust(env = process.env) {
    const inline = env?.[EXPERIMENT_PUBLIC_KEY_ENV];
    const keyPath = env?.[EXPERIMENT_PUBLIC_KEY_PATH_ENV];
    if (hasText(inline) && hasText(keyPath)) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            `set either ${EXPERIMENT_PUBLIC_KEY_ENV} or ${EXPERIMENT_PUBLIC_KEY_PATH_ENV}, not both`,
        );
    }
    if (hasText(inline)) {
        const bytes = inline.trim().startsWith("-----BEGIN")
            ? Buffer.from(inline.trim(), "utf8")
            : strictBase64Bytes(inline, EXPERIMENT_PUBLIC_KEY_ENV);
        const publicKey = parsePublicKeyBytes(bytes, EXPERIMENT_PUBLIC_KEY_ENV);
        return trustedKeyRecord(publicKey, {
            expectedFingerprint: validateExpectedFingerprint(
                env?.[EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV],
                false,
            ),
            source: "environment",
        });
    }
    if (!hasText(keyPath)) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_NOT_CONFIGURED,
            `set ${EXPERIMENT_PUBLIC_KEY_ENV}, or set ${
                EXPERIMENT_PUBLIC_KEY_PATH_ENV
            } with ${EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV}`,
        );
    }
    if (!path.isAbsolute(keyPath)) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            `${EXPERIMENT_PUBLIC_KEY_PATH_ENV} must be an absolute local path`,
            { path: keyPath },
        );
    }
    let localPath;
    try {
        localPath = assertLocalDatabasePath(keyPath, { env });
        localPath = verifyLocalRegularFile(localPath, {
            label: "experiment public key",
        });
    } catch (error) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            `trusted experiment public key path is invalid: ${
                error?.message ?? String(error)
            }`,
            { path: keyPath, cause: error?.code ?? null },
            { cause: error },
        );
    }
    let bytes;
    try {
        const size = fs.statSync(localPath).size;
        if (size > MAX_PUBLIC_KEY_BYTES) {
            fail(
                EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
                `trusted experiment public key exceeds ${MAX_PUBLIC_KEY_BYTES} bytes`,
                { path: localPath, bytes: size },
            );
        }
        bytes = fs.readFileSync(localPath);
    } catch (error) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            `failed to read trusted experiment public key: ${
                error?.message ?? String(error)
            }`,
            { path: localPath, cause: error?.code ?? null },
            { cause: error },
        );
    }
    const fileHash = sha256Bytes(
        bytes,
        "sha256:crucible-experiment-public-key-file-v1",
    );
    try {
        verifyAndHashFile(localPath, fileHash, {
            label: "experiment public key",
            algorithm: "sha256:crucible-experiment-public-key-file-v1",
        });
    } catch (error) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
            "trusted experiment public key changed while it was being read",
            { path: localPath, cause: error?.code ?? null },
            { cause: error },
        );
    }
    return trustedKeyRecord(
        parsePublicKeyBytes(bytes, EXPERIMENT_PUBLIC_KEY_PATH_ENV),
        {
            expectedFingerprint: validateExpectedFingerprint(
                env?.[EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV],
                true,
            ),
            source: localPath,
            sourceFileHash: fileHash,
        },
    );
}

function normalizeDetachedSignature(value) {
    let bytes;
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
        bytes = Buffer.from(value);
    } else if (typeof value === "string") {
        const text = value.trim();
        if (!BASE64.test(text)) {
            fail(
                EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
                "detached Ed25519 signature must be raw 64-byte data or canonical base64",
            );
        }

        bytes = Buffer.from(text, "base64");
        if (bytes.toString("base64") !== text) {
            fail(
                EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
                "detached Ed25519 signature is not canonical base64",
            );
        }
    } else {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_REQUIRED,
            "a detached Ed25519 signature is required",
        );
    }
    if (bytes.length !== 64) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
            "detached Ed25519 signature must contain exactly 64 bytes",
            { bytes: bytes.length },
        );
    }
    return Object.freeze({
        bytes,
        base64: bytes.toString("base64"),
    });
}

function normalizeManifestForAuthority(value) {
    try {
        return normalizeExperimentAuthorityManifest(value);
    } catch (error) {
        if (error instanceof ExperimentAuthorityError) throw error;
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
            `experiment authority manifest is invalid: ${
                error?.message ?? String(error)
            }`,
            { cause: error?.code ?? null, details: error?.details ?? null },
            { cause: error },
        );
    }
}

function normalizeAuthorityEnvelope(value) {
    try {
        return normalizeExperimentAuthority(value);
    } catch (error) {
        if (error instanceof ExperimentAuthorityError) throw error;
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
            `experiment authority envelope is invalid: ${
                error?.message ?? String(error)
            }`,
            { cause: error?.code ?? null, details: error?.details ?? null },
            { cause: error },
        );
    }
}

export function loadDetachedExperimentSignature(signaturePath) {
    if (!hasText(signaturePath) || !path.isAbsolute(signaturePath)) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_REQUIRED,
            "--signature-file must be an absolute path",
            { path: signaturePath ?? null },
        );
    }
    let resolved;
    try {
        resolved = verifyLocalRegularFile(signaturePath, {
            label: "detached experiment signature",
        });
    } catch (error) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_REQUIRED,
            `detached signature file is unavailable: ${
                error?.message ?? String(error)
            }`,
            { path: signaturePath, cause: error?.code ?? null },
            { cause: error },
        );
    }
    let bytes;
    try {
        bytes = fs.readFileSync(resolved);
    } catch (error) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_REQUIRED,
            `failed to read detached signature file: ${
                error?.message ?? String(error)
            }`,
            { path: resolved, cause: error?.code ?? null },
            { cause: error },
        );
    }
    if (bytes.length > MAX_SIGNATURE_FILE_BYTES) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
            `detached signature file exceeds ${MAX_SIGNATURE_FILE_BYTES} bytes`,
            { path: resolved, bytes: bytes.length },
        );
    }
    const signature = bytes.length === 64
        ? normalizeDetachedSignature(bytes)
        : normalizeDetachedSignature(bytes.toString("utf8"));
    try {
        const expectedHash = sha256Bytes(
            bytes,
            "sha256:crucible-experiment-signature-file-v1",
        );
        verifyAndHashFile(resolved, expectedHash, {
            label: "detached experiment signature",
            algorithm: "sha256:crucible-experiment-signature-file-v1",
        });
    } catch (error) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
            "detached signature file changed while it was being read",
            { path: resolved, cause: error?.code ?? null },
            { cause: error },
        );
    }
    return signature;
}

export function buildExperimentAuthorityManifest({
    experimentId,
    projectDir,
    harnessSuiteId,
    contract,
    trustFingerprint,
    investigationId = null,
}) {
    const normalizedContractHash = contractHash(contract);
    const derivedInvestigationId = deriveAuthorizedInvestigationId({
        experimentId,
        objective: contract.objective,
        projectDir,
        harnessSuiteId,
        harnessSuiteIdentity: contract.harnessSuiteIdentity,
        contractHash: normalizedContractHash,
        trustFingerprint,
    });
    if (investigationId !== null && investigationId !== derivedInvestigationId) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
            "requested investigation identity does not match the canonical signed payload",
            {
                expected: derivedInvestigationId,
                actual: investigationId,
            },
        );
    }
    return normalizeExperimentAuthorityManifest({
        version: EXPERIMENT_AUTHORITY_MANIFEST_VERSION,
        kind: EXPERIMENT_AUTHORITY_MANIFEST_KIND,
        experimentPayload: {
            version: 1,
            experimentId,
            projectDir,
            harnessSuiteId,
            contract,
        },
        contractHash: normalizedContractHash,
        harnessSuiteIdentity: contract.harnessSuiteIdentity,
        enumerandRoot: contract.enumerandManifest?.merkleRoot ?? null,
        statisticalPolicyIdentity: contract.statisticalPolicyIdentity,
        hypothesisPolicyIdentity: contract.hypothesisPolicyIdentity,
        trustFingerprint,
        investigationId: derivedInvestigationId,
    });
}

export function assertExperimentAuthorityBinding(authority, expected) {
    const normalized = normalizeAuthorityEnvelope(authority);
    const expectedManifest = buildExperimentAuthorityManifest({
        ...expected,
        trustFingerprint:
            expected.trustFingerprint ?? normalized.manifest.trustFingerprint,
        investigationId:
            expected.investigationId ?? normalized.manifest.investigationId,
    });
    if (!canonicalEqual(normalized.manifest, expectedManifest)) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_INVALID,
            "signed experiment manifest does not match the exact canonical experiment payload",
            {
                expectedManifestIdentity:
                    experimentAuthorityManifestIdentity(expectedManifest),
                actualManifestIdentity: normalized.manifestIdentity,
            },
        );
    }
    return normalized;
}

export function createExperimentAuthorityEnvelope({
    manifest,
    signature,
    trustFingerprint = manifest?.trustFingerprint,
}) {
    const normalizedManifest = normalizeManifestForAuthority(manifest);
    if (normalizedManifest.trustFingerprint !== trustFingerprint) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_FINGERPRINT_MISMATCH,
            "experiment authority envelope targets a different trust root",
            {
                expected: normalizedManifest.trustFingerprint,
                actual: trustFingerprint ?? null,
            },
        );
    }
    const detached = normalizeDetachedSignature(signature);
    const core = {
        version: EXPERIMENT_AUTHORITY_VERSION,
        algorithm: EXPERIMENT_AUTHORITY_ALGORITHM,
        manifest: normalizedManifest,
        manifestIdentity:
            experimentAuthorityManifestIdentity(normalizedManifest),
        signature: detached.base64,
        trustFingerprint,
    };
    return normalizeAuthorityEnvelope({
        ...core,
        identity: experimentAuthorityIdentity(core),
    });
}

function issueVerifiedExperimentAuthority(authority, trust) {
    const binding = Object.freeze({
        authority,
        trustedPublicKeyFingerprint: trust.fingerprint,
        signedPayload: authority.manifest,
        signedPayloadIdentity: authority.manifestIdentity,
        signature: authority.signature,
        contractHash: authority.manifest.contractHash,
        investigationId: authority.manifest.investigationId,
    });
    return new VerifiedExperimentAuthority(
        VERIFIED_EXPERIMENT_AUTHORITY_ISSUER,
        binding,
    );
}

export function readVerifiedExperimentAuthority(capability) {
    if (!VERIFIED_EXPERIMENT_AUTHORITIES.has(capability)) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.AUTHORITY_REQUIRED,
            "a verified experiment authority capability is required",
        );
    }
    return VERIFIED_EXPERIMENT_AUTHORITY_BINDINGS.get(capability);
}

export function verifyExperimentAuthority({
    authority,
    experimentId,
    projectDir,
    harnessSuiteId,
    contract,
    investigationId = null,
    env = process.env,
}) {
    const normalized = assertExperimentAuthorityBinding(authority, {
        experimentId,
        projectDir,
        harnessSuiteId,
        contract,
        trustFingerprint: authority?.manifest?.trustFingerprint,
        investigationId:
            investigationId ?? authority?.manifest?.investigationId ?? null,
    });
    const trust = resolveExperimentTrust(env);
    if (normalized.trustFingerprint !== trust.fingerprint) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.TRUST_FINGERPRINT_MISMATCH,
            "persisted experiment authority was signed under a different trust root",
            {
                expected: normalized.trustFingerprint,
                actual: trust.fingerprint,
            },
        );
    }
    const valid = verifyEd25519(
        null,
        experimentAuthorityManifestBytes(normalized.manifest),
        trust.publicKey,
        Buffer.from(normalized.signature, "base64"),
    );
    if (!valid) {
        fail(
            EXPERIMENT_AUTHORITY_ERROR_CODES.SIGNATURE_INVALID,
            "persisted detached experiment signature is invalid",
            {
                manifestIdentity: normalized.manifestIdentity,
                trustFingerprint: trust.fingerprint,
            },
        );
    }
    return issueVerifiedExperimentAuthority(normalized, trust);
}
