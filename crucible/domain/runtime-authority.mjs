import {
    hashCanonical,
    immutableCanonical,
} from "./canonical.mjs";
import { ContractError } from "./errors.mjs";

export const RUNTIME_CONFIG_AUTHORITY_VERSION = 1;
export const RUNTIME_CONFIG_AUTHORITY_KIND =
    "CrucibleRuntimeConfigAuthority";
export const RUNTIME_CONFIG_AUTHORITY_FINGERPRINT_ALGORITHM =
    "sha256:crucible-runtime-config-authority-v1";

const AUTHORITY_KEYS = Object.freeze([
    "fingerprint",
    "identities",
    "kind",
    "sandbox",
    "securityConfig",
    "version",
    "workerAdditionalContextHash",
]);
const TAGGED_SHA256 =
    /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u;

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

function authorityCore(value) {
    return {
        version: value.version,
        kind: value.kind,
        securityConfig: value.securityConfig,
        identities: value.identities,
        workerAdditionalContextHash: value.workerAdditionalContextHash,
        sandbox: value.sandbox,
    };
}

export function runtimeConfigAuthorityFingerprint(value) {
    return hashCanonical(
        authorityCore(value),
        RUNTIME_CONFIG_AUTHORITY_FINGERPRINT_ALGORITHM,
    );
}

export function normalizeRuntimeConfigAuthority(value) {
    requirePlainObject(value, "runtime config authority");
    const expected = new Set(AUTHORITY_KEYS);
    const missing = AUTHORITY_KEYS.filter((key) => !Object.hasOwn(value, key));
    const unknown = Object.keys(value).filter((key) => !expected.has(key));
    if (missing.length > 0 || unknown.length > 0) {
        fail("runtime config authority must contain exactly the canonical fields", {
            missing,
            unknown,
        });
    }
    if (value.version !== RUNTIME_CONFIG_AUTHORITY_VERSION) {
        fail(
            `runtime config authority version must be ${
                RUNTIME_CONFIG_AUTHORITY_VERSION
            }`,
            { actual: value.version ?? null },
        );
    }
    if (value.kind !== RUNTIME_CONFIG_AUTHORITY_KIND) {
        fail(`runtime config authority kind must be ${RUNTIME_CONFIG_AUTHORITY_KIND}`, {
            actual: value.kind ?? null,
        });
    }
    const core = {
        version: RUNTIME_CONFIG_AUTHORITY_VERSION,
        kind: RUNTIME_CONFIG_AUTHORITY_KIND,
        securityConfig: requirePlainObject(
            value.securityConfig,
            "runtime config authority.securityConfig",
        ),
        identities: requirePlainObject(
            value.identities,
            "runtime config authority.identities",
        ),
        workerAdditionalContextHash: requireTaggedHash(
            value.workerAdditionalContextHash,
            "runtime config authority.workerAdditionalContextHash",
            "sha256:crucible-worker-additional-context-v1",
        ),
        sandbox: requirePlainObject(
            value.sandbox,
            "runtime config authority.sandbox",
        ),
    };
    const fingerprint = runtimeConfigAuthorityFingerprint(core);
    if (value.fingerprint !== fingerprint) {
        fail("runtime config authority fingerprint does not match its canonical payload", {
            expected: fingerprint,
            actual: value.fingerprint ?? null,
        });
    }
    return immutableCanonical({ ...core, fingerprint });
}
