import { createHash } from "node:crypto";
import { CanonicalizationError } from "./errors.mjs";

export const CANONICAL_HASH_ALGORITHM = "sha256:crucible-canonical-json-v1";
export const EVENT_HASH_ALGORITHM = "sha256:crucible-event-v4";
export const CONTRACT_HASH_ALGORITHM = "sha256:crucible-contract-v4";

function fail(path, reason) {
    throw new CanonicalizationError(`Cannot canonicalize ${path}: ${reason}`, {
        path,
        reason,
    });
}

function serialize(value, path, ancestors) {
    if (value === null) {
        return "null";
    }

    switch (typeof value) {
        case "boolean":
            return value ? "true" : "false";
        case "string":
            return JSON.stringify(value);
        case "number":
            if (!Number.isFinite(value)) {
                fail(path, "numbers must be finite");
            }
            return Object.is(value, -0) ? "0" : JSON.stringify(value);
        case "undefined":
        case "bigint":
        case "symbol":
        case "function":
            fail(path, `unsupported ${typeof value}`);
            break;
        case "object":
            break;
        default:
            fail(path, `unsupported ${typeof value}`);
    }

    if (ancestors.has(value)) {
        fail(path, "cyclic reference");
    }

    ancestors.add(value);
    try {
        if (Array.isArray(value)) {
            const parts = [];
            for (let index = 0; index < value.length; index += 1) {
                if (!Object.hasOwn(value, index)) {
                    fail(`${path}[${index}]`, "sparse arrays are not canonical JSON");
                }
                parts.push(serialize(value[index], `${path}[${index}]`, ancestors));
            }
            return `[${parts.join(",")}]`;
        }

        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) {
            fail(path, "only plain objects are supported");
        }
        if (Object.getOwnPropertySymbols(value).length > 0) {
            fail(path, "symbol keys are not supported");
        }

        const keys = Object.keys(value).sort();
        const parts = keys.map((key) => {
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (!descriptor || !Object.hasOwn(descriptor, "value")) {
                fail(`${path}.${key}`, "accessor properties are not supported");
            }
            return `${JSON.stringify(key)}:${serialize(descriptor.value, `${path}.${key}`, ancestors)}`;
        });
        return `{${parts.join(",")}}`;
    } finally {
        ancestors.delete(value);
    }
}

export function canonicalJson(value) {
    return serialize(value, "$", new Set());
}

export function canonicalClone(value) {
    return JSON.parse(canonicalJson(value));
}

export function deepFreeze(value) {
    if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
        return value;
    }
    Object.freeze(value);
    for (const child of Object.values(value)) {
        deepFreeze(child);
    }
    return value;
}

export function immutableCanonical(value) {
    return deepFreeze(canonicalClone(value));
}

export function hashCanonical(value, algorithm = CANONICAL_HASH_ALGORITHM) {
    if (typeof algorithm !== "string" || !/^sha256:[a-z0-9][a-z0-9._-]*$/u.test(algorithm)) {
        throw new CanonicalizationError("Hash algorithm tag must identify a SHA-256 canonical algorithm");
    }
    const digest = createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
    return `${algorithm}:${digest}`;
}

export function isAlgorithmTaggedSha256(value) {
    return typeof value === "string"
        && /^sha256:[a-z0-9][a-z0-9._-]*:[a-f0-9]{64}$/u.test(value);
}

export function canonicalEqual(left, right) {
    return canonicalJson(left) === canonicalJson(right);
}
