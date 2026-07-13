import { describe, expect, it } from "vitest";

import {
    BUNDLE_ERROR_CODES,
    BUNDLE_TYPE,
    BUNDLE_VERSION,
    authenticateBundleVerification,
    validateBundleManifest,
} from "../persistence/bundle.mjs";
import {
    SCHEMA_FINGERPRINT,
    SCHEMA_VERSION,
    canonicalize,
} from "../persistence/index.mjs";

const DIGEST_HEX = "a".repeat(64);
const DIGEST = `sha256:${DIGEST_HEX}`;

function manifest() {
    return {
        type: BUNDLE_TYPE,
        version: BUNDLE_VERSION,
        algo: "sha256",
        createdAt: "2026-07-13T00:00:00.000Z",
        database: {
            path: "db/database.sqlite",
            size: 0,
            sha256: "b".repeat(64),
            schemaVersion: SCHEMA_VERSION,
            schemaFingerprint: SCHEMA_FINGERPRINT,
        },
        investigation: {
            id: "fast-investigation",
            domainVersion: 4,
            domainHead: {
                seq: 0,
                eventHash: null,
            },
        },
        artifacts: [],
        objects: [],
        snapshots: [],
        scientificReplay: null,
        metadata: {},
    };
}

function verification() {
    const value = manifest();
    return {
        digest: DIGEST,
        manifest: value,
        manifestBytes: Buffer.from(`${canonicalize(value)}\n`, "utf8"),
        inventoryBytes: Buffer.from(
            `${"b".repeat(64)}  db/database.sqlite\n`,
            "utf8",
        ),
    };
}

describe("bundle manifest policy", () => {
    it("accepts only the exact canonical v4 manifest schema and bytes", () => {
        const value = manifest();
        const bytes = Buffer.from(`${canonicalize(value)}\n`, "utf8");

        expect(validateBundleManifest(value, bytes)).toEqual(value);

        expect(() => validateBundleManifest({
            ...value,
            modelControlledPath: "outside",
        })).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.MANIFEST_INVALID,
        }));
        expect(() => validateBundleManifest(
            value,
            Buffer.from(JSON.stringify(value), "utf8"),
        )).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.MANIFEST_INVALID,
        }));
    });

    it("rejects non-canonical timestamps and domain-head bindings", () => {
        expect(() => validateBundleManifest({
            ...manifest(),
            createdAt: "2026-07-13T00:00:00Z",
        })).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.MANIFEST_INVALID,
        }));
        expect(() => validateBundleManifest({
            ...manifest(),
            investigation: {
                ...manifest().investigation,
                domainHead: { seq: 1, eventHash: null },
            },
        })).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.MANIFEST_INVALID,
        }));
    });
});

describe("bundle authentication policy", () => {
    it("requires authentication unless self-consistent import is explicit", () => {
        expect(() => authenticateBundleVerification(
            verification(),
        )).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.AUTHENTICATION_REQUIRED,
        }));
        expect(authenticateBundleVerification(
            verification(),
            { allowUnauthenticated: true },
        )).toBe("self-consistent");
    });

    it("accepts canonical or bare expected digests and rejects mismatches", () => {
        expect(authenticateBundleVerification(
            verification(),
            { expectedDigest: DIGEST },
        )).toBe("authenticated");
        expect(authenticateBundleVerification(
            verification(),
            { expectedDigest: DIGEST_HEX },
        )).toBe("authenticated");
        expect(() => authenticateBundleVerification(
            verification(),
            { expectedDigest: `sha256:${"c".repeat(64)}` },
        )).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.AUTHENTICATION_FAILED,
        }));
    });

    it("binds caller-owned signatures to the verified digest and canonical bytes", () => {
        let observed = null;
        expect(authenticateBundleVerification(
            verification(),
            {
                expectedSignature: "operator-signature",
                verifySignature: (input) => {
                    observed = input;
                    return true;
                },
            },
        )).toBe("authenticated");
        expect(observed).toMatchObject({
            digest: DIGEST,
            signature: "operator-signature",
            manifest: manifest(),
        });
        expect(Buffer.isBuffer(observed.manifestBytes)).toBe(true);
        expect(Buffer.isBuffer(observed.inventoryBytes)).toBe(true);
    });
});
