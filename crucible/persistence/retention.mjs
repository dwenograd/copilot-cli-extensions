import fs from "node:fs";
import path from "node:path";
import {
    createHash,
    createPrivateKey,
    createPublicKey,
    generateKeyPairSync,
    randomBytes,
    sign,
    timingSafeEqual,
    verify,
} from "node:crypto";

import { canonicalize } from "./canonical.mjs";
import {
    InvalidArgumentError,
    SchemaIntegrityError,
    StorageError,
} from "./errors.mjs";
import { assertLocalDatabasePath } from "./paths.mjs";

export const TOMBSTONE_TYPE = "crucible-investigation-tombstone";
export const TOMBSTONE_VERSION = 1;
export const TOMBSTONE_KEY_TYPE = "crucible-tombstone-signing-key";
export const TOMBSTONE_KEY_VERSION = 1;
export const TOMBSTONE_KEY_FINGERPRINT_ALGORITHM =
    "sha256:crucible-tombstone-signing-key-v1";

const KEY_FILE_NAME = "tombstone-signing-key.json";
const TOMBSTONE_KEYS = Object.freeze([
    "payload",
    "signature",
    "signingKeyFingerprint",
    "type",
    "version",
]);
const TOMBSTONE_PAYLOAD_KEYS = Object.freeze([
    "archiveDigest",
    "createdAtMs",
    "deletedAt",
    "domainHead",
    "domainVersion",
    "investigationId",
]);
const KEY_DOCUMENT_KEYS = Object.freeze([
    "fingerprint",
    "privateKeyPem",
    "publicKeyPem",
    "type",
    "version",
]);
const ARCHIVE_DIGEST_RE = /^sha256:[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;

function exactKeys(value, expected) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const actual = Object.keys(value).sort();
    return actual.length === expected.length
        && actual.every((key, index) => key === expected[index]);
}

function isInside(candidate, root) {
    const relative = path.relative(path.resolve(root), path.resolve(candidate));
    return relative === ""
        || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function samePath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function fsyncDirectory(directory) {
    let descriptor;
    try {
        descriptor = fs.openSync(
            directory,
            process.platform === "win32" ? "r+" : "r",
        );
        fs.fsyncSync(descriptor);
    } finally {
        if (descriptor !== undefined) fs.closeSync(descriptor);
    }
}

function ensureDirectory(directory, env) {
    const resolved = assertLocalDatabasePath(directory, { env });
    const parsed = path.parse(resolved);
    const segments = path.relative(parsed.root, resolved)
        .split(path.sep)
        .filter(Boolean);
    let current = parsed.root;
    for (const segment of segments) {
        current = path.join(current, segment);
        let stat;
        try {
            stat = fs.lstatSync(current);
        } catch (error) {
            if (error?.code !== "ENOENT") throw error;
            fs.mkdirSync(current, { recursive: false, mode: 0o700 });
            stat = fs.lstatSync(current);
            fsyncDirectory(path.dirname(current));
        }
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
            throw new SchemaIntegrityError(
                "retention path contains a link or non-directory component",
                { path: current },
            );
        }
        const real = fs.realpathSync.native(current);
        if (!samePath(real, current)) {
            throw new SchemaIntegrityError(
                "retention path resolves through a link or reparse point",
                { path: current, real },
            );
        }
    }
    return resolved;
}

function atomicWrite(file, bytes, env) {
    const resolved = assertLocalDatabasePath(file, { env });
    const directory = ensureDirectory(path.dirname(resolved), env);
    const temporary = path.join(
        directory,
        `.${path.basename(resolved)}.${process.pid}.${
            randomBytes(12).toString("hex")
        }.tmp`,
    );
    let descriptor;
    try {
        descriptor = fs.openSync(temporary, "wx", 0o600);
        fs.writeFileSync(descriptor, bytes);
        fs.fsyncSync(descriptor);
        fs.closeSync(descriptor);
        descriptor = undefined;
        fs.linkSync(temporary, resolved);
        fsyncDirectory(directory);
        fs.unlinkSync(temporary);
        fsyncDirectory(directory);
        return resolved;
    } catch (error) {
        if (descriptor !== undefined) {
            try {
                fs.closeSync(descriptor);
            } catch {
                // Preserve the primary failure.
            }
        }
        try {
            fs.rmSync(temporary, { force: true });
        } catch {
            // Preserve the primary failure.
        }
        throw new StorageError(
            `failed to write durable retention file: ${
                error?.message ?? String(error)
            }`,
            error,
        );
    }
}

function assertRegularFile(file, label, env) {
    const resolved = assertLocalDatabasePath(file, { env });
    const stat = fs.lstatSync(resolved);
    if (stat.isSymbolicLink() || !stat.isFile()) {
        throw new SchemaIntegrityError(
            `${label} must be a regular non-link file`,
            { file: resolved },
        );
    }
    const real = fs.realpathSync.native(resolved);
    if (!samePath(real, resolved)) {
        throw new SchemaIntegrityError(
            `${label} resolves through a link or reparse point`,
            { file: resolved, real },
        );
    }
    return resolved;
}

function sha256Digest(bytes) {
    return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function publicKeyFingerprint(publicKey) {
    const der = publicKey.export({ type: "spki", format: "der" });
    const digest = createHash("sha256").update(der).digest("hex");
    return `${TOMBSTONE_KEY_FINGERPRINT_ALGORITHM}:${digest}`;
}

function validateKeyDocument(document) {
    if (!exactKeys(document, KEY_DOCUMENT_KEYS)
        || document.type !== TOMBSTONE_KEY_TYPE
        || document.version !== TOMBSTONE_KEY_VERSION
        || typeof document.privateKeyPem !== "string"
        || typeof document.publicKeyPem !== "string"
        || typeof document.fingerprint !== "string") {
        throw new SchemaIntegrityError(
            "tombstone signing-key document is invalid",
        );
    }
    const privateKey = createPrivateKey(document.privateKeyPem);
    const publicKey = createPublicKey(document.publicKeyPem);
    const fingerprint = publicKeyFingerprint(publicKey);
    if (fingerprint !== document.fingerprint) {
        throw new SchemaIntegrityError(
            "tombstone signing-key fingerprint is invalid",
            { expected: fingerprint, actual: document.fingerprint },
        );
    }
    const challenge = Buffer.from(
        "crucible-tombstone-signing-key-self-test-v1",
        "utf8",
    );
    const signature = sign(null, challenge, privateKey);
    if (!verify(null, challenge, publicKey, signature)) {
        throw new SchemaIntegrityError(
            "tombstone signing-key pair does not match",
        );
    }
    return Object.freeze({
        privateKey,
        publicKey,
        fingerprint,
    });
}

function loadSigningKey(keyRoot, env, { create = false } = {}) {
    const resolvedRoot = assertLocalDatabasePath(keyRoot, { env });
    if (!create && !fs.existsSync(resolvedRoot)) {
        throw new SchemaIntegrityError(
            "tombstone signing-key directory is missing",
            { keyRoot: resolvedRoot },
        );
    }
    const root = create
        ? ensureDirectory(resolvedRoot, env)
        : resolvedRoot;
    if (!create) {
        const stat = fs.lstatSync(root);
        if (stat.isSymbolicLink() || !stat.isDirectory()
            || !samePath(fs.realpathSync.native(root), root)) {
            throw new SchemaIntegrityError(
                "tombstone signing-key directory is unsafe",
                { keyRoot: root },
            );
        }
    }
    const file = path.join(root, KEY_FILE_NAME);
    if (fs.existsSync(file)) {
        const bytes = fs.readFileSync(
            assertRegularFile(
                file,
                "tombstone signing-key document",
                env,
            ),
        );
        let document;
        try {
            document = JSON.parse(bytes.toString("utf8"));
        } catch (error) {
            throw new SchemaIntegrityError(
                "tombstone signing-key document is not valid JSON",
                { message: error?.message ?? null },
            );
        }
        if (!Buffer.from(`${canonicalize(document)}\n`, "utf8").equals(bytes)) {
            throw new SchemaIntegrityError(
                "tombstone signing-key document is not canonical",
            );
        }
        return validateKeyDocument(document);
    }
    if (!create) {
        throw new SchemaIntegrityError(
            "tombstone signing-key document is missing",
            { file },
        );
    }
    const pair = generateKeyPairSync("ed25519", {
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const publicKey = createPublicKey(pair.publicKey);
    const document = {
        type: TOMBSTONE_KEY_TYPE,
        version: TOMBSTONE_KEY_VERSION,
        fingerprint: publicKeyFingerprint(publicKey),
        privateKeyPem: pair.privateKey,
        publicKeyPem: pair.publicKey,
    };
    try {
        atomicWrite(
            file,
            Buffer.from(`${canonicalize(document)}\n`, "utf8"),
            env,
        );
    } catch (error) {
        if (!fs.existsSync(file)) throw error;
    }
    return loadSigningKey(keyRoot, env);
}

function normalizePayload(payload) {
    let canonicalDeletedAt = false;
    if (typeof payload?.deletedAt === "string") {
        try {
            canonicalDeletedAt =
                new Date(payload.deletedAt).toISOString()
                === payload.deletedAt;
        } catch {
            canonicalDeletedAt = false;
        }
    }
    if (!exactKeys(payload, TOMBSTONE_PAYLOAD_KEYS)
        || typeof payload.investigationId !== "string"
        || !IDENTIFIER_RE.test(payload.investigationId)
        || !Number.isSafeInteger(payload.createdAtMs)
        || payload.createdAtMs < 0
        || !canonicalDeletedAt
        || !Number.isSafeInteger(payload.domainVersion)
        || payload.domainVersion < 1
        || !ARCHIVE_DIGEST_RE.test(payload.archiveDigest)
        || payload.domainHead === null
        || typeof payload.domainHead !== "object"
        || Array.isArray(payload.domainHead)
        || !Number.isSafeInteger(payload.domainHead.seq)
        || payload.domainHead.seq < 0
        || (payload.domainHead.eventHash !== null
            && typeof payload.domainHead.eventHash !== "string")) {
        throw new InvalidArgumentError("tombstone payload is invalid");
    }
    return structuredClone(payload);
}

function parseTombstoneBytes(bytes) {
    let document;
    try {
        document = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
        throw new SchemaIntegrityError(
            "tombstone is not valid JSON",
            { message: error?.message ?? null },
        );
    }
    if (!exactKeys(document, TOMBSTONE_KEYS)
        || document.type !== TOMBSTONE_TYPE
        || document.version !== TOMBSTONE_VERSION
        || typeof document.signingKeyFingerprint !== "string"
        || typeof document.signature !== "string") {
        throw new SchemaIntegrityError("tombstone document is invalid");
    }
    const canonicalBytes = Buffer.from(
        `${canonicalize(document)}\n`,
        "utf8",
    );
    if (!canonicalBytes.equals(bytes)) {
        throw new SchemaIntegrityError("tombstone bytes are not canonical");
    }
    return Object.freeze({
        document,
        payload: normalizePayload(document.payload),
        bytes: canonicalBytes,
        digest: sha256Digest(canonicalBytes),
    });
}

export function writeSignedTombstone({
    file,
    keyRoot,
    payload,
    env = process.env,
} = {}) {
    if (typeof file !== "string" || typeof keyRoot !== "string") {
        throw new InvalidArgumentError(
            "tombstone file and keyRoot are required",
        );
    }
    const normalizedPayload = normalizePayload(payload);
    const key = loadSigningKey(keyRoot, env, { create: true });
    const payloadBytes = Buffer.from(canonicalize(normalizedPayload), "utf8");
    const signature = sign(null, payloadBytes, key.privateKey)
        .toString("base64");
    const document = {
        type: TOMBSTONE_TYPE,
        version: TOMBSTONE_VERSION,
        payload: normalizedPayload,
        signingKeyFingerprint: key.fingerprint,
        signature,
    };
    const bytes = Buffer.from(`${canonicalize(document)}\n`, "utf8");
    const resolved = assertLocalDatabasePath(file, { env });
    if (fs.existsSync(resolved)) {
        const existing = verifySignedTombstone({
            file: resolved,
            keyRoot,
            expectedInvestigationId: normalizedPayload.investigationId,
            env,
        });
        const compatibleExisting = canonicalize({
            ...existing.payload,
            deletedAt: normalizedPayload.deletedAt,
        }) === canonicalize(normalizedPayload);
        if (!compatibleExisting) {
            throw new SchemaIntegrityError(
                "an incompatible tombstone already exists for this investigation",
                { file: resolved },
            );
        }
        return existing;
    }
    atomicWrite(resolved, bytes, env);
    return verifySignedTombstone({
        file: resolved,
        keyRoot,
        expectedDigest: sha256Digest(bytes),
        expectedInvestigationId: normalizedPayload.investigationId,
        env,
    });
}

export function verifySignedTombstone({
    file,
    keyRoot,
    expectedDigest = null,
    expectedInvestigationId = null,
    env = process.env,
} = {}) {
    const resolved = assertLocalDatabasePath(file, { env });
    const parsed = parseTombstoneBytes(fs.readFileSync(
        assertRegularFile(resolved, "tombstone", env),
    ));
    const key = loadSigningKey(keyRoot, env);
    if (parsed.document.signingKeyFingerprint !== key.fingerprint) {
        throw new SchemaIntegrityError(
            "tombstone signing-key fingerprint does not match",
            {
                expected: key.fingerprint,
                actual: parsed.document.signingKeyFingerprint,
            },
        );
    }
    let signature;
    try {
        signature = Buffer.from(parsed.document.signature, "base64");
    } catch (error) {
        throw new SchemaIntegrityError(
            "tombstone signature is not valid base64",
            { message: error?.message ?? null },
        );
    }
    if (signature.length === 0
        || signature.toString("base64")
            !== parsed.document.signature) {
        throw new SchemaIntegrityError(
            "tombstone signature is not canonical base64",
        );
    }
    const payloadBytes = Buffer.from(
        canonicalize(parsed.payload),
        "utf8",
    );
    if (!verify(null, payloadBytes, key.publicKey, signature)) {
        throw new SchemaIntegrityError(
            "tombstone signature verification failed",
        );
    }
    if (expectedDigest !== null) {
        if (!ARCHIVE_DIGEST_RE.test(expectedDigest)) {
            throw new InvalidArgumentError(
                "expected tombstone digest must be sha256:<64 lowercase hex>",
            );
        }
        const expected = Buffer.from(expectedDigest.slice(7), "hex");
        const actual = Buffer.from(parsed.digest.slice(7), "hex");
        if (!timingSafeEqual(expected, actual)) {
            throw new SchemaIntegrityError(
                "tombstone digest does not match the catalog",
                { expected: expectedDigest, actual: parsed.digest },
            );
        }
    }
    if (expectedInvestigationId !== null
        && parsed.payload.investigationId !== expectedInvestigationId) {
        throw new SchemaIntegrityError(
            "tombstone investigation identity does not match",
            {
                expected: expectedInvestigationId,
                actual: parsed.payload.investigationId,
            },
        );
    }
    return Object.freeze({
        file: resolved,
        digest: parsed.digest,
        sizeBytes: parsed.bytes.length,
        signingKeyFingerprint: key.fingerprint,
        signature: parsed.document.signature,
        payload: Object.freeze(parsed.payload),
        verified: true,
    });
}

export function measureRetainedTree(root, { env = process.env } = {}) {
    const resolved = assertLocalDatabasePath(root, { env });
    const rootStat = fs.lstatSync(resolved);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
        throw new SchemaIntegrityError(
            "retained tree root must be a real directory",
            { root: resolved },
        );
    }
    const rootReal = fs.realpathSync.native(resolved);
    if (!samePath(rootReal, resolved)) {
        throw new SchemaIntegrityError(
            "retained tree root resolves through a link or reparse point",
            { root: resolved, real: rootReal },
        );
    }
    let sizeBytes = 0;
    let fileCount = 0;
    const walk = (directory) => {
        for (const name of fs.readdirSync(directory).sort()) {
            const child = path.join(directory, name);
            const stat = fs.lstatSync(child);
            if (stat.isSymbolicLink()) {
                throw new SchemaIntegrityError(
                    "retained tree contains a link or reparse entry",
                    { path: child },
                );
            }
            if (stat.isDirectory()) {
                const real = fs.realpathSync.native(child);
                if (!isInside(real, rootReal)) {
                    throw new SchemaIntegrityError(
                        "retained tree directory escaped its root",
                        { path: child, real },
                    );
                }
                walk(child);
            } else if (stat.isFile()) {
                sizeBytes += stat.size;
                fileCount += 1;
                if (!Number.isSafeInteger(sizeBytes)) {
                    throw new SchemaIntegrityError(
                        "retained tree size exceeds the safe integer range",
                    );
                }
            } else {
                throw new SchemaIntegrityError(
                    "retained tree contains a non-regular entry",
                    { path: child },
                );
            }
        }
    };
    walk(resolved);
    return Object.freeze({ sizeBytes, fileCount });
}

export function removeRetainedTree({
    target,
    containmentRoot,
    env = process.env,
} = {}) {
    const root = assertLocalDatabasePath(containmentRoot, { env });
    const resolved = assertLocalDatabasePath(target, { env });
    if (samePath(resolved, root)
        || !isInside(resolved, root)) {
        throw new InvalidArgumentError(
            "retained tree deletion escaped its containment root",
            { target: resolved, containmentRoot: root },
        );
    }
    const rootStat = fs.lstatSync(root);
    const rootReal = fs.realpathSync.native(root);
    if (rootStat.isSymbolicLink()
        || !rootStat.isDirectory()
        || !samePath(rootReal, root)) {
        throw new SchemaIntegrityError(
            "retained tree containment root is unsafe",
            { containmentRoot: root, real: rootReal },
        );
    }
    const remove = (entry) => {
        let stat;
        try {
            stat = fs.lstatSync(entry);
        } catch (error) {
            if (error?.code === "ENOENT") return;
            throw error;
        }
        const parentReal = fs.realpathSync.native(path.dirname(entry));
        if (!isInside(parentReal, rootReal)) {
            throw new SchemaIntegrityError(
                "retained tree deletion parent escaped containment",
                {
                    path: entry,
                    parentReal,
                    containmentRoot: rootReal,
                },
            );
        }
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
            fs.unlinkSync(entry);
            return;
        }
        const real = fs.realpathSync.native(entry);
        if (!samePath(real, entry)
            || !isInside(real, rootReal)) {
            throw new SchemaIntegrityError(
                "retained tree deletion encountered an unsafe directory",
                { path: entry, real, containmentRoot: root },
            );
        }
        for (const name of fs.readdirSync(entry)) {
            remove(path.join(entry, name));
        }
        fs.rmdirSync(entry);
    };
    remove(resolved);
    if (fs.existsSync(path.dirname(resolved))) {
        fsyncDirectory(path.dirname(resolved));
    }
    return !fs.existsSync(resolved);
}
