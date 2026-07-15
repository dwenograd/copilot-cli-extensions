// crucible/persistence/canonical.mjs
//
// Canonical JSON serialization + the event-hash chain primitive.
//
// The repository owns a *structural* hash chain over the event log: each event
// stores a `prev_hash` (the previous event's hash, or GENESIS for the first)
// and an `event_hash` computed deterministically from the event's own stored
// fields. This is a tamper-evidence mechanism for the log itself and is NOT
// domain policy — it says nothing about whether a decision was correct, only
// that the recorded bytes have not been altered after the fact.
//
// Payloads are stored in canonical (stable-key-order) form so that the hash is
// reproducible across processes and Node versions.

import { createHash } from "node:crypto";

import { CanonicalPayloadError, InvalidArgumentError } from "./errors.mjs";

// The prev_hash of the first event in every investigation.
export const GENESIS_PREV_HASH = "0".repeat(64);
const ISO_TIMESTAMP_RE =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;

export function normalizeCreatedAt(value, field = "createdAt") {
    if (typeof value !== "string" || !ISO_TIMESTAMP_RE.test(value)) {
        throw new InvalidArgumentError(
            `${field} must be an ISO-8601 timestamp string with an explicit timezone`,
            { field, valueType: typeof value },
        );
    }
    const parsed = new Date(value);
    if (!Number.isFinite(parsed.valueOf())) {
        throw new InvalidArgumentError(`${field} must be a valid ISO-8601 timestamp`, {
            field,
            value,
        });
    }
    return parsed.toISOString();
}

// Deterministic JSON: object keys sorted recursively; undefined rejected (JSON
// cannot represent it and it would make the hash ambiguous).
export function canonicalize(value) {
    return JSON.stringify(sortValue(value));
}

export function inspectCanonicalJson(text) {
    if (typeof text !== "string") {
        return {
            ok: false,
            reason: "payload is not text",
            value: undefined,
            canonical: undefined,
        };
    }
    try {
        const value = JSON.parse(text);
        const canonical = canonicalize(value);
        return {
            ok: canonical === text,
            reason: canonical === text ? null : "payload text is not canonical JSON",
            value,
            canonical,
        };
    } catch (err) {
        return {
            ok: false,
            reason: `payload is not valid JSON: ${err.message}`,
            value: undefined,
            canonical: undefined,
        };
    }
}

export function parseCanonicalJson(text, details = undefined) {
    const inspected = inspectCanonicalJson(text);
    if (!inspected.ok) {
        throw new CanonicalPayloadError(
            "stored event payload is not exact canonical JSON",
            {
                ...details,
                reason: inspected.reason,
                storedLength: typeof text === "string" ? Buffer.byteLength(text, "utf8") : null,
                canonicalLength: inspected.canonical === undefined
                    ? null
                    : Buffer.byteLength(inspected.canonical, "utf8"),
            },
        );
    }
    return inspected.value;
}

function sortValue(v) {
    if (v === undefined) {
        throw new InvalidArgumentError("cannot canonicalize `undefined`");
    }
    if (v === null || typeof v !== "object") {
        if (typeof v === "number" && !Number.isFinite(v)) {
            throw new InvalidArgumentError("cannot canonicalize non-finite number", { value: String(v) });
        }
        return v;
    }
    if (Array.isArray(v)) {
        return v.map(sortValue);
    }
    const out = {};
    for (const key of Object.keys(v).sort()) {
        const child = v[key];
        if (child === undefined) {
            continue; // match JSON.stringify's omission of undefined members
        }
        out[key] = sortValue(child);
    }
    return out;
}

// Compute the event hash from the exact fields persisted with the event. The
// payload is deliberately framed as raw canonical UTF-8 text rather than parsed
// and reserialized, so whitespace, key order, and escape encoding are bound.
export function computeEventHash({
    investigationId,
    seq,
    prevHash,
    kind,
    payloadCanonical,
    isTerminal = false,
    terminalKind = null,
    attemptId = null,
    evidenceKind = null,
    createdAt,
}) {
    if (typeof payloadCanonical !== "string") {
        throw new InvalidArgumentError("payloadCanonical must be a string");
    }
    const normalizedCreatedAt = normalizeCreatedAt(createdAt, "createdAt");
    const header = canonicalize({
        version: 2,
        investigationId,
        seq,
        prevHash,
        kind,
        isTerminal: isTerminal === true || isTerminal === 1,
        terminalKind,
        attemptId,
        evidenceKind,
        createdAt: normalizedCreatedAt,
    });
    return createHash("sha256")
        .update("crucible-event:v2\0")
        .update(header, "utf8")
        .update("\0payload\0")
        .update(payloadCanonical, "utf8")
        .digest("hex");
}

// SHA-256 of arbitrary bytes.
export function sha256Hex(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}
