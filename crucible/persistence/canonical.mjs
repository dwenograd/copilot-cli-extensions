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

import { InvalidArgumentError } from "./errors.mjs";

// The prev_hash of the first event in every investigation.
export const GENESIS_PREV_HASH = "0".repeat(64);

// Deterministic JSON: object keys sorted recursively; undefined rejected (JSON
// cannot represent it and it would make the hash ambiguous).
export function canonicalize(value) {
    return JSON.stringify(sortValue(value));
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

// Compute the canonical event hash from the exact fields persisted with the
// event. Any change to any field changes the hash; the caller-supplied
// `payloadCanonical` must already be the canonical string that is stored.
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
    const envelope = canonicalize({
        version: 1,
        investigationId,
        seq,
        prevHash,
        kind,
        payload: JSON.parse(payloadCanonical),
        isTerminal: isTerminal === true || isTerminal === 1,
        terminalKind,
        attemptId,
        evidenceKind,
        createdAt,
    });
    return createHash("sha256").update("crucible-event:").update(envelope).digest("hex");
}

// SHA-256 of arbitrary bytes (used for inline artifact self-description).
export function sha256Hex(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}
