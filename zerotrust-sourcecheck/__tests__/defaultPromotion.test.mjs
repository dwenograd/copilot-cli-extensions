// defaultPromotion.test.mjs — staged default-promotion contract.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
    DEFAULT_STRATEGY,
    _resolveEffectiveModeWith,
    defaultStrategy,
    flipReadinessGate,
    resolveEffectiveMode,
} from "../modes.mjs";

const REPO_KIND = "repo";
const RELEASE_KIND = "release";

function env(overrides = {}) {
    return { ...overrides };
}

// ---------- Live default-promotion state (DEFAULT_STRATEGY = "opt-out") ----------

test("opt-out: repo URL without env defaults to council mode", () => {
    assert.deepEqual(resolveEffectiveMode({ urlKind: REPO_KIND, env: env() }), {
        mode: "audit_source_council",
        source: "default",
    });
});

test("opt-out: council env is a no-op (council already default) for repo URL", () => {
    assert.deepEqual(
        resolveEffectiveMode({
            urlKind: REPO_KIND,
            env: env({ ZEROTRUST_DEFAULT_COUNCIL: "1" }),
        }),
        { mode: "audit_source_council", source: "default" },
    );
});

test("opt-out: council env does not change release URL default", () => {
    assert.deepEqual(
        resolveEffectiveMode({
            urlKind: RELEASE_KIND,
            env: env({ ZEROTRUST_DEFAULT_COUNCIL: "1" }),
        }),
        { mode: "verify_release", source: "default" },
    );
});

test("opt-out: deterministic-only env downgrades repo URL to audit_source", () => {
    assert.deepEqual(
        resolveEffectiveMode({
            urlKind: REPO_KIND,
            env: env({ ZEROTRUST_DETERMINISTIC_ONLY: "1" }),
        }),
        { mode: "audit_source", source: "env" },
    );
});

test("opt-out: deterministic-only env wins when both env vars are set", () => {
    assert.deepEqual(
        resolveEffectiveMode({
            urlKind: REPO_KIND,
            env: env({
                ZEROTRUST_DEFAULT_COUNCIL: "1",
                ZEROTRUST_DETERMINISTIC_ONLY: "1",
            }),
        }),
        { mode: "audit_source", source: "env" },
    );
});

test("opt-out: explicit build mode wins over default", () => {
    assert.deepEqual(
        resolveEffectiveMode({
            explicitMode: "audit_and_safe_build",
            urlKind: REPO_KIND,
            env: env(),
        }),
        { mode: "audit_and_safe_build", source: "explicit" },
    );
});

// ---------- Source-of-truth strategy ----------

test("defaultStrategy returns opt-out (council mode is the default)", () => {
    assert.equal(defaultStrategy(), "opt-out");
});

test("DEFAULT_STRATEGY is exported as opt-out", () => {
    assert.equal(DEFAULT_STRATEGY, "opt-out");
});

// ---------- Flip readiness gate ----------

test("flipReadinessGate blocks when corpus and hook probe are not ready", () => {
    assert.deepEqual(
        flipReadinessGate({ corpusGreen: false, hookProbeOk: false }),
        {
            readyToFlip: false,
            blockedReasons: ["corpus-not-green", "hook-probe-failed"],
        },
    );
});

test("flipReadinessGate blocks on hook probe when corpus is green", () => {
    assert.deepEqual(
        flipReadinessGate({ corpusGreen: true, hookProbeOk: false }),
        {
            readyToFlip: false,
            blockedReasons: ["hook-probe-failed"],
        },
    );
});

test("flipReadinessGate blocks on corpus when hook probe is ready", () => {
    assert.deepEqual(
        flipReadinessGate({ corpusGreen: false, hookProbeOk: true }),
        {
            readyToFlip: false,
            blockedReasons: ["corpus-not-green"],
        },
    );
});

test("flipReadinessGate is ready when corpus and hook probe are ready", () => {
    assert.deepEqual(
        flipReadinessGate({ corpusGreen: true, hookProbeOk: true }),
        {
            readyToFlip: true,
            blockedReasons: [],
        },
    );
});

test("flipReadinessGate defaults to safe blocked reasons", () => {
    assert.deepEqual(flipReadinessGate(), {
        readyToFlip: false,
        blockedReasons: ["corpus-not-green", "hook-probe-failed"],
    });
});

// ---------- Future opt-out strategy simulation ----------

test("future opt-out: repo URL defaults to council mode", () => {
    assert.equal(
        _resolveEffectiveModeWith({ urlKind: REPO_KIND, env: env(), strategy: "opt-out" }).mode,
        "audit_source_council",
    );
});

test("future opt-out: release URL keeps release verification default", () => {
    assert.equal(
        _resolveEffectiveModeWith({ urlKind: RELEASE_KIND, env: env(), strategy: "opt-out" }).mode,
        "verify_release",
    );
});

test("future opt-out: deterministic-only env downgrades repo URL", () => {
    assert.equal(
        _resolveEffectiveModeWith({
            urlKind: REPO_KIND,
            env: env({ ZEROTRUST_DETERMINISTIC_ONLY: "1" }),
            strategy: "opt-out",
        }).mode,
        "audit_source",
    );
});

test("future opt-out: council env is a no-op for repo URL", () => {
    assert.equal(
        _resolveEffectiveModeWith({
            urlKind: REPO_KIND,
            env: env({ ZEROTRUST_DEFAULT_COUNCIL: "1" }),
            strategy: "opt-out",
        }).mode,
        "audit_source_council",
    );
});

test("future opt-out: deterministic-only env wins over council env", () => {
    assert.equal(
        _resolveEffectiveModeWith({
            urlKind: REPO_KIND,
            env: env({
                ZEROTRUST_DEFAULT_COUNCIL: "1",
                ZEROTRUST_DETERMINISTIC_ONLY: "1",
            }),
            strategy: "opt-out",
        }).mode,
        "audit_source",
    );
});
