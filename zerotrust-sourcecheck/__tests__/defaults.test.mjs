// __tests__/defaults.test.mjs
//
// Tests for safeWrappers/defaults.mjs — the centralised DEFAULT_BUILD_ROOT
// resolution. Round-18 introduced this module to replace the hardcoded
// hardcoded Windows path that used to be embedded in 9 source
// files. The default now resolves from:
//   1. ZEROTRUST_BUILD_ROOT env var, OR
//   2. <homedir>/.copilot/zerotrust-sandbox

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import nodePath from "node:path";

import {
    DEFAULT_BUILD_ROOT,
    ensureDefaultBuildRoot,
    __internals,
} from "../safeWrappers/defaults.mjs";

test("DEFAULT_BUILD_ROOT is an absolute path", () => {
    assert.ok(DEFAULT_BUILD_ROOT, "must export a non-empty string");
    assert.ok(nodePath.isAbsolute(DEFAULT_BUILD_ROOT), "must be absolute");
});

test("DEFAULT_BUILD_ROOT contains no developer-specific paths (no leaked author/operator paths)", () => {
    // Catches accidental regression to any hardcoded developer path.
    assert.doesNotMatch(
        DEFAULT_BUILD_ROOT,
        /K:[\\\/]AI/i,
        "DEFAULT_BUILD_ROOT must not contain any developer-specific path fragment"
    );
});

test("resolveDefault: ZEROTRUST_BUILD_ROOT env var takes precedence", () => {
    const saved = process.env.ZEROTRUST_BUILD_ROOT;
    try {
        const override = process.platform === "win32"
            ? "D:\\custom\\sandbox"
            : "/var/custom/sandbox";
        process.env.ZEROTRUST_BUILD_ROOT = override;
        const got = __internals.resolveDefault();
        assert.equal(got, nodePath.resolve(override));
    } finally {
        if (saved === undefined) delete process.env.ZEROTRUST_BUILD_ROOT;
        else process.env.ZEROTRUST_BUILD_ROOT = saved;
    }
});

test("resolveDefault: falls back to <homedir>/.copilot/zerotrust-sandbox when env var is unset", () => {
    const saved = process.env.ZEROTRUST_BUILD_ROOT;
    try {
        delete process.env.ZEROTRUST_BUILD_ROOT;
        const got = __internals.resolveDefault();
        const expected = nodePath.resolve(
            nodePath.join(os.homedir(), ".copilot", "zerotrust-sandbox"),
        );
        assert.equal(got, expected);
    } finally {
        if (saved === undefined) delete process.env.ZEROTRUST_BUILD_ROOT;
        else process.env.ZEROTRUST_BUILD_ROOT = saved;
    }
});

test("resolveDefault: empty/whitespace env var is ignored, falls back to homedir", () => {
    const saved = process.env.ZEROTRUST_BUILD_ROOT;
    try {
        process.env.ZEROTRUST_BUILD_ROOT = "   ";
        const got = __internals.resolveDefault();
        const expected = nodePath.resolve(
            nodePath.join(os.homedir(), ".copilot", "zerotrust-sandbox"),
        );
        assert.equal(got, expected, "whitespace-only env var must be treated as unset");
    } finally {
        if (saved === undefined) delete process.env.ZEROTRUST_BUILD_ROOT;
        else process.env.ZEROTRUST_BUILD_ROOT = saved;
    }
});

// Round-19: env var path denylist
test("isDangerousRoot: filesystem roots are rejected", () => {
    assert.equal(__internals.isDangerousRoot("/"), true);
    assert.equal(__internals.isDangerousRoot("C:\\"), true);
});

test("isDangerousRoot: known system dirs are rejected", () => {
    if (process.platform === "win32") {
        assert.equal(__internals.isDangerousRoot("C:\\Windows"), true);
        assert.equal(__internals.isDangerousRoot("C:\\Program Files"), true);
        assert.equal(__internals.isDangerousRoot("C:\\Users"), true);
    } else {
        assert.equal(__internals.isDangerousRoot("/etc"), true);
        assert.equal(__internals.isDangerousRoot("/usr"), true);
        assert.equal(__internals.isDangerousRoot("/var"), true);
        assert.equal(__internals.isDangerousRoot("/tmp"), true);
    }
});

test("isDangerousRoot: case-insensitive on Windows", () => {
    // The denylist comparison lowercases both sides.
    assert.equal(__internals.isDangerousRoot("c:\\windows"), true);
});

test("isDangerousRoot: legitimate sandbox paths are accepted", () => {
    if (process.platform === "win32") {
        assert.equal(__internals.isDangerousRoot("C:\\Users\\someone\\.copilot\\zerotrust-sandbox"), false);
        assert.equal(__internals.isDangerousRoot("D:\\sandbox\\zerotrust"), false);
    } else {
        assert.equal(__internals.isDangerousRoot("/home/someone/.copilot/zerotrust-sandbox"), false);
        assert.equal(__internals.isDangerousRoot("/var/lib/zerotrust"), false);
    }
});

// Round-19 segment-count tightening: 1-segment paths under root are also
// rejected even when not on the explicit denylist, because they're
// equally risky (e.g. `/sandbox`, `C:\foo`).
test("isDangerousRoot: shallow 1-segment paths are rejected even if not on denylist", () => {
    if (process.platform === "win32") {
        assert.equal(__internals.isDangerousRoot("C:\\foo"), true);
        assert.equal(__internals.isDangerousRoot("D:\\trimmed"), true);
    } else {
        assert.equal(__internals.isDangerousRoot("/foo"), true);
        assert.equal(__internals.isDangerousRoot("/sandbox"), true);
    }
});

test("isDangerousRoot: macOS /Users is rejected", () => {
    // Independent of platform — the path is constructed as a literal
    // string. /Users is the macOS equivalent of /home + C:\Users and
    // must be denied even when this test runs on Windows / Linux.
    assert.equal(__internals.isDangerousRoot("/Users"), true);
});

test("resolveDefault: dangerous env var path falls back to homedir + warns", () => {
    const saved = process.env.ZEROTRUST_BUILD_ROOT;
    // Capture console.warn to verify the warning fires.
    const origWarn = console.warn;
    let warned = false;
    console.warn = () => { warned = true; };
    try {
        process.env.ZEROTRUST_BUILD_ROOT = process.platform === "win32" ? "C:\\Windows" : "/etc";
        const got = __internals.resolveDefault();
        const expected = nodePath.resolve(
            nodePath.join(os.homedir(), ".copilot", "zerotrust-sandbox"),
        );
        assert.equal(got, expected, "dangerous path must fall back to homedir default");
        assert.equal(warned, true, "must warn the operator about the rejected env var");
    } finally {
        console.warn = origWarn;
        if (saved === undefined) delete process.env.ZEROTRUST_BUILD_ROOT;
        else process.env.ZEROTRUST_BUILD_ROOT = saved;
    }
});

test("resolveDefault: env var is trimmed before use", () => {
    const saved = process.env.ZEROTRUST_BUILD_ROOT;
    try {
        const inner = process.platform === "win32"
            ? "D:\\sandbox\\trimmed"
            : "/var/lib/trimmed-sandbox";
        process.env.ZEROTRUST_BUILD_ROOT = `   ${inner}   `;
        const got = __internals.resolveDefault();
        assert.equal(got, nodePath.resolve(inner));
    } finally {
        if (saved === undefined) delete process.env.ZEROTRUST_BUILD_ROOT;
        else process.env.ZEROTRUST_BUILD_ROOT = saved;
    }
});

test("ensureDefaultBuildRoot returns DEFAULT_BUILD_ROOT and is idempotent", () => {
    // First call may or may not create the dir, depending on whether
    // it already existed. We just verify the contract: returns the
    // default, callable multiple times without throwing.
    const a = ensureDefaultBuildRoot();
    const b = ensureDefaultBuildRoot();
    assert.equal(a, DEFAULT_BUILD_ROOT);
    assert.equal(b, DEFAULT_BUILD_ROOT);
});
