// modes.test.mjs — lock in the mode-taxonomy contract from modes.mjs.
//
// modes.mjs is the single source of truth that handler.mjs, enforcement.mjs,
// packet.mjs, and extension.mjs all import from. These tests pin the
// behavior so Wave 1 / Wave 4 changes can't silently break the contract.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
    VALID_MODES,
    VALID_MODES_SET,
    COUNCIL_MODES,
    COUNCIL_MODES_SET,
    BUILD_MODES,
    BUILD_MODES_SET,
    FULL_BUILD_MODES,
    FULL_BUILD_MODES_SET,
    LOCAL_SOURCE_MODES,
    LOCAL_SOURCE_MODES_SET,
    isValidMode,
    modeUsesCouncil,
    modeIsBuild,
    modeIsFullBuild,
    modeIsSafeBuild,
    modeIsCouncilBuild,
    modeIsAudit,
    modeNeedsClone,
    modeUsesApiDirect,
    modeUsesLocalSource,
    defaultModeForUrlKind,
    resolveEffectiveMode,
} from "../modes.mjs";

// ---------- Mode set membership ----------

test("VALID_MODES contains the currently shipped modes", () => {
    assert.deepEqual([...VALID_MODES], [
        "metadata_only",
        "audit_source",
        "audit_source_council",
        "audit_local_source",
        "audit_local_source_council",
        "verify_release",
        "audit_and_safe_build",
        "audit_and_full_build",
        "audit_and_safe_build_council",
        "audit_and_full_build_council",
    ]);
});

test("VALID_MODES includes build-council modes", () => {
    assert.equal(VALID_MODES_SET.has("audit_and_safe_build_council"), true);
    assert.equal(VALID_MODES_SET.has("audit_and_full_build_council"), true);
});

test("VALID_MODES includes local-source modes", () => {
    assert.equal(VALID_MODES_SET.has("audit_local_source"), true);
    assert.equal(VALID_MODES_SET.has("audit_local_source_council"), true);
});

test("COUNCIL_MODES contains source, local-source, and build council modes", () => {
    assert.deepEqual([...COUNCIL_MODES], [
        "audit_source_council",
        "audit_local_source_council",
        "audit_and_safe_build_council",
        "audit_and_full_build_council",
    ]);
});

test("BUILD_MODES contains non-council and council build modes", () => {
    assert.deepEqual([...BUILD_MODES].sort(), [
        "audit_and_full_build",
        "audit_and_full_build_council",
        "audit_and_safe_build",
        "audit_and_safe_build_council",
    ]);
});

test("FULL_BUILD_MODES contains both full-build modes", () => {
    assert.deepEqual([...FULL_BUILD_MODES], [
        "audit_and_full_build",
        "audit_and_full_build_council",
    ]);
});

// ---------- Predicates ----------

test("isValidMode accepts every shipped mode and rejects others", () => {
    for (const m of VALID_MODES) assert.equal(isValidMode(m), true, `expected valid: ${m}`);
    assert.equal(isValidMode("nonsense"), false);
    assert.equal(isValidMode(""), false);
    assert.equal(isValidMode(null), false);
    assert.equal(isValidMode(undefined), false);
});

test("modeUsesCouncil only returns true for council modes", () => {
    assert.equal(modeUsesCouncil("audit_source_council"), true);
    assert.equal(modeUsesCouncil("audit_local_source_council"), true);
    assert.equal(modeUsesCouncil("audit_and_safe_build_council"), true);
    assert.equal(modeUsesCouncil("audit_and_full_build_council"), true);
    for (const m of ["metadata_only", "audit_source", "audit_local_source", "verify_release",
                      "audit_and_safe_build", "audit_and_full_build"]) {
        assert.equal(modeUsesCouncil(m), false, `expected false: ${m}`);
    }
});

test("modeIsBuild only returns true for build modes", () => {
    assert.equal(modeIsBuild("audit_and_safe_build"), true);
    assert.equal(modeIsBuild("audit_and_full_build"), true);
    assert.equal(modeIsBuild("audit_and_safe_build_council"), true);
    assert.equal(modeIsBuild("audit_and_full_build_council"), true);
    for (const m of ["metadata_only", "audit_source", "audit_source_council",
                     "audit_local_source", "audit_local_source_council", "verify_release"]) {
        assert.equal(modeIsBuild(m), false, `expected false: ${m}`);
    }
});

test("modeIsFullBuild only returns true for full-build modes", () => {
    assert.equal(modeIsFullBuild("audit_and_full_build"), true);
    assert.equal(modeIsFullBuild("audit_and_full_build_council"), true);
    assert.equal(modeIsFullBuild("audit_and_safe_build"), false);
    assert.equal(modeIsFullBuild("audit_and_safe_build_council"), false);
    assert.equal(modeIsFullBuild("audit_source"), false);
});

test("modeIsSafeBuild = build AND NOT full-build", () => {
    assert.equal(modeIsSafeBuild("audit_and_safe_build"), true);
    assert.equal(modeIsSafeBuild("audit_and_safe_build_council"), true);
    assert.equal(modeIsSafeBuild("audit_and_full_build"), false);
    assert.equal(modeIsSafeBuild("audit_and_full_build_council"), false);
    assert.equal(modeIsSafeBuild("audit_source"), false);
});

test("modeIsCouncilBuild = council AND build", () => {
    assert.equal(modeIsCouncilBuild("audit_and_safe_build_council"), true);
    assert.equal(modeIsCouncilBuild("audit_and_full_build_council"), true);
    assert.equal(modeIsCouncilBuild("audit_source_council"), false);
    assert.equal(modeIsCouncilBuild("audit_and_safe_build"), false);
});

test("modeIsAudit returns true for source-audit-class modes", () => {
    for (const m of ["audit_source", "audit_source_council",
                     "audit_local_source", "audit_local_source_council",
                     "audit_and_safe_build", "audit_and_full_build",
                     "audit_and_safe_build_council", "audit_and_full_build_council"]) {
        assert.equal(modeIsAudit(m), true, `expected true: ${m}`);
    }
    assert.equal(modeIsAudit("metadata_only"), false);
    assert.equal(modeIsAudit("verify_release"), false);
});

test("modeNeedsClone (current): only build modes need a clone; audit modes are API-direct or local", () => {
    // Non-clone modes: metadata_only, all API-direct audit modes, and local-source modes
    for (const m of ["metadata_only", "audit_source", "audit_source_council",
                     "audit_local_source", "audit_local_source_council", "verify_release"]) {
        assert.equal(modeNeedsClone(m), false, `expected false (no clone): ${m}`);
    }
    // Clone-needing modes: only the build family
    for (const m of ["audit_and_safe_build", "audit_and_full_build",
                     "audit_and_safe_build_council", "audit_and_full_build_council"]) {
        assert.equal(modeNeedsClone(m), true, `expected true (clone needed): ${m}`);
    }
});

test("modeUsesApiDirect is true for URL-driven audit modes only (excludes local-source)", () => {
    assert.equal(modeUsesApiDirect("metadata_only"), false);
    // URL-driven audit modes
    for (const m of ["audit_source", "audit_source_council", "verify_release"]) {
        assert.equal(modeUsesApiDirect(m), true, `expected true: ${m}`);
    }
    // Local-source modes are NOT api-direct — they read from disk
    for (const m of ["audit_local_source", "audit_local_source_council"]) {
        assert.equal(modeUsesApiDirect(m), false, `expected false (local, not api-direct): ${m}`);
    }
    // Build modes are NOT api-direct — they clone to disk
    for (const m of ["audit_and_safe_build", "audit_and_full_build",
                     "audit_and_safe_build_council", "audit_and_full_build_council"]) {
        assert.equal(modeUsesApiDirect(m), false, `expected false: ${m}`);
    }
});

test("modeUsesLocalSource is true ONLY for the two local-source modes", () => {
    for (const m of ["audit_local_source", "audit_local_source_council"]) {
        assert.equal(modeUsesLocalSource(m), true, `expected true: ${m}`);
    }
    for (const m of ["metadata_only", "audit_source", "audit_source_council", "verify_release",
                     "audit_and_safe_build", "audit_and_full_build",
                     "audit_and_safe_build_council", "audit_and_full_build_council"]) {
        assert.equal(modeUsesLocalSource(m), false, `expected false: ${m}`);
    }
    // Edge cases
    assert.equal(modeUsesLocalSource(""), false);
    assert.equal(modeUsesLocalSource(null), false);
    assert.equal(modeUsesLocalSource(undefined), false);
    assert.equal(modeUsesLocalSource("nonsense"), false);
});

test("LOCAL_SOURCE_MODES + LOCAL_SOURCE_MODES_SET are consistent", () => {
    assert.deepEqual([...LOCAL_SOURCE_MODES], [
        "audit_local_source",
        "audit_local_source_council",
    ]);
    for (const m of LOCAL_SOURCE_MODES) {
        assert.equal(LOCAL_SOURCE_MODES_SET.has(m), true);
    }
});

// ---------- Default-mode resolution ----------

test("defaultModeForUrlKind: release → verify_release, others → audit_source_council", () => {
    assert.equal(defaultModeForUrlKind("release"), "verify_release");
    for (const k of ["repo", "tree", "commit", "pr"]) {
        assert.equal(defaultModeForUrlKind(k), "audit_source_council", `kind ${k}`);
    }
    assert.equal(defaultModeForUrlKind("anything-else"), "audit_source_council");
});

test("resolveEffectiveMode: explicit mode always wins", () => {
    const r = resolveEffectiveMode({ explicitMode: "verify_release", urlKind: "repo" });
    assert.equal(r.mode, "verify_release");
    assert.equal(r.source, "explicit");
});

test("resolveEffectiveMode: no explicit, no env → URL-kind default (council in opt-out mode)", () => {
    const r = resolveEffectiveMode({ urlKind: "repo", env: {} });
    assert.equal(r.mode, "audit_source_council");
    assert.equal(r.source, "default");
});

test("resolveEffectiveMode: ZEROTRUST_DEFAULT_COUNCIL=1 is a no-op when council is already default", () => {
    const r = resolveEffectiveMode({ urlKind: "repo", env: { ZEROTRUST_DEFAULT_COUNCIL: "1" } });
    assert.equal(r.mode, "audit_source_council");
    assert.equal(r.source, "default");
});

test("resolveEffectiveMode: release URLs always default to verify_release regardless of env", () => {
    const r = resolveEffectiveMode({ urlKind: "release", env: { ZEROTRUST_DEFAULT_COUNCIL: "1" } });
    assert.equal(r.mode, "verify_release");
    assert.equal(r.source, "default");
});

test("resolveEffectiveMode: council is the default for all repo-class URLs (tree/commit/pr)", () => {
    for (const k of ["tree", "commit", "pr"]) {
        const r = resolveEffectiveMode({ urlKind: k, env: {} });
        assert.equal(r.mode, "audit_source_council", `kind ${k}`);
        assert.equal(r.source, "default", `kind ${k}`);
    }
});

test("resolveEffectiveMode: environment cannot silently downgrade the council default", () => {
    const r = resolveEffectiveMode({ urlKind: "repo", env: { ZEROTRUST_DETERMINISTIC_ONLY: "1" } });
    assert.equal(r.mode, "audit_source_council");
    assert.equal(r.source, "default");
});

test("resolveEffectiveMode: ZEROTRUST_DETERMINISTIC_ONLY env value other than '1' does NOT trigger downgrade", () => {
    for (const v of ["0", "true", "yes", "", undefined]) {
        const r = resolveEffectiveMode({ urlKind: "repo", env: { ZEROTRUST_DETERMINISTIC_ONLY: v } });
        assert.equal(r.mode, "audit_source_council", `env value ${JSON.stringify(v)}`);
    }
});
