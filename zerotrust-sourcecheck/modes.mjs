// modes.mjs — single source of truth for mode taxonomy.
//
// Council audit modes run the complete assurance lifecycle. Deterministic-only
// audit modes remain available for bounded static triage, but they must report
// partial/incomplete assurance because they omit required model semantic and
// evasive red-team coverage.

export const BUILD_MODE_TAXONOMY_NOTE =
    "Safe/full mode names are retained for compatibility and currently use identical install/build wrappers. Install lifecycle scripts remain suppressed. Hazardous post-audit host execution may run repo-controlled npm build scripts, build.rs, and MSBuild targets in either mode. Full mode currently changes admission/warning posture only, still requires unsafe, and reserves a future distinction.";

export const VALID_MODES = Object.freeze([
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

export const VALID_MODES_SET = new Set(VALID_MODES);

export const COUNCIL_MODES = Object.freeze([
    "audit_source_council",
    "audit_local_source_council",
    "audit_and_safe_build_council",
    "audit_and_full_build_council",
]);
export const COUNCIL_MODES_SET = new Set(COUNCIL_MODES);

export const BUILD_MODES = Object.freeze([
    "audit_and_safe_build",
    "audit_and_full_build",
    "audit_and_safe_build_council",
    "audit_and_full_build_council",
]);
export const BUILD_MODES_SET = new Set(BUILD_MODES);

export const FULL_BUILD_MODES = Object.freeze([
    "audit_and_full_build",
    "audit_and_full_build_council",
]);
export const FULL_BUILD_MODES_SET = new Set(FULL_BUILD_MODES);

export const LOCAL_SOURCE_MODES = Object.freeze([
    "audit_local_source",
    "audit_local_source_council",
]);
export const LOCAL_SOURCE_MODES_SET = new Set(LOCAL_SOURCE_MODES);

export function isValidMode(mode) {
    return VALID_MODES_SET.has(mode);
}

export function modeUsesCouncil(mode) {
    return COUNCIL_MODES_SET.has(mode);
}

export function modeIsBuild(mode) {
    return BUILD_MODES_SET.has(mode);
}

export function modeIsFullBuild(mode) {
    return FULL_BUILD_MODES_SET.has(mode);
}

export function modeIsSafeBuild(mode) {
    return modeIsBuild(mode) && !modeIsFullBuild(mode);
}

export function modeIsCouncilBuild(mode) {
    return modeUsesCouncil(mode) && modeIsBuild(mode);
}

export function modeUsesLocalSource(mode) {
    return LOCAL_SOURCE_MODES_SET.has(mode);
}

export function modeIsAudit(mode) {
    return mode === "audit_source"
        || mode === "audit_source_council"
        || modeUsesLocalSource(mode)
        || modeIsBuild(mode);
}

export function modeNeedsClone(mode) {
    return modeIsBuild(mode);
}

export function modeUsesApiDirect(mode) {
    return mode !== "metadata_only"
        && !modeIsBuild(mode)
        && !modeUsesLocalSource(mode);
}

export function defaultModeForUrlKind(kind) {
    switch (kind) {
        case "release":
            return "verify_release";
        case "pr":
        case "commit":
        case "tree":
        case "repo":
        default:
            return "audit_source_council";
    }
}

export function resolveEffectiveMode({ explicitMode, urlKind } = {}) {
    if (explicitMode) {
        return { mode: explicitMode, source: "explicit" };
    }
    return { mode: defaultModeForUrlKind(urlKind), source: "default" };
}
