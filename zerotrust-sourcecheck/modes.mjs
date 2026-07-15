// modes.mjs — single source of truth for mode taxonomy.
//
// Centralized so that Wave 1 of v3 (Feature 2 default-promotion + Feature 3
// build-mode council variants) edits one shared taxonomy instead of fighting
// over duplicated Set literals in handler.mjs / enforcement.mjs / packet.mjs.
//
// Contract:
// - VALID_MODES is the authoritative enum used by handler.mjs validation,
//   extension.mjs schema, and (by extension) every downstream consumer.
// - COUNCIL_MODES is a subset of VALID_MODES that triggers the 32-role
//   council in packet.mjs Section 5b/5c.
// - BUILD_MODES is a subset of VALID_MODES that permits wrapper-mediated
//   package-manager installs / build commands.
// - FULL_BUILD_MODES is a subset of BUILD_MODES that requires the additional
//   `unsafe` acknowledgement. Safe/full modes currently use the same
//   install/build wrappers. Install lifecycle scripts remain suppressed in
//   both, while repo-controlled npm build scripts, build.rs, and MSBuild
//   targets may execute in both. Full mode changes admission/warning posture
//   only and reserves a future distinction; it is not a less-restricted
//   installer today.
// - Council-build modes are exactly COUNCIL_MODES ∩ BUILD_MODES; the
//   safe-build wrapper refuses them until a passing council outcome is
//   recorded.
//
// All helpers in this file are pure: no I/O, no side effects, no imports
// from other modules in this extension. Safe to import from any module.

// Single source of truth for staged default promotion.
//
// "opt-in" (deterministic-only is default; council requires ZEROTRUST_DEFAULT_COUNCIL=1)
// "opt-out" (council is default for repo-class URLs; ZEROTRUST_DETERMINISTIC_ONLY=1 downgrades back)
//
// The configured strategy is currently "opt-out": council mode is the default
// for repo-class URLs, with ZEROTRUST_DETERMINISTIC_ONLY=1 as the escape hatch.
// This is a mode-selection fact, not a claim that wrappers intercept raw
// built-in tool calls; they do not.
export const DEFAULT_STRATEGY = "opt-out";

export const BUILD_MODE_TAXONOMY_NOTE =
    "Safe/full modes currently use the same install/build wrappers. Install lifecycle scripts remain suppressed. Build commands may execute repo-controlled npm build scripts, build.rs, and MSBuild targets in both modes. Full mode currently changes admission/warning posture only, still requires unsafe, and reserves a future distinction.";

export function defaultStrategy() {
    return DEFAULT_STRATEGY;
}

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

// LOCAL_SOURCE_MODES: read an already-on-disk directory rather than
// fetching from the GitHub API. The two modes here are the only ones
// that take a `local_path` arg (instead of `url`); the rest of the
// taxonomy stays GitHub-URL-driven.
export const LOCAL_SOURCE_MODES = Object.freeze([
    "audit_local_source",
    "audit_local_source_council",
]);
export const LOCAL_SOURCE_MODES_SET = new Set(LOCAL_SOURCE_MODES);

// ---------- Pure predicates ----------

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
    // "Audit" = anything that reads source. metadata_only is excluded
    // because it never clones; verify_release is excluded because its
    // focus is release-artifact provenance, not source inspection.
    return mode === "audit_source"
        || mode === "audit_source_council"
        || modeUsesLocalSource(mode)
        || modeIsBuild(mode);
}

export function modeNeedsClone(mode) {
    // Only build modes need a local clone. Pure URL audit modes
    // (`audit_source`, `audit_source_council`, `verify_release`,
    // `metadata_only`) return GitHub-API content through tool results and do
    // not intentionally create source files. Runtime/session logging is out
    // of scope for this taxonomy helper.
    return modeIsBuild(mode);
}

/**
 * Does this mode use the API-direct flow (fetch via the GitHub API without
 * intentionally creating a source tree)? True for all non-build,
 * non-metadata, non-local-source modes that need to read source. Host
 * CLI/session logging or oversized-output spill is outside this helper.
 *
 * - metadata_only is excluded because it doesn't read source at all
 *   (just GitHub metadata).
 * - build modes are excluded because they write source to disk.
 * - local-source modes are excluded because they read source from
 *   an already-on-disk directory, not via the API.
 */
export function modeUsesApiDirect(mode) {
    return mode !== "metadata_only"
        && !modeIsBuild(mode)
        && !modeUsesLocalSource(mode);
}

// ---------- Default-mode resolution ----------

/**
 * The default mode for a given URL kind, when the user did not pass an
 * explicit `mode` argument.
 *
 * This remains the deterministic baseline. DEFAULT_STRATEGY controls whether
 * omitted-mode repo-class URLs use this baseline or the council default.
 */
export function defaultModeForUrlKind(kind) {
    switch (kind) {
        case "release":
            return "verify_release";
        case "pr":
        case "commit":
        case "tree":
        case "repo":
        default:
            return "audit_source";
    }
}

const REPO_CLASS_URL_KINDS = new Set(["repo", "tree", "commit", "pr"]);

function isRepoClassUrlKind(kind) {
    return REPO_CLASS_URL_KINDS.has(kind);
}

/**
 * Resolve the effective mode for an invocation, applying explicit-arg →
 * env-var → URL-kind-default precedence.
 *
 * @param {object} args
 * @param {string|null|undefined} args.explicitMode    user-supplied `mode` argument
 * @param {string} args.urlKind                          parsed URL kind
 * @param {object} [args.env]                            optional env override (defaults to process.env)
 * @param {"opt-in"|"opt-out"} [args.strategy]            default-promotion strategy
 * @returns {{ mode: string, source: "explicit"|"env"|"default" }}
 */
export function _resolveEffectiveModeWith({ explicitMode, urlKind, env, strategy } = {}) {
    if (explicitMode) {
        return { mode: explicitMode, source: "explicit" };
    }
    const e = env || (typeof process !== "undefined" ? process.env : {}) || {};
    const effectiveStrategy = strategy || defaultStrategy();
    const repoClassUrl = isRepoClassUrlKind(urlKind);
    const deterministicOnly = e.ZEROTRUST_DETERMINISTIC_ONLY === "1";
    const defaultCouncil = e.ZEROTRUST_DEFAULT_COUNCIL === "1";

    // Safety precedence: deterministic opt-out wins over council opt-in.
    if (deterministicOnly && repoClassUrl) {
        return { mode: "audit_source", source: "env" };
    }

    if (effectiveStrategy === "opt-in") {
        if (defaultCouncil && repoClassUrl) {
            return { mode: "audit_source_council", source: "env" };
        }
        return { mode: defaultModeForUrlKind(urlKind), source: "default" };
    }

    if (effectiveStrategy === "opt-out" && repoClassUrl) {
        return {
            mode: "audit_source_council",
            source: "default",
        };
    }

    return { mode: defaultModeForUrlKind(urlKind), source: "default" };
}

export function resolveEffectiveMode({ explicitMode, urlKind, env } = {}) {
    return _resolveEffectiveModeWith({
        explicitMode,
        urlKind,
        env,
        strategy: defaultStrategy(),
    });
}

export function flipReadinessGate({ corpusGreen = false, hookProbeOk = false, env } = {}) {
    const blockedReasons = [];
    void env;
    if (corpusGreen !== true) {
        blockedReasons.push("corpus-not-green");
    }
    if (hookProbeOk !== true) {
        blockedReasons.push("hook-probe-failed");
    }
    return {
        readyToFlip: blockedReasons.length === 0,
        blockedReasons,
    };
}
