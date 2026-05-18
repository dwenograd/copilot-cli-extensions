// handler.mjs
//
// runHandler is the tool entry point. It:
//   1. Validates and normalizes args (including ack flags).
//   2. Parses + validates the GitHub URL via urlParser.
//   3. Resolves the audit mode (explicit, env, or default from URL kind).
//   4. Scrubs and applies injection-policy to user-provided strings (focus, ref).
//   5. Computes the canonical clone / report / quarantine paths under build_root.
//   6. Activates compatibility audit state for the vestigial hook path.
//   7. Builds and returns the instruction packet.
//
// The handler does NOT clone, fetch, or write anything. All side effects
// happen inside the calling agent's tool calls, with dangerous operations
// routed through safe-wrapper tools.

import nodePath from "node:path";
import { existsSync, mkdirSync } from "node:fs";

import {
    scrub,
    applyInjectionPolicy,
    generateNonce,
    renderInjectionPreamble,
    injectionInstructionForSubAgents,
} from "../_shared/index.mjs";

import { parseGithubUrl, buildClonePath, buildReportPath, buildQuarantinePath, validateRef } from "./urlParser.mjs";
import { validateLocalPath } from "./localPathValidator.mjs";
import { activateAudit } from "./enforcement.mjs";
import { clearRecordedOutcome } from "./safeWrappers/state.mjs";
import { buildInstructionPacket } from "./packet.mjs";
import { DEFAULT_BUILD_ROOT, ensureDefaultBuildRoot } from "./safeWrappers/defaults.mjs";
import {
    ROLE_IDS_IN_ORDER,
    DEFAULT_META_JUDGE_MODEL,
    DEFAULT_SUB_JUDGE_MODEL,
    ALLOWED_MODEL_IDS,
    resolveRoles,
    renderRolePrompt,
    validateExtraRoles,
} from "./council/index.mjs";
import {
    VALID_MODES_SET,
    COUNCIL_MODES_SET,
    isValidMode,
    modeUsesCouncil,
    modeIsBuild,
    modeIsFullBuild,
    modeUsesLocalSource,
    defaultModeForUrlKind,
    resolveEffectiveMode,
} from "./modes.mjs";

const TOOL = "zerotrust_sourcecheck";

const DEFAULT_MAX_PREMIUM_CALLS = 200;

// Local aliases preserved for source compatibility with the rest of this file.
// Behavior is sourced from modes.mjs — these are not separate definitions.
const VALID_MODES = VALID_MODES_SET;
const COUNCIL_MODES = COUNCIL_MODES_SET;

function fail(reason) {
    return {
        textResultForLlm: `❌ ${TOOL}: ${reason}`,
        resultType: "failure",
    };
}

function ensureDir(p) {
    if (!existsSync(p)) {
        mkdirSync(p, { recursive: true });
    }
}

/**
 * Try to ensure a path is OK to operate on:
 *   - Must be absolute
 *   - Must not contain `..` segments after resolve
 *   - Parent (build_root itself) is created if missing
 */
function preflightBuildRoot(buildRoot) {
    if (!nodePath.isAbsolute(buildRoot)) {
        return { ok: false, reason: `build_root must be an absolute path (got ${JSON.stringify(buildRoot)})` };
    }
    const resolved = nodePath.resolve(buildRoot);
    try {
        ensureDir(resolved);
    } catch (err) {
        return { ok: false, reason: `failed to create build_root ${resolved}: ${err.message}` };
    }
    return { ok: true, resolved };
}

export function runHandler(args, { sessionId, log } = {}) {
    args = args || {};

    // First-use mkdir of the default build_root (idempotent). If the
    // caller passes an explicit args.build_root, this is a no-op for
    // their actual destination — but other wrappers in the same audit
    // may still default-fall-back, so ensuring the default exists
    // up-front is cheap insurance.
    ensureDefaultBuildRoot();

    // --- 0. Mutually exclusive: url vs local_path ---
    const hasUrl = typeof args.url === "string" && args.url.length > 0;
    const hasLocal = typeof args.local_path === "string" && args.local_path.length > 0;
    if (hasUrl && hasLocal) {
        return fail("url and local_path are mutually exclusive — pick one.");
    }
    if (!hasUrl && !hasLocal) {
        return fail("must provide either `url` (GitHub URL) or `local_path` (absolute path to a directory).");
    }

    // --- 1a. Local-path branch ---
    let target;
    if (hasLocal) {
        if (args.i_understand_local_path_reads_my_disk !== true) {
            return fail(
                "local_path requires `i_understand_local_path_reads_my_disk: true`. " +
                "This mode lets the audit's role agents read files anywhere under the " +
                "given path with the operator's filesystem privileges.",
            );
        }
        const localResult = validateLocalPath(args.local_path);
        if (!localResult.ok) return fail(`local_path rejected: ${localResult.error}`);
        target = {
            kind: "local",
            localPath: localResult.resolved,
            slug: localResult.slug,
        };
        // Local-path mode only supports audit_local_source[_council];
        // reject any other mode the user passes.
        if (args.mode !== undefined && args.mode !== null && !modeUsesLocalSource(args.mode)) {
            return fail(
                `mode '${args.mode}' is not valid for local_path; ` +
                `use 'audit_local_source' or 'audit_local_source_council'.`,
            );
        }
    } else {
        // --- 1b. URL branch (existing behavior) ---
        const urlResult = parseGithubUrl(args.url);
        if (!urlResult.ok) {
            return fail(`URL rejected: ${urlResult.error}`);
        }
        target = { kind: "url", parsed: urlResult.parsed };
    }

    // --- 2. Resolve mode (explicit > env > kind-default) ---
    let mode;
    if (target.kind === "local") {
        // Default to council variant (matches the opt-out strategy for URL repo-class).
        mode = args.mode || "audit_local_source_council";
    } else {
        const modeResolution = resolveEffectiveMode({
            explicitMode: args.mode,
            urlKind: target.parsed.kind,
        });
        mode = modeResolution.mode;
    }
    if (!VALID_MODES.has(mode)) {
        return fail(
            `mode '${mode}' is not valid. Choose one of: ${[...VALID_MODES].join(", ")}.`,
        );
    }
    // Cross-check: local-source modes require local_path; URL-driven modes require url.
    if (modeUsesLocalSource(mode) && target.kind !== "local") {
        return fail(`mode '${mode}' requires \`local_path\`, not \`url\`.`);
    }
    if (!modeUsesLocalSource(mode) && target.kind === "local") {
        return fail(`mode '${mode}' requires \`url\`, not \`local_path\`.`);
    }

    // --- 3. Mode-specific ack-flag enforcement ---
    const buildExecAck = !!args.i_understand_build_executes_code;
    const unsafeAck = !!args.unsafe;
    const privateRepoAck = !!args.i_understand_private_repo_risk;

    if (modeIsBuild(mode) && !buildExecAck) {
        return fail(
            `mode '${mode}' requires \`i_understand_build_executes_code: true\`. Even with safe-mode flags, build steps execute repo-controlled code.`,
        );
    }
    if (modeIsFullBuild(mode) && !unsafeAck) {
        return fail(
            `mode '${mode}' requires \`unsafe: true\` in addition to \`i_understand_build_executes_code: true\`. This mode runs lifecycle scripts on your host with no sandbox.`,
        );
    }

    // --- 4. Validate ref override (if provided) ---
    // Refs only apply to URL-driven audits — reject ref with local_path.
    if (args.ref !== undefined && args.ref !== null) {
        if (target.kind === "local") {
            return fail("ref is not valid in local_path mode (refs apply to GitHub URLs only)");
        }
        if (typeof args.ref !== "string") {
            return fail("ref must be a string when provided");
        }
        // Round-2 hardening: validate args.ref directly via validateRef instead
        // of round-tripping through parseGithubUrl on a synthetic URL. The
        // URL re-parse path silently dropped any `#fragment` or `?query` from
        // the ref before validating, so a ref containing those would smuggle
        // additional bytes into the packet without triggering REF_RE.
        const refError = validateRef(args.ref);
        if (refError) {
            return fail(`ref override rejected: ${refError}`);
        }
    }
    const refOverride = args.ref ? String(args.ref) : null;

    // --- 5. Build root preflight ---
    // Round-4 hardening (gpt-5.5 F3): args.build_root must be a non-empty
    // string before any path operations. nodePath.isAbsolute throws on
    // non-string input which would otherwise surface as an uncaught
    // ERR_INVALID_ARG_TYPE.
    if (args.build_root !== undefined && args.build_root !== null) {
        if (typeof args.build_root !== "string" || args.build_root.length === 0) {
            return fail("build_root must be a non-empty string when provided");
        }
    }
    const buildRoot = args.build_root || DEFAULT_BUILD_ROOT;
    const rootCheck = preflightBuildRoot(buildRoot);
    if (!rootCheck.ok) return fail(rootCheck.reason);
    const resolvedBuildRoot = rootCheck.resolved;

    // --- 6. Compute canonical paths (placeholder SHA until agent resolves it) ---
    // For URL-driven audits, we use a deterministic placeholder ("0000000")
    // so the path string is stable in the packet for hook-side enforcement
    // and report references. The packet instructs the agent to recompute
    // paths after Section 3 (pin-the-ref) using the real SHA.
    //
    // For local-source audits, there's no SHA and no clone. The report path
    // is computed from the localPath slug + a UTC timestamp.
    let expectedClonePath, expectedReportPath, expectedQuarantinePath;
    if (target.kind === "local") {
        const ts = new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
        expectedClonePath = null;
        expectedQuarantinePath = null;
        try {
            expectedReportPath = nodePath.resolve(resolvedBuildRoot, "_reports", `local-${target.slug}-${ts}`);
        } catch (err) {
            return fail(`local report path construction failed: ${err.message}`);
        }
    } else {
        const placeholderSha = "0000000";
        try {
            expectedClonePath = buildClonePath(resolvedBuildRoot, target.parsed.owner, target.parsed.repo, placeholderSha);
            expectedReportPath = buildReportPath(resolvedBuildRoot, target.parsed.owner, target.parsed.repo, placeholderSha);
            expectedQuarantinePath = buildQuarantinePath(resolvedBuildRoot, target.parsed.owner, target.parsed.repo, placeholderSha);
        } catch (err) {
            return fail(`path construction failed: ${err.message}`);
        }
    }

    // --- 7. Scrub + injection-policy wrap user-provided free text ---
    const nonce = generateNonce();
    const injectionWarnings = [];
    let focusWrapped = null;
    let scrubNote = null;

    if (args.focus !== undefined && args.focus !== null) {
        if (typeof args.focus !== "string") return fail("focus must be a string when provided");
        const scrubbed = scrub(args.focus);
        if (scrubbed.redactions.length > 0) {
            const summary = scrubbed.redactions.map((r) => `${r.type}×${r.count}`).join(", ");
            scrubNote = `**Note:** \`focus\` was scrubbed (${summary}).`;
        }
        const policy = applyInjectionPolicy(scrubbed.text, "focus", nonce);
        if (!policy.ok) return fail(`focus blocked: ${policy.reason}`);
        if (policy.warnings && policy.warnings.length > 0) {
            injectionWarnings.push(...policy.warnings);
        }
        focusWrapped = policy.wrapped;
    }

    const injectionPreamble = renderInjectionPreamble();
    const subAgentInstruction = injectionInstructionForSubAgents();

    // --- 7b. Council-mode parameters (only when mode is in COUNCIL_MODES) ---
    let councilManifest = null;
    let councilJudgeModel = null;
    let councilSubJudgeModel = null;
    let maxPremiumCalls = null;

    if (modeUsesCouncil(mode)) {
        // Validate per-role model overrides
        const overrides = args.roles;
        if (overrides !== undefined && overrides !== null) {
            if (typeof overrides !== "object" || Array.isArray(overrides)) {
                return fail("roles must be an object mapping role-id to model-id");
            }
        }

        // Validate extra_roles (free-text, must be schema-checked + envelope-wrapped)
        const defaultRoleIds = new Set(ROLE_IDS_IN_ORDER);
        const extraResult = validateExtraRoles(args.extra_roles, { nonce, defaultRoleIds });
        if (!extraResult.ok) return fail(`extra_roles rejected: ${extraResult.error}`);

        // Resolve effective roster
        const resolved = resolveRoles({ roles: overrides, extraRoles: extraResult.validated });
        if (resolved.errors.length > 0) {
            return fail(`role resolution errors: ${resolved.errors.join("; ")}`);
        }

        // Validate judge override
        if (args.judge !== undefined && args.judge !== null) {
            if (typeof args.judge !== "string" || !ALLOWED_MODEL_IDS.includes(args.judge)) {
                return fail(`judge must be one of: ${ALLOWED_MODEL_IDS.join(", ")}`);
            }
            councilJudgeModel = args.judge;
        } else {
            councilJudgeModel = DEFAULT_META_JUDGE_MODEL;
        }
        councilSubJudgeModel = DEFAULT_SUB_JUDGE_MODEL;

        // Circuit breaker
        if (args.max_premium_calls !== undefined && args.max_premium_calls !== null) {
            if (!Number.isInteger(args.max_premium_calls) || args.max_premium_calls < 1) {
                return fail("max_premium_calls must be a positive integer");
            }
            maxPremiumCalls = args.max_premium_calls;
        } else {
            maxPremiumCalls = DEFAULT_MAX_PREMIUM_CALLS;
        }

        // Render each role's prompt for the manifest. The packet inlines these
        // so the calling agent has the full prompt available when launching
        // each task() call.
        councilManifest = resolved.roles.map((role) => ({
            id: role.id,
            category: role.category,
            model: role.model,
            tier: role.tier,
            mandatory: !!role.mandatory,
            renderedPrompt: renderRolePrompt(role, {
                clonePath: expectedClonePath,
                nonce,
                focusOverride: focusWrapped,
                // Tool-access flavor: local-source (view/grep/glob on
                // localPath), api-direct (safe_fetch_file), or on-disk
                // clone (grep against expectedClonePath).
                apiDirect: !modeIsBuild(mode) && !modeUsesLocalSource(mode),
                localSource: modeUsesLocalSource(mode),
                localPath: target.kind === "local" ? target.localPath : null,
                owner: target.kind === "url" ? target.parsed.owner : null,
                repo: target.kind === "url" ? target.parsed.repo : null,
            }),
        }));
    } else {
        // Reject council-only params when not in council mode (clearer than silently ignoring)
        for (const k of ["roles", "extra_roles", "judge", "max_premium_calls"]) {
            if (args[k] !== undefined && args[k] !== null) {
                return fail(`parameter '${k}' is only valid in council modes`);
            }
        }
    }

    // --- 8. Activate the enforcement audit-in-progress state ---
    if (sessionId) {
        try {
            // Clear any stale council outcome from a prior audit in the same
            // session BEFORE activating the new audit. Without this, a passing
            // outcome from audit-A could satisfy a council-build gate for an
            // unrelated audit-B in the same session (gpt-5.5 reviewer Finding #4
            // in the v3.1 hardening pass).
            try {
                clearRecordedOutcome(sessionId);
            } catch {
                // best-effort; clearRecordedOutcome is idempotent
            }
            activateAudit({
                sessionId,
                buildPath: resolvedBuildRoot,
                mode,
                expectedClonePath,
                owner: target.kind === "url" ? target.parsed.owner : undefined,
                repo: target.kind === "url" ? target.parsed.repo : undefined,
                ref: target.kind === "url" ? (refOverride || target.parsed.ref) : undefined,
                refType: target.kind === "url" ? target.parsed.refType : undefined,
                localPath: target.kind === "local" ? target.localPath : undefined,
                expectedReportPath: target.kind === "local" ? expectedReportPath : undefined,
            });
            if (typeof log === "function") {
                const targetLabel = target.kind === "url"
                    ? `${target.parsed.owner}/${target.parsed.repo}`
                    : `local:${target.localPath}`;
                log(`zerotrust-sourcecheck: audit activated for ${targetLabel} (mode=${mode}); use the safe-wrapper tools for clone/install/build operations.`);
            }
        } catch (err) {
            return fail(`failed to activate enforcement state: ${err.message}`);
        }
    }

    // --- 9. Build the packet ---
    const packetText = buildInstructionPacket({
        mode,
        target,
        // Back-compat for URL-driven sections: pass parsed when available.
        parsed: target.kind === "url" ? target.parsed : null,
        refOverride,
        focusWrapped,
        injectionPreamble,
        injectionWarnings,
        subAgentInstruction,
        nonce,
        scrubNote,
        privateRepoAck,
        buildExecAck,
        unsafeAck,
        buildRoot: resolvedBuildRoot,
        expectedClonePath,
        expectedReportPath,
        expectedQuarantinePath,
        placeholderSha: true,
        // Council-mode additions (null when mode is not in COUNCIL_MODES)
        councilManifest,
        councilJudgeModel,
        councilSubJudgeModel,
        maxPremiumCalls,
    });

    return {
        textResultForLlm: packetText,
        resultType: "success",
    };
}

export const __internals = {
    DEFAULT_BUILD_ROOT,
    DEFAULT_MAX_PREMIUM_CALLS,
    VALID_MODES,
    COUNCIL_MODES,
    defaultModeForUrlKind,
    preflightBuildRoot,
};
