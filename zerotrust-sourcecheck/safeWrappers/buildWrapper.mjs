// safeWrappers/buildWrapper.mjs — zerotrust_safe_build tool implementation.
//
// Like installWrapper but for the build phase. Critically: when invoked
// in a council-build mode, this wrapper checks the recorded council
// outcome (state.mjs) and refuses to build if the council didn't pass.
// THIS is where Feature 3's "council aborts the build" promise is
// actually enforced — substitutionally, not via the (broken) hook.
//
// Trust model (v3.1 hardening):
// - The "mode" used for the council-gate decision comes from the trusted
//   active-audit state (enforcement.activeAudits), NOT from args.mode.
//   args.mode is logged as advisory only — if the trusted mode differs,
//   the trusted mode wins. This closes the cluster-A gate-bypass attack
//   where an agent omits args.mode to skip the council check.
// - The build_root used for containment also comes from the trusted
//   active-audit state, not from args.build_root.
// - Same extra_args denylist as installWrapper.

import { execFileSync } from "node:child_process";
import nodePath from "node:path";

import { getRecordedOutcome, evaluateCouncilGate } from "./state.mjs";
import { modeIsBuild, modeUsesCouncil } from "../modes.mjs";
import { getTrustedAuditContext } from "../enforcement.mjs";
import { resolveTrustedProgram } from "./programResolver.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";

const BUILD_ECOSYSTEMS = {
    npm: {
        argv: (extra) => ["npm", "run", "build", "--if-present", ...extra],
        timeout: 600_000,
    },
    yarn: {
        argv: (extra) => ["yarn", "build", ...extra],
        timeout: 600_000,
    },
    pnpm: {
        argv: (extra) => ["pnpm", "build", ...extra],
        timeout: 600_000,
    },
    cargo: {
        argv: (extra) => ["cargo", "build", "--locked", "--offline", ...extra],
        timeout: 1_200_000,
    },
    dotnet: {
        argv: (extra) => ["dotnet", "build", "--no-restore", ...extra],
        timeout: 600_000,
    },
    "dotnet-publish": {
        argv: (extra) => ["dotnet", "publish", "--no-restore", ...extra],
        timeout: 600_000,
    },
};

const ARG_RE = /^[A-Za-z0-9._=:@/\\-]+$/;

// Same denylist principle as installWrapper. For build, the negation surface
// is smaller, but path-redirect / project-redirect args are the main risk.
// Round-2 hardening: split-form coverage + absolute-path / `..` rejection.
const ABS_PATH_RE = /(?:[A-Za-z]:[\\/]|^\\\\|^[\\/])/;
const TRAVERSAL_RE = /\.\./;
const URL_SCHEME_RE = /^[A-Za-z][A-Za-z0-9+.\-]*:\/\//;

const ARG_DENYLIST = [
    /^--cwd(?:=|$)/i,
    /^--directory(?:=|$)/i,
    /^--manifest-path(?:=|$)/i,
    /^--project(?:=|$)/i,
    /^--prefix(?:=|$)/i,
    /^--target(?:=|$)/i,
    /^--target-dir(?:=|$)/i,
    /^--output(?:=|$)/i,
    /^--output-dir(?:=|$)/i,
    /^--out(?:=|$)/i,
    /^--no-locked$/i,
    /^--no-offline$/i,
    /^--no-no-restore$/i,
    /^--source(?:=|$)/i,
    /^--package-source(?:=|$)/i,
    /^--config(?:=|$)/i,
    /^[A-Za-z]:[\\/]/,
    /^\\\\/,
    /^\\/,
    /^\//,
    /\.\./,
    URL_SCHEME_RE,
];

function validateExtraArgs(args) {
    if (!args) return [];
    if (!Array.isArray(args)) throw new Error("extra_args must be an array of strings (or omitted)");
    if (args.length > 32) throw new Error("extra_args has more than 32 entries");
    for (const a of args) {
        if (typeof a !== "string") throw new Error(`extra_args contains non-string entry: ${typeof a}`);
        if (a.length > 256) throw new Error("extra_args contains an entry over 256 chars");
        if (!ARG_RE.test(a)) throw new Error(`extra_args contains entry with disallowed characters: ${JSON.stringify(a)}`);
        for (const re of ARG_DENYLIST) {
            if (re.test(a)) {
                throw new Error(`extra_args contains a flag that would negate hardcoded safety flags: ${JSON.stringify(a)}`);
            }
        }
        const eqIdx = a.indexOf("=");
        if (eqIdx > 0 && eqIdx < a.length - 1) {
            const value = a.slice(eqIdx + 1);
            if (ABS_PATH_RE.test(value)) {
                throw new Error(`extra_args flag value contains absolute path / UNC: ${JSON.stringify(a)}`);
            }
            if (TRAVERSAL_RE.test(value)) {
                throw new Error(`extra_args flag value contains path traversal: ${JSON.stringify(a)}`);
            }
            if (URL_SCHEME_RE.test(value)) {
                throw new Error(`extra_args flag value contains a remote URL: ${JSON.stringify(a)}`);
            }
        }
    }
    return args;
}

function pathIsUnder(parent, child) {
    const p = nodePath.resolve(parent).toLowerCase();
    const c = nodePath.resolve(child).toLowerCase();
    if (p === c) return true;
    const rel = nodePath.relative(p, c);
    return !!rel && !rel.startsWith("..") && !nodePath.isAbsolute(rel);
}

/**
 * Tool signature:
 *   zerotrust_safe_build({
 *     ecosystem,
 *     clone_path,
 *     extra_args?: string[],
 *     mode?: string,                    // ADVISORY ONLY in v3.1+ — trusted mode comes from active audit
 *     council_build_override?: boolean, // bypass severity threshold (still requires complete OR proceed_on_council_failure)
 *     proceed_on_council_failure?: boolean, // bypass incomplete-council block (still requires verdict pass OR council_build_override)
 *     build_root?: string               // ADVISORY ONLY in v3.1+ — trusted build_root comes from active audit
 *   })
 */
export async function safeBuildHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;

    const ecosystem = args.ecosystem;
    if (typeof ecosystem !== "string" || !BUILD_ECOSYSTEMS[ecosystem]) {
        return failure(`ecosystem must be one of: ${Object.keys(BUILD_ECOSYSTEMS).join(", ")}`);
    }
    if (typeof args.clone_path !== "string" || !nodePath.isAbsolute(args.clone_path)) {
        return failure("clone_path is required and must be absolute");
    }

    // Trusted context — the active audit's mode + build_root win over args.
    const ctx = getTrustedAuditContext({ sessionId, args, defaultBuildRoot: DEFAULT_BUILD_ROOT });
    if (!ctx.ok) return failure(ctx.error);
    const buildRoot = ctx.buildRoot;
    const trustedMode = ctx.mode; // null when no active audit
    const advisoryAgentMode = typeof args.mode === "string" ? args.mode : null;

    // Local-source mode refusal: same reason as the install/clone wrappers.
    // A local-source audit has no clone and no build step authorised; the
    // operator owns the on-disk code and can run their own build.
    if (ctx.hasActiveAudit && ctx.localPath) {
        return failure(`safe_build refused: active audit is local-source mode (target: ${ctx.localPath}). Build operations apply to build-mode audits only.`);
    }

    // Round-3 hardening: when sessionId was supplied (production agents
    // always have one) but no active audit exists (TTL expired or
    // zerotrust_sourcecheck not invoked), REFUSE EARLY before any other
    // check. Without this guard, the trusted-mode check silently degrades
    // to "trust agent-supplied advisory mode", reopening the no-ack escape
    // path. The ack flag (i_understand_build_executes_code, plus `unsafe`
    // for full-build) is enforced only at handler-activation time; without
    // an active audit there's no proof the operator approved.
    if (sessionId && !ctx.hasActiveAudit) {
        return failure(`safe_build refused: no active audit for this session (TTL expired or zerotrust_sourcecheck not invoked). Re-invoke zerotrust_sourcecheck with the appropriate build mode + ack flags before running a build.`);
    }

    if (!pathIsUnder(buildRoot, args.clone_path)) {
        return failure(`clone_path ${args.clone_path} is not under build_root ${buildRoot}`);
    }

    // Round-4 hardening (gpt-5.5 F2) + round-6 hardening: if the active
    // audit has a recorded resolved clone path, the build must target THAT
    // path exactly. If the audit IS active but no resolved clone path has
    // been recorded yet, REFUSE — agent must call safe_clone first.
    if (ctx.hasActiveAudit) {
        if (!ctx.resolvedClonePath) {
            return failure(`safe_build refused: no resolved clone path recorded for the active audit. Call zerotrust_safe_clone before zerotrust_safe_build.`);
        }
        const argResolved = nodePath.resolve(args.clone_path).toLowerCase();
        const auditResolved = ctx.resolvedClonePath.toLowerCase();
        if (argResolved !== auditResolved) {
            return failure(`safe_build refused: clone_path ${args.clone_path} does not match the active audit's resolved clone path ${ctx.resolvedClonePath}`);
        }
    }

    // Council-gate decision uses the TRUSTED mode (from activeAudits), NOT
    // args.mode. This closes the cluster-A bypass where an agent passes
    // mode: "audit_and_safe_build" (a non-council build mode) when the
    // session's actual audit was activated as audit_and_safe_build_council.
    const effectiveMode = trustedMode || advisoryAgentMode;
    const isCouncilMode = effectiveMode && modeUsesCouncil(effectiveMode);
    const isBuildMode = effectiveMode && modeIsBuild(effectiveMode);
    const isCouncilBuildMode = isCouncilMode && isBuildMode;
    // Round-2 hardening: refuse to run a build when the trusted active-audit
    // mode is not a build mode.
    if (trustedMode && !modeIsBuild(trustedMode)) {
        return failure(`safe_build refused: active audit mode '${trustedMode}' is not a build mode. Re-invoke zerotrust_sourcecheck with audit_and_safe_build* or audit_and_full_build* (and the required ack flags) to run a build.`);
    }
    if (!trustedMode && !advisoryAgentMode) {
        return failure(`safe_build refused: no active audit and no mode hint. Invoke zerotrust_sourcecheck with a build mode first.`);
    }
    if (!trustedMode && advisoryAgentMode && !modeIsBuild(advisoryAgentMode)) {
        return failure(`safe_build refused: agent-supplied mode '${advisoryAgentMode}' is not a build mode and no active audit overrides it.`);
    }

    let gateOpenReason;
    if (isCouncilBuildMode) {
        const outcome = getRecordedOutcome(sessionId);
        const gate = evaluateCouncilGate(outcome, {
            override: !!args.council_build_override,
            overrideOnFailure: !!args.proceed_on_council_failure,
        });
        if (!gate.passes) {
            return failure(`council-build gate CLOSED: ${gate.reason}`);
        }
        gateOpenReason = gate.reason;
    }

    // If the agent's advisory mode disagrees with the trusted mode, log it
    // in the success metadata so operators can spot drift.
    let advisoryNote;
    if (trustedMode && advisoryAgentMode && trustedMode !== advisoryAgentMode) {
        advisoryNote = `agent passed mode=${JSON.stringify(advisoryAgentMode)} but trusted audit mode is ${JSON.stringify(trustedMode)}; trusted mode wins`;
    }

    let extraArgs;
    try {
        extraArgs = validateExtraArgs(args.extra_args);
    } catch (err) {
        return failure(err.message);
    }
    const spec = BUILD_ECOSYSTEMS[ecosystem];
    const argv = spec.argv(extraArgs);
    const bareProgram = argv[0];
    const programArgs = argv.slice(1);

    // Round-11 hardening (gpt-5.5 R11 F1): same trusted-program-resolution
    // hardening as installWrapper. See programResolver.mjs for rationale.
    const program = resolveTrustedProgram(bareProgram, {
        forbiddenRoots: [buildRoot, args.clone_path],
    });
    if (!program) {
        return failure(`safe_build refused: could not resolve a trusted absolute path for ${JSON.stringify(bareProgram)} on PATH (or every candidate was inside build_root). Ensure ${bareProgram} is installed system-wide and not shadowed by a repo-planted binary.`);
    }

    let stdout = "";
    let stderr = "";
    let exitCode = 0;
    try {
        stdout = execFileSync(program, programArgs, {
            encoding: "utf-8",
            cwd: args.clone_path,
            timeout: spec.timeout,
            windowsHide: true,
            stdio: ["ignore", "pipe", "pipe"],
        });
    } catch (err) {
        stdout = err.stdout ? String(err.stdout) : "";
        stderr = err.stderr ? String(err.stderr) : err.message;
        exitCode = err.status || 1;
        return failure(`${ecosystem} build failed (exit ${exitCode}): ${stderr.slice(-2000)}`);
    }

    return success({
        ecosystem,
        clonePath: args.clone_path,
        trustedMode,
        argv,
        exitCode,
        stdout: stdout.slice(-4000),
        stderr: stderr.slice(-2000),
        ...(gateOpenReason ? { councilGate: gateOpenReason } : {}),
        ...(advisoryNote ? { advisoryNote } : {}),
    });
}

function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, ...data }, null, 2),
        resultType: "success",
    };
}

function failure(message) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, error: message }, null, 2),
        resultType: "failure",
    };
}

export const __internals = {
    BUILD_ECOSYSTEMS,
    ARG_RE,
    ARG_DENYLIST,
    validateExtraArgs,
    pathIsUnder,
};
