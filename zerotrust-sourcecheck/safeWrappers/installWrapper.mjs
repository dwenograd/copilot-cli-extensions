// safeWrappers/installWrapper.mjs — zerotrust_safe_install tool implementation.
//
// Substitutional safety: agent calls this tool instead of running raw
// `npm install` / `pip install` / etc. The wrapper hardcodes the
// safe-mode flags (`--ignore-scripts`, `--only-binary=:all:`, etc.) so
// the agent CAN'T disable them — and the extra_args denylist prevents
// the agent from passing flags that would semantically negate the
// hardcoded safety flags via last-wins precedence.

import { execFileSync } from "node:child_process";
import nodePath from "node:path";

import { getTrustedAuditContext } from "../enforcement.mjs";
import { modeIsBuild } from "../modes.mjs";
import { resolveTrustedProgram } from "./programResolver.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";

const ECOSYSTEMS = {
    npm: {
        argv: (extra) => ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", ...extra],
        timeout: 300_000,
    },
    "npm-install": {
        argv: (extra) => ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", ...extra],
        timeout: 300_000,
    },
    yarn: {
        argv: (extra) => ["yarn", "install", "--ignore-scripts", "--frozen-lockfile", ...extra],
        timeout: 300_000,
    },
    pnpm: {
        argv: (extra) => ["pnpm", "install", "--ignore-scripts", "--frozen-lockfile", ...extra],
        timeout: 300_000,
    },
    pip: {
        argv: (extra) => ["pip", "install", "--only-binary=:all:", "--no-deps", ...extra],
        timeout: 300_000,
    },
    cargo: {
        argv: (extra) => ["cargo", "fetch", "--locked", ...extra],
        timeout: 300_000,
    },
    dotnet: {
        argv: (extra) => ["dotnet", "restore", "--locked-mode", ...extra],
        timeout: 300_000,
    },
};

const ARG_RE = /^[A-Za-z0-9._=:@/\\-]+$/;

// Patterns that — even though they pass ARG_RE — would semantically negate
// the hardcoded safety flags via last-wins precedence. Anything matching
// one of these denylist regexes is rejected before being appended to argv.
//
// Round-2 hardening: each negation flag is matched in BOTH the `flag=value`
// AND the bare `flag` form (which would consume the next positional arg as
// its value). Round-1's regex was `/^--no-binary[=$]/i` which incorrectly
// used `[=$]` (a character class containing `=` and literal `$`) instead of
// `(?:=|$)`. That allowed the bare `--no-binary` form (with the value
// passed as the next argv token) to slip through.
//
// We also reject:
//   - any extra arg that LOOKS like an absolute path (drive letter on
//     Windows or leading slash on POSIX) — most package managers don't
//     need such positional tokens for the operations these wrappers run,
//     and the few that do (e.g. `pip install ./local-wheel.whl`) can use
//     a relative path under cwd. Absolute positional tokens are how an
//     agent could redirect installs to attacker-controlled directories.
//   - any extra arg containing path-traversal segments (`..`).
// Patterns that look like absolute paths (any of: drive-letter, UNC, bare
// leading slash/backslash). Used both as standalone-arg rejects and as
// substring-match for FLAG VALUES (`--target=C:\evil`).
const ABS_PATH_RE = /(?:[A-Za-z]:[\\/]|^\\\\|^[\\/])/;
const TRAVERSAL_RE = /\.\./;

// URL schemes that an attacker could use to redirect installs to remote
// resources (in particular pip's positional install supports URLs to wheels).
const URL_SCHEME_RE = /^[A-Za-z][A-Za-z0-9+.\-]*:\/\//;

// Version-pinned package specs (npm `pkg@1.2.3`, npm scoped `@scope/pkg@1.2.3`,
// pip `pkg==1.2.3`). These reach the install command as positional args and
// pull arbitrary versions from the (default) registry — bypassing the
// lockfile-pinning the safe-mode flags rely on. Round-5 hardening
// (opus47xhigh F1 + gpt-5.5 F2). Round-6 hardening (opus47xhigh + gpt-5.5):
// also block npm scoped form `@scope/pkg(@version)?`.
const VERSION_PIN_RE = /^[A-Za-z0-9_.-]+(?:@|==).+/;
const SCOPED_PKG_RE = /^@[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:@.*)?$/;

const ARG_DENYLIST = [
    // Round-7 hardening (gpt-5.5 R7 F1): catch ANY form of the
    // ignore-scripts toggle, including `--no-ignore-scripts=true`,
    // `--ignore-scripts=anything-other-than-the-hardcoded-default`, etc.
    // The safe-mode `--ignore-scripts` is already hardcoded; agents have
    // no legitimate reason to pass another --ignore-scripts in extra_args.
    /^--no-ignore-scripts(?:=|$)/i,
    /^--ignore-scripts(?:=|$)/i,
    /^--only-binary=(?!:all:$).*/i,
    /^--only-binary$/i,
    /^--no-binary(?:=|$)/i,
    /^--no-only-binary$/i,
    /^--no-no-deps$/i,
    /^--no-no-build-isolation$/i,
    /^--use-feature(?:=|$).*no-build-isolation/i,
    /^--use-feature$/i,
    /^--no-locked$/i,
    /^--no-locked-mode$/i,
    /^--prefix(?:=|$)/i,
    /^--cwd(?:=|$)/i,
    /^--directory(?:=|$)/i,
    /^--manifest-path(?:=|$)/i,
    /^--project(?:=|$)/i,
    /^--target(?:=|$)/i,
    /^--target-dir(?:=|$)/i,
    /^--output(?:=|$)/i,
    /^--output-dir(?:=|$)/i,
    /^--root(?:=|$)/i,
    /^--user-base(?:=|$)/i,
    /^--global$/i,
    /^--index-url(?:=|$)/i,
    /^--extra-index-url(?:=|$)/i,
    /^--trusted-host(?:=|$)/i,
    /^--registry(?:=|$)/i,
    /^--source(?:=|$)/i,
    /^--package-source(?:=|$)/i,
    /^--config(?:=|$)/i,
    /^--no-package-lock(?:=|$)/i,
    /^--no-shrinkwrap(?:=|$)/i,
    /^--no-frozen-lockfile(?:=|$)/i,
    /^[A-Za-z]:[\\/]/,
    /^\\\\/,
    /^\\/,
    /^\//,
    /\.\./,
    URL_SCHEME_RE,
    VERSION_PIN_RE,
    SCOPED_PKG_RE,
];

function validateExtraArgs(args) {
    if (!args) return [];
    if (!Array.isArray(args)) {
        throw new Error("extra_args must be an array of strings (or omitted)");
    }
    if (args.length > 32) {
        throw new Error("extra_args has more than 32 entries (suspicious)");
    }
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (typeof a !== "string") throw new Error(`extra_args contains non-string entry: ${typeof a}`);
        if (a.length > 256) throw new Error("extra_args contains an entry over 256 chars");
        if (!ARG_RE.test(a)) throw new Error(`extra_args contains entry with disallowed characters: ${JSON.stringify(a)}`);

        // Round-8 hardening (gpt-5.5 R8 F2): reject positional (non-flag)
        // arguments entirely. The install wrappers exist to install the
        // audited project's pre-pinned dependencies (lockfile). They MUST
        // NOT be used to install arbitrary additional packages — that
        // would bypass the lockfile-pinning safety posture. The previous
        // denylist (URL / scoped-pkg / version-pin) caught most positional
        // attacks but bare package specs like `malicious-pkg` slipped
        // through. Allow only flags (start with `-`) and flag values
        // (positions immediately after a known value-taking flag).
        //
        // Heuristic for "this is a flag value": prior arg is a known
        // value-taking flag in some ecosystem. We don't maintain that list
        // because the install commands we run never take such flags
        // legitimately (npm ci / pip --no-deps / etc. do not need user-
        // supplied values for their config). So we just reject ALL
        // positionals.
        if (!a.startsWith("-")) {
            throw new Error(`extra_args contains a positional (non-flag) argument: ${JSON.stringify(a)}. Positional args (package specs, URLs, paths) are refused — install wrappers operate on the audited project's lockfile only.`);
        }

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

export async function safeInstallHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;

    const ecosystem = args.ecosystem;
    if (typeof ecosystem !== "string" || !ECOSYSTEMS[ecosystem]) {
        return failure(`ecosystem must be one of: ${Object.keys(ECOSYSTEMS).join(", ")}`);
    }
    if (typeof args.clone_path !== "string" || !nodePath.isAbsolute(args.clone_path)) {
        return failure("clone_path is required and must be absolute");
    }

    // Trusted build_root — active audit's buildPath wins; agent-supplied
    // build_root is rejected if it conflicts.
    const ctx = getTrustedAuditContext({ sessionId, args, defaultBuildRoot: DEFAULT_BUILD_ROOT });
    if (!ctx.ok) return failure(ctx.error);
    const buildRoot = ctx.buildRoot;

    // Local-source mode refusal: an audit in audit_local_source* mode
    // has no clone and no install pipeline. Installs target an on-disk
    // clone authorised by activateAudit; local-source audits don't
    // produce one.
    if (ctx.hasActiveAudit && ctx.localPath) {
        return failure(`safe_install refused: active audit is local-source mode (target: ${ctx.localPath}). Install operations apply to build-mode audits only. If you need to verify install behavior of this local project, run \`npm install\` (or your package manager) yourself outside zerotrust-sourcecheck — the wrappers don't apply to operator-owned local code.`);
    }

    // Round-3 hardening: if a sessionId was supplied (production agents
    // always have one) but no active audit exists, REFUSE. The round-2
    // mode-is-build check above only fires when ctx.mode is non-null, so
    // an expired/absent audit would let the agent run installs without
    // the i_understand_build_executes_code ack ever being checked. The
    // ack flag is enforced at handler-activation time only; without an
    // active audit we have no proof the operator consented.
    if (sessionId && !ctx.hasActiveAudit) {
        return failure(`safe_install refused: no active audit for this session (TTL expired or zerotrust_sourcecheck not invoked). Re-invoke zerotrust_sourcecheck with audit_and_safe_build* or audit_and_full_build* to authorize installs.`);
    }

    // Round-2 hardening: refuse to install when active audit mode is not a
    // build mode. Without this, an audit activated as audit_source gives the
    // agent a no-ack path to install packages (which can run setup.py / lifecycle
    // scripts depending on ecosystem). The ack-flag gate at activation time is
    // the only place i_understand_build_executes_code is enforced.
    if (ctx.mode && !modeIsBuild(ctx.mode)) {
        return failure(`safe_install refused: active audit mode '${ctx.mode}' is not a build mode. Re-invoke zerotrust_sourcecheck with audit_and_safe_build* or audit_and_full_build* (and the required ack flags) to install packages.`);
    }

    if (!pathIsUnder(buildRoot, args.clone_path)) {
        return failure(`clone_path ${args.clone_path} is not under build_root ${buildRoot}`);
    }

    // Round-4 hardening (gpt-5.5 F2): if the active audit has a recorded
    // resolved clone path (set by safe_clone success), the install must
    // target THAT path exactly. Without this, a session activated for repo
    // A could install dependencies into a sibling repo-B directory under
    // the same sandbox.
    //
    // Round-6 hardening (gpt-5.5 R6 F1): when the audit IS active but no
    // resolved clone path has been recorded yet (i.e. safe_clone hasn't
    // run), REFUSE — otherwise an agent could install into ANY sibling
    // before the binding is established. The intended sequence is
    // sourcecheck → safe_clone → safe_install → safe_build.
    if (ctx.hasActiveAudit) {
        if (!ctx.resolvedClonePath) {
            return failure(`safe_install refused: no resolved clone path recorded for the active audit. Call zerotrust_safe_clone before zerotrust_safe_install.`);
        }
        const argResolved = nodePath.resolve(args.clone_path).toLowerCase();
        const auditResolved = ctx.resolvedClonePath.toLowerCase();
        if (argResolved !== auditResolved) {
            return failure(`safe_install refused: clone_path ${args.clone_path} does not match the active audit's resolved clone path ${ctx.resolvedClonePath}`);
        }
    }
    let extraArgs;
    try {
        extraArgs = validateExtraArgs(args.extra_args);
    } catch (err) {
        return failure(err.message);
    }
    const spec = ECOSYSTEMS[ecosystem];
    const argv = spec.argv(extraArgs);
    const bareProgram = argv[0];
    const programArgs = argv.slice(1);

    // Round-11 hardening (gpt-5.5 R11 F1): resolve the bare program name
    // (npm/pip/cargo/dotnet/etc.) to a TRUSTED absolute path BEFORE
    // execFileSync. On Windows, the package managers are typically `.cmd`
    // shims; Node's child_process spawns `.cmd` via cmd.exe, which searches
    // the current directory before PATH. A malicious repo could plant
    // `npm.cmd` at the clone root and the wrapper would execute that.
    // Resolving to an absolute path (and refusing any candidate under the
    // build_root or clone_path) closes this hole.
    const program = resolveTrustedProgram(bareProgram, {
        forbiddenRoots: [buildRoot, args.clone_path],
    });
    if (!program) {
        return failure(`safe_install refused: could not resolve a trusted absolute path for ${JSON.stringify(bareProgram)} on PATH (or every candidate was inside build_root). Ensure ${bareProgram} is installed system-wide and not shadowed by a repo-planted binary.`);
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
            env: {
                ...process.env,
                npm_config_audit: "false",
                npm_config_fund: "false",
                npm_config_progress: "false",
            },
            stdio: ["ignore", "pipe", "pipe"],
        });
    } catch (err) {
        stdout = err.stdout ? String(err.stdout) : "";
        stderr = err.stderr ? String(err.stderr) : err.message;
        exitCode = err.status || 1;
        return failure(`${ecosystem} install failed (exit ${exitCode}): ${stderr.slice(-2000)}`);
    }

    return success({
        ecosystem,
        clonePath: args.clone_path,
        argv,
        exitCode,
        stdout: stdout.slice(-4000),
        stderr: stderr.slice(-2000),
    });
}

export const __internals = {
    ECOSYSTEMS,
    ARG_RE,
    ARG_DENYLIST,
    validateExtraArgs,
    pathIsUnder,
};
