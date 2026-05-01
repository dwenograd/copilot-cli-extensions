// triple-review/handler.mjs
//
// Pure handler function — orchestrates the validation/scrub/policy/resolve
// pipeline and calls the packet builder. Exported separately from
// extension.mjs so it can be unit-tested without spinning up joinSession().

import nodePath from "node:path";
import {
    DEFAULT_MODELS,
    CHEAP_MODELS,
    SYNTHESIS_MODEL,
    scrub,
    applyInjectionPolicy,
    generateNonce,
    renderInjectionPreamble,
    injectionInstructionForSubAgents,
    resolveModels,
    renderSubstitutionNote,
    formatZodError,
} from "../_shared/index.mjs";
import { tripleReviewSchema } from "../_shared/schemas.mjs";
import { checkBudget, renderBudgetBlock, SYNTH_CAP_PER_ROUND } from "../_shared/budget.mjs";
import { buildInstructionPacket } from "./packet.mjs";

const TOOL = "triple-review";

function quotePathForGitCommand(path) {
    if (/^[A-Za-z0-9._/\\:-]+$/.test(path)) {
        return path;
    }
    return JSON.stringify(path);
}

export function resolveScopeCommands(scope) {
    if (!scope) {
        return { diffCommand: null, shortstatCommand: null, mode: "auto-detect" };
    }

    if (scope === "staged") {
        return { diffCommand: "git diff --cached", shortstatCommand: "git diff --cached --shortstat", mode: "git" };
    }
    if (scope === "unstaged") {
        return { diffCommand: "git diff", shortstatCommand: "git diff --shortstat", mode: "git" };
    }
    if (scope === "all-uncommitted") {
        return { diffCommand: "git diff HEAD", shortstatCommand: "git diff HEAD --shortstat", mode: "git" };
    }
    if (scope.startsWith("branch:")) {
        const base = scope.slice("branch:".length);
        return { diffCommand: `git diff ${base}...HEAD`, shortstatCommand: `git diff ${base}...HEAD --shortstat`, mode: "git" };
    }
    if (scope.startsWith("commit:")) {
        const sha = scope.slice("commit:".length);
        return { diffCommand: `git show ${sha}`, shortstatCommand: `git show --shortstat --format= ${sha}`, mode: "git" };
    }
    if (scope.startsWith("files:")) {
        const files = scope
            .slice("files:".length)
            .split(",")
            .map((path) => quotePathForGitCommand(path.trim()))
            .join(" ");
        return {
            diffCommand: `git diff HEAD -- ${files}`,
            shortstatCommand: `git diff HEAD --shortstat -- ${files}`,
            mode: "git",
        };
    }
    if (scope.startsWith("paths:")) {
        // Non-git mode: reviewers `view` the listed files directly. No diff
        // is produced and no git command runs. Use this when:
        //   - the target dir isn't a git repo, OR
        //   - you want reviewers to inspect current file state without
        //     reference to a baseline (e.g., reviewing a finished module).
        // This sidesteps the "sub-agent-spawned shell hangs on git output"
        // failure pattern that recurred 5+ times across this session's
        // iterative reviews — by removing the git invocation entirely.
        const rawPaths = scope
            .slice("paths:".length)
            .split(",")
            .map((path) => path.trim())
            .filter((path) => path.length > 0);
        // Tilde expansion is intentionally NOT supported — `path.resolve`
        // would produce `<cwd>/~/...` which `view` cannot find. Fail loudly
        // with a clear message instead of silently producing a broken path.
        const tildePath = rawPaths.find((p) => p.startsWith("~/") || p.startsWith("~\\") || p === "~");
        if (tildePath) {
            throw new Error(
                `paths:<list> entries cannot start with '~' (got: '${tildePath}'). ` +
                `Tilde-expansion is not supported — pass an absolute path (e.g. 'C:\\Users\\you\\project\\file.js' on Windows or '/home/you/project/file.js' on Unix), ` +
                `or a path relative to the orchestrator's current working directory.`,
            );
        }
        const paths = rawPaths
            // Resolve relative paths against the orchestrator's cwd so that
            // sub-agent `view` calls (which require absolute paths) succeed
            // regardless of how the user invoked the tool. The handler is
            // intentionally NOT given a `cwd` parameter — it uses
            // `process.cwd()` at handler-call time, matching what the user
            // sees as "current directory" in their session.
            //
            // Cross-platform note: `nodePath.resolve` produces backslashes
            // on Windows and forward slashes everywhere else. To keep
            // packet snapshots reproducible across platforms (and because
            // the `view` tool accepts forward slashes on Windows too), we
            // normalize the resolved path to forward slashes here. User-
            // supplied absolute paths that were already backslash-style
            // ARE preserved verbatim — only handler-resolved relative
            // entries get normalized.
            .map((path) => {
                if (nodePath.isAbsolute(path)) {
                    return path;
                }
                return nodePath.resolve(process.cwd(), path).replace(/\\/g, "/");
            });
        return {
            diffCommand: null,
            shortstatCommand: null,
            mode: "no-git",
            paths,
        };
    }

    throw new Error(`Unsupported parsed scope: ${scope}`);
}

export async function runHandler(args, deps = {}) {
    const log = deps.log || (async () => {});

    // 1. Schema parse (input validation, trimming, length caps, scope grammar, mutual exclusion).
    const parsed = tripleReviewSchema.safeParse(args || {});
    if (!parsed.success) {
        return {
            textResultForLlm: `${TOOL} error: ${formatZodError(parsed.error)}`,
            resultType: "failure",
        };
    }
    const input = parsed.data;

    // 2. Budget check — handler-side authoritative gate.
    const budgetError = checkBudget(TOOL, input);
    if (budgetError) {
        return { textResultForLlm: budgetError, resultType: "failure" };
    }

    // 3. Deterministically resolve explicit scope to git command strings (or
    //    paths-only mode for the no-git case). The resolver may throw on
    //    semantically-invalid scopes that schema validation can't catch
    //    (e.g. tilde-prefixed paths in `paths:` lists).
    let resolvedScope;
    try {
        resolvedScope = resolveScopeCommands(input.scope);
    } catch (err) {
        return {
            textResultForLlm: `${TOOL} error: ${err.message}`,
            resultType: "failure",
        };
    }
    const { diffCommand, shortstatCommand, mode: scopeMode, paths: scopePaths } = resolvedScope;

    // 4. Scrub the only user-supplied free-text field BEFORE policy wrap.
    const scrubbedFocus = input.focus ? scrub(input.focus) : { text: "", redactions: [] };

    // 5. Apply injection policy + USER_INPUT envelope (per-call nonce) to focus only.
    const nonce = generateNonce();
    let focusPolicy = { ok: true, wrapped: "", warnings: [] };
    if (scrubbedFocus.text) {
        focusPolicy = applyInjectionPolicy(scrubbedFocus.text, "focus", nonce);
        if (!focusPolicy.ok) {
            return { textResultForLlm: `${TOOL} error: ${focusPolicy.reason}`, resultType: "failure" };
        }
    }

    // 6. Resolve models (substitute deprecated defaults; honor user overrides verbatim).
    //    Both the reviewer trio AND the synthesis model go through resolveModels
    //    so deprecation of either triggers the [fallback] log path uniformly.
    const isUserOverride = input.models !== undefined;
    const requestedTrio = input.models
        ?? (input.cheap ? CHEAP_MODELS : DEFAULT_MODELS);
    const resolved = resolveModels(requestedTrio, { isUserOverride });
    const resolvedSynth = resolveModels([SYNTHESIS_MODEL], { isUserOverride: false });
    const synthesisModel = resolvedSynth.models[0];
    const allSubstitutions = [...resolved.substitutions, ...resolvedSynth.substitutions];

    // 7. Build the protocol packet from the prepared pieces.
    const packet = buildInstructionPacket({
        trio: resolved.models,
        synthesisModel,
        cheap: input.cheap === true && !isUserOverride,
        focusWrapped: focusPolicy.wrapped,
        scope: input.scope ?? null,
        scopeMode,
        scopePaths,
        diffCommand,
        shortstatCommand,
        maxRounds: input.max_rounds,
        severityThreshold: input.severity_threshold,
        synthCap: SYNTH_CAP_PER_ROUND,
        budgetBlock: renderBudgetBlock(TOOL, input),
        substitutionNote: renderSubstitutionNote(allSubstitutions),
        injectionPreamble: renderInjectionPreamble(),
        scrubNote: scrubbedFocus.redactions.length > 0
            ? `> **Note:** scrubbed ${scrubbedFocus.redactions.reduce((s, r) => s + r.count, 0)} high-confidence credential(s) from input before sending to sub-agents.`
            : "",
        injectionWarnings: focusPolicy.warnings,
        subAgentInstruction: injectionInstructionForSubAgents(),
    });

    // 8. Operational logging — every substitution gets a [fallback] entry.
    if (scrubbedFocus.redactions.length > 0) {
        await log(`[scrub] ${JSON.stringify(scrubbedFocus.redactions)}`);
    }
    for (const sub of allSubstitutions) {
        await log(`[fallback] ${sub.requested} -> ${sub.used}: ${sub.reason}`);
    }
    await log(
        `${TOOL} invoked — ${input.cheap && !isUserOverride ? "CHEAP mode — " : ""}reviewers: ${resolved.models.join(", ")} — max ${input.max_rounds} round(s) — scope: ${input.scope || "auto-detect"}`,
    );

    return { textResultForLlm: packet, resultType: "success" };
}
