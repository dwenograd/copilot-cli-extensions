// Extension: zerotrust-sourcecheck
//
// Audits a GitHub URL or local directory for source-level malware indicators.
// Current architecture: API-direct URL reads, deterministic checks, an optional
// 32-role council, and substitutional wrappers for clone/install/build.
//
// IMPORTANT — no `hooks: {}` registration (operator-elevated-permissions
// minimization, v4-r3): earlier versions registered an onPreToolUse hook
// (forward-compat against observed Copilot CLI 1.0.x behavior where the runtime
// did not fire it for built-in tools; no public issue URL is recorded here)
// and an onSessionEnd hook (per-session
// Map cleanup). Registering hooks at all triggers an "extension wants
// elevated permissions: register hooks" prompt at every CLI launch, which
// exposes capabilities (see-every-tool-input, modify-tool-input, run
// arbitrary code on every invocation) that this extension does not actually
// need. We dropped the registration entirely:
//   - onPreToolUse was vestigial anyway; the safe-wrapper tools below are
//     the real safety mechanism, not the hook.
//   - onSessionEnd cleanup is replaced by the canonical end-of-audit
//     lifecycle close inside safeWrappers/sweepWrapper.mjs. The packet's
//     Section 9 instructs the agent to call zerotrust_sweep_audit_scratch
//     (REQUIRED) for EVERY mode (build, audit-only, API-direct,
//     metadata_only), and sweep is documented to run AFTER cleanup. So
//     sweep is the last wrapper in the audit lifecycle and on success
//     (non-dry-run) it calls clearRecordedOutcome + deactivateAudit to
//     close the audit-state Map entries. Per-mode TTL inside
//     enforcement.mjs::getActiveAudit remains a secondary safety net for
//     audits that never reach sweep (TTL expiry deletes the audit entry
//     and dispatches clearRecordedOutcome). Worst case: a session that
//     ends without reaching sweep AND without further audit access
//     leaves a few hundred bytes of stale Map state until the extension
//     process exits — bounded and trivial.
// `preToolUseHook` is still exported from enforcement.mjs and unit-tested;
// the function is just not wired into the SDK. If a future CLI release
// adds a non-elevated way to register an opt-in deny-only hook, that's
// the time to revisit.
//
// Architecture:
//   - extension.mjs (this file): joinSession + tool registrations
//   - handler.mjs              : URL parsing, mode resolution, scrub, council dispatch, packet build entry
//   - modes.mjs                : single source of truth for mode taxonomy + helpers
//   - urlParser.mjs            : pure URL/owner/repo/ref/path validation
//   - enforcement.mjs          : audit-in-progress state machine (activate/getActive/deactivate) used by the wrappers; also exports the unregistered preToolUseHook for tests and future re-wiring
//   - packet.mjs               : the natural-language playbook the agent executes
//   - council/                 : 32-role roster + universal prompt template + extra-roles validator
//   - safeWrappers/            : substitutional-safety tools

import { joinSession } from "@github/copilot-sdk/extension";
import { runHandler } from "./handler.mjs";
import {
    safeCloneHandler,
    safeInstallHandler,
    safeBuildHandler,
    recordOutcomeHandler,
    finalizeReportHandler,
    cleanupAuditHandler,
    sweepAuditScratchHandler,
    safeListTreeHandler,
    safeFetchFileHandler,
} from "./safeWrappers/index.mjs";

const session = await joinSession({
    tools: [
        {
            name: "zerotrust_sourcecheck",
            description:
                "Audit a GitHub URL or already-on-disk directory for source-level malware indicators. URL wrappers do not intentionally create source files, although Copilot CLI/session logging may retain returned text; verify_release downloads assets to _quarantine, which must be removed manually when no clone exists. Local modes read the supplied directory without SHA pinning. Council modes run 32 specialized roles. Build modes require explicit acknowledgements, but no separate prior-audit report is enforced. Safe/full build modes currently use the same install/build wrappers: install lifecycle scripts remain suppressed, while build scripts may execute in either mode. Wrapper protections apply only to calls routed through the registered wrappers; no pre-tool hook intercepts raw built-in shell calls.",
            parameters: {
                type: "object",
                properties: {
                    url: {
                        type: "string",
                        maxLength: 2048,
                        description:
                            "GitHub URL (mutually exclusive with local_path). Accepted shapes: https://github.com/<owner>/<repo>, /tree/<ref>, /blob/<ref>, /commit/<sha>, /releases/tag/<tag>, /releases, /pull/<n>. SSH URLs and credentialled URLs are rejected. Trailing .git is stripped.",
                    },
                    local_path: {
                        type: "string",
                        maxLength: 4096,
                        description:
                            "Absolute path to an already-on-disk directory to audit (mutually exclusive with url). Use this when you have a repo cloned locally and want to audit those exact bytes without re-fetching from GitHub. Requires i_understand_local_path_reads_my_disk: true. Only valid with mode=audit_local_source or audit_local_source_council (default if mode omitted). Rejected: relative paths, UNC paths (\\\\server\\share), the \\\\?\\ long-path prefix, paths with .. segments, credential-store paths (.ssh, .aws, .docker, .kube, .gnupg, .password-store, Microsoft\\Credentials, Microsoft\\Vault), root-level symlinks.",
                    },
                    mode: {
                        type: "string",
                        enum: [
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
                        ],
                        description:
                            "Audit depth. Repo/tree/commit/pull URLs default to audit_source_council unless ZEROTRUST_DETERMINISTIC_ONLY=1; release URLs default to verify_release; local paths default to audit_local_source_council. Build modes require i_understand_build_executes_code. Full variants also require unsafe, but currently use the same wrapper commands as safe variants. Council-build modes additionally require a recorded outcome unless the orthogonal incompleteness/severity overrides are supplied.",
                    },
                    ref: {
                        type: "string",
                        maxLength: 255,
                        description:
                            "Optional (URL mode only). Override the branch/tag/commit ref from the URL. Validated against ^[A-Za-z0-9._/-]{1,255}$ with no '..' segments or leading '-'. The handler still pins to the resolved commit SHA before any clone. Not valid with local_path (local audits operate on the bytes already on disk).",
                    },
                    i_understand_local_path_reads_my_disk: {
                        type: "boolean",
                        default: false,
                        description:
                            "Required ack flag for local_path mode. This mode lets the audit's role agents read files anywhere under the given path with the operator's filesystem privileges. The role prompts enforce a containment rule that every view/grep/glob path must start with the given local_path, but this is prompt-time discipline (not wrapper-enforced).",
                    },
                    focus: {
                        type: "string",
                        maxLength: 65536,
                        description:
                            "Optional. Free-text emphasis the audit should pay extra attention to. Scrubbed for credentials and wrapped in a USER_INPUT injection envelope before reaching the agent. Hard cap: 64KB.",
                    },
                    build_root: {
                        type: "string",
                        maxLength: 4096,
                        description:
                            "Optional. Absolute path under which all clone/build/report/quarantine artifacts will be created. Default: $ZEROTRUST_BUILD_ROOT env var if set, otherwise <homedir>/.copilot/zerotrust-sandbox. Must be absolute. Wrapper tools refuse clone/build/report paths outside this root.",
                    },
                    i_understand_build_executes_code: {
                        type: "boolean",
                        default: false,
                        description:
                            "Required ack flag for all build modes, including audit_and_safe_build_council and audit_and_full_build_council. Build steps execute repo-controlled code on your host even with safe-mode flags.",
                    },
                    unsafe: {
                        type: "boolean",
                        default: false,
                        description:
                            "Required acknowledgement for full-build modes, in addition to i_understand_build_executes_code. It changes admission/warning posture; current full modes still use the same wrappers as safe modes and do not enable an alternate lifecycle-script installer.",
                    },
                    i_understand_private_repo_risk: {
                        type: "boolean",
                        default: false,
                        description:
                            "Required when the audited repo is private. Auditing a private repo sends proprietary source to model sub-agents and may leak GitHub API access patterns to the repo owner.",
                    },
                    roles: {
                        type: "object",
                        description:
                            "Optional (council modes only). Per-role-id model overrides as a partial object, e.g. { \"obfuscation\": \"gpt-5.6-sol\" }. Roles you don't specify use the tiered defaults. Unknown role IDs are silently ignored; unknown model IDs produce an error.",
                        additionalProperties: { type: "string" },
                    },
                    extra_roles: {
                        type: "array",
                        description:
                            "Optional (council modes only). Inject ad-hoc roles into the council for this run. Each entry is { id, model, description, angle }. id must match ^[a-z][a-z0-9-]{2,63}$, model must be in the allowed list, description and angle are capped at 2KB and wrapped in USER_INPUT envelopes (treated as untrusted hints by sub-agents).",
                        items: { type: "object" },
                    },
                    judge: {
                        type: "string",
                        description:
                            "Optional (council modes only). Override the meta-judge model. Default is gpt-5.6-sol with elevated reasoning; every spawned meta-judge runs with context_tier:\"long_context\".",
                    },
                    max_premium_calls: {
                        type: "integer",
                        minimum: 1,
                        description:
                            "Optional (council modes only). Launch-count circuit breaker. Default 200. This is not a billing/cost estimate.",
                    },
                },
                required: [],
            },
            handler: (args, invocation) =>
                runHandler(args, {
                    sessionId: invocation?.sessionId,
                    log: (msg) => session.log(msg),
                }),
        },

        // ----- v4 API-direct audit tools (default for non-build modes) -----
        // These tools fetch GitHub content via `gh api` and return it through
        // tool results. They do not intentionally create source files, but CLI
        // logging/output spill behavior is outside this extension. The audit
        // packet for non-build modes directs the agent to call these
        // instead of safe_clone — keeping Defender out of the picture
        // for source files entirely.

        {
            name: "zerotrust_safe_list_tree",
            description:
                "List a repo tree at a resolved SHA through the GitHub API and return metadata in the tool result. The wrapper does not create a tree file. It cross-checks the active audit's owner/repo/ref/SHA. If coverageComplete is not true, drill into subtrees or report incomplete coverage; do not issue a no-red-flags verdict.",
            parameters: {
                type: "object",
                properties: {
                    url: { type: "string", description: "GitHub URL (alternative to owner/repo)" },
                    owner: { type: "string" },
                    repo: { type: "string" },
                    ref: { type: "string", description: "Branch / tag / SHA / refs/pull/N/head. Optional; defaults to active audit's pinned ref or HEAD." },
                    refType: { type: "string", enum: ["release_tag", "branch_or_tag", "pr_head", "commit"], description: "Optional; helps resolve ambiguous refs (e.g. tag vs branch with same name)." },
                },
            },
            handler: (args, invocation) => safeListTreeHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_fetch_file",
            description:
                "Fetch one file at the audit's pinned SHA through the GitHub API and return bounded data in the tool result. The wrapper does not create a source file, but Copilot CLI/session logging may retain returned text. Binary content is never returned in full; within the fetch cap it returns size, SHA-256, and a 256-byte preview, while over-ceiling files may be metadata-only. Text defaults to 256KB inline.",
            parameters: {
                type: "object",
                properties: {
                    owner: { type: "string" },
                    repo: { type: "string" },
                    sha: { type: "string", description: "40-char hex SHA (commit). Use the value returned by zerotrust_safe_list_tree." },
                    path: { type: "string", description: "Forward-slash repo-relative path. No '..' / no leading slash." },
                    max_bytes: { type: "integer", minimum: 1, description: "Optional hard ceiling per call (default 5MB, max 50MB). Over-ceiling files return metadata-only or a bounded preview depending on the GitHub API response path." },
                    max_text_bytes: { type: "integer", minimum: 1, description: "Optional inline-text cap (default 256KB, max 1MB). Text files over the cap are truncated with `textTruncated: true`. Has no effect on binaries (which never return content)." },
                },
                required: ["owner", "repo", "sha", "path"],
            },
            handler: (args, invocation) => safeFetchFileHandler(args, { sessionId: invocation?.sessionId }),
        },

        // ----- Substitutional-safety wrapper tools -----
        // These wrappers run the dangerous operations themselves with
        // hardened flags hardcoded. They remain available for build modes
        // (audit_and_*_build*), but for default audit modes the v4
        // API-direct tools above should be used instead — they avoid
        // the on-disk source-file step entirely.

        {
            name: "zerotrust_safe_clone",
            description:
                "Hardened build-mode clone. Resolves a trusted git executable and commit SHA, binds owner/repo/ref/SHA, and hardcodes protocol.file/ext=never, protocol.allow=never, protocol.https=always, symlinks/fsmonitor off, null hooks path, longpaths, no submodules/tags/checkout, blob filtering, and no LFS smudge. No minimum Git version is enforced; unsupported flags fail the call.",
            parameters: {
                type: "object",
                properties: {
                    url: {
                        type: "string",
                        description: "GitHub URL of the repo to clone (any of the shapes accepted by parseGithubUrl).",
                    },
                    ref: {
                        type: "string",
                        description: "Optional. Branch, tag, or 40-char SHA to check out. Defaults to the URL's embedded ref or HEAD.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional. Absolute path under which the clone subdirectory will be created. Defaults to the standard build_root.",
                    },
                },
                required: ["url"],
            },
            handler: (args, invocation) => safeCloneHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_install",
            description:
                "Run one allowlisted dependency operation against the active clone: npm ci, npm install, yarn install, pnpm install, pip install, cargo fetch, or dotnet restore with hardcoded safety flags. extra_args are flag tokens only; positional packages/URLs/paths, redirects, traversal, and safety-negating options are refused. Option values must use a single --flag=value token rather than a split positional value.",
            parameters: {
                type: "object",
                properties: {
                    ecosystem: {
                        type: "string",
                        enum: ["npm", "npm-install", "yarn", "pnpm", "pip", "cargo", "dotnet"],
                        description: "Which package manager to run. 'npm' uses `npm ci` (lockfile-strict); 'npm-install' uses `npm install` (allows resolution).",
                    },
                    clone_path: {
                        type: "string",
                        description: "Absolute path of the clone (must be under build_root).",
                    },
                    extra_args: {
                        type: "array",
                        items: { type: "string" },
                        description: "Optional flag-only args. Max 32 × 256 chars; positional packages/URLs/paths, redirects, traversal, absolute paths, and safety-negating options are refused.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional. Build_root containment bound. Defaults to the standard build_root.",
                    },
                },
                required: ["ecosystem", "clone_path"],
            },
            handler: (args, invocation) => safeInstallHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_build",
            description:
                "Run an allowlisted build command against the active clone. Safe and full modes use the same build implementation. Council-build modes require a recorded outcome; proceed_on_council_failure bypasses only incompleteness and council_build_override bypasses only severity, so both are needed to bypass both gates.",
            parameters: {
                type: "object",
                properties: {
                    ecosystem: {
                        type: "string",
                        enum: ["npm", "yarn", "pnpm", "cargo", "dotnet", "dotnet-publish"],
                        description: "Which build tool to run.",
                    },
                    clone_path: {
                        type: "string",
                        description: "Absolute path of the clone (must be under build_root).",
                    },
                    extra_args: {
                        type: "array",
                        items: { type: "string" },
                        description: "Optional args, max 32 × 256 chars. Redirect/negation flags, URL schemes, traversal, and absolute-path values are refused; unlike install, benign relative positional tokens are not categorically rejected.",
                    },
                    mode: {
                        type: "string",
                        description: "Optional. The audit mode in effect — when this is a council-build mode the council-gate check runs.",
                    },
                    council_build_override: {
                        type: "boolean",
                        description: "Optional (council-build modes only). Bypass the severity-threshold gate. Council must still be COMPLETE; doesn't bypass incomplete-council. Defaults to false.",
                    },
                    proceed_on_council_failure: {
                        type: "boolean",
                        description: "Optional (council-build modes only). Bypass the incomplete-council gate. Implies build proceeds with deterministic-baseline-only findings. Defaults to false.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional. Build_root containment bound.",
                    },
                },
                required: ["ecosystem", "clone_path"],
            },
            handler: (args, invocation) => safeBuildHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_record_council_outcome",
            description:
                "Record the council's verdict for this session. The agent must call this after the meta-judge produces its verdict, BEFORE invoking zerotrust_safe_build in any council-build mode — without a recorded outcome the build wrapper refuses to run. Verdict must be one of: critical | high | medium | low | no red flags found | incomplete.",
            parameters: {
                type: "object",
                properties: {
                    verdict: {
                        type: "string",
                        enum: ["critical", "high", "medium", "low", "no red flags found", "incomplete"],
                    },
                    critical_count: {
                        type: "integer",
                        minimum: 0,
                    },
                    high_count: {
                        type: "integer",
                        minimum: 0,
                    },
                    complete: {
                        type: "boolean",
                        description: "false when the council had to abort early (mandatory roles failed, per-category gap, <90% returns). true when the meta-judge produced a verdict on a complete-enough council.",
                    },
                },
                required: ["verdict", "critical_count", "high_count", "complete"],
            },
            handler: (args, invocation) => recordOutcomeHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_finalize_report",
            description:
                "Write the final audit report markdown to the canonical path under <build_root>\\_reports\\<owner>-<repo>-<short_sha>\\REPORT.md. Refuses if the computed path would escape build_root. Caps body at 1MB. Returns the report path on success.",
            parameters: {
                type: "object",
                properties: {
                    owner: { type: "string", description: "Repo owner (validated against the same regex as urlParser)." },
                    repo: { type: "string", description: "Repo name (validated against the same regex as urlParser)." },
                    short_sha: { type: "string", description: "7+ char SHA (lowercased and truncated to 7)." },
                    markdown_body: { type: "string", description: "The full markdown body to write." },
                    build_root: {
                        type: "string",
                        description: "Optional. Defaults to the standard build_root.",
                    },
                },
                required: ["owner", "repo", "short_sha", "markdown_body"],
            },
            handler: (args, invocation) => finalizeReportHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_cleanup_audit",
            description:
                "Delete a canonical build-mode clone and optionally its report/quarantine siblings. This runs before the final scratch sweep, not last. It cannot clean API-direct verify_release quarantine because clone_path is required. Report is kept by default; matching quarantine is deleted by default.",
            parameters: {
                type: "object",
                properties: {
                    clone_path: {
                        type: "string",
                        description: "Absolute path of the clone directory to delete (must be under build_root).",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional. Build_root containment bound. Defaults to the standard build_root.",
                    },
                    also_delete_report: {
                        type: "boolean",
                        description: "Optional. When true, also delete the matching <build_root>\\_reports\\<basename>\\ directory. Defaults to false (keep REPORT.md).",
                    },
                    also_delete_quarantine: {
                        type: "boolean",
                        description: "Optional. When true (default), also delete the matching <build_root>\\_quarantine\\<basename>\\ directory. Pass false to keep downloaded binaries on disk.",
                    },
                },
                required: ["clone_path"],
            },
            handler: (args, invocation) => cleanupAuditHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_sweep_audit_scratch",
            description:
                "Final audit-lifecycle sweep: delete unrecognized top-level files in build_root and, by default, its immediate parent, then deactivate the audit on non-dry-run success. It never deletes directories. Parent sweeping can affect unrelated files because the whitelist is finite; dry-run first and normally pass also_sweep_parent:false unless the parent is dedicated audit scratch.",
            parameters: {
                type: "object",
                properties: {
                    build_root: {
                        type: "string",
                        description: "Optional. Build_root to sweep. Defaults to the active audit's build_root or the standard build_root.",
                    },
                    also_sweep_parent: {
                        type: "boolean",
                        description: "Optional. Runtime default true: also sweep the immediate parent. This can delete unrelated unrecognized top-level files; dry-run first and prefer false unless the parent is dedicated audit scratch.",
                    },
                    dry_run: {
                        type: "boolean",
                        description: "Optional. When true, returns the list of scratch files without deleting them. Default is false (delete).",
                    },
                },
                required: [],
            },
            handler: (args, invocation) => sweepAuditScratchHandler(args, { sessionId: invocation?.sessionId }),
        },
    ],
    // Intentionally no `hooks: {}` block — see top-of-file comment. We do
    // not register onPreToolUse or onSessionEnd because doing so would
    // require the operator to grant the "register hooks" elevated
    // permission (a capability class that allows seeing every tool input,
    // modifying tool inputs, and running arbitrary code on every
    // invocation) for no actual benefit under the current runtime.
});
