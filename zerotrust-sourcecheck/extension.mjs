// Extension: zerotrust-sourcecheck
//
// Audits a GitHub URL for source-level malware indicators. v3:
// substitutional-safety hybrid — deterministic baseline checks +
// an optional 32-role multi-model security council, with the dangerous
// commands (clone/install/build) executed by the extension itself via
// safe-wrapper tools rather than by the agent's raw shell.
//
// IMPORTANT — no `hooks: {}` registration (operator-elevated-permissions
// minimization, v4-r3): earlier versions registered an onPreToolUse hook
// (forward-compat against a known Copilot CLI 1.0.x bug where the runtime
// doesn't fire it for built-in tools) and an onSessionEnd hook (per-session
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
//   - safeWrappers/            : the substitutional-safety tools (v3 core architecture)

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
                "Audits a GitHub URL OR an already-on-disk directory for source-level malware indicators. **URL mode (v4): API-direct by default — source files NEVER touch your disk for audit modes.** Pure URL audit modes (`audit_source`, `audit_source_council`, `metadata_only`) fetch GitHub content via the GitHub API into memory and produce a REPORT.md. `verify_release` is the same API-direct flow for source context, but ALSO downloads release artifacts to `_quarantine/` for hash + magic-byte verification. **Local-path mode:** pass `local_path` (an absolute path to an on-disk directory) + `i_understand_local_path_reads_my_disk: true` to audit bytes already on the operator's disk — use this when you've already downloaded a repo and want to audit that exact tree. Local mode uses `audit_local_source[_council]` only; no clone, no API fetches, no SHA pinning. Council modes (URL or local) run a 32-role multi-model security council across many independent angles. **All audit modes that produce on-disk content (build modes + local modes) include a Section 9b remediation flow** that walks the user through defang / delete-project / keep-as-is per HIGH/CRITICAL finding, with backup-before-edit and no-batch safety rules. Build modes (`audit_and_safe_build`, `audit_and_full_build`, `audit_and_*_build_council`) DO write source to a sandbox and execute the build — these are NOT offered up-front; operator must explicitly request as a follow-up after a clean audit. The hardened wrapper tools (`zerotrust_safe_list_tree`, `zerotrust_safe_fetch_file`, plus the on-disk `zerotrust_safe_clone`/`_install`/`_build` for build modes) all enforce trusted-context binding, path containment, and (for builds) the council-outcome gate. Wrappers refuse with explicit local-mode messages when the active audit is local-source.",
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
                            "Audit depth. metadata_only: GH API recon only, no clone. audit_source: deterministic checklist audit (default for repo/commit/tree URLs). audit_source_council: deterministic baseline plus a 32-role multi-model security council. audit_local_source: deterministic checklist audit against an on-disk directory (use with local_path). audit_local_source_council: 32-role council audit against an on-disk directory (use with local_path; default when local_path is set and mode omitted). verify_release: provenance verification of release artifacts (default for /releases/* URLs). audit_and_safe_build: audit_source + safe build (mandates safe install flags); requires i_understand_build_executes_code. audit_and_full_build: audit_source + lifecycle-script build; requires i_understand_build_executes_code AND unsafe. audit_and_safe_build_council: council audit + safe build; build waits for a recorded passing council outcome unless explicitly overridden. audit_and_full_build_council: council audit + lifecycle-script build; requires both build acknowledgements and the same recorded-outcome gate.",
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
                            "Required ack flag for full-build modes (audit_and_full_build and audit_and_full_build_council), in addition to i_understand_build_executes_code. These modes run lifecycle scripts on your host with no sandbox.",
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
                            "Optional (council modes only). Per-role-id model overrides as a partial object, e.g. { \"obfuscation\": \"gpt-5.5\" }. Roles you don't specify use the tiered defaults. Unknown role IDs are silently ignored; unknown model IDs produce an error.",
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
                            "Optional (council modes only). Override the meta-judge model. Default is claude-opus-4.6-1m (chosen for 1M context to ingest the 7 sub-judge outputs).",
                    },
                    max_premium_calls: {
                        type: "integer",
                        minimum: 1,
                        description:
                            "Optional (council modes only). Circuit breaker against runaway recursion. Default 200 (well above worst-case ~95). Not a cost cap.",
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
        // These tools fetch GitHub content via `gh api` and return it
        // in-memory only. NO source bytes ever land on disk. The audit
        // packet for non-build modes directs the agent to call these
        // instead of safe_clone — keeping Defender out of the picture
        // for source files entirely.

        {
            name: "zerotrust_safe_list_tree",
            description:
                "List a repo's full file tree at a specific SHA via the GitHub API. Returns { sha, truncated, entriesTruncated, totalEntryCount, entries: [{path, type, size, sha}, ...], entryCount, coverageComplete } in-memory. NO files written to disk. Pass either { url } (full GitHub URL) or { owner, repo, ref? }. Resolves the ref to a SHA before listing. Cross-checks active audit's pinned owner/repo/ref. **Coverage gate (mandatory):** if `coverageComplete !== true`, the tree was truncated (either by GitHub or by our 5000-entry anti-spill cap); the audit must drill into subtrees individually OR explicitly surface the coverage gap as a finding — do NOT issue a clean verdict on incomplete coverage. Use this as the FIRST step of an API-direct audit to discover what files exist; then use zerotrust_safe_fetch_file to fetch the interesting ones.",
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
                "Fetch a single file's contents from a repo at a specific SHA via the GitHub API. Returns text (utf-8) or metadata-only (binary) IN MEMORY — file is NEVER written to disk. **v4.1 hardening: BINARY content is NEVER returned in full** — for binary files, response is `{sizeBytes, sha256, encoding: 'binary', previewBase64: <first 256 bytes for magic-byte inspection>}`. Text files over 256KB are truncated to that size with `textTruncated: true`. Files larger than 5MB return metadata + 4KB preview only. Validates path against traversal. Cross-checks active audit's pinned owner/repo. Use after zerotrust_safe_list_tree to fetch the manifests / lockfiles / scripts / suspicious files for inspection — but for binaries, the size + sha256 from the tree listing is sufficient for an audit finding; do not call fetch on binaries unless you specifically need the magic-byte preview.",
            parameters: {
                type: "object",
                properties: {
                    owner: { type: "string" },
                    repo: { type: "string" },
                    sha: { type: "string", description: "40-char hex SHA (commit). Use the value returned by zerotrust_safe_list_tree." },
                    path: { type: "string", description: "Forward-slash repo-relative path. No '..' / no leading slash." },
                    max_bytes: { type: "integer", minimum: 1, description: "Optional hard ceiling per-call (default 5MB, max 50MB). Files over the ceiling return metadata + 4KB preview only." },
                    max_text_bytes: { type: "integer", minimum: 1, description: "Optional inline-text cap (default 256KB, max 1MB). Text files over the cap are truncated with `textTruncated: true`. Has no effect on binaries (which never return content)." },
                },
                required: ["owner", "repo", "sha", "path"],
            },
            handler: (args, invocation) => safeFetchFileHandler(args, { sessionId: invocation?.sessionId }),
        },

        // ----- Substitutional-safety wrapper tools (v3) -----
        // These wrappers run the dangerous operations themselves with
        // hardened flags hardcoded. They remain available for build modes
        // (audit_and_*_build*), but for default audit modes the v4
        // API-direct tools above should be used instead — they avoid
        // the on-disk source-file step entirely.

        {
            name: "zerotrust_safe_clone",
            description:
                "Hardened git clone, executed by the extension itself. Validates the URL against parseGithubUrl, resolves the ref to a SHA via `git ls-remote`, computes the canonical clone path under build_root, then runs `git clone` with the hardened security flags hardcoded (protocol.file.allow=never, no submodules, no LFS, no checkout, no symlinks, no hooks, longpaths). Returns { ok, clonePath, sha, canonicalUrl } on success or { ok: false, error } on failure.",
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
                "Run a package-manager install with safe-mode flags hardcoded. Refuses if clone_path is outside build_root or ecosystem isn't allowlisted. For npm/yarn/pnpm the wrapper enforces --ignore-scripts; for pip it enforces --only-binary=:all: --no-deps; for cargo --locked; for dotnet --locked-mode. Returns structured stdout/stderr/exitCode.",
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
                        description: "Optional additional args appended to the command. Validated against [A-Za-z0-9._=:@/\\\\-]+ to prevent injection.",
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
                "Run a build command with safe-mode flags. In council-build modes (audit_and_*_build_council), this wrapper checks the recorded council outcome and refuses to build if the council didn't pass — this is where Feature 3's 'council aborts the build' guarantee actually lives. Returns structured stdout/stderr/exitCode.",
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
                        description: "Optional additional args. Same validation as zerotrust_safe_install.",
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
                "Delete the cloned source tree (and optionally the report and quarantine subdirs) at end of audit. Refuses paths outside build_root. The packet's epilogue instructs the agent to call this as the LAST step of every audit so clones do not accumulate. By default the REPORT.md is preserved (operators usually want it); pass `also_delete_report: true` to nuke that too. Quarantine is deleted by default (downloaded binaries should never persist past the audit).",
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
                "Delete stray scratch files left at the top level of build_root and (optionally) its immediate parent dir at the end of an audit. Sub-agents are SUPPOSED to use API-direct tools (zerotrust_safe_fetch_file / zerotrust_safe_list_tree) but sometimes write source bytes or path lists to disk via PowerShell `Out-File` / `Set-Content` / `iwr -OutFile`. The `preToolUseHook` policy in enforcement.mjs would deny most of those — but the hook is not registered (see top-of-file comment) and even if it were, Copilot CLI 1.0.x does not invoke `onPreToolUse` for built-in tools — so this wrapper runs the cleanup inside the extension process where we control execution unconditionally. Only deletes top-level FILES (never directories) and skips known-good names (README, .gitignore, etc.). Pass `dry_run: true` to inspect the list before deleting. Recommended call site: as part of the audit's epilogue, AFTER zerotrust_finalize_report / zerotrust_record_council_outcome and AFTER any zerotrust_cleanup_audit you do for build modes.",
            parameters: {
                type: "object",
                properties: {
                    build_root: {
                        type: "string",
                        description: "Optional. Build_root to sweep. Defaults to the active audit's build_root or the standard build_root.",
                    },
                    also_sweep_parent: {
                        type: "boolean",
                        description: "Optional. When true (default), ALSO sweep the immediate parent directory of build_root (catches scratch files that sub-agents wrote one level up via cwd-relative paths). Pass false to limit sweeping to build_root itself.",
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
