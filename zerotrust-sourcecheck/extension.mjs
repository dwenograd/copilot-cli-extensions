// Extension: zerotrust-sourcecheck
//
// Audits a GitHub URL or local directory for source-level malicious behavior.
// Current architecture: contained API/local/build indexing, deterministic
// activation plugins, a 32-role discovery backbone, static trace/validation,
// deterministic dual-artifact finalization, and substitutional build wrappers.
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
//   - onSessionEnd cleanup is replaced by the explicit, non-destructive
//     zerotrust_close_audit lifecycle tool. Destructive cleanup wrappers run
//     first and retain trusted audit context on failure so they can be retried;
//     close_audit clears the audit/outcome Maps only after cleanup succeeds or
//     abandon_artifacts explicitly acknowledges leaving canonical artifacts.
//     Per-mode TTL inside
//     enforcement.mjs::getActiveAudit remains a secondary safety net for
//     audits that never reach close (TTL expiry deletes the audit entry
//     and dispatches clearRecordedOutcome). Worst case: a session that
//     ends without reaching close AND without further audit access
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
import { BUILD_MODE_TAXONOMY_NOTE, VALID_MODES } from "./modes.mjs";
import {
    safeCloneHandler,
    safeInstallHandler,
    safeBuildHandler,
    recordOutcomeHandler,
    finalizeReportHandler,
    cleanupAuditHandler,
    cleanupQuarantineHandler,
    sweepAuditScratchHandler,
    closeAuditHandler,
    safeListTreeHandler,
    safeFetchFileHandler,
    safeIndexSourceFileHandler,
    safeListAnalysisFactsHandler,
    safeListSourceHandler,
    recordCouncilCandidatesHandler,
    traceBehaviorGraphHandler,
    recordValidationHandler,
    safeListReleaseAssetsHandler,
    safeFetchReleaseAssetHandler,
    cacheCleanupHandler,
    cacheListHandler,
    cacheLoadHandler,
    cacheStoreHandler,
} from "./safeWrappers/index.mjs";

const CACHE_PLUGIN_VERSION_SCHEMA = {
    type: "object",
    additionalProperties: false,
    properties: {
        plugin_id: {
            type: "string",
            maxLength: 128,
            pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
        },
        plugin_version: {
            type: "string",
            maxLength: 64,
            pattern: "^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$",
        },
    },
    required: ["plugin_id", "plugin_version"],
};

const CACHE_PLUGIN_RECORD_SCHEMA = {
    type: "object",
    additionalProperties: false,
    properties: {
        pluginId: { type: "string", maxLength: 128 },
        pluginVersion: { type: "string", maxLength: 64 },
        sourceBlobs: { type: "array", maxItems: 4096, items: { type: "object" } },
        facts: { type: "array", maxItems: 20000, items: { type: "object" } },
        nodes: { type: "array", maxItems: 4096, items: { type: "object" } },
        edges: { type: "array", maxItems: 8192, items: { type: "object" } },
        findings: { type: "array", maxItems: 2048, items: { type: "object" } },
        validationDecisions: {
            type: "array",
            maxItems: 4096,
            items: { type: "object" },
        },
    },
    required: [
        "pluginId",
        "pluginVersion",
        "sourceBlobs",
        "facts",
        "nodes",
        "edges",
        "findings",
        "validationDecisions",
    ],
};

const session = await joinSession({
    tools: [
        {
            name: "zerotrust_sourcecheck",
            description:
                "Audit a GitHub URL or already-on-disk directory for source-level malicious behavior; this is not generic vulnerability or exploit scanning. Each activation emits a cryptographically random immutable audit ID used to bind council outcomes and lifecycle operations. URL wrappers do not intentionally create source files, although Copilot CLI/session logging may retain returned text; verify_release lists and downloads assets only through active-audit-bound wrappers into the canonical quarantine. Local and build-clone preparation uses exact-active-path-bound, non-executing source ingestion wrappers that do not follow reparse points and retain only bounded normalized facts. Council modes keep the 32-role discovery backbone and follow Prepare→Scan→Trace→Validate→Dedupe/score→Finalize: deterministic activation plugins seed the graph; candidates require exact indexed evidence; proof uses independent static confirm/refute/adjudication; and finalization deterministically writes REPORT.md + FINDINGS.json from trusted state and structured operator decisions. Any incomplete gate yields only incomplete. Build modes require explicit acknowledgements, but no separate prior-audit report is enforced. " +
                BUILD_MODE_TAXONOMY_NOTE +
                " Wrapper protections apply only to calls routed through the registered wrappers; no pre-tool hook intercepts raw built-in shell calls.",
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
                        enum: [...VALID_MODES],
                        description:
                            "Audit depth. Repo/tree/commit/pull URLs default to audit_source_council unless ZEROTRUST_DETERMINISTIC_ONLY=1; release URLs default to verify_release; local paths default to audit_local_source_council. Build modes require i_understand_build_executes_code. Council-build modes additionally require a recorded outcome unless the orthogonal incompleteness/severity overrides are supplied. " +
                            BUILD_MODE_TAXONOMY_NOTE,
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
                            "Required ack flag for local_path mode. Deterministic preparation is wrapper-enforced against the exact active local_path, refuses traversal and symlink/reparse following, performs no execution, and never returns source text. Council roles may still use view/grep/glob for deeper review under a separate prompt-level containment rule.",
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
                            "Required ack flag for all build modes, including audit_and_safe_build_council and audit_and_full_build_council. Install lifecycle scripts remain suppressed, but build commands may execute repo-controlled npm build scripts, build.rs, and MSBuild targets on your host.",
                    },
                    unsafe: {
                        type: "boolean",
                        default: false,
                        description:
                            "Required acknowledgement for full-build modes, in addition to i_understand_build_executes_code. Full mode currently changes admission/warning posture only and reserves a future distinction; it uses the same wrappers as safe mode and does not enable install lifecycle scripts or a less-restricted installer.",
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
                    validation_min_severity: {
                        type: "string",
                        enum: ["high", "medium", "low", "info"],
                        default: "high",
                        description:
                            "Optional (council modes only). Critical/high candidates are always statically validated. This sets the lowest additional severity entering independent confirm/refute/adjudication. Default: high.",
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
                "Resolve and bind the audit's commit (and actual release id/tag for release URLs), then enumerate its Git tree through the GitHub API. For truncated roots, pass a returned unresolved subtree_path or tree_sha; only tree identities discovered from the pinned commit are accepted. Results merge/dedupe across calls, mark every blob classificationRequired, annotate likelyBinaryByExtension only as a fetch-order hint, and expose bounded tree plus acquisitionCoverage snapshots. Required acquisition cannot complete until every enumerated blob is fetched sufficiently to classify its actual bytes and every text blob is fully scanned.",
            parameters: {
                type: "object",
                properties: {
                    url: { type: "string", description: "GitHub URL (alternative to owner/repo)" },
                    owner: { type: "string" },
                    repo: { type: "string" },
                    ref: { type: "string", description: "Branch / tag / SHA / refs/pull/N/head. Optional; defaults to active audit's pinned ref or HEAD." },
                    refType: { type: "string", enum: ["release_tag", "branch_or_tag", "pr_head", "commit"], description: "Optional; helps resolve ambiguous refs (e.g. tag vs branch with same name)." },
                    subtree_path: { type: "string", description: "Optional repo-relative subtree path returned in unresolvedSubtrees by an earlier call. Mutually exclusive with tree_sha." },
                    tree_sha: { type: "string", description: "Optional 40-char Git tree SHA returned in unresolvedSubtrees by an earlier call. It must belong to the pinned commit's discovered tree graph. Mutually exclusive with subtree_path." },
                },
            },
            handler: (args, invocation) => safeListTreeHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_fetch_file",
            description:
                "Fetch one enumerated blob at the audit's pinned SHA and account for it as mandatory deterministic acquisition or advisory council sampling. Classification uses actual fetched bytes; a .png/.exe suffix is only a likely-binary priority hint and never excludes text. Valid UTF-8 and supported UTF-16 are text. Invalid UTF-8 without trusted magic or strong binary byte evidence remains unknown/incomplete and is never lossy-decoded. Full text under any filename receives the deterministic invisible-Unicode scan. A true binary may satisfy mandatory classification with bounded metadata plus preview and no text scan. Truncated text, oversized/metadata-only, unfetchable, identity-mismatched, and council-sample-only blobs keep required acquisition incomplete; duplicate calls never inflate unique coverage.",
            parameters: {
                type: "object",
                properties: {
                    owner: { type: "string" },
                    repo: { type: "string" },
                    sha: { type: "string", description: "40-char hex SHA (commit). Use the value returned by zerotrust_safe_list_tree." },
                    path: { type: "string", description: "Forward-slash repo-relative path. No '..' / no leading slash." },
                    max_bytes: { type: "integer", minimum: 1, description: "Optional hard ceiling per call (default 5MB, max 50MB). Over-ceiling blobs return bounded metadata/preview when available and remain incomplete for mandatory coverage." },
                    max_text_bytes: { type: "integer", minimum: 1, description: "Optional inline-text cap (default 256KB, max 1MB). Text bytes under any filename over the cap are truncated with `textTruncated: true` and remain incomplete. True binaries never return full content." },
                    coverage_scope: {
                        type: "string",
                        enum: ["mandatory", "council_sample"],
                        description: "Acquisition accounting scope. Deterministic parent acquisition must use mandatory. Council-role fetches are advisory samples and must use council_sample. Defaults to council_sample in council modes and mandatory otherwise.",
                    },
                },
                required: ["owner", "repo", "sha", "path"],
            },
            handler: (args, invocation) => safeFetchFileHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_list_source",
            description:
                "Enumerate only the active audit's exact local-source root or recorded build clone without following symlinks/reparse points. Records bounded quantitative enumeration/read/index coverage, performs no execution, and returns no source text. The source root comes only from active audit state; callers cannot supply or redirect it.",
            parameters: {
                type: "object",
                properties: {
                    cursor: {
                        type: "integer",
                        minimum: 0,
                        description: "Optional zero-based cursor for the next bounded page of already-bound source entries.",
                    },
                    page_size: {
                        type: "integer",
                        minimum: 1,
                        maximum: 1000,
                        description: "Optional page size for returned source-entry metadata (default/max 1000).",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field; when supplied it must exactly match the active audit's build_root.",
                    },
                },
            },
            handler: (args, invocation) =>
                safeListSourceHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_index_source_file",
            description:
                "Read one path previously enumerated by zerotrust_safe_list_source from the active audit's exact local root or recorded build clone. Rechecks containment and every path segment without following symlinks/reparse points, performs no execution, and returns only classification, hashes, coverage, and bounded normalized facts—never source text. Advances acquired to prepared only after complete enumeration/read/index coverage.",
            parameters: {
                type: "object",
                properties: {
                    path: {
                        type: "string",
                        maxLength: 1024,
                        description: "Forward-slash source-root-relative path returned by zerotrust_safe_list_source. Traversal, absolute paths, and backslashes are refused.",
                    },
                    max_bytes: {
                        type: "integer",
                        minimum: 1,
                        maximum: 52428800,
                        description: "Optional maximum bytes to read for this file (default 5MB, absolute max 50MB). Over-cap files remain explicit preparation gaps.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field; when supplied it must exactly match the active audit's build_root.",
                    },
                },
                required: ["path"],
            },
            handler: (args, invocation) =>
                safeIndexSourceFileHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_list_analysis_facts",
            description:
                "Page through bounded normalized analysis facts only after the active API/local/build source index reaches prepared. Facts include type, repo-relative path, line bounds, excerpt SHA-256, and normalized names/values; source text and excerpts are never returned. Optional path/kind filters remain bound to the exact active audit ID.",
            parameters: {
                type: "object",
                properties: {
                    audit_id: {
                        type: "string",
                        description: "Exact immutable audit ID returned by zerotrust_sourcecheck.",
                    },
                    path: {
                        type: "string",
                        maxLength: 1024,
                        description: "Optional exact repo-relative indexed path filter.",
                    },
                    kind: {
                        type: "string",
                        enum: [
                            "manifest-key",
                            "config-key",
                            "declaration",
                            "import",
                            "execution-registration",
                            "command-construction",
                            "url",
                            "domain",
                            "sensitive-resource",
                            "source-hint",
                            "sink-hint",
                        ],
                        description: "Optional normalized fact-kind filter.",
                    },
                    cursor: {
                        type: "integer",
                        minimum: 0,
                        description: "Optional zero-based fact cursor.",
                    },
                    limit: {
                        type: "integer",
                        minimum: 1,
                        maximum: 256,
                        description: "Optional bounded page size (default/max 256).",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field; when supplied it must exactly match the active audit's build_root.",
                    },
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                safeListAnalysisFactsHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_cache_list",
            description:
                "List canonical metadata-cache entries only for the exact active audit's derived source namespace. Cache files are untrusted derived data: every listed entry is schema/integrity/canonical-JSON revalidated, corrupt regular files are discarded, and symlinks/reparse points are never followed. Cache absence is a normal successful result.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: {
                        type: "string",
                        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                    },
                    include_prior_sources: {
                        type: "boolean",
                        default: false,
                        description: "Include compatible prior source-SHA entries in the same active owner/repository namespace.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field; must exactly match the active audit build_root.",
                    },
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                cacheListHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_cache_load",
            description:
                "Load only active-identity-bound, strictly validated metadata cache records. Exact-source stage/coverage metadata may be returned; across source-SHA changes only records whose path and blob/content identity are unchanged are reusable. Plugin records require an exact requested plugin version. Verdicts, report/finalized state, source text, excerpts, prompts, credentials, and free-form model output are never cacheable.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: {
                        type: "string",
                        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{12}$",
                    },
                    plugin_versions: {
                        type: "array",
                        maxItems: 128,
                        items: CACHE_PLUGIN_VERSION_SCHEMA,
                        description: "Exact plugin ID/version pairs eligible for reuse. Unlisted or version-mismatched plugin records are omitted.",
                    },
                    include_prior_source_matches: {
                        type: "boolean",
                        default: true,
                        description: "Allow unchanged blob/content records from older source SHAs in the same active namespace. Prior-source stage/coverage is never returned.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field; must exactly match the active audit build_root.",
                    },
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                cacheLoadHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_cache_store",
            description:
                "Atomically store the active audit's normalized analysis-index hashes/facts and current compatible analysis-plugin facts/topology, plus optional strictly structured finding/validation metadata, in the canonical versioned cache under build_root. The wrapper derives all paths and source identity, enforces schema/tool compatibility and size/file-count caps, and refuses source text, snippets, prompts, credentials, verdicts, finalized report state, and arbitrary paths.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: {
                        type: "string",
                        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{12}$",
                    },
                    plugin_records: {
                        type: "array",
                        maxItems: 128,
                        items: CACHE_PLUGIN_RECORD_SCHEMA,
                        description: "Optional additional normalized plugin records (current activation-plugin records are captured automatically). The wrapper applies a stricter nested schema and rejects free-form/snippet-bearing fields.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field; must exactly match the active audit build_root.",
                    },
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                cacheStoreHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_cache_cleanup",
            description:
                "Delete only canonical metadata-cache files derived from the exact active audit identity. current_source removes one source-version entry; source_namespace removes current schema/tool-version entries for the active owner/repository or local source namespace. No raw path is accepted and no symlink/reparse point is followed.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: {
                        type: "string",
                        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{12}$",
                    },
                    scope: {
                        type: "string",
                        enum: ["current_source", "source_namespace"],
                        default: "current_source",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field; must exactly match the active audit build_root.",
                    },
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                cacheCleanupHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_record_council_candidates",
            description:
                "Audit-bound version-5 council candidate ingestion. action=submit validates and immutably records one known role/category batch of bounded structured candidate findings plus behavior-graph fragments against the current source identity and trusted analysis index. Evidence must reference enumerated paths, exact indexed line ranges, current blob/content identities, and valid excerpt hashes; source text/snippets and conflicting duplicate IDs are refused. Identical retries are idempotent. action=finalize rechecks the mandatory-role, per-category, 90%, deterministic-baseline, submission-completion, acquisition, and legal-stage gates before advancing prepared to scanned. Candidate ingestion never satisfies mandatory acquisition.",
            parameters: {
                type: "object",
                properties: {
                    action: {
                        type: "string",
                        enum: ["submit", "finalize"],
                    },
                    schemaVersion: {
                        type: "integer",
                        enum: [5],
                    },
                    audit_id: {
                        type: "string",
                        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                        description: "Immutable audit ID from the active sourcecheck packet.",
                    },
                    producer_role_id: {
                        type: "string",
                        pattern: "^[a-z][a-z0-9-]{2,63}$",
                        description: "submit only; must be a role in the active council manifest.",
                    },
                    producer_category: {
                        type: "string",
                        enum: ["A", "B", "C", "D", "E", "F", "G"],
                        description: "submit only; must match the bound producer role.",
                    },
                    source_identity: {
                        type: "object",
                        description: "submit only; exact current audit source identity.",
                        properties: {
                            kind: { type: "string", enum: ["git", "local"] },
                            owner: { type: "string" },
                            repo: { type: "string" },
                            resolved_sha: {
                                type: "string",
                                pattern: "^[a-fA-F0-9]{40}$",
                            },
                            local_path: { type: "string", maxLength: 4096 },
                        },
                    },
                    coverage_performed: {
                        type: "array",
                        maxItems: 64,
                        items: { type: "string", maxLength: 512 },
                        description: "submit only; non-empty concrete role coverage.",
                    },
                    coverage_skipped: {
                        type: "array",
                        maxItems: 64,
                        items: { type: "string", maxLength: 512 },
                        description: "submit only; bounded checks that could not be completed.",
                    },
                    candidates: {
                        type: "array",
                        maxItems: 32,
                        description: "submit only; structured candidate payloads. The wrapper derives each finding ID.",
                        items: {
                            type: "object",
                            properties: {
                                finding: {
                                    type: "object",
                                    description: "Version-5 candidate finding fields except the wrapper-derived id. Must include sourceIdentity, behaviorSignature trigger/capability/action/target, severity, confidence, maliciousProjectFit, candidate state, evidence references, exact nodeIds/edgeIds, and producer.",
                                },
                                strongestBenignHypothesis: {
                                    type: "string",
                                    maxLength: 2048,
                                },
                                coveragePerformed: {
                                    type: "array",
                                    minItems: 1,
                                    maxItems: 64,
                                    items: { type: "string", maxLength: 512 },
                                },
                                graph: {
                                    type: "object",
                                    properties: {
                                        nodes: {
                                            type: "array",
                                            minItems: 3,
                                            maxItems: 16,
                                            items: { type: "object" },
                                        },
                                        edges: {
                                            type: "array",
                                            minItems: 2,
                                            maxItems: 32,
                                            items: { type: "object" },
                                        },
                                    },
                                    required: ["nodes", "edges"],
                                },
                            },
                            required: [
                                "finding",
                                "strongestBenignHypothesis",
                                "coveragePerformed",
                                "graph",
                            ],
                        },
                    },
                    successful_role_ids: {
                        type: "array",
                        maxItems: 256,
                        items: {
                            type: "string",
                            pattern: "^[a-z][a-z0-9-]{2,63}$",
                        },
                        description: "finalize only; every successfully recorded role.",
                    },
                    failed_role_ids: {
                        type: "array",
                        maxItems: 256,
                        items: {
                            type: "string",
                            pattern: "^[a-z][a-z0-9-]{2,63}$",
                        },
                        description: "finalize only; every remaining active-manifest role.",
                    },
                    deterministic_baseline_complete: {
                        type: "boolean",
                        description: "finalize only; must be true before scanned can be recorded.",
                    },
                },
                required: ["action", "schemaVersion", "audit_id"],
            },
            handler: (args, invocation) =>
                recordCouncilCandidatesHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_trace_behavior_graph",
            description:
                "Merge the active audit's deterministic plugin graph seeds with successfully finalized council graph fragments, validate exact audit/source/evidence identity against the prepared index, and build bounded source-text-free behavior chains. Contradictory or incompatible edges are quarantined for validation rather than selected. Missing references, identity conflicts, or any graph/chain truncation keep trace coverage incomplete and prevent scanned-to-traced advancement. Identical retries are idempotent.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: {
                        type: "string",
                        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                        description: "Exact immutable audit ID returned by zerotrust_sourcecheck.",
                    },
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                traceBehaviorGraphHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_record_validation",
            description:
                "Audit-bound version-5 static validation lifecycle. prepare moves every required critical/high and configured lower-severity candidate to validating and returns paged source-text-free graph neighborhoods/facts. submit immutably records one independent confirm or refute decision using only existing chain/node/edge/evidence IDs. adjudicate records validated/refuted/unresolved without introducing evidence or topology. finalize advances traced to validated only after both sides and adjudication exist for every required candidate, with no truncation and all prior gates complete. Identical retries are idempotent; changed retries and identity/type conflicts are refused.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    action: {
                        type: "string",
                        enum: ["prepare", "submit", "adjudicate", "finalize"],
                    },
                    schemaVersion: { type: "integer", enum: [5] },
                    audit_id: {
                        type: "string",
                        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                    },
                    cursor: { type: "integer", minimum: 0 },
                    limit: { type: "integer", minimum: 1, maximum: 8 },
                    finding_id: {
                        type: "string",
                        pattern: "^ztf-v5-[a-f0-9]{64}$",
                    },
                    validator_id: { type: "string", maxLength: 128 },
                    decision_type: {
                        type: "string",
                        enum: ["confirm", "refute"],
                    },
                    conclusion: {
                        type: "string",
                        enum: [
                            "confirmed",
                            "not-confirmed",
                            "refuted",
                            "not-refuted",
                            "unresolved",
                        ],
                    },
                    adjudicator_id: { type: "string", maxLength: 128 },
                    decision: {
                        type: "string",
                        enum: ["validated", "refuted", "unresolved"],
                    },
                    severity: {
                        type: "string",
                        enum: ["critical", "high", "medium", "low", "info"],
                    },
                    confidence: {
                        type: "string",
                        enum: ["high", "medium", "low"],
                    },
                    malicious_project_fit: {
                        type: "string",
                        enum: ["unknown", "unlikely", "ambiguous", "likely", "strong"],
                    },
                    rationale_code: { type: "string", maxLength: 128 },
                    rationale: { type: "string", maxLength: 4096 },
                    chain_ids: {
                        type: "array",
                        maxItems: 64,
                        items: { type: "string", maxLength: 128 },
                    },
                    node_ids: {
                        type: "array",
                        maxItems: 64,
                        items: { type: "string", maxLength: 128 },
                    },
                    edge_ids: {
                        type: "array",
                        maxItems: 64,
                        items: { type: "string", maxLength: 128 },
                    },
                    evidence: {
                        type: "array",
                        maxItems: 64,
                        items: { type: "object" },
                    },
                    checks: { type: "object" },
                },
                required: ["action", "schemaVersion", "audit_id"],
            },
            handler: (args, invocation) =>
                recordValidationHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_list_release_assets",
            description:
                "List the assets for the already-bound verify_release identity. The wrapper accepts only the active audit's owner/repo/release ID/tag/source SHA, calls that numeric release ID without re-resolving latest or a tag, validates the response identity, and records bounded per-audit asset enumeration coverage (maximum 512 tracked unique assets).",
            parameters: {
                type: "object",
                properties: {
                    owner: { type: "string", description: "Owner returned by zerotrust_safe_list_tree; must match the active audit." },
                    repo: { type: "string", description: "Repository returned by zerotrust_safe_list_tree; must match the active audit." },
                    release_id: { type: "string", pattern: "^[1-9][0-9]{0,19}$", description: "Numeric release ID returned by zerotrust_safe_list_tree." },
                    tag_name: { type: "string", maxLength: 255, description: "Exact bound release tag returned by zerotrust_safe_list_tree." },
                    source_sha: { type: "string", pattern: "^[a-fA-F0-9]{40}$", description: "Exact full source commit SHA bound by zerotrust_safe_list_tree." },
                },
                required: ["owner", "repo", "release_id", "tag_name", "source_sha"],
            },
            handler: (args, invocation) => safeListReleaseAssetsHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_safe_fetch_release_asset",
            description:
                "Download and hash one release asset discovered by zerotrust_safe_list_release_assets. The active audit supplies all release identity and destination data; callers provide only the numeric asset ID and an optional lower byte cap. The wrapper enforces a 100 MB default/maximum, writes only <asset-id>.bin in the canonical quarantine, verifies byte counts, computes SHA-256, returns bounded magic/preview metadata, and records coverage.",
            parameters: {
                type: "object",
                properties: {
                    asset_id: { type: "string", pattern: "^[1-9][0-9]{0,19}$", description: "Numeric asset ID returned by zerotrust_safe_list_release_assets." },
                    max_bytes: { type: "integer", minimum: 1, maximum: 104857600, description: "Optional lower hard cap. Default and absolute maximum are 100 MB (104857600 bytes)." },
                    build_root: { type: "string", description: "Optional compatibility field; when supplied it must match the active audit's build_root." },
                },
                required: ["asset_id"],
            },
            handler: (args, invocation) => safeFetchReleaseAssetHandler(args, { sessionId: invocation?.sessionId }),
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
                "Run one allowlisted dependency operation against the active clone: npm ci, npm install, yarn install, pnpm install, pip install, cargo fetch, or dotnet restore with hardcoded safety flags. Safe/full modes use this same installer and install lifecycle scripts remain suppressed. extra_args are flag tokens only; positional packages/URLs/paths, redirects, traversal, and safety-negating options are refused. Option values must use a single --flag=value token rather than a split positional value.",
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
                "Run an allowlisted build command against the active clone. Safe/full modes use the same build implementation, and repo-controlled npm build scripts, build.rs, or MSBuild targets may execute in either mode. Council-build modes require an outcome whose audit ID, owner, repo, and resolved SHA exactly match the current audit; proceed_on_council_failure bypasses only incompleteness and council_build_override bypasses only severity.",
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
                "Record the council's immutable verdict for the current audit ID. audit_id must exactly match the active sourcecheck packet; delayed outcomes and replacement outcomes are refused. The stored identity also binds owner/repo/full resolved SHA. Complete outcomes from sourcecheck-activated council manifests require successful candidate submission, graph tracing, and independent confirm/refute/adjudication at analysis stage validated or later. Every council mode must call this before report finalization; council-build modes must do so before safe_build. API-direct trusted verdicts are refused unless mandatory acquisition coverage is complete.",
            parameters: {
                type: "object",
                properties: {
                    audit_id: {
                        type: "string",
                        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                        description: "Immutable cryptographically-random audit ID printed in the current zerotrust_sourcecheck packet/runtimeContext. Must match exactly.",
                    },
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
                required: ["audit_id", "verdict", "critical_count", "high_count", "complete"],
            },
            handler: (args, invocation) => recordOutcomeHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_finalize_report",
            description:
                "Finalize the canonical REPORT.md + FINDINGS.json pair exactly once through the active audit identity and return canonical reportPath/findingsPath values. v5 council flows deterministically render both artifacts from the trusted ledger/decision/graph/validation/remediation snapshot and accept only structured operator decision records; model-authored report prose is refused. Legacy non-council flows may still supply markdown_body and remain trusted:false outside the v5 privacy guarantee. Both files use exclusive same-directory publication with rollback where possible, are hashed and recorded together, and same-audit retries verify and return the existing pair without rewriting. Unrecorded pre-existing files fail closed. Trusted council verdicts require validated stage and every existing acquisition/release/council/trace/validation gate; incomplete output preserves exact blockers. validated advances to finalized only after both artifacts are durable and recorded.",
            parameters: {
                type: "object",
                properties: {
                    owner: {
                        type: "string",
                        description: "URL audits only. Repo owner; must match the active audit's pinned owner (case-insensitive). Omit for local-source audits.",
                    },
                    repo: {
                        type: "string",
                        description: "URL audits only. Repo name; must match the active audit's pinned repo (case-insensitive). Omit for local-source audits.",
                    },
                    resolved_sha: {
                        type: "string",
                        pattern: "^[a-fA-F0-9]{40}$",
                        description: "URL audits only. Full 40-character resolved commit SHA; must match active trusted state and is included in the canonical hashed artifact identity. Omit for local-source audits.",
                    },
                    markdown_body: {
                        type: "string",
                        maxLength: 1048576,
                        description: "Legacy non-council compatibility only. Complete in-memory Markdown draft. v5 council finalization rejects this field so model-authored finding tables or verdicts cannot conflict with the trusted ledger.",
                    },
                    operator_decisions: {
                        type: "array",
                        maxItems: 512,
                        description: "v5 council flows only. Optional source-text-free operator/remediation decision records. Each record references one canonical finding ID and uses predefined action/rationale categories. operator_rationale is a short explicitly user-supplied one-line exception and is rejected if it resembles code, a URL, an encoded token, a finding/verdict claim, or known source-derived text.",
                        items: {
                            type: "object",
                            properties: {
                                finding_id: {
                                    type: "string",
                                    description: "Canonical finding ID from the trusted decision snapshot.",
                                },
                                action: {
                                    type: "string",
                                    enum: ["defanged", "kept-as-is", "delete-project", "investigate", "no-action"],
                                },
                                rationale_category: {
                                    type: "string",
                                    enum: ["remediation-applied", "accepted-risk", "required-functionality", "false-positive-suspected", "deferred-review", "project-deleted", "alternate-path-remains", "graph-incomplete", "other"],
                                },
                                operator_rationale: {
                                    type: "string",
                                    maxLength: 240,
                                    description: "Optional one-line rationale authored by the human operator. Never use model-authored text here.",
                                },
                            },
                            required: ["finding_id", "action", "rationale_category"],
                            additionalProperties: false,
                        },
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field. When supplied it must exactly match the active audit's trusted build_root; it never selects a report destination.",
                    },
                },
            },
            handler: (args, invocation) => finalizeReportHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_cleanup_audit",
            description:
                "Delete only the current active build audit's recorded hashed-identity clone path, with exact session/path binding. A real sessionId, active build mode, and recorded resolved clone path are mandatory; no no-session or custom-root compatibility exists. Report is kept by default; matching quarantine is deleted by default. Failures leave the audit open for retry.",
            parameters: {
                type: "object",
                properties: {
                    clone_path: {
                        type: "string",
                        description: "Exact absolute hashed-identity clone path returned by zerotrust_safe_clone; must match active recorded state.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional compatibility field. If supplied, it must exactly match the active audit's trusted build_root and never selects a deletion root.",
                    },
                    also_delete_report: {
                        type: "boolean",
                        description: "Optional. When true, also delete the matching <build_root>\\_reports\\<basename>\\ directory. Defaults to false (keep the canonical REPORT.md + FINDINGS.json pair).",
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
            name: "zerotrust_cleanup_quarantine",
            description:
                "Delete the canonical verify_release quarantine directory derived from the active audit's trusted build root and resolved SHA. No raw path is accepted. Missing quarantine is an idempotent success; deletion failures leave audit state active for retry.",
            parameters: {
                type: "object",
                properties: {
                    build_root: {
                        type: "string",
                        description: "Optional. Must match the active audit's build_root when supplied.",
                    },
                },
                required: [],
            },
            handler: (args, invocation) => cleanupQuarantineHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_sweep_audit_scratch",
            description:
                "Delete unrecognized top-level files in build_root and optionally its immediate parent. Parent sweeping defaults off because the parent may contain unrelated files; dry-run before explicitly enabling it. It never deletes directories. Failures leave audit state active for retry.",
            parameters: {
                type: "object",
                properties: {
                    build_root: {
                        type: "string",
                        description: "Optional. Build_root to sweep. Defaults to the active audit's build_root or the standard build_root.",
                    },
                    also_sweep_parent: {
                        type: "boolean",
                        description: "Optional. Default false. When true, also sweep the immediate parent; dry-run first because the finite whitelist may not cover unrelated parent files.",
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

        {
            name: "zerotrust_close_audit",
            description:
                "Cleanup-aware lifecycle close. Refuses while an active build clone or verify_release quarantine still exists, preserving cleanup authority. Pass abandon_artifacts:true only to intentionally leave listed artifacts on disk and relinquish that authority. Artifact-free/API/local/metadata audits are idempotently closable.",
            parameters: {
                type: "object",
                properties: {
                    abandon_artifacts: {
                        type: "boolean",
                        default: false,
                        description: "Explicit acknowledgement that closure should intentionally leave any listed canonical clone/quarantine artifacts on disk and relinquish active cleanup authority.",
                    },
                },
                required: [],
            },
            handler: (args, invocation) => closeAuditHandler(args, { sessionId: invocation?.sessionId }),
        },
    ],
    // Intentionally no `hooks: {}` block — see top-of-file comment. We do
    // not register onPreToolUse or onSessionEnd because doing so would
    // require the operator to grant the "register hooks" elevated
    // permission (a capability class that allows seeing every tool input,
    // modifying tool inputs, and running arbitrary code on every
    // invocation) for no actual benefit under the current runtime.
});
