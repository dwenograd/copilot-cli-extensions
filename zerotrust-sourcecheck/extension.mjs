// Extension: zerotrust-sourcecheck
//
// Audits a GitHub URL or local directory for source-level malicious behavior.
// Current architecture: contained API/local/build indexing, deterministic
// activation plugins, a 32-role discovery backbone, static trace/validation,
// deterministic dual-artifact finalization, and substitutional build wrappers.
//
// IMPORTANT — no `hooks: {}` registration (operator-elevated-permissions
// minimization): an earlier implementation registered an onPreToolUse hook
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
//     close_audit clears active audit state only after cleanup succeeds or
//     abandon_artifacts explicitly acknowledges leaving canonical artifacts.
//     Per-mode TTL inside
//     enforcement.mjs::getActiveAudit remains a secondary safety net for
//     audits that never reach close (TTL expiry deletes the audit entry
//     and discards expired audit state). Worst case: a session that
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
//   - handler.mjs: URL parsing, mode resolution, scrub, council dispatch, packet build entry
//   - modes.mjs: single source of truth for mode taxonomy + helpers
//   - urlParser.mjs: pure URL/owner/repo/ref/path validation
//   - enforcement.mjs: audit-in-progress state machine (activate/getActive/deactivate) used by the wrappers; also exports the unregistered preToolUseHook for tests and future re-wiring
//   - packet.mjs: the natural-language playbook the agent executes
//   - council/: 32-role roster + universal prompt template + extra-roles validator
//   - safeWrappers/: substitutional-safety tools

import { joinSession } from "@github/copilot-sdk/extension";
import { runHandler } from "./handler.mjs";
import { BUILD_MODE_TAXONOMY_NOTE, VALID_MODES } from "./modes.mjs";
import {
    safeCloneHandler,
    safeInstallHandler,
    safeBuildHandler,
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
    safeListReleaseAssetsHandler,
    safeFetchReleaseAssetHandler,
    cacheCleanupHandler,
    cacheListHandler,
    cacheLoadHandler,
    cacheStoreHandler,
    assignSemanticReviewHandler,
    getSemanticCoverageHandler,
    prepareSemanticCoverageHandler,
    recordSemanticReviewHandler,
    recordSemanticScannerHandler,
    safeAnalyzeDependenciesHandler,
    safeInventoryDependenciesHandler,
    assignRedTeamHandler,
    finalizeRedTeamHandler,
    getRedTeamHandler,
    prepareRedTeamHandler,
    recordRedTeamReviewHandler,
    getEvasiveGraphHandler,
    prepareEvasiveGraphHandler,
    traceEvasiveGraphHandler,
    finalizeAssuranceValidationHandler,
    prepareAssuranceValidationHandler,
    recordAssuranceValidationHandler,
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

const AUDIT_ID_SCHEMA = {
    type: "string",
    pattern:
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
};

const OBJECT_ID_SCHEMA = {
    type: "string",
    pattern: "^zto-[a-f0-9]{64}$",
};

const ARTIFACT_IDS_SCHEMA = {
    type: "array",
    maxItems: 64,
    uniqueItems: true,
    items: {
        type: "string",
        pattern: "^zta-[a-f0-9]{64}$",
    },
};

const SEMANTIC_CHECKS_SCHEMA = {
    type: "object",
    additionalProperties: false,
    properties: {
        activationAndEntryPoints: {
            type: "string",
            enum: ["checked", "not-applicable", "unresolved"],
        },
        dataflowSourcesTransformsSinks: {
            type: "string",
            enum: ["checked", "not-applicable", "unresolved"],
        },
        dynamicExecutionAndIndirection: {
            type: "string",
            enum: ["checked", "not-applicable", "unresolved"],
        },
        environmentTimeStateGates: {
            type: "string",
            enum: ["checked", "not-applicable", "unresolved"],
        },
        generatedAndDecodedContent: {
            type: "string",
            enum: ["checked", "not-applicable", "unresolved"],
        },
        externalPayloads: {
            type: "string",
            enum: ["checked", "not-applicable", "unresolved"],
        },
        buildAndWorkflowHooks: {
            type: "string",
            enum: ["checked", "not-applicable", "unresolved"],
        },
        dependencyResolution: {
            type: "string",
            enum: ["checked", "not-applicable", "unresolved"],
        },
    },
    required: [
        "activationAndEntryPoints",
        "dataflowSourcesTransformsSinks",
        "dynamicExecutionAndIndirection",
        "environmentTimeStateGates",
        "generatedAndDecodedContent",
        "externalPayloads",
        "buildAndWorkflowHooks",
        "dependencyResolution",
    ],
};

const DEPENDENCY_MANIFEST_SCHEMA = {
    type: "object",
    additionalProperties: false,
    properties: {
        path: { type: "string", maxLength: 4096 },
        content: { type: "string", maxLength: 8388608 },
        content_sha256: {
            type: "string",
            pattern: "^[a-fA-F0-9]{64}$",
        },
    },
    required: ["path", "content", "content_sha256"],
};

const DEPENDENCY_LIMITS_SCHEMA = {
    type: "object",
    additionalProperties: false,
    properties: {
        maxDepth: { type: "integer", minimum: 0, maximum: 8 },
        maxPackages: { type: "integer", minimum: 1, maximum: 512 },
        maxRequests: { type: "integer", minimum: 1, maximum: 128 },
        maxRedirects: { type: "integer", minimum: 0, maximum: 2 },
        requestTimeoutMs: { type: "integer", minimum: 1, maximum: 15000 },
        maxResponseBytes: { type: "integer", minimum: 1, maximum: 16777216 },
        maxTotalBytes: { type: "integer", minimum: 1, maximum: 67108864 },
        maxArchiveEntries: { type: "integer", minimum: 1, maximum: 2048 },
        maxArchiveDepth: { type: "integer", minimum: 0, maximum: 4 },
        maxScannedTextBytes: { type: "integer", minimum: 1, maximum: 8388608 },
        maxFacts: { type: "integer", minimum: 1, maximum: 20000 },
    },
};

const session = await joinSession({
    tools: [
        {
            name: "zerotrust_sourcecheck",
            description:
                "Audit a GitHub URL or already-on-disk directory for source-level malicious behavior; this is not generic vulnerability or exploit scanning. Every activation owns one current assurance lifecycle: acquisition, object inventory and decoding, dependency analysis, deterministic semantic scanning, assignment-bound model semantic review, 32-role council discovery where selected, mandatory evasive red-team categories, exhaustive evasive graph tracing, independent assurance validation, remediation decisions, and deterministic REPORT.md + FINDINGS.json finalization. Each activation emits a cryptographically random immutable audit ID binding all state and artifacts. URL wrappers do not intentionally create source files, although Copilot CLI/session logging may retain returned text; verify_release assets are confined to the canonical quarantine. Local and build-clone ingestion is exact-path-bound, non-executing, reparse-safe, and source-text-free. Any incomplete required stage yields incomplete assurance. Build modes require explicit acknowledgements and a durable identity-matching finalized assurance report before hazardous host execution. " +
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
                            "Audit depth. Repo/tree/commit/pull URLs default to audit_source_council; release URLs default to verify_release; local paths default to audit_local_source_council. Modes without the 32-role discovery council still run required semantic and evasive model coverage. Build modes require i_understand_build_executes_code and a durable identity-matching finalized assurance report before hazardous post-audit host execution. " +
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
                            "Required ack flag for all build modes, including audit_and_safe_build_council and audit_and_full_build_council. Install lifecycle scripts remain suppressed, but hazardous post-audit host execution may run repo-controlled npm build scripts, build.rs, and MSBuild targets on your host.",
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
                },
                required: [],
            },
            handler: (args, invocation) =>
                runHandler(args, {
                    sessionId: invocation?.sessionId,
                    log: (msg) => session.log(msg),
                }),
        },

        // ----- API-direct audit tools for non-build modes -----
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
            name: "zerotrust_inventory_dependencies",
            description:
                "Parse exact active-audit-bound dependency lockfile bytes without network access or execution. Supports npm package-lock/npm-shrinkwrap, Cargo.lock, hashed requirements/Poetry/Pipfile locks, NuGet packages.lock.json/packages.config, and Git/local dependency forms. Returns an audit-bound package/provenance graph with exact versions, sources, integrity, aliases, local paths, mutable refs, and lifecycle/build-hook declarations. Missing integrity, mutable refs, unsupported registries, unresolved transitives, and caps are blockers.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    manifests: {
                        type: "array",
                        minItems: 1,
                        maxItems: 32,
                        items: DEPENDENCY_MANIFEST_SCHEMA,
                    },
                    limits: DEPENDENCY_LIMITS_SCHEMA,
                    build_root: {
                        type: "string",
                        description:
                            "Optional compatibility field; must exactly match the active audit build_root.",
                    },
                },
                required: ["audit_id", "manifests"],
            },
            handler: (args, invocation) =>
                safeInventoryDependenciesHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_analyze_dependencies",
            description:
                "Build and statically analyze the exact active-audit dependency closure without package managers, scripts, external libraries, registry CLIs, disk writes, or dependency execution. Metadata/artifact URLs are derived from bound lockfiles and fetched only with Node HTTPS from strict registry hosts under redirect/time/size/request/depth caps. Declared integrity is verified before in-memory tgz/tar/zip/wheel/nupkg/crate reading and existing language scanning. Hash mismatch, fetch failure, missing integrity, unsupported registry, mutable refs, or recursion caps remain blockers. Exact matching current object snapshots receive dependency-graph derived artifacts.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    manifests: {
                        type: "array",
                        minItems: 1,
                        maxItems: 32,
                        items: DEPENDENCY_MANIFEST_SCHEMA,
                    },
                    limits: DEPENDENCY_LIMITS_SCHEMA,
                    build_root: {
                        type: "string",
                        description:
                            "Optional compatibility field; must exactly match the active audit build_root.",
                    },
                },
                required: ["audit_id", "manifests"],
            },
            handler: (args, invocation) =>
                safeAnalyzeDependenciesHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_prepare_semantic_coverage",
            description:
                "Bind the active decoded snapshot to deterministic object classifications, scanner shards, model-review shards, and the complete set of source-text-free prompt normalized views. The plan is immutable and idempotent; missing prompt assessments remain explicit semantic blockers.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    normalized_views_json: {
                        type: "string",
                        maxLength: 8388608,
                        description:
                            "JSON array containing every validated prompt normalized view required by executable/config subjects. Use [] only when the plan has no such subjects.",
                    },
                    scanner_shard_count: {
                        type: "integer",
                        minimum: 1,
                        maximum: 256,
                        default: 16,
                    },
                    model_shard_count: {
                        type: "integer",
                        minimum: 1,
                        maximum: 256,
                        default: 16,
                    },
                },
                required: ["audit_id", "normalized_views_json"],
            },
            handler: (args, invocation) =>
                prepareSemanticCoverageHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_record_semantic_scanner",
            description:
                "Record one immutable scanner result against an exact deterministic scanner assignment/token and object or derived-artifact identity. Truncation and scanner blockers remain incomplete; retries are idempotent and replacement records are refused.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    assignment_id: {
                        type: "string",
                        pattern: "^ztsa-[a-f0-9]{64}$",
                    },
                    assignment_token: {
                        type: "string",
                        pattern: "^ztst-[a-f0-9]{64}$",
                    },
                    scanner_result_json: {
                        type: "string",
                        maxLength: 8388608,
                        description:
                            "Exact JSON object returned by the trusted scanner for the assigned path/content identity.",
                    },
                },
                required: [
                    "audit_id",
                    "assignment_id",
                    "assignment_token",
                    "scanner_result_json",
                ],
            },
            handler: (args, invocation) =>
                recordSemanticScannerHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_assign_semantic_review",
            description:
                "Issue and immutably store one wrapper-bound model semantic-review assignment for a deterministic model shard, only after every assigned scanner subject has an immutable record. The assignment embeds a strict source-text-free semanticView containing normalized scanner facts, unresolved targets/blockers, derived-artifact metadata, and all eight check bases. High-risk subjects expose two slots and require distinct reviewer IDs. Prompt-affected assignments also embed the normalized-view review contract.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    object_id: OBJECT_ID_SCHEMA,
                    reviewer_slot: {
                        type: "integer",
                        minimum: 1,
                        maximum: 2,
                    },
                    reviewer_id: {
                        type: "string",
                        maxLength: 128,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                    },
                    reviewer_version: {
                        type: "string",
                        maxLength: 64,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$",
                    },
                },
                required: [
                    "audit_id",
                    "object_id",
                    "reviewer_slot",
                    "reviewer_id",
                    "reviewer_version",
                ],
            },
            handler: (args, invocation) =>
                assignSemanticReviewHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_record_semantic_review",
            description:
                "Record one immutable wrapper-issued semantic review. Findings must be bounded structured candidates with behavior, severity, confidence, malicious-project fit, benign-hypothesis code, and exact assignment-bound object/artifact/fact/evidence identities; the wrapper derives candidate IDs. Completed reviews bind the exact semanticView ID/hash and review every assigned fact/artifact. Empty findings retain the exact negative-evidence contract. Duplicate retries/candidates never inflate the semantic candidate ledger.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    assignment_id: {
                        type: "string",
                        pattern: "^ztsma-[a-f0-9]{64}$",
                    },
                    assignment_token: {
                        type: "string",
                        pattern: "^ztsmt-[a-f0-9]{64}$",
                    },
                    reviewer_id: {
                        type: "string",
                        maxLength: 128,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                    },
                    object_id: OBJECT_ID_SCHEMA,
                    artifact_ids: ARTIFACT_IDS_SCHEMA,
                    semantic_view_id: {
                        type: "string",
                        pattern: "^ztsv-[a-f0-9]{64}$",
                    },
                    semantic_view_sha256: {
                        type: "string",
                        pattern: "^[a-f0-9]{64}$",
                    },
                    reviewed_fact_ids: {
                        type: "array",
                        maxItems: 8192,
                        uniqueItems: true,
                        items: {
                            type: "string",
                            pattern: "^[a-f0-9]{64}$",
                        },
                    },
                    reviewed_artifact_ids: ARTIFACT_IDS_SCHEMA,
                    decision: {
                        type: "string",
                        enum: ["findings-recorded", "no-findings", "incomplete"],
                    },
                    checks: SEMANTIC_CHECKS_SCHEMA,
                    negative_evidence_codes: {
                        type: "array",
                        maxItems: 8,
                        uniqueItems: true,
                        items: {
                            type: "string",
                            enum: [
                                "no-activation-path-supported",
                                "no-source-transform-sink-chain-supported",
                                "no-dynamic-execution-supported",
                                "no-environment-time-state-gate-supported",
                                "no-generated-or-decoded-payload-supported",
                                "no-external-payload-supported",
                                "no-build-workflow-hook-supported",
                                "no-dependency-substitution-supported",
                            ],
                        },
                    },
                    candidates: {
                        type: "array",
                        maxItems: 64,
                        items: {
                            type: "object",
                            additionalProperties: false,
                            properties: {
                                behavior: {
                                    type: "object",
                                    additionalProperties: false,
                                    properties: {
                                        trigger: {
                                            type: "string",
                                            maxLength: 128,
                                            pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                                        },
                                        capability: {
                                            type: "string",
                                            maxLength: 128,
                                            pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                                        },
                                        action: {
                                            type: "string",
                                            maxLength: 128,
                                            pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                                        },
                                        target: {
                                            type: "string",
                                            maxLength: 128,
                                            pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                                        },
                                    },
                                    required: ["trigger", "capability", "action", "target"],
                                },
                                severity: {
                                    type: "string",
                                    enum: ["info", "low", "medium", "high", "critical"],
                                },
                                confidence: {
                                    type: "string",
                                    enum: ["low", "medium", "high"],
                                },
                                maliciousProjectFit: {
                                    type: "string",
                                    enum: [
                                        "unknown",
                                        "unlikely",
                                        "ambiguous",
                                        "likely",
                                        "strong",
                                    ],
                                },
                                benignHypothesisCode: {
                                    type: "string",
                                    enum: [
                                        "expected-build-or-runtime-behavior",
                                        "test-or-development-only",
                                        "user-initiated-operation",
                                        "standard-dependency-resolution",
                                        "generated-code-pipeline",
                                        "platform-compatibility",
                                        "insufficient-context",
                                        "no-benign-hypothesis",
                                    ],
                                },
                                objectIds: {
                                    type: "array",
                                    minItems: 1,
                                    maxItems: 1,
                                    uniqueItems: true,
                                    items: OBJECT_ID_SCHEMA,
                                },
                                artifactIds: ARTIFACT_IDS_SCHEMA,
                                factIds: {
                                    type: "array",
                                    maxItems: 64,
                                    uniqueItems: true,
                                    items: {
                                        type: "string",
                                        pattern: "^[a-f0-9]{64}$",
                                    },
                                },
                                evidenceIds: {
                                    type: "array",
                                    minItems: 1,
                                    maxItems: 64,
                                    uniqueItems: true,
                                    items: {
                                        type: "string",
                                        pattern: "^ztre-[a-f0-9]{64}$",
                                    },
                                },
                            },
                            required: [
                                "behavior",
                                "severity",
                                "confidence",
                                "maliciousProjectFit",
                                "benignHypothesisCode",
                                "objectIds",
                                "artifactIds",
                                "factIds",
                                "evidenceIds",
                            ],
                        },
                    },
                    blocker_codes: {
                        type: "array",
                        maxItems: 2,
                        uniqueItems: true,
                        items: {
                            type: "string",
                            enum: ["semantic/incomplete", "semantic/truncated"],
                        },
                    },
                    prompt_review_json: {
                        type: "string",
                        maxLength: 8388608,
                        description:
                            "Required only when the assignment embeds a prompt normalized-view assignment; encode the exact structured prompt review record.",
                    },
                },
                required: [
                    "audit_id",
                    "assignment_id",
                    "assignment_token",
                    "reviewer_id",
                    "object_id",
                    "artifact_ids",
                    "semantic_view_id",
                    "semantic_view_sha256",
                    "reviewed_fact_ids",
                    "reviewed_artifact_ids",
                    "decision",
                    "checks",
                    "negative_evidence_codes",
                    "candidates",
                    "blocker_codes",
                ],
            },
            handler: (args, invocation) =>
                recordSemanticReviewHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_get_semantic_coverage",
            description:
                "Read the active audit's semantic plan, immutable scanner/reviewer records, deterministic structured semantic candidate ledger, coverage evaluation, snapshot binding, and current assurance stage. Returns no source text.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                getSemanticCoverageHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_prepare_red_team",
            description:
                "Prepare the evasive red-team stage from an exact completed semantic plan/evaluation. The wrapper deterministically creates the source-text-free initial discovery handoff, graph/artifact/dependency views, all nine mandatory category plans, inserts the red-team incompleteness blocker, and owns the persisted semantically-covered→scanned transition. No caller completeness boolean is accepted.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                prepareRedTeamHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_assign_red_team_review",
            description:
                "Issue one immutable wrapper-bound evasive red-team assignment for a mandatory category. The assignment binds the active audit, scanned snapshot, semantic plan/evaluation, initial discovery handoff, supply-chain identity, exact subjects, normalized semantic views, graph/artifact/dependency metadata, falsification checks, and negative-evidence contract. Same-reviewer/model limits must use the exact procedural enum derived by the wrapper.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    category_id: {
                        type: "string",
                        enum: [
                            "split-cross-file-chains",
                            "dormant-env-time-platform-gates",
                            "generated-decoded-code",
                            "dependency-staging-substitution",
                            "source-release-divergence",
                            "binary-archive-concealment",
                            "benign-decoy-alternate-path",
                            "prompt-reviewer-manipulation",
                            "dynamic-external-payload-loading",
                        ],
                    },
                    reviewer_id: {
                        type: "string",
                        maxLength: 128,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                    },
                    reviewer_version: {
                        type: "string",
                        maxLength: 64,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$",
                    },
                    model_id: {
                        type: "string",
                        maxLength: 128,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                    },
                },
                required: [
                    "audit_id",
                    "category_id",
                    "reviewer_id",
                    "reviewer_version",
                    "model_id",
                ],
            },
            handler: (args, invocation) =>
                assignRedTeamHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_record_red_team_review",
            description:
                "Record one immutable wrapper-issued evasive red-team review and admit any new evidence-bound candidates into the red-team candidate ledger before trace. Empty category results require exact complete subject arrays, every assigned falsification check, the exact category negative-evidence codes, unchanged canary/output markers, and no blockers. Unknown fields, free-form source text, identity substitution, changed retries, and narrative-only coverage are refused.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    assignment_id: {
                        type: "string",
                        pattern: "^ztra-[a-f0-9]{64}$",
                    },
                    review_json: {
                        type: "string",
                        maxLength: 8388608,
                        description:
                            "Exact JSON object emitted from the wrapper assignment contract. Candidate IDs are omitted and derived by the wrapper.",
                    },
                },
                required: ["audit_id", "assignment_id", "review_json"],
            },
            handler: (args, invocation) =>
                recordRedTeamReviewHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_get_red_team",
            description:
                "Read the active audit's red-team plan, wrapper assignments, immutable review records, deterministic category/90%/mandatory gates, source-text-free candidate ledger, blockers, current stage, and snapshot.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                getRedTeamHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_finalize_red_team",
            description:
                "Deterministically finalize evasive red-team coverage. The wrapper accepts no caller completeness boolean: all nine mandatory categories, immutable assignments/reviews, exact empty-result proof, at least 90% assignment coverage, no truncation, and no blockers are recomputed from trusted state. Only a complete result removes the red-team blocker and advances scanned→red-teamed; otherwise the stage remains scanned and exact blockers are returned.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                finalizeRedTeamHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_prepare_evasive_graph",
            description:
                "Prepare the evasive behavior graph from the exact red-teamed snapshot and trusted semantic scanner facts, derived artifacts, supply-chain graph, immutable semantic candidate ledger, and separate red-team candidate ledger. Exact object/artifact/fact/evidence identities and submitted severity are preserved. Unordered endpoint/kind contradiction buckets quarantine every direction variant and retain all competing records. No caller graph or completeness claim is accepted.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                prepareEvasiveGraphHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_trace_evasive_graph",
            description:
                "Exhaustively trace every activation/trigger root and alternate path in the prepared graph. Benign branches never suppress alternate effect paths. Dynamic or unsupported targets, missing targets, quarantined conflicts, cycles, caps, and truncation remain blockers. The wrapper recomputes all gates and alone may advance red-teamed→traced.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                traceEvasiveGraphHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_get_evasive_graph",
            description:
                "Read the active audit's immutable evasive graph plan, quarantined contradiction records, exhaustive trace, blockers, current stage, and bound snapshot. Returns source-text-free identities only.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                getEvasiveGraphHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_prepare_assurance_validation",
            description:
                "Prepare assurance validation from the exact complete trace. With no active findings, issue one wrapper-token-bound no-finding proof assignment covering semantic coverage, all red-team categories, supply chain, unsupported objects, alternate paths, dynamic targets, activation roots, and truncation. With findings, issue independent confirm/refute assignments for every active severity. No caller completeness boolean is accepted.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    no_finding_validator_id: {
                        type: "string",
                        maxLength: 128,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                    },
                    confirm_validator_id: {
                        type: "string",
                        maxLength: 128,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                    },
                    refute_validator_id: {
                        type: "string",
                        maxLength: 128,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$",
                    },
                    validator_version: {
                        type: "string",
                        maxLength: 64,
                        pattern: "^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$",
                    },
                },
                required: [
                    "audit_id",
                    "no_finding_validator_id",
                    "confirm_validator_id",
                    "refute_validator_id",
                    "validator_version",
                ],
            },
            handler: (args, invocation) =>
                prepareAssuranceValidationHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_record_assurance_validation",
            description:
                "Record one immutable wrapper-issued assurance decision. Records must bind the exact assignment token and assigned independent validator, may reference only existing graph/trace/evidence/basis identities, and cannot introduce evidence or topology. Changed retries and identity substitution are refused.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                    assignment_id: {
                        type: "string",
                        pattern: "^ztava-[a-f0-9]{64}$",
                    },
                    record_json: {
                        type: "string",
                        maxLength: 33554432,
                        description:
                            "Strict JSON record matching the wrapper assignment. Required fields: assignmentToken, validatorId, conclusion, reviewedNodeIds, reviewedEdgeIds, reviewedPathIds, reviewedEvidenceIds, reviewedBasisIds, checks, negativeEvidenceCodes, blockerCodes.",
                    },
                },
                required: ["audit_id", "assignment_id", "record_json"],
            },
            handler: (args, invocation) =>
                recordAssuranceValidationHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_finalize_assurance_validation",
            description:
                "Recompute no-finding or all-severity candidate validation from immutable assignments and records. No-finding proof is separate from candidate confirm/refute. Only complete, independent, identity-bound, untruncated validation with no unresolved outcomes advances traced→validated; otherwise exact blockers remain.",
            parameters: {
                type: "object",
                additionalProperties: false,
                properties: {
                    audit_id: AUDIT_ID_SCHEMA,
                },
                required: ["audit_id"],
            },
            handler: (args, invocation) =>
                finalizeAssuranceValidationHandler(args, {
                    sessionId: invocation?.sessionId,
                }),
        },

        {
            name: "zerotrust_cache_list",
            description:
                "List canonical metadata-cache entries for the exact active source namespace. Cache files are untrusted derived data: every entry is schema/integrity/canonical-JSON revalidated, corrupt regular files are discarded, and symlinks/reparse points are never followed. Cache records never supply assurance coverage, verdicts, report state, or finalization state.",
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
                "Load active-identity-bound, strictly validated metadata cache records. Across source-SHA changes only records whose path and blob/content identity are unchanged are reusable. Plugin records require an exact requested plugin version. Assurance coverage, verdicts, report/finalized state, source text, excerpts, prompts, credentials, and free-form model output are never cacheable.",
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
                "Atomically store the active audit's normalized analysis-index hashes/facts and compatible analysis-plugin facts/topology in the canonical metadata cache under build_root. The wrapper derives all paths and source identity, enforces schema/tool compatibility and size/file-count caps, and refuses source text, snippets, prompts, credentials, assurance coverage, verdicts, finalized report state, and arbitrary paths.",
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
                "Delete canonical metadata-cache files derived from the exact active audit identity. current_source removes one source-identity entry; source_namespace removes compatible schema/tool entries for the active owner/repository or local source namespace. No raw path is accepted and no symlink/reparse point is followed.",
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
                "Audit-bound council discovery candidate ingestion. action=submit validates and immutably records one known role/category batch of bounded structured candidate findings plus behavior-graph fragments against the current source identity and trusted analysis index. Evidence must reference enumerated paths, exact indexed line ranges, current blob/content identities, and valid excerpt hashes; source text/snippets and conflicting duplicate IDs are refused. Identical retries are idempotent. Candidate ingestion is discovery-only: there is no council finalize/verdict action, and submissions never satisfy mandatory acquisition, semantic coverage, red-team coverage, trace, validation, or finalization.",
            parameters: {
                type: "object",
                properties: {
                    action: {
                        type: "string",
                        enum: ["submit"],
                    },
                    schemaVersion: {
                        type: "integer",
                        enum: [5],
                        description:
                            "Strict candidate-batch contract metadata; not a workflow selector.",
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
                                    description: "Strict candidate finding fields except the wrapper-derived id. Must include sourceIdentity, behaviorSignature trigger/capability/action/target, severity, confidence, maliciousProjectFit, candidate state, evidence references, exact nodeIds/edgeIds, and producer.",
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
                },
                required: ["action", "schemaVersion", "audit_id"],
            },
            handler: (args, invocation) =>
                recordCouncilCandidatesHandler(args, { sessionId: invocation?.sessionId }),
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
        // (audit_and_*_build*), while non-build audit modes use the
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
                "Run hazardous post-audit host execution against the active clone through an allowlisted build command. Safe/full mode names are compatibility aliases for the same implementation. A durable identity-matching finalized assurance report with a finalizer-derived trusted outcome is mandatory. Incomplete assurance and supported critical/high malicious behavior are refused. No caller bypass exists, and build output is never assurance evidence.",
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
                        description: "Optional advisory mode metadata. Trusted active-audit mode and the finalized-report host gate are authoritative.",
                    },
                    build_root: {
                        type: "string",
                        description: "Optional. Build_root containment bound.",
                    },
                },
                required: ["ecosystem", "clone_path"],
                additionalProperties: false,
            },
            handler: (args, invocation) => safeBuildHandler(args, { sessionId: invocation?.sessionId }),
        },

        {
            name: "zerotrust_finalize_report",
            description:
                "Finalize the canonical REPORT.md + FINDINGS.json pair exactly once through the active audit identity and return canonical reportPath/findingsPath values. Validated current assurance state deterministically derives the findings verdict and separate assurance result, renders source-text-free stage/coverage/evasion, candidate-ledger, graph/trace, assurance-validation, supply-chain, and structured operator-decision artifacts, owns validated→finalized, and records the only trusted outcome. Caller verdict/count/completeness/prose fields are refused for source audits. Reconnaissance-only metadata Markdown remains trusted:false. Pair integrity, exclusive publication, rollback, and idempotent retry remain enforced.",
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
                        description: "Reconnaissance-only metadata mode. Complete in-memory Markdown draft; source-audit assurance finalization rejects this field.",
                    },
                    operator_decisions: {
                        type: "array",
                        maxItems: 512,
                        description: "Validated assurance flow only. Optional source-text-free operator decision records. Each record references one active canonical/graph finding ID and uses predefined action/rationale categories. operator_rationale is a short explicitly user-supplied one-line exception and is rejected if it resembles code, a URL, an encoded token, a finding/verdict claim, unsupported safe/clean claims, or known source-derived text.",
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
                                additionalProperties: false,
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
