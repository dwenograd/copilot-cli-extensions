# zerotrust-sourcecheck contributor guide

## Architecture

- `extension.mjs` registers the public tools and JSON schemas.
- `handler.mjs` validates activation arguments, binds the target, activates
  audit state, and returns the instruction packet.
- `modes.mjs` owns mode taxonomy and defaults.
- `enforcement.mjs` owns session/audit identity and current assurance state.
- `analysis/` owns deterministic contracts, inventories, scanners, candidate
  ledgers, graph construction/tracing, validation, assurance, and report data.
- `safeWrappers/` is the only production side-effect boundary.
- `packet/` renders the continuous agent workflow.
- `council/` owns the 32-role discovery roster and strict reviewer prompts.

## One lifecycle

All source-audit modes use the same ordered assurance lifecycle:

`acquired → inventoried → decoded → semantically-covered → scanned → red-teamed → traced → validated → finalized`

Audit activation creates the assurance state automatically. Do not add an
additional assurance activation tool.

The 32-role council is discovery input. Its candidates may guide attention, but
trusted findings must be reproduced through current deterministic scanner facts,
wrapper-issued semantic reviews, mandatory red-team reviews, evasive graph
trace, and independent assurance validation.

Modes without council discovery still require semantic-review and red-team model
coverage. If required model coverage cannot complete, report partial/incomplete
assurance and never authorize host execution.

## Public assurance tools

Keep these stable public names synchronized between `extension.mjs`,
`safeWrappers/index.mjs`, packet prose, and documentation:

- `zerotrust_prepare_semantic_coverage`
- `zerotrust_record_semantic_scanner`
- `zerotrust_assign_semantic_review`
- `zerotrust_record_semantic_review`
- `zerotrust_get_semantic_coverage`
- `zerotrust_prepare_red_team`
- `zerotrust_assign_red_team_review`
- `zerotrust_record_red_team_review`
- `zerotrust_get_red_team`
- `zerotrust_finalize_red_team`
- `zerotrust_prepare_evasive_graph`
- `zerotrust_trace_evasive_graph`
- `zerotrust_get_evasive_graph`
- `zerotrust_prepare_assurance_validation`
- `zerotrust_record_assurance_validation`
- `zerotrust_finalize_assurance_validation`

Dependency inventory and dependency analysis are also part of the same
lifecycle and use the same stable public naming contract.

## Contract rules

- Bind every operation to the immutable active audit ID.
- Treat paths, source identity, object/artifact/fact/evidence IDs, assignment
  tokens, and snapshot hashes as exact identities.
- Reject unknown fields and changed retries.
- Never accept caller completeness, verdict, graph, or topology claims when the
  wrapper can derive them.
- Never persist source text in semantic/red-team/validation records or durable
  findings artifacts.
- Numeric `schemaVersion` values are strict serialization metadata only.
- Preserve submitted finding severity; confidence and corroboration do not
  average impact downward.
- Empty model results require exact negative-evidence coverage.
- Truncation, unsupported artifacts, dynamic targets, missing paths, conflicts,
  and caps remain blockers.

## Finalization

The finalizer derives the findings verdict, assurance result, severity counts,
report prose, and trusted outcome from validated state. Source-audit callers may
provide only structured operator decisions. Finalize before install/build.

Do not add a caller-authored outcome recorder. Do not let council synthesis,
build success, or output hashes authorize host execution.

## Safety boundaries

- Preparation and validation execute no repository code.
- Source ingestion must remain exact-root-bound and reparse-safe.
- API-direct fetches remain pinned to the active commit.
- Release assets remain in the canonical quarantine.
- Safe/full names use identical install/build wrappers. Full mode adds only the
  `unsafe` acknowledgement and stronger admission/warning posture, reserving a
  future distinction; it does not enable a less-restricted installer.
- Install lifecycle scripts remain suppressed. Hazardous builds may still run
  repo-controlled npm build scripts, `build.rs`, and MSBuild targets.
- Build wrappers may execute repository-controlled build code only after the
  durable finalized assurance gate passes.
- Wrapper protections do not intercept raw built-in shell calls; packet
  instructions must continue to forbid bypasses.

## Editing checklist

When changing orchestration:

1. read current imports and core contract names first;
2. update extension registrations, wrapper barrel exports, packet prose, council
   prompt exports, README, and this guide together;
3. keep public tool names stable and free of workflow-generation branding;
4. keep the lifecycle ordered and continuous;
5. ensure deterministic-only preparation cannot be described as comprehensive
   without semantic and red-team model coverage;
6. keep finalization before install/build;
7. use static search and syntax checks to catch unresolved imports and stale
   names.
