# zerotrust-sourcecheck

Self-contained Copilot CLI extension for static auditing of source-level
malicious behavior. It is not a generic vulnerability scanner, dependency-CVE
scanner, sandbox, or malware execution environment.

## Assurance contract

Every `zerotrust_sourcecheck` activation creates an immutable random audit ID
and automatically owns one current assurance state.

The continuous lifecycle is:

1. activate and bind the target identity;
2. acquire every required source object without executing repository code;
3. inventory objects and decode bounded derived artifacts;
4. inventory and statically analyze supported dependency closures;
5. prepare deterministic semantic scanner assignments;
6. record every exact scanner result;
7. issue and record assignment-bound model semantic reviews;
8. optionally use the 32-role council as discovery input;
9. run every mandatory evasive red-team category;
10. prepare and exhaustively trace the evasive behavior graph;
11. run independent assurance validation;
12. collect operator remediation decisions;
13. deterministically finalize `REPORT.md` and `FINDINGS.json`;
14. only then permit wrapper-mediated install/build when the trusted gate passes;
15. clean up and close the audit.

Any missing identity, acquisition, scanner, reviewer, red-team, graph, trace,
validation, dependency, release-asset, or truncation gate yields partial or
incomplete assurance. Static analysis never proves that a project is clean.

Modes without the 32-role council still run the required semantic-review and
red-team model stages. They must not claim comprehensive assurance if those
assignments are skipped.

## Primary modes

- `metadata_only` — reconnaissance only; no source assurance.
- `audit_source` — API-direct source audit without the 32-role discovery council.
- `audit_source_council` — API-direct source audit with council discovery.
- `audit_local_source` — audit exact local bytes without council discovery.
- `audit_local_source_council` — local audit with council discovery.
- `verify_release` — source audit plus bound release-asset acquisition.
- `audit_and_safe_build` / `audit_and_full_build` — source audit followed by
  wrapper-mediated host execution only after trusted finalization.
- Council build variants add council discovery to the same lifecycle.

Safe/full build names currently use identical install/build wrappers. Full mode
adds an explicit `unsafe` acknowledgement and stronger admission/warning
posture, reserving a future distinction. Install lifecycle scripts remain
suppressed in both modes; full mode does not enable a less-restricted installer.
Hazardous builds may still execute repo-controlled npm build scripts,
`build.rs`, and MSBuild targets.

## Current assurance tools

Semantic coverage:

- `zerotrust_prepare_semantic_coverage`
- `zerotrust_record_semantic_scanner`
- `zerotrust_assign_semantic_review`
- `zerotrust_record_semantic_review`
- `zerotrust_get_semantic_coverage`

Evasive red team:

- `zerotrust_prepare_red_team`
- `zerotrust_assign_red_team_review`
- `zerotrust_record_red_team_review`
- `zerotrust_get_red_team`
- `zerotrust_finalize_red_team`

Graph and validation:

- `zerotrust_prepare_evasive_graph`
- `zerotrust_trace_evasive_graph`
- `zerotrust_get_evasive_graph`
- `zerotrust_prepare_assurance_validation`
- `zerotrust_record_assurance_validation`
- `zerotrust_finalize_assurance_validation`

Dependency tools use the same stable public naming contract:

- `zerotrust_inventory_dependencies`
- `zerotrust_analyze_dependencies`

The 32-role council submits discovery candidates through
`zerotrust_record_council_candidates`. Council output is not a second verdict
path: a lead becomes trusted only through current scanner, semantic-review,
red-team, graph, and validation records.

## Acquisition and containment

API-direct audits use:

- `zerotrust_safe_list_tree`
- `zerotrust_safe_fetch_file`

Local/build source ingestion uses:

- `zerotrust_safe_list_source`
- `zerotrust_safe_index_source_file`
- `zerotrust_safe_list_analysis_facts`

Release audits additionally use:

- `zerotrust_safe_list_release_assets`
- `zerotrust_safe_fetch_release_asset`

Wrappers bind the active audit, target identity, source SHA or local path,
canonical artifact paths, and bounded coverage. They do not follow source-tree
reparse points or execute repository code during preparation.

## Finalization and build gate

`zerotrust_finalize_report` is the only report writer. For source audits it
accepts structured operator decisions, derives the verdict and assurance result
from validated state, writes the canonical artifact pair atomically, and records
the only trusted outcome.

`zerotrust_safe_install` and `zerotrust_safe_build` require the active build
audit and its durable identity-matching finalized assurance report. Incomplete
assurance or supported critical/high malicious behavior closes the build gate.
Build output is never assurance evidence.

## Strict contracts

Tool payloads reject unknown fields, identity substitution, changed retries,
source-text leakage, unsupported topology, and caller-supplied completeness
claims. A numeric `schemaVersion` is strict contract metadata only; it does not
select a workflow.

## Lifecycle cleanup

- `zerotrust_cleanup_audit`
- `zerotrust_cleanup_quarantine`
- `zerotrust_sweep_audit_scratch`
- `zerotrust_close_audit`

## Development

Run every `__tests__/*.test.mjs` file with the fail-fast test runner:

```powershell
node __tests__/runAll.mjs
```

Each file runs in a separate Node process with a 60-second timeout. The runner
stops at the first failure or timeout and exits nonzero.

The extension intentionally registers no broad pre-tool hook. Safety guarantees
apply to operations routed through the registered wrappers.
