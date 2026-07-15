# zerotrust-sourcecheck

`zerotrust-sourcecheck` answers a narrow question:

> Does this repository or release appear to contain intentionally malicious
> source behavior?

It pins the source identity, reads and indexes the source without executing it,
traces suspicious behavior from activation to effect, independently validates
the evidence, and writes a report.

It is designed for the "someone sent me a repo, installer, dependency, or
release asset - should I trust it?" problem. It is not a general code-quality,
license, dependency-CVE, or vulnerability scanner.

## Quick start

Audit a GitHub repository:

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo>
```

That runs the default council audit: deterministic checks plus 32 specialized
review roles, behavior tracing, and independent validation.

Run the faster deterministic-only audit:

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo> mode=audit_source
```

Audit a local directory without cloning or fetching its source:

```text
@zerotrust_sourcecheck local_path="C:\path\to\repo"
                        i_understand_local_path_reads_my_disk=true
```

Audit a GitHub release and its published assets:

```text
@zerotrust_sourcecheck https://github.com/<owner>/<repo>/releases/tag/<tag>
```

The extension returns an instruction packet. Copilot follows that packet using
the registered `zerotrust_*` tools and produces the final report.

## What happens during an audit

```text
Pin identity -> acquire source -> index facts -> find candidates
             -> trace behavior -> confirm/refute -> write report
```

1. **Pin identity** - resolve the exact commit, local source identity, or
   release being audited.
2. **Acquire source** - enumerate every required file. API-direct audits do not
   intentionally create a source checkout.
3. **Index facts** - record bounded facts, hashes, line ranges, and evidence
   identities.
4. **Find candidates** - deterministic checks and, in council modes, specialized
   reviewers look for suspicious activation-to-effect behavior.
5. **Trace behavior** - connect triggers, capabilities, effects, and targets.
6. **Validate** - separate confirm, refute, and adjudication passes evaluate the
   existing evidence without executing repository code.
7. **Finalize** - write `REPORT.md` and `FINDINGS.json`.

If required coverage or validation is incomplete, the verdict is
`incomplete`. The extension does not turn missing evidence into a clean bill of
health.

## Choose a mode

| Mode | Use it for | Executes repository code? |
|---|---|---:|
| `audit_source_council` | Thorough GitHub source audit. Default for repo, commit, tree, and pull-request URLs. | No |
| `audit_source` | Faster deterministic GitHub source audit. | No |
| `audit_local_source_council` | Thorough audit of exact files already on disk. Default with `local_path`. | No |
| `audit_local_source` | Faster deterministic audit of local files. | No |
| `verify_release` | Source audit plus release-asset download, hashing, and provenance checks. Default for release URLs. | No |
| `metadata_only` | Repository metadata reconnaissance. This is not a security audit. | No |
| `audit_and_safe_build` | Deterministic audit followed by dependency install and build. | **Yes** |
| `audit_and_safe_build_council` | Council audit followed by dependency install and build. | **Yes** |
| `audit_and_full_build` | Currently the same build wrappers as safe build, with an additional `unsafe` acknowledgement. | **Yes** |
| `audit_and_full_build_council` | Council version of full build. | **Yes** |

To make omitted-mode GitHub audits deterministic-only:

```text
ZEROTRUST_DETERMINISTIC_ONLY=1
```

Release URLs still default to `verify_release`.

## Important safety boundaries

### Source audits are static

Normal URL and local-source audits do not execute repository code. Validators
also do not build, fuzz, or create proof-of-concept files.

API-direct source wrappers do not intentionally write source files, but source
text returned to Copilot may still be retained in CLI session logs or temporary
oversized-output storage.

### Build modes execute untrusted code

Build modes clone the pinned commit and run wrapper-controlled install/build
commands. Install lifecycle scripts are suppressed, but the build itself may
execute repository-controlled npm scripts, `build.rs`, MSBuild targets, or
equivalent code.

Both "safe" and "full" build modes currently use the same installer and builder.
Full mode is not more isolated; it adds an explicit `unsafe` acknowledgement and
reserves a future policy distinction.

Build modes require:

```text
i_understand_build_executes_code=true
```

Full-build modes additionally require:

```text
unsafe=true
```

### Local mode reads exactly the supplied directory

Local mode requires an absolute path and rejects traversal, credential-store
paths, and unsafe root links. Wrapper enumeration does not follow symlinks,
junctions, or other reparse points.

Council reviewers may use built-in read/search tools under prompt-level path
rules. Copilot CLI does not provide a pre-tool hook that can technically
intercept every built-in tool call. Evidence enters the trusted report only
when it matches the wrapper-owned index, content identity, line range, and
excerpt hash.

### Release assets are quarantined

`verify_release` writes assets as `<asset-id>.bin` under the audit quarantine,
never under attacker-controlled filenames. The limit is 512 assets and 100 MB
per asset. Skipped, oversized, truncated, failed, or mismatched assets make the
release acquisition incomplete.

## Results

Every completed audit writes:

| File | Contents |
|---|---|
| `REPORT.md` | Human-readable verdict, findings, evidence summary, limitations, and remediation guidance. |
| `FINDINGS.json` | Canonical source-text-free findings ledger for automation and verification. |

Reports live outside any build clone so the clone can be removed without
deleting the result.

Overall verdicts are:

- `critical`, `high`, `medium`, or `low`
- `no red flags found`
- `incomplete`

`no red flags found` means the completed audit found no supported malicious
behavior. It is not proof that the project is safe or bug-free.

## Cleanup

Audits use a lifecycle-bound working area containing reports, optional clones,
release quarantine, and metadata cache.

The normal cleanup order is:

1. `zerotrust_cleanup_audit` for a build clone.
2. `zerotrust_cleanup_quarantine` for downloaded release assets.
3. `zerotrust_sweep_audit_scratch` for unexpected top-level scratch files.
4. `zerotrust_close_audit` to release the active audit state.

`zerotrust_close_audit` refuses to strand a live clone or quarantine unless
`abandon_artifacts:true` explicitly gives up cleanup authority.

## Main options

```text
zerotrust_sourcecheck({
  url?: "https://github.com/<owner>/<repo>[/...]",
  local_path?: "C:\absolute\path",
  mode?: "<mode from the table above>",
  ref?: "branch, tag, or SHA override",
  focus?: "area to emphasize",
  build_root?: "C:\absolute\scratch\root",

  i_understand_local_path_reads_my_disk?: true,
  i_understand_build_executes_code?: true,
  i_understand_private_repo_risk?: true,
  unsafe?: true,

  roles?: object,
  extra_roles?: object[],
  judge?: string,
  max_premium_calls?: number,
  validation_min_severity?: "high" | "medium" | "low" | "info"
})
```

Most users should only need the URL or local-path forms shown in
[Quick start](#quick-start).

## Tool groups

The extension registers more than the main entry point because each sensitive
operation has a narrow wrapper:

- **Acquire and index:** list/fetch a pinned Git tree, or enumerate/index an
  exact local root.
- **Analyze:** record council candidates, trace the behavior graph, and record
  independent validation.
- **Release verification:** list and fetch assets bound to the active release.
- **Build:** hardened clone, dependency install, and build.
- **Persist:** metadata-cache operations and final report creation.
- **Clean up:** clone, quarantine, scratch, and lifecycle cleanup.

These helpers are normally driven by the instruction packet rather than called
manually.

## Development

The extension requires the repository's Node dependencies:

```powershell
npm install
npm run test:zerotrust
```

After changing extension code, restart Copilot CLI or reload extensions.

## Scope and limitations

This extension looks for malicious intent expressed through source-level
behavior. It does not replace:

- normal secure-code review;
- dependency/CVE scanning;
- malware scanning of arbitrary binaries;
- reproducible-build verification;
- license review;
- sandboxing or endpoint protection.

The audit is only as strong as its source coverage, pinned identity, evidence,
review models, deterministic checks, and operator trust in the local
environment.

## License

MIT
