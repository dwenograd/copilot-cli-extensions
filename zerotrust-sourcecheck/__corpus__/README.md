# Regression corpus harness

Experimental local harness for comparing `audit_source` with
`audit_source_council`. The committed registry currently contains only two
clean-control public repositories; it is not a malicious-sample corpus and is
not a release gate by itself.

## Dry run

From `zerotrust-sourcecheck/`:

```powershell
node __corpus__\runner\runCorpus.mjs --dry-run
```

Dry-run validates `urls.txt` and matching expectation files, prints the two
planned modes, and performs no network/audit dispatch.

Options:

- `--fixture <slug>` selects one expectation filename stem.
- `--promote-gate` returns nonzero for failed or inconclusive fixtures.

## Live mode is experimental

Without `--dry-run`, `dispatchAudit.mjs` currently shells out to:

```text
gh copilot exec -- <prompt>
```

That command path is marked TODO in source and has not been validated as a
reliable promotion gate. It requires the relevant `gh`/Copilot command,
authentication, network access, model availability, and parseable report-path
output. The path extractor recognizes Windows drive-letter paths only.

The runner does not copy reports into the corpus results directory. It reads
the absolute `REPORT.md` path printed by the child. If no path is parsed, the
fallback `<fixture>/<mode>-REPORT.md` name is only a guessed path and is not
created by `dispatchAudit`, so the comparison will fail when it tries to read
it. Live fixtures run sequentially with a 30-second delay.

## Results paths

Successful live comparisons create:

```text
__corpus__\results\<ISO-timestamp>\<fixture>\comparison.json
```

The actual audit reports remain in the Zero Trust canonical `_reports`
location returned by each child audit. `results/` is git-ignored.

## TSV format

`urls.txt` is tab-separated:

```text
URL<TAB>kind<TAB>expected_min_verdict<TAB>required_tags<TAB>forbidden_tags
```

Tags are comma-separated generic labels such as `remote-fetch`,
`obfuscation`, `credential-store-read`, `persistence`, `supply-chain`, or
`ci-workflow`.

## AV-safety contract

1. Do not store literal attack patterns, command inventories, encoded payload
   fragments, or invisible-character bytes in committed corpus files.
2. Expectations use category letters (`A` through `G`) and generic tags only.
3. Synthetic reports use category-letter prose and generic paths.
4. Risky URLs/expectations remain local under ignored paths or outside the
   repository.
5. Stop immediately if host AV alerts during corpus work.

These constraints reduce alert-prone byte shapes; they do not make live corpus
runs a sandbox or an AV test.
