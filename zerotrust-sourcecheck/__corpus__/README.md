# Regression corpus harness

This directory contains a local-only regression corpus for comparing the deterministic audit mode with the council audit mode. It ships with clean-control GitHub URLs only. Operators may add local-only fixtures for private validation, but those additions must not be committed.

## Run

From the extension directory:

```powershell
node __corpus__\runner\runCorpus.mjs --dry-run
```

`--dry-run` validates `urls.txt` and matching expectation files, prints the planned audit pairs, and does not start audits. Non-dry runs write summaries under `__corpus__\results\`, which is ignored by git.

Options:

- `--fixture <slug>` runs one fixture derived from the expectation filename.
- `--promote-gate` exits nonzero for any failure or inconclusive fixture.

## TSV format

`urls.txt` is tab-separated:

```text
URL<TAB>kind<TAB>expected_min_verdict<TAB>required_tags<TAB>forbidden_tags
```

Tags are comma-separated generic tags such as `remote-fetch`, `obfuscation`, `credential-store-read`, `persistence`, `supply-chain`, or `ci-workflow`.

## AV-safety contract

Defender alerts occurred twice during earlier development: once from an inert fixture shaped like a script payload, and once from dense prompt prose listing offensive PowerShell command names. The lesson is that byte shape and density matter, even when content is meant as documentation or a test fixture.

Rules for this corpus:

1. Do not store literal attack patterns, command-name inventories, encoded payload fragments, or invisible-character bytes in any corpus file.
2. Expectation files must use category letters (`A` through `G`) and generic tags only.
3. Synthetic reports in tests must use category-letter prose and generic file paths.
4. Operator-curated risky URLs and their expectations stay local under ignored paths or outside this repository.
5. If an AV alert appears during corpus work, stop immediately and treat it as a blocker.

The terse expectation files are intentional: they preserve regression semantics without writing risky byte patterns to disk.
