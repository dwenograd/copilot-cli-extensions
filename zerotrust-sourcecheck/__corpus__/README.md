# Evaluation corpus

The corpus evaluates malicious-source analysis behavior without committing live
malware, executable payloads, credentials, command inventories, or weaponizable
examples. It is not a generic vulnerability or exploit corpus.

It contains public clean-control GitHub URLs, local clean and benign-lookalike
controls, inert cross-file behavior markers, evasive-source fixtures, inventory
blockers, source/release divergence, and deliberately incomplete graph variants.

Local fixtures are printable-ASCII `.ztfixture` text. The runner parses their
restricted `marker.*(...)` declarations as data and never imports or executes
fixture contents. Arguments may use inert quoted-fragment joins such as
`"generic"+"-token"`.

## Safe default

```powershell
node __corpus__\runner\runCorpus.mjs --dry-run --quality-gate
```

No execution flag also defaults to dry-run. Dry-run validates expectations and
fixture syntax, executes local deterministic evaluation in memory, compares the
resulting FINDINGS-shaped snapshots, calculates metrics, and applies the
optional quality gate. It performs no network calls, model calls, subprocess
audit dispatch, or result writes.

Use `--fixture <slug>` to select one fixture.

## Local deterministic run

```powershell
node __corpus__\runner\runCorpus.mjs --local --quality-gate
```

Local mode writes ignored outputs under
`__corpus__\results\<ISO timestamp>\`. Each local fixture receives a
source-text-free `FINDINGS.json`-shaped snapshot and `comparison.json`.
The run-level `summary.json` uses `zerotrust-corpus-summary` and records the
execution mode, scope, run ID, expectation schema, metrics, and quality-gate
result. These outputs are not adopted audit state and do not replace the
production `REPORT.md` plus `FINDINGS.json` finalizer.

## Live multi-model run

Live URL audits require both an explicit flag and environment gate:

```powershell
$env:ZEROTRUST_CORPUS_LIVE = "1"
node __corpus__\runner\runCorpus.mjs --live
```

Live mode remains experimental. It runs API-direct `audit_source` and
`audit_source_council` flows only, forbids install/build/repository execution,
may use network and models, and runs sequentially with a delay.

The artifact parser consumes `FINDINGS.json` first and falls back to legacy
`REPORT.md` category parsing only when needed. Path extraction supports Windows,
UNC, POSIX, and JSON-encoded paths.

## Expectations

Expectations use the unversioned identifier:

```text
zerotrust-evaluation-expectation
```

Each expectation defines required/final stage completion; activation and plugin
facts; candidate, validated, refuted, and unresolved count ranges; chain
requirements; score ranges; tags; acceptable blocker codes; optional failure
stage; and dimension metadata for evasion classes, artifact classes, languages,
repository size, known coverage blockers, and metamorphic transforms.

`expectations/schema.json` documents the serialized contract.
`runner/expectationSchema.mjs` performs strict runtime validation. The numeric
`schema_version` field is serialization metadata, not a product generation.

## Metrics and quality gate

The runner reports activation recall, candidate recall, complete-chain recall,
validation/refutation accuracy, refutation accuracy, clean-control
false-positive rate, unresolved rate, metamorphic stability, failure reasons,
dimension-grouped metrics, and favorable-assurance counts for fixtures with
known coverage blockers.

`quality-gate.json` requires:

- at least 0.98 activation recall;
- at least 0.98 candidate recall in every mandatory evasion class;
- at least 0.95 complete-chain recall;
- at least 0.98 refutation accuracy;
- at most 0.03 clean-control false-positive rate;
- zero favorable-assurance results with known coverage blockers.

`--quality-gate` returns nonzero when a fixture comparison or threshold fails.
Planned URL fixtures do not count as evaluated dry-run fixtures.

## Metamorphic transforms

`runner/metamorphicTransforms.mjs` applies deterministic, in-memory-only
identifier renaming, whitespace plus inert comments, virtual relocation, and
quoted string splitting. It never writes, imports, evaluates, or executes
fixture content.

## AV-safety contract

1. Do not add live malware, executable payloads, credentials, encoded payload
   fragments, invisible characters, or attack-command inventories.
2. Use inert marker declarations and generic tokens only.
3. Keep local fixtures printable ASCII.
4. Never import or execute fixture contents.
5. Keep live runs explicit and API-direct.
6. Stop immediately if host protection alerts during corpus work.
