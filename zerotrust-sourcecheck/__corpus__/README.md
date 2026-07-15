# Version 5 evaluation corpus

The corpus evaluates stage behavior without committing live malware, executable
payloads, credentials, command inventories, or weaponizable examples.
It evaluates the malicious-source pipeline, not generic vulnerability/exploit
coverage.

It contains:

- two public clean-control GitHub URLs;
- local clean and benign-lookalike controls;
- inert cross-file marker fixtures for:
  - activation to fetch, transform, and effect;
  - credential-like source to transform and external-like sink;
  - startup to persistence-like registration;
  - CI trigger to secret-like value and external-like sink;
  - AI instruction to tool-like effect;
- incomplete and deliberately broken graph variants.

Local fixtures are plain `.ztfixture` text. The runner parses their restricted
`marker.*(...)` declarations as data and never imports or executes them.

## Safe default

```powershell
node __corpus__\runner\runCorpus.mjs --dry-run --promote-gate
```

No execution flag also defaults to dry-run. Dry-run:

1. validates every versioned expectation;
2. enforces printable-ASCII and restricted inert-marker fixture syntax;
3. runs local deterministic indexing, fixture-plugin seeding, graph merge,
   static validation, tracing, deduplication, and scoring in memory;
4. compares the resulting FINDINGS-shaped snapshot with expectations;
5. calculates promotion metrics;
6. performs no network calls, model calls, subprocess audit dispatch, or result
   writes.

Use `--fixture <slug>` to select one fixture.

## Local deterministic run

```powershell
node __corpus__\runner\runCorpus.mjs --local --promote-gate
```

Local mode writes ignored results under:

```text
__corpus__\results\<ISO timestamp>\
```

Each local fixture gets a source-text-free `FINDINGS.json`-shaped snapshot and
`comparison.json`. A run-level `summary.json` contains metrics and gate output.
These are evaluation outputs, not adopted audit state and not substitutes for
the exactly-once production `REPORT.md` + `FINDINGS.json` finalizer.

## Live multi-model run

Live URL audits require both an explicit flag and environment gate:

```powershell
$env:ZEROTRUST_CORPUS_LIVE = "1"
node __corpus__\runner\runCorpus.mjs --live
```

Live mode remains experimental. It runs API-direct `audit_source` and
`audit_source_council` flows only and tells the child not to install, build, or
execute repository code. It may use network and models, runs sequentially with
a delay, and is never selected implicitly.

The artifact parser consumes `FINDINGS.json` first. If the JSON artifact is not
available, it falls back to legacy `REPORT.md` category parsing. Report and
findings path extraction supports Windows, UNC, POSIX, and JSON-encoded paths.

## Expectations

Expectations use schema:

```text
zerotrust-evaluation-expectation/v1
```

Each expectation defines:

- required and final stage completion;
- required/minimum activation and plugin facts;
- candidate, validated, refuted, and unresolved count ranges;
- required, complete-required, and forbidden chain types;
- minimum/maximum severity, confidence, and malicious-project-fit;
- required and forbidden generic tags;
- acceptable generic blocker codes;
- expected prepare, scan, trace, validate, or finalize failure stage.

`expectations/schema-v1.json` documents the top-level serialized contract.
`runner/expectationSchema.mjs` performs the strict runtime validation.

## Metrics and promotion gate

The runner reports:

- activation recall;
- candidate recall;
- complete-chain recall;
- validation/refutation accuracy;
- false-positive rate on clean/benign controls;
- unresolved rate;
- prepare/scan/trace/validate/finalize failure reasons.

Thresholds live in `promotion-gate.v1.json`. `--promote-gate` returns nonzero
when a fixture comparison or metric threshold fails. Planned URL fixtures do
not count as evaluated dry-run fixtures.

## AV-safety contract

1. Do not add live malware, executable payloads, credentials, encoded payload
   fragments, invisible characters, or attack-command inventories.
2. Use inert marker declarations and generic tokens only.
3. Keep local fixtures printable ASCII; the parser rejects URLs, payload
   schemes, malformed calls, unknown marker APIs, and unrestricted prose.
4. Do not make local fixture execution import or execute fixture contents.
5. Keep live runs explicit and API-direct; never silently enable network/model
   use or repository execution.
6. Stop immediately if host protection alerts during corpus work.

These constraints reduce alert-prone byte shapes. They do not make live audit
runs an operating-system sandbox or an AV test.
