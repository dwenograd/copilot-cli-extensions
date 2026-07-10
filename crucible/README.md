# Crucible

Crucible is a fully automated local investigation runner. Model workers may
propose candidate file sets, but they receive only one custom submission tool
and cannot execute commands. A deterministic operator-allowlisted harness is
the only authority that can establish correctness.

The kernel runs an **adaptive scientific loop** (domain v2): it evaluates every
candidate, keeps a bounded archive of what was learned, feeds that archive back
into the next candidate's prompt, and only stops on a genuinely justified
terminal decision or an explicit non-result.

## Public tools

The public surface is **unchanged** by the domain-v2 redesign — still exactly
four tools, and only `crucible_result` may ever report a terminal decision:

- `crucible_start` has two mutually exclusive forms. A new investigation supplies
  the complete contract/project/case inputs; preflight stages and publishes the
  validation snapshots, freezes the harness identity, and launches the detached
  supervisor. A reattach supplies only `investigation_id` plus an optional later
  `deadline_iso`/required `reset_policy`; it loads and verifies the persisted
  contract, supervisor config, and snapshots, so the original project and case
  directories are not needed. Admission completes before resume is persisted,
  and a launch failure is compensated back to a durable retryable pause.
- `crucible_status` reports adaptive progress and whether a terminal result is
  available. It never reveals the decision, candidate identifiers, metric
  values, contract/event hashes, or evidence identifiers/hashes — only aggregate
  signals: evaluation and round/slot counters, plateau/escape phase, operator
  mix, archive counts, duplicate count, and a
  `passing_incumbent_available` boolean.
- `crucible_stop` requests a persisted resumable pause. Resumability is claimed
  only once the kernel-owned pause transition is actually persisted; a bare
  in-flight stop request is honest that the pause is not yet durable. Its
  `stop_state` distinguishes terminal, operational/domain non-result, persisted
  pause, and requested/in-flight pause outcomes.
- `crucible_result` is the only tool that may return `VERIFIED_RESULT` or
  `TARGET_UNREACHABLE`, always with its terminal evidence closure. It reads the
  persisted terminal decision and never recomputes policy.

Supervisor status/config/outcome files contain only opaque lifecycle state,
terminal availability, non-result codes, and generation/PID health. Runner
outcome files never carry a decision, winner, candidate/evidence identifiers or
hashes, event hashes, or closures, and the supervisor deletes each outcome file
immediately after consuming it. Full terminal repository/domain/artifact
verification is performed only by `crucible_result`.

## Harness allowlist

The allowlist defaults to:

`%LOCALAPPDATA%\Crucible\harnesses.json`

Override it with `CRUCIBLE_ALLOWLIST_PATH`. Investigation state defaults to
`%LOCALAPPDATA%\Crucible\investigations`.

Do not hand-edit this file. Author it with the operator CLI
(`tools/configure-harness.mjs`, described below), which computes every content
hash for you and re-validates the exact bytes it installs.

Every new contract freezes the canonical allowlist-entry hash, raw allowlist
file hash/version, executable and dependency hashes, argv-template hash,
allowed-environment hash, trusted parser version/source hashes,
`executesCandidateCode`, and the required sandbox policy identity/digest. The
allowlist entry hash is also part of the deterministic investigation identity.
The runner re-verifies the exact frozen identity before every measurement.
Replacing an entry under the same id, or changing the allowlist, executable,
dependency, environment policy, parser, or sandbox policy, therefore fails an
existing investigation closed. Intentional harness changes require a new
investigation identity.

Example:

```json
{
  "version": 1,
  "entries": {
    "example-harness": {
      "executable": "C:\\Program Files\\nodejs\\node.exe",
      "executableSha256": "<sha256 hex>",
      "argvTemplate": [
        "C:\\trusted\\crucible-harness.mjs",
        "{{candidatePath}}",
        "{{attemptId}}"
      ],
      "dependencies": [
        {
          "path": "C:\\trusted\\crucible-harness.mjs",
          "sha256": "<sha256 hex>",
          "role": "script"
        }
      ],
      "allowedEnv": {},
      "timeoutMs": 30000,
      "maxStdoutBytes": 1048576,
      "maxStderrBytes": 262144,
      "executesCandidateCode": false,
      "validationCases": {
        "accepts-known-good": {
          "snapshotHash": "sha256:<64 hex>",
          "description": "a candidate the harness must accept"
        },
        "rejects-known-bad": {
          "snapshotHash": "sha256:<64 hex>"
        }
      }
    }
  }
}
```

Each `validationCases[<id>].snapshotHash` is an ArtifactStore snapshot id
(`sha256:<64 hex>`) — the deterministic content address of a validation-case
directory. The allowlist stores **only** the snapshot id (and an optional
description); the accept/reject **expectation** lives in the frozen
`crucible_start` contract, never here.

The harness must emit exactly one JSON object:

```json
{
  "pass": true,
  "metrics": { "score": 1.0 }
}
```

Validation runs use the same `pass` field against frozen accept/reject cases.
Optional fields are `validationCases`, `searchSpaceExhausted`, and
`impossibilityCertificateHash`.

For `hypothesisTopology: "certified_impossibility"`, the same allowlisted
harness must also support verifier mode. After validation and every frozen
search slot complete without an accepted candidate, the kernel reserves a
single `verify_impossibility` command. The runner materializes a snapshot whose
root contains `crucible-impossibility-request.json`; the harness must inspect
that request and emit:

```json
{
  "pass": true,
  "searchSpaceExhausted": true
}
```

Only that exact positive combination parses to the certificate verdict
`target_unreachable`. `pass: false` is `not_proven`; `pass: true` without
`searchSpaceExhausted: true` is `invalid`. Both are persisted non-results. The
runtime captures and persists the exact stdout/stderr bytes, full measurement
receipt, canonical certificate, and verification-request snapshot. The domain
accepts only their algorithm-tagged hashes from the fenced trusted-harness
observation; a candidate/model claim or the optional
`impossibilityCertificateHash` output field cannot establish unreachability.

**Every candidate produces evidence.** The kernel commits a candidate evidence
record for every observed candidate slot and classifies it as one of
`accepted`, `near_miss`, `rejected`, or `invalid_metrics`; nothing is silently
dropped. Duplicate candidate artifacts are committed and *linked* to the first
occurrence (`dedupPolicy: "mark"`), never refused.

**Partial or missing metrics do not fail the run.** A candidate whose declared
ranking metrics are absent or non-numeric is classified `invalid_metrics`
(non-rankable) and archived as a lesson rather than rejected outright — so a
harness that can only partially score a candidate should still emit whatever it
has. Only the frozen acceptance predicate decides `accepted`; the metrics decide
*ranking* among rankable candidates.

Every executable and declared dependency is reverified, copied into a private
per-attempt staging directory, rehashed, and executed only from staged bytes.
Static script/file arguments must be declared dependencies.

Harnesses with `"executesCandidateCode": true` fail closed unless a real
sandbox provider admits the run. Working-directory isolation, environment
filtering, timeouts, and process-tree termination are not treated as a sandbox.

## Configuring a harness (operator CLI)

`tools/configure-harness.mjs` is the supported way to create or update an
allowlist entry **before any investigation starts**. It is a plain CLI, not an
extension process: it prints one JSON object to stdout on success and exits `0`;
on failure it prints one JSON error object to stderr and exits non-zero. It
never prompts.

```
node tools/configure-harness.mjs --config <config.json> [--allowlist <path>] [--replace]
```

- `--config <path>` — a strict JSON harness config (required). Unknown keys are
  rejected.
- `--allowlist <path>` — output allowlist path. Defaults to
  `%LOCALAPPDATA%\Crucible\harnesses.json`. If you overrode the extension's
  allowlist with `CRUCIBLE_ALLOWLIST_PATH`, pass that same path here so both
  point at one file.
- `--replace` — allow overwriting an entry whose `executable` changed. Without
  it, a differing-executable overwrite is refused (same-executable updates are
  always allowed).

The config lists **paths**, not hashes — the tool computes them:

```json
{
  "id": "example-harness",
  "executable": "C:\\Program Files\\nodejs\\node.exe",
  "argvTemplate": ["C:\\trusted\\crucible-harness.mjs", "{{candidatePath}}", "{{attemptId}}"],
  "dependencies": [{ "path": "C:\\trusted\\crucible-harness.mjs", "role": "script" }],
  "allowedEnv": {},
  "timeoutMs": 30000,
  "maxStdoutBytes": 1048576,
  "maxStderrBytes": 262144,
  "executesCandidateCode": false,
  "validationCases": [
    { "id": "accepts-known-good", "expectation": "accept", "sourceDir": "C:\\cases\\good", "description": "must accept" },
    { "id": "rejects-known-bad",  "expectation": "reject", "sourceDir": "C:\\cases\\bad" }
  ],
  "description": "example"
}
```

What the tool does, fail-closed, in one pass:

1. Validates a safe `id`, absolute local **non-symlink regular** executable and
   dependency files, and that any static-file `argvTemplate` entry is a declared
   dependency (the same rule the loader enforces).
2. Requires at least one `accept` and one `reject` validation case, with unique
   safe ids and absolute local non-symlink `sourceDir` directories.
3. Computes SHA-256 for the executable and every dependency.
4. Ingests each `sourceDir` through a **temporary** local `ArtifactStore` purely
   to compute its deterministic snapshot id, then discards that store.
5. Strict-parses the current allowlist, **preserving every unrelated entry**,
   and refuses a differing-executable overwrite unless `--replace` is given.
6. Emits schema version 1 with `validationCases` keyed by id holding
   `{ snapshotHash, description? }` — expectations are intentionally not written.
7. Installs the replacement atomically (temp file → fsync → backup the previous
   file to `<allowlist>.bak` → atomic rename), after re-validating the exact
   bytes through the real loader.

### Deterministic snapshot ids must match `crucible_start`

The snapshot id the tool records is the content address of the `sourceDir`
contents, computed the same way `crucible_start` stages it in an isolated
preflight `ArtifactStore` before publishing the verified bytes into the
per-investigation store. It is a pure function of the directory's files (sorted
relative posix paths + per-file SHA-256), independent of the store location, so
a throwaway store here yields the identical id `crucible_start` recomputes.

For validation to line up, the directory `crucible_start` ingests
(`project_dir` + the case `path`) must have **byte-for-byte identical contents**
to the `sourceDir` configured here. If the contents differ, the ingested
snapshot id will differ from the pinned `snapshotHash` and the case will not
match the allowlisted set. Freeze the case directories before configuring the
harness and keep them unchanged through `crucible_start`.


## Adaptive scientific loop (domain v2)

Between validation and a terminal decision, the kernel runs a deterministic,
replayable search loop. Everything below is a pure function of the frozen
contract (including its canonical `searchPolicy`) and the persisted event
history, so a replay reproduces every command byte-for-byte.

**Per-candidate commands.** Each round is broken into `candidatesPerRound`
slots. For every slot the kernel reserves one `search_candidate` command with a
deterministic identity — round, slot index, a generated (or bounded) candidate
id, the assigned worker model, a search operator, parent evidence ids, prompt
context refs, and a deterministic seed. The observing harness result must match
that reserved assignment exactly.

**Search operators.** Each candidate is assigned one operator, chosen by
deterministic weighted selection from the policy's `operatorWeights` and the
current archive:

- `fresh` — a de-novo candidate with no parents (the only operator available on
  a cold archive).
- `refinement` — improve a single parent drawn from the incumbent/near-miss
  pool.
- `crossover` — combine two parents from distinct mechanism groups.
- `diversification` — deliberately explore away from the current pool.
- `adversarial` — stress the incumbent's weak points.
- `restart` — abandon parents and reseed.

`diversification`, `adversarial`, and `restart` are the **mandatory-escape
operators**: during a plateau escape the kernel zeroes every non-escape operator
so the search must actually leave the plateau, not re-refine it.

**Archive.** A bounded, capped archive summarizes what has been learned:
`accepted`, `nearMisses`, `rejected`, and `invalidMetrics` cohorts, plus
`mechanismGroups` and lesson (`finding`) groups grouped by candidate
annotations, a duplicate index, and the current incumbent. Caps come from the
policy's `archiveCaps`, so the archive stays bounded no matter how long the
search runs.

**Feedback.** The archive is fed forward: the next candidate's
`promptContextRefs` and `parentEvidenceIds` are selected from the incumbent,
near-misses, and representative mechanism/lesson evidence (bounded by
`promptCaps`). Candidate annotations may cite only evidence that appears in that
prompt context — the kernel rejects out-of-context citations. The runner builds
a canonical byte-capped prompt context: objective, acceptance predicate,
ranking metrics, operator assignment, plateau/escape state, and omission counts
are trusted kernel/operator lines; prior model-authored findings are isolated in
nonce-delimited untrusted-data framing. Assigned parents are exposed only
through a per-session, read-only bounded tool backed by verified ArtifactStore
manifests and objects.

Invalidated candidate evidence remains in history but does not complete a slot,
round, plateau window, escape round, or bounded search space. Its slot is
reserved again with a deterministic replacement ordinal (and a replacement id
for generated candidates).

**First-pass default and termination.** By default the first passing candidate
is **not** terminal (`stopOnFirstAccept: false`): the loop keeps improving the
incumbent. A terminal `VERIFIED_RESULT` is justified only when one of these
holds, and each carries a distinct basis:

- `first_passing_candidate` — only when the policy sets `stopOnFirstAccept`.
- `rounds_exhausted_with_incumbent` — the frozen rounds ran out with an
  incumbent retained.
- `budget_exhausted_with_incumbent` — the declared command budget ran out with
  an incumbent.
- `plateau_after_mandatory_escape` — a detected plateau survived the mandatory
  escape rounds.

**Plateau escape.** A plateau is detected after `minRoundsBeforePlateau` and a
window of `plateauWindow` consecutive rounds with no improvement or novelty
(metric improvement below `plateauMinImprovement`, and no new
mechanism/content/acceptance novelty). Detection does **not** immediately
terminate: the kernel first requires `mandatoryEscapeRounds` full escape rounds
using only the mandatory-escape operators. Metric-less mechanism or content
novelty during those rounds counts as breaking the plateau. Open-generative
investigations are never declared `TARGET_UNREACHABLE`; a finite/bounded search
space that is fully evaluated without acceptance terminates
`TARGET_UNREACHABLE` with a `search_space_exhausted` evidence closure.
`certified_impossibility` is distinct: it freezes an `impossibilityPolicy`
(`search_exhausted` trigger plus request/certificate schema versions), completes
the ordinary search first, then runs the kernel-reserved allowlisted verifier.
Only non-invalidated evidence with verdict `target_unreachable` yields
`TARGET_UNREACHABLE`; negative/invalid certificates are non-results, invalidated
certificates are retried deterministically, and stop requests remain pauses.

## Domain v2 is a hard cutover

Domain v2 is a **hard cutover with no v1 compatibility path**. The frozen
`searchPolicy` is required and must already be in canonical kernel form —
`crucible_start` supplies the canonical `DEFAULT_SEARCH_POLICY` when a caller
omits it, and the schema fills partial policies with canonical defaults. Any
event history stamped with an older `domainVersion` fails replay with a typed
restart-required error rather than being migrated; such an investigation must be
restarted under a new identity. The deterministic investigation-id namespace
includes `DOMAIN_VERSION`, so a v2 start cannot reopen the corresponding v1
state directory.

## State model

Each investigation uses a local SQLite WAL event store plus a content-addressed
artifact store. Domain decisions are replayable from an append-only hash chain.
Domain observation/evidence appends atomically validate the current lease,
fencing token, and attempt transition in the same SQLite transaction. External
effects also carry a lease-independent logical effect key; recovery verifies and
reuses committed proposal/measurement artifacts while conservatively rerunning
uncertain dispatched work. Terminal decisions are unique database-constrained
events. `crucible_result` reports only persisted terminal
events and never recomputes policy; every terminal decision carries the evidence
closure the kernel sealed when it fired. Deadlines, pauses, failures, and budget
exhaustion remain explicit non-results.
