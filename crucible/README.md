# Crucible

Crucible is a persistent, local, evidence-judged investigation runner. The
current event domain is **v3**. Model workers propose bounded candidate file
sets; an operator-selected harness measures them; the kernel alone records
domain decisions.

A worker session always exposes `crucible_submit_candidate`. It conditionally
also exposes `crucible_read_parent_artifact` when parent snapshots are assigned.
Workers do not receive built-in shell/file tools, config discovery, or raw
ArtifactStore access.

The allowlist establishes which harness bytes the operator has chosen to trust
and freezes their identity. It does **not** prove that the harness is
semantically correct, unbiased, or deterministic. Validation cases calibrate
the selected harness; they are not a substitute for reviewing the harness.

## Requirements and layout

- **Node.js 24+** is the supported development/release baseline.
- Investigation state and all runtime paths must be on a trusted local
  filesystem.
- Harnesses that execute candidate code require the Windows containment
  provider described below.

```text
crucible/
  extension.mjs             four-tool SDK adapter
  api/                      schemas, environment resolution, preflight, handlers
  domain/                   v3 contract, reducer, strategy, archive, decisions
  persistence/              SQLite event repository, CAS, audit bundles
  measurement/              allowlist, parser, executor, Windows containment
  runtime/                  worker pool, runner, supervisor, config
  tools/configure-harness.mjs
  __tests__/

../scripts/
  run-crucible-integration.mjs
  run-crucible-windows-conformance.mjs

../vitest.config.mjs
../vitest.crucible-release.config.mjs
../vitest.crucible-integration.config.mjs
../vitest.windows-conformance.config.mjs
```

## Public API: exactly four tools

All argument objects are strict (`additionalProperties: false`).

### `crucible_start`

New-investigation form:

```text
crucible_start({
  objective: string,
  project_dir: absolute-local-directory,
  harness_id: lowercase-safe-id,
  acceptance_predicate: object,
  hypothesis_topology:
    "finite_enumerable" | "bounded_parameterized" |
    "open_generative" | "certified_impossibility",
  validation_cases: [
    { id: lowercase-safe-id, expectation: "accept" | "reject", path: string },
    ...
  ],
  worker_models: [safe-model-id, ...],
  candidates_per_round: integer,
  max_rounds: integer,
  metrics?: [{ key, direction: "min" | "max", epsilon? }, ...], // default []
  search_policy?: {
    stopOnFirstAccept?: boolean,
    plateauWindow?: integer,
    minRoundsBeforePlateau?: integer,
    plateauMinImprovement?: number,
    mandatoryEscapeRounds?: integer,
    operatorWeights?: {
      fresh?: integer, refinement?: integer, crossover?: integer,
      diversification?: integer, adversarial?: integer, restart?: integer
    },
    archiveCaps?: {
      accepted?: integer, nearMisses?: integer, rejected?: integer,
      invalidMetrics?: integer, mechanismGroups?: integer,
      lessonGroups?: integer, duplicateIndex?: integer
    },
    promptCaps?: {
      parentEvidenceIds?: integer,
      promptContextRefs?: integer
    },
    dedupPolicy?: "mark"
  },
  bounded_candidate_ids?: [safe-id, ...],
  deadline_iso?: ISO-8601-with-timezone,
})
```

`bounded_candidate_ids` is required for `finite_enumerable` and
`bounded_parameterized`, and forbidden for the other two topologies.
The acceptance grammar supports exactly `harness_pass`, `constant`,
`field_equals`, `number_compare`, `metric_compare`, `all`, `any`, and `not`
nodes. A supplied deadline must be a future timestamp with an explicit zone.

Reattach form:

```text
crucible_start({
  investigation_id: string,
  deadline_iso?: later-ISO-8601-with-timezone,
  reset_policy?: "circuit_open" | "failed",
})
```

The forms are mutually exclusive. Reattach does not accept the original
project, case, harness, model, or policy fields. A replacement deadline must be
later than the persisted one; `reset_policy` is valid only for the matching
persisted operational non-result.

### `crucible_status`

```text
crucible_status({ investigation_id: string })
```

This is never a result. A terminal investigation returns only
`{is_result:false, investigation_id, terminal_available:true}`. It does not
expose the decision or winner.

For a normal nonterminal read, the payload contains:

- `terminal_available`, `non_result`, `non_result_code`, `paused`, and domain
  `status`;
- `progress`: event sequence, attempted/observed/accepted counts, incumbent
  availability, next round/slot, partial/completed-round state, bounded/round
  completion, plateau/escape state, operator mix, archive counts, duplicates,
  stop requests, pauses, and domain non-result count;
- `supervisor_health`: presence/state/PIDs, ownership-qualified liveness,
  heartbeat, restart count, and any ensure/restart action;
- a redacted `next_recommendation` (`kind`, `code`, `command_kind`, `recorded`)
  or `null`, plus a human-readable note.

If structural replay/integrity verification fails, status returns an
`integrity_blocked` non-result payload and does not trust terminal state.
It attempts to ensure/restart a missing supervisor only while the domain is
nonterminal, unpaused, and free of domain/operational non-results.

### `crucible_stop`

```text
crucible_stop({
  investigation_id: string,
  reason?: string,
})
```

The response distinguishes `already_terminal`, `operational_non_result`,
`domain_non_result`, `pause_persisted`, and `pause_requested`.
`resumable:true` means the kernel-owned pause event is durable. It does **not**
by itself prove that every worker/session/process has already quiesced.
Supervisor status may separately retain fenced `pause_pending` or
`failed_non_quiescent` authority when cleanup cannot be proven.

### `crucible_result`

```text
crucible_result({ investigation_id: string })
```

This is the only result-emitting tool. It replays repository/domain state and,
for a terminal event, verifies the persisted artifact closure for all harness
evidence before returning:

- `is_result:true`, `decision`, terminal/event/contract hashes;
- winner/evidence identifiers when applicable;
- the kernel-sealed `basis` and `evidence_closure`.

Every nonterminal, paused, non-result, or integrity-blocked state returns
`is_result:false` with no winner payload.

## Admission, environment, and reattach

Preflight may read operator-owned inputs and create a disposable local staging
workspace, but it does not create/mutate durable investigation state. Apply
consumes only the validated preflight plan.

| Requirement | New start | Reattach |
|---|---:|---:|
| `CRUCIBLE_STATE_ROOT`, or `LOCALAPPDATA` for the default | yes | yes |
| `CRUCIBLE_ALLOWLIST_PATH`, or default under `LOCALAPPDATA` | yes | loaded from persisted supervisor config |
| `COPILOT_SDK_PATH` absolute local path | yes | persisted path must still validate |
| `CRUCIBLE_CLI_PATH`, `COPILOT_CLI_PATH`, or `copilot` on `PATH` | yes | persisted path must still validate |
| Existing absolute-local `project_dir` and case directories | yes | no |
| Event DB, artifact store, frozen contract, supervisor config | no | yes |
| Current allowlist/harness bytes still match frozen identity | yes | yes |
| Current sandbox admission when `executesCandidateCode:true` | yes | yes |

Reattach verifies the persisted contract, supervisor config, validation
snapshots, operational state, and frozen harness/sandbox identity. Terminal and
domain-non-result investigations require a new identity. Operational recovery
may require a later deadline or explicit reset policy.

Default locations:

```text
%LOCALAPPDATA%\Crucible\harnesses.json
%LOCALAPPDATA%\Crucible\investigations\<investigation-id>\
  state\events.sqlite
  state\supervisor\<id>.config.json
  state\supervisor\<id>.status.json
  artifacts\
```

The persisted supervisor config contains only runtime configuration:

```text
runner {
  investigationId, stateDir, artifactRoot, allowlistPath,
  copilotSdkPath, copilotCliPath, runnerEpochId, deadline, options
}
runnerCliPath, supervisorEpochId, maxRestarts,
baseBackoffMs, maxBackoffMs, heartbeatIntervalMs,
staleLockMs, circuitWindowMs
```

It does not contain a terminal decision, winner, evidence closure, or raw case
bytes. Those remain in the event repository/CAS. Status and runner-outcome
files are intentionally opaque lifecycle channels.

## Contract and execution limits

### Frozen contract

| Item | Limit |
|---|---:|
| Objective | 2,048 characters and 2,048 UTF-8 bytes |
| Acceptance predicate | 4,096 bytes; depth 16; 128 nodes; 32 children per boolean node |
| Predicate paths | 16 segments; 128 characters per segment |
| Predicate literal values | depth 8; 128 nodes; arrays 32; objects 32 properties; strings 1,024 characters / 2,048 bytes |
| Ranking metrics | 12 |
| Validation cases | 64, including at least one accept and one reject |
| Worker models | 8 distinct ids |
| Candidates per round | 8 |
| Rounds | 64 |
| Candidate evaluations | 512 |
| Bounded candidate ids | 512 |

Search-policy maxima are 64 for plateau window/minimum/escape rounds; archive
cohorts and mechanism/lesson groups are each capped at 32; duplicate index at
256; prompt context at 12 evidence refs; parents at 4. The public start path
freezes `declaredLimits:{}` and does not expose a domain command-budget knob.
Operator weights are integers `0..1,000,000`; `fresh` must remain enabled and
at least one escape operator must remain enabled. `minRoundsBeforePlateau`
cannot be lower than `plateauWindow`, and the parent cap cannot exceed the
prompt-reference cap.

### Worker proposal and prompt limits

| Item | Limit |
|---|---:|
| Candidate files | 32 |
| Relative path | 512 bytes |
| One file | 256 KiB |
| Total candidate content | 1 MiB |
| Annotation mechanism | 256 characters / bytes |
| Hypothesis | 2,048 characters / 4,096 bytes |
| Expected effects | 16 × 512 characters/bytes |
| Finding | 1,024 characters/bytes |
| Cited evidence ids | 12 |
| All annotations | 16 KiB |
| Trusted operator context | 2 KiB |
| Irreducible prompt context | 16 KiB default |
| Final proposal prompt | 32 KiB |

The optional parent reader is additionally bounded to 8 assigned parents,
32 calls, 256 listed entries, 64 KiB per chunk, 512 KiB per session, and
1 MiB per file. Public search policy assigns at most 4 parents.

### Measurement and storage limits

- Harness-config and allowlist files: 1 MiB each.
- Allowlist: at most 1,024 entries; argv template 256 items; dependencies 64;
  validation-case map 4,096 entries.
- General config strings are capped at 4,096 characters; argv items at 4,096;
  ids at 128; dependency roles at 64; allowed-environment values at 32,768.
- Harness timeout: at most 1 hour; stdout/stderr caps: at most 64 MiB each.
- Strict result parser: at most 8 MiB stdout; optional `metrics` and
  `validationCases` records each allow at most 4,096 keys.
- Default cumulative budgets:
  - output: 16 MiB/attempt, 256 MiB/investigation;
  - receipts: 2 MiB/attempt, 64 MiB/investigation;
  - CAS: 32 MiB/attempt, 2 GiB/investigation.

Runner loop, external-effect, and restart budgets are derived from the frozen
round/candidate/case topology plus safety margins. These are operational
containment budgets. They are not the public domain command budget and do not
create a `budget_exhausted_with_incumbent` basis in normal extension starts.
Normalized runner options cap session timeout at 1 hour, shutdown timeout at
60 seconds, and loop iterations at 1,000,000. Supervisor config accepts at most
100 restarts, but public starts derive a lower maximum capped at 12.

## Configuring the harness allowlist

Use the operator CLI; the extension never authors the allowlist:

```text
node tools/configure-harness.mjs --config <config.json> [--allowlist <path>] [--replace]
```

The strict config accepts exactly these keys:

```json
{
  "id": "example-harness",
  "executable": "C:\\Program Files\\nodejs\\node.exe",
  "argvTemplate": [
    "C:\\trusted\\crucible-harness.mjs",
    "{{candidatePath}}",
    "{{attemptId}}"
  ],
  "cwd": "C:\\trusted",
  "dependencies": [
    { "path": "C:\\trusted\\crucible-harness.mjs", "role": "script" }
  ],
  "allowedEnv": {},
  "timeoutMs": 30000,
  "maxStdoutBytes": 1048576,
  "maxStderrBytes": 262144,
  "executesCandidateCode": false,
  "validationCases": [
    {
      "id": "accepts-known-good",
      "expectation": "accept",
      "sourceDir": "C:\\cases\\good",
      "description": "must accept"
    },
    {
      "id": "rejects-known-bad",
      "expectation": "reject",
      "sourceDir": "C:\\cases\\bad"
    }
  ],
  "description": "example"
}
```

`cwd`, `dependencies`, `allowedEnv`, and `description` may be omitted; the
other keys are required. Unknown keys are rejected. Static file arguments in
`argvTemplate` must be declared dependencies. `--replace` is required only
when replacing an existing id with a different executable.

The CLI verifies local non-symlink files/directories, hashes executable and
dependencies, computes validation snapshot ids in a disposable ArtifactStore,
preserves unrelated entries, writes atomically with a `.bak`, and re-loads the
exact installed bytes through the production parser. The generated allowlist
stores validation snapshot ids and optional descriptions, not accept/reject
expectations.

## Harness output

The harness must emit exactly one JSON object followed only by whitespace.
`pass` is the only required field:

```json
{
  "pass": true,
  "metrics": { "score": 1.0 },
  "validationCases": { "accepts-known-good": true },
  "searchSpaceExhausted": false,
  "impossibilityCertificateHash": "sha256:<algorithm-tag>:<64hex>"
}
```

All four fields after `pass` are optional and normalize to `null` when absent.
Unknown top-level fields, duplicate JSON keys, non-finite metrics, trailing
content, and output overflow are rejected. Declared metrics rank candidates;
missing metrics do not overturn an accepted candidate. Accepted-but-unrankable
candidates sort behind rankable accepted candidates; non-accepted candidates
with incomplete metrics become `invalid_metrics`. The optional
`impossibilityCertificateHash` is not authority for unreachability; only the
kernel-bound verifier observation and persisted artifact/receipt closure can
qualify.

Every executable/dependency is reverified, privately staged, and rehashed for
each attempt. Receipts bind the allowlist/harness identity, concrete argv/env,
candidate closure, output bytes, parser, sandbox policy, and attempt identity.

## Candidate-code containment on Windows

`executesCandidateCode:true` fails admission unless the Windows provider probe
succeeds. It uses a zero-capability AppContainer/lowbox plus Job Object, with a
hash-pinned helper compiled by the inbox .NET Framework C# compiler and loaded
through inbox Windows PowerShell.

Prerequisites and limitations are explicit:

- Windows, the inbox .NET Framework `csc.exe`, inbox Windows PowerShell, and
  NTFS ACL support are required.
- Paths unsupported by the inbox .NET Framework runtime fail admission.
- AppContainer can still read resources ACLed to `ALL APPLICATION PACKAGES`.
- Host IPC endpoints permissively ACLed for AppContainers may remain reachable.
- Same-user processes outside the candidate Job Object are outside this
  containment boundary.

Non-candidate-executing harnesses do not require AppContainer, but Windows
harness/runner processes still use kill-on-close Job ownership and bounded
cleanup. Working-directory isolation, filtered environment, timeouts, and
process-tree termination alone are not represented as a sandbox.

## Domain-v3 search and termination

Domain v3 is a hard cutover: the domain version participates in investigation
identity, and older-version event history is not migrated in place.

Each slot freezes round, slot, candidate id, model, operator, parent evidence,
prompt refs, replacement ordinal, and deterministic seed. Invalidated candidate
evidence remains in history but does not complete the slot; the same slot is
reserved again with an incremented replacement ordinal (and a retry-suffixed id
for generated candidates).

Operators are `fresh`, `refinement`, `crossover`, `diversification`,
`adversarial`, and `restart`. Crossover requires two distinct active parents.
It **prefers** parents from different mechanism groups when available, then
falls back to the first two distinct eligible candidates.

The default does not stop on first accept. A normal public investigation can
reach:

- `VERIFIED_RESULT`: first passing candidate only when configured, rounds
  exhausted with an incumbent, or plateau completion after mandatory escape;
- `TARGET_UNREACHABLE`: complete finite/bounded coverage without acceptance,
  or a qualifying certified-impossibility certificate;
- a resumable pause, a domain non-result, or an operational non-result.

The domain also supports a declared-command-budget termination basis, but the
public start schema does not expose that budget. Derived runner/effect/restart
limits are operational and can stop the runtime without becoming a positive
domain result.

For `certified_impossibility`, verification runs only after validation and all
frozen search slots complete without acceptance. A positive
`pass:true + searchSpaceExhausted:true` certificate can qualify. A persisted
`not_proven` or `invalid` certificate becomes an inconclusive domain
non-result; it is not retried. Only **invalidated** certificate evidence is
ignored and deterministically retried with the next attempt ordinal.

## Replay, result closure, and bundles

Domain replay verifies the repository structure, event/artifact-reference
bindings, domain hash chain, and reducer transitions. It deterministically
reconstructs domain state and recommendations; it does not re-run model or
harness side effects. Operational evidence has its own verified event stream.
`crucible_result` adds full terminal artifact-closure verification across
harness evidence, measurements, snapshots, raw output, receipts, and decisive
basis.

Persistence bundles are self-contained and internally hash-verifiable, but
authenticity is out of band:

- export reports `trustLevel:"self-consistent"`;
- import requires an expected digest/signature by default;
- `allowUnauthenticated:true` permits import only as `self-consistent`, with
  `authenticated:false` and `verified:false`.

Do not treat an unauthenticated bundle as proof of who produced it.

## Release validation

Crucible release validation has four layers:

1. `npm run test:crucible` — fast, credential-free, host-independent suite.
2. `npm run test:crucible:release-safe` — release-only hard-kill,
   multiprocess, and long real-process matrices.
3. `npm run test:crucible:integration` — mandatory authenticated real SDK/CLI
   smoke; requires absolute `COPILOT_SDK_PATH` and `COPILOT_CLI_PATH`.
4. `npm run test:crucible:windows-conformance` — serial native Windows
   containment boundary.

`npm run test:crucible:release` runs all four. `npm run test:release` adds the
remaining workspace suites. Native containment and real authenticated SDK/CLI
coverage are intentionally not part of the default developer command.
