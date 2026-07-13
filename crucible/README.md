# Crucible

Crucible is a persistent, local, evidence-judged investigation runner. The
current event domain is **v4**. Model workers propose bounded candidate file
sets against a frozen statistical contract; an operator-selected
`HarnessSuiteV4` measures them; the kernel alone records domain decisions.

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
  domain/                   v4 contract, reducer, strategy, archive, decisions
  persistence/              SQLite event repository, CAS, audit bundles
  measurement/              allowlist, parser, executor, Windows containment
  runtime/                  worker pool, measurement scheduler, runner, supervisor
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
  experiment_id: lowercase-safe-operator-experiment-id,
  deadline_iso?: ISO-8601-with-timezone,
})
```

The public tool does not accept objective, acceptance, topology, enumerand,
hypothesis, harness, worker, or statistical-policy authority. Installing that
authority is a detached-signature workflow:

```powershell
# 0. Configure the public trust root first; its fingerprint is signed into the
#    manifest. The private key remains offline.
$env:CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH = "C:\operator\operator-ed25519-public.pem"
$env:CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT = "sha256:crucible-experiment-public-key-v1:<64-hex>"

# 1. Crucible prepares the exact canonical bytes. This does not install.
node crucible/tools/configure-experiment.mjs `
  --config C:\operator\experiment.json `
  --prepare-manifest C:\operator\experiment.manifest.json

# 2. Sign outside Crucible. The private key never enters Crucible or its env.
openssl pkeyutl -sign -rawin `
  -inkey C:\offline\operator-ed25519-private.pem `
  -in C:\operator\experiment.manifest.json `
  -out C:\operator\experiment.sig

# 3. Import under that same configured trusted public key.
node crucible/tools/configure-experiment.mjs `
  --config C:\operator\experiment.json `
  --signature-file C:\operator\experiment.sig
```

Do not reformat, append a newline to, or regenerate the prepared manifest before
external signing. Installation reconstructs the canonical manifest from the
config and current allowlisted suite, then verifies the detached signature over
those exact bytes before writing the registry. The programmatic
`configureExperiment` entry point accepts detached bytes in its `signature`
field; neither interface contains private-key generation or signing code.

The running extension accepts one trust source:

- `CRUCIBLE_EXPERIMENT_PUBLIC_KEY`: Ed25519 public key as PEM or canonical
  base64 (DER SPKI or raw 32-byte key); or
- `CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH`: absolute local non-link public-key
  file, together with mandatory
  `CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT`.

The fingerprint format is
`sha256:crucible-experiment-public-key-v1:<64-lowercase-hex>` over the DER SPKI
bytes. For example:

```powershell
openssl pkey -pubin -in C:\operator\operator-public.pem `
  -outform DER -out C:\operator\operator-public.der
$hex = (Get-FileHash C:\operator\operator-public.der -Algorithm SHA256).Hash.ToLowerInvariant()
$env:CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH = "C:\operator\operator-public.der"
$env:CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT = "sha256:crucible-experiment-public-key-v1:$hex"
```

An inline key may also supply the fingerprint; if present it must match. A key
path without the expected fingerprint is rejected because a mutable file path
is not a trust root.

The strict operator config (not a `crucible_start` argument) contains:

```text
{
  experiment_id: lowercase-safe-id,
  objective: string,
  project_dir: absolute-local-directory,
  harness_suite_id: lowercase-safe-id,
  acceptance_predicate: object,
  hypothesis_topology:
    "finite_enumerable" | "bounded_parameterized" |
    "open_generative" | "certified_impossibility",
  enumerand_manifest?: {
    topology: "finite_enumerable" | "bounded_parameterized",
    entries: [
      // finite: { id, ordinal, artifactSnapshotHash }
      // bounded: { id, ordinal, parameterTuple }
    ],
    control:
      { kind: "enumerand", ordinal } |
      { kind: "snapshot", snapshotHash }
  },
  observable_registry: [
    { key, kind: "numeric", minimum, maximum } |
    { key, kind: "categorical", values },
    ...
  ],
  hypothesis_policy: {
    required, maxPredictions, allowedKinds, allowRequiredForResult
  },
  statistical_policy: {
    version: "crucible-statistical-policy-v4",
    goalMode: "satisfice" | "optimize",
    metrics: [{
      key, priority?, minimum, maximum, estimand, unit, direction,
      acceptanceThreshold, practicalEquivalenceDelta, family
    }, ...],
    investigationAlpha,
    familyAllocations: [{ family, alpha }, ...],
    minBlocks, maxBlocks,
    control:
      { kind: "enumerand", identity, tolerances } |
      { kind: "snapshot", identity, tolerances },
    missingness: { mode, maxMissingPerBlock, maxMissingFraction },
    deterministicBlockSeed,
    maxConfirmations,
    evaluationBudget: {
      maxCandidateEvaluations, maxControlEvaluations, maxTotalEvaluations
    },
    resourceBudget: {
      perAttemptOutputBytes, perInvestigationOutputBytes,
      perAttemptReceiptBytes, perInvestigationReceiptBytes,
      perAttemptCasBytes, perInvestigationCasBytes
    }
  },
  worker_models: [safe-model-id, ...],
  candidates_per_round: integer,
  max_rounds: integer,
  search_policy?: {
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
      inconclusive?: integer,
      invalidMetrics?: integer, mechanismGroups?: integer,
      lessonGroups?: integer, duplicateIndex?: integer
    },
    promptCaps?: {
      parentEvidenceIds?: integer,
      promptContextRefs?: integer
    },
    dedupPolicy?: "mark"
  },
}
```

`enumerand_manifest` is required for `finite_enumerable` and
`bounded_parameterized`, and forbidden for the other two topologies. Snapshot
ids must already exist in the durable operator corpus; preflight verifies and
copies their complete CAS closures. Labels-only bounded candidate lists and
`stopOnFirstAccept` are rejected. Open generative investigations are never
treated as exhaustible.

The selected `HarnessSuiteV4` must provide calibration, search, confirmation,
challenge, and novelty roles. `certified_impossibility` additionally requires
the independent verifier role. Calibration expectations and every role case
snapshot come from the configured operator corpus; callers cannot supply or
relabel them.
Statistical acceptance supports `metric_compare`, `harness_pass`, or an `all`
conjunction of those claims. Metric comparisons must exactly match the frozen
metric direction and acceptance threshold. `harness_pass` is the only contract
form that gives the raw `pass` field acceptance meaning. A supplied deadline
must be a future timestamp with an explicit zone.

### Operator-signature boundary

The signed manifest contains the complete canonical experiment payload
(`experiment_id`, canonical project identity, suite id, and sealed contract),
plus the contract hash, HarnessSuiteV4 identity, enumerand Merkle root (or
`null`), statistical-policy identity, hypothesis-policy identity, exact trusted
public-key fingerprint, and the deterministically derived investigation id.
Registry entry/registry self-hashes are integrity checks only and cannot
substitute for the Ed25519 signature.

`--replace` requires a fresh valid detached signature under the same configured
trust root. New-start preflight verifies the registry bytes, exact manifest,
signature, and current key fingerprint before creating investigation state, and
apply verifies them again. Successful verification yields a process-local opaque
capability; the domain repository accepts only that capability for opening and
persists its underlying signed envelope. The opening event records the complete
manifest, signature, fingerprint, and authority identity; the event hash chain
and authority-bound investigation id make them part of persisted evidence identity.
Reattach ignores mutable registry authority and instead re-verifies that exact
persisted envelope against the current public key. A trust-key change produces
`CRUCIBLE_API_EXPERIMENT_AUTHORITY_MISMATCH` and requires a new investigation.
Status performs the same verification before advertising `terminal_available`;
result repeats it, recomputes the signed investigation id, and discloses no
winner or hash if authority is absent or mismatched.

The signature proves possession of the configured operator private key approved
those exact bytes. It does not prove the harness is correct, deterministic, or
unbiased, and it does not provide registry rollback/freshness protection. Keep
the private key outside Crucible, review the manifest before signing, and manage
registry history/rotation as an operator concern. Public keys and fingerprints
are intentionally non-secret.

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

This is never a result. A scientifically ready terminal returns only
`{is_result:false, investigation_id, terminal_available:true}`. A legacy,
synthetic, search-only, or scientifically incomplete terminal reports
`terminal_available:false` and exposes no decision, candidate, evidence, or
hash payload.

For a normal nonterminal read, the payload contains:

- `terminal_available`, `non_result`, `non_result_code`, `paused`, and domain
  `status`;
- `progress`: event sequence, attempted/observed/accepted counts, passing-candidate
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
- unique-candidate or supported tie-cohort identifiers when applicable;
- the frozen-priority pairwise relation and cohort closure;
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
| `CRUCIBLE_EXPERIMENT_PUBLIC_KEY`, or pinned `CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH` + `CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT` | yes | yes; must match persisted authority |
| `CRUCIBLE_ALLOWLIST_PATH`, or default under `LOCALAPPDATA` | yes | immutable opening authority path must still validate |
| `CRUCIBLE_CASE_STORE_PATH`, or `operator-corpus` beside the default allowlist | yes | no; frozen snapshots are already copied into the investigation CAS |
| `COPILOT_SDK_PATH` absolute local path | yes | persisted path must still validate |
| `CRUCIBLE_CLI_PATH`, `COPILOT_CLI_PATH`, or `copilot` on `PATH` | yes | persisted path must still validate |
| Existing absolute-local `project_dir` | yes | no |
| Event DB, artifact store, frozen contract, supervisor config | no | yes |
| Current allowlist/suite role bytes still match the frozen suite identity | yes | yes |
| Current sandbox admission for every role that executes candidate code | yes | yes |

The opening event persists a canonical runtime-config authority and fingerprint:
supervisor/runner options, worker additional context plus its hash, state/
artifact/allowlist paths, runner CLI path/hash, SDK entry identity, Copilot CLI
identity, Node runtime identity, and sandbox identity. Reattach treats the
supervisor config file as a deadline carrier only: every other field must match
the opening authority, and the launch config is reconstructed from that
immutable source. Tampering leaves a paused investigation paused. Terminal and
domain-non-result investigations require a new identity; operational recovery
may require a later deadline or explicit reset policy.

Default locations:

```text
%LOCALAPPDATA%\Crucible\harnesses.json
%LOCALAPPDATA%\Crucible\experiments.json
%LOCALAPPDATA%\Crucible\operator-corpus\
%LOCALAPPDATA%\Crucible\investigations\<investigation-id>\
  state\events.sqlite
  state\supervisor\<id>.config.json
  state\supervisor\<id>.status.json
  artifacts\
```

The persisted supervisor config contains runtime configuration for the
supervisor process:

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
bytes. It is not reattach authority: immutable fields are checked against the
opening event, and only a schema-validated later deadline may vary. Terminal
evidence remains in the event repository/CAS. Status and runner-outcome files
are intentionally opaque lifecycle channels.

## Contract and execution limits

### Frozen contract

| Item | Limit |
|---|---:|
| Objective | 2,048 characters and 2,048 UTF-8 bytes |
| Acceptance predicate | 4,096 bytes; depth 16; 128 nodes; 32 children per boolean node |
| Predicate paths | 16 segments; 128 characters per segment |
| Predicate literal values | depth 8; 128 nodes; arrays 32; objects 32 properties; strings 1,024 characters / 2,048 bytes |
| Statistical metrics | 12, each with frozen priority, finite bounds, estimand/unit, direction, threshold, and equivalence delta |
| Calibration cases | 64, operator-owned, including at least one accept and one reject |
| Worker models | 8 distinct ids |
| Candidates per round | 8 |
| Rounds | 64 |
| Candidate evaluations | 512 |
| Immutable enumerands | 512 |
| Alpha families | 32 |
| Blocks | 4,096 |
| Confirmations | 64 |
| Frozen statistical evaluations | 100,000 |

Metric/family/control order is canonicalized before hashing. Family names are
unique and their alpha allocations must sum to the finite investigation alpha.
Metric bounds must exactly match numeric observable registrations. Control
tolerances cover every metric exactly once. Finite/bounded control identity must
match the manifest; other topologies require a durable snapshot control.
Evaluation capacity must cover the frozen search, block, confirmation, control,
calibration, and optional verifier workload.
Runtime admission independently derives the worst-case role × block × arm count.
The frozen per-investigation output, receipt, and CAS budgets must cover that
count at their corresponding per-attempt caps; underprovisioned configurations
are rejected before effects.

### Deterministic blocked replication

Every search subject receives a canonical schedule derived from the contract
hash, subject/enumerand identity, frozen control, `minBlocks`, `maxBlocks`, and
`deterministicBlockSeed`. The schedule and seed are persisted before proposal or
measurement effects. Candidate and control use the exact frozen `search` role.
Within each block, a seeded base permutation is cyclically rotated, balancing
arm position while leaving each arm's seed independent of execution order.

Each raw arm attempt has stable block, replicate, arm, subject, and seed
bindings and its own receipt/stdout/stderr/snapshot artifact closure. A candidate
evidence item references the schedule artifact, a raw-complete-block composite,
and every raw measurement. Runner observations and composites contain no claim
state, pass/fail verdict, matched label, acceptance decision, or outcome class.
The kernel recomputes those from the raw blocks. Persisted means, confidence
sequences, claim states, alpha ledgers, control-tolerance metadata, calibration
states, and candidate support are cache only: each cache has a deterministic
digest and reducer replay canonical-compares it with a fresh raw-block
derivation before the value can enter domain state.

Only contiguous complete blocks from zero enter the statistical kernel. Partial
blocks resume at the exact missing arm after restart. Invalid or missing
candidate/control observations remain in their block and are handled by the
frozen missingness policy rather than selectively dropped. Out-of-bounds values,
invalid attempts, and control-drifted blocks become missing blocks and cannot
support acceptance. Replication continues through the minimum while required claims are unresolved.
Satisfice mode may stop when they resolve. Optimize mode keeps consuming the
candidate's preregistered blocks through `maxBlocks` so later pairwise
superiority/equivalence decisions do not inherit an early-stop ordering bias.
Either mode stops when `maxBlocks` is reached or the evaluation budget cannot
admit another complete block.

Calibration uses the same `evaluateStatisticalClaims` path. The signed
known-positive corpus must produce `SUPPORTED`; known-negative cases must
produce `REFUTED`. Calibration covers the frozen calibration, search,
confirmation, and challenge execution roles (identity-equivalent roles may
share one raw execution) before search starts. Each unsuccessful calibration
block is durable and retried only through the frozen `maxBlocks` bound. Exhaustion
records `VALIDATION_INCONCLUSIVE`; it never loops indefinitely or becomes a
result.

Candidate `outcomeClass` is kernel-derived from every required acceptance claim:
all `SUPPORTED` is `accepted`, any `REFUTED` is `rejected`, `INVALID` is
`invalid_metrics`, and unresolved evidence is `inconclusive`. A max-block
unresolved candidate remains inconclusive rather than becoming a rejection or
acceptance.

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
| Irreducible prompt context | 24 KiB default |
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

Runner loop, external-effect, restart, output, receipt, and CAS budgets are
derived from (or capped by) the frozen statistical evaluation/resource policy.
Admission rejects policies that cannot cover their declared topology or whose
per-investigation byte ceilings are below their per-attempt ceilings. These are
operational containment budgets; they do not grant terminal authority.
Normalized runner options cap session timeout at 1 hour, shutdown timeout at
60 seconds, and loop iterations at 1,000,000. Supervisor config accepts at most
100 restarts, but public starts derive a lower maximum capped at 12.

## Configuring the harness allowlist

Use the operator CLI; the extension never authors the allowlist:

```text
node tools/configure-harness.mjs --config <config.json> [--allowlist <path>] [--case-store <path>] [--replace]
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
dependencies, ingests validation snapshots into a durable operator-owned CAS
(by default `operator-corpus` beside the allowlist), preserves unrelated
entries, writes atomically with a `.bak`, and re-loads the exact installed bytes
through the production parser. The generated allowlist stores snapshot ids and
immutable operator expectations; admission callers cannot relabel them.

### HarnessSuiteV4 authoring

A suite config composes already-authored harness entries into the required
`calibration`, `search`, `confirmation`, `challenge`, and `novelty` roles, plus
an optional `impossibility_verifier`:

```json
{
  "kind": "HarnessSuiteV4",
  "version": 4,
  "id": "mesh-suite",
  "environment": { "platform": "windows-x64", "driver": "pinned" },
  "sharedPlatformDependencies": [],
  "roles": {
    "calibration": {
      "harnessId": "mesh-calibration",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["cal-good", "cal-bad"],
      "deterministicSeed": "calibration-seed-v1",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "search": {
      "harnessId": "mesh-search",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["search-a"],
      "deterministicSeed": "search-seed-v1",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "confirmation": {
      "harnessId": "mesh-confirmation",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["held-out-a"],
      "deterministicSeed": "confirmation-seed-v1",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "challenge": {
      "harnessId": "mesh-challenge",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["challenge-a"],
      "deterministicSeed": "challenge-seed-v1",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "novelty": {
      "harnessId": "mesh-novelty",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["novelty-a"],
      "deterministicSeed": "novelty-seed-v1",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    }
  }
}
```

The suite identity binds each role's executable, parser, dependencies,
operational config, observable-schema hash, case manifest, deterministic seed,
and sandbox identity. Confirmation/challenge/novelty manifests must be disjoint
from calibration/search; their case ids and snapshot ids are removed from the
worker projection. A verifier must have a separate executable/parser/application
implementation closure: parser identities cannot be reused as primary
executables or application dependencies (or vice versa), and application files
cannot be laundered as platform-shared. Separation compares the validated raw
SHA-256 digest bytes, not the surrounding domain tag, across executables, parser
sources, and application/entrypoint dependencies. Every shared dependency must
be explicitly classified as `"platform"` or `"runtime"`; no role executable,
parser, or application entrypoint digest may appear in that shared set. Only
genuine declared platform/runtime dependencies may overlap. `crucible_start`
resolves only the suite frozen in the
selected operator experiment; preflight reloads the durable allowlist, verifies
every required role and case snapshot, freezes the complete suite + identity
into the contract, and stages the snapshot closures before investigation state
is created.

## Harness output

The harness must emit exactly one JSON object followed only by whitespace.
`pass` is the only required field:

```json
{
  "pass": true,
  "metrics": { "score": 1.0 },
  "observables": { "outcome": "accepted" },
  "role": "confirmation",
  "phase": "confirmation",
  "replicateIndex": 0,
  "blockIndex": 2,
  "armIndex": 0,
  "armId": "candidate",
  "deterministicSeed": "confirmation-seed-v1",
  "subjectId": "candidate-17",
  "environmentIdentity": "sha256:crucible-harness-environment-v4:<64hex>",
  "suiteIdentity": "sha256:crucible-harness-suite-v4:<64hex>"
}
```

The legacy five result fields remain supported. For suite-bound runs, Crucible
passes the ten execution-binding fields shown above in concrete argv and env and
repeats them verbatim in the receipt. If a harness echoes binding fields in its
JSON, the parser requires an exact match to the trusted binding; otherwise the
executor injects the trusted binding into the canonical parsed observation.
Search, confirmation, challenge, novelty, and replicated calibration require
replicate, block, and arm ordinals. Validation may execute calibration, search,
confirmation, or challenge roles with `phase:"calibration"`. Impossibility
verification forbids replication ordinals. `validationCases` is
calibration-phase-only once a role binding is present, while
`searchSpaceExhausted` and `impossibilityCertificateHash` are verifier-only.
Unknown top-level fields, duplicate JSON keys, non-finite metrics, trailing
content, and output overflow are rejected. Metrics named by acceptance claims
are required evidence; other declared metrics are ranking-only. An explicit
`harness_pass` claim can therefore accept a statistically supported candidate
without optional ranking metrics. Accepted-but-unrankable candidates sort
behind rankable accepted candidates. The optional
`impossibilityCertificateHash` is not authority for unreachability; only the
kernel-bound verifier observation and persisted artifact/receipt closure can
qualify.

`observables` is an optional bounded record for registered numeric or
categorical prediction values that are not ranking metrics. Values may be
finite numbers, booleans, or bounded strings. A key cannot appear in both
`metrics` and `observables`; ambiguous duplicate observations fail closed.

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

## Domain-v4 search and termination

Domain v4 is a hard cutover: the domain version participates in investigation
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

The default does not stop on first accept. Accepted candidates are compared
pairwise in frozen metric-priority order from replay-derived confidence
sequences. A relation is `BETTER`/`WORSE` only when the supported margin exceeds
the practical delta; supported bounds wholly inside ±delta are
`PRACTICALLY_EQUIVALENT`; overlap alone is `UNRESOLVED`; missing metric authority
is `INCOMPARABLE`. The non-dominated frontier becomes either one provisional
best candidate or a supported tie cohort. Candidate ids and event order only
stabilize display order and never break scientific ties.

Statistical search support is only a provisional readiness gate and never
terminalizes by itself. When discovery stops, the kernel first persists
`scientific_confirmation_frozen`, binding the provisional unique candidate or
tie cohort, discovery head, relation closure, held-out role manifests,
candidate-dependent challenge seed policy, replication schedules, and distinct
alpha subject lanes. It then runs fresh `confirmation` blocks for every cohort
member followed by fresh `challenge` blocks. No confirmation/challenge
manifest, id, bytes, receipt, or raw result is exposed to workers or fed back
into search, and no research round follows the freeze.

Every cohort member must independently resolve both held-out roles to
`SUPPORTED`. Refutation, invalid evidence, unresolved claims at the frozen
block limit, invalidation, budget exhaustion, or attempted cohort/alpha reuse
ends as `SCIENTIFIC_CONFIRMATION_FAILED`; it never resumes search. A fully
supported closure makes the aggregate scientifically ready, but
`VERIFIED_RESULT` is still emitted only by the subsequent kernel decision
gate. Unresolved/incomparable discovery relations retain an explicit
preregistered-block plan and become a scientific non-result when those blocks
are exhausted. Finite/bounded exhaustion alone ends as
`INDEPENDENT_VERIFICATION_REQUIRED`; only qualifying evidence from the pinned
independent impossibility-verifier role may support `TARGET_UNREACHABLE`.

Every sealed typed prediction is translated into a frozen statistical claim
and evaluated independently from candidate acceptance over replay-derived
replicated blocks. Outcomes are exactly `SUPPORTED`, `REFUTED`, `UNRESOLVED`,
or `INVALID`, with evidence, block-ledger, estimate/bounds, and alpha-ledger
references. Optional refutations do not erase a successful candidate;
`requiredForResult` predictions must all be `SUPPORTED` before scientific
readiness. Later worker prompts receive supported/refuted outcomes in a
separate kernel-derived findings section, never mixed with prior model prose.
Control directions use paired within-block differences. Assigned-parent
directions use separately replayed parent blocks and an independent two-sample
Hoeffding sequence with a Bonferroni-split claim alpha; that limitation is
carried into the conclusion.

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
harness side effects. The replay result exposes a raw-authority root plus a
byte-canonical scientific aggregate, claim-state ledger, alpha ledger, and
closure hashes. Domain decisions read the compact replay-derived
support/calibration state,
never an unchecked persisted summary. Operational evidence has its own verified
event stream.
The terminal evidence closure carries the supported cohort, pairwise relation
hash/evidence, and one code-authored scientific conclusion per cohort member.
Candidate-performance status remains separate from sealed hypothesis-set
status, and every prediction includes its estimate, confidence bounds,
evidence/block/alpha references, and explicit limitations. Explanatory model
prose is excluded from conclusion authority.
`crucible_result` adds full terminal artifact-closure verification across
harness evidence, measurements, snapshots, raw output, receipts, and decisive
basis, requires the terminal closure to bind the replay-science root, then
rechecks the frozen scientific readiness policy. Persisted
search-only or synthetic terminals remain non-results with all
candidate/evidence/hash fields redacted.

Persistence bundle version 4 is self-contained and internally hash-verifiable.
It includes the event database, every referenced raw receipt/output/snapshot/
schedule/composite object, and a cache-only scientific replay digest. Export and
import both replay the bundled v4 database and reject any mismatch between that
digest and the raw schedule/policy/block history. They also canonical-compare
schedule/composite objects and each raw parsed observation against its
content-addressed receipt before publication or import. Authenticity is out of
band:

- export reports `trustLevel:"self-consistent"`;
- import requires an expected digest/signature by default;
- `allowUnauthenticated:true` permits import only as `self-consistent`, with
  `authenticated:false` and `verified:false`.

Do not treat an unauthenticated bundle as proof of who produced it.

## Development test loop

Use the smallest applicable tier while implementing:

```text
npm exec vitest run -- crucible/__tests__/<affected-file>.test.mjs
npm run test:crucible:unit
npm run test:crucible:changed
```

`test:crucible:unit` covers pure domain/schema/parser behavior and is intended
for the inner edit loop. `test:crucible:changed` asks Vitest for tests related
to changed Crucible files and aborts after 120 seconds; reaching that limit
means the next run should target explicit test files.

The complete safe suite runs once at a phase gate. Hard-kill, multiprocess,
credentialed SDK, and native AppContainer tests remain release-gate work and
must not run after every implementation edit.

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
