# Crucible

Crucible is a persistent, local, evidence-judged investigation runner. Model
workers propose bounded candidate file sets against a frozen statistical
contract; an operator-selected `HarnessSuiteV4` measures them; the kernel alone
records domain decisions.

The scientific kernel is paired with a durable operational lifecycle: active
investigations, immutable verified archives, signed tombstones, leases, recovery
ownership, and interrupted cleanup all live in a durable global catalog. The
runner can recover after process death without trusting PID alone, reconcile
accepted work whose SDK usage report was interrupted, and resume filesystem
transitions from persisted state instead of inferring intent from leftover
directories.

The four public tools intentionally separate authority:

- `crucible_start` admits a signed experiment or reattaches an existing active
  investigation;
- `crucible_status` inventories active, archived, and tombstoned state but can
  never emit a scientific result;
- `crucible_stop` pauses, archives, or deletes through fenced, durable lifecycle
  transitions; and
- `crucible_result` is the only surface that can emit a terminal decision, and
  only after replay, scientific closure, and artifact verification succeed.

Some literal configuration values, hash domains, and command names contain
revision suffixes because they are persisted protocol identifiers. They are
shown only where an operator must provide or recognize the exact string; they
do not name separate Crucible products or releases.

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
  domain/                   contract, reducer, strategy, archive, decisions
  persistence/              event repository, CAS, bundles, resource catalog
  measurement/              allowlist, parser, executor, Windows containment
  runtime/                  workers, scheduler, runner, supervisor, recovery
  tools/                    harness/experiment and recovery-task operator CLIs
  scripts/                  time-bounded, explicit-list test runners
  __tests__/
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

`enumerand_manifest` is required for `finite_enumerable`,
`bounded_parameterized`, and `certified_impossibility`, and forbidden for
`open_generative`. A certified-impossibility manifest declares either the
finite or bounded enumerand representation that the verifier must cover. Snapshot
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
public-key fingerprint, canonical runtime-identity policy plus its initial
Merkle root, and the deterministically derived investigation id.
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
crucible_status({ operation: "get", investigation_id: string })

crucible_status({
  operation: "list",
  cursor?: opaque-cursor,
  limit?: 1..100,
  state_filter?: "active" | "archived" | "tombstoned",
})
```

Both forms are read-only and never results. `get` resolves active state,
verified archives, and signed tombstones through the global catalog. A
scientifically ready terminal still returns only
``{is_result:false, investigation_id, terminal_available:true}`. A structurally
incompatible, synthetic, search-only, or scientifically incomplete terminal reports
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
  heartbeat, and restart count. `ensure_action` remains `null` for compatibility;
- `storage`: aggregate investigation/global bytes and counts, active WAL and
  sealed-segment bytes/counts, CAS/staging/journal/quarantine totals, and frozen
  thresholds. It never includes object ids, artifact names, result details, or
  evidence hashes;
- a redacted `next_recommendation` (`kind`, `code`, `command_kind`, `recorded`)
  or `null`, plus a human-readable note.

If structural replay/integrity verification fails, status returns an
`integrity_blocked` non-result payload and does not trust terminal state.
Status is read-only and never starts or restarts a supervisor.

`list` is ordered by investigation id and uses a filter-bound opaque cursor. It
exposes only investigation id, lifecycle state, created/updated timestamps,
persisted schema identity, terminal availability, integrity status, and retained size.
It never returns decisions, candidates, cohorts, evidence, or statistics.

Catalog reads are generation-consistent: one status/list operation reads one
lifecycle generation and does not combine rows from opposite sides of a
concurrent archive, delete, or lease transition. Archived investigation
databases are opened through SQLite immutable mode, so verifying status or a
result cannot create a WAL or modify the retained artifact.

### Unattended recovery daemon

`runtime/recovery-daemon-cli.mjs` provides same-user unattended recovery without
making status a liveness trigger. One daemon generation/incarnation holds the
state-root singleton lease in `resource-catalog.sqlite`. Exact PID/start-time
identity permits immediate takeover after process loss or a new logon without
waiting for lease expiry; Task Scheduler also uses `IgnoreNew`, so stale or
duplicate invocations cannot both act.

Each cycle discovers investigations from the verified catalog and considers
only active investigations using the supported persisted schema. Terminal,
paused, archived, tombstoned, structurally incompatible, domain-non-result, and
operational-non-result state is skipped. Before a missing supervisor can launch,
discovery verifies:

- the event database, sealed-segment catalog/hash chain, replay, and every
  referenced inline/external artifact;
- the persisted Ed25519 experiment authority against the current trusted public
  key;
- the immutable runtime config and complete runtime identity, including the
  exact Node, CLI, SDK, runner, allowlist, and sandbox identity;
- resource-catalog integrity and capacity for the next effect after conservative
  stale-lease reconciliation; and
- noninteractive Copilot SDK authentication plus availability of every frozen
  worker model.

Any failure is fail-closed and recorded as a fenced operational code in the
global catalog. The daemon never calls or emulates `crucible_result`, never
assesses terminal readiness, and its one-shot output contains counts only.
Supervisor startup still owns per-investigation generation allocation, runner
incarnation issuance, stale process/resource reconciliation, and logical-effect
deduplication.

Runner ownership is not represented by PID alone. At spawn, the supervisor
captures a durable process identity containing the executable, complete command
line, a hash-bound command identity, and an OS process-start identity. If
that identity cannot be captured, the child is terminated and never adopted.
Drain, escalation, Job Object termination, and post-termination checks all
re-read and compare the identity; PID reuse therefore cannot authorize killing
an unrelated process.

Windows installation uses a hidden current-user logon task with
`InteractiveToken`, least privilege, restart-on-failure, and no stored password.
Logon is intentional: startup/S4U would not guarantee the user's profile,
Copilot credentials, or network credentials. Task arguments contain only local
paths, the state root, timing, and public SHA-256 identities—never tokens or
secrets.

The scheduled action is not a direct `node daemon.mjs` launch. Crucible builds a
pinned launch manifest for the launcher host, Node executable, daemon entry
point, and production Crucible ESM closure, then embeds it in a self-verifying
PowerShell action. Installation verifies the launcher, Node, and daemon bytes,
requires exactly one action and one trigger, and canonical-compares the
installed principal, SID/user identity, trigger, arguments, working directory,
battery behavior, and action fingerprint. Uninstall refuses a nonmatching task,
stops a matching running task within a bound, and verifies that registration is
gone.

```powershell
# 1. Inspect exact paths/hashes and deterministic task identity.
node .\crucible\tools\configure-recovery-task.mjs `
  --state-root "$env:LOCALAPPDATA\Crucible\investigations" `
  --node-path (Get-Command node.exe).Source

# 2. Install using the exact hashes printed by configure.
node .\crucible\tools\install-recovery-task.mjs `
  --state-root "$env:LOCALAPPDATA\Crucible\investigations" `
  --node-path "<exact-node-path>" `
  --daemon-path "<exact-recovery-daemon-cli-path>" `
  --expected-node-sha256 "sha256:<hex>" `
  --expected-daemon-sha256 "sha256:<hex>"

# Manual, bounded one-shot for operator checks and tests.
node .\crucible\runtime\recovery-daemon-cli.mjs --once `
  --state-root "$env:LOCALAPPDATA\Crucible\investigations"

# Uninstall only the action matching those exact paths/hashes.
node .\crucible\tools\uninstall-recovery-task.mjs `
  --state-root "$env:LOCALAPPDATA\Crucible\investigations" `
  --node-path "<exact-node-path>" `
  --daemon-path "<exact-recovery-daemon-cli-path>" `
  --expected-node-sha256 "sha256:<hex>" `
  --expected-daemon-sha256 "sha256:<hex>"
```

Installation requires an existing verified state-root catalog, the same Node
runtime frozen into active investigations, configured experiment public-key
trust, and same-user noninteractive Copilot authentication. Upgrades remove the
old exact action before installing new hashes. The task permits execution on
battery and does not stop on a battery transition; those settings are part of
the exact verified definition.

The launch manifest's boundary is explicit. It pins and holds open the launcher
host, Node executable, and production Crucible ESM set. It does not attest Node
built-ins, Windows loader dependencies, or separately authenticated
per-investigation runtime inputs. The Windows conformance gate tests
process/logon-task recovery only; it does not reboot or power-cycle the host.

### `crucible_stop`

```text
crucible_stop({
  operation: "pause",
  investigation_id: string,
  reason?: string,
})

crucible_stop({
  operation: "archive",
  investigation_id: string,
  expected_head?: exact-event-head,
  authenticated_bundle_destination?: absolute-local-retention-path,
})

crucible_stop({
  operation: "delete",
  investigation_id: string,
  expected_archive_digest: "sha256:<64-lowercase-hex>",
})
```

`pause` distinguishes `already_terminal`, `operational_non_result`,
`domain_non_result`, `pause_persisted`, `pause_pending`, and
`pause_requested`. `resumable:true` requires both the kernel-owned pause and
the durable `PAUSED_QUIESCENT` zero-active proof. A bounded cleanup or
acknowledgement timeout reports `pause_pending`, `quiescent:false`, and
`intervention_required:true`; fenced authority is retained.

The runtime exports `QUIESCENT_STOP_*` protocol helpers plus
`QUIESCENT_STOP_INTEGRATION_NOTES`. Production stop reconciliation now probes
the state-root resource broker, aborts SDK sessions, closes owned process/Job
trees, and persists `PAUSED_QUIESCENT` only after runner leases, command
attempts, broker leases, SDK sessions, and owned PIDs are all zero.

`archive` accepts only a terminal, domain non-result, or
`PAUSED_QUIESCENT` investigation. It fences recovery/runtime authority, proves
zero active resources, exports the complete bundle, imports and verifies a
private staged copy under `CRUCIBLE_ARCHIVE_TRUST_POLICY` (`authenticated` by
default, or explicit `self-consistent`), commits the global catalog transition,
then removes active state. All retention paths remain under the local state-root
`.retention` directory.

`delete` accepts only a verified archived catalog entry and its exact digest.
It has no force-live mode. Deletion is a cataloged recovery state machine:
`reserved -> marked -> moved -> durability_pending -> durable`. Crucible
persists the cleanup path, ownership marker nonce/digest, source authority,
archive-discovery state, and durability progress; verifies containment and
symlink/canonical-path behavior; reserves retention paths against concurrent
operations; and fsyncs the relevant directories before completion. A crash at
any stage resumes from the recorded transition instead of guessing from the
filesystem. The archive and active catalog state are removed only through that
flow, while a canonical Ed25519-signed durable tombstone permanently blocks
recreation or recovery of the deterministic investigation id.

### Active working-set bounds

Every signed contract includes `workingSetPolicy`. It freezes per-effect and
per-investigation disk ceilings, terminal/non-result reserve, WAL
checkpoint/segment thresholds, orphan grace, maintenance cadence, and
diagnostic retention. The resource broker adds the global
`storage_bytes` admission lane, so external effects reserve worst-case growth
before writing and reconcile observed growth afterward.

The writable active event database checkpoints WAL only after transactions.
Commit-time interval/size probes use passive checkpoints; segment rotation
forces a post-commit truncate checkpoint. Maintenance scans repository
artifact metadata, active and sealed event payloads, bundle manifests, and CAS
installation state under the CAS generation lock. Missing, corrupt, or
ambiguous reference state defers deletion. Only aged objects that remain
unreferenced after the final race probe are removed; proposals, receipts, raw
blocks, controls, confirmations, proofs, and every other referenced object are
preserved. External-effect recovery capsules are transient authoritative CAS
references while their effect is unresolved; the runner releases that
reference only after a durable effect/recovery commit, after which orphan grace
controls eventual collection.

Storage pressure first triggers checkpoint/rotation/reconciliation. Exhaustion
before a scientifically ready terminal persists
`STORAGE_BUDGET_INCONCLUSIVE`; it never fabricates or changes a scientific
conclusion. Diagnostic originals are not rolled up by default. A future
roll-up may delete an original only under the frozen `sealed_rollup` policy
after a sealed summary exists and the original is explicitly non-authoritative
and not bundle-required.

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
- the kernel-sealed `basis` and `evidence_closure`;
- signed experiment/contract/suite/runtime authority and complete artifact-root
  closures;
- replay-derived performance claims, prediction outcomes, estimates/confidence
  bounds, assumptions/limitations, and held-out confirmation/challenge state;
- for `TARGET_UNREACHABLE`, the enumerand-coverage and independent-verifier
  request/output/receipt/certificate closure.

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
| `CRUCIBLE_CLI_PACKAGE_PATH`, or the parent of `COPILOT_SDK_PATH` | yes | persisted real path/tree must still validate |
| `CRUCIBLE_NODE_PATH`, or resolved local Node | yes | persisted executable bytes/path must still validate |
| Stable sandbox source/binary/launcher paths and launcher-script hash when sandboxing is required | yes | exact files and current sandbox policy must still validate |
| Existing absolute-local `project_dir` | yes | no |
| Event DB, artifact store, frozen contract, supervisor config | no | yes |
| Current allowlist/suite role bytes still match the frozen suite identity | yes | yes |
| Current sandbox admission for every role that executes candidate code | yes | yes |

The signed contract freezes a runtime-identity policy and initial root. The root
binds resolved real paths and content/Merkle identities for the Crucible source
closure, Node executable, Copilot CLI launcher/package, Copilot SDK package
tree, sandbox helper source/binary/launcher, launch templates, and selected
decision-relevant environment values. Symlinks, junctions/reparse redirection,
network/cloud paths, special files, and closures over the frozen file/byte/depth
caps fail admission. OS release and hardware inventory are recorded separately
as assumptions and do not silently become identity evidence.

The opening event persists that complete identity inside the canonical
runtime-config authority and fingerprint, together with supervisor/runner
options, worker additional context plus its hash, state/artifact/allowlist
paths, runner CLI path/hash, and sandbox policy. Reattach treats the
supervisor config file as a deadline carrier only: every other field must match
the opening authority, and the launch config is reconstructed from that
immutable source. New-start preflight verifies the signed initial root;
reattach/recovery rehashes it; apply verifies it again immediately before the
supervisor launch. Any mismatch returns `RUNTIME_DRIFT`, forbids in-place
repinning, and requires a new or explicitly forked investigation. Tampering
leaves a paused investigation paused. Terminal and
domain-non-result investigations require a new identity; operational recovery
may require a later deadline or explicit reset policy.

Candidate-code suites additionally configure:

```text
CRUCIBLE_SANDBOX_HELPER_SOURCE_PATH=<stable absolute local source path>
CRUCIBLE_SANDBOX_HELPER_BINARY_PATH=<stable absolute local helper path>
CRUCIBLE_SANDBOX_LAUNCHER_PATH=<stable absolute local launcher path>
CRUCIBLE_SANDBOX_LAUNCHER_SCRIPT_HASH=sha256:<domain>:<64hex>
```

The runtime identity reader hashes these files in place; it never copies
binaries. Its optional in-memory hash cache accepts only sealed records produced
after content hashing, detects cache-record tampering, and full verification
rehashes bytes before accepting an unchanged closure.

`runtime/runtime-identity.mjs` exports pure build/verify/root helpers plus
`reverifyRuntimeIdentity` and `assertRuntimeIdentityVerified`. The API,
supervisor, runner, SDK worker pool, and measurement launch lifecycle reverify
the immutable authority immediately before supervisor/runner/CLI/SDK/harness/
sandbox launch and before durable recovery or commitment. Drift records the
operational `RUNTIME_DRIFT` outcome and pause before any later science effect.

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
%LOCALAPPDATA%\Crucible\investigations\resource-catalog.sqlite
Task Scheduler: \Crucible\Recovery-<state-root-identity>
```

`runtime/resource-broker.mjs` owns the state-root catalog. It freezes global
capacities and per-investigation limits, then issues fenced, expiring leases
for SDK/sandbox/CPU/GPU concurrency and storage/model-cost reservations.
Admission `throttle`/`pause` outcomes are operational only and never scientific
conclusions. The supervisor claims each generation/incarnation before launch;
the runner reserves worst-case output/receipt/CAS/model cost before effects,
renews leases, reconciles SDK usage, and releases observed usage after cleanup.
SDK proposals use a durable first-valid-submission journal with stable logical
ids, frozen retry/deadline/cost policy, and quarantine for late, duplicate, or
ambiguous responses.

SDK accounting is independently crash-recoverable. The runner persists
hash-verified `runtime:sdk_accounting_state` records bound to the current lease,
fencing token, and nonce. If a worker submission is already sealed when usage
reporting fails, Crucible preserves the scientific submission and records
`usage_reconciliation_pending` or `usage_reconciliation_failed` operational
evidence. Reattach/recovery can reconcile the usage without rerunning accepted
work, losing accounted units, or charging the same work twice.

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
      "deterministicSeed": "calibration-seed",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "search": {
      "harnessId": "mesh-search",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["search-a"],
      "deterministicSeed": "search-seed",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "confirmation": {
      "harnessId": "mesh-confirmation",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["held-out-a"],
      "deterministicSeed": "confirmation-seed",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "challenge": {
      "harnessId": "mesh-challenge",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["challenge-a"],
      "deterministicSeed": "challenge-seed",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "novelty": {
      "harnessId": "mesh-novelty",
      "observableSchema": { "pass": "boolean", "metrics": ["error"] },
      "caseIds": ["novelty-a"],
      "deterministicSeed": "novelty-seed",
      "sandboxIdentity": { "required": false, "policyDigest": null }
    },
    "impossibility_verifier": {
      "harnessId": "mesh-independent-verifier",
      "observableSchema": { "status": "verifier-status" },
      "caseIds": [],
      "deterministicSeed": "impossibility-verifier-seed",
      "sandboxIdentity": {
        "required": true,
        "policyDigest": "sha256:crucible-measurement-sandbox-policy-identity-v1:<64hex>"
      },
      "independenceAttestation": {
        "kind": "operator_attested_separate_implementation"
      },
      "verificationPolicy": {
        "mode": "enumerand_reexecution",
        "certificateFormat": null
      }
    }
  }
}
```

The suite identity binds each role's executable, application entrypoint, parser, dependencies,
operational config, observable-schema hash, case manifest, deterministic seed,
and sandbox identity. Confirmation/challenge/novelty manifests must be disjoint
from calibration/search; their case ids and snapshot ids are removed from the
worker projection. A verifier must have a separate executable/parser/application
implementation closure: parser identities cannot be reused as primary
executables or application dependencies (or vice versa), and application files
cannot be laundered as platform-shared. Separation compares the validated raw
SHA-256 digest bytes, not the surrounding domain tag, across executables, parser
sources, and application/entrypoint dependencies. The verifier parser is a
separate runtime entrypoint, and the verifier must require the frozen
zero-capability AppContainer policy. The independence claim is explicitly an
operator-attested separate implementation, not a mathematical proof. Every shared dependency must
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
  "deterministicSeed": "confirmation-seed",
  "subjectId": "candidate-17",
  "environmentIdentity": "sha256:crucible-harness-environment-v4:<64hex>",
  "suiteIdentity": "sha256:crucible-harness-suite-v4:<64hex>"
}
```

The older five result fields remain supported. For suite-bound runs, Crucible
passes the ten execution-binding fields shown above in concrete argv and env and
repeats them verbatim in the receipt. If a harness echoes binding fields in its
JSON, the parser requires an exact match to the trusted binding; otherwise the
executor injects the trusted binding into the canonical parsed observation.
Search, confirmation, challenge, novelty, and replicated calibration require
replicate, block, and arm ordinals. Validation may execute calibration, search,
confirmation, or challenge roles with `phase:"calibration"`. The independent
impossibility verifier uses its own strict parser, requires deterministic
seed/block/subject binding, and forbids replicate/arm ordinals. `validationCases` is
calibration-phase-only once a role binding is present, while
older `searchSpaceExhausted` and `impossibilityCertificateHash` fields have no
verifier authority.
Unknown top-level fields, duplicate JSON keys, non-finite metrics, trailing
content, and output overflow are rejected. Metrics named by acceptance claims
are required evidence; other declared metrics are ranking-only. An explicit
`harness_pass` claim can therefore accept a statistically supported candidate
without optional ranking metrics. Accepted-but-unrankable candidates sort
behind rankable accepted candidates. Primary harness output cannot create verifier success. Only a formal checker
output parsed by the separately pinned verifier parser and bound to the
kernel-created request can qualify. Even then, output fields such as
`independentFactsRoot`, refutation receipts, and proof-validation receipts are
descriptive only: they cannot authorize readiness.

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

## Search and termination

The persisted event-domain schema participates in investigation identity.
Structurally incompatible event history is not migrated in place.

Newly configured search policy deterministically adapts operator weights from
completed history: an untried adversarial step is strongly favored, then
refinement is strongly favored after adversarial work completes. Because the
adaptation reads persisted aggregate history, replay selects the same operator.
Previously persisted policy remains authoritative for its own investigation;
Crucible does not reinterpret historical search decisions under newer rules.

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

Search evaluations also receive collision-free preregistered alpha lanes keyed
by round, slot, and replacement ordinal. Invalidating a candidate and filling
the same slot spends a new lane; it cannot reuse the replaced candidate's
significance authority. Before result material is derived, scientific replay
reconstructs evidence order, replacement ordinals, lane assignment, and
slot/candidate binding. Substitution, lane reuse, or reordered authority fails
closed. Previously persisted investigations retain their original lane rules
rather than being reinterpreted under the current policy.

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

For `certified_impossibility`, verification is possible only for a finite,
immutable `finite_enumerable` or explicitly discretized
`bounded_parameterized` manifest. Open-generative and non-discretized
continuous spaces can never produce `TARGET_UNREACHABLE`. Every manifest
ordinal/hash must have one active, terminal-grade replicated evaluation in
which **every** acceptance claim is `REFUTED`; `SUPPORTED`, `UNRESOLVED`, or
`INVALID` claims, missing/invalid blocks, control drift, missing role receipts,
and duplicate/re-identified artifacts block exhaustion. Invalidation reopens
the original slot, and a replacement creates a new closure rather than
laundering the stale evidence.

The formal coverage closure binds the manifest Merkle root, every enumerand
identity, evidence/event/provenance roots, raw block and role-receipt roots,
claim alpha allocations, calibration/control closure, invalidation lineage,
scientific replay, and the alpha ledger with no ordinal gaps. The verifier
request additionally binds the signed experiment authority/contract hash,
suite identity, statistical policy, verifier role identity, evidence roots,
coverage-closure root, proposed claim envelope, distinct proof artifact, and a
canonical object manifest for every covered snapshot/parameter tuple, complete
raw block, receipt, and artifact object. The capability-scoped checker snapshot
is immutable/read-only and contains the request, proposal, proof, generated
closure inputs, and a hash-bound object pack.

The suite selects either `enumerand_reexecution`, whose signed output must list
every exact ordinal/hash and independently `REFUTED` acceptance-claim state
with receipt/input-bound observations, or
`certificate_validation`, which must parse and validate the distinct proof
artifact using a separately pinned `impossibility-proof-checker` application
dependency. A proposal hash is never accepted as a proof/certificate hash. Raw checker output
has exactly four statuses: `VERIFIED`, `REJECTED`, `INCONCLUSIVE`, or `INVALID`.
Any disagreement or non-`VERIFIED` status is a scientific non-result. There is
no `pass + exhausted`, stop-request, or search-budget shortcut. The runner
revalidates the current closure before launch/recovery and persists the exact
checker output, complete MeasurementReceiptV6 identity, AppContainer policy,
request/proof bytes, and raw stdout/stderr. The repository adapter reparses
stdout with the pinned parser and derives a private code-stamped execution
reference bound to the effect attempt, lease/fencing token, supervisor
generation/incarnation, executable/parser/dependency bytes, and CAS artifacts.
Re-evaluation records an adapter-derived checker receipt for every enumerand;
certificate mode records an adapter-derived receipt for the actual proof bytes.
Public constructors and plain hashes cannot mint that capability, and replay
rederives it from repository/CAS state. Only a fully bound `VERIFIED` closure
derives the `v4_unreachable` basis that can terminalize
as `TARGET_UNREACHABLE`. Budget exhaustion without that proof remains
`BUDGET_EXHAUSTED_INCONCLUSIVE`/scientifically inconclusive. Independence is
reported as operator-attested separate implementation, never as mathematically
proven. Only **invalidated** verifier evidence is deterministically retried.

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
The terminal evidence closure carries signed experiment/contract/suite/runtime
authority, all artifact/provenance roots, the discovery stop/plateau basis, the
supported cohort and pairwise relation evidence, and one code-authored
scientific conclusion per cohort member.
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

Legacy-incompatible investigations may be inventoried through catalog discovery
but remain read-only. They cannot resume, archive, append events, or emit a new
terminal result. This prevents compatibility code from manufacturing current
domain authority for an older or structurally incomplete history.

The persistence bundle is self-contained and internally hash-verifiable.
It includes the event database, every referenced raw receipt/output/snapshot/
schedule/composite object, and a cache-only scientific replay digest. Export and
import both replay the bundled event database and reject any mismatch between that
digest and the raw schedule/policy/block history. They also canonical-compare
schedule/composite objects and each raw parsed observation against its
content-addressed receipt before publication or import. Impossibility bundles
also compare the verifier request, output, receipt, sandbox identity, and
certificate artifact against the replayed terminal. Authenticity is out of band:

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
for the inner edit loop. `test:crucible` runs that same curated fast suite.
Both commands are terminated at 55 seconds, making one minute a hard iteration
ceiling rather than a target. The runner also snapshots the repository tree
before and after the run and fails with the exact leaked paths if any test leaves
a new file or directory in the checkout.

## Release validation

`npm run test:crucible:release` is an alias for the same curated suite. Crucible
does not provide separate long-running release, science, integration,
hard-kill, Task Scheduler, or native Windows conformance suites. This is an
intentional iteration-time tradeoff: the retained suite must finish in under
one minute.
