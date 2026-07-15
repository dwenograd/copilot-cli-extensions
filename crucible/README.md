# Crucible

Crucible runs persistent, evidence-judged experiments.

You define and sign the experiment: objective, candidates, measurements,
acceptance rules, budgets, and trusted harness. Crucible then asks model workers
for candidate artifacts, measures them with that frozen harness, persists every
decision, survives interruption, and returns a result only when the evidence is
complete and verified.

The short version:

```text
Operator defines the rules -> workers propose candidates -> trusted harness
measures them -> kernel judges the evidence -> operator retrieves the result
```

Crucible is deliberately not a chat-based "pick the best answer" tool. Models
propose work; they do not control the experiment, measurements, acceptance
criteria, or final decision.

## When to use it

Use Crucible when:

- candidate artifacts can be evaluated by a deterministic or tightly bounded
  harness;
- the experiment needs explicit statistical and resource limits;
- work may run for multiple rounds or survive process restarts;
- the final decision must be reproducible from persisted evidence;
- an operator, not a model, must own the scientific contract.

Do not use it for:

- open-ended research without measurable outcomes;
- ordinary one-shot prompts;
- experiments whose harness cannot safely execute candidate code;
- decisions where the acceptance rule is still being invented during the run.

## Requirements

- Node.js 24 or newer.
- A trusted local filesystem for the state root and artifacts.
- A configured Ed25519 experiment public key.
- An operator-reviewed and allowlisted harness suite.
- Copilot CLI/SDK authentication and the configured worker models.
- On Windows, the Crucible containment provider when the harness executes
  candidate code.

## The four public tools

| Tool | Purpose |
|---|---|
| `crucible_start` | Start a preapproved experiment or resume an active investigation. |
| `crucible_status` | Read lifecycle and progress information. It never returns the scientific result. |
| `crucible_stop` | Pause, archive, or delete an investigation through durable lifecycle transitions. |
| `crucible_result` | The only tool allowed to return a terminal scientific decision. |

This separation is intentional: checking status cannot accidentally restart
work or reveal a result, and lifecycle cleanup cannot manufacture one.

## Quick start

Crucible will not accept an experiment definition directly through
`crucible_start`. The operator first installs a signed experiment.

### 1. Configure the experiment trust root

Keep the private key offline. Give Crucible only the public key:

```powershell
$env:CRUCIBLE_EXPERIMENT_PUBLIC_KEY_PATH = "C:\operator\operator-public.pem"
$env:CRUCIBLE_EXPERIMENT_PUBLIC_KEY_FINGERPRINT = "sha256:crucible-experiment-public-key-v1:<64-hex>"
```

An inline `CRUCIBLE_EXPERIMENT_PUBLIC_KEY` is also supported. A public-key path
must include the expected fingerprint so a mutable path is not treated as the
trust anchor.

### 2. Prepare, sign, and install the experiment

```powershell
# Prepare the exact canonical bytes.
node .\crucible\tools\configure-experiment.mjs `
  --config C:\operator\experiment.json `
  --prepare-manifest C:\operator\experiment.manifest.json

# Sign outside Crucible.
openssl pkeyutl -sign -rawin `
  -inkey C:\offline\operator-private.pem `
  -in C:\operator\experiment.manifest.json `
  -out C:\operator\experiment.sig

# Install the signed experiment.
node .\crucible\tools\configure-experiment.mjs `
  --config C:\operator\experiment.json `
  --signature-file C:\operator\experiment.sig
```

Do not reformat or regenerate the prepared manifest between preparation and
signing. Installation reconstructs the canonical payload and verifies the
detached signature.

The operator config defines, at a high level:

- the experiment ID, objective, and project directory;
- the trusted harness suite;
- the acceptance predicate and measured observables;
- the candidate topology and, when bounded, the complete enumerand;
- statistical, confirmation, missing-data, and resource budgets;
- worker models, rounds, candidates per round, and search policy.

Those values are frozen for the investigation. Models cannot replace them.

### 3. Start the investigation

```text
@crucible_start experiment_id="<installed-experiment-id>"
```

Optionally provide a future deadline with an explicit timezone:

```text
@crucible_start experiment_id="<id>"
                deadline_iso="2026-08-01T18:00:00-07:00"
```

The response includes the deterministic `investigation_id`.

### 4. Check progress

```text
@crucible_status operation=get investigation_id="<investigation-id>"
```

Status reports progress, lifecycle state, storage use, supervisor health, and
whether a terminal result is available. It never returns the winner, evidence,
or decision.

List known investigations:

```text
@crucible_status operation=list
```

### 5. Retrieve the result

```text
@crucible_result investigation_id="<investigation-id>"
```

Only `crucible_result` can return `is_result:true`. It first replays and verifies
the investigation, evidence closure, contract, harness identity, and terminal
state.

If the investigation is still running, paused, structurally incompatible,
integrity-blocked, or scientifically incomplete, it returns `is_result:false`
without a winner payload.

## How an investigation runs

1. **Admission** - verify the signed experiment, harness allowlist, runtime
   identity, models, storage budget, and candidate topology.
2. **Calibration** - verify that the selected harness behaves as declared on
   operator-provided cases.
3. **Search** - workers propose bounded candidate files. Workers cannot change
   the contract or directly access arbitrary shell/file tools.
4. **Measurement** - the trusted harness evaluates candidates and controls.
5. **Judgment** - the kernel applies the frozen acceptance and statistical
   policy.
6. **Confirmation and challenge** - held-out roles test claims before closure.
7. **Terminal verification** - replay and artifact verification determine
   whether a result may be emitted.

For finite or bounded experiments, Crucible can prove that the configured
search space was exhausted. Open-generative experiments are never treated as
exhaustive.

## Lifecycle

```text
active -> paused -> active
   |         |
   +------> archived -> deleted + signed tombstone
```

### Pause

```text
@crucible_stop operation=pause
               investigation_id="<investigation-id>"
               reason="operator request"
```

A pause is resumable only after Crucible proves that workers, commands, leases,
SDK sessions, and owned processes are quiescent. If cleanup is still in
progress, the response says intervention is required rather than pretending the
pause completed.

Resume by calling `crucible_start` with the existing `investigation_id`.

### Archive

```text
@crucible_stop operation=archive
               investigation_id="<investigation-id>"
```

Only terminal, domain-non-result, or fully quiescent paused investigations can
be archived. Crucible exports and verifies the complete bundle before removing
active state.

### Delete

```text
@crucible_stop operation=delete
               investigation_id="<investigation-id>"
               expected_archive_digest="sha256:<64-hex>"
```

Deletion requires the exact verified archive digest. It permanently records a
signed tombstone so the same deterministic investigation cannot silently be
recreated.

There is no force-delete for a live investigation.

## Trust model

### The operator owns the experiment

The signed experiment is the source of authority. It freezes the objective,
topology, observables, acceptance predicate, statistics, budgets, harness, and
worker configuration.

### The allowlist identifies trusted harness bytes

Allowlisting proves which harness implementation the operator chose. It does
not prove that the harness is correct, unbiased, or deterministic. Review the
harness and provide calibration cases.

### Workers only propose candidates

Worker sessions can submit candidate artifacts and, when assigned, read bounded
parent artifacts. They do not receive configuration discovery, raw artifact
storage access, or general built-in shell/file tools.

### The kernel owns decisions

Workers and harnesses produce proposals and observations. The persisted kernel
state applies the frozen policy and records domain decisions.

### `crucible_result` is the result boundary

Status, logs, archives, and worker output are not scientific results. Treat a
decision as terminal only when `crucible_result` returns `is_result:true`.

## State and recovery

By default, Crucible stores investigations under:

```text
%LOCALAPPDATA%\Crucible\investigations
```

Override it with `CRUCIBLE_STATE_ROOT`.

Active investigations use durable events, content-addressed artifacts,
resource leases, and a global catalog. Recovery verifies process identity,
runtime bytes, experiment authority, artifact integrity, and resource state
instead of trusting a PID or leftover directory.

`crucible_status` is read-only and does not start recovery. For unattended
same-user recovery, Crucible includes a Windows Task Scheduler integration:

```powershell
# Inspect the exact paths, hashes, and task identity first.
node .\crucible\tools\configure-recovery-task.mjs `
  --state-root "$env:LOCALAPPDATA\Crucible\investigations" `
  --node-path (Get-Command node.exe).Source

# Run one bounded recovery pass manually.
node .\crucible\runtime\recovery-daemon-cli.mjs --once `
  --state-root "$env:LOCALAPPDATA\Crucible\investigations"
```

The configure command prints the exact values required by
`install-recovery-task.mjs`. Installation is intentionally hash-pinned and
same-user; it stores no password or Copilot token in the task.

## Harness output

Harnesses communicate through bounded machine-readable output. They must report
the declared observables and role result without exceeding the experiment's
output, receipt, evaluation, and storage budgets.

Candidate-code execution is not automatically safe because it is called a
harness. On Windows, use the configured containment provider and treat harness
review as part of the experiment's trust setup.

## Common failure meanings

| State | Meaning |
|---|---|
| `is_result:false` | No verified terminal scientific result is available. |
| `integrity_blocked` | Persisted state or artifacts failed replay/integrity verification. |
| operational non-result | The run could not continue because of runtime, storage, model, or containment conditions. |
| domain non-result | The frozen experiment concluded without a winner, for example bounded exhaustion or an inconclusive statistical outcome. |
| paused but not quiescent | Stop was requested, but owned activity has not yet been proven zero. |

Crucible fails closed: operational trouble does not become a scientific
conclusion.

## Development

Install the repository dependencies, then run the curated suite:

```powershell
npm install
npm run test:crucible
```

The suite has a hard 55-second process ceiling and fails if tests leave files in
the checkout.

## Project layout

```text
crucible/
  api/          public schemas and handlers
  domain/       experiment contract, reducer, strategy, decisions
  measurement/  harness allowlist, execution, containment
  persistence/  events, artifacts, archives, resource catalog
  runtime/      workers, scheduler, supervisor, recovery
  tools/        operator configuration and recovery commands
```

## License

MIT
