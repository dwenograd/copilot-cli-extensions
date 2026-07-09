# Crucible

Crucible is a fully automated local investigation runner. Model workers may
propose candidate file sets, but they receive only one custom submission tool
and cannot execute commands. A deterministic operator-allowlisted harness is
the only authority that can establish correctness.

## Public tools

- `crucible_start` freezes a contract, ingests two-sided validation cases, and
  launches the detached supervisor.
- `crucible_status` reports progress and whether a terminal result is available.
  It never reveals the decision.
- `crucible_stop` requests a persisted resumable pause.
- `crucible_result` is the only tool that may return `VERIFIED_RESULT` or
  `TARGET_UNREACHABLE`.

## Harness allowlist

The allowlist defaults to:

`%LOCALAPPDATA%\Crucible\harnesses.json`

Override it with `CRUCIBLE_ALLOWLIST_PATH`. Investigation state defaults to
`%LOCALAPPDATA%\Crucible\investigations`.

Do not hand-edit this file. Author it with the operator CLI
(`tools/configure-harness.mjs`, described below), which computes every content
hash for you and re-validates the exact bytes it installs.

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
contents, computed the same way `crucible_start` computes it when it ingests the
validation-case directory into the per-investigation `ArtifactStore`. It is a
pure function of the directory's files (sorted relative posix paths + per-file
SHA-256), independent of the store location, so a throwaway store here yields
the identical id `crucible_start` recomputes later.

For validation to line up, the directory `crucible_start` ingests
(`project_dir` + the case `path`) must have **byte-for-byte identical contents**
to the `sourceDir` configured here. If the contents differ, the ingested
snapshot id will differ from the pinned `snapshotHash` and the case will not
match the allowlisted set. Freeze the case directories before configuring the
harness and keep them unchanged through `crucible_start`.


## State model

Each investigation uses a local SQLite WAL event store plus a content-addressed
artifact store. Domain decisions are replayable from an append-only hash chain.
External effects use fenced reservations, and terminal decisions are unique
database-constrained events. `crucible_result` reports only persisted terminal
events; deadlines, pauses, failures, and budget exhaustion remain explicit
non-results.
