# Copilot CLI Extensions Workspace

Five interrelated Copilot CLI extensions for multi-model orchestration:

| Extension | What it does |
|---|---|
| **triple-duck** | 3 rubber-duck critique agents in parallel → consensus-merged findings (3/3, 2/3, 1/3) |
| **triple-review** | 3 code-review agents per round + synthesis + auto-apply on 3/3 consensus |
| **triple-plan** | 3 planning agents in parallel → merged plan with consensus + alternatives + contested decisions |
| **debate** | 2 debaters arguing opposing positions + 1 independent judge |
| **duck-council** | 6 role-specialized rubber-ducks (security/stability/perf/maintainer/skeptic/user) + 1 judge synthesis pass |

All five return a **markdown instruction packet** that the calling Copilot CLI agent then executes via the built-in `task` tool — no agent runtimes are spawned by these extensions themselves. They're orchestrators-of-orchestrations.

## Installation

```bash
# Clone into your Copilot CLI extensions directory.
# Unix / macOS:
git clone https://github.com/dwenograd/copilot-cli-extensions.git ~/.copilot/extensions

# Windows (PowerShell):
git clone https://github.com/dwenograd/copilot-cli-extensions.git "$env:USERPROFILE\.copilot\extensions"

# Install dependencies (zod + vitest):
cd ~/.copilot/extensions   # or %USERPROFILE%\.copilot\extensions on Windows
npm install

# Restart Copilot CLI (or run `extensions_reload` from inside it).
```

After restart, the 5 tools (`triple-duck`, `triple-review`, `triple-plan`, `debate`, `duck-council`) become invokable in any session.

> **Already have a `~/.copilot/extensions/` directory?** Back it up first; the clone needs to write into an empty path. Existing extensions can be moved alongside (the workspace's `_shared/` is namespaced under `_shared/`, and each extension lives in its own subdirectory).

> **Heads-up on model availability:** if a model your provider doesn't offer is requested, the handler logs a `[fallback]` entry and silently substitutes per the static `_shared/models.mjs` `MODEL_FALLBACK_MAP` — but ONLY for model IDs explicitly listed in `KNOWN_DEPRECATED_MODELS` (empty by default). Other unavailable models will fail at call time, not silently fall back; if your provider doesn't offer one of the defaults, override it explicitly via `models` / `judge` / `debaters` / `roles`. The defaults assume access to GitHub Models / Anthropic / OpenAI tiers; less-equipped accounts may want to override explicitly.

## Workspace layout

```
extensions/
├── _shared/                    # shared module — imported by all 5 extensions
│   ├── index.mjs               # barrel export
│   ├── models.mjs              # DEFAULT_MODELS, CHEAP_MODELS, COUNCIL_*, MODEL_FALLBACK_MAP, etc.
│   ├── schemas.mjs             # zod schemas — validation for all 5 tools
│   ├── policy.mjs              # prompt-injection policy (warn-only + narrow hard-block; per-call USER_INPUT envelope)
│   ├── scrub.mjs               # secrets/PII scrubber
│   ├── budget.mjs              # cost ceiling enforcement (incl. duck-council 14/12 formula)
│   ├── resolveModels.mjs       # static model fallback resolution
│   ├── formatZodError.mjs      # ZodError → user-friendly string
│   └── __tests__/              # unit tests for the shared modules
├── triple-duck/
│   ├── extension.mjs           # thin shell — joinSession + parameter declaration
│   ├── handler.mjs             # pure runHandler() — orchestrates the pipeline
│   ├── packet.mjs              # pure buildInstructionPacket() — composes the markdown
│   └── __tests__/              # handler integration + packet snapshot tests
├── triple-review/              # same structure
├── triple-plan/                # same structure
├── debate/                     # same structure
├── duck-council/               # same structure (+ AGENTS.md no-`git diff` reminder)
├── package.json                # workspace root (vitest + zod)
└── .gitignore
```

## Handler pipeline (every extension follows this exact order)

```
parse (zod schema) → check budget → scrub each free-text field
                                  → applyInjectionPolicy (per-call nonce envelope)
                                  → resolveModels (static fallback)
                                  → buildInstructionPacket (compose meta-blocks + protocol)
```

Each stage can short-circuit with a clear error before the next runs.

## Hardening features

- **Schema validation (zod):** trimmed strings, length-3-distinct model arrays, 64KB free-text caps, mutually-exclusive `cheap`+overrides, `triple-review` scope grammar (command-injection prevention), `debate` judge-vs-debaters independence after default resolution, model-id allowlist (`/^[A-Za-z0-9._\-]+$/` + 80-char cap, prevents packet-injection via model overrides).
- **Cost ceiling (`max_premium_calls`):** handler-side authoritative gate rejects requests that can't fit the budget BEFORE the packet is built. Packet-side advisory counter for orchestrator UX.
- **Prompt-injection policy:** USER_INPUT envelope with per-call nonce defeats marker spoofing; warn-only for soft patterns (legitimate dev uses preserved); hard-block for the narrow tier of literal credential paths (`~/.ssh`, `id_rsa`, `.aws/credentials`, etc.).
- **Secrets scrubber:** high-confidence patterns only (AWS keys + STS, GitHub tokens (PAT/OAuth/server/user/refresh), private-key blocks (PKCS#1/8/EC/OpenSSH/DSA/PGP/ENCRYPTED), Bearer tokens (case-insensitive, JSON/YAML-quoted), DB connection strings). Emails NOT scrubbed (false positive rate is too high to be worth the trust cost).
- **Model fallback:** static map (since extension SDK doesn't expose `listModels()` to extensions). Built-in defaults silently substitute when in `KNOWN_DEPRECATED_MODELS`; user overrides honored or fail loudly. Every substitution logged via `session.log` with `[fallback]` prefix.

## Default models (after pass-7 upgrade)

- **Trio defaults** (triple-duck, triple-plan, triple-review): `claude-opus-4.7-xhigh`, `claude-opus-4.6-1m`, `gpt-5.5`
- **Debate defaults**: debaters `["claude-opus-4.7-xhigh", "gpt-5.5"]`, judge `"claude-opus-4.6-1m"`
- **Cheap presets** (unchanged): `claude-opus-4.7`, `claude-opus-4.6`, `gpt-5.5`
- **Duck-council defaults** (tiered, see `duck-council/README.md` for the table): security/stability/judge on `claude-opus-4.7-xhigh`; performance on `gpt-5.5`; maintainer on `claude-opus-4.6-1m`; skeptic on `gpt-5.4`; user on `claude-sonnet-4.6`. Family-diverse: 4 Claude + 2 GPT among the 6 reviewers.

The slot-1 default upgraded from a 1M-context Claude variant → `claude-opus-4.7-xhigh` after pass-7 of the iterative hardening review proved the extra-high reasoning catches bugs that standard reasoning misses (2 real medium bugs that 6 prior passes overlooked). Tradeoff: xhigh is ~200k context vs the prior 1M; for genuinely huge inputs, pass `models: ["claude-opus-4.6-1m", ...]` explicitly to recover 1M context.

## Tests

```bash
cd ~/.copilot/extensions
npm install   # one-time
npm test
```

199 tests across 15 files: 89 shared-module unit tests (12 policy + 12 budget + 11 resolveModels + 31 scrub + 23 schemas) + 84 handler integration tests (18×3 trio handlers + 16 debate + 14 duck-council) + 26 packet snapshot tests (6×4 + 2 duck-council).

If you change a packet wording deliberately, regenerate snapshots once with `npm run test:update`.

## Operational notes

- `MODEL_FALLBACK_MAP` is hand-maintained. See the drift policy at the top of `_shared/models.mjs`. Review monthly or whenever a `[fallback]` log entry appears.
- Extensions reload via `extensions_reload` (or restart the Copilot CLI). They have zero runtime dependencies beyond `zod` (installed locally in this workspace) and the SDK.

## How they were built

Hardening plan was generated via the extensions themselves: `triple-plan` for the implementation plan, `debate` for the markdown-vs-JSON architecture decision (verdict: keep markdown), `triple-duck` for blindspot review. See `plan.md` in the session folder for the full audit trail.
