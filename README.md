# Copilot CLI Extensions Workspace

Seven interrelated Copilot CLI extensions for multi-model orchestration, zero-trust source auditing, and MCP-connection resilience:

| Extension | What it does |
|---|---|
| **triple-duck** | 3 rubber-duck critique agents in parallel → consensus-merged findings (3/3, 2/3, 1/3) |
| **triple-review** | 3 code-review agents per round + synthesis + auto-apply on 3/3 consensus |
| **triple-plan** | 3 planning agents in parallel → merged plan with consensus + alternatives + contested decisions |
| **debate** | 2 debaters arguing opposing positions + 1 independent judge |
| **duck-council** | 6 role-specialized rubber-ducks (security/stability/perf/maintainer/skeptic/user) + 1 judge synthesis pass |
| **zerotrust-sourcecheck** | 32-role multi-model security council against a GitHub URL OR an on-disk local directory. API-direct for URL audits (no source bytes on disk); local-source mode for already-downloaded repos via `view`/`grep`/`glob` with path containment. Build-mode wrappers (clone/install/build) for runtime verification. Section 9b walks the operator through defang / delete-project / keep-as-is per HIGH/CRITICAL finding when any on-disk content was produced. |
| **mcp-autoreload** | Auto-reloads a stale MCP server connection when an MCP tool fails with a transport error, verifies it reconnected, then asks the agent to retry; escalates to the user if a reload doesn't recover. Exposes a manual `mcp_reload_now` tool. (Hook-based utility — does not use `_shared`.) |

All five orchestrator extensions (`triple-*`, `debate`, `duck-council`) return a **markdown instruction packet** that the calling Copilot CLI agent then executes via the built-in `task` tool — no agent runtimes are spawned by these extensions themselves. They're orchestrators-of-orchestrations. `zerotrust-sourcecheck` follows the same pattern (instruction packet) and additionally exposes a set of substitutional-safety wrapper tools (hardened clone / install / build / fetch / sweep) for operations the packet directs the agent to perform.

## Prerequisites

- **Node.js 20+** (the Copilot CLI itself requires this; orchestrator extensions use vitest, zerotrust uses Node's built-in `node:test`).
- **npm** (ships with Node).
- **`gh` CLI authenticated** (`gh auth login`) — only required by `zerotrust-sourcecheck` API-direct modes (`audit_source`, `audit_source_council`, `verify_release`); the orchestrator extensions have no network dependencies.
- **`git` 2.39+** — only required by `zerotrust-sourcecheck` build modes (`audit_and_*_build*`).

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

After restart, the seven tools (`triple-duck`, `triple-review`, `triple-plan`, `debate`, `duck-council`, `zerotrust_sourcecheck`, `mcp_reload_now`) become invokable in any session.

> **Already have a `~/.copilot/extensions/` directory?** Back it up first; the clone needs to write into an empty path. Existing extensions can be moved alongside (the workspace's `_shared/` is namespaced under `_shared/`, and each extension lives in its own subdirectory).

> **Heads-up on model availability:** if a model your provider doesn't offer is requested, the handler logs a `[fallback]` entry and silently substitutes per the static `_shared/models.mjs` `MODEL_FALLBACK_MAP` — but ONLY for model IDs explicitly listed in `KNOWN_DEPRECATED_MODELS` (empty by default). Other unavailable models will fail at call time, not silently fall back; if your provider doesn't offer one of the defaults, override it explicitly via `models` / `judge` / `debaters` / `roles`. The defaults assume access to GitHub Models / Anthropic / OpenAI tiers; less-equipped accounts may want to override explicitly.

## Workspace layout

```
extensions/
├── _shared/                    # shared module — imported by the orchestrator + zerotrust extensions (mcp-autoreload is standalone)
│   ├── index.mjs               # barrel export
│   ├── models.mjs              # DEFAULT_MODELS, CHEAP_MODELS, COUNCIL_*, MODEL_FALLBACK_MAP, etc.
│   ├── schemas.mjs             # zod schemas — validation for the trio + debate + duck-council tools
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
├── zerotrust-sourcecheck/      # 32-role security council + safeWrapper tools
│   ├── extension.mjs           # tool registrations + onPreToolUse hook (vestigial — see README)
│   ├── handler.mjs             # runHandler entry: validate, scrub, build packet
│   ├── packet.mjs              # long instruction-packet template
│   ├── enforcement.mjs         # hook logic + audit-in-progress state machine
│   ├── urlParser.mjs           # GitHub URL/owner/repo/ref/path validation
│   ├── localPathValidator.mjs  # local-mode on-disk path validation
│   ├── modes.mjs               # mode enum + per-mode policy helpers
│   ├── council/                # 32-role manifest + per-role prompt templates
│   ├── safeWrappers/           # clone / install / build / report / cleanup / sweep / fetch / list-tree
│   ├── __corpus__/             # regression corpus harness (clean-control URLs only)
│   ├── __tests__/              # node:test unit + integration tests
│   └── AGENTS.md               # agent-design notes (sub-agent file-write rule, etc.)
├── package.json                # workspace root (vitest + zod for the orchestrators; zerotrust uses node:test)
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

## Default models (slot-1 now claude-opus-4.8)

- **Trio defaults** (triple-duck, triple-plan, triple-review): `claude-opus-4.8`, `claude-opus-4.7-1m-internal`, `gpt-5.5`
- **Debate defaults**: debaters `["claude-opus-4.8", "gpt-5.5"]`, judge `"claude-opus-4.7-1m-internal"`
- **Cheap presets** (unchanged): `claude-opus-4.7`, `claude-opus-4.6`, `gpt-5.5`
- **Duck-council defaults** (tiered, see `duck-council/README.md` for the table): security/stability/judge on `claude-opus-4.8`; performance on `gpt-5.5`; maintainer on `claude-opus-4.7-1m-internal`; skeptic on `gpt-5.4`; user on `claude-sonnet-4.6`. Family-diverse: 4 Claude + 2 GPT among the 6 reviewers.

History: the slot-1 reviewer default was `claude-opus-4.7-xhigh` (chosen after pass-7 of the iterative hardening review proved extra-high reasoning caught 2 real medium bugs that 6 prior passes missed). It moved to `claude-opus-4.8` on the 4.8 release — a newer generation that is ~4x less likely to let a coding flaw pass unremarked, which is precisely these tools' job. Effort and context are now separate `task()` parameters: aliases such as `-xhigh` and `-1m-internal` remain readable presets, but `renderSpawnArgs` translates them to base model IDs plus `reasoning_effort`, and every spawned sub-agent runs with `context_tier:"long_context"`. The default slots moved from `claude-opus-4.6-1m` to `claude-opus-4.7-1m-internal` where useful for generational diversity (4.8 + 4.7 + GPT). The cheap-tier stability slot intentionally keeps the `claude-opus-4.6-1m` alias preset.

## Tests

```bash
cd ~/.copilot/extensions
npm install   # one-time
npm test
```

`npm test` runs both test runners in sequence: `vitest` for the five orchestrator extensions + `_shared/`, then `node --test` for `zerotrust-sourcecheck/` (which uses Node's built-in `node:test` runner). Test counts vary as the suites grow — at last count the orchestrator + shared suites total 207 tests across 15 files, and the zerotrust suite totals 753 tests across 29 files (reported as 13 suites by `node --test`), all green.

If you change a packet wording deliberately in any orchestrator extension, regenerate vitest snapshots once with `npm run test:update`. The zerotrust suite has no snapshots — its tests are explicit assertions.

To run only zerotrust:

```bash
cd ~/.copilot/extensions/zerotrust-sourcecheck
node --test "__tests__/*.test.mjs"
```

(Pass the glob explicitly — `node --test __tests__/` errors with "cannot find module".)

## Operational notes

- `MODEL_FALLBACK_MAP` is hand-maintained. See the drift policy at the top of `_shared/models.mjs`. Review monthly or whenever a `[fallback]` log entry appears.
- Extensions reload via `extensions_reload` (or restart the Copilot CLI). They have zero runtime dependencies beyond `zod` (installed locally in this workspace) and the SDK.

## How they were built

Hardening plan was generated via the extensions themselves: `triple-plan` for the implementation plan, `debate` for the markdown-vs-JSON architecture decision (verdict: keep markdown), `triple-duck` for blindspot review. See `plan.md` in the session folder for the full audit trail.
