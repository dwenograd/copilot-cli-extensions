# Crucible development workflow

## Test tiers

Implementation work must use the smallest relevant test tier.

1. Run the directly affected test files while editing:
   `npm exec vitest run -- crucible/__tests__/<file>.test.mjs`
2. Run `npm run test:crucible:unit` for domain/schema/parser changes.
3. Run `npm run test:crucible:changed` when the affected tests are unclear.
4. The parent/orchestrator runs `npm run test:crucible` once at a phase gate.
5. Release-only matrices, real SDK integration, and Windows conformance run only
   at explicit release gates.

Subagents must **not** run `npm test`, `test:crucible:release-safe`,
`test:crucible:integration`, `test:crucible:windows-conformance`,
`test:crucible:release`, or `test:release` unless their assigned todo is the
corresponding phase/release gate.

Do not repeatedly rerun a full tier after each edit. Fix all failures from one
run, then rerun the affected tier once.

## Runtime budget

- Targeted/unit loop: under 30 seconds.
- Changed-file loop: hard timeout of 120 seconds.
- Phase-gate suite: run by the parent only.
- Long native/crash matrices: release gate only.

If a targeted test exceeds these bounds, profile or split it rather than
raising its timeout.

## Test ownership

- Pure domain logic belongs in fast unit tests.
- Filesystem/process/database behavior belongs in component tests.
- Hard process death and multiprocess durability belong in `*.release.test.mjs`.
- Real Copilot SDK/CLI calls belong in `*.integration.test.mjs`.
- Native AppContainer enforcement belongs in `windows-conformance/`.

Never make a safe default test depend on credentials, external networking,
real user secrets, interactive UI, unbounded resource use, or host-global
registry/device state.
