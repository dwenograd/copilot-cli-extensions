# Crucible development workflow

## Test loop

Crucible has one curated test suite.

1. Run the directly affected test files while editing:
   `npm exec vitest run -- crucible/__tests__/<file>.test.mjs`
2. Run `npm run test:crucible` once after the edit.

`test:crucible:unit`, `test:crucible:changed`, and
`test:crucible:release` are aliases for that same suite. The runner has a hard
55-second process timeout. There are no longer separate long-running Crucible
release, science, integration, hard-kill, or Windows-conformance test commands.
The runner snapshots the repository tree before and after execution and fails
with the exact paths if a test leaves any new file or directory in the checkout.

Do not repeatedly rerun the suite after each edit. Fix all failures from one
run, then rerun the affected tier once.

## Runtime budget

- Targeted/unit loop: under 30 seconds; hard process ceiling 55 seconds.
- Changed/release aliases use the same 55-second-capped suite.

If a targeted test exceeds these bounds, profile or split it rather than
raising its timeout.

Never make a safe default test depend on credentials, external networking,
real user secrets, interactive UI, unbounded resource use, or host-global
registry/device state.
