# Crucible v3 science fixtures

This directory is Phase 0 baseline characterization only.

- Tests named `*.characterizes_v3.test.mjs` preserve the committed v3
  limitations as immutable fixture data. They do not execute v3 state through
  the active v4 decision kernel.
- These tests are not v4 acceptance criteria. Final v4 acceptance tests belong
  in a separate suite.
- Fixture truth/oracle calculations do not import Crucible implementation
  helpers.
- The benchmark runner is read-only and has no network, process-control, or
  host-lifecycle effects.

Run the isolated characterization suite:

```powershell
npm run test:crucible:science-fixtures
```

Check the machine-readable committed baseline:

```powershell
npm run benchmark:crucible:v3-science
```
