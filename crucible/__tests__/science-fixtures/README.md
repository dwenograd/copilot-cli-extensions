# Crucible science fixtures

This directory contains the executable scientific acceptance fixtures.

- Fixture truth/oracle calculations do not import the implementation helpers
  whose behavior they judge.
- The benchmark runner is read-only and has no network, process-control, or
  host-lifecycle effects.

Run the scientific acceptance gate:

```powershell
npm run test:crucible:science
```

Check the machine-readable benchmark:

```powershell
npm run benchmark:crucible:v4-science
```
