# When orchestrating triple-review on a non-git directory

The extensions dir (the workspace where these tools live, e.g. `~/.copilot/extensions/`) is not itself a git repo. When you want to run `triple-review` on its contents, **use the `paths:` scope** introduced as the pass-14 hung-shell fix:

```
triple-review({
    scope: "paths:_shared/budget.mjs,_shared/scrub.mjs,triple-review/handler.mjs,triple-review/packet.mjs"
})
```

This hands reviewers the absolute file paths and tells them to use the `view` tool. **No staging dir. No git init. No `git diff`. No hung shells.**

For backwards compatibility, the old workflow (create staging dir + git init + give reviewers a `staged` scope) still works — but the reviewer prompt now forbids them from running `git diff` or piping anything through `Select-Object -First`, so the failure mode is much smaller. Even if you forget and use the staging-dir pattern, reviewers will materialize the diff into a file via `Out-File` (Step 0.6 of the protocol) instead of letting sub-agent shells hang on git output buffers.

## Why the structural fix lives in `packet.mjs`

The hung-shell pattern recurred 5+ times in one session because:
1. The protocol packet told reviewers `Diff command: <diffCommand> (run this to see the exact changes under review)`.
2. Reviewers (sub-agents) ran the command via their PowerShell tool.
3. Their PowerShell tool didn't always drain git's stdout, OR they piped through `Select-Object -First N` which doesn't propagate stop-upstream.
4. Git blocked on full stdout buffer, sub-agent reported back anyway, shell stayed "running" forever holding a real OS process.

The pass-14 fix changed the protocol so reviewers receive a **pre-materialized diff snapshot path** instead of a command to run. The orchestrator (you or me) runs git ONCE, drains stdout fully into a file, and passes the path. Reviewers `view` the file. Subprocess output is owned by exactly one party (the orchestrator) instead of being fanned out to N stateless sub-agents.

## When to NOT use `paths:`

- When you ARE in a real git repo and want a real diff (use `staged`/`unstaged`/`branch:`/`commit:`/`files:` as before; the protocol now safely materializes the diff for reviewers either way).
- When the review baseline matters (e.g., "what changed since main") — `paths:` has no baseline.
