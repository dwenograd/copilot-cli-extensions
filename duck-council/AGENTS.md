# duck-council — agent design notes

## DO NOT use shell-based `git` commands inside reviewer prompts

This file mirrors `triple-review/AGENTS.md`. Same root cause, same fix.

**The rule:** rubber-duck reviewers spawned by this extension MUST NOT run `git diff`, `git show`, `git log -p`, `git status`, or any other `git` command via the powershell/bash tool. They `view` file paths directly instead.

**Why:**
- Sub-agent shells outlive the agent that spawned them. When 6 parallel reviewers each spawn `git diff` calls in PowerShell pipelines, race conditions and pipe-buffer SIGPIPE deadlocks have caused multiple hung shells in past triple-review runs.
- The hung-shell symptom shows up as the user noticing background tasks "still running" days after the conversation finished. Killing them required `Stop-Process -Id <pid>`.
- The fix lives in the reviewer prompt template itself (`packet.mjs`), not in orchestration habits — protocol-enforced is the only reliable enforcement.

**Specifically forbidden patterns** (called out explicitly in `packet.mjs` ROLE_PROMPTS append text):
- `git diff` (any form, including `git diff --cached`, `git diff HEAD`, etc.)
- `git show <sha>`
- `git log -p`
- `git status`
- `<command> | Select-Object -First N` — PowerShell pipelines do not always propagate stop-upstream signals to native processes; the upstream process can block on a full stdout buffer indefinitely.

**Allowed alternatives:**
- `view` against any file path mentioned in the topic/context.
- `view` with `view_range` for targeted reads of large files.
- Report a request for git context as a Finding instead of running it yourself (e.g., "I'd want to see the diff of `src/auth/cookies.ts` against main — please share that").

## Why duck-council does not have a Step 0.6 diff-materialization step

Unlike `triple-review`, which operates on a git repo and needs to materialize a diff for reviewers, `duck-council` operates on a topic + free-text context + free-text focus. There is no implicit git scope to materialize. Reviewers `view` whatever file paths the user pastes into `context`, and that's it.

If a future use case needs to council-review actual code changes, the right move is to add a `paths:` parameter (mirroring `triple-review`'s pass-14 addition) — not to lift the no-`git diff` rule.
