# triple-review — diff and no-git notes

## Git scopes

For `staged`, `unstaged`, `all-uncommitted`, `branch:`, `commit:`, and
`files:` scopes, the **orchestrator** runs the resolved git command once and
fully materializes its output into a snapshot file. Reviewers read that file
with `view`; they must not run `git diff`, `git show`, `git log -p`,
`git status`, or truncating PowerShell pipelines themselves.

This rule applies whether the target directory is this extensions repository
or any other git repository. It avoids hung native processes caused by
sub-agent shell output not being fully drained.

## `paths:` no-git/current-state scope

`paths:<comma-list>` does not require git and has no baseline. Relative paths
are resolved by the handler; reviewers inspect the current files directly.
Use it for a genuinely non-git directory or when current-state review is the
goal.

`paths:` skips diff sizing and backup creation. Auto-applied edits therefore
have no protocol-provided restore path; prefer manual acceptance unless the
operator already has another backup/VCS layer.

## Backup caveats

Git scopes use `git stash create`, which snapshots tracked staged/unstaged
content without changing the worktree. It does **not** include untracked files.
The packet currently shows both a timestamped backup ref (POSIX example) and
the fixed `refs/triple-review/backup` ref (PowerShell/final-report examples).
Record the exact ref and stash SHA actually written; do not assume the fixed
cleanup command applies to a timestamped ref.
