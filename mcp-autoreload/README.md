# mcp-autoreload

Standalone Copilot CLI extension that watches completed MCP tool calls and
registers the manual `mcp_reload_now` tool. It does not use `_shared`.

## Automatic recovery sequence

For a completed call whose result is `failure`/`error` and whose dedicated
error/message fields match a transport pattern:

1. Resolve the owning server from the configured server-name cache.
2. Call the SDK's global `mcp.reload()` operation (all configured servers
   re-handshake; there is no per-server reload API here).
3. Poll `mcp.list()` for the failed call's server for up to about 12 seconds.
4. If it reconnects, add context asking the agent to retry the exact action.
5. If reload/polling fails, or if another connection failure occurs before a
   successful MCP call clears the armed state, stop automatic retries and ask
   the user to verify the server/application.

Concurrent failures for one server share the same in-flight reload. Domain
errors, rejected/denied calls, and non-matching result shapes are ignored.

## Manual tool

`mcp_reload_now` calls global `mcp.reload()`, waits one second, then queries
`mcp.list()`. It returns each server's status when listing succeeds. If the
reload succeeds but the status query fails, the tool still returns success
with a `(reloaded, but status query failed: ...)` line; query status manually
with the CLI/MCP status surface if you need confirmation.

## Known limitations

- Recovery depends on `onPostToolUse`; calls that never produce a completed
  hook event are invisible.
- Tool-to-server mapping requires a configured server name followed by `-`,
  `_`, or `.`, or an exact server-name match. Other naming shapes are missed.
- Result classification recognizes only `resultType: success|failure|error`.
  Connection matching primarily scans `error`, `textResultForLlm`, `message`,
  and `text`; unusual payloads can be missed or, as a last resort, matched from
  serialized result data.
- Reload is global even though retry/escalation state is tracked per server.
- There are currently no automated tests for this extension.

## Installation

The extension is auto-discovered from
`~/.copilot/extensions/mcp-autoreload/` (Windows:
`%USERPROFILE%\.copilot\extensions\mcp-autoreload\`). After edits, restart
Copilot CLI or run `extensions_reload`.
