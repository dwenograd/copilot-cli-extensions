# mcp-autoreload

Standalone Copilot CLI extension that recovers stale MCP connections and
registers the manual `mcp_reload_now` tool. It does not use the workspace
`_shared` orchestration modules.

## Automatic recovery

The extension watches completed MCP tool calls through `onPostToolUse`.
When a call fails with a transport-style error, it:

1. Reloads all configured MCP connections.
2. Polls the failed tool's owning server for up to about 12 seconds.
3. Tells the calling agent to retry the exact action after reconnection.
4. Escalates to the user instead of looping if the same server fails again
   before a successful MCP call clears its recovery state.

Domain failures such as invalid arguments or missing application objects do
not trigger a reload. Concurrent failures for the same server share one
in-flight reload.

Because this extension registers session hooks, Copilot CLI may request the
corresponding extension permission when it loads.

## Manual tool

`mcp_reload_now` forces an immediate reload of every configured MCP server,
waits one second, and returns each server's current status. Use it after
restarting an application that hosts an MCP server or when a connection is
known to be stale.

## Installation

The extension is auto-discovered from
`~/.copilot/extensions/mcp-autoreload/` (Windows:
`%USERPROFILE%\.copilot\extensions\mcp-autoreload\`). After edits, restart
Copilot CLI or run `extensions_reload`.
