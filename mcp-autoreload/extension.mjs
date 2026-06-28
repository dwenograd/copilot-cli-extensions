// Extension: mcp-autoreload
//
// Automatically reloads MCP server connections when an MCP-backed tool call
// fails because the server connection went stale (e.g. you closed & reopened
// Unreal, killing the in-editor MCP server on 127.0.0.1:8765).
//
// Behaviour (matches the agreed spec):
//   1. An MCP tool fails with a connection-type error  -> auto-reload that
//      server once, verify it reconnected, then tell the agent to retry.
//   2. The SAME server fails a second time (after a reload) -> stop and ask
//      the user to intervene (confirm UE is running) instead of looping.
//   3. Any successful MCP tool call clears that server's armed state.
//
// Domain failures (e.g. UE says "actor not found") are NOT treated as
// connection failures and never trigger a reload.

import { joinSession } from "@github/copilot-sdk/extension";

// --- tuning ---------------------------------------------------------------
const VERIFY_POLLS = 24; // how many times to poll mcp.list() after a reload
const VERIFY_INTERVAL_MS = 500; // delay between polls (~12s total budget)

// Error text that indicates a transport/connection problem rather than a
// legitimate domain error returned by the server. Patterns are phrase- and
// boundary-anchored, and the ambiguous English phrases are transport-anchored
// (e.g. "failed to connect to", not bare "failed to connect"), so domain
// output from a game engine ("Pin is not connected", "Player disconnected
// from session", "Failed to connect component") does not false-positive.
const CONNECTION_ERROR_RE =
    /\b(?:client|server|mcp|socket|transport|peer|host|endpoint) (?:is )?not connected\b|not connected to (?:the )?(?:server|mcp|host|endpoint|remote)|connection (?:closed|lost|refused|reset|error|failed)|connection to .{0,40}?(?:closed|lost|failed)|fetch failed|\bECONN(?:REFUSED|RESET|ABORTED)\b|\bETIMEDOUT\b|\bEPIPE\b|\bENOTFOUND\b|socket hang ?up|disconnected from (?:the )?(?:server|mcp|host|remote|endpoint|peer)|transport (?:closed|error)|request timed out|failed to connect to|\bHTTP (?:502|503)\b|status (?:code )?(?:502|503)\b|service unavailable/i;

// --- state ----------------------------------------------------------------
// Servers we have already auto-reloaded since their last successful call. A
// server present here is "armed": a further connection failure escalates to
// the user instead of triggering another reload. Cleared only by a successful
// MCP call for that server (or a manual mcp_reload_now that reconnects it).
const reloaded = new Set();
// Per-server in-flight reload promise, so concurrent failures for the same
// server share a single reload+verify instead of each starting their own.
const inflight = new Map();
let serverNames = []; // cached MCP server config keys, longest-first
let refreshing = null; // de-dupe concurrent list() refreshes

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Logging must never break control flow. A rejecting session.log inside
// reloadAndVerify would otherwise make the shared in-flight promise reject,
// which both awaiters depend on never happening.
async function safeLog(msg, opts) {
    try {
        await session.log(msg, opts);
    } catch {
        // swallow — logging is best-effort
    }
}

async function refreshServerNames() {
    if (refreshing) return refreshing;
    refreshing = (async () => {
        try {
            const { servers } = await session.rpc.mcp.list();
            // Longest names first so prefix matching is greedy/correct when one
            // server name is a prefix of another.
            serverNames = (servers || [])
                .map((s) => s.name)
                .filter(Boolean)
                .sort((a, b) => b.length - a.length);
        } catch {
            // Leave the previous cache in place on failure.
        } finally {
            refreshing = null;
        }
    })();
    return refreshing;
}

// Map a tool name to its owning MCP server, or null if it isn't MCP-backed.
// MCP tools are namespaced as "<server><sep><tool>" (sep is - _ or .).
function matchMcpServer(toolName) {
    if (!toolName) return null;
    for (const name of serverNames) {
        if (
            toolName === name ||
            toolName.startsWith(name + "-") ||
            toolName.startsWith(name + "_") ||
            toolName.startsWith(name + ".")
        ) {
            return name;
        }
    }
    return null;
}

// A tool name that looks like it could belong to an MCP server (namespaced).
function looksMcpShaped(toolName) {
    return typeof toolName === "string" && /[-_.]/.test(toolName);
}

// Resolve the owning server, refreshing the cache once if the first match
// misses but the name looks MCP-shaped (covers servers added after startup).
async function resolveMcpServer(toolName) {
    let server = matchMcpServer(toolName);
    if (server || !looksMcpShaped(toolName)) return server;
    await refreshServerNames();
    return matchMcpServer(toolName);
}

// Only an explicit "success" means the connection is healthy again. "failure"
// and "error" are candidates for connection handling; "rejected"/"denied"
// (agent/user declined the call) are neither and must not disarm escalation.
function resultStatus(result) {
    const rt = result && result.resultType;
    if (rt === "success") return "success";
    if (rt === "failure" || rt === "error") return "failed";
    return "other";
}

function looksLikeConnectionError(result) {
    const parts = [];
    const push = (v) => {
        if (typeof v === "string") parts.push(v);
        else if (v && typeof v === "object" && typeof v.message === "string")
            parts.push(v.message);
    };
    if (result && typeof result === "object") {
        // Scan only the dedicated error/message-bearing fields, never the whole
        // serialized object. The transport patterns are specific, but matching
        // against arbitrary domain payload (actor lists, property dumps) is an
        // unnecessary false-positive surface for a game-engine MCP server.
        push(result.error);
        push(result.textResultForLlm);
        push(result.message);
        push(result.text);
        // Last resort only when no recognizable error field was present, to
        // still catch unusual result shapes without scanning domain content.
        if (parts.length === 0) {
            try {
                parts.push(JSON.stringify(result));
            } catch {
                parts.push(String(result));
            }
        }
    } else {
        parts.push(String(result ?? ""));
    }
    return CONNECTION_ERROR_RE.test(parts.join("\n"));
}

// Reload all MCP servers, then poll until the target server reports
// "connected" (or we give up). A "pending" status means it is still coming
// up, so we keep waiting through the whole budget. Returns true if it
// reconnected.
async function reloadAndVerify(server) {
    try {
        await session.rpc.mcp.reload();
    } catch (e) {
        await safeLog(
            `mcp-autoreload: reload() call failed: ${e?.message || e}`,
            { level: "warning" },
        );
        return false;
    }
    for (let i = 0; i < VERIFY_POLLS; i++) {
        await sleep(VERIFY_INTERVAL_MS);
        try {
            const { servers } = await session.rpc.mcp.list();
            const s = (servers || []).find((x) => x.name === server);
            if (s && s.status === "connected") return true;
            if (s && s.status === "needs-auth") return false; // reload won't fix auth
            // "pending"/"failed" -> keep polling until the budget runs out.
        } catch {
            // keep polling
        }
    }
    return false;
}

const retryContext = (server) =>
    `[mcp-autoreload] The "${server}" MCP connection was stale and has been ` +
    `automatically reloaded and is now connected again. Please retry the ` +
    `exact action you just attempted. Do not mention this reload to the user ` +
    `unless they ask.`;

const escalateContext = (server, reason) =>
    `[mcp-autoreload] STOP — do not retry "${server}" again automatically. ${reason} ` +
    `Pause the current task and ask the user to confirm the "${server}" server ` +
    `is running (for the ue5 server: make sure the Unreal Editor is open and ` +
    `finished loading). Wait for the user before continuing.`;

const session = await joinSession({
    hooks: {
        onSessionStart: async () => {
            await refreshServerNames();
        },

        onPostToolUse: async (input) => {
            const server = await resolveMcpServer(input.toolName);
            if (!server) return;

            const status = resultStatus(input.toolResult);

            if (status === "success") {
                // Healthy again -> disarm escalation for this server.
                reloaded.delete(server);
                return;
            }

            // Only act on genuine failures that look like connection problems.
            // "other" (rejected/denied) is ignored and must not change state.
            if (status !== "failed") return;
            if (!looksLikeConnectionError(input.toolResult)) return;

            // A reload for this server is already running (concurrent failure)
            // -> share its outcome instead of starting another reload.
            if (inflight.has(server)) {
                const ok = await inflight.get(server);
                return {
                    additionalContext: ok
                        ? retryContext(server)
                        : escalateContext(
                              server,
                              "An automatic reload did not bring it back online.",
                          ),
                };
            }

            // Already auto-reloaded once since the last success and still
            // failing -> escalate without reloading again.
            if (reloaded.has(server)) {
                await safeLog(
                    `mcp-autoreload: "${server}" still failing after reload — asking user to intervene`,
                    { level: "warning" },
                );
                return {
                    additionalContext: escalateContext(
                        server,
                        "It failed again even after an automatic reload, so the server is likely down.",
                    ),
                };
            }

            // First connection failure for this server -> auto-reload once.
            // Arm and register the in-flight promise synchronously (no await in
            // between) so concurrent/back-to-back failures share this reload or
            // see it in flight, rather than starting a second one or escalating
            // prematurely.
            reloaded.add(server);
            const p = reloadAndVerify(server);
            inflight.set(server, p);
            await safeLog(
                `mcp-autoreload: "${server}" connection looks stale — reloading…`,
                { ephemeral: true },
            );
            let ok = false;
            try {
                ok = await p;
            } finally {
                inflight.delete(server);
            }

            if (ok) {
                await safeLog(`mcp-autoreload: "${server}" reconnected`, {
                    ephemeral: true,
                });
                return { additionalContext: retryContext(server) };
            }

            // Reload didn't bring it back. Stay armed (do NOT clear `reloaded`)
            // so any further failure escalates immediately without re-reloading.
            await safeLog(
                `mcp-autoreload: "${server}" did not reconnect after reload`,
                { level: "warning" },
            );
            return {
                additionalContext: escalateContext(
                    server,
                    "An automatic reload did not bring it back online.",
                ),
            };
        },
    },

    tools: [
        {
            name: "mcp_reload_now",
            description:
                "Force an immediate reload of all MCP server connections (re-handshakes each configured MCP server). Use this if an MCP tool just failed with a connection/transport error, or after restarting an app that hosts an MCP server (e.g. the Unreal Editor). Returns the post-reload connection status of every server.",
            parameters: { type: "object", properties: {} },
            handler: async () => {
                try {
                    await session.rpc.mcp.reload();
                } catch (e) {
                    return {
                        textResultForLlm: `Reload failed: ${e?.message || e}`,
                        resultType: "failure",
                    };
                }
                await sleep(1000);
                let lines = [];
                try {
                    const { servers } = await session.rpc.mcp.list();
                    await refreshServerNames();
                    lines = (servers || []).map(
                        (s) =>
                            `- ${s.name}: ${s.status}${s.error ? ` (${s.error})` : ""}`,
                    );
                    // Reset state for any server that is now connected.
                    for (const s of servers || []) {
                        if (s.status === "connected") reloaded.delete(s.name);
                    }
                } catch (e) {
                    lines = [`(reloaded, but status query failed: ${e?.message || e})`];
                }
                return {
                    textResultForLlm: `MCP servers reloaded.\n${lines.join("\n")}`,
                    resultType: "success",
                };
            },
        },
    ],
});

// Keep the server-name cache fresh as servers come and go.
session.on("session.mcp_server_status_changed", () => {
    refreshServerNames();
});

// Prime the cache now (onSessionStart does not fire on a mid-session reload).
await refreshServerNames();
