export function renderTraceStage(context = {}) {
    const auditId = context.auditId || "<unavailable: no session identity>";
    return `
### Evasive graph preparation and exhaustive trace

After red-team finalization advances the current assurance state to
\`red-teamed\`, call:

\`\`\`
const graphPlan = zerotrust_prepare_evasive_graph({
  audit_id: ${JSON.stringify(auditId)}
})
const graphTrace = zerotrust_trace_evasive_graph({
  audit_id: ${JSON.stringify(auditId)}
})
\`\`\`

The graph is derived only from trusted scanner facts, decoded artifacts,
dependency/supply-chain state, semantic candidates, and red-team candidates.
No caller graph or completeness flag is accepted. Directional contradictions
are quarantined rather than selected.

Require \`graphTrace.advanced === true\`, stage \`traced\`, no blocker, no cap or
truncation, and complete coverage of every activation/trigger root plus every
alternate effect path. Dynamic/unsupported targets, missing targets, cycles,
or quarantined conflicts keep assurance incomplete. Use
\`zerotrust_get_evasive_graph\` for an identity-bound readback when needed.
`;
}
