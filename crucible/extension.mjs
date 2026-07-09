// Extension: oracle-v3
//
// Production thin Copilot extension for the clean-break Oracle v3. This file is
// intentionally almost pure registration: it wires the four public tools built
// from the single-source schema/handler layer under ./api and hands them to the
// SDK. All logic lives in ./api (schema.mjs, environment.mjs, handlers.mjs).
//
// Tools-only, NO hooks: registering hooks triggers a per-extension permission
// prompt that, if denied, disables the whole extension. The registration object
// returned by buildRegistration contains only a `tools` array. Diagnostics are
// routed through session.log — this extension never writes to stdout.
//
// Tool surface (four tools, no more):
//   oracle_start  — freeze a contract, ingest validation cases, start the runner
//   oracle_status — read-only progress + supervisor health (never a result)
//   oracle_stop   — request a resumable pause (never manufactures a terminal)
//   oracle_result — the ONLY tool that may emit a terminal result

import { joinSession } from "@github/copilot-sdk/extension";
import { buildRegistration } from "./api/handlers.mjs";

// The session (and thus session.log) only exists after joinSession resolves,
// but tool handlers run later, so route diagnostics through a mutable holder.
const sessionHolder = { current: null };
const log = (message) => {
    try {
        sessionHolder.current?.log?.(message);
    } catch {
        // Diagnostics must never break a tool call, and must never reach stdout.
    }
};

const session = await joinSession(buildRegistration({ env: process.env, log }));
sessionHolder.current = session;
