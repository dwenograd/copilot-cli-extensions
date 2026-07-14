import path from "node:path";

import { openResourceBrokerFromStateRoot } from "../../runtime/index.mjs";

const stateRoot = process.argv[2];
if (typeof stateRoot !== "string" || !path.isAbsolute(stateRoot)) {
    throw new Error("state root argument is required");
}

const broker = openResourceBrokerFromStateRoot({ stateRoot });
const lease = broker.acquireRecoveryDaemonLease({
    daemonIncarnation: `kill-fixture-${process.pid}`,
    leaseNonce: `kill-fixture-nonce-${process.pid}`,
    ownerProcessId: process.pid,
    ownerProcessStartId: `kill-fixture-process-${process.pid}`,
    ttlMs: 1_000,
});
process.stdout.write(`${JSON.stringify({
    ready: lease.acquired === true,
    daemonGeneration: lease.lease?.daemonGeneration ?? null,
})}\n`);

setInterval(() => {}, 60_000);
