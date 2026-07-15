import { EventEmitter } from "node:events";
import fs from "node:fs";

import {
    normalizeSupervisorConfig,
    runSupervisor,
} from "../../runtime/index.mjs";

const configFile = process.argv[2];
if (typeof configFile !== "string" || !fs.existsSync(configFile)) {
    process.exit(64);
}

const config = normalizeSupervisorConfig(
    JSON.parse(fs.readFileSync(configFile, "utf8")),
);
const runnerPid = process.pid + 100_000;
let announced = false;

await runSupervisor(config, {
    pid: process.pid,
    idFactory: () => `killed-supervisor-${process.pid}`,
    isPidAlive: (pid) => pid === process.pid || pid === runnerPid,
    runnerIncarnationFactory: () => `killed-runner-${process.pid}`,
    processTreeAdapter: {
        async close() {
            return { verified: true, activePids: [] };
        },
    },
    async spawnRunner(launchConfig, context) {
        const child = new EventEmitter();
        child.pid = runnerPid;
        const timer = setInterval(() => {
            if (announced || !fs.existsSync(launchConfig.paths.statusPath)) {
                return;
            }
            const status = JSON.parse(
                fs.readFileSync(launchConfig.paths.statusPath, "utf8"),
            );
            if (status.state !== "running") return;
            announced = true;
            clearInterval(timer);
            process.stdout.write(`${JSON.stringify({
                ready: true,
                supervisorGeneration: context.supervisorGeneration,
                runnerIncarnation: context.runnerIncarnation,
                statusRevision: status.statusRevision,
            })}\n`);
        }, 20);
        return {
            child,
            resultPath: launchConfig.paths.childResultPath,
        };
    },
});

process.exit(1);
