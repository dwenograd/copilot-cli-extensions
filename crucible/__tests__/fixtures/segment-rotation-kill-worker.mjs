import fs from "node:fs";

import { openRepository } from "../../persistence/index.mjs";

const [databaseFile, faultStage, markerFile] = process.argv.slice(2);
if (!databaseFile || !faultStage || !markerFile) {
    process.exit(64);
}

const repository = openRepository({
    file: databaseFile,
    segmentEventThreshold: 2,
});

repository.rotateEventSegment({
    investigationId: "segment-hard-kill",
    quiescent: true,
    faultInjector: (stage) => {
        if (stage === faultStage) {
            const fd = fs.openSync(markerFile, "wx");
            try {
                fs.writeFileSync(fd, JSON.stringify({
                    version: 1,
                    pid: process.pid,
                    stage,
                }));
                fs.fsyncSync(fd);
            } finally {
                fs.closeSync(fd);
            }
            const latch = new Int32Array(new SharedArrayBuffer(4));
            for (;;) Atomics.wait(latch, 0, 0, 60_000);
        }
    },
});

process.exit(0);
