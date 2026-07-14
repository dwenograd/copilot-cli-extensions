import {
    openRepository,
} from "../../persistence/index.mjs";

const [databaseFile, faultStage] = process.argv.slice(2);
if (!databaseFile || !faultStage) {
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
            process.kill(process.pid, "SIGKILL");
        }
    },
});

process.exit(0);
