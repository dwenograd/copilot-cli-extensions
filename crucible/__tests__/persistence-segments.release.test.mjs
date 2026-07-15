import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { expect, it } from "vitest";

import {
    SEGMENT_SEAL_STAGES,
    openRepository,
} from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

async function waitForBoundary(child, markerFile, readStderr, timeoutMs = 30_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (fs.existsSync(markerFile)) {
            return JSON.parse(fs.readFileSync(markerFile, "utf8"));
        }
        if (child.exitCode !== null || child.signalCode !== null) {
            throw new Error(
                `segment worker exited before the requested boundary: `
                + `code=${child.exitCode}; signal=${child.signalCode}; `
                + `stderr=${readStderr()}`,
            );
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
    }
    throw new Error(
        `timed out waiting for segment boundary marker; stderr=${readStderr()}`,
    );
}

function waitForExit(child, timeoutMs = 10_000) {
    if (child.exitCode !== null || child.signalCode !== null) {
        return Promise.resolve({
            code: child.exitCode,
            signal: child.signalCode,
        });
    }
    return new Promise((resolve, reject) => {
        const timer = setTimeout(
            () => reject(new Error("requested segment hard kill did not exit")),
            timeoutMs,
        );
        timer.unref?.();
        child.once("exit", (code, signal) => {
            clearTimeout(timer);
            resolve({ code, signal });
        });
    });
}

it.each(SEGMENT_SEAL_STAGES)(
    "recovers a valid event log after hard process death at %s",
    async (faultStage) => {
        const root = fs.mkdtempSync(
            path.join(HERE, `.segments-release-${faultStage}-`),
        );
        const databaseFile = path.join(root, "events.sqlite");
        const markerFile = path.join(root, "reached-boundary.json");
        let repository = openRepository({
            file: databaseFile,
            segmentEventThreshold: 2,
        });
        let worker = null;
        try {
            repository.ensureInvestigation({
                investigationId: "segment-hard-kill",
                metadata: { domainVersion: 4 },
            });
            repository.appendEvents({
                investigationId: "segment-hard-kill",
                expectedHead: null,
                events: [
                    {
                        kind: "one",
                        payload: {},
                        createdAt: "2026-07-13T00:00:01.000Z",
                    },
                    {
                        kind: "two",
                        payload: {},
                        createdAt: "2026-07-13T00:00:02.000Z",
                    },
                ],
            });
            repository.close();
            repository = null;

            worker = spawn(
                process.execPath,
                [
                    path.join(
                        HERE,
                        "fixtures",
                        "segment-rotation-kill-worker.mjs",
                    ),
                    databaseFile,
                    faultStage,
                    markerFile,
                ],
                {
                    cwd: path.resolve(HERE, ".."),
                    windowsHide: true,
                    stdio: ["ignore", "ignore", "pipe"],
                },
            );
            let stderr = "";
            worker.stderr.setEncoding("utf8");
            worker.stderr.on("data", (chunk) => {
                stderr += chunk;
            });
            const marker = await waitForBoundary(
                worker,
                markerFile,
                () => stderr,
            );
            expect(marker).toEqual({
                version: 1,
                pid: worker.pid,
                stage: faultStage,
            });
            expect(worker.kill("SIGKILL")).toBe(true);
            expect(await waitForExit(worker)).toEqual({
                code: null,
                signal: "SIGKILL",
            });

            repository = openRepository({
                file: databaseFile,
                segmentEventThreshold: 2,
            });
            const expectedSegments =
                SEGMENT_SEAL_STAGES.indexOf(faultStage) >= 3 ? 1 : 0;
            expect(repository.getSegmentCatalog({ verify: true }).segments)
                .toHaveLength(expectedSegments);
            expect(repository.listEvents("segment-hard-kill")
                .map((event) => event.seq)).toEqual([1, 2]);
            expect(repository.verifyInvestigation("segment-hard-kill").ok)
                .toBe(true);
            repository.appendEvents({
                investigationId: "segment-hard-kill",
                expectedHead: repository.getHead(
                    "segment-hard-kill",
                ).eventHash,
                events: [{
                    kind: "three",
                    payload: {},
                    createdAt: "2026-07-13T00:00:03.000Z",
                }],
            });
            expect(repository.getHead("segment-hard-kill").seq).toBe(3);
        } finally {
            if (worker !== null
                && worker.exitCode === null
                && worker.signalCode === null) {
                worker.kill("SIGKILL");
                await waitForExit(worker).catch(() => {});
            }
            try {
                repository?.close();
            } catch {
                // Process death may leave cleanup to reopen/recovery.
            }
            fs.rmSync(root, {
                recursive: true,
                force: true,
                maxRetries: 20,
                retryDelay: 25,
            });
        }
    },
);
