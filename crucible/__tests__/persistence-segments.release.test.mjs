import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { expect, it } from "vitest";

import {
    openRepository,
} from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

it("recovers a manifest-published segment after hard process death", () => {
    const root = fs.mkdtempSync(path.join(HERE, ".segments-release-"));
    const databaseFile = path.join(root, "events.sqlite");
    let repository = openRepository({
        file: databaseFile,
        segmentEventThreshold: 2,
    });
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

        const worker = spawnSync(
            process.execPath,
            [
                path.join(HERE, "fixtures", "segment-rotation-kill-worker.mjs"),
                databaseFile,
                "after-manifest-publish",
            ],
            {
                cwd: path.resolve(HERE, ".."),
                timeout: 30_000,
                windowsHide: true,
            },
        );
        expect(worker.status).not.toBe(0);

        repository = openRepository({
            file: databaseFile,
            segmentEventThreshold: 2,
        });
        expect(repository.getSegmentCatalog({ verify: true }).segments).toHaveLength(1);
        expect(repository.listEvents("segment-hard-kill").map((event) => event.seq))
            .toEqual([1, 2]);
        expect(repository.verifyInvestigation("segment-hard-kill").ok).toBe(true);
        repository.appendEvents({
            investigationId: "segment-hard-kill",
            expectedHead: repository.getHead("segment-hard-kill").eventHash,
            events: [{
                kind: "three",
                payload: {},
                createdAt: "2026-07-13T00:00:03.000Z",
            }],
        });
        expect(repository.getHead("segment-hard-kill").seq).toBe(3);
    } finally {
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
});
