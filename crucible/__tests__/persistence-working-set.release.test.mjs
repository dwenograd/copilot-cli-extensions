import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    DEFAULT_WORKING_SET_POLICY,
} from "../domain/index.mjs";
import {
    createWorkingSetController,
    openArtifactStore,
    openRepository,
} from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 40,
            retryDelay: 25,
        });
    }
});

describe("tiny-threshold working-set soak", () => {
    it("repeatedly rotates, checkpoints, reconciles, and preserves all references", () => {
        const root = fs.mkdtempSync(
            path.join(HERE, ".working-set-soak-"),
        );
        roots.push(root);
        const investigationId = "working-set-soak";
        const investigationDir = path.join(root, investigationId);
        const stateDir = path.join(investigationDir, "state");
        const artifactRoot = path.join(investigationDir, "artifacts");
        fs.mkdirSync(stateDir, { recursive: true });
        const repository = openRepository({
            file: path.join(stateDir, "events.sqlite"),
            segmentEventThreshold: 2,
            segmentByteThreshold: 1,
            walCheckpointBytes: 1,
            walCheckpointIntervalMs: 1,
        });
        const store = openArtifactStore({ root: artifactRoot });
        repository.ensureInvestigation({
            investigationId,
            metadata: { domainVersion: 4 },
        });
        const policy = {
            ...structuredClone(DEFAULT_WORKING_SET_POLICY),
            perAttemptBytes: 1024 * 1024,
            perInvestigationBytes: 256 * 1024 * 1024,
            terminalReserveBytes: 1024 * 1024,
            walCheckpointBytes: 1,
            walCheckpointIntervalMs: 1,
            segmentEventThreshold: 2,
            segmentByteThreshold: 1,
            maintenanceIntervalMs: 1,
            orphanGraceMs: 0,
        };
        const workingSet = createWorkingSetController({
            repository,
            artifactStore: store,
            investigationId,
            investigationDir,
            stateRoot: root,
            policy,
            globalLimitBytes: 512 * 1024 * 1024,
        });
        const objectIds = [];
        try {
            for (let index = 0; index < 32; index += 1) {
                const bytes = Buffer.from(`soak-object-${index}`);
                const stored = store.putBytes(bytes);
                objectIds.push(stored.id);
                const artifactId = `soak-artifact-${index}`;
                repository.registerExternalArtifact({
                    investigationId,
                    artifactId,
                    algo: "sha256",
                    hash: stored.hash,
                    sizeBytes: stored.size,
                    contentType:
                        "application/vnd.crucible.measurement-receipt+json",
                });
                repository.markArtifactDurable(artifactId);
                repository.appendEvents({
                    investigationId,
                    expectedHead:
                        repository.getHead(investigationId).eventHash,
                    events: [{
                        kind: "soak-evidence",
                        payload: { objectId: stored.id, index },
                        artifactIds: [artifactId],
                    }],
                });
                workingSet.maintain({
                    force: true,
                    quiescent: true,
                });
            }
            const telemetry = workingSet.telemetry();
            expect(telemetry.repository.sealedSegmentCount)
                .toBeGreaterThan(8);
            expect(telemetry.repository.walBytes)
                .toBeLessThanOrEqual(policy.walCheckpointBytes);
            for (const objectId of objectIds) {
                expect(store.verifyObject(objectId).ok).toBe(true);
            }
            expect(repository.verifyInvestigation(investigationId).ok)
                .toBe(true);
        } finally {
            repository.close();
        }
    }, 60_000);
});
