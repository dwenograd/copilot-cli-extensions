import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    removeRetainedTree,
    verifySignedTombstone,
    writeSignedTombstone,
} from "../persistence/index.mjs";
import {
    resolveCatalogRetentionPath,
    resolveRetentionPaths,
} from "../api/environment.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.retention-${label}-`),
    );
    roots.push(root);
    return root;
}

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 10,
            retryDelay: 20,
        });
    }
});

describe("state-root lifecycle retention", () => {
    it("keeps archive and catalog paths inside local retention roots", () => {
        const stateRoot = makeRoot("paths");
        const env = { CRUCIBLE_STATE_ROOT: stateRoot };
        const resolved = resolveRetentionPaths(
            stateRoot,
            "retention-investigation",
            { env },
        );
        expect(resolved.archiveDir).toBe(path.join(
            stateRoot,
            ".retention",
            "archives",
            "retention-investigation",
        ));
        expect(resolveCatalogRetentionPath(
            stateRoot,
            resolved.relativeArchivePath,
            { kind: "archive", env },
        )).toBe(resolved.archiveDir);

        expect(() => resolveRetentionPaths(
            stateRoot,
            "retention-investigation",
            {
                env,
                authenticatedBundleDestination: path.join(
                    path.dirname(stateRoot),
                    "outside-archive",
                ),
            },
        )).toThrow(/must be a child/u);
        expect(() => resolveCatalogRetentionPath(
            stateRoot,
            "../outside",
            { kind: "archive", env },
        )).toThrow(/canonical relative/u);
    });

    it("writes and verifies a canonical signed durable tombstone", () => {
        const stateRoot = makeRoot("tombstone");
        const env = { CRUCIBLE_STATE_ROOT: stateRoot };
        const retention = resolveRetentionPaths(
            stateRoot,
            "deleted-investigation",
            { env },
        );
        const payload = {
            investigationId: "deleted-investigation",
            createdAtMs: 1_000,
            deletedAt: "2026-07-14T00:00:00.000Z",
            domainVersion: 4,
            archiveDigest: `sha256:${"a".repeat(64)}`,
            domainHead: {
                seq: 2,
                eventHash:
                    `sha256:crucible-event-v4:${"b".repeat(64)}`,
            },
        };
        const written = writeSignedTombstone({
            file: retention.tombstonePath,
            keyRoot: retention.tombstoneKeyRoot,
            payload,
            env,
        });
        expect(written).toMatchObject({
            verified: true,
            payload,
        });
        expect(verifySignedTombstone({
            file: retention.tombstonePath,
            keyRoot: retention.tombstoneKeyRoot,
            expectedDigest: written.digest,
            expectedInvestigationId: "deleted-investigation",
            env,
        })).toMatchObject({
            verified: true,
            digest: written.digest,
        });
        expect(writeSignedTombstone({
            file: retention.tombstonePath,
            keyRoot: retention.tombstoneKeyRoot,
            payload: {
                ...payload,
                deletedAt: "2026-07-14T01:00:00.000Z",
            },
            env,
        }).digest).toBe(written.digest);

        const document = JSON.parse(
            fs.readFileSync(retention.tombstonePath, "utf8"),
        );
        document.payload.domainVersion = 5;
        fs.writeFileSync(
            retention.tombstonePath,
            `${JSON.stringify(document)}\n`,
        );
        expect(() => verifySignedTombstone({
            file: retention.tombstonePath,
            keyRoot: retention.tombstoneKeyRoot,
            expectedDigest: written.digest,
            expectedInvestigationId: "deleted-investigation",
            env,
        })).toThrow();
    });

    it("removes only trees contained by the authorized root", () => {
        const stateRoot = makeRoot("cleanup");
        const target = path.join(stateRoot, "child");
        fs.mkdirSync(target);
        fs.writeFileSync(path.join(target, "file.txt"), "retained");
        expect(removeRetainedTree({
            target,
            containmentRoot: stateRoot,
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
        })).toBe(true);
        expect(fs.existsSync(target)).toBe(false);
        expect(() => removeRetainedTree({
            target: path.dirname(stateRoot),
            containmentRoot: stateRoot,
            env: { CRUCIBLE_STATE_ROOT: stateRoot },
        })).toThrow(/escaped/u);
    });
});
