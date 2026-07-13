import { afterEach, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
    artifactRefsFromProvenance,
    canonicalJson,
    scientificReplaySummary,
} from "../domain/index.mjs";
import {
    BUNDLE_ERROR_CODES,
    exportBundle,
    importBundle,
    canonicalize,
    openRepositoryReadOnly,
    readBundleManifest,
} from "../persistence/index.mjs";
import { createDomainRepositoryAdapter } from "../runtime/index.mjs";
import {
    removeStaleTestRoots,
    removeTreeRobust,
} from "./test-cleanup.mjs";
import { createReplayStatsFixture } from "./v4-replay-stats-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
const fixtures = [];

beforeAll(async () => {
    await removeStaleTestRoots(HERE, ".v4-replay-stats-", {
        label: "stale v4 replay statistics test root",
    });
});

function makeRoot(label) {
    const root = fs.mkdtempSync(
        path.join(HERE, `.v4-replay-stats-${label}-`),
    );
    roots.push(root);
    return root;
}

function trackedFixture(label, options = {}) {
    const fixture = createReplayStatsFixture(makeRoot(label), options);
    fixtures.push(fixture);
    return fixture;
}

function objectPathForArtifact(manifest, artifactId) {
    const artifact = manifest.artifacts.find(
        (item) => item.artifactId === artifactId,
    );
    const object = manifest.objects.find(
        (item) => item.id === artifact?.object,
    );
    if (object === undefined) {
        throw new Error(`bundle object for ${artifactId} is missing`);
    }
    return object.path;
}

function regenerateInventory(bundleDir) {
    const files = [];
    const walk = (directory, prefix = "") => {
        for (const name of fs.readdirSync(directory).sort()) {
            const absolute = path.join(directory, name);
            const relative = prefix === "" ? name : `${prefix}/${name}`;
            const stat = fs.lstatSync(absolute);
            if (stat.isDirectory()) {
                walk(absolute, relative);
            } else if (relative !== "inventory.sha256") {
                files.push({ absolute, relative });
            }
        }
    };
    walk(bundleDir);
    const lines = files
        .sort((left, right) => left.relative.localeCompare(right.relative))
        .map(({ absolute, relative }) =>
            `${createHash("sha256").update(fs.readFileSync(absolute)).digest("hex")}  ${relative}`);
    fs.writeFileSync(
        path.join(bundleDir, "inventory.sha256"),
        `${lines.join("\n")}\n`,
    );
}

afterEach(async () => {
    for (const fixture of fixtures.splice(0)) {
        try {
            fixture.close();
        } catch {
            // Already closed by the test.
        }
    }
    for (const root of roots.splice(0)) {
        await removeTreeRobust(root, {
            label: "v4 replay statistics test root",
            timeoutMs: 30_000,
        });
    }
});

describe("v4 raw-authority replay statistics", () => {
    it("replays through a read-only repository without mutating persisted state", () => {
        const fixture = trackedFixture("read-only");
        const expected = fixture.replay.scientificReplay;
        fixture.close();
        fixtures.splice(fixtures.indexOf(fixture), 1);
        const beforeBytes = fs.readFileSync(fixture.dbFile);

        const repository = openRepositoryReadOnly({
            file: fixture.dbFile,
        });
        try {
            const replay = createDomainRepositoryAdapter({
                repository,
                investigationId: fixture.investigationId,
                ensure: false,
            }).replayScientific();
            expect(canonicalJson(replay.scientificReplay))
                .toBe(canonicalJson(expected));
            expect(scientificReplaySummary(replay.scientificReplay)).toEqual(
                scientificReplaySummary(replay.aggregate.scientificReplay),
            );
        } finally {
            repository.close();
        }
        expect(fs.readFileSync(fixture.dbFile)).toEqual(beforeBytes);
        expect(fs.readFileSync(fixture.dbFile)).toEqual(beforeBytes);
    });

    it("round-trips every raw receipt artifact and reproduces scientific bytes", () => {
        const fixture = trackedFixture("bundle");
        const bundleDir = path.join(fixture.root, "bundle");
        const importedDir = path.join(fixture.root, "imported");
        const exported = exportBundle({
            store: fixture.store,
            dbFile: fixture.dbFile,
            destDir: bundleDir,
            investigationId: fixture.investigationId,
            now: () => "2026-07-12T00:00:00.000Z",
        });
        const manifest = readBundleManifest(bundleDir);
        expect(manifest.scientificReplay).toEqual(
            scientificReplaySummary(
                fixture.replay.scientificReplay,
                fixture.replay.aggregate.terminal,
            ),
        );

        const expectedArtifactIds = new Set();
        const receiptArtifactIds = [];
        const scheduleArtifactIds = [];
        for (const evidenceId of fixture.replay.aggregate.evidenceOrder) {
            const evidence = fixture.replay.aggregate.evidence[evidenceId];
            receiptArtifactIds.push(
                ...evidence.receipt.provenance.measurements.map(
                    (measurement) => measurement.receiptArtifact.artifactId,
                ),
            );
            if (evidence.receipt.provenance.replicationScheduleArtifact !== null) {
                scheduleArtifactIds.push(
                    evidence.receipt.provenance.replicationScheduleArtifact
                        .artifactId,
                );
            }
            for (const artifact of artifactRefsFromProvenance(
                evidence.receipt.provenance,
            )) {
                expectedArtifactIds.add(artifact.artifactId);
            }
        }
        expect(manifest.artifacts.map((item) => item.artifactId))
            .toEqual([...expectedArtifactIds].sort());
        expect(receiptArtifactIds.length).toBeGreaterThan(0);
        expect(scheduleArtifactIds.length).toBeGreaterThan(0);
        expect(receiptArtifactIds.every((artifactId) =>
            expectedArtifactIds.has(artifactId))).toBe(true);
        expect(scheduleArtifactIds.every((artifactId) =>
            expectedArtifactIds.has(artifactId))).toBe(true);

        const imported = importBundle({
            bundleDir,
            destDir: importedDir,
            expectedDigest: exported.digest,
        });
        expect(imported.scientificReplay).toEqual(
            manifest.scientificReplay,
        );

        const importedRepository = openRepositoryReadOnly({
            file: path.join(importedDir, "db", "database.sqlite"),
        });
        try {
            const replay = createDomainRepositoryAdapter({
                repository: importedRepository,
                investigationId: fixture.investigationId,
                ensure: false,
            }).replayScientific();
            const source = fixture.replay.scientificReplay;
            const restored = replay.scientificReplay;
            expect(Buffer.from(canonicalJson(
                replay.aggregate.contract.statisticalPolicy,
            ))).toEqual(Buffer.from(canonicalJson(
                fixture.replay.aggregate.contract.statisticalPolicy,
            )));
            for (const evidenceId of fixture.replay.aggregate.evidenceOrder) {
                const sourceEvidence =
                    fixture.replay.aggregate.evidence[evidenceId];
                if (sourceEvidence.sourceKind !== "harness"
                    || (sourceEvidence.purpose !== "candidate"
                        && sourceEvidence.purpose !== "validation")) {
                    continue;
                }
                const restoredEvidence = replay.aggregate.evidence[evidenceId];
                const sourceObservation = fixture.replay.aggregate.observations[
                    sourceEvidence.observationId
                ];
                const restoredObservation = replay.aggregate.observations[
                    restoredEvidence.observationId
                ];
                const sourceCommand = fixture.replay.aggregate.commands[
                    sourceObservation.commandId
                ].command;
                const restoredCommand = replay.aggregate.commands[
                    restoredObservation.commandId
                ].command;
                expect(Buffer.from(canonicalJson(restoredObservation.receipt)))
                    .toEqual(Buffer.from(canonicalJson(sourceObservation.receipt)));
                expect(Buffer.from(canonicalJson(restoredObservation.data)))
                    .toEqual(Buffer.from(canonicalJson(sourceObservation.data)));
                expect(Buffer.from(canonicalJson(restoredCommand)))
                    .toEqual(Buffer.from(canonicalJson(sourceCommand)));
            }
            expect(Buffer.from(canonicalJson(restored.scientificAggregate)))
                .toEqual(Buffer.from(canonicalJson(source.scientificAggregate)));
            expect(Buffer.from(canonicalJson(restored.claimStates)))
                .toEqual(Buffer.from(canonicalJson(source.claimStates)));
            expect(Buffer.from(canonicalJson(restored.alphaLedger)))
                .toEqual(Buffer.from(canonicalJson(source.alphaLedger)));
            expect(restored.closureRoot).toBe(source.closureRoot);
            expect(scientificReplaySummary(restored))
                .toEqual(scientificReplaySummary(source));
        } finally {
            importedRepository.close();
        }
    });

    it("rejects a self-checksummed bundle whose replay digest cache was tampered", () => {
        const fixture = trackedFixture("bundle-cache-tamper");
        const bundleDir = path.join(fixture.root, "bundle");
        exportBundle({
            store: fixture.store,
            dbFile: fixture.dbFile,
            destDir: bundleDir,
            investigationId: fixture.investigationId,
            now: () => "2026-07-12T00:00:00.000Z",
        });
        const manifestPath = path.join(bundleDir, "manifest.json");
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        manifest.scientificReplay.scientificAggregateHash =
            `sha256:crucible-scientific-aggregate-v1:${"0".repeat(64)}`;
        fs.writeFileSync(
            manifestPath,
            `${canonicalize(manifest)}\n`,
        );
        regenerateInventory(bundleDir);

        expect(() => importBundle({
            bundleDir,
            destDir: path.join(fixture.root, "tampered-import"),
            allowUnauthenticated: true,
        })).toThrow(expect.objectContaining({
            code: "CRUCIBLE_BUNDLE_CLOSURE_INVALID",
        }));
    });

    it("rejects a novelty-role receipt whose structural facts were tampered", () => {
        const fixture = trackedFixture("bundle-novelty-tamper");
        const bundleDir = path.join(fixture.root, "bundle");
        exportBundle({
            store: fixture.store,
            dbFile: fixture.dbFile,
            destDir: bundleDir,
            investigationId: fixture.investigationId,
            now: () => "2026-07-12T00:00:00.000Z",
        });
        const aggregate = fixture.adapter.replay().aggregate;
        const evidence = aggregate.evidence["replay-candidate-evidence"];
        const noveltyMeasurement = evidence.receipt.provenance.measurements.find(
            (measurement) => measurement.role === "novelty",
        );
        const manifest = readBundleManifest(bundleDir);
        const receiptPath = path.join(
            bundleDir,
            objectPathForArtifact(
                manifest,
                noveltyMeasurement.receiptArtifact.artifactId,
            ),
        );
        const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
        receipt.parsed.metrics.nodeCount += 1;
        fs.writeFileSync(receiptPath, `${canonicalize(receipt)}\n`);
        regenerateInventory(bundleDir);

        expect(() => importBundle({
            bundleDir,
            destDir: path.join(fixture.root, "tampered-novelty-import"),
            allowUnauthenticated: true,
        })).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.TAMPER_DETECTED,
        }));
    });

    it("rejects tampered, missing, or reordered statistical bundle authority", () => {
        const fixture = trackedFixture("bundle-raw-authority");
        const bundleDir = path.join(fixture.root, "bundle");
        exportBundle({
            store: fixture.store,
            dbFile: fixture.dbFile,
            destDir: bundleDir,
            investigationId: fixture.investigationId,
            now: () => "2026-07-12T00:00:00.000Z",
        });
        const manifest = readBundleManifest(bundleDir);
        const candidateEvidence = fixture.replay.aggregate.evidence[
            "replay-candidate-evidence"
        ];
        const receiptArtifactId =
            candidateEvidence.receipt.provenance.measurements[0]
                .receiptArtifact.artifactId;
        const scheduleArtifactId =
            candidateEvidence.receipt.provenance.replicationScheduleArtifact
                .artifactId;

        const tamperedDir = path.join(fixture.root, "tampered-receipt");
        fs.cpSync(bundleDir, tamperedDir, { recursive: true });
        fs.appendFileSync(
            path.join(
                tamperedDir,
                ...objectPathForArtifact(
                    manifest,
                    receiptArtifactId,
                ).split("/"),
            ),
            "\n",
        );
        regenerateInventory(tamperedDir);
        expect(() => importBundle({
            bundleDir: tamperedDir,
            destDir: path.join(fixture.root, "tampered-import"),
            allowUnauthenticated: true,
        })).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.TAMPER_DETECTED,
        }));

        const missingDir = path.join(fixture.root, "missing-schedule");
        fs.cpSync(bundleDir, missingDir, { recursive: true });
        fs.rmSync(path.join(
            missingDir,
            ...objectPathForArtifact(
                manifest,
                scheduleArtifactId,
            ).split("/"),
        ));
        regenerateInventory(missingDir);
        expect(() => importBundle({
            bundleDir: missingDir,
            destDir: path.join(fixture.root, "missing-import"),
            allowUnauthenticated: true,
        })).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.CLOSURE_INVALID,
        }));

        const reorderedDir = path.join(fixture.root, "reordered-artifacts");
        fs.cpSync(bundleDir, reorderedDir, { recursive: true });
        const manifestPath = path.join(reorderedDir, "manifest.json");
        const reordered = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        reordered.artifacts.reverse();
        fs.writeFileSync(
            manifestPath,
            `${canonicalize(reordered)}\n`,
        );
        regenerateInventory(reorderedDir);
        expect(() => importBundle({
            bundleDir: reorderedDir,
            destDir: path.join(fixture.root, "reordered-import"),
            allowUnauthenticated: true,
        })).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.MANIFEST_INVALID,
        }));
    });

    it("rejects a content-addressed receipt that disagrees with raw replay facts", () => {
        const fixture = trackedFixture("receipt-fact-mismatch", {
            receiptMutation({ observationId, arm, parsed }) {
                if (observationId === "replay-candidate-observation"
                    && arm.armId === "candidate"
                    && parsed.role === "search") {
                    return {
                        ...parsed,
                        metrics: {
                            ...parsed.metrics,
                            score: parsed.metrics.score - 1,
                        },
                    };
                }
                return parsed;
            },
        });
        expect(() => exportBundle({
            store: fixture.store,
            dbFile: fixture.dbFile,
            destDir: path.join(fixture.root, "bundle"),
            investigationId: fixture.investigationId,
            now: () => "2026-07-12T00:00:00.000Z",
        })).toThrow(expect.objectContaining({
            code: BUNDLE_ERROR_CODES.CLOSURE_INVALID,
        }));
    });
});
