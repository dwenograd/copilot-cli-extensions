import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
    ERROR_CODES,
    SEGMENT_SEAL_STAGES,
    canonicalize,
    exportBundle,
    importBundle,
    openArtifactStore,
    openRepository,
    openRepositoryReadOnly,
    readBundleManifest,
} from "../persistence/index.mjs";
import { DatabaseSync } from "../persistence/sqlite.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];
const INVESTIGATION_ID = "segmented-investigation";

afterEach(() => {
    for (const root of roots.splice(0)) {
        fs.rmSync(root, {
            recursive: true,
            force: true,
            maxRetries: 20,
            retryDelay: 25,
        });
    }
});

function root(label) {
    const created = fs.mkdtempSync(path.join(HERE, `.segments-${label}-`));
    roots.push(created);
    return created;
}

function event(seq, overrides = {}) {
    return {
        kind: `event-${seq}`,
        payload: { seq, text: "x".repeat(seq) },
        createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, seq)).toISOString(),
        ...overrides,
    };
}

function openSegmented(directory, overrides = {}) {
    const repository = openRepository({
        file: path.join(directory, "events.sqlite"),
        segmentEventThreshold: 2,
        now: () => "2026-07-13T12:00:00.000Z",
        ...overrides,
    });
    repository.ensureInvestigation({
        investigationId: INVESTIGATION_ID,
        metadata: { domainVersion: 4, role: "test" },
    });
    return repository;
}

function appendRange(repository, first, last) {
    const expectedHead = repository.getHead(INVESTIGATION_ID).eventHash;
    return repository.appendEvents({
        investigationId: INVESTIGATION_ID,
        expectedHead,
        events: Array.from(
            { length: last - first + 1 },
            (_unused, index) => event(first + index),
        ),
    });
}

function rotate(repository, overrides = {}) {
    return repository.rotateEventSegment({
        investigationId: INVESTIGATION_ID,
        quiescent: true,
        ...overrides,
    });
}

function catchError(fn) {
    try {
        fn();
    } catch (error) {
        return error;
    }
    throw new Error("expected operation to fail");
}

describe("immutable segmented event repository", () => {
    it("replays three sealed segments plus active identically to a single database", () => {
        const directory = root("replay");
        const segmented = openSegmented(directory);
        const control = openRepository({
            file: path.join(directory, "control.sqlite"),
            now: () => "2026-07-13T12:00:00.000Z",
        });
        control.ensureInvestigation({
            investigationId: INVESTIGATION_ID,
            metadata: { domainVersion: 4, role: "test" },
        });
        try {
            for (const first of [1, 3, 5]) {
                appendRange(segmented, first, first + 1);
                appendRange(control, first, first + 1);
                expect(rotate(segmented).rotated).toBe(true);
            }
            appendRange(segmented, 7, 7);
            appendRange(control, 7, 7);

            expect(segmented.listEvents(INVESTIGATION_ID))
                .toEqual(control.listEvents(INVESTIGATION_ID));
            expect(segmented.getHead(INVESTIGATION_ID))
                .toEqual(control.getHead(INVESTIGATION_ID));
            expect(segmented.countEvents(INVESTIGATION_ID)).toBe(7);
            expect(segmented.verifyInvestigation(INVESTIGATION_ID)).toMatchObject({
                ok: true,
                checkedEvents: 7,
            });

            const catalog = segmented.getSegmentCatalog({ verify: true });
            expect(catalog.generation).toBe(3);
            expect(catalog.segments.map((entry) => [
                entry.index,
                entry.firstSeq,
                entry.lastSeq,
                entry.eventCount,
            ])).toEqual([
                [0, 1, 2, 2],
                [1, 3, 4, 2],
                [2, 5, 6, 2],
            ]);
            expect(catalog.segments[1].previousSegmentAnchor).toMatchObject({
                index: 0,
                lastSeq: 2,
                lastEventHash: catalog.segments[0].lastEventHash,
                fileSha256: catalog.segments[0].fileSha256,
            });

            const raw = new DatabaseSync(segmented.databaseFile, { readOnly: true });
            try {
                expect(Number(raw.prepare(
                    "SELECT COUNT(*) AS count FROM events WHERE investigation_id = ?",
                ).get(INVESTIGATION_ID).count)).toBe(1);
            } finally {
                raw.close();
            }
        } finally {
            segmented.close();
            control.close();
        }

        const readOnly = openRepositoryReadOnly({
            file: path.join(directory, "events.sqlite"),
        });
        try {
            expect(readOnly.readOnly).toBe(true);
            expect(readOnly.listEvents(INVESTIGATION_ID).map((row) => row.seq))
                .toEqual([1, 2, 3, 4, 5, 6, 7]);
            expect(readOnly.verifySegmentChain()).toMatchObject({
                ok: true,
                segmentCount: 3,
            });
            expect(() => rotate(readOnly)).toThrow(expect.objectContaining({
                code: ERROR_CODES.INVALID_ARGUMENT,
            }));
        } finally {
            readOnly.close();
        }
    });

    it("preserves CAS, evidence idempotency, terminal closure, and artifact refs across boundaries", () => {
        const directory = root("authority");
        const repository = openSegmented(directory, { segmentEventThreshold: 1 });
        try {
            repository.putInlineArtifact({
                investigationId: INVESTIGATION_ID,
                artifactId: "inline-proof",
                bytes: Buffer.from("proof"),
            });
            repository.appendEvents({
                investigationId: INVESTIGATION_ID,
                expectedHead: null,
                events: [{
                    ...event(1),
                    artifactIds: ["inline-proof"],
                }],
            });
            rotate(repository);
            repository.putInlineArtifact({
                investigationId: INVESTIGATION_ID,
                artifactId: "late-proof",
                bytes: Buffer.from("late"),
            });
            repository.referenceArtifact({
                investigationId: INVESTIGATION_ID,
                artifactId: "late-proof",
                seq: 1,
            });
            expect(repository.listArtifactRefsForEvent(INVESTIGATION_ID, 1))
                .toHaveLength(2);

            const duplicateSource = repository.ingestEvidence({
                investigationId: INVESTIGATION_ID,
                attemptId: "attempt-1",
                evidenceKind: "stdout",
                kind: "evidence",
                payload: { ok: true },
                createdAt: event(2).createdAt,
            });
            expect(duplicateSource.deduplicated).toBe(false);
            rotate(repository);
            expect(repository.ingestEvidence({
                investigationId: INVESTIGATION_ID,
                attemptId: "attempt-1",
                evidenceKind: "stdout",
                kind: "evidence",
                payload: { ok: true },
                createdAt: event(2).createdAt,
            })).toMatchObject({
                deduplicated: true,
                event: { seq: 2 },
            });

            const stale = repository.getHead(INVESTIGATION_ID);
            const other = openRepository({ file: repository.databaseFile });
            try {
                repository.appendEvents({
                    investigationId: INVESTIGATION_ID,
                    expectedHead: stale.eventHash,
                    events: [event(3)],
                });
                expect(() => other.appendEvents({
                    investigationId: INVESTIGATION_ID,
                    expectedHead: stale.eventHash,
                    events: [event(4)],
                })).toThrow(expect.objectContaining({
                    code: ERROR_CODES.CAS_CONFLICT,
                }));
            } finally {
                other.close();
            }

            repository.appendEvents({
                investigationId: INVESTIGATION_ID,
                expectedHead: repository.getHead(INVESTIGATION_ID).eventHash,
                events: [{
                    ...event(4),
                    kind: "verified",
                    terminal: { kind: "verified_result" },
                }],
            });
            rotate(repository);
            expect(repository.getTerminalEvent(INVESTIGATION_ID)).toMatchObject({
                seq: 4,
                terminalKind: "verified_result",
            });
            expect(() => repository.appendEvents({
                investigationId: INVESTIGATION_ID,
                expectedHead: repository.getHead(INVESTIGATION_ID).eventHash,
                events: [event(5)],
            })).toThrow(expect.objectContaining({
                code: ERROR_CODES.TERMINAL_EXISTS,
            }));
            expect(repository.verifyInvestigation(INVESTIGATION_ID).ok).toBe(true);
        } finally {
            repository.close();
        }
    });

    it("rotates only when a count or byte threshold is reached at quiescence", () => {
        const directory = root("threshold");
        const repository = openSegmented(directory, {
            segmentEventThreshold: Number.POSITIVE_INFINITY,
            segmentByteThreshold: 1,
        });
        try {
            appendRange(repository, 1, 1);
            expect(repository.rotateEventSegment({
                investigationId: INVESTIGATION_ID,
                quiescent: false,
            })).toMatchObject({
                rotated: false,
                reason: "not_quiescent",
            });
            expect(rotate(repository)).toMatchObject({
                rotated: true,
                eventCount: 1,
            });
        } finally {
            repository.close();
        }
    });

    it("initializes a catalog around an existing nonsegmented v4 database without rewriting events", () => {
        const directory = root("initialize");
        let repository = openSegmented(directory, { segmentEventThreshold: 100 });
        appendRange(repository, 1, 2);
        const expected = repository.listEvents(INVESTIGATION_ID);
        const catalogFile = repository.segmentCatalogFile;
        repository.close();
        fs.unlinkSync(catalogFile);

        repository = openRepository({ file: path.join(directory, "events.sqlite") });
        try {
            expect(repository.getSegmentCatalog()).toMatchObject({
                generation: 0,
                segments: [],
            });
            expect(repository.listEvents(INVESTIGATION_ID)).toEqual(expected);
        } finally {
            repository.close();
        }
    });

    it("anchors interleaved investigation chains independently in one catalog", () => {
        const directory = root("multi-investigation");
        const repository = openSegmented(directory, { segmentEventThreshold: 1 });
        const otherId = "other-investigation";
        repository.ensureInvestigation({
            investigationId: otherId,
            metadata: { domainVersion: 4 },
        });
        try {
            appendRange(repository, 1, 1);
            rotate(repository);
            repository.appendEvents({
                investigationId: otherId,
                expectedHead: null,
                events: [event(1)],
            });
            repository.rotateEventSegment({
                investigationId: otherId,
                quiescent: true,
            });
            appendRange(repository, 2, 2);
            rotate(repository);

            const entries = repository.getSegmentCatalog({ verify: true }).segments;
            expect(entries.map((entry) => entry.investigationId)).toEqual([
                INVESTIGATION_ID,
                otherId,
                INVESTIGATION_ID,
            ]);
            expect(entries[1].previousSegmentAnchor.index).toBeNull();
            expect(entries[2].previousSegmentAnchor).toMatchObject({
                index: 0,
                lastSeq: 1,
                lastEventHash: entries[0].lastEventHash,
            });
            expect(repository.listEvents(INVESTIGATION_ID).map((row) => row.seq))
                .toEqual([1, 2]);
            expect(repository.listEvents(otherId).map((row) => row.seq)).toEqual([1]);
        } finally {
            repository.close();
        }
    });
});

describe("segment rotation recovery and contention", () => {
    it.each(SEGMENT_SEAL_STAGES)(
        "recovers a valid old or new state after %s",
        (faultStage) => {
            const directory = root(`crash-${faultStage}`);
            let repository = openSegmented(directory);
            appendRange(repository, 1, 2);
            expect(() => rotate(repository, {
                faultInjector: (stage) => {
                    if (stage === faultStage) throw new Error(`crash:${stage}`);
                },
            })).toThrow(`crash:${faultStage}`);
            repository.close();

            const transitional = openRepositoryReadOnly({
                file: path.join(directory, "events.sqlite"),
            });
            try {
                expect(transitional.listEvents(INVESTIGATION_ID).map((row) => row.seq))
                    .toEqual([1, 2]);
                expect(transitional.verifyInvestigation(INVESTIGATION_ID).ok).toBe(true);
            } finally {
                transitional.close();
            }

            repository = openSegmented(directory);
            try {
                const expectedSegments = SEGMENT_SEAL_STAGES.indexOf(faultStage) >= 3
                    ? 1
                    : 0;
                expect(repository.getSegmentCatalog({ verify: true }).segments)
                    .toHaveLength(expectedSegments);
                expect(repository.listEvents(INVESTIGATION_ID).map((row) => row.seq))
                    .toEqual([1, 2]);
                expect(repository.verifyInvestigation(INVESTIGATION_ID).ok).toBe(true);
                appendRange(repository, 3, 3);
                expect(repository.listEvents(INVESTIGATION_ID).map((row) => row.seq))
                    .toEqual([1, 2, 3]);
                expect(fs.existsSync(
                    repository.segmentCatalogFile.replace(/\.json$/u, ".prepare.json"),
                )).toBe(false);
            } finally {
                repository.close();
            }
        },
    );

    it("serializes concurrent rotation and publishes exactly one segment", () => {
        const directory = root("concurrent");
        const first = openSegmented(directory);
        appendRange(first, 1, 2);
        const second = openRepository({
            file: first.databaseFile,
            busyTimeoutMs: 0,
            segmentEventThreshold: 2,
        });
        let contention = null;
        try {
            const result = rotate(first, {
                faultInjector: (stage) => {
                    if (stage === "after-prepare") {
                        contention = catchError(() => rotate(second));
                    }
                },
            });
            expect(result.rotated).toBe(true);
            expect(contention?.code).toBe(ERROR_CODES.STORAGE_ERROR);
            expect(rotate(second)).toMatchObject({
                rotated: false,
                reason: "below_threshold",
            });
            expect(first.getSegmentCatalog({ verify: true }).segments).toHaveLength(1);
            expect(first.listEvents(INVESTIGATION_ID).map((row) => row.seq))
                .toEqual([1, 2]);
        } finally {
            second.close();
            first.close();
        }
    });
});

describe("segment and catalog tamper detection", () => {
    function sealedFixture(label, segmentCount = 1) {
        const directory = root(label);
        const repository = openSegmented(directory, { segmentEventThreshold: 1 });
        for (let seq = 1; seq <= segmentCount; seq += 1) {
            appendRange(repository, seq, seq);
            rotate(repository);
        }
        const catalogFile = repository.segmentCatalogFile;
        const catalog = repository.getSegmentCatalog();
        repository.close();
        return { directory, catalogFile, catalog };
    }

    it("rejects a missing sealed file", () => {
        const fixture = sealedFixture("missing");
        fs.unlinkSync(path.join(fixture.directory, fixture.catalog.segments[0].file));
        expect(() => openRepositoryReadOnly({
            file: path.join(fixture.directory, "events.sqlite"),
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.SEGMENT_INTEGRITY_VIOLATION,
        }));
    });

    it("rejects corrupted sealed bytes", () => {
        const fixture = sealedFixture("corrupt");
        const segment = path.join(fixture.directory, fixture.catalog.segments[0].file);
        const fd = fs.openSync(segment, "r+");
        try {
            fs.writeSync(fd, Buffer.from([0xff]), 0, 1, 128);
            fs.fsyncSync(fd);
        } finally {
            fs.closeSync(fd);
        }
        expect(() => openRepositoryReadOnly({
            file: path.join(fixture.directory, "events.sqlite"),
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.SEGMENT_INTEGRITY_VIOLATION,
        }));
    });

    it("rejects reordered entries and a missing manifest", () => {
        const reordered = sealedFixture("reordered", 2);
        const changed = {
            ...reordered.catalog,
            segments: [...reordered.catalog.segments].reverse(),
        };
        fs.writeFileSync(
            reordered.catalogFile,
            `${canonicalize(changed)}\n`,
        );
        expect(() => openRepositoryReadOnly({
            file: path.join(reordered.directory, "events.sqlite"),
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.SEGMENT_INTEGRITY_VIOLATION,
        }));

        const missing = sealedFixture("missing-manifest");
        fs.unlinkSync(missing.catalogFile);
        expect(() => openRepositoryReadOnly({
            file: path.join(missing.directory, "events.sqlite"),
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.SEGMENT_INTEGRITY_VIOLATION,
        }));

        const corrupt = sealedFixture("corrupt-manifest");
        fs.writeFileSync(corrupt.catalogFile, "{}\n");
        expect(() => openRepositoryReadOnly({
            file: path.join(corrupt.directory, "events.sqlite"),
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.SEGMENT_INTEGRITY_VIOLATION,
        }));
    });

    it("rejects duplicate active authority without a recovery journal", () => {
        const fixture = sealedFixture("duplicate-active");
        const sealed = new DatabaseSync(
            path.join(fixture.directory, fixture.catalog.segments[0].file),
            { readOnly: true },
        );
        const row = sealed.prepare("SELECT * FROM events WHERE seq = 1").get();
        sealed.close();
        const active = new DatabaseSync(path.join(fixture.directory, "events.sqlite"));
        try {
            active.prepare(`
                INSERT INTO events(
                    investigation_id, seq, prev_hash, event_hash, kind, payload,
                    is_terminal, terminal_kind, attempt_id, evidence_kind, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                row.investigation_id,
                row.seq,
                row.prev_hash,
                row.event_hash,
                row.kind,
                row.payload,
                row.is_terminal,
                row.terminal_kind,
                row.attempt_id,
                row.evidence_kind,
                row.created_at,
            );
        } finally {
            active.close();
        }
        expect(() => openRepositoryReadOnly({
            file: path.join(fixture.directory, "events.sqlite"),
        })).toThrow(expect.objectContaining({
            code: ERROR_CODES.SEGMENT_INTEGRITY_VIOLATION,
        }));
    });
});

describe("segmented bundle closure", () => {
    it("roundtrips the catalog, three sealed files, and active tail", () => {
        const directory = root("bundle");
        let repository = openSegmented(directory, { segmentEventThreshold: 1 });
        const store = openArtifactStore({ root: path.join(directory, "cas") });
        for (let seq = 1; seq <= 3; seq += 1) {
            appendRange(repository, seq, seq);
            rotate(repository);
        }
        appendRange(repository, 4, 4);

        const bundleDir = path.join(directory, "bundle");
        const exported = exportBundle({
            store,
            dbFile: repository.databaseFile,
            destDir: bundleDir,
            investigationId: INVESTIGATION_ID,
            now: () => "2026-07-13T13:00:00.000Z",
        });
        const manifest = readBundleManifest(bundleDir);
        expect(manifest.segments).toMatchObject({
            catalogGeneration: 3,
            segmentCount: 3,
        });
        expect(manifest.segments.files.map((file) => file.index)).toEqual([0, 1, 2]);

        const importedDir = path.join(directory, "imported");
        importBundle({
            bundleDir,
            destDir: importedDir,
            expectedDigest: exported.digest,
        });
        repository.close();
        repository = openRepositoryReadOnly({
            file: path.join(importedDir, "db", "database.sqlite"),
        });
        try {
            expect(repository.listEvents(INVESTIGATION_ID).map((row) => row.seq))
                .toEqual([1, 2, 3, 4]);
            expect(repository.getSegmentCatalog({ verify: true }).segments)
                .toHaveLength(3);
            expect(repository.verifyInvestigation(INVESTIGATION_ID).ok).toBe(true);
        } finally {
            repository.close();
        }
    });
});
