import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
    BUNDLE_VERSION,
    openRepository,
    openArtifactStore,
    exportBundle,
    importBundle,
    readBundleManifest,
    canonicalize,
    BUNDLE_ERROR_CODES,
} from "../persistence/index.mjs";
import {
    DEFAULT_SEARCH_POLICY,
    DOMAIN_VERSION,
    createInvestigationContract,
} from "../domain/index.mjs";
import { appendLegacyV3Investigation } from "./legacy-v3-fixture.mjs";
import { makeV4ContractInput } from "./v4-contract-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SNAPSHOT_CONTENT_TYPE = "application/vnd.crucible.snapshot+json";

let base;
let store;
let repo;
let snap;
let extraObject;

function sha256(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

function sha256File(file) {
    return sha256(fs.readFileSync(file));
}

function listFiles(root) {
    const files = [];
    const walk = (dir, prefix = []) => {
        for (const name of fs.readdirSync(dir).sort()) {
            const abs = path.join(dir, name);
            const rel = [...prefix, name];
            const stat = fs.lstatSync(abs);
            if (stat.isDirectory()) {
                walk(abs, rel);
            } else if (stat.isFile()) {
                files.push(rel.join("/"));
            }
        }
    };
    walk(root);
    return files.sort();
}

function regenerateInventory(bundleDir) {
    const lines = listFiles(bundleDir)
        .filter((rel) => rel !== "inventory.sha256")
        .map((rel) => `${sha256File(path.join(bundleDir, ...rel.split("/")))}  ${rel}`);
    fs.writeFileSync(path.join(bundleDir, "inventory.sha256"), lines.join("\n") + "\n");
}

function rewriteManifest(bundleDir, mutate) {
    const manifestPath = path.join(bundleDir, "manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    mutate(manifest);
    fs.writeFileSync(manifestPath, canonicalize(manifest) + "\n");
    regenerateInventory(bundleDir);
}

function catchErr(fn) {
    try {
        fn();
    } catch (err) {
        return err;
    }
    throw new Error("expected the operation to throw");
}

function registerObject(objectId, artifactId, contentType = "application/octet-stream") {
    const bytes = store.readObject(objectId);
    repo.registerExternalArtifact({
        investigationId: "inv-1",
        artifactId,
        algo: "sha256",
        hash: objectId.slice("sha256:".length),
        sizeBytes: bytes.length,
        contentType,
    });
    repo.markArtifactDurable(artifactId);
    repo.referenceArtifact({ investigationId: "inv-1", artifactId });
}

function stageEntries(prefix) {
    return fs.readdirSync(base)
        .filter((name) => name.startsWith(`.crucible-bundle-${prefix}-`)
            && name.endsWith(".stage"));
}

beforeEach(() => {
    base = fs.mkdtempSync(path.join(HERE, ".persist-tmp-"));
    store = openArtifactStore({ root: path.join(base, "cas") });

    const src = path.join(base, "evidence");
    fs.mkdirSync(path.join(src, "logs"), { recursive: true });
    fs.writeFileSync(path.join(src, "report.txt"), "the target was reachable");
    fs.writeFileSync(path.join(src, "logs", "trace.log"), "step-1\nstep-2\n");
    snap = store.ingestDirectory({ sourceDir: src });
    extraObject = store.putBytes(Buffer.from("standalone-attachment"));

    repo = openRepository({ file: path.join(base, "events.sqlite") });
    repo.ensureInvestigation({
        investigationId: "inv-1",
        metadata: { case: "audit", domainVersion: DOMAIN_VERSION },
    });
    repo.appendEvents({
        investigationId: "inv-1",
        expectedHead: null,
        events: [{ kind: "bundle:seed", payload: { case: "audit" } }],
    });

    registerObject(snap.snapshot, "snapshot-manifest", SNAPSHOT_CONTENT_TYPE);
    for (const [index, entry] of snap.manifest.entries.entries()) {
        registerObject(entry.object, `snapshot-object-${index}`);
    }
    registerObject(extraObject.id, "standalone-object");
});

afterEach(() => {
    try {
        repo?.close();
    } catch {
        // already closed
    }
    fs.rmSync(base, { recursive: true, force: true });
});

function doExport(destName = "bundle", overrides = {}) {
    const destDir = path.join(base, destName);
    const res = exportBundle({
        store,
        dbFile: repo.databaseFile,
        destDir,
        investigationId: "inv-1",
        objectIds: [extraObject.id],
        snapshots: [snap.snapshot],
        now: () => "2026-07-09T00:00:00.000Z",
        ...overrides,
    });
    return { destDir, res };
}

function bundleDomainContract() {
    return createInvestigationContract(makeV4ContractInput({
        objective: "Archive a legacy Crucible investigation",
        acceptancePredicate: { kind: "harness_pass" },
        hypothesisTopology: "open_generative",
        criticality: "standard",
        policyVersion: "policy-v1",
        workerModels: ["model-a"],
        candidatesPerRound: 1,
        maxRounds: 1,
        searchPolicy: DEFAULT_SEARCH_POLICY,
    }));
}

describe("canonical export", () => {
    it("produces a strict deterministic bundle bound to schema, head, and referenced closure", () => {
        const first = doExport("bundle-a");
        const second = doExport("bundle-b");

        const manifest = readBundleManifest(first.destDir);
        expect(manifest.type).toBe("crucible-audit-bundle");
        expect(BUNDLE_VERSION).toBe(3);
        expect(manifest.version).toBe(BUNDLE_VERSION);
        expect(manifest.database.path).toBe("db/database.sqlite");
        expect(manifest.database.schemaFingerprint).toMatch(/^[0-9a-f]{64}$/);
        expect(manifest.investigation).toEqual({
            id: "inv-1",
            domainVersion: 4,
            domainHead: repo.getHead("inv-1"),
        });
        expect(manifest.snapshots).toEqual([snap.snapshot]);
        expect(manifest.artifacts.map((artifact) => artifact.artifactId)).toEqual([
            "snapshot-manifest",
            "snapshot-object-0",
            "snapshot-object-1",
            "standalone-object",
        ]);
        expect(first.res.objectCount).toBe(4);
        expect(first.res.domainVersion).toBe(4);
        expect(first.res.digest).toBe(second.res.digest);
        expect(fs.readFileSync(path.join(first.destDir, "manifest.json")))
            .toEqual(fs.readFileSync(path.join(second.destDir, "manifest.json")));
        expect(fs.readFileSync(path.join(first.destDir, "inventory.sha256")))
            .toEqual(fs.readFileSync(path.join(second.destDir, "inventory.sha256")));

        const inventory = fs.readFileSync(path.join(first.destDir, "inventory.sha256"), "utf8");
        expect(inventory).toMatch(/ {2}db\/database\.sqlite$/m);
        expect(inventory).not.toMatch(/inventory\.sha256/);
    });

    it("publishes only after completion and leaves no partial destination or stage", () => {
        const missing = store.putBytes(Buffer.from("missing-after-reference"));
        registerObject(missing.id, "will-be-missing");
        fs.rmSync(store.objectPath(missing.id));
        const destDir = path.join(base, "bundle-missing");

        const err = catchErr(() => exportBundle({
            store,
            dbFile: repo.databaseFile,
            destDir,
            investigationId: "inv-1",
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.OBJECT_MISSING);
        expect(fs.existsSync(destDir)).toBe(false);
        expect(stageEntries("export")).toEqual([]);
    });

    it.each([
        "before-stage-file-open",
        "after-source-copy",
        "before-database-backup",
        "before-publish",
    ])("cleans every private stage after an injected export failure at %s", (point) => {
        const destDir = path.join(base, `bundle-fault-${point}`);
        let injected = false;
        expect(() => exportBundle({
            store,
            dbFile: repo.databaseFile,
            destDir,
            investigationId: "inv-1",
            faultInjector(event) {
                if (!injected && event.point === point) {
                    injected = true;
                    throw new Error(`injected ${point}`);
                }
            },
        })).toThrow(`injected ${point}`);
        expect(injected).toBe(true);
        expect(fs.existsSync(destDir)).toBe(false);
        expect(stageEntries("export")).toEqual([]);
    });

    it("refuses a non-empty destination", () => {
        const destDir = path.join(base, "occupied");
        fs.mkdirSync(destDir);
        fs.writeFileSync(path.join(destDir, "squatter"), "x");
        const err = catchErr(() => exportBundle({
            store,
            dbFile: repo.databaseFile,
            destDir,
            investigationId: "inv-1",
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.DESTINATION_EXISTS);
    });

    it("rejects a non-string bundle clock before publication", () => {
        const destDir = path.join(base, "bad-bundle-clock");
        const err = catchErr(() => exportBundle({
            store,
            dbFile: repo.databaseFile,
            destDir,
            investigationId: "inv-1",
            now: () => 123,
        }));
        expect(err.code).toBe("CRUCIBLE_PERSIST_INVALID_ARGUMENT");
        expect(fs.existsSync(destDir)).toBe(false);
        expect(stageEntries("export")).toEqual([]);
    });
});

describe("bundle import and round trip", () => {
    it("archives v3 state read-only but rejects importing it into active v4", () => {
        const investigationId = "legacy-v3-bundle";
        const dbFile = path.join(base, "legacy-v3.sqlite");
        const legacyRepository = openRepository({ file: dbFile });
        const legacyStore = openArtifactStore({
            root: path.join(base, "legacy-v3-cas"),
        });
        try {
            appendLegacyV3Investigation(
                legacyRepository,
                investigationId,
                bundleDomainContract(),
            );
            const before = legacyRepository.listEvents(investigationId);
            const bundleDir = path.join(base, "legacy-v3-bundle");
            const archived = exportBundle({
                store: legacyStore,
                dbFile,
                destDir: bundleDir,
                investigationId,
                now: () => "2026-07-09T00:00:00.000Z",
            });

            expect(archived).toMatchObject({
                investigationId,
                domainVersion: 3,
                fileCount: 2,
            });
            expect(readBundleManifest(bundleDir)).toMatchObject({
                version: BUNDLE_VERSION,
                investigation: {
                    id: investigationId,
                    domainVersion: 3,
                },
            });
            expect(legacyRepository.listEvents(investigationId)).toEqual(before);

            const importedDir = path.join(base, "legacy-v3-import");
            const error = catchErr(() => importBundle({
                bundleDir,
                destDir: importedDir,
                allowUnauthenticated: true,
            }));
            expect(error).toMatchObject({
                code: BUNDLE_ERROR_CODES.DOMAIN_VERSION_MISMATCH,
                details: expect.objectContaining({
                    compatibility: "legacy_incompatible",
                    expectedDomainVersion: 4,
                    actualDomainVersion: 3,
                    restartRequired: true,
                }),
            });
            expect(fs.existsSync(importedDir)).toBe(false);
        } finally {
            legacyRepository.close();
        }
    });

    it("authenticates the expected digest and materializes an identical bundle", () => {
        const { destDir, res } = doExport();
        const dest = path.join(base, "imported");
        const imported = importBundle({
            bundleDir: destDir,
            destDir: dest,
            expectedDigest: res.digest,
        });

        expect(imported).toMatchObject({
            verified: true,
            selfConsistent: true,
            authenticated: true,
            trustLevel: "authenticated",
            digest: res.digest,
            investigationId: "inv-1",
            domainVersion: 4,
        });
        expect(listFiles(dest)).toEqual(listFiles(destDir));
        for (const rel of listFiles(destDir)) {
            expect(sha256File(path.join(dest, ...rel.split("/"))))
                .toBe(sha256File(path.join(destDir, ...rel.split("/"))));
        }

        const restored = openRepository({ file: path.join(dest, "db", "database.sqlite") });
        try {
            expect(restored.getHead("inv-1")).toEqual(repo.getHead("inv-1"));
        } finally {
            restored.close();
        }
        const restoredStore = openArtifactStore({ root: dest });
        expect(restoredStore.verifyObject(extraObject.id).ok).toBe(true);
        expect(restoredStore.verifySnapshot(snap.snapshot).ok).toBe(true);
    });

    it("rejects a missing or incorrect authentication claim", () => {
        const { destDir, res } = doExport();
        const noClaim = path.join(base, "no-claim");
        const required = catchErr(() => importBundle({ bundleDir: destDir, destDir: noClaim }));
        expect(required.code).toBe(BUNDLE_ERROR_CODES.AUTHENTICATION_REQUIRED);
        expect(fs.existsSync(noClaim)).toBe(false);

        const wrong = path.join(base, "wrong-digest");
        const failed = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: wrong,
            expectedDigest: `sha256:${res.digest.endsWith("0")
                ? res.digest.slice(7, -1) + "1"
                : res.digest.slice(7, -1) + "0"}`,
        }));
        expect(failed.code).toBe(BUNDLE_ERROR_CODES.AUTHENTICATION_FAILED);
        expect(fs.existsSync(wrong)).toBe(false);
    });

    it("returns self-consistent only after explicit unauthenticated opt-in", () => {
        const { destDir } = doExport();
        const dest = path.join(base, "self-consistent");
        const imported = importBundle({
            bundleDir: destDir,
            destDir: dest,
            allowUnauthenticated: true,
        });
        expect(imported.trustLevel).toBe("self-consistent");
        expect(imported).toMatchObject({
            selfConsistent: true,
            authenticated: false,
            verified: false,
        });
    });

    it("refuses a non-empty import destination before publication", () => {
        const { destDir } = doExport();
        const dest = path.join(base, "occupied-import");
        fs.mkdirSync(dest);
        fs.writeFileSync(path.join(dest, "existing"), "x");
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            allowUnauthenticated: true,
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.DESTINATION_EXISTS);
        expect(fs.readFileSync(path.join(dest, "existing"), "utf8")).toBe("x");
    });

    it("supports caller-owned signature verification", () => {
        const { destDir, res } = doExport();
        const dest = path.join(base, "signature-auth");
        const imported = importBundle({
            bundleDir: destDir,
            destDir: dest,
            expectedSignature: Buffer.from("signed"),
            verifySignature({ digest, signature }) {
                return digest === res.digest && signature.equals(Buffer.from("signed"));
            },
        });
        expect(imported).toMatchObject({
            trustLevel: "authenticated",
            selfConsistent: true,
            authenticated: true,
            verified: true,
        });
    });

    it("re-verifies staged bytes after caller-owned authentication", () => {
        const { destDir } = doExport();
        const dest = path.join(base, "signature-mutation");
        let stagingDir;
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            expectedSignature: Buffer.from("signed"),
            hooks: {
                beforePublish(event) {
                    stagingDir = event.stagingDir;
                },
            },
            verifySignature() {
                fs.appendFileSync(path.join(stagingDir, "manifest.json"), " ");
                return true;
            },
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.TAMPER_DETECTED);
        expect(fs.existsSync(dest)).toBe(false);
        expect(stageEntries("import")).toEqual([]);
    });

    it("authenticates the final staged digest after a before-publish mutation", () => {
        const { destDir, res } = doExport();
        const dest = path.join(base, "digest-mutation");
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            expectedDigest: res.digest,
            hooks: {
                beforePublish(event) {
                    rewriteManifest(event.stagingDir, (manifest) => {
                        manifest.metadata = { mutatedAfterInitialCopy: true };
                    });
                },
            },
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.AUTHENTICATION_FAILED);
        expect(fs.existsSync(dest)).toBe(false);
        expect(stageEntries("import")).toEqual([]);
    });
});

describe("canonical closure validation", () => {
    it("rejects an arbitrary self-checksummed directory payload", () => {
        const { destDir } = doExport();
        fs.writeFileSync(path.join(destDir, "payload.bin"), "arbitrary");
        regenerateInventory(destDir);

        const dest = path.join(base, "arbitrary-import");
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            allowUnauthenticated: true,
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.CLOSURE_INVALID);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects a valid-schema database substitution even with regenerated inventory", () => {
        const { destDir } = doExport();
        const alternatePath = path.join(base, "alternate.sqlite");
        const alternate = openRepository({ file: alternatePath });
        alternate.ensureInvestigation({ investigationId: "inv-other" });
        alternate.close();
        fs.copyFileSync(alternatePath, path.join(destDir, "db", "database.sqlite"));
        regenerateInventory(destDir);

        const dest = path.join(base, "db-substitution");
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            allowUnauthenticated: true,
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.TAMPER_DETECTED);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects an object closure mismatch with canonical manifest and inventory", () => {
        const { destDir } = doExport();
        const removedId = snap.manifest.entries[0].object;
        rewriteManifest(destDir, (manifest) => {
            const record = manifest.objects.find((object) => object.id === removedId);
            fs.rmSync(path.join(destDir, ...record.path.split("/")));
            manifest.objects = manifest.objects.filter((object) => object.id !== removedId);
        });

        const dest = path.join(base, "closure-mismatch");
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            allowUnauthenticated: true,
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.CLOSURE_INVALID);
        expect(fs.existsSync(dest)).toBe(false);
    });

    it("rejects a non-canonical manifest version after all checksums are regenerated", () => {
        const { destDir } = doExport();
        rewriteManifest(destDir, (manifest) => {
            manifest.version = 999;
        });
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: path.join(base, "bad-version"),
            allowUnauthenticated: true,
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.MANIFEST_INVALID);
    });
});

describe("source mutation and filesystem races", () => {
    it("fails closed when an opened source file is mutated during copy", () => {
        const { destDir } = doExport();
        const dest = path.join(base, "mutated-copy");
        let injected = false;
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            allowUnauthenticated: true,
            hooks: {
                afterSourceOpen(event) {
                    if (!injected && event.relativePath === "manifest.json") {
                        injected = true;
                        fs.appendFileSync(event.path, " ");
                    }
                },
            },
        }));
        expect(injected).toBe(true);
        expect(err.code).toBe(BUNDLE_ERROR_CODES.SOURCE_CHANGED);
        expect(fs.existsSync(dest)).toBe(false);
        expect(stageEntries("import")).toEqual([]);
    });

    it("detects files added while the source is being copied", () => {
        const { destDir } = doExport();
        let injected = false;
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: path.join(base, "added-during-copy"),
            allowUnauthenticated: true,
            hooks: {
                afterSourceCopy(event) {
                    if (!injected && event.relativePath === "manifest.json") {
                        injected = true;
                        fs.writeFileSync(path.join(destDir, "added.txt"), "late");
                    }
                },
            },
        }));
        expect(injected).toBe(true);
        expect(err.code).toBe(BUNDLE_ERROR_CODES.SOURCE_CHANGED);
    });

    it("detects files removed after their opened bytes were copied", () => {
        const { destDir } = doExport();
        const victim = readBundleManifest(destDir).objects[0].path;
        let injected = false;
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: path.join(base, "removed-during-copy"),
            allowUnauthenticated: true,
            hooks: {
                afterSourceCopy(event) {
                    if (!injected && event.relativePath === victim) {
                        injected = true;
                        fs.rmSync(event.path);
                    }
                },
            },
        }));
        expect(injected).toBe(true);
        expect(err.code).toBe(BUNDLE_ERROR_CODES.SOURCE_CHANGED);
    });

    it("rejects a junction swap before staging writes and never writes outside", () => {
        const { destDir } = doExport();
        const outside = path.join(base, "outside");
        fs.mkdirSync(outside);
        let injected = false;
        const dest = path.join(base, "junction-import");
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            allowUnauthenticated: true,
            hooks: {
                beforeStageFileOpen(event) {
                    if (!injected && event.relativePath === "db/database.sqlite") {
                        injected = true;
                        const dbDir = path.dirname(event.path);
                        fs.rmdirSync(dbDir);
                        fs.symlinkSync(outside, dbDir, "junction");
                    }
                },
            },
        }));
        expect(injected).toBe(true);
        expect(err.code).toBe(BUNDLE_ERROR_CODES.UNSAFE_PATH);
        expect(fs.existsSync(path.join(outside, "database.sqlite"))).toBe(false);
        expect(fs.existsSync(dest)).toBe(false);
        expect(stageEntries("import")).toEqual([]);
    });

    it("rejects a database-backup junction swap before VACUUM can write outside", () => {
        const outside = path.join(base, "backup-outside");
        fs.mkdirSync(outside);
        const dest = path.join(base, "junction-export");
        let injected = false;
        const err = catchErr(() => exportBundle({
            store,
            dbFile: repo.databaseFile,
            destDir: dest,
            investigationId: "inv-1",
            hooks: {
                beforeDatabaseBackup(event) {
                    injected = true;
                    const dbDir = path.dirname(event.stagedPath);
                    fs.rmdirSync(dbDir);
                    fs.symlinkSync(outside, dbDir, "junction");
                },
            },
        }));
        expect(injected).toBe(true);
        expect(err.code).toBe(BUNDLE_ERROR_CODES.UNSAFE_PATH);
        expect(fs.existsSync(path.join(outside, "database.sqlite"))).toBe(false);
        expect(fs.existsSync(dest)).toBe(false);
        expect(stageEntries("export")).toEqual([]);
    });

    it("fails closed when a publication ancestor directory cannot be fsynced", () => {
        const dest = path.join(base, "unsupported-dirsync");
        let injected = false;
        const err = catchErr(() => exportBundle({
            store,
            dbFile: repo.databaseFile,
            destDir: dest,
            investigationId: "inv-1",
            faultInjector(event) {
                if (!injected
                    && event.point === "before-directory-fsync"
                    && event.purpose === "bundle publication parent") {
                    injected = true;
                    throw Object.assign(new Error("directory fsync unsupported"), {
                        code: "EPERM",
                        syscall: "fsync",
                    });
                }
            },
        }));
        expect(injected).toBe(true);
        expect(err.code).toBe(BUNDLE_ERROR_CODES.IO_ERROR);
        expect(fs.existsSync(dest)).toBe(false);
        expect(stageEntries("export")).toEqual([]);
    });

    it("cleans partial staging after an injected copy failure", () => {
        const { destDir } = doExport();
        const dest = path.join(base, "partial");
        const err = catchErr(() => importBundle({
            bundleDir: destDir,
            destDir: dest,
            allowUnauthenticated: true,
            faultInjector(event) {
                if (event.point === "after-source-copy"
                    && event.relativePath === "manifest.json") {
                    throw new Error("injected copy failure");
                }
            },
        }));
        expect(err.code).toBe(BUNDLE_ERROR_CODES.IO_ERROR);
        expect(fs.existsSync(dest)).toBe(false);
        expect(stageEntries("import")).toEqual([]);
    });
});

describe("basic tamper detection", () => {
    it("rejects altered object, database, manifest, missing file, and malformed inventory", () => {
        const cases = [
            {
                name: "object",
                mutate(bundleDir) {
                    const record = readBundleManifest(bundleDir).objects[0];
                    fs.writeFileSync(path.join(bundleDir, ...record.path.split("/")), "tampered");
                },
                code: BUNDLE_ERROR_CODES.TAMPER_DETECTED,
            },
            {
                name: "database",
                mutate(bundleDir) {
                    const dbPath = path.join(bundleDir, "db", "database.sqlite");
                    const bytes = fs.readFileSync(dbPath);
                    bytes[bytes.length - 1] ^= 0xff;
                    fs.writeFileSync(dbPath, bytes);
                },
                code: BUNDLE_ERROR_CODES.TAMPER_DETECTED,
            },
            {
                name: "manifest",
                mutate(bundleDir) {
                    fs.appendFileSync(path.join(bundleDir, "manifest.json"), "\n");
                },
                code: BUNDLE_ERROR_CODES.TAMPER_DETECTED,
            },
            {
                name: "missing",
                mutate(bundleDir) {
                    const record = readBundleManifest(bundleDir).objects[0];
                    fs.rmSync(path.join(bundleDir, ...record.path.split("/")));
                },
                code: BUNDLE_ERROR_CODES.TAMPER_DETECTED,
            },
            {
                name: "inventory",
                mutate(bundleDir) {
                    fs.writeFileSync(path.join(bundleDir, "inventory.sha256"), "not valid\n");
                },
                code: BUNDLE_ERROR_CODES.INVENTORY_INVALID,
            },
            {
                name: "missing-inventory",
                mutate(bundleDir) {
                    fs.rmSync(path.join(bundleDir, "inventory.sha256"));
                },
                code: BUNDLE_ERROR_CODES.INVENTORY_INVALID,
            },
        ];

        for (const testCase of cases) {
            const { destDir } = doExport(`tamper-${testCase.name}`);
            testCase.mutate(destDir);
            const imported = path.join(base, `import-${testCase.name}`);
            const err = catchErr(() => importBundle({
                bundleDir: destDir,
                destDir: imported,
                allowUnauthenticated: true,
            }));
            expect(err.code, testCase.name).toBe(testCase.code);
            expect(fs.existsSync(imported), testCase.name).toBe(false);
        }
    });
});
