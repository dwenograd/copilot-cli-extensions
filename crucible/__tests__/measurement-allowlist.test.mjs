// crucible/__tests__/measurement-allowlist.test.mjs
//
// Verifies the HarnessAllowlist loader + verify-before-run flow.

import { describe, it, expect, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";

import {
    ENTRY_HASH_ALGORITHM,
    MEASUREMENT_ERROR_CODES,
    PARSER_VERSION,
    buildFrozenHarnessIdentity,
    isVerifiedHarnessEntry,
    loadHarnessAllowlist,
    verifyFrozenHarnessIdentity,
    verifyHarnessPreflight,
} from "../measurement/index.mjs";

import {
    NODE_EXE,
    canCreateFileSymlink,
    makeTempRoot,
    nodeExeSha256Hex,
    rmTempRoot,
    writeAllowlist,
} from "./measurement-fixtures.mjs";

const roots = [];
function tmp(label) { const r = makeTempRoot(`allow-${label}`); roots.push(r); return r; }
afterAll(() => roots.forEach(rmTempRoot));

function catchIt(fn) {
    try { fn(); } catch (e) { return e; }
    throw new Error("expected to throw");
}

describe("loadHarnessAllowlist", () => {
    it("loads a minimal valid allowlist and exposes entry hashes", () => {
        const root = tmp("min");
        const p = writeAllowlist(root, "echo-passer");
        const list = loadHarnessAllowlist(p);
        expect(list.listEntryIds()).toEqual(["echo-passer"]);
        const entry = list.getEntry("echo-passer");
        expect(entry.executable).toBe(NODE_EXE);
        expect(entry.executesCandidateCode).toBe(false);
        expect(list.getEntryHash("echo-passer")).toMatch(new RegExp(`^${ENTRY_HASH_ALGORITHM}:[a-f0-9]{64}$`));
        expect(list.contentHash).toMatch(/^sha256:crucible-measurement-allowlist-v1:[a-f0-9]{64}$/);
    });

    it("rejects unknown top-level keys and wrong version", () => {
        const root = tmp("badTop");
        const raw = { version: 1, entries: {} };
        raw.entries["x"] = {
            executable: NODE_EXE, executableSha256: nodeExeSha256Hex(),
            argvTemplate: [], timeoutMs: 1000, maxStdoutBytes: 1024, maxStderrBytes: 1024,
            executesCandidateCode: false,
        };
        raw.unknown = 1;
        const p = path.join(root, "a.json");
        fs.writeFileSync(p, JSON.stringify(raw));
        const err = catchIt(() => loadHarnessAllowlist(p));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);

        // Wrong version
        raw.unknown = undefined;
        delete raw.unknown;
        raw.version = 2;
        fs.writeFileSync(p, JSON.stringify(raw));
        const err2 = catchIt(() => loadHarnessAllowlist(p));
        expect(err2.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
    });

    it("rejects unknown entry keys", () => {
        const root = tmp("unkKey");
        const p = writeAllowlist(root, "e1", { NOT_A_KEY: 1 });
        const err = catchIt(() => loadHarnessAllowlist(p));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
    });

    it("rejects an unsafe entry id", () => {
        const root = tmp("badId");
        const p = writeAllowlist(root, "GOOD");   // uppercase → not SAFE_ID
        const err = catchIt(() => loadHarnessAllowlist(p));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
    });

    it("rejects dot-dot sequences in entry and validation-case ids", () => {
        const root = tmp("dotDotId");
        const badEntry = writeAllowlist(root, "bad..entry");
        expect(catchIt(() => loadHarnessAllowlist(badEntry)).code)
            .toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);

        const badCase = writeAllowlist(root, "safe-entry", {
            validationCases: {
                "bad..case": { snapshotHash: `sha256:${"a".repeat(64)}` },
            },
        }, { fileName: "bad-case.json" });
        expect(catchIt(() => loadHarnessAllowlist(badCase)).code)
            .toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
    });

    it("rejects a non-absolute executable path", () => {
        const root = tmp("relExe");
        const p = writeAllowlist(root, "e1", { executable: "node.exe" });
        const err = catchIt(() => loadHarnessAllowlist(p));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
    });

    it("rejects argv template with unknown placeholders", () => {
        const root = tmp("badPh");
        const p = writeAllowlist(root, "e1", { argvTemplate: ["--x", "{{secretPath}}"] });
        const err = catchIt(() => loadHarnessAllowlist(p));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
    });

    it("rejects a static script argv path unless it is a hash-pinned dependency", () => {
        const root = tmp("undeclaredScript");
        const script = path.join(root, "runner.mjs");
        fs.writeFileSync(script, "process.exit(0);\n");
        const p = writeAllowlist(root, "e1", {
            argvTemplate: [script],
            dependencies: [],
        });
        const err = catchIt(() => loadHarnessAllowlist(p));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
        expect(err.details.code).toBe(MEASUREMENT_ERROR_CODES.UNDECLARED_ARGV_FILE);
    });

    it("rejects candidatePath as a known interpreter's script entrypoint", () => {
        const root = tmp("candidateScript");
        const p = writeAllowlist(root, "e1", {
            argvTemplate: ["{{candidatePath}}"],
            dependencies: [],
        });
        const err = catchIt(() => loadHarnessAllowlist(p));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
    });

    it("rejects invalid env keys", () => {
        const root = tmp("badEnv");
        const p = writeAllowlist(root, "e1", { allowedEnv: { "bad-key": "v" } });
        const err = catchIt(() => loadHarnessAllowlist(p));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
    });

    it("rejects a missing allowlist with FILE_NOT_FOUND", () => {
        const root = tmp("missing");
        const err = catchIt(() =>
            loadHarnessAllowlist(path.join(root, "does-not-exist.json")));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_NOT_FOUND);
    });

    it("rejects an allowlist symlink with FILE_SYMLINK", () => {
        if (!canCreateFileSymlink()) return;
        const root = tmp("symlink");
        const target = writeAllowlist(root, "e1", {}, {
            fileName: "target.json",
        });
        const link = path.join(root, "allowlist-link.json");
        fs.symlinkSync(target, link, "file");

        const err = catchIt(() => loadHarnessAllowlist(link));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_SYMLINK);
    });

    it("produces byte-equal entry hashes for byte-equal entries and different hashes when a field changes", () => {
        const root1 = tmp("hashA");
        const root2 = tmp("hashB");
        const pA = writeAllowlist(root1, "e1", { timeoutMs: 5000 });
        const pB = writeAllowlist(root2, "e1", { timeoutMs: 5000 });
        const a = loadHarnessAllowlist(pA);
        const b = loadHarnessAllowlist(pB);
        expect(a.getEntryHash("e1")).toBe(b.getEntryHash("e1"));

        const root3 = tmp("hashC");
        const pC = writeAllowlist(root3, "e1", { timeoutMs: 5001 }); // different by 1ms
        const c = loadHarnessAllowlist(pC);
        expect(c.getEntryHash("e1")).not.toBe(a.getEntryHash("e1"));
    });
});

describe("verifyEntry (re-verify before every run)", () => {
    it("returns a branded VerifiedHarnessEntry", () => {
        const root = tmp("verify");
        const p = writeAllowlist(root, "e1");
        const list = loadHarnessAllowlist(p);
        const v = list.verifyEntry("e1");
        expect(isVerifiedHarnessEntry(v)).toBe(true);
        expect(v.executablePath.toLowerCase()).toBe(NODE_EXE.toLowerCase());
        expect(v.entryHash).toBe(list.getEntryHash("e1"));
    });

    it("rejects a hand-forged 'verified' entry", () => {
        const forged = Object.freeze({ entry: {}, entryHash: "x", executablePath: NODE_EXE, executableHash: "y", dependencies: [] });
        expect(isVerifiedHarnessEntry(forged)).toBe(false);
    });

    it("cannot be forged with the legacy global Symbol brand and the public index exports no brand", async () => {
        const forged = Object.freeze({
            entry: {},
            __brand: Symbol.for("crucible.measurement.VerifiedHarnessEntry"),
        });
        expect(isVerifiedHarnessEntry(forged)).toBe(false);
        const publicApi = await import("../measurement/index.mjs");
        expect(publicApi).not.toHaveProperty("VERIFIED_ENTRY_BRAND");
    });

    it("throws when the executable was modified between load and verify", () => {
        const root = tmp("exeChange");
        const fakeExe = path.join(root, "fake-node.exe");
        fs.writeFileSync(fakeExe, "originalABC");
        // Compute its hash and register it in the allowlist.
        const p = writeAllowlist(root, "e1", {
            executable: fakeExe,
            executableSha256: sha256HexOfLocal(fakeExe),
        });
        const list = loadHarnessAllowlist(p);
        // Mutate the executable file after load.
        fs.writeFileSync(fakeExe, "TAMPERED");
        const err = catchIt(() => list.verifyEntry("e1"));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH);
    });

    it("throws when the allowlist file itself was modified between load and verify", () => {
        const root = tmp("allowlistChange");
        const p = writeAllowlist(root, "e1");
        const list = loadHarnessAllowlist(p);
        // Append a whitespace character to change the file's on-disk bytes
        // without invalidating the JSON.
        fs.appendFileSync(p, "\n");
        const err = catchIt(() => list.verifyEntry("e1"));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH);
    });

    it("throws ALLOWLIST_ENTRY_NOT_FOUND for a bogus id", () => {
        const root = tmp("noid");
        const p = writeAllowlist(root, "real");
        const list = loadHarnessAllowlist(p);
        const err = catchIt(() => list.verifyEntry("does-not-exist"));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_ENTRY_NOT_FOUND);
    });

    it("returns a read-only preflight identity only when requested snapshots match", () => {
        const root = tmp("preflight");
        const good = `sha256:${"a".repeat(64)}`;
        const bad = `sha256:${"b".repeat(64)}`;
        const p = writeAllowlist(root, "e1", {
            allowedEnv: { CRUCIBLE_MODE: "strict" },
            validationCases: {
                good: { snapshotHash: good, expectation: "accept" },
                bad: { snapshotHash: bad, expectation: "reject" },
            },
        });
        const list = loadHarnessAllowlist(p);
        const verified = verifyHarnessPreflight(list, "e1", {
            parserVersion: PARSER_VERSION,
            validationCases: [
                { id: "good", expectation: "accept", artifactHash: good },
                { id: "bad", expectation: "reject", artifactHash: bad },
            ],
        });
        expect(verified.executableHash)
            .toMatch(/^sha256:crucible-measurement-file-v1:[a-f0-9]{64}$/u);
        expect(verified.argvTemplateHash)
            .toMatch(/^sha256:crucible-measurement-argv-template-v1:[a-f0-9]{64}$/u);
        expect(verified.allowedEnvHash)
            .toMatch(/^sha256:crucible-measurement-env-policy-v1:[a-f0-9]{64}$/u);
        expect(verified.parserSourceHash)
            .toMatch(/^sha256:crucible-measurement-parser-source-v1:[a-f0-9]{64}$/u);

        const mismatch = catchIt(() => verifyHarnessPreflight(list, "e1", {
            parserVersion: PARSER_VERSION,
            validationCases: [
                {
                    id: "good",
                    expectation: "accept",
                    artifactHash: `sha256:${"c".repeat(64)}`,
                },
            ],
        }));
        expect(mismatch.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);

        const relabel = catchIt(() => verifyHarnessPreflight(list, "e1", {
            parserVersion: PARSER_VERSION,
            validationCases: [{
                id: "good",
                expectation: "reject",
                artifactHash: good,
            }],
        }));
        expect(relabel.code).toBe(MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID);
        expect(relabel.message).toMatch(/cannot relabel/u);
    });

    it("freezes provider identity, policy fields, and Job limits", () => {
        const root = tmp("sandboxIdentity");
        const validationHash = `sha256:${"c".repeat(64)}`;
        const p = writeAllowlist(root, "e1", {
            executesCandidateCode: true,
            validationCases: {
                pinned: { snapshotHash: validationHash },
            },
        });
        const list = loadHarnessAllowlist(p);
        const verification = verifyHarnessPreflight(list, "e1", {
            parserVersion: PARSER_VERSION,
            validationCases: [{
                id: "pinned",
                expectation: "accept",
                artifactHash: validationHash,
            }],
        });
        const sandbox = {
            required: true,
            primitive: "fixture-appcontainer",
            providerId: "fixture-provider",
            providerVersion: "v2",
            policyId: "fixture-policy-v2",
            helperSourceHash:
                `sha256:fixture-helper-source:${"a".repeat(64)}`,
            helperBinaryHash:
                `sha256:fixture-helper-binary:${"b".repeat(64)}`,
            launcherId: "fixture-launcher-v1",
            launcherBinaryHash:
                `sha256:fixture-launcher-binary:${"d".repeat(64)}`,
            launcherScriptHash:
                `sha256:fixture-launcher-script:${"e".repeat(64)}`,
            securityContext: {
                appContainer: true,
                lowIntegrity: true,
                capabilities: [],
                loopbackExemptionRejected: true,
            },
            network: {
                mode: "deny-by-default",
                enforcement: "zero capabilities",
            },
            filesystem: {
                stagedHarness: "exact-manifest-read-execute",
                immutableCandidate: "private-staged-copy-read-only",
                outputTemp: "provider-owned",
                aclJournalRestored: true,
                exactLaunchClosure: true,
                hostWriteDenied: true,
            },
            job: {
                killOnJobClose: true,
                descendantsContained: true,
                uiRestrictions: true,
                activeProcessLimit: 4,
                processMemoryBytes: 128 * 1024 * 1024,
                jobMemoryBytes: 256 * 1024 * 1024,
                cpuRatePercent: 25,
                cpuTimeMs: 10_000,
                wallTimeMs: 20_000,
                terminationGraceMs: 2_000,
            },
        };
        const identity = buildFrozenHarnessIdentity(verification, { sandbox });
        expect(identity.sandbox.policyIdentity).toMatchObject({
            providerId: "fixture-provider",
            providerVersion: "v2",
            filesystem: {
                exactLaunchClosure: true,
                hostWriteDenied: true,
            },
            job: {
                activeProcessLimit: 4,
                processMemoryBytes: 128 * 1024 * 1024,
                jobMemoryBytes: 256 * 1024 * 1024,
            },
        });
        expect(() => verifyFrozenHarnessIdentity(list, identity, {
            validationCases: [{
                id: "pinned",
                expectation: "accept",
                artifactHash: validationHash,
            }],
            sandbox: {
                ...sandbox,
                job: {
                    ...sandbox.job,
                    activeProcessLimit: 5,
                },
            },
        })).toThrow(expect.objectContaining({
            code: MEASUREMENT_ERROR_CODES.ALLOWLIST_INVALID,
        }));
    });
});

// Local mini-hash helper (avoids depending on the module under test to hash
// its own inputs).
import { createHash } from "node:crypto";
function sha256HexOfLocal(p) {
    return createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}
