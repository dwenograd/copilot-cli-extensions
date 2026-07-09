// oracle-v3/__tests__/measurement-executor.test.mjs
//
// Happy-path / structural tests for the MeasurementExecutor:
// spawn a real trusted fixture (Node running a scripted harness), verify the
// receipt is well-formed and deterministic modulo timing.

import { describe, it, expect, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";

import {
    PARSER_VERSION,
    RECEIPT_DETERMINISM_KEYS,
    MEASUREMENT_ERROR_CODES,
    createDefaultProcessAdapter,
    createMeasurementExecutor,
    hashReceipt,
    loadHarnessAllowlist,
    projectDeterministicReceipt,
} from "../measurement/index.mjs";

import {
    NODE_EXE,
    fixedClock,
    fixedIds,
    makeTempRoot,
    materializeCandidateSnapshot,
    rmTempRoot,
    sha256HexOfFile,
    writeAllowlist,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";

const roots = [];
function tmp(l) { const r = makeTempRoot(`exec-${l}`); roots.push(r); return r; }
afterAll(() => roots.forEach(rmTempRoot));

async function runOnce({ root, entryId, script, snapshotBytes = "candidate-bytes", sandboxProvider = null, entryOverrides = {}, clock = null }) {
    const scriptPath = writeHarnessScript(root, entryId, script);
    const allowlistPath = writeAllowlist(root, entryId, {
        argvTemplate: [scriptPath, "{{candidatePath}}"],
        ...entryOverrides,
    });
    const list = loadHarnessAllowlist(allowlistPath);
    const verified = list.verifyEntry(entryId);
    const snapshot = materializeCandidateSnapshot(root, `${entryId}-snap`, snapshotBytes);
    const executor = createMeasurementExecutor({
        allowlist: list,
        sandboxProvider,
        clock: clock ?? fixedClock(),
        scratchRoot: root,
    });
    const ids = fixedIds();
    const result = await executor.run({
        verifiedEntry: verified,
        candidateSnapshot: snapshot,
        attemptId: ids.attemptId,
        runnerEpochId: ids.runnerEpochId,
    });
    return { result, verified, snapshot, list, allowlistPath, scriptPath };
}

describe("MeasurementExecutor happy path", () => {
    it("runs a trusted fixture that writes {pass:true} and produces a well-formed receipt", async () => {
        const root = tmp("hp");
        const { result, verified, snapshot } = await runOnce({
            root, entryId: "hp",
            script: `process.stdout.write(JSON.stringify({ pass: true, metrics: { seed: 1 } }));`,
        });
        expect(result.parsed.pass).toBe(true);
        expect(result.parsed.metrics).toEqual({ seed: 1 });
        expect(result.parsed.parserVersion).toBe(PARSER_VERSION);
        expect(result.exit.code).toBe(0);
        expect(result.stdoutBytes).toBeGreaterThan(0);

        const rec = result.receipt;
        expect(rec.version).toBe(2);
        expect(rec.harnessEntryHash).toBe(verified.entryHash);
        expect(rec.executableHash).toBe(verified.executableHash);
        expect(rec.stagedExecutableHash).toBe(verified.executableHash);
        expect(rec.candidateSnapshotHash).toBe(snapshot.hash);
        expect(rec.attemptId).toBe("att-0001");
        expect(rec.runnerEpochId).toBe("epoch-2026-07-09-a");
        expect(rec.parserVersion).toBe(PARSER_VERSION);
        expect(rec.sandbox).toBeNull();
        expect(rec.exit).toEqual({ code: 0, signal: null, timedOut: false });
        expect(rec.parsed).toEqual(result.parsed);
        expect(rec.argvHash).toMatch(/^sha256:oracle-measurement-argv-v1:[a-f0-9]{64}$/);
        expect(rec.envHash).toMatch(/^sha256:oracle-measurement-env-v1:[a-f0-9]{64}$/);
        expect(rec.stdoutHash).toMatch(/^sha256:oracle-measurement-stream-v1:[a-f0-9]{64}$/);
        expect(rec.stderrHash).toMatch(/^sha256:oracle-measurement-stream-v1:[a-f0-9]{64}$/);
    });

    it("passes the candidate snapshot path via env AND via the argv placeholder", async () => {
        const root = tmp("cand");
        const { result } = await runOnce({
            root, entryId: "readsnap",
            script: `
                const argPath = process.argv[2];
                const envPath = process.env.CANDIDATE_SNAPSHOT_PATH;
                const attempt = process.env.ORACLE_ATTEMPT_ID;
                const epoch = process.env.ORACLE_RUNNER_EPOCH_ID;
                const bytes = fs.readFileSync(argPath, "utf8");
                const same = argPath === envPath;
                process.stdout.write(JSON.stringify({
                    pass: same && bytes === "candidate-bytes" && attempt === "att-0001" && epoch === "epoch-2026-07-09-a",
                    metrics: { bytesLen: bytes.length }
                }));
            `,
        });
        expect(result.parsed.pass).toBe(true);
        expect(result.parsed.metrics).toEqual({ bytesLen: "candidate-bytes".length });
    });

    it("produces byte-identical deterministic receipts across two runs with the same inputs", async () => {
        const root = tmp("det");
        const scriptPath = writeHarnessScript(root, "det", `process.stdout.write(JSON.stringify({pass:true}));`);
        const allowlistPath = writeAllowlist(root, "det", {
            argvTemplate: [scriptPath, "{{candidatePath}}"],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("det");
        const snapshot = materializeCandidateSnapshot(root, "det-snap", "stable-bytes");
        const ids = fixedIds();

        async function run() {
            const executor = createMeasurementExecutor({
                allowlist: list,
                clock: fixedClock(),
                scratchRoot: root,
            });
            return executor.run({
                verifiedEntry: verified,
                candidateSnapshot: snapshot,
                attemptId: ids.attemptId,
                runnerEpochId: ids.runnerEpochId,
            });
        }

        const r1 = await run();
        const r2 = await run();

        const p1 = projectDeterministicReceipt(r1.receipt);
        const p2 = projectDeterministicReceipt(r2.receipt);
        expect(p1).toEqual(p2);
        // And a stable receipt hash over the deterministic projection.
        expect(hashReceipt(p1)).toBe(hashReceipt(p2));

        // Every documented determinism key is actually present.
        for (const key of RECEIPT_DETERMINISM_KEYS) {
            expect(p1).toHaveProperty(key);
        }
    });

    it("only exposes allowedEnv + fixed platform keys to the child process", async () => {
        const root = tmp("env");
        const secret = "SHOULD_NOT_APPEAR_IN_CHILD_ENV";
        process.env.ORACLE_MEASURE_SECRET_TEST_ONLY = secret;
        try {
            const { result } = await runOnce({
                root, entryId: "envcheck",
                script: `
                    const leaked = Object.hasOwn(process.env, "ORACLE_MEASURE_SECRET_TEST_ONLY");
                    process.stdout.write(JSON.stringify({ pass: !leaked, metrics: { leaked: leaked ? 1 : 0 } }));
                `,
                entryOverrides: { allowedEnv: { EXPECTED_VAR: "yes" } },
            });
            expect(result.parsed.pass).toBe(true);
            expect(result.parsed.metrics).toEqual({ leaked: 0 });
        } finally {
            delete process.env.ORACLE_MEASURE_SECRET_TEST_ONLY;
        }
    });

    it("spawns only staged executable/dependency paths and removes staging afterward", async () => {
        const root = tmp("staged");
        const scriptPath = writeHarnessScript(
            root,
            "staged",
            `process.stdout.write(JSON.stringify({ pass: true }));`,
        );
        const allowlistPath = writeAllowlist(root, "staged", {
            argvTemplate: [scriptPath],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("staged");
        const snapshot = materializeCandidateSnapshot(root, "staged-snap", "x");
        const real = createDefaultProcessAdapter();
        let spawnCall = null;
        const executor = createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
            processAdapter: {
                spawn(executable, argv, options) {
                    spawnCall = { executable, argv: [...argv], cwd: options.cwd };
                    return real.spawn(executable, argv, options);
                },
                terminateTree: (pid) => real.terminateTree(pid),
            },
        });

        const result = await executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
        });
        expect(result.parsed.pass).toBe(true);
        expect(spawnCall.executable).not.toBe(NODE_EXE);
        expect(spawnCall.argv[0]).not.toBe(scriptPath);
        expect(spawnCall.executable).toContain(`${path.sep}.oracle-stage-att-0001${path.sep}`);
        expect(spawnCall.argv[0]).toContain(`${path.sep}.oracle-stage-att-0001${path.sep}`);
        expect(fs.existsSync(path.dirname(path.dirname(spawnCall.executable)))).toBe(false);
        expect(result.receipt.stagedExecutableHash).toBe(result.receipt.executableHash);
        expect(result.receipt.stagedDependencyHashes[0].sha256)
            .toBe(result.receipt.dependencyHashes[0].sha256);
    });

    it("reverifies executable and script bytes at run time after verifyEntry issuance", async () => {
        const root = tmp("swap");
        const fakeExecutable = path.join(root, "fake.exe");
        fs.writeFileSync(fakeExecutable, "original executable");
        const allowlistPath = writeAllowlist(root, "swap", {
            executable: fakeExecutable,
            executableSha256: sha256HexOfFile(fakeExecutable),
            argvTemplate: [],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("swap");
        fs.writeFileSync(fakeExecutable, "swapped executable");
        const snapshot = materializeCandidateSnapshot(root, "swap-snap", "x");
        let spawned = false;
        const executor = createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
            processAdapter: {
                spawn() {
                    spawned = true;
                    throw new Error("must not spawn");
                },
                terminateTree() {},
            },
        });
        await expect(executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
        })).rejects.toMatchObject({ code: MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH });
        expect(spawned).toBe(false);

        const script = writeHarnessScript(root, "dep-swap", `process.stdout.write('{"pass":true}');`);
        const depAllowlist = writeAllowlist(root, "dep-swap", { argvTemplate: [script] });
        const depList = loadHarnessAllowlist(depAllowlist);
        const depVerified = depList.verifyEntry("dep-swap");
        fs.writeFileSync(script, "process.stdout.write('swapped');\n");
        const depExecutor = createMeasurementExecutor({
            allowlist: depList,
            scratchRoot: root,
            processAdapter: {
                spawn() {
                    spawned = true;
                    throw new Error("must not spawn");
                },
                terminateTree() {},
            },
        });
        await expect(depExecutor.run({
            verifiedEntry: depVerified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
        })).rejects.toMatchObject({ code: MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH });
        expect(spawned).toBe(false);
    });

    it("rejects a genuine entry issued by a different loaded allowlist instance", async () => {
        const root = tmp("wrong-owner");
        const script = writeHarnessScript(root, "owned", `process.stdout.write('{"pass":true}');`);
        const firstPath = writeAllowlist(root, "owned", {
            argvTemplate: [script],
        }, { fileName: "first.json" });
        const secondPath = writeAllowlist(root, "owned", {
            argvTemplate: [script],
        }, { fileName: "second.json" });
        const first = loadHarnessAllowlist(firstPath);
        const second = loadHarnessAllowlist(secondPath);
        const verified = first.verifyEntry("owned");
        const snapshot = materializeCandidateSnapshot(root, "owned-snap", "x");
        const executor = createMeasurementExecutor({
            allowlist: second,
            scratchRoot: root,
            processAdapter: {
                spawn() { throw new Error("must not spawn"); },
                terminateTree() {},
            },
        });
        await expect(executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
        })).rejects.toMatchObject({ code: MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT });
    });
});
