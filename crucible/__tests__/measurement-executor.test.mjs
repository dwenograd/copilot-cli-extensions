// crucible/__tests__/measurement-executor.test.mjs
//
// Happy-path / structural tests for the MeasurementExecutor:
// spawn a real trusted fixture (Node running a scripted harness), verify the
// receipt is well-formed and deterministic modulo timing.

import { describe, it, expect, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";

import {
    PARSER_VERSION,
    RECEIPT_DETERMINISM_KEYS,
    MEASUREMENT_ERROR_CODES,
    createDefaultProcessAdapter,
    createMeasurementExecutor,
    createSandboxProvider,
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

function createMutationProcessAdapter(mutate) {
    return {
        spawn() {
            const child = new EventEmitter();
            child.pid = 4242;
            child.stdout = new PassThrough();
            child.stderr = new PassThrough();
            setImmediate(() => {
                try {
                    mutate();
                    child.stdout.end(Buffer.from('{"pass":true}', "utf8"));
                    child.stderr.end();
                    child.emit("close", 0, null);
                } catch (error) {
                    child.stdout.end();
                    child.stderr.end(Buffer.from(error?.stack ?? String(error), "utf8"));
                    child.emit("close", 1, null);
                }
            });
            return child;
        },
        terminateTree() {},
    };
}

function mutableClock(start = 20_000) {
    let now = start;
    return {
        now: () => now,
        isoNow: () => new Date(now).toISOString(),
        advance(milliseconds) {
            now += milliseconds;
        },
    };
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
        expect(rec.version).toBe(3);
        expect(rec.harnessEntryHash).toBe(verified.entryHash);
        expect(rec.executableHash).toBe(verified.executableHash);
        expect(rec.stagedExecutableHash).toBe(verified.executableHash);
        expect(rec.candidateSnapshotHash).toBe(snapshot.hash);
        expect(rec.candidateSnapshotPreClosureHash).toMatch(
            /^sha256:crucible-measurement-snapshot-closure-v1:[a-f0-9]{64}$/,
        );
        expect(rec.candidateSnapshotPostClosureHash)
            .toBe(rec.candidateSnapshotPreClosureHash);
        expect(rec.candidateSnapshotIdentitySummary.pre)
            .toEqual(rec.candidateSnapshotIdentitySummary.post);
        expect(rec.candidateSnapshotMutationCheck).toMatchObject({
            status: "passed",
            closureStable: true,
            identityStable: true,
            openHandleRehashStable: true,
            reparseStable: true,
        });
        expect(
            rec.candidateSnapshotMutationCheck.readOnly.verifiedReadOnlyFiles
            + rec.candidateSnapshotMutationCheck.readOnly.unverifiedReadOnlyFiles,
        ).toBe(snapshot.manifest.fileCount);
        expect(rec.attemptId).toBe("att-0001");
        expect(rec.runnerEpochId).toBe("epoch-2026-07-09-a");
        expect(rec.parserVersion).toBe(PARSER_VERSION);
        expect(rec.sandbox).toBeNull();
        expect(rec.exit).toEqual({ code: 0, signal: null, timedOut: false });
        expect(rec.parsed).toEqual(result.parsed);
        expect(rec.argvHash).toMatch(/^sha256:crucible-measurement-argv-v1:[a-f0-9]{64}$/);
        expect(rec.envHash).toMatch(/^sha256:crucible-measurement-env-v1:[a-f0-9]{64}$/);
        expect(rec.stdoutHash).toMatch(/^sha256:crucible-measurement-stream-v1:[a-f0-9]{64}$/);
        expect(rec.stderrHash).toMatch(/^sha256:crucible-measurement-stream-v1:[a-f0-9]{64}$/);
    });

    it("passes the candidate snapshot path via env AND via the argv placeholder", async () => {
        const root = tmp("cand");
        const { result } = await runOnce({
            root, entryId: "readsnap",
            script: `
                const argPath = process.argv[2];
                const envPath = process.env.CANDIDATE_SNAPSHOT_PATH;
                const attempt = process.env.CRUCIBLE_ATTEMPT_ID;
                const epoch = process.env.CRUCIBLE_RUNNER_EPOCH_ID;
                const bytes = fs.readFileSync(path.join(argPath, "candidate.bin"), "utf8");
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
        process.env.CRUCIBLE_MEASURE_SECRET_TEST_ONLY = secret;
        try {
            const { result } = await runOnce({
                root, entryId: "envcheck",
                script: `
                    const leaked = Object.hasOwn(process.env, "CRUCIBLE_MEASURE_SECRET_TEST_ONLY");
                    process.stdout.write(JSON.stringify({ pass: !leaked, metrics: { leaked: leaked ? 1 : 0 } }));
                `,
                entryOverrides: { allowedEnv: { EXPECTED_VAR: "yes" } },
            });
            expect(result.parsed.pass).toBe(true);
            expect(result.parsed.metrics).toEqual({ leaked: 0 });
        } finally {
            delete process.env.CRUCIBLE_MEASURE_SECRET_TEST_ONLY;
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
        expect(spawnCall.executable).toContain(`${path.sep}.crucible-stage-att-0001${path.sep}`);
        expect(spawnCall.argv[0]).toContain(`${path.sep}.crucible-stage-att-0001${path.sep}`);
        expect(fs.existsSync(path.dirname(path.dirname(spawnCall.executable)))).toBe(false);
        expect(result.receipt.stagedExecutableHash).toBe(result.receipt.executableHash);
        expect(result.receipt.stagedDependencyHashes[0].sha256)
            .toBe(result.receipt.dependencyHashes[0].sha256);
    });

    it("propagates the remaining deadline to the harness and rejects late facts", async () => {
        const root = tmp("deadline");
        const scriptPath = writeHarnessScript(
            root,
            "deadline",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "deadline", {
            argvTemplate: [scriptPath],
            timeoutMs: 5_000,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("deadline");
        const snapshot = materializeCandidateSnapshot(root, "deadline-snap", "x");
        const clock = mutableClock();
        const deadlineMs = clock.now() + 500;
        let spawnOptions = null;
        const executor = createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
            clock,
            processAdapter: {
                spawn(_executable, _argv, options) {
                    spawnOptions = options;
                    const child = new EventEmitter();
                    child.pid = 5050;
                    child.stdout = new PassThrough();
                    child.stderr = new PassThrough();
                    setImmediate(() => {
                        child.stdout.end(Buffer.from('{"pass":true}', "utf8"));
                        child.stderr.end();
                        clock.advance(501);
                        child.emit("close", 0, null);
                    });
                    return child;
                },
                terminateTree() {
                    return true;
                },
            },
        });
        await expect(executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
            deadlineMs,
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.TIMEOUT,
            details: {
                deadlineExceeded: true,
                deadlineMs,
            },
        });
        expect(spawnOptions).toMatchObject({
            timeoutMs: 500,
            deadlineMs,
        });
    });

    it("bounds hung capability termination and cleanup", async () => {
        const root = tmp("capability-shutdown");
        const scriptPath = writeHarnessScript(
            root,
            "capability-shutdown",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "capability-shutdown", {
            argvTemplate: [scriptPath],
            timeoutMs: 20,
            executesCandidateCode: true,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("capability-shutdown");
        const snapshot = materializeCandidateSnapshot(
            root,
            "capability-shutdown-snap",
            "x",
        );
        const calls = { terminate: 0, cleanup: 0, terminationStartedAt: null };
        const provider = createSandboxProvider({
            providerId: "hung-capability-provider",
            providerVersion: "v1",
            admitAndPrepare(request, issueLaunchCapability) {
                const child = new EventEmitter();
                child.pid = 6060;
                child.stdout = new PassThrough();
                child.stderr = new PassThrough();
                return issueLaunchCapability({
                    capabilityId: "hung-capability",
                    policyId: "hung-policy",
                    policyDigest: `sha256:hung-policy:${"a".repeat(64)}`,
                    permittedStagedRoots: request.stagedRoots,
                    launch() {
                        return child;
                    },
                    terminate() {
                        calls.terminate += 1;
                        calls.terminationStartedAt ??= Date.now();
                        return new Promise(() => {});
                    },
                    cleanup() {
                        calls.cleanup += 1;
                        return new Promise(() => {});
                    },
                });
            },
        });
        const executor = createMeasurementExecutor({
            allowlist: list,
            sandboxProvider: provider,
            scratchRoot: root,
            terminationDrainMs: 10,
            capabilityCleanupTimeoutMs: 10,
            processAdapter: {
                spawn() {
                    throw new Error("host adapter must not launch candidate code");
                },
                terminateTree() {
                    throw new Error("host adapter must not terminate candidate code");
                },
            },
        });
        await expect(executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
        });
        expect(calls.terminationStartedAt).not.toBeNull();
        expect(Date.now() - calls.terminationStartedAt).toBeLessThan(500);
        expect(calls.terminate).toBeGreaterThanOrEqual(1);
        expect(calls.cleanup).toBe(1);
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

    it("rejects candidate bytes that no longer match the supplied immutable manifest before spawn", async () => {
        const root = tmp("candidate-pre-mismatch");
        const script = writeHarnessScript(
            root,
            "candidate-pre-mismatch",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "candidate-pre-mismatch", {
            argvTemplate: [script, "{{candidatePath}}"],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("candidate-pre-mismatch");
        const snapshot = materializeCandidateSnapshot(
            root,
            "candidate-pre-mismatch-snap",
            "original",
        );
        fs.writeFileSync(
            path.join(snapshot.path, snapshot.manifest.entries[0].path),
            "changed-before-spawn",
        );
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
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH,
        });
        expect(spawned).toBe(false);
    });

    for (const mutation of [
        {
            label: "content mutation",
            apply(filePath) {
                fs.chmodSync(filePath, 0o666);
                fs.writeFileSync(filePath, "mutated-during-run");
            },
        },
        {
            label: "replacement",
            apply(filePath) {
                const replacement = `${filePath}.replacement`;
                fs.writeFileSync(replacement, fs.readFileSync(filePath));
                fs.chmodSync(filePath, 0o666);
                fs.unlinkSync(filePath);
                fs.renameSync(replacement, filePath);
            },
        },
        {
            label: "unlink",
            apply(filePath) {
                fs.chmodSync(filePath, 0o666);
                fs.unlinkSync(filePath);
            },
        },
    ]) {
        it(`rejects candidate ${mutation.label} during harness execution`, async () => {
            const id = `candidate-${mutation.label.replace(/\s+/gu, "-")}`;
            const root = tmp(id);
            const script = writeHarnessScript(
                root,
                id,
                `process.stdout.write('{"pass":true}');`,
            );
            const allowlistPath = writeAllowlist(root, id, {
                argvTemplate: [script, "{{candidatePath}}"],
            });
            const list = loadHarnessAllowlist(allowlistPath);
            const verified = list.verifyEntry(id);
            const snapshot = materializeCandidateSnapshot(
                root,
                `${id}-snap`,
                "stable-candidate-bytes",
            );
            const filePath = path.join(
                snapshot.path,
                snapshot.manifest.entries[0].path,
            );
            let mutationRan = false;
            const executor = createMeasurementExecutor({
                allowlist: list,
                scratchRoot: root,
                processAdapter: createMutationProcessAdapter(() => {
                    mutation.apply(filePath);
                    mutationRan = true;
                }),
            });
            await expect(executor.run({
                verifiedEntry: verified,
                candidateSnapshot: snapshot,
                ...fixedIds(),
            })).rejects.toMatchObject({
                code: MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
            });
            expect(mutationRan).toBe(true);
        });
    }

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
