// crucible/__tests__/measurement-executor.test.mjs
//
// Release-only happy-path / structural tests for the MeasurementExecutor:
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
    canonicalizeReceipt,
    hashReceipt,
    loadHarnessAllowlist,
    projectDeterministicReceipt,
} from "../measurement/index.mjs";
import { MEASUREMENT_LIFECYCLE_ADAPTER } from "../measurement/private-adapters.mjs";

import {
    NODE_EXE,
    fixedIds,
    makeTempRoot,
    manualClock,
    materializeCandidateSnapshot,
    pinnedDependency,
    rmTempRoot,
    sha256HexOfFile,
    writeAllowlist,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";

const roots = [];
function tmp(l) { const r = makeTempRoot(`exec-${l}`); roots.push(r); return r; }
afterAll(() => roots.forEach(rmTempRoot));

function syntheticExecutable(root, label) {
    const executable = path.join(root, `${label}.exe`);
    fs.writeFileSync(executable, `synthetic executable: ${label}`);
    return {
        executable,
        executableSha256: sha256HexOfFile(executable),
    };
}

async function runOnce({ root, entryId, script, snapshotBytes = "candidate-bytes", sandboxProvider = null, entryOverrides = {}, clock = null }) {
    const scriptPath = writeHarnessScript(root, entryId, script);
    const allowlistPath = writeAllowlist(root, entryId, {
        argvTemplate: [scriptPath, "{{candidatePath}}"],
        ...entryOverrides,
        dependencies: [
            pinnedDependency(scriptPath),
            ...(entryOverrides.dependencies ?? []),
        ],
    });
    const list = loadHarnessAllowlist(allowlistPath);
    const verified = list.verifyEntry(entryId);
    const snapshot = materializeCandidateSnapshot(root, `${entryId}-snap`, snapshotBytes);
    const executor = createMeasurementExecutor({
        allowlist: list,
        sandboxProvider,
        clock: clock ?? manualClock(),
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
    let activeChild = null;
    return {
        spawn() {
            const child = new EventEmitter();
            activeChild = child;
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
        terminateTree() {
            if (activeChild === null) return false;
            activeChild.stdout.end();
            activeChild.stderr.end();
            setImmediate(() =>
                activeChild.emit("close", null, "SIGKILL"));
            return true;
        },
    };
}

function createChunkedProcessAdapter(events) {
    const terminations = [];
    let activeChild = null;
    let stopped = false;
    return {
        terminations,
        adapter: {
            spawn() {
                const child = new EventEmitter();
                activeChild = child;
                child.pid = 4343;
                child.stdout = new PassThrough();
                child.stderr = new PassThrough();
                let index = 0;
                const emitNext = () => {
                    if (stopped) return;
                    if (index >= events.length) {
                        child.stdout.end();
                        child.stderr.end();
                        setImmediate(() => child.emit("close", 0, null));
                        return;
                    }
                    const event = events[index];
                    index += 1;
                    const chunks = Array.isArray(event) ? event : [event];
                    for (const chunk of chunks) {
                        child[chunk.stream].write(Buffer.from(chunk.bytes));
                    }
                    setImmediate(emitNext);
                };
                setImmediate(emitNext);
                return child;
            },
            terminateTree(pid) {
                terminations.push(pid);
                if (activeChild !== null && !stopped) {
                    stopped = true;
                    setImmediate(() => {
                        activeChild.stdout.end();
                        activeChild.stderr.end();
                        activeChild.emit("close", null, "SIGKILL");
                    });
                }
                return true;
            },
        },
    };
}

async function runChunkedOutput({
    root,
    events,
    maxStdoutBytes,
    maxStderrBytes,
    byteBudgets,
    attemptId,
}) {
    const scriptPath = writeHarnessScript(
        root,
        "chunked",
        `process.stdout.write('{"pass":true}');`,
    );
    const allowlistPath = writeAllowlist(root, "chunked", {
        ...syntheticExecutable(root, "chunked"),
        argvTemplate: [scriptPath],
        dependencies: [pinnedDependency(scriptPath)],
        maxStdoutBytes,
        maxStderrBytes,
    });
    const list = loadHarnessAllowlist(allowlistPath);
    const verified = list.verifyEntry("chunked");
    const snapshot = materializeCandidateSnapshot(root, "chunked-snap", "candidate");
    const process = createChunkedProcessAdapter(events);
    const executor = createMeasurementExecutor({
        allowlist: list,
        processAdapter: process.adapter,
        clock: manualClock(),
        scratchRoot: root,
        ...(byteBudgets === undefined ? {} : { byteBudgets }),
    });
    return {
        process,
        promise: executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
            ...(attemptId === undefined ? {} : { attemptId }),
        }),
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
        expect(rec.version).toBe(6);
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
        expect(rec.outputCapture).toEqual({
            stdout: {
                capBytes: 1024 * 1024,
                totalObservedBytes: result.stdoutBytes,
                retainedBytes: result.stdoutBytes,
                overflowed: false,
                truncated: false,
            },
            stderr: {
                capBytes: 256 * 1024,
                totalObservedBytes: result.stderrBytes,
                retainedBytes: result.stderrBytes,
                overflowed: false,
                truncated: false,
            },
            overflowed: false,
            truncated: false,
        });
    });

    it("propagates strict parser failures from trusted harness output", async () => {
        const root = tmp("parse-failure");
        await expect(runOnce({
            root,
            entryId: "parse-failure",
            script: `process.stdout.write('{"pass":true} trailing');`,
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.PARSE_TRAILING,
        });
    });

    it("reports a non-zero harness exit with an explicit exit record", async () => {
        const root = tmp("nonzero");
        await expect(runOnce({
            root,
            entryId: "nonzero",
            script: `
                process.stderr.write("synthetic failure");
                process.exit(7);
            `,
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
            details: {
                exit: { code: 7, signal: null },
            },
        });
    });

    it("terminates a timed-out fake host process and waits for close", async () => {
        const root = tmp("host-timeout");
        const scriptPath = writeHarnessScript(
            root,
            "host-timeout",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "host-timeout", {
            ...syntheticExecutable(root, "host-timeout"),
            argvTemplate: [scriptPath],
            dependencies: [pinnedDependency(scriptPath)],
            timeoutMs: 10,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const child = new EventEmitter();
        child.pid = 7001;
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        const terminated = [];
        const executor = createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
            clock: manualClock(),
            processAdapter: {
                spawn() {
                    return child;
                },
                terminateTree(pid) {
                    terminated.push(pid);
                    child.stdout.end();
                    child.stderr.end();
                    setImmediate(() =>
                        child.emit("close", null, "SIGKILL"));
                    return true;
                },
            },
        });

        await expect(executor.run({
            verifiedEntry: list.verifyEntry("host-timeout"),
            candidateSnapshot: materializeCandidateSnapshot(
                root,
                "host-timeout-snap",
                "candidate",
            ),
            ...fixedIds(),
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.TIMEOUT,
        });
        expect(terminated).toEqual([child.pid]);
    });

    describe("H7 harness lifecycle failure matrix", () => {
        it("terminates the launched harness and removes staging when the runner crashes after launch", async () => {
            const root = tmp("fault-after-launch");
            const scriptPath = writeHarnessScript(
                root,
                "fault-after-launch",
                `process.stdout.write('{"pass":true}');`,
            );
            const allowlistPath = writeAllowlist(root, "fault-after-launch", {
                ...syntheticExecutable(root, "fault-after-launch"),
                argvTemplate: [scriptPath],
                dependencies: [pinnedDependency(scriptPath)],
                timeoutMs: 5_000,
            });
            const list = loadHarnessAllowlist(allowlistPath);
            const verified = list.verifyEntry("fault-after-launch");
            const snapshot = materializeCandidateSnapshot(
                root,
                "fault-after-launch-snap",
                "x",
            );
            const child = new EventEmitter();
            child.pid = 7171;
            child.stdout = new PassThrough();
            child.stderr = new PassThrough();
            const terminations = [];
            const executor = createMeasurementExecutor({
                allowlist: list,
                scratchRoot: root,
                terminationDrainMs: 20,
                processAdapter: {
                    spawn() {
                        return child;
                    },
                    terminateTree(pid) {
                        terminations.push(pid);
                        child.stdout.end();
                        child.stderr.end();
                        setImmediate(() => child.emit("close", null, "SIGKILL"));
                        return true;
                    },
                },
                [MEASUREMENT_LIFECYCLE_ADAPTER]: {
                    afterHarnessLaunch() {
                        throw new Error("injected launch crash");
                    },
                },
            });

            await expect(executor.run({
                verifiedEntry: verified,
                candidateSnapshot: snapshot,
                ...fixedIds(),
            })).rejects.toThrow("injected launch crash");
            expect(terminations).toEqual([child.pid]);
            expect(fs.readdirSync(root)
                .filter((name) => name.startsWith(".crucible-stage-"))).toEqual([]);
        });

        it("rejects facts when the absolute deadline crosses inside sandbox launch", async () => {
            const root = tmp("deadline-sandbox-launch");
            const scriptPath = writeHarnessScript(
                root,
                "deadline-sandbox-launch",
                `process.stdout.write('{"pass":true}');`,
            );
            const allowlistPath = writeAllowlist(root, "deadline-sandbox-launch", {
                ...syntheticExecutable(root, "deadline-sandbox-launch"),
                argvTemplate: [scriptPath],
                dependencies: [pinnedDependency(scriptPath)],
                timeoutMs: 5_000,
                executesCandidateCode: true,
            });
            const list = loadHarnessAllowlist(allowlistPath);
            const verified = list.verifyEntry("deadline-sandbox-launch");
            const snapshot = materializeCandidateSnapshot(
                root,
                "deadline-sandbox-launch-snap",
                "x",
            );
            const clock = mutableClock();
            const deadlineMs = clock.now() + 500;
            let cleanupCalls = 0;
            const provider = createSandboxProvider({
                providerId: "deadline-launch-provider",
                providerVersion: "v1",
                admitAndPrepare(request, issueLaunchCapability) {
                    return issueLaunchCapability({
                        capabilityId: "deadline-launch-capability",
                        policyId: "deadline-launch-policy",
                        policyDigest:
                            `sha256:deadline-launch-policy:${"d".repeat(64)}`,
                        permittedStagedRoots: request.stagedRoots,
                        launch() {
                            const child = new EventEmitter();
                            child.pid = 7272;
                            child.stdout = new PassThrough();
                            child.stderr = new PassThrough();
                            clock.advance(501);
                            setImmediate(() => {
                                child.stdout.end(Buffer.from('{"pass":true}', "utf8"));
                                child.stderr.end();
                                child.emit("close", 0, null);
                            });
                            return child;
                        },
                        terminate() {
                            return true;
                        },
                        cleanup() {
                            cleanupCalls += 1;
                            return true;
                        },
                    });
                },
            });
            const executor = createMeasurementExecutor({
                allowlist: list,
                sandboxProvider: provider,
                scratchRoot: root,
                clock,
                processAdapter: {
                    spawn() {
                        throw new Error("host launch is forbidden");
                    },
                    terminateTree() {
                        throw new Error("host termination is forbidden");
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
            expect(cleanupCalls).toBe(1);
        });
    });

    it("accepts output exactly at the cap and records exact observed/retained totals", async () => {
        const root = tmp("exact-cap");
        const cap = 64;
        const json = Buffer.from('{"pass":true}', "utf8");
        const exact = Buffer.concat([json, Buffer.alloc(cap - json.length, 0x20)]);
        const run = await runChunkedOutput({
            root,
            maxStdoutBytes: cap,
            maxStderrBytes: 8,
            events: [
                { stream: "stdout", bytes: exact.subarray(0, 7) },
                { stream: "stdout", bytes: exact.subarray(7) },
                { stream: "stderr", bytes: Buffer.from("12345678") },
            ],
        });
        const result = await run.promise;
        expect(result.parsed.pass).toBe(true);
        expect(result.outputCapture).toMatchObject({
            stdout: {
                totalObservedBytes: cap,
                retainedBytes: cap,
                overflowed: false,
                truncated: false,
            },
            stderr: {
                totalObservedBytes: 8,
                retainedBytes: 8,
                overflowed: false,
                truncated: false,
            },
            overflowed: false,
            truncated: false,
        });
        expect(run.process.terminations).toEqual([]);
    });

    it("rejects a later chunk after an exact-cap valid JSON prefix", async () => {
        const root = tmp("cap-later");
        const cap = 64;
        const json = Buffer.from('{"pass":true}', "utf8");
        const exact = Buffer.concat([json, Buffer.alloc(cap - json.length, 0x20)]);
        const contradictory = Buffer.from('{"pass":false}', "utf8");
        const run = await runChunkedOutput({
            root,
            maxStdoutBytes: cap,
            maxStderrBytes: 8,
            events: [
                { stream: "stdout", bytes: exact },
                { stream: "stdout", bytes: contradictory },
            ],
        });
        let error;
        try {
            await run.promise;
        } catch (caught) {
            error = caught;
        }
        expect(error.code).toBe(MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW);
        expect(error.details.outputCapture.stdout).toEqual({
            capBytes: cap,
            totalObservedBytes: cap + contradictory.length,
            retainedBytes: cap,
            overflowed: true,
            truncated: true,
        });
        expect(error.details.receipt.parsed).toBeNull();
        expect(error.details.receipt.outputCapture)
            .toEqual(error.details.outputCapture);
        expect(run.process.terminations).toEqual([4343]);
    });

    it("counts every multi-chunk byte while retaining only the cap", async () => {
        const root = tmp("multi-overflow");
        const run = await runChunkedOutput({
            root,
            maxStdoutBytes: 16,
            maxStderrBytes: 8,
            events: [
                { stream: "stdout", bytes: Buffer.from("12345") },
                { stream: "stdout", bytes: Buffer.from("6789012") },
                { stream: "stdout", bytes: Buffer.from("3456789012") },
            ],
        });
        let error;
        try {
            await run.promise;
        } catch (caught) {
            error = caught;
        }
        expect(error.code).toBe(MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW);
        expect(error.details.outputCapture.stdout).toMatchObject({
            totalObservedBytes: 22,
            retainedBytes: 16,
            overflowed: true,
            truncated: true,
        });
    });

    it("records overflow independently for stdout and stderr", async () => {
        const root = tmp("both-overflow");
        const run = await runChunkedOutput({
            root,
            maxStdoutBytes: 8,
            maxStderrBytes: 8,
            events: [
                [
                    { stream: "stdout", bytes: Buffer.from("1234567890") },
                    { stream: "stderr", bytes: Buffer.from("abcdefghijkl") },
                ],
            ],
        });
        let error;
        try {
            await run.promise;
        } catch (caught) {
            error = caught;
        }
        expect(error.code).toBe(MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW);
        expect(error.details.streams).toEqual(["stdout", "stderr"]);
        expect(error.details.outputCapture.stdout).toMatchObject({
            totalObservedBytes: 10,
            retainedBytes: 8,
            overflowed: true,
            truncated: true,
        });
        expect(error.details.outputCapture.stderr).toMatchObject({
            totalObservedBytes: 12,
            retainedBytes: 8,
            overflowed: true,
            truncated: true,
        });
    });

    it("enforces a combined attempt output budget before retaining a huge chunk", async () => {
        const root = tmp("combined-output-budget");
        const run = await runChunkedOutput({
            root,
            maxStdoutBytes: 1024 * 1024,
            maxStderrBytes: 1024 * 1024,
            byteBudgets: {
                perAttemptOutputBytes: 64,
                perInvestigationOutputBytes: 128,
            },
            events: [
                { stream: "stdout", bytes: Buffer.alloc(2 * 1024 * 1024, 0x61) },
            ],
        });
        await expect(run.promise).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.BYTE_BUDGET_EXCEEDED,
            details: {
                kind: "output",
                attemptLimit: 64,
                bytes: 2 * 1024 * 1024,
            },
        });
        expect(run.process.terminations).toEqual([4343]);
    });

    it("enforces cumulative investigation output across attempts", async () => {
        const root = tmp("investigation-output-budget");
        const scriptPath = writeHarnessScript(
            root,
            "cumulative",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "cumulative", {
            ...syntheticExecutable(root, "cumulative"),
            argvTemplate: [scriptPath],
            dependencies: [pinnedDependency(scriptPath)],
            maxStdoutBytes: 64,
            maxStderrBytes: 8,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("cumulative");
        const snapshot = materializeCandidateSnapshot(
            root,
            "cumulative-snap",
            "candidate",
        );
        const terminations = [];
        let activeChild = null;
        const stoppedChildren = new WeakSet();
        const adapter = {
            spawn() {
                const child = new EventEmitter();
                activeChild = child;
                child.pid = 4444;
                child.stdout = new PassThrough();
                child.stderr = new PassThrough();
                setImmediate(() => {
                    if (stoppedChildren.has(child)) return;
                    child.stdout.end(Buffer.from('{"pass":true}', "utf8"));
                    child.stderr.end();
                    child.emit("close", 0, null);
                });
                return child;
            },
            terminateTree(pid) {
                terminations.push(pid);
                if (activeChild !== null) {
                    stoppedChildren.add(activeChild);
                    activeChild.stdout.end();
                    activeChild.stderr.end();
                    setImmediate(() =>
                        activeChild.emit("close", null, "SIGKILL"));
                }
                return true;
            },
        };
        const executor = createMeasurementExecutor({
            allowlist: list,
            processAdapter: adapter,
            scratchRoot: root,
            byteBudgets: {
                perAttemptOutputBytes: 16,
                perInvestigationOutputBytes: 20,
            },
        });
        await executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
            attemptId: "att-budget-1",
        });
        await expect(executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
            attemptId: "att-budget-2",
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.BYTE_BUDGET_EXCEEDED,
            details: {
                kind: "output",
                investigationLimit: 20,
                investigationBytes: 26,
            },
        });
        expect(terminations).toContain(4444);
    });

    it("rejects an oversized receipt before exposing raw output", async () => {
        const root = tmp("receipt-budget");
        let captured = false;
        const scriptPath = writeHarnessScript(
            root,
            "receipt-budget",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "receipt-budget", {
            argvTemplate: [scriptPath],
            dependencies: [pinnedDependency(scriptPath)],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const executor = createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
            byteBudgets: {
                perAttemptReceiptBytes: 256,
                perInvestigationReceiptBytes: 256,
            },
            onCapturedOutput() {
                captured = true;
            },
        });
        await expect(executor.run({
            verifiedEntry: list.verifyEntry("receipt-budget"),
            candidateSnapshot: materializeCandidateSnapshot(
                root,
                "receipt-budget-snap",
                "candidate",
            ),
            ...fixedIds(),
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.BYTE_BUDGET_EXCEEDED,
            details: {
                kind: "receipt",
                attemptLimit: 256,
            },
        });
        expect(captured).toBe(false);
    });

    it("enforces cumulative investigation receipt bytes from prior usage", async () => {
        const root = tmp("cumulative-receipt-budget");
        const scriptPath = writeHarnessScript(
            root,
            "cumulative-receipt-budget",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(
            root,
            "cumulative-receipt-budget",
            {
                argvTemplate: [scriptPath],
                dependencies: [pinnedDependency(scriptPath)],
            },
        );
        const list = loadHarnessAllowlist(allowlistPath);
        const verifiedEntry = list.verifyEntry("cumulative-receipt-budget");
        const candidateSnapshot = materializeCandidateSnapshot(
            root,
            "cumulative-receipt-budget-snap",
            "candidate",
        );
        const first = await createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
        }).run({
            verifiedEntry,
            candidateSnapshot,
            ...fixedIds(),
            attemptId: "att-receipt-seed",
        });
        const priorReceiptBytes = Buffer.byteLength(
            canonicalizeReceipt(first.receipt),
            "utf8",
        );
        const limit = priorReceiptBytes + 16;
        const executor = createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
            byteBudgets: {
                perAttemptReceiptBytes: limit,
                perInvestigationReceiptBytes: limit,
            },
            initialByteUsage: {
                receiptBytes: priorReceiptBytes,
            },
        });
        await expect(executor.run({
            verifiedEntry,
            candidateSnapshot,
            ...fixedIds(),
            attemptId: "att-receipt-after-seed",
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.BYTE_BUDGET_EXCEEDED,
            details: {
                kind: "receipt",
                investigationLimit: limit,
            },
        });
    }, 30_000);

    it("rejects an oversized candidate CAS closure before private staging", async () => {
        const root = tmp("candidate-cas-budget");
        const scriptPath = writeHarnessScript(
            root,
            "candidate-cas-budget",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "candidate-cas-budget", {
            ...syntheticExecutable(root, "candidate-cas-budget"),
            argvTemplate: [scriptPath],
            dependencies: [pinnedDependency(scriptPath)],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const executor = createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
            byteBudgets: {
                perAttemptCasBytes: 512,
                perInvestigationCasBytes: 1024,
            },
        });
        await expect(executor.run({
            verifiedEntry: list.verifyEntry("candidate-cas-budget"),
            candidateSnapshot: materializeCandidateSnapshot(
                root,
                "candidate-cas-budget-snap",
                "x".repeat(1024),
            ),
            ...fixedIds(),
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.BYTE_BUDGET_EXCEEDED,
            details: {
                kind: "cas",
                attemptLimit: 512,
                stage: "candidate snapshot admission",
            },
        });
        expect(fs.readdirSync(root)
            .filter((name) => name.startsWith(".crucible-stage-")))
            .toEqual([]);
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
            dependencies: [pinnedDependency(scriptPath)],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("det");
        const snapshot = materializeCandidateSnapshot(root, "det-snap", "stable-bytes");
        const ids = fixedIds();

        async function run() {
            const executor = createMeasurementExecutor({
                allowlist: list,
                clock: manualClock(),
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
    }, 30_000);

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
            dependencies: [pinnedDependency(scriptPath)],
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

    for (const target of ["executable", "dependency", "candidate"]) {
        it(`rejects concurrent staged ${target} substitution before launch`, async () => {
            const root = tmp(`staged-substitution-${target}`);
            const scriptPath = writeHarnessScript(
                root,
                `staged-substitution-${target}`,
                `process.stdout.write('{"pass":true}');`,
            );
            const allowlistPath = writeAllowlist(
                root,
                `staged-substitution-${target}`,
                {
                    ...syntheticExecutable(
                        root,
                        `staged-substitution-${target}`,
                    ),
                    argvTemplate: [scriptPath, "{{candidatePath}}"],
                    dependencies: [pinnedDependency(scriptPath)],
                },
            );
            const list = loadHarnessAllowlist(allowlistPath);
            let spawned = false;
            const executor = createMeasurementExecutor({
                allowlist: list,
                scratchRoot: root,
                processAdapter: {
                    spawn() {
                        spawned = true;
                        throw new Error("substituted bytes must never launch");
                    },
                    terminateTree() {
                        throw new Error("termination must not run before spawn");
                    },
                },
                [MEASUREMENT_LIFECYCLE_ADAPTER]: {
                    afterHarnessStaging(details) {
                        const file = target === "executable"
                            ? details.executable
                            : target === "dependency"
                                ? details.dependencies[0]
                                : details.candidateFiles[0];
                        fs.chmodSync(file, 0o600);
                        fs.appendFileSync(file, "substituted");
                    },
                },
            });
            await expect(executor.run({
                verifiedEntry: list.verifyEntry(
                    `staged-substitution-${target}`,
                ),
                candidateSnapshot: materializeCandidateSnapshot(
                    root,
                    `staged-substitution-${target}-snap`,
                    "candidate",
                ),
                ...fixedIds(),
            })).rejects.toMatchObject({
                code: MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
            });
            expect(spawned).toBe(false);
        });
    }

    it("rejects staged identity-only mutation before launch", async () => {
        const root = tmp("staged-identity-mutation");
        const scriptPath = writeHarnessScript(
            root,
            "staged-identity-mutation",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "staged-identity-mutation", {
            ...syntheticExecutable(root, "staged-identity-mutation"),
            argvTemplate: [scriptPath],
            dependencies: [pinnedDependency(scriptPath)],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const executor = createMeasurementExecutor({
            allowlist: list,
            scratchRoot: root,
            [MEASUREMENT_LIFECYCLE_ADAPTER]: {
                afterHarnessStaging(details) {
                    const now = new Date(Date.now() + 60_000);
                    fs.utimesSync(details.executable, now, now);
                },
            },
        });
        await expect(executor.run({
            verifiedEntry: list.verifyEntry("staged-identity-mutation"),
            candidateSnapshot: materializeCandidateSnapshot(
                root,
                "staged-identity-mutation-snap",
                "candidate",
            ),
            ...fixedIds(),
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.FILE_CHANGED_DURING_VERIFICATION,
        });
    });

    it("propagates the remaining deadline to the harness and rejects late facts", async () => {
        const root = tmp("deadline");
        const scriptPath = writeHarnessScript(
            root,
            "deadline",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "deadline", {
            ...syntheticExecutable(root, "deadline"),
            argvTemplate: [scriptPath],
            dependencies: [pinnedDependency(scriptPath)],
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
                    child.stdout.end();
                    child.stderr.end();
                    setImmediate(() =>
                        child.emit("close", null, "SIGKILL"));
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
            ...syntheticExecutable(root, "capability-shutdown"),
            argvTemplate: [scriptPath],
            dependencies: [pinnedDependency(scriptPath)],
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
                terminateTree() {
                    throw new Error("termination must not run before spawn");
                },
            },
        });
        await expect(executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
        })).rejects.toMatchObject({ code: MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH });
        expect(spawned).toBe(false);

        const script = writeHarnessScript(root, "dep-swap", `process.stdout.write('{"pass":true}');`);
        const depAllowlist = writeAllowlist(root, "dep-swap", {
            argvTemplate: [script],
            dependencies: [pinnedDependency(script)],
        });
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
                terminateTree() {
                    throw new Error("termination must not run before spawn");
                },
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
            ...syntheticExecutable(root, "candidate-pre-mismatch"),
            argvTemplate: [script, "{{candidatePath}}"],
            dependencies: [pinnedDependency(script)],
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
                terminateTree() {
                    throw new Error("termination must not run before spawn");
                },
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
                ...syntheticExecutable(root, id),
                argvTemplate: [script, "{{candidatePath}}"],
                dependencies: [pinnedDependency(script)],
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
            ...syntheticExecutable(root, "owned"),
            argvTemplate: [script],
            dependencies: [pinnedDependency(script)],
        }, { fileName: "first.json" });
        const secondPath = writeAllowlist(root, "owned", {
            ...syntheticExecutable(root, "owned"),
            argvTemplate: [script],
            dependencies: [pinnedDependency(script)],
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
                terminateTree() {
                    throw new Error("termination must not run before spawn");
                },
            },
        });
        await expect(executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot,
            ...fixedIds(),
        })).rejects.toMatchObject({ code: MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT });
    });
});
