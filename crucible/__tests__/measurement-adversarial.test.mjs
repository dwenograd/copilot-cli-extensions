// crucible/__tests__/measurement-adversarial.test.mjs
//
// Adversarial tests for the trusted-measurement boundary:
//   - candidate-code refusal (no sandbox)
//   - sandbox provider refusal
//   - executable tampered between allowlist load and run
//   - allowlist file tampered between load and run
//   - path shadowing via a symlink / junction
//   - output overflow triggers tree-kill
//   - timeout triggers tree-kill
//   - malformed / trailing / nonfinite / oversized harness JSON
//   - receipt determinism fields (subset stable across runs)

import { describe, it, expect, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";

import {
    MEASUREMENT_ERROR_CODES,
    SandboxRequiredError,
    createMeasurementExecutor,
    createSandboxProvider,
    loadHarnessAllowlist,
    projectDeterministicReceipt,
} from "../measurement/index.mjs";

import {
    NODE_EXE,
    canCreateDirJunction,
    canCreateFileSymlink,
    fixedClock,
    fixedIds,
    makeTempRoot,
    materializeCandidateSnapshot,
    nodeExeSha256Hex,
    rmTempRoot,
    writeAllowlist,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";

const roots = [];
function tmp(l) { const r = makeTempRoot(`adv-${l}`); roots.push(r); return r; }
afterAll(() => roots.forEach(rmTempRoot));

async function catchAsync(promiseOrFn) {
    const p = typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn;
    try {
        await p;
    } catch (e) {
        return e;
    }
    throw new Error("expected the operation to throw");
}

function ids() { return fixedIds(); }

describe("SANDBOX_REQUIRED for candidate-code harnesses without a provider", () => {
    it("refuses to spawn an entry with executesCandidateCode=true when no SandboxProvider is supplied", async () => {
        const root = tmp("sbx1");
        const scriptPath = writeHarnessScript(root, "runcode", `process.stdout.write('{"pass":true}');`);
        const allowlistPath = writeAllowlist(root, "runcode", {
            argvTemplate: [scriptPath, "{{candidatePath}}"],
            executesCandidateCode: true, // <-- the danger flag
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("runcode");
        const snapshot = materializeCandidateSnapshot(root, "snap", "x");
        const executor = createMeasurementExecutor({ allowlist: list, sandboxProvider: null, scratchRoot: root });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect(err).toBeInstanceOf(SandboxRequiredError);
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.SANDBOX_REQUIRED);
    });

    it("does NOT accept cwd/env/timeout as a substitute for a real sandbox", async () => {
        // Same as above but with the executor set to a whole slew of
        // "restrictive-looking" options — nothing about that fools the gate.
        const root = tmp("sbx2");
        const scriptPath = writeHarnessScript(root, "runcode2", `process.stdout.write('{"pass":true}');`);
        const allowlistPath = writeAllowlist(root, "runcode2", {
            argvTemplate: [scriptPath],
            executesCandidateCode: true,
            allowedEnv: {},
            timeoutMs: 1000,
            maxStdoutBytes: 1024,
            maxStderrBytes: 1024,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("runcode2");
        const snapshot = materializeCandidateSnapshot(root, "snap2", "x");
        const executor = createMeasurementExecutor({ allowlist: list, sandboxProvider: null, scratchRoot: root });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.SANDBOX_REQUIRED);
    });

    it("SANDBOX_REFUSED when a provider is supplied but returns {admitted:false}", async () => {
        const root = tmp("refuse");
        const scriptPath = writeHarnessScript(root, "runcode3", `process.stdout.write('{"pass":true}');`);
        const allowlistPath = writeAllowlist(root, "runcode3", {
            argvTemplate: [scriptPath],
            executesCandidateCode: true,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("runcode3");
        const snapshot = materializeCandidateSnapshot(root, "snap3", "x");
        const refuser = createSandboxProvider({
            providerId: "fixture-refuser",
            providerVersion: "v1",
            admitAndPrepare: () => ({
                admitted: false,
                reason: "sandbox quota exhausted",
            }),
        });
        const executor = createMeasurementExecutor({ allowlist: list, sandboxProvider: refuser, scratchRoot: root });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.SANDBOX_REFUSED);
    });
});

describe("executable / allowlist tampering between load and run", () => {
    it("rejects a run when the harness executable was modified after load", async () => {
        const root = tmp("tamperExe");
        const fakeExe = path.join(root, "fake.exe");
        fs.writeFileSync(fakeExe, "original-bytes");
        const { createHash } = await import("node:crypto");
        const originalSha = createHash("sha256").update("original-bytes").digest("hex");
        const allowlistPath = writeAllowlist(root, "e1", {
            executable: fakeExe,
            executableSha256: originalSha,
            argvTemplate: [],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        // Mutate before verifyEntry.
        fs.writeFileSync(fakeExe, "TAMPERED-bytes");
        const err = await catchAsync(async () => list.verifyEntry("e1"));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH);
    });

    it("rejects a run when the allowlist file was modified after load", async () => {
        const root = tmp("tamperAllow");
        const scriptPath = writeHarnessScript(root, "ok", `process.stdout.write('{"pass":true}');`);
        const allowlistPath = writeAllowlist(root, "ok", {
            argvTemplate: [scriptPath],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        fs.appendFileSync(allowlistPath, "\n"); // trivial file-byte change
        const err = await catchAsync(async () => list.verifyEntry("ok"));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_HASH_MISMATCH);
    });
});

describe("path shadowing via symlink / junction", () => {
    it("rejects when the executable is a file symlink (if the platform allows creating one)", async () => {
        if (!canCreateFileSymlink()) return;
        const root = tmp("shadowFile");
        const real = path.join(root, "real.exe");
        fs.writeFileSync(real, "real-bytes");
        const link = path.join(root, "link.exe");
        fs.symlinkSync(real, link, "file");
        const { createHash } = await import("node:crypto");
        const sha = createHash("sha256").update("real-bytes").digest("hex");
        const allowlistPath = writeAllowlist(root, "sh", {
            executable: link,           // <-- symlink, not the real file
            executableSha256: sha,
            argvTemplate: [],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const err = await catchAsync(async () => list.verifyEntry("sh"));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_SYMLINK);
    });

    it("rejects when the executable is inside a shadowed ancestor directory (junction)", async () => {
        if (!canCreateDirJunction()) return;
        const root = tmp("shadowJct");
        const realDir = path.join(root, "real");
        fs.mkdirSync(realDir);
        const realExe = path.join(realDir, "e.bin");
        fs.writeFileSync(realExe, "e-bytes");
        const shadow = path.join(root, "shadow");
        fs.symlinkSync(realDir, shadow, "junction");
        const shadowedExe = path.join(shadow, "e.bin");
        const { createHash } = await import("node:crypto");
        const sha = createHash("sha256").update("e-bytes").digest("hex");
        const allowlistPath = writeAllowlist(root, "shj", {
            executable: shadowedExe,
            executableSha256: sha,
            argvTemplate: [],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const err = await catchAsync(async () => list.verifyEntry("shj"));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.FILE_REPARSE_POINT);
    });
});

describe("output-cap and timeout enforcement", () => {
    it("terminates and reports OUTPUT_OVERFLOW when stdout exceeds the cap", async () => {
        const root = tmp("overflow");
        // Write MANY bytes over the 4 KiB cap; the child should be killed
        // by the executor via the process adapter's tree-terminator.
        const scriptPath = writeHarnessScript(root, "flood", `
            const chunk = "x".repeat(1024);
            for (let i = 0; i < 100; i += 1) {
                process.stdout.write(chunk);
            }
            // Also try to keep writing after a short pause — this proves the
            // termination path is what stops the process, not natural EOF.
            setTimeout(() => process.stdout.write("more"), 200);
        `);
        const allowlistPath = writeAllowlist(root, "flood", {
            argvTemplate: [scriptPath],
            maxStdoutBytes: 4 * 1024,
            timeoutMs: 15000,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("flood");
        const snapshot = materializeCandidateSnapshot(root, "s", "x");
        const executor = createMeasurementExecutor({ allowlist: list, scratchRoot: root });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW);
        expect(err.details.stream).toBe("stdout");
    }, 30000);

    it("terminates and reports TIMEOUT when the harness runs too long", async () => {
        const root = tmp("timeout");
        const scriptPath = writeHarnessScript(root, "hang", `
            // Never write; never exit within the timeout window.
            setInterval(() => {}, 1000);
        `);
        const allowlistPath = writeAllowlist(root, "hang", {
            argvTemplate: [scriptPath],
            timeoutMs: 400,
            maxStdoutBytes: 1024,
            maxStderrBytes: 1024,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("hang");
        const snapshot = materializeCandidateSnapshot(root, "s", "x");
        const executor = createMeasurementExecutor({ allowlist: list, scratchRoot: root });
        const start = Date.now();
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        const elapsed = Date.now() - start;
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.TIMEOUT);
        // Sanity: we should have terminated within a few seconds of the
        // 400ms budget — not waited 15s+.
        expect(elapsed).toBeLessThan(15000);
    }, 30000);
});

describe("harness result rejection surfaces via the executor", () => {
    it("propagates PARSE_MALFORMED when the harness emits garbage on stdout", async () => {
        const root = tmp("malformed");
        const scriptPath = writeHarnessScript(root, "mal", `process.stdout.write("not json at all");`);
        const allowlistPath = writeAllowlist(root, "mal", {
            argvTemplate: [scriptPath],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("mal");
        const snapshot = materializeCandidateSnapshot(root, "s", "x");
        const executor = createMeasurementExecutor({ allowlist: list, scratchRoot: root });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect([
            MEASUREMENT_ERROR_CODES.PARSE_MALFORMED,
            MEASUREMENT_ERROR_CODES.PARSE_SCHEMA,
        ]).toContain(err.code);
    }, 30000);

    it("propagates PARSE_TRAILING when the harness prints valid JSON followed by extra bytes", async () => {
        const root = tmp("trailing");
        const scriptPath = writeHarnessScript(root, "tra", `process.stdout.write('{"pass":true} EXTRA');`);
        const allowlistPath = writeAllowlist(root, "tra", {
            argvTemplate: [scriptPath],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("tra");
        const snapshot = materializeCandidateSnapshot(root, "s", "x");
        const executor = createMeasurementExecutor({ allowlist: list, scratchRoot: root });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_TRAILING);
    }, 30000);

    it("propagates PARSE_SCHEMA when the harness emits a metric that is not a finite number", async () => {
        const root = tmp("nonfinite");
        const scriptPath = writeHarnessScript(root, "nf", `
            // Emit a metric string — JSON has no way to serialise NaN/Infinity
            // as a number, so a real harness would either crash or emit
            // something like "NaN" as a string. Both must be rejected.
            process.stdout.write(JSON.stringify({ pass: true, metrics: { x: "NaN" } }));
        `);
        const allowlistPath = writeAllowlist(root, "nf", {
            argvTemplate: [scriptPath],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("nf");
        const snapshot = materializeCandidateSnapshot(root, "s", "x");
        const executor = createMeasurementExecutor({ allowlist: list, scratchRoot: root });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.PARSE_SCHEMA);
    }, 30000);

    it("propagates NONZERO_EXIT when the harness exits non-zero", async () => {
        const root = tmp("exitcode");
        const scriptPath = writeHarnessScript(root, "boom", `
            process.stderr.write("harness failed hard");
            process.exit(2);
        `);
        const allowlistPath = writeAllowlist(root, "boom", {
            argvTemplate: [scriptPath],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("boom");
        const snapshot = materializeCandidateSnapshot(root, "s", "x");
        const executor = createMeasurementExecutor({ allowlist: list, scratchRoot: root });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.NONZERO_EXIT);
        expect(err.details.exit.code).toBe(2);
    }, 30000);
});

describe("receipt determinism fields survive two identical runs", () => {
    it("projectDeterministicReceipt is byte-equal across two runs with the same inputs", async () => {
        const root = tmp("det");
        const scriptPath = writeHarnessScript(root, "d", `process.stdout.write('{"pass":true,"metrics":{"k":7}}');`);
        const allowlistPath = writeAllowlist(root, "d", {
            argvTemplate: [scriptPath, "{{candidatePath}}"],
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("d");
        const snapshot = materializeCandidateSnapshot(root, "d-snap", "same");

        async function once() {
            const executor = createMeasurementExecutor({
                allowlist: list,
                clock: fixedClock(),
                scratchRoot: root,
            });
            return executor.run({
                verifiedEntry: verified,
                candidateSnapshot: snapshot,
                ...ids(),
            });
        }

        const r1 = await once();
        const r2 = await once();
        expect(projectDeterministicReceipt(r1.receipt))
            .toEqual(projectDeterministicReceipt(r2.receipt));

        // Sanity: changing the snapshot must produce a different
        // deterministic hash.
        const snapshot2 = materializeCandidateSnapshot(root, "d-snap-2", "different");
        const executor = createMeasurementExecutor({
            allowlist: list,
            clock: fixedClock(),
            scratchRoot: root,
        });
        const r3 = await executor.run({
            verifiedEntry: verified,
            candidateSnapshot: snapshot2,
            ...ids(),
        });
        expect(projectDeterministicReceipt(r3.receipt))
            .not.toEqual(projectDeterministicReceipt(r1.receipt));
    }, 30000);
});

describe("adapter tree-termination integration", () => {
    it("invokes processAdapter.terminateTree with an integer PID (not a name) on timeout", async () => {
        const root = tmp("adapter");
        const scriptPath = writeHarnessScript(root, "sleeper", `setInterval(() => {}, 1000);`);
        const allowlistPath = writeAllowlist(root, "sleeper", {
            argvTemplate: [scriptPath],
            timeoutMs: 200,
        });
        const list = loadHarnessAllowlist(allowlistPath);
        const verified = list.verifyEntry("sleeper");
        const snapshot = materializeCandidateSnapshot(root, "s", "x");

        const seen = [];
        const spawn = (executable, argv, options) => {
            // Delegate to the real Node child_process for a real child so
            // the timeout actually fires.
            // eslint-disable-next-line global-require
            const { spawn: rawSpawn } = require_child_process();
            return rawSpawn(executable, argv, {
                cwd: options.cwd,
                env: options.env,
                stdio: ["ignore", "pipe", "pipe"],
                shell: false,
                windowsHide: true,
                detached: true,
            });
        };
        const adapter = {
            spawn,
            terminateTree(pid) {
                seen.push({ type: typeof pid, pid });
                // Do a real kill so the test cleans up.
                try { process.kill(pid); } catch { /* already gone */ }
            },
        };
        const executor = createMeasurementExecutor({
            allowlist: list,
            processAdapter: adapter,
            scratchRoot: root,
        });
        const err = await catchAsync(() => executor.run({
            verifiedEntry: verified, candidateSnapshot: snapshot, ...ids(),
        }));
        expect(err.code).toBe(MEASUREMENT_ERROR_CODES.TIMEOUT);
        // At least one terminateTree call, all with integer pids.
        expect(seen.length).toBeGreaterThan(0);
        for (const call of seen) {
            expect(call.type).toBe("number");
            expect(Number.isInteger(call.pid)).toBe(true);
            expect(call.pid).toBeGreaterThan(0);
        }
    }, 30000);
});

// Local require shim so the adapter-integration test can pull in
// child_process without a top-level import (keeps the module ESM-clean).
import { spawn as _spawn } from "node:child_process";
function require_child_process() { return { spawn: _spawn }; }
