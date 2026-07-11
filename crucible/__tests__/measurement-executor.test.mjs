import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { PassThrough } from "node:stream";

import { afterEach, describe, expect, it } from "vitest";

import {
    MEASUREMENT_ERROR_CODES,
    createMeasurementExecutor,
    loadHarnessAllowlist,
} from "../measurement/index.mjs";
import {
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

afterEach(() => {
    const failures = [];
    for (const root of roots.splice(0)) {
        try {
            rmTempRoot(root);
        } catch (error) {
            failures.push(error);
        }
        if (fs.existsSync(root)) {
            failures.push(new Error(`measurement component root survived cleanup: ${root}`));
        }
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "measurement component cleanup failed");
    }
});

function makeFixture(label, entryOverrides = {}) {
    const root = makeTempRoot(`component-${label}`);
    roots.push(root);
    const executable = path.join(root, `${label}.exe`);
    fs.writeFileSync(executable, `synthetic executable ${label}`);
    const script = writeHarnessScript(
        root,
        label,
        `process.stdout.write('{"pass":true}');`,
    );
    const allowlistPath = writeAllowlist(root, label, {
        executable,
        executableSha256: sha256HexOfFile(executable),
        argvTemplate: [script, "{{candidatePath}}"],
        dependencies: [pinnedDependency(script)],
        ...entryOverrides,
    });
    const allowlist = loadHarnessAllowlist(allowlistPath);
    return {
        root,
        allowlist,
        verifiedEntry: allowlist.verifyEntry(label),
        candidateSnapshot: materializeCandidateSnapshot(
            root,
            `${label}-snapshot`,
            "candidate",
        ),
    };
}

function scriptedProcess({
    stdout = [Buffer.from('{"pass":true,"metrics":{"component":1}}', "utf8")],
    stderr = [],
    hang = false,
} = {}) {
    const terminations = [];
    let child = null;
    let closed = false;
    const close = (code, signal) => {
        if (closed || child === null) return;
        closed = true;
        child.stdout.end();
        child.stderr.end();
        setImmediate(() => child.emit("close", code, signal));
    };
    return {
        terminations,
        adapter: {
            spawn() {
                child = new EventEmitter();
                child.pid = 6101;
                child.stdout = new PassThrough();
                child.stderr = new PassThrough();
                if (!hang) {
                    setImmediate(() => {
                        for (const chunk of stdout) child.stdout.write(chunk);
                        for (const chunk of stderr) child.stderr.write(chunk);
                        close(0, null);
                    });
                }
                return child;
            },
            terminateTree(pid) {
                terminations.push(pid);
                close(null, "SIGKILL");
                return true;
            },
        },
    };
}

function runFixture(fixture, process, options = {}) {
    const executor = createMeasurementExecutor({
        allowlist: fixture.allowlist,
        processAdapter: process.adapter,
        scratchRoot: fixture.root,
        clock: manualClock(),
        ...options,
    });
    return executor.run({
        verifiedEntry: fixture.verifiedEntry,
        candidateSnapshot: fixture.candidateSnapshot,
        ...fixedIds(),
    });
}

describe("MeasurementExecutor fast component coverage", () => {
    it("stages, parses, receipts, and removes a synthetic successful launch", async () => {
        const fixture = makeFixture("success");
        const process = scriptedProcess();

        const result = await runFixture(fixture, process);

        expect(result.parsed).toMatchObject({
            pass: true,
            metrics: { component: 1 },
        });
        expect(result.receipt).toMatchObject({
            version: 5,
            exit: { code: 0, signal: null, timedOut: false },
            candidateSnapshotMutationCheck: {
                status: "passed",
            },
        });
        expect(process.terminations).toEqual([]);
        expect(fs.readdirSync(fixture.root)
            .filter((name) => name.startsWith(".crucible-stage-"))).toEqual([]);
    });

    it("terminates and awaits a synthetic process at the executor timeout", async () => {
        const fixture = makeFixture("timeout", { timeoutMs: 10 });
        const process = scriptedProcess({ hang: true });

        await expect(runFixture(fixture, process)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.TIMEOUT,
        });
        expect(process.terminations).toEqual([6101]);
        expect(fs.readdirSync(fixture.root)
            .filter((name) => name.startsWith(".crucible-stage-"))).toEqual([]);
    });

    it("fails closed on finite output overflow and retains exact telemetry", async () => {
        const fixture = makeFixture("overflow", { maxStdoutBytes: 16 });
        const bytes = Buffer.from('{"pass":true} trailing-overflow', "utf8");
        const process = scriptedProcess({ stdout: [bytes] });

        let error;
        try {
            await runFixture(fixture, process);
        } catch (caught) {
            error = caught;
        }

        expect(error).toMatchObject({
            code: MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW,
            details: {
                outputCapture: {
                    stdout: {
                        capBytes: 16,
                        totalObservedBytes: bytes.length,
                        retainedBytes: 16,
                        overflowed: true,
                        truncated: true,
                    },
                },
            },
        });
        expect(process.terminations).toEqual([6101]);
    });
});
