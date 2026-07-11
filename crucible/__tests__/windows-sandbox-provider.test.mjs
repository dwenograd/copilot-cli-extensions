import fs from "node:fs";
import path from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import {
    MEASUREMENT_ERROR_CODES,
    WINDOWS_SANDBOX_LIMITATIONS,
    WINDOWS_SANDBOX_POLICY_ID,
    WINDOWS_SANDBOX_PRIMITIVE,
    createMeasurementExecutor,
    createWindowsSandboxProvider,
    loadHarnessAllowlist,
    probeWindowsSandboxAvailability,
} from "../measurement/index.mjs";
import {
    fixedIds,
    makeTempRoot,
    manualClock,
    materializeCandidateSnapshot,
    pinnedDependency,
    rmTempRoot,
    writeAllowlist,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";

const roots = [];

function tmp(label) {
    const root = makeTempRoot(`windows-provider-${label}`);
    roots.push(root);
    return root;
}

afterAll(() => roots.forEach(rmTempRoot));

describe("Windows sandbox provider safe protocol surface", () => {
    it("publishes immutable policy identity constants", () => {
        expect(WINDOWS_SANDBOX_PRIMITIVE)
            .toBe("windows-appcontainer-lowbox+job-object");
        expect(WINDOWS_SANDBOX_POLICY_ID)
            .toBe("windows-appcontainer-lowbox-job-v3");
        expect(Object.isFrozen(WINDOWS_SANDBOX_LIMITATIONS)).toBe(true);
        expect(WINDOWS_SANDBOX_LIMITATIONS.length).toBeGreaterThan(0);
    });

    it("rejects unknown provider options instead of accepting test hooks", () => {
        expect(() => createWindowsSandboxProvider({
            unsupported: true,
        })).toThrow(expect.objectContaining({
            code: MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
        }));
    });

    it("reports typed unavailability for a test-owned non-directory control root", async () => {
        const root = tmp("control-file");
        const controlRoot = path.join(root, "control");
        fs.writeFileSync(controlRoot, "test-owned sentinel");

        const availability = await probeWindowsSandboxAvailability({
            controlRoot,
        });

        expect(availability).toMatchObject({
            available: false,
            code: MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE,
            primitive: WINDOWS_SANDBOX_PRIMITIVE,
        });
        expect(fs.readFileSync(controlRoot, "utf8"))
            .toBe("test-owned sentinel");
    });

    it("fails closed before an ordinary host spawn when unavailable", async () => {
        const root = tmp("no-fallback");
        const controlRoot = path.join(root, "control");
        fs.writeFileSync(controlRoot, "not a directory");
        const script = writeHarnessScript(
            root,
            "no-fallback",
            `process.stdout.write('{"pass":true}');`,
        );
        const allowlistPath = writeAllowlist(root, "no-fallback", {
            argvTemplate: [script, "{{candidatePath}}"],
            dependencies: [pinnedDependency(script)],
            executesCandidateCode: true,
        });
        const allowlist = loadHarnessAllowlist(allowlistPath);
        let hostSpawns = 0;
        const executor = createMeasurementExecutor({
            allowlist,
            sandboxProvider: createWindowsSandboxProvider({ controlRoot }),
            scratchRoot: path.join(root, "scratch"),
            processAdapter: {
                spawn() {
                    hostSpawns += 1;
                    throw new Error("host fallback is forbidden");
                },
                terminateTree() {
                    return false;
                },
            },
        });

        await expect(executor.run({
            verifiedEntry: allowlist.verifyEntry("no-fallback"),
            candidateSnapshot: materializeCandidateSnapshot(
                root,
                "no-fallback-snapshot",
                "candidate",
            ),
            ...fixedIds(),
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE,
        });
        expect(hostSpawns).toBe(0);
    });

    it("rejects an expired deadline before creating or launching helpers", async () => {
        const root = tmp("deadline");
        const stageRoot = path.join(root, "stage");
        const candidateRoot = path.join(stageRoot, "candidate");
        fs.mkdirSync(candidateRoot, { recursive: true });
        const controlRoot = path.join(root, "control");
        const clock = manualClock("1970-01-01T00:00:50.000Z");
        const provider = createWindowsSandboxProvider({
            controlRoot,
            clock,
        });
        const deadlineMs = clock.now() - 1;

        await expect(provider.admitAndPrepare({
            attemptId: "att-expired",
            runnerEpochId: "epoch-expired",
            harnessId: "expired",
            verifiedEntry: {},
            candidateSnapshot: {
                path: candidateRoot,
                hash: `sha256:test:${"a".repeat(64)}`,
            },
            stagedRoots: [stageRoot],
            launch: { deadlineMs },
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.TIMEOUT,
            details: {
                deadlineExceeded: true,
                deadlineMs,
                observedAtMs: clock.now(),
                stage: "native sandbox preparation",
            },
        });
        expect(fs.existsSync(controlRoot)).toBe(false);
    });
});
