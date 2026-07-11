import { afterAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { threadId } from "node:worker_threads";

import {
    MEASUREMENT_ERROR_CODES,
    WINDOWS_SANDBOX_POLICY_ID,
    WINDOWS_SANDBOX_PRIMITIVE,
    createMeasurementExecutor,
    createWindowsSandboxProvider,
    hashReceipt,
    loadHarnessAllowlist,
    probeWindowsSandboxAvailability,
} from "../measurement/index.mjs";
import {
    fixedIds,
    makeTempRoot,
    materializeCandidateSnapshot,
    rmTempRoot,
    writeAllowlist,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";

const roots = [];
const probeRoot = makeTempRoot("windows-sandbox-probe");
roots.push(probeRoot);
const availability = await probeWindowsSandboxAvailability({
    controlRoot: path.join(probeRoot, "control"),
});

afterAll(() => {
    for (const root of roots.splice(0)) rmTempRoot(root);
});

function makeFixture(label, body, {
    allowedEnv = {},
    clock,
    limits,
    provider,
    providerFactory,
    controlRootAsFile = false,
    processAdapter,
    timeoutMs = 15_000,
} = {}) {
    const root = makeTempRoot(`windows-sandbox-${label}`);
    roots.push(root);
    const script = writeHarnessScript(root, label, body);
    const allowlistPath = writeAllowlist(root, label, {
        argvTemplate: [script, "{{candidatePath}}"],
        allowedEnv,
        executesCandidateCode: true,
        timeoutMs,
    });
    const allowlist = loadHarnessAllowlist(allowlistPath);
    const controlRoot = path.join(root, "control");
    if (controlRootAsFile) {
        fs.writeFileSync(controlRoot, "not a directory");
    }
    const sandboxProvider = provider
        ?? providerFactory?.(controlRoot)
        ?? createWindowsSandboxProvider({
            controlRoot,
            ...(limits === undefined ? {} : { limits }),
        });
    const executor = createMeasurementExecutor({
        allowlist,
        sandboxProvider,
        scratchRoot: path.join(root, "scratch"),
        ...(clock === undefined ? {} : { clock }),
        ...(processAdapter === undefined ? {} : { processAdapter }),
    });
    const snapshot = materializeCandidateSnapshot(
        root,
        `${label}-candidate`,
        "immutable-candidate",
    );
    return {
        root,
        sandboxProvider,
        executor,
        snapshot,
        verifiedEntry: allowlist.verifyEntry(label),
    };
}

async function runFixture(fixture, ids = fixedIds()) {
    return fixture.executor.run({
        verifiedEntry: fixture.verifiedEntry,
        candidateSnapshot: fixture.snapshot,
        ...ids,
    });
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

function ownedSandboxProfiles() {
    const packages = path.join(process.env.LOCALAPPDATA, "Packages");
    if (!fs.existsSync(packages)) return [];
    const prefix =
        `crucible.sandbox.${process.pid}.${threadId}.`.toLowerCase();
    return fs.readdirSync(packages)
        .filter((name) => name.toLowerCase().startsWith(prefix))
        .sort();
}

function expectFixtureCleanup(fixture, beforeProfiles) {
    expect(fs.readdirSync(path.join(fixture.root, "control"))
        .filter((name) => name.startsWith("attempt-"))).toEqual([]);
    expect(ownedSandboxProfiles()).toEqual(beforeProfiles);
}

function cruciblePopupTitles() {
    const powershell = path.join(
        process.env.SystemRoot ?? "C:\\Windows",
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    );
    const result = spawnSync(
        powershell,
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "@(Get-Process | Where-Object { $_.MainWindowTitle -like '*CrucibleWindowsSandbox*' } | ForEach-Object { $_.MainWindowTitle }) | ConvertTo-Json -Compress",
        ],
        {
            encoding: "utf8",
            windowsHide: true,
            timeout: 10_000,
        },
    );
    if (result.status !== 0 || result.stdout.trim().length === 0) return [];
    const parsed = JSON.parse(result.stdout);
    return Array.isArray(parsed) ? parsed : [parsed];
}

function pidAlive(pid) {
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

async function waitForPidExit(pid, timeoutMs = 5_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (!pidAlive(pid)) return true;
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return !pidAlive(pid);
}

describe("Windows sandbox availability", () => {
    it("reports either a proved native boundary or typed unavailability", () => {
        expect(availability.primitive).toBe(WINDOWS_SANDBOX_PRIMITIVE);
        if (!availability.available) {
            expect(availability).toMatchObject({
                available: false,
                code: MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE,
            });
            expect(availability.reason).toEqual(expect.any(String));
            return;
        }
        expect(availability).toMatchObject({
            available: true,
            policyId: WINDOWS_SANDBOX_POLICY_ID,
            probe: {
                appContainer: true,
                lowIntegrity: true,
                zeroCapabilities: true,
                networkDenied: true,
                secretDenied: true,
                registryDenied: true,
                outputWriteAllowed: true,
                jobObjectConfigured: true,
            },
        });
    }, 180_000);

    it("fails closed with typed unavailability before any ordinary spawn", async () => {
        let hostSpawns = 0;
        const fixture = makeFixture("unavailable", `
            process.stdout.write(JSON.stringify({ pass: true }));
        `, {
            controlRootAsFile: true,
            processAdapter: {
                spawn() {
                    hostSpawns += 1;
                    throw new Error("ordinary spawn must not run candidate code");
                },
                terminateTree() {
                    return false;
                },
            },
        });
        await expect(runFixture(fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE,
        });
        expect(hostSpawns).toBe(0);
    });

    it("rejects an expired deadline with no timeout before any helper launch", async () => {
        const root = makeTempRoot("windows-sandbox-expired-deadline");
        roots.push(root);
        const stageRoot = path.join(root, "stage");
        const candidateRoot = path.join(stageRoot, "candidate");
        fs.mkdirSync(candidateRoot, { recursive: true });
        const clock = mutableClock(50_000);
        const helperOperations = [];
        const controlRoot = path.join(root, "control");
        const provider = createWindowsSandboxProvider({
            controlRoot,
            clock,
            testHooks: {
                beforeHelperSpawn(details) {
                    helperOperations.push(details.operation);
                },
            },
        });
        const deadlineMs = clock.now() - 1;

        await expect(provider.admitAndPrepare({
            attemptId: "att-expired-deadline",
            runnerEpochId: "epoch-expired-deadline",
            harnessId: "expired-deadline",
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
        expect(helperOperations).toEqual([]);
        expect(fs.existsSync(controlRoot)).toBe(false);
    });
});

describe.skipIf(!availability.available)("Windows AppContainer containment", () => {
    it("clamps prepare, policy, and helper limits to one deadline budget", async () => {
        const clock = mutableClock(80_000);
        const stages = [];
        let advanced = false;
        const fixture = makeFixture("deadline-stage-bounds", `
            process.stdout.write(JSON.stringify({ pass: true }));
        `, {
            clock,
            providerFactory: (controlRoot) => createWindowsSandboxProvider({
                controlRoot,
                clock,
                testHooks: {
                    beforeHelperSpawn(details) {
                        stages.push({
                            operation: details.operation,
                            timeoutMs: details.timeoutMs,
                        });
                        if (details.operation === "prepare" && !advanced) {
                            advanced = true;
                            clock.advance(2_000);
                        }
                    },
                },
            }),
        });
        await fixture.sandboxProvider.describePolicyIdentity();
        const beforeProfiles = ownedSandboxProfiles();
        const deadlineMs = clock.now() + 10_000;
        const result = await fixture.executor.run({
            verifiedEntry: fixture.verifiedEntry,
            candidateSnapshot: fixture.snapshot,
            ...fixedIds(),
            deadlineMs,
        });

        expect(stages.find(({ operation }) => operation === "prepare"))
            .toEqual({ operation: "prepare", timeoutMs: 10_000 });
        expect(result.receipt.sandbox.policy.effectiveJob.wallTimeMs)
            .toBe(8_000);
        expect(stages.find(({ operation }) => operation === "launch"))
            .toEqual({ operation: "launch", timeoutMs: 8_000 });
        expectFixtureCleanup(fixture, beforeProfiles);
    }, 180_000);

    it("prevents a full measurement from overrunning during prepare", async () => {
        const clock = mutableClock(120_000);
        const helperOperations = [];
        const fixture = makeFixture("deadline-prepare-expiry", `
            process.stdout.write(JSON.stringify({ pass: true }));
        `, {
            clock,
            providerFactory: (controlRoot) => createWindowsSandboxProvider({
                controlRoot,
                clock,
                testHooks: {
                    beforeHelperSpawn(details) {
                        helperOperations.push(details.operation);
                        if (details.operation === "prepare") {
                            clock.advance(1_000);
                        }
                    },
                },
            }),
        });
        await fixture.sandboxProvider.describePolicyIdentity();
        const beforeProfiles = ownedSandboxProfiles();
        const deadlineMs = clock.now() + 1_000;
        const started = Date.now();

        await expect(fixture.executor.run({
            verifiedEntry: fixture.verifiedEntry,
            candidateSnapshot: fixture.snapshot,
            ...fixedIds(),
            deadlineMs,
        })).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.TIMEOUT,
            details: {
                deadlineExceeded: true,
                deadlineMs,
                observedAtMs: deadlineMs,
                stage: "native sandbox preparation",
            },
        });
        expect(Date.now() - started).toBeLessThan(5_000);
        expect(helperOperations).toEqual(["prepare"]);
        expectFixtureCleanup(fixture, beforeProfiles);
    }, 180_000);

    it("keeps the helper binary identity stable across independent control roots", async () => {
        const secondProbeRoot = makeTempRoot("windows-sandbox-second-probe");
        roots.push(secondProbeRoot);
        const second = await probeWindowsSandboxAvailability({
            controlRoot: path.join(secondProbeRoot, "control"),
        });
        expect(second).toMatchObject({
            available: true,
            helperSourceHash: availability.helperSourceHash,
            helperBinaryHash: availability.helperBinaryHash,
            launcherId: availability.launcherId,
            launcherBinaryHash: availability.launcherBinaryHash,
            launcherScriptHash: availability.launcherScriptHash,
        });
    }, 180_000);

    it("reads immutable input and writes only provider-owned output/temp", async () => {
        const fixture = makeFixture("read-write", `
            const candidatePath = process.argv[2];
            const input = fs.readFileSync(
                path.join(candidatePath, "candidate.bin"),
                "utf8",
            );
            const output = path.join(process.env.TEMP, "result.txt");
            fs.writeFileSync(output, input.toUpperCase());
            process.stdout.write(JSON.stringify({
                pass: fs.readFileSync(output, "utf8") === "IMMUTABLE-CANDIDATE",
                metrics: { outputBytes: fs.statSync(output).size },
            }));
        `);
        const beforeProfiles = ownedSandboxProfiles();
        const result = await runFixture(fixture);
        expect(result.parsed).toMatchObject({
            pass: true,
            metrics: { outputBytes: 19 },
        });
        expect(result.receipt.sandbox).toMatchObject({
            providerId: "windows-native-appcontainer",
            providerVersion: "v3",
            policyId: WINDOWS_SANDBOX_POLICY_ID,
            launchPath: "sandbox-capability",
            capabilityLaunchUsed: true,
            policyIdentity: {
                providerId: "windows-native-appcontainer",
                providerVersion: "v3",
                policyId: WINDOWS_SANDBOX_POLICY_ID,
                launcherId: "powershell-loadfrom-no-ui-v1",
                launcherBinaryHash: expect.stringMatching(
                    /^sha256:crucible-windows-native-file-v1:[a-f0-9]{64}$/u,
                ),
                launcherScriptHash: expect.stringMatching(
                    /^sha256:crucible-windows-helper-launcher-script-v1:[a-f0-9]{64}$/u,
                ),
                filesystem: {
                    exactLaunchClosure: true,
                    hostWriteDenied: true,
                },
                job: {
                    activeProcessLimit: 8,
                    processMemoryBytes: 512 * 1024 * 1024,
                    jobMemoryBytes: 768 * 1024 * 1024,
                    cpuRatePercent: 50,
                    cpuTimeMs: 30_000,
                    wallTimeMs: 120_000,
                    terminationGraceMs: 5_000,
                },
            },
            policy: {
                version: 3,
                identity: {
                    providerId: "windows-native-appcontainer",
                    providerVersion: "v3",
                    policyId: WINDOWS_SANDBOX_POLICY_ID,
                },
                effectiveJob: {
                    activeProcessLimit: 8,
                },
            },
        });
        expect(result.receipt.sandbox.policyDigest).toMatch(
            /^sha256:crucible-windows-appcontainer-policy-v3:[a-f0-9]{64}$/u,
        );
        expect(hashReceipt({
            ...result.receipt,
            sandbox: {
                ...result.receipt.sandbox,
                policyDigest:
                    `sha256:crucible-windows-appcontainer-policy-v3:${"0".repeat(64)}`,
            },
        })).not.toBe(hashReceipt(result.receipt));
        expectFixtureCleanup(fixture, beforeProfiles);
    }, 180_000);

    it("denies host secrets, unrelated paths, and candidate mutation", async () => {
        const root = makeTempRoot("windows-sandbox-secrets");
        roots.push(root);
        const hostSecret = path.join(root, "host-secret.txt");
        const unrelated = path.join(root, "unrelated");
        fs.writeFileSync(hostSecret, "file-secret");
        fs.mkdirSync(unrelated);
        fs.writeFileSync(path.join(unrelated, "private.txt"), "private");

        const fixture = makeFixture("deny-secrets", `
                const candidateFile = path.join(
                    process.argv[2],
                    "candidate.bin",
                );
                const denied = (operation) => {
                    try {
                        operation();
                        return false;
                    } catch {
                        return true;
                    }
                };
                const fileSecretDenied = denied(() =>
                    fs.readFileSync(process.env.HOST_SECRET, "utf8"));
                const unrelatedDenied = denied(() =>
                    fs.readdirSync(process.env.UNRELATED_PATH));
                const candidateWriteDenied = denied(() =>
                    fs.writeFileSync(candidateFile, "mutated"));
                process.stdout.write(JSON.stringify({
                    pass: fileSecretDenied
                        && unrelatedDenied
                        && candidateWriteDenied,
                    metrics: {
                        deniedChecks: [
                            fileSecretDenied,
                            unrelatedDenied,
                            candidateWriteDenied,
                        ].filter(Boolean).length,
                    },
                }));
            `, {
                allowedEnv: {
                    HOST_SECRET: hostSecret,
                    UNRELATED_PATH: unrelated,
                },
            });
        const result = await runFixture(fixture);
        expect(result.parsed).toMatchObject({
            pass: true,
            metrics: { deniedChecks: 3 },
        });
        expect(fs.readFileSync(
            path.join(fixture.snapshot.path, "candidate.bin"),
            "utf8",
        )).toBe("immutable-candidate");
    }, 180_000);

    it("denies network even when a reachable host listener exists", async () => {
        let accepted = false;
        const server = net.createServer((socket) => {
            accepted = true;
            socket.destroy();
        });
        await new Promise((resolve, reject) => {
            server.once("error", reject);
            server.listen(0, "127.0.0.1", resolve);
        });
        const address = server.address();
        try {
            const fixture = makeFixture("deny-network", `
                const net = await import("node:net");
                const networkDenied = await new Promise((resolve) => {
                    let settled = false;
                    const finish = (value) => {
                        if (settled) return;
                        settled = true;
                        resolve(value);
                    };
                    let socket;
                    try {
                        socket = net.createConnection({
                            host: "127.0.0.1",
                            port: Number(process.env.TEST_PORT),
                        });
                    } catch {
                        finish(true);
                        return;
                    }
                    socket.once("connect", () => {
                        socket.destroy();
                        finish(false);
                    });
                    socket.once("error", () => finish(true));
                    setTimeout(() => {
                        socket.destroy();
                        finish(true);
                    }, 1500);
                });
                process.stdout.write(JSON.stringify({
                    pass: networkDenied,
                    metrics: { deniedConnections: networkDenied ? 1 : 0 },
                }));
            `, {
                allowedEnv: { TEST_PORT: String(address.port) },
            });
            const result = await runFixture(fixture);
            expect(result.parsed).toMatchObject({
                pass: true,
                metrics: { deniedConnections: 1 },
            });
            expect(accepted).toBe(false);
        } finally {
            await new Promise((resolve) => server.close(resolve));
        }
    }, 180_000);

    it("kills a detached descendant when the root candidate exits", async () => {
        const fixture = makeFixture("kill-descendant", `
            const { spawn } = await import("node:child_process");
            const child = spawn(
                process.execPath,
                ["-e", "setInterval(() => {}, 1000)"],
                {
                    detached: true,
                    stdio: "ignore",
                    windowsHide: true,
                },
            );
            child.unref();
            await new Promise((resolve) => setTimeout(resolve, 250));
            const wasAlive = child.exitCode === null;
            process.stdout.write(JSON.stringify({
                pass: wasAlive,
                metrics: { childPid: child.pid, wasAlive: wasAlive ? 1 : 0 },
            }));
        `);
        const result = await runFixture(fixture);
        expect(result.parsed.pass).toBe(true);
        const childPid = result.parsed.metrics.childPid;
        let alive = true;
        for (let attempt = 0; attempt < 20 && alive; attempt += 1) {
            try {
                process.kill(childPid, 0);
                await new Promise((resolve) => setTimeout(resolve, 100));
            } catch {
                alive = false;
            }
        }
        expect(alive).toBe(false);
    }, 180_000);

    it("rejects a concurrently substituted private helper before launch", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        let mutated = false;
        const fixture = makeFixture("helper-substitution", `
            process.stdout.write(JSON.stringify({ pass: true }));
        `, {
            providerFactory: (controlRoot) => createWindowsSandboxProvider({
                controlRoot,
                testHooks: {
                    beforeHelperSpawn(details) {
                        if (details.operation !== "launch" || mutated) return;
                        mutated = true;
                        fs.chmodSync(details.helperPath, 0o700);
                        fs.appendFileSync(details.helperPath, "substituted");
                    },
                },
            }),
        });
        await expect(runFixture(fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
        });
        expect(mutated).toBe(true);
        expectFixtureCleanup(fixture, beforeProfiles);
    }, 180_000);

    it("terminates the suspended lowbox child when Job assignment fails", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        const fixture = makeFixture("assign-job-failure", `
            process.stdout.write(JSON.stringify({ pass: true }));
        `, {
            providerFactory: (controlRoot) => createWindowsSandboxProvider({
                controlRoot,
                testHooks: {
                    failAssignProcessToJobObject: true,
                },
            }),
        });
        let error;
        try {
            await runFixture(fixture);
        } catch (caught) {
            error = caught;
        }
        expect(error).toMatchObject({
            code: MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
        });
        const match = /CRUCIBLE_TEST_ASSIGN_FAILURE_PID\s+(\d+)/u.exec(
            error.details.stderr,
        );
        expect(match).not.toBeNull();
        const childPid = Number(match[1]);
        expect(await waitForPidExit(childPid)).toBe(true);
        expectFixtureCleanup(fixture, beforeProfiles);
    }, 180_000);

    it("bounds invalid managed-helper startup without visible Windows UI", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        const beforeTitles = cruciblePopupTitles();
        const fixture = makeFixture("invalid-helper-startup", `
            process.stdout.write(JSON.stringify({ pass: true }));
        `, {
            providerFactory: (controlRoot) => createWindowsSandboxProvider({
                controlRoot,
                testHooks: {
                    invalidManagedHelperStartup: true,
                },
            }),
        });
        const started = Date.now();
        let error;
        try {
            await runFixture(fixture);
        } catch (caught) {
            error = caught;
        }
        expect(error).toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_LIFECYCLE,
        });
        expect(error.message).toMatch(/managed helper failed before startup/i);
        expect(Date.now() - started).toBeLessThan(10_000);
        expect(cruciblePopupTitles()).toEqual(beforeTitles);
        expectFixtureCleanup(fixture, beforeProfiles);
    }, 180_000);

    it("enforces Job Object CPU-time limits before the executor timeout", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        const fixture = makeFixture("cpu-limit", `
            let value = 0;
            while (true) value = (value + 1) >>> 0;
        `, {
            limits: {
                cpuRatePercent: 100,
                cpuTimeMs: 300,
                wallTimeMs: 5_000,
            },
            timeoutMs: 12_000,
        });
        const started = Date.now();
        await expect(runFixture(fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
        });
        expect(Date.now() - started).toBeLessThan(15_000);
        expectFixtureCleanup(fixture, beforeProfiles);
    }, 180_000);
});
