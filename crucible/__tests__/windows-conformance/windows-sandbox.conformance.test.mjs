import { spawn as rawSpawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
    afterAll,
    afterEach,
    beforeAll,
    beforeEach,
    describe,
    expect,
    it,
} from "vitest";

import {
    MEASUREMENT_ERROR_CODES,
    WINDOWS_SANDBOX_POLICY_ID,
    createMeasurementExecutor,
    createWindowsSandboxProvider,
    loadHarnessAllowlist,
} from "../../measurement/index.mjs";
import { MEASUREMENT_LIFECYCLE_ADAPTER } from "../../measurement/private-adapters.mjs";
import {
    fixedIds,
    makeTempRoot,
    materializeCandidateSnapshot,
    pinnedDependency,
    rmTempRoot,
    writeAllowlist,
    writeHarnessScript,
} from "../measurement-fixtures.mjs";
import {
    ConformanceResources,
    createRegistrySecret,
    listOwnedProfiles,
    listProviderScratch,
    readRegistrySecret,
    removeOwnedRegistryBaseIfEmpty,
    removeOwnedRegistryRoot,
    waitForPidExit,
} from "./conformance-fixtures.mjs";

const runToken =
    `${process.pid}-${randomBytes(8).toString("hex")}`.toLowerCase();
const registryRoot =
    `HKCU\\Software\\CrucibleSandboxConformance\\${runToken}`;
const suiteRoot = makeTempRoot(`windows-conformance-${runToken}`);
const controlRoot = path.join(suiteRoot, "control");
const suiteProfileBaseline = listOwnedProfiles();
let provider;
let resources;
let attemptCounter = 0;

function safeLabel(value) {
    return value.toLowerCase()
        .replace(/[^a-z0-9._-]+/gu, "-")
        .slice(0, 80);
}

function rejectingHostAdapter() {
    return {
        spawn() {
            throw new Error("native conformance forbids host fallback");
        },
        terminateTree() {
            throw new Error("native conformance forbids host termination");
        },
    };
}

function makeFixture(label, body, {
    allowedEnv = {},
    maxStdoutBytes,
    onHarnessExit,
    prepareRoot,
    sandboxLimits,
    timeoutMs = 15_000,
} = {}) {
    const safe = safeLabel(label);
    const root = resources.trackRoot(
        makeTempRoot(`windows-conformance-${safe}`),
    );
    const prepared = prepareRoot?.(root) ?? {};
    const script = writeHarnessScript(root, safe, body);
    const entryId = `conformance-${safe}`;
    const allowlistPath = writeAllowlist(root, entryId, {
        argvTemplate: [script, "{{candidatePath}}"],
        dependencies: [pinnedDependency(script)],
        allowedEnv: {
            ...allowedEnv,
            ...(prepared.allowedEnv ?? {}),
        },
        executesCandidateCode: true,
        timeoutMs,
        ...(maxStdoutBytes === undefined ? {} : { maxStdoutBytes }),
    });
    const allowlist = loadHarnessAllowlist(allowlistPath);
    const snapshot = materializeCandidateSnapshot(
        root,
        `${safe}-snapshot`,
        "immutable-candidate",
    );
    attemptCounter += 1;
    const ids = {
        ...fixedIds(),
        attemptId: `att-conformance-${attemptCounter}`,
    };
    const scratchRoot = path.join(root, "scratch");
    resources.trackEphemeralRoot(
        path.join(scratchRoot, `.crucible-stage-${ids.attemptId}`),
    );
    resources.trackAclTree(root);
    const fixtureProvider = sandboxLimits === undefined
        ? provider
        : createWindowsSandboxProvider({
            controlRoot,
            limits: sandboxLimits,
        });
    const executor = createMeasurementExecutor({
        allowlist,
        sandboxProvider: fixtureProvider,
        processAdapter: rejectingHostAdapter(),
        scratchRoot,
        [MEASUREMENT_LIFECYCLE_ADAPTER]: {
            afterHarnessStaging(details) {
                resources.trackEphemeralRoot(details.stageRoot);
            },
            afterHarnessLaunch(details) {
                resources.trackPid(details.pid);
            },
            async afterHarnessExit(details) {
                await onHarnessExit?.(details);
            },
        },
    });
    return {
        allowlist,
        entryId,
        executor,
        ids,
        prepared,
        root,
        snapshot,
    };
}

function runFixture(fixture) {
    return fixture.executor.run({
        verifiedEntry: fixture.allowlist.verifyEntry(fixture.entryId),
        candidateSnapshot: fixture.snapshot,
        ...fixture.ids,
    });
}

function listen(server, target) {
    return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(target, resolve);
    });
}

function closeServer(server) {
    return new Promise((resolve) => {
        if (!server.listening) {
            resolve();
            return;
        }
        server.close(resolve);
    });
}

beforeAll(async () => {
    if (process.env.CRUCIBLE_WINDOWS_CONFORMANCE !== "1") {
        throw new Error(
            "Windows conformance must run through the explicit serial job",
        );
    }
    if (process.platform !== "win32") {
        const error = new Error(
            `typed unavailability: ${MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE} on ${process.platform}`,
        );
        error.code = MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE;
        throw error;
    }

    provider = createWindowsSandboxProvider({ controlRoot });
    try {
        const identity = await provider.describePolicyIdentity();
        expect(identity).toMatchObject({
            policyId: WINDOWS_SANDBOX_POLICY_ID,
            securityContext: {
                appContainer: true,
                lowIntegrity: true,
                capabilities: [],
                loopbackExemptionRejected: true,
            },
        });
    } catch (error) {
        if (error?.code === MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE) {
            throw new Error(
                `Windows conformance unavailable: ${error.code}: ${error.message}`,
                { cause: error },
            );
        }
        throw error;
    }
    expect(listProviderScratch(controlRoot)).toEqual([]);
    expect(listOwnedProfiles()).toEqual(suiteProfileBaseline);
}, 180_000);

beforeEach(() => {
    resources = new ConformanceResources(controlRoot);
});

afterEach(async () => {
    await resources.cleanupAndAssert();
}, 60_000);

afterAll(() => {
    const failures = [];
    try {
        removeOwnedRegistryRoot(registryRoot);
        removeOwnedRegistryBaseIfEmpty();
    } catch (error) {
        failures.push(error);
    }
    try {
        rmTempRoot(suiteRoot);
    } catch (error) {
        failures.push(error);
    }
    if (fs.existsSync(suiteRoot)) {
        failures.push(new Error(`conformance suite root survived cleanup: ${suiteRoot}`));
    }
    const profiles = listOwnedProfiles();
    if (JSON.stringify(profiles) !== JSON.stringify(suiteProfileBaseline)) {
        failures.push(new Error(
            `conformance AppContainer profiles changed: before=${
                JSON.stringify(suiteProfileBaseline)
            } after=${JSON.stringify(profiles)}`,
        ));
    }
    if (failures.length > 0) {
        throw new AggregateError(failures, "Windows conformance suite cleanup failed");
    }
}, 60_000);

describe.sequential("Windows native containment conformance", () => {
    it("executes a positive contained measurement", async () => {
        const fixture = makeFixture("positive", `
            const candidate = process.argv[2];
            const input = fs.readFileSync(
                path.join(candidate, "candidate.bin"),
                "utf8",
            );
            const output = path.join(process.env.TEMP, "positive.txt");
            fs.writeFileSync(output, input.toUpperCase());
            process.stdout.write(JSON.stringify({
                pass: fs.readFileSync(output, "utf8")
                    === "IMMUTABLE-CANDIDATE",
                metrics: { outputBytes: fs.statSync(output).size },
            }));
        `);

        const result = await runFixture(fixture);

        expect(result.parsed).toMatchObject({
            pass: true,
            metrics: { outputBytes: 19 },
        });
        expect(result.receipt.sandbox).toMatchObject({
            providerId: "windows-native-appcontainer",
            policyId: WINDOWS_SANDBOX_POLICY_ID,
            launchPath: "sandbox-capability",
            capabilityLaunchUsed: true,
        });
        expect(result.receipt.exit.timedOut).toBe(false);
    }, 180_000);

    it("denies only synthetic files, registry, and candidate writes", async () => {
        const registryKey =
            resources.trackRegistryKey(`${registryRoot}\\synthetic-secret`);
        createRegistrySecret(registryKey, "synthetic-registry-secret");
        const regExe = path.join(
            process.env.SystemRoot ?? "C:\\Windows",
            "System32",
            "reg.exe",
        );
        const fixture = makeFixture("synthetic-secrets", `
            const { spawn } = await import("node:child_process");
            const explicitDenied = (operation) => {
                try {
                    operation();
                    return { denied: false, errno: 0 };
                } catch (error) {
                    const numeric = Number(error?.errno);
                    return {
                        denied: true,
                        errno: Number.isFinite(numeric)
                            ? Math.abs(numeric)
                            : 1,
                    };
                }
            };
            const file = explicitDenied(() =>
                fs.readFileSync(process.env.SYNTHETIC_SECRET, "utf8"));
            const outsideWrite = explicitDenied(() =>
                fs.writeFileSync(process.env.OUTSIDE_FILE, "changed"));
            const candidateFile = path.join(
                process.env.CANDIDATE_SNAPSHOT_PATH,
                "candidate.bin",
            );
            const candidateWrite = explicitDenied(() =>
                fs.writeFileSync(candidateFile, "changed"));
            const candidateAds = explicitDenied(() =>
                fs.writeFileSync(candidateFile + ":conformance", "changed"));
            const outsideAds = explicitDenied(() =>
                fs.writeFileSync(
                    process.env.OUTSIDE_FILE + ":conformance",
                    "changed",
                ));
            const candidateHardLink = explicitDenied(() =>
                fs.linkSync(
                    candidateFile,
                    path.join(process.env.TEMP, "candidate-hardlink.bin"),
                ));
            const outsideHardLink = explicitDenied(() =>
                fs.linkSync(
                    process.env.OUTSIDE_FILE,
                    path.join(process.env.TEMP, "outside-hardlink.txt"),
                ));
            const registry = await new Promise((resolve) => {
                let child;
                let settled = false;
                const finish = (value) => {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timer);
                    resolve(value);
                };
                const timer = setTimeout(() => {
                    try { child?.kill(); } catch {}
                    finish({
                        status: null,
                        timedOut: true,
                        spawnError: false,
                    });
                }, 2500);
                try {
                    child = spawn(
                        process.env.REG_EXE,
                        ["QUERY", process.env.REG_KEY, "/v", "Secret"],
                        {
                            stdio: "ignore",
                            windowsHide: true,
                            shell: false,
                        },
                    );
                } catch {
                    finish({
                        status: null,
                        timedOut: false,
                        spawnError: true,
                    });
                    return;
                }
                child.once("error", () => finish({
                    status: null,
                    timedOut: false,
                    spawnError: true,
                }));
                child.once("close", (status) => finish({
                    status,
                    timedOut: false,
                    spawnError: false,
                }));
            });
            const pass = file.denied
                && file.errno > 0
                && outsideWrite.denied
                && outsideWrite.errno > 0
                && candidateWrite.denied
                && candidateWrite.errno > 0
                && candidateAds.denied
                && candidateAds.errno > 0
                && outsideAds.denied
                && outsideAds.errno > 0
                && candidateHardLink.denied
                && candidateHardLink.errno > 0
                && outsideHardLink.denied
                && outsideHardLink.errno > 0
                && registry.timedOut === false
                && registry.spawnError === false
                && Number.isInteger(registry.status)
                && registry.status !== 0;
            process.stdout.write(JSON.stringify({
                pass,
                metrics: {
                    fileDenied: file.denied ? 1 : 0,
                    fileErrno: file.errno,
                    outsideWriteDenied: outsideWrite.denied ? 1 : 0,
                    outsideWriteErrno: outsideWrite.errno,
                    candidateWriteDenied: candidateWrite.denied ? 1 : 0,
                    candidateWriteErrno: candidateWrite.errno,
                    candidateAdsDenied: candidateAds.denied ? 1 : 0,
                    candidateAdsErrno: candidateAds.errno,
                    outsideAdsDenied: outsideAds.denied ? 1 : 0,
                    outsideAdsErrno: outsideAds.errno,
                    candidateHardLinkDenied:
                        candidateHardLink.denied ? 1 : 0,
                    candidateHardLinkErrno: candidateHardLink.errno,
                    outsideHardLinkDenied:
                        outsideHardLink.denied ? 1 : 0,
                    outsideHardLinkErrno: outsideHardLink.errno,
                    registryTimedOut: registry.timedOut ? 1 : 0,
                    registrySpawnError: registry.spawnError ? 1 : 0,
                    registryStatus: registry.status ?? -1,
                },
            }));
        `, {
            allowedEnv: {
                REG_EXE: regExe,
                REG_KEY: registryKey,
            },
            prepareRoot(root) {
                const hostOnly = path.join(root, "host-only");
                fs.mkdirSync(hostOnly);
                const secret = path.join(hostOnly, "secret.txt");
                const outside = path.join(hostOnly, "outside.txt");
                fs.writeFileSync(secret, "synthetic-file-secret");
                fs.writeFileSync(outside, "host-sentinel");
                return {
                    allowedEnv: {
                        SYNTHETIC_SECRET: secret,
                        OUTSIDE_FILE: outside,
                    },
                    outside,
                    secret,
                };
            },
        });

        const result = await runFixture(fixture);

        expect(result.parsed.pass).toBe(true);
        expect(result.parsed.metrics).toMatchObject({
            fileDenied: 1,
            outsideWriteDenied: 1,
            candidateWriteDenied: 1,
            candidateAdsDenied: 1,
            outsideAdsDenied: 1,
            candidateHardLinkDenied: 1,
            outsideHardLinkDenied: 1,
            registryTimedOut: 0,
            registrySpawnError: 0,
        });
        expect(fs.readFileSync(fixture.prepared.secret, "utf8"))
            .toBe("synthetic-file-secret");
        expect(fs.readFileSync(fixture.prepared.outside, "utf8"))
            .toBe("host-sentinel");
        expect(readRegistrySecret(registryKey))
            .toBe("synthetic-registry-secret");
        expect(fs.existsSync(`${fixture.prepared.outside}:conformance`))
            .toBe(false);
    }, 180_000);

    it("attests network isolation and explicitly denies a test-owned named pipe", async () => {
        let tcpAccepted = 0;
        let pipeAccepted = 0;
        const tcpServer = net.createServer((socket) => {
            tcpAccepted += 1;
            socket.destroy();
        });
        const pipeServer = net.createServer((socket) => {
            pipeAccepted += 1;
            socket.destroy();
        });
        await listen(tcpServer, { host: "127.0.0.1", port: 0 });
        const tcpAddress = tcpServer.address();
        const pipeName =
            `\\\\.\\pipe\\crucible-conformance-${runToken}-${attemptCounter}`;
        await listen(pipeServer, pipeName);
        resources.trackCleanup(() => closeServer(tcpServer));
        resources.trackCleanup(() => closeServer(pipeServer));

        const fixture = makeFixture("network-pipe", `
            const net = await import("node:net");
            const connectOutcome = (target) =>
                new Promise((resolve) => {
                    let socket;
                    let settled = false;
                    const finish = (kind, errno = 0) => {
                        if (settled) return;
                        settled = true;
                        clearTimeout(timer);
                        socket?.destroy();
                        resolve({ kind, errno });
                    };
                    const timer = setTimeout(
                        () => finish("timeout"),
                        2000,
                    );
                    try {
                        socket = net.createConnection(target);
                    } catch (error) {
                        const numeric = Number(error?.errno);
                        finish(
                            "error",
                            Number.isFinite(numeric)
                                ? Math.abs(numeric)
                                : 1,
                        );
                        return;
                    }
                    socket.once("connect", () => finish("connected"));
                    socket.once("error", (error) => {
                        const numeric = Number(error?.errno);
                        finish(
                            "error",
                            Number.isFinite(numeric)
                                ? Math.abs(numeric)
                                : 1,
                        );
                    });
                });
            const tcp = await connectOutcome({
                host: "127.0.0.1",
                port: Number(process.env.TCP_PORT),
            });
            const pipe = await connectOutcome(process.env.PIPE_NAME);
            const pass = pipe.kind === "error"
                && pipe.errno > 0;
            process.stdout.write(JSON.stringify({
                pass,
                metrics: {
                    tcpDenied: tcp.kind === "error" ? 1 : 0,
                    tcpTimedOut: tcp.kind === "timeout" ? 1 : 0,
                    tcpConnected: tcp.kind === "connected" ? 1 : 0,
                    tcpErrno: tcp.errno,
                    pipeDenied: pipe.kind === "error" ? 1 : 0,
                    pipeTimedOut: pipe.kind === "timeout" ? 1 : 0,
                    pipeConnected: pipe.kind === "connected" ? 1 : 0,
                    pipeErrno: pipe.errno,
                },
            }));
        `, {
            allowedEnv: {
                TCP_PORT: String(tcpAddress.port),
                PIPE_NAME: pipeName,
            },
        });

        const result = await runFixture(fixture);

        expect(result.parsed).toMatchObject({
            pass: true,
            metrics: {
                tcpConnected: 0,
                pipeDenied: 1,
                pipeTimedOut: 0,
                pipeConnected: 0,
            },
        });
        expect(result.receipt.sandbox.policyIdentity.securityContext)
            .toMatchObject({
                capabilities: [],
                loopbackExemptionRejected: true,
            });
        expect(
            result.parsed.metrics.tcpDenied
            + result.parsed.metrics.tcpTimedOut,
        ).toBe(1);
        expect(tcpAccepted).toBe(0);
        expect(pipeAccepted).toBe(0);
    }, 180_000);

    it("enforces the active-process cap with a fixed test-owned child set", async () => {
        const fixture = makeFixture("active-process-cap", `
            const { spawn } = await import("node:child_process");
            const children = [];
            const attempted = 6;
            for (let index = 0; index < attempted; index += 1) {
                try {
                    const child = spawn(
                        process.execPath,
                        ["-e", "setTimeout(() => {}, 60000)"],
                        {
                            detached: false,
                            stdio: "ignore",
                            windowsHide: true,
                            shell: false,
                        },
                    );
                    child.on("error", () => {});
                    child.unref();
                    children.push(child);
                } catch {
                    children.push(null);
                }
            }
            await new Promise((resolve) => setTimeout(resolve, 750));
            const alive = children.filter((child) =>
                child !== null
                && Number.isSafeInteger(child.pid)
                && child.pid > 0
                && child.exitCode === null
                && child.signalCode === null);
            const metrics = {
                activeProcessLimit: 3,
                attempted,
                alive: alive.length,
                denied: attempted - alive.length,
                survivorPid0: alive[0]?.pid ?? 0,
                survivorPid1: alive[1]?.pid ?? 0,
            };
            process.stdout.write(JSON.stringify({
                pass: metrics.alive <= 2 && metrics.denied >= 1,
                metrics,
            }));
        `, {
            sandboxLimits: {
                activeProcessLimit: 3,
                cpuRatePercent: 100,
            },
        });

        const result = await runFixture(fixture);
        const telemetry = result.parsed.metrics;
        for (const field of ["survivorPid0", "survivorPid1"]) {
            if (telemetry[field] > 0) {
                resources.trackPid(telemetry[field]);
                expect(await waitForPidExit(telemetry[field])).toBe(true);
            }
        }
        expect(result.parsed.pass).toBe(true);
        expect(telemetry).toMatchObject({
            activeProcessLimit: 3,
            attempted: 6,
        });
        expect(telemetry.alive).toBeLessThanOrEqual(2);
        expect(telemetry.denied).toBeGreaterThanOrEqual(1);
        expect(result.receipt.sandbox.policy.effectiveJob.activeProcessLimit)
            .toBe(3);
    }, 180_000);

    it("enforces fixed-size process and aggregate Job memory caps", async () => {
        const processLimits = {
            activeProcessLimit: 3,
            processMemoryBytes: 192 * 1024 * 1024,
            jobMemoryBytes: 512 * 1024 * 1024,
            cpuRatePercent: 100,
            wallTimeMs: 10_000,
        };
        const processFixture = makeFixture("process-memory-cap", `
            await new Promise((resolve) =>
                process.stderr.write(
                    "CRUCIBLE_PROCESS_MEMORY_CAP_BEGIN\\n",
                    resolve,
                ));
            const allocations = [];
            for (let index = 0; index < 24; index += 1) {
                allocations.push(Buffer.alloc(16 * 1024 * 1024, 0x5a));
            }
            process.stdout.write(JSON.stringify({
                pass: false,
                metrics: { allocatedMiB: 384 },
            }));
        `, {
            sandboxLimits: processLimits,
            timeoutMs: 20_000,
        });
        const processStartedAt = Date.now();
        let processError;
        try {
            await runFixture(processFixture);
        } catch (caught) {
            processError = caught;
        }
        expect(processError).toMatchObject({
            code: MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
            details: {
                stderr: expect.stringContaining(
                    "CRUCIBLE_PROCESS_MEMORY_CAP_BEGIN",
                ),
                receipt: {
                    sandbox: {
                        policy: {
                            effectiveJob: {
                                processMemoryBytes:
                                    processLimits.processMemoryBytes,
                                jobMemoryBytes:
                                    processLimits.jobMemoryBytes,
                            },
                        },
                    },
                },
            },
        });
        expect(processError.details.exit.code).not.toBe(124);
        expect(Date.now() - processStartedAt).toBeLessThan(15_000);

        const jobLimits = {
            activeProcessLimit: 4,
            processMemoryBytes: 320 * 1024 * 1024,
            jobMemoryBytes: 320 * 1024 * 1024,
            cpuRatePercent: 100,
            wallTimeMs: 15_000,
        };
        const jobFixture = makeFixture("job-memory-cap", `
            const { spawn } = await import("node:child_process");
            await new Promise((resolve) =>
                process.stderr.write(
                    "CRUCIBLE_JOB_MEMORY_CAP_PARENT_BEGIN\\n",
                    resolve,
                ));
            const records = [];
            const childCode = [
                "process.stderr.write('CRUCIBLE_JOB_MEMORY_CAP_CHILD_BEGIN\\\\n');",
                "const allocations=[];",
                "for(let i=0;i<14;i+=1){allocations.push(Buffer.alloc(16*1024*1024,0x4b));}",
                "setTimeout(()=>{},60000);",
            ].join("");
            for (let index = 0; index < 2; index += 1) {
                const record = {
                    child: null,
                    code: null,
                    signal: null,
                    error: false,
                };
                try {
                    record.child = spawn(
                        process.execPath,
                        ["-e", childCode],
                        {
                            stdio: "ignore",
                            windowsHide: true,
                            shell: false,
                        },
                    );
                    record.child.on("error", () => {
                        record.error = true;
                    });
                    record.child.on("close", (code, signal) => {
                        record.code = code;
                        record.signal = signal;
                    });
                    record.child.unref();
                } catch {
                    record.error = true;
                }
                records.push(record);
            }
            await new Promise((resolve) => setTimeout(resolve, 5_000));
            const aliveBeforeCleanup = records.filter((record) =>
                record.child !== null
                && Number.isSafeInteger(record.child.pid)
                && record.child.exitCode === null
                && record.child.signalCode === null).length;
            const failed = records.filter((record) =>
                record.error
                || record.code !== null
                || record.signal !== null).length;
            for (const record of records) {
                if (record.child !== null
                    && record.child.exitCode === null
                    && record.child.signalCode === null) {
                    try { record.child.kill(); } catch {}
                }
            }
            process.stdout.write(JSON.stringify({
                pass: failed >= 1 && aliveBeforeCleanup <= 1,
                metrics: {
                    attempted: 2,
                    failed,
                    aliveBeforeCleanup,
                    started: records.filter((record) =>
                        Number.isSafeInteger(record.child?.pid)).length,
                },
            }));
        `, {
            sandboxLimits: jobLimits,
            timeoutMs: 20_000,
        });
        const jobStartedAt = Date.now();
        let jobResult;
        let jobError;
        try {
            jobResult = await runFixture(jobFixture);
        } catch (caught) {
            jobError = caught;
        }
        const jobReceipt = jobResult?.receipt ?? jobError?.details?.receipt;
        expect(jobReceipt.sandbox.policy.effectiveJob).toMatchObject({
            processMemoryBytes: jobLimits.processMemoryBytes,
            jobMemoryBytes: jobLimits.jobMemoryBytes,
        });
        if (jobError !== undefined) {
            expect(jobError).toMatchObject({
                code: MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
                details: {
                    stderr: expect.stringContaining(
                        "CRUCIBLE_JOB_MEMORY_CAP_PARENT_BEGIN",
                    ),
                },
            });
            expect(jobError.details.exit.code).not.toBe(124);
        } else {
            expect(jobResult.parsed).toMatchObject({
                pass: true,
                metrics: {
                    attempted: 2,
                    failed: expect.any(Number),
                    aliveBeforeCleanup: expect.any(Number),
                    started: expect.any(Number),
                },
            });
            expect(jobResult.parsed.metrics.failed).toBeGreaterThanOrEqual(1);
            expect(jobResult.parsed.metrics.aliveBeforeCleanup)
                .toBeLessThanOrEqual(1);
        }
        expect(Date.now() - jobStartedAt).toBeLessThan(15_000);
    }, 180_000);

    it("enforces native wall time before the executor timeout", async () => {
        let exitTelemetry = null;
        const fixture = makeFixture("native-wall-time", `
            await new Promise((resolve) =>
                process.stderr.write("CRUCIBLE_NATIVE_WALL_BEGIN\\n", resolve));
            setTimeout(() => {}, 60000);
        `, {
            onHarnessExit(details) {
                exitTelemetry = details;
            },
            sandboxLimits: {
                cpuRatePercent: 100,
                cpuTimeMs: 30_000,
                wallTimeMs: 3_000,
            },
            timeoutMs: 15_000,
        });

        const startedAt = Date.now();
        let error;
        try {
            await runFixture(fixture);
        } catch (caught) {
            error = caught;
        }

        expect(error).toMatchObject({
            code: MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
            details: {
                exit: { code: 124, signal: null },
                stderr: expect.stringContaining("CRUCIBLE_NATIVE_WALL_BEGIN"),
                receipt: {
                    sandbox: {
                        policy: {
                            effectiveJob: {
                                wallTimeMs: expect.any(Number),
                            },
                        },
                    },
                },
            },
        });
        expect(error.details.receipt.sandbox.policy.effectiveJob.wallTimeMs)
            .toBeLessThanOrEqual(3_000);
        expect(exitTelemetry).toMatchObject({
            exit: { code: 124, signal: null },
            timedOut: false,
            overflowStreams: [],
        });
        expect(Date.now() - startedAt).toBeLessThan(12_000);
    }, 180_000);

    it("kills tracked descendants and cleans native state after failure", async () => {
        const fixture = makeFixture("failure-cleanup", `
            const { spawn } = await import("node:child_process");
            const child = spawn(
                process.execPath,
                ["-e", "setTimeout(() => {}, 60000)"],
                {
                    detached: true,
                    stdio: "ignore",
                    windowsHide: true,
                    shell: false,
                },
            );
            child.unref();
            process.stderr.write(
                "CRUCIBLE_CHILD_PID=" + child.pid + "\\n",
                () => setTimeout(() => process.exit(7), 100),
            );
        `);

        let error;
        try {
            await runFixture(fixture);
        } catch (caught) {
            error = caught;
        }

        expect(error).toMatchObject({
            code: MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
            details: {
                exit: { code: 7, signal: null },
            },
        });
        const match = /CRUCIBLE_CHILD_PID=(\d+)/u.exec(error.details.stderr);
        expect(match).not.toBeNull();
        const childPid = resources.trackPid(Number(match[1]));
        expect(await waitForPidExit(childPid)).toBe(true);
        expect(listProviderScratch(controlRoot)).toEqual([]);
    }, 180_000);

    it("enforces output bounds with a finite fixture and cleans the Job", async () => {
        const fixture = makeFixture("bounded-output", `
            const chunk = "x".repeat(16 * 1024);
            for (let index = 0; index < 8; index += 1) {
                process.stdout.write(chunk);
            }
        `, {
            maxStdoutBytes: 4 * 1024,
        });

        await expect(runFixture(fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW,
            details: {
                stream: "stdout",
            },
        });
        expect(listProviderScratch(controlRoot)).toEqual([]);
    }, 180_000);

    it("closes the Job Object when the owning adapter parent dies", async () => {
        const root = resources.trackRoot(
            makeTempRoot("windows-conformance-parent-death"),
        );
        const candidatePidPath = path.join(root, "candidate.pid");
        const ownerPidPath = path.join(root, "owner.pid");
        const harnessPath = path.join(root, "linger.mjs");
        const parentPath = path.join(root, "parent.mjs");
        fs.writeFileSync(harnessPath, `
            import fs from "node:fs";
            fs.writeFileSync(
                ${JSON.stringify(candidatePidPath)},
                String(process.pid),
            );
            setTimeout(() => {}, 60000);
        `);
        const adapterUrl = pathToFileURL(path.join(
            suiteRoot,
            "..",
            "..",
            "measurement",
            "windows-adapter.mjs",
        )).href;
        fs.writeFileSync(parentPath, `
            import fs from "node:fs";
            import { createDefaultProcessAdapter } from ${JSON.stringify(adapterUrl)};
            const adapter = createDefaultProcessAdapter();
            const child = adapter.spawn(
                process.execPath,
                [${JSON.stringify(harnessPath)}],
                {
                    cwd: ${JSON.stringify(root)},
                    env: { SystemRoot: process.env.SystemRoot },
                    stdio: ["ignore", "pipe", "pipe"],
                    executesCandidateCode: false,
                    launchPath: "host-process-adapter",
                    timeoutMs: 60000,
                    ownerRoot: ${JSON.stringify(root)},
                },
            );
            fs.writeFileSync(${JSON.stringify(ownerPidPath)}, String(child.pid));
            child.on("error", () => {});
            setTimeout(() => {}, 60000);
        `);

        const parent = rawSpawn(process.execPath, [parentPath], {
            cwd: root,
            stdio: "ignore",
            shell: false,
            windowsHide: true,
        });
        resources.trackPid(parent.pid);
        let candidatePid = 0;
        let ownerPid = 0;
        try {
            const deadline = Date.now() + 15_000;
            while ((!fs.existsSync(candidatePidPath)
                || !fs.existsSync(ownerPidPath))
                && Date.now() < deadline) {
                await new Promise((resolve) => setTimeout(resolve, 50));
            }
            expect(fs.existsSync(candidatePidPath)).toBe(true);
            expect(fs.existsSync(ownerPidPath)).toBe(true);
            candidatePid = resources.trackPid(
                Number(fs.readFileSync(candidatePidPath, "utf8")),
            );
            ownerPid = resources.trackPid(
                Number(fs.readFileSync(ownerPidPath, "utf8")),
            );

            parent.kill("SIGKILL");
            await new Promise((resolve) => parent.once("close", resolve));
            expect(await waitForPidExit(candidatePid)).toBe(true);
            expect(await waitForPidExit(ownerPid)).toBe(true);
        } finally {
            if (fs.existsSync(candidatePidPath)) {
                resources.trackPid(
                    Number(fs.readFileSync(candidatePidPath, "utf8")),
                );
            }
            if (fs.existsSync(ownerPidPath)) {
                resources.trackPid(
                    Number(fs.readFileSync(ownerPidPath, "utf8")),
                );
            }
            try { parent.kill("SIGKILL"); } catch {}
        }
    }, 180_000);
});
