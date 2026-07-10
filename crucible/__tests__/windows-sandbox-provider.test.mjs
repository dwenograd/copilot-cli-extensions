import { afterAll, describe, expect, it } from "vitest";
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
    limits,
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
    const provider = createWindowsSandboxProvider({
        controlRoot,
        ...(limits === undefined ? {} : { limits }),
    });
    const executor = createMeasurementExecutor({
        allowlist,
        sandboxProvider: provider,
        scratchRoot: path.join(root, "scratch"),
        ...(processAdapter === undefined ? {} : { processAdapter }),
    });
    const snapshot = materializeCandidateSnapshot(
        root,
        `${label}-candidate`,
        "immutable-candidate",
    );
    return {
        root,
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
});

describe.skipIf(!availability.available)("Windows AppContainer containment", () => {
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
            policyId: WINDOWS_SANDBOX_POLICY_ID,
            launchPath: "sandbox-capability",
            capabilityLaunchUsed: true,
        });
        expect(result.receipt.sandbox.policyDigest).toMatch(
            /^sha256:crucible-windows-appcontainer-policy-v1:[a-f0-9]{64}$/u,
        );
        expect(hashReceipt({
            ...result.receipt,
            sandbox: {
                ...result.receipt.sandbox,
                policyDigest:
                    `sha256:crucible-windows-appcontainer-policy-v1:${"0".repeat(64)}`,
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
        expect(Date.now() - started).toBeLessThan(10_000);
        expectFixtureCleanup(fixture, beforeProfiles);
    }, 180_000);
});
