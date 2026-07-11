import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { PassThrough } from "node:stream";

import { afterAll, describe, expect, it } from "vitest";

import {
    MEASUREMENT_ERROR_CODES,
    createDefaultProcessAdapter,
    createMeasurementExecutor,
    createSandboxProvider,
    hashReceipt,
    loadHarnessAllowlist,
} from "../measurement/index.mjs";
import {
    fixedIds,
    makeTempRoot,
    manualClock,
    materializeCandidateSnapshot,
    rmTempRoot,
    sha256HexOfFile,
    writeAllowlist,
} from "./measurement-fixtures.mjs";

const POLICY_DIGEST =
    `sha256:fixture-containment-policy-v1:${"a".repeat(64)}`;
const OTHER_POLICY_DIGEST =
    `sha256:fixture-containment-policy-v1:${"b".repeat(64)}`;
const roots = [];
let nextPid = 8100;

function tmp(label) {
    const root = makeTempRoot(`capability-${label}`);
    roots.push(root);
    return root;
}

afterAll(() => roots.forEach(rmTempRoot));

function makeChild({
    stdout = '{"pass":true}',
    stderr = "",
    autoClose = true,
} = {}) {
    const child = new EventEmitter();
    child.pid = nextPid += 1;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    if (autoClose) {
        setImmediate(() => {
            child.stdout.end(Buffer.from(stdout, "utf8"));
            child.stderr.end(Buffer.from(stderr, "utf8"));
            child.emit("close", 0, null);
        });
    }
    return child;
}

function makeFixture(label, entryOverrides = {}) {
    const root = tmp(label);
    const fakeExecutable = path.join(root, "fixture.exe");
    fs.writeFileSync(fakeExecutable, "fixture executable bytes");
    const entryId = `cap-${label}`;
    const allowlistPath = writeAllowlist(root, entryId, {
        executable: fakeExecutable,
        executableSha256: sha256HexOfFile(fakeExecutable),
        argvTemplate: ["{{candidatePath}}"],
        executesCandidateCode: true,
        timeoutMs: 250,
        ...entryOverrides,
    });
    const allowlist = loadHarnessAllowlist(allowlistPath);
    return {
        root,
        entryId,
        allowlist,
        verifiedEntry: allowlist.verifyEntry(entryId),
        snapshot: materializeCandidateSnapshot(root, `${label}-snapshot`, "candidate"),
    };
}

function makeHostAdapter(calls, childFactory = () => makeChild()) {
    return {
        spawn(executable, argv, options) {
            calls.hostLaunches.push({ executable, argv, options });
            return childFactory();
        },
        terminateTree(pid) {
            calls.hostTerminations.push(pid);
            return true;
        },
    };
}

function issueFixtureCapability(
    request,
    issueLaunchCapability,
    calls,
    {
        capabilityId = `capability-${request.attemptId}`,
        launch = () => makeChild(),
        terminate = () => true,
        cleanup = () => true,
    } = {},
) {
    return issueLaunchCapability({
        capabilityId,
        policyId: "fixture-policy-v1",
        policyDigest: POLICY_DIGEST,
        permittedStagedRoots: request.stagedRoots,
        launch(launchRequest) {
            calls.launches.push(launchRequest);
            return launch(launchRequest);
        },
        terminate(terminationRequest) {
            calls.terminations.push(terminationRequest);
            return terminate(terminationRequest);
        },
        cleanup(cleanupRequest) {
            calls.cleanups.push(cleanupRequest);
            return cleanup(cleanupRequest);
        },
    });
}

function emptyCalls() {
    return {
        admissions: [],
        launches: [],
        terminations: [],
        cleanups: [],
        hostLaunches: [],
        hostTerminations: [],
    };
}

function createFixtureProvider(calls, overrides = {}) {
    return createSandboxProvider({
        providerId: overrides.providerId ?? "fixture-containment",
        providerVersion: overrides.providerVersion ?? "v1.2.3",
        admitAndPrepare(request, issueLaunchCapability) {
            calls.admissions.push(request);
            return issueFixtureCapability(
                request,
                issueLaunchCapability,
                calls,
                overrides,
            );
        },
    });
}

function createExecutor(fixture, sandboxProvider, processAdapter, extra = {}) {
    return createMeasurementExecutor({
        allowlist: fixture.allowlist,
        sandboxProvider,
        processAdapter,
        scratchRoot: fixture.root,
        clock: manualClock(),
        ...extra,
    });
}

function runFixture(executor, fixture, ids = fixedIds()) {
    return executor.run({
        verifiedEntry: fixture.verifiedEntry,
        candidateSnapshot: fixture.snapshot,
        ...ids,
    });
}

function manualAdmissionRequest(fixture, stageRoot, attemptId = "att-manual") {
    fs.mkdirSync(stageRoot, { recursive: true });
    return {
        verifiedEntry: fixture.verifiedEntry,
        candidateSnapshot: fixture.snapshot,
        attemptId,
        runnerEpochId: fixedIds().runnerEpochId,
        harnessId: fixture.entryId,
        stagedRoots: [stageRoot],
        launch: {},
    };
}

describe("opaque SandboxLaunchCapability", () => {
    it("requires a sandbox provider for candidate-code harnesses", async () => {
        const fixture = makeFixture("required");
        const calls = emptyCalls();
        const executor = createMeasurementExecutor({
            allowlist: fixture.allowlist,
            sandboxProvider: null,
            processAdapter: makeHostAdapter(calls),
            scratchRoot: fixture.root,
            clock: manualClock(),
        });

        await expect(runFixture(executor, fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_REQUIRED,
        });
        expect(calls.hostLaunches).toHaveLength(0);
    });

    it("surfaces an explicit provider refusal without host fallback", async () => {
        const fixture = makeFixture("refused");
        const calls = emptyCalls();
        const provider = createSandboxProvider({
            providerId: "refusing-provider",
            providerVersion: "v1",
            admitAndPrepare: () => ({
                admitted: false,
                reason: "synthetic refusal",
            }),
        });
        const executor = createExecutor(
            fixture,
            provider,
            makeHostAdapter(calls),
        );

        await expect(runFixture(executor, fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_REFUSED,
        });
        expect(calls.hostLaunches).toHaveLength(0);
    });

    it("rejects forged providers and advisory {admitted:true} results", async () => {
        const fixture = makeFixture("forged");
        expect(() => createMeasurementExecutor({
            allowlist: fixture.allowlist,
            scratchRoot: fixture.root,
            sandboxProvider: {
                admitAndPrepare: () => ({ admitted: true }),
            },
        })).toThrow(expect.objectContaining({
            code: MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
        }));

        const advisoryProvider = createSandboxProvider({
            providerId: "advisory-provider",
            providerVersion: "v1",
            admitAndPrepare: () => ({
                admitted: true,
                sandboxId: "not-a-capability",
                environmentHash: POLICY_DIGEST,
            }),
        });
        const calls = emptyCalls();
        const executor = createExecutor(
            fixture,
            advisoryProvider,
            makeHostAdapter(calls),
        );
        await expect(runFixture(executor, fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
        });
        expect(calls.hostLaunches).toHaveLength(0);
    });

    it("rejects a provider that returns an ordinary host process adapter", async () => {
        const fixture = makeFixture("host-return");
        const provider = createSandboxProvider({
            providerId: "host-returner",
            providerVersion: "v1",
            admitAndPrepare: () => createDefaultProcessAdapter(),
        });
        const calls = emptyCalls();
        const executor = createExecutor(
            fixture,
            provider,
            makeHostAdapter(calls),
        );
        await expect(runFixture(executor, fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
        });
        expect(calls.hostLaunches).toHaveLength(0);

        const hostAdapter = createDefaultProcessAdapter();
        expect(() => hostAdapter.spawn(process.execPath, [], {
            cwd: fixture.root,
            env: {},
            stdio: ["ignore", "pipe", "pipe"],
            executesCandidateCode: true,
            launchPath: "sandbox-capability",
        })).toThrow(expect.objectContaining({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_REQUIRED,
        }));
    });

    it("binds a capability to its issuing provider and admission", async () => {
        const fixture = makeFixture("provider-binding");
        const callsA = emptyCalls();
        let foreignCapability = null;
        const providerA = createSandboxProvider({
            providerId: "provider-a",
            providerVersion: "v1",
            admitAndPrepare(request, issueLaunchCapability) {
                foreignCapability = issueFixtureCapability(
                    request,
                    issueLaunchCapability,
                    callsA,
                );
                return foreignCapability;
            },
        });
        const manualRoot = path.join(fixture.root, "manual-provider-a");
        const request = manualAdmissionRequest(fixture, manualRoot);
        await providerA.admitAndPrepare(request);
        expect(Object.keys(foreignCapability)).toEqual([]);
        expect(Object.getOwnPropertySymbols(foreignCapability)).toEqual([]);

        const providerB = createSandboxProvider({
            providerId: "provider-b",
            providerVersion: "v1",
            admitAndPrepare: () => foreignCapability,
        });
        await expect(providerB.admitAndPrepare(request)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
        });

        const forgedFromPrototype = Object.freeze(
            Object.create(Object.getPrototypeOf(foreignCapability)),
        );
        const providerC = createSandboxProvider({
            providerId: "provider-c",
            providerVersion: "v1",
            admitAndPrepare: () => forgedFromPrototype,
        });
        await expect(providerC.admitAndPrepare(request)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_INVALID,
        });
    });

    it("rejects one-shot capability replay after a completed attempt", async () => {
        const fixture = makeFixture("replay");
        const calls = emptyCalls();
        let cachedCapability = null;
        const provider = createSandboxProvider({
            providerId: "replay-provider",
            providerVersion: "v1",
            admitAndPrepare(request, issueLaunchCapability) {
                calls.admissions.push(request);
                if (cachedCapability === null) {
                    cachedCapability = issueFixtureCapability(
                        request,
                        issueLaunchCapability,
                        calls,
                    );
                }
                return cachedCapability;
            },
        });
        const executor = createExecutor(
            fixture,
            provider,
            makeHostAdapter(calls),
        );

        const first = await runFixture(executor, fixture);
        expect(first.parsed.pass).toBe(true);
        await expect(runFixture(executor, fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_REPLAY,
        });
        expect(calls.launches).toHaveLength(1);
        expect(calls.cleanups).toHaveLength(1);
        expect(calls.hostLaunches).toHaveLength(0);
    });

    it("rejects an unconsumed capability issued for a different attempt", async () => {
        const fixture = makeFixture("wrong-attempt");
        const calls = emptyCalls();
        let cachedCapability = null;
        let reuseCached = false;
        const provider = createSandboxProvider({
            providerId: "attempt-provider",
            providerVersion: "v1",
            admitAndPrepare(request, issueLaunchCapability) {
                if (reuseCached) return cachedCapability;
                cachedCapability = issueFixtureCapability(
                    request,
                    issueLaunchCapability,
                    calls,
                );
                return cachedCapability;
            },
        });
        await provider.admitAndPrepare(manualAdmissionRequest(
            fixture,
            path.join(fixture.root, "manual-wrong-attempt"),
            "att-other",
        ));
        reuseCached = true;

        const executor = createExecutor(
            fixture,
            provider,
            makeHostAdapter(calls),
        );
        await expect(runFixture(executor, fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.SANDBOX_CAPABILITY_BINDING,
        });
        expect(calls.launches).toHaveLength(0);
        expect(calls.hostLaunches).toHaveLength(0);
    });

    it("delegates launch and cleanup exclusively to the containment capability", async () => {
        const fixture = makeFixture("owned-launch");
        const calls = emptyCalls();
        const provider = createFixtureProvider(calls);
        const executor = createExecutor(
            fixture,
            provider,
            makeHostAdapter(calls, () => {
                throw new Error("host adapter must not launch candidate code");
            }),
        );

        const result = await runFixture(executor, fixture);
        expect(result.parsed.pass).toBe(true);
        expect(calls.hostLaunches).toHaveLength(0);
        expect(calls.hostTerminations).toHaveLength(0);
        expect(calls.launches).toHaveLength(1);
        expect(calls.cleanups).toHaveLength(1);
        expect(calls.terminations).toHaveLength(0);

        const launch = calls.launches[0];
        expect(launch.options).toMatchObject({
            executesCandidateCode: true,
            launchPath: "sandbox-capability",
            shell: false,
            windowsHide: true,
        });
        expect(launch.stagedPaths.every((item) =>
            item.startsWith(launch.permittedStagedRoots[0]))).toBe(true);
        expect(calls.cleanups[0]).toMatchObject({
            launchUsed: true,
            terminationRequested: false,
        });
    });

    it("delegates timeout termination and cleanup to the same capability", async () => {
        const fixture = makeFixture("owned-termination", { timeoutMs: 10 });
        const calls = emptyCalls();
        let child = null;
        const provider = createFixtureProvider(calls, {
            launch() {
                child = makeChild({ autoClose: false });
                return child;
            },
            terminate() {
                child.stdout.end();
                child.stderr.end();
                setImmediate(() => child.emit("close", null, "SIGKILL"));
                return true;
            },
        });
        const executor = createExecutor(
            fixture,
            provider,
            makeHostAdapter(calls),
        );

        await expect(runFixture(executor, fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.TIMEOUT,
        });
        expect(calls.hostTerminations).toHaveLength(0);
        expect(calls.terminations).toHaveLength(1);
        expect(calls.terminations[0]).toMatchObject({
            pid: child.pid,
            reason: "timeout",
        });
        expect(calls.cleanups).toHaveLength(1);
        expect(calls.cleanups[0]).toMatchObject({
            launchUsed: true,
            terminationRequested: true,
        });
    });

    it("records and hash-binds provider, policy, capability, roots, and launch path", async () => {
        const fixture = makeFixture("receipt");
        const calls = emptyCalls();
        const provider = createFixtureProvider(calls, {
            providerId: "receipt-provider",
            providerVersion: "v9.4",
            capabilityId: "receipt-capability",
        });
        const executor = createExecutor(
            fixture,
            provider,
            makeHostAdapter(calls),
        );

        const result = await runFixture(executor, fixture);
        expect(result.receipt.sandbox).toMatchObject({
            sandboxId: "receipt-capability",
            environmentHash: POLICY_DIGEST,
            providerId: "receipt-provider",
            providerVersion: "v9.4",
            policyId: "fixture-policy-v1",
            policyDigest: POLICY_DIGEST,
            policyIdentity: {
                providerId: "receipt-provider",
                providerVersion: "v9.4",
                policyId: "fixture-policy-v1",
            },
            policy: {
                version: 1,
                identity: {
                    providerId: "receipt-provider",
                    providerVersion: "v9.4",
                    policyId: "fixture-policy-v1",
                },
            },
            capabilityId: "receipt-capability",
            launchPath: "sandbox-capability",
            capabilityLaunchUsed: true,
            permittedStagedRoots: [
                expect.stringContaining(".crucible-stage-att-0001"),
            ],
        });

        const originalHash = hashReceipt(result.receipt);
        const tampered = {
            ...result.receipt,
            sandbox: {
                ...result.receipt.sandbox,
                policyDigest: OTHER_POLICY_DIGEST,
            },
        };
        expect(hashReceipt(tampered)).not.toBe(originalHash);
    });

    it("keeps executesCandidateCode=false on the staged host adapter path", async () => {
        const fixture = makeFixture("host-safe", {
            executesCandidateCode: false,
        });
        const calls = emptyCalls();
        const provider = createSandboxProvider({
            providerId: "unused-provider",
            providerVersion: "v1",
            admitAndPrepare() {
                calls.admissions.push("unexpected");
                throw new Error("provider must not be called");
            },
        });
        const executor = createExecutor(
            fixture,
            provider,
            makeHostAdapter(calls),
        );

        const result = await runFixture(executor, fixture);
        expect(result.parsed.pass).toBe(true);
        expect(result.receipt.sandbox).toBeNull();
        expect(calls.admissions).toHaveLength(0);
        expect(calls.hostLaunches).toHaveLength(1);
        expect(calls.hostLaunches[0].options).toMatchObject({
            executesCandidateCode: false,
            launchPath: "host-process-adapter",
        });
    });
});
