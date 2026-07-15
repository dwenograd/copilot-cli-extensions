import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
    buildRecoveryTaskSpec,
} from "../tools/recovery-task.mjs";
import {
    captureRecoveryLaunchEnvironment,
    hashRecoveryLaunchFile,
} from "../tools/recovery-launcher.mjs";
import {
    ROOT,
    isCrucibleOwnershipInput,
    listCurrentOwnershipInputs,
    resolveOwnership,
} from "../../scripts/run-crucible-related.mjs";
import {
    assertCleanOwnedHost,
    assertNoLeaks,
    formatFailure,
    isRecognizedOwnedRoot,
    isTestOwnedTask,
    isTestOwnedProcess,
    listOwnedRoots,
    runPhase,
} from "../../scripts/run-crucible-unattended-release.mjs";

describe("Crucible release test plumbing", () => {
    it("maps every current source, PowerShell, config, fixture, and test input", () => {
        const inputs = listCurrentOwnershipInputs();
        const selection = resolveOwnership(inputs, { includeRelease: true });

        expect(inputs.length).toBeGreaterThan(0);
        expect(selection.unmatched).toEqual([]);
        expect(selection.releaseRequired).toEqual([]);
        for (const target of selection.targets) {
            expect(
                fs.existsSync(path.join(ROOT, ...target.file.split("/"))),
                target.file,
            ).toBe(true);
        }
    });

    it("requires an exact marker for repository-root e2e cleanup", () => {
        const root = fs.mkdtempSync(path.join(ROOT, ".e-marker-probe-"));
        try {
            expect(isRecognizedOwnedRoot(root)).toBe(false);
            fs.writeFileSync(
                path.join(root, ".crucible-test-root.json"),
                `${JSON.stringify({
                    version: 1,
                    kind: "crucible-api-e2e-test-root",
                    root: path.resolve(root),
                })}\n`,
            );
            expect(isRecognizedOwnedRoot(root)).toBe(true);
        } finally {
            fs.rmSync(root, { recursive: true, force: true });
        }
    });

    it("recognizes test scheduler tasks through the authenticated manifest", () => {
        const stateRoot = path.join(
            ROOT,
            "crucible",
            "__tests__",
            ".recovery-task-conformance-owned",
        );
        const daemonPath = path.join(
            ROOT,
            "crucible",
            "runtime",
            "recovery-daemon-cli.mjs",
        );
        const launcherPath = path.join(
            process.env.SystemRoot ?? "C:\\Windows",
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe",
        );
        const spec = buildRecoveryTaskSpec({
            stateRoot,
            runtime: {
                runtimeRoot: path.join(ROOT, "crucible"),
                daemonPath,
                nodePath: process.execPath,
                launcherPath,
                ...(() => {
                    const node = hashRecoveryLaunchFile(process.execPath);
                    const daemon = hashRecoveryLaunchFile(daemonPath);
                    const launcher = hashRecoveryLaunchFile(launcherPath);
                    return {
                        nodeSha256: node.sha256,
                        nodeSize: node.size,
                        daemonSha256: daemon.sha256,
                        daemonSize: daemon.size,
                        launcherSha256: launcher.sha256,
                        launcherSize: launcher.size,
                    };
                })(),
                launchEnvironment: captureRecoveryLaunchEnvironment(
                    process.env,
                ),
            },
            user: {
                userId: "CONTOSO\\crucible-user",
                userSid: "S-1-5-21-1000-1001-1002-1003",
            },
        });
        expect(isTestOwnedTask({
            arguments: spec.action.arguments,
        })).toBe(true);
        expect(isTestOwnedTask({
            arguments: `${spec.action.arguments} --tampered`,
        })).toBe(false);
    });

    it("keeps each mapped edit loop narrow", () => {
        for (const input of listCurrentOwnershipInputs()) {
            const selection = resolveOwnership([input], {
                includeRelease: true,
            });
            expect(selection.targets.length, input).toBeGreaterThan(0);
            expect(selection.targets.length, input).toBeLessThanOrEqual(4);
        }
    });

    it("fails closed for unknown or out-of-scope inputs", () => {
        const selection = resolveOwnership([
            "crucible/runtime/not-owned.mjs",
            "zerotrust-sourcecheck/extension.mjs",
        ]);
        expect(selection.targets).toEqual([]);
        expect(selection.unmatched).toEqual([
            "crucible/runtime/not-owned.mjs",
            "zerotrust-sourcecheck/extension.mjs",
        ]);
    });

    it("requires an explicit release gate for release-only fixtures", () => {
        const input =
            "crucible/__tests__/fixtures/segment-rotation-kill-worker.mjs";
        expect(isCrucibleOwnershipInput(input)).toBe(true);
        expect(resolveOwnership([input])).toMatchObject({
            targets: [],
            unmatched: [],
            releaseRequired: [input],
        });
        expect(resolveOwnership([input], { includeRelease: true }))
            .toMatchObject({
                unmatched: [],
                releaseRequired: [],
                targets: [{
                    file:
                        "crucible/__tests__/persistence-segments.release.test.mjs",
                    tier: "release",
                }],
            });
    });

    it("inventories only explicitly recognized test roots", () => {
        const testsRoot = path.join(ROOT, "crucible", "__tests__");
        const root = fs.mkdtempSync(
            path.join(testsRoot, ".runtime-runner-inventory-probe-"),
        );
        try {
            expect(listOwnedRoots()).toContain(root);
            expect(isRecognizedOwnedRoot(root)).toBe(true);
            expect(isRecognizedOwnedRoot(path.join(ROOT, ".git"))).toBe(false);
            expect(isRecognizedOwnedRoot(
                path.join(ROOT, "crucible"),
            )).toBe(false);
            expect(isRecognizedOwnedRoot(testsRoot)).toBe(false);
            expect(isRecognizedOwnedRoot(
                path.join(testsRoot, ".unrecognized-user-state"),
            )).toBe(false);
        } finally {
            fs.rmSync(root, { recursive: true, force: true });
        }
    });

    it("rejects stale recognized host fixtures instead of baselining them", () => {
        const clean = {
            roots: [],
            tasks: [],
            processes: [],
            profiles: [],
            registry: "",
            userEnvironment: null,
        };
        expect(() => assertCleanOwnedHost(clean)).not.toThrow();
        expect(() => assertCleanOwnedHost({
            ...clean,
            roots: [path.join(
                ROOT,
                "crucible",
                "__tests__",
                ".runtime-runner-stale-root",
            )],
        })).toThrow(AggregateError);
        expect(() => assertCleanOwnedHost({
            ...clean,
            processes: [{
                pid: 123,
                parentPid: 1,
                creationDate: "fixture",
                command: "node runtime-runner.release.test.mjs",
            }],
        })).toThrow(AggregateError);
        expect(() => assertCleanOwnedHost({
            ...clean,
            profiles: ["crucible.sandbox.stale"],
        })).toThrow(AggregateError);
        expect(() => assertCleanOwnedHost({
            ...clean,
            registry: "HKEY_CURRENT_USER\\Software\\CrucibleSandboxConformance",
        })).toThrow(AggregateError);
    });

    it("never treats production Crucible processes as test-owned by name alone", () => {
        for (const command of [
            "node crucible/runtime/recovery-daemon-cli.mjs",
            "node crucible/runtime/supervisor-cli.mjs",
            "node crucible/runtime/runner-cli.mjs",
        ]) {
            expect(isTestOwnedProcess({ command }, [])).toBe(false);
        }
        const ownedRoot = path.join(
            ROOT,
            "crucible",
            "__tests__",
            ".runtime-runner-owned-process",
        );
        expect(isTestOwnedProcess({
            command: `node crucible/runtime/runner-cli.mjs ${ownedRoot}`,
        }, [ownedRoot])).toBe(true);
    });

    it("reports inventory leaks and preserves aggregate causes", () => {
        const before = {
            roots: [],
            tasks: [],
            processes: [],
            profiles: [],
            registry: "",
            userEnvironment: null,
        };
        expect(() => assertNoLeaks(before, {
            ...before,
            roots: ["new-root"],
            processes: [{
                pid: 123,
                parentPid: 1,
                name: "node.exe",
                command: "fixture",
            }],
        })).toThrow(AggregateError);

        const nested = new AggregateError(
            [new Error("cleanup leaf", { cause: new Error("leaf cause") })],
            "cleanup aggregate",
        );
        const rendered = formatFailure(nested);
        expect(rendered).toContain("cleanup aggregate");
        expect(rendered).toContain("cleanup leaf");
        expect(rendered).toContain("leaf cause");
    });

    it("retains child status and nested diagnostics for abnormal exits", () => {
        let failure = null;
        try {
            runPhase(
                "synthetic abnormal exit",
                process.execPath,
                ["-e", "process.stderr.write('fixture failure'); process.exit(-1)"],
            );
        } catch (error) {
            failure = error;
        }
        expect(failure).toBeInstanceOf(Error);
        const rendered = formatFailure(failure);
        expect(rendered).toContain("synthetic abnormal exit failed with exit");
        expect(rendered).toContain("child diagnostics: status=");
        expect(rendered).toContain("fixture failure");
    });
});
