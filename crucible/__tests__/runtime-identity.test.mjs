import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
    DEFAULT_RUNTIME_IDENTITY_POLICY,
    immutableCanonical,
} from "../domain/index.mjs";
import {
    RUNTIME_IDENTITY_RESULT_CODES,
    buildRuntimeIdentity,
    createRuntimeIdentityHashCache,
    verifyRuntimeIdentity,
} from "../runtime/runtime-identity.mjs";
import { removeTrackedRoots } from "./test-cleanup.mjs";

const roots = [];
const hash = (label, character = "a") =>
    `sha256:${label}:${character.repeat(64)}`;

afterEach(async () => {
    await removeTrackedRoots(roots, {
        label: "runtime identity test root",
    });
});

function write(file, content) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
    return file;
}

function workspace(label) {
    const root = fs.mkdtempSync(
        path.join(os.tmpdir(), `crucible-runtime-identity-${label}-`),
    );
    roots.push(root);
    const source = path.join(root, "source");
    const cliPackage = path.join(root, "cli-package");
    const sdk = path.join(root, "sdk");
    const sandbox = path.join(root, "sandbox");
    const files = {
        sourceMain: write(
            path.join(source, "extension.mjs"),
            "export const version = 1;\n",
        ),
        sourceRuntime: write(
            path.join(source, "runtime", "worker.mjs"),
            "export function run() { return 1; }\n",
        ),
        node: write(path.join(root, "node.exe"), "node-runtime-v1"),
        cli: write(path.join(root, "copilot.exe"), "copilot-launcher-v1"),
        cliPackage: write(
            path.join(cliPackage, "app.js"),
            "export const cli = 1;\n",
        ),
        sdk: write(path.join(sdk, "index.js"), "export const sdk = 1;\n"),
        helperSource: write(
            path.join(sandbox, "helper.cs"),
            "public class Helper {}\n",
        ),
        helperBinary: write(
            path.join(sandbox, "helper.exe"),
            "sandbox-helper-v1",
        ),
        launcher: write(
            path.join(sandbox, "powershell.exe"),
            "sandbox-launcher-v1",
        ),
    };
    const policy = immutableCanonical({
        ...structuredClone(DEFAULT_RUNTIME_IDENTITY_POLICY),
        environmentKeys: ["PATH", "TEST_DECISION"],
    });
    const input = {
        policy,
        crucibleSourceRoot: source,
        nodeExecutablePath: files.node,
        copilotCliLauncherPath: files.cli,
        copilotCliPackageRoot: cliPackage,
        copilotSdkPackageRoot: sdk,
        sandbox: {
            required: true,
            helperSourcePath: files.helperSource,
            helperBinaryPath: files.helperBinary,
            launcherPath: files.launcher,
            launcherScriptHash: hash(
                "crucible-test-sandbox-launcher-script-v1",
            ),
        },
        commandTemplates: {
            supervisor: {
                executable: "component:nodeExecutable",
                argv: [
                    "component:crucibleSource/runtime/supervisor-cli.mjs",
                    "--config",
                    "<supervisor-config>",
                ],
                shell: false,
            },
            worker: {
                executable: "component:copilotCli.launcher",
                argv: ["<worker-command>"],
                shell: false,
            },
        },
        env: {
            PATH: "C:\\runtime\\bin",
            TEST_DECISION: "strict",
        },
        assumptions: {
            os: { platform: "fixture", release: "1" },
            hardware: { logicalCpuCount: 8, model: "fixture-cpu" },
        },
    };
    return { root, files, input };
}

function append(file, text = "\nmutated") {
    fs.appendFileSync(file, text);
}

describe("runtime identity closure", () => {
    it("builds a deeply frozen closure and accepts legitimate unchanged reuse", () => {
        const ws = workspace("unchanged");
        const identity = buildRuntimeIdentity(ws.input);
        const verified = verifyRuntimeIdentity(identity, ws.input);

        expect(verified.ok).toBe(true);
        expect(verified.actualRoot).toBe(identity.root);
        expect(Object.isFrozen(identity)).toBe(true);
        expect(Object.isFrozen(identity.components.copilotCli.package)).toBe(true);

        const changedAssumptions = verifyRuntimeIdentity(identity, {
            ...ws.input,
            assumptions: {
                os: { platform: "fixture", release: "2" },
                hardware: { logicalCpuCount: 16, model: "replacement-cpu" },
            },
        });
        expect(changedAssumptions.ok).toBe(true);
        expect(changedAssumptions.assumptionsChanged).toBe(true);
    });

    it.each([
        ["Crucible source", "sourceMain", "crucibleSource"],
        ["Node executable", "node", "nodeExecutable"],
        ["Copilot CLI launcher", "cli", "copilotCli"],
        ["Copilot CLI package", "cliPackage", "copilotCli"],
        ["Copilot SDK package", "sdk", "copilotSdk"],
        ["sandbox helper source", "helperSource", "sandbox"],
        ["sandbox helper binary", "helperBinary", "sandbox"],
        ["sandbox launcher", "launcher", "sandbox"],
    ])("returns RUNTIME_DRIFT when %s changes", (_label, key, component) => {
        const ws = workspace(`mutate-${key}`);
        const identity = buildRuntimeIdentity(ws.input);
        append(ws.files[key]);

        const result = verifyRuntimeIdentity(identity, ws.input);
        expect(result).toMatchObject({
            ok: false,
            code: RUNTIME_IDENTITY_RESULT_CODES.RUNTIME_DRIFT,
            inPlaceRepinAllowed: false,
        });
        expect(result.changedComponents).toContain(component);
    });

    it("detects command-template and decision-environment drift", () => {
        const ws = workspace("commands-environment");
        const identity = buildRuntimeIdentity(ws.input);
        const commandResult = verifyRuntimeIdentity(identity, {
            ...ws.input,
            commandTemplates: {
                ...ws.input.commandTemplates,
                worker: {
                    ...ws.input.commandTemplates.worker,
                    argv: ["--unsafe", "<worker-command>"],
                },
            },
        });
        expect(commandResult.changedComponents).toEqual(["commandTemplates"]);

        const environmentResult = verifyRuntimeIdentity(identity, {
            ...ws.input,
            env: {
                ...ws.input.env,
                TEST_DECISION: "permissive",
            },
        });
        expect(environmentResult.changedComponents).toEqual(["environment"]);
    });

    it("treats a same-content path swap as drift", () => {
        const ws = workspace("path-swap");
        const identity = buildRuntimeIdentity(ws.input);
        const replacement = write(
            path.join(ws.root, "other", "copilot.exe"),
            fs.readFileSync(ws.files.cli),
        );
        const result = verifyRuntimeIdentity(identity, {
            ...ws.input,
            copilotCliLauncherPath: replacement,
        });

        expect(result.code).toBe(RUNTIME_IDENTITY_RESULT_CODES.RUNTIME_DRIFT);
        expect(result.changedComponents).toEqual(["copilotCli"]);
    });

    it("rejects symlink/reparse and non-local component paths", () => {
        const ws = workspace("unsafe-paths");
        const sourceAlias = path.join(ws.root, "source-alias");
        fs.symlinkSync(
            ws.input.crucibleSourceRoot,
            sourceAlias,
            process.platform === "win32" ? "junction" : "dir",
        );
        expect(() => buildRuntimeIdentity({
            ...ws.input,
            crucibleSourceRoot: sourceAlias,
        })).toThrow(/symlink|reparse/u);

        expect(() => buildRuntimeIdentity({
            ...ws.input,
            nodeExecutablePath: "\\\\server\\share\\node.exe",
        })).toThrow(/trusted local|network path/u);
    });

    it("rejects a tampered content-hash cache instead of trusting it", () => {
        const ws = workspace("cache-tamper");
        const cache = createRuntimeIdentityHashCache();
        const identity = buildRuntimeIdentity(ws.input, {
            cache,
            trustVerifiedCache: true,
        });
        const [key, record] = cache.entries().next().value;
        cache.set(key, {
            ...record,
            contentHash: hash("crucible-runtime-file-content-v1", "0"),
        });

        const result = verifyRuntimeIdentity(identity, ws.input, { cache });
        expect(result).toMatchObject({
            ok: false,
            code: RUNTIME_IDENTITY_RESULT_CODES.RUNTIME_DRIFT,
            reason: "runtime_identity_verification_failed",
        });
        expect(result.message).toMatch(/cache entry failed integrity/u);
    });

    it("reuses only sealed, previously content-verified cache records", () => {
        const ws = workspace("cache-unchanged");
        const cache = createRuntimeIdentityHashCache();
        const first = buildRuntimeIdentity(ws.input, {
            cache,
            trustVerifiedCache: true,
        });
        const second = buildRuntimeIdentity(ws.input, {
            cache,
            trustVerifiedCache: true,
        });
        expect(second.root).toBe(first.root);
        expect(cache.size).toBeGreaterThan(0);
        for (const record of cache.values()) {
            expect(Object.isFrozen(record)).toBe(true);
            expect(record.seal).toMatch(
                /^sha256:crucible-runtime-hash-cache-record-v1:[a-f0-9]{64}$/u,
            );
        }
    });

    it("produces the same source Merkle root regardless of directory order", () => {
        const ws = workspace("source-order");
        for (let index = 0; index < 20; index += 1) {
            write(
                path.join(
                    ws.input.crucibleSourceRoot,
                    `group-${index % 4}`,
                    `file-${index}.mjs`,
                ),
                `export default ${index};\n`,
            );
        }
        const forward = buildRuntimeIdentity(ws.input);
        const reverse = buildRuntimeIdentity(ws.input, {
            readDirectory: (directory) =>
                fs.readdirSync(directory, { withFileTypes: true }).reverse(),
        });

        expect(reverse.components.crucibleSource.merkleRoot)
            .toBe(forward.components.crucibleSource.merkleRoot);
        expect(reverse.root).toBe(forward.root);
    });

    it("enforces file/size caps and stays within the targeted performance cap", () => {
        const ws = workspace("caps-performance");
        const tooSmall = {
            ...structuredClone(ws.input.policy),
            limits: {
                ...ws.input.policy.limits,
                maxFiles: 3,
            },
        };
        expect(() => buildRuntimeIdentity({
            ...ws.input,
            policy: tooSmall,
        })).toThrow(/file\/byte caps/u);
        const tinyFiles = {
            ...structuredClone(ws.input.policy),
            limits: {
                ...ws.input.policy.limits,
                maxFileBytes: 1,
            },
        };
        expect(() => buildRuntimeIdentity({
            ...ws.input,
            policy: tinyFiles,
        })).toThrow(/per-file size cap/u);

        const started = performance.now();
        const identity = buildRuntimeIdentity(ws.input);
        const elapsed = performance.now() - started;
        expect(identity.components.crucibleSource.fileCount).toBe(2);
        expect(elapsed).toBeLessThan(1_500);
    });
});
