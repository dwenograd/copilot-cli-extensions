import { afterAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { threadId } from "node:worker_threads";

import {
    MEASUREMENT_ERROR_CODES,
    createMeasurementExecutor,
    createWindowsSandboxProvider,
    loadHarnessAllowlist,
    probeWindowsSandboxAvailability,
} from "../measurement/index.mjs";
import {
    canCreateDirJunction,
    fixedIds,
    makeTempRoot,
    materializeCandidateSnapshot,
    rmTempRoot,
    writeAllowlist,
    writeHarnessScript,
} from "./measurement-fixtures.mjs";

const roots = [];
const suiteRoot = makeTempRoot("windows-sandbox-h3");
roots.push(suiteRoot);
const controlRoot = path.join(suiteRoot, "control");
const availability = await probeWindowsSandboxAvailability({ controlRoot });
const typedUnavailable = availability.available === false
    && availability.code === MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE;
const defaultProvider = createWindowsSandboxProvider({ controlRoot });
let attemptCounter = 0;

afterAll(() => {
    for (const root of roots.splice(0)) rmTempRoot(root);
});

function safeLabel(value) {
    return value.toLowerCase().replace(/[^a-z0-9._-]+/gu, "-").slice(0, 80);
}

function makeFixture(label, body, {
    allowedEnv = {},
    candidateBytes = "immutable-candidate",
    dependencyFiles = [],
    faultInjector,
    limits,
    maxStderrBytes,
    maxStdoutBytes,
    prepareRoot,
    provider,
    timeoutMs = 15_000,
} = {}) {
    const safe = safeLabel(label);
    const root = makeTempRoot(`windows-sandbox-h3-${safe}`);
    roots.push(root);
    const prepared = prepareRoot?.(root) ?? {};
    const script = writeHarnessScript(root, safe, body);
    const dependencies = dependencyFiles.map(({ name, contents }) => {
        const dependency = path.join(root, name);
        fs.mkdirSync(path.dirname(dependency), { recursive: true });
        fs.writeFileSync(dependency, contents);
        return dependency;
    });
    const entryId = `h3-${safe}`;
    const allowlistPath = writeAllowlist(root, entryId, {
        argvTemplate: [script, ...dependencies, "{{candidatePath}}"],
        allowedEnv: {
            ...allowedEnv,
            ...(prepared.allowedEnv ?? {}),
        },
        executesCandidateCode: true,
        timeoutMs,
        ...(maxStdoutBytes === undefined ? {} : { maxStdoutBytes }),
        ...(maxStderrBytes === undefined ? {} : { maxStderrBytes }),
    });
    const allowlist = loadHarnessAllowlist(allowlistPath);
    const sandboxProvider = provider
        ?? (limits === undefined
            ? defaultProvider
            : createWindowsSandboxProvider({ controlRoot, limits }));
    const executor = createMeasurementExecutor({
        allowlist,
        sandboxProvider,
        scratchRoot: path.join(root, "scratch"),
        ...(faultInjector === undefined ? {} : { faultInjector }),
    });
    const snapshot = materializeCandidateSnapshot(
        root,
        `${safe}-candidate`,
        candidateBytes,
    );
    attemptCounter += 1;
    return {
        allowlistPath,
        dependencies,
        entryId,
        executor,
        prepared,
        root,
        script,
        snapshot,
        verifiedEntry: allowlist.verifyEntry(entryId),
        ids: {
            ...fixedIds(),
            attemptId: `att-h3-${attemptCounter}`,
        },
    };
}

function runFixture(fixture) {
    return fixture.executor.run({
        verifiedEntry: fixture.verifiedEntry,
        candidateSnapshot: fixture.snapshot,
        ...fixture.ids,
    });
}

function existingReadTargets(fixture) {
    const userProfile = process.env.USERPROFILE;
    const appData = process.env.APPDATA;
    const localAppData = process.env.LOCALAPPDATA;
    const candidates = [
        ["copilot-home", path.join(userProfile, ".copilot"), "directory"],
        ["copilot-session", path.join(userProfile, ".copilot", "session-state"), "directory"],
        ["copilot-extensions", path.join(userProfile, ".copilot", "extensions"), "directory"],
        ["profile-documents", path.join(userProfile, "Documents"), "directory"],
        ["git-config", path.join(userProfile, ".gitconfig"), "file"],
        ["git-credentials", path.join(userProfile, ".git-credentials"), "file"],
        ["git-config-xdg", path.join(userProfile, ".config", "git", "config"), "file"],
        ["ssh-home", path.join(userProfile, ".ssh"), "directory"],
        ["aws-home", path.join(userProfile, ".aws"), "directory"],
        ["azure-home", path.join(userProfile, ".azure"), "directory"],
        ["dpapi-protect", path.join(appData, "Microsoft", "Protect"), "directory"],
        ["credential-roaming", path.join(appData, "Microsoft", "Credentials"), "directory"],
        ["credential-local", path.join(localAppData, "Microsoft", "Credentials"), "directory"],
        ["github-cli", path.join(appData, "GitHub CLI"), "directory"],
        ["unrelated-drive", "K:\\AI", "directory"],
        ["crucible-control", controlRoot, "directory"],
        ["crucible-allowlist", fixture.allowlistPath, "file"],
        ["source-harness", fixture.script, "file"],
    ];
    return candidates
        .filter(([, target]) => fs.existsSync(target))
        .map(([id, target, kind]) => ({ id, path: target, kind }));
}

function expectAllCasesTrue(result, expectedIds = null) {
    const cases = result.parsed.validationCases;
    expect(cases).not.toBeNull();
    if (expectedIds !== null) {
        expect(Object.keys(cases).sort()).toEqual([...expectedIds].sort());
    }
    for (const [id, passed] of Object.entries(cases)) {
        expect(passed, id).toBe(true);
    }
    expect(result.parsed.pass).toBe(true);
}

function attemptRoots() {
    if (!fs.existsSync(controlRoot)) return [];
    return fs.readdirSync(controlRoot)
        .filter((name) => name.startsWith("attempt-"));
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

function expectSandboxCleanup(beforeProfiles) {
    expect(attemptRoots()).toEqual([]);
    expect(ownedSandboxProfiles()).toEqual(beforeProfiles);
}

function pidAlive(pid) {
    if (!Number.isInteger(pid) || pid <= 0) return false;
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
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return !pidAlive(pid);
}

function forceKillPid(pid) {
    if (!pidAlive(pid)) return;
    try {
        process.kill(pid, "SIGKILL");
    } catch {
        // Best effort cleanup for a test that already detected a defect.
    }
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

function registryFixture() {
    const regExe = path.join(
        process.env.SystemRoot ?? "C:\\Windows",
        "System32",
        "reg.exe",
    );
    const suffix = `${process.pid}-${randomBytes(6).toString("hex")}`;
    const key = `HKCU\\Software\\CrucibleSandboxH3\\${suffix}`;
    const secret = "host-registry-secret-h3";
    const added = spawnSync(
        regExe,
        ["ADD", key, "/v", "Secret", "/t", "REG_SZ", "/d", secret, "/f"],
        { encoding: "utf8", windowsHide: true },
    );
    if (added.status !== 0) {
        throw new Error(`failed to create registry fixture: ${added.stderr}`);
    }
    return {
        key,
        regExe,
        secret,
        cleanup() {
            spawnSync(regExe, ["DELETE", key, "/f"], {
                encoding: "utf8",
                windowsHide: true,
            });
            spawnSync(
                regExe,
                ["DELETE", "HKCU\\Software\\CrucibleSandboxH3", "/f"],
                { encoding: "utf8", windowsHide: true },
            );
        },
    };
}

function secretReadProbeBody() {
    return `
        const { spawn } = await import("node:child_process");
        const targets = JSON.parse(
            Buffer.from(process.env.READ_TARGETS_B64, "base64")
                .toString("utf8"),
        );
        const boundedTargetDenied = (target) => new Promise((resolve) => {
            let settled = false;
            const finish = (value) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                resolve(value);
            };
            const timer = setTimeout(() => finish(true), 1000);
            void (async () => {
                try {
                    if (target.kind === "directory") {
                        const directory = await fs.promises.opendir(target.path);
                        await directory.close();
                    } else {
                        const handle = await fs.promises.open(target.path, "r");
                        try {
                            const byte = Buffer.alloc(1);
                            await handle.read(byte, 0, 1, 0);
                        } finally {
                            await handle.close();
                        }
                    }
                    finish(false);
                } catch {
                    finish(true);
                }
            })();
        });
        const boundedRegistryQuery = () => new Promise((resolve) => {
            let child = null;
            let settled = false;
            let timer = null;
            const finish = (result) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                resolve(result);
            };
            timer = setTimeout(() => {
                try { child?.kill(); } catch {}
                child?.unref();
                finish({ status: null, timedOut: true });
            }, 2500);
            try {
                child = spawn(
                    process.env.REG_EXE,
                    ["QUERY", process.env.REG_KEY, "/v", "Secret"],
                    {
                        stdio: "ignore",
                        windowsHide: true,
                    },
                );
            } catch {
                finish({ status: null, timedOut: false });
                return;
            }
            child.once("error", () =>
                finish({ status: null, timedOut: false }));
            child.once("close", (status) =>
                finish({ status, timedOut: false }));
        });
        const [targetResults, registry] = await Promise.all([
            Promise.all(targets.map(boundedTargetDenied)),
            boundedRegistryQuery(),
        ]);
        const validationCases = {};
        targets.forEach((target, index) => {
            validationCases[target.id] = targetResults[index];
        });
        validationCases["registry-secret"] =
            registry.timedOut || registry.status !== 0;
        const values = Object.values(validationCases);
        const output = JSON.stringify({
            pass: values.every(Boolean),
            metrics: {
                denied: values.filter(Boolean).length,
                attempted: values.length,
            },
            validationCases,
        });
        process.stdout.write(output, () => process.exit(0));
    `;
}

describe("Windows sandbox H3 fail-closed gating", () => {
    it("skips dynamic enforcement only for typed SANDBOX_UNAVAILABLE", () => {
        if (availability.available) {
            expect(availability.code).toBeNull();
            return;
        }
        expect(typedUnavailable).toBe(true);
        expect(availability.code).toBe(
            MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE,
        );
        expect(availability.reason).toEqual(expect.any(String));
    });

    it("rejects a reparse-point control root as typed unavailability", async () => {
        expect(canCreateDirJunction()).toBe(true);
        const root = makeTempRoot("windows-sandbox-h3-control-junction");
        roots.push(root);
        const real = path.join(root, "real");
        const junction = path.join(root, "junction");
        fs.mkdirSync(real);
        fs.symlinkSync(real, junction, "junction");
        const result = await probeWindowsSandboxAvailability({
            controlRoot: junction,
        });
        expect(result).toMatchObject({
            available: false,
            code: MEASUREMENT_ERROR_CODES.SANDBOX_UNAVAILABLE,
        });
        expect(result.reason).toMatch(/reparse point/iu);
    });

    it("refuses a candidate snapshot containing a junction before launch", async () => {
        expect(canCreateDirJunction()).toBe(true);
        const fixture = makeFixture("candidate-junction", `
            process.stdout.write(JSON.stringify({ pass: true }));
        `);
        const target = path.join(fixture.root, "junction-target");
        fs.mkdirSync(target);
        fs.symlinkSync(
            target,
            path.join(fixture.snapshot.path, "escape"),
            "junction",
        );
        await expect(runFixture(fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.FILE_SYMLINK,
        });
        expect(attemptRoots()).toEqual([]);
    });
});

describe.skipIf(typedUnavailable)("Windows sandbox H3 secret and hook isolation", () => {
    it("denies Copilot, profile, git, DPAPI, drive, state, allowlist, and registry reads", async () => {
        const registry = registryFixture();
        const beforeProfiles = ownedSandboxProfiles();
        try {
            let fixture;
            fixture = makeFixture("secret-reads", `
                process.stdout.write(JSON.stringify({ pass: true }));
            `);
            const targets = existingReadTargets(fixture);
            fixture = makeFixture(
                "secret-reads-run",
                secretReadProbeBody(),
                {
                    allowedEnv: {
                        READ_TARGETS_B64: Buffer.from(
                            JSON.stringify(targets),
                            "utf8",
                        ).toString("base64"),
                        REG_EXE: registry.regExe,
                        REG_KEY: registry.key,
                    },
                },
            );
            const result = await runFixture(fixture);
            expectAllCasesTrue(result, [
                ...targets.map(({ id }) => id),
                "registry-secret",
            ]);
            expect(result.parsed.metrics.denied).toBe(
                result.parsed.metrics.attempted,
            );
            expectSandboxCleanup(beforeProfiles);
        } finally {
            registry.cleanup();
        }
    }, 180_000);

    it("minimizes inherited environment and redirects all profile hooks", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        const inherited = {
            AWS_SECRET_ACCESS_KEY: "h3-aws-secret",
            AZURE_CLIENT_SECRET: "h3-azure-secret",
            BASH_ENV: "C:\\host\\bash-hook",
            COPILOT_TOKEN: "h3-copilot-secret",
            ENV: "C:\\host\\shell-hook",
            GIT_ASKPASS: "C:\\host\\git-askpass.exe",
            GIT_CONFIG_GLOBAL: "C:\\host\\gitconfig",
            GITHUB_TOKEN: "h3-github-secret",
            NODE_OPTIONS: "--require=C:\\host\\node-preload.cjs",
            NODE_PATH: "C:\\host\\node-modules",
            NPM_CONFIG_USERCONFIG: "C:\\host\\npmrc",
            PERL5OPT: "-MC:\\host\\perl-hook",
            PSModulePath: "C:\\host\\powershell-modules",
            PYTHONPATH: "C:\\host\\python-modules",
            PYTHONSTARTUP: "C:\\host\\python-startup.py",
            RUBYOPT: "-rC:\\host\\ruby-hook",
            SSH_AUTH_SOCK: "\\\\.\\pipe\\host-ssh-agent",
        };
        const originals = new Map();
        for (const [key, value] of Object.entries(inherited)) {
            originals.set(key, process.env[key]);
            process.env[key] = value;
        }
        try {
            const fixture = makeFixture("environment-hooks", `
                const { spawn } = await import("node:child_process");
                const output = path.resolve(
                    process.env.CRUCIBLE_SANDBOX_OUTPUT,
                );
                const insideOutput = (value) => {
                    if (typeof value !== "string" || value.length === 0) {
                        return false;
                    }
                    const relative = path.relative(output, path.resolve(value));
                    return relative === ""
                        || (
                            !path.isAbsolute(relative)
                            && relative !== ".."
                            && !relative.startsWith(".." + path.sep)
                        );
                };
                const inheritedEnvironment = JSON.parse(
                    Buffer.from(process.env.INHERITED_ENV_B64, "base64")
                        .toString("utf8"),
                );
                const validationCases = {};
                validationCases["inherited-secrets-absent"] =
                    Object.entries(inheritedEnvironment).every(
                        ([key, value]) =>
                            !Object.hasOwn(process.env, key)
                            || process.env[key] !== value,
                    );
                validationCases["search-path-minimized"] =
                    !Object.hasOwn(process.env, "PATH")
                    && !Object.hasOwn(process.env, "PATHEXT");
                validationCases["node-options-pinned"] =
                    process.env.NODE_OPTIONS
                    === "--preserve-symlinks --preserve-symlinks-main";
                validationCases["allowed-env-present"] =
                    process.env.EXPECTED_ALLOWED === "present";
                const profileKeys = [
                    "HOME",
                    "USERPROFILE",
                    "LOCALAPPDATA",
                    "APPDATA",
                    "TEMP",
                    "TMP",
                ];
                for (const key of profileKeys) {
                    validationCases[
                        "profile-" + key.toLowerCase() + "-contained"
                    ] = insideOutput(process.env[key]);
                }
                validationCases["profile-vars-contained"] =
                    profileKeys.every((key) =>
                        insideOutput(process.env[key]));
                const hostProfiles = JSON.parse(
                    Buffer.from(process.env.HOST_PROFILES_B64, "base64")
                        .toString("utf8"),
                ).map((value) => path.resolve(value).toLowerCase());
                validationCases["host-profile-not-selected"] = [
                    process.env.USERPROFILE,
                    process.env.LOCALAPPDATA,
                    process.env.APPDATA,
                ].every((value) =>
                    !hostProfiles.includes(path.resolve(value).toLowerCase()));
                validationCases["staged-executable"] =
                    process.execPath.includes(".crucible-stage-");
                validationCases["staged-cwd"] =
                    process.cwd().includes(".crucible-stage-");
                validationCases["staged-script"] =
                    process.argv[1].includes(".crucible-stage-");
                validationCases["staged-dependency"] =
                    process.argv[2].includes(".crucible-stage-")
                    && fs.readFileSync(process.argv[2], "utf8")
                        === "trusted-dependency";
                const candidate = process.env.CANDIDATE_SNAPSHOT_PATH;
                validationCases["candidate-readable"] =
                    fs.readFileSync(
                        path.join(candidate, "candidate.bin"),
                        "utf8",
                    ) === "immutable-candidate";
                const denied = (operation) => {
                    try {
                        operation();
                        return false;
                    } catch {
                        return true;
                    }
                };
                validationCases["staged-cwd-read-only"] = denied(() =>
                    fs.writeFileSync(
                        path.join(process.cwd(), "candidate-write.txt"),
                        "blocked",
                    ));
                validationCases["candidate-read-only"] = denied(() =>
                    fs.writeFileSync(
                        path.join(candidate, "candidate.bin"),
                        "blocked",
                    ));
                let profileWrites = true;
                for (const key of [
                    "HOME",
                    "USERPROFILE",
                    "LOCALAPPDATA",
                    "APPDATA",
                    "TEMP",
                    "TMP",
                ]) {
                    try {
                        const directory = process.env[key];
                        fs.mkdirSync(directory, { recursive: true });
                        const file = path.join(
                            directory,
                            "h3-" + key.toLowerCase() + ".txt",
                        );
                        fs.writeFileSync(file, key);
                        profileWrites = profileWrites
                            && fs.readFileSync(file, "utf8") === key;
                    } catch {
                        profileWrites = false;
                    }
                }
                validationCases["profile-writes-contained"] = profileWrites;
                const fakeNode = path.join(output, "node.exe");
                fs.writeFileSync(fakeNode, "not an executable");
                const childMarker = path.join(output, "trusted-child.txt");
                const child = await new Promise((resolve) => {
                    let processHandle = null;
                    let settled = false;
                    let timer = null;
                    const finish = (result) => {
                        if (settled) return;
                        settled = true;
                        clearTimeout(timer);
                        resolve(result);
                    };
                    timer = setTimeout(() => {
                        try { processHandle?.kill(); } catch {}
                        processHandle?.unref();
                        finish({ status: null, timedOut: true });
                    }, 3000);
                    try {
                        processHandle = spawn(
                            process.execPath,
                            [
                                "-e",
                                "require('node:fs').writeFileSync("
                                    + "process.argv[1], 'trusted-child')",
                                childMarker,
                            ],
                            {
                                cwd: output,
                                stdio: "ignore",
                                windowsHide: true,
                            },
                        );
                    } catch {
                        finish({ status: null, timedOut: false });
                        return;
                    }
                    processHandle.once("error", () =>
                        finish({ status: null, timedOut: false }));
                    processHandle.once("close", (status) =>
                        finish({ status, timedOut: false }));
                });
                validationCases["absolute-interpreter-staged"] =
                    child.timedOut === false
                    && child.status === 0
                    && fs.existsSync(childMarker)
                    && fs.readFileSync(childMarker, "utf8")
                        === "trusted-child";
                const values = Object.values(validationCases);
                const result = JSON.stringify({
                    pass: values.every(Boolean),
                    metrics: {
                        passed: values.filter(Boolean).length,
                        attempted: values.length,
                    },
                    validationCases,
                });
                process.stdout.write(result, () => process.exit(0));
            `, {
                allowedEnv: {
                    EXPECTED_ALLOWED: "present",
                    HOST_PROFILES_B64: Buffer.from(JSON.stringify([
                        process.env.USERPROFILE,
                        process.env.LOCALAPPDATA,
                        process.env.APPDATA,
                    ])).toString("base64"),
                    INHERITED_ENV_B64: Buffer.from(
                        JSON.stringify(inherited),
                    ).toString("base64"),
                },
                dependencyFiles: [{
                    name: "trusted-dependency.txt",
                    contents: "trusted-dependency",
                }],
            });
            const result = await runFixture(fixture);
            expectAllCasesTrue(result);
            expect(result.parsed.metrics.passed).toBe(
                result.parsed.metrics.attempted,
            );
            expectSandboxCleanup(beforeProfiles);
        } finally {
            for (const [key, value] of originals) {
                if (value === undefined) delete process.env[key];
                else process.env[key] = value;
            }
        }
    }, 180_000);
});

describe.skipIf(typedUnavailable)("Windows sandbox H3 filesystem and IPC containment", () => {
    it("denies outside writes, ADS, hard links, device paths, and reparse escapes", async () => {
        const fixture = makeFixture("filesystem-escapes", `
            const output = process.env.CRUCIBLE_SANDBOX_OUTPUT;
            const outsideDir = process.env.OUTSIDE_DIR;
            const outsideFile = process.env.OUTSIDE_FILE;
            const candidateFile = path.join(
                process.env.CANDIDATE_SNAPSHOT_PATH,
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
            const validationCases = {};
            const outputFile = path.join(output, "inside.txt");
            fs.writeFileSync(outputFile, "inside");
            validationCases["output-write"] =
                fs.readFileSync(outputFile, "utf8") === "inside";
            validationCases["outside-overwrite"] = denied(() =>
                fs.writeFileSync(outsideFile, "escaped"));
            validationCases["outside-create"] = denied(() =>
                fs.writeFileSync(
                    path.join(outsideDir, "created.txt"),
                    "escaped",
                ));
            validationCases["extended-path-write"] = denied(() =>
                fs.writeFileSync("\\\\\\\\?\\\\" + outsideFile, "escaped"));
            validationCases["candidate-write"] = denied(() =>
                fs.writeFileSync(candidateFile, "escaped"));
            validationCases["candidate-ads"] = denied(() =>
                fs.writeFileSync(candidateFile + ":h3", "escaped"));
            validationCases["outside-ads"] = denied(() =>
                fs.writeFileSync(outsideFile + ":h3", "escaped"));
            validationCases["outside-hardlink"] = denied(() =>
                fs.linkSync(outsideFile, path.join(output, "outside-link")));
            validationCases["candidate-hardlink"] = denied(() =>
                fs.linkSync(candidateFile, path.join(output, "candidate-link")));
            const movable = path.join(output, "movable.txt");
            fs.writeFileSync(movable, "inside");
            validationCases["rename-outside"] = denied(() =>
                fs.renameSync(
                    movable,
                    path.join(outsideDir, "renamed.txt"),
                ));
            const junction = path.join(output, "junction");
            let junctionCreated = false;
            try {
                fs.symlinkSync(outsideDir, junction, "junction");
                junctionCreated = true;
            } catch {
                junctionCreated = false;
            }
            validationCases["junction-read-escape"] =
                !junctionCreated
                || denied(() =>
                    fs.readFileSync(
                        path.join(junction, "sentinel.txt"),
                        "utf8",
                    ));
            validationCases["junction-write-escape"] =
                !junctionCreated
                || denied(() =>
                    fs.writeFileSync(
                        path.join(junction, "junction-write.txt"),
                        "escaped",
                    ));
            const fileLink = path.join(output, "file-link.txt");
            let fileLinkCreated = false;
            try {
                fs.symlinkSync(outsideFile, fileLink, "file");
                fileLinkCreated = true;
            } catch {
                fileLinkCreated = false;
            }
            validationCases["symlink-read-escape"] =
                !fileLinkCreated
                || denied(() => fs.readFileSync(fileLink, "utf8"));
            validationCases["symlink-write-escape"] =
                !fileLinkCreated
                || denied(() => fs.writeFileSync(fileLink, "escaped"));
            validationCases["physical-drive-read"] = denied(() => {
                const fd = fs.openSync("\\\\\\\\.\\\\PhysicalDrive0", "r");
                fs.closeSync(fd);
            });
            validationCases["missing-pipe-write"] = denied(() =>
                fs.writeFileSync(
                    "\\\\\\\\.\\\\pipe\\\\crucible-h3-no-such-pipe",
                    "escaped",
                ));
            let outputAds = false;
            try {
                const stream = outputFile + ":contained";
                fs.writeFileSync(stream, "inside-ads");
                outputAds = fs.readFileSync(stream, "utf8") === "inside-ads";
            } catch {
                outputAds = false;
            }
            validationCases["output-ads-contained"] = outputAds;
            const values = Object.values(validationCases);
            process.stdout.write(JSON.stringify({
                pass: values.every(Boolean),
                metrics: {
                    passed: values.filter(Boolean).length,
                    attempted: values.length,
                },
                validationCases,
            }));
        `, {
            prepareRoot(root) {
                const outsideDir = path.join(root, "outside-private");
                const outsideFile = path.join(outsideDir, "sentinel.txt");
                fs.mkdirSync(outsideDir);
                fs.writeFileSync(outsideFile, "host-sentinel");
                return {
                    allowedEnv: {
                        OUTSIDE_DIR: outsideDir,
                        OUTSIDE_FILE: outsideFile,
                    },
                    outsideDir,
                    outsideFile,
                };
            },
        });
        const result = await runFixture(fixture);
        expectAllCasesTrue(result);
        expect(result.parsed.metrics.passed).toBe(
            result.parsed.metrics.attempted,
        );
        expect(fs.readFileSync(fixture.prepared.outsideFile, "utf8"))
            .toBe("host-sentinel");
        expect(fs.readdirSync(fixture.prepared.outsideDir).sort())
            .toEqual(["sentinel.txt"]);
        expect(fs.existsSync(`${fixture.prepared.outsideFile}:h3`)).toBe(false);
        expect(attemptRoots()).toEqual([]);
    }, 180_000);

    it("denies localhost, outbound TCP, DNS, HTTP, and host named pipes", async () => {
        let tcpAccepted = 0;
        let pipeAccepted = 0;
        const httpServer = http.createServer((_request, response) => {
            response.writeHead(200, { "content-type": "text/plain" });
            response.end("host-http");
        });
        httpServer.on("connection", (socket) => {
            tcpAccepted += 1;
            socket.destroy();
        });
        await listen(httpServer, { host: "127.0.0.1", port: 0 });
        const address = httpServer.address();
        const pipeName = `\\\\.\\pipe\\crucible-h3-${process.pid}-${randomBytes(6).toString("hex")}`;
        const pipeServer = net.createServer((socket) => {
            pipeAccepted += 1;
            socket.destroy();
        });
        await listen(pipeServer, pipeName);
        try {
            const fixture = makeFixture("network-ipc", `
                const dns = await import("node:dns");
                const http = await import("node:http");
                const net = await import("node:net");
                const deniedConnection = (options) =>
                    new Promise((resolve) => {
                        let settled = false;
                        const finish = (value) => {
                            if (settled) return;
                            settled = true;
                            resolve(value);
                        };
                        let socket;
                        try {
                            socket = net.createConnection(options);
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
                        }, 1800);
                    });
                const deniedHttp = (url) =>
                    new Promise((resolve) => {
                        let settled = false;
                        const finish = (value) => {
                            if (settled) return;
                            settled = true;
                            resolve(value);
                        };
                        let request;
                        try {
                            request = http.get(url, (response) => {
                                response.destroy();
                                finish(false);
                            });
                        } catch {
                            finish(true);
                            return;
                        }
                        request.once("error", () => finish(true));
                        request.setTimeout(1800, () => {
                            request.destroy();
                            finish(true);
                        });
                    });
                const deniedDns = (method) =>
                    new Promise((resolve) => {
                        let settled = false;
                        const finish = (value) => {
                            if (settled) return;
                            settled = true;
                            resolve(value);
                        };
                        const timer = setTimeout(() => finish(true), 2000);
                        method((error, value) => {
                            clearTimeout(timer);
                            finish(Boolean(error) || value == null);
                        });
                    });
                const validationCases = {};
                validationCases["localhost-tcp"] = await deniedConnection({
                    host: "127.0.0.1",
                    port: Number(process.env.LOCAL_PORT),
                });
                validationCases["localhost-http"] = await deniedHttp(
                    "http://127.0.0.1:" + process.env.LOCAL_PORT + "/",
                );
                validationCases["outbound-tcp"] = await deniedConnection({
                    host: "1.1.1.1",
                    port: 443,
                });
                validationCases["dns-resolve"] = await deniedDns((done) =>
                    dns.resolve4("example.com", done));
                validationCases["dns-lookup"] = await deniedDns((done) =>
                    dns.lookup("example.com", done));
                validationCases["named-pipe"] = await deniedConnection(
                    process.env.PIPE_NAME,
                );
                const values = Object.values(validationCases);
                process.stdout.write(JSON.stringify({
                    pass: values.every(Boolean),
                    metrics: {
                        denied: values.filter(Boolean).length,
                        attempted: values.length,
                    },
                    validationCases,
                }));
            `, {
                allowedEnv: {
                    LOCAL_PORT: String(address.port),
                    PIPE_NAME: pipeName,
                },
                timeoutMs: 20_000,
            });
            const result = await runFixture(fixture);
            expectAllCasesTrue(result);
            expect(result.parsed.metrics.denied)
                .toBe(result.parsed.metrics.attempted);
            expect(tcpAccepted).toBe(0);
            expect(pipeAccepted).toBe(0);
            expect(attemptRoots()).toEqual([]);
        } finally {
            await Promise.all([
                closeServer(httpServer),
                closeServer(pipeServer),
            ]);
        }
    }, 180_000);
});

describe.skipIf(typedUnavailable)("Windows sandbox H3 process and resource containment", () => {
    it("kills detached children and grandchildren when the root exits", async () => {
        const grandchildCode = "setInterval(() => {}, 1000);";
        const childCode = `
            const fs = require("node:fs");
            const { spawn } = require("node:child_process");
            const marker = process.argv[1];
            const grandchild = spawn(
                process.execPath,
                ["-e", ${JSON.stringify(grandchildCode)}],
                { detached: true, stdio: "ignore", windowsHide: true },
            );
            grandchild.on("error", () => {});
            grandchild.unref();
            fs.writeFileSync(
                marker,
                JSON.stringify({ pid: grandchild.pid ?? 0 }),
            );
            setInterval(() => {}, 1000);
        `;
        const fixture = makeFixture("grandchild-cleanup", `
            const { spawn } = await import("node:child_process");
            const marker = path.join(
                process.env.CRUCIBLE_SANDBOX_OUTPUT,
                "grandchild.json",
            );
            const child = spawn(
                process.execPath,
                ["-e", ${JSON.stringify(childCode)}, marker],
                { detached: true, stdio: "ignore", windowsHide: true },
            );
            child.on("error", () => {});
            child.unref();
            const deadline = Date.now() + 5000;
            while (!fs.existsSync(marker) && Date.now() < deadline) {
                await new Promise((resolve) => setTimeout(resolve, 50));
            }
            let grandchildPid = 0;
            if (fs.existsSync(marker)) {
                grandchildPid = JSON.parse(
                    fs.readFileSync(marker, "utf8"),
                ).pid;
            }
            process.stdout.write(JSON.stringify({
                pass: Number.isInteger(child.pid)
                    && child.pid > 0
                    && Number.isInteger(grandchildPid)
                    && grandchildPid > 0,
                metrics: {
                    childPid: child.pid ?? 0,
                    grandchildPid,
                },
            }));
        `);
        let childPid = 0;
        let grandchildPid = 0;
        try {
            const result = await runFixture(fixture);
            expect(result.parsed.pass).toBe(true);
            childPid = result.parsed.metrics.childPid;
            grandchildPid = result.parsed.metrics.grandchildPid;
            expect(await waitForPidExit(childPid)).toBe(true);
            expect(await waitForPidExit(grandchildPid)).toBe(true);
            expect(attemptRoots()).toEqual([]);
        } finally {
            forceKillPid(childPid);
            forceKillPid(grandchildPid);
        }
    }, 180_000);

    it("enforces the active process limit during fork pressure", async () => {
        const fixture = makeFixture("process-limit", `
            const { spawn } = await import("node:child_process");
            const children = [];
            for (let index = 0; index < 12; index += 1) {
                try {
                    const child = spawn(
                        process.execPath,
                        ["-e", "setInterval(() => {}, 1000)"],
                        {
                            detached: true,
                            stdio: "ignore",
                            windowsHide: true,
                        },
                    );
                    child.on("error", () => {});
                    child.unref();
                    children.push(child);
                } catch {
                    children.push(null);
                }
            }
            await new Promise((resolve) => setTimeout(resolve, 1200));
            const alive = children.filter((child) =>
                child !== null
                && Number.isInteger(child.pid)
                && child.exitCode === null).length;
            const firstAlive = children.find((child) =>
                child !== null
                && Number.isInteger(child.pid)
                && child.exitCode === null);
            process.stdout.write(JSON.stringify({
                pass: alive <= 2 && alive < children.length,
                metrics: {
                    alive,
                    attempted: children.length,
                    survivorPid: firstAlive?.pid ?? 0,
                },
            }));
        `, {
            limits: {
                activeProcessLimit: 3,
            },
        });
        let survivorPid = 0;
        try {
            const result = await runFixture(fixture);
            expect(result.parsed.pass).toBe(true);
            expect(result.parsed.metrics.alive).toBeLessThanOrEqual(2);
            expect(result.parsed.metrics.alive)
                .toBeLessThan(result.parsed.metrics.attempted);
            survivorPid = result.parsed.metrics.survivorPid;
            if (survivorPid > 0) {
                expect(await waitForPidExit(survivorPid)).toBe(true);
            }
            expect(attemptRoots()).toEqual([]);
        } finally {
            forceKillPid(survivorPid);
        }
    }, 180_000);

    it("enforces process/job memory caps", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        const fixture = makeFixture("memory-limit", `
            const allocations = [];
            while (true) {
                allocations.push(Buffer.alloc(16 * 1024 * 1024, 0x5a));
            }
        `, {
            limits: {
                processMemoryBytes: 256 * 1024 * 1024,
                jobMemoryBytes: 320 * 1024 * 1024,
                wallTimeMs: 15_000,
            },
            timeoutMs: 25_000,
        });
        const started = Date.now();
        await expect(runFixture(fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.NONZERO_EXIT,
        });
        expect(Date.now() - started).toBeLessThan(20_000);
        expectSandboxCleanup(beforeProfiles);
    }, 180_000);

    it("enforces native wall time before the executor timeout", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        let exitEvent = null;
        const fixture = makeFixture("wall-limit", `
            setInterval(() => {}, 1000);
        `, {
            faultInjector(point, details) {
                if (point === "after_harness_exit") exitEvent = details;
            },
            limits: {
                cpuRatePercent: 100,
                cpuTimeMs: 30_000,
                wallTimeMs: 5_000,
            },
            timeoutMs: 15_000,
        });
        const started = Date.now();
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
            },
        });
        const effectiveWallTimeMs =
            error.details.receipt.sandbox.policy.effectiveJob.wallTimeMs;
        expect(effectiveWallTimeMs).toBeGreaterThan(0);
        expect(effectiveWallTimeMs).toBeLessThanOrEqual(5_000);
        expect(exitEvent).toMatchObject({
            exit: { code: 124, signal: null },
            timedOut: false,
            overflowStreams: [],
        });
        expect(Date.now() - started).toBeLessThan(20_000);
        expectSandboxCleanup(beforeProfiles);
    }, 180_000);

    it("cleans the profile after an executor timeout", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        const fixture = makeFixture("executor-timeout-cleanup", `
            setInterval(() => {}, 1000);
        `, {
            limits: {
                wallTimeMs: 30_000,
            },
            timeoutMs: 1_000,
        });
        const started = Date.now();
        await expect(runFixture(fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.TIMEOUT,
        });
        expect(Date.now() - started).toBeLessThan(10_000);
        expectSandboxCleanup(beforeProfiles);
    }, 180_000);

    it("enforces stdout caps and cleans the Job Object", async () => {
        const beforeProfiles = ownedSandboxProfiles();
        const fixture = makeFixture("output-limit", `
            const chunk = "x".repeat(64 * 1024);
            while (true) process.stdout.write(chunk);
        `, {
            maxStdoutBytes: 4 * 1024,
            timeoutMs: 15_000,
        });
        await expect(runFixture(fixture)).rejects.toMatchObject({
            code: MEASUREMENT_ERROR_CODES.OUTPUT_OVERFLOW,
            details: {
                stream: "stdout",
            },
        });
        expectSandboxCleanup(beforeProfiles);
    }, 180_000);
});
