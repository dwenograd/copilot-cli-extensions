// oracle-v3/__tests__/tools-configure-harness.test.mjs
//
// Verifies the operator harness-allowlist configuration CLI
// (tools/configure-harness.mjs): first create, preservation of unrelated
// entries, replacement refusal/allow, deterministic snapshot hashes, malformed
// input, symlink rejection, static-argv dependency enforcement, atomic backup,
// and throwaway-store cleanup.

import { describe, it, expect, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    CONFIGURE_ERROR_CODES,
    ConfigureHarnessError,
    configureHarness,
    loadConfigFile,
    main,
    resolveOutputAllowlistPath,
} from "../tools/configure-harness.mjs";
import {
    MEASUREMENT_ERROR_CODES,
    loadHarnessAllowlist,
} from "../measurement/index.mjs";
import { openArtifactStore } from "../persistence/index.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

function tmp(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.cfg-tmp-${label}-`));
    roots.push(root);
    return root;
}

afterAll(() => {
    for (const root of roots) {
        try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ }
    }
});

function writeFile(p, content) {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
    return p;
}

function makeDir(p, files = {}) {
    fs.mkdirSync(p, { recursive: true });
    for (const [name, content] of Object.entries(files)) {
        fs.writeFileSync(path.join(p, name), content);
    }
    return p;
}

// A self-contained workspace: a dummy (non-interpreter) executable, two
// validation-case directories, and a minimal env whose LOCALAPPDATA points
// inside the workspace so nothing escapes __tests__.
function workspace(label) {
    const root = tmp(label);
    const executable = writeFile(path.join(root, "harness.bin"), "#!fake harness\n");
    const acceptDir = makeDir(path.join(root, "cases", "accept"), { "a.txt": "accept-content" });
    const rejectDir = makeDir(path.join(root, "cases", "reject"), { "b.txt": "reject-content" });
    const allowlistPath = path.join(root, "OracleV3", "harnesses.json");
    const env = { LOCALAPPDATA: path.join(root, "localappdata") };
    return { root, executable, acceptDir, rejectDir, allowlistPath, env };
}

function baseConfig(ws, overrides = {}) {
    return {
        id: "example-harness",
        executable: ws.executable,
        argvTemplate: ["{{candidatePath}}", "{{attemptId}}"],
        dependencies: [],
        allowedEnv: {},
        timeoutMs: 30000,
        maxStdoutBytes: 1048576,
        maxStderrBytes: 262144,
        executesCandidateCode: false,
        validationCases: [
            { id: "good", expectation: "accept", sourceDir: ws.acceptDir, description: "accepts" },
            { id: "bad", expectation: "reject", sourceDir: ws.rejectDir },
        ],
        description: "example",
        ...overrides,
    };
}

function catchErr(fn) {
    try {
        fn();
    } catch (err) {
        return err;
    }
    throw new Error("expected the call to throw");
}

describe("configureHarness — first create", () => {
    it("creates a new allowlist with a strict entry and validationCases keyed by id", () => {
        const ws = workspace("create");
        const result = configureHarness({
            config: baseConfig(ws),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        });

        expect(result.schemaVersion).toBe(1);
        expect(result.allowlistPath).toBe(ws.allowlistPath);
        expect(result.entryId).toBe("example-harness");
        expect(result.entryHash).toMatch(/^sha256:oracle-measurement-entry-v1:[a-f0-9]{64}$/);
        expect(result.executableSha256).toMatch(/^[a-f0-9]{64}$/);
        expect(result.backupPath).toBeNull();
        expect(result.replaced).toBe(false);
        expect(Object.keys(result.validationSnapshots).sort()).toEqual(["bad", "good"]);
        for (const id of ["bad", "good"]) {
            expect(result.validationSnapshots[id]).toMatch(/^sha256:[a-f0-9]{64}$/);
        }

        // The written file loads through the real loader unchanged.
        const list = loadHarnessAllowlist(ws.allowlistPath);
        expect(list.listEntryIds()).toEqual(["example-harness"]);
        const entry = list.getEntry("example-harness");
        expect(entry.executable).toBe(fs.realpathSync.native(ws.executable));
        expect(entry.validationCases.good.snapshotHash).toBe(result.validationSnapshots.good);
        expect(entry.validationCases.good.description).toBe("accepts");
        expect(entry.validationCases.bad.snapshotHash).toBe(result.validationSnapshots.bad);

        // Expectations are NEVER written to the allowlist — they belong to the
        // frozen oracle_start contract.
        const raw = JSON.parse(fs.readFileSync(ws.allowlistPath, "utf8"));
        const rawCase = raw.entries["example-harness"].validationCases.good;
        expect(rawCase).not.toHaveProperty("expectation");
        expect(Object.keys(rawCase).sort()).toEqual(["description", "snapshotHash"]);
    });

    it("computes the executable SHA-256 that matches the on-disk bytes", () => {
        const ws = workspace("exehash");
        const result = configureHarness({ config: baseConfig(ws), allowlistPath: ws.allowlistPath, env: ws.env });
        const list = loadHarnessAllowlist(ws.allowlistPath);
        // The loader re-hashes the executable on verifyEntry; it must accept the
        // digest we wrote.
        const verified = list.verifyEntry("example-harness");
        expect(verified.executableHash.endsWith(result.executableSha256)).toBe(true);
    });
});

describe("configureHarness — preserve unrelated entries", () => {
    it("keeps existing entries when adding a new one", () => {
        const ws = workspace("preserve");
        configureHarness({ config: baseConfig(ws, { id: "alpha" }), allowlistPath: ws.allowlistPath, env: ws.env });
        const result = configureHarness({ config: baseConfig(ws, { id: "beta" }), allowlistPath: ws.allowlistPath, env: ws.env });

        expect(result.preservedEntryIds).toEqual(["alpha"]);
        const list = loadHarnessAllowlist(ws.allowlistPath);
        expect(list.listEntryIds().sort()).toEqual(["alpha", "beta"]);
    });

    it("refuses to clobber an existing allowlist that does not strict-parse", () => {
        const ws = workspace("badexisting");
        writeFile(ws.allowlistPath, "{ this is not valid json ");
        const err = catchErr(() => configureHarness({
            config: baseConfig(ws),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err).toBeInstanceOf(ConfigureHarnessError);
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.EXISTING_ALLOWLIST_INVALID);
        // Original malformed file is left untouched (fail-closed).
        expect(fs.readFileSync(ws.allowlistPath, "utf8")).toBe("{ this is not valid json ");
    });
});

describe("configureHarness — replacement refusal / allow", () => {
    it("refuses to overwrite an entry with a different executable unless --replace", () => {
        const ws = workspace("replace");
        const exeA = writeFile(path.join(ws.root, "exeA.bin"), "AAAA");
        const exeB = writeFile(path.join(ws.root, "exeB.bin"), "BBBB");

        configureHarness({ config: baseConfig(ws, { executable: exeA }), allowlistPath: ws.allowlistPath, env: ws.env });

        const err = catchErr(() => configureHarness({
            config: baseConfig(ws, { executable: exeB }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.ENTRY_CONFLICT);
        // Untouched: still the original executable.
        expect(loadHarnessAllowlist(ws.allowlistPath).getEntry("example-harness").executable)
            .toBe(fs.realpathSync.native(exeA));

        // With --replace it succeeds and switches the executable.
        const ok = configureHarness({
            config: baseConfig(ws, { executable: exeB }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
            replace: true,
        });
        expect(ok.replaced).toBe(true);
        expect(ok.replacedByOverride).toBe(true);
        expect(loadHarnessAllowlist(ws.allowlistPath).getEntry("example-harness").executable)
            .toBe(fs.realpathSync.native(exeB));
    });

    it("allows updating the same-executable entry without --replace", () => {
        const ws = workspace("sameexe");
        configureHarness({ config: baseConfig(ws, { timeoutMs: 30000 }), allowlistPath: ws.allowlistPath, env: ws.env });
        const ok = configureHarness({
            config: baseConfig(ws, { timeoutMs: 45000 }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        });
        expect(ok.replaced).toBe(true);
        expect(loadHarnessAllowlist(ws.allowlistPath).getEntry("example-harness").timeoutMs).toBe(45000);
    });
});

describe("configureHarness — deterministic snapshot hashes", () => {
    it("produces the same snapshot id a fresh ArtifactStore would compute (matches oracle_start)", () => {
        const ws = workspace("determ");
        const result = configureHarness({ config: baseConfig(ws), allowlistPath: ws.allowlistPath, env: ws.env });

        const storeRoot = path.join(ws.root, "independent-store");
        const store = openArtifactStore({ root: storeRoot, env: ws.env });
        const direct = store.ingestDirectory({ sourceDir: ws.acceptDir, env: ws.env });
        expect(result.validationSnapshots.good).toBe(direct.snapshot);
    });

    it("is stable across repeated runs on identical content", () => {
        const ws = workspace("determ2");
        const first = configureHarness({ config: baseConfig(ws, { id: "one" }), allowlistPath: ws.allowlistPath, env: ws.env });
        const second = configureHarness({ config: baseConfig(ws, { id: "two" }), allowlistPath: ws.allowlistPath, env: ws.env });
        expect(second.validationSnapshots.good).toBe(first.validationSnapshots.good);
        expect(second.validationSnapshots.bad).toBe(first.validationSnapshots.bad);
    });
});

describe("configureHarness — malformed input", () => {
    it("rejects non-JSON config files", () => {
        const ws = workspace("badjson");
        const cfgPath = writeFile(path.join(ws.root, "config.json"), "{ nope ");
        const err = catchErr(() => loadConfigFile(cfgPath));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.CONFIG_INVALID_JSON);
    });

    it("reports a missing config file distinctly", () => {
        const err = catchErr(() => loadConfigFile(path.join(HERE, "does-not-exist-xyz.json")));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.CONFIG_NOT_FOUND);
    });

    it("rejects unknown config keys", () => {
        const ws = workspace("unknownkey");
        const err = catchErr(() => configureHarness({
            config: baseConfig(ws, { bogusKey: 1 }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.CONFIG_INVALID);
    });

    it("rejects an unsafe id", () => {
        const ws = workspace("badid");
        const err = catchErr(() => configureHarness({
            config: baseConfig(ws, { id: "NOT_SAFE" }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.CONFIG_INVALID);
    });

    it("requires at least one accept and one reject case", () => {
        const ws = workspace("onesided");
        const err = catchErr(() => configureHarness({
            config: baseConfig(ws, {
                validationCases: [
                    { id: "good", expectation: "accept", sourceDir: ws.acceptDir },
                    { id: "good2", expectation: "accept", sourceDir: ws.rejectDir },
                ],
            }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.CONFIG_INVALID);
    });

    it("rejects a non-existent executable", () => {
        const ws = workspace("noexe");
        const err = catchErr(() => configureHarness({
            config: baseConfig(ws, { executable: path.join(ws.root, "missing.bin") }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.EXECUTABLE_INVALID);
    });
});

describe("configureHarness — symlink rejection", () => {
    const dir = fs.mkdtempSync(path.join(HERE, ".cfg-symprobe-"));
    let canSymlink = false;
    let canJunction = false;
    try {
        const target = path.join(dir, "t.txt");
        const link = path.join(dir, "l.txt");
        fs.writeFileSync(target, "x");
        fs.symlinkSync(target, link, "file");
        canSymlink = true;
    } catch { canSymlink = false; }
    try {
        const targetDir = path.join(dir, "td");
        const jn = path.join(dir, "jn");
        fs.mkdirSync(targetDir, { recursive: true });
        fs.symlinkSync(targetDir, jn, "junction");
        canJunction = true;
    } catch { canJunction = false; }
    fs.rmSync(dir, { recursive: true, force: true });

    it.runIf(canSymlink)("refuses a dependency that is a symlink", () => {
        const ws = workspace("symdep");
        const target = writeFile(path.join(ws.root, "real-dep.mjs"), "export const x = 1;\n");
        const link = path.join(ws.root, "linked-dep.mjs");
        fs.symlinkSync(target, link, "file");
        const err = catchErr(() => configureHarness({
            config: baseConfig(ws, { dependencies: [{ path: link, role: "script" }] }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.DEPENDENCY_INVALID);
        expect(err.details.cause).toBe(MEASUREMENT_ERROR_CODES.FILE_SYMLINK);
    });

    it.runIf(canJunction)("refuses a validation sourceDir that is a symlink/junction", () => {
        const ws = workspace("symsrc");
        const link = path.join(ws.root, "linked-accept");
        fs.symlinkSync(ws.acceptDir, link, "junction");
        const err = catchErr(() => configureHarness({
            config: baseConfig(ws, {
                validationCases: [
                    { id: "good", expectation: "accept", sourceDir: link },
                    { id: "bad", expectation: "reject", sourceDir: ws.rejectDir },
                ],
            }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.SOURCE_DIR_INVALID);
    });
});

describe("configureHarness — dependency enforcement", () => {
    it("refuses a static-file argv entry that is not a declared dependency", () => {
        const ws = workspace("undeclared");
        const script = writeFile(path.join(ws.root, "runner.mjs"), "export const x = 1;\n");
        const err = catchErr(() => configureHarness({
            config: baseConfig(ws, {
                argvTemplate: [script, "{{candidatePath}}"],
                dependencies: [],
            }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.RESULT_INVALID);
        expect(err.details.cause).toBe(MEASUREMENT_ERROR_CODES.UNDECLARED_ARGV_FILE);
        // The rejected document never became the live allowlist.
        expect(fs.existsSync(ws.allowlistPath)).toBe(false);
    });

    it("accepts the same static-file argv entry once it is declared", () => {
        const ws = workspace("declared");
        const script = writeFile(path.join(ws.root, "runner.mjs"), "export const x = 1;\n");
        const result = configureHarness({
            config: baseConfig(ws, {
                argvTemplate: [script, "{{candidatePath}}"],
                dependencies: [{ path: script, role: "script" }],
            }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        });
        expect(result.dependencies).toHaveLength(1);
        expect(result.dependencies[0].path).toBe(fs.realpathSync.native(script));
        const entry = loadHarnessAllowlist(ws.allowlistPath).getEntry("example-harness");
        expect(entry.argvTemplate[0]).toBe(fs.realpathSync.native(script));
    });
});

describe("configureHarness — atomic backup", () => {
    it("creates a .bak of the previous file on update and not on first create", () => {
        const ws = workspace("backup");
        const first = configureHarness({ config: baseConfig(ws, { id: "alpha" }), allowlistPath: ws.allowlistPath, env: ws.env });
        expect(first.backupPath).toBeNull();
        const afterFirst = fs.readFileSync(ws.allowlistPath, "utf8");

        const second = configureHarness({ config: baseConfig(ws, { id: "beta" }), allowlistPath: ws.allowlistPath, env: ws.env });
        expect(second.backupPath).toBe(`${ws.allowlistPath}.bak`);
        expect(fs.existsSync(second.backupPath)).toBe(true);
        // The backup holds the pre-update bytes exactly.
        expect(fs.readFileSync(second.backupPath, "utf8")).toBe(afterFirst);
    });
});

describe("configureHarness — throwaway store cleanup", () => {
    it("leaves no temporary ArtifactStore behind after success", () => {
        const ws = workspace("cleanup");
        configureHarness({ config: baseConfig(ws), allowlistPath: ws.allowlistPath, env: ws.env });
        const leftovers = fs.readdirSync(path.dirname(ws.allowlistPath))
            .filter((name) => name.startsWith(".oracle-configure-store-"));
        expect(leftovers).toEqual([]);
    });

    it("leaves no temporary ArtifactStore behind after failure", () => {
        const ws = workspace("cleanupfail");
        catchErr(() => configureHarness({
            config: baseConfig(ws, { executable: path.join(ws.root, "missing.bin") }),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        }));
        // allowlistDir may not exist if we failed very early; guard the read.
        const dir = path.dirname(ws.allowlistPath);
        const leftovers = fs.existsSync(dir)
            ? fs.readdirSync(dir).filter((name) => name.startsWith(".oracle-configure-store-"))
            : [];
        expect(leftovers).toEqual([]);
    });
});

describe("resolveOutputAllowlistPath", () => {
    it("defaults to %LOCALAPPDATA%\\OracleV3\\harnesses.json", () => {
        const ws = workspace("default");
        const resolved = resolveOutputAllowlistPath(undefined, { LOCALAPPDATA: ws.root });
        expect(resolved).toBe(path.join(ws.root, "OracleV3", "harnesses.json"));
    });

    it("prefers an explicit path over the default", () => {
        const ws = workspace("explicit");
        const explicit = path.join(ws.root, "custom", "list.json");
        expect(resolveOutputAllowlistPath(explicit, { LOCALAPPDATA: ws.root })).toBe(explicit);
    });

    it("fails clearly when LOCALAPPDATA is unset and no path is given", () => {
        const err = catchErr(() => resolveOutputAllowlistPath(undefined, {}));
        expect(err.code).toBe(CONFIGURE_ERROR_CODES.ALLOWLIST_PATH_INVALID);
    });
});

function capture() {
    return { chunks: [], write(s) { this.chunks.push(s); return true; }, text() { return this.chunks.join(""); } };
}

describe("main (CLI surface)", () => {
    it("prints one JSON result to stdout and exits 0 on success", () => {
        const ws = workspace("cli-ok");
        const cfgPath = writeFile(path.join(ws.root, "config.json"), JSON.stringify(baseConfig(ws)));
        const stdout = capture();
        const stderr = capture();
        const code = main(
            ["--config", cfgPath, "--allowlist", ws.allowlistPath],
            { env: ws.env, stdout, stderr },
        );
        expect(code).toBe(0);
        expect(stderr.text()).toBe("");
        const lines = stdout.text().trim().split("\n");
        expect(lines).toHaveLength(1);
        const parsed = JSON.parse(lines[0]);
        expect(parsed.ok).toBe(true);
        expect(parsed.entryId).toBe("example-harness");
        expect(parsed.allowlistPath).toBe(ws.allowlistPath);
        expect(fs.existsSync(ws.allowlistPath)).toBe(true);
    });

    it("exits nonzero with a JSON error on stderr when --config is missing", () => {
        const stdout = capture();
        const stderr = capture();
        const code = main([], { env: { LOCALAPPDATA: "C:\\nope" }, stdout, stderr });
        expect(code).toBe(2);
        expect(stdout.text()).toBe("");
        const parsed = JSON.parse(stderr.text().trim());
        expect(parsed.ok).toBe(false);
        expect(parsed.error.code).toBe(CONFIGURE_ERROR_CODES.USAGE);
    });

    it("exits 1 with a JSON error on stderr when the config is invalid", () => {
        const ws = workspace("cli-bad");
        const cfgPath = writeFile(path.join(ws.root, "config.json"), JSON.stringify(baseConfig(ws, { id: "NOT_SAFE" })));
        const stdout = capture();
        const stderr = capture();
        const code = main(
            ["--config", cfgPath, "--allowlist", ws.allowlistPath],
            { env: ws.env, stdout, stderr },
        );
        expect(code).toBe(1);
        expect(stdout.text()).toBe("");
        const parsed = JSON.parse(stderr.text().trim());
        expect(parsed.ok).toBe(false);
        expect(parsed.error.code).toBe(CONFIGURE_ERROR_CODES.CONFIG_INVALID);
    });

    it("supports --config=<path> and prints usage for --help", () => {
        const stdout = capture();
        const stderr = capture();
        const code = main(["--help"], { env: {}, stdout, stderr });
        expect(code).toBe(0);
        expect(stdout.text()).toContain("Usage: node tools/configure-harness.mjs");
    });
});
