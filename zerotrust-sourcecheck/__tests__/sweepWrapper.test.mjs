// __tests__/sweepWrapper.test.mjs
//
// Tests for safeWrappers/sweepWrapper.mjs (the zerotrust_sweep_audit_scratch tool).
// Cleans up stray scratch files left at the top level of build_root and its
// immediate parent dir at the end of an audit.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";

import {
    sweepAuditScratchHandler,
    __internals as sweepInternals,
} from "../safeWrappers/sweepWrapper.mjs";
import { activateAudit, deactivateAudit } from "../enforcement.mjs";

// Layout used in these tests:
//   <tmp>/parent_<run>/
//     scratch_in_parent.txt        ← should be swept when also_sweep_parent
//     README.md                    ← legitimate
//     build/                       ← the build_root for the test
//       README.md                  ← legitimate
//       .gitignore                 ← legitimate
//       agent_scratch.txt        ← scratch
//       BootEncryption.cpp         ← scratch (source file dropped by agent)
//       _audit_dlgcode.c           ← scratch
//       _reports/                  ← subdir; must NOT be swept
//         keep_me.md
//       canonical-clone-abc1234/   ← subdir; must NOT be swept

const RUN_ID = Date.now() + "-" + Math.random().toString(36).slice(2, 8);
const PARENT = join(tmpdir(), `zerotrust-sweep-${RUN_ID}`);
const BR = join(PARENT, "build");
const SESSION = `sweep-test-${RUN_ID}`;

// Round-17: tests must register an audit so sweep recognises BR as
// the active-audit anchor. Without this, sweep refuses agent-supplied
// build_root that doesn't match DEFAULT_BUILD_ROOT (a production
// safety-net check). Real callers always have an active audit when
// sweep runs (it's the last step before reporting), so this mirrors
// production behaviour.
function registerSweepAudit() {
    activateAudit({
        sessionId: SESSION,
        buildPath: BR,
        mode: "audit_source_council",
        expectedClonePath: join(BR, "octocat-Hello-aaaaaaa"),
        owner: "octocat",
        repo: "Hello",
        ref: "main",
        refType: "ref",
    });
}

function setupTree() {
    if (existsSync(PARENT)) rmSync(PARENT, { recursive: true, force: true });
    mkdirSync(BR, { recursive: true });
    registerSweepAudit();
    // Parent-level files
    writeFileSync(join(PARENT, "scratch_in_parent.txt"), "scratch");
    writeFileSync(join(PARENT, "README.md"), "# legit");
    // Build-root-level files
    writeFileSync(join(BR, "README.md"), "# legit");
    writeFileSync(join(BR, ".gitignore"), "node_modules\n");
    writeFileSync(join(BR, "package.json"), "{}");
    writeFileSync(join(BR, "agent_scratch.txt"), "list of paths\n");
    writeFileSync(join(BR, "BootEncryption.cpp"), "// source dropped by agent");
    writeFileSync(join(BR, "_audit_dlgcode.c"), "// audit scratch");
    // Subdirs that must NOT be swept
    mkdirSync(join(BR, "_reports"), { recursive: true });
    writeFileSync(join(BR, "_reports", "keep_me.md"), "# preserved");
    mkdirSync(join(BR, "canonical-clone-abc1234"), { recursive: true });
    writeFileSync(join(BR, "canonical-clone-abc1234", "marker.txt"), "marker");
}

test.afterEach(() => {
    deactivateAudit(SESSION);
    if (existsSync(PARENT)) rmSync(PARENT, { recursive: true, force: true });
});

// ---------- happy paths ----------

test("dry_run lists scratch files without deleting", async () => {
    setupTree();
    const r = await sweepAuditScratchHandler({
        build_root: BR,
        dry_run: true,
    }, { sessionId: SESSION });
    assert.equal(r.resultType, "success");
    const data = JSON.parse(r.textResultForLlm);
    assert.equal(data.ok, true);
    assert.equal(data.dryRun, true);

    // Scratch in build_root must be reported, legitimate files must not.
    assert.ok(data.found.includes(join(BR, "agent_scratch.txt")));
    assert.ok(data.found.includes(join(BR, "BootEncryption.cpp")));
    assert.ok(data.found.includes(join(BR, "_audit_dlgcode.c")));
    assert.ok(data.found.includes(join(PARENT, "scratch_in_parent.txt")));
    assert.ok(!data.found.includes(join(BR, "README.md")));
    assert.ok(!data.found.includes(join(BR, ".gitignore")));
    assert.ok(!data.found.includes(join(BR, "package.json")));
    assert.ok(!data.found.includes(join(PARENT, "README.md")));

    // Nothing should be deleted.
    assert.ok(existsSync(join(BR, "agent_scratch.txt")));
    assert.ok(existsSync(join(BR, "BootEncryption.cpp")));
    assert.ok(existsSync(join(PARENT, "scratch_in_parent.txt")));

    assert.equal(data.removed, null);
    assert.equal(data.removedCount, 0);
    assert.equal(data.foundCount, data.found.length);
});

test("default (non-dry-run) deletes scratch files", async () => {
    setupTree();
    const r = await sweepAuditScratchHandler({ build_root: BR }, { sessionId: SESSION });
    assert.equal(r.resultType, "success");
    const data = JSON.parse(r.textResultForLlm);
    assert.equal(data.ok, true);
    assert.equal(data.dryRun, false);

    // Scratch files: gone.
    assert.ok(!existsSync(join(BR, "agent_scratch.txt")));
    assert.ok(!existsSync(join(BR, "BootEncryption.cpp")));
    assert.ok(!existsSync(join(BR, "_audit_dlgcode.c")));
    assert.ok(!existsSync(join(PARENT, "scratch_in_parent.txt")));

    // Legitimate files: preserved.
    assert.ok(existsSync(join(BR, "README.md")));
    assert.ok(existsSync(join(BR, ".gitignore")));
    assert.ok(existsSync(join(BR, "package.json")));
    assert.ok(existsSync(join(PARENT, "README.md")));

    // Subdirectories: preserved (never touched).
    assert.ok(existsSync(join(BR, "_reports", "keep_me.md")));
    assert.ok(existsSync(join(BR, "canonical-clone-abc1234", "marker.txt")));

    assert.ok(data.removedCount >= 4);
});

test("also_sweep_parent: false leaves parent files alone", async () => {
    setupTree();
    const r = await sweepAuditScratchHandler({
        build_root: BR,
        also_sweep_parent: false,
    }, { sessionId: SESSION });
    assert.equal(r.resultType, "success");

    // Build-root scratch gone, parent scratch preserved.
    assert.ok(!existsSync(join(BR, "agent_scratch.txt")));
    assert.ok(existsSync(join(PARENT, "scratch_in_parent.txt")));

    const data = JSON.parse(r.textResultForLlm);
    assert.equal(data.sweptDirs.length, 1);
    assert.equal(data.sweptDirs[0], BR);
});

test("never touches subdirectories or their contents", async () => {
    setupTree();
    await sweepAuditScratchHandler({ build_root: BR }, { sessionId: SESSION });
    // _reports/ + its file preserved.
    assert.ok(existsSync(join(BR, "_reports")));
    assert.ok(existsSync(join(BR, "_reports", "keep_me.md")));
    // Canonical clone dir + its contents preserved.
    assert.ok(existsSync(join(BR, "canonical-clone-abc1234")));
    assert.ok(existsSync(join(BR, "canonical-clone-abc1234", "marker.txt")));
});

test("non-existent build_root returns empty success", async () => {
    if (existsSync(PARENT)) rmSync(PARENT, { recursive: true, force: true });
    // Register an audit anchored at BR (which doesn't exist on disk yet).
    // Sweep should accept BR as the path-to-sweep and return empty success
    // (no error) when the directory is missing.
    registerSweepAudit();
    const r = await sweepAuditScratchHandler({
        build_root: BR,
        also_sweep_parent: false,
    }, { sessionId: SESSION });
    // The path doesn't exist, so nothing to sweep.
    assert.equal(r.resultType, "success");
    const data = JSON.parse(r.textResultForLlm);
    assert.equal(data.foundCount, 0);
});

// ---------- specific filename coverage ----------

test("recognises all whitelisted legitimate filenames", () => {
    const allowed = [
        "README.md", "readme.md", "README", "readme.txt",
        ".gitignore", ".gitattributes", ".gitkeep", ".keep", ".npmrc",
        "LICENSE", "license", "LICENSE.txt", "license.md",
        "package.json", "package-lock.json",
    ];
    for (const name of allowed) {
        assert.equal(
            sweepInternals.isAllowedFilename(name),
            true,
            `expected ${name} to be allowed`,
        );
    }
});

test("treats common scratch filenames as candidates for deletion", () => {
    const scratch = [
        "agent_scratch.txt",
        "BootEncryption.cpp",
        "BootMain.cpp",
        "Setup.c",
        "Mount_part1.c",
        "_audit_dlgcode.c",
        "_dma_audit_BootEncryption.cpp",
        "efi_install.txt",
        "random_dump.bin",
        "scratch.txt",
        "Language.xml",
    ];
    for (const name of scratch) {
        assert.equal(
            sweepInternals.isAllowedFilename(name),
            false,
            `expected ${name} to be a scratch candidate`,
        );
    }
});

// ---------- containment safety ----------

test("listScratchFiles only returns top-level files, not subdir contents", () => {
    setupTree();
    const files = sweepInternals.listScratchFiles(BR);
    // Should contain the scratch files
    assert.ok(files.includes(join(BR, "agent_scratch.txt")));
    assert.ok(files.includes(join(BR, "BootEncryption.cpp")));
    // Should NOT contain anything from subdirs
    for (const f of files) {
        assert.equal(dirname(f), BR, `file ${f} is not at top level of ${BR}`);
    }
});

test("listScratchFiles excludes allowlisted files", () => {
    setupTree();
    const files = sweepInternals.listScratchFiles(BR);
    assert.ok(!files.includes(join(BR, "README.md")));
    assert.ok(!files.includes(join(BR, ".gitignore")));
    assert.ok(!files.includes(join(BR, "package.json")));
});

test("survives empty build_root (no scratch, no error)", async () => {
    if (existsSync(PARENT)) rmSync(PARENT, { recursive: true, force: true });
    mkdirSync(BR, { recursive: true });
    registerSweepAudit();
    const r = await sweepAuditScratchHandler({
        build_root: BR,
        also_sweep_parent: false,
    }, { sessionId: SESSION });
    assert.equal(r.resultType, "success");
    const data = JSON.parse(r.textResultForLlm);
    assert.equal(data.foundCount, 0);
});

// ---------- round-15: triple-review fixes ----------

test("round-15: preserves Section 9b backup files at top level", async () => {
    // Section 9b writes `<original>.zerotrust-backup-<utc-ts>`. If the
    // <original> happens to be at the top level of build_root (or parent),
    // the backup is too. The sweep wrapper must NOT delete those.
    if (existsSync(PARENT)) rmSync(PARENT, { recursive: true, force: true });
    mkdirSync(BR, { recursive: true });
    registerSweepAudit();
    const backupNames = [
        "main.ts.zerotrust-backup-20260517T101800Z",
        "package.json.zerotrust-backup-20260517T101800Z",
        "Dockerfile.zerotrust-backup-20251231T235959Z",
    ];
    for (const name of backupNames) {
        writeFileSync(join(BR, name), "backup contents");
    }
    // Also drop a real scratch file alongside to confirm the sweep still works.
    writeFileSync(join(BR, "scratch_to_kill.txt"), "scratch");

    const r = await sweepAuditScratchHandler({
        build_root: BR,
        also_sweep_parent: false,
    }, { sessionId: SESSION });
    assert.equal(r.resultType, "success");

    for (const name of backupNames) {
        assert.ok(existsSync(join(BR, name)), `backup file ${name} should be preserved`);
    }
    assert.ok(!existsSync(join(BR, "scratch_to_kill.txt")), "scratch file should be deleted");
});

test("round-15: isAllowedFilename recognises backup naming convention", () => {
    const samples = [
        "main.ts.zerotrust-backup-20260517T101800Z",
        "package.json.zerotrust-backup-20260517T101800Z",
        "Dockerfile.zerotrust-backup-20251231T235959Z",
        "deeply.nested.name.with.dots.cpp.zerotrust-backup-20260101T000000Z",
        "foo.zerotrust-backup-abc123",  // permissive on the timestamp shape
    ];
    for (const name of samples) {
        assert.equal(
            sweepInternals.isAllowedFilename(name), true,
            `expected ${name} to be allowed (backup pattern)`,
        );
    }
});

test("round-15: backup pattern doesn't false-match non-backup files", () => {
    const samples = [
        "agent_scratch.txt",
        "BootEncryption.cpp",
        "zerotrust-backup.txt",       // no leading dot
        "myfile.zerotrust-backup",    // no `-<ts>` suffix
        "myfile.zerotrust.backup-x",  // wrong separator
    ];
    for (const name of samples) {
        // None of these match the backup pattern, but the first two are
        // scratch (not in whitelist either), the latter three are unusual
        // names that aren't legitimate either — all should be NOT allowed.
        assert.equal(
            sweepInternals.isAllowedFilename(name), false,
            `expected ${name} to be NOT allowed`,
        );
    }
});

test("round-16: backup pattern rejects executables masquerading as backups (dot-in-suffix bypass)", () => {
    // The round-15 regex was too permissive — `.` was in the character
    // class for the timestamp suffix, so a file named
    // `evil.zerotrust-backup-DROP.exe` would match and be preserved by
    // sweep. The round-16 fix tightens the class to exclude `.`.
    const malicious = [
        "evil.zerotrust-backup-DROP.exe",
        "exploit.zerotrust-backup-anything.dll",
        "main.ts.zerotrust-backup-20260517T101800Z.evil.exe",
        "shell.zerotrust-backup-foo.bar.cmd",
    ];
    for (const name of malicious) {
        assert.equal(
            sweepInternals.isAllowedFilename(name), false,
            `expected ${name} (executable masquerading as backup) to be NOT allowed`,
        );
    }
    // Sanity: real backup files still pass.
    const legitimate = [
        "main.ts.zerotrust-backup-20260517T101800Z",
        "package.json.zerotrust-backup-20251231T235959Z",
        "deeply.nested.name.with.dots.cpp.zerotrust-backup-20260101T000000Z",
    ];
    for (const name of legitimate) {
        assert.equal(
            sweepInternals.isAllowedFilename(name), true,
            `expected ${name} to be allowed`,
        );
    }
});

test("round-15: expanded whitelist accepts common project files", () => {
    const projectFiles = [
        "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md",
        "Makefile", "GnuMakefile", "Dockerfile", ".dockerignore",
        "tsconfig.json", "jsconfig.json", ".editorconfig",
        ".prettierrc", ".eslintrc.json",
        "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
        "Cargo.toml", "Cargo.lock",
        "go.mod", "go.sum",
        "pom.xml", "build.gradle", "build.gradle.kts",
        "yarn.lock", "pnpm-lock.yaml",
        ".nvmrc", ".npmignore",
        "compose.yaml", "docker-compose.yml",
        ".env.example",
        "AUTHORS", "NOTICE", ".mailmap",
    ];
    for (const name of projectFiles) {
        assert.equal(
            sweepInternals.isAllowedFilename(name), true,
            `expected ${name} to be allowed (common project file)`,
        );
    }
});

test("round-15: expanded whitelist preserves project files during sweep", async () => {
    if (existsSync(PARENT)) rmSync(PARENT, { recursive: true, force: true });
    mkdirSync(BR, { recursive: true });
    registerSweepAudit();
    const projectFiles = ["CHANGELOG.md", "Makefile", "tsconfig.json", "Cargo.toml"];
    for (const name of projectFiles) {
        writeFileSync(join(BR, name), "legitimate project file");
    }
    writeFileSync(join(BR, "scratch.txt"), "scratch");

    await sweepAuditScratchHandler({
        build_root: BR,
        also_sweep_parent: false,
    }, { sessionId: SESSION });

    for (const name of projectFiles) {
        assert.ok(existsSync(join(BR, name)), `${name} should be preserved`);
    }
    assert.ok(!existsSync(join(BR, "scratch.txt")), "scratch file should be deleted");
});


// Round-17: defense-in-depth. The sweep wrapper MUST refuse a caller-
// supplied build_root that doesn't match the default (or active audit)
// even when invocation.sessionId is missing. Without this, a tool call
// with a falsy sessionId could supply an arbitrary path like
// `C:\Users\testuser` and have sweep operate on it destructively.
test("round-17: sweep refuses non-default build_root when invocation has no sessionId (null)", async () => {
    const r = await sweepAuditScratchHandler(
        { build_root: "C:\\Users\\testuser", also_sweep_parent: false, dry_run: true },
        {},
    );
    assert.equal(r.resultType, "failure", "sweep must refuse arbitrary path without active audit");
    assert.match(r.textResultForLlm, /does not match default build_root/i);
});

test("round-17: sweep refuses non-default build_root when invocation.sessionId is undefined", async () => {
    const r = await sweepAuditScratchHandler(
        { build_root: "C:\\evil", also_sweep_parent: true, dry_run: true },
        { sessionId: undefined },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match default build_root/i);
});

test("round-17: sweep refuses non-default build_root when invocation.sessionId is empty string", async () => {
    const r = await sweepAuditScratchHandler(
        { build_root: "C:\\Windows\\Temp", also_sweep_parent: false, dry_run: true },
        { sessionId: "" },
    );
    assert.equal(r.resultType, "failure");
    assert.match(r.textResultForLlm, /does not match default build_root/i);
});

test("round-17: sweep still allows the default build_root without sessionId", async () => {
    // We dry-run so we don't actually delete anything in the real sandbox.
    const DEFAULT_BUILD_ROOT = sweepInternals.DEFAULT_BUILD_ROOT;
    assert.ok(DEFAULT_BUILD_ROOT, "test seam must expose DEFAULT_BUILD_ROOT");
    const r = await sweepAuditScratchHandler(
        { build_root: DEFAULT_BUILD_ROOT, also_sweep_parent: false, dry_run: true },
        {},
    );
    assert.equal(r.resultType, "success", "default build_root must still be allowed");
});

test("round-17: sweep still works with no args at all (falls back to default)", async () => {
    const r = await sweepAuditScratchHandler({ dry_run: true, also_sweep_parent: false }, {});
    assert.equal(r.resultType, "success", "no build_root arg falls back to default and succeeds");
});
