// crucible/__tests__/measurement-fixtures.mjs
//
// Shared support code for the measurement test suites. Not a *.test.mjs
// file so vitest does not collect it as a suite. Depends only on stdlib.
//
// The measurement layer needs REAL executables to spawn. On Windows the one
// executable we can rely on being present is node.exe (process.execPath).
// This module:
//   - Computes node.exe's SHA-256 once and memoises it, so allowlist
//     verification does not re-hash a ~100 MB binary in every test.
//   - Creates temp directories under __tests__ (never in /tmp) and returns
//     small helpers to write fixture scripts + allowlists.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
    canonicalJson,
    immutableCanonical,
} from "../domain/canonical.mjs";

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const NODE_EXE = process.execPath;

let _nodeHash = null;
export function nodeExeSha256Hex() {
    if (_nodeHash !== null) return _nodeHash;
    const hash = createHash("sha256");
    const fd = fs.openSync(NODE_EXE, "r");
    try {
        const buf = Buffer.allocUnsafe(1024 * 1024);
        // eslint-disable-next-line no-constant-condition
        while (true) {
            const n = fs.readSync(fd, buf, 0, buf.length, null);
            if (n <= 0) break;
            hash.update(buf.subarray(0, n));
        }
    } finally {
        fs.closeSync(fd);
    }
    _nodeHash = hash.digest("hex");
    return _nodeHash;
}

export function sha256HexOfFile(p) {
    const hash = createHash("sha256");
    hash.update(fs.readFileSync(p));
    return hash.digest("hex");
}

export function makeTempRoot(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.measure-tmp-${label}-`));
    return root;
}

export function rmTempRoot(root) {
    if (root) fs.rmSync(root, { recursive: true, force: true });
}

// Write a tiny .mjs script that behaves as an crucible harness. `body` is a
// snippet of JS that runs inside the script (after node imports fs). It
// must eventually call process.exit or print to stdout and let the script
// finish. Returns the absolute path of the created script.
export function writeHarnessScript(root, name, body) {
    const p = path.join(root, `${name}.mjs`);
    fs.writeFileSync(p, `import fs from "node:fs";\nimport path from "node:path";\n${body}\n`);
    return p;
}

// Write a valid allowlist JSON referencing a single entry. `overrides` is
// a partial entry that is merged over sensible defaults. Returns the
// absolute path of the created allowlist file.
export function writeAllowlist(root, entryId, entryOverrides = {}, { fileName = "harness.allowlist.json" } = {}) {
    const inferredDependencies = Array.isArray(entryOverrides.argvTemplate)
        ? entryOverrides.argvTemplate
            .filter((item) => typeof item === "string"
                && !item.includes("{{")
                && path.isAbsolute(item)
                && fs.existsSync(item)
                && path.resolve(item).toLowerCase() !== path.resolve(entryOverrides.executable ?? NODE_EXE).toLowerCase())
            .map((dependencyPath) => ({
                path: dependencyPath,
                sha256: sha256HexOfFile(dependencyPath),
                role: "script",
            }))
        : [];
    const entries = { [entryId]: {
        executable: NODE_EXE,
        executableSha256: nodeExeSha256Hex(),
        argvTemplate: [],
        dependencies: inferredDependencies,
        timeoutMs: 15000,
        maxStdoutBytes: 1024 * 1024,
        maxStderrBytes: 256 * 1024,
        executesCandidateCode: false,
        ...entryOverrides,
    } };
    const doc = { version: 1, entries };
    const p = path.join(root, fileName);
    fs.writeFileSync(p, JSON.stringify(doc, null, 2));
    return p;
}

// Materialise a frozen candidate snapshot directory with the same manifest /
// object-closure shape supplied by the runtime runner.
export function materializeCandidateSnapshot(root, name, bytes) {
    const p = path.join(root, `${name}.snapshot`);
    fs.mkdirSync(p);
    const buf = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes;
    const relPath = "candidate.bin";
    fs.writeFileSync(path.join(p, relPath), buf);
    const objectId =
        `sha256:${createHash("sha256").update(buf).digest("hex")}`;
    const manifest = {
        type: "crucible-snapshot",
        version: 1,
        algo: "sha256",
        fileCount: 1,
        totalBytes: buf.length,
        entries: [{
            path: relPath,
            size: buf.length,
            object: objectId,
        }],
    };
    const snapshotId =
        `sha256:${createHash("sha256")
            .update(canonicalJson(manifest), "utf8")
            .digest("hex")}`;
    return immutableCanonical({
        path: p,
        hash: `sha256:crucible-measurement-snapshot-v1:${snapshotId.slice("sha256:".length)}`,
        snapshotId,
        manifest,
        expectedObjectClosure: [objectId, snapshotId].sort(),
    });
}

// Stable identifiers for tests.
export function fixedIds() {
    return {
        attemptId: "att-0001",
        runnerEpochId: "epoch-2026-07-09-a",
    };
}

// A frozen-clock helper: repeated calls to now()/isoNow() advance by a
// fixed delta each time so durationMs is predictable in tests.
export function fixedClock(startIso = "2026-07-09T12:00:00.000Z", stepMs = 100) {
    const start = Date.parse(startIso);
    let n = 0;
    return {
        now() { const v = start + n * stepMs; n += 1; return v; },
        isoNow() { const v = new Date(start + n * stepMs).toISOString(); n += 1; return v; },
    };
}

// Whether the current process can create a Windows file symlink. Requires
// SeCreateSymbolicLinkPrivilege (admin, or Developer Mode). We probe once
// per suite so per-test decisions are cheap.
let _fileSymlinkOk = null;
export function canCreateFileSymlink() {
    if (_fileSymlinkOk !== null) return _fileSymlinkOk;
    const dir = fs.mkdtempSync(path.join(HERE, ".measure-probe-symlink-"));
    try {
        const target = path.join(dir, "target.txt");
        const link = path.join(dir, "link.txt");
        fs.writeFileSync(target, "probe");
        try {
            fs.symlinkSync(target, link, "file");
            _fileSymlinkOk = true;
        } catch {
            _fileSymlinkOk = false;
        }
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
    return _fileSymlinkOk;
}

export function canCreateDirJunction() {
    if (process.platform !== "win32") return false;
    const dir = fs.mkdtempSync(path.join(HERE, ".measure-probe-junction-"));
    try {
        const target = path.join(dir, "target");
        const link = path.join(dir, "j");
        fs.mkdirSync(target);
        try {
            fs.symlinkSync(target, link, "junction");
            return true;
        } catch {
            return false;
        }
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

// Ensure our temp roots go under __tests__/ and never under system /tmp.
export function assertUnderTests(p) {
    const abs = path.resolve(p);
    if (!abs.startsWith(HERE + path.sep)) {
        throw new Error(`temp path ${abs} escaped __tests__ (${HERE})`);
    }
    return abs;
}

// A tiny convenience so tests can build a full run input in one line.
export function runInputFor({ verifiedEntry, snapshot, attemptId, runnerEpochId }) {
    return { verifiedEntry, candidateSnapshot: snapshot, attemptId, runnerEpochId };
}

export { os };
