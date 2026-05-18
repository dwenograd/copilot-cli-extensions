// safeWrappers/programResolver.mjs — round-11 hardening (gpt-5.5 R11 F1).
//
// Problem: `execFileSync("npm", ...)` with `cwd: args.clone_path` on Windows
// can resolve `npm` to a repo-planted `npm.cmd` because:
//   - On Windows, npm/yarn/pnpm/pip/cargo/dotnet are typically `.cmd` shims.
//   - Node's child_process for `.cmd` scripts spawns via cmd.exe, which
//     searches the current directory before PATH (legacy Win32 behavior
//     that Node CAN'T change by setting SetSearchPathMode for cmd.exe's
//     internal lookup).
//   - A malicious repo can drop `npm.cmd` (or `npm.exe`) at the clone root
//     and the wrapper would execute that instead of the trusted system npm.
//
// Fix: resolve the program to a trusted absolute path BEFORE handing it to
// execFileSync. Reject if the resolved path is under build_root or clone_path
// (which would mean the repo planted the binary).

import { existsSync } from "node:fs";
import nodePath from "node:path";

const IS_WINDOWS = process.platform === "win32";
const PATHEXT = IS_WINDOWS
    ? (process.env.PATHEXT || ".COM;.EXE;.BAT;.CMD;.PS1").split(";").map((e) => e.toLowerCase())
    : [""];

function pathIsUnder(parent, child) {
    if (!parent || !child) return false;
    const p = nodePath.resolve(parent).toLowerCase();
    const c = nodePath.resolve(child).toLowerCase();
    if (p === c) return true;
    const rel = nodePath.relative(p, c);
    return !!rel && !rel.startsWith("..") && !nodePath.isAbsolute(rel);
}

/**
 * Search PATH for `program` and return the first matching absolute path,
 * skipping any candidate that resolves under any of `forbiddenRoots`.
 *
 * Returns the trusted absolute path on success, or null if no trusted
 * candidate exists.
 */
export function resolveTrustedProgram(program, { forbiddenRoots = [] } = {}) {
    if (!program || typeof program !== "string") return null;
    // If `program` already contains a path separator, it's an explicit path —
    // resolve and verify it's not under a forbidden root.
    if (program.includes("/") || program.includes("\\")) {
        const abs = nodePath.resolve(program);
        if (forbiddenRoots.some((r) => pathIsUnder(r, abs))) return null;
        return existsSync(abs) ? abs : null;
    }

    const pathDirs = (process.env.PATH || "").split(nodePath.delimiter).filter(Boolean);
    for (const dir of pathDirs) {
        const dirAbs = nodePath.resolve(dir);
        // Skip any PATH directory that's itself under a forbidden root —
        // a malicious repo could prepend its own bin dir to PATH.
        if (forbiddenRoots.some((r) => pathIsUnder(r, dirAbs))) continue;
        for (const ext of PATHEXT) {
            const candidate = nodePath.join(dirAbs, program + ext);
            if (existsSync(candidate)) {
                return candidate;
            }
        }
    }
    return null;
}

export const __internals = {
    pathIsUnder,
    PATHEXT,
    IS_WINDOWS,
};
