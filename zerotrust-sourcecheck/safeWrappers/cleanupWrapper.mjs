// safeWrappers/cleanupWrapper.mjs — zerotrust_cleanup_audit tool implementation.
//
// Purpose: at end of audit, the agent calls this to delete the cloned
// source tree (and optionally the report and quarantine directories).
// Without it, every audit leaves its clone on disk forever.
//
// Substitutional safety:
// - Refuses paths outside build_root (containment check).
// - Refuses clone_path that isn't an immediate child of build_root with the
//   canonical hashed clone-naming pattern (`zt-<sha256>`). This prevents
//   a prompt-injected agent from passing `clone_path: "<build_root>\\_reports"`
//   and wiping every prior audit's preserved REPORT.md in one call.
// - Refuses paths whose basename starts with `_` (the meta-dirs convention).
// - Treats paths that don't exist as a no-op success (idempotent).
// - Default behavior keeps the REPORT.md + FINDINGS.json pair;
//   pass `also_delete_report: true` to nuke that too.
// - Default behavior deletes the matching _quarantine/ subdir.

import { existsSync, rmSync, statSync } from "node:fs";
import nodePath from "node:path";

import { getTrustedAuditContext } from "../enforcement.mjs";
import { modeIsBuild } from "../modes.mjs";
import { ARTIFACT_NAME_RE } from "../urlParser.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
import { failure, success } from "./result.mjs";

const CLONE_NAME_RE = ARTIFACT_NAME_RE;

function pathIsUnder(parent, child) {
    const p = nodePath.resolve(parent).toLowerCase();
    const c = nodePath.resolve(child).toLowerCase();
    if (p === c) return false; // refuse to delete build_root itself
    const rel = nodePath.relative(p, c);
    return !!rel && !rel.startsWith("..") && !nodePath.isAbsolute(rel);
}

function pathsEqual(left, right) {
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase(): a === b;
}

function safeRemove(p) {
    if (!existsSync(p)) return { existed: false, removed: false };
    try {
        const st = statSync(p, { throwIfNoEntry: false });
        if (!st) return { existed: false, removed: false };
        rmSync(p, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        if (existsSync(p)) {
            return { existed: true, removed: false, error: "path still exists after removal" };
        }
        return { existed: true, removed: true };
    } catch (err) {
        return { existed: true, removed: false, error: err.message };
    }
}

/**
 * Tool signature:
 *   zerotrust_cleanup_audit({
 *     clone_path: string,                  // absolute, must be IMMEDIATE child of build_root with canonical clone-naming pattern
 *     build_root?: string,                 // default DEFAULT_BUILD_ROOT (or active audit's build_root if set)
 *      also_delete_report?: boolean,        // default false (keep artifact pair)
 *     also_delete_quarantine?: boolean,    // default true (downloaded binaries should not persist)
 *   })
 */
export async function cleanupAuditHandler(args, invocation, dependencies = {}) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) {
        return failure("cleanup_audit requires an invocation sessionId");
    }

    if (typeof args.clone_path !== "string" || !nodePath.isAbsolute(args.clone_path)) {
        return failure("clone_path is required and must be absolute");
    }

    // Trusted build_root — active audit wins over agent-supplied args.
    const ctx = getTrustedAuditContext({ sessionId, args, defaultBuildRoot: DEFAULT_BUILD_ROOT });
    if (!ctx.ok) return failure(ctx.error);
    if (!ctx.hasActiveAudit) {
        return failure("cleanup_audit requires an active audit for this session");
    }
    if (!modeIsBuild(ctx.mode)) {
        return failure(`cleanup_audit is only valid for build-mode audits (active mode: ${ctx.mode})`);
    }
    if (!ctx.resolvedClonePath) {
        return failure("cleanup_audit refused: no resolved clone path recorded for the active audit. Call zerotrust_safe_clone before zerotrust_cleanup_audit.");
    }
    const buildRoot = ctx.buildRoot;
    if (!nodePath.isAbsolute(buildRoot)) {
        return failure(`build_root must be absolute, got ${JSON.stringify(buildRoot)}`);
    }
    if (!pathIsUnder(buildRoot, args.clone_path)) {
        return failure(`clone_path ${args.clone_path} is not under build_root ${buildRoot} (refusing to delete)`);
    }

    // Reject anything that isn't an immediate child of build_root or doesn't
    // match the canonical clone-naming convention. This prevents passing
    // build_root/_reports or build_root/_quarantine as the "clone" to delete.
    const cloneAbs = nodePath.resolve(args.clone_path);
    const cloneBase = nodePath.basename(cloneAbs);
    const cloneParent = nodePath.dirname(cloneAbs);
    if (!pathsEqual(cloneParent, buildRoot)) {
        return failure(`clone_path ${args.clone_path} is not an immediate child of build_root ${buildRoot} (refusing to delete: only canonical clone dirs may be cleaned)`);
    }
    if (cloneBase.startsWith("_")) {
        return failure(`clone_path basename starts with '_' (reserved for meta-dirs like _reports/_quarantine); refusing to delete`);
    }
    if (!CLONE_NAME_RE.test(cloneBase)) {
        return failure(`clone_path basename ${JSON.stringify(cloneBase)} does not match canonical clone-naming pattern zt-<sha256>; refusing to delete`);
    }

    if (!pathsEqual(args.clone_path, ctx.resolvedClonePath)) {
        return failure(`cleanup_audit refused: clone_path ${args.clone_path} does not match the active audit's resolved clone path ${ctx.resolvedClonePath}`);
    }

    const reportDir = nodePath.join(buildRoot, "_reports", cloneBase);
    const quarantineDir = nodePath.join(buildRoot, "_quarantine", cloneBase);

    const alsoDeleteReport = args.also_delete_report === true;
    const alsoDeleteQuarantine = args.also_delete_quarantine !== false; // default true

    const remove = dependencies.remove || safeRemove;
    const cloneResult = remove(cloneAbs);

    let reportResult = { existed: false, removed: false, skipped: !alsoDeleteReport };
    if (alsoDeleteReport) {
        // Symmetric defense-in-depth containment check — same pattern used
        // for quarantineDir below. Defends against future refactor that
        // changes how cloneBase is derived.
        if (pathIsUnder(buildRoot, reportDir)) {
            reportResult = remove(reportDir);
        } else {
            reportResult = { existed: false, removed: false, error: "report path containment check failed" };
        }
    }

    let quarantineResult = { existed: false, removed: false, skipped: !alsoDeleteQuarantine };
    if (alsoDeleteQuarantine) {
        if (pathIsUnder(buildRoot, quarantineDir)) {
            quarantineResult = remove(quarantineDir);
        } else {
            quarantineResult = { existed: false, removed: false, error: "quarantine path containment check failed" };
        }
    }

    const deletionErrors = [
        ["clone", cloneResult],
        ["report", reportResult],
        ["quarantine", quarantineResult],
    ].filter(([, result]) =>
        !result.skipped && (result.error || (result.existed && !result.removed)),
    ).map(([target, result]) => ({
        target,
        error: result.error || "path was not removed",
    }));

    if (deletionErrors.length > 0) {
        return failure(
            "cleanup_audit did not remove every requested target; the active audit remains open so cleanup can be retried",
            {
                clonePath: args.clone_path,
                clone: cloneResult,
                report: reportResult,
                quarantine: quarantineResult,
                deletionErrors,
                auditStillActive: ctx.hasActiveAudit,
            },
        );
    }

    return success({
        clonePath: args.clone_path,
        clone: cloneResult,
        report: reportResult,
        quarantine: quarantineResult,
        auditStillActive: ctx.hasActiveAudit,
        keptReportPath: alsoDeleteReport ? null: (existsSync(reportDir) ? reportDir: null),
        keptReportArtifacts: alsoDeleteReport || !existsSync(reportDir)
            ? []: ["REPORT.md", "FINDINGS.json"]
                .map((name) => nodePath.join(reportDir, name))
                .filter((path) => existsSync(path)),
        metadataCachePreserved: true,
    });
}

export const __internals = {
    pathIsUnder,
    pathsEqual,
    safeRemove,
    CLONE_NAME_RE,
};
