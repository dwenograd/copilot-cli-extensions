// safeWrappers/quarantineWrapper.mjs — verify_release quarantine cleanup.

import { existsSync, rmSync } from "node:fs";
import nodePath from "node:path";

import { getTrustedAuditContext } from "../enforcement.mjs";
import { buildQuarantinePath } from "../urlParser.mjs";
import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";

function safeRemove(p) {
    if (!existsSync(p)) return { existed: false, removed: false };
    try {
        rmSync(p, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        if (existsSync(p)) {
            return { existed: true, removed: false, error: "path still exists after removal" };
        }
        return { existed: true, removed: true };
    } catch (err) {
        return { existed: true, removed: false, error: err.message };
    }
}

function pathsEqual(left, right) {
    const a = nodePath.resolve(left);
    const b = nodePath.resolve(right);
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function resolvedQuarantinePath(ctx) {
    if (!ctx.canonicalOwner || !ctx.canonicalRepo || !ctx.resolvedSha) return null;
    const canonical = buildQuarantinePath(
        ctx.buildRoot,
        ctx.canonicalOwner,
        ctx.canonicalRepo,
        ctx.resolvedSha,
    );
    if (ctx.expectedQuarantinePath
        && !pathsEqual(ctx.expectedQuarantinePath, canonical)) {
        return null;
    }
    return canonical;
}

/**
 * Tool signature:
 *   zerotrust_cleanup_quarantine({
 *     build_root?: string,
 *   })
 *
 * No path argument is accepted. The target is derived from the active
 * verify_release audit's trusted build root, canonical placeholder path, and
 * resolved SHA.
 */
export async function cleanupQuarantineHandler(args, invocation, dependencies = {}) {
    args = args || {};
    const unexpectedArgs = Object.keys(args).filter((key) => key !== "build_root");
    if (unexpectedArgs.length > 0) {
        return failure(
            `cleanup_quarantine does not accept raw paths or extra arguments: ${unexpectedArgs.join(", ")}`,
        );
    }
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) {
        return failure("cleanup_quarantine requires an active audit session");
    }

    const ctx = getTrustedAuditContext({
        sessionId,
        args,
        defaultBuildRoot: DEFAULT_BUILD_ROOT,
    });
    if (!ctx.ok) return failure(ctx.error);
    if (!ctx.hasActiveAudit) {
        return failure("cleanup_quarantine requires an active audit");
    }
    if (ctx.mode !== "verify_release") {
        return failure(`cleanup_quarantine is only valid for verify_release audits (active mode: ${ctx.mode})`);
    }
    if (!ctx.resolvedSha) {
        return failure("cleanup_quarantine refused: no resolved SHA is recorded for the active audit");
    }

    const quarantinePath = resolvedQuarantinePath(ctx);
    if (!quarantinePath) {
        return failure("cleanup_quarantine could not derive the canonical quarantine path from the active audit");
    }

    const quarantineRoot = nodePath.resolve(ctx.buildRoot, "_quarantine");
    const resolvedPath = nodePath.resolve(quarantinePath);
    if (nodePath.dirname(resolvedPath).toLowerCase() !== quarantineRoot.toLowerCase()) {
        return failure("cleanup_quarantine canonical path containment check failed");
    }

    const remove = dependencies.remove || safeRemove;
    const result = remove(resolvedPath);
    if (result.error || (result.existed && !result.removed)) {
        return failure(
            `cleanup_quarantine failed for ${resolvedPath}: ${result.error || "path was not removed"}`,
            { quarantinePath: resolvedPath, quarantine: result },
        );
    }

    return success({
        quarantinePath: resolvedPath,
        quarantine: result,
        auditStillActive: true,
    });
}

function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, ...data }, null, 2),
        resultType: "success",
    };
}

function failure(message, data = {}) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, error: message, ...data }, null, 2),
        resultType: "failure",
    };
}

export const __internals = {
    safeRemove,
    resolvedQuarantinePath,
};
