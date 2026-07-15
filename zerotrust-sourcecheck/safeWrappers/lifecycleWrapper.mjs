// safeWrappers/lifecycleWrapper.mjs — non-destructive audit-state closure.

import { existsSync } from "node:fs";

import { deactivateAudit, getActiveAudit } from "../enforcement.mjs";
import { modeIsBuild } from "../modes.mjs";
import { buildQuarantinePath } from "../urlParser.mjs";
import {
    clearCacheBinding,
    clearRecordedOutcome,
    getCacheBinding,
} from "./state.mjs";

/**
 * Tool signature:
 *   zerotrust_close_audit({})
 *
 * This is intentionally separate from destructive cleanup. Cleanup wrappers
 * retain the active audit anchor so failed deletions can be retried safely.
 */
export async function closeAuditHandler(args, invocation, dependencies = {}) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;
    if (!sessionId) {
        return failure("close_audit requires an invocation sessionId");
    }
    const unexpectedArgs = Object.keys(args).filter((key) => key !== "abandon_artifacts");
    if (unexpectedArgs.length > 0) {
        return failure(`close_audit does not accept arguments: ${unexpectedArgs.join(", ")}`);
    }
    if (Object.hasOwn(args, "abandon_artifacts")
        && typeof args.abandon_artifacts !== "boolean") {
        return failure("abandon_artifacts must be boolean when supplied");
    }

    const activeAudit = getActiveAudit(sessionId);
    if (!activeAudit) {
        const recordedOutcomeCleared = clearRecordedOutcome(sessionId);
        const cacheBindingCleared = clearCacheBinding(sessionId);
        return success({
            closed: true,
            alreadyClosed: !recordedOutcomeCleared && !cacheBindingCleared,
            auditDeactivated: false,
            recordedOutcomeCleared,
            cacheBindingCleared,
            diskCachePreserved: true,
            artifactsAbandoned: false,
        });
    }
    const hadCacheBinding = !!getCacheBinding(sessionId, { auditId: activeAudit.auditId });
    const finalizedArtifacts = activeAudit.reportFinalization
        ? [
            activeAudit.reportFinalization.reportPath,
            activeAudit.reportFinalization.findingsPath,
        ].filter((path) => typeof path === "string")
        : [];

    const pathExists = dependencies.exists || existsSync;
    const blockingArtifacts = [];
    if (modeIsBuild(activeAudit.mode)
        && activeAudit.resolvedClonePath
        && pathExists(activeAudit.resolvedClonePath)) {
        blockingArtifacts.push({
            kind: "clone",
            path: activeAudit.resolvedClonePath,
            cleanupTool: "zerotrust_cleanup_audit",
        });
    }
    if (activeAudit.mode === "verify_release"
        && activeAudit.canonicalOwner
        && activeAudit.canonicalRepo
        && activeAudit.resolvedSha) {
        const quarantinePath = buildQuarantinePath(
            activeAudit.buildPath,
            activeAudit.canonicalOwner,
            activeAudit.canonicalRepo,
            activeAudit.resolvedSha,
        );
        if (pathExists(quarantinePath)) {
            blockingArtifacts.push({
                kind: "quarantine",
                path: quarantinePath,
                cleanupTool: "zerotrust_cleanup_quarantine",
            });
        }
    }
    const abandoning = args.abandon_artifacts === true;
    if (blockingArtifacts.length > 0 && !abandoning) {
        return failure(
            "close_audit refused: canonical audit artifacts still exist. Run the listed cleanup tool(s), or pass abandon_artifacts:true to intentionally leave them on disk and relinquish active cleanup authority.",
            { blockingArtifacts, auditStillActive: true },
        );
    }

    const auditDeactivated = deactivateAudit(sessionId);
    const recordedOutcomeCleared = clearRecordedOutcome(sessionId);

    return success({
        closed: true,
        alreadyClosed: !auditDeactivated && !recordedOutcomeCleared && !hadCacheBinding,
        auditDeactivated,
        recordedOutcomeCleared,
        cacheBindingCleared: hadCacheBinding,
        diskCachePreserved: true,
        finalizedArtifactsPreserved: finalizedArtifacts,
        artifactsAbandoned: abandoning && blockingArtifacts.length > 0,
        ...(blockingArtifacts.length > 0 ? { abandonedArtifacts: blockingArtifacts } : {}),
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
