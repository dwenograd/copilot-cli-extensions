// safeWrappers/reportWrapper.mjs — zerotrust_finalize_report tool.
//
// Writes the agent's audit-report markdown to a canonical path under
// `<build_root>\_reports\<owner>-<repo>-<short-sha>\REPORT.md`. Refuses
// to write outside that directory. Refuses oversized writes.
//
// Trust model (v3.1 hardening round 2):
// - The build_root used here comes from the trusted active-audit state
//   (via getTrustedAuditContext), NOT from args.build_root. This closes
//   the round-2 cluster-J-extension finding (3/3 critical) where this
//   wrapper had been missed by the round-1 cluster-J fix and let an
//   agent write 1MB of attacker-controlled markdown anywhere on disk
//   the extension process could create directories.

import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import nodePath from "node:path";

import { buildReportPath } from "../urlParser.mjs";
import { getTrustedAuditContext } from "../enforcement.mjs";

import { DEFAULT_BUILD_ROOT } from "./defaults.mjs";
const MAX_REPORT_BYTES = 1024 * 1024; // 1 MB cap

export async function finalizeReportHandler(args, invocation) {
    args = args || {};
    const sessionId = invocation?.sessionId || null;

    if (typeof args.owner !== "string" || typeof args.repo !== "string" || typeof args.short_sha !== "string") {
        return failure("owner, repo, and short_sha are required strings");
    }
    if (typeof args.markdown_body !== "string") {
        return failure("markdown_body is required (string)");
    }
    if (Buffer.byteLength(args.markdown_body, "utf-8") > MAX_REPORT_BYTES) {
        return failure(`markdown_body exceeds ${MAX_REPORT_BYTES} bytes`);
    }

    // Trusted build_root — active audit's buildPath wins; agent-supplied
    // args.build_root is rejected if it conflicts (or if no audit is active
    // and an override is provided).
    const ctx = getTrustedAuditContext({ sessionId, args, defaultBuildRoot: DEFAULT_BUILD_ROOT });
    if (!ctx.ok) return failure(ctx.error);
    const buildRoot = ctx.buildRoot;
    if (!nodePath.isAbsolute(buildRoot)) {
        return failure(`build_root must be absolute, got ${JSON.stringify(buildRoot)}`);
    }

    // Round-17 defense-in-depth (mirrors sweepWrapper): finalize_report
    // performs a destructive writeFileSync (and recursive mkdirSync) at
    // <build_root>/_reports/<owner>-<repo>-<sha>/REPORT.md. The general
    // getTrustedAuditContext check is gated on a truthy sessionId; a tool
    // invocation with a falsy sessionId could otherwise supply an arbitrary
    // build_root and have us write/mkdir at that path. Refuse mismatches
    // explicitly here.
    if (args.build_root && !ctx.hasActiveAudit) {
        const argResolved = nodePath.resolve(String(args.build_root)).toLowerCase();
        const defaultResolved = nodePath.resolve(DEFAULT_BUILD_ROOT).toLowerCase();
        if (argResolved !== defaultResolved) {
            return failure(
                `finalize_report refused: args.build_root (${args.build_root}) does not match ` +
                    `default build_root (${DEFAULT_BUILD_ROOT}) and no active audit is anchoring this path. ` +
                    `Refusing to write report to agent-supplied path. ` +
                    `Re-invoke zerotrust_sourcecheck to activate an audit first.`,
            );
        }
    }

    let reportDir;
    try {
        reportDir = buildReportPath(buildRoot, args.owner, args.repo, args.short_sha);
    } catch (err) {
        return failure(`report path construction failed: ${err.message}`);
    }

    if (!existsSync(reportDir)) {
        try {
            mkdirSync(reportDir, { recursive: true });
        } catch (err) {
            return failure(`failed to create report dir ${reportDir}: ${err.message}`);
        }
    }

    const reportPath = nodePath.join(reportDir, "REPORT.md");

    // One more containment check after the join — defense in depth against
    // a hypothetical buildReportPath bug.
    const rel = nodePath.relative(nodePath.resolve(buildRoot), reportPath);
    if (rel.startsWith("..") || nodePath.isAbsolute(rel)) {
        return failure(`computed report path ${reportPath} would escape build_root ${buildRoot}`);
    }

    try {
        writeFileSync(reportPath, args.markdown_body, { encoding: "utf-8" });
    } catch (err) {
        return failure(`write failed: ${err.message}`);
    }

    return success({
        reportPath,
        bytesWritten: Buffer.byteLength(args.markdown_body, "utf-8"),
    });
}

function success(data) {
    return {
        textResultForLlm: JSON.stringify({ ok: true, ...data }, null, 2),
        resultType: "success",
    };
}

function failure(message) {
    return {
        textResultForLlm: JSON.stringify({ ok: false, error: message }, null, 2),
        resultType: "failure",
    };
}

export const __internals = {
    MAX_REPORT_BYTES,
};
