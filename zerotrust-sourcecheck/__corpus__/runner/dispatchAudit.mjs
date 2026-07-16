// __corpus__/runner/dispatchAudit.mjs
// Thin subprocess wrapper for live corpus runs. Unit tests and --dry-run never
// call the live path.

import { spawn } from "node:child_process";
import nodePath from "node:path";

const LIVE_MODES = new Set(["audit_source", "audit_source_council"]);

export async function dispatchAudit({
    url,
    mode,
    outDir,
    buildRoot,
    sessionId,
    dryRun = false,
    env = process.env,
} = {}) {
    if (typeof url !== "string" || url.length === 0) throw new Error("url is required");
    if (!LIVE_MODES.has(mode)) throw new Error(`unsupported corpus audit mode: ${mode}`);
    if (dryRun) {
        return {
            ok: true,
            planned: true,
            reportPath: null,
            findingsPath: null,
            mode,
            url,
        };
    }
    if (env.ZEROTRUST_CORPUS_LIVE !== "1") {
        return {
            ok: false,
            exitCode: null,
            mode,
            url,
            reportPath: null,
            findingsPath: null,
            stderr: "live corpus dispatch requires ZEROTRUST_CORPUS_LIVE=1",
            stdout: "",
        };
    }

    // Runtime mechanism note for operators:
    // Option 1 is spawning `gh copilot` as a child process so the audit runs in
    // the same outer CLI path an operator would use. Option 2 is importing the
    // extension handler in-process, which is easier to unit-test but does not
    // exercise the real operator workflow. For Wave 1 this file picks Option 1.
    // TODO: validate this live subprocess command against real audits before
    // relying on non-dry corpus runs as a quality gate.
    const prompt = [
        "Run zerotrust_sourcecheck for this corpus fixture.",
        `URL: ${url}`,
        `mode: ${mode}`,
        buildRoot ? `build_root: ${buildRoot}`: null,
        sessionId ? `session_id: ${sessionId}`: null,
        "Use API-direct source inspection only. Do not install, build, or execute repository code.",
        "Return the final REPORT.md and FINDINGS.json paths.",
    ].filter(Boolean).join("\n");

    const child = spawn("gh", ["copilot", "exec", "--", prompt], {
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...env, ZEROTRUST_CORPUS_SESSION: sessionId || "" },
    });

    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));

    const exitCode = await new Promise((resolve) => {
        child.on("error", () => resolve(1));
        child.on("close", resolve);
    });

    const stdoutText = Buffer.concat(stdout).toString("utf-8");
    const stderrText = Buffer.concat(stderr).toString("utf-8");
    const reportPath = findReportPath(stdoutText)
        || (outDir ? nodePath.join(outDir, `${mode}-REPORT.md`): null);
    const findingsPath = findFindingsPath(stdoutText)
        || (reportPath ? siblingArtifactPath(reportPath, "FINDINGS.json"): null);

    return {
        ok: exitCode === 0,
        exitCode,
        mode,
        url,
        reportPath,
        findingsPath,
        stdout: stdoutText,
        stderr: stderrText,
    };
}

function findReportPath(text) {
    return findArtifactPath(text, "REPORT.md", "reportPath");
}

function findFindingsPath(text) {
    return findArtifactPath(text, "FINDINGS.json", "findingsPath");
}

function findArtifactPath(text, basename, jsonField) {
    const input = String(text || "");
    const jsonPattern = new RegExp(`"${jsonField}"\\s*:\\s*("(?:\\\\.|[^"\\\\])*")`, "iu");
    const jsonMatch = jsonPattern.exec(input);
    if (jsonMatch) {
        try {
            return JSON.parse(jsonMatch[1]);
        } catch {
            // Fall through to plain-text path extraction.
        }
    }
    const escaped = basename.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const patterns = [
        new RegExp(`((?:[A-Za-z]:[\\\\/]|\\\\\\\\)[^\\r\\n"'<>|]*?${escaped})`, "iu"),
        new RegExp(`(/[^\\r\\n"'<>]*?${escaped})`, "iu"),
    ];
    for (const pattern of patterns) {
        const match = pattern.exec(input);
        if (match) return match[1].trim();
    }
    return null;
}

function siblingArtifactPath(path, basename) {
    const value = String(path || "");
    const implementation = /^[A-Za-z]:[\\/]/u.test(value) || value.startsWith("\\\\")
        ? nodePath.win32: nodePath.posix;
    return implementation.join(implementation.dirname(value), basename);
}

export const __internals = {
    LIVE_MODES,
    findReportPath,
    findFindingsPath,
    findArtifactPath,
    siblingArtifactPath,
};
