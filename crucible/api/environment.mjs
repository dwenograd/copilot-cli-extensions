// crucible/api/environment.mjs
//
// Environment, configuration and local-state resolution for the Crucible thin
// extension. Every path the extension touches is derived here from operator-
// owned environment variables (never from tool arguments) and validated to be
// on a trusted local filesystem. All failures are typed EnvironmentErrors so
// the SDK boundary can surface them clearly.
//
// Deterministic identity: an investigationId is derived from the canonical
// objective + projectDir + harnessId as a safe slug plus a SHA-256 suffix, and
// all state/artifact directories live under the local state root — never under
// the project, a NAS mount, or a cloud-sync folder.

import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

import { assertLocalDatabasePath } from "../persistence/index.mjs";
import { DOMAIN_VERSION } from "../domain/index.mjs";
import { EnvironmentError } from "./errors.mjs";

// Fixed contract defaults the tool surface does not expose as arguments. These
// are part of the frozen contract identity but are not operator-tunable knobs
// at the thin-extension layer.
export const POLICY_VERSION = "crucible-policy-1";
export const CRITICALITY = "standard";

const DEFAULT_ROOT_DIRNAME = "Crucible";
const DEFAULT_ALLOWLIST_FILENAME = "harnesses.json";
const DEFAULT_INVESTIGATIONS_DIRNAME = "investigations";
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/u;

function hasText(value) {
    return typeof value === "string" && value.trim().length > 0;
}

function requireAbsoluteLocalPath(value, label, env) {
    if (!hasText(value)) {
        throw new EnvironmentError(`${label} is not configured`, { label });
    }
    if (!path.isAbsolute(value)) {
        throw new EnvironmentError(`${label} must be an absolute path`, { label, value });
    }
    try {
        return assertLocalDatabasePath(value, { env });
    } catch (error) {
        throw new EnvironmentError(
            `${label} must be on a trusted local filesystem: ${error?.message ?? String(error)}`,
            { label, value, reason: error?.details?.reason ?? error?.code ?? null },
        );
    }
}

function localAppData(env) {
    const value = env?.LOCALAPPDATA;
    if (!hasText(value)) {
        throw new EnvironmentError(
            "LOCALAPPDATA is not set; set CRUCIBLE_ALLOWLIST_PATH and CRUCIBLE_STATE_ROOT explicitly",
            { variable: "LOCALAPPDATA" },
        );
    }
    return value;
}

// Operator-owned harness allowlist path: CRUCIBLE_ALLOWLIST_PATH, else the
// per-user default under %LOCALAPPDATA%. Never taken from tool arguments.
export function resolveAllowlistPath(env) {
    const raw = hasText(env?.CRUCIBLE_ALLOWLIST_PATH)
        ? env.CRUCIBLE_ALLOWLIST_PATH
        : path.join(localAppData(env), DEFAULT_ROOT_DIRNAME, DEFAULT_ALLOWLIST_FILENAME);
    return requireAbsoluteLocalPath(raw, "CRUCIBLE_ALLOWLIST_PATH", env);
}

// Local investigation state root: CRUCIBLE_STATE_ROOT, else default under
// %LOCALAPPDATA%.
export function resolveStateRoot(env) {
    const raw = hasText(env?.CRUCIBLE_STATE_ROOT)
        ? env.CRUCIBLE_STATE_ROOT
        : path.join(localAppData(env), DEFAULT_ROOT_DIRNAME, DEFAULT_INVESTIGATIONS_DIRNAME);
    return requireAbsoluteLocalPath(raw, "CRUCIBLE_STATE_ROOT", env);
}

// Copilot SDK path: COPILOT_SDK_PATH (required, no default).
export function resolveSdkPath(env) {
    if (!hasText(env?.COPILOT_SDK_PATH)) {
        throw new EnvironmentError("COPILOT_SDK_PATH is required", { variable: "COPILOT_SDK_PATH" });
    }
    return requireAbsoluteLocalPath(env.COPILOT_SDK_PATH, "COPILOT_SDK_PATH", env);
}

// CLI executable: CRUCIBLE_CLI_PATH, else the environment-supplied strict local
// absolute default COPILOT_CLI_PATH. Required — fail clearly if neither exists.
export function resolveCliPath(env) {
    let raw = hasText(env?.CRUCIBLE_CLI_PATH) ? env.CRUCIBLE_CLI_PATH : env?.COPILOT_CLI_PATH;
    if (!hasText(raw)) {
        try {
            const output = execFileSync(
                process.platform === "win32" ? "where.exe" : "which",
                [process.platform === "win32" ? "copilot.exe" : "copilot"],
                {
                    encoding: "utf8",
                    windowsHide: true,
                    stdio: ["ignore", "pipe", "ignore"],
                    env,
                },
            );
            raw = output.split(/\r?\n/u).map((line) => line.trim()).find(Boolean);
        } catch {
            raw = null;
        }
    }
    if (!hasText(raw)) {
        throw new EnvironmentError(
            "CLI executable path is required (set CRUCIBLE_CLI_PATH/COPILOT_CLI_PATH or place copilot on PATH)",
            { variable: "CRUCIBLE_CLI_PATH" },
        );
    }
    return requireAbsoluteLocalPath(raw, "CRUCIBLE_CLI_PATH", env);
}

// Resolve every runtime path crucible_start needs in one place, failing clearly
// if any required environment configuration is unavailable.
export function resolveStartEnvironment(env) {
    return Object.freeze({
        allowlistPath: resolveAllowlistPath(env),
        stateRoot: resolveStateRoot(env),
        sdkPath: resolveSdkPath(env),
        cliPath: resolveCliPath(env),
    });
}

function sha256Hex(value) {
    return createHash("sha256").update(value, "utf8").digest("hex");
}

// Whitespace-canonical objective: trimmed and internal runs collapsed. Used
// both for the deterministic id material and as the contract objective so the
// identity and the frozen contract stay consistent.
export function canonicalObjective(objective) {
    if (typeof objective !== "string") {
        throw new EnvironmentError("objective must be a string", { field: "objective" });
    }
    const normalized = objective.trim().replace(/\s+/gu, " ");
    if (normalized.length === 0) {
        throw new EnvironmentError("objective must be a non-empty string", { field: "objective" });
    }
    return normalized;
}

function normalizeProjectDirForHash(projectDir) {
    return path.resolve(projectDir).replace(/\//gu, "\\").toLowerCase();
}

function slugify(text) {
    return text
        .toLowerCase()
        .replace(/[^a-z0-9]+/gu, "-")
        .replace(/^-+|-+$/gu, "")
        .slice(0, 40)
        .replace(/-+$/gu, "");
}

// Deterministic, filesystem-safe investigationId: safe slug of the objective
// plus a SHA-256 suffix over domain version + canonical objective + projectDir
// + harnessId. A domain-version change must never reopen an older identity.
export function deriveInvestigationId({ objective, projectDir, harnessId }) {
    const canonicalObj = canonicalObjective(objective);
    if (!hasText(projectDir)) {
        throw new EnvironmentError("project_dir must be a non-empty string", { field: "project_dir" });
    }
    if (typeof harnessId !== "string" || !IDENTIFIER_RE.test(harnessId)) {
        throw new EnvironmentError("harness_id must be a safe identifier", { field: "harness_id" });
    }
    const material = [
        `crucible-investigation-domain-v${DOMAIN_VERSION}`,
        harnessId,
        canonicalObj,
        normalizeProjectDirForHash(projectDir),
    ].join("\u0000");
    const suffix = sha256Hex(material).slice(0, 16);
    const slug = slugify(canonicalObj);
    const investigationId = slug.length > 0 ? `${slug}-${suffix}` : `inv-${suffix}`;
    if (!IDENTIFIER_RE.test(investigationId)) {
        // Defensive: the slug alphabet + hex suffix always satisfy this, but a
        // future slug change must never emit a path-unsafe id.
        throw new EnvironmentError("derived investigationId is not filesystem-safe", { investigationId });
    }
    return investigationId;
}

// Deterministic lowercase runner-epoch id (required lowercase identifier).
export function deriveRunnerEpochId(investigationId) {
    return `epoch-${sha256Hex(investigationId).slice(0, 16)}`;
}

// Local state/artifact layout for one investigation, all under the state root.
export function resolveInvestigationPaths(stateRoot, investigationId) {
    const investigationDir = path.join(stateRoot, investigationId);
    const stateDir = path.join(investigationDir, "state");
    const artifactRoot = path.join(investigationDir, "artifacts");
    const eventsDbPath = path.join(stateDir, "events.sqlite");
    return Object.freeze({ investigationDir, stateDir, artifactRoot, eventsDbPath });
}

// Build the raw supervisor config input (the actual runtime API then
// normalizes/validates it). Runner reads worker models / rounds from the frozen
// contract, so only paths + identity + optional deadline are supplied here.
export function buildSupervisorConfigInput({
    investigationId,
    stateDir,
    artifactRoot,
    allowlistPath,
    sdkPath,
    cliPath,
    deadlineIso,
    runnerEpochId = deriveRunnerEpochId(investigationId),
}) {
    return {
        runner: {
            investigationId,
            stateDir,
            artifactRoot,
            allowlistPath,
            copilotSdkPath: sdkPath,
            copilotCliPath: cliPath,
            runnerEpochId,
            ...(hasText(deadlineIso) ? { deadline: deadlineIso } : {}),
        },
    };
}
