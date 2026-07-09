// oracle-v3/measurement/allowlist.mjs
//
// HarnessAllowlist: the operator-owned, strictly-schema'd catalogue of
// executables the measurement boundary is permitted to spawn.
//
// The allowlist lives at a filesystem path chosen by the operator (the
// extension/runner supplies it explicitly — the executor NEVER discovers it
// via search paths, env vars, or working-directory heuristics). Every field
// is validated; unknown fields at any level are rejected. Every referenced
// file (the allowlist itself, the executable, any interpreter/dependency)
// is verified and hashed *before every run*, not just at load time — an
// attacker who swaps the executable file after the allowlist is cached is
// caught at the next invocation.
//
// This module intentionally exposes NO way to construct an entry from an
// arbitrary executable path — the only supported entry point is
// `loadHarnessAllowlist(allowlistPath)`. That is the whole point of the
// fail-closed boundary.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

import {
    hashCanonical,
    immutableCanonical,
} from "../domain/canonical.mjs";
import {
    AllowlistInvalidError,
    MEASUREMENT_ERROR_CODES,
    MeasurementError,
} from "./errors.mjs";
import {
    FILE_HASH_ALGORITHM,
    closeVerifiedFileHandle,
    normalizeExpectedHash,
    openVerifiedFileHandle,
    stageVerifiedFileHandle,
    verifyAndHashFile,
    verifyLocalRegularFile,
} from "./fs-verify.mjs";

// Algorithm tag for canonical-JSON hashes of allowlist entries. Kept distinct
// from the generic domain canonical hash so an entry hash cannot be silently
// confused with, e.g., a contract hash even if the bytes happened to match.
export const ENTRY_HASH_ALGORITHM = "sha256:oracle-measurement-entry-v1";
export const ALLOWLIST_HASH_ALGORITHM = "sha256:oracle-measurement-allowlist-v1";

// Maximum sizes chosen defensively. The allowlist is small operator-owned
// JSON — 1 MiB is generous; anything larger is almost certainly wrong.
const MAX_ALLOWLIST_BYTES = 1 * 1024 * 1024;

// Known argv template placeholders. Only these are substituted; any other
// `{{...}}` pattern in a template argv is rejected at load time so that a
// new placeholder cannot be silently misused as opaque data.
export const ARGV_PLACEHOLDERS = Object.freeze(["candidatePath", "attemptId"]);

const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/u;
const ENV_KEY = /^[A-Z_][A-Z0-9_]{0,127}$/u;
const PLACEHOLDER_ANY = /\{\{([^}]*)\}\}/gu;
const STATIC_FILE_EXTENSION = /\.(?:bat|cmd|com|dll|exe|json|mjs|cjs|js|jsx|ps1|py|pyw|rb|sh|ts|tsx|wasm|yaml|yml)$/iu;
const INTERPRETER_BASENAMES = new Set([
    "bash",
    "bash.exe",
    "cmd",
    "cmd.exe",
    "deno",
    "deno.exe",
    "node",
    "node.exe",
    "perl",
    "perl.exe",
    "php",
    "php.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "python",
    "python.exe",
    "python3",
    "python3.exe",
    "ruby",
    "ruby.exe",
    "sh",
]);
const verifiedEntries = new WeakMap();
const runLeases = new WeakMap();
const loadedAllowlists = new WeakSet();

const ENTRY_ALLOWED_KEYS = new Set([
    "id",
    "executable",
    "executableSha256",
    "argvTemplate",
    "cwd",
    "dependencies",
    "allowedEnv",
    "timeoutMs",
    "maxStdoutBytes",
    "maxStderrBytes",
    "executesCandidateCode",
    "validationCases",
    "description",
]);

const DEPENDENCY_ALLOWED_KEYS = new Set(["path", "sha256", "role"]);
const VALIDATION_CASE_ALLOWED_KEYS = new Set(["snapshotHash", "description"]);

function invalid(message, details) {
    throw new AllowlistInvalidError(message, details);
}

function requireObject(value, field) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        invalid(`${field} must be an object`);
    }
}

function requireString(value, field, { maxLength = 4096, minLength = 1 } = {}) {
    if (typeof value !== "string" || value.length < minLength || value.length > maxLength) {
        invalid(`${field} must be a string of length ${minLength}..${maxLength}`);
    }
    return value;
}

function requirePositiveInteger(value, field, max) {
    if (!Number.isInteger(value) || value <= 0 || value > max) {
        invalid(`${field} must be a positive integer <= ${max}`);
    }
    return value;
}

function requireBool(value, field) {
    if (typeof value !== "boolean") {
        invalid(`${field} must be a boolean`);
    }
    return value;
}

function rejectUnknownKeys(obj, allowed, field) {
    for (const key of Object.keys(obj)) {
        if (!allowed.has(key)) {
            invalid(`${field} has unknown key ${JSON.stringify(key)}`);
        }
    }
}

function normalizeArgvTemplate(argvTemplate, entryId) {
    if (!Array.isArray(argvTemplate)) {
        invalid(`entries.${entryId}.argvTemplate must be an array`);
    }
    if (argvTemplate.length > 256) {
        invalid(`entries.${entryId}.argvTemplate is too long (max 256 items)`);
    }
    const out = [];
    for (let i = 0; i < argvTemplate.length; i += 1) {
        const raw = argvTemplate[i];
        if (typeof raw !== "string") {
            invalid(`entries.${entryId}.argvTemplate[${i}] must be a string`);
        }
        if (raw.length > 4096) {
            invalid(`entries.${entryId}.argvTemplate[${i}] is too long`);
        }
        // No control characters — an entry file that contains a NUL would
        // let the argument break out of Windows' argv parser assumptions.
        // eslint-disable-next-line no-control-regex
        if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(raw)) {
            invalid(`entries.${entryId}.argvTemplate[${i}] contains disallowed control characters`);
        }
        // Any {{...}} placeholder must be from the known set. This is the
        // *only* form of substitution the executor supports.
        const placeholders = [...raw.matchAll(PLACEHOLDER_ANY)].map((m) => m[1]);
        for (const name of placeholders) {
            if (!ARGV_PLACEHOLDERS.includes(name)) {
                invalid(
                    `entries.${entryId}.argvTemplate[${i}] references unknown placeholder {{${name}}}`,
                    { known: ARGV_PLACEHOLDERS },
                );
            }
        }
        out.push(raw);
    }
    return Object.freeze(out);
}

function normalizeAllowedEnv(allowedEnv, entryId) {
    if (allowedEnv === undefined || allowedEnv === null) {
        return Object.freeze({});
    }
    requireObject(allowedEnv, `entries.${entryId}.allowedEnv`);
    const out = {};
    const keys = Object.keys(allowedEnv).sort();
    for (const key of keys) {
        if (!ENV_KEY.test(key)) {
            invalid(`entries.${entryId}.allowedEnv key ${JSON.stringify(key)} must match /^[A-Z_][A-Z0-9_]*$/`);
        }
        const value = allowedEnv[key];
        if (typeof value !== "string" || value.length > 32768) {
            invalid(`entries.${entryId}.allowedEnv[${key}] must be a string <= 32768 chars`);
        }
        // eslint-disable-next-line no-control-regex
        if (/\u0000/u.test(value)) {
            invalid(`entries.${entryId}.allowedEnv[${key}] must not contain NUL`);
        }
        out[key] = value;
    }
    return Object.freeze(out);
}

function normalizeDependencies(dependencies, entryId) {
    if (dependencies === undefined || dependencies === null) {
        return Object.freeze([]);
    }
    if (!Array.isArray(dependencies)) {
        invalid(`entries.${entryId}.dependencies must be an array`);
    }
    if (dependencies.length > 64) {
        invalid(`entries.${entryId}.dependencies has too many entries (max 64)`);
    }
    const out = [];
    const seen = new Set();
    for (let i = 0; i < dependencies.length; i += 1) {
        const dep = dependencies[i];
        requireObject(dep, `entries.${entryId}.dependencies[${i}]`);
        rejectUnknownKeys(dep, DEPENDENCY_ALLOWED_KEYS, `entries.${entryId}.dependencies[${i}]`);
        const depPath = requireString(dep.path, `entries.${entryId}.dependencies[${i}].path`);
        if (!path.isAbsolute(depPath)) {
            invalid(`entries.${entryId}.dependencies[${i}].path must be absolute`);
        }
        const expected = normalizeExpectedHash(
            requireString(dep.sha256, `entries.${entryId}.dependencies[${i}].sha256`, { maxLength: 200 }),
            `entries.${entryId}.dependencies[${i}].sha256`,
        );
        const role = dep.role === undefined
            ? "dependency"
            : requireString(dep.role, `entries.${entryId}.dependencies[${i}].role`, { maxLength: 64 });
        const key = process.platform === "win32"
            ? path.resolve(depPath).toLowerCase()
            : path.resolve(depPath);
        if (seen.has(key)) {
            invalid(`entries.${entryId}.dependencies contains duplicate path ${JSON.stringify(depPath)}`);
        }
        seen.add(key);
        out.push(Object.freeze({ path: path.resolve(depPath), sha256: expected, role }));
    }
    return Object.freeze(out);
}

function pathKey(value) {
    const resolved = path.resolve(value);
    return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function splitStaticFileArg(raw, base) {
    if ([...raw.matchAll(PLACEHOLDER_ANY)].length > 0) return null;
    if (/^file:/iu.test(raw)) {
        invalid("argvTemplate file: URLs are not supported; declare a normal dependency path");
    }
    let prefix = "";
    let value = raw;
    const equals = raw.indexOf("=");
    if (raw.startsWith("-") && equals > 0) {
        prefix = raw.slice(0, equals + 1);
        value = raw.slice(equals + 1);
    }
    const pathLike = path.isAbsolute(value)
        || value.includes("/")
        || value.includes("\\")
        || STATIC_FILE_EXTENSION.test(value)
        || (!value.startsWith("-") && fs.existsSync(path.resolve(base, value)));
    return pathLike && value.length > 0 ? { prefix, value } : null;
}

function normalizeArgvDependencyRefs({
    argvTemplate,
    dependencies,
    executable,
    cwd,
    entryId,
}) {
    const byPath = new Map(dependencies.map((dep, index) => [pathKey(dep.path), index]));
    const base = cwd ?? path.dirname(executable);
    const refs = [];
    for (let index = 0; index < argvTemplate.length; index += 1) {
        const staticRef = splitStaticFileArg(argvTemplate[index], base);
        if (staticRef === null) continue;
        const resolved = path.isAbsolute(staticRef.value)
            ? path.resolve(staticRef.value)
            : path.resolve(base, staticRef.value);
        const dependencyIndex = byPath.get(pathKey(resolved));
        if (dependencyIndex === undefined) {
            throw new AllowlistInvalidError(
                `entries.${entryId}.argvTemplate[${index}] references a static file that is not a hash-pinned dependency`,
                {
                    code: MEASUREMENT_ERROR_CODES.UNDECLARED_ARGV_FILE,
                    argv: argvTemplate[index],
                    resolvedPath: resolved,
                },
            );
        }
        refs.push(Object.freeze({
            argvIndex: index,
            prefix: staticRef.prefix,
            dependencyIndex,
        }));
    }

    if (INTERPRETER_BASENAMES.has(path.basename(executable).toLowerCase())) {
        let firstPositionalIndex = -1;
        for (let index = 0; index < argvTemplate.length; index += 1) {
            const arg = argvTemplate[index];
            if (arg === "--") continue;
            if (!arg.startsWith("-")) {
                firstPositionalIndex = index;
                break;
            }
        }
        if (firstPositionalIndex >= 0) {
            const first = argvTemplate[firstPositionalIndex];
            if (first.includes("{{candidatePath}}")) {
                invalid(
                    `entries.${entryId}.argvTemplate cannot use candidatePath as an interpreter script`,
                );
            }
            if (!refs.some((ref) => ref.argvIndex === firstPositionalIndex)) {
                invalid(
                    `entries.${entryId}.argvTemplate interpreter entrypoint must be a declared hash-pinned dependency`,
                );
            }
        }
    }
    return Object.freeze(refs);
}

function normalizeValidationCases(validationCases, entryId) {
    if (validationCases === undefined || validationCases === null) {
        return null;
    }
    requireObject(validationCases, `entries.${entryId}.validationCases`);
    const out = {};
    const keys = Object.keys(validationCases).sort();
    if (keys.length > 4096) {
        invalid(`entries.${entryId}.validationCases has too many cases`);
    }
    for (const key of keys) {
        if (!SAFE_ID.test(key)) {
            invalid(`entries.${entryId}.validationCases key ${JSON.stringify(key)} is not a safe id`);
        }
        const spec = validationCases[key];
        requireObject(spec, `entries.${entryId}.validationCases[${key}]`);
        rejectUnknownKeys(spec, VALIDATION_CASE_ALLOWED_KEYS, `entries.${entryId}.validationCases[${key}]`);
        const snapshotHashRaw = requireString(
            spec.snapshotHash,
            `entries.${entryId}.validationCases[${key}].snapshotHash`,
            { maxLength: 200 },
        ).toLowerCase();
        if (!/^sha256:[a-f0-9]{64}$/u.test(snapshotHashRaw)) {
            invalid(
                `entries.${entryId}.validationCases[${key}].snapshotHash must be an ArtifactStore sha256:<hex> id`,
            );
        }
        const snapshotHash = snapshotHashRaw;
        out[key] = Object.freeze({
            snapshotHash,
            description: spec.description === undefined
                ? null
                : requireString(spec.description, `entries.${entryId}.validationCases[${key}].description`, { maxLength: 4096 }),
        });
    }
    return Object.freeze(out);
}

function normalizeEntry(entryId, raw) {
    requireObject(raw, `entries.${entryId}`);
    rejectUnknownKeys(raw, ENTRY_ALLOWED_KEYS, `entries.${entryId}`);
    if (raw.id !== undefined && raw.id !== entryId) {
        invalid(`entries.${entryId}.id must equal its keyed id`);
    }

    const executable = requireString(raw.executable, `entries.${entryId}.executable`);
    if (!path.isAbsolute(executable)) {
        invalid(`entries.${entryId}.executable must be absolute`);
    }
    const executableSha256 = normalizeExpectedHash(
        requireString(raw.executableSha256, `entries.${entryId}.executableSha256`, { maxLength: 200 }),
        `entries.${entryId}.executableSha256`,
    );
    const argvTemplate = normalizeArgvTemplate(raw.argvTemplate, entryId);
    let cwd = null;
    if (raw.cwd !== undefined && raw.cwd !== null) {
        cwd = requireString(raw.cwd, `entries.${entryId}.cwd`);
        if (!path.isAbsolute(cwd)) {
            invalid(`entries.${entryId}.cwd must be absolute`);
        }
    }
    const dependencies = normalizeDependencies(raw.dependencies, entryId);
    const argvDependencyRefs = normalizeArgvDependencyRefs({
        argvTemplate,
        dependencies,
        executable,
        cwd,
        entryId,
    });
    const allowedEnv = normalizeAllowedEnv(raw.allowedEnv, entryId);
    const timeoutMs = requirePositiveInteger(raw.timeoutMs, `entries.${entryId}.timeoutMs`, 60 * 60 * 1000);
    const maxStdoutBytes = requirePositiveInteger(raw.maxStdoutBytes, `entries.${entryId}.maxStdoutBytes`, 64 * 1024 * 1024);
    const maxStderrBytes = requirePositiveInteger(raw.maxStderrBytes, `entries.${entryId}.maxStderrBytes`, 64 * 1024 * 1024);
    const executesCandidateCode = requireBool(raw.executesCandidateCode, `entries.${entryId}.executesCandidateCode`);
    const validationCases = normalizeValidationCases(raw.validationCases, entryId);

    const normalized = {
        id: entryId,
        executable,
        executableSha256,
        argvTemplate,
        argvDependencyRefs,
        cwd,
        dependencies,
        allowedEnv,
        timeoutMs,
        maxStdoutBytes,
        maxStderrBytes,
        executesCandidateCode,
        validationCases,
        description: raw.description === undefined
            ? null
            : requireString(raw.description, `entries.${entryId}.description`, { maxLength: 4096 }),
    };

    const canonical = immutableCanonical(normalized);
    const entryHash = hashCanonical(canonical, ENTRY_HASH_ALGORITHM);
    return { entry: canonical, entryHash };
}

const ALLOWLIST_ALLOWED_KEYS = new Set(["version", "entries", "description"]);

function parseAllowlistJson(rawText, allowlistPath) {
    if (rawText.length > MAX_ALLOWLIST_BYTES) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.ALLOWLIST_LOAD,
            `allowlist file exceeds maximum size of ${MAX_ALLOWLIST_BYTES} bytes`,
            { path: allowlistPath, bytes: rawText.length },
        );
    }
    let parsed;
    try {
        parsed = JSON.parse(rawText);
    } catch (err) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.ALLOWLIST_LOAD,
            `allowlist file is not valid JSON: ${err?.message ?? String(err)}`,
            { path: allowlistPath },
        );
    }
    return parsed;
}

// Load the allowlist at `allowlistPath`. On success, returns a frozen
// HarnessAllowlist object with methods to look up + verify entries.
export function loadHarnessAllowlist(allowlistPath) {
    const resolvedAllowlistPath = verifyLocalRegularFile(allowlistPath, { label: "allowlist" });
    let rawText;
    try {
        rawText = fs.readFileSync(resolvedAllowlistPath, "utf8");
    } catch (err) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.ALLOWLIST_LOAD,
            `failed to read allowlist: ${err?.message ?? String(err)}`,
            { path: resolvedAllowlistPath, cause: err?.code ?? null },
        );
    }

    const parsed = parseAllowlistJson(rawText, resolvedAllowlistPath);
    requireObject(parsed, "allowlist");
    rejectUnknownKeys(parsed, ALLOWLIST_ALLOWED_KEYS, "allowlist");
    if (parsed.version !== 1) {
        invalid(`allowlist.version must be 1 (got ${JSON.stringify(parsed.version)})`);
    }
    requireObject(parsed.entries, "allowlist.entries");

    const entryIds = Object.keys(parsed.entries).sort();
    if (entryIds.length === 0) {
        invalid("allowlist.entries must define at least one entry");
    }
    if (entryIds.length > 1024) {
        invalid("allowlist.entries has too many entries (max 1024)");
    }
    for (const id of entryIds) {
        if (!SAFE_ID.test(id)) {
            invalid(`allowlist.entries key ${JSON.stringify(id)} is not a safe id`);
        }
    }

    const entries = {};
    const entryHashes = {};
    for (const id of entryIds) {
        const { entry, entryHash } = normalizeEntry(id, parsed.entries[id]);
        entries[id] = entry;
        entryHashes[id] = entryHash;
    }

    // Snapshot the allowlist file's own hash and content-hash. The file hash
    // is over the raw bytes-on-disk (so a tampered file after load is
    // detectable if the caller re-verifies); the content hash is over the
    // canonicalised entries (so equivalent JSON with different whitespace
    // still produces the same content hash for logging).
    const allowlistFile = verifyAndHashFile(resolvedAllowlistPath, sha256HexOfString(rawText), {
        label: "allowlist",
    });
    const contentHash = hashCanonical(entries, ALLOWLIST_HASH_ALGORITHM);

    const state = Object.freeze({
        version: 1,
        allowlistPath: resolvedAllowlistPath,
        allowlistFileHash: allowlistFile.hash,
        contentHash,
        loadedAt: new Date().toISOString(),
        entries: immutableCanonical(entries),
        entryHashes: immutableCanonical(entryHashes),
    });

    const allowlist = Object.freeze({
        allowlistPath: state.allowlistPath,
        allowlistFileHash: state.allowlistFileHash,
        contentHash: state.contentHash,
        loadedAt: state.loadedAt,

        listEntryIds: () => Object.keys(state.entries),

        getEntry(id) {
            if (typeof id !== "string" || !Object.hasOwn(state.entries, id)) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.ALLOWLIST_ENTRY_NOT_FOUND,
                    `no allowlist entry ${JSON.stringify(id)}`,
                );
            }
            return state.entries[id];
        },

        getEntryHash(id) {
            if (typeof id !== "string" || !Object.hasOwn(state.entryHashes, id)) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.ALLOWLIST_ENTRY_NOT_FOUND,
                    `no allowlist entry ${JSON.stringify(id)}`,
                );
            }
            return state.entryHashes[id];
        },

        // Re-verify the allowlist file on disk against the hash captured at
        // load time. Callers do this before every run so an attacker who
        // swaps the file after we load cannot ride on our cached view.
        reverifyAllowlistFile() {
            return verifyAndHashFile(state.allowlistPath, state.allowlistFileHash, {
                label: "allowlist",
            });
        },

        // Verify one entry's executable and dependencies live at the declared
        // paths, are local regular files, and hash to the declared values.
        // Returns a frozen VerifiedHarnessEntry the executor accepts.
        verifyEntry(id) {
            const entry = this.getEntry(id);
            this.reverifyAllowlistFile();
            const executable = verifyAndHashFile(entry.executable, entry.executableSha256, {
                label: `entries.${id}.executable`,
            });
            const dependencies = entry.dependencies.map((dep, i) => {
                const v = verifyAndHashFile(dep.path, dep.sha256, {
                    label: `entries.${id}.dependencies[${i}]`,
                });
                return Object.freeze({
                    path: v.resolvedPath,
                    sha256: v.hash,
                    role: dep.role,
                });
            });
            const verified = Object.freeze({
                entry,
                entryHash: this.getEntryHash(id),
                allowlistFileHash: state.allowlistFileHash,
                executablePath: executable.resolvedPath,
                executableHash: executable.hash,
                dependencies: Object.freeze(dependencies),
                verifiedAt: new Date().toISOString(),
            });
            verifiedEntries.set(verified, Object.freeze({
                allowlist,
                state,
                id,
            }));
            return verified;
        },
    });
    loadedAllowlists.add(allowlist);
    return allowlist;
}

export function isVerifiedHarnessEntry(value) {
    return value !== null && typeof value === "object" && verifiedEntries.has(value);
}

export function isLoadedHarnessAllowlist(value) {
    return value !== null && typeof value === "object" && loadedAllowlists.has(value);
}

function closeLeaseState(state) {
    if (state.closed) return false;
    state.closed = true;
    closeVerifiedFileHandle(state.executable);
    for (const dependency of state.dependencies) {
        closeVerifiedFileHandle(dependency.handle);
    }
    return true;
}

// Internal executor handshake. The WeakMap identity cannot be forged and the
// source files are re-opened and re-hashed for this run. This function is not
// re-exported from measurement/index.mjs.
export function acquireVerifiedHarnessRun(verifiedEntry, expectedAllowlist) {
    const registration = verifiedEntries.get(verifiedEntry);
    if (registration === undefined) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "run() requires a verifiedEntry issued by the loaded HarnessAllowlist instance",
        );
    }
    if (!loadedAllowlists.has(expectedAllowlist)
        || registration.allowlist !== expectedAllowlist) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "verifiedEntry was not issued by this executor's loaded HarnessAllowlist instance",
        );
    }
    const { allowlist, state, id } = registration;
    const entry = allowlist.getEntry(id);
    allowlist.reverifyAllowlistFile();
    let executable;
    const dependencies = [];
    try {
        executable = openVerifiedFileHandle(entry.executable, entry.executableSha256, {
            label: `entries.${id}.executable`,
        });
        for (let index = 0; index < entry.dependencies.length; index += 1) {
            const dependency = entry.dependencies[index];
            dependencies.push(Object.freeze({
                spec: dependency,
                handle: openVerifiedFileHandle(dependency.path, dependency.sha256, {
                    label: `entries.${id}.dependencies[${index}]`,
                }),
            }));
        }
    } catch (error) {
        if (executable !== undefined) closeVerifiedFileHandle(executable);
        for (const dependency of dependencies) closeVerifiedFileHandle(dependency.handle);
        throw error;
    }
    const lease = Object.freeze({
        harnessId: id,
        verifiedAt: new Date().toISOString(),
    });
    runLeases.set(lease, {
        closed: false,
        entry,
        entryHash: state.entryHashes[id],
        allowlistFileHash: state.allowlistFileHash,
        executable,
        dependencies,
    });
    return lease;
}

function requireRunLease(lease) {
    const state = runLeases.get(lease);
    if (state === undefined || state.closed) {
        throw new MeasurementError(
            MEASUREMENT_ERROR_CODES.INVALID_ARGUMENT,
            "verified harness run lease is not live",
        );
    }
    return state;
}

function isInside(candidate, root) {
    const relative = path.relative(path.resolve(root), path.resolve(candidate));
    return relative === ""
        || (!relative.startsWith(`..${path.sep}`)
            && relative !== ".."
            && !path.isAbsolute(relative));
}

function dependencyLayout(entry, stageRoot) {
    const workRoot = path.join(stageRoot, "work");
    if (entry.dependencies.length === 0) {
        fs.mkdirSync(workRoot, { recursive: true });
        return { workRoot, paths: [] };
    }
    let anchor;
    if (entry.cwd !== null) {
        anchor = path.resolve(entry.cwd);
        for (const dependency of entry.dependencies) {
            if (!isInside(dependency.path, anchor)) {
                throw new MeasurementError(
                    MEASUREMENT_ERROR_CODES.STAGING_REFUSED,
                    "declared cwd cannot be staged safely because a dependency lies outside it",
                    { cwd: entry.cwd, dependency: dependency.path },
                );
            }
        }
    } else {
        anchor = path.dirname(entry.dependencies[0].path);
        for (const dependency of entry.dependencies.slice(1)) {
            while (!isInside(dependency.path, anchor)) {
                const parent = path.dirname(anchor);
                if (parent === anchor) {
                    throw new MeasurementError(
                        MEASUREMENT_ERROR_CODES.STAGING_REFUSED,
                        "declared dependencies do not share a stageable local layout",
                    );
                }
                anchor = parent;
            }
        }
    }
    const paths = entry.dependencies.map((dependency) => {
        const relative = path.relative(anchor, dependency.path);
        if (relative === ""
            || relative === ".."
            || relative.startsWith(`..${path.sep}`)
            || path.isAbsolute(relative)) {
            throw new MeasurementError(
                MEASUREMENT_ERROR_CODES.STAGING_REFUSED,
                "dependency layout escapes the private staging directory",
                { anchor, dependency: dependency.path },
            );
        }
        return path.join(workRoot, relative);
    });
    fs.mkdirSync(workRoot, { recursive: true });
    return { workRoot, paths };
}

// Copy every run-pinned file into a private staging root. Only these returned
// paths may reach spawn().
export function stageVerifiedHarnessRun(lease, stageRoot) {
    const state = requireRunLease(lease);
    const executableDestination = path.join(
        stageRoot,
        "bin",
        path.basename(state.executable.resolvedPath),
    );
    const layout = dependencyLayout(state.entry, stageRoot);
    const executable = stageVerifiedFileHandle(
        state.executable,
        executableDestination,
        { label: `entries.${state.entry.id}.executable` },
    );
    const dependencies = state.dependencies.map((dependency, index) => {
        const staged = stageVerifiedFileHandle(
            dependency.handle,
            layout.paths[index],
            { label: `entries.${state.entry.id}.dependencies[${index}]` },
        );
        return Object.freeze({
            ...staged,
            role: dependency.spec.role,
        });
    });
    return Object.freeze({
        entry: state.entry,
        entryHash: state.entryHash,
        allowlistFileHash: state.allowlistFileHash,
        executable,
        dependencies: Object.freeze(dependencies),
        cwd: layout.workRoot,
    });
}

export function releaseVerifiedHarnessRun(lease) {
    const state = runLeases.get(lease);
    if (state === undefined) return false;
    const released = closeLeaseState(state);
    runLeases.delete(lease);
    return released;
}

function sha256HexOfString(s) {
    return createHash("sha256").update(s, "utf8").digest("hex");
}
