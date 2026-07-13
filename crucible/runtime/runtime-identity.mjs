import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";

import {
    DEFAULT_RUNTIME_IDENTITY_POLICY,
    RUNTIME_IDENTITY_ASSUMPTIONS_HASH_ALGORITHM,
    RUNTIME_IDENTITY_CLI_IDENTITY_ALGORITHM,
    RUNTIME_IDENTITY_COMMANDS_IDENTITY_ALGORITHM,
    RUNTIME_IDENTITY_ENVIRONMENT_IDENTITY_ALGORITHM,
    RUNTIME_IDENTITY_FILE_HASH_ALGORITHM,
    RUNTIME_IDENTITY_FILE_IDENTITY_ALGORITHM,
    RUNTIME_IDENTITY_KIND,
    RUNTIME_IDENTITY_POLICY_HASH_ALGORITHM,
    RUNTIME_IDENTITY_ROOT_ALGORITHM,
    RUNTIME_IDENTITY_SANDBOX_IDENTITY_ALGORITHM,
    RUNTIME_IDENTITY_TREE_IDENTITY_ALGORITHM,
    RUNTIME_IDENTITY_TREE_MERKLE_ALGORITHM,
    RUNTIME_IDENTITY_VERSION,
    canonicalEqual,
    canonicalJson,
    hashCanonical,
    immutableCanonical,
    normalizeRuntimeIdentity,
    normalizeRuntimeIdentityPolicy,
    runtimeIdentityPolicyIdentity,
    runtimeIdentityRoot,
} from "../domain/index.mjs";
import {
    assertLocalDatabasePath,
    isNetworkOrUncPath,
} from "../persistence/index.mjs";
import {
    RuntimeConfigError,
    RuntimeDriftError,
    RuntimeIntegrityError,
} from "./errors.mjs";

export const RUNTIME_IDENTITY_RESULT_CODES = Object.freeze({
    RUNTIME_DRIFT: "RUNTIME_DRIFT",
});

const TREE_LEAF_HASH_ALGORITHM =
    "sha256:crucible-runtime-tree-leaf-v1";
const TREE_NODE_HASH_ALGORITHM =
    "sha256:crucible-runtime-tree-node-v1";
const ENVIRONMENT_VALUE_HASH_ALGORITHM =
    "sha256:crucible-runtime-environment-value-v1";
const HASH_CACHE_RECORD_ALGORITHM =
    "sha256:crucible-runtime-hash-cache-record-v1";
const HASH_CACHE_RECORD_VERSION = 1;
const READ_CHUNK_BYTES = 1024 * 1024;

function samePath(left, right) {
    const a = path.resolve(left);
    const b = path.resolve(right);
    return process.platform === "win32"
        ? a.toLowerCase() === b.toLowerCase()
        : a === b;
}

function pathInside(candidate, root) {
    const relative = path.relative(root, candidate);
    return relative === ""
        || (!relative.startsWith("..")
            && !path.isAbsolute(relative));
}

function requirePlainObject(value, field) {
    if (value === null
        || typeof value !== "object"
        || Array.isArray(value)
        || (Object.getPrototypeOf(value) !== Object.prototype
            && Object.getPrototypeOf(value) !== null)) {
        throw new RuntimeConfigError(`${field} must be a plain object`);
    }
    return value;
}

function requireAbsolutePath(value, field) {
    if (typeof value !== "string"
        || value.length === 0
        || !path.isAbsolute(value)) {
        throw new RuntimeConfigError(`${field} must be an absolute path`, {
            field,
            value,
        });
    }
    return value;
}

function statSignature(stat) {
    return Object.freeze({
        dev: stat.dev.toString(),
        ino: stat.ino.toString(),
        size: stat.size.toString(),
        mode: stat.mode.toString(),
        mtimeNs: stat.mtimeNs.toString(),
        ctimeNs: stat.ctimeNs.toString(),
        birthtimeNs: stat.birthtimeNs.toString(),
    });
}

function equalStatSignature(left, right) {
    return canonicalEqual(left, right);
}

function cacheRecordCore(value) {
    return {
        version: value.version,
        path: value.path,
        stat: value.stat,
        contentHash: value.contentHash,
    };
}

function cacheRecordSeal(value) {
    return hashCanonical(cacheRecordCore(value), HASH_CACHE_RECORD_ALGORITHM);
}

function validateCacheRecord(record, realPath) {
    if (record === null
        || typeof record !== "object"
        || Array.isArray(record)
        || record.version !== HASH_CACHE_RECORD_VERSION
        || record.path !== realPath
        || record.stat === null
        || typeof record.stat !== "object"
        || typeof record.contentHash !== "string"
        || typeof record.seal !== "string"
        || record.seal !== cacheRecordSeal(record)) {
        throw new RuntimeIntegrityError(
            "Runtime identity hash cache entry failed integrity verification",
            { path: realPath, reason: "cache-tamper" },
        );
    }
    return record;
}

export function createRuntimeIdentityHashCache(entries = []) {
    if (!Array.isArray(entries)) {
        throw new RuntimeConfigError("runtime identity cache entries must be an array");
    }
    return new Map(entries.map(([key, value]) => [key, value]));
}

function resolveLocalRegularFile(filePath, field, env) {
    const requested = requireAbsolutePath(filePath, field);
    try {
        assertLocalDatabasePath(requested, { env });
    } catch (error) {
        throw new RuntimeIntegrityError(
            `${field} must be on a trusted local filesystem`,
            { path: requested, cause: error?.code ?? null },
            { cause: error },
        );
    }
    if (isNetworkOrUncPath(requested)) {
        throw new RuntimeIntegrityError(`${field} must not be a network path`, {
            path: requested,
        });
    }
    let before;
    let real;
    try {
        before = fs.lstatSync(requested, { bigint: true });
        real = fs.realpathSync.native(requested);
    } catch (error) {
        throw new RuntimeIntegrityError(`${field} is unavailable`, {
            path: requested,
            cause: error?.code ?? null,
        }, { cause: error });
    }
    if (before.isSymbolicLink() || !before.isFile()) {
        throw new RuntimeIntegrityError(
            `${field} must be a regular non-symlink file`,
            { path: requested },
        );
    }
    if (!samePath(requested, real) || isNetworkOrUncPath(real)) {
        throw new RuntimeIntegrityError(
            `${field} must not resolve through a symlink or reparse point`,
            { path: requested, real },
        );
    }
    return Object.freeze({ real, stat: before });
}

function resolveLocalDirectory(directoryPath, field, env) {
    const requested = requireAbsolutePath(directoryPath, field);
    try {
        assertLocalDatabasePath(requested, { env });
    } catch (error) {
        throw new RuntimeIntegrityError(
            `${field} must be on a trusted local filesystem`,
            { path: requested, cause: error?.code ?? null },
            { cause: error },
        );
    }
    let before;
    let real;
    try {
        before = fs.lstatSync(requested, { bigint: true });
        real = fs.realpathSync.native(requested);
    } catch (error) {
        throw new RuntimeIntegrityError(`${field} is unavailable`, {
            path: requested,
            cause: error?.code ?? null,
        }, { cause: error });
    }
    if (before.isSymbolicLink() || !before.isDirectory()) {
        throw new RuntimeIntegrityError(
            `${field} must be a regular non-symlink directory`,
            { path: requested },
        );
    }
    if (!samePath(requested, real) || isNetworkOrUncPath(real)) {
        throw new RuntimeIntegrityError(
            `${field} must not resolve through a symlink or reparse point`,
            { path: requested, real },
        );
    }
    return Object.freeze({ real, stat: before });
}

function hashOpenFile(filePath, statBefore) {
    const fd = fs.openSync(filePath, "r");
    try {
        const openedBefore = fs.fstatSync(fd, { bigint: true });
        if (!equalStatSignature(
            statSignature(statBefore),
            statSignature(openedBefore),
        )) {
            throw new RuntimeIntegrityError(
                "Runtime identity file changed before hashing",
                { path: filePath },
            );
        }
        const hash = createHash("sha256");
        const buffer = Buffer.allocUnsafe(READ_CHUNK_BYTES);
        let offset = 0;
        while (true) {
            const count = fs.readSync(fd, buffer, 0, buffer.length, offset);
            if (count === 0) break;
            hash.update(buffer.subarray(0, count));
            offset += count;
        }
        const openedAfter = fs.fstatSync(fd, { bigint: true });
        if (!equalStatSignature(
            statSignature(openedBefore),
            statSignature(openedAfter),
        )) {
            throw new RuntimeIntegrityError(
                "Runtime identity file changed while hashing",
                { path: filePath },
            );
        }
        return `${RUNTIME_IDENTITY_FILE_HASH_ALGORITHM}:${hash.digest("hex")}`;
    } finally {
        fs.closeSync(fd);
    }
}

function contentHashForFile(resolved, {
    cache,
    trustVerifiedCache,
}) {
    const signature = statSignature(resolved.stat);
    if (cache instanceof Map && cache.has(resolved.real)) {
        const cached = validateCacheRecord(cache.get(resolved.real), resolved.real);
        if (equalStatSignature(cached.stat, signature)
            && trustVerifiedCache === true) {
            return cached.contentHash;
        }
    }
    const contentHash = hashOpenFile(resolved.real, resolved.stat);
    const after = resolveLocalRegularFile(
        resolved.real,
        "runtime identity file",
        {},
    );
    if (!equalStatSignature(signature, statSignature(after.stat))) {
        throw new RuntimeIntegrityError(
            "Runtime identity file changed after hashing",
            { path: resolved.real },
        );
    }
    if (cache instanceof Map) {
        const record = {
            version: HASH_CACHE_RECORD_VERSION,
            path: resolved.real,
            stat: signature,
            contentHash,
        };
        cache.set(resolved.real, Object.freeze({
            ...record,
            seal: cacheRecordSeal(record),
        }));
    }
    return contentHash;
}

function consumeFileBudget(stat, budget, limits, label) {
    const size = Number(stat.size);
    if (!Number.isSafeInteger(size)
        || size < 0
        || size > limits.maxFileBytes) {
        throw new RuntimeIntegrityError(
            `${label} exceeds the runtime identity per-file size cap`,
            { size, maxFileBytes: limits.maxFileBytes },
        );
    }
    budget.files += 1;
    budget.bytes += size;
    if (budget.files > limits.maxFiles || budget.bytes > limits.maxTotalBytes) {
        throw new RuntimeIntegrityError(
            "Runtime identity closure exceeds its file/byte caps",
            {
                files: budget.files,
                bytes: budget.bytes,
                maxFiles: limits.maxFiles,
                maxTotalBytes: limits.maxTotalBytes,
            },
        );
    }
    return size;
}

function buildFileIdentity(filePath, field, context) {
    const resolved = resolveLocalRegularFile(filePath, field, context.env);
    const size = consumeFileBudget(
        resolved.stat,
        context.budget,
        context.policy.limits,
        field,
    );
    const core = {
        kind: "file",
        path: resolved.real,
        size,
        contentHash: contentHashForFile(resolved, context),
    };
    return Object.freeze({
        ...core,
        identity: hashCanonical(
            core,
            RUNTIME_IDENTITY_FILE_IDENTITY_ALGORITHM,
        ),
    });
}

function normalizedRelativePath(root, candidate) {
    return path.relative(root, candidate).split(path.sep).join("/");
}

function matchesRuleValue(value, candidates) {
    return process.platform === "win32"
        ? candidates.some((candidate) =>
            candidate.toLowerCase() === value.toLowerCase())
        : candidates.includes(value);
}

function excludedByRule(relativePath, rule) {
    const segments = relativePath.split("/").filter(Boolean);
    const basename = segments.at(-1) ?? "";
    if (segments.some((segment) =>
        matchesRuleValue(segment, rule.excludedSegments))) {
        return true;
    }
    if (matchesRuleValue(basename, rule.excludedBasenames)) {
        return true;
    }
    const comparison = process.platform === "win32"
        ? basename.toLowerCase()
        : basename;
    return rule.excludedSuffixes.some((suffix) =>
        comparison.endsWith(process.platform === "win32"
            ? suffix.toLowerCase()
            : suffix));
}

function fileIncluded(relativePath, rule) {
    if (excludedByRule(relativePath, rule)) return false;
    if (rule.includedExtensions.length === 0) return true;
    const extension = path.extname(relativePath);
    return matchesRuleValue(extension, rule.includedExtensions);
}

function directoryIdentity(directoryPath) {
    const stat = fs.lstatSync(directoryPath, { bigint: true });
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
        throw new RuntimeIntegrityError(
            "Runtime identity tree contains a non-directory or reparse directory",
            { path: directoryPath },
        );
    }
    const real = fs.realpathSync.native(directoryPath);
    if (!samePath(directoryPath, real)) {
        throw new RuntimeIntegrityError(
            "Runtime identity tree contains a symlink or reparse directory",
            { path: directoryPath, real },
        );
    }
    return Object.freeze({ path: real, stat: statSignature(stat) });
}

function enumerateTree(root, rule, context) {
    const files = [];
    const directories = [];
    const pending = [{ directory: root, depth: 0 }];
    while (pending.length > 0) {
        const current = pending.pop();
        if (current.depth > context.policy.limits.maxDepth) {
            throw new RuntimeIntegrityError(
                "Runtime identity tree exceeds its maximum depth",
                {
                    root,
                    path: current.directory,
                    maxDepth: context.policy.limits.maxDepth,
                },
            );
        }
        const directory = directoryIdentity(current.directory);
        if (!pathInside(directory.path, root)) {
            throw new RuntimeIntegrityError(
                "Runtime identity tree directory escapes its root",
                { root, path: directory.path },
            );
        }
        directories.push(directory);
        const entries = context.readDirectory(current.directory);
        for (const entry of entries) {
            const name = typeof entry === "string" ? entry : entry.name;
            if (typeof name !== "string" || name.length === 0
                || name === "." || name === ".."
                || name.includes("/") || name.includes("\\")) {
                throw new RuntimeIntegrityError(
                    "Runtime identity tree returned an invalid directory entry",
                    { root, directory: current.directory, name },
                );
            }
            const candidate = path.join(current.directory, name);
            const relativePath = normalizedRelativePath(root, candidate);
            if (excludedByRule(relativePath, rule)) continue;
            const stat = fs.lstatSync(candidate, { bigint: true });
            if (stat.isSymbolicLink()) {
                throw new RuntimeIntegrityError(
                    "Runtime identity tree contains a symbolic link or reparse point",
                    { root, path: candidate },
                );
            }
            if (stat.isDirectory()) {
                pending.push({
                    directory: candidate,
                    depth: current.depth + 1,
                });
                continue;
            }
            if (!stat.isFile()) {
                throw new RuntimeIntegrityError(
                    "Runtime identity tree contains a non-regular filesystem entry",
                    { root, path: candidate },
                );
            }
            if (fileIncluded(relativePath, rule)) {
                files.push({ path: candidate, relativePath });
            }
        }
    }
    files.sort((left, right) =>
        left.relativePath.localeCompare(right.relativePath));
    const pathKeys = files.map((item) => process.platform === "win32"
        ? item.relativePath.toLowerCase()
        : item.relativePath);
    if (new Set(pathKeys).size !== pathKeys.length) {
        throw new RuntimeIntegrityError(
            "Runtime identity tree contains duplicate canonical paths",
            { root },
        );
    }
    return { files, directories };
}

function merkleRoot(leaves) {
    let level = leaves.map((leaf) => hashCanonical(
        leaf,
        TREE_LEAF_HASH_ALGORITHM,
    ));
    if (level.length === 0) {
        throw new RuntimeIntegrityError(
            "Runtime identity tree must contain at least one selected file",
        );
    }
    while (level.length > 1) {
        const next = [];
        for (let index = 0; index < level.length; index += 2) {
            const left = level[index];
            const right = level[index + 1] ?? left;
            next.push(hashCanonical({ left, right }, TREE_NODE_HASH_ALGORITHM));
        }
        level = next;
    }
    return hashCanonical(
        { leafCount: leaves.length, nodeRoot: level[0] },
        RUNTIME_IDENTITY_TREE_MERKLE_ALGORITHM,
    );
}

function buildTreeIdentity(rootPath, ruleName, field, context) {
    const root = resolveLocalDirectory(rootPath, field, context.env);
    const rule = context.policy.treeRules[ruleName];
    const { files, directories } = enumerateTree(root.real, rule, context);
    const leaves = [];
    let totalBytes = 0;
    for (const item of files) {
        const identity = buildFileIdentity(item.path, field, context);
        totalBytes += identity.size;
        leaves.push({
            path: item.relativePath,
            size: identity.size,
            contentHash: identity.contentHash,
        });
    }
    for (const directory of directories) {
        const current = directoryIdentity(directory.path);
        if (!equalStatSignature(directory.stat, current.stat)) {
            throw new RuntimeIntegrityError(
                "Runtime identity tree changed while it was hashed",
                { root: root.real, path: directory.path },
            );
        }
    }
    const core = {
        kind: "tree",
        rootPath: root.real,
        fileCount: leaves.length,
        totalBytes,
        merkleRoot: merkleRoot(leaves),
    };
    return Object.freeze({
        ...core,
        identity: hashCanonical(
            core,
            RUNTIME_IDENTITY_TREE_IDENTITY_ALGORITHM,
        ),
    });
}

function rawDigest(value) {
    return typeof value === "string" ? value.split(":").at(-1) : null;
}

function assertExpectedFileHash(actual, expected, field) {
    if (expected === undefined || expected === null) return;
    if (!/^[a-f0-9]{64}$/u.test(rawDigest(expected) ?? "")
        || rawDigest(actual) !== rawDigest(expected)) {
        throw new RuntimeIntegrityError(
            `${field} does not match the admitted sandbox identity`,
            { expected, actual },
        );
    }
}

function buildSandboxIdentity(value, context) {
    if (value === undefined || value === null || value.required === false) {
        const core = { kind: "sandbox", required: false };
        return Object.freeze({
            ...core,
            identity: hashCanonical(
                core,
                RUNTIME_IDENTITY_SANDBOX_IDENTITY_ALGORITHM,
            ),
        });
    }
    requirePlainObject(value, "runtime identity sandbox");
    if (value.required !== true) {
        throw new RuntimeConfigError(
            "runtime identity sandbox.required must be boolean",
        );
    }
    const core = {
        kind: "sandbox",
        required: true,
        helperSource: buildFileIdentity(
            value.helperSourcePath,
            "runtime identity sandbox helper source",
            context,
        ),
        helperBinary: buildFileIdentity(
            value.helperBinaryPath,
            "runtime identity sandbox helper binary",
            context,
        ),
        launcher: buildFileIdentity(
            value.launcherPath,
            "runtime identity sandbox launcher",
            context,
        ),
        launcherScriptHash:
            typeof value.launcherScriptHash === "string"
                ? value.launcherScriptHash
                : (() => {
                    throw new RuntimeConfigError(
                        "runtime identity sandbox launcherScriptHash is required",
                    );
                })(),
    };
    assertExpectedFileHash(
        core.helperSource.contentHash,
        value.expectedHelperSourceHash,
        "sandbox helper source",
    );
    assertExpectedFileHash(
        core.helperBinary.contentHash,
        value.expectedHelperBinaryHash,
        "sandbox helper binary",
    );
    assertExpectedFileHash(
        core.launcher.contentHash,
        value.expectedLauncherBinaryHash,
        "sandbox launcher",
    );
    if (value.expectedLauncherScriptHash !== undefined
        && value.expectedLauncherScriptHash !== null
        && core.launcherScriptHash !== value.expectedLauncherScriptHash) {
        throw new RuntimeIntegrityError(
            "sandbox launcher command template hash changed",
            {
                expected: value.expectedLauncherScriptHash,
                actual: core.launcherScriptHash,
            },
        );
    }
    return Object.freeze({
        ...core,
        identity: hashCanonical(
            core,
            RUNTIME_IDENTITY_SANDBOX_IDENTITY_ALGORITHM,
        ),
    });
}

function buildCommandTemplates(value, policy) {
    requirePlainObject(value, "runtime identity commandTemplates");
    const bytes = Buffer.byteLength(canonicalJson(value), "utf8");
    if (bytes > policy.limits.maxTemplateBytes) {
        throw new RuntimeIntegrityError(
            "Runtime identity command templates exceed their byte cap",
            { bytes, maximum: policy.limits.maxTemplateBytes },
        );
    }
    const core = {
        kind: "command_templates",
        templates: immutableCanonical(value),
    };
    return Object.freeze({
        ...core,
        identity: hashCanonical(
            core,
            RUNTIME_IDENTITY_COMMANDS_IDENTITY_ALGORITHM,
        ),
    });
}

function environmentValue(env, name) {
    if (Object.hasOwn(env, name) && typeof env[name] === "string") {
        return env[name];
    }
    if (process.platform !== "win32") return null;
    const actual = Object.keys(env).find((key) =>
        key.toLowerCase() === name.toLowerCase()
        && typeof env[key] === "string");
    return actual === undefined ? null : env[actual];
}

function buildEnvironmentIdentity(env, policy) {
    const variables = policy.environmentKeys.map((name) => {
        const value = environmentValue(env, name);
        return value === null
            ? { name, present: false, valueHash: null }
            : {
                name,
                present: true,
                valueHash: hashCanonical(
                    { name, value },
                    ENVIRONMENT_VALUE_HASH_ALGORITHM,
                ),
            };
    });
    const core = { kind: "environment", variables };
    return Object.freeze({
        ...core,
        identity: hashCanonical(
            core,
            RUNTIME_IDENTITY_ENVIRONMENT_IDENTITY_ALGORITHM,
        ),
    });
}

export function collectRuntimeAssumptions() {
    const cpuModels = os.cpus()
        .map((cpu) => cpu.model)
        .sort((left, right) => left.localeCompare(right));
    return immutableCanonical({
        os: {
            platform: os.platform(),
            type: os.type(),
            release: os.release(),
            version: typeof os.version === "function" ? os.version() : null,
            architecture: os.arch(),
            endianness: os.endianness(),
        },
        hardware: {
            logicalCpuCount: cpuModels.length,
            cpuModels,
            totalMemoryBytes: os.totalmem(),
        },
    });
}

function buildCliIdentity(launcher, packageTree) {
    const core = {
        kind: "cli",
        launcher,
        package: packageTree,
    };
    return Object.freeze({
        ...core,
        identity: hashCanonical(
            core,
            RUNTIME_IDENTITY_CLI_IDENTITY_ALGORITHM,
        ),
    });
}

export function buildRuntimeIdentity(input, options = {}) {
    requirePlainObject(input, "runtime identity input");
    const policy = normalizeRuntimeIdentityPolicy(
        input.policy ?? DEFAULT_RUNTIME_IDENTITY_POLICY,
    );
    const context = {
        env: input.env ?? process.env,
        policy,
        budget: { files: 0, bytes: 0 },
        cache: options.cache ?? input.cache ?? null,
        trustVerifiedCache:
            options.trustVerifiedCache === true
            || input.trustVerifiedCache === true,
        readDirectory:
            options.readDirectory
            ?? input.readDirectory
            ?? ((directory) => fs.readdirSync(directory, { withFileTypes: true })),
    };
    if (context.cache !== null && !(context.cache instanceof Map)) {
        throw new RuntimeConfigError("runtime identity cache must be a Map");
    }
    if (typeof context.readDirectory !== "function") {
        throw new RuntimeConfigError("runtime identity readDirectory must be a function");
    }
    const crucibleSource = buildTreeIdentity(
        input.crucibleSourceRoot,
        "crucibleSource",
        "Crucible source/build closure",
        context,
    );
    const nodeExecutable = buildFileIdentity(
        input.nodeExecutablePath,
        "Node executable",
        context,
    );
    const cliLauncher = buildFileIdentity(
        input.copilotCliLauncherPath,
        "Copilot CLI launcher",
        context,
    );
    const cliPackage = buildTreeIdentity(
        input.copilotCliPackageRoot,
        "copilotCliPackage",
        "Copilot CLI package",
        context,
    );
    const copilotSdk = buildTreeIdentity(
        input.copilotSdkPackageRoot,
        "copilotSdkPackage",
        "Copilot SDK package",
        context,
    );
    const sandbox = buildSandboxIdentity(input.sandbox, context);
    const commandTemplates = buildCommandTemplates(
        input.commandTemplates,
        policy,
    );
    const environment = buildEnvironmentIdentity(context.env, policy);
    const assumptions = immutableCanonical(
        input.assumptions ?? collectRuntimeAssumptions(),
    );
    const components = {
        crucibleSource,
        nodeExecutable,
        copilotCli: buildCliIdentity(cliLauncher, cliPackage),
        copilotSdk,
        sandbox,
        commandTemplates,
        environment,
    };
    const core = {
        version: RUNTIME_IDENTITY_VERSION,
        kind: RUNTIME_IDENTITY_KIND,
        policy,
        policyIdentity: runtimeIdentityPolicyIdentity(policy),
        components,
    };
    return normalizeRuntimeIdentity({
        ...core,
        assumptions,
        assumptionsHash: hashCanonical(
            assumptions,
            RUNTIME_IDENTITY_ASSUMPTIONS_HASH_ALGORITHM,
        ),
        root: runtimeIdentityRoot(core),
    });
}

function changedComponents(expected, actual) {
    return Object.keys(expected.components)
        .filter((name) =>
            expected.components[name].identity
            !== actual.components[name].identity)
        .sort();
}

export function verifyRuntimeIdentity(expectedValue, currentInput, options = {}) {
    let expected;
    try {
        expected = normalizeRuntimeIdentity(expectedValue);
    } catch (error) {
        return Object.freeze({
            ok: false,
            code: RUNTIME_IDENTITY_RESULT_CODES.RUNTIME_DRIFT,
            reason: "expected_identity_invalid",
            expectedRoot: expectedValue?.root ?? null,
            actualRoot: null,
            changedComponents: [],
            assumptionsChanged: false,
            cause: error?.code ?? "INVALID_RUNTIME_IDENTITY",
            message: error?.message ?? String(error),
            requiredAction: "start_new_or_forked_investigation",
            inPlaceRepinAllowed: false,
        });
    }
    try {
        const actual = buildRuntimeIdentity(currentInput, {
            ...options,
            trustVerifiedCache: false,
        });
        const assumptionsChanged =
            expected.assumptionsHash !== actual.assumptionsHash;
        if (actual.root === expected.root) {
            return Object.freeze({
                ok: true,
                code: null,
                identity: actual,
                expectedRoot: expected.root,
                actualRoot: actual.root,
                changedComponents: Object.freeze([]),
                assumptionsChanged,
            });
        }
        return Object.freeze({
            ok: false,
            code: RUNTIME_IDENTITY_RESULT_CODES.RUNTIME_DRIFT,
            reason: "runtime_identity_mismatch",
            identity: actual,
            expectedRoot: expected.root,
            actualRoot: actual.root,
            changedComponents: Object.freeze(
                changedComponents(expected, actual),
            ),
            assumptionsChanged,
            requiredAction: "start_new_or_forked_investigation",
            inPlaceRepinAllowed: false,
        });
    } catch (error) {
        return Object.freeze({
            ok: false,
            code: RUNTIME_IDENTITY_RESULT_CODES.RUNTIME_DRIFT,
            reason: "runtime_identity_verification_failed",
            expectedRoot: expected.root,
            actualRoot: null,
            changedComponents: Object.freeze([]),
            assumptionsChanged: false,
            cause: error?.code ?? "RUNTIME_IDENTITY_VERIFICATION_FAILED",
            message: error?.message ?? String(error),
            requiredAction: "start_new_or_forked_investigation",
            inPlaceRepinAllowed: false,
        });
    }
}

export function runtimeIdentityBuildInputFromIdentity(
    expectedValue,
    {
        env = process.env,
        sandboxExpectedHashes = null,
        commandTemplates = null,
        assumptions = null,
    } = {},
) {
    const expected = normalizeRuntimeIdentity(expectedValue);
    const sandbox = expected.components.sandbox.required
        ? {
            required: true,
            helperSourcePath:
                expected.components.sandbox.helperSource.path,
            helperBinaryPath:
                expected.components.sandbox.helperBinary.path,
            launcherPath: expected.components.sandbox.launcher.path,
            launcherScriptHash:
                expected.components.sandbox.launcherScriptHash,
            ...(sandboxExpectedHashes ?? {}),
        }
        : { required: false };
    return Object.freeze({
        policy: expected.policy,
        crucibleSourceRoot: expected.components.crucibleSource.rootPath,
        nodeExecutablePath: expected.components.nodeExecutable.path,
        copilotCliLauncherPath:
            expected.components.copilotCli.launcher.path,
        copilotCliPackageRoot:
            expected.components.copilotCli.package.rootPath,
        copilotSdkPackageRoot: expected.components.copilotSdk.rootPath,
        sandbox,
        commandTemplates:
            commandTemplates
            ?? expected.components.commandTemplates.templates,
        env,
        ...(assumptions === null ? {} : { assumptions }),
    });
}

export function reverifyRuntimeIdentity(expectedValue, options = {}) {
    try {
        return verifyRuntimeIdentity(
            expectedValue,
            runtimeIdentityBuildInputFromIdentity(expectedValue, options),
            options,
        );
    } catch (error) {
        return Object.freeze({
            ok: false,
            code: RUNTIME_IDENTITY_RESULT_CODES.RUNTIME_DRIFT,
            reason: "runtime_identity_verification_failed",
            expectedRoot: expectedValue?.root ?? null,
            actualRoot: null,
            changedComponents: Object.freeze([]),
            assumptionsChanged: false,
            cause: error?.code ?? "RUNTIME_IDENTITY_VERIFICATION_FAILED",
            message: error?.message ?? String(error),
            requiredAction: "start_new_or_forked_investigation",
            inPlaceRepinAllowed: false,
        });
    }
}

export function assertRuntimeIdentityVerified(result, message = null) {
    if (result?.ok === true) return result.identity;
    throw new RuntimeDriftError(
        message ?? "Current runtime identity differs from the frozen initial root",
        {
            expectedRoot: result?.expectedRoot ?? null,
            actualRoot: result?.actualRoot ?? null,
            changedComponents: result?.changedComponents ?? [],
            reason: result?.reason ?? null,
            cause: result?.cause ?? null,
        },
    );
}

export {
    runtimeIdentityPolicyIdentity,
    runtimeIdentityRoot,
    RUNTIME_IDENTITY_POLICY_HASH_ALGORITHM,
    RUNTIME_IDENTITY_ROOT_ALGORITHM,
};
