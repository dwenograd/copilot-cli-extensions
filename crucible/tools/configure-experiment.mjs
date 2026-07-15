import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

import {
    EXPERIMENT_REGISTRY_ERROR_CODES,
    ExperimentRegistryError,
    createExperimentEntry,
    createExperimentRegistryDocument,
    loadExperimentConfig,
    loadExperimentRegistry,
    prepareExperimentManifest,
    resolveExperimentRegistryPath,
    serializeExperimentRegistryDocument,
} from "../api/experiment-registry.mjs";

function fail(code, message, details = null, options = {}) {
    throw new ExperimentRegistryError(code, message, details, options);
}

function fsyncDirectoryBestEffort(directory) {
    let fd;
    try {
        fd = fs.openSync(directory, "r");
        fs.fsyncSync(fd);
    } catch {
        // Windows may not permit directory fsync; the same-directory rename is
        // still the atomic publication boundary.
    } finally {
        if (fd !== undefined) {
            try { fs.closeSync(fd); } catch { /* ignore */ }
        }
    }
}

function writeAllAndSync(filePath, bytes, flag) {
    const fd = fs.openSync(filePath, flag);
    try {
        let offset = 0;
        while (offset < bytes.length) {
            offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
        }
        fs.fsyncSync(fd);
    } finally {
        fs.closeSync(fd);
    }
}

function atomicWriteRegistry(targetPath, content) {
    const directory = path.dirname(targetPath);
    fs.mkdirSync(directory, { recursive: true });
    const temporaryPath = path.join(
        directory,
        `.${path.basename(targetPath)}.${randomBytes(8).toString("hex")}.tmp`,
    );
    const bytes = Buffer.from(content, "utf8");
    let backupPath = null;
    try {
        writeAllAndSync(temporaryPath, bytes, "wx");
        if (fs.existsSync(targetPath)) {
            backupPath = `${targetPath}.bak`;
            writeAllAndSync(backupPath, fs.readFileSync(targetPath), "w");
        }
        fs.renameSync(temporaryPath, targetPath);
        fsyncDirectoryBestEffort(directory);
        return { backupPath };
    } catch (error) {
        try { fs.rmSync(temporaryPath, { force: true }); } catch { /* ignore */ }
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.WRITE_FAILED,
            `failed to install experiment registry: ${error?.message ?? String(error)}`,
            {
                path: targetPath,
                backupPath,
                cause: error?.code ?? null,
            },
            { cause: error },
        );
    }
}

function existingExperiments(registryPath, env) {
    if (!fs.existsSync(registryPath)) {
        return {
            experiments: {},
        };
    }
    const registry = loadExperimentRegistry(registryPath, { env });
    return {
        experiments: Object.fromEntries(
            registry.listExperimentIds().map((id) => [
                id,
                registry.getExperiment(id),
            ]),
        ),
    };
}

export function configureExperiment(options = {}) {
    if (options.config !== undefined && options.configPath !== undefined) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
            "pass either config or configPath, not both",
        );
    }
    const env = options.env ?? process.env;
    const rawConfig = options.config !== undefined
        ? options.config
        : loadExperimentConfig(options.configPath);
    const registryPath = resolveExperimentRegistryPath(options.registryPath, env);
    const entry = createExperimentEntry(rawConfig, {
        allowlistPath: options.allowlistPath,
        signature: options.signature,
        signaturePath: options.signaturePath,
        env,
    });
    const existing = existingExperiments(registryPath, env);
    const prior = existing.experiments[entry.experimentId] ?? null;
    const changed = prior !== null
        && prior.experimentIdentity !== entry.experimentIdentity;
    if (changed && options.replace !== true) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.EXPERIMENT_CONFLICT,
            `experiment '${entry.experimentId}' has a different authoritative identity; pass --replace to overwrite`,
            {
                experimentId: entry.experimentId,
                existingIdentity: prior.experimentIdentity,
                newIdentity: entry.experimentIdentity,
            },
        );
    }
    const experiments = {
        ...existing.experiments,
        [entry.experimentId]: entry,
    };
    const document = createExperimentRegistryDocument(experiments, { env });
    const content = serializeExperimentRegistryDocument(document, { env });
    const validationPath = path.join(
        path.dirname(registryPath),
        `.experiments-validate-${randomBytes(8).toString("hex")}.json`,
    );
    fs.mkdirSync(path.dirname(registryPath), { recursive: true });
    try {
        writeAllAndSync(validationPath, Buffer.from(content, "utf8"), "wx");
        const validated = loadExperimentRegistry(validationPath, {
            experimentId: entry.experimentId,
            env,
        });
        const validatedEntry = validated.getExperiment(entry.experimentId);
        if (validated.registryIdentity !== document.identity
            || validatedEntry.experimentIdentity !== entry.experimentIdentity
            || validatedEntry.contractHash !== entry.contractHash) {
            fail(
                EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_INVALID,
                "serialized experiment registry changed identity during strict validation",
            );
        }
    } finally {
        try { fs.rmSync(validationPath, { force: true }); } catch { /* ignore */ }
    }
    const install = atomicWriteRegistry(registryPath, content);
    const installed = loadExperimentRegistry(registryPath, {
        experimentId: entry.experimentId,
        env,
    });
    return Object.freeze({
        registryPath,
        registryIdentity: installed.registryIdentity,
        registryFileHash: installed.registryFileHash,
        experimentId: entry.experimentId,
        experimentIdentity: entry.experimentIdentity,
        contractHash: entry.contractHash,
        runtimeIdentityPolicyIdentity:
            entry.contract.runtimeIdentityPolicyIdentity,
        runtimeIdentityRoot: entry.contract.runtimeIdentityRoot,
        investigationId: entry.investigationId,
        harnessSuiteId: entry.harnessSuiteId,
        harnessSuiteIdentity: entry.harnessSuiteIdentity,
        authorityIdentity: entry.authority.identity,
        manifestIdentity: entry.authority.manifestIdentity,
        trustFingerprint: entry.authority.trustFingerprint,
        created: prior === null,
        replaced: changed,
        idempotent: prior !== null && !changed,
        replacedByOverride: changed && options.replace === true,
        backupPath: install.backupPath,
        preservedExperimentIds: Object.keys(existing.experiments)
            .filter((id) => id !== entry.experimentId)
            .sort(),
    });
}

export function prepareUnsignedExperimentManifest(options = {}) {
    if (options.config !== undefined && options.configPath !== undefined) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
            "pass either config or configPath, not both",
        );
    }
    if (typeof options.outputPath !== "string"
        || options.outputPath.trim().length === 0
        || !path.isAbsolute(options.outputPath)) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
            "--prepare-manifest <path> must be an absolute output path",
        );
    }
    const env = options.env ?? process.env;
    const rawConfig = options.config !== undefined
        ? options.config
        : loadExperimentConfig(options.configPath);
    const prepared = prepareExperimentManifest(rawConfig, {
        allowlistPath: options.allowlistPath,
        env,
    });
    fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
    try {
        writeAllAndSync(
            options.outputPath,
            Buffer.from(prepared.canonicalManifest, "utf8"),
            "wx",
        );
    } catch (error) {
        fail(
            EXPERIMENT_REGISTRY_ERROR_CODES.WRITE_FAILED,
            `failed to write unsigned experiment manifest: ${
                error?.message ?? String(error)
            }`,
            { path: options.outputPath, cause: error?.code ?? null },
            { cause: error },
        );
    }
    return Object.freeze({
        manifestPath: options.outputPath,
        manifestIdentity: prepared.manifestIdentity,
        experimentId: prepared.experimentId,
        investigationId: prepared.investigationId,
        contractHash: prepared.contractHash,
        harnessSuiteIdentity: prepared.harnessSuiteIdentity,
        trustFingerprint: prepared.trustFingerprint,
        enumerandRoot: prepared.enumerandRoot,
        statisticalPolicyIdentity: prepared.statisticalPolicyIdentity,
        hypothesisPolicyIdentity: prepared.hypothesisPolicyIdentity,
        runtimeIdentityPolicyIdentity:
            prepared.runtimeIdentityPolicyIdentity,
        runtimeIdentityRoot: prepared.runtimeIdentityRoot,
        bytes: Buffer.byteLength(prepared.canonicalManifest, "utf8"),
    });
}

function parseArgs(argv) {
    const out = {
        config: undefined,
        registry: undefined,
        allowlist: undefined,
        signatureFile: undefined,
        prepareManifest: undefined,
        replace: false,
        help: false,
    };
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === "--help" || argument === "-h") {
            out.help = true;
        } else if (argument === "--replace") {
            out.replace = true;
        } else if (argument === "--config") {
            out.config = argv[index + 1];
            index += 1;
        } else if (argument.startsWith("--config=")) {
            out.config = argument.slice("--config=".length);
        } else if (argument === "--registry") {
            out.registry = argv[index + 1];
            index += 1;
        } else if (argument.startsWith("--registry=")) {
            out.registry = argument.slice("--registry=".length);
        } else if (argument === "--allowlist") {
            out.allowlist = argv[index + 1];
            index += 1;
        } else if (argument.startsWith("--allowlist=")) {
            out.allowlist = argument.slice("--allowlist=".length);
        } else if (argument === "--signature-file") {
            out.signatureFile = argv[index + 1];
            index += 1;
        } else if (argument.startsWith("--signature-file=")) {
            out.signatureFile = argument.slice("--signature-file=".length);
        } else if (argument === "--prepare-manifest") {
            out.prepareManifest = argv[index + 1];
            index += 1;
        } else if (argument.startsWith("--prepare-manifest=")) {
            out.prepareManifest = argument.slice("--prepare-manifest=".length);
        } else {
            fail(
                EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
                `unknown argument ${JSON.stringify(argument)}`,
            );
        }
    }
    return out;
}

const USAGE = `Usage:
  node tools/configure-experiment.mjs --config <path> --prepare-manifest <path> [--allowlist <path>]
  node tools/configure-experiment.mjs --config <path> --signature-file <path> [--registry <path>] [--allowlist <path>] [--replace]

Preparation writes the exact canonical unsigned authority manifest for external
Ed25519 signing. Installation imports and verifies the detached signature under
the configured trusted public key before any registry write. This CLI never
reads or creates a private key.

Options:
  --config <path>     Strict JSON experiment config (required).
  --registry <path>   Output registry (default %LOCALAPPDATA%\\Crucible\\experiments.json,
                      override with CRUCIBLE_EXPERIMENT_REGISTRY_PATH).
  --allowlist <path>  Harness allowlist (default CRUCIBLE_ALLOWLIST_PATH or
                      %LOCALAPPDATA%\\Crucible\\harnesses.json).
  --prepare-manifest <path>
                      Write exact canonical bytes to sign; do not install.
  --signature-file <path>
                      Detached raw/base64 Ed25519 signature to verify and import.
  --replace           Replace an existing changed experiment identity.
  -h, --help          Show this help.`;

function errorPayload(error) {
    return {
        ok: false,
        error: {
            code: error?.code ?? "CRUCIBLE_EXPERIMENT_UNKNOWN",
            message: error?.message ?? String(error),
            ...(error?.details ? { details: error.details } : {}),
        },
    };
}

function main(
    argv = process.argv.slice(2),
    {
        env = process.env,
        stdout = process.stdout,
        stderr = process.stderr,
    } = {},
) {
    let args;
    try {
        args = parseArgs(argv);
    } catch (error) {
        stderr.write(`${JSON.stringify(errorPayload(error))}\n`);
        return 2;
    }
    if (args.help) {
        stdout.write(`${USAGE}\n`);
        return 0;
    }
    if (typeof args.config !== "string" || args.config.trim().length === 0) {
        stderr.write(`${JSON.stringify(errorPayload(new ExperimentRegistryError(
            EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
            "--config <path> is required",
        )))}\n`);
        return 2;
    }
    try {
        if (args.prepareManifest !== undefined
            && args.signatureFile !== undefined) {
            throw new ExperimentRegistryError(
                EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
                "--prepare-manifest and --signature-file are mutually exclusive",
            );
        }
        if (args.prepareManifest !== undefined
            && (args.replace || args.registry !== undefined)) {
            throw new ExperimentRegistryError(
                EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
                "--prepare-manifest cannot be combined with --replace or --registry",
            );
        }
        const result = args.prepareManifest !== undefined
            ? prepareUnsignedExperimentManifest({
                configPath: args.config,
                outputPath: args.prepareManifest,
                allowlistPath: args.allowlist,
                env,
            })
            : configureExperiment({
                configPath: args.config,
                registryPath: args.registry,
                allowlistPath: args.allowlist,
                signaturePath: args.signatureFile,
                replace: args.replace,
                env,
            });
        stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
        return 0;
    } catch (error) {
        stderr.write(`${JSON.stringify(errorPayload(error))}\n`);
        return 1;
    }
}

const invokedDirectly = (() => {
    if (!process.argv[1]) return false;
    try {
        return import.meta.url === pathToFileURL(process.argv[1]).href;
    } catch {
        return false;
    }
})();

if (invokedDirectly) {
    process.exit(main());
}
