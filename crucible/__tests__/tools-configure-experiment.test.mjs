import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    EXPERIMENT_REGISTRY_ERROR_CODES,
    loadExperimentRegistry,
    resolveExperimentRegistryPath,
} from "../api/experiment-registry.mjs";
import {
    configureExperiment,
    main,
    parseArgs,
    prepareUnsignedExperimentManifest,
} from "../tools/configure-experiment.mjs";
import {
    loadHarnessAllowlist,
} from "../measurement/index.mjs";
import { openArtifactStore } from "../persistence/index.mjs";
import {
    buildHarnessSuiteForAllowlist,
    fakeHypothesisPolicy,
    fakeObservableRegistry,
    fakeStatisticalPolicy,
} from "./v4-contract-fixture.mjs";
import {
    createExperimentAuthorityFixture,
    prepareAndSignExperiment,
} from "./experiment-authority-fixture.mjs";
import {
    EXPERIMENT_PUBLIC_KEY_ENV,
    EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV,
    EXPERIMENT_PUBLIC_KEY_PATH_ENV,
} from "../api/experiment-authority.mjs";
import { removeTrackedRoots } from "./test-cleanup.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const roots = [];

afterEach(async () => {
    await removeTrackedRoots(roots, {
        label: "configure-experiment test root",
    });
});

function sha256File(file) {
    return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function workspace(label) {
    const root = fs.mkdtempSync(path.join(HERE, `.configure-experiment-${label}-`));
    roots.push(root);
    const authority = createExperimentAuthorityFixture();
    const projectDir = path.join(root, "project");
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(path.join(projectDir, "README.txt"), "project");

    const storeRoot = path.join(root, "operator-corpus");
    const store = openArtifactStore({ root: storeRoot });
    const cases = {};
    for (const [id, expectation] of [
        ["cal-good", "accept"],
        ["cal-bad", "reject"],
        ["search", "accept"],
        ["confirmation", "accept"],
        ["challenge", "reject"],
        ["novelty", "accept"],
    ]) {
        const source = path.join(root, `case-${id}`);
        fs.mkdirSync(source, { recursive: true });
        fs.writeFileSync(path.join(source, "input.txt"), id);
        cases[id] = {
            snapshotHash: store.ingestDirectory({ sourceDir: source }).snapshot,
            expectation,
        };
    }

    const executable = path.join(root, "harness.exe");
    const script = path.join(root, "harness.mjs");
    fs.writeFileSync(executable, "fixture executable");
    fs.writeFileSync(script, "process.stdout.write('{}');\n");
    const allowlistPath = path.join(root, "harnesses.json");
    const allowlistDocument = {
        version: 1,
        entries: {
            "primary-harness": {
                executable,
                executableSha256: sha256File(executable),
                argvTemplate: [script],
                dependencies: [{
                    path: script,
                    sha256: sha256File(script),
                    role: "script",
                }],
                allowedEnv: {},
                timeoutMs: 1000,
                maxStdoutBytes: 4096,
                maxStderrBytes: 4096,
                executesCandidateCode: false,
                validationCases: cases,
            },
        },
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(allowlistDocument));
    const loaded = loadHarnessAllowlist(allowlistPath);
    allowlistDocument.suites = {
        "primary-suite": buildHarnessSuiteForAllowlist(loaded, {
            roleCaseIds: {
                calibration: ["cal-good", "cal-bad"],
                search: ["search"],
                confirmation: ["confirmation"],
                challenge: ["challenge"],
                novelty: ["novelty"],
            },
        }),
    };
    fs.writeFileSync(allowlistPath, JSON.stringify(allowlistDocument));

    return {
        root,
        projectDir,
        storeRoot,
        allowlistPath,
        registryPath: path.join(root, "experiments.json"),
        controlSnapshot: cases["cal-good"].snapshotHash,
        authority,
        env: {
            LOCALAPPDATA: root,
            CRUCIBLE_ALLOWLIST_PATH: allowlistPath,
            ...authority.env,
        },
    };
}

function experimentConfig(ws, experimentId, overrides = {}) {
    const observableRegistry = fakeObservableRegistry();
    const statisticalPolicy = fakeStatisticalPolicy({
        topology: "open_generative",
        searchSlots: 1,
        control: {
            kind: "snapshot",
            identity: ws.controlSnapshot,
        },
    });
    return {
        experiment_id: experimentId,
        objective: `evaluate ${experimentId}`,
        project_dir: ws.projectDir,
        harness_suite_id: "primary-suite",
        acceptance_predicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: 0.8,
        },
        hypothesis_topology: "open_generative",
        observable_registry: observableRegistry,
        hypothesis_policy: fakeHypothesisPolicy(),
        statistical_policy: statisticalPolicy,
        worker_models: ["worker-a"],
        candidates_per_round: 1,
        max_rounds: 1,
        ...overrides,
    };
}

function configure(ws, config, replace = false) {
    const { signature } = prepareAndSignExperiment({
        config,
        allowlistPath: ws.allowlistPath,
        env: ws.env,
        privateKey: ws.authority.privateKey,
    });
    return configureExperiment({
        config,
        registryPath: ws.registryPath,
        allowlistPath: ws.allowlistPath,
        signature,
        replace,
        env: ws.env,
    });
}

describe("configure-experiment operator CLI", () => {
    it("creates a canonical registry and preserves unrelated experiments", () => {
        const ws = workspace("create-preserve");
        const first = configure(ws, experimentConfig(ws, "experiment-a"));
        expect(first.created).toBe(true);
        expect(first.contractHash).toMatch(
            /^sha256:crucible-contract-v4:[a-f0-9]{64}$/u,
        );
        expect(first.experimentIdentity).toMatch(
            /^sha256:crucible-operator-experiment-v5:[a-f0-9]{64}$/u,
        );

        const second = configure(ws, experimentConfig(ws, "experiment-b"));
        expect(second.preservedExperimentIds).toEqual(["experiment-a"]);
        const registry = loadExperimentRegistry(ws.registryPath, {
            env: ws.env,
        });
        expect(registry.listExperimentIds()).toEqual([
            "experiment-a",
            "experiment-b",
        ]);
        expect(registry.getExperiment("experiment-a").contractHash)
            .toBe(first.contractHash);
        expect(registry.getExperiment("experiment-b").contractHash)
            .toBe(second.contractHash);
    });

    it("requires --replace for a changed authoritative identity", () => {
        const ws = workspace("replace");
        const original = configure(ws, experimentConfig(ws, "experiment-a"));
        const changed = experimentConfig(ws, "experiment-a", {
            objective: "changed operator objective",
        });
        expect(() => configure(ws, changed)).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.EXPERIMENT_CONFLICT,
        }));
        expect(loadExperimentRegistry(ws.registryPath, { env: ws.env })
            .getExperiment("experiment-a").experimentIdentity)
            .toBe(original.experimentIdentity);

        const replacement = configure(ws, changed, true);
        expect(replacement.replaced).toBe(true);
        expect(replacement.replacedByOverride).toBe(true);
        expect(replacement.experimentIdentity).not.toBe(original.experimentIdentity);
        expect(fs.existsSync(`${ws.registryPath}.bak`)).toBe(true);
    });

    it("rejects self-hashes, wrong keys, and signatures over modified payloads", () => {
        const ws = workspace("signature-failures");
        const config = experimentConfig(ws, "experiment-a");
        const prepared = prepareAndSignExperiment({
            config,
            allowlistPath: ws.allowlistPath,
            env: ws.env,
            privateKey: ws.authority.privateKey,
        }).prepared;
        const digest = createHash("sha256")
            .update(prepared.canonicalManifest, "utf8")
            .digest();
        expect(() => configureExperiment({
            config,
            registryPath: ws.registryPath,
            allowlistPath: ws.allowlistPath,
            signature: Buffer.concat([digest, digest]),
            env: ws.env,
        })).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.SIGNATURE_INVALID,
        }));

        const wrong = createExperimentAuthorityFixture();
        const wrongSignature = prepareAndSignExperiment({
            config,
            allowlistPath: ws.allowlistPath,
            env: ws.env,
            privateKey: wrong.privateKey,
        }).signature;
        expect(() => configureExperiment({
            config,
            registryPath: ws.registryPath,
            allowlistPath: ws.allowlistPath,
            signature: wrongSignature,
            env: ws.env,
        })).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.SIGNATURE_INVALID,
        }));

        const validSignature = prepareAndSignExperiment({
            config,
            allowlistPath: ws.allowlistPath,
            env: ws.env,
            privateKey: ws.authority.privateKey,
        }).signature;
        expect(() => configureExperiment({
            config: {
                ...config,
                objective: "modified after external signing",
            },
            registryPath: ws.registryPath,
            allowlistPath: ws.allowlistPath,
            signature: validSignature,
            env: ws.env,
        })).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.SIGNATURE_INVALID,
        }));
        expect(fs.existsSync(ws.registryPath)).toBe(false);
    });

    it("rejects a changed trust key and replacement without a fresh signature", () => {
        const ws = workspace("trust-change");
        const original = experimentConfig(ws, "experiment-a");
        configure(ws, original);
        const changedTrust = createExperimentAuthorityFixture();
        expect(() => loadExperimentRegistry(ws.registryPath, {
            env: {
                ...ws.env,
                ...changedTrust.env,
            },
        })).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.TRUST_FINGERPRINT_MISMATCH,
        }));

        expect(() => configureExperiment({
            config: {
                ...original,
                objective: "replacement without detached signature",
            },
            registryPath: ws.registryPath,
            allowlistPath: ws.allowlistPath,
            replace: true,
            env: ws.env,
        })).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.AUTHORITY_REQUIRED,
        }));
    });

    it("requires an expected fingerprint for a mutable public-key path", () => {
        const ws = workspace("pinned-key-path");
        const config = experimentConfig(ws, "experiment-a");
        const { signature } = prepareAndSignExperiment({
            config,
            allowlistPath: ws.allowlistPath,
            env: ws.env,
            privateKey: ws.authority.privateKey,
        });
        const publicKeyPath = path.join(ws.root, "operator-public-key.der");
        fs.writeFileSync(publicKeyPath, ws.authority.publicKeyDer);
        const pathEnv = {
            ...ws.env,
            [EXPERIMENT_PUBLIC_KEY_ENV]: undefined,
            [EXPERIMENT_PUBLIC_KEY_PATH_ENV]: publicKeyPath,
        };
        expect(() => configureExperiment({
            config,
            registryPath: ws.registryPath,
            allowlistPath: ws.allowlistPath,
            signature,
            env: pathEnv,
        })).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.TRUST_CONFIGURATION_INVALID,
        }));

        const installed = configureExperiment({
            config,
            registryPath: ws.registryPath,
            allowlistPath: ws.allowlistPath,
            signature,
            env: {
                ...pathEnv,
                [EXPERIMENT_PUBLIC_KEY_FINGERPRINT_ENV]:
                    ws.authority.fingerprint,
            },
        });
        expect(installed.trustFingerprint).toBe(ws.authority.fingerprint);
    });

    it("does not mutate the registry for an invalid experiment", () => {
        const ws = workspace("invalid-no-side-effects");
        configure(ws, experimentConfig(ws, "experiment-a"));
        const before = fs.readFileSync(ws.registryPath);
        const invalid = {
            ...experimentConfig(ws, "experiment-b"),
            raw_authority_injection: true,
        };

        expect(() => configure(ws, invalid)).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.CONFIG_INVALID,
        }));
        expect(fs.readFileSync(ws.registryPath)).toEqual(before);
        expect(fs.existsSync(`${ws.registryPath}.bak`)).toBe(false);
        expect(
            fs.readdirSync(ws.root)
                .filter((name) => name.startsWith(".experiments-validate-")),
        ).toEqual([]);
    });

    it("detects registry and entry tampering", () => {
        const ws = workspace("tamper");
        configure(ws, experimentConfig(ws, "experiment-a"));
        const tampered = JSON.parse(fs.readFileSync(ws.registryPath, "utf8"));
        tampered.experiments["experiment-a"].contract.objective =
            "prompt-injected replacement";
        fs.writeFileSync(ws.registryPath, JSON.stringify(tampered));
        expect(() => loadExperimentRegistry(ws.registryPath, {
            env: ws.env,
        })).toThrow(
            expect.objectContaining({
                code: EXPERIMENT_REGISTRY_ERROR_CODES.REGISTRY_TAMPERED,
            }),
        );
    });

    it("honors the environment registry override and parses CLI arguments strictly", () => {
        const ws = workspace("env");
        const override = path.join(ws.root, "operator", "approved.json");
        expect(resolveExperimentRegistryPath(undefined, {
            ...ws.env,
            CRUCIBLE_EXPERIMENT_REGISTRY_PATH: override,
        })).toBe(override);
        expect(parseArgs([
            "--config=config.json",
            `--registry=${override}`,
            `--allowlist=${ws.allowlistPath}`,
            "--replace",
        ])).toEqual({
            config: "config.json",
            registry: override,
            allowlist: ws.allowlistPath,
            signatureFile: undefined,
            prepareManifest: undefined,
            replace: true,
            help: false,
        });
        expect(() => parseArgs(["--unknown"])).toThrow(
            expect.objectContaining({
                code: EXPERIMENT_REGISTRY_ERROR_CODES.USAGE,
            }),
        );
    });

    it("prints one JSON result through the CLI entry point", () => {
        const ws = workspace("main");
        const configPath = path.join(ws.root, "experiment.json");
        fs.writeFileSync(
            configPath,
            JSON.stringify(experimentConfig(ws, "experiment-a")),
        );
        const { signature } = prepareAndSignExperiment({
            config: experimentConfig(ws, "experiment-a"),
            allowlistPath: ws.allowlistPath,
            env: ws.env,
            privateKey: ws.authority.privateKey,
        });
        const signaturePath = path.join(ws.root, "experiment.sig");
        fs.writeFileSync(signaturePath, signature);
        let stdout = "";
        let stderr = "";
        const exitCode = main([
            "--config",
            configPath,
            "--registry",
            ws.registryPath,
            "--allowlist",
            ws.allowlistPath,
            "--signature-file",
            signaturePath,
        ], {
            env: ws.env,
            stdout: { write: (value) => { stdout += value; } },
            stderr: { write: (value) => { stderr += value; } },
        });
        expect(exitCode).toBe(0);
        expect(stderr).toBe("");
        expect(JSON.parse(stdout)).toMatchObject({
            ok: true,
            experimentId: "experiment-a",
            created: true,
        });
    });

    it("prepares exact unsigned bytes but cannot install without external authority", () => {
        const ws = workspace("prepare-unsigned");
        const config = experimentConfig(ws, "experiment-a");
        const configPath = path.join(ws.root, "experiment.json");
        const manifestPath = path.join(ws.root, "experiment.manifest.json");
        fs.writeFileSync(configPath, JSON.stringify(config));

        const prepared = prepareUnsignedExperimentManifest({
            configPath,
            outputPath: manifestPath,
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        });
        expect(fs.readFileSync(manifestPath, "utf8")).not.toMatch(/\n$/u);
        expect(prepared.manifestIdentity).toMatch(
            /^sha256:crucible-experiment-authority-manifest-v1:[a-f0-9]{64}$/u,
        );
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        expect(manifest).toMatchObject({
            investigationId: prepared.investigationId,
            trustFingerprint: ws.authority.fingerprint,
            contractHash: prepared.contractHash,
            harnessSuiteIdentity: prepared.harnessSuiteIdentity,
            enumerandRoot: prepared.enumerandRoot,
            statisticalPolicyIdentity: prepared.statisticalPolicyIdentity,
            hypothesisPolicyIdentity: prepared.hypothesisPolicyIdentity,
        });
        expect(() => configureExperiment({
            config,
            registryPath: ws.registryPath,
            allowlistPath: ws.allowlistPath,
            env: ws.env,
        })).toThrow(expect.objectContaining({
            code: EXPERIMENT_REGISTRY_ERROR_CODES.AUTHORITY_REQUIRED,
        }));
        expect(fs.existsSync(ws.registryPath)).toBe(false);
    });
});
