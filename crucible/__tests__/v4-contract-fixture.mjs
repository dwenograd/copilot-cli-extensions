import {
    DEFAULT_SEARCH_POLICY,
    STATISTICAL_POLICY_VERSION,
    hashCanonical,
    normalizeEnumerandManifest,
    resolveControlEnumerand,
    statisticalEvaluationRequirements,
} from "../domain/index.mjs";
import {
    PARSER_VERSION,
    PARSER_SOURCE_HASH_ALGORITHM,
    PARSER_VERSION_HASH_ALGORITHM,
    computeHarnessSuiteV4Identity,
    hashHarnessEnvironmentV4,
    hashHarnessObservableSchemaV4,
    hashHarnessRoleConfigV4,
    sha256File,
} from "../measurement/index.mjs";
import { fileURLToPath } from "node:url";

export const snapshot = (character) => `sha256:${character.repeat(64)}`;

const ROLE_CONFIG = Object.freeze({
    argvTemplate: [],
    cwd: null,
    allowedEnv: {},
    timeoutMs: 1000,
    maxStdoutBytes: 4096,
    maxStderrBytes: 4096,
    executesCandidateCode: false,
});

function tagged(label) {
    return hashCanonical(
        { label },
        "sha256:crucible-v4-contract-fixture-v1",
    );
}

const DEFAULT_CASES = Object.freeze({
    calibration: Object.freeze([
        ["cal-accept", snapshot("1"), "accept"],
        ["cal-reject", snapshot("2"), "reject"],
    ]),
    search: Object.freeze([["search-case", snapshot("3"), "accept"]]),
    confirmation: Object.freeze([["confirmation-case", snapshot("4"), "accept"]]),
    challenge: Object.freeze([["challenge-case", snapshot("5"), "reject"]]),
    novelty: Object.freeze([["novelty-case", snapshot("6"), "accept"]]),
});

function roleIdentity(role, cases, executesCandidateCode = false) {
    const roleConfig = {
        ...ROLE_CONFIG,
        executesCandidateCode,
    };
    return {
        harnessId: `${role.replaceAll("_", "-")}-harness`,
        harnessEntryHash: tagged(`${role}-entry`),
        executableHash: tagged(`${role}-executable`),
        parser: {
            version: PARSER_VERSION,
            versionHash: tagged("parser-version"),
            sourceHash: tagged("parser-source"),
        },
        dependencies: [],
        configHash: hashHarnessRoleConfigV4(roleConfig),
        observableSchemaHash: hashHarnessObservableSchemaV4({
            pass: "boolean",
            metrics: ["score"],
            role,
        }),
        caseManifest: cases.map(([id, snapshotHash]) => ({
            id,
            snapshotHash,
        })),
        deterministicSeed: `seed-${role}`,
        sandboxIdentity: {
            required: executesCandidateCode,
            policyDigest: executesCandidateCode
                ? tagged("sandbox-policy")
                : null,
        },
    };
}

export function fakeHarnessSuiteV4({
    includeVerifier = false,
    executesCandidateCode = false,
    cases = DEFAULT_CASES,
    id = "fixture-suite",
} = {}) {
    const roles = {};
    const corpusCases = {};
    for (const role of Object.keys(DEFAULT_CASES)) {
        const roleCases = cases[role] ?? DEFAULT_CASES[role];
        roles[role] = roleIdentity(role, roleCases, executesCandidateCode);
        for (const [caseId, snapshotHash, expectation] of roleCases) {
            corpusCases[caseId] = { snapshotHash, expectation };
        }
    }
    if (includeVerifier) {
        roles.impossibility_verifier = roleIdentity(
            "impossibility_verifier",
            [],
            executesCandidateCode,
        );
    }
    return {
        version: 4,
        kind: "HarnessSuiteV4",
        id,
        environmentIdentity: hashHarnessEnvironmentV4({
            platform: "fixture",
            architecture: "x64",
        }),
        sharedPlatformDependencies: [],
        roles,
        operatorCorpus: {
            version: 1,
            cases: corpusCases,
        },
    };
}

export function buildHarnessSuiteForAllowlist(
    allowlist,
    {
        suiteId = "primary-suite",
        harnessId = "primary-harness",
        roleCaseIds,
        includeVerifier = false,
        verifierHarnessId = harnessId,
        environment = { platform: "fixture", architecture: "x64" },
        deterministicSeedPrefix = "fixture",
        sandboxPolicyDigest = null,
        sharedPlatformDependencies = [],
    },
) {
    const parserPath = fileURLToPath(
        new URL("../measurement/parser.mjs", import.meta.url),
    );
    const parser = {
        version: PARSER_VERSION,
        versionHash: hashCanonical(
            { parserVersion: PARSER_VERSION },
            PARSER_VERSION_HASH_ALGORITHM,
        ),
        sourceHash: sha256File(parserPath, PARSER_SOURCE_HASH_ALGORITHM),
    };
    const sharedKeys = new Set(sharedPlatformDependencies.map((dependency) =>
        `${dependency.role}\0${dependency.sha256}`));
    const roleSpec = (role, caseIds, selectedHarnessId = harnessId) => {
        const entry = allowlist.getEntry(selectedHarnessId);
        const verified = allowlist.verifyEntry(selectedHarnessId);
        const roleConfig = {
            argvTemplate: [...entry.argvTemplate],
            cwd: entry.cwd,
            allowedEnv: { ...entry.allowedEnv },
            timeoutMs: entry.timeoutMs,
            maxStdoutBytes: entry.maxStdoutBytes,
            maxStderrBytes: entry.maxStderrBytes,
            executesCandidateCode: entry.executesCandidateCode,
        };
        return {
            harnessId: selectedHarnessId,
            harnessEntryHash: verified.entryHash,
            executableHash: verified.executableHash,
            parser,
            dependencies: verified.dependencies.map((dependency) => ({
                role: dependency.role,
                sha256: dependency.sha256,
                kind: sharedKeys.has(`${dependency.role}\0${dependency.sha256}`)
                    ? "platform"
                    : "application",
            })),
            configHash: hashHarnessRoleConfigV4(roleConfig),
            observableSchemaHash: hashHarnessObservableSchemaV4({
                pass: "boolean",
                metrics: ["score"],
                role,
            }),
            caseManifest: caseIds.map((id) => ({
                id,
                snapshotHash: entry.validationCases[id].snapshotHash,
            })),
            deterministicSeed: `${deterministicSeedPrefix}-${role}`,
            sandboxIdentity: {
                required: entry.executesCandidateCode,
                policyDigest: entry.executesCandidateCode
                    ? sandboxPolicyDigest
                    : null,
            },
        };
    };
    const roles = {};
    const operatorCases = {};
    for (const role of [
        "calibration",
        "search",
        "confirmation",
        "challenge",
        "novelty",
    ]) {
        const ids = roleCaseIds[role];
        roles[role] = roleSpec(role, ids);
        const entry = allowlist.getEntry(harnessId);
        for (const id of ids) {
            const item = entry.validationCases[id];
            operatorCases[id] = {
                snapshotHash: item.snapshotHash,
                expectation: item.expectation,
            };
        }
    }
    if (includeVerifier) {
        roles.impossibility_verifier = roleSpec(
            "impossibility_verifier",
            roleCaseIds.impossibility_verifier ?? [],
            verifierHarnessId,
        );
    }
    return {
        version: 4,
        kind: "HarnessSuiteV4",
        id: suiteId,
        environmentIdentity: hashHarnessEnvironmentV4(environment),
        sharedPlatformDependencies,
        roles,
        operatorCorpus: {
            version: 1,
            cases: operatorCases,
        },
    };
}

export function fakeObservableRegistry() {
    return [
        {
            key: "score",
            kind: "numeric",
            minimum: 0,
            maximum: 1,
        },
    ];
}

export function fakeHypothesisPolicy() {
    return {
        required: false,
        maxPredictions: 8,
        allowedKinds: [
            "threshold",
            "bounded_interval",
            "direction",
            "categorical_outcome",
        ],
        allowRequiredForResult: true,
    };
}

export function fakeStatisticalPolicy({
    topology = "open_generative",
    searchSlots = 1,
    validationCaseCount = 2,
    manifest = null,
    goalMode = "optimize",
    maxBlocks = 1,
    minBlocks = 1,
    maxConfirmations = 1,
    control = null,
    metrics = null,
} = {}) {
    const normalizedMetrics = metrics ?? [{
        key: "score",
        minimum: 0,
        maximum: 1,
        estimand: "mean score difference versus control",
        unit: "score",
        direction: "max",
        acceptanceThreshold: 0.8,
        practicalEquivalenceDelta: 0.01,
        family: "primary",
    }];
    let resolvedControl = control;
    if (resolvedControl === null && manifest !== null) {
        const manifestControl = resolveControlEnumerand(manifest);
        resolvedControl = manifestControl.kind === "reference"
            ? {
                kind: "snapshot",
                identity: manifestControl.referenceHash,
            }
            : {
                kind: "enumerand",
                identity: manifestControl.enumerandHash,
            };
    }
    resolvedControl ??= {
        kind: "snapshot",
        identity: snapshot("f"),
    };
    const requirements = statisticalEvaluationRequirements({
        searchSlots,
        maxBlocks,
        maxConfirmations,
        validationCaseCount,
        hypothesisTopology: topology,
    });
    const maxCandidateEvaluations = requirements.requiredCandidateEvaluations;
    const maxControlEvaluations = requirements.requiredControlEvaluations;
    const maxTotalEvaluations = requirements.validationCaseCount
        + requirements.verifierEvaluations
        + maxCandidateEvaluations
        + maxControlEvaluations;
    return {
        version: STATISTICAL_POLICY_VERSION,
        goalMode,
        metrics: normalizedMetrics,
        investigationAlpha: 0.05,
        familyAllocations: [{ family: "primary", alpha: 0.05 }],
        minBlocks,
        maxBlocks,
        control: {
            ...resolvedControl,
            tolerances: normalizedMetrics.map((metric) => ({
                metric: metric.key,
                absolute: 0,
                relative: 0,
            })),
        },
        missingness: {
            mode: "fail_closed",
            maxMissingPerBlock: 0,
            maxMissingFraction: 0,
        },
        deterministicBlockSeed: "fixture-block-seed-v1",
        maxConfirmations,
        evaluationBudget: {
            maxCandidateEvaluations,
            maxControlEvaluations,
            maxTotalEvaluations,
        },
        resourceBudget: {
            perAttemptOutputBytes: 16 * 1024 * 1024,
            perInvestigationOutputBytes: 256 * 1024 * 1024,
            perAttemptReceiptBytes: 2 * 1024 * 1024,
            perInvestigationReceiptBytes: 64 * 1024 * 1024,
            perAttemptCasBytes: 32 * 1024 * 1024,
            perInvestigationCasBytes: 2 * 1024 * 1024 * 1024,
        },
    };
}

export function fakeEnumerandManifest(
    topology,
    ids = ["candidate-a"],
) {
    if (topology === "finite_enumerable") {
        return normalizeEnumerandManifest({
            topology,
            entries: ids.map((id, ordinal) => ({
                id,
                ordinal,
                artifactSnapshotHash:
                    `sha256:${(ordinal + 10).toString(16).padStart(64, "0")}`,
            })),
            control: { kind: "enumerand", ordinal: 0 },
        });
    }
    if (topology === "bounded_parameterized") {
        return normalizeEnumerandManifest({
            topology,
            entries: ids.map((id, ordinal) => ({
                id,
                ordinal,
                parameterTuple: [id, ordinal],
            })),
            control: { kind: "enumerand", ordinal: 0 },
        });
    }
    return null;
}

export function makeV4ContractInput(overrides = {}) {
    const topology = overrides.hypothesisTopology ?? "open_generative";
    const candidatesPerRound = overrides.candidatesPerRound ?? 1;
    const maxRounds = overrides.maxRounds ?? 1;
    const requestedManifest = Object.hasOwn(overrides, "enumerandManifest")
        ? overrides.enumerandManifest
        : fakeEnumerandManifest(
            topology,
            Array.from(
                { length: candidatesPerRound * maxRounds },
                (_unused, index) => `candidate-${index}`,
            ),
        );
    const suite = overrides.harnessSuite ?? fakeHarnessSuiteV4({
        includeVerifier: topology === "certified_impossibility",
    });
    const registry = overrides.observableRegistry ?? fakeObservableRegistry();
    const statisticalPolicy = overrides.statisticalPolicy
        ?? fakeStatisticalPolicy({
            topology,
            searchSlots:
                requestedManifest?.entries.length
                ?? candidatesPerRound * maxRounds,
            manifest: requestedManifest,
        });
    const base = {
        objective: "Find a candidate that satisfies the frozen objective",
        acceptancePredicate: {
            kind: "metric_compare",
            metric: "score",
            operator: ">=",
            value: 0.8,
        },
        harnessSuite: suite,
        harnessSuiteIdentity: computeHarnessSuiteV4Identity(suite),
        hypothesisTopology: topology,
        criticality: "standard",
        policyVersion: "crucible-policy-1",
        workerModels: ["worker-a"],
        candidatesPerRound,
        maxRounds,
        searchPolicy: structuredClone(DEFAULT_SEARCH_POLICY),
        observableRegistry: registry,
        hypothesisPolicy: fakeHypothesisPolicy(),
        statisticalPolicy,
        ...(requestedManifest === null ? {} : { enumerandManifest: requestedManifest }),
        ...(topology === "certified_impossibility"
            ? {
                impossibilityPolicy: {
                    trigger: "search_exhausted",
                    requestVersion: "crucible-impossibility-request-v1",
                    certificateVersion:
                        "crucible-impossibility-certificate-v1",
                },
            }
            : {}),
    };
    return {
        ...base,
        ...overrides,
    };
}

export function upgradeLegacyContractInput(input) {
    const topology = input.hypothesisTopology ?? "open_generative";
    const candidatesPerRound = input.candidatesPerRound ?? 1;
    const maxRounds = input.maxRounds ?? 1;
    const ids = input.boundedCandidateIds
        ?? Array.from(
            { length: candidatesPerRound * maxRounds },
            (_unused, index) => `candidate-${index}`,
        );
    const manifest = input.enumerandManifest
        ?? fakeEnumerandManifest(topology, ids);
    const legacyCalibration = Array.isArray(input.validationCases)
        && input.validationCases.length >= 2
        ? input.validationCases.map((item) => [
            item.id,
            item.artifactHash,
            item.expectation,
        ])
        : DEFAULT_CASES.calibration;
    const suite = fakeHarnessSuiteV4({
        includeVerifier: topology === "certified_impossibility",
        cases: {
            ...DEFAULT_CASES,
            calibration: legacyCalibration,
        },
    });
    const oldMetrics = Array.isArray(input.metrics) && input.metrics.length > 0
        ? input.metrics
        : [{ key: "score", direction: "max", epsilon: 0.01 }];
    const registry = input.observableRegistry ?? oldMetrics.map((metric) => ({
        key: metric.key,
        kind: "numeric",
        minimum: 0,
        maximum: 1,
    }));
    const statisticalMetrics = oldMetrics.map((metric) => ({
        key: metric.key,
        minimum: 0,
        maximum: 1,
        estimand: `${metric.key} versus control`,
        unit: metric.key,
        direction: metric.direction,
        acceptanceThreshold: metric.direction === "min" ? 0.2 : 0.8,
        practicalEquivalenceDelta: Math.max(metric.epsilon ?? 0.01, 0.000001),
        family: "primary",
    }));
    return makeV4ContractInput({
        objective: input.objective,
        acceptancePredicate: input.acceptancePredicate,
        hypothesisTopology: topology,
        criticality: input.criticality,
        policyVersion: input.policyVersion,
        workerModels: input.workerModels,
        candidatesPerRound,
        maxRounds,
        searchPolicy: input.searchPolicy,
        observableRegistry: registry,
        hypothesisPolicy: input.hypothesisPolicy ?? fakeHypothesisPolicy(),
        statisticalPolicy: input.statisticalPolicy ?? fakeStatisticalPolicy({
                topology,
                searchSlots: manifest?.entries.length
                    ?? candidatesPerRound * maxRounds,
                manifest,
                metrics: statisticalMetrics,
            }),
        harnessSuite: suite,
        harnessSuiteIdentity: computeHarnessSuiteV4Identity(suite),
        ...(manifest === null ? {} : { enumerandManifest: manifest }),
    });
}
