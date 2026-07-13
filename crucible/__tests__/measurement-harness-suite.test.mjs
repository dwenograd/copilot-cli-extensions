import { describe, expect, it } from "vitest";

import { hashCanonical } from "../domain/canonical.mjs";
import {
    buildMeasurementReceipt,
    computeHarnessSuiteV4Identity,
    HARNESS_SUITE_RECEIPT_VERSION,
    hashHarnessEnvironmentV4,
    hashHarnessObservableSchemaV4,
    hashHarnessRoleConfigV4,
    normalizeHarnessSuiteV4,
    parseHarnessResult,
    projectDeterministicReceipt,
    projectHarnessSuiteV4ForWorker,
    validateHarnessSuiteV4CaseClaims,
} from "../measurement/index.mjs";

const snapshot = (char) => `sha256:${char.repeat(64)}`;
const tagged = (label) => hashCanonical(
    { label },
    "sha256:crucible-harness-suite-fixture-v1",
);
const retagged = (value, tag) =>
    `sha256:${tag}:${value.split(":").at(-1)}`;

const ROLE_CONFIG = Object.freeze({
    argvTemplate: [],
    cwd: null,
    allowedEnv: {},
    timeoutMs: 1000,
    maxStdoutBytes: 4096,
    maxStderrBytes: 4096,
    executesCandidateCode: false,
});

const CASES = Object.freeze({
    calibration: Object.freeze([
        ["cal-accept", snapshot("a"), "accept"],
        ["cal-reject", snapshot("b"), "reject"],
    ]),
    search: Object.freeze([
        ["search-accept", snapshot("c"), "accept"],
    ]),
    confirmation: Object.freeze([
        ["confirm-accept", snapshot("d"), "accept"],
    ]),
    challenge: Object.freeze([
        ["challenge-reject", snapshot("e"), "reject"],
    ]),
    novelty: Object.freeze([
        ["novelty-accept", snapshot("f"), "accept"],
    ]),
});

function roleIdentity(role, cases = CASES[role] ?? []) {
    return {
        harnessId: `${role.replaceAll("_", "-")}-harness`,
        harnessEntryHash: tagged(`${role}-entry`),
        executableHash: tagged(`${role}-executable`),
        parser: {
            version: "fixture-parser-v2",
            versionHash: tagged("parser-version"),
            sourceHash: tagged("parser-source"),
        },
        dependencies: [],
        configHash: hashHarnessRoleConfigV4(ROLE_CONFIG),
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
            required: false,
            policyDigest: null,
        },
    };
}

function baseSuite({ verifier = false } = {}) {
    const roles = {};
    const corpusCases = {};
    for (const role of Object.keys(CASES)) {
        roles[role] = roleIdentity(role);
        for (const [id, snapshotHash, expectation] of CASES[role]) {
            corpusCases[id] = { snapshotHash, expectation };
        }
    }
    if (verifier) {
        roles.impossibility_verifier = roleIdentity(
            "impossibility_verifier",
            [],
        );
    }
    return {
        version: 4,
        kind: "HarnessSuiteV4",
        id: "fixture-suite",
        environmentIdentity: hashHarnessEnvironmentV4({
            os: "fixture",
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

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

describe("HarnessSuiteV4 normalization and identity", () => {
    it("requires every primary role", () => {
        const suite = baseSuite();
        delete suite.roles.novelty;
        expect(() => normalizeHarnessSuiteV4(suite))
            .toThrow(/roles\.novelty is required/u);
    });

    it("rejects held-out byte overlap with search/calibration manifests", () => {
        const suite = baseSuite();
        suite.roles.confirmation.caseManifest[0].snapshotHash =
            suite.roles.search.caseManifest[0].snapshotHash;
        suite.operatorCorpus.cases["confirm-accept"].snapshotHash =
            suite.roles.search.caseManifest[0].snapshotHash;
        expect(() => normalizeHarnessSuiteV4(suite))
            .toThrow(/overlap by bytes/u);
    });

    it("prevents callers from relabeling operator-owned expectations", () => {
        const suite = baseSuite();
        expect(() => validateHarnessSuiteV4CaseClaims(suite, [{
            id: "cal-accept",
            snapshotHash: snapshot("a"),
            expectation: "reject",
        }], { role: "calibration" })).toThrow(/cannot be relabeled/u);
    });

    it("changes identity when case bytes change and stays stable under reordering", () => {
        const suite = baseSuite();
        const stable = clone(suite);
        stable.roles = Object.fromEntries(
            Object.entries(stable.roles).reverse(),
        );
        stable.roles.calibration.caseManifest.reverse();
        stable.operatorCorpus.cases = Object.fromEntries(
            Object.entries(stable.operatorCorpus.cases).reverse(),
        );
        expect(computeHarnessSuiteV4Identity(stable))
            .toBe(computeHarnessSuiteV4Identity(suite));

        const changed = clone(suite);
        changed.roles.novelty.caseManifest[0].snapshotHash = snapshot("9");
        changed.operatorCorpus.cases["novelty-accept"].snapshotHash =
            snapshot("9");
        expect(computeHarnessSuiteV4Identity(changed))
            .not.toBe(computeHarnessSuiteV4Identity(suite));
    });

    it("keeps verifier application code separate while allowing declared platform sharing", () => {
        const overlapping = baseSuite({ verifier: true });
        overlapping.roles.impossibility_verifier.executableHash =
            overlapping.roles.search.executableHash;
        expect(() => normalizeHarnessSuiteV4(overlapping))
            .toThrow(/verifier application implementation closure overlaps/u);

        const executableAsParser = baseSuite({ verifier: true });
        executableAsParser.roles.impossibility_verifier.executableHash =
            executableAsParser.roles.search.parser.sourceHash;
        expect(() => normalizeHarnessSuiteV4(executableAsParser))
            .toThrow(/verifier application implementation closure overlaps/u);

        const parserAsApplication = baseSuite({ verifier: true });
        const primaryApplicationHash = tagged("primary-application");
        parserAsApplication.roles.search.dependencies = [{
            role: "search-application",
            sha256: primaryApplicationHash,
            kind: "application",
        }];
        parserAsApplication.roles.impossibility_verifier.parser.sourceHash =
            primaryApplicationHash;
        expect(() => normalizeHarnessSuiteV4(parserAsApplication))
            .toThrow(/verifier application implementation closure overlaps/u);

        const parserIdentityMismatch = baseSuite({ verifier: true });
        parserIdentityMismatch.roles.impossibility_verifier.parser.versionHash =
            tagged("different-parser-version-identity");
        expect(() => normalizeHarnessSuiteV4(parserIdentityMismatch))
            .toThrow(/verifier application implementation closure overlaps/u);

        const valid = baseSuite({ verifier: true });
        const platformHash = tagged("shared-platform");
        valid.sharedPlatformDependencies = [{
            classification: "runtime",
            role: "node-runtime",
            sha256: platformHash,
        }];
        for (const role of ["search", "impossibility_verifier"]) {
            valid.roles[role].dependencies = [{
                role: "node-runtime",
                sha256: platformHash,
                kind: "platform",
            }];
        }
        expect(normalizeHarnessSuiteV4(valid)
            .sharedPlatformDependencies).toHaveLength(1);
    });

    it("never launders a primary executable as a shared platform dependency", () => {
        const exploit = baseSuite({ verifier: true });
        const primaryExecutable = exploit.roles.search.executableHash;
        exploit.sharedPlatformDependencies = [{
            classification: "runtime",
            role: "node-runtime",
            sha256: primaryExecutable,
        }];
        exploit.roles.search.dependencies = [{
            role: "node-runtime",
            sha256: primaryExecutable,
            kind: "platform",
        }];
        exploit.roles.impossibility_verifier.dependencies = [{
            role: "node-runtime",
            sha256: primaryExecutable,
            kind: "platform",
        }];
        expect(() => normalizeHarnessSuiteV4(exploit))
            .toThrow(/only declared runtime\/platform dependency files/u);

        const parserExploit = baseSuite({ verifier: true });
        parserExploit.sharedPlatformDependencies = [{
            classification: "runtime",
            role: "runtime-parser",
            sha256: parserExploit.roles.search.parser.sourceHash,
        }];
        for (const role of ["search", "impossibility_verifier"]) {
            parserExploit.roles[role].dependencies = [{
                role: "runtime-parser",
                sha256: parserExploit.roles.search.parser.sourceHash,
                kind: "platform",
            }];
        }
        expect(() => normalizeHarnessSuiteV4(parserExploit))
            .toThrow(/only declared runtime\/platform dependency files/u);
    });

    it("requires every shared dependency to be explicitly platform or runtime classified", () => {
        const suite = baseSuite({ verifier: true });
        const platformHash = tagged("unclassified-shared-file");
        suite.sharedPlatformDependencies = [{
            role: "node-runtime",
            sha256: platformHash,
        }];
        for (const role of ["search", "impossibility_verifier"]) {
            suite.roles[role].dependencies = [{
                role: "node-runtime",
                sha256: platformHash,
                kind: "platform",
            }];
        }
        expect(() => normalizeHarnessSuiteV4(suite))
            .toThrow(/classification must be "platform" or "runtime"/u);
    });

    it("rejects identical executable and entrypoint bytes hidden behind different tags", () => {
        const executableExploit = baseSuite({ verifier: true });
        executableExploit.roles.impossibility_verifier.executableHash =
            retagged(
                executableExploit.roles.search.executableHash,
                "attacker-verifier-executable-v1",
            );
        expect(() => normalizeHarnessSuiteV4(executableExploit))
            .toThrow(/verifier application implementation closure overlaps/u);

        const parserExploit = baseSuite({ verifier: true });
        parserExploit.roles.impossibility_verifier.executableHash = retagged(
            parserExploit.roles.search.parser.sourceHash,
            "attacker-verifier-binary-v1",
        );
        expect(() => normalizeHarnessSuiteV4(parserExploit))
            .toThrow(/verifier application implementation closure overlaps/u);

        const platformLaundering = baseSuite({ verifier: true });
        const primaryEntrypoint = tagged("primary-entrypoint");
        platformLaundering.roles.search.dependencies = [{
            role: "search-entrypoint",
            sha256: primaryEntrypoint,
            kind: "application",
        }];
        const retaggedEntrypoint = retagged(
            primaryEntrypoint,
            "attacker-runtime-v1",
        );
        platformLaundering.sharedPlatformDependencies = [{
            classification: "runtime",
            role: "node-runtime",
            sha256: retaggedEntrypoint,
        }];
        platformLaundering.roles.impossibility_verifier.dependencies = [{
            role: "node-runtime",
            sha256: retaggedEntrypoint,
            kind: "platform",
        }];
        platformLaundering.roles.confirmation.dependencies = [{
            role: "node-runtime",
            sha256: retaggedEntrypoint,
            kind: "platform",
        }];
        expect(() => normalizeHarnessSuiteV4(platformLaundering))
            .toThrow(/only declared runtime\/platform dependency files/u);
    });

    it("redacts held-out/challenge case ids and snapshot ids from worker projections", () => {
        const projection = projectHarnessSuiteV4ForWorker(baseSuite());
        expect(projection).not.toHaveProperty("operatorCorpus");
        expect(projection.roles.challenge.caseManifest).toBeNull();
        expect(projection.roles.confirmation.caseManifest).toBeNull();
        expect(projection.roles.search.caseManifest[0].id)
            .toBe("search-accept");
        const encoded = JSON.stringify(projection);
        expect(encoded).not.toContain("challenge-reject");
        expect(encoded).not.toContain(snapshot("e"));
    });
});

function receiptInput(parsed, measurementBinding = undefined) {
    const hash = tagged("receipt-field");
    return {
        allowlistFileHash: hash,
        harnessEntryHash: hash,
        executableHash: hash,
        stagedExecutableHash: hash,
        dependencyHashes: [],
        stagedDependencyHashes: [],
        launchFileBindings: [],
        argvHash: hash,
        envHash: hash,
        candidateSnapshotHash: hash,
        stagedCandidateSnapshotHash: hash,
        stagedCandidateSnapshotClosureHash: hash,
        stagedCandidateSnapshotIdentitySummary: {},
        candidateSnapshotPreClosureHash: hash,
        candidateSnapshotPostClosureHash: hash,
        candidateSnapshotIdentitySummary: {},
        candidateSnapshotMutationCheck: { status: "passed" },
        stdoutHash: hash,
        stderrHash: hash,
        outputCapture: {
            stdout: {
                capBytes: 1024,
                totalObservedBytes: 10,
                retainedBytes: 10,
                overflowed: false,
                truncated: false,
            },
            stderr: {
                capBytes: 1024,
                totalObservedBytes: 0,
                retainedBytes: 0,
                overflowed: false,
                truncated: false,
            },
            overflowed: false,
            truncated: false,
        },
        parserVersion: parsed.parserVersion,
        sandbox: null,
        attemptId: "attempt-1",
        runnerEpochId: "epoch-1",
        startedAt: "2026-07-12T00:00:00.000Z",
        completedAt: "2026-07-12T00:00:01.000Z",
        durationMs: 1000,
        exit: { code: 0, signal: null, timedOut: false },
        parsed,
        ...(measurementBinding === undefined ? {} : { measurementBinding }),
    };
}

describe("HarnessSuiteV4 parser/receipt binding", () => {
    it("carries the trusted role binding into the receipt and deterministic projection", () => {
        const binding = {
            role: "confirmation",
            phase: "confirmation",
            replicateIndex: 1,
            blockIndex: 3,
            armIndex: 0,
            armId: "candidate",
            deterministicSeed: "confirmation-seed",
            subjectId: "candidate-42",
            environmentIdentity:
                `sha256:crucible-harness-environment-v4:${"1".repeat(64)}`,
            suiteIdentity:
                `sha256:crucible-harness-suite-v4:${"2".repeat(64)}`,
        };
        const parsed = parseHarnessResult(JSON.stringify({
            pass: true,
            metrics: { score: 7 },
            ...binding,
        }), { expectedBinding: binding });
        const receipt = buildMeasurementReceipt(receiptInput(parsed));
        expect(receipt.version).toBe(HARNESS_SUITE_RECEIPT_VERSION);
        expect(receipt).toMatchObject(binding);
        expect(projectDeterministicReceipt(receipt)).toMatchObject(binding);

        expect(() => buildMeasurementReceipt(receiptInput(parsed, {
            ...binding,
            subjectId: "candidate-99",
        }))).toThrow(/binding disagrees/u);
    });
});
